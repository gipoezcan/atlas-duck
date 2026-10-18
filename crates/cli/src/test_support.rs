//! Test doubles for the connected commands: a recording fake `RequestHandler` served by the real
//! `IpcServer` (Unix socket / Windows pipe in a temp dir), and a `Connector` that reaches it.
//! Adapted from the ipc crate's `tests/common`.
//!
//! The MCP tests (M9 Task 6) add runtime knobs: hello recording and modes, a configurable build,
//! submit and known-id status answers, a submit that never answers, an await that honours
//! `timeout_ms` with a scripted progress schedule, and a connector whose hello build and endpoint
//! can change. Each knob defaults to the behaviour the connected/doctor tests rely on.
#![allow(dead_code)]

use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atlas_duck_ipc::client::{ClientContext, ConnectError, IpcClient};
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::paths::{
    BaseDirs, DataDirResolution, EndpointLocation, LocalDataDir, check_data_dir,
};
use atlas_duck_ipc::proto::{
    AwaitParams, ConnectionMeta, Hello, HelloReply, ListState, MatchParams, ProgressNotification,
    ProgressSink, RequestHandler, SubmitParams, SubmitReply,
};
use atlas_duck_ipc::server::{HandlerCell, IpcServer, ServerLimits, ShutdownSignal};
use serde_json::{Map, Value, json};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::connected::Connector;
use crate::deadline::Deadline;
use crate::discover::{AppLocation, DataState, Discovery};
use crate::interrupt::{BoxFuture, Interrupts};
use crate::launch::{LaunchError, LaunchSys};

/// Upper bound for anything a test waits on.
pub(crate) const WAIT: Duration = Duration::from_secs(10);
/// The build id the fake server answers `hello` with (the connector's hello uses it too).
pub(crate) const BUILD: &str = "test-build";
pub(crate) const REQ_ID: &str = "req_00000000000000000000000000000001";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Hello,
    Submit,
    ScriptSubmit,
    AwaitStart,
    AwaitDone,
    Status,
    Cancel,
    RequestsList,
    OpsList,
    OpsDescribe,
    InstancesList,
    Doctor,
}

#[derive(Debug, Clone)]
pub(crate) struct Event {
    pub kind: Kind,
    pub at: Instant,
    pub detail: Option<String>,
}

/// `requests.list` arguments: agent, state, match params.
pub(crate) type ListCall = (Option<String>, Option<ListState>, Option<MatchParams>);

/// One `hello` the fake saw, with the connection it came on.
#[derive(Debug, Clone)]
pub(crate) struct HelloSeen {
    pub hello: Hello,
    pub connection_id: String,
}

/// How the fake answers `hello`.
#[derive(Debug, Clone)]
// `Refuse` carries a whole envelope; a test double, set a few times per test.
#[allow(clippy::large_enum_variant)]
pub(crate) enum HelloMode {
    /// Accept every hello, answering with the client's own build (the default).
    AcceptAll,
    /// Accept only the fake's build; another is refused as `gate::hello_check` does
    /// (`protocol_mismatch` with `details.client_build`/`server_build`).
    Exact,
    /// Refuse every hello with this envelope (e.g. `unreachable {app_shutting_down}`).
    Refuse(Envelope),
}

/// A scripted `request.await` (instead of the fixed `await_delay`): progress at offsets from the
/// start of the await, a decision at an offset, and `pending` with the id once `timeout_ms`
/// passed, as the app answers.
#[derive(Debug, Clone, Default)]
pub(crate) struct AwaitScript {
    pub progress: Vec<(Duration, Status)>,
    /// The decision and when it comes; its `request_id` is set to the awaited id if absent.
    pub decision: Option<(Duration, Envelope)>,
}

/// How long a scripted await without `timeout_ms` holds when no decision comes.
const AWAIT_UNBOUNDED: Duration = Duration::from_secs(3600);

/// Records every call; answers with an envelope whose `data.method` names the call.
pub(crate) struct Fake {
    events: Mutex<Vec<Event>>,
    pub submits: Mutex<Vec<SubmitParams>>,
    pub awaits: Mutex<Vec<AwaitParams>>,
    pub lists: Mutex<Vec<ListCall>>,
    /// The status `submit` answers with (`Pending` carries the request id and hash).
    pub submit_status: Status,
    pub submit_delay: Duration,
    pub await_delay: Duration,
    pub doctor_delay: Duration,
    /// A `pending` submit reply that carries no request id (a broken app).
    pub submit_null_id: bool,
    /// The `request_id` the await answer carries. `None` models an app that answers an error:
    /// an id-less `failed` envelope. A successful answer always names its request (T34b m-5).
    pub await_reply_id: Option<&'static str>,
    hellos: Mutex<Vec<HelloSeen>>,
    hello_mode: Mutex<HelloMode>,
    /// The server's build (`HelloMode::Exact` compares against it).
    build: Mutex<String>,
    /// Answers every submit with this envelope instead of the `submit_status` answer.
    submit_answer: Mutex<Option<Envelope>>,
    /// Records each submit, then never answers it.
    submit_hold: AtomicBool,
    /// Known ids: `request.status` answers these envelopes.
    statuses: Mutex<HashMap<String, Envelope>>,
    await_script: Mutex<Option<AwaitScript>>,
}

impl Fake {
    pub(crate) fn new() -> Fake {
        Fake {
            events: Mutex::new(Vec::new()),
            submits: Mutex::new(Vec::new()),
            awaits: Mutex::new(Vec::new()),
            lists: Mutex::new(Vec::new()),
            submit_status: Status::Pending,
            submit_delay: Duration::ZERO,
            await_delay: Duration::ZERO,
            doctor_delay: Duration::ZERO,
            submit_null_id: false,
            await_reply_id: Some(REQ_ID),
            hellos: Mutex::new(Vec::new()),
            hello_mode: Mutex::new(HelloMode::AcceptAll),
            build: Mutex::new(BUILD.to_owned()),
            submit_answer: Mutex::new(None),
            submit_hold: AtomicBool::new(false),
            statuses: Mutex::new(HashMap::new()),
            await_script: Mutex::new(None),
        }
    }

    // ---- runtime knobs (the fake is shared as `Arc<Fake>`) ----

    pub(crate) fn hellos(&self) -> Vec<HelloSeen> {
        self.hellos.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub(crate) fn set_hello_mode(&self, mode: HelloMode) {
        if let Ok(mut g) = self.hello_mode.lock() {
            *g = mode;
        }
    }

    pub(crate) fn build(&self) -> String {
        self.build
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| BUILD.to_owned())
    }

    pub(crate) fn set_build(&self, build: &str) {
        if let Ok(mut g) = self.build.lock() {
            *g = build.to_owned();
        }
    }

    pub(crate) fn set_submit_answer(&self, answer: Option<Envelope>) {
        if let Ok(mut g) = self.submit_answer.lock() {
            *g = answer;
        }
    }

    pub(crate) fn set_submit_hold(&self, hold: bool) {
        self.submit_hold.store(hold, Ordering::SeqCst);
    }

    /// `request.status` of `request_id` answers `answer` (its `request_id` set to that id).
    pub(crate) fn set_status(&self, request_id: &str, mut answer: Envelope) {
        answer.request_id = Some(request_id.to_owned());
        if let Ok(mut g) = self.statuses.lock() {
            g.insert(request_id.to_owned(), answer);
        }
    }

    pub(crate) fn set_await_script(&self, script: Option<AwaitScript>) {
        if let Ok(mut g) = self.await_script.lock() {
            *g = script;
        }
    }

    // The `Err` type is `RequestHandler::hello`'s.
    #[allow(clippy::result_large_err)]
    fn hello_answer(&self, h: &Hello) -> Result<HelloReply, Envelope> {
        let mode = self
            .hello_mode
            .lock()
            .map(|g| g.clone())
            .unwrap_or(HelloMode::AcceptAll);
        match mode {
            HelloMode::AcceptAll => Ok(HelloReply {
                build_id: h.build_id.clone(),
            }),
            HelloMode::Exact => {
                let build = self.build();
                if h.build_id == build {
                    return Ok(HelloReply { build_id: build });
                }
                let mut env = Envelope::failed(
                    ErrorCode::ProtocolMismatch,
                    true,
                    "client and app builds differ",
                );
                if let Some(err) = env.error.as_mut() {
                    let mut d = Map::new();
                    d.insert("client_build".into(), Value::String(h.build_id.clone()));
                    d.insert("server_build".into(), Value::String(build));
                    err.details = Some(d);
                }
                Err(env)
            }
            HelloMode::Refuse(env) => Err(env),
        }
    }

    /// The scripted await: progress at its offsets until the decision or `timeout_ms`.
    async fn scripted_await(
        &self,
        script: AwaitScript,
        a: &AwaitParams,
        progress: &dyn ProgressSink,
    ) -> Envelope {
        let start = tokio::time::Instant::now();
        let limit = match a.timeout_ms {
            Some(ms) => Duration::from_millis(ms),
            None => AWAIT_UNBOUNDED,
        };
        let decided_at = script.decision.as_ref().map(|(at, _)| *at);
        let end = decided_at.map_or(limit, |at| at.min(limit));
        for (offset, status) in &script.progress {
            if *offset >= end {
                break;
            }
            tokio::time::sleep_until(start + *offset).await;
            progress.progress(ProgressNotification {
                request_id: a.request_id.clone(),
                status: *status,
            });
        }
        tokio::time::sleep_until(start + end).await;
        match script.decision {
            Some((at, mut env)) if at <= limit => {
                if env.request_id.is_none() {
                    env.request_id = Some(a.request_id.clone());
                }
                env
            }
            _ => {
                let mut env = Fake::answer("request.await");
                env.status = Status::Pending;
                env.data = None;
                env.request_id = Some(a.request_id.clone());
                env
            }
        }
    }

    fn record(&self, kind: Kind, detail: Option<String>) {
        if let Ok(mut g) = self.events.lock() {
            g.push(Event {
                kind,
                at: Instant::now(),
                detail,
            });
        }
    }

    pub(crate) fn of(&self, kind: Kind) -> Vec<Event> {
        self.events
            .lock()
            .map(|g| g.iter().filter(|e| e.kind == kind).cloned().collect())
            .unwrap_or_default()
    }

    pub(crate) fn count(&self, kind: Kind) -> usize {
        self.of(kind).len()
    }

    /// Polls until `kind` was recorded `n` times; fails the test after [`WAIT`].
    pub(crate) async fn wait_for(&self, kind: Kind, n: usize) -> Vec<Event> {
        let until = Instant::now() + WAIT;
        loop {
            let got = self.of(kind);
            if got.len() >= n {
                return got;
            }
            assert!(Instant::now() < until, "{kind:?} seen {} times", got.len());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn answer(method: &str) -> Envelope {
        Envelope {
            request_id: None,
            op_id: None,
            instance: None,
            status: Status::Succeeded,
            data: Some(json!({"method": method})),
            edited: false,
            redacted: false,
            redaction_note: None,
            message: None,
            error: None,
            meta: None,
        }
    }

    async fn submit_reply(&self, method: &str, p: SubmitParams) -> SubmitReply {
        tokio::time::sleep(self.submit_delay).await;
        if self.submit_hold.load(Ordering::SeqCst) {
            if let Ok(mut g) = self.submits.lock() {
                g.push(p);
            }
            return std::future::pending().await;
        }
        let answer = self.submit_answer.lock().ok().and_then(|g| g.clone());
        if let Some(envelope) = answer {
            if let Ok(mut g) = self.submits.lock() {
                g.push(p);
            }
            let params_sha256 = envelope.request_id.is_some().then(|| "ab".repeat(32));
            return SubmitReply {
                envelope,
                params_sha256,
            };
        }
        let mut envelope = Fake::answer(method);
        envelope.op_id = Some(p.op_id.clone());
        envelope.instance = p.instance.clone();
        if let Ok(mut g) = self.submits.lock() {
            g.push(p);
        }
        envelope.status = self.submit_status;
        if self.submit_status == Status::Pending {
            envelope.request_id = (!self.submit_null_id).then(|| REQ_ID.to_owned());
            envelope.data = None;
            SubmitReply {
                envelope,
                params_sha256: Some("ab".repeat(32)),
            }
        } else {
            envelope.status = Status::Failed;
            envelope.data = None;
            envelope.error = Envelope::failed(
                atlas_duck_ipc::envelope::ErrorCode::Validation,
                false,
                "invalid",
            )
            .error;
            SubmitReply {
                envelope,
                params_sha256: None,
            }
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Fake {
    async fn hello(&self, conn: &ConnectionMeta, h: Hello) -> Result<HelloReply, Envelope> {
        self.record(Kind::Hello, Some(conn.connection_id.clone()));
        let answer = self.hello_answer(&h);
        if let Ok(mut g) = self.hellos.lock() {
            g.push(HelloSeen {
                hello: h,
                connection_id: conn.connection_id.clone(),
            });
        }
        answer
    }

    async fn ops_list(&self, instance: Option<&str>) -> Envelope {
        self.record(Kind::OpsList, instance.map(str::to_owned));
        Fake::answer("ops.list")
    }

    async fn ops_describe(&self, op_id: &str, instance: Option<&str>) -> Envelope {
        self.record(
            Kind::OpsDescribe,
            Some(format!("{op_id}|{}", instance.unwrap_or("-"))),
        );
        Fake::answer("ops.describe")
    }

    async fn instances_list(&self) -> Envelope {
        self.record(Kind::InstancesList, None);
        Fake::answer("instances.list")
    }

    async fn submit(&self, _conn: &ConnectionMeta, p: SubmitParams) -> SubmitReply {
        self.record(Kind::Submit, Some(p.op_id.clone()));
        self.submit_reply("request.submit", p).await
    }

    async fn submit_script(&self, _conn: &ConnectionMeta, p: SubmitParams) -> SubmitReply {
        self.record(Kind::ScriptSubmit, Some(p.op_id.clone()));
        self.submit_reply("script.submit", p).await
    }

    async fn await_request(
        &self,
        _conn: &ConnectionMeta,
        a: AwaitParams,
        progress: &dyn ProgressSink,
    ) -> Envelope {
        self.record(Kind::AwaitStart, Some(a.request_id.clone()));
        let id = a.request_id.clone();
        if let Ok(mut g) = self.awaits.lock() {
            g.push(a.clone());
        }
        let script = self.await_script.lock().ok().and_then(|g| g.clone());
        if let Some(script) = script {
            let env = self.scripted_await(script, &a, progress).await;
            self.record(Kind::AwaitDone, Some(id));
            return env;
        }
        tokio::time::sleep(self.await_delay).await;
        self.record(Kind::AwaitDone, Some(id));
        match self.await_reply_id {
            Some(id) => {
                let mut env = Fake::answer("request.await");
                env.request_id = Some(id.to_owned());
                env
            }
            None => Envelope::failed(ErrorCode::Internal, false, "the fake app failed the await"),
        }
    }

    async fn status(&self, request_id: &str) -> Envelope {
        self.record(Kind::Status, Some(request_id.to_owned()));
        let known = self
            .statuses
            .lock()
            .ok()
            .and_then(|g| g.get(request_id).cloned());
        known.unwrap_or_else(|| Fake::answer("request.status"))
    }

    async fn cancel(&self, request_id: &str) -> Envelope {
        self.record(Kind::Cancel, Some(request_id.to_owned()));
        Fake::answer("request.cancel")
    }

    async fn requests_list(
        &self,
        agent: Option<&str>,
        state: Option<ListState>,
        match_params: Option<MatchParams>,
    ) -> Envelope {
        self.record(Kind::RequestsList, None);
        if let Ok(mut g) = self.lists.lock() {
            g.push((agent.map(str::to_owned), state, match_params));
        }
        Fake::answer("requests.list")
    }

    async fn doctor(&self) -> Envelope {
        self.record(Kind::Doctor, None);
        tokio::time::sleep(self.doctor_delay).await;
        Fake::answer("doctor")
    }
}

// ---------- the served endpoint ----------

pub(crate) struct Running {
    pub location: EndpointLocation,
    pub data: LocalDataDir,
    pub shutdown: ShutdownSignal,
    task: JoinHandle<()>,
    /// `serve`'s own temp dir; `None` for `serve_at`, whose caller owns the data dir.
    _tmp: Option<tempfile::TempDir>,
}

impl Running {
    pub(crate) async fn stop(self) {
        self.shutdown.0.cancel();
        let _ = tokio::time::timeout(WAIT, self.task).await;
    }
}

pub(crate) fn local(dir: &Path) -> LocalDataDir {
    match check_data_dir(dir) {
        Ok(DataDirResolution::Local(d)) => d,
        other => panic!("temp dir is not a local data dir: {other:?}"),
    }
}

fn location(tmp: &tempfile::TempDir, data: &LocalDataDir) -> EndpointLocation {
    location_named(tmp.path(), data, "atlas-duck.sock")
}

/// An endpoint location for a server in `dir` (Unix: the socket `dir/s/<socket>`; Windows: the
/// user's pipe prefix, the server picks a fresh name and writes it to `<data>/endpoint`).
#[cfg(unix)]
pub(crate) fn location_named(dir: &Path, _data: &LocalDataDir, socket: &str) -> EndpointLocation {
    let dir = dir.join("s");
    if let Err(e) = atlas_duck_ipc::paths::ensure_socket_dir(&dir) {
        panic!("socket dir: {e}");
    }
    EndpointLocation::UnixSocket(dir.join(socket))
}

#[cfg(windows)]
pub(crate) fn location_named(_dir: &Path, data: &LocalDataDir, _socket: &str) -> EndpointLocation {
    match atlas_duck_ipc::paths::endpoint_location(data, "host") {
        Ok(l) => l,
        Err(e) => panic!("endpoint location: {e}"),
    }
}

/// Serves `fake` on a fresh temp endpoint.
pub(crate) async fn serve(fake: &Arc<Fake>) -> Running {
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => panic!("tempdir: {e}"),
    };
    let dir = tmp.path().join("data");
    if let Err(e) = std::fs::create_dir(&dir) {
        panic!("data dir: {e}");
    }
    let data = local(&dir);
    let location = location(&tmp, &data);
    let mut running = serve_at(fake, &data, location);
    running._tmp = Some(tmp);
    running
}

/// Serves `fake` at `location` over the caller's data dir (which outlives the server, so a test
/// can stop it and serve again on the same dir: an app restart).
pub(crate) fn serve_at(
    fake: &Arc<Fake>,
    data: &LocalDataDir,
    location: EndpointLocation,
) -> Running {
    let server = match IpcServer::bind_at(data, location.clone()) {
        Ok(s) => s.with_limits(ServerLimits::default()),
        Err(e) => panic!("bind: {e}"),
    };
    let cell = Arc::new(HandlerCell::new(fake.clone()));
    let shutdown = ShutdownSignal::default();
    let task = tokio::spawn(server.serve(cell, shutdown.clone()));
    Running {
        location,
        data: data.clone(),
        shutdown,
        task,
        _tmp: None,
    }
}

// ---------- the connector double ----------

/// A `LaunchSys` whose endpoint is present (nothing is launched) or never appears (the launch
/// poll runs until the deadline).
pub(crate) struct PresentSys {
    pub present: bool,
}

impl LaunchSys for PresentSys {
    fn gui_session(&self) -> bool {
        true
    }
    fn launch_env(&self) -> Vec<(OsString, OsString)> {
        Vec::new()
    }
    fn spawn_app(
        &self,
        _app: &Path,
        _env: &[(OsString, OsString)],
        _deadline: &Deadline,
    ) -> Result<(), LaunchError> {
        if self.present {
            Err(LaunchError::Unsupported)
        } else {
            Ok(())
        }
    }
    fn endpoint_present(&self, _data: &LocalDataDir, _host: &str) -> bool {
        self.present
    }
    fn base_dirs(&self) -> io::Result<BaseDirs> {
        Err(io::Error::other("no base dirs in tests"))
    }
}

pub(crate) enum Mode {
    /// Connect to the fake server (hello built with [`BUILD`]).
    Server(EndpointLocation),
    /// Connect fails with this error.
    Fail(fn() -> ConnectError),
    /// Connect never completes.
    Hang,
}

/// An interrupt source driven by a `Notify` (a stored permit fires at once).
pub(crate) struct NotifyInterrupt(pub Arc<Notify>);

impl Interrupts for NotifyInterrupt {
    fn next(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(self.0.notified())
    }
}

pub(crate) struct TestConnector {
    pub discovery: Discovery,
    pub mode: Mode,
    pub interrupt: Arc<Notify>,
    /// `false`: the endpoint never appears, so `ensure_running` launches and polls.
    pub present: bool,
    pub connects: AtomicUsize,
    pub notices: Mutex<Vec<(String, Option<String>, Instant)>>,
    /// Keeps a counting double's data dir alive.
    _keep: Option<tempfile::TempDir>,
    /// The `build_id` every hello carries (default [`BUILD`]).
    hello_build: Mutex<String>,
    /// Replaces the `Mode::Server` location (a restarted server listens elsewhere).
    endpoint: Mutex<Option<EndpointLocation>>,
    /// `discover` calls: one per attempt to reach the app (launch check included).
    discovers: AtomicUsize,
}

impl TestConnector {
    pub(crate) fn new(data: LocalDataDir, mode: Mode) -> TestConnector {
        TestConnector {
            discovery: Discovery {
                host: "host".to_owned(),
                data: DataState::Local(data),
                app: AppLocation::NotFound,
            },
            mode,
            interrupt: Arc::new(Notify::new()),
            present: true,
            connects: AtomicUsize::new(0),
            notices: Mutex::new(Vec::new()),
            _keep: None,
            hello_build: Mutex::new(BUILD.to_owned()),
            endpoint: Mutex::new(None),
            discovers: AtomicUsize::new(0),
        }
    }

    pub(crate) fn set_hello_build(&self, build: &str) {
        if let Ok(mut g) = self.hello_build.lock() {
            *g = build.to_owned();
        }
    }

    /// Points `Mode::Server` connects at `location` from now on.
    pub(crate) fn set_endpoint(&self, location: EndpointLocation) {
        if let Ok(mut g) = self.endpoint.lock() {
            *g = Some(location);
        }
    }

    pub(crate) fn discover_count(&self) -> usize {
        self.discovers.load(Ordering::SeqCst)
    }

    /// A connector over a fresh empty data dir whose connect fails with `fail`.
    pub(crate) fn failing(fail: fn() -> ConnectError) -> TestConnector {
        let tmp = match tempfile::tempdir() {
            Ok(t) => t,
            Err(e) => panic!("tempdir: {e}"),
        };
        let mut c = TestConnector::new(local(tmp.path()), Mode::Fail(fail));
        c._keep = Some(tmp);
        c
    }

    pub(crate) fn connect_count(&self) -> usize {
        self.connects.load(Ordering::SeqCst)
    }

    pub(crate) fn notice_lines(&self) -> Vec<(String, Option<String>, Instant)> {
        self.notices.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl Connector for TestConnector {
    fn discover(&self) -> Discovery {
        self.discovers.fetch_add(1, Ordering::SeqCst);
        self.discovery.clone()
    }

    fn launch_sys(&self) -> Arc<dyn LaunchSys + Send> {
        Arc::new(PresentSys {
            present: self.present,
        })
    }

    fn connect<'a>(
        &'a self,
        ctx: &'a ClientContext,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<IpcClient, ConnectError>> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        let build = self
            .hello_build
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| BUILD.to_owned());
        let repointed = self.endpoint.lock().ok().and_then(|g| g.clone());
        Box::pin(async move {
            match &self.mode {
                Mode::Fail(make) => Err(make()),
                Mode::Hang => std::future::pending().await,
                Mode::Server(location) => {
                    let hello = Hello {
                        build_id: build,
                        ..ctx.hello.clone()
                    };
                    let location = repointed.as_ref().unwrap_or(location);
                    connect_server(location, &ctx.data_dir, hello, deadline).await
                }
            }
        })
    }

    fn interrupts(&self) -> Box<dyn Interrupts> {
        Box::new(NotifyInterrupt(self.interrupt.clone()))
    }

    fn notice(&self, request_id: &str, params_sha256: Option<&str>) {
        if let Ok(mut g) = self.notices.lock() {
            g.push((
                request_id.to_owned(),
                params_sha256.map(str::to_owned),
                Instant::now(),
            ));
        }
    }
}

#[cfg(unix)]
async fn connect_server(
    location: &EndpointLocation,
    data: &LocalDataDir,
    hello: Hello,
    deadline: Instant,
) -> Result<IpcClient, ConnectError> {
    let check = atlas_duck_ipc::transport::unix::SameUser;
    IpcClient::connect_at(location, data, &hello, &check, deadline).await
}

/// Windows: the production `connect`, which reads `<data>/endpoint` and checks the prefix.
#[cfg(windows)]
async fn connect_server(
    _location: &EndpointLocation,
    data: &LocalDataDir,
    hello: Hello,
    deadline: Instant,
) -> Result<IpcClient, ConnectError> {
    let ctx = ClientContext {
        data_dir: data.clone(),
        host: "host".to_owned(),
        hello,
    };
    IpcClient::connect(&ctx, deadline).await
}
