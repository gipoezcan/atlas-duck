//! Test doubles for the connected commands: a recording fake `RequestHandler` served by the real
//! `IpcServer` (Unix socket / Windows pipe in a temp dir), and a `Connector` that reaches it.
//! Adapted from the ipc crate's `tests/common`.
#![allow(dead_code)]

use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atlas_duck_ipc::client::{ClientContext, ConnectError, IpcClient};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::paths::{
    BaseDirs, DataDirResolution, EndpointLocation, LocalDataDir, check_data_dir,
};
use atlas_duck_ipc::proto::{
    AwaitParams, ConnectionMeta, Hello, HelloReply, ListState, MatchParams, ProgressSink,
    RequestHandler, SubmitParams, SubmitReply,
};
use atlas_duck_ipc::server::{HandlerCell, IpcServer, ServerLimits, ShutdownSignal};
use serde_json::json;
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
        let mut envelope = Fake::answer(method);
        envelope.op_id = Some(p.op_id.clone());
        envelope.instance = p.instance.clone();
        if let Ok(mut g) = self.submits.lock() {
            g.push(p);
        }
        envelope.status = self.submit_status;
        if self.submit_status == Status::Pending {
            envelope.request_id = Some(REQ_ID.to_owned());
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
    async fn hello(&self, _conn: &ConnectionMeta, _h: Hello) -> Result<HelloReply, Envelope> {
        Ok(HelloReply {
            build_id: BUILD.to_owned(),
        })
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
        _progress: &dyn ProgressSink,
    ) -> Envelope {
        self.record(Kind::AwaitStart, Some(a.request_id.clone()));
        let id = a.request_id.clone();
        if let Ok(mut g) = self.awaits.lock() {
            g.push(a);
        }
        tokio::time::sleep(self.await_delay).await;
        self.record(Kind::AwaitDone, Some(id));
        Fake::answer("request.await")
    }

    async fn status(&self, request_id: &str) -> Envelope {
        self.record(Kind::Status, Some(request_id.to_owned()));
        Fake::answer("request.status")
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
    _tmp: tempfile::TempDir,
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

#[cfg(unix)]
fn location(tmp: &tempfile::TempDir, _data: &LocalDataDir) -> EndpointLocation {
    let dir = tmp.path().join("s");
    if let Err(e) = atlas_duck_ipc::paths::ensure_socket_dir(&dir) {
        panic!("socket dir: {e}");
    }
    EndpointLocation::UnixSocket(dir.join("atlas-duck.sock"))
}

#[cfg(windows)]
fn location(_tmp: &tempfile::TempDir, data: &LocalDataDir) -> EndpointLocation {
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
    let server = match IpcServer::bind_at(&data, location.clone()) {
        Ok(s) => s.with_limits(ServerLimits::default()),
        Err(e) => panic!("bind: {e}"),
    };
    let cell = Arc::new(HandlerCell::new(fake.clone()));
    let shutdown = ShutdownSignal::default();
    let task = tokio::spawn(server.serve(cell, shutdown.clone()));
    Running {
        location,
        data,
        shutdown,
        task,
        _tmp: tmp,
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
        }
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
        Box::pin(async move {
            match &self.mode {
                Mode::Fail(make) => Err(make()),
                Mode::Hang => std::future::pending().await,
                Mode::Server(location) => {
                    let hello = Hello {
                        build_id: BUILD.to_owned(),
                        ..ctx.hello.clone()
                    };
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
