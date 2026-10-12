#![cfg(feature = "async")]
//! `IpcClient` (§3.2 (a) before any byte, (b) hello build match, §3.3, §4.7, PD-08, PD-27):
//! discovery, the owner-checked connect, the hello round trip and its refusals, calls with
//! progress, and the connection-lost and deadline paths. The server is the in-process
//! `IpcServer` over the fake handler, or a raw listener where the server must misbehave.

mod common;

use std::cmp::Ordering;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::client::{
    ClientContext, ClientError, ConnectError, IpcClient, ServerCheck, compare_build_versions,
};
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::paths::{EndpointLocation, LocalDataDir};
use atlas_duck_ipc::proto::{
    AgentNameSource, AwaitParams, ClientKind, Hello, ProgressNotification, RequestHandler,
    SubmitParams, SubmitReply,
};
use atlas_duck_ipc::rpc::{OpsListParams, codes, method};
use atlas_duck_ipc::server::{HandlerCell, IpcServer, ServerLimits, ShutdownSignal};
use atlas_duck_ipc::transport::Conn;
use common::{BUILD, Fake, Kind, WAIT, local};
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;

// ---------- harness ----------

struct Running {
    location: EndpointLocation,
    data: LocalDataDir,
    name: String,
    shutdown: ShutdownSignal,
    task: JoinHandle<()>,
    _tmp: tempfile::TempDir,
}

impl Running {
    async fn stop(self) {
        self.shutdown.0.cancel();
        tokio::time::timeout(WAIT, self.task)
            .await
            .expect("serve did not return after shutdown")
            .expect("serve panicked");
    }
}

/// A temp dir with a local data dir `data/` in it.
fn data_dir() -> (tempfile::TempDir, LocalDataDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    std::fs::create_dir(&dir).expect("data dir");
    let data = local(&dir);
    (tmp, data)
}

#[cfg(unix)]
fn location(tmp: &tempfile::TempDir, _data: &LocalDataDir) -> EndpointLocation {
    let dir = tmp.path().join("s");
    atlas_duck_ipc::paths::ensure_socket_dir(&dir).expect("socket dir");
    EndpointLocation::UnixSocket(dir.join("atlas-duck.sock"))
}

#[cfg(windows)]
fn location(_tmp: &tempfile::TempDir, data: &LocalDataDir) -> EndpointLocation {
    atlas_duck_ipc::paths::endpoint_location(data, "host").expect("location")
}

async fn start_with(handler: Arc<dyn RequestHandler>, limits: ServerLimits) -> Running {
    let (tmp, data) = data_dir();
    let location = location(&tmp, &data);
    let server = IpcServer::bind_at(&data, location.clone())
        .expect("bind")
        .with_limits(limits);
    let name = server.endpoint_name().to_owned();
    let cell = Arc::new(HandlerCell::new(handler));
    let shutdown = ShutdownSignal::default();
    let task = tokio::spawn(server.serve(cell, shutdown.clone()));
    Running {
        location,
        data,
        name,
        shutdown,
        task,
        _tmp: tmp,
    }
}

async fn start(fake: &Arc<Fake>) -> Running {
    start_with(fake.clone(), ServerLimits::default()).await
}

fn hello(build: &str) -> Hello {
    Hello {
        build_id: build.to_owned(),
        client_kind: ClientKind::Cli,
        agent_name: Some("tester".to_owned()),
        agent_name_source: AgentNameSource::Flag,
        cwd_basename: "repo".to_owned(),
    }
}

fn soon() -> Instant {
    Instant::now() + WAIT
}

#[cfg(unix)]
fn same_user() -> atlas_duck_ipc::transport::unix::SameUser {
    atlas_duck_ipc::transport::unix::SameUser
}

#[cfg(windows)]
fn same_user() -> atlas_duck_ipc::transport::windows::SameUser {
    atlas_duck_ipc::transport::windows::SameUser::current().expect("own SID")
}

/// Unix: the explicit socket (the OS socket dir is not the test's); Windows: the production
/// `connect`, which reads `<data>/endpoint` and checks the prefix.
#[cfg(unix)]
async fn connect_to(
    location: &EndpointLocation,
    data: &LocalDataDir,
    hello: Hello,
    deadline: Instant,
) -> Result<IpcClient, ConnectError> {
    IpcClient::connect_at(location, data, &hello, &same_user(), deadline).await
}

#[cfg(windows)]
async fn connect_to(
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

async fn connect(srv: &Running, hello: Hello) -> Result<IpcClient, ConnectError> {
    connect_to(&srv.location, &srv.data, hello, soon()).await
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(150)).await;
}

/// `failed` / `protocol_mismatch` with `details {client_build, server_build}` (as `core`).
fn mismatch(client_build: &str, server_build: &str) -> Envelope {
    let mut env = Envelope::failed(
        ErrorCode::ProtocolMismatch,
        true,
        "client and app builds differ",
    );
    if let Some(err) = env.error.as_mut() {
        err.details = json!({"client_build": client_build, "server_build": server_build})
            .as_object()
            .cloned();
    }
    env
}

fn data_by(env: &Envelope) -> (String, String) {
    let data = env.data.as_ref().expect("data");
    (
        data["by"].as_str().unwrap_or("?").to_owned(),
        data["method"].as_str().unwrap_or("?").to_owned(),
    )
}

fn await_params() -> AwaitParams {
    AwaitParams {
        request_id: "req_00000000000000000000000000000001".to_owned(),
        timeout_ms: None,
    }
}

// ---------- raw servers ----------

/// What a raw listener does with each accepted connection.
#[derive(Clone)]
enum Raw {
    /// Holds the connection open and never reads or answers.
    Silent,
    /// Reads one frame, then closes without answering.
    CloseAfterFrame,
    /// Reads until EOF and reports how many bytes arrived.
    Count(tokio::sync::mpsc::UnboundedSender<usize>),
}

async fn serve_raw(conn: Conn, raw: Raw) {
    let (mut rd, _wr) = conn.split();
    match raw {
        Raw::Silent => tokio::time::sleep(Duration::from_secs(60)).await,
        Raw::CloseAfterFrame => {
            let _ = atlas_duck_ipc::rpc::frame::read_frame_async(&mut rd, 1 << 20).await;
        }
        Raw::Count(tx) => {
            let mut total = 0;
            let mut buf = [0u8; 4096];
            while let Ok(n) = rd.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                total += n;
            }
            let _ = tx.send(total);
        }
    }
}

/// A raw listener at this user's endpoint (Unix: a socket in `tmp`; Windows: a pipe with
/// the user's prefix, its name written to `<data>/endpoint`).
#[cfg(unix)]
fn raw_server(
    tmp: &tempfile::TempDir,
    data: &LocalDataDir,
    raw: Raw,
) -> (EndpointLocation, JoinHandle<()>) {
    let location = location(tmp, data);
    let EndpointLocation::UnixSocket(path) = &location else {
        panic!("not a socket location");
    };
    let listener = atlas_duck_ipc::transport::unix::Listener::bind(path).expect("raw bind");
    let task = tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            tokio::spawn(serve_raw(conn, raw.clone()));
        }
    });
    (location, task)
}

#[cfg(windows)]
fn raw_server(
    tmp: &tempfile::TempDir,
    data: &LocalDataDir,
    raw: Raw,
) -> (EndpointLocation, JoinHandle<()>) {
    let location = location(tmp, data);
    let EndpointLocation::WindowsPipePrefix(prefix) = &location else {
        panic!("not a pipe location");
    };
    let mut listener =
        atlas_duck_ipc::transport::windows::PipeListener::bind(prefix).expect("raw bind");
    atlas_duck_ipc::paths::write_endpoint_file(data, listener.name()).expect("endpoint file");
    let task = tokio::spawn(async move {
        while let Ok((pipe, _)) = listener.accept().await {
            tokio::spawn(serve_raw(Conn::new(pipe), raw.clone()));
        }
    });
    (location, task)
}

/// An owner check that always says no.
struct Never;

#[cfg(unix)]
impl atlas_duck_ipc::transport::unix::OwnerCheck for Never {
    fn server_ok(&self, _peer: &atlas_duck_ipc::transport::unix::PeerCred) -> bool {
        false
    }
}

#[cfg(windows)]
impl atlas_duck_ipc::transport::windows::PipeOwnerProbe for Never {
    fn owner_ok(&self, _client: &tokio::net::windows::named_pipe::NamedPipeClient) -> bool {
        false
    }
}

/// Waits a moment inside the owner check and records whether the server had already seen
/// `hello` (it would, had the client written before asking), then defers to `SameUser`.
struct Recording {
    fake: Arc<Fake>,
    calls: AtomicUsize,
    hello_before_check: AtomicBool,
}

impl Recording {
    fn observe(&self) {
        self.calls.fetch_add(1, AtomicOrdering::SeqCst);
        std::thread::sleep(Duration::from_millis(200));
        if self.fake.count(Kind::Hello) > 0 {
            self.hello_before_check.store(true, AtomicOrdering::SeqCst);
        }
    }
}

#[cfg(unix)]
impl atlas_duck_ipc::transport::unix::OwnerCheck for Recording {
    fn server_ok(&self, peer: &atlas_duck_ipc::transport::unix::PeerCred) -> bool {
        self.observe();
        same_user().server_ok(peer)
    }
}

#[cfg(windows)]
impl atlas_duck_ipc::transport::windows::PipeOwnerProbe for Recording {
    fn owner_ok(&self, client: &tokio::net::windows::named_pipe::NamedPipeClient) -> bool {
        self.observe();
        same_user().owner_ok(client)
    }
}

// ---------- round trip ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_hello_call_roundtrip() {
    let fake = Arc::new(Fake::new("A"));
    let srv = start(&fake).await;
    assert_eq!(
        atlas_duck_ipc::paths::read_endpoint_file(&srv.data).expect("endpoint file"),
        Some(srv.name.clone())
    );
    let mut c = connect(&srv, hello(BUILD)).await.expect("connect");
    assert!(!c.written_request(), "hello counted as a request");

    let env: Envelope = c
        .call(
            method::OPS_LIST,
            OpsListParams {
                instance: Some("jira".to_owned()),
            },
        )
        .await
        .expect("ops.list");
    assert!(c.written_request());
    assert_eq!(data_by(&env), ("A".to_owned(), "ops.list".to_owned()));
    assert_eq!(fake.of(Kind::OpsList)[0].detail.as_deref(), Some("jira"));

    let reply: SubmitReply = c
        .call(
            method::REQUEST_SUBMIT,
            SubmitParams {
                op_id: "jira.issue.get".to_owned(),
                params: json!({"key": "A-1"}),
                instance: None,
                reason: None,
            },
        )
        .await
        .expect("submit");
    assert_eq!(reply.envelope.status, Status::Pending);
    assert_eq!(reply.params_sha256, Some("00".repeat(32)));

    // An error answer is the RPC error with its envelope; the connection stays usable.
    let err = c
        .call::<Envelope>("no.such.method", json!({}))
        .await
        .expect_err("unknown method answered");
    match err {
        ClientError::Rpc(e) => {
            assert_eq!(e.code, codes::METHOD_NOT_FOUND);
            let env = e.data.expect("envelope");
            assert_eq!(env.error.expect("error").code, ErrorCode::ProtocolError);
        }
        other => panic!("expected Rpc, got {other:?}"),
    }
    let env: Envelope = c.call(method::DOCTOR, json!({})).await.expect("doctor");
    assert_eq!(data_by(&env).1, "doctor");

    let hellos = fake.of(Kind::Hello);
    assert_eq!(hellos.len(), 1);
    assert_eq!(hellos[0].detail.as_deref(), Some(BUILD));
    drop(c);
    fake.wait_for(Kind::Disconnected, 1).await;
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_call_answer_is_ignored() {
    let mut fake = Fake::new("A");
    fake.await_delay = Duration::from_millis(200);
    fake.submit_delay = Duration::from_millis(500);
    let fake = Arc::new(fake);
    let srv = start(&fake).await;
    let mut c = connect(&srv, hello(BUILD)).await.expect("connect");
    let cut = tokio::time::timeout(
        Duration::from_millis(50),
        c.call::<Envelope>(method::REQUEST_AWAIT, await_params()),
    )
    .await;
    assert!(cut.is_err(), "await answered within 50 ms");
    // The stale answer arrives while the next call (a slower submit) waits: routed by id, it
    // never reaches that call.
    let reply: SubmitReply = c
        .call(
            method::REQUEST_SUBMIT,
            SubmitParams {
                op_id: "jira.issue.get".to_owned(),
                params: json!({}),
                instance: None,
                reason: None,
            },
        )
        .await
        .expect("submit");
    assert_eq!(data_by(&reply.envelope).1, "request.submit");
    let done = fake.of(Kind::AwaitDone);
    let submitted = fake.of(Kind::SubmitDone);
    assert!(
        done[0].at < submitted[0].at,
        "the stale answer did not arrive during the submit"
    );
    settle().await;
    let env: Envelope = c.call(method::DOCTOR, json!({})).await.expect("doctor");
    assert_eq!(data_by(&env).1, "doctor");
    srv.stop().await;
}

// ---------- hello build match (§3.2 (b), PD-08) ----------

#[test]
fn compare_build_versions_table() {
    let table: &[(&str, &str, Option<Ordering>)] = &[
        ("0.1.0+x", "0.1.0+y", Some(Ordering::Equal)),
        ("0.1.0", "0.1.0+aaaaaaaaaaaa", Some(Ordering::Equal)),
        ("0.2.0", "0.1.9", Some(Ordering::Greater)),
        ("0.1.9", "0.2.0", Some(Ordering::Less)),
        ("0.10.0", "0.9.0", Some(Ordering::Greater)),
        ("1.0.0+unknown", "0.99.99+abc", Some(Ordering::Greater)),
        (
            "0.0.1+aaaaaaaaaaaa",
            "99.0.0+bbbbbbbbbbbb",
            Some(Ordering::Less),
        ),
        ("garbage", "0.1.0", None),
        ("0.1.0", "garbage", None),
        ("", "0.1.0", None),
        ("+abc", "0.1.0", None),
        ("0.1", "0.1.0", None),
        ("0.1.0.0", "0.1.0", None),
        ("0.1.x", "0.1.0", None),
        ("0..1", "0.1.0", None),
        ("0.+1.0", "0.1.0", None),
        ("0.-1.0", "0.1.0", None),
        (" 0.1.0", "0.1.0", None),
        ("0.1.0-rc1", "0.1.0", None),
        ("0.1.99999999999999999999", "0.1.0", None),
        ("test-build", BUILD_ID, None),
    ];
    for (client, server, want) in table {
        assert_eq!(
            compare_build_versions(client, server),
            *want,
            "{client:?} vs {server:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s01_build_mismatch_before_submit() {
    assert_eq!(
        compare_build_versions(BUILD_ID, "0.0.1+aaaaaaaaaaaa"),
        Some(Ordering::Greater),
        "the test needs a workspace version above 0.0.1"
    );
    for (server_build, newer) in [("0.0.1+aaaaaaaaaaaa", true), ("99.0.0+bbbbbbbbbbbb", false)] {
        let fake = Arc::new(Fake::new("A"));
        *fake.hello_refusal.lock().expect("lock") = Some(mismatch(BUILD_ID, server_build));
        let srv = start(&fake).await;
        let err = connect(&srv, hello(BUILD_ID))
            .await
            .expect_err("connected despite the mismatch");
        match err {
            ConnectError::BuildMismatch {
                client_newer,
                client_build,
                server_build: got,
            } => {
                assert_eq!(client_newer, newer, "server {server_build}");
                assert_eq!(client_build, BUILD_ID);
                assert_eq!(got, server_build);
            }
            other => panic!("expected BuildMismatch, got {other:?}"),
        }
        settle().await;
        let kinds: Vec<Kind> = fake.events().iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![Kind::Hello],
            "a method followed the refused hello"
        );
        srv.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn success_reply_with_another_build_is_a_mismatch() {
    // The fake accepts every hello and answers with its own build ("test-build").
    let fake = Arc::new(Fake::new("A"));
    let srv = start(&fake).await;
    let err = connect(&srv, hello("0.1.0+cccccccccccc"))
        .await
        .expect_err("connected to another build");
    match err {
        ConnectError::BuildMismatch {
            client_newer,
            client_build,
            server_build,
        } => {
            assert!(!client_newer);
            assert_eq!(client_build, "0.1.0+cccccccccccc");
            assert_eq!(server_build, BUILD);
        }
        other => panic!("expected BuildMismatch, got {other:?}"),
    }
    fake.wait_for(Kind::Disconnected, 1).await;
    let kinds: Vec<Kind> = fake.events().iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![Kind::Hello, Kind::Disconnected]);
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn other_hello_refusal_passes_the_envelope() {
    let fake = Arc::new(Fake::new("A"));
    let refusal = Envelope::failed(ErrorCode::Locked, true, "atlas-duck is locked");
    *fake.hello_refusal.lock().expect("lock") = Some(refusal.clone());
    let srv = start(&fake).await;
    match connect(&srv, hello(BUILD)).await {
        Err(ConnectError::Hello(env)) => assert_eq!(env, refusal),
        other => panic!("expected Hello(env), got {other:?}"),
    }
    srv.stop().await;
}

// ---------- discovery and connect failures ----------

/// The production `connect` (this user's real endpoint location and owner check) with no
/// server: not running, and the client creates nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_connect_without_server_is_not_running() {
    let (_tmp, data) = data_dir();
    let ctx = ClientContext {
        data_dir: data.clone(),
        host: "host".to_owned(),
        hello: hello(BUILD),
    };

    #[cfg(unix)]
    {
        let location = atlas_duck_ipc::paths::endpoint_location(&data, "host").expect("location");
        let EndpointLocation::UnixSocket(path) = location else {
            panic!("not a socket location");
        };
        if path.exists() {
            eprintln!("skipped: {} exists (an app may be running)", path.display());
            return;
        }
        let dir = path.parent().expect("socket dir").to_path_buf();
        let dir_existed = dir.exists();
        let got = IpcClient::connect(&ctx, soon()).await;
        assert!(matches!(got, Err(ConnectError::NotRunning)), "{got:?}");
        if !dir_existed {
            assert!(!dir.exists(), "the client created the socket dir");
        }
    }

    #[cfg(windows)]
    {
        let got = IpcClient::connect(&ctx, soon()).await;
        assert!(matches!(got, Err(ConnectError::NotRunning)), "{got:?}");
        let entries = std::fs::read_dir(data.path()).expect("data dir").count();
        assert_eq!(entries, 0, "the client wrote into the data dir");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn not_running_when_no_endpoint() {
    let (tmp, data) = data_dir();

    #[cfg(unix)]
    {
        let dir = tmp.path().join("s");
        let path = dir.join("atlas-duck.sock");
        let location = EndpointLocation::UnixSocket(path.clone());
        // No socket dir: not running, and the client creates nothing.
        let got = connect_to(&location, &data, hello(BUILD), soon()).await;
        assert!(matches!(got, Err(ConnectError::NotRunning)), "{got:?}");
        assert!(!dir.exists(), "the client created the socket dir");
        // The dir, but no socket.
        atlas_duck_ipc::paths::ensure_socket_dir(&dir).expect("socket dir");
        let got = connect_to(&location, &data, hello(BUILD), soon()).await;
        assert!(matches!(got, Err(ConnectError::NotRunning)), "{got:?}");
        // A stale socket nobody listens on (ECONNREFUSED).
        drop(std::os::unix::net::UnixListener::bind(&path).expect("stale socket"));
        assert!(path.exists());
        let got = connect_to(&location, &data, hello(BUILD), soon()).await;
        assert!(matches!(got, Err(ConnectError::NotRunning)), "{got:?}");
    }

    #[cfg(windows)]
    {
        use atlas_duck_ipc::paths::{ENDPOINT_FILE, write_endpoint_file};
        use atlas_duck_ipc::transport::windows::PipeListener;

        let location = location(&tmp, &data);
        let EndpointLocation::WindowsPipePrefix(prefix) = &location else {
            panic!("not a pipe location");
        };
        // No endpoint file.
        let got = connect_to(&location, &data, hello(BUILD), soon()).await;
        assert!(matches!(got, Err(ConnectError::NotRunning)), "{got:?}");

        // A live pipe under another prefix: not ours, never opened.
        let foreign = r"\\.\pipe\atlas-duck-ffffffffffffffff-";
        assert_ne!(prefix, foreign);
        let mut squatter = PipeListener::bind(foreign).expect("foreign pipe");
        write_endpoint_file(&data, squatter.name()).expect("endpoint file");
        let got = connect_to(&location, &data, hello(BUILD), soon()).await;
        assert!(matches!(got, Err(ConnectError::NotRunning)), "{got:?}");
        let opened = tokio::time::timeout(Duration::from_millis(300), squatter.accept()).await;
        assert!(opened.is_err(), "the client opened the foreign pipe");

        // Our prefix, but the pipe is gone (a stale file).
        write_endpoint_file(&data, &format!("{prefix}{}", "0".repeat(32))).expect("endpoint file");
        let got = connect_to(&location, &data, hello(BUILD), soon()).await;
        assert!(matches!(got, Err(ConnectError::NotRunning)), "{got:?}");

        // A file the server never writes (trailing newline).
        std::fs::write(
            data.path().join(ENDPOINT_FILE),
            format!("{prefix}{}\n", "0".repeat(32)),
        )
        .expect("corrupt endpoint file");
        let got = connect_to(&location, &data, hello(BUILD), soon()).await;
        assert!(matches!(got, Err(ConnectError::NotRunning)), "{got:?}");
    }
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoint_file_read_on_every_connect() {
    let a = Arc::new(Fake::new("A"));
    let b = Arc::new(Fake::new("B"));
    let srv_a = start(&a).await;
    let srv_b = start(&b).await;
    let mut c = connect(&srv_a, hello(BUILD)).await.expect("connect A");
    let env: Envelope = c.call(method::DOCTOR, json!({})).await.expect("doctor");
    assert_eq!(data_by(&env).0, "A");
    // The server rebinds under a fresh name (as after an accept failure): the next connect
    // follows the file.
    atlas_duck_ipc::paths::write_endpoint_file(&srv_a.data, &srv_b.name).expect("rewrite");
    let mut c = connect(&srv_a, hello(BUILD)).await.expect("connect B");
    let env: Envelope = c.call(method::DOCTOR, json!({})).await.expect("doctor");
    assert_eq!(data_by(&env).0, "B");
    srv_a.stop().await;
    srv_b.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn busy_maps_to_busy_5() {
    let fake = Arc::new(Fake::new("A"));
    let limits = ServerLimits {
        max_connections: 1,
        ..ServerLimits::default()
    };
    let srv = start_with(fake.clone(), limits).await;
    let _first = connect(&srv, hello(BUILD)).await.expect("first connect");
    match connect(&srv, hello(BUILD)).await {
        Err(ConnectError::Busy { retry_after_s }) => assert_eq!(retry_after_s, 5),
        other => panic!("expected Busy, got {other:?}"),
    }
    assert_eq!(
        fake.count(Kind::Hello),
        1,
        "the busy hello reached the handler"
    );
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hello_eof_is_server_identity() {
    // A server that reads the hello frame and closes without an answer (what a Windows server
    // does to a client whose SID it refuses).
    let (tmp, data) = data_dir();
    let (location, task) = raw_server(&tmp, &data, Raw::CloseAfterFrame);
    let got = connect_to(&location, &data, hello(BUILD), soon()).await;
    assert!(matches!(got, Err(ConnectError::ServerIdentity)), "{got:?}");
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deadline_exceeded_during_hello() {
    let (tmp, data) = data_dir();
    let (location, task) = raw_server(&tmp, &data, Raw::Silent);
    let t0 = Instant::now();
    let got = connect_to(
        &location,
        &data,
        hello(BUILD),
        t0 + Duration::from_millis(300),
    )
    .await;
    let waited = t0.elapsed();
    assert!(
        matches!(got, Err(ConnectError::DeadlineExceeded)),
        "{got:?}"
    );
    assert!(
        waited >= Duration::from_millis(250),
        "gave up after {waited:?}"
    );
    assert!(
        waited < Duration::from_millis(600),
        "gave up after {waited:?}"
    );

    // A deadline already past: nothing is attempted.
    let t0 = Instant::now();
    let got = connect_to(&location, &data, hello(BUILD), t0).await;
    assert!(
        matches!(got, Err(ConnectError::DeadlineExceeded)),
        "{got:?}"
    );
    assert!(t0.elapsed() < Duration::from_millis(100));
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_check_runs_before_first_byte() {
    // A failed owner check: the server reads zero bytes.
    let (tmp, data) = data_dir();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let (location, task) = raw_server(&tmp, &data, Raw::Count(tx));
    let check: &dyn ServerCheck = &Never;
    let got = IpcClient::connect_at(&location, &data, &hello(BUILD), check, soon()).await;
    assert!(matches!(got, Err(ConnectError::ServerIdentity)), "{got:?}");
    let bytes = tokio::time::timeout(WAIT, rx.recv())
        .await
        .expect("the server saw no connection close")
        .expect("count");
    assert_eq!(
        bytes, 0,
        "bytes reached a server that failed the owner check"
    );
    task.abort();

    // A passing check runs before the hello is written: while it runs, the server has seen
    // no hello.
    let fake = Arc::new(Fake::new("A"));
    let srv = start(&fake).await;
    let recording = Recording {
        fake: fake.clone(),
        calls: AtomicUsize::new(0),
        hello_before_check: AtomicBool::new(false),
    };
    let check: &dyn ServerCheck = &recording;
    let c = IpcClient::connect_at(&srv.location, &srv.data, &hello(BUILD), check, soon())
        .await
        .expect("connect");
    assert_eq!(recording.calls.load(AtomicOrdering::SeqCst), 1);
    assert!(
        !recording.hello_before_check.load(AtomicOrdering::SeqCst),
        "hello reached the server before the owner check"
    );
    assert_eq!(fake.count(Kind::Hello), 1);
    drop(c);
    srv.stop().await;
}

// ---------- calls ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn progress_callback_receives_notifications() {
    let mut fake = Fake::new("A");
    fake.progress = vec![Status::Pending, Status::Executing];
    fake.await_delay = Duration::from_millis(100);
    let fake = Arc::new(fake);
    let srv = start(&fake).await;
    let mut c = connect(&srv, hello(BUILD)).await.expect("connect");
    let mut seen: Vec<ProgressNotification> = Vec::new();
    let env: Envelope = c
        .call_with_progress(method::REQUEST_AWAIT, await_params(), &mut |n| seen.push(n))
        .await
        .expect("await");
    assert_eq!(data_by(&env).1, "request.await");
    let statuses: Vec<Status> = seen.iter().map(|n| n.status).collect();
    assert_eq!(statuses, vec![Status::Pending, Status::Executing]);
    assert!(
        seen.iter()
            .all(|n| n.request_id == await_params().request_id)
    );

    // A plain call drops notifications.
    let env: Envelope = c
        .call(method::REQUEST_AWAIT, await_params())
        .await
        .expect("await");
    assert_eq!(data_by(&env).1, "request.await");
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_lost_mid_call() {
    let mut fake = Fake::new("A");
    fake.await_delay = Duration::from_secs(30);
    let fake = Arc::new(fake);
    let srv = start(&fake).await;
    let mut c = connect(&srv, hello(BUILD)).await.expect("connect");
    let call = c.call::<Envelope>(method::REQUEST_AWAIT, await_params());
    let kill = async {
        fake.wait_for(Kind::AwaitStart, 1).await;
        // Dropping `serve` drops every connection at once.
        srv.task.abort();
    };
    let (got, ()) = tokio::join!(tokio::time::timeout(WAIT, call), kill);
    let got = got.expect("no answer and no EOF within WAIT");
    assert!(matches!(got, Err(ClientError::ConnectionLost)), "{got:?}");
    assert!(c.written_request());
    // Every later call fails the same way, without waiting.
    let again = tokio::time::timeout(WAIT, c.call::<Envelope>(method::DOCTOR, json!({})))
        .await
        .expect("a call on a lost connection hung");
    assert!(
        matches!(again, Err(ClientError::ConnectionLost)),
        "{again:?}"
    );
}
