#![cfg(feature = "async")]
//! `SharedClient` (Δ1, PD-115): concurrent calls over one connection, routed by id; progress
//! routed by `request_id`; a closed connection fails every waiter; a `null`-id error closes the
//! client; at most `SHARED_IN_FLIGHT` requests held by the server; a wrong-shaped answer fails
//! only its own call. The server is the in-process `IpcServer` over a scripted handler, or a
//! raw peer where the server must misbehave. The unit tests that hold the writer live in
//! `src/client/shared.rs`.

type TestResult = Result<(), Box<dyn std::error::Error>>;

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_duck_ipc::client::{
    ClientError, ConnectError, IpcClient, SHARED_IN_FLIGHT, Sent, SharedClient,
};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::paths::{EndpointLocation, LocalDataDir};
use atlas_duck_ipc::proto::{
    AgentNameSource, AwaitParams, ClientKind, ConnectionMeta, Hello, HelloReply, ListState,
    MatchParams, ProgressNotification, ProgressSink, RequestHandler, SubmitParams, SubmitReply,
};
use atlas_duck_ipc::rpc::frame::{read_frame_async, write_frame_async};
use atlas_duck_ipc::rpc::{IdParams, method};
use atlas_duck_ipc::sandbox::MAX_FRAME_BYTES;
use atlas_duck_ipc::server::{
    HELLO_MAX_BYTES, HandlerCell, IpcServer, ServerLimits, ShutdownSignal,
};
use atlas_duck_ipc::transport::Conn;
use common::{BUILD, Fake, Kind, WAIT, local};
use serde_json::{Value, json};
use tokio::sync::{Barrier, mpsc};
use tokio::task::JoinHandle;

// ---------- harness ----------

struct Running {
    location: EndpointLocation,
    data: LocalDataDir,
    shutdown: ShutdownSignal,
    task: JoinHandle<()>,
    _tmp: tempfile::TempDir,
}

impl Running {
    async fn stop(self) -> TestResult {
        self.shutdown.0.cancel();
        tokio::time::timeout(WAIT, self.task).await??;
        Ok(())
    }
}

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

async fn start(handler: Arc<dyn RequestHandler>) -> Running {
    let (tmp, data) = data_dir();
    let location = location(&tmp, &data);
    let server = IpcServer::bind_at(&data, location.clone())
        .expect("bind")
        .with_limits(ServerLimits::default());
    let cell = Arc::new(HandlerCell::new(handler));
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

fn hello() -> Hello {
    Hello {
        build_id: BUILD.to_owned(),
        client_kind: ClientKind::Mcp,
        agent_name: Some("tester".to_owned()),
        agent_name_source: AgentNameSource::Flag,
        cwd_basename: "repo".to_owned(),
    }
}

fn soon() -> Option<Instant> {
    Some(Instant::now() + WAIT)
}

/// Unix: the explicit socket; Windows: the production `connect` (reads `<data>/endpoint`).
#[cfg(unix)]
async fn connect_at(
    location: &EndpointLocation,
    data: &LocalDataDir,
) -> Result<IpcClient, ConnectError> {
    let check = atlas_duck_ipc::transport::unix::SameUser;
    IpcClient::connect_at(location, data, &hello(), &check, Instant::now() + WAIT).await
}

#[cfg(windows)]
async fn connect_at(
    _location: &EndpointLocation,
    data: &LocalDataDir,
) -> Result<IpcClient, ConnectError> {
    let ctx = atlas_duck_ipc::client::ClientContext {
        data_dir: data.clone(),
        host: "host".to_owned(),
        hello: hello(),
    };
    IpcClient::connect(&ctx, Instant::now() + WAIT).await
}

async fn shared(srv: &Running) -> Result<SharedClient, ConnectError> {
    Ok(connect_at(&srv.location, &srv.data).await?.into_shared())
}

fn rid(i: usize) -> String {
    format!("req_{i:0>32}")
}

fn answer(method: &str, request_id: Option<&str>) -> Envelope {
    Envelope {
        request_id: request_id.map(str::to_owned),
        op_id: None,
        instance: None,
        status: Status::Succeeded,
        data: Some(json!({"method": method, "request_id": request_id})),
        edited: false,
        redacted: false,
        redaction_note: None,
        message: None,
        error: None,
        meta: None,
    }
}

fn answered_id(env: &Envelope) -> Option<String> {
    env.data
        .as_ref()
        .and_then(|d| d["request_id"].as_str())
        .map(str::to_owned)
}

/// Joins a spawned call, failing (not hanging) after [`WAIT`].
async fn join<T>(task: JoinHandle<T>) -> Result<T, Box<dyn std::error::Error>> {
    Ok(tokio::time::timeout(WAIT, task).await??)
}

// ---------- scripted handler ----------

/// `request.status` sleeps per request id; `request.await` meets the other awaits at the
/// barrier, emits `progress` for its own id, meets them again, then answers. Every answer's
/// `data.request_id` names the request it answers.
#[derive(Default)]
struct Scripted {
    status_delay: HashMap<String, Duration>,
    progress: Vec<Status>,
    barrier: Option<Barrier>,
}

#[async_trait::async_trait]
impl RequestHandler for Scripted {
    async fn hello(&self, _conn: &ConnectionMeta, _h: Hello) -> Result<HelloReply, Envelope> {
        Ok(HelloReply {
            build_id: BUILD.to_owned(),
        })
    }

    async fn ops_list(&self, _instance: Option<&str>) -> Envelope {
        answer(method::OPS_LIST, None)
    }

    async fn ops_describe(&self, _op_id: &str, _instance: Option<&str>) -> Envelope {
        answer(method::OPS_DESCRIBE, None)
    }

    async fn instances_list(&self) -> Envelope {
        answer(method::INSTANCES_LIST, None)
    }

    async fn submit(&self, _conn: &ConnectionMeta, _p: SubmitParams) -> SubmitReply {
        SubmitReply {
            envelope: answer(method::REQUEST_SUBMIT, None),
            params_sha256: None,
        }
    }

    async fn submit_script(&self, _conn: &ConnectionMeta, _p: SubmitParams) -> SubmitReply {
        SubmitReply {
            envelope: answer(method::SCRIPT_SUBMIT, None),
            params_sha256: None,
        }
    }

    async fn await_request(
        &self,
        _conn: &ConnectionMeta,
        a: AwaitParams,
        progress: &dyn ProgressSink,
    ) -> Envelope {
        if let Some(b) = &self.barrier {
            b.wait().await;
        }
        for status in &self.progress {
            progress.progress(ProgressNotification {
                request_id: a.request_id.clone(),
                status: *status,
            });
        }
        // Every await emitted before any answers: each call sees every copy for its id.
        if let Some(b) = &self.barrier {
            b.wait().await;
        }
        answer(method::REQUEST_AWAIT, Some(&a.request_id))
    }

    async fn status(&self, request_id: &str) -> Envelope {
        if let Some(d) = self.status_delay.get(request_id) {
            tokio::time::sleep(*d).await;
        }
        answer(method::REQUEST_STATUS, Some(request_id))
    }

    async fn cancel(&self, request_id: &str) -> Envelope {
        answer(method::REQUEST_CANCEL, Some(request_id))
    }

    async fn requests_list(
        &self,
        _agent: Option<&str>,
        _state: Option<ListState>,
        _match_params: Option<MatchParams>,
    ) -> Envelope {
        answer(method::REQUESTS_LIST, None)
    }

    async fn doctor(&self) -> Envelope {
        answer(method::DOCTOR, None)
    }
}

// ---------- raw peer ----------

/// What the test tells a raw peer to do.
enum Cmd {
    Write(Value),
    Close,
}

/// A raw listener at this user's endpoint that answers the hello with our build, then hands
/// every request frame to the test and writes or closes on its command.
struct RawPeer {
    location: EndpointLocation,
    data: LocalDataDir,
    requests: mpsc::UnboundedReceiver<Value>,
    cmds: mpsc::UnboundedSender<Cmd>,
    _task: JoinHandle<()>,
    _tmp: tempfile::TempDir,
}

impl RawPeer {
    async fn start() -> RawPeer {
        let (tmp, data) = data_dir();
        let location = location(&tmp, &data);
        let (req_tx, requests) = mpsc::unbounded_channel();
        let (cmds, cmd_rx) = mpsc::unbounded_channel();
        let task = raw_listen(&location, &data, req_tx, cmd_rx);
        RawPeer {
            location,
            data,
            requests,
            cmds,
            _task: task,
            _tmp: tmp,
        }
    }

    async fn client(&self) -> Result<SharedClient, ConnectError> {
        Ok(connect_at(&self.location, &self.data).await?.into_shared())
    }

    /// The next request the peer read; fails after [`WAIT`].
    async fn next(&mut self) -> Result<Value, Box<dyn std::error::Error>> {
        tokio::time::timeout(WAIT, self.requests.recv())
            .await?
            .ok_or_else(|| "raw peer ended".into())
    }

    fn send(&self, cmd: Cmd) -> TestResult {
        self.cmds.send(cmd).map_err(|_| "raw peer ended")?;
        Ok(())
    }
}

async fn serve_raw(
    conn: Conn,
    requests: mpsc::UnboundedSender<Value>,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
) {
    let (mut rd, mut wr) = conn.split();
    let Ok(Some(_hello)) = read_frame_async(&mut rd, HELLO_MAX_BYTES).await else {
        return;
    };
    let ok = json!({"jsonrpc": "2.0", "id": 1, "result": {"build_id": BUILD}});
    if write_frame_async(&mut wr, &serde_json::to_vec(&ok).unwrap_or_default())
        .await
        .is_err()
    {
        return;
    }
    let reader = tokio::spawn(async move {
        while let Ok(Some(frame)) = read_frame_async(&mut rd, MAX_FRAME_BYTES).await {
            let v = serde_json::from_slice(&frame).unwrap_or(Value::Null);
            if requests.send(v).is_err() {
                return;
            }
        }
    });
    while let Some(cmd) = cmds.recv().await {
        match cmd {
            Cmd::Write(v) => {
                let bytes = serde_json::to_vec(&v).unwrap_or_default();
                if write_frame_async(&mut wr, &bytes).await.is_err() {
                    break;
                }
            }
            Cmd::Close => break,
        }
    }
    // Both halves gone: the connection closes.
    reader.abort();
    let _ = reader.await;
    drop(wr);
}

#[cfg(unix)]
fn raw_listen(
    location: &EndpointLocation,
    _data: &LocalDataDir,
    requests: mpsc::UnboundedSender<Value>,
    cmds: mpsc::UnboundedReceiver<Cmd>,
) -> JoinHandle<()> {
    let EndpointLocation::UnixSocket(path) = location else {
        panic!("not a socket location");
    };
    let listener = atlas_duck_ipc::transport::unix::Listener::bind(path).expect("raw bind");
    tokio::spawn(async move {
        if let Ok((conn, _)) = listener.accept().await {
            serve_raw(conn, requests, cmds).await;
        }
    })
}

#[cfg(windows)]
fn raw_listen(
    location: &EndpointLocation,
    data: &LocalDataDir,
    requests: mpsc::UnboundedSender<Value>,
    cmds: mpsc::UnboundedReceiver<Cmd>,
) -> JoinHandle<()> {
    let EndpointLocation::WindowsPipePrefix(prefix) = location else {
        panic!("not a pipe location");
    };
    let mut listener =
        atlas_duck_ipc::transport::windows::PipeListener::bind(prefix).expect("raw bind");
    atlas_duck_ipc::paths::write_endpoint_file(data, listener.name()).expect("endpoint file");
    tokio::spawn(async move {
        if let Ok((pipe, _)) = listener.accept().await {
            serve_raw(Conn::new(pipe), requests, cmds).await;
        }
    })
}

fn status_call(client: &SharedClient, i: usize) -> JoinHandle<Sent<Envelope>> {
    let c = client.clone();
    tokio::spawn(async move {
        c.call::<Envelope>(
            method::REQUEST_STATUS,
            IdParams { request_id: rid(i) },
            soon(),
        )
        .await
    })
}

// ---------- tests ----------

/// Ten concurrent calls whose answers come back in reverse order each get their own answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_client_concurrent_calls_route_by_id() -> TestResult {
    let handler = Scripted {
        status_delay: (0..10)
            .map(|i| (rid(i), Duration::from_millis(40 * (10 - i as u64))))
            .collect(),
        ..Scripted::default()
    };
    let srv = start(Arc::new(handler)).await;
    let client = shared(&srv).await?;
    let calls: Vec<_> = (0..10).map(|i| (i, status_call(&client, i))).collect();
    for (i, task) in calls {
        let sent = join(task).await?;
        assert!(sent.written, "call {i}: not written");
        let env = sent.result?;
        assert_eq!(
            answered_id(&env),
            Some(rid(i)),
            "call {i} got another answer"
        );
    }
    assert!(!client.is_closed());
    srv.stop().await
}

/// Progress goes to every call awaiting that `request_id`, and only to those.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_client_progress_routed_per_request_id() -> TestResult {
    let handler = Scripted {
        progress: vec![Status::Pending, Status::Executing],
        barrier: Some(Barrier::new(2)),
        ..Scripted::default()
    };
    let srv = start(Arc::new(handler)).await;
    let client = shared(&srv).await?;

    let awaiting = |id: String| {
        let c = client.clone();
        tokio::spawn(async move {
            let mut seen: Vec<ProgressNotification> = Vec::new();
            let sent = c
                .call_with_progress::<Envelope>(
                    method::REQUEST_AWAIT,
                    AwaitParams {
                        request_id: id,
                        timeout_ms: None,
                    },
                    soon(),
                    &mut |n| seen.push(n),
                )
                .await;
            (sent, seen)
        })
    };

    // Different ids: each sees only its own.
    let (a, b) = (awaiting(rid(1)), awaiting(rid(2)));
    for (task, id) in [(a, rid(1)), (b, rid(2))] {
        let (sent, seen) = join(task).await?;
        assert_eq!(answered_id(&sent.result?), Some(id.clone()));
        let want: Vec<ProgressNotification> = [Status::Pending, Status::Executing]
            .into_iter()
            .map(|status| ProgressNotification {
                request_id: id.clone(),
                status,
            })
            .collect();
        assert_eq!(seen, want, "{id}");
    }

    // The same id twice: the server sends one copy per await task, and each call sees both.
    let (a, b) = (awaiting(rid(3)), awaiting(rid(3)));
    for task in [a, b] {
        let (sent, seen) = join(task).await?;
        assert_eq!(answered_id(&sent.result?), Some(rid(3)));
        assert_eq!(seen.len(), 4, "{seen:?}");
        assert!(seen.iter().all(|n| n.request_id == rid(3)), "{seen:?}");
        for status in [Status::Pending, Status::Executing] {
            assert_eq!(seen.iter().filter(|n| n.status == status).count(), 2);
        }
    }
    srv.stop().await
}

/// The server closes with three calls in flight: each gets `ConnectionLost` with
/// `written: true`; the client is closed and a new call fails at once, unwritten.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_client_closed_fails_all_waiters() -> TestResult {
    let mut peer = RawPeer::start().await;
    let client = peer.client().await?;
    let calls: Vec<_> = (0..3).map(|i| status_call(&client, i)).collect();
    for _ in 0..3 {
        peer.next().await?;
    }
    assert!(!client.is_closed());
    peer.send(Cmd::Close)?;
    for task in calls {
        let sent = join(task).await?;
        assert!(sent.written);
        assert!(
            matches!(sent.result, Err(ClientError::ConnectionLost)),
            "{:?}",
            sent.result
        );
    }
    assert!(client.is_closed());
    let t0 = Instant::now();
    let sent = tokio::time::timeout(
        WAIT,
        client.call::<Envelope>(method::DOCTOR, json!({}), None),
    )
    .await?;
    assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
    assert!(!sent.written);
    assert!(
        matches!(sent.result, Err(ClientError::ConnectionLost)),
        "{:?}",
        sent.result
    );
    Ok(())
}

/// A `null`-id error cannot be attributed with two calls in flight: it closes the client.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_client_null_id_error_closes() -> TestResult {
    let mut peer = RawPeer::start().await;
    let client = peer.client().await?;
    let calls: Vec<_> = (0..2).map(|i| status_call(&client, i)).collect();
    for _ in 0..2 {
        peer.next().await?;
    }
    peer.send(Cmd::Write(json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {"code": -32700, "message": "parse error"},
    })))?;
    for task in calls {
        let sent = join(task).await?;
        assert!(sent.written);
        assert!(
            matches!(sent.result, Err(ClientError::Protocol(_))),
            "{:?}",
            sent.result
        );
    }
    assert!(client.is_closed());
    let sent = tokio::time::timeout(
        WAIT,
        client.call::<Envelope>(method::DOCTOR, json!({}), soon()),
    )
    .await?;
    assert!(!sent.written);
    assert!(
        matches!(sent.result, Err(ClientError::Protocol(_))),
        "{:?}",
        sent.result
    );
    Ok(())
}

/// The slot travels with the route: 48 awaits whose futures were dropped still hold their
/// slots until the server answers them, so a 49th call waits for that answer (or its own
/// deadline, unwritten) and the server never holds more than 48 requests from this client.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_client_in_flight_cap() -> TestResult {
    let mut fake = Fake::new("A");
    fake.await_delay = Duration::from_secs(3);
    let fake = Arc::new(fake);
    let srv = start(fake.clone()).await;
    let client = shared(&srv).await?;

    let held: Vec<_> = (0..SHARED_IN_FLIGHT)
        .map(|i| {
            let c = client.clone();
            tokio::spawn(async move {
                c.call::<Envelope>(
                    method::REQUEST_AWAIT,
                    AwaitParams {
                        request_id: rid(i),
                        timeout_ms: None,
                    },
                    None,
                )
                .await
            })
        })
        .collect();
    fake.wait_for(Kind::AwaitStart, SHARED_IN_FLIGHT).await;
    for task in &held {
        task.abort();
    }
    for task in held {
        let _ = task.await;
    }

    // The 49th request is an await too, so the server's own count shows whether it was held
    // beside the 48. No slot comes free before the server answers: a short deadline queues
    // nothing.
    let forty_ninth = rid(SHARED_IN_FLIGHT);
    let await_49th = |at: Option<Instant>| {
        let c = client.clone();
        let request_id = forty_ninth.clone();
        async move {
            c.call::<Envelope>(
                method::REQUEST_AWAIT,
                AwaitParams {
                    request_id,
                    timeout_ms: None,
                },
                at,
            )
            .await
        }
    };
    let sent = await_49th(Some(Instant::now() + Duration::from_millis(200))).await;
    assert!(!sent.written);
    assert!(
        matches!(sent.result, Err(ClientError::DeadlineExceeded)),
        "{:?}",
        sent.result
    );

    // A patient call gets a slot once the server answered a dropped await.
    let patient = tokio::spawn(await_49th(soon()));
    let sent = join(patient).await?;
    assert!(sent.written);
    sent.result?;

    let first_done = fake
        .of(Kind::AwaitDone)
        .iter()
        .map(|e| e.at)
        .min()
        .ok_or("no await finished")?;
    let starts_49th: Vec<_> = fake
        .of(Kind::AwaitStart)
        .into_iter()
        .filter(|e| e.detail.as_deref() == Some(forty_ninth.as_str()))
        .collect();
    assert_eq!(
        starts_49th.len(),
        1,
        "the short-deadline call reached the server"
    );
    assert!(
        starts_49th[0].at >= first_done,
        "the 49th request reached the server before any slot came free"
    );
    // The server never held more than 48 of this client's awaits at once.
    let mut changes: Vec<(Instant, i32)> = Vec::new();
    for e in fake.events() {
        match e.kind {
            Kind::AwaitStart => changes.push((e.at, 1)),
            Kind::AwaitDone | Kind::AwaitDropped => changes.push((e.at, -1)),
            _ => {}
        }
    }
    // An end sorts before a start at the same instant.
    changes.sort();
    let (mut held, mut most) = (0, 0);
    for (_, change) in changes {
        held += change;
        most = most.max(held);
    }
    assert_eq!(most, SHARED_IN_FLIGHT as i32, "most awaits held at once");
    assert!(!client.is_closed());
    srv.stop().await
}

/// A connection that ended before `into_shared` gives a closed client: its calls fail at
/// once, unwritten, instead of waiting on a dead connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_client_into_shared_on_a_lost_connection_is_closed() -> TestResult {
    let peer = RawPeer::start().await;
    let mut client = connect_at(&peer.location, &peer.data).await?;
    peer.send(Cmd::Close)?;
    // Whether the call meets the reader's end or the failed write first, the client is dead.
    let lost = tokio::time::timeout(
        WAIT,
        client.call::<Envelope>(method::DOCTOR, json!({"call": "after the close"})),
    )
    .await?;
    assert!(matches!(lost, Err(ClientError::ConnectionLost)), "{lost:?}");
    let shared = client.into_shared();
    assert!(shared.is_closed());
    let sent = tokio::time::timeout(
        WAIT,
        shared.call::<Envelope>(method::DOCTOR, json!({}), None),
    )
    .await?;
    assert!(!sent.written);
    assert!(
        matches!(sent.result, Err(ClientError::ConnectionLost)),
        "{:?}",
        sent.result
    );
    Ok(())
}
