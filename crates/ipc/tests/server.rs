#![cfg(feature = "async")]
//! `IpcServer` (§3.3, PD-27, PD-28, PD-37, Δ2, C.2 drive-to-completion): hello ordering and
//! deadline, protocol errors, connection limits, one task per request, progress,
//! `disconnected`, handler swaps, shutdown. The client side speaks raw frames.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::paths::{ENDPOINT_FILE, EndpointLocation, read_endpoint_file};
use atlas_duck_ipc::proto::RequestHandler;
use atlas_duck_ipc::sandbox::MAX_FRAME_BYTES;
use atlas_duck_ipc::server::{HandlerCell, IpcServer, ServerLimits, ShutdownSignal};
use common::{Client, Fake, Kind, WAIT, error_of, hello_params, local, mismatch_envelope, request};
use serde_json::{Value, json};
use tokio::task::JoinHandle;

// ---------- harness ----------

struct Running {
    name: String,
    cell: Arc<HandlerCell>,
    shutdown: ShutdownSignal,
    task: JoinHandle<()>,
    data: atlas_duck_ipc::paths::LocalDataDir,
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

#[cfg(unix)]
fn location(tmp: &tempfile::TempDir) -> EndpointLocation {
    let dir = tmp.path().join("s");
    atlas_duck_ipc::paths::ensure_socket_dir(&dir).expect("socket dir");
    EndpointLocation::UnixSocket(dir.join("atlas-duck.sock"))
}

#[cfg(windows)]
fn location(_tmp: &tempfile::TempDir) -> EndpointLocation {
    let tmp = tempfile::tempdir().expect("tempdir");
    atlas_duck_ipc::paths::endpoint_location(&local(tmp.path()), "host").expect("location")
}

async fn start_with(handler: Arc<dyn RequestHandler>, limits: ServerLimits) -> Running {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir(&data_dir).expect("data dir");
    let data = local(&data_dir);
    let server = IpcServer::bind_at(&data, location(&tmp))
        .expect("bind")
        .with_limits(limits);
    let name = server.endpoint_name().to_owned();
    let cell = Arc::new(HandlerCell::new(handler));
    let shutdown = ShutdownSignal::default();
    let task = tokio::spawn(server.serve(cell.clone(), shutdown.clone()));
    Running {
        name,
        cell,
        shutdown,
        task,
        data,
        _tmp: tmp,
    }
}

async fn start(fake: &Arc<Fake>) -> Running {
    start_with(fake.clone(), ServerLimits::default()).await
}

fn by(v: &Value) -> &str {
    v["result"]["data"]["by"]
        .as_str()
        .or_else(|| v["result"]["envelope"]["data"]["by"].as_str())
        .unwrap_or("?")
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

// ---------- hello ordering ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hello_must_be_first() {
    let fake = Arc::new(Fake::new("A"));
    let srv = start(&fake).await;
    let mut c = Client::connect(&srv.name).await;
    let v = c.call(7, "ops.list", json!({})).await;
    assert_eq!(v["id"], json!(7));
    assert_eq!(error_of(&v), (-32600, Some("hello_required".to_owned())));
    assert_eq!(v["error"]["data"]["status"], json!("failed"));
    assert_eq!(v["error"]["data"]["error"]["code"], json!("protocol_error"));
    assert_eq!(v["error"]["data"]["error"]["retryable"], json!(false));
    assert!(c.closed().await, "connection stayed open");
    assert!(fake.events().is_empty(), "handler saw {:?}", fake.events());
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hello_deadline_5s() {
    let fake = Arc::new(Fake::new("A"));
    let limits = ServerLimits {
        hello_timeout: Duration::from_millis(300),
        ..ServerLimits::default()
    };
    let srv = start_with(fake.clone(), limits).await;
    let mut c = Client::connect(&srv.name).await;
    let t0 = Instant::now();
    let v = c.recv().await.expect("an error frame before close");
    let waited = t0.elapsed();
    assert_eq!(v["id"], Value::Null);
    assert_eq!(error_of(&v), (-32600, Some("hello_timeout".to_owned())));
    assert!(
        waited >= Duration::from_millis(250),
        "answered after {waited:?}"
    );
    assert!(waited < Duration::from_secs(3), "answered after {waited:?}");
    assert!(c.closed().await);
    assert!(fake.events().is_empty());
    assert_eq!(
        ServerLimits::default().hello_timeout,
        Duration::from_secs(5)
    );
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_hello_rejected() {
    let fake = Arc::new(Fake::new("A"));
    let srv = start(&fake).await;
    let mut c = Client::hello(&srv.name).await;
    let v = c.call(2, "hello", hello_params()).await;
    assert_eq!(v["id"], json!(2));
    assert_eq!(error_of(&v), (-32600, Some("hello_repeated".to_owned())));
    // The connection stays open.
    let v = c.call(3, "ops.list", json!({})).await;
    assert_eq!(by(&v), "A", "{v}");
    assert_eq!(fake.count(Kind::Hello), 1);
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn build_mismatch_hello_error_then_close() {
    let fake = Arc::new(Fake::new("A"));
    *fake.hello_refusal.lock().expect("lock") = Some(mismatch_envelope());
    let srv = start(&fake).await;
    let mut c = Client::connect(&srv.name).await;
    let v = c.call(1, "hello", hello_params()).await;
    assert_eq!(v["id"], json!(1));
    assert_eq!(v["error"]["code"], json!(-32000));
    let env: Envelope = serde_json::from_value(v["error"]["data"].clone()).expect("envelope");
    assert_eq!(env, mismatch_envelope());
    // Nothing further is served: the server closed the connection.
    assert!(c.closed().await);
    settle().await;
    assert_eq!(fake.count(Kind::OpsList), 0);
    // A connection whose hello failed is never `disconnected`.
    assert_eq!(fake.count(Kind::Disconnected), 0);
    srv.stop().await;
}

// ---------- framing and protocol errors ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversize_frame_protocol_error() {
    let fake = Arc::new(Fake::new("A"));
    let srv = start(&fake).await;

    // As the first frame.
    let mut c = Client::connect(&srv.name).await;
    let announced = u32::try_from(MAX_FRAME_BYTES + 1).expect("u32");
    c.send_raw(&announced.to_be_bytes()).await;
    let v = c.recv().await.expect("error frame");
    assert_eq!(v["id"], Value::Null);
    assert_eq!(error_of(&v), (-32600, Some("frame_too_large".to_owned())));
    assert!(c.closed().await);
    assert!(fake.events().is_empty(), "handler saw {:?}", fake.events());

    // After hello.
    let mut c = Client::hello(&srv.name).await;
    c.send_raw(&announced.to_be_bytes()).await;
    let v = c.recv().await.expect("error frame");
    assert_eq!(v["id"], Value::Null);
    assert_eq!(error_of(&v), (-32600, Some("frame_too_large".to_owned())));
    assert!(c.closed().await);
    assert_eq!(fake.count(Kind::Hello), 1);
    fake.wait_for(Kind::Disconnected, 1).await;
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_json_parse_error() {
    let fake = Arc::new(Fake::new("A"));
    let srv = start(&fake).await;
    let frame = |payload: &[u8]| {
        let mut v = u32::try_from(payload.len())
            .expect("u32")
            .to_be_bytes()
            .to_vec();
        v.extend_from_slice(payload);
        v
    };

    let mut c = Client::connect(&srv.name).await;
    c.send_raw(&frame(b"{not json")).await;
    let v = c.recv().await.expect("error frame");
    assert_eq!(v["id"], Value::Null);
    assert_eq!(error_of(&v), (-32700, Some("parse".to_owned())));
    assert!(c.closed().await);
    assert!(fake.events().is_empty());

    let mut c = Client::hello(&srv.name).await;
    c.send_raw(&frame(b"[1,2")).await;
    let v = c.recv().await.expect("error frame");
    assert_eq!(error_of(&v), (-32700, Some("parse".to_owned())));
    assert!(c.closed().await);
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_request_closes() {
    let fake = Arc::new(Fake::new("A"));
    let srv = start(&fake).await;
    let mut c = Client::hello(&srv.name).await;
    // A notification (no id) is not a request.
    c.send(&json!({"jsonrpc": "2.0", "method": "ops.list", "params": {}}))
        .await;
    let v = c.recv().await.expect("error frame");
    assert_eq!(v["id"], Value::Null);
    assert_eq!(error_of(&v), (-32600, Some("invalid_request".to_owned())));
    assert!(c.closed().await);

    // A wrong `jsonrpc` value: the id is echoed when it can be read.
    let mut c = Client::hello(&srv.name).await;
    c.send(&json!({"jsonrpc": "1.0", "id": 9, "method": "ops.list"}))
        .await;
    let v = c.recv().await.expect("error frame");
    assert_eq!(v["id"], json!(9));
    assert_eq!(error_of(&v), (-32600, Some("invalid_request".to_owned())));
    assert!(c.closed().await);
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_method_and_bad_params() {
    let fake = Arc::new(Fake::new("A"));
    let srv = start(&fake).await;
    let mut c = Client::hello(&srv.name).await;

    let v = c.call(1, "ops.frobnicate", json!({})).await;
    assert_eq!(v["id"], json!(1));
    assert_eq!(error_of(&v), (-32601, Some("unknown_method".to_owned())));
    // The progress notification is server-to-client only.
    let v = c.call(2, "request.progress", json!({})).await;
    assert_eq!(error_of(&v), (-32601, Some("unknown_method".to_owned())));

    let v = c.call(3, "request.status", json!({"id": "x"})).await;
    assert_eq!(v["id"], json!(3));
    assert_eq!(error_of(&v), (-32602, Some("invalid_params".to_owned())));
    let v = c.call(4, "ops.list", json!({"instance": 5})).await;
    assert_eq!(error_of(&v), (-32602, Some("invalid_params".to_owned())));
    let v = c.call(5, "doctor", json!([])).await;
    assert_eq!(error_of(&v), (-32602, Some("invalid_params".to_owned())));
    // An omitted `params` is `{}`: fine where every field is optional, invalid otherwise.
    c.send(&json!({"jsonrpc": "2.0", "id": 6, "method": "ops.list"}))
        .await;
    let v = c.recv().await.expect("answer");
    assert_eq!(v["id"], json!(6));
    assert_eq!(by(&v), "A", "{v}");
    c.send(&json!({"jsonrpc": "2.0", "id": 7, "method": "request.cancel"}))
        .await;
    let v = c.recv().await.expect("answer");
    assert_eq!(error_of(&v), (-32602, Some("invalid_params".to_owned())));

    // The connection is still usable and nothing invalid reached the handler.
    let v = c.call(8, "instances.list", json!({})).await;
    assert_eq!(by(&v), "A");
    assert_eq!(fake.count(Kind::OpsList), 1);
    assert_eq!(fake.count(Kind::Status), 0);
    assert_eq!(fake.count(Kind::Cancel), 0);
    assert_eq!(fake.count(Kind::Doctor), 0);
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_method_is_dispatched() {
    let fake = Arc::new(Fake::new("A"));
    let srv = start(&fake).await;
    let mut c = Client::hello(&srv.name).await;
    let submit = json!({"op_id": "jira.issue.get", "params": {"key": "A-1"}, "instance": null, "reason": null});
    let cases = [
        ("ops.list", json!({"instance": "prod"}), Kind::OpsList),
        (
            "ops.describe",
            json!({"op_id": "jira.issue.get"}),
            Kind::OpsDescribe,
        ),
        ("instances.list", json!({}), Kind::InstancesList),
        ("request.submit", submit.clone(), Kind::Submit),
        ("script.submit", submit, Kind::ScriptSubmit),
        (
            "request.await",
            json!({"request_id": "r", "timeout_ms": null}),
            Kind::AwaitStart,
        ),
        ("request.status", json!({"request_id": "r"}), Kind::Status),
        ("request.cancel", json!({"request_id": "r"}), Kind::Cancel),
        (
            "requests.list",
            json!({"state": "pending"}),
            Kind::RequestsList,
        ),
        ("doctor", json!({}), Kind::Doctor),
    ];
    for (i, (method, params, kind)) in cases.into_iter().enumerate() {
        let id = 10 + i as u64;
        let v = c.call(id, method, params).await;
        assert_eq!(v["id"], json!(id), "{method}: {v}");
        assert!(v.get("result").is_some(), "{method}: {v}");
        assert_eq!(by(&v), "A", "{method}: {v}");
        assert_eq!(fake.count(kind), 1, "{method}");
    }
    // Submit answers carry the SubmitReply shape (Δ1).
    let v = c
        .call(
            30,
            "request.submit",
            json!({"op_id": "x", "params": {}, "instance": null, "reason": null}),
        )
        .await;
    assert_eq!(v["result"]["envelope"]["status"], json!("pending"));
    assert_eq!(v["result"]["params_sha256"], json!("00".repeat(32)));
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversize_response_becomes_frame_too_large() {
    let mut fake = Fake::new("A");
    fake.doctor_bytes = MAX_FRAME_BYTES;
    let fake = Arc::new(fake);
    let srv = start(&fake).await;
    let mut c = Client::hello(&srv.name).await;
    let v = c.call(4, "doctor", json!({})).await;
    assert_eq!(v["id"], json!(4));
    assert_eq!(error_of(&v), (-32600, Some("frame_too_large".to_owned())));
    // Only that answer is replaced; the connection goes on.
    let v = c.call(5, "ops.list", json!({})).await;
    assert_eq!(by(&v), "A");
    srv.stop().await;
}

// ---------- limits ----------

async fn assert_busy(name: &str, fake: &Fake) {
    let hellos = fake.count(Kind::Hello);
    let mut c = Client::connect(name).await;
    let v = c.call(1, "hello", hello_params()).await;
    assert_eq!(v["id"], json!(1));
    assert_eq!(v["error"]["code"], json!(-32000), "{v}");
    let data = &v["error"]["data"];
    assert_eq!(data["status"], json!("failed"));
    assert_eq!(data["error"]["code"], json!("busy"));
    assert_eq!(data["error"]["retryable"], json!(true));
    assert_eq!(data["error"]["details"]["retry_after_s"], json!(5));
    assert_eq!(data["request_id"], Value::Null);
    assert!(c.closed().await);
    assert_eq!(fake.count(Kind::Hello), hellos, "hello reached the handler");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_limits_busy_5() {
    // Total limit: 3 (every test connection has the same origin, so the per-origin limit
    // is raised out of the way here and tested below).
    let fake = Arc::new(Fake::new("A"));
    let limits = ServerLimits {
        max_connections: 3,
        per_origin: 16,
        ..ServerLimits::default()
    };
    let srv = start_with(fake.clone(), limits).await;
    let mut open = Vec::new();
    for _ in 0..3 {
        open.push(Client::hello(&srv.name).await);
    }
    assert_busy(&srv.name, &fake).await;
    assert_eq!(fake.count(Kind::Hello), 3);
    // A closed connection frees its slot.
    drop(open.pop());
    fake.wait_for(Kind::Disconnected, 1).await;
    let _again = Client::hello(&srv.name).await;
    assert_eq!(fake.count(Kind::Hello), 4);
    srv.stop().await;

    // Per-origin limit: 2.
    let fake = Arc::new(Fake::new("B"));
    let limits = ServerLimits {
        max_connections: 64,
        per_origin: 2,
        ..ServerLimits::default()
    };
    let srv = start_with(fake.clone(), limits).await;
    let _a = Client::hello(&srv.name).await;
    let _b = Client::hello(&srv.name).await;
    assert_busy(&srv.name, &fake).await;
    srv.stop().await;

    let d = ServerLimits::default();
    assert_eq!((d.max_connections, d.per_origin), (64, 16));
}

// ---------- requests ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_run_concurrently_answered_by_id() {
    let mut fake = Fake::new("A");
    fake.await_delay = Duration::from_millis(1500);
    let fake = Arc::new(fake);
    let srv = start(&fake).await;
    let mut c = Client::hello(&srv.name).await;
    c.send(&request(
        2,
        "request.await",
        json!({"request_id": "r1", "timeout_ms": null}),
    ))
    .await;
    fake.wait_for(Kind::AwaitStart, 1).await;
    let t0 = Instant::now();
    c.send(&request(3, "request.status", json!({"request_id": "r1"})))
        .await;
    let first = c.recv().await.expect("first answer");
    assert_eq!(first["id"], json!(3), "status was blocked by the await");
    assert!(t0.elapsed() < Duration::from_secs(1));
    let second = c.recv().await.expect("second answer");
    assert_eq!(second["id"], json!(2));
    assert_eq!(by(&second), "A");
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn progress_notifications_forwarded() {
    let mut fake = Fake::new("A");
    fake.progress = vec![Status::Pending, Status::Executing];
    fake.await_delay = Duration::from_millis(50);
    let fake = Arc::new(fake);
    let srv = start(&fake).await;
    let mut c = Client::hello(&srv.name).await;
    c.send(&request(
        5,
        "request.await",
        json!({"request_id": "req_1", "timeout_ms": 1000}),
    ))
    .await;
    let mut notes = Vec::new();
    let answer = loop {
        let v = c.recv().await.expect("frame");
        if v.get("method").is_some() {
            notes.push(v);
        } else {
            break v;
        }
    };
    assert_eq!(answer["id"], json!(5));
    assert_eq!(
        notes,
        vec![
            json!({"jsonrpc": "2.0", "method": "request.progress", "params": {"request_id": "req_1", "status": "pending"}}),
            json!({"jsonrpc": "2.0", "method": "request.progress", "params": {"request_id": "req_1", "status": "executing"}}),
        ]
    );
    srv.stop().await;
}

// ---------- disconnect ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnect_never_cancels_submit() {
    let mut fake = Fake::new("A");
    fake.submit_delay = Duration::from_millis(500);
    let fake = Arc::new(fake);
    let srv = start(&fake).await;
    let mut c = Client::hello(&srv.name).await;
    c.send(&request(
        2,
        "request.submit",
        json!({"op_id": "jira.issue.create", "params": {}, "instance": null, "reason": null}),
    ))
    .await;
    fake.wait_for(Kind::Submit, 1).await;
    drop(c);
    fake.wait_for(Kind::SubmitDone, 1).await;
    fake.wait_for(Kind::Disconnected, 1).await;
    assert_eq!(fake.count(Kind::Cancel), 0);
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_calls_disconnected_after_tasks_finish() {
    let mut fake = Fake::new("A");
    fake.submit_delay = Duration::from_millis(500);
    let fake = Arc::new(fake);
    let srv = start(&fake).await;
    let mut c = Client::hello(&srv.name).await;
    let conn_id = fake.of(Kind::Hello)[0]
        .conn
        .as_ref()
        .expect("meta")
        .connection_id
        .clone();
    c.send(&request(
        2,
        "request.submit",
        json!({"op_id": "x", "params": {}, "instance": null, "reason": null}),
    ))
    .await;
    fake.wait_for(Kind::Submit, 1).await;
    drop(c);
    let done = fake.wait_for(Kind::SubmitDone, 1).await;
    let disc = fake.wait_for(Kind::Disconnected, 1).await;
    assert!(
        disc[0].at >= done[0].at,
        "disconnected before the submit finished"
    );
    assert_eq!(disc[0].conn.as_ref().expect("meta").connection_id, conn_id);
    settle().await;
    assert_eq!(fake.count(Kind::Disconnected), 1, "called more than once");

    // A connection whose hello never succeeded is never `disconnected`.
    let mut c = Client::connect(&srv.name).await;
    let _ = c.call(1, "ops.list", json!({})).await;
    assert!(c.closed().await);
    settle().await;
    assert_eq!(fake.count(Kind::Disconnected), 1);
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn await_dropped_on_disconnect() {
    let mut fake = Fake::new("A");
    fake.await_delay = Duration::from_secs(30);
    let fake = Arc::new(fake);
    let srv = start(&fake).await;
    let mut c = Client::hello(&srv.name).await;
    c.send(&request(
        2,
        "request.await",
        json!({"request_id": "r", "timeout_ms": null}),
    ))
    .await;
    fake.wait_for(Kind::AwaitStart, 1).await;
    drop(c);
    let dropped = fake.wait_for(Kind::AwaitDropped, 1).await;
    let disc = fake.wait_for(Kind::Disconnected, 1).await;
    assert!(disc[0].at >= dropped[0].at);
    assert_eq!(fake.count(Kind::AwaitDone), 0);
    srv.stop().await;
}

// ---------- handler swap ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn swap_seen_from_next_request() {
    let a = Arc::new(Fake::new("A"));
    let b = Arc::new(Fake::new("B"));
    let srv = start(&a).await;
    let mut c = Client::hello(&srv.name).await;
    let v = c.call(1, "ops.list", json!({})).await;
    assert_eq!(by(&v), "A");
    srv.cell.swap(b.clone());
    let v = c.call(2, "ops.list", json!({})).await;
    assert_eq!(by(&v), "B");
    assert_eq!(a.count(Kind::OpsList), 1);
    assert_eq!(b.count(Kind::OpsList), 1);
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn swap_keeps_session() {
    let a = Arc::new(Fake::new("A"));
    let b = Arc::new(Fake::new("B"));
    let srv = start(&a).await;
    let mut c = Client::hello(&srv.name).await;
    let meta_a = a.of(Kind::Hello)[0].conn.clone().expect("meta");
    srv.cell.swap(b.clone());
    assert_eq!(b.count(Kind::Hello), 0, "replayed before the next request");
    let v = c
        .call(
            2,
            "request.submit",
            json!({"op_id": "x", "params": {}, "instance": null, "reason": null}),
        )
        .await;
    assert_eq!(by(&v), "B");
    // B saw the connection's hello (same meta, same build) before the submit.
    let hello_b = b.of(Kind::Hello);
    assert_eq!(hello_b.len(), 1);
    assert_eq!(hello_b[0].conn.as_ref(), Some(&meta_a));
    assert_eq!(hello_b[0].detail.as_deref(), Some(common::BUILD));
    let submit_b = b.of(Kind::Submit);
    assert!(hello_b[0].at <= submit_b[0].at);
    assert_eq!(submit_b[0].conn.as_ref(), Some(&meta_a));
    // No second replay while the cell stays put.
    let _ = c.call(3, "ops.list", json!({})).await;
    assert_eq!(b.count(Kind::Hello), 1);
    assert_eq!(a.count(Kind::Hello), 1);

    // A refused replay answers that request with the refusal and closes.
    let r = Arc::new(Fake::new("R"));
    *r.hello_refusal.lock().expect("lock") = Some(mismatch_envelope());
    srv.cell.swap(r.clone());
    let v = c.call(4, "ops.list", json!({})).await;
    assert_eq!(v["id"], json!(4));
    assert_eq!(v["error"]["code"], json!(-32000));
    assert!(c.closed().await);
    assert_eq!(r.count(Kind::OpsList), 0);

    // `disconnected` reaches the current handler.
    r.wait_for(Kind::Disconnected, 1).await;
    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnected_goes_to_current_handler() {
    let a = Arc::new(Fake::new("A"));
    let b = Arc::new(Fake::new("B"));
    let srv = start(&a).await;
    let c = Client::hello(&srv.name).await;
    let meta = a.of(Kind::Hello)[0].conn.clone().expect("meta");
    srv.cell.swap(b.clone());
    drop(c);
    let disc = b.wait_for(Kind::Disconnected, 1).await;
    assert_eq!(disc[0].conn.as_ref(), Some(&meta));
    srv.stop().await;
}

// ---------- shutdown, endpoint, peer ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_stops_and_removes_endpoint() {
    let mut fake = Fake::new("A");
    fake.submit_delay = Duration::from_millis(500);
    let fake = Arc::new(fake);
    let srv = start(&fake).await;
    // The endpoint file names the endpoint, one line, no newline.
    assert_eq!(
        read_endpoint_file(&srv.data).expect("read"),
        Some(srv.name.clone())
    );
    let mut c = Client::hello(&srv.name).await;
    c.send(&request(
        2,
        "request.submit",
        json!({"op_id": "x", "params": {}, "instance": null, "reason": null}),
    ))
    .await;
    fake.wait_for(Kind::Submit, 1).await;

    let name = srv.name.clone();
    let data_path = srv.data.path().to_path_buf();
    let t0 = Instant::now();
    srv.shutdown.0.cancel();
    // The in-flight answer is still written, then the connection closes.
    let v = c.recv().await.expect("in-flight answer");
    assert_eq!(v["id"], json!(2));
    assert!(c.closed().await);
    tokio::time::timeout(WAIT, srv.task)
        .await
        .expect("serve returned")
        .expect("no panic");
    assert!(t0.elapsed() < Duration::from_secs(4));
    assert!(
        !data_path.join(ENDPOINT_FILE).exists(),
        "endpoint file kept"
    );
    assert_not_listening(&name).await;
}

#[cfg(windows)]
async fn assert_not_listening(name: &str) {
    assert!(atlas_duck_ipc::transport::windows::open_client(name).is_err());
}

#[cfg(unix)]
async fn assert_not_listening(name: &str) {
    assert!(tokio::net::UnixStream::connect(name).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_bounds_a_stuck_request() {
    let mut fake = Fake::new("A");
    fake.submit_delay = Duration::from_secs(60);
    let fake = Arc::new(fake);
    let srv = start(&fake).await;
    let mut c = Client::hello(&srv.name).await;
    c.send(&request(
        2,
        "request.submit",
        json!({"op_id": "x", "params": {}, "instance": null, "reason": null}),
    ))
    .await;
    fake.wait_for(Kind::Submit, 1).await;
    let t0 = Instant::now();
    srv.shutdown.0.cancel();
    tokio::time::timeout(WAIT, srv.task)
        .await
        .expect("serve returned")
        .expect("no panic");
    let took = t0.elapsed();
    assert!(took < Duration::from_secs(4), "shutdown took {took:?}");
    assert!(c.closed().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_meta_populated() {
    let fake = Arc::new(Fake::new("A"));
    let srv = start(&fake).await;
    let _c = Client::hello(&srv.name).await;
    let _d = Client::hello(&srv.name).await;
    let hellos = fake.of(Kind::Hello);
    let metas: Vec<_> = hellos
        .iter()
        .map(|e| e.conn.clone().expect("meta"))
        .collect();
    for meta in &metas {
        let id = &meta.connection_id;
        let hex = id.strip_prefix("conn_").expect("conn_ prefix");
        assert_eq!(hex.len(), 32, "{id}");
        assert!(
            hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{id}"
        );
        assert_eq!(meta.peer.peer_pid, Some(std::process::id()));
        assert!(!meta.peer.peer_chain.is_empty(), "{meta:?}");
        assert!(meta.peer.peer_exe.is_some());
    }
    assert_ne!(metas[0].connection_id, metas[1].connection_id);
    srv.stop().await;
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bind_writes_pipe_name_and_sweeps_temps() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = local(tmp.path());
    std::fs::write(tmp.path().join(".endpoint.1.1.tmp"), b"stale").expect("temp");
    let server = IpcServer::bind(&data, "host").expect("bind");
    let name = server.endpoint_name().to_owned();
    let EndpointLocation::WindowsPipePrefix(prefix) =
        atlas_duck_ipc::paths::endpoint_location(&data, "host").expect("location")
    else {
        panic!("not a pipe prefix");
    };
    assert!(atlas_duck_ipc::paths::pipe_name_has_prefix(&name, &prefix));
    let raw = std::fs::read(tmp.path().join(ENDPOINT_FILE)).expect("endpoint file");
    assert_eq!(raw, name.as_bytes(), "not exactly the name");
    assert!(!tmp.path().join(".endpoint.1.1.tmp").exists());
    drop(server);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cell_current_and_swap() {
    let a: Arc<dyn RequestHandler> = Arc::new(Fake::new("A"));
    let b: Arc<dyn RequestHandler> = Arc::new(Fake::new("B"));
    let cell = HandlerCell::new(a.clone());
    assert!(std::ptr::addr_eq(
        Arc::as_ptr(&cell.current()),
        Arc::as_ptr(&a)
    ));
    cell.swap(b.clone());
    assert!(std::ptr::addr_eq(
        Arc::as_ptr(&cell.current()),
        Arc::as_ptr(&b)
    ));
}
