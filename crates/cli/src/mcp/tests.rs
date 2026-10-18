//! Rig tests of the MCP server (M9 Tasks 6-10) and the rig's own self-tests. Real clock, short
//! periods; every wait is bounded, so a broken server fails a test instead of hanging it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

type TestResult = Result<(), Box<dyn std::error::Error>>;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use atlas_duck_ipc::build_info::{APP_VERSION, BUILD_ID};
use atlas_duck_ipc::client::{ClientError, ConnectError, SharedClient};
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::proto::{
    AgentNameSource, AwaitParams, ClientKind, ListState, ProgressNotification, SubmitParams,
    SubmitReply,
};
use atlas_duck_ipc::rpc::{IdParams, method};
use rmcp::ServiceError;
use rmcp::model::{ErrorCode as McpErrorCode, ProtocolVersion, RequestMetaObject};
use rmcp::service::ClientLifecycleMode;
use serde_json::{Map, Value, json};

use super::config::{McpConfig, ToolSet};
use super::result::RESTART_TEXT;
use super::rig::{RIG_BUILD, RIG_HEARTBEAT, Rig, RigApp, RigOpts};
use super::server::{AtlasMcp, SendFuture, Shared, ToolBodies, ToolCall};
use super::session::{Session, hello_of};
use super::tools::catalog;
use super::{run_on, run_on_with, serve_with};
use crate::connected::{Connector, cwd_basename};
use crate::deadline::Deadline;
use crate::discover::AppLocation;
use crate::flow::MSG_CONNECTION_LOST_NO_ID;
use crate::local;
use crate::test_support::{AwaitScript, HelloMode, Kind, REQ_ID, TestConnector, WAIT};

const OTHER_ID: &str = "req_00000000000000000000000000000002";

fn code(env: &Value) -> Option<&str> {
    env.get("error")?.get("code")?.as_str()
}

fn detail<'a>(env: &'a Value, key: &str) -> Option<&'a Value> {
    env.get("error")?.get("details")?.get(key)
}

fn reason_envelope(code: ErrorCode, reason: &str) -> Envelope {
    let mut env = Envelope::failed(code, false, "refused");
    if let Some(err) = env.error.as_mut() {
        let mut d = Map::new();
        d.insert("reason".to_owned(), Value::from(reason));
        err.details = Some(d);
    }
    env
}

// ---------- the MCP server (Task 6) ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn initialize_declares_tools_only() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    let lines = rig.lines();
    let init: Value = serde_json::from_str(lines.first().ok_or("no initialize answer")?)?;
    let result = init.get("result").ok_or("initialize failed")?;
    assert_eq!(
        result.get("capabilities"),
        Some(&json!({"tools": {"listChanged": false}}))
    );
    assert_eq!(result["serverInfo"]["name"], "atlas-duck");
    assert_eq!(result["serverInfo"]["version"], APP_VERSION);
    // rmcp's client asks for 2026-07-28 (no `initialize` lifecycle); the server stays on the
    // newest revision with a handshake.
    assert_eq!(result["protocolVersion"], "2025-11-25");
    assert!(result.get("instructions").is_none());
    assert_eq!(rig.connector().connect_count(), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tools_list_never_connects() -> TestResult {
    for set in [ToolSet::Full, ToolSet::Generic] {
        let rig = Rig::new(RigOpts {
            tools: set,
            present: false,
            ..RigOpts::default()
        })
        .await;
        let tools = rig.list_tools().await;
        // §4.6: no tool declares an `outputSchema` on the wire (T6 review M-3).
        for tool in &tools {
            assert!(tool.output_schema.is_none(), "{}", tool.name);
        }
        let names: Vec<String> = tools.into_iter().map(|t| t.name.into_owned()).collect();
        let want: Vec<String> = catalog(set)
            .into_iter()
            .map(|t| t.name.into_owned())
            .collect();
        assert_eq!(names, want, "{set:?}");
        assert_eq!(names.len(), if set == ToolSet::Full { 54 } else { 9 });
        assert_eq!(rig.connector().connect_count(), 0, "{set:?}");
        assert_eq!(
            rig.connector().discover_count(),
            0,
            "{set:?}: no launch check"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ops_list_and_describe_answer_locally() -> TestResult {
    let rig = Rig::new(RigOpts {
        present: false,
        ..RigOpts::default()
    })
    .await;
    let list = rig.call("ops_list", json!({}), false).await;
    assert!(!list.is_error());
    assert_eq!(list.envelope(), serde_json::to_value(local::ops_list())?);

    let describe = rig
        .call("ops_describe", json!({"op_id": "jira.issue.get"}), false)
        .await;
    assert!(!describe.is_error());
    assert_eq!(
        describe.envelope(),
        serde_json::to_value(local::ops_describe("jira.issue.get"))?
    );

    // A bad argument is a local usage error too.
    let bad = rig
        .call("ops_describe", json!({"op_id": "jira.nope"}), false)
        .await;
    assert!(bad.is_error());
    assert_eq!(code(&bad.envelope()), Some("usage"));
    assert_eq!(detail(&bad.envelope(), "arg"), Some(&json!("op_id")));

    assert_eq!(rig.connector().connect_count(), 0);
    assert_eq!(rig.connector().discover_count(), 0);
    assert_eq!(rig.fake().count(Kind::OpsList), 0);
    assert_eq!(rig.fake().count(Kind::OpsDescribe), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_tool_is_error_result_not_protocol_error() -> TestResult {
    let full = Rig::new(RigOpts::default()).await;
    let generic = Rig::new(RigOpts {
        tools: ToolSet::Generic,
        ..RigOpts::default()
    })
    .await;
    // `call` is only in the generic set, op tools only in the full one.
    for (rig, tool) in [
        (&full, "no_such_tool"),
        (&full, "call"),
        (&generic, "jira_issue_get"),
    ] {
        let started = rig.start(tool, json!({}), false).await;
        let id = serde_json::to_value(&started.id)?;
        let called = rig.finish(started).await;
        assert!(called.is_error(), "{tool}");
        let env = called.envelope();
        assert_eq!(code(&env), Some("usage"), "{tool}");
        assert_eq!(detail(&env, "tool"), Some(&json!(tool)), "{tool}");
        // A JSON-RPC result, not a JSON-RPC error.
        let line = rig
            .lines()
            .into_iter()
            .filter_map(|l| serde_json::from_str::<Value>(&l).ok())
            .find(|m| m.get("id") == Some(&id))
            .ok_or("no answer line")?;
        assert!(line.get("result").is_some(), "{tool}: {line}");
        assert!(line.get("error").is_none(), "{tool}: {line}");
        assert_eq!(rig.connector().connect_count(), 0, "{tool}");
    }
    Ok(())
}

/// Every line on the server's stdout is one JSON-RPC 2.0 response or notification.
fn assert_jsonrpc_lines(lines: &[String]) {
    assert!(!lines.is_empty());
    for line in lines {
        let msg: Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("not JSON ({e}): {line}"));
        let obj = msg
            .as_object()
            .unwrap_or_else(|| panic!("not an object: {line}"));
        assert_eq!(obj.get("jsonrpc"), Some(&json!("2.0")), "{line}");
        let response = obj.contains_key("id") && !obj.contains_key("method");
        let notification = obj.contains_key("method") && !obj.contains_key("id");
        assert!(response || notification, "{line}");
        if response {
            assert!(
                obj.contains_key("result") != obj.contains_key("error"),
                "result xor error: {line}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serve_writes_only_jsonrpc_lines() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    rig.list_tools().await;
    rig.call("ops_list", json!({}), true).await;
    rig.call("ops_describe", json!({"op_id": 7}), true).await;
    rig.call("no_such_tool", json!({"x": 1}), false).await;
    rig.call("request_status", json!({"request_id": "bad"}), true)
        .await;
    rig.close_stdin();
    assert!(matches!(rig.serve_result(WAIT).await, Some(Ok(()))));
    assert_jsonrpc_lines(&rig.lines());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdin_eof_ends_serve_with_ok() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    rig.call("ops_list", json!({}), false).await;
    let closed = Instant::now();
    rig.close_stdin();
    let served = rig.serve_result(WAIT).await.ok_or("still serving")?;
    assert!(served.is_ok(), "{served:?}");
    // Not rmcp's 5 s drain.
    assert!(
        closed.elapsed() < Duration::from_secs(2),
        "{:?}",
        closed.elapsed()
    );
    Ok(())
}

/// Bodies that wait until rmcp cancels the call's token, recording that they started and saw it.
#[derive(Default)]
struct WaitForCancel {
    started: AtomicBool,
    cancelled: AtomicBool,
}

impl ToolBodies for WaitForCancel {
    fn call<'a>(&'a self, _shared: &'a Shared, call: ToolCall) -> SendFuture<'a, Envelope> {
        Box::pin(async move {
            self.started.store(true, Ordering::SeqCst);
            call.context.ct.cancelled().await;
            self.cancelled.store(true, Ordering::SeqCst);
            local::usage("cancelled", Map::new())
        })
    }
}

/// I-6: at stdin EOF a waiting tool call is dropped at once (its token cancelled), not after
/// rmcp's 5 s drain; `serve` returns `Ok`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdin_eof_drops_waiting_tool_calls() -> TestResult {
    let bodies = Arc::new(WaitForCancel::default());
    let rig = Rig::new(RigOpts {
        bodies: Some(bodies.clone()),
        ..RigOpts::default()
    })
    .await;
    let _waiting = rig
        .start("request_status", json!({"request_id": REQ_ID}), true)
        .await;
    let until = Instant::now() + WAIT;
    while !bodies.started.load(Ordering::SeqCst) {
        assert!(Instant::now() < until, "the body never started");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    rig.close_stdin();
    let served = rig
        .serve_result(Duration::from_secs(2))
        .await
        .ok_or("serve still waits for the tool call")?;
    assert!(served.is_ok(), "{served:?}");
    assert!(bodies.cancelled.load(Ordering::SeqCst));
    Ok(())
}

/// The protocol-version decision: only revisions with an `initialize` handshake; a request that
/// names the 2026-07-28 inline lifecycle is refused, one that names 2025-11-25 is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inline_lifecycle_request_is_refused() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    let mut meta = RequestMetaObject::new();
    meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
    let started = rig.start_with_meta("ops_list", json!({}), meta).await;
    match rig.outcome_within(started, WAIT).await {
        Some(Err(ServiceError::McpError(e))) => {
            assert_eq!(e.code, McpErrorCode::UNSUPPORTED_PROTOCOL_VERSION, "{e:?}");
        }
        other => panic!("expected unsupported_protocol_version, got {other:?}"),
    }
    let mut meta = RequestMetaObject::new();
    meta.set_protocol_version(ProtocolVersion::V_2025_11_25);
    let started = rig.start_with_meta("ops_list", json!({}), meta).await;
    let served = rig.finish(started).await;
    assert!(!served.is_error());
    Ok(())
}

/// Bodies that record the `clientInfo.name` each tool call saw.
#[derive(Default)]
struct RecordClientName(std::sync::Mutex<Vec<Option<String>>>);

impl RecordClientName {
    fn seen(&self) -> Vec<Option<String>> {
        self.0.lock().unwrap().clone()
    }
}

impl ToolBodies for RecordClientName {
    fn call<'a>(&'a self, _shared: &'a Shared, call: ToolCall) -> SendFuture<'a, Envelope> {
        self.0.lock().unwrap().push(call.client_name());
        Box::pin(std::future::ready(local::ops_list()))
    }
}

/// T6 review I-1, `initialize` lifecycle: the name comes from the handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_name_from_initialize() -> TestResult {
    let bodies = Arc::new(RecordClientName::default());
    let rig = Rig::new(RigOpts {
        client_name: "desk".to_owned(),
        bodies: Some(bodies.clone()),
        ..RigOpts::default()
    })
    .await;
    let called = rig
        .call("request_status", json!({"request_id": REQ_ID}), false)
        .await;
    assert!(!called.is_error(), "{:?}", called.texts());
    assert_eq!(bodies.seen(), [Some("desk".to_owned())]);
    Ok(())
}

/// T6 review I-1, a client that never sends `initialize` (its first request carries the
/// lifecycle in `_meta`): the name comes from the request's `_meta.clientInfo`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_name_from_request_meta_without_initialize() -> TestResult {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let bodies = Arc::new(RecordClientName::default());
    let connector: Arc<dyn Connector> =
        Arc::new(TestConnector::failing(|| ConnectError::NotRunning));
    let server =
        AtlasMcp::new(plain_config(), connector, RIG_HEARTBEAT).with_bodies(bodies.clone());
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let (server_read, server_write) = tokio::io::split(server_end);
    let serve = tokio::spawn(serve_with(server, server_read, server_write));
    let (client_read, mut client_write) = tokio::io::split(client_end);
    let call = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "request_status",
            "arguments": {"request_id": REQ_ID},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                "io.modelcontextprotocol/clientInfo": {"name": "inline-client", "version": "1"},
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    });
    client_write
        .write_all(format!("{call}\n").as_bytes())
        .await?;
    let mut lines = BufReader::new(client_read).lines();
    let line = tokio::time::timeout(WAIT, lines.next_line())
        .await??
        .ok_or("no answer")?;
    let answer: Value = serde_json::from_str(&line)?;
    assert_eq!(answer.get("id"), Some(&json!(1)), "{answer}");
    assert!(answer.get("result").is_some(), "{answer}");
    assert_eq!(bodies.seen(), [Some("inline-client".to_owned())]);
    // Both halves: the pipe reports EOF once the whole client end is gone.
    drop((client_write, lines));
    let served = tokio::time::timeout(WAIT, serve).await??;
    assert!(served.is_ok(), "{served:?}");
    Ok(())
}

/// T6 review I-1: a client that probes with `server/discover` (rmcp's `Auto` lifecycle, 2026-07-28
/// first) is refused that revision, settles on 2025-11-25 without `initialize`, and is served;
/// its tool calls carry its name in `_meta`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovering_client_is_served_and_named() -> TestResult {
    let bodies = Arc::new(RecordClientName::default());
    let rig = Rig::new(RigOpts {
        client_name: "auto".to_owned(),
        bodies: Some(bodies.clone()),
        lifecycle: Some(ClientLifecycleMode::Auto {
            preferred_versions: vec![ProtocolVersion::V_2026_07_28, ProtocolVersion::V_2025_11_25],
            legacy_version: Some(ProtocolVersion::V_2025_11_25),
        }),
        ..RigOpts::default()
    })
    .await;
    let called = rig
        .call("request_status", json!({"request_id": REQ_ID}), false)
        .await;
    let lines: Vec<Value> = rig
        .lines()
        .iter()
        .map(|l| serde_json::from_str(l))
        .collect::<Result<_, _>>()?;
    let answers: Vec<&Value> = lines.iter().filter(|l| l.get("id").is_some()).collect();
    // 2026-07-28 refused, then the discover answer: no `initialize` ran.
    assert_eq!(
        answers
            .first()
            .and_then(|a| a.get("error"))
            .and_then(|e| e.get("code")),
        Some(&json!(-32022)),
        "{lines:?}"
    );
    let discovered = answers.get(1).and_then(|a| a.get("result"));
    assert!(
        discovered.is_some_and(|r| r.get("supportedVersions").is_some()),
        "{lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l
            .get("result")
            .is_some_and(|r| r.get("protocolVersion").is_some())),
        "an initialize answer: {lines:?}"
    );
    assert!(!called.is_error(), "{:?}", called.texts());
    assert_eq!(bodies.seen(), [Some("auto".to_owned())]);
    Ok(())
}

fn plain_config() -> McpConfig {
    RigOpts::default().config()
}

/// `run_on` on a thread of its own; `None` if it did not return within `WAIT`.
fn run_on_thread(input: &'static [u8]) -> Option<(i32, Duration)> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let connector: Arc<dyn Connector> =
            Arc::new(TestConnector::failing(|| ConnectError::NotRunning));
        let start = Instant::now();
        let code = run_on(plain_config(), connector, input, tokio::io::sink());
        let _ = tx.send((code, start.elapsed()));
    });
    rx.recv_timeout(WAIT).ok()
}

const INIT: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}\n";

#[test]
fn run_on_returns_after_stdin_eof() {
    // A closed reader before `initialize`, and one closed right after it.
    for input in [&b""[..], INIT] {
        let (code, took) = run_on_thread(input).expect("run_on returned");
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(input));
        assert!(took < Duration::from_secs(2), "{took:?}");
    }
}

/// How long the blocking task [`LeaveBlocking`] leaves behind sleeps.
const LEFT_BLOCKING: Duration = Duration::from_secs(6);

/// Bodies that leave a blocking task behind (like a launch poll still sleeping on its blocking
/// thread) and say so.
struct LeaveBlocking(std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>);

impl ToolBodies for LeaveBlocking {
    fn call<'a>(&'a self, _shared: &'a Shared, _call: ToolCall) -> SendFuture<'a, Envelope> {
        drop(tokio::task::spawn_blocking(|| {
            std::thread::sleep(LEFT_BLOCKING)
        }));
        if let Some(tx) = self.0.lock().unwrap().take() {
            let _ = tx.send(());
        }
        Box::pin(std::future::ready(local::ops_list()))
    }
}

/// T6 review M-5: `run_on` returns at stdin EOF although a blocking task is still running (the
/// runtime is shut down in the background; dropping it would wait for the task).
#[test]
fn run_on_does_not_wait_for_blocking_tasks() {
    use tokio::io::AsyncWriteExt;

    const CALL: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"request_status\",\"arguments\":{\"request_id\":\"req_00000000000000000000000000000001\"}}}\n";
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let bodies = Arc::new(LeaveBlocking(std::sync::Mutex::new(Some(started_tx))));
    let (input, feed) = tokio::io::duplex(1 << 16);
    // Feeds `initialize` and one tool call, then closes stdin once the body left its task.
    let feeder = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("feeder runtime");
        rt.block_on(async move {
            let mut feed = feed;
            feed.write_all(INIT).await.expect("write initialize");
            feed.write_all(CALL).await.expect("write tools/call");
            let started = started_rx.recv_timeout(WAIT).is_ok();
            drop(feed);
            started
        })
    });
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let connector: Arc<dyn Connector> =
            Arc::new(TestConnector::failing(|| ConnectError::NotRunning));
        let server = AtlasMcp::new(plain_config(), connector, RIG_HEARTBEAT).with_bodies(bodies);
        let start = Instant::now();
        let code = run_on_with(server, input, tokio::io::sink());
        let _ = tx.send((code, start.elapsed()));
    });
    let (code, took) = rx.recv_timeout(WAIT).expect("run_on returned");
    assert!(feeder.join().expect("feeder"), "the body never ran");
    assert_eq!(code, 0);
    assert!(took < Duration::from_secs(3), "{took:?}");
}

// ---------- the rig itself, over a plain IpcClient ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rig_fake_hello_modes() -> TestResult {
    let app = RigApp::new(RigOpts::default().fake, true);
    let first = app.ipc_client().await?;
    let seen = app.fake.hellos();
    assert_eq!(seen.len(), 1);
    let one = seen.first().ok_or("no hello")?;
    assert_eq!(one.hello.build_id, RIG_BUILD);
    assert_eq!(one.hello.client_kind, ClientKind::Cli);
    assert_eq!(one.hello.cwd_basename, "rig");
    assert!(!one.connection_id.is_empty());
    assert_eq!(app.fake.count(Kind::Hello), 1);

    // `Exact` refuses another build and names its own.
    app.connector.set_hello_build("1.0.1+other");
    match app.ipc_client().await {
        Err(ConnectError::BuildMismatch {
            client_newer,
            server_build,
            ..
        }) => {
            assert!(client_newer);
            assert_eq!(server_build, RIG_BUILD);
        }
        other => panic!("expected a build mismatch, got {other:?}"),
    }

    // `Refuse` answers its envelope; switching affects the next hello.
    app.fake.set_hello_mode(HelloMode::Refuse(reason_envelope(
        ErrorCode::Unreachable,
        "app_shutting_down",
    )));
    match app.ipc_client().await {
        Err(ConnectError::Hello(env)) => {
            let env = serde_json::to_value(env)?;
            assert_eq!(detail(&env, "reason"), Some(&json!("app_shutting_down")));
        }
        other => panic!("expected the refusal, got {other:?}"),
    }
    app.fake.set_hello_mode(HelloMode::AcceptAll);
    let second = app.ipc_client().await?;

    let seen = app.fake.hellos();
    assert_eq!(seen.len(), 4);
    let ids: Vec<&str> = seen.iter().map(|h| h.connection_id.as_str()).collect();
    for (i, a) in ids.iter().enumerate() {
        assert!(!ids.iter().skip(i + 1).any(|b| b == a), "{ids:?}");
    }
    drop((first, second));
    Ok(())
}

fn submit_params() -> SubmitParams {
    SubmitParams {
        op_id: "jira.issue.get".to_owned(),
        params: json!({"key": "A-1"}),
        instance: None,
        reason: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rig_fake_submit_and_status_answers() -> TestResult {
    let app = RigApp::new(RigOpts::default().fake, true);
    let mut client = app.ipc_client().await?;

    // Default: pending with the request id.
    let reply: SubmitReply = client.call(method::REQUEST_SUBMIT, submit_params()).await?;
    assert_eq!(reply.envelope.status, Status::Pending);
    assert_eq!(reply.envelope.request_id.as_deref(), Some(REQ_ID));

    // A configured answer comes back unchanged.
    let mut busy = Envelope::failed(ErrorCode::Busy, true, "busy");
    if let Some(err) = busy.error.as_mut() {
        let mut d = Map::new();
        d.insert("retry_after_s".to_owned(), json!(7));
        err.details = Some(d);
    }
    app.fake.set_submit_answer(Some(busy.clone()));
    let reply: SubmitReply = client.call(method::REQUEST_SUBMIT, submit_params()).await?;
    assert_eq!(reply.envelope, busy);
    assert_eq!(reply.params_sha256, None);
    app.fake.set_submit_answer(None);

    // Known ids answer their envelope with the id; others the default answer.
    let mut denied = Envelope::failed(ErrorCode::Denied, false, "use await for details");
    denied.status = Status::Denied;
    app.fake.set_status(OTHER_ID, denied);
    let known: Envelope = client
        .call(
            method::REQUEST_STATUS,
            IdParams {
                request_id: OTHER_ID.to_owned(),
            },
        )
        .await?;
    assert_eq!(known.status, Status::Denied);
    assert_eq!(known.request_id.as_deref(), Some(OTHER_ID));
    let unknown: Envelope = client
        .call(
            method::REQUEST_STATUS,
            IdParams {
                request_id: REQ_ID.to_owned(),
            },
        )
        .await?;
    assert_eq!(unknown.data, Some(json!({"method": "request.status"})));

    // `submit_hold`: recorded, never answered.
    app.fake.set_submit_hold(true);
    let mut held = app.ipc_client().await?;
    let before = app.fake.submits.lock().map(|g| g.len()).unwrap_or(0);
    let waited = tokio::time::timeout(
        Duration::from_millis(500),
        held.call::<SubmitReply>(method::REQUEST_SUBMIT, submit_params()),
    )
    .await;
    assert!(waited.is_err(), "a held submit answered: {waited:?}");
    let after = app.fake.submits.lock().map(|g| g.len()).unwrap_or(0);
    assert_eq!(after, before + 1);
    assert_eq!(app.fake.count(Kind::Submit), 3);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rig_fake_await_honours_timeout_and_schedule() -> TestResult {
    let app = RigApp::new(RigOpts::default().fake, true);
    let mut client = app.ipc_client().await?;
    let ms = Duration::from_millis;

    // No decision: progress at the offsets, then `pending` with the id at `timeout_ms`.
    app.fake.set_await_script(Some(AwaitScript {
        progress: vec![(ms(100), Status::Executing), (ms(250), Status::Executing)],
        decision: None,
    }));
    let start = Instant::now();
    let mut seen: Vec<(Duration, ProgressNotification)> = Vec::new();
    let env: Envelope = client
        .call_with_progress(
            method::REQUEST_AWAIT,
            AwaitParams {
                request_id: REQ_ID.to_owned(),
                timeout_ms: Some(600),
            },
            &mut |n| seen.push((start.elapsed(), n)),
        )
        .await?;
    let took = start.elapsed();
    assert_eq!(env.status, Status::Pending);
    assert_eq!(env.request_id.as_deref(), Some(REQ_ID));
    assert!(took >= ms(600) && took < ms(1600), "{took:?}");
    assert_eq!(seen.len(), 2, "{seen:?}");
    for ((at, n), offset) in seen.iter().zip([ms(100), ms(250)]) {
        assert!(*at >= offset, "{at:?} < {offset:?}");
        assert_eq!(n.request_id, REQ_ID);
        assert_eq!(n.status, Status::Executing);
    }

    // A decision before the timeout ends the wait with it; later progress is not sent.
    let mut released = Envelope::failed(ErrorCode::Internal, false, "");
    released.status = Status::Released;
    released.error = None;
    app.fake.set_await_script(Some(AwaitScript {
        progress: vec![(ms(50), Status::Executing), (ms(900), Status::Executing)],
        decision: Some((ms(300), released)),
    }));
    let start = Instant::now();
    let mut count = 0;
    let env: Envelope = client
        .call_with_progress(
            method::REQUEST_AWAIT,
            AwaitParams {
                request_id: REQ_ID.to_owned(),
                timeout_ms: Some(5_000),
            },
            &mut |_| count += 1,
        )
        .await?;
    let took = start.elapsed();
    assert_eq!(env.status, Status::Released);
    assert_eq!(env.request_id.as_deref(), Some(REQ_ID));
    assert!(took >= ms(300) && took < ms(1300), "{took:?}");
    assert_eq!(count, 1);
    assert_eq!(app.fake.count(Kind::AwaitDone), 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rig_restart_server_repoints_connector() -> TestResult {
    let app = RigApp::new(RigOpts::default().fake, true);
    let mut old = app.ipc_client().await?;
    app.restart_server("2.0.0+x").await;

    // The old connection is gone.
    let lost = tokio::time::timeout(
        WAIT,
        old.call::<Envelope>(
            method::REQUEST_STATUS,
            IdParams {
                request_id: REQ_ID.to_owned(),
            },
        ),
    )
    .await?;
    assert!(matches!(lost, Err(ClientError::ConnectionLost)), "{lost:?}");

    // The next connect reaches the new server, whose hello refuses the old build.
    match app.ipc_client().await {
        Err(ConnectError::BuildMismatch {
            client_newer,
            server_build,
            ..
        }) => {
            assert!(!client_newer);
            assert_eq!(server_build, "2.0.0+x");
        }
        other => panic!("expected a build mismatch, got {other:?}"),
    }
    // A client of the new build is served.
    app.connector.set_hello_build("2.0.0+x");
    let mut new = app.ipc_client().await?;
    let env: Envelope = new
        .call(
            method::REQUEST_STATUS,
            IdParams {
                request_id: REQ_ID.to_owned(),
            },
        )
        .await?;
    assert_eq!(env.status, Status::Succeeded);
    let builds: Vec<String> = app
        .fake
        .hellos()
        .into_iter()
        .map(|h| h.hello.build_id)
        .collect();
    assert_eq!(builds, [RIG_BUILD, RIG_BUILD, "2.0.0+x"]);

    // `drop_connections` keeps the build.
    app.drop_connections().await;
    assert_eq!(app.fake.build(), "2.0.0+x");
    let _again = app.ipc_client().await?;
    Ok(())
}

// ---------- the session (Task 7): `Session::client` against the rig's app ----------

fn deadline_in(limit: Duration) -> Deadline {
    Deadline::new(Instant::now(), Some(limit))
}

fn session_of(app: &RigApp, cfg: &McpConfig) -> Arc<Session> {
    let connector: Arc<dyn Connector> = app.connector.clone();
    Arc::new(Session::new(cfg, connector))
}

/// `Session::client` within `WAIT`, its refusal as a test error.
async fn connect(session: &Session, client_name: Option<&str>) -> Result<SharedClient, String> {
    session
        .client(&deadline_in(WAIT), client_name)
        .await
        .map_err(|env| format!("refused: {env:?}"))
}

/// One `request.status` over `client`.
async fn status_over(client: &SharedClient) -> Result<Envelope, String> {
    let params = IdParams {
        request_id: REQ_ID.to_owned(),
    };
    let sent = client
        .call::<Envelope>(method::REQUEST_STATUS, params, Some(Instant::now() + WAIT))
        .await;
    sent.result.map_err(|e| format!("request.status: {e:?}"))
}

/// Polls until `client` reports its connection closed (the reader sees the EOF on its own
/// schedule); fails the test after `WAIT`.
async fn wait_closed(client: &SharedClient) {
    let until = Instant::now() + WAIT;
    while !client.is_closed() {
        assert!(Instant::now() < until, "the old connection never closed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn reason_of(env: &Envelope) -> Option<String> {
    let env = serde_json::to_value(env).ok()?;
    detail(&env, "reason")?.as_str().map(str::to_owned)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hello_is_mcp_with_client_info_name() -> TestResult {
    let app = RigApp::new(RigOpts::default().fake, true);
    let session = session_of(&app, &RigOpts::default().config());
    connect(&session, Some("desk")).await?;
    let seen = app.fake.hellos();
    assert_eq!(seen.len(), 1);
    let hello = &seen.first().ok_or("no hello")?.hello;
    assert_eq!(hello.client_kind, ClientKind::Mcp);
    assert_eq!(hello.agent_name.as_deref(), Some("desk"));
    assert_eq!(hello.agent_name_source, AgentNameSource::McpClientInfo);
    assert_eq!(hello.cwd_basename, cwd_basename());
    Ok(())
}

/// The configuration argv and `ATLAS_DUCK_AGENT` make for `args`.
fn mcp_config(args: &[&str], env_agent: Option<&str>) -> McpConfig {
    let args: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
    let env = |k: &str| {
        (k == "ATLAS_DUCK_AGENT")
            .then(|| env_agent.map(std::ffi::OsString::from))
            .flatten()
    };
    let parsed = crate::argv::parse(
        &args,
        &env,
        &mut crate::input::Inputs::new(std::io::empty()),
    );
    let (opts, cmd) = parsed.unwrap_or_else(|e| panic!("{args:?}: {}", e.message));
    let crate::argv::Command::Mcp {
        tools,
        instance,
        agent_given,
    } = cmd
    else {
        panic!("{args:?}: not mcp: {cmd:?}");
    };
    McpConfig::from_env(&opts, tools, instance, agent_given, &env)
        .unwrap_or_else(|e| panic!("{args:?}: {}", e.message))
}

/// PD-122 / L158: `--agent` > `ATLAS_DUCK_AGENT` > `clientInfo.name` > none; `--agent ""` is no
/// agent at all (neither the environment nor `clientInfo` fills it); an empty
/// `ATLAS_DUCK_AGENT` or `clientInfo.name` counts as absent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_flag_and_env_override_client_info() -> TestResult {
    use AgentNameSource as Src;
    // `ATLAS_DUCK_AGENT=e`; `clientInfo.name` "desk".
    const E: Option<&str> = Some("e");
    const D: Option<&str> = Some("desk");
    // (argv, ATLAS_DUCK_AGENT, clientInfo.name) -> (agent name, its source)
    type Row<'a> = (
        &'a [&'a str],
        Option<&'a str>,
        Option<&'a str>,
        Option<&'a str>,
        Src,
    );
    let table: [Row; 9] = [
        (&["mcp", "--agent", "a"], E, D, Some("a"), Src::Flag),
        (&["mcp", "--agent", "a"], None, None, Some("a"), Src::Flag),
        (&["mcp"], E, D, Some("e"), Src::Env),
        (&["mcp", "--agent", ""], E, D, None, Src::None),
        (&["mcp", "--agent="], None, D, None, Src::None),
        (&["mcp"], Some(""), D, D, Src::McpClientInfo),
        (&["mcp"], None, D, D, Src::McpClientInfo),
        (&["mcp"], None, Some(""), None, Src::None),
        (&["mcp"], None, None, None, Src::None),
    ];
    for (args, env, client, name, source) in table {
        let hello = hello_of(&mcp_config(args, env), client);
        let row = format!("{args:?} env={env:?} clientInfo={client:?}");
        assert_eq!(hello.client_kind, ClientKind::Mcp, "{row}");
        // L16: this build's id (the rig's connector replaces it on the wire, so only here).
        assert_eq!(hello.build_id, BUILD_ID, "{row}");
        assert_eq!(hello.agent_name.as_deref(), name, "{row}");
        assert_eq!(hello.agent_name_source, source, "{row}");
    }

    // The `--agent ""` row end to end: the app's hello carries no agent.
    let app = RigApp::new(RigOpts::default().fake, true);
    let session = session_of(&app, &mcp_config(&["mcp", "--agent", ""], Some("e")));
    connect(&session, Some("desk")).await?;
    let seen = app.fake.hellos();
    let hello = &seen.first().ok_or("no hello")?.hello;
    assert_eq!(hello.agent_name, None);
    assert_eq!(hello.agent_name_source, Src::None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_connects_lazily() -> TestResult {
    let app = RigApp::new(RigOpts::default().fake, true);
    let session = session_of(&app, &RigOpts::default().config());
    assert_eq!(app.connector.discover_count(), 0);
    assert_eq!(app.connector.connect_count(), 0);
    assert!(app.fake.hellos().is_empty());

    let first = connect(&session, None).await?;
    let second = connect(&session, None).await?;
    assert_eq!(app.connector.connect_count(), 1);
    assert_eq!(app.fake.hellos().len(), 1);
    status_over(&first).await?;
    status_over(&second).await?;
    assert_eq!(app.fake.count(Kind::Status), 2);
    assert_eq!(app.fake.hellos().len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_session_clients_share_one_connection() -> TestResult {
    let app = RigApp::new(RigOpts::default().fake, true);
    let session = session_of(&app, &RigOpts::default().config());
    let calls: Vec<_> = (0..8)
        .map(|_| {
            let session = session.clone();
            tokio::spawn(async move {
                let client = connect(&session, Some("desk")).await?;
                status_over(&client).await
            })
        })
        .collect();
    for call in calls {
        let env = tokio::time::timeout(WAIT, call).await???;
        assert_eq!(env.status, Status::Succeeded);
    }
    assert_eq!(app.fake.count(Kind::Status), 8);
    assert_eq!(app.fake.hellos().len(), 1, "one hello, one connection_id");
    assert_eq!(app.connector.connect_count(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_flight_reconnect() -> TestResult {
    let app = RigApp::new(RigOpts::default().fake, true);
    let session = session_of(&app, &RigOpts::default().config());
    let old = connect(&session, None).await?;
    // An app restart (same build) closes the connection.
    app.drop_connections().await;
    wait_closed(&old).await;

    let calls: Vec<_> = (0..5)
        .map(|_| {
            let session = session.clone();
            tokio::spawn(async move {
                let client = connect(&session, None).await?;
                status_over(&client).await?;
                Ok::<SharedClient, String>(client)
            })
        })
        .collect();
    for call in calls {
        let client = tokio::time::timeout(WAIT, call).await???;
        assert!(!client.is_closed());
    }
    let seen = app.fake.hellos();
    assert_eq!(seen.len(), 2, "exactly one new hello");
    assert_eq!(app.connector.connect_count(), 2);
    let ids: Vec<&str> = seen.iter().map(|h| h.connection_id.as_str()).collect();
    assert_ne!(ids.first(), ids.get(1));
    assert!(old.is_closed());
    Ok(())
}

/// R1: `mark_closed` never drops an open connection, also when a call that held the old client
/// reports its loss after another call already reconnected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mark_closed_never_drops_a_live_connection() -> TestResult {
    let app = RigApp::new(RigOpts::default().fake, true);
    let session = session_of(&app, &RigOpts::default().config());
    let first = connect(&session, None).await?;
    session.mark_closed();
    connect(&session, None).await?;
    assert_eq!(app.fake.hellos().len(), 1, "marked closed while open");

    app.drop_connections().await;
    wait_closed(&first).await;
    connect(&session, None).await?;
    assert_eq!(app.fake.hellos().len(), 2);
    // A late report about `first`.
    session.mark_closed();
    let still = connect(&session, None).await?;
    status_over(&still).await?;
    assert_eq!(app.fake.hellos().len(), 2, "a stale report reconnected");
    assert_eq!(app.connector.connect_count(), 2);
    Ok(())
}

/// PD-128: a failed attempt answers that call only and caches nothing; the next call retries.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_reach_leaves_state_unchanged() -> TestResult {
    let app = RigApp::new(RigOpts::default().fake, true);
    let session = session_of(&app, &RigOpts::default().config());
    app.fake.set_hello_mode(HelloMode::Refuse(reason_envelope(
        ErrorCode::Unreachable,
        "app_shutting_down",
    )));
    let refused = connect(&session, None).await.err().ok_or("connected")?;
    assert!(refused.contains("app_shutting_down"), "{refused}");
    let refused = session
        .client(&deadline_in(WAIT), None)
        .await
        .err()
        .ok_or("connected")?;
    assert_eq!(reason_of(&refused).as_deref(), Some("app_shutting_down"));
    app.fake.set_hello_mode(HelloMode::Exact);
    let client = connect(&session, None).await?;
    status_over(&client).await?;
    assert_eq!(app.fake.hellos().len(), 3);

    // From a closed connection: the app comes back as another build (refused), then as this
    // server's build again.
    app.restart_server("2.0.0+x").await;
    wait_closed(&client).await;
    let mismatch = session
        .client(&deadline_in(WAIT), None)
        .await
        .err()
        .ok_or("connected to another build")?;
    let mismatch = serde_json::to_value(&mismatch)?;
    assert_eq!(code(&mismatch), Some("protocol_mismatch"));
    assert_eq!(detail(&mismatch, "server_build"), Some(&json!("2.0.0+x")));
    app.restart_server(RIG_BUILD).await;
    let back = connect(&session, None).await?;
    status_over(&back).await?;
    assert_eq!(app.fake.hellos().len(), 5);
    Ok(())
}

/// The launch poll inside `client` stops at the caller's deadline (real clock).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_reach_capped_by_deadline() -> TestResult {
    let app = RigApp::new(RigOpts::default().fake, false);
    let session = session_of(&app, &RigOpts::default().config());
    let start = Instant::now();
    let refused = session
        .client(&deadline_in(Duration::from_secs(1)), None)
        .await
        .err()
        .ok_or("connected without an app")?;
    let took = start.elapsed();
    assert_eq!(reason_of(&refused).as_deref(), Some("launch_timeout"));
    // The poll ran (no instant `app_not_found`) and ended at the deadline.
    assert!(took >= Duration::from_millis(900), "{took:?}");
    assert!(took < Duration::from_secs(2), "{took:?}");
    assert!(app.connector.discover_count() >= 1);
    assert_eq!(app.connector.connect_count(), 0);
    Ok(())
}

/// A call that waits for another call's attempt is bounded by its own deadline: it answers
/// `launch_timeout` with nothing queued while the other attempt is still polling.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn waiting_for_another_reach_is_bounded_by_own_deadline() -> TestResult {
    let app = RigApp::new(RigOpts::default().fake, false);
    let session = session_of(&app, &RigOpts::default().config());
    let first = {
        let session = session.clone();
        tokio::spawn(async move {
            session
                .client(&deadline_in(Duration::from_secs(3)), None)
                .await
                .err()
        })
    };
    // The first call holds the attempt (its launch poll runs).
    let until = Instant::now() + WAIT;
    while app.connector.discover_count() == 0 {
        assert!(Instant::now() < until, "the first attempt never started");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let start = Instant::now();
    let refused = session
        .client(&deadline_in(Duration::from_millis(500)), None)
        .await
        .err()
        .ok_or("connected without an app")?;
    let took = start.elapsed();
    assert_eq!(reason_of(&refused).as_deref(), Some("launch_timeout"));
    assert!(took < Duration::from_millis(1500), "{took:?}");
    assert!(!first.is_finished(), "the first attempt ended early");
    assert_eq!(
        app.connector.discover_count(),
        1,
        "the waiter made its own attempt"
    );
    let first = tokio::time::timeout(WAIT, first).await??;
    assert_eq!(
        first.as_ref().and_then(reason_of).as_deref(),
        Some("launch_timeout")
    );
    Ok(())
}

/// T7 review M-2: with `ATLAS_DUCK_MCP_TIMEOUT=0` (no deadline) a call waiting for another call's
/// attempt gives up after the session's own bound (`OWN_LIMIT`; shorter here) with
/// `launch_timeout`, nothing queued, instead of queueing behind every earlier attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unbounded_wait_for_another_reach_is_bounded_by_own_limit() -> TestResult {
    let app = RigApp::new(RigOpts::default().fake, false);
    let connector: Arc<dyn Connector> = app.connector.clone();
    let session = Arc::new(
        Session::new(&RigOpts::default().config(), connector)
            .with_lock_limit(Duration::from_millis(500)),
    );
    let first = {
        let session = session.clone();
        tokio::spawn(async move {
            session
                .client(&deadline_in(Duration::from_secs(3)), None)
                .await
                .err()
        })
    };
    let until = Instant::now() + WAIT;
    while app.connector.discover_count() == 0 {
        assert!(Instant::now() < until, "the first attempt never started");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let start = Instant::now();
    let unbounded = Deadline::new(Instant::now(), None);
    let refused = tokio::time::timeout(WAIT, session.client(&unbounded, None))
        .await
        .map_err(|_| "the unbounded waiter never gave up")?
        .err()
        .ok_or("connected without an app")?;
    let took = start.elapsed();
    assert_eq!(reason_of(&refused).as_deref(), Some("launch_timeout"));
    assert!(took < Duration::from_millis(1500), "{took:?}");
    assert!(!first.is_finished(), "the first attempt ended early");
    assert_eq!(
        app.connector.discover_count(),
        1,
        "the waiter made an attempt"
    );
    tokio::time::timeout(WAIT, first).await??;
    Ok(())
}

// ---------- the tool bodies (Task 8) ----------

fn submits(rig: &Rig) -> Vec<SubmitParams> {
    rig.fake().submits.lock().unwrap().clone()
}

fn submit(
    op_id: &str,
    params: Value,
    instance: Option<&str>,
    reason: Option<&str>,
) -> SubmitParams {
    SubmitParams {
        op_id: op_id.to_owned(),
        params,
        instance: instance.map(str::to_owned),
        reason: reason.map(str::to_owned),
    }
}

/// A well-formed request id of its own.
fn id_n(n: u32) -> String {
    format!("req_{n:032}")
}

/// Polls until `done` holds; fails the test after `WAIT`.
async fn until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !done() {
        assert!(Instant::now() < deadline, "never: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The connection ids of every hello the Fake saw.
fn connection_ids(rig: &Rig) -> Vec<String> {
    rig.fake()
        .hellos()
        .into_iter()
        .map(|h| h.connection_id)
        .collect()
}

fn released(data: Value) -> Envelope {
    let mut env = Envelope::failed(ErrorCode::Internal, false, "");
    env.status = Status::Released;
    env.error = None;
    env.data = Some(data);
    env
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn op_tool_submits_op_id_params_reason_instance() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    let called = rig
        .call(
            "jira_issue_get",
            json!({"key": "A-1", "reason": "triage", "instance": "dc"}),
            false,
        )
        .await;
    assert!(!called.is_error(), "{:?}", called.texts());
    assert_eq!(
        submits(&rig),
        [submit(
            "jira.issue.get",
            json!({"key": "A-1"}),
            Some("dc"),
            Some("triage")
        )]
    );
    assert_eq!(rig.fake().count(Kind::Submit), 1);
    // Then the wait: the Fake's await answer is the result, `timeout_ms` the time left.
    let awaits = rig.fake().awaits.lock().unwrap().clone();
    let first = awaits.first().ok_or("no request.await")?;
    assert_eq!(first.request_id, REQ_ID);
    let ms = first.timeout_ms.ok_or("no timeout_ms")?;
    assert!(ms > 0 && ms <= 5_000, "{ms}");
    assert_eq!(
        called.envelope()["data"],
        json!({"method": "request.await"})
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_tool_submits_like_op_tool() -> TestResult {
    let rig = Rig::new(RigOpts {
        tools: ToolSet::Generic,
        ..RigOpts::default()
    })
    .await;
    let called = rig
        .call(
            "call",
            json!({
                "op_id": "jira.issue.get",
                "params": {"key": "A-1"},
                "reason": "triage",
                "instance": "dc",
            }),
            false,
        )
        .await;
    assert!(!called.is_error(), "{:?}", called.texts());
    assert_eq!(
        submits(&rig),
        [submit(
            "jira.issue.get",
            json!({"key": "A-1"}),
            Some("dc"),
            Some("triage")
        )]
    );
    assert_eq!(rig.fake().count(Kind::Submit), 1);
    Ok(())
}

/// §9.1/§9.5 `script.submit` params; §4.4 + PD-124: a script names no instance, not even the
/// server's default one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn script_run_submits_script_params_without_instance() -> TestResult {
    let rig = Rig::new(RigOpts {
        instance: Some("dflt".to_owned()),
        ..RigOpts::default()
    })
    .await;
    let full = rig
        .call(
            "script_run",
            json!({
                "source": "return 1",
                "args": {"a": [1, 2]},
                "limits": {"timeout_s": 5},
                "reason": "why",
            }),
            false,
        )
        .await;
    assert!(!full.is_error(), "{:?}", full.texts());
    let bare = rig
        .call("script_run", json!({"source": "return 2"}), false)
        .await;
    assert!(!bare.is_error(), "{:?}", bare.texts());
    assert_eq!(
        submits(&rig),
        [
            submit(
                "script.run",
                json!({"source": "return 1", "args": {"a": [1, 2]}, "limits": {"timeout_s": 5}}),
                None,
                Some("why"),
            ),
            submit(
                "script.run",
                json!({"source": "return 2", "args": {}}),
                None,
                None
            ),
        ]
    );
    assert_eq!(rig.fake().count(Kind::ScriptSubmit), 2);
    assert_eq!(rig.fake().count(Kind::Submit), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn script_run_dry_run_values_full_and_sparse() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    for mode in ["full", "sparse"] {
        let called = rig
            .call(
                "script_run",
                json!({"source": "return 1", "dry_run": mode}),
                false,
            )
            .await;
        assert!(!called.is_error(), "{mode}: {:?}", called.texts());
    }
    let dry: Vec<Value> = submits(&rig)
        .into_iter()
        .map(|s| s.params["dry_run"].clone())
        .collect();
    assert_eq!(dry, [json!("full"), json!("sparse")]);
    Ok(())
}

/// PD-124: `--instance` fills op tools, `call` and `request_list.match_params` without an
/// instance; `ops_list`/`ops_describe` without one stay local; `script_run` names none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn default_instance_fills_op_and_match_params_not_ops_or_script() -> TestResult {
    let full = Rig::new(RigOpts {
        instance: Some("dflt".to_owned()),
        ..RigOpts::default()
    })
    .await;
    full.call("jira_issue_get", json!({"key": "A-1"}), false)
        .await;
    full.call(
        "jira_issue_get",
        json!({"key": "A-1", "instance": "x"}),
        false,
    )
    .await;
    full.call("script_run", json!({"source": "return 1"}), false)
        .await;
    let instances: Vec<Option<String>> = submits(&full).into_iter().map(|s| s.instance).collect();
    assert_eq!(
        instances,
        [Some("dflt".to_owned()), Some("x".to_owned()), None]
    );

    let mp = json!({"op_id": "jira.issue.get", "params": {"key": "A-1"}});
    full.call("request_list", json!({"match_params": mp}), false)
        .await;
    let mut mp_x = mp.clone();
    mp_x["instance"] = json!("x");
    full.call("request_list", json!({"match_params": mp_x}), false)
        .await;
    let listed: Vec<Option<String>> = full
        .fake()
        .lists
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, m)| m.as_ref().and_then(|m| m.instance.clone()))
        .collect();
    assert_eq!(listed, [Some("dflt".to_owned()), Some("x".to_owned())]);

    // The app-free tools stay local: the default instance does not make them connect.
    let list = full.call("ops_list", json!({}), false).await;
    assert_eq!(list.envelope(), serde_json::to_value(local::ops_list())?);
    full.call("ops_describe", json!({"op_id": "jira.issue.get"}), false)
        .await;
    assert_eq!(full.fake().count(Kind::OpsList), 0);
    assert_eq!(full.fake().count(Kind::OpsDescribe), 0);

    let generic = Rig::new(RigOpts {
        tools: ToolSet::Generic,
        instance: Some("dflt".to_owned()),
        ..RigOpts::default()
    })
    .await;
    generic
        .call(
            "call",
            json!({"op_id": "jira.issue.get", "params": {"key": "A-1"}}),
            false,
        )
        .await;
    let instances: Vec<Option<String>> =
        submits(&generic).into_iter().map(|s| s.instance).collect();
    assert_eq!(instances, [Some("dflt".to_owned())]);
    Ok(())
}

/// PD-118: a fixed tool's bad argument is answered before any connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixed_tool_arguments_validated_locally() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    for (tool, args, arg) in [
        (
            "request_status",
            json!({"request_id": "req_short"}),
            "request_id",
        ),
        ("request_await", json!({"request_id": 7}), "request_id"),
        (
            "script_run",
            json!({"source": "return 1", "dry_run": "maybe"}),
            "dry_run",
        ),
    ] {
        let called = rig.call(tool, args, false).await;
        assert!(called.is_error(), "{tool}");
        let env = called.envelope();
        assert_eq!(code(&env), Some("usage"), "{tool}");
        assert_eq!(detail(&env, "arg"), Some(&json!(arg)), "{tool}");
    }
    assert_eq!(rig.connector().connect_count(), 0);
    assert_eq!(rig.connector().discover_count(), 0);
    Ok(())
}

/// L131 through MCP: a `pending` submit reply without a request id is `protocol_error`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_pending_reply_without_id_is_protocol_error() -> TestResult {
    let mut fake = RigOpts::default().fake;
    fake.submit_null_id = true;
    let rig = Rig::new(RigOpts {
        fake,
        ..RigOpts::default()
    })
    .await;
    let called = rig
        .call("jira_issue_get", json!({"key": "A-1"}), false)
        .await;
    assert!(called.is_error());
    let env = called.envelope();
    assert_eq!(env["status"], "failed");
    assert_eq!(code(&env), Some("protocol_error"));
    assert_eq!(env["request_id"], Value::Null);
    assert_eq!(rig.fake().count(Kind::Submit), 1);
    assert_eq!(
        rig.fake().count(Kind::AwaitStart),
        0,
        "awaited without an id"
    );
    Ok(())
}

/// L131 through MCP: an await answer naming another request is `protocol_error`, after a submit
/// and for `request_await`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_await_reply_naming_another_request_is_protocol_error() -> TestResult {
    let mut fake = RigOpts::default().fake;
    fake.await_reply_id = Some(OTHER_ID);
    let rig = Rig::new(RigOpts {
        fake,
        ..RigOpts::default()
    })
    .await;
    for (tool, args) in [
        ("jira_issue_get", json!({"key": "A-1"})),
        ("request_await", json!({"request_id": REQ_ID})),
    ] {
        let called = rig.call(tool, args, false).await;
        assert!(called.is_error(), "{tool}");
        let env = called.envelope();
        assert_eq!(code(&env), Some("protocol_error"), "{tool}");
        assert_eq!(env["request_id"], Value::Null, "{tool}");
    }
    assert_eq!(rig.fake().count(Kind::AwaitDone), 2);
    Ok(())
}

/// I-16 / §4.4: `request_status` of a known id answers at once and is never an error, whatever
/// the request's state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_of_known_id_is_not_error() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    let mut pending = released(Value::Null);
    pending.status = Status::Pending;
    pending.data = None;
    let mut denied = Envelope::failed(ErrorCode::Denied, false, "denied by the user");
    denied.status = Status::Denied;
    if let Some(err) = denied.error.as_mut() {
        let mut d = Map::new();
        d.insert("hint".to_owned(), json!("use the sandbox project"));
        err.details = Some(d);
    }
    let upstream = released(json!({"error": {"status": 404}}));
    let mut failed_write = Envelope::failed(ErrorCode::UpstreamHttp, false, "HTTP 400");
    failed_write.op_id = Some("jira.issue.create".to_owned());
    let table = [
        pending,
        released(json!({"key": "A-1"})),
        denied,
        upstream,
        failed_write,
    ];
    for (n, env) in table.into_iter().enumerate() {
        let id = id_n(100 + u32::try_from(n)?);
        rig.fake().set_status(&id, env.clone());
        let called = rig
            .call("request_status", json!({"request_id": id}), false)
            .await;
        assert!(!called.is_error(), "{id}: {:?}", called.texts());
        let mut want = env;
        want.request_id = Some(id.clone());
        assert_eq!(called.envelope(), serde_json::to_value(want)?, "{id}");
    }
    assert_eq!(rig.fake().count(Kind::AwaitStart), 0);
    Ok(())
}

/// I-04: `request_status` never waits (the Fake would hold an await for a minute).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i04_request_status_never_blocks() -> TestResult {
    let mut fake = RigOpts::default().fake;
    fake.await_delay = Duration::from_secs(60);
    let rig = Rig::new(RigOpts {
        fake,
        ..RigOpts::default()
    })
    .await;
    // Connect first, so the measured call is the status call alone.
    rig.call("request_status", json!({"request_id": REQ_ID}), false)
        .await;
    let start = Instant::now();
    let called = rig
        .call("request_status", json!({"request_id": REQ_ID}), true)
        .await;
    let took = start.elapsed();
    assert!(!called.is_error(), "{:?}", called.texts());
    assert!(took < Duration::from_secs(1), "{took:?}");
    assert_eq!(rig.fake().count(Kind::Status), 2);
    assert_eq!(rig.fake().count(Kind::AwaitStart), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i04_request_cancel_cancels() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    let called = rig
        .call("request_cancel", json!({"request_id": OTHER_ID}), false)
        .await;
    assert_eq!(
        called.envelope()["data"],
        json!({"method": "request.cancel"})
    );
    let cancels = rig.fake().of(Kind::Cancel);
    assert_eq!(cancels.len(), 1);
    assert_eq!(
        cancels.first().and_then(|e| e.detail.as_deref()),
        Some(OTHER_ID)
    );
    assert_eq!(rig.fake().count(Kind::Submit), 0);
    Ok(())
}

/// L66: the agent filter comes only from the tool's own `agent` argument, never from `--agent`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_list_agent_only_from_argument() -> TestResult {
    let rig = Rig::new(RigOpts {
        agent: Some("cfg-agent".to_owned()),
        agent_source: AgentNameSource::Flag,
        agent_given: true,
        ..RigOpts::default()
    })
    .await;
    rig.call("request_list", json!({}), false).await;
    rig.call(
        "request_list",
        json!({"agent": "other", "state": "recent"}),
        false,
    )
    .await;
    let lists = rig.fake().lists.lock().unwrap().clone();
    assert_eq!(
        lists,
        [
            (None, None, None),
            (Some("other".to_owned()), Some(ListState::Recent), None),
        ]
    );
    Ok(())
}

/// RF-2: a `busy` answer passes through unchanged (`retry_after_s` included).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn busy_envelope_passes_through_unchanged() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    let mut busy = Envelope::failed(ErrorCode::Busy, true, "busy");
    if let Some(err) = busy.error.as_mut() {
        let mut d = Map::new();
        d.insert("retry_after_s".to_owned(), json!(7));
        err.details = Some(d);
    }
    rig.fake().set_submit_answer(Some(busy.clone()));
    let called = rig
        .call("jira_issue_get", json!({"key": "A-1"}), false)
        .await;
    assert!(called.is_error());
    assert_eq!(called.envelope(), serde_json::to_value(&busy)?);
    assert_eq!(rig.fake().count(Kind::AwaitStart), 0);
    Ok(())
}

/// PD-16 / L63: the submit frame was written, then the connection dropped before the answer:
/// `pending` with an unknown id (never `launch_timeout`), `isError` and the restart text (PD-121,
/// PD-123).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_submit_lost_after_write_is_pending_unknown_id() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    rig.fake().set_submit_hold(true);
    let started = rig
        .start("jira_issue_get", json!({"key": "A-1"}), false)
        .await;
    until("the Fake recorded the submit", || submits(&rig).len() == 1).await;
    rig.app.drop_connections().await;
    let called = rig.finish(started).await;
    let env = called.envelope();
    assert_eq!(env["status"], "pending");
    assert_eq!(env["request_id"], Value::Null);
    assert_eq!(env["error"]["message"], MSG_CONNECTION_LOST_NO_ID);
    assert_eq!(detail(&env, "reason"), Some(&json!("connection_lost")));
    assert!(called.is_error());
    assert_eq!(
        called.texts().first().map(String::as_str),
        Some(RESTART_TEXT)
    );
    Ok(())
}

/// B-1 / PD-16: a deadline that passes after the writer took the submit frame is
/// `unknown_request_pending`, never `launch_timeout`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_submit_deadline_after_write_is_pending_not_launch_timeout() -> TestResult {
    let rig = Rig::new(RigOpts {
        timeout: Some(Duration::from_secs(1)),
        ..RigOpts::default()
    })
    .await;
    rig.fake().set_submit_hold(true);
    let start = Instant::now();
    let called = rig
        .call("jira_issue_get", json!({"key": "A-1"}), false)
        .await;
    let took = start.elapsed();
    assert_eq!(submits(&rig).len(), 1, "the Fake has the submit");
    let env = called.envelope();
    assert_eq!(env["status"], "pending");
    assert_eq!(env["request_id"], Value::Null);
    assert_eq!(detail(&env, "reason"), Some(&json!("connection_lost")));
    assert!(took < Duration::from_secs(3), "{took:?}");
    // The connection is intact: the next call reuses it.
    rig.call("request_status", json!({"request_id": REQ_ID}), false)
        .await;
    assert_eq!(rig.fake().hellos().len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn instances_list_and_ops_with_instance_connect() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    let instances = rig.call("instances_list", json!({}), false).await;
    assert!(!instances.is_error(), "{:?}", instances.texts());
    assert_eq!(
        instances.envelope()["data"],
        json!({"method": "instances.list"})
    );
    let list = rig.call("ops_list", json!({"instance": "dc"}), false).await;
    assert_eq!(list.envelope()["data"], json!({"method": "ops.list"}));
    let describe = rig
        .call(
            "ops_describe",
            json!({"op_id": "jira.issue.get", "instance": "dc"}),
            false,
        )
        .await;
    assert_eq!(
        describe.envelope()["data"],
        json!({"method": "ops.describe"})
    );
    let detail_of = |kind| {
        rig.fake()
            .of(kind)
            .into_iter()
            .map(|e| e.detail)
            .collect::<Vec<_>>()
    };
    assert_eq!(detail_of(Kind::InstancesList), [None]);
    assert_eq!(detail_of(Kind::OpsList), [Some("dc".to_owned())]);
    assert_eq!(
        detail_of(Kind::OpsDescribe),
        [Some("jira.issue.get|dc".to_owned())]
    );
    assert_eq!(rig.connector().connect_count(), 1);
    Ok(())
}

/// PD-121: an 8 MiB release reaches the client intact through rmcp's stdio codec, as
/// `structuredContent` and as the JSON text block.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_envelope_passes_through_intact() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    let blob = "x\"\u{e9}".repeat(8 * 1024 * 1024 / 4);
    let decision = released(json!({"blob": blob}));
    rig.fake().set_await_script(Some(AwaitScript {
        progress: Vec::new(),
        decision: Some((Duration::ZERO, decision.clone())),
    }));
    let started = rig
        .start("request_await", json!({"request_id": REQ_ID}), false)
        .await;
    let called = rig.finish_within(started, Duration::from_secs(60)).await;
    assert!(!called.is_error());
    let mut want = decision;
    want.request_id = Some(REQ_ID.to_owned());
    let want = serde_json::to_value(want)?;
    assert!(called.envelope() == want, "structuredContent differs");
    let texts = called.texts();
    let last: Value = serde_json::from_str(texts.last().ok_or("no text block")?)?;
    assert!(last == want, "the JSON text block differs");
    Ok(())
}

/// Moved from Task 7: nothing connects at `initialize` or `tools/list`; the first connected tool
/// call connects once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lazy_connect_on_first_connected_tool_call() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    rig.list_tools().await;
    assert_eq!(rig.connector().connect_count(), 0);
    assert_eq!(rig.connector().discover_count(), 0);
    assert!(rig.fake().hellos().is_empty());
    rig.call("request_status", json!({"request_id": REQ_ID}), false)
        .await;
    rig.call("request_status", json!({"request_id": REQ_ID}), false)
        .await;
    assert_eq!(rig.connector().connect_count(), 1);
    assert_eq!(rig.fake().hellos().len(), 1);
    Ok(())
}

/// PD-115: concurrent tool calls share one connection (one hello, one `connection_id`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_tool_calls_share_one_connection() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    let mut started = Vec::new();
    for _ in 0..8 {
        started.push(
            rig.start("request_status", json!({"request_id": REQ_ID}), false)
                .await,
        );
    }
    for call in started {
        let called = rig.finish(call).await;
        assert!(!called.is_error(), "{:?}", called.texts());
    }
    assert_eq!(rig.fake().count(Kind::Status), 8);
    assert_eq!(rig.fake().hellos().len(), 1, "one hello, one connection_id");
    assert_eq!(rig.connector().connect_count(), 1);
    Ok(())
}

/// R1 / PD-115: an error answer, a reply the L131 checks refuse and a deadline that passes
/// mid-await end only their own tool call; the next call uses the same connection (no new
/// hello, no new approval session).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_call_error_keeps_the_connection() -> TestResult {
    let mut fake = RigOpts::default().fake;
    // Every `request.await` outlives the tool call's deadline.
    fake.await_delay = Duration::from_secs(60);
    let rig = Rig::new(RigOpts {
        fake,
        timeout: Some(Duration::from_secs(1)),
        ..RigOpts::default()
    })
    .await;
    rig.call("request_status", json!({"request_id": REQ_ID}), false)
        .await;

    // An error answer.
    let mut invalid = Envelope::failed(ErrorCode::Validation, false, "invalid");
    invalid.op_id = Some("jira.issue.get".to_owned());
    rig.fake().set_submit_answer(Some(invalid));
    let called = rig
        .call("jira_issue_get", json!({"key": "A-1"}), false)
        .await;
    assert_eq!(code(&called.envelope()), Some("validation"));

    // A reply the L131 check refuses (a per-call `protocol_error`).
    let mut no_id = released(Value::Null);
    no_id.status = Status::Pending;
    no_id.data = None;
    rig.fake().set_submit_answer(Some(no_id));
    let called = rig
        .call("jira_issue_get", json!({"key": "A-1"}), false)
        .await;
    assert_eq!(code(&called.envelope()), Some("protocol_error"));
    rig.fake().set_submit_answer(None);

    // A deadline that passes mid-await: the request lives on.
    let called = rig
        .call("request_await", json!({"request_id": REQ_ID}), false)
        .await;
    let env = called.envelope();
    assert_eq!(env["status"], "pending");
    assert_eq!(env["request_id"], REQ_ID);
    assert!(!called.is_error(), "{:?}", called.texts());

    rig.call("request_status", json!({"request_id": REQ_ID}), false)
        .await;
    let ids = connection_ids(&rig);
    assert_eq!(ids.len(), 1, "a per-call error reconnected: {ids:?}");
    assert_eq!(rig.connector().connect_count(), 1);
    assert_eq!(rig.fake().count(Kind::Status), 2);
    Ok(())
}

/// §4.6: `ATLAS_DUCK_MCP_TIMEOUT` counts from the tool call's receipt and covers the launch
/// poll: an app that never comes up answers `launch_timeout` in time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deadline_from_tool_call_receipt_caps_launch_and_hello() -> TestResult {
    let rig = Rig::new(RigOpts {
        timeout: Some(Duration::from_secs(2)),
        present: false,
        ..RigOpts::default()
    })
    .await;
    let start = Instant::now();
    let called = rig
        .call("jira_issue_get", json!({"key": "A-1"}), false)
        .await;
    let took = start.elapsed();
    let env = called.envelope();
    assert_eq!(code(&env), Some("unreachable"));
    assert_eq!(detail(&env, "reason"), Some(&json!("launch_timeout")));
    assert!(called.is_error());
    assert_eq!(
        called.texts().first().map(String::as_str),
        Some(RESTART_TEXT)
    );
    assert!(
        took >= Duration::from_millis(1800),
        "the launch poll did not run: {took:?}"
    );
    assert!(took < Duration::from_secs(3), "{took:?}");
    assert!(rig.connector().discover_count() >= 1);
    assert!(submits(&rig).is_empty());
    Ok(())
}

/// §4.3 / PD-16: a deadline that passes before the submit frame was taken is `launch_timeout`
/// and the app never sees the submit: while the app does not come up, and while every one of
/// the 48 slots of the shared connection is held by an await the app holds past every deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deadline_before_submit_is_launch_timeout_nothing_queued() -> TestResult {
    let no_app = Rig::new(RigOpts {
        timeout: Some(Duration::from_secs(1)),
        present: false,
        ..RigOpts::default()
    })
    .await;
    let called = no_app
        .call("jira_issue_get", json!({"key": "A-1"}), false)
        .await;
    assert_eq!(
        detail(&called.envelope(), "reason"),
        Some(&json!("launch_timeout"))
    );
    assert_eq!(no_app.connector().connect_count(), 0);
    assert_eq!(no_app.fake().count(Kind::Submit), 0);

    let mut fake = RigOpts::default().fake;
    fake.await_delay = Duration::from_secs(60);
    let full = Rig::new(RigOpts {
        fake,
        timeout: Some(Duration::from_secs(1)),
        ..RigOpts::default()
    })
    .await;
    let mut held = Vec::new();
    for n in 0..48 {
        let id = id_n(1000 + n);
        held.push(
            full.start("request_await", json!({"request_id": id}), false)
                .await,
        );
    }
    until("the app holds 48 awaits", || {
        full.fake().count(Kind::AwaitStart) == 48
    })
    .await;
    let called = full
        .call("jira_issue_get", json!({"key": "A-1"}), false)
        .await;
    let env = called.envelope();
    assert_eq!(code(&env), Some("unreachable"));
    assert_eq!(detail(&env, "reason"), Some(&json!("launch_timeout")));
    assert!(called.is_error());
    assert_eq!(full.fake().count(Kind::Submit), 0, "a submit was queued");
    assert!(submits(&full).is_empty());
    drop(held);
    Ok(())
}

/// §4.6: the server never exits because of the app: with the app gone every connected tool call
/// is an error result, and `serve` runs until stdin closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_never_exits_because_of_the_app() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    let ok = rig
        .call("request_status", json!({"request_id": REQ_ID}), false)
        .await;
    assert!(!ok.is_error());
    rig.app.stop_server().await;
    for tool in ["request_status", "request_await", "request_cancel"] {
        let called = rig.call(tool, json!({"request_id": REQ_ID}), false).await;
        assert!(called.is_error(), "{tool}");
        assert_eq!(code(&called.envelope()), Some("unreachable"), "{tool}");
    }
    let called = rig
        .call("jira_issue_get", json!({"key": "A-1"}), false)
        .await;
    assert!(called.is_error());
    assert!(
        rig.serve_result(Duration::from_millis(300)).await.is_none(),
        "serve ended because of the app"
    );
    rig.close_stdin();
    let served = rig.serve_result(WAIT).await.ok_or("still serving")?;
    assert!(served.is_ok(), "{served:?}");
    Ok(())
}

/// §4.6 "never cancel by accident": stdin EOF stops a waiting tool call at once and sends no
/// `request.cancel`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdin_eof_cancels_nothing() -> TestResult {
    let rig = Rig::new(RigOpts::default()).await;
    // The app holds the await until its `timeout_ms` (5 s).
    rig.fake().set_await_script(Some(AwaitScript::default()));
    let _waiting = rig
        .start("request_await", json!({"request_id": REQ_ID}), true)
        .await;
    rig.fake().wait_for(Kind::AwaitStart, 1).await;
    rig.close_stdin();
    let served = rig
        .serve_result(Duration::from_secs(2))
        .await
        .ok_or("serve still waits for the await")?;
    assert!(served.is_ok(), "{served:?}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(rig.fake().count(Kind::Cancel), 0);
    Ok(())
}

/// I-6: stdin closes while a tool call's launch poll sleeps on its blocking thread: `run_on`
/// returns at once, not when the poll ends (20 s).
#[test]
fn run_exit_does_not_wait_for_blocking_launch() {
    use tokio::io::AsyncWriteExt;

    const CALL: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"request_status\",\"arguments\":{\"request_id\":\"req_00000000000000000000000000000001\"}}}\n";
    let mut connector = TestConnector::failing(|| ConnectError::NotRunning);
    connector.present = false;
    let app_file = std::env::current_exe().expect("test binary path");
    connector.discovery.app = AppLocation::Found(app_file);
    let connector = Arc::new(connector);
    let polling = connector.clone();
    let (input, feed) = tokio::io::duplex(1 << 16);
    // Feeds `initialize` and one tool call, closes stdin once the launch poll runs, and says
    // when it closed.
    let feeder = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("feeder runtime");
        rt.block_on(async move {
            let mut feed = feed;
            feed.write_all(INIT).await.expect("write initialize");
            feed.write_all(CALL).await.expect("write tools/call");
            let until = Instant::now() + WAIT;
            while polling.discover_count() == 0 && Instant::now() < until {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let polled = polling.discover_count() > 0;
            // Into the poll's sleep.
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(feed);
            (polled, Instant::now())
        })
    });
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let cfg = McpConfig {
            timeout: Some(Duration::from_secs(30)),
            ..plain_config()
        };
        let code = run_on(cfg, connector, input, tokio::io::sink());
        let _ = tx.send((code, Instant::now()));
    });
    let (code, ended) = rx.recv_timeout(WAIT * 2).expect("run_on returned");
    let (polled, closed) = feeder.join().expect("feeder");
    assert!(polled, "the launch poll never started");
    assert_eq!(code, 0);
    let took = ended.saturating_duration_since(closed);
    assert!(took < Duration::from_secs(2), "{took:?}");
}

/// T7 review M-1 (lead ruling): the hello freezes the agent name at the first attempt to
/// connect, so every connected tool body passes the call's `clientInfo.name`: whichever tool is
/// called first, the hello names the agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_connected_tool_passes_the_client_name() -> TestResult {
    let calls = [
        (ToolSet::Full, "jira_issue_get", json!({"key": "A-1"})),
        (
            ToolSet::Generic,
            "call",
            json!({"op_id": "jira.issue.get", "params": {}}),
        ),
        (ToolSet::Full, "script_run", json!({"source": "return 1"})),
        (
            ToolSet::Full,
            "request_await",
            json!({"request_id": REQ_ID}),
        ),
        (
            ToolSet::Full,
            "request_status",
            json!({"request_id": REQ_ID}),
        ),
        (
            ToolSet::Full,
            "request_cancel",
            json!({"request_id": REQ_ID}),
        ),
        (ToolSet::Full, "request_list", json!({})),
        (ToolSet::Full, "ops_list", json!({"instance": "dc"})),
        (
            ToolSet::Full,
            "ops_describe",
            json!({"op_id": "jira.issue.get", "instance": "dc"}),
        ),
        (ToolSet::Full, "instances_list", json!({})),
    ];
    for (tools, tool, args) in calls {
        let rig = Rig::new(RigOpts {
            tools,
            client_name: "desk".to_owned(),
            ..RigOpts::default()
        })
        .await;
        rig.call(tool, args, false).await;
        let seen = rig.fake().hellos();
        let hello = &seen.first().ok_or(format!("{tool}: no hello"))?.hello;
        assert_eq!(hello.agent_name.as_deref(), Some("desk"), "{tool}");
        assert_eq!(
            hello.agent_name_source,
            AgentNameSource::McpClientInfo,
            "{tool}"
        );
    }
    Ok(())
}
