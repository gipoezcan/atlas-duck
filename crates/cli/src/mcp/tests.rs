//! Rig tests of the MCP server (M9 Tasks 6-10) and the rig's own self-tests. Real clock, short
//! periods; every wait is bounded, so a broken server fails a test instead of hanging it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

type TestResult = Result<(), Box<dyn std::error::Error>>;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use atlas_duck_ipc::build_info::APP_VERSION;
use atlas_duck_ipc::client::{ClientError, ConnectError};
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::proto::{
    AwaitParams, ClientKind, ProgressNotification, SubmitParams, SubmitReply,
};
use atlas_duck_ipc::rpc::{IdParams, method};
use rmcp::ServiceError;
use rmcp::model::{ErrorCode as McpErrorCode, ProtocolVersion, RequestMetaObject};
use serde_json::{Map, Value, json};

use super::config::{McpConfig, ToolSet};
use super::rig::{RIG_BUILD, Rig, RigApp, RigOpts};
use super::run_on;
use super::server::{SendFuture, Shared, ToolBodies, ToolCall};
use super::tools::catalog;
use crate::connected::Connector;
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
        let names: Vec<String> = rig
            .list_tools()
            .await
            .into_iter()
            .map(|t| t.name.into_owned())
            .collect();
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

#[test]
fn run_on_returns_after_stdin_eof() {
    const INIT: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}\n";
    // A closed reader before `initialize`, and one closed right after it.
    for input in [&b""[..], INIT] {
        let (code, took) = run_on_thread(input).expect("run_on returned");
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(input));
        assert!(took < Duration::from_secs(2), "{took:?}");
    }
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
