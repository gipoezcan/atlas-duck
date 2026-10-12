//! The connected flow against the real `IpcServer` serving a fake handler (see `test_support`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_duck_ipc::client::{ClientError, ConnectError};
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::proto::{AgentNameSource, ListState};
use serde_json::{Value, json};

use super::*;
use crate::argv::{MatchParams as CliMatch, OutputMode};
use crate::exit::exit_for;
use crate::test_support::{Fake, Kind, Mode, REQ_ID, Running, TestConnector, serve};

fn opts() -> GlobalOpts {
    GlobalOpts {
        agent: None,
        agent_source: AgentNameSource::None,
        reason: None,
        timeout: None,
        instance: None,
        output: OutputMode::Json,
        help: false,
    }
}

fn within(ms: u64) -> Deadline {
    Deadline::new(Instant::now(), Some(Duration::from_millis(ms)))
}

fn op() -> Command {
    Command::Op {
        op_id: "jira.issue.get".to_owned(),
        params: json!({"key": "ABC-1"}),
    }
}

fn status_of(env: &Envelope) -> Status {
    env.status
}

fn code(env: &Envelope) -> Option<ErrorCode> {
    env.error.as_ref().map(|e| e.code)
}

fn reason_of(env: &Envelope) -> Option<String> {
    env.error
        .as_ref()
        .and_then(|e| e.details.as_ref())
        .and_then(|d| d.get("reason"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn data_method(env: &Envelope) -> Option<String> {
    env.data
        .as_ref()
        .and_then(|d| d.get("method"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

async fn setup(fake: &Arc<Fake>) -> (Running, Arc<TestConnector>) {
    let running = serve(fake).await;
    let connector = Arc::new(TestConnector::new(
        running.data.clone(),
        Mode::Server(running.location.clone()),
    ));
    (running, connector)
}

async fn run(
    cmd: &Command,
    opts: &GlobalOpts,
    deadline: &Deadline,
    connector: &TestConnector,
) -> (Envelope, i32) {
    let env = execute(cmd, opts, deadline, connector).await;
    let exit = exit_for(cmd, &env);
    (env, exit)
}

#[tokio::test]
async fn submit_wait_returns_await_answer() {
    let fake = Arc::new(Fake::new());
    let (running, connector) = setup(&fake).await;
    let (env, exit) = run(&op(), &opts(), &within(5_000), &connector).await;
    assert_eq!(status_of(&env), Status::Succeeded);
    assert_eq!(data_method(&env).as_deref(), Some("request.await"));
    assert_eq!(exit, 0);
    assert_eq!(fake.count(Kind::Submit), 1);
    assert_eq!(fake.count(Kind::AwaitDone), 1);
    // The await asks for the request the submit reply named, within the deadline.
    let awaits = fake.awaits.lock().map(|g| g.clone()).unwrap_or_default();
    assert_eq!(awaits.len(), 1);
    assert_eq!(awaits[0].request_id, REQ_ID);
    assert!(awaits[0].timeout_ms.is_some_and(|ms| ms <= 5_000 && ms > 0));
    running.stop().await;
}

#[tokio::test]
async fn submit_params_carry_instance_reason_and_op() {
    let fake = Arc::new(Fake::new());
    let (running, connector) = setup(&fake).await;
    let mut o = opts();
    o.instance = Some("prod".to_owned());
    o.reason = Some("because".to_owned());
    let _ = run(&op(), &o, &within(5_000), &connector).await;
    let submits = fake.submits.lock().map(|g| g.clone()).unwrap_or_default();
    assert_eq!(submits.len(), 1);
    assert_eq!(submits[0].op_id, "jira.issue.get");
    assert_eq!(submits[0].params, json!({"key": "ABC-1"}));
    assert_eq!(submits[0].instance.as_deref(), Some("prod"));
    assert_eq!(submits[0].reason.as_deref(), Some("because"));
    running.stop().await;
}

#[tokio::test]
async fn script_run_uses_script_submit() {
    let fake = Arc::new(Fake::new());
    let (running, connector) = setup(&fake).await;
    let cmd = Command::ScriptRun {
        source: "1+1".to_owned(),
        args: json!({"p": 1}),
        limits: Some(json!({"timeout_s": 5})),
        dry_run: Some(DryRun::Sparse),
    };
    let (env, exit) = run(&cmd, &opts(), &within(5_000), &connector).await;
    assert_eq!(fake.count(Kind::ScriptSubmit), 1);
    assert_eq!(fake.count(Kind::Submit), 0);
    let submits = fake.submits.lock().map(|g| g.clone()).unwrap_or_default();
    assert_eq!(submits[0].op_id, "script.run");
    assert_eq!(
        submits[0].params,
        json!({"source": "1+1", "args": {"p": 1}, "limits": {"timeout_s": 5}, "dry_run": "sparse"})
    );
    assert_eq!((status_of(&env), exit), (Status::Succeeded, 0));
    // No limits and no dry run: only `source` and `args` are sent.
    let bare = Command::ScriptRun {
        source: "x".to_owned(),
        args: json!({}),
        limits: None,
        dry_run: None,
    };
    let _ = run(&bare, &opts(), &within(5_000), &connector).await;
    let submits = fake.submits.lock().map(|g| g.clone()).unwrap_or_default();
    assert_eq!(submits[1].params, json!({"source": "x", "args": {}}));
    running.stop().await;
}

#[tokio::test]
async fn notice_only_from_reply() {
    let fake = Arc::new(Fake::new());
    let (running, connector) = setup(&fake).await;
    let _ = run(&op(), &opts(), &within(5_000), &connector).await;
    let notices = connector.notice_lines();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].0, REQ_ID);
    assert_eq!(notices[0].1.as_deref(), Some("ab".repeat(32).as_str()));
    // Before any await started.
    let await_at = fake.of(Kind::AwaitStart).first().map(|e| e.at);
    assert!(await_at.is_some_and(|at| notices[0].2 <= at));
    running.stop().await;

    // A reply that is not pending (here: `validation`) gives no notice and no await.
    let mut invalid = Fake::new();
    invalid.submit_status = Status::Failed;
    let invalid = Arc::new(invalid);
    let (running, connector) = setup(&invalid).await;
    let (env, exit) = run(&op(), &opts(), &within(5_000), &connector).await;
    assert_eq!(code(&env), Some(ErrorCode::Validation));
    assert_eq!(exit, 2);
    assert!(connector.notice_lines().is_empty());
    assert_eq!(invalid.count(Kind::AwaitStart), 0);
    running.stop().await;
}

#[tokio::test]
async fn dropped_connection_before_the_reply_gives_no_notice() {
    let mut slow = Fake::new();
    slow.submit_delay = Duration::from_secs(30);
    let fake = Arc::new(slow);
    let (running, connector) = setup(&fake).await;
    let shutdown = running.shutdown.clone();
    let seen = fake.clone();
    tokio::spawn(async move {
        seen.wait_for(Kind::Submit, 1).await;
        shutdown.0.cancel();
    });
    let (env, exit) = run(&op(), &opts(), &within(8_000), &connector).await;
    assert!(connector.notice_lines().is_empty());
    assert_eq!(status_of(&env), Status::Pending);
    assert_eq!(env.request_id, None);
    assert_eq!(exit, 4);
    running.stop().await;
}

#[tokio::test]
async fn timeout_zero_returns_pending_after_launch() {
    let fake = Arc::new(Fake::new());
    let (running, connector) = setup(&fake).await;
    let mut o = opts();
    o.timeout = Some(0);
    let deadline = Deadline::from_timeout(Instant::now(), Some(0));
    let (env, exit) = run(&op(), &o, &deadline, &connector).await;
    assert_eq!(status_of(&env), Status::Pending);
    assert_eq!(env.request_id.as_deref(), Some(REQ_ID));
    assert_eq!(exit, 4);
    assert_eq!(connector.notice_lines().len(), 1);
    assert_eq!(fake.count(Kind::AwaitStart), 0);
    running.stop().await;
}

#[tokio::test]
async fn await_command_sends_remaining_or_zero() {
    let fake = Arc::new(Fake::new());
    let (running, connector) = setup(&fake).await;
    let cmd = Command::Await {
        id: REQ_ID.to_owned(),
    };
    let (env, exit) = run(&cmd, &opts(), &within(5_000), &connector).await;
    assert_eq!((status_of(&env), exit), (Status::Succeeded, 0));
    let mut o = opts();
    o.timeout = Some(0);
    let _ = run(
        &cmd,
        &o,
        &Deadline::from_timeout(Instant::now(), Some(0)),
        &connector,
    )
    .await;
    let awaits = fake.awaits.lock().map(|g| g.clone()).unwrap_or_default();
    assert!(awaits[0].timeout_ms.is_some_and(|ms| ms > 0 && ms <= 5_000));
    assert_eq!(awaits[1].timeout_ms, Some(0));
    // `await` never prints a submission notice.
    assert!(connector.notice_lines().is_empty());
    running.stop().await;
}

#[tokio::test]
async fn pending_at_the_deadline_prints_the_submit_reply_exit_4() {
    let mut slow = Fake::new();
    slow.await_delay = Duration::from_secs(30);
    let fake = Arc::new(slow);
    let (running, connector) = setup(&fake).await;
    let (env, exit) = run(&op(), &opts(), &within(300), &connector).await;
    assert_eq!(status_of(&env), Status::Pending);
    assert_eq!(env.request_id.as_deref(), Some(REQ_ID));
    assert_eq!(env.op_id.as_deref(), Some("jira.issue.get"));
    assert!(env.error.is_none());
    assert_eq!(exit, 4);
    assert_eq!(fake.count(Kind::Cancel), 0);
    running.stop().await;
}

#[tokio::test]
async fn connection_lost_after_submit_exit4() {
    let mut slow = Fake::new();
    slow.await_delay = Duration::from_secs(30);
    let fake = Arc::new(slow);
    let (running, connector) = setup(&fake).await;
    let shutdown = running.shutdown.clone();
    let seen = fake.clone();
    tokio::spawn(async move {
        seen.wait_for(Kind::AwaitStart, 1).await;
        shutdown.0.cancel();
    });
    let (env, exit) = run(&op(), &opts(), &within(8_000), &connector).await;
    assert_eq!(status_of(&env), Status::Pending);
    assert_eq!(env.request_id.as_deref(), Some(REQ_ID));
    assert_eq!(code(&env), Some(ErrorCode::Unreachable));
    assert_eq!(reason_of(&env).as_deref(), Some("connection_lost"));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert_eq!(exit, 4);
    // The notice came from the submit reply, before the loss.
    assert_eq!(connector.notice_lines().len(), 1);
    running.stop().await;
}

#[tokio::test]
async fn interrupt_before_submit_launch_timeout() {
    let fake = Arc::new(Fake::new());
    let running = serve(&fake).await;
    let connector = TestConnector::new(running.data.clone(), Mode::Hang);
    connector.interrupt.notify_one();
    let (env, exit) = run(&op(), &opts(), &within(5_000), &connector).await;
    assert_eq!(status_of(&env), Status::Failed);
    assert_eq!(code(&env), Some(ErrorCode::Unreachable));
    assert_eq!(reason_of(&env).as_deref(), Some("launch_timeout"));
    assert_eq!(exit, 5);
    assert_eq!(fake.count(Kind::Submit), 0);
    assert_eq!(fake.count(Kind::Cancel), 0);
    running.stop().await;
}

#[tokio::test]
async fn interrupt_after_the_frame_was_written_is_pending_without_an_id() {
    let mut slow = Fake::new();
    slow.submit_delay = Duration::from_secs(30);
    let fake = Arc::new(slow);
    let (running, connector) = setup(&fake).await;
    let interrupt = connector.interrupt.clone();
    let seen = fake.clone();
    tokio::spawn(async move {
        seen.wait_for(Kind::Submit, 1).await;
        interrupt.notify_one();
    });
    let (env, exit) = run(&op(), &opts(), &within(20_000), &connector).await;
    assert_eq!(status_of(&env), Status::Pending);
    assert_eq!(env.request_id, None);
    assert_eq!(code(&env), Some(ErrorCode::Unreachable));
    assert_eq!(reason_of(&env).as_deref(), Some("connection_lost"));
    assert_eq!(
        env.error.as_ref().map(|e| e.message.as_str()),
        Some(MSG_CONNECTION_LOST_NO_ID)
    );
    assert_eq!(exit, 4);
    assert_eq!(fake.count(Kind::Cancel), 0);
    running.stop().await;
}

#[tokio::test]
async fn interrupt_after_reply_pending_exit4() {
    let mut slow = Fake::new();
    slow.await_delay = Duration::from_secs(30);
    let fake = Arc::new(slow);
    let (running, connector) = setup(&fake).await;
    let interrupt = connector.interrupt.clone();
    let seen = fake.clone();
    tokio::spawn(async move {
        seen.wait_for(Kind::AwaitStart, 1).await;
        interrupt.notify_one();
    });
    let (env, exit) = run(&op(), &opts(), &within(20_000), &connector).await;
    assert_eq!(status_of(&env), Status::Pending);
    assert_eq!(env.request_id.as_deref(), Some(REQ_ID));
    assert_eq!(env.op_id.as_deref(), Some("jira.issue.get"));
    assert!(env.error.is_none());
    assert_eq!(exit, 4);
    // The request survives: it is never cancelled.
    assert_eq!(fake.count(Kind::Cancel), 0);
    assert_eq!(connector.notice_lines().len(), 1);
    running.stop().await;
}

#[tokio::test]
async fn interrupt_during_await_command_prints_that_id() {
    let mut slow = Fake::new();
    slow.await_delay = Duration::from_secs(30);
    let fake = Arc::new(slow);
    let (running, connector) = setup(&fake).await;
    let interrupt = connector.interrupt.clone();
    let seen = fake.clone();
    tokio::spawn(async move {
        seen.wait_for(Kind::AwaitStart, 1).await;
        interrupt.notify_one();
    });
    let cmd = Command::Await {
        id: "req_x".to_owned(),
    };
    let (env, exit) = run(&cmd, &opts(), &within(20_000), &connector).await;
    assert_eq!(status_of(&env), Status::Pending);
    assert_eq!(env.request_id.as_deref(), Some("req_x"));
    assert_eq!(exit, 4);
    assert_eq!(fake.count(Kind::Cancel), 0);
    running.stop().await;
}

#[tokio::test]
async fn interrupt_during_the_launch_poll_is_launch_timeout() {
    let mut connector = TestConnector::failing(|| ConnectError::ServerIdentity);
    connector.present = false;
    connector.discovery.app = crate::discover::AppLocation::Found(std::path::PathBuf::from("app"));
    let interrupt = connector.interrupt.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        interrupt.notify_one();
    });
    let started = Instant::now();
    // The poll would run for the whole 1.5 s deadline; the interrupt ends the wait at once.
    let (env, exit) = run(&op(), &opts(), &within(1_500), &connector).await;
    assert!(started.elapsed() < Duration::from_millis(1_200));
    assert_eq!(reason_of(&env).as_deref(), Some("launch_timeout"));
    assert_eq!(exit, 5);
    assert_eq!(connector.connect_count(), 0);
}

#[tokio::test]
async fn short_commands_ignore_the_interrupt_source() {
    let fake = Arc::new(Fake::new());
    let (running, connector) = setup(&fake).await;
    connector.interrupt.notify_one();
    let cmd = Command::Status {
        id: REQ_ID.to_owned(),
    };
    let (env, exit) = run(&cmd, &opts(), &within(5_000), &connector).await;
    assert_eq!(data_method(&env).as_deref(), Some("request.status"));
    assert_eq!(exit, 0);
    running.stop().await;
}

#[tokio::test]
async fn status_cancel_requests_instances_methods() {
    let fake = Arc::new(Fake::new());
    let (running, connector) = setup(&fake).await;
    let d = within(5_000);
    let cases: Vec<(Command, &str)> = vec![
        (
            Command::Status {
                id: "req_s".to_owned(),
            },
            "request.status",
        ),
        (
            Command::Cancel {
                id: "req_c".to_owned(),
            },
            "request.cancel",
        ),
        (
            Command::RequestsList {
                agent: Some("bot".to_owned()),
                state: Some("recent".to_owned()),
                match_params: Some(CliMatch {
                    op_id: "jira.issue.get".to_owned(),
                    params: json!({"key": "A-1"}),
                    instance: Some("prod".to_owned()),
                }),
            },
            "requests.list",
        ),
        (Command::Instances, "instances.list"),
        (
            Command::OpsList {
                instance: Some("prod".to_owned()),
            },
            "ops.list",
        ),
        (
            Command::OpsDescribe {
                op_id: "jira.issue.get".to_owned(),
                instance: Some("prod".to_owned()),
            },
            "ops.describe",
        ),
    ];
    for (cmd, expected) in cases {
        let (env, exit) = run(&cmd, &opts(), &d, &connector).await;
        assert_eq!(data_method(&env).as_deref(), Some(expected), "{cmd:?}");
        assert_eq!(exit, 0, "{cmd:?}");
    }
    let status = fake.of(Kind::Status);
    assert_eq!(status[0].detail.as_deref(), Some("req_s"));
    assert_eq!(fake.of(Kind::Cancel)[0].detail.as_deref(), Some("req_c"));
    assert_eq!(fake.of(Kind::OpsList)[0].detail.as_deref(), Some("prod"));
    assert_eq!(
        fake.of(Kind::OpsDescribe)[0].detail.as_deref(),
        Some("jira.issue.get|prod")
    );
    let lists = fake.lists.lock().map(|g| g.clone()).unwrap_or_default();
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].0.as_deref(), Some("bot"));
    assert_eq!(lists[0].1, Some(ListState::Recent));
    let m = lists[0].2.clone();
    assert_eq!(m.as_ref().map(|m| m.op_id.as_str()), Some("jira.issue.get"));
    assert_eq!(m.and_then(|m| m.instance).as_deref(), Some("prod"));
    // None of the short commands submitted, awaited or notified.
    assert_eq!(fake.count(Kind::Submit) + fake.count(Kind::AwaitStart), 0);
    assert!(connector.notice_lines().is_empty());
    running.stop().await;
}

// ---------- connect failures ----------

async fn failing(fail: fn() -> ConnectError) -> (Envelope, i32, TestConnector) {
    let connector = TestConnector::failing(fail);
    let (env, exit) = run(&op(), &opts(), &within(5_000), &connector).await;
    (env, exit, connector)
}

#[tokio::test]
async fn not_running_after_one_more_attempt() {
    let (env, exit, connector) = failing(|| ConnectError::NotRunning).await;
    assert_eq!(connector.connect_count(), 2);
    assert_eq!(code(&env), Some(ErrorCode::Unreachable));
    assert_eq!(reason_of(&env).as_deref(), Some("not_running"));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(exit, 5);
}

#[tokio::test]
async fn server_identity_retryable_false() {
    let (env, exit, connector) = failing(|| ConnectError::ServerIdentity).await;
    assert_eq!(connector.connect_count(), 1);
    assert_eq!(code(&env), Some(ErrorCode::ServerIdentity));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert_eq!(
        env.error.as_ref().map(|e| e.message.as_str()),
        Some("the atlas-duck endpoint is not owned by this user")
    );
    assert_eq!(exit, 5);
}

#[tokio::test]
async fn busy_deadline_protocol_and_hello_mapping() {
    let (env, exit, _) = failing(|| ConnectError::PipeBusy).await;
    assert_eq!((code(&env), exit), (Some(ErrorCode::Busy), 11));
    let detail = env.error.and_then(|e| e.details);
    assert_eq!(
        detail.and_then(|d| d.get("retry_after_s").cloned()),
        Some(json!(5))
    );

    let (env, exit, _) = failing(|| ConnectError::Busy { retry_after_s: 30 }).await;
    assert_eq!((code(&env), exit), (Some(ErrorCode::Busy), 11));

    let (env, exit, _) = failing(|| ConnectError::DeadlineExceeded).await;
    assert_eq!(reason_of(&env).as_deref(), Some("launch_timeout"));
    assert_eq!(exit, 5);

    let (env, exit, _) = failing(|| ConnectError::Protocol("x".to_owned())).await;
    assert_eq!((code(&env), exit), (Some(ErrorCode::ProtocolError), 1));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));

    let (env, exit, _) =
        failing(|| ConnectError::Hello(Envelope::failed(ErrorCode::Locked, true, "hello refused")))
            .await;
    assert_eq!((code(&env), exit), (Some(ErrorCode::Locked), 9));
}

#[tokio::test]
async fn an_empty_host_is_paths_unreadable() {
    let mut connector = TestConnector::failing(|| ConnectError::ServerIdentity);
    connector.discovery.host = String::new();
    let (env, exit) = run(&op(), &opts(), &within(5_000), &connector).await;
    assert_eq!(code(&env), Some(ErrorCode::NotConfigured));
    assert_eq!(reason_of(&env).as_deref(), Some("paths_unreadable"));
    assert_eq!(exit, 9);
    assert_eq!(connector.connect_count(), 0);
}

#[tokio::test]
async fn a_refused_data_dir_never_connects() {
    let mut connector = TestConnector::failing(|| ConnectError::ServerIdentity);
    connector.discovery.data = crate::discover::DataState::Refused(Box::new(
        crate::discover::refusal(atlas_duck_ipc::paths::REASON_DATA_DIR_MISSING),
    ));
    let (env, exit) = run(&op(), &opts(), &within(5_000), &connector).await;
    assert_eq!(reason_of(&env).as_deref(), Some("data_dir_missing"));
    assert_eq!(exit, 9);
    assert_eq!(connector.connect_count(), 0);
}

#[test]
fn build_mismatch_messages_verbatim() {
    let upgraded = build_mismatch(true, "1.3.0+abc", "1.2.0+def");
    assert_eq!(code(&upgraded), Some(ErrorCode::Unreachable));
    assert_eq!(reason_of(&upgraded).as_deref(), Some("app_upgraded"));
    assert_eq!(
        upgraded.error.as_ref().map(|e| e.message.as_str()),
        Some("atlas-duck was upgraded; restart the app")
    );
    assert_eq!(upgraded.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(atlas_duck_ipc::proto::exit_code(&upgraded), 5);

    let other = build_mismatch(false, "1.2.0+abc", "1.3.0+def");
    assert_eq!(code(&other), Some(ErrorCode::ProtocolMismatch));
    assert_eq!(
        other.error.as_ref().map(|e| e.message.as_str()),
        Some(
            "atlas-duck app (v1.3.0) differs from CLI (v1.2.0): quit and relaunch the app, or reinstall"
        )
    );
    let details = other.error.as_ref().and_then(|e| e.details.clone());
    assert_eq!(
        details.as_ref().and_then(|d| d.get("client_build")),
        Some(&json!("1.2.0+abc"))
    );
    assert_eq!(
        details.as_ref().and_then(|d| d.get("server_build")),
        Some(&json!("1.3.0+def"))
    );
    assert_eq!(other.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(atlas_duck_ipc::proto::exit_code(&other), 5);

    // A refusal that named no server build never prints an empty version.
    let unknown = build_mismatch(false, "1.2.0+abc", "unknown");
    let message = unknown.error.map(|e| e.message).unwrap_or_default();
    assert_eq!(
        message,
        "atlas-duck app (unknown version) differs from CLI (v1.2.0): quit and relaunch the app, or reinstall"
    );
    let empty = build_mismatch(false, "", "");
    assert!(
        !empty
            .error
            .map(|e| e.message)
            .unwrap_or_default()
            .contains("(v)")
    );
}

#[test]
fn failures_of_status_never_echo_the_request_id() {
    let status = Command::Status {
        id: REQ_ID.to_owned(),
    };
    for e in [
        short_error(ClientError::ConnectionLost),
        short_error(ClientError::Protocol("x".to_owned())),
        short_error(ClientError::DeadlineExceeded),
        short_error(ClientError::Io(std::io::ErrorKind::Other.into())),
    ] {
        assert_eq!(e.request_id, None);
        assert_ne!(exit_for(&status, &e), 0, "{e:?}");
    }
    assert_eq!(
        exit_for(&status, &short_error(ClientError::ConnectionLost)),
        5
    );
    assert_eq!(
        exit_for(&status, &short_error(ClientError::Protocol(String::new()))),
        1
    );
}

#[test]
fn oversize_request_is_a_usage_failure() {
    let env = short_error(ClientError::Io(std::io::ErrorKind::InvalidInput.into()));
    assert_eq!(code(&env), Some(ErrorCode::Usage));
    assert_eq!(atlas_duck_ipc::proto::exit_code(&env), 2);
}

#[test]
fn rpc_error_without_an_envelope_is_protocol_error() {
    use atlas_duck_ipc::rpc::RpcError;
    let bare = RpcError {
        code: -32602,
        message: "x".to_owned(),
        data: None,
    };
    let env = short_error(ClientError::Rpc(bare));
    assert_eq!(code(&env), Some(ErrorCode::ProtocolError));
    let with = RpcError {
        code: -32602,
        message: "x".to_owned(),
        data: Some(Envelope::failed(
            ErrorCode::UnknownRequest,
            false,
            "no such",
        )),
    };
    assert_eq!(
        code(&short_error(ClientError::Rpc(with))),
        Some(ErrorCode::UnknownRequest)
    );
}
