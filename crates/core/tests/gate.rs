//! L46: the gate handler for states without a store; the shared `hello` check.

use std::sync::{Arc, Mutex};

use atlas_duck_audit::{LockedReason, RecoveryOffer};
use atlas_duck_core::{GateHandler, GateState, MSG_FIRST_RUN, UiEvent, UiSink, hello_check};
use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::proto::{
    AgentNameSource, AwaitParams, ClientKind, ConnectionMeta, Hello, ListState, PeerInfo,
    ProgressNotification, ProgressSink, RequestHandler, SubmitParams, exit_code,
};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct RecordingUi(Mutex<Vec<UiEvent>>);

impl UiSink for RecordingUi {
    fn emit(&self, e: UiEvent) {
        if let Ok(mut v) = self.0.lock() {
            v.push(e);
        }
    }
}

impl RecordingUi {
    fn events(&self) -> Vec<UiEvent> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

struct NoProgress;
impl ProgressSink for NoProgress {
    fn progress(&self, _n: ProgressNotification) {}
}

fn states() -> Vec<GateState> {
    vec![
        GateState::FirstRun,
        GateState::Locked(LockedReason::KeychainUnavailable),
        GateState::Locked(LockedReason::KeychainLost {
            offer: RecoveryOffer::RecoverThisLog,
        }),
        GateState::Locked(LockedReason::KeyringNotLocal),
        GateState::StoreNewer,
        GateState::NotConfigured("data_dir_missing"),
        GateState::NotConfigured("data_dir_not_local"),
        GateState::NotConfigured("config_unreadable"),
        GateState::ShuttingDown,
    ]
}

fn conn() -> ConnectionMeta {
    ConnectionMeta {
        connection_id: "c1".to_owned(),
        peer: PeerInfo::default(),
    }
}

fn hello(build_id: &str) -> Hello {
    Hello {
        build_id: build_id.to_owned(),
        client_kind: ClientKind::Cli,
        agent_name: Some("AGENTCANARY".to_owned()),
        agent_name_source: AgentNameSource::Flag,
        cwd_basename: "work".to_owned(),
    }
}

fn submit_params() -> SubmitParams {
    SubmitParams {
        op_id: "jira.issue.get".to_owned(),
        params: json!({"key": "ABC-1"}),
        instance: None,
        reason: None,
    }
}

fn reason(env: &Envelope) -> Option<&str> {
    env.error
        .as_ref()?
        .details
        .as_ref()?
        .get("reason")?
        .as_str()
}

#[tokio::test]
async fn gate_envelopes_per_state() -> TestResult {
    // `Locked(passphrase)` does not exist in v1 (L39); the master-plan exit-criterion text names
    // it, but the enum has no such variant and this table has no such row.
    // (state, error.code, details.reason, exit code)
    let table = [
        (
            GateState::FirstRun,
            ErrorCode::NotConfigured,
            "first_run",
            9,
        ),
        (
            GateState::Locked(LockedReason::KeychainUnavailable),
            ErrorCode::Locked,
            "keychain_unavailable",
            9,
        ),
        (
            GateState::Locked(LockedReason::KeychainLost {
                offer: RecoveryOffer::FinishRestore,
            }),
            ErrorCode::Locked,
            "keychain_lost",
            9,
        ),
        (
            GateState::Locked(LockedReason::KeyringNotLocal),
            ErrorCode::Locked,
            "keyring_not_local",
            9,
        ),
        (
            GateState::StoreNewer,
            ErrorCode::Unreachable,
            "store_newer",
            5,
        ),
        (
            GateState::NotConfigured("data_dir_missing"),
            ErrorCode::NotConfigured,
            "data_dir_missing",
            9,
        ),
        (
            GateState::NotConfigured("data_dir_not_local"),
            ErrorCode::NotConfigured,
            "data_dir_not_local",
            9,
        ),
        (
            GateState::NotConfigured("config_unreadable"),
            ErrorCode::NotConfigured,
            "config_unreadable",
            9,
        ),
        (
            GateState::ShuttingDown,
            ErrorCode::Unreachable,
            "app_shutting_down",
            5,
        ),
    ];
    for (state, code, why, exit) in table {
        let h = GateHandler::new(state, Arc::new(RecordingUi::default()));
        let env = h.submit(&conn(), submit_params()).await;
        assert_eq!(env.status, Status::Failed, "{why}");
        let err = env.error.as_ref().ok_or("no error object")?;
        assert_eq!(err.code, code, "{why}");
        assert!(err.retryable, "{why}");
        assert_eq!(reason(&env), Some(why));
        assert!(env.request_id.is_none(), "{why}");
        assert_eq!(exit_code(&env), exit, "{why}");
    }
    Ok(())
}

#[test]
fn gate_first_run_message_verbatim() -> TestResult {
    assert_eq!(
        MSG_FIRST_RUN,
        "atlas-duck is not set up yet: finish the setup window on the desktop"
    );
    let env = GateState::FirstRun.envelope();
    assert_eq!(env.error.ok_or("no error")?.message, MSG_FIRST_RUN);
    Ok(())
}

#[tokio::test]
async fn gate_method_split() -> TestResult {
    for state in states() {
        let h = GateHandler::new(state, Arc::new(RecordingUi::default()));
        let want = state.envelope();

        let reply = h.hello(&conn(), hello(BUILD_ID)).await;
        assert_eq!(reply.map_err(|_| "hello refused")?.build_id, BUILD_ID);

        let doctor = h.doctor().await;
        assert_eq!(doctor.status, Status::Succeeded);
        assert!(
            doctor
                .data
                .as_ref()
                .and_then(|d| d.get("gate"))
                .and_then(Value::as_str)
                .is_some()
        );

        let list = h.ops_list(None).await;
        assert_eq!(list.status, Status::Succeeded);
        assert!(list.request_id.is_none());
        let ops = list
            .data
            .as_ref()
            .and_then(|d| d.get("ops"))
            .and_then(Value::as_array)
            .ok_or("no ops array")?;
        assert_eq!(ops.len(), 46);

        let desc = h.ops_describe("jira.issue.get", None).await;
        assert_eq!(desc.status, Status::Succeeded);
        assert_eq!(
            desc.data.as_ref().and_then(|d| d.get("op_id")),
            Some(&json!("jira.issue.get"))
        );
        assert_eq!(
            desc.data.as_ref().and_then(|d| d.get("limits_source")),
            Some(&json!("default"))
        );
        let unknown = h.ops_describe("no.such.op", None).await;
        assert_eq!(unknown.status, Status::Failed);
        assert_eq!(unknown.error.ok_or("no error")?.code, ErrorCode::Usage);

        assert_eq!(h.ops_list(Some("x")).await, want);
        assert_eq!(h.ops_describe("jira.issue.get", Some("x")).await, want);
        assert_eq!(h.instances_list().await, want);
        assert_eq!(h.status("req_x").await, want);
        assert_eq!(h.requests_list(None, None, None).await, want);
    }
    Ok(())
}

#[tokio::test]
async fn gate_doctor_labels_each_state() -> TestResult {
    // The label set is part of the PD-11 contract.
    let want = [
        "first_run",
        "locked",
        "locked",
        "locked",
        "store_newer",
        "not_configured",
        "not_configured",
        "not_configured",
        "shutting_down",
    ];
    for (state, label) in states().into_iter().zip(want) {
        let h = GateHandler::new(state, Arc::new(RecordingUi::default()));
        let env = h.doctor().await;
        assert_eq!(
            env.data.as_ref().and_then(|d| d.get("gate")),
            Some(&json!(label))
        );
    }
    Ok(())
}

#[tokio::test]
async fn gate_refused_counter_only_four_methods() -> TestResult {
    for state in states() {
        let ui = Arc::new(RecordingUi::default());
        let h = GateHandler::new(state, ui.clone());
        let c = conn();
        let _ = h.hello(&c, hello(BUILD_ID)).await;
        let _ = h.ops_list(None).await;
        let _ = h.ops_describe("jira.issue.get", None).await;
        let _ = h.instances_list().await;
        let _ = h.submit(&c, submit_params()).await;
        let _ = h.submit_script(&c, submit_params()).await;
        let _ = h
            .await_request(
                &c,
                AwaitParams {
                    request_id: "req_x".to_owned(),
                    timeout_ms: None,
                },
                &NoProgress,
            )
            .await;
        let _ = h.status("req_x").await;
        let _ = h.cancel("req_x").await;
        let _ = h.requests_list(None, Some(ListState::Pending), None).await;
        let _ = h.doctor().await;
        assert_eq!(h.refused(), 4);
        assert_eq!(ui.events(), vec![UiEvent::CredentialContextChanged; 4]);
    }
    Ok(())
}

#[tokio::test]
async fn gate_hello_build_mismatch() -> TestResult {
    let h = GateHandler::new(GateState::FirstRun, Arc::new(RecordingUi::default()));
    let env = h
        .hello(&conn(), hello("0.0.0+000000000000"))
        .await
        .err()
        .ok_or("mismatch was accepted")?;
    assert_eq!(env.status, Status::Failed);
    let err = env.error.as_ref().ok_or("no error")?;
    assert_eq!(err.code, ErrorCode::ProtocolMismatch);
    assert!(err.retryable);
    let d = err.details.as_ref().ok_or("no details")?;
    assert_eq!(d.get("client_build"), Some(&json!("0.0.0+000000000000")));
    assert_eq!(d.get("server_build"), Some(&json!(BUILD_ID)));
    // the agent string is never echoed
    assert!(!env.to_json_line().contains("AGENTCANARY"));
    let ok = hello_check(&hello(BUILD_ID)).map_err(|_| "refused")?;
    assert_eq!(ok.build_id, BUILD_ID);
    Ok(())
}
