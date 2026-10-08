//! Serving without a store: `GateState`, `gate_handler` and the shared `hello` check (§2.5
//! "Requests before setup completes", §3.3, §4.3, §8.7, §8.13, L46).
//!
//! `Core::start` needs an open `audit::Store`; `audit::open` can return first run, locked or
//! store-newer, and the app must still answer IPC then. The gate answers `hello`, `doctor` and
//! the local `ops.list`/`ops.describe`; every other method gets the state's envelope. Nothing is
//! queued or logged, and the agent string is never read.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use atlas_duck_audit::LockedReason;
use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::proto::{
    AwaitParams, ConnectionMeta, Hello, HelloReply, ListState, MatchParams, ProgressSink,
    RequestHandler, SubmitParams,
};
use atlas_duck_ipc::sandbox::ScriptLimits;
use atlas_duck_registry::{DescribeEnv, LimitsSource, describe};
use serde::Serialize;
use serde_json::{Map, Value, json};

/// §2.5 (verbatim): the fixed message of the first-run refusal.
pub const MSG_FIRST_RUN: &str =
    "atlas-duck is not set up yet: finish the setup window on the desktop";

/// Which attention a queue change raised (C.7, one-to-one with the C.10 events).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AttentionKind {
    New,
    Stale,
    Failed,
    OutcomeUnknown,
}

/// What the core tells the UI. Ids and counts only; never an agent string, a param or a
/// fetched value (§5.6, §10.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum UiEvent {
    QueueChanged { request_ids: Vec<String> },
    Attention { kind: AttentionKind, count: u32 },
    StatusBanner { line_ids: Vec<String> },
    NeedsAttentionChanged { count: u32 },
    RunningScriptsChanged,
    CredentialContextChanged,
}

/// The sink the app implements over Tauri events (C.10).
pub trait UiSink: Send + Sync {
    fn emit(&self, e: UiEvent);
}

/// Why no `Core` is serving (C.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateState {
    /// No store in a local pinned dir, before `GENESIS` (wizard 1b); exit 9 `not_configured` (L46).
    FirstRun,
    /// `keychain_unavailable | keychain_lost | keyring_not_local` (`passphrase` is v1.1, L39).
    Locked(LockedReason),
    /// §8.13.
    StoreNewer,
    /// The reasons that leave no store: `data_dir_missing | data_dir_not_local | config_unreadable`.
    NotConfigured(&'static str),
    /// §2.5.
    ShuttingDown,
}

impl GateState {
    /// The envelope every refused method gets in this state (C.7, L46).
    pub fn envelope(&self) -> Envelope {
        let (code, reason, message): (ErrorCode, &str, String) = match self {
            GateState::FirstRun => (
                ErrorCode::NotConfigured,
                "first_run",
                MSG_FIRST_RUN.to_owned(),
            ),
            GateState::Locked(r) => (
                ErrorCode::Locked,
                r.as_str(),
                format!("atlas-duck is locked ({})", r.as_str()),
            ),
            GateState::StoreNewer => (
                ErrorCode::Unreachable,
                "store_newer",
                "the audit store was written by a newer atlas-duck; upgrade atlas-duck".to_owned(),
            ),
            GateState::NotConfigured(r) => (
                ErrorCode::NotConfigured,
                r,
                format!("atlas-duck is not configured ({r})"),
            ),
            GateState::ShuttingDown => (
                ErrorCode::Unreachable,
                "app_shutting_down",
                "atlas-duck is shutting down".to_owned(),
            ),
        };
        let mut env = Envelope::failed(code, true, &message);
        if let Some(err) = env.error.as_mut() {
            let mut d = Map::new();
            d.insert("reason".into(), Value::String(reason.to_owned()));
            err.details = Some(d);
        }
        env
    }

    /// The `doctor` label (PD-11).
    fn label(&self) -> &'static str {
        match self {
            GateState::FirstRun => "first_run",
            GateState::Locked(_) => "locked",
            GateState::StoreNewer => "store_newer",
            GateState::NotConfigured(_) => "not_configured",
            GateState::ShuttingDown => "shutting_down",
        }
    }
}

/// The handler served while no `Core` exists. The counter feeds the "Locked - N requests
/// refused" header (§2.5, UI-04).
pub struct GateHandler {
    state: GateState,
    ui: Arc<dyn UiSink>,
    refused: AtomicU64,
}

/// C.7: the handler `IpcServer` serves in a gate state.
pub fn gate_handler(state: GateState, ui: Arc<dyn UiSink>) -> Arc<dyn RequestHandler> {
    GateHandler::new(state, ui)
}

impl GateHandler {
    pub fn new(state: GateState, ui: Arc<dyn UiSink>) -> Arc<GateHandler> {
        Arc::new(GateHandler {
            state,
            ui,
            refused: AtomicU64::new(0),
        })
    }

    /// How many `submit`, `submit_script`, `await` and `cancel` calls were refused so far.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::SeqCst)
    }

    fn refuse(&self) -> Envelope {
        self.refused.fetch_add(1, Ordering::SeqCst);
        self.ui.emit(UiEvent::CredentialContextChanged); // a count only; no agent string
        self.state.envelope()
    }
}

/// §3.3 `hello`: the build ids must match; the CLI decides `app_upgraded` vs `protocol_mismatch`
/// from the details. The agent string is not read here.
// The `Err` type is fixed by `RequestHandler::hello`.
#[allow(clippy::result_large_err)]
pub fn hello_check(h: &Hello) -> Result<HelloReply, Envelope> {
    if h.build_id == BUILD_ID {
        return Ok(HelloReply {
            build_id: BUILD_ID.to_owned(),
        });
    }
    let mut env = Envelope::failed(
        ErrorCode::ProtocolMismatch,
        true,
        "client and app builds differ",
    );
    if let Some(err) = env.error.as_mut() {
        let mut d = Map::new();
        d.insert("client_build".into(), Value::String(h.build_id.clone()));
        d.insert("server_build".into(), Value::String(BUILD_ID.to_owned()));
        err.details = Some(d);
    }
    Err(env)
}

fn succeeded(data: Value) -> Envelope {
    Envelope {
        request_id: None,
        op_id: None,
        instance: None,
        status: Status::Succeeded,
        data: Some(data),
        edited: false,
        redacted: false,
        redaction_note: None,
        message: None,
        error: None,
        meta: None,
    }
}

fn describe_env() -> DescribeEnv {
    DescribeEnv {
        limits_source: LimitsSource::Default,
        available: None,
        caps: Value::Null,
        script_limits: serde_json::to_value(ScriptLimits::default()).unwrap_or(Value::Null),
    }
}

/// `ops.list` without `instance` (PD-16): every registry op with the built-in defaults.
pub fn ops_list_local() -> Envelope {
    let env = describe_env();
    let ops: Vec<Value> = atlas_duck_registry::all()
        .iter()
        .map(|spec| {
            let d = describe(spec, &env);
            json!({
                "op_id": d["op_id"],
                "class": d["class"],
                "approval": d["approval"],
                "description": d["description"],
            })
        })
        .collect();
    succeeded(json!({ "ops": ops }))
}

/// `ops.describe` without `instance` (PD-16); an unknown id is a `usage` failure.
pub fn ops_describe_local(op_id: &str) -> Envelope {
    match atlas_duck_registry::get(op_id) {
        Some(spec) => succeeded(describe(spec, &describe_env())),
        None => Envelope::failed(ErrorCode::Usage, false, &format!("unknown op id: {op_id}")),
    }
}

#[async_trait::async_trait]
impl RequestHandler for GateHandler {
    async fn hello(&self, _c: &ConnectionMeta, h: Hello) -> Result<HelloReply, Envelope> {
        hello_check(&h)
    }
    async fn ops_list(&self, instance: Option<&str>) -> Envelope {
        if instance.is_some() {
            self.state.envelope()
        } else {
            ops_list_local()
        }
    }
    async fn ops_describe(&self, op_id: &str, instance: Option<&str>) -> Envelope {
        if instance.is_some() {
            self.state.envelope()
        } else {
            ops_describe_local(op_id)
        }
    }
    async fn instances_list(&self) -> Envelope {
        self.state.envelope()
    }
    async fn submit(&self, _c: &ConnectionMeta, _p: SubmitParams) -> Envelope {
        self.refuse()
    }
    async fn submit_script(&self, _c: &ConnectionMeta, _p: SubmitParams) -> Envelope {
        self.refuse()
    }
    async fn await_request(
        &self,
        _c: &ConnectionMeta,
        _a: AwaitParams,
        _s: &dyn ProgressSink,
    ) -> Envelope {
        self.refuse()
    }
    async fn status(&self, _id: &str) -> Envelope {
        self.state.envelope()
    }
    async fn cancel(&self, _id: &str) -> Envelope {
        self.refuse()
    }
    async fn requests_list(
        &self,
        _a: Option<&str>,
        _s: Option<ListState>,
        _m: Option<MatchParams>,
    ) -> Envelope {
        self.state.envelope()
    }
    async fn doctor(&self) -> Envelope {
        succeeded(json!({ "gate": self.state.label() }))
    }
}
