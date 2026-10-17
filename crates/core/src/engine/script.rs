//! The script lifecycle against the `ScriptRunner` seam (§9, Task 27).
//!
//! **Seam.** The traits `app` implements over `sandbox-host` in M8 (C.7): [`ScriptRunner`]
//! (compile check, start), [`HostCalls`] (what a worker's `host.call` and `atlas.log` reach) and
//! [`RunHandle`]. Δ C.7: `RunHandle` is `Send + Sync` and `wait(&self)`, because the cancel path
//! kills a run while the task that drives it awaits its end.
//!
//! **Flow** (`submit` → `run_real` / `run_dry`). `REQUEST_RECEIVED`, static checks, the §3.4
//! availability re-check (`check_available`, no slot; `SCRIPT_FAILED {sandbox_unavailable,
//! direct}` on failure), then a compile check in the dry pool (`SCRIPT_FAILED {script_syntax |
//! sandbox_unavailable | timeout_s, direct}` on failure), a wait for one of the two real slots
//! (`queued` = the permit was not immediately available), `SCRIPT_STARTED`, the run. The run
//! policy ([`RunPolicy`]) is read before each of those runner calls, never captured at submit
//! (PD-141). Every record-bearing step goes through [`Engine::transition_with`]
//! (so an expiry that fired while the run could not expire takes effect right after its
//! release item), and every host-call record through [`append_gated`] (the entry's gate, and
//! only while the run is `Running`: a cancel that ended the request first gets nothing more).
//!
//! **Host calls** ([`LiveBackend`]). Validated by [`EngineValidator`] (Read class, schema, field
//! rules, caps with `for_script`, instance routing, the op's own static checks); the first
//! accepted call commits `SCRIPT_CALL_SENT` before anything is sent (the run is *dispatched*);
//! each call commits `SCRIPT_CALL` and only then returns its result. An append that fails kills
//! the run (`SCRIPT_FAILED {audit_failure}`, terminal). Dry runs ([`DryRunBackend`]) answer from
//! the registry's examples and hold no client handle.
//!
//! **Ends** ([`classify`]). Decided by the host from its own state (§9.5): a compile failure, or
//! a host-measured limit or a spawn-time unavailability of a run that neither queued nor
//! dispatched, is direct (`failed`, exit 8); every other end is one release item (`SCRIPT_FINISHED` / non-direct
//! `SCRIPT_FAILED`) except client cancels and the shutdown path, which end in `CANCELLED`.
//!
//! **Candidates.** `{"result": value}` for a result, `{"script_error": {class, message, stack,
//! elapsed, logs, stderr}}` for error details (`ErrorClassOnly` keeps `script_error.class`);
//! both are rebuilt from the committed record by [`normalize`] (`cache`'s one construction path).

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use atlas_duck_atlassian::{FetchControl, ReadBudget};
use atlas_duck_audit::{AuditError, NewEvent};
use atlas_duck_ipc::envelope::{Envelope, ErrorCode};
use atlas_duck_ipc::proto::{ConnectionMeta, SubmitParams, params_sha256};
use atlas_duck_ipc::sandbox::probe::ConfinementReport;
use atlas_duck_ipc::sandbox::{HostCall, HostCallResult, ScriptLimits};
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_preview::{PreviewBody, ProvenanceRow, ScriptItemKind};
use atlas_duck_registry::{
    BodySource, CliBinding, OpClass, OperationSpec, Product, Projection, RELEASE_CAP_BYTES,
    SCRIPT_RUN, Similarity, StatusSet, SuccessBody, SuccessShape, TargetDisplay,
    script_target_display,
};
use serde_json::{Map, Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use super::cache::{Candidate, RebuildError};
use super::envelope::{self, OpenStatus};
use super::handler::{CoreHandler, excerpt, internal_error};
use super::queue::{AgentKey, Reservation};
use super::read::{self, Classified};
use super::{Engine, NewEntry, OnAuditFailure, RequestEntry, RequestHead, audit_failure_retryable};
use crate::audit_port::commit_request_received;
use crate::gate::{AttentionKind, GateState, UiEvent};
use crate::identity;
use crate::ids::RequestId;
use crate::instances::{InstanceState, RouteError};
use crate::lifecycle::model::{Event, Kind, Model, Phase, ReleaseItem, step};
use crate::normalize::normalize_reason;
use crate::ops::generic::{count_shown_text, fallback_preview};
use crate::ops::{
    ExecError, ExecPlan, PreviewCtx, PreviewInput, PreviewModel, ReadPlan, ReadView, op_table,
};
use crate::payloads::{
    self, EventCtx, InFlightReason, OutcomeKind, ReadFetched, ScriptCallMeta, ScriptErrorDetails,
    ScriptFailed,
};
use crate::redact::RedactionMeta;
use crate::running::KillAnswer;
use crate::validate::{ValidateCtx, Validated, ValidationError, validate, validate_script_submit};

const MIB: u64 = 1024 * 1024;

// ---- the seam (C.7) ---------------------------------------------------------------------------

/// A submit-time compile failure (§9.1 step 2): the position and the compiler's message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub line: u32,
    pub column: u32,
    pub message: String,
}

/// Why the sandbox cannot run a script (Δ3). Only `AppUpgraded` reaches the wire (`details.reason`,
/// `retryable: true`, §4.3 exit-8 row); every reason is kept in `SCRIPT_FAILED.details` (PD-138).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    /// §3.4: the sandbox binary's identity changed since the probe (an upgrade under a running
    /// app); scripts stay refused until restart.
    AppUpgraded,
    /// §9.4: the confinement floor cannot be applied, and degraded confinement is not allowed.
    FloorNotMet,
    /// PD-138: the startup probe report did not arrive in time.
    ProbePending,
    /// The worker could not be spawned (or never sent its ready frame).
    SpawnFailed,
}

impl UnavailableReason {
    /// The `SCRIPT_FAILED.details.reason` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AppUpgraded => REASON_APP_UPGRADED,
            Self::FloorNotMet => "floor_not_met",
            Self::ProbePending => "probe_pending",
            Self::SpawnFailed => "spawn_failed",
        }
    }
}

/// Why no worker could be started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerError {
    /// §9.4, §3.4: `failed`, exit 8, `sandbox_unavailable`.
    SandboxUnavailable { reason: UnavailableReason },
}

/// Why the submit-time compile check did not pass (Δ3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileFailure {
    /// The source does not compile: direct `script_syntax`.
    Syntax(CompileError),
    /// No compile worker could run: direct `sandbox_unavailable`.
    Unavailable(RunnerError),
    /// PD-135: the compile worker did not answer within its bound (10 s or the submitted
    /// `timeout_s`, whichever is lower): a direct, data-free `script_limit {timeout_s}`, never
    /// `script_syntax`.
    Timeout { timeout_s: u32 },
}

/// What a run may accept from the sandbox (Δ3, PD-141). Read from [`Engine::script_policy`]
/// immediately before each use (`check_available`, the compile check, the real-slot
/// acquisition, and again before a real run's spawn), never captured at submit: a
/// security-weakening setting never outlives its revocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunPolicy {
    /// "Allow scripts with degraded confinement" (§9.4). It covers only a probe-time floor
    /// failure (PD-141 (d)).
    pub allow_degraded: bool,
}

/// Which confinement a run gets (PD-138).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfinementMode {
    /// The §9.4 floor is met.
    Floor,
    /// The floor is not met and degraded confinement is allowed (§9.4, PD-141).
    Degraded,
}

impl ConfinementMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Floor => "floor",
            Self::Degraded => "degraded",
        }
    }
}

/// `SCRIPT_STARTED.confinement` (PD-138, R1): the mode and worker version a run is spawned under,
/// with the confinement report the runner holds for it. Computed from the slot-time policy, before
/// the record is appended: a revocation logged before the record narrows the spawn, so the record
/// can say `degraded` for a run whose `start` is then refused; the `SCRIPT_FAILED
/// {sandbox_unavailable, details.reason: floor_not_met}` that follows keeps the trail true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunConfinement {
    pub mode: ConfinementMode,
    pub worker_version: String,
    pub report: ConfinementReport,
}

impl RunConfinement {
    /// The record's `{mode, worker_version, report}`.
    pub fn to_value(&self) -> Value {
        json!({
            "mode": self.mode.as_str(),
            "worker_version": self.worker_version,
            "report": serde_json::to_value(&self.report).unwrap_or(Value::Null),
        })
    }
}

/// Why a run is killed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillReason {
    /// The agent's `cancel`.
    Client,
    /// The Running-scripts UI's kill button (§9.6).
    User,
    /// The shutdown path (§2.5 step 3).
    Shutdown,
    /// A limit the host measured (`max_calls`, `max_fetch_mb`, ...).
    Limit(String),
    /// An audit append failed (§5.1 inv. 1).
    AuditFailure,
}

/// How a run ended, as the host observed it (§9.1 step 5, §9.5). The worker's own `class`,
/// `message` and `stack` are untrusted payload for the release preview.
#[derive(Debug, Clone, PartialEq)]
pub enum RunEnd {
    Result {
        value: Value,
        logs: Vec<String>,
        stderr: String,
    },
    Error {
        class: String,
        message: String,
        stack: String,
        /// The host's clock from the spawn to the terminal frame (PD-134), never the worker's.
        elapsed_ms: u64,
        logs: Vec<String>,
        stderr: String,
    },
    /// A limit the host itself measured (timer, job-object or rlimit kill reason, OOM), or a
    /// spawn-time unavailability (Δ3). `name` is one of the closed set `timeout_s`, `heap_mb`,
    /// `process_mb`, `max_result_mb`, `sandbox_unavailable`, `app_upgraded`; the last two end as
    /// `SCRIPT_FAILED {reason: sandbox_unavailable}`, never as a `script_limit`.
    HostLimit {
        name: String,
    },
    Killed {
        reason: KillReason,
    },
    ProtocolViolation,
    Crashed,
}

/// What `start` hands the worker glue.
#[derive(Debug, Clone, PartialEq)]
pub struct RunSpec {
    pub run_id: String,
    pub source: String,
    pub args: Value,
    pub limits: ScriptLimits,
    pub dry_run: bool,
    /// Read right before the spawn (PD-141): for a real run, the policy read when it acquired its
    /// slot AND the one read again after its `SCRIPT_STARTED` committed (narrowing only, T15
    /// review I-1); for a dry run, after its compile check.
    pub policy: RunPolicy,
}

/// C.7: implemented by `app` over `sandbox-host` (M8); `testing::FakeScriptRunner` in M3.
#[async_trait]
pub trait ScriptRunner: Send + Sync {
    /// §3.4 re-check at submit, after static validation and before the compile check: the
    /// sandbox binary's file identity, the probe report and the floor rule under `policy`. Needs
    /// no slot; a failure is a direct `sandbox_unavailable`.
    async fn check_available(&self, policy: RunPolicy) -> Result<(), RunnerError>;
    /// The submit-time compile check, in a compile-only worker of the dry-run pool. `limits` are
    /// the run's (the worker's memory limits; the compile is bounded by 10 s or
    /// `limits.timeout_s`, whichever is lower, PD-135).
    async fn compile_check(
        &self,
        source: &str,
        limits: &ScriptLimits,
        policy: RunPolicy,
    ) -> Result<(), CompileFailure>;
    /// What a run spawned now under `policy` runs with, for `SCRIPT_STARTED.confinement`
    /// (PD-138; the slot-time policy, see [`RunConfinement`]). `None`: the runner states nothing
    /// and the record has no `confinement` key.
    fn confinement(&self, policy: RunPolicy) -> Option<RunConfinement>;
    /// Starts a worker; its `host.call`s arrive at `calls`.
    async fn start(
        &self,
        run: RunSpec,
        calls: Arc<dyn HostCalls>,
    ) -> Result<Arc<dyn RunHandle>, RunnerError>;
}

/// C.7: what the worker's `host.call`s and `atlas.log` go through.
#[async_trait]
pub trait HostCalls: Send + Sync {
    async fn call(&self, run_id: &str, call: HostCall) -> HostCallResult;
    fn log(&self, run_id: &str, line: &str);
}

/// C.7 (Δ: `Send + Sync`, `wait(&self)`): the cancel path kills a run while another task awaits
/// its end, so both methods take `&self` on a shared handle.
#[async_trait]
pub trait RunHandle: Send + Sync {
    /// Terminates the worker (`TerminateJobObject` / `SIGKILL`) without waiting for it. A kill
    /// that reaches a worker that already exited is a no-op: core marks a run ended only after
    /// `wait` returned, so `kill` can race the exit. The implementation owns its child or job
    /// handle and never signals a bare PID (the PID may be reaped and reused).
    fn kill(&self, why: KillReason);
    /// The run's end. Core calls it exactly once per handle; it settles when the worker is gone
    /// and answers the same `RunEnd` however often it is awaited.
    async fn wait(&self) -> RunEnd;
}

// ---- the script's place in the registry-shaped world --------------------------------------------

/// `script.run` is not a registry operation (§9, `registry::SCRIPT_RUN`), but the request entry,
/// the candidate cache, the redaction engine and the fallback previewer are all keyed by an
/// [`OperationSpec`]. This one has no endpoint, no params schema, no redaction rules and no
/// paging: the neutral value every one of those paths treats as "nothing special".
pub static SCRIPT_SPEC: OperationSpec = OperationSpec {
    id: "script.run",
    product: Product::Jira,
    class: OpClass::Read,
    endpoint: atlas_duck_registry::Endpoint {
        method: atlas_duck_registry::Method::Get,
        path: "",
        query: &[],
        body: BodySource::None,
    },
    alt_endpoint: None,
    params_schema: "{}",
    cli: CliBinding {
        noun_path: &[],
        positional: None,
        flags: &[],
    },
    target_params: &[],
    conflict_baselines: &[],
    target_display: TargetDisplay::None,
    similarity: Similarity::None,
    field_rules: None,
    caps: atlas_duck_registry::Caps {
        max: None,
        move_limit: None,
        comments_cap: None,
        upload_max_bytes: None,
        static_result_cap_bytes: RELEASE_CAP_BYTES,
    },
    min_version: None,
    paginated: None,
    result_projection: Projection::Empty,
    success: SuccessShape {
        statuses: StatusSet::Any2xx,
        body: SuccessBody::Json,
    },
    redaction_rules: atlas_duck_registry::RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &[],
    },
    result_example: "null",
    result_example_sparse: "null",
    result_schema: "{}",
    write_guidance: false,
};

/// The data-free reasons of a limit end (`SCRIPT_FAILED.reason`) are the limit's own name; these
/// are the other host-decided ones.
const REASON_SCRIPT_SYNTAX: &str = "script_syntax";
const REASON_SANDBOX_UNAVAILABLE: &str = "sandbox_unavailable";
/// The `HostLimit` name and `details.reason` of an identity mismatch (§3.4, PD-133).
const REASON_APP_UPGRADED: &str = "app_upgraded";
const LIMIT_TIMEOUT_S: &str = "timeout_s";
const REASON_KILLED_BY_USER: &str = "killed_by_user";
const REASON_PROTOCOL_VIOLATION: &str = "protocol_violation";
const REASON_WORKER_CRASH: &str = "worker_crash";
const REASON_AUDIT_FAILURE: &str = "audit_failure";

const MSG_RUN_NOT_POSSIBLE: &str = "the script could not be run";
const MSG_CALL_CANCELLED: &str = "the run was cancelled";
const MSG_UPSTREAM_FAILED: &str = "the server could not be reached or its answer was unusable";

// ---- per-request state --------------------------------------------------------------------------

/// Which of the registry's static examples a dry run answers from (§9.1 step 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExampleMode {
    Full,
    Sparse,
}

impl ExampleMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Sparse => "sparse",
        }
    }
}

/// What a script request keeps beside the model (Task 27). Never `Debug`-printed in full: the
/// source and the args are agent data (§7.7).
#[derive(Clone)]
pub struct ScriptState {
    pub source: String,
    pub args: Value,
    pub limits: ScriptLimits,
    /// `Some` for a dry run.
    pub dry: Option<ExampleMode>,
    /// The run waited for a real slot held by another real run (§9.5).
    pub queued: bool,
    /// §9.5: the data-free limit outcome of a `queued` run pre-selects "keep error class only".
    pub preselect_error_class_only: bool,
    /// The release item once the run ended.
    pub item: Option<ReleaseItem>,
    /// The run's host-side facts while it lives.
    pub shared: Option<Arc<RunShared>>,
    /// The slot instant, set by the `SlotAcquired` step (PD-142): the wall time as RFC 3339 ms
    /// beside the suspend-aware monotonic reading `elapsed_ms` is measured from.
    pub slot: Option<(String, Duration)>,
    /// The instance ids the run called (§7.1: a PAT or origin change invalidates the candidate).
    pub instances: BTreeSet<String>,
    /// Host calls whose results were truncated or lossy (§9.5 preview warning), host-counted.
    pub lossy_calls: u64,
    /// PD-145: the run's host calls that were sent, for the release preview. Built from each
    /// request as the script sent it, never from a response; at most `max_calls` rows (a call
    /// over the limit is refused before it is sent). In memory only: after a restart the item
    /// is `ABANDONED` (§11.3).
    pub calls: Vec<ProvenanceRow>,
    /// R8 (M5 M-13): a host call's request asked for `renderedFields`, so the candidate may hold
    /// rendered copies a field drop leaves behind (the Caution `script_rendered_copies`).
    pub rendered_call: bool,
    pub redaction_meta: Option<RedactionMeta>,
    pub also_appears_in: Vec<String>,
}

impl ScriptState {
    fn new(source: String, args: Value, limits: ScriptLimits, dry: Option<ExampleMode>) -> Self {
        ScriptState {
            source,
            args,
            limits,
            dry,
            queued: false,
            preselect_error_class_only: false,
            item: None,
            shared: None,
            slot: None,
            instances: BTreeSet::new(),
            lossy_calls: 0,
            calls: Vec::new(),
            rendered_call: false,
            redaction_meta: None,
            also_appears_in: Vec::new(),
        }
    }
}

impl fmt::Debug for ScriptState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptState")
            .field("source_bytes", &self.source.len())
            .field("dry", &self.dry)
            .field("queued", &self.queued)
            .field("item", &self.item)
            .field("lossy_calls", &self.lossy_calls)
            .field("calls", &self.calls.len())
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the cancel path needs of one host call in flight to record it (`cancelled_in_flight`).
#[derive(Clone)]
pub(crate) struct CallInfo {
    pub call_id: u64,
    pub op: String,
    pub params: Value,
    pub alias: String,
    pub instance_id: String,
    pub user_key: Option<String>,
}

struct InFlight {
    info: CallInfo,
    ctl: FetchControl,
}

#[derive(Default)]
struct SharedInner {
    handle: Option<Arc<dyn RunHandle>>,
    kill: Option<KillReason>,
    ended: bool,
    dispatched: bool,
    audit_failed: bool,
    calls: u32,
    fetched_bytes: u64,
    instances: BTreeSet<String>,
    /// The aliases of the instances the run called (PD-142), as the calls named them.
    aliases: BTreeSet<String>,
    in_flight: HashMap<u64, InFlight>,
}

/// The host's own state of one run (§9.5: classification is decided from it, never from the
/// worker): whether it dispatched, its call and byte counters, the instances it called, the
/// host calls in flight and the kill that was asked for. Shared by the run task, the backend
/// and the cancel path.
#[derive(Default)]
pub struct RunShared {
    inner: Mutex<SharedInner>,
}

impl RunShared {
    /// Asks for the worker's death. The first reason wins; a run that ended is not killed.
    /// `false` = nothing was asked (the run ended or a kill was already requested).
    pub(crate) fn request_kill(&self, why: KillReason) -> bool {
        let handle = {
            let mut g = lock(&self.inner);
            if g.ended || g.kill.is_some() {
                return false;
            }
            g.kill = Some(why.clone());
            g.handle.clone()
        };
        if let Some(h) = handle {
            h.kill(why);
        }
        true
    }

    fn set_handle(&self, h: Arc<dyn RunHandle>) {
        let pending = {
            let mut g = lock(&self.inner);
            g.handle = Some(h.clone());
            g.kill.clone()
        };
        // A kill asked for before the worker existed: it dies at once.
        if let Some(why) = pending {
            h.kill(why);
        }
    }

    fn mark_ended(&self) {
        lock(&self.inner).ended = true;
    }

    /// The run's worker is gone (the end record may not be appended yet).
    pub(crate) fn ended(&self) -> bool {
        lock(&self.inner).ended
    }

    /// Host calls the run made so far (validated calls, counted by the host, never the worker).
    pub(crate) fn calls(&self) -> u32 {
        lock(&self.inner).calls
    }

    pub(crate) fn kill_reason(&self) -> Option<KillReason> {
        lock(&self.inner).kill.clone()
    }

    pub(crate) fn dispatched(&self) -> bool {
        lock(&self.inner).dispatched
    }

    fn mark_dispatched(&self) {
        lock(&self.inner).dispatched = true;
    }

    fn set_audit_failed(&self) {
        lock(&self.inner).audit_failed = true;
    }

    fn audit_failed(&self) -> bool {
        lock(&self.inner).audit_failed
    }

    /// Counts a validated call against `max_calls`; `false` = over the limit.
    fn accept_call(&self, instance_id: &str, alias: &str, max_calls: u32) -> bool {
        let mut g = lock(&self.inner);
        g.calls = g.calls.saturating_add(1);
        g.instances.insert(instance_id.to_owned());
        g.aliases.insert(alias.to_owned());
        g.calls <= max_calls
    }

    /// Bytes the run's host calls fetched so far (host counter).
    pub(crate) fn fetched_bytes(&self) -> u64 {
        lock(&self.inner).fetched_bytes
    }

    fn add_fetched(&self, n: u64) {
        let mut g = lock(&self.inner);
        g.fetched_bytes = g.fetched_bytes.saturating_add(n);
    }

    /// The instances (ids) the run called, for `CandidateChanged` (Task 25 handoff).
    pub(crate) fn instances(&self) -> BTreeSet<String> {
        lock(&self.inner).instances.clone()
    }

    /// The aliases of the instances the run called, for the Running-scripts view (PD-142).
    pub(crate) fn aliases(&self) -> BTreeSet<String> {
        lock(&self.inner).aliases.clone()
    }

    fn add_in_flight(&self, info: CallInfo, ctl: FetchControl) {
        lock(&self.inner)
            .in_flight
            .insert(info.call_id, InFlight { info, ctl });
    }

    /// `false` = the end of the run took the call (it records it itself). Called under the
    /// entry's gate, right before the call's own record is appended.
    fn finish_in_flight(&self, call_id: u64) -> bool {
        lock(&self.inner).in_flight.remove(&call_id).is_some()
    }

    /// The calls in flight, taken by the cancel path or the end of the run under the entry's gate.
    pub(crate) fn take_in_flight(&self) -> Vec<(CallInfo, FetchControl)> {
        let mut g = lock(&self.inner);
        let mut calls: Vec<_> = g.in_flight.drain().map(|(_, f)| (f.info, f.ctl)).collect();
        calls.sort_by_key(|(i, _)| i.call_id);
        calls
    }

    /// The `SCRIPT_CALL {cancelled_in_flight}` records of the calls in flight (§9.5): each call
    /// is taken, its control cancelled and the bytes received recorded. A call whose request was
    /// never written has nothing to record. Under the entry's gate only.
    pub(crate) fn in_flight_records(
        &self,
        ctx: &EventCtx,
        reason: InFlightReason,
    ) -> Vec<NewEvent> {
        self.in_flight_records_with_calls(ctx, reason).0
    }

    /// [`Self::in_flight_records`] with the calls it recorded, in `call_id` order (the release
    /// preview lists them as `cancelled_in_flight`, PD-145).
    pub(crate) fn in_flight_records_with_calls(
        &self,
        ctx: &EventCtx,
        reason: InFlightReason,
    ) -> (Vec<NewEvent>, Vec<CallInfo>) {
        let mut records = Vec::new();
        let mut recorded = Vec::new();
        for (info, ctl) in self.take_in_flight() {
            ctl.cancel();
            let cap = ctl.take_captured();
            if !cap.sent {
                continue;
            }
            let size = cap
                .pages
                .iter()
                .map(|p| p.body.len() as u64)
                .sum::<u64>()
                .saturating_add(cap.partial.len() as u64);
            let ctx = EventCtx {
                instance_id: Some(info.instance_id.clone()),
                ..ctx.clone()
            };
            records.push(payloads::script_call(
                &ctx,
                &ScriptCallMeta {
                    call_id: info.call_id,
                    op: &info.op,
                    params: &info.params,
                    instance: Some(&info.alias),
                    user_key: info.user_key.as_deref(),
                    rejection: Some("cancelled_in_flight"),
                },
                &ReadFetched::CancelledInFlight {
                    reason,
                    responses: &cap.pages,
                    partial: &cap.partial,
                    size,
                },
                size,
                None,
            ));
            recorded.push(info);
        }
        (records, recorded)
    }
}

// ---- host-call validation -----------------------------------------------------------------------

/// A host call that passed the static half of §9.1 step 4.
pub struct ValidatedCall {
    pub spec: &'static OperationSpec,
    pub validated: Validated,
    pub instance_id: String,
    pub alias: String,
    pub user_key: Option<String>,
}

/// The static half of a host call (§9.1 step 4): Read class, schema, field rules, caps with
/// `for_script`, instance routing. Both backends validate through it.
pub trait CallValidator: Send + Sync {
    /// `Err` is the rejection the script sees.
    fn validate(&self, call: &HostCall) -> Result<ValidatedCall, HostCallResult>;
}

fn class_name(code: ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "internal".to_owned())
}

/// A rejection inside the script: catchable, it does not end the run (§9.5).
fn rejected(code: ErrorCode, message: &str, extra: Map<String, Value>) -> HostCallResult {
    let mut details = Map::new();
    details.insert("message".into(), message.into());
    details.extend(extra);
    HostCallResult::Rejected {
        class: class_name(code),
        details: Value::Object(details),
    }
}

fn rejected_msg(code: ErrorCode, message: &str) -> HostCallResult {
    rejected(code, message, Map::new())
}

fn reason_details(reason: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("reason".into(), reason.into());
    m
}

/// [`CallValidator`] over the engine's instance table.
pub struct EngineValidator {
    engine: Arc<Engine>,
}

impl EngineValidator {
    pub fn new(engine: Arc<Engine>) -> EngineValidator {
        EngineValidator { engine }
    }
}

impl CallValidator for EngineValidator {
    fn validate(&self, call: &HostCall) -> Result<ValidatedCall, HostCallResult> {
        // `SCRIPT_CALL` records the params even of a rejected call: bound them like `args`.
        let fits = serde_json::to_vec(&call.params)
            .is_ok_and(|b| b.len() <= crate::validate::MAX_SCRIPT_ARGS_BYTES);
        if !fits {
            let mut m = Map::new();
            m.insert("param".into(), "params".into());
            return Err(rejected(
                ErrorCode::Validation,
                "the params are over 1 MiB",
                m,
            ));
        }
        let Some(spec) = atlas_duck_registry::get(&call.op_id) else {
            return Err(rejected_msg(ErrorCode::Validation, "unknown op"));
        };
        if spec.class != OpClass::Read {
            return Err(rejected_msg(
                ErrorCode::Validation,
                "only read ops can be called from a script",
            ));
        }
        if call.all && spec.paginated.is_none() {
            return Err(rejected_msg(
                ErrorCode::Validation,
                "this op is not paginated; use atlas.call",
            ));
        }
        let table = self.engine.instances();
        let inst = table
            .resolve(spec.product, call.instance.as_deref())
            .map_err(|e| match e {
                RouteError::ConfigUnreadable => rejected(
                    ErrorCode::NotConfigured,
                    "atlas-duck is not configured",
                    reason_details(crate::config::REASON_CONFIG_UNREADABLE),
                ),
                RouteError::UnknownAlias | RouteError::WrongProduct => {
                    let mut m = Map::new();
                    m.insert("param".into(), "instance".into());
                    rejected(ErrorCode::Validation, "unknown instance alias", m)
                }
                RouteError::NoInstance => rejected(
                    ErrorCode::NotConfigured,
                    "no instance is configured for this op",
                    reason_details("no_instance"),
                ),
            })?;
        match inst.state {
            InstanceState::Ok => {}
            InstanceState::NeedsToken => {
                return Err(rejected_msg(ErrorCode::NeedsToken, read::MSG_NEEDS_TOKEN));
            }
            InstanceState::IdentityHeaderMissing | InstanceState::IdentityHeaderMismatch => {
                return Err(rejected(
                    ErrorCode::UpstreamUnavailable,
                    envelope::MSG_IDENTITY_HEADER,
                    reason_details(inst.state.as_str()),
                ));
            }
            InstanceState::InsecureScheme | InstanceState::InstanceUnconfirmed => {
                return Err(rejected(
                    ErrorCode::NotConfigured,
                    "the instance is not configured",
                    reason_details(inst.state.as_str()),
                ));
            }
        }
        let (Some(id), Some(base)) = (inst.id.clone(), inst.base.clone()) else {
            return Err(rejected_msg(
                ErrorCode::NotConfigured,
                "the instance is not configured",
            ));
        };
        let caps = self.engine.effective_caps();
        let ctx = ValidateCtx {
            instance_version: inst.version,
            caps: &caps,
            for_script: true,
        };
        let validated = validate(spec, &call.params, &ctx).map_err(|e| from_validation(&e))?;
        // The op's own static checks (CQL rules, ...): the dry executor call.
        let dry = match op_table().get(spec.id) {
            Some(op) => (op.executor)(&self.engine.exec_ctx(
                spec,
                &validated.params,
                &base,
                None,
                validated.effective_max,
                validated.comments_cap,
            ))
            .map(|_| ()),
            None => Err(ExecError::NotInThisBuild),
        };
        match dry {
            Ok(()) | Err(ExecError::EnrichmentRequired) => {}
            Err(ExecError::NotInThisBuild) => {
                return Err(rejected_msg(ErrorCode::Internal, MSG_RUN_NOT_POSSIBLE));
            }
            Err(ExecError::Invalid(e)) => return Err(from_validation(&e)),
        }
        Ok(ValidatedCall {
            spec,
            validated,
            instance_id: id,
            alias: inst.alias.clone(),
            user_key: inst.identity.as_ref().map(|i| i.atlassian_user_key.clone()),
        })
    }
}

fn from_validation(e: &ValidationError) -> HostCallResult {
    rejected(e.code, &e.message, e.details.clone())
}

// ---- the dry-run backend ------------------------------------------------------------------------

/// Answers every call from the registry's examples (§9.1 step 7, §9.5). Built from a mode and a
/// validator only: it holds no HTTP client handle, so it cannot reach Atlassian (C.0), and it
/// commits no record. Its call log (`op_id`, `params`, `instance`, `validation`) is what
/// `SCRIPT_DRY_RUN.calls` records.
pub struct DryRunBackend {
    mode: ExampleMode,
    validator: Arc<dyn CallValidator>,
    max_calls: u32,
    calls: Mutex<Vec<Value>>,
}

impl DryRunBackend {
    pub fn new(mode: ExampleMode, validator: Arc<dyn CallValidator>) -> DryRunBackend {
        DryRunBackend {
            mode,
            validator,
            max_calls: ScriptLimits::default().max_calls,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// The run's `max_calls` (the call log is bounded by it).
    pub fn with_max_calls(mut self, max_calls: u32) -> DryRunBackend {
        self.max_calls = max_calls;
        self
    }

    /// The calls the run made so far.
    pub fn calls(&self) -> Vec<Value> {
        lock(&self.calls).clone()
    }
}

#[async_trait]
impl HostCalls for DryRunBackend {
    async fn call(&self, _run_id: &str, call: HostCall) -> HostCallResult {
        let outcome = self.validator.validate(&call);
        let validation = match &outcome {
            Ok(_) => "ok".to_owned(),
            Err(HostCallResult::Rejected { class, .. }) => format!("rejected: {class}"),
            Err(HostCallResult::Ok(_)) => "rejected".to_owned(),
        };
        {
            let mut log = lock(&self.calls);
            let over = u32::try_from(log.len()).is_ok_and(|n| n >= self.max_calls);
            if over {
                return rejected_msg(ErrorCode::ScriptLimit, "the run exceeded max_calls");
            }
            log.push(json!({
                "op_id": call.op_id,
                "params": call.params,
                "instance": call.instance,
                "validation": validation,
            }));
        }
        match outcome {
            Ok(vc) => HostCallResult::Ok(match self.mode {
                ExampleMode::Full => vc.spec.result_example_json(),
                ExampleMode::Sparse => vc.spec.result_example_sparse_json(),
            }),
            Err(rejection) => rejection,
        }
    }

    fn log(&self, _run_id: &str, _line: &str) {}
}

// ---- the live backend ---------------------------------------------------------------------------

/// Appends one record of a run that is still `Running`, under the entry's gate (a cancel or
/// audit failure that ended the request first gets nothing more).
enum Appended {
    Done,
    Ended,
    Failed,
}

async fn append_gated(engine: &Arc<Engine>, entry: &Arc<RequestEntry>, ev: NewEvent) -> Appended {
    append_gated_call(engine, entry, None, ev, |_| {}).await
}

/// [`append_gated`] for the record of host call `call.1`: the call leaves the run's in-flight
/// table under the gate, right before its record is appended. The end of the run (cancel,
/// timeout, kill, crash) takes the calls still in the table under the same gate and records
/// them itself, so a call is recorded exactly once, by whoever holds the gate first. The body
/// runs in its own task: a dropped call future cannot release the gate while the append runs.
/// `on_done` runs under the gate once the record is appended, so what it adds to the model is
/// there before the end of the run can take the gate.
async fn append_gated_call(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    call: Option<(Arc<RunShared>, u64)>,
    ev: NewEvent,
    on_done: impl FnOnce(&RequestEntry) + Send + 'static,
) -> Appended {
    let (engine, entry) = (engine.clone(), entry.clone());
    tokio::spawn(async move {
        let _gate = entry.gate.clone().lock_owned().await;
        if !matches!(entry.state().model.phase(), Phase::Running) {
            return Appended::Ended;
        }
        if let Some((shared, id)) = &call
            && !shared.finish_in_flight(*id)
        {
            return Appended::Ended;
        }
        match engine.blocking(move |p| p.append(ev).map(|_| ())).await {
            Ok(()) => {
                on_done(&entry);
                Appended::Done
            }
            Err(_) => Appended::Failed,
        }
    })
    .await
    .unwrap_or(Appended::Failed)
}

/// §5.1 inv. 1: an append of the run failed. The worker is killed and the request ends
/// `failed`, `audit_failure` (`SCRIPT_FAILED {audit_failure}`, terminal); nothing is released.
async fn audit_failure(engine: &Arc<Engine>, entry: &Arc<RequestEntry>, shared: &RunShared) {
    shared.set_audit_failed();
    shared.request_kill(KillReason::AuditFailure);
    let (ctx, queued, dispatched) = (
        entry.ctx.clone(),
        entry.state().script.as_ref().is_some_and(|s| s.queued),
        shared.dispatched(),
    );
    let _ = engine
        .transition_with(
            entry,
            Event::AuditFailure,
            move |_| {
                vec![payloads::script_failed(
                    &ctx,
                    &ScriptFailed {
                        reason: REASON_AUDIT_FAILURE,
                        queued,
                        dispatched,
                        direct: false,
                        details: None,
                        candidate: None,
                    },
                )]
            },
            OnAuditFailure::FailRequest,
            |_| {},
        )
        .await;
}

/// The real run's host calls (§9.1 step 4).
pub struct LiveBackend {
    engine: Arc<Engine>,
    entry: Arc<RequestEntry>,
    shared: Arc<RunShared>,
    validator: Arc<dyn CallValidator>,
    limits: ScriptLimits,
    /// Held while the first accepted call commits `SCRIPT_CALL_SENT`: a second call waits for
    /// it, so no send precedes the dispatch record.
    dispatch: tokio::sync::Mutex<bool>,
}

impl LiveBackend {
    pub fn new(
        engine: Arc<Engine>,
        entry: Arc<RequestEntry>,
        shared: Arc<RunShared>,
        validator: Arc<dyn CallValidator>,
        limits: ScriptLimits,
    ) -> LiveBackend {
        LiveBackend {
            engine,
            entry,
            shared,
            validator,
            limits,
            dispatch: tokio::sync::Mutex::new(false),
        }
    }

    fn running(&self) -> bool {
        matches!(self.entry.state().model.phase(), Phase::Running)
    }

    fn ctx_for(&self, vc: &ValidatedCall) -> EventCtx {
        EventCtx {
            instance_id: Some(vc.instance_id.clone()),
            ..self.entry.ctx.clone()
        }
    }

    /// Commits `SCRIPT_CALL_SENT` for the first accepted call (the run is *dispatched*, §9.5).
    async fn ensure_dispatched(
        &self,
        call: &HostCall,
        vc: &ValidatedCall,
    ) -> Result<(), HostCallResult> {
        let mut sent = self.dispatch.lock().await;
        if *sent {
            return Ok(());
        }
        let ev =
            payloads::script_call_sent(&self.ctx_for(vc), call.id, &call.op_id, Some(&vc.alias));
        match append_gated(&self.engine, &self.entry, ev).await {
            Appended::Done => {
                *sent = true;
                self.shared.mark_dispatched();
                Ok(())
            }
            Appended::Ended => Err(rejected_msg(ErrorCode::Cancelled, MSG_CALL_CANCELLED)),
            Appended::Failed => {
                audit_failure(&self.engine, &self.entry, &self.shared).await;
                Err(rejected_msg(ErrorCode::Internal, MSG_RUN_NOT_POSSIBLE))
            }
        }
    }

    async fn live_call(&self, call: HostCall) -> HostCallResult {
        let vc = match self.validator.validate(&call) {
            Ok(v) => v,
            Err(r) => return r,
        };
        if !self.running() {
            return rejected_msg(ErrorCode::Cancelled, MSG_CALL_CANCELLED);
        }
        // `max_calls` and `max_fetch_mb` are host counters; over them a call is rejected inside
        // the script (§9.5 "in-script rejections ... `script_limit`").
        let fetch_cap = u64::from(self.limits.max_fetch_mb).saturating_mul(MIB);
        let over = !self
            .shared
            .accept_call(&vc.instance_id, &vc.alias, self.limits.max_calls)
            || self.shared.fetched_bytes() >= fetch_cap;
        if over {
            return rejected_msg(
                ErrorCode::ScriptLimit,
                "the run exceeded a call or fetch limit",
            );
        }
        if let Err(r) = self.ensure_dispatched(&call, &vc).await {
            return r;
        }
        self.execute(call, vc).await
    }

    async fn execute(&self, call: HostCall, vc: ValidatedCall) -> HostCallResult {
        let info = CallInfo {
            call_id: call.id,
            op: call.op_id.clone(),
            params: call.params.clone(),
            alias: vc.alias.clone(),
            instance_id: vc.instance_id.clone(),
            user_key: vc.user_key.clone(),
        };
        let ctl = FetchControl::new();
        // The control first, then the cover: a cancel that took the control before it exists
        // finds nothing in flight and a request that ended mints no cover (Task 24 rule).
        self.shared.add_in_flight(info.clone(), ctl.clone());
        let classified = match self.fetch(&call, &vc, &ctl).await {
            Ok(c) => c,
            Err(result) => {
                self.shared.finish_in_flight(call.id);
                return result;
            }
        };
        // R8: the request went out asking for `renderedFields`, whatever the answer turns out to
        // be (`Err` above = nothing was sent).
        if requests_rendered(&call.params)
            && let Some(s) = self.entry.state().script.as_mut()
        {
            s.rendered_call = true;
        }
        // The control was cancelled by the end of the run, which took the call and records it.
        let Some(settled) = self.settle(&call, &vc, &info, classified) else {
            self.shared.finish_in_flight(call.id);
            return rejected_msg(ErrorCode::Cancelled, MSG_CALL_CANCELLED);
        };
        self.shared.add_fetched(settled.size);
        let ended = Some((self.shared.clone(), call.id));
        // From the request as sent (`call.params`), never from the response.
        let row = provenance_row(
            call.id,
            vc.spec,
            &info.alias,
            &call.params,
            &outcome_of(&settled.result),
        );
        let lossy = settled.lossy;
        // The row and the lossy count go in under the gate, with the record: the end of the run
        // cannot commit the item between the two.
        let note = move |entry: &RequestEntry| {
            if let Some(s) = entry.state().script.as_mut() {
                if lossy {
                    s.lossy_calls += 1;
                }
                s.calls.push(row);
            }
        };
        match append_gated_call(&self.engine, &self.entry, ended, settled.record, note).await {
            Appended::Done => settled.result,
            Appended::Ended => rejected_msg(ErrorCode::Cancelled, MSG_CALL_CANCELLED),
            Appended::Failed => {
                audit_failure(&self.engine, &self.entry, &self.shared).await;
                rejected_msg(ErrorCode::Internal, MSG_RUN_NOT_POSSIBLE)
            }
        }
    }

    /// The call's fetch under the request's cover, with the identity handling of Task 26
    /// (§7.1): a failed header check or a JSON 401 runs the token re-check, and a rename
    /// re-fetches once. `Err` = nothing was sent.
    async fn fetch(
        &self,
        call: &HostCall,
        vc: &ValidatedCall,
        ctl: &FetchControl,
    ) -> Result<Classified, HostCallResult> {
        let internal = || rejected_msg(ErrorCode::Internal, MSG_RUN_NOT_POSSIBLE);
        let http = self
            .engine
            .client(&vc.instance_id)
            .await
            .map_err(|_| internal())?;
        let op = op_table().get(vc.spec.id).ok_or_else(internal)?;
        let plan = (op.executor)(&self.engine.exec_ctx(
            vc.spec,
            &vc.validated.params,
            http.client.base(),
            None,
            vc.validated.effective_max,
            vc.validated.comments_cap,
        ));
        let Ok(ExecPlan::Read(plan)) = plan else {
            return Err(internal());
        };
        // `atlas.all` pages to the end; the host's own counters bound it.
        let plan = if call.all { widen(plan) } else { plan };
        let cover = self
            .engine
            .covers()
            .for_request(&self.entry.head.request_id)
            .map_err(|_| internal())?;
        let fetch_cap = u64::from(self.limits.max_fetch_mb).saturating_mul(MIB);
        let budget = ReadBudget {
            max_bytes: fetch_cap.saturating_sub(self.shared.fetched_bytes()),
            max_response_bytes: u64::from(self.limits.max_call_result_mb).saturating_mul(MIB),
            ..self.engine.read_budget()
        };
        let start = vc
            .validated
            .params
            .get("start")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let mut refetched = false;
        loop {
            let seen = self.engine.identity_epoch(&vc.instance_id);
            let fetched = read::run_plan(&http.client, &cover, &plan, &budget, ctl, start).await;
            let Some(trigger) = read::fetched_trigger(&fetched) else {
                return Ok(read::classify_read(fetched, &http.proxy));
            };
            let effect = if refetched {
                identity::Effect::HeaderCheckFailed
            } else {
                let result = identity::recheck(&self.engine, &vc.instance_id, seen).await;
                identity::effect(identity::Path::DirectRead, trigger, &result)
            };
            match effect {
                identity::Effect::Ordinary => {
                    return Ok(read::classify_read(read::ordinary(fetched), &http.proxy));
                }
                identity::Effect::Refetch => {
                    let (earlier, answer) = read::split_answer(fetched);
                    let mut responses = earlier;
                    responses.extend(answer);
                    let first = payloads::script_call(
                        &self.ctx_for(vc),
                        &ScriptCallMeta {
                            call_id: call.id,
                            op: &call.op_id,
                            params: &call.params,
                            instance: Some(&vc.alias),
                            user_key: vc.user_key.as_deref(),
                            rejection: Some("identity_check_retried"),
                        },
                        &ReadFetched::Unavailable {
                            responses: &responses,
                            reason: "identity_check",
                        },
                        responses.iter().map(|r| r.body.len() as u64).sum(),
                        None,
                    );
                    match append_gated(&self.engine, &self.entry, first).await {
                        Appended::Done => {}
                        Appended::Ended => {
                            return Err(rejected_msg(ErrorCode::Cancelled, MSG_CALL_CANCELLED));
                        }
                        Appended::Failed => {
                            audit_failure(&self.engine, &self.entry, &self.shared).await;
                            return Err(internal());
                        }
                    }
                    refetched = true;
                }
                other => return Ok(read::identity_classified(other, fetched)),
            }
        }
    }

    /// What the script sees, the `SCRIPT_CALL` record and the bytes received.
    fn settle(
        &self,
        call: &HostCall,
        vc: &ValidatedCall,
        info: &CallInfo,
        classified: Classified,
    ) -> Option<Settled> {
        let ctx = self.ctx_for(vc);
        let max_result = u64::from(self.limits.max_call_result_mb).saturating_mul(MIB);
        match classified {
            Classified::Item(rec) => {
                let size = rec.size();
                let event = rec.record(&ctx);
                let (result, rejection, lossy) = match rec.item {
                    ReleaseItem::Result => {
                        settle_result(vc.spec, &vc.validated.params, &rec, call.all, max_result)
                    }
                    ReleaseItem::UpstreamError => {
                        let (status, text) = rec.responses.last().map_or((0, String::new()), |r| {
                            (r.status, read::error_text(&r.body))
                        });
                        let mut m = Map::new();
                        m.insert("status".into(), status.into());
                        m.insert("error_messages".into(), text.into());
                        (
                            rejected(ErrorCode::UpstreamHttp, envelope::MSG_UPSTREAM_HTTP, m),
                            Some("upstream_http"),
                            false,
                        )
                    }
                    _ => {
                        // The record names the cap that stopped the fetch and the cause of a
                        // later-page failure (`read::gated`).
                        let cap = event.payload.get("cap_or_budget").and_then(Value::as_str);
                        let cause = event.payload.get("reason").and_then(Value::as_str);
                        let kind = rec.outcome.as_ref().map(|o| o.kind);
                        let (result, name) = match (kind, cap, cause) {
                            // The run's fetched bytes reached `max_fetch_mb` (§9.5).
                            (Some(OutcomeKind::TooLarge), Some("fetch_cap_50mib"), _) => (
                                rejected_msg(
                                    ErrorCode::ScriptLimit,
                                    "the run exceeded a call or fetch limit",
                                ),
                                "max_fetch_mb",
                            ),
                            (Some(OutcomeKind::TooLarge), _, _) => (
                                rejected_msg(ErrorCode::ResultTooLarge, MSG_UPSTREAM_FAILED),
                                "result_too_large",
                            ),
                            (Some(OutcomeKind::Unparsable), _, Some("needs_token")) => (
                                rejected_msg(ErrorCode::NeedsToken, read::MSG_NEEDS_TOKEN),
                                "needs_token",
                            ),
                            (Some(OutcomeKind::Unparsable), _, _) => (
                                rejected_msg(ErrorCode::UpstreamUnavailable, MSG_UPSTREAM_FAILED),
                                "upstream_unavailable",
                            ),
                            _ => (
                                rejected_msg(ErrorCode::UpstreamNetwork, MSG_UPSTREAM_FAILED),
                                "upstream_network",
                            ),
                        };
                        (result, Some(name), false)
                    }
                };
                Some(Settled {
                    result,
                    record: payloads::script_call_from(
                        event,
                        &call_meta(call, info, rejection),
                        size,
                    ),
                    size,
                    lossy,
                })
            }
            Classified::Direct(d) => {
                let size: u64 = d.responses.iter().map(|r| r.body.len() as u64).sum();
                let reason = d
                    .cause
                    .map_or_else(|| class_name(d.code), |(_, v)| v.to_owned());
                let record = payloads::script_call(
                    &ctx,
                    &call_meta(call, info, Some(&reason)),
                    &ReadFetched::Unavailable {
                        responses: &d.responses,
                        reason: &reason,
                    },
                    size,
                    None,
                );
                let mut extra = Map::new();
                if let Some(r) = d.reason_detail {
                    extra.insert("reason".into(), r.into());
                }
                Some(Settled {
                    result: rejected(d.code, &d.message, extra),
                    record,
                    size,
                    lossy: false,
                })
            }
            // The control was cancelled by the end of the run, which records the call itself.
            Classified::Cancelled => None,
        }
    }
}

fn call_meta<'a>(
    call: &HostCall,
    info: &'a CallInfo,
    rejection: Option<&'a str>,
) -> ScriptCallMeta<'a> {
    ScriptCallMeta {
        call_id: call.id,
        op: &info.op,
        params: &info.params,
        instance: Some(&info.alias),
        user_key: info.user_key.as_deref(),
        rejection,
    }
}

/// One host call settled: what the script sees, the record that goes first, bytes received.
struct Settled {
    result: HostCallResult,
    record: NewEvent,
    size: u64,
    /// The result is truncated or lossy (§9.5 preview warning).
    lossy: bool,
}

/// A 2xx answer: its body as the script's result, unless it is over `max_call_result_mb`.
fn settle_result(
    spec: &'static OperationSpec,
    params: &Value,
    rec: &read::ItemRecord,
    all: bool,
    max_result: u64,
) -> (HostCallResult, Option<&'static str>, bool) {
    let shape = read::ReadShape::of(spec, params);
    match read::result_value(spec, shape, rec.responses.iter().map(|r| r.body.as_slice())) {
        Ok((body, _)) => {
            let len = serde_json::to_vec(&body).map_or(u64::MAX, |b| b.len() as u64);
            if len > max_result {
                (
                    rejected_msg(
                        ErrorCode::ResultTooLarge,
                        "the result is above max_call_result_mb",
                    ),
                    Some("result_too_large"),
                    false,
                )
            } else {
                // `atlas.all` pages to the end; a single call that stopped early is lossy, and
                // so are comments cut at the comments cap (which `atlas.all` keeps).
                let lossy = (!all && rec.page.is_some_and(|p| p.next_start.is_some()))
                    || rec.comments_truncated.is_some();
                (HostCallResult::Ok(body), None, lossy)
            }
        }
        Err(_) => (
            rejected_msg(
                ErrorCode::UpstreamUnavailable,
                "the answer of the server could not be read",
            ),
            Some("upstream_unavailable"),
            false,
        ),
    }
}

#[async_trait]
impl HostCalls for LiveBackend {
    async fn call(&self, _run_id: &str, call: HostCall) -> HostCallResult {
        self.live_call(call).await
    }

    fn log(&self, _run_id: &str, _line: &str) {}
}

fn widen(plan: ReadPlan) -> ReadPlan {
    match plan {
        ReadPlan::Get(g) => ReadPlan::Get(g),
        ReadPlan::Paged { call, .. } => ReadPlan::Paged {
            call,
            max_items: u64::MAX,
        },
        ReadPlan::Search {
            call, items_key, ..
        } => ReadPlan::Search {
            call,
            items_key,
            max_items: u64::MAX,
        },
        // The comments cap is a hard cap, not the agent's `max`: `atlas.all` keeps it.
        composite @ ReadPlan::IssueWithComments { .. } => composite,
    }
}

// ---- the candidate ------------------------------------------------------------------------------

/// The bare candidate body of a committed `SCRIPT_FINISHED` / non-direct `SCRIPT_FAILED` payload
/// (`cache`'s one construction path): `{result}` or `{script_error}`. Reads nothing but the
/// payload.
pub fn normalize(payload: &Value) -> Result<Value, RebuildError> {
    if let Some(result) = payload.get("result") {
        return Ok(json!({ "result": result }));
    }
    if let Some(error) = payload.get("error").or_else(|| payload.get("candidate")) {
        return Ok(json!({ "script_error": bound_error(error.clone()) }));
    }
    Err(RebuildError::Malformed)
}

/// The bytes of `{"result":` and `}` around a result value.
const RESULT_WRAPPER_BYTES: u64 = 11;
/// Bounds of an error candidate (§9.5, I-3): the worker's own text is untrusted and unbounded,
/// the released envelope must fit one IPC frame. The record keeps the full text; the candidate
/// (and so the preview and the release) carries the first part and a marker.
const ERROR_MESSAGE_MAX_BYTES: usize = 64 * 1024;
const ERROR_STACK_MAX_BYTES: usize = 64 * 1024;
const ERROR_STDERR_MAX_BYTES: usize = 256 * 1024;
const ERROR_LOGS_MAX_BYTES: usize = 1024 * 1024;

/// `text` cut to at most `max` bytes (on a character boundary) plus a marker naming how many
/// bytes were dropped; `None` = it fits.
fn truncated(text: &str, max: usize) -> Option<String> {
    if text.len() <= max {
        return None;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Some(format!(
        "{}\n[truncated {} bytes]",
        &text[..end],
        text.len() - end
    ))
}

/// The error candidate within its byte bounds: `message`, `stack`, `stderr` and `logs` cut with
/// a marker, `truncated: true` beside them when anything was. Deterministic in the value, so
/// the candidate built at the end of the run and the one rebuilt from the record agree.
pub(crate) fn bound_error(mut error: Value) -> Value {
    let Some(map) = error.as_object_mut() else {
        return error;
    };
    let mut cut = false;
    for (key, max) in [
        ("message", ERROR_MESSAGE_MAX_BYTES),
        ("stack", ERROR_STACK_MAX_BYTES),
        ("stderr", ERROR_STDERR_MAX_BYTES),
    ] {
        let short = map
            .get(key)
            .and_then(Value::as_str)
            .and_then(|t| truncated(t, max));
        if let Some(short) = short {
            map.insert(key.to_owned(), short.into());
            cut = true;
        }
    }
    if let Some(Value::Array(logs)) = map.get_mut("logs") {
        let mut budget = ERROR_LOGS_MAX_BYTES;
        let mut kept = Vec::with_capacity(logs.len());
        let mut dropped = 0usize;
        for line in logs.iter() {
            let text = line
                .as_str()
                .map_or_else(|| line.to_string(), str::to_owned);
            if budget == 0 {
                dropped += 1;
                continue;
            }
            if let Some(short) = truncated(&text, budget) {
                budget = 0;
                kept.push(Value::String(short));
            } else {
                budget -= text.len();
                kept.push(Value::String(text));
            }
        }
        if dropped > 0 {
            kept.push(Value::String(format!("[truncated {dropped} log lines]")));
        }
        if dropped > 0 || kept.iter().zip(logs.iter()).any(|(a, b)| a != b) {
            cut = true;
            *logs = kept;
        }
    }
    if cut {
        map.insert("truncated".to_owned(), true.into());
    }
    error
}

/// [`normalize`] for `Engine::candidate`.
pub(crate) fn normalizer() -> impl FnOnce(&Value) -> Result<Value, RebuildError> + Send + 'static {
    |payload| normalize(payload)
}

/// R8: whether a host call's request asks for `renderedFields` (`rendered: true`, or
/// `expand` naming it), judged from the request params alone.
fn requests_rendered(params: &Value) -> bool {
    crate::ops::jira::comments_rendered(params)
}

/// The class the host recorded for a call's answer: `ok` or `rejected:<class>` (PD-145).
fn outcome_of(result: &HostCallResult) -> String {
    match result {
        HostCallResult::Ok(_) => "ok".to_owned(),
        HostCallResult::Rejected { class, .. } => format!("rejected:{class}"),
    }
}

/// One provenance row, from the host-call request (§2.3 `target_display` of the request params).
fn provenance_row(
    call_id: u64,
    spec: &OperationSpec,
    alias: &str,
    params: &Value,
    outcome: &str,
) -> ProvenanceRow {
    ProvenanceRow {
        call_id,
        op_id: spec.id.to_owned(),
        instance: alias.to_owned(),
        target_display: atlas_duck_registry::target_display(spec, params),
        outcome: outcome.to_owned(),
    }
}

/// The provenance row of a call the end of the run cancelled in flight.
fn cancelled_row(info: &CallInfo) -> ProvenanceRow {
    let target_display = atlas_duck_registry::get(&info.op).map_or_else(
        || info.op.clone(),
        |spec| atlas_duck_registry::target_display(spec, &info.params),
    );
    ProvenanceRow {
        call_id: info.call_id,
        op_id: info.op.clone(),
        instance: info.alias.clone(),
        target_display,
        outcome: "cancelled_in_flight".to_owned(),
    }
}

/// What the preview of a script's release item says about the run's text output beside the
/// candidate: `atlas.log` lines and stderr, within the error candidate's bounds (§9.5, I-3).
#[derive(Debug, Default, Clone)]
pub(crate) struct RunOutput {
    logs: Vec<String>,
    stderr: String,
    cut: bool,
}

/// Said beside logs, stderr or error text that was cut at its size bound.
const OUTPUT_CUT_NOTE: &str =
    "output was cut at its size bound; the audit record keeps the full text";

impl RunOutput {
    /// Read out of an error candidate's `script_error`, as it is: [`bound_error`] already cut it
    /// (cutting again would show wrong truncation markers); anything but strings is dropped.
    fn from_candidate(error: &Value) -> RunOutput {
        RunOutput {
            logs: error
                .get("logs")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            stderr: error
                .get("stderr")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            cut: error.get("truncated") == Some(&Value::Bool(true)),
        }
    }

    /// Read out of the `{logs, stderr}` of a committed `SCRIPT_FINISHED` payload and bounded
    /// like an error candidate; anything but strings is dropped.
    pub(crate) fn from_value(v: &Value) -> RunOutput {
        let logs: Vec<Value> = v
            .get("logs")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|l| l.as_str().map(|s| Value::String(s.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        let stderr = v.get("stderr").and_then(Value::as_str).unwrap_or_default();
        let bounded = bound_error(json!({ "logs": logs, "stderr": stderr }));
        RunOutput {
            logs: bounded
                .get("logs")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            stderr: bounded
                .get("stderr")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            cut: bounded.get("truncated") == Some(&Value::Bool(true)),
        }
    }
}

/// The preview of a script's release item: the candidate view (§6.3 fallback JSON tree), the
/// header of a script (no instance), what only the approver sees (source, provenance, and for
/// an error item its logs and stderr), the host-computed "N host calls returned truncated or
/// lossy data" warning (§9.5) and the R8 Caution. The logs and stderr of a *result* are not in
/// its candidate: [`with_record_output`] adds them from the committed record.
pub(crate) fn preview_model(st: &ScriptState, c: &Candidate) -> PreviewModel {
    let view = ReadView {
        candidate: c.value(),
        byte_size: c.bytes().len() as u64,
        server_total: None,
        more_available: false,
        clamped: false,
        comments_truncated: None,
    };
    let mut m = fallback_preview(&PreviewCtx {
        spec: &SCRIPT_SPEC,
        instance_alias: "",
        params: &Value::Null,
        input: PreviewInput::Read(view),
        field_names: None,
    });
    m.header.class = "script".to_owned();
    if st.rendered_call {
        m.warnings.push(Warning::new(
            WarningId::ScriptRenderedCopies,
            warning::TEXT_SCRIPT_RENDERED_COPIES,
        ));
    }
    if st.lossy_calls > 0 {
        m.warnings.push(Warning::new(
            WarningId::HostCallsLossy,
            warning::host_calls_lossy(st.lossy_calls),
        ));
    }
    // An error item has its logs and stderr in the candidate (redactable with it); a result's
    // are not, and stay empty here.
    let error = c.value().get("script_error");
    let item = if error.is_some() {
        ScriptItemKind::ErrorDetails
    } else {
        ScriptItemKind::Result
    };
    let out = error.map(RunOutput::from_candidate).unwrap_or_default();
    // Completion order is not the order the script made its calls in.
    let mut provenance = st.calls.clone();
    provenance.sort_by_key(|r| r.call_id);
    // T18 review I-3: the §6.4 counts and Cautions cover what the document shows beyond the
    // candidate (an error item's logs and stderr are in the candidate, counted once above).
    let calls = provenance.iter().flat_map(|r| {
        [
            r.op_id.as_str(),
            r.instance.as_str(),
            r.target_display.as_str(),
            r.outcome.as_str(),
        ]
    });
    count_shown_text(&mut m, std::iter::once(st.source.as_str()).chain(calls));
    let view = m.body;
    m.body = PreviewBody::Script {
        item,
        view: Box::new(view),
        source: st.source.clone(),
        provenance,
        logs: out.logs,
        logs_note: out.cut.then(|| OUTPUT_CUT_NOTE.to_owned()),
        stderr: out.stderr,
    };
    m
}

/// A result item's logs and stderr, read from its committed `SCRIPT_FINISHED` record, into the
/// preview `m` of [`preview_model`] (R7: never part of the released bytes), counted for §6.4.
/// An error item keeps the ones its candidate has.
pub(crate) fn with_record_output(m: &mut PreviewModel, out: RunOutput) {
    if !matches!(
        m.body,
        PreviewBody::Script {
            item: ScriptItemKind::Result,
            ..
        }
    ) {
        return;
    }
    count_shown_text(
        m,
        out.logs
            .iter()
            .map(String::as_str)
            .chain([out.stderr.as_str()]),
    );
    if let PreviewBody::Script {
        item: ScriptItemKind::Result,
        logs,
        logs_note,
        stderr,
        ..
    } = &mut m.body
    {
        *logs = out.logs;
        *stderr = out.stderr;
        *logs_note = out.cut.then(|| OUTPUT_CUT_NOTE.to_owned());
    }
}

// ---- submit -------------------------------------------------------------------------------------

/// `submit_script`: the shutdown check, the hello session, admission, `params_sha256`, then
/// everything from the `REQUEST_RECEIVED` commit on in its own task (a pending request is
/// independent of its connection, §4.4).
pub(crate) async fn submit(
    engine: &Arc<Engine>,
    conn: &ConnectionMeta,
    p: SubmitParams,
    sha_out: &mut Option<String>,
) -> Envelope {
    let Some(gate) = engine.enter_submit().await else {
        return GateState::ShuttingDown.envelope();
    };
    let Some(session) = engine.session(&conn.connection_id) else {
        return envelope::protocol_error();
    };
    match engine.blocking(|p| p.admission_check()).await {
        Ok(()) => {}
        Err(AuditError::StorageLow) => return envelope::audit_storage_low(),
        Err(_) => return envelope::audit_failure(audit_failure_retryable(Kind::Script)),
    }
    let agent = AgentKey::new(
        session.normalized.agent_name.as_deref(),
        session.hello.client_kind,
        conn,
    );
    // A dry run has no result to release: it reserves nothing (§5.2 names reads and scripts
    // that wait for a release).
    let live = engine.admission().script_limits();
    let reservation = if peek_dry_run(&p.params) {
        Reservation::none()
    } else {
        Reservation::script(&live)
    };
    let ticket = match engine.admission().admit(agent, reservation) {
        Ok(t) => t,
        Err(busy) => return busy.envelope(),
    };
    let Ok(sha) = params_sha256(SCRIPT_RUN.id, None, &p.params) else {
        return envelope::integer_out_of_range();
    };
    let Ok(request_id) = RequestId::new() else {
        return envelope::internal("no request id could be generated");
    };
    *sha_out = Some(hex::encode(sha));
    let job = Received {
        sha,
        request_id,
        params: p.params,
        reason: p.reason,
        session,
        conn: conn.clone(),
        ticket,
        gate,
        live,
    };
    tokio::spawn(record_and_validate(engine.clone(), job))
        .await
        .unwrap_or_else(|_| envelope::internal("the request task failed"))
}

struct Received {
    sha: [u8; 32],
    request_id: RequestId,
    params: Value,
    reason: Option<String>,
    session: super::Session,
    conn: ConnectionMeta,
    ticket: super::queue::Ticket,
    /// Held until the request is registered (shutdown barrier, review I-1).
    #[allow(dead_code)]
    gate: tokio::sync::OwnedRwLockReadGuard<()>,
    /// The configured limits read once at submit: the reservation was made from them and the
    /// run is validated against them, whatever Settings changes in between.
    live: ScriptLimits,
}

/// The reservation needs the kind before validation: a lenient look at `dry_run`.
fn peek_dry_run(params: &Value) -> bool {
    !matches!(
        params.get("dry_run"),
        None | Some(Value::Null | Value::Bool(false))
    )
}

/// The submit-time shape of a script request (§9.1 step 2).
struct Parsed {
    source: String,
    args: Value,
    limits: ScriptLimits,
    dry: Option<ExampleMode>,
}

fn invalid(param: &str, message: &str) -> ValidationError {
    let mut details = Map::new();
    details.insert("param".into(), param.into());
    ValidationError {
        code: ErrorCode::Validation,
        message: message.to_owned(),
        details,
    }
}

fn parse(params: &Value, ceiling: &ScriptLimits) -> Result<Parsed, ValidationError> {
    let Some(map) = params.as_object() else {
        return Err(invalid("params", "must be an object"));
    };
    if let Some(unknown) = map
        .keys()
        .find(|k| !matches!(k.as_str(), "source" | "args" | "limits" | "dry_run"))
    {
        return Err(invalid(
            &crate::validate::echo(unknown),
            "unknown parameter",
        ));
    }
    let Some(source) = map.get("source").and_then(Value::as_str) else {
        return Err(invalid("source", "is required and must be a string"));
    };
    let args = map.get("args").cloned().unwrap_or_else(|| json!({}));
    let limits_in = map.get("limits").cloned().unwrap_or(Value::Null);
    let limits = validate_script_submit(source, &args, &limits_in, ceiling)?;
    let dry = match map.get("dry_run") {
        None | Some(Value::Null | Value::Bool(false)) => None,
        Some(Value::Bool(true)) => Some(ExampleMode::Full),
        Some(Value::String(s)) if s == "full" => Some(ExampleMode::Full),
        Some(Value::String(s)) if s == "sparse" => Some(ExampleMode::Sparse),
        Some(_) => return Err(invalid("dry_run", "must be true, \"full\" or \"sparse\"")),
    };
    Ok(Parsed {
        source: source.to_owned(),
        args,
        limits,
        dry,
    })
}

/// `submit` from the `REQUEST_RECEIVED` commit to the pending envelope.
async fn record_and_validate(engine: Arc<Engine>, j: Received) -> Envelope {
    let target = script_target_display(&j.params);
    let ctx = EventCtx {
        request_id: Some(j.request_id.0.clone()),
        op_id: Some(SCRIPT_RUN.id.to_owned()),
        op_class: Some("script".to_owned()),
        instance_id: None,
        target: Some(target.clone()),
        actor: Default::default(),
    };
    #[cfg(feature = "testing")]
    if let Some(pause) = engine.hooks().pause_before_received.clone() {
        pause.hold().await;
    }
    let committed = {
        let (ctx, params, hello, conn, reason, set, sha) = (
            ctx,
            j.params.clone(),
            j.session.hello.clone(),
            j.conn.clone(),
            j.reason.clone(),
            engine.committed().clone(),
            j.sha,
        );
        engine
            .blocking(move |port| {
                let ev = payloads::request_received(
                    &ctx,
                    &params,
                    &sha,
                    &hello,
                    &conn,
                    reason.as_deref(),
                );
                commit_request_received(port, &set, ev).map(|_| ctx)
            })
            .await
    };
    let ctx = match committed {
        Ok(ctx) => ctx,
        Err(_) => return envelope::audit_failure(audit_failure_retryable(Kind::Script)),
    };
    #[cfg(feature = "testing")]
    if let Some(pause) = engine.hooks().pause_after_received.clone() {
        pause.hold().await;
    }
    let head = RequestHead {
        request_id: j.request_id.0.clone(),
        op_id: SCRIPT_RUN.id.to_owned(),
        instance: String::new(),
    };
    let (reason, reason_unusual) = match j.reason.as_deref().map(normalize_reason) {
        Some((r, u)) => ((!r.is_empty()).then_some(r), u),
        None => (None, false),
    };
    let reason_excerpt = reason.as_deref().map(excerpt);
    let (connection, peer_chain) = payloads::connection_facts(&j.session.hello, &j.conn);
    let mut new = NewEntry {
        head,
        spec: &SCRIPT_SPEC,
        instance_id: String::new(),
        params_sha256: hex::encode(j.sha),
        target_display: target,
        agent_name: j.session.normalized.agent_name.clone(),
        reason_excerpt,
        reason,
        script_params: Some(j.params.clone()),
        connection,
        peer_chain,
        unusual: j.session.normalized.unusual || reason_unusual,
        session: j.session.key(&j.conn),
        validated: None,
        ctx,
        model: Model::new(Kind::Script),
        unlogged_terminal: None,
        ticket: Some(j.ticket),
    };
    let parsed = match parse(&j.params, &j.live) {
        Ok(p) => p,
        Err(err) => {
            let _ = step(&mut new.model, Event::ValidationFailed);
            return CoreHandler::reject(&engine, new, err).await;
        }
    };
    if parsed.dry.is_some() {
        new.model = Model::new(Kind::DryRun);
    }
    if step(&mut new.model, Event::ValidationPassed).is_err() {
        new.model = Model::new(Kind::Script);
        let _ = step(&mut new.model, Event::ValidationFailed);
        return CoreHandler::reject(&engine, new, internal_error("request state error")).await;
    }
    let entry = engine.insert(new);
    entry.state().script = Some(ScriptState::new(
        parsed.source,
        parsed.args,
        parsed.limits,
        parsed.dry,
    ));
    engine.arm_expiry(&entry);
    dispatch(&engine, &entry);
    envelope::pending_envelope(
        &entry.head.request_id,
        Some(&entry.head.op_id),
        None,
        OpenStatus::Pending,
    )
}

// ---- the run ------------------------------------------------------------------------------------

/// Starts the run of a request that just entered the map in `Validated`. A run task that panics
/// fails its request `internal` (gated like every record-bearing end) and kills the worker,
/// instead of leaving it `Running` with its admission place until expiry.
fn dispatch(engine: &Arc<Engine>, entry: &Arc<RequestEntry>) {
    let (engine, entry) = (engine.clone(), entry.clone());
    let task = tokio::spawn(run(engine.clone(), entry.clone()));
    tokio::spawn(async move {
        if task.await.is_err() {
            let shared = entry.state().script.as_ref().and_then(|s| s.shared.clone());
            if let Some(shared) = shared {
                shared.request_kill(KillReason::Limit("internal".to_owned()));
            }
            let ctx = entry.ctx.clone();
            let _ = engine
                .transition_with(
                    &entry,
                    Event::AuditFailure,
                    move |_| vec![payloads::request_failed(&ctx, ErrorCode::Internal)],
                    OnAuditFailure::FailRequest,
                    |_| {},
                )
                .await;
        }
    });
}

async fn run(engine: Arc<Engine>, entry: Arc<RequestEntry>) {
    let dry = entry.state().script.as_ref().and_then(|s| s.dry);
    match (engine.scripts.clone(), dry) {
        (Some(runner), None) => run_real(&engine, &entry, runner.as_ref()).await,
        (Some(runner), Some(mode)) => run_dry(&engine, &entry, runner.as_ref(), mode).await,
        (None, dry) => no_sandbox(&engine, &entry, dry.is_some()).await,
    }
}

/// A slot of `sem`, or `None` once the request is terminal (cancel, expiry) meanwhile.
async fn slot(
    sem: &Arc<Semaphore>,
    entry: &RequestEntry,
    immediately: bool,
) -> Option<(OwnedSemaphorePermit, bool)> {
    if immediately {
        match sem.clone().try_acquire_owned() {
            Ok(p) => return Some((p, false)),
            Err(TryAcquireError::NoPermits) => {}
            Err(TryAcquireError::Closed) => return None,
        }
    }
    let mut rx = entry.subscribe();
    let ended = async move {
        loop {
            if OpenStatus::of(*rx.borrow_and_update()).is_none() || rx.changed().await.is_err() {
                return;
            }
        }
    };
    tokio::select! {
        permit = sem.clone().acquire_owned() => permit.ok().map(|p| (p, true)),
        () = ended => None,
    }
}

fn limits_of(entry: &RequestEntry) -> (String, Value, ScriptLimits) {
    let st = entry.state();
    st.script.as_ref().map_or_else(
        || (String::new(), Value::Null, ScriptLimits::default()),
        |s| (s.source.clone(), s.args.clone(), s.limits),
    )
}

/// The syntax-error details the record and the envelope carry.
fn syntax_details(e: &CompileError) -> Value {
    json!({ "line": e.line, "column": e.column, "message": e.message })
}

/// A direct failure (§9.5 single rule): `SCRIPT_FAILED {direct: true}` is terminal.
async fn fail_direct(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    event: Event,
    reason: &str,
    queued: bool,
    details: Option<Value>,
) {
    let (ctx, reason) = (entry.ctx.clone(), reason.to_owned());
    let _ = engine
        .transition_with(
            entry,
            event,
            move |_| {
                vec![payloads::script_failed(
                    &ctx,
                    &ScriptFailed {
                        reason: &reason,
                        queued,
                        dispatched: false,
                        direct: true,
                        details: details.as_ref(),
                        candidate: None,
                    },
                )]
            },
            OnAuditFailure::FailRequest,
            |_| {},
        )
        .await;
}

/// No runner in this build (§9.4): scripts are disabled, `failed`, exit 8, `sandbox_unavailable`.
async fn no_sandbox(engine: &Arc<Engine>, entry: &Arc<RequestEntry>, dry: bool) {
    let start = if dry {
        Event::DryRunStarted
    } else {
        Event::CompileStarted
    };
    if engine
        .step_unlogged(entry, start, None, |_| {})
        .await
        .is_err()
    {
        return;
    }
    let end = if dry {
        Event::DryRunEnded { ok: false }
    } else {
        Event::CompileFailed
    };
    fail_direct(engine, entry, end, REASON_SANDBOX_UNAVAILABLE, false, None).await;
}

async fn run_real(engine: &Arc<Engine>, entry: &Arc<RequestEntry>, runner: &dyn ScriptRunner) {
    let (source, args, limits) = limits_of(entry);
    if engine
        .step_unlogged(entry, Event::CompileStarted, None, |_| {})
        .await
        .is_err()
    {
        return;
    }
    // 1. The §3.4 re-check at submit (no slot needed): a failure is direct.
    if let Err(RunnerError::SandboxUnavailable { reason }) =
        runner.check_available(engine.script_policy()).await
    {
        fail_unavailable(engine, entry, Event::CompileFailed, reason).await;
        return;
    }
    // 2. The submit-time compile check, in the dry pool (never a real slot, §9.1 step 2).
    let Some((dry_permit, _)) = slot(&engine.dry_slots, entry, false).await else {
        return;
    };
    let compiled = runner
        .compile_check(&source, &limits, engine.script_policy())
        .await;
    drop(dry_permit);
    match compiled {
        Ok(()) => {}
        Err(CompileFailure::Syntax(e)) => {
            let details = syntax_details(&e);
            fail_direct(
                engine,
                entry,
                Event::CompileFailed,
                REASON_SCRIPT_SYNTAX,
                false,
                Some(details),
            )
            .await;
            return;
        }
        Err(CompileFailure::Unavailable(RunnerError::SandboxUnavailable { reason })) => {
            fail_unavailable(engine, entry, Event::CompileFailed, reason).await;
            return;
        }
        // PD-135: a data-free `script_limit {timeout_s}`, never `script_syntax`.
        Err(CompileFailure::Timeout { .. }) => {
            fail_direct(
                engine,
                entry,
                Event::CompileFailed,
                LIMIT_TIMEOUT_S,
                false,
                None,
            )
            .await;
            return;
        }
    }
    if engine
        .step_unlogged(entry, Event::CompileOk, None, |_| {})
        .await
        .is_err()
    {
        return;
    }
    // 3. A real slot; `queued` = it was not immediately available (§9.5). The run policy is read
    //    here, when the slot is acquired (PD-141), and `confinement` is this slot-time admission;
    //    the spawn below reads it again and may only narrow it.
    let Some((permit, queued)) = slot(&engine.script_slots, entry, true).await else {
        return;
    };
    let policy = engine.script_policy();
    let confinement = runner.confinement(policy).map(|c| c.to_value());
    #[cfg(feature = "testing")]
    if let Some(pause) = engine.hooks.pause_before_script_started.clone() {
        pause.hold().await;
    }
    // 4. `SCRIPT_STARTED` is the record of the slot (§9.1 step 2). The run's shared state is
    //    installed by the step that enters `Running`, under the gate: a cancel or a kill that
    //    comes after finds it, one that came before ended the request and this step is refused.
    let shared = Arc::new(RunShared::default());
    let installed = shared.clone();
    // The slot instant (PD-142): read once, before the step, so the view's `started_at` and the
    // `elapsed_ms` origin are one moment.
    let slot_at = (
        engine.clock().now_utc().to_rfc3339_ms(),
        engine.clock().suspend_aware_elapsed(),
    );
    let (ctx, s, a) = (entry.ctx.clone(), source.clone(), args.clone());
    let started = engine
        .transition_with(
            entry,
            Event::SlotAcquired,
            move |_| {
                vec![payloads::script_started(
                    &ctx,
                    &s,
                    &a,
                    &limits,
                    queued,
                    confinement.as_ref(),
                )]
            },
            OnAuditFailure::FailRequest,
            move |st| {
                if let Some(s) = st.script.as_mut() {
                    s.queued = queued;
                    s.slot = Some(slot_at);
                    s.shared = Some(installed);
                }
            },
        )
        .await;
    if started.is_err() {
        return;
    }
    engine.ui().emit(UiEvent::RunningScriptsChanged);
    // 5. The worker.
    let validator = Arc::new(EngineValidator::new(engine.clone()));
    let backend = Arc::new(LiveBackend::new(
        engine.clone(),
        entry.clone(),
        shared.clone(),
        validator,
        limits,
    ));
    // The policy again, now that `SCRIPT_STARTED` is committed (T15 review I-1): a revocation
    // with a lower seq is in the store's view by now, so no worker spawns degraded after a logged
    // revocation. It only narrows the slot's admission, never widens it.
    let policy = RunPolicy {
        allow_degraded: policy.allow_degraded && engine.script_policy().allow_degraded,
    };
    let spec = RunSpec {
        run_id: entry.head.request_id.clone(),
        source,
        args,
        limits,
        dry_run: false,
        policy,
    };
    let began = Instant::now();
    // The cause of a spawn-time unavailability `start` reported (kept in the record).
    let mut cause = None;
    // A kill asked for before the worker exists (a cancel, a user kill in this window): no
    // worker is started for it.
    let end = if let Some(reason) = shared.kill_reason() {
        shared.mark_ended();
        RunEnd::Killed { reason }
    } else {
        match runner.start(spec, backend).await {
            Ok(handle) => {
                shared.set_handle(handle.clone());
                let end = handle.wait().await;
                shared.mark_ended();
                end
            }
            // §3.4: a spawn-time unavailability counts like a host-measured limit: direct for a
            // run that neither queued nor dispatched, else through release (PD-133).
            Err(RunnerError::SandboxUnavailable { reason }) => {
                shared.mark_ended();
                cause = Some(reason);
                spawn_unavailable(reason)
            }
        }
    };
    drop(permit);
    engine.ui().emit(UiEvent::RunningScriptsChanged);
    let end = Ended {
        end,
        cause,
        queued,
        elapsed: began.elapsed(),
    };
    finish_real(engine, entry, &shared, end, &limits).await;
}

/// `start`'s refusal as the run's end: the `HostLimit` name of the closed set (Δ3).
fn spawn_unavailable(reason: UnavailableReason) -> RunEnd {
    let name = match reason {
        UnavailableReason::AppUpgraded => REASON_APP_UPGRADED,
        _ => REASON_SANDBOX_UNAVAILABLE,
    };
    RunEnd::HostLimit {
        name: name.to_owned(),
    }
}

/// The two spawn-time names of `RunEnd::HostLimit` (Δ3), with the reason the name itself
/// carries; `None` for any other name.
fn unavailable_name(name: &str) -> Option<Option<UnavailableReason>> {
    match name {
        REASON_APP_UPGRADED => Some(Some(UnavailableReason::AppUpgraded)),
        REASON_SANDBOX_UNAVAILABLE => Some(None),
        _ => None,
    }
}

/// `SCRIPT_FAILED.details` of an unavailability: `{reason}` when the cause is known (PD-138; only
/// `app_upgraded` is delivered, `envelope.rs`).
fn unavailable_details(reason: Option<UnavailableReason>) -> Option<Value> {
    reason.map(|r| json!({ "reason": r.as_str() }))
}

/// A direct `sandbox_unavailable` (§3.4, §9.4): `failed`, exit 8, nothing queued or dispatched.
async fn fail_unavailable(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    event: Event,
    reason: UnavailableReason,
) {
    fail_direct(
        engine,
        entry,
        event,
        REASON_SANDBOX_UNAVAILABLE,
        false,
        unavailable_details(Some(reason)),
    )
    .await;
}

/// A real run's end with the host's facts about it.
struct Ended {
    end: RunEnd,
    /// The cause of a spawn-time unavailability `start` answered.
    cause: Option<UnavailableReason>,
    queued: bool,
    elapsed: Duration,
}

/// What the host makes of a run's end (§9.5).
#[allow(clippy::large_enum_variant)] // one value per run, consumed at once
enum Finish {
    /// The cancel or the audit-failure path ended the request.
    Ignore,
    /// A release item with its `SCRIPT_FINISHED` record.
    Item {
        item: ReleaseItem,
        record: NewEvent,
        body: Value,
    },
    /// `SCRIPT_FAILED`: direct, or a release item built from its candidate.
    Failed {
        reason: String,
        direct: bool,
        candidate: Option<Value>,
        /// A limit the host measured or a spawn-time unavailability (the "keep error class only"
        /// preset applies).
        limit: bool,
        /// `SCRIPT_FAILED.details` (`{reason}` of an unavailability).
        details: Option<Value>,
    },
}

fn host_error(class: &str, message: &str, elapsed: Duration) -> Value {
    ScriptErrorDetails {
        class: class.to_owned(),
        message: message.to_owned(),
        stack: String::new(),
        elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        logs: Vec::new(),
        stderr: String::new(),
    }
    .to_value()
}

/// The single place a run's end becomes a release item, a direct failure or nothing (§9.5).
fn classify(ended: Ended, shared: &RunShared, ctx: &EventCtx, limits: &ScriptLimits) -> Finish {
    let Ended {
        end,
        cause,
        queued,
        elapsed,
    } = ended;
    if shared.audit_failed() {
        return Finish::Ignore;
    }
    if matches!(
        shared.kill_reason(),
        Some(KillReason::Client | KillReason::Shutdown | KillReason::AuditFailure)
    ) {
        return Finish::Ignore;
    }
    let dispatched = shared.dispatched();
    let limit = |name: String| -> Finish {
        let direct = !queued && !dispatched;
        let candidate = (!direct)
            .then(|| host_error("script_limit", &format!("limit reached: {name}"), elapsed));
        Finish::Failed {
            reason: name,
            direct,
            candidate,
            limit: true,
            details: None,
        }
    };
    // Δ3: a spawn-time unavailability is `sandbox_unavailable` for a direct and a gated run alike,
    // never the generic limit (which the envelope would deliver as `script_limit`).
    let unavailable = |reason: Option<UnavailableReason>| -> Finish {
        let direct = !queued && !dispatched;
        let message = if reason == Some(UnavailableReason::AppUpgraded) {
            envelope::MSG_APP_UPGRADED
        } else {
            envelope::MSG_SANDBOX_UNAVAILABLE
        };
        let candidate = (!direct).then(|| host_error(REASON_SANDBOX_UNAVAILABLE, message, elapsed));
        Finish::Failed {
            reason: REASON_SANDBOX_UNAVAILABLE.to_owned(),
            direct,
            candidate,
            limit: true,
            details: unavailable_details(reason),
        }
    };
    let failed = |reason: &str, message: &str| Finish::Failed {
        reason: reason.to_owned(),
        direct: false,
        candidate: Some(host_error(reason, message, elapsed)),
        limit: false,
        details: None,
    };
    match end {
        RunEnd::Result {
            value,
            logs,
            stderr,
        } => {
            // `max_result_mb`, and the 16 MiB release cap with the candidate's wrapper (I-3): a
            // result whose candidate could not be released is a limit, not a release item.
            let bound = u64::from(limits.max_result_mb)
                .saturating_mul(MIB)
                .min(RELEASE_CAP_BYTES.saturating_sub(RESULT_WRAPPER_BYTES));
            let too_big = serde_json::to_vec(&value).map_or(u64::MAX, |b| b.len() as u64) > bound;
            if too_big {
                return limit("max_result_mb".to_owned());
            }
            Finish::Item {
                item: ReleaseItem::ScriptResult,
                record: payloads::script_finished_result(ctx, &value, &logs, &stderr),
                body: json!({ "result": value }),
            }
        }
        RunEnd::Error {
            class,
            message,
            stack,
            elapsed_ms,
            logs,
            stderr,
        } => {
            let d = ScriptErrorDetails {
                class,
                message,
                stack,
                elapsed_ms,
                logs,
                stderr,
            };
            Finish::Item {
                item: ReleaseItem::ScriptErrorDetails,
                record: payloads::script_finished_error(ctx, &d),
                body: json!({ "script_error": bound_error(d.to_value()) }),
            }
        }
        RunEnd::HostLimit { name } => match unavailable_name(&name) {
            Some(named) => unavailable(named.or(cause)),
            None => limit(name),
        },
        RunEnd::Killed {
            reason: KillReason::Limit(name),
        } => limit(name),
        RunEnd::Killed {
            reason: KillReason::User,
        } => failed(REASON_KILLED_BY_USER, "the run was killed by the user"),
        RunEnd::Killed {
            reason: KillReason::Client | KillReason::Shutdown | KillReason::AuditFailure,
        } => Finish::Ignore,
        RunEnd::ProtocolViolation => failed(
            REASON_PROTOCOL_VIOLATION,
            "the worker violated the host protocol",
        ),
        RunEnd::Crashed => failed(REASON_WORKER_CRASH, "the worker process died"),
    }
}

async fn finish_real(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    shared: &Arc<RunShared>,
    ended: Ended,
    limits: &ScriptLimits,
) {
    let (dispatched, queued) = (shared.dispatched(), ended.queued);
    match classify(ended, shared, &entry.ctx, limits) {
        Finish::Ignore => {}
        Finish::Item { item, record, body } => {
            commit_item(engine, entry, item, record, body, false, shared).await;
        }
        Finish::Failed {
            reason,
            direct: true,
            details,
            ..
        } => {
            let event = Event::RunEnded {
                direct: true,
                item: ReleaseItem::ScriptErrorDetails,
            };
            fail_direct(engine, entry, event, &reason, queued, details).await;
        }
        Finish::Failed {
            reason,
            candidate,
            limit,
            details,
            ..
        } => {
            let candidate = candidate.unwrap_or(Value::Null);
            let record = payloads::script_failed(
                &entry.ctx,
                &ScriptFailed {
                    reason: &reason,
                    queued,
                    dispatched,
                    direct: false,
                    details: details.as_ref(),
                    candidate: Some(&candidate),
                },
            );
            let body = json!({ "script_error": candidate });
            // §9.5: the data-free limit outcome of a `queued` run pre-selects the preset.
            let preselect = limit && queued && !dispatched;
            commit_item(
                engine,
                entry,
                ReleaseItem::ScriptErrorDetails,
                record,
                body,
                preselect,
                shared,
            )
            .await;
        }
    }
}

/// Records the end of a run that becomes a release item and applies it with its candidate (rev
/// 1), through `transition_with` (an expiry that is due fires right after, under the gate).
async fn commit_item(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    item: ReleaseItem,
    record: NewEvent,
    body: Value,
    preselect: bool,
    shared: &Arc<RunShared>,
) {
    // Building the candidate (serialize, hash, preview) is CPU work.
    let built = tokio::task::spawn_blocking(move || Candidate::from_value(body)).await;
    let candidate = match built {
        // The release cap (§5.2): what cannot be released under it fails closed (I-3).
        Ok(Ok(c)) if c.bytes().len() as u64 <= RELEASE_CAP_BYTES => Arc::new(c),
        _ => {
            let ctx = entry.ctx.clone();
            let _ = engine
                .transition_with(
                    entry,
                    Event::AuditFailure,
                    move |_| vec![payloads::request_failed(&ctx, ErrorCode::Internal)],
                    OnAuditFailure::FailRequest,
                    |_| {},
                )
                .await;
            return;
        }
    };
    let caution = {
        let st = entry.state();
        st.script.as_ref().map_or(0, |s| {
            super::read::caution_count(&preview_model(s, &candidate))
        })
    };
    let (cache, id) = (engine.clone(), entry.head.request_id.clone());
    let (called, in_flight) = (shared.instances(), shared.clone());
    let ctx = entry.ctx.clone();
    // The calls the end of the run recorded as cancelled, for the preview's provenance (PD-145).
    let cancelled = Arc::new(Mutex::new(Vec::new()));
    let (took, cancelled_rows) = (cancelled.clone(), cancelled);
    let applied = engine
        .transition_with(
            entry,
            Event::RunEnded {
                direct: false,
                item,
            },
            // Host calls still in flight when the run ended by itself (timeout, kill, crash,
            // limit) are taken under this gate and recorded before the end (§9.5).
            move |_| {
                let (mut records, calls) =
                    in_flight.in_flight_records_with_calls(&ctx, InFlightReason::RunEnded);
                *lock(&took) = calls;
                records.push(record);
                records
            },
            OnAuditFailure::FailRequest,
            move |st| {
                st.candidate_hash = *candidate.hash();
                st.redaction_ops = Vec::new();
                st.rebuild_failed = false;
                st.caution_count = caution;
                if let Some(s) = st.script.as_mut() {
                    s.item = Some(item);
                    s.preselect_error_class_only = preselect;
                    s.calls
                        .extend(lock(&cancelled_rows).iter().map(cancelled_row));
                    s.instances = called;
                    s.shared = None;
                }
                // §5.1 inv. 6: a fresh candidate has no ops to block it.
                st.model.set_approvable(true);
                cache.candidates().insert(&id, candidate);
            },
        )
        .await;
    if applied.is_ok() {
        let ui = engine.ui();
        ui.emit(UiEvent::QueueChanged {
            request_ids: vec![entry.head.request_id.clone()],
        });
        ui.emit(UiEvent::Attention {
            kind: AttentionKind::New,
            count: 1,
        });
    }
}

// ---- dry runs -----------------------------------------------------------------------------------

async fn run_dry(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    runner: &dyn ScriptRunner,
    mode: ExampleMode,
) {
    let (source, args, limits) = limits_of(entry);
    // The §3.4 re-check at submit, before the dry pool (it needs no slot): a failure is direct.
    if let Err(RunnerError::SandboxUnavailable { reason }) =
        runner.check_available(engine.script_policy()).await
    {
        if engine
            .step_unlogged(entry, Event::DryRunStarted, None, |_| {})
            .await
            .is_ok()
        {
            fail_unavailable(engine, entry, Event::DryRunEnded { ok: false }, reason).await;
        }
        return;
    }
    // The dry pool: a dry run never waits on a real slot (§9.4, §9.5).
    let Some((permit, _)) = slot(&engine.dry_slots, entry, false).await else {
        return;
    };
    // The kill handle exists from the step that enters `DryRunning`: a cancel during the compile
    // check is recorded there and no worker is started for it.
    let shared = Arc::new(RunShared::default());
    let installed = shared.clone();
    if engine
        .step_unlogged(entry, Event::DryRunStarted, None, move |st| {
            if let Some(s) = st.script.as_mut() {
                s.shared = Some(installed);
            }
        })
        .await
        .is_err()
    {
        return;
    }
    let compiled = runner
        .compile_check(&source, &limits, engine.script_policy())
        .await;
    if shared.kill_reason().is_some() {
        // The cancel path ended the request.
        return;
    }
    match compiled {
        Ok(()) => {}
        Err(CompileFailure::Syntax(e)) => {
            let details = syntax_details(&e);
            dry_end(
                engine,
                entry,
                mode,
                &[],
                "script_syntax",
                ("details", &details),
                &[],
                false,
            )
            .await;
            return;
        }
        Err(CompileFailure::Unavailable(RunnerError::SandboxUnavailable { reason })) => {
            shared.mark_ended();
            drop(permit);
            fail_unavailable(engine, entry, Event::DryRunEnded { ok: false }, reason).await;
            return;
        }
        // PD-135: the dry run's own data-free limit outcome, never `script_syntax`.
        Err(CompileFailure::Timeout { .. }) => {
            let d = json!({ "limit": LIMIT_TIMEOUT_S });
            dry_end(
                engine,
                entry,
                mode,
                &[],
                "script_limit",
                ("details", &d),
                &[],
                false,
            )
            .await;
            return;
        }
    }
    let validator = Arc::new(EngineValidator::new(engine.clone()));
    let backend = Arc::new(DryRunBackend::new(mode, validator).with_max_calls(limits.max_calls));
    let spec = RunSpec {
        run_id: entry.head.request_id.clone(),
        source,
        args,
        limits,
        dry_run: true,
        policy: engine.script_policy(),
    };
    let began = Instant::now();
    let end = match runner.start(spec, backend.clone()).await {
        Ok(handle) => {
            shared.set_handle(handle.clone());
            let end = handle.wait().await;
            shared.mark_ended();
            end
        }
        Err(RunnerError::SandboxUnavailable { reason }) => {
            shared.mark_ended();
            drop(permit);
            fail_unavailable(engine, entry, Event::DryRunEnded { ok: false }, reason).await;
            return;
        }
    };
    drop(permit);
    if matches!(
        shared.kill_reason(),
        Some(KillReason::Client | KillReason::Shutdown | KillReason::AuditFailure)
    ) {
        return;
    }
    let calls = backend.calls();
    let elapsed = began.elapsed();
    match end {
        RunEnd::Result {
            value,
            logs,
            stderr: _,
        } => {
            let too_big = serde_json::to_vec(&value).map_or(u64::MAX, |b| b.len() as u64)
                > u64::from(limits.max_result_mb).saturating_mul(MIB);
            if too_big {
                let d = json!({ "limit": "max_result_mb" });
                dry_end(
                    engine,
                    entry,
                    mode,
                    &calls,
                    "script_limit",
                    ("details", &d),
                    &logs,
                    false,
                )
                .await;
            } else {
                dry_end(
                    engine,
                    entry,
                    mode,
                    &calls,
                    "result",
                    ("result", &value),
                    &logs,
                    true,
                )
                .await;
            }
        }
        RunEnd::Error {
            class,
            message,
            stack,
            elapsed_ms,
            logs,
            stderr,
        } => {
            let d = ScriptErrorDetails {
                class,
                message,
                stack,
                elapsed_ms,
                logs: logs.clone(),
                stderr,
            }
            .to_value();
            dry_end(
                engine,
                entry,
                mode,
                &calls,
                "error",
                ("error", &d),
                &logs,
                true,
            )
            .await;
        }
        // Δ3: the spawn found the sandbox unavailable: the direct answer of every dry run.
        RunEnd::HostLimit { name } if unavailable_name(&name).is_some() => {
            fail_direct(
                engine,
                entry,
                Event::DryRunEnded { ok: false },
                REASON_SANDBOX_UNAVAILABLE,
                false,
                unavailable_details(unavailable_name(&name).flatten()),
            )
            .await;
        }
        RunEnd::HostLimit { name }
        | RunEnd::Killed {
            reason: KillReason::Limit(name),
        } => {
            let d = json!({ "limit": name });
            dry_end(
                engine,
                entry,
                mode,
                &calls,
                "script_limit",
                ("details", &d),
                &[],
                false,
            )
            .await;
        }
        RunEnd::Killed { .. } | RunEnd::ProtocolViolation | RunEnd::Crashed => {
            let (class, message) = match end {
                RunEnd::ProtocolViolation => (
                    REASON_PROTOCOL_VIOLATION,
                    "the worker violated the host protocol",
                ),
                _ => (REASON_WORKER_CRASH, "the worker process died"),
            };
            let d = host_error(class, message, elapsed);
            dry_end(
                engine,
                entry,
                mode,
                &calls,
                "error",
                ("error", &d),
                &[],
                true,
            )
            .await;
        }
    }
}

/// `SCRIPT_DRY_RUN` (terminal), then `succeeded` (a result, or an error with
/// `data.script_error`) or `failed` (a compile error or a limit).
#[allow(clippy::too_many_arguments)]
async fn dry_end(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    mode: ExampleMode,
    calls: &[Value],
    outcome: &str,
    body: (&str, &Value),
    logs: &[String],
    ok: bool,
) {
    let record = payloads::script_dry_run(&entry.ctx, mode.as_str(), calls, outcome, body, logs);
    let _ = engine
        .transition_with(
            entry,
            Event::DryRunEnded { ok },
            move |_| vec![record],
            OnAuditFailure::FailRequest,
            |_| {},
        )
        .await;
}

// ---- the cancel path's and the UI's hooks -------------------------------------------------------

impl Engine {
    /// §9.6 kill button: the run becomes a release item (`SCRIPT_FAILED {killed_by_user,
    /// direct: false}`). `NotRunning` = no such live real run; `AlreadyStopping` = a kill reason
    /// was already set or the worker ended and its record is not appended yet (PD-143).
    pub fn kill_script(&self, request_id: &str) -> KillAnswer {
        let Some(entry) = self.entry(request_id) else {
            return KillAnswer::NotRunning;
        };
        // A dry run has no release item to end in: only a real run can be killed by the user. A
        // run is alive while its model is in `Running`: before the slot it is not running, after
        // its end record it is a release item.
        let shared = {
            let st = entry.state();
            if st.model.phase() != Phase::Running {
                return KillAnswer::NotRunning;
            }
            st.script
                .as_ref()
                .filter(|s| s.dry.is_none())
                .and_then(|s| s.shared.clone())
        };
        let Some(shared) = shared else {
            return KillAnswer::NotRunning;
        };
        // In `Running` and not asked: the kill was set already or the worker ended.
        if shared.request_kill(KillReason::User) {
            KillAnswer::Killed
        } else {
            KillAnswer::AlreadyStopping
        }
    }

    /// The run policy (Δ3, PD-141), read immediately before each use and never cached: the
    /// audit-authoritative "Allow scripts with degraded confinement" setting as the store's view
    /// holds it now (L32; off while that view could not be rebuilt from the log).
    pub fn script_policy(&self) -> RunPolicy {
        #[cfg(feature = "testing")]
        if let Some(flag) = &self.hooks.allow_degraded_scripts {
            return RunPolicy {
                allow_degraded: flag.load(std::sync::atomic::Ordering::SeqCst),
            };
        }
        RunPolicy {
            allow_degraded: self.port().settings().allow_degraded_scripts,
        }
    }
}

/// Task 25 handoff: a script candidate that called `instance_id` is invalidated when its PAT or
/// origin changed (§7.1): a new revision, which must be opened again before it can be released.
pub(crate) async fn on_instance_changed(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    instance_id: &str,
) {
    let called = {
        let st = entry.state();
        matches!(st.model.phase(), Phase::AwaitingRelease(_))
            && st
                .script
                .as_ref()
                .is_some_and(|s| s.instances.contains(instance_id))
    };
    if !called {
        return;
    }
    let applied = engine
        .step_unlogged(entry, Event::CandidateChanged, None, |st| {
            if !st.rebuild_failed {
                st.model.set_approvable(true);
            }
        })
        .await;
    if applied.is_ok() {
        engine.ui().emit(UiEvent::QueueChanged {
            request_ids: vec![entry.head.request_id.clone()],
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(call_id: u64, outcome: &str) -> ProvenanceRow {
        ProvenanceRow {
            call_id,
            op_id: "jira.issue.get".to_owned(),
            instance: "jira-main".to_owned(),
            target_display: "ABC-1".to_owned(),
            outcome: outcome.to_owned(),
        }
    }

    /// T17 review M-2: rows land in completion order (and cancelled ones at the end of the run);
    /// the preview lists them by `call_id`.
    #[test]
    fn preview_provenance_is_ordered_by_call_id() -> Result<(), String> {
        let mut st = ScriptState::new(String::new(), Value::Null, ScriptLimits::default(), None);
        st.calls = vec![row(3, "ok"), row(1, "cancelled_in_flight"), row(2, "ok")];
        let c = Candidate::from_value(json!({ "result": 1 })).map_err(|e| e.to_string())?;
        let PreviewBody::Script { provenance, .. } = preview_model(&st, &c).body else {
            return Err("not a script body".to_owned());
        };
        let ids: Vec<u64> = provenance.iter().map(|r| r.call_id).collect();
        assert_eq!(ids, [1, 2, 3]);
        Ok(())
    }
}
