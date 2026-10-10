//! The write flow (§5.4 steps 2–6, Task 22): from `Validated` through enrichment to the approval
//! queue, then (after a committed `WRITE_APPROVED`) the identity call, the op's stale rule and the
//! one approved request, ending in `WRITE_EXECUTED` / `WRITE_FAILED` / `WRITE_OUTCOME_UNKNOWN`
//! or a return to the queue (`WRITE_STALE`). This is the only path that mutates Atlassian data.
//!
//! 1. **Enrich** (`EnrichStarted`): every GET of the op's `EnrichRule::plan` runs under the
//!    request's cover and is recorded as `PREVIEW_FETCH` (each one, before the next GET or with
//!    the event it decides). [`enrich_effect`] is the one place that maps an enrichment GET to
//!    the §5.4 step 2 table: usable 2xx JSON, an "enrichment failed" hold (upstream error or a
//!    post-send failure, gated: Approve disabled, the agent sees `pending`), or a data-free
//!    direct `REQUEST_FAILED`. A refresh (§5.4 step 5) maps every GET with [`recheck`] instead:
//!    anything but a parsed 2xx JSON returns the write to its previous hold (`recheck_failed`).
//! 2. **Render**: the executor turns the params and a `Preview` verdict into the exact request
//!    list (§5.1 inv. 3); the revision's `candidate_hash` is `request_set_hash` of that list.
//!    Approvability comes only from the latest `Enriched` verdict, the model's hold and the
//!    instance state ([`approvable`]; T12 I-1a), never from the phase alone.
//! 3. **Decide** (`decision`): approve commits `WRITE_APPROVED` (the hashed list itself) before
//!    anything is sent; edit commits `WRITE_EDITED` and re-renders or re-enriches; deny commits
//!    `WRITE_DENIED` with an optional hint the current hold allows.
//! 4. **Stale check** (spawned once `WRITE_APPROVED` is committed): the identity call, then the
//!    op's stale rule; a change or a failed re-check returns the write to the queue
//!    (`WRITE_STALE`), a change with a refresh started in the same critical section (T12 I-1b).
//! 5. **Execute**: the list is re-hashed and checked against the committed approval, then sent
//!    exactly (`send_approved_ctl`); [`settle_execution`] maps every `WriteOutcome`. A write that
//!    may have reached the server is never retried (§5.4 step 6).
//!
//! Opacity (§4.5): nothing here reaches an envelope before a decision; `executing` is the model's
//! once `StalePassed` applied and stays until terminal (also across a version-conflict return).

use std::fmt;
use std::sync::Arc;

use atlas_duck_atlassian::{
    ApprovedWrite, BodyFailure, ExpectedBody, FetchControl, FetchFailure, FetchOutcome, GetCall,
    HttpRequestSpec, NormalizedBaseUrl, NotSentReason, PostSendKind, StoredIdentity,
    SuccessExpectation, UnavailableReason, UnknownReason, UpstreamResponse, WriteOutcome,
    build_url,
};
use atlas_duck_audit::request_set::requests_to_json;
use atlas_duck_audit::{NewEvent, RequestRecord, request_set_hash};
use atlas_duck_ipc::envelope::ErrorCode;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_preview::{Level, OutcomeKind as CardKind};
use atlas_duck_registry::{OperationSpec, Product, StatusSet, SuccessBody};
use serde_json::{Map, Value, json};

use super::envelope::MSG_IDENTITY_HEADER;
use super::read::{
    MSG_IDENTITY, MSG_NEEDS_TOKEN, class_name, connection_message, error_text, unavailable_message,
    unavailable_name,
};
use super::{
    Engine, EntryState, InFlight, InstanceHttp, OnAuditFailure, RequestEntry, TransitionError,
};
use crate::edit::EditedKeys;
use crate::gate::{AttentionKind, UiEvent};
use crate::identity::{self, Lost};
use crate::instances::InstanceState;
use crate::instances::admin::shown;
use crate::lifecycle::model::{
    Applied, Event, ExecOutcome, Hold, InstanceEvt, Model, Phase, Rejection, StaleReason,
    is_pending, step,
};
use crate::ops::generic::write_preview;
use crate::ops::{
    EnrichCtx, EnrichFailure, EnrichPurpose, EnrichVerdict, ExecCtx, ExecError, ExecPlan,
    PreviewCtx, PreviewInput, PreviewModel, StaleCtx, StaleVerdict, WriteView, op_table,
};
use crate::payloads::{
    self, EventCtx, FetchRecord, OutcomeKind, PreviewFetchPurpose, WriteFailure, WriteStaleReason,
};
use crate::proxy::ResolvedProxy;

/// §5.4 step 2 (verbatim): the deny reason the approvals UI pre-fills for a conflict (M6).
pub const CONFLICT_DENY_PREFILL: &str = "target changed since you read it; re-read and resubmit";

/// Plan wording: the fixed messages of the post-send enrichment outcome hints (§5.4 step 2: "a
/// fixed app-generated message and no size").
pub const HINT_ENRICH_NETWORK: &str = "the server's answer to an enrichment request was not received in full (timeout or network error)";
pub const HINT_ENRICH_UNPARSABLE: &str =
    "the server's answer to an enrichment request could not be read as JSON";
pub const HINT_ENRICH_TOO_LARGE: &str =
    "the server's answer to an enrichment request exceeded the size limit";

/// Plan wording: the messages of a write's terminal failures (§4.3, §11.2).
const MSG_WRITE_REFUSED: &str = "the Atlassian server refused the write";
const MSG_WRITE_REDIRECT: &str = "the server answered the write with a redirect";
const MSG_WRITE_NON_JSON_401: &str = "the server answered the write with 401 without JSON";
const MSG_WRITE_INTERNAL: &str = "the write could not be sent";
/// Plan wording: a direct enrichment failure that is a bug, not data.
const MSG_PREPARE_INTERNAL: &str = "the write could not be prepared";
const MSG_PREPARE_ABORTED: &str = "the write's preparation was aborted";
/// Shown when the executor cannot build the request from a `Preview` verdict (fail closed).
const TEXT_UNRENDERABLE: &str = "the request could not be built from the server's answers";

// ---- state ---------------------------------------------------------------------------------------

/// What a deny may attach for a failed enrichment fetch (§5.4 step 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureHint {
    /// An upstream error: `upstream_http` with the status and the (optional) messages.
    UpstreamHttp,
    /// A post-send outcome: `upstream_network`, `upstream_unavailable` or `result_too_large`.
    Outcome(ErrorCode),
    /// Nothing the agent may be told (an answer of the wrong shape, a request that could not be
    /// built).
    None,
}

/// The enrichment fetch behind an `EnrichmentError` hold: the card and the attachable hint.
#[derive(Clone, PartialEq)]
pub struct Failure {
    pub card: EnrichFailure,
    pub hint: FailureHint,
}

impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Failure")
            .field("card", &self.card)
            .field("hint", &self.hint)
            .finish()
    }
}

/// The §4.2 delivery view of an edited write: names and the agent's own keys only.
#[derive(Clone, PartialEq)]
pub struct EditView {
    pub executed_params: Value,
    pub edited_keys: EditedKeys,
}

/// Why a write came back to the queue: the re-review leads with it (§5.4 step 5).
#[derive(Clone, PartialEq)]
pub enum Returned {
    /// The stale rule's baseline delta (display-escaped).
    Changed(String),
    RecheckFailed,
    /// `class` for the identity-header states (§7.2 *Header lost*).
    IdentityMismatch(Option<String>),
    VersionConflict,
    Instance(InstanceEvt),
    /// `instance_changed` with the old and new origin (§7.1 "instance URL changed: <old> → <new>").
    InstanceUrl {
        old: String,
        new: String,
    },
    /// `user_renamed` (§7.1 *Username rename*): "Atlassian username changed: <old> → <new>".
    UserRenamed {
        old: String,
        new: String,
    },
}

/// A write's state beside its model (Task 22). Nothing here reaches an agent before a decision.
#[derive(Clone)]
pub struct WriteState {
    /// The params that run: the agent's, then the human's edits (§5.4 step 4). Never the
    /// delivery view (`EditView::executed_params`) and never enrichment output (T15 handoff).
    pub params: Value,
    /// The latest `Enriched` verdict (§5.1 inv. 6: approvability comes only from it).
    pub verdict: EnrichVerdict,
    /// The failed fetch behind an `EnrichmentError` hold, if one failed.
    pub failure: Option<Failure>,
    /// The current revision's exact request list (empty unless the verdict is `Preview`).
    pub requests: Vec<HttpRequestSpec>,
    /// Set once the human edited the write (decision column `approve_edited`, PD-20).
    pub edit: Option<EditView>,
    /// The `request_set_hash` the latest committed `WRITE_APPROVED` names.
    pub approved_hash: Option<[u8; 32]>,
    pub returned: Option<Returned>,
    /// `instance_changed`: the write waits for the instance's new PAT, then
    /// [`Engine::start_refresh`] (Task 25); its approvability stays false until the refresh's
    /// `Enriched`, whatever the instance state does meanwhile.
    pub awaiting_refresh: bool,
}

/// Kinds and counts only (§7.7): params, bodies and verdict values can be Atlassian data.
impl fmt::Debug for WriteState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteState")
            .field("verdict", &self.verdict)
            .field("failure", &self.failure)
            .field("requests", &self.requests.len())
            .field("edited", &self.edit.is_some())
            .field("approved", &self.approved_hash.is_some())
            .finish_non_exhaustive()
    }
}

impl WriteState {
    fn new(params: Value) -> WriteState {
        WriteState {
            params,
            verdict: EnrichVerdict::unusable(),
            failure: None,
            requests: Vec::new(),
            edit: None,
            approved_hash: None,
            returned: None,
            awaiting_refresh: false,
        }
    }
}

/// §5.1 inv. 6 for a write: the queue hold is `Preview`, the latest `Enriched` verdict is
/// `Preview` with a rendered list, and the instance has a usable PAT (`identity`; Task 26 adds
/// the identity-matched part). The model's own `Approve` check is the second line (T12 I-1a).
pub(crate) fn approvable(st: &EntryState, pat: bool) -> bool {
    pat && st.model.phase() == Phase::AwaitingApproval(Hold::Preview)
        && st
            .write
            .as_ref()
            .is_some_and(|w| w.verdict.hold == Hold::Preview && !w.requests.is_empty())
}

/// The `RequestRecord`s `WRITE_APPROVED` stores and hashes (§5.4 step 4).
pub fn records(requests: &[HttpRequestSpec]) -> Vec<RequestRecord> {
    requests
        .iter()
        .map(|r| RequestRecord {
            index: r.index,
            method: r.method.clone(),
            resolved_url: r.resolved_url.clone(),
            content_type: r.content_type.clone(),
            body_bytes: r.body.clone(),
        })
        .collect()
}

/// The revision's candidate hash: `request_set_hash` of its list (§5.1 inv. 3).
pub fn list_hash(requests: &[HttpRequestSpec]) -> [u8; 32] {
    request_set_hash(&records(requests))
}

/// Plan decision: the Raw tab of a write shows the request list exactly as `WRITE_APPROVED`
/// stores it (`requests_to_json`: index, method, URL, content type, base64 body).
pub fn raw_bytes(requests: &[HttpRequestSpec]) -> Vec<u8> {
    serde_json::to_vec(&requests_to_json(&records(requests))).unwrap_or_default()
}

/// The registry's declared success (§7.2) as the client takes it.
fn expectation(spec: &OperationSpec) -> SuccessExpectation {
    SuccessExpectation {
        statuses: match spec.success.statuses {
            StatusSet::Any2xx => None,
            StatusSet::Exactly(s) => Some(s.to_vec()),
        },
        body: match spec.success.body {
            SuccessBody::Json => ExpectedBody::Json,
            SuccessBody::Empty => ExpectedBody::Empty,
        },
    }
}

/// The exact request list for `params` and a `Preview` verdict (§5.1 inv. 3). The executor sees
/// the verdict only when it is `Preview` (T18 as built).
pub(crate) fn render(
    spec: &'static OperationSpec,
    base: &NormalizedBaseUrl,
    params: &Value,
    verdict: Option<&EnrichVerdict>,
    effective_max: Option<u32>,
) -> Result<Vec<HttpRequestSpec>, ExecError> {
    let op = op_table().get(spec.id).ok_or(ExecError::NotInThisBuild)?;
    let enrichment = verdict.filter(|v| v.hold == Hold::Preview);
    match (op.executor)(&ExecCtx {
        spec,
        params,
        base,
        enrichment,
        effective_max,
    })? {
        ExecPlan::Write(requests) => Ok(requests),
        ExecPlan::Read(_) => Err(ExecError::NotInThisBuild),
    }
}

// ---- previews -------------------------------------------------------------------------------------

/// The warning the re-review leads with (§5.4 step 5: "the re-review leads with the baseline
/// delta"; §6.2 texts).
fn returned_warning(r: &Returned, executes_as: Option<&str>) -> Option<Warning> {
    Some(match r {
        Returned::Changed(delta) if delta.is_empty() => Warning::new(
            WarningId::ChangedSinceReview,
            warning::TEXT_CHANGED_SINCE_REVIEW,
        ),
        Returned::Changed(delta) => Warning::new(
            WarningId::ChangedSinceReview,
            format!("{}: {delta}", warning::TEXT_CHANGED_SINCE_REVIEW),
        ),
        Returned::RecheckFailed => {
            Warning::new(WarningId::CouldNotRecheck, warning::TEXT_COULD_NOT_RECHECK)
        }
        Returned::IdentityMismatch(Some(_)) => Warning::new(
            WarningId::IdentityHeaderLost,
            warning::TEXT_IDENTITY_HEADER_LOST,
        ),
        Returned::IdentityMismatch(None) => Warning::new(
            WarningId::TokenIdentityMismatch,
            warning::token_no_longer_resolves(executes_as.unwrap_or_default()),
        ),
        Returned::Instance(InstanceEvt::CredentialChanged) => Warning::new(
            WarningId::TokenChanged,
            warning::token_changed(executes_as.unwrap_or_default()),
        ),
        // The conflict card speaks for itself; Tasks 25/26 bring the URL and rename texts.
        Returned::InstanceUrl { old, new } => Warning::new(
            WarningId::InstanceUrlChanged,
            warning::instance_url_changed(old, new),
        ),
        // Server-supplied names reach the approver escaped and capped (review I-3).
        Returned::UserRenamed { old, new } => Warning::new(
            WarningId::UserRenamed,
            warning::user_renamed(&shown(old), &shown(new)),
        ),
        Returned::VersionConflict
        | Returned::Instance(InstanceEvt::InstanceChanged | InstanceEvt::UserRenamed) => {
            return None;
        }
    })
}

/// §7.2 *Header lost*: a pending write of an instance in an identity-header state shows the
/// admin hint as a Caution (Approve is disabled by the instance state, §5.1 inv. 6), whether or
/// not the write was ever returned for it.
pub(crate) fn instance_warning(engine: &Engine, instance_id: &str) -> Option<Warning> {
    let state = engine.instances().by_id(instance_id).map(|i| i.state)?;
    matches!(
        state,
        InstanceState::IdentityHeaderMissing | InstanceState::IdentityHeaderMismatch
    )
    .then(|| {
        Warning::new(
            WarningId::IdentityHeaderLost,
            warning::TEXT_IDENTITY_HEADER_LOST,
        )
    })
}

/// The preview model of a write in `hold`: the op's previewer over the request list (or the
/// hold's card), led by the reason it came back, "executes as" filled in (§5.6).
pub(crate) fn preview_model(
    spec: &'static OperationSpec,
    alias: &str,
    w: &WriteState,
    hold: Hold,
    executes_as: Option<&str>,
) -> PreviewModel {
    // The name comes from the server (a connection test, a rename): escaped for display (I-3).
    let executes_as = executes_as.map(shown);
    let executes_as = executes_as.as_deref();
    let previewer = op_table()
        .get(spec.id)
        .map_or(write_preview as crate::ops::PreviewerFn, |o| o.previewer);
    let mut model = previewer(&PreviewCtx {
        spec,
        instance_alias: alias,
        params: &w.params,
        input: PreviewInput::Write(WriteView {
            requests: &w.requests,
            hold,
            enrichment: Some(&w.verdict),
            failure: w.failure.as_ref().map(|f| &f.card),
        }),
    });
    if let Some(lead) = w
        .returned
        .as_ref()
        .and_then(|r| returned_warning(r, executes_as))
    {
        model.warnings.insert(0, lead);
    }
    model.header.executes_as = executes_as.map(str::to_owned);
    model
}

/// The queue row's "caution (N)" of the current revision (§5.6).
fn refresh_caution(st: &mut EntryState, spec: &'static OperationSpec, alias: &str) {
    let (Phase::AwaitingApproval(hold), Some(w)) = (st.model.phase(), st.write.as_ref()) else {
        return;
    };
    let n = preview_model(spec, alias, w, hold, None)
        .warnings
        .iter()
        .filter(|w| w.level == Level::Caution)
        .count();
    st.caution_count = u32::try_from(n).unwrap_or(u32::MAX);
}

/// The instance's stored identity, if it has a usable PAT (§5.1 inv. 6; Task 26 adds the
/// identity-matched part). The keychain read runs off the async runtime.
pub(crate) async fn stored_identity(
    engine: &Engine,
    entry: &RequestEntry,
) -> Option<StoredIdentity> {
    if !instance_ok(engine, &entry.instance_id) {
        return None;
    }
    let (creds, id) = (engine.credentials().clone(), entry.instance_id.clone());
    tokio::task::spawn_blocking(move || creds.load(&id))
        .await
        .ok()
        .and_then(Result::ok)
        .flatten()
        .map(|c| c.identity)
}

/// The in-memory half of "a usable PAT": the instance's state. Read again inside the critical
/// sections that set approvability (review M-11), so an instance-state change between the
/// keychain read and the apply is seen. Lock order: an entry's state lock, then the instance
/// table's read lock; never take an entry's state lock while holding the table's write lock
/// (Task 25).
fn instance_ok(engine: &Engine, instance_id: &str) -> bool {
    engine
        .instances()
        .by_id(instance_id)
        .is_some_and(|i| i.state == InstanceState::Ok)
}

/// Approvability inside an apply: the stored credential read before (`credential`) and the
/// instance state now.
fn pat_now(engine: &Engine, instance_id: &str, credential: bool) -> bool {
    credential && instance_ok(engine, instance_id)
}

// ---- engine plumbing -----------------------------------------------------------------------------

/// Why a queued write is refreshed (§5.4 step 5, §7.1): Tasks 25–26 call [`Engine::refresh_write`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshCause {
    /// A stale-check return (from `StaleCheck`); only `Changed` is refreshed.
    Stale(StaleReason),
    /// `credential_changed`, `instance_changed` (refreshed when the new PAT is stored, Task 25:
    /// [`Engine::start_refresh`]) or `user_renamed`.
    Instance(InstanceEvt),
}

fn stale_reason(r: StaleReason) -> WriteStaleReason {
    match r {
        StaleReason::Changed => WriteStaleReason::Changed,
        StaleReason::RecheckFailed => WriteStaleReason::RecheckFailed,
        StaleReason::IdentityMismatch => WriteStaleReason::IdentityMismatch,
    }
}

fn instance_reason(e: InstanceEvt) -> WriteStaleReason {
    match e {
        InstanceEvt::CredentialChanged => WriteStaleReason::CredentialChanged,
        InstanceEvt::InstanceChanged => WriteStaleReason::InstanceChanged,
        InstanceEvt::UserRenamed => WriteStaleReason::UserRenamed,
    }
}

/// One approval of a write (review I-1): the stale-check and execute task it spawned acts only
/// while this approval is current, i.e. the model is still at the approved revision and in
/// `StaleCheck`/`Executing`. Any return to the queue bumps the revision, so a superseded task
/// can neither pass, fail nor execute a later approval, nor end a refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Approval {
    rev: u64,
}

impl Approval {
    /// The approval of revision `rev` (the `Approve {rev}` that committed `WRITE_APPROVED`).
    pub(crate) fn of(rev: u64) -> Approval {
        Approval { rev }
    }

    fn current(self, m: &Model) -> bool {
        m.rev() == self.rev && matches!(m.phase(), Phase::StaleCheck | Phase::Executing)
    }
}

/// The guard of a transition made by a task bound to `approval` (`None`: not bound).
fn bound(approval: Option<Approval>) -> impl Fn(&Model) -> bool + Send + 'static {
    move |m: &Model| approval.is_none_or(|a| a.current(m))
}

impl Engine {
    /// Appends records of a request that is still pending (and, for a task bound to an
    /// approval, while that approval is current), under its transition gate: a request a
    /// cancel, expiry or later approval superseded gets nothing more. An append failure fails
    /// the request (§11.1). `false` = nothing appended and the flow stops.
    pub(crate) async fn append_pending(
        self: &Arc<Self>,
        entry: &Arc<RequestEntry>,
        mut evs: Vec<NewEvent>,
        approval: Option<Approval>,
    ) -> bool {
        let _gate = entry.gate.clone().lock_owned().await;
        {
            let st = entry.state();
            if !is_pending(st.model.phase()) || !bound(approval)(&st.model) {
                return false;
            }
        }
        let appended = if evs.len() == 1 {
            match evs.pop() {
                Some(ev) => self.blocking(move |p| p.append(ev).map(|_| ())).await,
                None => Ok(()),
            }
        } else {
            self.blocking(move |p| p.append_batch(evs).map(|_| ()))
                .await
        };
        if appended.is_err() {
            self.fail_unlogged(entry);
            return false;
        }
        entry.take_parked();
        true
    }

    /// Tasks 25–26 (T12 I-1b): logs `WRITE_STALE {reason}` and steps the matching event; a
    /// `Changed`, `credential_changed` or `user_renamed` return starts the refresh
    /// (`EnrichStarted`, `PREVIEW_FETCH {purpose: refresh}`) in the same entry critical section,
    /// so no decision can interleave. `instance_changed` does not refresh: the write stays not
    /// approvable (§5.1 inv. 6) until Task 25 stores the new PAT and calls
    /// [`Engine::start_refresh`]. From `StaleCheck` the running stale check is superseded (its
    /// GET cancelled; it applies nothing more, review I-1).
    pub async fn refresh_write(
        self: &Arc<Self>,
        entry: &Arc<RequestEntry>,
        cause: RefreshCause,
    ) -> Result<Applied, TransitionError> {
        self.refresh_write_returned(entry, cause, None).await
    }

    /// `refresh_write` with the lead warning of the re-review replaced (an `instance_changed`
    /// return names the old and new URL).
    pub(crate) async fn refresh_write_returned(
        self: &Arc<Self>,
        entry: &Arc<RequestEntry>,
        cause: RefreshCause,
        lead: Option<Returned>,
    ) -> Result<Applied, TransitionError> {
        let ctx = entry.ctx.clone();
        let (event, reason, refresh, returned) = match cause {
            RefreshCause::Stale(r) => (
                Event::Stale(r),
                stale_reason(r),
                r == StaleReason::Changed,
                match r {
                    StaleReason::Changed => Returned::Changed(String::new()),
                    StaleReason::RecheckFailed => Returned::RecheckFailed,
                    StaleReason::IdentityMismatch => Returned::IdentityMismatch(None),
                },
            ),
            RefreshCause::Instance(e) => (
                Event::Instance(e),
                instance_reason(e),
                e != InstanceEvt::InstanceChanged,
                lead.unwrap_or(Returned::Instance(e)),
            ),
        };
        let record = payloads::write_stale(&ctx, reason, None);
        stale_return(self, entry, event, vec![record], returned, refresh, None).await
    }

    /// Task 25 (T12 I-1b): the deferred refresh of a queued write, e.g. an `instance_changed`
    /// write once the instance's new PAT is stored: `EnrichStarted` from `AwaitingApproval` in
    /// one gated section (approvable stays false until the refresh's `Enriched`), then the
    /// refresh GETs (`PREVIEW_FETCH {purpose: refresh}`) under the new PAT and base URL.
    /// `Illegal` for a write that is not in the queue.
    pub async fn start_refresh(
        self: &Arc<Self>,
        entry: &Arc<RequestEntry>,
    ) -> Result<Applied, Rejection> {
        let applied = {
            let _gate = entry.gate.clone().lock_owned().await;
            let applied = {
                let mut st = entry.state();
                match st.model.phase() {
                    Phase::AwaitingApproval(_) => {
                        let applied = step(&mut st.model, Event::EnrichStarted);
                        st.model.set_approvable(false);
                        if let Some(w) = st.write.as_mut() {
                            w.awaiting_refresh = false;
                        }
                        applied
                    }
                    _ => Err(Rejection::Illegal),
                }
            };
            self.after_change(entry);
            applied
        }?;
        if let Some(c) = entry.fetch_control() {
            c.cancel();
        }
        entry.set_fetch_control(None);
        queue_changed(self, entry);
        spawn_guarded(self, entry, None, enrich_task);
        Ok(applied)
    }
}

/// An instance change that met a write in `Enriching` (M-5): the kind only in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub enum PendingChange {
    Credential,
    Origin { old: String, new: String },
}

impl fmt::Debug for PendingChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Credential => "PendingChange::Credential",
            Self::Origin { .. } => "PendingChange::Origin",
        })
    }
}

/// What happened to an instance that its queued writes follow (Task 25, §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstanceChange {
    /// A PAT of another user replaced the stored one: `credential_changed`.
    TokenReplaced,
    /// The base URL changed and the PAT was deleted: `instance_changed`.
    OriginChanged { old: String, new: String },
    /// A PAT was stored (a first one, or the same user's again): writes waiting for it refresh,
    /// the others re-read their approvability against the instance state.
    TokenStored,
    /// Task 26: a re-check moved the instance to `needs_token` or an identity-header state: its
    /// queued writes re-read their approvability.
    StateChanged,
    /// Task 26: the Atlassian username changed under the same key (§7.1): every queued write is
    /// refreshed (`WRITE_STALE {user_renamed}`), without a native confirmation.
    UserRenamed { old: String, new: String },
}

impl Engine {
    /// Task 25: carries an instance's credential or origin change to its queued writes (§7.1).
    /// A write in `AwaitingApproval` or `StaleCheck` returns with `WRITE_STALE` and refreshes
    /// (`credential_changed`), or waits for the new PAT (`instance_changed`); a write parked that
    /// way refreshes once a PAT is stored. A write in `Enriching` is not handled here (M-5, see
    /// the as-built note of Task 25). Call it after the instance table was swapped: it reads the
    /// instance state inside each entry's critical section (lock order: entry, then the table).
    pub(crate) async fn instance_changed(
        self: &Arc<Self>,
        instance_id: &str,
        change: InstanceChange,
    ) {
        for entry in self.pending_entries() {
            if entry.instance_id != instance_id {
                continue;
            }
            let (phase, parked, identity_return) = match route_change(&mut entry.state(), &change) {
                Routed::Skip | Routed::Deferred => continue,
                Routed::Go {
                    phase,
                    parked,
                    identity_return,
                } => (phase, parked, identity_return),
            };
            let queued = matches!(phase, Phase::AwaitingApproval(_) | Phase::StaleCheck);
            let waiting = parked && matches!(phase, Phase::AwaitingApproval(_));
            match &change {
                InstanceChange::TokenReplaced | InstanceChange::TokenStored if waiting => {
                    let _ = self.start_refresh(&entry).await;
                }
                // Task 26: the identity is restored: a write held in `IdentityMismatch` is
                // refreshed like a credential change (the hold stays until the refresh's
                // `Enriched`).
                InstanceChange::TokenStored
                    if phase == Phase::AwaitingApproval(Hold::IdentityMismatch) =>
                {
                    let _ = self
                        .refresh_write(
                            &entry,
                            RefreshCause::Instance(InstanceEvt::CredentialChanged),
                        )
                        .await;
                }
                InstanceChange::UserRenamed { old, new }
                    if matches!(phase, Phase::AwaitingApproval(_)) && !parked =>
                {
                    let lead = Returned::UserRenamed {
                        old: old.clone(),
                        new: new.clone(),
                    };
                    let _ = self
                        .refresh_write_returned(
                            &entry,
                            RefreshCause::Instance(InstanceEvt::UserRenamed),
                            Some(lead),
                        )
                        .await;
                }
                InstanceChange::TokenReplaced if queued => {
                    let _ = self
                        .refresh_write(
                            &entry,
                            RefreshCause::Instance(InstanceEvt::CredentialChanged),
                        )
                        .await;
                }
                InstanceChange::OriginChanged { old, new } if queued => {
                    let lead = Returned::InstanceUrl {
                        old: old.clone(),
                        new: new.clone(),
                    };
                    let _ = self
                        .refresh_write_returned(
                            &entry,
                            RefreshCause::Instance(InstanceEvt::InstanceChanged),
                            Some(lead),
                        )
                        .await;
                }
                InstanceChange::TokenStored | InstanceChange::StateChanged
                    if matches!(phase, Phase::AwaitingApproval(_)) && !identity_return =>
                {
                    let credential = stored_identity(self, &entry).await.is_some();
                    let _gate = entry.gate.clone().lock_owned().await;
                    {
                        let mut st = entry.state();
                        let parked_now = st.write.as_ref().is_some_and(|w| w.awaiting_refresh);
                        if matches!(st.model.phase(), Phase::AwaitingApproval(_)) && !parked_now {
                            let ok = approvable(&st, pat_now(self, instance_id, credential));
                            st.model.set_approvable(ok);
                        }
                    }
                    self.after_change(&entry);
                    queue_changed(self, &entry);
                }
                _ => {}
            }
        }
    }
}

/// What `Engine::instance_changed` does with one entry (review I-3).
#[derive(Debug, PartialEq, Eq)]
enum Routed {
    /// Not a write.
    Skip,
    /// The write is in `Enriching`: the change is recorded for the verdict to follow (M-5).
    Deferred,
    /// The write is not in `Enriching`: route by this phase.
    Go {
        phase: Phase,
        parked: bool,
        identity_return: bool,
    },
}

/// Reads the phase and decides on it in ONE critical section of the entry (review I-3). The
/// verdict of an enrichment applies, and takes `instance_change_pending`, in that same section:
/// either the change is recorded here before the verdict lands (and the verdict follows it), or
/// the phase seen here is already the one after it, so the change is routed by the phase the
/// write is really in. A phase read in one section and a recording made in another could miss
/// the verdict in between and drop the change.
fn route_change(st: &mut EntryState, change: &InstanceChange) -> Routed {
    let phase = st.model.phase();
    let Some(w) = st.write.as_ref() else {
        return Routed::Skip;
    };
    if phase == Phase::Enriching {
        let pending = match change {
            InstanceChange::TokenReplaced => Some(PendingChange::Credential),
            InstanceChange::OriginChanged { old, new } => Some(PendingChange::Origin {
                old: old.clone(),
                new: new.clone(),
            }),
            InstanceChange::TokenStored
            | InstanceChange::StateChanged
            | InstanceChange::UserRenamed { .. } => None,
        };
        if let Some(p) = pending {
            st.instance_change_pending = Some(p);
            return Routed::Deferred;
        }
    }
    Routed::Go {
        phase,
        parked: w.awaiting_refresh,
        identity_return: matches!(w.returned, Some(Returned::IdentityMismatch(_))),
    }
}

/// M-5: the change that met the write in `Enriching`, taken inside the critical section that
/// applies the verdict of the enrichment (which then leaves the write not approvable).
fn take_pending(st: &mut EntryState) -> Option<PendingChange> {
    st.instance_change_pending.take()
}

/// M-5: after the verdict (or the return of a refresh) was applied with the write held not
/// approvable, the change it missed: `WRITE_STALE {credential_changed | instance_changed}`, the
/// `Instance` step and, for a credential change, the refresh under the new PAT.
async fn follow_pending(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    pending: Option<PendingChange>,
) {
    let Some(p) = pending else { return };
    let phase = entry.state().model.phase();
    if !matches!(phase, Phase::AwaitingApproval(_)) {
        return;
    }
    let _ = match p {
        PendingChange::Credential => {
            engine
                .refresh_write(
                    entry,
                    RefreshCause::Instance(InstanceEvt::CredentialChanged),
                )
                .await
        }
        PendingChange::Origin { old, new } => {
            engine
                .refresh_write_returned(
                    entry,
                    RefreshCause::Instance(InstanceEvt::InstanceChanged),
                    Some(Returned::InstanceUrl { old, new }),
                )
                .await
        }
    };
}

/// Runs `f` in its own task; if that task panics, the request is ended or returned fail-closed
/// for the phase it is in (never left in a phase without a driver). A task bound to an approval
/// acts only while that approval is current.
fn spawn_guarded<F, Fut>(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    approval: Option<Approval>,
    f: F,
) where
    F: FnOnce(Arc<Engine>, Arc<RequestEntry>) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (engine, entry) = (engine.clone(), entry.clone());
    let task = tokio::spawn(f(engine.clone(), entry.clone()));
    tokio::spawn(async move {
        if task.await.is_err() {
            fail_closed(&engine, &entry, approval).await;
        }
    });
}

/// A write task that died (or found its state missing): an initial enrichment fails
/// `internal`; a refresh or a stale check returns the write to the queue (`recheck_failed`,
/// nothing was sent); an execution that may have sent is `outcome_unknown` (never retried,
/// §5.4 step 6).
async fn fail_closed(engine: &Arc<Engine>, entry: &Arc<RequestEntry>, approval: Option<Approval>) {
    let (phase, refreshing) = {
        let st = entry.state();
        (st.model.phase(), st.model.refreshing())
    };
    let ctx = entry.ctx.clone();
    match phase {
        Phase::Enriching if !refreshing => {
            let record = payloads::request_failed_direct(
                &ctx,
                ErrorCode::Internal,
                MSG_PREPARE_INTERNAL,
                &Value::Object(Map::new()),
                None,
            );
            let _ = engine
                .transition(entry, Event::EnrichFailedDirect, move |_| record)
                .await;
        }
        Phase::Enriching | Phase::StaleCheck => {
            let record =
                payloads::write_stale(&ctx, WriteStaleReason::RecheckFailed, Some("internal"));
            let _ = stale_return(
                engine,
                entry,
                Event::Stale(StaleReason::RecheckFailed),
                vec![record],
                Returned::RecheckFailed,
                false,
                approval,
            )
            .await;
        }
        Phase::Executing => {
            let mut record = payloads::write_outcome_unknown(
                &ctx,
                first_index(entry),
                &UnknownReason::UndeclaredSuccess,
                None,
                &[],
            );
            if let Some(o) = record.payload.as_object_mut() {
                o.insert("reason".into(), "internal".into());
            }
            let _ = finish(
                engine,
                entry,
                Event::Executed(ExecOutcome::OutcomeUnknown),
                record,
                Some(AttentionKind::OutcomeUnknown),
                approval,
            )
            .await;
        }
        _ => {}
    }
}

fn first_index(entry: &RequestEntry) -> u32 {
    entry
        .state()
        .write
        .as_ref()
        .and_then(|w| w.requests.first().map(|r| r.index))
        .unwrap_or(0)
}

fn queue_changed(engine: &Engine, entry: &RequestEntry) {
    engine.ui().emit(UiEvent::QueueChanged {
        request_ids: vec![entry.head.request_id.clone()],
    });
}

fn attention(engine: &Engine, kind: AttentionKind) {
    engine.ui().emit(UiEvent::Attention { kind, count: 1 });
}

/// A return to the queue (`WRITE_STALE`, `VersionConflict` or an `Instance` change): the event
/// with its records, then in the same critical section either the refresh `EnrichStarted` (T12
/// I-1b) or, only for a failed re-check, the approvability of the hold the write is back in
/// ("the user may approve again later", §5.4 step 5). Every other return stays not approvable
/// (review I-2): a refresh decides at its `Enriched`, `instance_changed` waits for the new PAT,
/// an identity mismatch for a matching identity call. The control of the GET or send it
/// replaces is cancelled. `approval`: the stale-check task making the return (review I-1).
async fn stale_return(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    event: Event,
    records: Vec<NewEvent>,
    returned: Returned,
    refresh: bool,
    approval: Option<Approval>,
) -> Result<Applied, TransitionError> {
    let credential = stored_identity(engine, entry).await.is_some();
    let (spec, alias) = (entry.spec, entry.head.instance.clone());
    let (eng, id) = (engine.clone(), entry.instance_id.clone());
    let recompute = returned == Returned::RecheckFailed && !refresh;
    let pending = Arc::new(std::sync::Mutex::new(None));
    let pending_out = pending.clone();
    let applied = engine
        .transition_guarded(
            entry,
            event,
            move |_| records,
            OnAuditFailure::FailRequest,
            move |st| {
                st.stale = true;
                if let Some(w) = st.write.as_mut() {
                    w.awaiting_refresh = matches!(
                        returned,
                        Returned::Instance(InstanceEvt::InstanceChanged)
                            | Returned::InstanceUrl { .. }
                    );
                    w.returned = Some(returned);
                    w.approved_hash = None;
                }
                let refreshing = refresh && step(&mut st.model, Event::EnrichStarted).is_ok();
                // M-5: a change that met the enrichment this return ends is followed now; one
                // that meets the refresh just started waits for its verdict.
                let missed = if refreshing { None } else { take_pending(st) };
                let ok = !refreshing
                    && missed.is_none()
                    && recompute
                    && approvable(st, pat_now(&eng, &id, credential));
                st.model.set_approvable(ok);
                *pending_out
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = missed;
                if !refreshing {
                    refresh_caution(st, spec, &alias);
                }
            },
            bound(approval),
        )
        .await;
    if applied.is_ok() {
        // The superseded GET or send stops at once (review I-1).
        if let Some(c) = entry.fetch_control() {
            c.cancel();
        }
        entry.set_fetch_control(None);
        queue_changed(engine, entry);
        attention(engine, AttentionKind::Stale);
        let refreshing = entry.state().model.phase() == Phase::Enriching;
        if refresh && refreshing {
            spawn_guarded(engine, entry, None, enrich_task);
        }
        let missed = pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if missed.is_some() {
            // A task of its own: `follow_pending` can return the write again (recursion).
            tokio::spawn(follow_task(engine.clone(), entry.clone(), missed));
        }
    }
    applied
}

/// The refresh as a boxed `Send` future: a refresh can return the write again (`stale_return`),
/// which starts the next refresh, and the boxed type breaks that cycle for the compiler.
fn enrich_task(
    engine: Arc<Engine>,
    entry: Arc<RequestEntry>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async move { enrich(&engine, &entry).await })
}

/// A terminal outcome of an execution: its record (only while `approval` is current), then the
/// UI's attention for a post-approval failure or unknown outcome (§5.6).
async fn finish(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    event: Event,
    record: NewEvent,
    kind: Option<AttentionKind>,
    approval: Option<Approval>,
) -> Result<Applied, TransitionError> {
    let applied = engine
        .transition_guarded(
            entry,
            event,
            move |_| vec![record],
            OnAuditFailure::FailRequest,
            |_| {},
            bound(approval),
        )
        .await;
    queue_changed(engine, entry);
    if let (Ok(_), Some(kind)) = (&applied, kind) {
        attention(engine, kind);
        // §5.6: listed under "Needs attention" until acknowledged.
        if matches!(kind, AttentionKind::Failed | AttentionKind::OutcomeUnknown) {
            engine.flag_attention(&entry.head.request_id);
        }
    }
    applied
}

// ---- 1. enrichment --------------------------------------------------------------------------------

/// Starts the enrichment of a write that just entered the map in `Validated` (Task 19 step 9).
pub(crate) fn dispatch(engine: &Arc<Engine>, entry: &Arc<RequestEntry>) {
    let params = entry
        .validated
        .as_ref()
        .map_or(Value::Null, |v| v.params.clone());
    entry.state().write = Some(WriteState::new(params));
    spawn_guarded(engine, entry, None, |engine, entry| async move {
        // Cancelled or expired meanwhile: the model refuses, nothing is sent.
        if engine
            .step_unlogged(&entry, Event::EnrichStarted, None, |_| {})
            .await
            .is_err()
        {
            return;
        }
        enrich(&engine, &entry).await;
    });
}

/// Re-enrichment after an edit that touched an enrichment-relevant key (`Edit {rerun}` moved the
/// model to `Enriching`; `PREVIEW_FETCH {purpose: enrich}`, PD-24).
pub(crate) fn rerun(engine: &Arc<Engine>, entry: &Arc<RequestEntry>) {
    spawn_guarded(engine, entry, None, |engine, entry| async move {
        enrich(&engine, &entry).await;
    });
}

/// What an enrichment GET means for the §5.4 step 2 table.
enum Effect {
    /// "enrichment failed": Approve disabled, a deny may attach the hint.
    Held(Failure),
    /// Data-free, returned directly (`REQUEST_FAILED`).
    Direct(Direct),
}

/// A data-free direct enrichment failure.
struct Direct {
    code: ErrorCode,
    message: String,
    cause: Option<(&'static str, &'static str)>,
    /// `details.reason` in the envelope: only the §4.3 identity-header states.
    reason_detail: Option<&'static str>,
}

impl Direct {
    fn internal(message: &str) -> Direct {
        Direct {
            code: ErrorCode::Internal,
            message: message.to_owned(),
            cause: None,
            reason_detail: None,
        }
    }
}

/// `upstream_unavailable` for an answer that failed the identity check without the re-check
/// finding the token or the header at fault (§7.1).
fn identity_unavailable() -> Direct {
    Direct {
        code: ErrorCode::UpstreamUnavailable,
        message: MSG_IDENTITY.to_owned(),
        cause: Some(("reason", "identity_check")),
        reason_detail: None,
    }
}

/// §7.2 *Header lost*: the reason and the admin hint, data-free.
fn header_lost_direct(lost: Lost) -> Direct {
    Direct {
        code: ErrorCode::UpstreamUnavailable,
        message: MSG_IDENTITY_HEADER.to_owned(),
        cause: Some(("reason", lost.reason())),
        reason_detail: Some(lost.reason()),
    }
}

fn needs_token_direct() -> Direct {
    Direct {
        code: ErrorCode::NeedsToken,
        message: MSG_NEEDS_TOKEN.to_owned(),
        cause: None,
        reason_detail: None,
    }
}

/// How a GET's identity failure is mapped: an initial enrichment (or an edit's) fails with an
/// [`Effect`]; a refresh or a stale check returns the write with a [`Recheck`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum GetMode {
    Enrich,
    Recheck,
}

/// What an identity-gated GET came to (Task 26).
enum Gated {
    /// Classify the answer as before (a passing re-check turned a JSON 401 into a plain one).
    Proceed(FetchOutcome),
    /// A rename: run the GET once more.
    Rerun,
    /// An initial enrichment's failure.
    Held(Effect),
    /// A refresh's or stale check's return.
    Stale(Recheck),
}

/// The identity handling of one GET (§7.1): a failed `X-AUSERNAME` check or a JSON 401 runs the
/// token re-check, and [`identity::effect`] decides. `allow_rerun` is false for the second run
/// of a GET (a rename re-runs it once; a second failure falls back).
async fn gate_get(
    engine: &Arc<Engine>,
    instance_id: &str,
    seen: u64,
    outcome: FetchOutcome,
    mode: GetMode,
    allow_rerun: bool,
) -> Gated {
    let Some(trigger) = identity::trigger(&outcome) else {
        return Gated::Proceed(outcome);
    };
    let effect = if allow_rerun {
        let path = match mode {
            GetMode::Enrich => identity::Path::Enrichment,
            GetMode::Recheck => identity::Path::StaleOrRefresh,
        };
        let result = identity::recheck(engine, instance_id, seen).await;
        identity::effect(path, trigger, &result)
    } else {
        identity::Effect::HeaderCheckFailed
    };
    let enrich = mode == GetMode::Enrich;
    match effect {
        identity::Effect::Ordinary => Gated::Proceed(identity::as_response(outcome)),
        identity::Effect::Refetch => Gated::Rerun,
        identity::Effect::HeaderCheckFailed if enrich => {
            Gated::Held(Effect::Direct(identity_unavailable()))
        }
        identity::Effect::HeaderCheckFailed => Gated::Stale((StaleReason::IdentityMismatch, None)),
        identity::Effect::Inconclusive if enrich => {
            Gated::Held(Effect::Direct(identity_unavailable()))
        }
        identity::Effect::Inconclusive => Gated::Stale(recheck_failed("identity_recheck")),
        identity::Effect::HeaderLost(l) if enrich => {
            Gated::Held(Effect::Direct(header_lost_direct(l)))
        }
        identity::Effect::HeaderLost(l) => {
            Gated::Stale((StaleReason::IdentityMismatch, Some(l.reason().to_owned())))
        }
        identity::Effect::NeedsToken if enrich => Gated::Held(Effect::Direct(needs_token_direct())),
        identity::Effect::NeedsToken => Gated::Stale((StaleReason::IdentityMismatch, None)),
    }
}

/// An instance already `needs_token` or in an identity-header state is not called (PD-03):
/// the failure an admitted write meets at the start of an enrichment.
fn state_refusal(
    engine: &Engine,
    instance_id: &str,
    mode: GetMode,
) -> Option<Result<Effect, Recheck>> {
    let state = engine.instances().by_id(instance_id).map(|i| i.state)?;
    let lost = match state {
        InstanceState::IdentityHeaderMissing => Lost::Missing,
        InstanceState::IdentityHeaderMismatch => Lost::Mismatch,
        InstanceState::NeedsToken => {
            return Some(match mode {
                GetMode::Enrich => Ok(Effect::Direct(needs_token_direct())),
                GetMode::Recheck => Err((StaleReason::IdentityMismatch, None)),
            });
        }
        InstanceState::Ok | InstanceState::InsecureScheme | InstanceState::InstanceUnconfirmed => {
            return None;
        }
    };
    Some(match mode {
        GetMode::Enrich => Ok(Effect::Direct(header_lost_direct(lost))),
        GetMode::Recheck => Err((
            StaleReason::IdentityMismatch,
            Some(lost.reason().to_owned()),
        )),
    })
}

fn held(status: Option<u16>, text: String, card: Option<CardKind>, hint: FailureHint) -> Effect {
    Effect::Held(Failure {
        card: EnrichFailure {
            status,
            text,
            outcome: card,
        },
        hint,
    })
}

/// A post-send outcome as an "enrichment failed" hold (§5.4 step 2).
fn held_outcome(kind: OutcomeKind, card: CardKind, status: Option<u16>) -> Effect {
    let code = match kind {
        OutcomeKind::TooLarge => ErrorCode::ResultTooLarge,
        OutcomeKind::Unparsable => ErrorCode::UpstreamUnavailable,
        OutcomeKind::Timeout | OutcomeKind::Network => ErrorCode::UpstreamNetwork,
    };
    held(
        status,
        String::new(),
        Some(card),
        FailureHint::Outcome(code),
    )
}

fn status_2xx(r: &UpstreamResponse) -> bool {
    (200..300).contains(&r.status)
}

/// The single source of truth for an initial or edit-triggered enrichment GET (§5.4 step 2
/// table, §7.2, §11.2): a usable 2xx JSON body, or its effect.
fn enrich_effect(outcome: FetchOutcome, proxy: &ResolvedProxy) -> Result<Value, Effect> {
    match outcome {
        FetchOutcome::Response(r) if status_2xx(&r) => serde_json::from_slice(&r.body)
            // The client accepted the JSON, `Value` could not hold it (nesting): gated.
            .map_err(|_| {
                held_outcome(
                    OutcomeKind::Unparsable,
                    CardKind::JsonBodyUnreadable,
                    Some(r.status),
                )
            }),
        // A JSON 401 reaches here only after a passing re-check (`gate_get`): an ordinary 4xx.
        FetchOutcome::Response(r) => Err(held(
            Some(r.status),
            error_text(&r.body),
            None,
            FailureHint::UpstreamHttp,
        )),
        FetchOutcome::Failed(f) => Err(match f {
            FetchFailure::PostSend { kind, .. } => match kind {
                PostSendKind::PerCallTimeout | PostSendKind::ReadBudget120s => {
                    held_outcome(OutcomeKind::Timeout, CardKind::PerCallTimeout30, None)
                }
                PostSendKind::NetworkError => {
                    held_outcome(OutcomeKind::Network, CardKind::NetworkAfterSend, None)
                }
                PostSendKind::ResponseCap32MiB | PostSendKind::FetchCap50MiB => {
                    held_outcome(OutcomeKind::TooLarge, CardKind::ResponseCap32, None)
                }
            },
            // Review Focus 2: after a JSON 2xx head every failure is gated.
            FetchFailure::BodyDecided { kind, response } => {
                let o = match kind {
                    BodyFailure::ReadError => OutcomeKind::Network,
                    BodyFailure::ParseFailure => OutcomeKind::Unparsable,
                };
                held_outcome(o, CardKind::JsonBodyUnreadable, Some(response.status))
            }
            // Never built for a GET without a call budget; gated (the fail-closed side).
            FetchFailure::BudgetExpiredBeforeSend => {
                held_outcome(OutcomeKind::Timeout, CardKind::PerCallTimeout30, None)
            }
            FetchFailure::PreSendConnection(class) => Effect::Direct(Direct {
                code: ErrorCode::UpstreamNetwork,
                message: connection_message(class, proxy),
                cause: Some(("class", class_name(class))),
                reason_detail: None,
            }),
            FetchFailure::StatusHeaderDecided { reason, .. } => Effect::Direct(Direct {
                code: ErrorCode::UpstreamUnavailable,
                message: unavailable_message(reason).to_owned(),
                cause: Some(("reason", unavailable_name(reason))),
                reason_detail: matches!(
                    reason,
                    UnavailableReason::IdentityHeaderMissing
                        | UnavailableReason::IdentityHeaderMismatch
                )
                .then(|| unavailable_name(reason)),
            }),
            FetchFailure::NeedsToken | FetchFailure::OriginGuardRefused => Effect::Direct(Direct {
                code: ErrorCode::NeedsToken,
                message: MSG_NEEDS_TOKEN.to_owned(),
                cause: None,
                reason_detail: None,
            }),
            // Reached for a failed check the re-check did not turn into anything else (Task 26,
            // `gate_get`): `upstream_unavailable`, body audit-only.
            FetchFailure::IdentityCheckFailed { .. } => Effect::Direct(identity_unavailable()),
            // Task 24 records an in-flight cancel and its terminal event; a request still
            // pending here was aborted otherwise and fails closed.
            FetchFailure::CancelledInFlight { .. } | FetchFailure::CancelledBeforeSend => {
                Effect::Direct(Direct::internal(MSG_PREPARE_ABORTED))
            }
            FetchFailure::MethodGuardRefused => Effect::Direct(Direct::internal(
                "the enrichment plan was refused by the method guard",
            )),
        }),
    }
}

/// `WRITE_STALE` reason and class of a stale-check or refresh GET.
type Recheck = (StaleReason, Option<String>);

fn recheck_failed(class: &str) -> Recheck {
    (StaleReason::RecheckFailed, Some(class.to_owned()))
}

/// A stale-check or refresh GET (§5.4 step 5): anything but a parsed 2xx JSON answer is
/// `recheck_failed {class}` (`network`, `http_<status>`, `redirect`, `non_json`, `too_large`,
/// `origin_mismatch`); a Jira answer that fails the `X-AUSERNAME` check is `identity_mismatch`
/// (a JSON 401 that passed the re-check of `gate_get` is `http_401`).
fn recheck(outcome: FetchOutcome) -> Result<Value, Recheck> {
    match outcome {
        FetchOutcome::Response(r) if status_2xx(&r) => {
            serde_json::from_slice(&r.body).map_err(|_| recheck_failed("non_json"))
        }
        FetchOutcome::Response(r) => Err(recheck_failed(&format!("http_{}", r.status))),
        FetchOutcome::Failed(f) => Err(match f {
            FetchFailure::PreSendConnection(_)
            | FetchFailure::BudgetExpiredBeforeSend
            | FetchFailure::PostSend {
                kind:
                    PostSendKind::PerCallTimeout
                    | PostSendKind::NetworkError
                    | PostSendKind::ReadBudget120s,
                ..
            }
            | FetchFailure::BodyDecided {
                kind: BodyFailure::ReadError,
                ..
            } => recheck_failed("network"),
            FetchFailure::PostSend {
                kind: PostSendKind::ResponseCap32MiB | PostSendKind::FetchCap50MiB,
                ..
            } => recheck_failed("too_large"),
            FetchFailure::BodyDecided {
                kind: BodyFailure::ParseFailure,
                ..
            } => recheck_failed("non_json"),
            FetchFailure::StatusHeaderDecided { reason, .. } => match reason {
                UnavailableReason::Redirect3xx => recheck_failed("redirect"),
                UnavailableReason::NonJson2xx | UnavailableReason::NonJson401 => {
                    recheck_failed("non_json")
                }
                UnavailableReason::IdentityHeaderMissing
                | UnavailableReason::IdentityHeaderMismatch => (
                    StaleReason::IdentityMismatch,
                    Some(unavailable_name(reason).to_owned()),
                ),
            },
            FetchFailure::IdentityCheckFailed { response, .. } if response.status == 401 => {
                recheck_failed("http_401")
            }
            FetchFailure::IdentityCheckFailed { .. } => (StaleReason::IdentityMismatch, None),
            FetchFailure::OriginGuardRefused => recheck_failed("origin_mismatch"),
            FetchFailure::NeedsToken => recheck_failed("needs_token"),
            FetchFailure::CancelledInFlight { .. } | FetchFailure::CancelledBeforeSend => {
                recheck_failed("cancelled")
            }
            FetchFailure::MethodGuardRefused => recheck_failed("internal"),
        }),
    }
}

/// The resolved path and query of a GET, for `PREVIEW_FETCH.path`.
fn call_path(base: &NormalizedBaseUrl, call: &GetCall) -> String {
    match build_url(base, &call.endpoint_template, &call.params, &call.query) {
        Ok(u) => match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_owned(),
        },
        Err(_) => call.endpoint_template.clone(),
    }
}

/// `PREVIEW_FETCH {purpose, method, path, status, response | outcome}` of one GET, with every
/// byte received (§5.4 step 2); a GET that was refused or never left names its `class`.
fn get_record(
    ctx: &EventCtx,
    purpose: PreviewFetchPurpose,
    base: &NormalizedBaseUrl,
    call: &GetCall,
    outcome: &FetchOutcome,
) -> NewEvent {
    let path = call_path(base, call);
    let (record, class) = fetch_view(outcome);
    let mut ev = payloads::preview_fetch(ctx, purpose, "GET", &path, &record);
    if let (Some(c), Some(o)) = (class, ev.payload.as_object_mut()) {
        o.insert("class".into(), c.into());
    }
    ev
}

/// `SYSTEM_FETCH {phase: result}` of one GET of a connection test (Task 25): the same record
/// body as `get_record`, with every byte received.
pub(crate) fn system_get_record(
    purpose: payloads::SystemFetchPurpose,
    instance_id: &str,
    fetch_id: &str,
    base: &NormalizedBaseUrl,
    call: &GetCall,
    outcome: &FetchOutcome,
) -> NewEvent {
    let path = call_path(base, call);
    let (record, class) = fetch_view(outcome);
    let mut ev =
        payloads::system_fetch_result(purpose, instance_id, fetch_id, "GET", &path, &record);
    if let (Some(c), Some(o)) = (class, ev.payload.as_object_mut()) {
        o.insert("class".into(), c.into());
    }
    ev
}

/// What a GET's outcome records, and the `class` of one that was refused or never left.
fn fetch_view(outcome: &FetchOutcome) -> (FetchRecord<'_>, Option<&'static str>) {
    let nothing = FetchRecord::Outcome {
        outcome: OutcomeKind::Network,
        status: None,
        content_type: None,
        received: &[],
    };
    match outcome {
        FetchOutcome::Response(r) => (FetchRecord::Response(r), None),
        FetchOutcome::Failed(f) => match f {
            FetchFailure::StatusHeaderDecided { reason, response } => (
                FetchRecord::Response(response),
                Some(unavailable_name(*reason)),
            ),
            FetchFailure::IdentityCheckFailed { response, .. } => {
                (FetchRecord::Response(response), Some("identity_check"))
            }
            FetchFailure::BodyDecided { kind, response } => (
                FetchRecord::Outcome {
                    outcome: match kind {
                        BodyFailure::ReadError => OutcomeKind::Network,
                        BodyFailure::ParseFailure => OutcomeKind::Unparsable,
                    },
                    status: Some(response.status),
                    content_type: response.content_type.as_deref(),
                    received: &response.body,
                },
                None,
            ),
            FetchFailure::PostSend { kind, received } => (
                FetchRecord::Outcome {
                    outcome: match kind {
                        PostSendKind::PerCallTimeout | PostSendKind::ReadBudget120s => {
                            OutcomeKind::Timeout
                        }
                        PostSendKind::NetworkError => OutcomeKind::Network,
                        PostSendKind::ResponseCap32MiB | PostSendKind::FetchCap50MiB => {
                            OutcomeKind::TooLarge
                        }
                    },
                    status: None,
                    content_type: None,
                    received,
                },
                None,
            ),
            FetchFailure::PreSendConnection(c) => (nothing, Some(class_name(*c))),
            FetchFailure::CancelledInFlight { bytes_received } => (
                FetchRecord::Outcome {
                    outcome: OutcomeKind::Network,
                    status: None,
                    content_type: None,
                    received: bytes_received,
                },
                Some("cancelled"),
            ),
            FetchFailure::CancelledBeforeSend => (nothing, Some("cancelled")),
            FetchFailure::BudgetExpiredBeforeSend => (nothing, Some("budget_expired")),
            FetchFailure::OriginGuardRefused => (nothing, Some("origin_mismatch")),
            FetchFailure::NeedsToken => (nothing, Some("needs_token")),
            FetchFailure::MethodGuardRefused => (nothing, Some("method_guard")),
        },
    }
}

/// One enrichment (initial, after an edit, or a refresh): every GET of the plan, recorded, then
/// the verdict and the rendered list (`Enriched`), or the failure's effect.
async fn enrich(engine: &Arc<Engine>, entry: &Arc<RequestEntry>) {
    let (params, refreshing) = {
        let st = entry.state();
        (
            st.write.as_ref().map(|w| w.params.clone()),
            st.model.refreshing(),
        )
    };
    // An enrichment that cannot run fails closed (never left without a driver, review M-3).
    let internal = |message: &str| {
        if refreshing {
            Err(recheck_failed("internal"))
        } else {
            Ok(Effect::Direct(Direct::internal(message)))
        }
    };
    let (Some(params), Some(op)) = (params, op_table().get(entry.spec.id).copied()) else {
        enrich_failed(engine, entry, None, internal(MSG_PREPARE_INTERNAL)).await;
        return;
    };
    let spec = entry.spec;
    let mode = if refreshing {
        GetMode::Recheck
    } else {
        GetMode::Enrich
    };
    // PD-03 for an admitted write: an instance that went bad meanwhile is not called.
    if let Some(fail) = state_refusal(engine, &entry.instance_id, mode) {
        enrich_failed(engine, entry, None, fail).await;
        return;
    }
    let http = match engine.client(&entry.instance_id).await {
        Ok(h) => h,
        Err(_) => {
            let fail =
                internal("the instance's connection settings (custom CA or proxy) cannot be used");
            enrich_failed(engine, entry, None, fail).await;
            return;
        }
    };
    let calls = op
        .enrich
        .map(|r| {
            (r.plan)(&EnrichCtx {
                spec,
                params: &params,
            })
        })
        .unwrap_or_default();
    let mut bodies = Vec::new();
    let mut last = None;
    if !calls.is_empty() {
        let ctl = FetchControl::new();
        entry.set_fetch_control(Some(ctl.clone()));
        // §5.1 inv. 1: only an id whose `REQUEST_RECEIVED` committed gets a cover.
        let Ok(cover) = engine.covers().for_request(&entry.head.request_id) else {
            enrich_failed(engine, entry, None, internal(MSG_PREPARE_INTERNAL)).await;
            return;
        };
        let n = calls.len();
        for (i, (purpose, call)) in calls.into_iter().enumerate() {
            let purpose = match (refreshing, purpose) {
                (true, _) => PreviewFetchPurpose::Refresh,
                (false, EnrichPurpose::Enrich) => PreviewFetchPurpose::Enrich,
                (false, EnrichPurpose::Resolve) => PreviewFetchPurpose::Resolve,
            };
            let mut attempt = 0u8;
            let (record, got) = loop {
                let seen = engine.identity_epoch(&entry.instance_id);
                // A cancel while this GET is in flight records it (`cancelled_in_flight`,
                // Task 24).
                entry.set_in_flight(Some(InFlight {
                    purpose,
                    path: call_path(http.client.base(), &call),
                }));
                let outcome = http.client.get_ctl(&cover, &call, &ctl).await;
                entry.set_in_flight(None);
                let record = get_record(&entry.ctx, purpose, http.client.base(), &call, &outcome);
                park(engine, entry, &record).await;
                let gated = gate_get(
                    engine,
                    &entry.instance_id,
                    seen,
                    outcome,
                    mode,
                    attempt == 0,
                )
                .await;
                match gated {
                    // A rename: the first answer is recorded, the GET runs once more (§7.1).
                    Gated::Rerun => {
                        attempt += 1;
                        if !engine.append_pending(entry, vec![record], None).await {
                            return;
                        }
                    }
                    Gated::Proceed(outcome) => {
                        let got = if refreshing {
                            recheck(outcome).map_err(Err)
                        } else {
                            enrich_effect(outcome, &http.proxy).map_err(Ok)
                        };
                        break (record, got);
                    }
                    Gated::Held(effect) => break (record, Err(Ok(effect))),
                    Gated::Stale(fail) => break (record, Err(Err(fail))),
                }
            };
            match got {
                Ok(v) => bodies.push(v),
                Err(fail) => {
                    enrich_failed(engine, entry, Some(record), fail).await;
                    return;
                }
            }
            if i + 1 < n {
                if !engine.append_pending(entry, vec![record], None).await {
                    return;
                }
            } else {
                last = Some(record);
            }
        }
    }
    let verdict = match op.enrich {
        Some(rule) => (rule.judge)(
            &EnrichCtx {
                spec,
                params: &params,
            },
            &bodies,
        ),
        None => EnrichVerdict::preview(Value::Null, Map::new()),
    };
    let effective_max = entry.validated.as_ref().and_then(|v| v.effective_max);
    let rendered = if verdict.hold == Hold::Preview {
        render(
            spec,
            http.client.base(),
            &params,
            Some(&verdict),
            effective_max,
        )
    } else {
        Ok(Vec::new())
    };
    let (verdict, failure, requests) = match rendered {
        Ok(requests) => (verdict, None, requests),
        Err(_) => (
            EnrichVerdict::unusable(),
            Some(Failure {
                card: EnrichFailure {
                    status: None,
                    text: TEXT_UNRENDERABLE.to_owned(),
                    outcome: None,
                },
                hint: FailureHint::None,
            }),
            Vec::new(),
        ),
    };
    enriched(engine, entry, verdict, failure, requests, last).await;
}

/// The GET finished and its record is built: park it until an append commits it, so a cancel or
/// expiry in between still logs it (Task 24 review I-2).
async fn park(engine: &Arc<Engine>, entry: &Arc<RequestEntry>, record: &NewEvent) {
    entry.park_record(record);
    #[cfg(feature = "testing")]
    if let Some(pause) = engine.hooks.pause_after_get.clone() {
        pause.hold().await;
    }
    #[cfg(not(feature = "testing"))]
    let _ = engine;
}

/// A failed GET of an enrichment: in a refresh a return to the previous hold (`WRITE_STALE`);
/// otherwise an "enrichment failed" hold or a direct `REQUEST_FAILED` (§5.4 step 2).
async fn enrich_failed(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    record: Option<NewEvent>,
    fail: Result<Effect, Recheck>,
) {
    let ctx = entry.ctx.clone();
    match fail {
        Err((reason, class)) => {
            let mut records: Vec<NewEvent> = record.into_iter().collect();
            records.push(payloads::write_stale(
                &ctx,
                stale_reason(reason),
                class.as_deref(),
            ));
            let returned = match reason {
                StaleReason::IdentityMismatch => Returned::IdentityMismatch(class),
                _ => Returned::RecheckFailed,
            };
            let _ = stale_return(
                engine,
                entry,
                Event::Stale(reason),
                records,
                returned,
                false,
                None,
            )
            .await;
        }
        Ok(Effect::Held(failure)) => {
            enriched(
                engine,
                entry,
                EnrichVerdict::unusable(),
                Some(failure),
                Vec::new(),
                record,
            )
            .await;
        }
        Ok(Effect::Direct(d)) => {
            let mut records: Vec<NewEvent> = record.into_iter().collect();
            let mut details = Map::new();
            if let Some(r) = d.reason_detail {
                details.insert("reason".into(), r.into());
            }
            records.push(payloads::request_failed_direct(
                &ctx,
                d.code,
                &d.message,
                &Value::Object(details),
                d.cause,
            ));
            // A cancel or expiry that landed first already ended the request.
            let applied = engine
                .transition_with(
                    entry,
                    Event::EnrichFailedDirect,
                    move |_| records,
                    OnAuditFailure::FailRequest,
                    |_| {},
                )
                .await;
            if applied.is_ok() {
                queue_changed(engine, entry);
            }
        }
    }
}

/// `Enriched(hold)` with the last GET's record: the verdict, the list and its hash become the
/// new revision in the critical section that applies the event; approvability from the verdict,
/// the hold and the PAT (§5.1 inv. 6).
async fn enriched(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    verdict: EnrichVerdict,
    failure: Option<Failure>,
    requests: Vec<HttpRequestSpec>,
    record: Option<NewEvent>,
) {
    let hold = verdict.hold;
    let hash = list_hash(&requests);
    let credential = stored_identity(engine, entry).await.is_some();
    let (eng, id) = (engine.clone(), entry.instance_id.clone());
    let (spec, alias) = (entry.spec, entry.head.instance.clone());
    let refresh = entry.state().model.refreshing();
    let pending = Arc::new(std::sync::Mutex::new(None));
    let pending_out = pending.clone();
    let apply = move |st: &mut EntryState| {
        st.candidate_hash = hash;
        if let Some(w) = st.write.as_mut() {
            w.verdict = verdict;
            w.failure = failure;
            w.requests = requests;
        }
        let missed = take_pending(st);
        let ok = missed.is_none() && approvable(st, pat_now(&eng, &id, credential));
        st.model.set_approvable(ok);
        refresh_caution(st, spec, &alias);
        *pending_out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = missed;
    };
    let applied = match record {
        Some(rec) => engine
            .transition_with(
                entry,
                Event::Enriched(hold),
                move |_| vec![rec],
                OnAuditFailure::FailRequest,
                apply,
            )
            .await
            .is_ok(),
        None => engine
            .step_unlogged(entry, Event::Enriched(hold), None, apply)
            .await
            .is_ok(),
    };
    if applied {
        entry.set_fetch_control(None);
        queue_changed(engine, entry);
        // A refresh already drew attention when the write came back.
        if !refresh {
            attention(engine, AttentionKind::New);
        }
        let missed = pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        follow_pending(engine, entry, missed).await;
    }
}

/// `follow_pending` as a boxed `Send` future: it returns the write, which can end in another
/// return, and the boxed type breaks that cycle for the compiler (like `enrich_task`).
fn follow_task(
    engine: Arc<Engine>,
    entry: Arc<RequestEntry>,
    pending: Option<PendingChange>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async move { follow_pending(&engine, &entry, pending).await })
}

// ---- 4. stale check -------------------------------------------------------------------------------

/// Starts the stale check of a write whose `WRITE_APPROVED` for revision `rev` just committed
/// (§5.4 step 5). The task is bound to that approval (review I-1).
pub(crate) fn start_stale_check(engine: &Arc<Engine>, entry: &Arc<RequestEntry>, rev: u64) {
    let approval = Approval::of(rev);
    spawn_guarded(
        engine,
        entry,
        Some(approval),
        move |engine, entry| async move {
            stale_check(&engine, &entry, approval).await;
        },
    );
}

/// §7.1 identity call: Jira `GET /rest/api/2/myself`, Confluence `GET /rest/api/user/current`.
pub(crate) fn identity_call(product: Product) -> GetCall {
    let template = match product {
        Product::Jira => "/rest/api/2/myself",
        Product::Confluence => "/rest/api/user/current",
    };
    GetCall {
        endpoint_template: template.to_owned(),
        params: Value::Object(Map::new()),
        query: Vec::new(),
    }
}

/// An identity match (§5.4 step 5, §7.1): Jira 200 JSON whose `key` is the stored user key (the
/// client already checked `X-AUSERNAME` against the stored name); Confluence 200 JSON with
/// `type == "known"` and the stored `userKey`. A parsed answer that is not a match is
/// `identity_mismatch`; anything else is `recheck_failed {class}`.
fn identity_check(outcome: FetchOutcome, product: Product, user_key: &str) -> Result<(), Recheck> {
    // §7.1: a match is a 200; another parsed 2xx JSON answer is not one (review M-4).
    let ok_status = matches!(&outcome, FetchOutcome::Response(r) if r.status == 200);
    let v = recheck(outcome)?;
    let matched = ok_status
        && match product {
            Product::Jira => v.get("key").and_then(Value::as_str) == Some(user_key),
            Product::Confluence => {
                v.get("type").and_then(Value::as_str) == Some("known")
                    && v.get("userKey").and_then(Value::as_str) == Some(user_key)
            }
        };
    if matched {
        Ok(())
    } else {
        Err((StaleReason::IdentityMismatch, None))
    }
}

/// A stale check that did not pass: `WRITE_STALE {reason, class?}` after the last GET's record;
/// a change is refreshed in the same critical section, a failed re-check is not.
async fn stale_fail(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    approval: Approval,
    record: Option<NewEvent>,
    (reason, class): Recheck,
) {
    let mut records: Vec<NewEvent> = record.into_iter().collect();
    records.push(payloads::write_stale(
        &entry.ctx,
        stale_reason(reason),
        class.as_deref(),
    ));
    let returned = match reason {
        StaleReason::IdentityMismatch => Returned::IdentityMismatch(class),
        _ => Returned::RecheckFailed,
    };
    let _ = stale_return(
        engine,
        entry,
        Event::Stale(reason),
        records,
        returned,
        false,
        Some(approval),
    )
    .await;
}

/// §5.4 step 5: (a) the identity call, (b) the op's stale rule, (c) `StalePassed` (the agent
/// sees `executing` from here on), then the execution. Everything it applies is bound to
/// `approval` (review I-1): once the write left that approval (an `Instance` return, a later
/// approval) the task applies and sends nothing more.
async fn stale_check(engine: &Arc<Engine>, entry: &Arc<RequestEntry>, approval: Approval) {
    let state = {
        let st = entry.state();
        if !approval.current(&st.model) {
            return;
        }
        st.write
            .as_ref()
            .map(|w| (w.params.clone(), w.verdict.baseline.clone()))
    };
    let (Some((params, baseline)), Some(op)) = (state, op_table().get(entry.spec.id).copied())
    else {
        // Unreachable for a write in the map; never left without a driver (review M-3).
        stale_fail(engine, entry, approval, None, recheck_failed("internal")).await;
        return;
    };
    let spec = entry.spec;
    let Ok(http) = engine.client(&entry.instance_id).await else {
        stale_fail(engine, entry, approval, None, recheck_failed("internal")).await;
        return;
    };
    // An instance in an identity-header state names that reason (§7.2 *Header lost*).
    if let Some(Err(fail)) = state_refusal(engine, &entry.instance_id, GetMode::Recheck)
        && fail.1.is_some()
    {
        stale_fail(engine, entry, approval, None, fail).await;
        return;
    }
    let Some(identity) = stored_identity(engine, entry).await else {
        stale_fail(engine, entry, approval, None, recheck_failed("needs_token")).await;
        return;
    };
    let Ok(cover) = engine.covers().for_request(&entry.head.request_id) else {
        stale_fail(engine, entry, approval, None, recheck_failed("internal")).await;
        return;
    };
    let ctl = FetchControl::new();
    entry.set_fetch_control(Some(ctl.clone()));
    let base = http.client.base();
    let purpose = PreviewFetchPurpose::StaleCheck;

    // (a) The identity call, for every write op (§5.4 step 5). A failed check or a JSON 401
    // runs the token re-check; a rename runs the call once more (§7.1).
    let call = identity_call(spec.product);
    let mut attempt = 0u8;
    let mut last = loop {
        let seen = engine.identity_epoch(&entry.instance_id);
        entry.set_in_flight(Some(InFlight {
            purpose,
            path: call_path(base, &call),
        }));
        let outcome = http.client.get_ctl(&cover, &call, &ctl).await;
        entry.set_in_flight(None);
        let record = get_record(&entry.ctx, purpose, base, &call, &outcome);
        park(engine, entry, &record).await;
        let gated = gate_get(
            engine,
            &entry.instance_id,
            seen,
            outcome,
            GetMode::Recheck,
            attempt == 0,
        )
        .await;
        match gated {
            Gated::Rerun => {
                attempt += 1;
                if !engine
                    .append_pending(entry, vec![record], Some(approval))
                    .await
                {
                    return;
                }
            }
            Gated::Proceed(outcome) => {
                if let Err(fail) =
                    identity_check(outcome, spec.product, &identity.atlassian_user_key)
                {
                    // A parsed answer for another user (or an anonymous one) is the §7.1
                    // trigger the identity call itself is the only place to notice for
                    // Confluence: the token re-check runs and decides the instance state.
                    if fail == (StaleReason::IdentityMismatch, None) {
                        let _ = identity::recheck(engine, &entry.instance_id, seen).await;
                    }
                    stale_fail(engine, entry, approval, Some(record), fail).await;
                    return;
                }
                break record;
            }
            Gated::Stale(fail) => {
                stale_fail(engine, entry, approval, Some(record), fail).await;
                return;
            }
            Gated::Held(_) => {
                stale_fail(
                    engine,
                    entry,
                    approval,
                    Some(record),
                    recheck_failed("internal"),
                )
                .await;
                return;
            }
        }
    };

    // (b) The op's rule (PD-10).
    if let Some(rule) = op.stale_check {
        let ctx = StaleCtx {
            spec,
            params: &params,
            baseline: &baseline,
        };
        let mut bodies = Vec::new();
        for call in (rule.plan)(&ctx) {
            if !engine
                .append_pending(entry, vec![last], Some(approval))
                .await
            {
                return;
            }
            let mut attempt = 0u8;
            loop {
                let seen = engine.identity_epoch(&entry.instance_id);
                entry.set_in_flight(Some(InFlight {
                    purpose,
                    path: call_path(base, &call),
                }));
                let outcome = http.client.get_ctl(&cover, &call, &ctl).await;
                entry.set_in_flight(None);
                last = get_record(&entry.ctx, purpose, base, &call, &outcome);
                park(engine, entry, &last).await;
                let gated = gate_get(
                    engine,
                    &entry.instance_id,
                    seen,
                    outcome,
                    GetMode::Recheck,
                    attempt == 0,
                )
                .await;
                match gated {
                    Gated::Rerun => {
                        attempt += 1;
                        if !engine
                            .append_pending(entry, vec![last], Some(approval))
                            .await
                        {
                            return;
                        }
                    }
                    Gated::Proceed(outcome) => match recheck(outcome) {
                        Ok(v) => {
                            bodies.push(v);
                            break;
                        }
                        Err(fail) => {
                            stale_fail(engine, entry, approval, Some(last), fail).await;
                            return;
                        }
                    },
                    Gated::Stale(fail) => {
                        stale_fail(engine, entry, approval, Some(last), fail).await;
                        return;
                    }
                    Gated::Held(_) => {
                        stale_fail(
                            engine,
                            entry,
                            approval,
                            Some(last),
                            recheck_failed("internal"),
                        )
                        .await;
                        return;
                    }
                }
            }
        }
        if let StaleVerdict::Changed { delta } = (rule.judge)(&ctx, &bodies) {
            let mut stale = payloads::write_stale(&entry.ctx, WriteStaleReason::Changed, None);
            if let Some(o) = stale.payload.as_object_mut() {
                o.insert("delta".into(), Value::String(delta.clone()));
            }
            let _ = stale_return(
                engine,
                entry,
                Event::Stale(StaleReason::Changed),
                vec![last, stale],
                Returned::Changed(delta),
                true,
                Some(approval),
            )
            .await;
            return;
        }
    }

    // (c) Passed: `executing` from here on (§4.5). The write is sent right after this commit.
    let passed = engine
        .transition_guarded(
            entry,
            Event::StalePassed,
            move |_| vec![last],
            OnAuditFailure::FailRequest,
            |st| st.stale = false,
            bound(Some(approval)),
        )
        .await;
    if passed.is_ok() {
        queue_changed(engine, entry);
        execute(engine, entry, &http, &cover, approval).await;
    }
}

// ---- 5. execution ---------------------------------------------------------------------------------

/// §5.4 step 6: the list held in the entry is re-hashed and must equal the committed approval;
/// then exactly that request is sent and its outcome recorded.
async fn execute(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    http: &InstanceHttp,
    cover: &atlas_duck_atlassian::AuditCover,
    approval: Approval,
) {
    let held = {
        let st = entry.state();
        if !approval.current(&st.model) {
            return;
        }
        st.write
            .as_ref()
            .map(|w| (w.requests.clone(), w.approved_hash, w.edit.clone()))
    };
    // A write in `Executing` always has its state; a missing one fails closed (review M-3).
    let (requests, approved, edit) = held.unwrap_or_default();
    let index = requests.first().map_or(0, |r| r.index);
    if approved.is_none() || approved != Some(list_hash(&requests)) {
        // Nothing was sent; still a terminal outcome event of an approved write (M-8: an append
        // failure here is `outcome_unknown`, conservative and intended).
        let record = payloads::write_failed(
            &entry.ctx,
            index,
            ErrorCode::Internal,
            MSG_WRITE_INTERNAL,
            &WriteFailure::Class {
                class: "request_set_mismatch",
                status: None,
                received: &[],
            },
        );
        let _ = finish(
            engine,
            entry,
            Event::Executed(ExecOutcome::Failed),
            record,
            Some(AttentionKind::Failed),
            Some(approval),
        )
        .await;
        return;
    }
    let ctl = FetchControl::new();
    entry.set_fetch_control(Some(ctl.clone()));
    let w = ApprovedWrite {
        requests,
        success: expectation(entry.spec),
    };
    // Review I-1 (c): the approval is checked once more right before the send.
    if !approval.current(&entry.state().model) {
        return;
    }
    let seen = engine.identity_epoch(&entry.instance_id);
    let outcome = http.client.send_approved_ctl(cover, &w, &ctl).await;
    // Bodies of the outcomes that do not carry their response (§7.2: audit-only, T10 handoff).
    let received = ctl.take_captured().partial;
    settle_execution(engine, entry, outcome, &received, edit, approval, seen).await;
}

/// The single source of truth for a write's outcome (§5.4 step 6, §7.2, §11.2).
async fn settle_execution(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    outcome: WriteOutcome,
    received: &[u8],
    edit: Option<EditView>,
    approval: Approval,
    seen: u64,
) {
    let ctx = entry.ctx.clone();
    // A write answer that failed the identity check stays `outcome_unknown`, never retried
    // (§7.1); the token re-check that follows only brings the instance state up to date.
    let identity_followup = matches!(
        &outcome,
        WriteOutcome::OutcomeUnknown {
            reason: UnknownReason::IdentityMismatch { .. },
            ..
        }
    );
    // A write's JSON 401 is `needs_token` only when the token re-check fails too (§7.1, I-23);
    // otherwise it is an ordinary upstream error. The write is terminal either way.
    let needs_token = if matches!(outcome, WriteOutcome::NeedsToken) {
        let result = identity::recheck(engine, &entry.instance_id, seen).await;
        matches!(
            identity::effect(
                identity::Path::WriteResponse,
                identity::Trigger::Json401,
                &result
            ),
            identity::Effect::NeedsToken
        )
    } else {
        false
    };
    let failed = |index: u32, code: ErrorCode, message: &str, class: &str| {
        payloads::write_failed(
            &ctx,
            index,
            code,
            message,
            &WriteFailure::Class {
                class,
                status: None,
                received,
            },
        )
    };
    let index0 = first_index(entry);
    let (event, record, kind) = match outcome {
        WriteOutcome::Executed {
            response,
            server_user,
            request_index,
        } => {
            let mut record =
                payloads::write_executed(&ctx, request_index, &response, server_user.as_deref());
            // The delivery view (§4.2): the agent's own (edited) keys and the edited names; the
            // receipt is projected from the recorded response at delivery.
            if let (Some(e), Some(o)) = (edit, record.payload.as_object_mut()) {
                o.insert("edited".into(), true.into());
                o.insert("executed_params".into(), e.executed_params);
                o.insert(
                    "edited_keys".into(),
                    serde_json::to_value(&e.edited_keys).unwrap_or(Value::Null),
                );
            }
            (Event::Executed(ExecOutcome::Succeeded), record, None)
        }
        WriteOutcome::Failed4xx {
            response,
            request_index,
        } => {
            let json = response
                .content_type
                .as_deref()
                .is_some_and(|c| c.to_ascii_lowercase().contains("json"));
            // A non-JSON 401 (SSO, maintenance) is `upstream_unavailable`, body out of the
            // agent's view (§11.2, §7.2; T10 `write_non_json_401_is_failed4xx`).
            let record = if response.status == 401 && !json {
                payloads::write_failed(
                    &ctx,
                    request_index,
                    ErrorCode::UpstreamUnavailable,
                    MSG_WRITE_NON_JSON_401,
                    &WriteFailure::Class {
                        class: "non_json_401",
                        status: Some(response.status),
                        received: &response.body,
                    },
                )
            } else {
                let details = json!({
                    "status": response.status,
                    "error_messages": error_text(&response.body),
                });
                payloads::write_failed(
                    &ctx,
                    request_index,
                    ErrorCode::UpstreamHttp,
                    MSG_WRITE_REFUSED,
                    &WriteFailure::Response {
                        response: &response,
                        details: &details,
                    },
                )
            };
            (
                Event::Executed(ExecOutcome::Failed),
                record,
                Some(AttentionKind::Failed),
            )
        }
        WriteOutcome::Unavailable3xx { request_index } => (
            Event::Executed(ExecOutcome::Failed),
            failed(
                request_index,
                ErrorCode::UpstreamUnavailable,
                MSG_WRITE_REDIRECT,
                "redirect",
            ),
            Some(AttentionKind::Failed),
        ),
        WriteOutcome::NeedsToken if !needs_token => (
            Event::Executed(ExecOutcome::Failed),
            payloads::write_failed(
                &ctx,
                index0,
                ErrorCode::UpstreamHttp,
                MSG_WRITE_REFUSED,
                &WriteFailure::Class {
                    class: "http_401",
                    status: Some(401),
                    received,
                },
            ),
            Some(AttentionKind::Failed),
        ),
        WriteOutcome::NeedsToken => (
            Event::Executed(ExecOutcome::Failed),
            failed(
                index0,
                ErrorCode::NeedsToken,
                MSG_NEEDS_TOKEN,
                "needs_token",
            ),
            Some(AttentionKind::Failed),
        ),
        WriteOutcome::RefusedMismatch { request_index } => (
            Event::Executed(ExecOutcome::Failed),
            failed(
                request_index,
                ErrorCode::Internal,
                MSG_WRITE_INTERNAL,
                "request_mismatch",
            ),
            Some(AttentionKind::Failed),
        ),
        WriteOutcome::OutcomeUnknown {
            reason,
            request_index,
            status,
        } => (
            Event::Executed(ExecOutcome::OutcomeUnknown),
            payloads::write_outcome_unknown(&ctx, request_index, &reason, status, received),
            Some(AttentionKind::OutcomeUnknown),
        ),
        // Confluence's optimistic lock (§5.4 step 6): back to the queue, refreshed in the same
        // critical section; the refresh sees current ≠ `base_version` (conflict hold).
        WriteOutcome::VersionConflict { request_index } => {
            let mut stale = payloads::write_stale(&ctx, WriteStaleReason::VersionConflict, None);
            if let Some(o) = stale.payload.as_object_mut() {
                o.insert("request_index".into(), request_index.into());
                o.insert("received".into(), payloads::body_json(received));
            }
            let _ = stale_return(
                engine,
                entry,
                Event::VersionConflict,
                vec![stale],
                Returned::VersionConflict,
                true,
                Some(approval),
            )
            .await;
            return;
        }
        // Nothing left the client: back to the queue as `recheck_failed` (§7.2, T10 Δ C.4).
        WriteOutcome::OriginGuardRefused | WriteOutcome::NotSent { .. } => {
            let class = match outcome {
                WriteOutcome::OriginGuardRefused => "origin_mismatch",
                // `Cancelled` arises only on the shutdown path (Task 28).
                WriteOutcome::NotSent {
                    reason: NotSentReason::Cancelled,
                } => "cancelled",
                _ => "network",
            };
            let stale = payloads::write_stale(&ctx, WriteStaleReason::RecheckFailed, Some(class));
            let _ = stale_return(
                engine,
                entry,
                Event::Stale(StaleReason::RecheckFailed),
                vec![stale],
                Returned::RecheckFailed,
                false,
                Some(approval),
            )
            .await;
            return;
        }
    };
    let _ = finish(engine, entry, event, record, kind, Some(approval)).await;
    if identity_followup {
        let _ = identity::recheck(engine, &entry.instance_id, seen).await;
    }
}

// ---- decisions -----------------------------------------------------------------------------------

/// What a write decision needs from the entry, read under one lock.
pub(crate) struct Snapshot {
    pub write: WriteState,
    pub hold: Option<Hold>,
}

pub(crate) fn snapshot(entry: &RequestEntry) -> Option<Snapshot> {
    let st = entry.state();
    let hold = match st.model.phase() {
        Phase::AwaitingApproval(h) => Some(h),
        _ => None,
    };
    st.write.clone().map(|write| Snapshot { write, hold })
}

/// The new revision of an edit that does not re-enrich, applied with the `Edit` event: the list
/// rendered from the edited params and the latest verdict (§5.4 step 4, inv. 5).
pub(crate) fn edit_apply(
    engine: Arc<Engine>,
    entry: &RequestEntry,
    params: Value,
    view: EditView,
    rendered: Option<Vec<HttpRequestSpec>>,
    credential: bool,
) -> impl FnOnce(&mut EntryState) + Send + 'static {
    let (spec, alias, instance_id) = (
        entry.spec,
        entry.head.instance.clone(),
        entry.instance_id.clone(),
    );
    move |st: &mut EntryState| {
        if let Some(w) = st.write.as_mut() {
            w.params = params;
            w.edit = Some(view);
            w.returned = None;
            if let Some(requests) = rendered {
                w.requests = requests;
            }
        }
        if let Some(w) = st.write.as_ref()
            && st.model.phase() != Phase::Enriching
        {
            st.candidate_hash = list_hash(&w.requests);
        }
        let ok = approvable(st, pat_now(&engine, &instance_id, credential));
        st.model.set_approvable(ok);
        refresh_caution(st, spec, &alias);
    }
}

/// The `WRITE_APPROVED` records of the current list and whether the write was ever edited.
pub(crate) fn approval(entry: &RequestEntry) -> Option<(Vec<RequestRecord>, [u8; 32], bool)> {
    let st = entry.state();
    let w = st.write.as_ref()?;
    let recs = records(&w.requests);
    let hash = request_set_hash(&recs);
    Some((recs, hash, w.edit.is_some()))
}

/// Applied with an accepted `Approve`: the hash the execution must reproduce.
pub(crate) fn approve_apply(hash: [u8; 32]) -> impl FnOnce(&mut EntryState) + Send + 'static {
    move |st: &mut EntryState| {
        st.stale = false;
        if let Some(w) = st.write.as_mut() {
            w.approved_hash = Some(hash);
            w.returned = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn resp(status: u16, ct: &str, body: &[u8]) -> UpstreamResponse {
        UpstreamResponse {
            status,
            content_type: Some(ct.to_owned()),
            body: body.to_vec(),
        }
    }

    fn direct_proxy() -> ResolvedProxy {
        ResolvedProxy {
            choice: atlas_duck_atlassian::ProxyChoice::Direct,
            pac_configured: false,
            uses_os: false,
            os_read_failed: false,
            effective: "direct".to_owned(),
        }
    }

    /// An entry state whose write is in the phase the steps lead to.
    fn write_in(phase_events: &[Event]) -> Result<EntryState, Box<dyn std::error::Error>> {
        let mut model = Model::new(crate::lifecycle::model::Kind::Write);
        for e in phase_events {
            step(&mut model, *e).map_err(|e| format!("{e:?}"))?;
        }
        Ok(EntryState {
            model,
            candidate_hash: [0; 32],
            stale: false,
            caution_count: 0,
            redaction_ops: Vec::new(),
            rebuild_failed: false,
            unlogged_terminal: None,
            read: None,
            write: Some(WriteState::new(json!({}))),
            expiry_due: false,
            instance_change_pending: None,
        })
    }

    const TO_ENRICHING: [Event; 2] = [Event::ValidationPassed, Event::EnrichStarted];

    fn origin_change() -> InstanceChange {
        InstanceChange::OriginChanged {
            old: "https://a.example".to_owned(),
            new: "https://b.example".to_owned(),
        }
    }

    /// Review I-3: a change that meets an enriching write is recorded for the verdict, in the
    /// same critical section that read the phase.
    #[test]
    fn a_change_meeting_an_enriching_write_is_recorded_for_the_verdict() -> TestResult {
        let mut st = write_in(&TO_ENRICHING)?;
        assert_eq!(
            route_change(&mut st, &InstanceChange::TokenReplaced),
            Routed::Deferred
        );
        assert_eq!(st.instance_change_pending, Some(PendingChange::Credential));
        let mut st = write_in(&TO_ENRICHING)?;
        assert_eq!(route_change(&mut st, &origin_change()), Routed::Deferred);
        assert!(matches!(
            st.instance_change_pending,
            Some(PendingChange::Origin { .. })
        ));
        // A stored token or a state change has nothing to wait for.
        let mut st = write_in(&TO_ENRICHING)?;
        assert!(matches!(
            route_change(&mut st, &InstanceChange::TokenStored),
            Routed::Go {
                phase: Phase::Enriching,
                ..
            }
        ));
        assert_eq!(st.instance_change_pending, None);
        Ok(())
    }

    /// Review I-3: when the enrichment has finished by the time the change looks, the change is
    /// routed by the phase the write is in NOW (`AwaitingApproval`), so the caller refreshes or
    /// parks it; it is neither recorded for a verdict that already landed nor dropped.
    #[test]
    fn a_change_after_the_verdict_is_routed_by_the_fresh_phase() -> TestResult {
        let mut events = TO_ENRICHING.to_vec();
        events.push(Event::Enriched(Hold::Preview));
        for change in [InstanceChange::TokenReplaced, origin_change()] {
            let mut st = write_in(&events)?;
            assert_eq!(
                route_change(&mut st, &change),
                Routed::Go {
                    phase: Phase::AwaitingApproval(Hold::Preview),
                    parked: false,
                    identity_return: false,
                }
            );
            assert_eq!(st.instance_change_pending, None);
        }
        // Not a write at all.
        let mut st = write_in(&events)?;
        st.write = None;
        assert_eq!(route_change(&mut st, &origin_change()), Routed::Skip);
        Ok(())
    }

    #[test]
    fn recheck_classes() -> TestResult {
        let ok = recheck(FetchOutcome::Response(resp(200, "application/json", b"{}")));
        assert_eq!(ok.map_err(|e| format!("{e:?}"))?, json!({}));
        let class = |o| recheck(o).err().and_then(|(_, c)| c);
        assert_eq!(
            class(FetchOutcome::Response(resp(503, "text/html", b"x"))),
            Some("http_503".to_owned())
        );
        assert_eq!(
            class(FetchOutcome::Failed(FetchFailure::StatusHeaderDecided {
                reason: UnavailableReason::Redirect3xx,
                response: resp(302, "text/html", b""),
            })),
            Some("redirect".to_owned())
        );
        assert_eq!(
            class(FetchOutcome::Failed(FetchFailure::PostSend {
                kind: PostSendKind::ResponseCap32MiB,
                received: vec![],
            })),
            Some("too_large".to_owned())
        );
        assert_eq!(
            class(FetchOutcome::Failed(FetchFailure::OriginGuardRefused)),
            Some("origin_mismatch".to_owned())
        );
        // A Jira answer not attributed to the PAT's user is an identity mismatch; a JSON 401
        // follows the token rule.
        let mismatch = recheck(FetchOutcome::Failed(FetchFailure::IdentityCheckFailed {
            observed: atlas_duck_atlassian::IdentityObserved::Anonymous,
            response: resp(200, "application/json", b"{}"),
        }));
        assert_eq!(mismatch.err(), Some((StaleReason::IdentityMismatch, None)));
        let json401 = recheck(FetchOutcome::Failed(FetchFailure::IdentityCheckFailed {
            observed: atlas_duck_atlassian::IdentityObserved::Anonymous,
            response: resp(401, "application/json", b"{}"),
        }));
        assert_eq!(json401.err(), Some(recheck_failed("http_401")));
        Ok(())
    }

    #[test]
    fn enrichment_table() {
        let proxy = direct_proxy();
        let effect = |o| enrich_effect(o, &proxy).err();
        // An upstream error is held with the `upstream_http` hint.
        assert!(matches!(
            effect(FetchOutcome::Response(resp(404, "application/json", b"{}"))),
            Some(Effect::Held(Failure {
                hint: FailureHint::UpstreamHttp,
                ..
            }))
        ));
        // Post-send failures are held with an outcome hint, never direct.
        for (f, code) in [
            (
                FetchFailure::PostSend {
                    kind: PostSendKind::PerCallTimeout,
                    received: vec![],
                },
                ErrorCode::UpstreamNetwork,
            ),
            (
                FetchFailure::PostSend {
                    kind: PostSendKind::ResponseCap32MiB,
                    received: vec![],
                },
                ErrorCode::ResultTooLarge,
            ),
            (
                FetchFailure::BodyDecided {
                    kind: BodyFailure::ParseFailure,
                    response: resp(200, "application/json", b"{"),
                },
                ErrorCode::UpstreamUnavailable,
            ),
        ] {
            let held = match effect(FetchOutcome::Failed(f)) {
                Some(Effect::Held(Failure {
                    hint: FailureHint::Outcome(c),
                    ..
                })) => Some(c),
                _ => None,
            };
            assert_eq!(held, Some(code));
        }
        // Decided before or without the request's content: direct.
        for f in [
            FetchFailure::PreSendConnection(atlas_duck_atlassian::ConnClass::Dns),
            FetchFailure::StatusHeaderDecided {
                reason: UnavailableReason::NonJson2xx,
                response: resp(200, "text/html", b""),
            },
            FetchFailure::NeedsToken,
            FetchFailure::OriginGuardRefused,
        ] {
            assert!(matches!(
                effect(FetchOutcome::Failed(f)),
                Some(Effect::Direct(_))
            ));
        }
    }

    #[test]
    fn identity_match_rules() {
        let ok = |body: &str, product| {
            identity_check(
                FetchOutcome::Response(resp(200, "application/json", body.as_bytes())),
                product,
                "JIRAUSER1",
            )
        };
        assert_eq!(ok(r#"{"key":"JIRAUSER1"}"#, Product::Jira), Ok(()));
        assert_eq!(
            ok(r#"{"key":"JIRAUSER9"}"#, Product::Jira),
            Err((StaleReason::IdentityMismatch, None))
        );
        assert_eq!(
            ok(
                r#"{"type":"known","userKey":"JIRAUSER1"}"#,
                Product::Confluence
            ),
            Ok(())
        );
        assert_eq!(
            ok(r#"{"type":"anonymous"}"#, Product::Confluence),
            Err((StaleReason::IdentityMismatch, None))
        );
    }

    #[test]
    fn prefill_is_verbatim() {
        assert_eq!(
            CONFLICT_DENY_PREFILL,
            "target changed since you read it; re-read and resubmit"
        );
    }
}
