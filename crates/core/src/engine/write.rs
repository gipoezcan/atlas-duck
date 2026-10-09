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

use super::read::{
    MSG_IDENTITY, MSG_NEEDS_TOKEN, class_name, connection_message, error_text, unavailable_message,
    unavailable_name,
};
use super::{Engine, EntryState, InstanceHttp, OnAuditFailure, RequestEntry, TransitionError};
use crate::edit::EditedKeys;
use crate::gate::{AttentionKind, UiEvent};
use crate::instances::InstanceState;
use crate::lifecycle::model::{
    Applied, Event, ExecOutcome, Hold, InstanceEvt, Phase, StaleReason, is_pending, step,
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
/// A JSON 401 during enrichment (Task 26 replaces it with the `token_recheck` result).
const MSG_JSON_401: &str = "the server answered 401";
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
        Returned::VersionConflict
        | Returned::Instance(InstanceEvt::InstanceChanged | InstanceEvt::UserRenamed) => {
            return None;
        }
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
    let ok = engine
        .instances()
        .by_id(&entry.instance_id)
        .is_some_and(|i| i.state == InstanceState::Ok);
    if !ok {
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

// ---- engine plumbing -----------------------------------------------------------------------------

/// Why a queued write is refreshed (§5.4 step 5, §7.1): Tasks 25–26 call [`Engine::refresh_write`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshCause {
    /// A stale-check return (from `StaleCheck`); only `Changed` is refreshed.
    Stale(StaleReason),
    /// `credential_changed`, `instance_changed` (refreshed when the new PAT is stored, Task 25)
    /// or `user_renamed`.
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

impl Engine {
    /// Appends records of a request that is still pending, under its transition gate (a request
    /// a cancel or expiry ended meanwhile gets nothing more). An append failure fails the request
    /// (§11.1). `false` = nothing appended and the flow stops.
    pub(crate) async fn append_pending(
        self: &Arc<Self>,
        entry: &Arc<RequestEntry>,
        mut evs: Vec<NewEvent>,
    ) -> bool {
        let _gate = entry.gate.clone().lock_owned().await;
        if !is_pending(entry.state().model.phase()) {
            return false;
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
        true
    }

    /// Tasks 25–26 (T12 I-1b): logs `WRITE_STALE {reason}` and steps the matching event; a
    /// `Changed`, `credential_changed` or `user_renamed` return starts the refresh
    /// (`EnrichStarted`, `PREVIEW_FETCH {purpose: refresh}`) in the same entry critical section,
    /// so no decision can interleave; `instance_changed` waits for the new PAT (Task 25).
    pub async fn refresh_write(
        self: &Arc<Self>,
        entry: &Arc<RequestEntry>,
        cause: RefreshCause,
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
                Returned::Instance(e),
            ),
        };
        let record = payloads::write_stale(&ctx, reason, None);
        stale_return(self, entry, event, vec![record], returned, refresh).await
    }
}

/// Runs `f` in its own task; if that task panics, the request is ended or returned fail-closed
/// for the phase it is in (never left in a phase without a driver).
fn spawn_guarded<F, Fut>(engine: &Arc<Engine>, entry: &Arc<RequestEntry>, f: F)
where
    F: FnOnce(Arc<Engine>, Arc<RequestEntry>) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (engine, entry) = (engine.clone(), entry.clone());
    let task = tokio::spawn(f(engine.clone(), entry.clone()));
    tokio::spawn(async move {
        if task.await.is_err() {
            fail_closed(&engine, &entry).await;
        }
    });
}

/// A write task that died: an initial enrichment fails `internal`; a refresh or a stale check
/// returns the write to the queue (`recheck_failed`, nothing was sent); an execution that may
/// have sent is `outcome_unknown` (never retried, §5.4 step 6).
async fn fail_closed(engine: &Arc<Engine>, entry: &Arc<RequestEntry>) {
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
/// I-1b; approvable stays false until its `Enriched`) or the approvability of the hold the write
/// is back in (a failed re-check: "the user may approve again later", §5.4 step 5).
async fn stale_return(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    event: Event,
    records: Vec<NewEvent>,
    returned: Returned,
    refresh: bool,
) -> Result<Applied, TransitionError> {
    let pat = stored_identity(engine, entry).await.is_some();
    let (spec, alias) = (entry.spec, entry.head.instance.clone());
    let applied = engine
        .transition_with(
            entry,
            event,
            move |_| records,
            OnAuditFailure::FailRequest,
            move |st| {
                st.stale = true;
                if let Some(w) = st.write.as_mut() {
                    w.returned = Some(returned);
                    w.approved_hash = None;
                }
                let refreshing = refresh && step(&mut st.model, Event::EnrichStarted).is_ok();
                if !refreshing {
                    let ok = approvable(st, pat);
                    st.model.set_approvable(ok);
                    refresh_caution(st, spec, &alias);
                }
            },
        )
        .await;
    if applied.is_ok() {
        entry.set_fetch_control(None);
        queue_changed(engine, entry);
        attention(engine, AttentionKind::Stale);
        let refreshing = entry.state().model.phase() == Phase::Enriching;
        if refresh && refreshing {
            spawn_guarded(engine, entry, enrich_task);
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

/// A terminal outcome of an execution: its record, then the UI's attention for a post-approval
/// failure or unknown outcome (§5.6).
async fn finish(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    event: Event,
    record: NewEvent,
    kind: Option<AttentionKind>,
) -> Result<Applied, TransitionError> {
    let applied = engine.transition(entry, event, move |_| record).await;
    queue_changed(engine, entry);
    if let (Ok(_), Some(kind)) = (&applied, kind) {
        attention(engine, kind);
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
    spawn_guarded(engine, entry, |engine, entry| async move {
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
    spawn_guarded(engine, entry, |engine, entry| async move {
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
        // A JSON 401 (a Confluence one; Jira's arrives as an identity failure): Task 26 runs
        // `token_recheck`; until then data-free `upstream_unavailable`.
        FetchOutcome::Response(r) if r.status == 401 => Err(Effect::Direct(Direct {
            code: ErrorCode::UpstreamUnavailable,
            message: MSG_JSON_401.to_owned(),
            cause: Some(("reason", "json_401")),
            reason_detail: None,
        })),
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
            // Task 26 runs `token_recheck` here; until then `upstream_unavailable`.
            FetchFailure::IdentityCheckFailed { .. } => Effect::Direct(Direct {
                code: ErrorCode::UpstreamUnavailable,
                message: MSG_IDENTITY.to_owned(),
                cause: Some(("reason", "identity_check")),
                reason_detail: None,
            }),
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
/// (a JSON 401 follows the token rule: `http_401`, Task 26 adds the recheck).
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
    let nothing = FetchRecord::Outcome {
        outcome: OutcomeKind::Network,
        status: None,
        content_type: None,
        received: &[],
    };
    let (record, class): (FetchRecord<'_>, Option<&str>) = match outcome {
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
    };
    let mut ev = payloads::preview_fetch(ctx, purpose, "GET", &path, &record);
    if let (Some(c), Some(o)) = (class, ev.payload.as_object_mut()) {
        o.insert("class".into(), c.into());
    }
    ev
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
    let (Some(params), Some(op)) = (params, op_table().get(entry.spec.id).copied()) else {
        return;
    };
    let spec = entry.spec;
    let http = match engine.client(&entry.instance_id).await {
        Ok(h) => h,
        Err(_) => {
            let fail = if refreshing {
                Err(recheck_failed("internal"))
            } else {
                Ok(Effect::Direct(Direct::internal(
                    "the instance's connection settings (custom CA or proxy) cannot be used",
                )))
            };
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
            return;
        };
        let n = calls.len();
        for (i, (purpose, call)) in calls.into_iter().enumerate() {
            let outcome = http.client.get_ctl(&cover, &call, &ctl).await;
            let purpose = match (refreshing, purpose) {
                (true, _) => PreviewFetchPurpose::Refresh,
                (false, EnrichPurpose::Enrich) => PreviewFetchPurpose::Enrich,
                (false, EnrichPurpose::Resolve) => PreviewFetchPurpose::Resolve,
            };
            let record = get_record(&entry.ctx, purpose, http.client.base(), &call, &outcome);
            let got = if refreshing {
                recheck(outcome).map_err(Err)
            } else {
                enrich_effect(outcome, &http.proxy).map_err(Ok)
            };
            match got {
                Ok(v) => bodies.push(v),
                Err(fail) => {
                    enrich_failed(engine, entry, Some(record), fail).await;
                    return;
                }
            }
            if i + 1 < n {
                if !engine.append_pending(entry, vec![record]).await {
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
    let pat = stored_identity(engine, entry).await.is_some();
    let (spec, alias) = (entry.spec, entry.head.instance.clone());
    let refresh = entry.state().model.refreshing();
    let apply = move |st: &mut EntryState| {
        st.candidate_hash = hash;
        if let Some(w) = st.write.as_mut() {
            w.verdict = verdict;
            w.failure = failure;
            w.requests = requests;
        }
        let ok = approvable(st, pat);
        st.model.set_approvable(ok);
        refresh_caution(st, spec, &alias);
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
    }
}

// ---- 4. stale check -------------------------------------------------------------------------------

/// Starts the stale check of a write whose `WRITE_APPROVED` just committed (§5.4 step 5).
pub(crate) fn start_stale_check(engine: &Arc<Engine>, entry: &Arc<RequestEntry>) {
    spawn_guarded(engine, entry, |engine, entry| async move {
        stale_check(&engine, &entry).await;
    });
}

/// §7.1 identity call: Jira `GET /rest/api/2/myself`, Confluence `GET /rest/api/user/current`.
fn identity_call(product: Product) -> GetCall {
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
    let v = recheck(outcome)?;
    let matched = match product {
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
    )
    .await;
}

/// §5.4 step 5: (a) the identity call, (b) the op's stale rule, (c) `StalePassed` (the agent
/// sees `executing` from here on), then the execution.
async fn stale_check(engine: &Arc<Engine>, entry: &Arc<RequestEntry>) {
    let state = {
        let st = entry.state();
        st.write
            .as_ref()
            .map(|w| (w.params.clone(), w.verdict.baseline.clone()))
    };
    let (Some((params, baseline)), Some(op)) = (state, op_table().get(entry.spec.id).copied())
    else {
        return;
    };
    let spec = entry.spec;
    let Ok(http) = engine.client(&entry.instance_id).await else {
        stale_fail(engine, entry, None, recheck_failed("internal")).await;
        return;
    };
    let Some(identity) = stored_identity(engine, entry).await else {
        stale_fail(engine, entry, None, recheck_failed("needs_token")).await;
        return;
    };
    let ctl = FetchControl::new();
    entry.set_fetch_control(Some(ctl.clone()));
    let Ok(cover) = engine.covers().for_request(&entry.head.request_id) else {
        return;
    };
    let base = http.client.base();
    let purpose = PreviewFetchPurpose::StaleCheck;

    // (a) The identity call, for every write op (§5.4 step 5).
    let call = identity_call(spec.product);
    let outcome = http.client.get_ctl(&cover, &call, &ctl).await;
    let mut last = get_record(&entry.ctx, purpose, base, &call, &outcome);
    if let Err(fail) = identity_check(outcome, spec.product, &identity.atlassian_user_key) {
        stale_fail(engine, entry, Some(last), fail).await;
        return;
    }

    // (b) The op's rule (PD-10).
    if let Some(rule) = op.stale_check {
        let ctx = StaleCtx {
            spec,
            params: &params,
            baseline: &baseline,
        };
        let mut bodies = Vec::new();
        for call in (rule.plan)(&ctx) {
            if !engine.append_pending(entry, vec![last]).await {
                return;
            }
            let outcome = http.client.get_ctl(&cover, &call, &ctl).await;
            last = get_record(&entry.ctx, purpose, base, &call, &outcome);
            match recheck(outcome) {
                Ok(v) => bodies.push(v),
                Err(fail) => {
                    stale_fail(engine, entry, Some(last), fail).await;
                    return;
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
            )
            .await;
            return;
        }
    }

    // (c) Passed: `executing` from here on (§4.5). The write is sent right after this commit.
    let passed = engine
        .transition_with(
            entry,
            Event::StalePassed,
            move |_| vec![last],
            OnAuditFailure::FailRequest,
            |st| st.stale = false,
        )
        .await;
    if passed.is_ok() {
        queue_changed(engine, entry);
        execute(engine, entry, &http, &cover).await;
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
) {
    let held = {
        let st = entry.state();
        st.write
            .as_ref()
            .map(|w| (w.requests.clone(), w.approved_hash, w.edit.clone()))
    };
    let Some((requests, approved, edit)) = held else {
        return;
    };
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
    let outcome = http.client.send_approved_ctl(cover, &w, &ctl).await;
    // Bodies of the outcomes that do not carry their response (§7.2: audit-only, T10 handoff).
    let received = ctl.take_captured().partial;
    settle_execution(engine, entry, outcome, &received, edit).await;
}

/// The single source of truth for a write's outcome (§5.4 step 6, §7.2, §11.2).
async fn settle_execution(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    outcome: WriteOutcome,
    received: &[u8],
    edit: Option<EditView>,
) {
    let ctx = entry.ctx.clone();
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
        } => (
            Event::Executed(ExecOutcome::OutcomeUnknown),
            payloads::write_outcome_unknown(&ctx, request_index, &reason, None, received),
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
            )
            .await;
            return;
        }
    };
    let _ = finish(engine, entry, event, record, kind).await;
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
    spec: &'static OperationSpec,
    alias: String,
    params: Value,
    view: EditView,
    rendered: Option<Vec<HttpRequestSpec>>,
    pat: bool,
) -> impl FnOnce(&mut EntryState) + Send + 'static {
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
        let ok = approvable(st, pat);
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
