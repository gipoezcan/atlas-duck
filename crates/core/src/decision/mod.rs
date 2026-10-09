//! The Rust decision API (C.7, §2.4, §5.6): the only way a human decision reaches the engine.
//! The approvals UI (M6) and the scripted approver call it, nothing else.
//!
//! Task 19 declared the contract and the queue; Task 21 decides reads (preview, raw pages,
//! release, release with redactions, deny); Task 22 writes (preview, approve, edit, deny with
//! hints); batches are Task 23. Every return type is `Serialize` (PD-12: the capture hook
//! records them).
//!
//! The trait is synchronous (PD-13): each call runs its async part on the core's runtime
//! (`Engine::run_sync`). Every decision steps a clone of the model first (PD-19): a rejection is
//! logged as `DECISION_STALE` / `DECISION_INVALID` where §8.3 says so and changes nothing; an
//! accepted one commits its record through `Engine::transition` before anything else happens.
//!
//! **Redactions (plan decision, PD-20 analogue).** A `Release`/`ReleaseRedacted` decision whose
//! `redactions` differ from the current revision's ops does not release: it applies the ops to
//! the normalized body as a new revision (`CandidateChanged`, inv. 5) and answers `pending`; that
//! revision must be opened (`preview_fetch`) and then released with the same ops (or `None`).
//! Ops that block (§5.3 checks, an outcome item) are `DECISION_INVALID {not_approvable}`.

use std::path::PathBuf;
use std::sync::Arc;

use atlas_duck_audit::{AuditError, NewEvent};
use atlas_duck_ipc::envelope::{ErrorCode, Status};
use atlas_duck_preview::invisible::strip;
use atlas_duck_preview::{
    CandidateRev, PREVIEW_BUILDER_VERSION, Preview, RAW_PAGE_BYTES, RawPager,
};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use serde_json::Value;

use crate::edit::{EditError, Edits, apply_edits};
use crate::engine::cache::{Candidate, RebuildError, build_redacted, source_body};
use crate::engine::read::{
    OUTCOME_HINT, ReadContext, caution_count, normalizer, preview_model, release_meta,
};
use crate::engine::write;
use crate::engine::{Engine, EntryState, OnAuditFailure, RequestEntry, TransitionError};
use crate::gate::UiEvent;
use crate::lifecycle::model::{Event, Hold, Kind, Phase, Rejection, ReleaseItem, is_pending, step};
use crate::ops::{ExecError, op_table};
use crate::payloads::{self, InvalidReason, ReleasedItem, SubmittedDecision};
use crate::redact::RedactionOp;
use crate::validate::{EffectiveCaps, ValidateCtx, ValidationError, echo};

/// Maps to the audit `decision` values (C.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Approve,
    ApproveEdited,
    Release,
    ReleaseRedacted,
    Deny,
}

/// The deny-hint choices of §5.4/§6.3/§11.2 (PD-20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyDetails {
    UpstreamHttp {
        include_messages: bool,
    },
    OutcomeHint,
    ResolutionFailed {
        include_candidates: bool,
    },
    /// M5.
    MissingFields {
        include_allowed_values: bool,
    },
}

/// One decision (C.7 + PD-20). `edits: Some` applies the edit and returns the new revision; it
/// never approves in the same call.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub request_id: String,
    pub decision: DecisionKind,
    pub candidate_rev: CandidateRev,
    pub edits: Option<Edits>,
    pub redactions: Option<Vec<RedactionOp>>,
    pub reason: Option<String>,
    pub deny_details: Option<DenyDetails>,
}

/// §5.6 session: `agent_name` + `peer_origin_exe` (MCP: `connection_id`) + `cwd_basename`, all
/// normalized agent-side values.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct SessionKey {
    pub agent_name: Option<String>,
    pub peer_origin_exe: Option<PathBuf>,
    /// MCP only.
    pub connection_id: Option<String>,
    pub cwd_basename: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchItem {
    pub request_id: String,
    pub candidate_rev: CandidateRev,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionOutcome {
    pub request_id: String,
    pub status: Status,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BatchOutcome {
    pub batch_id: String,
    pub items: Vec<DecisionOutcome>,
}

/// Handed out only after `PREVIEW_SHOWN` is committed (§5.6 "opened").
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewDelivery {
    pub preview: Preview,
}

/// An exact slice of the hashed candidate bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawPage {
    pub page: u64,
    pub page_count: u64,
    pub total_bytes: u64,
    pub bytes: Vec<u8>,
}

/// Why one batch item failed the all-or-nothing check (L43).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchFailure {
    Stale,
    Invalid(InvalidReason),
    NotPending,
}

impl Serialize for BatchFailure {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Stale => s.serialize_str("stale"),
            Self::Invalid(r) => s.serialize_str(r.as_str()),
            Self::NotPending => s.serialize_str("not_pending"),
        }
    }
}

/// C.7 (+ PD-29 `NotDecidable`).
#[derive(Debug, Clone, PartialEq)]
pub enum DecisionError {
    Stale {
        current: CandidateRev,
    },
    Invalid(InvalidReason),
    EditRejected(ValidationError),
    Audit(AuditError),
    BatchRejected {
        failed: Vec<(String, BatchFailure)>,
    },
    Cancelled,
    /// The request is not waiting for a decision (`Enriching`, `StaleCheck`, `Executing`,
    /// terminal, or unknown): nothing logged, nothing stepped (PD-29).
    NotDecidable,
}

/// `{kind, ..}`; an `AuditError` is reduced to its kind (its text can name paths).
impl Serialize for DecisionError {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        match self {
            Self::Stale { current } => {
                m.serialize_entry("kind", "stale")?;
                m.serialize_entry("current", current)?;
            }
            Self::Invalid(r) => {
                m.serialize_entry("kind", "invalid")?;
                m.serialize_entry("reason", r.as_str())?;
            }
            Self::EditRejected(e) => {
                m.serialize_entry("kind", "edit_rejected")?;
                m.serialize_entry("error", e)?;
            }
            Self::Audit(_) => m.serialize_entry("kind", "audit")?,
            Self::BatchRejected { failed } => {
                m.serialize_entry("kind", "batch_rejected")?;
                m.serialize_entry("failed", failed)?;
            }
            Self::Cancelled => m.serialize_entry("kind", "cancelled")?,
            Self::NotDecidable => m.serialize_entry("kind", "not_decidable")?,
        }
        m.end()
    }
}

/// The row `queue_list` returns (C.7, plan-named fields). Agent strings are the normalized ones
/// (§3.3) and are marked unverified; nothing here goes to an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueueItem {
    pub request_id: String,
    pub op_id: String,
    /// `"read"`, `"write"` or `"script"`.
    pub class: &'static str,
    pub instance_alias: String,
    pub target_display: String,
    pub agent_name: Option<String>,
    /// Always `true` (§2.4: every agent string is self-reported).
    pub agent_unverified: bool,
    pub reason_excerpt: Option<String>,
    /// Something was stripped or cut from an agent string (§3.3).
    pub unusual: bool,
    pub age_s: u64,
    /// The item returned to the queue after a stale check (§5.4 step 5; Task 22).
    pub stale: bool,
    /// Caution-level warnings of the current revision (Tasks 21/22).
    pub caution_count: u32,
    /// Task 23.
    pub possible_duplicate_of: Option<String>,
    /// Task 23.
    pub similar_to: Option<String>,
    pub session: SessionKey,
    pub opened: bool,
    pub approvable: bool,
    pub candidate_rev: CandidateRev,
}

/// C.7. Synchronous (PD-13): callers are never on a UI thread (M6 uses `spawn_blocking`).
pub trait DecisionApi: Send + Sync {
    fn queue_list(&self) -> Vec<QueueItem>;
    fn queue_get(&self, request_id: &str) -> Option<QueueItem>;
    /// Commits `PREVIEW_SHOWN` before delivery; this is "opened" (Task 21).
    fn preview_fetch(
        &self,
        request_id: &str,
        rev: Option<CandidateRev>,
    ) -> Result<PreviewDelivery, DecisionError>;
    fn raw_page(
        &self,
        request_id: &str,
        rev: CandidateRev,
        page: u64,
    ) -> Result<RawPage, DecisionError>;
    fn decide(&self, d: Decision) -> Result<DecisionOutcome, DecisionError>;
    /// All or nothing (L43, Task 23).
    fn decide_batch(&self, items: Vec<BatchItem>) -> Result<BatchOutcome, DecisionError>;
    /// No dialog, per item, not all-or-nothing (L43).
    fn deny_batch(&self, request_ids: &[String], reason: &str) -> Result<usize, DecisionError>;
    fn deny_session(&self, session: SessionKey, reason: &str) -> Result<usize, DecisionError>;
    /// In memory, not audited.
    fn acknowledge_attention(&self, request_ids: &[String]);
}

/// The core's `DecisionApi` (reads from Task 21; writes Task 22, batches Task 23).
pub struct CoreDecisions {
    engine: Arc<Engine>,
}

impl CoreDecisions {
    pub(crate) fn new(engine: Arc<Engine>) -> CoreDecisions {
        CoreDecisions { engine }
    }
}

/// An item waits for a human only in `AwaitingRelease` / `AwaitingApproval` (§5.1).
fn decidable(p: Phase) -> bool {
    matches!(p, Phase::AwaitingRelease(_) | Phase::AwaitingApproval(_))
}

/// The queue row of an entry that waits for a decision.
fn in_queue(e: &RequestEntry) -> Option<QueueItem> {
    let st = e.state();
    let m = &st.model;
    if !decidable(m.phase()) {
        return None;
    }
    Some(QueueItem {
        request_id: e.head.request_id.clone(),
        op_id: e.head.op_id.clone(),
        class: e.class(),
        instance_alias: e.head.instance.clone(),
        target_display: e.target_display.clone(),
        agent_name: e.agent_name.clone(),
        agent_unverified: true,
        reason_excerpt: e.reason_excerpt.clone(),
        unusual: e.unusual,
        age_s: e.age().as_secs(),
        stale: st.stale,
        caution_count: st.caution_count,
        possible_duplicate_of: None,
        similar_to: None,
        session: e.session.clone(),
        opened: m.opened(),
        approvable: st.approvable(),
        candidate_rev: current_rev(&st),
    })
}

fn current_rev(st: &EntryState) -> CandidateRev {
    CandidateRev {
        counter: st.model.rev(),
        candidate_hash: st.candidate_hash,
    }
}

fn task_failed() -> DecisionError {
    DecisionError::Audit(AuditError::AppendFailed(
        "the decision could not run (no multi-thread core runtime, or its task died)".into(),
    ))
}

/// What a decision is checked against, read under one lock.
#[derive(Debug, Clone, Copy)]
struct Snapshot {
    current: CandidateRev,
    phase: Phase,
    /// The current revision carries redaction ops.
    redacted: bool,
}

fn snapshot(st: &EntryState) -> Snapshot {
    Snapshot {
        current: current_rev(st),
        phase: st.model.phase(),
        redacted: !st.redaction_ops.is_empty(),
    }
}

/// Steps a clone with the event `event` builds from the snapshot (nothing changes), under the
/// lock the snapshot is taken in, so a rejection names the revision it was checked against. A
/// submitted revision is current only if its counter **and** its hash are (inv. 5);
/// approvability follows `EntryState::approvable`.
fn dry_step(
    entry: &RequestEntry,
    event: impl FnOnce(&Snapshot) -> Event,
    submitted: Option<&CandidateRev>,
) -> Result<Snapshot, (Rejection, Snapshot)> {
    let st = entry.state();
    let snap = snapshot(&st);
    if let Some(r) = submitted
        && r.counter == st.model.rev()
        && r.candidate_hash != st.candidate_hash
    {
        let r = Rejection::StaleRev {
            current: st.model.rev(),
        };
        return Err((r, snap));
    }
    let mut m = st.model.clone();
    if st.rebuild_failed {
        m.set_approvable(false);
    }
    match step(&mut m, event(&snap)) {
        Ok(_) => Ok(snap),
        Err(r) => Err((r, snap)),
    }
}

/// A rejected decision (PD-19): `StaleRev` → `DECISION_STALE`; `NotOpened` / `NotApprovable` /
/// `TargetParamEdit` → `DECISION_INVALID {reason}`; `Illegal` on a pending request in a phase
/// where no decision applies (`Validated`, `Fetching`, `Enriching`, `StaleCheck`, `Executing`)
/// → `DECISION_STALE` (the M-3 exception); any other `Illegal` (a decision kind the item does
/// not take, a terminal request) and every preview refusal but a stale one → nothing logged.
/// Nothing else changes. The snapshot is the state the rejection was decided on.
async fn rejected(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    (r, at): (Rejection, Snapshot),
    submitted: u64,
    decision: SubmittedDecision,
) -> DecisionError {
    let (current, phase) = (at.current, at.phase);
    let ctx = &entry.ctx;
    let stale = || payloads::decision_stale(ctx, submitted, current.counter, decision, false);
    let invalid = |reason| payloads::decision_invalid(ctx, reason, submitted, decision, false);
    let (record, err): (Option<NewEvent>, DecisionError) = match r {
        Rejection::StaleRev { .. } => (Some(stale()), DecisionError::Stale { current }),
        Rejection::NotOpened if decision != SubmittedDecision::Preview => (
            Some(invalid(InvalidReason::NotOpened)),
            DecisionError::Invalid(InvalidReason::NotOpened),
        ),
        Rejection::NotApprovable if decision != SubmittedDecision::Preview => (
            Some(invalid(InvalidReason::NotApprovable)),
            DecisionError::Invalid(InvalidReason::NotApprovable),
        ),
        Rejection::TargetParamEdit => (
            Some(invalid(InvalidReason::TargetParamEdit)),
            DecisionError::Invalid(InvalidReason::TargetParamEdit),
        ),
        Rejection::Illegal
            if decision != SubmittedDecision::Preview && is_pending(phase) && !decidable(phase) =>
        {
            (Some(stale()), DecisionError::Stale { current })
        }
        _ => (None, DecisionError::NotDecidable),
    };
    if let Some(ev) = record
        && let Err(e) = engine.blocking(move |p| p.append(ev)).await
    {
        return DecisionError::Audit(e);
    }
    err
}

/// A transition error of an accepted dry step: the model moved on meanwhile.
async fn transition_failed(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    e: TransitionError,
    submitted: u64,
    decision: SubmittedDecision,
) -> DecisionError {
    match e {
        TransitionError::Rejected(r) => {
            let at = snapshot(&entry.state());
            rejected(engine, entry, (r, at), submitted, decision).await
        }
        // The record committed for a revision that is no longer current (PD-19 re-step).
        TransitionError::Raced(_) => DecisionError::Stale {
            current: current_rev(&entry.state()),
        },
        TransitionError::Audit(e) => DecisionError::Audit(e),
    }
}

/// The current candidate: cached, or rebuilt from the committed record (§5.2). A permanent
/// rebuild failure has disabled Release (`rebuild_failed`).
async fn candidate(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
) -> Result<Arc<Candidate>, RebuildError> {
    engine.candidate(entry, normalizer(entry.spec)).await
}

fn read_context(entry: &RequestEntry) -> (&Value, ReadContext<'_>) {
    let params = entry.validated.as_ref().map_or(&Value::Null, |v| &v.params);
    (
        params,
        ReadContext {
            spec: entry.spec,
            alias: &entry.head.instance,
            params,
            target_display: &entry.target_display,
        },
    )
}

fn queue_changed(engine: &Engine, entry: &RequestEntry) {
    engine.ui().emit(UiEvent::QueueChanged {
        request_ids: vec![entry.head.request_id.clone()],
    });
}

/// What a preview delivery shows: the preview, the revision it shows and whether that revision
/// was opened before. `None` = the revision moved on while it was built.
type Built = Option<(Preview, CandidateRev, bool)>;

/// A read's preview: its candidate (rebuilt if evicted) through the op's previewer or the cards.
async fn read_preview(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    submitted: u64,
) -> Result<Built, DecisionError> {
    let c = match candidate(engine, entry).await {
        Ok(c) => c,
        Err(RebuildError::Audit(e)) => return Err(DecisionError::Audit(e)),
        // §5.2: the item failed closed; only Deny remains (M6 shows the `internal` banner).
        Err(_) => return Err(DecisionError::Invalid(InvalidReason::NotApprovable)),
    };
    let built = {
        let st = entry.state();
        if st.model.rev() != submitted || &st.candidate_hash != c.hash() {
            None
        } else {
            st.read
                .clone()
                .map(|read| (read, current_rev(&st), st.approvable(), st.model.opened()))
        }
    };
    let Some((read, shown, approvable, opened)) = built else {
        return Ok(None);
    };
    let (_, cx) = read_context(entry);
    let model = preview_model(&cx, &read, &c);
    let preview = Preview {
        candidate_rev: shown,
        approvable,
        raw: RawPager::for_total(u64::try_from(c.bytes().len()).unwrap_or(u64::MAX)),
        header: model.header,
        warnings: model.warnings,
        body: model.body,
        also_appears_in: read.also_appears_in.clone(),
        preview_builder_version: PREVIEW_BUILDER_VERSION.to_owned(),
    };
    Ok(Some((preview, shown, opened)))
}

/// A write's preview (§6.3, §5.6): the exact request list or the hold's card, led by the reason
/// it came back, "executes as" the instance's PAT user, Raw over the list as `WRITE_APPROVED`
/// stores it (`write::raw_bytes`).
async fn write_preview(engine: &Arc<Engine>, entry: &Arc<RequestEntry>, submitted: u64) -> Built {
    let identity = write::stored_identity(engine, entry).await;
    let built = {
        let st = entry.state();
        match (st.model.phase(), &st.write) {
            (Phase::AwaitingApproval(hold), Some(w)) if st.model.rev() == submitted => Some((
                w.clone(),
                hold,
                current_rev(&st),
                st.approvable(),
                st.model.opened(),
            )),
            _ => None,
        }
    };
    let (w, hold, shown, approvable, opened) = built?;
    let executes_as = identity.as_ref().map(|i| i.atlassian_user.as_str());
    let model = write::preview_model(entry.spec, &entry.head.instance, &w, hold, executes_as);
    let raw = write::raw_bytes(&w.requests);
    let preview = Preview {
        candidate_rev: shown,
        approvable,
        raw: RawPager::for_total(u64::try_from(raw.len()).unwrap_or(u64::MAX)),
        header: model.header,
        warnings: model.warnings,
        body: model.body,
        also_appears_in: Vec::new(),
        preview_builder_version: PREVIEW_BUILDER_VERSION.to_owned(),
    };
    Some((preview, shown, opened))
}

/// Step 6 (PD-19 order, PD-29): a dry step first, so no `PREVIEW_SHOWN` is ever committed for
/// an event the model rejects; then the candidate (rebuilt if evicted) and the preview; then
/// `PREVIEW_SHOWN` through `transition` (re-step, never overwrite). An append failure leaves
/// the request as it was and "opened" clear (§5.6).
async fn preview_fetch(
    engine: Arc<Engine>,
    id: String,
    rev: Option<CandidateRev>,
) -> Result<PreviewDelivery, DecisionError> {
    let entry = engine.entry(&id).ok_or(DecisionError::NotDecidable)?;
    let submitted = rev.map_or_else(|| entry.state().model.rev(), |r| r.counter);
    let event = Event::PreviewShown { rev: submitted };
    if let Err(rej) = dry_step(&entry, |_| event, rev.as_ref()) {
        return Err(rejected(&engine, &entry, rej, submitted, SubmittedDecision::Preview).await);
    }
    let built = match entry.kind() {
        Kind::Read => read_preview(&engine, &entry, submitted).await?,
        Kind::Write => write_preview(&engine, &entry, submitted).await,
        // Task 27 previews scripts.
        Kind::Script | Kind::DryRun => return Err(DecisionError::NotDecidable),
    };
    let Some((preview, shown, opened)) = built else {
        let at = snapshot(&entry.state());
        let r = Rejection::StaleRev {
            current: at.current.counter,
        };
        let dec = SubmittedDecision::Preview;
        return Err(rejected(&engine, &entry, (r, at), submitted, dec).await);
    };
    // §5.6: only the first delivery of a revision commits `PREVIEW_SHOWN`.
    if opened {
        return Ok(PreviewDelivery { preview });
    }
    let warning_ids: Vec<String> = preview
        .warnings
        .iter()
        .filter_map(|w| serde_json::to_value(w.id).ok())
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    let ctx = entry.ctx.clone();
    let shown_rec = move |_: &crate::lifecycle::model::Model| {
        vec![payloads::preview_shown(
            &ctx,
            &shown,
            &warning_ids,
            PREVIEW_BUILDER_VERSION,
        )]
    };
    match engine
        .transition_with(
            &entry,
            event,
            shown_rec,
            OnAuditFailure::KeepRequest,
            |_| {},
        )
        .await
    {
        Ok(_) => Ok(PreviewDelivery { preview }),
        Err(e) => {
            Err(transition_failed(&engine, &entry, e, submitted, SubmittedDecision::Preview).await)
        }
    }
}

/// Step 7: an exact slice of the current, opened revision's bytes; no record.
async fn raw_page(
    engine: Arc<Engine>,
    id: String,
    rev: CandidateRev,
    page: u64,
) -> Result<RawPage, DecisionError> {
    let entry = engine.entry(&id).ok_or(DecisionError::NotDecidable)?;
    if !matches!(entry.kind(), Kind::Read | Kind::Write) {
        return Err(DecisionError::NotDecidable);
    }
    let write_raw = {
        let st = entry.state();
        if !decidable(st.model.phase()) {
            return Err(DecisionError::NotDecidable);
        }
        if current_rev(&st) != rev {
            return Err(DecisionError::Stale {
                current: current_rev(&st),
            });
        }
        if !st.model.opened() {
            return Err(DecisionError::Invalid(InvalidReason::NotOpened));
        }
        // A write's Raw is its request list (plan decision, `write::raw_bytes`).
        st.write.as_ref().map(|w| write::raw_bytes(&w.requests))
    };
    let bytes: Arc<[u8]> = match write_raw {
        Some(raw) => raw.into(),
        None => {
            let c = match candidate(&engine, &entry).await {
                Ok(c) => c,
                Err(RebuildError::Audit(e)) => return Err(DecisionError::Audit(e)),
                Err(_) => return Err(DecisionError::Invalid(InvalidReason::NotApprovable)),
            };
            if c.hash() != &rev.candidate_hash {
                return Err(DecisionError::Stale {
                    current: current_rev(&entry.state()),
                });
            }
            c.bytes().clone()
        }
    };
    let total = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let pager = RawPager::for_total(total);
    let from = page.saturating_mul(RAW_PAGE_BYTES).min(total);
    let to = from.saturating_add(RAW_PAGE_BYTES).min(total);
    let slice = usize::try_from(from)
        .ok()
        .zip(usize::try_from(to).ok())
        .and_then(|(a, b)| bytes.get(a..b))
        .unwrap_or_default();
    Ok(RawPage {
        page,
        page_count: pager.page_count,
        total_bytes: total,
        bytes: slice.to_vec(),
    })
}

async fn decide(engine: Arc<Engine>, d: Decision) -> Result<DecisionOutcome, DecisionError> {
    let entry = engine
        .entry(&d.request_id)
        .ok_or(DecisionError::NotDecidable)?;
    match entry.kind() {
        Kind::Read => {}
        Kind::Write => return decide_write(&engine, &entry, d).await,
        // Task 27 decides scripts.
        Kind::Script | Kind::DryRun => return Err(DecisionError::NotDecidable),
    }
    match d.decision {
        DecisionKind::Deny => deny(&engine, &entry, &d).await,
        DecisionKind::Release | DecisionKind::ReleaseRedacted if d.edits.is_none() => {
            let current_ops = entry.state().redaction_ops.clone();
            match d.redactions {
                Some(ops) if ops != current_ops => {
                    redact(&engine, &entry, d.candidate_rev, ops).await
                }
                _ => release(&engine, &entry, d.candidate_rev).await,
            }
        }
        // A read takes no approval and no edit.
        _ => Err(DecisionError::NotDecidable),
    }
}

fn outcome(entry: &RequestEntry) -> DecisionOutcome {
    DecisionOutcome {
        request_id: entry.head.request_id.clone(),
        status: entry.agent_status(),
    }
}

/// Step 8: `READ_RELEASED` with the exact candidate bytes (a rebuild first if evicted; a hash
/// mismatch disables Release, §5.2), then `Release`; watchers wake.
async fn release(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    rev: CandidateRev,
) -> Result<DecisionOutcome, DecisionError> {
    let dec = SubmittedDecision::Release;
    let release = |snap: &Snapshot| Event::Release {
        rev: rev.counter,
        redacted: snap.redacted,
    };
    let event = match dry_step(entry, release, Some(&rev)) {
        Ok(snap) => release(&snap),
        Err(rej) => return Err(rejected(engine, entry, rej, rev.counter, dec).await),
    };
    let c = match candidate(engine, entry).await {
        Ok(c) => c,
        Err(RebuildError::Audit(e)) => return Err(DecisionError::Audit(e)),
        Err(_) => {
            let rej = (Rejection::NotApprovable, snapshot(&entry.state()));
            return Err(rejected(engine, entry, rej, rev.counter, dec).await);
        }
    };
    if c.hash() != &rev.candidate_hash {
        let at = snapshot(&entry.state());
        let r = Rejection::StaleRev {
            current: at.current.counter,
        };
        return Err(rejected(engine, entry, (r, at), rev.counter, dec).await);
    }
    let (read, ops) = {
        let st = entry.state();
        (st.read.clone(), st.redaction_ops.clone())
    };
    let Some(read) = read else {
        return Err(DecisionError::NotDecidable);
    };
    let ctx = &entry.ctx;
    let record = match read.item {
        ReleaseItem::Outcome => {
            let code = c
                .value()
                .get("code")
                .cloned()
                .and_then(|v| serde_json::from_value::<ErrorCode>(v).ok())
                .ok_or(DecisionError::NotDecidable)?;
            payloads::read_released_outcome(ctx, code, OUTCOME_HINT)
        }
        item => {
            let marker = if item == ReleaseItem::UpstreamError {
                ReleasedItem::UpstreamError
            } else {
                ReleasedItem::Result
            };
            let meta = release_meta(entry.spec, &read, c.value());
            payloads::read_released_item(ctx, c.bytes(), &ops, marker, &meta)
                .map_err(|_| DecisionError::Audit(AuditError::Invalid("release record")))?
        }
    };
    match engine.transition(entry, event, move |_| record).await {
        Ok(_) => {
            queue_changed(engine, entry);
            Ok(outcome(entry))
        }
        Err(e) => Err(transition_failed(engine, entry, e, rev.counter, dec).await),
    }
}

/// `READ_DENIED {reason}`, then `Deny` (`denied`, exit 3, the reason as message).
async fn deny(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    d: &Decision,
) -> Result<DecisionOutcome, DecisionError> {
    let rev = d.candidate_rev;
    let event = Event::Deny { rev: rev.counter };
    let dec = SubmittedDecision::Deny;
    if let Err(rej) = dry_step(entry, |_| event, Some(&rev)) {
        return Err(rejected(engine, entry, rej, rev.counter, dec).await);
    }
    // The human's reason reaches the agent: flagged characters are stripped as for the agent's
    // own `reason` (§3.3 rule, newlines kept; review M-1 ruling).
    let reason = d.reason.as_deref().map(|r| strip(r, true).0);
    let record = payloads::read_denied(&entry.ctx, reason.as_deref());
    match engine.transition(entry, event, move |_| record).await {
        Ok(_) => {
            queue_changed(engine, entry);
            Ok(outcome(entry))
        }
        Err(e) => Err(transition_failed(engine, entry, e, rev.counter, dec).await),
    }
}

/// A new set of redaction ops on the normalized body: a new revision (`CandidateChanged`, inv.
/// 5) that must be opened before it can be released. No record: the ops are recorded with the
/// release (`READ_RELEASED.redaction_ops`).
async fn redact(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    rev: CandidateRev,
    ops: Vec<RedactionOp>,
) -> Result<DecisionOutcome, DecisionError> {
    let dec = SubmittedDecision::Release;
    let at = match dry_step(entry, |_| Event::CandidateChanged, Some(&rev)) {
        Ok(snap) => snap,
        Err(rej) => return Err(rejected(engine, entry, rej, rev.counter, dec).await),
    };
    let read = entry.state().read.clone();
    let Some(read) = read else {
        return Err(DecisionError::NotDecidable);
    };
    // An outcome item has no content to redact (§5.2 step 6: Release outcome or Deny).
    if read.item == ReleaseItem::Outcome {
        return Err(rejected(
            engine,
            entry,
            (Rejection::NotApprovable, at),
            rev.counter,
            dec,
        )
        .await);
    }
    let (spec, id) = (entry.spec, entry.head.request_id.clone());
    let base = engine
        .blocking(move |p| Ok(source_body(p, &id, normalizer(spec))))
        .await
        .map_err(DecisionError::Audit)?;
    let base = match base {
        Ok(b) => b,
        Err(RebuildError::Audit(e)) => return Err(DecisionError::Audit(e)),
        Err(_) => {
            return Err(rejected(
                engine,
                entry,
                (Rejection::NotApprovable, at),
                rev.counter,
                dec,
            )
            .await);
        }
    };
    // T14 handoff: on the bare body, with the op's `items_key`; heavy for big candidates. The
    // rebuild path's own function (`cache::build_redacted`), so a rebuild reproduces the hash.
    let applied = tokio::task::spawn_blocking(move || {
        build_redacted(spec, base, &ops).map(|(c, report)| (c, report, ops))
    })
    .await;
    let (c, report, ops) = match applied {
        Ok(Ok(built)) => built,
        // §5.3 checks failed (mirror, every-occurrence mask, encodings, missing targets), or the
        // redacted candidate is over the 16 MiB release cap.
        Ok(Err(RebuildError::Blocked)) => {
            return Err(rejected(
                engine,
                entry,
                (Rejection::NotApprovable, at),
                rev.counter,
                dec,
            )
            .await);
        }
        _ => return Err(DecisionError::Audit(AuditError::Invalid("redaction"))),
    };
    let (redaction_meta, also_appears_in) = match report {
        Some(r) => (Some(r.meta), r.also_appears_in),
        None => (None, Vec::new()),
    };
    let new_read = crate::engine::read::ReadState {
        redaction_meta,
        also_appears_in,
        ..read
    };
    let (_, cx) = read_context(entry);
    let caution = caution_count(&preview_model(&cx, &new_read, &c));
    let c = Arc::new(c);
    let (cache, id) = (engine.clone(), entry.head.request_id.clone());
    let applied = engine
        .step_unlogged(
            entry,
            Event::CandidateChanged,
            Some(rev.counter),
            move |st| {
                st.candidate_hash = *c.hash();
                st.redaction_ops = ops;
                st.rebuild_failed = false;
                st.caution_count = caution;
                st.read = Some(new_read);
                st.model.set_approvable(true);
                cache.candidates().insert(&id, c);
            },
        )
        .await;
    match applied {
        Ok(_) => {
            queue_changed(engine, entry);
            Ok(outcome(entry))
        }
        Err(r) => {
            let at = snapshot(&entry.state());
            Err(rejected(engine, entry, (r, at), rev.counter, dec).await)
        }
    }
}

// ---- writes (Task 22) ----------------------------------------------------------------------------

/// Plan wording: a deny hint the current hold has no data for (the UI offers only the ones that
/// apply; refused like a malformed edit, nothing logged).
const MSG_HINT_NOT_APPLICABLE: &str = "these deny details do not apply to this request";
/// Plan wording: redaction ops sent with a write decision (review M-6).
const MSG_NO_WRITE_REDACTIONS: &str = "redactions do not apply to a write decision";
/// Plan wording: an edit key that is not a param name or `<object param>.<sub>`.
const MSG_BAD_EDIT_KEY: &str = "not an editable param";

/// §5.4 step 4: approve, edit (a new revision; it never approves in the same call, PD-20) or
/// deny. A write takes no release.
async fn decide_write(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    d: Decision,
) -> Result<DecisionOutcome, DecisionError> {
    // A write has no release candidate to redact; deny details are "redacted" only through the
    // `DenyDetails` include toggles in v1 (M6 owns finer masking). Refused rather than dropped.
    if d.redactions.as_ref().is_some_and(|ops| !ops.is_empty()) {
        return Err(edit_refused(MSG_NO_WRITE_REDACTIONS, "redactions"));
    }
    match (d.decision, d.edits) {
        (DecisionKind::Deny, _) => {
            deny_write(
                engine,
                entry,
                d.candidate_rev,
                d.reason.as_deref(),
                d.deny_details,
            )
            .await
        }
        (DecisionKind::Approve | DecisionKind::ApproveEdited, Some(edits)) => {
            edit_write(engine, entry, d.candidate_rev, &edits).await
        }
        (DecisionKind::Approve | DecisionKind::ApproveEdited, None) => {
            approve_write(engine, entry, d.candidate_rev).await
        }
        (DecisionKind::Release | DecisionKind::ReleaseRedacted, _) => {
            Err(DecisionError::NotDecidable)
        }
    }
}

/// `WRITE_APPROVED {candidate_rev, request_set_hash, requests}` (decision `approve`, or
/// `approve_edited` for a write that was ever edited) commits before anything is sent (§5.1 inv.
/// 1, 3); then the stale check starts on the core runtime.
async fn approve_write(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    rev: CandidateRev,
) -> Result<DecisionOutcome, DecisionError> {
    let dec = SubmittedDecision::Approve;
    let event = Event::Approve { rev: rev.counter };
    if let Err(rej) = dry_step(entry, |_| event, Some(&rev)) {
        return Err(rejected(engine, entry, rej, rev.counter, dec).await);
    }
    let Some((records, hash, edited)) = write::approval(entry) else {
        return Err(DecisionError::NotDecidable);
    };
    // Inv. 3: the list approved is the list of the revision shown.
    if hash != rev.candidate_hash {
        let at = snapshot(&entry.state());
        let r = Rejection::StaleRev {
            current: at.current.counter,
        };
        return Err(rejected(engine, entry, (r, at), rev.counter, dec).await);
    }
    let ctx = entry.ctx.clone();
    let record = move |_: &crate::lifecycle::model::Model| {
        vec![payloads::write_approved(&ctx, &rev, &records, edited)]
    };
    match engine
        .transition_with(
            entry,
            event,
            record,
            OnAuditFailure::FailRequest,
            write::approve_apply(hash),
        )
        .await
    {
        Ok(_) => {
            queue_changed(engine, entry);
            write::start_stale_check(engine, entry, rev.counter);
            Ok(outcome(entry))
        }
        Err(e) => Err(transition_failed(engine, entry, e, rev.counter, dec).await),
    }
}

fn edit_refused(message: &str, param: &str) -> DecisionError {
    let mut details = serde_json::Map::new();
    details.insert("param".into(), Value::from(param));
    DecisionError::EditRejected(ValidationError {
        code: ErrorCode::Validation,
        message: message.to_owned(),
        details,
    })
}

fn exec_refused(e: ExecError) -> DecisionError {
    match e {
        ExecError::Invalid(v) => DecisionError::EditRejected(v),
        other => DecisionError::EditRejected(ValidationError {
            code: ErrorCode::Internal,
            message: other.to_string(),
            details: serde_json::Map::new(),
        }),
    }
}

/// §5.4 step 4: the edit applied to the current params (targets and baselines immutable, T15),
/// re-validated, checked by the op's executor, then `WRITE_EDITED {original, edited}` and either
/// the new list rendered with the latest verdict (`Edit`, a new revision) or a re-enrichment
/// (`Edit {rerun}`, `PREVIEW_FETCH {purpose: enrich}`, PD-24). A malformed key or invalid params
/// leave the request unchanged and log nothing (T15 handoff); a target or baseline edit is
/// `DECISION_INVALID {target_param_edit}`.
async fn edit_write(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    rev: CandidateRev,
    edits: &Edits,
) -> Result<DecisionOutcome, DecisionError> {
    let dec = SubmittedDecision::Edit;
    let probe = Event::Edit {
        rev: rev.counter,
        target_or_baseline_changed: false,
        rerun_enrichment: false,
    };
    let at = match dry_step(entry, |_| probe, Some(&rev)) {
        Ok(at) => at,
        Err(rej) => return Err(rejected(engine, entry, rej, rev.counter, dec).await),
    };
    let (Some(snap), Some(op)) = (write::snapshot(entry), op_table().get(entry.spec.id)) else {
        return Err(DecisionError::NotDecidable);
    };
    let spec = entry.spec;
    let version = engine
        .instances()
        .by_id(&entry.instance_id)
        .and_then(|i| i.version);
    let caps = EffectiveCaps::default();
    let vctx = ValidateCtx {
        instance_version: version,
        caps: &caps,
        for_script: false,
    };
    let agent = entry
        .validated
        .as_ref()
        .map_or(Value::Null, |v| v.params.clone());
    let result = match apply_edits(
        spec,
        &agent,
        &snap.write.params,
        edits,
        op.enrich_keys,
        &vctx,
    ) {
        Ok(r) => r,
        Err(EditError::TargetParamEdit) => {
            let r = (Rejection::TargetParamEdit, at);
            return Err(rejected(engine, entry, r, rev.counter, dec).await);
        }
        Err(EditError::Rejected(e)) => return Err(DecisionError::EditRejected(e)),
        Err(EditError::BadKey(key)) => return Err(edit_refused(MSG_BAD_EDIT_KEY, &key)),
    };
    // The op's own static checks (the validation dry call, T19 step 8), then the new list.
    let http = engine
        .client(&entry.instance_id)
        .await
        .map_err(|_| edit_refused("the instance cannot be reached from this build", "instance"))?;
    let base = http.client.base();
    let effective_max = entry.validated.as_ref().and_then(|v| v.effective_max);
    match write::render(spec, base, &result.params, None, effective_max) {
        Ok(_) | Err(ExecError::EnrichmentRequired) => {}
        Err(e) => return Err(exec_refused(e)),
    }
    let rendered = if result.rerun_enrichment {
        None
    } else if snap.write.verdict.hold == Hold::Preview {
        let verdict = Some(&snap.write.verdict);
        Some(
            write::render(spec, base, &result.params, verdict, effective_max)
                .map_err(exec_refused)?,
        )
    } else {
        Some(Vec::new())
    };
    let pat = write::stored_identity(engine, entry).await.is_some();
    let rerun = result.rerun_enrichment;
    let event = Event::Edit {
        rev: rev.counter,
        target_or_baseline_changed: false,
        rerun_enrichment: rerun,
    };
    // §5.4 step 4 "original + edited params": the agent's params on every edit (lead ruling 4).
    let (ctx, original, edited) = (entry.ctx.clone(), agent, result.params.clone());
    let record = move |_: &crate::lifecycle::model::Model| {
        vec![payloads::write_edited(&ctx, &original, &edited)]
    };
    let view = write::EditView {
        executed_params: result.executed_params,
        edited_keys: result.edited_keys,
    };
    let apply = write::edit_apply(engine.clone(), entry, result.params, view, rendered, pat);
    match engine
        .transition_with(entry, event, record, OnAuditFailure::FailRequest, apply)
        .await
    {
        Ok(_) => {
            queue_changed(engine, entry);
            if rerun {
                write::rerun(engine, entry);
            }
            Ok(outcome(entry))
        }
        Err(e) => Err(transition_failed(engine, entry, e, rev.counter, dec).await),
    }
}

/// §5.4 step 2: "no issue type named 'Bugg' in ABC" (app-generated; the value is the agent's).
fn resolution_message(params: &Value, param: &str, value: &str) -> String {
    let value = echo(value);
    let of = |name: &str| params.get(name).and_then(Value::as_str).unwrap_or_default();
    match param {
        "issuetype" => format!("no issue type named '{value}' in {}", of("project")),
        "transition" => format!("no transition named '{value}' for {}", of("key")),
        _ => format!("no {param} named '{value}'"),
    }
}

/// The hint a deny attaches (§5.4 step 2, §4.3), only one the current hold has the data for.
fn deny_hint(entry: &RequestEntry, details: DenyDetails) -> Result<Value, DecisionError> {
    let refuse = || edit_refused(MSG_HINT_NOT_APPLICABLE, "deny_details");
    let snap = write::snapshot(entry).ok_or(DecisionError::NotDecidable)?;
    let failure = snap.write.failure.as_ref();
    match (details, snap.hold) {
        (DenyDetails::UpstreamHttp { include_messages }, Some(Hold::EnrichmentError)) => {
            let card = failure
                .filter(|f| f.hint == write::FailureHint::UpstreamHttp)
                .map(|f| &f.card)
                .ok_or_else(refuse)?;
            let mut d = serde_json::Map::new();
            d.insert("status".into(), serde_json::json!(card.status));
            if include_messages {
                d.insert("error_messages".into(), Value::from(card.text.clone()));
            }
            Ok(serde_json::json!({ "code": "upstream_http", "details": d }))
        }
        (DenyDetails::OutcomeHint, Some(Hold::EnrichmentError)) => {
            let code = match failure.map(|f| f.hint) {
                Some(write::FailureHint::Outcome(code)) => code,
                _ => return Err(refuse()),
            };
            let message = match code {
                ErrorCode::ResultTooLarge => write::HINT_ENRICH_TOO_LARGE,
                ErrorCode::UpstreamUnavailable => write::HINT_ENRICH_UNPARSABLE,
                _ => write::HINT_ENRICH_NETWORK,
            };
            // Fixed message, no details, no size (§4.3, L25, L31).
            Ok(serde_json::json!({ "code": code, "message": message }))
        }
        (DenyDetails::ResolutionFailed { include_candidates }, Some(Hold::UnresolvedName)) => {
            let (param, value, _, candidates) =
                snap.write.verdict.unresolved.as_ref().ok_or_else(refuse)?;
            let mut d = serde_json::Map::new();
            d.insert("param".into(), Value::from(param.clone()));
            d.insert("value".into(), Value::from(echo(value)));
            d.insert(
                "message".into(),
                Value::from(resolution_message(&snap.write.params, param, value)),
            );
            if include_candidates {
                d.insert("candidates".into(), serde_json::json!(candidates));
            }
            Ok(serde_json::json!({ "code": "resolution_failed", "details": d }))
        }
        // `missing_fields` is M5's (createmeta required fields).
        _ => Err(refuse()),
    }
}

/// `WRITE_DENIED {reason, hint?}`, then `Deny` (`denied`, exit 3; with a hint its code).
async fn deny_write(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    rev: CandidateRev,
    reason: Option<&str>,
    details: Option<DenyDetails>,
) -> Result<DecisionOutcome, DecisionError> {
    let dec = SubmittedDecision::Deny;
    let event = Event::Deny { rev: rev.counter };
    if let Err(rej) = dry_step(entry, |_| event, Some(&rev)) {
        return Err(rejected(engine, entry, rej, rev.counter, dec).await);
    }
    let hint = details.map(|d| deny_hint(entry, d)).transpose()?;
    // The human's reason reaches the agent: stripped like the agent's own (review M-1 ruling).
    let reason = reason.map(|r| strip(r, true).0);
    let record = payloads::write_denied(&entry.ctx, reason.as_deref(), hint.as_ref());
    match engine.transition(entry, event, move |_| record).await {
        Ok(_) => {
            queue_changed(engine, entry);
            Ok(outcome(entry))
        }
        Err(e) => Err(transition_failed(engine, entry, e, rev.counter, dec).await),
    }
}

impl DecisionApi for CoreDecisions {
    fn queue_list(&self) -> Vec<QueueItem> {
        let mut items: Vec<QueueItem> = self
            .engine
            .pending_entries()
            .iter()
            .filter_map(|e| in_queue(e))
            .collect();
        items.sort_by(|a, b| {
            b.age_s
                .cmp(&a.age_s)
                .then_with(|| a.request_id.cmp(&b.request_id))
        });
        items
    }

    fn queue_get(&self, request_id: &str) -> Option<QueueItem> {
        self.engine.entry(request_id).and_then(|e| in_queue(&e))
    }

    fn preview_fetch(
        &self,
        request_id: &str,
        rev: Option<CandidateRev>,
    ) -> Result<PreviewDelivery, DecisionError> {
        let (engine, id) = (self.engine.clone(), request_id.to_owned());
        self.engine
            .run_sync(preview_fetch(engine, id, rev))
            .unwrap_or_else(|| Err(task_failed()))
    }

    fn raw_page(
        &self,
        request_id: &str,
        rev: CandidateRev,
        page: u64,
    ) -> Result<RawPage, DecisionError> {
        let (engine, id) = (self.engine.clone(), request_id.to_owned());
        self.engine
            .run_sync(raw_page(engine, id, rev, page))
            .unwrap_or_else(|| Err(task_failed()))
    }

    fn decide(&self, d: Decision) -> Result<DecisionOutcome, DecisionError> {
        let engine = self.engine.clone();
        self.engine
            .run_sync(decide(engine, d))
            .unwrap_or_else(|| Err(task_failed()))
    }

    fn decide_batch(&self, items: Vec<BatchItem>) -> Result<BatchOutcome, DecisionError> {
        Err(DecisionError::BatchRejected {
            failed: items
                .iter()
                .map(|i| (i.request_id.clone(), BatchFailure::NotPending))
                .collect(),
        })
    }

    fn deny_batch(&self, _request_ids: &[String], _reason: &str) -> Result<usize, DecisionError> {
        Ok(0)
    }

    fn deny_session(&self, _session: SessionKey, _reason: &str) -> Result<usize, DecisionError> {
        Ok(0)
    }

    fn acknowledge_attention(&self, _request_ids: &[String]) {}
}
