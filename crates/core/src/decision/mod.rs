//! The Rust decision API (C.7, §2.4, §5.6): the only way a human decision reaches the engine.
//! The approvals UI (M6) and the scripted approver call it, nothing else.
//!
//! Task 19 declared the contract and the queue; Task 21 decides reads (preview, raw pages,
//! release, release with redactions, deny); Task 22 writes (preview, approve, edit, deny with
//! hints); Task 23 batches (`batch`) and the "possible duplicate" / "similar request" flags of
//! queue rows and previews (§5.6); Task 27 scripts (preview, release with or without
//! redactions, deny, batch release: `SCRIPT_RELEASED` / `SCRIPT_DENIED`). Every return type is
//! `Serialize` (PD-12: the capture hook records them).
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
//!
//! M6 Δ2 (Task 7) adds the UI's side reads: `redaction_preview` (what a set of ops would do,
//! nothing logged), `recent` and `needs_attention` ("Recently decided (24 h) / Needs
//! attention"), the Rust-computed deny offers of a write preview (PD-70), the `internal` banner
//! of a candidate that failed closed (M5 M-11), and path-free session ids (PD-86).

mod batch;
mod offers;
mod recent;
mod redaction_preview;

use std::path::PathBuf;
use std::sync::Arc;

use atlas_duck_audit::{AuditError, NewEvent};
use atlas_duck_ipc::envelope::{ErrorCode, Status};
use atlas_duck_preview::invisible::{escape_for_display, strip};
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_preview::{
    CandidateRev, PREVIEW_BUILDER_VERSION, Preview, RAW_PAGE_BYTES, RawPager, cap_error_text,
};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use recent::RecentItem;
pub use redaction_preview::RedactionReport;

/// M5 M-11 (PD-90 banner level caution): the header banner of a candidate that failed closed
/// (§5.2: a rebuild that does not reproduce the revision, or a first build the §5.3 mirror check
/// refuses); Release stays disabled. Worded per the T7 review M-2 ruling (the plan's "only Deny
/// remains" was wrong for the mirror case, where dropping the flagged items makes the rest
/// releasable).
pub const RELEASE_BLOCKED_INTERNAL: &str = "release blocked: the candidate could not be built exactly (internal); deny it, or drop the flagged items";

/// A session's label when its agent named itself nothing: the T7 implementer's wording (not
/// PD-86 text), ledgered in the T7 review (M-4).
pub const SESSION_NO_AGENT_NAME: &str = "(no agent name)";

use crate::edit::{EditError, Edits, apply_edits};
use crate::engine::cache::{Candidate, RebuildError, build_redacted, source_body};
use crate::engine::read::{
    OUTCOME_HINT, ReadContext, caution_count, normalizer, preview_field_names, preview_model,
    release_meta,
};
use crate::engine::script;
use crate::engine::write;
use crate::engine::{Engine, EntryState, OnAuditFailure, RequestEntry, TransitionError};
use crate::gate::UiEvent;
use crate::lifecycle::model::{Event, Hold, Kind, Phase, Rejection, ReleaseItem, is_pending, step};
use crate::ops::{ExecError, MissingField, op_table};
use crate::payloads::{self, InvalidReason, ReleasedItem, SubmittedDecision};
use crate::redact::RedactionOp;
use crate::similarity::SimHit;
use crate::validate::{ValidateCtx, ValidationError, echo};

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

impl SessionKey {
    /// PD-86: lowercase hex SHA-256 of the JCS object of the key, the webview's only handle on a
    /// session (no path crosses the boundary). `peer_origin_exe` enters as the hex of its
    /// lossless OS bytes (§8.4 WTF-8), so a path that is not UTF-8 hashes as well.
    pub fn id(&self) -> String {
        let exe = self
            .peer_origin_exe
            .as_deref()
            .map(|p| hex::encode(atlas_duck_audit::encoding::os_path_bytes(p)));
        let v = serde_json::json!({
            "agent_name": self.agent_name,
            "connection_id": self.connection_id,
            "cwd_basename": self.cwd_basename,
            "peer_origin_exe": exe,
        });
        let bytes = atlas_duck_ipc::jcs::to_jcs_vec(&v).unwrap_or_else(|_| v.to_string().into());
        hex::encode(Sha256::digest(&bytes))
    }

    /// PD-86: what the queue shows for the session: the agent name and the `cwd_basename`, both
    /// normalized at hello and display-escaped here; never `peer_origin_exe`.
    pub fn label(&self) -> String {
        let agent = self
            .agent_name
            .as_deref()
            .map_or_else(|| SESSION_NO_AGENT_NAME.to_owned(), escape_for_display);
        format!("{agent} · {}", escape_for_display(&self.cwd_basename))
    }
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
    /// Caution-level warnings of the current revision (Tasks 21/22), the two flags below
    /// included.
    pub caution_count: u32,
    /// Another pending request with the same `params_sha256` (§5.6, regardless of session).
    pub possible_duplicate_of: Option<String>,
    /// Another request of the same op and instance that matches under the op's `similarity`
    /// rule and is pending or was decided in the last 24 h (§5.6).
    pub similar_to: Option<String>,
    /// Never serialized (PD-86: it carries `peer_origin_exe`); the app resolves a webview's
    /// `session_id` to it by scanning `queue_list`.
    #[serde(skip)]
    pub session: SessionKey,
    /// [`SessionKey::id`].
    pub session_id: String,
    /// [`SessionKey::label`].
    pub session_label: String,
    pub opened: bool,
    pub approvable: bool,
    pub candidate_rev: CandidateRev,
}

/// What the Approvals window's Request tab shows of a queued request (§5.6): the agent's params,
/// their hash, the normalized reason and the connection facts. Every string that came from an
/// agent or from the peer's process is display-escaped here (§6.4), the strings and keys of
/// `params` included; `params` is JSON the UI renders as text. The peer facts are the OS's, not
/// the agent's: the UI shows them as unverified (§3.1).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RequestDetail {
    pub params: Value,
    /// Lowercase hex (§4.4).
    pub params_sha256: String,
    /// The whole normalized `reason` (§3.3), display-escaped; `None` when the agent sent none.
    pub reason: Option<String>,
    /// RFC 3339 UTC, ms.
    pub submitted_at: String,
    pub client_kind: Option<String>,
    pub agent_name: Option<String>,
    /// `flag`, `env`, `mcp-clientInfo` or `none` (§3.3): where the agent name came from.
    pub agent_name_source: Option<String>,
    pub cwd_basename: String,
    pub connection_id: Option<String>,
    pub peer_pid: Option<u32>,
    pub peer_exe: Option<String>,
    pub peer_origin_exe: Option<String>,
    /// One display-escaped line per hop, direct peer first (`<pid> <exe>`), at most `MAX_HOPS`.
    pub peer_chain: Vec<String>,
}

fn display_path(p: &std::path::Path) -> String {
    escape_for_display(&p.to_string_lossy())
}

/// `v` with every string and key display-escaped (§6.4): the Request tab shows params as text, and
/// an invisible or bidi character in them must not reorder or hide what the approver reads.
fn escape_json(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(escape_for_display(s)),
        Value::Array(a) => Value::Array(a.iter().map(escape_json).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| (escape_for_display(k), escape_json(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// C.7. Synchronous (PD-13): callers are never on a UI thread (M6 uses `spawn_blocking`).
pub trait DecisionApi: Send + Sync {
    fn queue_list(&self) -> Vec<QueueItem>;
    fn queue_get(&self, request_id: &str) -> Option<QueueItem>;
    /// M6 T14: the Request tab's facts of a queued request; `None` once it left the queue.
    fn request_detail(&self, request_id: &str) -> Option<RequestDetail>;
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
    /// `deny_batch` over the session's queued items. Items not yet queued or not decidable
    /// (fetching, enriching, checking, executing) are skipped (§5.1, §5.6, L43).
    fn deny_session(&self, session: SessionKey, reason: &str) -> Result<usize, DecisionError>;
    /// In memory, not audited.
    fn acknowledge_attention(&self, request_ids: &[String]);
    /// M6 Δ2 (M3 handoff): what `ops` would do to revision `rev` of an opened item, as the
    /// release path decides it (§5.3: block reasons, "also appears in", "N other occurrences
    /// remain", the size). UI-only and never logged: no record, no `PREVIEW_SHOWN`, no state
    /// change. Refused like `raw_page` (`NotDecidable`, `Stale`, `Invalid(NotOpened)`).
    fn redaction_preview(
        &self,
        request_id: &str,
        rev: CandidateRev,
        ops: &[RedactionOp],
    ) -> Result<RedactionReport, DecisionError>;
    /// M6 Δ2: the "Recently decided (24 h) / Needs attention" rows (§5.6).
    fn recent(&self) -> Vec<RecentItem>;
    /// M6 Δ2: the unacknowledged "Needs attention" ids (sorted; in memory, reset on restart).
    fn needs_attention(&self) -> Vec<String>;
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

/// §5.6 "possible duplicate" and "similar request" of a request, as of now: they change as the
/// queue moves (another item arrives or is decided), so they are computed on every read and
/// never stored with a revision. Both are Caution; neither disables Approve, both keep the item
/// out of a batch approval.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Flags {
    duplicate_of: Option<String>,
    similar: Option<SimHit>,
}

impl Flags {
    fn of(engine: &Engine, e: &RequestEntry) -> Flags {
        let index = engine.similarity();
        let duplicate_of = index
            .duplicates(&e.params_sha256, &e.head.request_id)
            .into_iter()
            .next();
        let similar = index
            .record(&e.head.request_id)
            .and_then(|r| index.similar_to(&r));
        Flags {
            duplicate_of,
            similar,
        }
    }

    fn any(&self) -> bool {
        self.duplicate_of.is_some() || self.similar.is_some()
    }

    /// The §6.2 Caution warnings.
    fn warnings(&self) -> Vec<Warning> {
        let mut w = Vec::new();
        if let Some(other) = &self.duplicate_of {
            w.push(Warning::new(
                WarningId::PossibleDuplicate,
                warning::possible_duplicate(other),
            ));
        }
        if let Some(hit) = &self.similar {
            w.push(Warning::new(WarningId::SimilarRequest, hit.text()));
        }
        w
    }
}

/// The queue row of an entry that waits for a decision.
fn in_queue(engine: &Engine, e: &RequestEntry) -> Option<QueueItem> {
    let flags = Flags::of(engine, e);
    let st = e.state();
    let m = &st.model;
    if !decidable(m.phase()) {
        return None;
    }
    let flagged = u32::try_from(flags.warnings().len()).unwrap_or(u32::MAX);
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
        caution_count: st.caution_count.saturating_add(flagged),
        possible_duplicate_of: flags.duplicate_of.clone(),
        similar_to: flags.similar.as_ref().map(|h| h.request_id.clone()),
        session: e.session.clone(),
        session_id: e.session.id(),
        session_label: e.session.label(),
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
    match entry.kind() {
        Kind::Script | Kind::DryRun => engine.candidate(entry, script::normalizer()).await,
        _ => {
            let params = entry.validated.as_ref().map_or(&Value::Null, |v| &v.params);
            engine
                .candidate(entry, normalizer(entry.spec, params))
                .await
        }
    }
}

fn read_context<'a>(engine: &Arc<Engine>, entry: &'a RequestEntry) -> (&'a Value, ReadContext<'a>) {
    let params = entry.validated.as_ref().map_or(&Value::Null, |v| &v.params);
    (
        params,
        ReadContext {
            spec: entry.spec,
            alias: &entry.head.instance,
            params,
            target_display: &entry.target_display,
            field_names: preview_field_names(engine, entry),
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
        Err(RebuildError::Transient(e)) => return Err(DecisionError::Audit(e)),
        // §5.2: the item failed closed; only Deny remains. No candidate, so no preview: the UI
        // shows `RELEASE_BLOCKED_INTERNAL` for this refusal itself (M5 M-11).
        Err(_) => return Err(DecisionError::Invalid(InvalidReason::NotApprovable)),
    };
    let built = {
        let st = entry.state();
        if st.model.rev() != submitted || &st.candidate_hash != c.hash() {
            None
        } else {
            st.read.clone().map(|read| {
                let at = (current_rev(&st), st.approvable(), st.model.opened());
                (read, at, st.rebuild_failed)
            })
        }
    };
    let Some((read, (shown, approvable, opened), failed)) = built else {
        return Ok(None);
    };
    let (_, cx) = read_context(engine, entry);
    let model = preview_model(&cx, &read, &c);
    let mut warnings = model.warnings;
    warnings.extend(Flags::of(engine, entry).warnings());
    let preview = Preview {
        candidate_rev: shown,
        approvable,
        raw: RawPager::for_total(u64::try_from(c.bytes().len()).unwrap_or(u64::MAX)),
        header: blocked_header(model.header, failed),
        warnings,
        body: model.body,
        also_appears_in: read.also_appears_in.clone(),
        preview_builder_version: PREVIEW_BUILDER_VERSION.to_owned(),
        edit_form: None,
        deny_offers: Vec::new(),
        deny_prefill: None,
    };
    Ok(Some((preview, shown, opened)))
}

/// M5 M-11: a revision whose candidate failed closed (`rebuild_failed`, e.g. a read's first
/// build the §5.3 mirror check refuses) carries the `internal` banner.
fn blocked_header(
    mut header: atlas_duck_preview::PreviewHeader,
    rebuild_failed: bool,
) -> atlas_duck_preview::PreviewHeader {
    header.release_blocked = rebuild_failed.then_some(RELEASE_BLOCKED_INTERNAL);
    header
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
    let mut warnings = model.warnings;
    if let Some(w) = write::instance_warning(engine, &entry.instance_id)
        && !warnings.iter().any(|x| x.id == w.id)
    {
        warnings.insert(0, w);
    }
    warnings.extend(Flags::of(engine, entry).warnings());
    let preview = Preview {
        candidate_rev: shown,
        approvable,
        raw: RawPager::for_total(u64::try_from(raw.len()).unwrap_or(u64::MAX)),
        header: model.header,
        warnings,
        body: model.body,
        also_appears_in: Vec::new(),
        preview_builder_version: PREVIEW_BUILDER_VERSION.to_owned(),
        edit_form: Some(write::edit_form(entry.spec, &w)),
        deny_offers: offers::deny_offers(entry.spec.id, &w, Some(hold)),
        deny_prefill: (hold == Hold::Conflict).then(|| write::CONFLICT_DENY_PREFILL.to_owned()),
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
        Kind::Script => script_preview(&engine, &entry, submitted).await?,
        // A dry run is terminal at once: it never waits for a decision.
        Kind::DryRun => return Err(DecisionError::NotDecidable),
    };
    let Some((preview, shown, opened)) = built else {
        let at = snapshot(&entry.state());
        let r = Rejection::StaleRev {
            current: at.current.counter,
        };
        let dec = SubmittedDecision::Preview;
        return Err(rejected(&engine, &entry, (r, at), submitted, dec).await);
    };
    // Shown = audited: the Caution strip renders exactly these warnings, so a body's implied
    // warning must be among them (`PREVIEW_SHOWN.warning_ids` below).
    debug_assert!(
        preview.body.implied_warning_present(&preview.warnings),
        "{:?} body without its warning",
        preview.body.implied_warning()
    );
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
    if !matches!(entry.kind(), Kind::Read | Kind::Write | Kind::Script) {
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
                Err(RebuildError::Transient(e)) => return Err(DecisionError::Audit(e)),
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
        Kind::Read | Kind::Script => {}
        Kind::Write => return decide_write(&engine, &entry, d).await,
        Kind::DryRun => return Err(DecisionError::NotDecidable),
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
        Err(RebuildError::Transient(e)) => return Err(DecisionError::Audit(e)),
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
    let record = release_record(entry, &rev, &c)?;
    match engine.transition(entry, event, move |_| record).await {
        Ok(_) => {
            queue_changed(engine, entry);
            Ok(outcome(entry))
        }
        Err(e) => Err(transition_failed(engine, entry, e, rev.counter, dec).await),
    }
}

/// `READ_RELEASED` of the current revision's exact candidate `c` with its redaction ops: the
/// outcome answer `{code, hint}`, or the bytes with the `item` marker and `meta` (§5.2 step 8).
fn release_record(
    entry: &RequestEntry,
    rev: &CandidateRev,
    c: &Candidate,
) -> Result<NewEvent, DecisionError> {
    if entry.kind() == Kind::Script {
        return script_release_record(entry, rev, c);
    }
    let (read, ops) = {
        let st = entry.state();
        (st.read.clone(), st.redaction_ops.clone())
    };
    let Some(read) = read else {
        return Err(DecisionError::NotDecidable);
    };
    let ctx = &entry.ctx;
    match read.item {
        ReleaseItem::Outcome => {
            let code = c
                .value()
                .get("code")
                .cloned()
                .and_then(|v| serde_json::from_value::<ErrorCode>(v).ok())
                .ok_or(DecisionError::NotDecidable)?;
            Ok(payloads::read_released_outcome(
                ctx,
                rev,
                code,
                OUTCOME_HINT,
            ))
        }
        item => {
            let marker = if item == ReleaseItem::UpstreamError {
                ReleasedItem::UpstreamError
            } else {
                ReleasedItem::Result
            };
            let meta = release_meta(entry.spec, &read, c.value());
            payloads::read_released_item(ctx, rev, c.bytes(), &ops, marker, &meta)
                .map_err(|_| DecisionError::Audit(AuditError::Invalid("release record")))
        }
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
    let record = if entry.kind() == Kind::Script {
        payloads::script_denied(&entry.ctx, reason.as_deref())
    } else {
        payloads::read_denied(&entry.ctx, reason.as_deref())
    };
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
    if entry.kind() == Kind::Script {
        return redact_script(engine, entry, rev, ops, at).await;
    }
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
    let params = entry.validated.as_ref().map_or(&Value::Null, |v| &v.params);
    let normalize = normalizer(spec, params);
    let base = engine
        .blocking(move |p| Ok(source_body(p, &id, normalize)))
        .await
        .map_err(DecisionError::Audit)?;
    let base = match base {
        Ok(b) => b,
        Err(RebuildError::Transient(e)) => return Err(DecisionError::Audit(e)),
        Err(_) => {
            mark_rebuild_failed(entry, &rev);
            queue_changed(engine, entry);
            let at = snapshot(&entry.state());
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
    let (_, cx) = read_context(engine, entry);
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

// ---- scripts (Task 27) ---------------------------------------------------------------------------

/// A script's preview: its candidate (`{result}` or `{script_error}`, rebuilt if evicted)
/// through the fallback tree, led by the host-counted "lossy host calls" warning.
async fn script_preview(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    submitted: u64,
) -> Result<Built, DecisionError> {
    let c = match candidate(engine, entry).await {
        Ok(c) => c,
        Err(RebuildError::Transient(e)) => return Err(DecisionError::Audit(e)),
        Err(_) => return Err(DecisionError::Invalid(InvalidReason::NotApprovable)),
    };
    let built = {
        let st = entry.state();
        if st.model.rev() != submitted || &st.candidate_hash != c.hash() {
            None
        } else {
            st.script.clone().map(|s| {
                let at = (current_rev(&st), st.approvable(), st.model.opened());
                (s, at, st.rebuild_failed)
            })
        }
    };
    let Some((script, (shown, approvable, opened), failed)) = built else {
        return Ok(None);
    };
    let model = script::preview_model(&script, &c);
    let mut warnings = model.warnings;
    warnings.extend(Flags::of(engine, entry).warnings());
    let preview = Preview {
        candidate_rev: shown,
        approvable,
        raw: RawPager::for_total(u64::try_from(c.bytes().len()).unwrap_or(u64::MAX)),
        header: blocked_header(model.header, failed),
        warnings,
        body: model.body,
        also_appears_in: script.also_appears_in.clone(),
        preview_builder_version: PREVIEW_BUILDER_VERSION.to_owned(),
        edit_form: None,
        deny_offers: Vec::new(),
        deny_prefill: None,
    };
    Ok(Some((preview, shown, opened)))
}

/// `SCRIPT_RELEASED` of the current revision's exact candidate `c` with its redaction ops.
fn script_release_record(
    entry: &RequestEntry,
    rev: &CandidateRev,
    c: &Candidate,
) -> Result<NewEvent, DecisionError> {
    let (item, ops, redactions) = {
        let st = entry.state();
        (
            st.script.as_ref().and_then(|s| s.item),
            st.redaction_ops.clone(),
            st.script.as_ref().and_then(|s| s.redaction_meta.clone()),
        )
    };
    let meta = redactions
        .and_then(|r| serde_json::to_value(r).ok())
        .map(|r| serde_json::json!({ "redactions": r }));
    let item = match item {
        Some(ReleaseItem::ScriptResult) => payloads::ScriptReleasedItem::Result,
        Some(ReleaseItem::ScriptErrorDetails) => payloads::ScriptReleasedItem::Error,
        _ => return Err(DecisionError::NotDecidable),
    };
    payloads::script_released(&entry.ctx, rev, c.bytes(), &ops, item, meta.as_ref())
        .map_err(|_| DecisionError::Audit(AuditError::Invalid("release record")))
}

/// A source record that cannot be read for good fails the revision `rev` closed (§5.2: rebuild
/// failure, internal banner, Release disabled), as `Engine::candidate` does for a rebuild; a newer
/// revision is left alone.
fn mark_rebuild_failed(entry: &Arc<RequestEntry>, rev: &CandidateRev) {
    let mut st = entry.state();
    if st.candidate_hash == rev.candidate_hash {
        st.rebuild_failed = true;
        st.model.set_approvable(false);
    }
}

/// [`redact`] for a script's candidate: the same flow over `{result}` / `{script_error}`.
async fn redact_script(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    rev: CandidateRev,
    ops: Vec<RedactionOp>,
    at: Snapshot,
) -> Result<DecisionOutcome, DecisionError> {
    let dec = SubmittedDecision::Release;
    let Some(script) = entry.state().script.clone() else {
        return Err(DecisionError::NotDecidable);
    };
    let (spec, id) = (entry.spec, entry.head.request_id.clone());
    let base = engine
        .blocking(move |p| Ok(source_body(p, &id, script::normalizer())))
        .await
        .map_err(DecisionError::Audit)?;
    let base = match base {
        Ok(b) => b,
        Err(RebuildError::Transient(e)) => return Err(DecisionError::Audit(e)),
        Err(_) => {
            mark_rebuild_failed(entry, &rev);
            queue_changed(engine, entry);
            let rej = (Rejection::NotApprovable, snapshot(&entry.state()));
            return Err(rejected(engine, entry, rej, rev.counter, dec).await);
        }
    };
    let applied = tokio::task::spawn_blocking(move || {
        build_redacted(spec, base, &ops).map(|(c, report)| (c, report, ops))
    })
    .await;
    let (c, report, ops) = match applied {
        Ok(Ok(built)) => built,
        Ok(Err(RebuildError::Blocked)) => {
            let rej = (Rejection::NotApprovable, at);
            return Err(rejected(engine, entry, rej, rev.counter, dec).await);
        }
        _ => return Err(DecisionError::Audit(AuditError::Invalid("redaction"))),
    };
    let (redaction_meta, also_appears_in) = match report {
        Some(r) => (Some(r.meta), r.also_appears_in),
        None => (None, Vec::new()),
    };
    let new_script = script::ScriptState {
        redaction_meta,
        also_appears_in,
        ..script
    };
    let caution = caution_count(&script::preview_model(&new_script, &c));
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
                st.script = Some(new_script);
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
/// (`Edit {rerun}`, `PREVIEW_FETCH {purpose: enrich}`, PD-24). A malformed key, invalid params or
/// a choice label core cannot send (`write::choice_edits`, T12 review I1) leave the request
/// unchanged and log nothing (T15 handoff); a target or baseline edit is
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
    let caps = engine.effective_caps();
    let vctx = ValidateCtx {
        instance_version: version,
        caps: &caps,
        for_script: false,
    };
    let agent = entry
        .validated
        .as_ref()
        .map_or(Value::Null, |v| v.params.clone());
    // T12 review I1: a label picked in a pre-added choice becomes the Jira value it stands for,
    // from the very form this revision shows.
    let form = write::edit_form(spec, &snap.write);
    let missing = &snap.write.verdict.missing_fields;
    let edits = write::choice_edits(&form, missing, edits).map_err(DecisionError::EditRejected)?;
    let result = match apply_edits(
        spec,
        &agent,
        &snap.write.params,
        &edits,
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
    match write::render(engine, spec, base, &result.params, None, effective_max) {
        Ok(_) | Err(ExecError::EnrichmentRequired) => {}
        Err(e) => return Err(exec_refused(e)),
    }
    let rendered = if result.rerun_enrichment {
        None
    } else if snap.write.verdict.hold == Hold::Preview {
        let verdict = Some(&snap.write.verdict);
        Some(
            write::render(engine, spec, base, &result.params, verdict, effective_max)
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
/// Keyed by the op and the param (T16 review M7): another op's param of the same name gets the
/// generic text, never one that names the wrong kind of thing.
fn resolution_message(op: &str, params: &Value, param: &str, value: &str) -> String {
    let value = echo(value);
    // The agent's own values (never a resolved one: that would be fetched data), escaped.
    let of = |name: &str| echo(params.get(name).and_then(Value::as_str).unwrap_or_default());
    match (op, param) {
        ("jira.issue.create", "issuetype") => {
            format!("no issue type named '{value}' in {}", of("project"))
        }
        ("jira.issue.transition", "transition") => {
            format!("no transition named '{value}' for {}", of("key"))
        }
        // PD-62 (plan text).
        ("jira.issue.assign", "assignee") => {
            format!("no assignable user '{value}' for {}", of("key"))
        }
        // PD-62 (plan text).
        ("jira.issuelink.create", "type") => format!("no issue link type named '{value}'"),
        _ => format!("no {param} named '{value}'"),
    }
}

/// M5 M-8: a deny hint reaches the agent; serialized it is at most this many bytes (lists cut
/// at item boundaries, their `*_total` counts kept).
pub const DENY_HINT_MAX_BYTES: usize = 64 * 1024;

/// Room kept beside a hint's lists for the rest of it and a `*_total` count.
const HINT_LIST_RESERVE: usize = 256;

/// T7 review M-1: each server string in a deny hint is cut to this many bytes (with `…`), so a
/// single unbounded field (a createmeta name, say) cannot exceed [`DENY_HINT_MAX_BYTES`] alone.
const SERVER_TEXT_MAX_BYTES: usize = 1024;

/// M5 M-8: server text in a deny hint (field ids and names, schema types, allowed-value labels,
/// resolution candidates) is stripped like an agent string (§3.3), line breaks included, and cut
/// to [`SERVER_TEXT_MAX_BYTES`] before it reaches the agent; upstream messages keep their line
/// breaks (see `hint_for`).
fn server_text(s: &str) -> String {
    let s = strip(s, false).0;
    if s.len() <= SERVER_TEXT_MAX_BYTES {
        return s;
    }
    let mut end = SERVER_TEXT_MAX_BYTES - '…'.len_utf8();
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

fn json_len(v: &Value) -> usize {
    serde_json::to_vec(v).map_or(usize::MAX, |b| b.len())
}

/// The longest prefix of `items` that fits `budget` serialized bytes (each with a separator).
fn fit(items: Vec<Value>, budget: usize) -> Vec<Value> {
    let mut used = 0usize;
    let mut out = Vec::new();
    for item in items {
        used = used.saturating_add(json_len(&item).saturating_add(1));
        if used > budget {
            break;
        }
        out.push(item);
    }
    out
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// PD-49: a missing required field as a `missing_fields` deny hint lists it (§4.3): server text
/// like resolution candidates (stripped, M-8), `allowed_values` (names only) only when the human
/// ticked them, at most `budget` bytes of them, with `allowed_values_total` when that list is cut
/// (T12 review M5).
fn missing_field_detail(f: &MissingField, include_allowed_values: bool, budget: usize) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("id".into(), Value::from(server_text(&f.id)));
    m.insert("name".into(), Value::from(server_text(&f.name)));
    m.insert(
        "schema_type".into(),
        Value::from(server_text(&f.schema_type)),
    );
    if include_allowed_values {
        let labels: Vec<Value> = f
            .allowed_values
            .iter()
            .map(|v| Value::from(server_text(&v.label)))
            .collect();
        let labels = fit(labels, budget);
        if f.allowed_total > len_u64(labels.len()) {
            m.insert("allowed_values_total".into(), Value::from(f.allowed_total));
        }
        m.insert("allowed_values".into(), Value::Array(labels));
    }
    Value::Object(m)
}

/// The hint a deny attaches (§5.4 step 2, §4.3), only one the current hold has the data for.
fn deny_hint(entry: &RequestEntry, details: DenyDetails) -> Result<Value, DecisionError> {
    let snap = write::snapshot(entry).ok_or(DecisionError::NotDecidable)?;
    hint_for(entry.spec.id, &snap.write, snap.hold, details)
}

/// [`deny_hint`] of a write state and the hold it waits in; also what the preview's deny offers
/// are computed by (PD-70), so an offer is exactly a hint this accepts.
fn hint_for(
    op_id: &str,
    w: &write::WriteState,
    hold: Option<Hold>,
    details: DenyDetails,
) -> Result<Value, DecisionError> {
    let refuse = || edit_refused(MSG_HINT_NOT_APPLICABLE, "deny_details");
    let failure = w.failure.as_ref();
    match (details, hold) {
        (DenyDetails::UpstreamHttp { include_messages }, Some(Hold::EnrichmentError)) => {
            let card = failure
                .filter(|f| f.hint == write::FailureHint::UpstreamHttp)
                .map(|f| &f.card)
                .ok_or_else(refuse)?;
            let mut d = serde_json::Map::new();
            d.insert("status".into(), serde_json::json!(card.status));
            if include_messages {
                // One line per upstream message (`read::error_text` joins them with `\n`):
                // stripped like the human's own reason, line breaks kept.
                let text = cap_error_text(&strip(&card.text, true).0);
                d.insert("error_messages".into(), Value::from(text));
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
            let (param, value, _, candidates) = w.verdict.unresolved.as_ref().ok_or_else(refuse)?;
            let mut d = serde_json::Map::new();
            d.insert("param".into(), Value::from(param.clone()));
            d.insert("value".into(), Value::from(echo(value)));
            d.insert(
                "message".into(),
                Value::from(resolution_message(op_id, &w.params, param, value)),
            );
            if include_candidates {
                let budget = DENY_HINT_MAX_BYTES
                    .saturating_sub(json_len(&Value::Object(d.clone())))
                    .saturating_sub(HINT_LIST_RESERVE);
                let all: Vec<Value> = candidates
                    .iter()
                    .map(|c| Value::from(server_text(c)))
                    .collect();
                let listed = fit(all, budget);
                // T7 review I-1 (lead ruling): an additive key of the same class as
                // `missing_fields_total` / `allowed_values_total` (§4.3), present only when the
                // human ticked the candidates and the list was cut.
                if listed.len() < candidates.len() {
                    d.insert("candidates_total".into(), Value::from(candidates.len()));
                }
                d.insert("candidates".into(), Value::Array(listed));
            }
            Ok(serde_json::json!({ "code": "resolution_failed", "details": d }))
        }
        // PD-49: only a `Preview` verdict that found missing required fields has them.
        (
            DenyDetails::MissingFields {
                include_allowed_values,
            },
            Some(Hold::Preview),
        ) => {
            let verdict = &w.verdict;
            if verdict.hold != Hold::Preview || verdict.missing_fields.is_empty() {
                return Err(refuse());
            }
            // M-8: whole fields while they fit; a first field too large alone keeps the
            // allowed values that fit.
            let budget = DENY_HINT_MAX_BYTES.saturating_sub(HINT_LIST_RESERVE);
            let mut used = 0usize;
            let mut list: Vec<Value> = Vec::new();
            for f in &verdict.missing_fields {
                let mut detail = missing_field_detail(f, include_allowed_values, usize::MAX);
                let n = json_len(&detail).saturating_add(1);
                if used.saturating_add(n) > budget {
                    if !list.is_empty() {
                        break;
                    }
                    let bare = json_len(&missing_field_detail(f, false, 0));
                    let room = budget
                        .saturating_sub(bare)
                        .saturating_sub(HINT_LIST_RESERVE);
                    detail = missing_field_detail(f, include_allowed_values, room);
                    list.push(detail);
                    break;
                }
                used = used.saturating_add(n);
                list.push(detail);
            }
            let mut d = serde_json::Map::new();
            // T12 review M5: a list cut at `jira::MAX_MISSING_FIELDS` (or by M-8) says how many
            // there are.
            let total = verdict
                .missing_fields_total
                .max(len_u64(verdict.missing_fields.len()));
            if total > len_u64(list.len()) {
                d.insert("missing_fields_total".into(), Value::from(total));
            }
            d.insert("missing_fields".into(), Value::Array(list));
            Ok(serde_json::json!({ "code": "denied", "details": d }))
        }
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
            .filter_map(|e| in_queue(&self.engine, e))
            .collect();
        items.sort_by(|a, b| {
            b.age_s
                .cmp(&a.age_s)
                .then_with(|| a.request_id.cmp(&b.request_id))
        });
        items
    }

    fn queue_get(&self, request_id: &str) -> Option<QueueItem> {
        self.engine
            .entry(request_id)
            .and_then(|e| in_queue(&self.engine, &e))
    }

    fn request_detail(&self, request_id: &str) -> Option<RequestDetail> {
        let e = self.engine.entry(request_id)?;
        in_queue(&self.engine, &e)?;
        let actor = &e.connection;
        Some(RequestDetail {
            params: e.params().map_or(Value::Null, escape_json),
            params_sha256: e.params_sha256.clone(),
            reason: e.reason.as_deref().map(escape_for_display),
            submitted_at: e.submitted_at.clone(),
            client_kind: actor.client_kind.clone(),
            agent_name: e.agent_name.as_deref().map(escape_for_display),
            agent_name_source: actor.agent_name_source.clone(),
            cwd_basename: escape_for_display(&e.session.cwd_basename),
            connection_id: actor.connection_id.clone(),
            peer_pid: actor.peer_pid,
            peer_exe: actor.peer_exe.as_deref().map(display_path),
            peer_origin_exe: actor.peer_origin_exe.as_deref().map(display_path),
            peer_chain: e
                .peer_chain
                .iter()
                .map(|h| format!("{} {}", h.pid, display_path(&h.exe)))
                .collect(),
        })
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
        let engine = self.engine.clone();
        self.engine
            .run_sync(batch::decide_batch(engine, items))
            .unwrap_or_else(|| Err(task_failed()))
    }

    fn deny_batch(&self, request_ids: &[String], reason: &str) -> Result<usize, DecisionError> {
        let (engine, ids) = (self.engine.clone(), request_ids.to_vec());
        self.engine
            .run_sync(batch::deny_batch(engine, ids, reason.to_owned()))
            .unwrap_or_else(|| Err(task_failed()))
    }

    fn deny_session(&self, session: SessionKey, reason: &str) -> Result<usize, DecisionError> {
        let ids = batch::session_items(&self.engine, &session);
        self.deny_batch(&ids, reason)
    }

    fn acknowledge_attention(&self, request_ids: &[String]) {
        self.engine.acknowledge_attention(request_ids);
    }

    fn redaction_preview(
        &self,
        request_id: &str,
        rev: CandidateRev,
        ops: &[RedactionOp],
    ) -> Result<RedactionReport, DecisionError> {
        let (engine, id) = (self.engine.clone(), request_id.to_owned());
        self.engine
            .run_sync(redaction_preview::redaction_preview(
                engine,
                id,
                rev,
                ops.to_vec(),
            ))
            .unwrap_or_else(|| Err(task_failed()))
    }

    fn recent(&self) -> Vec<RecentItem> {
        let engine = self.engine.clone();
        self.engine
            .run_sync(recent::recent(engine))
            .unwrap_or_default()
    }

    fn needs_attention(&self) -> Vec<String> {
        self.engine.needs_attention()
    }
}
