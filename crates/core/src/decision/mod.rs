//! The Rust decision API (C.7, §2.4, §5.6): the only way a human decision reaches the engine.
//! The approvals UI (M6) and the scripted approver call it, nothing else.
//!
//! Task 19 declares the contract and answers the queue; the decisions are Tasks 21–23. Until
//! then nothing ever waits for a decision (requests stop at `Validated`), so every
//! preview/decision call is honestly `NotDecidable` and the deny calls deny nothing. Every
//! return type is `Serialize` (PD-12: the capture hook records them).

use std::path::PathBuf;
use std::sync::Arc;

use atlas_duck_audit::AuditError;
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::{CandidateRev, Preview};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::edit::Edits;
use crate::engine::{Engine, RequestEntry};
use crate::lifecycle::model::Phase;
use crate::payloads::InvalidReason;
use crate::redact::RedactionOp;
use crate::validate::ValidationError;

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

/// The core's `DecisionApi` (queue only until Task 21).
pub struct CoreDecisions {
    engine: Arc<Engine>,
}

impl CoreDecisions {
    pub(crate) fn new(engine: Arc<Engine>) -> CoreDecisions {
        CoreDecisions { engine }
    }
}

/// An item waits for a human only in `AwaitingRelease` / `AwaitingApproval` (§5.1).
fn in_queue(e: &RequestEntry) -> Option<QueueItem> {
    let st = e.state();
    let m = &st.model;
    if !matches!(
        m.phase(),
        Phase::AwaitingRelease(_) | Phase::AwaitingApproval(_)
    ) {
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
        approvable: m.approvable(),
        candidate_rev: CandidateRev {
            counter: m.rev(),
            candidate_hash: st.candidate_hash,
        },
    })
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
        _request_id: &str,
        _rev: Option<CandidateRev>,
    ) -> Result<PreviewDelivery, DecisionError> {
        Err(DecisionError::NotDecidable)
    }

    fn raw_page(
        &self,
        _request_id: &str,
        _rev: CandidateRev,
        _page: u64,
    ) -> Result<RawPage, DecisionError> {
        Err(DecisionError::NotDecidable)
    }

    fn decide(&self, _d: Decision) -> Result<DecisionOutcome, DecisionError> {
        Err(DecisionError::NotDecidable)
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
