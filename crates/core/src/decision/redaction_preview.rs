//! `DecisionApi::redaction_preview` (M6 Δ2, the M3 handoff): what a set of redaction ops would do
//! to an opened revision, shown before the approver submits them (§5.3 block reasons, "also
//! appears in", "N other occurrences remain"). UI-only: no record, no `PREVIEW_SHOWN`, no state
//! change, not even the `rebuild_failed` mark a release sets when the source record is unusable.
//!
//! The ops run through the release path's own check (`cache::check_redacted`, which
//! `build_redacted` decides on) over the same source body a submit uses, on a scratch copy: what
//! the preview reports blocked is exactly what a submit would refuse.

use std::fmt;
use std::sync::Arc;

use atlas_duck_audit::AuditError;
use atlas_duck_preview::CandidateRev;
use serde::Serialize;
use serde_json::Value;

use super::{DecisionError, MSG_NO_WRITE_REDACTIONS, current_rev, decidable, edit_refused};
use crate::engine::cache::{RebuildError, check_redacted, source_body};
use crate::engine::read::normalizer;
use crate::engine::{Engine, script};
use crate::lifecycle::model::{Kind, ReleaseItem};
use crate::payloads::InvalidReason;
use crate::redact::{BlockReason, RedactionOp};

/// C.7 (M6 Δ2): the release path's verdict on a set of ops. `blocked` empty ⇒ a submit of the
/// ops gives a releasable revision (after any "N other occurrences remain" confirmation).
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RedactionReport {
    pub blocked: Vec<BlockReason>,
    /// Locations with a canonical hit for a masked string (§5.3), then those of blocked values.
    pub also_appears_in: Vec<String>,
    /// Occurrences the single-occurrence masks leave in place, summed.
    pub other_occurrences: u64,
    /// Bytes of the candidate the ops give.
    pub released_bytes: u64,
}

/// Redacting `Debug` (§7.7): paths can be object keys that hold the masked string.
impl fmt::Debug for RedactionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedactionReport")
            .field("blocked", &self.blocked)
            .field("also_appears_in", &self.also_appears_in.len())
            .field("other_occurrences", &self.other_occurrences)
            .field("released_bytes", &self.released_bytes)
            .finish()
    }
}

/// Refused like `raw_page`: unknown or not waiting for a decision → `NotDecidable`; another
/// revision → `Stale`; not opened → `Invalid(NotOpened)`. A write has nothing to redact (as
/// `decide` refuses its redactions); an outcome item, or a source record that cannot be read for
/// good, has no content to redact → `Invalid(NotApprovable)`. Nothing of it is logged.
pub(super) async fn redaction_preview(
    engine: Arc<Engine>,
    id: String,
    rev: CandidateRev,
    ops: Vec<RedactionOp>,
) -> Result<RedactionReport, DecisionError> {
    let entry = engine.entry(&id).ok_or(DecisionError::NotDecidable)?;
    let kind = entry.kind();
    {
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
        match kind {
            Kind::Write => return Err(edit_refused(MSG_NO_WRITE_REDACTIONS, "redactions")),
            Kind::Script if st.script.is_some() => {}
            Kind::Script | Kind::DryRun => return Err(DecisionError::NotDecidable),
            Kind::Read => {
                // An outcome item has no content to redact (§5.2 step 6: Release or Deny).
                let item = st.read.as_ref().map(|r| r.item);
                if item.is_none_or(|i| i == ReleaseItem::Outcome) {
                    return Err(DecisionError::Invalid(InvalidReason::NotApprovable));
                }
            }
        }
    }
    let (spec, rid) = (entry.spec, id.clone());
    let base = if kind == Kind::Script {
        engine
            .blocking(move |p| Ok(source_body(p, &rid, script::normalizer())))
            .await
    } else {
        let params = entry.validated.as_ref().map_or(&Value::Null, |v| &v.params);
        let normalize = normalizer(spec, params);
        engine
            .blocking(move |p| Ok(source_body(p, &rid, normalize)))
            .await
    }
    .map_err(DecisionError::Audit)?;
    let base = match base {
        Ok(b) => b,
        Err(RebuildError::Transient(e)) => return Err(DecisionError::Audit(e)),
        Err(_) => return Err(DecisionError::Invalid(InvalidReason::NotApprovable)),
    };
    let check = match tokio::task::spawn_blocking(move || check_redacted(spec, base, &ops)).await {
        Ok(Ok(check)) => check,
        _ => return Err(DecisionError::Audit(AuditError::Invalid("redaction"))),
    };
    // The report is about the revision asked for; it may have moved on meanwhile.
    let now = current_rev(&entry.state());
    if now != rev {
        return Err(DecisionError::Stale { current: now });
    }
    Ok(RedactionReport {
        blocked: check.blocked,
        also_appears_in: check.report.map(|r| r.also_appears_in).unwrap_or_default(),
        other_occurrences: check.other_occurrences,
        released_bytes: u64::try_from(check.candidate.bytes().len()).unwrap_or(u64::MAX),
    })
}
