//! `ScriptedApprover` (C.7 `core::testing`): a headless human over `DecisionApi`. Task 21 adds
//! the read decisions (`open`, `release`, `release_redacted`, `release_status_only`, `deny`);
//! Task 22 adds `approve`, `edit` and `deny_with`.
//!
//! Every decision opens the item's current revision first (`PREVIEW_SHOWN`, §5.6), as the
//! approvals UI does, unless the method says `unopened`. The methods block (`DecisionApi` is
//! synchronous, PD-13): call them from a multi-thread runtime's test body, never from a
//! current-thread runtime.

use std::sync::Arc;

use atlas_duck_preview::CandidateRev;

use crate::decision::{
    Decision, DecisionApi, DecisionError, DecisionKind, DecisionOutcome, PreviewDelivery, QueueItem,
};
use crate::redact::{RedactionOp, RedactionPreset};

pub struct ScriptedApprover {
    decisions: Arc<dyn DecisionApi>,
}

fn decision(request_id: &str, decision: DecisionKind, rev: CandidateRev) -> Decision {
    Decision {
        request_id: request_id.to_owned(),
        decision,
        candidate_rev: rev,
        edits: None,
        redactions: None,
        reason: None,
        deny_details: None,
    }
}

impl ScriptedApprover {
    pub fn new(decisions: Arc<dyn DecisionApi>) -> ScriptedApprover {
        ScriptedApprover { decisions }
    }

    /// The queue row of `request_id`, if it waits for a decision.
    pub fn item(&self, request_id: &str) -> Option<QueueItem> {
        self.decisions.queue_get(request_id)
    }

    /// The current revision, or `NotDecidable` when the item is not in the queue.
    pub fn rev(&self, request_id: &str) -> Result<CandidateRev, DecisionError> {
        self.item(request_id)
            .map(|i| i.candidate_rev)
            .ok_or(DecisionError::NotDecidable)
    }

    /// Opens the current revision (§5.6 "opened"; commits `PREVIEW_SHOWN`).
    pub fn open(&self, request_id: &str) -> Result<PreviewDelivery, DecisionError> {
        let rev = self.rev(request_id)?;
        self.decisions.preview_fetch(request_id, Some(rev))
    }

    /// Opens and releases the current revision as it is.
    pub fn release(&self, request_id: &str) -> Result<DecisionOutcome, DecisionError> {
        self.open(request_id)?;
        self.release_unopened(request_id)
    }

    /// Releases the current revision without opening it.
    pub fn release_unopened(&self, request_id: &str) -> Result<DecisionOutcome, DecisionError> {
        let rev = self.rev(request_id)?;
        self.decisions
            .decide(decision(request_id, DecisionKind::Release, rev))
    }

    /// Applies `ops` to the current revision: a new revision that must be opened before it can
    /// be released (§5.1 inv. 5). Returns that revision.
    pub fn redact(
        &self,
        request_id: &str,
        ops: Vec<RedactionOp>,
    ) -> Result<CandidateRev, DecisionError> {
        let rev = self.rev(request_id)?;
        self.decisions.decide(Decision {
            redactions: Some(ops),
            ..decision(request_id, DecisionKind::ReleaseRedacted, rev)
        })?;
        self.rev(request_id)
    }

    /// Opens, applies `ops`, opens the redacted revision and releases it.
    pub fn release_redacted(
        &self,
        request_id: &str,
        ops: Vec<RedactionOp>,
    ) -> Result<DecisionOutcome, DecisionError> {
        self.open(request_id)?;
        let rev = self.redact(request_id, ops.clone())?;
        self.decisions.preview_fetch(request_id, Some(rev))?;
        self.decisions.decide(Decision {
            redactions: Some(ops),
            ..decision(request_id, DecisionKind::ReleaseRedacted, rev)
        })
    }

    /// §5.2 step 6 "Release status only" (an upstream-error item).
    pub fn release_status_only(&self, request_id: &str) -> Result<DecisionOutcome, DecisionError> {
        self.release_redacted(
            request_id,
            vec![RedactionOp::Preset(RedactionPreset::StatusOnly)],
        )
    }

    /// Opens and denies the current revision with `reason`.
    pub fn deny(&self, request_id: &str, reason: &str) -> Result<DecisionOutcome, DecisionError> {
        self.open(request_id)?;
        self.deny_unopened(request_id, reason)
    }

    /// Denies without opening (Deny needs no opened revision).
    pub fn deny_unopened(
        &self,
        request_id: &str,
        reason: &str,
    ) -> Result<DecisionOutcome, DecisionError> {
        let rev = self.rev(request_id)?;
        self.decisions.decide(Decision {
            reason: Some(reason.to_owned()),
            ..decision(request_id, DecisionKind::Deny, rev)
        })
    }
}
