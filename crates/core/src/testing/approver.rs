//! `ScriptedApprover` (C.7 `core::testing`): a headless human over `DecisionApi`. Task 21 adds
//! the read decisions (`open`, `release`, `release_redacted`, `release_status_only`, `deny`);
//! Task 22 the write decisions (`approve`, `edit`, `deny_with`); M5 Task 12 `edit_preadded` and
//! `choose_preadded`; M6 Task 7 the side reads `redaction_preview` and `recent`.
//!
//! Every decision opens the item's current revision first (`PREVIEW_SHOWN`, §5.6), as the
//! approvals UI does, unless the method says `unopened`. The methods block (`DecisionApi` is
//! synchronous, PD-13): call them from a multi-thread runtime's test body, never from a
//! current-thread runtime.

use std::sync::Arc;

use atlas_duck_ipc::envelope::ErrorCode;
use atlas_duck_preview::form::{EditInput, InputKind};
use atlas_duck_preview::{CandidateRev, Preview};
use serde_json::{Map, Value};

use crate::decision::{
    Decision, DecisionApi, DecisionError, DecisionKind, DecisionOutcome, DenyDetails,
    PreviewDelivery, QueueItem, RecentItem, RedactionReport,
};
use crate::edit::Edits;
use crate::redact::{RedactionOp, RedactionPreset};
use crate::validate::ValidationError;

pub struct ScriptedApprover {
    decisions: Arc<dyn DecisionApi>,
}

/// The input `path` of `preview`'s edit form, if enrichment pre-added it.
fn preadded<'p>(preview: &'p Preview, path: &str) -> Option<&'p EditInput> {
    preview
        .edit_form
        .as_ref()?
        .inputs
        .iter()
        .find(|i| i.pre_added && i.path == path)
}

/// What the UI would not let through, refused before it reaches core (nothing logged).
fn refused(path: &str, message: &str) -> DecisionError {
    let mut details = Map::new();
    details.insert("param".into(), Value::from(path));
    DecisionError::EditRejected(ValidationError {
        code: ErrorCode::Validation,
        message: message.to_owned(),
        details,
    })
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

    /// What `ops` would do to the current revision (M6 Δ2; nothing logged). The revision must
    /// be opened, as in the UI, where the redaction panel is part of an opened preview.
    pub fn redaction_preview(
        &self,
        request_id: &str,
        ops: &[RedactionOp],
    ) -> Result<RedactionReport, DecisionError> {
        let rev = self.rev(request_id)?;
        self.decisions.redaction_preview(request_id, rev, ops)
    }

    /// The "Recently decided (24 h) / Needs attention" rows (M6 Δ2).
    pub fn recent(&self) -> Vec<RecentItem> {
        self.decisions.recent()
    }

    /// `request_id`'s "Recently decided" row, if listed.
    pub fn recent_row(&self, request_id: &str) -> Option<RecentItem> {
        self.recent()
            .into_iter()
            .find(|r| r.request_id == request_id)
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

    /// Opens and denies a write with an attached hint (§5.4 step 2, PD-20).
    pub fn deny_with(
        &self,
        request_id: &str,
        reason: &str,
        details: DenyDetails,
    ) -> Result<DecisionOutcome, DecisionError> {
        self.open(request_id)?;
        let rev = self.rev(request_id)?;
        self.decisions.decide(Decision {
            reason: Some(reason.to_owned()),
            deny_details: Some(details),
            ..decision(request_id, DecisionKind::Deny, rev)
        })
    }

    /// Opens and approves a write's current revision (decision `approve`, or `approve_edited`
    /// for a write that was edited).
    pub fn approve(&self, request_id: &str) -> Result<DecisionOutcome, DecisionError> {
        self.open(request_id)?;
        self.approve_unopened(request_id)
    }

    /// Approves the current revision without opening it.
    pub fn approve_unopened(&self, request_id: &str) -> Result<DecisionOutcome, DecisionError> {
        let rev = self.rev(request_id)?;
        self.decisions
            .decide(decision(request_id, DecisionKind::Approve, rev))
    }

    /// Applies `edits` to the current revision ("Edit & approve" without the approve, PD-20):
    /// the edit makes a new revision (or re-runs enrichment) that must be opened and approved.
    pub fn edit(&self, request_id: &str, edits: Edits) -> Result<DecisionOutcome, DecisionError> {
        let rev = self.rev(request_id)?;
        self.decisions.decide(Decision {
            edits: Some(edits),
            ..decision(request_id, DecisionKind::ApproveEdited, rev)
        })
    }

    /// Fills the pre-added input `path` (`fields.<id>`, a missing required field, PD-49) of the
    /// current revision's edit form with `value`, as the approvals UI does: opens the revision,
    /// refuses a path its edit form did not pre-add, then edits like [`Self::edit`] (an
    /// `enrich_keys` param: enrichment runs again). The open is the UI's own (the form is only
    /// reachable from an opened preview, §5.6), so it logs `PREVIEW_SHOWN` even when the path is
    /// then refused; the refusal itself logs nothing (T12 review M9).
    pub fn edit_preadded(
        &self,
        request_id: &str,
        path: &str,
        value: Value,
    ) -> Result<DecisionOutcome, DecisionError> {
        let preview = self.open(request_id)?.preview;
        if preadded(&preview, path).is_none() {
            return Err(refused(path, "not a pre-added input of this revision"));
        }
        self.set(request_id, path, value)
    }

    /// Picks `label` in the pre-added `Choice` input `path`, as the approvals UI does: opens the
    /// revision, refuses a label the input does not list, then sends the label as the edit; core
    /// turns it into the Jira value (T12 review I1).
    pub fn choose_preadded(
        &self,
        request_id: &str,
        path: &str,
        label: &str,
    ) -> Result<DecisionOutcome, DecisionError> {
        let preview = self.open(request_id)?.preview;
        let listed = match preadded(&preview, path).map(|i| &i.kind) {
            Some(InputKind::Choice(allowed)) => allowed.as_slice().iter().any(|l| l == label),
            _ => false,
        };
        if !listed {
            return Err(refused(path, "not a choice of this revision's input"));
        }
        self.set(request_id, path, Value::from(label))
    }

    /// Fills every pre-added input of the current revision's edit form with its first allowed
    /// value (any other kind: `"x"`) and submits the edit, like [`Self::edit_preadded`] for all of
    /// them at once. `Ok(false)` when the revision has none (nothing was edited; the revision
    /// was opened).
    pub fn edit_all_preadded(&self, request_id: &str) -> Result<bool, DecisionError> {
        let preview = self.open(request_id)?.preview;
        let mut set = Map::new();
        let inputs = preview.edit_form.iter().flat_map(|f| f.inputs.iter());
        for input in inputs.filter(|i| i.pre_added) {
            let value = match &input.kind {
                InputKind::Choice(allowed) => allowed.as_slice().first().map(String::as_str),
                _ => None,
            };
            set.insert(input.path.clone(), Value::from(value.unwrap_or("x")));
        }
        if set.is_empty() {
            return Ok(false);
        }
        self.edit(
            request_id,
            Edits {
                set,
                remove: Vec::new(),
            },
        )?;
        Ok(true)
    }

    fn set(
        &self,
        request_id: &str,
        path: &str,
        value: Value,
    ) -> Result<DecisionOutcome, DecisionError> {
        let mut set = Map::new();
        set.insert(path.to_owned(), value);
        self.edit(
            request_id,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
    }
}
