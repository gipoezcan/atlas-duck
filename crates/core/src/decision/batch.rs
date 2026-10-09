//! Batch decisions (L43, §5.6): all-or-nothing approve/release of several opened items behind one
//! native confirmation, and per-item batch / session deny without a dialog.
//!
//! `decide_batch` (one batch at a time, the engine's batch gate):
//! 1. **Pre-check** every item, no gate held: pending, `candidate_rev` current (counter and
//!    hash), opened, not flagged "possible duplicate" / "similar request", approvable (§5.1 inv.
//!    6). Each failure is logged with `batch: true` (`DECISION_STALE` for a stale revision or a
//!    request in a phase where no decision applies, `DECISION_INVALID {reason}` otherwise; a
//!    request no longer pending is not logged) and the whole batch is rejected.
//! 2. **Dialog**: Rust-built text (count, op ids, `target_display`, instance alias, each item's
//!    Caution texts; never an agent's reason), shown by `NativeConfirmer::confirm` on a
//!    dedicated OS thread, off the runtime's workers, with no request lock held. Cancel logs
//!    nothing and changes nothing.
//! 3. **Re-check** under every item's transition gate (taken in request id order), with the
//!    same rules and logging: an item that expired, was cancelled, changed revision or became
//!    flagged while the dialog was open rejects the batch.
//! 4. **Commit** `BATCH_CONFIRMED {batch_id, items, dialog_text_sha256}` and every item's natural
//!    positive decision (writes `WRITE_APPROVED`, reads `READ_RELEASED`; each with the `batch`
//!    flag and `batch_id`) in **one** `append_batch`, `BATCH_CONFIRMED` first. A failed append
//!    decides nothing (`Err(Audit)`, every item still pending).
//! 5. **Effects** only after the commit: the model steps apply, released reads wake their
//!    watchers, approved writes start their stale checks (each bound to its approval).
//!
//! The natural decision is the one the item's current, opened revision takes as it is: no edits
//! and no new redactions (those are individual decisions). A read whose current revision already
//! carries redaction ops (applied, then opened, individually) is released with them
//! (`release_redacted`), so exactly the bytes whose hash the item names are released.
//!
//! `deny_batch` / `deny_session` deny each still-queued item with the same reason, one record
//! per item, not all-or-nothing. They carry no `batch` flag: that flag marks the per-item
//! decisions of a confirmed batch only (T17 ruling, U-32), and a batch deny has no dialog and no
//! `BATCH_CONFIRMED`.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::Arc;

use atlas_duck_audit::{Actor, AuditError, RequestRecord};
use atlas_duck_preview::invisible::strip;
use atlas_duck_preview::{CandidateRev, Level};
use sha2::{Digest, Sha256};

use super::{
    BatchFailure, BatchItem, BatchOutcome, Decision, DecisionError, DecisionKind, DecisionOutcome,
    Flags, SessionKey, Snapshot, candidate, current_rev, decidable, deny, deny_write, dry_step,
    outcome, queue_changed, read_context, release_record, snapshot,
};
use crate::core::Confirm;
use crate::engine::cache::{Candidate, RebuildError};
use crate::engine::read::preview_model;
use crate::engine::write;
use crate::engine::{BatchCommitError, BatchStep, Engine, OnApply, RequestEntry};
use crate::ids::BatchId;
use crate::lifecycle::model::{Event, Kind, Rejection, is_pending};
use crate::payloads::{self, InvalidReason, SubmittedDecision};

/// Why an item check stopped: the item failed (the batch is rejected), or logging its failure
/// failed (the decision cannot be recorded; the caller gets the audit error).
enum Fail {
    Item(BatchFailure),
    Audit(AuditError),
}

/// One line of the dialog (§5.6).
struct Line {
    class: &'static str,
    op_id: String,
    target: String,
    alias: String,
    cautions: Vec<String>,
}

/// What an item's natural positive decision records.
enum Natural {
    /// A read: its current candidate (`READ_RELEASED` with the current ops).
    Release(Arc<Candidate>),
    /// A write: the request list of the revision shown (`WRITE_APPROVED`, inv. 3).
    Approve {
        records: Vec<RequestRecord>,
        hash: [u8; 32],
        edited: bool,
    },
}

/// An item that passed its check.
struct Checked {
    entry: Arc<RequestEntry>,
    rev: CandidateRev,
    event: Event,
    natural: Natural,
    line: Line,
}

/// The decision a batch item's rejection record names.
fn submitted(kind: Kind) -> SubmittedDecision {
    match kind {
        Kind::Write => SubmittedDecision::Approve,
        _ => SubmittedDecision::Release,
    }
}

/// Logs a failed item with `batch: true` (PD-19 records; nothing for a request that is no longer
/// pending) and hands the failure back.
async fn failed(
    engine: &Arc<Engine>,
    entry: &RequestEntry,
    f: BatchFailure,
    submitted_rev: u64,
) -> Fail {
    let current = snapshot(&entry.state()).current.counter;
    let ctx = &entry.ctx;
    let dec = submitted(entry.kind());
    let record = match f {
        BatchFailure::Stale => Some(payloads::decision_stale(
            ctx,
            submitted_rev,
            current,
            dec,
            true,
        )),
        BatchFailure::Invalid(reason) => Some(payloads::decision_invalid(
            ctx,
            reason,
            submitted_rev,
            dec,
            true,
        )),
        BatchFailure::NotPending => None,
    };
    if let Some(ev) = record
        && let Err(e) = engine.blocking(move |p| p.append(ev)).await
    {
        return Fail::Audit(e);
    }
    Fail::Item(f)
}

/// A model rejection of the natural event as a batch failure (the §5.6 order: stale, not
/// opened, flagged, not approvable). A decision in a pending phase where none applies
/// (`Fetching`, `Enriching`, `StaleCheck`, `Executing`) is stale (PD-19 M-3).
fn failure_of(r: Rejection, at: &Snapshot, flagged: bool) -> BatchFailure {
    match r {
        Rejection::StaleRev { .. } => BatchFailure::Stale,
        Rejection::NotOpened => BatchFailure::Invalid(InvalidReason::NotOpened),
        Rejection::NotApprovable if flagged => {
            BatchFailure::Invalid(InvalidReason::BatchItemFlagged)
        }
        Rejection::Illegal if !is_pending(at.phase) => BatchFailure::NotPending,
        Rejection::Illegal if !decidable(at.phase) => BatchFailure::Stale,
        _ => BatchFailure::Invalid(InvalidReason::NotApprovable),
    }
}

/// The text a dialog line may carry: the invisible-character classifier applied (the registry's
/// `target_display` filter is the minimal one; display.rs leaves the rest to the dialog).
fn shown(text: &str) -> String {
    strip(text, false).0
}

fn cautions(warnings: &[atlas_duck_preview::warning::Warning]) -> Vec<String> {
    warnings
        .iter()
        .filter(|w| w.level == Level::Caution)
        .map(|w| shown(&w.text))
        .collect()
}

/// Checks one item against the current state (the rules of step 1 and step 3) and gathers what
/// its decision and its dialog line need.
async fn check(engine: &Arc<Engine>, item: &BatchItem) -> Result<Checked, Fail> {
    let Some(entry) = engine.entry(&item.request_id) else {
        return Err(Fail::Item(BatchFailure::NotPending));
    };
    let rev = item.candidate_rev;
    let kind = entry.kind();
    // Task 27 adds scripts (released as `SCRIPT_RELEASED`).
    if !matches!(kind, Kind::Read | Kind::Write) {
        return Err(Fail::Item(BatchFailure::NotPending));
    }
    let event_of = |s: &Snapshot| match kind {
        Kind::Write => Event::Approve { rev: rev.counter },
        _ => Event::Release {
            rev: rev.counter,
            redacted: s.redacted,
        },
    };
    let flagged = Flags::of(engine, &entry).any();
    let event = match dry_step(&entry, event_of, Some(&rev)) {
        Ok(_) if flagged => {
            let f = BatchFailure::Invalid(InvalidReason::BatchItemFlagged);
            return Err(failed(engine, &entry, f, rev.counter).await);
        }
        Ok(at) => event_of(&at),
        Err((r, at)) => {
            let f = failure_of(r, &at, flagged);
            return Err(failed(engine, &entry, f, rev.counter).await);
        }
    };
    let spec = entry.spec;
    let alias = entry.head.instance.clone();
    let (natural, warnings) = match kind {
        Kind::Write => {
            let Some((records, hash, edited)) = write::approval(&entry) else {
                return Err(Fail::Item(BatchFailure::NotPending));
            };
            // Inv. 3: the list approved is the list of the revision shown.
            if hash != rev.candidate_hash {
                return Err(failed(engine, &entry, BatchFailure::Stale, rev.counter).await);
            }
            let identity = write::stored_identity(engine, &entry).await;
            let executes_as = identity.as_ref().map(|i| i.atlassian_user.as_str());
            let warnings = match write::snapshot(&entry) {
                Some(write::Snapshot {
                    write: w,
                    hold: Some(hold),
                }) => write::preview_model(spec, &alias, &w, hold, executes_as).warnings,
                _ => return Err(Fail::Item(BatchFailure::NotPending)),
            };
            (
                Natural::Approve {
                    records,
                    hash,
                    edited,
                },
                warnings,
            )
        }
        _ => {
            let c = match candidate(engine, &entry).await {
                Ok(c) => c,
                Err(RebuildError::Audit(e)) => return Err(Fail::Audit(e)),
                // §5.2: a failed rebuild disabled Release on this revision.
                Err(_) => {
                    let f = BatchFailure::Invalid(InvalidReason::NotApprovable);
                    return Err(failed(engine, &entry, f, rev.counter).await);
                }
            };
            if c.hash() != &rev.candidate_hash {
                return Err(failed(engine, &entry, BatchFailure::Stale, rev.counter).await);
            }
            let Some(read) = entry.state().read.clone() else {
                return Err(Fail::Item(BatchFailure::NotPending));
            };
            let (_, cx) = read_context(&entry);
            let warnings = preview_model(&cx, &read, &c).warnings;
            (Natural::Release(c), warnings)
        }
    };
    let line = Line {
        class: entry.class(),
        op_id: entry.head.op_id.clone(),
        target: shown(&entry.target_display),
        alias,
        cautions: cautions(&warnings),
    };
    Ok(Checked {
        entry,
        rev,
        event,
        natural,
        line,
    })
}

/// Checks every item; all failures are logged (one record each), then reported together.
async fn check_all(
    engine: &Arc<Engine>,
    items: &[BatchItem],
) -> Result<Vec<Checked>, DecisionError> {
    let mut ok = Vec::with_capacity(items.len());
    let mut bad = Vec::new();
    for it in items {
        match check(engine, it).await {
            Ok(c) => ok.push(c),
            Err(Fail::Item(f)) => bad.push((it.request_id.clone(), f)),
            Err(Fail::Audit(e)) => return Err(DecisionError::Audit(e)),
        }
    }
    if bad.is_empty() {
        Ok(ok)
    } else {
        Err(DecisionError::BatchRejected { failed: bad })
    }
}

/// §5.6: "count, op ids, `target_display` per item, instance, and each item's Caution-level
/// warning texts". App-generated; the agent's reason never appears.
fn dialog_text(lines: &[Line]) -> String {
    let n = lines.len();
    let reads = lines.iter().filter(|l| l.class == "read").count();
    let writes = n - reads;
    let plural = |k: usize, one: &str, many: &str| {
        if k == 1 {
            format!("1 {one}")
        } else {
            format!("{k} {many}")
        }
    };
    let mut parts = Vec::new();
    if reads > 0 {
        parts.push(format!("release {}", plural(reads, "read", "reads")));
    }
    if writes > 0 {
        parts.push(format!("approve {}", plural(writes, "write", "writes")));
    }
    let mut s = format!(
        "Batch decision: {} ({})\n",
        plural(n, "request", "requests"),
        parts.join(", ")
    );
    for (i, l) in lines.iter().enumerate() {
        let _ = write!(s, "\n{}. {} {} on {}", i + 1, l.op_id, l.target, l.alias);
        for c in &l.cautions {
            let _ = write!(s, "\n   Caution: {c}");
        }
    }
    s
}

/// Sorted by request id (the gate order), exact repeats dropped. A request listed twice with
/// different revisions stays twice: one of them is stale and fails the check.
fn normalized(mut items: Vec<BatchItem>) -> Vec<BatchItem> {
    items.sort_by(|a, b| {
        a.request_id
            .cmp(&b.request_id)
            .then_with(|| a.candidate_rev.counter.cmp(&b.candidate_rev.counter))
            .then_with(|| {
                a.candidate_rev
                    .candidate_hash
                    .cmp(&b.candidate_rev.candidate_hash)
            })
    });
    items.dedup();
    items
}

/// The dialog on a dedicated OS thread (PD-13, PD-25); the async caller waits off the workers.
async fn confirm(engine: &Engine, text: String) -> Confirm {
    let confirmer = engine.confirmer().clone();
    tokio::task::spawn_blocking(move || {
        std::thread::Builder::new()
            .name("atlas-duck-batch-confirm".into())
            .spawn(move || confirmer.confirm(&text))
            .map(|t| t.join().unwrap_or(Confirm::Cancel))
            .unwrap_or(Confirm::Cancel)
    })
    .await
    .unwrap_or(Confirm::Cancel)
}

/// The item's record (with the `batch` flag and `batch_id`) and the state its event brings.
fn step_of(c: &Checked, batch_id: &str) -> Result<BatchStep, DecisionError> {
    let (record, on_apply): (_, OnApply) = match &c.natural {
        Natural::Release(candidate) => (release_record(&c.entry, candidate)?, Box::new(|_| {})),
        Natural::Approve {
            records,
            hash,
            edited,
        } => (
            payloads::write_approved(&c.entry.ctx, &c.rev, records, *edited),
            Box::new(write::approve_apply(*hash)),
        ),
    };
    Ok(BatchStep {
        entry: c.entry.clone(),
        event: c.event,
        record: payloads::with_batch(record, batch_id),
        on_apply,
    })
}

/// `DecisionApi::decide_batch` (module doc).
pub(super) async fn decide_batch(
    engine: Arc<Engine>,
    items: Vec<BatchItem>,
) -> Result<BatchOutcome, DecisionError> {
    // L43: one batch dialog at a time; a second batch waits here.
    let _one_dialog = engine.batch_dialog().lock().await;
    let items = normalized(items);
    if items.is_empty() {
        return Err(DecisionError::BatchRejected { failed: Vec::new() });
    }
    // 1. Pre-check, nothing held afterwards.
    let lines: Vec<Line> = check_all(&engine, &items)
        .await?
        .into_iter()
        .map(|c| c.line)
        .collect();
    // 2. The dialog.
    let text = dialog_text(&lines);
    let text_sha256: [u8; 32] = Sha256::digest(text.as_bytes()).into();
    if confirm(&engine, text).await == Confirm::Cancel {
        return Err(DecisionError::Cancelled);
    }
    // 3. Re-check under every item's gate (request id order).
    let mut entries = Vec::with_capacity(items.len());
    let mut gone = Vec::new();
    for it in &items {
        match engine.entry(&it.request_id) {
            Some(e)
                if !entries
                    .iter()
                    .any(|x: &Arc<RequestEntry>| Arc::ptr_eq(x, &e)) =>
            {
                entries.push(e);
            }
            Some(_) => {}
            None => gone.push((it.request_id.clone(), BatchFailure::NotPending)),
        }
    }
    if !gone.is_empty() {
        return Err(DecisionError::BatchRejected { failed: gone });
    }
    let gates = Engine::lock_gates(&entries).await;
    let checked = check_all(&engine, &items).await?;
    // 4. One append: `BATCH_CONFIRMED` first, then every item's decision.
    let batch_id = BatchId::new()
        .map_err(|_| DecisionError::Audit(AuditError::AppendFailed("no batch id".into())))?;
    let listed: Vec<(String, CandidateRev)> = checked
        .iter()
        .map(|c| (c.entry.head.request_id.clone(), c.rev))
        .collect();
    // The approver's identity columns are those of every other human decision record.
    let lead =
        payloads::batch_confirmed(&Actor::default(), batch_id.as_str(), &listed, &text_sha256);
    let steps = checked
        .iter()
        .map(|c| step_of(c, batch_id.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    match engine.commit_batch(&gates, lead, steps).await {
        Ok(_) => {}
        Err(BatchCommitError::Audit(e)) => return Err(DecisionError::Audit(e)),
        // The request changed outside the gate between the check and the commit (e.g. a
        // rebuild failure cleared approvability): nothing was appended.
        Err(BatchCommitError::Rejected(i, r)) => {
            let Some(c) = checked.get(i) else {
                return Err(DecisionError::BatchRejected { failed: Vec::new() });
            };
            let at = snapshot(&c.entry.state());
            let f = failure_of(r, &at, false);
            let id = c.entry.head.request_id.clone();
            return match failed(&engine, &c.entry, f, c.rev.counter).await {
                Fail::Audit(e) => Err(DecisionError::Audit(e)),
                Fail::Item(f) => Err(DecisionError::BatchRejected {
                    failed: vec![(id, f)],
                }),
            };
        }
    }
    drop(gates);
    // 5. Effects, only now.
    let mut out = Vec::with_capacity(checked.len());
    for c in &checked {
        queue_changed(&engine, &c.entry);
        if matches!(c.natural, Natural::Approve { .. }) {
            write::start_stale_check(&engine, &c.entry, c.rev.counter);
        }
        out.push(outcome(&c.entry));
    }
    Ok(BatchOutcome {
        batch_id: batch_id.as_str().to_owned(),
        items: out,
    })
}

/// Denies one queued item at its current revision (one retry if the revision moves meanwhile).
async fn deny_one(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    reason: &str,
) -> Option<Result<DecisionOutcome, DecisionError>> {
    let mut last = None;
    for _ in 0..2 {
        let rev = {
            let st = entry.state();
            if !decidable(st.model.phase()) {
                return last;
            }
            current_rev(&st)
        };
        let res = match entry.kind() {
            Kind::Read => {
                let d = Decision {
                    request_id: entry.head.request_id.clone(),
                    decision: DecisionKind::Deny,
                    candidate_rev: rev,
                    edits: None,
                    redactions: None,
                    reason: Some(reason.to_owned()),
                    deny_details: None,
                };
                deny(engine, entry, &d).await
            }
            Kind::Write => deny_write(engine, entry, rev, Some(reason), None).await,
            // Task 27 adds scripts.
            Kind::Script | Kind::DryRun => return None,
        };
        let retry = matches!(res, Err(DecisionError::Stale { .. }));
        last = Some(res);
        if !retry {
            break;
        }
    }
    last
}

/// `DecisionApi::deny_batch`: every listed item still in the queue is denied with `reason`, one
/// record each, no dialog; returns how many were denied. Items that are not (or no longer)
/// waiting for a decision are skipped. An audit failure on some item does not stop the others;
/// if nothing could be denied because of one, the audit error is returned.
pub(super) async fn deny_batch(
    engine: Arc<Engine>,
    request_ids: Vec<String>,
    reason: String,
) -> Result<usize, DecisionError> {
    let mut seen = BTreeSet::new();
    let mut denied = 0;
    let mut audit = None;
    for id in request_ids {
        if !seen.insert(id.clone()) {
            continue;
        }
        let Some(entry) = engine.entry(&id) else {
            continue;
        };
        match deny_one(&engine, &entry, &reason).await {
            Some(Ok(_)) => denied += 1,
            Some(Err(DecisionError::Audit(e))) => audit = Some(e),
            _ => {}
        }
    }
    match audit {
        Some(e) if denied == 0 => Err(DecisionError::Audit(e)),
        _ => Ok(denied),
    }
}

/// The queued items of one session (§5.6 "select all from session"), sorted.
pub(super) fn session_items(engine: &Engine, session: &SessionKey) -> Vec<String> {
    let mut ids: Vec<String> = engine
        .pending_entries()
        .iter()
        .filter(|e| e.session == *session && decidable(e.state().model.phase()))
        .map(|e| e.head.request_id.clone())
        .collect();
    ids.sort();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(class: &'static str, target: &str, cautions: &[&str]) -> Line {
        Line {
            class,
            op_id: "jira.issue.get".into(),
            target: shown(target),
            alias: "jira-main".into(),
            cautions: cautions.iter().map(|c| (*c).to_owned()).collect(),
        }
    }

    #[test]
    fn dialog_text_lists_every_item_and_its_cautions() {
        let text = dialog_text(&[
            line("read", "ABC-1", &["all fields requested (`*all`)"]),
            line("write", "ABC-2", &[]),
        ]);
        assert!(text.starts_with("Batch decision: 2 requests (release 1 read, approve 1 write)"));
        assert!(text.contains("\n1. jira.issue.get ABC-1 on jira-main"));
        assert!(text.contains("\n   Caution: all fields requested (`*all`)"));
        assert!(text.contains("\n2. jira.issue.get ABC-2 on jira-main"));
    }

    #[test]
    fn dialog_targets_lose_invisible_characters() {
        let text = dialog_text(&[line("read", "ABC\u{202E}-1", &[])]);
        assert!(!text.contains('\u{202E}'), "{text:?}");
    }

    #[test]
    fn normalized_sorts_and_drops_exact_repeats() {
        let rev = |counter| CandidateRev {
            counter,
            candidate_hash: [0; 32],
        };
        let item = |id: &str, counter| BatchItem {
            request_id: id.into(),
            candidate_rev: rev(counter),
        };
        let out = normalized(vec![
            item("req_b", 1),
            item("req_a", 1),
            item("req_b", 1),
            item("req_b", 2),
        ]);
        assert_eq!(
            out,
            vec![item("req_a", 1), item("req_b", 1), item("req_b", 2)]
        );
    }
}
