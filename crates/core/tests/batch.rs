#![cfg(feature = "testing")]
//! Batch decisions (Task 23, L43, I-06 batch clauses): all-or-nothing approve/release with the
//! native dialog, checked before and after it, `BATCH_CONFIRMED` and every per-item decision in
//! one `append_batch`; batch and session deny per item without a dialog; "Needs attention"
//! acknowledgement.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::{EventFlags, EventType};
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::{Channel, FaultPlan, Harness};
use atlas_duck_core::{BatchFailure, BatchItem, Confirm, DecisionError};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_ipc::proto::SubmitParams;
use atlas_duck_preview::warning::TEXT_ALL_FIELDS;
use common::{TestError, TestResult, de, request_id};
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path};

const ISSUE: &str = "jira.issue.get";
const COMMENT: &str = "jira.comment.add";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

/// A `jira.issue.get` of `key`, queued.
async fn read_item(h: &Harness, key: &str) -> Result<String, TestError> {
    jira(h)?
        .json(
            &format!("/rest/api/2/issue/{key}"),
            200,
            fixtures::JIRA_ISSUE,
        )
        .await;
    let id = request_id(&h.submit(ISSUE, json!({ "key": key })).await)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

async fn identity_ok(mock: &MockDc) {
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
}

async fn mount_comment_post(mock: &MockDc, status: u16) {
    let t = if status < 300 {
        mock.response(status)
            .set_body_raw(fixtures::JIRA_COMMENT, "application/json")
    } else {
        mock.response(status).set_body_raw(
            r#"{"errorMessages":["Comment body can not be empty!"],"errors":{}}"#,
            "application/json",
        )
    };
    Mock::given(method("POST"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1/comment")))
        .respond_with(t)
        .with_priority(1)
        .mount(mock.server())
        .await;
}

/// A `jira.comment.add` on `ABC-1`, queued.
async fn comment_item(h: &Harness, body: &str) -> Result<String, TestError> {
    let params = json!({ "key": "ABC-1", "body": body, "body_format": "wiki" });
    let id = request_id(&h.submit(COMMENT, params).await)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

fn batch_item(h: &Harness, id: &str) -> Result<BatchItem, TestError> {
    Ok(BatchItem {
        request_id: id.to_owned(),
        candidate_rev: h.approver().rev(id).map_err(de)?,
    })
}

fn items(h: &Harness, ids: &[&str]) -> Result<Vec<BatchItem>, TestError> {
    ids.iter().map(|id| batch_item(h, id)).collect()
}

/// The payloads of every record of type `t` of `id`.
async fn records(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

/// How many records of `t` the store holds (any request, system records too).
fn count_type(h: &Harness, t: EventType) -> Result<usize, TestError> {
    Ok(h.store()
        .recent_headers(Duration::from_secs(24 * 3600))?
        .iter()
        .filter(|e| e.event_type == t)
        .count())
}

fn rejected(
    res: Result<atlas_duck_core::BatchOutcome, DecisionError>,
) -> Result<Vec<(String, BatchFailure)>, TestError> {
    match res {
        Err(DecisionError::BatchRejected { failed }) => Ok(failed),
        other => Err(format!("expected BatchRejected, got {other:?}").into()),
    }
}

/// Still pending and in the queue, with the opened flag as given.
fn still_queued(h: &Harness, ids: &[&str], opened: bool) -> TestResult {
    for id in ids {
        let item = h.approver().item(id).ok_or("left the queue")?;
        assert_eq!(item.opened, opened, "{id}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_batch_with_unopened_applies_none() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let a = read_item(&h, "ABC-1").await?;
    let b = read_item(&h, "ABC-2").await?;
    let c = read_item(&h, "ABC-3").await?;
    h.approver().open(&a).map_err(de)?;
    h.approver().open(&b).map_err(de)?;
    let failed = rejected(h.decisions().decide_batch(items(&h, &[&a, &b, &c])?))?;
    assert_eq!(
        failed,
        [(c.clone(), BatchFailure::Invalid(InvalidReason::NotOpened))]
    );
    assert_eq!(
        records(&h, &c, EventType::DECISION_INVALID).await?,
        [
            json!({ "reason": "not_opened", "submitted_rev": 1, "decision": "release", "batch": true })
        ]
    );
    for id in [&a, &b] {
        assert!(
            records(&h, id, EventType::DECISION_INVALID)
                .await?
                .is_empty()
        );
    }
    for id in [&a, &b, &c] {
        assert!(records(&h, id, EventType::READ_RELEASED).await?.is_empty());
    }
    assert_eq!(count_type(&h, EventType::BATCH_CONFIRMED)?, 0);
    assert!(
        h.confirmer().texts().is_empty(),
        "no dialog for a failed pre-check"
    );
    still_queued(&h, &[&a, &b], true)?;
    still_queued(&h, &[&c], false)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_batch_with_stale_applies_none() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let a = read_item(&h, "ABC-1").await?;
    let b = read_item(&h, "ABC-2").await?;
    let ap = h.approver();
    ap.open(&a).map_err(de)?;
    let old = ap.open(&b).map_err(de)?.preview.candidate_rev;
    let mask = atlas_duck_core::RedactionOp::MaskText {
        text: "Login page".into(),
        every_occurrence: true,
        at: None,
    };
    let new = ap.redact(&b, vec![mask]).map_err(de)?;
    h.decisions().preview_fetch(&b, Some(new)).map_err(de)?;
    let batch = vec![
        batch_item(&h, &a)?,
        BatchItem {
            request_id: b.clone(),
            candidate_rev: old,
        },
    ];
    let failed = rejected(h.decisions().decide_batch(batch))?;
    assert_eq!(failed, [(b.clone(), BatchFailure::Stale)]);
    assert_eq!(
        records(&h, &b, EventType::DECISION_STALE).await?,
        [json!({ "submitted_rev": 1, "current_rev": 2, "decision": "release", "batch": true })]
    );
    assert!(records(&h, &a, EventType::READ_RELEASED).await?.is_empty());
    assert_eq!(count_type(&h, EventType::BATCH_CONFIRMED)?, 0);
    still_queued(&h, &[&a, &b], true)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_batch_with_duplicate_applies_none() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let a = read_item(&h, "ABC-1").await?;
    let b = read_item(&h, "ABC-1").await?;
    let ap = h.approver();
    ap.open(&a).map_err(de)?;
    ap.open(&b).map_err(de)?;
    let row = ap.item(&b).ok_or("not queued")?;
    assert_eq!(row.possible_duplicate_of.as_deref(), Some(a.as_str()));
    let failed = rejected(h.decisions().decide_batch(items(&h, &[&a, &b])?))?;
    let flagged = BatchFailure::Invalid(InvalidReason::BatchItemFlagged);
    let mut want = vec![(a.clone(), flagged), (b.clone(), flagged)];
    want.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(failed, want, "both flagged, in request id order");
    assert_eq!(
        records(&h, &a, EventType::DECISION_INVALID).await?,
        [
            json!({ "reason": "batch_item_flagged", "submitted_rev": 1, "decision": "release", "batch": true })
        ]
    );
    assert_eq!(count_type(&h, EventType::BATCH_CONFIRMED)?, 0);
    // Individually, each can still be released.
    ap.release(&a).map_err(de)?;
    assert_eq!(h.await_(&a, 5000).await.status, Status::Released);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_batch_mixed_not_approvable_rejected() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount_comment_post(mock, 201).await;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    let clean = comment_item(&h, "Done.").await?;
    let edit = request_id(
        &h.submit(
            "jira.issue.edit",
            json!({
                "key": "ABC-1",
                "fields": { "summary": "Login fails after reset" },
                "expected": { "summary": "Login page time out" }
            }),
        )
        .await,
    )?;
    h.queued(&edit, 10_000).await.ok_or("never queued")?;
    let ap = h.approver();
    ap.open(&clean).map_err(de)?;
    ap.open(&edit).map_err(de)?;
    assert!(!ap.item(&edit).ok_or("gone")?.approvable);
    let failed = rejected(h.decisions().decide_batch(items(&h, &[&clean, &edit])?))?;
    assert_eq!(
        failed,
        [(
            edit.clone(),
            BatchFailure::Invalid(InvalidReason::NotApprovable)
        )]
    );
    assert_eq!(
        records(&h, &edit, EventType::DECISION_INVALID).await?,
        [
            json!({ "reason": "not_approvable", "submitted_rev": 1, "decision": "approve", "batch": true })
        ]
    );
    for id in [&clean, &edit] {
        assert!(records(&h, id, EventType::WRITE_APPROVED).await?.is_empty());
    }
    assert!(h.confirmer().texts().is_empty());
    assert!(
        !mock
            .received()
            .await
            .iter()
            .any(|r| r.method.as_str() == "POST" || r.method.as_str() == "PUT")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_confirmer_cancel_changes_nothing() -> TestResult {
    // The script is empty: the stub answers Cancel.
    let h = Harness::jira().await?;
    let a = read_item(&h, "ABC-1").await?;
    let b = read_item(&h, "ABC-2").await?;
    h.approver().open(&a).map_err(de)?;
    h.approver().open(&b).map_err(de)?;
    let before = h.event_count().await?;
    let res = h.decisions().decide_batch(items(&h, &[&a, &b])?);
    assert!(matches!(res, Err(DecisionError::Cancelled)), "{res:?}");
    assert_eq!(h.confirmer().texts().len(), 1);
    assert_eq!(h.event_count().await?, before, "Cancel logs nothing");
    still_queued(&h, &[&a, &b], true)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l43_cancel_logs_nothing() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Cancel])
        .start()
        .await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount_comment_post(mock, 201).await;
    let w = comment_item(&h, "Done.").await?;
    let r = read_item(&h, "ABC-2").await?;
    h.approver().open(&w).map_err(de)?;
    h.approver().open(&r).map_err(de)?;
    let before = h.event_count().await?;
    let res = h.decisions().decide_batch(items(&h, &[&w, &r])?);
    assert!(matches!(res, Err(DecisionError::Cancelled)), "{res:?}");
    assert_eq!(h.event_count().await?, before);
    assert_eq!(count_type(&h, EventType::BATCH_CONFIRMED)?, 0);
    assert!(records(&h, &w, EventType::WRITE_APPROVED).await?.is_empty());
    still_queued(&h, &[&w, &r], true)?;
    // Nothing was sent.
    assert!(
        !mock
            .received()
            .await
            .iter()
            .any(|r| r.method.as_str() == "POST")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l43_item_expiring_during_dialog_rejects_batch() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let a = read_item(&h, "ABC-1").await?;
    let b = read_item(&h, "ABC-2").await?;
    h.approver().open(&a).map_err(de)?;
    h.approver().open(&b).map_err(de)?;
    let (engine, handle, gone) = (
        h.engine().clone(),
        tokio::runtime::Handle::current(),
        b.clone(),
    );
    // The dialog runs on its own thread: the expiry runs on the core's runtime meanwhile.
    h.confirmer().set_hook(Arc::new(move |_| {
        assert!(handle.block_on(engine.expire_now(&gone)));
    }));
    let failed = rejected(h.decisions().decide_batch(items(&h, &[&a, &b])?))?;
    assert_eq!(failed, [(b.clone(), BatchFailure::NotPending)]);
    assert_eq!(count_type(&h, EventType::BATCH_CONFIRMED)?, 0);
    assert!(records(&h, &a, EventType::READ_RELEASED).await?.is_empty());
    // A request that left the queue is not logged as stale or invalid.
    assert!(records(&h, &b, EventType::DECISION_STALE).await?.is_empty());
    assert!(
        records(&h, &b, EventType::DECISION_INVALID)
            .await?
            .is_empty()
    );
    still_queued(&h, &[&a], true)?;
    assert_eq!(h.status(&b).await.status, Status::Expired);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l43_revision_change_during_dialog_rejects_batch() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let a = read_item(&h, "ABC-1").await?;
    let b = read_item(&h, "ABC-2").await?;
    h.approver().open(&a).map_err(de)?;
    h.approver().open(&b).map_err(de)?;
    let (decisions, changed) = (h.decisions(), b.clone());
    h.confirmer().set_hook(Arc::new(move |_| {
        let Some(rev) = decisions.queue_get(&changed).map(|i| i.candidate_rev) else {
            return;
        };
        let mask = atlas_duck_core::RedactionOp::MaskText {
            text: "Login page".into(),
            every_occurrence: true,
            at: None,
        };
        let _ = decisions.decide(atlas_duck_core::Decision {
            request_id: changed.clone(),
            decision: atlas_duck_core::DecisionKind::ReleaseRedacted,
            candidate_rev: rev,
            edits: None,
            redactions: Some(vec![mask]),
            reason: None,
            deny_details: None,
        });
    }));
    let failed = rejected(h.decisions().decide_batch(items(&h, &[&a, &b])?))?;
    assert_eq!(failed, [(b.clone(), BatchFailure::Stale)]);
    assert_eq!(
        records(&h, &b, EventType::DECISION_STALE).await?,
        [json!({ "submitted_rev": 1, "current_rev": 2, "decision": "release", "batch": true })]
    );
    assert_eq!(count_type(&h, EventType::BATCH_CONFIRMED)?, 0);
    assert!(records(&h, &a, EventType::READ_RELEASED).await?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l43_duplicate_arriving_during_dialog_rejects_batch() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let a = read_item(&h, "ABC-1").await?;
    let b = read_item(&h, "ABC-2").await?;
    h.approver().open(&a).map_err(de)?;
    h.approver().open(&b).map_err(de)?;
    // While the dialog is open the agent submits `ABC-2` again: the re-check finds `b` flagged.
    let (handler, conn, handle) = (
        h.handler(),
        h.default_conn().clone(),
        tokio::runtime::Handle::current(),
    );
    h.confirmer().set_hook(Arc::new(move |_| {
        let params = SubmitParams {
            op_id: ISSUE.to_owned(),
            params: json!({ "key": "ABC-2" }),
            instance: None,
            reason: None,
        };
        handle.block_on(handler.submit(&conn, params));
    }));
    let failed = rejected(h.decisions().decide_batch(items(&h, &[&a, &b])?))?;
    assert_eq!(
        failed,
        [(
            b.clone(),
            BatchFailure::Invalid(InvalidReason::BatchItemFlagged)
        )]
    );
    assert_eq!(
        records(&h, &b, EventType::DECISION_INVALID).await?,
        [
            json!({ "reason": "batch_item_flagged", "submitted_rev": 1, "decision": "release", "batch": true })
        ]
    );
    assert_eq!(count_type(&h, EventType::BATCH_CONFIRMED)?, 0);
    assert!(records(&h, &a, EventType::READ_RELEASED).await?.is_empty());
    still_queued(&h, &[&a, &b], true)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l43_append_failure_on_batch_decides_nothing() -> TestResult {
    let plan = FaultPlan::new();
    plan.fail_nth(EventType::BATCH_CONFIRMED, 1);
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan)
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount_comment_post(mock, 201).await;
    let w = comment_item(&h, "Done.").await?;
    let r = read_item(&h, "ABC-2").await?;
    h.approver().open(&w).map_err(de)?;
    h.approver().open(&r).map_err(de)?;
    let before = h.event_count().await?;
    let res = h.decisions().decide_batch(items(&h, &[&w, &r])?);
    assert!(matches!(res, Err(DecisionError::Audit(_))), "{res:?}");
    assert_eq!(h.plan().attempts(EventType::BATCH_CONFIRMED), 1);
    assert_eq!(h.event_count().await?, before, "nothing committed");
    // Every item is still pending, opened and decidable; nothing was sent.
    still_queued(&h, &[&w, &r], true)?;
    assert_eq!(h.status(&w).await.status, Status::Pending);
    assert_eq!(h.status(&r).await.status, Status::Pending);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !mock
            .received()
            .await
            .iter()
            .any(|r| r.method.as_str() == "POST" || r.url.path().ends_with("/myself"))
    );
    // The next attempt goes through.
    h.confirmer().push(Confirm::Ok);
    h.decisions()
        .decide_batch(items(&h, &[&w, &r])?)
        .map_err(de)?;
    assert_eq!(h.await_(&r, 5000).await.status, Status::Released);
    assert_eq!(h.await_(&w, 10_000).await.status, Status::Succeeded);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l43_one_dialog_at_a_time() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok, Confirm::Ok])
        .start()
        .await?;
    let a = read_item(&h, "ABC-1").await?;
    let b = read_item(&h, "ABC-2").await?;
    h.approver().open(&a).map_err(de)?;
    h.approver().open(&b).map_err(de)?;
    let open = Arc::new(AtomicUsize::new(0));
    let most = Arc::new(AtomicUsize::new(0));
    let (o, m) = (open.clone(), most.clone());
    h.confirmer().set_hook(Arc::new(move |_| {
        let now = o.fetch_add(1, Ordering::SeqCst) + 1;
        m.fetch_max(now, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(300));
        o.fetch_sub(1, Ordering::SeqCst);
    }));
    let (ia, ib) = (vec![batch_item(&h, &a)?], vec![batch_item(&h, &b)?]);
    let (da, db) = (h.decisions(), h.decisions());
    let results = tokio::task::block_in_place(|| {
        std::thread::scope(|s| {
            let ta = s.spawn(move || da.decide_batch(ia));
            let tb = s.spawn(move || db.decide_batch(ib));
            (ta.join(), tb.join())
        })
    });
    let (ra, rb) = match results {
        (Ok(ra), Ok(rb)) => (ra, rb),
        _ => return Err("a batch thread panicked".into()),
    };
    ra.map_err(de)?;
    rb.map_err(de)?;
    assert_eq!(h.confirmer().texts().len(), 2);
    assert_eq!(
        most.load(Ordering::SeqCst),
        1,
        "two dialogs were open at once"
    );
    assert_eq!(count_type(&h, EventType::BATCH_CONFIRMED)?, 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l43_batch_deny_per_item_no_dialog() -> TestResult {
    let h = Harness::jira().await?;
    let ids = [
        read_item(&h, "ABC-1").await?,
        read_item(&h, "ABC-2").await?,
        read_item(&h, "ABC-3").await?,
        read_item(&h, "ABC-4").await?,
    ];
    h.approver().deny_unopened(&ids[3], "not now").map_err(de)?;
    let n = h.decisions().deny_batch(&ids, "out of scope").map_err(de)?;
    assert_eq!(n, 3);
    assert!(
        h.confirmer().texts().is_empty(),
        "batch deny shows no dialog"
    );
    for id in &ids[..3] {
        assert_eq!(
            records(&h, id, EventType::READ_DENIED).await?,
            [json!({ "reason": "out of scope" })]
        );
        let env = h.await_(id, 5000).await;
        assert_eq!(env.status, Status::Denied);
        // No dialog, no `BATCH_CONFIRMED`: the per-item denies carry no batch flag (U-32).
        let headers = h.store().headers_for_request(id)?;
        assert!(
            headers.iter().all(|e| !e.flags.contains(EventFlags::BATCH)),
            "{id}"
        );
    }
    assert_eq!(
        records(&h, &ids[3], EventType::READ_DENIED).await?,
        [json!({ "reason": "not now" })]
    );
    assert_eq!(count_type(&h, EventType::BATCH_CONFIRMED)?, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deny_session_denies_only_that_session() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    for key in ["ABC-1", "ABC-2", "ABC-3"] {
        mock.json(
            &format!("/rest/api/2/issue/{key}"),
            200,
            fixtures::JIRA_ISSUE,
        )
        .await;
    }
    let other = h.conn("other-agent").await?;
    let mine1 = request_id(&h.submit(ISSUE, json!({ "key": "ABC-1" })).await)?;
    let mine2 = request_id(&h.submit(ISSUE, json!({ "key": "ABC-2" })).await)?;
    let theirs = request_id(
        &h.submit_with(&other, ISSUE, json!({ "key": "ABC-3" }), None)
            .await,
    )?;
    for id in [&mine1, &mine2, &theirs] {
        h.queued(id, 10_000).await.ok_or("never queued")?;
    }
    let session = h.approver().item(&mine1).ok_or("gone")?.session;
    assert_ne!(session, h.approver().item(&theirs).ok_or("gone")?.session);
    let n = h
        .decisions()
        .deny_session(session, "wrong session")
        .map_err(de)?;
    assert_eq!(n, 2);
    assert_eq!(h.await_(&mine1, 5000).await.status, Status::Denied);
    assert_eq!(h.await_(&mine2, 5000).await.status, Status::Denied);
    assert!(
        h.approver().item(&theirs).is_some(),
        "another session untouched"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_happy_path_reads_and_writes() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount_comment_post(mock, 201).await;
    let r1 = read_item(&h, "ABC-1").await?;
    let r2 = read_item(&h, "ABC-2").await?;
    let w = comment_item(&h, "Done.").await?;
    let ap = h.approver();
    for id in [&r1, &r2, &w] {
        ap.open(id).map_err(de)?;
    }
    h.plan().record_appends(true);
    let batch = items(&h, &[&r1, &r2, &w])?;
    let out = h.decisions().decide_batch(batch.clone()).map_err(de)?;
    h.plan().record_appends(false);
    assert!(out.batch_id.starts_with("bat_"));
    assert_eq!(out.items.len(), 3);
    // One `append_batch` holds `BATCH_CONFIRMED` first and every per-item decision.
    let calls = h.plan().appends();
    let call = calls
        .iter()
        .find(|c| {
            c.first()
                .is_some_and(|e| e.event_type == EventType::BATCH_CONFIRMED)
        })
        .ok_or("no BATCH_CONFIRMED call")?;
    assert_eq!(call.len(), 4);
    let lead = &call[0].payload;
    assert_eq!(lead["batch_id"], json!(out.batch_id));
    assert_eq!(lead["items"].as_array().map(Vec::len), Some(3));
    let mut kinds: Vec<EventType> = call[1..].iter().map(|e| e.event_type).collect();
    kinds.sort_by_key(|t| t.as_str());
    assert_eq!(
        kinds,
        [
            EventType::READ_RELEASED,
            EventType::READ_RELEASED,
            EventType::WRITE_APPROVED
        ]
    );
    for e in &call[1..] {
        assert!(e.flags.contains(EventFlags::BATCH));
        assert_eq!(e.payload["batch_id"], json!(out.batch_id));
        let id = e.request_id.clone().ok_or("no request id")?;
        let listed = lead["items"]
            .as_array()
            .ok_or("no items")?
            .iter()
            .find(|i| i["request_id"] == json!(id))
            .ok_or("not listed")?;
        let rev = &batch
            .iter()
            .find(|b| b.request_id == id)
            .ok_or("not in batch")?
            .candidate_rev;
        assert_eq!(listed["candidate_rev"]["counter"], json!(rev.counter));
        assert_eq!(
            listed["candidate_rev"]["candidate_hash"],
            json!(hex::encode(rev.candidate_hash))
        );
    }
    assert!(
        lead["dialog_text_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64)
    );
    // Effects start only after the commit: the reads deliver, the write executes.
    assert_eq!(h.await_(&r1, 5000).await.status, Status::Released);
    assert_eq!(h.await_(&r2, 5000).await.status, Status::Released);
    let env = h.await_(&w, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(
        h.event_types(&w).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_SHOWN,
            EventType::WRITE_APPROVED,
            EventType::PREVIEW_FETCH,
            EventType::WRITE_EXECUTED,
            EventType::DELIVERED,
        ]
    );
    let approved = h
        .store()
        .headers_for_request(&w)?
        .into_iter()
        .find(|e| e.event_type == EventType::WRITE_APPROVED)
        .ok_or("no WRITE_APPROVED")?;
    assert!(approved.flags.contains(EventFlags::BATCH));
    assert_eq!(approved.decision.map(|d| d.as_str()), Some("approve"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dialog_text_has_targets_and_cautions() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.json("/rest/api/2/issue/XYZ-9", 200, fixtures::JIRA_ISSUE)
        .await;
    let env = h
        .handler()
        .submit(
            h.default_conn(),
            SubmitParams {
                op_id: ISSUE.to_owned(),
                params: json!({ "key": "ABC-1", "fields": ["*all"] }),
                instance: None,
                reason: Some("AGENTREASON-7f3a: please hurry".to_owned()),
            },
        )
        .await;
    let a = request_id(&env)?;
    h.queued(&a, 10_000).await.ok_or("never queued")?;
    let b = read_item(&h, "XYZ-9").await?;
    h.approver().open(&a).map_err(de)?;
    h.approver().open(&b).map_err(de)?;
    let res = h.decisions().decide_batch(items(&h, &[&a, &b])?);
    assert!(matches!(res, Err(DecisionError::Cancelled)), "{res:?}");
    let texts = h.confirmer().texts();
    let text = texts.first().ok_or("no dialog")?;
    assert!(text.contains("2 requests"), "{text}");
    assert!(text.contains(ISSUE), "{text}");
    assert!(text.contains("ABC-1") && text.contains("XYZ-9"), "{text}");
    assert!(text.contains("jira-main"), "{text}");
    assert!(text.contains(TEXT_ALL_FIELDS), "{text}");
    assert!(!text.contains("AGENTREASON"), "{text}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn needs_attention_until_acknowledged() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount_comment_post(mock, 400).await;
    let w = comment_item(&h, "Done.").await?;
    h.approver().approve(&w).map_err(de)?;
    let env = h.await_(&w, 10_000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(h.engine().needs_attention(), [w.clone()]);
    h.decisions()
        .acknowledge_attention(std::slice::from_ref(&w));
    assert!(h.engine().needs_attention().is_empty());
    let counts: Vec<u64> = h
        .capture()
        .records()
        .iter()
        .filter(|r| r.channel == Channel::UiEvent)
        .filter_map(|r| serde_json::from_str::<Value>(&r.json).ok())
        .filter_map(|e| e.pointer("/NeedsAttentionChanged/count")?.as_u64())
        .collect();
    assert_eq!(counts, [1, 0]);
    Ok(())
}
