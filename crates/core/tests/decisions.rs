#![cfg(feature = "testing")]
//! The Rust decision rules on reads (Task 21, I-06 read half): "opened" per revision (§5.6),
//! decision binding to the current revision (§5.1 inv. 5), `PREVIEW_SHOWN` fail-closed, the
//! PD-19 rejection records, redaction revisions and Raw pages. The write half is Task 22's.

mod common;

use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::{FaultPlan, Harness};
use atlas_duck_core::{
    CandidateRev, Decision, DecisionError, DecisionKind, RedactionOp, RedactionPreset,
};
use atlas_duck_ipc::envelope::Status;
use common::{TestError, TestResult, de, request_id};
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::path;

const ISSUE: &str = "jira.issue.get";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

async fn issue_item(h: &Harness) -> Result<String, TestError> {
    jira(h)?
        .json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    let id = request_id(&h.submit(ISSUE, json!({ "key": "ABC-1" })).await)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

/// The payloads of every record of type `t`.
async fn records(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

fn release(id: &str, rev: CandidateRev) -> Decision {
    Decision {
        request_id: id.to_owned(),
        decision: DecisionKind::Release,
        candidate_rev: rev,
        edits: None,
        redactions: None,
        reason: None,
        deny_details: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_unopened_release_rejected() -> TestResult {
    let h = Harness::jira().await?;
    let id = issue_item(&h).await?;
    let res = h.approver().release_unopened(&id);
    assert!(
        matches!(res, Err(DecisionError::Invalid(InvalidReason::NotOpened))),
        "{res:?}"
    );
    let invalid = records(&h, &id, EventType::DECISION_INVALID).await?;
    assert_eq!(
        invalid,
        [
            json!({ "reason": "not_opened", "submitted_rev": 1, "decision": "release", "batch": false })
        ]
    );
    // No state change: still pending, still in the queue, unopened.
    assert_eq!(h.status(&id).await.status, Status::Pending);
    let item = h.approver().item(&id).ok_or("left the queue")?;
    assert!(!item.opened);
    assert!(records(&h, &id, EventType::READ_RELEASED).await?.is_empty());
    // Opened, the same release goes through.
    h.approver().release(&id).map_err(de)?;
    assert_eq!(h.await_(&id, 5000).await.status, Status::Released);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_rev_release_rejected() -> TestResult {
    let h = Harness::jira().await?;
    let id = issue_item(&h).await?;
    let ap = h.approver();
    let rev1 = ap.open(&id).map_err(de)?.preview.candidate_rev;
    assert_eq!(rev1.counter, 1);
    let mask = RedactionOp::MaskText {
        text: "Login page".into(),
        every_occurrence: true,
        at: None,
    };
    let rev2 = ap.redact(&id, vec![mask.clone()]).map_err(de)?;
    assert_eq!(rev2.counter, 2);
    assert_ne!(rev2.candidate_hash, rev1.candidate_hash);
    // The redaction is pending, not a release.
    assert_eq!(h.status(&id).await.status, Status::Pending);
    let res = h.decisions().decide(release(&id, rev1));
    match res {
        Err(DecisionError::Stale { current }) => assert_eq!(current, rev2),
        other => return Err(format!("{other:?}").into()),
    }
    assert_eq!(
        records(&h, &id, EventType::DECISION_STALE).await?,
        [json!({ "submitted_rev": 1, "current_rev": 2, "decision": "release", "batch": false })]
    );
    // Revision 2 is not opened yet (a new revision clears the flag).
    let res = h.decisions().decide(release(&id, rev2));
    assert!(
        matches!(res, Err(DecisionError::Invalid(InvalidReason::NotOpened))),
        "{res:?}"
    );
    let shown = h.decisions().preview_fetch(&id, Some(rev2)).map_err(de)?;
    assert!(
        !serde_json::to_string(&shown.preview)?.contains("Login page times out"),
        "the preview shows the masked revision"
    );
    // A redacted revision rebuilds to the same hash (T20 contract, review M-4): evicted, the
    // release rebuilds it from the record and its ops and goes through.
    h.evict_candidate(&id);
    h.decisions().decide(release(&id, rev2)).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released);
    assert!(env.redacted);
    let line = env.to_json_line();
    assert!(!line.contains("Login page"), "{line}");
    let meta = env.meta.clone().ok_or("no meta")?;
    assert!(meta["redactions"]["spans_masked"].as_u64() >= Some(1));
    // The release records the ops it applied (§5.2 step 7).
    let released = records(&h, &id, EventType::READ_RELEASED).await?;
    assert_eq!(
        released.first().map(|r| r["redaction_ops"].clone()),
        Some(serde_json::to_value(vec![mask])?)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preview_shown_fail_closed() -> TestResult {
    let plan = FaultPlan::new();
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .start()
        .await?;
    let id = issue_item(&h).await?;
    plan.fail_nth(EventType::PREVIEW_SHOWN, 1);
    let res = h.approver().open(&id);
    assert!(matches!(res, Err(DecisionError::Audit(_))), "{res:?}");
    // Nothing delivered, the flag stays clear and the request is unchanged (§5.6).
    let res = h.approver().release_unopened(&id);
    assert!(
        matches!(res, Err(DecisionError::Invalid(InvalidReason::NotOpened))),
        "{res:?}"
    );
    assert_eq!(h.status(&id).await.status, Status::Pending);
    assert!(records(&h, &id, EventType::PREVIEW_SHOWN).await?.is_empty());
    // The next open commits and opens.
    h.approver().release(&id).map_err(de)?;
    assert_eq!(h.await_(&id, 5000).await.status, Status::Released);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn decision_while_fetching_is_stale_preview_not_decidable() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    Mock::given(path(mock.path("/rest/api/2/issue/SLOW-1")))
        .respond_with(
            mock.response(200)
                .set_body_raw(fixtures::JIRA_ISSUE, "application/json")
                .set_delay(Duration::from_millis(1500)),
        )
        .mount(mock.server())
        .await;
    let id = request_id(&h.submit(ISSUE, json!({ "key": "SLOW-1" })).await)?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let rev0 = CandidateRev {
        counter: 0,
        candidate_hash: [0; 32],
    };
    // PD-29: a preview of a request that waits for nothing is refused, nothing logged.
    let res = h.decisions().preview_fetch(&id, None);
    assert!(matches!(res, Err(DecisionError::NotDecidable)), "{res:?}");
    // PD-19 M-3: a decision on a pending request in a phase without decisions is stale.
    let res = h.decisions().decide(release(&id, rev0));
    assert!(matches!(res, Err(DecisionError::Stale { .. })), "{res:?}");
    assert_eq!(
        records(&h, &id, EventType::DECISION_STALE).await?,
        [json!({ "submitted_rev": 0, "current_rev": 0, "decision": "release", "batch": false })]
    );
    assert!(records(&h, &id, EventType::PREVIEW_SHOWN).await?.is_empty());
    // The read then arrives normally.
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_redaction_is_not_approvable() -> TestResult {
    let h = Harness::jira().await?;
    let id = issue_item(&h).await?;
    h.approver().open(&id).map_err(de)?;
    // `StatusOnly` expects the upstream-error shape: on a result it names nothing (blocks).
    let res = h
        .approver()
        .redact(&id, vec![RedactionOp::Preset(RedactionPreset::StatusOnly)]);
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    let item = h.approver().item(&id).ok_or("left the queue")?;
    assert_eq!(item.candidate_rev.counter, 1, "no new revision");
    assert!(item.opened && item.approvable);
    assert_eq!(
        records(&h, &id, EventType::DECISION_INVALID)
            .await?
            .first()
            .map(|r| r["reason"].clone()),
        Some(json!("not_approvable"))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_pages_are_exact_slices() -> TestResult {
    let h = Harness::jira().await?;
    let summary: String = std::iter::repeat_n('r', 600 * 1024).collect();
    let body = json!({ "key": "ABC-1", "fields": { "summary": summary } }).to_string();
    jira(&h)?.json("/rest/api/2/issue/ABC-1", 200, &body).await;
    let id = request_id(&h.submit(ISSUE, json!({ "key": "ABC-1" })).await)?;
    let rev = h
        .queued(&id, 10_000)
        .await
        .ok_or("never queued")?
        .candidate_rev;
    // Raw shows bytes of an opened revision only.
    let res = h.decisions().raw_page(&id, rev, 0);
    assert!(
        matches!(res, Err(DecisionError::Invalid(InvalidReason::NotOpened))),
        "{res:?}"
    );
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(preview.raw.page_count, 3);
    let mut bytes = Vec::new();
    for page in 0..preview.raw.page_count {
        let p = h.decisions().raw_page(&id, rev, page).map_err(de)?;
        assert_eq!((p.page, p.page_count), (page, 3));
        bytes.extend(p.bytes);
    }
    assert_eq!(bytes.len() as u64, preview.raw.total_bytes);
    // Raw = released (inv. 4): the pages are the bytes the agent receives as `result`.
    h.decisions().decide(release(&id, rev)).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    let result = env
        .data
        .as_ref()
        .map(|d| d["result"].clone())
        .ok_or("no data")?;
    assert_eq!(bytes, serde_json::to_vec(&result)?);
    // A stale revision gets nothing.
    let stale = CandidateRev {
        counter: rev.counter,
        candidate_hash: [1; 32],
    };
    assert!(h.decisions().raw_page(&id, stale, 0).is_err());
    Ok(())
}

/// PD-13: the synchronous API waits without starving the runtime, even when called from its
/// only worker (the decision's own tasks still run).
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn decisions_from_the_only_runtime_worker_complete() -> TestResult {
    let h = std::sync::Arc::new(Harness::jira().await?);
    let id = issue_item(&h).await?;
    let (h2, id2) = (h.clone(), id.clone());
    let task = tokio::spawn(async move {
        h2.approver()
            .release(&id2)
            .map(|o| o.status)
            .map_err(|e| format!("{e:?}"))
    });
    let status = tokio::time::timeout(Duration::from_secs(30), task).await???;
    assert_eq!(status, Status::Released);
    assert_eq!(h.await_(&id, 5000).await.status, Status::Released);
    Ok(())
}

/// Review I-3: a redacted revision stays under the 16 MiB release cap. Every-occurrence masks
/// replace each match with `[REDACTED]`, so masking a short frequent string can grow the body.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redaction_over_release_cap_is_blocked() -> TestResult {
    let h = Harness::jira().await?;
    // ~15.5 MiB with about a million "ab": each becomes `[REDACTED]` (+8 bytes).
    let unit = "abxxxxxxxxxxxxxx";
    let summary = unit.repeat(15 * 1024 * 1024 / unit.len() + 30_000);
    let body = json!({ "key": "ABC-1", "fields": { "summary": summary } }).to_string();
    assert!(body.len() < 16 * 1024 * 1024);
    jira(&h)?.json("/rest/api/2/issue/ABC-1", 200, &body).await;
    let id = request_id(&h.submit(ISSUE, json!({ "key": "ABC-1" })).await)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    h.approver().open(&id).map_err(de)?;
    let res = h.approver().redact(
        &id,
        vec![RedactionOp::MaskText {
            text: "ab".into(),
            every_occurrence: true,
            at: None,
        }],
    );
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    let item = h.approver().item(&id).ok_or("left the queue")?;
    assert_eq!(item.candidate_rev.counter, 1, "no new revision");
    assert_eq!(
        records(&h, &id, EventType::DECISION_INVALID)
            .await?
            .first()
            .map(|r| r["reason"].clone()),
        Some(json!("not_approvable"))
    );
    Ok(())
}
