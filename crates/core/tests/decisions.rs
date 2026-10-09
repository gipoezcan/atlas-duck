#![cfg(feature = "testing")]
//! The Rust decision rules on reads (Task 21, I-06 read half): "opened" per revision (§5.6),
//! decision binding to the current revision (§5.1 inv. 5), `PREVIEW_SHOWN` fail-closed, the
//! PD-19 rejection records, redaction revisions and Raw pages. The write half (Task 22): targets
//! and baselines immutable, holds never approvable, name edits re-enrich, decisions while the
//! stale check or a refresh runs are stale.

mod common;

use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::{FaultPlan, Harness};
use atlas_duck_core::{
    CandidateRev, Decision, DecisionError, DecisionKind, DenyDetails, Edits, RedactionOp,
    RedactionPreset,
};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::PreviewBody;
use common::{TestError, TestResult, de, request_id};
use serde_json::{Map, Value, json};
use wiremock::Mock;
use wiremock::matchers::{path, query_param};

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

// ---- write half (Task 22) ---------------------------------------------------------------------

const COMMENT: &str = "jira.comment.add";
const TRANSITION: &str = "jira.issue.transition";

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no confluence mock".into())
}

async fn identity_ok(mock: &MockDc) {
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
}

/// The transitions and the current status of `ABC-1` (`jira.issue.transition` enrichment).
async fn transitions_ok(mock: &MockDc) {
    mock.json(
        "/rest/api/2/issue/ABC-1/transitions",
        200,
        fixtures::JIRA_TRANSITIONS,
    )
    .await;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
}

/// Submits and waits for the queue.
async fn queued_write(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let id = request_id(&h.submit(op, params).await)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

/// Waits until the queue row's revision is past `counter` (a refresh or re-enrichment ended).
async fn rev_after(
    h: &Harness,
    id: &str,
    counter: u64,
) -> Result<atlas_duck_core::QueueItem, TestError> {
    for _ in 0..500 {
        if let Some(i) = h.approver().item(id)
            && i.candidate_rev.counter > counter
        {
            return Ok(i);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("no new revision".into())
}

fn not_approvable(res: Result<atlas_duck_core::DecisionOutcome, DecisionError>) -> TestResult {
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_target_param_edit_rejected() -> TestResult {
    let h = Harness::jira().await?;
    let id = queued_write(
        &h,
        COMMENT,
        json!({ "key": "ABC-1", "body": "Done.", "body_format": "wiki" }),
    )
    .await?;
    let ap = h.approver();
    let before = ap.open(&id).map_err(de)?.preview;
    let mut set = Map::new();
    set.insert("key".into(), json!("OTHER-1"));
    let res = ap.edit(
        &id,
        Edits {
            set,
            remove: Vec::new(),
        },
    );
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::TargetParamEdit))
        ),
        "{res:?}"
    );
    assert_eq!(
        records(&h, &id, EventType::DECISION_INVALID).await?,
        [
            json!({ "reason": "target_param_edit", "submitted_rev": 1, "decision": "edit", "batch": false })
        ]
    );
    assert!(records(&h, &id, EventType::WRITE_EDITED).await?.is_empty());
    // The request list is unchanged: same revision, same bytes, still opened.
    let item = ap.item(&id).ok_or("left the queue")?;
    assert_eq!(item.candidate_rev, before.candidate_rev);
    assert!(item.opened);
    assert_eq!(ap.open(&id).map_err(de)?.preview.body, before.body);
    // A malformed key is refused without a record (T15 handoff).
    let mut set = Map::new();
    set.insert("body.x".into(), json!("y"));
    let res = ap.edit(
        &id,
        Edits {
            set,
            remove: Vec::new(),
        },
    );
    assert!(
        matches!(res, Err(DecisionError::EditRejected(_))),
        "{res:?}"
    );
    assert_eq!(
        records(&h, &id, EventType::DECISION_INVALID).await?.len(),
        1
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_conflict_edit_not_approvable() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    let id = queued_write(
        &h,
        "jira.issue.edit",
        json!({
            "key": "ABC-1",
            "fields": { "summary": "Login fails after reset" },
            "expected": { "summary": "Login page time out" }
        }),
    )
    .await?;
    let item = h.approver().item(&id).ok_or("not queued")?;
    assert!(!item.approvable);
    assert!(item.caution_count >= 1, "the conflict is a Caution");
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(matches!(preview.body, PreviewBody::Conflict { .. }));
    assert!(!preview.approvable);
    not_approvable(h.approver().approve_unopened(&id))?;
    assert!(
        records(&h, &id, EventType::WRITE_APPROVED)
            .await?
            .is_empty()
    );
    assert_eq!(
        records(&h, &id, EventType::DECISION_INVALID)
            .await?
            .first()
            .map(|r| r["reason"].clone()),
        Some(json!("not_approvable"))
    );
    // Nothing was sent.
    assert!(
        !mock
            .received()
            .await
            .iter()
            .any(|r| r.method.as_str() == "PUT")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_page_update_conflict_not_approvable() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let mut page: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE)?;
    page["version"]["number"] = json!(6);
    mock.json("/rest/api/content/65537", 200, &page.to_string())
        .await;
    let id = queued_write(
        &h,
        "confluence.page.update",
        json!({ "id": "65537", "base_version": 5, "body": "<p>x</p>", "body_format": "storage" }),
    )
    .await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    match &preview.body {
        PreviewBody::Conflict { summary, .. } => {
            assert!(
                summary.contains("v5") && summary.contains("v6"),
                "{summary}"
            )
        }
        other => return Err(format!("not the conflict card: {other:?}").into()),
    }
    not_approvable(h.approver().approve_unopened(&id))?;
    assert!(
        records(&h, &id, EventType::WRITE_APPROVED)
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_unresolved_name_not_approvable() -> TestResult {
    let h = Harness::jira().await?;
    transitions_ok(jira(&h)?).await;
    let id = queued_write(
        &h,
        TRANSITION,
        json!({ "key": "ABC-1", "transition": "Doen" }),
    )
    .await?;
    match h.approver().open(&id).map_err(de)?.preview.body {
        PreviewBody::UnresolvedName { param, matches, .. } => {
            assert_eq!((param.as_str(), matches), ("transition", 0))
        }
        other => return Err(format!("not the unresolved-name card: {other:?}").into()),
    }
    not_approvable(h.approver().approve_unopened(&id))?;
    h.approver()
        .deny_with(
            &id,
            "no such transition",
            DenyDetails::ResolutionFailed {
                include_candidates: false,
            },
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Denied);
    assert_eq!(common::exit(&env), 3);
    assert_eq!(common::code(&env), "resolution_failed");
    let details = env
        .error
        .as_ref()
        .and_then(|e| e.details.clone())
        .ok_or("no details")?;
    assert_eq!(
        Value::Object(details),
        json!({
            "param": "transition",
            "value": "Doen",
            "message": "no transition named 'Doen' for ABC-1"
        })
    );
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_enrichment_failed_not_approvable() -> TestResult {
    let h = Harness::jira().await?;
    jira(&h)?
        .json(
            "/rest/api/2/issue/ABC-1/transitions",
            404,
            r#"{"errorMessages":["Issue does not exist"],"errors":{}}"#,
        )
        .await;
    let id = queued_write(
        &h,
        TRANSITION,
        json!({ "key": "ABC-1", "transition": "Done" }),
    )
    .await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    match preview.body {
        PreviewBody::EnrichmentError { status, .. } => assert_eq!(status, Some(404)),
        other => return Err(format!("not the enrichment-error card: {other:?}").into()),
    }
    not_approvable(h.approver().approve_unopened(&id))?;
    assert!(
        records(&h, &id, EventType::WRITE_APPROVED)
            .await?
            .is_empty()
    );
    assert_eq!(h.status(&id).await.status, Status::Pending);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_name_edit_reruns_enrichment() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    transitions_ok(mock).await;
    identity_ok(mock).await;
    mount_post(mock, "/rest/api/2/issue/ABC-1/transitions", 204).await;
    let id = queued_write(
        &h,
        TRANSITION,
        json!({ "key": "ABC-1", "transition": "Doen" }),
    )
    .await?;
    let rev1 = h.approver().rev(&id).map_err(de)?;
    let enrich_before = records(&h, &id, EventType::PREVIEW_FETCH).await?.len();
    let mut set = Map::new();
    set.insert("transition".into(), json!("Done"));
    h.approver()
        .edit(
            &id,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
        .map_err(de)?;
    let item = rev_after(&h, &id, rev1.counter).await?;
    assert!(item.approvable && !item.opened);
    let fetches = records(&h, &id, EventType::PREVIEW_FETCH).await?;
    let new: Vec<Value> = fetches
        .iter()
        .skip(enrich_before)
        .map(|f| f["purpose"].clone())
        .collect();
    assert_eq!(new, ["resolve", "enrich"]);
    assert_eq!(records(&h, &id, EventType::WRITE_EDITED).await?.len(), 1);
    // The resolved transition id is what runs.
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert!(env.edited);
    let post = mock
        .received()
        .await
        .into_iter()
        .find(|r| r.method.as_str() == "POST")
        .ok_or("no POST")?;
    assert!(String::from_utf8_lossy(&post.body).contains(r#""id":"31""#));
    Ok(())
}

async fn mount_post(mock: &MockDc, p: &str, status: u16) {
    Mock::given(wiremock::matchers::method("POST"))
        .and(path(mock.path(p)))
        .respond_with(mock.response(status))
        .with_priority(1)
        .mount(mock.server())
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn decision_during_stale_check_logged_stale() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    Mock::given(path(mock.path("/rest/api/2/myself")))
        .respond_with(
            mock.response(200)
                .set_body_raw(
                    fixtures::jira_myself(TEST_USER, TEST_USER_KEY),
                    "application/json",
                )
                .set_delay(Duration::from_millis(1500)),
        )
        .mount(mock.server())
        .await;
    Mock::given(wiremock::matchers::method("POST"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1/comment")))
        .respond_with(
            mock.response(201)
                .set_body_raw(fixtures::JIRA_COMMENT, "application/json"),
        )
        .with_priority(1)
        .mount(mock.server())
        .await;
    let id = queued_write(
        &h,
        COMMENT,
        json!({ "key": "ABC-1", "body": "Done.", "body_format": "wiki" }),
    )
    .await?;
    let rev = h.approver().rev(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    // The stale check's identity call stalls: an approve and a deny are stale (PD-19 M-3).
    tokio::time::sleep(Duration::from_millis(200)).await;
    let approve = Decision {
        decision: DecisionKind::Approve,
        ..release(&id, rev)
    };
    let res = h.decisions().decide(approve);
    assert!(matches!(res, Err(DecisionError::Stale { .. })), "{res:?}");
    let deny = Decision {
        decision: DecisionKind::Deny,
        reason: Some("stop".into()),
        ..release(&id, rev)
    };
    let res = h.decisions().decide(deny);
    assert!(matches!(res, Err(DecisionError::Stale { .. })), "{res:?}");
    assert_eq!(
        records(&h, &id, EventType::DECISION_STALE).await?,
        [
            json!({ "submitted_rev": 1, "current_rev": 1, "decision": "approve", "batch": false }),
            json!({ "submitted_rev": 1, "current_rev": 1, "decision": "deny", "batch": false }),
        ]
    );
    // PD-29: no preview in the stale check.
    assert!(matches!(
        h.decisions().preview_fetch(&id, None),
        Err(DecisionError::NotDecidable)
    ));
    assert_eq!(h.status(&id).await.status, Status::Pending);
    // The write then executes normally.
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert!(records(&h, &id, EventType::WRITE_DENIED).await?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approve_racing_refresh_logged_stale() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mock.confluence_user_current(
        atlas_duck_atlassian::testing::UserKind::Known,
        TEST_USER,
        TEST_USER_KEY,
    )
    .await;
    let content = mock.path("/rest/api/content/65537");
    let page = |v: u64| -> Result<String, TestError> {
        let mut p: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE)?;
        p["version"]["number"] = json!(v);
        Ok(p.to_string())
    };
    let enrich_q = "body.storage,version,space";
    // The enrichment sees v5; the stale check sees v6 (changed); the refresh stalls.
    Mock::given(wiremock::matchers::method("GET"))
        .and(path(content.clone()))
        .and(query_param("expand", enrich_q))
        .respond_with(
            mock.response(200)
                .set_body_raw(page(5)?, "application/json"),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(path(content.clone()))
        .and(query_param("expand", enrich_q))
        .respond_with(
            mock.response(200)
                .set_body_raw(page(6)?, "application/json")
                .set_delay(Duration::from_millis(1500)),
        )
        .with_priority(2)
        .mount(mock.server())
        .await;
    Mock::given(wiremock::matchers::method("GET"))
        .and(path(content))
        .and(query_param("expand", "version"))
        .respond_with(
            mock.response(200)
                .set_body_raw(page(6)?, "application/json"),
        )
        .mount(mock.server())
        .await;
    let id = queued_write(
        &h,
        "confluence.page.update",
        json!({ "id": "65537", "base_version": 5, "body": "<p>x</p>", "body_format": "storage" }),
    )
    .await?;
    h.approver().approve(&id).map_err(de)?;
    // Wait for `WRITE_STALE {changed}`: the refresh then runs (`Enriching`, not decidable).
    let mut stale = Vec::new();
    for _ in 0..300 {
        stale = records(&h, &id, EventType::WRITE_STALE).await?;
        if !stale.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        stale.first().map(|s| s["reason"].clone()),
        Some(json!("changed"))
    );
    let current = {
        let entry = h.engine().entry(&id).ok_or("not in memory")?;
        let st = entry.state();
        assert_eq!(
            st.model.phase(),
            atlas_duck_core::lifecycle::model::Phase::Enriching
        );
        CandidateRev {
            counter: st.model.rev(),
            candidate_hash: st.candidate_hash,
        }
    };
    let approve = Decision {
        decision: DecisionKind::Approve,
        ..release(&id, current)
    };
    let res = h.decisions().decide(approve);
    assert!(matches!(res, Err(DecisionError::Stale { .. })), "{res:?}");
    let records_stale = records(&h, &id, EventType::DECISION_STALE).await?;
    assert_eq!(
        records_stale,
        [json!({
            "submitted_rev": current.counter,
            "current_rev": current.counter,
            "decision": "approve",
            "batch": false
        })]
    );
    // The refresh lands: the conflict hold (current v6 ≠ base v5), led by the delta.
    let item = rev_after(&h, &id, current.counter).await?;
    assert!(!item.approvable);
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(matches!(preview.body, PreviewBody::Conflict { .. }));
    assert_eq!(
        preview.warnings.first().map(|w| w.id),
        Some(atlas_duck_preview::warning::WarningId::ChangedSinceReview)
    );
    assert_eq!(records(&h, &id, EventType::WRITE_APPROVED).await?.len(), 1);
    Ok(())
}
