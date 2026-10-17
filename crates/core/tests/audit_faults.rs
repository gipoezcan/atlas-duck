#![cfg(feature = "testing")]
//! Append failures at every gated point (X-04, §5.1 inv. 1) and payload retrievability (X-06,
//! §8.3): when the record that gates an act does not commit, the act does not happen; and every
//! kind of payload the core writes decrypts through the audit API to what happened.

mod common;

use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_core::payloads::{InvalidReason, body_from_json, sha256_hex};
use atlas_duck_core::testing::{FakeScriptRunner, FaultPlan, Harness, ScriptPlan, host_call};
use atlas_duck_core::{AdminError, BatchItem, Confirm, DecisionError, Edits, RunEnd};
use atlas_duck_ipc::envelope::{Envelope, Status};
use common::{TestError, TestResult, code, de, exit, request_id};
use serde_json::{Map, Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const ISSUE: &str = "jira.issue.get";
const COMMENT: &str = "jira.comment.add";
const EDIT: &str = "jira.issue.edit";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

async fn mount(mock: &MockDc, m: &str, p: &str, t: ResponseTemplate) {
    Mock::given(method(m))
        .and(path(mock.path(p)))
        .respond_with(t)
        .with_priority(1)
        .mount(mock.server())
        .await;
}

/// A harness whose plan is the test's, with every answer the rows need.
async fn rig() -> Result<(Harness, std::sync::Arc<FaultPlan>), TestError> {
    let plan = FaultPlan::new();
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .confirm(vec![Confirm::Ok, Confirm::Ok])
        .start()
        .await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.jira_server_info("9.12.0").await;
    for key in ["ABC-1", "ABC-2"] {
        mock.json(
            &format!("/rest/api/2/issue/{key}"),
            200,
            fixtures::JIRA_ISSUE,
        )
        .await;
    }
    mount(
        mock,
        "POST",
        "/rest/api/2/issue/ABC-1/comment",
        mock.response(201)
            .set_body_raw(fixtures::JIRA_COMMENT, "application/json"),
    )
    .await;
    mount(mock, "PUT", "/rest/api/2/issue/ABC-1", mock.response(204)).await;
    Ok((h, plan))
}

fn comment() -> Value {
    json!({ "key": "ABC-1", "body": "Seen.", "body_format": "wiki" })
}

fn edit() -> Value {
    json!({
        "key": "ABC-1",
        "fields": { "summary": "Login fails" },
        "expected": { "summary": "Login page times out" }
    })
}

async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

/// How many requests the instance has received.
async fn received(h: &Harness) -> Result<usize, TestError> {
    Ok(common::test_hits(jira(h)?).await.len())
}

async fn non_get(h: &Harness) -> Result<usize, TestError> {
    Ok(jira(h)?
        .received()
        .await
        .iter()
        .filter(|r| r.method.as_str() != "GET")
        .count())
}

/// The agent got an audit failure and no data, whatever it was told next.
fn audit_failure(env: &Envelope, retryable: bool) {
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(exit(env), 1, "{}", env.to_json_line());
    assert_eq!(code(env), "audit_failure");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(retryable));
    assert_eq!((&env.data, &env.meta), (&None, &None));
}

fn no_data(env: &Envelope) {
    assert!(env.data.is_none(), "{}", env.to_json_line());
    assert!(!env.to_json_line().contains("Login page"));
}

async fn count_of(h: &Harness, t: EventType) -> Result<usize, TestError> {
    Ok(h.events_of(t).await?.len())
}

// ---- X-04 -------------------------------------------------------------------------------------------

/// `REQUEST_RECEIVED` of a read: nothing is sent, the request never existed.
async fn row_request_received_read() -> TestResult {
    let (h, plan) = rig().await?;
    plan.fail_nth(EventType::REQUEST_RECEIVED, 1);
    let env = h.submit(ISSUE, json!({ "key": "ABC-1" })).await;
    audit_failure(&env, true);
    assert_eq!(received(&h).await?, 0);
    assert_eq!(count_of(&h, EventType::REQUEST_RECEIVED).await?, 0);
    Ok(())
}

/// `REQUEST_RECEIVED` of a write.
async fn row_request_received_write() -> TestResult {
    let (h, plan) = rig().await?;
    plan.fail_nth(EventType::REQUEST_RECEIVED, 1);
    let env = h.submit(COMMENT, comment()).await;
    audit_failure(&env, false);
    assert_eq!(received(&h).await?, 0);
    Ok(())
}

/// `PREVIEW_SHOWN`: the decision API fails and the request is not decidable until a preview is
/// recorded; nothing is released.
async fn row_preview_shown() -> TestResult {
    let (h, plan) = rig().await?;
    let id = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    let before = received(&h).await?;
    plan.fail_nth(EventType::PREVIEW_SHOWN, 1);
    let res = h.approver().open(&id);
    assert!(matches!(res, Err(DecisionError::Audit(_))), "{res:?}");
    let res = h.approver().release_unopened(&id);
    assert!(
        matches!(res, Err(DecisionError::Invalid(InvalidReason::NotOpened))),
        "{res:?}"
    );
    assert_eq!(h.status(&id).await.status, Status::Pending);
    no_data(&h.await_(&id, 100).await);
    assert_eq!(count_of(&h, EventType::READ_RELEASED).await?, 0);
    assert_eq!(received(&h).await?, before);
    Ok(())
}

/// `BATCH_CONFIRMED`: no item is decided, nothing is sent.
async fn row_batch_confirmed() -> TestResult {
    let (h, plan) = rig().await?;
    let r = queued(&h, ISSUE, json!({ "key": "ABC-2" })).await?;
    let w = queued(&h, COMMENT, comment()).await?;
    h.approver().open(&r).map_err(de)?;
    h.approver().open(&w).map_err(de)?;
    let before = received(&h).await?;
    let batch: Vec<BatchItem> = [&r, &w]
        .into_iter()
        .map(|id| {
            Ok(BatchItem {
                request_id: id.clone(),
                candidate_rev: h.approver().rev(id).map_err(de)?,
            })
        })
        .collect::<Result<_, TestError>>()?;
    plan.fail_nth(EventType::BATCH_CONFIRMED, 1);
    let res = h.decisions().decide_batch(batch);
    assert!(matches!(res, Err(DecisionError::Audit(_))), "{res:?}");
    for id in [&r, &w] {
        assert_eq!(h.status(id).await.status, Status::Pending);
        no_data(&h.await_(id, 100).await);
    }
    assert_eq!(count_of(&h, EventType::READ_RELEASED).await?, 0);
    assert_eq!(count_of(&h, EventType::WRITE_APPROVED).await?, 0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(received(&h).await?, before);
    assert_eq!(non_get(&h).await?, 0);
    Ok(())
}

/// `WRITE_APPROVED`: the write is not sent, the request ends `audit_failure` (never retryable:
/// a human approved something that has no record).
async fn row_write_approved() -> TestResult {
    let (h, plan) = rig().await?;
    let id = queued(&h, COMMENT, comment()).await?;
    let before = received(&h).await?;
    plan.fail_nth(EventType::WRITE_APPROVED, 1);
    let res = h.approver().approve(&id);
    assert!(matches!(res, Err(DecisionError::Audit(_))), "{res:?}");
    audit_failure(&h.await_(&id, 5000).await, false);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(received(&h).await?, before);
    assert_eq!(non_get(&h).await?, 0);
    assert_eq!(count_of(&h, EventType::WRITE_EXECUTED).await?, 0);
    Ok(())
}

/// `READ_RELEASED`: nothing is released or delivered, and the request fails (`audit_failure`,
/// retryable for a read, §5.1 inv. 1) like `WRITE_APPROVED` does: it is not decidable again.
async fn row_read_released() -> TestResult {
    let (h, plan) = rig().await?;
    let id = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    let before = received(&h).await?;
    plan.fail_nth(EventType::READ_RELEASED, 1);
    let res = h.approver().release(&id);
    assert!(matches!(res, Err(DecisionError::Audit(_))), "{res:?}");
    audit_failure(&h.await_(&id, 5000).await, true);
    assert!(h.approver().item(&id).is_none());
    let again = h.approver().release_unopened(&id);
    assert!(
        matches!(
            again,
            Err(DecisionError::NotDecidable | DecisionError::Stale { .. })
        ),
        "{again:?}"
    );
    assert_eq!(count_of(&h, EventType::READ_RELEASED).await?, 0);
    assert_eq!(count_of(&h, EventType::DELIVERED).await?, 0);
    assert_eq!(received(&h).await?, before);
    Ok(())
}

/// `DELIVERED`: the data stays in the core; the next `await` delivers it.
async fn row_delivered() -> TestResult {
    let (h, plan) = rig().await?;
    let id = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    h.approver().release(&id).map_err(de)?;
    let before = received(&h).await?;
    plan.fail_nth(EventType::DELIVERED, 1);
    audit_failure(&h.await_(&id, 5000).await, true);
    assert_eq!(count_of(&h, EventType::DELIVERED).await?, 0);
    assert_eq!(received(&h).await?, before);
    let again = h.await_(&id, 5000).await;
    assert_eq!(again.status, Status::Released);
    assert_eq!(count_of(&h, EventType::DELIVERED).await?, 1);
    Ok(())
}

/// `PREVIEW_FETCH` of the enrichment: the write never reaches approval or the wire.
async fn row_preview_fetch_enrich() -> TestResult {
    let (h, plan) = rig().await?;
    plan.fail_nth(EventType::PREVIEW_FETCH, 1);
    let env = h.submit(EDIT, edit()).await;
    let id = request_id(&env)?;
    assert!(h.settled(&id, 10_000).await, "never ended");
    audit_failure(&h.status(&id).await, false);
    audit_failure(&h.await_(&id, 1000).await, false);
    assert!(h.approver().item(&id).is_none());
    assert_eq!(non_get(&h).await?, 0);
    assert_eq!(count_of(&h, EventType::WRITE_APPROVED).await?, 0);
    // The enrichment `GET` was the only call and it was sent before its record failed: that
    // record is the one this row injects, so nothing follows it.
    assert_eq!(received(&h).await?, 1);
    Ok(())
}

/// `SYSTEM_FETCH` start of a connection test: no request leaves.
async fn row_system_fetch_start() -> TestResult {
    let (h, plan) = rig().await?;
    // The field-name cache's start fill (PD-46) committed its two records before the test ran.
    let before = count_of(&h, EventType::SYSTEM_FETCH).await?;
    plan.fail_nth(
        EventType::SYSTEM_FETCH,
        plan.attempts(EventType::SYSTEM_FETCH) + 1,
    );
    let res = h.instances().retest_token("jira-main").await;
    assert!(matches!(res, Err(AdminError::Audit(_))), "{res:?}");
    assert_eq!(received(&h).await?, 0);
    assert_eq!(count_of(&h, EventType::SYSTEM_FETCH).await?, before);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x04_append_failure_at_every_gated_point() -> TestResult {
    row_request_received_read()
        .await
        .map_err(|e| format!("REQUEST_RECEIVED (read): {e}"))?;
    row_request_received_write()
        .await
        .map_err(|e| format!("REQUEST_RECEIVED (write): {e}"))?;
    row_preview_shown()
        .await
        .map_err(|e| format!("PREVIEW_SHOWN: {e}"))?;
    row_batch_confirmed()
        .await
        .map_err(|e| format!("BATCH_CONFIRMED: {e}"))?;
    row_write_approved()
        .await
        .map_err(|e| format!("WRITE_APPROVED: {e}"))?;
    row_read_released()
        .await
        .map_err(|e| format!("READ_RELEASED: {e}"))?;
    row_delivered()
        .await
        .map_err(|e| format!("DELIVERED: {e}"))?;
    row_preview_fetch_enrich()
        .await
        .map_err(|e| format!("PREVIEW_FETCH (enrich): {e}"))?;
    row_system_fetch_start()
        .await
        .map_err(|e| format!("SYSTEM_FETCH start: {e}"))?;
    Ok(())
}

// ---- X-04, scripts ----------------------------------------------------------------------------------

const SCRIPT_TYPES: [EventType; 6] = [
    EventType::SCRIPT_STARTED,
    EventType::SCRIPT_CALL_SENT,
    EventType::SCRIPT_CALL,
    EventType::SCRIPT_FINISHED,
    EventType::SCRIPT_RELEASED,
    EventType::DELIVERED,
];

/// A harness with a script runner whose one run makes one host call; `plan` fails the append
/// the test names. `hold` keeps the run alive after its call, so a kill from the failure
/// reaches it.
async fn script_rig(
    hold: bool,
) -> Result<
    (
        Harness,
        std::sync::Arc<FaultPlan>,
        std::sync::Arc<FakeScriptRunner>,
    ),
    TestError,
> {
    let plan = FaultPlan::new();
    let mut run = ScriptPlan::new(
        vec![host_call(1, ISSUE, json!({ "key": "ABC-1" }))],
        RunEnd::Result {
            value: json!({ "n": 1 }),
            logs: Vec::new(),
            stderr: String::new(),
        },
    );
    if hold {
        run = run.holding(30_000);
    }
    let runner = FakeScriptRunner::new(vec![run]);
    let h = Harness::builder()
        .jira("jira-main")
        .scripts(runner.clone())
        .faults(plan.clone())
        .start()
        .await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.jira_server_info("9.12.0").await;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    Ok((h, plan, runner))
}

/// How many issue reads the instance has received.
async fn issue_reads(h: &Harness) -> Result<usize, TestError> {
    Ok(common::test_hits(jira(h)?).await.len())
}

/// The script request's record types, without the request's own and its preview's.
async fn script_records(h: &Harness, id: &str) -> Result<Vec<EventType>, TestError> {
    Ok(h.event_types(id)
        .await?
        .into_iter()
        .filter(|t| SCRIPT_TYPES.contains(t))
        .collect())
}

/// The script ended `audit_failure`, retryable, with no data and no release item, and none of
/// the records that follow `point` exist: nothing was released, delivered or sent after it.
async fn script_stopped_at(
    h: &Harness,
    id: &str,
    point: EventType,
    sent: usize,
) -> Result<(), TestError> {
    let after = SCRIPT_TYPES
        .iter()
        .position(|t| *t == point)
        .ok_or("not a script point")?;
    let types = script_records(h, id).await?;
    for later in &SCRIPT_TYPES[after..] {
        // Before the release, the one `DELIVERED` is the `audit_failure` envelope's own.
        if *later == EventType::DELIVERED && after < 4 {
            continue;
        }
        assert!(
            !types.contains(later),
            "{later:?} after the failed {point:?}: {types:?}"
        );
    }
    assert!(
        h.approver().item(id).is_none(),
        "a release item for {point:?}"
    );
    assert_eq!(count_of(h, EventType::SCRIPT_RELEASED).await?, 0);
    assert_eq!(issue_reads(h).await?, sent, "requests sent at {point:?}");
    Ok(())
}

/// A failed append before the run's end: the agent gets `audit_failure` (retryable) and no data,
/// the run is killed for the audit failure, and `later` records never exist.
async fn script_point_in_run(point: EventType, hold: bool, sent: usize) -> TestResult {
    let (h, plan, runner) = script_rig(hold).await?;
    plan.fail_nth(point, 1);
    let env = h.submit_script(json!({ "source": "return 1;" })).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    audit_failure(&h.await_(&id, 10_000).await, true);
    audit_failure(&h.status(&id).await, true);
    if point == EventType::SCRIPT_STARTED {
        // The record gates the spawn: no worker ever existed.
        assert_eq!(runner.starts(), 0);
        assert!(runner.kills().is_empty());
    } else if hold {
        for _ in 0..1000 {
            if runner.kills().iter().any(Option::is_some) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            runner.kills(),
            [Some(atlas_duck_core::KillReason::AuditFailure)],
            "{point:?}"
        );
    }
    script_stopped_at(&h, &id, point, sent).await
}

/// `SCRIPT_RELEASED`: the release fails, the candidate is not delivered, the request is not
/// decidable again.
async fn script_point_released() -> TestResult {
    let (h, plan, _runner) = script_rig(false).await?;
    let env = h.submit_script(json!({ "source": "return 1;" })).await;
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    plan.fail_nth(EventType::SCRIPT_RELEASED, 1);
    let res = h.approver().release(&id);
    assert!(matches!(res, Err(DecisionError::Audit(_))), "{res:?}");
    audit_failure(&h.await_(&id, 5000).await, true);
    assert!(h.approver().item(&id).is_none());
    let again = h.approver().release_unopened(&id);
    assert!(
        matches!(
            again,
            Err(DecisionError::NotDecidable | DecisionError::Stale { .. })
        ),
        "{again:?}"
    );
    let types = script_records(&h, &id).await?;
    assert!(!types.contains(&EventType::SCRIPT_RELEASED), "{types:?}");
    assert!(!types.contains(&EventType::DELIVERED), "{types:?}");
    assert_eq!(issue_reads(&h).await?, 1);
    Ok(())
}

/// `DELIVERED`: the result stays in the core; the next `await` delivers it.
async fn script_point_delivered() -> TestResult {
    let (h, plan, _runner) = script_rig(false).await?;
    let env = h.submit_script(json!({ "source": "return 1;" })).await;
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    h.approver().release(&id).map_err(de)?;
    plan.fail_nth(EventType::DELIVERED, 1);
    audit_failure(&h.await_(&id, 5000).await, true);
    assert_eq!(count_of(&h, EventType::DELIVERED).await?, 0);
    assert_eq!(issue_reads(&h).await?, 1);
    let again = h.await_(&id, 5000).await;
    assert_eq!(again.status, Status::Released, "{}", again.to_json_line());
    assert_eq!(
        again.data.ok_or("no data")?["result"],
        json!({ "n": 1 }),
        "the second await delivers what the first held back"
    );
    assert_eq!(count_of(&h, EventType::DELIVERED).await?, 1);
    Ok(())
}

// X-04, one test per script injection point, so a failure is named by its test. Nothing is sent
// before `SCRIPT_CALL_SENT` commits; the call's request left before its own record
// (`SCRIPT_CALL`) failed; the run's end follows the call.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x04_script_started() -> TestResult {
    script_point_in_run(EventType::SCRIPT_STARTED, true, 0).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x04_script_call_sent() -> TestResult {
    script_point_in_run(EventType::SCRIPT_CALL_SENT, true, 0).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x04_script_call() -> TestResult {
    script_point_in_run(EventType::SCRIPT_CALL, true, 1).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x04_script_finished() -> TestResult {
    script_point_in_run(EventType::SCRIPT_FINISHED, false, 1).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x04_script_released() -> TestResult {
    script_point_released().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x04_script_delivered() -> TestResult {
    script_point_delivered().await
}

// ---- X-06 -------------------------------------------------------------------------------------------

/// The bytes of a stored `{"text": ..}` / `{"b64": ..}` body.
fn bytes(v: &Value) -> Result<Vec<u8>, TestError> {
    body_from_json(v).ok_or_else(|| format!("not a stored body: {v}").into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x06_six_payload_kinds_decrypt() -> TestResult {
    let (h, _plan) = rig().await?;
    // One read released and delivered, one denied.
    let released = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    h.approver().release(&released).map_err(de)?;
    let delivered = h.await_(&released, 5000).await;
    assert_eq!(delivered.status, Status::Released);
    let denied = queued(&h, ISSUE, json!({ "key": "ABC-2" })).await?;
    h.approver().deny(&denied, "not needed").map_err(de)?;
    // One write edited, then executed.
    let write = queued(&h, EDIT, edit()).await?;
    let rev1 = h.approver().rev(&write).map_err(de)?;
    let mut set = Map::new();
    set.insert("fields.summary".into(), json!("Login fails after reset"));
    h.approver()
        .edit(
            &write,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
        .map_err(de)?;
    let mut bumped = false;
    for _ in 0..500 {
        if h.approver()
            .item(&write)
            .is_some_and(|i| i.candidate_rev.counter > rev1.counter)
        {
            bumped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(bumped, "the edit never produced a new revision");
    h.approver().approve(&write).map_err(de)?;
    assert_eq!(h.await_(&write, 10_000).await.status, Status::Succeeded);

    let one = |recs: &[(EventType, Value)], t: EventType| -> Result<Value, TestError> {
        recs.iter()
            .find(|(e, _)| *e == t)
            .map(|(_, p)| p.clone())
            .ok_or_else(|| format!("no {t:?}").into())
    };
    let read = h.events(&released).await?;
    // fetched: the instance's answer, byte for byte.
    let fetched = one(&read, EventType::READ_FETCHED)?;
    assert_eq!(
        bytes(&fetched["responses"][0]["body"])?,
        fixtures::JIRA_ISSUE.as_bytes()
    );
    assert_eq!(fetched["responses"][0]["status"], 200);
    // released: parses, hashes to `released_sha256`, which is what was delivered.
    let rel = one(&read, EventType::READ_RELEASED)?;
    let released_bytes = bytes(&rel["released"])?;
    let parsed: Value = serde_json::from_slice(&released_bytes)?;
    assert!(parsed.to_string().contains("Login page times out"));
    let hash = sha256_hex(&released_bytes);
    assert_eq!(rel["released_sha256"], hash);
    let del = one(&read, EventType::DELIVERED)?;
    assert_eq!(del["payload_sha256"], hash);
    // denied.
    let den = one(&h.events(&denied).await?, EventType::READ_DENIED)?;
    assert_eq!(den["reason"], "not needed");
    // edited and executed.
    let w = h.events(&write).await?;
    let edited = one(&w, EventType::WRITE_EDITED)?;
    assert_eq!(edited["original"]["fields"]["summary"], "Login fails");
    assert_eq!(
        edited["edited"]["fields"]["summary"],
        "Login fails after reset"
    );
    let executed = one(&w, EventType::WRITE_EXECUTED)?;
    assert_eq!(executed["response"]["status"], 204);
    assert_eq!(executed["server_user"], TEST_USER);
    assert_eq!(executed["request_index"], 0);
    // Every record of all three requests decrypts (no payload is unreadable).
    for id in [&released, &denied, &write] {
        for seq in h
            .store()
            .headers_for_request(id)?
            .iter()
            .map(|h| h.seq)
            .collect::<Vec<_>>()
        {
            let raw = h.store().read_payload(seq)?;
            serde_json::from_slice::<Value>(raw.as_slice())?;
        }
    }
    Ok(())
}
