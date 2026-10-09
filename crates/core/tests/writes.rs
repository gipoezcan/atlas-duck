#![cfg(feature = "testing")]
//! The write lifecycle (Task 22): enrichment and its failure split (I-12), approval binding the
//! wire (U-03), the identity call and stale check, execution and its outcomes, the delivery
//! view of an edited write (U-30), and the opacity of `executing` (§4.5).

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use atlas_duck_atlassian::Timeouts;
use atlas_duck_atlassian::testing::{
    MockDc, RawHttpServer, RawStep, TEST_USER, TEST_USER_KEY, TestTlsServer, XAuser, fixtures,
};
use atlas_duck_audit::EventType;
use atlas_duck_audit::request_set::requests_from_json;
use atlas_duck_audit::request_set_hash;
use atlas_duck_core::engine::write::RefreshCause;
use atlas_duck_core::lifecycle::model::InstanceEvt;
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::{FaultPlan, Harness, InstanceAt};
use atlas_duck_core::{DecisionError, DenyDetails, Edits};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::proto::{AwaitParams, ProgressNotification, ProgressSink};
use atlas_duck_preview::PreviewBody;
use atlas_duck_registry::Product;
use base64::Engine as _;
use common::{TestError, TestResult, code, de, exit, request_id};
use serde_json::{Map, Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const COMMENT: &str = "jira.comment.add";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no confluence mock".into())
}

/// The identity call of the stale check (§5.4 step 5) answers as the PAT's user.
async fn identity_ok(mock: &MockDc) {
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
}

/// `method` on `p` answers `t` (wiremock, any query).
async fn mount(mock: &MockDc, m: &str, p: &str, t: ResponseTemplate) {
    Mock::given(method(m))
        .and(path(mock.path(p)))
        .respond_with(t)
        .mount(mock.server())
        .await;
}

fn comment_params() -> Value {
    json!({ "key": "ABC-1", "body": "Reproduced on *staging*.", "body_format": "wiki" })
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

async fn one(h: &Harness, id: &str, t: EventType) -> Result<Value, TestError> {
    records(h, id, t)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| format!("no {t:?}").into())
}

/// Requests the mock received with `m` on `p`.
async fn hits(mock: &MockDc, m: &str, p: &str) -> usize {
    let want = mock.path(p);
    mock.received()
        .await
        .iter()
        .filter(|r| r.method.as_str() == m && r.url.path() == want)
        .count()
}

/// Waits until the request is decidable (enriched into the queue).
async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comment_add_happy_path() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount(
        mock,
        "POST",
        "/rest/api/2/issue/ABC-1/comment",
        mock.response(201)
            .set_body_raw(fixtures::JIRA_COMMENT, "application/json"),
    )
    .await;
    let env = h.submit(COMMENT, comment_params()).await;
    assert_eq!(env.status, Status::Pending);
    let id = request_id(&env)?;
    let item = h.queued(&id, 10_000).await.ok_or("never queued")?;
    assert!(item.approvable && !item.opened);
    assert_eq!(item.class, "write");
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(preview.header.executes_as.as_deref(), Some(TEST_USER));
    assert_eq!(preview.header.receipt_fields, ["id"]);
    assert!(matches!(preview.body, PreviewBody::WriteRequests { .. }));
    h.approver().approve_unopened(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(exit(&env), 0);
    assert_eq!(env.data, Some(json!({ "receipt": { "id": "20001" } })));
    assert!(!env.edited);
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_SHOWN,
            EventType::WRITE_APPROVED,
            EventType::PREVIEW_FETCH,
            EventType::WRITE_EXECUTED,
            EventType::DELIVERED,
        ]
    );
    let fetch = one(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(fetch["purpose"], "stale_check");
    assert_eq!(fetch["path"], mock.path("/rest/api/2/myself"));
    let executed = one(&h, &id, EventType::WRITE_EXECUTED).await?;
    assert_eq!(executed["server_user"], TEST_USER);
    assert_eq!(executed["request_index"], 0);
    // The approval's decision column (PD-20).
    let approved = h
        .store()
        .headers_for_request(&id)?
        .into_iter()
        .find(|e| e.event_type == EventType::WRITE_APPROVED)
        .ok_or("no WRITE_APPROVED")?;
    assert_eq!(
        approved.decision,
        Some(atlas_duck_audit::DecisionColumn::Approve)
    );
    assert_eq!(
        hits(mock, "POST", "/rest/api/2/issue/ABC-1/comment").await,
        1
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u03_write_wire_equals_write_approved_requests() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount(
        mock,
        "POST",
        "/rest/api/2/issue/ABC-1/comment",
        mock.response(201)
            .set_body_raw(fixtures::JIRA_COMMENT, "application/json"),
    )
    .await;
    let id = queued(&h, COMMENT, comment_params()).await?;
    let rev = h.approver().open(&id).map_err(de)?.preview.candidate_rev;
    h.approver().approve_unopened(&id).map_err(de)?;
    assert_eq!(h.await_(&id, 10_000).await.status, Status::Succeeded);

    let approved = one(&h, &id, EventType::WRITE_APPROVED).await?;
    let list = requests_from_json(&approved["requests"])?;
    let [approved_req] = list.as_slice() else {
        return Err("not exactly one approved request".into());
    };
    // The stored hash recomputes from the stored list, and it is the revision's hash.
    let hash = request_set_hash(&list);
    assert_eq!(approved["request_set_hash"], hex::encode(hash));
    assert_eq!(rev.candidate_hash, hash);
    assert_eq!(approved["candidate_rev"]["counter"], rev.counter);
    // Exactly one non-GET left, and it is the approved request byte for byte.
    let writes: Vec<_> = mock
        .received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() != "GET")
        .collect();
    let [sent] = writes.as_slice() else {
        return Err(format!("{} writes sent", writes.len()).into());
    };
    assert_eq!(sent.method.as_str(), approved_req.method);
    // wiremock rebuilds `url` with host `localhost`: the wire's origin is its `Host` header.
    let host = sent
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .ok_or("no Host")?;
    let query = sent
        .url
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    assert_eq!(
        format!("http://{host}{}{query}", sent.url.path()),
        approved_req.resolved_url
    );
    let ct = sent
        .headers
        .get("content-type")
        .map(|v| v.as_bytes().to_vec());
    assert_eq!(
        ct,
        approved_req
            .content_type
            .as_ref()
            .map(|c| c.as_bytes().to_vec())
    );
    assert_eq!(sent.body, approved_req.body_bytes);
    assert_eq!(
        sent.headers
            .get("x-atlassian-token")
            .map(|v| v.as_bytes().to_vec()),
        Some(b"no-check".to_vec())
    );
    // The stored body is base64 of the exact bytes (§5.4 step 4).
    let b64 = approved["requests"][0]["body_b64"]
        .as_str()
        .ok_or("no body_b64")?;
    assert_eq!(
        base64::engine::general_purpose::STANDARD.decode(b64)?,
        sent.body
    );
    Ok(())
}

/// Records every progress notification.
#[derive(Default)]
struct Recorder(Mutex<Vec<Status>>);

impl ProgressSink for Recorder {
    fn progress(&self, n: ProgressNotification) {
        if let Ok(mut v) = self.0.lock() {
            v.push(n.status);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn executing_is_sticky() -> TestResult {
    let h = Arc::new(Harness::jira().await?);
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount(
        mock,
        "POST",
        "/rest/api/2/issue/ABC-1/comment",
        mock.response(201)
            .set_body_raw(fixtures::JIRA_COMMENT, "application/json")
            .set_delay(Duration::from_millis(800)),
    )
    .await;
    let id = queued(&h, COMMENT, comment_params()).await?;
    let rec = Arc::new(Recorder::default());
    let (h2, id2, rec2) = (h.clone(), id.clone(), rec.clone());
    let waiter = tokio::spawn(async move {
        h2.handler()
            .await_request(
                h2.default_conn(),
                AwaitParams {
                    request_id: id2,
                    timeout_ms: Some(20_000),
                },
                &*rec2,
            )
            .await
    });
    // Before the decision: only `pending` (§4.5).
    assert_eq!(h.status(&id).await.status, Status::Pending);
    h.approver().approve(&id).map_err(de)?;
    // While the slow POST is in flight the status is `executing`.
    let mut saw_executing = false;
    for _ in 0..100 {
        match h.status(&id).await.status {
            Status::Executing => {
                saw_executing = true;
                break;
            }
            Status::Pending => tokio::time::sleep(Duration::from_millis(10)).await,
            other => return Err(format!("{other:?} before executing").into()),
        }
    }
    assert!(saw_executing);
    let env = waiter.await?;
    assert_eq!(env.status, Status::Succeeded);
    let stream = rec.0.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(stream, [Status::Executing, Status::Succeeded]);
    Ok(())
}

/// `confluence.page.update` of page 65537 at `version` (the enrichment and refresh GET).
fn page_at(version: u64) -> String {
    let mut page: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE).unwrap_or(Value::Null);
    page["version"]["number"] = json!(version);
    page.to_string()
}

async fn confluence_identity_ok(mock: &MockDc) {
    mock.confluence_user_current(
        atlas_duck_atlassian::testing::UserKind::Known,
        TEST_USER,
        TEST_USER_KEY,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_update_version_conflict_returns_to_queue() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    confluence_identity_ok(mock).await;
    let content = mock.path("/rest/api/content/65537");
    let enrich_q = "body.storage,version,space";
    // Enrichment sees v5 once, the refresh after the conflict sees v6; the stale check sees v5.
    Mock::given(method("GET"))
        .and(path(content.clone()))
        .and(query_param("expand", enrich_q))
        .respond_with(
            mock.response(200)
                .set_body_raw(page_at(5), "application/json"),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(content.clone()))
        .and(query_param("expand", enrich_q))
        .respond_with(
            mock.response(200)
                .set_body_raw(page_at(6), "application/json"),
        )
        .with_priority(2)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(content.clone()))
        .and(query_param("expand", "version"))
        .respond_with(
            mock.response(200)
                .set_body_raw(page_at(5), "application/json"),
        )
        .mount(mock.server())
        .await;
    mount(
        mock,
        "PUT",
        "/rest/api/content/65537",
        mock.response(409).set_body_raw(
            fixtures::CONFLUENCE_VERSION_CONFLICT_409,
            "application/json",
        ),
    )
    .await;
    let params = json!({
        "id": "65537", "base_version": 5, "body": "<p>New text.</p>", "body_format": "storage"
    });
    let id = queued(&h, "confluence.page.update", params).await?;
    let rev1 = h.approver().rev(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    // Back in the queue after the refresh: the conflict hold, not approvable.
    let mut item = None;
    for _ in 0..500 {
        if let Some(i) = h.approver().item(&id)
            && i.candidate_rev.counter > rev1.counter + 1
        {
            item = Some(i);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let item = item.ok_or("never back in the queue")?;
    assert!(!item.approvable && !item.opened && item.stale);
    let stale = one(&h, &id, EventType::WRITE_STALE).await?;
    assert_eq!(stale["reason"], "version_conflict");
    let refresh: Vec<Value> = records(&h, &id, EventType::PREVIEW_FETCH)
        .await?
        .into_iter()
        .filter(|r| r["purpose"] == "refresh")
        .collect();
    assert_eq!(refresh.len(), 1);
    // §4.5: `executing` was emitted and stays.
    assert_eq!(h.status(&id).await.status, Status::Executing);
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(matches!(preview.body, PreviewBody::Conflict { .. }));
    let res = h.approver().approve_unopened(&id);
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    let invalid = records(&h, &id, EventType::DECISION_INVALID).await?;
    assert_eq!(
        invalid.first().map(|r| r["reason"].clone()),
        Some(json!("not_approvable"))
    );
    assert_eq!(records(&h, &id, EventType::WRITE_APPROVED).await?.len(), 1);
    assert_eq!(h.status(&id).await.status, Status::Executing);
    // Denied with the pre-fill: `denied`, exit 3.
    h.approver()
        .deny_unopened(&id, atlas_duck_core::engine::write::CONFLICT_DENY_PREFILL)
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!((env.status, exit(&env)), (Status::Denied, 3));
    assert_eq!(
        env.error.as_ref().map(|e| e.message.as_str()),
        Some(atlas_duck_core::engine::write::CONFLICT_DENY_PREFILL)
    );
    Ok(())
}

/// A Jira issue fixture with `summary`.
fn issue_with(summary: &str) -> String {
    let mut issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE).unwrap_or(Value::Null);
    issue["fields"]["summary"] = json!(summary);
    issue.to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issuelink_style_empty_success() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount(
        mock,
        "GET",
        "/rest/api/2/issue/ABC-1",
        mock.response(200)
            .set_body_raw(issue_with("Login page times out"), "application/json"),
    )
    .await;
    // `[204] Empty` (§7.2): any content type, no body.
    mount(
        mock,
        "PUT",
        "/rest/api/2/issue/ABC-1",
        mock.response(204)
            .insert_header("Content-Type", "application/json"),
    )
    .await;
    let params = json!({
        "key": "ABC-1",
        "fields": { "summary": "Login fails after reset" },
        "expected": { "summary": "Login page times out" }
    });
    let id = queued(&h, "jira.issue.edit", params).await?;
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(env.data, Some(json!({ "receipt": {} })));
    // Enrichment, then the identity call and the stale rule's re-read.
    let purposes: Vec<Value> = records(&h, &id, EventType::PREVIEW_FETCH)
        .await?
        .into_iter()
        .map(|r| r["purpose"].clone())
        .collect();
    assert_eq!(purposes, ["enrich", "stale_check", "stale_check"]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u30_edited_write_receipt_has_no_added_values() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount(
        mock,
        "GET",
        "/rest/api/2/issue/ABC-1",
        mock.response(200)
            .set_body_raw(issue_with("Login page times out"), "application/json"),
    )
    .await;
    mount(mock, "PUT", "/rest/api/2/issue/ABC-1", mock.response(204)).await;
    let params = json!({
        "key": "ABC-1",
        "fields": { "summary": "Login fails" },
        "expected": { "summary": "Login page times out" }
    });
    let id = queued(&h, "jira.issue.edit", params).await?;
    let rev1 = h.approver().rev(&id).map_err(de)?;
    let mut set = Map::new();
    set.insert("fields.customfield_9".into(), json!("ADDEDVALUE"));
    set.insert("fields.summary".into(), json!("Login fails after reset"));
    h.approver()
        .edit(
            &id,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
        .map_err(de)?;
    // `fields` is enrichment-relevant: a re-enrichment, then a new revision.
    let mut rev2 = None;
    for _ in 0..500 {
        if let Some(i) = h.approver().item(&id)
            && i.candidate_rev.counter > rev1.counter
        {
            rev2 = Some(i);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let item = rev2.ok_or("never re-rendered")?;
    assert!(item.approvable);
    assert_eq!(
        records(&h, &id, EventType::WRITE_EDITED).await?.len(),
        1,
        "one edit"
    );
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert!(env.edited);
    let data = env.data.clone().ok_or("no data")?;
    assert_eq!(data["receipt"], json!({}));
    // Only the agent's own keys, with the human's value for them (§4.2).
    assert_eq!(
        data["executed_params"],
        json!({
            "key": "ABC-1",
            "fields": { "summary": "Login fails after reset" },
            "expected": { "summary": "Login page times out" }
        })
    );
    assert_eq!(
        data["edited_keys"]["added"],
        json!(["fields.customfield_9"])
    );
    assert_eq!(data["edited_keys"]["changed"], json!(["fields.summary"]));
    assert!(!env.to_json_line().contains("ADDEDVALUE"));
    // What ran carried the added value (the executor runs `params`, T15).
    let put = mock
        .received()
        .await
        .into_iter()
        .find(|r| r.method.as_str() == "PUT")
        .ok_or("no PUT")?;
    assert!(String::from_utf8_lossy(&put.body).contains("ADDEDVALUE"));
    let approved = h
        .store()
        .headers_for_request(&id)?
        .into_iter()
        .find(|e| e.event_type == EventType::WRITE_APPROVED)
        .ok_or("no WRITE_APPROVED")?;
    assert_eq!(
        approved.decision,
        Some(atlas_duck_audit::DecisionColumn::ApproveEdited)
    );
    Ok(())
}

// ---- I-12: enrichment outcomes ----------------------------------------------------------------

/// A Jira instance at a raw server whose every answer runs `script`, with short per-call
/// timeouts.
async fn raw_jira(script: Vec<RawStep>) -> Result<(Harness, RawHttpServer), TestError> {
    let server = RawHttpServer::serve(script).await?;
    let h = Harness::builder()
        .instance_at(
            "jira-main",
            Product::Jira,
            InstanceAt {
                base_url: server.base_url(),
                ..InstanceAt::default()
            },
        )
        .timeouts(Timeouts {
            per_call: Duration::from_millis(400),
            ..Timeouts::default()
        })
        .start()
        .await?;
    Ok((h, server))
}

fn json_head(extra: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-AUSERNAME: {TEST_USER}\r\nConnection: close\r\n{extra}\r\n"
    )
}

const TRANSITION: &str = "jira.issue.transition";

fn transition_params(name: &str) -> Value {
    json!({ "key": "ABC-1", "transition": name })
}

/// The write is held as "enrichment failed" (pending, not approvable, an approve is
/// `DECISION_INVALID {not_approvable}`); returns the request id.
async fn assert_enrichment_failed(h: &Harness, id: &str) -> TestResult {
    let item = h.queued(id, 10_000).await.ok_or("never queued")?;
    assert!(!item.approvable);
    assert_eq!(h.status(id).await.status, Status::Pending);
    match h.approver().open(id).map_err(de)?.preview.body {
        PreviewBody::EnrichmentError { .. } => {}
        other => return Err(format!("not the enrichment-error card: {other:?}").into()),
    }
    let res = h.approver().approve_unopened(id);
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    assert!(records(h, id, EventType::WRITE_APPROVED).await?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i12_enrichment_timeout_after_send_enrichment_failed() -> TestResult {
    let (h, _server) = raw_jira(vec![
        RawStep::Send(json_head("Content-Length: 100\r\n").into_bytes()),
        RawStep::Sleep(5_000),
    ])
    .await?;
    let id = request_id(&h.submit(TRANSITION, transition_params("Done")).await)?;
    assert_enrichment_failed(&h, &id).await?;
    let fetch = one(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(fetch["purpose"], "resolve");
    assert_eq!(fetch["outcome"], "timeout");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i12_enrichment_reset_mid_body() -> TestResult {
    let body = fixtures::JIRA_TRANSITIONS.as_bytes();
    let mut answer = json_head(&format!("Content-Length: {}\r\n", body.len())).into_bytes();
    answer.extend_from_slice(body.get(..body.len() / 2).ok_or("cut")?);
    let (h, _server) = raw_jira(vec![RawStep::Send(answer), RawStep::Close]).await?;
    let id = request_id(&h.submit(TRANSITION, transition_params("Done")).await)?;
    assert_enrichment_failed(&h, &id).await?;
    let fetch = one(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(fetch["outcome"], "network");
    // Every byte received is in the record (§5.4 step 2).
    assert!(fetch["received"].to_string().contains("Start Progress"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i12_enrichment_over_32mib() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let mut page: Value = serde_json::from_str(&page_at(5))?;
    page["body"]["storage"]["value"] = json!("x".repeat(33 * 1024 * 1024));
    mount(
        mock,
        "GET",
        "/rest/api/content/65537",
        mock.response(200)
            .set_body_raw(page.to_string(), "application/json"),
    )
    .await;
    let params = json!({
        "id": "65537", "base_version": 5, "body": "<p>x</p>", "body_format": "storage"
    });
    let id = request_id(&h.submit("confluence.page.update", params).await)?;
    let item = h.queued(&id, 30_000).await.ok_or("never queued")?;
    assert!(!item.approvable);
    let fetch = one(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(fetch["outcome"], "too_large");
    // The deny hint is `result_too_large` without a size.
    h.approver()
        .deny_with(&id, "too big", DenyDetails::OutcomeHint)
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!((env.status, exit(&env)), (Status::Denied, 3));
    assert_eq!(code(&env), "result_too_large");
    assert!(env.error.as_ref().is_some_and(|e| e.details.is_none()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i12_deny_with_outcome_hint() -> TestResult {
    let (h, _server) = raw_jira(vec![
        RawStep::Send(json_head("Content-Length: 100\r\n").into_bytes()),
        RawStep::Sleep(5_000),
    ])
    .await?;
    let id = request_id(&h.submit(TRANSITION, transition_params("Done")).await)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    h.approver()
        .deny_with(&id, "the server is slow", DenyDetails::OutcomeHint)
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!((env.status, exit(&env)), (Status::Denied, 3));
    assert_eq!(code(&env), "upstream_network");
    let e = env.error.as_ref().ok_or("no error")?;
    assert!(!e.retryable);
    assert!(e.details.is_none());
    // A fixed message, no size, no content (L25, L31): the human's reason is not delivered
    // either, since the hint replaces it.
    assert_eq!(
        e.message,
        atlas_duck_core::engine::write::HINT_ENRICH_NETWORK
    );
    assert_eq!((env.data.clone(), env.meta.clone()), (None, None));
    assert!(!env.to_json_line().contains("slow"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i12_enrichment_dns_tls_direct() -> TestResult {
    let tls = TestTlsServer::start().await?;
    let h = Harness::builder()
        .instance_at(
            "jira-main",
            Product::Jira,
            InstanceAt {
                base_url: "http://nonexistent.invalid".to_owned(),
                ..InstanceAt::default()
            },
        )
        .instance_at(
            "tls",
            Product::Jira,
            InstanceAt {
                base_url: tls.base_url(),
                ..InstanceAt::default()
            },
        )
        .start()
        .await?;
    for alias in ["jira-main", "tls"] {
        let env = h
            .submit_with(
                h.default_conn(),
                TRANSITION,
                transition_params("Done"),
                Some(alias),
            )
            .await;
        let id = request_id(&env)?;
        assert!(h.settled(&id, 10_000).await, "{alias} never settled");
        let env = h.await_(&id, 1000).await;
        assert_eq!((env.status, exit(&env)), (Status::Failed, 6), "{alias}");
        assert_eq!(code(&env), "upstream_network");
        assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
        assert_eq!(
            h.event_types(&id).await?,
            [
                EventType::REQUEST_RECEIVED,
                EventType::PREVIEW_FETCH,
                EventType::REQUEST_FAILED,
                EventType::DELIVERED,
            ]
        );
        let failed = one(&h, &id, EventType::REQUEST_FAILED).await?;
        assert!(
            failed["class"].is_string(),
            "{alias}: the class is recorded"
        );
        assert!(h.approver().item(&id).is_none());
    }
    Ok(())
}

/// Every status a pending write shows until its decision: progress notifications of a short
/// `await`, then `status` and the `await` answer.
async fn stream_until_decision(h: &Harness, id: &str) -> Result<Vec<String>, TestError> {
    let rec = Recorder::default();
    let awaited = h
        .handler()
        .await_request(
            h.default_conn(),
            AwaitParams {
                request_id: id.to_owned(),
                timeout_ms: Some(50),
            },
            &rec,
        )
        .await;
    let status = h.status(id).await;
    let mut out: Vec<String> = rec
        .0
        .lock()
        .map_err(|_| "poisoned")?
        .iter()
        .map(|s| format!("{s:?}"))
        .collect();
    for env in [awaited, status] {
        out.push(env.to_json_line().replace(id, "<id>"));
    }
    Ok(out)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i12_status_stream_identical() -> TestResult {
    // The two gated cases (a timeout after the request was sent, a reset mid-body) look the
    // same to the agent until the decision (§4.5, §5.4 step 2).
    let (timeout_h, _a) = raw_jira(vec![
        RawStep::Send(json_head("Content-Length: 100\r\n").into_bytes()),
        RawStep::Sleep(5_000),
    ])
    .await?;
    let body = fixtures::JIRA_TRANSITIONS.as_bytes();
    let mut answer = json_head(&format!("Content-Length: {}\r\n", body.len())).into_bytes();
    answer.extend_from_slice(body.get(..body.len() / 2).ok_or("cut")?);
    let (reset_h, _b) = raw_jira(vec![RawStep::Send(answer), RawStep::Close]).await?;
    let mut streams = Vec::new();
    for h in [&timeout_h, &reset_h] {
        let env = h.submit(TRANSITION, transition_params("Done")).await;
        let id = request_id(&env)?;
        let mut s = vec![env.to_json_line().replace(&id, "<id>")];
        s.extend(stream_until_decision(h, &id).await?);
        h.queued(&id, 10_000).await.ok_or("never queued")?;
        s.extend(stream_until_decision(h, &id).await?);
        streams.push(s);
    }
    assert_eq!(streams[0], streams[1]);
    assert!(streams[0].iter().all(|s| !s.contains("executing")));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_404_enrichment_deny_with_upstream_http() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.json(
        "/rest/api/2/issue/NOPE-1/transitions",
        404,
        r#"{"errorMessages":["Issue does not exist"],"errors":{}}"#,
    )
    .await;
    let id = queued(
        &h,
        TRANSITION,
        json!({ "key": "NOPE-1", "transition": "Done" }),
    )
    .await?;
    // A hint the hold has no data for is refused without a record.
    let res = h.approver().deny_with(
        &id,
        "no",
        DenyDetails::ResolutionFailed {
            include_candidates: false,
        },
    );
    assert!(
        matches!(res, Err(DecisionError::EditRejected(_))),
        "{res:?}"
    );
    assert!(records(&h, &id, EventType::WRITE_DENIED).await?.is_empty());
    h.approver()
        .deny_with(
            &id,
            "the issue is gone",
            DenyDetails::UpstreamHttp {
                include_messages: true,
            },
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!((env.status, exit(&env)), (Status::Denied, 3));
    assert_eq!(code(&env), "upstream_http");
    assert_eq!(common::detail(&env, "status"), json!(404));
    assert_eq!(
        common::detail(&env, "error_messages"),
        json!("Issue does not exist")
    );
    assert_eq!(common::message(&env), "the issue is gone");
    Ok(())
}

/// The DELIVERED hash of a receipt delivery is the JCS hash of the delivered `data`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn receipt_delivery_hash_and_window() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount(
        mock,
        "POST",
        "/rest/api/2/issue/ABC-1/comment",
        mock.response(201)
            .set_body_raw(fixtures::JIRA_COMMENT, "application/json"),
    )
    .await;
    let id = queued(&h, COMMENT, comment_params()).await?;
    h.approver().approve(&id).map_err(de)?;
    let env: Envelope = h.await_(&id, 10_000).await;
    let data = env.data.clone().ok_or("no data")?;
    let delivered = one(&h, &id, EventType::DELIVERED).await?;
    let hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        atlas_duck_ipc::jcs::to_jcs_vec(&data)?,
    ));
    assert_eq!(delivered["payload_sha256"], hash);
    // After the 1 h window: the true status, `result_evicted`, exit 10, not retryable.
    h.clock().advance(Duration::from_secs(61 * 60));
    let env = h.await_(&id, 1000).await;
    assert_eq!(env.status, Status::Succeeded);
    assert_eq!((code(&env), exit(&env)), ("result_evicted".to_owned(), 10));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert_eq!(env.data, None);
    Ok(())
}

/// §5.1 inv. 1: an approval whose `WRITE_APPROVED` does not commit executes nothing (no
/// identity call, no write) and fails the request `audit_failure`, not retryable for a write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_approved_append_failure_sends_nothing() -> TestResult {
    let plan = FaultPlan::new();
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .start()
        .await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount(
        mock,
        "POST",
        "/rest/api/2/issue/ABC-1/comment",
        mock.response(201)
            .set_body_raw(fixtures::JIRA_COMMENT, "application/json"),
    )
    .await;
    let id = queued(&h, COMMENT, comment_params()).await?;
    plan.fail_nth(EventType::WRITE_APPROVED, 1);
    let res = h.approver().approve(&id);
    assert!(matches!(res, Err(DecisionError::Audit(_))), "{res:?}");
    let env = h.await_(&id, 5000).await;
    assert_eq!((env.status, exit(&env)), (Status::Failed, 1));
    assert_eq!(code(&env), "audit_failure");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(mock.received().await.is_empty(), "nothing was sent");
    assert!(
        records(&h, &id, EventType::WRITE_APPROVED)
            .await?
            .is_empty()
    );
    assert!(records(&h, &id, EventType::PREVIEW_FETCH).await?.is_empty());
    Ok(())
}

// ---- review fixes: approval-bound stale checks (I-1), instance changes (I-2), outcome arms ----

/// `GET /rest/api/2/myself`: the first answer after `delay_ms` with `status`, later ones at once
/// as the PAT's user.
async fn myself_first_slow(mock: &MockDc, delay_ms: u64, status: u16) {
    let first = if status == 200 {
        mock.response(200).set_body_raw(
            fixtures::jira_myself(TEST_USER, TEST_USER_KEY),
            "application/json",
        )
    } else {
        mock.response(status)
            .set_body_raw("<html>maintenance</html>", "text/html")
    };
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/myself")))
        .respond_with(first.set_delay(Duration::from_millis(delay_ms)))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    identity_ok(mock).await;
}

async fn comment_ok(mock: &MockDc) {
    mount(
        mock,
        "POST",
        "/rest/api/2/issue/ABC-1/comment",
        mock.response(201)
            .set_body_raw(fixtures::JIRA_COMMENT, "application/json"),
    )
    .await;
}

fn entry_of(
    h: &Harness,
    id: &str,
) -> Result<Arc<atlas_duck_core::engine::RequestEntry>, TestError> {
    h.engine().entry(id).ok_or_else(|| "not in memory".into())
}

/// Waits until the queue row's revision is past `counter`.
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

/// Review I-1 (a): a credential change during the stale check supersedes it; the re-approval
/// runs its own identity call before its send, and the old check applies nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn superseded_stale_check_never_gates_a_later_approval() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    // The superseded identity call answers (a match) while the re-approval's own, slower one is
    // still running: unbound, it would pass the re-approval's stale check and send early.
    for (priority, delay) in [(1, 1200), (2, 3000)] {
        Mock::given(method("GET"))
            .and(path(mock.path("/rest/api/2/myself")))
            .respond_with(
                mock.response(200)
                    .set_body_raw(
                        fixtures::jira_myself(TEST_USER, TEST_USER_KEY),
                        "application/json",
                    )
                    .set_delay(Duration::from_millis(delay)),
            )
            .up_to_n_times(1)
            .with_priority(priority)
            .mount(mock.server())
            .await;
    }
    comment_ok(mock).await;
    let id = queued(&h, COMMENT, comment_params()).await?;
    let rev1 = h.approver().rev(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.engine()
        .refresh_write(
            &entry_of(&h, &id)?,
            RefreshCause::Instance(InstanceEvt::CredentialChanged),
        )
        .await
        .map_err(|e| format!("{e:?}"))?;
    let item = rev_after(&h, &id, rev1.counter + 1).await?;
    assert!(item.approvable);
    let reapproved = std::time::Instant::now();
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    // Sent only after the re-approval's own identity call (3 s) answered, not on the superseded
    // one's answer (at 1.2 s).
    assert!(
        reapproved.elapsed() >= Duration::from_millis(2500),
        "sent after {:?}",
        reapproved.elapsed()
    );
    assert_eq!(
        hits(mock, "POST", "/rest/api/2/issue/ABC-1/comment").await,
        1
    );
    let stale = records(&h, &id, EventType::WRITE_STALE).await?;
    assert_eq!(
        stale
            .iter()
            .map(|s| s["reason"].clone())
            .collect::<Vec<_>>(),
        [json!("credential_changed")]
    );
    // Exactly one identity call between the second approval and the send, and none recorded
    // for the superseded check.
    let types = h.event_types(&id).await?;
    let approved: Vec<usize> = types
        .iter()
        .enumerate()
        .filter(|(_, t)| **t == EventType::WRITE_APPROVED)
        .map(|(i, _)| i)
        .collect();
    let executed = types
        .iter()
        .position(|t| *t == EventType::WRITE_EXECUTED)
        .ok_or("no WRITE_EXECUTED")?;
    assert_eq!(approved.len(), 2);
    assert_eq!(
        types[approved[1]..executed]
            .iter()
            .filter(|t| **t == EventType::PREVIEW_FETCH)
            .count(),
        1
    );
    assert_eq!(records(&h, &id, EventType::PREVIEW_FETCH).await?.len(), 1);
    Ok(())
}

/// Review I-1 (b): a refresh running while the superseded stale check fails is not ended by it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_survives_a_superseded_stale_fail() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    // The stale check's identity call would fail (503) after a while.
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/user/current")))
        .respond_with(
            mock.response(503)
                .set_body_raw("<html>down</html>", "text/html")
                .set_delay(Duration::from_millis(1000)),
        )
        .mount(mock.server())
        .await;
    let content = mock.path("/rest/api/content/65537");
    let enrich_q = "body.storage,version,space";
    Mock::given(method("GET"))
        .and(path(content.clone()))
        .and(query_param("expand", enrich_q))
        .respond_with(
            mock.response(200)
                .set_body_raw(page_at(5), "application/json"),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    // The refresh is slow: it is still running when the superseded check would fail.
    Mock::given(method("GET"))
        .and(path(content))
        .and(query_param("expand", enrich_q))
        .respond_with(
            mock.response(200)
                .set_body_raw(page_at(5), "application/json")
                .set_delay(Duration::from_millis(1500)),
        )
        .with_priority(2)
        .mount(mock.server())
        .await;
    let params = json!({
        "id": "65537", "base_version": 5, "body": "<p>x</p>", "body_format": "storage"
    });
    let id = queued(&h, "confluence.page.update", params).await?;
    let rev1 = h.approver().rev(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.engine()
        .refresh_write(
            &entry_of(&h, &id)?,
            RefreshCause::Instance(InstanceEvt::CredentialChanged),
        )
        .await
        .map_err(|e| format!("{e:?}"))?;
    // The refresh lands with its own verdict: approvable, one `WRITE_STALE`, no re-check failure.
    let item = rev_after(&h, &id, rev1.counter + 1).await?;
    assert!(item.approvable && !item.opened);
    let stale = records(&h, &id, EventType::WRITE_STALE).await?;
    assert_eq!(
        stale
            .iter()
            .map(|s| s["reason"].clone())
            .collect::<Vec<_>>(),
        [json!("credential_changed")]
    );
    let purposes: Vec<Value> = records(&h, &id, EventType::PREVIEW_FETCH)
        .await?
        .into_iter()
        .map(|r| r["purpose"].clone())
        .collect();
    assert_eq!(purposes, ["enrich", "refresh"]);
    assert_eq!(hits(mock, "PUT", "/rest/api/content/65537").await, 0);
    Ok(())
}

/// Review I-2: `instance_changed` (here during the stale check) leaves the write not approvable
/// until Task 25's deferred refresh (`Engine::start_refresh`) has run under the new PAT.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn instance_changed_not_approvable_until_refreshed() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    myself_first_slow(mock, 1500, 200).await;
    comment_ok(mock).await;
    let id = queued(&h, COMMENT, comment_params()).await?;
    let rev1 = h.approver().rev(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let entry = entry_of(&h, &id)?;
    h.engine()
        .refresh_write(&entry, RefreshCause::Instance(InstanceEvt::InstanceChanged))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let item = rev_after(&h, &id, rev1.counter).await?;
    assert!(!item.approvable && item.stale);
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(!preview.approvable);
    let res = h.approver().approve_unopened(&id);
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    // The superseded identity call answers meanwhile: nothing changes, nothing is sent.
    tokio::time::sleep(Duration::from_millis(1800)).await;
    let item = h.approver().item(&id).ok_or("left the queue")?;
    assert!(!item.approvable);
    assert_eq!(
        hits(mock, "POST", "/rest/api/2/issue/ABC-1/comment").await,
        0
    );
    // Task 25: the new PAT is stored, the deferred refresh runs; then it is approvable again.
    let before = item.candidate_rev.counter;
    h.engine()
        .start_refresh(&entry)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let item = rev_after(&h, &id, before).await?;
    assert!(item.approvable);
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(
        hits(mock, "POST", "/rest/api/2/issue/ABC-1/comment").await,
        1
    );
    let stale = records(&h, &id, EventType::WRITE_STALE).await?;
    assert_eq!(
        stale
            .iter()
            .map(|s| s["reason"].clone())
            .collect::<Vec<_>>(),
        [json!("instance_changed")]
    );
    // A write that is not in the queue takes no deferred refresh.
    assert!(h.engine().start_refresh(&entry).await.is_err());
    Ok(())
}

/// Approves a `jira.comment.add` on `ABC-1` whose POST answers `t`; returns the `await`.
async fn executed_with(
    answer: impl FnOnce(&MockDc) -> ResponseTemplate,
) -> Result<(Harness, String, Envelope), TestError> {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount(
        mock,
        "POST",
        "/rest/api/2/issue/ABC-1/comment",
        answer(mock),
    )
    .await;
    let id = queued(&h, COMMENT, comment_params()).await?;
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    Ok((h, id, env))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_4xx_upstream_http_details_then_evicted() -> TestResult {
    let (h, id, env) = executed_with(|m| {
        m.response(400)
            .set_body_raw(fixtures::JIRA_ERROR_400, "application/json")
    })
    .await?;
    assert_eq!(
        (env.status, exit(&env)),
        (Status::Failed, 6),
        "{}",
        env.to_json_line()
    );
    assert_eq!(code(&env), "upstream_http");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert_eq!(common::detail(&env, "status"), json!(400));
    assert_eq!(
        common::detail(&env, "error_messages"),
        json!("summary: You must specify a summary of the issue.")
    );
    // The failure stays; its Atlassian text is deliverable for 1 h after the decision (§4.4).
    h.clock().advance(Duration::from_secs(61 * 60));
    let env = h.await_(&id, 1000).await;
    assert_eq!(env.status, Status::Failed);
    assert_eq!((code(&env), exit(&env)), ("result_evicted".to_owned(), 10));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert!(!env.to_json_line().contains("summary"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_non_json_401_is_upstream_unavailable() -> TestResult {
    let (h, id, env) = executed_with(|m| {
        m.response(401)
            .set_body_raw("<html>SSO login SECRETPAGE</html>", "text/html")
    })
    .await?;
    assert_eq!(
        (env.status, exit(&env)),
        (Status::Failed, 6),
        "{}",
        env.to_json_line()
    );
    assert_eq!(code(&env), "upstream_unavailable");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert!(env.error.as_ref().is_some_and(|e| e.details.is_none()));
    assert!(!env.to_json_line().contains("SECRETPAGE"));
    let failed = one(&h, &id, EventType::WRITE_FAILED).await?;
    assert_eq!(failed["class"], "non_json_401");
    assert!(failed["received"].to_string().contains("SECRETPAGE"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_5xx_is_outcome_unknown() -> TestResult {
    let (h, id, env) = executed_with(|m| {
        m.response(503)
            .set_body_raw(r#"{"errorMessages":["SERVERBODY"]}"#, "application/json")
    })
    .await?;
    assert_eq!(
        (env.status, exit(&env)),
        (Status::OutcomeUnknown, 6),
        "{}",
        env.to_json_line()
    );
    assert_eq!(env.data, Some(json!({ "target": "ABC-1" })));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert!(!env.to_json_line().contains("SERVERBODY"));
    let unknown = one(&h, &id, EventType::WRITE_OUTCOME_UNKNOWN).await?;
    assert_eq!(unknown["reason"], "server_error_5xx");
    Ok(())
}

/// A write whose request never left (`NotSent`, here the write budget ran out before the send):
/// back in the queue, approvable again, the agent still sees `executing` and a cancel answers
/// `executing` (§4.5, T12 I-3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_not_sent_returns_to_queue_still_executing() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .timeouts(Timeouts {
            write: Duration::ZERO,
            ..Timeouts::default()
        })
        .start()
        .await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    comment_ok(mock).await;
    let id = queued(&h, COMMENT, comment_params()).await?;
    let rev1 = h.approver().rev(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    let item = rev_after(&h, &id, rev1.counter).await?;
    assert!(item.approvable && !item.opened && item.stale);
    let stale = one(&h, &id, EventType::WRITE_STALE).await?;
    assert_eq!(
        stale,
        json!({ "reason": "recheck_failed", "class": "network" })
    );
    assert_eq!(
        hits(mock, "POST", "/rest/api/2/issue/ABC-1/comment").await,
        0
    );
    assert_eq!(h.status(&id).await.status, Status::Executing);
    let env = h.handler().cancel(&id).await;
    assert_eq!((env.status, exit(&env)), (Status::Executing, 4));
    assert!(records(&h, &id, EventType::CANCELLED).await?.is_empty());
    Ok(())
}

/// Lead ruling 4: `WRITE_EDITED.original` is the agent's params on every edit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_edited_original_is_the_agents_params() -> TestResult {
    let h = Harness::jira().await?;
    let id = queued(&h, COMMENT, comment_params()).await?;
    for body in ["first edit", "second edit"] {
        let mut set = Map::new();
        set.insert("body".into(), json!(body));
        h.approver()
            .edit(
                &id,
                Edits {
                    set,
                    remove: Vec::new(),
                },
            )
            .map_err(de)?;
    }
    let edited = records(&h, &id, EventType::WRITE_EDITED).await?;
    assert_eq!(edited.len(), 2);
    for (e, body) in edited.iter().zip(["first edit", "second edit"]) {
        assert_eq!(e["original"], comment_params());
        assert_eq!(e["edited"]["body"], body);
    }
    // Redactions do not apply to a write decision: refused, nothing logged.
    let rev = h.approver().rev(&id).map_err(de)?;
    let res = h.decisions().decide(atlas_duck_core::Decision {
        request_id: id.clone(),
        decision: atlas_duck_core::DecisionKind::Deny,
        candidate_rev: rev,
        edits: None,
        redactions: Some(vec![atlas_duck_core::RedactionOp::Preset(
            atlas_duck_core::RedactionPreset::StatusOnly,
        )]),
        reason: Some("no".into()),
        deny_details: None,
    });
    assert!(
        matches!(res, Err(DecisionError::EditRejected(_))),
        "{res:?}"
    );
    assert!(records(&h, &id, EventType::WRITE_DENIED).await?.is_empty());
    Ok(())
}
