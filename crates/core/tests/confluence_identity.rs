#![cfg(feature = "testing")]
//! RF-5a (PD-93, Task 13, §7.1, §7.2, §15 V25): every direct Confluence read ends its fetch with
//! one `GET /rest/api/user/current` under the request's cover, after its last content page and
//! its user lookups, before `READ_FETCHED`, recorded `PREVIEW_FETCH {purpose: identity}`. An
//! answer that is not an identity match is handled like a failed Jira header check: the content is
//! audit-only (`READ_FETCHED {unavailable}`), the token re-check runs and the M3 effect table
//! decides; an answer decided from status and headers is a direct `upstream_unavailable`, a
//! body-decided or budget failure an outcome item. `confluence.user.current` judges its own
//! answer and sends no second GET.

mod common;

use std::time::Duration;

use atlas_duck_atlassian::ReadBudget;
use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_core::engine::cancel::{CancelCause, ShutdownReason};
use atlas_duck_core::testing::Harness;
use atlas_duck_core::{Pause, TestHooks};
use atlas_duck_ipc::envelope::{Envelope, Status};
use common::confluence::{content_path, mount_page, mount_users, page_with_storage, user_gets};
use common::jira::gets_on;
use common::{TestError, TestResult, code, exit, request_id};
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const PAGE_GET: &str = "confluence.page.get";
const USER_CURRENT: &str = "confluence.user.current";
const SPACE_LIST: &str = "confluence.space.list";
const ID: &str = "65537";
const IDENTITY: &str = "/rest/api/user/current";
/// A page body whose text must never reach an envelope when the identity is not confirmed.
const PLAIN: &str = "<p>Quarterly numbers: confidential.</p>";
const MARKER: &str = "Quarterly numbers";
/// One mention, looked up before the identity GET.
const MENTION: &str = r#"<p>Owner <ri:user ri:userkey="key-gone"/>: quarterly numbers.</p>"#;

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no wiki mock".into())
}

fn json_answer(mock: &MockDc, status: u16, body: &str) -> ResponseTemplate {
    mock.response(status).set_body_raw(body, "application/json")
}

fn anonymous(mock: &MockDc) -> ResponseTemplate {
    json_answer(mock, 200, fixtures::CONFLUENCE_USER_ANONYMOUS)
}

fn known(mock: &MockDc, username: &str) -> ResponseTemplate {
    json_answer(
        mock,
        200,
        &fixtures::confluence_user_current(username, TEST_USER_KEY),
    )
}

/// Every `GET /rest/api/user/current` answers `t` (ahead of the harness's known default).
async fn identity_answers(mock: &MockDc, t: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(mock.path(IDENTITY)))
        .respond_with(t)
        .mount(mock.server())
        .await;
}

/// The first `GET /rest/api/user/current` answers `t`; later ones (the token re-check) get the
/// harness's default, a known answer for the stored user.
async fn identity_answers_once(mock: &MockDc, t: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(mock.path(IDENTITY)))
        .respond_with(t)
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
}

async fn identity_gets(mock: &MockDc) -> Vec<wiremock::Request> {
    gets_on(mock, IDENTITY).await
}

/// Polls until the mock received `n` identity GETs.
async fn wait_identity_gets(mock: &MockDc, n: usize) -> TestResult {
    for _ in 0..2000 {
        if identity_gets(mock).await.len() >= n {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("never {n} identity GETs").into())
}

async fn submit(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    request_id(&env)
}

async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let id = submit(h, op, params).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    Ok(id)
}

/// Waits for a read's terminal `failed` envelope.
async fn failed(h: &Harness, id: &str) -> Result<Envelope, TestError> {
    assert!(h.settled(id, 20_000).await, "never settled");
    let env = h.await_(id, 1000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert!(
        !env.to_json_line().contains(MARKER),
        "{}",
        env.to_json_line()
    );
    Ok(env)
}

async fn records(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

/// The one record of `id` of type `t`.
async fn one(h: &Harness, id: &str, t: EventType) -> Result<Value, TestError> {
    match records(h, id, t).await?.as_slice() {
        [r] => Ok(r.clone()),
        other => Err(format!("{} {t:?} records", other.len()).into()),
    }
}

/// The request's records without the `DELIVERED` that an `await` adds.
async fn types(h: &Harness, id: &str) -> Result<Vec<EventType>, TestError> {
    let mut t = h.event_types(id).await?;
    t.retain(|e| *e != EventType::DELIVERED);
    Ok(t)
}

async fn rechecks(h: &Harness, phase: &str) -> Result<Vec<Value>, TestError> {
    Ok(h.events_of(EventType::SYSTEM_FETCH)
        .await?
        .into_iter()
        .filter(|p| p["purpose"] == "token_recheck" && p["phase"] == phase)
        .collect())
}

fn state_of(h: &Harness) -> &'static str {
    h.instances().list().first().map_or("?", |i| i.state)
}

/// The identity record: `purpose: identity`, the resolved path, the answer's status.
fn assert_identity_record(f: &Value, status: u64) {
    assert_eq!(f["purpose"], "identity", "{f}");
    assert_eq!(f["method"], "GET", "{f}");
    assert_eq!(f["path"], "/wiki/rest/api/user/current", "{f}");
    assert_eq!(f["status"], status, "{f}");
}

/// The content answer is audit-only: in the `READ_FETCHED` of the direct failure, never in a
/// release item.
async fn assert_content_audit_only(h: &Harness, id: &str, unavailable: &str) -> TestResult {
    let r = one(h, id, EventType::READ_FETCHED).await?;
    assert_eq!(r["unavailable"], unavailable, "{r}");
    assert_eq!(r["pages"], 1, "{r}");
    assert!(r.to_string().contains(MARKER), "{r}");
    // Only the content: the identity answer is in its own `PREVIEW_FETCH`.
    assert!(!r.to_string().contains("profilePicture"), "{r}");
    assert!(h.approver().item(id).is_none(), "no release item");
    Ok(())
}

// ---- the identity step ------------------------------------------------------------------------

/// A known identity: `PREVIEW_FETCH {identity}` before `READ_FETCHED`, the read releases.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_known_identity_releases_normally() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(PLAIN)).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::READ_FETCHED,
        ]
    );
    let f = one(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_identity_record(&f, 200);
    assert!(f["response"].to_string().contains(TEST_USER), "{f}");
    // The identity answer is in its own record only.
    let r = one(&h, &id, EventType::READ_FETCHED).await?;
    assert!(!r.to_string().contains("profilePicture"), "{r}");
    assert_eq!(identity_gets(mock).await.len(), 1);
    // The identity GET left after the content GET.
    let hits: Vec<String> = mock
        .received()
        .await
        .iter()
        .map(|r| r.url.path().to_owned())
        .collect();
    assert_eq!(
        hits,
        [mock.path(&content_path(ID)), mock.path(IDENTITY)],
        "{hits:?}"
    );
    h.approver().release(&id).map_err(common::de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    assert!(env.to_json_line().contains(MARKER));
    assert!(rechecks(&h, "start").await?.is_empty());
    Ok(())
}

/// RF-5 (a): a revoked PAT answered as anonymous never makes a release item. The content is in
/// `READ_FETCHED {unavailable: identity_check}` only; the token re-check confirms the failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_confluence_anonymous_read() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(PLAIN)).await;
    identity_answers(mock, anonymous(mock)).await;
    let id = submit(&h, PAGE_GET, json!({ "id": ID })).await?;
    let env = failed(&h, &id).await?;
    assert_eq!(code(&env), "needs_token", "{}", env.to_json_line());
    assert_eq!(exit(&env), 9);
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::READ_FETCHED,
            EventType::READ_FAILED,
        ]
    );
    assert_identity_record(&one(&h, &id, EventType::PREVIEW_FETCH).await?, 200);
    assert_content_audit_only(&h, &id, "identity_check").await?;
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(rechecks(&h, "result").await?.len(), 1);
    let changes = h.events_of(EventType::INSTANCE_STATE_CHANGED).await?;
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert_eq!(changes[0]["state"], "needs_token");
    assert_eq!(state_of(&h), "needs_token");
    // The identity GET and the re-check's own GET.
    assert_eq!(identity_gets(mock).await.len(), 2);
    Ok(())
}

/// A paged read is checked once, after its last page.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_paged_read_checked_once_after_last_page() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let pages = [
        (0, 25, Some("/rest/api/space?limit=25&start=25")),
        (25, 25, Some("/rest/api/space?limit=25&start=50")),
        (50, 10, None),
    ];
    for (start, size, next) in pages {
        Mock::given(method("GET"))
            .and(path(mock.path("/rest/api/space")))
            .and(query_param("start", start.to_string().as_str()))
            .respond_with(json_answer(
                mock,
                200,
                &fixtures::confluence_space_page(start, 25, size, next),
            ))
            .mount(mock.server())
            .await;
    }
    let id = queued(&h, SPACE_LIST, json!({ "max": 500 })).await?;
    let hits: Vec<String> = mock
        .received()
        .await
        .iter()
        .map(|r| r.url.path().to_owned())
        .collect();
    let space = mock.path("/rest/api/space");
    assert_eq!(
        hits,
        [space.clone(), space.clone(), space, mock.path(IDENTITY)],
        "{hits:?}"
    );
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::READ_FETCHED,
        ]
    );
    assert_eq!(one(&h, &id, EventType::READ_FETCHED).await?["pages"], 3);
    Ok(())
}

/// The order of a Markdown read: content, user lookups, identity GET.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_identity_get_follows_the_user_lookups() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(MENTION)).await;
    mount_users(mock, &[("key-gone", None)]).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    let purposes: Vec<Value> = records(&h, &id, EventType::PREVIEW_FETCH)
        .await?
        .iter()
        .map(|f| f["purpose"].clone())
        .collect();
    assert_eq!(purposes, [json!("resolve"), json!("identity")]);
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::PREVIEW_FETCH,
            EventType::READ_FETCHED,
        ]
    );
    // The definitive answer is cached once the identity matched.
    assert_eq!(h.user_cached("wiki", "key-gone"), Some(None));
    Ok(())
}

/// T11 handoff: the lookups of a read whose identity is not confirmed ran under the anonymous
/// fallback too; their answers are not cached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_lookups_not_cached_without_an_identity_match() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(MENTION)).await;
    mount_users(mock, &[("key-gone", None)]).await;
    identity_answers(mock, anonymous(mock)).await;
    let id = submit(&h, PAGE_GET, json!({ "id": ID })).await?;
    let env = failed(&h, &id).await?;
    assert_eq!(code(&env), "needs_token");
    assert_eq!(user_gets(mock).await.len(), 1);
    assert_eq!(h.user_cached("wiki", "key-gone"), None);
    Ok(())
}

/// The re-check finds the token fine (a race): `upstream_unavailable`, retryable, the instance
/// stays `ok`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_identity_match_race_is_upstream_unavailable() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(PLAIN)).await;
    identity_answers_once(mock, anonymous(mock)).await;
    let id = submit(&h, PAGE_GET, json!({ "id": ID })).await?;
    let env = failed(&h, &id).await?;
    assert_eq!(code(&env), "upstream_unavailable", "{}", env.to_json_line());
    assert_eq!(exit(&env), 6);
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_content_audit_only(&h, &id, "identity_check").await?;
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(state_of(&h), "ok");
    assert!(
        h.events_of(EventType::INSTANCE_STATE_CHANGED)
            .await?
            .is_empty()
    );
    Ok(())
}

/// RF-2: an identity GET answered by a redirect is decided from status and headers: direct
/// `upstream_unavailable`, no re-check, the content audit-only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_identity_get_3xx_is_direct_upstream_unavailable() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(PLAIN)).await;
    identity_answers(
        mock,
        mock.response(302)
            .insert_header("Location", "https://sso.corp.example/login")
            .set_body_raw("<html>moved</html>", "text/html"),
    )
    .await;
    let id = submit(&h, PAGE_GET, json!({ "id": ID })).await?;
    let env = failed(&h, &id).await?;
    assert_eq!(code(&env), "upstream_unavailable", "{}", env.to_json_line());
    assert_eq!(exit(&env), 6);
    let f = one(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_identity_record(&f, 302);
    assert_eq!(f["class"], "redirect_3xx", "{f}");
    assert_content_audit_only(&h, &id, "redirect_3xx").await?;
    assert!(rechecks(&h, "start").await?.is_empty());
    assert_eq!(identity_gets(mock).await.len(), 1);
    assert_eq!(state_of(&h), "ok");
    Ok(())
}

/// A JSON 503 takes the re-check route (the re-check answers known: `upstream_unavailable`); an
/// HTML 503 is decided from status and headers (no re-check).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_identity_get_503_is_upstream_unavailable() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(PLAIN)).await;
    identity_answers_once(
        mock,
        json_answer(mock, 503, r#"{"statusCode":503,"message":"busy"}"#),
    )
    .await;
    let id = submit(&h, PAGE_GET, json!({ "id": ID })).await?;
    let env = failed(&h, &id).await?;
    assert_eq!(code(&env), "upstream_unavailable", "{}", env.to_json_line());
    assert_eq!(exit(&env), 6);
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_identity_record(&one(&h, &id, EventType::PREVIEW_FETCH).await?, 503);
    assert_content_audit_only(&h, &id, "identity_check").await?;
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(rechecks(&h, "result").await?.len(), 1);
    assert_eq!(state_of(&h), "ok");

    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(PLAIN)).await;
    identity_answers(
        mock,
        mock.response(503)
            .set_body_raw("<html>maintenance</html>", "text/html; charset=UTF-8"),
    )
    .await;
    let id = submit(&h, PAGE_GET, json!({ "id": ID })).await?;
    let env = failed(&h, &id).await?;
    assert_eq!(code(&env), "upstream_unavailable", "{}", env.to_json_line());
    assert_eq!(exit(&env), 6);
    assert_identity_record(&one(&h, &id, EventType::PREVIEW_FETCH).await?, 503);
    assert_content_audit_only(&h, &id, "identity_check").await?;
    assert!(rechecks(&h, "start").await?.is_empty());
    assert_eq!(identity_gets(mock).await.len(), 1);
    Ok(())
}

/// A JSON 401 on the identity GET triggers the re-check; a token failure there is `needs_token`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_identity_get_json_401_rechecks() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(PLAIN)).await;
    identity_answers(mock, json_answer(mock, 401, r#"{"statusCode":401}"#)).await;
    let id = submit(&h, PAGE_GET, json!({ "id": ID })).await?;
    let env = failed(&h, &id).await?;
    assert_eq!(code(&env), "needs_token", "{}", env.to_json_line());
    assert_eq!(exit(&env), 9);
    assert_content_audit_only(&h, &id, "identity_check").await?;
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(state_of(&h), "needs_token");
    Ok(())
}

/// A body-decided failure of the identity GET (truncated JSON) is gated like every body-decided
/// read failure: an outcome item, never `READ_FAILED`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_identity_get_truncated_json_is_gated() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(PLAIN)).await;
    identity_answers(
        mock,
        json_answer(mock, 200, r#"{"type":"known","username":"cut-off-answer"#),
    )
    .await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::READ_FETCHED,
        ]
    );
    let r = one(&h, &id, EventType::READ_FETCHED).await?;
    assert_eq!(r["outcome"], "unparsable", "{r}");
    assert_eq!(r["reason"], "identity_check", "{r}");
    assert!(r.to_string().contains(MARKER), "{r}");
    // The identity answer is in its own record only.
    assert!(!r.to_string().contains("cut-off-answer"), "{r}");
    let f = one(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(f["outcome"], "unparsable", "{f}");
    assert!(f.to_string().contains("cut-off-answer"), "{f}");
    assert!(rechecks(&h, "start").await?.is_empty());
    // The released outcome names no content.
    h.approver().release(&id).map_err(common::de)?;
    let env = h.await_(&id, 5000).await;
    assert!(
        !env.to_json_line().contains(MARKER),
        "{}",
        env.to_json_line()
    );
    Ok(())
}

/// The identity GET runs inside the read budget: a budget spent during it is the read-budget
/// outcome item.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_identity_get_counts_in_read_budget() -> TestResult {
    let h = Harness::builder()
        .confluence("wiki")
        .hooks(TestHooks {
            read_budget: Some(ReadBudget {
                total: Duration::from_secs(2),
                ..ReadBudget::default()
            }),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(PLAIN)).await;
    identity_answers(
        mock,
        known(mock, TEST_USER).set_delay(Duration::from_secs(10)),
    )
    .await;
    let began = std::time::Instant::now();
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert!(
        began.elapsed() < Duration::from_secs(8),
        "{:?}",
        began.elapsed()
    );
    let f = one(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(f["purpose"], "identity", "{f}");
    assert_eq!(f["outcome"], "timeout", "{f}");
    let r = one(&h, &id, EventType::READ_FETCHED).await?;
    assert_eq!(r["outcome"], "timeout", "{r}");
    assert_eq!(r["cap_or_budget"], "read_budget_120s", "{r}");
    assert!(r.to_string().contains(MARKER), "{r}");
    Ok(())
}

/// An upstream-error answer is server content attributed to the user: it is identity-checked
/// too, and an anonymous answer makes no upstream-error card.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_upstream_error_read_is_identity_checked() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(ID))))
        .respond_with(json_answer(
            mock,
            404,
            r#"{"statusCode":404,"message":"Quarterly numbers page not found"}"#,
        ))
        .mount(mock.server())
        .await;
    identity_answers(mock, anonymous(mock)).await;
    let id = submit(&h, PAGE_GET, json!({ "id": ID })).await?;
    let env = failed(&h, &id).await?;
    assert_eq!(code(&env), "needs_token", "{}", env.to_json_line());
    assert_eq!(exit(&env), 9);
    let r = one(&h, &id, EventType::READ_FETCHED).await?;
    assert_eq!(r["unavailable"], "identity_check", "{r}");
    assert!(r.to_string().contains(MARKER), "{r}");
    assert!(h.approver().item(&id).is_none());
    Ok(())
}

/// A read that already ended directly (a status/header-decided content answer) sends no
/// identity GET.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_direct_failure_runs_no_identity_get() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mock.redirect(&content_path(ID), "https://sso.corp.example/login")
        .await;
    let id = submit(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert!(h.settled(&id, 20_000).await, "never settled");
    let env = h.await_(&id, 1000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "upstream_unavailable");
    assert_eq!(exit(&env), 6);
    assert!(identity_gets(mock).await.is_empty());
    assert!(records(&h, &id, EventType::PREVIEW_FETCH).await?.is_empty());
    Ok(())
}

/// A known identity under another username (same key) is a rename: the re-check stores the new
/// name and the read fetches once more (its first content audit-only), then releases.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_identity_rename_refetches_once() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(PLAIN)).await;
    identity_answers(mock, known(mock, "jdoe2")).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::READ_FETCHED,
            EventType::PREVIEW_FETCH,
            EventType::READ_FETCHED,
        ]
    );
    let fetched = records(&h, &id, EventType::READ_FETCHED).await?;
    assert_eq!(
        fetched[0]["unavailable"], "identity_check",
        "{}",
        fetched[0]
    );
    assert!(fetched[1].get("unavailable").is_none(), "{}", fetched[1]);
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    let changes = h.events_of(EventType::INSTANCE_STATE_CHANGED).await?;
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert_eq!(changes[0]["state"], "user_renamed");
    assert_eq!(changes[0]["new"], "jdoe2");
    // Content, identity, re-check, content, identity.
    assert_eq!(gets_on(mock, &content_path(ID)).await.len(), 2);
    assert_eq!(identity_gets(mock).await.len(), 3);
    h.approver().release(&id).map_err(common::de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    Ok(())
}

// ---- confluence.user.current ------------------------------------------------------------------

/// The op's own answer is the identity answer: an anonymous one is the token-failure path, with
/// no second `user/current` GET.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_user_current_op_anonymous_is_token_failure() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    identity_answers(mock, anonymous(mock)).await;
    let id = submit(&h, USER_CURRENT, json!({})).await?;
    assert!(h.settled(&id, 20_000).await, "never settled");
    let env = h.await_(&id, 1000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "needs_token", "{}", env.to_json_line());
    assert_eq!(exit(&env), 9);
    assert_eq!(identity_gets(mock).await.len(), 1);
    assert!(rechecks(&h, "start").await?.is_empty());
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::READ_FETCHED,
            EventType::READ_FAILED,
        ]
    );
    let r = one(&h, &id, EventType::READ_FETCHED).await?;
    assert_eq!(r["unavailable"], "identity_check", "{r}");
    assert_eq!(state_of(&h), "needs_token");
    let changes = h.events_of(EventType::INSTANCE_STATE_CHANGED).await?;
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert_eq!(changes[0]["state"], "needs_token");
    Ok(())
}

/// A known answer for the stored user releases, with one GET only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5a_user_current_op_known_releases_with_one_get() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let id = queued(&h, USER_CURRENT, json!({})).await?;
    assert_eq!(identity_gets(mock).await.len(), 1);
    assert_eq!(
        types(&h, &id).await?,
        [EventType::REQUEST_RECEIVED, EventType::READ_FETCHED]
    );
    h.approver().release(&id).map_err(common::de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    assert!(env.to_json_line().contains(TEST_USER_KEY));
    Ok(())
}

// ---- cancel, quit and the record windows of the identity GET -----------------------------------

/// Mounts the page and an identity GET held by the mock, submits, and waits until it is on the
/// wire.
async fn read_held_in_identity(h: &Harness) -> Result<String, TestError> {
    let mock = wiki(h)?;
    mount_page(mock, ID, &page_with_storage(PLAIN)).await;
    identity_answers(
        mock,
        known(mock, TEST_USER).set_delay(Duration::from_secs(30)),
    )
    .await;
    let id = submit(h, PAGE_GET, json!({ "id": ID })).await?;
    wait_identity_gets(mock, 1).await?;
    // The GET has left; the answer is held by the mock.
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(id)
}

/// The records of a read that ended (`terminal`) while its identity GET was in flight.
async fn assert_ended_in_identity(
    h: &Harness,
    id: &str,
    reason: &str,
    terminal: EventType,
) -> TestResult {
    assert_eq!(
        types(h, id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::READ_FETCHED,
            terminal,
        ]
    );
    let f = one(h, id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(f["purpose"], "identity", "{f}");
    assert_eq!(f["outcome"], "cancelled_in_flight", "{f}");
    assert_eq!(f["reason"], reason, "{f}");
    assert_eq!(f["path"], "/wiki/rest/api/user/current", "{f}");
    // §5.2 step 3: every byte received, so the content page already received.
    let r = one(h, id, EventType::READ_FETCHED).await?;
    assert_eq!(r["outcome"], "cancelled_in_flight", "{r}");
    assert_eq!(r["reason"], reason, "{r}");
    assert_eq!(r["pages"], 1, "{r}");
    assert!(r.to_string().contains(MARKER), "{r}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_during_identity_get_records_cancelled_in_flight() -> TestResult {
    let h = Harness::confluence().await?;
    let id = read_held_in_identity(&h).await?;
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    assert_ended_in_identity(&h, &id, "by_client", EventType::CANCELLED).await?;
    let cancelled = one(&h, &id, EventType::CANCELLED).await?;
    assert_eq!(cancelled["reason"], "by_client");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quit_during_identity_get_records_cancelled_in_flight() -> TestResult {
    let h = Harness::confluence().await?;
    let id = read_held_in_identity(&h).await?;
    let env = h
        .engine()
        .cancel_and_wait(&id, CancelCause::Shutdown(ShutdownReason::AppQuit))
        .await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    assert_ended_in_identity(&h, &id, "app_quit", EventType::CANCELLED).await
}

/// A read whose identity GET a hook holds.
async fn held_read(hooks: TestHooks) -> Result<(Harness, String), TestError> {
    let h = Harness::builder()
        .confluence("wiki")
        .hooks(hooks)
        .start()
        .await?;
    mount_page(wiki(&h)?, ID, &page_with_storage(PLAIN)).await;
    let id = submit(&h, PAGE_GET, json!({ "id": ID })).await?;
    Ok((h, id))
}

/// Cancels `id` while a hook holds it, then lets the held task go on and waits for it.
async fn cancel_held(h: &Harness, id: &str, pause: &Pause) -> TestResult {
    let env = h.handler().cancel(id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    pause.release.notify_one();
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(())
}

/// I-1 order: a cancel after the identity GET returned and before its record is parked records
/// the GET once, as in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_before_identity_park_records_it_in_flight() -> TestResult {
    let pause = Pause::new();
    let (h, id) = held_read(TestHooks {
        pause_before_identity_park: Some(pause.clone()),
        ..TestHooks::none()
    })
    .await?;
    pause.reached.notified().await;
    cancel_held(&h, &id, &pause).await?;
    assert_ended_in_identity(&h, &id, "by_client", EventType::CANCELLED).await?;
    assert_eq!(identity_gets(wiki(&h)?).await.len(), 1);
    Ok(())
}

/// I-1 order: a cancel after the identity GET's record is parked records it once, from the
/// parked record (with its answer), not again as in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_after_identity_answered_records_it_once() -> TestResult {
    let pause = Pause::new();
    let (h, id) = held_read(TestHooks {
        pause_after_get: Some(pause.clone()),
        ..TestHooks::none()
    })
    .await?;
    pause.reached.notified().await;
    cancel_held(&h, &id, &pause).await?;
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::READ_FETCHED,
            EventType::CANCELLED,
        ]
    );
    let f = one(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_identity_record(&f, 200);
    assert_ne!(f["outcome"], "cancelled_in_flight", "{f}");
    let r = one(&h, &id, EventType::READ_FETCHED).await?;
    assert_eq!(r["outcome"], "cancelled_in_flight", "{r}");
    assert_eq!(r["pages"], 1, "{r}");
    assert!(r.to_string().contains(MARKER), "{r}");
    Ok(())
}

/// A cancel during the identity GET of an upstream-error read records the error answer too
/// (every byte received; the kept answer is any JSON status, not only a 2xx).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_during_identity_get_of_an_upstream_error_keeps_it() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(ID))))
        .respond_with(json_answer(
            mock,
            404,
            r#"{"statusCode":404,"message":"Quarterly numbers page not found"}"#,
        ))
        .mount(mock.server())
        .await;
    identity_answers(
        mock,
        known(mock, TEST_USER).set_delay(Duration::from_secs(30)),
    )
    .await;
    let id = submit(&h, PAGE_GET, json!({ "id": ID })).await?;
    wait_identity_gets(mock, 1).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    assert_ended_in_identity(&h, &id, "by_client", EventType::CANCELLED).await
}
