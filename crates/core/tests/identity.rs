#![cfg(feature = "testing")]
//! Token replacement (Task 25, I-27 replacement half): a token of another user needs a native
//! confirmation naming both users, a cancel keeps the old token, and a confirmed change returns
//! every queued write of the instance to review under the new identity; the same user's token
//! changes nothing the human saw.
//!
//! Identity checks (Task 26, I-23 JSON-401 case, I-28, I-29, I-30 later half, I-32): the
//! per-response X-AUSERNAME check, `token_recheck`, rename reconciliation, the identity-header
//! states and identity_mismatch writes.

mod common;

use std::time::Duration;

use atlas_duck_atlassian::CredentialProvider;
use atlas_duck_atlassian::testing::{MockDc, TEST_PAT, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_core::testing::{Channel, Harness};
use atlas_duck_core::{AdminError, Confirm, QueueItem};
use atlas_duck_ipc::envelope::Status;
use common::{TestError, TestResult, code, de, detail, exit, request_id};
use secrecy::SecretString;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const COMMENT: &str = "jira.comment.add";

fn pat(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

/// The mock answers the connection test (and the stale check's identity call) as `user`.
async fn answers_as(mock: &MockDc, user: &str, key: &str) {
    mock.server().reset().await;
    mock.jira_myself(user, key, XAuser::Same).await;
    // `serverInfo` answers as the same user (the mock's own user is `jdoe`).
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/serverInfo")))
        .respond_with(
            mock.response(200)
                .insert_header("X-AUSERNAME", user)
                .set_body_raw(fixtures::jira_server_info("9.12.0"), "application/json"),
        )
        .mount(mock.server())
        .await;
    mock.json(
        "/rest/api/2/issue/ABC-1/comment",
        201,
        fixtures::JIRA_COMMENT,
    )
    .await;
}

fn comment_params() -> Value {
    json!({ "key": "ABC-1", "body": "Reproduced on staging.", "body_format": "wiki" })
}

async fn queued_comment(h: &Harness) -> Result<String, TestError> {
    let env = h.submit(COMMENT, comment_params()).await;
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

async fn stale_reasons(h: &Harness, id: &str) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::WRITE_STALE)
        .map(|(_, p)| p["reason"].clone())
        .collect())
}

async fn item_after(h: &Harness, id: &str, rev: u64) -> Result<QueueItem, TestError> {
    for _ in 0..400 {
        if let Some(item) = h.approver().item(id)
            && item.candidate_rev.counter > rev
        {
            return Ok(item);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err("the revision never advanced".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i27_other_user_needs_confirmation() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    answers_as(jira(&h)?, "bob", "JIRAUSER2").await;
    let report = h
        .instances()
        .set_token("jira-main", pat("bobs-token"), None)
        .await?;
    assert_eq!(report.atlassian_user, "bob");
    assert_eq!(
        h.confirmer().texts(),
        ["This token belongs to bob, previously jdoe"]
    );
    let id = h.instance("jira-main").ok_or("instance")?.id.clone();
    let stored = h.credentials().load(&id)?.ok_or("no token")?;
    assert_eq!(stored.identity.atlassian_user_key, "JIRAUSER2");
    let changed = h.events_of(EventType::CREDENTIAL_CHANGED).await?;
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0]["change"], "replaced");
    assert_eq!(changed[0]["old_user_key"], TEST_USER_KEY);
    assert_eq!(changed[0]["new_user_key"], "JIRAUSER2");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i27_cancel_keeps_old_pat() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Cancel])
        .start()
        .await?;
    answers_as(jira(&h)?, "bob", "JIRAUSER2").await;
    let res = h
        .instances()
        .set_token("jira-main", pat("bobs-token"), None)
        .await;
    assert_eq!(res.err(), Some(AdminError::Cancelled));
    let id = h.instance("jira-main").ok_or("instance")?.id.clone();
    let stored = h.credentials().load(&id)?.ok_or("no token")?;
    assert_eq!(stored.pat.expose_secret(), TEST_PAT);
    assert_eq!(stored.identity.atlassian_user, TEST_USER);
    assert!(h.events_of(EventType::CREDENTIAL_CHANGED).await?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i27_confirmed_change_refreshes_pending_writes() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    answers_as(jira(&h)?, TEST_USER, TEST_USER_KEY).await;
    let id = queued_comment(&h).await?;
    h.approver().open(&id).map_err(de)?;
    let before = h.approver().item(&id).ok_or("not queued")?;
    assert!(before.opened && before.approvable);
    answers_as(jira(&h)?, "bob", "JIRAUSER2").await;
    h.instances()
        .set_token("jira-main", pat("bobs-token"), None)
        .await?;
    assert_eq!(stale_reasons(&h, &id).await?, [json!("credential_changed")]);
    let after = item_after(&h, &id, before.candidate_rev.counter).await?;
    assert!(!after.opened, "the human has to look again");
    // The refresh (comment add has no GETs) ends in the queue, under the new token.
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(preview.header.executes_as.as_deref(), Some("bob"));
    let caution = preview
        .warnings
        .iter()
        .find(|w| format!("{:?}", w.id) == "TokenChanged")
        .ok_or("no token_changed caution")?;
    assert_eq!(caution.text, "token changed: now executes as bob");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i27_same_user_replacement_changes_nothing() -> TestResult {
    let h = Harness::jira().await?;
    answers_as(jira(&h)?, TEST_USER, TEST_USER_KEY).await;
    let id = queued_comment(&h).await?;
    h.approver().open(&id).map_err(de)?;
    let before = h.approver().item(&id).ok_or("not queued")?;
    h.instances()
        .set_token("jira-main", pat("rotated-token"), None)
        .await?;
    assert!(
        h.confirmer().texts().is_empty(),
        "no dialog for the same user"
    );
    assert!(stale_reasons(&h, &id).await?.is_empty());
    let after = h.approver().item(&id).ok_or("left the queue")?;
    assert_eq!(after.candidate_rev, before.candidate_rev);
    assert!(after.opened && after.approvable);
    let changed = h.events_of(EventType::CREDENTIAL_CHANGED).await?;
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0]["old_user_key"], changed[0]["new_user_key"]);
    let sid = h.instance("jira-main").ok_or("instance")?.id.clone();
    assert_eq!(
        h.credentials()
            .load(&sid)?
            .ok_or("no token")?
            .pat
            .expose_secret(),
        "rotated-token"
    );
    Ok(())
}

/// M-5: the token changes while the write is still being enriched under the old one. The
/// enrichment's verdict applies, the write is never approvable on it, `WRITE_STALE
/// {credential_changed}` follows, and the refresh runs under the new token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i27_change_during_enrichment_refreshes_after_enriched() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let mock = jira(&h)?;
    answers_as(mock, "bob", "JIRAUSER2").await;
    // The first answers (the enrichment under the old token) carry `jdoe`, the later ones
    // (the refresh under the new token) `bob`; the last GET of the enrichment is the slow one.
    for (p, body, slow) in [
        (
            "/rest/api/2/issue/ABC-1/transitions",
            fixtures::JIRA_TRANSITIONS,
            0,
        ),
        ("/rest/api/2/issue/ABC-1", fixtures::JIRA_ISSUE, 700),
    ] {
        for (user, once) in [(TEST_USER, true), ("bob", false)] {
            let delay = Duration::from_millis(if once { slow } else { 0 });
            let mut m = Mock::given(method("GET"))
                .and(path(mock.path(p)))
                .respond_with(
                    mock.response(200)
                        .insert_header("X-AUSERNAME", user)
                        .set_delay(delay)
                        .set_body_raw(body, "application/json"),
                );
            if once {
                m = m.up_to_n_times(1).with_priority(1);
            } else {
                m = m.with_priority(5);
            }
            m.mount(mock.server()).await;
        }
    }
    let env = h
        .submit(
            "jira.issue.transition",
            json!({ "key": "ABC-1", "transition": "Start Progress" }),
        )
        .await;
    let id = request_id(&env)?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(h.approver().item(&id).is_none(), "still being enriched");
    h.instances()
        .set_token("jira-main", pat("bobs-token"), None)
        .await?;
    // From here the write may reach the queue, but never approvable before the stale record.
    let mut approvable_seen = false;
    for _ in 0..600 {
        if h.approver().item(&id).is_some_and(|i| i.approvable) {
            assert_eq!(
                stale_reasons(&h, &id).await?,
                [json!("credential_changed")],
                "approvable before the change was followed"
            );
            approvable_seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(approvable_seen, "never approvable after the refresh");
    let fetches: Vec<String> = h
        .events(&id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::PREVIEW_FETCH)
        .filter_map(|(_, p)| p["purpose"].as_str().map(str::to_owned))
        .collect();
    assert!(fetches.iter().any(|p| p == "refresh"), "{fetches:?}");
    assert_eq!(fetches.last().map(String::as_str), Some("refresh"));
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(preview.header.executes_as.as_deref(), Some("bob"));
    Ok(())
}

// ---- Task 26: identity checks ----------------------------------------------------------------

const ISSUE: &str = "jira.issue.get";
const MARKER: &str = "FIRST-BODY-MARKER";

/// `GET /issue/ABC-1` answers `body` with `X-AUSERNAME: header` (`None`: no header at all).
async fn issue_as(mock: &MockDc, header: Option<&str>, body: &str, status: u16, priority: u8) {
    let mut t = ResponseTemplate::new(status).set_body_raw(body, "application/json");
    if let Some(h) = header {
        t = t.insert_header("X-AUSERNAME", h);
    }
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1")))
        .respond_with(t)
        .with_priority(priority)
        .mount(mock.server())
        .await;
}

/// The payloads of the `SYSTEM_FETCH {purpose: token_recheck}` records of `phase`.
async fn rechecks(h: &Harness, phase: &str) -> Result<Vec<Value>, TestError> {
    Ok(h.events_of(EventType::SYSTEM_FETCH)
        .await?
        .into_iter()
        .filter(|p| p["purpose"] == "token_recheck" && p["phase"] == phase)
        .collect())
}

async fn state_changes(h: &Harness) -> Result<Vec<Value>, TestError> {
    h.events_of(EventType::INSTANCE_STATE_CHANGED).await
}

fn state_of(h: &Harness) -> &'static str {
    h.instances().list().first().map_or("?", |i| i.state)
}

async fn submit_read(h: &Harness) -> Result<String, TestError> {
    request_id(&h.submit(ISSUE, json!({ "key": "ABC-1" })).await)
}

/// Waits for a read's terminal (failed) envelope.
async fn failed_read(
    h: &Harness,
    id: &str,
) -> Result<atlas_duck_ipc::envelope::Envelope, TestError> {
    assert!(h.settled(id, 10_000).await, "never settled");
    let env = h.await_(id, 1000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    Ok(env)
}

async fn posts(mock: &MockDc) -> usize {
    mock.received()
        .await
        .iter()
        .filter(|r| r.method.as_str() == "POST")
        .count()
}

async fn wait_not_approvable(h: &Harness, id: &str) -> Result<(), TestError> {
    for _ in 0..400 {
        if h.approver().item(id).is_some_and(|i| !i.approvable) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err("still approvable".into())
}

async fn wait_approvable(h: &Harness, id: &str) -> Result<(), TestError> {
    for _ in 0..400 {
        if h.approver().item(id).is_some_and(|i| i.approvable) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err("never approvable".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i28_anonymous_read_needs_token() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    issue_as(mock, Some("anonymous"), fixtures::JIRA_ISSUE, 200, 5).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Anonymous)
        .await;
    let id = submit_read(&h).await?;
    let env = failed_read(&h, &id).await?;
    assert_eq!((exit(&env), code(&env).as_str()), (9, "needs_token"));
    assert_eq!(env.data, None);
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::READ_FETCHED,
            EventType::READ_FAILED,
            EventType::DELIVERED
        ]
    );
    // The answer is audit-only: in `READ_FETCHED`, in no envelope.
    let fetched = h
        .events(&id)
        .await?
        .into_iter()
        .find(|(t, _)| *t == EventType::READ_FETCHED)
        .map(|(_, p)| p)
        .ok_or("no READ_FETCHED")?;
    assert!(fetched.to_string().contains("Login page times out"));
    assert!(
        !h.capture()
            .on(Channel::Envelope)
            .iter()
            .any(|c| c.json.contains("Login page times out"))
    );
    assert!(h.approver().item(&id).is_none(), "never a release item");
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(rechecks(&h, "result").await?.len(), 1);
    assert_eq!(
        rechecks(&h, "start").await?[0]["planned"][0]["path"],
        "/rest/api/2/myself"
    );
    // A token verdict never deletes the PAT (§7.1).
    let sid = h.instance("jira-main").ok_or("instance")?.id.clone();
    assert!(h.credentials().load(&sid)?.is_some());
    assert_eq!(state_of(&h), "needs_token");
    let changes = state_changes(&h).await?;
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["state"], "needs_token");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i28_comment_add_identity_call_stale() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    answers_as(mock, TEST_USER, TEST_USER_KEY).await;
    let id = queued_comment(&h).await?;
    h.approver().open(&id).map_err(de)?;
    let before = h.approver().item(&id).ok_or("not queued")?;
    // From here the identity call answers as anonymous (the PAT stopped working).
    mock.server().reset().await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Anonymous)
        .await;
    mock.json(
        "/rest/api/2/issue/ABC-1/comment",
        201,
        fixtures::JIRA_COMMENT,
    )
    .await;
    h.approver().approve(&id).map_err(de)?;
    let after = item_after(&h, &id, before.candidate_rev.counter).await?;
    assert!(!after.approvable);
    assert_eq!(stale_reasons(&h, &id).await?, [json!("identity_mismatch")]);
    assert_eq!(posts(mock).await, 0, "nothing was sent");
    assert_eq!(state_of(&h), "needs_token");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i28_passing_recheck_is_upstream_unavailable() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    // The read's answer names `bob`; the recheck's own `/myself` is jdoe's, header and all.
    issue_as(mock, Some("bob"), fixtures::JIRA_ISSUE, 200, 5).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    let id = submit_read(&h).await?;
    let env = failed_read(&h, &id).await?;
    assert_eq!(
        (exit(&env), code(&env).as_str()),
        (6, "upstream_unavailable")
    );
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(state_of(&h), "ok");
    assert!(state_changes(&h).await?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i28_recheck_other_user_needs_token() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    issue_as(mock, Some("bob"), fixtures::JIRA_ISSUE, 200, 5).await;
    mock.jira_myself("bob", "JIRAUSER9", XAuser::Same).await;
    let id = submit_read(&h).await?;
    let env = failed_read(&h, &id).await?;
    assert_eq!((exit(&env), code(&env).as_str()), (9, "needs_token"));
    let view = h.instances().list().into_iter().next().ok_or("no view")?;
    assert_eq!(view.state, "needs_token");
    assert_eq!(view.note.as_deref(), Some("token now resolves to bob"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i28_write_response_anonymous_outcome_unknown() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    answers_as(mock, TEST_USER, TEST_USER_KEY).await;
    // The stale check passes, the write's own answer comes back as anonymous.
    Mock::given(method("POST"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1/comment")))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("X-AUSERNAME", "anonymous")
                .set_body_raw(fixtures::JIRA_COMMENT, "application/json"),
        )
        .with_priority(1)
        .mount(mock.server())
        .await;
    let id = queued_comment(&h).await?;
    h.approver().open(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::OutcomeUnknown, "{}", env.to_json_line());
    let unknown = h
        .events(&id)
        .await?
        .into_iter()
        .find(|(t, _)| *t == EventType::WRITE_OUTCOME_UNKNOWN)
        .map(|(_, p)| p)
        .ok_or("no WRITE_OUTCOME_UNKNOWN")?;
    assert_eq!(unknown["reason"], "identity_mismatch");
    assert_eq!(unknown["server_user"], "anonymous");
    // Δ C.4: the status of the answer the check refused.
    assert_eq!(unknown["status"], 201);
    // The write is never retried; the recheck only brings the instance state up to date.
    assert_eq!(posts(mock).await, 1);
    for _ in 0..200 {
        if !rechecks(&h, "start").await?.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i28_write_executed_records_server_user() -> TestResult {
    let h = Harness::jira().await?;
    answers_as(jira(&h)?, TEST_USER, TEST_USER_KEY).await;
    let id = queued_comment(&h).await?;
    h.approver().open(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let executed = h
        .events(&id)
        .await?
        .into_iter()
        .find(|(t, _)| *t == EventType::WRITE_EXECUTED)
        .map(|(_, p)| p)
        .ok_or("no WRITE_EXECUTED")?;
    assert_eq!(executed["server_user"], "jdoe");
    Ok(())
}

/// The mock renamed `jdoe` to `jdoe2` (same key): every answer carries the new name; the first
/// answer of the issue read has a body that must never be released.
async fn renamed(mock: &MockDc) {
    mock.server().reset().await;
    let first = json!({ "key": "ABC-1", "fields": { "summary": MARKER } }).to_string();
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-AUSERNAME", "jdoe2")
                .set_body_raw(first, "application/json"),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    issue_as(mock, Some("jdoe2"), fixtures::JIRA_ISSUE, 200, 5).await;
    mock.jira_myself("jdoe2", TEST_USER_KEY, XAuser::Same).await;
    mock.jira_server_info("9.12.0").await;
    Mock::given(method("POST"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1/comment")))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("X-AUSERNAME", "jdoe2")
                .set_body_raw(fixtures::JIRA_COMMENT, "application/json"),
        )
        .mount(mock.server())
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i29_rename_refetches_once_and_heals() -> TestResult {
    let h = Harness::jira().await?;
    renamed(jira(&h)?).await;
    let id = submit_read(&h).await?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    let changes = state_changes(&h).await?;
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["state"], "user_renamed");
    assert_eq!(changes[0]["old"], "jdoe");
    assert_eq!(changes[0]["new"], "jdoe2");
    assert_eq!(changes[0]["user_key"], TEST_USER_KEY);
    let sid = h.instance("jira-main").ok_or("instance")?.id.clone();
    let stored = h.credentials().load(&sid)?.ok_or("no token")?;
    assert_eq!(stored.identity.atlassian_user, "jdoe2");
    assert_eq!(stored.identity.atlassian_user_key, TEST_USER_KEY);
    // The first answer is audit-only; the re-fetched one is the release item.
    let fetched: Vec<Value> = h
        .events(&id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::READ_FETCHED)
        .map(|(_, p)| p)
        .collect();
    assert_eq!(fetched.len(), 2);
    assert!(fetched[0]["unavailable"].is_string());
    assert!(fetched[0].to_string().contains(MARKER));
    assert!(fetched[1].get("unavailable").is_none());
    h.approver().open(&id).map_err(de)?;
    h.approver().release(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    assert!(!env.to_json_line().contains(MARKER));
    for released in h.events_of(EventType::READ_RELEASED).await? {
        assert!(!released.to_string().contains(MARKER));
    }
    assert!(env.to_json_line().contains("Login page times out"));
    // Healed: the next read passes the per-response check without a recheck.
    let second = submit_read(&h).await?;
    h.queued(&second, 10_000).await.ok_or("never queued")?;
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(state_of(&h), "ok");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i29_rename_refreshes_pending_write() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    answers_as(mock, TEST_USER, TEST_USER_KEY).await;
    let id = queued_comment(&h).await?;
    h.approver().open(&id).map_err(de)?;
    let before = h.approver().item(&id).ok_or("not queued")?;
    assert!(before.opened && before.approvable);
    // The rename becomes visible through a read.
    renamed(mock).await;
    let read = submit_read(&h).await?;
    h.queued(&read, 10_000).await.ok_or("read never queued")?;
    let after = item_after(&h, &id, before.candidate_rev.counter).await?;
    assert!(!after.opened, "the human has to look again");
    assert!(
        stale_reasons(&h, &id)
            .await?
            .contains(&json!("user_renamed"))
    );
    wait_approvable(&h, &id).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(preview.header.executes_as.as_deref(), Some("jdoe2"));
    let caution = preview
        .warnings
        .iter()
        .find(|w| format!("{:?}", w.id) == "UserRenamed")
        .ok_or("no user_renamed caution")?;
    assert_eq!(caution.text, "Atlassian username changed: jdoe → jdoe2");
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i29_different_key_needs_token() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    issue_as(mock, Some("jdoe2"), fixtures::JIRA_ISSUE, 200, 5).await;
    mock.jira_myself("jdoe2", "JIRAUSER7", XAuser::Same).await;
    let id = submit_read(&h).await?;
    let env = failed_read(&h, &id).await?;
    assert_eq!((exit(&env), code(&env).as_str()), (9, "needs_token"));
    let changes = state_changes(&h).await?;
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["state"], "needs_token");
    let sid = h.instance("jira-main").ok_or("instance")?.id.clone();
    let stored = h.credentials().load(&sid)?.ok_or("no token")?;
    assert_eq!(
        stored.identity.atlassian_user, TEST_USER,
        "no rename for another key"
    );
    Ok(())
}

/// Header stripped by a proxy: every Jira answer arrives without `X-AUSERNAME` (or, for the
/// read, with `header`).
async fn header_lost(mock: &MockDc, header: Option<&str>) {
    mock.server().reset().await;
    issue_as(mock, header, fixtures::JIRA_ISSUE, 200, 5).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Missing)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i30_header_lost_later_state() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    answers_as(mock, TEST_USER, TEST_USER_KEY).await;
    let write = queued_comment(&h).await?;
    assert!(h.approver().item(&write).is_some_and(|i| i.approvable));
    header_lost(mock, None).await;
    let id = submit_read(&h).await?;
    let env = failed_read(&h, &id).await?;
    assert_eq!(
        (exit(&env), code(&env).as_str()),
        (6, "upstream_unavailable")
    );
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert_eq!(detail(&env, "reason"), json!("identity_header_missing"));
    assert_eq!(
        common::message(&env),
        "X-AUSERNAME not received, possibly stripped by a reverse proxy in front of Jira; ask the Jira administrator"
    );
    assert_eq!(state_of(&h), "identity_header_missing");
    let changes = state_changes(&h).await?;
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["state"], "identity_header_missing");
    // The pending write is not approvable and says why.
    wait_not_approvable(&h, &write).await?;
    let preview = h.approver().open(&write).map_err(de)?.preview;
    assert!(!preview.approvable);
    let caution = preview
        .warnings
        .iter()
        .find(|w| format!("{:?}", w.id) == "IdentityHeaderLost")
        .ok_or("no identity_header_lost caution")?;
    assert!(
        caution.text.contains("ask the Jira administrator"),
        "{}",
        caution.text
    );
    // No new request is sent to the instance (PD-03).
    let before = mock.received().await.len();
    let env = h.submit(ISSUE, json!({ "key": "ABC-1" })).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(detail(&env, "reason"), json!("identity_header_missing"));
    assert_eq!(mock.received().await.len(), before);
    // "Re-test stored token" with the header back clears the state; the write is approvable.
    answers_as(mock, TEST_USER, TEST_USER_KEY).await;
    h.instances().retest_token("jira-main").await?;
    assert_eq!(state_of(&h), "ok");
    wait_approvable(&h, &write).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i30_header_anonymous_takes_recheck_path() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    // `anonymous` on the read, but the recheck finds the stored key without the header: the
    // header is lost, the token is not at fault.
    header_lost(mock, Some("anonymous")).await;
    let id = submit_read(&h).await?;
    let env = failed_read(&h, &id).await?;
    assert_eq!(
        (exit(&env), code(&env).as_str()),
        (6, "upstream_unavailable")
    );
    assert_eq!(detail(&env, "reason"), json!("identity_header_missing"));
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(state_of(&h), "identity_header_missing");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_json401_needs_token_only_if_recheck_fails() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    // A Jira JSON 401 carries `X-AUSERNAME: anonymous` by nature.
    let body = r#"{"errorMessages":["You are not authenticated"],"errors":{}}"#;
    issue_as(mock, Some("anonymous"), body, 401, 5).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    // The recheck passes: the 401 is an ordinary 4xx, an upstream-error item.
    let id = submit_read(&h).await?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(
        matches!(
            preview.body,
            atlas_duck_preview::PreviewBody::UpstreamError { .. }
        ),
        "{:?}",
        preview.body
    );
    assert_eq!(state_of(&h), "ok");
    let sid = h.instance("jira-main").ok_or("instance")?.id.clone();
    assert!(h.credentials().load(&sid)?.is_some());
    // The recheck fails too: needs_token, the PAT stays.
    mock.server().reset().await;
    issue_as(mock, Some("anonymous"), body, 401, 5).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Anonymous)
        .await;
    let second = submit_read(&h).await?;
    let env = failed_read(&h, &second).await?;
    assert_eq!((exit(&env), code(&env).as_str()), (9, "needs_token"));
    assert!(h.credentials().load(&sid)?.is_some());
    assert_eq!(state_of(&h), "needs_token");
    Ok(())
}

/// A recheck that is not a parsed JSON 2xx (here a 429 without the header) changes nothing; the
/// original call is `upstream_unavailable` (the §7.1 branches do not name this case).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i28_inconclusive_recheck_changes_no_state() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    issue_as(mock, None, fixtures::JIRA_ISSUE, 200, 5).await;
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/myself")))
        .respond_with(ResponseTemplate::new(429).set_body_raw("{}", "application/json"))
        .mount(mock.server())
        .await;
    let id = submit_read(&h).await?;
    let env = failed_read(&h, &id).await?;
    assert_eq!(
        (exit(&env), code(&env).as_str()),
        (6, "upstream_unavailable")
    );
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(state_of(&h), "ok");
    assert!(state_changes(&h).await?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_recheck_in_flight_per_instance() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    issue_as(mock, None, fixtures::JIRA_ISSUE, 200, 5).await;
    // A slow recheck keeps the others waiting on it.
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/myself")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(400))
                .set_body_raw(
                    fixtures::jira_myself(TEST_USER, TEST_USER_KEY),
                    "application/json",
                ),
        )
        .mount(mock.server())
        .await;
    let mut ids = Vec::new();
    for _ in 0..10 {
        ids.push(submit_read(&h).await?);
    }
    for id in &ids {
        let env = failed_read(&h, id).await?;
        assert_eq!(
            detail(&env, "reason"),
            json!("identity_header_missing"),
            "{id}"
        );
    }
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(state_changes(&h).await?.len(), 1);
    Ok(())
}

// ---- enrichment, retest and the base-URL change ------------------------------------------------

const TRANSITION: &str = "jira.issue.transition";

fn transition_params() -> Value {
    json!({ "key": "ABC-1", "transition": "Start Progress" })
}

/// `GET /issue/ABC-1/transitions` answers the fixture with `X-AUSERNAME: header`.
async fn transitions_as(mock: &MockDc, header: &str, priority: u8, times: Option<u64>) {
    let mut m = Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1/transitions")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-AUSERNAME", header)
                .set_body_raw(fixtures::JIRA_TRANSITIONS, "application/json"),
        )
        .with_priority(priority);
    if let Some(n) = times {
        m = m.up_to_n_times(n);
    }
    m.mount(mock.server()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i28_enrichment_anonymous_fails_needs_token() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    transitions_as(mock, "anonymous", 5, None).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Anonymous)
        .await;
    let id = request_id(&h.submit(TRANSITION, transition_params()).await)?;
    let env = failed_read(&h, &id).await?;
    assert_eq!((exit(&env), code(&env).as_str()), (9, "needs_token"));
    assert!(h.approver().item(&id).is_none());
    let types = h.event_types(&id).await?;
    assert!(types.contains(&EventType::REQUEST_FAILED), "{types:?}");
    assert_eq!(state_of(&h), "needs_token");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i29_enrichment_rename_reruns_once() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.server().reset().await;
    // The first enrichment answer already carries the new name; the rerun's too.
    transitions_as(mock, "jdoe2", 5, None).await;
    issue_as(mock, Some("jdoe2"), fixtures::JIRA_ISSUE, 200, 5).await;
    mock.jira_myself("jdoe2", TEST_USER_KEY, XAuser::Same).await;
    let id = request_id(&h.submit(TRANSITION, transition_params()).await)?;
    let item = h.queued(&id, 10_000).await.ok_or("never queued")?;
    assert!(item.approvable, "{item:?}");
    let fetches: Vec<Value> = h
        .events(&id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::PREVIEW_FETCH)
        .map(|(_, p)| p)
        .collect();
    // The transitions GET ran twice (the rename), then the issue GET once.
    assert_eq!(fetches.len(), 3, "{fetches:?}");
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(state_changes(&h).await?[0]["state"], "user_renamed");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i28_retest_other_user_needs_token() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    answers_as(mock, "bob", "JIRAUSER9").await;
    let res = h.instances().retest_token("jira-main").await;
    assert_eq!(
        res.err(),
        Some(AdminError::ConnectionFailed(
            atlas_duck_core::ConnectionFailure::OtherUser
        ))
    );
    assert_eq!(state_of(&h), "needs_token");
    let view = h.instances().list().into_iter().next().ok_or("no view")?;
    assert_eq!(view.note.as_deref(), Some("token now resolves to bob"));
    let sid = h.instance("jira-main").ok_or("instance")?.id.clone();
    let stored = h.credentials().load(&sid)?.ok_or("no token")?;
    assert_eq!(
        stored.identity.atlassian_user, TEST_USER,
        "the PAT stays as it was"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i29_retest_rename_updates_the_stored_name() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    answers_as(mock, "jdoe2", TEST_USER_KEY).await;
    let report = h.instances().retest_token("jira-main").await?;
    assert_eq!(report.atlassian_user, "jdoe2");
    let changes = state_changes(&h).await?;
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["state"], "user_renamed");
    assert!(h.events_of(EventType::CREDENTIAL_CHANGED).await?.is_empty());
    let sid = h.instance("jira-main").ok_or("instance")?.id.clone();
    let stored = h.credentials().load(&sid)?.ok_or("no token")?;
    assert_eq!(stored.identity.atlassian_user, "jdoe2");
    let view = h.instances().list().into_iter().next().ok_or("no view")?;
    assert_eq!(view.executes_as.as_deref(), Some("jdoe2"));
    assert_eq!(state_of(&h), "ok");
    Ok(())
}

fn page_at(version: u64) -> String {
    let mut page: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE).unwrap_or(Value::Null);
    page["version"]["number"] = json!(version);
    page.to_string()
}

/// A Confluence mock that serves page 65537 at version 5 and accepts the update.
async fn page_server(mock: &MockDc) {
    mock.confluence_user_current(
        atlas_duck_atlassian::testing::UserKind::Known,
        TEST_USER,
        TEST_USER_KEY,
    )
    .await;
    mock.applinks_manifest("9.2.1").await;
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/content/65537")))
        .respond_with(
            mock.response(200)
                .set_body_raw(page_at(5), "application/json"),
        )
        .mount(mock.server())
        .await;
    Mock::given(method("PUT"))
        .and(path(mock.path("/rest/api/content/65537")))
        .respond_with(
            mock.response(200)
                .set_body_raw(fixtures::CONFLUENCE_PAGE_UPDATED, "application/json"),
        )
        .mount(mock.server())
        .await;
}

async fn puts(mock: &MockDc) -> usize {
    mock.received()
        .await
        .iter()
        .filter(|r| r.method.as_str() == "PUT")
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i32_base_url_change_restales_pending_update() -> TestResult {
    let h = Harness::builder()
        .confluence("wiki")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let a = h.mock("wiki").ok_or("mock A")?;
    page_server(a).await;
    let params = json!({
        "id": "65537", "base_version": 5, "body": "<p>New text.</p>", "body_format": "storage"
    });
    let id = request_id(&h.submit("confluence.page.update", params).await)?;
    let item = h.queued(&id, 10_000).await.ok_or("never queued")?;
    assert!(item.approvable);
    h.approver().open(&id).map_err(de)?;
    let rev1 = h.approver().rev(&id).map_err(de)?.counter;
    let b = MockDc::start(atlas_duck_atlassian::Product::Confluence, "/wiki2").await;
    page_server(&b).await;
    let received_at_a = a.received().await.len();
    h.instances().change_base_url("wiki", &b.base_url())?;
    let item = item_after(&h, &id, rev1).await?;
    assert!(
        !item.approvable,
        "not approvable until the instance has a PAT"
    );
    assert_eq!(stale_reasons(&h, &id).await?, [json!("instance_changed")]);
    // The same user's token on the new origin: the refresh re-enriches against B.
    h.instances()
        .set_token("wiki", pat("new-pat"), None)
        .await?;
    wait_approvable(&h, &id).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(
        format!("{:?}", preview.body).contains(&b.base_url()),
        "Raw shows the new origin: {:?}",
        preview.body
    );
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(puts(&b).await, 1, "B received the PUT");
    assert_eq!(puts(a).await, 0);
    assert_eq!(
        a.received().await.len(),
        received_at_a,
        "A receives nothing after the change"
    );
    Ok(())
}
