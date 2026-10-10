#![cfg(feature = "testing")]
//! Token replacement (Task 25, I-27 replacement half): a token of another user needs a native
//! confirmation naming both users, a cancel keeps the old token, and a confirmed change returns
//! every queued write of the instance to review under the new identity; the same user's token
//! changes nothing the human saw.

mod common;

use std::time::Duration;

use atlas_duck_atlassian::CredentialProvider;
use atlas_duck_atlassian::testing::{MockDc, TEST_PAT, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_core::testing::Harness;
use atlas_duck_core::{AdminError, Confirm, QueueItem};
use common::{TestError, TestResult, de, request_id};
use secrecy::SecretString;
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path};

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
