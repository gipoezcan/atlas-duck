#![cfg(feature = "testing")]
//! Jira reads in M5. Task 9: `jira.issue.get --comments` is a composite read (PD-45, §7.3): the
//! issue GET (its `fields` without `comment`), then the `jira.comment.list` pages up to the
//! comments cap, under one cover, one control and one read budget, recorded in one
//! `READ_FETCHED` and merged into `fields.comment` (and, rendered, `renderedFields.comment`).

mod common;

use std::time::Duration;

use atlas_duck_atlassian::ReadBudget;
use atlas_duck_atlassian::testing::MockDc;
use atlas_duck_audit::EventType;
use atlas_duck_core::engine::queue::{Limits, MIB};
use atlas_duck_core::testing::Harness;
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::warning::{Level, WarningId};
use atlas_duck_preview::{OutcomeKind, PreviewBody};
use common::jira::{
    comment_page, comments_path, gets_on, issue_path, mount_comment_page_delayed,
    mount_comment_page_with, mount_comments, mount_comments_rendered, mount_issue, query,
};
use common::{TestError, TestResult, code, de, request_id, test_hits};
use serde_json::{Value, json};

const ISSUE: &str = "jira.issue.get";
const KEY: &str = "ABC-7";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

/// The issue as Jira answers it; it carries a stale `fields.comment` the merge must replace.
fn issue_body() -> Value {
    json!({
        "id": "10007",
        "key": KEY,
        "self": "https://jira.corp.example/rest/api/2/issue/10007",
        "fields": {
            "summary": "Composite read",
            "comment": {"startAt": 0, "maxResults": 1, "total": 1, "comments": [{"id": "1"}]}
        }
    })
}

/// Submits, expects `pending`, and waits until the read waits for release.
async fn queued(h: &Harness, params: Value) -> Result<String, TestError> {
    let env = h.submit(ISSUE, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    Ok(id)
}

/// Releases `id` and returns the released `result`.
async fn released(h: &Harness, id: &str) -> Result<Value, TestError> {
    h.approver().release(id).map_err(de)?;
    let env = h.await_(id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    let meta = env.meta.clone().ok_or("no meta")?;
    assert!(
        meta.get("page").is_none(),
        "jira.issue.get is not paginated"
    );
    Ok(env.data.ok_or("no data")?["result"].clone())
}

/// The payloads of `id`'s records of type `t`.
async fn records(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

/// `fields.comment.comments` of a released issue.
fn comments_of(result: &Value) -> Result<&Vec<Value>, TestError> {
    result["fields"]["comment"]["comments"]
        .as_array()
        .ok_or_else(|| "no fields.comment.comments".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comments_flag_merges_comment_pages() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_issue(mock, KEY, &issue_body()).await;
    mount_comments(
        mock,
        KEY,
        &[
            comment_page(0, 50, 70, 50, false),
            comment_page(50, 50, 70, 20, false),
        ],
    )
    .await;
    let id = queued(
        &h,
        json!({ "key": KEY, "fields": ["summary", "comment"], "comments": true }),
    )
    .await?;
    let result = released(&h, &id).await?;
    let comments = comments_of(&result)?;
    assert_eq!(comments.len(), 70);
    assert_eq!(comments[0]["id"], "30000");
    assert_eq!(comments[69]["id"], "30069");
    assert_eq!(result["fields"]["comment"]["total"], 70);
    assert_eq!(result["fields"]["comment"]["startAt"], 0);
    assert_eq!(result["fields"]["summary"], "Composite read");
    assert_eq!(result["key"], KEY);

    // Exactly one issue GET, without `comment` in its `fields`, then the two pages in order.
    let issue_gets = gets_on(mock, &issue_path(KEY)).await;
    assert_eq!(issue_gets.len(), 1);
    assert_eq!(query(&issue_gets[0], "fields").as_deref(), Some("summary"));
    let pages = gets_on(mock, &comments_path(KEY)).await;
    let starts: Vec<Option<String>> = pages.iter().map(|r| query(r, "startAt")).collect();
    assert_eq!(starts, [Some("0".to_owned()), Some("50".to_owned())]);
    for p in &pages {
        assert_eq!(query(p, "maxResults").as_deref(), Some("50"));
        assert_eq!(query(p, "orderBy").as_deref(), Some("created"));
        assert_eq!(query(p, "expand"), None);
    }
    assert_eq!(test_hits(mock).await.len(), 3, "nothing else was sent");

    // One READ_FETCHED: page 0 the issue, then the comment pages.
    let fetched = records(&h, &id, EventType::READ_FETCHED).await?;
    let [f] = fetched.as_slice() else {
        return Err(format!("{} READ_FETCHED records", fetched.len()).into());
    };
    assert_eq!(f["pages"], 3);
    let first: Value = serde_json::from_str(
        f["responses"][0]["body"]["text"]
            .as_str()
            .ok_or("no issue body")?,
    )?;
    assert_eq!(first, issue_body());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comments_false_stays_one_get() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_issue(mock, KEY, &issue_body()).await;
    mount_comments(mock, KEY, &[comment_page(0, 50, 3, 3, false)]).await;
    let id = queued(&h, json!({ "key": KEY, "comments": false })).await?;
    let result = released(&h, &id).await?;
    assert_eq!(result, issue_body());
    assert!(gets_on(mock, &comments_path(KEY)).await.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comments_cap_and_truncated_info() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_issue(mock, KEY, &issue_body()).await;
    let pages: Vec<Value> = (0..5)
        .map(|n| comment_page(n * 50, 50, 250, 50, false))
        .collect();
    mount_comments(mock, KEY, &pages).await;
    let id = queued(&h, json!({ "key": KEY, "comments": true })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let info: Vec<_> = preview
        .warnings
        .iter()
        .filter(|w| w.id == WarningId::TruncatedByCap)
        .collect();
    let [w] = info.as_slice() else {
        return Err(format!("{} truncated_by_cap warnings", info.len()).into());
    };
    assert_eq!(w.level, Level::Info);
    assert_eq!(w.text, "result truncated by cap (100 of 250)");
    let result = released(&h, &id).await?;
    assert_eq!(comments_of(&result)?.len(), 100);
    assert_eq!(
        result["fields"]["comment"]["total"], 250,
        "the server total"
    );
    // Two pages of 50, never one page of 100 and never a third.
    let gets = gets_on(mock, &comments_path(KEY)).await;
    let asked: Vec<(Option<String>, Option<String>)> = gets
        .iter()
        .map(|r| (query(r, "startAt"), query(r, "maxResults")))
        .collect();
    assert_eq!(
        asked,
        [
            (Some("0".to_owned()), Some("50".to_owned())),
            (Some("50".to_owned()), Some("50".to_owned()))
        ]
    );

    // Δ7: a configured cap of 10 (Settings in M6; here the harness limits).
    let h = Harness::builder()
        .jira("jira-main")
        .limits(Limits {
            comments_cap: Some(10),
            ..Limits::default()
        })
        .start()
        .await?;
    let mock = jira(&h)?;
    mount_issue(mock, KEY, &issue_body()).await;
    mount_comments(mock, KEY, &[comment_page(0, 10, 250, 10, false)]).await;
    let id = queued(&h, json!({ "key": KEY, "comments": true })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(
        preview
            .warnings
            .iter()
            .any(|w| w.text == "result truncated by cap (10 of 250)"),
        "{:?}",
        preview.warnings
    );
    let result = released(&h, &id).await?;
    assert_eq!(comments_of(&result)?.len(), 10);
    let gets = gets_on(mock, &comments_path(KEY)).await;
    let [only] = gets.as_slice() else {
        return Err(format!("{} comment GETs", gets.len()).into());
    };
    assert_eq!(query(only, "maxResults").as_deref(), Some("10"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comments_within_cap_have_no_truncated_info() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_issue(mock, KEY, &issue_body()).await;
    mount_comments(
        mock,
        KEY,
        &[
            comment_page(0, 50, 100, 50, false),
            comment_page(50, 50, 100, 50, false),
        ],
    )
    .await;
    let id = queued(&h, json!({ "key": KEY, "comments": true })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(
        !preview
            .warnings
            .iter()
            .any(|w| w.id == WarningId::TruncatedByCap),
        "{:?}",
        preview.warnings
    );
    assert_eq!(comments_of(&released(&h, &id).await?)?.len(), 100);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comments_rendered_mirror_shape() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    let mut issue = issue_body();
    issue["renderedFields"] = json!({ "description": "<p>rendered</p>" });
    mount_issue(mock, KEY, &issue).await;
    mount_comments_rendered(
        mock,
        KEY,
        &[
            comment_page(0, 50, 60, 50, true),
            comment_page(50, 50, 60, 10, true),
        ],
    )
    .await;
    let id = queued(
        &h,
        json!({ "key": KEY, "comments": true, "rendered": true }),
    )
    .await?;
    let result = released(&h, &id).await?;
    let comments = comments_of(&result)?;
    assert_eq!(comments.len(), 60);
    let mirror = result["renderedFields"]["comment"]["comments"]
        .as_array()
        .ok_or("no renderedFields.comment.comments")?;
    assert_eq!(mirror.len(), 60);
    for (i, (c, m)) in comments.iter().zip(mirror).enumerate() {
        assert!(
            c.get("renderedBody").is_none(),
            "renderedBody on the field side"
        );
        assert_eq!(
            m,
            &json!({"id": c["id"], "body": format!("<p>comment <b>{i}</b></p>")})
        );
    }
    assert_eq!(result["renderedFields"]["description"], "<p>rendered</p>");
    // The issue GET asked for the rendered fields; every page for the rendered bodies.
    let issue_gets = gets_on(mock, &issue_path(KEY)).await;
    assert_eq!(
        issue_gets
            .first()
            .and_then(|r| query(r, "expand"))
            .as_deref(),
        Some("renderedFields")
    );
    for p in gets_on(mock, &comments_path(KEY)).await {
        assert_eq!(query(&p, "expand").as_deref(), Some("renderedBody"));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comments_merge_rebuild_hash_stable() -> TestResult {
    // A cache smaller than any candidate: every preview and the release rebuild from the record.
    let h = Harness::builder()
        .jira("jira-main")
        .limits(Limits {
            candidate_cache_bytes: MIB / 1024,
            ..Limits::default()
        })
        .start()
        .await?;
    let mock = jira(&h)?;
    let mut issue = issue_body();
    issue["renderedFields"] = json!({});
    mount_issue(mock, KEY, &issue).await;
    mount_comments_rendered(
        mock,
        KEY,
        &[
            comment_page(0, 50, 70, 50, true),
            comment_page(50, 50, 70, 20, true),
        ],
    )
    .await;
    let id = queued(
        &h,
        json!({ "key": KEY, "comments": true, "rendered": true }),
    )
    .await?;
    let rev = h.approver().item(&id).ok_or("not queued")?.candidate_rev;
    assert!(!h.engine().candidates().contains(&id));
    let hits = test_hits(mock).await.len();
    let first = h.approver().open(&id).map_err(de)?.preview;
    h.evict_candidate(&id);
    let again = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(
        test_hits(mock).await.len(),
        hits,
        "a rebuild makes no network call"
    );
    assert_eq!(first.candidate_rev.candidate_hash, rev.candidate_hash);
    assert_eq!(again.candidate_rev.candidate_hash, rev.candidate_hash);
    assert!(again.approvable, "the rebuilt candidate matches its hash");
    let result = released(&h, &id).await?;
    assert_eq!(comments_of(&result)?.len(), 70);
    assert_eq!(
        result["renderedFields"]["comment"]["comments"]
            .as_array()
            .map(Vec::len),
        Some(70)
    );
    assert_eq!(test_hits(mock).await.len(), hits);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comment_page_failure_is_gated() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_issue(mock, KEY, &issue_body()).await;
    mount_comments(mock, KEY, &[comment_page(0, 50, 70, 50, false)]).await;
    let redirect = mock
        .response(302)
        .insert_header("Location", "https://sso.corp.example/login")
        .set_body_raw("<html>moved</html>", "text/html");
    mount_comment_page_with(mock, KEY, 50, redirect).await;
    let id = queued(&h, json!({ "key": KEY, "comments": true })).await?;
    let types = h.event_types(&id).await?;
    assert!(!types.contains(&EventType::READ_FAILED), "{types:?}");
    let preview = h.approver().open(&id).map_err(de)?.preview;
    match preview.body {
        PreviewBody::Outcome { outcome, .. } => assert_eq!(outcome, OutcomeKind::LaterPageRefused),
        other => return Err(format!("not an outcome card: {other:?}").into()),
    }
    let fetched = records(&h, &id, EventType::READ_FETCHED).await?;
    let f = fetched.first().ok_or("no READ_FETCHED")?;
    assert_eq!(f["outcome"], "unparsable");
    assert_eq!(f["reason"], "redirect_3xx");
    // The issue, the first page and the 302 answer: every byte received is recorded.
    assert_eq!(f["pages"], 3);
    h.approver().release(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "upstream_unavailable");
    assert_eq!(env.data, None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue_failure_requests_no_comment_page() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.json(
        &issue_path(KEY),
        404,
        r#"{"errorMessages":["Issue Does Not Exist"],"errors":{}}"#,
    )
    .await;
    mount_comments(mock, KEY, &[comment_page(0, 50, 3, 3, false)]).await;
    let id = queued(&h, json!({ "key": KEY, "comments": true })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    match preview.body {
        PreviewBody::UpstreamError { status, .. } => assert_eq!(status, 404),
        other => return Err(format!("not an upstream-error card: {other:?}").into()),
    }
    assert!(gets_on(mock, &comments_path(KEY)).await.is_empty());
    let fetched = records(&h, &id, EventType::READ_FETCHED).await?;
    assert_eq!(fetched.first().map(|f| f["pages"].clone()), Some(json!(1)));

    // A status-decided issue answer is a direct failure, exactly as without `comments`.
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.redirect(&issue_path(KEY), "https://sso.corp.example/login")
        .await;
    mount_comments(mock, KEY, &[comment_page(0, 50, 3, 3, false)]).await;
    let env = h
        .submit(ISSUE, json!({ "key": KEY, "comments": true }))
        .await;
    let id = request_id(&env)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "upstream_unavailable");
    assert!(h.event_types(&id).await?.contains(&EventType::READ_FAILED));
    assert!(gets_on(mock, &comments_path(KEY)).await.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comments_share_one_read_budget() -> TestResult {
    // Issue and pages together get 1 s: each answer alone would fit, both do not.
    let h = Harness::builder()
        .jira("jira-main")
        .read_budget(ReadBudget {
            total: Duration::from_millis(1000),
            ..ReadBudget::default()
        })
        .start()
        .await?;
    let mock = jira(&h)?;
    let issue = mock
        .response(200)
        .set_body_raw(issue_body().to_string(), "application/json")
        .set_delay(Duration::from_millis(700));
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(mock.path(&issue_path(KEY))))
        .respond_with(issue)
        .mount(mock.server())
        .await;
    mount_comment_page_delayed(
        mock,
        KEY,
        &comment_page(0, 50, 3, 3, false),
        Duration::from_millis(700),
    )
    .await;
    let id = queued(&h, json!({ "key": KEY, "comments": true })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    match preview.body {
        PreviewBody::Outcome { outcome, .. } => assert_eq!(outcome, OutcomeKind::ReadBudget120),
        other => return Err(format!("not an outcome card: {other:?}").into()),
    }
    let fetched = records(&h, &id, EventType::READ_FETCHED).await?;
    let f = fetched.first().ok_or("no READ_FETCHED")?;
    assert_eq!(f["cap_or_budget"], "read_budget_120s");
    assert_eq!(f["pages"], 1, "the issue is recorded");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comments_share_one_fetch_cap() -> TestResult {
    // The issue takes most of the fetch cap; the first comment page (about 2.8 KB) fits the
    // whole cap but not what the issue left of it.
    let filler: String = "x".repeat(6000);
    let mut issue = issue_body();
    issue["fields"]["description"] = json!(filler);
    let page = comment_page(0, 50, 10, 10, false);
    assert!(page.to_string().len() > 2000);
    let cap = issue.to_string().len() as u64 + 2000;
    let h = Harness::builder()
        .jira("jira-main")
        .read_budget(ReadBudget {
            max_bytes: cap,
            ..ReadBudget::default()
        })
        .start()
        .await?;
    let mock = jira(&h)?;
    mount_issue(mock, KEY, &issue).await;
    mount_comments(mock, KEY, &[page]).await;
    let id = queued(&h, json!({ "key": KEY, "comments": true })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    match preview.body {
        PreviewBody::Outcome { outcome, .. } => assert_eq!(outcome, OutcomeKind::FetchCap50),
        other => return Err(format!("not an outcome card: {other:?}").into()),
    }
    let fetched = records(&h, &id, EventType::READ_FETCHED).await?;
    assert_eq!(
        fetched.first().map(|f| f["cap_or_budget"].clone()),
        Some(json!("fetch_cap_50mib"))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comments_cancel_records_the_issue_page() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_issue(mock, KEY, &issue_body()).await;
    mount_comment_page_delayed(
        mock,
        KEY,
        &comment_page(0, 50, 3, 3, false),
        Duration::from_secs(10),
    )
    .await;
    let env = h
        .submit(ISSUE, json!({ "key": KEY, "comments": true }))
        .await;
    let id = request_id(&env)?;
    // The comment page is in flight once the server saw it.
    for _ in 0..500 {
        if !gets_on(mock, &comments_path(KEY)).await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(gets_on(mock, &comments_path(KEY)).await.len(), 1);
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    let fetched = records(&h, &id, EventType::READ_FETCHED).await?;
    let [f] = fetched.as_slice() else {
        return Err(format!("{} READ_FETCHED records", fetched.len()).into());
    };
    assert_eq!(f["outcome"], "cancelled_in_flight");
    assert_eq!(f["pages"], 1, "the issue answer is in the record");
    let first: Value = serde_json::from_str(
        f["responses"][0]["body"]["text"]
            .as_str()
            .ok_or("no issue body")?,
    )?;
    assert_eq!(first, issue_body());
    Ok(())
}
