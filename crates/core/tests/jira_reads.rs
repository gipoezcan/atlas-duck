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
use atlas_duck_preview::{CommentView, FieldRow, IssueCard, OutcomeKind, Preview, PreviewBody};
use common::jira::{
    comment_page, comments_path, full_issue, gets_on, issue_path, mount_comment_page_delayed,
    mount_comment_page_with, mount_comments, mount_comments_rendered, mount_issue, mount_search,
    query, restriction, search_starts,
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

/// Review I-1 (A): the very first comment page answers 302. The issue is already page 0 of the
/// record, so this is a later-page failure: gated, never `READ_FAILED`, issue data not released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_comment_page_failure_is_gated() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_issue(mock, KEY, &issue_body()).await;
    let redirect = mock
        .response(302)
        .insert_header("Location", "https://sso.corp.example/login")
        .set_body_raw("<html>moved</html>", "text/html");
    mount_comment_page_with(mock, KEY, 0, redirect).await;
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
    assert_eq!(f["reason"], "redirect_3xx");
    // The issue as page 0, then the 302 answer.
    assert_eq!(f["pages"], 2);
    let first: Value = serde_json::from_str(
        f["responses"][0]["body"]["text"]
            .as_str()
            .ok_or("no issue body")?,
    )?;
    assert_eq!(first, issue_body());
    h.approver().release(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "upstream_unavailable");
    assert_eq!(env.data, None);
    Ok(())
}

/// Review I-1 (B), PD-45 as built: a comment page answering JSON 500 (page 2) or 404 (page 1) is
/// an `UpstreamError` item with that status, gated, never `READ_FAILED`; neither the issue nor
/// the earlier pages are released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comment_page_json_error_is_a_gated_upstream_error() -> TestResult {
    for (failing_start, status, pages) in [(50, 500, 3), (0, 404, 2)] {
        let h = Harness::jira().await?;
        let mock = jira(&h)?;
        mount_issue(mock, KEY, &issue_body()).await;
        if failing_start > 0 {
            mount_comments(mock, KEY, &[comment_page(0, 50, 70, 50, false)]).await;
        }
        let err = mock.response(status).set_body_raw(
            r#"{"errorMessages":["comment trouble"],"errors":{}}"#,
            "application/json",
        );
        mount_comment_page_with(mock, KEY, failing_start, err).await;
        let id = queued(&h, json!({ "key": KEY, "comments": true })).await?;
        let types = h.event_types(&id).await?;
        assert!(!types.contains(&EventType::READ_FAILED), "{types:?}");
        let preview = h.approver().open(&id).map_err(de)?.preview;
        match preview.body {
            PreviewBody::UpstreamError { status: s, .. } => assert_eq!(s, status),
            other => return Err(format!("not an upstream-error card: {other:?}").into()),
        }
        let fetched = records(&h, &id, EventType::READ_FETCHED).await?;
        let f = fetched.first().ok_or("no READ_FETCHED")?;
        assert_eq!(f["pages"], pages, "{status}");
        h.approver().release(&id).map_err(de)?;
        let env = h.await_(&id, 5000).await;
        assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
        assert_eq!(code(&env), "upstream_http");
        assert_eq!(env.data, None);
    }
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

// ---- Task 10: the Jira issue previewer (§6.2 levels, U-34; mirrors, U-27; S-12) -------------------

/// The `JiraIssue` body of a preview.
type IssueParts<'a> = (
    &'a IssueCard,
    &'a [FieldRow],
    Option<&'a str>,
    &'a [CommentView],
);

fn issue_parts(p: &Preview) -> Result<IssueParts<'_>, TestError> {
    match &p.body {
        PreviewBody::JiraIssue {
            card,
            fields,
            description_html,
            comments,
        } => Ok((
            card,
            fields.as_slice(),
            description_html.as_deref(),
            comments.as_slice(),
        )),
        other => Err(format!("not a Jira issue preview: {other:?}").into()),
    }
}

fn ids_at(p: &Preview, level: Level) -> Vec<WarningId> {
    p.warnings
        .iter()
        .filter(|w| w.level == level)
        .map(|w| w.id)
        .collect()
}

fn warning_text(p: &Preview, id: WarningId) -> Option<&str> {
    p.warnings
        .iter()
        .find(|w| w.id == id)
        .map(|w| w.text.as_str())
}

/// A comment page whose comment `n` (page 0, rendered) carries the role restriction.
fn restricted_page(count: u64, n: usize) -> Value {
    let mut page = comment_page(0, 50, count, count, true);
    page["comments"][n]["visibility"] = restriction();
    page
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u34_default_issue_get_zero_caution() -> TestResult {
    let h = Harness::jira().await?;
    mount_issue(jira(&h)?, KEY, &full_issue(KEY)).await;
    let id = queued(&h, json!({ "key": KEY })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(
        ids_at(&preview, Level::Caution),
        Vec::<WarningId>::new(),
        "{:?}",
        preview.warnings
    );
    assert_eq!(
        ids_at(&preview, Level::Info),
        [WarningId::LinkedIssueSummaries, WarningId::CustomFields]
    );
    // parent (1) + two issue links + no sub-tasks; one custom field.
    assert_eq!(
        warning_text(&preview, WarningId::LinkedIssueSummaries),
        Some("includes summary/status of 3 linked/parent/sub-task issues")
    );
    assert_eq!(
        warning_text(&preview, WarningId::CustomFields),
        Some("contains 1 custom fields")
    );
    let (card, fields, description, comments) = issue_parts(&preview)?;
    assert_eq!(card.key, KEY);
    assert_eq!(card.summary, "Login page times out");
    assert_eq!(card.issue_type, "Bug");
    assert_eq!(card.status, "In Progress");
    assert_eq!(card.priority.as_deref(), Some("High"));
    assert_eq!(card.assignee.as_deref(), Some("Jane Doe (jdoe)"));
    assert_eq!(card.reporter.as_deref(), Some("Alex Smith (asmith)"));
    assert!(description.is_some_and(|d| d.contains("login")));
    assert!(comments.is_empty());
    // Every released key of `fields` has a row, in id order.
    let ids: Vec<&str> = fields.iter().map(|f| f.id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
    for key in full_issue(KEY)["fields"]
        .as_object()
        .ok_or("no fields")?
        .keys()
    {
        assert!(ids.contains(&key.as_str()), "no row for {key}: {ids:?}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u34_security_level_exactly_one_caution() -> TestResult {
    let h = Harness::jira().await?;
    let mut issue = full_issue(KEY);
    issue["fields"]["security"] = json!({"id": "10000", "name": "Internal"});
    mount_issue(jira(&h)?, KEY, &issue).await;
    let id = queued(&h, json!({ "key": KEY })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(
        ids_at(&preview, Level::Caution),
        [WarningId::SecurityLevel],
        "{:?}",
        preview.warnings
    );
    assert_eq!(
        warning_text(&preview, WarningId::SecurityLevel),
        Some("issue has a security level")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u34_restricted_comment_caution_over_both_trees() -> TestResult {
    // fields side: a composite read with a restricted comment (mirror built from renderedBody).
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    let mut issue = full_issue(KEY);
    issue["renderedFields"] = json!({});
    mount_issue(mock, KEY, &issue).await;
    mount_comments_rendered(mock, KEY, &[restricted_page(3, 1)]).await;
    let id = queued(
        &h,
        json!({ "key": KEY, "comments": true, "rendered": true }),
    )
    .await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(
        ids_at(&preview, Level::Caution),
        [WarningId::RestrictedComments],
        "{:?}",
        preview.warnings
    );
    assert_eq!(
        warning_text(&preview, WarningId::RestrictedComments),
        Some("includes restricted-visibility comments")
    );
    let (_, _, _, comments) = issue_parts(&preview)?;
    let flags: Vec<bool> = comments.iter().map(|c| c.restricted).collect();
    assert_eq!(flags, [false, true, false]);
    assert_eq!(comments[1].id, "30001");
    assert_eq!(comments[1].author.as_deref(), Some("Jane Doe (jdoe)"));

    // No restriction anywhere: no Caution.
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    let mut issue = full_issue(KEY);
    issue["renderedFields"] = json!({});
    mount_issue(mock, KEY, &issue).await;
    mount_comments_rendered(mock, KEY, &[comment_page(0, 50, 2, 2, true)]).await;
    let id = queued(
        &h,
        json!({ "key": KEY, "comments": true, "rendered": true }),
    )
    .await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(ids_at(&preview, Level::Caution).is_empty());

    // Only the rendered mirror entry carries the marker: still a Caution (§6.2 "both trees").
    let h = Harness::jira().await?;
    let mut issue = full_issue(KEY);
    issue["fields"]["comment"] = json!({
        "total": 1, "startAt": 0, "maxResults": 50,
        "comments": [{"id": "7", "body": "plain", "author": {"name": "jdoe"}}]
    });
    issue["renderedFields"] = json!({
        "comment": {"comments": [{"id": "7", "body": "<p>plain</p>", "visibility": restriction()}]}
    });
    mount_issue(jira(&h)?, KEY, &issue).await;
    let id = queued(
        &h,
        json!({ "key": KEY, "fields": ["summary", "comment"], "rendered": true }),
    )
    .await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(
        ids_at(&preview, Level::Caution),
        [WarningId::RestrictedComments]
    );
    let (_, _, _, comments) = issue_parts(&preview)?;
    assert!(comments.iter().all(|c| c.restricted), "{comments:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u27_drop_restricted_comment_rendered_leaves_nothing() -> TestResult {
    use atlas_duck_core::RedactionOp;
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    let mut issue = full_issue(KEY);
    issue["renderedFields"] = json!({});
    mount_issue(mock, KEY, &issue).await;
    mount_comments_rendered(mock, KEY, &[restricted_page(3, 1)]).await;
    let id = queued(
        &h,
        json!({ "key": KEY, "comments": true, "rendered": true }),
    )
    .await?;
    let ap = h.approver();
    let before = ap.open(&id).map_err(de)?.preview;
    assert!(ids_at(&before, Level::Caution).contains(&WarningId::RestrictedComments));
    let ops = vec![RedactionOp::DropItem {
        array_path: "fields.comment.comments".into(),
        key: "id".into(),
        value: json!("30001"),
    }];
    // The redacted revision no longer has the Caution or the card.
    let rev = ap.redact(&id, ops.clone()).map_err(de)?;
    let shown = h.decisions().preview_fetch(&id, Some(rev)).map_err(de)?;
    assert!(
        ids_at(&shown.preview, Level::Caution).is_empty(),
        "{:?}",
        shown.preview.warnings
    );
    let (_, _, _, comments) = issue_parts(&shown.preview)?;
    let seen: Vec<&str> = comments.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(seen, ["30000", "30002"]);
    ap.release(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    let text = env.to_json_line();
    for gone in ["30001", "comment *1*", "<b>1</b>", "Administrators"] {
        assert!(!text.contains(gone), "{gone} survived: {text}");
    }
    assert!(text.contains("30000") && text.contains("30002"));
    let meta = env.meta.clone().ok_or("no meta")?;
    assert_eq!(meta["redactions"]["items_dropped"], 1, "{meta}");
    // The server total stays what the server said.
    let result = env.data.ok_or("no data")?["result"].clone();
    assert_eq!(result["fields"]["comment"]["total"], 3);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u27_per_item_field_drop_and_mask_reach_mirror() -> TestResult {
    use atlas_duck_core::{DropScope, RedactionOp};
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    let mut issue = full_issue(KEY);
    issue["renderedFields"] = json!({});
    mount_issue(mock, KEY, &issue).await;
    let mut page = comment_page(0, 50, 2, 2, true);
    page["comments"][0]["body"] = json!("the secretword here");
    page["comments"][0]["renderedBody"] = json!("<p>the secretword here</p>");
    mount_comments_rendered(mock, KEY, &[page]).await;
    let id = queued(
        &h,
        json!({ "key": KEY, "comments": true, "rendered": true }),
    )
    .await?;
    let ops = vec![
        RedactionOp::DropField {
            path: "fields.comment.comments[id=30001].body".into(),
            scope: DropScope::PerItem,
        },
        RedactionOp::MaskText {
            text: "secretword".into(),
            every_occurrence: false,
            at: Some("fields.comment.comments[0].body".into()),
        },
    ];
    h.approver().release_redacted(&id, ops).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    let text = env.to_json_line();
    for gone in ["secretword", "comment *1*", "<b>1</b>"] {
        assert!(!text.contains(gone), "{gone} survived: {text}");
    }
    let result = env.data.ok_or("no data")?["result"].clone();
    assert_eq!(
        result["fields"]["comment"]["comments"][0]["body"],
        "the [REDACTED] here"
    );
    assert_eq!(
        result["renderedFields"]["comment"]["comments"][0]["body"],
        "<p>the [REDACTED] here</p>"
    );
    assert!(result["fields"]["comment"]["comments"][1]["body"].is_null());
    assert!(result["renderedFields"]["comment"]["comments"][1]["body"].is_null());
    assert_eq!(
        result["renderedFields"]["comment"]["comments"][1]["id"],
        "30001"
    );
    Ok(())
}

/// An issue whose rendered mirror holds comment 9, which `fields.comment.comments` lacks (§5.3
/// "a mirror entry … which has no counterpart at all").
fn orphan_issue() -> Value {
    let mut issue = full_issue(KEY);
    issue["fields"]["comment"] = json!({
        "total": 1, "startAt": 0, "maxResults": 50,
        "comments": [{"id": "7", "body": "plain"}]
    });
    issue["renderedFields"] = json!({
        "comment": {"comments": [
            {"id": "7", "body": "<p>plain</p>"},
            {"id": "9", "body": "<p>orphan</p>", "visibility": restriction()}
        ]}
    });
    issue
}

/// A plain release of `id` is refused as not approvable: `DECISION_INVALID {not_approvable}`,
/// nothing released.
async fn plain_release_refused(h: &Harness, id: &str) -> TestResult {
    use atlas_duck_core::DecisionError;
    use atlas_duck_core::payloads::InvalidReason;
    let res = h.approver().release(id);
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    let invalid = records(h, id, EventType::DECISION_INVALID).await?;
    assert_eq!(
        invalid.first().map(|r| r["reason"].clone()),
        Some(json!("not_approvable"))
    );
    assert!(
        records(h, id, EventType::READ_RELEASED).await?.is_empty(),
        "nothing was released"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u27_mirror_without_counterpart_blocks_release() -> TestResult {
    use atlas_duck_core::DecisionError;
    use atlas_duck_core::payloads::InvalidReason;
    let h = Harness::jira().await?;
    mount_issue(jira(&h)?, KEY, &orphan_issue()).await;
    let id = queued(
        &h,
        json!({ "key": KEY, "fields": ["summary", "comment"], "rendered": true }),
    )
    .await?;
    // The mirror check runs on the unredacted candidate too (§5.3, §5.1 inv. 6): the preview is
    // not approvable and a plain release is refused.
    let ap = h.approver();
    let preview = ap.open(&id).map_err(de)?.preview;
    assert!(!preview.approvable, "an orphan mirror entry is approvable");
    plain_release_refused(&h, &id).await?;
    // A redaction that leaves the orphan in place is refused as well (`apply`'s own check).
    let res = ap.redact(
        &id,
        vec![atlas_duck_core::RedactionOp::DropItem {
            array_path: "fields.comment.comments".into(),
            key: "id".into(),
            value: json!("7"),
        }],
    );
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    assert!(records(&h, &id, EventType::READ_RELEASED).await?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u27_dropping_the_orphan_unblocks_and_undo_is_refused() -> TestResult {
    use atlas_duck_core::payloads::InvalidReason;
    use atlas_duck_core::{DecisionError, RedactionOp};
    let h = Harness::jira().await?;
    mount_issue(jira(&h)?, KEY, &orphan_issue()).await;
    let id = queued(
        &h,
        json!({ "key": KEY, "fields": ["summary", "comment"], "rendered": true }),
    )
    .await?;
    let ap = h.approver();
    ap.open(&id).map_err(de)?;
    // Dropping the orphan entry itself passes the check: a new, approvable revision.
    let rev = ap
        .redact(
            &id,
            vec![RedactionOp::DropItem {
                array_path: "renderedFields.comment.comments".into(),
                key: "id".into(),
                value: json!("9"),
            }],
        )
        .map_err(de)?;
    let shown = h.decisions().preview_fetch(&id, Some(rev)).map_err(de)?;
    assert!(shown.preview.approvable);
    // Undoing every redaction (back to no ops) rebuilds the orphan candidate: refused, and the
    // redacted revision stays current.
    let res = ap.redact(&id, Vec::new());
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    assert!(records(&h, &id, EventType::READ_RELEASED).await?.is_empty());
    ap.release(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    let text = env.to_json_line();
    assert!(!text.contains("orphan"), "{text}");
    assert!(!text.contains("Administrators"), "{text}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u27_search_orphan_mirror_blocks_release() -> TestResult {
    let h = Harness::jira().await?;
    let mut issue = orphan_issue();
    issue["fields"] = json!({
        "summary": "found",
        "comment": orphan_issue()["fields"]["comment"].clone()
    });
    let page = json!({"startAt": 0, "maxResults": 50, "total": 1, "issues": [issue]});
    jira(&h)?
        .json("/rest/api/2/search", 200, &page.to_string())
        .await;
    let env = h
        .submit("jira.search", json!({ "jql": "project = ABC" }))
        .await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(!preview.approvable, "an orphan mirror entry is approvable");
    plain_release_refused(&h, &id).await
}

/// M5 M-11: a first build the §5.3 mirror check refuses fails the item closed, and its preview
/// carries the `internal` banner (Release disabled); a clean candidate and a redacted revision
/// that passes the check carry none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m11_first_build_internal_banner() -> TestResult {
    use atlas_duck_core::{RELEASE_BLOCKED_INTERNAL, RedactionOp};
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_issue(mock, KEY, &orphan_issue()).await;
    mount_issue(mock, "ABC-8", &full_issue("ABC-8")).await;
    let params = json!({ "key": KEY, "fields": ["summary", "comment"], "rendered": true });
    let id = queued(&h, params).await?;
    let ap = h.approver();
    let preview = ap.open(&id).map_err(de)?.preview;
    assert!(!preview.approvable);
    assert_eq!(
        preview.header.release_blocked,
        Some(RELEASE_BLOCKED_INTERNAL)
    );
    assert_eq!(
        RELEASE_BLOCKED_INTERNAL,
        "release blocked: the candidate could not be built exactly (internal); deny it, or drop \
         the flagged items"
    );
    assert!(!ap.item(&id).ok_or("not queued")?.approvable);
    // Dropping the orphan gives a revision that passes: no banner.
    let rev = ap
        .redact(
            &id,
            vec![RedactionOp::DropItem {
                array_path: "renderedFields.comment.comments".into(),
                key: "id".into(),
                value: json!("9"),
            }],
        )
        .map_err(de)?;
    let shown = h.decisions().preview_fetch(&id, Some(rev)).map_err(de)?;
    assert!(shown.preview.approvable);
    assert_eq!(shown.preview.header.release_blocked, None);
    // A clean issue has none from the start.
    let clean = queued(&h, json!({ "key": "ABC-8" })).await?;
    let preview = ap.open(&clean).map_err(de)?.preview;
    assert!(preview.approvable);
    assert_eq!(preview.header.release_blocked, None);
    Ok(())
}

/// M5 M-11: a rebuild after eviction that the mirror check refuses (`Blocked`) keeps the item
/// failed closed: no preview, nothing logged for the refusal, the release refused as
/// `not_approvable`, Deny still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m11_rebuild_after_eviction_blocked() -> TestResult {
    use atlas_duck_core::DecisionError;
    use atlas_duck_core::payloads::InvalidReason;
    let h = Harness::jira().await?;
    mount_issue(jira(&h)?, KEY, &orphan_issue()).await;
    let id = queued(
        &h,
        json!({ "key": KEY, "fields": ["summary", "comment"], "rendered": true }),
    )
    .await?;
    let ap = h.approver();
    ap.open(&id).map_err(de)?;
    h.evict_candidate(&id);
    let count = h.event_count().await?;
    let res = ap.open(&id);
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    assert_eq!(
        h.event_count().await?,
        count,
        "the refused open logs nothing"
    );
    assert!(!h.engine().candidates().contains(&id), "nothing cached");
    let item = ap.item(&id).ok_or("not queued")?;
    assert!(!item.approvable);
    let res = ap.release_unopened(&id);
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
    assert!(records(&h, &id, EventType::READ_RELEASED).await?.is_empty());
    ap.deny_unopened(&id, "cannot be released").map_err(de)?;
    assert_eq!(h.await_(&id, 5000).await.status, Status::Denied);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s12_issue_preview_marks_invisible() -> TestResult {
    let h = Harness::jira().await?;
    let mut issue = full_issue(KEY);
    issue["fields"]["description"] = json!(
        "evil \u{202e}text\n\n!https://evil.example/x.png!\n\n[click|https://evil.example/p]"
    );
    mount_issue(jira(&h)?, KEY, &issue).await;
    let id = queued(&h, json!({ "key": KEY })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(preview.header.bidi_controls, 1);
    assert!(ids_at(&preview, Level::Caution).contains(&WarningId::BidiControls));
    let (_, _, description, _) = issue_parts(&preview)?;
    let html = description.ok_or("no description_html")?;
    for resource in [
        "<img", "src=", "href=", "srcset", "<a ", "<script", "<iframe",
    ] {
        assert!(!html.contains(resource), "{resource} in {html}");
    }
    // The bidi control is visible as an escape, not a live character.
    assert!(html.contains("\u{27e8}U+202E\u{27e9}"), "{html}");
    assert!(!html.contains('\u{202e}'));
    Ok(())
}

/// Builds the previewer's context by hand (no harness): a read of `candidate`.
fn preview_of(
    candidate: &Value,
    params: &Value,
    names: Option<&atlas_duck_core::metadata::FieldNames>,
) -> Result<atlas_duck_core::ops::PreviewModel, TestError> {
    use atlas_duck_core::ops::{PreviewCtx, PreviewInput, ReadView, jira_preview};
    let spec = atlas_duck_registry::get(ISSUE).ok_or("no jira.issue.get")?;
    Ok(jira_preview::issue_preview(&PreviewCtx {
        spec,
        instance_alias: "jira-main",
        params,
        input: PreviewInput::Read(ReadView {
            candidate,
            byte_size: u64::try_from(candidate.to_string().len())?,
            server_total: None,
            more_available: false,
            clamped: false,
            comments_truncated: None,
        }),
        field_names: names,
    }))
}

#[test]
fn field_table_names_custom_fields_and_flags_unknown() -> TestResult {
    use atlas_duck_core::metadata::FieldNames;
    let names = FieldNames::from(std::collections::BTreeMap::from([
        ("customfield_10200".to_owned(), "Team".to_owned()),
        ("summary".to_owned(), "Summary".to_owned()),
    ]));
    let mut issue = full_issue(KEY);
    issue["fields"]["customfield_99999"] = json!("x");
    issue["renderedFields"] = json!({"description": "<p>rendered</p>"});
    let params = json!({ "key": KEY, "rendered": true });
    let model = preview_of(&issue, &params, Some(&names))?;
    let PreviewBody::JiraIssue { fields, .. } = &model.body else {
        return Err("not a Jira issue body".into());
    };
    let name_of = |id: &str| fields.iter().find(|f| f.id == id).map(|f| f.name.as_str());
    assert_eq!(name_of("customfield_10200"), Some("Team"));
    assert_eq!(
        name_of("customfield_99999"),
        Some("customfield_99999 (unknown field)")
    );
    // System ids without a cached name use the built-in §7.3 names.
    assert_eq!(name_of("status"), Some("Status"));
    assert_eq!(name_of("issuetype"), Some("Issue Type"));
    // The value is the compact JSON, or the string itself.
    let value_of = |id: &str| {
        fields
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.value_text.as_str())
    };
    assert_eq!(
        value_of("customfield_10200"),
        Some(r#"{"value":"Platform"}"#)
    );
    assert_eq!(value_of("customfield_99999"), Some("x"));
    // The server-rendered mirror is a row too, marked.
    let rendered = fields
        .iter()
        .find(|f| f.id == "renderedFields.description")
        .ok_or("no renderedFields row")?;
    assert!(
        rendered.name.ends_with("(server-rendered)"),
        "{}",
        rendered.name
    );

    // Names never change the warnings (T8 handoff): same warnings with and without the map.
    let bare = preview_of(&issue, &params, None)?;
    let warnings = |m: &atlas_duck_core::ops::PreviewModel| -> Vec<(WarningId, String)> {
        m.warnings.iter().map(|w| (w.id, w.text.clone())).collect()
    };
    assert_eq!(warnings(&model), warnings(&bare));
    let PreviewBody::JiraIssue {
        fields: bare_rows, ..
    } = &bare.body
    else {
        return Err("not a Jira issue body".into());
    };
    let bare_name = |id: &str| {
        bare_rows
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.name.as_str())
    };
    assert_eq!(
        bare_name("customfield_10200"),
        Some("customfield_10200 (unknown field)")
    );
    Ok(())
}

#[test]
fn field_labels_are_escaped_one_line_text() -> TestResult {
    use atlas_duck_core::metadata::FieldNames;
    let names = FieldNames::from(std::collections::BTreeMap::from([(
        "customfield_10200".to_owned(),
        "Te\u{202e}am\nTwo".to_owned(),
    )]));
    let model = preview_of(&full_issue(KEY), &json!({ "key": KEY }), Some(&names))?;
    let PreviewBody::JiraIssue { fields, .. } = &model.body else {
        return Err("not a Jira issue body".into());
    };
    let row = fields
        .iter()
        .find(|f| f.id == "customfield_10200")
        .ok_or("no row")?;
    assert_eq!(
        row.name,
        "Te\u{27e8}U+202E\u{27e9}am\u{27e8}U+000A\u{27e9}Two"
    );
    // The classifier counts come from the candidate, not from names.
    assert_eq!(model.header.bidi_controls, 0);
    Ok(())
}

#[test]
fn long_values_are_cut_and_counted_as_hidden() -> TestResult {
    let mut issue = full_issue(KEY);
    issue["fields"]["customfield_10200"] = json!("x".repeat(10_000));
    let model = preview_of(&issue, &json!({ "key": KEY }), None)?;
    let PreviewBody::JiraIssue { fields, .. } = &model.body else {
        return Err("not a Jira issue body".into());
    };
    let row = fields
        .iter()
        .find(|f| f.id == "customfield_10200")
        .ok_or("no row")?;
    assert!(row.value_text.len() < 5_000, "{}", row.value_text.len());
    assert!(row.value_text.ends_with("(see Raw)"), "{}", row.value_text);
    assert_eq!(model.header.hidden_in_preview_bytes, 10_000 - 4096);
    Ok(())
}

/// The rows of a `JiraIssue` preview model.
fn rows_of(model: &atlas_duck_core::ops::PreviewModel) -> Result<&[FieldRow], TestError> {
    match &model.body {
        PreviewBody::JiraIssue { fields, .. } => Ok(fields),
        _ => Err("not a Jira issue body".into()),
    }
}

#[test]
fn top_level_keys_have_rows_and_count_as_hidden() -> TestResult {
    // §6.1 principle 3: a `changelog` (old values of any field) is shown or counted as hidden.
    let mut issue = full_issue(KEY);
    let old = "<old secret text>".repeat(500);
    issue["changelog"] = json!({"histories": [{"items": [
        {"field": "description", "fromString": old, "toString": "new"}
    ]}]});
    issue["names"] = json!({"summary": "Summary"});
    let params = json!({ "key": KEY, "changelog": true });
    let model = preview_of(&issue, &params, None)?;
    let rows = rows_of(&model)?;
    let changelog = rows
        .iter()
        .find(|r| r.id == "changelog")
        .ok_or("no changelog row")?;
    assert_eq!(changelog.name, "Change history (outside fields)");
    assert!(changelog.value_text.contains("<old secret text>"));
    assert!(changelog.value_text.ends_with("(see Raw)"));
    let names = rows
        .iter()
        .find(|r| r.id == "names")
        .ok_or("no names row")?;
    assert_eq!(names.value_text, r#"{"summary":"Summary"}"#);
    let full = issue["changelog"].to_string().len();
    assert_eq!(
        model.header.hidden_in_preview_bytes,
        u64::try_from(full - 4096)?
    );
    // `key`, `id`, `self` and `expand` have no row (the card shows the key).
    for skipped in ["key", "id", "self", "expand"] {
        assert!(rows.iter().all(|r| r.id != skipped), "{skipped} has a row");
    }
    Ok(())
}

#[test]
fn description_is_not_counted_twice() -> TestResult {
    // The `description` row points at the rendered description; only that one is cut.
    let mut issue = full_issue(KEY);
    issue["fields"]["description"] = json!("d".repeat(10_000));
    let model = preview_of(&issue, &json!({ "key": KEY }), None)?;
    assert_eq!(model.header.hidden_in_preview_bytes, 0);
    let row = rows_of(&model)?
        .iter()
        .find(|r| r.id == "description")
        .ok_or("no description row")?;
    assert_eq!(row.value_text, "rendered below");
    Ok(())
}

#[test]
fn server_rendered_comment_row_names_where_the_bodies_are() -> TestResult {
    let mut issue = full_issue(KEY);
    issue["fields"]["comment"] = json!({"comments": [{"id": "7", "body": "plain"}]});
    issue["renderedFields"] = json!({"comment": {"comments": [{"id": "7", "body": "<p>x</p>"}]}});
    let model = preview_of(&issue, &json!({ "key": KEY, "rendered": true }), None)?;
    let rows = rows_of(&model)?;
    let value = |id: &str| {
        rows.iter()
            .find(|r| r.id == id)
            .map(|r| r.value_text.as_str())
    };
    assert_eq!(value("comment"), Some("1 comments, shown below"));
    assert_eq!(
        value("renderedFields.comment"),
        Some("1 server-rendered comments (bodies in Raw; the cards below show the wiki source)")
    );
    Ok(())
}

#[test]
fn cached_name_wins_over_the_built_in_name() -> TestResult {
    use atlas_duck_core::metadata::FieldNames;
    let names = FieldNames::from(std::collections::BTreeMap::from([(
        "status".to_owned(),
        "Workflow State".to_owned(),
    )]));
    let model = preview_of(&full_issue(KEY), &json!({ "key": KEY }), Some(&names))?;
    let row = rows_of(&model)?
        .iter()
        .find(|r| r.id == "status")
        .ok_or("no status row")?;
    assert_eq!(row.name, "Workflow State");
    Ok(())
}

#[test]
fn description_and_comment_caps_cut_and_count() -> TestResult {
    let mut issue = full_issue(KEY);
    issue["fields"]["description"] = json!("a".repeat(64 * 1024 + 100));
    issue["fields"]["comment"] = json!({"comments": [
        {"id": "7", "body": "b".repeat(16 * 1024 + 50)}
    ]});
    let model = preview_of(&issue, &json!({ "key": KEY }), None)?;
    let PreviewBody::JiraIssue {
        description_html,
        comments,
        ..
    } = &model.body
    else {
        return Err("not a Jira issue body".into());
    };
    let description = description_html.as_deref().ok_or("no description_html")?;
    assert!(
        description.contains("… 100 more bytes (see Raw)"),
        "{}",
        &description[description.len().saturating_sub(200)..]
    );
    let body = &comments.first().ok_or("no comment")?.body_html;
    assert!(body.contains("… 50 more bytes (see Raw)"));
    assert_eq!(model.header.hidden_in_preview_bytes, 150);
    Ok(())
}

#[test]
fn cut_never_splits_a_multi_byte_char() -> TestResult {
    let mut issue = full_issue(KEY);
    issue["fields"]["customfield_10200"] = json!(format!("{}é", "a".repeat(4095)));
    let model = preview_of(&issue, &json!({ "key": KEY }), None)?;
    let row = rows_of(&model)?
        .iter()
        .find(|r| r.id == "customfield_10200")
        .ok_or("no row")?;
    assert_eq!(
        row.value_text,
        format!("{}… 2 more bytes (see Raw)", "a".repeat(4095))
    );
    assert_eq!(model.header.hidden_in_preview_bytes, 2);
    // A description cut inside a multi-byte char keeps the whole char out.
    let mut issue = full_issue(KEY);
    issue["fields"]["description"] = json!(format!("{}é", "a".repeat(64 * 1024 - 1)));
    let model = preview_of(&issue, &json!({ "key": KEY }), None)?;
    assert_eq!(model.header.hidden_in_preview_bytes, 2);
    Ok(())
}

#[test]
fn field_row_ids_are_one_line() -> TestResult {
    let mut issue = full_issue(KEY);
    issue["fields"]["odd\nid"] = json!("x");
    issue["renderedFields"] = json!({"odd\nid": "y"});
    let model = preview_of(&issue, &json!({ "key": KEY, "rendered": true }), None)?;
    let ids: Vec<&str> = rows_of(&model)?.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"odd\u{27e8}U+000A\u{27e9}id"), "{ids:?}");
    assert!(
        ids.contains(&"renderedFields.odd\u{27e8}U+000A\u{27e9}id"),
        "{ids:?}"
    );
    assert!(ids.iter().all(|i| !i.contains('\n')));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comment_page_failure_card_names_the_comments_endpoint() -> TestResult {
    const NOTE: &str = "the failing request was the issue's comment list, not the issue itself";
    // A comment page failing: the card says so; an issue failure (404 on the issue) does not.
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_issue(mock, KEY, &issue_body()).await;
    let err = mock.response(404).set_body_raw(
        r#"{"errorMessages":["Issue Does Not Exist"],"errors":{}}"#,
        "application/json",
    );
    mount_comment_page_with(mock, KEY, 0, err).await;
    let id = queued(&h, json!({ "key": KEY, "comments": true })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let PreviewBody::UpstreamError {
        error_messages_text,
        ..
    } = &preview.body
    else {
        return Err(format!("{:?}", preview.body).into());
    };
    assert!(error_messages_text.contains(NOTE), "{error_messages_text}");
    assert!(error_messages_text.contains("Issue Does Not Exist"));

    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.json(
        &issue_path(KEY),
        404,
        r#"{"errorMessages":["Issue Does Not Exist"],"errors":{}}"#,
    )
    .await;
    let id = queued(&h, json!({ "key": KEY, "comments": true })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let PreviewBody::UpstreamError {
        error_messages_text,
        ..
    } = &preview.body
    else {
        return Err(format!("{:?}", preview.body).into());
    };
    assert!(!error_messages_text.contains(NOTE), "{error_messages_text}");
    Ok(())
}

// ---- Task 11: search and list previews, `meta.page` (I-22) ----------------------------------------

const SEARCH: &str = "jira.search";

/// The released envelope's `meta` and `data.result` after `ops` redacted the read (none: a plain
/// release).
async fn release_with(
    h: &Harness,
    id: &str,
    ops: Vec<atlas_duck_core::RedactionOp>,
) -> Result<(Value, Value), TestError> {
    if ops.is_empty() {
        h.approver().release(id).map_err(de)?;
    } else {
        h.approver().release_redacted(id, ops).map_err(de)?;
    }
    let env = h.await_(id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    let meta = env.meta.clone().ok_or("no meta")?;
    Ok((meta, env.data.ok_or("no data")?["result"].clone()))
}

async fn queued_op(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    Ok(id)
}

fn drop_issue(key: &str) -> atlas_duck_core::RedactionOp {
    atlas_duck_core::RedactionOp::DropItem {
        array_path: "issues".into(),
        key: "key".into(),
        value: json!(key),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i22_jira_drops_keep_totals_and_next_start() -> TestResult {
    let h = Harness::jira().await?;
    mount_search(
        jira(&h)?,
        25,
        |n| json!({ "summary": format!("Issue {n}") }),
    )
    .await;
    let id = queued_op(&h, SEARCH, json!({ "jql": "project = ABC", "max": 10 })).await?;
    let (meta, result) =
        release_with(&h, &id, vec![drop_issue("ABC-3"), drop_issue("ABC-4")]).await?;
    // §7.5: the page is what the server answered; the drops only lower `returned`.
    assert_eq!(
        meta["page"],
        json!({ "start": 0, "returned": 8, "total": 25, "truncated": true, "next_start": 10 })
    );
    assert_eq!(meta["redactions"]["items_dropped"], 2);
    assert_eq!(result["total"], 25);
    assert_eq!(result["issues"].as_array().map(Vec::len), Some(8));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i22_next_start_loop_rerequests_no_dropped_item() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_search(mock, 25, |n| json!({ "summary": format!("Issue {n}") })).await;
    let mut next = Some(0u64);
    let mut dropped: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    while let Some(start) = next {
        let id = queued_op(
            &h,
            SEARCH,
            json!({ "jql": "project = ABC", "max": 10, "start": start }),
        )
        .await?;
        // Every page drops its first two issues.
        let first = |n: u64| format!("ABC-{}", start + n + 1);
        dropped.extend([first(0), first(1)]);
        let ops = vec![drop_issue(&first(0)), drop_issue(&first(1))];
        let (meta, result) = release_with(&h, &id, ops).await?;
        let keys = result["issues"]
            .as_array()
            .ok_or("no issues")?
            .iter()
            .filter_map(|i| i["key"].as_str().map(str::to_owned));
        seen.extend(keys);
        next = meta["page"]["next_start"].as_u64();
        assert_eq!(meta["page"]["start"], start);
    }
    // The agent followed `next_start` only: it never asked for a range holding a dropped item.
    assert_eq!(search_starts(mock).await, [0, 10, 20]);
    assert!(
        seen.iter().all(|k| !dropped.contains(k)),
        "a dropped issue came back: {seen:?}"
    );
    assert_eq!(seen.len(), 25 - 6);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i22_agile_islast_and_short_page() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    // No `total`, `isLast` on a short page.
    mock.json(
        "/rest/agile/1.0/board",
        200,
        r#"{"maxResults":50,"startAt":0,"isLast":true,"values":[
            {"id":1,"name":"A","type":"scrum"},{"id":2,"name":"B","type":"kanban"}]}"#,
    )
    .await;
    mock.json(
        "/rest/agile/1.0/sprint/5/issue",
        200,
        r#"{"maxResults":50,"startAt":0,"total":2,"isLast":true,"issues":[
            {"id":"1","key":"ABC-1","fields":{"summary":"a"}},
            {"id":"2","key":"ABC-2","fields":{"summary":"b"}}]}"#,
    )
    .await;
    for (op, params, returned, total) in [
        ("jira.board.list", json!({ "max": 50 }), 2, Value::Null),
        (
            "jira.sprint.issues",
            json!({ "id": 5, "max": 50 }),
            2,
            json!(2),
        ),
    ] {
        let id = queued_op(&h, op, params).await?;
        let (meta, _) = release_with(&h, &id, Vec::new()).await?;
        assert_eq!(
            meta["page"],
            json!({
                "start": 0, "returned": returned, "total": total,
                "truncated": false, "next_start": null
            }),
            "{op}"
        );
    }
    Ok(())
}

type Table<'a> = (
    &'a [String],
    &'a [Vec<String>],
    Option<atlas_duck_preview::ItemCount>,
);

fn table_of(body: &PreviewBody) -> Result<Table<'_>, TestError> {
    match body {
        PreviewBody::Table {
            columns,
            rows,
            count,
        } => Ok((columns.as_slice(), rows.as_slice(), *count)),
        other => Err(format!("not a table: {other:?}").into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn search_table_columns_and_count() -> TestResult {
    let h = Harness::jira().await?;
    mount_search(
        jira(&h)?,
        25,
        |n| json!({ "summary": format!("Issue {n}"), "status": {"name": "Open"}, "labels": ["a"] }),
    )
    .await;
    let id = queued_op(
        &h,
        SEARCH,
        json!({ "jql": "project = ABC", "fields": ["status", "summary"], "max": 10 }),
    )
    .await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let (columns, rows, count) = table_of(&preview.body)?;
    // `key`, then the requested fields in the requested order.
    assert_eq!(columns, ["Key", "Status", "Summary"]);
    assert_eq!(rows.len(), 10);
    assert_eq!(rows[0], ["ABC-1", r#"{"name":"Open"}"#, "Issue 0"]);
    assert_eq!(rows[9][0], "ABC-10");
    assert_eq!(
        count,
        Some(atlas_duck_preview::ItemCount {
            shown: 10,
            total: Some(25),
            more_available: true
        })
    );
    assert_eq!(preview.header.item_count, count);
    // `labels` was not requested: the server's extra field is not in the table and is counted.
    assert!(preview.header.hidden_in_preview_bytes > 0);
    assert_eq!(preview.header.query.as_deref(), Some("project = ABC"));

    // No `fields`: the registry's default fields.
    let id = queued_op(&h, SEARCH, json!({ "jql": "project = ABC", "max": 3 })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let (columns, rows, _) = table_of(&preview.body)?;
    assert_eq!(columns.first().map(String::as_str), Some("Key"));
    assert_eq!(columns.get(1).map(String::as_str), Some("Summary"));
    assert_eq!(columns.get(2).map(String::as_str), Some("Status"));
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r.len() == columns.len()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_preview_tables() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.json(
        "/rest/api/2/issueLinkType",
        200,
        r#"{"issueLinkTypes":[
            {"id":"10000","name":"Blocks","inward":"is blocked by","outward":"blocks"},
            {"id":"10001","name":"Relates","inward":"relates to","outward":"relates to"}]}"#,
    )
    .await;
    mock.json(
        "/rest/api/2/issue/ABC-1/transitions",
        200,
        r#"{"expand":"transitions","transitions":[
            {"id":"11","name":"Start","hasScreen":false,"to":{"id":"3","name":"In Progress"}}]}"#,
    )
    .await;
    mock.json(
        "/rest/api/2/user/assignable/search",
        200,
        r#"[{"name":"jdoe","key":"JIRAUSER1","displayName":"Jane Doe","active":true}]"#,
    )
    .await;
    mock.json(
        "/rest/api/2/myself",
        200,
        r#"{"name":"jdoe","key":"JIRAUSER1","displayName":"Jane Doe"}"#,
    )
    .await;

    let id = queued_op(&h, "jira.issuelinktype.list", json!({})).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let (columns, rows, count) = table_of(&preview.body)?;
    assert_eq!(columns, ["id", "name", "inward", "outward"]);
    assert_eq!(rows[0], ["10000", "Blocks", "is blocked by", "blocks"]);
    assert_eq!(rows.len(), 2);
    assert_eq!(count.map(|c| c.shown), Some(2));

    let id = queued_op(&h, "jira.transition.list", json!({ "key": "ABC-1" })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let (columns, rows, _) = table_of(&preview.body)?;
    // The nested `to` object is not a scalar: it is no column and is counted as hidden.
    assert_eq!(columns, ["id", "name", "hasScreen"]);
    assert_eq!(rows[0], ["11", "Start", "false"]);
    assert!(preview.header.hidden_in_preview_bytes > 0);

    let id = queued_op(
        &h,
        "jira.user.assignable",
        json!({ "username": "jdoe", "issueKey": "ABC-1" }),
    )
    .await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let (columns, rows, _) = table_of(&preview.body)?;
    // The identifying keys first (id, key, name, displayName), then the rest.
    assert_eq!(columns, ["key", "name", "displayName", "active"]);
    assert_eq!(rows[0], ["JIRAUSER1", "jdoe", "Jane Doe", "true"]);

    // A single object stays the JSON tree.
    let id = queued_op(&h, "jira.myself", json!({})).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(
        matches!(preview.body, PreviewBody::JsonTree { .. }),
        "{:?}",
        preview.body
    );
    Ok(())
}

// -- the previewers on hand-built candidates --

type PreviewerFn = fn(&atlas_duck_core::ops::PreviewCtx<'_>) -> atlas_duck_core::ops::PreviewModel;

fn read_preview(
    op: &str,
    previewer: PreviewerFn,
    candidate: &Value,
    params: &Value,
    names: Option<&atlas_duck_core::metadata::FieldNames>,
) -> Result<atlas_duck_core::ops::PreviewModel, TestError> {
    use atlas_duck_core::ops::{PreviewCtx, PreviewInput, ReadView};
    let spec = atlas_duck_registry::get(op).ok_or("unknown op")?;
    Ok(previewer(&PreviewCtx {
        spec,
        instance_alias: "jira-main",
        params,
        input: PreviewInput::Read(ReadView {
            candidate,
            byte_size: u64::try_from(candidate.to_string().len())?,
            server_total: candidate.get("total").and_then(Value::as_u64),
            more_available: false,
            clamped: false,
            comments_truncated: None,
        }),
        field_names: names,
    }))
}

fn search_model(
    candidate: &Value,
    params: &Value,
    names: Option<&atlas_duck_core::metadata::FieldNames>,
) -> Result<atlas_duck_core::ops::PreviewModel, TestError> {
    read_preview(
        SEARCH,
        atlas_duck_core::ops::jira_preview::search_preview,
        candidate,
        params,
        names,
    )
}

fn list_model(
    op: &str,
    candidate: &Value,
) -> Result<atlas_duck_core::ops::PreviewModel, TestError> {
    read_preview(
        op,
        atlas_duck_core::ops::jira_preview::list_preview,
        candidate,
        &json!({}),
        None,
    )
}

fn search_page(issues: Value) -> Value {
    json!({ "startAt": 0, "maxResults": 50, "total": 1, "issues": issues })
}

#[test]
fn search_columns_resolve_names_and_disambiguate_duplicates() -> TestResult {
    use atlas_duck_core::metadata::FieldNames;
    let names = FieldNames::from(std::collections::BTreeMap::from([
        ("customfield_10200".to_owned(), "Team".to_owned()),
        ("customfield_10201".to_owned(), "Team".to_owned()),
    ]));
    let page = search_page(json!([{
        "key": "ABC-1",
        "fields": {"summary": "s", "customfield_10200": "a", "customfield_10201": "b"}
    }]));
    let params = json!({ "jql": "x", "fields": ["summary", "customfield_10200", "customfield_10201", "customfield_99999"] });
    let model = search_model(&page, &params, Some(&names))?;
    let (columns, rows, _) = table_of(&model.body)?;
    // A name two columns share is told apart by the id; an unknown custom field is flagged.
    assert_eq!(
        columns,
        [
            "Key",
            "Summary",
            "Team (customfield_10200)",
            "Team (customfield_10201)",
            "customfield_99999 (unknown field)"
        ]
    );
    assert_eq!(rows[0], ["ABC-1", "s", "a", "b", ""]);
    // Names never reach the warnings (T8 handoff).
    let bare = search_model(&page, &params, None)?;
    let ids = |m: &atlas_duck_core::ops::PreviewModel| -> Vec<(WarningId, String)> {
        m.warnings.iter().map(|w| (w.id, w.text.clone())).collect()
    };
    assert_eq!(ids(&model), ids(&bare));
    Ok(())
}

#[test]
fn search_cells_are_escaped_one_line_text() -> TestResult {
    let page = search_page(json!([{
        "key": "AB\u{202e}C-1",
        "fields": {"summary": "line one\nline two \u{202e}x", "description": "x"}
    }]));
    let params = json!({ "jql": "x", "fields": ["summary"] });
    let model = search_model(&page, &params, None)?;
    let (_, rows, _) = table_of(&model.body)?;
    assert_eq!(rows[0][0], "AB\u{27e8}U+202E\u{27e9}C-1");
    assert_eq!(
        rows[0][1],
        "line one\u{27e8}U+000A\u{27e9}line two \u{27e8}U+202E\u{27e9}x"
    );
    assert!(model.header.bidi_controls >= 2);
    assert!(
        model
            .warnings
            .iter()
            .any(|w| w.id == WarningId::BidiControls)
    );
    Ok(())
}

#[test]
fn search_cell_cap_cuts_on_a_char_boundary_and_counts_hidden() -> TestResult {
    let page = search_page(json!([{
        "key": "ABC-1",
        "fields": {"summary": "é".repeat(300), "other": {"a": "x".repeat(300)}}
    }]));
    let params = json!({ "jql": "x", "fields": ["summary", "other"] });
    let model = search_model(&page, &params, None)?;
    let (_, rows, _) = table_of(&model.body)?;
    // 200 chars kept, 100 chars (200 bytes) cut, said in the cell.
    assert_eq!(
        rows[0][1],
        format!("{}… 200 more bytes (see Raw)", "é".repeat(200))
    );
    // A non-string value is cut like a string.
    assert!(rows[0][2].contains("(see Raw)"), "{}", rows[0][2]);
    let compact = json!({"a": "x".repeat(300)}).to_string();
    let cut = u64::try_from(compact.len() - 200)?;
    assert_eq!(model.header.hidden_in_preview_bytes, 200 + cut);
    Ok(())
}

#[test]
fn search_hidden_counts_what_the_table_does_not_show() -> TestResult {
    let mut page = search_page(json!([{
        "id": "1", "key": "ABC-1", "self": "https://x/1", "expand": "renderedFields",
        "fields": {"summary": "x", "labels": ["a"]},
        "renderedFields": {"summary": "x"},
        "changelog": {"total": 0}
    }]));
    page["names"] = json!({"summary": "Summary"});
    page["warningMessages"] = json!(["w"]);
    let params = json!({ "jql": "x", "fields": ["summary"] });
    let model = search_model(&page, &params, None)?;
    // `labels` (an unrequested field), the issue's other top-level keys and the result's other
    // top-level keys: key length plus compact value length each.
    let expect = |k: &str, v: Value| u64::try_from(k.len() + v.to_string().len());
    let want = expect("labels", json!(["a"]))?
        + expect("renderedFields", json!({"summary": "x"}))?
        + expect("changelog", json!({"total": 0}))?
        + expect("names", json!({"summary": "Summary"}))?
        + expect("warningMessages", json!(["w"]))?;
    assert_eq!(model.header.hidden_in_preview_bytes, want);
    Ok(())
}

#[test]
fn search_star_fields_show_every_field_key_and_warn() -> TestResult {
    let page = search_page(json!([
        {"key": "ABC-1", "fields": {"summary": "a", "labels": []}},
        {"key": "ABC-2", "fields": {"summary": "b", "priority": {"name": "High"}}}
    ]));
    let params = json!({ "jql": "x", "fields": ["*all"] });
    let model = search_model(&page, &params, None)?;
    let (columns, rows, _) = table_of(&model.body)?;
    // The registry's default fields first, then the others as first seen.
    assert_eq!(columns, ["Key", "Summary", "Priority", "Labels"]);
    assert_eq!(rows[1], ["ABC-2", "b", r#"{"name":"High"}"#, ""]);
    assert!(model.warnings.iter().any(|w| w.id == WarningId::AllFields));
    // Agile lists name no default fields: the same union.
    let agile = json!({ "startAt": 0, "maxResults": 50, "total": 2, "issues": page["issues"] });
    let model = read_preview(
        "jira.sprint.issues",
        atlas_duck_core::ops::jira_preview::search_preview,
        &agile,
        &json!({ "id": 5 }),
        None,
    )?;
    // No default fields there: the keys as first seen (sorted within an issue).
    let (columns, _, _) = table_of(&model.body)?;
    assert_eq!(columns, ["Key", "Labels", "Summary", "Priority"]);
    Ok(())
}

#[test]
fn search_warns_for_restricted_comments_and_security_levels() -> TestResult {
    let plain =
        search_page(json!([{"key": "ABC-1", "fields": {"summary": "a", "security": null}}]));
    let params = json!({ "jql": "x", "fields": ["summary", "comment", "security"] });
    let model = search_model(&plain, &params, None)?;
    assert!(
        !model.warnings.iter().any(|w| w.level == Level::Caution),
        "{:?}",
        model.warnings
    );
    let page = search_page(json!([{
        "key": "ABC-1",
        "fields": {
            "security": {"name": "Staff"},
            "comment": {"comments": [{"id": "1", "visibility": restriction()}]}
        },
        "renderedFields": {"comment": {"comments": [{"id": "9", "visibility": restriction()}]}}
    }]));
    let model = search_model(&page, &params, None)?;
    let cautions: Vec<WarningId> = model
        .warnings
        .iter()
        .filter(|w| w.level == Level::Caution)
        .map(|w| w.id)
        .collect();
    assert!(
        cautions.contains(&WarningId::RestrictedComments),
        "{cautions:?}"
    );
    assert!(cautions.contains(&WarningId::SecurityLevel), "{cautions:?}");
    // One of each, however many issues carry it.
    assert_eq!(cautions.len(), 2, "{cautions:?}");
    Ok(())
}

#[test]
fn search_rows_are_capped_with_a_visible_note() -> TestResult {
    let issues: Vec<Value> = (0..600)
        .map(|n| json!({"key": format!("ABC-{n}"), "fields": {"summary": "s"}}))
        .collect();
    let page = json!({ "startAt": 0, "maxResults": 600, "total": 600, "issues": issues });
    let params = json!({ "jql": "x", "fields": ["summary"] });
    let model = search_model(&page, &params, None)?;
    let (_, rows, count) = table_of(&model.body)?;
    assert_eq!(rows.len(), 501);
    assert!(
        rows[500][0].contains("100 more items (see Raw)"),
        "{:?}",
        rows[500]
    );
    assert_eq!(count.map(|c| c.shown), Some(600));
    assert!(model.header.hidden_in_preview_bytes > 0);
    Ok(())
}

#[test]
fn list_columns_are_the_scalar_keys_of_the_first_50_items() -> TestResult {
    let mut items: Vec<Value> = (0..60)
        .map(|n| json!({"id": n, "name": format!("n{n}"), "nested": {"a": 1}}))
        .collect();
    items[1]["extra"] = json!("late");
    items[55]["tail"] = json!("beyond the first 50");
    items[2]["flag"] = json!(true);
    items[3]["none"] = Value::Null;
    let candidate = json!({ "values": items, "startAt": 0, "maxResults": 100, "isLast": true });
    let model = list_model("jira.board.list", &candidate)?;
    let (columns, rows, count) = table_of(&model.body)?;
    // `id`, `name`, then first seen; `nested` is no scalar; `tail` is outside the first 50 items.
    assert_eq!(columns, ["id", "name", "extra", "flag", "none"]);
    assert_eq!(rows.len(), 60);
    assert_eq!(rows[0], ["0", "n0", "", "", ""]);
    assert_eq!(rows[1][2], "late");
    assert_eq!(rows[2][3], "true");
    assert_eq!(count.map(|c| c.shown), Some(60));
    // Hidden: every `nested` object and the `tail` key of item 55 (page mechanics excluded).
    let nested = u64::try_from("nested".len() + json!({"a": 1}).to_string().len())?;
    let tail = u64::try_from("tail".len() + json!("beyond the first 50").to_string().len())?;
    assert_eq!(model.header.hidden_in_preview_bytes, 60 * nested + tail);
    Ok(())
}

#[test]
fn list_roots_without_item_objects_keep_the_json_tree() -> TestResult {
    for candidate in [
        json!({"name": "jdoe"}),
        json!(["a", "b"]),
        json!({"values": ["a"]}),
        json!({"values": []}),
        json!({"fields": {"summary": {}}}),
    ] {
        let model = list_model("jira.board.list", &candidate)?;
        assert!(
            matches!(model.body, PreviewBody::JsonTree { .. }),
            "{candidate}: {:?}",
            model.body
        );
    }
    Ok(())
}

#[test]
fn list_text_is_escaped_and_other_root_keys_are_counted() -> TestResult {
    let mut candidate = json!([{"na\nme": "a\u{202e}b", "id": 1}]);
    let model = list_model("jira.project.list", &candidate)?;
    let (columns, rows, _) = table_of(&model.body)?;
    assert_eq!(columns, ["id", "na\u{27e8}U+000A\u{27e9}me"]);
    assert_eq!(rows[0][1], "a\u{27e8}U+202E\u{27e9}b");
    assert_eq!(model.header.bidi_controls, 1);
    assert!(
        model
            .warnings
            .iter()
            .any(|w| w.id == WarningId::BidiControls)
    );

    candidate = json!({
        "transitions": [{"id": "1"}], "expand": "transitions", "warningMessages": ["w"]
    });
    let model = list_model("jira.transition.list", &candidate)?;
    let want = u64::try_from("warningMessages".len() + json!(["w"]).to_string().len())?;
    assert_eq!(model.header.hidden_in_preview_bytes, want);
    let (_, _, count) = table_of(&model.body)?;
    assert_eq!(
        count,
        Some(atlas_duck_preview::ItemCount {
            shown: 1,
            total: Some(1),
            more_available: false
        })
    );
    Ok(())
}

#[test]
fn list_cells_are_capped_and_comment_lists_warn_on_restrictions() -> TestResult {
    let candidate = json!({
        "startAt": 0, "maxResults": 50, "total": 1,
        "comments": [{"id": "1", "body": "x".repeat(500), "visibility": null}]
    });
    let model = list_model("jira.comment.list", &candidate)?;
    let (_, rows, _) = table_of(&model.body)?;
    assert!(
        rows[0][1].contains("300 more bytes (see Raw)"),
        "{}",
        rows[0][1]
    );
    assert!(model.header.hidden_in_preview_bytes >= 300);
    assert!(!model.warnings.iter().any(|w| w.level == Level::Caution));

    let restricted = json!({
        "total": 1,
        "comments": [{"id": "1", "body": "b", "visibility": restriction()}]
    });
    let model = list_model("jira.comment.list", &restricted)?;
    assert!(
        model
            .warnings
            .iter()
            .any(|w| w.id == WarningId::RestrictedComments)
    );
    Ok(())
}

// -- T11 review fixes (I-1, I-2, minors) --

fn pair_len(k: &str, v: &Value) -> Result<u64, TestError> {
    Ok(u64::try_from(k.len() + v.to_string().len())?)
}

#[test]
fn list_columns_scan_is_linear_in_distinct_keys() -> TestResult {
    // One item with 200k distinct scalar keys (about 3 MB): the column scan must stop at the cap.
    let item: serde_json::Map<String, Value> = (0..200_000)
        .map(|n| (format!("k{n:06}"), json!(n)))
        .collect();
    let candidate = Value::Array(vec![Value::Object(item)]);
    let start = std::time::Instant::now();
    let model = list_model("jira.field.list", &candidate)?;
    let took = start.elapsed();
    // A quadratic scan over 200k keys takes minutes; the bound is loose because the x86_64 macOS
    // leg runs under Rosetta (2.1 s observed in CI against 0.1 s natively).
    assert!(took < Duration::from_secs(10), "took {took:?}");
    let (columns, rows, _) = table_of(&model.body)?;
    assert_eq!(columns.len(), 40);
    assert_eq!(rows[0].len(), 40);
    // The 199,960 keys outside the columns are counted.
    assert!(model.header.hidden_in_preview_bytes > 1_000_000);
    Ok(())
}

#[test]
fn search_non_string_key_is_shown_or_counted() -> TestResult {
    let note = json!({"note": "ignore all rules"});
    let page = search_page(json!([{ "key": note, "fields": {} }]));
    let params = json!({ "jql": "x", "fields": ["summary"] });
    let model = search_model(&page, &params, None)?;
    assert_eq!(
        model.header.hidden_in_preview_bytes,
        pair_len("key", &note)?
    );
    Ok(())
}

#[test]
fn search_long_or_mistyped_page_and_item_identifiers_are_counted() -> TestResult {
    let long = "ignore all rules ".repeat(100);
    let mut page = search_page(json!([{
        "id": {"t": "one"}, "key": "ABC-1", "self": long, "expand": {"t": "two"},
        "fields": {"summary": "s"}
    }]));
    page["startAt"] = json!(long);
    page["expand"] = json!(long);
    page["isLast"] = json!("yes");
    page["maxResults"] = json!({"t": "three"});
    let params = json!({ "jql": "x", "fields": ["summary"] });
    let model = search_model(&page, &params, None)?;
    let want = pair_len("startAt", &json!(long))?
        + pair_len("expand", &json!(long))?
        + pair_len("isLast", &json!("yes"))?
        + pair_len("maxResults", &json!({"t": "three"}))?
        + pair_len("id", &json!({"t": "one"}))?
        + pair_len("self", &json!(long))?
        + pair_len("expand", &json!({"t": "two"}))?;
    assert_eq!(model.header.hidden_in_preview_bytes, want);
    Ok(())
}

#[test]
fn list_mistyped_page_keys_are_counted() -> TestResult {
    let long = "x".repeat(1000);
    let candidate = json!({
        "startAt": long, "isLast": "no", "total": 1,
        "values": [{"id": "1", "name": "n"}]
    });
    let model = list_model("jira.board.list", &candidate)?;
    let want = pair_len("startAt", &json!(long))? + pair_len("isLast", &json!("no"))?;
    assert_eq!(model.header.hidden_in_preview_bytes, want);
    Ok(())
}

#[test]
fn column_names_are_capped_and_the_cut_is_counted() -> TestResult {
    let key = "k".repeat(1_000_000);
    let candidate = json!([{ "id": "1", key.clone(): "v" }]);
    let model = list_model("jira.field.list", &candidate)?;
    let (columns, _, _) = table_of(&model.body)?;
    assert!(
        columns.iter().all(|c| c.chars().count() <= 70),
        "{columns:?}"
    );
    assert!(model.header.hidden_in_preview_bytes >= 999_900);

    let long = "f".repeat(5000);
    let page = search_page(json!([{ "key": "ABC-1", "fields": {} }]));
    let params = json!({ "jql": "x", "fields": [long] });
    let model = search_model(&page, &params, None)?;
    let (columns, _, _) = table_of(&model.body)?;
    assert!(
        columns.iter().all(|c| c.chars().count() <= 70),
        "{columns:?}"
    );
    assert!(model.header.hidden_in_preview_bytes > 0);
    Ok(())
}

#[test]
fn escaped_cells_stay_within_the_cell_cap() -> TestResult {
    let page = search_page(json!([{
        "key": "ABC-1", "fields": {"summary": "\u{202e}".repeat(300)}
    }]));
    let params = json!({ "jql": "x", "fields": ["summary"] });
    let model = search_model(&page, &params, None)?;
    let (_, rows, _) = table_of(&model.body)?;
    let shown = rows[0][1].split('…').next().unwrap_or_default();
    assert!(shown.chars().count() <= 200, "{}", shown.chars().count());
    assert!(rows[0][1].contains("(see Raw)"), "{}", rows[0][1]);
    assert!(model.header.hidden_in_preview_bytes > 0);
    Ok(())
}

#[test]
fn restrictions_are_found_past_the_row_cap() -> TestResult {
    let mut issues: Vec<Value> = (0..600)
        .map(|n| json!({"key": format!("ABC-{n}"), "fields": {"summary": "s"}}))
        .collect();
    issues[550] = json!({
        "key": "ABC-550",
        "fields": {"summary": "s", "security": {"name": "Staff"},
                   "comment": {"comments": [{"id": "1", "visibility": restriction()}]}}
    });
    let page = json!({ "startAt": 0, "maxResults": 600, "total": 600, "issues": issues });
    let params = json!({ "jql": "x", "fields": ["summary"] });
    let model = search_model(&page, &params, None)?;
    let (_, rows, _) = table_of(&model.body)?;
    assert_eq!(rows.len(), 501);
    for id in [WarningId::RestrictedComments, WarningId::SecurityLevel] {
        assert!(model.warnings.iter().any(|w| w.id == id), "{id:?}");
    }
    Ok(())
}

#[test]
fn comment_list_caution_survives_the_tree_fallback() -> TestResult {
    // No scalar key in any comment: no table columns, the JSON tree.
    let candidate = json!({
        "comments": [{"visibility": {"type": "role"}, "author": {"name": "a"}}]
    });
    let model = list_model("jira.comment.list", &candidate)?;
    assert!(matches!(model.body, PreviewBody::JsonTree { .. }));
    assert!(
        model
            .warnings
            .iter()
            .any(|w| w.id == WarningId::RestrictedComments)
    );
    Ok(())
}

#[test]
fn column_order_is_sorted_key_order() -> TestResult {
    // serde_json without `preserve_order` sorts keys; a feature unification that turned it on
    // would reorder every table, so fail here first.
    let object: serde_json::Map<String, Value> = serde_json::from_str(r#"{"z": 1, "a": 2}"#)?;
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        ["a", "z"]
    );
    let model = list_model("jira.field.list", &json!([{"z": 1, "b": 2, "a": 3}]))?;
    let (columns, _, _) = table_of(&model.body)?;
    assert_eq!(columns, ["a", "b", "z"]);
    Ok(())
}

#[test]
fn single_object_reads_stay_the_json_tree() -> TestResult {
    for (op, candidate) in [
        (
            "jira.project.get",
            json!({"id": "10000", "key": "ABC", "name": "Alpha", "lead": {"name": "jdoe"}}),
        ),
        (
            "jira.issue.editmeta",
            json!({"fields": {"summary": {"required": true, "name": "Summary"}}}),
        ),
    ] {
        let model = list_model(op, &candidate)?;
        assert!(
            matches!(model.body, PreviewBody::JsonTree { .. }),
            "{op}: {:?}",
            model.body
        );
    }
    Ok(())
}
