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
    mount_comment_page_with, mount_comments, mount_comments_rendered, mount_issue, query,
    restriction,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u27_mirror_without_counterpart_blocks_release() -> TestResult {
    use atlas_duck_core::DecisionError;
    use atlas_duck_core::payloads::InvalidReason;
    let h = Harness::jira().await?;
    let mut issue = full_issue(KEY);
    issue["fields"]["comment"] = json!({
        "total": 1, "startAt": 0, "maxResults": 50,
        "comments": [{"id": "7", "body": "plain"}]
    });
    issue["renderedFields"] = json!({
        "comment": {"comments": [
            {"id": "7", "body": "<p>plain</p>"},
            {"id": "9", "body": "<p>orphan</p>"}
        ]}
    });
    mount_issue(jira(&h)?, KEY, &issue).await;
    let id = queued(
        &h,
        json!({ "key": KEY, "fields": ["summary", "comment"], "rendered": true }),
    )
    .await?;
    // The M3 mirror check runs with the redaction ops (an unredacted release drops nothing): a
    // redaction of an issue whose rendered mirror holds an entry with no `fields` counterpart
    // is not approvable, so no redacted revision is built and nothing is released.
    let ap = h.approver();
    ap.open(&id).map_err(de)?;
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
    let invalid = records(&h, &id, EventType::DECISION_INVALID).await?;
    assert_eq!(
        invalid.first().map(|r| r["reason"].clone()),
        Some(json!("not_approvable"))
    );
    assert!(
        records(&h, &id, EventType::READ_RELEASED).await?.is_empty(),
        "nothing was released"
    );
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
