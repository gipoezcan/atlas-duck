//! Shared Jira wiremock helpers for the M5 suites (`jira_reads.rs` and the write suites after it).
//! Every mount answers through `MockDc::response`, so the harness user's `X-AUSERNAME` and a
//! `Date` header are set like on every other harness answer.

use std::time::Duration;

use atlas_duck_atlassian::testing::MockDc;
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

/// `/rest/api/2/issue/{key}`.
pub fn issue_path(key: &str) -> String {
    format!("/rest/api/2/issue/{key}")
}

/// `/rest/api/2/issue/{key}/comment` (`jira.comment.list`, the `--comments` pages).
pub fn comments_path(key: &str) -> String {
    format!("/rest/api/2/issue/{key}/comment")
}

fn json_answer(mock: &MockDc, status: u16, body: &Value) -> ResponseTemplate {
    mock.response(status)
        .set_body_raw(body.to_string(), "application/json")
}

/// `GET /rest/api/2/issue/{key}` answers `body` (200).
pub async fn mount_issue(mock: &MockDc, key: &str, body: &Value) {
    mount_get(mock, &issue_path(key), json_answer(mock, 200, body)).await;
}

/// One comment as `GET .../comment` lists it.
pub fn comment(id: u64, body: &str) -> Value {
    json!({
        "self": format!("https://jira.corp.example/rest/api/2/issue/10001/comment/{id}"),
        "id": id.to_string(),
        "author": {"name": "jdoe", "key": "JIRAUSER1", "displayName": "Jane Doe"},
        "body": body,
        "created": "2026-10-06T10:00:00.000+0200",
        "updated": "2026-10-06T10:00:00.000+0200"
    })
}

/// A comment page `{startAt, maxResults, total, comments}` with `count` comments whose ids run
/// from `30000 + start_at`; with `rendered`, each carries `renderedBody`.
pub fn comment_page(
    start_at: u64,
    max_results: u64,
    total: u64,
    count: u64,
    rendered: bool,
) -> Value {
    let comments: Vec<Value> = (start_at..start_at + count)
        .map(|n| {
            let mut c = comment(30_000 + n, &format!("comment *{n}*"));
            if rendered {
                c["renderedBody"] = json!(format!("<p>comment <b>{n}</b></p>"));
            }
            c
        })
        .collect();
    json!({
        "startAt": start_at,
        "maxResults": max_results,
        "total": total,
        "comments": comments
    })
}

/// The comment pages of `key`, each answering the GET whose `startAt` is the page's own.
pub async fn mount_comments(mock: &MockDc, key: &str, pages: &[Value]) {
    for page in pages {
        let start = page["startAt"].as_u64().unwrap_or(0).to_string();
        Mock::given(method("GET"))
            .and(path(mock.path(&comments_path(key))))
            .and(query_param("startAt", start.as_str()))
            .respond_with(json_answer(mock, 200, page))
            .mount(mock.server())
            .await;
    }
}

/// [`mount_comments`] for `expand=renderedBody` requests only (an unrendered request gets 404).
pub async fn mount_comments_rendered(mock: &MockDc, key: &str, pages: &[Value]) {
    for page in pages {
        let start = page["startAt"].as_u64().unwrap_or(0).to_string();
        Mock::given(method("GET"))
            .and(path(mock.path(&comments_path(key))))
            .and(query_param("startAt", start.as_str()))
            .and(query_param("expand", "renderedBody"))
            .respond_with(json_answer(mock, 200, page))
            .mount(mock.server())
            .await;
    }
}

/// The comment page at `start_at` of `key` answers `t` (a failure, a delay).
pub async fn mount_comment_page_with(mock: &MockDc, key: &str, start_at: u64, t: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(mock.path(&comments_path(key))))
        .and(query_param("startAt", start_at.to_string().as_str()))
        .respond_with(t)
        .mount(mock.server())
        .await;
}

/// `page` at `start_at`, answered `delay` after the request arrived.
pub async fn mount_comment_page_delayed(mock: &MockDc, key: &str, page: &Value, delay: Duration) {
    let start = page["startAt"].as_u64().unwrap_or(0);
    let t = json_answer(mock, 200, page).set_delay(delay);
    mount_comment_page_with(mock, key, start, t).await;
}

/// `GET /rest/api/2/issue/createmeta/{project}/issuetypes/{type_id}` answers `body`.
pub async fn mount_createmeta_fields(mock: &MockDc, project: &str, type_id: &str, body: &Value) {
    let p = format!("/rest/api/2/issue/createmeta/{project}/issuetypes/{type_id}");
    mount_get(mock, &p, json_answer(mock, 200, body)).await;
}

/// `GET /rest/api/2/issueLinkType` answers `{"issueLinkTypes": types}`.
pub async fn mount_link_types(mock: &MockDc, types: &Value) {
    let body = json!({ "issueLinkTypes": types });
    mount_get(
        mock,
        "/rest/api/2/issueLinkType",
        json_answer(mock, 200, &body),
    )
    .await;
}

/// `GET /rest/api/2/user/assignable/search` answers `users`.
pub async fn mount_assignable(mock: &MockDc, users: &Value) {
    mount_get(
        mock,
        "/rest/api/2/user/assignable/search",
        json_answer(mock, 200, users),
    )
    .await;
}

/// `GET /rest/agile/1.0/sprint/{id}` answers `body`.
pub async fn mount_sprint(mock: &MockDc, id: u64, body: &Value) {
    let p = format!("/rest/agile/1.0/sprint/{id}");
    mount_get(mock, &p, json_answer(mock, 200, body)).await;
}

/// `GET /rest/api/2/project` answers `projects`.
pub async fn mount_projects(mock: &MockDc, projects: &Value) {
    mount_get(
        mock,
        "/rest/api/2/project",
        json_answer(mock, 200, projects),
    )
    .await;
}

async fn mount_get(mock: &MockDc, p: &str, t: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(mock.path(p)))
        .respond_with(t)
        .mount(mock.server())
        .await;
}

/// The GETs `mock` received on `p` (under the context path), in arrival order.
pub async fn gets_on(mock: &MockDc, p: &str) -> Vec<wiremock::Request> {
    let full = mock.path(p);
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.url.path() == full && r.method.as_str() == "GET")
        .collect()
}

/// The value of query parameter `name` of `r`.
pub fn query(r: &wiremock::Request, name: &str) -> Option<String> {
    r.url
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}
