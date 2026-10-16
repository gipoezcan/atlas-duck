//! Shared Confluence wiremock helpers for the M7 suites (`confluence_reads.rs` and the write
//! suites after it). Every mount answers through `MockDc::response`, so a `Date` header is set
//! like on every other harness answer; paths are given without the `/wiki` context path.

use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, UserKind, fixtures};
use atlas_duck_registry::{OpClass, OperationSpec};
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

use super::jira::{declared_success, fill_path, http_method};

/// The `expand` of a `confluence.page.get` in `markdown` or `storage` format (PD-100).
pub const PAGE_EXPAND_STORAGE: &str = "body.storage,version,space,ancestors";
/// The `expand` of a `confluence.page.get` in `view` format (PD-100).
pub const PAGE_EXPAND_VIEW: &str = "body.view,version,space,ancestors";

/// `/rest/api/content/{id}`.
pub fn content_path(id: &str) -> String {
    format!("/rest/api/content/{id}")
}

fn json_answer(mock: &MockDc, status: u16, body: &Value) -> ResponseTemplate {
    mock.response(status)
        .set_body_raw(body.to_string(), "application/json")
}

/// `fixtures::CONFLUENCE_PAGE` (id `65537`, space `DOC`, version 7) with `storage` as its
/// `body.storage.value`.
pub fn page_with_storage(storage: &str) -> Value {
    let mut page: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE).unwrap_or(Value::Null);
    page["body"] = json!({"storage": {"value": storage, "representation": "storage"}});
    page
}

/// A small storage body whose Markdown is `lines` lines of 101 bytes and more (T10 review B-1):
/// a code block in 50 nested quotes, every line of it with the quotes' 100-byte prefix.
pub fn amplified_storage(lines: usize) -> String {
    format!(
        "{}<ac:structured-macro ac:name=\"code\"><ac:plain-text-body><![CDATA[{}]]>\
         </ac:plain-text-body></ac:structured-macro>{}",
        "<blockquote>".repeat(50),
        "x\n".repeat(lines),
        "</blockquote>".repeat(50)
    )
}

/// `fixtures::CONFLUENCE_PAGE` with `html` as its `body.view.value` and no `body.storage`.
pub fn page_with_view(html: &str) -> Value {
    let mut page: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE).unwrap_or(Value::Null);
    page["body"] = json!({"view": {"value": html, "representation": "view"}});
    page
}

/// `GET /rest/api/content/{id}?expand=body.storage,version,space,ancestors` answers `body`.
pub async fn mount_page(mock: &MockDc, id: &str, body: &Value) {
    mount_page_delayed(mock, id, body, Duration::ZERO).await;
}

/// [`mount_page`] answering `delay` after the request arrived.
pub async fn mount_page_delayed(mock: &MockDc, id: &str, body: &Value, delay: Duration) {
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(id))))
        .and(query_param("expand", PAGE_EXPAND_STORAGE))
        .respond_with(json_answer(mock, 200, body).set_delay(delay))
        .mount(mock.server())
        .await;
}

/// `GET /rest/api/content/{id}?expand=body.view,version,space,ancestors` answers `body`.
pub async fn mount_page_view(mock: &MockDc, id: &str, body: &Value) {
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(id))))
        .and(query_param("expand", PAGE_EXPAND_VIEW))
        .respond_with(json_answer(mock, 200, body))
        .mount(mock.server())
        .await;
}

/// `GET /rest/api/content/{id}?version=<version>&status=historical` (any `expand`) answers
/// `body`, ahead of a [`mount_page`] of the same path.
pub async fn mount_history_version(mock: &MockDc, id: &str, version: u64, body: &Value) {
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(id))))
        .and(query_param("version", version.to_string().as_str()))
        .and(query_param("status", "historical"))
        .respond_with(json_answer(mock, 200, body))
        .with_priority(1)
        .mount(mock.server())
        .await;
}

/// `GET /rest/api/content/{id}/history` (the summary, `page.history` without `version`)
/// answers `body`.
pub async fn mount_history_summary(mock: &MockDc, id: &str, body: &Value) {
    mount_get(
        mock,
        &format!("{}/history", content_path(id)),
        json_answer(mock, 200, body),
    )
    .await;
}

/// A known user as `GET /rest/api/user?key=` answers it.
pub fn user(key: &str, username: &str) -> Value {
    json!({
        "type": "known",
        "username": username,
        "userKey": key,
        "displayName": username,
        "_links": {"self": format!("https://wiki.corp.example/rest/api/user?key={key}")}
    })
}

/// `GET /rest/api/user?key=<key>` per entry: a known user for `Some(username)`, a JSON 404
/// for `None` (PD-99 user lookups, Task 11).
pub async fn mount_users(mock: &MockDc, users: &[(&str, Option<&str>)]) {
    mount_users_delayed(mock, users, Duration::ZERO).await;
}

/// [`mount_users`] with every answer sent `delay` after its request arrived (a lookup the test
/// wants to see held in flight).
pub async fn mount_users_delayed(mock: &MockDc, users: &[(&str, Option<&str>)], delay: Duration) {
    for (key, username) in users {
        let answer = match username {
            Some(name) => json_answer(mock, 200, &user(key, name)),
            None => json_answer(
                mock,
                404,
                &json!({"statusCode": 404, "message": "No user found with key"}),
            ),
        };
        Mock::given(method("GET"))
            .and(path(mock.path("/rest/api/user")))
            .and(query_param("key", *key))
            .respond_with(answer.set_delay(delay))
            .mount(mock.server())
            .await;
    }
}

/// `GET /rest/api/user?key=<key>` answers `status` with the JSON `body` (a lookup answer that is
/// not a plain known user or a 404).
pub async fn mount_user_answer(mock: &MockDc, key: &str, status: u16, body: &Value) {
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/user")))
        .and(query_param("key", key))
        .respond_with(json_answer(mock, status, body))
        .mount(mock.server())
        .await;
}

/// The user lookups (`GET /rest/api/user`) the mock received, in order.
pub async fn user_gets(mock: &MockDc) -> Vec<wiremock::Request> {
    super::jira::gets_on(mock, "/rest/api/user").await
}

/// The comment pages of content `id` (`confluence.comment.list`), each answering the GET whose
/// `start` is the page's own.
pub async fn mount_comments(mock: &MockDc, id: &str, pages: &[Value]) {
    mount_pages(mock, &format!("{}/child/comment", content_path(id)), pages).await;
}

/// `GET /rest/api/space/{key}` answers `body`.
pub async fn mount_space(mock: &MockDc, key: &str, body: &Value) {
    mount_get(
        mock,
        &format!("/rest/api/space/{key}"),
        json_answer(mock, 200, body),
    )
    .await;
}

/// The child-page pages of content `id` (`confluence.page.children`), by `start`.
pub async fn mount_children(mock: &MockDc, id: &str, pages: &[Value]) {
    mount_pages(mock, &format!("{}/child/page", content_path(id)), pages).await;
}

/// `GET /rest/api/content/{id}/child/attachment` (any query) answers `body`.
pub async fn mount_attachments(mock: &MockDc, id: &str, body: &Value) {
    mount_get(
        mock,
        &format!("{}/child/attachment", content_path(id)),
        json_answer(mock, 200, body),
    )
    .await;
}

/// `GET /rest/api/content?spaceKey=<space>&title=<title>` answers `results` as a
/// `{results, start, limit, size}` page (title lookups: `page.find`, parent and duplicate-title
/// checks).
pub async fn mount_title_lookup(mock: &MockDc, space: &str, title: &str, results: &[Value]) {
    let body = json!({
        "results": results,
        "start": 0,
        "limit": 25,
        "size": results.len(),
        "_links": {"base": "https://wiki.corp.example", "context": ""}
    });
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/content")))
        .and(query_param("spaceKey", space))
        .and(query_param("title", title))
        .respond_with(json_answer(mock, 200, &body))
        .mount(mock.server())
        .await;
}

/// `GET /rest/api/search` (any query) answers `body` (`confluence.search`).
pub async fn mount_search(mock: &MockDc, body: &Value) {
    mount_get(mock, "/rest/api/search", json_answer(mock, 200, body)).await;
}

/// The search GETs (`GET /rest/api/search`) the mock received, in order.
pub async fn search_gets(mock: &MockDc) -> Vec<wiremock::Request> {
    super::jira::gets_on(mock, "/rest/api/search").await
}

async fn mount_pages(mock: &MockDc, p: &str, pages: &[Value]) {
    for page in pages {
        let start = page["start"].as_u64().unwrap_or(0).to_string();
        Mock::given(method("GET"))
            .and(path(mock.path(p)))
            .and(query_param("start", start.as_str()))
            .respond_with(json_answer(mock, 200, page))
            .mount(mock.server())
            .await;
    }
}

async fn mount_get(mock: &MockDc, p: &str, t: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(mock.path(p)))
        .respond_with(t)
        .mount(mock.server())
        .await;
}

// ---- X-09: mounts generated from the registry ------------------------------------------------------

/// A GET a Confluence op sends besides its own request (an enrichment, a resolution, a stale
/// check): `path` answers `body`.
pub struct Aux {
    pub path: String,
    pub body: Value,
}

fn read_example(op_id: &str) -> Result<Value, String> {
    atlas_duck_registry::get(op_id)
        .map(|s| s.result_example_json())
        .ok_or_else(|| format!("no registry op {op_id}"))
}

/// The extra GETs of `spec` for `params`. Every Confluence op id is named here: an op whose
/// GETs are not decided yet is an error, so X-09 fails for it instead of passing vacuously
/// (the write tasks of M7 add their stages here).
pub fn aux_gets(spec: &OperationSpec, params: &Value) -> Result<Vec<Aux>, String> {
    match spec.id {
        "confluence.user.current"
        | "confluence.space.list"
        | "confluence.space.get"
        | "confluence.page.get"
        | "confluence.page.find"
        | "confluence.search"
        | "confluence.page.children"
        | "confluence.comment.list"
        | "confluence.label.list"
        | "confluence.attachment.list"
        | "confluence.page.history" => Ok(Vec::new()),
        // One enrichment round: the current page with its storage body (M3; Task 15 adds the
        // historical base body).
        "confluence.page.update" => {
            let id = params["id"]
                .as_str()
                .ok_or("example params have no string id")?;
            Ok(vec![Aux {
                path: content_path(id),
                body: read_example("confluence.page.get")?,
            }])
        }
        other => Err(format!(
            "{other}: no X-09 mount rule in common::confluence::aux_gets (a new op needs its GETs decided)"
        )),
    }
}

/// Mounts everything `spec` needs to run once with `params`: the identity answer
/// (`/rest/api/user/current`, known), the GETs of [`aux_gets`] and the op's own endpoint (a read
/// answers its `result_example`, a write its declared success). Returns the GETs it mounted.
pub async fn mount_for_op(
    mock: &MockDc,
    spec: &OperationSpec,
    params: &Value,
) -> Result<Vec<Aux>, String> {
    let aux = aux_gets(spec, params)?;
    mock.confluence_user_current(UserKind::Known, TEST_USER, TEST_USER_KEY)
        .await;
    for a in &aux {
        mount_get(mock, &a.path, json_answer(mock, 200, &a.body)).await;
    }
    let own = fill_path(spec.endpoint.path, params)?;
    let answer = match spec.class {
        OpClass::Read => json_answer(mock, 200, &spec.result_example_json()),
        OpClass::Write => declared_success(mock, spec),
    };
    Mock::given(method(http_method(spec.endpoint.method)))
        .and(path(mock.path(&own)))
        .respond_with(answer)
        .mount(mock.server())
        .await;
    Ok(aux)
}

/// The `READ_FETCHED` payload `payloads::read_fetched` writes for one 2xx answer, with `users`
/// as its `user_resolutions`.
pub fn fetched_payload(content: &Value, users: Option<Value>) -> Value {
    let mut payload = json!({
        "pages": 1,
        "responses": [{
            "status": 200,
            "content_type": "application/json",
            "body": atlas_duck_core::payloads::body_json(content.to_string().as_bytes()),
        }],
    });
    if let Some(users) = users {
        payload["user_resolutions"] = users;
    }
    payload
}
