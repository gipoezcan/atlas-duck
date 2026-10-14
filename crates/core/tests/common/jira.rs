//! Shared Jira wiremock helpers for the M5 suites (`jira_reads.rs` and the write suites after it).
//! Every mount answers through `MockDc::response`, so the harness user's `X-AUSERNAME` and a
//! `Date` header are set like on every other harness answer.

use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_registry::{Method, OpClass, OperationSpec, StatusSet, SuccessBody};
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

/// `/rest/api/2/project` (`jira.issue.create` stage 1, PD-48).
pub const PROJECTS_PATH: &str = "/rest/api/2/project";

/// `/rest/api/2/issue/createmeta/{project}/issuetypes` (stage 2).
pub fn issuetypes_path(project: &str) -> String {
    format!("/rest/api/2/issue/createmeta/{project}/issuetypes")
}

/// `/rest/api/2/issue/createmeta/{project}/issuetypes/{type_id}` (stage 3, PD-49).
pub fn create_fields_path(project: &str, type_id: &str) -> String {
    format!("/rest/api/2/issue/createmeta/{project}/issuetypes/{type_id}")
}

/// The three enrichment answers of a `jira.issue.create` in `ABC` (`Alpha Beta`) with issue type
/// `Bug` (`10002`) and no missing required field.
pub async fn mount_create_stages(mock: &MockDc) {
    mock.json(PROJECTS_PATH, 200, fixtures::JIRA_PROJECTS).await;
    mock.json(
        &issuetypes_path("ABC"),
        200,
        fixtures::JIRA_CREATEMETA_ISSUETYPES,
    )
    .await;
    mock.json(
        &create_fields_path("ABC", "10002"),
        200,
        fixtures::JIRA_CREATEMETA_FIELDS,
    )
    .await;
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

/// `m p` answers `body` (200 JSON) **without** `X-AUSERNAME` and without `MockDc::response`'s
/// other headers: an answer that fails the §7.2 per-response identity check (T19, RF-5b).
pub async fn mount_without_xauser(mock: &MockDc, m: &str, p: &str, body: &str) {
    Mock::given(method(m))
        .and(path(mock.path(p)))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body.to_owned(), "application/json"))
        .mount(mock.server())
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

/// An issue as the previewer tests need it (T10): a parent, two issue links, a custom field,
/// `security: null`, no comments, no invisible characters (U-34's "default issue").
pub fn full_issue(key: &str) -> Value {
    json!({
        "id": "10007",
        "key": key,
        "self": "https://jira.corp.example/rest/api/2/issue/10007",
        "fields": {
            "summary": "Login page times out",
            "issuetype": {"id": "1", "name": "Bug"},
            "status": {"id": "3", "name": "In Progress"},
            "priority": {"id": "2", "name": "High"},
            "assignee": {"name": "jdoe", "key": "JIRAUSER1", "displayName": "Jane Doe"},
            "reporter": {"name": "asmith", "key": "JIRAUSER2", "displayName": "Alex Smith"},
            "description": "h1. Steps\n\nOpen the *login* page.",
            "labels": ["web"],
            "parent": {"id": "10001", "key": "ABC-1", "fields": {"summary": "Epic"}},
            "issuelinks": [
                {"id": "1", "type": {"name": "Blocks"}, "outwardIssue": {"key": "ABC-8"}},
                {"id": "2", "type": {"name": "Blocks"}, "inwardIssue": {"key": "ABC-9"}}
            ],
            "subtasks": [],
            "security": null,
            "customfield_10200": {"value": "Platform"}
        }
    })
}

/// A role restriction as Jira sends it on a restricted comment.
pub fn restriction() -> Value {
    json!({"type": "role", "value": "Administrators"})
}

/// `POST /rest/api/2/search` answers pages of `total` issues ABC-1.. from the body's
/// `startAt`/`maxResults`; each issue's `fields` is `fields(n)` for its zero-based number `n`.
pub async fn mount_search(
    mock: &MockDc,
    total: u64,
    fields: impl Fn(u64) -> Value + Send + Sync + 'static,
) {
    let ok = mock.response(200);
    Mock::given(method("POST"))
        .and(path(mock.path("/rest/api/2/search")))
        .respond_with(move |req: &wiremock::Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let start = body["startAt"].as_u64().unwrap_or(0);
            let max = body["maxResults"].as_u64().unwrap_or(50);
            let count = max.min(total.saturating_sub(start));
            let issues: Vec<Value> = (start..start + count)
                .map(|n| {
                    json!({
                        "id": (10_001 + n).to_string(),
                        "key": format!("ABC-{}", n + 1),
                        "self": format!("https://jira.corp.example/rest/api/2/issue/{}", 10_001 + n),
                        "fields": fields(n)
                    })
                })
                .collect();
            let page = json!({
                "startAt": start, "maxResults": max, "total": total, "issues": issues
            });
            ok.clone().set_body_raw(page.to_string(), "application/json")
        })
        .mount(mock.server())
        .await;
}

/// The `startAt` of every `POST /rest/api/2/search` the mock received, in arrival order.
pub async fn search_starts(mock: &MockDc) -> Vec<u64> {
    let full = mock.path("/rest/api/2/search");
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.url.path() == full && r.method.as_str() == "POST")
        .filter_map(|r| {
            serde_json::from_slice::<Value>(&r.body)
                .ok()
                .and_then(|b| b["startAt"].as_u64())
        })
        .collect()
}

// ---- X-09: mounts generated from the registry ------------------------------------------------------

/// `params_schema["examples"][0]`: the params X-09 submits.
pub fn example_params(spec: &OperationSpec) -> Value {
    spec.params_schema_json()["examples"][0].clone()
}

/// The registry's method as the wire name.
pub fn http_method(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
    }
}

/// `template` (`/rest/api/2/issue/{key}`) with each `{name}` replaced by `params[name]`.
pub fn fill_path(template: &str, params: &Value) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let (head, tail) = rest.split_at(open);
        out.push_str(head);
        let close = tail
            .find('}')
            .ok_or_else(|| format!("{template}: unclosed placeholder"))?;
        let name = tail.get(1..close).unwrap_or_default();
        let value = match &params[name] {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            other => {
                return Err(format!(
                    "{template}: no value for {name} in params ({other})"
                ));
            }
        };
        out.push_str(&value);
        rest = tail.get(close + 1..).unwrap_or_default();
    }
    out.push_str(rest);
    Ok(out)
}

/// A GET an op sends besides its own request (an enrichment, a resolution, a stale check, or the
/// second leg of a composite read): `path` answers `body`.
pub struct Aux {
    pub path: String,
    pub body: Value,
}

fn read_example(op_id: &str) -> Result<Value, String> {
    atlas_duck_registry::get(op_id)
        .map(|s| s.result_example_json())
        .ok_or_else(|| format!("no registry op {op_id}"))
}

fn str_param<'a>(params: &'a Value, name: &str) -> Result<&'a str, String> {
    params[name]
        .as_str()
        .ok_or_else(|| format!("example params have no string {name}"))
}

/// The enrichment and stale-check GETs of `spec` for `params`, each body the `result_example` of
/// the Jira read op that answers the same endpoint, so the fixtures cannot drift from the
/// registry. Every Jira op id is named here: an op that is not is an error (X-09 fails for a new
/// op until its GETs are decided, even when the decision is "none").
pub fn aux_gets(spec: &OperationSpec, params: &Value) -> Result<Vec<Aux>, String> {
    let issue = |params: &Value| -> Result<Aux, String> {
        let key = str_param(params, "key")?;
        Ok(Aux {
            path: issue_path(key),
            body: read_example("jira.issue.get")?,
        })
    };
    match spec.id {
        "jira.myself"
        | "jira.project.list"
        | "jira.project.get"
        | "jira.search"
        | "jira.comment.list"
        | "jira.worklog.list"
        | "jira.transition.list"
        | "jira.issue.editmeta"
        | "jira.createmeta.issuetypes"
        | "jira.createmeta.fields"
        | "jira.field.list"
        | "jira.issuelinktype.list"
        | "jira.attachment.meta"
        | "jira.user.assignable"
        | "jira.board.list"
        | "jira.sprint.list"
        | "jira.sprint.issues"
        | "jira.backlog.issues" => Ok(Vec::new()),
        // The composite read's second leg: the comment pages (T9).
        "jira.issue.get" => {
            if params["comments"] == json!(true) {
                let key = str_param(params, "key")?;
                Ok(vec![Aux {
                    path: comments_path(key),
                    body: read_example("jira.comment.list")?,
                }])
            } else {
                Ok(Vec::new())
            }
        }
        "jira.issue.create" => {
            let project = str_param(params, "project")?;
            let wanted = str_param(params, "issuetype")?;
            let types = read_example("jira.createmeta.issuetypes")?;
            let type_id = types["values"]
                .as_array()
                .and_then(|v| v.iter().find(|t| t["name"] == wanted))
                .and_then(|t| t["id"].as_str())
                .ok_or_else(|| format!("the issuetypes example has no {wanted}"))?
                .to_owned();
            Ok(vec![
                Aux {
                    path: PROJECTS_PATH.to_owned(),
                    body: read_example("jira.project.list")?,
                },
                Aux {
                    path: issuetypes_path(project),
                    body: types,
                },
                Aux {
                    path: create_fields_path(project, &type_id),
                    body: read_example("jira.createmeta.fields")?,
                },
            ])
        }
        "jira.issue.edit" => Ok(vec![issue(params)?]),
        "jira.issue.transition" => {
            let key = str_param(params, "key")?;
            Ok(vec![
                Aux {
                    path: format!("{}/transitions", issue_path(key)),
                    body: read_example("jira.transition.list")?,
                },
                issue(params)?,
            ])
        }
        "jira.issue.assign" => Ok(vec![
            Aux {
                path: "/rest/api/2/user/assignable/search".to_owned(),
                body: read_example("jira.user.assignable")?,
            },
            issue(params)?,
        ]),
        "jira.issuelink.create" => Ok(vec![Aux {
            path: "/rest/api/2/issueLinkType".to_owned(),
            body: read_example("jira.issuelinktype.list")?,
        }]),
        "jira.sprint.move_issues" => {
            let id = params["id"]
                .as_u64()
                .ok_or("example params have no sprint id")?;
            let sprints = read_example("jira.sprint.list")?;
            let sprint = sprints["values"]
                .as_array()
                .and_then(|v| v.iter().find(|s| s["id"] == id))
                .cloned()
                .ok_or_else(|| format!("the sprint.list example has no sprint {id}"))?;
            Ok(vec![Aux {
                path: format!("/rest/agile/1.0/sprint/{id}"),
                body: sprint,
            }])
        }
        // No enrichment and no stale rule: the identity call is the only GET.
        "jira.comment.add" | "jira.worklog.add" | "jira.backlog.move_issues" => Ok(Vec::new()),
        other => Err(format!(
            "{other}: no X-09 mount rule in common::jira::aux_gets (a new op needs its GETs decided)"
        )),
    }
}

/// A write's declared success (§7.2): `{[204], Empty}` is 204 without a body, `{[201], Empty}` is
/// 201 with an empty `text/html` body, JSON is 201 with the registry receipt example plus a
/// `self` link a projection must drop.
pub fn declared_success(mock: &MockDc, spec: &OperationSpec) -> ResponseTemplate {
    let status = match spec.success.statuses {
        StatusSet::Exactly(list) => list.first().copied().unwrap_or(200),
        StatusSet::Any2xx => 201,
    };
    match spec.success.body {
        SuccessBody::Empty if status == 204 => mock.response(204),
        SuccessBody::Empty => mock
            .response(status)
            .set_body_raw(String::new(), "text/html;charset=UTF-8"),
        SuccessBody::Json => {
            let mut body = spec.result_example_json();
            if let Some(m) = body.as_object_mut() {
                m.insert(
                    "self".into(),
                    json!("https://jira.example.invalid/rest/api/2/x/1"),
                );
            }
            json_answer(mock, status, &body)
        }
    }
}

/// Mounts everything `spec` needs to run once with `params`: the identity call, the GETs of
/// [`aux_gets`] and the op's own endpoint (a read answers its `result_example`, a write its
/// declared success). Returns the GETs it mounted.
pub async fn mount_for_op(
    mock: &MockDc,
    spec: &OperationSpec,
    params: &Value,
) -> Result<Vec<Aux>, String> {
    let aux = aux_gets(spec, params)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
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
