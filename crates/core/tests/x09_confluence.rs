#![cfg(feature = "testing")]
//! X-09 (Confluence half) and X-10 (Confluence gates), M7 Task 22. Every Confluence op of the
//! registry runs once against wiremock through the scripted approver, generated from the registry
//! like `x09_jira.rs`: no hand-written per-op fixture list. The params are
//! `params_schema["examples"][0]` plus the variants the first example does not reach; the mocks are
//! `common::confluence::mount_for_op` (the op's endpoint answers the server's form of its
//! `result_example` or its declared write success, and the enrichment, lookup, stale-check and
//! identity GETs answer bodies built from the `result_example` of the matching read op). A
//! Confluence op that `aux_gets` does not name makes the generator fail, so a new op cannot appear
//! without a decision about what it needs.
//!
//! * `x09_confluence_every_op_once`: submit, release (reads) or approve (writes), the released
//!   result validates against `result_schema` or the receipt equals the registry example, and the
//!   requests the instance saw match the spec's declared method, path, query and body source;
//!   every hit of a write has its records (I-19, `check_coverage_on`).
//! * `x09_confluence_writes_wait_for_approval` and
//!   `x09_confluence_reads_hold_their_result_until_released`: the gates of the same generated
//!   cases (nothing is sent before an approval, nothing is delivered before a release, a denial
//!   delivers and sends nothing).
//! * X-10: the version floor never hides a Confluence op and never puts a version string in an
//!   envelope.

mod common;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, UserKind, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_core::testing::Harness;
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_registry::{
    BodySource, OpClass, OperationSpec, Product, QueryValue, StatusSet, SuccessBody, Version,
};
use common::confluence::{
    Aux, REPLACE_ATTACHMENT_ID, aux_gets, is_replace, mount_for_op, own_request, server_answer,
};
use common::flows::check_coverage_on;
use common::jira::{example_params, fill_path, http_method};
use common::{TestError, TestResult, de, exit, json, request_id};
use serde_json::{Value, json as j};
use wiremock::Request;

const ALIAS: &str = "wiki";

/// One generated case: an op (or a variant of its example) and the params it runs with.
struct Case {
    label: String,
    spec: &'static OperationSpec,
    params: Value,
}

fn confluence_specs() -> Vec<&'static OperationSpec> {
    atlas_duck_registry::all()
        .iter()
        .filter(|s| s.product == Product::Confluence)
        .collect()
}

/// The variants the first example of an op does not reach, as `(op id, label, params edit)`.
type Variant = (&'static str, &'static str, fn(&mut Value));

const VARIANTS: [Variant; 6] = [
    ("confluence.page.get", "format=storage", |p| {
        p["format"] = j!("storage");
    }),
    ("confluence.page.get", "format=view", |p| {
        p["format"] = j!("view");
    }),
    ("confluence.page.history", "version", |p| {
        p["version"] = j!(2);
    }),
    ("confluence.attachment.upload", "replace", |p| {
        p["replace"] = j!(true);
    }),
    // The example names a parent; the page also goes to the space root.
    ("confluence.page.create", "no parent", |p| {
        if let Some(m) = p.as_object_mut() {
            m.remove("parent");
        }
    }),
    ("confluence.comment.add", "reply_to", |p| {
        p["reply_to"] = j!("789");
    }),
];

/// One case per Confluence op id (its first example), then its variants.
fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for spec in confluence_specs() {
        out.push(Case {
            label: spec.id.to_owned(),
            spec,
            params: example_params(spec),
        });
        for (id, name, edit) in VARIANTS {
            if id == spec.id {
                let mut params = example_params(spec);
                edit(&mut params);
                out.push(Case {
                    label: format!("{} [{name}]", spec.id),
                    spec,
                    params,
                });
            }
        }
    }
    out
}

/// Spec §7.4, transcribed: op id, method and path template. An oracle independent of the
/// registry, so a wrong endpoint in the registry fails here instead of agreeing with itself.
const SPEC_ENDPOINTS: [(&str, &str, &str); 18] = [
    ("confluence.user.current", "GET", "/rest/api/user/current"),
    ("confluence.space.list", "GET", "/rest/api/space"),
    ("confluence.space.get", "GET", "/rest/api/space/{key}"),
    ("confluence.page.get", "GET", "/rest/api/content/{id}"),
    ("confluence.page.find", "GET", "/rest/api/content"),
    ("confluence.search", "GET", "/rest/api/search"),
    (
        "confluence.page.children",
        "GET",
        "/rest/api/content/{id}/child/page",
    ),
    (
        "confluence.comment.list",
        "GET",
        "/rest/api/content/{id}/child/comment",
    ),
    (
        "confluence.label.list",
        "GET",
        "/rest/api/content/{id}/label",
    ),
    (
        "confluence.attachment.list",
        "GET",
        "/rest/api/content/{id}/child/attachment",
    ),
    (
        "confluence.page.history",
        "GET",
        "/rest/api/content/{id}/history",
    ),
    ("confluence.page.create", "POST", "/rest/api/content"),
    ("confluence.page.update", "PUT", "/rest/api/content/{id}"),
    ("confluence.page.move", "PUT", "/rest/api/content/{id}"),
    ("confluence.comment.add", "POST", "/rest/api/content"),
    (
        "confluence.label.add",
        "POST",
        "/rest/api/content/{id}/label",
    ),
    (
        "confluence.label.remove",
        "DELETE",
        "/rest/api/content/{id}/label/{label}",
    ),
    (
        "confluence.attachment.upload",
        "POST",
        "/rest/api/content/{id}/child/attachment",
    ),
];

/// §7.4: `page.history` with `version` is `GET /rest/api/content/{id}?version=n&status=
/// historical&expand=body.storage,version`.
const HISTORY_VERSION_ENDPOINT: (&str, &str) = ("GET", "/rest/api/content/{id}");

/// The oracle's method and path template of `op_id`.
fn spec_endpoint(op_id: &str) -> Result<(&'static str, &'static str), String> {
    SPEC_ENDPOINTS
        .iter()
        .find(|(id, _, _)| *id == op_id)
        .map(|(_, m, p)| (*m, *p))
        .ok_or_else(|| format!("{op_id} is not in the spec's endpoint table"))
}

fn s(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}

/// A started Confluence harness with `case`'s mounts, and the GETs those mounts answer.
async fn start(case: &Case) -> Result<(Harness, Vec<Aux>), String> {
    let h = Harness::confluence().await.map_err(s)?;
    let mock = h.mock(ALIAS).ok_or("no confluence mock")?;
    let aux = mount_for_op(mock, case.spec, &case.params).await?;
    Ok((h, aux))
}

/// Submits `case` and waits until it is queued for the human.
async fn submit_queued(h: &Harness, case: &Case) -> Result<String, String> {
    let env = h.submit(case.spec.id, case.params.clone()).await;
    if env.status != Status::Pending {
        return Err(format!("not pending: {}", env.to_json_line()));
    }
    let id = request_id(&env).map_err(s)?;
    h.queued(&id, 20_000)
        .await
        .ok_or_else(|| format!("{id} never queued"))?;
    Ok(id)
}

fn validates(schema: &Value, value: &Value) -> Result<(), String> {
    let validator = jsonschema::validator_for(schema).map_err(s)?;
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|e| e.to_string())
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// The query value a param is sent as, for the scalar kinds (arrays are joined by the op).
fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn query_of(r: &Request, name: &str) -> Option<String> {
    r.url
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// Every whole value a request carries: its path segments, its query values, the scalar leaves of
/// a JSON body and the file names of a multipart one. A target param must be one of these, not a
/// substring of the URL or the body.
fn wire_values(r: &Request, body_text: &str) -> Vec<String> {
    fn leaves(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Array(a) => a.iter().for_each(|x| leaves(x, out)),
            Value::Object(m) => m.values().for_each(|x| leaves(x, out)),
            other => out.extend(scalar(other)),
        }
    }
    let mut out: Vec<String> = r
        .url
        .path_segments()
        .map(|s| s.map(str::to_owned).collect())
        .unwrap_or_default();
    out.extend(r.url.query_pairs().map(|(_, v)| v.into_owned()));
    if let Ok(body) = serde_json::from_str::<Value>(body_text) {
        leaves(&body, &mut out);
    }
    for part in body_text.split("filename=\"").skip(1) {
        if let Some((name, _)) = part.split_once('"') {
            out.push(name.to_owned());
        }
    }
    out
}

/// The registry endpoint the case's own request uses: the alternative one for `page.history`
/// with `version`.
fn used_endpoint(case: &Case) -> atlas_duck_registry::Endpoint {
    match case.spec.alt_endpoint {
        Some(alt) if !case.params[alt.when_param_present].is_null() => alt.endpoint,
        _ => case.spec.endpoint,
    }
}

/// The `expand` of a `page.get` in the case's format (PD-100: `view` swaps the body expand).
fn expected_const<'a>(case: &Case, name: &str, declared: &'a str) -> &'a str {
    if case.spec.id == "confluence.page.get" && name == "expand" && case.params["format"] == "view"
    {
        common::confluence::PAGE_EXPAND_VIEW
    } else {
        declared
    }
}

/// The requests the instance received for `case`: method and path against the spec's table,
/// query and body against the registry's declaration.
async fn check_shape(
    case: &Case,
    mock: &MockDc,
    aux: &[Aux],
    response: Option<&Value>,
) -> Result<(), String> {
    let spec = case.spec;
    let ep = used_endpoint(case);
    // The oracle's method and path of the request the case sends.
    let (spec_method, spec_path) = if ep.path == spec.endpoint.path {
        spec_endpoint(spec.id)?
    } else {
        HISTORY_VERSION_ENDPOINT
    };
    if spec_method != http_method(ep.method) || spec_path != ep.path {
        return Err(format!(
            "registry endpoint {} {} differs from the spec's {spec_method} {spec_path}",
            http_method(ep.method),
            ep.path
        ));
    }
    let replace = spec.id == "confluence.attachment.upload" && is_replace(&case.params);
    let (method, path_template) = own_request(spec, &case.params)?;
    if method != spec_method {
        return Err(format!(
            "the case sends {method}, the spec says {spec_method}"
        ));
    }
    let own_path = mock.path(&path_template);
    let hits = mock.received().await;
    let own: Vec<&Request> = hits
        .iter()
        .filter(|r| r.method.as_str() == method && r.url.path() == own_path)
        .collect();
    let [r] = own.as_slice() else {
        return Err(format!(
            "{} requests {method} {own_path}, wanted exactly one",
            own.len()
        ));
    };
    // Nothing else was asked: the identity call and the mounted GETs only.
    let identity = mock.path("/rest/api/user/current");
    for h in &hits {
        let known = (h.method.as_str() == method && h.url.path() == own_path)
            || (h.method.as_str() == "GET"
                && (h.url.path() == identity
                    || aux.iter().any(|a| mock.path(&a.path) == h.url.path())));
        if !known {
            return Err(format!("unexpected request {} {}", h.method, h.url.path()));
        }
    }
    // Every GET the generator mounted was used, or its mount would prove nothing.
    for a in aux {
        let full = mock.path(&a.path);
        if !hits
            .iter()
            .any(|h| h.method.as_str() == "GET" && h.url.path() == full)
        {
            return Err(format!("the mounted GET {} was never asked", a.path));
        }
    }
    // Query: the declared pairs, with values from the params; no other name but the pager's and
    // the upload's `allowDuplicated`.
    let mut allowed: Vec<&str> = ep.query.iter().map(|q| q.name).collect();
    if let Some(p) = spec.paginated {
        allowed.push(p.offset_param);
        allowed.push(p.limit_param);
    }
    if spec.id == "confluence.attachment.upload" {
        allowed.push("allowDuplicated");
    }
    for (name, _) in r.url.query_pairs() {
        if !allowed.contains(&name.as_ref()) {
            return Err(format!("undeclared query parameter {name}"));
        }
    }
    for q in ep.query {
        let got = query_of(r, q.name);
        match q.value {
            QueryValue::Const(c) => {
                let want = expected_const(case, q.name, c);
                if got.as_deref() != Some(want) {
                    return Err(format!("query {}: {got:?}, declared const {want}", q.name));
                }
            }
            // The rewritten CQL wraps the agent's (U-31): the agent's text is in it.
            QueryValue::Param("cql") => {
                let want = scalar(&case.params["cql"]).ok_or("no cql param")?;
                if !got.as_deref().is_some_and(|g| g.contains(want.as_str())) {
                    return Err(format!("query cql: {got:?} does not carry {want}"));
                }
            }
            QueryValue::Param(p) => {
                if let Some(want) = scalar(&case.params[p])
                    && got.as_deref() != Some(want.as_str())
                {
                    return Err(format!("query {}: {got:?}, param {p} is {want}", q.name));
                }
            }
            QueryValue::ParamOr { param, default } => {
                let want = scalar(&case.params[param]).unwrap_or_else(|| default.to_owned());
                if got.as_deref() != Some(want.as_str()) {
                    return Err(format!("query {}: {got:?}, wanted {want}", q.name));
                }
            }
            QueryValue::ParamBoolFlag {
                param,
                value_if_true,
            } => {
                let want = (case.params[param] == j!(true)).then_some(value_if_true);
                if got.as_deref() != want {
                    return Err(format!("query {}: {got:?}, wanted {want:?}", q.name));
                }
            }
        }
    }
    if spec.id == "confluence.attachment.upload" {
        // PD-109: a new attachment never overwrites one (`allowDuplicated=false`); a replace goes
        // to the attachment's own `/data` endpoint.
        let want = (!replace).then_some("false");
        if query_of(r, "allowDuplicated").as_deref() != want {
            return Err(format!(
                "allowDuplicated {:?}, wanted {want:?}",
                query_of(r, "allowDuplicated")
            ));
        }
        if replace != own_path.ends_with(&format!("/{REPLACE_ATTACHMENT_ID}/data")) {
            return Err(format!("replace is {replace}, the path is {own_path}"));
        }
    }
    // Body: the declared source. A write's target params reach the wire (path, query or body).
    let content_type = r
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let body_text = String::from_utf8_lossy(&r.body).into_owned();
    match ep.body {
        BodySource::None if !r.body.is_empty() => {
            return Err(format!(
                "a body of {} bytes on a bodiless endpoint",
                r.body.len()
            ));
        }
        BodySource::None => {
            if !content_type.is_empty() {
                return Err(format!("content-type {content_type:?} without a body"));
            }
        }
        BodySource::ParamsAsJson | BodySource::OpSpecific
            if content_type.starts_with("multipart/form-data") =>
        {
            if spec.id != "confluence.attachment.upload" {
                return Err(format!("a multipart body for {}", spec.id));
            }
            let filename = scalar(&case.params["filename"]).ok_or("no filename param")?;
            if !body_text.contains(&format!("filename=\"{filename}\"")) {
                return Err("the multipart body has no file part of that name".to_owned());
            }
        }
        BodySource::ParamsAsJson | BodySource::OpSpecific => {
            let body: Value = serde_json::from_slice(&r.body).map_err(|e| format!("body: {e}"))?;
            let empty = match &body {
                Value::Object(m) => m.is_empty(),
                Value::Array(a) => a.is_empty(),
                _ => true,
            };
            if empty {
                return Err(format!("body is not a non-empty object or array: {body}"));
            }
            if !content_type.starts_with("application/json") {
                return Err(format!("content-type {content_type:?}"));
            }
        }
    }
    let wire = wire_values(r, &body_text);
    for t in spec.target_params {
        let values: Vec<String> = match &case.params[*t] {
            Value::Array(a) => a.iter().filter_map(scalar).collect(),
            other => scalar(other).into_iter().collect(),
        };
        for v in values {
            if !wire.contains(&v) {
                return Err(format!(
                    "target param {t}={v} is not a path segment, query value, body value or file \
                     name of the request: {wire:?}"
                ));
            }
        }
    }
    // The agent's labels are the body of `label.add`, in its order.
    if spec.id == "confluence.label.add" {
        let body: Value = serde_json::from_slice(&r.body).map_err(|e| format!("body: {e}"))?;
        let sent: Vec<&str> = body
            .as_array()
            .map(|a| a.iter().filter_map(|l| l["name"].as_str()).collect())
            .unwrap_or_default();
        let want: Vec<&str> = case.params["labels"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if sent != want {
            return Err(format!("labels sent {sent:?}, the agent wrote {want:?}"));
        }
    }
    // The answer the instance gave a write is what real DC answers (V06), and the registry's
    // declared success covers it, in status and shape.
    if let (OpClass::Write, Some(response)) = (spec.class, response) {
        check_declared_success(spec, response)?;
    }
    Ok(())
}

/// Spec §7.2/V06: the status real Confluence DC answers each write with, typed here and not taken
/// from the registry (which declares `Any2xx` for the JSON writes, so its set cannot say which).
const DC_WRITE_STATUS: [(&str, u16); 7] = [
    ("confluence.page.create", 200),
    ("confluence.page.update", 200),
    ("confluence.page.move", 200),
    ("confluence.comment.add", 200),
    ("confluence.label.add", 200),
    ("confluence.label.remove", 204),
    ("confluence.attachment.upload", 200),
];

fn dc_write_status(op_id: &str) -> Result<u16, String> {
    DC_WRITE_STATUS
        .iter()
        .find(|(id, _)| *id == op_id)
        .map(|(_, st)| *st)
        .ok_or_else(|| format!("{op_id} has no real DC write status in DC_WRITE_STATUS"))
}

/// The registry declares `status` (and the `Empty`/`Json` shape) as `spec`'s success.
fn declares(spec: &OperationSpec, status: u16) -> bool {
    match spec.success.statuses {
        StatusSet::Exactly(list) => list.contains(&status),
        StatusSet::Any2xx => (200..300).contains(&status),
    }
}

/// `response` is the `WRITE_EXECUTED` response of `spec`: exactly the status real DC answers, a
/// status the registry declares (a registry that contradicts real DC fails here, reported, not
/// edited), and the declared body shape (empty text for `Empty`, a JSON object for `Json`).
fn check_declared_success(spec: &OperationSpec, response: &Value) -> Result<(), String> {
    let want = dc_write_status(spec.id)?;
    if !declares(spec, want) {
        return Err(format!(
            "the registry's declared success {:?} does not cover the {want} real DC answers",
            spec.success.statuses
        ));
    }
    let got = response["status"].as_u64();
    if got != Some(u64::from(want)) {
        return Err(format!(
            "WRITE_EXECUTED recorded status {got:?}, real DC answers {want}"
        ));
    }
    let text = response["body"]["text"].as_str();
    match spec.success.body {
        SuccessBody::Empty if text == Some("") || response["body"]["b64"].as_str() == Some("") => {
            Ok(())
        }
        SuccessBody::Empty => Err(format!("a declared empty success recorded {response}")),
        SuccessBody::Json => {
            let json_type = response["content_type"]
                .as_str()
                .is_some_and(|c| c.contains("json"));
            let object = text
                .and_then(|t| serde_json::from_str::<Value>(t).ok())
                .is_some_and(|v| v.is_object());
            if json_type && object {
                Ok(())
            } else {
                Err(format!("a declared JSON success recorded {response}"))
            }
        }
    }
}

/// What a read releases: the body its mock answers, except that a Markdown page body is the
/// registry example's converted one (the answer holds the storage it is the release of, Δ4 f), and
/// that `format: storage|view` release the server's body as sent (PD-100).
fn expected_read(case: &Case) -> Result<Value, String> {
    let spec = case.spec;
    let as_sent = spec.id == "confluence.page.get" && case.params["format"] != j!(null);
    if as_sent && case.params["format"] != j!("markdown") {
        return server_answer(spec, &case.params);
    }
    if spec.id == "confluence.page.history" && !case.params["version"].is_null() {
        // The historical content is released as a page: the `page.get` example.
        return atlas_duck_registry::get("confluence.page.get")
            .map(OperationSpec::result_example_json)
            .ok_or_else(|| "no confluence.page.get".to_owned());
    }
    Ok(spec.result_example_json())
}

/// Runs `case` once and checks its outcome and the wire.
async fn run_case(case: &Case) -> Result<(), String> {
    let spec = case.spec;
    let (h, aux) = start(case).await?;
    let id = submit_queued(&h, case).await?;
    let mut write_response = None;
    match spec.class {
        OpClass::Read => {
            h.approver().release(&id).map_err(|e| s(de(e)))?;
            let env = h.await_(&id, 10_000).await;
            if (env.status, exit(&env)) != (Status::Released, 0) {
                return Err(format!("not released: {}", env.to_json_line()));
            }
            let result = env
                .data
                .as_ref()
                .map(|d| d["result"].clone())
                .ok_or("no data")?;
            validates(&spec.result_schema_json(), &result)
                .map_err(|e| format!("released result: {e}"))?;
            if spec.id == "confluence.user.current" {
                // The identity mock (same path, mounted first) answers this read: the released
                // result is that identity, not the registry example.
                if result["username"] != TEST_USER || result["userKey"] != TEST_USER_KEY {
                    return Err(format!("confluence.user.current released {result}"));
                }
            } else {
                let want = expected_read(case)?;
                if result != want {
                    return Err(format!(
                        "released result {result}, the instance answered {want}"
                    ));
                }
            }
        }
        OpClass::Write => {
            // Nothing is on the wire while the write waits (I-4): a short continuous watch
            // before the approval.
            let mock = h.mock(ALIAS).ok_or("no confluence mock")?;
            let held = mock.received().await.len();
            watch_wire(mock, held, 150).await?;
            h.approver().approve(&id).map_err(|e| s(de(e)))?;
            let env = h.await_(&id, 10_000).await;
            if (env.status, exit(&env)) != (Status::Succeeded, 0) {
                return Err(format!("not succeeded: {}", env.to_json_line()));
            }
            let receipt = env
                .data
                .as_ref()
                .map(|d| d["receipt"].clone())
                .ok_or("no data")?;
            if receipt != spec.result_example_json() {
                return Err(format!(
                    "receipt {receipt}, registry example {}",
                    spec.result_example
                ));
            }
            let executed = h.events(&id).await.map_err(s)?;
            let payload = executed
                .iter()
                .find(|(t, _)| *t == EventType::WRITE_EXECUTED)
                .map(|(_, p)| p.clone())
                .ok_or("no WRITE_EXECUTED record")?;
            if payload["response"]["status"].as_u64().is_none() {
                return Err(format!("WRITE_EXECUTED without a status: {payload}"));
            }
            write_response = Some(payload["response"].clone());
            // I-19 (T30 review M-1): every hit of the write (its enrichment, lookup, identity and
            // stale-check GETs and its own request) has its covering and response records, so
            // `page.create`, `comment.add`, `label.add` and a replace upload are checked too.
            let covered = check_coverage_on(&h, ALIAS)
                .await
                .map_err(|e| format!("I-19: {e}"))?;
            if covered <= aux.len() {
                return Err(format!(
                    "I-19: only {covered} authenticated hits for {} GETs",
                    aux.len()
                ));
            }
        }
    }
    let mock = h.mock(ALIAS).ok_or("no confluence mock")?;
    check_shape(case, mock, &aux, write_response.as_ref()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x09_confluence_every_op_once() -> TestResult {
    let all = cases();
    // One case per op, plus its variants.
    assert_eq!(
        all.len(),
        confluence_specs().len() + VARIANTS.len(),
        "the case list lost or gained an op"
    );
    let mut failed = Vec::new();
    for case in &all {
        match run_case(case).await {
            Ok(()) => println!("X09 {} ok", case.label),
            Err(e) => failed.push(format!("{}: {e}", case.label)),
        }
    }
    // Every Confluence op id has its case, and the ids are the registry's.
    for spec in confluence_specs() {
        assert!(
            all.iter().any(|c| c.spec.id == spec.id),
            "{} has no case",
            spec.id
        );
    }
    assert!(
        failed.is_empty(),
        "{} of {} cases failed:\n{}",
        failed.len(),
        all.len(),
        failed.join("\n")
    );
    Ok(())
}

/// The generator itself: every op's examples validate against its own schemas, every op has its
/// mount rule, and an op the rules do not name fails instead of being skipped.
#[test]
fn x09_confluence_generator_covers_the_registry() -> TestResult {
    let specs = confluence_specs();
    assert_eq!(
        specs.len(),
        18,
        "the Confluence catalog is 18 ops (spec §7.4)"
    );
    // The registry's endpoints are the spec's (§7.4), op for op.
    assert_eq!(
        SPEC_ENDPOINTS.len(),
        specs.len(),
        "the oracle and the registry list other ops"
    );
    for spec in &specs {
        let (m, p) = spec_endpoint(spec.id)?;
        assert_eq!(
            (http_method(spec.endpoint.method), spec.endpoint.path),
            (m, p),
            "{}: registry endpoint differs from spec §7.4",
            spec.id
        );
        assert_eq!(
            spec.alt_endpoint.is_some(),
            spec.id == "confluence.page.history",
            "{}: only page.history has an alternative endpoint",
            spec.id
        );
    }
    // Every write has its real DC status (typed here and in the mock's `real_dc_status`, which
    // must agree), and the registry's declared success covers it, in status and body shape.
    let writes: Vec<_> = specs.iter().filter(|s| s.class == OpClass::Write).collect();
    assert_eq!(
        writes.len(),
        DC_WRITE_STATUS.len(),
        "a write without a DC status"
    );
    for spec in writes {
        let want = dc_write_status(spec.id)?;
        assert_eq!(
            common::confluence::real_dc_status(spec)?,
            want,
            "{}: the mock answers another status than real DC",
            spec.id
        );
        assert!(
            declares(spec, want),
            "{}: the registry declares {:?}, real DC answers {want}",
            spec.id,
            spec.success.statuses
        );
        assert_eq!(
            spec.success.body == SuccessBody::Empty,
            want == 204,
            "{}: the declared body shape and the status disagree",
            spec.id
        );
    }
    let history = atlas_duck_registry::get("confluence.page.history").ok_or("no page.history")?;
    let alt = history
        .alt_endpoint
        .ok_or("page.history has no alt endpoint")?;
    assert_eq!(alt.when_param_present, "version");
    assert_eq!(
        (http_method(alt.endpoint.method), alt.endpoint.path),
        HISTORY_VERSION_ENDPOINT
    );
    for spec in &specs {
        let params = example_params(spec);
        validates(&spec.params_schema_json(), &params)
            .map_err(|e| format!("{} params example: {e}", spec.id))?;
        validates(&spec.result_schema_json(), &spec.result_example_json())
            .map_err(|e| format!("{} result example: {e}", spec.id))?;
        validates(
            &spec.result_schema_json(),
            &spec.result_example_sparse_json(),
        )
        .map_err(|e| format!("{} sparse example: {e}", spec.id))?;
        aux_gets(spec, &params)?;
        own_request(spec, &params)?;
        fill_path(spec.endpoint.path, &params)?;
    }
    // Every variant's params validate against the op's params schema, and its mount rule is
    // decided.
    for case in cases() {
        validates(&case.spec.params_schema_json(), &case.params)
            .map_err(|e| format!("{} params: {e}", case.label))?;
        aux_gets(case.spec, &case.params)?;
    }
    let spec = |id: &str| atlas_duck_registry::get(id).ok_or(format!("no {id}"));
    // The variants reach their further legs: a replace looks the attachment up by its name, a
    // reply reads the comment too, a page without a parent has no parent GET, and a history
    // `version` is the one call of the alternative endpoint.
    let upload = spec("confluence.attachment.upload")?;
    let mut params = example_params(upload);
    let new = aux_gets(upload, &params)?;
    assert_eq!(new.len(), 1);
    assert_eq!(new[0].body["results"], j!([]));
    params["replace"] = j!(true);
    let found = aux_gets(upload, &params)?;
    assert_eq!(found[0].body["results"][0]["title"], params["filename"]);
    assert_eq!(found[0].body["results"][0]["id"], REPLACE_ATTACHMENT_ID);
    assert!(own_request(upload, &params)?.1.ends_with("/att3001/data"));
    let comment = spec("confluence.comment.add")?;
    let mut params = example_params(comment);
    assert_eq!(aux_gets(comment, &params)?.len(), 1);
    params["reply_to"] = j!("789");
    assert_eq!(aux_gets(comment, &params)?.len(), 2);
    let create = spec("confluence.page.create")?;
    let mut params = example_params(create);
    assert_eq!(aux_gets(create, &params)?.len(), 3);
    if let Some(m) = params.as_object_mut() {
        m.remove("parent");
    }
    assert_eq!(aux_gets(create, &params)?.len(), 2);
    let mut params = example_params(history);
    assert_eq!(
        own_request(history, &params)?.1,
        "/rest/api/content/123456/history"
    );
    params["version"] = j!(2);
    assert_eq!(own_request(history, &params)?.1, "/rest/api/content/123456");
    // An op id the rules do not know is an error, not a silent skip.
    let unknown = OperationSpec {
        id: "confluence.not.listed",
        ..*upload
    };
    assert!(aux_gets(&unknown, &example_params(upload)).is_err());
    Ok(())
}

/// Polls the mock every 20 ms for `ms`: no request but GETs, and no request at all beyond the
/// `held` ones that were there when the request was queued. A write sent late by a task that
/// outlives a snapshot is seen by a later poll.
async fn watch_wire(mock: &MockDc, held: usize, ms: u64) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(ms);
    loop {
        let hits = mock.received().await;
        if let Some(r) = hits.iter().find(|r| r.method.as_str() != "GET") {
            return Err(format!("{} {} was sent", r.method, r.url.path()));
        }
        if hits.len() != held {
            return Err(format!(
                "{} requests on the wire, {held} when queued",
                hits.len()
            ));
        }
        if tokio::time::Instant::now() > deadline {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Gate: a write is held for the human: nothing is sent while it waits (watched at every poll of
/// the wait), and a denial sends nothing and records no execution.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x09_confluence_writes_wait_for_approval() -> TestResult {
    let mut failed = Vec::new();
    let writes: Vec<Case> = cases()
        .into_iter()
        .filter(|c| c.spec.class == OpClass::Write)
        .collect();
    assert!(writes.len() >= 7, "{} write cases", writes.len());
    for case in &writes {
        let run = async {
            let (h, _) = start(case).await?;
            let id = submit_queued(&h, case).await?;
            let mock = h.mock(ALIAS).ok_or("no confluence mock")?;
            // Every poll of the whole wait: no write, and no request of any kind beyond the
            // reads the preview needed (a task that sends late is caught by a later poll).
            let held = mock.received().await.len();
            watch_wire(mock, held, 400)
                .await
                .map_err(|e| format!("before the decision: {e}"))?;
            h.approver().deny(&id, "no").map_err(|e| s(de(e)))?;
            let env = h.await_(&id, 10_000).await;
            if env.status != Status::Denied {
                return Err(format!("not denied: {}", env.to_json_line()));
            }
            watch_wire(mock, held, 300)
                .await
                .map_err(|e| format!("after a denial: {e}"))?;
            let types = h.event_types(&id).await.map_err(s)?;
            if types.iter().any(|t| {
                matches!(
                    *t,
                    EventType::WRITE_APPROVED | EventType::WRITE_EXECUTED | EventType::WRITE_FAILED
                )
            }) {
                return Err(format!("a denied write left {types:?}"));
            }
            Ok::<(), String>(())
        };
        if let Err(e) = run.await {
            failed.push(format!("{}: {e}", case.label));
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
    Ok(())
}

/// Every string of `v` that is long enough to be distinctive and is not in `params`.
fn marker_strings(v: &Value, params: &str, out: &mut Vec<String>) {
    match v {
        Value::String(t) if t.len() >= 6 && !params.contains(t.as_str()) => out.push(t.clone()),
        Value::Array(a) => a.iter().for_each(|x| marker_strings(x, params, out)),
        Value::Object(m) => m.values().for_each(|x| marker_strings(x, params, out)),
        _ => {}
    }
}

fn envelope_text(env: &Envelope) -> Result<String, TestError> {
    Ok(json(env)?.to_string())
}

/// What the instance answered `case`'s read, as far as the agent must not see it before a
/// release: the distinctive strings of the body the mock serves ([`server_answer`], decoded, so
/// the storage XML of a page and not the Markdown of its example), and for `user.current` the
/// identity the identity mock serves. The op id and the params are the agent's own words and are
/// left out (`comment` is a `type` value and sits in the op id).
fn answer_markers(case: &Case) -> Result<Vec<String>, String> {
    let own = format!("{} {}", case.spec.id, case.params);
    let mut markers = Vec::new();
    if case.spec.id == "confluence.user.current" {
        markers.push(TEST_USER.to_owned());
        markers.push(TEST_USER_KEY.to_owned());
    } else {
        marker_strings(&server_answer(case.spec, &case.params)?, &own, &mut markers);
        marker_strings(&case.spec.result_example_json(), &own, &mut markers);
    }
    markers.sort();
    markers.dedup();
    if markers.is_empty() {
        return Err("the answer has no distinctive string to look for".to_owned());
    }
    Ok(markers)
}

/// The first marker that is part of a string value of `v`, compared decoded (a quote or a line
/// break in a value is not JSON-escaped here).
fn find_marker<'a>(v: &Value, markers: &'a [String]) -> Option<&'a String> {
    match v {
        Value::String(t) => markers.iter().find(|m| t.contains(m.as_str())),
        Value::Array(a) => a.iter().find_map(|x| find_marker(x, markers)),
        Value::Object(m) => m.values().find_map(|x| find_marker(x, markers)),
        _ => None,
    }
}

/// `env` carries none of `markers`.
fn no_answer(markers: &[String], env: &Envelope, what: &str) -> Result<(), String> {
    let v = json(env).map_err(s)?;
    match find_marker(&v, markers) {
        Some(m) => Err(format!("{what} carries the instance's answer ({m})")),
        None => Ok(()),
    }
}

/// Gate: a read's bytes reach the agent only through a release: the pending and the denied
/// envelope carry none of the instance's answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x09_confluence_reads_hold_their_result_until_released() -> TestResult {
    let mut failed = Vec::new();
    let reads: Vec<Case> = cases()
        .into_iter()
        .filter(|c| c.spec.class == OpClass::Read)
        .collect();
    assert!(reads.len() >= 11, "{} read cases", reads.len());
    for case in &reads {
        let run = async {
            let markers = answer_markers(case)?;
            let (h, _) = start(case).await?;
            let env = h.submit(case.spec.id, case.params.clone()).await;
            if env.status != Status::Pending {
                return Err(format!("not pending: {}", env.to_json_line()));
            }
            no_answer(&markers, &env, "the submit envelope")?;
            let id = request_id(&env).map_err(s)?;
            h.queued(&id, 20_000).await.ok_or("never queued")?;
            // The read is fetched and waits for the human: `await` (bounded) and `status` answer
            // pending and carry nothing of the instance's answer.
            let waiting = h.await_(&id, 300).await;
            if waiting.status != Status::Pending || waiting.data.is_some() {
                return Err(format!(
                    "await while queued is not a data-free pending: {}",
                    waiting.to_json_line()
                ));
            }
            no_answer(&markers, &waiting, "await while queued")?;
            let status = h.status(&id).await;
            if status.data.is_some() {
                return Err(format!(
                    "status while queued has data: {}",
                    status.to_json_line()
                ));
            }
            no_answer(&markers, &status, "status while queued")?;
            h.approver().deny(&id, "no").map_err(|e| s(de(e)))?;
            let denied = h.await_(&id, 10_000).await;
            if denied.status != Status::Denied {
                return Err(format!("not denied: {}", denied.to_json_line()));
            }
            no_answer(&markers, &denied, "the denied envelope")?;
            // Control: the same markers are in the envelope of a release, so a clean envelope
            // above is not a marker that cannot match.
            let (h2, _) = start(case).await?;
            let id2 = submit_queued(&h2, case).await?;
            h2.approver().release(&id2).map_err(|e| s(de(e)))?;
            let released = h2.await_(&id2, 10_000).await;
            if released.status != Status::Released {
                return Err(format!("not released: {}", released.to_json_line()));
            }
            if find_marker(&json(&released).map_err(s)?, &markers).is_none() {
                return Err(format!(
                    "no marker {markers:?} in the released envelope: the gate's markers do not \
                     match what a release carries"
                ));
            }
            Ok::<(), String>(())
        };
        if let Err(e) = run.await {
            failed.push(format!("{}: {e}", case.label));
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
    Ok(())
}

/// Gate: an op the registry does not list is refused as `usage` before any request is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x10_confluence_unlisted_ops_are_refused() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = h.mock(ALIAS).ok_or("no confluence mock")?;
    for id in [
        "confluence.page.delete",
        "confluence.comment.delete",
        "confluence.attachment.delete",
        "confluence.space.create",
        "confluence.label.set",
    ] {
        assert!(atlas_duck_registry::get(id).is_none(), "{id} is registered");
        let env = h.submit(id, j!({"id": "123456"})).await;
        assert_eq!(common::code(&env), "usage", "{id}: {}", env.to_json_line());
        assert_eq!(exit(&env), 2, "{id}");
    }
    assert!(
        mock.received().await.is_empty(),
        "an unlisted op reached the instance"
    );
    Ok(())
}

/// A harness whose Confluence instance reports `version`, with the connection test run once. The
/// version the test recorded is asserted, so a floor test cannot pass because nothing was cached.
async fn harness_at(version: &str) -> Result<Harness, TestError> {
    let h = Harness::confluence().await?;
    let mock = h.mock(ALIAS).ok_or("no confluence mock")?;
    // The fixture set's identity key is not the harness user's (the connection test would refuse
    // it as `OtherUser`): the same user the harness stored, the applinks manifest of `version`,
    // and the page the envelope test reads.
    mock.confluence_user_current(UserKind::Known, TEST_USER, TEST_USER_KEY)
        .await;
    mock.applinks_manifest(version).await;
    mock.json("/rest/api/content/65537", 200, fixtures::CONFLUENCE_PAGE)
        .await;
    h.instances()
        .retest_token(ALIAS)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let recorded = h.instance_version(ALIAS).ok_or("no version recorded")?;
    assert_eq!(
        format!("{}.{}.{}", recorded.major, recorded.minor, recorded.patch),
        version,
        "the connection test recorded another version"
    );
    Ok(h)
}

/// A structured version field in `v`: a non-null `min_version`, `instance_version` or
/// `server_version`, or an object that is a version (`major`, `minor` and `patch`). A version that
/// leaks as numbers carries no `7.9` text, so the text check alone would miss it.
fn version_field(v: &Value) -> Option<String> {
    match v {
        Value::Object(m) => {
            if ["min_version", "instance_version", "server_version"]
                .iter()
                .any(|k| m.get(*k).is_some_and(|x| !x.is_null()))
                || ["major", "minor", "patch"]
                    .iter()
                    .all(|k| m.contains_key(*k))
            {
                return Some(v.to_string());
            }
            m.values().find_map(version_field)
        }
        Value::Array(a) => a.iter().find_map(version_field),
        _ => None,
    }
}

fn available(env: &Envelope) -> Result<Value, TestError> {
    let v = json(env)?;
    Ok(v["data"]["available"].clone())
}

/// X-10 over the whole Confluence catalog: on an instance at the Confluence connection-test floor
/// (7.9.0) every op is available (none has a `min_version`: the floor is the catalog's), `ops
/// list --instance` says so, and no envelope shows the instance's version.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x10_confluence_every_op_available_on_floor() -> TestResult {
    let h = harness_at("7.9.0").await?;
    for spec in confluence_specs() {
        assert!(
            spec.min_version.is_none(),
            "{} has a min_version: decide X-10 for it",
            spec.id
        );
        let env = h.handler().ops_describe(spec.id, Some(ALIAS)).await;
        assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
        let v = json(&env)?;
        assert_eq!(v["data"]["available"], true, "{}: {v}", spec.id);
        assert_eq!(v["data"]["op_id"], spec.id);
        assert!(!v.to_string().contains("7.9"), "{}: {v}", spec.id);
        assert_eq!(version_field(&v), None, "{}: a structured version", spec.id);
    }
    let list = json(&h.handler().ops_list(Some(ALIAS)).await)?;
    let ops = list["data"]["ops"].as_array().ok_or("no ops")?;
    assert_eq!(ops.len(), confluence_specs().len());
    assert!(ops.iter().all(|o| o["available"] == true), "{list}");
    assert!(!list.to_string().contains("7.9"), "{list}");
    assert_eq!(version_field(&list), None, "a structured version: {list}");
    Ok(())
}

/// X-10: no envelope of a request against an instance at the floor carries its version string:
/// the pending and the released read, a write's pending, approved and denied envelope, the error
/// of a refused (unlisted) op and of a failed read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x10_confluence_no_version_string_in_envelopes() -> TestResult {
    let h = harness_at("7.9.0").await?;
    let mock = h.mock(ALIAS).ok_or("no confluence mock")?;
    let all = cases();
    let find = |label: &str| {
        all.iter()
            .find(|c| c.label == label)
            .ok_or_else(|| format!("no case {label}"))
    };
    let mut texts: Vec<(String, String)> = Vec::new();
    let mut note = |what: &str, env: &Envelope| -> Result<(), TestError> {
        texts.push((what.to_owned(), envelope_text(env)?));
        Ok(())
    };
    // A read: pending, then released (the fixture set answers the page `65537` and the search).
    let env = h.submit("confluence.page.get", j!({"id": "65537"})).await;
    note("page get pending", &env)?;
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    h.approver().release(&id).map_err(de)?;
    let released = h.await_(&id, 10_000).await;
    assert_eq!(
        released.status,
        Status::Released,
        "{}",
        released.to_json_line()
    );
    note("page get released", &released)?;
    // A read the instance answers with a 404: the failure envelope.
    let env = h.submit("confluence.page.get", j!({"id": "999"})).await;
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    h.approver().release(&id).map_err(de)?;
    let failed = h.await_(&id, 10_000).await;
    note("page get failed", &failed)?;
    // A write against the floor: pending, approved, and a denied one.
    let case = find("confluence.label.remove")?;
    let aux = mount_for_op(mock, case.spec, &case.params).await?;
    assert!(!aux.is_empty());
    for approve in [true, false] {
        let env = h.submit(case.spec.id, case.params.clone()).await;
        note("label remove pending", &env)?;
        let id = request_id(&env)?;
        h.queued(&id, 20_000).await.ok_or("never queued")?;
        if approve {
            h.approver().approve(&id).map_err(de)?;
        } else {
            h.approver().deny(&id, "no").map_err(de)?;
        }
        let done = h.await_(&id, 10_000).await;
        note(
            if approve {
                "label remove approved"
            } else {
                "label remove denied"
            },
            &done,
        )?;
    }
    let env = h
        .submit("confluence.page.delete", j!({"id": "65537"}))
        .await;
    note("unlisted op", &env)?;
    for (what, text) in &texts {
        assert!(
            !text.contains("7.9"),
            "{what}: the instance's version is in {text}"
        );
    }
    Ok(())
}

/// An instance whose version is unknown (never tested) keeps every op available (§2.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x10_confluence_unknown_version_keeps_every_op_available() -> TestResult {
    let h = Harness::confluence().await?;
    assert_eq!(
        h.instance_version(ALIAS),
        None,
        "the harness cached a version"
    );
    for spec in confluence_specs() {
        let env = h.handler().ops_describe(spec.id, Some(ALIAS)).await;
        assert_eq!(
            available(&env)?,
            true,
            "{}: {}",
            spec.id,
            env.to_json_line()
        );
    }
    Ok(())
}

/// X-10 control: a version below every `min_version` the registry knows changes nothing for the
/// Confluence catalog (it has none), whatever the cached version is, and the envelope still
/// carries no version string.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x10_confluence_catalog_has_no_version_gate() -> TestResult {
    let h = Harness::confluence().await?;
    let low = Version {
        major: 7,
        minor: 0,
        patch: 3,
    };
    assert!(h.set_instance_version(ALIAS, low));
    assert_eq!(h.instance_version(ALIAS), Some(low));
    for spec in confluence_specs() {
        let env = h.handler().ops_describe(spec.id, Some(ALIAS)).await;
        assert_eq!(
            available(&env)?,
            true,
            "{}: {}",
            spec.id,
            env.to_json_line()
        );
        let v = json(&env)?;
        assert!(
            !v.to_string().contains("7.0.3"),
            "{}: the instance's version is in the envelope",
            spec.id
        );
        assert_eq!(version_field(&v), None, "{}: a structured version", spec.id);
    }
    Ok(())
}
