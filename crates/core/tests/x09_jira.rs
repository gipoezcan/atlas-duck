#![cfg(feature = "testing")]
//! X-09 (Jira half) and X-10 (Jira gates), M5 Task 22. Every Jira op of the registry runs once
//! against wiremock through the scripted approver, generated from the registry: no hand-written
//! per-op fixture list. The params are `params_schema["examples"][0]`; the mocks are
//! `common::jira::mount_for_op` (the op's endpoint answers its `result_example`, or its declared
//! write success, and the enrichment and stale-check GETs answer the `result_example` of the read
//! op for the same endpoint). A Jira op that `aux_gets` does not name makes the generator fail, so
//! a new op cannot appear without a decision about what it needs.
//!
//! * `x09_jira_every_op_once`: submit, release (reads) or approve (writes), the released result
//!   validates against `result_schema` or the receipt equals the registry example, and the
//!   requests the instance saw match the spec's declared method, path, query and body source.
//! * `x09_jira_writes_wait_for_approval` and `x09_jira_reads_hold_their_result_until_released`:
//!   the gates of the same generated cases (nothing is sent before an approval, nothing is
//!   delivered before a release, a denial delivers and sends nothing).
//! * X-10: the version floor never hides a Jira op and never puts a version string in an envelope.

mod common;

use atlas_duck_atlassian::testing::MockDc;
use atlas_duck_audit::EventType;
use atlas_duck_core::testing::Harness;
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_registry::{BodySource, OpClass, OperationSpec, Product, QueryValue, StatusSet};
use common::jira::{Aux, example_params, fill_path, http_method, mount_for_op};
use common::{TestError, TestResult, de, exit, json, request_id, test_hits};
use serde_json::{Value, json as j};
use wiremock::Request;

/// One generated case: an op (or a variant of its example) and the params it runs with.
struct Case {
    label: String,
    spec: &'static OperationSpec,
    params: Value,
}

fn jira_specs() -> Vec<&'static OperationSpec> {
    atlas_duck_registry::all()
        .iter()
        .filter(|s| s.product == Product::Jira)
        .collect()
}

/// One case per Jira op id (its first example), plus the variants the first example does not
/// reach: `jira.issue.get` with `comments: true` (the composite read, T9).
fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for spec in jira_specs() {
        out.push(Case {
            label: spec.id.to_owned(),
            spec,
            params: example_params(spec),
        });
        if spec.id == "jira.issue.get" {
            let mut params = example_params(spec);
            params["comments"] = j!(true);
            out.push(Case {
                label: format!("{} [comments]", spec.id),
                spec,
                params,
            });
        }
    }
    out
}

fn s(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}

/// A started Jira harness with `case`'s mounts, and the GETs those mounts answer.
async fn start(case: &Case) -> Result<(Harness, Vec<Aux>), String> {
    let h = Harness::jira().await.map_err(s)?;
    let mock = h.mock("jira-main").ok_or("no jira mock")?;
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

/// The requests the instance received for `case`, against the registry's declared endpoint.
async fn check_shape(
    case: &Case,
    mock: &MockDc,
    aux: &[Aux],
    status: Option<u16>,
) -> Result<(), String> {
    let spec = case.spec;
    let ep = spec.endpoint;
    let own_path = mock.path(&fill_path(ep.path, &case.params)?);
    let field_path = mock.path("/rest/api/2/field");
    let all = mock.received().await;
    // Every harness fills the field-name cache once at start (PD-46), through a GET on `/field`
    // that is not the op's.
    let mut cache_fill_skipped = false;
    let hits: Vec<&Request> = all
        .iter()
        .filter(|r| {
            if r.method.as_str() == "GET" && r.url.path() == field_path && !cache_fill_skipped {
                cache_fill_skipped = true;
                return false;
            }
            true
        })
        .collect();
    let method = http_method(ep.method);
    let own: Vec<&&Request> = hits
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
    let myself = mock.path("/rest/api/2/myself");
    for h in &hits {
        let known = (h.method.as_str() == method && h.url.path() == own_path)
            || (h.method.as_str() == "GET"
                && (h.url.path() == myself
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
    // the field rules'.
    let mut allowed: Vec<&str> = ep.query.iter().map(|q| q.name).collect();
    if let Some(p) = spec.paginated {
        allowed.push(p.offset_param);
        allowed.push(p.limit_param);
    }
    if spec.field_rules.is_some() {
        allowed.extend(["fields", "expand"]);
    }
    for (name, _) in r.url.query_pairs() {
        if !allowed.contains(&name.as_ref()) {
            return Err(format!("undeclared query parameter {name}"));
        }
    }
    for q in ep.query {
        let got = query_of(r, q.name);
        match q.value {
            QueryValue::Const(c) if got.as_deref() != Some(c) => {
                return Err(format!("query {}: {got:?}, declared const {c}", q.name));
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
            QueryValue::Const(_) => {}
        }
    }
    // Body: the declared source. A write's target params reach the wire (path or body).
    match ep.body {
        BodySource::None if !r.body.is_empty() => {
            return Err(format!(
                "a body of {} bytes on a bodiless endpoint",
                r.body.len()
            ));
        }
        BodySource::None => {}
        BodySource::ParamsAsJson | BodySource::OpSpecific => {
            let body: Value = serde_json::from_slice(&r.body).map_err(|e| format!("body: {e}"))?;
            if !body.is_object() || body.as_object().is_some_and(serde_json::Map::is_empty) {
                return Err(format!("body is not a non-empty object: {body}"));
            }
            let ct = r
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            if !ct.starts_with("application/json") {
                return Err(format!("content-type {ct:?}"));
            }
            if ep.body == BodySource::ParamsAsJson && body["jql"] != case.params["jql"] {
                return Err(format!("the search body drops the jql: {body}"));
            }
            let wire = format!("{} {body}", r.url.path());
            for t in spec.target_params {
                let values: Vec<String> = match &case.params[*t] {
                    Value::Array(a) => a.iter().filter_map(scalar).collect(),
                    other => scalar(other).into_iter().collect(),
                };
                for v in values {
                    if !wire.contains(&v) {
                        return Err(format!("target param {t}={v} is not on the wire: {wire}"));
                    }
                }
            }
        }
    }
    // The answer the mock gave a write is the registry's declared success.
    if let (OpClass::Write, Some(got)) = (spec.class, status) {
        let ok = match spec.success.statuses {
            StatusSet::Exactly(list) => list.contains(&got),
            StatusSet::Any2xx => (200..300).contains(&got),
        };
        if !ok {
            return Err(format!("WRITE_EXECUTED recorded status {got}"));
        }
    }
    Ok(())
}

/// Runs `case` once and checks its outcome and the wire.
async fn run_case(case: &Case) -> Result<(), String> {
    let spec = case.spec;
    let (h, aux) = start(case).await?;
    let id = submit_queued(&h, case).await?;
    let mut write_status = None;
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
        }
        OpClass::Write => {
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
            write_status = payload["response"]["status"].as_u64().map(|n| n as u16);
            if write_status.is_none() {
                return Err(format!("WRITE_EXECUTED without a status: {payload}"));
            }
        }
    }
    let mock = h.mock("jira-main").ok_or("no jira mock")?;
    check_shape(case, mock, &aux, write_status).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x09_jira_every_op_once() -> TestResult {
    let all = cases();
    assert!(all.len() >= 28, "only {} Jira cases", all.len());
    let mut failed = Vec::new();
    for case in &all {
        match run_case(case).await {
            Ok(()) => println!("X09 {} ok", case.label),
            Err(e) => failed.push(format!("{}: {e}", case.label)),
        }
    }
    // Every Jira op id has its case, and the ids are the registry's.
    for spec in jira_specs() {
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
fn x09_jira_generator_covers_the_registry() -> TestResult {
    let specs = jira_specs();
    assert!(specs.len() >= 28, "only {} Jira ops", specs.len());
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
        common::jira::aux_gets(spec, &params)?;
        fill_path(spec.endpoint.path, &params)?;
    }
    // The composite read's variant reaches its second leg.
    let issue = atlas_duck_registry::get("jira.issue.get").ok_or("no jira.issue.get")?;
    let mut params = example_params(issue);
    assert!(common::jira::aux_gets(issue, &params)?.is_empty());
    params["comments"] = j!(true);
    assert_eq!(common::jira::aux_gets(issue, &params)?.len(), 1);
    // An op id the rules do not know is an error, not a silent skip.
    let unknown = OperationSpec {
        id: "jira.not.listed",
        ..*issue
    };
    assert!(common::jira::aux_gets(&unknown, &example_params(issue)).is_err());
    Ok(())
}

/// Gate: a write is held for the human: nothing is sent while it waits, and a denial sends
/// nothing and records no execution.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x09_jira_writes_wait_for_approval() -> TestResult {
    let mut failed = Vec::new();
    for case in cases().iter().filter(|c| c.spec.class == OpClass::Write) {
        let run = async {
            let (h, _) = start(case).await?;
            let id = submit_queued(&h, case).await?;
            let mock = h.mock("jira-main").ok_or("no jira mock")?;
            let sent =
                |hits: Vec<Request>| hits.iter().filter(|r| r.method.as_str() != "GET").count();
            let before = sent(test_hits(mock).await);
            if before != 0 {
                return Err(format!("{before} writes sent before the approval"));
            }
            h.approver().deny(&id, "no").map_err(|e| s(de(e)))?;
            let env = h.await_(&id, 10_000).await;
            if env.status != Status::Denied {
                return Err(format!("not denied: {}", env.to_json_line()));
            }
            let after = sent(test_hits(mock).await);
            if after != 0 {
                return Err(format!("{after} writes sent after a denial"));
            }
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

/// Gate: a read's bytes reach the agent only through a release: the pending and the denied
/// envelope carry none of the instance's answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x09_jira_reads_hold_their_result_until_released() -> TestResult {
    let mut failed = Vec::new();
    for case in cases().iter().filter(|c| c.spec.class == OpClass::Read) {
        let run = async {
            let (h, _) = start(case).await?;
            let env = h.submit(case.spec.id, case.params.clone()).await;
            let pending = envelope_text(&env).map_err(s)?;
            if env.status != Status::Pending {
                return Err(format!("not pending: {pending}"));
            }
            let id = request_id(&env).map_err(s)?;
            h.queued(&id, 20_000).await.ok_or("never queued")?;
            h.approver().deny(&id, "no").map_err(|e| s(de(e)))?;
            let denied = h.await_(&id, 10_000).await;
            if denied.status != Status::Denied {
                return Err(format!("not denied: {}", denied.to_json_line()));
            }
            let mut markers = Vec::new();
            marker_strings(
                &case.spec.result_example_json(),
                &case.params.to_string(),
                &mut markers,
            );
            if markers.is_empty() {
                return Err("the example has no distinctive string to look for".to_owned());
            }
            for text in [pending, envelope_text(&denied).map_err(s)?] {
                if let Some(m) = markers.iter().find(|m| text.contains(m.as_str())) {
                    return Err(format!("the envelope carries the instance's answer ({m})"));
                }
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
async fn x10_jira_unlisted_ops_are_refused() -> TestResult {
    let h = Harness::jira().await?;
    let mock = h.mock("jira-main").ok_or("no jira mock")?;
    for id in [
        "jira.issue.delete",
        "jira.comment.delete",
        "jira.worklog.delete",
        "jira.issue.assign_all",
    ] {
        assert!(atlas_duck_registry::get(id).is_none(), "{id} is registered");
        let env = h.submit(id, j!({"key": "ABC-1"})).await;
        assert_eq!(common::code(&env), "usage", "{id}: {}", env.to_json_line());
        assert_eq!(exit(&env), 2, "{id}");
    }
    assert!(
        test_hits(mock).await.is_empty(),
        "an unlisted op reached the instance"
    );
    Ok(())
}

/// A harness whose Jira instance reports `version`, with the connection test run once.
async fn harness_at(version: &str) -> Result<Harness, TestError> {
    let h = Harness::jira().await?;
    let mock = h.mock("jira-main").ok_or("no jira mock")?;
    mock.mount_fixture_set(version).await;
    h.instances()
        .retest_token("jira-main")
        .await
        .map_err(|e| format!("{e:?}"))?;
    Ok(h)
}

/// X-10: on an instance at the Jira floor (8.14.0) `jira.createmeta.fields` is available, and the
/// envelope carries no version string (§7.1: below `min_version` the op does not exist and the
/// error names the registry's version, never the instance's).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x10_jira_createmeta_available_on_floor() -> TestResult {
    let h = harness_at("8.14.0").await?;
    let env = h
        .handler()
        .ops_describe("jira.createmeta.fields", Some("jira-main"))
        .await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let v = json(&env)?;
    assert_eq!(v["data"]["available"], true);
    assert_eq!(v["data"]["op_id"], "jira.createmeta.fields");
    let text = v.to_string();
    assert!(
        !text.contains("8.14"),
        "the instance's version is in {text}"
    );
    Ok(())
}

/// X-10 over the whole Jira catalog: at the floor every op is available (each `min_version` is at
/// or below it), `ops list --instance` says so, and no envelope shows the instance's version.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x10_jira_every_op_available_on_floor() -> TestResult {
    let h = harness_at("8.14.0").await?;
    for spec in jira_specs() {
        let env = h.handler().ops_describe(spec.id, Some("jira-main")).await;
        let v = json(&env)?;
        assert_eq!(v["data"]["available"], true, "{}: {v}", spec.id);
        assert!(!v.to_string().contains("8.14"), "{}: {v}", spec.id);
    }
    let list = json(&h.handler().ops_list(Some("jira-main")).await)?;
    let ops = list["data"]["ops"].as_array().ok_or("no ops")?;
    assert_eq!(ops.len(), jira_specs().len());
    assert!(ops.iter().all(|o| o["available"] == true), "{list}");
    assert!(!list.to_string().contains("8.14"), "{list}");
    Ok(())
}
