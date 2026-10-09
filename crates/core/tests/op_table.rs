//! U-05 (core half): the op table, generic read plans, the M3 write executors with their
//! enrichment and stale rules, the CQL rewrite (§7.4) and the fallback / write previews.

use std::collections::BTreeSet;

use atlas_duck_atlassian::testing::fixtures;
use atlas_duck_atlassian::{
    ALLOWED_READ_POSTS, GetCall, HttpRequestSpec, NormalizedBaseUrl, normalize_base_url,
};
use atlas_duck_core::lifecycle::model::Hold;
use atlas_duck_core::ops::{
    EnrichCtx, EnrichFailure, EnrichPurpose, EnrichVerdict, ExecCtx, ExecError, ExecPlan,
    PreviewCtx, PreviewInput, PreviewModel, ReadPlan, ReadView, StaleCtx, StaleVerdict, WriteView,
    confluence, generic, op_table,
};
use atlas_duck_ipc::envelope::ErrorCode;
use atlas_duck_preview::{BodyView, ItemCount, PreviewBody, WarningId};
use atlas_duck_registry::{OpClass, OperationSpec, SCRIPT_RUN};
use serde_json::{Map, Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const M3_WRITES: [&str; 5] = [
    "jira.issue.create",
    "jira.issue.edit",
    "jira.comment.add",
    "jira.issue.transition",
    "confluence.page.update",
];

const LATER_WRITES: [&str; 11] = [
    "jira.issue.assign",
    "jira.worklog.add",
    "jira.issuelink.create",
    "jira.sprint.move_issues",
    "jira.backlog.move_issues",
    "confluence.page.create",
    "confluence.page.move",
    "confluence.comment.add",
    "confluence.label.add",
    "confluence.label.remove",
    "confluence.attachment.upload",
];

fn op(id: &str) -> Result<&'static OperationSpec, String> {
    atlas_duck_registry::get(id).ok_or_else(|| format!("no op {id}"))
}

fn base() -> Result<NormalizedBaseUrl, Box<dyn std::error::Error>> {
    Ok(normalize_base_url("https://jira.example.invalid/ctx")?)
}

fn example(spec: &OperationSpec) -> Value {
    spec.params_schema_json()["examples"][0].clone()
}

fn exec(
    id: &str,
    params: &Value,
    enrichment: Option<&EnrichVerdict>,
    effective_max: Option<u32>,
) -> Result<Result<ExecPlan, ExecError>, Box<dyn std::error::Error>> {
    let spec = op(id)?;
    let imp = op_table().get(id).ok_or("no OpImpl")?;
    let base = base()?;
    let ctx = ExecCtx {
        spec,
        params,
        base: &base,
        enrichment,
        effective_max,
    };
    Ok((imp.executor)(&ctx))
}

fn read_plan(
    id: &str,
    params: &Value,
    max: Option<u32>,
) -> Result<ReadPlan, Box<dyn std::error::Error>> {
    match exec(id, params, None, max)?? {
        ExecPlan::Read(plan) => Ok(plan),
        ExecPlan::Write(_) => Err("expected a read plan".into()),
    }
}

fn write_requests(
    id: &str,
    params: &Value,
    enrichment: Option<&EnrichVerdict>,
) -> Result<Vec<HttpRequestSpec>, Box<dyn std::error::Error>> {
    match exec(id, params, enrichment, None)?? {
        ExecPlan::Write(requests) => Ok(requests),
        ExecPlan::Read(_) => Err("expected a write".into()),
    }
}

fn body_json(r: &HttpRequestSpec) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(&r.body)
}

fn query_of(call: &GetCall) -> Vec<(&str, &str)> {
    call.query
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

type EnrichOutcome = (Vec<(EnrichPurpose, GetCall)>, EnrichVerdict);

fn enrich(
    id: &str,
    params: &Value,
    responses: &[Value],
) -> Result<EnrichOutcome, Box<dyn std::error::Error>> {
    let spec = op(id)?;
    let rule = op_table()
        .get(id)
        .and_then(|i| i.enrich)
        .ok_or("no enrich rule")?;
    let ctx = EnrichCtx { spec, params };
    Ok(((rule.plan)(&ctx), (rule.judge)(&ctx, responses)))
}

fn stale(
    id: &str,
    params: &Value,
    baseline: &Value,
    responses: &[Value],
) -> Result<(Vec<GetCall>, StaleVerdict), Box<dyn std::error::Error>> {
    let spec = op(id)?;
    let rule = op_table()
        .get(id)
        .and_then(|i| i.stale_check)
        .ok_or("no stale rule")?;
    let ctx = StaleCtx {
        spec,
        params,
        baseline,
    };
    Ok(((rule.plan)(&ctx), (rule.judge)(&ctx, responses)))
}

fn rejected_cql(cql: &str) -> Result<atlas_duck_core::validate::ValidationError, String> {
    match confluence::effective_cql(cql) {
        Ok(_) => Err(format!("accepted: {cql}")),
        Err(e) => Ok(e),
    }
}

// ---- U-05 -----------------------------------------------------------------------------------

#[test]
fn u05_op_table_covers_registry_exactly() {
    let table: BTreeSet<&str> = op_table().keys().copied().collect();
    let registry: BTreeSet<&str> = atlas_duck_registry::all().iter().map(|s| s.id).collect();
    assert_eq!(table, registry);
    assert_eq!(op_table().len(), 46);
    assert!(!op_table().contains_key(SCRIPT_RUN.id));
}

#[test]
fn u05_only_writes_have_stale_check() -> TestResult {
    let mut with_rule = BTreeSet::new();
    for (id, imp) in op_table() {
        if imp.stale_check.is_some() {
            assert_eq!(op(id)?.class, OpClass::Write, "{id}");
            with_rule.insert(*id);
        }
    }
    let pd10: BTreeSet<&str> = [
        "jira.issue.edit",
        "jira.issue.transition",
        "confluence.page.update",
    ]
    .into_iter()
    .collect();
    assert_eq!(with_rule, pd10);
    Ok(())
}

#[test]
fn reads_have_no_enrich() -> TestResult {
    let mut with_enrich = BTreeSet::new();
    for (id, imp) in op_table() {
        if imp.enrich.is_some() {
            assert_eq!(op(id)?.class, OpClass::Write, "{id}");
            with_enrich.insert(*id);
        }
        if op(id)?.class == OpClass::Read {
            assert!(imp.enrich_keys.is_empty(), "{id}");
        }
    }
    let expected: BTreeSet<&str> = [
        "jira.issue.create",
        "jira.issue.edit",
        "jira.issue.transition",
        "confluence.page.update",
    ]
    .into_iter()
    .collect();
    assert_eq!(with_enrich, expected);
    Ok(())
}

// ---- reads ----------------------------------------------------------------------------------

#[test]
fn read_methods_are_get_or_search() -> TestResult {
    let base = base()?;
    for spec in atlas_duck_registry::all()
        .iter()
        .filter(|s| s.class == OpClass::Read)
    {
        let params = example(spec);
        let plan = read_plan(spec.id, &params, spec.caps.max.map(|m| m.default))?;
        match plan {
            ReadPlan::Get(call) => {
                assert_eq!(spec.paginated, None, "{}", spec.id);
                // The call builds a URL under the base.
                atlas_duck_atlassian::build_url(
                    &base,
                    &call.endpoint_template,
                    &call.params,
                    &call.query,
                )?;
            }
            ReadPlan::Paged { call, .. } => {
                assert!(spec.paginated.is_some(), "{}", spec.id);
                atlas_duck_atlassian::build_url(
                    &base,
                    &call.get.endpoint_template,
                    &call.get.params,
                    &call.get.query,
                )?;
            }
            ReadPlan::Search { call, .. } => {
                assert_eq!(spec.id, "jira.search");
                assert!(ALLOWED_READ_POSTS.contains(&call.endpoint_template.as_str()));
            }
        }
    }
    Ok(())
}

#[test]
fn get_call_params_hold_only_placeholders() -> TestResult {
    let plan = read_plan(
        "jira.issue.get",
        &json!({"key": "ABC-1", "fields": ["summary"], "comments": true}),
        None,
    )?;
    let ReadPlan::Get(call) = plan else {
        return Err("expected a GET".into());
    };
    assert_eq!(call.endpoint_template, "/rest/api/2/issue/{key}");
    assert_eq!(call.params, json!({"key": "ABC-1"}));
    // `comments` is accepted and has no effect in M3 (PD-09).
    assert_eq!(query_of(&call), vec![("fields", "summary")]);
    Ok(())
}

#[test]
fn issue_get_maps_changelog_rendered_and_default_fields() -> TestResult {
    let ReadPlan::Get(call) = read_plan("jira.issue.get", &json!({"key": "ABC-1"}), None)? else {
        return Err("expected a GET".into());
    };
    assert_eq!(
        query_of(&call),
        vec![(
            "fields",
            atlas_duck_registry::ISSUE_GET_DEFAULT_FIELDS
                .join(",")
                .as_str()
        )]
    );
    let params = json!({"key": "ABC-1", "expand": ["names"], "changelog": true, "rendered": true});
    let ReadPlan::Get(call) = read_plan("jira.issue.get", &params, None)? else {
        return Err("expected a GET".into());
    };
    let q = query_of(&call);
    assert_eq!(q[1], ("expand", "names,changelog,renderedFields"));
    // An empty list is absent: the registry default applies, never `fields=`.
    let ReadPlan::Get(call) = read_plan(
        "jira.issue.get",
        &json!({"key": "ABC-1", "fields": [], "expand": []}),
        None,
    )?
    else {
        return Err("expected a GET".into());
    };
    assert_eq!(
        query_of(&call),
        vec![(
            "fields",
            atlas_duck_registry::ISSUE_GET_DEFAULT_FIELDS
                .join(",")
                .as_str()
        )]
    );
    let ReadPlan::Search { call, .. } =
        read_plan("jira.search", &json!({"jql": "x", "fields": []}), Some(5))?
    else {
        return Err("expected a search".into());
    };
    assert_eq!(
        call.body["fields"],
        json!(atlas_duck_registry::SEARCH_DEFAULT_FIELDS)
    );
    // No duplicate when the agent already asked for it.
    let params =
        json!({"key": "ABC-1", "expand": ["changelog"], "changelog": true, "rendered": false});
    let ReadPlan::Get(call) = read_plan("jira.issue.get", &params, None)? else {
        return Err("expected a GET".into());
    };
    assert_eq!(query_of(&call)[1], ("expand", "changelog"));
    Ok(())
}

#[test]
fn search_sends_excerpt_none_when_absent() -> TestResult {
    let ReadPlan::Paged { call, max_items } = read_plan(
        "confluence.search",
        &json!({"cql": "space = DOC"}),
        Some(25),
    )?
    else {
        return Err("expected a paged read".into());
    };
    assert_eq!(max_items, 25);
    assert_eq!(
        query_of(&call.get),
        vec![
            (
                "cql",
                "(space = DOC) AND type in (page,blogpost,comment,attachment)"
            ),
            ("excerpt", "none"),
        ]
    );
    // The agent's choice is sent as given; `highlight` never appears.
    let params = json!({"cql": "space = DOC", "excerpt": "indexed"});
    let ReadPlan::Paged { call, .. } = read_plan("confluence.search", &params, Some(25))? else {
        return Err("expected a paged read".into());
    };
    assert_eq!(query_of(&call.get)[1], ("excerpt", "indexed"));
    assert!(call.get.query.iter().all(|(_, v)| v != "highlight"));
    Ok(())
}

#[test]
fn paged_reads_use_start_and_clamped_max() -> TestResult {
    let params = json!({"id": 42, "start": 50, "max": 900});
    let ReadPlan::Paged { call, max_items } = read_plan("jira.sprint.issues", &params, Some(500))?
    else {
        return Err("expected a paged read".into());
    };
    assert_eq!((call.start, call.page_size, max_items), (50, 500, 500));
    assert_eq!(call.items_key, "issues");
    assert_eq!(
        (call.offset_param.as_str(), call.limit_param.as_str()),
        ("startAt", "maxResults")
    );
    assert_eq!(call.get.params, json!({"id": 42}));
    // No `start`/`max` in the query: pagination appends its own.
    assert!(call.get.query.is_empty());

    // A non-paged op with a `max` cap sends the clamped value.
    let ReadPlan::Get(call) = read_plan(
        "jira.user.assignable",
        &json!({"username": "jdoe", "max": 5000}),
        Some(1000),
    )?
    else {
        return Err("expected a GET".into());
    };
    assert_eq!(
        query_of(&call),
        vec![("username", "jdoe"), ("maxResults", "1000")]
    );
    Ok(())
}

#[test]
fn jira_search_body_from_params() -> TestResult {
    let ReadPlan::Search {
        call,
        items_key,
        max_items,
    } = read_plan(
        "jira.search",
        &json!({"jql": "project = ABC", "start": 10}),
        Some(50),
    )?
    else {
        return Err("expected a search".into());
    };
    assert_eq!((items_key.as_str(), max_items), ("issues", 50));
    assert_eq!(
        call.body,
        json!({
            "jql": "project = ABC",
            "startAt": 10,
            "maxResults": 50,
            "fields": atlas_duck_registry::SEARCH_DEFAULT_FIELDS,
        })
    );
    let params = json!({"jql": "x", "fields": ["*all"], "expand": ["names"]});
    let ReadPlan::Search { call, .. } = read_plan("jira.search", &params, Some(7))? else {
        return Err("expected a search".into());
    };
    assert_eq!(
        call.body,
        json!({"jql": "x", "startAt": 0, "maxResults": 7, "fields": ["*all"], "expand": ["names"]})
    );
    Ok(())
}

#[test]
fn page_history_uses_alt_endpoint_with_version() -> TestResult {
    let ReadPlan::Get(call) = read_plan("confluence.page.history", &json!({"id": "1"}), None)?
    else {
        return Err("expected a GET".into());
    };
    assert_eq!(call.endpoint_template, "/rest/api/content/{id}/history");
    let ReadPlan::Get(call) = read_plan(
        "confluence.page.history",
        &json!({"id": "1", "version": 3}),
        None,
    )?
    else {
        return Err("expected a GET".into());
    };
    assert_eq!(call.endpoint_template, "/rest/api/content/{id}");
    assert_eq!(
        query_of(&call),
        vec![
            ("version", "3"),
            ("status", "historical"),
            ("expand", "body.storage,version")
        ]
    );
    Ok(())
}

// ---- CQL (§7.4) ----------------------------------------------------------------------------

const TYPES: &str = "type in (page,blogpost,comment,attachment)";

#[test]
fn cql_rewrite_wraps_and_keeps_order_by() -> TestResult {
    assert_eq!(
        confluence::effective_cql("space = DOC")?,
        format!("(space = DOC) AND {TYPES}")
    );
    assert_eq!(
        confluence::effective_cql("space = DOC OR label = x order   by lastmodified desc")?,
        format!("(space = DOC OR label = x) AND {TYPES} order   by lastmodified desc")
    );
    assert_eq!(
        confluence::effective_cql("(a = 1 OR b = 2) AND c = 3 ORDER BY title")?,
        format!("((a = 1 OR b = 2) AND c = 3) AND {TYPES} ORDER BY title")
    );
    // The executor sends the rewrite.
    let ReadPlan::Paged { call, .. } = read_plan(
        "confluence.search",
        &json!({"cql": "space = DOC ORDER BY created"}),
        Some(25),
    )?
    else {
        return Err("expected a paged read".into());
    };
    assert_eq!(
        call.get.query[0].1,
        format!("(space = DOC) AND {TYPES} ORDER BY created")
    );
    Ok(())
}

#[test]
fn cql_order_by_inside_parens_or_twice_rejected() -> TestResult {
    for cql in [
        "(space = DOC ORDER BY created)",
        "space = DOC ORDER BY created ORDER BY title",
        "ORDER BY created AND space = DOC",
        "order by title",
        "space = DOC ORDER BY created OR (type = space)",
    ] {
        let e = rejected_cql(cql)?;
        assert_eq!(e.code, ErrorCode::Validation, "{cql}");
        assert_eq!(e.details.get("param"), Some(&json!("cql")), "{cql}");
        assert!(!serde_json::to_string(&e)?.contains("created"), "{cql}");
    }
    // The executor is the validator hook: the same rejection, before any fetch.
    let r = exec(
        "confluence.search",
        &json!({"cql": "(a = 1 ORDER BY b)"}),
        None,
        Some(25),
    )?;
    assert!(matches!(r, Err(ExecError::Invalid(e)) if e.code == ErrorCode::Validation));
    Ok(())
}

#[test]
fn cql_unterminated_quote_rejected() -> TestResult {
    for cql in [
        "title ~ \"open",
        "title ~ 'open",
        "title ~ \"ends with escape\\\"",
        "title ~ \"a\" OR text ~ 'b",
    ] {
        let e = rejected_cql(cql)?;
        assert_eq!(e.code, ErrorCode::Validation, "{cql}");
        assert_eq!(e.details.get("param"), Some(&json!("cql")));
        assert!(
            !e.message.contains("open") && !e.message.contains("title"),
            "{cql}"
        );
    }
    Ok(())
}

#[test]
fn cql_paren_escape_attempt_rejected() -> TestResult {
    for cql in [
        "space=A) OR (type=space",
        "space = A)",
        "(space = A",
        "space = A) OR type = space OR (space = B",
        // A backslash outside a quoted string could make the server read a paren or quote
        // differently from this tokenizer: fail closed.
        "\\( space = A ) OR ( type = space \\)",
        "\\\" ) OR ( type = space \"",
    ] {
        let e = rejected_cql(cql)?;
        assert_eq!(e.code, ErrorCode::Validation, "{cql}");
        assert_eq!(e.details.get("param"), Some(&json!("cql")));
        assert!(!serde_json::to_string(&e)?.contains("space"), "{cql}");
    }
    Ok(())
}

#[test]
fn cql_quoted_parens_and_order_by_are_text() -> TestResult {
    assert_eq!(
        confluence::effective_cql("title ~ \"a) OR (b\"")?,
        format!("(title ~ \"a) OR (b\") AND {TYPES}")
    );
    assert_eq!(
        confluence::effective_cql("text ~ 'x ORDER BY y' ORDER BY created")?,
        format!("(text ~ 'x ORDER BY y') AND {TYPES} ORDER BY created")
    );
    assert_eq!(
        confluence::effective_cql("title ~ \"say \\\"hi\\\" (\" and text ~ 'it\\'s )'")?,
        format!("(title ~ \"say \\\"hi\\\" (\" and text ~ 'it\\'s )') AND {TYPES}")
    );
    // `ORDER` alone (a value) and `ordered` are not ORDER BY.
    assert_eq!(
        confluence::effective_cql("label = order AND title ~ ordered")?,
        format!("(label = order AND title ~ ordered) AND {TYPES}")
    );
    Ok(())
}

// ---- writes ---------------------------------------------------------------------------------

#[test]
fn not_in_this_build_writes() -> TestResult {
    for id in LATER_WRITES {
        let spec = op(id)?;
        assert_eq!(spec.class, OpClass::Write);
        assert_eq!(
            exec(id, &example(spec), None, None)?,
            Err(ExecError::NotInThisBuild),
            "{id}"
        );
    }
    let writes = atlas_duck_registry::all()
        .iter()
        .filter(|s| s.class == OpClass::Write)
        .count();
    assert_eq!(writes, M3_WRITES.len() + LATER_WRITES.len());
    Ok(())
}

fn create_verdict() -> EnrichVerdict {
    let mut resolved = Map::new();
    resolved.insert("issuetype".to_owned(), json!("10002"));
    EnrichVerdict::preview(json!({"issuetype_id": "10002"}), resolved)
}

fn transition_verdict() -> EnrichVerdict {
    let mut resolved = Map::new();
    resolved.insert("transition".to_owned(), json!("31"));
    EnrichVerdict::preview(json!({"status_id": "3", "transition_id": "31"}), resolved)
}

fn page_verdict() -> EnrichVerdict {
    let mut resolved = Map::new();
    resolved.insert("title".to_owned(), json!("Release checklist"));
    resolved.insert("space_key".to_owned(), json!("DOC"));
    EnrichVerdict::preview(
        json!({"version": 5, "title": "Release checklist", "space_key": "DOC"}),
        resolved,
    )
}

fn fixture_cases() -> Vec<(&'static str, Value, Option<EnrichVerdict>)> {
    vec![
        (
            "jira.issue.create",
            json!({"project": "ABC", "issuetype": "bug", "summary": "S", "description": "D",
                   "body_format": "wiki", "fields": {"customfield_10200": {"value": "Platform"}}}),
            Some(create_verdict()),
        ),
        (
            "jira.issue.edit",
            json!({"key": "ABC-1", "fields": {"summary": "New"}, "update": {"labels": [{"add": "x"}]},
                   "expected": {"summary": "Old"}}),
            None,
        ),
        (
            "jira.comment.add",
            json!({"key": "ABC-1", "body": "Fixed.", "body_format": "wiki",
                   "visibility": {"type": "role", "value": "Developers"}}),
            None,
        ),
        (
            "jira.issue.transition",
            json!({"key": "ABC-1", "transition": "Done", "fields": {"resolution": {"name": "Fixed"}},
                   "comment": "Closing."}),
            Some(transition_verdict()),
        ),
        (
            "confluence.page.update",
            json!({"id": "65537", "base_version": 5, "body": "<p>x</p>", "body_format": "storage"}),
            Some(page_verdict()),
        ),
    ]
}

#[test]
fn executors_deterministic() -> TestResult {
    for (id, params, verdict) in fixture_cases() {
        let a = write_requests(id, &params, verdict.as_ref())?;
        let b = write_requests(id, &params, verdict.as_ref())?;
        assert_eq!(a, b, "{id}");
        assert_eq!(a.len(), 1, "{id}");
        assert_eq!(a[0].index, 0);
        assert_eq!(a[0].content_type.as_deref(), Some("application/json"));
        // Key order is fixed (serde_json's ordered map): re-serializing gives the same bytes.
        assert_eq!(serde_json::to_vec(&body_json(&a[0])?)?, a[0].body, "{id}");
    }
    Ok(())
}

#[test]
fn write_bodies_and_urls() -> TestResult {
    let cases = fixture_cases();
    let get = |id: &str| {
        cases
            .iter()
            .find(|c| c.0 == id)
            .ok_or(format!("no case {id}"))
    };

    let (id, params, verdict) = get("jira.issue.create")?;
    let r = &write_requests(id, params, verdict.as_ref())?[0];
    assert_eq!(r.method, "POST");
    assert_eq!(
        r.resolved_url,
        "https://jira.example.invalid/ctx/rest/api/2/issue"
    );
    assert_eq!(
        body_json(r)?,
        json!({"fields": {"project": {"key": "ABC"}, "issuetype": {"id": "10002"}, "summary": "S",
                          "description": "D", "customfield_10200": {"value": "Platform"}}})
    );

    let (id, params, _) = get("jira.issue.edit")?;
    let r = &write_requests(id, params, None)?[0];
    assert_eq!(r.method, "PUT");
    assert_eq!(
        r.resolved_url,
        "https://jira.example.invalid/ctx/rest/api/2/issue/ABC-1"
    );
    assert_eq!(
        body_json(r)?,
        json!({"fields": {"summary": "New"}, "update": {"labels": [{"add": "x"}]}})
    );

    let (id, params, _) = get("jira.comment.add")?;
    let r = &write_requests(id, params, None)?[0];
    assert_eq!(r.method, "POST");
    assert_eq!(
        r.resolved_url,
        "https://jira.example.invalid/ctx/rest/api/2/issue/ABC-1/comment"
    );
    assert_eq!(
        body_json(r)?,
        json!({"body": "Fixed.", "visibility": {"type": "role", "value": "Developers"}})
    );

    let (id, params, verdict) = get("jira.issue.transition")?;
    let r = &write_requests(id, params, verdict.as_ref())?[0];
    assert_eq!(r.method, "POST");
    assert_eq!(
        r.resolved_url,
        "https://jira.example.invalid/ctx/rest/api/2/issue/ABC-1/transitions"
    );
    assert_eq!(
        body_json(r)?,
        json!({"transition": {"id": "31"}, "fields": {"resolution": {"name": "Fixed"}},
               "update": {"comment": [{"add": {"body": "Closing."}}]}})
    );
    // Optional parts are absent, never null.
    let r = &write_requests(
        id,
        &json!({"key": "ABC-1", "transition": "31"}),
        verdict.as_ref(),
    )?[0];
    assert_eq!(body_json(r)?, json!({"transition": {"id": "31"}}));

    // A numeric project is an id.
    let p = json!({"project": "10000", "issuetype": "Bug", "summary": "S"});
    let r = &write_requests("jira.issue.create", &p, Some(&create_verdict()))?[0];
    assert_eq!(body_json(r)?["fields"]["project"], json!({"id": "10000"}));
    Ok(())
}

#[test]
fn page_update_sends_base_plus_one() -> TestResult {
    let params =
        json!({"id": "65537", "base_version": 5, "body": "<p>x</p>", "body_format": "storage"});
    let r = &write_requests("confluence.page.update", &params, Some(&page_verdict()))?[0];
    assert_eq!(r.method, "PUT");
    assert_eq!(
        r.resolved_url,
        "https://jira.example.invalid/ctx/rest/api/content/65537"
    );
    let body = body_json(r)?;
    assert_eq!(body["version"]["number"], json!(6));
    assert_eq!(
        body,
        json!({"id": "65537", "type": "page", "title": "Release checklist", "space": {"key": "DOC"},
               "body": {"storage": {"value": "<p>x</p>", "representation": "storage"}},
               "version": {"number": 6}})
    );
    // A given title wins over the current one.
    let params = json!({"id": "65537", "base_version": 5, "body": "b", "body_format": "storage", "title": "New"});
    let r = &write_requests("confluence.page.update", &params, Some(&page_verdict()))?[0];
    assert_eq!(body_json(r)?["title"], json!("New"));
    Ok(())
}

#[test]
fn writes_needing_enrichment_wait_for_a_preview_verdict() -> TestResult {
    for (id, params, verdict) in fixture_cases() {
        if verdict.is_none() {
            continue;
        }
        assert_eq!(
            exec(id, &params, None, None)?,
            Err(ExecError::EnrichmentRequired),
            "{id}"
        );
        let mut held = verdict.ok_or("verdict")?;
        held.hold = Hold::UnresolvedName;
        assert_eq!(
            exec(id, &params, Some(&held), None)?,
            Err(ExecError::EnrichmentRequired),
            "{id}"
        );
    }
    // An edit with nothing to change is refused statically.
    let r = exec(
        "jira.issue.edit",
        &json!({"key": "ABC-1", "expected": {"summary": "x"}}),
        None,
        None,
    )?;
    assert!(matches!(r, Err(ExecError::Invalid(e)) if e.code == ErrorCode::Validation));
    Ok(())
}

// ---- enrichment and stale rules --------------------------------------------------------------

#[test]
fn create_resolves_issuetype_by_id_or_name() -> TestResult {
    let types: Value = serde_json::from_str(fixtures::JIRA_CREATEMETA_ISSUETYPES)?;
    let params = json!({"project": "ABC", "issuetype": "bug", "summary": "S"});
    let (plan, v) = enrich("jira.issue.create", &params, std::slice::from_ref(&types))?;
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].0, EnrichPurpose::Resolve);
    assert_eq!(
        plan[0].1.endpoint_template,
        "/rest/api/2/issue/createmeta/{project}/issuetypes"
    );
    assert_eq!(plan[0].1.params, json!({"project": "ABC"}));
    assert_eq!(v.hold, Hold::Preview);
    assert_eq!(v.resolved.get("issuetype"), Some(&json!("10002")));

    let (_, v) = enrich(
        "jira.issue.create",
        &json!({"project": "ABC", "issuetype": "10001", "summary": "S"}),
        std::slice::from_ref(&types),
    )?;
    assert_eq!(v.resolved.get("issuetype"), Some(&json!("10001")));

    let (_, v) = enrich(
        "jira.issue.create",
        &json!({"project": "ABC", "issuetype": "Bugg", "summary": "S"}),
        std::slice::from_ref(&types),
    )?;
    assert_eq!(v.hold, Hold::UnresolvedName);
    let (param, value, matches, candidates) = v.unresolved.ok_or("unresolved")?;
    assert_eq!(
        (param.as_str(), value.as_str(), matches),
        ("issuetype", "Bugg", 0)
    );
    assert_eq!(candidates, vec!["Story".to_owned(), "Bug".to_owned()]);

    // Two types with the same name (case-insensitive) are ambiguous.
    let twice = json!({"values": [{"id": "1", "name": "Bug"}, {"id": "2", "name": "BUG"}]});
    let (_, v) = enrich(
        "jira.issue.create",
        &json!({"project": "ABC", "issuetype": "bug", "summary": "S"}),
        &[twice],
    )?;
    assert_eq!(v.hold, Hold::UnresolvedName);
    assert_eq!(v.unresolved.map(|u| u.2), Some(2));

    // No response at all: fail closed.
    let (_, v) = enrich("jira.issue.create", &params, &[])?;
    assert_eq!(v.hold, Hold::EnrichmentError);
    Ok(())
}

#[test]
fn edit_conflict_and_stale_rule() -> TestResult {
    let params = json!({"key": "ABC-1", "fields": {"summary": "New"}, "update": {"labels": [{"add": "x"}]},
                        "expected": {"summary": "Login page times out"}});
    let issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    let (plan, v) = enrich("jira.issue.edit", &params, std::slice::from_ref(&issue))?;
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].0, EnrichPurpose::Enrich);
    assert_eq!(plan[0].1.endpoint_template, "/rest/api/2/issue/{key}");
    assert_eq!(query_of(&plan[0].1), vec![("fields", "labels,summary")]);
    assert_eq!(v.hold, Hold::Preview);
    assert_eq!(
        v.baseline,
        json!({"labels": ["web"], "summary": "Login page times out"})
    );

    let mismatched =
        json!({"key": "ABC-1", "fields": {"summary": "New"}, "expected": {"summary": "Old"}});
    let (_, v) = enrich("jira.issue.edit", &mismatched, std::slice::from_ref(&issue))?;
    assert_eq!(v.hold, Hold::Conflict);
    assert_eq!(
        v.conflict.as_deref(),
        Some("fields changed since the agent read it: summary")
    );
    assert!(v.warnings.iter().any(|w| w.id == WarningId::Conflict));

    // An expected field the issue does not have compares as null.
    let absent =
        json!({"key": "ABC-1", "fields": {"duedate": "2026-11-01"}, "expected": {"duedate": null}});
    let (_, v) = enrich("jira.issue.edit", &absent, std::slice::from_ref(&issue))?;
    assert_eq!(v.hold, Hold::Preview);

    let baseline = json!({"labels": ["web"], "summary": "Login page times out"});
    let (calls, verdict) = stale(
        "jira.issue.edit",
        &params,
        &baseline,
        std::slice::from_ref(&issue),
    )?;
    assert_eq!(query_of(&calls[0]), vec![("fields", "labels,summary")]);
    assert_eq!(verdict, StaleVerdict::Unchanged);
    let mut changed = issue.clone();
    changed["fields"]["summary"] = json!("Someone else's edit");
    let (_, verdict) = stale("jira.issue.edit", &params, &baseline, &[changed])?;
    assert!(matches!(verdict, StaleVerdict::Changed { delta } if delta.contains("summary")));
    Ok(())
}

#[test]
fn transition_resolution_and_stale_rule() -> TestResult {
    let transitions: Value = serde_json::from_str(fixtures::JIRA_TRANSITIONS)?;
    let issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    let params = json!({"key": "ABC-1", "transition": "done"});
    let responses = [transitions.clone(), issue.clone()];
    let (plan, v) = enrich("jira.issue.transition", &params, &responses)?;
    assert_eq!(plan.len(), 2);
    assert_eq!(plan[0].0, EnrichPurpose::Resolve);
    assert_eq!(
        plan[0].1.endpoint_template,
        "/rest/api/2/issue/{key}/transitions"
    );
    assert_eq!(query_of(&plan[0].1), vec![("expand", "transitions.fields")]);
    assert_eq!(plan[1].0, EnrichPurpose::Enrich);
    assert_eq!(query_of(&plan[1].1), vec![("fields", "status")]);
    assert_eq!(v.hold, Hold::Preview);
    assert_eq!(v.resolved.get("transition"), Some(&json!("31")));
    assert_eq!(v.baseline, json!({"status_id": "3", "transition_id": "31"}));

    let (_, v) = enrich(
        "jira.issue.transition",
        &json!({"key": "ABC-1", "transition": "Doen"}),
        &responses,
    )?;
    assert_eq!(v.hold, Hold::UnresolvedName);

    let baseline = v_baseline();
    let (calls, verdict) = stale("jira.issue.transition", &params, &baseline, &responses)?;
    assert_eq!(calls.len(), 2);
    assert_eq!(verdict, StaleVerdict::Unchanged);
    let mut moved = issue.clone();
    moved["fields"]["status"]["id"] = json!("10001");
    let (_, verdict) = stale(
        "jira.issue.transition",
        &params,
        &baseline,
        &[transitions.clone(), moved],
    )?;
    assert!(matches!(verdict, StaleVerdict::Changed { .. }));
    let gone = json!({"transitions": [{"id": "21", "name": "Start Progress"}]});
    let (_, verdict) = stale("jira.issue.transition", &params, &baseline, &[gone, issue])?;
    assert!(matches!(verdict, StaleVerdict::Changed { .. }));
    Ok(())
}

fn v_baseline() -> Value {
    json!({"status_id": "3", "transition_id": "31"})
}

#[test]
fn page_update_conflict_and_stale_rule() -> TestResult {
    let page: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE)?;
    let params = json!({"id": "65537", "base_version": 7, "body": "b", "body_format": "storage"});
    let (plan, v) = enrich(
        "confluence.page.update",
        &params,
        std::slice::from_ref(&page),
    )?;
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].1.endpoint_template, "/rest/api/content/{id}");
    assert_eq!(
        query_of(&plan[0].1),
        vec![("expand", "body.storage,version,space")]
    );
    assert_eq!(v.hold, Hold::Preview);
    assert_eq!(
        v.baseline,
        json!({"version": 7, "title": "Release checklist", "space_key": "DOC"})
    );

    let stale_base =
        json!({"id": "65537", "base_version": 5, "body": "b", "body_format": "storage"});
    let (_, v) = enrich(
        "confluence.page.update",
        &stale_base,
        std::slice::from_ref(&page),
    )?;
    assert_eq!(v.hold, Hold::Conflict);
    assert_eq!(
        v.conflict.as_deref(),
        Some("conflict: page changed since the agent read it (v5 → v7)")
    );

    let baseline = json!({"version": 7, "title": "Release checklist", "space_key": "DOC"});
    let (calls, verdict) = stale(
        "confluence.page.update",
        &params,
        &baseline,
        std::slice::from_ref(&page),
    )?;
    assert_eq!(query_of(&calls[0]), vec![("expand", "version")]);
    assert_eq!(verdict, StaleVerdict::Unchanged);
    let mut newer = page;
    newer["version"]["number"] = json!(8);
    let (_, verdict) = stale("confluence.page.update", &params, &baseline, &[newer])?;
    assert!(matches!(verdict, StaleVerdict::Changed { .. }));
    Ok(())
}

// ---- fixtures against registry schemas -------------------------------------------------------

#[test]
fn fixtures_match_registry_schemas() -> TestResult {
    let owned = [
        ("jira.myself", fixtures::jira_myself("jdoe", "JIRAUSER1")),
        ("jira.search", fixtures::jira_search_page(50, 50, 120, 50)),
        (
            "jira.board.list",
            fixtures::jira_board_page(0, 50, Some(3), 3),
        ),
        ("jira.board.list", fixtures::jira_board_page(0, 50, None, 3)),
        (
            "confluence.user.current",
            fixtures::confluence_user_current("jdoe", "8a7f808a1"),
        ),
        (
            "confluence.space.list",
            fixtures::confluence_space_page(0, 25, 25, Some("/rest/api/space?limit=25&start=25")),
        ),
    ];
    let fixed = [
        ("jira.myself", fixtures::JIRA_MYSELF),
        ("jira.issue.get", fixtures::JIRA_ISSUE),
        ("jira.search", fixtures::JIRA_SEARCH_PAGE),
        (
            "jira.createmeta.issuetypes",
            fixtures::JIRA_CREATEMETA_ISSUETYPES,
        ),
        ("jira.transition.list", fixtures::JIRA_TRANSITIONS),
        ("jira.comment.add", fixtures::JIRA_COMMENT),
        ("jira.issue.create", fixtures::JIRA_ISSUE_CREATED),
        (
            "confluence.user.current",
            fixtures::CONFLUENCE_USER_ANONYMOUS,
        ),
        ("confluence.page.get", fixtures::CONFLUENCE_PAGE),
        ("confluence.page.history", fixtures::CONFLUENCE_PAGE),
        ("confluence.search", fixtures::CONFLUENCE_SEARCH_PAGE),
        ("confluence.page.update", fixtures::CONFLUENCE_PAGE_UPDATED),
    ];
    let cases = owned
        .iter()
        .map(|(id, body)| (*id, body.as_str()))
        .chain(fixed);
    for (id, body) in cases {
        let spec = op(id)?;
        let mut value: Value = serde_json::from_str(body)?;
        // A write's schema is the receipt the agent gets: the projection of the response.
        if spec.class == OpClass::Write {
            value = generic::project_receipt(spec, &value, &example(spec));
        }
        let validator = jsonschema::validator_for(&spec.result_schema_json())?;
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "{id}: {errors:?}");
    }
    Ok(())
}

#[test]
fn receipts_project_the_static_fields() -> TestResult {
    let created: Value = serde_json::from_str(fixtures::JIRA_ISSUE_CREATED)?;
    let spec = op("jira.issue.create")?;
    assert_eq!(
        generic::project_receipt(spec, &created, &json!({})),
        json!({"id": "10003", "key": "ABC-3"})
    );
    let updated: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE_UPDATED)?;
    assert_eq!(
        generic::project_receipt(op("confluence.page.update")?, &updated, &json!({})),
        json!({"id": "65537", "type": "page", "status": "current", "version": {"number": 8},
               "_links": {"webui": "/display/DOC/Release+checklist"}})
    );
    assert_eq!(
        generic::project_receipt(op("jira.issue.edit")?, &json!(null), &json!({})),
        json!({})
    );
    assert_eq!(
        generic::project_receipt(
            op("confluence.label.add")?,
            &json!({"results": [{"name": "other"}]}),
            &json!({"id": "1", "labels": ["release"]})
        ),
        json!({"labels": ["release"]})
    );
    Ok(())
}

// ---- previews -------------------------------------------------------------------------------

fn read_preview(
    id: &str,
    params: &Value,
    candidate: &Value,
    clamped: bool,
    more: bool,
) -> Result<PreviewModel, Box<dyn std::error::Error>> {
    let spec = op(id)?;
    let imp = op_table().get(id).ok_or("no OpImpl")?;
    let byte_size = u64::try_from(serde_json::to_vec(candidate)?.len())?;
    let ctx = PreviewCtx {
        spec,
        instance_alias: "jira-prod",
        params,
        input: PreviewInput::Read(ReadView {
            candidate,
            byte_size,
            server_total: candidate.get("total").and_then(Value::as_u64),
            more_available: more,
            clamped,
        }),
    };
    Ok((imp.previewer)(&ctx))
}

fn ids(m: &PreviewModel) -> Vec<WarningId> {
    m.warnings.iter().map(|w| w.id).collect()
}

#[test]
fn fallback_preview_header_and_tree() -> TestResult {
    let issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    let m = read_preview(
        "jira.issue.get",
        &json!({"key": "ABC-1"}),
        &issue,
        false,
        false,
    )?;
    assert_eq!(m.header.op_id, "jira.issue.get");
    assert_eq!(m.header.instance_alias, "jira-prod");
    assert_eq!(m.header.class, "read");
    assert_eq!(
        m.header.byte_size,
        u64::try_from(fixtures::JIRA_ISSUE.len())?
    );
    assert_eq!(m.header.item_count, None);
    assert_eq!(
        m.header.fields_included.len(),
        atlas_duck_registry::ISSUE_GET_DEFAULT_FIELDS.len()
    );
    assert_eq!((m.header.bidi_controls, m.header.other_invisible), (0, 0));
    assert!(m.warnings.is_empty());
    assert!(matches!(m.body, PreviewBody::JsonTree { .. }));
    assert_eq!(m.query, None);

    let m = read_preview(
        "jira.issue.get",
        &json!({"key": "ABC-1", "fields": ["*all"]}),
        &issue,
        false,
        false,
    )?;
    assert_eq!(ids(&m), vec![WarningId::AllFields]);
    Ok(())
}

#[test]
fn fallback_counts_raw_strings_not_serialized_json() -> TestResult {
    // ESC is escaped as \u001b by serde_json; it must still be counted (S-13).
    let candidate =
        json!({"key": "ABC-1", "fields": {"summary": "a\u{1B}b\u{202E}c", "x\u{200B}y": 1}});
    let m = read_preview(
        "jira.issue.get",
        &json!({"key": "ABC-1"}),
        &candidate,
        false,
        false,
    )?;
    assert_eq!((m.header.bidi_controls, m.header.other_invisible), (1, 2));
    assert_eq!(
        ids(&m),
        vec![WarningId::BidiControls, WarningId::OtherInvisible]
    );
    Ok(())
}

#[test]
fn fallback_paged_counts_and_truncation() -> TestResult {
    let page: Value = serde_json::from_str(&fixtures::jira_search_page(0, 50, 120, 50))?;
    let m = read_preview(
        "jira.search",
        &json!({"jql": "project = ABC", "max": 900}),
        &page,
        true,
        true,
    )?;
    assert_eq!(
        m.header.item_count,
        Some(ItemCount {
            shown: 50,
            total: Some(120),
            more_available: true
        })
    );
    assert_eq!(ids(&m), vec![WarningId::TruncatedByCap]);
    assert_eq!(m.warnings[0].text, "result truncated by cap (50 of 120)");
    assert_eq!(m.query.as_deref(), Some("project = ABC"));
    // Not clamped, or nothing more available: no warning.
    let m = read_preview("jira.search", &json!({"jql": "x"}), &page, false, true)?;
    assert!(m.warnings.is_empty());
    let m = read_preview(
        "jira.search",
        &json!({"jql": "x", "max": 900}),
        &page,
        true,
        false,
    )?;
    assert!(m.warnings.is_empty());
    Ok(())
}

#[test]
fn search_preview_shows_effective_cql() -> TestResult {
    let page: Value = serde_json::from_str(fixtures::CONFLUENCE_SEARCH_PAGE)?;
    let m = read_preview(
        "confluence.search",
        &json!({"cql": "space = DOC\u{202E}"}),
        &page,
        false,
        false,
    )?;
    assert_eq!(
        m.query.as_deref(),
        Some(format!("(space = DOC⟨U+202E⟩) AND {TYPES}").as_str())
    );
    Ok(())
}

#[test]
fn fallback_mixed_script_identifiers() -> TestResult {
    // A punycode host is all ASCII: only its Unicode form shows the mix (Latin j, Cyrillic і).
    let host = idna::domain_to_ascii("j\u{456}ra.example")?;
    assert!(host.starts_with("xn--"));
    let candidate = json!({
        "self": format!("https://{host}:8443/rest/api/2/issue/1"),
        "key": "\u{410}BC-1",
        "fields": {
            "summary": "Prose \u{43f}\u{440}\u{43e}\u{441}\u{442}o is never checked",
            "assignee": {"name": "j\u{43e}hn", "key": "JIRAUSER1", "displayName": "J\u{43e}hn Doe"},
            "status": {"name": "Ope\u{43d}"}
        }
    });
    let m = read_preview(
        "jira.issue.get",
        &json!({"key": "ABC-1"}),
        &candidate,
        false,
        false,
    )?;
    let texts: Vec<&str> = m
        .warnings
        .iter()
        .filter(|w| w.id == WarningId::MixedScript)
        .map(|w| w.text.as_str())
        .collect();
    // Document order of the (key-sorted) candidate: fields.assignee, key, self.
    assert_eq!(
        texts,
        vec![
            "mixed-script identifier: j\u{43e}hn",
            "mixed-script identifier: \u{410}BC-1",
            "mixed-script identifier: j\u{456}ra.example",
        ]
    );
    Ok(())
}

fn write_preview(
    id: &str,
    params: &Value,
    requests: &[HttpRequestSpec],
    hold: Hold,
    enrichment: Option<&EnrichVerdict>,
    failure: Option<&EnrichFailure>,
) -> Result<PreviewModel, Box<dyn std::error::Error>> {
    let spec = op(id)?;
    let imp = op_table().get(id).ok_or("no OpImpl")?;
    let ctx = PreviewCtx {
        spec,
        instance_alias: "jira-prod",
        params,
        input: PreviewInput::Write(WriteView {
            requests,
            hold,
            enrichment,
            failure,
        }),
    };
    Ok((imp.previewer)(&ctx))
}

#[test]
fn write_preview_shows_exact_requests() -> TestResult {
    let params = json!({"key": "ABC-1", "body": "Fixed \u{202E}.", "body_format": "wiki"});
    let requests = write_requests("jira.comment.add", &params, None)?;
    let m = write_preview(
        "jira.comment.add",
        &params,
        &requests,
        Hold::Preview,
        None,
        None,
    )?;
    assert_eq!(m.header.class, "write");
    assert_eq!(m.header.receipt_fields, vec!["id".to_owned()]);
    assert_eq!(m.header.executes_as, None);
    assert_eq!(m.header.byte_size, u64::try_from(requests[0].body.len())?);
    assert_eq!(m.header.bidi_controls, 1);
    let PreviewBody::WriteRequests { requests: views } = &m.body else {
        return Err("expected WriteRequests".into());
    };
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].method, "POST");
    assert_eq!(views[0].resolved_url, requests[0].resolved_url);
    assert_eq!(
        views[0].body,
        BodyView::Text(String::from_utf8(requests[0].body.clone())?)
    );

    let m = write_preview(
        "jira.issue.create",
        &json!({"project": "ABC", "issuetype": "Bug", "summary": "S"}),
        &[],
        Hold::Preview,
        None,
        None,
    )?;
    assert_eq!(
        m.header.receipt_fields,
        vec!["id".to_owned(), "key".to_owned()]
    );
    Ok(())
}

#[test]
fn write_preview_hold_bodies() -> TestResult {
    let params = json!({"key": "ABC-1", "transition": "Doen"});
    let transitions: Value = serde_json::from_str(fixtures::JIRA_TRANSITIONS)?;
    let issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    let (_, v) = enrich("jira.issue.transition", &params, &[transitions, issue])?;
    let m = write_preview(
        "jira.issue.transition",
        &params,
        &[],
        v.hold,
        Some(&v),
        None,
    )?;
    assert_eq!(
        m.body,
        PreviewBody::UnresolvedName {
            param: "transition".to_owned(),
            value: "Doen".to_owned(),
            matches: 0,
            candidates: vec!["Start Progress".to_owned(), "Done".to_owned()],
        }
    );

    let params = json!({"id": "65537", "base_version": 5, "body": "b", "body_format": "storage"});
    let page: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE)?;
    let (_, v) = enrich("confluence.page.update", &params, &[page])?;
    let m = write_preview(
        "confluence.page.update",
        &params,
        &[],
        v.hold,
        Some(&v),
        None,
    )?;
    let PreviewBody::Conflict { summary, .. } = &m.body else {
        return Err("expected Conflict".into());
    };
    assert_eq!(
        summary,
        "conflict: page changed since the agent read it (v5 → v7)"
    );
    assert!(ids(&m).contains(&WarningId::Conflict));

    let failure = EnrichFailure {
        status: Some(404),
        text: "Issue does not exist".to_owned(),
        outcome: None,
    };
    let m = write_preview(
        "jira.issue.edit",
        &json!({"key": "ABC-1"}),
        &[],
        Hold::EnrichmentError,
        None,
        Some(&failure),
    )?;
    assert_eq!(
        m.body,
        PreviewBody::enrichment_error(Some(404), "Issue does not exist", None)
    );
    Ok(())
}
