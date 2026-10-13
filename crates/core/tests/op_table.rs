//! U-05 (core half): the op table, generic read plans, the M3 write executors with their
//! enrichment and stale rules, the CQL rewrite (§7.4) and the fallback / write previews.

use std::collections::BTreeSet;

use atlas_duck_atlassian::testing::fixtures;
use atlas_duck_atlassian::{
    ALLOWED_READ_POSTS, GetCall, HttpRequestSpec, NormalizedBaseUrl, normalize_base_url,
};
use atlas_duck_core::lifecycle::model::Hold;
use atlas_duck_core::ops::{
    DIFF_TEXT_CAP_BYTES, EnrichCtx, EnrichFailure, EnrichPurpose, EnrichStep, EnrichVerdict,
    ExecCtx, ExecError, ExecPlan, PreviewCtx, PreviewInput, PreviewModel, ReadPlan, ReadView,
    StaleCtx, StaleVerdict, WriteView, confluence, entry_count, generic, op_table,
};
use atlas_duck_ipc::envelope::ErrorCode;
use atlas_duck_preview::{BodyView, ItemCount, Level, PreviewBody, WarningId};
use atlas_duck_registry::{BodySource, Method, OpClass, OperationSpec, SCRIPT_RUN};
use proptest::prelude::*;
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
        comments_cap: None,
        #[cfg(feature = "testing")]
        test_fault: None,
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

/// A single-round rule (Δ3, wrapped): its first round's GETs and the judge over `responses`.
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
    let calls = match (rule.plan)(&ctx, &[]) {
        EnrichStep::Fetch(calls) => calls,
        EnrichStep::Judge => Vec::new(),
    };
    Ok((calls, (rule.judge)(&ctx, responses)))
}

/// The next round of a staged rule after `answers` (Δ3).
fn plan_after(
    id: &str,
    params: &Value,
    answers: &[Value],
) -> Result<EnrichStep, Box<dyn std::error::Error>> {
    let spec = op(id)?;
    let rule = op_table()
        .get(id)
        .and_then(|i| i.enrich)
        .ok_or("no enrich rule")?;
    Ok((rule.plan)(&EnrichCtx { spec, params }, answers))
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
    // A duplicated row would shadow another one and still give 46 keys.
    assert_eq!(entry_count(), op_table().len());
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
        // The plan follows the body source; a read declared POST without one would hide.
        let endpoints = [Some(spec.endpoint), spec.alt_endpoint.map(|a| a.endpoint)];
        for e in endpoints.into_iter().flatten() {
            assert!(
                e.method == Method::Get || e.body == BodySource::ParamsAsJson,
                "{}",
                spec.id
            );
        }
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
            // No registry example asks for `comments`.
            ReadPlan::IssueWithComments { .. } => {
                return Err(format!("{}: the example plans a composite read", spec.id).into());
            }
        }
    }
    Ok(())
}

#[test]
fn get_call_params_hold_only_placeholders() -> TestResult {
    let plan = read_plan(
        "jira.issue.get",
        &json!({"key": "ABC-1", "fields": ["summary"], "changelog": false}),
        None,
    )?;
    let ReadPlan::Get(call) = plan else {
        return Err("expected a GET".into());
    };
    assert_eq!(call.endpoint_template, "/rest/api/2/issue/{key}");
    assert_eq!(call.params, json!({"key": "ABC-1"}));
    assert_eq!(query_of(&call), vec![("fields", "summary")]);
    Ok(())
}

/// PD-45: `comments: true` plans the issue GET without `comment` in its `fields`, then the
/// `jira.comment.list` pages (`orderBy=created`, pages of `min(50, cap)`, up to the cap).
#[test]
fn issue_get_comments_plans_the_composite_read() -> TestResult {
    let plan = read_plan(
        "jira.issue.get",
        &json!({"key": "ABC-1", "fields": ["summary", "comment"], "comments": true}),
        None,
    )?;
    let ReadPlan::IssueWithComments {
        issue,
        comments,
        max_items,
        rendered,
    } = plan
    else {
        return Err("expected the composite read".into());
    };
    assert_eq!(issue.endpoint_template, "/rest/api/2/issue/{key}");
    assert_eq!(issue.params, json!({"key": "ABC-1"}));
    assert_eq!(query_of(&issue), vec![("fields", "summary")]);
    assert_eq!(
        comments.get.endpoint_template,
        "/rest/api/2/issue/{key}/comment"
    );
    assert_eq!(comments.get.params, json!({"key": "ABC-1"}));
    assert_eq!(query_of(&comments.get), vec![("orderBy", "created")]);
    assert_eq!(
        (comments.items_key.as_str(), comments.offset_param.as_str()),
        ("comments", "startAt")
    );
    assert_eq!(comments.limit_param, "maxResults");
    assert_eq!((comments.page_size, comments.start), (50, 0));
    // The registry cap (100) when nothing is configured.
    assert_eq!((max_items, rendered), (100, false));

    // Rendered (also through the agent's own `expand`): the pages carry `renderedBody`. A
    // `fields` list of only `comment` is sent as it is (an empty one means the defaults).
    for params in [
        json!({"key": "ABC-1", "comments": true, "rendered": true, "fields": ["comment"]}),
        json!({"key": "ABC-1", "comments": true, "expand": ["renderedFields"], "fields": ["comment"]}),
    ] {
        let ReadPlan::IssueWithComments {
            issue,
            comments,
            rendered,
            ..
        } = read_plan("jira.issue.get", &params, None)?
        else {
            return Err("expected the composite read".into());
        };
        assert!(rendered);
        assert_eq!(
            query_of(&issue),
            vec![("fields", "comment"), ("expand", "renderedFields")]
        );
        assert_eq!(
            query_of(&comments.get),
            vec![("orderBy", "created"), ("expand", "renderedBody")]
        );
    }

    // A configured cap below the page size: one page of the cap.
    let spec = op("jira.issue.get")?;
    let imp = op_table().get("jira.issue.get").ok_or("no OpImpl")?;
    let base = base()?;
    let params = json!({"key": "ABC-1", "comments": true});
    let ctx = ExecCtx {
        spec,
        params: &params,
        base: &base,
        enrichment: None,
        effective_max: None,
        comments_cap: Some(10),
        #[cfg(feature = "testing")]
        test_fault: None,
    };
    let Ok(ExecPlan::Read(ReadPlan::IssueWithComments {
        comments,
        max_items,
        ..
    })) = (imp.executor)(&ctx)
    else {
        return Err("expected the composite read".into());
    };
    assert_eq!((comments.page_size, max_items), (10, 10));
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
        // Mid-query ORDER BY at depth 0: WHERE content after the sort clause.
        "space = DOC ORDER BY created AND label = x",
        "space = A ORDER BY title AND type = space",
        "space = A ORDER BY created OR type = space",
        "space = A ORDER BY title = 'x'",
        "space = A ORDER BY NOT title",
        "space = A ORDER BY",
        "space = A ORDER BY title,",
        "space = A ORDER BY title desc asc",
        "space = A ORDER BY , title",
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
    // Sort keys: words or quoted names, an optional direction, comma-separated.
    assert_eq!(
        confluence::effective_cql("space = A order by title ASC, lastmodified desc,\"created\"")?,
        format!("(space = A) AND {TYPES} order by title ASC, lastmodified desc,\"created\"")
    );
    // ORDER BY inside a string is text, also with AND after it.
    assert_eq!(
        confluence::effective_cql("title ~ \"a ORDER BY b AND c\" ORDER BY created")?,
        format!("(title ~ \"a ORDER BY b AND c\") AND {TYPES} ORDER BY created")
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
    resolved.insert("project_key".to_owned(), json!("ABC"));
    resolved.insert("issuetype".to_owned(), json!("10002"));
    EnrichVerdict::preview(
        json!({"project_key": "ABC", "issuetype_id": "10002"}),
        resolved,
    )
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
        // PD-43: Markdown bodies convert in the executor; every render gives the same bytes.
        (
            "jira.issue.create",
            json!({"project": "ABC", "issuetype": "bug", "summary": "S",
                   "description": MARKDOWN}),
            Some(create_verdict()),
        ),
        (
            "jira.comment.add",
            json!({"key": "ABC-1", "body": MARKDOWN, "body_format": "markdown"}),
            None,
        ),
    ]
}

/// A Markdown body with a heading, emphasis, wiki specials, a quote and a code block.
const MARKDOWN: &str =
    "# Steps\n\n**bold** {toc} [~jdoe]\n\n> quoted\n>\n> twice\n\n```rust\n{code}\n```\n";

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
    // The Markdown cases carry the converter's output (PD-43), never the agent's text.
    let wiki = json!(atlas_duck_convert::markdown_to_wiki(MARKDOWN).0);
    let create =
        json!({"project": "ABC", "issuetype": "bug", "summary": "S", "description": MARKDOWN});
    let r = &write_requests("jira.issue.create", &create, Some(&create_verdict()))?[0];
    assert_eq!(body_json(r)?["fields"]["description"], wiki);
    let comment = json!({"key": "ABC-1", "body": MARKDOWN});
    let r = &write_requests("jira.comment.add", &comment, None)?[0];
    assert_eq!(body_json(r)?["body"], wiki);
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

    // PD-48: the body names the key enrichment resolved, whatever the agent wrote (the M3
    // all-digit `{"id"}` guess is gone).
    let p = json!({"project": "10000", "issuetype": "Bug", "summary": "S"});
    let r = &write_requests("jira.issue.create", &p, Some(&create_verdict()))?[0];
    assert_eq!(body_json(r)?["fields"]["project"], json!({"key": "ABC"}));
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

/// The single call of a `Fetch` round.
fn one_call(step: EnrichStep) -> Result<(EnrichPurpose, GetCall), Box<dyn std::error::Error>> {
    match step {
        EnrichStep::Fetch(mut calls) if calls.len() == 1 => calls.pop().ok_or("no call".into()),
        other => Err(format!("not one GET: {other:?}").into()),
    }
}

/// Δ3 / PD-48 / PD-49 (rewritten from M3's one-stage issue-type rule): projects, then the
/// resolved project's issue types, then the issue type's createmeta fields, then `Judge`.
#[test]
fn create_resolves_issuetype_by_id_or_name() -> TestResult {
    const CREATE: &str = "jira.issue.create";
    let projects: Value = serde_json::from_str(fixtures::JIRA_PROJECTS)?;
    let types: Value = serde_json::from_str(fixtures::JIRA_CREATEMETA_ISSUETYPES)?;
    let fields: Value = serde_json::from_str(fixtures::JIRA_CREATEMETA_FIELDS)?;
    let params = json!({"project": "alpha beta", "issuetype": "bug", "summary": "S"});

    let (purpose, call) = one_call(plan_after(CREATE, &params, &[])?)?;
    assert_eq!(purpose, EnrichPurpose::Resolve);
    assert_eq!(call.endpoint_template, "/rest/api/2/project");
    let (purpose, call) = one_call(plan_after(
        CREATE,
        &params,
        std::slice::from_ref(&projects),
    )?)?;
    assert_eq!(purpose, EnrichPurpose::Resolve);
    assert_eq!(
        call.endpoint_template,
        "/rest/api/2/issue/createmeta/{project}/issuetypes"
    );
    // The resolved key, never the agent's value.
    assert_eq!(call.params, json!({"project": "ABC"}));
    let two = [projects.clone(), types.clone()];
    let (purpose, call) = one_call(plan_after(CREATE, &params, &two)?)?;
    assert_eq!(purpose, EnrichPurpose::Enrich);
    assert_eq!(
        call.endpoint_template,
        "/rest/api/2/issue/createmeta/{project}/issuetypes/{typeId}"
    );
    assert_eq!(call.params, json!({"project": "ABC", "typeId": "10002"}));
    let all = [projects.clone(), types.clone(), fields.clone()];
    assert_eq!(plan_after(CREATE, &params, &all)?, EnrichStep::Judge);
    let (_, v) = enrich(CREATE, &params, &all)?;
    assert_eq!(v.hold, Hold::Preview);
    assert_eq!(v.resolved.get("project_key"), Some(&json!("ABC")));
    assert_eq!(v.resolved.get("issuetype"), Some(&json!("10002")));
    assert!(v.missing_fields.is_empty() && v.warnings.is_empty());

    let by_id = json!({"project": "ABC", "issuetype": "10001", "summary": "S"});
    let (_, v) = enrich(CREATE, &by_id, &all)?;
    assert_eq!(v.resolved.get("issuetype"), Some(&json!("10001")));

    // An unresolved issue type: `Judge` at once, no fields GET.
    let bugg = json!({"project": "ABC", "issuetype": "Bugg", "summary": "S"});
    assert_eq!(plan_after(CREATE, &bugg, &two)?, EnrichStep::Judge);
    let (_, v) = enrich(CREATE, &bugg, &two)?;
    assert_eq!(v.hold, Hold::UnresolvedName);
    let (param, value, matches, candidates) = v.unresolved.ok_or("unresolved")?;
    assert_eq!(
        (param.as_str(), value.as_str(), matches),
        ("issuetype", "Bugg", 0)
    );
    assert_eq!(candidates, vec!["Story".to_owned(), "Bug".to_owned()]);

    // Two types with the same name (case-insensitive) are ambiguous.
    let twice = json!({"values": [{"id": "1", "name": "Bug"}, {"id": "2", "name": "BUG"}]});
    let (_, v) = enrich(CREATE, &params, &[projects.clone(), twice])?;
    assert_eq!(v.hold, Hold::UnresolvedName);
    assert_eq!(v.unresolved.map(|u| u.2), Some(2));

    // An unresolved project: `Judge` after stage 1.
    let nope = json!({"project": "Nope", "issuetype": "Bug", "summary": "S"});
    assert_eq!(
        plan_after(CREATE, &nope, std::slice::from_ref(&projects))?,
        EnrichStep::Judge
    );
    let (_, v) = enrich(CREATE, &nope, std::slice::from_ref(&projects))?;
    assert_eq!(
        v.unresolved.map(|u| (u.0, u.2)),
        Some(("project".to_owned(), 0))
    );

    // Answers missing or of the wrong shape: fail closed.
    for answers in [
        Vec::new(),
        vec![projects.clone(), types.clone()],
        vec![json!({"values": []})],
        vec![projects.clone(), types.clone(), json!([])],
        // A server key that cannot stand in a URL path.
        vec![json!([{"id": "1", "key": "../x", "name": "Alpha Beta"}])],
    ] {
        let (_, v) = enrich(CREATE, &params, &answers)?;
        assert_eq!(v.hold, Hold::EnrichmentError, "{answers:?}");
    }
    let bad_key = json!([{"id": "1", "key": "../x", "name": "Alpha Beta"}]);
    assert_eq!(plan_after(CREATE, &params, &[bad_key])?, EnrichStep::Judge);
    Ok(())
}

/// PD-49: which required fields are missing, the Caution text, the cap of 10 names.
#[test]
fn create_missing_required_fields() -> TestResult {
    const CREATE: &str = "jira.issue.create";
    let projects: Value = serde_json::from_str(fixtures::JIRA_PROJECTS)?;
    let types: Value = serde_json::from_str(fixtures::JIRA_CREATEMETA_ISSUETYPES)?;
    let field = |id: &str, name: &str, ty: &str, required: bool, default: bool| {
        json!({"fieldId": id, "name": name, "schema": {"type": ty}, "required": required,
               "hasDefaultValue": default})
    };
    let page = json!({"isLast": true, "values": [
        field("summary", "Summary", "string", true, false),
        field("description", "Description", "string", true, false),
        field("customfield_1", "Team", "option", true, false),
        field("customfield_2", "Points", "number", true, true),
        field("customfield_3", "Notes", "string", false, false),
        field("labels", "Labels", "array", true, false)
    ]});
    let answers = [projects.clone(), types.clone(), page];
    // No description param and no `fields`: description, Team and Labels are missing.
    let p = json!({"project": "ABC", "issuetype": "Bug", "summary": "S"});
    let (_, v) = enrich(CREATE, &p, &answers)?;
    assert_eq!(v.hold, Hold::Preview);
    let ids: Vec<&str> = v.missing_fields.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["description", "customfield_1", "labels"]);
    assert_eq!(v.warnings.len(), 1);
    assert_eq!(v.warnings[0].id, WarningId::MissingRequiredFields);
    assert_eq!(
        v.warnings[0].text,
        "missing required fields: Description (description, string), Team (customfield_1, \
         option), Labels (labels, array)"
    );
    // A description param and `fields` keys set them.
    let p = json!({"project": "ABC", "issuetype": "Bug", "summary": "S", "description": "D",
                   "fields": {"customfield_1": {"value": "x"}, "labels": []}});
    let (_, v) = enrich(CREATE, &p, &answers)?;
    assert!(v.missing_fields.is_empty() && v.warnings.is_empty());

    // More than 10: ten names, then "… and N more"; names display-escaped.
    let values: Vec<Value> = (0..12)
        .map(|n| {
            field(
                &format!("customfield_{n}"),
                &format!("F{n}\u{202E}"),
                "string",
                true,
                false,
            )
        })
        .collect();
    let answers = [projects, types, json!({"isLast": true, "values": values})];
    let p = json!({"project": "ABC", "issuetype": "Bug", "summary": "S"});
    let (_, v) = enrich(CREATE, &p, &answers)?;
    assert_eq!(v.missing_fields.len(), 12);
    let text = &v.warnings[0].text;
    assert!(text.ends_with(", … and 2 more"), "{text}");
    assert!(
        text.contains("F9⟨U+202E⟩ (customfield_9, string)"),
        "{text}"
    );
    assert!(!text.contains("F10"), "{text}");
    assert!(!text.contains('\u{202E}'), "{text}");
    Ok(())
}

/// The projects and issue-type fixtures: the answers of the create's first two stages.
fn create_stage_answers() -> Result<[Value; 2], serde_json::Error> {
    Ok([
        serde_json::from_str(fixtures::JIRA_PROJECTS)?,
        serde_json::from_str(fixtures::JIRA_CREATEMETA_ISSUETYPES)?,
    ])
}

/// A createmeta field that is not required.
fn optional_field(n: u64) -> Value {
    json!({"fieldId": format!("customfield_{}", 30_000 + n), "name": format!("F{n}"),
           "schema": {"type": "string"}, "required": false, "hasDefaultValue": false})
}

/// A createmeta field page of `count` optional fields from `start`.
fn field_page(start: u64, max: u64, total: Option<u64>, last: bool, count: u64) -> Value {
    let mut page = json!({"startAt": start, "maxResults": max, "isLast": last,
                          "values": (start..start + count).map(optional_field).collect::<Vec<_>>()});
    if let Some(total) = total {
        page["total"] = json!(total);
    }
    page
}

/// Name/value pairs: a query, or the rows of a card.
type Pairs = Vec<(String, String)>;

/// The later field pages a plan asks for, as `(startAt, maxResults)` query pairs.
fn later_pages(step: EnrichStep) -> Result<Vec<Pairs>, Box<dyn std::error::Error>> {
    let EnrichStep::Fetch(calls) = step else {
        return Err("no later pages".into());
    };
    Ok(calls
        .iter()
        .map(|(purpose, call)| {
            assert_eq!(*purpose, EnrichPurpose::Enrich);
            query_of(call)
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect()
        })
        .collect())
}

fn page_query(start: u64, max: u64) -> Pairs {
    vec![
        ("startAt".to_owned(), start.to_string()),
        ("maxResults".to_owned(), max.to_string()),
    ]
}

/// T12 review M2: a page that is not the last but shorter than its `maxResults` steps the later
/// pages by its own length, so no field between them is skipped.
#[test]
fn create_later_pages_step_by_page_length() -> TestResult {
    const CREATE: &str = "jira.issue.create";
    let [projects, types] = create_stage_answers()?;
    let params = json!({"project": "ABC", "issuetype": "Bug", "summary": "S"});
    let short = field_page(0, 5, Some(6), false, 2);
    let pages = later_pages(plan_after(CREATE, &params, &[projects, types, short])?)?;
    assert_eq!(pages, [page_query(2, 2), page_query(4, 2)]);
    Ok(())
}

/// PD-49 / T12 review M10: at most 4 field pages: a total of 1000 asks for pages 2..4 (one round)
/// and no fifth; after them the plan judges.
#[test]
fn create_field_pages_capped_at_four() -> TestResult {
    const CREATE: &str = "jira.issue.create";
    let [projects, types] = create_stage_answers()?;
    let params = json!({"project": "ABC", "issuetype": "Bug", "summary": "S"});
    let first = field_page(0, 50, Some(1000), false, 50);
    let mut answers = vec![projects, types, first];
    let pages = later_pages(plan_after(CREATE, &params, &answers)?)?;
    assert_eq!(
        pages,
        [page_query(50, 50), page_query(100, 50), page_query(150, 50)]
    );
    answers.extend((1..4).map(|k| field_page(k * 50, 50, Some(1000), false, 50)));
    assert!(matches!(
        plan_after(CREATE, &params, &answers)?,
        EnrichStep::Judge
    ));
    Ok(())
}

/// T12 review M10: a required-field list cut by the page cap says so (Info, never a block);
/// a complete one does not.
#[test]
fn create_incomplete_field_list_is_an_info() -> TestResult {
    const CREATE: &str = "jira.issue.create";
    let [projects, types] = create_stage_answers()?;
    let params = json!({"project": "ABC", "issuetype": "Bug", "summary": "S"});
    let judged = |total: Option<u64>, last_is_last: bool| {
        let mut answers = vec![projects.clone(), types.clone()];
        answers.extend((0..4).map(|k| field_page(k * 50, 50, total, k == 3 && last_is_last, 50)));
        enrich(CREATE, &params, &answers).map(|(_, v)| v)
    };
    let info = |v: &EnrichVerdict| {
        v.warnings
            .iter()
            .find(|w| w.id == WarningId::RequiredFieldListIncomplete)
            .cloned()
    };
    let v = judged(Some(1000), false)?;
    assert_eq!(v.hold, Hold::Preview);
    let w = info(&v).ok_or("no incomplete-list warning")?;
    assert_eq!(w.level, Level::Info);
    assert_eq!(w.text, "required-field list incomplete: 4 of 20 pages read");
    // No total: the fourth page still says `isLast: false`.
    let v = judged(None, false)?;
    let w = info(&v).ok_or("no incomplete-list warning")?;
    assert_eq!(
        w.text,
        "required-field list incomplete: 4 of more than 4 pages read"
    );
    // Complete: every page up to the total was read, or the last one says so.
    assert!(info(&judged(Some(200), false)?).is_none());
    assert!(info(&judged(None, true)?).is_none());
    let one = [projects, types, field_page(0, 50, None, true, 3)];
    assert!(info(&enrich(CREATE, &params, &one)?.1).is_none());
    Ok(())
}

/// T12 review M6: an empty string or a `null` does not set a required field (Jira refuses it).
#[test]
fn create_empty_or_null_value_leaves_a_required_field_missing() -> TestResult {
    const CREATE: &str = "jira.issue.create";
    let [projects, types] = create_stage_answers()?;
    let required = |id: &str, name: &str, ty: &str| {
        json!({"fieldId": id, "name": name, "schema": {"type": ty}, "required": true,
               "hasDefaultValue": false})
    };
    let page = json!({"isLast": true, "values": [
        required("description", "Description", "string"),
        required("customfield_1", "Team", "option"),
        required("customfield_2", "Notes", "string")
    ]});
    let answers = [projects, types, page];
    let p = json!({"project": "ABC", "issuetype": "Bug", "summary": "S", "description": "",
                   "fields": {"customfield_1": null, "customfield_2": ""}});
    let (_, v) = enrich(CREATE, &p, &answers)?;
    let ids: Vec<&str> = v.missing_fields.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["description", "customfield_1", "customfield_2"]);
    Ok(())
}

/// T12 review I1 / M5: each allowed value keeps the Jira value it stands for (`{"id"}` when
/// createmeta gives one, else `{"value"}`, in an array for an `array` of `option`; none derivable
/// from a bare `name`), and a field with more than 10 keeps the first 10 and counts them all.
#[test]
fn create_missing_field_allowed_values_carry_wire_values() -> TestResult {
    const CREATE: &str = "jira.issue.create";
    let [projects, types] = create_stage_answers()?;
    let field = |id: &str, schema: Value, allowed: Value| {
        json!({"fieldId": id, "name": id, "schema": schema, "required": true,
               "hasDefaultValue": false, "allowedValues": allowed})
    };
    let many: Vec<Value> = (0..12)
        .map(|n| json!({"id": format!("{}", 500 + n), "value": format!("V{n}")}))
        .collect();
    let page = json!({"isLast": true, "values": [
        field("customfield_1", json!({"type": "option"}), json!([
            {"id": "10400", "value": "Platform"}, {"value": "Ops"}, {"id": "10402"},
            {"name": "Legacy"}
        ])),
        field("customfield_2", json!({"type": "array", "items": "option"}),
              json!([{"id": "1", "value": "UI"}, {"value": "API"}])),
        field("customfield_3", json!({"type": "option"}), json!(many))
    ]});
    let p = json!({"project": "ABC", "issuetype": "Bug", "summary": "S"});
    let (_, v) = enrich(CREATE, &p, &[projects, types, page])?;
    let [single, multi, long] = v.missing_fields.as_slice() else {
        return Err(format!("{:?}", v.missing_fields).into());
    };
    let pairs = |f: &atlas_duck_core::ops::MissingField| -> Vec<(String, Option<Value>)> {
        f.allowed_values
            .iter()
            .map(|a| (a.label.clone(), a.wire.clone()))
            .collect()
    };
    assert_eq!(
        pairs(single),
        [
            ("Platform".to_owned(), Some(json!({"id": "10400"}))),
            ("Ops".to_owned(), Some(json!({"value": "Ops"}))),
            ("10402".to_owned(), Some(json!({"id": "10402"}))),
            ("Legacy".to_owned(), None),
        ]
    );
    assert_eq!(single.allowed_total, 4);
    assert_eq!(
        pairs(multi),
        [
            ("UI".to_owned(), Some(json!([{"id": "1"}]))),
            ("API".to_owned(), Some(json!([{"value": "API"}]))),
        ]
    );
    assert_eq!(long.allowed_values.len(), 10);
    assert_eq!(long.allowed_total, 12);
    Ok(())
}

/// T12 review M4 / M8: the create card's project and issue type are read from the request that
/// is sent, a `fields` row is named like the Caution names it (`<name> (<id>)`), and a verdict
/// whose facts disagree with the sent body cannot put its names on the card.
#[test]
fn create_preview_rows_come_from_the_sent_body() -> TestResult {
    const CREATE: &str = "jira.issue.create";
    let [projects, types] = create_stage_answers()?;
    let page = json!({"isLast": true, "values": [
        {"fieldId": "customfield_1", "name": "Team", "schema": {"type": "option"},
         "required": true, "hasDefaultValue": false}
    ]});
    let p = json!({"project": "ABC", "issuetype": "Bug", "summary": "S",
                   "fields": {"customfield_1": {"id": "10400"}}});
    let (_, v) = enrich(CREATE, &p, &[projects, types, page])?;
    let rows_of = |v: &EnrichVerdict| -> Result<(String, Pairs), Box<dyn std::error::Error>> {
        let requests = write_requests(CREATE, &p, Some(v))?;
        match write_preview(CREATE, &p, &requests, Hold::Preview, Some(v), None)?.body {
            PreviewBody::WriteSummary { sentence, rows, .. } => Ok((sentence, rows)),
            other => Err(format!("not the create card: {other:?}").into()),
        }
    };
    let row = |rows: &[(String, String)], k: &str| {
        rows.iter()
            .find(|(name, _)| name == k)
            .map(|(_, v)| v.clone())
    };
    let (sentence, rows) = rows_of(&v)?;
    assert_eq!(sentence, "Create a Bug in ABC");
    assert_eq!(row(&rows, "Project").as_deref(), Some("ABC (Alpha Beta)"));
    assert_eq!(row(&rows, "Issue type").as_deref(), Some("Bug"));
    assert_eq!(
        row(&rows, "Team (customfield_1)").as_deref(),
        Some(r#"{"id":"10400"}"#),
        "{rows:?}"
    );
    // The executor sends what `resolved` says; facts that disagree are not shown as its names.
    let mut other = v.clone();
    other
        .resolved
        .insert("project_key".to_owned(), json!("OPS"));
    other
        .resolved
        .insert("issuetype".to_owned(), json!("10001"));
    let (sentence, rows) = rows_of(&other)?;
    assert_eq!(
        row(&rows, "Project").as_deref(),
        Some("OPS (enrichment resolved ABC)")
    );
    assert_eq!(
        row(&rows, "Issue type").as_deref(),
        Some("10001 (enrichment resolved 10002)")
    );
    assert_eq!(sentence, "Create a 10001 in OPS");
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
        Some("conflict: fields changed since the agent read it: summary")
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
fn edit_conflict_diff_is_capped() -> TestResult {
    let mut issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    issue["fields"]["description"] = json!("é".repeat(40 * 1024));
    let params =
        json!({"key": "ABC-1", "fields": {"description": "x"}, "expected": {"description": "y"}});
    let (_, v) = enrich("jira.issue.edit", &params, &[issue])?;
    assert_eq!(v.hold, Hold::Conflict);
    assert!(v.diff_text.len() <= DIFF_TEXT_CAP_BYTES);
    // T13 review M-5: the long `+ current` line is cut at its own budget and marked there.
    assert!(v.diff_text.ends_with("…\n"), "{:?}", v.diff_text.get(..80));
    Ok(())
}

#[test]
fn page_update_refuses_non_page_content() -> TestResult {
    let mut post: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE)?;
    post["type"] = json!("blogpost");
    let params = json!({"id": "65537", "base_version": 7, "body": "b", "body_format": "storage"});
    let (_, v) = enrich("confluence.page.update", &params, &[post])?;
    assert_eq!(v.hold, Hold::EnrichmentError);
    Ok(())
}

#[test]
fn dry_call_checks_write_paths_before_enrichment() -> TestResult {
    // `project` has no schema pattern; a dot segment is caught by the dry call, not at the
    // enrichment GET.
    let r = exec(
        "jira.issue.create",
        &json!({"project": "..", "issuetype": "Bug", "summary": "S"}),
        None,
        None,
    )?;
    assert!(matches!(r, Err(ExecError::Invalid(e))
        if e.code == ErrorCode::Validation && e.details.get("param") == Some(&json!("project"))));
    Ok(())
}

proptest! {
    #[test]
    fn cql_never_panics(cql in "[a-zA-Z0-9 ()'\"\\\\=~,<>!é😀\u{202E}]{0,40}") {
        if let Ok(q) = confluence::effective_cql(&cql) {
            prop_assert!(q.contains(") AND type in (page,blogpost,comment,attachment)"));
        }
    }
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
            comments_truncated: None,
        }),
        field_names: None,
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
    // T10: `jira.issue.get` has its own layout; the other fallback tests cover the JSON tree.
    assert!(matches!(m.body, PreviewBody::JiraIssue { .. }));
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
        field_names: None,
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

#[test]
fn ops_without_a_layout_use_the_json_tree() -> TestResult {
    let m = read_preview(
        "jira.project.get",
        &json!({"key": "ABC"}),
        &json!({"key": "ABC", "name": "Alpha"}),
        false,
        false,
    )?;
    assert!(matches!(m.body, PreviewBody::JsonTree { .. }));
    Ok(())
}
