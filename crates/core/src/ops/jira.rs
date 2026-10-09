//! Jira specifics in M3 (PD-09): `jira.issue.get`'s flag mapping, and the four M3 writes with
//! their enrichment (name resolution, `expected` conflict, from-status baseline).

use atlas_duck_atlassian::GetCall;
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::warning::{Warning, WarningId};
use serde_json::{Map, Value, json};

use super::{
    EnrichCtx, EnrichPurpose, EnrichRule, EnrichVerdict, ExecCtx, ExecError, ExecPlan, generic,
    get_call, json_request, str_param,
};
use crate::lifecycle::model::Hold;
use crate::validate::invalid;

/// At most this many candidate names in an unresolved-name preview and deny hint (§5.4 step 2).
pub const MAX_CANDIDATES: usize = 10;

const ISSUE_PATH: &str = "/rest/api/2/issue/{key}";
const TRANSITIONS_PATH: &str = "/rest/api/2/issue/{key}/transitions";
const CREATEMETA_ISSUETYPES_PATH: &str = "/rest/api/2/issue/createmeta/{project}/issuetypes";

// ---- jira.issue.get ----------------------------------------------------------------------------

/// §7.3: `changelog` → `expand += changelog`, `rendered` → `expand += renderedFields`; the
/// default `fields` come from the registry. `comments` is accepted and has no effect until M5
/// merges the comment-list executor (PD-09).
pub fn issue_get_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    let mut expand: Vec<Value> = ctx
        .params
        .get("expand")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (flag, value) in [("changelog", "changelog"), ("rendered", "renderedFields")] {
        if ctx.params.get(flag) == Some(&Value::Bool(true))
            && !expand.iter().any(|e| e.as_str() == Some(value))
        {
            expand.push(Value::from(value));
        }
    }
    let mut params = ctx.params.clone();
    if let Some(map) = params.as_object_mut()
        && !expand.is_empty()
    {
        map.insert("expand".to_owned(), Value::Array(expand));
    }
    generic::read_plan(ctx, &params)
}

// ---- name resolution ---------------------------------------------------------------------------

pub(crate) enum Resolution {
    One(String),
    /// Match count (0 or > 1) and candidate names (the matches, or every name when none
    /// matched), at most [`MAX_CANDIDATES`].
    Unresolved(u64, Vec<String>),
}

/// §5.4 step 2: an exact `id`, else exactly one case-insensitive `name`.
pub(crate) fn resolve(items: &[Value], wanted: &str) -> Resolution {
    let id_of = |v: &Value| v.get("id").and_then(Value::as_str).map(str::to_owned);
    let name_of = |v: &Value| v.get("name").and_then(Value::as_str).map(str::to_owned);
    if let Some(hit) = items.iter().find(|v| id_of(v).as_deref() == Some(wanted)) {
        return id_of(hit).map_or(Resolution::Unresolved(0, Vec::new()), Resolution::One);
    }
    let folded = wanted.to_lowercase();
    let matches: Vec<&Value> = items
        .iter()
        .filter(|v| name_of(v).is_some_and(|n| n.to_lowercase() == folded))
        .collect();
    if let [one] = matches.as_slice()
        && let Some(id) = id_of(one)
    {
        return Resolution::One(id);
    }
    let pool: Vec<&Value> = if matches.is_empty() {
        items.iter().collect()
    } else {
        matches.clone()
    };
    let candidates = pool
        .into_iter()
        .filter_map(name_of)
        .take(MAX_CANDIDATES)
        .collect();
    Resolution::Unresolved(u64::try_from(matches.len()).unwrap_or(u64::MAX), candidates)
}

fn unresolved(param: &str, value: &str, matches: u64, candidates: Vec<String>) -> EnrichVerdict {
    EnrichVerdict {
        hold: Hold::UnresolvedName,
        unresolved: Some((param.to_owned(), value.to_owned(), matches, candidates)),
        ..EnrichVerdict::preview(Value::Null, Map::new())
    }
}

/// The `resolved` string of a `Preview` verdict, else `EnrichmentRequired`.
fn resolved_id<'a>(ctx: &'a ExecCtx<'_>, name: &str) -> Result<&'a str, ExecError> {
    ctx.enrichment
        .filter(|v| v.hold == Hold::Preview)
        .and_then(|v| v.resolved.get(name))
        .and_then(Value::as_str)
        .ok_or(ExecError::EnrichmentRequired)
}

fn resolved(name: &str, id: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(name.to_owned(), Value::from(id));
    m
}

// ---- jira.issue.create -------------------------------------------------------------------------

pub static ISSUE_CREATE_ENRICH: EnrichRule = EnrichRule {
    plan: create_plan,
    judge: create_judge,
};

fn create_plan(ctx: &EnrichCtx<'_>) -> Vec<(EnrichPurpose, GetCall)> {
    vec![(
        EnrichPurpose::Resolve,
        get_call(CREATEMETA_ISSUETYPES_PATH, ctx.params, &[]),
    )]
}

fn create_judge(ctx: &EnrichCtx<'_>, responses: &[Value]) -> EnrichVerdict {
    let Some(types) = responses
        .first()
        .and_then(|r| r.get("values"))
        .and_then(Value::as_array)
    else {
        return EnrichVerdict::unusable();
    };
    let wanted = str_param(ctx.params, "issuetype");
    match resolve(types, wanted) {
        Resolution::One(id) => {
            EnrichVerdict::preview(json!({"issuetype_id": id}), resolved("issuetype", &id))
        }
        Resolution::Unresolved(n, candidates) => unresolved("issuetype", wanted, n, candidates),
    }
}

/// `POST /rest/api/2/issue` `{"fields": {project, issuetype: {id}, summary, description?, ..}}`.
pub fn issue_create_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    let issuetype = resolved_id(ctx, "issuetype")?;
    let mut fields = ctx
        .params
        .get("fields")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let project = str_param(ctx.params, "project");
    // Jira project keys start with a letter, so an all-digit value is a project id.
    let project_ref = if !project.is_empty() && project.bytes().all(|b| b.is_ascii_digit()) {
        json!({"id": project})
    } else {
        json!({"key": project})
    };
    fields.insert("project".to_owned(), project_ref);
    fields.insert("issuetype".to_owned(), json!({"id": issuetype}));
    fields.insert(
        "summary".to_owned(),
        Value::from(str_param(ctx.params, "summary")),
    );
    if let Some(description) = ctx.params.get("description") {
        fields.insert("description".to_owned(), description.clone());
    }
    json_request(ctx, &json!({"fields": fields}))
}

// ---- jira.issue.edit ---------------------------------------------------------------------------

pub static ISSUE_EDIT_ENRICH: EnrichRule = EnrichRule {
    plan: edit_plan,
    judge: edit_judge,
};

/// The field ids the edit touches or checks (`fields`, `update` and `expected` keys), sorted.
fn edited_field_ids(params: &Value) -> Vec<String> {
    let mut ids: Vec<String> = ["fields", "update", "expected"]
        .iter()
        .filter_map(|p| params.get(*p).and_then(Value::as_object))
        .flat_map(|m| m.keys().cloned())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// `GET /rest/api/2/issue/{key}?fields=<ids>`; none when there is nothing to read.
pub(crate) fn issue_fields_call(params: &Value, ids: &[String]) -> Option<GetCall> {
    if ids.is_empty() {
        return None;
    }
    Some(get_call(ISSUE_PATH, params, &[("fields", &ids.join(","))]))
}

fn edit_plan(ctx: &EnrichCtx<'_>) -> Vec<(EnrichPurpose, GetCall)> {
    issue_fields_call(ctx.params, &edited_field_ids(ctx.params))
        .map(|c| vec![(EnrichPurpose::Enrich, c)])
        .unwrap_or_default()
}

fn edit_judge(ctx: &EnrichCtx<'_>, responses: &[Value]) -> EnrichVerdict {
    let ids = edited_field_ids(ctx.params);
    if ids.is_empty() {
        return EnrichVerdict::preview(Value::Object(Map::new()), Map::new());
    }
    let Some(current) = responses
        .first()
        .and_then(|r| r.get("fields"))
        .and_then(Value::as_object)
    else {
        return EnrichVerdict::unusable();
    };
    let value_of = |id: &str| current.get(id).cloned().unwrap_or(Value::Null);
    let baseline: Map<String, Value> = ids.iter().map(|id| (id.clone(), value_of(id))).collect();

    let mut changed = Vec::new();
    let mut diff = String::new();
    for (id, expected) in ctx
        .params
        .get("expected")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let now = value_of(id);
        if &now != expected {
            changed.push(id.clone());
            diff.push_str(&format!("{id}\n- read:    {expected}\n+ current: {now}\n"));
        }
    }
    let mut verdict = EnrichVerdict::preview(Value::Object(baseline), Map::new());
    if !changed.is_empty() {
        let summary = escape_for_display(&format!(
            "fields changed since the agent read it: {}",
            changed.join(", ")
        ));
        verdict.hold = Hold::Conflict;
        verdict.warnings.push(Warning::new(
            WarningId::Conflict,
            format!("conflict: {summary}"),
        ));
        verdict.conflict = Some(summary);
        verdict.diff_text = escape_for_display(&diff);
    }
    verdict
}

/// `PUT /rest/api/2/issue/{key}` `{"fields"?, "update"?}`; at least one of them.
pub fn issue_edit_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    let mut body = Map::new();
    for name in ["fields", "update"] {
        if let Some(v) = ctx.params.get(name).filter(|v| !v.is_null()) {
            body.insert(name.to_owned(), v.clone());
        }
    }
    if body.is_empty() {
        return Err(ExecError::Invalid(invalid(
            "fields",
            "nothing to edit: give fields or update",
            None,
        )));
    }
    json_request(ctx, &Value::Object(body))
}

// ---- jira.comment.add --------------------------------------------------------------------------

/// `POST /rest/api/2/issue/{key}/comment` `{"body", "visibility"?}` (wiki markup, PD-09).
pub fn comment_add_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    let mut body = Map::new();
    body.insert(
        "body".to_owned(),
        Value::from(str_param(ctx.params, "body")),
    );
    if let Some(v) = ctx.params.get("visibility").filter(|v| !v.is_null()) {
        body.insert("visibility".to_owned(), v.clone());
    }
    json_request(ctx, &Value::Object(body))
}

// ---- jira.issue.transition ---------------------------------------------------------------------

pub static ISSUE_TRANSITION_ENRICH: EnrichRule = EnrichRule {
    plan: transition_plan,
    judge: transition_judge,
};

/// The available transitions and the current status: enrichment and stale check read the same.
pub(crate) fn transition_calls(params: &Value) -> [GetCall; 2] {
    [
        get_call(
            TRANSITIONS_PATH,
            params,
            &[("expand", "transitions.fields")],
        ),
        get_call(ISSUE_PATH, params, &[("fields", "status")]),
    ]
}

fn transition_plan(ctx: &EnrichCtx<'_>) -> Vec<(EnrichPurpose, GetCall)> {
    let [transitions, status] = transition_calls(ctx.params);
    vec![
        (EnrichPurpose::Resolve, transitions),
        (EnrichPurpose::Enrich, status),
    ]
}

/// `(transitions, current status id)` from the two answers of [`transition_calls`].
pub(crate) fn transition_facts(responses: &[Value]) -> Option<(&Vec<Value>, &str)> {
    let transitions = responses.first()?.get("transitions")?.as_array()?;
    let status = responses
        .get(1)?
        .get("fields")?
        .get("status")?
        .get("id")?
        .as_str()?;
    Some((transitions, status))
}

fn transition_judge(ctx: &EnrichCtx<'_>, responses: &[Value]) -> EnrichVerdict {
    let Some((transitions, status_id)) = transition_facts(responses) else {
        return EnrichVerdict::unusable();
    };
    let wanted = str_param(ctx.params, "transition");
    match resolve(transitions, wanted) {
        Resolution::One(id) => EnrichVerdict::preview(
            json!({"status_id": status_id, "transition_id": id}),
            resolved("transition", &id),
        ),
        Resolution::Unresolved(n, candidates) => unresolved("transition", wanted, n, candidates),
    }
}

/// `POST /rest/api/2/issue/{key}/transitions`
/// `{"transition": {"id"}, "fields"?, "update"?: {"comment": [{"add": {"body"}}]}}`.
pub fn issue_transition_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    let id = resolved_id(ctx, "transition")?;
    let mut body = Map::new();
    body.insert("transition".to_owned(), json!({"id": id}));
    if let Some(fields) = ctx.params.get("fields").filter(|v| !v.is_null()) {
        body.insert("fields".to_owned(), fields.clone());
    }
    if let Some(comment) = ctx.params.get("comment").and_then(Value::as_str) {
        body.insert(
            "update".to_owned(),
            json!({"comment": [{"add": {"body": comment}}]}),
        );
    }
    json_request(ctx, &Value::Object(body))
}
