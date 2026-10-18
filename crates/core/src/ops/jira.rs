//! Jira specifics in M3 (PD-09): `jira.issue.get`'s flag mapping, and the four M3 writes with
//! their enrichment (name resolution, `expected` conflict, from-status baseline). M5: the
//! `--comments` read (PD-45) and the staged create enrichment (Δ3, PD-48, PD-49: project and
//! issue type resolution, the createmeta required fields).

use atlas_duck_atlassian::GetCall;
use atlas_duck_ipc::jcs::to_jcs_vec;
use atlas_duck_preview::diff::{DiffOp, line_diff};
use atlas_duck_preview::invisible::{cut_boundary, escape_for_display};
use atlas_duck_preview::warning::{self, Warning, WarningId};
use serde_json::{Map, Value, json};

use super::{
    AllowedValue, DIFF_TEXT_CAP_BYTES, EnrichCtx, EnrichPurpose, EnrichRule, EnrichStep,
    EnrichVerdict, ExecCtx, ExecError, ExecPlan, MAX_ALLOWED_VALUES, MissingField, ReadPlan,
    WriteSummaryFacts, cap_diff_text, generic, get_call, jira_body, json_request, resolve_url,
    single_round, str_param,
};
use crate::lifecycle::model::Hold;
use crate::validate::invalid;

/// At most this many candidate names in an unresolved-name preview and deny hint (§5.4 step 2).
pub const MAX_CANDIDATES: usize = 10;

pub(crate) const ISSUE_PATH: &str = "/rest/api/2/issue/{key}";
const TRANSITIONS_PATH: &str = "/rest/api/2/issue/{key}/transitions";
const PROJECTS_PATH: &str = "/rest/api/2/project";
const CREATEMETA_ISSUETYPES_PATH: &str = "/rest/api/2/issue/createmeta/{project}/issuetypes";
const CREATEMETA_FIELDS_PATH: &str = "/rest/api/2/issue/createmeta/{project}/issuetypes/{typeId}";

// ---- jira.issue.get ----------------------------------------------------------------------------

/// §7.3: `changelog` → `expand += changelog`, `rendered` → `expand += renderedFields`; the
/// default `fields` come from the registry. `comments` makes the read composite (PD-45, see
/// [`issue_with_comments`]).
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
    if wants_comments(ctx.params) {
        return issue_with_comments(ctx, params);
    }
    generic::read_plan(ctx, &params)
}

/// `comments: true` on `jira.issue.get` (PD-45): the read is the composite
/// [`ReadPlan::IssueWithComments`]. Its committed params decide the merge too
/// (`engine::read::ReadShape`), so the first build and every rebuild agree.
pub fn wants_comments(params: &Value) -> bool {
    params.get("comments") == Some(&Value::Bool(true))
}

/// Whether a composite read's issue carries `renderedFields` (`rendered: true`, or the agent's
/// own `expand`): its comment pages are then fetched with `expand=renderedBody`, so every
/// comment has its `renderedFields.comment` counterpart (the M3 mirror, U-27).
pub fn comments_rendered(params: &Value) -> bool {
    params.get("rendered") == Some(&Value::Bool(true))
        || params
            .get("expand")
            .and_then(Value::as_array)
            .is_some_and(|e| e.iter().any(|v| v.as_str() == Some("renderedFields")))
}

/// The comment pages of `--comments` hold at most this many comments each (§7.3: the
/// `jira.comment.list` page size).
const COMMENT_PAGE_SIZE: u32 = 50;

/// PD-45: the issue GET with `comment` taken out of the agent's `fields` (the merge fills
/// `fields.comment`; a list that held only `comment` is sent as it is, since an empty one would
/// fall back to the registry defaults), then the `jira.comment.list` plan (`orderBy=created`,
/// `+ expand=renderedBody` when rendered) in pages of `min(50, cap)` up to the cap.
fn issue_with_comments(ctx: &ExecCtx<'_>, mut params: Value) -> Result<ExecPlan, ExecError> {
    if let Some(Value::Array(fields)) = params.get_mut("fields") {
        let kept: Vec<Value> = fields
            .iter()
            .filter(|f| f.as_str() != Some("comment"))
            .cloned()
            .collect();
        if !kept.is_empty() {
            *fields = kept;
        }
    }
    let ExecPlan::Read(ReadPlan::Get(issue)) = generic::read_plan(ctx, &params)? else {
        return Err(composite_internal());
    };
    let cap = ctx
        .comments_cap
        .or(ctx.spec.caps.comments_cap)
        .ok_or_else(composite_internal)?
        .max(1);
    let page_size = cap.min(COMMENT_PAGE_SIZE);
    let list = atlas_duck_registry::get("jira.comment.list").ok_or_else(composite_internal)?;
    let mut list_params = Map::new();
    if let Some(key) = ctx.params.get("key") {
        list_params.insert("key".to_owned(), key.clone());
    }
    let list_params = Value::Object(list_params);
    let list_ctx = ExecCtx {
        spec: list,
        params: &list_params,
        base: ctx.base,
        enrichment: None,
        effective_max: Some(page_size),
        comments_cap: None,
        #[cfg(feature = "testing")]
        test_fault: None,
    };
    let ExecPlan::Read(ReadPlan::Paged { mut call, .. }) =
        generic::read_plan(&list_ctx, &list_params)?
    else {
        return Err(composite_internal());
    };
    let rendered = comments_rendered(ctx.params);
    if rendered {
        call.get
            .query
            .push(("expand".to_owned(), "renderedBody".to_owned()));
    }
    Ok(ExecPlan::Read(ReadPlan::IssueWithComments {
        issue,
        comments: Box::new(call),
        max_items: u64::from(cap),
        rendered,
    }))
}

/// A registry entry the composite read needs is missing or of the wrong shape (a bug).
fn composite_internal() -> ExecError {
    ExecError::Invalid(crate::validate::ValidationError {
        code: atlas_duck_ipc::envelope::ErrorCode::Internal,
        message: "the comment pages of the read cannot be planned".to_owned(),
        details: Map::new(),
    })
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

pub(crate) fn unresolved(
    param: &str,
    value: &str,
    matches: u64,
    candidates: Vec<String>,
) -> EnrichVerdict {
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

/// Three stages (Δ3, PD-48, PD-49): the projects (`resolve`), the project's issue types
/// (`resolve`), the issue type's createmeta fields (`enrich`, up to [`MAX_FIELD_PAGES`] pages). An
/// unresolved project or issue type ends the plan early (`Judge`, no further GET).
pub static ISSUE_CREATE_ENRICH: EnrichRule = EnrichRule {
    plan: create_plan,
    judge: create_judge,
};

/// PD-49: at most this many createmeta field pages: the first, then the rest in one round, so
/// the three stages stay within [`super::MAX_ENRICH_STAGES`] rounds.
pub const MAX_FIELD_PAGES: u64 = 4;

/// At most this many missing fields are kept (deny details, pre-added inputs); the Caution counts
/// them all.
pub const MAX_MISSING_FIELDS: usize = 100;

/// Server-supplied names and ids kept for a preview or a deny hint are cut to this many chars.
const NAME_CAP_CHARS: usize = crate::metadata::MAX_NAME_CHARS;

/// The resolved project of a create (PD-48).
struct Project {
    key: String,
    name: Option<String>,
}

/// The resolved issue type of a create.
struct IssueType {
    id: String,
    name: Option<String>,
}

/// `s` cut to [`NAME_CAP_CHARS`] chars (`…` marks a cut). Raw text; escaped where it is shown.
pub(crate) fn capped(s: &str) -> String {
    match s.char_indices().nth(NAME_CAP_CHARS) {
        Some((end, _)) => format!("{}…", &s[..end]),
        None => s.to_owned(),
    }
}

/// A key that can stand in a URL path segment as Jira writes project keys (`[A-Za-z0-9_]+`).
/// Anything else from the server fails the enrichment closed rather than reach a URL.
fn usable_key(key: &str) -> bool {
    !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// PD-48: exactly one project whose `id` equals the value, else whose `key` equals it (ASCII
/// case-insensitively), else whose `name` equals it (case-insensitively, as [`resolve`]). The
/// first rule with any hit decides: one hit resolves, more are ambiguous (the hits are the
/// candidates); no hit at all lists every project (≤ [`MAX_CANDIDATES`] names).
fn resolve_project(ctx: &EnrichCtx<'_>, answer: &Value) -> Result<Project, Box<EnrichVerdict>> {
    let Some(projects) = answer.as_array() else {
        return Err(Box::new(EnrichVerdict::unusable()));
    };
    let wanted = str_param(ctx.params, "project");
    let folded = wanted.to_lowercase();
    let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let rules: [&dyn Fn(&Value) -> bool; 3] = [
        &|v| text(v, "id").as_deref() == Some(wanted),
        &|v| text(v, "key").is_some_and(|k| k.eq_ignore_ascii_case(wanted)),
        &|v| text(v, "name").is_some_and(|n| n.to_lowercase() == folded),
    ];
    let names = |items: Vec<&Value>| -> Vec<String> {
        items
            .into_iter()
            .filter_map(|v| text(v, "name"))
            .take(MAX_CANDIDATES)
            .collect()
    };
    for rule in rules {
        let hits: Vec<&Value> = projects.iter().filter(|v| rule(v)).collect();
        match hits.as_slice() {
            [] => continue,
            [one] => {
                let key = text(one, "key").unwrap_or_default();
                if !usable_key(&key) {
                    return Err(Box::new(EnrichVerdict::unusable()));
                }
                return Ok(Project {
                    key,
                    name: text(one, "name"),
                });
            }
            _ => {
                let n = u64::try_from(hits.len()).unwrap_or(u64::MAX);
                return Err(Box::new(unresolved("project", wanted, n, names(hits))));
            }
        }
    }
    Err(Box::new(unresolved(
        "project",
        wanted,
        0,
        names(projects.iter().collect()),
    )))
}

/// The issue type among the project's createmeta issue types ([`resolve`]); its id goes into the
/// stage-3 path, so it must be all digits (createmeta's `typeId`).
fn resolve_issuetype(ctx: &EnrichCtx<'_>, answer: &Value) -> Result<IssueType, Box<EnrichVerdict>> {
    let Some(types) = answer.get("values").and_then(Value::as_array) else {
        return Err(Box::new(EnrichVerdict::unusable()));
    };
    let wanted = str_param(ctx.params, "issuetype");
    match resolve(types, wanted) {
        Resolution::One(id) if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) => {
            let name = types
                .iter()
                .find(|t| t.get("id").and_then(Value::as_str) == Some(id.as_str()))
                .and_then(|t| t.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            Ok(IssueType { id, name })
        }
        Resolution::One(_) => Err(Box::new(EnrichVerdict::unusable())),
        Resolution::Unresolved(n, candidates) => {
            Err(Box::new(unresolved("issuetype", wanted, n, candidates)))
        }
    }
}

/// Stage 3: `GET /rest/api/2/issue/createmeta/{key}/issuetypes/{typeId}` (a later page with its
/// `startAt` and the server's page size).
fn fields_call(key: &str, type_id: &str, page: Option<(u64, u64)>) -> (EnrichPurpose, GetCall) {
    let params = json!({"project": key, "typeId": type_id});
    let call = match page {
        Some((start, size)) => get_call(
            CREATEMETA_FIELDS_PATH,
            &params,
            &[
                ("startAt", &start.to_string()),
                ("maxResults", &size.to_string()),
            ],
        ),
        None => get_call(CREATEMETA_FIELDS_PATH, &params, &[]),
    };
    (EnrichPurpose::Enrich, call)
}

/// How many fields a createmeta page holds.
fn page_len(page: &Value) -> Option<u64> {
    page.get("values")
        .and_then(Value::as_array)
        .and_then(|v| u64::try_from(v.len()).ok())
}

/// The page step of a createmeta answer: its length when it has one, capped by the server's
/// `maxResults` (T12 review M2: a page shorter than `maxResults` that is not the last must not
/// make the later pages skip fields), else `maxResults`.
fn page_step(first: &Value) -> Option<u64> {
    let max = first
        .get("maxResults")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0);
    match (max, page_len(first).filter(|n| *n > 0)) {
        (Some(max), Some(len)) => Some(max.min(len)),
        (max, len) => max.or(len),
    }
}

/// PD-49: the pages after the first while it says `isLast: false`, all in one round: by
/// [`page_step`] from its `startAt`, below `total` when it sends one, at most
/// [`MAX_FIELD_PAGES`] pages in all. Without a `total` they are asked for speculatively (3 more
/// GETs at most, each answer within the 32 MiB response cap).
fn later_field_pages(key: &str, type_id: &str, first: &Value) -> Vec<(EnrichPurpose, GetCall)> {
    if first.get("isLast").and_then(Value::as_bool) != Some(false) {
        return Vec::new();
    }
    let Some(size) = page_step(first) else {
        return Vec::new();
    };
    let start = first.get("startAt").and_then(Value::as_u64).unwrap_or(0);
    let total = first.get("total").and_then(Value::as_u64);
    (1..MAX_FIELD_PAGES)
        .map_while(|k| start.checked_add(k.checked_mul(size)?))
        .take_while(|s| total.is_none_or(|t| *s < t))
        .map(|s| fields_call(key, type_id, Some((s, size))))
        .collect()
}

/// T12 review M10: whether the field pages read leave some out, as `(pages read, pages in all)`
/// (`None` in all when no `total` says): page 1 said `isLast: false`, and either the pages read
/// end below its `total`, or (no total) the last one read says `isLast: false` too.
fn field_list_cut(pages: &[Value]) -> Option<(u64, Option<u64>)> {
    let first = pages.first()?;
    if first.get("isLast").and_then(Value::as_bool) != Some(false) {
        return None;
    }
    let read = u64::try_from(pages.len()).unwrap_or(u64::MAX);
    match first.get("total").and_then(Value::as_u64) {
        Some(total) => {
            let covered = pages
                .iter()
                .filter_map(|p| {
                    let start = p.get("startAt").and_then(Value::as_u64).unwrap_or(0);
                    start.checked_add(page_len(p)?)
                })
                .max()
                .unwrap_or(0);
            (covered < total).then(|| {
                let all = page_step(first).map(|s| total.div_ceil(s).max(read.saturating_add(1)));
                (read, all)
            })
        }
        None => {
            let more = pages.last()?.get("isLast").and_then(Value::as_bool) == Some(false);
            more.then_some((read, None))
        }
    }
}

/// Δ3: answers `[projects]`, `[.., issue types]`, `[.., fields page 1]`, `[.., later pages]`.
fn create_plan(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichStep {
    let Some(projects) = answers.first() else {
        return EnrichStep::Fetch(vec![(
            EnrichPurpose::Resolve,
            get_call(PROJECTS_PATH, ctx.params, &[]),
        )]);
    };
    let Ok(project) = resolve_project(ctx, projects) else {
        return EnrichStep::Judge;
    };
    let Some(types) = answers.get(1) else {
        let params = json!({"project": project.key});
        return EnrichStep::Fetch(vec![(
            EnrichPurpose::Resolve,
            get_call(CREATEMETA_ISSUETYPES_PATH, &params, &[]),
        )]);
    };
    let Ok(issuetype) = resolve_issuetype(ctx, types) else {
        return EnrichStep::Judge;
    };
    match answers.get(2..) {
        Some([]) | None => EnrichStep::Fetch(vec![fields_call(&project.key, &issuetype.id, None)]),
        Some([first]) => {
            let more = later_field_pages(&project.key, &issuetype.id, first);
            if more.is_empty() {
                EnrichStep::Judge
            } else {
                EnrichStep::Fetch(more)
            }
        }
        Some(_) => EnrichStep::Judge,
    }
}

/// Whether a dedicated param or a `fields` key sets `id` (PD-49). `description` counts only when
/// the agent gave one. A `null` or an empty string sets nothing (T12 review M6: Jira refuses it
/// for a required field); an empty array or object is left to Jira.
fn set_by_params(params: &Value, id: &str) -> bool {
    let set = |v: Option<&Value>| v.is_some_and(|v| !v.is_null() && v.as_str() != Some(""));
    match id {
        "project" | "issuetype" | "summary" | "description" if set(params.get(id)) => true,
        _ => set(params
            .get("fields")
            .and_then(Value::as_object)
            .and_then(|m| m.get(id))),
    }
}

/// T12 review M8: createmeta's `(fieldId, name)` of the `fields` keys the params set, in
/// createmeta order, each once, at most [`MAX_MISSING_FIELDS`] (the card names their rows).
fn set_field_names(params: &Value, pages: &[Value]) -> Vec<(String, String)> {
    let Some(set) = params.get("fields").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut seen = std::collections::HashSet::new();
    pages
        .iter()
        .filter_map(|p| p.get("values").and_then(Value::as_array))
        .flatten()
        .filter_map(|f| {
            let id = f.get("fieldId").and_then(Value::as_str)?;
            let name = f.get("name").and_then(Value::as_str)?;
            (set.contains_key(id) && seen.insert(id)).then(|| (id.to_owned(), capped(name)))
        })
        .take(MAX_MISSING_FIELDS)
        .collect()
}

/// PD-49: `required && !hasDefaultValue` fields no param sets, in createmeta order over the pages
/// (a field id seen on an earlier page is not counted again), and how many there are in all. The
/// kept list stops at [`MAX_MISSING_FIELDS`]. `None`: a page is not a createmeta answer.
fn missing_fields(params: &Value, pages: &[Value]) -> Option<(Vec<MissingField>, u64)> {
    let mut seen = std::collections::HashSet::new();
    let (mut out, mut total) = (Vec::new(), 0u64);
    for page in pages {
        for field in page.get("values")?.as_array()? {
            let Some(id) = field.get("fieldId").and_then(Value::as_str) else {
                continue;
            };
            let flag = |k: &str| field.get(k) == Some(&Value::Bool(true));
            if !seen.insert(id) || !flag("required") || flag("hasDefaultValue") {
                continue;
            }
            if set_by_params(params, id) {
                continue;
            }
            total = total.saturating_add(1);
            if out.len() == MAX_MISSING_FIELDS {
                continue;
            }
            out.push(missing_field(id, field));
        }
    }
    Some((out, total))
}

/// One required field as createmeta (or a transition screen) lists it: its names, `schema` and
/// the first [`MAX_ALLOWED_VALUES`] of its `allowedValues`.
fn missing_field(id: &str, field: &Value) -> MissingField {
    let schema = |k: &str| {
        field
            .get("schema")
            .and_then(|s| s.get(k))
            .and_then(Value::as_str)
            .map(capped)
    };
    let many = schema("type").as_deref() == Some("array");
    let listed = field
        .get("allowedValues")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let allowed_values = listed
        .iter()
        .filter_map(|v| allowed_value(v, many))
        .take(MAX_ALLOWED_VALUES)
        .collect();
    MissingField {
        id: capped(id),
        name: field
            .get("name")
            .and_then(Value::as_str)
            .map_or_else(|| capped(id), capped),
        schema_type: schema("type").unwrap_or_default(),
        schema_items: schema("items"),
        allowed_values,
        allowed_total: u64::try_from(listed.len()).unwrap_or(u64::MAX),
    }
}

/// One createmeta `allowedValues` entry (T12 review I1): its label (`value`, else `name`, else
/// `id`) and the value Jira takes for it: `{"id"}` when there is one (exact), else `{"value"}`
/// with the raw value, in an array when the field is an `array` (`many`). `None`: no label.
fn allowed_value(v: &Value, many: bool) -> Option<AllowedValue> {
    let text = |k: &str| v.get(k).and_then(Value::as_str);
    let id = text("id").filter(|i| !i.is_empty());
    let label = text("value").or_else(|| text("name")).or(id)?;
    let one = match (id, text("value")) {
        (Some(id), _) => Some(json!({"id": id})),
        (None, Some(value)) => Some(json!({"value": value})),
        (None, None) => None,
    };
    Some(AllowedValue {
        label: capped(label),
        wire: one.map(|w| if many { Value::Array(vec![w]) } else { w }),
    })
}

/// PD-49 (plan text): `"<name> (<fieldId>, <schema.type>)"` joined by `", "` in createmeta order,
/// display-escaped, at most [`MAX_CANDIDATES`] then `"… and N more"`.
fn missing_list(fields: &[MissingField], total: u64) -> String {
    let shown = |s: &str| crate::metadata::one_line(escape_for_display(s));
    let mut list: Vec<String> = fields
        .iter()
        .take(MAX_CANDIDATES)
        .map(|f| {
            format!(
                "{} ({}, {})",
                shown(&f.name),
                shown(&f.id),
                shown(&f.schema_type)
            )
        })
        .collect();
    let listed = u64::try_from(list.len()).unwrap_or(u64::MAX);
    if total > listed {
        list.push(format!("… and {} more", total - listed));
    }
    list.join(", ")
}

fn create_judge(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichVerdict {
    let Some(projects) = answers.first() else {
        return EnrichVerdict::unusable();
    };
    let project = match resolve_project(ctx, projects) {
        Ok(p) => p,
        Err(v) => return *v,
    };
    let Some(types) = answers.get(1) else {
        return EnrichVerdict::unusable();
    };
    let issuetype = match resolve_issuetype(ctx, types) {
        Ok(t) => t,
        Err(v) => return *v,
    };
    let Some(pages) = answers.get(2..).filter(|pages| !pages.is_empty()) else {
        return EnrichVerdict::unusable();
    };
    let Some((missing, total)) = missing_fields(ctx.params, pages) else {
        return EnrichVerdict::unusable();
    };
    let mut resolved = Map::new();
    resolved.insert("project_key".to_owned(), Value::from(project.key.clone()));
    resolved.insert("issuetype".to_owned(), Value::from(issuetype.id.clone()));
    let baseline = json!({"project_key": project.key, "issuetype_id": issuetype.id});
    let mut verdict = EnrichVerdict::preview(baseline, resolved);
    if total > 0 {
        verdict.warnings.push(Warning::new(
            WarningId::MissingRequiredFields,
            warning::missing_required_fields(&missing_list(&missing, total)),
        ));
    }
    // PD-49 is advisory (§5.4 step 2: Jira decides): a cut field list is an Info, not a block.
    if let Some((read, all)) = field_list_cut(pages) {
        verdict.warnings.push(Warning::new(
            WarningId::RequiredFieldListIncomplete,
            warning::required_field_list_incomplete(read, all),
        ));
    }
    verdict.missing_fields = missing;
    verdict.missing_fields_total = total;
    verdict.summary = Some(WriteSummaryFacts {
        project_key: Some(project.key),
        project_name: project.name.as_deref().map(capped),
        issue_type_id: Some(issuetype.id),
        issue_type: issuetype.name.as_deref().map(capped),
        field_names: set_field_names(ctx.params, pages),
        ..WriteSummaryFacts::default()
    });
    verdict
}

/// `POST /rest/api/2/issue` `{"fields": {project: {key}, issuetype: {id}, summary,
/// description?, ..}}`; the project is the key enrichment resolved (PD-48).
pub fn issue_create_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    // Path checks first, so the validation dry call reports a bad placeholder (exit 2) even
    // before enrichment: the write URL, and the agent's project as a path segment (M3): a value
    // that cannot stand in a path (`..`) cannot name the project whose key goes there.
    resolve_url(ctx.base, ctx.spec.endpoint.path, ctx.params, &[])?;
    resolve_url(ctx.base, CREATEMETA_ISSUETYPES_PATH, ctx.params, &[])?;
    // PD-43: converted and hard-checked before the enrichment wait, so the dry call rejects it.
    let description = jira_body::wiki_text(ctx, "description")?;
    let project_key = resolved_id(ctx, "project_key")?;
    let issuetype = resolved_id(ctx, "issuetype")?;
    let mut fields = ctx
        .params
        .get("fields")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    fields.insert("project".to_owned(), json!({"key": project_key}));
    fields.insert("issuetype".to_owned(), json!({"id": issuetype}));
    fields.insert(
        "summary".to_owned(),
        Value::from(str_param(ctx.params, "summary")),
    );
    if let Some(description) = description {
        fields.insert("description".to_owned(), Value::from(description));
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

/// One round (Δ3, wrapped mechanically); none when there is nothing to read.
fn edit_plan(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichStep {
    let calls = issue_fields_call(ctx.params, &edited_field_ids(ctx.params))
        .map(|c| vec![(EnrichPurpose::Enrich, c)])
        .unwrap_or_default();
    single_round(calls, answers)
}

/// PD-50 (§5.4 step 2 "compared like the step 5 rule"): two field values are equal when their
/// JCS bytes are. A value JCS refuses (an integer beyond ±(2^53−1)) is compared member by
/// member with the same rule, and such an integer equals exactly the same integer only (T13
/// review M-4: a current value holding one must not make the edit stale forever; nothing is
/// rounded, so a neighbour or a float of it differs). The caller passes `null` for an absent
/// field.
pub(crate) fn field_values_equal(a: &Value, b: &Value) -> bool {
    match (to_jcs_vec(a), to_jcs_vec(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => wide_equal(a, b),
    }
}

/// [`field_values_equal`] without the whole-value JCS: objects by key set and members, arrays
/// by position, leaves by their JCS bytes, an over-range integer by its exact value.
fn wide_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| wide_equal(v, w)))
        }
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(v, w)| wide_equal(v, w))
        }
        (Value::Number(x), Value::Number(y)) => match (to_jcs_vec(a), to_jcs_vec(b)) {
            (Ok(a), Ok(b)) => a == b,
            // Integers only: serde keeps them exact as i64/u64.
            _ => match (x.as_i64(), y.as_i64(), x.as_u64(), y.as_u64()) {
                (Some(x), Some(y), _, _) => x == y,
                (_, _, Some(x), Some(y)) => x == y,
                _ => false,
            },
        },
        _ => a == b,
    }
}

/// 2-space pretty JSON (PD-51's raw form of a field value); compact JSON cannot fail either, so
/// the fallback is never taken in practice.
pub(crate) fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

/// `s` display-escaped and cut to at most `budget` bytes of escaped text, never inside an
/// escape or an emoji sequence ([`cut_boundary`], ZWJ review M-7): the escaped text kept and how
/// many bytes of `s` it shows (T13 review M-6: a budget counts what is shown, and an escape
/// widens a char up to 12 bytes).
pub(crate) fn escaped_prefix(s: &str, budget: usize) -> (String, usize) {
    let escaped = escape_for_display(s);
    if escaped.len() <= budget {
        return (escaped, s.len());
    }
    let end = cut_boundary(&escaped, budget);
    // `escape_for_display` writes each char either as itself or as one `⟨U+XXXX⟩`, and every
    // `⟨` it writes starts an escape (a literal `⟨` is escaped too); `end` is between two of
    // those.
    let (mut shown, mut taken) = (0usize, 0usize);
    let mut rest = escaped.as_str();
    for c in s.chars() {
        let width = if rest.starts_with('⟨') {
            rest.find('⟩').map_or(rest.len(), |i| i + '⟩'.len_utf8())
        } else {
            rest.chars().next().map_or(0, char::len_utf8)
        };
        if width == 0 || shown + width > end {
            break;
        }
        shown += width;
        taken += c.len_utf8();
        rest = rest.get(width..).unwrap_or("");
    }
    (escaped.get(..shown).unwrap_or("").to_owned(), taken)
}

/// Escaped bytes of conflict-card line text kept per kind (context, `- read`, `+ current`);
/// what is left of [`DIFF_TEXT_CAP_BYTES`] carries the headings and marks (T13 review M-5: a
/// long `- read` line cannot push the `+ current` one out).
const CONFLICT_KIND_BYTES: usize = (DIFF_TEXT_CAP_BYTES - 1024) / 3;

/// The conflict card's diff of one field (§6.3 Conflict): the raw diff (PD-51's pretty JSON)
/// of what the agent read against the current value, under a `<id> (- read, + current)` line;
/// one display-escaped text line per diff line, `-`/`+`/space marked. Each kind of line draws
/// on its own budget in `left` (escaped bytes, across fields); the line a budget cuts ends in
/// `…` and later lines of that kind are left out (`None`), each field saying so once with a
/// lone `…` line of that kind. A `line_diff` cut at its caps (a middle over `DIFF_MAX_LINES`
/// lines or 4 MiB) is far over these budgets, so its `…` marks it as cut.
fn conflict_diff(id: &str, read: &Value, current: &Value, left: &mut [Option<usize>; 3]) -> String {
    let mut out = format!("{} (- read, + current)\n", escape_for_display(id));
    let mut marked = [false; 3];
    for line in line_diff(&pretty(read), &pretty(current)).lines {
        let (mark, slot) = match line.op {
            DiffOp::Del => ("- ", 1),
            DiffOp::Add => ("+ ", 2),
            DiffOp::Same | DiffOp::Field => ("  ", 0),
        };
        let (Some(budget), Some(marked)) = (left.get_mut(slot), marked.get_mut(slot)) else {
            continue;
        };
        let Some(bytes) = budget else {
            if !*marked {
                *marked = true;
                out.push_str(mark);
                out.push_str("…\n");
            }
            continue;
        };
        let text = line.text.strip_suffix('\n').unwrap_or(&line.text);
        let (kept, taken) = escaped_prefix(text, *bytes);
        out.push_str(mark);
        out.push_str(&kept);
        if taken < text.len() {
            out.push('…');
            *budget = None;
            *marked = true;
        } else {
            *bytes -= kept.len();
        }
        out.push('\n');
    }
    out
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
    let mut left = [Some(CONFLICT_KIND_BYTES); 3];
    for (id, expected) in ctx
        .params
        .get("expected")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let now = value_of(id);
        if !field_values_equal(&now, expected) {
            changed.push(id.clone());
            // The cap below bounds what is kept; this bounds the work: once the text is past
            // it, later fields are only named in the summary.
            if diff.len() <= DIFF_TEXT_CAP_BYTES {
                diff.push_str(&conflict_diff(id, expected, &now, &mut left));
            }
        }
    }
    let mut verdict = EnrichVerdict::preview(Value::Object(baseline), Map::new());
    if !changed.is_empty() {
        // Same shape as the Confluence text (`warning::conflict`): "conflict: <what> changed …".
        let summary = escape_for_display(&format!(
            "conflict: fields changed since the agent read it: {}",
            changed.join(", ")
        ));
        verdict.hold = Hold::Conflict;
        verdict
            .warnings
            .push(Warning::new(WarningId::Conflict, summary.clone()));
        verdict.conflict = Some(summary);
        verdict.diff_text = cap_diff_text(&diff);
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

/// `POST /rest/api/2/issue/{key}/comment` `{"body", "visibility"?}`; `body` is wiki markup,
/// converted from Markdown unless `body_format` is `wiki` (PD-43).
pub fn comment_add_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    let text = jira_body::wiki_text(ctx, "body")?.unwrap_or_default();
    let mut body = Map::new();
    body.insert("body".to_owned(), Value::from(text));
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

/// One round (Δ3, wrapped mechanically): the transitions, then the current status.
fn transition_plan(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichStep {
    let [transitions, status] = transition_calls(ctx.params);
    let calls = vec![
        (EnrichPurpose::Resolve, transitions),
        (EnrichPurpose::Enrich, status),
    ];
    single_round(calls, answers)
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
        Resolution::One(id) => {
            let transition = transitions
                .iter()
                .find(|t| t.get("id").and_then(Value::as_str) == Some(id.as_str()));
            // M5 final review M-2 (L102): the status the transition leads to is baselined too, so
            // an admin retarget of the same transition id between review and approval is stale.
            let to_status_id = transition
                .and_then(|t| t.get("to"))
                .and_then(|to| to.get("id"))
                .and_then(Value::as_str);
            let mut verdict = EnrichVerdict::preview(
                json!({"status_id": status_id, "transition_id": id, "to_status_id": to_status_id}),
                resolved("transition", &id),
            );
            if let Some(transition) = transition {
                transition_summary(&mut verdict, ctx.params, transition, responses);
            }
            verdict
        }
        Resolution::Unresolved(n, candidates) => unresolved("transition", wanted, n, candidates),
    }
}

/// Whether the params set the transition screen's field `id` (a `fields` key; the `comment` param
/// sets `comment`). A `null` or an empty string sets nothing (as for createmeta, PD-49).
fn transition_field_set(params: &Value, id: &str) -> bool {
    let set = |v: Option<&Value>| v.is_some_and(|v| !v.is_null() && v.as_str() != Some(""));
    (id == "comment" && set(params.get("comment")))
        || set(params
            .get("fields")
            .and_then(Value::as_object)
            .and_then(|m| m.get(id)))
}

/// T14: the facts of the transition card (the status the issue is in, the one the transition
/// leads to, the screen's names of the fields the params set) and the transition screen's
/// required fields no param sets: a Caution, never a block (PD-49 applied to the screen the
/// enrichment GET already expanded), with the pre-added inputs and the deny hint that come with
/// `missing_fields`. (T14 review M9: every edit of `comment` or `fields` re-runs this enrichment,
/// two GETs, and re-baselines the status and transition; the card shows the new from/to and needs
/// a fresh Approve, and an unreachable Jira turns the edit into an enrichment error, the I-18
/// analogue.)
fn transition_summary(
    verdict: &mut EnrichVerdict,
    params: &Value,
    transition: &Value,
    responses: &[Value],
) {
    let screen = transition.get("fields").and_then(Value::as_object);
    let name_of = |v: Option<&Value>| {
        v.and_then(|v| v.get("name"))
            .and_then(Value::as_str)
            .map(capped)
    };
    let (mut missing, mut total) = (Vec::new(), 0u64);
    for (id, field) in screen.into_iter().flatten() {
        let flag = |k: &str| field.get(k) == Some(&Value::Bool(true));
        if !flag("required") || flag("hasDefaultValue") || transition_field_set(params, id) {
            continue;
        }
        total = total.saturating_add(1);
        if missing.len() < MAX_MISSING_FIELDS {
            missing.push(missing_field(id, field));
        }
    }
    if total > 0 {
        verdict.warnings.push(Warning::new(
            WarningId::MissingRequiredFields,
            warning::missing_required_fields(&missing_list(&missing, total)),
        ));
    }
    verdict.missing_fields = missing;
    verdict.missing_fields_total = total;
    let field_names = params
        .get("fields")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(Map::keys)
        .filter_map(|id| Some((id.clone(), name_of(screen?.get(id.as_str()))?)))
        .take(MAX_MISSING_FIELDS)
        .collect();
    verdict.summary = Some(WriteSummaryFacts {
        from_status: name_of(
            responses
                .get(1)
                .and_then(|r| r.get("fields")?.get("status")),
        ),
        to_status: name_of(transition.get("to")),
        transition_name: name_of(Some(transition)),
        field_names,
        ..WriteSummaryFacts::default()
    });
}

/// `POST /rest/api/2/issue/{key}/transitions`
/// `{"transition": {"id"}, "fields"?, "update"?: {"comment": [{"add": {"body"}}]}}`.
pub fn issue_transition_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    resolve_url(ctx.base, ctx.spec.endpoint.path, ctx.params, &[])?;
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
