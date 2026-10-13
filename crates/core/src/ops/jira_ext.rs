//! The Jira writes M5 completes beyond the M3 four (PD-09): `jira.issue.assign` (T15, PD-52), with
//! the assignable-user resolution under the §7.2 username comparison and the current assignee as
//! the stale-check baseline; `jira.issuelink.create` (T16, PD-53), with the link-type resolution.

use atlas_duck_atlassian::{GetCall, UsernameMatcher};
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use serde_json::{Map, Value, json};

use super::jira::{ISSUE_PATH, MAX_CANDIDATES, capped, unresolved};
use super::{
    EnrichCtx, EnrichPurpose, EnrichRule, EnrichStep, EnrichVerdict, ExecCtx, ExecError, ExecPlan,
    JiraLinkType, JiraUser, WriteSummaryFacts, get_call, json_request, resolve_url, single_round,
    str_param,
};
use crate::lifecycle::model::Hold;
use crate::metadata::one_line;
use crate::validate::invalid;

// ---- jira.issue.assign -------------------------------------------------------------------------

const ASSIGNABLE_PATH: &str = "/rest/api/2/user/assignable/search";

/// PD-52: the assignable-user search asks for at most this many users. An answer this long may
/// be cut (T15 review M1): only the username rule resolves on it.
const ASSIGNABLE_MAX_RESULTS: usize = 50;

/// Jira's "automatic assignee" (`-1`, T15 review M2): never a user to search for, resolve or
/// send.
fn is_automatic(name: &str) -> bool {
    name.trim() == "-1"
}

/// A value that names nobody (T15 review M4): blank (the schema has no `minLength`) or `-1`.
/// Unresolved without a search: an empty `username=` may list every assignable user.
fn names_nobody(name: &str) -> bool {
    name.trim().is_empty() || is_automatic(name)
}

/// PD-52: stage 1 resolves the assignee over the assignable-user search (`resolve`; skipped for
/// `null`, an unassign), stage 2 reads the current assignee (`enrich`), the stale-check baseline.
/// An unresolved assignee ends the plan after stage 1 (`Judge`, no further GET).
pub static ISSUE_ASSIGN_ENRICH: EnrichRule = EnrichRule {
    plan: assign_plan,
    judge: assign_judge,
};

/// The agent's assignee: `Ok(None)` is `null` (unassign), `Ok(Some(name))` a user to resolve.
/// Anything else (the schema allows neither) is `Err`, and nothing is resolved or sent.
fn wanted(params: &Value) -> Result<Option<&str>, ()> {
    match params.get("assignee") {
        Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        _ => Err(()),
    }
}

/// `GET /rest/api/2/user/assignable/search?username=<v>&issueKey=<key>&maxResults=50`: the
/// agent's value and the agent's (pattern-validated) issue key, query-encoded; no server value.
fn search_call(params: &Value, name: &str) -> GetCall {
    let key = params.get("key").and_then(Value::as_str).unwrap_or("");
    let max = ASSIGNABLE_MAX_RESULTS.to_string();
    get_call(
        ASSIGNABLE_PATH,
        params,
        &[
            ("username", name),
            ("issueKey", key),
            ("maxResults", max.as_str()),
        ],
    )
}

/// `GET /rest/api/2/issue/{key}?fields=assignee`: enrichment and the stale check read the same.
pub(crate) fn assignee_call(params: &Value) -> GetCall {
    get_call(ISSUE_PATH, params, &[("fields", "assignee")])
}

/// The current assignee of an issue answer: `Some(None)` when unassigned, `None` when the answer
/// does not say (no `fields.assignee`, or an assignee without a string `key`): fail closed, a
/// missing key must never pass for "unassigned".
pub(crate) fn current_assignee(issue: &Value) -> Option<Option<JiraUser>> {
    let assignee = issue.get("fields")?.as_object()?.get("assignee")?;
    if assignee.is_null() {
        return Some(None);
    }
    let text = |k: &str| assignee.get(k).and_then(Value::as_str);
    let key = text("key").filter(|k| !k.is_empty())?;
    Some(Some(JiraUser {
        name: text("name").map(str::to_owned),
        key: Some(key.to_owned()),
        display_name: text("displayName").map(capped),
    }))
}

/// PD-52: exactly one user whose `name` matches the value under the §7.2 username comparison
/// (`atlassian::username_matches`, as a [`UsernameMatcher`]), else whose `key` equals it, else whose `displayName` equals
/// it case-insensitively (as [`super::jira::resolve`]). The first rule with any hit decides: one
/// hit resolves, more are ambiguous (their usernames are the candidates) and never a pick; no hit
/// at all lists the first [`MAX_CANDIDATES`] usernames of the answer. Each rule is one pass over the answer. A value that names nobody is unresolved
/// without an answer ([`names_nobody`]); a user named `-1` never resolves and is never a
/// candidate; on a full page only the username rule resolves (the key or display-name hits are
/// the candidates). A resolved user without a `name` cannot be sent (fail closed), nor can a
/// missing or non-array answer.
fn resolve_user(wanted: &str, answer: Option<&Value>) -> Result<JiraUser, Box<EnrichVerdict>> {
    if names_nobody(wanted) {
        return Err(Box::new(unresolved("assignee", wanted, 0, Vec::new())));
    }
    let Some(answer) = answer.and_then(Value::as_array) else {
        return Err(Box::new(EnrichVerdict::unusable()));
    };
    fn text<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
        v.get(k).and_then(Value::as_str)
    }
    // Counted before the `-1` users leave: the page the server sent.
    let full_page = answer.len() >= ASSIGNABLE_MAX_RESULTS;
    let users: Vec<&Value> = answer
        .iter()
        .filter(|v| !text(v, "name").is_some_and(is_automatic))
        .collect();
    // Each side canonicalized once: linear in the answer, whatever the value's length.
    let matcher = UsernameMatcher::new(wanted);
    let folded = wanted.to_lowercase();
    let rules: [&dyn Fn(&Value) -> bool; 3] = [
        &|v| text(v, "name").is_some_and(|n| matcher.matches(n)),
        &|v| text(v, "key") == Some(wanted),
        &|v| text(v, "displayName").is_some_and(|d| d.to_lowercase() == folded),
    ];
    let names = |items: &[&Value]| -> Vec<String> {
        items
            .iter()
            .filter_map(|v| text(v, "name"))
            .take(MAX_CANDIDATES)
            .map(capped)
            .collect()
    };
    for (n, rule) in rules.iter().enumerate() {
        let hits: Vec<&Value> = users.iter().copied().filter(|v| rule(v)).collect();
        match hits.as_slice() {
            [] => continue,
            // The user named, or a namesake, may be past the page: the hit is a candidate.
            [_] if n > 0 && full_page => {
                return Err(Box::new(unresolved("assignee", wanted, 1, names(&hits))));
            }
            [one] => {
                let Some(name) = text(one, "name").filter(|n| !n.is_empty()) else {
                    return Err(Box::new(EnrichVerdict::unusable()));
                };
                return Ok(JiraUser {
                    name: Some(name.to_owned()),
                    key: text(one, "key").map(str::to_owned),
                    display_name: text(one, "displayName").map(capped),
                });
            }
            _ => {
                let n = u64::try_from(hits.len()).unwrap_or(u64::MAX);
                return Err(Box::new(unresolved("assignee", wanted, n, names(&hits))));
            }
        }
    }
    Err(Box::new(unresolved("assignee", wanted, 0, names(&users))))
}

/// Δ3: `null` → `[issue]`; a name → `[users]`, then `[.., issue]` once it resolved; a value that
/// names nobody → no GET.
fn assign_plan(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichStep {
    let fetch = |purpose, call| EnrichStep::Fetch(vec![(purpose, call)]);
    match (wanted(ctx.params), answers) {
        (Ok(None), []) => fetch(EnrichPurpose::Enrich, assignee_call(ctx.params)),
        (Ok(Some(name)), []) if !names_nobody(name) => {
            fetch(EnrichPurpose::Resolve, search_call(ctx.params, name))
        }
        (Ok(Some(name)), [users]) if resolve_user(name, Some(users)).is_ok() => {
            fetch(EnrichPurpose::Enrich, assignee_call(ctx.params))
        }
        _ => EnrichStep::Judge,
    }
}

fn assign_judge(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichVerdict {
    let (to, issue) = match wanted(ctx.params) {
        Err(()) => return EnrichVerdict::unusable(),
        Ok(None) => (None, answers.first()),
        Ok(Some(name)) => match resolve_user(name, answers.first()) {
            Ok(user) => (Some(user), answers.get(1)),
            Err(v) => return *v,
        },
    };
    let Some(from) = issue.and_then(current_assignee) else {
        return EnrichVerdict::unusable();
    };
    // The raw key and name (never cut): the stale rule compares the key exactly.
    let baseline = json!({
        "assignee_key": from.as_ref().and_then(|u| u.key.clone()),
        "assignee_name": from.as_ref().and_then(|u| u.name.clone()),
    });
    let mut resolved = Map::new();
    resolved.insert(
        "assignee".to_owned(),
        to.as_ref()
            .and_then(|u| u.name.clone())
            .map_or(Value::Null, Value::from),
    );
    let mut verdict = EnrichVerdict::preview(baseline, resolved);
    verdict.summary = Some(WriteSummaryFacts {
        assignee_from: from,
        assignee_to: to,
        ..WriteSummaryFacts::default()
    });
    verdict
}

/// `PUT /rest/api/2/issue/{key}/assignee` `{"name": <resolved name>}`, or `{"name": null}` to
/// unassign (PD-52, V05 pending). Only a `Preview` verdict for the same kind of assignment renders
/// a request: the name is the one enrichment resolved, never the agent's spelling of it, and
/// never `-1` (Jira's automatic assignee).
pub fn issue_assign_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    resolve_url(ctx.base, ctx.spec.endpoint.path, ctx.params, &[])?;
    let wanted = wanted(ctx.params).map_err(|()| {
        ExecError::Invalid(invalid("assignee", "must be a username or null", None))
    })?;
    let resolved = ctx
        .enrichment
        .filter(|v| v.hold == Hold::Preview)
        .and_then(|v| v.resolved.get("assignee"));
    let name = match (wanted, resolved) {
        (None, Some(Value::Null)) => Value::Null,
        (Some(_), Some(Value::String(name))) if !name.is_empty() && !is_automatic(name) => {
            Value::from(name.clone())
        }
        _ => return Err(ExecError::EnrichmentRequired),
    };
    json_request(ctx, &json!({ "name": name }))
}

// ---- jira.issuelink.create ---------------------------------------------------------------------

const LINK_TYPES_PATH: &str = "/rest/api/2/issueLinkType";

/// PD-53: one GET, the link types (`resolve`); a `type` that names none ends the plan without it.
pub static ISSUELINK_CREATE_ENRICH: EnrichRule = EnrichRule {
    plan: link_plan,
    judge: link_judge,
};

/// A `type` that names no link type: blank (the schema's `minLength` lets whitespace through).
fn names_no_type(wanted: &str) -> bool {
    wanted.trim().is_empty()
}

/// `GET /rest/api/2/issueLinkType`: a fixed path, nothing of the params in the URL.
fn link_plan(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichStep {
    if names_no_type(str_param(ctx.params, "type")) {
        return EnrichStep::Judge;
    }
    let call = get_call(LINK_TYPES_PATH, ctx.params, &[]);
    single_round(vec![(EnrichPurpose::Resolve, call)], answers)
}

/// PD-53, tightened (T16): a type matches the value by its `id` (exactly) or its `name`,
/// `outward` or `inward` phrase (case-insensitively, as [`super::jira::resolve`]). Exactly one
/// type matched in any of these ways resolves; several types are ambiguous even when each matched
/// by another rule (a name of one that is a phrase of another), and their names are the
/// candidates; no match lists the first [`MAX_CANDIDATES`] type names. The request names the type
/// by `name`, so a resolved name another type shares (any case) is ambiguous too. A blank value
/// names no type (no answer needed); an answer that is not the documented object, or a resolved
/// type without an id, a name or both phrases, fails closed. One pass over the answer per check.
/// With the type, whether the value named it only by its inward phrase, of a type whose phrases
/// differ (T16 review I1): the link then reads the other way round from the agent's wording.
fn resolve_link_type(
    wanted: &str,
    answer: Option<&Value>,
) -> Result<(JiraLinkType, bool), Box<EnrichVerdict>> {
    if names_no_type(wanted) {
        return Err(Box::new(unresolved("type", wanted, 0, Vec::new())));
    }
    let Some(types) = answer
        .and_then(|a| a.get("issueLinkTypes"))
        .and_then(Value::as_array)
    else {
        return Err(Box::new(EnrichVerdict::unusable()));
    };
    fn text<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
        v.get(k).and_then(Value::as_str)
    }
    fn names<'a>(items: impl IntoIterator<Item = &'a Value>) -> Vec<String> {
        items
            .into_iter()
            .filter_map(|v| text(v, "name"))
            .take(MAX_CANDIDATES)
            .map(capped)
            .collect()
    }
    fn count(items: &[&Value]) -> u64 {
        u64::try_from(items.len()).unwrap_or(u64::MAX)
    }
    let folded = wanted.to_lowercase();
    let same = |s: Option<&str>| s.is_some_and(|s| s.to_lowercase() == folded);
    let hits: Vec<&Value> = types
        .iter()
        .filter(|t| {
            text(t, "id") == Some(wanted)
                || same(text(t, "name"))
                || same(text(t, "outward"))
                || same(text(t, "inward"))
        })
        .collect();
    let one = match hits.as_slice() {
        [] => return Err(Box::new(unresolved("type", wanted, 0, names(types)))),
        [one] => *one,
        _ => {
            let n = count(&hits);
            return Err(Box::new(unresolved("type", wanted, n, names(hits))));
        }
    };
    let filled = |k: &str| text(one, k).filter(|s| !s.trim().is_empty());
    let (Some(id), Some(name), Some(inward), Some(outward)) = (
        filled("id"),
        filled("name"),
        filled("inward"),
        filled("outward"),
    ) else {
        return Err(Box::new(EnrichVerdict::unusable()));
    };
    let folded_name = name.to_lowercase();
    let namesakes: Vec<&Value> = types
        .iter()
        .filter(|t| text(t, "name").is_some_and(|n| n.to_lowercase() == folded_name))
        .collect();
    if namesakes.len() > 1 {
        let n = count(&namesakes);
        return Err(Box::new(unresolved("type", wanted, n, names(namesakes))));
    }
    let by_inward_only = same(Some(inward))
        && text(one, "id") != Some(wanted)
        && !same(Some(name))
        && !same(Some(outward))
        && inward.to_lowercase() != outward.to_lowercase();
    let link_type = JiraLinkType {
        id: capped(id),
        name: name.to_owned(),
        inward: capped(inward),
        outward: capped(outward),
    };
    Ok((link_type, by_inward_only))
}

/// Server text (already [`capped`]) in a Caution: display-escaped, on one line.
fn caution_text(cut: &str) -> String {
    one_line(escape_for_display(cut))
}

fn link_judge(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichVerdict {
    match resolve_link_type(str_param(ctx.params, "type"), answers.first()) {
        Err(verdict) => *verdict,
        Ok((link_type, by_inward_only)) => {
            let mut resolved = Map::new();
            resolved.insert("type".to_owned(), Value::from(link_type.name.clone()));
            // No stale rule (§5.4 step 5: "none"), so no baseline.
            let mut verdict = EnrichVerdict::preview(Value::Null, resolved);
            if by_inward_only {
                verdict.warnings.push(Warning::new(
                    WarningId::LinkTypeInwardPhrase,
                    warning::link_type_inward_phrase(
                        &caution_text(&link_type.inward),
                        &caution_text(&link_type.outward),
                    ),
                ));
            }
            verdict.summary = Some(WriteSummaryFacts {
                link_type: Some(link_type),
                ..WriteSummaryFacts::default()
            });
            verdict
        }
    }
}

/// An issue key as Jira tells issues apart (T16 review M4): the project key in upper case and the
/// number without its leading zeros (`abc-01` is `ABC-1`); a value of another shape as it is.
fn issue_identity(key: &str) -> String {
    match key.rsplit_once('-') {
        Some((project, number))
            if !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()) =>
        {
            let number = number.trim_start_matches('0');
            let number = if number.is_empty() { "0" } else { number };
            format!("{}-{number}", project.to_uppercase())
        }
        _ => key.to_owned(),
    }
}

/// Whether two keys name one issue: equal, or equal as [`issue_identity`] reads them. Another
/// key of a moved issue (an old project key) is not seen; Jira decides those.
fn same_issue(a: &str, b: &str) -> bool {
    a == b || issue_identity(a) == issue_identity(b)
}

/// `POST /rest/api/2/issueLink` `{"type": {"name": <resolved name>}, "inwardIssue": {"key":
/// inward}, "outwardIssue": {"key": outward}, "comment"?: {"body": comment}}` (PD-53): the params
/// fill the fields of the same names; the comment is wiki markup, sent verbatim (PD-42). Static
/// checks first, so the validation dry call (and an edit) refuses them (exit 2): a blank type and
/// a blank comment (`minLength` lets whitespace through, T16 review M5: refused alike, as the
/// schema refuses an empty one), and a link of an issue to itself ([`same_issue`]). Only a
/// `Preview` verdict renders a request, with the type name enrichment resolved.
pub fn issuelink_create_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    if names_no_type(str_param(ctx.params, "type")) {
        return Err(ExecError::Invalid(invalid(
            "type",
            "must not be blank",
            None,
        )));
    }
    let inward = str_param(ctx.params, "inward");
    let outward = str_param(ctx.params, "outward");
    if same_issue(inward, outward) {
        return Err(ExecError::Invalid(invalid(
            "outward",
            "must name another issue than inward",
            None,
        )));
    }
    let comment = match ctx.params.get("comment") {
        None | Some(Value::Null) => None,
        Some(Value::String(c)) if !c.trim().is_empty() => Some(c.as_str()),
        Some(_) => {
            return Err(ExecError::Invalid(invalid(
                "comment",
                "must not be blank",
                None,
            )));
        }
    };
    let name = ctx
        .enrichment
        .filter(|v| v.hold == Hold::Preview)
        .and_then(|v| v.resolved.get("type"))
        .and_then(Value::as_str)
        .filter(|n| !n.trim().is_empty())
        .ok_or(ExecError::EnrichmentRequired)?;
    let mut body = Map::new();
    body.insert("type".to_owned(), json!({ "name": name }));
    body.insert("inwardIssue".to_owned(), json!({ "key": inward }));
    body.insert("outwardIssue".to_owned(), json!({ "key": outward }));
    if let Some(comment) = comment {
        body.insert("comment".to_owned(), json!({ "body": comment }));
    }
    json_request(ctx, &Value::Object(body))
}
