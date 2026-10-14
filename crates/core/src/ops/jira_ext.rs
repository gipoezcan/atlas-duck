//! The Jira writes M5 completes beyond the M3 four (PD-09): `jira.issue.assign` (T15, PD-52), with
//! the assignable-user resolution under the §7.2 username comparison and the current assignee as
//! the stale-check baseline; `jira.issuelink.create` (T16, PD-53), with the link-type resolution;
//! `jira.worklog.add` (T17, PD-55), whose time and start are checked strictly (no enrichment).

use atlas_duck_atlassian::{GetCall, UsernameMatcher};
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use chrono::{NaiveDate, NaiveDateTime, NaiveTime, TimeDelta};
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

// ---- jira.worklog.add --------------------------------------------------------------------------

/// The most one worklog books (PD-55, T17): four working weeks at Jira's default time tracking
/// (1d = 8h, 1w = 5d), in minutes. A larger value is a typo or a unit mix-up, not a worklog.
const MAX_WORKLOG_MINUTES: u32 = 4 * 5 * 8 * 60;

/// A `time_spent` amount has at most this many digits (`9999`).
const MAX_AMOUNT_DIGITS: usize = 4;

/// Jira's default working time (the instance's time tracking settings can change it): hours in a
/// day and days in a week.
const DEFAULT_HOURS_PER_DAY: u32 = 8;
const DEFAULT_DAYS_PER_WEEK: u32 = 5;

const NOT_A_STRING: &str = "must be a string";

const TIME_SHAPE: &str = "must be amounts of w, d, h or m, such as '1h 30m'";

/// A worklog's `timeSpent` as Jira reads it: each of weeks, days, hours and minutes at most once,
/// the largest first (`1w 2d 3h 4m`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimeSpent {
    weeks: u32,
    days: u32,
    hours: u32,
    minutes: u32,
}

impl TimeSpent {
    /// The minutes at Jira's default working time (1d = 8h, 1w = 5d).
    fn default_minutes(self) -> u32 {
        let days = self.weeks * DEFAULT_DAYS_PER_WEEK + self.days;
        (days * DEFAULT_HOURS_PER_DAY + self.hours) * 60 + self.minutes
    }
}

/// Parses a worklog's `time_spent`, strictly: single-space separated `<1-4 digits><w|d|h|m>`
/// tokens, each unit once and the largest first, more than zero and at most
/// [`MAX_WORKLOG_MINUTES`]. Anything Jira could read another way (`2h30m`, `1.5h`, `90s`, `2H`,
/// two spaces, non-ASCII digits) is refused, so what is sent has one reading.
pub(crate) fn parse_time_spent(raw: &str) -> Result<TimeSpent, &'static str> {
    let mut amounts = [0u32; 4];
    let mut last: Option<usize> = None;
    for token in raw.split(' ') {
        let Some((digits, unit)) = token.split_at_checked(token.len().saturating_sub(1)) else {
            return Err(TIME_SHAPE);
        };
        let rank = match unit {
            "w" => 0,
            "d" => 1,
            "h" => 2,
            "m" => 3,
            _ => return Err(TIME_SHAPE),
        };
        if digits.is_empty()
            || digits.len() > MAX_AMOUNT_DIGITS
            || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(TIME_SHAPE);
        }
        match last {
            Some(prev) if rank == prev => return Err("must name each unit only once"),
            Some(prev) if rank < prev => return Err("must name the largest unit first"),
            _ => {}
        }
        last = Some(rank);
        let amount: u32 = digits.parse().map_err(|_| TIME_SHAPE)?;
        if let Some(slot) = amounts.get_mut(rank) {
            *slot = amount;
        }
    }
    let [weeks, days, hours, minutes] = amounts;
    let spent = TimeSpent {
        weeks,
        days,
        hours,
        minutes,
    };
    match spent.default_minutes() {
        0 => Err("must be more than zero"),
        m if m > MAX_WORKLOG_MINUTES => Err("must not exceed 4w (the most one worklog books)"),
        _ => Ok(spent),
    }
}

/// What the approver reads next to the sent `time_spent`: the amounts in words. Weeks and days
/// are working time, whose length Jira's time tracking settings decide, so the seconds are given
/// at the defaults and as that; hours and minutes alone are exact.
pub(crate) fn describe_time_spent(raw: &str) -> Option<String> {
    let spent = parse_time_spent(raw).ok()?;
    let part = |n: u32, one: &str, many: &str| {
        (n > 0).then(|| format!("{n} {}", if n == 1 { one } else { many }))
    };
    let words: Vec<String> = [
        part(spent.weeks, "week", "weeks"),
        part(spent.days, "day", "days"),
        part(spent.hours, "hour", "hours"),
        part(spent.minutes, "minute", "minutes"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let words = words.join(", ");
    let minutes = spent.default_minutes();
    let seconds = u64::from(minutes) * 60;
    if spent.weeks == 0 && spent.days == 0 {
        return Some(format!("{words} = {seconds} s"));
    }
    let (h, m) = (minutes / 60, minutes % 60);
    let total = if m == 0 {
        format!("{h}h")
    } else {
        format!("{h}h {m}m")
    };
    Some(format!(
        "{words} of working time; at Jira's defaults (1d = {DEFAULT_HOURS_PER_DAY}h, \
         1w = {DEFAULT_DAYS_PER_WEEK}d) {total} = {seconds} s, your instance's time tracking \
         settings decide"
    ))
}

/// A worklog's `started` in Jira's `yyyy-MM-dd'T'HH:mm:ss.SSSZ` (`2026-09-02T09:00:00.000+0200`):
/// the local date and time and the zone's offset in seconds east of UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Started {
    local: NaiveDateTime,
    offset_secs: i32,
}

/// No worklog starts before this year (a typo or a wrong century).
const EARLIEST_STARTED_YEAR: i32 = 2000;

/// The zones are within `-14:00` to `+14:00`.
const MAX_OFFSET_SECS: i32 = 14 * 3600;

const STARTED_SHAPE: &str = "must be Jira's format, such as 2026-09-02T09:00:00.000+0200";

impl Started {
    /// The instant in UTC, when it is representable.
    fn utc(self) -> Option<NaiveDateTime> {
        self.local
            .checked_sub_signed(TimeDelta::try_seconds(i64::from(self.offset_secs))?)
    }
}

/// Parses a `started`, strictly: the exact shape, a real date and time (seconds up to `59`), a
/// zone of at most 14 hours written `+hhmm` (not `Z`, not `+hh:mm`), the year at least 2000.
/// Digits are ASCII digits only.
pub(crate) fn parse_started(raw: &str) -> Result<Started, &'static str> {
    let b = raw.as_bytes();
    let digits = |from: usize, to: usize| -> Option<u32> {
        b.get(from..to)?.iter().try_fold(0u32, |n, c| {
            c.is_ascii_digit().then(|| n * 10 + u32::from(*c - b'0'))
        })
    };
    let sep = |at: usize, want: u8| b.get(at) == Some(&want);
    let sign = match b.get(23) {
        Some(b'+') => 1i32,
        Some(b'-') => -1i32,
        _ => return Err(STARTED_SHAPE),
    };
    if b.len() != 28
        || !(sep(4, b'-') && sep(7, b'-') && sep(10, b'T'))
        || !(sep(13, b':') && sep(16, b':') && sep(19, b'.'))
    {
        return Err(STARTED_SHAPE);
    }
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        digits(0, 4),
        digits(5, 7),
        digits(8, 10),
        digits(11, 13),
        digits(14, 16),
        digits(17, 19),
    ) else {
        return Err(STARTED_SHAPE);
    };
    let (Some(_millis), Some(zone_h), Some(zone_m)) =
        (digits(20, 23), digits(24, 26), digits(26, 28))
    else {
        return Err(STARTED_SHAPE);
    };
    let year = i32::try_from(year).map_err(|_| STARTED_SHAPE)?;
    let (Some(date), Some(time)) = (
        NaiveDate::from_ymd_opt(year, month, day),
        NaiveTime::from_hms_opt(hour, minute, second),
    ) else {
        return Err("must be a date and time that exist");
    };
    if year < EARLIEST_STARTED_YEAR {
        return Err("must not be before the year 2000");
    }
    let offset = i32::try_from(zone_h * 3600 + zone_m * 60).map_err(|_| STARTED_SHAPE)?;
    if zone_m > 59 || offset > MAX_OFFSET_SECS {
        return Err("must have a zone between -1400 and +1400");
    }
    Ok(Started {
        local: date.and_time(time),
        offset_secs: sign * offset,
    })
}

/// What the approver reads next to the sent `started`: the local time with its zone and the same
/// instant in UTC (`2026-09-02 09:00:00 at UTC+02:00 (2026-09-02 07:00:00 UTC)`).
pub(crate) fn describe_started(raw: &str) -> Option<String> {
    let started = parse_started(raw).ok()?;
    let utc = started.utc()?;
    let offset = started.offset_secs.unsigned_abs();
    let sign = if started.offset_secs < 0 { '-' } else { '+' };
    Some(format!(
        "{} at UTC{sign}{:02}:{:02} ({utc} UTC)",
        started.local,
        offset / 3600,
        offset % 3600 / 60,
    ))
}

/// `POST /rest/api/2/issue/{key}/worklog` `{"timeSpent", "comment"?, "started"?}` (PD-55): the
/// params fill the fields of the same names, verbatim (PD-42: the comment is plain text or wiki
/// markup, `started` Jira's timestamp). Static checks first, so the validation dry call (and an
/// edit) refuses them (exit 2): the time ([`parse_time_spent`]), the start ([`parse_started`]; no
/// future check, so the executor is a pure function of the params and reads no clock, PD-55) and a blank comment (`maxLength` alone lets whitespace through; refused as
/// the link comment is). An absent or `null` optional sends nothing. No enrichment and no stale
/// rule (§5.4 step 5: an additive op).
pub fn worklog_add_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    let refuse = |param: &str, message: &str| ExecError::Invalid(invalid(param, message, None));
    let time_spent = match ctx.params.get("time_spent") {
        Some(Value::String(t)) => t.as_str(),
        Some(_) => return Err(refuse("time_spent", NOT_A_STRING)),
        None => "",
    };
    parse_time_spent(time_spent).map_err(|why| refuse("time_spent", why))?;
    let started = match ctx.params.get("started") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.trim().is_empty() => {
            return Err(refuse("started", "must not be blank"));
        }
        Some(Value::String(s)) => {
            parse_started(s).map_err(|why| refuse("started", why))?;
            Some(s.as_str())
        }
        Some(_) => return Err(refuse("started", NOT_A_STRING)),
    };
    let comment = match ctx.params.get("comment") {
        None | Some(Value::Null) => None,
        Some(Value::String(c)) if !c.trim().is_empty() => Some(c.as_str()),
        Some(Value::String(_)) => return Err(refuse("comment", "must not be blank")),
        Some(_) => return Err(refuse("comment", NOT_A_STRING)),
    };
    let mut body = Map::new();
    body.insert("timeSpent".to_owned(), Value::from(time_spent));
    if let Some(comment) = comment {
        body.insert("comment".to_owned(), Value::from(comment));
    }
    if let Some(started) = started {
        body.insert("started".to_owned(), Value::from(started));
    }
    json_request(ctx, &Value::Object(body))
}
