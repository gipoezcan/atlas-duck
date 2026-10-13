//! The Jira issue previewer (§6.3 "Jira issue", §6.2 levels, PD-45/PD-46): a card, the table of
//! every released field (and of the issue's other keys, such as `changelog`), the description and
//! the comments rendered from their wiki markup. The search and list tables (T11), and the write
//! cards over the exact request list (T12: `jira.issue.create`).
//!
//! Everything shown is display-escaped text, except the two HTML strings, which come only from
//! `convert::wiki_to_preview_html` through `preview::sanitize_html` (S-12) and are display-escaped
//! afterwards (invisible and bidi characters show as `⟨U+XXXX⟩`). Server-rendered HTML
//! (`renderedFields`) is never shown as HTML: its rows are text, marked as server-rendered.
//!
//! Warnings follow the content of the released candidate alone. Field names (the cache, which
//! changes between previews) never influence a warning or the Caution count (T8 handoff).

use atlas_duck_convert::{wiki_constructs, wiki_to_preview_html, wiki_to_text};
use atlas_duck_preview::diff::{DiffLine, DiffOp, LineDiff, hunks, line_diff};
use atlas_duck_preview::invisible::{self, escape_for_display};
use atlas_duck_preview::mixed_script::is_mixed_script;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_preview::{
    CommentView, ConstructList, FieldRow, IssueCard, ItemCount, JSON_STRING_COLLAPSE_BYTES,
    PreviewBody, PreviewHeader, sanitize_html,
};
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap, HashSet};

use super::jira::{escaped_prefix, pretty};
use super::{JiraUser, PreviewCtx, PreviewInput, PreviewModel, generic};
use crate::lifecycle::model::Hold;
use crate::metadata::{FieldNames, field_label, one_line};

/// A field value shows at most this many bytes (the JSON tree's collapse limit); Raw has it all.
const FIELD_VALUE_CAP: usize = JSON_STRING_COLLAPSE_BYTES;

/// The description's wiki text is rendered up to this many bytes.
const DESCRIPTION_CAP: usize = 64 * 1024;

/// Each comment's wiki text is rendered up to this many bytes.
const COMMENT_CAP: usize = 16 * 1024;

/// A transition card shows at most this many `fields` rows; the last row says how many it leaves
/// out (T14 review M8).
const TRANSITION_FIELD_ROWS: usize = 25;

/// The marker on the rows of `renderedFields` (plan text, T10).
const SERVER_RENDERED: &str = " (server-rendered)";

/// The marker on the rows of the issue's keys outside `fields` (T10 review I-3).
const OUTSIDE_FIELDS: &str = " (outside fields)";

/// §6.3 "Jira issue": the previewer of `jira.issue.get`. A candidate that is not a JSON object
/// (nothing to lay out) and every non-read input use the §6.3 Fallback.
pub fn issue_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let PreviewInput::Read(view) = &ctx.input else {
        return generic::fallback_preview(ctx);
    };
    let Some(issue) = view.candidate.as_object() else {
        return generic::fallback_preview(ctx);
    };
    let empty = Map::new();
    let fields = issue
        .get("fields")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let rendered = issue
        .get("renderedFields")
        .and_then(Value::as_object)
        .unwrap_or(&empty);

    let mut hidden = 0u64;
    let rows = field_rows(ctx.field_names, issue, fields, rendered, &mut hidden);
    let description_html = fields
        .get("description")
        .and_then(Value::as_str)
        .map(|d| render_wiki(d, DESCRIPTION_CAP, &mut hidden));
    let comments = comment_views(fields, rendered, &mut hidden);

    let (header, mut warnings) = generic::read_parts(ctx, view, hidden);
    content_warnings(&mut warnings, fields, rendered);

    let query = header.query.clone();
    PreviewModel {
        header,
        body: PreviewBody::JiraIssue {
            card: card(issue, fields),
            fields: rows,
            description_html,
            comments,
        },
        warnings,
        query,
    }
}

// ---- warnings --------------------------------------------------------------------------------

/// §6.2: Caution `restricted_comments` (a `visibility` on a released comment, in `fields` or its
/// `renderedFields` mirror) and `security_level` (a non-null `security`); Info
/// `linked_issue_summaries` and `custom_fields`. The `*all`, classifier, mixed-script and cap
/// warnings are the shared ones ([`generic::read_parts`]).
fn content_warnings(
    warnings: &mut Vec<Warning>,
    fields: &Map<String, Value>,
    rendered: &Map<String, Value>,
) {
    let restrictions = Restrictions::of_issue(fields, rendered);
    restrictions.push_warnings(warnings);
    let len = |key: &str| {
        fields
            .get(key)
            .and_then(Value::as_array)
            .map_or(0, |a| u64::try_from(a.len()).unwrap_or(u64::MAX))
    };
    let parent = u64::from(fields.get("parent").is_some_and(|p| !p.is_null()));
    let linked = len("issuelinks")
        .saturating_add(parent)
        .saturating_add(len("subtasks"));
    if linked > 0 {
        warnings.push(Warning::new(
            WarningId::LinkedIssueSummaries,
            warning::linked_issue_summaries(linked),
        ));
    }
    let custom = fields
        .keys()
        .filter(|k| k.starts_with("customfield_"))
        .count();
    if custom > 0 {
        warnings.push(Warning::new(
            WarningId::CustomFields,
            warning::custom_fields(u64::try_from(custom).unwrap_or(u64::MAX)),
        ));
    }
}

/// What restricts a released issue (or many): the two §6.2 Cautions, each shown once however many
/// issues carry it.
#[derive(Default)]
struct Restrictions {
    comments: bool,
    security: bool,
}

impl Restrictions {
    /// Restricted comments in `fields` or the `renderedFields` mirror, a non-null `security`.
    fn of_issue(fields: &Map<String, Value>, rendered: &Map<String, Value>) -> Restrictions {
        Restrictions {
            comments: comment_array(fields).iter().any(has_visibility)
                || comment_array(rendered).iter().any(has_visibility),
            security: fields.get("security").is_some_and(|s| !s.is_null()),
        }
    }

    fn merge(&mut self, other: Restrictions) {
        self.comments |= other.comments;
        self.security |= other.security;
    }

    fn push_warnings(&self, warnings: &mut Vec<Warning>) {
        if self.comments {
            warnings.push(Warning::new(
                WarningId::RestrictedComments,
                warning::TEXT_RESTRICTED_COMMENTS,
            ));
        }
        if self.security {
            warnings.push(Warning::new(
                WarningId::SecurityLevel,
                warning::TEXT_SECURITY_LEVEL,
            ));
        }
    }
}

/// `<fields or renderedFields>.comment.comments`, or none.
fn comment_array(tree: &Map<String, Value>) -> &[Value] {
    tree.get("comment")
        .and_then(|c| c.get("comments"))
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// A comment (or its mirror entry) restricted to a group or role: Jira sends `visibility` only
/// then.
fn has_visibility(comment: &Value) -> bool {
    comment.get("visibility").is_some_and(|v| !v.is_null())
}

// ---- the card --------------------------------------------------------------------------------

fn card(issue: &Map<String, Value>, fields: &Map<String, Value>) -> IssueCard {
    let text = |v: Option<&Value>| v.and_then(Value::as_str).map(escape_for_display);
    let name = |key: &str| text(fields.get(key).and_then(|v| v.get("name"))).unwrap_or_default();
    IssueCard {
        key: text(issue.get("key")).unwrap_or_default(),
        summary: text(fields.get("summary")).unwrap_or_default(),
        issue_type: name("issuetype"),
        status: name("status"),
        priority: text(fields.get("priority").and_then(|v| v.get("name"))),
        assignee: person(fields.get("assignee")),
        reporter: person(fields.get("reporter")),
    }
}

/// `displayName (name)`; whichever of the two exists alone; `None` for no user object.
fn person(user: Option<&Value>) -> Option<String> {
    let user = user?.as_object()?;
    let text = |key: &str| {
        user.get(key)
            .and_then(Value::as_str)
            .map(escape_for_display)
    };
    match (text("displayName"), text("name")) {
        (Some(display), Some(name)) => Some(format!("{display} ({name})")),
        (Some(one), None) | (None, Some(one)) => Some(one),
        (None, None) => None,
    }
}

// ---- the field table -------------------------------------------------------------------------

/// Which part of the issue a row comes from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tree {
    Fields,
    /// `renderedFields`, marked as server-rendered.
    Rendered,
    /// A key of the issue itself beside `fields` (`changelog`, `names`, `transitions`, …).
    TopLevel,
}

/// Top-level keys without a row: the card shows `key`; `id`, `self` and `expand` are the
/// issue's own identifiers; the two field trees have their rows.
const NO_ROW_KEYS: [&str; 6] = ["key", "id", "self", "expand", "fields", "renderedFields"];

/// A row for every released key of `fields`, then of `renderedFields` (marked), then of the issue
/// itself outside them (§6.1 principle 3: a `changelog` carries old values of any field), each in
/// id order.
fn field_rows(
    names: Option<&FieldNames>,
    issue: &Map<String, Value>,
    fields: &Map<String, Value>,
    rendered: &Map<String, Value>,
    hidden: &mut u64,
) -> Vec<FieldRow> {
    let mut rows = Vec::with_capacity(fields.len() + rendered.len());
    for (map, tree) in [
        (fields, Tree::Fields),
        (rendered, Tree::Rendered),
        (issue, Tree::TopLevel),
    ] {
        let mut ids: Vec<&String> = map.keys().collect();
        ids.sort_unstable();
        for id in ids {
            let Some(value) = map.get(id) else { continue };
            let shown = one_line(escape_for_display(id));
            let (name, shown_id) = match tree {
                Tree::Fields => (row_name(names, id), shown),
                Tree::Rendered => (
                    format!("{}{SERVER_RENDERED}", row_name(names, id)),
                    format!("renderedFields.{shown}"),
                ),
                Tree::TopLevel if NO_ROW_KEYS.contains(&id.as_str()) => continue,
                Tree::TopLevel => (
                    format!(
                        "{}{OUTSIDE_FIELDS}",
                        top_level_name(id).map_or_else(|| shown.clone(), str::to_owned)
                    ),
                    shown,
                ),
            };
            let restricted = tree != Tree::TopLevel
                && match id.as_str() {
                    "security" => !value.is_null(),
                    "comment" => value
                        .get("comments")
                        .and_then(Value::as_array)
                        .is_some_and(|c| c.iter().any(has_visibility)),
                    _ => false,
                };
            rows.push(FieldRow {
                id: shown_id,
                name,
                value_text: value_text(id, value, tree, hidden),
                restricted,
            });
        }
    }
    rows
}

/// Names of the top-level keys an `expand` (or Jira itself) adds to an issue.
fn top_level_name(key: &str) -> Option<&'static str> {
    Some(match key {
        "changelog" => "Change history",
        "names" => "Field names",
        "schema" => "Field schemas",
        "transitions" => "Transitions",
        "editmeta" => "Edit metadata",
        "operations" => "Operations",
        "versionedRepresentations" => "Versioned representations",
        _ => return None,
    })
}

/// The name of field `id`: the instance's cached name, else the built-in name of a system field
/// (§7.3 list), else [`field_label`] (an unknown `customfield_N` is flagged). Display-escaped.
fn row_name(names: Option<&FieldNames>, id: &str) -> String {
    if names.and_then(|n| n.get(id)).is_none()
        && let Some(builtin) = builtin_name(id)
    {
        return builtin.to_owned();
    }
    field_label(names, id)
}

/// Jira's own names of the §7.3 default fields and the other system fields an issue carries.
fn builtin_name(id: &str) -> Option<&'static str> {
    Some(match id {
        "summary" => "Summary",
        "status" => "Status",
        "issuetype" => "Issue Type",
        "priority" => "Priority",
        "assignee" => "Assignee",
        "reporter" => "Reporter",
        "created" => "Created",
        "updated" => "Updated",
        "labels" => "Labels",
        "components" => "Component/s",
        "fixVersions" => "Fix Version/s",
        "parent" => "Parent",
        "description" => "Description",
        "issuelinks" => "Linked Issues",
        "security" => "Security Level",
        "subtasks" => "Sub-tasks",
        "comment" => "Comment",
        "worklog" => "Log Work",
        "attachment" => "Attachment",
        _ => return None,
    })
}

/// The string itself, else compact JSON; comments are counted (their cards are below the table)
/// and the wiki description points at its rendering below (cut and counted there, not twice).
/// Cut at [`FIELD_VALUE_CAP`]; the cut bytes are added to `hidden`.
fn value_text(id: &str, value: &Value, tree: Tree, hidden: &mut u64) -> String {
    if tree != Tree::TopLevel
        && id == "comment"
        && let Some(comments) = value.get("comments").and_then(Value::as_array)
    {
        let n = comments.len();
        return if tree == Tree::Rendered {
            // The cards show the wiki source; the server's HTML bodies are only in Raw.
            format!(
                "{n} server-rendered comments (bodies in Raw; the cards below show the wiki source)"
            )
        } else {
            format!("{n} comments, shown below")
        };
    }
    if tree == Tree::Fields && id == "description" && value.is_string() {
        return "rendered below".to_owned();
    }
    let full = match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let (kept, cut) = cut_at(&full, FIELD_VALUE_CAP);
    *hidden = hidden.saturating_add(cut);
    if cut == 0 {
        escape_for_display(kept)
    } else {
        format!("{}… {cut} more bytes (see Raw)", escape_for_display(kept))
    }
}

// ---- description and comments ----------------------------------------------------------------

/// `s` cut to at most `cap` bytes at a char boundary, and how many bytes were cut.
fn cut_at(s: &str, cap: usize) -> (&str, u64) {
    if s.len() <= cap {
        return (s, 0);
    }
    let mut end = cap;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    (&s[..end], u64::try_from(s.len() - end).unwrap_or(u64::MAX))
}

/// Wiki text as preview HTML: rendered by the local renderer (never the server's HTML), sanitized,
/// then display-escaped. Text over `cap` bytes is cut and says so; the cut bytes are added to
/// `hidden`.
fn render_wiki(wiki: &str, cap: usize, hidden: &mut u64) -> String {
    let (kept, cut) = cut_at(wiki, cap);
    let mut html = wiki_to_preview_html(kept);
    if cut > 0 {
        *hidden = hidden.saturating_add(cut);
        html.push_str(&format!("<p>… {cut} more bytes (see Raw)</p>"));
    }
    escape_for_display(&sanitize_html(&html))
}

/// A card per comment of `fields.comment.comments`. A comment is restricted when it or its
/// `renderedFields` counterpart (same `id`) carries a `visibility`.
fn comment_views(
    fields: &Map<String, Value>,
    rendered: &Map<String, Value>,
    hidden: &mut u64,
) -> Vec<CommentView> {
    let mirror = comment_array(rendered);
    comment_array(fields)
        .iter()
        .map(|c| {
            let id = c.get("id");
            let counterpart_restricted = mirror
                .iter()
                .any(|m| id.is_some() && m.get("id") == id && has_visibility(m));
            let text = |key: &str| c.get(key).and_then(Value::as_str).map(escape_for_display);
            CommentView {
                id: id
                    .map(|v| match v {
                        Value::String(s) => escape_for_display(s),
                        other => escape_for_display(&other.to_string()),
                    })
                    .unwrap_or_default(),
                author: person(c.get("author")),
                created: text("created"),
                body_html: c
                    .get("body")
                    .and_then(Value::as_str)
                    .map(|b| render_wiki(b, COMMENT_CAP, hidden))
                    .unwrap_or_default(),
                restricted: has_visibility(c) || counterpart_restricted,
            }
        })
        .collect()
}

// ---- tables: search and lists ----------------------------------------------------------------

/// A table cell shows at most this many chars; Raw has the rest.
const CELL_CAP_CHARS: usize = 200;

/// A table has at most this many rows; the last row says how many items it leaves out.
const TABLE_ROW_CAP: usize = 500;

/// The columns of a table come from this many first items.
const COLUMN_SAMPLE_ITEMS: usize = 50;

/// A table has at most this many columns; the keys beyond count as hidden.
const MAX_COLUMNS: usize = 40;

/// A column name shows at most this many chars; the cut bytes count as hidden.
const COLUMN_NAME_CAP_CHARS: usize = 64;

/// A page key or identifier is skipped (not counted as hidden) only when it has the expected
/// type and, for a string, is at most this many bytes: nothing reaches the agent unshown and
/// uncounted.
const IDENT_CAP_BYTES: usize = 256;

fn short_string(v: &Value) -> bool {
    matches!(v, Value::String(s) if s.len() <= IDENT_CAP_BYTES)
}

/// A key of a result root that is page mechanics (shown as the count), not content: a number, a
/// bool or a short string of the expected kind.
fn is_page_mechanic(key: &str, value: &Value) -> bool {
    match key {
        "startAt" | "maxResults" | "total" => value.is_number(),
        "isLast" => value.is_boolean(),
        "expand" => short_string(value),
        _ => false,
    }
}

/// A key of a search item that is not content: its identifiers (the key has its column) with a
/// short value, and `fields` (shown by the columns, the rest counted apart).
fn is_item_identifier(key: &str, value: &Value) -> bool {
    match key {
        "fields" => true,
        "key" | "self" | "expand" => short_string(value),
        "id" => short_string(value) || value.is_number(),
        _ => false,
    }
}

/// The item arrays of the list ops that are objects (the paginated ops name theirs in the spec).
const LIST_KEYS: [&str; 5] = [
    "values",
    "issueLinkTypes",
    "transitions",
    "worklogs",
    "comments",
];

/// The keys a list table puts first, in this order, where the items have them.
const LEADING_KEYS: [&str; 4] = ["id", "key", "name", "displayName"];

/// Bytes a key and its value take as compact JSON: what a layout that drops them hides.
fn pair_bytes(key: &str, value: &Value) -> u64 {
    u64::try_from(key.len().saturating_add(value.to_string().len())).unwrap_or(u64::MAX)
}

fn bytes_of(value: &Value) -> u64 {
    u64::try_from(value.to_string().len()).unwrap_or(u64::MAX)
}

/// `s` cut to at most `cap` chars, and how many bytes were cut.
fn cut_chars(s: &str, cap: usize) -> (&str, u64) {
    match s.char_indices().nth(cap) {
        None => (s, 0),
        Some((at, _)) => (&s[..at], u64::try_from(s.len() - at).unwrap_or(u64::MAX)),
    }
}

/// `raw` cut at `cap` chars, display-escaped and one line, then cut at `cap` chars again (the
/// escape widens an invisible char to `⟨U+XXXX⟩`): the text, and the bytes cut in all.
fn capped_text(raw: &str, cap: usize) -> (String, u64) {
    let (kept, cut) = cut_chars(raw, cap);
    let escaped = one_line(escape_for_display(kept));
    let (shown, cut_escaped) = cut_chars(&escaped, cap);
    (shown.to_owned(), cut.saturating_add(cut_escaped))
}

/// A table cell: the string itself, else compact JSON, cut at [`CELL_CAP_CHARS`] after escaping
/// (said in the cell, the cut bytes added to `hidden`), display-escaped and one line.
fn cell(value: &Value, hidden: &mut u64) -> String {
    let full = match value {
        Value::String(s) => std::borrow::Cow::Borrowed(s.as_str()),
        other => std::borrow::Cow::Owned(other.to_string()),
    };
    let (shown, cut) = capped_text(&full, CELL_CAP_CHARS);
    if cut == 0 {
        return shown;
    }
    *hidden = hidden.saturating_add(cut);
    format!("{shown}… {cut} more bytes (see Raw)")
}

/// A column name (display-escaped, one line) cut at [`COLUMN_NAME_CAP_CHARS`]; the cut bytes are
/// added to `hidden`.
fn column_name(raw: &str, hidden: &mut u64) -> String {
    let (shown, cut) = capped_text(raw, COLUMN_NAME_CAP_CHARS);
    if cut == 0 {
        return shown;
    }
    *hidden = hidden.saturating_add(cut);
    format!("{shown}…")
}

/// A table cell of an item's member, or empty where the item has none.
fn cell_of(member: Option<&Value>, hidden: &mut u64) -> String {
    member.map_or_else(String::new, |v| cell(v, hidden))
}

/// The row that says what the row cap left out; its text is in the first cell.
fn omitted_row(columns: usize, omitted: usize) -> Vec<String> {
    let mut row = vec![format!("… {omitted} more items (see Raw)")];
    row.resize(columns.max(1), String::new());
    row
}

/// The result root's keys that are neither the item array nor page mechanics: hidden.
fn other_root_bytes(root: &Value, items_key: Option<&str>) -> u64 {
    let Some(map) = root.as_object() else {
        return 0;
    };
    map.iter()
        .filter(|(k, v)| Some(k.as_str()) != items_key && !is_page_mechanic(k, v))
        .fold(0u64, |sum, (k, v)| sum.saturating_add(pair_bytes(k, v)))
}

/// The count of a table: the paging facts of the read, else what the list holds.
fn table_count(header: &mut PreviewHeader, shown: usize) -> Option<ItemCount> {
    let shown = u64::try_from(shown).unwrap_or(u64::MAX);
    let count = header.item_count.unwrap_or(ItemCount {
        shown,
        total: Some(shown),
        more_available: false,
    });
    header.item_count = Some(count);
    Some(count)
}

/// §6.3 "Jira search": a table of the key and the requested (or default) fields, a row per issue,
/// "N of total". Used for `jira.search` and the agile issue lists. Every cell is display-escaped
/// text; what the table leaves out of the issues (other fields, `renderedFields`, `changelog`, …)
/// is counted in `hidden_in_preview_bytes`. Server-rendered HTML is never shown.
pub fn search_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let PreviewInput::Read(view) = &ctx.input else {
        return generic::fallback_preview(ctx);
    };
    let items_key = ctx.spec.paginated.map(|p| p.items_key);
    let Some(issues) = items_key
        .and_then(|k| view.candidate.get(k))
        .and_then(Value::as_array)
    else {
        return generic::fallback_preview(ctx);
    };

    let mut hidden = other_root_bytes(view.candidate, items_key);
    let ids = search_field_ids(ctx, issues);
    let columns = search_columns(ctx.field_names, &ids, &mut hidden);
    let mut rows: Vec<Vec<String>> = Vec::with_capacity(issues.len().min(TABLE_ROW_CAP + 1));
    let mut restrictions = Restrictions::default();
    let empty = Map::new();
    for (n, issue) in issues.iter().enumerate() {
        let Some(map) = issue.as_object() else {
            hidden = hidden.saturating_add(bytes_of(issue));
            continue;
        };
        let fields = map
            .get("fields")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        let rendered = map
            .get("renderedFields")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        // Every issue scanned counts for the Cautions, shown row or not.
        restrictions.merge(Restrictions::of_issue(fields, rendered));
        if n >= TABLE_ROW_CAP {
            hidden = hidden.saturating_add(bytes_of(issue));
            continue;
        }
        let mut row = Vec::with_capacity(ids.len() + 1);
        row.push(match map.get("key") {
            Some(Value::String(k)) if k.len() <= IDENT_CAP_BYTES => one_line(escape_for_display(k)),
            // Not a short string: counted below, not shown.
            _ => String::new(),
        });
        row.extend(ids.iter().map(|id| cell_of(fields.get(id), &mut hidden)));
        rows.push(row);
        for (k, v) in fields.iter().filter(|(k, _)| !ids.contains(k)) {
            hidden = hidden.saturating_add(pair_bytes(k, v));
        }
        if let Some(f) = map.get("fields").filter(|f| !f.is_object()) {
            hidden = hidden.saturating_add(pair_bytes("fields", f));
        }
        for (k, v) in map.iter().filter(|(k, v)| !is_item_identifier(k, v)) {
            hidden = hidden.saturating_add(pair_bytes(k, v));
        }
    }
    if issues.len() > TABLE_ROW_CAP {
        rows.push(omitted_row(columns.len(), issues.len() - TABLE_ROW_CAP));
    }

    let (mut header, mut warnings) = generic::read_parts(ctx, view, hidden);
    restrictions.push_warnings(&mut warnings);
    let count = table_count(&mut header, issues.len());
    let query = header.query.clone();
    PreviewModel {
        header,
        body: PreviewBody::Table {
            columns,
            rows,
            count,
        },
        warnings,
        query,
    }
}

/// The field ids of the table's columns: the requested ones in order, else the registry's
/// defaults; with no list, or a list of `*`/`-` tokens (`*all`, `*navigable`, `-description`),
/// the field keys of the first issues in first-seen order.
fn search_field_ids(ctx: &PreviewCtx<'_>, issues: &[Value]) -> Vec<String> {
    let rules = ctx.spec.field_rules;
    let requested: Vec<&str> = rules
        .and_then(|r| r.fields_param)
        .and_then(|name| ctx.params.get(name))
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let named = !requested.is_empty()
        && requested
            .iter()
            .all(|f| !f.starts_with(['*', '-']) && !f.is_empty());
    let mut ids: Vec<String> = Vec::new();
    let mut push = |id: &str| {
        if ids.len() < MAX_COLUMNS && !ids.iter().any(|i| i == id) {
            ids.push(id.to_owned());
        }
    };
    if named {
        requested.iter().for_each(|f| push(f));
    } else if requested.is_empty() && rules.is_some_and(|r| !r.default_fields.is_empty()) {
        rules
            .into_iter()
            .flat_map(|r| r.default_fields.iter())
            .for_each(|f| push(f));
    } else {
        // The registry's default fields first (a JSON object has no insertion order: its keys
        // come sorted), then the others as first seen.
        let seen: Vec<&String> = issues
            .iter()
            .take(COLUMN_SAMPLE_ITEMS)
            .filter_map(|i| i.get("fields").and_then(Value::as_object))
            .flat_map(Map::keys)
            .collect();
        let defaults = rules.map_or(&[][..], |r| r.default_fields);
        defaults
            .iter()
            .filter(|d| seen.iter().any(|k| k.as_str() == **d))
            .for_each(|d| push(d));
        seen.iter().for_each(|k| push(k));
    }
    ids
}

/// `Key`, then a label per field id. A label two columns share gets its id appended.
fn search_columns(names: Option<&FieldNames>, ids: &[String], hidden: &mut u64) -> Vec<String> {
    const KEY: &str = "Key";
    let labels: Vec<String> = ids.iter().map(|id| row_name(names, id)).collect();
    let taken = |label: &str| {
        usize::from(label == KEY) + labels.iter().filter(|l| l.as_str() == label).count() > 1
    };
    let mut out = vec![KEY.to_owned()];
    // Labels are display-escaped already; the id (server or agent text) is escaped here.
    let named: Vec<String> = ids
        .iter()
        .zip(&labels)
        .map(|(id, label)| {
            if taken(label) {
                format!("{label} ({})", one_line(escape_for_display(id)))
            } else {
                label.clone()
            }
        })
        .collect();
    out.extend(named.iter().map(|n| column_name(n, hidden)));
    out
}

/// §6.3 "Lists": an item list (an array root, or `values`/`issueLinkTypes`/`transitions`/
/// `worklogs`/`comments`) as a table whose columns are the scalar keys of the first 50 items in
/// first-seen order, a row per item. A result that is no list of objects (`jira.myself`,
/// `project.get`, `attachment.meta`, `editmeta`) keeps the §6.3 Fallback (the JSON tree). What
/// the table leaves out (nested values, later items' extra keys, other root keys) is counted in
/// `hidden_in_preview_bytes`; Raw has the exact bytes.
pub fn list_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let PreviewInput::Read(view) = &ctx.input else {
        return generic::fallback_preview(ctx);
    };
    let spec_key = ctx.spec.paginated.map(|p| p.items_key);
    let (items, items_key) = match view.candidate {
        Value::Array(items) => (items, None),
        Value::Object(map) => {
            let found = spec_key
                .into_iter()
                .chain(LIST_KEYS)
                .find_map(|k| map.get(k).and_then(Value::as_array).map(|a| (a, Some(k))));
            match found {
                Some(found) => found,
                None => return generic::fallback_preview(ctx),
            }
        }
        _ => return generic::fallback_preview(ctx),
    };
    let columns = scalar_columns(items);
    let restricted_comments =
        ctx.spec.id == "jira.comment.list" && items.iter().any(has_visibility);
    if columns.is_empty() {
        let mut model = generic::fallback_preview(ctx);
        if restricted_comments {
            model.warnings.push(restricted_comments_warning());
        }
        return model;
    }

    let mut hidden = other_root_bytes(view.candidate, items_key);
    let mut rows: Vec<Vec<String>> = Vec::with_capacity(items.len().min(TABLE_ROW_CAP + 1));
    for (n, item) in items.iter().enumerate() {
        let (Some(map), true) = (item.as_object(), n < TABLE_ROW_CAP) else {
            hidden = hidden.saturating_add(bytes_of(item));
            continue;
        };
        rows.push(
            columns
                .iter()
                .map(|c| cell_of(map.get(c).filter(|v| is_scalar(v)), &mut hidden))
                .collect(),
        );
        for (k, v) in map {
            if !(is_scalar(v) && columns.contains(k)) {
                hidden = hidden.saturating_add(pair_bytes(k, v));
            }
        }
    }
    if items.len() > TABLE_ROW_CAP {
        rows.push(omitted_row(columns.len(), items.len() - TABLE_ROW_CAP));
    }

    let columns: Vec<String> = columns
        .iter()
        .map(|c| column_name(c, &mut hidden))
        .collect();
    let (mut header, mut warnings) = generic::read_parts(ctx, view, hidden);
    if restricted_comments {
        warnings.push(restricted_comments_warning());
    }
    let count = table_count(&mut header, items.len());
    let query = header.query.clone();
    PreviewModel {
        header,
        body: PreviewBody::Table {
            columns,
            rows,
            count,
        },
        warnings,
        query,
    }
}

fn restricted_comments_warning() -> Warning {
    Warning::new(
        WarningId::RestrictedComments,
        warning::TEXT_RESTRICTED_COMMENTS,
    )
}

fn is_scalar(v: &Value) -> bool {
    !matches!(v, Value::Array(_) | Value::Object(_))
}

/// The scalar keys of the first [`COLUMN_SAMPLE_ITEMS`] items, at most [`MAX_COLUMNS`]: the
/// identifying keys of [`LEADING_KEYS`] first, then the rest in first-seen order. (A JSON object
/// here has no insertion order, its keys come sorted, so "first seen" is per item in key order.)
fn scalar_columns(items: &[Value]) -> Vec<String> {
    let mut leading: [Option<&String>; LEADING_KEYS.len()] = [None; LEADING_KEYS.len()];
    let mut rest: Vec<&String> = Vec::new();
    let mut seen: HashSet<&String> = HashSet::new();
    let keys = items
        .iter()
        .take(COLUMN_SAMPLE_ITEMS)
        .filter_map(Value::as_object)
        .flat_map(|m| m.iter().filter(|(_, v)| is_scalar(v)).map(|(k, _)| k));
    for key in keys {
        if let Some(slot) = LEADING_KEYS.iter().position(|l| *l == key.as_str()) {
            if let Some(entry) = leading.get_mut(slot) {
                entry.get_or_insert(key);
            }
        } else if rest.len() < MAX_COLUMNS && seen.insert(key) {
            rest.push(key);
        }
        // Everything the columns can hold is known: the remaining keys are not scanned.
        if rest.len() >= MAX_COLUMNS && leading.iter().all(Option::is_some) {
            break;
        }
    }
    leading
        .into_iter()
        .flatten()
        .chain(rest)
        .take(MAX_COLUMNS)
        .cloned()
        .collect()
}

// ---- write previews (Task 12) -----------------------------------------------------------------

/// The sentence of the create card (plan text, §6.3 Create).
fn create_sentence(issue_type: &str, project_key: &str) -> String {
    format!("Create a {issue_type} in {project_key}")
}

/// One line of display text cut to `cap` chars ([`capped_text`]); the cut bytes go to `hidden`.
fn line(raw: &str, cap: usize, hidden: &mut u64) -> String {
    let (shown, cut) = capped_text(raw, cap);
    *hidden = hidden.saturating_add(cut);
    shown
}

/// The constructs of an outgoing wiki text (PD-47), each entry display-escaped on one line.
fn construct_list(wiki: &str) -> ConstructList {
    let c = wiki_constructs(wiki);
    let shown = |v: Vec<String>| -> Vec<String> {
        v.iter().map(|s| one_line(escape_for_display(s))).collect()
    };
    ConstructList {
        macros: shown(c.macros),
        mentions: shown(c.mentions),
        includes: shown(c.includes),
        links: shown(c.links),
        images: shown(c.images),
        attachments: shown(c.attachments),
    }
}

/// §6.3 Create: the `jira.issue.create` card over the exact request (§5.1 inv. 4: the request list
/// stays part of the body). Every row is read from the request that is sent (T7 M-6: never
/// converted again; T12 review M4: the project key and issue type id too, named from the
/// verdict's facts only where they are about the same ones), the description shown as the text of its wiki markup with its constructs
/// listed (PD-47). The missing-fields Caution is the verdict's own (PD-49). Every other hold,
/// or a request that is not the create JSON, keeps the generic write preview.
pub fn create_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let mut model = generic::write_preview(ctx);
    let PreviewInput::Write(view) = &ctx.input else {
        return model;
    };
    let facts = view
        .enrichment
        .filter(|v| v.hold == Hold::Preview)
        .and_then(|v| v.summary.as_ref());
    let (Some(facts), Some(request), PreviewBody::WriteRequests { .. }) =
        (facts, view.requests.first(), &model.body)
    else {
        return model;
    };
    let Some(fields) = serde_json::from_slice::<Value>(&request.body)
        .ok()
        .and_then(|b| b.get("fields").and_then(Value::as_object).cloned())
    else {
        return model;
    };
    let mut hidden = 0u64;
    // T12 review M4: the project and issue type the request sends; the verdict's names only
    // where its facts are about the same ones (by construction always; a mismatch is shown).
    let sent = |k: &str, sub: &str| {
        fields
            .get(k)
            .and_then(|v| v.get(sub))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let (key, type_id) = (sent("project", "key"), sent("issuetype", "id"));
    let project = match (facts.project_key.as_deref(), facts.project_name.as_deref()) {
        (Some(k), Some(name)) if k == key => format!("{key} ({name})"),
        (Some(k), _) if k != key => format!("{key} (enrichment resolved {k})"),
        _ => key.clone(),
    };
    let same_type = facts.issue_type_id.as_deref() == Some(type_id.as_str());
    let issue_type = match facts.issue_type.as_deref() {
        Some(name) if same_type => name.to_owned(),
        _ => type_id.clone(),
    };
    let type_row = match facts.issue_type_id.as_deref() {
        Some(id) if !same_type => format!("{type_id} (enrichment resolved {id})"),
        _ => issue_type.clone(),
    };
    let mut rows = vec![
        (
            "Project".to_owned(),
            line(&project, CELL_CAP_CHARS * 2, &mut hidden),
        ),
        (
            "Issue type".to_owned(),
            line(&type_row, CELL_CAP_CHARS * 2, &mut hidden),
        ),
    ];
    let text = |k: &str| fields.get(k).and_then(Value::as_str);
    if let Some(summary) = text("summary") {
        rows.push((
            "Summary".to_owned(),
            line(summary, CELL_CAP_CHARS * 2, &mut hidden),
        ));
    }
    let description = text("description");
    if let Some(wiki) = description {
        let (kept, cut) = cut_at(wiki, DESCRIPTION_CAP);
        hidden = hidden.saturating_add(cut);
        let mut shown = escape_for_display(&wiki_to_text(kept));
        if cut > 0 {
            shown.push_str(&format!("… {cut} more bytes (see Raw)"));
        }
        rows.push(("Description".to_owned(), shown));
    }
    // The other fields, verbatim JSON (PD-42), named like the Caution and the edit form name a
    // field (`<name> (<id>)`, T12 review M8) where createmeta listed it; else by id (write
    // previews take no cached field names, T8 handoff).
    for (id, value) in &fields {
        if matches!(
            id.as_str(),
            "project" | "issuetype" | "summary" | "description"
        ) {
            continue;
        }
        let label = field_row_label(&facts.field_names, id, &mut hidden);
        let json = serde_json::to_string(value).unwrap_or_default();
        rows.push((label, line(&json, FIELD_VALUE_CAP, &mut hidden)));
    }
    let requests = take_requests(&mut model);
    model.body = PreviewBody::WriteSummary {
        sentence: line(
            &create_sentence(&issue_type, &key),
            CELL_CAP_CHARS * 2,
            &mut hidden,
        ),
        rows,
        constructs: description.map(construct_list),
        requests,
    };
    model.header.hidden_in_preview_bytes = hidden;
    model
}

/// A `fields` row's label: `<name> (<id>)` where enrichment named the field (createmeta, the
/// transition screen; T12 review M8), else the id (write previews take no cached field names, T8
/// handoff). One display-escaped line.
fn field_row_label(names: &[(String, String)], id: &str, hidden: &mut u64) -> String {
    match names.iter().find(|(f, _)| f == id) {
        Some((_, name)) => line(&format!("{name} ({id})"), CELL_CAP_CHARS * 2, hidden),
        None => field_label(None, id),
    }
}

/// The request list of a write preview whose body is [`PreviewBody::WriteRequests`], moved out
/// (§5.1 inv. 4: every write card keeps it); the body is left empty for the caller to replace.
fn take_requests(model: &mut PreviewModel) -> Vec<atlas_duck_preview::RequestView> {
    match std::mem::replace(
        &mut model.body,
        PreviewBody::WriteRequests {
            requests: Vec::new(),
        },
    ) {
        PreviewBody::WriteRequests { requests } => requests,
        _ => Vec::new(),
    }
}

/// The text of a wiki text's rendering (`wiki_to_text`), display-escaped: the source is cut at
/// `cap` bytes before it is rendered, the rendering again at `cap` escaped bytes
/// ([`escaped_prefix`], so an escape is never split and a text of invisible characters stays
/// bounded). A cut says how many bytes of the rendered text it hides (one unit, T14 review M7:
/// the cut-off source is rendered too, at least 1 byte for a cut), which are also added to
/// `hidden`.
fn rendered_text(wiki: &str, cap: usize, hidden: &mut u64) -> String {
    let (kept, cut) = cut_at(wiki, cap);
    let text = wiki_to_text(kept);
    let (mut shown, used) = escaped_prefix(&text, cap);
    let more = u64::try_from(text.len().saturating_sub(used)).unwrap_or(u64::MAX);
    let cut_text = if cut > 0 {
        let tail = wiki.get(kept.len()..).map_or(0, |t| wiki_to_text(t).len());
        u64::try_from(tail).unwrap_or(u64::MAX).max(1)
    } else {
        0
    };
    let hides = cut_text.saturating_add(more);
    *hidden = hidden.saturating_add(hides);
    if hides > 0 {
        shown.push_str(&format!("… {hides} more bytes (see Raw)"));
    }
    shown
}

/// §6.3 comment: the `jira.comment.add` card over the exact request: "Comment on <key>", the
/// body shown as the text of its wiki markup (read from the request that is sent, T7 M-6: a
/// Markdown body was converted once, at validation, and not again here), a visibility row when
/// the comment is restricted (no `restricted_comments` Caution: §6.2 defines it for released
/// reads, and on a write it would only inflate the queue's Caution count, T14 review I1), and the
/// constructs of the body (PD-47). Any other input keeps the generic write preview.
pub fn comment_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let mut model = generic::write_preview(ctx);
    let PreviewInput::Write(view) = &ctx.input else {
        return model;
    };
    let (Some(request), PreviewBody::WriteRequests { .. }) = (view.requests.first(), &model.body)
    else {
        return model;
    };
    let Some(body) = serde_json::from_slice::<Value>(&request.body)
        .ok()
        .and_then(|b| b.as_object().cloned())
    else {
        return model;
    };
    let Some(wiki) = body.get("body").and_then(Value::as_str) else {
        return model;
    };
    let mut hidden = 0u64;
    let key = ctx.params.get("key").and_then(Value::as_str).unwrap_or("");
    let mut rows = vec![(
        "Body".to_owned(),
        rendered_text(wiki, COMMENT_CAP, &mut hidden),
    )];
    if let Some(visibility) = body.get("visibility").filter(|v| !v.is_null()) {
        let text = match (
            visibility.get("type").and_then(Value::as_str),
            visibility.get("value").and_then(Value::as_str),
        ) {
            (Some(kind), Some(value)) => format!("{kind}: {value}"),
            _ => serde_json::to_string(visibility).unwrap_or_default(),
        };
        rows.push((
            "Visibility".to_owned(),
            line(&text, CELL_CAP_CHARS * 2, &mut hidden),
        ));
    }
    let requests = take_requests(&mut model);
    model.body = PreviewBody::WriteSummary {
        sentence: line(
            &format!("Comment on {key}"),
            CELL_CAP_CHARS * 2,
            &mut hidden,
        ),
        rows,
        constructs: Some(construct_list(wiki)),
        requests,
    };
    model.header.hidden_in_preview_bytes = hidden;
    model
}

/// §6.3 transition: the `jira.issue.transition` card over the exact request: the status the
/// issue is in and the one the transition leads to (the verdict's facts), the `fields` the
/// transition sets (named like the Caution names a field where the transition screen does), the
/// comment sent with it as the text of its wiki markup, and that comment's constructs (PD-42,
/// PD-47: sent verbatim). The required-fields Caution is the verdict's own. Every other hold, or
/// a request that is not the transition JSON, keeps the generic write preview.
pub fn transition_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let mut model = generic::write_preview(ctx);
    let PreviewInput::Write(view) = &ctx.input else {
        return model;
    };
    let facts = view
        .enrichment
        .filter(|v| v.hold == Hold::Preview)
        .and_then(|v| v.summary.as_ref());
    let (Some(facts), Some(request), PreviewBody::WriteRequests { .. }) =
        (facts, view.requests.first(), &model.body)
    else {
        return model;
    };
    let Some(body) = serde_json::from_slice::<Value>(&request.body)
        .ok()
        .and_then(|b| b.as_object().cloned())
    else {
        return model;
    };
    let mut hidden = 0u64;
    let status = |name: &Option<String>, hidden: &mut u64| {
        line(
            name.as_deref().unwrap_or("(not named)"),
            CELL_CAP_CHARS * 2,
            hidden,
        )
    };
    let from = status(&facts.from_status, &mut hidden);
    let to = status(&facts.to_status, &mut hidden);
    let sent_id = body
        .get("transition")
        .and_then(|t| t.get("id"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let transition = match facts.transition_name.as_deref() {
        Some(name) => line(
            &format!("{name} ({sent_id})"),
            CELL_CAP_CHARS * 2,
            &mut hidden,
        ),
        None => line(sent_id, CELL_CAP_CHARS * 2, &mut hidden),
    };
    let mut fields = Vec::new();
    let sent_fields = body.get("fields").and_then(Value::as_object);
    for (n, (id, value)) in sent_fields.into_iter().flatten().enumerate() {
        if n >= TRANSITION_FIELD_ROWS {
            let left = sent_fields.map_or(0, |m| m.len().saturating_sub(n));
            let bytes = sent_fields
                .into_iter()
                .flatten()
                .skip(n)
                .fold(0u64, |sum, (k, v)| sum.saturating_add(pair_bytes(k, v)));
            hidden = hidden.saturating_add(bytes);
            fields.push((
                format!("… {left} more fields"),
                format!("{bytes} bytes (see Raw)"),
            ));
            break;
        }
        let label = field_row_label(&facts.field_names, id, &mut hidden);
        let json = serde_json::to_string(value).unwrap_or_default();
        fields.push((label, line(&json, FIELD_VALUE_CAP, &mut hidden)));
    }
    let comment = body
        .get("update")
        .and_then(|u| u.get("comment"))
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|c| c.get("add")?.get("body")?.as_str());
    if let Some(wiki) = comment {
        // Labelled apart from a `fields.comment` entry, which is its own row (T14 review M8).
        fields.push((
            "comment (update.comment)".to_owned(),
            rendered_text(wiki, COMMENT_CAP, &mut hidden),
        ));
    }
    let requests = take_requests(&mut model);
    model.body = PreviewBody::Transition {
        transition,
        from,
        to,
        fields,
        constructs: comment.map(construct_list),
        requests,
    };
    model.header.hidden_in_preview_bytes = hidden;
    model
}

/// A display name on the assign card shows at most this many chars after display escaping (T15
/// review I1): one the user chose, padded with invisible characters (each an 8-char
/// `⟨U+XXXX⟩`), never pushes the username out of its line.
const DISPLAY_NAME_CAP_CHARS: usize = 64;

/// `raw` (a display name) cut where its display-escaped one-line form would pass
/// [`DISPLAY_NAME_CAP_CHARS`] chars, never inside an escape, with `…` where it was cut; the bytes
/// of `raw` cut go to `hidden`. Raw text: [`line`] escapes it with the rest of its line.
fn short_display_name(raw: &str, hidden: &mut u64) -> String {
    let escaped = one_line(escape_for_display(raw));
    let mut rest = escaped.as_str();
    let mut width = 0usize;
    for (at, _) in raw.char_indices() {
        // Each char shows as itself or as one `⟨U+XXXX⟩` (a literal `⟨` is escaped too).
        let len = if rest.starts_with('⟨') {
            rest.find('⟩').map_or(rest.len(), |i| i + '⟩'.len_utf8())
        } else {
            rest.chars().next().map_or(0, char::len_utf8)
        };
        let (shown, tail) = rest.split_at_checked(len).unwrap_or((rest, ""));
        width += shown.chars().count();
        if width > DISPLAY_NAME_CAP_CHARS {
            let cut = u64::try_from(raw.len().saturating_sub(at)).unwrap_or(u64::MAX);
            *hidden = hidden.saturating_add(cut);
            return format!("{}…", raw.get(..at).unwrap_or_default());
        }
        rest = tail;
    }
    raw.to_owned()
}

/// The assign card's text for a user: `<name> (<display name>)`, the username first (T15 review
/// I1) and the display name cut ([`short_display_name`]), else whichever is there (raw; [`line`]
/// escapes it).
fn user_text(user: &JiraUser, hidden: &mut u64) -> String {
    let display = user
        .display_name
        .as_deref()
        .map(|d| short_display_name(d, hidden));
    match (user.name.as_deref(), display) {
        (Some(name), Some(display)) => format!("{name} ({display})"),
        (Some(name), None) => name.to_owned(),
        (None, Some(display)) => display,
        (None, None) => user.key.clone().unwrap_or_default(),
    }
}

/// Adds the invisible characters of server text a write card shows beyond its request (T15
/// review I1: a display name) to the §6.4 counts; the `bidi_controls` / `other_invisible`
/// Cautions then follow the totals.
fn count_card_text<'a>(model: &mut PreviewModel, texts: impl IntoIterator<Item = &'a str>) {
    let header = &mut model.header;
    for text in texts {
        let (bidi, other) = invisible::count(text);
        header.bidi_controls = header.bidi_controls.saturating_add(bidi);
        header.other_invisible = header.other_invisible.saturating_add(other);
    }
    for (id, n, text) in [
        (
            WarningId::BidiControls,
            header.bidi_controls,
            warning::bidi_controls(header.bidi_controls),
        ),
        (
            WarningId::OtherInvisible,
            header.other_invisible,
            warning::other_invisible(header.other_invisible),
        ),
    ] {
        match model.warnings.iter_mut().find(|w| w.id == id) {
            Some(w) => *w = Warning::new(id, text),
            None if n > 0 => model.warnings.push(Warning::new(id, text)),
            None => {}
        }
    }
}

/// What the assign card shows for nobody (an unassigned issue, an unassign).
const UNASSIGNED: &str = "(unassigned)";

/// §6.3 Assign: the `jira.issue.assign` card over the exact request: "Assign <key> to <user>" or
/// "Unassign <key>", rows `From` (the current assignee enrichment read, the stale-check baseline)
/// and `To`, the sent username alone (`Sent as user name`), and each user's key (§7.3: previews
/// show `name` and `key`). `To` is read from the request that is sent (T12 review M4): the
/// resolved user's display name and key are shown only when the facts are about the sent `name`,
/// else "<sent> (enrichment resolved <name>)". A user shows as `<name> (<display name>)`, the
/// display name cut short, so the sent username always leads the sentence and `To` (T15 review
/// I1); the invisible characters of the server text the card shows count into the §6.4
/// Cautions. The sent username is an identifier the agent may not have named (resolved by key
/// or display name), so it gets the mixed-script check the params get (§6.4). Every other hold,
/// or a request that is not the assign JSON, keeps the generic write preview.
pub fn assign_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let mut model = generic::write_preview(ctx);
    let PreviewInput::Write(view) = &ctx.input else {
        return model;
    };
    let facts = view
        .enrichment
        .filter(|v| v.hold == Hold::Preview)
        .and_then(|v| v.summary.as_ref());
    let (Some(facts), Some(request), PreviewBody::WriteRequests { .. }) =
        (facts, view.requests.first(), &model.body)
    else {
        return model;
    };
    let Some(body) = serde_json::from_slice::<Value>(&request.body).ok() else {
        return model;
    };
    let sent = match body.get("name") {
        Some(Value::Null) => None,
        Some(Value::String(name)) => Some(name.as_str()),
        _ => return model,
    };
    let key = ctx.params.get("key").and_then(Value::as_str).unwrap_or("");
    let mut hidden = 0u64;
    let cap = CELL_CAP_CHARS * 2;
    let from = facts.assignee_from.as_ref();
    let to = facts
        .assignee_to
        .as_ref()
        .filter(|u| sent.is_some() && u.name.as_deref() == sent);
    let other = facts
        .assignee_to
        .as_ref()
        .and_then(|u| u.name.as_deref())
        .filter(|_| to.is_none());
    let to_text = match (sent, to) {
        (None, _) => UNASSIGNED.to_owned(),
        (Some(_), Some(user)) => user_text(user, &mut hidden),
        (Some(name), None) => match other {
            Some(other) => format!("{name} (enrichment resolved {other})"),
            None => name.to_owned(),
        },
    };
    let sentence = match sent {
        None => format!("Unassign {key}"),
        Some(_) => format!("Assign {key} to {to_text}"),
    };
    let from_text = match from {
        Some(user) => user_text(user, &mut hidden),
        None => UNASSIGNED.to_owned(),
    };
    let mut rows = vec![
        ("From".to_owned(), line(&from_text, cap, &mut hidden)),
        ("To".to_owned(), line(&to_text, cap, &mut hidden)),
    ];
    if let Some(name) = sent {
        rows.push(("Sent as user name".to_owned(), line(name, cap, &mut hidden)));
    }
    for (label, user) in [("From user key", from), ("To user key", to)] {
        if let Some(k) = user.and_then(|u| u.key.as_deref()) {
            rows.push((label.to_owned(), line(k, cap, &mut hidden)));
        }
    }
    if let Some(name) = sent
        && is_mixed_script(name)
    {
        let text = warning::mixed_script(&escape_for_display(name));
        if !model
            .warnings
            .iter()
            .any(|w| w.id == WarningId::MixedScript && w.text == text)
        {
            model
                .warnings
                .push(Warning::new(WarningId::MixedScript, text));
        }
    }
    // The server text the card shows beyond the request (which has the sent name).
    let shown = from
        .into_iter()
        .flat_map(|u| [&u.display_name, &u.name, &u.key])
        .chain(to.into_iter().flat_map(|u| [&u.display_name, &u.key]))
        .filter_map(|t| t.as_deref())
        .chain(other);
    count_card_text(&mut model, shown);
    let requests = take_requests(&mut model);
    model.body = PreviewBody::WriteSummary {
        sentence: line(&sentence, cap, &mut hidden),
        rows,
        constructs: None,
        requests,
    };
    model.header.hidden_in_preview_bytes = hidden;
    model
}

// ---- edit diffs (Task 13) ---------------------------------------------------------------------

/// Each view of an edit diff shows at most this many bytes per line kind (`Same`, `Del`, `Add`),
/// counted after display escaping (T13 review M-6); the rest is cut, flagged by the
/// `diff_truncated` Caution and counted as hidden. A budget per kind, so a huge current value
/// never pushes the outgoing one out of the diff.
const EDIT_DIFF_KIND_BYTES: usize = 1024 * 1024;

/// A field's section heading shows at most this many chars, suffix included.
const FIELD_HEADING_CAP_CHARS: usize = 256;

/// Field ids whose text Jira shows verbatim, never as wiki markup (T13 review M-3): their
/// rendered view is the text itself, so markup characters show and count as visible. A fixed
/// list: the field-name cache never influences a warning.
const PLAIN_TEXT_FIELDS: [&str; 1] = ["summary"];

/// One view (rendered or raw) of an edit diff while it is built.
struct DiffView {
    lines: Vec<DiffLine>,
    /// Escaped bytes left for `Same`, `Del`, `Add` lines.
    left: [usize; 3],
    /// Bytes of either text the view does not show.
    cut: u64,
}

impl DiffView {
    fn new() -> DiffView {
        DiffView {
            lines: Vec::new(),
            left: [EDIT_DIFF_KIND_BYTES; 3],
            cut: 0,
        }
    }

    fn heading(&mut self, label: &str) {
        self.lines.push(DiffLine {
            op: DiffOp::Field,
            text: label.to_owned(),
        });
    }

    /// One text line, display-escaped and cut to the escaped bytes its kind's budget has left,
    /// never inside an escape (the line terminator stays: the escape leaves `\n`, `\r` and `\t`
    /// alone). The text bytes not shown count as cut.
    fn push(&mut self, op: DiffOp, text: &str) {
        let slot = match op {
            DiffOp::Same => 0,
            DiffOp::Del => 1,
            DiffOp::Add => 2,
            DiffOp::Field => return self.heading(text),
        };
        let Some(left) = self.left.get_mut(slot) else {
            return;
        };
        let (kept, taken) = escaped_prefix(text, *left);
        *left -= kept.len();
        let cut = u64::try_from(text.len().saturating_sub(taken)).unwrap_or(u64::MAX);
        self.cut = self.cut.saturating_add(cut);
        if !kept.is_empty() {
            self.lines.push(DiffLine { op, text: kept });
        }
    }

    /// A whole [`line_diff`] of `old` against `new`; what its own caps dropped counts as cut.
    fn extend(&mut self, diff: &LineDiff, old: &str, new: &str) {
        let (mut same, mut del, mut add) = (0usize, 0usize, 0usize);
        for line in &diff.lines {
            match line.op {
                DiffOp::Same => same += line.text.len(),
                DiffOp::Del => del += line.text.len(),
                DiffOp::Add => add += line.text.len(),
                DiffOp::Field => {}
            }
            self.push(line.op, &line.text);
        }
        if diff.truncated {
            let missing = old
                .len()
                .saturating_sub(same + del)
                .saturating_add(new.len().saturating_sub(same + add))
                .max(1);
            self.cut = self
                .cut
                .saturating_add(u64::try_from(missing).unwrap_or(u64::MAX));
        }
    }
}

/// The text pair a string field's rendered diff compares (PD-51): both strings, or a string and
/// `null` (an absent or cleared field reads as no text). `None` for every other pair.
fn string_pair<'a>(current: &'a Value, outgoing: &'a Value) -> Option<(&'a str, &'a str)> {
    match (current, outgoing) {
        (Value::String(c), Value::String(o)) => Some((c, o)),
        (Value::Null, Value::String(o)) => Some(("", o)),
        (Value::String(c), Value::Null) => Some((c, "")),
        _ => None,
    }
}

/// A diff line without its `\n` terminator.
fn line_body(line: &str) -> &str {
    line.strip_suffix('\n').unwrap_or(line)
}

/// `a` and `b` without the lines they share one for one, compared by `key`.
fn cancel<'a>(
    a: &[&'a str],
    b: &[&'a str],
    key: for<'x> fn(&'x str) -> &'x str,
) -> (Vec<&'a str>, Vec<&'a str>) {
    let mut in_b: HashMap<&str, usize> = HashMap::new();
    for y in b {
        *in_b.entry(key(y)).or_default() += 1;
    }
    let mut shared: HashMap<&str, usize> = HashMap::new();
    let a_left = a
        .iter()
        .copied()
        .filter(|x| match in_b.get_mut(key(x)) {
            Some(n) if *n > 0 => {
                *n -= 1;
                *shared.entry(key(x)).or_default() += 1;
                false
            }
            _ => true,
        })
        .collect();
    let b_left = b
        .iter()
        .copied()
        .filter(|y| match shared.get_mut(key(y)) {
            Some(n) if *n > 0 => {
                *n -= 1;
                false
            }
            _ => true,
        })
        .collect();
    (a_left, b_left)
}

/// Takes one `key` from `pool`; whether there was one.
fn take(pool: &mut HashMap<&str, usize>, key: &str) -> bool {
    match pool.get_mut(key) {
        Some(n) if *n > 0 => {
            *n -= 1;
            true
        }
        _ => false,
    }
}

/// The changed source lines (not blank) the rendered diff does not show: neither the line's own
/// projection nor its text is among the rendered diff's changed lines of that side (`pool`, one
/// use each, compared without trailing whitespace).
fn unshown(lines: &[&str], pool: &mut HashMap<&str, usize>) -> u64 {
    let mut count = 0u64;
    for line in lines.iter().filter(|l| !l.trim().is_empty()) {
        let projected = wiki_to_text(line);
        let shown = [projected.trim_end(), line.trim_end()]
            .into_iter()
            .filter(|k| !k.is_empty())
            .any(|k| take(pool, k));
        if !shown {
            count += 1;
        }
    }
    count
}

/// The raw-only changes of one hunk of the wiki-source diff, the largest of three counts:
/// - 1 when the hunk's removed and added text project to the same text (T13);
/// - with as many removed as added lines, each line pair that differs but projects alike
///   (T13 review I-1: an invisible change beside a visible one in the same hunk);
/// - per side, the changed lines [`unshown`] in the rendered diff (any line counts; the fallback
///   for unequal counts). Lines that differ only in their `\n` are left out of this count.
fn hunk_changes(dels: &[&str], adds: &[&str], pools: &mut [HashMap<&str, usize>; 2]) -> u64 {
    let whole = u64::from(wiki_to_text(&dels.concat()) == wiki_to_text(&adds.concat()));
    let pairs = if dels.len() == adds.len() {
        dels.iter()
            .zip(adds)
            .filter(|(d, a)| line_body(d) != line_body(a) && wiki_to_text(d) == wiki_to_text(a))
            .count()
    } else {
        0
    };
    let pairs = u64::try_from(pairs).unwrap_or(u64::MAX);
    let (dels, adds) = cancel(dels, adds, line_body);
    let [del_pool, add_pool] = pools;
    let lost = unshown(&dels, del_pool).max(unshown(&adds, add_pool));
    whole.max(pairs).max(lost)
}

/// T6 handoff and T13 review I-1 (PD-51 weakness, narrowed): the changes of a string field's
/// wiki source the rendered diff `rendered` (of the two projections) cannot show, however many
/// visible changes the field has, summed over the hunks of the source line diff
/// ([`hunk_changes`]). The rule may over-count (a line is projected out of its block, so a
/// change inside a `{code}` or `{quote}` block or to a block's delimiter line can count) and
/// does not see: an invisible change inside a line that also changes visibly, a change of only
/// a line's `\n` beside a visible change, a changed blank line beside a visible change. The raw
/// view shows all of them. A source diff cut at its caps counts nothing here (the
/// `diff_truncated` Caution covers it).
fn invisible_changes(old: &str, new: &str, rendered: &LineDiff) -> u64 {
    let diff = line_diff(old, new);
    if diff.truncated {
        return 0;
    }
    // The rendered diff's changed lines per side, without the pairs that differ only in
    // trailing whitespace (a line that only gained or lost its `\n` there shows no change).
    let side = |op: DiffOp| -> Vec<&str> {
        rendered
            .lines
            .iter()
            .filter(|l| l.op == op)
            .map(|l| l.text.as_str())
            .collect()
    };
    let (gone, came) = cancel(&side(DiffOp::Del), &side(DiffOp::Add), str::trim_end);
    let mut pools: [HashMap<&str, usize>; 2] = [HashMap::new(), HashMap::new()];
    for (pool, lines) in pools.iter_mut().zip([gone, came]) {
        for l in lines {
            *pool.entry(l.trim_end()).or_default() += 1;
        }
    }
    let mut count = 0u64;
    let (mut dels, mut adds): (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
    for line in diff.lines.iter().map(Some).chain([None]) {
        match line.map(|l| (l.op, l.text.as_str())) {
            Some((DiffOp::Del, t)) => dels.push(t),
            Some((DiffOp::Add, t)) => adds.push(t),
            _ => {
                if !(dels.is_empty() && adds.is_empty()) {
                    count = count.saturating_add(hunk_changes(&dels, &adds, &mut pools));
                }
                dels.clear();
                adds.clear();
            }
        }
    }
    count
}

/// The single value a list of `update` operations sets: exactly `[{"set": v}]`.
fn single_set(ops: &Value) -> Option<&Value> {
    let [op] = ops.as_array()?.as_slice() else {
        return None;
    };
    let op = op.as_object().filter(|o| o.len() == 1)?;
    op.get("set")
}

/// Whether a list of `update` operations sets the value somewhere.
fn sets_value(ops: &Value) -> bool {
    ops.as_array()
        .is_some_and(|a| a.iter().any(|op| op.get("set").is_some()))
}

/// Both views of an edit diff while they are built, with what they count.
struct EditDiff {
    rendered: DiffView,
    raw: DiffView,
    /// Bytes of field ids cut from headings.
    headings_cut: u64,
    raw_only: u64,
    /// Sections shown without the current value (`no_current_value`).
    no_current: u64,
}

impl EditDiff {
    fn new() -> EditDiff {
        EditDiff {
            rendered: DiffView::new(),
            raw: DiffView::new(),
            headings_cut: 0,
            raw_only: 0,
            no_current: 0,
        }
    }

    /// A section heading in both views: `label` display-escaped and one line, then `suffix`,
    /// at most [`FIELD_HEADING_CAP_CHARS`] chars in all (T13 review M-7). A cut label ends in
    /// `…` before the suffix: two long ids with one prefix must not look alike.
    fn heading(&mut self, label: &str, suffix: &str) {
        let room = FIELD_HEADING_CAP_CHARS.saturating_sub(suffix.chars().count());
        let (shown, cut) = capped_text(label, room);
        let text = if cut == 0 {
            format!("{shown}{suffix}")
        } else {
            let (shorter, more) = cut_chars(&shown, room.saturating_sub(1));
            self.headings_cut = self.headings_cut.saturating_add(cut).saturating_add(more);
            format!("{shorter}…{suffix}")
        };
        self.rendered.heading(&text);
        self.raw.heading(&text);
    }

    /// A value that replaces field `id`'s current one (`fields.<id>`, or `update.<id>` with one
    /// `set`; PD-51): the raw diff of the pretty JSON of the current against the outgoing value;
    /// the rendered diff of their projections for a string field (`wiki_to_text`, or the text
    /// itself for [`PLAIN_TEXT_FIELDS`]), else the raw diff again. A value sent unchanged is a
    /// heading only. Raw-only changes: `max(0, raw hunks − rendered hunks)` (PD-51), or the
    /// [`invisible_changes`] when there are more of those. Without a current value: [`Self::sent`].
    fn replace(&mut self, label: &str, id: &str, current: Option<&Value>, outgoing: &Value) {
        let Some(current) = current else {
            return self.sent(label, outgoing);
        };
        let (old, new) = (pretty(current), pretty(outgoing));
        if old == new {
            return self.heading(label, " (unchanged)");
        }
        self.heading(label, "");
        let raw_diff = line_diff(&old, &new);
        self.raw.extend(&raw_diff, &old, &new);
        let Some((c, o)) = string_pair(current, outgoing) else {
            return self.rendered.extend(&raw_diff, &old, &new);
        };
        let plain = PLAIN_TEXT_FIELDS.contains(&id);
        let (c_text, o_text) = if plain {
            (c.to_owned(), o.to_owned())
        } else {
            (wiki_to_text(c), wiki_to_text(o))
        };
        let rendered_diff = line_diff(&c_text, &o_text);
        self.rendered.extend(&rendered_diff, &c_text, &o_text);
        let by_hunks = hunks(&raw_diff.lines).saturating_sub(hunks(&rendered_diff.lines));
        // The text projected as itself hides nothing.
        let invisible = if plain {
            0
        } else {
            invisible_changes(c, o, &rendered_diff)
        };
        self.raw_only = self.raw_only.saturating_add(by_hunks.max(invisible));
    }

    /// What is sent, as its raw JSON lines (all `Add`) in both views.
    fn operations(&mut self, label: &str, sent: &Value) {
        self.heading(label, "");
        let text = pretty(sent);
        let diff = line_diff("", &text);
        self.rendered.extend(&diff, "", &text);
        self.raw.extend(&diff, "", &text);
    }

    /// What is sent without a current value to diff it against (no baseline for the id, or an
    /// operation list that sets the value): its raw lines, counted for `no_current_value` (T13
    /// review M-1).
    fn sent(&mut self, label: &str, sent: &Value) {
        self.operations(label, sent);
        self.no_current = self.no_current.saturating_add(1);
    }
}

/// §6.3 Edit/update: the `jira.issue.edit` preview over the exact request (§5.1 inv. 4: the
/// request list stays part of the body). Per edited field id (sorted; `fields` before `update`
/// for one id) a section in both views: the current value is the verdict's baseline (what the
/// stale check compares, PD-51), the outgoing one the sent body's `fields.<id>` or the value of
/// a single `update.<id>` `set` (never the params again). Other `update` operation lists are
/// sent verbatim and shown as their raw JSON lines in both views. Caution `raw_only_diff(n)`
/// when a change shows only in the raw diff; Caution `no_current_value(n)` when a section has
/// no current value to diff against; Caution `diff_truncated(n)` when a view was cut. The
/// conflict card (a `Conflict` verdict) and every other hold keep the generic write preview.
pub fn edit_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let mut model = generic::write_preview(ctx);
    let PreviewInput::Write(view) = &ctx.input else {
        return model;
    };
    let verdict = view.enrichment.filter(|v| v.hold == Hold::Preview);
    let (Some(verdict), Some(request), PreviewBody::WriteRequests { .. }) =
        (verdict, view.requests.first(), &model.body)
    else {
        return model;
    };
    let Some(body) = serde_json::from_slice::<Value>(&request.body)
        .ok()
        .and_then(|b| b.as_object().cloned())
    else {
        return model;
    };
    let map = |k: &str| body.get(k).and_then(Value::as_object);
    let (fields, update) = (map("fields"), map("update"));
    let ids: BTreeSet<&String> = fields
        .into_iter()
        .chain(update)
        .flat_map(Map::keys)
        .collect();
    let mut diff = EditDiff::new();
    for id in ids {
        let current = verdict.baseline.get(id.as_str());
        if let Some(outgoing) = fields.and_then(|f| f.get(id.as_str())) {
            diff.replace(&format!("fields.{id}"), id, current, outgoing);
        }
        if let Some(ops) = update.and_then(|u| u.get(id.as_str())) {
            let label = format!("update.{id}");
            match single_set(ops) {
                Some(value) => diff.replace(&label, id, current, value),
                None if sets_value(ops) => diff.sent(&label, ops),
                None => diff.operations(&label, ops),
            }
        }
    }
    if diff.raw_only > 0 {
        model.warnings.push(Warning::new(
            WarningId::RawOnlyDiff,
            warning::raw_only_diff(diff.raw_only),
        ));
    }
    if diff.no_current > 0 {
        model.warnings.push(Warning::new(
            WarningId::NoCurrentValue,
            warning::no_current_value(diff.no_current),
        ));
    }
    let cut = diff.raw.cut.max(diff.rendered.cut);
    if cut > 0 {
        model.warnings.push(Warning::new(
            WarningId::DiffTruncated,
            warning::diff_truncated(cut),
        ));
    }
    let requests = match std::mem::replace(
        &mut model.body,
        PreviewBody::WriteRequests {
            requests: Vec::new(),
        },
    ) {
        PreviewBody::WriteRequests { requests } => requests,
        _ => Vec::new(),
    };
    model.body = PreviewBody::EditDiff {
        rendered: diff.rendered.lines,
        raw: diff.raw.lines,
        raw_only_changes: diff.raw_only,
        requests,
    };
    model.header.hidden_in_preview_bytes = diff.headings_cut.saturating_add(cut);
    model
}
