//! The Jira issue previewer (§6.3 "Jira issue", §6.2 levels, PD-45/PD-46): a card, the table of
//! every released field, the description and the comments rendered from their wiki markup.
//!
//! Everything shown is display-escaped text, except the two HTML strings, which come only from
//! `convert::wiki_to_preview_html` through `preview::sanitize_html` (S-12) and are display-escaped
//! afterwards (invisible and bidi characters show as `⟨U+XXXX⟩`). Server-rendered HTML
//! (`renderedFields`) is never shown as HTML: its rows are text, marked as server-rendered.
//!
//! Warnings follow the content of the released candidate alone. Field names (the cache, which
//! changes between previews) never influence a warning or the Caution count (T8 handoff).

use atlas_duck_convert::wiki_to_preview_html;
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_preview::{
    CommentView, FieldRow, IssueCard, JSON_STRING_COLLAPSE_BYTES, PreviewBody, sanitize_html,
};
use serde_json::{Map, Value};

use super::{PreviewCtx, PreviewInput, PreviewModel, generic};
use crate::metadata::{FieldNames, field_label};

/// A field value shows at most this many bytes (the JSON tree's collapse limit); Raw has it all.
const FIELD_VALUE_CAP: usize = JSON_STRING_COLLAPSE_BYTES;

/// The description's wiki text is rendered up to this many bytes.
const DESCRIPTION_CAP: usize = 64 * 1024;

/// Each comment's wiki text is rendered up to this many bytes.
const COMMENT_CAP: usize = 16 * 1024;

/// The marker on the rows of `renderedFields` (plan text, T10).
const SERVER_RENDERED: &str = " (server-rendered)";

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
    let rows = field_rows(ctx.field_names, fields, rendered, &mut hidden);
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
    if comment_array(fields).iter().any(has_visibility)
        || comment_array(rendered).iter().any(has_visibility)
    {
        warnings.push(Warning::new(
            WarningId::RestrictedComments,
            warning::TEXT_RESTRICTED_COMMENTS,
        ));
    }
    if fields.get("security").is_some_and(|s| !s.is_null()) {
        warnings.push(Warning::new(
            WarningId::SecurityLevel,
            warning::TEXT_SECURITY_LEVEL,
        ));
    }
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

/// A row for every released key of `fields`, then of `renderedFields` (marked), each in id order.
fn field_rows(
    names: Option<&FieldNames>,
    fields: &Map<String, Value>,
    rendered: &Map<String, Value>,
    hidden: &mut u64,
) -> Vec<FieldRow> {
    let mut rows = Vec::with_capacity(fields.len() + rendered.len());
    for (tree, mirror) in [(fields, false), (rendered, true)] {
        let mut ids: Vec<&String> = tree.keys().collect();
        ids.sort_unstable();
        for id in ids {
            let Some(value) = tree.get(id) else { continue };
            let label = row_name(names, id);
            let (name, shown_id) = if mirror {
                (
                    format!("{label}{SERVER_RENDERED}"),
                    format!("renderedFields.{}", escape_for_display(id)),
                )
            } else {
                (label, escape_for_display(id))
            };
            let restricted = match id.as_str() {
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
                value_text: value_text(id, value, mirror, hidden),
                restricted,
            });
        }
    }
    rows
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

/// The string itself, else compact JSON; comments are counted (their cards are below the table).
/// Cut at [`FIELD_VALUE_CAP`]; the cut bytes are added to `hidden`.
fn value_text(id: &str, value: &Value, mirror: bool, hidden: &mut u64) -> String {
    if id == "comment"
        && let Some(comments) = value.get("comments").and_then(Value::as_array)
    {
        let kind = if mirror { "server-rendered " } else { "" };
        return format!("{} {kind}comments, shown below", comments.len());
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
