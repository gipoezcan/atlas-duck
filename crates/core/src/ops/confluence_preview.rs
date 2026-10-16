//! The Confluence previewers (§6.3): the search table (Task 12a), the page card and the comment
//! thread (Task 12b). Every cell and field is display-escaped text (the shared table cells of
//! `generic`); what a layout leaves out of the candidate is counted in `hidden_in_preview_bytes`,
//! and Raw has the exact bytes. The list ops use `generic::list_table` (PD-114).
//!
//! The page and comment bodies are HTML: the local renderer's output only
//! (`convert::markdown_to_preview_html` over Markdown, never converter markup taken as HTML),
//! or for `format=view` the server's HTML; either way through `preview::sanitize_html` (S-12) and
//! display-escaped afterwards (invisible and bidi characters show as `⟨U+XXXX⟩`), as the Jira
//! previews do with wiki markup.

use std::collections::HashMap;

use atlas_duck_convert::{
    ConversionReport, MarkdownTooLarge, UserResolutions, markdown_to_preview_html,
    storage_to_markdown_within,
};
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_preview::{ConfluenceComment, ConversionFacts, PreviewBody, sanitize_html};
use atlas_duck_registry::Product;
use serde_json::{Map, Value};

use super::confluence::{BodyFormat, body_format};
use super::generic::{
    TABLE_ROW_CAP, bytes_of, cell_of, cut_at, omitted_row, other_root_bytes, pair_bytes,
    short_string, table_count,
};
use super::{PreviewCtx, PreviewInput, PreviewModel, generic};

/// §6.3 "Confluence search": the table's columns (plan text, Task 12a), in this order.
const SEARCH_COLUMNS: [&str; 4] = ["title", "space", "type", "last modified"];

/// The column added with `excerpt=indexed` (§6.3 "excerpt").
const EXCERPT_COLUMN: &str = "excerpt";

/// §6.3 "Confluence search": a row per released result with its `title`, its space
/// (`resultGlobalContainer.title`), `content.type`, `lastModified` and, only when the agent asked
/// for `excerpt=indexed`, its `excerpt`; the count "N of totalSize" (the read's paging facts).
/// `None` when the candidate holds no `results` list (an upstream-error card keeps the Fallback).
pub(crate) fn search_table(ctx: &PreviewCtx<'_>) -> Option<PreviewModel> {
    let PreviewInput::Read(view) = &ctx.input else {
        return None;
    };
    let root = view.candidate.as_object()?;
    let results = root.get("results")?.as_array()?;
    let excerpt = ctx.params.get("excerpt").and_then(Value::as_str) == Some("indexed");

    let mut hidden = other_root_bytes(Product::Confluence, view.candidate, Some("results"));
    let mut columns: Vec<String> = SEARCH_COLUMNS.iter().map(|c| (*c).to_owned()).collect();
    if excerpt {
        columns.push(EXCERPT_COLUMN.to_owned());
    }
    let mut rows: Vec<Vec<String>> = Vec::with_capacity(results.len().min(TABLE_ROW_CAP + 1));
    for (n, result) in results.iter().enumerate() {
        let (Some(map), true) = (result.as_object(), n < TABLE_ROW_CAP) else {
            hidden = hidden.saturating_add(bytes_of(result));
            continue;
        };
        let member = |object: &str, key: &str| {
            map.get(object)
                .and_then(Value::as_object)
                .and_then(|o| o.get(key))
        };
        let mut row = vec![
            cell_of(map.get("title"), &mut hidden),
            cell_of(member("resultGlobalContainer", "title"), &mut hidden),
            cell_of(member("content", "type"), &mut hidden),
            cell_of(map.get("lastModified"), &mut hidden),
        ];
        if excerpt {
            row.push(cell_of(map.get("excerpt"), &mut hidden));
        }
        rows.push(row);
        hidden = hidden.saturating_add(unshown_bytes(map, excerpt));
    }
    if results.len() > TABLE_ROW_CAP {
        rows.push(omitted_row(columns.len(), results.len() - TABLE_ROW_CAP));
    }

    let (mut header, warnings) = generic::read_parts(ctx, view, hidden);
    let count = table_count(&mut header, results.len());
    let query = header.query.clone();
    Some(PreviewModel {
        header,
        body: PreviewBody::Table {
            columns,
            rows,
            count,
        },
        warnings,
        query,
    })
}

/// The bytes of a result its row does not show: every key and nested key but the shown ones,
/// except a short `content.id` (the result's identifier, as a Jira issue's `id`).
fn unshown_bytes(map: &Map<String, Value>, excerpt: bool) -> u64 {
    map.iter().fold(0u64, |sum, (key, value)| {
        let unshown = match (key.as_str(), value) {
            ("title" | "lastModified", _) => 0,
            ("excerpt", _) if excerpt => 0,
            ("content", Value::Object(content)) => unshown_in(content, &|k, v| {
                k == "type" || (k == "id" && (short_string(v) || v.is_number()))
            }),
            ("resultGlobalContainer", Value::Object(space)) => {
                unshown_in(space, &|k, _| k == "title")
            }
            _ => pair_bytes(key, value),
        };
        sum.saturating_add(unshown)
    })
}

/// The bytes of the members of `object` that `shown` does not name.
fn unshown_in(object: &Map<String, Value>, shown: &dyn Fn(&str, &Value) -> bool) -> u64 {
    object
        .iter()
        .filter(|(k, v)| !shown(k, v))
        .fold(0u64, |sum, (k, v)| sum.saturating_add(pair_bytes(k, v)))
}

// ---- the page card (§6.3 "Confluence page", PD-100) --------------------------------------------

/// plan text (Task 12b): the label of a `format=storage` page body, which the preview renders
/// locally from the storage it releases (with an empty user map: mentions show as `@user:<key>`).
pub const STORAGE_RENDERED_LABEL: &str = "rendered locally from storage";

/// A page body's Markdown (or view HTML) is rendered up to this many bytes; Raw has it all.
const PAGE_BODY_CAP: usize = 256 * 1024;

/// A storage body is rendered only while its Markdown stays within this many bytes (the
/// conversion stops there, T10 review B-1); a larger one is not rendered here.
const STORAGE_MARKDOWN_BUDGET: usize = 1024 * 1024;

/// Each comment's Markdown is rendered up to this many bytes (as a Jira comment's wiki text).
const COMMENT_BODY_CAP: usize = 16 * 1024;

/// A comment's storage is rendered only while its Markdown stays within this many bytes.
const COMMENT_MARKDOWN_BUDGET: usize = 64 * 1024;

/// §6.3 "Confluence page": the previewer of `confluence.page.get` and of
/// `confluence.page.history` (with `version`; the history summary has no body and keeps the
/// §6.3 Fallback). A card with the title, the space, the version, the ancestor titles and the
/// format, then the body: the released Markdown rendered locally (with the conversion facts),
/// the released storage rendered locally (labelled), or the server's `view` HTML sanitized (with
/// the Caution `server_rendered_view`). A candidate without the format's body text (an id that
/// is not a page, an upstream answer) keeps the Fallback.
pub(crate) fn page_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    page_model(ctx).unwrap_or_else(|| generic::fallback_preview(ctx))
}

fn page_model(ctx: &PreviewCtx<'_>) -> Option<PreviewModel> {
    let PreviewInput::Read(view) = &ctx.input else {
        return None;
    };
    let (format, _historical) = body_format(ctx.spec, ctx.params)?;
    let page = view.candidate.as_object()?;
    let body = page.get("body")?.as_object()?;
    let text = |container: &str| {
        body.get(container)
            .and_then(Value::as_object)
            .and_then(|o| o.get("value"))
            .and_then(Value::as_str)
    };

    let mut hidden = page_unshown_bytes(page, format);
    let mut warnings_after: Vec<Warning> = Vec::new();
    let (format_name, body_html, conversion) = match format {
        BodyFormat::Markdown => {
            if body.get("format").and_then(Value::as_str) != Some("markdown") {
                return None;
            }
            let markdown = body.get("value")?.as_str()?;
            let report = view.conversion.as_ref();
            if let Some(r) = report {
                info_warnings(r, true, &mut warnings_after);
            }
            (
                "markdown",
                render_markdown(markdown, PAGE_BODY_CAP, &mut hidden),
                report.map(facts),
            )
        }
        BodyFormat::Storage => {
            let storage = text("storage")?;
            let (html, report) = render_storage(
                storage,
                STORAGE_MARKDOWN_BUDGET,
                PAGE_BODY_CAP,
                Some(STORAGE_RENDERED_LABEL),
                &mut hidden,
            );
            // Mentions are not looked up for storage (PD-99): `unresolved_mention` is the
            // Markdown release's alone.
            if let Some(r) = &report {
                info_warnings(r, false, &mut warnings_after);
            }
            ("storage", html, None)
        }
        BodyFormat::View => {
            let html = text("view")?;
            let (kept, cut) = cut_at(html, PAGE_BODY_CAP);
            let mut shown = sanitize_html(kept);
            if cut > 0 {
                hidden = hidden.saturating_add(cut);
                shown.push_str(&more_bytes(cut));
            }
            warnings_after.push(Warning::new(
                WarningId::ServerRenderedView,
                warning::TEXT_SERVER_RENDERED_VIEW,
            ));
            ("view", escape_for_display(&shown), None)
        }
    };

    let (header, mut warnings) = generic::read_parts(ctx, view, hidden);
    warnings.extend(warnings_after);
    let query = header.query.clone();
    Some(PreviewModel {
        header,
        body: PreviewBody::ConfluencePage {
            title: text_of(page.get("title")).unwrap_or_default(),
            space: space_text(page.get("space")),
            version: page
                .get("version")
                .and_then(|v| v.get("number"))
                .and_then(Value::as_u64),
            ancestors: page
                .get("ancestors")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(|a| text_of(a.get("title")))
                        .collect()
                })
                .unwrap_or_default(),
            format: format_name.to_owned(),
            body_html,
            conversion,
        },
        warnings,
        query,
    })
}

/// A string member, display-escaped.
fn text_of(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(escape_for_display)
}

/// `Name (KEY)`, whichever of the two the space object has, or empty.
fn space_text(space: Option<&Value>) -> String {
    let name = text_of(space.and_then(|s| s.get("name")));
    let key = text_of(space.and_then(|s| s.get("key")));
    match (name, key) {
        (Some(name), Some(key)) => format!("{name} ({key})"),
        (Some(one), None) | (None, Some(one)) => one,
        (None, None) => String::new(),
    }
}

/// The Info warnings a conversion report implies (§6.2): `unknown_macros` when it names any,
/// and (`mentions`: a Markdown release) `unresolved_mention` when a mention stayed a key.
fn info_warnings(report: &ConversionReport, mentions: bool, warnings: &mut Vec<Warning>) {
    if !report.unknown_macros.is_empty() {
        warnings.push(Warning::new(
            WarningId::UnknownMacros,
            warning::TEXT_UNKNOWN_MACROS,
        ));
    }
    if mentions && report.unresolved_users > 0 {
        warnings.push(Warning::new(
            WarningId::UnresolvedMention,
            warning::TEXT_UNRESOLVED_MENTION,
        ));
    }
}

fn facts(r: &ConversionReport) -> ConversionFacts {
    ConversionFacts {
        lossy: r.lossy,
        macros: r.lost.macros,
        images: r.lost.images,
        links: r.lost.links,
        layouts: r.lost.layouts,
        unresolved_users: r.unresolved_users,
        fallback: r.fallback,
    }
}

fn more_bytes(cut: u64) -> String {
    format!("<p>… {cut} more bytes (see Raw)</p>")
}

/// Markdown as preview HTML: the local renderer, sanitized, then display-escaped. Text over
/// `cap` bytes is cut and says so; the cut bytes are added to `hidden`.
fn render_markdown(markdown: &str, cap: usize, hidden: &mut u64) -> String {
    let (kept, cut) = cut_at(markdown, cap);
    let mut html = markdown_to_preview_html(kept);
    if cut > 0 {
        *hidden = hidden.saturating_add(cut);
        html.push_str(&more_bytes(cut));
    }
    escape_for_display(&sanitize_html(&html))
}

/// Storage rendered locally (PD-103, Task 12b): converted with an empty user map within
/// `budget` bytes of Markdown, then as [`render_markdown`] with `cap`, after `label` when given.
/// A storage whose Markdown passes the budget is not rendered (its bytes count as hidden).
fn render_storage(
    storage: &str,
    budget: usize,
    cap: usize,
    label: Option<&str>,
    hidden: &mut u64,
) -> (String, Option<ConversionReport>) {
    let mut html = label.map_or_else(String::new, |l| format!("<p><strong>{l}</strong></p>"));
    let empty = UserResolutions::new();
    match storage_to_markdown_within(storage, &empty, budget) {
        Ok((markdown, report, _)) => {
            html.push_str(&render_markdown(&markdown, cap, hidden));
            (html, Some(report))
        }
        Err(MarkdownTooLarge) => {
            let bytes = u64::try_from(storage.len()).unwrap_or(u64::MAX);
            *hidden = hidden.saturating_add(bytes);
            html.push_str(&format!(
                "<p>… {bytes} bytes not rendered here (see Raw)</p>"
            ));
            (html, None)
        }
    }
}

/// The bytes of the page the card does not show: every member but the title, a short `id`, the
/// space's name and key, the version number, the ancestors' titles and the body text the format
/// shows (with the Markdown body's `format`).
fn page_unshown_bytes(page: &Map<String, Value>, format: BodyFormat) -> u64 {
    page.iter().fold(0u64, |sum, (key, value)| {
        let unshown = match (key.as_str(), value) {
            ("title", Value::String(_)) => 0,
            ("id", v) if short_string(v) => 0,
            ("space", Value::Object(space)) => {
                unshown_in(space, &|k, v| matches!(k, "name" | "key") && v.is_string())
            }
            ("version", Value::Object(version)) => {
                unshown_in(version, &|k, v| k == "number" && v.is_u64())
            }
            ("ancestors", Value::Array(list)) => list.iter().fold(0u64, |sum, a| {
                sum.saturating_add(match a {
                    Value::Object(o) => unshown_in(o, &|k, v| k == "title" && v.is_string()),
                    other => bytes_of(other),
                })
            }),
            ("body", Value::Object(body)) => body_unshown_bytes(body, format),
            _ => pair_bytes(key, value),
        };
        sum.saturating_add(unshown)
    })
}

fn body_unshown_bytes(body: &Map<String, Value>, format: BodyFormat) -> u64 {
    let container = match format {
        BodyFormat::Markdown => {
            return unshown_in(body, &|k, v| {
                matches!(k, "format" | "value") && v.is_string()
            });
        }
        BodyFormat::Storage => "storage",
        BodyFormat::View => "view",
    };
    body.iter().fold(0u64, |sum, (k, v)| {
        sum.saturating_add(match v {
            Value::Object(o) if k == container => {
                unshown_in(o, &|k, v| k == "value" && v.is_string())
            }
            _ => pair_bytes(k, v),
        })
    })
}

// ---- comments (§6.3 "Confluence comments", PD-103) ---------------------------------------------

/// §6.3 "Confluence comments" (PD-103): the comments of `confluence.comment.list` as a thread.
/// Each storage body is rendered locally (empty user map); a comment is placed under the last
/// entry of its `ancestors` (its parent) when that comment is in the list, else at the top level;
/// the thread is emitted depth-first, so the renderer can nest by `depth` and order alone (T8
/// review m-6). `location` is `extensions.location` as sent (the renderer says "location not
/// reported" without it). A candidate without a `results` list keeps the Fallback.
pub(crate) fn comments_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    comments_model(ctx).unwrap_or_else(|| generic::fallback_preview(ctx))
}

fn comments_model(ctx: &PreviewCtx<'_>) -> Option<PreviewModel> {
    let PreviewInput::Read(view) = &ctx.input else {
        return None;
    };
    let results = view.candidate.get("results")?.as_array()?;
    let mut hidden = other_root_bytes(Product::Confluence, view.candidate, Some("results"));
    hidden = results
        .iter()
        .filter(|c| !c.is_object())
        .fold(hidden, |sum, c| sum.saturating_add(bytes_of(c)));
    let comments: Vec<ConfluenceComment> = thread_order(results)
        .into_iter()
        .filter_map(|(i, depth)| {
            let comment = results.get(i)?.as_object()?;
            Some(comment_view(comment, depth, &mut hidden))
        })
        .collect();

    let (mut header, warnings) = generic::read_parts(ctx, view, hidden);
    let count = table_count(&mut header, results.len());
    let query = header.query.clone();
    Some(PreviewModel {
        header,
        body: PreviewBody::ConfluenceComments { comments, count },
        warnings,
        query,
    })
}

/// An id as text: a string as sent, a number in decimal.
fn id_text(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The parent comment's id: the last entry of `ancestors` (PD-103).
fn parent_id(comment: &Map<String, Value>) -> Option<String> {
    let last = comment.get("ancestors")?.as_array()?.last()?;
    id_text(last.get("id"))
}

/// The comments (object entries of `results`, by index) in thread order with their depth: each
/// top-level comment (no parent in the list) in list order, each followed depth-first by its
/// replies in list order. A comment whose parent chain never reaches the top level (a cycle in
/// the server's `ancestors`) starts a thread of its own where it first appears; every comment
/// is emitted exactly once.
fn thread_order(results: &[Value]) -> Vec<(usize, u32)> {
    let mut index: HashMap<String, usize> = HashMap::new();
    for (i, c) in results.iter().enumerate() {
        if let Some(id) = c.as_object().and_then(|o| id_text(o.get("id"))) {
            index.entry(id).or_insert(i);
        }
    }
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); results.len()];
    let mut roots: Vec<usize> = Vec::new();
    for (i, c) in results.iter().enumerate() {
        let Some(comment) = c.as_object() else {
            continue;
        };
        let parent = parent_id(comment)
            .and_then(|p| index.get(&p).copied())
            .filter(|&p| p != i);
        match parent.and_then(|p| children.get_mut(p)) {
            Some(siblings) => siblings.push(i),
            None => roots.push(i),
        }
    }

    let mut visited = vec![false; results.len()];
    let mut out: Vec<(usize, u32)> = Vec::with_capacity(results.len());
    let starts: Vec<usize> = roots
        .into_iter()
        .chain((0..results.len()).filter(|&i| results.get(i).is_some_and(Value::is_object)))
        .collect();
    for start in starts {
        let mut stack: Vec<(usize, u32)> = vec![(start, 0)];
        while let Some((i, depth)) = stack.pop() {
            match visited.get_mut(i) {
                Some(seen) if !*seen => *seen = true,
                _ => continue,
            }
            out.push((i, depth));
            if let Some(replies) = children.get(i) {
                stack.extend(replies.iter().rev().map(|&r| (r, depth.saturating_add(1))));
            }
        }
    }
    out
}

/// `displayName (username)`; whichever of the two exists alone; `None` for no user object.
fn person(user: Option<&Value>) -> Option<String> {
    let user = user?.as_object()?;
    match (
        text_of(user.get("displayName")),
        text_of(user.get("username")),
    ) {
        (Some(display), Some(name)) => Some(format!("{display} ({name})")),
        (Some(one), None) | (None, Some(one)) => Some(one),
        (None, None) => None,
    }
}

/// One comment of the thread; what it does not show is added to `hidden`.
fn comment_view(comment: &Map<String, Value>, depth: u32, hidden: &mut u64) -> ConfluenceComment {
    let history = comment.get("history");
    let storage = comment
        .get("body")
        .and_then(|b| b.get("storage"))
        .and_then(|s| s.get("value"))
        .and_then(Value::as_str);
    let body_html = storage.map_or_else(String::new, |s| {
        render_storage(s, COMMENT_MARKDOWN_BUDGET, COMMENT_BODY_CAP, None, hidden).0
    });
    *hidden = hidden.saturating_add(comment_unshown_bytes(comment));
    ConfluenceComment {
        id: id_text(comment.get("id"))
            .map(|id| escape_for_display(&id))
            .unwrap_or_default(),
        author: person(history.and_then(|h| h.get("createdBy"))),
        created: text_of(history.and_then(|h| h.get("createdDate"))),
        location: text_of(comment.get("extensions").and_then(|e| e.get("location"))),
        depth,
        parent_id: parent_id(comment).map(|p| escape_for_display(&p)),
        body_html,
    }
}

/// The bytes of a comment its view does not show: every member but a short `id`, the storage
/// text, the author's display and user names, the creation date and the location. `ancestors`
/// (the thread places the comment, its entries are not shown) counts in full.
fn comment_unshown_bytes(comment: &Map<String, Value>) -> u64 {
    comment.iter().fold(0u64, |sum, (key, value)| {
        let unshown = match (key.as_str(), value) {
            ("id", v) if short_string(v) || v.is_number() => 0,
            ("body", Value::Object(body)) => body.iter().fold(0u64, |sum, (k, v)| {
                sum.saturating_add(match v {
                    Value::Object(o) if k == "storage" => {
                        unshown_in(o, &|k, v| k == "value" && v.is_string())
                    }
                    _ => pair_bytes(k, v),
                })
            }),
            ("history", Value::Object(history)) => history.iter().fold(0u64, |sum, (k, v)| {
                sum.saturating_add(match (k.as_str(), v) {
                    ("createdDate", Value::String(_)) => 0,
                    ("createdBy", Value::Object(user)) => unshown_in(user, &|k, v| {
                        matches!(k, "displayName" | "username") && v.is_string()
                    }),
                    _ => pair_bytes(k, v),
                })
            }),
            ("extensions", Value::Object(ext)) => {
                unshown_in(ext, &|k, v| k == "location" && v.is_string())
            }
            _ => pair_bytes(key, value),
        };
        sum.saturating_add(unshown)
    })
}
