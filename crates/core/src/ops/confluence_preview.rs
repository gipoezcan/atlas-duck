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
//!
//! Server markup released verbatim (`format=storage`, `format=view`, comment bodies) reaches the
//! agent whole, while the local render drops parts of it (comments, script and style content,
//! attributes): those bytes count as hidden and raise the Info `source_formatting_removed`
//! (T12b review I-1, m-1; [`dropped_markup`]).

use std::collections::HashMap;

use atlas_duck_atlassian::HttpRequestSpec;
use atlas_duck_convert::storage::KNOWN_MACROS;
use atlas_duck_convert::{
    ConversionReport, LostCounts, MarkdownTooLarge, UserResolutions, lossy_update,
    markdown_to_preview_html, storage_constructs, storage_lines, storage_to_markdown_within,
};
use atlas_duck_preview::diff::{DiffLine, DiffOp, LineDiff, hunks, line_diff, line_diff_lines};
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::render::DOC_MAX_ROWS;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_preview::{
    ConfluenceComment, ConstructList, ConversionFacts, PreviewBody, sanitize_html,
};
use atlas_duck_registry::Product;
use serde_json::{Map, Value};

use super::confluence::{
    BodyFormat, PAGE_BODY_LIMIT, TEXT_CURRENT_UNPARSABLE, TEXT_PAGE_TOO_LARGE, body_format,
};
use super::confluence_body::is_markdown;
use super::confluence_ext::TEXT_MOVE_INTO_OWN_SUBTREE;
use super::generic::{
    TABLE_ROW_CAP, bytes_of, cell_of, cut_at, omitted_row, other_root_bytes, pair_bytes,
    short_string, table_count,
};
use super::jira_preview::{DiffView, count_card_text};
use super::{ConfluenceFacts, PreviewCtx, PreviewInput, PreviewModel, WriteView, generic};
use crate::lifecycle::model::Hold;
use crate::metadata::one_line;

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
/// is not a page, an upstream answer) keeps the Fallback; a `view` read whose `body.view` is
/// there without text keeps the Caution on it (T12b review m-5).
pub(crate) fn page_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    page_model(ctx).unwrap_or_else(|| {
        let mut model = generic::fallback_preview(ctx);
        if has_view_body(ctx) {
            model.warnings.push(view_caution());
        }
        model
    })
}

/// A `view` read whose candidate has a `body.view` member.
fn has_view_body(ctx: &PreviewCtx<'_>) -> bool {
    let PreviewInput::Read(view) = &ctx.input else {
        return false;
    };
    matches!(
        body_format(ctx.spec, ctx.params),
        Some((BodyFormat::View, _))
    ) && view
        .candidate
        .get("body")
        .and_then(|b| b.get("view"))
        .is_some()
}

fn view_caution() -> Warning {
    Warning::new(
        WarningId::ServerRenderedView,
        warning::TEXT_SERVER_RENDERED_VIEW,
    )
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
                info_warnings(r, &mut warnings_after);
            }
            (
                "markdown",
                render_markdown(markdown, PAGE_BODY_CAP, &mut hidden),
                report.map(facts),
            )
        }
        BodyFormat::Storage => {
            let storage = text("storage")?;
            let (html, notes) = render_storage(
                storage,
                STORAGE_MARKDOWN_BUDGET,
                PAGE_BODY_CAP,
                Some(STORAGE_RENDERED_LABEL),
                &mut hidden,
            );
            // Mentions are not looked up for storage (PD-99): `unresolved_mention` is the
            // Markdown release's alone.
            notes.push(&mut warnings_after);
            ("storage", html, None)
        }
        BodyFormat::View => {
            let html = text("view")?;
            let (kept, cut) = cut_at(html, PAGE_BODY_CAP);
            // What the sanitizer drops of the kept part; the cut part counts whole.
            let dropped = dropped_markup(kept, Markup::View);
            hidden = hidden.saturating_add(dropped.bytes);
            let mut shown = sanitize_html(kept);
            if cut > 0 {
                hidden = hidden.saturating_add(cut);
                shown.push_str(&more_bytes(cut));
            }
            warnings_after.push(view_caution());
            BodyNotes {
                unknown_macros: false,
                stripped: dropped.stripped(),
            }
            .push(&mut warnings_after);
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

/// The Info warnings the Markdown release's conversion report implies (§6.2): `unknown_macros`
/// when it names any, `unresolved_mention` when a mention stayed a key.
fn info_warnings(report: &ConversionReport, warnings: &mut Vec<Warning>) {
    BodyNotes {
        unknown_macros: !report.unknown_macros.is_empty(),
        stripped: false,
    }
    .push(warnings);
    if report.unresolved_users > 0 {
        warnings.push(Warning::new(
            WarningId::UnresolvedMention,
            warning::TEXT_UNRESOLVED_MENTION,
        ));
    }
}

/// The §6.2 Info facts of server markup the card renders locally (a storage or `view` body, a
/// comment thread); each raises its Info once.
#[derive(Clone, Copy, Default)]
struct BodyNotes {
    /// The body names a macro the converter does not know: `unknown_macros`.
    unknown_macros: bool,
    /// The render left out markup the agent receives, or styling it does not apply
    /// ([`Dropped::stripped`]): `source_formatting_removed`.
    stripped: bool,
}

impl BodyNotes {
    fn merge(&mut self, other: BodyNotes) {
        self.unknown_macros |= other.unknown_macros;
        self.stripped |= other.stripped;
    }

    fn push(self, warnings: &mut Vec<Warning>) {
        if self.unknown_macros {
            warnings.push(Warning::new(
                WarningId::UnknownMacros,
                warning::TEXT_UNKNOWN_MACROS,
            ));
        }
        if self.stripped {
            warnings.push(Warning::new(
                WarningId::SourceFormattingRemoved,
                warning::TEXT_SOURCE_FORMATTING_REMOVED,
            ));
        }
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
/// `budget` bytes of Markdown, then as [`render_markdown`] with `cap`, after `label` when given;
/// what the conversion drops of the storage counts as hidden ([`dropped_markup`]). A storage
/// whose Markdown passes the budget is not rendered (its bytes count as hidden); its macros
/// still come from its construct inventory (T12b review m-3).
fn render_storage(
    storage: &str,
    budget: usize,
    cap: usize,
    label: Option<&str>,
    hidden: &mut u64,
) -> (String, BodyNotes) {
    let mut html = label.map_or_else(String::new, |l| format!("<p><strong>{l}</strong></p>"));
    let empty = UserResolutions::new();
    match storage_to_markdown_within(storage, &empty, budget) {
        Ok((markdown, report, _)) => {
            let dropped = dropped_markup(storage, Markup::Storage);
            *hidden = hidden.saturating_add(dropped.bytes);
            html.push_str(&render_markdown(&markdown, cap, hidden));
            let notes = BodyNotes {
                unknown_macros: !report.unknown_macros.is_empty(),
                stripped: dropped.stripped(),
            };
            (html, notes)
        }
        Err(MarkdownTooLarge) => {
            *hidden = hidden.saturating_add(len_u64(storage.len()));
            html.push_str(&not_rendered(storage.len()));
            let notes = BodyNotes {
                unknown_macros: names_unknown_macros(storage),
                stripped: false,
            };
            (html, notes)
        }
    }
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn not_rendered(bytes: usize) -> String {
    format!("<p>… {bytes} bytes not rendered here (see Raw)</p>")
}

/// `ac:` elements the converter writes as a placeholder (or as their content) without listing
/// them in `unknown_macros` (`convert::storage::to_md` `AC_QUIET`, `AC_MARKERS`).
const QUIET_AC: [&str; 3] = ["emoticon", "placeholder", "inline-comment-marker"];

/// Whether `storage` names a macro the converter would list in `unknown_macros`, read from its
/// construct inventory (no Markdown is built): an include, a macro outside
/// [`KNOWN_MACROS`], any other non-structural `ac:` element but [`QUIET_AC`], a foreign
/// element. It may over-report (an old `ac:macro` is listed by its element name), never misses
/// a structured macro.
fn names_unknown_macros(storage: &str) -> bool {
    let constructs = storage_constructs(storage);
    !constructs.includes.is_empty()
        || constructs.macros.iter().any(|name| {
            !KNOWN_MACROS
                .iter()
                .chain(QUIET_AC.iter())
                .any(|k| k.eq_ignore_ascii_case(name))
        })
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
/// reported" without it). The thread raises `unknown_macros` and `source_formatting_removed`
/// once each when any rendered body does (T12b review m-1, m-2). A candidate without a
/// `results` list keeps the Fallback.
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
    let mut notes = BodyNotes::default();
    // The renderer shows the first `DOC_MAX_ROWS` comments of the thread: only their bodies
    // are rendered here (T12b review m-7); the bodies of the rest count as hidden.
    let comments: Vec<ConfluenceComment> = thread_order(results)
        .into_iter()
        .enumerate()
        .filter_map(|(n, (i, depth))| {
            let comment = results.get(i)?.as_object()?;
            let render = n < DOC_MAX_ROWS;
            Some(comment_view(
                comment,
                depth,
                render,
                &mut hidden,
                &mut notes,
            ))
        })
        .collect();

    let (mut header, mut warnings) = generic::read_parts(ctx, view, hidden);
    notes.push(&mut warnings);
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
/// replies in list order. The comments whose parent chain never reaches the top level (a cycle
/// in the server's `ancestors`) follow after the top-level threads, in list order, each
/// starting a thread of its own unless an earlier one took it in; every comment is emitted
/// exactly once.
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

/// One comment of the thread; what it does not show is added to `hidden`, its body's Info facts
/// to `notes`. Without `render` the body is left out (empty) and its storage counts as hidden.
fn comment_view(
    comment: &Map<String, Value>,
    depth: u32,
    render: bool,
    hidden: &mut u64,
    notes: &mut BodyNotes,
) -> ConfluenceComment {
    let history = comment.get("history");
    let storage = comment
        .get("body")
        .and_then(|b| b.get("storage"))
        .and_then(|s| s.get("value"))
        .and_then(Value::as_str);
    let body_html = match storage {
        Some(s) if render => {
            let (html, body_notes) =
                render_storage(s, COMMENT_MARKDOWN_BUDGET, COMMENT_BODY_CAP, None, hidden);
            notes.merge(body_notes);
            html
        }
        Some(s) => {
            *hidden = hidden.saturating_add(len_u64(s.len()));
            String::new()
        }
        None => String::new(),
    };
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
/// (the thread places the comment, its entries are not shown) counts in full. What the render
/// drops of the storage text is counted where it is rendered ([`render_storage`]).
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

// ---- the update card (§6.3 Edit/update and Conflict, PD-104, Task 15) ---------------------------

/// M7 Δ2 / PD-104: every Markdown projection of the update card converts within this many bytes
/// (the host-call default, `max_call_result_mb` 16): `DIFF_MAX_LINES` caps after the conversion
/// and does not bound its allocation (T10 review). A side past it is not projected: the rendered
/// diff leaves it out (counted, `diff_truncated`) and the raw diff shows it. The judge keeps no
/// server body of more storage bytes (T15 review I-1): the same number, but this one bounds the
/// Markdown a projection writes, so a side past it stays possible (an outgoing body, a projection
/// longer than its storage).
const UPDATE_MARKDOWN_BUDGET: usize = PAGE_BODY_LIMIT;

/// §6.3 Edit/update and Conflict for `confluence.page.update` (PD-104), over the exact request
/// (§5.1 inv. 4; the outgoing storage is read from the request that is sent, never from the
/// params) and the bodies enrichment read ([`ConfluenceFacts`]):
/// - `Preview`: the rendered diff of the Markdown projections (empty user map: mentions as
///   keys) and the raw diff of `storage_lines` of the current and the sent storage, raw-only
///   changes `max(0, raw hunks − rendered hunks)` with the Caution `raw_only_diff`, the outgoing
///   storage constructs (§7.6, T9 review I-2), and for a Markdown update the Caution
///   `lossy_update` (`convert::lossy_update`);
/// - `Conflict`: the rendered diffs base → current and base → sent (M6 T10 review M-5); what
///   their projections leave out of the base and current server bodies counts as hidden
///   (T12b rules, Info `source_formatting_removed`), since the card has no raw view of them;
/// - the judge's `EnrichmentError` over an unparsable current body: the PD-94 plan text; over a
///   body past the diff budget: [`TEXT_PAGE_TOO_LARGE`] (T15 review I-1).
///
/// A title the request changes heads both diffs of the edit card with a `title` section, then a
/// `body` section (T15 review m-5). The invisible characters of the server text the card shows
/// count into the §6.4 header. Every other hold, or a request that is not the update JSON, keeps
/// the generic write preview.
pub(crate) fn update_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    update_preview_within(ctx, UPDATE_MARKDOWN_BUDGET)
}

/// [`update_preview`] with the Markdown projections held to `budget` bytes (T15 review m-1: the
/// tests reach the over-budget path with small bodies).
pub(crate) fn update_preview_within(ctx: &PreviewCtx<'_>, budget: usize) -> PreviewModel {
    let mut model = generic::write_preview(ctx);
    let PreviewInput::Write(view) = &ctx.input else {
        return model;
    };
    let Some(facts) = view
        .enrichment
        .and_then(|v| v.summary.as_ref())
        .and_then(|s| s.confluence.as_ref())
    else {
        return model;
    };
    match view.hold {
        Hold::EnrichmentError if view.failure.is_none() && facts.page_too_large => {
            model.body = PreviewBody::enrichment_error(None, TEXT_PAGE_TOO_LARGE, None);
            model
        }
        Hold::EnrichmentError if view.failure.is_none() && facts.current_unparsable => {
            model.body = PreviewBody::enrichment_error(None, TEXT_CURRENT_UNPARSABLE, None);
            model
        }
        Hold::Conflict => conflict_card(model, view, facts, budget),
        Hold::Preview => edit_card(ctx, model, view, facts, budget),
        _ => model,
    }
}

/// The JSON body of the first request (the one `PUT`), as sent.
fn sent_json(requests: &[HttpRequestSpec]) -> Option<Value> {
    serde_json::from_slice(&requests.first()?.body).ok()
}

/// `body.storage.value` of a sent update body.
fn storage_in(body: &Value) -> Option<&str> {
    body.get("body")?.get("storage")?.get("value")?.as_str()
}

/// `body.storage.value` of the first request (the one `PUT`), as sent.
fn sent_storage(requests: &[HttpRequestSpec]) -> Option<String> {
    storage_in(&sent_json(requests)?).map(str::to_owned)
}

/// The Markdown projection the rendered diffs compare (empty user map, PD-104), or `None` past
/// `budget` ([`UPDATE_MARKDOWN_BUDGET`]).
fn projection(storage: &str, budget: usize) -> Option<String> {
    storage_to_markdown_within(storage, &UserResolutions::new(), budget)
        .ok()
        .map(|(markdown, _, _)| markdown)
}

/// The rendered diff of `old` against `new` into `view`, display-escaped and capped; its hunks.
/// A side past the budget is left out whole: both texts count as cut.
fn rendered_into(view: &mut DiffView, old: &str, new: &str, budget: usize) -> u64 {
    match (projection(old, budget), projection(new, budget)) {
        (Some(o), Some(n)) => {
            let d = line_diff(&o, &n);
            view.extend(&d, &o, &n);
            hunks(&d.lines)
        }
        _ => {
            view.cut = view
                .cut
                .saturating_add(len_u64(old.len()))
                .saturating_add(len_u64(new.len()));
            0
        }
    }
}

/// §7.6: the storage constructs of the outgoing body, display-escaped, one line each.
fn storage_construct_list(storage: &str) -> ConstructList {
    let c = storage_constructs(storage);
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

/// T15 review m-5: the `title` section (the current title deleted, the sent one added) and the
/// heading of the `body` section after it, for a request that renames the page.
fn title_section(current: &str, sent: &str) -> LineDiff {
    let line = |op: DiffOp, text: &str| DiffLine {
        op,
        text: text.to_owned(),
    };
    LineDiff {
        lines: vec![
            line(DiffOp::Field, "title"),
            line(DiffOp::Del, current),
            line(DiffOp::Add, sent),
            line(DiffOp::Field, "body"),
        ],
        truncated: false,
    }
}

fn edit_card(
    ctx: &PreviewCtx<'_>,
    mut model: PreviewModel,
    view: &WriteView<'_>,
    facts: &ConfluenceFacts,
    budget: usize,
) -> PreviewModel {
    let sent = sent_json(view.requests);
    let (Some(current), Some(outgoing), PreviewBody::WriteRequests { .. }) = (
        facts.current_storage.as_deref(),
        sent.as_ref().and_then(storage_in),
        &model.body,
    ) else {
        return model;
    };
    // The title the request sends, against the one the page has (§5.1 inv. 4: never the params).
    let renamed = match (
        facts.page.as_ref(),
        sent.as_ref()
            .and_then(|b| b.get("title"))
            .and_then(Value::as_str),
    ) {
        (Some(page), Some(title)) if page.title != title => Some((page.title.as_str(), title)),
        _ => None,
    };
    let (mut rendered, mut raw) = (DiffView::new(), DiffView::new());
    if let Some((was, title)) = renamed {
        let section = title_section(was, title);
        rendered.extend(&section, "", "");
        raw.extend(&section, "", "");
    }
    let rendered_hunks = rendered_into(&mut rendered, current, outgoing, budget);
    let raw_diff = line_diff_lines(&storage_lines(current), &storage_lines(outgoing));
    raw.extend(&raw_diff, current, outgoing);
    let raw_only = hunks(&raw_diff.lines).saturating_sub(rendered_hunks);
    if raw_only > 0 {
        model.warnings.push(Warning::new(
            WarningId::RawOnlyDiff,
            warning::raw_only_diff(raw_only),
        ));
    }
    if is_markdown(ctx.params) {
        let lost = lossy_update(current, outgoing);
        if lost != LostCounts::default() {
            model.warnings.push(Warning::new(
                WarningId::LossyUpdate,
                warning::lossy_update(lost.macros, lost.images, lost.links, lost.layouts),
            ));
        }
    }
    let cut = raw.cut.max(rendered.cut);
    if cut > 0 {
        model.warnings.push(Warning::new(
            WarningId::DiffTruncated,
            warning::diff_truncated(cut),
        ));
    }
    // The raw diff shows every byte of both bodies (its cut aside); what their renders leave out
    // is not hidden, but it is formatting the rendered diff does not show (§6.4).
    let stripped = [current, outgoing]
        .iter()
        .any(|s| dropped_markup(s, Markup::Storage).stripped());
    BodyNotes {
        unknown_macros: false,
        stripped,
    }
    .push(&mut model.warnings);
    count_card_text(
        &mut model,
        [Some(current), renamed.map(|(was, _)| was)]
            .into_iter()
            .flatten(),
    );
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
        rendered: rendered.lines,
        raw: raw.lines,
        raw_only_changes: raw_only,
        constructs: Some(storage_construct_list(outgoing)),
        requests,
    };
    model.header.hidden_in_preview_bytes = model.header.hidden_in_preview_bytes.saturating_add(cut);
    model
}

fn conflict_card(
    mut model: PreviewModel,
    view: &WriteView<'_>,
    facts: &ConfluenceFacts,
    budget: usize,
) -> PreviewModel {
    let (Some(base), Some(current)) = (
        facts.base_storage.as_deref(),
        facts.current_storage.as_deref(),
    ) else {
        return model;
    };
    let mut to_current = DiffView::new();
    rendered_into(&mut to_current, base, current, budget);
    // The agent's intended change: from its base to what the request sends (none when the
    // request could not be built).
    let mut intended = DiffView::new();
    let outgoing = sent_storage(view.requests);
    if let Some(sent) = outgoing.as_deref() {
        rendered_into(&mut intended, base, sent, budget);
    }
    let cut = to_current.cut.max(intended.cut);
    if cut > 0 {
        model.warnings.push(Warning::new(
            WarningId::DiffTruncated,
            warning::diff_truncated(cut),
        ));
    }
    // No raw view of the server bodies on this card: what their projections leave out is hidden.
    let (base_dropped, current_dropped) = (
        dropped_markup(base, Markup::Storage),
        dropped_markup(current, Markup::Storage),
    );
    let sent_stripped = outgoing
        .as_deref()
        .is_some_and(|s| dropped_markup(s, Markup::Storage).stripped());
    BodyNotes {
        unknown_macros: false,
        stripped: base_dropped.stripped() || current_dropped.stripped() || sent_stripped,
    }
    .push(&mut model.warnings);
    count_card_text(&mut model, [base, current]);
    if let PreviewBody::Conflict {
        base_to_current,
        intended: shown_intended,
        ..
    } = &mut model.body
    {
        *base_to_current = to_current.lines;
        *shown_intended = intended.lines;
    }
    model.header.hidden_in_preview_bytes = model
        .header
        .hidden_in_preview_bytes
        .saturating_add(cut)
        .saturating_add(base_dropped.bytes)
        .saturating_add(current_dropped.bytes);
    model
}

// ---- what the local render drops (T12b review I-1, m-1) -----------------------------------------

/// Which parser reads the server markup the card renders.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Markup {
    /// Storage XHTML, read by the converter (`storage_to_markdown_within`).
    Storage,
    /// `view` HTML, read by `preview::sanitize_html` (an HTML parser).
    View,
}

/// What the local render of released server markup leaves out although the agent receives it.
#[derive(Default)]
struct Dropped {
    /// The bytes dropped: comments; every attribute the render does not show (in `view` the
    /// sanitizer's, in storage the converter's); in `view` also script and style element content.
    bytes: u64,
    /// Styling the render does not apply: a `style` attribute or a `<style>` element.
    styled: bool,
}

impl Dropped {
    /// The render stripped something: §6.2 / §6.4 Info `source_formatting_removed`.
    fn stripped(&self) -> bool {
        self.bytes > 0 || self.styled
    }

    fn add(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_add(len_u64(bytes));
    }
}

/// What the local render of `markup` drops, read lexically (as `convert::storage_lines` reads
/// storage), so it works on any input, parsable or not:
/// - a comment `<!--…-->`; unterminated, it runs to the end in `view` (HTML), while in storage
///   it is not XML and the converter's fallback shows it as text;
/// - in storage a CDATA section is text the converter keeps (a code body): nothing inside it
///   counts;
/// - in `view`: any other `<!…>` or `<?…>` (HTML reads them as comments); the content of a
///   `<script>` or `<style>` element up to its end tag (or the end); every attribute
///   `sanitize_html` does not keep ([`view_keeps`]), from its name to the end of its value.
///
/// In storage every attribute the converter does not write into the card counts too, from its
/// name to the end of its value ([`storage_surfaces`] lists the ones it shows), since the agent
/// receives the storage verbatim: `<p title="x">` counts `title="x"`. A storage `style` attribute
/// or `<style>` element also sets `styled`. Pure; never panics.
fn dropped_markup(markup: &str, kind: Markup) -> Dropped {
    let mut out = Dropped::default();
    let mut i = 0;
    while let Some(off) = markup.get(i..).and_then(|r| r.find('<')) {
        let at = i + off;
        let tail = markup.get(at..).unwrap_or("");
        i = at + 1;
        if let Some(after) = tail.strip_prefix("<!--") {
            match after.find("-->") {
                Some(end) => {
                    let len = "<!--".len() + end + "-->".len();
                    out.add(len);
                    i = at + len;
                }
                None if kind == Markup::View => {
                    out.add(tail.len());
                    i = markup.len();
                }
                None => {}
            }
        } else if kind == Markup::Storage
            && let Some(after) = tail.strip_prefix("<![CDATA[")
        {
            i = after.find("]]>").map_or(markup.len(), |end| {
                at + "<![CDATA[".len() + end + "]]>".len()
            });
        } else if kind == Markup::View && (tail.starts_with("<!") || tail.starts_with("<?")) {
            let len = tail.find('>').map_or(tail.len(), |end| end + 1);
            out.add(len);
            i = at + len;
        } else if tail.as_bytes().get(1).is_some_and(u8::is_ascii_alphabetic) {
            let (name, attrs, len) = start_tag(tail);
            for (attr, value, bytes) in attrs {
                out.styled |= attr.eq_ignore_ascii_case("style");
                let surfaced = match kind {
                    Markup::View => view_keeps(name, attr, value),
                    Markup::Storage => storage_surfaces(name, attr),
                };
                if !surfaced {
                    out.add(bytes);
                }
            }
            i = at + len;
            out.styled |= name.eq_ignore_ascii_case("style");
            let raw_text =
                name.eq_ignore_ascii_case("script") || name.eq_ignore_ascii_case("style");
            if kind == Markup::View && raw_text {
                let rest = markup.get(i..).unwrap_or("");
                let (content, skip) = end_tag(rest, name).unwrap_or((rest.len(), rest.len()));
                out.add(content);
                i += skip;
            }
        }
    }
    out
}

/// The start tag at the start of `tail` (`<` and a letter): its name, its attributes as
/// `(name, raw value, bytes)` (from the name to the end of the value, quotes included; an
/// unterminated quoted value runs to the end), and its length up to and with the `>` that ends
/// it outside a quoted value (all of `tail` when none does). ASCII whitespace separates, as in
/// HTML; a `/` between attributes is skipped.
fn start_tag(tail: &str) -> (&str, Vec<(&str, &str, usize)>, usize) {
    let space = |c: char| c.is_ascii_whitespace();
    let rest_at = |p: usize| tail.get(p..).unwrap_or("");
    let body = rest_at(1);
    let name_len = body
        .find(|c: char| space(c) || matches!(c, '/' | '>'))
        .unwrap_or(body.len());
    let name = body.get(..name_len).unwrap_or("");
    let mut attrs = Vec::new();
    let mut p = 1 + name_len;
    loop {
        let rest = rest_at(p);
        p += rest.len()
            - rest
                .trim_start_matches(|c: char| space(c) || c == '/')
                .len();
        let rest = rest_at(p);
        if rest.is_empty() {
            return (name, attrs, tail.len());
        }
        if rest.starts_with('>') {
            return (name, attrs, p + 1);
        }
        let start = p;
        // An attribute name may start with `=` in HTML: always take one character.
        let first = rest.chars().next().map_or(1, char::len_utf8);
        let name_len = rest
            .get(first..)
            .and_then(|r| r.find(|c: char| space(c) || matches!(c, '=' | '>' | '/')))
            .map_or(rest.len(), |n| first + n);
        let attr = rest.get(..name_len).unwrap_or("");
        p += name_len;
        let after = rest_at(p);
        let gap = after.len() - after.trim_start_matches(space).len();
        if !after.get(gap..).unwrap_or("").starts_with('=') {
            attrs.push((attr, "", name_len));
            continue;
        }
        p += gap + 1;
        let after = rest_at(p);
        p += after.len() - after.trim_start_matches(space).len();
        let value = rest_at(p);
        let (raw, len) = match value.chars().next() {
            Some(quote @ ('"' | '\'')) => {
                let inner = value.get(1..).unwrap_or("");
                match inner.find(quote) {
                    Some(end) => (inner.get(..end).unwrap_or(""), end + 2),
                    None => (inner, value.len()),
                }
            }
            _ => {
                let end = value
                    .find(|c: char| space(c) || c == '>')
                    .unwrap_or(value.len());
                (value.get(..end).unwrap_or(""), end)
            }
        };
        p += len;
        attrs.push((attr, raw, p - start));
    }
}

/// Where the raw text of a `name` element in `rest` ends: the bytes before its end tag
/// (`</name` followed by whitespace, `/`, `>` or the end, ASCII case-insensitive), and the
/// bytes up to and with that tag's `>` (or the end).
fn end_tag(rest: &str, name: &str) -> Option<(usize, usize)> {
    rest.match_indices("</").find_map(|(j, _)| {
        let after = rest.get(j + 2..)?;
        let named = after.get(..name.len())?.eq_ignore_ascii_case(name);
        let ends = after
            .get(name.len()..)?
            .chars()
            .next()
            .is_none_or(|c| c.is_ascii_whitespace() || matches!(c, '/' | '>'));
        (named && ends).then(|| {
            let close = rest.get(j..).and_then(|r| r.find('>'));
            (j, close.map_or(rest.len(), |c| j + c + 1))
        })
    })
}

/// The attributes `preview::sanitize_html` keeps (or shows: a link's URL becomes text), by
/// element: `img` `alt` and an inline raster `src`, `td`/`th` `colspan`/`rowspan`, `ol` `start`,
/// `a` `href`. Names compare ASCII case-insensitively.
fn view_keeps(tag: &str, attr: &str, value: &str) -> bool {
    let tag = tag.to_ascii_lowercase();
    let attr = attr.to_ascii_lowercase();
    match (tag.as_str(), attr.as_str()) {
        ("img", "alt") | ("td" | "th", "colspan" | "rowspan") | ("ol", "start") | ("a", "href") => {
            true
        }
        ("img", "src") => inline_raster(value),
        _ => false,
    }
}

/// The storage attributes whose value the converter writes into the card (`convert::storage`
/// `to_md.rs`): `a href`, `img src` and `img alt`; `ac:name` (a macro's name, a parameter's key);
/// `ac:anchor` of a link; `time datetime` (a date lozenge's date); on an `ri:` element the
/// attribute its target text is built from (`ri:userkey`, `ri:username`, `ri:space-key`,
/// `ri:content-title`, `ri:filename`, `ri:value`, `ri:content-id`). Names compare exactly (XML).
/// Every other attribute (`title`, `class`, `style`, `data-*`, `ac:macro-id`, any other `href` or
/// `alt`, ...) reaches the agent in the storage and not the card.
fn storage_surfaces(tag: &str, attr: &str) -> bool {
    match (tag, attr) {
        ("a", "href") | ("img", "src" | "alt") | ("time", "datetime") => true,
        (_, "ac:name" | "ac:anchor") => true,
        (t, a) if t.starts_with("ri:") => matches!(
            a,
            "ri:userkey"
                | "ri:username"
                | "ri:space-key"
                | "ri:content-title"
                | "ri:filename"
                | "ri:value"
                | "ri:content-id"
        ),
        _ => false,
    }
}

/// `preview::sanitize_html`'s image rule: only a `data:image/{png,jpeg,gif,webp};base64,`
/// source survives (compared on the raw value, so an entity-encoded one counts as dropped).
fn inline_raster(src: &str) -> bool {
    let src = src.trim_start();
    ["png", "jpeg", "gif", "webp"].iter().any(|t| {
        let prefix = format!("data:image/{t};base64,");
        src.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(&prefix))
    })
}

// ---- the comment card (§6.3 add comment, PD-107, Task 18) --------------------------------------

/// §6.3 add comment for `confluence.comment.add` (PD-107) over the exact request (§5.1 inv. 4):
/// a sentence naming the content and the reply, the facts enrichment read (container, space,
/// reply target), the outgoing storage rendered locally (read from the request that is sent, never
/// from the params; what the render leaves out of the storage the agent sends counts as hidden and
/// raises `source_formatting_removed`, T12b rules) and the storage constructs of that body
/// (§7.6). Every other hold, or a request that is not the comment JSON, keeps the generic write
/// preview.
pub(crate) fn comment_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let mut model = generic::write_preview(ctx);
    let PreviewInput::Write(view) = &ctx.input else {
        return model;
    };
    let facts = view
        .enrichment
        .filter(|v| v.hold == Hold::Preview)
        .and_then(|v| v.summary.as_ref())
        .and_then(|s| s.confluence.as_ref());
    let (Some(facts), Some(storage), PreviewBody::WriteRequests { .. }) =
        (facts, sent_storage(view.requests), &model.body)
    else {
        return model;
    };
    let mut hidden = 0u64;
    let (body_html, notes) = render_storage(
        &storage,
        COMMENT_MARKDOWN_BUDGET,
        COMMENT_BODY_CAP,
        None,
        &mut hidden,
    );
    notes.push(&mut model.warnings);

    let mut cut = 0u64;
    let mut line = |raw: &str| {
        let (shown, bytes) = generic::capped_text(raw, generic::CELL_CAP_CHARS * 2);
        cut = cut.saturating_add(bytes);
        shown
    };
    let kind = facts.container_type.as_deref().unwrap_or("content");
    let (id, title) = facts
        .page
        .as_ref()
        .map_or(("", ""), |p| (p.id.as_str(), p.title.as_str()));
    let reply = ctx.params.get("reply_to").and_then(Value::as_str);
    let on = format!("the {kind} \"{title}\"");
    let sentence = match reply {
        Some(reply) => line(&format!("Add a reply to comment {reply} on {on}")),
        None => line(&format!("Add a comment to {on}")),
    };
    let mut rows = vec![("Content".to_owned(), line(&format!("{kind} {id}")))];
    let space = match (facts.space_name.as_deref(), facts.space_key.as_str()) {
        (Some(name), "") => Some(name.to_owned()),
        (Some(name), key) => Some(format!("{name} ({key})")),
        (None, "") => None,
        (None, key) => Some(key.to_owned()),
    };
    if let Some(space) = space {
        rows.push(("Space".to_owned(), line(&space)));
    }
    if let Some(reply) = reply {
        rows.push(("Reply to".to_owned(), line(&format!("comment {reply}"))));
    }
    count_card_text(
        &mut model,
        [
            title,
            facts.space_key.as_str(),
            facts.space_name.as_deref().unwrap_or(""),
        ],
    );

    let requests = match std::mem::replace(
        &mut model.body,
        PreviewBody::WriteRequests {
            requests: Vec::new(),
        },
    ) {
        PreviewBody::WriteRequests { requests } => requests,
        _ => Vec::new(),
    };
    model.body = PreviewBody::ContentWrite {
        sentence,
        rows,
        body_html: Some(body_html),
        constructs: Some(storage_construct_list(&storage)),
        requests,
    };
    model.header.hidden_in_preview_bytes = model
        .header
        .hidden_in_preview_bytes
        .saturating_add(hidden)
        .saturating_add(cut);
    model
}

// ---- the create card (§6.3 Create, PD-105, Task 16) --------------------------------------------

/// §6.3 Create for `confluence.page.create` (PD-105) over the exact request (§5.1 inv. 4): the
/// sentence "Create page '<title>' in <space name> (<KEY>) under '<parent title>'" (the title,
/// the space key and the parent id read from the request that is sent, the names from what
/// enrichment resolved for them), rows for the space, the parent and its path, the outgoing
/// storage rendered locally (what the render leaves out of it counts as hidden and raises
/// `source_formatting_removed`, T12b rules) and its storage constructs (§7.6). The
/// duplicate-title Caution comes with the verdict. Every other hold, or a request that is not the
/// create JSON, keeps the generic write preview.
pub(crate) fn create_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let mut model = generic::write_preview(ctx);
    let PreviewInput::Write(view) = &ctx.input else {
        return model;
    };
    let facts = view
        .enrichment
        .filter(|v| v.hold == Hold::Preview)
        .and_then(|v| v.summary.as_ref())
        .and_then(|s| s.confluence.as_ref());
    let sent: Option<Value> = view
        .requests
        .first()
        .and_then(|r| serde_json::from_slice(&r.body).ok());
    let (Some(facts), Some(sent), PreviewBody::WriteRequests { .. }) = (facts, sent, &model.body)
    else {
        return model;
    };
    let (Some(title), Some(key), Some(storage)) = (
        sent.get("title").and_then(Value::as_str),
        sent.pointer("/space/key").and_then(Value::as_str),
        sent.pointer("/body/storage/value").and_then(Value::as_str),
    ) else {
        return model;
    };
    // The parent the request sends, named only when it is the one enrichment resolved.
    let sent_parent = sent.pointer("/ancestors/0/id").and_then(Value::as_str);
    let parent = facts
        .parent
        .as_ref()
        .filter(|p| sent_parent == Some(p.id.as_str()));
    if sent_parent.is_some() && parent.is_none() {
        return model;
    }
    // The space name is shown only for the key it was resolved for (the executor sends the
    // server's spelling, so they are equal), and the card says "page" only for a page.
    if facts.space_key != key || sent.get("type").and_then(Value::as_str) != Some("page") {
        return model;
    }

    let mut hidden = 0u64;
    let (body_html, notes) = render_storage(
        storage,
        STORAGE_MARKDOWN_BUDGET,
        PAGE_BODY_CAP,
        None,
        &mut hidden,
    );
    notes.push(&mut model.warnings);

    let mut cut = 0u64;
    let mut line = |raw: &str| {
        let (shown, bytes) = generic::capped_text(raw, generic::CELL_CAP_CHARS * 2);
        cut = cut.saturating_add(bytes);
        shown
    };
    let space = match facts.space_name.as_deref() {
        Some(name) => format!("{name} ({key})"),
        None => key.to_owned(),
    };
    let mut sentence = format!("Create page '{title}' in {space}");
    if let Some(p) = parent {
        sentence.push_str(&format!(" under '{}'", p.title));
    }
    let sentence = line(&sentence);
    let mut rows = vec![("Space".to_owned(), line(&space))];
    if let Some(p) = parent {
        rows.push((
            "Parent".to_owned(),
            line(&format!("{} (page {})", p.title, p.id)),
        ));
        rows.push(("Path".to_owned(), line(&facts.to_path.join(" / "))));
    }
    // Server text the card shows beyond the request (§6.4 counts), each once: the space name and
    // the path (the parent's ancestors, then the parent).
    let shown = facts
        .space_name
        .iter()
        .chain(parent.map_or(&[][..], |_| facts.to_path.as_slice()))
        .map(String::as_str);
    count_card_text(&mut model, shown);

    let requests = match std::mem::replace(
        &mut model.body,
        PreviewBody::WriteRequests {
            requests: Vec::new(),
        },
    ) {
        PreviewBody::WriteRequests { requests } => requests,
        _ => Vec::new(),
    };
    model.body = PreviewBody::ContentWrite {
        sentence,
        rows,
        body_html: Some(body_html),
        constructs: Some(storage_construct_list(storage)),
        requests,
    };
    model.header.hidden_in_preview_bytes = model
        .header
        .hidden_in_preview_bytes
        .saturating_add(hidden)
        .saturating_add(cut);
    model
}

// ---- the label cards (§6.3 labels, PD-108, Task 19) --------------------------------------------

/// The label names the request sends: the `name` of each entry of an add's JSON array, or the
/// last (percent-decoded) path segment of a remove's URL. `None`: not a label request.
fn sent_labels(remove: bool, requests: &[HttpRequestSpec]) -> Option<Vec<String>> {
    let request = requests.first()?;
    if remove {
        let last = request.resolved_url.rsplit('/').next()?;
        let name = percent_encoding::percent_decode_str(last)
            .decode_utf8()
            .ok()?;
        return Some(vec![name.into_owned()]);
    }
    let body: Value = serde_json::from_slice(&request.body).ok()?;
    body.as_array()?
        .iter()
        .map(|e| e.get("name").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

/// §6.3 labels for `confluence.label.add` and `confluence.label.remove` (PD-108) over the exact
/// request (§5.1 inv. 4): a sentence naming the labels the request sends and the content's title,
/// the content, and a row for the labels the content already has (add) or does not have (remove).
/// Labels compare case-insensitively (Confluence folds label names to lower case); the sentence
/// and the request show them as sent. Every other hold, or a request that is not a label request,
/// keeps the generic write preview.
pub(crate) fn labels_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let mut model = generic::write_preview(ctx);
    let PreviewInput::Write(view) = &ctx.input else {
        return model;
    };
    let remove = ctx.spec.id == "confluence.label.remove";
    let facts = view
        .enrichment
        .filter(|v| v.hold == Hold::Preview)
        .and_then(|v| v.summary.as_ref())
        .and_then(|s| s.confluence.as_ref());
    let (Some(facts), Some(labels), PreviewBody::WriteRequests { .. }) =
        (facts, sent_labels(remove, view.requests), &model.body)
    else {
        return model;
    };
    let mut cut = 0u64;
    let mut line = |raw: &str| {
        let (shown, bytes) = generic::capped_text(raw, generic::CELL_CAP_CHARS * 2);
        cut = cut.saturating_add(bytes);
        shown
    };
    let (id, title) = facts
        .page
        .as_ref()
        .map_or(("", ""), |p| (p.id.as_str(), p.title.as_str()));
    let has = |label: &String| {
        facts
            .current_labels
            .iter()
            .any(|c| c.eq_ignore_ascii_case(label))
    };
    let listed = labels.join(", ");
    let noun = if labels.len() == 1 { "label" } else { "labels" };
    let sentence = line(&if remove {
        format!("Remove {noun} {listed} from '{title}'")
    } else {
        format!("Add {noun} {listed} to '{title}'")
    });
    let kind = facts.container_type.as_deref().unwrap_or("content");
    let mut rows = vec![("Content".to_owned(), line(&format!("{kind} {id}")))];
    // Add: the labels the content already has. Remove: the label the content does not have.
    let flagged: Vec<&str> = labels
        .iter()
        .filter(|l| has(l) != remove)
        .map(String::as_str)
        .collect();
    if !flagged.is_empty() {
        let name = if remove {
            "Not present"
        } else {
            "Already present"
        };
        rows.push((name.to_owned(), line(&flagged.join(", "))));
    }
    count_card_text(&mut model, [title]);

    let requests = match std::mem::replace(
        &mut model.body,
        PreviewBody::WriteRequests {
            requests: Vec::new(),
        },
    ) {
        PreviewBody::WriteRequests { requests } => requests,
        _ => Vec::new(),
    };
    model.body = PreviewBody::WriteSummary {
        sentence,
        rows,
        constructs: None,
        requests,
    };
    model.header.hidden_in_preview_bytes = model.header.hidden_in_preview_bytes.saturating_add(cut);
    model
}

// ---- the move card (§6.3 Page move, PD-106, Task 17) --------------------------------------------

/// The keys of the PD-106 move body, exactly: a request with any other key (a `body` above all,
/// which the card's fixed row says is not sent) keeps the generic card.
const MOVE_BODY_KEYS: [&str; 5] = ["id", "type", "title", "version", "ancestors"];

/// §6.3 Page move for `confluence.page.move` (PD-106) over the exact request (§5.1 inv. 4): the
/// page row "<title> (page <id>, version <current> → <sent>)", the old path (the page's ancestors,
/// then the page) and the new path (the parent's ancestors, the parent, then the page). The page,
/// its title, the version and the parent are read from the request that is sent; the names around
/// them are what enrichment resolved for exactly those, else the generic card stays. The renderer
/// adds the fixed row "body not sent; title and body kept by Confluence" (plan review m-14). The
/// judge's hold of a move under the page's own subtree shows the PD-106 text; every other hold
/// keeps the generic write preview.
pub(crate) fn move_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let mut model = generic::write_preview(ctx);
    let PreviewInput::Write(view) = &ctx.input else {
        return model;
    };
    let Some(verdict) = view.enrichment else {
        return model;
    };
    let Some(facts) = verdict.summary.as_ref().and_then(|s| s.confluence.as_ref()) else {
        return model;
    };
    match view.hold {
        Hold::EnrichmentError if view.failure.is_none() && facts.into_own_subtree => {
            model.body = PreviewBody::enrichment_error(None, TEXT_MOVE_INTO_OWN_SUBTREE, None);
            return model;
        }
        Hold::Preview if verdict.hold == Hold::Preview => {}
        _ => return model,
    }
    let ([request], PreviewBody::WriteRequests { .. }) = (view.requests, &model.body) else {
        return model;
    };
    let Ok(Value::Object(sent)) = serde_json::from_slice::<Value>(&request.body) else {
        return model;
    };
    let (Some(page), Some(parent)) = (facts.page.as_ref(), facts.parent.as_ref()) else {
        return model;
    };
    let text = |k: &str| sent.get(k).and_then(Value::as_str);
    let sent_parent = match sent
        .get("ancestors")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
    {
        Some([one]) => one.get("id").and_then(Value::as_str),
        _ => None,
    };
    let sent_version = sent
        .get("version")
        .and_then(|v| v.get("number"))
        .and_then(Value::as_u64);
    let current = verdict.baseline.get("version").and_then(Value::as_u64);
    let is_this_move = sent.len() == MOVE_BODY_KEYS.len()
        && MOVE_BODY_KEYS.iter().all(|k| sent.contains_key(*k))
        && text("id") == Some(page.id.as_str())
        && text("type") == Some("page")
        && text("title") == Some(page.title.as_str())
        && sent_parent == Some(parent.id.as_str());
    let (true, Some(current), Some(next)) = (is_this_move, current, sent_version) else {
        return model;
    };
    if current.checked_add(1) != Some(next) {
        return model;
    }

    let mut cut = 0u64;
    let mut line = |raw: &str| {
        let (shown, bytes) = generic::capped_text(raw, generic::CELL_CAP_CHARS * 2);
        cut = cut.saturating_add(bytes);
        shown
    };
    let title = page.title.as_str();
    let page_row = line(&format!(
        "{title} (page {}, version {current} → {next})",
        page.id
    ));
    let mut from_path = Vec::with_capacity(facts.from_path.len() + 1);
    for t in &facts.from_path {
        from_path.push(line(t));
    }
    from_path.push(line(title));
    let mut to_path = Vec::with_capacity(facts.to_path.len() + 1);
    for t in &facts.to_path {
        to_path.push(line(t));
    }
    to_path.push(line(title));
    // Server text the card shows beyond the request (§6.4 counts): the ancestors and the parent.
    count_card_text(
        &mut model,
        facts
            .from_path
            .iter()
            .chain(&facts.to_path)
            .map(String::as_str),
    );

    let requests = match std::mem::replace(
        &mut model.body,
        PreviewBody::WriteRequests {
            requests: Vec::new(),
        },
    ) {
        PreviewBody::WriteRequests { requests } => requests,
        _ => Vec::new(),
    };
    model.body = PreviewBody::PageMove {
        page: page_row,
        from_path,
        to_path,
        requests,
    };
    model.header.hidden_in_preview_bytes = model.header.hidden_in_preview_bytes.saturating_add(cut);
    model
}

// ---- the attachment card (§6.3 Attachment upload, PD-109, PD-110, Task 20b) -------------------

/// PD-110: a raster image of at most this many bytes gets a `data:` thumbnail. Its base64 (about
/// 2.7 MiB) fits the 4 MiB `DOC_MAX_BYTES` render cap together with the rest of the card.
const THUMBNAIL_MAX_BYTES: usize = 2 * 1024 * 1024;

/// plan text (PD-110, plan review m-9): the fact row of an active or mismatched extension.
pub const TEXT_EXTENSION_MISMATCH: &str = "extension and content type differ";

/// Extensions a browser renders or runs as active content when the file is served under them:
/// PD-110's `html`, `htm`, `svg`, `js` and their siblings (XHTML, server-side includes, SVGZ, ES
/// modules, XML with XSLT, MHTML archives).
const ACTIVE_EXTENSIONS: [&str; 14] = [
    "html", "htm", "xhtml", "xht", "shtml", "svg", "svgz", "js", "mjs", "xml", "xsl", "xslt",
    "mht", "mhtml",
];

/// The extensions that name each type `confluence_ext::sniff_mime` knows. A zip is also every
/// container format built on it (Office Open XML, OpenDocument, Java, EPUB), so an Office file
/// carries no fact row.
const TYPE_EXTENSIONS: [(&str, &[&str]); 6] = [
    ("image/png", &["png"]),
    ("image/jpeg", &["jpg", "jpeg", "jpe", "jfif"]),
    ("image/gif", &["gif"]),
    ("image/webp", &["webp"]),
    ("application/pdf", &["pdf"]),
    (
        "application/zip",
        &[
            "zip", "docx", "docm", "dotx", "xlsx", "xlsm", "xltx", "pptx", "pptm", "potx", "odt",
            "ods", "odp", "odg", "jar", "epub",
        ],
    ),
];

/// The fact row shows at most this many chars of the extension.
const EXTENSION_CAP_CHARS: usize = 32;

/// The comment shows at most this many chars (the schema's `maxLength`).
const COMMENT_CAP_CHARS: usize = 1000;

/// The file part's headers and the comment part's, exactly as `confluence_ext::multipart` writes
/// them (the boundary and the file name around them).
const FILE_PART_HEAD: &str = "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"";
const FILE_TYPE_HEAD: &str = "\"\r\nContent-Type: ";
const COMMENT_PART_HEAD: &str = "\r\nContent-Disposition: form-data; name=\"comment\"\r\n\
                                 Content-Type: text/plain; charset=utf-8\r\n\r\n";

/// The upload one request sends, read back from its multipart body.
struct SentUpload<'a> {
    filename: &'a str,
    mime: &'static str,
    content: &'a [u8],
    comment: Option<&'a str>,
}

/// The upload `request` sends when its body is exactly the layout `confluence_ext::multipart`
/// writes: the file part (a file name without a double quote or control character, sent as the
/// type sniffed from its bytes), then the comment part when given, then the closing delimiter.
/// Anything else is `None` (the card keeps the generic request list).
fn sent_upload(request: &HttpRequestSpec) -> Option<SentUpload<'_>> {
    let b = request
        .content_type
        .as_deref()?
        .strip_prefix("multipart/form-data; boundary=")?;
    if b.is_empty() {
        return None;
    }
    let rest = request
        .body
        .strip_prefix(format!("--{b}{FILE_PART_HEAD}").as_bytes())?;
    let name_end = generic::find_bytes(rest, FILE_TYPE_HEAD.as_bytes())?;
    let filename = std::str::from_utf8(rest.get(..name_end)?).ok()?;
    let rest = rest.get(name_end + FILE_TYPE_HEAD.len()..)?;
    let type_end = generic::find_bytes(rest, b"\r\n\r\n")?;
    let part_type = rest.get(..type_end)?;
    let rest = rest.get(type_end + 4..)?;
    let delimiter = format!("\r\n--{b}");
    let end = generic::find_bytes(rest, delimiter.as_bytes())?;
    let content = rest.get(..end)?;
    let tail = rest.get(end + delimiter.len()..)?;
    let comment = if tail == b"--\r\n" {
        None
    } else {
        let text = tail
            .strip_prefix(COMMENT_PART_HEAD.as_bytes())?
            .strip_suffix(format!("{delimiter}--\r\n").as_bytes())?;
        let text = std::str::from_utf8(text).ok()?;
        // A comment holding the delimiter would not split back into these parts.
        if text.contains(&delimiter) {
            return None;
        }
        Some(text)
    };
    let mime = super::confluence_ext::sniff_mime(content);
    let plain_name = !filename.chars().any(|c| c == '"' || c.is_control());
    (plain_name && part_type == mime.as_bytes()).then_some(SentUpload {
        filename,
        mime,
        content,
        comment,
    })
}

/// The `data:` thumbnail of a raster image of at most [`THUMBNAIL_MAX_BYTES`] (PD-110): standard
/// base64, unwrapped (T8 review m-7), typed by the sniffed type, never by the extension; never SVG.
fn thumbnail(mime: &str, content: &[u8]) -> Option<String> {
    use base64::Engine as _;
    let raster = matches!(
        mime,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp"
    );
    (raster && content.len() <= THUMBNAIL_MAX_BYTES).then(|| {
        format!(
            "data:{mime};base64,{}",
            base64::engine::general_purpose::STANDARD.encode(content)
        )
    })
}

/// PD-110 (plan review m-9): the extension of `filename` when it names an active type, names a
/// sniffable type other than `mime`, or `mime` is a sniffed type the extension does not name.
/// Trailing dots and spaces are dropped first (Windows drops them when the file is saved, so
/// `x.html.` opens as `x.html`); a name without an extension has none.
fn mismatched_extension<'a>(filename: &'a str, mime: &str) -> Option<&'a str> {
    let (_, ext) = filename.trim_end_matches(['.', ' ']).rsplit_once('.')?;
    let lower = ext.to_ascii_lowercase();
    let named = TYPE_EXTENSIONS
        .iter()
        .find(|(_, exts)| exts.contains(&lower.as_str()))
        .map(|(t, _)| *t);
    let of_sniffed = TYPE_EXTENSIONS
        .iter()
        .find(|(t, _)| *t == mime)
        .map(|(_, exts)| *exts);
    let differs = ACTIVE_EXTENSIONS.contains(&lower.as_str())
        || named.is_some_and(|t| t != mime)
        || of_sniffed.is_some_and(|exts| !exts.contains(&lower.as_str()));
    differs.then_some(ext)
}

/// §6.3 Attachment upload for `confluence.attachment.upload` (PD-109, PD-110) over the exact
/// request (§5.1 inv. 4): the file name, size, the type the part is sent as (sniffed), the
/// SHA-256, the capped thumbnail, the comment, PD-110's fact row; the collision hold's "attachment
/// already exists" with the facts of the attachment found, or a replace's "replaces existing
/// attachment vN". The card never carries the file beyond the thumbnail, and the request list
/// keeps the Δ2 envelope (the file part as its size and SHA-256 line, counted as hidden by
/// `generic`). A request that is not exactly the upload the verdict calls for (another endpoint,
/// another layout), and every other hold, keeps the generic write preview.
pub(crate) fn attachment_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let mut model = generic::write_preview(ctx);
    let PreviewInput::Write(view) = &ctx.input else {
        return model;
    };
    let Some(verdict) = view.enrichment else {
        return model;
    };
    let existing = verdict
        .summary
        .as_ref()
        .and_then(|s| s.confluence.as_ref())
        .and_then(|c| c.existing_attachment.as_ref());
    let replace = verdict.resolved.get("replace") == Some(&Value::Bool(true));
    // The collision names the attachment found; a replace's preview the one it replaces; a new
    // attachment's preview found none.
    let (collision, replaced) = match (view.hold, verdict.hold, replace, existing) {
        (Hold::Collision, Hold::Collision, false, Some(e)) => (Some(e), None),
        (Hold::Preview, Hold::Preview, true, Some(e)) => (None, Some(e)),
        (Hold::Preview, Hold::Preview, false, None) => (None, None),
        _ => return model,
    };
    let ([request], PreviewBody::WriteRequests { .. }) = (view.requests, &model.body) else {
        return model;
    };
    let Some(content_id) = verdict.resolved.get("id").and_then(Value::as_str) else {
        return model;
    };
    let endpoint = match replaced {
        Some(e) => format!(
            "/rest/api/content/{content_id}/child/attachment/{}/data",
            e.id
        ),
        None => format!("/rest/api/content/{content_id}/child/attachment?allowDuplicated=false"),
    };
    let Some(sent) = sent_upload(request).filter(|_| request.resolved_url.ends_with(&endpoint))
    else {
        return model;
    };

    let mut cut = 0u64;
    let mut line = |raw: &str, cap: usize| {
        let (shown, bytes) = generic::capped_text(raw, cap);
        cut = cut.saturating_add(bytes);
        shown
    };
    let filename = line(sent.filename, generic::CELL_CAP_CHARS * 2);
    let comment = sent.comment.map(|c| line(c, COMMENT_CAP_CHARS));
    let notes: Vec<String> = mismatched_extension(sent.filename, sent.mime)
        .map(|ext| {
            let ext = line(ext, EXTENSION_CAP_CHARS);
            format!("{TEXT_EXTENSION_MISMATCH}: .{ext}, sent as {}", sent.mime)
        })
        .into_iter()
        .collect();
    let existing = collision.map(|e| {
        let size = e
            .size
            .map_or_else(|| "size not reported".to_owned(), |n| format!("{n} bytes"));
        line(
            &format!("attachment {}, version {}, {size}", e.id, e.version),
            generic::CELL_CAP_CHARS,
        )
    });
    // Server text the card shows beyond the request (§6.4 counts): the attachment found.
    count_card_text(&mut model, collision.map(|e| e.id.as_str()));

    let requests = match std::mem::replace(
        &mut model.body,
        PreviewBody::WriteRequests {
            requests: Vec::new(),
        },
    ) {
        PreviewBody::WriteRequests { requests } => requests,
        _ => Vec::new(),
    };
    model.body = PreviewBody::AttachmentUpload {
        filename,
        size: len_u64(sent.content.len()),
        mime: sent.mime.to_owned(),
        sha256: crate::payloads::sha256_hex(sent.content),
        thumbnail_data_uri: thumbnail(sent.mime, sent.content),
        replaces_version: replaced.map(|e| e.version),
        existing,
        comment,
        notes,
        requests,
    };
    model.header.hidden_in_preview_bytes = model.header.hidden_in_preview_bytes.saturating_add(cut);
    model
}
