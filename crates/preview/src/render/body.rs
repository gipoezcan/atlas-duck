//! The body of the preview document, one layout per `PreviewBody` variant (§6.3, PD-67).

use super::{DOC_MAX_DIFF_LINES, DOC_MAX_ROWS, Doc, item_count_text, len_u64, more_not_shown};
use crate::diff::{DiffLine, DiffOp};
use crate::json_tree::JsonNode;
use crate::model::{
    BodyView, CommentView, ConstructList, FieldRow, IssueCard, OutcomeKind, PreviewBody,
    RequestView,
};
use crate::warning;

// ---- fixed texts -------------------------------------------------------------------------------

/// §6.3 Conflict (verbatim): the card's heading.
pub const CONFLICT_HEADING: &str = "Changed since the agent read it";

/// One §6.3 consequence line: the action and what the agent receives, in parts (the backticked
/// words of the spec render as `<code>`).
struct Consequence {
    action: &'static str,
    parts: &'static [Part],
}

enum Part {
    Text(&'static str),
    Code(&'static str),
    /// The card's HTTP status.
    Status,
}

/// §6.3 Upstream error (verbatim): Release → "agent receives `failed` (exit 6), HTTP <status> + the
/// text below".
const UPSTREAM_RELEASE: Consequence = Consequence {
    action: "Release",
    parts: &[
        Part::Text("agent receives "),
        Part::Code("failed"),
        Part::Text(" (exit 6), HTTP "),
        Part::Status,
        Part::Text(" + the text below"),
    ],
};

/// §6.3 Upstream error (verbatim): Release status only → "agent receives `failed` (exit 6), HTTP
/// <status>, no text".
const UPSTREAM_STATUS_ONLY: Consequence = Consequence {
    action: "Release status only",
    parts: &[
        Part::Text("agent receives "),
        Part::Code("failed"),
        Part::Text(" (exit 6), HTTP "),
        Part::Status,
        Part::Text(", no text"),
    ],
};

/// §6.3 / §5.2 step 6 (verbatim): Deny → "agent receives `denied` (exit 3) + your reason".
const DENY: Consequence = Consequence {
    action: "Deny",
    parts: &[
        Part::Text("agent receives "),
        Part::Code("denied"),
        Part::Text(" (exit 3) + your reason"),
    ],
};

/// §6.3 Read outcome (verbatim): Release outcome → "agent receives `failed` (exit 6),
/// `result_too_large` / `upstream_network` / `upstream_unavailable` and a fixed hint; no size".
const OUTCOME_RELEASE: Consequence = Consequence {
    action: "Release outcome",
    parts: &[
        Part::Text("agent receives "),
        Part::Code("failed"),
        Part::Text(" (exit 6), "),
        Part::Code("result_too_large"),
        Part::Text(" / "),
        Part::Code("upstream_network"),
        Part::Text(" / "),
        Part::Code("upstream_unavailable"),
        Part::Text(" and a fixed hint; no size"),
    ],
};

/// §6.3 Enrichment error (verbatim): the deny of an outcome → "agent receives `denied` (exit 3),
/// `upstream_network` / `upstream_unavailable` / `result_too_large`, no size".
const ENRICHMENT_OUTCOME_DENY: Consequence = Consequence {
    action: "Deny",
    parts: &[
        Part::Text("agent receives "),
        Part::Code("denied"),
        Part::Text(" (exit 3), "),
        Part::Code("upstream_network"),
        Part::Text(" / "),
        Part::Code("upstream_unavailable"),
        Part::Text(" / "),
        Part::Code("result_too_large"),
        Part::Text(", no size"),
    ],
};

/// §6.3 Read outcome / §7.2: which cap, budget or failure was hit. `LaterPageRefused` is the
/// M5 T21 class (plan text).
pub fn outcome_text(o: OutcomeKind) -> &'static str {
    match o {
        OutcomeKind::ReleaseCap16 => "16 MiB release cap",
        OutcomeKind::ResponseCap32 => "32 MiB per-response cap",
        OutcomeKind::FetchCap50 => "50 MiB fetch cap",
        OutcomeKind::ReadBudget120 => "120 s read budget",
        OutcomeKind::PerCallTimeout30 => "30 s per-call timeout",
        OutcomeKind::NetworkAfterSend => "network error after send",
        OutcomeKind::JsonBodyUnreadable => "JSON body that failed to read or parse",
        OutcomeKind::LaterPageRefused => "a later page was refused or answered without usable JSON",
    }
}

fn consequences(doc: &mut Doc, lines: &[&Consequence], status: Option<u16>) {
    doc.el("h3", "What the agent receives");
    doc.open("ul");
    for c in lines {
        doc.open("li");
        doc.el("strong", c.action);
        doc.fixed(" → ");
        for part in c.parts {
            match part {
                Part::Text(t) => doc.fixed(t),
                Part::Code(t) => doc.el("code", t),
                Part::Status => doc.fixed(&status.map_or_else(String::new, |s| s.to_string())),
            }
        }
        doc.close("li");
    }
    doc.close("ul");
}

// ---- dispatch ----------------------------------------------------------------------------------

pub(super) fn body(doc: &mut Doc, body: &PreviewBody) {
    match body {
        PreviewBody::JsonTree { tree } => {
            section(doc, "Result (JSON tree)");
            doc.open("ul");
            json_node(doc, None, tree);
            doc.close("ul");
            doc.close("section");
        }
        PreviewBody::WriteRequests { requests } => {
            requests_section(doc, "Requests to be sent", requests)
        }
        PreviewBody::UpstreamError {
            status,
            error_messages_text,
        } => {
            section(doc, "Upstream error");
            fact_table(doc, &[("HTTP status", &status.to_string())]);
            consequences(
                doc,
                &[&UPSTREAM_RELEASE, &UPSTREAM_STATUS_ONLY, &DENY],
                Some(*status),
            );
            doc.el("h3", "Atlassian error messages");
            pre_text(doc, error_messages_text);
            doc.close("section");
        }
        PreviewBody::Outcome {
            outcome,
            size_or_pages,
            query,
        } => {
            section(doc, "Read outcome");
            doc.open("table");
            doc.open("tbody");
            fixed_row(doc, "outcome", outcome_text(*outcome));
            text_row(doc, "reached", size_or_pages);
            text_row(doc, "query", query);
            doc.close("tbody");
            doc.close("table");
            doc.el("p", "No fetched content is shown or released.");
            consequences(doc, &[&OUTCOME_RELEASE, &DENY], None);
            doc.close("section");
        }
        PreviewBody::EnrichmentError {
            status,
            text,
            outcome,
        } => {
            section(doc, "Enrichment error");
            doc.open("table");
            doc.open("tbody");
            if let Some(s) = status {
                fixed_row(doc, "HTTP status", &s.to_string());
            }
            if let Some(o) = outcome {
                fixed_row(doc, "outcome", outcome_text(*o));
            }
            doc.close("tbody");
            doc.close("table");
            let deny = if outcome.is_some() {
                &ENRICHMENT_OUTCOME_DENY
            } else {
                &DENY
            };
            consequences(doc, &[deny], *status);
            if !text.is_empty() {
                doc.el("h3", "Atlassian error messages");
                pre_text(doc, text);
            }
            doc.close("section");
        }
        PreviewBody::UnresolvedName {
            param,
            value,
            matches,
            candidates,
        } => {
            section(doc, "Unresolved name");
            doc.open("table");
            doc.open("tbody");
            text_row(doc, "parameter", param);
            text_row(doc, "submitted value", value);
            fixed_row(doc, "matches", &matches.to_string());
            doc.close("tbody");
            doc.close("table");
            doc.el("h3", "Candidates");
            text_list(doc, candidates, "candidates");
            consequences(doc, &[&DENY], None);
            doc.close("section");
        }
        PreviewBody::Conflict { summary, diff_text } => {
            section(doc, CONFLICT_HEADING);
            doc.open("div");
            doc.text(summary);
            doc.close("div");
            if !diff_text.is_empty() {
                doc.el("h3", "Agent's base against the current state");
                pre_text(doc, diff_text);
            }
            consequences(doc, &[&DENY], None);
            doc.close("section");
        }
        PreviewBody::CouldNotRecheck { class, requests } => {
            section(doc, warning::TEXT_COULD_NOT_RECHECK);
            doc.open("table");
            doc.open("tbody");
            text_row(doc, "failure class", class);
            doc.close("tbody");
            doc.close("table");
            consequences(doc, &[&DENY], None);
            doc.close("section");
            requests_section(doc, "Requests to be sent (unchanged)", requests);
        }
        PreviewBody::JiraIssue {
            card,
            fields,
            description_html,
            comments,
        } => jira_issue(doc, card, fields, description_html.as_deref(), comments),
        PreviewBody::Table {
            columns,
            rows,
            count,
        } => {
            section(doc, "Results");
            doc.open("table");
            if let Some(c) = count {
                doc.el("caption", &item_count_text(c));
            }
            doc.open("thead");
            doc.open("tr");
            for c in columns {
                doc.open("th");
                doc.text(c);
                doc.close("th");
            }
            doc.close("tr");
            doc.close("thead");
            doc.open("tbody");
            let mut left_out = None;
            for (i, row) in rows.iter().enumerate() {
                if i >= DOC_MAX_ROWS || doc.full() {
                    left_out = Some(i);
                    break;
                }
                doc.open("tr");
                for cell in row {
                    doc.open("td");
                    doc.text(cell);
                    doc.close("td");
                }
                doc.close("tr");
            }
            doc.close("tbody");
            doc.close("table");
            if let Some(i) = left_out {
                let rest = &rows[i..];
                doc.hide(rest.iter().map(|r| strings_len(r)).sum());
                more_note(doc, rest.len(), "rows");
            }
            doc.close("section");
        }
        PreviewBody::WriteSummary {
            sentence,
            rows,
            constructs,
            requests,
        } => {
            section(doc, "Summary");
            doc.open("div");
            doc.text(sentence);
            doc.close("div");
            pair_table(doc, rows);
            if let Some(c) = constructs {
                construct_list(doc, c);
            }
            doc.close("section");
            requests_section(doc, "Requests to be sent", requests);
        }
        PreviewBody::EditDiff {
            rendered,
            raw,
            raw_only_changes,
            requests,
        } => {
            section(doc, "Rendered diff");
            diff(doc, rendered);
            doc.close("section");
            section(doc, "Raw diff");
            if *raw_only_changes > 0 {
                doc.open("p");
                doc.el("strong", &warning::raw_only_diff(*raw_only_changes));
                doc.close("p");
            }
            diff(doc, raw);
            doc.close("section");
            requests_section(doc, "Requests to be sent", requests);
        }
        PreviewBody::Transition {
            transition,
            from,
            to,
            fields,
            constructs,
            requests,
        } => {
            section(doc, "Transition");
            doc.open("div");
            doc.text(from);
            doc.fixed(" → ");
            doc.text(to);
            doc.close("div");
            doc.open("table");
            doc.open("tbody");
            text_row(doc, "transition", transition);
            doc.close("tbody");
            doc.close("table");
            doc.el("h3", "Fields set during the transition");
            if fields.is_empty() {
                doc.el("p", "none");
            } else {
                pair_table(doc, fields);
            }
            if let Some(c) = constructs {
                construct_list(doc, c);
            }
            doc.close("section");
            requests_section(doc, "Requests to be sent", requests);
        }
        // Task 18 renders the script sections (source, host calls, atlas.log, stderr); until
        // then only the candidate view shows, through its own arm.
        PreviewBody::Script { view, .. } => self::body(doc, view),
    }
}

// ---- building blocks ---------------------------------------------------------------------------

fn section(doc: &mut Doc, title: &str) {
    doc.open("section");
    doc.el("h2", title);
}

fn more_note(doc: &mut Doc, n: usize, unit: &str) {
    doc.open("p");
    doc.fixed(&more_not_shown(len_u64(n), unit));
    doc.close("p");
}

fn strings_len(items: &[String]) -> u64 {
    items.iter().map(|s| len_u64(s.len())).sum()
}

fn fixed_row(doc: &mut Doc, label: &str, value: &str) {
    doc.open("tr");
    doc.el("th", label);
    doc.el("td", value);
    doc.close("tr");
}

fn text_row(doc: &mut Doc, label: &str, value: &str) {
    doc.open("tr");
    doc.el("th", label);
    doc.open("td");
    doc.text(value);
    doc.close("td");
    doc.close("tr");
}

fn fact_table(doc: &mut Doc, rows: &[(&str, &str)]) {
    doc.open("table");
    doc.open("tbody");
    for (label, value) in rows {
        fixed_row(doc, label, value);
    }
    doc.close("tbody");
    doc.close("table");
}

/// Multi-line display text (error messages, a conflict diff) in `<pre><code>`: the `<code>`
/// keeps a leading newline of the text from being dropped by the HTML parser after `<pre>`.
fn pre_text(doc: &mut Doc, text: &str) {
    doc.open("pre");
    doc.open("code");
    doc.text(text);
    doc.close("code");
    doc.close("pre");
}

/// A `<ul>` of display texts, at most [`DOC_MAX_ROWS`]; `none` when empty.
fn text_list(doc: &mut Doc, items: &[String], unit: &str) {
    if items.is_empty() {
        doc.el("p", "none");
        return;
    }
    doc.open("ul");
    let mut left_out = None;
    for (i, item) in items.iter().enumerate() {
        if i >= DOC_MAX_ROWS || doc.full() {
            left_out = Some(i);
            break;
        }
        doc.open("li");
        doc.text(item);
        doc.close("li");
    }
    doc.close("ul");
    if let Some(i) = left_out {
        doc.hide(strings_len(&items[i..]));
        more_note(doc, items.len() - i, unit);
    }
}

/// Label/value rows (`th` + `td`), at most [`DOC_MAX_ROWS`].
fn pair_table(doc: &mut Doc, rows: &[(String, String)]) {
    if rows.is_empty() {
        return;
    }
    doc.open("table");
    doc.open("tbody");
    let mut left_out = None;
    for (i, (label, value)) in rows.iter().enumerate() {
        if i >= DOC_MAX_ROWS || doc.full() {
            left_out = Some(i);
            break;
        }
        doc.open("tr");
        doc.open("th");
        doc.text(label);
        doc.close("th");
        doc.open("td");
        doc.text(value);
        doc.close("td");
        doc.close("tr");
    }
    doc.close("tbody");
    doc.close("table");
    if let Some(i) = left_out {
        let rest = &rows[i..];
        doc.hide(rest.iter().map(|(l, v)| len_u64(l.len() + v.len())).sum());
        more_note(doc, rest.len(), "rows");
    }
}

/// PD-47: the wiki constructs of the outgoing text, per kind, as text (never a live link).
fn construct_list(doc: &mut Doc, c: &ConstructList) {
    doc.el("h3", "Wiki constructs in the text");
    let kinds: [(&str, &[String]); 6] = [
        ("macros", &c.macros),
        ("mentions", &c.mentions),
        ("includes", &c.includes),
        ("links", &c.links),
        ("images", &c.images),
        ("attachments", &c.attachments),
    ];
    if kinds.iter().all(|(_, items)| items.is_empty()) {
        doc.el("p", "none");
        return;
    }
    doc.open("table");
    doc.open("tbody");
    for (label, items) in kinds {
        if items.is_empty() {
            continue;
        }
        doc.open("tr");
        doc.el("th", label);
        doc.open("td");
        for (i, item) in items.iter().take(DOC_MAX_ROWS).enumerate() {
            if i > 0 {
                doc.fixed(", ");
            }
            doc.text(item);
        }
        if items.len() > DOC_MAX_ROWS {
            let rest = &items[DOC_MAX_ROWS..];
            doc.hide(strings_len(rest));
            doc.fixed(", ");
            doc.fixed(&more_not_shown(len_u64(rest.len()), "entries"));
        }
        doc.close("td");
        doc.close("tr");
    }
    doc.close("tbody");
    doc.close("table");
}

// ---- requests (§5.1 inv. 4: the exact list is part of every write body) ------------------------

fn request_len(r: &RequestView) -> u64 {
    let body = match &r.body {
        BodyView::None => 0,
        BodyView::Text(t) | BodyView::Base64(t) => t.len(),
    };
    len_u64(r.method.len() + r.resolved_url.len() + body)
}

fn requests_section(doc: &mut Doc, title: &str, requests: &[RequestView]) {
    section(doc, title);
    if requests.is_empty() {
        doc.el("p", "none");
    }
    for (i, r) in requests.iter().enumerate() {
        if i >= DOC_MAX_ROWS || doc.full() {
            let rest = &requests[i..];
            doc.hide(rest.iter().map(request_len).sum());
            more_note(doc, rest.len(), "requests");
            break;
        }
        doc.el("h3", &format!("Request {}", r.index));
        doc.open("table");
        doc.open("tbody");
        raw_row(doc, "method", &r.method);
        raw_row(doc, "URL", &r.resolved_url);
        match &r.content_type {
            Some(ct) => raw_row(doc, "Content-Type", ct),
            None => fixed_row(doc, "Content-Type", "none"),
        }
        doc.close("tbody");
        doc.close("table");
        match &r.body {
            BodyView::None => doc.el("p", "No body."),
            BodyView::Text(t) => {
                doc.el("p", "Body:");
                doc.open("pre");
                doc.open("code");
                doc.raw_text(t);
                doc.close("code");
                doc.close("pre");
            }
            BodyView::Base64(b) => {
                doc.el("p", "Binary body (base64):");
                doc.open("pre");
                doc.open("code");
                doc.raw_text(b);
                doc.close("code");
                doc.close("pre");
            }
        }
    }
    doc.close("section");
}

fn raw_row(doc: &mut Doc, label: &str, value: &str) {
    doc.open("tr");
    doc.el("th", label);
    doc.open("td");
    doc.raw_text(value);
    doc.close("td");
    doc.close("tr");
}

// ---- the JSON tree (§6.3 Fallback: JSON tree with sizes) ---------------------------------------

/// Bytes of a node the document leaves out: its compact JSON size less what core already counts
/// as collapsed.
fn node_len(n: &JsonNode) -> u64 {
    match n {
        JsonNode::Null | JsonNode::Bool { value: true } => 4,
        JsonNode::Bool { value: false } => 5,
        JsonNode::Number { text } => len_u64(text.len()),
        JsonNode::String { text } => len_u64(text.len()).saturating_add(2),
        JsonNode::Collapsed { .. } => 0,
        JsonNode::Array { size, .. } | JsonNode::Object { size, .. } => {
            size.saturating_sub(n.hidden_bytes())
        }
    }
}

/// One `<li>`: the key (or index), the value or its kind and size, the children in a `<ul>`.
fn json_node(doc: &mut Doc, key: Option<Key<'_>>, n: &JsonNode) {
    doc.open("li");
    match key {
        Some(Key::Name(k)) => {
            doc.raw_code_text(k);
            doc.fixed(": ");
        }
        Some(Key::Index(i)) => doc.fixed(&format!("[{i}]: ")),
        None => {}
    }
    match n {
        JsonNode::Null => doc.el("code", "null"),
        JsonNode::Bool { value } => doc.el("code", if *value { "true" } else { "false" }),
        JsonNode::Number { text } => doc.raw_code_text(text),
        JsonNode::String { text } => doc.raw_quoted(text),
        JsonNode::Collapsed { byte_len, .. } => doc.fixed(&format!(
            "string of {byte_len} bytes, not shown here; see Structured or Raw"
        )),
        JsonNode::Array { size, items } => {
            doc.fixed(&format!("array, {} items, {size} bytes", items.len()));
            if !items.is_empty() {
                doc.open("ul");
                for (i, item) in items.iter().enumerate() {
                    if doc.full() {
                        let rest = &items[i..];
                        doc.hide(rest.iter().map(node_len).sum());
                        more_item(doc, rest.len());
                        break;
                    }
                    json_node(doc, Some(Key::Index(i)), item);
                }
                doc.close("ul");
            }
        }
        JsonNode::Object { size, entries } => {
            doc.fixed(&format!("object, {} keys, {size} bytes", entries.len()));
            if !entries.is_empty() {
                doc.open("ul");
                for (i, (k, v)) in entries.iter().enumerate() {
                    if doc.full() {
                        let rest = &entries[i..];
                        doc.hide(
                            rest.iter()
                                .map(|(k, v)| len_u64(k.len()).saturating_add(node_len(v)))
                                .sum(),
                        );
                        more_item(doc, rest.len());
                        break;
                    }
                    json_node(doc, Some(Key::Name(k)), v);
                }
                doc.close("ul");
            }
        }
    }
    doc.close("li");
}

#[derive(Clone, Copy)]
enum Key<'a> {
    Name(&'a str),
    Index(usize),
}

fn more_item(doc: &mut Doc, n: usize) {
    doc.open("li");
    doc.fixed(&more_not_shown(len_u64(n), "items"));
    doc.close("li");
}

// ---- diffs (§6.3 Edit/update, PD-51, PD-69) ----------------------------------------------------

/// A diff: each `Field` line is an `<h3>`; the lines after it form one `<table>` with a marker
/// column (`+`, `-`, ` `), one `<tbody>` per run (a hunk is a run of `Add`/`Del` lines), the
/// text PD-69-visible and in a `<pre>` (a change in a run of spaces shows without the
/// stylesheet, T10 review I-1). At most [`DOC_MAX_DIFF_LINES`] lines.
fn diff(doc: &mut Doc, lines: &[DiffLine]) {
    if lines.is_empty() {
        doc.el("p", "no changes");
        return;
    }
    // `None`: no table open; `Some(changed)`: a `<tbody>` of changed (or same) lines is open.
    let mut open: Option<bool> = None;
    for (i, line) in lines.iter().enumerate() {
        if i >= DOC_MAX_DIFF_LINES || doc.full() {
            close_table(doc, &mut open);
            let rest = &lines[i..];
            doc.hide(rest.iter().map(|l| len_u64(l.text.len())).sum());
            more_note(doc, rest.len(), "lines");
            return;
        }
        let (marker, wrap) = match line.op {
            DiffOp::Field => {
                close_table(doc, &mut open);
                doc.open("h3");
                doc.text(&line.text);
                doc.close("h3");
                continue;
            }
            DiffOp::Same => (" ", None),
            DiffOp::Add => ("+", Some("ins")),
            DiffOp::Del => ("-", Some("del")),
        };
        let changed = wrap.is_some();
        match open {
            None => {
                doc.open("table");
                doc.open("tbody");
            }
            Some(was) if was != changed => {
                doc.close("tbody");
                doc.open("tbody");
            }
            Some(_) => {}
        }
        open = Some(changed);
        doc.open("tr");
        doc.el("td", marker);
        doc.open("td");
        doc.open("pre");
        if let Some(tag) = wrap {
            doc.open(tag);
        }
        doc.diff_line(&line.text);
        if let Some(tag) = wrap {
            doc.close(tag);
        }
        doc.close("pre");
        doc.close("td");
        doc.close("tr");
    }
    close_table(doc, &mut open);
}

fn close_table(doc: &mut Doc, open: &mut Option<bool>) {
    if open.take().is_some() {
        doc.close("tbody");
        doc.close("table");
    }
}

// ---- Jira issue (§6.3) -------------------------------------------------------------------------

fn jira_issue(
    doc: &mut Doc,
    card: &IssueCard,
    fields: &[FieldRow],
    description_html: Option<&str>,
    comments: &[CommentView],
) {
    section(doc, "Issue");
    doc.open("table");
    doc.open("tbody");
    text_row(doc, "key", &card.key);
    text_row(doc, "summary", &card.summary);
    text_row(doc, "type", &card.issue_type);
    text_row(doc, "status", &card.status);
    for (label, value) in [
        ("priority", &card.priority),
        ("assignee", &card.assignee),
        ("reporter", &card.reporter),
    ] {
        match value {
            Some(v) => text_row(doc, label, v),
            None => fixed_row(doc, label, "none"),
        }
    }
    doc.close("tbody");
    doc.close("table");

    doc.el("h3", "Fields");
    if fields.is_empty() {
        doc.el("p", "none");
    } else {
        doc.open("table");
        doc.open("thead");
        doc.open("tr");
        doc.el("th", "field");
        doc.el("th", "id");
        doc.el("th", "value");
        doc.close("tr");
        doc.close("thead");
        doc.open("tbody");
        let mut left_out = None;
        for (i, f) in fields.iter().enumerate() {
            if i >= DOC_MAX_ROWS || doc.full() {
                left_out = Some(i);
                break;
            }
            doc.open("tr");
            doc.open("td");
            doc.text(&f.name);
            doc.close("td");
            doc.open("td");
            doc.code_text(&f.id);
            doc.close("td");
            doc.open("td");
            if f.restricted {
                doc.el("strong", "restricted visibility");
                doc.fixed(" ");
            }
            doc.text(&f.value_text);
            doc.close("td");
            doc.close("tr");
        }
        doc.close("tbody");
        doc.close("table");
        if let Some(i) = left_out {
            let rest = &fields[i..];
            doc.hide(
                rest.iter()
                    .map(|f| len_u64(f.name.len() + f.id.len() + f.value_text.len()))
                    .sum(),
            );
            more_note(doc, rest.len(), "rows");
        }
    }

    doc.el("h3", "Description");
    match description_html {
        Some(html) => doc.html(html),
        None => doc.el("p", "none"),
    }

    doc.el("h3", &format!("Comments ({})", comments.len()));
    for (i, c) in comments.iter().enumerate() {
        if i >= DOC_MAX_ROWS || doc.full() {
            let rest = &comments[i..];
            doc.hide(rest.iter().map(|c| len_u64(c.body_html.len())).sum());
            more_note(doc, rest.len(), "comments");
            break;
        }
        doc.open("section");
        doc.open("h4");
        doc.fixed("Comment ");
        doc.text(&c.id);
        doc.close("h4");
        doc.open("div");
        match &c.author {
            Some(a) => doc.text(a),
            None => doc.fixed("unknown author"),
        }
        if let Some(created) = &c.created {
            doc.fixed(", ");
            doc.text(created);
        }
        if c.restricted {
            doc.fixed(" ");
            doc.el("strong", "restricted visibility");
        }
        doc.close("div");
        doc.html(&c.body_html);
        doc.close("section");
    }
}
