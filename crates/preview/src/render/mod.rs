//! The sandboxed preview document (M6 Δ5, PD-67; §6.1–§6.4): every `PreviewBody` variant rendered
//! to one HTML document in Rust, shown by the Approvals window as the `srcdoc` of an
//! `<iframe sandbox="">`. TypeScript never builds HTML.
//!
//! Rules (S-12, S-06):
//! - Every non-HTML string is HTML-escaped after the display escaping (core's, or
//!   `invisible::escape_for_display` here for the raw ones: diff lines, request views, JSON tree
//!   strings and keys), made whitespace-visible (PD-69, [`ws`]) and wrapped in `<bdi>`; each
//!   `⟨…⟩` escape is a `<mark>`. A flagged character core left raw is escaped here as well.
//! - `*_html` strings pass `sanitize_html` again; flagged characters in their text are escaped.
//! - Semantic elements only (`header`, `section`, `table`, `th`, `td`, `ins`, `del`, `h2`–`h4`,
//!   `ul`, `li`, `p`, `pre`, `code`, `bdi`, `mark`, `strong`), never a `class` or `style`
//!   attribute: `preview.css` styles by element and position.
//! - Display caps: [`DOC_MAX_ROWS`] rows per table or list, [`DOC_MAX_DIFF_LINES`] lines per diff,
//!   [`DOC_MAX_BYTES`] for the whole body. What a cap leaves out is replaced by the PD-67 note and
//!   counted in the header's "hidden in preview" bytes.
//! - The document is [`crate::iframe_document`]: meta CSP first, then `preview.css`, and the body
//!   sanitized once more under the document allowlist.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod body;
pub mod ws;

use crate::invisible;
use crate::model::{ItemCount, Preview, PreviewBody};
use crate::sanitize::{Platform, iframe_document, sanitize_html};
use crate::warning::{self, Level, Warning, WarningId};

/// Most rows of one table or list in the document (PD-67).
pub const DOC_MAX_ROWS: usize = 2_000;
/// Most lines of one diff in the document (PD-67).
pub const DOC_MAX_DIFF_LINES: usize = 5_000;
/// Most bytes of the document body (PD-67).
pub const DOC_MAX_BYTES: usize = 4 << 20;

/// plan text (PD-67): "N more rows / lines not shown here; see Structured or Raw", with the unit
/// of what was left out.
pub fn more_not_shown(n: u64, unit: &str) -> String {
    format!("{n} more {unit} not shown here; see Structured or Raw")
}

/// The whole `srcdoc` document for `p` (Δ5).
pub fn document(p: &Preview, platform: Platform) -> String {
    let mut doc = Doc::default();
    body::body(&mut doc, &p.body);
    if doc.cut_text > 0 {
        doc.open("p");
        doc.fixed(&more_not_shown(doc.cut_text, "bytes"));
        doc.close("p");
    }
    let body = std::mem::take(&mut doc.out);
    let cut = doc.cut;
    let mut head = Doc::default();
    header(&mut head, p, cut);
    head.out.push_str(&body);
    iframe_document(&head.out, platform)
}

/// The document being written: HTML text, the bytes a cap left out, and the part of them cut
/// from inside a text.
#[derive(Default)]
pub(crate) struct Doc {
    out: String,
    /// Every byte a cap left out of the body (rows, lines, items, cut texts).
    cut: u64,
    /// The part of `cut` cut from inside a single text (one note at the end of the body).
    cut_text: u64,
}

impl Doc {
    /// The byte budget of the body is used up.
    pub(crate) fn full(&self) -> bool {
        self.out.len() >= DOC_MAX_BYTES
    }

    /// Bytes a cap left out.
    pub(crate) fn hide(&mut self, bytes: u64) {
        self.cut = self.cut.saturating_add(bytes);
    }

    /// `<tag>` (fixed markup, no attribute).
    pub(crate) fn open(&mut self, tag: &str) {
        self.out.push('<');
        self.out.push_str(tag);
        self.out.push('>');
    }

    pub(crate) fn close(&mut self, tag: &str) {
        self.out.push_str("</");
        self.out.push_str(tag);
        self.out.push('>');
    }

    /// `<tag>fixed</tag>`.
    pub(crate) fn el(&mut self, tag: &str, fixed: &str) {
        self.open(tag);
        self.fixed(fixed);
        self.close(tag);
    }

    /// App-generated text (labels, notes, consequence lines): HTML-escaped, no `<bdi>`.
    pub(crate) fn fixed(&mut self, s: &str) {
        push_escaped(&mut self.out, s);
    }

    /// A string core display-escaped: whitespace made visible, HTML-escaped, escapes marked, in
    /// `<bdi>`. Cut at the byte budget (the rest is counted and noted at the end of the body).
    pub(crate) fn text(&mut self, s: &str) {
        let shown = ws::visible_value(s);
        self.bdi(&shown);
    }

    /// A raw string (diff-free): display-escaped here first, then as [`Doc::text`].
    pub(crate) fn raw_text(&mut self, s: &str) {
        self.text(&invisible::escape_for_display(s));
    }

    /// One diff line (raw): display-escaped, PD-69 line notation, as [`Doc::text`].
    pub(crate) fn diff_line(&mut self, s: &str) {
        let shown = ws::visible_line(&invisible::escape_for_display(s));
        self.bdi(&shown);
    }

    fn bdi(&mut self, shown: &str) {
        self.open("bdi");
        let left = push_marked(&mut self.out, shown, DOC_MAX_BYTES);
        if left > 0 {
            self.out.push('…');
            self.cut_text = self.cut_text.saturating_add(left);
            self.hide(left);
        }
        self.close("bdi");
    }

    /// Sanitized HTML (a `*_html` string): `sanitize_html` again, flagged characters in its text
    /// escaped and marked. Left out whole (and noted) when it does not fit the budget.
    pub(crate) fn html(&mut self, html: &str) {
        let clean = sanitize_html(html);
        if self.out.len().saturating_add(clean.len()) > DOC_MAX_BYTES {
            let n = len_u64(html.len());
            self.hide(n);
            self.open("p");
            self.fixed(&more_not_shown(n, "bytes"));
            self.close("p");
            return;
        }
        mark_html(&mut self.out, &clean);
    }
}

pub(crate) fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// `&`, `<`, `>` and `"` as entities.
fn push_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        push_escaped_char(out, c);
    }
}

fn push_escaped_char(out: &mut String, c: char) {
    match c {
        '&' => out.push_str("&amp;"),
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        '"' => out.push_str("&quot;"),
        _ => out.push(c),
    }
}

/// The byte length of the `⟨…⟩` escape `rest` starts with: `⟨U+XXXX⟩` (4 to 6 upper-case hex
/// digits) or [`ws::NO_NEWLINE_AT_END`]; `None` for anything else.
fn escape_len(rest: &str) -> Option<usize> {
    if rest.starts_with(ws::NO_NEWLINE_AT_END) {
        return Some(ws::NO_NEWLINE_AT_END.len());
    }
    let inner = rest.strip_prefix("⟨U+")?;
    let hex = inner
        .bytes()
        .take_while(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(b))
        .count();
    ((4..=6).contains(&hex) && inner[hex..].starts_with('⟩'))
        .then(|| "⟨U+".len() + hex + '⟩'.len_utf8())
}

/// Writes display text `s` HTML-escaped with every `⟨…⟩` escape (and every flagged character
/// still raw, escaped here) in a `<mark>`, until `out` reaches `limit` bytes. Returns the bytes of
/// `s` left out (0 when all of it fits).
fn push_marked(out: &mut String, s: &str, limit: usize) -> u64 {
    let flags = invisible::flags(s);
    let mut skip_to = 0;
    for ((i, c), flagged) in s.char_indices().zip(flags) {
        if i < skip_to {
            continue;
        }
        if out.len() >= limit {
            return len_u64(s.len() - i);
        }
        if flagged {
            out.push_str("<mark>");
            ws::push_escape(out, c);
            out.push_str("</mark>");
        } else if let Some(len) = (c == '⟨').then(|| escape_len(&s[i..])).flatten() {
            out.push_str("<mark>");
            out.push_str(&s[i..i + len]);
            out.push_str("</mark>");
            skip_to = i + len;
        } else {
            push_escaped_char(out, c);
        }
    }
    0
}

/// Sanitizer output with the text between its tags passed through the escape marking (its
/// entities stay as they are). The sanitizer's serialization is canonical: a `<` in text is always
/// `&lt;` and attribute values are double-quoted with `"` written `&quot;`, so a tag ends at the
/// first `>` outside quotes. Attribute values (an `alt`) are copied unchanged.
fn mark_html(out: &mut String, html: &str) {
    let mut rest = html;
    while !rest.is_empty() {
        match rest.find('<') {
            Some(0) => {
                let mut quoted = false;
                let end = rest
                    .char_indices()
                    .find(|&(_, c)| {
                        if c == '"' {
                            quoted = !quoted;
                        }
                        c == '>' && !quoted
                    })
                    .map_or(rest.len(), |(i, _)| i + 1);
                out.push_str(&rest[..end]);
                rest = &rest[end..];
            }
            found => {
                let end = found.unwrap_or(rest.len());
                mark_text(out, &rest[..end]);
                rest = &rest[end..];
            }
        }
    }
}

/// [`push_marked`] for text that is already HTML (no entity escaping, no budget).
fn mark_text(out: &mut String, text: &str) {
    let flags = invisible::flags(text);
    let mut skip_to = 0;
    for ((i, c), flagged) in text.char_indices().zip(flags) {
        if i < skip_to {
            continue;
        }
        if flagged {
            out.push_str("<mark>");
            ws::push_escape(out, c);
            out.push_str("</mark>");
        } else if let Some(len) = (c == '⟨').then(|| escape_len(&text[i..])).flatten() {
            out.push_str("<mark>");
            out.push_str(&text[i..i + len]);
            out.push_str("</mark>");
            skip_to = i + len;
        } else {
            out.push(c);
        }
    }
}

// ---- header, Caution strip, Info line (§6.1 principle 3, §6.2, §5.6) ---------------------------

/// plan text (PD-67): the Caution strip's label (§6.2: a text-labelled "Caution" strip).
pub const CAUTION_LABEL: &str = "Caution";
/// plan text (PD-67): the Info line's label.
pub const INFO_LABEL: &str = "Info:";
/// plan text (PD-67): the "agent receives" value of a write with an empty receipt.
pub const NO_RECEIPT_FIELDS: &str = "no receipt fields";

/// "N of total", or "N shown, more available" when the server reports no total (§6.1).
pub fn item_count_text(c: &ItemCount) -> String {
    match (c.total, c.more_available) {
        (Some(total), _) => format!("{} of {total}", c.shown),
        (None, true) => format!("{} shown, more available", c.shown),
        (None, false) => format!("{} shown", c.shown),
    }
}

/// The Caution strip's lines in order: the release-blocked banner, then the stale warnings the
/// re-review leads with (§5.4 step 5: "Could not re-check target" first), then the rest. A
/// `CouldNotRecheck` body or raw-only diff changes the warnings do not name still get their line.
fn caution_lines<'a>(p: &'a Preview) -> Vec<CautionLine<'a>> {
    let mut lines = Vec::new();
    if let Some(text) = p.header.release_blocked {
        lines.push(CautionLine::Fixed(text.to_owned()));
    }
    let cautions: Vec<&Warning> = p
        .warnings
        .iter()
        .filter(|w| w.level == Level::Caution)
        .collect();
    let has = |id: WarningId| cautions.iter().any(|w| w.id == id);
    if matches!(p.body, PreviewBody::CouldNotRecheck { .. }) && !has(WarningId::CouldNotRecheck) {
        lines.push(CautionLine::Fixed(
            warning::TEXT_COULD_NOT_RECHECK.to_owned(),
        ));
    }
    let (lead, rest): (Vec<&Warning>, Vec<&Warning>) = cautions
        .iter()
        .partition(|w| w.id == WarningId::CouldNotRecheck);
    lines.extend(
        lead.into_iter()
            .chain(rest)
            .map(|w| CautionLine::Text(&w.text)),
    );
    if let PreviewBody::EditDiff {
        raw_only_changes, ..
    } = &p.body
        && *raw_only_changes > 0
        && !has(WarningId::RawOnlyDiff)
    {
        lines.push(CautionLine::Fixed(warning::raw_only_diff(
            *raw_only_changes,
        )));
    }
    lines
}

enum CautionLine<'a> {
    /// App-generated (core's constant or a fixed template over counts).
    Fixed(String),
    /// A warning text (display-escaped by core where it carries server or agent text).
    Text(&'a str),
}

fn header(doc: &mut Doc, p: &Preview, cut: u64) {
    let h = &p.header;
    doc.open("header");
    let cautions = caution_lines(p);
    if !cautions.is_empty() {
        doc.open("section");
        doc.el("h2", CAUTION_LABEL);
        doc.open("ul");
        for line in &cautions {
            doc.open("li");
            match line {
                CautionLine::Fixed(text) => doc.fixed(text),
                CautionLine::Text(text) => doc.text(text),
            }
            doc.close("li");
        }
        doc.close("ul");
        doc.close("section");
    }

    doc.open("table");
    doc.open("tbody");
    row_text(doc, "instance", &h.instance_alias);
    row_text(doc, "operation", &h.op_id);
    row_text(doc, "class", &h.class);
    if let Some(c) = &h.item_count {
        row_fixed(doc, "items", &item_count_text(c));
    }
    row_fixed(doc, "size", &format!("{} bytes", h.byte_size));
    if !h.fields_included.is_empty() {
        row_list(doc, "fields included", &h.fields_included);
    }
    let hidden = h.hidden_in_preview_bytes.saturating_add(cut);
    row_fixed(doc, "hidden in preview", &format!("{hidden} bytes"));
    row_fixed(doc, "bidi controls", &h.bidi_controls.to_string());
    row_fixed(doc, "other invisible", &h.other_invisible.to_string());
    if let Some(user) = &h.executes_as {
        row_text(doc, "executes as", user);
    }
    if !h.receipt_fields.is_empty() {
        row_list(doc, "agent receives", &h.receipt_fields);
    } else if h.class == "write" {
        row_fixed(doc, "agent receives", NO_RECEIPT_FIELDS);
    }
    if let Some(q) = &h.query {
        doc.open("tr");
        doc.el("th", "query");
        doc.open("td");
        doc.open("code");
        doc.text(q);
        doc.close("code");
        doc.close("td");
        doc.close("tr");
    }
    doc.close("tbody");
    doc.close("table");

    let infos: Vec<&Warning> = p
        .warnings
        .iter()
        .filter(|w| w.level == Level::Info)
        .collect();
    if !infos.is_empty() {
        doc.open("p");
        doc.el("strong", INFO_LABEL);
        for (i, w) in infos.iter().enumerate() {
            doc.fixed(if i == 0 { " " } else { "; " });
            doc.text(&w.text);
        }
        doc.close("p");
    }
    doc.close("header");
}

fn row_text(doc: &mut Doc, label: &str, value: &str) {
    doc.open("tr");
    doc.el("th", label);
    doc.open("td");
    doc.text(value);
    doc.close("td");
    doc.close("tr");
}

fn row_fixed(doc: &mut Doc, label: &str, value: &str) {
    doc.open("tr");
    doc.el("th", label);
    doc.el("td", value);
    doc.close("tr");
}

/// A comma-separated list, each entry in its own `<bdi>`, at most [`DOC_MAX_ROWS`] entries.
fn row_list(doc: &mut Doc, label: &str, items: &[String]) {
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
        doc.fixed(&format!(
            ", {}",
            more_not_shown(len_u64(items.len() - DOC_MAX_ROWS), "entries")
        ));
    }
    doc.close("td");
    doc.close("tr");
}
