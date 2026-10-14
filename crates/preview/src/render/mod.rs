//! The sandboxed preview document (M6 Δ5, PD-67; §6.1–§6.4): every `PreviewBody` variant rendered
//! to one HTML document in Rust, shown by the Approvals window as the `srcdoc` of an
//! `<iframe sandbox="">`. TypeScript never builds HTML.
//!
//! Rules (S-12, S-06):
//! - Every non-HTML string is HTML-escaped after the display escaping (core's, or
//!   `invisible::escape_for_display` here for the raw ones: diff lines, request views, JSON tree
//!   strings and keys), made whitespace-visible (PD-69, [`ws`]) and wrapped in `<bdi>`; each
//!   `⟨…⟩` escape is a `<mark>`. A flagged character core left raw is escaped here as well.
//! - Whitespace fidelity does not depend on `preview.css` (T10 review I-1: PD-92 leaves its load
//!   unproven): diff lines, and every value whose whitespace a browser would collapse (leading
//!   space, a run of spaces, a tab, a newline), are in a `<pre>` (UA `white-space: pre`).
//! - `*_html` strings pass `sanitize_html` again; flagged characters in their text are escaped,
//!   in their attribute values (an `alt`) too.
//! - Semantic elements only (`header`, `section`, `table`, `th`, `td`, `ins`, `del`, `h2`–`h4`,
//!   `ul`, `li`, `p`, `div`, `pre`, `code`, `bdi`, `mark`, `strong`), never a `class` or `style`
//!   attribute: `preview.css` styles by element and position. A value that may need a `<pre>`
//!   sits in a `div`, never a `p` (which cannot hold one).
//! - Display caps: [`DOC_MAX_ROWS`] rows per table or list, [`DOC_MAX_DIFF_LINES`] lines per diff,
//!   [`DOC_MAX_BYTES`] for the whole body. What a cap leaves out is replaced by the PD-67 note and
//!   counted in the header's "hidden in preview" bytes.
//! - The document is [`crate::iframe_document`]: meta CSP first, then `preview.css`, and the body
//!   sanitized once more under the document allowlist.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod body;
pub mod raw;
pub mod ws;

pub use raw::{RawDisplay, raw_display, raw_display_last};

use crate::invisible;
use crate::model::{ItemCount, Preview};
use crate::sanitize::{Platform, iframe_document, sanitize_html};
use crate::warning::{Level, Warning, WarningId};

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
    let mut body = Doc::default();
    body::body(&mut body, &p.body);
    // The header's own caps (a list past its row cap, a text past the budget) count too: its
    // "hidden in preview" value is written once the header is done.
    let mut head = Doc::default();
    let hidden_at = header(&mut head, p);
    let hidden = p
        .header
        .hidden_in_preview_bytes
        .saturating_add(body.cut)
        .saturating_add(head.cut);
    head.out.insert_str(hidden_at, &format!("{hidden} bytes"));
    head.out.push_str(&body.out);
    let cut_text = body.cut_text.saturating_add(head.cut_text);
    if cut_text > 0 {
        head.open("p");
        head.fixed(&more_not_shown(cut_text, "bytes"));
        head.close("p");
    }
    iframe_document(&head.out, platform)
}

/// The document being written: HTML text, the bytes a cap left out, and the part of them cut
/// from inside a text.
#[derive(Default)]
pub(crate) struct Doc {
    out: String,
    /// Every byte a cap left out (rows, lines, items, cut texts).
    cut: u64,
    /// The part of `cut` cut from inside a single text (one note at the end of the body).
    cut_text: u64,
    /// `<pre>` elements open.
    pre: u32,
}

/// How [`Doc::value`] frames a value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Frame {
    Plain,
    Code,
    /// In double quotes (a JSON string).
    Quoted,
}

/// A browser collapses this display text's whitespace unless it is in a `<pre>` (or styled):
/// a leading space, a run of spaces, a tab or a newline. Trailing spaces and tabs are escapes
/// already (PD-69).
fn collapses(shown: &str) -> bool {
    shown.starts_with(' ') || shown.contains("  ") || shown.contains(['\t', '\n'])
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
        if tag == "pre" {
            self.pre = self.pre.saturating_add(1);
        }
        self.out.push('<');
        self.out.push_str(tag);
        self.out.push('>');
    }

    pub(crate) fn close(&mut self, tag: &str) {
        if tag == "pre" {
            self.pre = self.pre.saturating_sub(1);
        }
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
    /// `<bdi>` ([`Doc::value`]). Cut at the byte budget (the rest is counted and noted at the end
    /// of the body).
    pub(crate) fn text(&mut self, s: &str) {
        self.value(&ws::visible_value(s), Frame::Plain);
    }

    /// [`Doc::text`] in `<code>`.
    pub(crate) fn code_text(&mut self, s: &str) {
        self.value(&ws::visible_value(s), Frame::Code);
    }

    /// A raw string (diff-free): display-escaped here first, then as [`Doc::text`].
    pub(crate) fn raw_text(&mut self, s: &str) {
        self.text(&invisible::escape_for_display(s));
    }

    /// [`Doc::raw_text`] in `<code>`.
    pub(crate) fn raw_code_text(&mut self, s: &str) {
        self.code_text(&invisible::escape_for_display(s));
    }

    /// [`Doc::raw_text`] in double quotes (a JSON string value).
    pub(crate) fn raw_quoted(&mut self, s: &str) {
        let shown = ws::visible_value(&invisible::escape_for_display(s));
        self.value(&shown, Frame::Quoted);
    }

    /// One diff line (raw): display-escaped, PD-69 line notation, in `<bdi>`. The caller puts
    /// every diff line in a `<pre>`, so a whitespace-only change shows without the stylesheet.
    pub(crate) fn diff_line(&mut self, s: &str) {
        let shown = ws::visible_line(&invisible::escape_for_display(s));
        self.bdi(&shown);
    }

    /// Display text `shown` (whitespace already made visible) framed in `<bdi>`, and in a `<pre>`
    /// around the frame when its whitespace would collapse without the stylesheet and no `<pre>`
    /// is open (T10 review I-1). The `<pre>` starts with an element or a quote, never with the
    /// value's text, so the parser's leading-newline rule cannot eat a newline of the value.
    fn value(&mut self, shown: &str, frame: Frame) {
        let pre = self.pre == 0 && collapses(shown);
        if pre {
            self.open("pre");
        }
        match frame {
            Frame::Plain => self.bdi(shown),
            Frame::Code => {
                self.open("code");
                self.bdi(shown);
                self.close("code");
            }
            Frame::Quoted => {
                self.fixed("\"");
                self.bdi(shown);
                self.fixed("\"");
            }
        }
        if pre {
            self.close("pre");
        }
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
/// first `>` outside quotes. In a tag (only an attribute value, an `alt`, can hold one) a flagged
/// character becomes its `⟨U+XXXX⟩` escape: an attribute cannot hold a `<mark>` (T10 review M-1).
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
                let tag = &rest[..end];
                for (c, flagged) in tag.chars().zip(invisible::flags(tag)) {
                    if flagged {
                        ws::push_escape(out, c);
                    } else {
                        out.push(c);
                    }
                }
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
/// re-review leads with (§5.4 step 5: "Could not re-check target" first), then the rest. Exactly
/// the model's Caution warnings, so the strip shows what `PREVIEW_SHOWN.warning_ids` records
/// (core asserts a body's implied warning is among them:
/// [`crate::PreviewBody::implied_warning`]).
fn caution_lines(p: &Preview) -> Vec<CautionLine<'_>> {
    let mut lines = Vec::new();
    if let Some(text) = p.header.release_blocked {
        lines.push(CautionLine::Fixed(text));
    }
    let (lead, rest): (Vec<&Warning>, Vec<&Warning>) = p
        .warnings
        .iter()
        .filter(|w| w.level == Level::Caution)
        .partition(|w| w.id == WarningId::CouldNotRecheck);
    lines.extend(
        lead.into_iter()
            .chain(rest)
            .map(|w| CautionLine::Text(&w.text)),
    );
    lines
}

enum CautionLine<'a> {
    /// App-generated (core's constant).
    Fixed(&'static str),
    /// A warning text (display-escaped by core where it carries server or agent text).
    Text(&'a str),
}

/// Writes the header; returns where its "hidden in preview" value goes ([`document`] writes it
/// once every cap, the header's own included, is counted).
fn header(doc: &mut Doc, p: &Preview) -> usize {
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
    doc.open("tr");
    doc.el("th", "hidden in preview");
    doc.open("td");
    let hidden_at = doc.out.len();
    doc.close("td");
    doc.close("tr");
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
        doc.code_text(q);
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
        doc.open("div");
        doc.el("strong", INFO_LABEL);
        for (i, w) in infos.iter().enumerate() {
            doc.fixed(if i == 0 { " " } else { "; " });
            doc.text(&w.text);
        }
        doc.close("div");
    }
    doc.close("header");
    hidden_at
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

/// A comma-separated list, each entry in its own `<bdi>`, at most [`DOC_MAX_ROWS`] entries (the
/// rest noted and counted).
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
    if let Some(rest) = items.get(DOC_MAX_ROWS..)
        && !rest.is_empty()
    {
        doc.hide(rest.iter().map(|s| len_u64(s.len())).sum());
        doc.fixed(&format!(
            ", {}",
            more_not_shown(len_u64(rest.len()), "entries")
        ));
    }
    doc.close("td");
    doc.close("tr");
}
