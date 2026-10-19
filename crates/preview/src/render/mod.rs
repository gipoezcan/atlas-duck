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
//!   `ul`, `ol`, `li`, `p`, `div`, `pre`, `code`, `bdi`, `mark`, `strong`), never a `class` or
//!   `style` attribute: `preview.css` styles by element and position. A value that may need a
//!   `<pre>` sits in a `div`, never a `p` (which cannot hold one). The one attribute-bearing
//!   element the renderer itself writes is the attachment thumbnail (M7 Δ2, PD-110):
//!   `<img src="data:image/<raster>;base64,…" alt="">`, emitted through the sanitizer and only
//!   for a raster `data:` URI (a sanitized `*_html` string may still carry a data-raster `<img>`
//!   with `src` and `alt`, T8 review m-4).
//! - Display caps: [`DOC_MAX_ROWS`] rows per table or list, [`DOC_MAX_DIFF_LINES`] lines per diff,
//!   [`DOC_MAX_BYTES`] for the whole body. What a cap leaves out is replaced by the PD-67 note and
//!   counted in the header's "hidden in preview" bytes. A script item's own sections have a
//!   reserved share of the body each ([`DOC_SCRIPT_RESERVE_BYTES`]; the source capped by bytes,
//!   not lines) and notes that name the audit record ([`more_in_audit_record`]).
//! - The document is [`crate::iframe_document`]: meta CSP first, then `preview.css`, and the body
//!   sanitized once more under the document allowlist.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod audit;
mod body;
pub mod raw;
pub mod ws;

pub use audit::{
    AUDIT_TREE_MAX_BYTES, audit_payload_document, audit_payload_page_document, more_in_raw_text,
};
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

/// Bytes of the body reserved for a script item's own sections (M8 T18 review I-1): the source,
/// Host calls, atlas.log (with its note) and stderr are in no other tab, so a candidate view the
/// agent sized cannot crowd them out. Each section has its own share; the view gets the rest of
/// [`DOC_MAX_BYTES`].
pub const DOC_SCRIPT_RESERVE_BYTES: usize = DOC_SCRIPT_SOURCE_BYTES
    + DOC_SCRIPT_CALLS_BYTES
    + DOC_SCRIPT_LOG_BYTES
    + DOC_SCRIPT_NOTE_BYTES
    + DOC_SCRIPT_STDERR_BYTES;
/// Most bytes of the "Script source" section's markup (T18 review I-2: a byte cap, so padding
/// lines cannot hide the tail behind a line count, and empty lines cannot grow the markup past it).
pub const DOC_SCRIPT_SOURCE_BYTES: usize = 1 << 20;
/// Most bytes of the "Host calls" table.
pub const DOC_SCRIPT_CALLS_BYTES: usize = 512 << 10;
/// Most bytes of the atlas.log lines.
pub const DOC_SCRIPT_LOG_BYTES: usize = 384 << 10;
/// Most bytes of the atlas.log note (core's fixed sentence, shown even when the lines filled
/// their share).
pub const DOC_SCRIPT_NOTE_BYTES: usize = 4 << 10;
/// Most bytes of the stderr section.
pub const DOC_SCRIPT_STDERR_BYTES: usize = 128 << 10;

/// plan text (PD-67): "N more rows / lines not shown here; see Structured or Raw", with the unit
/// of what was left out.
pub fn more_not_shown(n: u64, unit: &str) -> String {
    format!("{n} more {unit} not shown here; see Structured or Raw")
}

/// [`more_not_shown`] for a script's own sections (T18 review I-2): the source, Host calls, logs
/// and stderr are in no other tab, the audit record has them.
pub fn more_in_audit_record(n: u64, unit: &str) -> String {
    format!("{n} more {unit} not shown here; the audit record keeps the full text")
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
pub(crate) struct Doc {
    out: String,
    /// Every byte a cap left out (rows, lines, items, cut texts).
    cut: u64,
    /// The part of `cut` cut from inside a single text (one note at the end of the body).
    cut_text: u64,
    /// `<pre>` elements open.
    pre: u32,
    /// Most bytes of `out`: the body budget, or the share of one part of it.
    limit: usize,
    /// A text was cut here: nothing more is written, even when the cut moved back to a
    /// sequence's start and left a few bytes of the budget (ZWJ review M-2).
    exhausted: bool,
    /// A script's own section ([`Doc::record`]): its notes name the audit record.
    record: bool,
    /// Inside a section of the document (a script item's candidate view): headings one level
    /// down.
    nested: bool,
}

impl Default for Doc {
    fn default() -> Self {
        Self::with_limit(DOC_MAX_BYTES)
    }
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
    /// A part of the document with its own byte budget `limit`.
    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            out: String::new(),
            cut: 0,
            cut_text: 0,
            pre: 0,
            limit,
            exhausted: false,
            record: false,
            nested: false,
        }
    }

    /// A script's own section (source, Host calls, atlas.log, stderr) with its share `limit` of
    /// the body (T18 review I-1). What its caps leave out is in no other tab: its notes name the
    /// audit record, a text cut inside it is noted in it ([`Doc::append`]), not at the end of the
    /// body.
    pub(crate) fn record(limit: usize) -> Self {
        Self {
            record: true,
            ..Self::with_limit(limit)
        }
    }

    /// Writes `part` here and counts what its caps left out. A [`Doc::record`] part notes its cut
    /// text at its end first.
    pub(crate) fn append(&mut self, mut part: Doc) {
        if part.record && part.cut_text > 0 {
            let note = part.more(part.cut_text, "bytes");
            part.open("p");
            part.fixed(&note);
            part.close("p");
            part.cut_text = 0;
        }
        self.out.push_str(&part.out);
        self.cut = self.cut.saturating_add(part.cut);
        self.cut_text = self.cut_text.saturating_add(part.cut_text);
    }

    /// The PD-67 note for `n` `unit` left out here.
    pub(crate) fn more(&self, n: u64, unit: &str) -> String {
        if self.record {
            more_in_audit_record(n, unit)
        } else {
            more_not_shown(n, unit)
        }
    }

    /// The heading of a section: `h2`, or `h3` inside a section.
    pub(crate) fn heading(&self) -> &'static str {
        if self.nested { "h3" } else { "h2" }
    }

    /// The byte budget of the body (or of this part) is used up.
    pub(crate) fn full(&self) -> bool {
        self.exhausted || self.out.len() >= self.limit
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

    /// One diff line (raw): display-escaped, PD-69 line notation (the missing-newline mark only
    /// when the line ends its side, `side_end`), in `<bdi>`. The caller puts every diff line in
    /// a `<pre>`, so a whitespace-only change shows without the stylesheet.
    pub(crate) fn diff_line(&mut self, s: &str, side_end: bool) {
        let shown = ws::visible_line_at(&invisible::escape_for_display(s), side_end);
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
        let limit = if self.exhausted { 0 } else { self.limit };
        let left = push_marked(&mut self.out, shown, limit);
        if left > 0 {
            self.exhausted = true;
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
        if self.exhausted || self.out.len().saturating_add(clean.len()) > self.limit {
            let n = len_u64(html.len());
            self.hide(n);
            self.open("p");
            self.fixed(&self.more(n, "bytes"));
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
/// digits), [`ws::NO_NEWLINE_AT_END`], or the PD-68 byte escape `⟨0xHH⟩` of a Raw page (Audit
/// window, M10 T12); `None` for anything else. Text that went through the display escaping holds
/// no literal `⟨`, so none can be forged there. Text that is marked without that escaping first
/// (`mark_text`, the sanitized `*_html` text) can carry a literal `⟨0x41⟩` or `⟨U+0041⟩`; it is
/// then only styled as an escape (a `<mark>`), nothing else follows from it.
fn escape_len(rest: &str) -> Option<usize> {
    if rest.starts_with(ws::NO_NEWLINE_AT_END) {
        return Some(ws::NO_NEWLINE_AT_END.len());
    }
    if let Some(inner) = rest.strip_prefix("⟨0x")
        && inner.len() >= 2
        && inner.as_bytes()[..2]
            .iter()
            .all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F'))
        && inner[2..].starts_with('⟩')
    {
        return Some("⟨0x".len() + 2 + '⟩'.len_utf8());
    }
    invisible::escape_len(rest)
}

/// Writes display text `s` HTML-escaped with every `⟨…⟩` escape (and every flagged character
/// still raw, escaped here) in a `<mark>`, until `out` reaches `limit` bytes. Returns the bytes of
/// `s` left out (0 when all of it fits).
///
/// The flags are those of the whole of `s`, so the cut never splits an emoji sequence that
/// unflags a character (a 👩‍💻 cut before the 💻 left a raw U+200D that the written text flags,
/// M8 S-06 proptest seed): it moves back to the sequence's start. What is written is then
/// classified as it would be on its own, and every byte not written is counted.
fn push_marked(out: &mut String, s: &str, limit: usize) -> u64 {
    let (flags, sequences) = invisible::flags_and_sequences(s);
    let mut sequences = sequences.iter().peekable();
    // The last place a cut keeps every sequence whole: a byte of `s`, and the length of `out`
    // there.
    let mut whole = (0, out.len());
    let mut skip_to = 0;
    for ((i, c), flagged) in s.char_indices().zip(flags) {
        if i < skip_to {
            continue;
        }
        while sequences.next_if(|r| r.end <= i).is_some() {}
        if sequences.peek().is_none_or(|r| r.start >= i) {
            whole = (i, out.len());
        }
        if out.len() >= limit {
            let (at, len) = whole;
            out.truncate(len);
            return len_u64(s.len() - at);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// ZWJ review M-2 (cut review M-7): a text cut back to a sequence's start leaves bytes of the
    /// budget, and `html` must still leave its markup out whole and count it (it would fit).
    #[test]
    fn html_after_a_cut_text_is_left_out_though_it_would_fit() {
        // 35 bytes, one sequence (char boundaries 0 4 8 11 14 17 20 24 27 31 35).
        const KISS: &str =
            "\u{1F469}\u{1F3FB}\u{200D}\u{2764}\u{FE0F}\u{200D}\u{1F48B}\u{200D}\u{1F468}\u{1F3FC}";
        let mut doc = Doc::with_limit(40);
        doc.text(&format!("{}{KISS}", "e".repeat(10)));
        assert!(doc.exhausted);
        // `<bdi>` + ten `e` + `…` + `</bdi>`: the cut moved back to the sequence's start.
        assert_eq!(doc.out, "<bdi>eeeeeeeeee…</bdi>");
        assert_eq!(doc.cut, 35);
        // 8 bytes more still fit the budget: only the cut text keeps them out.
        assert!(doc.out.len() + "<p>x</p>".len() <= doc.limit);
        doc.html("<p>x</p>");
        assert!(!doc.out.contains("<p>x</p>"), "{}", doc.out);
        assert_eq!(doc.cut, 35 + 8);
    }
}
