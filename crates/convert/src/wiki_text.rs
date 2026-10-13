//! Wiki markup → plain text projection (spec §6.3 rendered diff, §7.6; plan Task 5).
//!
//! The text of the same rendering [`crate::wiki_to_preview_html`] produces: one line per
//! block, list items prefixed `• ` / `1. `, table cells joined by ` | `, code bodies verbatim.
//! The helpers shared with the HTML renderer live here so the two cannot disagree on a label.

use crate::wiki::{Block, CodeKind, Inline, parse};

/// Macros that only style their content; the tags are dropped and the content kept.
pub(crate) fn is_styling(name: &str) -> bool {
    ["color", "span"]
        .iter()
        .any(|s| name.eq_ignore_ascii_case(s))
}

/// Longest parameter text shown in a macro label, in characters; the rest is cut and marked.
const MACRO_PARAMS_MAX: usize = 80;

/// The text standing in for a macro (§7.6: macros are never executed or expanded): the name and
/// the parameters, so a retargeted `{include:...}` or `{jira:key=...}` is visible in a diff.
/// Parameters are one line (controls become spaces) and capped with an ellipsis. Styling macros
/// show the name only.
pub(crate) fn macro_label(name: &str, params: &str) -> String {
    let params = params.trim();
    if params.is_empty() || is_styling(name) {
        return format!("[macro: {name}]");
    }
    let mut shown: String = params
        .chars()
        .take(MACRO_PARAMS_MAX)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if params.chars().nth(MACRO_PARAMS_MAX).is_some() {
        shown.push('\u{2026}');
    }
    format!("[macro: {name} {shown}]")
}

/// A link as text: `text (url)`, or just the URL when there is no distinct text.
pub(crate) fn link_label(text: Option<&str>, target: &str) -> String {
    match text.map(decode_refs) {
        Some(t) if !t.is_empty() && t != target => format!("{t} ({target})"),
        _ => target.to_owned(),
    }
}

/// A code body as displayed: the newline after the opening tag and the one before the
/// closing tag are layout, not content.
pub(crate) fn code_display(body: &str) -> &str {
    let b = body
        .strip_prefix("\r\n")
        .or_else(|| body.strip_prefix('\n'))
        .unwrap_or(body);
    b.strip_suffix("\r\n")
        .or_else(|| b.strip_suffix('\n'))
        .unwrap_or(b)
}

/// Characters a numeric reference must not produce: everything the §6.4 classifier flags
/// (Default_Ignorable_Code_Point, Cf, Cc, Zl, Zp) stays as literal reference text. This crate has
/// no `preview` edge, so the set is spelled out as a superset of it (line and paragraph
/// separators, ALM, soft hyphen, CGJ, Hangul fillers, variation selectors, every bidi and
/// zero-width character, tag characters); a test compares it with `preview::invisible`.
fn decodable(c: char) -> bool {
    !(c.is_control()
        || matches!(c,
            '\u{ad}'
                | '\u{34f}'
                | '\u{600}'..='\u{605}'
                | '\u{61c}'
                | '\u{6dd}'
                | '\u{70f}'
                | '\u{890}'..='\u{891}'
                | '\u{8e2}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff0}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0000}'..='\u{e0fff}'))
}

/// Decodes decimal and hex numeric character references (`&#92;`, `&#x5c;`) once. The
/// converter writes them where wiki markup has no escape (`&#92;` for a backslash, `&#126;`
/// for `~`, `&#160;`, …). Malformed references, surrogates, out-of-range values, controls and
/// invisible characters stay literal. Named references are not decoded.
pub(crate) fn decode_refs(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("&#") {
        out.push_str(rest.get(..i).unwrap_or(""));
        let tail = rest.get(i + 2..).unwrap_or("");
        let (radix, digits_from) = match tail.chars().next() {
            Some('x' | 'X') => (16, 1),
            _ => (10, 0),
        };
        let body = tail.get(digits_from..).unwrap_or("");
        let n = body.chars().take_while(|c| c.is_digit(radix)).count();
        let decoded = (n > 0 && n <= 7 && body.get(n..).is_some_and(|r| r.starts_with(';')))
            .then(|| body.get(..n))
            .flatten()
            .and_then(|d| u32::from_str_radix(d, radix).ok())
            .and_then(char::from_u32)
            .filter(|c| decodable(*c));
        match decoded {
            Some(c) => {
                out.push(c);
                // `&#` + optional `x` + digits + `;`
                rest = rest.get(i + 2 + digits_from + n + 1..).unwrap_or("");
            }
            None => {
                out.push_str("&#");
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

fn inlines_text(inlines: &[Inline], out: &mut String) {
    for inline in inlines {
        match inline {
            Inline::Text(t) | Inline::Monospace(t) => out.push_str(&decode_refs(t)),
            Inline::Strong(c) | Inline::Emphasis(c) | Inline::Strike(c) => inlines_text(c, out),
            Inline::Link { text, target } => out.push_str(&link_label(text.as_deref(), target)),
            Inline::Mention(n) => {
                out.push('@');
                out.push_str(n);
            }
            Inline::Image(t) => out.push_str(&format!("[image: {t}]")),
            Inline::Attachment(f) => out.push_str(&format!("[attachment: {f}]")),
            Inline::Macro { name, .. } if is_styling(name) => {}
            Inline::Macro { name, params, .. } => out.push_str(&macro_label(name, params)),
            Inline::LineBreak => out.push('\n'),
        }
    }
}

fn line(inlines: &[Inline]) -> String {
    let mut s = String::new();
    inlines_text(inlines, &mut s);
    s
}

fn blocks_text(blocks: &[Block]) -> String {
    let parts: Vec<String> = blocks
        .iter()
        .map(block_text)
        .filter(|s| !s.is_empty())
        .collect();
    parts.join("\n")
}

fn block_text(block: &Block) -> String {
    match block {
        Block::Heading { inlines, .. } | Block::Paragraph(inlines) => line(inlines),
        Block::List { ordered, items } => {
            let marker = if *ordered { "1. " } else { "• " };
            let mut cur = 0usize;
            let lines: Vec<String> = items
                .iter()
                .map(|(depth, inl)| {
                    // Same clamp as the HTML: a jump of more than one level is one level deeper.
                    cur = usize::from(*depth).clamp(1, cur + 1);
                    let indent = "  ".repeat(cur - 1);
                    format!("{indent}{marker}{}", line(inl))
                })
                .collect();
            lines.join("\n")
        }
        Block::Table { rows } => {
            let lines: Vec<String> = rows
                .iter()
                .map(|r| {
                    let cells: Vec<String> = r.cells.iter().map(|c| line(&c.inlines)).collect();
                    cells.join(" | ")
                })
                .collect();
            lines.join("\n")
        }
        Block::Quote(children) => {
            let inner = blocks_text(children);
            // An empty quote stays visible as a lone `>`.
            if inner.is_empty() {
                return ">".to_owned();
            }
            inner
                .lines()
                .map(|l| format!("> {l}"))
                .collect::<Vec<_>>()
                .join("\n")
        }
        Block::Code {
            kind, lang, body, ..
        } => {
            // The tags are shown (and an empty block is kept) so code vs noformat, the
            // language and the block boundaries are visible in the rendered diff.
            let (name, lang) = match kind {
                CodeKind::Code => ("code", lang.as_deref().filter(|l| !l.is_empty())),
                CodeKind::Noformat => ("noformat", None),
            };
            let open = match lang {
                Some(l) => format!("{{{name}:{l}}}"),
                None => format!("{{{name}}}"),
            };
            let body = code_display(body);
            if body.is_empty() {
                format!("{open}\n{{{name}}}")
            } else {
                format!("{open}\n{body}\n{{{name}}}")
            }
        }
        Block::Panel { title, blocks } => {
            let mut parts = vec![macro_label("panel", "")];
            if let Some(t) = title.as_deref().filter(|t| !t.is_empty()) {
                parts.push(decode_refs(t));
            }
            let inner = blocks_text(blocks);
            if !inner.is_empty() {
                parts.push(inner);
            }
            parts.join("\n")
        }
        Block::Macro {
            name, params, body, ..
        } => match body.as_deref().map(code_display) {
            Some(b) if !b.is_empty() => format!("{}\n{b}", macro_label(name, params)),
            _ => macro_label(name, params),
        },
        Block::Rule => "----".to_owned(),
    }
}

/// The text projection of the preview rendering of `wiki`, used for the Jira rendered diff
/// (§6.3). Pure and deterministic; never fails.
pub fn wiki_to_text(wiki: &str) -> String {
    blocks_text(&parse(wiki).blocks)
}
