//! Wiki markup → plain text projection (spec §6.3 rendered diff, §7.6; plan Task 5).
//!
//! The text of the same rendering [`crate::wiki_to_preview_html`] produces: one line per
//! block, list items prefixed `• ` / `1. `, table cells joined by ` | `, code bodies verbatim.
//! The helpers shared with the HTML renderer live here so the two cannot disagree on a label.

use crate::wiki::{Block, Inline, parse};

/// Macros that only style their content; the tags are dropped and the content kept.
pub(crate) fn is_styling(name: &str) -> bool {
    ["color", "span"]
        .iter()
        .any(|s| name.eq_ignore_ascii_case(s))
}

/// The text standing in for a macro (§7.6: macros are never executed or expanded).
pub(crate) fn macro_label(name: &str) -> String {
    format!("[macro: {name}]")
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

/// Characters a numeric reference must not produce: controls and the invisible or bidi
/// formatting characters the §6.4 classifier warns about stay as literal reference text.
fn decodable(c: char) -> bool {
    !(c.is_control()
        || matches!(c,
            '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}'))
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
            Inline::Macro { name, .. } => out.push_str(&macro_label(name)),
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
            let lines: Vec<String> = items
                .iter()
                .map(|(depth, inl)| {
                    let indent = "  ".repeat(usize::from(*depth).saturating_sub(1));
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
        Block::Quote(children) => blocks_text(children)
            .lines()
            .map(|l| format!("> {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
        Block::Code { body, .. } => code_display(body).to_owned(),
        Block::Panel { title, blocks } => {
            let mut parts = vec![macro_label("panel")];
            if let Some(t) = title.as_deref().filter(|t| !t.is_empty()) {
                parts.push(decode_refs(t));
            }
            let inner = blocks_text(blocks);
            if !inner.is_empty() {
                parts.push(inner);
            }
            parts.join("\n")
        }
        Block::Macro { name, body, .. } => match body.as_deref().map(code_display) {
            Some(b) if !b.is_empty() => format!("{}\n{b}", macro_label(name)),
            _ => macro_label(name),
        },
        Block::Rule => "----".to_owned(),
    }
}

/// The text projection of the preview rendering of `wiki`, used for the Jira rendered diff
/// (§6.3). Pure and deterministic; never fails.
pub fn wiki_to_text(wiki: &str) -> String {
    blocks_text(&parse(wiki).blocks)
}
