//! Wiki markup → preview HTML (spec §7.6 "Wiki markup → preview HTML", §6.4; plan Task 5).
//!
//! The renderer emits only structural text elements. Links, images, attachments, mentions and
//! macros appear as escaped text (`text (url)`, `[image: url]`, `[attachment: file]`,
//! `@name`, `[macro: name]`), never as `<a>`, `<img>` or any element that loads or runs
//! something, and styling macros (`{color}`, `{span}`) are dropped. Core still passes the
//! result through `preview::sanitize_html`; this crate has no `preview` edge.

use crate::wiki::{Block, Inline, parse};
use crate::wiki_text::{code_display, decode_refs, is_styling, link_label, macro_label};

/// Escapes text for HTML element content and double-quoted attribute values.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn inlines_html(inlines: &[Inline], out: &mut String) {
    for inline in inlines {
        match inline {
            Inline::Text(t) => out.push_str(&esc(&decode_refs(t))),
            Inline::Strong(c) => wrap("strong", c, out),
            Inline::Emphasis(c) => wrap("em", c, out),
            Inline::Strike(c) => wrap("del", c, out),
            Inline::Monospace(t) => {
                out.push_str("<code>");
                out.push_str(&esc(&decode_refs(t)));
                out.push_str("</code>");
            }
            Inline::Link { text, target } => {
                out.push_str(&esc(&link_label(text.as_deref(), target)));
            }
            Inline::Mention(n) => {
                out.push('@');
                out.push_str(&esc(n));
            }
            Inline::Image(t) => out.push_str(&esc(&format!("[image: {t}]"))),
            Inline::Attachment(f) => out.push_str(&esc(&format!("[attachment: {f}]"))),
            Inline::Macro { name, .. } if is_styling(name) => {}
            Inline::Macro { name, .. } => out.push_str(&esc(&macro_label(name))),
            Inline::LineBreak => out.push_str("<br>"),
        }
    }
}

fn wrap(tag: &str, inlines: &[Inline], out: &mut String) {
    out.push('<');
    out.push_str(tag);
    out.push('>');
    inlines_html(inlines, out);
    out.push_str("</");
    out.push_str(tag);
    out.push('>');
}

fn inline_string(inlines: &[Inline]) -> String {
    let mut s = String::new();
    inlines_html(inlines, &mut s);
    s
}

fn list_html(ordered: bool, items: &[(u8, Vec<Inline>)]) -> String {
    let tag = if ordered { "ol" } else { "ul" };
    let mut out = String::new();
    let mut cur = 0usize;
    for (depth, inlines) in items {
        // A jump of more than one level is shown as one level deeper.
        let level = usize::from(*depth).clamp(1, cur + 1);
        if level > cur {
            out.push_str(&format!("<{tag}>"));
        } else {
            out.push_str("</li>");
            while cur > level {
                out.push_str(&format!("</{tag}></li>"));
                cur -= 1;
            }
        }
        cur = level;
        out.push_str("<li>");
        inlines_html(inlines, &mut out);
    }
    if cur > 0 {
        out.push_str("</li>");
        while cur > 1 {
            out.push_str(&format!("</{tag}></li>"));
            cur -= 1;
        }
        out.push_str(&format!("</{tag}>"));
    }
    out
}

fn blocks_html(blocks: &[Block]) -> String {
    let parts: Vec<String> = blocks.iter().map(block_html).collect();
    parts.join("\n")
}

fn block_html(block: &Block) -> String {
    match block {
        Block::Heading { level, inlines } => {
            let n = (*level).clamp(1, 6);
            format!("<h{n}>{}</h{n}>", inline_string(inlines))
        }
        Block::Paragraph(inlines) => format!("<p>{}</p>", inline_string(inlines)),
        Block::List { ordered, items } => list_html(*ordered, items),
        Block::Table { rows } => {
            let mut out = String::from("<table>");
            for row in rows {
                out.push_str("<tr>");
                for cell in &row.cells {
                    let tag = if cell.header { "th" } else { "td" };
                    out.push_str(&format!("<{tag}>{}</{tag}>", inline_string(&cell.inlines)));
                }
                out.push_str("</tr>");
            }
            out.push_str("</table>");
            out
        }
        Block::Quote(children) => format!("<blockquote>{}</blockquote>", blocks_html(children)),
        Block::Code { body, .. } => format!("<pre>{}</pre>", esc(code_display(body))),
        Block::Panel { title, blocks } => {
            let mut out = labelled_open("panel");
            if let Some(t) = title.as_deref().filter(|t| !t.is_empty()) {
                out.push_str(&format!("<p>{}</p>", esc(&decode_refs(t))));
            }
            if !blocks.is_empty() {
                out.push('\n');
                out.push_str(&blocks_html(blocks));
            }
            out.push_str("</div>");
            out
        }
        Block::Macro { name, body, .. } => {
            let mut out = labelled_open(name);
            if let Some(b) = body.as_deref().map(code_display).filter(|b| !b.is_empty()) {
                out.push_str(&format!("<pre>{}</pre>", esc(b)));
            }
            out.push_str("</div>");
            out
        }
        Block::Rule => "<hr>".to_owned(),
    }
}

/// `<div data-macro="name"><p>[macro: name]</p>`: the labelled block a macro becomes.
fn labelled_open(name: &str) -> String {
    format!(
        "<div data-macro=\"{}\"><p>{}</p>",
        esc(name),
        esc(&macro_label(name))
    )
}

/// Renders Jira wiki markup as inert preview HTML (§7.6). Pure and deterministic; never fails.
pub fn wiki_to_preview_html(wiki: &str) -> String {
    blocks_html(&parse(wiki).blocks)
}
