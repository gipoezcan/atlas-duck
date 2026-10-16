//! Markdown → preview HTML (spec §6.3 Confluence page "Rendered Markdown", §6.4; plan Task 7,
//! PD-94).
//!
//! An in-house renderer over the `pulldown-cmark` event stream (the options Markdown → storage
//! uses: tables, strikethrough, task lists), like [`crate::wiki_to_preview_html`]: the `html`
//! feature stays off and the output never trusts converter or agent text as markup. It writes
//! only `<h1>`–`<h6>`, `<p>`, `<br>`, `<hr>`, `<strong>`, `<em>`, `<del>`, `<code>`, `<pre>`,
//! `<blockquote>`, `<ul>`/`<ol>`/`<li>` and `<table>`/`<thead>`/`<tbody>`/`<tr>`/`<th>`/`<td>`,
//! never with an attribute (no `start` on `<ol>`, no alignment, no language class). All text
//! is HTML-escaped:
//! - links are text, `text (url)`: just the text when it equals the URL or the URL is empty,
//!   just the URL when the text is blank;
//! - images are text, `[image: src]`, or `[image: alt (src)]` when the alt text is not blank
//!   and differs from the source (Markdown → storage sends the alt text as link text);
//! - raw HTML (inline and block) is escaped text, a block keeping its lines (`<br>`);
//! - task-list markers are the text `☐ ` / `☑ `; placeholders (`[macro: …]`, `@user:…`) are
//!   plain text.
//!
//! The nesting follows the event stream, so it is always well formed and in the form
//! `preview::sanitize_html` keeps; core still passes the result through it. Pure,
//! deterministic, never panics.

use pulldown_cmark::{Event, HeadingLevel, Parser, Tag};

use crate::placeholders;

/// Renders Markdown as inert preview HTML (PD-94). Every block ends with `\n`; empty Markdown
/// gives an empty string.
pub fn markdown_to_preview_html(md: &str) -> String {
    let mut w = Writer::default();
    for ev in Parser::new_ext(md, placeholders::options()) {
        w.event(ev);
    }
    w.finish()
}

enum Frame {
    /// An element whose start tag is written; its end tag (with a following `\n` for blocks).
    Element(&'static str),
    /// A table: whether its `<tbody>` is open.
    Table { body: bool },
    /// The header row of a table (`<thead><tr>` of `<th>` cells).
    Head,
    /// A code block: its text, written escaped at the end.
    Code(String),
    /// An HTML block: its raw text, written as escaped lines at the end.
    Html(String),
    /// A link; `start` is where its text begins in the output.
    Link { dest: String, start: usize },
    /// An image: alt text collected raw; `depth` counts tags opened inside it.
    Image {
        dest: String,
        alt: String,
        depth: usize,
    },
    /// A tag without output of its own (its content is still written).
    Transparent,
}

#[derive(Default)]
struct Writer {
    out: String,
    stack: Vec<Frame>,
    /// Inside a table's header row.
    head: bool,
}

impl Writer {
    fn event(&mut self, ev: Event<'_>) {
        match self.stack.last_mut() {
            Some(Frame::Image { alt, depth, .. }) => {
                match ev {
                    Event::Start(_) => *depth += 1,
                    Event::End(_) if *depth > 0 => *depth -= 1,
                    Event::End(_) => self.end(),
                    Event::Text(t)
                    | Event::Code(t)
                    | Event::Html(t)
                    | Event::InlineHtml(t)
                    | Event::InlineMath(t)
                    | Event::DisplayMath(t)
                    | Event::FootnoteReference(t) => alt.push_str(&t),
                    Event::SoftBreak | Event::HardBreak => alt.push(' '),
                    Event::Rule | Event::TaskListMarker(_) => {}
                }
                return;
            }
            // Only text reaches a code or HTML block; anything else would be an impossible
            // state and is dropped (it never becomes markup).
            Some(Frame::Code(body) | Frame::Html(body)) => {
                match ev {
                    Event::Text(t) | Event::Html(t) | Event::InlineHtml(t) => body.push_str(&t),
                    Event::End(_) => self.end(),
                    _ => {}
                }
                return;
            }
            _ => {}
        }
        match ev {
            Event::Start(tag) => self.start(tag),
            Event::End(_) => self.end(),
            Event::Text(t) | Event::Html(t) | Event::InlineHtml(t) => self.text(&t),
            Event::Code(t) => {
                self.out.push_str("<code>");
                self.text(&t);
                self.out.push_str("</code>");
            }
            Event::InlineMath(t) => self.text(&format!("${t}$")),
            Event::DisplayMath(t) => self.text(&format!("$${t}$$")),
            Event::FootnoteReference(t) => self.text(&format!("[^{t}]")),
            Event::TaskListMarker(done) => self.text(if done { "☑ " } else { "☐ " }),
            Event::SoftBreak => self.out.push('\n'),
            Event::HardBreak => self.out.push_str("<br>"),
            Event::Rule => self.out.push_str("<hr>\n"),
        }
    }

    fn text(&mut self, t: &str) {
        push_escaped(&mut self.out, t);
    }

    fn open(&mut self, start: &str, end: &'static str) -> Frame {
        self.out.push_str(start);
        Frame::Element(end)
    }

    fn start(&mut self, tag: Tag<'_>) {
        let frame = match tag {
            Tag::Paragraph => self.open("<p>", "</p>\n"),
            Tag::Heading { level, .. } => {
                let (start, end) = heading_tags(level);
                self.open(start, end)
            }
            Tag::BlockQuote(_) => self.open("<blockquote>\n", "</blockquote>\n"),
            Tag::CodeBlock(_) => Frame::Code(String::new()),
            Tag::HtmlBlock => Frame::Html(String::new()),
            Tag::List(Some(_)) => self.open("<ol>\n", "</ol>\n"),
            Tag::List(None) => self.open("<ul>\n", "</ul>\n"),
            Tag::Item => self.open("<li>", "</li>\n"),
            Tag::Table(_) => {
                self.out.push_str("<table>\n");
                Frame::Table { body: false }
            }
            Tag::TableHead => {
                self.head = true;
                self.out.push_str("<thead>\n<tr>");
                Frame::Head
            }
            Tag::TableRow => {
                if let Some(Frame::Table { body }) = self.stack.last_mut()
                    && !*body
                {
                    *body = true;
                    self.out.push_str("<tbody>\n");
                }
                self.open("<tr>", "</tr>\n")
            }
            Tag::TableCell if self.head => self.open("<th>", "</th>"),
            Tag::TableCell => self.open("<td>", "</td>"),
            Tag::Emphasis => self.open("<em>", "</em>"),
            Tag::Strong => self.open("<strong>", "</strong>"),
            Tag::Strikethrough => self.open("<del>", "</del>"),
            Tag::Link { dest_url, .. } => Frame::Link {
                dest: dest_url.into_string(),
                start: self.out.len(),
            },
            Tag::Image { dest_url, .. } => Frame::Image {
                dest: dest_url.into_string(),
                alt: String::new(),
                depth: 0,
            },
            _ => Frame::Transparent,
        };
        self.stack.push(frame);
    }

    fn end(&mut self) {
        let Some(frame) = self.stack.pop() else {
            return;
        };
        match frame {
            Frame::Element(end) => self.out.push_str(end),
            Frame::Head => {
                self.head = false;
                self.out.push_str("</tr>\n</thead>\n");
            }
            Frame::Table { body } => {
                if body {
                    self.out.push_str("</tbody>\n");
                }
                self.out.push_str("</table>\n");
            }
            Frame::Code(body) => {
                self.out.push_str("<pre><code>");
                self.text(body.strip_suffix('\n').unwrap_or(&body));
                self.out.push_str("</code></pre>\n");
            }
            Frame::Html(raw) => {
                self.out.push_str("<p>");
                for (i, line) in raw.trim_end_matches('\n').split('\n').enumerate() {
                    if i > 0 {
                        self.out.push_str("<br>");
                    }
                    self.text(line);
                }
                self.out.push_str("</p>\n");
            }
            Frame::Link { dest, start } => {
                let written = self.out.get(start..).unwrap_or("");
                if written.trim().is_empty() {
                    self.text(&dest);
                } else if !dest.is_empty() {
                    let escaped = escaped(&dest);
                    if written != escaped {
                        self.out.push_str(" (");
                        self.out.push_str(&escaped);
                        self.out.push(')');
                    }
                }
            }
            Frame::Image { dest, alt, .. } => {
                let label = if alt.trim().is_empty() || alt == dest {
                    format!("[image: {dest}]")
                } else if dest.is_empty() {
                    format!("[image: {alt}]")
                } else {
                    format!("[image: {alt} ({dest})]")
                };
                self.text(&label);
            }
            Frame::Transparent => {}
        }
    }

    fn finish(mut self) -> String {
        while !self.stack.is_empty() {
            self.end();
        }
        self.out
    }
}

fn heading_tags(level: HeadingLevel) -> (&'static str, &'static str) {
    match level {
        HeadingLevel::H1 => ("<h1>", "</h1>\n"),
        HeadingLevel::H2 => ("<h2>", "</h2>\n"),
        HeadingLevel::H3 => ("<h3>", "</h3>\n"),
        HeadingLevel::H4 => ("<h4>", "</h4>\n"),
        HeadingLevel::H5 => ("<h5>", "</h5>\n"),
        HeadingLevel::H6 => ("<h6>", "</h6>\n"),
    }
}

/// Escapes text for HTML element content (and attribute values, which this renderer never
/// writes): `&`, `<`, `>`, `"`, `'`.
fn push_escaped(out: &mut String, s: &str) {
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
}

fn escaped(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    push_escaped(&mut out, s);
    out
}
