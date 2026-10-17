//! Markdown → Confluence storage (spec §7.6, plan Task 5, PD-96).
//!
//! The `pulldown-cmark` event stream (the placeholder check's options: tables, strikethrough,
//! task lists) drives a stack of frames, one per open tag, and is written as XHTML from a fixed
//! set: `<h1>`–`<h6>`, `<p>`, `<em>`, `<strong>`, `<s>`, `<ul>`/`<ol>`/`<li>`,
//! `<table><tbody><tr><th>`/`<td>` (header cells are the first row; no `<thead>`), `<blockquote>`,
//! `<hr/>`, `<br/>`, `<code>`, and `<a href>`. No element carries an attribute other than the
//! `href` of `<a>` (no `start` on `<ol>`, no alignment, no link title): the storage parser's
//! `CONVERTER_HTML` list is exactly this set. All text goes through [`crate::xml_escape`], so
//! Markdown can never produce a macro, a mention, an include, a link or image resource, or any
//! other element:
//! - raw HTML (inline and block) is escaped text; an HTML block keeps its lines (`<br/>`);
//! - links become `<a href>` only for `http:`, `https:` and `mailto:` destinations (ASCII
//!   case-insensitive; an e-mail autolink gets `mailto:`); any other destination is written as
//!   the link text followed by ` (<destination>)` (just the text when the two are equal, just
//!   the destination when the text is blank, just the text when the destination is empty);
//! - images become links the same way (never `ac:image`); an image inside link text is its alt
//!   text;
//! - task-list markers are the literal text `[ ] ` / `[x] `; `@name` is text.
//!
//! Fenced and indented code becomes the code macro
//! `<ac:structured-macro ac:name="code">[<ac:parameter ac:name="language">lang</ac:parameter>]
//! <ac:plain-text-body><![CDATA[…]]></ac:plain-text-body></ac:structured-macro>` (no other
//! attribute or parameter), recorded in [`EmittedConstructs`] as a `CodeMacro` from
//! `<ac:structured-macro` through `</ac:structured-macro>`. The language is the info string's
//! first word when it matches `[A-Za-z0-9+#-]{1,32}` (the pattern storage → Markdown keeps); the
//! body loses one trailing newline, and every `]]>` in it is split as `]]]]><![CDATA[>`.
//!
//! Line ends are normalised to LF first (as an XML parser would). Top-level blocks are
//! separated by one `\n`; nothing else is added between elements. Nesting is written as it is
//! (no bound), so input nested past the storage parser's depth limit yields output the hard
//! check refuses rather than a flattened body. Pure, deterministic, never panics; the output
//! ends without a newline.

use std::borrow::Cow;

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, LinkType, Parser, Tag};

use crate::md_to_wiki::{ContainerKind, EmittedCode, EmittedConstructs};
use crate::placeholders;
use crate::xml_escape;

/// Longest code-macro language kept.
const MAX_LANG: usize = 32;

/// `href` schemes written as `<a>` (PD-96), ASCII case-insensitive; the storage parser accepts
/// exactly these (PD-97 (c)).
const SAFE_SCHEMES: [&str; 3] = ["http:", "https:", "mailto:"];

const CODE_OPEN: &str = "<ac:structured-macro ac:name=\"code\">";
const CODE_CLOSE: &str = "</ac:structured-macro>";

/// Converts Markdown (CommonMark + tables + strikethrough + task lists) to Confluence storage.
/// Pure, deterministic, never panics; the output ends without a newline.
pub fn markdown_to_storage(md: &str) -> (String, EmittedConstructs) {
    let md: Cow<'_, str> = if md.contains('\r') {
        Cow::Owned(md.replace("\r\n", "\n").replace('\r', "\n"))
    } else {
        Cow::Borrowed(md)
    };
    let mut w = Writer::default();
    for ev in Parser::new_ext(&md, placeholders::options()) {
        w.event(ev);
    }
    w.finish()
}

enum Frame {
    /// An element whose start tag is written; its end tag.
    Element(&'static str),
    /// The header row of a table (`<tr>` of `<th>` cells).
    Head,
    /// A code block: its body is collected and written as one code macro at the end.
    Code { lang: Option<String>, body: String },
    /// An HTML block: its raw text is collected and written as escaped text at the end.
    Html(String),
    /// A link; `start` is where its text begins in the output.
    Link {
        dest: String,
        safe: bool,
        start: usize,
    },
    /// An image: alt text is collected raw; `depth` counts tags opened inside it.
    Image {
        dest: String,
        safe: bool,
        plain: bool,
        alt: String,
        depth: usize,
    },
    /// A tag without output of its own.
    Transparent,
}

#[derive(Default)]
struct Writer {
    out: String,
    stack: Vec<Frame>,
    code: Vec<EmittedCode>,
    /// Open link frames (no `<a>` is ever written inside another).
    links: usize,
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
            Some(Frame::Code { body, .. } | Frame::Html(body)) => {
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
            Event::TaskListMarker(done) => self.text(if done { "[x] " } else { "[ ] " }),
            Event::SoftBreak => self.out.push('\n'),
            Event::HardBreak => self.out.push_str("<br/>"),
            Event::Rule => {
                self.block_sep();
                self.out.push_str("<hr/>");
            }
        }
    }

    fn text(&mut self, t: &str) {
        xml_escape::push_text(&mut self.out, t);
    }

    /// One `\n` before a top-level block that follows another.
    fn block_sep(&mut self) {
        if self.stack.is_empty() && !self.out.is_empty() {
            self.out.push('\n');
        }
    }

    fn open(&mut self, start: &str, end: &'static str) -> Frame {
        self.out.push_str(start);
        Frame::Element(end)
    }

    fn start(&mut self, tag: Tag<'_>) {
        self.block_sep();
        let frame = match tag {
            Tag::Paragraph => self.open("<p>", "</p>"),
            Tag::Heading { level, .. } => {
                let (start, end) = heading_tags(level);
                self.open(start, end)
            }
            Tag::BlockQuote(_) => self.open("<blockquote>", "</blockquote>"),
            Tag::CodeBlock(kind) => Frame::Code {
                lang: code_lang(&kind),
                body: String::new(),
            },
            Tag::HtmlBlock => Frame::Html(String::new()),
            Tag::List(Some(_)) => self.open("<ol>", "</ol>"),
            Tag::List(None) => self.open("<ul>", "</ul>"),
            Tag::Item => self.open("<li>", "</li>"),
            Tag::Table(_) => self.open("<table><tbody>", "</tbody></table>"),
            Tag::TableHead => {
                self.head = true;
                self.out.push_str("<tr>");
                Frame::Head
            }
            Tag::TableRow => self.open("<tr>", "</tr>"),
            Tag::TableCell if self.head => self.open("<th>", "</th>"),
            Tag::TableCell => self.open("<td>", "</td>"),
            Tag::Emphasis => self.open("<em>", "</em>"),
            Tag::Strong => self.open("<strong>", "</strong>"),
            Tag::Strikethrough => self.open("<s>", "</s>"),
            Tag::Link {
                link_type,
                dest_url,
                ..
            } => {
                let dest = full_dest(link_type, &dest_url);
                let safe = self.links == 0 && safe_href(&dest);
                if safe {
                    self.out.push_str("<a href=\"");
                    self.out.push_str(&xml_escape::attr(&dest));
                    self.out.push_str("\">");
                }
                self.links += 1;
                Frame::Link {
                    safe,
                    dest,
                    start: self.out.len(),
                }
            }
            Tag::Image {
                link_type,
                dest_url,
                ..
            } => {
                let dest = full_dest(link_type, &dest_url);
                Frame::Image {
                    safe: safe_href(&dest),
                    plain: self.links > 0 || dest.is_empty(),
                    dest,
                    alt: String::new(),
                    depth: 0,
                }
            }
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
                self.out.push_str("</tr>");
            }
            Frame::Code { lang, body } => self.code_macro(lang.as_deref(), &body),
            Frame::Html(raw) => {
                self.out.push_str("<p>");
                for (i, line) in raw.trim_end_matches('\n').split('\n').enumerate() {
                    if i > 0 {
                        self.out.push_str("<br/>");
                    }
                    self.text(line);
                }
                self.out.push_str("</p>");
            }
            Frame::Link { dest, safe, start } => {
                self.links = self.links.saturating_sub(1);
                let written = self.out.get(start..).unwrap_or("");
                let blank = written.trim().is_empty();
                if safe {
                    if blank {
                        self.text(&dest);
                    }
                    self.out.push_str("</a>");
                } else if !dest.is_empty() {
                    let escaped = xml_escape::text(&dest);
                    if blank {
                        self.out.push_str(&escaped);
                    } else if written != escaped {
                        self.out.push_str(" (");
                        self.out.push_str(&escaped);
                        self.out.push(')');
                    }
                }
            }
            Frame::Image {
                dest,
                safe,
                plain,
                alt,
                ..
            } => {
                if plain {
                    self.text(&alt);
                } else if safe {
                    self.out.push_str("<a href=\"");
                    self.out.push_str(&xml_escape::attr(&dest));
                    self.out.push_str("\">");
                    self.text(if alt.trim().is_empty() { &dest } else { &alt });
                    self.out.push_str("</a>");
                } else if alt.trim().is_empty() {
                    self.text(&dest);
                } else {
                    self.text(&alt);
                    self.out.push_str(" (");
                    self.text(&dest);
                    self.out.push(')');
                }
            }
            Frame::Transparent => {}
        }
    }

    /// Writes one code macro and records its range.
    fn code_macro(&mut self, lang: Option<&str>, body: &str) {
        let start = self.out.len();
        self.out.push_str(CODE_OPEN);
        if let Some(l) = lang {
            self.out.push_str("<ac:parameter ac:name=\"language\">");
            self.text(l);
            self.out.push_str("</ac:parameter>");
        }
        self.out.push_str("<ac:plain-text-body>");
        xml_escape::push_cdata(&mut self.out, body.strip_suffix('\n').unwrap_or(body));
        self.out.push_str("</ac:plain-text-body>");
        self.out.push_str(CODE_CLOSE);
        self.code.push(EmittedCode {
            kind: ContainerKind::CodeMacro,
            byte_range: start..self.out.len(),
        });
    }

    fn finish(mut self) -> (String, EmittedConstructs) {
        while !self.stack.is_empty() {
            self.end();
        }
        (
            self.out,
            EmittedConstructs {
                code_blocks: self.code,
            },
        )
    }
}

fn heading_tags(level: HeadingLevel) -> (&'static str, &'static str) {
    match level {
        HeadingLevel::H1 => ("<h1>", "</h1>"),
        HeadingLevel::H2 => ("<h2>", "</h2>"),
        HeadingLevel::H3 => ("<h3>", "</h3>"),
        HeadingLevel::H4 => ("<h4>", "</h4>"),
        HeadingLevel::H5 => ("<h5>", "</h5>"),
        HeadingLevel::H6 => ("<h6>", "</h6>"),
    }
}

/// The destination as sent: `mailto:` added to an e-mail autolink that lacks it.
fn full_dest(link_type: LinkType, dest: &str) -> String {
    if link_type == LinkType::Email && !starts_with_ignore_case(dest, "mailto:") {
        format!("mailto:{dest}")
    } else {
        dest.to_owned()
    }
}

fn safe_href(dest: &str) -> bool {
    SAFE_SCHEMES
        .iter()
        .any(|s| starts_with_ignore_case(dest, s))
}

fn starts_with_ignore_case(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
}

/// The code macro's language: the info string's first word (split at whitespace or `,`) when
/// it matches `[A-Za-z0-9+#-]{1,32}`; none for indented code.
fn code_lang(kind: &CodeBlockKind<'_>) -> Option<String> {
    let CodeBlockKind::Fenced(info) = kind else {
        return None;
    };
    let word = info.split(|c: char| c.is_whitespace() || c == ',').next()?;
    let ok = (1..=MAX_LANG).contains(&word.len())
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'#' | b'-'));
    ok.then(|| word.to_owned())
}
