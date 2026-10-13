//! Markdown → Jira wiki markup (spec §7.6, plan Task 3, PD-43, PD-44).
//!
//! The `pulldown-cmark` event stream drives a stack of frames, one per open tag. All text
//! goes through [`crate::escape`], so Markdown can never produce a macro, mention, include,
//! image or attachment link. Beyond the escaping:
//! - Code bodies (fenced, indented): `{code[:lang]}` (lang only when Jira has a formatter, see
//!   `code_lang`) unless the body contains `{code`
//!   (ASCII case-insensitive), else `{noformat}` unless it also contains `{noformat`, else
//!   escaped monospace lines (`{{…}}` per line, an empty line as `{{&#160;}}`). Inline code is
//!   always escaped `{{…}}`.
//! - Block quotes: one paragraph → `bq. ` (line breaks as `\\`); several blocks → a
//!   `{quote}` container. `{quote}` cannot nest, so a quote inside a quote is written flat
//!   (paragraphs as `bq. ` lines, other blocks as they are), and so is a quote whose rendered
//!   content holds a `{quote` tag (`{`, optional whitespace, `quote`; ASCII case-insensitive)
//!   anywhere: in a code body, or as
//!   escaped prose `\{quote\}` (Jira's search for the closing tag may not honour escapes).
//! - Images become links `[alt|url]` (PD-44); raw HTML is escaped text; link targets are
//!   percent-encoded where the wiki grammar would read them.
//! - A list item is one line: its first paragraph, further paragraphs appended after `\\`.
//!   Other blocks inside an item (code, quotes, tables, …) follow it as blocks of their own.
//!
//! Every `{code}`, `{noformat}` and `{quote}` container written is recorded with its byte
//! range (opening `{` through the closing tag's `}`), sorted by start. Quotes, lists and
//! emphasis nested deeper than [`MAX_DEPTH`] are flattened, so the cost stays linear.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::ops::Range;

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, LinkType, Options, Parser, Tag};

use crate::escape::{Out, SpanMark};

/// Nesting bound for quotes plus lists, and for emphasis.
const MAX_DEPTH: usize = 32;

/// Longest code-block language kept in `{code:lang}`.
const MAX_LANG: usize = 32;

/// A container the converter wrote itself (Δ1, widened by the T2 ruling: `{quote}` too).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContainerKind {
    Code,
    Noformat,
    Quote,
}

/// One recorded container: `byte_range` runs from its opening `{` through the closing tag's
/// `}` in the converter's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedCode {
    pub kind: ContainerKind,
    pub byte_range: Range<usize>,
}

/// The containers of one conversion, sorted by start (a `{code}` inside a `{quote}` follows
/// the quote).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EmittedConstructs {
    pub code_blocks: Vec<EmittedCode>,
}

/// Converts Markdown (CommonMark + tables + strikethrough) to Jira wiki markup. Pure,
/// deterministic, never panics; the output ends with exactly one `\n`.
pub fn markdown_to_wiki(md: &str) -> (String, EmittedConstructs) {
    let md: Cow<'_, str> = if md.contains('\r') {
        Cow::Owned(md.replace("\r\n", "\n").replace('\r', "\n"))
    } else {
        Cow::Borrowed(md)
    };
    let mut c = Converter::default();
    for ev in Parser::new_ext(&md, Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH) {
        c.event(ev);
    }
    c.finish()
}

/// Rendered wiki text with its containers (ranges relative to `text`).
#[derive(Debug, Default)]
struct Rendered {
    text: String,
    containers: Vec<EmittedCode>,
}

impl Rendered {
    fn plain(text: String) -> Rendered {
        Rendered {
            text,
            containers: Vec::new(),
        }
    }

    fn container(kind: ContainerKind, text: String) -> Rendered {
        let byte_range = 0..text.len();
        Rendered {
            text,
            containers: vec![EmittedCode { kind, byte_range }],
        }
    }

    fn append(&mut self, other: Rendered) {
        let off = self.text.len();
        self.text.push_str(&other.text);
        self.containers
            .extend(other.containers.into_iter().map(|c| EmittedCode {
                kind: c.kind,
                byte_range: c.byte_range.start + off..c.byte_range.end + off,
            }));
    }

    fn is_blank(&self) -> bool {
        self.containers.is_empty() && self.text.trim().is_empty()
    }
}

/// Blocks separated by blank lines.
fn join(blocks: impl IntoIterator<Item = Rendered>) -> Rendered {
    let mut out = Rendered::default();
    for (i, b) in blocks.into_iter().enumerate() {
        if i > 0 {
            out.text.push_str("\n\n");
        }
        out.append(b);
    }
    out
}

fn para(o: Out) -> Rendered {
    Rendered::plain(o.into_string().trim_end().to_owned())
}

/// A block of a document or quote; `para` = a paragraph (may become a `bq. ` line).
struct Child {
    r: Rendered,
    para: bool,
}

/// Output of lists: item lines (joined by newlines) and blocks (set off by blank lines).
enum Piece {
    Line(String),
    Block(Rendered),
}

fn render_pieces(pieces: Vec<Piece>) -> Rendered {
    let mut out = Rendered::default();
    let mut prev_line: Option<bool> = None;
    for p in pieces {
        let line = matches!(p, Piece::Line(_));
        match prev_line {
            Some(true) if line => out.text.push('\n'),
            Some(_) => out.text.push_str("\n\n"),
            None => {}
        }
        match p {
            Piece::Line(l) => out.text.push_str(&l),
            Piece::Block(b) => out.append(b),
        }
        prev_line = Some(line);
    }
    out
}

/// Blocks of the document or of a quote; `tail` takes inline content outside a paragraph.
#[derive(Default)]
struct BlockList {
    children: Vec<Child>,
    tail: Option<Out>,
}

impl BlockList {
    fn flush(&mut self) {
        if let Some(t) = self.tail.take() {
            let r = para(t);
            if !r.is_blank() {
                self.children.push(Child { r, para: true });
            }
        }
    }

    fn push(&mut self, r: Rendered, para: bool) {
        self.flush();
        if !r.is_blank() {
            self.children.push(Child { r, para });
        }
    }

    fn sink(&mut self) -> &mut Out {
        self.tail.get_or_insert_with(Out::para)
    }
}

/// A list item: its line, then any blocks and nested list lines in order.
struct Item {
    prefix: String,
    line: Out,
    pieces: Vec<Piece>,
    tail: Option<Out>,
}

impl Item {
    fn flush(&mut self) {
        if let Some(t) = self.tail.take() {
            let r = para(t);
            if !r.is_blank() {
                self.pieces.push(Piece::Block(r));
            }
        }
    }

    fn push_block(&mut self, r: Rendered) {
        self.flush();
        if !r.is_blank() {
            self.pieces.push(Piece::Block(r));
        }
    }

    fn sink(&mut self) -> &mut Out {
        if self.pieces.is_empty() {
            &mut self.line
        } else {
            self.tail.get_or_insert_with(Out::para)
        }
    }

    fn finish(mut self) -> Vec<Piece> {
        self.flush();
        let text = self.line.as_str().trim().to_owned();
        let mut out = Vec::with_capacity(self.pieces.len() + 1);
        if !text.is_empty() || self.pieces.is_empty() {
            out.push(Piece::Line(format!("{} {text}", self.prefix)));
        }
        out.extend(self.pieces);
        out
    }
}

enum Frame {
    Doc(BlockList),
    Quote {
        blocks: BlockList,
        nested: bool,
    },
    List {
        prefix: String,
        pieces: Vec<Piece>,
    },
    Item(Item),
    /// A paragraph written into its item's line.
    ItemPara,
    Para(Out),
    Heading {
        level: u8,
        out: Out,
    },
    Code {
        lang: Option<String>,
        body: String,
    },
    Html(String),
    Table {
        rows: Vec<String>,
        cells: Vec<String>,
    },
    Row {
        header: bool,
    },
    Cell(Out),
    Span {
        delim: char,
        mark: SpanMark,
    },
    Link {
        target: String,
        out: Out,
    },
    /// Alt text is collected raw; `depth` counts tags opened inside the image.
    Image {
        target: String,
        alt: String,
        depth: usize,
        plain: bool,
    },
    /// A tag without output of its own (or beyond the nesting bound).
    Transparent,
}

struct Converter {
    stack: Vec<Frame>,
    /// Stack indices of the frames that take inline content (the last one does).
    owners: Vec<usize>,
    /// Stack indices of the frames that take blocks.
    collectors: Vec<usize>,
    lists: Vec<usize>,
    tables: Vec<usize>,
    quotes: usize,
    spans: usize,
    links: usize,
    /// Consecutive text events, escaped as one text: the escaping looks ahead, and pulldown
    /// splits text at escapes and entities (`h1\.` is `h1` + `.`).
    pending: String,
}

impl Default for Converter {
    fn default() -> Converter {
        Converter {
            stack: vec![Frame::Doc(BlockList::default())],
            owners: vec![0],
            collectors: vec![0],
            lists: Vec::new(),
            tables: Vec::new(),
            quotes: 0,
            spans: 0,
            links: 0,
            pending: String::new(),
        }
    }
}

impl Converter {
    fn push_frame(&mut self, f: Frame) {
        let idx = self.stack.len();
        match &f {
            Frame::Doc(_) | Frame::Item(_) => {
                self.owners.push(idx);
                self.collectors.push(idx);
            }
            Frame::Quote { .. } => {
                self.owners.push(idx);
                self.collectors.push(idx);
                self.quotes += 1;
            }
            Frame::List { .. } => {
                self.collectors.push(idx);
                self.lists.push(idx);
            }
            Frame::Para(_) | Frame::Heading { .. } | Frame::Cell(_) => self.owners.push(idx),
            Frame::Link { .. } => {
                self.owners.push(idx);
                self.links += 1;
            }
            Frame::Table { .. } => self.tables.push(idx),
            Frame::Span { .. } => self.spans += 1,
            _ => {}
        }
        self.stack.push(f);
    }

    /// Pops the top frame; the document frame stays.
    fn pop_frame(&mut self) -> Option<Frame> {
        if self.stack.len() <= 1 {
            return None;
        }
        let f = self.stack.pop()?;
        let idx = self.stack.len();
        for s in [
            &mut self.owners,
            &mut self.collectors,
            &mut self.lists,
            &mut self.tables,
        ] {
            if s.last() == Some(&idx) {
                s.pop();
            }
        }
        match &f {
            Frame::Quote { .. } => self.quotes = self.quotes.saturating_sub(1),
            Frame::Link { .. } => self.links = self.links.saturating_sub(1),
            Frame::Span { .. } => self.spans = self.spans.saturating_sub(1),
            _ => {}
        }
        Some(f)
    }

    /// Where inline content goes.
    fn sink(&mut self) -> Option<&mut Out> {
        let idx = *self.owners.last()?;
        match self.stack.get_mut(idx)? {
            Frame::Doc(b) | Frame::Quote { blocks: b, .. } => Some(b.sink()),
            Frame::Item(it) => Some(it.sink()),
            Frame::Para(o) | Frame::Heading { out: o, .. } | Frame::Cell(o) => Some(o),
            Frame::Link { out, .. } => Some(out),
            _ => None,
        }
    }

    fn push_block(&mut self, r: Rendered, para: bool) {
        let Some(&idx) = self.collectors.last() else {
            return;
        };
        match self.stack.get_mut(idx) {
            Some(Frame::Doc(b) | Frame::Quote { blocks: b, .. }) => b.push(r, para),
            Some(Frame::Item(it)) => it.push_block(r),
            Some(Frame::List { pieces, .. }) if !r.is_blank() => pieces.push(Piece::Block(r)),
            _ => {}
        }
    }

    fn push_pieces(&mut self, new: Vec<Piece>) {
        let Some(&idx) = self.collectors.last() else {
            return;
        };
        match self.stack.get_mut(idx) {
            Some(Frame::Doc(b) | Frame::Quote { blocks: b, .. }) => {
                b.push(render_pieces(new), false);
            }
            Some(Frame::Item(it)) => {
                it.flush();
                it.pieces.extend(new);
            }
            Some(Frame::List { pieces, .. }) => pieces.extend(new),
            _ => {}
        }
    }

    fn depth(&self) -> usize {
        self.quotes + self.lists.len()
    }

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
            Some(Frame::Code { body, .. } | Frame::Html(body)) => match ev {
                Event::Text(t) | Event::Html(t) | Event::InlineHtml(t) => {
                    body.push_str(&t);
                    return;
                }
                Event::End(_) => {
                    self.end();
                    return;
                }
                _ => {}
            },
            _ => {}
        }
        if let Event::Text(t) | Event::Html(t) | Event::InlineHtml(t) = &ev {
            self.pending.push_str(t);
            return;
        }
        self.flush_text();
        match ev {
            Event::Start(tag) => self.start(tag),
            Event::End(_) => self.end(),
            Event::Text(t) | Event::Html(t) | Event::InlineHtml(t) => self.text(&t),
            Event::Code(t) => self.inline_code(&t),
            Event::InlineMath(t) => self.text(&format!("${t}$")),
            Event::DisplayMath(t) => self.text(&format!("$${t}$$")),
            Event::FootnoteReference(t) => self.text(&format!("[^{t}]")),
            Event::TaskListMarker(done) => self.text(if done { "[x] " } else { "[ ] " }),
            Event::SoftBreak => {
                if let Some(o) = self.sink() {
                    o.soft_break();
                }
            }
            Event::HardBreak => {
                if let Some(o) = self.sink() {
                    o.hard_break();
                }
            }
            Event::Rule => self.push_block(Rendered::plain("----".to_owned()), false),
        }
    }

    fn text(&mut self, t: &str) {
        if let Some(o) = self.sink() {
            o.text(t);
        }
    }

    fn flush_text(&mut self) {
        if !self.pending.is_empty() {
            let t = std::mem::take(&mut self.pending);
            self.text(&t);
        }
    }

    fn inline_code(&mut self, t: &str) {
        if t.is_empty() {
            return;
        }
        if let Some(o) = self.sink() {
            o.raw("{{");
            o.text_one_line(t);
            o.raw("}}");
        }
    }

    fn start(&mut self, tag: Tag<'_>) {
        let frame = match tag {
            Tag::Paragraph => self.paragraph(),
            Tag::Heading { level, .. } => Frame::Heading {
                level: heading_level(level),
                out: Out::inline(' '),
            },
            Tag::BlockQuote(_) if self.depth() < MAX_DEPTH => Frame::Quote {
                blocks: BlockList::default(),
                nested: self.quotes > 0,
            },
            Tag::CodeBlock(kind) => Frame::Code {
                lang: code_lang(&kind),
                body: String::new(),
            },
            Tag::HtmlBlock => Frame::Html(String::new()),
            Tag::List(start) if self.depth() < MAX_DEPTH => Frame::List {
                prefix: self.list_prefix(start.is_some()),
                pieces: Vec::new(),
            },
            Tag::Item => Frame::Item(Item {
                prefix: self.item_prefix(),
                line: Out::inline(' '),
                pieces: Vec::new(),
                tail: None,
            }),
            Tag::Table(_) => Frame::Table {
                rows: Vec::new(),
                cells: Vec::new(),
            },
            Tag::TableHead => Frame::Row { header: true },
            Tag::TableRow => Frame::Row { header: false },
            Tag::TableCell => Frame::Cell(Out::inline('|')),
            Tag::Emphasis => self.span('_'),
            Tag::Strong => self.span('*'),
            Tag::Strikethrough => self.span('-'),
            Tag::Link {
                link_type,
                dest_url,
                ..
            } if self.links == 0 && !dest_url.is_empty() => Frame::Link {
                target: link_target(link_type, &dest_url),
                out: Out::link(),
            },
            Tag::Image {
                link_type,
                dest_url,
                ..
            } => Frame::Image {
                plain: self.links > 0 || dest_url.is_empty(),
                target: link_target(link_type, &dest_url),
                alt: String::new(),
                depth: 0,
            },
            _ => Frame::Transparent,
        };
        self.push_frame(frame);
    }

    /// A paragraph directly in an item without blocks so far is written into its line.
    fn paragraph(&mut self) -> Frame {
        if let Some(&idx) = self.collectors.last()
            && let Some(Frame::Item(it)) = self.stack.get_mut(idx)
            && it.pieces.is_empty()
        {
            if !it.line.is_blank() {
                it.line.raw("\\\\");
            }
            return Frame::ItemPara;
        }
        Frame::Para(Out::para())
    }

    fn span(&mut self, delim: char) -> Frame {
        if self.spans >= MAX_DEPTH {
            return Frame::Transparent;
        }
        match self.sink() {
            Some(o) => Frame::Span {
                delim,
                mark: o.open_span(delim),
            },
            None => Frame::Transparent,
        }
    }

    /// `*`/`#` run of a new list: its item's prefix plus its own marker.
    fn list_prefix(&self, ordered: bool) -> String {
        let marker = if ordered { '#' } else { '*' };
        let mut prefix = match self.collectors.last().and_then(|&i| self.stack.get(i)) {
            Some(Frame::Item(it)) => it.prefix.clone(),
            _ => String::new(),
        };
        prefix.push(marker);
        prefix
    }

    fn item_prefix(&self) -> String {
        match self.lists.last().and_then(|&i| self.stack.get(i)) {
            Some(Frame::List { prefix, .. }) => prefix.clone(),
            _ => "*".to_owned(),
        }
    }

    fn end(&mut self) {
        let Some(frame) = self.pop_frame() else {
            return;
        };
        match frame {
            Frame::Doc(_) | Frame::ItemPara | Frame::Transparent => {}
            Frame::Quote { blocks, nested } => {
                let r = quote(blocks, nested);
                self.push_block(r, false);
            }
            Frame::List { pieces, .. } => self.push_pieces(pieces),
            Frame::Item(it) => {
                let pieces = it.finish();
                self.push_pieces(pieces);
            }
            Frame::Para(o) => self.push_block(para(o), true),
            Frame::Heading { level, out } => {
                let t = out.as_str().trim();
                let line = if t.is_empty() {
                    format!("h{level}.")
                } else {
                    format!("h{level}. {t}")
                };
                self.push_block(Rendered::plain(line), false);
            }
            Frame::Code { lang, body } => {
                self.push_block(code_block(lang.as_deref(), &body), false);
            }
            Frame::Html(raw) => {
                let mut o = Out::para();
                o.text(raw.trim_end());
                self.push_block(para(o), true);
            }
            Frame::Table { rows, .. } => {
                if !rows.is_empty() {
                    self.push_block(Rendered::plain(rows.join("\n")), false);
                }
            }
            Frame::Row { header } => self.finish_row(header),
            Frame::Cell(o) => {
                let text = o.into_string();
                let t = text.trim();
                let cell = if t.is_empty() { " " } else { t };
                if let Some(Frame::Table { cells, .. }) =
                    self.tables.last().and_then(|&i| self.stack.get_mut(i))
                {
                    cells.push(cell.to_owned());
                }
            }
            Frame::Span { delim, mark } => {
                if let Some(o) = self.sink() {
                    o.close_span(mark, delim);
                }
            }
            Frame::Link { target, out } => {
                let text = out.into_string();
                if let Some(o) = self.sink() {
                    if text.trim().is_empty() {
                        o.raw(&format!("[{target}]"));
                    } else {
                        o.raw(&format!("[{text}|{target}]"));
                    }
                }
            }
            Frame::Image {
                target, alt, plain, ..
            } => {
                let Some(o) = self.sink() else {
                    return;
                };
                if plain {
                    o.text(&alt);
                } else if alt.trim().is_empty() {
                    o.raw(&format!("[{target}]"));
                } else {
                    let mut t = Out::link();
                    t.text(&alt);
                    o.raw(&format!("[{}|{target}]", t.as_str()));
                }
            }
        }
    }

    fn finish_row(&mut self, header: bool) {
        if let Some(Frame::Table { rows, cells }) =
            self.tables.last().and_then(|&i| self.stack.get_mut(i))
        {
            if cells.is_empty() {
                return;
            }
            let row = if header {
                format!("||{}||", cells.join("||"))
            } else {
                format!("|{}|", cells.join("|"))
            };
            cells.clear();
            rows.push(row);
        }
    }

    fn finish(mut self) -> (String, EmittedConstructs) {
        self.flush_text();
        while self.stack.len() > 1 {
            self.end();
        }
        let mut blocks = match self.stack.pop() {
            Some(Frame::Doc(b)) => b,
            _ => BlockList::default(),
        };
        blocks.flush();
        let mut r = join(blocks.children.into_iter().map(|c| c.r));
        r.text.push('\n');
        (
            r.text,
            EmittedConstructs {
                code_blocks: r.containers,
            },
        )
    }
}

fn heading_level(level: HeadingLevel) -> u8 {
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

/// A finished block quote (see the module docs for flat vs `{quote}`).
fn quote(mut blocks: BlockList, nested: bool) -> Rendered {
    blocks.flush();
    let children = blocks.children;
    if children.is_empty() {
        return Rendered::default();
    }
    let flat = nested
        || matches!(children.as_slice(), [Child { para: true, .. }])
        || children.iter().any(|c| has_quote_tag(&c.r.text));
    if flat {
        return join(children.into_iter().map(|c| {
            if c.para {
                Rendered::plain(format!("bq. {}", c.r.text.replace('\n', "\\\\")))
            } else {
                c.r
            }
        }));
    }
    let mut r = Rendered::plain("{quote}\n".to_owned());
    r.append(join(children.into_iter().map(|c| c.r)));
    r.text.push_str("\n{quote}");
    let byte_range = 0..r.text.len();
    r.containers.insert(
        0,
        EmittedCode {
            kind: ContainerKind::Quote,
            byte_range,
        },
    );
    r
}

/// The container for a code body, chosen by content (§7.6).
fn code_block(lang: Option<&str>, body: &str) -> Rendered {
    let close = if body.is_empty() || body.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    if !contains_ci(body, "{code") {
        let open = match lang {
            Some(l) => format!("{{code:{l}}}"),
            None => "{code}".to_owned(),
        };
        return Rendered::container(
            ContainerKind::Code,
            format!("{open}\n{body}{close}{{code}}"),
        );
    }
    if !contains_ci(body, "{noformat") {
        return Rendered::container(
            ContainerKind::Noformat,
            format!("{{noformat}}\n{body}{close}{{noformat}}"),
        );
    }
    Rendered::plain(mono_lines(body))
}

/// A body holding both `{code` and `{noformat`: one escaped `{{…}}` line per code line,
/// leading whitespace as no-break spaces (it would collapse), an empty line as one.
fn mono_lines(body: &str) -> String {
    let body = body.strip_suffix('\n').unwrap_or(body);
    let lines: Vec<String> = body
        .split('\n')
        .map(|line| {
            let rest = line.trim_start_matches([' ', '\t']);
            let lead = line.get(..line.len() - rest.len()).unwrap_or("");
            let mut o = Out::inline('{');
            for c in lead.chars() {
                o.raw(if c == '\t' {
                    "&#160;&#160;&#160;&#160;"
                } else {
                    "&#160;"
                });
            }
            o.text(rest);
            if o.as_str().is_empty() {
                o.raw("&#160;");
            }
            format!("{{{{{}}}}}", o.as_str())
        })
        .collect();
    lines.join("\n")
}

/// The languages of Jira's `{code}` macro; any other gets an "unable to find source-code
/// formatter" panel.
const JIRA_LANGS: [&str; 32] = [
    "actionscript",
    "ada",
    "applescript",
    "bash",
    "c",
    "c#",
    "c++",
    "css",
    "erlang",
    "go",
    "groovy",
    "haskell",
    "html",
    "java",
    "javascript",
    "json",
    "lua",
    "none",
    "nyan",
    "objc",
    "perl",
    "php",
    "python",
    "r",
    "rainbow",
    "ruby",
    "scala",
    "sql",
    "swift",
    "visualbasic",
    "xml",
    "yaml",
];

/// Common info-string names mapped to a Jira language.
const LANG_ALIASES: [(&str, &str); 17] = [
    ("js", "javascript"),
    ("jsx", "javascript"),
    ("ts", "javascript"),
    ("tsx", "javascript"),
    ("typescript", "javascript"),
    ("py", "python"),
    ("yml", "yaml"),
    ("rb", "ruby"),
    ("sh", "bash"),
    ("shell", "bash"),
    ("console", "bash"),
    ("zsh", "bash"),
    ("text", "none"),
    ("plain", "none"),
    ("plaintext", "none"),
    ("cpp", "c++"),
    ("cs", "c#"),
];

/// The Jira language of a fenced block: its info string's first word (ASCII
/// case-insensitive, at most [`MAX_LANG`] chars), through [`LANG_ALIASES`], when Jira has a
/// formatter for it; else none (the `{code}` macro then shows no formatter error).
fn code_lang(kind: &CodeBlockKind<'_>) -> Option<String> {
    let CodeBlockKind::Fenced(info) = kind else {
        return None;
    };
    let word = info.split(|c: char| c.is_whitespace() || c == ',').next()?;
    if word.is_empty() || word.len() > MAX_LANG {
        return None;
    }
    let word = word.to_ascii_lowercase();
    let word = if word == "csharp" {
        "c#"
    } else {
        LANG_ALIASES
            .iter()
            .find(|(alias, _)| *alias == word)
            .map_or(word.as_str(), |(_, lang)| lang)
    };
    JIRA_LANGS.contains(&word).then(|| word.to_owned())
}

/// Whether `text` holds a `{quote` tag as the parser's closer grammar reads it: `{`, optional
/// whitespace, `quote` (ASCII case-insensitive).
pub(crate) fn has_quote_tag(text: &str) -> bool {
    text.match_indices('{').any(|(i, _)| {
        let rest = text
            .get(i + 1..)
            .unwrap_or("")
            .trim_start_matches(|c: char| c.is_whitespace() || c <= ' ');
        rest.as_bytes()
            .get(..5)
            .is_some_and(|w| w.eq_ignore_ascii_case(b"quote"))
    })
}

/// A link target: `mailto:` for e-mail autolinks; chars the wiki grammar reads inside
/// `[…|…]` (`{ } [ ] | ! \`, whitespace, controls, and a leading `~`/`^`, which would make a
/// mention or attachment link) are percent-encoded.
fn link_target(link_type: LinkType, dest: &str) -> String {
    let has_scheme = dest
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("mailto:"));
    let full: Cow<'_, str> = if link_type == LinkType::Email && !has_scheme {
        Cow::Owned(format!("mailto:{dest}"))
    } else {
        Cow::Borrowed(dest)
    };
    let mut out = String::with_capacity(full.len());
    for (i, c) in full.char_indices() {
        let encode = matches!(c, '{' | '}' | '[' | ']' | '|' | '!' | '\\')
            || c.is_whitespace()
            || c.is_control()
            || (i == 0 && matches!(c, '~' | '^'));
        if encode {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                let _ = write!(out, "%{b:02X}");
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// ASCII case-insensitive substring test.
pub(crate) fn contains_ci(hay: &str, needle: &str) -> bool {
    let n = needle.as_bytes();
    !n.is_empty()
        && hay
            .as_bytes()
            .windows(n.len())
            .any(|w| w.eq_ignore_ascii_case(n))
}
