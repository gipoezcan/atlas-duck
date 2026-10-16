//! Jira wiki markup parser (spec §7.6, plan PD-44).
//!
//! One parser serves the preview renderer and the hard check, so whatever the preview shows
//! as a construct is what the check counts. [`parse`] never fails: syntax it does not know is
//! text. Where Jira's own behaviour is uncertain the parser errs towards reporting a
//! construct (fail closed): macros inside `{{…}}`, link text, image content and table cells
//! are all found, and only `{code}`/`{noformat}` bodies are opaque.
//!
//! Grammar summary (the contract the converter's escaping is written against):
//! - A backslash before one of `{ } [ ] | ! ~ * _ ^ - + ? #` makes that char literal; `\\` is
//!   a forced line break; a backslash before anything else is a literal backslash.
//! - A macro tag is an unescaped `{name}` or `{name:params}` on one line; `name` (trimmed) is
//!   alphanumerics, `-`, `_` and `.`; params run to the first unescaped `}`.
//! - `{code…}`/`{noformat…}` (lowercase name, no space before it) open an opaque body that ends
//!   at the next literal `{code}`/`{noformat}`, or at the end of the input.
//! - `{{` opens monospace when an unescaped `}}` follows on the same line; its content is
//!   still scanned for constructs.

pub(crate) mod lexer;
mod parse;

use std::ops::Range;

/// A parsed wiki document. Built only by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WikiDoc {
    pub blocks: Vec<Block>,
    /// Every construct (and link) the parser recognised, sorted by start offset; this side
    /// table also covers constructs that have no node of their own in `blocks` (inside link
    /// text, image content or a raw macro body).
    spans: Vec<ConstructSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// `h1.`–`h6.`.
    Heading {
        level: u8,
        inlines: Vec<Inline>,
    },
    Paragraph(Vec<Inline>),
    /// Consecutive `*`/`#`/`-` item lines; `ordered` follows the first item's marker.
    List {
        ordered: bool,
        items: Vec<(u8 /* depth */, Vec<Inline>)>,
    },
    Table {
        rows: Vec<TableRow>,
    },
    /// `bq.` (one paragraph) or a `{quote}…{quote}` container.
    Quote(Vec<Block>),
    /// `{code}`/`{noformat}`; `body` is the raw text between the tags (opaque);
    /// `byte_range` runs from the opening `{` through the closing tag's `}` (or the end of the
    /// input when unterminated).
    Code {
        kind: CodeKind,
        lang: Option<String>,
        body: String,
        byte_range: Range<usize>,
    },
    /// `{panel[:title=…]}…{panel}`.
    Panel {
        title: Option<String>,
        blocks: Vec<Block>,
    },
    /// A macro tag that starts a line: either alone on it (`body: None`, `byte_range` = the
    /// tag) or paired with a later parameterless tag of the same name (`body` = the raw text
    /// between, `byte_range` = both tags and the body). The body is raw text for display; its
    /// constructs are still reported by [`construct_spans`]. Renderers show it as text and
    /// must not re-parse it.
    Macro {
        name: String,
        params: String,
        body: Option<String>,
        byte_range: Range<usize>,
    },
    /// `----`.
    Rule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRow {
    pub cells: Vec<TableCell>,
}

/// One cell; `header` when it follows `||`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableCell {
    pub header: bool,
    pub inlines: Vec<Inline>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inline {
    Text(String),
    Strong(Vec<Inline>),
    Emphasis(Vec<Inline>),
    /// `{{…}}`. Constructs inside it are split out as siblings between `Monospace` segments.
    Monospace(String),
    Strike(Vec<Inline>),
    /// `[target]`, `[text|target]` or a bare `http(s)://`, `ftp://`, `file://`, `mailto:` URL.
    /// `text` is the plain projection of the link text; constructs inside it follow the link
    /// as siblings.
    Link {
        text: Option<String>,
        target: String,
    },
    /// `[~name]` or `[text|~name]`.
    Mention(String),
    /// `!target!` / `!target|params!`: the target only.
    Image(String),
    /// `[^file]` or `[text|^file]`.
    Attachment(String),
    /// Any macro tag inside a line, including each tag of an inline pair such as
    /// `{color:red}x{color}` (two `Macro`s with the text between them as ordinary inlines).
    Macro {
        name: String,
        params: String,
        byte_range: Range<usize>,
    },
    /// A newline inside a paragraph or `\\`.
    LineBreak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeKind {
    Code,
    Noformat,
}

/// Construct kinds the hard checks count (Δ1, PD-44, PD-97). `Link` and `Markup` are
/// storage-only (`ac:link`/`ri:page`/an unsafe `<a>`; an element the storage converter never
/// writes or a foreign namespace): the wiki parser never reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstructKind {
    Macro,
    Mention,
    Include,
    Image,
    Attachment,
    Link,
    Markup,
}

impl ConstructKind {
    /// Lowercase name for messages and `details` (`macro`, `mention`, `include`, `image`,
    /// `attachment`, `link`, `markup`).
    pub fn as_str(self) -> &'static str {
        match self {
            ConstructKind::Macro => "macro",
            ConstructKind::Mention => "mention",
            ConstructKind::Include => "include",
            ConstructKind::Image => "image",
            ConstructKind::Attachment => "attachment",
            ConstructKind::Link => "link",
            ConstructKind::Markup => "markup",
        }
    }
}

/// The construct inventory a write preview lists (Δ1, §7.6), each list in document order,
/// one entry per occurrence. Strings are raw (not display-escaped).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WikiConstructs {
    /// Macro names, including `code`, `noformat`, `quote` and `panel` containers.
    pub macros: Vec<String>,
    pub mentions: Vec<String>,
    /// The params of `{include:…}` / `{excerpt-include:…}`.
    pub includes: Vec<String>,
    /// Link targets.
    pub links: Vec<String>,
    pub images: Vec<String>,
    pub attachments: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpanKind {
    Construct(ConstructKind),
    Link,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConstructSpan {
    kind: SpanKind,
    range: Range<usize>,
    /// Name, target or file, as listed by [`wiki_constructs`].
    label: String,
}

/// Parses Jira wiki markup. Never fails and never panics; unknown syntax is text.
pub fn parse(wiki: &str) -> WikiDoc {
    parse::parse_doc(wiki)
}

/// Every macro, mention, include, image and attachment of `doc` with its byte range in the
/// parsed input, sorted by start offset. Containers (`{code}`, `{noformat}`, `{quote}`,
/// `{panel}`, a paired body macro) are one `Macro` span covering both tags and the body.
/// Used by the hard check; public so the never-panics property can be tested from outside.
pub fn construct_spans(doc: &WikiDoc) -> Vec<(ConstructKind, Range<usize>)> {
    doc.spans
        .iter()
        .filter_map(|s| match s.kind {
            SpanKind::Construct(k) => Some((k, s.range.clone())),
            SpanKind::Link => None,
        })
        .collect()
}

/// The inventory of `wiki` for the write previews (Δ1, PD-47).
pub fn wiki_constructs(wiki: &str) -> WikiConstructs {
    let doc = parse(wiki);
    let mut out = WikiConstructs::default();
    for s in doc.spans {
        let list = match s.kind {
            SpanKind::Construct(ConstructKind::Macro) => &mut out.macros,
            SpanKind::Construct(ConstructKind::Mention) => &mut out.mentions,
            SpanKind::Construct(ConstructKind::Include) => &mut out.includes,
            SpanKind::Construct(ConstructKind::Image) => &mut out.images,
            SpanKind::Construct(ConstructKind::Attachment) => &mut out.attachments,
            // Never recorded by the wiki parser; listed where a reader would look for them.
            SpanKind::Construct(ConstructKind::Link) | SpanKind::Link => &mut out.links,
            SpanKind::Construct(ConstructKind::Markup) => &mut out.macros,
        };
        list.push(s.label);
    }
    out
}
