//! Storage → Markdown (spec §7.6, plan Task 3, PD-94, PD-95).
//!
//! **Mechanism.** The fragment is parsed once ([`parse`]) and the tree is written back as HTML
//! for `htmd`: XHTML elements by name (unknown ones as `<span>`, a `<pre>` as `<pre><code>`
//! holding its text only), text HTML-escaped, and every `ac:`, `ri:` and foreign element
//! replaced by an indexed token (`U+FFFF <index> U+FFFE`; XML 1.0 forbids both characters, so
//! a parsed body never holds them) that stands for a fragment written here: a placeholder, a
//! link, an image, a mention, a task checkbox, or a fenced code block (a block token sits in a
//! `<div>` of its own). Structure (`ac:rich-text-body`, layouts, task bodies, link bodies) is
//! written as HTML around its content. `htmd` converts the whole document in one pass, then the
//! tokens are replaced left to right; a code block keeps the list or quote prefix of its line
//! and becomes inline code on a line that holds other text (a table cell). Placeholders and
//! code blocks are therefore never `htmd`'s.
//!
//! **Look-alikes.** A last pass runs the placeholder grammar ([`crate::placeholders`]) over the
//! result and backslash-escapes every hit that is not one of the converter's own placeholders:
//! prose `@user:abc`, a genuine `<a href="confluence:…">` (`\[text](confluence:…)`), a prose
//! `[macro: …]` that `htmd` did not already escape (it escapes every `[` of prose, so nothing is
//! escaped twice). Code spans and code blocks are never hits, so code is never touched. The same
//! pass escapes the `&` of a prose character reference (`&lt;` from the text `&amp;lt;`), which
//! `htmd` writes as is.
//!
//! **Fallback** (the parse is not `xml_ok`): the CDATA sections are cut out of the raw input
//! first (adjacent ones joined, each a fenced code block at the top level), and every part
//! between them is read lexically: every tag is stripped (a block-level tag ends a paragraph),
//! character references are decoded, and the text is Markdown-escaped. No HTML parser sees a
//! body that failed the XML parse: `html5ever` would rebuild misnested markup into a tree as
//! deep and as large as the input chooses (T3 review B-1). The look-alike pass runs as above.
//! No mention is rendered, no user map is used and nothing is counted (`fallback` and `lossy`
//! say so); U+FFFE and U+FFFF become U+FFFD.
//!
//! **Tables** never reach `htmd`, which pads every cell to the widest cell of its column (rows ×
//! width bytes from a page of rows + width bytes; T10 review B-1). A table with a header (a `th`
//! or `thead`, as `htmd` decides) outside any cell becomes a pipe table written here, unpadded:
//! `htmd` converts its cells in one run of their own, each cell on one line (`|` as `&#124;`);
//! any other table is written as the `<div>`s `htmd` makes of it.
//!
//! **Budget** ([`storage_to_markdown_within`]): the Markdown may not pass a byte budget. Before
//! each `htmd` run, what the output holds beyond the text of the HTML (the fragments, and the
//! prefix of the enclosing quotes and list items on every line) is held to [`ESTIMATE_FACTOR`]
//! × the budget, as the writer estimates it; after `htmd` every stage is measured exactly.
//! Either check stops the conversion with [`MarkdownTooLarge`]. What `htmd` makes of the HTML
//! itself is bounded by the input, not by the budget (a few times the body; T10 review m-3).

use std::collections::{BTreeMap, BTreeSet};

use htmd::HtmlToMarkdown;
use htmd::options::{BrStyle, BulletListMarker, HrStyle, Options};
use pulldown_cmark::{CodeBlockKind, Event, Parser, Tag, TagEnd};

use super::parse::{Element, Node, Ns, decode_attr, lex_attrs, parse, resolve_ref, user_refs};
use crate::placeholders::{self, PlaceholderKind, escaped};

/// `user_resolutions` (§7.6, Δ1): user key → username, `None` when unresolved.
pub type UserResolutions = BTreeMap<String, Option<String>>;

/// Constructs a Markdown round trip loses (Δ1; `meta.conversion.lost`, §4.2). Outermost
/// constructs only, so one construct is one count (PD-104 counting, plan review I-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LostCounts {
    pub macros: u64,
    pub images: u64,
    pub links: u64,
    pub layouts: u64,
}

/// [`storage_to_markdown_within`]: the Markdown would pass the byte budget (T10 review B-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkdownTooLarge;

/// How far the writer's estimate ([`Writer::estimate`]) may pass the budget before `htmd` runs.
/// The fragments are in the output as they are and the prefixes are counted at most twice per
/// line, so a page within the budget never reaches this multiple, and `htmd` never builds
/// quotes or list items of many times the budget (60 nested quotes give every line 120 bytes).
const ESTIMATE_FACTOR: usize = 4;

/// What [`storage_to_markdown`] reduced (Δ1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConversionReport {
    /// `lost` is non-zero, or the fallback ran.
    pub lossy: bool,
    pub lost: LostCounts,
    /// Macro names outside [`KNOWN_MACROS`], and the names of other `ac:`, `ri:` and foreign
    /// elements written as placeholders: raw, in document order, deduplicated.
    pub unknown_macros: Vec<String>,
    /// Mentions written as `@user:<key>` (one per occurrence).
    pub unresolved_users: u64,
    /// The XML parse failed and the CDATA-first fallback ran.
    pub fallback: bool,
}

/// Macros the conversion names without listing them in `unknown_macros` (PD-95, lead ruling
/// Q11 after the Task 3 review): those whose placeholder and inlined body carry everything the
/// macro stores and shows. A macro whose content the server generates (`children`, `jira`,
/// `include`, `pagetree`, …) stays unknown, which is what the `unknown_macros` Info is for.
/// Every macro but `code` and `noformat` still counts as lost.
pub const KNOWN_MACROS: [&str; 16] = [
    "code", "noformat", "info", "note", "tip", "warning", "panel", "expand", "excerpt", "toc",
    "anchor", "status", "details", "section", "column", "toc-zone",
];

/// `ac:` elements written as a `[macro: …]` placeholder and counted as lost, but never listed
/// in `unknown_macros` (lead ruling Q11): a page with an emoticon or an instructional
/// placeholder does not raise the "unknown macros" Info.
const AC_QUIET: [&str; 2] = ["emoticon", "placeholder"];

/// `ac:` elements that mark up content without being content: written as their content alone
/// (no placeholder, no `unknown_macros` entry) but each counted as one lost macro, because a
/// Markdown round trip drops them. `ac:inline-comment-marker` binds an inline comment to the
/// text it wraps; dropping it detaches the comment (lead default 2026-10-16, Task 2 review
/// ruling). This is the one place that rule lives: moving a name to [`AC_STRUCTURE`] makes it
/// uncounted, removing it makes it a `[macro: …]` placeholder.
const AC_MARKERS: [&str; 1] = ["inline-comment-marker"];

/// `ac:` elements that structure content (descended into, never counted). A task list is
/// structure too, but counted ([`lost_counts`]).
const AC_STRUCTURE: [&str; 10] = [
    "rich-text-body",
    "task-id",
    "task-status",
    "task-body",
    "layout-section",
    "layout-cell",
    "link-body",
    "plain-text-link-body",
    "parameter",
    "plain-text-body",
];

/// How a non-structural `ac:` element outside the PD-95 mapping is converted and counted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AcRule {
    /// Content only, never counted.
    Structure,
    /// Content only, one lost macro ([`AC_MARKERS`]).
    Marker,
    /// `[macro: <local-name> {}]`, then its content; one lost macro (PD-95).
    Placeholder,
}

fn ac_rule(local: &str) -> AcRule {
    if AC_STRUCTURE.contains(&local) {
        AcRule::Structure
    } else if AC_MARKERS.contains(&local) {
        AcRule::Marker
    } else {
        AcRule::Placeholder
    }
}

/// XHTML elements written back by name; any other becomes a `<span>`. `table` is written by
/// [`Writer::table`].
const PASS_HTML: [&str; 62] = [
    "a",
    "abbr",
    "address",
    "article",
    "aside",
    "b",
    "big",
    "blockquote",
    "caption",
    "center",
    "cite",
    "code",
    "colgroup",
    "dd",
    "del",
    "details",
    "dfn",
    "div",
    "dl",
    "dt",
    "em",
    "figcaption",
    "figure",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "i",
    "ins",
    "kbd",
    "li",
    "main",
    "mark",
    "nav",
    "ol",
    "p",
    "q",
    "s",
    "samp",
    "section",
    "small",
    "span",
    "strike",
    "strong",
    "sub",
    "summary",
    "sup",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "time",
    "tr",
    "tt",
    "u",
    "ul",
    "var",
];

/// Void XHTML elements (written without an end tag).
const VOID_HTML: [&str; 4] = ["br", "hr", "img", "col"];

const TOKEN_OPEN: char = '\u{FFFF}';
const TOKEN_CLOSE: char = '\u{FFFE}';
const MAX_USERNAME_CHARS: usize = 255;
const MAX_MACRO_NAME: usize = 64;
const MAX_LANGUAGE: usize = 32;
/// Bound on the look-alike passes (each escapes what the previous one found).
const MAX_PASSES: usize = 8;
const CDATA_OPEN: &str = "<![CDATA[";
const CDATA_CLOSE: &str = "]]>";

/// Converts a storage body to Markdown (§7.6, PD-95) with the user map `users` and returns the
/// Markdown (ending in exactly one newline, or empty), the report, and the map it used: every
/// non-empty `ri:userkey` of the body (macro parameters included) with its value from `users`,
/// `None` where `users` lacks it (legacy `ri:username` mentions need no entry). A given value
/// that is no usable username (empty, longer than 255 chars, a control character) is returned
/// as given but rendered `@user:<key>` and counted unresolved. The fallback uses no map and
/// returns an empty one.
/// Pure and deterministic; never panics. No budget: a caller converting fetched content uses
/// [`storage_to_markdown_within`].
pub fn storage_to_markdown(
    storage: &str,
    users: &UserResolutions,
) -> (String, ConversionReport, UserResolutions) {
    // No check trips at `usize::MAX` (the estimate saturates, no string is that long).
    storage_to_markdown_within(storage, users, usize::MAX).unwrap_or_else(|MarkdownTooLarge| {
        let report = ConversionReport {
            lossy: true,
            fallback: true,
            ..ConversionReport::default()
        };
        (String::new(), report, UserResolutions::new())
    })
}

/// [`storage_to_markdown`] with a budget (T10 review B-1): `Err(MarkdownTooLarge)` once the
/// Markdown would be longer than `max_bytes` (the final newline included), before any stage
/// builds much more than that (the estimate before `htmd` is held to [`ESTIMATE_FACTOR`] ×
/// `max_bytes`, every later stage to `max_bytes` exactly). `Ok` is exactly what
/// [`storage_to_markdown`] returns.
pub fn storage_to_markdown_within(
    storage: &str,
    users: &UserResolutions,
    max_bytes: usize,
) -> Result<(String, ConversionReport, UserResolutions), MarkdownTooLarge> {
    let doc = parse(storage);
    if !doc.xml_ok {
        let report = ConversionReport {
            lossy: true,
            fallback: true,
            ..ConversionReport::default()
        };
        return Ok((
            fallback(storage, max_bytes)?,
            report,
            UserResolutions::new(),
        ));
    }
    let used: UserResolutions = user_refs(&doc)
        .keys
        .into_iter()
        .filter(|k| !k.is_empty())
        .map(|k| {
            let v = users.get(&k).cloned().flatten();
            (k, v)
        })
        .collect();
    let mut w = Writer::new(&used, max_bytes.saturating_mul(ESTIMATE_FACTOR));
    w.nodes(&doc.nodes);
    if w.over() {
        return Err(MarkdownTooLarge);
    }
    let lost = lost_counts(&doc.nodes);
    let md = finish(&w.html, &w.frags, max_bytes)?;
    let report = ConversionReport {
        lossy: lost != LostCounts::default(),
        lost,
        unknown_macros: w.unknown,
        unresolved_users: w.unresolved,
        fallback: false,
    };
    Ok((md, report, used))
}

/// A piece of Markdown this module writes in place of a token.
enum Frag {
    /// Inline Markdown; `genuine` when it is a placeholder the check must see.
    Inline {
        md: String,
        genuine: Option<PlaceholderKind>,
    },
    /// A fenced code block.
    Code {
        language: Option<String>,
        body: String,
    },
    /// A pipe table, one line per entry (an empty entry is a blank line). Its cells hold the
    /// tokens of their own fragments; [`expand_tables`] puts the lines in place before the
    /// tokens are replaced.
    Table { lines: Vec<String> },
}

/// The line prefix `htmd` gives the content of a bulleted list item (`- `); an ordered item's is
/// its marker (`<digits>. `).
const BULLET_INDENT: usize = 2;
/// The line prefix of a quote (`> `).
const QUOTE_INDENT: usize = 2;

/// Writes the HTML for `htmd` and collects the fragments.
struct Writer<'u> {
    users: &'u UserResolutions,
    html: String,
    frags: Vec<Frag>,
    unknown: Vec<String>,
    seen: BTreeSet<String>,
    unresolved: u64,
    /// Enclosing table cells (a table inside one is never a pipe table, as with `htmd`).
    cells: usize,
    /// The width of the line prefix `htmd` gives what is written now (quotes, list items).
    indent: usize,
    /// The marker width of an item of the list written now.
    item: usize,
    /// What the Markdown holds beyond the HTML `htmd` gets: the fragments' bytes and every
    /// line's prefix.
    estimate: usize,
    /// The estimate at which the conversion stops ([`ESTIMATE_FACTOR`] × the budget).
    ceiling: usize,
    /// The estimate passed `ceiling`: nothing more is written.
    stopped: bool,
}

impl<'u> Writer<'u> {
    fn new(users: &'u UserResolutions, ceiling: usize) -> Self {
        Writer {
            users,
            html: String::new(),
            frags: Vec::new(),
            unknown: Vec::new(),
            seen: BTreeSet::new(),
            unresolved: 0,
            cells: 0,
            indent: 0,
            item: BULLET_INDENT,
            estimate: 0,
            ceiling,
            stopped: false,
        }
    }

    /// The estimate passed the ceiling (sticky).
    fn over(&mut self) -> bool {
        self.stopped |= self.estimate > self.ceiling;
        self.stopped
    }

    /// `n` lines, each with the current prefix.
    fn lines(&mut self, n: usize) {
        self.estimate = self.estimate.saturating_add(n.saturating_mul(self.indent));
    }

    fn token(&mut self, frag: Frag) {
        let bytes = match &frag {
            Frag::Inline { md, .. } => md.len(),
            // The body, its fences (as long as its longest backtick run) and the language.
            Frag::Code { body, .. } => {
                self.lines(body.matches('\n').count().saturating_add(2));
                body.len().saturating_add(2 * MAX_LANGUAGE)
            }
            Frag::Table { lines } => {
                self.lines(lines.len());
                lines.iter().map(String::len).sum()
            }
        };
        self.estimate = self.estimate.saturating_add(bytes);
        push_token(&mut self.html, self.frags.len());
        self.frags.push(frag);
    }

    fn inline(&mut self, md: String, genuine: Option<PlaceholderKind>) {
        self.token(Frag::Inline { md, genuine });
    }

    /// A fragment on its own lines.
    fn block(&mut self, frag: Frag) {
        self.lines(2);
        self.html.push_str("<div>");
        self.token(frag);
        self.html.push_str("</div>");
    }

    fn placeholder(&mut self, name: &str, params: &[(String, String)]) {
        self.inline(
            macro_placeholder(name, params),
            Some(PlaceholderKind::Macro),
        );
    }

    fn unknown(&mut self, name: &str) {
        if self.seen.insert(name.to_owned()) {
            self.unknown.push(name.to_owned());
        }
    }

    fn text(&mut self, t: &str) {
        // A line break kept in the output (a `<pre>`) has a prefix of its own.
        self.lines(t.matches('\n').count());
        push_html_text(&mut self.html, t);
    }

    fn nodes(&mut self, nodes: &[Node]) {
        for n in nodes {
            self.node(n);
        }
    }

    fn node(&mut self, n: &Node) {
        match n {
            Node::Text(t) | Node::CData { text: t, .. } => self.text(t),
            Node::Element(e) => self.element(e),
        }
    }

    fn element(&mut self, e: &Element) {
        if self.over() {
            return;
        }
        match e.ns {
            Ns::Html => self.html_element(e),
            Ns::Ac => self.ac(e),
            Ns::Ri if e.local == "user" => self.mention(e),
            Ns::Ri => {
                self.unknown(&e.local);
                self.placeholder(&e.local, &[]);
            }
            Ns::Other => {
                self.unknown(&e.qname());
                self.placeholder(&e.local, &[]);
            }
        }
    }

    fn wrap(&mut self, tag: &str, e: &Element) {
        self.html.push('<');
        self.html.push_str(tag);
        self.html.push('>');
        self.nodes(&e.children);
        self.html.push_str("</");
        self.html.push_str(tag);
        self.html.push('>');
    }

    fn html_element(&mut self, e: &Element) {
        let name = e.local.to_ascii_lowercase();
        if BREAK_HTML.contains(&name.as_str()) {
            self.lines(2);
        }
        let indent = match name.as_str() {
            "blockquote" => QUOTE_INDENT,
            "li" => self.item,
            _ => 0,
        };
        let item = self.item;
        match name.as_str() {
            "ul" => self.item = BULLET_INDENT,
            "ol" => {
                let items = e.child_elements().count().max(1);
                self.item = items.to_string().len() + 2;
            }
            _ => {}
        }
        self.indent += indent;
        self.html_element_body(&name, e);
        self.indent -= indent;
        self.item = item;
    }

    fn html_element_body(&mut self, name: &str, e: &Element) {
        let constructs = has_construct(&e.children);
        match name {
            "table" => self.table(e),
            // A Confluence date lozenge (`<time datetime="2026-10-20"/>`) has no text: its
            // date is written as text (T3 review I-2; not counted lost).
            "time" if !constructs && !has_text(&e.children) => {
                if let Some(date) = e.attr("datetime") {
                    self.text(date.trim());
                }
            }
            "pre" if !constructs => {
                let mut t = String::new();
                plain_text(&e.children, &mut t);
                self.html.push_str("<pre><code>");
                self.text(&t);
                self.html.push_str("</code></pre>");
            }
            // A construct inside code would land in a code span and never be seen.
            "pre" => self.wrap("div", e),
            "code" if constructs => self.wrap("span", e),
            n if VOID_HTML.contains(&n) => {
                self.open(n, e);
                self.nodes(&e.children);
            }
            n if PASS_HTML.contains(&n) => {
                self.open(n, e);
                self.nodes(&e.children);
                self.html.push_str("</");
                self.html.push_str(n);
                self.html.push('>');
            }
            _ => self.wrap("span", e),
        }
    }

    /// A start tag with the attributes `htmd` reads (`href`, `src`, `alt`). An `<ol start>` is
    /// dropped: `htmd` pads list markers with `usize` arithmetic on a digit count it takes from
    /// that number, and page content must not choose it.
    fn open(&mut self, name: &str, e: &Element) {
        self.html.push('<');
        self.html.push_str(name);
        for (k, v) in &e.attrs {
            let value = match k.as_str() {
                "href" | "src" => v.clone(),
                // `htmd` writes `alt` as is.
                "alt" => escape_text(v),
                _ => continue,
            };
            self.html.push(' ');
            self.html.push_str(k);
            self.html.push_str("=\"");
            push_html_attr(&mut self.html, &value);
            self.html.push('"');
        }
        self.html.push('>');
    }

    fn ac(&mut self, e: &Element) {
        match e.local.as_str() {
            "structured-macro" | "macro" => self.structured_macro(e),
            "link" => self.link(e),
            "image" => self.image(e),
            "task-list" => {
                self.html.push_str("<ul>");
                self.tasks(&e.children);
                self.html.push_str("</ul>");
            }
            "task" => {
                self.html.push_str("<ul>");
                self.task(e);
                self.html.push_str("</ul>");
            }
            // Layout cells in document order, separated by blank lines.
            "layout" | "layout-section" | "layout-cell" | "rich-text-body" => self.wrap("div", e),
            "link-body" | "plain-text-link-body" | "task-body" => self.wrap("span", e),
            "task-id" | "task-status" => {}
            local => {
                if ac_rule(local) == AcRule::Placeholder {
                    if !AC_QUIET.contains(&local) {
                        self.unknown(local);
                    }
                    self.placeholder(local, &[]);
                }
                self.nodes(&e.children);
            }
        }
    }

    /// `ac:structured-macro` (and the old `ac:macro`): `code`/`noformat` → a fenced block;
    /// any other → `[macro: <name> {<k>=<v>, …}]`, followed on their own lines by its
    /// plain-text body (fenced) and its rich-text body (converted).
    fn structured_macro(&mut self, e: &Element) {
        let name = e.attr("ac:name").unwrap_or("");
        let mut params: Vec<(String, String)> = Vec::new();
        let mut plain: Option<String> = None;
        let mut bodies: Vec<&Element> = Vec::new();
        let mut rest: Vec<&Element> = Vec::new();
        for c in e.child_elements() {
            if c.is(Ns::Ac, "parameter") {
                let key = c.attr("ac:name").unwrap_or("").to_owned();
                params.push((key, self.param_text(c)));
            } else if c.is(Ns::Ac, "plain-text-body") {
                plain_text(&c.children, plain.get_or_insert_with(String::new));
            } else if c.is(Ns::Ac, "rich-text-body") {
                bodies.push(c);
            } else {
                rest.push(c);
            }
        }
        params.sort_by(|a, b| a.0.cmp(&b.0));
        let language = params
            .iter()
            .find(|(k, _)| k == "language")
            .map(|(_, v)| v.clone())
            .filter(|l| valid_language(l));
        if is_code(name) {
            let language = if name.eq_ignore_ascii_case("code") {
                language
            } else {
                None
            };
            self.block(Frag::Code {
                language,
                body: plain.unwrap_or_default(),
            });
        } else {
            if name.is_empty() {
                // Listed by the name its placeholder shows (T3 review m-3).
                self.unknown(&fit_name(name));
            } else if !KNOWN_MACROS.iter().any(|k| k.eq_ignore_ascii_case(name)) {
                self.unknown(name);
            }
            let md = macro_placeholder(name, &params);
            if plain.is_none() && bodies.is_empty() {
                self.inline(md, Some(PlaceholderKind::Macro));
            } else {
                self.block(Frag::Inline {
                    md,
                    genuine: Some(PlaceholderKind::Macro),
                });
                if let Some(body) = plain {
                    self.block(Frag::Code { language, body });
                }
            }
        }
        for b in bodies {
            self.wrap("div", b);
        }
        for r in rest {
            self.element(r);
        }
    }

    /// The display text of a macro parameter: its text, with each `ri:` resource by its label.
    fn param_text(&self, p: &Element) -> String {
        let mut out = String::new();
        self.param_nodes(&p.children, &mut out);
        one_line(&out)
    }

    fn param_nodes(&self, nodes: &[Node], out: &mut String) {
        for n in nodes {
            match n {
                Node::Text(t) | Node::CData { text: t, .. } => out.push_str(t),
                Node::Element(e) if e.ns == Ns::Ri => {
                    if !out.trim().is_empty() {
                        out.push_str(", ");
                    }
                    out.push_str(&self.resource_label(e));
                }
                Node::Element(e) => self.param_nodes(&e.children, out),
            }
        }
    }

    fn resource_label(&self, e: &Element) -> String {
        let attr = |k: &str| e.attr(k).unwrap_or("").to_owned();
        match e.local.as_str() {
            "user" => match e.attr("ri:userkey") {
                Some(key) => match self.users.get(key).cloned().flatten() {
                    Some(name) if valid_username(&name) => name,
                    _ => key.to_owned(),
                },
                None => attr("ri:username"),
            },
            "page" | "blog-post" => match e.attr("ri:space-key") {
                Some(space) => format!("{space}:{}", attr("ri:content-title")),
                None => attr("ri:content-title"),
            },
            "space" => attr("ri:space-key"),
            "attachment" => attr("ri:filename"),
            "url" => attr("ri:value"),
            "content-entity" => attr("ri:content-id"),
            _ => e.attrs.first().map(|(_, v)| v.clone()).unwrap_or_default(),
        }
    }

    /// `ac:link`: a page or blog post → `[<body or title>](confluence:<space>/<title>)` (the
    /// space segment empty when the link names none: the page's own space); an attachment →
    /// `[<body or file>](confluence:attachment/<file>)`; a user → a mention; any other target
    /// (an anchor, a space, a URL) → its body (or label) as prose. Counted as one lost link.
    fn link(&mut self, e: &Element) {
        let target = e.child_elements().find(|c| c.ns == Ns::Ri);
        let mut body = String::new();
        for c in e.child_elements() {
            if c.is(Ns::Ac, "link-body") || c.is(Ns::Ac, "plain-text-link-body") {
                plain_text(&c.children, &mut body);
            }
        }
        let body = collapse(&body);
        let or_body = |label: &str| {
            if body.is_empty() {
                label.to_owned()
            } else {
                body.clone()
            }
        };
        match target.map(|t| (t, t.local.as_str())) {
            Some((t, "page" | "blog-post")) => {
                let title = t.attr("ri:content-title").unwrap_or("");
                let space = t.attr("ri:space-key").unwrap_or("");
                let md = format!(
                    "[{}](confluence:{}/{})",
                    escape_text(&or_body(title)),
                    percent(space, url_safe),
                    percent(title, url_safe)
                );
                self.inline(md, Some(PlaceholderKind::Link));
            }
            Some((t, "attachment")) => {
                let file = t.attr("ri:filename").unwrap_or("");
                let md = format!(
                    "[{}](confluence:attachment/{})",
                    escape_text(&or_body(file)),
                    percent(file, url_safe)
                );
                self.inline(md, Some(PlaceholderKind::Link));
            }
            Some((t, "user")) => self.mention(t),
            target => {
                let label = match target {
                    Some((t, _)) => self.resource_label(t),
                    None => e.attr("ac:anchor").unwrap_or("").to_owned(),
                };
                let text = or_body(&label);
                self.text(&text);
            }
        }
    }

    /// `ac:image`: an attachment → `![<file>](confluence:attachment/<file>)`, a URL →
    /// `![image](confluence:url/<url>)`, anything else → `[macro: image {}]`.
    fn image(&mut self, e: &Element) {
        let target = e.child_elements().find(|c| c.ns == Ns::Ri);
        match target.map(|t| (t, t.local.as_str())) {
            Some((t, "attachment")) => {
                let file = t.attr("ri:filename").unwrap_or("");
                let md = format!(
                    "![{}](confluence:attachment/{})",
                    escape_text(file),
                    percent(file, url_safe)
                );
                self.inline(md, Some(PlaceholderKind::Image));
            }
            Some((t, "url")) => {
                let url = t.attr("ri:value").unwrap_or("");
                let md = format!("![image](confluence:url/{})", percent(url, url_safe));
                self.inline(md, Some(PlaceholderKind::Image));
            }
            _ => self.placeholder("image", &[]),
        }
    }

    /// `ri:user` → `@<username>` (from the map, or the legacy `ri:username`), escaped like
    /// prose; `@user:<key>` when the map holds `None` or the name is empty, longer than 255
    /// chars or holds a control character.
    fn mention(&mut self, u: &Element) {
        let key = u.attr("ri:userkey").filter(|k| !k.is_empty());
        let name = match key {
            Some(k) => self.users.get(k).cloned().flatten(),
            None => u.attr("ri:username").map(str::to_owned),
        };
        if let Some(name) = name.filter(|n| valid_username(n)) {
            self.inline(format!("@{}", escape_all_punctuation(&name)), None);
            return;
        }
        match key.or_else(|| u.attr("ri:username").filter(|n| !n.is_empty())) {
            Some(id) => {
                self.unresolved += 1;
                self.inline(
                    format!("@user:{}", percent(id, key_safe)),
                    Some(PlaceholderKind::User),
                );
            }
            None => self.placeholder("user", &[]),
        }
    }

    fn tasks(&mut self, nodes: &[Node]) {
        for n in nodes {
            match n {
                Node::Element(t) if t.is(Ns::Ac, "task") => self.task(t),
                n => self.node(n),
            }
        }
    }

    /// `ac:task` → a list item starting `[ ] ` or `[x] ` (`ac:task-status` `complete`).
    fn task(&mut self, e: &Element) {
        let done = e
            .child_elements()
            .find(|c| c.is(Ns::Ac, "task-status"))
            .is_some_and(|c| {
                let mut t = String::new();
                plain_text(&c.children, &mut t);
                t.trim() == "complete"
            });
        self.lines(2);
        self.indent += BULLET_INDENT;
        self.html.push_str("<li>");
        self.inline(if done { "[x] " } else { "[ ] " }.to_owned(), None);
        for n in &e.children {
            match n {
                Node::Element(c) if c.is(Ns::Ac, "task-body") => self.nodes(&c.children),
                Node::Element(c) if c.is(Ns::Ac, "task-id") || c.is(Ns::Ac, "task-status") => {}
                n => self.node(n),
            }
        }
        self.html.push_str("</li>");
        self.indent -= BULLET_INDENT;
    }

    /// An XHTML `<table>`. One with a header ([`explicit_header`]) outside any cell is a pipe
    /// table ([`Writer::pipe_table`]); any other is written as its parts ([`Writer::table_parts`]).
    fn table(&mut self, e: &Element) {
        if self.cells == 0 && explicit_header(&e.children) && self.pipe_table(e) {
            return;
        }
        self.table_parts(e);
    }

    /// A table `htmd` does not write as a table: a `<div>`, its sections, rows, cells and
    /// captions `<div>`s too (the blocks `htmd` makes of them), `colgroup` and `col` dropped
    /// (they hold no content), anything else as it is.
    fn table_parts(&mut self, e: &Element) {
        if self.over() {
            return;
        }
        self.lines(2);
        self.html.push_str("<div>");
        for n in &e.children {
            match n {
                Node::Element(c) => match table_part(c) {
                    Some(TablePart::Columns) => {}
                    Some(TablePart::Cell) => self.cell(c),
                    Some(_) => self.table_parts(c),
                    None => self.element(c),
                },
                n => self.node(n),
            }
        }
        self.html.push_str("</div>");
    }

    /// The content of a table cell (or caption) as a block.
    fn cell(&mut self, c: &Element) {
        self.cells += 1;
        self.lines(2);
        self.html.push_str("<div>");
        self.nodes(&c.children);
        self.html.push_str("</div>");
        self.cells -= 1;
    }

    /// A pipe table without padding (T10 review B-1): the captions (each one line, then a blank
    /// line), the header row, `| --- |` per column, the body rows; every row has as many cells as
    /// the widest one. The header is the first row of the first `thead`, or else the first row
    /// when it holds a `th`, or else a row of empty cells; every other row with a cell is a body
    /// row, in document order. Rows are the `tr`s of the table and of its sections (a section
    /// without a `tr` but with cells is one row); cells are the `td`s and `th`s of a row. What
    /// stands in the table outside those (text, other elements) is written before the table, as
    /// an HTML parser would move it. `htmd` converts the cells and captions in one run of their
    /// own; a cell's text is trimmed, its line breaks become spaces and `|` becomes `&#124;`.
    /// `false` (nothing written) for a table without a cell.
    fn pipe_table(&mut self, e: &Element) -> bool {
        let mut captions: Vec<&Element> = Vec::new();
        let mut head: Vec<&Element> = Vec::new();
        let mut body: Vec<&Element> = Vec::new();
        let mut strays: Vec<&Node> = Vec::new();
        for n in &e.children {
            let Node::Element(c) = n else {
                if !is_blank(n) {
                    strays.push(n);
                }
                continue;
            };
            match table_part(c) {
                Some(TablePart::Caption) => captions.push(c),
                Some(TablePart::Columns) => {}
                Some(TablePart::Head) => section_rows(c, &mut head, &mut strays),
                Some(TablePart::Section) => section_rows(c, &mut body, &mut strays),
                Some(TablePart::Row) => body.push(c),
                Some(TablePart::Cell) | None => strays.push(n),
            }
        }
        let first_has_th = body.first().is_some_and(|r| r.child_elements().any(is_th));
        let (header, rest): (Option<&Element>, Vec<&Element>) = match head.split_first() {
            Some((first, more)) => (Some(*first), more.iter().chain(&body).copied().collect()),
            None if first_has_th => (
                body.first().copied(),
                body.iter().skip(1).copied().collect(),
            ),
            None => (None, body),
        };
        let header: Vec<&Element> = header
            .map(|h| row_cells(h, &mut strays))
            .unwrap_or_default();
        let rows: Vec<Vec<&Element>> = rest
            .into_iter()
            .map(|r| row_cells(r, &mut strays))
            .filter(|cells| !cells.is_empty())
            .collect();
        let columns = rows.iter().map(Vec::len).fold(header.len(), usize::max);
        if columns == 0 {
            return false;
        }
        for n in strays {
            self.node(n);
        }
        // The captions and cells in one `htmd` run, each followed by a separator.
        let outer = std::mem::take(&mut self.html);
        let indent = std::mem::take(&mut self.indent);
        let all = captions.iter().chain(&header).chain(rows.iter().flatten());
        for c in all {
            self.cell(c);
            self.html.push_str("<div>");
            self.html.push_str(CELL_END);
            self.html.push_str("</div>");
        }
        let batch = std::mem::replace(&mut self.html, outer);
        self.indent = indent;
        if self.over() {
            return true;
        }
        let md = html_to_md(&batch);
        let mut texts = md.split(CELL_END).map(cell_text);
        let mut next = || texts.next().unwrap_or_default();
        let mut lines: Vec<String> = Vec::new();
        for _ in &captions {
            let caption = next();
            if !caption.is_empty() {
                lines.push(caption);
            }
        }
        if !lines.is_empty() {
            lines.push(String::new());
        }
        let header: Vec<String> = header.iter().map(|_| next()).collect();
        lines.push(pipe_row(&header, columns));
        lines.push(pipe_row(&vec!["---".to_owned(); columns], columns));
        for row in &rows {
            let cells: Vec<String> = row.iter().map(|_| next()).collect();
            lines.push(pipe_row(&cells, columns));
        }
        self.block(Frag::Table { lines });
        true
    }
}

/// The parts of a table, by XHTML element name.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TablePart {
    Caption,
    Columns,
    Head,
    Section,
    Row,
    Cell,
}

fn table_part(e: &Element) -> Option<TablePart> {
    if e.ns != Ns::Html {
        return None;
    }
    match e.local.to_ascii_lowercase().as_str() {
        "caption" => Some(TablePart::Caption),
        "colgroup" | "col" => Some(TablePart::Columns),
        "thead" => Some(TablePart::Head),
        "tbody" | "tfoot" => Some(TablePart::Section),
        "tr" => Some(TablePart::Row),
        "td" | "th" => Some(TablePart::Cell),
        _ => None,
    }
}

fn is_th(e: &Element) -> bool {
    e.ns == Ns::Html && e.local.eq_ignore_ascii_case("th")
}

fn is_blank(n: &Node) -> bool {
    matches!(n, Node::Text(t) if t.trim().is_empty())
}

/// The cells of a table row; anything else in it goes to `strays`.
fn row_cells<'e>(r: &'e Element, strays: &mut Vec<&'e Node>) -> Vec<&'e Element> {
    let mut cells = Vec::new();
    for n in &r.children {
        match n {
            Node::Element(c) if table_part(c) == Some(TablePart::Cell) => cells.push(c),
            n if is_blank(n) => {}
            n => strays.push(n),
        }
    }
    cells
}

/// The rows of a table section: its `tr`s, or the section itself when it holds cells but no
/// `tr`; anything else in it goes to `strays`.
fn section_rows<'e>(s: &'e Element, rows: &mut Vec<&'e Element>, strays: &mut Vec<&'e Node>) {
    let has_rows = s
        .child_elements()
        .any(|c| table_part(c) == Some(TablePart::Row));
    if !has_rows {
        if s.child_elements()
            .any(|c| table_part(c) == Some(TablePart::Cell))
        {
            rows.push(s);
        } else {
            strays.extend(s.children.iter().filter(|n| !is_blank(n)));
        }
        return;
    }
    for n in &s.children {
        match n {
            Node::Element(c) if table_part(c) == Some(TablePart::Row) => rows.push(c),
            n if is_blank(n) => {}
            n => strays.push(n),
        }
    }
}

/// Whether `nodes` hold a `th` or a `thead` outside nested tables: `htmd` writes only such a
/// table as a table.
fn explicit_header(nodes: &[Node]) -> bool {
    nodes.iter().any(|n| match n {
        Node::Element(e) if e.ns == Ns::Html && e.local.eq_ignore_ascii_case("table") => false,
        Node::Element(e) => {
            matches!(table_part(e), Some(TablePart::Head))
                || is_th(e)
                || explicit_header(&e.children)
        }
        _ => false,
    })
}

/// Ends each cell of an `htmd` run of table cells (no token: never a fragment index).
const CELL_END: &str = "\u{FFFF}|\u{FFFE}";

/// A cell's Markdown on one line: trimmed, line breaks as spaces, `|` as `&#124;`.
fn cell_text(md: &str) -> String {
    let ws = ['\t', '\n', '\r', ' '];
    md.trim_matches(ws)
        .replace('\r', "")
        .replace('\n', " ")
        .replace('|', "&#124;")
        .trim_matches(ws)
        .to_owned()
}

/// `| a | b |`, with empty cells up to `columns`.
fn pipe_row(cells: &[String], columns: usize) -> String {
    let mut line = String::from("|");
    for i in 0..columns {
        line.push(' ');
        line.push_str(cells.get(i).map_or("", String::as_str));
        line.push_str(" |");
    }
    line
}

fn is_code(name: &str) -> bool {
    name.eq_ignore_ascii_case("code") || name.eq_ignore_ascii_case("noformat")
}

/// `[A-Za-z0-9+#-]{1,32}` (PD-95).
fn valid_language(l: &str) -> bool {
    (1..=MAX_LANGUAGE).contains(&l.len())
        && l.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'#' | b'-'))
}

fn valid_username(n: &str) -> bool {
    !n.is_empty()
        && n.chars().count() <= MAX_USERNAME_CHARS
        && n.chars()
            .all(|c| !c.is_control() && c != TOKEN_OPEN && c != TOKEN_CLOSE)
}

/// `[macro: <name> {<k>=<v>, …}]`: the name made to fit the grammar ([`fit_name`]), keys and
/// values escaped by [`escape_param`].
fn macro_placeholder(name: &str, params: &[(String, String)]) -> String {
    let mut out = format!("[macro: {} {{", fit_name(name));
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&escape_param(k));
        out.push('=');
        out.push_str(&escape_param(v));
    }
    out.push_str("}]");
    out
}

/// A placeholder name: `[A-Za-z0-9_.-]{1,64}` (PD-98), the first 64 characters with every
/// other character as `-`, and every `_` that does not stand between two ASCII alphanumerics
/// as `-` too (T3 review I-1): only an intraword `_` can neither open nor close emphasis, and
/// emphasis inside a placeholder would hide it from the placeholder check. Empty → `-`.
fn fit_name(name: &str) -> String {
    let chars: Vec<char> = name
        .chars()
        .take(MAX_MACRO_NAME)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let alnum = |i: Option<usize>| {
        i.and_then(|i| chars.get(i))
            .is_some_and(char::is_ascii_alphanumeric)
    };
    let mut out: String = chars
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            if c == '_' && !(alnum(i.checked_sub(1)) && alnum(Some(i + 1))) {
                '-'
            } else {
                c
            }
        })
        .collect();
    if out.is_empty() {
        out.push('-');
    }
    out
}

/// Markdown specials that would start an inline construct (or a table cell) in prose.
fn markdown_special(c: char) -> bool {
    matches!(
        c,
        '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '&' | '!' | '~' | '|'
    )
}

/// Inline text (link text, alt text) with the Markdown specials backslash-escaped.
fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if markdown_special(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A placeholder parameter key or value: the Markdown specials and `,`, `}` (PD-95)
/// backslash-escaped, so the placeholder stays one run of text on one line.
fn escape_param(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if markdown_special(c) || matches!(c, ',' | '}') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A username: every ASCII punctuation character escaped (CommonMark allows a backslash before
/// each), so no part of a name can form a placeholder, a link or emphasis.
fn escape_all_punctuation(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_punctuation() {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn url_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-')
}

/// A user key keeps `[A-Za-z0-9.-]`; `_` is percent-encoded too (`%5F`), so no key can open or
/// close emphasis and hide a mention from the placeholder check (T3 review I-1).
fn key_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

/// Percent-encodes every byte of `s` that is not `safe`.
fn percent(s: &str, safe: fn(u8) -> bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if safe(b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// TAB, CR and LF become spaces; the ends are trimmed.
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| {
            if matches!(c, '\t' | '\r' | '\n') {
                ' '
            } else {
                c
            }
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Runs of ASCII whitespace become one space; the ends are trimmed.
fn collapse(s: &str) -> String {
    s.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

/// Whether `nodes` hold anything but XHTML elements and text (a construct, or CDATA).
fn has_construct(nodes: &[Node]) -> bool {
    nodes.iter().any(|n| match n {
        Node::Text(_) => false,
        Node::CData { .. } => true,
        Node::Element(e) => e.ns != Ns::Html || has_construct(&e.children),
    })
}

/// Whether `nodes` hold any text that is not whitespace.
fn has_text(nodes: &[Node]) -> bool {
    nodes.iter().any(|n| match n {
        Node::Text(t) | Node::CData { text: t, .. } => !t.trim().is_empty(),
        Node::Element(e) => has_text(&e.children),
    })
}

/// The text of `nodes` (CDATA included), a `<br>` as a newline.
fn plain_text(nodes: &[Node], out: &mut String) {
    for n in nodes {
        match n {
            Node::Text(t) | Node::CData { text: t, .. } => out.push_str(t),
            Node::Element(e) if e.ns == Ns::Html && e.local.eq_ignore_ascii_case("br") => {
                out.push('\n');
            }
            Node::Element(e) => plain_text(&e.children, out),
        }
    }
}

fn push_token(out: &mut String, index: usize) {
    out.push(TOKEN_OPEN);
    out.push_str(&index.to_string());
    out.push(TOKEN_CLOSE);
}

fn push_html_text(out: &mut String, t: &str) {
    for c in t.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
}

fn push_html_attr(out: &mut String, t: &str) {
    for c in t.chars() {
        match c {
            '"' => out.push_str("&quot;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
}

/// The constructs a Markdown round trip of `nodes` loses (PD-104 counting, shared with the
/// lossy-update check): each `ac:structured-macro` other than `code`/`noformat`, each other
/// `ac:` element that is not structure (`ac:emoticon`, `ac:inline-comment-marker`, …), each
/// outermost `ac:task-list` (Markdown task items are plain text, T3 review I-3; a stray
/// `ac:task` likewise) and each foreign element = 1 macro; each `ac:image` = 1 image (its
/// resource is not counted again); each `ac:link` = 1 link (likewise), and each `ri:` element
/// outside them = 1 link (a bare `ri:user` mention included); each `ac:layout` = 1 layout. A
/// macro's parameters belong to it; its rich-text body is content and counted on its own, as
/// is a task's body.
pub(crate) fn lost_counts(nodes: &[Node]) -> LostCounts {
    let mut c = LostCounts::default();
    count_nodes(nodes, &mut c, false);
    c
}

/// `in_tasks`: inside a counted task list, whose nested task lists are not counted again.
fn count_nodes(nodes: &[Node], c: &mut LostCounts, in_tasks: bool) {
    for n in nodes {
        if let Node::Element(e) = n {
            count_element(e, c, in_tasks);
        }
    }
}

fn count_element(e: &Element, c: &mut LostCounts, in_tasks: bool) {
    match (e.ns, e.local.as_str()) {
        (Ns::Other, _) => c.macros += 1,
        (Ns::Html, _) => count_nodes(&e.children, c, in_tasks),
        (Ns::Ac, "structured-macro" | "macro") => {
            if !is_code(e.attr("ac:name").unwrap_or("")) {
                c.macros += 1;
            }
            for b in e.child_elements() {
                if b.is(Ns::Ac, "rich-text-body") {
                    count_nodes(&b.children, c, in_tasks);
                } else if !(b.is(Ns::Ac, "parameter") || b.is(Ns::Ac, "plain-text-body")) {
                    count_element(b, c, in_tasks);
                }
            }
        }
        (Ns::Ac, "task-list" | "task") => {
            if !in_tasks {
                c.macros += 1;
            }
            count_nodes(&e.children, c, true);
        }
        (Ns::Ac, "image") => c.images += 1,
        (Ns::Ac, "link") => c.links += 1,
        (Ns::Ac, "layout") => {
            c.layouts += 1;
            count_nodes(&e.children, c, in_tasks);
        }
        (Ns::Ac, local) => {
            if ac_rule(local) != AcRule::Structure {
                c.macros += 1;
            }
            count_nodes(&e.children, c, in_tasks);
        }
        (Ns::Ri, _) => c.links += 1,
    }
}

/// The `htmd` settings every conversion uses.
fn converter() -> HtmlToMarkdown {
    HtmlToMarkdown::builder()
        .options(Options {
            bullet_list_marker: BulletListMarker::Dash,
            ul_bullet_spacing: 1,
            ol_number_spacing: 1,
            br_style: BrStyle::Backslash,
            hr_style: HrStyle::Dashes,
            ..Options::default()
        })
        .build()
}

/// `htmd`, the tables, the tokens, the look-alike pass, one final newline; at most `max`
/// bytes.
fn finish(html: &str, frags: &[Frag], max: usize) -> Result<String, MarkdownTooLarge> {
    let md = expand_tables(&html_to_md(html), frags);
    let (md, genuine) = substitute(&md, frags);
    within(&md, max)?;
    finalize(md, genuine, max)
}

fn html_to_md(html: &str) -> String {
    // `convert` cannot fail: html5ever reads a `&str` without I/O.
    converter().convert(html).unwrap_or_default()
}

const TRAILING: [char; 4] = ['\n', '\r', ' ', '\t'];

/// `Err` when `md` as [`finalize`] ends it would be longer than `max`. Every later stage only
/// inserts (before text, never into the trailing whitespace), so it can stop at once.
fn within(md: &str, max: usize) -> Result<(), MarkdownTooLarge> {
    let len = md.trim_end_matches(TRAILING).len();
    let final_len = if len == 0 { 0 } else { len.saturating_add(1) };
    if final_len > max {
        Err(MarkdownTooLarge)
    } else {
        Ok(())
    }
}

/// The look-alike pass and one final newline.
fn finalize(
    md: String,
    genuine: BTreeSet<(usize, PlaceholderKind)>,
    max: usize,
) -> Result<String, MarkdownTooLarge> {
    let mut md = neutralize(md, genuine, max)?;
    let end = md.trim_end_matches(TRAILING).len();
    md.truncate(end);
    if !md.is_empty() {
        md.push('\n');
    }
    within(&md, max)?;
    Ok(md)
}

/// Puts the lines of each table fragment in place of its token in `src` (`htmd`'s output,
/// where a table token stands on a line of its own): the first line after the token's line
/// prefix, every other line after its continuation (as a code block's, [`continuation`]); a
/// table on a line that holds anything else becomes one line. Other tokens stay.
fn expand_tables(src: &str, frags: &[Frag]) -> String {
    if !frags.iter().any(|f| matches!(f, Frag::Table { .. })) {
        return src.to_owned();
    }
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    let (mut line_start, mut scanned) = (0, 0);
    while let Some(open) = rest.find(TOKEN_OPEN) {
        out.push_str(rest.get(..open).unwrap_or(""));
        let after = rest.get(open + TOKEN_OPEN.len_utf8()..).unwrap_or("");
        let close = after.find(TOKEN_CLOSE);
        let table = close
            .and_then(|c| after.get(..c))
            .and_then(|i| i.parse::<usize>().ok())
            .and_then(|i| frags.get(i))
            .and_then(|f| match f {
                Frag::Table { lines } => Some(lines),
                _ => None,
            });
        let (Some(lines), Some(close)) = (table, close) else {
            out.push(TOKEN_OPEN);
            rest = after;
            continue;
        };
        rest = after.get(close + TOKEN_CLOSE.len_utf8()..).unwrap_or("");
        if let Some(nl) = out.get(scanned..).and_then(|s| s.rfind('\n')) {
            line_start = scanned + nl + 1;
        }
        let rest_blank = rest
            .chars()
            .take_while(|&c| c != '\n')
            .all(char::is_whitespace);
        let cont = continuation(out.get(line_start..).unwrap_or("")).filter(|_| rest_blank);
        let before = out.len();
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                match &cont {
                    Some(cont) if line.is_empty() => {
                        out.push('\n');
                        out.push_str(cont.trim_end());
                    }
                    Some(cont) => {
                        out.push('\n');
                        out.push_str(cont);
                    }
                    None => out.push(' '),
                }
            }
            out.push_str(line);
        }
        if let Some(nl) = out.get(before..).and_then(|s| s.rfind('\n')) {
            line_start = before + nl + 1;
        }
        scanned = out.len();
    }
    out.push_str(rest);
    out
}

/// Replaces the tokens in `src` by their fragments and returns the result with the offsets of
/// the converter's own placeholders. A fragment after an odd run of backslashes gets one more
/// (the run stays literal text). A macro placeholder followed by `(` or `:` gets that
/// character escaped (it would otherwise make the placeholder the text of a link or a link
/// reference definition); a link placeholder after a `!` gets the `!` escaped (an image).
fn substitute(src: &str, frags: &[Frag]) -> (String, BTreeSet<(usize, PlaceholderKind)>) {
    let mut out = String::with_capacity(src.len());
    let mut genuine = BTreeSet::new();
    let mut rest = src;
    // The start of the last line of `out`, from what has been scanned up to `scanned`
    // (incremental, so many code tokens on one line stay linear; T3 review m-4).
    let (mut line_start, mut scanned) = (0, 0);
    while let Some(open) = rest.find(TOKEN_OPEN) {
        push_clean(&mut out, rest.get(..open).unwrap_or(""));
        let after = rest.get(open + TOKEN_OPEN.len_utf8()..).unwrap_or("");
        let Some(close) = after.find(TOKEN_CLOSE) else {
            rest = after;
            continue;
        };
        let frag = after
            .get(..close)
            .and_then(|i| i.parse::<usize>().ok())
            .and_then(|i| frags.get(i));
        rest = after.get(close + TOKEN_CLOSE.len_utf8()..).unwrap_or("");
        // `htmd` can end a hard break's `\` without its newline right before a token
        // (`<span><br></span><a>…`); that backslash would escape the fragment's first
        // character and hide a placeholder, so it becomes a literal one.
        if frag.is_some() && escaped(&out, out.len()) {
            out.push('\\');
        }
        match frag {
            Some(Frag::Inline { md, genuine: kind }) => {
                if *kind == Some(PlaceholderKind::Link)
                    && out.ends_with('!')
                    && !escaped(&out, out.len() - 1)
                {
                    out.insert(out.len() - 1, '\\');
                }
                if let Some(k) = kind {
                    genuine.insert((out.len(), *k));
                }
                out.push_str(md);
                if *kind == Some(PlaceholderKind::Macro) && rest.starts_with(['(', ':']) {
                    out.push('\\');
                }
            }
            Some(Frag::Code { language, body }) => {
                if let Some(nl) = out.get(scanned..).and_then(|s| s.rfind('\n')) {
                    line_start = scanned + nl + 1;
                }
                scanned = out.len();
                code_block(&mut out, line_start, rest, language.as_deref(), body);
            }
            // Tables are in place already ([`expand_tables`]).
            Some(Frag::Table { .. }) | None => {}
        }
    }
    push_clean(&mut out, rest);
    (out, genuine)
}

/// Text from `htmd` without stray token characters.
fn push_clean(out: &mut String, s: &str) {
    out.extend(s.chars().filter(|&c| c != TOKEN_OPEN && c != TOKEN_CLOSE));
}

/// A code block at the end of `out`, whose last line starts at `line_start`: fenced when that
/// line holds only a list or quote prefix and the rest of the line in `rest` is blank
/// (continuation lines get the same prefix), else inline code.
fn code_block(out: &mut String, line_start: usize, rest: &str, language: Option<&str>, body: &str) {
    let prefix = out.get(line_start..).unwrap_or("");
    let table = table_row(prefix);
    let rest_blank = rest
        .chars()
        .take_while(|&c| c != '\n')
        .all(char::is_whitespace);
    match continuation(prefix) {
        Some(cont) if rest_blank => fenced(out, &cont, language, body),
        _ => inline_code(out, body, table),
    }
}

/// The prefix that continues a line starting with `prefix` (spaces, `>` and list markers,
/// which become spaces), or `None` when `prefix` holds anything else.
fn continuation(prefix: &str) -> Option<String> {
    let b = prefix.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        match c {
            b' ' | b'>' => {
                out.push(char::from(c));
                i += 1;
            }
            b'-' | b'*' | b'+' if b.get(i + 1) == Some(&b' ') => {
                out.push_str("  ");
                i += 2;
            }
            b'0'..=b'9' => {
                let digits = b
                    .get(i..)
                    .unwrap_or(&[])
                    .iter()
                    .take_while(|d| d.is_ascii_digit())
                    .count();
                let marker = matches!(b.get(i + digits), Some(b'.' | b')'))
                    && b.get(i + digits + 1) == Some(&b' ');
                if digits > 9 || !marker {
                    return None;
                }
                out.push_str(&" ".repeat(digits + 2));
                i += digits + 2;
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Whether a line starting with `prefix` is a table row: a `|` after its quote and list
/// prefix (a table inside a quote or a list item).
fn table_row(prefix: &str) -> bool {
    let mut p = prefix;
    loop {
        let t = p.trim_start_matches([' ', '>']);
        let t = t
            .strip_prefix("- ")
            .or_else(|| t.strip_prefix("* "))
            .or_else(|| t.strip_prefix("+ "))
            .or_else(|| {
                let digits = t.bytes().take_while(u8::is_ascii_digit).count();
                t.get(digits..)
                    .filter(|_| (1..=9).contains(&digits))
                    .and_then(|r| r.strip_prefix(". ").or_else(|| r.strip_prefix(") ")))
            })
            .unwrap_or(t);
        if t.len() == p.len() {
            return p.starts_with('|');
        }
        p = t;
    }
}

fn longest_run(s: &str, ch: char) -> usize {
    let (mut best, mut cur) = (0, 0);
    for c in s.chars() {
        if c == ch {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

fn fenced(out: &mut String, cont: &str, language: Option<&str>, body: &str) {
    let fence = "`".repeat(longest_run(body, '`').max(2) + 1);
    out.push_str(&fence);
    out.push_str(language.unwrap_or(""));
    let body = body.strip_suffix('\n').unwrap_or(body);
    if !body.is_empty() {
        for line in body.split('\n') {
            out.push('\n');
            if line.is_empty() {
                out.push_str(cont.trim_end());
            } else {
                out.push_str(cont);
                out.push_str(line);
            }
        }
    }
    out.push('\n');
    out.push_str(cont);
    out.push_str(&fence);
}

/// Code on one line (inside a table cell, `|` escaped as the table syntax requires).
fn inline_code(out: &mut String, body: &str, table: bool) {
    let mut content: String = body
        .chars()
        .map(|c| if matches!(c, '\n' | '\r') { ' ' } else { c })
        .collect();
    if content.trim().is_empty() {
        return;
    }
    if table {
        content = content.replace('|', "\\|");
    }
    let ticks = "`".repeat(longest_run(&content, '`') + 1);
    let pad = content.starts_with(['`', ' ']) || content.ends_with(['`', ' ']);
    out.push_str(&ticks);
    if pad {
        out.push(' ');
    }
    out.push_str(&content);
    if pad {
        out.push(' ');
    }
    out.push_str(&ticks);
}

/// Escapes what the placeholder check would count but the converter did not put there (and
/// the `&` of prose character references), until nothing is left (bounded).
fn neutralize(
    mut md: String,
    mut genuine: BTreeSet<(usize, PlaceholderKind)>,
    max: usize,
) -> Result<String, MarkdownTooLarge> {
    let at = reference_escapes(&md);
    insert_backslashes(&mut md, &mut genuine, at);
    within(&md, max)?;
    for _ in 0..MAX_PASSES {
        let mut at = tilde_fences(&md);
        let hits = placeholders::scan(&md);
        let closers = if hits.iter().any(|h| !genuine.contains(&(h.at, h.kind))) {
            link_closers(&md)
        } else {
            BTreeMap::new()
        };
        for hit in hits {
            if genuine.contains(&(hit.at, hit.kind)) {
                continue;
            }
            // An image is neutralised at its `[`, unless that `[` is a genuine link (then the
            // `!` is escaped).
            let image_bracket = hit.at + 1;
            if hit.kind == PlaceholderKind::Image
                && genuine.contains(&(image_bracket, PlaceholderKind::Link))
            {
                at.push(hit.at);
                continue;
            }
            at.push(if hit.kind == PlaceholderKind::Image {
                image_bracket
            } else {
                hit.at
            });
            // The `]` that closed the dead link is escaped with its `[`, so that the text is
            // already what `htmd` writes for it on a second round (`\[a\](…)`).
            if let Some(&close) = closers.get(&hit.at) {
                at.push(close);
            }
        }
        if at.is_empty() {
            break;
        }
        insert_backslashes(&mut md, &mut genuine, at);
        within(&md, max)?;
    }
    Ok(md)
}

/// For each link or image written as `[text](…)` or `![alt](…)` (or a reference form), the
/// offset of its closing `]`, keyed by the offset of the link's (or image's) start.
fn link_closers(md: &str) -> BTreeMap<usize, usize> {
    let mut closers = BTreeMap::new();
    // (start, end of the last child seen so far, written with brackets)
    let mut open: Vec<(usize, usize, bool)> = Vec::new();
    for (event, range) in Parser::new_ext(md, placeholders::options()).into_offset_iter() {
        if matches!(event, Event::End(TagEnd::Link | TagEnd::Image))
            && let Some((start, child_end, bracketed)) = open.pop()
            && bracketed
            && let Some(inner) = md.get(child_end..range.end)
            && let Some(i) = inner.find(']')
        {
            closers.insert(start, child_end + i);
        }
        if let Some(top) = open.last_mut() {
            top.1 = top.1.max(range.end);
        }
        match event {
            Event::Start(Tag::Link { .. }) => {
                let bracketed = md.get(range.start..).is_some_and(|s| s.starts_with('['));
                open.push((range.start, range.start + 1, bracketed));
            }
            Event::Start(Tag::Image { .. }) => {
                let bracketed = md.get(range.start..).is_some_and(|s| s.starts_with("!["));
                open.push((range.start, range.start + 2, bracketed));
            }
            _ => {}
        }
    }
    closers
}

/// Offsets that stop every `~~~` fence from opening a code block. The converter and `htmd`
/// write backtick fences only, so a tilde fence is prose: `htmd` escapes a text's leading `~`
/// but not one after leading whitespace it then trims (`<p> ~~~</p>`), and the code block
/// would hide what follows, a genuine placeholder included (found by the T3 fix round's
/// property test). Each line of such a block that starts with `~~~` is escaped too, so that no
/// fence inside it opens once the outer one is gone.
fn tilde_fences(md: &str) -> Vec<usize> {
    let mut at = Vec::new();
    for (event, range) in Parser::new_ext(md, placeholders::options()).into_offset_iter() {
        let Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(_))) = event else {
            continue;
        };
        let Some(block) = md.get(range.clone()) else {
            continue;
        };
        // The fence is the first backtick or tilde (a list marker or `>` may precede it).
        let Some(fence) = block.find(['`', '~']) else {
            continue;
        };
        if !block.get(fence..).is_some_and(|f| f.starts_with('~')) {
            continue;
        }
        at.push(range.start + fence);
        let mut line_start = range.start;
        for line in block.split_inclusive('\n') {
            let indent = line.len() - line.trim_start_matches([' ', '\t', '>']).len();
            if line.get(indent..).is_some_and(|l| l.starts_with("~~~")) {
                at.push(line_start + indent);
            }
            line_start += line.len();
        }
    }
    at
}

/// Offsets of prose character references (`&lt;`), outside code; `&#124;` is `htmd`'s own
/// escape of `|` in a table cell and stays.
fn reference_escapes(md: &str) -> Vec<usize> {
    let mut at = Vec::new();
    let mut in_code_block = false;
    for (event, range) in Parser::new_ext(md, placeholders::options()).into_offset_iter() {
        match event {
            Event::Start(Tag::CodeBlock(_)) => in_code_block = true,
            Event::End(TagEnd::CodeBlock) => in_code_block = false,
            Event::Text(t) if !in_code_block => {
                if let Some(src) = md.get(range.clone())
                    && src.starts_with('&')
                    && src != &*t
                    && src != "&#124;"
                {
                    at.push(range.start);
                }
            }
            _ => {}
        }
    }
    at
}

/// Inserts a backslash before each offset in `at` and moves the genuine offsets with them.
fn insert_backslashes(
    md: &mut String,
    genuine: &mut BTreeSet<(usize, PlaceholderKind)>,
    mut at: Vec<usize>,
) {
    if at.is_empty() {
        return;
    }
    at.sort_unstable();
    at.dedup();
    let mut out = String::with_capacity(md.len() + at.len());
    let mut last = 0;
    for &i in &at {
        out.push_str(md.get(last..i).unwrap_or(""));
        out.push('\\');
        last = i;
    }
    out.push_str(md.get(last..).unwrap_or(""));
    *md = out;
    *genuine = genuine
        .iter()
        .map(|&(p, k)| (p + at.partition_point(|&i| i <= p), k))
        .collect();
}

/// The §7.6 fallback: CDATA bodies first (fenced code), then the text of the rest with every
/// tag stripped ([`stripped_paragraphs`]); at most `max` bytes.
fn fallback(storage: &str, max: usize) -> Result<String, MarkdownTooLarge> {
    let clean: String = storage
        .chars()
        .map(|c| {
            if c == TOKEN_OPEN || c == TOKEN_CLOSE {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect();
    let clean = clean.replace("\r\n", "\n").replace('\r', "\n");
    let mut html_parts: Vec<&str> = Vec::new();
    let mut bodies: Vec<String> = Vec::new();
    let mut rest = clean.as_str();
    while let Some(i) = rest.find(CDATA_OPEN) {
        html_parts.push(rest.get(..i).unwrap_or(""));
        let mut body = String::new();
        let mut tail = rest.get(i..).unwrap_or("");
        while let Some(after) = tail.strip_prefix(CDATA_OPEN) {
            match after.find(CDATA_CLOSE) {
                Some(j) => {
                    body.push_str(after.get(..j).unwrap_or(""));
                    tail = after.get(j + CDATA_CLOSE.len()..).unwrap_or("");
                }
                None => {
                    body.push_str(after);
                    tail = "";
                }
            }
        }
        bodies.push(body);
        rest = tail;
    }
    html_parts.push(rest);
    // The code blocks stand between the parts' paragraphs at the top level.
    let mut md = String::new();
    for (i, part) in html_parts.iter().enumerate() {
        for paragraph in stripped_paragraphs(part) {
            push_block(&mut md, &paragraph);
            within(&md, max)?;
        }
        if let Some(body) = bodies.get(i) {
            let mut code = String::new();
            fenced(&mut code, "", None, body);
            push_block(&mut md, &code);
            within(&md, max)?;
        }
    }
    finalize(md, BTreeSet::new(), max)
}

/// Appends a block, separated from what is there by a blank line.
fn push_block(md: &mut String, block: &str) {
    if block.trim().is_empty() {
        return;
    }
    if !md.is_empty() {
        md.push_str("\n\n");
    }
    md.push_str(block);
}

/// HTML elements whose start or end tag ends a paragraph of the fallback's text.
const BREAK_HTML: [&str; 41] = [
    "address",
    "article",
    "aside",
    "blockquote",
    "body",
    "br",
    "caption",
    "center",
    "dd",
    "details",
    "div",
    "dl",
    "dt",
    "figcaption",
    "figure",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "summary",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "title",
    "tr",
    "ul",
];

/// `ac:` elements that sit inside a line; every other `ac:` element ends a paragraph.
const INLINE_AC: [&str; 7] = [
    "link",
    "link-body",
    "plain-text-link-body",
    "emoticon",
    "inline-comment-marker",
    "image",
    "placeholder",
];

/// The longest reference name the fallback decodes (HTML5 names are at most 31 characters).
const MAX_REFERENCE: usize = 40;

/// What the fallback makes of a tag.
enum Lexed {
    /// Nothing (inline markup, a comment, a declaration).
    Inline,
    /// The end of a paragraph.
    Break,
    /// Text in place of the tag (a date lozenge's date).
    Text(String),
}

/// The text of `src` (a part of a body that failed the XML parse) as Markdown paragraphs: every
/// tag stripped, a block-level tag ending a paragraph, references decoded, whitespace collapsed,
/// Markdown specials escaped. One linear pass: a `<` starts a tag only when a letter, `_`, `/`,
/// `!` or `?` follows and a `>` ends it (outside a quoted value) before the next `<`; any other
/// `<` is text.
fn stripped_paragraphs(src: &str) -> Vec<String> {
    let mut paragraphs = Vec::new();
    let mut cur = String::new();
    // Whether a `-->` may still follow (an unterminated comment makes its `<` text).
    let mut comment_end = true;
    let mut rest = src;
    while let Some(i) = rest.find(['<', '&']) {
        cur.push_str(rest.get(..i).unwrap_or(""));
        let at = rest.get(i..).unwrap_or("");
        if let Some(after) = at.strip_prefix('&') {
            match reference(after) {
                Some((text, len)) => {
                    cur.push_str(&text);
                    rest = after.get(len..).unwrap_or("");
                }
                None => {
                    cur.push('&');
                    rest = after;
                }
            }
            continue;
        }
        match lex_tag(at, &mut comment_end) {
            Some((lexed, len)) => {
                match lexed {
                    Lexed::Inline => {}
                    Lexed::Break => end_paragraph(&mut paragraphs, &mut cur),
                    Lexed::Text(t) => cur.push_str(&t),
                }
                rest = at.get(len..).unwrap_or("");
            }
            None => {
                cur.push('<');
                rest = at.get(1..).unwrap_or("");
            }
        }
    }
    cur.push_str(rest);
    end_paragraph(&mut paragraphs, &mut cur);
    paragraphs
}

/// The decoded text of the reference that `after` (the text after a `&`) starts with, and the
/// bytes it takes (through the `;`); `None` when it is no reference the parser would resolve.
fn reference(after: &str) -> Option<(String, usize)> {
    let (semi, _) = after
        .char_indices()
        .take(MAX_REFERENCE)
        .find(|&(_, c)| c == ';')?;
    let text = resolve_ref(after.get(..semi)?)?;
    Some((text.into_owned(), semi + 1))
}

/// The tag `at` starts with (`at` starts with `<`) and its length, or `None` when that `<` is
/// text.
fn lex_tag(at: &str, comment_end: &mut bool) -> Option<(Lexed, usize)> {
    let body = at.get(1..)?;
    if let Some(comment) = body.strip_prefix("!--") {
        if !*comment_end {
            return None;
        }
        return match comment.find("-->") {
            Some(j) => Some((Lexed::Inline, "<!--".len() + j + "-->".len())),
            None => {
                *comment_end = false;
                None
            }
        };
    }
    let name_src = body.strip_prefix('/').unwrap_or(body);
    let declaration = body.starts_with(['!', '?']);
    if !declaration && !name_src.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        return None;
    }
    let mut quote: Option<char> = None;
    let mut end = None;
    for (j, c) in body.char_indices() {
        match (quote, c) {
            (_, '<') => break,
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(c),
            (None, '>') => {
                end = Some(j);
                break;
            }
            _ => {}
        }
    }
    let end = end?;
    let len = end + 2;
    if declaration {
        return Some((Lexed::Inline, len));
    }
    let inner = body.get(..end)?;
    let closing = inner.starts_with('/');
    let tag = inner.strip_prefix('/').unwrap_or(inner);
    let name_len = tag
        .find(|c: char| c.is_whitespace() || c == '/')
        .unwrap_or(tag.len());
    let name = tag.get(..name_len)?.to_ascii_lowercase();
    // A date lozenge (`<time datetime="…"/>`) has no text but its date.
    if name == "time" && !closing && tag.trim_end().ends_with('/') {
        let date = lex_attrs(tag.get(name_len..)?)
            .into_iter()
            .find(|(k, _)| *k == "datetime")
            .map(|(_, v)| decode_attr(v).unwrap_or_else(|| v.to_owned()));
        if let Some(date) = date {
            return Some((Lexed::Text(date), len));
        }
    }
    let breaks = match name.split_once(':') {
        Some(("ac", local)) => !INLINE_AC.contains(&local),
        Some(_) => false,
        None => BREAK_HTML.contains(&name.as_str()),
    };
    Some((if breaks { Lexed::Break } else { Lexed::Inline }, len))
}

/// Ends the paragraph in `cur`: whitespace collapsed, Markdown specials escaped, and a line
/// start that would open a block (a heading, a list item, a quote) escaped too.
fn end_paragraph(paragraphs: &mut Vec<String>, cur: &mut String) {
    let text = collapse(cur);
    cur.clear();
    if text.is_empty() {
        return;
    }
    let mut out = escape_text(&text);
    if out.starts_with(['#', '-', '+', '>', '=']) {
        out.insert(0, '\\');
    } else {
        let digits = out.bytes().take_while(u8::is_ascii_digit).count();
        if (1..=9).contains(&digits) && matches!(out.as_bytes().get(digits), Some(b'.' | b')')) {
            out.insert(digits, '\\');
        }
    }
    paragraphs.push(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::placeholders::scan;

    fn convert(storage: &str) -> (String, ConversionReport) {
        let (md, report, _) = storage_to_markdown(storage, &UserResolutions::new());
        (md, report)
    }

    fn kinds(md: &str) -> Vec<PlaceholderKind> {
        scan(md).into_iter().map(|h| h.kind).collect()
    }

    /// T3 review I-1: no name turns a placeholder into emphasis that hides it from the check.
    #[test]
    fn placeholder_names_are_found_by_the_scan() {
        for (name, fitted) in [
            ("_x_", "-x-"),
            ("__init__", "--init--"),
            ("a._b_", "a.-b-"),
            ("*x*", "-x-"),
            ("a_b", "a_b"),
            ("_", "-"),
            ("", "-"),
            ("üx", "-x"),
        ] {
            let (md, report) = convert(&format!(
                "<p>a <ac:structured-macro ac:name=\"{name}\"/> b</p>"
            ));
            assert_eq!(kinds(&md), vec![PlaceholderKind::Macro], "{name}: {md}");
            assert_eq!(md, format!("a [macro: {fitted} {{}}] b\n"), "{name}");
            assert_eq!(report.lost.macros, 1, "{name}");
        }
        // A pair whose fitted names would make `_x … x_` across two placeholders.
        let (md, _) = convert(
            "<p><ac:structured-macro ac:name=\"üx\"/> and <ac:structured-macro ac:name=\"xü\"/>\
             </p>",
        );
        assert_eq!(kinds(&md), vec![PlaceholderKind::Macro; 2], "{md}");
        assert_eq!(md, "[macro: -x {}] and [macro: x- {}]\n");
        // `ac:`, `ri:` and foreign local names.
        for storage in [
            "<p>a <ac:_x_/> b</p>",
            "<p>a <ri:_x_/> b</p>",
            "<p>a <zz:_x_ xmlns:zz=\"urn:z\"/> b</p>",
        ] {
            let (md, _) = convert(storage);
            assert_eq!(kinds(&md), vec![PlaceholderKind::Macro], "{storage}: {md}");
            assert_eq!(md, "a [macro: -x- {}] b\n", "{storage}");
        }
        // Parameter keys and values are escaped, so `_` there never forms emphasis either.
        let (md, _) = convert(
            "<p><ac:structured-macro ac:name=\"m\"><ac:parameter ac:name=\"_k_\">_v_ __w__\
             </ac:parameter></ac:structured-macro> x_</p>",
        );
        assert_eq!(kinds(&md), vec![PlaceholderKind::Macro], "{md}");
        // A name 64 characters long ending in `_` at the cut.
        let long = format!("{}_x", "a".repeat(63));
        let (md, _) = convert(&format!("<ac:structured-macro ac:name=\"{long}\"/>"));
        assert_eq!(md, format!("[macro: {}- {{}}]\n", "a".repeat(63)));
        assert_eq!(kinds(&md), vec![PlaceholderKind::Macro]);
    }

    /// T10 review B-1: the writer's estimate stops a page whose line prefixes alone pass the
    /// ceiling before `htmd` sees it, and leaves an ordinary page alone.
    #[test]
    fn writer_estimate_stops_before_htmd() {
        let deep = format!(
            "{}<p>{}</p>{}",
            "<blockquote>".repeat(60),
            "x<br/>".repeat(100_000),
            "</blockquote>".repeat(60)
        );
        let doc = parse(&deep);
        assert!(doc.xml_ok);
        let users = UserResolutions::new();
        let mut w = Writer::new(&users, 4 * 1024 * 1024);
        w.nodes(&doc.nodes);
        assert!(w.stopped);
        // It stopped about where 120 bytes of prefix on two lines per break pass 4 MiB.
        assert!(w.html.len() < 200_000, "{}", w.html.len());
        let mut w = Writer::new(&users, usize::MAX);
        w.nodes(&doc.nodes);
        assert!(!w.stopped);
        assert!(w.estimate >= 100_000 * 2 * 120, "{}", w.estimate);
        // A page without quotes or lists costs its fragments only.
        let flat = "<p>a <ac:structured-macro ac:name=\"toc\"/></p>".repeat(1000);
        let doc = parse(&flat);
        let mut w = Writer::new(&users, usize::MAX);
        w.nodes(&doc.nodes);
        assert_eq!(w.estimate, 1000 * "[macro: toc {}]".len());
    }

    /// T3 review I-1: `_` in a user key is `%5F`, so `@user:_a @user:b_` is two mentions.
    #[test]
    fn user_keys_with_underscores_are_two_mentions() {
        let (md, report) =
            convert("<p><ri:user ri:userkey=\"_a\"/> <ri:user ri:userkey=\"b_\"/> __c__</p>");
        assert_eq!(kinds(&md), vec![PlaceholderKind::User; 2], "{md}");
        assert_eq!(md, "@user:%5Fa @user:b%5F \\_\\_c\\_\\_\n");
        assert_eq!(report.unresolved_users, 2);
    }
}
