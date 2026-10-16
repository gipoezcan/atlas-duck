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
//! first (adjacent ones joined, each a fenced code block at the top level), each part between
//! them goes through `htmd` (whose parser is `html5ever`) on its own, and the look-alike pass
//! runs as above. No mention is rendered, no user map is used and nothing is counted (`fallback`
//! and `lossy` say so). A part nested deeper than [`MAX_DEPTH`] (counted lexically) loses its
//! tags first, since `htmd` walks the tree recursively; U+FFFE and U+FFFF become U+FFFD.

use std::collections::{BTreeMap, BTreeSet};

use htmd::HtmlToMarkdown;
use htmd::options::{BrStyle, BulletListMarker, HrStyle, Options};
use pulldown_cmark::{Event, Parser, Tag, TagEnd};

use super::parse::{Element, MAX_DEPTH, Node, Ns, parse, user_refs};
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

/// Macros the conversion names without listing them in `unknown_macros` (plan text PD-95;
/// provisional, lead ruling Q11). Every macro but `code` and `noformat` still counts as lost.
pub const KNOWN_MACROS: [&str; 14] = [
    "code", "noformat", "info", "note", "warning", "tip", "panel", "expand", "toc", "status",
    "anchor", "excerpt", "children", "jira",
];

/// `ac:` elements that mark up content without being content: written as their content alone
/// (no placeholder, no `unknown_macros` entry) but each counted as one lost macro, because a
/// Markdown round trip drops them. `ac:inline-comment-marker` binds an inline comment to the
/// text it wraps; dropping it detaches the comment (lead default 2026-10-16, Task 2 review
/// ruling). This is the one place that rule lives: moving a name to [`AC_STRUCTURE`] makes it
/// uncounted, removing it makes it a `[macro: …]` placeholder.
const AC_MARKERS: [&str; 1] = ["inline-comment-marker"];

/// `ac:` elements that structure content (descended into, never counted).
const AC_STRUCTURE: [&str; 12] = [
    "rich-text-body",
    "task-list",
    "task",
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

/// XHTML elements written back by name; any other becomes a `<span>`.
const PASS_HTML: [&str; 63] = [
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
    "table",
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
/// `None` where `users` lacks it (legacy `ri:username` mentions need no entry). The fallback
/// uses no map and returns an empty one.
/// Pure and deterministic; never panics.
pub fn storage_to_markdown(
    storage: &str,
    users: &UserResolutions,
) -> (String, ConversionReport, UserResolutions) {
    let doc = parse(storage);
    if !doc.xml_ok {
        let report = ConversionReport {
            lossy: true,
            fallback: true,
            ..ConversionReport::default()
        };
        return (fallback(storage), report, UserResolutions::new());
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
    let mut w = Writer::new(&used);
    w.nodes(&doc.nodes);
    let lost = lost_counts(&doc.nodes);
    let md = finish(&w.html, &w.frags);
    let report = ConversionReport {
        lossy: lost != LostCounts::default(),
        lost,
        unknown_macros: w.unknown,
        unresolved_users: w.unresolved,
        fallback: false,
    };
    (md, report, used)
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
}

/// Writes the HTML for `htmd` and collects the fragments.
struct Writer<'u> {
    users: &'u UserResolutions,
    html: String,
    frags: Vec<Frag>,
    unknown: Vec<String>,
    seen: BTreeSet<String>,
    unresolved: u64,
}

impl<'u> Writer<'u> {
    fn new(users: &'u UserResolutions) -> Self {
        Writer {
            users,
            html: String::new(),
            frags: Vec::new(),
            unknown: Vec::new(),
            seen: BTreeSet::new(),
            unresolved: 0,
        }
    }

    fn token(&mut self, frag: Frag) {
        push_token(&mut self.html, self.frags.len());
        self.frags.push(frag);
    }

    fn inline(&mut self, md: String, genuine: Option<PlaceholderKind>) {
        self.token(Frag::Inline { md, genuine });
    }

    /// A fragment on its own lines.
    fn block(&mut self, frag: Frag) {
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
        let constructs = has_construct(&e.children);
        match name.as_str() {
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
                    self.unknown(local);
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
            if !KNOWN_MACROS.iter().any(|k| k.eq_ignore_ascii_case(name)) {
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
    }
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

/// `[macro: <name> {<k>=<v>, …}]`: the name made to fit `[A-Za-z0-9_.-]{1,64}` (any other
/// character becomes `_`), keys and values escaped by [`escape_param`].
fn macro_placeholder(name: &str, params: &[(String, String)]) -> String {
    let mut fitted: String = name
        .chars()
        .take(MAX_MACRO_NAME)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if fitted.is_empty() {
        fitted.push('_');
    }
    let mut out = format!("[macro: {fitted} {{");
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

fn key_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
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
/// `ac:` element that is not structure (`ac:emoticon`, `ac:inline-comment-marker`, …) and each
/// foreign element = 1 macro; each `ac:image` = 1 image (its resource is not counted again);
/// each `ac:link` = 1 link (likewise), and each `ri:` element outside them = 1 link (a bare
/// `ri:user` mention included); each `ac:layout` = 1 layout. A macro's parameters belong to it;
/// its rich-text body is content and counted on its own.
pub(crate) fn lost_counts(nodes: &[Node]) -> LostCounts {
    let mut c = LostCounts::default();
    count_nodes(nodes, &mut c);
    c
}

fn count_nodes(nodes: &[Node], c: &mut LostCounts) {
    for n in nodes {
        if let Node::Element(e) = n {
            count_element(e, c);
        }
    }
}

fn count_element(e: &Element, c: &mut LostCounts) {
    match (e.ns, e.local.as_str()) {
        (Ns::Other, _) => c.macros += 1,
        (Ns::Html, _) => count_nodes(&e.children, c),
        (Ns::Ac, "structured-macro" | "macro") => {
            if !is_code(e.attr("ac:name").unwrap_or("")) {
                c.macros += 1;
            }
            for b in e.child_elements() {
                if b.is(Ns::Ac, "rich-text-body") {
                    count_nodes(&b.children, c);
                } else if !(b.is(Ns::Ac, "parameter") || b.is(Ns::Ac, "plain-text-body")) {
                    count_element(b, c);
                }
            }
        }
        (Ns::Ac, "image") => c.images += 1,
        (Ns::Ac, "link") => c.links += 1,
        (Ns::Ac, "layout") => {
            c.layouts += 1;
            count_nodes(&e.children, c);
        }
        (Ns::Ac, local) => {
            if ac_rule(local) != AcRule::Structure {
                c.macros += 1;
            }
            count_nodes(&e.children, c);
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

/// `htmd`, the tokens, the look-alike pass, one final newline.
fn finish(html: &str, frags: &[Frag]) -> String {
    let (md, genuine) = substitute(&html_to_md(html), frags);
    finalize(md, genuine)
}

fn html_to_md(html: &str) -> String {
    // `convert` cannot fail: html5ever reads a `&str` without I/O.
    converter().convert(html).unwrap_or_default()
}

/// The look-alike pass and one final newline.
fn finalize(md: String, genuine: BTreeSet<(usize, PlaceholderKind)>) -> String {
    let mut md = neutralize(md, genuine);
    let end = md.trim_end_matches(['\n', '\r', ' ', '\t']).len();
    md.truncate(end);
    if !md.is_empty() {
        md.push('\n');
    }
    md
}

/// Replaces the tokens in `src` by their fragments and returns the result with the offsets of
/// the converter's own placeholders. A macro placeholder followed by `(` or `:` gets that
/// character escaped (it would otherwise make the placeholder the text of a link or a link
/// reference definition); a link placeholder after a `!` gets the `!` escaped (an image).
fn substitute(src: &str, frags: &[Frag]) -> (String, BTreeSet<(usize, PlaceholderKind)>) {
    let mut out = String::with_capacity(src.len());
    let mut genuine = BTreeSet::new();
    let mut rest = src;
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
                code_block(&mut out, rest, language.as_deref(), body);
            }
            None => {}
        }
    }
    push_clean(&mut out, rest);
    (out, genuine)
}

/// Text from `htmd` without stray token characters.
fn push_clean(out: &mut String, s: &str) {
    out.extend(s.chars().filter(|&c| c != TOKEN_OPEN && c != TOKEN_CLOSE));
}

/// A code block at the end of `out`: fenced when its line holds only a list or quote prefix
/// (continuation lines get the same prefix), else inline code.
fn code_block(out: &mut String, rest: &str, language: Option<&str>, body: &str) {
    let line_start = out.rfind('\n').map_or(0, |i| i + 1);
    let prefix = out.get(line_start..).unwrap_or("").to_owned();
    let line_rest = rest.split('\n').next().unwrap_or("");
    match continuation(&prefix) {
        Some(cont) if line_rest.trim().is_empty() => fenced(out, &cont, language, body),
        _ => inline_code(out, body, prefix.starts_with('|')),
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
fn neutralize(mut md: String, mut genuine: BTreeSet<(usize, PlaceholderKind)>) -> String {
    let at = reference_escapes(&md);
    insert_backslashes(&mut md, &mut genuine, at);
    for _ in 0..MAX_PASSES {
        let mut at = Vec::new();
        for hit in placeholders::scan(&md) {
            if genuine.contains(&(hit.at, hit.kind)) {
                continue;
            }
            // An image is neutralised at its `[`, unless that `[` is a genuine link (then the
            // `!` is escaped).
            let image_bracket = hit.at + 1;
            at.push(
                if hit.kind == PlaceholderKind::Image
                    && !genuine.contains(&(image_bracket, PlaceholderKind::Link))
                {
                    image_bracket
                } else {
                    hit.at
                },
            );
        }
        if at.is_empty() {
            break;
        }
        insert_backslashes(&mut md, &mut genuine, at);
    }
    md
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

/// The §7.6 fallback: CDATA bodies first, then `htmd` over the rest.
fn fallback(storage: &str) -> String {
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
    // Each part is converted on its own and the code blocks stand between them at the top
    // level, so markup left open in one part (an unclosed `<b>`) cannot wrap a code block.
    let mut md = String::new();
    for (i, part) in html_parts.iter().enumerate() {
        let part_md = if too_deep(part) {
            let mut text = String::new();
            strip_tags(part, &mut text);
            html_to_md(&text)
        } else {
            html_to_md(part)
        };
        push_block(&mut md, part_md.trim_matches('\n'));
        if let Some(body) = bodies.get(i) {
            let mut code = String::new();
            fenced(&mut code, "", None, body);
            push_block(&mut md, &code);
        }
    }
    finalize(md, BTreeSet::new())
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

/// Whether `html` opens more than [`MAX_DEPTH`] elements at once, read the way an HTML parser
/// would: a non-void start tag opens (`/>` does not close it), an end tag closes back to the
/// nearest open element of its name.
fn too_deep(html: &str) -> bool {
    let mut open: Vec<String> = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find('<') {
        rest = rest.get(i + 1..).unwrap_or("");
        let (end, name_src) = match rest.strip_prefix('/') {
            Some(r) => (true, r),
            None => (false, rest),
        };
        let len = name_src
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '>' | '<'))
            .unwrap_or(name_src.len());
        let name = name_src.get(..len).unwrap_or("").to_ascii_lowercase();
        if !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
            continue;
        }
        if end {
            if let Some(p) = open.iter().rposition(|n| *n == name) {
                open.truncate(p);
            }
        } else if !VOID_HTML.contains(&name.as_str()) {
            open.push(name);
            if open.len() > MAX_DEPTH {
                return true;
            }
        }
    }
    false
}

/// `s` without its tags; a `<` that starts no tag is escaped.
fn strip_tags(s: &str, out: &mut String) {
    let mut rest = s;
    while let Some(i) = rest.find('<') {
        out.push_str(rest.get(..i).unwrap_or(""));
        let after = rest.get(i + 1..).unwrap_or("");
        match after.find('>') {
            Some(j) => rest = after.get(j + 1..).unwrap_or(""),
            None => {
                out.push_str("&lt;");
                rest = after;
            }
        }
    }
    out.push_str(rest);
}
