//! The storage parser, the construct inventory and the static body check (plan Task 2, PD-94,
//! PD-97).
//!
//! The fragment is wrapped in a root element declaring `ac:` and `ri:` and read with a plain
//! `quick_xml::Reader` (prefixes are resolved lexically, never through `xmlns`): end names
//! checked, comments checked, no trimming, empty elements kept as such, no dangling `&`.
//! Entity and character references (`Event::GeneralRef`) and attribute values are decoded by
//! the same resolver: numeric references, then HTML5 named entities (`&nbsp;`, `&uuml;`, …);
//! an unknown named entity stays literal text (`&foo;`). Attribute values also get XML
//! attribute-value normalisation (a raw TAB, CR, LF or CRLF becomes one space).
//!
//! **Fail closed.** `xml_ok` is false, and `nodes` holds only what was read up to that point,
//! when the input is not well-formed XML 1.0 (including characters XML 1.0 forbids, raw or as a
//! reference, and `]]>` in text), nests elements deeper than [`MAX_DEPTH`], closes the wrapper
//! from inside, or holds a `<!DOCTYPE`, an `<!ENTITY` or a processing instruction (`<?…?>`,
//! the XML declaration included): quick-xml expands no DTD, so a declared entity would look
//! literal and hide what Confluence expands it to. An element carrying an `xmlns`/`xmlns:*`
//! attribute, an element with a prefix other than `ac`/`ri`, or an attribute with a prefix other
//! than `ac`/`ri`/`xml`, is read but classified [`Ns::Other`] together with its whole subtree.
//! After a DOCTYPE, a PI or the depth limit the reader keeps scanning (without building nodes)
//! so that [`check_storage_body`] can name the most important reason; after a syntax error it
//! stops.
//!
//! Ranges are byte ranges of the original input (not the wrapped one), always on char
//! boundaries. Recursion over the tree is bounded by [`MAX_DEPTH`].

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt;
use std::ops::Range;

use quick_xml::Reader;
use quick_xml::errors::{Error as XmlError, IllFormedError};
use quick_xml::escape::resolve_html5_entity;
use quick_xml::events::{BytesRef, BytesStart, Event};

use crate::wiki::{ConstructKind, WikiConstructs};

/// Deepest element nesting the parser accepts (an element at depth 65 sets `xml_ok = false`).
pub const MAX_DEPTH: usize = 64;

const ROOT_NAME: &str = "ad-storage-root";
const ROOT_OPEN: &str = "<ad-storage-root xmlns:ac=\"http://atlassian.com/content\" \
                         xmlns:ri=\"http://atlassian.com/resource/identifier\">";
const ROOT_CLOSE: &str = "</ad-storage-root>";

/// The namespace of an element, from its prefix alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ns {
    /// No prefix: plain XHTML.
    Html,
    /// `ac:`.
    Ac,
    /// `ri:`.
    Ri,
    /// Any other prefix, an `xmlns` declaration on the element, an attribute prefixed other
    /// than `ac`/`ri`/`xml`, or inside such an element (PD-94 (2)). Always counted as markup.
    Other,
}

/// One element. `attrs` keep their qualified names and source order, values decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub ns: Ns,
    /// The prefix as written (`ac`, `ri`, or a foreign one), `None` without one.
    pub prefix: Option<String>,
    pub local: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Node>,
    /// From the `<` of the start tag through the `>` of the end tag (or of `/>`). For an
    /// element still open where the parse stopped, through that point.
    pub byte_range: Range<usize>,
}

impl Element {
    /// The qualified name as written (`ac:structured-macro`, `p`).
    pub fn qname(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{p}:{}", self.local),
            None => self.local.clone(),
        }
    }

    /// The decoded value of the attribute with this qualified name.
    pub fn attr(&self, qname: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == qname)
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn is(&self, ns: Ns, local: &str) -> bool {
        self.ns == ns && self.local == local
    }

    pub(crate) fn child_elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Element(Element),
    /// Character data, references decoded and line ends normalised; consecutive text and
    /// references (also across a comment) are one node.
    Text(String),
    /// One CDATA section (opaque). The `]]]]><![CDATA[>` split yields two adjacent nodes;
    /// `byte_range` covers `<![CDATA[` through `]]>`.
    CData {
        text: String,
        byte_range: Range<usize>,
    },
}

/// A parsed storage fragment. Built only by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageDoc {
    pub nodes: Vec<Node>,
    /// False when `nodes` is incomplete (PD-94 (3)): no consumer may treat it as complete.
    pub xml_ok: bool,
    reasons: Reasons,
}

/// Why an agent-supplied storage body is refused (Δ1, PD-94). Carries no text or offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageReject {
    NotWellFormed,
    Doctype,
    EntityDecl,
    ProcessingInstruction,
    NamespaceDecl,
    UnknownPrefix,
    TooDeep,
}

impl StorageReject {
    /// snake_case name for `details.storage`.
    pub fn as_str(self) -> &'static str {
        match self {
            StorageReject::NotWellFormed => "not_well_formed",
            StorageReject::Doctype => "doctype",
            StorageReject::EntityDecl => "entity_decl",
            StorageReject::ProcessingInstruction => "processing_instruction",
            StorageReject::NamespaceDecl => "namespace_decl",
            StorageReject::UnknownPrefix => "unknown_prefix",
            StorageReject::TooDeep => "too_deep",
        }
    }
}

impl fmt::Display for StorageReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for StorageReject {}

/// The `ri:user` references of a body (Δ1): `ri:userkey` values, and legacy `ri:username`
/// values (which need no lookup).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StorageUsers {
    pub keys: BTreeSet<String>,
    pub usernames: BTreeSet<String>,
}

/// Everything the parse found wrong, not only the first thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Reasons {
    doctype: bool,
    entity_decl: bool,
    processing_instruction: bool,
    namespace_decl: bool,
    unknown_prefix: bool,
    too_deep: bool,
    not_well_formed: bool,
}

impl Reasons {
    /// Whether `nodes` is incomplete. A namespace declaration or a foreign prefix is not:
    /// the element is read and classified `Other`.
    fn fatal(&self) -> bool {
        self.doctype
            || self.entity_decl
            || self.processing_instruction
            || self.too_deep
            || self.not_well_formed
    }

    /// The reason [`check_storage_body`] names, in the Δ1 priority order.
    fn first(&self) -> Option<StorageReject> {
        [
            (self.doctype, StorageReject::Doctype),
            (self.entity_decl, StorageReject::EntityDecl),
            (
                self.processing_instruction,
                StorageReject::ProcessingInstruction,
            ),
            (self.namespace_decl, StorageReject::NamespaceDecl),
            (self.unknown_prefix, StorageReject::UnknownPrefix),
            (self.too_deep, StorageReject::TooDeep),
            (self.not_well_formed, StorageReject::NotWellFormed),
        ]
        .into_iter()
        .find_map(|(set, r)| set.then_some(r))
    }
}

/// Parses a storage fragment. Never fails and never panics; see the module doc for when
/// `xml_ok` is false.
pub fn parse(storage: &str) -> StorageDoc {
    let wrapped = [ROOT_OPEN, storage, ROOT_CLOSE].concat();
    let mut reader = Reader::from_str(&wrapped);
    let config = reader.config_mut();
    config.check_end_names = true;
    config.check_comments = true;
    config.expand_empty_elements = false;
    config.trim_text(false);
    config.allow_dangling_amp = false;
    config.allow_unmatched_ends = false;
    let mut b = Builder::new(storage, wrapped.len());
    match reader.read_event() {
        Ok(Event::Start(e))
            if e.name().into_inner() == ROOT_NAME
                && reader.buffer_position() == ROOT_OPEN.len() as u64 => {}
        _ => {
            b.reasons.not_well_formed = true;
            return b.finish();
        }
    }
    loop {
        let start = reader.buffer_position();
        let event = reader.read_event();
        let end = reader.buffer_position();
        match event {
            Err(err) => {
                let at = reader.error_position();
                b.syntax_error(&wrapped, at, &err);
                b.stop_building(at);
                break;
            }
            Ok(Event::Eof) => {
                if b.building && !b.root_closed {
                    b.reasons.not_well_formed = true;
                    b.stop_building(end);
                }
                break;
            }
            Ok(event) => {
                if !b.event(event, start, end) {
                    b.stop_building(start);
                    break;
                }
            }
        }
    }
    b.finish()
}

/// Builds the tree from the reader's events.
struct Builder<'s> {
    src: &'s str,
    wrapped_len: u64,
    /// Open elements; `frames[0]` is the wrapper.
    frames: Vec<Element>,
    nodes: Vec<Node>,
    root_closed: bool,
    /// False after a fatal reason: only reasons are collected from then on.
    building: bool,
    reasons: Reasons,
}

impl<'s> Builder<'s> {
    fn new(src: &'s str, wrapped_len: usize) -> Self {
        Builder {
            src,
            wrapped_len: wrapped_len as u64,
            frames: vec![Element {
                ns: Ns::Html,
                prefix: None,
                local: ROOT_NAME.to_owned(),
                attrs: Vec::new(),
                children: Vec::new(),
                byte_range: 0..0,
            }],
            nodes: Vec::new(),
            root_closed: false,
            building: true,
            reasons: Reasons::default(),
        }
    }

    fn finish(mut self) -> StorageDoc {
        if !self.frames.is_empty() {
            let at = self.wrapped_len;
            self.stop_building(at);
        }
        StorageDoc {
            nodes: self.nodes,
            xml_ok: !self.reasons.fatal(),
            reasons: self.reasons,
        }
    }

    /// A reader position as an offset of the original input, clamped to it and moved back
    /// onto a char boundary.
    fn offset(&self, pos: u64) -> usize {
        let pos = usize::try_from(pos).unwrap_or(usize::MAX);
        let mut at = pos.saturating_sub(ROOT_OPEN.len()).min(self.src.len());
        while !self.src.is_char_boundary(at) {
            at = at.saturating_sub(1);
        }
        at
    }

    /// Handles one event; false ends the parse (the reason is already recorded).
    fn event(&mut self, event: Event<'_>, start: u64, end: u64) -> bool {
        match event {
            Event::Start(e) => self.element(&e, start, end, false),
            Event::Empty(e) => self.element(&e, start, end, true),
            Event::End(_) => self.end(end),
            Event::Text(t) => {
                let text = t.xml10_content();
                if !xml_chars(&text) || text.contains("]]>") {
                    return self.malformed();
                }
                self.push_text(&text);
                true
            }
            Event::GeneralRef(r) => match resolve_ref(&r) {
                Some(text) => {
                    self.push_text(&text);
                    true
                }
                None => self.malformed(),
            },
            Event::CData(c) => {
                let text = c.xml10_content();
                if !xml_chars(&text) {
                    return self.malformed();
                }
                let byte_range = self.offset(start)..self.offset(end);
                self.attach(Node::CData {
                    text: text.into_owned(),
                    byte_range,
                });
                true
            }
            Event::Comment(c) => xml_chars(&c.xml10_content()) || self.malformed(),
            Event::DocType(_) => {
                self.reasons.doctype = true;
                self.stop_building(start);
                true
            }
            Event::PI(_) | Event::Decl(_) => {
                self.reasons.processing_instruction = true;
                self.stop_building(start);
                true
            }
            Event::Eof => true,
        }
    }

    fn malformed(&mut self) -> bool {
        self.reasons.not_well_formed = true;
        false
    }

    /// A start or empty tag: names and attributes are checked (and their namespace reasons
    /// recorded) even when no longer building.
    fn element(&mut self, e: &BytesStart<'_>, start: u64, end: u64, empty: bool) -> bool {
        let parent_other = self.building && self.frames.last().is_some_and(|f| f.ns == Ns::Other);
        let Some(mut el) = self.head(e, parent_other) else {
            return self.malformed();
        };
        if !self.building {
            return true;
        }
        if self.frames.len() > MAX_DEPTH {
            self.reasons.too_deep = true;
            self.stop_building(start);
            return true;
        }
        el.byte_range = self.offset(start)..self.offset(end);
        if empty {
            self.attach(Node::Element(el));
        } else {
            self.frames.push(el);
        }
        true
    }

    /// Name, attributes and namespace of a tag; `None` when not well-formed.
    fn head(&mut self, e: &BytesStart<'_>, parent_other: bool) -> Option<Element> {
        let (prefix, local) = split_qname(e.name().into_inner())?;
        let mut foreign = prefix.is_some_and(|p| p != "ac" && p != "ri");
        let mut ns_decl = false;
        let mut attrs = Vec::new();
        for attr in e.attributes() {
            let attr = attr.ok()?;
            let key = attr.key.into_inner();
            let (key_prefix, _) = split_qname(key)?;
            if is_ns_decl(key) {
                ns_decl = true;
            } else if key_prefix.is_some_and(|p| !KNOWN_ATTR_PREFIXES.contains(&p)) {
                foreign = true;
            }
            attrs.push((key.to_owned(), decode_attr(&attr.value)?));
        }
        self.reasons.namespace_decl |= ns_decl;
        self.reasons.unknown_prefix |= foreign;
        let ns = if ns_decl || foreign || parent_other {
            Ns::Other
        } else {
            match prefix {
                None => Ns::Html,
                Some("ac") => Ns::Ac,
                Some(_) => Ns::Ri,
            }
        };
        Some(Element {
            ns,
            prefix: prefix.map(str::to_owned),
            local: local.to_owned(),
            attrs,
            children: Vec::new(),
            byte_range: 0..0,
        })
    }

    /// An end tag (quick-xml already matched its name). Closing the wrapper anywhere but at
    /// the very end means the fragment closed it.
    fn end(&mut self, end: u64) -> bool {
        if !self.building {
            return true;
        }
        let Some(mut el) = self.frames.pop() else {
            return self.malformed();
        };
        if self.frames.is_empty() {
            self.nodes = std::mem::take(&mut el.children);
            self.root_closed = true;
            return end == self.wrapped_len || self.malformed();
        }
        el.byte_range.end = self.offset(end);
        self.attach(Node::Element(el));
        true
    }

    fn push_text(&mut self, text: &str) {
        if !self.building {
            return;
        }
        if let Some(Node::Text(last)) = self.frames.last_mut().and_then(|f| f.children.last_mut()) {
            last.push_str(text);
            return;
        }
        self.attach(Node::Text(text.to_owned()));
    }

    fn attach(&mut self, node: Node) {
        if !self.building {
            return;
        }
        match self.frames.last_mut() {
            Some(f) => f.children.push(node),
            None => self.nodes.push(node),
        }
    }

    /// Stops building: every open element is closed at `pos` and the wrapper's children
    /// become the nodes.
    fn stop_building(&mut self, pos: u64) {
        if !self.building {
            return;
        }
        let at = self.offset(pos);
        while let Some(mut el) = self.frames.pop() {
            el.byte_range.end = at.max(el.byte_range.start);
            match self.frames.last_mut() {
                Some(parent) => parent.children.push(Node::Element(el)),
                None => self.nodes = el.children,
            }
        }
        self.building = false;
    }

    /// Classifies a reader error by the markup at its position: a bare `<!ENTITY` (and an
    /// unparsable DOCTYPE or PI) is a syntax error to quick-xml.
    fn syntax_error(&mut self, wrapped: &str, pos: u64, err: &XmlError) {
        let at = usize::try_from(pos)
            .ok()
            .and_then(|p| wrapped.get(p..))
            .unwrap_or("");
        if matches!(err, XmlError::IllFormed(IllFormedError::MissingDoctypeName))
            || starts_with_ignore_case(at, "<!DOCTYPE")
        {
            self.reasons.doctype = true;
        } else if starts_with_ignore_case(at, "<!ENTITY") {
            self.reasons.entity_decl = true;
        } else if at.starts_with("<?") {
            self.reasons.processing_instruction = true;
        } else {
            self.reasons.not_well_formed = true;
        }
    }
}

/// Attribute prefixes that leave an element in its namespace: `ac`, `ri`, and `xml` (bound by
/// the Namespaces spec, never rebindable).
const KNOWN_ATTR_PREFIXES: [&str; 3] = ["ac", "ri", "xml"];

/// `xmlns` or `xmlns:*`.
fn is_ns_decl(key: &str) -> bool {
    key == "xmlns" || key.starts_with("xmlns:")
}

fn starts_with_ignore_case(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
}

/// Whether `c` is allowed in XML 1.0 (`Char` production).
fn xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

fn xml_chars(s: &str) -> bool {
    s.chars().all(xml_char)
}

/// An XML `NCName` (fail closed: combining marks and other exotic name chars are refused).
fn ncname(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let start =
        |c: char| c.is_ascii_alphabetic() || c == '_' || (!c.is_ascii() && c.is_alphabetic());
    start(first)
        && chars.all(|c| {
            start(c)
                || c.is_ascii_digit()
                || matches!(c, '-' | '.' | '\u{B7}')
                || (!c.is_ascii() && c.is_alphanumeric())
        })
}

/// `prefix:local` or `local`, each an `NCName`.
fn split_qname(q: &str) -> Option<(Option<&str>, &str)> {
    match q.split_once(':') {
        None => ncname(q).then_some((None, q)),
        Some((p, l)) => (ncname(p) && ncname(l)).then_some((Some(p), l)),
    }
}

/// The text of a reference (`name` is what sits between `&` and `;`): a character reference
/// to a char XML allows, an HTML5 named entity, or an unknown name kept literal. `None` for
/// anything else (not well-formed).
fn resolve_ref(name: &str) -> Option<Cow<'static, str>> {
    if name.starts_with('#') {
        return match BytesRef::new(name).resolve_char_ref() {
            Ok(Some(c)) if xml_char(c) => Some(Cow::Owned(c.to_string())),
            _ => None,
        };
    }
    if !ncname(name) {
        return None;
    }
    Some(match resolve_html5_entity(name) {
        Some(text) => Cow::Borrowed(text),
        None => Cow::Owned(format!("&{name};")),
    })
}

/// Decodes a raw attribute value with [`resolve_ref`] and normalises raw TAB, CR, LF and CRLF
/// to one space each. `None` when not well-formed (a raw `<`, a bad reference or char).
fn decode_attr(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while let Some(c) = raw.get(i..).and_then(|s| s.chars().next()) {
        match c {
            '&' => {
                let tail = raw.get(i + 1..)?;
                let semi = tail.find(';')?;
                out.push_str(&resolve_ref(tail.get(..semi)?)?);
                i += semi + 2;
            }
            '\r' => {
                out.push(' ');
                i += 1;
                if raw.get(i..).is_some_and(|s| s.starts_with('\n')) {
                    i += 1;
                }
            }
            '\n' | '\t' => {
                out.push(' ');
                i += 1;
            }
            '<' => return None,
            c if xml_char(c) => {
                out.push(c);
                i += c.len_utf8();
            }
            _ => return None,
        }
    }
    Some(out)
}

/// The static fail-closed check of an agent-supplied `body_format=storage` body (Δ1, PD-94):
/// the first reason in the order `Doctype`, `EntityDecl`, `ProcessingInstruction`,
/// `NamespaceDecl`, `UnknownPrefix`, `TooDeep`, `NotWellFormed`. A reason past a syntax error
/// the reader cannot get beyond is not seen; the body is refused either way.
pub fn check_storage_body(storage: &str) -> Result<(), StorageReject> {
    match parse(storage).reasons.first() {
        None => Ok(()),
        Some(r) => Err(r),
    }
}

/// HTML elements the Markdown → storage converter writes (PD-96), each without attributes
/// except `href` on `a`. [`construct_spans`] reports every other element as `Markup`; keep
/// this list and the converter in step.
const CONVERTER_HTML: [&str; 22] = [
    "p",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "em",
    "strong",
    "s",
    "ul",
    "ol",
    "li",
    "table",
    "tbody",
    "tr",
    "th",
    "td",
    "blockquote",
    "hr",
    "br",
    "code",
];

/// `href` schemes the converter writes as `<a>` (PD-96, PD-97 (c)), ASCII case-insensitive.
const SAFE_SCHEMES: [&str; 3] = ["http:", "https:", "mailto:"];

/// Every construct of `doc` the storage hard check judges (PD-97, Task 6), with its byte
/// range, sorted by start offset; empty for exactly what the Markdown converter writes
/// outside its code macros. Outermost constructs only, so one construct is one span:
/// - an `Ns::Other` element (with its subtree), and an HTML element outside the converter's
///   set or with attributes, are `Markup`;
/// - an `<a>` whose `href` does not start with `http:`, `https:` or `mailto:` (or has other
///   attributes) is `Link`;
/// - `ac:structured-macro` is `Include` (`include`, `excerpt-include`) or `Macro`; the content
///   of its `ac:parameter`, `ac:plain-text-body` and `ac:rich-text-body` children, and any other
///   child, is judged on its own (so an element inside a recorded code macro's parameter or
///   body is still a span; its CDATA is opaque);
/// - `ac:image` is `Image`; `ac:link` is `Mention`/`Attachment` for a `ri:user`/`ri:attachment`
///   target, else `Link`; any other `ac:` element is `Macro`;
/// - `ri:user` is `Mention`, `ri:attachment` `Attachment`, `ri:page`/`ri:space`/
///   `ri:content-entity` `Link`, any other `ri:` element `Macro`.
///
/// Meaningful only with `doc.xml_ok` (the hard check fails closed otherwise). Public, though not
/// in the Δ1 list (an addition, like [`crate::wiki::construct_spans`]), for the Task 6 hard
/// check's tests and the properties tested from outside.
pub fn construct_spans(doc: &StorageDoc) -> Vec<(ConstructKind, Range<usize>)> {
    let mut out = Vec::new();
    spans(&doc.nodes, &mut out);
    out
}

fn spans(nodes: &[Node], out: &mut Vec<(ConstructKind, Range<usize>)>) {
    for node in nodes {
        if let Node::Element(e) = node {
            span(e, out);
        }
    }
}

fn span(e: &Element, out: &mut Vec<(ConstructKind, Range<usize>)>) {
    let kind = match (e.ns, e.local.as_str()) {
        (Ns::Other, _) => ConstructKind::Markup,
        (Ns::Ac, "structured-macro") => {
            let kind = if e.attr("ac:name").is_some_and(is_include) {
                ConstructKind::Include
            } else {
                ConstructKind::Macro
            };
            out.push((kind, e.byte_range.clone()));
            for c in e.child_elements() {
                if c.is(Ns::Ac, "rich-text-body")
                    || c.is(Ns::Ac, "parameter")
                    || c.is(Ns::Ac, "plain-text-body")
                {
                    spans(&c.children, out);
                } else {
                    span(c, out);
                }
            }
            return;
        }
        (Ns::Ac, "image") => ConstructKind::Image,
        (Ns::Ac, "link") => {
            match e
                .child_elements()
                .find(|c| c.ns == Ns::Ri)
                .map(|c| c.local.as_str())
            {
                Some("user") => ConstructKind::Mention,
                Some("attachment") => ConstructKind::Attachment,
                _ => ConstructKind::Link,
            }
        }
        (Ns::Ac, _) => ConstructKind::Macro,
        (Ns::Ri, "user") => ConstructKind::Mention,
        (Ns::Ri, "attachment") => ConstructKind::Attachment,
        (Ns::Ri, "page" | "space" | "content-entity") => ConstructKind::Link,
        (Ns::Ri, _) => ConstructKind::Macro,
        (Ns::Html, "a") => {
            if matches!(e.attrs.as_slice(), [(k, href)] if k == "href" && safe_href(href)) {
                return spans(&e.children, out);
            }
            ConstructKind::Link
        }
        (Ns::Html, local) => {
            if CONVERTER_HTML.contains(&local) && e.attrs.is_empty() {
                return spans(&e.children, out);
            }
            ConstructKind::Markup
        }
    };
    out.push((kind, e.byte_range.clone()));
}

fn safe_href(href: &str) -> bool {
    SAFE_SCHEMES
        .iter()
        .any(|s| starts_with_ignore_case(href, s))
}

fn is_include(name: &str) -> bool {
    name.eq_ignore_ascii_case("include") || name.eq_ignore_ascii_case("excerpt-include")
}

/// `ac:` elements that structure content and are no construct of their own: the inventory
/// descends into them without an entry. A macro's parameters and plain-text body are skipped
/// together with the macro; standing elsewhere they are structure too.
const AC_STRUCTURE: [&str; 13] = [
    "rich-text-body",
    "task-list",
    "task",
    "task-id",
    "task-status",
    "task-body",
    "layout",
    "layout-section",
    "layout-cell",
    "link-body",
    "plain-text-link-body",
    "parameter",
    "plain-text-body",
];

/// The inventory of `storage` for the write previews (Δ1), each list in document order, one
/// entry per occurrence, strings raw (decoded, not display-escaped):
/// - `macros`: the `ac:name` of each `ac:structured-macro` (code macros included), the local
///   name of any other `ac:` element that is not structure (`emoticon`, `placeholder`, …),
///   and the qualified name of each `Ns::Other` element (listed, never dropped; its subtree is
///   not listed further);
/// - `includes`: each `include`/`excerpt-include` macro by its target page
///   (`<space>:<title>`, or `<title>`), else by its name;
/// - `mentions`: `ri:user` by a non-empty `ri:userkey`, else legacy `ri:username`;
/// - `links`: `ri:page`/`ri:blog-post` (`<space>:<title>` or `<title>`), `ri:space`,
///   `ri:content-entity`, `ri:url`, other `ri:` elements by qualified name, an `ac:link` without
///   a resource (`#anchor`), and `<a href>` values;
/// - `images`: `ac:image` by its `ri:attachment` filename or `ri:url` value (its other children,
///   a caption, are content), and `<img src>`;
/// - `attachments`: `ri:attachment` outside an `ac:image`.
///
/// HTML names compare ASCII case-insensitively. A macro's parameters belong to it and are not
/// listed again; its rich-text body is content. When the parse is not `xml_ok`, the lexical
/// scan of start tags (`lexical_constructs`) runs instead: it over-reports, never
/// under-reports (on a well-formed body each of its lists is at least as long as this one).
pub fn storage_constructs(storage: &str) -> WikiConstructs {
    let doc = parse(storage);
    if !doc.xml_ok {
        return lexical_constructs(storage);
    }
    let mut out = WikiConstructs::default();
    inventory(&doc.nodes, &mut out);
    out
}

fn inventory(nodes: &[Node], out: &mut WikiConstructs) {
    for node in nodes {
        if let Node::Element(e) = node {
            inventory_element(e, out);
        }
    }
}

fn inventory_element(e: &Element, out: &mut WikiConstructs) {
    match (e.ns, e.local.as_str()) {
        (Ns::Other, _) => out.macros.push(e.qname()),
        (Ns::Ac, "structured-macro") => {
            let name = e.attr("ac:name").unwrap_or("");
            if is_include(name) {
                out.includes
                    .push(include_target(e).unwrap_or_else(|| name.to_owned()));
            } else {
                out.macros.push(name.to_owned());
            }
            for c in e.child_elements() {
                if c.is(Ns::Ac, "rich-text-body") {
                    inventory(&c.children, out);
                } else if !(c.is(Ns::Ac, "parameter") || c.is(Ns::Ac, "plain-text-body")) {
                    inventory_element(c, out);
                }
            }
        }
        (Ns::Ac, "image") => {
            let label = e
                .child_elements()
                .find_map(|c| match (c.ns, c.local.as_str()) {
                    (Ns::Ri, "attachment") => c.attr("ri:filename"),
                    (Ns::Ri, "url") => c.attr("ri:value"),
                    _ => None,
                })
                .unwrap_or("");
            out.images.push(label.to_owned());
            // The `ri:` children are the image's source; anything else (a caption) is content.
            for c in e.child_elements().filter(|c| c.ns != Ns::Ri) {
                inventory_element(c, out);
            }
        }
        (Ns::Ac, "link") => {
            let mut target = false;
            for c in e.child_elements() {
                if c.ns == Ns::Ri {
                    target = true;
                    resource(&c.local, tree_attr(c), out);
                } else if c.is(Ns::Ac, "link-body") {
                    inventory(&c.children, out);
                }
            }
            if !target {
                let anchor = e.attr("ac:anchor").map(|a| format!("#{a}"));
                out.links.push(anchor.unwrap_or_default());
            }
        }
        (Ns::Ac, local) => {
            if !AC_STRUCTURE.contains(&local) {
                out.macros.push(local.to_owned());
            }
            inventory(&e.children, out);
        }
        (Ns::Ri, local) => resource(local, tree_attr(e), out),
        (Ns::Html, local) if local.eq_ignore_ascii_case("img") => {
            out.images.push(e.attr("src").unwrap_or("").to_owned());
        }
        (Ns::Html, local) => {
            if local.eq_ignore_ascii_case("a")
                && let Some(href) = e.attr("href")
            {
                out.links.push(href.to_owned());
            }
            inventory(&e.children, out);
        }
    }
}

/// The attribute reader of a tree element for [`resource`] and [`page_label`].
fn tree_attr(e: &Element) -> impl Fn(&str) -> Option<String> + '_ {
    |k| e.attr(k).map(str::to_owned)
}

/// The entry of the `ri:` resource `ri:<local>` outside an `ac:image`; `attr` reads a decoded
/// attribute value. The tree and the lexical scan list a resource the same way.
fn resource(local: &str, attr: impl Fn(&str) -> Option<String>, out: &mut WikiConstructs) {
    let value = |k: &str| attr(k).unwrap_or_default();
    match local {
        "user" => out.mentions.push(
            attr("ri:userkey")
                .filter(|k| !k.is_empty())
                .or_else(|| attr("ri:username"))
                .unwrap_or_default(),
        ),
        "attachment" => out.attachments.push(value("ri:filename")),
        "page" | "blog-post" => out.links.push(page_label(&attr)),
        "space" => out.links.push(value("ri:space-key")),
        "content-entity" => out.links.push(value("ri:content-id")),
        "url" => out.links.push(value("ri:value")),
        _ => out.links.push(format!("ri:{local}")),
    }
}

/// `<space>:<title>` when a space key is given, else `<title>`.
fn page_label(attr: impl Fn(&str) -> Option<String>) -> String {
    let title = attr("ri:content-title").unwrap_or_default();
    match attr("ri:space-key") {
        Some(space) => format!("{space}:{title}"),
        None => title,
    }
}

/// The first `ri:page` inside an include macro (depth first).
fn include_target(e: &Element) -> Option<String> {
    e.child_elements().find_map(|c| {
        if c.is(Ns::Ri, "page") {
            Some(page_label(tree_attr(c)))
        } else {
            include_target(c)
        }
    })
}

/// The `ri:user` references of `storage` (Δ1), from the parsed tree: CDATA is opaque, an
/// `Ns::Other` subtree holds no `ri:` element, and an empty value is no reference (no lookup
/// is issued for it). When the parse is not `xml_ok`, only what was read up to the failure
/// point counts (`storage_to_markdown` then runs its fallback, which renders no mention).
pub fn storage_user_refs(storage: &str) -> StorageUsers {
    user_refs(&parse(storage))
}

/// [`storage_user_refs`] of an already parsed fragment.
pub(crate) fn user_refs(doc: &StorageDoc) -> StorageUsers {
    let mut out = StorageUsers::default();
    users(&doc.nodes, &mut out);
    out
}

fn users(nodes: &[Node], out: &mut StorageUsers) {
    for node in nodes {
        let Node::Element(e) = node else { continue };
        if e.is(Ns::Ri, "user") {
            if let Some(key) = e.attr("ri:userkey").filter(|k| !k.is_empty()) {
                out.keys.insert(key.to_owned());
            }
            if let Some(name) = e.attr("ri:username").filter(|n| !n.is_empty()) {
                out.usernames.insert(name.to_owned());
            }
        }
        users(&e.children, out);
    }
}

/// The inventory of a body whose parse is not `xml_ok` (PD-94 (3)): a scan of every start tag
/// (CDATA and comments included, since their bounds cannot be trusted either), each listed by
/// the rules of [`storage_constructs`] that need no tree. It over-reports, never under-reports:
/// on a well-formed body each list is at least as long as the tree's, because the scan sees
/// every element the tree lists, in the same list, plus those inside macro parameters, foreign
/// subtrees, CDATA and comments.
/// - A tag the tree makes `Ns::Other` (a prefix other than `ac`/`ri`, an `xmlns`/`xmlns:*`
///   attribute, an attribute prefixed other than `ac`/`ri`/`xml`) is listed under `macros` by
///   its name as written, and by the rules below as well.
/// - `ac:structured-macro` by its `ac:name` (an include by that name), `ac:image` and `ac:link`
///   with an empty label (their children are listed on their own), any other `ac:` element
///   outside the structure list by its local name, a `ri:` resource as in the tree, `<a>` by its
///   `href` (else empty) and `<img>` by its `src`, the HTML names ASCII case-insensitive.
///
/// Attributes are read lexically (a quoted value may hold `>`; nothing runs past the next `<`)
/// and decoded like the tree's, raw where the value is not well-formed.
pub(crate) fn lexical_constructs(storage: &str) -> WikiConstructs {
    let mut out = WikiConstructs::default();
    for (i, _) in storage.match_indices('<') {
        let Some(rest) = storage.get(i + 1..) else {
            continue;
        };
        let name_len = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '>' | '<'))
            .unwrap_or(rest.len());
        let (Some(name), Some(after)) = (rest.get(..name_len), rest.get(name_len..)) else {
            continue;
        };
        if name.is_empty() || name.starts_with(['!', '?', '/']) {
            continue;
        }
        let attrs = lex_attrs(after);
        let attr = |k: &str| {
            attrs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| decode_attr(v).unwrap_or_else(|| (*v).to_owned()))
        };
        let (prefix, local) = match name.split_once(':') {
            Some((p, l)) => (Some(p), l),
            None => (None, name),
        };
        let foreign_attr = |k: &str| {
            is_ns_decl(k)
                || k.split_once(':')
                    .is_some_and(|(p, _)| !KNOWN_ATTR_PREFIXES.contains(&p))
        };
        if prefix.is_some_and(|p| p != "ac" && p != "ri")
            || attrs.iter().any(|(k, _)| foreign_attr(k))
        {
            out.macros.push(name.to_owned());
        }
        match prefix {
            Some("ac") => match local {
                "structured-macro" => {
                    let macro_name = attr("ac:name").unwrap_or_default();
                    if is_include(&macro_name) {
                        out.includes.push(macro_name);
                    } else {
                        out.macros.push(macro_name);
                    }
                }
                "image" => out.images.push(String::new()),
                "link" => out.links.push(String::new()),
                l if AC_STRUCTURE.contains(&l) => {}
                l => out.macros.push(l.to_owned()),
            },
            Some("ri") => resource(local, attr, &mut out),
            Some(_) => {}
            None if local.eq_ignore_ascii_case("img") => {
                out.images.push(attr("src").unwrap_or_default());
            }
            None if local.eq_ignore_ascii_case("a") => {
                out.links.push(attr("href").unwrap_or_default());
            }
            None => {}
        }
    }
    out
}

/// The attributes of a start tag, read lexically from just after its name: each name with its
/// raw value (empty without `=`), up to the `>` that ends the tag outside a quoted value, or up
/// to the next `<` (which no well-formed value holds).
fn lex_attrs(tag: &str) -> Vec<(&str, &str)> {
    let name_end = |c: char| c.is_whitespace() || matches!(c, '=' | '>' | '<' | '/');
    let mut out = Vec::new();
    let mut rest = tag;
    loop {
        rest = rest.trim_start();
        let Some(c) = rest.chars().next() else {
            break;
        };
        if matches!(c, '>' | '<') {
            break;
        }
        let len = rest.find(name_end).unwrap_or(rest.len());
        if len == 0 {
            // A `/` or a stray `=`.
            rest = rest.get(c.len_utf8()..).unwrap_or("");
            continue;
        }
        let name = rest.get(..len).unwrap_or("");
        rest = rest.get(len..).unwrap_or("").trim_start();
        let Some(value) = rest.strip_prefix('=') else {
            out.push((name, ""));
            continue;
        };
        let value = value.trim_start();
        let (value, after) = match value.chars().next() {
            Some(q @ ('"' | '\'')) => {
                let body = value.get(1..).unwrap_or("");
                let end = body.find([q, '<']).unwrap_or(body.len());
                let after = body.get(end..).unwrap_or("");
                (
                    body.get(..end).unwrap_or(""),
                    after.strip_prefix(q).unwrap_or(after),
                )
            }
            _ => {
                let end = value
                    .find(|c: char| c.is_whitespace() || matches!(c, '>' | '<'))
                    .unwrap_or(value.len());
                (
                    value.get(..end).unwrap_or(""),
                    value.get(end..).unwrap_or(""),
                )
            }
        };
        out.push((name, value));
        rest = after;
    }
    out
}
