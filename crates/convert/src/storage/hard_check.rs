//! The storage re-parse hard check (spec §7.6, Δ1, PD-97): the Markdown → storage converter's
//! output is parsed with the storage parser ([`super::parse`]), and every construct
//! [`construct_spans`] reports must be a code macro the converter recorded. Anything else
//! means the escaping failed, and the conversion is rejected.
//!
//! Fail closed throughout:
//! - (e) a re-parse that is not `xml_ok` (malformed, nested deeper than 64, a DOCTYPE, an
//!   entity declaration or a processing instruction) is refused as `Markup`, never checked half;
//! - (a)–(c) every `ac:`/`ri:` element, every element outside the converter's own set (or with
//!   attributes it never writes) and every `<a>` whose `href` is not `http`, `https` or `mailto`
//!   is unrecorded unless it is a trusted code macro; so is a comment (the converter writes
//!   none outside CDATA), as `Markup`; and so is a CDATA section outside every construct (the
//!   converter writes CDATA only inside a code macro);
//! - (d) a record is trusted only when its range is exactly one `ac:structured-macro` element of
//!   the tree written byte for byte as the converter writes a code macro: `ac:name="code"` and
//!   no other attribute, an optional first `ac:parameter ac:name="language"` holding one word of
//!   `[A-Za-z0-9+#-]{1,32}`, then one `ac:plain-text-body` holding only adjacent CDATA sections,
//!   and nothing else (no whitespace between the parts, no comment between the sections, no
//!   nesting). Only `ContainerKind::CodeMacro` records count; any other kind licenses nothing.
//!
//! The error names the kind of the first unrecorded construct in document order and how many
//! of that kind there are; never text or offsets.

use std::collections::{HashMap, HashSet};
use std::ops::Range;

use super::parse::{Element, Node, Ns, StorageDoc, construct_spans, parse};
use crate::hard_check::Unrecorded;
use crate::md_to_wiki::{ContainerKind, EmittedConstructs};
use crate::wiki::ConstructKind;

const CODE_OPEN: &str = "<ac:structured-macro ac:name=\"code\">";
const CODE_CLOSE: &str = "</ac:structured-macro>";
const LANG_OPEN: &str = "<ac:parameter ac:name=\"language\">";
const LANG_CLOSE: &str = "</ac:parameter>";
const BODY_OPEN: &str = "<ac:plain-text-body>";
const BODY_CLOSE: &str = "</ac:plain-text-body>";
const CDATA_OPEN: &str = "<![CDATA[";
const CDATA_CLOSE: &str = "]]>";

/// Longest code-macro language the converter writes.
const MAX_LANG: usize = 32;

/// Re-parses the storage `s` and checks every construct against `e` (Δ1, PD-97). `Err` names
/// the kind of the first unrecorded construct (by start offset) and the number of unrecorded
/// constructs of that kind; an unparsable `s` is `Err` with kind `Markup` and count 1. Pure;
/// never panics, whatever the ranges in `e`.
pub fn hard_check_storage(s: &str, e: &EmittedConstructs) -> Result<(), Unrecorded> {
    let doc = parse(s);
    if !doc.xml_ok {
        return Err(Unrecorded {
            kind: ConstructKind::Markup,
            count: 1,
        });
    }
    let trusted = trusted_ranges(s, &doc, e);
    let all = construct_spans(&doc);
    let mut spans: Vec<(ConstructKind, Range<usize>)> = all
        .iter()
        .filter(|(kind, r)| !(*kind == ConstructKind::Macro && trusted.contains(&(r.start, r.end))))
        .cloned()
        .collect();
    spans.extend(
        comments(s, &doc)
            .into_iter()
            .map(|r| (ConstructKind::Markup, r)),
    );
    spans.extend(
        stray_cdata(&doc, &all)
            .into_iter()
            .map(|r| (ConstructKind::Markup, r)),
    );
    spans.sort_by_key(|(_, r)| r.start);
    let mut first: Option<ConstructKind> = None;
    let mut count: u64 = 0;
    for (kind, _) in spans {
        if *first.get_or_insert(kind) == kind {
            count = count.saturating_add(1);
        }
    }
    match first {
        None => Ok(()),
        Some(kind) => Err(Unrecorded { kind, count }),
    }
}

/// The `(start, end)` of each `CodeMacro` record that slices exactly one code macro of the
/// converter's shape.
fn trusted_ranges(s: &str, doc: &StorageDoc, e: &EmittedConstructs) -> HashSet<(usize, usize)> {
    let mut macros = HashMap::new();
    structured_macros(&doc.nodes, &mut macros);
    e.code_blocks
        .iter()
        .filter(|c| c.kind == ContainerKind::CodeMacro)
        .map(|c| (c.byte_range.start, c.byte_range.end))
        .filter(|key| macros.get(key).is_some_and(|m| converter_code_macro(s, m)))
        .collect()
}

/// Every `ac:structured-macro` of the tree by its byte range (the tree of an `xml_ok` parse is
/// at most [`super::MAX_DEPTH`] deep, so the recursion is bounded).
fn structured_macros<'d>(nodes: &'d [Node], out: &mut HashMap<(usize, usize), &'d Element>) {
    for node in nodes {
        if let Node::Element(el) = node {
            if el.is(Ns::Ac, "structured-macro") {
                out.insert((el.byte_range.start, el.byte_range.end), el);
            }
            structured_macros(&el.children, out);
        }
    }
}

/// Whether `m` is a code macro exactly as the Markdown → storage converter writes it: the
/// tree has the converter's shape, and the source slice is that shape rebuilt from the tree
/// byte for byte (so the CDATA sections close where the record says, and nothing the tree does
/// not show, a comment, whitespace or a reference, sits in between).
fn converter_code_macro(s: &str, m: &Element) -> bool {
    let name_only = |e: &Element, value: &str| matches!(e.attrs.as_slice(), [(k, v)] if k == "ac:name" && v == value);
    if !(m.is(Ns::Ac, "structured-macro") && name_only(m, "code")) {
        return false;
    }
    let parts: Option<Vec<&Element>> = m
        .children
        .iter()
        .map(|n| match n {
            Node::Element(e) => Some(e),
            _ => None,
        })
        .collect();
    let (lang, body) = match parts.as_deref() {
        Some([body]) => (None, *body),
        Some([param, body]) => {
            let lang = match param.children.as_slice() {
                [Node::Text(t)] if language(t) => t.as_str(),
                _ => return false,
            };
            if !(param.is(Ns::Ac, "parameter") && name_only(param, "language")) {
                return false;
            }
            (Some(lang), *body)
        }
        _ => return false,
    };
    if !(body.is(Ns::Ac, "plain-text-body") && body.attrs.is_empty()) || body.children.is_empty() {
        return false;
    }
    let mut expected = String::from(CODE_OPEN);
    if let Some(l) = lang {
        expected.push_str(LANG_OPEN);
        expected.push_str(l);
        expected.push_str(LANG_CLOSE);
    }
    expected.push_str(BODY_OPEN);
    for n in &body.children {
        let Node::CData { text, .. } = n else {
            return false;
        };
        expected.push_str(CDATA_OPEN);
        expected.push_str(text);
        expected.push_str(CDATA_CLOSE);
    }
    expected.push_str(BODY_CLOSE);
    expected.push_str(CODE_CLOSE);
    s.get(m.byte_range.clone()) == Some(expected.as_str())
}

/// `[A-Za-z0-9+#-]{1,32}` (PD-95, PD-96).
fn language(s: &str) -> bool {
    (1..=MAX_LANG).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'#' | b'-'))
}

/// The ranges of the comments of `s` (the tree drops them). In an `xml_ok` fragment a raw `<`
/// stands only in markup and CDATA, and a comment cannot hold `--`, so each `<!--` outside a
/// CDATA section starts a comment that ends at the next `-->`.
fn comments(s: &str, doc: &StorageDoc) -> Vec<Range<usize>> {
    let mut cdata = Vec::new();
    cdata_ranges(&doc.nodes, &mut cdata);
    cdata.sort_by_key(|r| r.start);
    let mut out = Vec::new();
    for (at, _) in s.match_indices("<!--") {
        let idx = cdata.partition_point(|r| r.start <= at);
        let in_cdata = idx
            .checked_sub(1)
            .and_then(|i| cdata.get(i))
            .is_some_and(|r| r.contains(&at));
        if in_cdata {
            continue;
        }
        let end = s
            .get(at..)
            .and_then(|rest| rest.find("-->"))
            .map_or(s.len(), |i| at + i + "-->".len());
        out.push(at..end);
    }
    out
}

/// The CDATA sections that lie in no construct span: the converter writes CDATA only in the
/// body of a code macro (a construct itself, trusted or reported), so any other section is
/// escaping gone wrong, and counts as `Markup` like a comment. `all` holds the outermost,
/// disjoint construct spans.
fn stray_cdata(doc: &StorageDoc, all: &[(ConstructKind, Range<usize>)]) -> Vec<Range<usize>> {
    let mut spans: Vec<&Range<usize>> = all.iter().map(|(_, r)| r).collect();
    spans.sort_by_key(|r| r.start);
    let mut cdata = Vec::new();
    cdata_ranges(&doc.nodes, &mut cdata);
    cdata
        .into_iter()
        .filter(|c| {
            let idx = spans.partition_point(|r| r.start <= c.start);
            !idx.checked_sub(1)
                .and_then(|i| spans.get(i))
                .is_some_and(|r| r.start <= c.start && c.end <= r.end)
        })
        .collect()
}

fn cdata_ranges(nodes: &[Node], out: &mut Vec<Range<usize>>) {
    for node in nodes {
        match node {
            Node::CData { byte_range, .. } => out.push(byte_range.clone()),
            Node::Element(el) => cdata_ranges(&el.children, out),
            Node::Text(_) => {}
        }
    }
}
