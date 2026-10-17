//! The lossy-update count and the raw-diff line projection (plan Task 7, spec §7.6 "Lossy
//! updates", §6.3 Edit/update, PD-94, PD-104).
//!
//! **One rule set.** [`lossy_update`] counts each side with `to_md::lost_counts`, the function
//! that fills `ConversionReport.lost`, so what a read reports in `meta.conversion.lost` and
//! what an update's Caution says it removes cannot disagree on a body that parses. A current
//! side whose parse is not `xml_ok` is counted by a lexical scan of its start tags (PD-94 (3))
//! that feeds each tag, as a childless element, to the same function: it over-reports, never
//! under-reports. An outgoing side that is not `xml_ok` counts as zero constructs, so its
//! over-reporting can never offset what the update removes.

use super::parse::{Element, Node, Ns, decode_attr, lex_attrs, parse};
use super::to_md::{LostCounts, lost_counts};

/// Attribute prefixes that leave an element in its namespace (the parser's rule, PD-94 (2)).
const KNOWN_ATTR_PREFIXES: [&str; 3] = ["ac", "ri", "xml"];

/// What a Markdown update removes (Δ1, PD-104): per kind, the count of `current` minus the
/// count of `outgoing`, saturating at 0. Outermost constructs only, by the rules of the read's
/// `meta.conversion.lost`: each `ac:structured-macro` other than `code`/`noformat`, each other
/// non-structural `ac:` element, each outermost `ac:task-list` (or stray `ac:task`) and each
/// foreign element = 1 macro; each `ac:image` = 1 image; each `ac:link` = 1 link, and each `ri:`
/// element outside an `ac:link`/`ac:image` = 1 link (a bare mention included); each
/// `ac:layout` = 1 layout. A current side whose parse is not `xml_ok` is counted lexically
/// (over-counting is the safe direction); an outgoing side that is not `xml_ok` counts as zero,
/// since over-counting it would hide a loss.
/// Pure and deterministic; never panics.
pub fn lossy_update(current: &str, outgoing: &str) -> LostCounts {
    let o = parse(outgoing);
    let o = if o.xml_ok {
        lost_counts(&o.nodes)
    } else {
        LostCounts::default()
    };
    let c = count(current);
    LostCounts {
        macros: c.macros.saturating_sub(o.macros),
        images: c.images.saturating_sub(o.images),
        links: c.links.saturating_sub(o.links),
        layouts: c.layouts.saturating_sub(o.layouts),
    }
}

fn count(storage: &str) -> LostCounts {
    let doc = parse(storage);
    if doc.xml_ok {
        lost_counts(&doc.nodes)
    } else {
        lexical_counts(storage)
    }
}

/// The count of a body whose parse is not `xml_ok`: every start tag (inside CDATA and comments
/// too, since their bounds cannot be trusted) contributes what the tree rules give it as an
/// element without children. On a well-formed body this is at least the tree's count in every
/// kind, because the tree counts a subset of the same elements by the same per-element rule
/// (it skips nested task lists, macro parameters, `ri:` resources of links and images, and
/// foreign subtrees). A tag the tree would make `Ns::Other` through an attribute (`xmlns`, a
/// foreign attribute prefix) adds one macro on top of its prefix's own count, so neither
/// reading of it can under-report.
fn lexical_counts(storage: &str) -> LostCounts {
    let mut total = LostCounts::default();
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
        let attrs: Vec<(String, String)> = lex_attrs(after)
            .into_iter()
            .map(|(k, v)| (k.to_owned(), decode_attr(v).unwrap_or_else(|| v.to_owned())))
            .collect();
        let (prefix, local) = match name.split_once(':') {
            Some((p, l)) => (Some(p), l),
            None => (None, name),
        };
        let ns = match prefix {
            None => Ns::Html,
            Some("ac") => Ns::Ac,
            Some("ri") => Ns::Ri,
            Some(_) => Ns::Other,
        };
        let foreign_attr = attrs.iter().any(|(k, _)| {
            k == "xmlns"
                || k.starts_with("xmlns:")
                || k.split_once(':')
                    .is_some_and(|(p, _)| !KNOWN_ATTR_PREFIXES.contains(&p))
        });
        if foreign_attr && ns != Ns::Other {
            total.macros += 1;
        }
        let tag = Element {
            ns,
            prefix: prefix.map(str::to_owned),
            local: local.to_owned(),
            attrs,
            children: Vec::new(),
            byte_range: i..i,
        };
        let one = lost_counts(&[Node::Element(tag)]);
        total.macros += one.macros;
        total.images += one.images;
        total.links += one.links;
        total.layouts += one.layouts;
    }
    total
}

/// Elements whose end tag ends a raw-diff line (PD-104), compared ASCII case-insensitively;
/// a self-closing start tag of one ends a line too (`<ac:structured-macro ac:name="toc"/>`).
const LINE_END_TAGS: [&str; 14] = [
    "p",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "li",
    "tr",
    "table",
    "blockquote",
    "pre",
    "ac:structured-macro",
    "ac:layout-section",
];

/// Void elements whose tag ends a line, self-closing or not.
const LINE_BREAK_TAGS: [&str; 2] = ["br", "hr"];

/// Sections no tag inside of ends a line: (open, close).
const OPAQUE: [(&str, &str); 2] = [("<![CDATA[", "]]>"), ("<!--", "-->")];

/// The raw-diff projection of a storage body (Δ1, PD-104): a line ends after each end tag of
/// `p`, `h1`–`h6`, `li`, `tr`, `table`, `blockquote`, `pre`, `ac:structured-macro` and
/// `ac:layout-section` (and after a self-closing start tag of one), after each `<br>`/`<hr>`
/// tag, and after every `\n`. Inside a CDATA section or a comment no tag ends a line (a `\n`
/// still does, so a code body diffs line by line); an unterminated one runs to the end.
/// Lexical, so it works on any input, parsable or not. The lines are non-empty and concatenate
/// to `storage`. Pure and deterministic; never panics.
pub fn storage_lines(storage: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    // Where the opaque section the scan is in ends (after its close marker, or at the end of
    // the input when it is unterminated).
    let mut opaque: Option<usize> = None;
    while let Some(rest) = storage.get(i..).filter(|r| !r.is_empty()) {
        let cut = if let Some(end) = opaque {
            let inside = storage.get(i..end).unwrap_or("");
            match inside.find('\n').map(|n| i + n + 1) {
                Some(n) => {
                    i = n;
                    true
                }
                None => {
                    i = end;
                    opaque = None;
                    false
                }
            }
        } else {
            let Some(off) = rest.find(['<', '\n']) else {
                break;
            };
            let at = i + off;
            let tail = rest.get(off..).unwrap_or("");
            if tail.starts_with('\n') {
                i = at + 1;
                true
            } else if let Some((open, close)) = OPAQUE.iter().find(|(o, _)| tail.starts_with(o)) {
                i = at + open.len();
                let end = storage.get(i..).and_then(|r| r.find(close));
                opaque = Some(end.map_or(storage.len(), |c| i + c + close.len()));
                false
            } else if let Some(len) = line_ending_tag(tail) {
                i = at + len;
                true
            } else {
                i = at + 1;
                false
            }
        };
        if cut {
            if let Some(line) = storage.get(start..i) {
                lines.push(line);
            }
            start = i;
        }
    }
    if let Some(line) = storage.get(start..).filter(|l| !l.is_empty()) {
        lines.push(line);
    }
    lines
}

/// The length of the tag at the start of `tail` when it ends a line: `</name>` (whitespace
/// allowed before `>`) for a [`LINE_END_TAGS`] name, a self-closing start tag of one, or any
/// [`LINE_BREAK_TAGS`] start tag. A tag whose text holds a `\n` is none of these: the `\n`
/// ends the line first, so no line holds an interior newline.
fn line_ending_tag(tail: &str) -> Option<usize> {
    let listed = |set: &[&str], name: &str| set.iter().any(|t| t.eq_ignore_ascii_case(name));
    let body = tail.strip_prefix('<')?;
    if let Some(body) = body.strip_prefix('/') {
        let name_len = body.find(|c: char| c.is_whitespace() || matches!(c, '>' | '<'))?;
        let name = body.get(..name_len)?;
        let after = body.get(name_len..)?;
        let trimmed = after.trim_start();
        let ws = after.len() - trimmed.len();
        let closed = trimmed.starts_with('>');
        let len = 2 + name_len + ws + 1;
        let ends = closed && listed(&LINE_END_TAGS, name);
        return (ends && !tail.get(..len)?.contains('\n')).then_some(len);
    }
    let name_len = body
        .find(|c: char| c.is_whitespace() || matches!(c, '/' | '>' | '<'))
        .unwrap_or(body.len());
    let name = body.get(..name_len)?;
    let len = tag_end(tail)?;
    let self_closing = tail.get(..len)?.ends_with("/>");
    let ends = listed(&LINE_BREAK_TAGS, name) || (self_closing && listed(&LINE_END_TAGS, name));
    (ends && !tail.get(..len)?.contains('\n')).then_some(len)
}

/// The length of the tag at the start of `tail` through its `>` (outside quoted attribute
/// values); `None` when another `<` or the end of the input comes first.
fn tag_end(tail: &str) -> Option<usize> {
    let mut quote = None;
    for (i, c) in tail.char_indices().skip(1) {
        match (quote, c) {
            (_, '<') => return None,
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(c),
            (None, '>') => return Some(i + 1),
            (None, _) => {}
        }
    }
    None
}
