//! The re-parse hard check (spec §7.6, Δ1, PD-44): the converter's output is parsed with the
//! preview's parser ([`crate::wiki`]), and every macro, mention, include, image and attachment
//! link found must be a container the converter recorded. Anything else means the escaping
//! failed, and the conversion is rejected.
//!
//! Fail closed throughout. A record is trusted only when its range slices a whole container
//! of its kind exactly as the converter writes one, with a body that does not hold the
//! container's own tag (ASCII case-insensitive, also after whitespace or controls: `{ code}`,
//! `{\tquote}`; the converter's own rule), and only when
//! no two records cross each other. Anything a record does not cover is unrecorded, wherever
//! it sits (a macro inside a recorded `{quote}` is unrecorded; a recorded `{code}` body is
//! opaque to the parser, so nothing inside it is reported at all).

use std::cmp::Reverse;
use std::collections::HashSet;
use std::fmt;
use std::ops::Range;

use crate::md_to_wiki::{ContainerKind, EmittedConstructs, has_tag};
use crate::wiki::{ConstructKind, construct_spans, parse};

/// A construct the converter did not record (Δ1): the kind of the first one in document
/// order and how many of that kind there are. Never any text or offset, so the error cannot
/// echo the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unrecorded {
    pub kind: ConstructKind,
    pub count: u64,
}

impl fmt::Display for Unrecorded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unrecorded {} (count {})",
            self.kind.as_str(),
            self.count
        )
    }
}

impl std::error::Error for Unrecorded {}

/// Re-parses `wiki` and checks every construct against `e` (Δ1). A `Macro` span whose range
/// equals a trusted record's range, or the opening tag of one, is recorded; every other
/// macro, mention, include, image or attachment span is not. `Err` names the kind of the
/// first unrecorded span (by start offset) and the number of unrecorded spans of that kind.
/// Pure; never panics, whatever the ranges in `e`.
pub fn hard_check_wiki(wiki: &str, e: &EmittedConstructs) -> Result<(), Unrecorded> {
    let accepted = accepted_ranges(wiki, e);
    let mut first: Option<ConstructKind> = None;
    let mut count: u64 = 0;
    for (kind, range) in construct_spans(&parse(wiki)) {
        if kind == ConstructKind::Macro && accepted.contains(&(range.start, range.end)) {
            continue;
        }
        if *first.get_or_insert(kind) == kind {
            count = count.saturating_add(1);
        }
    }
    match first {
        None => Ok(()),
        Some(kind) => Err(Unrecorded { kind, count }),
    }
}

/// The `(start, end)` ranges a `Macro` span may have to count as recorded: each trusted
/// container and its opening tag. Empty when any two trusted records cross.
fn accepted_ranges(wiki: &str, e: &EmittedConstructs) -> HashSet<(usize, usize)> {
    let mut trusted: Vec<(Range<usize>, usize)> = e
        .code_blocks
        .iter()
        .filter_map(|c| {
            let open = container(wiki, c.kind, &c.byte_range)?;
            Some((c.byte_range.clone(), open))
        })
        .collect();
    trusted.sort_by_key(|(r, _)| (r.start, Reverse(r.end)));
    if crossing(trusted.iter().map(|(r, _)| r)) {
        return HashSet::new();
    }
    let mut set = HashSet::with_capacity(trusted.len().saturating_mul(2));
    for (r, open) in trusted {
        set.insert((r.start, r.start + open));
        set.insert((r.start, r.end));
    }
    set
}

/// Whether two of `ranges` (sorted by start, then longest first) overlap without one
/// containing the other.
fn crossing<'a>(ranges: impl Iterator<Item = &'a Range<usize>>) -> bool {
    let mut open_ends: Vec<usize> = Vec::new();
    for r in ranges {
        while open_ends.last().is_some_and(|&end| end <= r.start) {
            open_ends.pop();
        }
        if open_ends.last().is_some_and(|&end| end < r.end) {
            return true;
        }
        open_ends.push(r.end);
    }
    false
}

/// The opening tag's length when `range` of `wiki` is a whole container of `kind` as the
/// converter writes it: `{code}` or `{code:lang}` (lang from `[A-Za-z0-9_+#.-]`),
/// `{noformat}`, `{quote}`, then a body without the container's own tag (`has_tag`, the rule
/// the converter chooses containers by), then the closing tag. `None` otherwise (out of
/// bounds, off a char boundary, other params, a body holding the tag).
fn container(wiki: &str, kind: ContainerKind, range: &Range<usize>) -> Option<usize> {
    let slice = wiki.get(range.clone())?;
    let (close, name) = match kind {
        ContainerKind::Code => ("{code}", "code"),
        ContainerKind::Noformat => ("{noformat}", "noformat"),
        ContainerKind::Quote => ("{quote}", "quote"),
        // A storage code macro is never a wiki container: fail closed.
        ContainerKind::CodeMacro => return None,
    };
    let open = opening_tag_len(kind, slice)?;
    let body = slice.get(open..slice.len().checked_sub(close.len())?)?;
    (slice.ends_with(close) && !has_tag(body, name)).then_some(open)
}

fn opening_tag_len(kind: ContainerKind, slice: &str) -> Option<usize> {
    let tag = match kind {
        ContainerKind::Code => "{code}",
        ContainerKind::Noformat => "{noformat}",
        ContainerKind::Quote => "{quote}",
        ContainerKind::CodeMacro => return None,
    };
    if slice.starts_with(tag) {
        return Some(tag.len());
    }
    let rest = match kind {
        ContainerKind::Code => slice.strip_prefix("{code:")?,
        ContainerKind::Noformat | ContainerKind::Quote | ContainerKind::CodeMacro => return None,
    };
    let lang = rest.get(..rest.find('}')?)?;
    let ok = !lang.is_empty()
        && lang
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '#' | '.' | '-'));
    ok.then_some("{code:".len() + lang.len() + 1)
}
