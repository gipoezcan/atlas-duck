//! The placeholder grammar (plan PD-98) over the `pulldown-cmark` event stream, shared by the
//! storage → Markdown look-alike pass (Task 3) and the placeholder check (Task 4), so that the
//! converter escapes exactly what the check would count.
//!
//! - **Rule 1:** a link or image whose destination (after the parser's own unescaping) starts
//!   with `confluence:`, ASCII case-insensitive.
//! - **Rules 2 and 3** match on the source of a *run*: a maximal sequence of consecutive `Text`
//!   events outside code whose source ranges touch, or are separated by exactly the one
//!   backslash of a backslash escape (pulldown-cmark leaves that byte out of the escaped
//!   character's range, so `[macro: m {k=a\,b}]` is three `Text` events with gaps). Rule 2:
//!   `[macro: ` + a name `[A-Za-z0-9_.-]{1,64}` + ` {` … `}]` on one line. Rule 3: `@user:`
//!   followed by one of `[A-Za-z0-9._%-]`. A `[` or `@` preceded by an odd number of
//!   backslashes in the source is escaped and never matches.
//!
//! Code spans and code blocks end a run and are never hits.

use std::ops::Range;

use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

/// The kind of a placeholder (Δ1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlaceholderKind {
    Link,
    Image,
    Macro,
    User,
}

/// One placeholder in a Markdown source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hit {
    pub(crate) kind: PlaceholderKind,
    /// The byte offset of the link's `[` (or `<`), the image's `!`, the macro's `[` or the
    /// user's `@`.
    pub(crate) at: usize,
}

/// The parser options the check and the converter use.
pub(crate) fn options() -> Options {
    Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS
}

const MACRO_OPEN: &str = "[macro: ";
const USER_OPEN: &str = "@user:";
const SCHEME: &str = "confluence:";

/// Every placeholder of `md`, sorted by offset.
pub(crate) fn scan(md: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut run: Option<Range<usize>> = None;
    let mut in_code_block = false;
    for (event, range) in Parser::new_ext(md, options()).into_offset_iter() {
        match event {
            Event::Text(_) if !in_code_block => {
                run = Some(match run.take() {
                    Some(r) if joins(md, r.end, range.start) => r.start..range.end,
                    Some(r) => {
                        run_hits(md, r, &mut hits);
                        range
                    }
                    None => range,
                });
                continue;
            }
            Event::Start(Tag::CodeBlock(_)) => in_code_block = true,
            Event::End(TagEnd::CodeBlock) => in_code_block = false,
            Event::Start(Tag::Link { dest_url, .. }) if is_confluence(&dest_url) => {
                hits.push(Hit {
                    kind: PlaceholderKind::Link,
                    at: range.start,
                });
            }
            Event::Start(Tag::Image { dest_url, .. }) if is_confluence(&dest_url) => {
                hits.push(Hit {
                    kind: PlaceholderKind::Image,
                    at: range.start,
                });
            }
            _ => {}
        }
        if let Some(r) = run.take() {
            run_hits(md, r, &mut hits);
        }
    }
    if let Some(r) = run {
        run_hits(md, r, &mut hits);
    }
    hits.sort_by_key(|h| h.at);
    hits
}

/// Whether a run ending at `end` continues with a `Text` event starting at `start`.
fn joins(md: &str, end: usize, start: usize) -> bool {
    start == end || (start == end + 1 && md.as_bytes().get(end) == Some(&b'\\'))
}

fn is_confluence(dest: &str) -> bool {
    dest.get(..SCHEME.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(SCHEME))
}

/// Whether the byte at `at` is preceded by an odd number of backslashes.
pub(crate) fn escaped(md: &str, at: usize) -> bool {
    md.as_bytes()
        .get(..at)
        .map_or(0, |b| b.iter().rev().take_while(|&&c| c == b'\\').count())
        % 2
        == 1
}

fn run_hits(md: &str, run: Range<usize>, out: &mut Vec<Hit>) {
    let Some(src) = md.get(run.clone()) else {
        return;
    };
    for (i, _) in src.match_indices(MACRO_OPEN) {
        let at = run.start + i;
        if !escaped(md, at) && src.get(i..).is_some_and(macro_grammar) {
            out.push(Hit {
                kind: PlaceholderKind::Macro,
                at,
            });
        }
    }
    for (i, _) in src.match_indices(USER_OPEN) {
        let at = run.start + i;
        let key_start = src
            .get(i + USER_OPEN.len()..)
            .and_then(|s| s.bytes().next())
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'-'));
        if key_start && !escaped(md, at) {
            out.push(Hit {
                kind: PlaceholderKind::User,
                at,
            });
        }
    }
}

/// `s` starts with `[macro: `: a name `[A-Za-z0-9_.-]{1,64}`, ` {`, then `}]` on the same line.
fn macro_grammar(s: &str) -> bool {
    let Some(rest) = s.get(MACRO_OPEN.len()..) else {
        return false;
    };
    let name = rest
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        .count();
    if !(1..=64).contains(&name) {
        return false;
    }
    let Some(params) = rest.get(name..).and_then(|p| p.strip_prefix(" {")) else {
        return false;
    };
    let line = params.split('\n').next().unwrap_or("");
    line.contains("}]")
}
