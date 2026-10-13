//! Line diff for the edit previews (§6.3, PD-51): a small Myers O(ND) implementation with caps,
//! so no diff crate enters the trusted base.

use serde::Serialize;

/// More differing lines than this on either side (after the common prefix and suffix are cut):
/// no diff is computed, the middle is one Del block of old lines followed by one Add block of new
/// lines, each cut to this many lines and [`DIFF_MAX_MIDDLE_BYTES`] bytes (`truncated` is set).
pub const DIFF_MAX_LINES: usize = 20_000;

/// Most bytes of changed (Del or Add) line text emitted per side. A line that crosses the budget
/// is cut at a char boundary and the rest is dropped (`truncated` is set).
pub const DIFF_MAX_MIDDLE_BYTES: usize = 4 * 1024 * 1024;

/// Edit distance bound of the Myers search. Past it the differing middle (after the common
/// prefix and suffix are cut) is shown as a whole replace; this keeps time and the O(D^2) trace
/// bounded for inputs with nothing in common.
const DIFF_MAX_D: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffOp {
    Same,
    Add,
    Del,
    /// T13: the header of one field's section in a multi-field diff (`EditDiff`); its text is
    /// the field's label, written by core, never a line of either text. [`line_diff`] never
    /// emits it.
    Field,
}

/// One diff line. `text` is the line exactly as it is in the input, including its `\n`
/// terminator (a final line without one has none), so a `\r`, a missing final newline or a
/// trailing space is part of the text: the rendering layer must make them visible (escape `\r`
/// and `\n`, mark trailing whitespace); the text is untrusted and goes out as text, never HTML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffLine {
    pub op: DiffOp,
    pub text: String,
}

/// The result of [`line_diff`]. `lines` is a script whose Same+Del lines concatenate to `old`
/// and whose Same+Add lines concatenate to `new`, unless `truncated`: then the changed middle
/// was cut at [`DIFF_MAX_LINES`] lines / [`DIFF_MAX_MIDDLE_BYTES`] bytes per side and the UI must
/// say so (and must not offer the diff as the whole change).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LineDiff {
    pub lines: Vec<DiffLine>,
    pub truncated: bool,
}

/// Number of hunks: maximal runs of `Add`/`Del` lines (a `Same` or `Field` line ends a run).
pub fn hunks(lines: &[DiffLine]) -> u64 {
    let mut count = 0u64;
    let mut in_hunk = false;
    for l in lines {
        let changed = matches!(l.op, DiffOp::Add | DiffOp::Del);
        if changed && !in_hunk {
            count += 1;
        }
        in_hunk = changed;
    }
    count
}

fn push(out: &mut Vec<DiffLine>, op: DiffOp, text: &str) {
    out.push(DiffLine {
        op,
        text: text.to_owned(),
    });
}

/// Line diff of `old` against `new`. Lines split after each `\n` and keep it
/// (`split_inclusive`), so the diff is byte-faithful: two different texts never diff as all
/// `Same` (a final newline, `\r\n` against `\n`, a lone `\r`, U+2028 and trailing whitespace all
/// change a line). The script is a minimal edit script (fewest Add + Del lines) unless a cap
/// applies (the internal distance bound, then [`DIFF_MAX_LINES`] / [`DIFF_MAX_MIDDLE_BYTES`]).
/// The common prefix and suffix are always cut first and kept as `Same`; only the differing
/// middle is capped. Same lines come from the input (so they are bounded by it); changed lines
/// are bounded per side.
pub fn line_diff(old: &str, new: &str) -> LineDiff {
    let a: Vec<&str> = old.split_inclusive('\n').collect();
    let b: Vec<&str> = new.split_inclusive('\n').collect();
    let prefix = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let a_rest = a.get(prefix..).unwrap_or_default();
    let b_rest = b.get(prefix..).unwrap_or_default();
    let suffix = a_rest
        .iter()
        .rev()
        .zip(b_rest.iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let a_mid = a_rest.get(..a_rest.len() - suffix).unwrap_or_default();
    let b_mid = b_rest.get(..b_rest.len() - suffix).unwrap_or_default();

    let mut out = Vec::new();
    let mut truncated = false;
    for t in a.iter().take(prefix) {
        push(&mut out, DiffOp::Same, t);
    }
    let fits = |m: &[&str]| {
        m.len() <= DIFF_MAX_LINES
            && m.iter().map(|t| t.len()).sum::<usize>() <= DIFF_MAX_MIDDLE_BYTES
    };
    let small = fits(a_mid) && fits(b_mid);
    match small.then(|| myers(a_mid, b_mid)).flatten() {
        Some(script) => out.extend(script),
        None => truncated = replace_all(&mut out, a_mid, b_mid),
    }
    for t in a_rest.iter().skip(a_rest.len() - suffix) {
        push(&mut out, DiffOp::Same, t);
    }
    LineDiff {
        lines: out,
        truncated,
    }
}

/// The middle as one Del block then one Add block, each side bounded; whether anything was cut.
fn replace_all(out: &mut Vec<DiffLine>, a: &[&str], b: &[&str]) -> bool {
    let cut_a = push_bounded(out, DiffOp::Del, a);
    let cut_b = push_bounded(out, DiffOp::Add, b);
    cut_a || cut_b
}

fn push_bounded(out: &mut Vec<DiffLine>, op: DiffOp, lines: &[&str]) -> bool {
    let mut left = DIFF_MAX_MIDDLE_BYTES;
    for (i, t) in lines.iter().enumerate() {
        if i >= DIFF_MAX_LINES {
            return true;
        }
        if t.len() <= left {
            push(out, op, t);
            left -= t.len();
            continue;
        }
        let mut end = left;
        while !t.is_char_boundary(end) {
            end -= 1;
        }
        if let Some(head) = t.get(..end).filter(|h| !h.is_empty()) {
            push(out, op, head);
        }
        return true;
    }
    false
}

/// Myers' forward search with a trace for the backtrack. `None` when the edit distance exceeds
/// [`DIFF_MAX_D`].
fn myers(a: &[&str], b: &[&str]) -> Option<Vec<DiffLine>> {
    let n = isize::try_from(a.len()).ok()?;
    let m = isize::try_from(b.len()).ok()?;
    let max_d = isize::try_from(DIFF_MAX_D).ok()?.min(n + m);
    // `v[k + max_d + 1]` = furthest x on diagonal k.
    let off = max_d + 1;
    let mut v = vec![0isize; usize::try_from(2 * max_d + 3).ok()?];
    let idx = |k: isize| usize::try_from(k + off).ok();
    // trace[d] = the values of diagonals -d..=d after step d.
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let mut found = None;
    for d in 0..=max_d {
        let mut k = -d;
        while k <= d {
            let down = k == -d || (k != d && *v.get(idx(k - 1)?)? < *v.get(idx(k + 1)?)?);
            let mut x = if down {
                *v.get(idx(k + 1)?)?
            } else {
                *v.get(idx(k - 1)?)? + 1
            };
            let mut y = x - k;
            while x < n
                && y < m
                && a.get(usize::try_from(x).ok()?) == b.get(usize::try_from(y).ok()?)
            {
                x += 1;
                y += 1;
            }
            *v.get_mut(idx(k)?)? = x;
            if x >= n && y >= m {
                found = Some(d);
            }
            k += 2;
        }
        let mut snap = Vec::with_capacity(usize::try_from(2 * d + 1).ok()?);
        for k in -d..=d {
            snap.push(*v.get(idx(k)?)?);
        }
        trace.push(snap);
        if found.is_some() {
            break;
        }
    }
    let d_end = found?;

    // Backtrack from (n, m); edits are collected in reverse.
    let mut rev: Vec<DiffLine> = Vec::new();
    let (mut x, mut y) = (n, m);
    let mut d = d_end;
    while d > 0 {
        let prev = trace.get(usize::try_from(d - 1).ok()?)?;
        let at = |k: isize| prev.get(usize::try_from(k + d - 1).ok()?).copied();
        let k = x - y;
        let prev_k = if k == -d || (k != d && at(k - 1)? < at(k + 1)?) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = at(prev_k)?;
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            x -= 1;
            y -= 1;
            rev.push(line(DiffOp::Same, a, x)?);
        }
        if x == prev_x {
            y -= 1;
            rev.push(line(DiffOp::Add, b, y)?);
        } else {
            x -= 1;
            rev.push(line(DiffOp::Del, a, x)?);
        }
        d -= 1;
    }
    while x > 0 && y > 0 {
        x -= 1;
        y -= 1;
        rev.push(line(DiffOp::Same, a, x)?);
    }
    rev.reverse();
    Some(rev)
}

fn line(op: DiffOp, src: &[&str], i: isize) -> Option<DiffLine> {
    Some(DiffLine {
        op,
        text: (*src.get(usize::try_from(i).ok()?)?).to_owned(),
    })
}
