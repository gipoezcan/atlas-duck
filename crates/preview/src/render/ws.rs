//! PD-69 visible whitespace: a carriage return renders as `⟨U+000D⟩`, a trailing space or tab
//! as `⟨U+0020⟩`/`⟨U+0009⟩` (each one), a tab inside a line as `⟨U+0009⟩` in diffs only, and a
//! diff line without its final `\n` gets the suffix ` ⟨no newline at end⟩`. Same notation as the
//! flagged characters (`⟨U+202E⟩`, §6.4), so one legend explains all.
//!
//! The input is display-escaped text (`invisible::escape_for_display` leaves `\t`, `\n`, `\r` and
//! spaces alone, and escapes every literal `⟨`/`⟩`), so each `⟨…⟩` added here is a real escape.

use std::fmt::Write;

/// plan text (PD-69): the suffix of a diff line without its final `\n`.
pub const NO_NEWLINE_AT_END: &str = "⟨no newline at end⟩";

/// A diff line (its `\n` terminator included when it has one, [`crate::diff::DiffLine`]): the
/// terminator is dropped, `\r` and every tab are escaped, trailing spaces are escaped, and a line
/// without a terminator ends in [`NO_NEWLINE_AT_END`].
pub fn visible_line(line: &str) -> String {
    visible_line_at(line, true)
}

/// [`visible_line`] for a line that may not end its side of the diff (M7 Task 15): the
/// [`NO_NEWLINE_AT_END`] suffix only when `side_end`, since a projection that ends lines at
/// tags (the raw storage lines) leaves most lines without `\n` and only a side's last line
/// says where its text ends.
pub fn visible_line_at(line: &str, side_end: bool) -> String {
    let (content, newline) = match line.strip_suffix('\n') {
        Some(content) => (content, true),
        None => (line, false),
    };
    let mut out = String::with_capacity(content.len() + 24);
    mark_line(&mut out, content, true);
    if !newline && side_end {
        out.push(' ');
        out.push_str(NO_NEWLINE_AT_END);
    }
    out
}

/// A rendered value: per line, `\r` and trailing spaces and tabs are escaped; tabs inside a line
/// and the `\n` terminators stay as they are.
pub fn visible_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.split_inclusive('\n') {
        match line.strip_suffix('\n') {
            Some(content) => {
                mark_line(&mut out, content, false);
                out.push('\n');
            }
            None => mark_line(&mut out, line, false),
        }
    }
    out
}

/// One line without its `\n`: the trailing run of spaces, tabs and `\r` (a `\r\n` terminator
/// leaves its `\r` there) is escaped char by char, and so is every other `\r` (and every tab when
/// `tabs`).
fn mark_line(out: &mut String, content: &str, tabs: bool) {
    let keep = content.trim_end_matches([' ', '\t', '\r']).len();
    for (i, c) in content.char_indices() {
        let escape = match c {
            '\r' => true,
            '\t' => tabs || i >= keep,
            ' ' => i >= keep,
            _ => false,
        };
        if escape {
            push_escape(out, c);
        } else {
            out.push(c);
        }
    }
}

/// `⟨U+XXXX⟩` (at least four upper-case hex digits), the `invisible::escape_for_display` form.
pub(crate) fn push_escape(out: &mut String, c: char) {
    let _ = write!(out, "⟨U+{:04X}⟩", u32::from(c));
}
