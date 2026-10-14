//! PD-68 Raw display projection: one Raw page (an exact slice of the hashed candidate bytes) as
//! the text the Approvals window shows. The UI shows this text and never decodes the bytes.
//!
//! - Flagged characters are escaped by [`invisible::escape_for_display`] (one classifier, §6.4).
//! - Whitespace is made visible per PD-69 ([`super::ws::visible_value`]): `\r`, and trailing
//!   spaces and tabs of a line, as `⟨U+000D⟩`, `⟨U+0020⟩`, `⟨U+0009⟩`. A page boundary inside a
//!   line makes the end of the page look like a line end, so spaces right before the boundary are
//!   marked as trailing: a mark that is there for a space is never missing.
//! - Emoji sequences (ZWJ, VS16) are classified per page, so one cut by a boundary can be marked
//!   on a page although the unsplit text does not mark it (the safe direction), and overlapping
//!   RGI sequences can match differently; the bytes are shown either way, but the marks of such a
//!   sequence can differ from the header counts.
//! - Bytes that are not UTF-8 are shown as `⟨0xFF⟩` (one per byte). The delimiters `⟨` and `⟩` of
//!   the text itself are escaped, so a marker is never forged by the candidate's own text.
//! - A UTF-8 sequence cut by the page boundary is carried: the page before ends ahead of it (its
//!   bytes are `carry_out`) and the page after starts with it. The carry is derived from the
//!   previous page's own bytes ([`incomplete_tail`]), never taken from the UI. The last page shows
//!   an incomplete tail as bytes ([`raw_display_last`]): nothing is held back for a page that does
//!   not exist.

use std::fmt::Write;

use super::ws;
use crate::invisible;

/// The longest incomplete UTF-8 sequence (a 4-byte one cut after its third byte).
pub const MAX_CARRY_BYTES: usize = 3;

/// One page of Raw as display text, and the bytes the next page starts with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDisplay {
    pub text: String,
    /// 0 to 3 bytes: an incomplete UTF-8 sequence at the end of this page (after `carry`).
    pub carry_out: Vec<u8>,
}

/// The trailing bytes of `bytes` that are a proper prefix of one UTF-8 sequence, so more bytes
/// could complete it (0 to 3 of them).
pub fn incomplete_tail(bytes: &[u8]) -> &[u8] {
    let max = bytes.len().min(MAX_CARRY_BYTES);
    for k in (1..=max).rev() {
        let tail = &bytes[bytes.len() - k..];
        if let Err(e) = std::str::from_utf8(tail)
            && e.valid_up_to() == 0
            && e.error_len().is_none()
        {
            return tail;
        }
    }
    &[]
}

/// A page that is not the last: an incomplete UTF-8 tail (after `carry`, the previous page's
/// [`incomplete_tail`]) is not shown but handed on in `carry_out`.
pub fn raw_display(bytes: &[u8], carry: &[u8]) -> RawDisplay {
    display(bytes, carry, false)
}

/// The last page: an incomplete tail is shown as bytes like any other invalid byte.
pub fn raw_display_last(bytes: &[u8], carry: &[u8]) -> RawDisplay {
    display(bytes, carry, true)
}

fn display(bytes: &[u8], carry: &[u8], last: bool) -> RawDisplay {
    let mut all = Vec::with_capacity(carry.len() + bytes.len());
    all.extend_from_slice(carry);
    all.extend_from_slice(bytes);
    let tail = if last { 0 } else { incomplete_tail(&all).len() };
    let (body, carry_out) = all.split_at(all.len() - tail);
    let mut escaped = String::with_capacity(body.len() + 16);
    let mut rest = body;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                escaped.push_str(&invisible::escape_for_display(s));
                break;
            }
            Err(e) => {
                let (valid, after) = rest.split_at(e.valid_up_to());
                // Valid by `valid_up_to`; the fallback keeps the bytes visible if that ever lied.
                match std::str::from_utf8(valid) {
                    Ok(s) => escaped.push_str(&invisible::escape_for_display(s)),
                    Err(_) => push_bytes(&mut escaped, valid),
                }
                // `error_len` None: an incomplete sequence at the very end of the body. The last
                // page gets here with its tail; so does a page whose body ends in an incomplete
                // sequence that a carried lead byte follows (`C3` + carried `F0 9F`).
                let bad = e.error_len().unwrap_or(after.len()).min(after.len());
                let (bad_bytes, next) = after.split_at(bad);
                push_bytes(&mut escaped, bad_bytes);
                rest = next;
            }
        }
    }
    RawDisplay {
        text: ws::visible_value(&escaped),
        carry_out: carry_out.to_vec(),
    }
}

fn push_bytes(out: &mut String, bytes: &[u8]) {
    for b in bytes {
        let _ = write!(out, "⟨0x{b:02X}⟩");
    }
}
