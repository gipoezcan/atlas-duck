//! §6.4 invisible-character classifier: the single definition used for agent-string stripping
//! (§3.3), preview marking and header counts (§6.1), warnings (§6.2) and escaping.
//!
//! Character data comes from `icu_properties` compiled data and RGI emoji sequences from the
//! `emojis` table; both versions are part of [`crate::PREVIEW_BUILDER_VERSION`] (V31).

use std::ops::Range;

use icu_properties::props::{
    BidiControl, DefaultIgnorableCodePoint, ExtendedPictographic, GeneralCategory,
};
use icu_properties::{CodePointMapData, CodePointSetData};

const ZWJ: char = '\u{200D}';
const VS15: char = '\u{FE0E}';
const VS16: char = '\u{FE0F}';

/// Length in scalars of the longest emoji in the `emojis` table (a kiss/couple ZWJ sequence with
/// two skin tones). Bounds the RGI lookahead so a long run of digits stays linear; a test keeps
/// it equal to the table's maximum.
pub const MAX_RGI_EMOJI_CHARS: usize = 10;

/// §6.4: Default_Ignorable_Code_Point ∪ Cf ∪ (Cc minus \t \n \r) ∪ Zl ∪ Zp. Context-free.
/// Cf is listed explicitly (lead ruling 2026-10-08, fail closed): §6.4 says the set "covers Cf",
/// but some Cf code points (U+0600–0605, U+06DD, U+070F, U+FFF9–FFFB, U+13430–1343F, …) are not
/// Default_Ignorable.
pub fn is_flagged(c: char) -> bool {
    // No ASCII code point is Default_Ignorable, Cf, Zl or Zp, and ASCII Cc is U+0000–001F and
    // U+007F: the same set without the table lookups (a test compares every ASCII char).
    if c.is_ascii() {
        return c.is_ascii_control() && !matches!(c, '\t' | '\n' | '\r');
    }
    if CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(c) {
        return true;
    }
    match CodePointMapData::<GeneralCategory>::new().get(c) {
        GeneralCategory::Control => !matches!(c, '\t' | '\n' | '\r'),
        GeneralCategory::Format
        | GeneralCategory::LineSeparator
        | GeneralCategory::ParagraphSeparator => true,
        _ => false,
    }
}

/// §6.4: Bidi_Control (U+061C, U+200E–200F, U+202A–202E, U+2066–2069).
pub fn is_bidi_control(c: char) -> bool {
    CodePointSetData::new::<BidiControl>().contains(c)
}

/// Per-char flags for `s` (in `char_indices` order): `is_flagged`, except U+FE0E, U+FE0F and
/// U+200D inside an RGI emoji sequence. Sequences are found leftmost-longest within each maximal
/// run of emoji-sequence characters; a candidate counts only when it is spelled exactly as a
/// fully-qualified emoji of emoji-test.txt (§6.4, L57). `emojis::get` also maps
/// minimally-qualified and unqualified spellings to their fully-qualified entry, so the match
/// compares `as_str()`. U+FE0E is never part of a fully-qualified emoji and so is never exempt.
pub fn flags(s: &str) -> Vec<bool> {
    flags_and_sequences(s).0
}

/// [`flags`], and the byte ranges of the RGI emoji sequences that unflag a character (in order,
/// disjoint). A cut of `s` strictly inside one of them would change the flags of what is kept
/// (the U+200D of a 👩‍💻 cut before the 💻 is flagged); a cut anywhere else keeps them: the
/// flags of the prefix are the prefix of the flags (M8 S-06 proptest seed).
pub fn flags_and_sequences(s: &str) -> (Vec<bool>, Vec<Range<usize>>) {
    let mut out: Vec<bool> = s.chars().map(is_flagged).collect();
    let mut sequences = Vec::new();
    // Only ZWJ and the variation selectors can be unflagged: without them the sequence pass
    // changes nothing, and its index (16 bytes a char, 256 MiB for a 16 MiB candidate string,
    // I-37) is not built.
    if !s.contains([ZWJ, VS15, VS16]) {
        return (out, sequences);
    }
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    // Byte offset where char `k` starts (`s.len()` past the end): candidates are slices of `s`.
    let byte_at = |k: usize| chars.get(k).map_or(s.len(), |&(b, _)| b);
    let mut i = 0;
    while i < chars.len() {
        if !is_emoji_seq_char(chars[i].1) {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && is_emoji_seq_char(chars[i].1) {
            i += 1;
        }
        // Only ZWJ and the variation selectors can be unflagged; skip runs without them.
        if !chars[start..i]
            .iter()
            .any(|&(_, c)| matches!(c, ZWJ | VS15 | VS16))
        {
            continue;
        }
        let mut j = start;
        while j < i {
            let mut matched = None;
            // No table emoji starts with a joiner/modifier/tag or ends with ZWJ (tested), so
            // those lookups are skipped.
            if can_start_emoji(chars[j].1) {
                for end in (j + 1..=i.min(j + MAX_RGI_EMOJI_CHARS)).rev() {
                    if chars[end - 1].1 == ZWJ {
                        continue;
                    }
                    let candidate = &s[byte_at(j)..byte_at(end)];
                    if emojis::get(candidate).is_some_and(|e| e.as_str() == candidate) {
                        matched = Some(end);
                        break;
                    }
                }
            }
            match matched {
                Some(end) => {
                    let mut unflags = false;
                    for k in j..end {
                        if matches!(chars[k].1, ZWJ | VS15 | VS16) {
                            out[k] = false;
                            unflags = true;
                        }
                    }
                    if unflags {
                        sequences.push(byte_at(j)..byte_at(end));
                    }
                    j = end;
                }
                None => j += 1,
            }
        }
    }
    (out, sequences)
}

/// Where a cap of `s` at `max` bytes may cut (`s.len()` when it fits): the last char boundary at
/// or before `max` that is strictly inside no sequence of [`flags_and_sequences`] (the kept text
/// would flag its U+200D or U+FE0F, which display text shows raw and a stripped string must not
/// hold) and no `⟨U+XXXX⟩` escape of [`escape_for_display`] (half of one is unmarked text that no
/// longer names its char). The flags of `s[..cut]` are the prefix of the flags of `s`. In raw text
/// an escape-shaped run only moves the cut back before it (M8 ZWJ review I-2).
pub fn cut_boundary(s: &str, max: usize) -> usize {
    if max >= s.len() {
        return s.len();
    }
    let mut cut = max;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    // Only ZWJ and the variation selectors are ever unflagged (see `flags_and_sequences`).
    if s.contains([ZWJ, VS15, VS16])
        && let Some(r) = flags_and_sequences(s)
            .1
            .into_iter()
            .find(|r| r.start < cut && cut < r.end)
    {
        cut = r.start;
    }
    // An escape holds no `⟨` after its first char, so only the last `⟨` before the cut can open
    // one around it, at most an escape's length back. Neither back-off can land inside the other
    // kind: a sequence holds no `⟨`, and an escape's digits are never followed by U+FE0F.
    let from = (cut.saturating_sub(MAX_ESCAPE_BYTES)..=cut)
        .find(|&b| s.is_char_boundary(b))
        .unwrap_or(cut);
    if let Some(at) = s[from..cut].rfind('⟨').map(|i| from + i)
        && escape_len(&s[at..]).is_some_and(|len| cut < at + len)
    {
        cut = at;
    }
    cut
}

/// Bytes of the longest `⟨U+XXXX⟩` escape (six hex digits).
const MAX_ESCAPE_BYTES: usize = "⟨U+".len() + 6 + '⟩'.len_utf8();

/// The byte length of the `⟨U+XXXX⟩` escape (4 to 6 upper-case hex digits) `rest` starts with.
fn escape_len(rest: &str) -> Option<usize> {
    let inner = rest.strip_prefix("⟨U+")?;
    let hex = inner
        .bytes()
        .take_while(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F'))
        .count();
    ((4..=6).contains(&hex) && inner[hex..].starts_with('⟩'))
        .then(|| "⟨U+".len() + hex + '⟩'.len_utf8())
}

fn can_start_emoji(c: char) -> bool {
    !(matches!(c, ZWJ | VS15 | VS16 | '\u{20E3}')
        || ('\u{1F3FB}'..='\u{1F3FF}').contains(&c)
        || ('\u{E0020}'..='\u{E007F}').contains(&c))
}

fn is_emoji_seq_char(c: char) -> bool {
    matches!(c, ZWJ | VS15 | VS16 | '\u{20E3}' | '#' | '*' | '0'..='9')
        || ('\u{1F1E6}'..='\u{1F1FF}').contains(&c) // regional indicators
        || ('\u{1F3FB}'..='\u{1F3FF}').contains(&c) // skin-tone modifiers
        || ('\u{E0020}'..='\u{E007F}').contains(&c) // tags (stay flagged; only FE0E/FE0F/200D are exempt)
        || CodePointSetData::new::<ExtendedPictographic>().contains(c)
}

/// (bidi controls, other invisible) over the whole string.
pub fn count(s: &str) -> (u64, u64) {
    // All-ASCII text (most of a JSON body): no bidi control and no emoji sequence, so the
    // flagged chars are the ASCII ones `is_flagged` names, counted without the per-char flags.
    if s.is_ascii() {
        let other = s.bytes().filter(|&b| is_flagged(char::from(b))).count();
        return (0, u64::try_from(other).unwrap_or(u64::MAX));
    }
    let mut bidi = 0;
    let mut other = 0;
    for (c, flagged) in s.chars().zip(flags(s)) {
        if flagged {
            if is_bidi_control(c) {
                bidi += 1
            } else {
                other += 1
            }
        }
    }
    (bidi, other)
}

/// Flagged characters as `⟨U+XXXX⟩` (at least 4 hex digits, upper case). The delimiters
/// themselves (U+27E8 `⟨`, U+27E9 `⟩`) are escaped the same way when they occur in `s`, so the
/// encoding is injective: every `⟨` in the output starts an escape and literal text can never
/// pass for one. They are display escapes only; `count` and `strip` ignore them. C.6 shape: a
/// plain `String`.
pub fn escape_for_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (c, flagged) in s.chars().zip(flags(s)) {
        if flagged || matches!(c, '⟨' | '⟩') {
            out.push_str(&format!("⟨U+{:04X}⟩", c as u32))
        } else {
            out.push(c)
        }
    }
    out
}

/// §3.3 agent-string stripping: every flagged char plus `\t`, `\r` and (unless `keep_newlines`,
/// which the agent's `reason`, the human's deny reasons and a deny hint's upstream messages use)
/// `\n`. Returns the stripped string and whether anything was removed.
pub fn strip(s: &str, keep_newlines: bool) -> (String, bool) {
    let mut out = String::with_capacity(s.len());
    let mut removed = false;
    for (c, flagged) in s.chars().zip(flags(s)) {
        let drop = flagged || c == '\t' || c == '\r' || (c == '\n' && !keep_newlines);
        if drop { removed = true } else { out.push(c) }
    }
    (out, removed)
}
