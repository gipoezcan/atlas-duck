//! §6.4 invisible-character classifier: the single definition used for agent-string stripping
//! (§3.3), preview marking and header counts (§6.1), warnings (§6.2) and escaping.
//!
//! Character data comes from `icu_properties` compiled data and RGI emoji sequences from the
//! `emojis` table; both versions are part of [`crate::PREVIEW_BUILDER_VERSION`] (V31).

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

/// §6.4: Default_Ignorable_Code_Point ∪ (Cc minus \t \n \r) ∪ Zl ∪ Zp. Context-free.
pub fn is_flagged(c: char) -> bool {
    if CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(c) {
        return true;
    }
    match CodePointMapData::<GeneralCategory>::new().get(c) {
        GeneralCategory::Control => !matches!(c, '\t' | '\n' | '\r'),
        GeneralCategory::LineSeparator | GeneralCategory::ParagraphSeparator => true,
        _ => false,
    }
}

/// §6.4: Bidi_Control (U+061C, U+200E–200F, U+202A–202E, U+2066–2069).
pub fn is_bidi_control(c: char) -> bool {
    CodePointSetData::new::<BidiControl>().contains(c)
}

/// Per-char flags for `s` (in `char_indices` order): `is_flagged`, except U+FE0E, U+FE0F and
/// U+200D inside an RGI emoji sequence. Sequences are found leftmost-longest within each maximal
/// run of emoji-sequence characters; a candidate counts when `emojis::get` knows it (the table is
/// the fully-qualified emoji of emoji-test.txt; `get` also maps minimally-qualified and
/// unqualified spellings to them).
pub fn flags(s: &str) -> Vec<bool> {
    let chars: Vec<char> = s.chars().collect();
    let mut out: Vec<bool> = chars.iter().map(|&c| is_flagged(c)).collect();
    let mut i = 0;
    while i < chars.len() {
        if !is_emoji_seq_char(chars[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && is_emoji_seq_char(chars[i]) {
            i += 1;
        }
        // Only ZWJ and the variation selectors can be unflagged; skip runs without them.
        if !chars[start..i]
            .iter()
            .any(|&c| matches!(c, ZWJ | VS15 | VS16))
        {
            continue;
        }
        let mut j = start;
        while j < i {
            let mut matched = None;
            for end in (j + 1..=i.min(j + MAX_RGI_EMOJI_CHARS)).rev() {
                let candidate: String = chars[j..end].iter().collect();
                if emojis::get(&candidate).is_some() {
                    matched = Some(end);
                    break;
                }
            }
            match matched {
                Some(end) => {
                    for k in j..end {
                        if matches!(chars[k], ZWJ | VS15 | VS16) {
                            out[k] = false;
                        }
                    }
                    j = end;
                }
                None => j += 1,
            }
        }
    }
    out
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

/// Flagged characters as `⟨U+XXXX⟩` (at least 4 hex digits, upper case).
pub fn escape_for_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (c, flagged) in s.chars().zip(flags(s)) {
        if flagged {
            out.push_str(&format!("⟨U+{:04X}⟩", c as u32))
        } else {
            out.push(c)
        }
    }
    out
}

/// §3.3 agent-string stripping: every flagged char plus `\t`, `\r` and (unless `keep_newlines`,
/// which only `reason` uses) `\n`. Returns the stripped string and whether anything was removed.
pub fn strip(s: &str, keep_newlines: bool) -> (String, bool) {
    let mut out = String::with_capacity(s.len());
    let mut removed = false;
    for (c, flagged) in s.chars().zip(flags(s)) {
        let drop = flagged || c == '\t' || c == '\r' || (c == '\n' && !keep_newlines);
        if drop { removed = true } else { out.push(c) }
    }
    (out, removed)
}
