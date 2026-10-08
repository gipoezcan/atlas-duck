use std::time::{Duration, Instant};

use atlas_duck_preview::PREVIEW_BUILDER_VERSION;
use atlas_duck_preview::invisible::{
    MAX_RGI_EMOJI_CHARS, count, escape_for_display, flags, is_bidi_control, is_flagged, strip,
};
use atlas_duck_preview::mixed_script::is_mixed_script;
use icu_properties::CodePointMapData;
use icu_properties::props::Script;

/// §13 S-13 input: ESC, NEL, U+3164, U+E0041, U+202E, the ZWJ sequence 👩‍🚀 and ❤️ (U+FE0F).
const S13: &str = "a\u{1B}b\u{85}c\u{3164}d\u{E0041}e\u{202E}f👩\u{200D}🚀g❤\u{FE0F}h";

#[test]
fn s13_golden_classifier() {
    assert_eq!(count(S13), (1, 4));
    assert_eq!(
        escape_for_display(S13),
        "a⟨U+001B⟩b⟨U+0085⟩c⟨U+3164⟩d⟨U+E0041⟩e⟨U+202E⟩f👩\u{200D}🚀g❤\u{FE0F}h"
    );
    let (stripped, removed) = strip(S13, false);
    assert_eq!(stripped, "abcdef👩\u{200D}🚀g❤\u{FE0F}h");
    assert!(removed);

    // Outside an RGI sequence the exempt code points are flagged.
    assert_eq!(flags("a\u{200D}b"), [false, true, false]);
    assert_eq!(flags("a\u{FE0F}"), [false, true]);
    assert_eq!(count("a\u{200D}b"), (0, 1));
}

#[test]
fn s13_mixed_script_identifiers() {
    assert!(is_mixed_script("АBC-1")); // Cyrillic А
    assert!(!is_mixed_script("ABC-1"));
    assert!(is_mixed_script("раypal.com")); // Cyrillic р, а
    assert!(!is_mixed_script("münchen.example"));
    assert!(!is_mixed_script("jdoe@corp.example"));
}

#[test]
fn mixed_script_uses_uts39_augmented_sets() {
    // Han + Hiragana is single-script Jpan, Han + Hangul is Kore (UTS #39 §5.1).
    assert!(!is_mixed_script("山田たろう"));
    assert!(!is_mixed_script("김민준金"));
    assert!(!is_mixed_script("ヤマダ山田"));
    // Hiragana + Hangul share no augmented set.
    assert!(is_mixed_script("たろう김"));
    // Common and Inherited characters alone never make an identifier mixed.
    assert!(!is_mixed_script(""));
    assert!(!is_mixed_script("123-_.@"));
    assert!(!is_mixed_script("e\u{301}x")); // combining acute (Inherited)
    // Greek omicron in a Latin key.
    assert!(is_mixed_script("PRΟJ-1"));
}

#[test]
fn strip_keeps_newlines_for_reason() {
    assert_eq!(strip("a\nb\tc", true), ("a\nbc".to_string(), true));
    assert_eq!(strip("a\r\nb", false), ("ab".to_string(), true));
    assert_eq!(strip("plain", false), ("plain".to_string(), false));
}

#[test]
fn classifier_definition() {
    // Default_Ignorable_Code_Point samples (§6.4).
    for c in [
        '\u{AD}',
        '\u{34F}',
        '\u{115F}',
        '\u{1160}',
        '\u{3164}',
        '\u{FFA0}',
        '\u{180B}',
        '\u{180F}',
        '\u{200B}',
        '\u{2060}',
        '\u{FEFF}',
        '\u{FE00}',
        '\u{E0001}',
        '\u{E0100}',
    ] {
        assert!(is_flagged(c), "U+{:04X}", c as u32);
    }
    // Cc except \t \n \r; Zl; Zp.
    assert!(is_flagged('\0'));
    assert!(is_flagged('\u{7F}'));
    assert!(is_flagged('\u{9F}'));
    assert!(is_flagged('\u{2028}'));
    assert!(is_flagged('\u{2029}'));
    for c in ['\t', '\n', '\r', ' ', 'a', 'ä', '\u{A0}', '😀', '\u{E000}'] {
        assert!(!is_flagged(c), "U+{:04X}", c as u32);
    }
    // Context-free: the emoji exemption lives in `flags`, not `is_flagged`.
    assert!(is_flagged('\u{200D}'));
    assert!(is_flagged('\u{FE0F}'));
}

#[test]
fn bidi_controls_are_exactly_the_bidi_control_property() {
    let expected: Vec<u32> = [0x061C, 0x200E, 0x200F]
        .into_iter()
        .chain(0x202A..=0x202E)
        .chain(0x2066..=0x2069)
        .collect();
    let found: Vec<u32> = (0..=0x10FFFFu32)
        .filter_map(char::from_u32)
        .filter(|&c| is_bidi_control(c))
        .map(|c| c as u32)
        .collect();
    assert_eq!(found, expected);
    // Every bidi control is also flagged, so the two header groups partition flagged chars.
    assert!(
        found
            .iter()
            .filter_map(|&u| char::from_u32(u))
            .all(is_flagged)
    );
}

#[test]
fn rgi_emoji_sequences_unflag_only_zwj_and_variation_selectors() {
    // Keycap, flag, skin-tone ZWJ sequence, kiss with skin tones.
    for e in [
        "#\u{FE0F}\u{20E3}",
        "🇩🇪",
        "🧑🏽\u{200D}💻",
        "👨🏻\u{200D}❤\u{FE0F}\u{200D}💋\u{200D}👨🏼",
        "🏳\u{FE0F}\u{200D}🌈",
    ] {
        assert_eq!(count(e), (0, 0), "{e}");
        assert_eq!(strip(e, false), (e.to_string(), false), "{e}");
    }
    // Subdivision flag: tag characters stay flagged (§6.4, L57).
    let england = "🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}";
    assert_eq!(count(england), (0, 6));
    // A ZWJ that joins nothing RGI stays flagged; the trailing ❤️ is still RGI.
    assert_eq!(flags("👩\u{200D}❤\u{FE0F}"), [false, true, false, false]);
    // FE0E never appears in a fully-qualified emoji, so it stays flagged.
    assert_eq!(flags("❤\u{FE0E}"), [false, true]);
    // A ZWJ sequence glued to neighbouring digits is still found.
    assert_eq!(
        escape_for_display("12👩\u{200D}🚀3\u{200D}"),
        "12👩\u{200D}🚀3⟨U+200D⟩"
    );
}

#[test]
fn escape_uses_at_least_four_upper_hex_digits() {
    assert_eq!(escape_for_display("\u{1}"), "⟨U+0001⟩");
    assert_eq!(escape_for_display("\u{feff}"), "⟨U+FEFF⟩");
    assert_eq!(escape_for_display("\u{e007f}"), "⟨U+E007F⟩");
}

#[test]
fn max_rgi_emoji_chars_bounds_the_table() {
    let longest = emojis::iter()
        .flat_map(|e| {
            let tones: Vec<&emojis::Emoji> =
                e.skin_tones().map(|t| t.collect()).unwrap_or_default();
            std::iter::once(e).chain(tones)
        })
        .map(|e| e.as_str().chars().count())
        .max()
        .unwrap_or(0);
    assert_eq!(longest, MAX_RGI_EMOJI_CHARS);
}

#[test]
fn long_emoji_runs_stay_linear() {
    // Digits, `#` and `*` are emoji-sequence characters: one huge run must not go quadratic.
    let digits = "7".repeat(200_000);
    let zwj_run = "1\u{200D}".repeat(100_000);
    let start = Instant::now();
    assert_eq!(count(&digits), (0, 0));
    assert_eq!(count(&zwj_run), (0, 100_000));
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn v31_builder_version_names_unicode_versions() {
    for tag in ["icu-", "emoji-"] {
        let at = PREVIEW_BUILDER_VERSION.find(tag).map(|i| i + tag.len());
        let next = at.and_then(|i| PREVIEW_BUILDER_VERSION[i..].chars().next());
        assert!(
            next.is_some_and(|c| c.is_ascii_digit()),
            "{PREVIEW_BUILDER_VERSION}"
        );
    }
}

#[test]
fn v31_builder_version_matches_the_linked_tables() {
    let emoji = format!(
        ";emoji-{}.{}",
        emojis::UNICODE_VERSION.major(),
        emojis::UNICODE_VERSION.minor()
    );
    assert!(
        PREVIEW_BUILDER_VERSION.ends_with(&emoji),
        "{PREVIEW_BUILDER_VERSION}"
    );
    // ICU data is Unicode 17.0: U+10940 (Sidetic, new in 17.0) is assigned to its script.
    assert!(PREVIEW_BUILDER_VERSION.contains(";icu-17.0;"));
    assert_eq!(
        CodePointMapData::<Script>::new().get('\u{10940}'),
        Script::Sidetic
    );
}
