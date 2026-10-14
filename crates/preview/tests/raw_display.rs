//! M6 T11 (PD-68, PD-69): the Raw display projection. Byte-faithful: invisible, bidi, CR and
//! trailing whitespace are marked, invalid UTF-8 is shown as bytes, a UTF-8 sequence cut by a page
//! boundary is carried and shown once.

use atlas_duck_preview::render::raw::{self, incomplete_tail};
use atlas_duck_preview::render::{raw_display, raw_display_last};
use proptest::prelude::*;

#[test]
fn pd69_raw_display_marks_cr_and_trailing_ws() {
    let d = raw_display_last(b"a \r\nb\t\nc  d  ", &[]);
    assert_eq!(d.text, "a⟨U+0020⟩⟨U+000D⟩\nb⟨U+0009⟩\nc  d⟨U+0020⟩⟨U+0020⟩");
    // A lone CR inside a line is marked too, a plain tab inside a line is not.
    assert_eq!(raw_display_last(b"x\ry\tz", &[]).text, "x⟨U+000D⟩y\tz");
}

#[test]
fn raw_display_marks_bidi_and_invisible_and_the_delimiters() {
    let d = raw_display_last("a\u{202E}b\u{200B}c⟨x⟩".as_bytes(), &[]);
    assert_eq!(d.text, "a⟨U+202E⟩b⟨U+200B⟩c⟨U+27E8⟩x⟨U+27E9⟩");
    assert!(d.carry_out.is_empty());
}

#[test]
fn raw_display_marks_control_and_line_separator_characters() {
    let d = raw_display_last("a\u{0}b\u{1B}c\u{85}d\u{2028}e".as_bytes(), &[]);
    assert_eq!(d.text, "a⟨U+0000⟩b⟨U+001B⟩c⟨U+0085⟩d⟨U+2028⟩e");
}

/// Documented in `raw.rs`: the end of a page looks like a line end, so spaces and a CR right
/// before a boundary are marked, although they would not be in the middle of a line.
#[test]
fn spaces_and_cr_before_a_page_boundary_are_over_marked() {
    assert_eq!(raw_display(b"a  ", &[]).text, "a⟨U+0020⟩⟨U+0020⟩");
    assert_eq!(raw_display(b"a\r", &[]).text, "a⟨U+000D⟩");
    // The same bytes in the middle of a line.
    assert_eq!(raw_display_last(b"a  b", &[]).text, "a  b");
}

/// Documented in `raw.rs`: emoji sequences are classified per page, so a ZWJ sequence cut by a
/// boundary has its ZWJ marked on the page, which the unsplit text does not do (the safe side).
#[test]
fn a_zwj_sequence_cut_by_a_boundary_is_over_marked() {
    let whole = "👩\u{200D}💻";
    assert_eq!(raw_display_last(whole.as_bytes(), &[]).text, whole);
    let cut = whole.find('\u{200D}').map(|i| i + '\u{200D}'.len_utf8());
    let (a, b) = whole.split_at(cut.unwrap_or(0));
    let first = raw_display(a.as_bytes(), &[]);
    let second = raw_display_last(b.as_bytes(), &first.carry_out);
    assert_eq!(format!("{}{}", first.text, second.text), "👩⟨U+200D⟩💻");
}

#[test]
fn raw_display_utf8_split_carried() {
    let emoji = "😀".as_bytes();
    assert_eq!(emoji.len(), 4);
    let mut page1 = b"ab".to_vec();
    page1.extend_from_slice(&emoji[..1]);
    let mut page2 = emoji[1..].to_vec();
    page2.extend_from_slice(b"cd");

    let first = raw_display(&page1, &[]);
    assert_eq!(first.text, "ab");
    assert_eq!(first.carry_out, emoji[..1]);
    assert_eq!(incomplete_tail(&page1), &emoji[..1]);

    let second = raw_display_last(&page2, &first.carry_out);
    assert_eq!(second.text, "😀cd");
    assert!(second.carry_out.is_empty());
    assert_eq!(
        format!("{}{}", first.text, second.text)
            .matches('😀')
            .count(),
        1
    );
}

#[test]
fn raw_display_utf8_split_in_every_position() {
    let s = "x€y😀z";
    let bytes = s.as_bytes();
    for cut in 0..=bytes.len() {
        let first = raw_display(&bytes[..cut], &[]);
        let second = raw_display_last(&bytes[cut..], &first.carry_out);
        assert_eq!(format!("{}{}", first.text, second.text), s, "cut {cut}");
    }
}

#[test]
fn raw_display_invalid_utf8_shown_as_bytes() {
    assert_eq!(raw_display_last(b"a\xFFb", &[]).text, "a⟨0xFF⟩b");
    // Bytes that look like a sequence start but are not valid are shown one by one.
    assert_eq!(raw_display_last(b"\xE2\x82x", &[]).text, "⟨0xE2⟩⟨0x82⟩x");
    // An overlong and a surrogate encoding are not UTF-8 either.
    assert_eq!(raw_display_last(b"\xC0\x80", &[]).text, "⟨0xC0⟩⟨0x80⟩");
    assert_eq!(
        raw_display_last(b"\xED\xA0\x80", &[]).text,
        "⟨0xED⟩⟨0xA0⟩⟨0x80⟩"
    );
}

#[test]
fn raw_display_last_page_shows_an_incomplete_tail() {
    // Not the last page: carried. The last page: shown, nothing is hidden.
    let bytes = b"ok\xF0\x9F\x98";
    let mid = raw_display(bytes, &[]);
    assert_eq!(mid.text, "ok");
    assert_eq!(mid.carry_out, [0xF0, 0x9F, 0x98]);
    let last = raw_display_last(bytes, &[]);
    assert_eq!(last.text, "ok⟨0xF0⟩⟨0x9F⟩⟨0x98⟩");
    assert!(last.carry_out.is_empty());
}

#[test]
fn incomplete_tail_is_only_a_valid_prefix() {
    assert_eq!(incomplete_tail(b""), b"");
    assert_eq!(incomplete_tail(b"abc"), b"");
    assert_eq!(incomplete_tail(b"a\xFF"), b"");
    assert_eq!(incomplete_tail(b"a\xC3"), b"\xC3");
    assert_eq!(incomplete_tail(b"a\xE2\x82"), b"\xE2\x82");
    assert_eq!(incomplete_tail(b"a\xF0\x9F\x98"), b"\xF0\x9F\x98");
    // A lone continuation byte, or a complete character, is not a tail.
    assert_eq!(incomplete_tail(b"a\x98"), b"");
    assert_eq!(incomplete_tail("€".as_bytes()), b"");
    // A prefix that no valid sequence continues (overlong, surrogate, above U+10FFFF).
    assert_eq!(incomplete_tail(b"a\xE0\x80"), b"");
    assert_eq!(incomplete_tail(b"a\xED\xA0"), b"");
    assert_eq!(incomplete_tail(b"a\xF4\x90"), b"");
    assert_eq!(raw::MAX_CARRY_BYTES, 3);
}

/// Pieces without space, tab, CR (their marks depend on where a page ends) and without ZWJ or
/// variation selectors (their flag depends on the emoji around them).
fn piece() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        proptest::sample::select(vec![
            "a", "Z", "\n", "é", "€", "日", "😀", "\u{202E}", "\u{200B}", "⟨"
        ])
        .prop_map(|s| s.as_bytes().to_vec()),
        any::<u8>()
            .prop_filter("not space, tab or CR", |b| !matches!(
                b,
                b' ' | b'\t' | b'\r'
            ))
            .prop_map(|b| vec![b]),
    ]
}

proptest! {
    /// Any split of any byte string into pages (each carry derived from the page before alone):
    /// the pages' displays concatenated equal the display of the whole.
    #[test]
    fn page_boundary_carry_equals_the_unsplit_display(
        pieces in proptest::collection::vec(piece(), 0..40),
        cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..5),
    ) {
        let bytes: Vec<u8> = pieces.concat();
        let mut at: Vec<usize> = cuts.iter().map(|i| i.index(bytes.len() + 1)).collect();
        at.sort_unstable();
        let mut pages: Vec<&[u8]> = Vec::new();
        let mut from = 0;
        for c in at {
            pages.push(&bytes[from..c]);
            from = c;
        }
        pages.push(&bytes[from..]);

        let mut text = String::new();
        let mut carry: Vec<u8> = Vec::new();
        for (i, page) in pages.iter().enumerate() {
            let d = if i + 1 == pages.len() {
                raw_display_last(page, &carry)
            } else {
                raw_display(page, &carry)
            };
            // The carry the command derives from the page before alone is the one handed on,
            // except for a page too short to hold a whole tail of its own.
            if i + 1 < pages.len() && page.len() >= raw::MAX_CARRY_BYTES {
                prop_assert_eq!(&d.carry_out[..], incomplete_tail(page));
            }
            text.push_str(&d.text);
            carry = d.carry_out;
        }
        prop_assert_eq!(text, raw_display_last(&bytes, &[]).text);
    }
}
