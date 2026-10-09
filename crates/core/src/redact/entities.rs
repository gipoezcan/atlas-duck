//! WHATWG named character references that expand to two code points.
//!
//! html-escape 0.2.15 keeps only the first code point of these (`&fjlig;` gives `f`), so the
//! lenient view (plan addition) looks them up here first. Generated from
//! <https://html.spec.whatwg.org/entities.json> (entries with a `;` and more than one code
//! point), sorted by name for binary search.
//!
//! Provenance: WHATWG HTML Living Standard, named character references (entities.json,
//! fetched 2026-10-09; the named-reference list is frozen by the standard). Copyright © WHATWG
//! (Apple, Google, Mozilla, Microsoft), licensed under CC BY 4.0
//! (<https://creativecommons.org/licenses/by/4.0/>). This is a factual 93-row table.

pub(crate) static MULTI_CODE_POINT: [(&[u8], &str); 93] = [
    (b"NotEqualTilde", "\u{2242}\u{0338}"),
    (b"NotGreaterFullEqual", "\u{2267}\u{0338}"),
    (b"NotGreaterGreater", "\u{226B}\u{0338}"),
    (b"NotGreaterSlantEqual", "\u{2A7E}\u{0338}"),
    (b"NotHumpDownHump", "\u{224E}\u{0338}"),
    (b"NotHumpEqual", "\u{224F}\u{0338}"),
    (b"NotLeftTriangleBar", "\u{29CF}\u{0338}"),
    (b"NotLessLess", "\u{226A}\u{0338}"),
    (b"NotLessSlantEqual", "\u{2A7D}\u{0338}"),
    (b"NotNestedGreaterGreater", "\u{2AA2}\u{0338}"),
    (b"NotNestedLessLess", "\u{2AA1}\u{0338}"),
    (b"NotPrecedesEqual", "\u{2AAF}\u{0338}"),
    (b"NotRightTriangleBar", "\u{29D0}\u{0338}"),
    (b"NotSquareSubset", "\u{228F}\u{0338}"),
    (b"NotSquareSuperset", "\u{2290}\u{0338}"),
    (b"NotSubset", "\u{2282}\u{20D2}"),
    (b"NotSucceedsEqual", "\u{2AB0}\u{0338}"),
    (b"NotSucceedsTilde", "\u{227F}\u{0338}"),
    (b"NotSuperset", "\u{2283}\u{20D2}"),
    (b"ThickSpace", "\u{205F}\u{200A}"),
    (b"acE", "\u{223E}\u{0333}"),
    (b"bne", "\u{003D}\u{20E5}"),
    (b"bnequiv", "\u{2261}\u{20E5}"),
    (b"caps", "\u{2229}\u{FE00}"),
    (b"cups", "\u{222A}\u{FE00}"),
    (b"fjlig", "\u{0066}\u{006A}"),
    (b"gesl", "\u{22DB}\u{FE00}"),
    (b"gvertneqq", "\u{2269}\u{FE00}"),
    (b"gvnE", "\u{2269}\u{FE00}"),
    (b"lates", "\u{2AAD}\u{FE00}"),
    (b"lesg", "\u{22DA}\u{FE00}"),
    (b"lvertneqq", "\u{2268}\u{FE00}"),
    (b"lvnE", "\u{2268}\u{FE00}"),
    (b"nGg", "\u{22D9}\u{0338}"),
    (b"nGt", "\u{226B}\u{20D2}"),
    (b"nGtv", "\u{226B}\u{0338}"),
    (b"nLl", "\u{22D8}\u{0338}"),
    (b"nLt", "\u{226A}\u{20D2}"),
    (b"nLtv", "\u{226A}\u{0338}"),
    (b"nang", "\u{2220}\u{20D2}"),
    (b"napE", "\u{2A70}\u{0338}"),
    (b"napid", "\u{224B}\u{0338}"),
    (b"nbump", "\u{224E}\u{0338}"),
    (b"nbumpe", "\u{224F}\u{0338}"),
    (b"ncongdot", "\u{2A6D}\u{0338}"),
    (b"nedot", "\u{2250}\u{0338}"),
    (b"nesim", "\u{2242}\u{0338}"),
    (b"ngE", "\u{2267}\u{0338}"),
    (b"ngeqq", "\u{2267}\u{0338}"),
    (b"ngeqslant", "\u{2A7E}\u{0338}"),
    (b"nges", "\u{2A7E}\u{0338}"),
    (b"nlE", "\u{2266}\u{0338}"),
    (b"nleqq", "\u{2266}\u{0338}"),
    (b"nleqslant", "\u{2A7D}\u{0338}"),
    (b"nles", "\u{2A7D}\u{0338}"),
    (b"notinE", "\u{22F9}\u{0338}"),
    (b"notindot", "\u{22F5}\u{0338}"),
    (b"nparsl", "\u{2AFD}\u{20E5}"),
    (b"npart", "\u{2202}\u{0338}"),
    (b"npre", "\u{2AAF}\u{0338}"),
    (b"npreceq", "\u{2AAF}\u{0338}"),
    (b"nrarrc", "\u{2933}\u{0338}"),
    (b"nrarrw", "\u{219D}\u{0338}"),
    (b"nsce", "\u{2AB0}\u{0338}"),
    (b"nsubE", "\u{2AC5}\u{0338}"),
    (b"nsubset", "\u{2282}\u{20D2}"),
    (b"nsubseteqq", "\u{2AC5}\u{0338}"),
    (b"nsucceq", "\u{2AB0}\u{0338}"),
    (b"nsupE", "\u{2AC6}\u{0338}"),
    (b"nsupset", "\u{2283}\u{20D2}"),
    (b"nsupseteqq", "\u{2AC6}\u{0338}"),
    (b"nvap", "\u{224D}\u{20D2}"),
    (b"nvge", "\u{2265}\u{20D2}"),
    (b"nvgt", "\u{003E}\u{20D2}"),
    (b"nvle", "\u{2264}\u{20D2}"),
    (b"nvlt", "\u{003C}\u{20D2}"),
    (b"nvltrie", "\u{22B4}\u{20D2}"),
    (b"nvrtrie", "\u{22B5}\u{20D2}"),
    (b"nvsim", "\u{223C}\u{20D2}"),
    (b"race", "\u{223D}\u{0331}"),
    (b"smtes", "\u{2AAC}\u{FE00}"),
    (b"sqcaps", "\u{2293}\u{FE00}"),
    (b"sqcups", "\u{2294}\u{FE00}"),
    (b"varsubsetneq", "\u{228A}\u{FE00}"),
    (b"varsubsetneqq", "\u{2ACB}\u{FE00}"),
    (b"varsupsetneq", "\u{228B}\u{FE00}"),
    (b"varsupsetneqq", "\u{2ACC}\u{FE00}"),
    (b"vnsub", "\u{2282}\u{20D2}"),
    (b"vnsup", "\u{2283}\u{20D2}"),
    (b"vsubnE", "\u{2ACB}\u{FE00}"),
    (b"vsubne", "\u{228A}\u{FE00}"),
    (b"vsupnE", "\u{2ACC}\u{FE00}"),
    (b"vsupne", "\u{228B}\u{FE00}"),
];

/// WHATWG numeric character reference remap of 0x80–0x9F (windows-1252), as browsers decode
/// `&#146;` to `’`; the other C1 values stay as they are.
pub(crate) fn c1_remap(n: u32) -> Option<char> {
    Some(match n {
        0x80 => '\u{20AC}',
        0x82 => '\u{201A}',
        0x83 => '\u{0192}',
        0x84 => '\u{201E}',
        0x85 => '\u{2026}',
        0x86 => '\u{2020}',
        0x87 => '\u{2021}',
        0x88 => '\u{02C6}',
        0x89 => '\u{2030}',
        0x8A => '\u{0160}',
        0x8B => '\u{2039}',
        0x8C => '\u{0152}',
        0x8E => '\u{017D}',
        0x91 => '\u{2018}',
        0x92 => '\u{2019}',
        0x93 => '\u{201C}',
        0x94 => '\u{201D}',
        0x95 => '\u{2022}',
        0x96 => '\u{2013}',
        0x97 => '\u{2014}',
        0x98 => '\u{02DC}',
        0x99 => '\u{2122}',
        0x9A => '\u{0161}',
        0x9B => '\u{203A}',
        0x9C => '\u{0153}',
        0x9E => '\u{017E}',
        0x9F => '\u{0178}',
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_every_entry_has_two_code_points() {
        assert!(MULTI_CODE_POINT.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(MULTI_CODE_POINT.iter().all(|(_, s)| s.chars().count() == 2));
    }

    /// Consistency with html-escape, whose table lists every entity name: each name exists there
    /// and the library's (truncated) value is our first code point.
    #[test]
    fn names_and_first_code_points_match_html_escape() {
        for (name, full) in MULTI_CODE_POINT {
            let lib = html_escape::NAMED_ENTITIES
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| *v);
            let first = full.chars().next().map(String::from);
            assert_eq!(
                lib.map(str::to_owned),
                first,
                "{}",
                String::from_utf8_lossy(name)
            );
        }
    }
}
