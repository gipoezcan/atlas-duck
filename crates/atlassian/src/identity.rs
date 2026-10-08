//! The one Jira username comparison (§7.2).

/// Trim, percent-decode only when a `%XX` triplet is present, NFC, Unicode
/// simple case folding. `anonymous` and the empty name never match.
pub fn username_matches(header: &str, stored: &str) -> bool {
    match (canon(header), canon(stored)) {
        (Some(h), Some(s)) => h != "anonymous" && !h.is_empty() && h == s,
        _ => false, // undecodable percent-escapes fail closed (recheck path)
    }
}

fn canon(v: &str) -> Option<String> {
    let t = v.trim();
    let decoded = if has_pct_triplet(t) {
        percent_encoding::percent_decode_str(t)
            .decode_utf8()
            .ok()?
            .into_owned()
    } else {
        t.to_owned()
    };
    let nfc = icu_normalizer::ComposingNormalizerBorrowed::new_nfc()
        .normalize(&decoded)
        .into_owned();
    let cm = icu_casemap::CaseMapperBorrowed::new();
    Some(nfc.chars().map(|c| cm.simple_fold(c)).collect())
}

fn has_pct_triplet(s: &str) -> bool {
    let b = s.as_bytes();
    b.windows(3)
        .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
}
