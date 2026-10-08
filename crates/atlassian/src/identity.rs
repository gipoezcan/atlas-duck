//! The one Jira username comparison (§7.2).

use crate::types::IdentityObserved;

/// The per-response `X-AUSERNAME` check (§7.2), given every value the header carried.
/// Missing, then `anonymous`, then any other name; more than one value fails closed.
pub(crate) fn check_jira_header(values: &[String], stored: &str) -> Result<(), IdentityObserved> {
    let value = match values {
        [] => return Err(IdentityObserved::Missing),
        [one] => one,
        many => return Err(IdentityObserved::Other(many.join(", "))),
    };
    if canon(value).as_deref() == Some("anonymous") {
        return Err(IdentityObserved::Anonymous);
    }
    if username_matches(value, stored) {
        Ok(())
    } else {
        Err(IdentityObserved::Other(value.clone()))
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn vals(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn jira_header_check_order() {
        assert_eq!(check_jira_header(&vals(&["jdoe"]), "jdoe"), Ok(()));
        assert_eq!(check_jira_header(&vals(&[" JDoe "]), "jdoe"), Ok(()));
        assert_eq!(
            check_jira_header(&vals(&["jdoe%40corp.example"]), "jdoe@corp.example"),
            Ok(())
        );
        assert_eq!(
            check_jira_header(&[], "jdoe"),
            Err(IdentityObserved::Missing)
        );
        for anon in ["anonymous", "ANONYMOUS", " Anonymous ", "anonymou%73"] {
            assert_eq!(
                check_jira_header(&vals(&[anon]), "anonymous"),
                Err(IdentityObserved::Anonymous),
                "{anon}"
            );
        }
        assert_eq!(
            check_jira_header(&vals(&["bob"]), "jdoe"),
            Err(IdentityObserved::Other("bob".to_owned()))
        );
        assert_eq!(
            check_jira_header(&vals(&[""]), ""),
            Err(IdentityObserved::Other(String::new()))
        );
        assert_eq!(
            check_jira_header(&vals(&["jdoe", "jdoe"]), "jdoe"),
            Err(IdentityObserved::Other("jdoe, jdoe".to_owned()))
        );
    }
}
