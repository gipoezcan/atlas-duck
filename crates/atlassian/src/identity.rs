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
    UsernameMatcher::new(header).matches(stored)
}

/// [`username_matches`] with its first name canonicalized once, for comparing one name with many
/// (the assignable-user resolution, T15): linear in the names compared.
pub struct UsernameMatcher(Option<String>);

impl UsernameMatcher {
    pub fn new(header: &str) -> UsernameMatcher {
        // Undecodable percent-escapes fail closed (recheck path), like `anonymous` and "".
        UsernameMatcher(canon(header).filter(|h| h != "anonymous" && !h.is_empty()))
    }

    pub fn matches(&self, stored: &str) -> bool {
        self.0.is_some() && self.0 == canon(stored)
    }
}

/// Redacting `Debug` (§7.7): a username is Atlassian data.
impl std::fmt::Debug for UsernameMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsernameMatcher").finish_non_exhaustive()
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

    /// T15: the matcher is the same comparison with one side canonicalized once.
    #[test]
    fn username_matcher_agrees_with_username_matches() {
        let names = [
            "jdoe",
            " JDoe ",
            "jdoe%40corp.example",
            "jdoe@corp.example",
            "JDOE@CORP.EXAMPLE",
            "anonymous",
            "ANONYMOU%53",
            "",
            "  ",
            "%ZZ",
            "%FF",
            "Ä",
            "A\u{308}",
            "bob",
        ];
        for a in names {
            let m = UsernameMatcher::new(a);
            for b in names {
                assert_eq!(m.matches(b), username_matches(a, b), "{a:?} vs {b:?}");
            }
        }
    }
}
