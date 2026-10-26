//! CSRF token and Origin checks (SM-2.5). Every state-changing `/api/` request must carry an
//! `Origin` equal to the public URL's origin, and (with a session) an `X-CSRF-Token` equal to the
//! session's token, compared in constant time.

use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

pub const CSRF_HEADER: &str = "x-csrf-token";

/// `Origin` equals `scheme://host[:port]` of the public URL exactly (no trailing slash, case of
/// the scheme and host as browsers send them: lowercase).
pub fn origin_ok(origin: Option<&str>, public_origin: &str) -> bool {
    origin.is_some_and(|o| o == public_origin)
}

/// Constant-time token comparison; a missing header never matches.
pub fn token_ok(header: Option<&str>, session_token: &SecretString) -> bool {
    match header {
        Some(h) => {
            let want = session_token.expose_secret().as_bytes();
            h.len() == want.len() && bool::from(h.as_bytes().ct_eq(want))
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_table() {
        let o = "https://duck.example.test";
        assert!(origin_ok(Some(o), o));
        for bad in [
            None,
            Some("https://duck.example.test/"),
            Some("http://duck.example.test"),
            Some("https://duck.example.test:444"),
            Some("https://evil.example.test"),
            Some("null"),
        ] {
            assert!(!origin_ok(bad, o), "{bad:?}");
        }
    }

    #[test]
    fn token_table() {
        let t = SecretString::from("tok-abc".to_owned());
        assert!(token_ok(Some("tok-abc"), &t));
        assert!(!token_ok(Some("tok-abd"), &t));
        assert!(!token_ok(Some("tok-ab"), &t));
        assert!(!token_ok(Some(""), &t));
        assert!(!token_ok(None, &t));
    }
}
