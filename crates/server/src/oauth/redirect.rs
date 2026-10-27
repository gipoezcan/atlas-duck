//! Redirect URIs (PD-238, RFC 8252 §7.3). Registered: absolute, at most 512 bytes, no fragment, no
//! userinfo; `https` with any host, or `http` with host `127.0.0.1`, `[::1]` or `localhost`.
//! Custom schemes are refused (L243). At authorization a loopback URI matches a registered one
//! ignoring the port only; every other URI matches by exact string.

use url::{Host, Url};

pub const MAX_LEN: usize = 512;
pub const MAX_URIS: usize = 5;

fn is_loopback(u: &Url) -> bool {
    match u.host() {
        Some(Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
        Some(Host::Domain(d)) => d == "localhost",
        None => false,
    }
}

/// The URI parsed, if it may be registered.
pub fn validate_registered(raw: &str) -> Option<Url> {
    if raw.len() > MAX_LEN || raw.contains('#') || raw.chars().any(char::is_whitespace) {
        return None;
    }
    let u = Url::parse(raw).ok()?;
    if u.cannot_be_a_base()
        || u.fragment().is_some()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.host().is_none()
    {
        return None;
    }
    match u.scheme() {
        "https" => Some(u),
        "http" if is_loopback(&u) => Some(u),
        _ => None,
    }
}

/// The form a registered URI is stored in (batch-1 review M4): a loopback URI in its normal
/// form, which [`matches`] compares against, so stored == compared; any other URI as given
/// (it matches by exact string). `None` when it may not be registered.
pub fn registered_form(raw: &str) -> Option<String> {
    let u = validate_registered(raw)?;
    Some(if is_loopback(&u) {
        u.as_str().to_owned()
    } else {
        raw.to_owned()
    })
}

/// Does the presented redirect URI match the registered one? Exact string match, except that a
/// loopback `http` URI may differ in its port. The presented URI must be in its normal form, so
/// `/cb/../evil`-style spellings never match by normalisation.
pub fn matches(registered: &str, presented: &str) -> bool {
    if registered == presented {
        return true;
    }
    let (Some(reg), Some(pre)) = (
        validate_registered(registered),
        validate_registered(presented),
    ) else {
        return false;
    };
    if reg.scheme() != "http" || !is_loopback(&reg) || pre.as_str() != presented {
        return false;
    }
    let mut moved = pre.clone();
    if moved.set_port(reg.port()).is_err() {
        return false;
    }
    moved == reg
}

/// The host shown on the consent page and recorded in `OAUTH_GRANT_CREATED`.
pub fn host_of(uri: &str) -> String {
    Url::parse(uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn registration_rules() {
        for ok in [
            "https://a.example/cb",
            "https://a.example:8443/cb?x=1",
            "http://127.0.0.1/cb",
            "http://127.0.0.1:33418/callback",
            "http://[::1]:9/cb",
            "http://localhost:3000/cb",
        ] {
            assert!(validate_registered(ok).is_some(), "{ok}");
        }
        for bad in [
            "http://example.com/cb",
            "http://127.0.0.2/cb",
            "com.example.app:/cb",
            "myapp://cb",
            "https://a.example/cb#frag",
            "https://a.example/cb#",
            "https://user:pw@a.example/cb",
            "https://user@a.example/cb",
            "/relative/cb",
            "javascript:alert(1)",
            "data:text/html,x",
            "file:///etc/passwd",
            "https://a.example/ cb",
        ] {
            assert!(validate_registered(bad).is_none(), "{bad}");
        }
        let long = format!("https://a.example/{}", "x".repeat(MAX_LEN));
        assert!(validate_registered(&long).is_none());
    }

    #[test]
    fn matching_table() {
        let cases = [
            // Loopback: any port, nothing else may differ.
            ("http://127.0.0.1/cb", "http://127.0.0.1:51234/cb", true),
            ("http://127.0.0.1:1/cb", "http://127.0.0.1:2/cb", true),
            ("http://[::1]:1/cb", "http://[::1]:7/cb", true),
            ("http://localhost:1/cb", "http://localhost:7/cb", true),
            ("http://127.0.0.1/cb", "http://localhost/cb", false),
            ("http://localhost/cb", "http://127.0.0.1/cb", false),
            ("http://127.0.0.1/cb", "http://127.0.0.1:5/cb2", false),
            ("http://127.0.0.1/cb", "http://127.0.0.1:5/cb?x=1", false),
            ("http://127.0.0.1/cb", "http://127.0.0.1:5/x/../cb", false),
            ("http://127.0.0.1/cb", "https://127.0.0.1:5/cb", false),
            // Everything else: exact.
            ("https://a.example/cb", "https://a.example/cb", true),
            (
                "https://a.example/cb",
                "https://a.example/cb/../evil",
                false,
            ),
            ("https://a.example/cb", "https://a.example/cb?x=1", false),
            ("https://a.example/cb", "https://a.example.evil/cb", false),
            ("https://a.example/cb", "https://a.example:443/cb", false),
            ("https://a.example/cb", "https://A.example/cb", false),
            (
                "https://a.example:8443/cb",
                "https://a.example:9443/cb",
                false,
            ),
        ];
        for (reg, pre, want) in cases {
            assert_eq!(matches(reg, pre), want, "{reg} vs {pre}");
        }
    }

    #[test]
    fn loopback_uris_are_stored_normalised() {
        // A non-normal loopback spelling is stored normal, so it matches its normal forms and
        // the stored string is what matching compares.
        let stored = registered_form("http://localhost:1/a/../cb").unwrap();
        assert_eq!(stored, "http://localhost:1/cb");
        assert!(matches(&stored, "http://localhost:7/cb"));
        assert_eq!(
            registered_form("http://127.0.0.1:80/cb").unwrap(),
            "http://127.0.0.1/cb"
        );
        assert_eq!(
            registered_form("HTTP://[::1]:5/cb").unwrap(),
            "http://[::1]:5/cb"
        );
        // https URIs stay as given (exact match).
        assert_eq!(
            registered_form("https://a.example:443/cb").unwrap(),
            "https://a.example:443/cb"
        );
        assert!(registered_form("http://example.com/cb").is_none());
    }

    #[test]
    fn host_for_display() {
        assert_eq!(host_of("http://127.0.0.1:5/cb"), "127.0.0.1");
        assert_eq!(host_of("https://a.example/cb"), "a.example");
        assert_eq!(host_of("::"), "");
    }
}
