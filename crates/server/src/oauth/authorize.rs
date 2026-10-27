//! The authorization endpoint (PD-234, PD-237, PD-238, PD-241). Order of checks: the client is
//! known, then the redirect URI is registered and matches (until both hold, errors go to our own
//! error page, never to a URI we have not validated), then the browser session (else the login
//! page with `next`), then the remaining parameters (errors redirect to the validated URI with
//! `error`, `state`, `iss`), then a consent request bound to the session.

use url::Url;

use super::redirect::matches;
use super::{CONSENT_TTL_SECS, OAuth, SCOPES, random_b64, secret_hash};
use crate::store::{ConsentRequestRecord, OAuthClientRecord, ServerStore};

/// `state` is required and at most this long (bytes).
pub const MAX_STATE: usize = 512;
/// Our own error page (the consent page renders `?error=<code>`).
pub const ERROR_PAGE: &str = "/oauth/consent";

/// Where `GET /oauth/authorize` sends the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Our error page: the client or its redirect URI could not be validated.
    ErrorPage(&'static str),
    /// No session: the login page, coming back to this very URL.
    Login,
    /// The validated redirect URI with `error`, `state`, `iss`.
    ErrorRedirect(String),
    /// The consent page for the stored request.
    Consent(String),
}

/// The parameters, each at most once (a repeated parameter is `None`).
pub fn params(query: Option<&str>) -> Option<std::collections::HashMap<String, String>> {
    let mut out = std::collections::HashMap::new();
    for (k, v) in url::form_urlencoded::parse(query.unwrap_or("").as_bytes()) {
        if out.insert(k.into_owned(), v.into_owned()).is_some() {
            return None;
        }
    }
    Some(out)
}

/// `uri` with `pairs` appended to its query.
pub fn with_params(uri: &str, pairs: &[(&str, &str)]) -> String {
    match Url::parse(uri) {
        Ok(mut u) => {
            {
                let mut q = u.query_pairs_mut();
                for (k, v) in pairs {
                    q.append_pair(k, v);
                }
            }
            u.to_string()
        }
        Err(_) => ERROR_PAGE.to_owned(),
    }
}

/// PD-237: the resource after normalisation (lowercase scheme and host, no default port, no
/// trailing slash) must be the one resource; a fragment or query never matches.
pub fn resource_ok(o: &OAuth, raw: &str) -> bool {
    let Ok(u) = Url::parse(raw) else {
        return false;
    };
    if u.fragment().is_some() || u.query().is_some() || raw.contains('#') {
        return false;
    }
    u.as_str().trim_end_matches('/') == o.resource
}

/// The requested scopes: a space-separated subset of [`SCOPES`]; absent means `read`; `read` is
/// always added (PD-242). `None` for an unknown scope.
pub fn parse_scopes(raw: Option<&str>) -> Option<Vec<String>> {
    let mut out: Vec<String> = vec!["read".into()];
    for s in raw.unwrap_or("").split(' ').filter(|s| !s.is_empty()) {
        if !SCOPES.contains(&s) {
            return None;
        }
        if !out.iter().any(|x| x == s) {
            out.push(s.to_owned());
        }
    }
    out.sort_by_key(|s| SCOPES.iter().position(|x| x == s));
    Some(out)
}

/// A PKCE S256 challenge: 43 base64url characters.
pub fn challenge_ok(c: &str) -> bool {
    c.len() == 43
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The session's view of the request: its user and the hash of its id.
pub struct Browser<'a> {
    pub user_id: &'a str,
    pub session_hash: [u8; 32],
}

/// Validates an authorization request and stores its consent request.
pub fn authorize(
    o: &OAuth,
    store: &dyn ServerStore,
    query: Option<&str>,
    browser: Option<Browser<'_>>,
    now: i64,
) -> Outcome {
    let Some(p) = params(query) else {
        return Outcome::ErrorPage("invalid_request");
    };
    let client: OAuthClientRecord = match p.get("client_id").map(|id| store.oauth_client_get(id)) {
        Some(Ok(Some(c))) => c,
        Some(Err(_)) => return Outcome::ErrorPage("server_error"),
        _ => return Outcome::ErrorPage("invalid_client"),
    };
    let Some(redirect_uri) = p
        .get("redirect_uri")
        .filter(|r| client.redirect_uris.iter().any(|reg| matches(reg, r)))
    else {
        return Outcome::ErrorPage("invalid_redirect_uri");
    };
    let Some(browser) = browser else {
        return Outcome::Login;
    };
    let state = p.get("state").map(String::as_str);
    let fail = |error: &str| {
        let mut pairs = vec![("error", error)];
        if let Some(s) = state.filter(|s| s.len() <= MAX_STATE) {
            pairs.push(("state", s));
        }
        pairs.push(("iss", o.issuer.as_str()));
        Outcome::ErrorRedirect(with_params(redirect_uri, &pairs))
    };
    if p.get("response_type").map(String::as_str) != Some("code") {
        return fail("unsupported_response_type");
    }
    let Some(state) = state.filter(|s| !s.is_empty() && s.len() <= MAX_STATE) else {
        return fail("invalid_request");
    };
    let challenge = match (
        p.get("code_challenge"),
        p.get("code_challenge_method").map(String::as_str),
    ) {
        (Some(c), Some("S256")) if challenge_ok(c) => c.clone(),
        _ => return fail("invalid_request"),
    };
    if !p.get("resource").is_some_and(|r| resource_ok(o, r)) {
        return fail("invalid_target");
    }
    let Some(scopes) = parse_scopes(p.get("scope").map(String::as_str)) else {
        return fail("invalid_scope");
    };
    if !crate::users::is_active(store, browser.user_id) {
        return fail("access_denied");
    }
    let Some(id) = random_b64(32) else {
        return fail("server_error");
    };
    let rec = ConsentRequestRecord {
        id_hash: secret_hash("consent", &id),
        session_hash: browser.session_hash,
        user_id: browser.user_id.to_owned(),
        client_id: client.client_id,
        redirect_uri: redirect_uri.clone(),
        scopes,
        code_challenge: challenge,
        state: state.to_owned(),
        resource: o.resource.clone(),
        created_at: now,
        expires_at: now + CONSENT_TTL_SECS,
    };
    if store.consent_put(&rec).is_err() {
        return fail("server_error");
    }
    Outcome::Consent(format!("{ERROR_PAGE}?req={id}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::oauth::OAuthConfig;

    #[test]
    fn resource_normalisation() {
        let o = OAuth::new(
            OAuthConfig::DEFAULT,
            "https://duck.example.test",
            zeroize::Zeroizing::new([0; 32]),
        );
        for ok in [
            "https://duck.example.test/mcp",
            "https://DUCK.example.test/mcp",
            "HTTPS://duck.example.test:443/mcp",
            "https://duck.example.test/mcp/",
        ] {
            assert!(resource_ok(&o, ok), "{ok}");
        }
        for bad in [
            "https://duck.example.test",
            "https://duck.example.test/mcp#x",
            "https://duck.example.test/mcp?x=1",
            "https://duck.example.test:8443/mcp",
            "http://duck.example.test/mcp",
            "https://duck.example.test/MCP",
            "https://evil.example/mcp",
            "",
        ] {
            assert!(!resource_ok(&o, bad), "{bad}");
        }
    }

    #[test]
    fn scopes_and_params() {
        assert_eq!(parse_scopes(None).unwrap(), ["read"]);
        assert_eq!(
            parse_scopes(Some("scripts read")).unwrap(),
            ["read", "scripts"]
        );
        assert_eq!(
            parse_scopes(Some("propose_write")).unwrap(),
            ["read", "propose_write"]
        );
        assert_eq!(parse_scopes(Some("read admin")), None);
        assert!(params(Some("a=1&a=2")).is_none());
        assert_eq!(params(Some("a=1&b=x%20y")).unwrap()["b"], "x y");
        assert!(challenge_ok(&"a".repeat(43)));
        assert!(!challenge_ok(&"a".repeat(42)));
        assert!(!challenge_ok(&format!("{}=", "a".repeat(42))));
        assert_eq!(
            with_params(
                "http://127.0.0.1:5/cb?x=1",
                &[("code", "a b"), ("state", "s&t")]
            ),
            "http://127.0.0.1:5/cb?x=1&code=a+b&state=s%26t"
        );
    }
}
