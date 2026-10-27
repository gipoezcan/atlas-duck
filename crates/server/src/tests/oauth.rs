//! Unit checks of the OAuth helpers (token shapes and hashes, client names). The HTTP behaviour
//! is tested through the router in `web::tests::oauth` and in `tests/oauth_flow.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use secrecy::ExposeSecret;

use super::*;

#[test]
fn tokens_have_their_shape_and_distinct_hashes_per_kind() {
    let t = new_token(ACCESS_PREFIX).unwrap();
    let t = t.expose_secret();
    assert!(token_shape_ok(t, ACCESS_PREFIX), "{t}");
    assert!(!token_shape_ok(t, REFRESH_PREFIX));
    assert!(!token_shape_ok(&format!("{t}x"), ACCESS_PREFIX));
    assert!(!token_shape_ok("ado_at_short", ACCESS_PREFIX));
    assert!(!token_shape_ok(
        &format!("ado_at_{}", "+".repeat(43)),
        ACCESS_PREFIX
    ));
    assert_ne!(new_token(ACCESS_PREFIX).unwrap().expose_secret(), t);
    // The kind is part of the hash: the same string hashes differently per kind.
    assert_ne!(secret_hash("access", t), secret_hash("refresh", t));
    assert_eq!(secret_hash("access", t), secret_hash("access", t));
}

#[test]
fn client_names() {
    use register::valid_client_name;
    for ok in [
        "Claude Code",
        "VS Code – Copilot",
        "エージェント",
        &"x".repeat(64),
    ] {
        assert!(valid_client_name(ok), "{ok}");
    }
    for bad in [
        "",
        " lead",
        "trail ",
        "a\u{202e}b",
        "a\u{2066}b",
        "a\u{200f}b",
        "a\nb",
        "a\u{7f}b",
        &"x".repeat(65),
    ] {
        assert!(!valid_client_name(bad), "{bad:?}");
    }
}

#[test]
fn resource_and_metadata_url() {
    let o = OAuth::new(OAuthConfig::DEFAULT, "https://duck.example.test/");
    assert_eq!(o.issuer, "https://duck.example.test");
    assert_eq!(o.resource, "https://duck.example.test/mcp");
    assert_eq!(
        o.resource_metadata_url(),
        "https://duck.example.test/.well-known/oauth-protected-resource/mcp"
    );
}
