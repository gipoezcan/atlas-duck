//! OAuth through the in-process router (M14 T6–T8): discovery documents, dynamic registration,
//! authorization and consent, tokens, revocation and the bearer check of `/mcp`.

use super::*;
use crate::oauth::OAuthConfig;
use crate::store::OAuthClientRecord;

fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

fn register_req(body: &Value, ip: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/oauth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", ip)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn loopback_client() -> Value {
    json!({
        "client_name": "Claude Code",
        "redirect_uris": ["http://127.0.0.1:33418/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    })
}

impl H {
    async fn register(&self, body: &Value, ip: &str) -> (StatusCode, Value, Response) {
        let res = self.send(register_req(body, ip)).await;
        let status = res.status();
        let headers = res.headers().clone();
        let v = json_body(res).await;
        let mut keep = Response::new(Body::empty());
        *keep.headers_mut() = headers;
        (status, v, keep)
    }
}

// ---- T6: discovery ----------------------------------------------------------------------------

#[tokio::test]
async fn metadata_documents_are_exact() {
    let h = H::new();
    let want_prm = json!({
        "resource": "https://duck.example.test/mcp",
        "authorization_servers": ["https://duck.example.test"],
        "scopes_supported": ["read", "propose_write", "scripts"],
        "bearer_methods_supported": ["header"],
        "resource_name": "atlas-duck",
    });
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let res = h.send(get(path)).await;
        assert_eq!(res.status(), StatusCode::OK, "{path}");
        assert_eq!(res.headers()[header::CACHE_CONTROL], "max-age=300");
        assert_eq!(json_body(res).await, want_prm, "{path}");
    }
    let res = h.send(get("/.well-known/oauth-authorization-server")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "max-age=300");
    let doc = json_body(res).await;
    assert_eq!(
        doc,
        json!({
            "issuer": "https://duck.example.test",
            "authorization_endpoint": "https://duck.example.test/oauth/authorize",
            "token_endpoint": "https://duck.example.test/oauth/token",
            "registration_endpoint": "https://duck.example.test/oauth/register",
            "revocation_endpoint": "https://duck.example.test/oauth/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["read", "propose_write", "scripts"],
            "authorization_response_iss_parameter_supported": true,
        })
    );
    // RFC 8414 §3.3: the issuer is the URL the document was fetched under minus the suffix.
    let fetched = format!("{ORIGIN}/.well-known/oauth-authorization-server");
    assert_eq!(
        Some(doc["issuer"].as_str().unwrap()),
        fetched.strip_suffix("/.well-known/oauth-authorization-server")
    );
    // No Client ID Metadata Document support is advertised (L241).
    assert!(doc.get("client_id_metadata_document_supported").is_none());
}

#[tokio::test]
async fn disabled_oauth_answers_404_everywhere() {
    let h = H::with_oauth(OAuthConfig {
        enabled: false,
        ..OAuthConfig::DEFAULT
    });
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-authorization-server",
    ] {
        let res = h.send(get(path)).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(json_body(res).await["error"]["code"], "oauth/disabled");
    }
    let (s, v, _) = h.register(&loopback_client(), "192.0.2.1").await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("oauth/disabled"))
    );
    assert_eq!(h.store.oauth_client_count().unwrap(), 0);
}

// ---- T6: registration -------------------------------------------------------------------------

#[tokio::test]
async fn registration_of_a_loopback_and_an_https_client() {
    let h = H::new();
    let (s, v, res) = h.register(&loopback_client(), "192.0.2.1").await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    let id = v["client_id"].as_str().unwrap();
    assert!(id.starts_with("adc_") && id.len() == 4 + 22, "{id}");
    assert_eq!(v["client_id_issued_at"], T0);
    assert_eq!(v["token_endpoint_auth_method"], "none");
    assert_eq!(
        v["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(v["response_types"], json!(["code"]));
    assert!(v.get("client_secret").is_none() && v.get("registration_access_token").is_none());
    let rec = h.store.oauth_client_get(id).unwrap().unwrap();
    assert_eq!(rec.name, "Claude Code");
    assert_eq!(rec.redirect_uris, ["http://127.0.0.1:33418/callback"]);
    // The IP is kept hashed only, in the store and in the anchor row.
    assert_eq!(
        rec.source_ip_hash,
        crate::oauth::register::ip_hash("192.0.2.1")
    );
    let row = h.store.anchor_last().unwrap().unwrap();
    assert_eq!(row.kind, "OAUTH_CLIENT_REGISTERED");
    let body = String::from_utf8(row.body_jcs).unwrap();
    assert!(body.contains(id) && body.contains("127.0.0.1"), "{body}");
    assert!(!body.contains("192.0.2.1"), "{body}");

    // An https client; client_uri is ignored, not refused.
    let (s, v, _) = h
        .register(
            &json!({"client_name": "Web agent", "redirect_uris": ["https://agent.example/cb"],
                    "client_uri": "https://agent.example", "software_id": "x"}),
            "192.0.2.1",
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    // Absent grant_types: authorization_code only.
    assert_eq!(v["grant_types"], json!(["authorization_code"]));
}

#[tokio::test]
async fn registration_refusals() {
    let h = H::new();
    let with = |k: &str, v: Value| {
        let mut c = loopback_client();
        c[k] = v;
        c
    };
    let six: Vec<String> = (0..6).map(|i| format!("http://127.0.0.1/cb{i}")).collect();
    let cases = [
        (
            with("redirect_uris", json!(["http://example.com/cb"])),
            "invalid_redirect_uri",
        ),
        (
            with("redirect_uris", json!(["myapp://cb"])),
            "invalid_redirect_uri",
        ),
        (
            with("redirect_uris", json!(["https://a.example/cb#x"])),
            "invalid_redirect_uri",
        ),
        (with("redirect_uris", json!(six)), "invalid_redirect_uri"),
        (with("redirect_uris", json!([])), "invalid_redirect_uri"),
        (
            with("redirect_uris", json!("http://127.0.0.1/cb")),
            "invalid_redirect_uri",
        ),
        (
            with("token_endpoint_auth_method", json!("client_secret_basic")),
            "invalid_client_metadata",
        ),
        (
            with("grant_types", json!(["implicit"])),
            "invalid_client_metadata",
        ),
        (
            with("grant_types", json!(["refresh_token"])),
            "invalid_client_metadata",
        ),
        (
            with("grant_types", json!(["authorization_code", "password"])),
            "invalid_client_metadata",
        ),
        (
            with("response_types", json!(["token"])),
            "invalid_client_metadata",
        ),
        (
            with("client_name", json!("evil\u{202e}gpj.exe")),
            "invalid_client_metadata",
        ),
        (
            with("client_name", json!("tab\tname")),
            "invalid_client_metadata",
        ),
        (with("client_name", json!("")), "invalid_client_metadata"),
        (
            with("client_name", json!("x".repeat(65))),
            "invalid_client_metadata",
        ),
        (
            with("logo_uri", json!("https://evil.example/logo.png")),
            "invalid_client_metadata",
        ),
        (
            with("jwks_uri", json!("https://evil.example/jwks")),
            "invalid_client_metadata",
        ),
        (
            with("contacts", json!(["a@b.c"])),
            "invalid_client_metadata",
        ),
    ];
    for (body, want) in cases {
        let (s, v, res) = h.register(&body, "192.0.2.1").await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body} -> {v}");
        assert_eq!(v["error"], want, "{body}");
        assert!(v["error_description"].is_string());
        assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    }
    // Not JSON, and a body over 16 KiB.
    let res = h
        .send(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/register")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let mut big = loopback_client();
    big["software_version"] = json!("x".repeat(17 * 1024));
    let (s, _, _) = h.register(&big, "192.0.2.1").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(h.store.oauth_client_count().unwrap(), 0);
}

#[tokio::test]
async fn registration_rate_limit_per_ip() {
    let h = H::new();
    for i in 0..10 {
        let (s, v, _) = h.register(&loopback_client(), "192.0.2.7").await;
        assert_eq!(s, StatusCode::CREATED, "{i}: {v}");
    }
    let (s, v, res) = h.register(&loopback_client(), "192.0.2.7").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    let retry: u64 = res.headers()[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=3600).contains(&retry), "{retry}");
    // Another IP is not limited; an hour later the first is free again.
    let (s, _, _) = h.register(&loopback_client(), "192.0.2.8").await;
    assert_eq!(s, StatusCode::CREATED);
    h.clock.advance(3600);
    let (s, _, _) = h.register(&loopback_client(), "192.0.2.7").await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn registration_cap_purges_then_refuses() {
    let fill = |id: String, created_at: i64| OAuthClientRecord {
        client_id: id,
        name: "n".into(),
        redirect_uris: vec!["http://127.0.0.1/cb".into()],
        created_at,
        source_ip_hash: String::new(),
    };
    let capped = || {
        H::with_oauth(OAuthConfig {
            max_clients: 10,
            ..OAuthConfig::DEFAULT
        })
    };
    // Ten clients an hour old: nothing is purgeable, the registration is refused.
    let h = capped();
    for i in 0..10 {
        h.store
            .oauth_client_insert(&fill(format!("adc_fresh{i}"), T0 - 3600))
            .unwrap();
    }
    let (s, v, res) = h.register(&loopback_client(), "192.0.2.1").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    assert!(res.headers().contains_key(header::RETRY_AFTER));
    assert_eq!(h.store.oauth_client_count().unwrap(), 10);
    // One of ten is 25 h old without a grant: purged, and the registration fits.
    let h = capped();
    for i in 0..9 {
        h.store
            .oauth_client_insert(&fill(format!("adc_fresh{i}"), T0 - 3600))
            .unwrap();
    }
    h.store
        .oauth_client_insert(&fill("adc_old".into(), T0 - 25 * 3600))
        .unwrap();
    let (s, v, _) = h.register(&loopback_client(), "192.0.2.1").await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert!(h.store.oauth_client_get("adc_old").unwrap().is_none());
    assert!(h.store.oauth_client_get("adc_fresh0").unwrap().is_some());
    assert_eq!(h.store.oauth_client_count().unwrap(), 10);
}
