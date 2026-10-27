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
    assert_eq!(rec.source_ip_hash, h.state.0.oauth.ip_hash("192.0.2.1"));
    // Keyed (batch-1 review M1): not the plain SHA-256 an enumeration of addresses would find,
    // and the HMAC under the master key's derived purpose key.
    use sha2::Digest;
    assert_ne!(
        rec.source_ip_hash,
        hex::encode(sha2::Sha256::digest(b"192.0.2.1"))
    );
    let key = MasterKey::for_tests("k1", [5; 32]).derive(crate::oauth::IP_KEY_LABEL);
    assert_eq!(
        rec.source_ip_hash,
        hex::encode(crate::master_key::hmac_sha256(&key, b"192.0.2.1"))
    );
    let other = MasterKey::for_tests("k2", [6; 32]).derive(crate::oauth::IP_KEY_LABEL);
    assert_ne!(
        rec.source_ip_hash,
        hex::encode(crate::master_key::hmac_sha256(&other, b"192.0.2.1"))
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

// ---- T7: authorization and consent ------------------------------------------------------------

/// RFC 7636 appendix B.
pub(super) const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
pub(super) const RESOURCE: &str = "https://duck.example.test/mcp";
const STATE: &str = "st a&b=c/\u{e9}~";

/// The query of an authorization request; `over` replaces or (with "") drops parameters.
pub(super) fn authz_query(client_id: &str, over: &[(&str, &str)]) -> String {
    let mut p: Vec<(String, String)> = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", "http://127.0.0.1:51000/callback"),
        ("scope", "read scripts"),
        ("state", STATE),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("resource", RESOURCE),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    for (k, v) in over {
        p.retain(|(x, _)| x != k);
        if !v.is_empty() {
            p.push(((*k).to_owned(), (*v).to_owned()));
        }
    }
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(p)
        .finish()
}

pub(super) fn cookie_header(cookie: &str) -> String {
    format!("__Host-atlas_duck_session={cookie}")
}

pub(super) fn location(res: &Response) -> String {
    res.headers()[header::LOCATION].to_str().unwrap().to_owned()
}

pub(super) fn query_of(uri: &str) -> std::collections::HashMap<String, String> {
    let u = url::Url::parse(uri).unwrap();
    u.query_pairs().into_owned().collect()
}

impl H {
    pub(super) async fn client_id(&self) -> String {
        let (s, v, _) = self.register(&loopback_client(), "192.0.2.1").await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        v["client_id"].as_str().unwrap().to_owned()
    }

    pub(super) async fn authorize(&self, cookie: Option<&str>, query: &str) -> Response {
        let mut b = Request::builder().uri(format!("/oauth/authorize?{query}"));
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, cookie_header(c));
        }
        self.send(b.body(Body::empty()).unwrap()).await
    }

    /// Authorizes and answers the consent request id.
    pub(super) async fn consent_req(&self, cookie: &str, query: &str) -> String {
        let res = self.authorize(Some(cookie), query).await;
        assert_eq!(res.status(), StatusCode::FOUND);
        let loc = location(&res);
        loc.strip_prefix("/oauth/consent?req=")
            .unwrap_or_else(|| panic!("not a consent redirect: {loc}"))
            .to_owned()
    }

    pub(super) async fn consent_get(&self, cookie: &str, req: &str) -> (StatusCode, Value) {
        let res = self
            .send(
                Request::builder()
                    .uri(format!("/api/oauth/consent/{req}"))
                    .header(header::COOKIE, cookie_header(cookie))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        let s = res.status();
        (s, json_body(res).await)
    }

    pub(super) async fn consent_post_with(
        &self,
        cookie: &str,
        csrf: Option<&str>,
        req: &str,
        body: Value,
        extra: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/oauth/consent/{req}"))
            .header(header::COOKIE, cookie_header(cookie))
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(c) = csrf {
            b = b.header("x-csrf-token", c);
        }
        for (k, v) in extra {
            b = b.header(*k, *v);
        }
        let res = self
            .send(b.body(Body::from(body.to_string())).unwrap())
            .await;
        let s = res.status();
        (s, json_body(res).await)
    }

    pub(super) async fn consent_post(
        &self,
        (cookie, csrf): &(String, String),
        req: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        self.consent_post_with(cookie, Some(csrf), req, body, &[])
            .await
    }

    /// The whole browser leg: authorize, allow `scopes`, answer the redirect's parameters.
    pub(super) async fn code_for(
        &self,
        sess: &(String, String),
        client_id: &str,
        scopes: &[&str],
    ) -> std::collections::HashMap<String, String> {
        let req = self
            .consent_req(&sess.0, &authz_query(client_id, &[]))
            .await;
        let (s, v) = self
            .consent_post(sess, &req, json!({"decision": "allow", "scopes": scopes}))
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        query_of(v["redirect"].as_str().unwrap())
    }
}

#[tokio::test]
async fn authorization_happy_path_to_a_code() {
    let h = H::new();
    let client = h.client_id().await;
    let (cookie, csrf) = h.session("alice", PW_CANARY).await;
    let req = h.consent_req(&cookie, &authz_query(&client, &[])).await;
    let (s, d) = h.consent_get(&cookie, &req).await;
    assert_eq!(s, StatusCode::OK, "{d}");
    assert_eq!(d["client_name"], "Claude Code");
    assert_eq!(d["client_id"], client.as_str());
    assert_eq!(d["redirect_host"], "127.0.0.1");
    assert_eq!(d["redirect_uri"], "http://127.0.0.1:51000/callback");
    assert_eq!(
        d["scopes"],
        json!([
            {"name": "read", "text": "Read Jira and Confluence data you can read, after you release it."},
            {"name": "scripts", "text": "Run read-only scripts in the sandbox; you approve each final result."},
        ])
    );
    // Allow with `scripts` dropped: the grant holds `read` only.
    let (s, v) = h
        .consent_post(
            &(cookie.clone(), csrf),
            &req,
            json!({"decision": "allow", "scopes": ["read"]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let redirect = v["redirect"].as_str().unwrap();
    assert!(
        redirect.starts_with("http://127.0.0.1:51000/callback?"),
        "{redirect}"
    );
    let q = query_of(redirect);
    assert!(q["code"].starts_with("ado_ac_") && q["code"].len() == 7 + 43);
    // `state` comes back byte for byte; `iss` names the issuer (RFC 9207).
    assert_eq!(q["state"], STATE);
    assert_eq!(q["iss"], ORIGIN);
    let uid = user_id_for("alice");
    let grants = h.store.grant_list(&uid).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].scopes, ["read"]);
    assert_eq!(grants[0].resource, RESOURCE);
    assert_eq!(grants[0].expires_at, T0 + 90 * 86_400);
    // The code is stored by hash only.
    let hash = crate::oauth::secret_hash("code", &q["code"]);
    let (code, grant) = h.store.code_redeem(&hash, T0).unwrap();
    assert_eq!(grant.grant_id, grants[0].grant_id);
    assert_eq!(code.code_challenge, CHALLENGE);
    // OAUTH_GRANT_CREATED is in alice's chain.
    let rt = h
        .registry
        .runtime(&UserCtxT::from_authenticated(&uid))
        .await
        .unwrap();
    let page = rt
        .audit_store()
        .query(
            &atlas_duck_audit::types::AuditFilter::default(),
            atlas_duck_audit::types::AuditCursor::first(100),
        )
        .unwrap();
    assert!(
        page.rows
            .iter()
            .any(|r| r.event_type == atlas_duck_audit::EventType::OAUTH_GRANT_CREATED)
    );
    // The request is consumed.
    assert_eq!(h.consent_get(&cookie, &req).await.0, StatusCode::NOT_FOUND);
}

use crate::clock::Clock as _;
use crate::runtime::UserCtx as UserCtxT;

#[tokio::test]
async fn without_a_session_the_login_page_comes_back_to_the_same_url() {
    let h = H::new();
    let client = h.client_id().await;
    let query = authz_query(&client, &[]);
    let res = h.authorize(None, &query).await;
    assert_eq!(res.status(), StatusCode::FOUND);
    let loc = location(&res);
    let encoded: String =
        url::form_urlencoded::byte_serialize(format!("/oauth/authorize?{query}").as_bytes())
            .collect();
    assert_eq!(loc, format!("/login?next={encoded}"));
    assert!(loc.starts_with("/login?next=%2Foauth%2Fauthorize%3F"));
    // After login the decoded `next` continues to consent.
    let next: String = url::form_urlencoded::parse(loc.trim_start_matches("/login?").as_bytes())
        .find(|(k, _)| k == "next")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let (cookie, _) = h.session("alice", PW_CANARY).await;
    let res = h
        .send(
            Request::builder()
                .uri(next)
                .header(header::COOKIE, cookie_header(&cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(location(&res).starts_with("/oauth/consent?req="));
}

#[tokio::test]
async fn unvalidated_clients_and_redirects_never_get_a_redirect() {
    let h = H::new();
    let client = h.client_id().await;
    let (cookie, _) = h.session("alice", PW_CANARY).await;
    for (query, want) in [
        (
            authz_query(
                "adc_unknownclient000000",
                &[("redirect_uri", "https://evil.example/cb")],
            ),
            "/oauth/consent?error=invalid_client",
        ),
        (
            authz_query(&client, &[("redirect_uri", "https://evil.example/cb")]),
            "/oauth/consent?error=invalid_redirect_uri",
        ),
        (
            authz_query(
                &client,
                &[("redirect_uri", "http://localhost:51000/callback")],
            ),
            "/oauth/consent?error=invalid_redirect_uri",
        ),
        (
            authz_query(&client, &[("redirect_uri", "")]),
            "/oauth/consent?error=invalid_redirect_uri",
        ),
        (
            format!("{}&client_id={client}", authz_query(&client, &[])),
            "/oauth/consent?error=invalid_request",
        ),
    ] {
        for cookie in [None, Some(cookie.as_str())] {
            let res = h.authorize(cookie, &query).await;
            assert_eq!(res.status(), StatusCode::FOUND);
            let loc = location(&res);
            assert_eq!(loc, want, "{query}");
            assert!(!loc.contains("evil") && !loc.contains("127.0.0.1"));
        }
    }
}

#[tokio::test]
async fn parameter_errors_redirect_with_state_and_iss() {
    let h = H::new();
    let client = h.client_id().await;
    let (cookie, _) = h.session("alice", PW_CANARY).await;
    for (over, want) in [
        (vec![("code_challenge", "")], "invalid_request"),
        (vec![("code_challenge_method", "plain")], "invalid_request"),
        (vec![("code_challenge_method", "")], "invalid_request"),
        (vec![("code_challenge", "short")], "invalid_request"),
        (vec![("resource", "")], "invalid_target"),
        (
            vec![("resource", "https://other.example/mcp")],
            "invalid_target",
        ),
        (vec![("scope", "read admin")], "invalid_scope"),
        (
            vec![("response_type", "token")],
            "unsupported_response_type",
        ),
    ] {
        let res = h
            .authorize(Some(&cookie), &authz_query(&client, &over))
            .await;
        let loc = location(&res);
        assert!(loc.starts_with("http://127.0.0.1:51000/callback?"), "{loc}");
        let q = query_of(&loc);
        assert_eq!(q["error"], want, "{over:?}");
        assert_eq!(q["state"], STATE);
        assert_eq!(q["iss"], ORIGIN);
        assert!(!q.contains_key("code"));
    }
    // A missing state: invalid_request without a state.
    let res = h
        .authorize(Some(&cookie), &authz_query(&client, &[("state", "")]))
        .await;
    let q = query_of(&location(&res));
    assert_eq!(q["error"], "invalid_request");
    assert!(!q.contains_key("state"));
    assert!(
        h.store
            .grant_list(&user_id_for("alice"))
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn consent_is_bound_to_its_session_and_guarded() {
    let h = H::new();
    let client = h.client_id().await;
    let alice = h.session("alice", PW_CANARY).await;
    let alice2 = h.session("alice", PW_CANARY).await;
    let bob = h.session("bob", "pw-bob").await;
    let req = h.consent_req(&alice.0, &authz_query(&client, &[])).await;
    // Another session, even the same user's, sees and decides nothing.
    for other in [&alice2, &bob] {
        assert_eq!(h.consent_get(&other.0, &req).await.0, StatusCode::NOT_FOUND);
        let (s, v) = h
            .consent_post(other, &req, json!({"decision": "allow"}))
            .await;
        assert_eq!(
            (s, v["error"]["code"].as_str()),
            (StatusCode::NOT_FOUND, Some("oauth/request_unknown"))
        );
    }
    // No CSRF token, a bearer, a foreign Origin: refused by the guard.
    let (s, v) = h
        .consent_post_with(&alice.0, None, &req, json!({"decision": "allow"}), &[])
        .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("auth/csrf_mismatch"))
    );
    let (s, v) = h
        .consent_post_with(
            &alice.0,
            Some(&alice.1),
            &req,
            json!({"decision": "allow"}),
            &[(
                "authorization",
                "Bearer ado_at_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            )],
        )
        .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("auth/bearer_not_accepted"))
    );
    let res = h
        .send(
            Request::builder()
                .uri(format!("/api/oauth/consent/{req}"))
                .header(header::COOKIE, cookie_header(&alice.0))
                .header(header::AUTHORIZATION, "Bearer adk_x")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    // Adding a scope that was not requested is refused; the request survives a refused body?
    // No: a decision consumes it, so use a fresh request for the add-scope probe.
    let req2 = h
        .consent_req(&alice.0, &authz_query(&client, &[("scope", "read")]))
        .await;
    let (s, _) = h
        .consent_post(
            &alice,
            &req2,
            json!({"decision": "allow", "scopes": ["read", "propose_write"]}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // The original request still works for its own session.
    let (s, v) = h
        .consent_post(
            &alice,
            &req,
            json!({"decision": "allow", "scopes": ["scripts"]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let grants = h.store.grant_list(&user_id_for("alice")).unwrap();
    assert_eq!(grants[0].scopes, ["read", "scripts"]);
}

#[tokio::test]
async fn deny_expiry_and_re_consent() {
    let h = H::new();
    let client = h.client_id().await;
    let alice = h.session("alice", PW_CANARY).await;
    // Deny: access_denied, the request is consumed, no grant.
    let req = h.consent_req(&alice.0, &authz_query(&client, &[])).await;
    let (s, v) = h
        .consent_post(&alice, &req, json!({"decision": "deny"}))
        .await;
    assert_eq!(s, StatusCode::OK);
    let q = query_of(v["redirect"].as_str().unwrap());
    assert_eq!(
        (q["error"].as_str(), q["state"].as_str()),
        ("access_denied", STATE)
    );
    assert!(!q.contains_key("code"));
    assert_eq!(
        h.consent_post(&alice, &req, json!({"decision": "deny"}))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert!(
        h.store
            .grant_list(&user_id_for("alice"))
            .unwrap()
            .is_empty()
    );
    // Older than 10 minutes: 410.
    let req = h.consent_req(&alice.0, &authz_query(&client, &[])).await;
    h.clock.advance(601);
    let (s, v) = h.consent_get(&alice.0, &req).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::GONE, Some("oauth/request_expired"))
    );
    let (s, _) = h
        .consent_post(&alice, &req, json!({"decision": "allow"}))
        .await;
    assert_eq!(s, StatusCode::GONE);
    // A second consent for the same client replaces the first grant.
    h.code_for(&alice, &client, &["read"]).await;
    h.code_for(&alice, &client, &["read"]).await;
    let grants = h.store.grant_list(&user_id_for("alice")).unwrap();
    assert_eq!(grants.len(), 2);
    let live: Vec<_> = grants.iter().filter(|g| g.live(h.clock.now())).collect();
    assert_eq!(live.len(), 1);
    let old = grants.iter().find(|g| !g.live(h.clock.now())).unwrap();
    assert_eq!(old.revoke_reason.as_deref(), Some("replaced"));
}

// ---- T8: token, revocation, bearer --------------------------------------------------------------

pub(super) const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const MCP_INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}"#;

fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

impl H {
    pub(super) async fn post_form(
        &self,
        path: &str,
        pairs: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let res = self
            .send(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("x-forwarded-for", "192.0.2.50")
                    .body(Body::from(form(pairs)))
                    .unwrap(),
            )
            .await;
        let s = res.status();
        if s == StatusCode::OK || s.is_client_error() {
            assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store", "{path}");
        }
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        (s, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    pub(super) async fn redeem(&self, client: &str, code: &str) -> (StatusCode, Value) {
        self.post_form(
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", "http://127.0.0.1:51000/callback"),
                ("client_id", client),
                ("code_verifier", VERIFIER),
                ("resource", RESOURCE),
            ],
        )
        .await
    }

    pub(super) async fn refresh(
        &self,
        client: &str,
        rt: &str,
        scope: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut p = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", client),
            ("resource", RESOURCE),
        ];
        if let Some(s) = scope {
            p.push(("scope", s));
        }
        self.post_form("/oauth/token", &p).await
    }

    /// `initialize` at `/mcp` with `bearer`; answers the response.
    pub(super) async fn mcp_init(&self, bearer: &str, session: Option<&str>) -> Response {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::HOST, "duck.example.test")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        if let Some(s) = session {
            b = b.header("mcp-session-id", s);
        }
        self.send(b.body(Body::from(MCP_INIT)).unwrap()).await
    }

    /// A client, alice's consent for `scopes`, and the redeemed token pair.
    pub(super) async fn tokens_for(&self, scopes: &[&str]) -> (String, (String, String), Value) {
        let client = self.client_id().await;
        let alice = self.session("alice", PW_CANARY).await;
        let q = self.code_for(&alice, &client, scopes).await;
        let (s, v) = self.redeem(&client, &q["code"]).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        (client, alice, v)
    }

    pub(super) fn chain_kinds(
        &self,
        rt: &crate::runtime::UserRuntime,
    ) -> Vec<(atlas_duck_audit::EventType, Value)> {
        let page = rt
            .audit_store()
            .query(
                &atlas_duck_audit::types::AuditFilter::default(),
                atlas_duck_audit::types::AuditCursor::first(500),
            )
            .unwrap();
        page.rows
            .iter()
            .map(|r| {
                let p = rt
                    .audit_store()
                    .payload_view(r.seq, 0)
                    .ok()
                    .and_then(|v| serde_json::from_slice::<Value>(&v.bytes).ok())
                    .unwrap_or(Value::Null);
                (r.event_type, p)
            })
            .collect()
    }

    pub(super) async fn alice_chain(&self) -> Vec<(atlas_duck_audit::EventType, Value)> {
        let rt = self
            .registry
            .runtime(&UserCtxT::from_authenticated(&user_id_for("alice")))
            .await
            .unwrap();
        self.chain_kinds(&rt)
    }

    fn anchor_kinds(&self) -> Vec<String> {
        self.store
            .anchor_all()
            .unwrap()
            .into_iter()
            .map(|r| r.kind)
            .collect()
    }
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or_default().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn code_for_tokens_and_the_access_token_opens_mcp() {
    let h = H::new();
    let (_, _, v) = h.tokens_for(&["read", "scripts"]).await;
    assert!(s(&v, "access_token").starts_with("ado_at_"));
    assert!(s(&v, "refresh_token").starts_with("ado_rt_"));
    assert_eq!(v["token_type"], "Bearer");
    assert_eq!(v["expires_in"], 900);
    assert_eq!(v["scope"], "read scripts");
    let res = h.mcp_init(&s(&v, "access_token"), None).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers().contains_key("mcp-session-id"));
    // Only hashes are stored.
    let db = h.db_bytes();
    for t in [s(&v, "access_token"), s(&v, "refresh_token")] {
        assert!(
            !db.windows(t.len()).any(|w| w == t.as_bytes()),
            "token in server.db"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_redemption_revokes_the_grant_and_its_tokens() {
    let h = H::new();
    let client = h.client_id().await;
    let alice = h.session("alice", PW_CANARY).await;
    let q = h.code_for(&alice, &client, &["read"]).await;
    let (st, v) = h.redeem(&client, &q["code"]).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let access = s(&v, "access_token");
    assert_eq!(h.mcp_init(&access, None).await.status(), StatusCode::OK);
    let (st, e) = h.redeem(&client, &q["code"]).await;
    assert_eq!(
        (st, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    // The tokens of the first redemption are dead at once.
    let res = h.mcp_init(&access, None).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let (st, e) = h.refresh(&client, &s(&v, "refresh_token"), None).await;
    assert_eq!(
        (st, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    let g = &h.store.grant_list(&user_id_for("alice")).unwrap()[0];
    assert_eq!(g.revoke_reason.as_deref(), Some("code_reuse"));
    let chain = h.alice_chain().await;
    assert!(
        chain.iter().any(
            |(k, p)| *k == atlas_duck_audit::EventType::OAUTH_GRANT_REVOKED
                && p.to_string().contains("reuse_detected")
        ),
        "{chain:?}"
    );
    assert!(h.anchor_kinds().contains(&"OAUTH_REUSE".to_owned()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redemption_refusals() {
    let h = H::new();
    let client = h.client_id().await;
    let other = h.client_id().await;
    let alice = h.session("alice", PW_CANARY).await;
    let redeem_with = |code: String, over: Vec<(&'static str, String)>| {
        let client = client.clone();
        async move {
            let mut p: Vec<(String, String)> = vec![
                ("grant_type".into(), "authorization_code".into()),
                ("code".into(), code),
                (
                    "redirect_uri".into(),
                    "http://127.0.0.1:51000/callback".into(),
                ),
                ("client_id".into(), client),
                ("code_verifier".into(), VERIFIER.into()),
                ("resource".into(), RESOURCE.into()),
            ];
            for (k, v) in over {
                p.retain(|(x, _)| x != k);
                p.push((k.into(), v));
            }
            p
        }
    };
    // A wrong verifier burns the code: the right one afterwards is refused too.
    let code = h.code_for(&alice, &client, &["read"]).await["code"].clone();
    let p = redeem_with(code.clone(), vec![("code_verifier", "x".repeat(43))]).await;
    let refs: Vec<(&str, &str)> = p.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let (st, e) = h.post_form("/oauth/token", &refs).await;
    assert_eq!(
        (st, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    let (st, _) = h.redeem(&client, &code).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    for (over, status, want) in [
        (
            vec![("redirect_uri", "http://127.0.0.1:51001/callback".to_owned())],
            400,
            "invalid_grant",
        ),
        (vec![("client_id", other.clone())], 400, "invalid_grant"),
        (
            vec![("client_id", "adc_nobody00000000000000".to_owned())],
            401,
            "invalid_client",
        ),
        (
            vec![("resource", "https://evil.example/mcp".to_owned())],
            400,
            "invalid_target",
        ),
        (
            vec![("code_verifier", String::new())],
            400,
            "invalid_request",
        ),
        (
            vec![("grant_type", "password".to_owned())],
            400,
            "unsupported_grant_type",
        ),
        (vec![("grant_type", String::new())], 400, "invalid_request"),
    ] {
        let code = h.code_for(&alice, &client, &["read"]).await["code"].clone();
        let p = redeem_with(code, over.clone()).await;
        let refs: Vec<(&str, &str)> = p.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let (st, e) = h.post_form("/oauth/token", &refs).await;
        assert_eq!(
            (st.as_u16(), e["error"].as_str()),
            (status, Some(want)),
            "{over:?}"
        );
        assert!(e.get("access_token").is_none());
    }
    // A plain-method client presenting the challenge as verifier gets nothing.
    let code = h.code_for(&alice, &client, &["read"]).await["code"].clone();
    let p = redeem_with(code, vec![("code_verifier", CHALLENGE.to_owned())]).await;
    let refs: Vec<(&str, &str)> = p.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    assert_eq!(
        h.post_form("/oauth/token", &refs).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_rotates_and_a_reused_refresh_token_revokes_the_grant() {
    let h = H::new();
    let (client, _, v) = h.tokens_for(&["read", "scripts"]).await;
    let rt1 = s(&v, "refresh_token");
    // A broader scope is refused before the token is spent; a narrower one is honoured.
    let (st, e) = h.refresh(&client, &rt1, Some("read propose_write")).await;
    assert_eq!(
        (st, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_scope"))
    );
    let (st, e) = h
        .post_form(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &rt1),
                ("client_id", &client),
                ("resource", "https://duck.example.test/other"),
            ],
        )
        .await;
    assert_eq!(
        (st, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_target"))
    );
    let (st, v2) = h.refresh(&client, &rt1, Some("read")).await;
    assert_eq!(st, StatusCode::OK, "{v2}");
    assert_eq!(v2["scope"], "read");
    let rt2 = s(&v2, "refresh_token");
    assert_ne!(rt1, rt2);
    // Final review m2: a refresh without `resource` gets the grant's resource.
    let (st, v3) = h
        .post_form(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &rt2),
                ("client_id", &client),
            ],
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v3}");
    assert_eq!(
        h.mcp_init(&s(&v3, "access_token"), None).await.status(),
        StatusCode::OK
    );
    let rt2 = s(&v3, "refresh_token");
    // The old access token stays valid until its expiry; the new one works.
    assert_eq!(
        h.mcp_init(&s(&v, "access_token"), None).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        h.mcp_init(&s(&v2, "access_token"), None).await.status(),
        StatusCode::OK
    );
    // Reusing rt1: invalid_grant, the whole grant revoked, every token dead.
    let (st, e) = h.refresh(&client, &rt1, None).await;
    assert_eq!(
        (st, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    for t in [s(&v, "access_token"), s(&v2, "access_token")] {
        assert_eq!(
            h.mcp_init(&t, None).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        h.refresh(&client, &rt2, None).await.0,
        StatusCode::BAD_REQUEST
    );
    let g = &h.store.grant_list(&user_id_for("alice")).unwrap()[0];
    assert_eq!(g.revoke_reason.as_deref(), Some("refresh_reuse"));
    let chain = h.alice_chain().await;
    assert!(chain.iter().any(
        |(k, p)| *k == atlas_duck_audit::EventType::OAUTH_GRANT_REVOKED
            && p.to_string().contains("reuse_detected")
    ));
    assert_eq!(
        h.anchor_kinds()
            .iter()
            .filter(|k| *k == "OAUTH_REUSE")
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_access_token_is_401_and_recorded() {
    let h = H::new();
    let (_, _, v) = h.tokens_for(&["read"]).await;
    h.clock.advance(900);
    let res = h.mcp_init(&s(&v, "access_token"), None).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let www = res.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(www.contains("resource_metadata=\"https://duck.example.test/.well-known/oauth-protected-resource/mcp\""), "{www}");
    assert!(www.ends_with("error=\"invalid_token\""), "{www}");
    let chain = h.alice_chain().await;
    assert!(
        chain
            .iter()
            .any(|(k, p)| *k == atlas_duck_audit::EventType::LOGIN
                && p.to_string().contains("\"oauth\"")
                && p.to_string().contains("\"expired\"")),
        "{chain:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_token_endpoint_refuses_a_user_who_is_not_active() {
    let h = H::new();
    let (client, alice, v) = h.tokens_for(&["read"]).await;
    let code = h.code_for(&alice, &client, &["read"]).await["code"].clone();
    // The user is gone (M13 deactivation reads the same seam, users::is_active).
    let c = rusqlite::Connection::open(h.dir.path().join("server.db")).unwrap();
    // The grant rows stay (only the user row goes), as after M13's deactivation.
    c.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    c.execute(
        "DELETE FROM users WHERE user_id = ?1",
        [user_id_for("alice")],
    )
    .unwrap();
    let (st, e) = h.refresh(&client, &s(&v, "refresh_token"), None).await;
    assert_eq!(
        (st, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant")),
        "{e}"
    );
    let (st, e) = h.redeem(&client, &code).await;
    assert_eq!(
        (st, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant")),
        "{e}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_token_records_are_deduplicated_per_grant() {
    let h = H::new();
    let (_, _, v) = h.tokens_for(&["read"]).await;
    let access = s(&v, "access_token");
    h.clock.advance(900);
    let refusals = |chain: &[(atlas_duck_audit::EventType, serde_json::Value)]| {
        chain
            .iter()
            .filter(|(k, p)| {
                *k == atlas_duck_audit::EventType::LOGIN && p.to_string().contains("\"refused\"")
            })
            .count()
    };
    // A burst of requests with the expired token: every one is 401, one record.
    for _ in 0..5 {
        assert_eq!(
            h.mcp_init(&access, None).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(refusals(&h.alice_chain().await), 1);
    // Inside the window still none; after it, one more.
    h.clock.advance(crate::oauth::REFUSAL_RECORD_EVERY - 1);
    h.mcp_init(&access, None).await;
    assert_eq!(refusals(&h.alice_chain().await), 1);
    h.clock.advance(1);
    h.mcp_init(&access, None).await;
    assert_eq!(refusals(&h.alice_chain().await), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_endpoint_and_deactivation() {
    let h = H::new();
    let (client, _, v) = h.tokens_for(&["read"]).await;
    let access = s(&v, "access_token");
    // Unknown and other clients' tokens: 200, nothing happens; a missing token is 400.
    let other = h.client_id().await;
    for (token, cid) in [
        ("ado_at_unknown", client.as_str()),
        (access.as_str(), other.as_str()),
    ] {
        let (st, _) = h
            .post_form("/oauth/revoke", &[("token", token), ("client_id", cid)])
            .await;
        assert_eq!(st, StatusCode::OK);
    }
    assert_eq!(h.mcp_init(&access, None).await.status(), StatusCode::OK);
    let (st, e) = h
        .post_form("/oauth/revoke", &[("client_id", &client)])
        .await;
    assert_eq!(
        (st, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_request"))
    );
    let (st, _) = h
        .post_form(
            "/oauth/revoke",
            &[("token", &s(&v, "refresh_token")), ("client_id", &client)],
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    // The very next request with the access token is refused.
    assert_eq!(
        h.mcp_init(&access, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let chain = h.alice_chain().await;
    assert!(chain.iter().any(
        |(k, p)| *k == atlas_duck_audit::EventType::OAUTH_GRANT_REVOKED
            && p.to_string().contains("revocation_endpoint")
    ));
    // Δ-M14-4: deactivation revokes every grant with a record each.
    let (_, _, v) = h.tokens_for(&["read"]).await;
    let n = crate::oauth::token::revoke_all_for_user(
        h.store.as_ref(),
        &h.registry,
        &user_id_for("alice"),
        h.clock.now(),
    )
    .await
    .unwrap();
    assert_eq!(n, 1);
    assert_eq!(
        h.mcp_init(&s(&v, "access_token"), None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let chain = h.alice_chain().await;
    assert!(chain.iter().any(
        |(k, p)| *k == atlas_duck_audit::EventType::OAUTH_GRANT_REVOKED
            && p.to_string().contains("deactivation")
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oauth_token_never_approves_and_sessions_bind_to_the_credential() {
    let h = H::new();
    let (_, alice, v) = h.tokens_for(&["read"]).await;
    let bearer = format!("Bearer {}", s(&v, "access_token"));
    for (method, path, body) in [
        (
            Method::POST,
            "/api/cmd/decide",
            json!({"request_id": "req_x", "decision": "approve"}),
        ),
        (
            Method::POST,
            "/api/me/api-keys",
            json!({"name": "x", "scopes": ["read"]}),
        ),
        (Method::GET, "/api/me/api-keys", Value::Null),
    ] {
        let res = h
            .send(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::COOKIE, cookie_header(&alice.0))
                    .header("x-csrf-token", &alice.1)
                    .header(header::ORIGIN, ORIGIN)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(
            json_body(res).await["error"]["code"],
            "auth/bearer_not_accepted"
        );
    }
    // An MCP session opened with the token cannot be continued with an API key of the same user.
    let res = h.mcp_init(&s(&v, "access_token"), None).await;
    let sid = res.headers()["mcp-session-id"].to_str().unwrap().to_owned();
    let created = h
        .state
        .api_keys
        .create(
            &UserCtxT::from_authenticated(&user_id_for("alice")),
            "k",
            &["read".into()],
            None,
        )
        .unwrap();
    let key = secrecy::ExposeSecret::expose_secret(&created.key).to_owned();
    assert_eq!(
        h.mcp_init(&key, Some(&sid)).await.status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_token_endpoint_is_rate_limited_per_ip() {
    let h = H::new();
    for _ in 0..60 {
        let (st, _) = h
            .post_form("/oauth/token", &[("grant_type", "password")])
            .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }
    let res = h
        .send(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header("x-forwarded-for", "192.0.2.50")
                .body(Body::from("grant_type=password"))
                .unwrap(),
        )
        .await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers().contains_key(header::RETRY_AFTER));
}

// ---- T9: connected apps ----------------------------------------------------------------------

impl H {
    async fn grants(&self, cookie: &str) -> (StatusCode, Value) {
        let res = self
            .send(
                Request::builder()
                    .uri("/api/me/oauth/grants")
                    .header(header::COOKIE, cookie_header(cookie))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        let s = res.status();
        (s, json_body(res).await)
    }

    async fn revoke_grant(&self, sess: &(String, String), id: &str) -> StatusCode {
        self.send(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/me/oauth/grants/{id}"))
                .header(header::COOKIE, cookie_header(&sess.0))
                .header("x-csrf-token", &sess.1)
                .header(header::ORIGIN, ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .status()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grants_are_listed_and_revoked_per_user() {
    let h = H::new();
    let (_, alice, v) = h.tokens_for(&["read", "scripts"]).await;
    let bob = h.session("bob", "pw-bob").await;
    let (st, list) = h.grants(&alice.0).await;
    assert_eq!(st, StatusCode::OK);
    let rows = list.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    let g = &rows[0];
    assert_eq!(g["client_name"], "Claude Code");
    assert_eq!(g["redirect_hosts"], json!(["127.0.0.1"]));
    assert_eq!(g["scopes"], json!(["read", "scripts"]));
    assert!(g["revoked_at"].is_null());
    // Never a token or a hash in the list.
    let text = list.to_string();
    for t in [s(&v, "access_token"), s(&v, "refresh_token")] {
        assert!(!text.contains(&t));
    }
    assert!(!text.contains("hash"));
    let id = g["grant_id"].as_str().unwrap().to_owned();
    // Bob sees nothing and cannot revoke alice's grant (answered like an unknown id).
    assert_eq!(h.grants(&bob.0).await.1, json!([]));
    assert_eq!(h.revoke_grant(&bob, &id).await, StatusCode::NOT_FOUND);
    assert_eq!(
        h.revoke_grant(&bob, "grt_unknown").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h.mcp_init(&s(&v, "access_token"), None).await.status(),
        StatusCode::OK
    );
    // Alice revokes: the token dies at once and the chain records it.
    assert_eq!(h.revoke_grant(&alice, &id).await, StatusCode::NO_CONTENT);
    assert_eq!(
        h.mcp_init(&s(&v, "access_token"), None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(h.revoke_grant(&alice, &id).await, StatusCode::NO_CONTENT);
    let chain = h.alice_chain().await;
    assert_eq!(
        chain
            .iter()
            .filter(
                |(k, p)| *k == atlas_duck_audit::EventType::OAUTH_GRANT_REVOKED
                    && p["by"] == "user"
            )
            .count(),
        1
    );
    assert!(!h.grants(&alice.0).await.1[0]["revoked_at"].is_null());
    // Without CSRF: refused by the guard.
    let res = h
        .send(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/me/oauth/grants/{id}"))
                .header(header::COOKIE, cookie_header(&alice.0))
                .header(header::ORIGIN, ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oauth_paths_refuse_a_deactivated_user() {
    let h = H::new();
    let (client, alice, v) = h.tokens_for(&["read"]).await;
    // A second client, so its consent does not replace the first grant.
    let other = h.client_id().await;
    let code = h.code_for(&alice, &other, &["read"]).await["code"].clone();
    let uid = user_id_for("alice");
    assert!(
        h.store
            .user_deactivate(&uid, T0, "admin", T0 + 86_400)
            .unwrap()
    );
    // Bearer, refresh and code redemption all refuse (the grant itself is not revoked here).
    assert_eq!(
        h.mcp_init(&s(&v, "access_token"), None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let (st, e) = h.refresh(&client, &s(&v, "refresh_token"), None).await;
    assert_eq!(
        (st, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    let (st, e) = h.redeem(&other, &code).await;
    assert_eq!(
        (st, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    assert!(
        h.store
            .grant_list(&uid)
            .unwrap()
            .iter()
            .all(|g| g.revoked_at.is_none())
    );
}
