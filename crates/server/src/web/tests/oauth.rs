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
