//! OAuth conformance and abuse suite (M14 T10, SM-3.3, PD-233..PD-245) over real HTTP: a
//! spec-following public client discovers the server from the `/mcp` 401, registers, sends
//! alice's browser through authorization and consent, receives the code on its loopback
//! listener, redeems it with PKCE, speaks MCP with the access token and refreshes. Then the
//! abuse cases, and the audit trail both chains keep of them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::time::Duration;

use atlas_duck_audit::EventType;
use atlas_duck_audit::types::{AuditCursor, AuditFilter};
use atlas_duck_server::anchor;
use atlas_duck_server::users::user_id_for;
use rmcp::ServiceExt as _;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::{Value, json};
use support::oauth_client::{OAuthClient, Pkce, authorize_location, consent_request, discover};
use support::*;

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(60), f)
        .await
        .expect("timed out")
}

fn field(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or_default().to_owned()
}

async fn mcp_status(s: &TestServer, token: &str) -> u16 {
    s.http
        .post(s.url("/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// Alice's chain: `(kind, payload)` per record.
async fn alice_chain(s: &TestServer) -> Vec<(EventType, Value)> {
    let uid = user_id_for(ALICE.0);
    let rt = s
        .registry
        .open_runtimes()
        .await
        .into_iter()
        .find(|r| r.user_id() == uid)
        .expect("alice's runtime is open");
    let page = rt
        .audit_store()
        .query(&AuditFilter::default(), AuditCursor::first(500))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_registration_consent_token_mcp_refresh() {
    within(async {
        let s = TestServer::start().await;
        let d = discover(&s).await;
        assert_eq!(d.resource, s.url("/mcp"));
        assert_eq!(d.issuer, s.base);
        let client = OAuthClient::register(&s, &d, "Conformance client").await;
        let alice = s.login(ALICE).await;
        let pkce = Pkce::new();
        let q = client
            .authorize(&s, &alice, &pkce, "read scripts", "xyz-state", &["scripts"])
            .await;
        assert_eq!(q["state"], "xyz-state");
        assert_eq!(q["iss"], s.base);
        let (st, tok) = client.redeem(&s, &q["code"], &pkce.verifier).await;
        assert_eq!(st, 200, "{tok}");
        assert_eq!(tok["scope"], "read scripts");

        // MCP over streamable HTTP with the access token: initialize + tools/list.
        let transport = StreamableHttpClientTransport::from_config(
            StreamableHttpClientTransportConfig::with_uri(s.url("/mcp"))
                .auth_header(s_of(&tok, "access_token")),
        );
        let mcp = ().serve(transport).await.unwrap();
        let names: Vec<String> = mcp
            .list_all_tools()
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.name.into_owned())
            .collect();
        assert!(names.contains(&"ops_list".to_owned()), "{names:?}");
        assert!(
            !names.iter().any(|n| n.contains("comment_add")),
            "no write tools for read scripts"
        );

        // Refresh: a new pair; the old access token stays valid until its expiry, the old
        // refresh token is dead (and presenting it is a reuse).
        let (st, tok2) = client.refresh(&s, &s_of(&tok, "refresh_token")).await;
        assert_eq!(st, 200, "{tok2}");
        assert_ne!(s_of(&tok2, "access_token"), s_of(&tok, "access_token"));
        assert_eq!(mcp_status(&s, &s_of(&tok, "access_token")).await, 200);
        assert_eq!(mcp_status(&s, &s_of(&tok2, "access_token")).await, 200);
        let (st, e) = client.refresh(&s, &s_of(&tok, "refresh_token")).await;
        assert_eq!((st, s_of(&e, "error")), (400, "invalid_grant".to_owned()));
        let _ = mcp.cancel().await;
    })
    .await;
}

fn s_of(v: &Value, k: &str) -> String {
    field(v, k)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abuse_cases() {
    within(async {
        let s = TestServer::start().await;
        let d = discover(&s).await;
        let a = OAuthClient::register(&s, &d, "Client A").await;
        let b = OAuthClient::register(&s, &d, "Client B").await;
        let alice = s.login(ALICE).await;

        // Code interception without the verifier: refused, and the legitimate client still
        // redeems (a request without a verifier does not reach the code).
        let p1 = Pkce::new();
        let q1 = a.authorize(&s, &alice, &p1, "read", "s1", &[]).await;
        let (st, e) = a
            .token(
                &s,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &q1["code"]),
                    ("redirect_uri", &a.redirect_uri),
                    ("client_id", &a.client_id),
                    ("resource", &d.resource),
                ],
            )
            .await;
        assert_eq!((st, s_of(&e, "error")), (400, "invalid_request".to_owned()));
        let (st, tok1) = a.redeem(&s, &q1["code"], &p1.verifier).await;
        assert_eq!(st, 200, "{tok1}");

        // Token replay after revocation. (Every later consent for A replaces A's grant, so this
        // runs before the next authorization of A.)
        let access1 = s_of(&tok1, "access_token");
        assert_eq!(mcp_status(&s, &access1).await, 200);
        assert_eq!(a.revoke(&s, &access1).await, 200);
        assert_eq!(mcp_status(&s, &access1).await, 401);

        // The verifier of another flow: refused (and the code is burned).
        let p2 = Pkce::new();
        let q2 = a.authorize(&s, &alice, &p2, "read", "s2", &[]).await;
        let (st, e) = a.redeem(&s, &q2["code"], &p1.verifier).await;
        assert_eq!((st, s_of(&e, "error")), (400, "invalid_grant".to_owned()));
        assert_eq!(a.redeem(&s, &q2["code"], &p2.verifier).await.0, 400);

        // Mixing clients: A's code redeemed by B.
        let p3 = Pkce::new();
        let q3 = a.authorize(&s, &alice, &p3, "read", "s3", &[]).await;
        let (st, e) = b
            .token(
                &s,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &q3["code"]),
                    ("redirect_uri", &a.redirect_uri),
                    ("client_id", &b.client_id),
                    ("code_verifier", &p3.verifier),
                    ("resource", &d.resource),
                ],
            )
            .await;
        assert_eq!((st, s_of(&e, "error")), (400, "invalid_grant".to_owned()));

        // Refresh reuse race: two refreshes with the same token at once.
        let p4 = Pkce::new();
        let q4 = b.authorize(&s, &alice, &p4, "read", "s4", &[]).await;
        let (_, tok4) = b.redeem(&s, &q4["code"], &p4.verifier).await;
        let rt4 = s_of(&tok4, "refresh_token");
        let (r1, r2) = tokio::join!(b.refresh(&s, &rt4), b.refresh(&s, &rt4));
        let statuses = [r1.0, r2.0];
        assert!(
            statuses.contains(&200) && statuses.contains(&400),
            "{statuses:?}"
        );
        let winner = if r1.0 == 200 { &r1.1 } else { &r2.1 };
        // The loser's reuse revoked the grant: the winner's fresh tokens are dead as well.
        assert_eq!(mcp_status(&s, &s_of(winner, "access_token")).await, 401);
        assert_eq!(b.refresh(&s, &s_of(winner, "refresh_token")).await.0, 400);
        let g4 = s
            .store
            .grant_list(&user_id_for(ALICE.0))
            .unwrap()
            .into_iter()
            .find(|g| g.client_id == b.client_id)
            .unwrap();
        assert_eq!(g4.revoke_reason.as_deref(), Some("refresh_reuse"));

        // Open-redirect attempts against a registered https URI: our error page, never theirs.
        let reg = s
            .http
            .post(&d.registration_endpoint)
            .json(&json!({"client_name": "Web", "redirect_uris": ["https://a.example/cb"]}))
            .send()
            .await
            .unwrap();
        let web: Value = reg.json().await.unwrap();
        let web_id = s_of(&web, "client_id");
        let p5 = Pkce::new();
        for presented in [
            "https://a.example/cb/../evil",
            "https://a.example/cb?x=1",
            "https://a.example.evil/cb",
            "https://evil.example/cb",
        ] {
            let q = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("response_type", "code"),
                    ("client_id", web_id.as_str()),
                    ("redirect_uri", presented),
                    ("state", "s"),
                    ("code_challenge", p5.challenge.as_str()),
                    ("code_challenge_method", "S256"),
                    ("resource", d.resource.as_str()),
                ])
                .finish();
            let loc = authorize_location(
                &s,
                Some(&alice),
                &format!("{}?{q}", d.authorization_endpoint),
            )
            .await;
            assert_eq!(
                loc, "/oauth/consent?error=invalid_redirect_uri",
                "{presented}"
            );
        }

        // A missing state: the error comes back on the validated redirect, without a state.
        let url = a
            .authorize_url(&Pkce::new(), "read", "s")
            .replace("&state=s", "");
        let loc = authorize_location(&s, Some(&alice), &url).await;
        assert!(loc.starts_with(&a.redirect_uri), "{loc}");
        assert!(
            loc.contains("error=invalid_request") && !loc.contains("state="),
            "{loc}"
        );

        // Consent CSRF: a cross-origin POST without the token.
        let req = consent_request(&s, &alice, &a.authorize_url(&Pkce::new(), "read", "s6")).await;
        let res = s
            .http
            .post(s.url(&format!("/api/oauth/consent/{req}")))
            .header("cookie", format!("{COOKIE}={}", alice.cookie))
            .header("origin", "https://evil.example")
            .json(&json!({"decision": "allow"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403);
        // Login CSRF into consent: the request is bound to alice's session; another session
        // (an attacker who logged the victim's browser into their own account) cannot use it.
        let bob = s.login(BOB).await;
        let (st, v) = s
            .send(
                reqwest::Method::POST,
                &format!("/api/oauth/consent/{req}"),
                Some(&bob),
                Some(json!({"decision": "allow"})),
            )
            .await;
        assert_eq!(
            (st, v["error"]["code"].as_str()),
            (404, Some("oauth/request_unknown"))
        );
        let (st, v) = s
            .send(
                reqwest::Method::POST,
                &format!("/api/oauth/consent/{req}"),
                Some(&alice),
                Some(json!({"decision": "deny"})),
            )
            .await;
        assert_eq!(st, 200, "{v}");
        let back = a.follow(&s, v["redirect"].as_str().unwrap()).await;
        assert_eq!(back["error"], "access_denied");

        // The audit trail: alice's chain and the anchor chain, both verifying.
        let chain = alice_chain(&s).await;
        let has = |k: EventType, needle: &str| {
            chain
                .iter()
                .any(|(kind, p)| *kind == k && p.to_string().contains(needle))
        };
        assert!(has(EventType::OAUTH_GRANT_CREATED, "Client A"));
        assert!(has(EventType::OAUTH_GRANT_REVOKED, "reuse_detected"));
        assert!(has(EventType::OAUTH_GRANT_REVOKED, "revocation_endpoint"));
        assert!(has(EventType::LOGIN, "\"refused\""));
        assert!(chain.iter().any(|(k, p)| *k == EventType::LOGIN
            && p["method"] == "oauth"
            && p["outcome"] == "refused"
            && p["reason"] == "revoked"));
        let kinds: Vec<String> = s
            .store
            .anchor_all()
            .unwrap()
            .into_iter()
            .map(|r| r.kind)
            .collect();
        assert!(kinds.contains(&"OAUTH_CLIENT_REGISTERED".to_owned()));
        assert!(kinds.contains(&"OAUTH_REUSE".to_owned()));
        let uid = user_id_for(ALICE.0);
        let rt = s
            .registry
            .open_runtimes()
            .await
            .into_iter()
            .find(|r| r.user_id() == uid)
            .unwrap();
        let findings = rt.audit_store().full_verify();
        assert!(findings.is_empty(), "{findings:?}");
        anchor::verify(s.store.as_ref()).unwrap();
    })
    .await;
}
