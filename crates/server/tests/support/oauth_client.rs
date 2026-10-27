//! A minimal OAuth public client as an MCP client drives it (M14 T10): discovery from the `/mcp`
//! 401 (RFC 9728 `resource_metadata`), authorization-server metadata (RFC 8414), dynamic
//! registration (RFC 7591), PKCE S256 (RFC 7636), a loopback redirect listener on `127.0.0.1:0`
//! (RFC 8252 §7.3), the token and refresh grants. The browser leg is a signed-in [`Browser`].

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{Browser, COOKIE, LIMIT, TestServer};

/// What discovery found.
#[derive(Debug, Clone)]
pub struct Discovered {
    pub resource: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
    pub revocation_endpoint: String,
}

/// A registered client with its loopback listener.
pub struct OAuthClient {
    pub d: Discovered,
    pub client_id: String,
    pub redirect_uri: String,
    listener: TcpListener,
}

/// A PKCE pair.
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn new() -> Pkce {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).unwrap();
        let verifier = URL_SAFE_NO_PAD.encode(b);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Pkce {
            verifier,
            challenge,
        }
    }
}

fn quoted(header: &str, key: &str) -> Option<String> {
    let at = header.find(&format!("{key}=\""))? + key.len() + 2;
    let rest = &header[at..];
    Some(rest[..rest.find('"')?].to_owned())
}

/// The discovery chain an MCP client follows, starting from an unauthenticated `POST /mcp`.
pub async fn discover(s: &TestServer) -> Discovered {
    let res = s
        .http
        .post(s.url("/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let www = res.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .to_owned();
    let prm_url = quoted(&www, "resource_metadata").expect("resource_metadata in the challenge");
    let prm: Value = s
        .http
        .get(&prm_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let issuer = prm["authorization_servers"][0].as_str().unwrap().to_owned();
    let asm: Value = s
        .http
        .get(format!("{issuer}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(asm["issuer"], issuer.as_str());
    assert!(
        asm["code_challenge_methods_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("S256"))
    );
    let field = |k: &str| asm[k].as_str().unwrap().to_owned();
    Discovered {
        resource: prm["resource"].as_str().unwrap().to_owned(),
        issuer,
        authorization_endpoint: field("authorization_endpoint"),
        token_endpoint: field("token_endpoint"),
        registration_endpoint: field("registration_endpoint"),
        revocation_endpoint: field("revocation_endpoint"),
    }
}

impl OAuthClient {
    /// Registers a public client whose redirect URI is a fresh loopback listener.
    pub async fn register(s: &TestServer, d: &Discovered, name: &str) -> OAuthClient {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let redirect_uri = format!("http://127.0.0.1:{port}/callback");
        let res = s
            .http
            .post(&d.registration_endpoint)
            .json(&json!({
                "client_name": name,
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
        let v: Value = res.json().await.unwrap();
        OAuthClient {
            d: d.clone(),
            client_id: v["client_id"].as_str().unwrap().to_owned(),
            redirect_uri,
            listener,
        }
    }

    /// The authorization URL for `pkce`, `scope` and `state`.
    pub fn authorize_url(&self, pkce: &Pkce, scope: &str, state: &str) -> String {
        let q = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", self.client_id.as_str()),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("scope", scope),
                ("state", state),
                ("code_challenge", pkce.challenge.as_str()),
                ("code_challenge_method", "S256"),
                ("resource", self.d.resource.as_str()),
            ])
            .finish();
        format!("{}?{q}", self.d.authorization_endpoint)
    }

    /// The browser leg: `GET` the authorization URL with the session, allow `scopes` on the
    /// consent API, follow the redirect into this client's loopback listener; answers the
    /// callback's query parameters as the listener received them.
    pub async fn authorize(
        &self,
        s: &TestServer,
        b: &Browser,
        pkce: &Pkce,
        scope: &str,
        state: &str,
        allow: &[&str],
    ) -> std::collections::HashMap<String, String> {
        let req = consent_request(s, b, &self.authorize_url(pkce, scope, state)).await;
        let (status, v) = s
            .send(
                reqwest::Method::POST,
                &format!("/api/oauth/consent/{req}"),
                Some(b),
                Some(json!({"decision": "allow", "scopes": allow})),
            )
            .await;
        assert_eq!(status, 200, "{v}");
        self.follow(s, v["redirect"].as_str().unwrap()).await
    }

    /// The browser follows `redirect` into this client's listener.
    pub async fn follow(
        &self,
        s: &TestServer,
        redirect: &str,
    ) -> std::collections::HashMap<String, String> {
        assert!(redirect.starts_with(&self.redirect_uri), "{redirect}");
        let accept = async {
            let (mut sock, _) = self.listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await
                .unwrap();
            head
        };
        let get = s.http.get(redirect).send();
        let (head, res) = tokio::time::timeout(LIMIT, async { tokio::join!(accept, get) })
            .await
            .expect("the loopback callback never arrived");
        assert_eq!(res.unwrap().status(), 200);
        let target = head.split(' ').nth(1).unwrap().to_owned();
        let url = url::Url::parse(&format!("http://127.0.0.1{target}")).unwrap();
        assert_eq!(url.path(), "/callback");
        url.query_pairs().into_owned().collect()
    }

    pub async fn token(&self, s: &TestServer, pairs: &[(&str, &str)]) -> (u16, Value) {
        let res = s
            .http
            .post(&self.d.token_endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(pairs)
                    .finish(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(res.headers()["cache-control"], "no-store");
        let status = res.status().as_u16();
        (status, res.json().await.unwrap_or(Value::Null))
    }

    pub async fn redeem(&self, s: &TestServer, code: &str, verifier: &str) -> (u16, Value) {
        self.token(
            s,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &self.redirect_uri),
                ("client_id", &self.client_id),
                ("code_verifier", verifier),
                ("resource", &self.d.resource),
            ],
        )
        .await
    }

    pub async fn refresh(&self, s: &TestServer, refresh_token: &str) -> (u16, Value) {
        self.token(
            s,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", &self.client_id),
                ("resource", &self.d.resource),
            ],
        )
        .await
    }

    pub async fn revoke(&self, s: &TestServer, token: &str) -> u16 {
        s.http
            .post(&self.d.revocation_endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([("token", token), ("client_id", self.client_id.as_str())])
                    .finish(),
            )
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }
}

/// `GET <authorize URL>` with the browser's cookie, no redirect following: the `Location`.
pub async fn authorize_location(s: &TestServer, b: Option<&Browser>, url: &str) -> String {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(LIMIT)
        .build()
        .unwrap();
    let mut req = client.get(url);
    if let Some(b) = b {
        req = req.header("cookie", format!("{COOKIE}={}", b.cookie));
    }
    let res = req.send().await.unwrap();
    assert_eq!(res.status(), 302, "{url}");
    let loc = res.headers()["location"].to_str().unwrap().to_owned();
    let _ = s;
    loc
}

/// The consent request id the authorization endpoint redirects to.
pub async fn consent_request(s: &TestServer, b: &Browser, url: &str) -> String {
    let loc = authorize_location(s, Some(b), url).await;
    loc.strip_prefix("/oauth/consent?req=")
        .unwrap_or_else(|| panic!("not a consent redirect: {loc}"))
        .to_owned()
}
