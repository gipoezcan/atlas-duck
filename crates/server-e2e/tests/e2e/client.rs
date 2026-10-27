//! The suite's HTTP side: a browser (session cookie, CSRF token, `Origin`), API keys, an MCP
//! client over the streamable HTTP transport, a minimal OAuth public client (discovery, RFC 7591
//! registration, PKCE S256, a loopback redirect listener) and a ustar reader. Every call returns
//! `R` instead of panicking; every wait is bounded.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Method;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{RoleClient, ServiceExt as _};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub type R<T> = Result<T, String>;

/// Every request and every MCP call is bounded by this.
pub const LIMIT: Duration = Duration::from_secs(30);

/// `Option`/`Result` into the suite's error with context.
pub trait Ctx<T> {
    fn ctx(self, what: &str) -> R<T>;
}

impl<T> Ctx<T> for Option<T> {
    fn ctx(self, what: &str) -> R<T> {
        self.ok_or_else(|| what.to_owned())
    }
}

impl<T, E: std::fmt::Display> Ctx<T> for Result<T, E> {
    fn ctx(self, what: &str) -> R<T> {
        self.map_err(|e| format!("{what}: {e}"))
    }
}

/// `Err(..)` unless `cond`.
macro_rules! ensure {
    ($cond:expr, $($fmt:tt)+) => {
        if !$cond {
            return Err(format!($($fmt)+));
        }
    };
}
pub(crate) use ensure;

/// A test user from the PD-261 users file.
#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub password: String,
    pub groups: Vec<String>,
}

/// The users file: plain users (no admin or auditor group), the first admin, the first auditor.
pub struct Users {
    pub plain: Vec<User>,
    pub admin: User,
    pub auditor: User,
}

impl Users {
    pub fn read(path: &str) -> R<Users> {
        let text = std::fs::read_to_string(path).ctx("users file")?;
        let v: Value = serde_json::from_str(&text).ctx("users file JSON")?;
        let mut all = Vec::new();
        for u in v["users"].as_array().ctx("users file: no users array")? {
            all.push(User {
                name: u["username"].as_str().ctx("username")?.to_owned(),
                password: u["password"].as_str().ctx("password")?.to_owned(),
                groups: u["groups"]
                    .as_array()
                    .ctx("groups")?
                    .iter()
                    .filter_map(|g| g.as_str().map(str::to_owned))
                    .collect(),
            });
        }
        let has = |u: &User, g: &str| u.groups.iter().any(|x| x.contains(g));
        let admin = all.iter().find(|u| has(u, "admins")).cloned();
        let auditor = all
            .iter()
            .find(|u| has(u, "auditors") && !has(u, "admins"))
            .cloned();
        let plain: Vec<User> = all
            .into_iter()
            .filter(|u| !has(u, "admins") && !has(u, "auditors"))
            .collect();
        ensure!(plain.len() >= 2, "the users file needs two plain users");
        Ok(Users {
            plain,
            admin: admin.ctx("the users file has no admin")?,
            auditor: auditor.ctx("the users file has no auditor")?,
        })
    }
}

/// A signed-in browser: the session cookie (`name=value`) and its CSRF token.
#[derive(Debug, Clone)]
pub struct Browser {
    pub cookie: String,
    pub csrf: String,
}

/// The server under test.
pub struct Server {
    pub base: String,
    pub http: reqwest::Client,
}

impl Server {
    pub fn new(base: &str, ca_file: Option<&str>) -> R<Server> {
        let mut b = reqwest::Client::builder()
            .timeout(LIMIT)
            .redirect(reqwest::redirect::Policy::none());
        if let Some(ca) = ca_file {
            let pem = std::fs::read(ca).ctx("CA file")?;
            for c in reqwest::Certificate::from_pem_bundle(&pem).ctx("CA file PEM")? {
                b = b.add_root_certificate(c);
            }
        }
        Ok(Server {
            base: base.to_owned(),
            http: b.build().ctx("HTTP client")?,
        })
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub async fn login(&self, u: &User) -> R<Browser> {
        let res = self
            .http
            .post(self.url("/api/login"))
            .header("origin", &self.base)
            .json(&json!({"username": u.name, "password": u.password}))
            .send()
            .await
            .ctx("login")?;
        ensure!(
            res.status() == 200,
            "login {} answered {}",
            u.name,
            res.status()
        );
        let set = res
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .ctx("login: no Set-Cookie")?;
        let cookie = set.split(';').next().ctx("Set-Cookie")?.to_owned();
        let body: Value = res.json().await.ctx("login body")?;
        Ok(Browser {
            cookie,
            csrf: body["csrf_token"].as_str().ctx("csrf_token")?.to_owned(),
        })
    }

    /// A browser request with the CSRF token only when `csrf` and the given `Origin` (the
    /// guard probes).
    pub async fn send_with(
        &self,
        method: Method,
        path: &str,
        b: Option<&Browser>,
        body: Option<Value>,
        csrf: bool,
        origin: Option<&str>,
    ) -> R<(u16, Value)> {
        let mut req = self.http.request(method, self.url(path));
        if let Some(b) = b {
            req = req.header("cookie", &b.cookie);
            if csrf {
                req = req.header("x-csrf-token", &b.csrf);
            }
        }
        if let Some(o) = origin {
            req = req.header("origin", o);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let res = req.send().await.ctx(path)?;
        let status = res.status().as_u16();
        let text = res.text().await.unwrap_or_default();
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }

    pub async fn send(
        &self,
        method: Method,
        path: &str,
        b: Option<&Browser>,
        body: Option<Value>,
    ) -> R<(u16, Value)> {
        let changing = method != Method::GET;
        let origin = changing.then_some(self.base.clone());
        self.send_with(method, path, b, body, changing, origin.as_deref())
            .await
    }

    pub async fn cmd(&self, b: &Browser, name: &str, body: Value) -> R<(u16, Value)> {
        self.send(
            Method::POST,
            &format!("/api/cmd/{name}"),
            Some(b),
            Some(body),
        )
        .await
    }

    /// A new API key: `(id, key)`.
    pub async fn api_key(&self, b: &Browser, scopes: &[&str]) -> R<(String, String)> {
        let (s, v) = self
            .send(
                Method::POST,
                "/api/me/api-keys",
                Some(b),
                Some(json!({"name": "e2e", "scopes": scopes})),
            )
            .await?;
        ensure!(s == 201, "api key: {s} {v}");
        Ok((
            v["id"].as_str().ctx("key id")?.to_owned(),
            v["key"].as_str().ctx("key")?.to_owned(),
        ))
    }

    /// An MCP client with `bearer` (API key or OAuth access token).
    pub async fn mcp(&self, bearer: &str) -> R<RunningService<RoleClient, ()>> {
        let transport = StreamableHttpClientTransport::with_client(
            self.http.clone(),
            StreamableHttpClientTransportConfig::with_uri(self.url("/mcp"))
                .auth_header(bearer.to_owned()),
        );
        tokio::time::timeout(LIMIT, ().serve(transport))
            .await
            .ctx("MCP initialize timed out")?
            .ctx("MCP initialize")
    }

    /// The status of an MCP `initialize` POST with `bearer`.
    pub async fn mcp_status(&self, bearer: &str) -> R<u16> {
        let res = self
            .http
            .post(self.url("/mcp"))
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(INIT)
            .send()
            .await
            .ctx("POST /mcp")?;
        Ok(res.status().as_u16())
    }
}

/// An MCP `initialize` request body.
pub const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}"#;

pub async fn call(c: &RunningService<RoleClient, ()>, tool: &str, args: Value) -> R<Value> {
    let params = CallToolRequestParams::new(tool.to_owned())
        .with_arguments(args.as_object().cloned().unwrap_or_default());
    let r: CallToolResult = tokio::time::timeout(LIMIT * 3, c.call_tool(params))
        .await
        .ctx("tool call timed out")?
        .ctx(tool)?;
    Ok(r.structured_content.unwrap_or(Value::Null))
}

/// What discovery found.
#[derive(Debug, Clone)]
pub struct Discovered {
    pub resource: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
    pub revocation_endpoint: String,
}

fn quoted(header: &str, key: &str) -> Option<String> {
    let at = header.find(&format!("{key}=\""))? + key.len() + 2;
    let rest = &header[at..];
    Some(rest[..rest.find('"')?].to_owned())
}

/// The discovery chain an MCP client follows from an unauthenticated `POST /mcp`.
pub async fn discover(s: &Server) -> R<Discovered> {
    let res = s
        .http
        .post(s.url("/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(INIT)
        .send()
        .await
        .ctx("POST /mcp")?;
    ensure!(
        res.status() == 401,
        "/mcp without a token: {}",
        res.status()
    );
    let www = res
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .ctx("no WWW-Authenticate")?
        .to_owned();
    let prm_url = quoted(&www, "resource_metadata").ctx("no resource_metadata")?;
    let prm: Value = s
        .http
        .get(&prm_url)
        .send()
        .await
        .ctx("PRM")?
        .json()
        .await
        .ctx("PRM JSON")?;
    let issuer = prm["authorization_servers"][0]
        .as_str()
        .ctx("authorization_servers")?
        .to_owned();
    let asm: Value = s
        .http
        .get(format!("{issuer}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .ctx("AS metadata")?
        .json()
        .await
        .ctx("AS metadata JSON")?;
    ensure!(asm["issuer"] == issuer.as_str(), "issuer mismatch: {asm}");
    ensure!(
        asm["code_challenge_methods_supported"] == json!(["S256"]),
        "PKCE methods: {asm}"
    );
    let field = |k: &str| asm[k].as_str().map(str::to_owned).ctx(k);
    Ok(Discovered {
        resource: prm["resource"].as_str().ctx("resource")?.to_owned(),
        authorization_endpoint: field("authorization_endpoint")?,
        token_endpoint: field("token_endpoint")?,
        registration_endpoint: field("registration_endpoint")?,
        revocation_endpoint: field("revocation_endpoint")?,
    })
}

/// A PKCE pair.
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn new() -> R<Pkce> {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).ctx("randomness")?;
        let verifier = URL_SAFE_NO_PAD.encode(b);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Ok(Pkce {
            verifier,
            challenge,
        })
    }
}

/// A registered public client with its loopback listener.
pub struct OAuthClient {
    pub d: Discovered,
    pub client_id: String,
    pub redirect_uri: String,
    listener: TcpListener,
}

type Query = std::collections::HashMap<String, String>;

impl OAuthClient {
    pub async fn register(s: &Server, d: &Discovered, name: &str) -> R<OAuthClient> {
        let listener = TcpListener::bind("127.0.0.1:0").await.ctx("loopback")?;
        let port = listener.local_addr().ctx("loopback addr")?.port();
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
            .ctx("register")?;
        ensure!(res.status() == 201, "register: {}", res.status());
        let v: Value = res.json().await.ctx("register JSON")?;
        Ok(OAuthClient {
            d: d.clone(),
            client_id: v["client_id"].as_str().ctx("client_id")?.to_owned(),
            redirect_uri,
            listener,
        })
    }

    fn authorize_url(&self, pkce: &Pkce, scope: &str) -> String {
        let q = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", self.client_id.as_str()),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("scope", scope),
                ("state", "e2e-state"),
                ("code_challenge", pkce.challenge.as_str()),
                ("code_challenge_method", "S256"),
                ("resource", self.d.resource.as_str()),
            ])
            .finish();
        format!("{}?{q}", self.d.authorization_endpoint)
    }

    /// The browser leg: the authorization URL with the session, consent for `allow`, the
    /// redirect into the loopback listener. Answers the callback's query.
    pub async fn authorize(
        &self,
        s: &Server,
        b: &Browser,
        pkce: &Pkce,
        scope: &str,
        allow: &[&str],
    ) -> R<Query> {
        let res = s
            .http
            .get(self.authorize_url(pkce, scope))
            .header("cookie", &b.cookie)
            .send()
            .await
            .ctx("authorize")?;
        ensure!(res.status() == 302, "authorize: {}", res.status());
        let loc = res
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ctx("authorize: no Location")?
            .to_owned();
        let req = loc
            .strip_prefix("/oauth/consent?req=")
            .ctx("not a consent redirect")?
            .to_owned();
        let (status, v) = s
            .send(
                Method::POST,
                &format!("/api/oauth/consent/{req}"),
                Some(b),
                Some(json!({"decision": "allow", "scopes": allow})),
            )
            .await?;
        ensure!(status == 200, "consent: {status} {v}");
        let redirect = v["redirect"].as_str().ctx("consent redirect")?;
        ensure!(
            redirect.starts_with(&self.redirect_uri),
            "redirect {redirect}"
        );
        let accept = async {
            let (mut sock, _) = self.listener.accept().await.ctx("callback accept")?;
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.ctx("callback read")?;
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await
                .ctx("callback write")?;
            R::Ok(head)
        };
        let get = reqwest::Client::new().get(redirect).timeout(LIMIT).send();
        let (head, res) = tokio::time::timeout(LIMIT, async { tokio::join!(accept, get) })
            .await
            .ctx("the loopback callback never arrived")?;
        res.ctx("callback GET")?;
        let target = head?
            .split(' ')
            .nth(1)
            .ctx("callback request line")?
            .to_owned();
        let url = url::Url::parse(&format!("http://127.0.0.1{target}")).ctx("callback URL")?;
        Ok(url.query_pairs().into_owned().collect())
    }

    async fn form(&self, s: &Server, endpoint: &str, pairs: &[(&str, &str)]) -> R<(u16, Value)> {
        let res = s
            .http
            .post(endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(pairs)
                    .finish(),
            )
            .send()
            .await
            .ctx(endpoint)?;
        let status = res.status().as_u16();
        Ok((status, res.json().await.unwrap_or(Value::Null)))
    }

    pub async fn redeem(&self, s: &Server, code: &str, verifier: &str) -> R<(u16, Value)> {
        self.form(
            s,
            &self.d.token_endpoint,
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

    pub async fn refresh(&self, s: &Server, refresh_token: &str) -> R<(u16, Value)> {
        self.form(
            s,
            &self.d.token_endpoint,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", &self.client_id),
                ("resource", &self.d.resource),
            ],
        )
        .await
    }

    pub async fn revoke(&self, s: &Server, token: &str) -> R<u16> {
        Ok(self
            .form(
                s,
                &self.d.revocation_endpoint,
                &[("token", token), ("client_id", &self.client_id)],
            )
            .await?
            .0)
    }

    /// Discovery, registration, consent for `scopes` and the code redemption: the token body.
    pub async fn tokens_for(s: &Server, b: &Browser, scopes: &[&str]) -> R<(OAuthClient, Value)> {
        let d = discover(s).await?;
        let c = OAuthClient::register(s, &d, "e2e client").await?;
        let pkce = Pkce::new()?;
        let q = c.authorize(s, b, &pkce, &scopes.join(" "), scopes).await?;
        ensure!(
            q.get("state").map(String::as_str) == Some("e2e-state"),
            "state: {q:?}"
        );
        let code = q.get("code").ctx("no code in the callback")?;
        let (st, tok) = c.redeem(s, code, &pkce.verifier).await?;
        ensure!(st == 200, "redeem: {st} {tok}");
        Ok((c, tok))
    }
}

/// A string field of a JSON value.
pub fn field(v: &Value, k: &str) -> R<String> {
    v[k].as_str().map(str::to_owned).ctx(k)
}

/// The members of a ustar archive `(name, data)`, with magic and header checksum checks.
pub fn untar(archive: &[u8]) -> R<Vec<(String, Vec<u8>)>> {
    let field = |h: &[u8], a: usize, b: usize| -> R<String> {
        let s = &h[a..b];
        let end = s.iter().position(|c| *c == 0).unwrap_or(s.len());
        String::from_utf8(s[..end].to_vec()).ctx("tar field")
    };
    let num = |h: &[u8], a: usize, b: usize| -> R<u64> {
        u64::from_str_radix(field(h, a, b)?.trim(), 8).ctx("tar number")
    };
    let mut out = Vec::new();
    let mut at = 0;
    while at + 512 <= archive.len() {
        let h = &archive[at..at + 512];
        if h.iter().all(|b| *b == 0) {
            break;
        }
        ensure!(&h[257..263] == b"ustar\0", "not ustar");
        let mut copy = h.to_vec();
        copy[148..156].fill(b' ');
        let sum: u64 = copy.iter().map(|b| u64::from(*b)).sum();
        ensure!(num(h, 148, 155)? == sum, "tar header checksum");
        let prefix = field(h, 345, 500)?;
        let base = field(h, 0, 100)?;
        let name = if prefix.is_empty() {
            base
        } else {
            format!("{prefix}/{base}")
        };
        let size = usize::try_from(num(h, 124, 136)?).ctx("tar size")?;
        let data = archive
            .get(at + 512..at + 512 + size)
            .ctx("tar member past the end")?;
        out.push((name, data.to_vec()));
        at += 512 + size.div_ceil(512) * 512;
    }
    Ok(out)
}
