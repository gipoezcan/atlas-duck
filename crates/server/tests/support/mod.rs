//! The in-process test server of the integration suites (T23, T24): the full router on
//! `127.0.0.1:0` with a temp SQLite store, the stub directory (`alice`, `bob`, `carol` the admin,
//! `dave` the auditor), a test master key, plain-HTTP cookies (`cookie_secure = false`, the name
//! without `__Host-`) and an Atlassian mock as Jira. Requests carry real cookies, CSRF tokens
//! and Origin headers. Every wait is bounded.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use atlas_duck_atlassian::Product;
use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_server::anchor::AnchorWriter;
use atlas_duck_server::api_keys::{ApiKeyParams, ApiKeys};
use atlas_duck_server::clock::{Clock, SystemClock};
use atlas_duck_server::config::Groups;
use atlas_duck_server::directory::stub::StubDirectory;
use atlas_duck_server::health::Health;
use atlas_duck_server::login::LoginService;
use atlas_duck_server::master_key::MasterKey;
use atlas_duck_server::mcp::McpSessions;
use atlas_duck_server::ratelimit::LoginLimiter;
use atlas_duck_server::runtime::{Registry, RegistrySink, RuntimeDeps, SSE_CAPACITY};
use atlas_duck_server::session::SessionTable;
use atlas_duck_server::static_files::WebDir;
use atlas_duck_server::store::ServerStore;
use atlas_duck_server::store::sqlite::SqliteStore;
use atlas_duck_server::web::{AppInner, AppState, router};
use reqwest::header::{HeaderMap, HeaderValue};
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{RoleClient, ServiceExt as _};
use serde_json::{Value, json};

pub const LIMIT: Duration = Duration::from_secs(30);
pub const MASTER_BYTES: [u8; 32] = [7; 32];

pub const ALICE: (&str, &str) = ("alice", "pw-alice-canary-3d1f");
pub const BOB: (&str, &str) = ("bob", "pw-bob-5c2e");
pub const CAROL: (&str, &str) = ("carol", "pw-carol-8a4b");
pub const DAVE: (&str, &str) = ("dave", "pw-dave-1e9f");

fn stub_json() -> String {
    json!({"users": [
        {"username": ALICE.0, "password": ALICE.1, "groups": ["cn=users,dc=t"]},
        {"username": BOB.0, "password": BOB.1, "groups": ["cn=users,dc=t"]},
        {"username": CAROL.0, "password": CAROL.1, "groups": ["cn=users,dc=t", "cn=admins,dc=t"]},
        {"username": DAVE.0, "password": DAVE.1, "groups": ["cn=users,dc=t", "cn=auditors,dc=t"]},
    ]})
    .to_string()
}

pub struct TestServer {
    pub base: String,
    pub state: AppState,
    pub store: Arc<dyn ServerStore>,
    pub registry: Arc<Registry>,
    pub anchor: Arc<AnchorWriter>,
    pub mock: MockDc,
    pub dir: tempfile::TempDir,
    pub http: reqwest::Client,
}

/// A signed-in browser: the session cookie value and its CSRF token.
#[derive(Clone)]
pub struct Browser {
    pub cookie: String,
    pub csrf: String,
}

pub const COOKIE: &str = "atlas_duck_session";

/// The Jira mock: identity, server info, issue `ABC-1` (any method) and its comments.
pub async fn jira_mock() -> MockDc {
    let mock = MockDc::start(Product::Jira, "").await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.jira_server_info("9.12.0").await;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.json(
        "/rest/api/2/issue/ABC-1/comment",
        201,
        r#"{"id":"10100","body":"Seen on staging.","author":{"name":"jdoe"}}"#,
    )
    .await;
    mock
}

impl TestServer {
    pub async fn start() -> TestServer {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(data.join("server")).unwrap();
        let store: Arc<dyn ServerStore> =
            Arc::new(SqliteStore::open(&data.join("server").join("server.db")).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let master = Arc::new(MasterKey::for_tests("k1", MASTER_BYTES));
        let registry = Arc::new(Registry::new(
            RuntimeDeps {
                data_dir: data,
                store: store.clone(),
                master: master.clone(),
                org_ca: None,
                clock: clock.clone(),
                allow_http: true,
                sse_capacity: SSE_CAPACITY,
            },
            50,
        ));
        let sessions =
            Arc::new(SessionTable::new(store.clone(), clock.clone(), 28_800, 1_800).unwrap());
        let directory = Arc::new(StubDirectory::from_json(&stub_json()).unwrap());
        let login = LoginService {
            store: store.clone(),
            master,
            directory: directory.clone(),
            limiter: Arc::new(LoginLimiter::new(50, 500, 900)),
            sessions: sessions.clone(),
            groups: Groups {
                users: "cn=users,dc=t".into(),
                auditors: Some("cn=auditors,dc=t".into()),
                admins: Some("cn=admins,dc=t".into()),
            },
            clock: clock.clone(),
            sink: Arc::new(RegistrySink(registry.clone())),
        };
        let web = dir.path().join("web");
        std::fs::create_dir_all(web.join("assets")).unwrap();
        let state = AppState(Arc::new(AppInner {
            public_origin: base.clone(),
            cookie_secure: false,
            trusted_proxy_hops: 0,
            store: store.clone(),
            sessions,
            login,
            registry: registry.clone(),
            web: WebDir(web),
            health: Arc::new(Health::new(store.clone(), directory, true)),
            api_keys: Arc::new(
                ApiKeys::new(store.clone(), clock.clone(), ApiKeyParams::TEST).unwrap(),
            ),
            mcp_sessions: Arc::new(McpSessions::new()),
        }));
        let anchor = Arc::new(AnchorWriter::new(store.clone(), registry.clone(), clock));
        anchor
            .start(&json!({"version": "test", "mode": "test"}))
            .unwrap();
        let app = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        TestServer {
            base,
            state,
            store,
            registry,
            anchor,
            mock: jira_mock().await,
            dir,
            http: reqwest::Client::builder().timeout(LIMIT).build().unwrap(),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn headers(&self, b: Option<&Browser>, changing: bool) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(b) = b {
            h.insert(
                "cookie",
                HeaderValue::from_str(&format!("{COOKIE}={}", b.cookie)).unwrap(),
            );
            if changing {
                h.insert("x-csrf-token", HeaderValue::from_str(&b.csrf).unwrap());
            }
        }
        if changing {
            h.insert("origin", HeaderValue::from_str(&self.base).unwrap());
        }
        h
    }

    pub async fn login(&self, (user, pw): (&str, &str)) -> Browser {
        let res = self
            .http
            .post(self.url("/api/login"))
            .headers(self.headers(None, true))
            .json(&json!({"username": user, "password": pw}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "login {user}");
        let set = res.headers()["set-cookie"].to_str().unwrap().to_owned();
        let cookie = set
            .strip_prefix(&format!("{COOKIE}="))
            .and_then(|r| r.split(';').next())
            .unwrap()
            .to_owned();
        let body: Value = res.json().await.unwrap();
        Browser {
            cookie,
            csrf: body["csrf_token"].as_str().unwrap().to_owned(),
        }
    }

    /// A request from a browser: state-changing methods carry Origin and its CSRF token.
    pub async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        b: Option<&Browser>,
        body: Option<Value>,
    ) -> (u16, Value) {
        let changing = method != reqwest::Method::GET;
        let mut req = self
            .http
            .request(method, self.url(path))
            .headers(self.headers(b, changing));
        if let Some(body) = body {
            req = req.json(&body);
        }
        let res = req.send().await.unwrap();
        let status = res.status().as_u16();
        let text = res.text().await.unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    pub async fn cmd(&self, b: &Browser, name: &str, body: Value) -> (u16, Value) {
        self.send(
            reqwest::Method::POST,
            &format!("/api/cmd/{name}"),
            Some(b),
            Some(body),
        )
        .await
    }

    /// Admin `carol` adds the Jira mock as `work` (the default Jira).
    pub async fn add_work(&self) {
        let carol = self.login(CAROL).await;
        let (s, v) = self
            .send(
                reqwest::Method::POST,
                "/api/admin/instances",
                Some(&carol),
                Some(json!({"alias": "work", "product": "jira",
                            "base_url": self.mock.base_url(), "proxy": "direct",
                            "is_default": true})),
            )
            .await;
        assert_eq!(s, 201, "{v}");
    }

    /// The user stores the test PAT for `work` (the real credential check against the mock).
    pub async fn store_pat(&self, b: &Browser, pat: &str) {
        let (s, v) = self
            .send(
                reqwest::Method::PUT,
                "/api/me/pats/work",
                Some(b),
                Some(json!({"pat": pat})),
            )
            .await;
        assert_eq!(s, 200, "{v}");
    }

    /// A new API key: `(id, key)`.
    pub async fn api_key(&self, b: &Browser, scopes: &[&str]) -> (String, String) {
        let (s, v) = self
            .send(
                reqwest::Method::POST,
                "/api/me/api-keys",
                Some(b),
                Some(json!({"name": "agent", "scopes": scopes})),
            )
            .await;
        assert_eq!(s, 201, "{v}");
        (
            v["id"].as_str().unwrap().to_owned(),
            v["key"].as_str().unwrap().to_owned(),
        )
    }

    pub async fn mcp(&self, key: &str) -> RunningService<RoleClient, ()> {
        let transport = StreamableHttpClientTransport::from_config(
            StreamableHttpClientTransportConfig::with_uri(self.url("/mcp"))
                .auth_header(key.to_owned()),
        );
        tokio::time::timeout(LIMIT, ().serve(transport))
            .await
            .expect("initialize hung")
            .unwrap()
    }

    /// Polls `queue_list` until it holds `n` items.
    pub async fn queue_of(&self, b: &Browser, n: usize) -> Value {
        let mut q = Value::Null;
        for _ in 0..300 {
            q = self.cmd(b, "queue_list", json!({})).await.1;
            if q.as_array().is_some_and(|a| a.len() >= n) {
                return q;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("queue never reached {n}: {q}");
    }
}

pub async fn call(c: &RunningService<RoleClient, ()>, tool: &str, args: Value) -> CallToolResult {
    let params = CallToolRequestParams::new(tool.to_owned())
        .with_arguments(args.as_object().cloned().unwrap_or_default());
    tokio::time::timeout(LIMIT * 3, c.call_tool(params))
        .await
        .expect("tool call hung")
        .unwrap()
}

pub fn envelope(r: &CallToolResult) -> Value {
    r.structured_content.clone().unwrap_or(Value::Null)
}

/// The comment an agent proposes on `ABC-1`.
pub fn comment_args() -> Value {
    json!({"key": "ABC-1", "body": "Seen on staging.", "body_format": "wiki", "reason": "triage"})
}
