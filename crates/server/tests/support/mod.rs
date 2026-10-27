//! The in-process test server of the integration suites (T23, T24): the full router on
//! `127.0.0.1:0` with a temp SQLite store, the stub directory (`alice`, `bob`, `carol` the admin,
//! `dave` the auditor), a test master key, plain-HTTP cookies (`cookie_secure = false`, the name
//! without `__Host-`) and an Atlassian mock as Jira. Requests carry real cookies, CSRF tokens
//! and Origin headers. Every wait is bounded.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

pub mod oauth_client;

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
use atlas_duck_server::oauth::{OAuth, OAuthConfig};
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
    /// Every response body (and recorded tool result) of the run, for the secret sweep; the
    /// one create-key answer is left out.
    pub transcript: std::sync::Mutex<Vec<String>>,
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
                data_dir: data.clone(),
                store: store.clone(),
                master: master.clone(),
                org_ca: None,
                clock: clock.clone(),
                allow_http: true,
                sse_capacity: SSE_CAPACITY,
                scripts: None,
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
        let anchor = Arc::new(AnchorWriter::new(
            store.clone(),
            registry.clone(),
            clock.clone(),
        ));
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
            clock: clock.clone(),
            anchor: anchor.clone(),
            oauth: Arc::new(OAuth::new(OAuthConfig::DEFAULT, &base)),
            exports: Arc::new(atlas_duck_server::export_job::ExportJobs::new(
                store.clone(),
                registry.clone(),
                anchor.clone(),
                clock.clone(),
                &data,
                &base,
                atlas_duck_server::export_job::ExportConfig::DEFAULT,
            )),
        }));
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
            transcript: std::sync::Mutex::new(Vec::new()),
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

    pub fn record(&self, text: &str) {
        self.transcript.lock().unwrap().push(text.to_owned());
    }

    /// A request from a browser: state-changing methods carry Origin and its CSRF token.
    pub async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        b: Option<&Browser>,
        body: Option<Value>,
    ) -> (u16, Value) {
        self.send_rec(method, path, b, body, true).await
    }

    /// [`Self::send`] with extra request headers (spoofing probes).
    pub async fn send_with(
        &self,
        method: reqwest::Method,
        path: &str,
        b: Option<&Browser>,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> (u16, Value) {
        self.send_full(method, path, b, body, true, extra).await
    }

    async fn send_rec(
        &self,
        method: reqwest::Method,
        path: &str,
        b: Option<&Browser>,
        body: Option<Value>,
        record: bool,
    ) -> (u16, Value) {
        self.send_full(method, path, b, body, record, &[]).await
    }

    async fn send_full(
        &self,
        method: reqwest::Method,
        path: &str,
        b: Option<&Browser>,
        body: Option<Value>,
        record: bool,
        extra: &[(&str, &str)],
    ) -> (u16, Value) {
        let changing = method != reqwest::Method::GET;
        let mut req = self
            .http
            .request(method, self.url(path))
            .headers(self.headers(b, changing));
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let res = req.send().await.unwrap();
        let status = res.status().as_u16();
        let text = res.text().await.unwrap_or_default();
        if record {
            self.record(&text);
        }
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
        // The one answer that carries the key: not part of the transcript.
        let (s, v) = self
            .send_rec(
                reqwest::Method::POST,
                "/api/me/api-keys",
                Some(b),
                Some(json!({"name": "agent", "scopes": scopes})),
                false,
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

/// What the exit-criterion flow leaves behind.
pub struct Flow {
    pub alice: Browser,
    pub key: String,
    pub read_id: String,
    pub write_id: String,
}

/// The candidate revision of a queued request, from its preview.
async fn rev_of(s: &TestServer, b: &Browser, id: &str) -> Value {
    let (status, p) = s.cmd(b, "preview_fetch", json!({"request_id": id})).await;
    assert_eq!(status, 200, "{p}");
    p["preview"]["candidate_rev"].clone()
}

/// The master plan's M12 exit flow over HTTP: the admin adds Jira; alice signs in, stores `pat`
/// and creates an API key; her MCP agent lists ops, reads `ABC-1` (released in the browser) and
/// proposes a comment, which pends with its approval URL until alice approves it in the browser;
/// the agent's `request_await` then answers `succeeded` and the mock got exactly one write with
/// alice's PAT.
pub async fn exit_flow(s: &TestServer, pat: &str) -> Flow {
    s.add_work().await;
    let alice = s.login(ALICE).await;
    s.store_pat(&alice, pat).await;
    let (_, key) = s.api_key(&alice, &["read", "propose_write"]).await;
    let agent = Arc::new(s.mcp(&key).await);
    let rec = |r: &CallToolResult| s.record(&serde_json::to_string(r).unwrap());

    let ops = call(&agent, "ops_list", json!({})).await;
    rec(&ops);
    assert_eq!(envelope(&ops)["status"], "succeeded");

    // A read: pending until alice releases it, then the data.
    let reading = {
        let agent = agent.clone();
        tokio::spawn(async move { call(&agent, "jira_issue_get", json!({"key": "ABC-1"})).await })
    };
    let q = s.queue_of(&alice, 1).await;
    let read_id = q[0]["request_id"].as_str().unwrap().to_owned();
    let rev = rev_of(s, &alice, &read_id).await;
    let (status, out) = s
        .cmd(
            &alice,
            "decide",
            json!({"request_id": read_id, "decision": "release", "candidate_rev": rev}),
        )
        .await;
    assert_eq!(status, 200, "{out}");
    let read = tokio::time::timeout(LIMIT, reading)
        .await
        .expect("read hung")
        .unwrap();
    rec(&read);
    let env = envelope(&read);
    assert_eq!(env["status"], "released", "{env}");
    assert!(env["data"].to_string().contains("ABC-1"), "{env}");

    // A write: pending with its approval URL, approved in the browser.
    let writing = {
        let agent = agent.clone();
        tokio::spawn(async move { call(&agent, "jira_comment_add", comment_args()).await })
    };
    let mut write_id = String::new();
    for _ in 0..300 {
        let q = s.cmd(&alice, "queue_list", json!({})).await.1;
        if let Some(row) = q
            .as_array()
            .and_then(|a| a.iter().find(|r| r["request_id"] != read_id.as_str()))
        {
            write_id = row["request_id"].as_str().unwrap().to_owned();
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!write_id.is_empty(), "the write never queued");
    let status = call(&agent, "request_status", json!({"request_id": write_id})).await;
    rec(&status);
    let env = envelope(&status);
    assert_eq!(env["status"], "pending", "{env}");
    assert_eq!(
        env["meta"]["approval_url"],
        format!("{}/approvals?item={write_id}", s.base)
    );
    let rev = rev_of(s, &alice, &write_id).await;
    let (status, out) = s
        .cmd(
            &alice,
            "decide",
            json!({"request_id": write_id, "decision": "approve", "candidate_rev": rev}),
        )
        .await;
    assert_eq!(status, 200, "{out}");
    let wrote = tokio::time::timeout(LIMIT * 3, writing)
        .await
        .expect("write hung")
        .unwrap();
    rec(&wrote);
    assert_eq!(
        envelope(&wrote)["status"],
        "succeeded",
        "{:?}",
        envelope(&wrote)
    );
    let awaited = call(&agent, "request_await", json!({"request_id": write_id})).await;
    rec(&awaited);
    assert_eq!(
        envelope(&awaited)["status"],
        "succeeded",
        "{:?}",
        envelope(&awaited)
    );

    let writes: Vec<_> = s
        .mock
        .received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
        .collect();
    assert_eq!(writes.len(), 1, "exactly one write reached Jira");
    assert_eq!(writes[0].url.path(), "/rest/api/2/issue/ABC-1/comment");
    assert_eq!(
        writes[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("Bearer {pat}")
    );
    Flow {
        alice,
        key,
        read_id,
        write_id,
    }
}
