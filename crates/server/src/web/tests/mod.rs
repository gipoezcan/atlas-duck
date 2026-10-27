//! Login, sessions, CSRF and Origin through the in-process router (`tower::ServiceExt::oneshot`),
//! the stub directory and a SQLite store in a temp dir. Time moves through a manual clock.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::Response;
use serde_json::{Map, Value, json};
use tower::ServiceExt;

use super::{AppInner, AppState, client_ip, router};
use crate::clock::ManualClock;
use crate::config::Groups;
use crate::directory::stub::StubDirectory;
use crate::errors::ApiError;
use crate::login::{LoginService, LoginSink};
use crate::master_key::MasterKey;
use crate::ratelimit::LoginLimiter;
use crate::session::SessionTable;
use crate::store::ServerStore;
use crate::store::sqlite::SqliteStore;
use crate::users::user_id_for;

/// M14 T16: the own-chain audit reads.
mod audit;
/// M14 T17: auditor reads.
mod auditor;
/// `/mcp` (T19) over the same harness.
mod mcp;
/// M14: OAuth discovery, registration, authorization, tokens.
mod oauth;

const ORIGIN: &str = "https://duck.example.test";
const T0: i64 = 1_800_000_000;
const PW_CANARY: &str = "pw-canary-7f3a9c";
const LIMIT: Duration = Duration::from_secs(30);

const STUB: &str = r#"{"users": [
  {"username": "alice", "password": "pw-canary-7f3a9c", "groups": ["CN=Users,DC=t"]},
  {"username": "bob", "password": "pw-bob", "groups": ["cn=users,dc=t", "cn=admins,dc=t"]},
  {"username": "audrey", "password": "pw-audrey", "groups": ["cn=auditors,dc=t"]},
  {"username": "vera", "password": "pw-vera", "groups": ["cn=users,dc=t", "cn=auditors,dc=t"]},
  {"username": "ursula", "password": "pw-ursula", "groups": ["cn=other,dc=t"]},
  {"username": "dora", "password": "pw-dora", "groups": ["cn=users,dc=t"], "disabled": true}
]}"#;

#[derive(Default)]
struct RecSink {
    created: Mutex<Vec<String>>,
    logins: Mutex<Vec<(String, Map<String, Value>)>>,
}

#[async_trait]
impl LoginSink for RecSink {
    async fn user_created(&self, user_id: &str) -> Result<(), ApiError> {
        self.created.lock().unwrap().push(user_id.to_owned());
        Ok(())
    }
    async fn login_recorded(
        &self,
        user_id: &str,
        payload: Map<String, Value>,
    ) -> Result<(), ApiError> {
        self.logins
            .lock()
            .unwrap()
            .push((user_id.to_owned(), payload));
        Ok(())
    }
}

/// M14 harness options.
struct Opts {
    oauth: crate::oauth::OAuthConfig,
    scripts: Option<Arc<crate::scripts::ServerScripts>>,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts {
            oauth: crate::oauth::OAuthConfig::DEFAULT,
            scripts: None,
        }
    }
}

struct H {
    router: Router,
    state: AppState,
    registry: Arc<crate::runtime::Registry>,
    clock: Arc<ManualClock>,
    stub: Arc<StubDirectory>,
    sink: Arc<RecSink>,
    store: Arc<dyn ServerStore>,
    db: PathBuf,
    dir: tempfile::TempDir,
}

fn groups() -> Groups {
    Groups {
        users: "cn=users,dc=t".into(),
        auditors: Some("cn=auditors,dc=t".into()),
        admins: Some("cn=admins,dc=t".into()),
    }
}

impl H {
    fn new() -> H {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("server.db");
        let store: Arc<dyn ServerStore> = Arc::new(SqliteStore::open(&db).unwrap());
        Self::over(dir, db, store, ManualClock::at(T0))
    }

    /// [H::new] with an OAuth configuration of its own (M14).
    fn with_oauth(cfg: crate::oauth::OAuthConfig) -> H {
        Self::with(Opts {
            oauth: cfg,
            ..Opts::default()
        })
    }

    /// [H::new] with M14 options (OAuth configuration, script state).
    fn with(opts: Opts) -> H {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("server.db");
        let store: Arc<dyn ServerStore> = Arc::new(SqliteStore::open(&db).unwrap());
        Self::over_with(dir, db, store, ManualClock::at(T0), opts)
    }

    /// A fresh router (and session table) over the same store and clock: a restart.
    fn restart(self) -> H {
        let store: Arc<dyn ServerStore> = Arc::new(SqliteStore::open(&self.db).unwrap());
        Self::over(self.dir, self.db, store, self.clock)
    }

    fn over(
        dir: tempfile::TempDir,
        db: PathBuf,
        store: Arc<dyn ServerStore>,
        clock: Arc<ManualClock>,
    ) -> H {
        Self::over_with(dir, db, store, clock, Opts::default())
    }

    fn over_with(
        dir: tempfile::TempDir,
        db: PathBuf,
        store: Arc<dyn ServerStore>,
        clock: Arc<ManualClock>,
        opts: Opts,
    ) -> H {
        let Opts { oauth, scripts } = opts;
        let stub = Arc::new(StubDirectory::from_json(STUB).unwrap());
        let sink = Arc::new(RecSink::default());
        let sessions =
            Arc::new(SessionTable::new(store.clone(), clock.clone(), 28_800, 1_800).unwrap());
        let login = LoginService {
            store: store.clone(),
            master: Arc::new(MasterKey::for_tests("k1", [5; 32])),
            directory: stub.clone(),
            limiter: Arc::new(LoginLimiter::new(5, 20, 900)),
            sessions: sessions.clone(),
            groups: groups(),
            clock: clock.clone(),
            sink: sink.clone(),
        };
        let web = dir.path().join("web");
        let _ = std::fs::create_dir_all(web.join("assets"));
        let _ = std::fs::write(
            web.join("login.html"),
            "<!doctype html><title>login</title>",
        );
        let _ = std::fs::write(web.join("assets").join("app-1a2b.js"), "console.log(1)");
        let _ = std::fs::write(dir.path().join("secret.txt"), "not served");
        let registry = Arc::new(crate::runtime::Registry::new(
            crate::runtime::RuntimeDeps {
                data_dir: dir.path().join("data"),
                store: store.clone(),
                master: Arc::new(MasterKey::for_tests("k1", [5; 32])),
                org_ca: None,
                clock: clock.clone(),
                allow_http: true,
                sse_capacity: crate::runtime::SSE_CAPACITY,
                scripts,
            },
            10,
        ));
        let state = AppState(Arc::new(AppInner {
            public_origin: ORIGIN.into(),
            cookie_secure: true,
            trusted_proxy_hops: 1,
            store: store.clone(),
            sessions,
            login,
            registry: registry.clone(),
            web: crate::static_files::WebDir(web),
            health: Arc::new(crate::health::Health::new(
                store.clone(),
                stub.clone(),
                true,
            )),
            api_keys: Arc::new(
                crate::api_keys::ApiKeys::new(
                    store.clone(),
                    clock.clone(),
                    crate::api_keys::ApiKeyParams::TEST,
                )
                .unwrap(),
            ),
            mcp_sessions: Arc::new(crate::mcp::McpSessions::new()),
            clock: clock.clone(),
            anchor: Arc::new(crate::anchor::AnchorWriter::new(
                store.clone(),
                registry.clone(),
                clock.clone(),
            )),
            oauth: Arc::new(crate::oauth::OAuth::new(oauth, ORIGIN)),
        }));
        H {
            router: router(state.clone()),
            state,
            registry,
            clock,
            stub,
            sink,
            store,
            db,
            dir,
        }
    }

    async fn send(&self, req: Request<Body>) -> Response {
        tokio::time::timeout(LIMIT, self.router.clone().oneshot(req))
            .await
            .expect("request hung")
            .unwrap()
    }

    async fn login_from(&self, user: &str, pw: &str, ip: &str) -> Response {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/login")
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-forwarded-for", ip)
            .body(Body::from(
                json!({"username": user, "password": pw}).to_string(),
            ))
            .unwrap();
        self.send(req).await
    }

    async fn login(&self, user: &str, pw: &str) -> Response {
        self.login_from(user, pw, "192.0.2.10").await
    }

    /// Logs in and answers `(cookie value, csrf token)`.
    async fn session(&self, user: &str, pw: &str) -> (String, String) {
        let res = self.login(user, pw).await;
        assert_eq!(res.status(), StatusCode::OK);
        let cookie = set_cookie(&res);
        let body = json_body(res).await;
        let id = cookie
            .strip_prefix("__Host-atlas_duck_session=")
            .and_then(|r| r.split(';').next())
            .unwrap()
            .to_owned();
        (id, body["csrf_token"].as_str().unwrap().to_owned())
    }

    async fn get_session(&self, cookie: &str) -> Response {
        let req = Request::builder()
            .uri("/api/session")
            .header(
                header::COOKIE,
                format!("__Host-atlas_duck_session={cookie}"),
            )
            .body(Body::empty())
            .unwrap();
        self.send(req).await
    }

    async fn logout(&self, cookie: &str, csrf: Option<&str>, origin: Option<&str>) -> Response {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/api/logout")
            .header(
                header::COOKIE,
                format!("__Host-atlas_duck_session={cookie}"),
            );
        if let Some(c) = csrf {
            b = b.header("x-csrf-token", c);
        }
        if let Some(o) = origin {
            b = b.header(header::ORIGIN, o);
        }
        self.send(b.body(Body::empty()).unwrap()).await
    }

    /// The bytes of the database and its WAL.
    fn db_bytes(&self) -> Vec<u8> {
        let mut out = std::fs::read(&self.db).unwrap();
        let wal = self.db.with_extension("db-wal");
        if let Ok(w) = std::fs::read(wal) {
            out.extend(w);
        }
        out
    }
}

fn set_cookie(res: &Response) -> String {
    res.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_owned()
}

async fn json_body(res: Response) -> Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn code(res: Response) -> (StatusCode, String) {
    let status = res.status();
    let v = json_body(res).await;
    (status, v["error"]["code"].as_str().unwrap_or("").to_owned())
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn login_success_sets_cookie_with_exact_attributes() {
    let h = H::new();
    let res = h.login("Alice", PW_CANARY).await;
    assert_eq!(res.status(), StatusCode::OK);
    let cookie = set_cookie(&res);
    let (name_value, attrs) = cookie.split_once("; ").unwrap();
    let value = name_value
        .strip_prefix("__Host-atlas_duck_session=")
        .unwrap();
    assert_eq!(value.len(), 43, "32 bytes base64url");
    assert!(
        value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
    assert_eq!(attrs, "HttpOnly; Secure; SameSite=Strict; Path=/");
    let body = json_body(res).await;
    assert_eq!(body["user"], "alice");
    assert_eq!(body["roles"], json!(["user"]));
    assert_eq!(body["expires_at"], crate::clock::rfc3339(T0 + 28_800));
    assert_eq!(body["csrf_token"].as_str().unwrap().len(), 43);
    // First login: the user row, its store, the LOGIN record in the user's chain.
    let uid = user_id_for("alice");
    assert_eq!(*h.sink.created.lock().unwrap(), std::slice::from_ref(&uid));
    let logins = h.sink.logins.lock().unwrap();
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].0, uid);
    assert_eq!(
        Value::Object(logins[0].1.clone()),
        json!({"method": "password", "outcome": "success", "roles": ["user"],
               "source_ip": "192.0.2.10", "directory": "stub"})
    );
    assert!(h.store.user(&uid).unwrap().is_some());
}

#[tokio::test]
async fn second_login_does_not_recreate_the_user() {
    let h = H::new();
    h.session("alice", PW_CANARY).await;
    h.session("alice", PW_CANARY).await;
    assert_eq!(h.sink.created.lock().unwrap().len(), 1);
    assert_eq!(h.sink.logins.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn sixth_failure_for_a_username_is_limited_without_a_bind() {
    let h = H::new();
    for i in 0..5 {
        let (s, c) = code(
            h.login_from("alice", "wrong", &format!("198.51.100.{i}"))
                .await,
        )
        .await;
        assert_eq!(
            (s, c.as_str()),
            (StatusCode::UNAUTHORIZED, "auth/invalid_credentials")
        );
    }
    let res = h.login_from("alice", PW_CANARY, "198.51.100.99").await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(res.headers()[header::RETRY_AFTER], "900");
    assert_eq!(code(res).await.1, "auth/rate_limited");
    assert_eq!(
        h.stub.calls(),
        5,
        "the limited attempt never reached the directory"
    );
}

/// A directory that answers after a delay and counts its binds.
struct SlowDirectory {
    inner: Arc<StubDirectory>,
    calls: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl crate::directory::Directory for SlowDirectory {
    async fn authenticate(
        &self,
        username: &str,
        password: &secrecy::SecretString,
    ) -> Result<crate::directory::DirectoryUser, crate::directory::DirectoryError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(200)).await;
        self.inner.authenticate(username, password).await
    }
    async fn probe(&self) -> Result<(), crate::directory::DirectoryError> {
        Ok(())
    }
    fn kind(&self) -> &'static str {
        "stub"
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_failures_never_exceed_the_username_limit() {
    // Batch-2 review I1: the check and the count are one step, so ten parallel attempts with a
    // slow directory reach it at most five times.
    let h = H::new();
    let slow = Arc::new(SlowDirectory {
        inner: h.stub.clone(),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let l = &h.state.login;
    let svc = Arc::new(LoginService {
        store: l.store.clone(),
        master: l.master.clone(),
        directory: slow.clone(),
        limiter: Arc::new(LoginLimiter::new(5, 20, 900)),
        sessions: l.sessions.clone(),
        groups: l.groups.clone(),
        clock: l.clock.clone(),
        sink: l.sink.clone(),
    });
    let mut tasks = Vec::new();
    for i in 0..10 {
        let svc = svc.clone();
        tasks.push(tokio::spawn(async move {
            svc.login(
                "alice",
                secrecy::SecretString::from("wrong".to_owned()),
                &format!("198.51.100.{i}"),
            )
            .await
            .map(|_| ())
        }));
    }
    let results = tokio::time::timeout(LIMIT, futures::future::join_all(tasks))
        .await
        .expect("logins hung");
    let limited = results
        .iter()
        .filter(|r| matches!(r, Ok(Err(e)) if e.code == "auth/rate_limited"))
        .count();
    let calls = slow.calls.load(std::sync::atomic::Ordering::SeqCst);
    assert!(calls <= 5, "directory reached {calls} times");
    assert_eq!(limited, 10 - calls);
}

#[tokio::test]
async fn twenty_one_failures_from_one_ip_are_limited() {
    let h = H::new();
    for i in 0..20 {
        let res = h.login_from(&format!("user{i}"), "x", "203.0.113.9").await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    let res = h.login_from("alice", PW_CANARY, "203.0.113.9").await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    // Another address is not limited.
    assert_eq!(
        h.login_from("alice", PW_CANARY, "203.0.113.10")
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn success_resets_the_username_window() {
    let h = H::new();
    for _ in 0..4 {
        h.login("alice", "wrong").await;
    }
    assert_eq!(h.login("alice", PW_CANARY).await.status(), StatusCode::OK);
    for _ in 0..5 {
        assert_eq!(
            h.login_from("alice", "wrong", "192.0.2.77").await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn empty_password_is_400_without_bind_or_count() {
    let h = H::new();
    for _ in 0..7 {
        let (s, c) = code(h.login("alice", "").await).await;
        assert_eq!(
            (s, c.as_str()),
            (StatusCode::BAD_REQUEST, "auth/empty_password")
        );
    }
    assert_eq!(h.stub.calls(), 0);
    assert_eq!(h.login("alice", PW_CANARY).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn bad_username_shape_never_binds() {
    let h = H::new();
    let (s, c) = code(h.login("*)(uid=*", "x").await).await;
    assert_eq!(
        (s, c.as_str()),
        (StatusCode::UNAUTHORIZED, "auth/invalid_credentials")
    );
    assert_eq!(h.stub.calls(), 0);
}

#[tokio::test]
async fn roles_need_the_users_group_and_are_additive() {
    let h = H::new();
    for user in ["ursula", "audrey", "dora"] {
        let (s, c) = code(h.login(user, &format!("pw-{user}")).await).await;
        assert_eq!(
            (s, c.as_str()),
            (StatusCode::FORBIDDEN, "auth/not_permitted"),
            "{user}"
        );
    }
    let body = json_body(h.login("bob", "pw-bob").await).await;
    assert_eq!(body["roles"], json!(["user", "admin"]));
}

#[tokio::test]
async fn idle_expiry_after_30_minutes() {
    let h = H::new();
    let (cookie, _) = h.session("alice", PW_CANARY).await;
    h.clock.advance(1_799);
    assert_eq!(h.get_session(&cookie).await.status(), StatusCode::OK);
    h.clock.advance(1_800);
    let (s, c) = code(h.get_session(&cookie).await).await;
    assert_eq!(
        (s, c.as_str()),
        (StatusCode::UNAUTHORIZED, "auth/session_expired")
    );
    // Gone for good.
    assert_eq!(
        code(h.get_session(&cookie).await).await.1,
        "auth/no_session"
    );
}

#[tokio::test]
async fn absolute_expiry_after_8_hours_even_when_active() {
    let h = H::new();
    let (cookie, _) = h.session("alice", PW_CANARY).await;
    for _ in 0..23 {
        h.clock.advance(1_200);
        assert_eq!(h.get_session(&cookie).await.status(), StatusCode::OK);
    }
    // 27 600 s so far; past 28 800 the session ends however active it is.
    h.clock.advance(1_200);
    assert_eq!(
        code(h.get_session(&cookie).await).await.1,
        "auth/session_expired"
    );
}

#[tokio::test]
async fn session_answer_shape() {
    let h = H::new();
    let (cookie, csrf) = h.session("bob", "pw-bob").await;
    h.clock.advance(100);
    let res = h.get_session(&cookie).await;
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    let body = json_body(res).await;
    assert_eq!(body["user"], "bob");
    assert_eq!(body["csrf_token"], csrf);
    assert_eq!(
        body["idle_expires_at"],
        crate::clock::rfc3339(T0 + 100 + 1_800)
    );
}

#[tokio::test]
async fn logout_then_reuse_is_401() {
    let h = H::new();
    let (cookie, csrf) = h.session("alice", PW_CANARY).await;
    let res = h.logout(&cookie, Some(&csrf), Some(ORIGIN)).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(set_cookie(&res).contains("Max-Age=0"));
    assert_eq!(
        code(h.get_session(&cookie).await).await.1,
        "auth/no_session"
    );
    assert!(h.store.sessions_all().unwrap().is_empty());
}

#[tokio::test]
async fn logout_needs_the_origin_and_the_csrf_token() {
    let h = H::new();
    let (cookie, csrf) = h.session("alice", PW_CANARY).await;
    for origin in [
        None,
        Some("https://evil.example.test"),
        Some("http://duck.example.test"),
    ] {
        let (s, c) = code(h.logout(&cookie, Some(&csrf), origin).await).await;
        assert_eq!(
            (s, c.as_str()),
            (StatusCode::FORBIDDEN, "auth/origin_mismatch"),
            "{origin:?}"
        );
    }
    for token in [None, Some("wrong"), Some("")] {
        let (s, c) = code(h.logout(&cookie, token, Some(ORIGIN)).await).await;
        assert_eq!(
            (s, c.as_str()),
            (StatusCode::FORBIDDEN, "auth/csrf_mismatch"),
            "{token:?}"
        );
    }
    // Still signed in.
    assert_eq!(h.get_session(&cookie).await.status(), StatusCode::OK);
    // A login from another origin is refused before the body is read.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/login")
        .header(header::ORIGIN, "https://evil.example.test")
        .body(Body::from("not json"))
        .unwrap();
    assert_eq!(code(h.send(req).await).await.1, "auth/origin_mismatch");
}

#[tokio::test]
async fn bearer_is_refused_on_cmd_and_me() {
    let h = H::new();
    let (cookie, csrf) = h.session("alice", PW_CANARY).await;
    for (method, uri) in [
        (Method::POST, "/api/cmd/decide"),
        (Method::GET, "/api/me/api-keys"),
        (Method::PUT, "/api/me/pats/work"),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, "Bearer adk_abcdefgh_secret")
            .header(
                header::COOKIE,
                format!("__Host-atlas_duck_session={cookie}"),
            )
            .header("x-csrf-token", &csrf)
            .header(header::ORIGIN, ORIGIN)
            .body(Body::empty())
            .unwrap();
        let (s, c) = code(h.send(req).await).await;
        assert_eq!(
            (s, c.as_str()),
            (StatusCode::FORBIDDEN, "auth/bearer_not_accepted"),
            "{uri}"
        );
    }
}

#[tokio::test]
async fn state_changing_without_session_is_401() {
    let h = H::new();
    let res = h
        .logout("unknown-session-id", Some("x"), Some(ORIGIN))
        .await;
    assert_eq!(
        code(res).await,
        (StatusCode::UNAUTHORIZED, "auth/no_session".to_owned())
    );
}

#[tokio::test]
async fn body_limits_and_bad_bodies() {
    let h = H::new();
    let big = "x".repeat(super::BODY_LIMIT + 1);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/login")
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_LENGTH, big.len())
        .body(Body::from(big.clone()))
        .unwrap();
    assert_eq!(
        code(h.send(req).await).await,
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            "api/body_too_large".to_owned()
        )
    );
    // Without a Content-Length the read itself stops at the limit.
    let stream = futures::stream::iter(vec![Ok::<_, std::io::Error>(axum::body::Bytes::from(big))]);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/login")
        .header(header::ORIGIN, ORIGIN)
        .body(Body::from_stream(stream))
        .unwrap();
    assert_eq!(code(h.send(req).await).await.1, "api/body_too_large");
    for body in [
        "not json",
        r#"{"username": "alice"}"#,
        r#"{"username": "a", "password": "b", "x": 1}"#,
    ] {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/login")
            .header(header::ORIGIN, ORIGIN)
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            code(h.send(req).await).await,
            (StatusCode::BAD_REQUEST, "api/bad_request".to_owned()),
            "{body}"
        );
    }
}

#[tokio::test]
async fn restart_keeps_the_session() {
    let h = H::new();
    let (cookie, _) = h.session("alice", PW_CANARY).await;
    let h = h.restart();
    h.clock.advance(10);
    assert_eq!(h.get_session(&cookie).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_database_holds_the_id_hash_never_the_id_or_the_password() {
    let h = H::new();
    let (cookie, _) = h.session("alice", PW_CANARY).await;
    h.login("alice", "pw-wrong-canary-1d2e").await;
    h.login_from("nobody", "pw-unknown-canary-9b8a", "192.0.2.200")
        .await;
    let rows = h.store.sessions_all().unwrap();
    assert_eq!(rows.len(), 1);
    let want: [u8; 32] = sha2::Digest::finalize(sha2::Digest::chain_update(
        <sha2::Sha256 as sha2::Digest>::new(),
        cookie.as_bytes(),
    ))
    .into();
    assert_eq!(rows[0].id_hash, want);
    let bytes = h.db_bytes();
    for canary in [
        cookie.as_str(),
        PW_CANARY,
        "pw-wrong-canary-1d2e",
        "pw-unknown-canary-9b8a",
    ] {
        assert!(
            !contains(&bytes, canary.as_bytes()),
            "{canary} found in the database"
        );
    }
}

#[tokio::test]
async fn failures_go_to_the_anchor_chain_without_the_password() {
    let h = H::new();
    h.login_from("alice", "pw-wrong-canary-1d2e", "192.0.2.5")
        .await;
    h.login("ursula", "pw-ursula").await;
    let rows = h.store.anchor_all().unwrap();
    let bodies: Vec<Value> = rows
        .iter()
        .map(|r| serde_json::from_slice(&r.body_jcs).unwrap())
        .collect();
    assert!(rows.iter().all(|r| r.kind == "LOGIN_FAILED"));
    assert_eq!(
        bodies,
        [
            json!({"username": "alice", "source_ip": "192.0.2.5", "reason": "invalid_credentials"}),
            json!({"username": "ursula", "source_ip": "192.0.2.10", "reason": "not_permitted"}),
        ]
    );
    assert!(!contains(&h.db_bytes(), b"pw-wrong-canary-1d2e"));
}

/// An invalid username of any length keys the limiter by its first 64 characters only.
#[tokio::test]
async fn huge_invalid_usernames_cost_a_bounded_limiter_key() {
    let h = H::new();
    let long = format!("{}*", "A".repeat(10_000));
    for _ in 0..5 {
        assert_eq!(h.login(&long, "x").await.status(), StatusCode::UNAUTHORIZED);
    }
    // The same 64-character prefix is the same key: the 6th attempt is limited.
    let other_tail = format!("{})", "a".repeat(9_000));
    assert_eq!(
        h.login_from(&other_tail, "x", "192.0.2.99").await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(crate::login::limiter_key(&long), "a".repeat(64));
    assert_eq!(h.stub.calls(), 0);
}

/// Global Constraints: on /api/cmd and /api/me the bearer refusal precedes every other check.
#[tokio::test]
async fn bearer_refusal_precedes_size_origin_and_session() {
    let h = H::new();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/cmd/decide")
        .header(header::AUTHORIZATION, "Bearer x")
        .header(header::CONTENT_LENGTH, super::BODY_LIMIT + 1)
        .body(Body::from("x".repeat(super::BODY_LIMIT + 1)))
        .unwrap();
    assert_eq!(code(h.send(req).await).await.1, "auth/bearer_not_accepted");
}

/// Review M1: an entry that is not an IP address is never used; the peer address is.
#[test]
fn client_ip_must_be_an_ip_address() {
    use axum::http::HeaderMap;
    let peer = Some("10.0.0.1:5555".parse().unwrap());
    for forged in [
        "9".repeat(500),
        "evil, not-an-ip".into(),
        "1.2.3.4.5".into(),
    ] {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", forged.parse().unwrap());
        assert_eq!(client_ip(&h, peer, 1), "10.0.0.1", "{forged}");
    }
    let mut h = HeaderMap::new();
    h.insert("x-forwarded-for", "2001:db8::1".parse().unwrap());
    assert_eq!(client_ip(&h, peer, 1), "2001:db8::1");
}

#[test]
fn client_ip_from_forwarded_for() {
    use axum::http::HeaderMap;
    let mut h = HeaderMap::new();
    let peer = Some("10.0.0.1:5555".parse().unwrap());
    assert_eq!(client_ip(&h, peer, 1), "10.0.0.1");
    h.insert("x-forwarded-for", "198.51.100.1, 10.1.1.1".parse().unwrap());
    assert_eq!(client_ip(&h, peer, 1), "10.1.1.1");
    assert_eq!(client_ip(&h, peer, 2), "198.51.100.1");
    // Fewer entries than trusted hops: the leftmost is client text, the peer is used.
    assert_eq!(client_ip(&h, peer, 3), "10.0.0.1");
    assert_eq!(client_ip(&h, peer, 0), "10.0.0.1");
    assert_eq!(client_ip(&HeaderMap::new(), None, 1), "unknown");
}

// ---- T14: static files and health -----------------------------------------------------------

async fn get(h: &H, uri: &str) -> Response {
    h.send(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
}

#[tokio::test]
async fn pages_carry_the_csp_and_no_store() {
    let h = H::new();
    let res = get(&h, "/login").await;
    assert_eq!(res.status(), StatusCode::OK);
    let hd = res.headers();
    assert_eq!(
        hd[header::CONTENT_SECURITY_POLICY],
        crate::static_files::CSP
    );
    assert_eq!(
        crate::static_files::CSP,
        "default-src 'self'; frame-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    );
    assert_eq!(hd[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(hd[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(hd[header::CACHE_CONTROL], "no-store");
    assert!(
        hd[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let asset = get(&h, "/assets/app-1a2b.js").await;
    assert_eq!(asset.status(), StatusCode::OK);
    assert!(
        asset.headers()[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .contains("immutable")
    );
}

#[tokio::test]
async fn static_routes_never_escape_the_web_dir() {
    let h = H::new();
    for uri in [
        "/assets/../secret.txt",
        "/assets/..%2fsecret.txt",
        "/assets/%2e%2e",
        "/assets/missing.js",
        "/assets/.hidden",
        "/secret.txt",
        "/web/login.html",
        "/approvals", // a page whose file the build lacks
    ] {
        assert_eq!(get(&h, uri).await.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn healthz_and_readyz() {
    let h = H::new();
    let res = get(&h, "/healthz").await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = get(&h, "/readyz").await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = json_body(res).await;
    assert_eq!(body["directory"], "stub");
    assert_eq!(
        body["checks"],
        json!({"store": true, "master_key": true, "directory": true})
    );
}

#[tokio::test]
async fn readyz_is_503_when_the_stub_file_vanished() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("users.json");
    std::fs::write(&file, STUB).unwrap();
    let stub = Arc::new(StubDirectory::from_file(&file).unwrap());
    let store: Arc<dyn ServerStore> = Arc::new(crate::store::memory::MemoryStore::new());
    let health = crate::health::Health::new(store, stub, true);
    assert_eq!(health.readyz().await.status(), StatusCode::OK);
    std::fs::remove_file(&file).unwrap();
    // The probe result is cached for 30 s; a fresh checker sees the missing file at once.
    let res = health.readyz().await;
    assert_eq!(res.status(), StatusCode::OK, "cached for 30 s");
    let store: Arc<dyn ServerStore> = Arc::new(crate::store::memory::MemoryStore::new());
    std::fs::write(&file, STUB).unwrap();
    let stub3 = Arc::new(StubDirectory::from_file(&file).unwrap());
    std::fs::remove_file(&file).unwrap();
    let fresh = crate::health::Health::new(store, stub3, true);
    let res = fresh.readyz().await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = json_body(res).await;
    assert_eq!(body["checks"]["directory"], false);
}

// ---- T13: admin instances over HTTP --------------------------------------------------------

async fn admin_call(
    h: &H,
    method: Method,
    uri: &str,
    cookie: &str,
    csrf: &str,
    body: &str,
) -> Response {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header(
            header::COOKIE,
            format!("__Host-atlas_duck_session={cookie}"),
        )
        .header("x-csrf-token", csrf)
        .header(header::ORIGIN, ORIGIN)
        .body(Body::from(body.to_owned()))
        .unwrap();
    h.send(req).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_instances_need_the_admin_role() {
    let h = H::new();
    let body = r#"{"alias": "work", "product": "jira", "base_url": "https://jira.example.test", "is_default": true}"#;
    let (cookie, csrf) = h.session("alice", PW_CANARY).await;
    for (m, uri) in [
        (Method::GET, "/api/admin/instances"),
        (Method::POST, "/api/admin/instances"),
        (Method::DELETE, "/api/admin/instances/work"),
    ] {
        let (s, c) = code(admin_call(&h, m, uri, &cookie, &csrf, body).await).await;
        assert_eq!(
            (s, c.as_str()),
            (StatusCode::FORBIDDEN, "auth/role_required"),
            "{uri}"
        );
    }
    let (cookie, csrf) = h.session("bob", "pw-bob").await;
    let res = admin_call(
        &h,
        Method::POST,
        "/api/admin/instances",
        &cookie,
        &csrf,
        body,
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = json_body(res).await;
    assert_eq!(
        created,
        json!({"alias": "work", "product": "jira", "base_url": "https://jira.example.test",
               "proxy": null, "ca_ref": null, "is_default": true})
    );
    let (s, c) = code(
        admin_call(
            &h,
            Method::POST,
            "/api/admin/instances",
            &cookie,
            &csrf,
            body,
        )
        .await,
    )
    .await;
    assert_eq!((s, c.as_str()), (StatusCode::CONFLICT, "instance/exists"));
    let (s, c) = code(
        admin_call(
            &h,
            Method::POST,
            "/api/admin/instances",
            &cookie,
            &csrf,
            r#"{"alias": "x"}"#,
        )
        .await,
    )
    .await;
    assert_eq!(
        (s, c.as_str()),
        (StatusCode::BAD_REQUEST, "instance/invalid")
    );
    let listed =
        json_body(admin_call(&h, Method::GET, "/api/admin/instances", &cookie, &csrf, "").await)
            .await;
    assert_eq!(listed.as_array().unwrap().len(), 1);
    let res = admin_call(
        &h,
        Method::DELETE,
        "/api/admin/instances/work",
        &cookie,
        &csrf,
        "",
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let (s, c) = code(
        admin_call(
            &h,
            Method::DELETE,
            "/api/admin/instances/work",
            &cookie,
            &csrf,
            "",
        )
        .await,
    )
    .await;
    assert_eq!((s, c.as_str()), (StatusCode::NOT_FOUND, "instance/unknown"));
}

// ---- T16: approvals commands and SSE --------------------------------------------------------

use atlas_duck_atlassian::testing::{MockDc, XAuser};
use atlas_duck_atlassian::testing::{TEST_PAT, TEST_USER, TEST_USER_KEY, fixtures};
use atlas_duck_atlassian::{
    CredentialProvider, PatSecret, Product, StoredCredential, StoredIdentity,
};

/// Stores the user's PAT for `work` (before the user's runtime opens: core reads it at start).
fn store_pat(h: &H, user: &str, mock: &MockDc) {
    let uid = user_id_for(user);
    let master = MasterKey::for_tests("k1", [5; 32]);
    let wrapped = crate::master_key::WrappedKey::from_json(
        &h.store.user(&uid).unwrap().unwrap().data_key_wrapped,
    )
    .unwrap();
    let creds = crate::credentials::server_credentials(
        h.store.clone(),
        &uid,
        master.unwrap(&uid, &wrapped).unwrap(),
        h.clock.clone(),
    );
    creds
        .store(
            &crate::instances::instance_id_for("work"),
            StoredCredential {
                pat: PatSecret::new(TEST_PAT.into()),
                base_url_hash: atlas_duck_atlassian::url::url_hash(&mock.base()),
                identity: StoredIdentity {
                    atlassian_user: TEST_USER.into(),
                    atlassian_user_key: TEST_USER_KEY.into(),
                },
                expires_at: None,
            },
        )
        .unwrap();
}

/// An agent's read of `ABC-1` on Jira `work` (a mock), pending for the user's release.
async fn pending_read(h: &H, user: &str, mock: &MockDc) -> String {
    store_pat(h, user, mock);
    submit_read(h, user).await
}

async fn submit_read(h: &H, user: &str) -> String {
    let uid = user_id_for(user);
    let rt = h
        .registry
        .runtime(&crate::runtime::UserCtx::from_authenticated(&uid))
        .await
        .unwrap();
    let conn = atlas_duck_ipc::proto::ConnectionMeta {
        connection_id: "conn-1".into(),
        peer: Default::default(),
    };
    rt.handler()
        .hello(
            &conn,
            atlas_duck_ipc::proto::Hello {
                build_id: atlas_duck_ipc::build_info::BUILD_ID.to_owned(),
                client_kind: atlas_duck_ipc::proto::ClientKind::Cli,
                agent_name: Some("agent".into()),
                agent_name_source: atlas_duck_ipc::proto::AgentNameSource::Flag,
                cwd_basename: "work".into(),
            },
        )
        .await
        .map_err(|e| e.to_json_line())
        .unwrap();
    let reply = rt
        .handler()
        .submit(
            &conn,
            atlas_duck_ipc::proto::SubmitParams {
                op_id: "jira.issue.get".into(),
                params: json!({"key": "ABC-1"}),
                instance: None,
                reason: None,
            },
        )
        .await;
    let env = serde_json::to_value(&reply.envelope).unwrap();
    assert_eq!(env["status"], "pending", "{env}");
    env["request_id"].as_str().unwrap().to_owned()
}

async fn jira_mock() -> MockDc {
    let mock = MockDc::start(Product::Jira, "").await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.jira_server_info("9.12.0").await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path_regex("^/rest/api/2/issue/ABC-1$"))
        .respond_with(
            mock.response(200)
                .set_body_raw(fixtures::JIRA_ISSUE, "application/json"),
        )
        .mount(mock.server())
        .await;
    mock
}

fn put_work(h: &H, base_url: &str) {
    h.store
        .instance_put(&crate::store::InstanceRecord {
            alias: "work".into(),
            product: "jira".into(),
            base_url: base_url.into(),
            proxy: Some("direct".into()),
            ca_ref: None,
            is_default: true,
        })
        .unwrap();
}

async fn cmd(h: &H, cookie: &str, csrf: &str, name: &str, body: Value) -> Response {
    admin_call(
        h,
        Method::POST,
        &format!("/api/cmd/{name}"),
        cookie,
        csrf,
        &body.to_string(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queue_is_per_user_and_a_release_reaches_the_instance() {
    let h = H::new();
    let mock = jira_mock().await;
    put_work(&h, &mock.base_url());
    let (ca, ta) = h.session("alice", PW_CANARY).await;
    let (cb, tb) = h.session("bob", "pw-bob").await;
    let id = pending_read(&h, "alice", &mock).await;
    // The read fetches its candidate first; the row appears once it is built.
    let mut a = json!([]);
    for _ in 0..200 {
        a = json_body(cmd(&h, &ca, &ta, "queue_list", json!({})).await).await;
        if !a.as_array().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(a.as_array().unwrap().len(), 1, "{a}");
    assert_eq!(a[0]["request_id"], id);
    let b = json_body(cmd(&h, &cb, &tb, "queue_list", json!({})).await).await;
    assert_eq!(b, json!([]));
    // B cannot read A's item either.
    let res = cmd(&h, &cb, &tb, "queue_get", json!({"request_id": id})).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(res).await, json!({"kind": "not_found"}));
    // A opens the preview, then releases that revision.
    let detail = json_body(cmd(&h, &ca, &ta, "queue_get", json!({"request_id": id})).await).await;
    assert_eq!(detail["item"]["request_id"], id);
    let preview =
        json_body(cmd(&h, &ca, &ta, "preview_fetch", json!({"request_id": id})).await).await;
    let rev = preview["preview"]["candidate_rev"].clone();
    assert!(
        preview["srcdoc"].as_str().unwrap().contains("<"),
        "{preview}"
    );
    let raw = cmd(
        &h,
        &ca,
        &ta,
        "raw_page",
        json!({"request_id": id, "candidate_rev": rev, "page": 0}),
    )
    .await;
    assert_eq!(raw.status(), StatusCode::OK);
    let out = cmd(
        &h,
        &ca,
        &ta,
        "decide",
        json!({"request_id": id, "decision": "release", "candidate_rev": rev}),
    )
    .await;
    assert_eq!(out.status(), StatusCode::OK);
    let outcome = json_body(out).await;
    assert_eq!(outcome["status"], "released", "{outcome}");
    let gets = mock
        .received()
        .await
        .iter()
        .filter(|r| r.url.path() == "/rest/api/2/issue/ABC-1")
        .count();
    assert_eq!(gets, 1, "the read fetched once, before the release");
    assert_eq!(
        json_body(cmd(&h, &ca, &ta, "queue_list", json!({})).await).await,
        json!([])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commands_refuse_bad_bodies_unknown_names_and_missing_csrf() {
    let h = H::new();
    let (c, t) = h.session("alice", PW_CANARY).await;
    let res = cmd(&h, &c, &t, "decide_batch", json!({})).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(res).await,
        json!({"kind": "not_found", "code": "api/unknown_command"})
    );
    let res = cmd(&h, &c, &t, "queue_get", json!({"request_id": "req_short"})).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(res).await,
        json!({"kind": "invalid_argument", "field": "request_id"})
    );
    let res = cmd(&h, &c, &t, "queue_list", json!({"x": 1})).await;
    assert_eq!(
        json_body(res).await,
        json!({"kind": "invalid_argument", "field": "payload"})
    );
    assert_eq!(
        json_body(cmd(&h, &c, &t, "app_status", json!({})).await).await,
        json!([])
    );
    let (s, code_) = code(cmd(&h, &c, "wrong-token", "queue_list", json!({})).await).await;
    assert_eq!(
        (s, code_.as_str()),
        (StatusCode::FORBIDDEN, "auth/csrf_mismatch")
    );
}

/// Reads SSE frames until one contains `needle` (or the stream ends: `None`).
async fn frame_with(body: &mut axum::body::BodyDataStream, needle: &str) -> Option<String> {
    use futures::StreamExt;
    let mut buf = String::new();
    loop {
        let chunk = tokio::time::timeout(LIMIT, body.next())
            .await
            .expect("sse hung")?;
        buf.push_str(&String::from_utf8_lossy(&chunk.ok()?));
        if let Some(i) = buf.find(needle) {
            return Some(buf[i..].to_owned());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_delivers_queue_changed_and_ends_at_session_expiry() {
    let h = H::new();
    let mock = jira_mock().await;
    put_work(&h, &mock.base_url());
    let (c, _) = h.session("alice", PW_CANARY).await;
    store_pat(&h, "alice", &mock);
    let res = h
        .send(
            Request::builder()
                .uri("/api/events")
                .header(header::COOKIE, format!("__Host-atlas_duck_session={c}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    let mut body = res.into_body().into_data_stream();
    submit_read(&h, "alice").await;
    let f = frame_with(&mut body, "event: queue_changed").await.unwrap();
    assert!(f.contains("request_ids"), "{f}");
    assert!(frame_with(&mut body, ": keep-alive").await.is_some());
    h.clock.advance(1_801);
    // At the next keep-alive check the stream ends.
    assert_eq!(frame_with(&mut body, "never-in-a-frame").await, None);
}

#[tokio::test]
async fn a_lagging_stream_gets_resync() {
    use futures::StreamExt;
    let h = H::new();
    let (c, _) = h.session("alice", PW_CANARY).await;
    let (tx, rx) = tokio::sync::broadcast::channel(1);
    for n in 0..3 {
        tx.send(crate::runtime::SseEvent {
            name: "attention",
            data: json!({"count": n}),
        })
        .unwrap();
    }
    let sessions =
        Arc::new(SessionTable::new(h.store.clone(), h.clock.clone(), 28_800, 1_800).unwrap());
    let sse = crate::sse::stream(rx, None, sessions, c);
    let mut body = axum::response::IntoResponse::into_response(sse)
        .into_body()
        .into_data_stream();
    let first = tokio::time::timeout(LIMIT, body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&first).contains("event: resync"),
        "{first:?}"
    );
    drop(tx);
}

// ---- T17: PAT entry -------------------------------------------------------------------------

const PAT_CANARY: &str = "pat-canary-4c1d9e2b77";

async fn put_pat(h: &H, cookie: &str, csrf: &str, alias: &str, pat: &str) -> Response {
    admin_call(
        h,
        Method::PUT,
        &format!("/api/me/pats/{alias}"),
        cookie,
        csrf,
        &json!({"pat": pat}).to_string(),
    )
    .await
}

async fn instances_of(h: &H, cookie: &str) -> Value {
    let req = Request::builder()
        .uri("/api/instances")
        .header(
            header::COOKIE,
            format!("__Host-atlas_duck_session={cookie}"),
        )
        .body(Body::empty())
        .unwrap();
    json_body(h.send(req).await).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_good_pat_is_checked_stored_sealed_and_usable() {
    let h = H::new();
    let mock = jira_mock().await;
    put_work(&h, &mock.base_url());
    let (ca, ta) = h.session("alice", PW_CANARY).await;
    let (cb, _) = h.session("bob", "pw-bob").await;
    assert_eq!(instances_of(&h, &ca).await[0]["pat"], "none");
    let res = put_pat(&h, &ca, &ta, "work", PAT_CANARY).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = json_body(res).await;
    assert_eq!(body, json!({"alias": "work", "identity": TEST_USER}));
    let mine = instances_of(&h, &ca).await;
    assert_eq!(mine[0]["pat"], "stored", "{mine}");
    assert_eq!(mine[0]["identity"], TEST_USER);
    assert!(!mine.to_string().contains(PAT_CANARY));
    // B sees no PAT of A.
    let theirs = instances_of(&h, &cb).await;
    assert_eq!(theirs[0]["pat"], "none");
    assert!(theirs[0]["identity"].is_null());
    // The PAT went to the instance (the check), and is usable for an agent read now.
    let auth_seen = mock.received().await.iter().any(|r| {
        r.headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == format!("Bearer {PAT_CANARY}"))
    });
    assert!(auth_seen);
    submit_read(&h, "alice").await;
    // Sealed: the canary is nowhere in the database bytes.
    assert!(!contains(&h.db_bytes(), PAT_CANARY.as_bytes()));
    // Delete: the instance is back to none.
    let res = admin_call(&h, Method::DELETE, "/api/me/pats/work", &ca, &ta, "").await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(instances_of(&h, &ca).await[0]["pat"], "none");
    assert!(
        h.store
            .pat_get(&user_id_for("alice"), "work")
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_pat_is_422_and_nothing_is_stored() {
    let h = H::new();
    let mock = MockDc::start(Product::Jira, "").await;
    wiremock::Mock::given(wiremock::matchers::path("/rest/api/2/myself"))
        .respond_with(mock.response(401))
        .mount(mock.server())
        .await;
    mock.jira_server_info("9.12.0").await;
    put_work(&h, &mock.base_url());
    let (c, t) = h.session("alice", PW_CANARY).await;
    let res = put_pat(&h, &c, &t, "work", PAT_CANARY).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = json_body(res).await;
    assert_eq!(body["error"]["code"], "pat/check_failed");
    assert_eq!(body["error"]["reason"], "http_401");
    assert!(!body.to_string().contains(PAT_CANARY));
    assert!(
        h.store
            .pat_get(&user_id_for("alice"), "work")
            .unwrap()
            .is_none()
    );
    assert!(!contains(&h.db_bytes(), PAT_CANARY.as_bytes()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_instance_is_502_and_bad_requests_are_refused() {
    let h = H::new();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    put_work(&h, &format!("http://127.0.0.1:{port}"));
    let (c, t) = h.session("alice", PW_CANARY).await;
    let res = put_pat(&h, &c, &t, "work", PAT_CANARY).await;
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(res).await["error"]["code"],
        "pat/instance_unreachable"
    );
    let (s, code_) = code(put_pat(&h, &c, &t, "nope", PAT_CANARY).await).await;
    assert_eq!(
        (s, code_.as_str()),
        (StatusCode::NOT_FOUND, "instance/unknown")
    );
    for bad in [String::new(), "x".repeat(MAX_PAT + 1)] {
        let (s, code_) = code(put_pat(&h, &c, &t, "work", &bad).await).await;
        assert_eq!(
            (s, code_.as_str()),
            (StatusCode::BAD_REQUEST, "api/bad_request")
        );
    }
    let res = admin_call(
        &h,
        Method::PUT,
        "/api/me/pats/work",
        &c,
        &t,
        r#"{"pat": "x", "y": 1}"#,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

const MAX_PAT: usize = super::pat_routes::MAX_PAT_CHARS;

// ---- T18: API keys --------------------------------------------------------------------------

async fn bearer_probe(h: &H, auth: Option<&str>) -> Response {
    use axum::routing::get;
    let r: Router = Router::new()
        .route(
            "/probe",
            get(
                |super::extract::BearerUser(k): super::extract::BearerUser| async move {
                    axum::Json(json!({"user": k.user.user_id(), "scopes": k.scopes}))
                },
            ),
        )
        .with_state(h.state.clone());
    let mut b = Request::builder().uri("/probe");
    if let Some(a) = auth {
        b = b.header(header::AUTHORIZATION, a);
    }
    tokio::time::timeout(LIMIT, r.oneshot(b.body(Body::empty()).unwrap()))
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_keys_over_http_create_once_list_revoke_and_record() {
    let h = H::new();
    let (c, t) = h.session("alice", PW_CANARY).await;
    let res = admin_call(
        &h,
        Method::POST,
        "/api/me/api-keys",
        &c,
        &t,
        r#"{"name": "laptop", "scopes": ["read", "propose_write"], "expires_in_days": 7}"#,
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    let created = json_body(res).await;
    let key = created["key"].as_str().unwrap().to_owned();
    assert!(key.starts_with(&format!("adk_{}_", created["prefix"].as_str().unwrap())));
    let id = created["id"].as_str().unwrap().to_owned();
    // The key authenticates as alice with its scopes.
    let ok = bearer_probe(&h, Some(&format!("Bearer {key}"))).await;
    assert_eq!(ok.status(), StatusCode::OK);
    let who = json_body(ok).await;
    assert_eq!(who["user"], user_id_for("alice"));
    assert_eq!(who["scopes"], json!(["read", "propose_write"]));
    // Lists never show the key; the DB never holds it.
    let listed = json_body(admin_call(&h, Method::GET, "/api/me/api-keys", &c, &t, "").await).await;
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert!(!listed.to_string().contains(&key[13..]));
    assert!(!contains(&h.db_bytes(), key.as_bytes()));
    assert!(!contains(&h.db_bytes(), &key.as_bytes()[13..]));
    // Bob sees none of it and cannot revoke it.
    let (cb, tb) = h.session("bob", "pw-bob").await;
    assert_eq!(
        json_body(admin_call(&h, Method::GET, "/api/me/api-keys", &cb, &tb, "").await).await,
        json!([])
    );
    let res = admin_call(
        &h,
        Method::DELETE,
        &format!("/api/me/api-keys/{id}"),
        &cb,
        &tb,
        "",
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    // Revoke: 204, then the key is refused at once, and the refusal is in alice's chain.
    let rt = h
        .registry
        .runtime(&crate::runtime::UserCtx::from_authenticated(&user_id_for(
            "alice",
        )))
        .await
        .unwrap();
    let res = admin_call(
        &h,
        Method::DELETE,
        &format!("/api/me/api-keys/{id}"),
        &c,
        &t,
        "",
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let before = rt.head().1;
    let refused = bearer_probe(&h, Some(&format!("Bearer {key}"))).await;
    assert_eq!(
        code(refused).await,
        (StatusCode::UNAUTHORIZED, "auth/api_key_invalid".to_owned())
    );
    assert_eq!(rt.head().1, before + 1, "LOGIN refused revoked recorded");
    // Every other bad bearer answers the same, without a record.
    for auth in [
        None,
        Some("Bearer nope"),
        Some("Basic abc"),
        Some(format!("Bearer adk_aaaaaaaa_{}", "A".repeat(43)).as_str()),
    ] {
        let res = bearer_probe(&h, auth).await;
        assert_eq!(
            code(res).await,
            (StatusCode::UNAUTHORIZED, "auth/api_key_invalid".to_owned()),
            "{auth:?}"
        );
    }
    assert_eq!(rt.head().1, before + 1);
    // Validation errors over HTTP.
    let (s, c_) = code(
        admin_call(
            &h,
            Method::POST,
            "/api/me/api-keys",
            &c,
            &t,
            r#"{"name": "x", "scopes": []}"#,
        )
        .await,
    )
    .await;
    assert_eq!(
        (s, c_.as_str()),
        (StatusCode::BAD_REQUEST, "api_key/scope_invalid")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_listed_route_is_routed() {
    // T23: the isolation suite walks `ROUTES`; each entry must be a route the router serves
    // with that method (not the 404 fallback, not 405).
    let h = H::new();
    for (method, path, _) in super::ROUTES {
        let concrete = path
            .replace("{name}", "x.js")
            .replace("{alias}", "work")
            .replace("{command}", "queue_list")
            .replace("{id}", "key_x");
        let req = Request::builder()
            .method(*method)
            .uri(&concrete)
            .header(header::HOST, "duck.example.test")
            .body(Body::empty())
            .unwrap();
        let res = h.send(req).await;
        assert_ne!(
            res.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path}"
        );
        if res.status() == StatusCode::NOT_FOUND {
            let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
                .await
                .unwrap();
            assert!(
                !String::from_utf8_lossy(&bytes).contains("api/not_found"),
                "{method} {path} fell through to the fallback"
            );
        }
    }
}

#[test]
fn every_route_row_has_a_handler_and_bearer_rows_are_mcp() {
    // Batch-4b review I3: the router is built from ROUTES, so this pins the table both ways.
    for (method, path, access) in super::ROUTES {
        match access {
            super::Access::Bearer => {
                assert_eq!(*path, crate::mcp::MCP_PATH, "{method} {path}");
                assert!(super::handler(method, path).is_none());
            }
            _ => assert!(super::handler(method, path).is_some(), "{method} {path}"),
        }
    }
    let mut seen = std::collections::HashSet::new();
    for (method, path, _) in super::ROUTES {
        assert!(
            seen.insert((*method, *path)),
            "duplicate row {method} {path}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_whose_audit_record_fails_is_never_stored() {
    // Final review I1/I2: API_KEY_CREATED comes first; when it fails, no key exists to use.
    let h = H::new();
    let (cookie, csrf) = h.session("alice", PW_CANARY).await;
    let uid = user_id_for("alice");
    let rt = h
        .registry
        .runtime(&crate::runtime::UserCtx::from_authenticated(&uid))
        .await
        .unwrap();
    rt.fail_next_append
        .store(true, std::sync::atomic::Ordering::SeqCst);
    drop(rt);
    let body = r#"{"name": "agent", "scopes": ["read"]}"#;
    let res = admin_call(&h, Method::POST, "/api/me/api-keys", &cookie, &csrf, body).await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(code(res).await.1, "store/unavailable");
    assert!(
        h.store.api_key_list(&uid).unwrap().is_empty(),
        "no key was stored"
    );
    // With the store back, the same request works and the key is listed.
    let res = admin_call(&h, Method::POST, "/api/me/api-keys", &cookie, &csrf, body).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(h.store.api_key_list(&uid).unwrap().len(), 1);
}
