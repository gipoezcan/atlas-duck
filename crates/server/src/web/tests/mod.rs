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

const ORIGIN: &str = "https://duck.example.test";
const T0: i64 = 1_800_000_000;
const PW_CANARY: &str = "pw-canary-7f3a9c";
const LIMIT: Duration = Duration::from_secs(30);

const STUB: &str = r#"{"users": [
  {"username": "alice", "password": "pw-canary-7f3a9c", "groups": ["CN=Users,DC=t"]},
  {"username": "bob", "password": "pw-bob", "groups": ["cn=users,dc=t", "cn=admins,dc=t"]},
  {"username": "audrey", "password": "pw-audrey", "groups": ["cn=auditors,dc=t"]},
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

struct H {
    router: Router,
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
        Self::over(dir, db, store)
    }

    /// A fresh router (and session table) over the same store: a restart.
    fn restart(self) -> H {
        let store: Arc<dyn ServerStore> = Arc::new(SqliteStore::open(&self.db).unwrap());
        let mut h = Self::over(self.dir, self.db, store);
        h.clock = self.clock;
        h
    }

    fn over(dir: tempfile::TempDir, db: PathBuf, store: Arc<dyn ServerStore>) -> H {
        let clock = ManualClock::at(T0);
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
        let state = AppState(Arc::new(AppInner {
            public_origin: ORIGIN.into(),
            cookie_secure: true,
            trusted_proxy_hops: 1,
            store: store.clone(),
            sessions,
            login,
        }));
        H {
            router: router(state),
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
            .strip_prefix("atlas_duck_session=")
            .and_then(|r| r.split(';').next())
            .unwrap()
            .to_owned();
        (id, body["csrf_token"].as_str().unwrap().to_owned())
    }

    async fn get_session(&self, cookie: &str) -> Response {
        let req = Request::builder()
            .uri("/api/session")
            .header(header::COOKIE, format!("atlas_duck_session={cookie}"))
            .body(Body::empty())
            .unwrap();
        self.send(req).await
    }

    async fn logout(&self, cookie: &str, csrf: Option<&str>, origin: Option<&str>) -> Response {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/api/logout")
            .header(header::COOKIE, format!("atlas_duck_session={cookie}"));
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
    let value = name_value.strip_prefix("atlas_duck_session=").unwrap();
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
            .header(header::COOKIE, format!("atlas_duck_session={cookie}"))
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

#[test]
fn client_ip_from_forwarded_for() {
    use axum::http::HeaderMap;
    let mut h = HeaderMap::new();
    let peer = Some("10.0.0.1:5555".parse().unwrap());
    assert_eq!(client_ip(&h, peer, 1), "10.0.0.1");
    h.insert("x-forwarded-for", "198.51.100.1, 10.1.1.1".parse().unwrap());
    assert_eq!(client_ip(&h, peer, 1), "10.1.1.1");
    assert_eq!(client_ip(&h, peer, 2), "198.51.100.1");
    assert_eq!(client_ip(&h, peer, 3), "198.51.100.1");
    assert_eq!(client_ip(&h, peer, 0), "10.0.0.1");
    assert_eq!(client_ip(&HeaderMap::new(), None, 1), "unknown");
}
