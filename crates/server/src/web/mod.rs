//! The axum router and the web API. Task 12: the `/api/` guard (bearer refusal, Origin, CSRF,
//! body limit) and the auth routes; Task 14 adds the listener, the other routes and static files.

pub mod admin_routes;
pub mod api_key_routes;
pub mod auth_routes;
pub mod cmd_routes;
pub mod extract;
pub mod pat_routes;

#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, Method, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, delete, get, post, put};

use crate::csrf::{CSRF_HEADER, origin_ok, token_ok};
use crate::errors::ApiError;
use crate::health::{self, Health};
use crate::login::LoginService;
use crate::runtime::Registry;
use crate::session::{SessionTable, cookie_value};
use crate::static_files::{self, WebDir};
use crate::store::ServerStore;

/// Every `/api/*` body is at most 64 KiB (413 `api/body_too_large`).
pub const BODY_LIMIT: usize = 64 * 1024;

pub struct AppInner {
    pub public_origin: String,
    pub cookie_secure: bool,
    pub trusted_proxy_hops: u32,
    pub store: Arc<dyn ServerStore>,
    pub sessions: Arc<SessionTable>,
    pub login: LoginService,
    pub registry: Arc<Registry>,
    pub web: WebDir,
    pub health: Arc<Health>,
    pub api_keys: Arc<crate::api_keys::ApiKeys>,
    pub mcp_sessions: Arc<crate::mcp::McpSessions>,
}

#[derive(Clone)]
pub struct AppState(pub Arc<AppInner>);

impl std::ops::Deref for AppState {
    type Target = AppInner;
    fn deref(&self) -> &AppInner {
        &self.0
    }
}

/// Who may call a route (the isolation suite's route-table scan, T23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Public,
    /// A session; the answer is the session user's own data only.
    Session,
    /// A session with role `admin`; the answer carries no user data (SM-2.5).
    Admin,
    /// A bearer API key; the answer is the key owner's own data only.
    Bearer,
}

/// Every route [`router`] serves, `(method, path, access)`; `web::tests` pins that each is
/// routed, and the isolation suite walks it. Static pages are [`static_files::PAGES`].
pub const ROUTES: &[(&str, &str, Access)] = &[
    ("GET", "/healthz", Access::Public),
    ("GET", "/readyz", Access::Public),
    ("GET", "/assets/{name}", Access::Public),
    ("POST", "/api/login", Access::Public),
    ("POST", "/api/logout", Access::Session),
    ("GET", "/api/session", Access::Session),
    ("GET", "/api/admin/instances", Access::Admin),
    ("POST", "/api/admin/instances", Access::Admin),
    ("DELETE", "/api/admin/instances/{alias}", Access::Admin),
    ("POST", "/api/cmd/{command}", Access::Session),
    ("GET", "/api/events", Access::Session),
    ("GET", "/api/instances", Access::Session),
    ("PUT", "/api/me/pats/{alias}", Access::Session),
    ("DELETE", "/api/me/pats/{alias}", Access::Session),
    ("GET", "/api/me/api-keys", Access::Session),
    ("POST", "/api/me/api-keys", Access::Session),
    ("DELETE", "/api/me/api-keys/{id}", Access::Session),
    ("POST", "/mcp", Access::Bearer),
    ("GET", "/mcp", Access::Bearer),
    ("DELETE", "/mcp", Access::Bearer),
];

/// The handler of one [`ROUTES`] row; `None` for the bearer rows, which [`crate::mcp::routes`]
/// serves. Batch-4b review I3: the router is built from the table, so a route exists exactly when
/// its row does (`web::tests` pins that every non-bearer row has a handler).
pub(crate) fn handler(method: &str, path: &str) -> Option<MethodRouter<AppState>> {
    Some(match (method, path) {
        ("GET", "/healthz") => get(health::healthz),
        ("GET", "/readyz") => get(readyz),
        ("GET", "/assets/{name}") => get(asset),
        ("POST", "/api/login") => post(auth_routes::login),
        ("POST", "/api/logout") => post(auth_routes::logout),
        ("GET", "/api/session") => get(auth_routes::session),
        ("GET", "/api/admin/instances") => get(admin_routes::list),
        ("POST", "/api/admin/instances") => post(admin_routes::add),
        ("DELETE", "/api/admin/instances/{alias}") => delete(admin_routes::remove),
        ("POST", "/api/cmd/{command}") => post(cmd_routes::command),
        ("GET", "/api/events") => get(cmd_routes::events),
        ("GET", "/api/instances") => get(pat_routes::instances),
        ("PUT", "/api/me/pats/{alias}") => put(pat_routes::put),
        ("DELETE", "/api/me/pats/{alias}") => delete(pat_routes::delete),
        ("GET", "/api/me/api-keys") => get(api_key_routes::list),
        ("POST", "/api/me/api-keys") => post(api_key_routes::create),
        ("DELETE", "/api/me/api-keys/{id}") => delete(api_key_routes::revoke),
        _ => return None,
    })
}

/// Every route group: health, static pages and assets, auth, commands and SSE, PATs, API keys,
/// admin instances (all from [`ROUTES`]) and `/mcp` (bearer only, its own guard). An unrouted
/// path is 404.
pub fn router(state: AppState) -> Router {
    let mut by_path: std::collections::BTreeMap<&str, MethodRouter<AppState>> =
        std::collections::BTreeMap::new();
    for (method, path, _) in ROUTES {
        if let Some(h) = handler(method, path) {
            let merged = match by_path.remove(path) {
                Some(m) => m.merge(h),
                None => h,
            };
            by_path.insert(path, merged);
        }
    }
    let mut r = Router::new();
    for (path, m) in by_path {
        r = r.route(path, m);
    }
    for (path, _) in static_files::PAGES {
        r = r.route(path, get(page));
    }
    r.merge(crate::mcp::routes(&state))
        .fallback(|| async { ApiError::NOT_FOUND })
        .layer(middleware::from_fn_with_state(state.clone(), api_guard))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            count_requests,
        ))
        .with_state(state)
}

async fn readyz(State(st): State<AppState>) -> Response {
    if st.registry.maintenance() {
        let mut reasons = vec!["maintenance"];
        if crate::admin::restore::interrupted(&st.registry.deps().data_dir) {
            reasons.push("restore_interrupted");
        }
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"ready": false, "reasons": reasons})),
        )
            .into_response();
    }
    st.health.readyz().await
}

/// The metrics listener's router (M13 T10, `ATLAS_DUCK_METRICS_LISTEN`): `GET /metrics` only, on a
/// port of its own that the Ingress never routes. The main port has no `/metrics` (404).
pub fn metrics_router(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .fallback(|| async { ApiError::NOT_FOUND })
        .with_state(state)
}

/// Prometheus text with no user data (`health::Health::metrics`).
async fn metrics(State(st): State<AppState>) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        st.health.metrics().await,
    )
        .into_response()
}

/// M13 T10: every answer is counted by method and status class (`atlas_duck_requests_total`).
async fn count_requests(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let res = next.run(req).await;
    st.health.count(&method, res.status());
    res
}

async fn page(State(st): State<AppState>, uri: axum::http::Uri) -> Response {
    static_files::page(&st.web, uri.path()).await
}

async fn asset(
    State(st): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    static_files::asset(&st.web, &name).await
}

/// SM-3.4: agents never approve; these paths take a session cookie only.
fn session_only_path(path: &str) -> bool {
    path.starts_with("/api/cmd/")
        || path == "/api/cmd"
        || path.starts_with("/api/me/")
        || path == "/api/me"
}

fn header_str(h: &HeaderMap, name: impl header::AsHeaderName) -> Option<&str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// The `/api/` guard, in this order: body size, bearer on session-only paths, then for
/// state-changing methods Origin (before any body is read) and, except for `/api/login`, the
/// session and its CSRF token. The checked session rides on the request for the extractor.
async fn api_guard(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    // M13 T6: in maintenance only the probes answer (the admin CLI uses its socket).
    if st.registry.maintenance() && !["/healthz", "/readyz"].contains(&path.as_str()) {
        return ApiError::MAINTENANCE.into_response();
    }
    if !path.starts_with("/api/") {
        return next.run(req).await;
    }
    let headers = req.headers();
    // Global Constraints: the bearer refusal comes before every other check.
    if session_only_path(&path) && headers.contains_key(header::AUTHORIZATION) {
        return ApiError::BEARER_NOT_ACCEPTED.into_response();
    }
    if header_str(headers, header::CONTENT_LENGTH)
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > BODY_LIMIT)
    {
        return ApiError::BODY_TOO_LARGE.into_response();
    }
    let changing = req.method() != Method::GET && req.method() != Method::HEAD;
    if changing {
        if !origin_ok(header_str(headers, header::ORIGIN), &st.public_origin) {
            return ApiError::ORIGIN_MISMATCH.into_response();
        }
        if path != "/api/login" {
            let Some(cookie) =
                header_str(headers, header::COOKIE).and_then(|h| cookie_value(h, st.cookie_secure))
            else {
                return ApiError::NO_SESSION.into_response();
            };
            let session = match st.sessions.lookup(cookie) {
                Ok(s) => s,
                Err(e) => return e.into_response(),
            };
            if !token_ok(header_str(headers, CSRF_HEADER), &session.csrf_token) {
                return ApiError::CSRF_MISMATCH.into_response();
            }
            req.extensions_mut().insert(session);
        }
    }
    next.run(req).await
}

/// The client address (PD-201): with `hops` > 0 the `hops`-th `X-Forwarded-For` entry from the
/// right (the address the outermost trusted proxy saw), else the peer address. Review M1: only
/// the configured number of entries from the right is trusted; a shorter list, or an entry that
/// is not an IP address, falls back to the peer address (the leftmost entries are client text).
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>, hops: u32) -> String {
    let peer_ip = || peer.map_or_else(|| "unknown".to_owned(), |p| p.ip().to_string());
    if hops == 0 {
        return peer_ip();
    }
    let entries: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let n = hops as usize;
    let len = entries.len();
    if len < n {
        return peer_ip();
    }
    match entries[len - n].parse::<std::net::IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => peer_ip(),
    }
}

/// The peer address axum's `into_make_service_with_connect_info` records, if any.
pub fn peer(req_ext: &axum::http::Extensions) -> Option<SocketAddr> {
    req_ext.get::<ConnectInfo<SocketAddr>>().map(|c| c.0)
}
