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
use axum::routing::{delete, get, post, put};

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
}

#[derive(Clone)]
pub struct AppState(pub Arc<AppInner>);

impl std::ops::Deref for AppState {
    type Target = AppInner;
    fn deref(&self) -> &AppInner {
        &self.0
    }
}

/// Every route group (T14): health, static pages and assets, the auth routes; the command, SSE,
/// PAT, API-key and MCP groups join in their tasks. An unrouted path is 404.
pub fn router(state: AppState) -> Router {
    let mut r = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(readyz))
        .route("/assets/{name}", get(asset))
        .route("/api/login", post(auth_routes::login))
        .route("/api/logout", post(auth_routes::logout))
        .route("/api/session", get(auth_routes::session))
        .route(
            "/api/admin/instances",
            get(admin_routes::list).post(admin_routes::add),
        )
        .route("/api/admin/instances/{alias}", delete(admin_routes::remove))
        .route("/api/cmd/{command}", post(cmd_routes::command))
        .route("/api/events", get(cmd_routes::events))
        .route("/api/instances", get(pat_routes::instances))
        .route(
            "/api/me/pats/{alias}",
            put(pat_routes::put).delete(pat_routes::delete),
        )
        .route(
            "/api/me/api-keys",
            get(api_key_routes::list).post(api_key_routes::create),
        )
        .route("/api/me/api-keys/{id}", delete(api_key_routes::revoke));
    for (path, _) in static_files::PAGES {
        r = r.route(path, get(page));
    }
    r.fallback(|| async { ApiError::NOT_FOUND })
        .layer(middleware::from_fn_with_state(state.clone(), api_guard))
        .with_state(state)
}

async fn readyz(State(st): State<AppState>) -> Response {
    st.health.readyz().await
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
            let Some(cookie) = header_str(headers, header::COOKIE).and_then(cookie_value) else {
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
/// right (the address the outermost trusted proxy saw), else the peer address.
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
    let ip = match entries.len() {
        0 => return peer_ip(),
        len if len >= n => entries[len - n],
        _ => entries[0],
    };
    // Header text: bounded, as it keys the rate limiter and lands in LOGIN_FAILED.
    ip.chars().take(MAX_IP_CHARS).collect()
}

/// The longest client address kept (an IPv6 address with zone fits).
pub const MAX_IP_CHARS: usize = 64;

/// The peer address axum's `into_make_service_with_connect_info` records, if any.
pub fn peer(req_ext: &axum::http::Extensions) -> Option<SocketAddr> {
    req_ext.get::<ConnectInfo<SocketAddr>>().map(|c| c.0)
}
