//! Remote MCP over streamable HTTP (SM-3.1, SM-3.2, SM-3.4, PD-193, PD-194, PD-204): rmcp's
//! `StreamableHttpService` at `/mcp` behind a bearer guard. The guard authenticates the API key
//! (401 with `WWW-Authenticate` otherwise), puts the key's `KeyCtx` on the request for the handler
//! and binds every MCP session id to the user whose key created it: another user's key naming
//! that session is answered 404, as if it did not exist.

pub mod handler;
pub mod session;

use axum::Router;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::errors::ApiError;
use crate::web::AppState;
use crate::web::extract::BearerUser;

pub use handler::{ServerMcp, allowed, tools_for};
pub use session::McpSessions;

pub const MCP_PATH: &str = "/mcp";
/// The MCP session header (streamable HTTP).
pub const SESSION_HEADER: &str = "mcp-session-id";
/// PD-204: no `resource_metadata` before M14.
pub const WWW_AUTHENTICATE: &str = "Bearer realm=\"atlas-duck\"";

/// The `/mcp` routes, guarded.
pub fn routes(state: &AppState) -> Router<AppState> {
    let mcp = ServerMcp::new(state.registry.clone(), &state.public_origin);
    // Decision (T19): rmcp's Host allow-list guards local servers against DNS rebinding; every
    // `/mcp` request here carries a bearer key a rebinding page cannot have, and the public
    // host is the proxy's to check, so the list is off.
    let config = StreamableHttpServerConfig::default().disable_allowed_hosts();
    let service = StreamableHttpService::new(
        move || Ok(mcp.clone()),
        std::sync::Arc::new(LocalSessionManager::default()),
        config,
    );
    Router::new()
        .route_service(MCP_PATH, service)
        .layer(middleware::from_fn_with_state(state.clone(), guard))
}

fn unauthorized(e: ApiError) -> Response {
    let mut res = e.into_response();
    res.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(WWW_AUTHENTICATE),
    );
    res
}

/// Bearer → `KeyCtx` on the request; session ids bound to their creator.
async fn guard(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();
    let key = match BearerUser::from_request_parts(&mut parts, &st).await {
        Ok(BearerUser(key)) => key,
        Err(e) if e.status == StatusCode::UNAUTHORIZED => return unauthorized(e),
        Err(e) => return e.into_response(),
    };
    let user_id = key.user.user_id().to_owned();
    let sid = parts
        .headers
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if let Some(s) = &sid
        && !st.mcp_sessions.may_use(s, &user_id)
    {
        return ApiError::NOT_FOUND.into_response();
    }
    let delete = parts.method == Method::DELETE;
    parts.extensions.insert(key);
    let res = next.run(Request::from_parts(parts, body)).await;
    match &sid {
        None => {
            if let Some(new) = res
                .headers()
                .get(SESSION_HEADER)
                .and_then(|v| v.to_str().ok())
            {
                st.mcp_sessions.bind(new, &user_id);
            }
        }
        Some(s) if delete && res.status().is_success() => st.mcp_sessions.forget(s),
        Some(_) => {}
    }
    res
}
