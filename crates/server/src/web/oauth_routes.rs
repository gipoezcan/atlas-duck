//! The OAuth HTTP surface (M14 T6–T8): discovery documents, registration, and (later tasks)
//! authorization, consent, token and revocation. Protocol endpoints answer in the RFC formats
//! (PD-239); `ATLAS_DUCK_OAUTH=disabled` makes every one of them 404 `oauth/disabled`.

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::{AppState, client_ip, peer};
use crate::errors::ApiError;
use crate::oauth::error::{OAuthError, no_store};
use crate::oauth::{metadata, register};

fn cached(v: serde_json::Value) -> Response {
    let mut res = Json(v).into_response();
    res.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(metadata::CACHE_CONTROL),
    );
    res
}

/// `GET /.well-known/oauth-protected-resource[/mcp]` (RFC 9728).
pub async fn protected_resource(State(st): State<AppState>) -> Response {
    if !st.oauth.cfg.enabled {
        return ApiError::OAUTH_DISABLED.into_response();
    }
    cached(metadata::protected_resource(&st.oauth))
}

/// `GET /.well-known/oauth-authorization-server` (RFC 8414).
pub async fn authorization_server(State(st): State<AppState>) -> Response {
    if !st.oauth.cfg.enabled {
        return ApiError::OAUTH_DISABLED.into_response();
    }
    cached(metadata::authorization_server(&st.oauth))
}

/// The body of `req`, at most `limit` bytes.
async fn body_bytes(req: Request<Body>, limit: usize) -> Option<axum::body::Bytes> {
    to_bytes(req.into_body(), limit).await.ok()
}

/// `POST /oauth/register` (RFC 7591).
pub async fn register(State(st): State<AppState>, req: Request<Body>) -> Response {
    if !st.oauth.cfg.enabled {
        return ApiError::OAUTH_DISABLED.into_response();
    }
    let ip = client_ip(req.headers(), peer(req.extensions()), st.trusted_proxy_hops);
    let Some(body) = body_bytes(req, register::BODY_LIMIT).await else {
        return OAuthError::INVALID_CLIENT_METADATA.into_response();
    };
    let now = st.clock.now();
    let st2 = st.clone();
    let out = tokio::task::spawn_blocking(move || {
        register::register(&st2.oauth, st2.store.as_ref(), &st2.anchor, &ip, now, &body)
    })
    .await
    .unwrap_or(Err(OAuthError::SERVER_ERROR));
    match out {
        Ok(v) => {
            let mut res = (StatusCode::CREATED, Json(v)).into_response();
            no_store(&mut res);
            res
        }
        Err(e) => e.into_response(),
    }
}
