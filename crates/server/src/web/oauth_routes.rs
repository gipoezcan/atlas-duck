//! The OAuth HTTP surface (M14 T6–T8): discovery documents, registration, and (later tasks)
//! authorization, consent, token and revocation. Protocol endpoints answer in the RFC formats
//! (PD-239); `ATLAS_DUCK_OAUTH=disabled` makes every one of them 404 `oauth/disabled`.

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::extract::SessionUser;
use super::{AppState, client_ip, peer};
use crate::errors::ApiError;
use crate::oauth::error::{OAuthError, no_store};
use crate::oauth::{authorize, consent, metadata, register};

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

/// `GET /oauth/authorize` (T7): never answers an error body to the browser; it redirects to our
/// error page, the login page, the validated client redirect or the consent page.
pub async fn authorize(State(st): State<AppState>, req: Request<Body>) -> Response {
    if !st.oauth.cfg.enabled {
        return ApiError::OAUTH_DISABLED.into_response();
    }
    let (mut parts, _) = req.into_parts();
    let query = parts.uri.query().map(str::to_owned);
    let session = SessionUser::from_request_parts(&mut parts, &st).await.ok();
    let browser = session.as_ref().map(|s| authorize::Browser {
        user_id: &s.0.user_id,
        session_hash: s.0.id_hash,
    });
    let out = authorize::authorize(
        &st.oauth,
        st.store.as_ref(),
        query.as_deref(),
        browser,
        st.clock.now(),
    );
    let location = match out {
        authorize::Outcome::ErrorPage(code) => {
            format!("{}?error={code}", authorize::ERROR_PAGE)
        }
        authorize::Outcome::Login => {
            let back = match &query {
                Some(q) => format!("{}?{q}", metadata::AUTHORIZE_PATH),
                None => metadata::AUTHORIZE_PATH.to_owned(),
            };
            let next: String = url::form_urlencoded::byte_serialize(back.as_bytes()).collect();
            format!("/login?next={next}")
        }
        authorize::Outcome::ErrorRedirect(to) | authorize::Outcome::Consent(to) => to,
    };
    let mut res = StatusCode::FOUND.into_response();
    if let Ok(v) = HeaderValue::from_str(&location) {
        res.headers_mut().insert(header::LOCATION, v);
    }
    no_store(&mut res);
    res
}

/// `GET /api/oauth/consent/{req}` (T7).
pub async fn consent_details(
    State(st): State<AppState>,
    user: SessionUser,
    Path(req): Path<String>,
) -> Response {
    if !st.oauth.cfg.enabled {
        return ApiError::OAUTH_DISABLED.into_response();
    }
    match consent::details(st.store.as_ref(), &req, &user.0.id_hash, st.clock.now()) {
        Ok(v) => {
            let mut res = Json(v).into_response();
            no_store(&mut res);
            res
        }
        Err(e) => e.into_response(),
    }
}

/// `POST /api/oauth/consent/{req}` (T7): session + CSRF + Origin through the `/api/` guard.
pub async fn consent_decide(
    State(st): State<AppState>,
    user: SessionUser,
    Path(req): Path<String>,
    body: Result<Json<consent::DecisionBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !st.oauth.cfg.enabled {
        return ApiError::OAUTH_DISABLED.into_response();
    }
    let Ok(Json(body)) = body else {
        return ApiError::BAD_REQUEST.into_response();
    };
    let rt = match st.registry.runtime(&user.ctx()).await {
        Ok(rt) => rt,
        Err(e) => return e.into_response(),
    };
    match consent::decide(
        &st.oauth,
        st.store.as_ref(),
        &rt,
        &req,
        &user.0.id_hash,
        body,
        st.clock.now(),
    )
    .await
    {
        Ok(redirect) => {
            let mut res = Json(serde_json::json!({ "redirect": redirect })).into_response();
            no_store(&mut res);
            res
        }
        Err(e) => e.into_response(),
    }
}
