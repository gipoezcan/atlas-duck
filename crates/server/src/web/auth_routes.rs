//! `POST /api/login`, `POST /api/logout`, `GET /api/session` (SM-2.1, SM-2.4). The login body is
//! never logged; the password becomes a `SecretString` as it is parsed.

use axum::Json;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;

use super::extract::{SessionUser, cookie_of};
use super::{AppState, BODY_LIMIT, client_ip, peer};
use crate::clock::rfc3339;
use crate::errors::ApiError;
use crate::session::{clear_cookie, set_cookie};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBody {
    username: String,
    /// Final review M2: a `SecretString` straight from the parser, never a plain field.
    #[serde(deserialize_with = "secret_string")]
    password: SecretString,
}

fn secret_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<SecretString, D::Error> {
    let s = zeroize::Zeroizing::new(<String as serde::Deserialize>::deserialize(d)?);
    Ok(SecretString::from(s.as_str()))
}

/// Reads at most `BODY_LIMIT` bytes of a body.
pub async fn body_bytes(body: Body) -> Result<axum::body::Bytes, ApiError> {
    axum::body::to_bytes(body, BODY_LIMIT)
        .await
        .map_err(|_| ApiError::BODY_TOO_LARGE)
}

fn with_cookie(mut res: Response, cookie: &str) -> Response {
    if let Ok(v) = HeaderValue::from_str(cookie) {
        res.headers_mut().insert(header::SET_COOKIE, v);
    }
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

pub async fn login(State(st): State<AppState>, req: Request) -> Result<Response, ApiError> {
    let ip = client_ip(req.headers(), peer(req.extensions()), st.trusted_proxy_hops);
    let bytes = body_bytes(req.into_body()).await?;
    let body: LoginBody = serde_json::from_slice(&bytes).map_err(|_| ApiError::BAD_REQUEST)?;
    drop(bytes);
    let LoginBody { username, password } = body;
    let ok = st.login.login(&username, password, &ip).await?;
    let s = &ok.created.session;
    let answer = Json(json!({
        "user": ok.user.username,
        "roles": s.roles,
        "csrf_token": s.csrf_token.expose_secret(),
        "expires_at": rfc3339(s.absolute_expiry),
    }));
    Ok(with_cookie(
        answer.into_response(),
        &set_cookie(&ok.created.cookie_id, st.cookie_secure),
    ))
}

pub async fn logout(
    State(st): State<AppState>,
    SessionUser(_): SessionUser,
    req: Request,
) -> Result<Response, ApiError> {
    if let Some(id) = cookie_of(req.headers(), st.cookie_secure) {
        st.sessions.delete(&id)?;
    }
    Ok(with_cookie(
        StatusCode::NO_CONTENT.into_response(),
        &clear_cookie(st.cookie_secure),
    ))
}

pub async fn session(
    State(st): State<AppState>,
    SessionUser(s): SessionUser,
) -> Result<Response, ApiError> {
    let user = st
        .store
        .user(&s.user_id)
        .map_err(|_| ApiError::STORE_UNAVAILABLE)?
        .ok_or(ApiError::NO_SESSION)?;
    // M15 T4 (PD-295): the page resolves `auto` against the browser's language.
    let lang_pref = st
        .store
        .user_lang_pref(&s.user_id)
        .map_err(|_| ApiError::STORE_UNAVAILABLE)?;
    let mut res = Json(json!({
        "user": user.username,
        "roles": s.roles,
        "csrf_token": s.csrf_token.expose_secret(),
        "expires_at": rfc3339(s.absolute_expiry),
        "idle_expires_at": rfc3339(s.idle_expiry),
        "lang_pref": lang_pref.as_str(),
    }))
    .into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}
