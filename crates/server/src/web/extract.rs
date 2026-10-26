//! The `SessionUser` extractor: the session the `/api/` guard checked (state-changing requests),
//! else the cookie's session looked up here (GET). Unknown → 401 `auth/no_session`, expired →
//! 401 `auth/session_expired`.

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;

use super::AppState;
use crate::errors::ApiError;
use crate::session::{Session, cookie_value};

pub struct SessionUser(pub Session);

impl FromRequestParts<AppState> for SessionUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, ApiError> {
        if let Some(s) = parts.extensions.get::<Session>() {
            return Ok(SessionUser(s.clone()));
        }
        let cookie = parts
            .headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(cookie_value)
            .ok_or(ApiError::NO_SESSION)?;
        st.sessions.lookup(cookie).map(SessionUser)
    }
}

/// The session cookie's value (logout needs it to delete the session).
pub fn cookie_of(parts: &axum::http::HeaderMap) -> Option<String> {
    parts
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(cookie_value)
        .map(str::to_owned)
}
