//! `PUT /api/me/preferences` (M15 T4, PD-295): the session user's own display preferences, today
//! the UI language. Session + CSRF + Origin through the `/api` guard (a bearer is refused there).
//! A display preference: no audit record, no anchor row.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::AppState;
use super::auth_routes::body_bytes;
use super::extract::SessionUser;
use crate::errors::ApiError;
use crate::store::LangPref;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrefsBody {
    lang_pref: String,
}

pub async fn put(
    State(st): State<AppState>,
    SessionUser(s): SessionUser,
    req: Request,
) -> Result<Response, ApiError> {
    let bytes = body_bytes(req.into_body()).await?;
    let body: PrefsBody = serde_json::from_slice(&bytes).map_err(|_| ApiError::BAD_REQUEST)?;
    let pref = LangPref::parse(&body.lang_pref).ok_or(ApiError::BAD_REQUEST)?;
    st.store
        .set_user_lang_pref(&s.user_id, pref)
        .map_err(|_| ApiError::STORE_UNAVAILABLE)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
