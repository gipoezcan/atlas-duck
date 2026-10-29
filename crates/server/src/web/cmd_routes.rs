//! `POST /api/cmd/{command}` and `GET /api/events` (SM-3.4, SM-5.1, SM-5.2): session only; the
//! `/api` guard has already refused a bearer, a foreign Origin and a missing CSRF token, so an
//! approval decision is reachable only from the user's own browser session.

use axum::Json;
use axum::extract::{Path, Request, State};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use super::AppState;
use super::auth_routes::body_bytes;
use super::extract::{SessionUser, cookie_of};
use crate::cmd::{self, CmdError};
use crate::errors::ApiError;

fn cmd_error(e: CmdError) -> Response {
    (e.status(), Json(e)).into_response()
}

pub async fn command(
    State(st): State<AppState>,
    user: SessionUser,
    Path(name): Path<String>,
    req: Request,
) -> Response {
    if !cmd::SERVER_COMMANDS.contains(&name.as_str()) {
        return cmd_error(CmdError::UnknownCommand);
    }
    // M15 T10b: the preview and payload documents in the reader's language.
    let lang = super::pref_routes::reader_lang(&st, &user.0.user_id, req.headers());
    let bytes = match body_bytes(req.into_body()).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let body: Value = if bytes.is_empty() {
        Value::Object(Default::default())
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return cmd_error(CmdError::InvalidArgument { field: "payload" }),
        }
    };
    let rt = match st.registry.runtime(&user.ctx()).await {
        Ok(rt) => rt,
        Err(e) => return e.into_response(),
    };
    // M14 T16: the audit reads go to the user's own store (SM-6.4 first sentence).
    let answer = if cmd::AUDIT_COMMANDS.contains(&name.as_str()) {
        cmd::run_audit(rt.audit_handle(), name, body, lang).await
    } else {
        cmd::run(rt.decisions(), name, body, lang).await
    };
    match answer {
        Ok(v) => Json(v).into_response(),
        Err(e) => cmd_error(e),
    }
}

pub async fn events(
    State(st): State<AppState>,
    user: SessionUser,
    req: Request,
) -> Result<Response, ApiError> {
    let cookie = cookie_of(req.headers(), st.cookie_secure).ok_or(ApiError::NO_SESSION)?;
    let rt = st.registry.runtime(&user.ctx()).await?;
    let pin = rt.try_sse_pin().ok_or(ApiError::TOO_MANY_STREAMS)?;
    let rx = rt.events();
    Ok(crate::sse::stream(rx, Some(pin), st.sessions.clone(), cookie).into_response())
}
