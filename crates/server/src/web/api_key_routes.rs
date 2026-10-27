//! `GET/POST /api/me/api-keys`, `DELETE /api/me/api-keys/{id}` (SM-3.2; session + CSRF via the
//! `/api` guard, which also refuses any bearer here). The key string is answered once, at
//! creation; lists carry no key and no hash. `API_KEY_CREATED` / `API_KEY_REVOKED {by: user}` go
//! into the user's chain.

use atlas_duck_audit::EventType;
use axum::Json;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_json::json;

use super::AppState;
use super::auth_routes::body_bytes;
use super::extract::SessionUser;
use crate::audit_kinds::{RevokedBy, api_key_created, api_key_revoked};
use crate::clock::rfc3339;
use crate::errors::ApiError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    name: String,
    scopes: Vec<String>,
    #[serde(default)]
    expires_in_days: Option<u64>,
}

pub async fn list(State(st): State<AppState>, user: SessionUser) -> Result<Response, ApiError> {
    Ok(Json(st.api_keys.list(&user.ctx())?).into_response())
}

pub async fn create(
    State(st): State<AppState>,
    user: SessionUser,
    req: Request,
) -> Result<Response, ApiError> {
    let bytes = body_bytes(req.into_body()).await?;
    let body: CreateBody = serde_json::from_slice(&bytes).map_err(|_| ApiError::BAD_REQUEST)?;
    let ctx = user.ctx();
    let prepared = st
        .api_keys
        .prepare(&ctx, &body.name, &body.scopes, body.expires_in_days)?;
    let v = prepared.view();
    let scopes: Vec<&str> = v.scopes.iter().map(String::as_str).collect();
    // Final review I2: audit before effect. The key is stored only after `API_KEY_CREATED`
    // committed; a failed append leaves no key at all.
    let rt = st.registry.runtime(&ctx).await?;
    rt.append_server_record(
        EventType::API_KEY_CREATED,
        api_key_created(&v.id, &v.name, &v.prefix, &scopes, &rfc3339(v.expires_at)),
    )
    .await?;
    drop(rt);
    let created = match st.api_keys.insert(prepared) {
        Ok(c) => c,
        Err(e) => {
            // Final review I1: the record names a key that was never stored; say so.
            tracing::error!(event = "api_key_insert_failed", key_id = %v.id);
            return Err(e);
        }
    };
    let v = &created.view;
    let mut res = (
        StatusCode::CREATED,
        Json(json!({
            "id": v.id,
            "key": created.key.expose_secret(),
            "name": v.name,
            "prefix": v.prefix,
            "scopes": v.scopes,
            "created_at": v.created_at,
            "expires_at": v.expires_at,
        })),
    )
        .into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

pub async fn revoke(
    State(st): State<AppState>,
    user: SessionUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let ctx = user.ctx();
    let key = st
        .api_keys
        .list(&ctx)?
        .into_iter()
        .find(|k| k.id == id && k.revoked_at.is_none())
        .ok_or(ApiError::NOT_FOUND)?;
    // Audit before effect: the record commits, then the key stops working.
    let rt = st.registry.runtime(&ctx).await?;
    rt.append_server_record(
        EventType::API_KEY_REVOKED,
        api_key_revoked(&key.id, &key.prefix, RevokedBy::User),
    )
    .await?;
    st.api_keys.revoke(&ctx, &id)?.ok_or(ApiError::NOT_FOUND)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
