//! Connected apps (M14 T9, SM-3.3 "revocable from the web UI", PD-245): the session user's OAuth
//! grants and their revocation. Lists never carry a token or a hash; another user's grant id is
//! answered like an unknown one.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use super::AppState;
use super::extract::SessionUser;
use crate::audit_kinds::{GrantRevokedBy, oauth_grant_revoked};
use crate::errors::ApiError;
use crate::oauth::redirect::host_of;

/// One row of the connected-apps page.
#[derive(Debug, Serialize)]
pub struct GrantView {
    pub grant_id: String,
    pub client_id: String,
    pub client_name: String,
    pub redirect_hosts: Vec<String>,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}

/// `GET /api/me/oauth/grants`: newest first, ended grants included.
pub async fn list(State(st): State<AppState>, user: SessionUser) -> Response {
    let grants = match st.store.grant_list(&user.0.user_id) {
        Ok(g) => g,
        Err(_) => return ApiError::STORE_UNAVAILABLE.into_response(),
    };
    let mut out = Vec::with_capacity(grants.len());
    for g in grants {
        let client = st.store.oauth_client_get(&g.client_id).ok().flatten();
        let (client_name, mut redirect_hosts) = match client {
            Some(c) => (
                c.name,
                c.redirect_uris
                    .iter()
                    .map(|u| host_of(u))
                    .collect::<Vec<_>>(),
            ),
            None => (String::new(), Vec::new()),
        };
        redirect_hosts.sort();
        redirect_hosts.dedup();
        out.push(GrantView {
            grant_id: g.grant_id,
            client_id: g.client_id,
            client_name,
            redirect_hosts,
            scopes: g.scopes,
            created_at: g.created_at,
            last_used_at: g.last_used_at,
            expires_at: g.expires_at,
            revoked_at: g.revoked_at,
        });
    }
    Json(out).into_response()
}

/// `DELETE /api/me/oauth/grants/{id}` (session + CSRF): `OAUTH_GRANT_REVOKED {by: user}` in the
/// user's chain, then the grant and all its tokens are dead (the bearer check reads the grant).
pub async fn revoke(
    State(st): State<AppState>,
    user: SessionUser,
    Path(id): Path<String>,
) -> Response {
    let g = match st.store.grant_get(&id) {
        Ok(Some(g)) if g.user_id == user.0.user_id => g,
        Ok(_) => return ApiError::OAUTH_GRANT_UNKNOWN.into_response(),
        Err(_) => return ApiError::STORE_UNAVAILABLE.into_response(),
    };
    if g.revoked_at.is_some() {
        return StatusCode::NO_CONTENT.into_response();
    }
    let rt = match st.registry.runtime(&user.ctx()).await {
        Ok(rt) => rt,
        Err(e) => return e.into_response(),
    };
    // Audit before effect.
    if let Err(e) = rt
        .append_server_record(
            atlas_duck_audit::EventType::OAUTH_GRANT_REVOKED,
            oauth_grant_revoked(&g.grant_id, &g.client_id, GrantRevokedBy::User),
        )
        .await
    {
        return e.into_response();
    }
    match st
        .store
        .grant_revoke(&g.grant_id, GrantRevokedBy::User.as_str(), st.clock.now())
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => ApiError::STORE_UNAVAILABLE.into_response(),
    }
}
