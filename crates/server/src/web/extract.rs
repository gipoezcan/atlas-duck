//! The `SessionUser` extractor: the session the `/api/` guard checked (state-changing requests),
//! else the cookie's session looked up here (GET). Unknown → 401 `auth/no_session`, expired →
//! 401 `auth/session_expired`.

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;

use super::AppState;
use crate::errors::ApiError;
use crate::runtime::UserCtx;
use crate::session::{Session, cookie_value};

pub struct SessionUser(pub Session);

impl SessionUser {
    /// The request's user for the registry (the only way a web handler names a user).
    pub fn ctx(&self) -> UserCtx {
        UserCtx::from_authenticated(&self.0.user_id)
    }

    /// 403 `auth/role_required` unless the session holds `role`.
    pub fn require_role(&self, role: &str) -> Result<(), ApiError> {
        if self.0.roles.iter().any(|r| r == role) {
            Ok(())
        } else {
            Err(ApiError::ROLE_REQUIRED)
        }
    }
}

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
            .and_then(|h| cookie_value(h, st.cookie_secure))
            .ok_or(ApiError::NO_SESSION)?;
        st.sessions.lookup(cookie).map(SessionUser)
    }
}

/// The session cookie's value (logout needs it to delete the session).
pub fn cookie_of(parts: &axum::http::HeaderMap, secure: bool) -> Option<String> {
    parts
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| cookie_value(h, secure))
        .map(str::to_owned)
}

/// `Authorization: Bearer adk_…` (the `/mcp` endpoint, T19): the key's user and scopes. Every bad
/// key is 401 `auth/api_key_invalid`; a revoked or expired key of a known owner is first recorded
/// as `LOGIN {method: api_key, outcome: refused, reason}` in the owner's chain (PD-214).
pub struct BearerUser(pub crate::api_keys::KeyCtx);

impl FromRequestParts<AppState> for BearerUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, ApiError> {
        let key = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError::API_KEY_INVALID)?
            .to_owned();
        let key = zeroize::Zeroizing::new(key);
        // M14 PD-243: an OAuth access token goes to the grant check, everything else to the
        // API-key check (which also answers malformed bearers in constant work).
        if st.oauth.cfg.enabled && key.starts_with(crate::oauth::ACCESS_PREFIX) {
            return oauth_bearer(parts, st, &key).await;
        }
        // argon2id runs off the async workers.
        let keys = st.api_keys.clone();
        let outcome = tokio::task::spawn_blocking(move || keys.authenticate(&key))
            .await
            .map_err(|_| ApiError::INTERNAL)?;
        match outcome {
            Ok(ctx) => Ok(BearerUser(ctx)),
            Err(crate::api_keys::AuthFail::Refused {
                user_id,
                key_id,
                prefix,
                reason,
            }) => {
                let ip = super::client_ip(
                    &parts.headers,
                    super::peer(&parts.extensions),
                    st.trusted_proxy_hops,
                );
                let directory = if st.login.directory.kind() == "stub" {
                    crate::audit_kinds::DirectoryKind::Stub
                } else {
                    crate::audit_kinds::DirectoryKind::Ldap
                };
                let payload = crate::audit_kinds::login(&crate::audit_kinds::Login {
                    method: crate::audit_kinds::LoginMethod::ApiKey,
                    outcome: crate::audit_kinds::LoginOutcome::Refused,
                    reason: Some(reason),
                    roles: None,
                    source_ip: &ip,
                    directory,
                    key_id: Some(&key_id),
                    prefix: Some(&prefix),
                    grant_id: None,
                });
                let owner = UserCtx::from_authenticated(&user_id);
                if let Ok(rt) = st.registry.runtime(&owner).await
                    && rt
                        .append_server_record(atlas_duck_audit::EventType::LOGIN, payload)
                        .await
                        .is_err()
                {
                    tracing::error!(event = "audit_append_failed", kind = "LOGIN");
                }
                Err(ApiError::API_KEY_INVALID)
            }
            Err(crate::api_keys::AuthFail::Store) => Err(ApiError::STORE_UNAVAILABLE),
            Err(crate::api_keys::AuthFail::Invalid) => Err(ApiError::API_KEY_INVALID),
        }
    }
}

fn directory_kind(st: &AppState) -> crate::audit_kinds::DirectoryKind {
    if st.login.directory.kind() == "stub" {
        crate::audit_kinds::DirectoryKind::Stub
    } else {
        crate::audit_kinds::DirectoryKind::Ldap
    }
}

/// The OAuth branch of [`BearerUser`]: the grant check (no cache), and for a refused token of a
/// known grant `LOGIN {method: oauth, outcome: refused, reason, grant_id}` in its owner's chain,
/// at most once per grant per [`crate::oauth::REFUSAL_RECORD_EVERY`].
async fn oauth_bearer(parts: &Parts, st: &AppState, token: &str) -> Result<BearerUser, ApiError> {
    let now = st.clock.now();
    match crate::oauth::bearer::authenticate(&st.oauth, st.store.as_ref(), token, now) {
        Ok(ctx) => Ok(BearerUser(ctx)),
        Err(crate::oauth::bearer::AccessFail::Refused {
            user_id,
            grant_id,
            reason,
        }) => {
            // Once per grant and window: a token holder cannot flood the owner's chain.
            if !st.oauth.refusal_due(&grant_id, now) {
                return Err(ApiError::API_KEY_INVALID);
            }
            let ip = super::client_ip(
                &parts.headers,
                super::peer(&parts.extensions),
                st.trusted_proxy_hops,
            );
            let payload = crate::audit_kinds::login(&crate::audit_kinds::Login {
                method: crate::audit_kinds::LoginMethod::Oauth,
                outcome: crate::audit_kinds::LoginOutcome::Refused,
                reason: Some(reason),
                roles: None,
                source_ip: &ip,
                directory: directory_kind(st),
                key_id: None,
                prefix: None,
                grant_id: Some(&grant_id),
            });
            let owner = UserCtx::from_authenticated(&user_id);
            if let Ok(rt) = st.registry.runtime(&owner).await
                && rt
                    .append_server_record(atlas_duck_audit::EventType::LOGIN, payload)
                    .await
                    .is_err()
            {
                tracing::error!(event = "audit_append_failed", kind = "LOGIN");
            }
            Err(ApiError::API_KEY_INVALID)
        }
        Err(crate::oauth::bearer::AccessFail::Store) => Err(ApiError::STORE_UNAVAILABLE),
        Err(crate::oauth::bearer::AccessFail::Invalid) => Err(ApiError::API_KEY_INVALID),
    }
}
