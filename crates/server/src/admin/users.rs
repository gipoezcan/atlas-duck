//! `admin users list|deactivate` (SM-6.5, SM-8.1, M13 PD-M13-14). [`deactivate`] is the one
//! deactivation path: the CLI and the daily offboarding check (T9) both call it, and M14 extends it
//! with OAuth grant revocation (Δ-M14-4).
//!
//! Order: mark the user deactivated (no new login from here on), end every session, revoke every
//! API key (cache evicted), delete every PAT, each with its record in the user's own chain, then
//! anchor the chain's final head as `USER_DEACTIVATED`. Deactivation is final: a user who shows up
//! in the directory again stays refused. A second call finds nothing left and appends nothing.

use atlas_duck_audit::EventType;
use serde::Serialize;
use serde_json::{Map, Value};

use super::AdminCtx;
use crate::audit_kinds::{RevokedBy, api_key_revoked};
use crate::clock::rfc3339;
use crate::instances::instance_id_for;
use crate::users::{canonical, valid_username};

/// Who deactivated (`users.deactivated_by`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeactivatedBy {
    Admin,
    Offboarding,
}

impl DeactivatedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            DeactivatedBy::Admin => "admin",
            DeactivatedBy::Offboarding => "offboarding",
        }
    }
}

/// What a deactivation did (counts only; no key, PAT or session id).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeactivationReport {
    pub username: String,
    /// False when the user was already deactivated.
    pub newly_deactivated: bool,
    pub sessions_ended: usize,
    pub api_keys_revoked: usize,
    pub pats_deleted: usize,
    /// Seq of the `USER_DEACTIVATED` anchor row, when one was appended.
    pub anchor_seq: Option<u64>,
}

/// One row of `users list`: no user id, key, wrapped key or session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserView {
    pub username: String,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
    pub last_login_at: Option<String>,
    /// `active` or `deactivated`.
    pub state: &'static str,
    pub deactivated_at: Option<String>,
    pub deactivated_by: Option<String>,
}

pub fn list(ctx: &AdminCtx) -> Result<Value, &'static str> {
    let rows = ctx.store.users_all().map_err(|_| "store/unavailable")?;
    let views: Vec<UserView> = rows
        .into_iter()
        .map(|(u, s)| UserView {
            username: u.username,
            display_name: u.display_name,
            roles: u.roles,
            last_login_at: s.last_login_at.map(rfc3339),
            state: if s.deactivated_at.is_some() {
                "deactivated"
            } else {
                "active"
            },
            deactivated_at: s.deactivated_at.map(rfc3339),
            deactivated_by: s.deactivated_by,
        })
        .collect();
    serde_json::to_value(views).map_err(|_| "admin/internal")
}

/// `users deactivate <username>`.
pub async fn deactivate_by_name(ctx: &AdminCtx, username: &str) -> Result<Value, &'static str> {
    if !valid_username(username) {
        return Err("admin/user_unknown");
    }
    let user = ctx
        .store
        .user_by_name(&canonical(username))
        .map_err(|_| "store/unavailable")?
        .ok_or("admin/user_unknown")?;
    let report = deactivate(ctx, &user.user_id, DeactivatedBy::Admin).await?;
    serde_json::to_value(report).map_err(|_| "admin/internal")
}

/// Deactivates `user_id` (SM-6.5). Idempotent.
pub async fn deactivate(
    ctx: &AdminCtx,
    user_id: &str,
    by: DeactivatedBy,
) -> Result<DeactivationReport, &'static str> {
    let store = ctx.store.as_ref();
    let user = store
        .user(user_id)
        .map_err(|_| "store/unavailable")?
        .ok_or("admin/user_unknown")?;
    let now = ctx.clock.now();
    let retention_until = now.saturating_add(i64::from(ctx.retention_days) * 86_400);
    let newly = store
        .user_deactivate(user_id, now, by.as_str(), retention_until)
        .map_err(|_| "store/unavailable")?;

    // Sessions end first: the browser is out before anything else happens.
    let sessions_ended = ctx
        .sessions
        .delete_for_user(user_id)
        .map_err(|_| "store/unavailable")?;

    // API keys: revoked in the store and evicted from the cache, then recorded.
    let keys = store
        .api_keys_revoke_all(user_id, now)
        .map_err(|_| "store/unavailable")?;
    for k in &keys {
        ctx.api_keys.invalidate(&k.id);
    }
    let pats = store.pat_list(user_id).map_err(|_| "store/unavailable")?;
    let anything = newly || sessions_ended > 0 || !keys.is_empty() || !pats.is_empty();
    if !anything {
        return Ok(DeactivationReport {
            username: user.username,
            newly_deactivated: false,
            sessions_ended: 0,
            api_keys_revoked: 0,
            pats_deleted: 0,
            anchor_seq: None,
        });
    }

    let rt = ctx
        .registry
        .open_user(user_id)
        .await
        .map_err(|_| "admin/user_store_unavailable")?;
    for k in &keys {
        rt.append_server_record(
            EventType::API_KEY_REVOKED,
            api_key_revoked(&k.id, &k.prefix, RevokedBy::Deactivation),
        )
        .await
        .map_err(|e| e.code)?;
    }
    // PATs: the record goes into the chain before the PAT goes (as instance removal).
    for p in &pats {
        let mut payload = Map::new();
        payload.insert("alias".into(), Value::from(p.alias.as_str()));
        payload.insert("instance_id".into(), Value::from(instance_id_for(&p.alias)));
        payload.insert("change".into(), Value::from("deleted"));
        payload.insert("reason".into(), Value::from("user_deactivated"));
        rt.append_server_record(EventType::CREDENTIAL_CHANGED, payload)
            .await
            .map_err(|e| e.code)?;
        store
            .pat_delete(user_id, &p.alias)
            .map_err(|_| "store/unavailable")?;
    }
    let row = ctx
        .writer
        .user_deactivated(user_id, &rt.head())
        .map_err(|_| "anchor/append_failed")?;
    tracing::info!(
        event = "user_deactivated",
        user_id,
        by = by.as_str(),
        sessions = sessions_ended,
        api_keys = keys.len(),
        pats = pats.len()
    );
    Ok(DeactivationReport {
        username: user.username,
        newly_deactivated: newly,
        sessions_ended,
        api_keys_revoked: keys.len(),
        pats_deleted: pats.len(),
        anchor_seq: Some(row.seq),
    })
}
