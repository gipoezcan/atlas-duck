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
    /// `active`, `deactivated` or `deleted` (retention removed the chain).
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
            state: if s.chain_deleted_at.is_some() {
                "deleted"
            } else if s.deactivated_at.is_some() {
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

/// Whether a `USER_DEACTIVATED` row already anchors this user's final head.
fn deactivation_anchored(
    store: &dyn crate::store::ServerStore,
    user_id: &str,
) -> Result<bool, &'static str> {
    let rows = store.anchor_all().map_err(|_| "store/unavailable")?;
    for r in rows
        .iter()
        .filter(|r| r.kind == crate::anchor::KIND_USER_DEACTIVATED)
    {
        let heads = store
            .anchor_heads_for(r.seq)
            .map_err(|_| "store/unavailable")?;
        if heads.iter().any(|h| h.user_id == user_id) {
            return Ok(true);
        }
    }
    Ok(false)
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

    // Batch-1 review I-2: every record goes into the chain before its effect, and what is still
    // owed is derived from the stored state, so a retry after any failure completes the audit.
    // Meanwhile the keys are already dead: the deactivated flag refuses them (api_keys.rs).
    let keys: Vec<_> = store
        .api_key_list(user_id)
        .map_err(|_| "store/unavailable")?
        .into_iter()
        .filter(|k| k.revoked_at.is_none())
        .collect();
    let pats = store.pat_list(user_id).map_err(|_| "store/unavailable")?;
    let anchored = deactivation_anchored(store, user_id)?;
    if keys.is_empty() && pats.is_empty() && anchored {
        return Ok(DeactivationReport {
            username: user.username,
            newly_deactivated: newly,
            sessions_ended,
            api_keys_revoked: 0,
            pats_deleted: 0,
            anchor_seq: None,
        });
    }

    let rt = ctx.registry.open_user(user_id).await.map_err(|e| {
        tracing::warn!(event = "user_store_unavailable", user_id, error = ?e);
        "admin/user_store_unavailable"
    })?;
    for k in &keys {
        rt.append_server_record(
            EventType::API_KEY_REVOKED,
            api_key_revoked(&k.id, &k.prefix, RevokedBy::Deactivation),
        )
        .await
        .map_err(|e| e.code)?;
        store
            .api_key_revoke(user_id, &k.id, now)
            .map_err(|_| "store/unavailable")?;
        ctx.api_keys.invalidate(&k.id);
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
