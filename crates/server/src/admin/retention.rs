//! Retention (SM-6.5, M13 T8): a deactivated user's chain stays for auditors for the retention
//! period (`retention_until`, set at deactivation from `ATLAS_DUCK_RETENTION_DAYS`, default 365)
//! and is then deleted: the runtime is closed, the user's store directory removed, the user's
//! remaining server rows purged and the wrapped data key wiped (the row itself stays, so the user
//! stays refused at login). Each deletion is a `CHAIN_DELETED {user_id, chain_id, head_seq}` row
//! in the anchor chain, each run a `RETENTION_RUN`. `admin retention run [--dry-run]` and the daily
//! scheduler job (T9) call [`run`].

use serde::Serialize;
use serde_json::{Value, json};

use super::AdminCtx;
use crate::anchor::{KIND_CHAIN_DELETED, KIND_RETENTION_RUN};
use crate::clock::rfc3339;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Due {
    pub username: String,
    pub deactivated_at: Option<String>,
    pub retention_until: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetentionReport {
    pub dry_run: bool,
    pub due: Vec<Due>,
    pub deleted: usize,
}

/// One retention pass at the context's clock.
pub async fn run(ctx: &AdminCtx, dry_run: bool) -> Result<RetentionReport, &'static str> {
    let now = ctx.clock.now();
    let users = ctx.store.users_all().map_err(|_| "store/unavailable")?;
    let due: Vec<_> = users
        .into_iter()
        .filter(|(_, s)| {
            s.deactivated_at.is_some()
                && s.chain_deleted_at.is_none()
                && s.retention_until.is_some_and(|t| t <= now)
        })
        .collect();
    let listed: Vec<Due> = due
        .iter()
        .map(|(u, s)| Due {
            username: u.username.clone(),
            deactivated_at: s.deactivated_at.map(rfc3339),
            retention_until: s.retention_until.map(rfc3339),
        })
        .collect();
    if dry_run {
        return Ok(RetentionReport {
            dry_run,
            due: listed,
            deleted: 0,
        });
    }
    let latest = ctx
        .store
        .anchor_latest_heads()
        .map_err(|_| "store/unavailable")?;
    let data = ctx.registry.deps().data_dir.clone();
    let mut deleted = 0;
    for (u, _) in &due {
        // The final head: the open runtime's, else the last one anchored.
        let head = match ctx.registry.close_user(&u.user_id).await {
            Some(h) => {
                ctx.writer
                    .record_heads(&[(u.user_id.clone(), h.clone())])
                    .map_err(|_| "anchor/append_failed")?;
                Some((h.0, h.1))
            }
            None => latest
                .iter()
                .find(|h| h.user_id == u.user_id)
                .map(|h| (h.chain_id.clone(), h.head_seq)),
        };
        let dir = crate::users::user_dir(&data, &u.user_id);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("retention/delete_failed"),
        }
        ctx.store
            .user_purge(&u.user_id, now)
            .map_err(|_| "store/unavailable")?;
        ctx.writer.forget_user(&u.user_id);
        let (chain_id, head_seq) = head.unwrap_or_default();
        ctx.writer
            .operational(
                KIND_CHAIN_DELETED,
                &json!({"user_id": u.user_id, "chain_id": chain_id, "head_seq": head_seq}),
            )
            .map_err(|_| "anchor/append_failed")?;
        tracing::info!(event = "chain_deleted", user_id = %u.user_id);
        deleted += 1;
    }
    ctx.writer
        .operational(
            KIND_RETENTION_RUN,
            &json!({"deleted": deleted, "due": due.len()}),
        )
        .map_err(|_| "anchor/append_failed")?;
    Ok(RetentionReport {
        dry_run,
        due: listed,
        deleted,
    })
}

/// `admin retention run [--dry-run]`.
pub async fn admin(ctx: &AdminCtx, dry_run: bool) -> Result<Value, &'static str> {
    serde_json::to_value(run(ctx, dry_run).await?).map_err(|_| "admin/internal")
}
