//! `admin rotate-master-key --new-key-file <path>` and `admin master-key status` (SM-6.2,
//! ADR 0002, M13 T7, batch-2 review I1/I2).
//!
//! The new key must already be loaded from `ATLAS_DUCK_MASTER_KEY_NEXT_FILE` (the
//! `masterKey.nextSecret` mount): the file given must be that key, so a restart at any point finds
//! every row wrapped under a mounted key. The new key becomes the primary first, so data keys
//! created during the run (first logins) are wrapped under it; then every row still under another
//! id is re-wrapped one at a time (compare-and-set), pass after pass, until none is left. Then
//! `MASTER_KEY_ROTATED {old_key_id, new_key_id}` goes into the anchor chain. `master-key status`
//! counts the rows per key id; the runbook swaps the Secret only when `rows_not_primary` is 0.
//! Output: key ids and counts only.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};

use super::AdminCtx;
use crate::anchor::KIND_MASTER_KEY_ROTATED;
use crate::master_key::{MasterKey, RingError, WrappedKey};
use crate::store::ServerStore;

pub async fn run(ctx: &AdminCtx, new_key_file: &str) -> Result<Value, &'static str> {
    let new = MasterKey::load(Path::new(new_key_file)).map_err(|_| "rotate/key_file_invalid")?;
    run_with(ctx, new, None)
}

/// The key id of every live row (retention tombstones carry none).
fn row_key_ids(store: &dyn ServerStore) -> Result<Vec<(String, String, String)>, &'static str> {
    let users = store.users_all().map_err(|_| "store/unavailable")?;
    let mut out = Vec::new();
    for (u, s) in users {
        if s.chain_deleted_at.is_some() || u.data_key_wrapped.is_empty() {
            continue;
        }
        let w =
            WrappedKey::from_json(&u.data_key_wrapped).map_err(|_| "rotate/data_key_invalid")?;
        out.push((u.user_id, w.master_key_id, u.data_key_wrapped));
    }
    Ok(out)
}

/// The rotation with an already loaded key file; `stop_after` re-wraps at most that many rows and
/// then fails as a crash would (tests of the resume path).
pub fn run_with(
    ctx: &AdminCtx,
    new: MasterKey,
    stop_after: Option<usize>,
) -> Result<Value, &'static str> {
    let master = ctx.registry.deps().master.clone();
    let new_id = new.id();
    // I2: only the mounted next key, so crash safety never depends on the file the operator typed.
    if !master.knows(&new_id) {
        return Err("rotate/next_key_not_mounted");
    }
    match master.accept(new) {
        Ok(()) => {}
        Err(RingError::SameKey) => return Err("rotate/same_key"),
        Err(RingError::IdConflict) => return Err("rotate/key_id_conflict"),
    }
    let primary = master.id();
    let old_id = if primary == new_id {
        master.ids().into_iter().find(|id| *id != new_id)
    } else {
        Some(primary)
    };
    let Some(old_id) = old_id else {
        return Err("rotate/same_key");
    };
    // I1: new data keys from here on are wrapped under the new key.
    master.promote(&new_id);
    let (mut rewrapped, mut already) = (0usize, 0usize);
    let mut first_pass = true;
    loop {
        let rows = row_key_ids(ctx.store.as_ref())?;
        let mut this_pass = 0usize;
        for (user_id, key_id, json_text) in &rows {
            if *key_id == new_id {
                if first_pass {
                    already += 1;
                }
                continue;
            }
            if stop_after.is_some_and(|n| rewrapped >= n) {
                return Err("rotate/interrupted");
            }
            let w = WrappedKey::from_json(json_text).map_err(|_| "rotate/data_key_invalid")?;
            let dk = master
                .unwrap(user_id, &w)
                .map_err(|_| "rotate/unwrap_failed")?;
            let nw = master
                .wrap_with(&new_id, user_id, &dk)
                .map_err(|_| "rotate/wrap_failed")?;
            // Compare-and-set; a row that changed meanwhile is picked up by the next pass.
            if ctx
                .store
                .user_set_wrapped(user_id, json_text, &nw.to_json())
                .map_err(|_| "store/unavailable")?
            {
                rewrapped += 1;
                this_pass += 1;
            }
        }
        first_pass = false;
        let left = row_key_ids(ctx.store.as_ref())?
            .iter()
            .filter(|(_, k, _)| *k != new_id)
            .count();
        if left == 0 {
            break;
        }
        if this_pass == 0 {
            return Err("rotate/rows_left");
        }
    }
    let users = row_key_ids(ctx.store.as_ref())?.len();
    ctx.writer
        .operational(
            KIND_MASTER_KEY_ROTATED,
            &json!({"old_key_id": old_id, "new_key_id": new_id, "users": users}),
        )
        .map_err(|_| "anchor/append_failed")?;
    tracing::info!(
        event = "master_key_rotated",
        old_key_id = %old_id,
        new_key_id = %new_id,
        rewrapped
    );
    Ok(
        json!({"old_key_id": old_id, "new_key_id": new_id, "rewrapped": rewrapped,
              "already_rewrapped": already, "rows_not_primary": 0}),
    )
}

/// `admin master-key status`: the loaded ids and how many rows each id wraps.
pub fn status(ctx: &AdminCtx) -> Result<Value, &'static str> {
    let master = &ctx.registry.deps().master;
    let primary = master.id();
    let mut by_id: BTreeMap<String, usize> = BTreeMap::new();
    for (_, k, _) in row_key_ids(ctx.store.as_ref())? {
        *by_id.entry(k).or_insert(0) += 1;
    }
    let not_primary: usize = by_id
        .iter()
        .filter(|(k, _)| **k != primary)
        .map(|(_, n)| n)
        .sum();
    Ok(
        json!({"primary": primary, "loaded": master.ids(), "rows_by_key_id": by_id,
              "rows_not_primary": not_primary}),
    )
}

/// At start (I1b): when the next key is mounted and already wraps some row, a rotation was under
/// way, so the next key becomes the primary again (new data keys must not go under the old one).
pub fn promote_next_if_in_use(
    master: &MasterKey,
    store: &dyn ServerStore,
    next_id: &str,
) -> Result<bool, &'static str> {
    let in_use = row_key_ids(store)?.iter().any(|(_, k, _)| k == next_id);
    if in_use {
        master.promote(next_id);
    }
    Ok(in_use)
}
