//! `admin rotate-master-key --new-key-file <path>` (SM-6.2, ADR 0002, M13 T7).
//!
//! The new key (the `masterKey.nextSecret` mount) joins the loaded keys, every user's data key is
//! re-wrapped under it one row at a time (compare-and-set, so a row is always wrapped under some
//! loaded key), then the new key becomes the primary and `MASTER_KEY_ROTATED {old_key_id,
//! new_key_id}` goes into the anchor chain. A crash part-way is safe: with both keys mounted
//! (`ATLAS_DUCK_MASTER_KEY_NEXT_FILE`) the restarted server opens every user, and running the
//! command again re-wraps only the rows still under the old key. Output: key ids and counts only.

use std::path::Path;

use serde_json::{Value, json};

use super::AdminCtx;
use crate::anchor::KIND_MASTER_KEY_ROTATED;
use crate::master_key::{MasterKey, RingError, WrappedKey};

pub async fn run(ctx: &AdminCtx, new_key_file: &str) -> Result<Value, &'static str> {
    let new = MasterKey::load(Path::new(new_key_file)).map_err(|_| "rotate/key_file_invalid")?;
    run_with(ctx, new, None)
}

/// The rotation with an already loaded key; `stop_after` re-wraps at most that many rows and then
/// fails as a crash would (tests of the resume path).
pub fn run_with(
    ctx: &AdminCtx,
    new: MasterKey,
    stop_after: Option<usize>,
) -> Result<Value, &'static str> {
    let master = ctx.registry.deps().master.clone();
    let old_id = master.id();
    let new_id = new.id();
    if new_id == old_id {
        return Err("rotate/same_key");
    }
    match master.accept(new) {
        Ok(()) => {}
        Err(RingError::SameKey) => return Err("rotate/same_key"),
        Err(RingError::IdConflict) => return Err("rotate/key_id_conflict"),
    }
    let users = ctx.store.users_all().map_err(|_| "store/unavailable")?;
    let (mut rewrapped, mut already) = (0usize, 0usize);
    for (u, _) in &users {
        let w =
            WrappedKey::from_json(&u.data_key_wrapped).map_err(|_| "rotate/data_key_invalid")?;
        if w.master_key_id == new_id {
            already += 1;
            continue;
        }
        if stop_after.is_some_and(|n| rewrapped >= n) {
            return Err("rotate/interrupted");
        }
        let dk = master
            .unwrap(&u.user_id, &w)
            .map_err(|_| "rotate/unwrap_failed")?;
        let nw = master
            .wrap_with(&new_id, &u.user_id, &dk)
            .map_err(|_| "rotate/wrap_failed")?;
        // Compare-and-set: a row changed meanwhile (a new login cannot change it) is reported.
        if !ctx
            .store
            .user_set_wrapped(&u.user_id, &u.data_key_wrapped, &nw.to_json())
            .map_err(|_| "store/unavailable")?
        {
            return Err("rotate/concurrent_change");
        }
        rewrapped += 1;
    }
    master.promote(&new_id);
    ctx.writer
        .operational(
            KIND_MASTER_KEY_ROTATED,
            &json!({"old_key_id": old_id, "new_key_id": new_id, "users": users.len()}),
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
              "already_rewrapped": already}),
    )
}
