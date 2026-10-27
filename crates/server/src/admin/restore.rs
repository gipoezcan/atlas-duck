//! `admin restore <bundle>` (SM-6.1, SM-6.2, SM-8.1, M13 T6). Only in maintenance mode, inside
//! the serving process (no second store opener, ADR 0003).
//!
//! Before anything live changes: the bundle is copied into `<data>/restore-staging-<stamp>/`, every
//! copied file is checked against the manifest's SHA-256, the master key id must be the loaded
//! one and every wrapped data key must open with it, the staged anchor chain must verify and end
//! at the manifest's head, and every staged user chain must open, pass a full verification and
//! reach its manifest head. Then the swap: the runtimes are quiesced, the live `server.db` is
//! copied and `<data>/users` moved to `<data>/pre-restore-<stamp>/` (kept until an admin deletes
//! it), the staged users move in and the live database takes the staged content through SQLite's
//! backup API in one step. Sessions and the API-key cache are reloaded, and `RESTORED` goes into
//! the (restored) anchor chain.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};

use super::AdminCtx;
use super::backup::{
    FORMAT, MANIFEST, MAX_MANIFEST_BYTES, Manifest, SERVER_DB, USERS_DIR, allowed_dir, safe_rel,
    sha256_file, stamp, unique_dir,
};
use crate::anchor::{KIND_RESTORED, verify};
use crate::master_key::{KeyError, WrappedKey};
use crate::runtime::{RuntimeDeps, UserHead, UserRuntime};
use crate::store::ServerStore;
use crate::store::sqlite::SqliteStore;

fn read_manifest(bundle: &Path) -> Result<Manifest, &'static str> {
    let p = bundle.join(MANIFEST);
    let meta = std::fs::metadata(&p).map_err(|_| "restore/manifest_missing")?;
    if meta.len() > MAX_MANIFEST_BYTES {
        return Err("restore/manifest_invalid");
    }
    let bytes = std::fs::read(&p).map_err(|_| "restore/manifest_missing")?;
    let m: Manifest = serde_json::from_slice(&bytes).map_err(|_| "restore/manifest_invalid")?;
    if m.format != FORMAT {
        return Err("restore/manifest_invalid");
    }
    Ok(m)
}

/// Copies every manifest file into `staging` and checks the copies' hashes.
fn stage_files(bundle: &Path, staging: &Path, m: &Manifest) -> Result<(), &'static str> {
    for f in &m.files {
        let rel = safe_rel(&f.path).ok_or("restore/manifest_invalid")?;
        let (src, dst) = (bundle.join(&rel), staging.join(&rel));
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent).map_err(|_| "restore/stage_failed")?;
        }
        std::fs::copy(&src, &dst).map_err(|_| "restore/hash_mismatch")?;
        let got = sha256_file(&dst).map_err(|_| "restore/stage_failed")?;
        if hex::encode(got) != f.sha256 {
            return Err("restore/hash_mismatch");
        }
    }
    if !staging.join(SERVER_DB).is_file() {
        return Err("restore/manifest_invalid");
    }
    Ok(())
}

/// Every check on the staged copy; answers the staged chains' heads after their verification.
async fn verify_staged(
    ctx: &AdminCtx,
    staging: &Path,
    m: &Manifest,
) -> Result<Vec<UserHead>, &'static str> {
    let deps = ctx.registry.deps();
    if m.master_key_id != deps.master.id() {
        return Err("restore/unknown_master_key");
    }
    let staged: Arc<dyn ServerStore> = match SqliteStore::open(&staging.join(SERVER_DB)) {
        Ok(s) => Arc::new(s),
        Err(crate::store::StoreError::Newer(_)) => return Err("restore/backup_newer"),
        Err(_) => return Err("restore/store_invalid"),
    };
    verify(staged.as_ref()).map_err(|_| "restore/anchor_chain_invalid")?;
    let last = staged
        .anchor_last()
        .map_err(|_| "restore/store_invalid")?
        .ok_or("restore/anchor_chain_invalid")?;
    if last.seq != m.anchor_head.seq || hex::encode(last.hash) != m.anchor_head.hash {
        return Err("restore/anchor_chain_invalid");
    }
    let users = staged.users_all().map_err(|_| "restore/store_invalid")?;
    // Retention tombstones (T8) carry no data key and no store: nothing to check or open.
    let live = |u: &crate::store::UserRecord, s: &crate::store::UserState| {
        s.chain_deleted_at.is_none() && !u.data_key_wrapped.is_empty()
    };
    for (u, _) in users.iter().filter(|(u, s)| live(u, s)) {
        let w =
            WrappedKey::from_json(&u.data_key_wrapped).map_err(|_| "restore/data_key_invalid")?;
        match deps.master.unwrap(&u.user_id, &w) {
            Ok(_) => {}
            Err(KeyError::WrongMasterKey) => return Err("restore/unknown_master_key"),
            Err(_) => return Err("restore/data_key_invalid"),
        }
    }
    let staged_deps = RuntimeDeps {
        data_dir: staging.to_path_buf(),
        store: staged.clone(),
        master: deps.master.clone(),
        org_ca: deps.org_ca.clone(),
        clock: deps.clock.clone(),
        allow_http: deps.allow_http,
        sse_capacity: deps.sse_capacity,
    };
    let mut heads = Vec::new();
    for (u, _) in users.iter().filter(|(u, s)| live(u, s)) {
        let want = m.users.iter().find(|h| h.user_id == u.user_id);
        let dir = crate::users::user_dir(staging, &u.user_id);
        if want.is_none() && !dir.exists() {
            continue; // never opened: no store, nothing anchored
        }
        if want.is_some() && !dir.exists() {
            return Err("restore/chain_invalid");
        }
        let rt = UserRuntime::open(&u.user_id, &staged_deps)
            .await
            .map_err(|_| "restore/chain_invalid")?;
        let (chain, seq, _) = rt.head();
        let reached = want.is_none_or(|h| h.chain_id == chain && seq >= h.head_seq);
        let clean = rt.full_verify().await;
        rt.close().await;
        if !reached || !clean {
            return Err("restore/chain_invalid");
        }
        heads.push((u.user_id.clone(), rt.head()));
    }
    Ok(heads)
}

/// The live swap; on a failure before the database step, the users directory is put back.
async fn swap(ctx: &AdminCtx, staging: &Path, data: &Path, pre: &Path) -> Result<(), &'static str> {
    std::fs::create_dir_all(pre).map_err(|_| "restore/swap_failed")?;
    ctx.store
        .snapshot_to(&pre.join(SERVER_DB))
        .map_err(|_| "restore/swap_failed")?;
    let live_users = data.join(USERS_DIR);
    let staged_users = staging.join(USERS_DIR);
    let had_users = live_users.exists();
    if had_users {
        std::fs::rename(&live_users, pre.join(USERS_DIR)).map_err(|_| "restore/swap_failed")?;
    }
    let moved = if staged_users.exists() {
        std::fs::rename(&staged_users, &live_users)
    } else {
        std::fs::create_dir_all(&live_users)
    };
    let undo = || {
        let _ = std::fs::remove_dir_all(&live_users);
        if had_users {
            let _ = std::fs::rename(pre.join(USERS_DIR), &live_users);
        }
    };
    if moved.is_err() {
        undo();
        return Err("restore/swap_failed");
    }
    if ctx.store.restore_from(&staging.join(SERVER_DB)).is_err() {
        undo();
        return Err("restore/swap_failed");
    }
    Ok(())
}

pub async fn run(ctx: &AdminCtx, dir: &str) -> Result<Value, &'static str> {
    if !ctx.registry.maintenance() {
        return Err("admin/maintenance_required");
    }
    let data = ctx.registry.deps().data_dir.clone();
    let bundle = allowed_dir(&data, dir)?;
    let manifest = read_manifest(&bundle)?;
    let manifest_sha256 =
        hex::encode(sha256_file(&bundle.join(MANIFEST)).map_err(|_| "restore/manifest_missing")?);
    let now = ctx.clock.now();
    let staging = unique_dir(&data, &format!("restore-staging-{}", stamp(now)));
    let staged = {
        let (b, s, m) = (bundle.clone(), staging.clone(), manifest.clone());
        tokio::task::spawn_blocking(move || stage_files(&b, &s, &m))
            .await
            .unwrap_or(Err("admin/internal"))
    };
    let checked = match staged {
        Ok(()) => verify_staged(ctx, &staging, &manifest).await,
        Err(e) => Err(e),
    };
    let verify_heads = match checked {
        Ok(h) => h,
        Err(code) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(code);
        }
    };

    let closed = ctx.registry.quiesce().await;
    if ctx.writer.record_heads(&closed).is_err() {
        tracing::error!(event = "anchor_append_failed", kind = "RUNTIME_CLOSED");
    }
    let pre: PathBuf = unique_dir(&data, &format!("pre-restore-{}", stamp(now)));
    let swapped = swap(ctx, &staging, &data, &pre).await;
    if swapped.is_ok() {
        if ctx.sessions.reload().is_err() {
            tracing::error!(event = "sessions_reload_failed");
        }
        ctx.api_keys.invalidate_all();
        ctx.writer.forget_anchored();
    }
    let _ = std::fs::remove_dir_all(&staging);
    let outcome = match swapped {
        Err(code) => Err(code),
        Ok(()) => {
            // The verification's own records (APP_START, VERIFY, APP_STOP) are anchored first.
            let rows = ctx
                .writer
                .record_heads(&verify_heads)
                .and_then(|_| {
                    ctx.writer.operational(
                        KIND_RESTORED,
                        &json!({"bundle_manifest_sha256": manifest_sha256,
                                "backup_anchor_seq": manifest.anchor_head.seq,
                                "previous": pre.file_name().map(|n| n.to_string_lossy().into_owned())}),
                    )
                })
                .map_err(|_| "anchor/append_failed");
            rows.map(|row| {
                tracing::info!(event = "restored", users = verify_heads.len());
                json!({"restored": true, "users": verify_heads.len(), "anchor_seq": row.seq,
                       "previous": pre.display().to_string()})
            })
        }
    };
    ctx.registry.resume();
    outcome
}
