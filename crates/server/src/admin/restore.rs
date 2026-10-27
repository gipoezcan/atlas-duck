//! `admin restore <bundle>` (SM-6.1, SM-6.2, SM-8.1, M13 T6). Only in maintenance mode, inside
//! the serving process (no second store opener, ADR 0003).
//!
//! Before anything live changes: the bundle is copied into `<data>/restore-staging-<stamp>/`, every
//! copied file is checked against the manifest's SHA-256, the master key id must be the loaded
//! one and every wrapped data key must open with it, the staged anchor chain must verify and end
//! at the manifest's head, and every staged user chain must open, pass a full verification and
//! reach its manifest head. Then the swap, with the runtimes quiesced:
//! 1. the live data is written as a full bundle `<data>/backups/pre-restore-<stamp>/` (manifest,
//!    hashes), so going back is an ordinary `admin restore` of it (batch-1 review I-1);
//! 2. the journal `<data>/restore-in-progress` (staging, replaced and pre-restore paths) is
//!    written and fsync'd;
//! 3. `<data>/users` moves aside, the staged users move in, and the live database takes the
//!    staged content through SQLite's backup API in one step;
//! 4. sessions and the API-key cache reload, `RESTORED` is anchored, the journal goes.
//!
//! A crash between 2 and 4 leaves the journal. The next start then keeps the server in
//! maintenance (`/readyz` reason `restore_interrupted`) and logs how to recover: `admin restore
//! --resume` finishes the verified swap, or `admin restore <pre-restore bundle>` goes back.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};

use super::AdminCtx;
use super::backup::{
    FORMAT, MANIFEST, MAX_MANIFEST_BYTES, Manifest, SERVER_DB, USERS_DIR, allowed_dir, safe_rel,
    sha256_file, stamp, sync_dir, sync_file, unique_dir, write_bundle,
};
use crate::anchor::{KIND_RESTORED, verify};
use crate::clock::rfc3339;
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
        sync_file(&dst).map_err(|_| "restore/stage_failed")?;
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
    // Final review I2: any loaded key will do (the old key mounted as the next one, to restore a
    // pre-rotation bundle); the per-row unwrap below is the real gate.
    let ids = if m.key_ids.is_empty() {
        std::slice::from_ref(&m.master_key_id)
    } else {
        m.key_ids.as_slice()
    };
    if !ids.iter().all(|id| deps.master.knows(id)) {
        return Err("restore/unknown_master_key");
    }
    let staged: Arc<dyn ServerStore> =
        match SqliteStore::open_with(&staging.join(SERVER_DB), deps.journal) {
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
        journal: deps.journal,
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

/// The journal of a swap in progress (batch-1 review I-1).
pub const JOURNAL: &str = "restore-in-progress";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    staging: PathBuf,
    replaced: PathBuf,
    pre: PathBuf,
    manifest_sha256: String,
    backup_anchor_seq: u64,
}

/// Whether a restore was interrupted in `data` (startup and `/readyz` ask).
pub fn interrupted(data: &Path) -> bool {
    data.join(JOURNAL).exists()
}

fn read_journal(data: &Path) -> Option<Journal> {
    serde_json::from_slice(&std::fs::read(data.join(JOURNAL)).ok()?).ok()
}

fn write_journal(data: &Path, j: &Journal) -> Result<(), &'static str> {
    let p = data.join(JOURNAL);
    let bytes = serde_json::to_vec(j).map_err(|_| "admin/internal")?;
    std::fs::write(&p, bytes).map_err(|_| "restore/swap_failed")?;
    sync_file(&p).map_err(|_| "restore/swap_failed")?;
    sync_dir(data);
    Ok(())
}

/// Where a test stops a swap as a crash would (no cleanup at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrashAt {
    Never,
    AfterUsersMoved,
}

/// Moves the staged users in (the live ones aside) and gives the live database the staged
/// content. Idempotent, so `--resume` can run it again after a crash.
fn swap_files(
    ctx: &AdminCtx,
    data: &Path,
    j: &Journal,
    crash: CrashAt,
) -> Result<(), &'static str> {
    let live = data.join(USERS_DIR);
    let staged = j.staging.join(USERS_DIR);
    if staged.exists() {
        if live.exists() && !j.replaced.exists() {
            std::fs::rename(&live, &j.replaced).map_err(|_| "restore/swap_failed")?;
        } else if live.exists() {
            std::fs::remove_dir_all(&live).map_err(|_| "restore/swap_failed")?;
        }
        std::fs::rename(&staged, &live).map_err(|_| "restore/swap_failed")?;
    } else if !live.exists() {
        std::fs::create_dir_all(&live).map_err(|_| "restore/swap_failed")?;
    }
    sync_dir(data);
    if crash == CrashAt::AfterUsersMoved {
        return Err("restore/interrupted");
    }
    ctx.store
        .restore_from(&j.staging.join(SERVER_DB))
        .map_err(|_| "restore/swap_failed")
}

/// After the swap: caches, anchors, cleanup of the journal and its directories.
fn finish(
    ctx: &AdminCtx,
    data: &Path,
    j: &Journal,
    verify_heads: &[UserHead],
) -> Result<Value, &'static str> {
    if ctx.sessions.reload().is_err() {
        tracing::error!(event = "sessions_reload_failed");
    }
    ctx.api_keys.invalidate_all();
    ctx.writer.forget_anchored();
    let row = ctx
        .writer
        .record_heads(verify_heads)
        .and_then(|_| {
            ctx.writer.operational(
                KIND_RESTORED,
                &json!({"bundle_manifest_sha256": j.manifest_sha256,
                        "backup_anchor_seq": j.backup_anchor_seq,
                        "previous": j.pre.file_name().map(|n| n.to_string_lossy().into_owned())}),
            )
        })
        .map_err(|_| "anchor/append_failed")?;
    let _ = std::fs::remove_file(data.join(JOURNAL));
    sync_dir(data);
    let _ = std::fs::remove_dir_all(&j.replaced);
    let _ = std::fs::remove_dir_all(&j.staging);
    tracing::info!(event = "restored", users = verify_heads.len());
    Ok(
        json!({"restored": true, "users": verify_heads.len(), "anchor_seq": row.seq,
              "previous": j.pre.display().to_string()}),
    )
}

pub async fn run(ctx: &AdminCtx, dir: &str) -> Result<Value, &'static str> {
    run_inner(ctx, dir, CrashAt::Never).await
}

pub(crate) async fn run_inner(
    ctx: &AdminCtx,
    dir: &str,
    crash: CrashAt,
) -> Result<Value, &'static str> {
    if !ctx.registry.maintenance() {
        return Err("admin/maintenance_required");
    }
    let data = ctx.registry.deps().data_dir.clone();
    let bundle = allowed_dir(&data, ctx.backup_dir.as_deref(), dir)?;
    let manifest = read_manifest(&bundle)?;
    let manifest_sha256 =
        hex::encode(sha256_file(&bundle.join(MANIFEST)).map_err(|_| "restore/manifest_missing")?);
    // A restore after an interrupted one (going back to its pre-restore bundle) cleans that one up.
    let earlier = read_journal(&data);
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
    let backups = data.join("backups");
    let pre = unique_dir(&backups, &format!("pre-restore-{}", stamp(now)));
    let written = {
        let (store, d, p, id) = (
            ctx.store.clone(),
            data.clone(),
            pre.clone(),
            ctx.registry.deps().master.id(),
        );
        tokio::task::spawn_blocking(move || write_bundle(&store, &d, &p, rfc3339(now), id))
            .await
            .unwrap_or(Err("admin/internal"))
    };
    if let Err(code) = written {
        let _ = std::fs::remove_dir_all(&pre);
        let _ = std::fs::remove_dir_all(&staging);
        ctx.registry.resume();
        return Err(code);
    }
    let journal = Journal {
        replaced: unique_dir(&data, &format!("users-replaced-{}", stamp(now))),
        staging: staging.clone(),
        pre,
        manifest_sha256,
        backup_anchor_seq: manifest.anchor_head.seq,
    };
    let outcome = match write_journal(&data, &journal) {
        Err(code) => Err(code),
        Ok(()) => match swap_files(ctx, &data, &journal, crash) {
            Err("restore/interrupted") => return Err("restore/interrupted"),
            Err(code) => {
                // Not a crash: put the live users back and drop the journal.
                let live = data.join(USERS_DIR);
                if journal.replaced.exists() {
                    let _ = std::fs::remove_dir_all(&live);
                    let _ = std::fs::rename(&journal.replaced, &live);
                }
                let _ = std::fs::remove_file(data.join(JOURNAL));
                Err(code)
            }
            Ok(()) => finish(ctx, &data, &journal, &verify_heads),
        },
    };
    if outcome.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    if outcome.is_ok()
        && let Some(e) = earlier
    {
        let _ = std::fs::remove_dir_all(&e.replaced);
        let _ = std::fs::remove_dir_all(&e.staging);
    }
    ctx.registry.resume();
    outcome
}

/// `admin restore --resume`: finishes a swap a crash interrupted. The staged copy was fully
/// verified before the journal was written, so finishing it is safe.
pub async fn resume(ctx: &AdminCtx) -> Result<Value, &'static str> {
    if !ctx.registry.maintenance() {
        return Err("admin/maintenance_required");
    }
    let data = ctx.registry.deps().data_dir.clone();
    let journal = read_journal(&data).ok_or("restore/nothing_to_resume")?;
    if !journal.staging.join(SERVER_DB).is_file() {
        return Err("restore/staging_missing");
    }
    let closed = ctx.registry.quiesce().await;
    if ctx.writer.record_heads(&closed).is_err() {
        tracing::error!(event = "anchor_append_failed", kind = "RUNTIME_CLOSED");
    }
    let outcome = match swap_files(ctx, &data, &journal, CrashAt::Never) {
        Ok(()) => finish(ctx, &data, &journal, &[]),
        Err(code) => Err(code),
    };
    ctx.registry.resume();
    outcome
}
