//! `admin backup <dir>` (SM-6.1, SM-6.2, SM-8.1, M13 T6): a consistent snapshot of every store.
//!
//! The registry is quiesced (every runtime closed and its final head anchored, no runtime opens),
//! `server.db` is copied with SQLite's online backup API, every user store database the same way
//! (WAL included) and every other user file as is; then the runtimes may open again. The bundle
//! `atlas-duck-server-backup-<stamp>/` holds `server.db`, `users/<user_id>/…` and, written last,
//! `manifest.json` (per-file SHA-256, the anchor-chain head and every user's anchored head, the id
//! of the master key that wraps the data keys). The master key itself is never in a bundle: a
//! backup is useless without it (ADR 0002). `BACKUP_TAKEN` with the manifest's SHA-256 goes into
//! the anchor chain after the bundle is complete.
//!
//! Targets: under `<data>/backups` (same volume; copy it off-cluster) or the temp directory.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::AdminCtx;
use crate::anchor::KIND_BACKUP_TAKEN;
use crate::clock::rfc3339;
use crate::store::ServerStore;
use crate::store::schema::SCHEMA_VERSION;

pub const BUNDLE_PREFIX: &str = "atlas-duck-server-backup-";
pub const MANIFEST: &str = "manifest.json";
pub const SERVER_DB: &str = "server.db";
pub const USERS_DIR: &str = "users";
pub const FORMAT: &str = "atlas-duck-server-backup/v1";
/// A manifest larger than this was not written by a backup.
pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// Files of a user directory never copied: the lock and SQLite's side files (the database copy
/// already holds the WAL's content).
fn skipped(name: &str) -> bool {
    name == "instance.lock" || name.ends_with("-wal") || name.ends_with("-shm")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadRef {
    pub seq: u64,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserHeadRef {
    pub user_id: String,
    pub chain_id: String,
    pub head_seq: u64,
    pub head_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRef {
    /// Relative, `/`-separated.
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub created_at: String,
    pub app_version: String,
    pub schema_version: u32,
    /// The master key the bundle's data keys are wrapped with (an id, never key material).
    pub master_key_id: String,
    pub anchor_head: HeadRef,
    pub users: Vec<UserHeadRef>,
    pub files: Vec<FileRef>,
}

/// What a backup wrote; `written` is in write order (the manifest last).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackupReport {
    pub bundle: String,
    pub users: usize,
    pub files: usize,
    pub manifest_sha256: String,
    pub anchor_seq: u64,
    pub written: Vec<String>,
}

pub fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

/// `2026-10-27T09:00:00.000Z` → `20261027T090000Z`.
pub fn stamp(now: i64) -> String {
    rfc3339(now)
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .replacen("000Z", "Z", 1)
}

/// `base/name`, or `base/name-2`, `-3`, … when taken.
pub fn unique_dir(base: &Path, name: &str) -> PathBuf {
    let first = base.join(name);
    if !first.exists() {
        return first;
    }
    (2..)
        .map(|n| base.join(format!("{name}-{n}")))
        .find(|p| !p.exists())
        .unwrap_or(first)
}

/// The roots a backup may be written to or restored from.
pub fn allowed_roots(data: &Path) -> Vec<PathBuf> {
    let mut roots = vec![data.join("backups"), std::env::temp_dir()];
    roots.retain(|r| r.exists() || r.ends_with("backups"));
    roots
}

/// `dir` canonicalized when it lies under an allowed root (`<data>/backups` is created on first
/// use); else `backup/target_not_allowed`.
pub fn allowed_dir(data: &Path, dir: &str) -> Result<PathBuf, &'static str> {
    let wanted = PathBuf::from(dir);
    let backups = data.join("backups");
    if wanted == backups && !wanted.exists() {
        std::fs::create_dir_all(&backups).map_err(|_| "backup/target_unusable")?;
    }
    let real = wanted
        .canonicalize()
        .map_err(|_| "backup/target_not_allowed")?;
    let under = |p: &Path| p.canonicalize().is_ok_and(|root| real.starts_with(root));
    // Inside the data volume only `<data>/backups`: never the live stores themselves.
    let in_live_data = under(data) && !under(&backups);
    let ok = !in_live_data && real.is_dir() && allowed_roots(data).iter().any(|r| under(r));
    if ok {
        Ok(real)
    } else {
        Err("backup/target_not_allowed")
    }
}

/// A manifest path: relative, plain components only.
pub fn safe_rel(rel: &str) -> Option<PathBuf> {
    let p = Path::new(rel);
    let ok = !rel.is_empty()
        && !rel.contains('\\')
        && p.components().all(|c| matches!(c, Component::Normal(_)));
    ok.then(|| p.to_path_buf())
}

fn rel_string(rel: &Path) -> String {
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Copies one user directory: SQLite databases through the online backup API, other files as
/// they are. Answers the relative paths written.
fn copy_user_dir(src: &Path, dst: &Path, rel: &Path, out: &mut Vec<String>) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    let mut entries: Vec<_> = std::fs::read_dir(src)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        let ty = e.file_type()?;
        if ty.is_dir() {
            copy_user_dir(&e.path(), &dst.join(&name), &rel.join(&name), out)?;
        } else if ty.is_file() && !skipped(&name) {
            if name.ends_with(".db") {
                let c = rusqlite::Connection::open_with_flags(
                    e.path(),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )
                .map_err(std::io::Error::other)?;
                c.backup(rusqlite::MAIN_DB, dst.join(&name), None)
                    .map_err(std::io::Error::other)?;
            } else {
                std::fs::copy(e.path(), dst.join(&name))?;
            }
            out.push(rel_string(&rel.join(&name)));
        }
    }
    Ok(())
}

/// The anchor-chain head and every user's latest anchored head, read from the snapshot itself.
fn snapshot_heads(db: &Path) -> rusqlite::Result<(HeadRef, Vec<UserHeadRef>)> {
    let c = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let (seq, hash): (i64, Vec<u8>) = c
        .query_row(
            "SELECT seq, hash FROM anchor_chain ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap_or((0, vec![0; 32]));
    let mut st = c.prepare(
        "SELECT user_id, chain_id, head_seq, record_hash FROM anchor_heads
         WHERE rowid IN (SELECT MAX(rowid) FROM anchor_heads GROUP BY user_id) ORDER BY user_id",
    )?;
    let users = st
        .query_map([], |r| {
            Ok(UserHeadRef {
                user_id: r.get(0)?,
                chain_id: r.get(1)?,
                head_seq: u64::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                head_hash: hex::encode(r.get::<_, Vec<u8>>(3)?),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok((
        HeadRef {
            seq: u64::try_from(seq).unwrap_or(0),
            hash: hex::encode(hash),
        },
        users,
    ))
}

/// Everything after the quiesce: the files, then the manifest. Blocking.
fn write_bundle(
    store: &Arc<dyn ServerStore>,
    data: &Path,
    bundle: &Path,
    created_at: String,
    master_key_id: String,
) -> Result<(Manifest, Vec<String>), &'static str> {
    let io = |_| "backup/write_failed";
    std::fs::create_dir_all(bundle).map_err(io)?;
    let mut written = Vec::new();
    store
        .snapshot_to(&bundle.join(SERVER_DB))
        .map_err(|_| "backup/write_failed")?;
    written.push(SERVER_DB.to_owned());
    let users = store.users_all().map_err(|_| "store/unavailable")?;
    for (u, _) in &users {
        let src = crate::users::user_dir(data, &u.user_id);
        if src.is_dir() {
            let rel = Path::new(USERS_DIR).join(&u.user_id);
            copy_user_dir(&src, &bundle.join(&rel), &rel, &mut written).map_err(io)?;
        }
    }
    let mut files = Vec::new();
    for rel in &written {
        let p = bundle.join(rel);
        files.push(FileRef {
            path: rel.clone(),
            size: std::fs::metadata(&p).map_err(io)?.len(),
            sha256: hex::encode(sha256_file(&p).map_err(io)?),
        });
    }
    let (anchor_head, user_heads) =
        snapshot_heads(&bundle.join(SERVER_DB)).map_err(|_| "backup/write_failed")?;
    let manifest = Manifest {
        format: FORMAT.to_owned(),
        created_at,
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
        schema_version: SCHEMA_VERSION,
        master_key_id,
        anchor_head,
        users: user_heads,
        files,
    };
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|_| "admin/internal")?;
    // Written last: a bundle without a manifest is incomplete and never restored.
    let mut f = std::fs::File::create_new(bundle.join(MANIFEST)).map_err(io)?;
    std::io::Write::write_all(&mut f, &bytes).map_err(io)?;
    f.sync_all().map_err(io)?;
    written.push(MANIFEST.to_owned());
    Ok((manifest, written))
}

pub async fn run(ctx: &AdminCtx, dir: &str) -> Result<Value, &'static str> {
    let deps = ctx.registry.deps();
    let data = deps.data_dir.clone();
    let target = allowed_dir(&data, dir)?;
    let now = ctx.clock.now();
    let bundle = unique_dir(&target, &format!("{BUNDLE_PREFIX}{}", stamp(now)));
    let master_key_id = deps.master.id().to_owned();

    let heads = ctx.registry.quiesce().await;
    let anchored = ctx.writer.record_heads(&heads);
    let result = match anchored {
        Err(_) => Err("anchor/append_failed"),
        Ok(_) => {
            let store = ctx.store.clone();
            let (d, b) = (data.clone(), bundle.clone());
            tokio::task::spawn_blocking(move || {
                write_bundle(&store, &d, &b, rfc3339(now), master_key_id)
            })
            .await
            .unwrap_or(Err("admin/internal"))
        }
    };
    ctx.registry.resume();
    let (manifest, written) = match result {
        Ok(r) => r,
        Err(code) => {
            // A partial bundle has no manifest; remove it so nobody mistakes it for a backup.
            let _ = std::fs::remove_dir_all(&bundle);
            return Err(code);
        }
    };
    let manifest_sha256 =
        hex::encode(sha256_file(&bundle.join(MANIFEST)).map_err(|_| "backup/write_failed")?);
    let name = bundle
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let row = ctx
        .writer
        .operational(
            KIND_BACKUP_TAKEN,
            &json!({"bundle": name, "manifest_sha256": manifest_sha256,
                    "anchor_seq": manifest.anchor_head.seq}),
        )
        .map_err(|_| "anchor/append_failed")?;
    tracing::info!(
        event = "backup_taken",
        files = written.len(),
        users = manifest.users.len()
    );
    serde_json::to_value(BackupReport {
        bundle: bundle.display().to_string(),
        users: manifest.users.len(),
        files: manifest.files.len(),
        manifest_sha256,
        anchor_seq: row.seq,
        written,
    })
    .map_err(|_| "admin/internal")
}
