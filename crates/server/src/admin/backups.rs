//! `admin backups list|remove <name>|export <name> --stdout` (final review I3): bundles kept on
//! the volume (`admin backup <dir>`, the pre-restore bundles, leftovers of interrupted uploads)
//! can be seen, copied off the cluster and removed without a shell. Removals are recorded in the
//! anchor chain (`BACKUP_REMOVED`). Old bundles still hold the chains retention deleted later
//! (SM-6.5): `list` says how old each one is, and the runbook makes pruning an operator duty.

use std::path::PathBuf;

use serde::Serialize;
use serde_json::{Value, json};

use super::AdminCtx;
use super::backup::{MANIFEST, Manifest};
use crate::anchor::KIND_BACKUP_REMOVED;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleView {
    pub name: String,
    /// A manifest exists: the bundle is complete and restorable.
    pub complete: bool,
    pub created_at: Option<String>,
    pub bytes: u64,
}

fn backups_dir(ctx: &AdminCtx) -> PathBuf {
    ctx.registry.deps().data_dir.join("backups")
}

/// A bundle name: one plain path component inside `<data>/backups`.
fn bundle_path(ctx: &AdminCtx, name: &str) -> Result<PathBuf, &'static str> {
    let plain = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', ':'])
        && !name.starts_with('.');
    if !plain {
        return Err("backups/name_invalid");
    }
    let p = backups_dir(ctx).join(name);
    if p.is_dir() {
        Ok(p)
    } else {
        Err("backups/unknown")
    }
}

fn dir_bytes(p: &std::path::Path) -> u64 {
    std::fs::read_dir(p)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| match e.file_type() {
                    Ok(t) if t.is_dir() => dir_bytes(&e.path()),
                    _ => e.metadata().map(|m| m.len()).unwrap_or(0),
                })
                .sum()
        })
        .unwrap_or(0)
}

pub fn list(ctx: &AdminCtx) -> Result<Value, &'static str> {
    let dir = backups_dir(ctx);
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.filter_map(Result::ok) {
            if !e.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let p = e.path();
            let manifest: Option<Manifest> = std::fs::read(p.join(MANIFEST))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok());
            out.push(BundleView {
                name: e.file_name().to_string_lossy().into_owned(),
                complete: manifest.is_some(),
                created_at: manifest.map(|m| m.created_at),
                bytes: dir_bytes(&p),
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    serde_json::to_value(out).map_err(|_| "admin/internal")
}

pub fn remove(ctx: &AdminCtx, name: &str) -> Result<Value, &'static str> {
    let p = bundle_path(ctx, name)?;
    std::fs::remove_dir_all(&p).map_err(|_| "backups/remove_failed")?;
    ctx.writer
        .operational(KIND_BACKUP_REMOVED, &json!({"bundle": name}))
        .map_err(|_| "anchor/append_failed")?;
    tracing::info!(event = "backup_removed", bundle = name);
    Ok(json!({"removed": name}))
}

/// A complete (manifest-bearing) bundle by name, for `export`.
pub fn complete_bundle(ctx: &AdminCtx, name: &str) -> Result<PathBuf, &'static str> {
    let p = bundle_path(ctx, name)?;
    if p.join(MANIFEST).is_file() {
        Ok(p)
    } else {
        Err("backups/incomplete")
    }
}
