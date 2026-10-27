//! `admin backup --stdout`, `admin backups export <name> --stdout` and `admin restore --stdin`
//! (lead decision after batch 3): a bundle travels as a tar stream over the admin connection, so
//! `kubectl exec deploy/atlas-duck -- /app/atlas-duck-server admin backup --stdout > bundle.tar`
//! and `kubectl exec -i ... admin restore --stdin < bundle.tar` work without `tar` in the image or
//! a debug container. The snapshot, the manifest and every check are those of `backup` and
//! `restore`.
//!
//! Framing (final review I1): one answer line whose data carries `tar_bytes`, exactly that many
//! tar bytes, then a trailer line `{"tar_bytes": n, "sha256": "<hex>"}`. The client checks length
//! and hash and exits non-zero on any mismatch; the server removes a streamed backup from the
//! volume only after the whole stream and its trailer went out.

use std::path::Path;

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::backup::{stamp, unique_dir};
use super::{AdminCtx, Response, tarball, write_line};

/// The default bound of a streamed restore's file data (final review M4); the configuration
/// key `ATLAS_DUCK_MAX_RESTORE_BYTES` changes it.
pub const DEFAULT_MAX_STREAM_BYTES: u64 = crate::config::DEFAULT_MAX_RESTORE_BYTES;

/// Streams the bundle at `bundle`: answer line (with `report` plus `tar_bytes`), tar, trailer.
/// Answers whether everything went out.
async fn stream_bundle<W: AsyncWrite + Unpin>(
    w: &mut W,
    bundle: &Path,
    mut report: Value,
) -> std::io::Result<bool> {
    let name = bundle
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let size = match tarball::tar_size(bundle) {
        Ok(n) => n,
        Err(_) => {
            write_line(w, &Response::err("backup/stream_failed")).await?;
            return Ok(false);
        }
    };
    report["tar_bytes"] = json!(size);
    write_line(w, &Response::ok(report)).await?;
    let (n, sha) = tarball::write_dir(w, bundle, &name).await?;
    let trailer = json!({"tar_bytes": n, "sha256": hex::encode(sha)});
    let mut line = serde_json::to_vec(&trailer).map_err(std::io::Error::other)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    w.flush().await?;
    Ok(n == size)
}

/// `backup --stdout`: a backup into `<data>/backups`, streamed, removed only after a complete
/// stream (else kept and logged, so the snapshot anchored as `BACKUP_TAKEN` still exists).
pub async fn backup_out<W: AsyncWrite + Unpin>(ctx: &AdminCtx, w: &mut W) -> std::io::Result<()> {
    let data = ctx.registry.deps().data_dir.clone();
    let target = data.join("backups");
    let report = match super::backup::run(ctx, &target.display().to_string()).await {
        Ok(r) => r,
        Err(code) => {
            write_line(w, &Response::err(code)).await?;
            return w.shutdown().await;
        }
    };
    let bundle = std::path::PathBuf::from(report["bundle"].as_str().unwrap_or_default());
    let complete = stream_bundle(w, &bundle, report).await;
    if matches!(complete, Ok(true)) {
        let _ = std::fs::remove_dir_all(&bundle);
        tracing::info!(event = "backup_streamed", ok = true);
    } else {
        tracing::error!(event = "backup_streamed", ok = false, kept = %bundle.display());
    }
    complete?;
    w.shutdown().await
}

/// `backups export <name> --stdout`: an existing bundle in `<data>/backups`, streamed, kept.
pub async fn export_out<W: AsyncWrite + Unpin>(
    ctx: &AdminCtx,
    name: &str,
    w: &mut W,
) -> std::io::Result<()> {
    match super::backups::complete_bundle(ctx, name) {
        Err(code) => write_line(w, &Response::err(code)).await?,
        Ok(bundle) => {
            let ok = stream_bundle(w, &bundle, json!({"bundle": name})).await?;
            tracing::info!(event = "backup_exported", ok);
        }
    }
    w.shutdown().await
}

/// Reads a streamed bundle into `<data>/backups/upload-<stamp>/`, restores it, removes the upload.
pub async fn restore_in<R: AsyncRead + Unpin>(ctx: &AdminCtx, r: &mut R) -> Response {
    if !ctx.registry.maintenance() {
        return Response::err("admin/maintenance_required");
    }
    let data = ctx.registry.deps().data_dir.clone();
    let backups = data.join("backups");
    if std::fs::create_dir_all(&backups).is_err() {
        return Response::err("restore/stage_failed");
    }
    let upload = unique_dir(&backups, &format!("upload-{}", stamp(ctx.clock.now())));
    let out = match tarball::read_into(r, &upload, ctx.max_stream_bytes).await {
        Err(code) => Response::err(code),
        Ok(bundle) => match super::restore::run(ctx, &bundle.display().to_string()).await {
            Ok(v) => Response::ok(v),
            Err(code) => Response::err(code),
        },
    };
    let _ = std::fs::remove_dir_all(&upload);
    out
}
