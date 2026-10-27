//! `admin backup --stdout` and `admin restore --stdin` (lead decision after batch 3): the bundle
//! travels as a tar stream over the admin connection, so
//! `kubectl exec deploy/atlas-duck -- /app/atlas-duck-server admin backup --stdout > bundle.tar`
//! and `... admin restore --stdin < bundle.tar` work without `tar` in the image or a debug
//! container. The snapshot, the manifest and every check are those of `backup` and `restore`;
//! the bundle exists on the volume only while it streams.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::backup::{stamp, unique_dir};
use super::{AdminCtx, Response, tarball, write_line};

/// The most file data a streamed restore accepts.
pub const MAX_STREAM_BYTES: u64 = 256 * 1024 * 1024 * 1024;

/// Takes a backup into `<data>/backups`, answers its report line, streams it, then removes it.
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
    let name = bundle
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    write_line(w, &Response::ok(report)).await?;
    let streamed = tarball::write_dir(w, &bundle, &name).await;
    let _ = std::fs::remove_dir_all(&bundle);
    tracing::info!(event = "backup_streamed", ok = streamed.is_ok());
    streamed?;
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
    let out = match tarball::read_into(r, &upload, MAX_STREAM_BYTES).await {
        Err(code) => Response::err(code),
        Ok(bundle) => match super::restore::run(ctx, &bundle.display().to_string()).await {
            Ok(v) => Response::ok(v),
            Err(code) => Response::err(code),
        },
    };
    let _ = std::fs::remove_dir_all(&upload);
    out
}
