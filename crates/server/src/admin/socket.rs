//! The admin socket (M13 PD-M13-1): a Unix socket at `ATLAS_DUCK_ADMIN_SOCKET` (the chart's
//! in-memory emptyDir `/run/atlas-duck`), mode 0600, and every peer's UID (`SO_PEERCRED`) must be
//! the server's own, i.e. the socket file's owner. `kubectl exec` into the pod runs as that UID.

use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use tokio::net::UnixListener;

use super::{AdminCtx, serve_conn};

/// Binds the socket at `path` (a stale socket file is replaced; any other file is an error), sets
/// mode 0600 and answers the listener with the UID allowed to connect (the file's owner).
pub fn bind(path: &Path) -> io::Result<(UnixListener, u32)> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "admin socket path is not a socket",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        // Batch-1 review M-2: no window with umask permissions. The directory is closed to
        // everyone else first (best effort: an emptyDir may belong to root), then the socket
        // itself is narrowed to 0600.
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let owner = std::fs::metadata(path)?.uid();
    Ok((listener, owner))
}

/// Accepts connections until the task is aborted; a peer with another UID is closed unanswered.
pub async fn serve(listener: UnixListener, allowed_uid: u32, ctx: Arc<AdminCtx>) {
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(_) => {
                tracing::warn!(event = "admin_accept_failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        match stream.peer_cred() {
            Ok(c) if c.uid() == allowed_uid => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if serve_conn(&ctx, stream).await.is_err() {
                        tracing::warn!(event = "admin_connection_failed");
                    }
                });
            }
            Ok(c) => tracing::warn!(event = "admin_peer_refused", uid = c.uid()),
            Err(_) => tracing::warn!(event = "admin_peer_refused"),
        }
    }
}
