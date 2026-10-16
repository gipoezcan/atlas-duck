//! Helpers shared by the integration tests that include this module (`mod common;`).

/// Unix: a short base for a test's socket dir, under `/tmp`, removed with the returned dir.
/// `sun_path` holds 104 bytes on macOS (108 on Linux), and a scratch dir under a CI checkout's
/// `target/tmp` (`CARGO_TARGET_TMPDIR`) is longer than that. Production picks its own short dir
/// (`socket_dir`) and refuses one that does not fit; nothing there is relaxed.
#[cfg(unix)]
pub fn short_socket_base() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new().prefix("ad").tempdir_in("/tmp")
}

/// Unix: the endpoint in `<base>/s/` (created with the production checks of `ensure_socket_dir`).
#[cfg(unix)]
pub fn socket_location(
    base: &std::path::Path,
) -> Result<atlas_duck_ipc::paths::EndpointLocation, Box<dyn std::error::Error>> {
    let dir = base.join("s");
    atlas_duck_ipc::paths::ensure_socket_dir(&dir)?;
    Ok(atlas_duck_ipc::paths::EndpointLocation::UnixSocket(
        dir.join("atlas-duck.sock"),
    ))
}
