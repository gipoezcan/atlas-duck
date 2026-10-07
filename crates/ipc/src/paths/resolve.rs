//! Shared data-dir resolution (§3.1 "one shared function", §7.7 Path
//! stability and CLI-side data-dir check). Used by the app (startup gate),
//! the CLI (M4) and the wizard (M6). Nothing here creates or writes anything.

use std::io;
use std::path::{Path, PathBuf};

use super::PinnedPaths;
use super::locality::{Locality, NotLocalKind, check_locality, windows_prefix_refusal};

/// `details.reason` for a pinned data dir that does not exist (§4.3 exit 9).
pub const REASON_DATA_DIR_MISSING: &str = "data_dir_missing";
/// `details.reason` for a pinned data dir that is not on a local filesystem.
pub const REASON_DATA_DIR_NOT_LOCAL: &str = "data_dir_not_local";

/// Proof that a data dir existed as a directory on a local filesystem when it
/// was checked. The only way to get one is `check_data_dir`/`resolve_data_dir`.
///
/// ```compile_fail,E0451
/// let _ = atlas_duck_ipc::paths::LocalDataDir { path: std::path::PathBuf::new() };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDataDir {
    path: PathBuf,
}

impl LocalDataDir {
    /// The data dir exactly as it was passed to the check.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Outcome of resolving this host's data dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataDirResolution {
    /// No pinned file for this host: first run (the wizard enforces locality).
    BeforeFirstRun,
    /// The path does not exist or is not a directory: not configured.
    Missing { path: PathBuf },
    /// The path is not on a local filesystem: not configured.
    NotLocal { path: PathBuf, kind: NotLocalKind },
    /// Exists, is a directory, and is local.
    Local(LocalDataDir),
}

impl DataDirResolution {
    /// The §4.3 `details.reason` for the refusal states, `None` otherwise.
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            DataDirResolution::Missing { .. } => Some(REASON_DATA_DIR_MISSING),
            DataDirResolution::NotLocal { .. } => Some(REASON_DATA_DIR_NOT_LOCAL),
            DataDirResolution::BeforeFirstRun | DataDirResolution::Local(_) => None,
        }
    }
}

/// Resolves this host's pinned data dir. `None` (no pinned file) is
/// `BeforeFirstRun`; otherwise the pinned `data_dir` is checked.
pub fn resolve_data_dir(pinned: Option<&PinnedPaths>) -> io::Result<DataDirResolution> {
    match pinned {
        None => Ok(DataDirResolution::BeforeFirstRun),
        Some(p) => check_data_dir(&p.data_dir),
    }
}

/// Existence and local-filesystem check of one data dir. Order:
/// 1. Windows UNC/device prefix -> `NotLocal` with no OS call;
/// 2. missing or not a directory -> `Missing`;
/// 3. OS locality check -> `NotLocal` or `Local`.
///
/// Other I/O errors (e.g. permission denied) are returned as `Err`.
pub fn check_data_dir(path: &Path) -> io::Result<DataDirResolution> {
    if let Some(kind) = windows_prefix_refusal(path) {
        return Ok(DataDirResolution::NotLocal {
            path: path.to_path_buf(),
            kind,
        });
    }
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return Ok(DataDirResolution::Missing {
                path: path.to_path_buf(),
            });
        }
        Err(e) if is_missing(&e) => {
            return Ok(DataDirResolution::Missing {
                path: path.to_path_buf(),
            });
        }
        Err(e) => return Err(e),
    }
    match check_locality(path)? {
        Locality::Local => Ok(DataDirResolution::Local(LocalDataDir {
            path: path.to_path_buf(),
        })),
        Locality::NotLocal(kind) => Ok(DataDirResolution::NotLocal {
            path: path.to_path_buf(),
            kind,
        }),
    }
}

/// "Does not exist" in the §7.7 sense (removed folder, unmounted drive).
fn is_missing(e: &io::Error) -> bool {
    if matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    ) {
        return true;
    }
    is_missing_os_specific(e)
}

/// Windows: ERROR_INVALID_DRIVE (15) and ERROR_NOT_READY (21), e.g. a drive
/// letter that is gone or a card reader without media.
#[cfg(windows)]
fn is_missing_os_specific(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(15) | Some(21))
}

#[cfg(not(windows))]
fn is_missing_os_specific(_e: &io::Error) -> bool {
    false
}
