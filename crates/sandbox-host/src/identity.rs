//! Sandbox binary identity (§3.4): file identity (device/inode or file index,
//! size, mtime) plus the version the worker binary reports about itself.
//!
//! The probe records it (§9.4); M8 re-checks it at submit and before every
//! spawn and refuses runs with `sandbox_unavailable` / `app_upgraded` on a
//! mismatch.

use std::io;
use std::path::Path;
use std::time::SystemTime;

use serde::Serialize;

/// OS file identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileId {
    /// Unix: `st_dev` / `st_ino`.
    DevIno { dev: u64, ino: u64 },
    /// Windows: volume serial number and 64-bit file index from
    /// `GetFileInformationByHandle`.
    FileIndex { volume_serial: u32, index: u64 },
}

/// Recorded identity of the sandbox worker binary (§3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SandboxBinaryIdentity {
    pub file_id: FileId,
    pub size: u64,
    pub mtime: SystemTime,
    /// `ProbeReady.worker_version` (the worker's compiled-in `BUILD_ID`).
    pub embedded_version: String,
}

/// Returns `(file id, size, mtime)` of `path`, following symlinks.
#[cfg(unix)]
pub fn file_identity(path: &Path) -> io::Result<(FileId, u64, SystemTime)> {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::metadata(path)?;
    let id = FileId::DevIno {
        dev: meta.dev(),
        ino: meta.ino(),
    };
    Ok((id, meta.len(), meta.modified()?))
}

/// Returns `(file id, size, mtime)` of `path`, following symlinks.
///
/// `std::os::windows::fs::MetadataExt::{volume_serial_number, file_index}`
/// are unstable (`windows_by_handle`), so the file index comes from
/// `GetFileInformationByHandle` on an opened handle.
#[cfg(windows)]
pub fn file_identity(path: &Path) -> io::Result<(FileId, u64, SystemTime)> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is a valid value (plain
    // integers and FILETIME structs).
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `file` is an open handle for the duration of the call and `info`
    // is a valid, writable out-pointer.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let id = FileId::FileIndex {
        volume_serial: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    };
    Ok((id, meta.len(), meta.modified()?))
}
