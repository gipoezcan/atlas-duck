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

/// The part of the recorded identity that no longer matches (§3.4 "Binary identity re-check",
/// PD-133): the file parts are M8 Task 10's re-check of the binary on disk; the embedded version
/// is the bridge's check of a spawned worker's ready frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityPart {
    FileId,
    Size,
    Mtime,
    /// The binary is gone, or its metadata cannot be read (a transient error, such as a Windows
    /// sharing violation, also lands here).
    Missing,
    /// The ready frame's `worker_version` differs from the recorded `embedded_version`.
    EmbeddedVersion,
}

/// The binary on disk is no longer the recorded one (§3.4 "Binary identity re-check", PD-133).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct IdentityMismatch {
    /// The first part that differs, checked in the order `Missing`, `FileId`, `Size`, `Mtime`.
    pub what: IdentityPart,
}

impl std::fmt::Display for IdentityMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the sandbox binary no longer matches the probe ({:?})",
            self.what
        )
    }
}

impl std::error::Error for IdentityMismatch {}

/// Re-checks the file identity of `path` against `recorded` (§3.4, PD-133): nothing is spawned
/// from a binary that was replaced, renamed over or removed since the probe.
///
/// A file whose metadata cannot be read (gone, or any `stat` error) is `Missing`: an identity
/// that cannot be confirmed is a mismatch. On Unix an unreadable file still stats, so it fails
/// later as a spawn error instead. The embedded version is not part of this check; the bridge
/// compares it with the spawned worker's ready frame.
pub fn recheck(recorded: &SandboxBinaryIdentity, path: &Path) -> Result<(), IdentityMismatch> {
    let (file_id, size, mtime) = file_identity(path).map_err(|_| IdentityMismatch {
        what: IdentityPart::Missing,
    })?;
    let what = if file_id != recorded.file_id {
        IdentityPart::FileId
    } else if size != recorded.size {
        IdentityPart::Size
    } else if mtime != recorded.mtime {
        IdentityPart::Mtime
    } else {
        return Ok(());
    };
    Err(IdentityMismatch { what })
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A scratch directory next to the test executable (inside the target dir), removed on drop.
    /// Only plain data files are written here; nothing in it is ever executed.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let dir = std::env::current_exe()?
                .parent()
                .ok_or("the test executable has no parent")?
                .join(format!("v21-identity-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir)?;
            Ok(Scratch(dir))
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn recorded(path: &Path) -> Result<SandboxBinaryIdentity, Box<dyn std::error::Error>> {
        let (file_id, size, mtime) = file_identity(path)?;
        Ok(SandboxBinaryIdentity {
            file_id,
            size,
            mtime,
            embedded_version: "v".to_owned(),
        })
    }

    fn what(r: Result<(), IdentityMismatch>) -> Option<IdentityPart> {
        r.err().map(|m| m.what)
    }

    #[test]
    fn recheck_ok_for_untouched_file() -> TestResult {
        let dir = Scratch::new("untouched")?;
        let path = dir.file("worker");
        fs::write(&path, b"worker bytes")?;
        let id = recorded(&path)?;
        assert_eq!(recheck(&id, &path), Ok(()));
        Ok(())
    }

    #[test]
    fn recheck_detects_replaced_file() -> TestResult {
        let dir = Scratch::new("replaced")?;
        let path = dir.file("worker");
        fs::write(&path, b"worker bytes")?;
        let id = recorded(&path)?;
        // Copied over in place: the same file, other bytes (one appended).
        fs::write(&path, b"worker bytes\0")?;
        assert_eq!(what(recheck(&id, &path)), Some(IdentityPart::Size));
        Ok(())
    }

    #[test]
    fn recheck_detects_same_size_rewrite_by_mtime() -> TestResult {
        let dir = Scratch::new("mtime")?;
        let path = dir.file("worker");
        fs::write(&path, b"worker bytes")?;
        let id = recorded(&path)?;
        // Same file, same length: only the modification time can tell.
        let file = fs::OpenOptions::new().write(true).open(&path)?;
        file.set_modified(id.mtime + Duration::from_secs(5))?;
        drop(file);
        assert_eq!(what(recheck(&id, &path)), Some(IdentityPart::Mtime));
        Ok(())
    }

    #[test]
    fn recheck_detects_renamed_replacement() -> TestResult {
        let dir = Scratch::new("renamed")?;
        let path = dir.file("worker");
        let next = dir.file("worker.new");
        fs::write(&path, b"worker bytes")?;
        let id = recorded(&path)?;
        // A real upgrade's shape: a new file renamed over the old one. The new file exists next
        // to the old one first, so it has another inode / file index.
        fs::write(&next, b"worker bytes")?;
        fs::rename(&next, &path)?;
        assert_eq!(what(recheck(&id, &path)), Some(IdentityPart::FileId));
        Ok(())
    }

    #[test]
    fn missing_file_is_mismatch() -> TestResult {
        let dir = Scratch::new("missing")?;
        let path = dir.file("worker");
        fs::write(&path, b"worker bytes")?;
        let id = recorded(&path)?;
        fs::remove_file(&path)?;
        assert_eq!(what(recheck(&id, &path)), Some(IdentityPart::Missing));
        Ok(())
    }
}
