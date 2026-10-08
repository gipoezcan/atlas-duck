//! Low-space admission (§8.1): before a new agent request is accepted, free space on the DB
//! volume must exceed a threshold. A probe error counts as low space (fail closed).

use std::io;
use std::path::Path;

use crate::error::AuditError;

/// `max(2 GiB, 4 × 24 MiB)` (§8.1); the second term never wins.
pub const DEFAULT_MIN_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub trait FreeSpaceProbe: Send + Sync {
    /// Bytes available to this process on the volume holding `path`.
    fn free_bytes(&self, path: &Path) -> io::Result<u64>;
}

/// The OS probe: `GetDiskFreeSpaceExW` (bytes available to the caller) on Windows,
/// `statvfs` (`f_bavail × f_frsize`) on Unix.
pub struct OsFreeSpace;

impl FreeSpaceProbe for OsFreeSpace {
    #[cfg(windows)]
    fn free_bytes(&self, path: &Path) -> io::Result<u64> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut avail: u64 = 0;
        // SAFETY: `wide` is NUL-terminated and outlives the call; `avail` is a valid
        // out-pointer and the two other out-pointers may be null.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut avail,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(avail)
    }

    #[cfg(unix)]
    #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
    fn free_bytes(&self, path: &Path) -> io::Result<u64> {
        use std::os::unix::ffi::OsStrExt;

        let c = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::other("path contains a NUL byte"))?;
        // SAFETY: an all-zero `statvfs` is a valid value of this plain C struct.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `c` is NUL-terminated and `st` is a valid, writable statvfs for the call.
        let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
    }
}

/// `Ok` only if the probe answers and reports more than `min_free_bytes`.
pub(crate) fn check(
    probe: &dyn FreeSpaceProbe,
    dir: &Path,
    min_free_bytes: u64,
) -> Result<(), AuditError> {
    match probe.free_bytes(dir) {
        Ok(free) if free > min_free_bytes => Ok(()),
        _ => Err(AuditError::StorageLow),
    }
}
