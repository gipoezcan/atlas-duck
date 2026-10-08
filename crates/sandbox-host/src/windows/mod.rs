//! Windows worker spawn routine (section 3.4 Spawning, section 9.4 Windows).
//!
//! The worker runs in an AppContainer with zero capabilities (Less-Privileged
//! AppContainer when every file has the `S-1-15-2-2` ACE), inside a job object
//! (`ACTIVE_PROCESS = 1`, `KILL_ON_JOB_CLOSE`, `DIE_ON_UNHANDLED_EXCEPTION`,
//! process memory limit, `UILIMIT_ALL`), with exactly three inherited handles
//! (its stdio pipes). There is no fallback to a lockdown token here: if the
//! AppContainer cannot be used the spawn fails and the floor is not met (the
//! degraded path is M8).

mod aces;
mod appcontainer;
mod job;
mod pipes;
mod spawner;

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;

pub use aces::{
    AceEnsure, AceStatus, WORKER_EXE_NAME, check_aces, dacl_bytes, ensure_aces, grant_aces,
    pe_import_names, worker_ace_files, worker_ace_files_for_exe,
};
pub use appcontainer::delete_appcontainer_profile;
pub use job::{JobLimits, JobSnapshot};
pub use spawner::{WindowsProcess, WindowsSpawner};

/// AppContainer profile name (plan decision; the spec names none). The profile
/// is per Windows user. The app never deletes it in M1 (uninstall is M10);
/// [`delete_appcontainer_profile`] exists for the T19 tests' clean-up and for
/// M10.
pub const APPCONTAINER_NAME: &str = "atlas-duck.sandbox";
/// `ALL APPLICATION PACKAGES` (section 9.4).
pub const SID_ALL_APP_PACKAGES: &str = "S-1-15-2-1";
/// `ALL RESTRICTED APPLICATION PACKAGES` (section 9.4).
pub const SID_ALL_RESTRICTED_APP_PACKAGES: &str = "S-1-15-2-2";
/// The environment variables the host chooses to give the worker (section
/// 3.4): the Windows directory and the fixed time zone.
pub const WORKER_ENV_NAMES: [&str; 2] = ["SystemRoot", "TZ"];
/// The one more variable the host has to pass: `CreateProcessW` with an
/// AppContainer fails with `ERROR_ENVVAR_NOT_FOUND` (203) without it, and
/// derives the container's own `LOCALAPPDATA`, `TEMP` and `TMP` from it. A
/// section 15 V09 finding: section 3.4's "only `SystemRoot` and `TZ`" cannot be
/// met on Windows.
pub const WORKER_ENV_OS_REQUIRED: &str = "LOCALAPPDATA";
/// Every variable name the worker actually sees, sorted: the three above plus
/// the `TEMP` and `TMP` that process creation adds (all values point into the
/// container's own folder; nothing comes from the session).
pub const WORKER_ENV_OBSERVED: [&str; 5] = ["LOCALAPPDATA", "SystemRoot", "TEMP", "TMP", "TZ"];

/// UTF-16, NUL-terminated.
pub(crate) fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Reads a NUL-terminated UTF-16 string from `p`.
///
/// # Safety
/// `p` must point to a valid NUL-terminated UTF-16 string.
pub(crate) unsafe fn from_wide_ptr(p: *const u16) -> String {
    let mut len = 0usize;
    // SAFETY: the caller guarantees NUL termination, so every read up to and
    // including the terminator is in bounds.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` elements were just read from `p`.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

/// An `io::Error` for a failed `HRESULT`. `HRESULT_FROM_WIN32` values (facility
/// 7, for example `0x80070005` for `ERROR_ACCESS_DENIED`) keep the Win32 code
/// as their raw OS error, so callers and tests can match on `5`; other
/// `HRESULT`s keep their full value.
pub(crate) fn hresult_error(hr: i32) -> io::Error {
    let bits = hr as u32;
    if bits & 0xFFFF_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((bits & 0xFFFF) as i32)
    } else {
        io::Error::from_raw_os_error(hr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win32_hresults_keep_the_win32_code() {
        assert_eq!(
            hresult_error(0x8007_0005_u32 as i32).raw_os_error(),
            Some(5)
        );
        assert_eq!(
            hresult_error(0x8000_4005_u32 as i32).raw_os_error(),
            Some(0x8000_4005_u32 as i32)
        );
    }
}
