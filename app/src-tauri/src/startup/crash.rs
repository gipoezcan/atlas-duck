//! Crash-artifact settings (§2.5 "Crash artifacts", "Linux: `prctl(PR_SET_DUMPABLE, 0)`").
//!
//! Applied only to GUI and `--background` launches (§2.5 Scope). The early-argv modes `__cli` and
//! `__verify-export` are dispatched in `main` before [`apply_process_crash_settings`] runs and
//! keep their stdio (§12.1).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use atlas_duck_ipc::paths::LocalDataDir;

/// Executables excluded from Windows Error Reporting (§2.5, verbatim).
pub const WER_EXCLUDED_EXES: [&str; 2] = ["atlas-duck-app.exe", "atlas-duck-sandbox.exe"];

/// `<data>/webview`: the WebView2 user-data folder (§2.5, §12.5).
pub const WEBVIEW_DIR_NAME: &str = "webview";

/// Path of the Crashpad report folder below the WebView2 user-data folder.
/// WebView2 puts its data in an `EBWebView` subfolder of the user-data folder; Crashpad keeps its
/// database in `EBWebView/Crashpad`, with the dumps in `reports`. The layout is checked again
/// against `ICoreWebView2Environment11::FailureReportFolderPath` once M6 creates a webview
/// (§15 V30).
pub const CRASHPAD_REPORTS_SUBPATH: [&str; 3] = ["EBWebView", "Crashpad", "reports"];

/// What [`apply_process_crash_settings`] achieved. `None` means "not applicable on this OS";
/// `Some(false)` means the call failed on the OS where it applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashSettingsReport {
    pub stderr_null: bool,
    pub wer_excluded: Option<bool>,
    pub non_dumpable: Option<bool>,
}

static APPLIED: OnceLock<CrashSettingsReport> = OnceLock::new();

/// Applies the process-wide crash settings in this order: non-dumpable (Linux), WER exclusion
/// (Windows), stderr to the null device. It never fails: each result is recorded in the returned
/// report, which is also kept for [`applied_report`] (the first call wins).
pub fn apply_process_crash_settings() -> CrashSettingsReport {
    #[cfg(target_os = "linux")]
    let non_dumpable = Some(set_non_dumpable().is_ok());
    #[cfg(not(target_os = "linux"))]
    let non_dumpable = None;

    #[cfg(windows)]
    let wer_excluded = Some(exclude_from_wer().is_ok());
    #[cfg(not(windows))]
    let wer_excluded = None;

    let stderr_null = redirect_stderr_to_null().is_ok();

    let report = CrashSettingsReport {
        stderr_null,
        wer_excluded,
        non_dumpable,
    };
    let _ = APPLIED.set(report);
    report
}

/// The report of the first [`apply_process_crash_settings`] call in this process, for later
/// startup code (log line, `APP_START`).
pub fn applied_report() -> Option<&'static CrashSettingsReport> {
    APPLIED.get()
}

/// Points this process's stderr at `/dev/null` (fd 2).
#[cfg(unix)]
pub fn redirect_stderr_to_null() -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let null = std::fs::OpenOptions::new().write(true).open("/dev/null")?;
    // SAFETY: `null` is an open descriptor for the duration of the call; dup2 atomically
    // replaces fd 2 and leaves `null` to be closed on drop.
    let rc = unsafe { libc::dup2(null.as_raw_fd(), libc::STDERR_FILENO) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Points this process's stderr at `NUL`, for both writers on Windows: the CRT descriptor 2
/// (C code) and the Win32 `STD_ERROR_HANDLE` that Rust's `std::io::stderr` looks up on every
/// write.
#[cfg(windows)]
pub fn redirect_stderr_to_null() -> io::Result<()> {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, SetStdHandle};

    // CRT descriptor 2.
    // SAFETY: the path is a NUL-terminated C string literal.
    let crt_fd = unsafe { libc::open(c"NUL".as_ptr(), libc::O_WRONLY) };
    if crt_fd < 0 {
        return Err(io::Error::other("CRT _open(\"NUL\") failed"));
    }
    // SAFETY: `crt_fd` is a valid CRT descriptor; `_dup2` closes whatever descriptor 2 held and
    // makes it a duplicate of `crt_fd`.
    let rc = unsafe { libc::dup2(crt_fd, 2) };
    // SAFETY: `crt_fd` is ours and no longer needed after the duplicate.
    unsafe { libc::close(crt_fd) };
    if rc < 0 {
        return Err(io::Error::other("CRT _dup2 onto descriptor 2 failed"));
    }

    // Win32 standard error handle. The handle is deliberately leaked: it stays the process's
    // stderr until exit.
    let nul = std::fs::OpenOptions::new().write(true).open("NUL")?;
    let handle = nul.into_raw_handle();
    // SAFETY: `handle` is an open file handle owned by nobody else.
    let ok = unsafe { SetStdHandle(STD_ERROR_HANDLE, handle) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `WerAddExcludedApplication(name, FALSE)` (current user, HKCU) for each name in
/// [`WER_EXCLUDED_EXES`]. Tries every name and returns the first error.
#[cfg(windows)]
pub fn exclude_from_wer() -> io::Result<()> {
    use windows_sys::Win32::System::ErrorReporting::WerAddExcludedApplication;

    let mut first_err = None;
    for name in WER_EXCLUDED_EXES {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call.
        let hr = unsafe { WerAddExcludedApplication(wide.as_ptr(), 0) };
        if hr < 0 && first_err.is_none() {
            first_err = Some(io::Error::from_raw_os_error(hr));
        }
    }
    match first_err {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Windows Error Reporting exists only on Windows.
#[cfg(not(windows))]
pub fn exclude_from_wer() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows Error Reporting exists only on Windows",
    ))
}

/// `prctl(PR_SET_DUMPABLE, 0)`, then confirms with `PR_GET_DUMPABLE`. Blocks same-uid ptrace,
/// `process_vm_readv` and `/proc/<pid>/mem`, and suppresses core dumps (§2.5). Precondition for
/// the Linux memory-read probe (§9.4).
#[cfg(target_os = "linux")]
pub fn set_non_dumpable() -> io::Result<()> {
    let zero: libc::c_ulong = 0;
    // SAFETY: PR_SET_DUMPABLE takes one integer argument; the rest are unused.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, zero, zero, zero, zero) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: PR_GET_DUMPABLE takes no arguments and returns the flag.
    let now = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, zero, zero, zero, zero) };
    if now != 0 {
        return Err(io::Error::other(format!(
            "PR_GET_DUMPABLE reports {now} after PR_SET_DUMPABLE 0"
        )));
    }
    Ok(())
}

/// The dumpable flag is Linux-only; macOS relies on the hardened runtime without
/// `get-task-allow` (bundle config), Windows on the default mandatory policy (§2.5).
#[cfg(not(target_os = "linux"))]
pub fn set_non_dumpable() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "PR_SET_DUMPABLE exists only on Linux",
    ))
}

/// `<data>/webview`. Window builders (M6) pass this to `WebviewWindowBuilder::data_directory`;
/// the `WEBVIEW2_USER_DATA_FOLDER` environment variable is never used (§2.5).
pub fn webview_data_dir(data: &LocalDataDir) -> PathBuf {
    data.path().join(WEBVIEW_DIR_NAME)
}

/// `<webview_dir>/EBWebView/Crashpad/reports`.
pub fn crashpad_reports_dir(webview_dir: &Path) -> PathBuf {
    CRASHPAD_REPORTS_SUBPATH
        .iter()
        .fold(webview_dir.to_path_buf(), |p, c| p.join(c))
}

/// Empties `<webview_dir>/EBWebView/Crashpad/reports` and returns the number of entries removed.
/// An absent folder (or one that is not a real directory, such as a symlink) gives `Ok(0)`;
/// nothing is ever created. Every entry is attempted; the first error is returned after the loop.
pub fn clear_crashpad_reports(webview_dir: &Path) -> io::Result<usize> {
    let reports = crashpad_reports_dir(webview_dir);
    match std::fs::symlink_metadata(&reports) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => return Ok(0),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    }

    let mut removed = 0usize;
    let mut first_err = None;
    for entry in std::fs::read_dir(&reports)? {
        let result = entry.and_then(|entry| {
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path).or_else(|err| {
                    // A directory symlink or junction on Windows is removed with remove_dir,
                    // never followed.
                    if cfg!(windows) && file_type.is_symlink() {
                        std::fs::remove_dir(&path)
                    } else {
                        Err(err)
                    }
                })
            }
        });
        match result {
            Ok(()) => removed += 1,
            Err(err) => {
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
    }
    match first_err {
        Some(err) => Err(err),
        None => Ok(removed),
    }
}
