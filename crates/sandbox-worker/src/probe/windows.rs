//! Windows probe attempts (§9.4): `OpenProcess(PROCESS_VM_READ)` on the app,
//! `CredReadW`, `OpenClipboard`, a child process, and the handle sentinel.
//! The Win32 error-code tables are plain constants and compile on every OS, so
//! the Windows classification is unit-tested on Linux and macOS as well. Only
//! the Win32 calls are `cfg(windows)`.

use atlas_duck_ipc::sandbox::probe::ProbeOutcome;

/// `ERROR_ACCESS_DENIED`: file open, `OpenProcess`, `OpenClipboard` and
/// `CredReadW` in an AppContainer.
pub const ERROR_ACCESS_DENIED: i64 = 5;
/// `ERROR_INVALID_HANDLE`: the handle value is not in this process's table.
pub const ERROR_INVALID_HANDLE: i64 = 6;
/// `ERROR_NOT_FOUND`: `CredReadW` for a credential that does not exist. It is
/// returned after the access check, so it means the call was allowed.
pub const ERROR_NOT_FOUND: i64 = 1168;
/// `ERROR_NOT_ENOUGH_QUOTA`: `CreateProcess` inside a job with
/// `ActiveProcessLimit = 1` (measured on Windows 11 in the Task 14 experiment).
pub const ERROR_NOT_ENOUGH_QUOTA: i64 = 1816;
/// `WSAEACCES`: `connect` without the network capabilities.
pub const WSAEACCES: i64 = 10013;
/// `WSAEHOSTUNREACH`, a stack error.
pub const WSAEHOSTUNREACH: i64 = 10065;
/// Winsock errors that come from the network stack itself: the connect got
/// past the sandbox. `WSAEWOULDBLOCK` and `WSAEINPROGRESS` are the Windows
/// spellings of `EINPROGRESS`.
pub const CONNECT_REACHED: [i64; 7] = [
    10035, // WSAEWOULDBLOCK
    10036, // WSAEINPROGRESS
    10051, // WSAENETUNREACH
    10053, // WSAECONNABORTED
    10054, // WSAECONNRESET
    10060, // WSAETIMEDOUT
    10061, // WSAECONNREFUSED
];

/// `ERROR_ACCESS_DENIED` or `WSAEACCES`: the explicit denials.
pub fn is_denial(code: i64) -> bool {
    code == ERROR_ACCESS_DENIED || code == WSAEACCES
}

/// Scores a failed `connect`: a denial is `Blocked`; a stack error is `Allowed`;
/// anything else is `Error`.
pub fn classify_connect(code: i64) -> ProbeOutcome {
    if is_denial(code) {
        ProbeOutcome::Blocked
    } else if code == WSAEHOSTUNREACH || CONNECT_REACHED.contains(&code) {
        ProbeOutcome::Allowed
    } else {
        ProbeOutcome::Error
    }
}

/// Scores a failed `CreateProcess`: access denied (AppContainer) or the job's
/// active-process quota is `Blocked`; anything else is `Error`.
pub fn classify_spawn(code: i64) -> ProbeOutcome {
    if code == ERROR_ACCESS_DENIED || code == ERROR_NOT_ENOUGH_QUOTA {
        ProbeOutcome::Blocked
    } else {
        ProbeOutcome::Error
    }
}

/// Scores `OpenProcess(PROCESS_VM_READ)`: access denied is `Blocked`; every
/// other failure (for example `ERROR_INVALID_PARAMETER`, no such process) is
/// `Error`.
pub fn classify_open_process(code: i64) -> ProbeOutcome {
    if code == ERROR_ACCESS_DENIED {
        ProbeOutcome::Blocked
    } else {
        ProbeOutcome::Error
    }
}

/// Scores a failed `CredReadW`: access denied is `Blocked`, `ERROR_NOT_FOUND`
/// (the credential store was consulted) is `Allowed`, anything else is `Error`.
pub fn classify_cred_read(code: i64) -> ProbeOutcome {
    match code {
        ERROR_ACCESS_DENIED => ProbeOutcome::Blocked,
        ERROR_NOT_FOUND => ProbeOutcome::Allowed,
        _ => ProbeOutcome::Error,
    }
}

/// Scores a failed `OpenClipboard`: access denied is `Blocked`, anything else
/// is `Error`.
pub fn classify_open_clipboard(code: i64) -> ProbeOutcome {
    if code == ERROR_ACCESS_DENIED {
        ProbeOutcome::Blocked
    } else {
        ProbeOutcome::Error
    }
}

/// Scores a failed `GetHandleInformation` on the sentinel value:
/// `ERROR_INVALID_HANDLE` means the value is not in the worker's handle table
/// (`Blocked`); anything else is `Error`. A success is `Allowed` (the worker
/// holds a handle it must not hold) and never reaches this function.
pub fn classify_handle_sentinel(code: i64) -> ProbeOutcome {
    if code == ERROR_INVALID_HANDLE {
        ProbeOutcome::Blocked
    } else {
        ProbeOutcome::Error
    }
}

#[cfg(windows)]
mod calls {
    use std::path::PathBuf;
    use std::process::Command;

    use atlas_duck_ipc::sandbox::probe::{ProbeId, ProbeOutcome, ProbeResultMsg};
    use windows_sys::Win32::Foundation::{CloseHandle, GetHandleInformation, GetLastError};
    use windows_sys::Win32::Security::Credentials::{
        CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
    };
    use windows_sys::Win32::System::DataExchange::{CloseClipboard, OpenClipboard};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

    use super::{
        classify_cred_read, classify_handle_sentinel, classify_open_clipboard,
        classify_open_process, classify_spawn,
    };
    use crate::probe::{os_code, result};

    fn last_error() -> i64 {
        // SAFETY: `GetLastError` has no preconditions.
        i64::from(unsafe { GetLastError() })
    }

    /// `OpenProcessVmRead`: `OpenProcess(PROCESS_VM_READ, FALSE, app_pid)`.
    pub fn open_process_vm_read(app_pid: u32) -> ProbeResultMsg {
        let probe = ProbeId::OpenProcessVmRead;
        // SAFETY: plain value arguments; a null return is a failure.
        let handle = unsafe { OpenProcess(PROCESS_VM_READ, 0, app_pid) };
        if handle.is_null() {
            let code = last_error();
            let outcome = classify_open_process(code);
            let detail = match outcome {
                ProbeOutcome::Blocked => "OpenProcess(PROCESS_VM_READ) refused",
                _ => "OpenProcess(PROCESS_VM_READ) failed unexpectedly",
            };
            return result(probe, outcome, Some(code), detail);
        }
        // SAFETY: `handle` is the valid handle returned above.
        unsafe {
            CloseHandle(handle);
        }
        result(
            probe,
            ProbeOutcome::Allowed,
            None,
            "OpenProcess(PROCESS_VM_READ) succeeded",
        )
    }

    /// `CredRead`: `CredReadW` of a generic credential that does not exist. The
    /// target name is fixed and holds no secret.
    pub fn cred_read() -> ProbeResultMsg {
        let probe = ProbeId::CredRead;
        let target: Vec<u16> = "atlas-duck.sandbox-probe.nonexistent\0"
            .encode_utf16()
            .collect();
        let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `target` is NUL-terminated; `cred` is a valid out pointer.
        let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) };
        if ok != 0 {
            // SAFETY: `cred` was allocated by the successful `CredReadW`.
            unsafe { CredFree(cred.cast()) };
            return result(
                probe,
                ProbeOutcome::Allowed,
                None,
                "CredReadW returned a credential",
            );
        }
        let code = last_error();
        let outcome = classify_cred_read(code);
        let detail = match outcome {
            ProbeOutcome::Blocked => "CredReadW refused",
            ProbeOutcome::Allowed => "CredReadW reached the credential store",
            ProbeOutcome::Error => "CredReadW failed unexpectedly",
        };
        result(probe, outcome, Some(code), detail)
    }

    /// `OpenClipboard`: `OpenClipboard(NULL)`. Another process may hold the
    /// clipboard for a moment, and then the call also fails with
    /// `ERROR_ACCESS_DENIED`, so a failure is retried a few times before it is
    /// scored. An AppContainer is refused every time.
    pub fn open_clipboard() -> ProbeResultMsg {
        let probe = ProbeId::OpenClipboard;
        let mut code = 0;
        for _ in 0..5 {
            // SAFETY: a null owner window is allowed.
            if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
                // SAFETY: this thread opened the clipboard just above.
                unsafe {
                    CloseClipboard();
                }
                return result(
                    probe,
                    ProbeOutcome::Allowed,
                    None,
                    "OpenClipboard succeeded",
                );
            }
            code = last_error();
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let outcome = classify_open_clipboard(code);
        let detail = match outcome {
            ProbeOutcome::Blocked => "OpenClipboard refused",
            _ => "OpenClipboard failed unexpectedly",
        };
        result(probe, outcome, Some(code), detail)
    }

    fn cmd_exe() -> PathBuf {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        PathBuf::from(root).join("System32").join("cmd.exe")
    }

    /// `SpawnProcess`: run `cmd.exe /C exit 0` and wait for it. Blocked by the
    /// job's `ActiveProcessLimit = 1` (`ERROR_NOT_ENOUGH_QUOTA`) or by the
    /// AppContainer (`ERROR_ACCESS_DENIED`).
    pub fn spawn_process() -> ProbeResultMsg {
        let probe = ProbeId::SpawnProcess;
        match Command::new(cmd_exe()).args(["/C", "exit", "0"]).status() {
            Ok(status) if status.success() => {
                result(probe, ProbeOutcome::Allowed, None, "child process ran")
            }
            Ok(_) => result(
                probe,
                ProbeOutcome::Error,
                None,
                "child process ran but exited abnormally",
            ),
            Err(e) => {
                let code = os_code(&e);
                let outcome = code.map_or(ProbeOutcome::Error, classify_spawn);
                result(probe, outcome, code, "child process not started")
            }
        }
    }

    /// `HandleSentinel`: `GetHandleInformation` on a handle value that exists
    /// only in the host (§3.4: the worker holds nothing but its three pipes).
    pub fn handle_sentinel(handle: Option<u64>) -> ProbeResultMsg {
        let probe = ProbeId::HandleSentinel;
        let Some(value) = handle else {
            return result(
                probe,
                ProbeOutcome::Error,
                None,
                "no handle value in the request",
            );
        };
        let mut flags: u32 = 0;
        // SAFETY: the value is only looked up in this process's handle table;
        // `flags` is a valid out pointer.
        let ok = unsafe { GetHandleInformation(value as usize as *mut _, &mut flags) };
        if ok != 0 {
            return result(
                probe,
                ProbeOutcome::Allowed,
                None,
                "the worker holds the sentinel handle",
            );
        }
        let code = last_error();
        let outcome = classify_handle_sentinel(code);
        let detail = match outcome {
            ProbeOutcome::Blocked => "the sentinel handle is not in the worker",
            _ => "GetHandleInformation failed unexpectedly",
        };
        result(probe, outcome, Some(code), detail)
    }
}

#[cfg(windows)]
pub use calls::{cred_read, handle_sentinel, open_clipboard, open_process_vm_read, spawn_process};
