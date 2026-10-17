//! Windows: the host confines the worker at spawn (section 9.4), so the worker
//! applies nothing to itself. It only reports what it finds: it is
//! confined if its own token says AppContainer and it is a member of a job.
//!
//! The report is read from the OS, never hardcoded, so a worker that was
//! started without the AppContainer (for example by hand) reports
//! `applied: false` and the host scores the floor as not met.
//!
//! The degraded start (§9.4, M8 Task 11, [`drop_startup_token`]) is the one
//! step the worker takes itself: it drops the startup impersonation token of
//! its main thread before its first frame.

use std::ffi::c_void;
use std::ptr::null_mut;

use atlas_duck_ipc::sandbox::probe::ConfinementReport;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN, FALSE, GetLastError, HANDLE,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, RevertToSelf, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TokenIsAppContainer,
    TokenSecurityAttributes,
};
use windows_sys::Win32::System::JobObjects::IsProcessInJob;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use super::{ConfineError, LOCKDOWN_TOKEN, lockdown_token_report};

/// Reads one `DWORD` token flag of the current process; `Err` is the Win32
/// error code.
fn token_flag(class: TOKEN_INFORMATION_CLASS) -> Result<bool, u32> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the pseudo handle of the current process is always valid and
    // `token` is a valid out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        // SAFETY: no preconditions.
        return Err(unsafe { GetLastError() });
    }
    let mut value = 0u32;
    let mut returned = 0u32;
    // SAFETY: `token` is open; `value` is a writable DWORD of the size passed.
    let ok = unsafe {
        GetTokenInformation(
            token,
            class,
            (&mut value as *mut u32).cast::<c_void>(),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
        )
    };
    // SAFETY: no preconditions.
    let error = if ok == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    // SAFETY: `token` was opened above and is closed once.
    unsafe { CloseHandle(token) };
    match error {
        Some(e) => Err(e),
        None => Ok(value != 0),
    }
}

/// `UNICODE_STRING` (the layout of `ntdef.h`).
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

/// `TOKEN_SECURITY_ATTRIBUTE_V1` (not in windows-sys).
#[repr(C)]
struct SecurityAttributeV1 {
    name: UnicodeString,
    value_type: u16,
    reserved: u16,
    flags: u32,
    value_count: u32,
    values: *const c_void,
}

/// `TOKEN_SECURITY_ATTRIBUTES_INFORMATION` (not in windows-sys).
#[repr(C)]
struct SecurityAttributesInformation {
    version: u16,
    reserved: u16,
    attribute_count: u32,
    attributes: *const SecurityAttributeV1,
}

/// `TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64`.
const ATTRIBUTE_TYPE_UINT64: u16 = 2;

/// The security attribute that marks a Less-Privileged AppContainer token.
const NO_ALL_APP_PACKAGES: &str = "WIN://NOALLAPPPKG";

/// True when the token carries `WIN://NOALLAPPPKG = 1`, which is what an LPAC
/// process has (`TokenIsLessPrivilegedAppContainer` is reserved and
/// `GetTokenInformation` rejects it with `ERROR_INVALID_PARAMETER`, measured on
/// Windows 11). A token without the attribute, or a process that is no
/// AppContainer at all, is `Ok(false)`.
fn token_is_lpac() -> Result<bool, u32> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the pseudo handle of the current process is always valid and
    // `token` is a valid out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        // SAFETY: no preconditions.
        return Err(unsafe { GetLastError() });
    }
    let result = lpac_attribute(token);
    // SAFETY: `token` was opened above and is closed once.
    unsafe { CloseHandle(token) };
    result
}

fn lpac_attribute(token: HANDLE) -> Result<bool, u32> {
    // u64 backing keeps the buffer 8-byte aligned for the structures below.
    let mut buf = vec![0u64; 512];
    loop {
        let mut needed = 0u32;
        // SAFETY: `buf` is writable for the byte size passed.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenSecurityAttributes,
                buf.as_mut_ptr().cast::<c_void>(),
                (buf.len() * 8) as u32,
                &mut needed,
            )
        };
        if ok != 0 {
            break;
        }
        // SAFETY: no preconditions.
        let e = unsafe { GetLastError() };
        if e == ERROR_INSUFFICIENT_BUFFER && needed as usize > buf.len() * 8 {
            buf = vec![0u64; (needed as usize).div_ceil(8)];
            continue;
        }
        return Err(e);
    }
    // SAFETY: on success the buffer starts with a
    // TOKEN_SECURITY_ATTRIBUTES_INFORMATION whose pointers refer into the
    // same buffer, which outlives every use below.
    let info = unsafe { &*(buf.as_ptr().cast::<SecurityAttributesInformation>()) };
    for i in 0..info.attribute_count as usize {
        // SAFETY: `attribute_count` entries follow `attributes`.
        let attr = unsafe { &*info.attributes.add(i) };
        let units = usize::from(attr.name.length) / 2;
        // SAFETY: the name is `length` bytes of UTF-16 at `buffer`.
        let name = String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(attr.name.buffer, units)
        });
        if name.eq_ignore_ascii_case(NO_ALL_APP_PACKAGES) {
            if attr.value_type == ATTRIBUTE_TYPE_UINT64 && attr.value_count > 0 {
                // SAFETY: a UINT64 attribute has `value_count` u64 values.
                return Ok(unsafe { *attr.values.cast::<u64>() } == 1);
            }
            return Ok(false);
        }
    }
    Ok(false)
}

/// True if the current process is in any job object.
fn in_job() -> Result<bool, u32> {
    let mut result = 0i32;
    // SAFETY: the current-process pseudo handle; a NULL job asks "any job";
    // `result` is a valid out-pointer.
    if unsafe { IsProcessInJob(GetCurrentProcess(), null_mut(), &mut result) } == 0 {
        // SAFETY: no preconditions.
        return Err(unsafe { GetLastError() });
    }
    Ok(result != 0)
}

/// Whether the calling thread impersonates: `Ok(true)` when it has a token,
/// `Ok(false)` on `ERROR_NO_TOKEN`, `Err` with any other error code.
fn thread_impersonates() -> Result<bool, u32> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the pseudo handle of the current thread is always valid and
    // `token` is a valid out-pointer. `OpenAsSelf = FALSE`: while the thread
    // impersonates, the check is made with its own token (the lockdown process
    // token would be refused); without a token there is nothing to check.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &mut token) } == 0 {
        // SAFETY: no preconditions.
        let e = unsafe { GetLastError() };
        return if e == ERROR_NO_TOKEN {
            Ok(false)
        } else {
            Err(e)
        };
    }
    // SAFETY: `token` was opened above and is closed once.
    unsafe { CloseHandle(token) };
    Ok(true)
}

/// Loads, while the startup token can still open files, what Rust's std loads
/// on first use and the worker uses later: the source of the hash keys
/// (`ProcessPrng`) and the clocks. The DLLs the worker imports are loaded
/// before `main`, and the script engine is plain C on the CRT.
fn warm_up() {
    use std::hash::BuildHasher;
    let keys = std::collections::hash_map::RandomState::new();
    std::hint::black_box(keys.hash_one(0u8));
    std::hint::black_box(std::time::SystemTime::now());
    std::hint::black_box(std::time::Instant::now());
}

/// The degraded start (§9.4 "applied after startup", M8 Task 11). The process
/// token is the lockdown token (restricting SID = NULL SID), which can open
/// nothing; the main thread was resumed on a startup impersonation token so
/// that the loader could open the worker's DLLs. This drops that token with
/// `RevertToSelf` before the first frame and checks that the thread no longer
/// impersonates. The host lowers the process token to untrusted integrity once
/// it has the first frame, and checks both before it sends anything.
///
/// `Err` (the token could not be dropped, or the thread still has one) is
/// fatal: the worker must exit without a frame. A missing startup token is no
/// error (nothing to drop), but the report carries `ERROR_NO_TOKEN`.
pub(super) fn drop_startup_token() -> Result<ConfinementReport, ConfineError> {
    let fatal = |os_error: Option<u32>| ConfineError {
        mechanism: LOCKDOWN_TOKEN,
        os_error: os_error.map(i64::from),
    };
    let startup = thread_impersonates();
    warm_up();
    // SAFETY: no preconditions; ends the calling thread's impersonation.
    if unsafe { RevertToSelf() } == 0 {
        // SAFETY: no preconditions.
        return Err(fatal(Some(unsafe { GetLastError() })));
    }
    match thread_impersonates() {
        Ok(false) => {}
        Ok(true) => return Err(fatal(None)),
        Err(e) => return Err(fatal(Some(e))),
    }
    let os_error = match startup {
        Ok(true) => None,
        Ok(false) => Some(ERROR_NO_TOKEN),
        Err(e) => Some(e),
    };
    Ok(lockdown_token_report(os_error.map(i64::from)))
}

/// What the worker's own token and job membership say.
pub(super) fn apply() -> ConfinementReport {
    let app_container = token_flag(TokenIsAppContainer);
    let lpac = token_is_lpac();
    let job = in_job();
    let os_error = [app_container.err(), lpac.err(), job.err()]
        .into_iter()
        .flatten()
        .next()
        .map(i64::from);
    ConfinementReport {
        applied: app_container == Ok(true) && job == Ok(true),
        mechanism: "appcontainer".to_owned(),
        no_new_privs: None,
        landlock_abi: None,
        seccomp: None,
        lpac: lpac.ok(),
        os_error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test process is neither an AppContainer nor in a worker job, so it
    /// must not claim to be confined. (The AppContainer case is covered by
    /// `probes_windows.rs`, where the host spawns the real worker.)
    /// The test thread never impersonates: dropping "the startup token" is a
    /// no-op that succeeds, and the report says that none was there.
    #[test]
    fn a_thread_without_a_startup_token_reports_no_token() {
        assert_eq!(thread_impersonates(), Ok(false));
        let report = drop_startup_token();
        assert_eq!(
            report,
            Ok(lockdown_token_report(Some(i64::from(ERROR_NO_TOKEN))))
        );
        assert_eq!(thread_impersonates(), Ok(false));
    }

    #[test]
    fn an_unconfined_process_does_not_report_applied() {
        let report = apply();
        assert!(!report.applied, "{report:?}");
        assert_eq!(report.mechanism, "appcontainer");
        assert_ne!(report.lpac, Some(true), "{report:?}");
    }
}
