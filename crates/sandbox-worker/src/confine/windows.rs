//! Windows: the host confines the worker at spawn (section 9.4), so the worker
//! applies nothing to itself. It only reports what it finds: it is
//! confined if its own token says AppContainer and it is a member of a job.
//!
//! The report is read from the OS, never hardcoded, so a worker that was
//! started without the AppContainer (for example by hand) reports
//! `applied: false` and the host scores the floor as not met.

use std::ffi::c_void;
use std::ptr::null_mut;

use atlas_duck_ipc::sandbox::probe::ConfinementReport;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TokenIsAppContainer,
    TokenSecurityAttributes,
};
use windows_sys::Win32::System::JobObjects::IsProcessInJob;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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
    #[test]
    fn an_unconfined_process_does_not_report_applied() {
        let report = apply();
        assert!(!report.applied, "{report:?}");
        assert_eq!(report.mechanism, "appcontainer");
        assert_ne!(report.lpac, Some(true), "{report:?}");
    }
}
