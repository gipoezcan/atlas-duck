//! macOS probe attempts (§9.4): `task_for_pid` on the app and a
//! `bootstrap_look_up` of securityd. The return-code tables are plain
//! constants and compile on every OS; only the Mach calls are `cfg(macos)`.

use atlas_duck_ipc::sandbox::probe::ProbeOutcome;
#[cfg(target_os = "macos")]
use atlas_duck_ipc::sandbox::probe::{ProbeId, ProbeResultMsg};

#[cfg(target_os = "macos")]
use super::result;

/// `KERN_SUCCESS`.
pub const KERN_SUCCESS: i64 = 0;
/// `KERN_FAILURE`: what `task_for_pid` returns when the target refuses (no
/// `get-task-allow` under the hardened runtime) or the seatbelt profile denies.
pub const KERN_FAILURE: i64 = 5;
/// `BOOTSTRAP_NOT_PRIVILEGED`: what `bootstrap_look_up` returns for a service
/// that the sandbox profile denies (`mach-lookup`).
pub const BOOTSTRAP_NOT_PRIVILEGED: i64 = 1100;

/// `task_for_pid`: success is `Allowed`, `KERN_FAILURE` is `Blocked`, any other
/// code is `Error`.
pub fn classify_task_for_pid(kr: i64) -> ProbeOutcome {
    match kr {
        KERN_SUCCESS => ProbeOutcome::Allowed,
        KERN_FAILURE => ProbeOutcome::Blocked,
        _ => ProbeOutcome::Error,
    }
}

/// `bootstrap_look_up`: success is `Allowed`, `BOOTSTRAP_NOT_PRIVILEGED` is
/// `Blocked`, any other code (including `BOOTSTRAP_UNKNOWN_SERVICE`, 1102, a
/// service that does not exist) is `Error`.
pub fn classify_mach_lookup(kr: i64) -> ProbeOutcome {
    match kr {
        KERN_SUCCESS => ProbeOutcome::Allowed,
        BOOTSTRAP_NOT_PRIVILEGED => ProbeOutcome::Blocked,
        _ => ProbeOutcome::Error,
    }
}

#[cfg(target_os = "macos")]
mod ffi {
    use std::ffi::c_char;

    use libc::{c_int, kern_return_t, mach_port_t};

    // libSystem exports these. `libc` does not declare `task_for_pid`,
    // `bootstrap_look_up`, `bootstrap_port` or `mach_task_self_`.
    unsafe extern "C" {
        pub static mach_task_self_: mach_port_t;
        pub static bootstrap_port: mach_port_t;
        pub fn task_for_pid(
            target_tport: mach_port_t,
            pid: c_int,
            task: *mut mach_port_t,
        ) -> kern_return_t;
        pub fn bootstrap_look_up(
            bootstrap: mach_port_t,
            service_name: *const c_char,
            service_port: *mut mach_port_t,
        ) -> kern_return_t;
        pub fn mach_port_deallocate(task: mach_port_t, name: mach_port_t) -> kern_return_t;
    }
}

/// `TaskForPid`: `task_for_pid(mach_task_self(), app_pid)`.
#[cfg(target_os = "macos")]
pub fn task_for_pid(app_pid: u32) -> ProbeResultMsg {
    let probe = ProbeId::TaskForPid;
    let mut task: libc::mach_port_t = 0;
    // SAFETY: `task` is a valid out pointer; `mach_task_self_` is initialized by libSystem.
    let kr = unsafe { ffi::task_for_pid(ffi::mach_task_self_, app_pid as libc::c_int, &mut task) };
    let kr = i64::from(kr);
    let outcome = classify_task_for_pid(kr);
    if kr == KERN_SUCCESS {
        // SAFETY: releases the send right the successful call returned.
        unsafe {
            ffi::mach_port_deallocate(ffi::mach_task_self_, task);
        }
    }
    let detail = match outcome {
        ProbeOutcome::Allowed => "task_for_pid returned the task port",
        ProbeOutcome::Blocked => "task_for_pid refused",
        ProbeOutcome::Error => "task_for_pid failed unexpectedly",
    };
    result(probe, outcome, Some(kr), detail)
}

/// `MachLookupSecurityd`: `bootstrap_look_up` of the keychain daemon's service, `com.apple.SecurityServer`.
#[cfg(target_os = "macos")]
pub fn mach_lookup_securityd() -> ProbeResultMsg {
    let probe = ProbeId::MachLookupSecurityd;
    let name = c"com.apple.SecurityServer";
    let mut port: libc::mach_port_t = 0;
    // SAFETY: `name` is NUL-terminated and `port` is a valid out pointer.
    let kr = unsafe { ffi::bootstrap_look_up(ffi::bootstrap_port, name.as_ptr(), &mut port) };
    let kr = i64::from(kr);
    let outcome = classify_mach_lookup(kr);
    if kr == KERN_SUCCESS {
        // SAFETY: releases the send right the successful lookup returned.
        unsafe {
            ffi::mach_port_deallocate(ffi::mach_task_self_, port);
        }
    }
    let detail = match outcome {
        ProbeOutcome::Allowed => "mach-lookup of securityd succeeded",
        ProbeOutcome::Blocked => "mach-lookup of securityd refused",
        ProbeOutcome::Error => "mach-lookup of securityd failed unexpectedly",
    };
    result(probe, outcome, Some(kr), detail)
}
