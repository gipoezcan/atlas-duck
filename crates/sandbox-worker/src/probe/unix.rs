//! Probe attempts shared by Linux and macOS, and the errno tables.

use std::process::Command;

use atlas_duck_ipc::sandbox::probe::{ProbeId, ProbeOutcome, ProbeResultMsg};

use super::{os_code, result};

/// `EACCES` or `EPERM`: the explicit denials. Seccomp `open*` returns `EACCES`
/// (§9.4), Landlock `EACCES`, seatbelt `EPERM`.
pub fn is_denial(errno: i64) -> bool {
    errno == i64::from(libc::EACCES) || errno == i64::from(libc::EPERM)
}

/// A denial is `Blocked`; every other errno is `Error`, never `Blocked`.
pub fn classify_denial(errno: i64) -> ProbeOutcome {
    if is_denial(errno) {
        ProbeOutcome::Blocked
    } else {
        ProbeOutcome::Error
    }
}

/// Scores a failed `connect`: a denial is `Blocked`; an error that comes from
/// the network stack itself (`ECONNREFUSED`, `ETIMEDOUT`, `ENETUNREACH`,
/// `EHOSTUNREACH`, `EINPROGRESS`, `ECONNRESET`, `ECONNABORTED`) means the
/// sandbox let the attempt through, so it is `Allowed`. Anything else is `Error`.
pub fn classify_connect(errno: i64) -> ProbeOutcome {
    const REACHED: [i32; 7] = [
        libc::ECONNREFUSED,
        libc::ETIMEDOUT,
        libc::ENETUNREACH,
        libc::EHOSTUNREACH,
        libc::EINPROGRESS,
        libc::ECONNRESET,
        libc::ECONNABORTED,
    ];
    if is_denial(errno) {
        ProbeOutcome::Blocked
    } else if REACHED.iter().any(|&e| errno == i64::from(e)) {
        ProbeOutcome::Allowed
    } else {
        ProbeOutcome::Error
    }
}

/// `SpawnProcess`: run `/bin/sh -c 'exit 0'` and wait for it. Never
/// `current_exe()`: in the in-process negative-control test that is the test
/// harness. The child's stdio is inherited, not `/dev/null`: opening
/// `/dev/null` is itself a file open that Landlock or seccomp would deny, and
/// the probe would then blame the wrong syscall. Under seccomp the first
/// `clone`/`execve` kills the worker with SIGSYS (scored by the host).
pub fn spawn_process() -> ProbeResultMsg {
    let probe = ProbeId::SpawnProcess;
    #[cfg(target_os = "linux")]
    super::announce_attempt("clone");
    match Command::new("/bin/sh").args(["-c", "exit 0"]).status() {
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
            let outcome = code.map_or(ProbeOutcome::Error, classify_denial);
            // macOS reports a seatbelt-refused exec as ENOENT (CI run 1).
            // That is a denial only because `/bin/sh` was seen to exist before
            // the profile was applied; with no such evidence it stays `Error`.
            #[cfg(target_os = "macos")]
            {
                if code == Some(i64::from(libc::ENOENT))
                    && crate::confine::macos::spawn_target_present_at_startup()
                {
                    return result(
                        probe,
                        ProbeOutcome::Blocked,
                        code,
                        "exec of an existing /bin/sh refused (seatbelt reports ENOENT)",
                    );
                }
            }
            result(probe, outcome, code, "child process not started")
        }
    }
}
