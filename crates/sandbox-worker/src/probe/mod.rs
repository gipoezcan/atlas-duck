//! The §9.4 probe attempts, one library function per `ProbeId`.
//!
//! Each probe tries one forbidden thing and reports what happened:
//! * `Blocked`: the OS (or the sandbox) refused with an explicit denial code.
//! * `Allowed`: the attempt got past the sandbox. A failure that happens after
//!   the sandbox check (`ECONNREFUSED`, `ERROR_NOT_FOUND`, `EFAULT` ...) counts
//!   as Allowed too, because the denial would have come first.
//! * `Error`: anything unexpected. An unknown error code is never `Blocked`, so
//!   a broken probe cannot make the floor look met.
//!
//! On Linux, the seccomp default-kill filter ends the worker with SIGSYS before
//! a probe can answer; the host scores that death as `Blocked` (T15 `score`).

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use atlas_duck_ipc::sandbox::probe::{ProbeId, ProbeOutcome, ProbeRequest, ProbeResultMsg};

#[cfg(target_os = "linux")]
pub mod linux;
pub mod macos;
#[cfg(unix)]
pub mod unix;
// Compiled on every OS: the Win32 error-code tables are plain constants, so the
// Windows classification is unit-tested on Linux and macOS too. Only the Win32
// calls inside are `cfg(windows)`.
pub mod windows;

/// Deadline of the connect probes. `TcpStream::connect_timeout` is a
/// non-blocking connect plus a wait with this deadline and starts no thread. A
/// blocking connect to 192.0.2.1 would wait for minutes of SYN retries.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(2);

/// Longest `detail` string, in bytes. Details are short evidence words, never
/// file names, paths or response text.
pub const MAX_DETAIL_BYTES: usize = 256;

/// Builds a result message with a bounded `detail`.
pub fn result(
    probe: ProbeId,
    outcome: ProbeOutcome,
    os_error: Option<i64>,
    detail: &str,
) -> ProbeResultMsg {
    let mut end = detail.len().min(MAX_DETAIL_BYTES);
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    ProbeResultMsg {
        probe,
        outcome,
        os_error,
        detail: Some(detail[..end].to_owned()),
        env_names: None,
    }
}

/// Linux: names on stderr the forbidden syscall that the next statement
/// attempts. Under the seccomp default-kill filter the attempt ends the worker
/// with SIGSYS and no result frame, and the host scores that as `Blocked`. A
/// worker that dies earlier, because the allowlist lacks a syscall that the
/// start-up or the probe code needs, would look the same; the host-side test
/// therefore requires this line in the worker's stderr head next to the SIGSYS
/// (preflight C7). `write` to fd 2 is on the allowlist, and the line only
/// names a syscall: no path, address or value.
#[cfg(target_os = "linux")]
pub(crate) fn announce_attempt(syscall: &str) {
    use std::io::Write;
    let _ = std::io::stderr().write_all(format!("probe-attempt: {syscall}\n").as_bytes());
}

/// The raw OS error code of an I/O error as the wire type.
pub fn os_code(e: &io::Error) -> Option<i64> {
    e.raw_os_error().map(i64::from)
}

/// Runs one probe in this process and returns its result message.
pub fn run_probe(req: &ProbeRequest) -> ProbeResultMsg {
    match req.probe {
        ProbeId::FileInProfile => file_in_profile(&req.profile_path),
        ProbeId::ConnectLoopback => connect(req.probe, &req.loopback_addr),
        ProbeId::ConnectPublic => connect(req.probe, &req.public_addr),
        ProbeId::SpawnProcess => spawn_process(),
        ProbeId::EngineSelfTest => engine_self_test(),
        ProbeId::EnvNames => env_names(),
        ProbeId::HandleSentinel => handle_sentinel(req.handle_value),
        _ => linux_only(req)
            .or_else(|| macos_only(req))
            .or_else(|| windows_only(req))
            .unwrap_or_else(|| {
                result(
                    req.probe,
                    ProbeOutcome::Error,
                    None,
                    "probe is not defined on this OS",
                )
            }),
    }
}

#[cfg(target_os = "linux")]
fn linux_only(req: &ProbeRequest) -> Option<ProbeResultMsg> {
    match req.probe {
        ProbeId::RawClone => Some(linux::raw_clone()),
        ProbeId::Clone3 => Some(linux::clone3()),
        ProbeId::MemReadProcessVm => Some(linux::mem_read_process_vm(req.app_pid)),
        ProbeId::MemReadProcMem => Some(linux::mem_read_proc_mem(req.app_pid)),
        _ => None,
    }
}

#[cfg(not(target_os = "linux"))]
fn linux_only(_req: &ProbeRequest) -> Option<ProbeResultMsg> {
    None
}

#[cfg(target_os = "macos")]
fn macos_only(req: &ProbeRequest) -> Option<ProbeResultMsg> {
    match req.probe {
        ProbeId::TaskForPid => Some(macos::task_for_pid(req.app_pid)),
        ProbeId::MachLookupSecurityd => Some(macos::mach_lookup_securityd()),
        _ => None,
    }
}

#[cfg(not(target_os = "macos"))]
fn macos_only(_req: &ProbeRequest) -> Option<ProbeResultMsg> {
    None
}

#[cfg(windows)]
fn windows_only(req: &ProbeRequest) -> Option<ProbeResultMsg> {
    match req.probe {
        ProbeId::OpenProcessVmRead => Some(windows::open_process_vm_read(req.app_pid)),
        ProbeId::CredRead => Some(windows::cred_read()),
        ProbeId::OpenClipboard => Some(windows::open_clipboard()),
        _ => None,
    }
}

#[cfg(not(windows))]
fn windows_only(_req: &ProbeRequest) -> Option<ProbeResultMsg> {
    None
}

/// `FileInProfile`: open the user's profile directory (`profile_path`), the
/// §9.4 "open a file in the user profile" / §15 V09 `CreateFileW` on
/// `%USERPROFILE%`. It opens; it does not list. On Windows a plain
/// `CreateFileW` on a directory fails with `ERROR_ACCESS_DENIED` even when
/// access is allowed, which would be a false `Blocked`, so the open passes
/// `FILE_FLAG_BACKUP_SEMANTICS` (see [`open_profile_dir`]). Under Landlock or
/// seccomp `openat` returns `EACCES`; under seatbelt `EPERM`; in an
/// AppContainer `ERROR_ACCESS_DENIED`.
fn file_in_profile(profile_path: &str) -> ProbeResultMsg {
    let probe = ProbeId::FileInProfile;
    match open_profile_dir(profile_path) {
        Ok(_) => result(
            probe,
            ProbeOutcome::Allowed,
            None,
            "profile directory opened",
        ),
        Err(e) => {
            let code = os_code(&e);
            let outcome = match code {
                Some(c) if platform_is_denial(c) => ProbeOutcome::Blocked,
                _ => ProbeOutcome::Error,
            };
            result(probe, outcome, code, "profile directory not opened")
        }
    }
}

/// Opens a directory handle for reading. The handle is dropped by the caller.
#[cfg(windows)]
fn open_profile_dir(path: &str) -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

/// Opens a directory for reading (`openat` with `O_RDONLY`). The handle is
/// dropped by the caller.
#[cfg(unix)]
fn open_profile_dir(path: &str) -> io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// `ConnectLoopback` / `ConnectPublic`: a non-blocking connect with a 2 s
/// deadline. Only an explicit denial is `Blocked`.
fn connect(probe: ProbeId, addr: &str) -> ProbeResultMsg {
    let Ok(sock) = addr.parse::<SocketAddr>() else {
        return result(probe, ProbeOutcome::Error, None, "invalid probe address");
    };
    #[cfg(target_os = "linux")]
    announce_attempt("socket");
    // Windows: std asserts on `WSAStartup`, which can fail (measured: under
    // LPAC). Record the failure as evidence (an `Error`, never `Blocked`, and
    // with no claim about the cause) instead of panicking.
    #[cfg(windows)]
    if let Err(code) = windows::wsa_startup() {
        return result(
            probe,
            ProbeOutcome::Error,
            Some(code),
            &format!("WSAStartup failed (code {code}), no connect attempted"),
        );
    }
    match TcpStream::connect_timeout(&sock, CONNECT_DEADLINE) {
        Ok(_) => result(probe, ProbeOutcome::Allowed, None, "connected"),
        Err(e) => {
            let code = os_code(&e);
            let outcome = classify_connect(code, e.kind());
            let detail = match outcome {
                ProbeOutcome::Blocked => "connect denied",
                ProbeOutcome::Allowed => "connect reached the network stack",
                ProbeOutcome::Error => "connect failed unexpectedly",
            };
            result(probe, outcome, code, detail)
        }
    }
}

/// Scores a failed connect. `code` is the raw OS error; `kind` is used only
/// when there is none (`connect_timeout` reports its own deadline as
/// `TimedOut` without a code, the "EINPROGRESS then timeout" case).
pub fn classify_connect(code: Option<i64>, kind: io::ErrorKind) -> ProbeOutcome {
    match code {
        Some(c) => platform_classify_connect(c),
        None if kind == io::ErrorKind::TimedOut => ProbeOutcome::Allowed,
        None => ProbeOutcome::Error,
    }
}

#[cfg(unix)]
fn platform_is_denial(code: i64) -> bool {
    unix::is_denial(code)
}

#[cfg(windows)]
fn platform_is_denial(code: i64) -> bool {
    windows::is_denial(code)
}

#[cfg(unix)]
fn platform_classify_connect(code: i64) -> ProbeOutcome {
    unix::classify_connect(code)
}

#[cfg(windows)]
fn platform_classify_connect(code: i64) -> ProbeOutcome {
    windows::classify_connect(code)
}

#[cfg(unix)]
fn spawn_process() -> ProbeResultMsg {
    unix::spawn_process()
}

#[cfg(windows)]
fn spawn_process() -> ProbeResultMsg {
    windows::spawn_process()
}

#[cfg(windows)]
fn handle_sentinel(handle: Option<u64>) -> ProbeResultMsg {
    windows::handle_sentinel(handle)
}

#[cfg(not(windows))]
fn handle_sentinel(_handle: Option<u64>) -> ProbeResultMsg {
    result(
        ProbeId::HandleSentinel,
        ProbeOutcome::Error,
        None,
        "handle sentinel is only defined on Windows",
    )
}

/// `EngineSelfTest`: the §15 V11 self-test, run under the confinement.
/// `Allowed` means it passed; `Error` carries the failed check names.
fn engine_self_test() -> ProbeResultMsg {
    match crate::engine::run_selftest() {
        Ok(()) => result(
            ProbeId::EngineSelfTest,
            ProbeOutcome::Allowed,
            None,
            "engine self-test passed",
        ),
        Err(failed) => result(
            ProbeId::EngineSelfTest,
            ProbeOutcome::Error,
            None,
            &format!("engine self-test failed: {failed}"),
        ),
    }
}

/// `EnvNames`: the names, never the values, of the worker's environment (§3.4:
/// the host clears it to a fixed allowlist, and the host test checks that).
fn env_names() -> ProbeResultMsg {
    let mut names: Vec<String> = std::env::vars_os()
        .map(|(name, _value)| name.to_string_lossy().into_owned())
        .collect();
    names.sort();
    let mut msg = result(
        ProbeId::EnvNames,
        ProbeOutcome::Allowed,
        None,
        "environment names listed",
    );
    msg.env_names = Some(names);
    msg
}
