//! Linux probe attempts (§9.4): raw `clone`, `clone3`, and the two ways to
//! read the app's memory. The seccomp filter kills the worker on `clone`,
//! `process_vm_readv` and the rest, so under confinement these functions never
//! return; the host scores the SIGSYS death. They return only where the
//! syscall answers with an errno (`clone3` -> `ENOSYS`, `open*` -> `EACCES`)
//! or where nothing is confined (the negative controls).

use std::ffi::c_void;

use atlas_duck_ipc::sandbox::probe::{ProbeId, ProbeOutcome, ProbeResultMsg};

use super::unix::is_denial;
use super::{os_code, result};

/// Remote address read by `MemReadProcessVm`. Unmapped in every process (below
/// `mmap_min_addr`), so a read can never return app data. The kernel runs the
/// ptrace access check (`mm_access`) before it touches any remote address, so
/// the errno still tells whether the read would have been allowed: `EPERM`
/// means refused, `EFAULT` means the check passed and only the address is bad.
pub const UNMAPPED_REMOTE_ADDR: usize = 0x10;

fn last_errno() -> i64 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(-1, i64::from)
}

/// Scores a failed `clone`/`clone3`. A denial is `Blocked`. For `clone3`,
/// `ENOSYS` is `Blocked` as well: the seccomp allowlist answers `clone3` with
/// `ENOSYS` so glibc falls back to `clone` (§9.4). For raw `clone`, `ENOSYS`
/// is `Error`.
pub fn classify_clone(errno: i64, enosys_means_blocked: bool) -> ProbeOutcome {
    if is_denial(errno) || (enosys_means_blocked && errno == i64::from(libc::ENOSYS)) {
        ProbeOutcome::Blocked
    } else {
        ProbeOutcome::Error
    }
}

/// Scores a failed `process_vm_readv`: `EPERM`/`EACCES` is `Blocked`, `EFAULT`
/// (the access check passed, the address is unmapped) is `Allowed`, and
/// `ESRCH` (no such process), `ENOSYS` and the rest are `Error`.
pub fn classify_process_vm(errno: i64) -> ProbeOutcome {
    if is_denial(errno) {
        ProbeOutcome::Blocked
    } else if errno == i64::from(libc::EFAULT) {
        ProbeOutcome::Allowed
    } else {
        ProbeOutcome::Error
    }
}

/// Reaps a child that exited immediately after a successful raw clone.
fn reap(pid: libc::pid_t) {
    let mut status: libc::c_int = 0;
    // SAFETY: `pid` is a child of this process and `status` is a valid out pointer.
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
}

/// `RawClone`: the raw `clone` syscall with `SIGCHLD` and no other flag (a
/// fork). The child does nothing but `_exit(0)`.
pub fn raw_clone() -> ProbeResultMsg {
    let probe = ProbeId::RawClone;
    // SAFETY: a fork-equivalent `clone` (flags = SIGCHLD, no shared memory, no
    // new stack). The child path below only calls the async-signal-safe `_exit`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::SIGCHLD as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if rc == 0 {
        // SAFETY: child of the clone above; `_exit` is async-signal-safe.
        unsafe { libc::_exit(0) }
    }
    if rc > 0 {
        reap(rc as libc::pid_t);
        return result(
            probe,
            ProbeOutcome::Allowed,
            None,
            "raw clone created a child",
        );
    }
    let errno = last_errno();
    result(
        probe,
        classify_clone(errno, false),
        Some(errno),
        "raw clone refused",
    )
}

/// The first 64 bytes of `struct clone_args` (`CLONE_ARGS_SIZE_VER0`), which
/// is all a plain fork needs.
#[repr(C)]
struct CloneArgsV0 {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
}

/// `Clone3`: the `clone3` syscall as a fork. The child does nothing but `_exit(0)`.
pub fn clone3() -> ProbeResultMsg {
    let probe = ProbeId::Clone3;
    let args = CloneArgsV0 {
        flags: 0,
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
    };
    // SAFETY: `args` is a valid `clone_args` of the stated size; with flags = 0
    // this is a fork, and the child path only calls the async-signal-safe `_exit`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const CloneArgsV0,
            std::mem::size_of::<CloneArgsV0>(),
        )
    };
    if rc == 0 {
        // SAFETY: child of the clone3 above; `_exit` is async-signal-safe.
        unsafe { libc::_exit(0) }
    }
    if rc > 0 {
        reap(rc as libc::pid_t);
        return result(probe, ProbeOutcome::Allowed, None, "clone3 created a child");
    }
    let errno = last_errno();
    result(
        probe,
        classify_clone(errno, true),
        Some(errno),
        "clone3 refused",
    )
}

/// `MemReadProcessVm`: `process_vm_readv` of one byte at
/// [`UNMAPPED_REMOTE_ADDR`] in the app (`app_pid`).
pub fn mem_read_process_vm(app_pid: u32) -> ProbeResultMsg {
    let probe = ProbeId::MemReadProcessVm;
    let mut buf = [0u8; 1];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<c_void>(),
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: UNMAPPED_REMOTE_ADDR as *mut c_void,
        iov_len: 1,
    };
    // SAFETY: one valid local iovec and one remote iovec; the kernel validates
    // the remote range, and a bad address fails with EFAULT.
    let n = unsafe { libc::process_vm_readv(app_pid as libc::pid_t, &local, 1, &remote, 1, 0) };
    if n >= 0 {
        return result(
            probe,
            ProbeOutcome::Allowed,
            None,
            "process_vm_readv read bytes",
        );
    }
    let errno = last_errno();
    let detail = match classify_process_vm(errno) {
        ProbeOutcome::Allowed => "process_vm_readv passed the access check",
        ProbeOutcome::Blocked => "process_vm_readv refused",
        ProbeOutcome::Error => "process_vm_readv failed unexpectedly",
    };
    result(probe, classify_process_vm(errno), Some(errno), detail)
}

/// `MemReadProcMem`: open `/proc/<app pid>/mem` for reading. The kernel does
/// its ptrace access check at `open`, so a successful open already proves
/// read access. Under seccomp `open*` returns `EACCES` first.
pub fn mem_read_proc_mem(app_pid: u32) -> ProbeResultMsg {
    let probe = ProbeId::MemReadProcMem;
    match std::fs::File::open(format!("/proc/{app_pid}/mem")) {
        Ok(_) => result(probe, ProbeOutcome::Allowed, None, "/proc/<pid>/mem opened"),
        Err(e) => {
            let code = os_code(&e);
            let outcome = code.map_or(ProbeOutcome::Error, |c| {
                if is_denial(c) {
                    ProbeOutcome::Blocked
                } else {
                    ProbeOutcome::Error
                }
            });
            result(probe, outcome, code, "/proc/<pid>/mem not opened")
        }
    }
}
