//! The Unix half of the worker split shared by Linux and macOS (Δ2, PD-137):
//! the guarded pid kill and the reaper.
//!
//! A pid kill takes the [`ReapGuard`]'s lock across `kill(2)`; the reaper sets
//! the guard's `reaped` flag in an order that leaves no gap between the reap
//! and the flag, so a recycled pid is never hit:
//! - Linux: the reaper blocks in `waitid(P_PID, pid, WEXITED | WNOWAIT)`, which
//!   waits for the exit without reaping, holding no lock; then it marks the
//!   guard and only then reaps with `waitpid`. If `waitid` fails, it falls back
//!   to the poll below. (The Linux kill handle normally signals through a pidfd
//!   and needs no guard; the guard covers the `ENOSYS` fallback.)
//! - macOS: Darwin's `waitid` is not reliable (Go's `os` package does not use it
//!   there, golang.org/issue/19314), which is PD-137's "historical quirks". The
//!   reaper polls `waitpid(WNOHANG)` every 10 ms inside the guard's lock
//!   ([`reap_polling_until`]); the call never blocks, so the lock rule holds.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::kill::{GuardedKill, ReapGuard, reap_polling_until};
use crate::spawn::{ExitKind, KillHandle, Reaper};

/// How often a polling reap tries `waitpid(WNOHANG)`.
const REAP_POLL: Duration = Duration::from_millis(10);
/// How long a reaper dropped without `wait` waits for the killed worker.
const DROP_REAP: Duration = Duration::from_secs(2);

/// Decodes a `waitpid` status.
fn decode(status: libc::c_int) -> ExitKind {
    let st = ExitStatus::from_raw(status);
    match (st.code(), st.signal()) {
        (Some(code), _) => ExitKind::Code(code),
        (None, Some(sig)) => ExitKind::Signal(sig),
        // stopped or continued; not reported without WUNTRACED/WCONTINUED
        (None, None) => ExitKind::Code(-1),
    }
}

/// `kill(pid, SIGKILL)`. The caller holds the reap guard's lock, so `pid` is
/// an unreaped child (a zombie keeps its pid). `kill(2)` does not block.
pub(crate) fn sigkill_pid(pid: libc::pid_t) {
    // SAFETY: `kill` takes two integers and touches no memory of ours; the pid
    // is our unreaped child (see above), so the signal reaches no other process.
    unsafe { libc::kill(pid, libc::SIGKILL) };
}

/// `waitpid(pid, WNOHANG)`: `Some` once `pid` is reaped; never blocks.
fn waitpid_nohang(pid: libc::pid_t) -> io::Result<Option<ExitKind>> {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a valid out-pointer and `pid` is our child.
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == 0 {
            return Ok(None);
        }
        if rc == pid {
            return Ok(Some(decode(status)));
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_wait {
    use std::io;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::decode;
    use crate::spawn::ExitKind;

    /// Reaps that fell back to polling because `waitid(WNOWAIT)` failed (CI
    /// evidence, PD-137).
    pub(super) static REAP_FALLBACKS: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn reap_fallbacks() -> u64 {
        REAP_FALLBACKS.load(Ordering::Relaxed)
    }

    /// Blocks until `pid` has exited, without reaping it.
    pub(super) fn wait_exited(pid: libc::pid_t) -> io::Result<()> {
        let id = libc::id_t::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative pid"))?;
        loop {
            // SAFETY: an all-zero `siginfo_t` is a valid out-buffer.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: `info` is a valid out-pointer for the call; `pid` is our
            // child. WNOWAIT leaves the child waitable.
            let rc =
                unsafe { libc::waitid(libc::P_PID, id, &mut info, libc::WEXITED | libc::WNOWAIT) };
            if rc == 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    /// `waitpid(pid, 0)`: reaps `pid` (which has exited) and decodes its
    /// status.
    pub(super) fn waitpid_blocking(pid: libc::pid_t) -> io::Result<ExitKind> {
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: `status` is a valid out-pointer and `pid` is our child.
            let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            if rc == pid {
                return Ok(decode(status));
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux_wait::reap_fallbacks;

/// The reaper of a split Unix worker (Δ2). Dropped without `wait`, it kills the
/// worker and reaps it for up to 2 s, as the unsplit worker's drop did.
pub(crate) struct UnixReaper {
    pid: libc::pid_t,
    kill: Arc<GuardedKill>,
    /// Set once the worker is reaped (or was reaped before the split).
    exit: Option<ExitKind>,
}

impl UnixReaper {
    /// `exit` is the status when the worker was already reaped before the
    /// split; the guard of `kill` is then marked at once.
    pub(crate) fn new(
        pid: libc::pid_t,
        kill: Arc<GuardedKill>,
        exit: Option<ExitKind>,
    ) -> UnixReaper {
        if exit.is_some() {
            kill.guard().mark_reaped();
        }
        UnixReaper { pid, kill, exit }
    }

    fn guard(&self) -> &ReapGuard {
        self.kill.guard()
    }

    /// Polls inside the guard's lock until the worker is reaped.
    fn reap_polling(&self) -> io::Result<ExitKind> {
        let pid = self.pid;
        reap_polling_until(self.guard(), || waitpid_nohang(pid), REAP_POLL, None)?
            .ok_or_else(|| io::Error::other("the worker was not reaped"))
    }

    #[cfg(target_os = "linux")]
    fn reap(&self) -> io::Result<ExitKind> {
        use std::sync::atomic::Ordering;

        use crate::kill::reap_after_wait;

        let pid = self.pid;
        match reap_after_wait(
            self.guard(),
            || linux_wait::wait_exited(pid),
            || linux_wait::waitpid_blocking(pid),
        ) {
            Ok(exit) => Ok(exit),
            // `waitid` failed before anything was reaped (the guard is marked
            // only after it returned): poll inside the lock instead.
            Err(_) if !self.guard().is_reaped() => {
                linux_wait::REAP_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                self.reap_polling()
            }
            Err(err) => Err(err),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn reap(&self) -> io::Result<ExitKind> {
        self.reap_polling()
    }
}

impl Reaper for UnixReaper {
    fn wait(mut self: Box<Self>) -> io::Result<ExitKind> {
        if let Some(exit) = self.exit {
            return Ok(exit);
        }
        let exit = self.reap()?;
        self.exit = Some(exit);
        Ok(exit)
    }
}

impl Drop for UnixReaper {
    fn drop(&mut self) {
        if self.exit.is_some() {
            return;
        }
        // A no-op when a kill was already sent or the worker is reaped.
        self.kill.kill();
        let pid = self.pid;
        if let Ok(Some(exit)) = reap_polling_until(
            self.guard(),
            || waitpid_nohang(pid),
            REAP_POLL,
            Some(Instant::now() + DROP_REAP),
        ) {
            self.exit = Some(exit);
        }
    }
}
