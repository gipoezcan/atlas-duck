//! Kill handles that never block, and the reap guard they share with the
//! reaper (§3.4, §9.5 "cancel does not wait for the reap", M3 final review
//! M-1, PD-137).
//!
//! A worker's [`KillHandle`] and its [`Reaper`](crate::spawn::Reaper) share
//! one [`ReapGuard`]: two flags behind a short lock.
//! - `kill` takes the lock, sends the signal unless the worker was already
//!   killed or reaped, and returns. The signal is one call that does not block
//!   (`TerminateJobObject`, `pidfd_send_signal`, `kill(2)`), so the lock is
//!   never held across a call that can block, and `kill` takes no lock that a
//!   reader, writer or reaper thread holds while it blocks.
//! - The reaper blocks in a wait that does not reap (`waitid(WNOWAIT)`,
//!   `WaitForSingleObject`) without the lock, then sets `reaped` under the lock
//!   ([`reap_after_wait`]), and only then reaps. A pid kill can therefore never
//!   reach a pid the kernel has already handed to another process: no signal is
//!   sent between the reap and the flag.
//! - Where that wait is unavailable, [`reap_polling_until`] holds the lock
//!   across each non-blocking reap attempt (`waitpid(WNOHANG)`), which gives the
//!   same order.
//! - `killed` is set only after the OS call succeeded (a worker that already
//!   exited counts as success). A failed call leaves the handle armed, so the
//!   next `kill` (the bridge's timer, the macOS watchdog) tries again.
//!
//! Precondition on Unix: sandbox-host is the worker's sole reaper. `SIGCHLD`
//! is neither `SIG_IGN` nor `SA_NOCLDWAIT` (the spawners refuse to spawn
//! otherwise, `crate::unix::ensure_sole_reaper`), and nothing else in the
//! process waits for the worker (no `waitpid(-1)`). Without it the kernel or a
//! foreign wait could reap the worker and free its pid before the reaper marks
//! the guard. A wait that fails with `ECHILD` shows such a violation: the guard
//! is then marked reaped at once ([`reaped_elsewhere`]), so no later kill
//! signals the pid.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::spawn::KillHandle;

#[derive(Debug, Default)]
struct Flags {
    killed: bool,
    reaped: bool,
}

/// The two flags of PD-137 shared by a worker's kill handle and its reaper.
#[derive(Debug, Default)]
pub struct ReapGuard {
    flags: Mutex<Flags>,
}

impl ReapGuard {
    /// A guard for a worker that is neither killed nor reaped.
    pub fn new() -> Arc<ReapGuard> {
        Arc::new(ReapGuard::default())
    }

    fn flags(&self) -> MutexGuard<'_, Flags> {
        self.flags.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `send` with the flag lock held, unless the worker was already
    /// killed or reaped. `send` must not block and cannot fail. Returns whether
    /// it ran.
    pub fn kill_with(&self, send: impl FnOnce()) -> bool {
        matches!(
            self.try_kill_with(|| {
                send();
                Ok(())
            }),
            Ok(true)
        )
    }

    /// Runs `send` with the flag lock held, unless the worker was already
    /// killed or reaped (`Ok(false)`). `send` must not block. The worker counts
    /// as killed only when `send` succeeded; its error is returned and the next
    /// call tries again.
    pub fn try_kill_with(&self, send: impl FnOnce() -> io::Result<()>) -> io::Result<bool> {
        let mut flags = self.flags();
        if flags.killed || flags.reaped {
            return Ok(false);
        }
        send()?;
        flags.killed = true;
        Ok(true)
    }

    /// Records that the worker is about to be reaped. The reaper calls it
    /// after its non-reaping wait returned and before the reaping wait.
    pub fn mark_reaped(&self) {
        self.flags().reaped = true;
    }

    /// True once the worker is (about to be) reaped.
    pub fn is_reaped(&self) -> bool {
        self.flags().reaped
    }

    /// Runs `look` with the flag lock held unless the worker is (about to be)
    /// reaped (`None`). While it runs the worker cannot be reaped, so its pid
    /// still names the worker (a zombie keeps its pid). `look` must not block
    /// (the macOS footprint reading, M8 Task 9).
    pub fn while_unreaped<T>(&self, look: impl FnOnce() -> T) -> Option<T> {
        let flags = self.flags();
        if flags.reaped {
            return None;
        }
        Some(look())
    }

    /// True once a kill was sent.
    pub fn is_killed(&self) -> bool {
        self.flags().killed
    }

    /// Runs one reap attempt with the flag lock held and marks the worker
    /// reaped when it reaped, or when the attempt shows that someone else
    /// reaped it ([`reaped_elsewhere`]). `try_reap` must not block
    /// (`waitpid(WNOHANG)`).
    pub fn reap_locked<T>(
        &self,
        try_reap: impl FnOnce() -> io::Result<Option<T>>,
    ) -> io::Result<Option<T>> {
        let mut flags = self.flags();
        let reaped = try_reap();
        match &reaped {
            Ok(Some(_)) => flags.reaped = true,
            Err(e) if reaped_elsewhere(e) => flags.reaped = true,
            _ => {}
        }
        reaped
    }
}

/// `ECHILD`: the worker is no longer our child. Something else reaped it
/// (`SIGCHLD` ignored, `SA_NOCLDWAIT`, a foreign `waitpid(-1)`), so its pid may
/// already name another process and must never be signalled again. This breaks
/// the sole-reaper precondition (see the module documentation); the reap that
/// sees it marks the guard and passes the error on.
pub fn reaped_elsewhere(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(libc::ECHILD)
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

/// The PD-137 reap: `wait_exited` blocks until the worker exited without
/// reaping it (no lock held), then the guard is marked, then `reap` collects
/// the exit status. A `wait_exited` that fails with [`reaped_elsewhere`] marks
/// the guard too.
pub fn reap_after_wait<T>(
    guard: &ReapGuard,
    wait_exited: impl FnOnce() -> io::Result<()>,
    reap: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    if let Err(e) = wait_exited() {
        if reaped_elsewhere(&e) {
            guard.mark_reaped();
        }
        return Err(e);
    }
    guard.mark_reaped();
    reap()
}

/// One kill through `primary`, and through `fallback` when `primary` fails
/// (I-2): Linux `pidfd_send_signal`, then the guarded `kill(pid)`; Windows
/// `TerminateJobObject`, then `TerminateProcess`. Both run under the caller's
/// guard lock and must not block, so nothing is logged here: when both fail,
/// the error (the fallback's kind, both messages) goes to the caller, which
/// logs it after the lock is released.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) fn signal_or_fallback(
    primary: impl FnOnce() -> io::Result<()>,
    fallback: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    match primary() {
        Ok(()) => Ok(()),
        Err(first) => fallback().map_err(|second| {
            io::Error::new(
                second.kind(),
                format!("{first}; the fallback failed too: {second}"),
            )
        }),
    }
}

/// The fallback reap: one [`ReapGuard::reap_locked`] attempt every `poll`
/// until it reaps (`Some`), fails, or `deadline` passes (`None`; no deadline
/// polls until the worker is reaped).
pub fn reap_polling_until<T>(
    guard: &ReapGuard,
    mut try_reap: impl FnMut() -> io::Result<Option<T>>,
    poll: Duration,
    deadline: Option<Instant>,
) -> io::Result<Option<T>> {
    loop {
        if let Some(exit) = guard.reap_locked(&mut try_reap)? {
            return Ok(Some(exit));
        }
        let pause = match deadline {
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Ok(None);
                }
                left.min(poll)
            }
            None => poll,
        };
        thread::sleep(pause);
    }
}

/// The OS call of a [`GuardedKill`].
type Signal = Box<dyn Fn() -> io::Result<()> + Send + Sync>;

/// A [`KillHandle`] that sends one non-blocking signal under a [`ReapGuard`].
pub struct GuardedKill {
    guard: Arc<ReapGuard>,
    signal: Signal,
}

impl GuardedKill {
    /// `signal` is an OS call that cannot fail (it must not block); it runs at
    /// most once, and never after the guard is marked reaped.
    pub fn new(guard: Arc<ReapGuard>, signal: impl Fn() + Send + Sync + 'static) -> GuardedKill {
        GuardedKill::fallible(guard, move || {
            signal();
            Ok(())
        })
    }

    /// `signal` is the OS call (it must not block). It reports success also
    /// when the worker had already exited (`ESRCH`, a zombie, an empty job).
    /// It runs until it succeeds once, and never after the guard is marked
    /// reaped.
    pub fn fallible(
        guard: Arc<ReapGuard>,
        signal: impl Fn() -> io::Result<()> + Send + Sync + 'static,
    ) -> GuardedKill {
        GuardedKill {
            guard,
            signal: Box::new(signal),
        }
    }

    /// The guard this handle shares with its reaper.
    pub fn guard(&self) -> &Arc<ReapGuard> {
        &self.guard
    }

    /// [`KillHandle::kill`] with its outcome: `Ok(true)` the signal was sent,
    /// `Ok(false)` nothing to do (already killed or reaped), `Err` the OS call
    /// failed and the next kill tries again.
    pub fn try_kill(&self) -> io::Result<bool> {
        self.guard.try_kill_with(|| (self.signal)())
    }
}

impl KillHandle for GuardedKill {
    fn kill(&self) {
        if let Err(e) = self.try_kill() {
            eprintln!("sandbox worker kill failed ({e}); the next kill tries again");
        }
    }
}

impl std::fmt::Debug for GuardedKill {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardedKill")
            .field("guard", &self.guard)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kill_after_the_mark_sends_nothing_and_the_mark_survives_a_kill() {
        let guard = ReapGuard::new();
        assert!(guard.kill_with(|| {}));
        assert!(guard.is_killed());
        assert!(!guard.kill_with(|| {}), "second kill");
        guard.mark_reaped();
        assert!(guard.is_reaped());

        let reaped = ReapGuard::new();
        reaped.mark_reaped();
        let mut ran = false;
        assert!(!reaped.kill_with(|| ran = true));
        assert!(!ran);
        assert!(!reaped.is_killed());
    }

    #[test]
    fn a_look_runs_only_before_the_reap() {
        let guard = ReapGuard::new();
        assert_eq!(guard.while_unreaped(|| 7), Some(7));
        assert!(guard.kill_with(|| {}));
        assert_eq!(guard.while_unreaped(|| 8), Some(8), "killed is not reaped");
        guard.mark_reaped();
        let mut ran = false;
        assert_eq!(guard.while_unreaped(|| ran = true), None);
        assert!(!ran);
    }

    #[test]
    fn reap_after_wait_marks_between_the_two_waits() {
        let guard = ReapGuard::new();
        let exit = reap_after_wait(
            &guard,
            || {
                assert!(!guard.is_reaped(), "not marked before the wait returned");
                Ok(())
            },
            || {
                assert!(guard.is_reaped(), "marked before the reap");
                Ok(7)
            },
        );
        assert_eq!(exit.ok(), Some(7));
    }

    #[test]
    fn a_failed_signal_leaves_the_handle_armed() {
        let guard = ReapGuard::new();
        let calls = std::sync::atomic::AtomicU32::new(0);
        let attempt = || {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        };
        assert_eq!(
            guard.try_kill_with(attempt).err().map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert!(!guard.is_killed(), "a failed call is not a kill");
        assert_eq!(guard.try_kill_with(attempt).ok(), Some(true), "retried");
        assert!(guard.is_killed());
        assert_eq!(guard.try_kill_with(attempt).ok(), Some(false), "no-op now");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn the_fallback_runs_only_when_the_primary_call_fails() {
        let ran = std::cell::Cell::new(0);
        let ok = signal_or_fallback(
            || Ok(()),
            || {
                ran.set(ran.get() + 1);
                Ok(())
            },
        );
        assert!(ok.is_ok());
        assert_eq!(ran.get(), 0);
        let ok = signal_or_fallback(
            || Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            || {
                ran.set(ran.get() + 1);
                Ok(())
            },
        );
        assert!(ok.is_ok());
        assert_eq!(ran.get(), 1);
        let both = signal_or_fallback(
            || Err(io::Error::other("pidfd call refused")),
            || {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pid call refused",
                ))
            },
        )
        .err();
        assert_eq!(
            both.as_ref().map(io::Error::kind),
            Some(io::ErrorKind::InvalidInput)
        );
        let text = both.map(|e| e.to_string()).unwrap_or_default();
        assert!(
            text.contains("pidfd call refused") && text.contains("pid call refused"),
            "{text}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn echild_marks_the_guard_so_no_later_kill_signals() {
        let echild = || io::Error::from_raw_os_error(libc::ECHILD);
        // the polling reap
        let guard = ReapGuard::new();
        let signals = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counted = Arc::clone(&signals);
        let kill = GuardedKill::new(Arc::clone(&guard), move || {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        let err = reap_polling_until(
            &guard,
            || Err::<Option<i32>, _>(echild()),
            Duration::from_millis(1),
            None,
        )
        .err();
        assert!(err.as_ref().is_some_and(reaped_elsewhere), "{err:?}");
        assert!(guard.is_reaped());
        kill.kill();
        assert_eq!(signals.load(std::sync::atomic::Ordering::SeqCst), 0);
        // the waitid reap
        let guard = ReapGuard::new();
        let exit = reap_after_wait(&guard, || Err(echild()), || Ok(0));
        assert!(exit.is_err());
        assert!(guard.is_reaped());
        // any other error leaves the worker unreaped (and killable)
        let guard = ReapGuard::new();
        let other = || io::Error::from_raw_os_error(libc::EINVAL);
        assert!(
            guard
                .reap_locked(|| Err::<Option<i32>, _>(other()))
                .is_err()
        );
        assert!(reap_after_wait(&guard, || Err(other()), || Ok(0)).is_err());
        assert!(!guard.is_reaped());
    }

    #[test]
    fn a_failed_wait_does_not_mark() {
        let guard = ReapGuard::new();
        let exit = reap_after_wait(
            &guard,
            || Err(io::Error::from(io::ErrorKind::InvalidInput)),
            || Ok(0),
        );
        assert_eq!(
            exit.err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
        assert!(!guard.is_reaped());
    }
}
