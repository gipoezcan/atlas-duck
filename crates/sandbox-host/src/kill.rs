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
    /// killed or reaped. `send` must not block. Returns whether it ran.
    pub fn kill_with(&self, send: impl FnOnce()) -> bool {
        let mut flags = self.flags();
        if flags.killed || flags.reaped {
            return false;
        }
        flags.killed = true;
        send();
        true
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

    /// True once a kill was sent.
    pub fn is_killed(&self) -> bool {
        self.flags().killed
    }

    /// Runs one reap attempt with the flag lock held and marks the worker
    /// reaped when it reaped. `try_reap` must not block (`waitpid(WNOHANG)`).
    pub fn reap_locked<T>(
        &self,
        try_reap: impl FnOnce() -> io::Result<Option<T>>,
    ) -> io::Result<Option<T>> {
        let mut flags = self.flags();
        let reaped = try_reap();
        if matches!(reaped, Ok(Some(_))) {
            flags.reaped = true;
        }
        reaped
    }
}

/// The PD-137 reap: `wait_exited` blocks until the worker exited without
/// reaping it (no lock held), then the guard is marked, then `reap` collects
/// the exit status.
pub fn reap_after_wait<T>(
    guard: &ReapGuard,
    wait_exited: impl FnOnce() -> io::Result<()>,
    reap: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    wait_exited()?;
    guard.mark_reaped();
    reap()
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

/// A [`KillHandle`] that sends one non-blocking signal under a [`ReapGuard`].
pub struct GuardedKill {
    guard: Arc<ReapGuard>,
    signal: Box<dyn Fn() + Send + Sync>,
}

impl GuardedKill {
    /// `signal` is the OS call (it must not block); it runs at most once, and
    /// never after the guard is marked reaped.
    pub fn new(guard: Arc<ReapGuard>, signal: impl Fn() + Send + Sync + 'static) -> GuardedKill {
        GuardedKill {
            guard,
            signal: Box::new(signal),
        }
    }

    /// The guard this handle shares with its reaper.
    pub fn guard(&self) -> &Arc<ReapGuard> {
        &self.guard
    }
}

impl KillHandle for GuardedKill {
    fn kill(&self) {
        self.guard.kill_with(|| (self.signal)());
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
