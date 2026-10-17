//! Host-measured limits (§9.4, §9.5, PD-134): which verdict a run's end gets from what the host
//! itself observed, and the seam through which a spawner lets the host watch a worker's memory.
//!
//! §9.5: `script_limit` comes "only for limits the host itself measured (its timer and counters,
//! the job-object/rlimit/watchdog kill reason, host-decided OOM)". The facts per OS:
//! - `timeout_s`: the bridge's run timer (PD-135), a [`HostCause`].
//! - `process_mb`: Windows the job's `JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT` on its completion port
//!   ([`OsMemorySignal::JobMemoryLimit`]); macOS the footprint watchdog's kill
//!   ([`OsMemorySignal::WatchdogKill`], [`crate::watchdog`]); Linux the worker's exit code
//!   `EXIT_PROCESS_LIMIT` under `RLIMIT_AS` (no Linux watchdog, R3). On Windows the worker also
//!   exits `EXIT_PROCESS_LIMIT` when the job refuses an allocation.
//! - `heap_mb`: the worker's exit code `EXIT_HEAP_LIMIT` (its QuickJS allocator refused).
//!
//! The two exit codes are worker-reported, but they come from a process exit the host observed;
//! they can make "direct" only a run that is neither queued nor dispatched, which holds no data
//! (PD-134).

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::io;

use atlas_duck_ipc::sandbox::{EXIT_HEAP_LIMIT, EXIT_PROCESS_LIMIT, EXIT_PROTOCOL};

use crate::bridge::{HostVerdict, KillCause, ViolationKind};
use crate::spawn::{ExitKind, KillHandle};

/// §9.4 limit name: the run timer.
pub const LIMIT_TIMEOUT_S: &str = "timeout_s";
/// §9.4 limit name: the QuickJS heap.
pub const LIMIT_HEAP_MB: &str = "heap_mb";
/// §9.4 limit name: the worker process's memory.
pub const LIMIT_PROCESS_MB: &str = "process_mb";

/// What the host itself did to end a run, first one wins (the bridge's run state records it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCause {
    /// The run timer (`timeout_s`, PD-135).
    Timeout,
    /// The bridge killed the worker for a channel violation.
    Violation(ViolationKind),
    /// The caller killed the run ([`crate::bridge::RunHandleImpl::kill`]).
    Killed(KillCause),
}

/// A memory-limit fact the OS gave the host about a worker (§9.4 `process_mb`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsMemorySignal {
    /// Windows: the worker's job posted `JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT` (or the job-wide
    /// `JOB_OBJECT_MSG_JOB_MEMORY_LIMIT`) to its completion port.
    JobMemoryLimit,
    /// macOS: the footprint watchdog saw `ri_phys_footprint` above `process_mb` and killed.
    WatchdogKill,
}

/// The host's verdict on a run's end (M8 Task 9, PD-134), by this precedence:
/// 1. a host cause (the timer, a channel violation, the caller's kill);
/// 2. an accepted terminal frame: no verdict, whatever the exit or a later OS report says;
/// 3. `EXIT_PROTOCOL` without a terminal frame: the worker could not read what the host sent, a
///    host fault (T4, T7 review I-2), checked before any limit;
/// 4. an OS memory report (the Windows job message, the macOS watchdog kill) → `process_mb`;
/// 5. `EXIT_HEAP_LIMIT` → `heap_mb`;
/// 6. `EXIT_PROCESS_LIMIT` → `process_mb`;
/// 7. a signal the host did not send (SIGSYS included) → `Crashed`, never a violation;
/// 8. any other exit without a terminal frame, 0 included, or an unknown exit (`None`, the reap
///    failed) → `Crashed`.
///
/// A host kill ends a worker with `Signal(SIGKILL)` (Unix) or `Code(1)` (Windows
/// `TerminateJobObject`); rule 1 comes first, so that exit is never read as a crash.
pub fn attribute(
    exit: Option<ExitKind>,
    host_cause: Option<&HostCause>,
    os_signal: Option<OsMemorySignal>,
    terminal_accepted: bool,
) -> HostVerdict {
    match host_cause {
        Some(HostCause::Timeout) => return HostVerdict::Limit(LIMIT_TIMEOUT_S),
        Some(HostCause::Violation(kind)) => return HostVerdict::Violation(*kind),
        Some(HostCause::Killed(cause)) => return HostVerdict::Killed(cause.clone()),
        None => {}
    }
    if terminal_accepted {
        return HostVerdict::None;
    }
    if exit == Some(ExitKind::Code(EXIT_PROTOCOL)) {
        return HostVerdict::HostFault;
    }
    if os_signal.is_some() {
        return HostVerdict::Limit(LIMIT_PROCESS_MB);
    }
    match exit {
        Some(ExitKind::Code(EXIT_HEAP_LIMIT)) => HostVerdict::Limit(LIMIT_HEAP_MB),
        Some(ExitKind::Code(EXIT_PROCESS_LIMIT)) => HostVerdict::Limit(LIMIT_PROCESS_MB),
        other => HostVerdict::Crashed(other),
    }
}

/// How a spawner lets the host watch one split worker's memory (§9.4 `process_mb`): Windows the
/// job's completion port, macOS the footprint watchdog. Linux has none (`RLIMIT_AS` makes the
/// worker exit `EXIT_PROCESS_LIMIT`; R3). See [`crate::spawn::WorkerProcess::memory_watch`].
///
/// The bridge takes the [`MemoryWatch::stopper`], runs [`MemoryWatch::run`] on a thread of its
/// own, and calls the stopper once the worker is reaped.
pub trait MemoryWatch: Send {
    /// The fact this watch reports.
    fn signal(&self) -> OsMemorySignal;

    /// The handle that makes [`MemoryWatch::run`] return. Taken once, before `run`; dropping it
    /// without a call stops the watch too.
    fn stopper(&mut self) -> Box<dyn FnOnce() + Send>;

    /// Blocks until stopped or until the worker is gone. Each time the OS reports the worker
    /// above `process_mb`, it calls `limit.kill()` (the bridge records the fact, then kills).
    /// An OS report the watch received before the stop is acted on before it returns.
    /// `Err` when the watch could not observe the worker at all (the bridge logs a diag).
    fn run(self: Box<Self>, limit: &dyn KillHandle) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(
        exit: Option<ExitKind>,
        cause: Option<HostCause>,
        signal: Option<OsMemorySignal>,
        terminal: bool,
    ) -> HostVerdict {
        attribute(exit, cause.as_ref(), signal, terminal)
    }

    #[test]
    fn exit_code_maps_to_heap_or_process_limit() {
        let heap = Some(ExitKind::Code(EXIT_HEAP_LIMIT));
        let process = Some(ExitKind::Code(EXIT_PROCESS_LIMIT));
        assert_eq!(
            verdict(heap, None, None, false),
            HostVerdict::Limit("heap_mb")
        );
        assert_eq!(
            verdict(process, None, None, false),
            HostVerdict::Limit("process_mb")
        );
        // The OS reports win over the exit code; both mean process_mb on their own.
        for signal in [OsMemorySignal::JobMemoryLimit, OsMemorySignal::WatchdogKill] {
            assert_eq!(
                verdict(heap, None, Some(signal), false),
                HostVerdict::Limit("process_mb"),
                "{signal:?}"
            );
            // A watchdog or job kill ends the worker with SIGKILL / Code(1).
            for exit in [ExitKind::Signal(9), ExitKind::Code(1)] {
                assert_eq!(
                    verdict(Some(exit), None, Some(signal), false),
                    HostVerdict::Limit("process_mb"),
                    "{signal:?} {exit:?}"
                );
            }
            assert_eq!(
                verdict(None, None, Some(signal), false),
                HostVerdict::Limit("process_mb"),
                "a lost exit status does not hide the OS report"
            );
        }
    }

    #[test]
    fn sigsys_is_crashed_never_violation() {
        // SIGSYS is 31 on Linux x86_64/aarch64, 12 on macOS: both are signals the host did not
        // send, so both are crashes (go/no-go T17 note), never an attack verdict.
        for sig in [31, 12, 11, 6] {
            assert_eq!(
                verdict(Some(ExitKind::Signal(sig)), None, None, false),
                HostVerdict::Crashed(Some(ExitKind::Signal(sig))),
                "signal {sig}"
            );
        }
    }

    #[test]
    fn host_kill_reason_wins() {
        let causes = [
            (HostCause::Timeout, HostVerdict::Limit("timeout_s")),
            (
                HostCause::Violation(ViolationKind::Oversize),
                HostVerdict::Violation(ViolationKind::Oversize),
            ),
            (
                HostCause::Killed(KillCause::User),
                HostVerdict::Killed(KillCause::User),
            ),
        ];
        let exits = [
            None,
            Some(ExitKind::Signal(9)),
            Some(ExitKind::Code(1)),
            Some(ExitKind::Code(EXIT_HEAP_LIMIT)),
            Some(ExitKind::Code(EXIT_PROCESS_LIMIT)),
            Some(ExitKind::Code(EXIT_PROTOCOL)),
        ];
        for (cause, want) in causes {
            for exit in exits {
                for signal in [None, Some(OsMemorySignal::WatchdogKill)] {
                    for terminal in [false, true] {
                        assert_eq!(
                            verdict(exit, Some(cause.clone()), signal, terminal),
                            want,
                            "{cause:?} {exit:?} {signal:?} terminal={terminal}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn exit_zero_without_terminal_is_crashed() {
        for code in [0, 1, 5, 101, -1] {
            assert_eq!(
                verdict(Some(ExitKind::Code(code)), None, None, false),
                HostVerdict::Crashed(Some(ExitKind::Code(code))),
                "exit {code}"
            );
        }
        assert_eq!(verdict(None, None, None, false), HostVerdict::Crashed(None));
    }

    #[test]
    fn exit_after_accepted_terminal_is_ignored() {
        let exits = [
            None,
            Some(ExitKind::Code(0)),
            Some(ExitKind::Code(EXIT_HEAP_LIMIT)),
            Some(ExitKind::Code(EXIT_PROCESS_LIMIT)),
            Some(ExitKind::Code(EXIT_PROTOCOL)),
            Some(ExitKind::Signal(9)),
            Some(ExitKind::Signal(31)),
        ];
        for exit in exits {
            for signal in [
                None,
                Some(OsMemorySignal::JobMemoryLimit),
                Some(OsMemorySignal::WatchdogKill),
            ] {
                assert_eq!(
                    verdict(exit, None, signal, true),
                    HostVerdict::None,
                    "{exit:?} {signal:?}"
                );
            }
        }
    }

    #[test]
    fn exit_protocol_is_a_host_fault_before_any_limit() {
        let protocol = Some(ExitKind::Code(EXIT_PROTOCOL));
        assert_eq!(verdict(protocol, None, None, false), HostVerdict::HostFault);
        assert_eq!(
            verdict(protocol, None, Some(OsMemorySignal::JobMemoryLimit), false),
            HostVerdict::HostFault
        );
    }
}
