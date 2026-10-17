//! The macOS footprint reader of the memory watchdog (M8 Task 9, §9.4 `process_mb`: "macOS
//! host-side watchdog (polls `proc_pid_rusage` `ri_phys_footprint` every 100 ms, SIGKILL above
//! the limit; `RLIMIT_AS` is not enforced on Darwin)"). The poll loop is OS-independent
//! ([`crate::watchdog`]); this module holds only the reading and the [`MemoryWatch`] that runs it.
//!
//! The reading is taken under the worker's reap guard: while it runs the worker cannot be
//! reaped, so the pid still names the worker (a zombie keeps its pid), and once the worker is
//! reaped nothing is read and the watchdog ends. A recycled pid is never read or signalled (the
//! kill goes through the guarded kill handle too).

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::io;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};

use crate::kill::ReapGuard;
use crate::limits::{MemoryWatch, OsMemorySignal};
use crate::spawn::KillHandle;
use crate::watchdog::{self, FootprintReader};

/// `proc_pid_rusage(pid, RUSAGE_INFO_V2)` → `ri_phys_footprint`, under the reap guard.
pub(crate) struct ProcFootprint {
    pid: libc::pid_t,
    guard: Arc<ReapGuard>,
}

impl ProcFootprint {
    pub(crate) fn new(pid: libc::pid_t, guard: Arc<ReapGuard>) -> ProcFootprint {
        ProcFootprint { pid, guard }
    }
}

/// One `proc_pid_rusage` call: the physical footprint of `pid` in bytes.
fn phys_footprint(pid: libc::pid_t) -> io::Result<u64> {
    // SAFETY: an all-zero `rusage_info_v2` (plain integers and a byte array) is a valid value.
    let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a writable `rusage_info_v2`, the structure `RUSAGE_INFO_V2` fills. The
    // libc binding types the buffer as `*mut rusage_info_t` (`rusage_info_t` is `*mut c_void`),
    // mirroring Apple's header, where callers pass their structure's address cast that way; the
    // kernel writes `size_of::<rusage_info_v2>()` bytes into it. The call does not block.
    let rc = unsafe {
        libc::proc_pid_rusage(
            pid,
            libc::RUSAGE_INFO_V2,
            (&mut info as *mut libc::rusage_info_v2).cast::<libc::rusage_info_t>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.ri_phys_footprint)
}

impl FootprintReader for ProcFootprint {
    fn footprint(&self) -> io::Result<Option<u64>> {
        let pid = self.pid;
        self.guard
            .while_unreaped(|| phys_footprint(pid))
            .transpose()
    }
}

/// The watchdog of one split worker ([`MemoryWatch`]): [`watchdog::run`] over its footprint, with
/// `process_mb` as the limit.
pub(crate) struct FootprintWatch {
    reader: ProcFootprint,
    limit_bytes: u64,
    stop_rx: Receiver<()>,
    stop_tx: Option<Sender<()>>,
}

impl FootprintWatch {
    pub(crate) fn new(pid: libc::pid_t, guard: Arc<ReapGuard>, process_mb: u32) -> FootprintWatch {
        let (stop_tx, stop_rx) = mpsc::channel();
        FootprintWatch {
            reader: ProcFootprint::new(pid, guard),
            limit_bytes: u64::from(process_mb) * 1024 * 1024,
            stop_rx,
            stop_tx: Some(stop_tx),
        }
    }
}

impl MemoryWatch for FootprintWatch {
    fn signal(&self) -> OsMemorySignal {
        OsMemorySignal::WatchdogKill
    }

    fn stopper(&mut self) -> Box<dyn FnOnce() + Send> {
        let tx = self.stop_tx.take();
        Box::new(move || {
            if let Some(tx) = tx {
                let _ = tx.send(());
            }
        })
    }

    fn run(self: Box<Self>, limit: &dyn KillHandle) -> io::Result<()> {
        let end = watchdog::run(&self.reader, limit, self.limit_bytes, &self.stop_rx);
        if end.readings == 0 && end.failed > 0 {
            return Err(io::Error::other(
                "the watchdog never read the worker's footprint",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_reads_its_own_footprint_and_nothing_after_the_reap() {
        // The test process itself stands in for a worker (no process is spawned).
        let me = std::process::id() as libc::pid_t;
        let guard = ReapGuard::new();
        let reader = ProcFootprint::new(me, Arc::clone(&guard));
        let bytes = reader.footprint().ok().flatten();
        assert!(bytes.is_some_and(|b| b > 0), "{bytes:?}");
        guard.mark_reaped();
        assert_eq!(reader.footprint().ok(), Some(None));
    }
}
