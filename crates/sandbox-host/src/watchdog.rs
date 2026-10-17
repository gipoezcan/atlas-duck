//! The host-side memory watchdog's poll loop (§9.4 `process_mb` on macOS: "polls
//! `proc_pid_rusage` `ri_phys_footprint` every 100 ms, SIGKILL above the limit; `RLIMIT_AS` is not
//! enforced on Darwin"). OS-independent: it reads through a [`FootprintReader`] and kills through
//! a [`KillHandle`], so it is tested with fakes on every OS. Only macOS supplies a reader
//! (`crate::macos` `watchdog`); Linux has no watchdog (R3).

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

use std::io;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use crate::spawn::KillHandle;

/// §9.4: the watchdog polls every 100 ms.
pub const POLL: Duration = Duration::from_millis(100);

/// Reads one worker's memory footprint.
pub trait FootprintReader {
    /// The footprint in bytes; `Ok(None)` once the worker is reaped (its pid may name another
    /// process then, so nothing is read).
    fn footprint(&self) -> io::Result<Option<u64>>;
}

/// What a watchdog run saw.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WatchdogEnd {
    /// Readings above the limit, each followed by a kill (a kill after one that took is a no-op
    /// of the [`KillHandle`]; one that failed is retried this way).
    pub kills: u32,
    /// Successful readings.
    pub readings: u64,
    /// Readings that failed.
    pub failed: u64,
}

/// [`run_every`] at the §9.4 interval ([`POLL`]).
pub fn run(
    reader: &dyn FootprintReader,
    kill: &dyn KillHandle,
    limit_bytes: u64,
    stop: &Receiver<()>,
) -> WatchdogEnd {
    run_every(reader, kill, limit_bytes, stop, POLL)
}

/// Reads the footprint at once and then every `poll`; above `limit_bytes` it kills. It returns
/// when `stop` receives or its sender is gone (the bridge stops it at the reap), or when the
/// reader reports the worker reaped. A failed reading is counted and the poll goes on: it never
/// kills.
pub fn run_every(
    reader: &dyn FootprintReader,
    kill: &dyn KillHandle,
    limit_bytes: u64,
    stop: &Receiver<()>,
    poll: Duration,
) -> WatchdogEnd {
    let mut end = WatchdogEnd::default();
    loop {
        match reader.footprint() {
            Ok(Some(bytes)) => {
                end.readings += 1;
                if bytes > limit_bytes {
                    end.kills += 1;
                    kill.kill();
                }
            }
            Ok(None) => return end,
            Err(_) => end.failed += 1,
        }
        match stop.recv_timeout(poll) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return end,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::mpsc;
    use std::time::Instant;

    use super::*;

    /// Plays a list of readings; past its end it reports the worker reaped. Records how many
    /// readings were taken when each kill came.
    struct Script {
        readings: Mutex<Vec<io::Result<Option<u64>>>>,
        taken: Mutex<u32>,
        kills_at: Mutex<Vec<u32>>,
    }

    impl Script {
        fn new(readings: Vec<io::Result<Option<u64>>>) -> Script {
            Script {
                readings: Mutex::new(readings.into_iter().rev().collect()),
                taken: Mutex::new(0),
                kills_at: Mutex::new(Vec::new()),
            }
        }

        fn taken(&self) -> u32 {
            self.taken.lock().map(|t| *t).unwrap_or(0)
        }

        fn kills_at(&self) -> Vec<u32> {
            self.kills_at.lock().map(|k| k.clone()).unwrap_or_default()
        }
    }

    impl FootprintReader for Script {
        fn footprint(&self) -> io::Result<Option<u64>> {
            if let Ok(mut t) = self.taken.lock() {
                *t += 1;
            }
            self.readings
                .lock()
                .map_err(|_| io::Error::other("poisoned"))?
                .pop()
                .unwrap_or(Ok(None))
        }
    }

    struct Kill<'a>(&'a Script);

    impl KillHandle for Kill<'_> {
        fn kill(&self) {
            let taken = self.0.taken();
            if let Ok(mut k) = self.0.kills_at.lock() {
                k.push(taken);
            }
        }
    }

    const MB: u64 = 1024 * 1024;

    #[test]
    fn watchdog_kills_above_limit_after_poll() {
        // At the limit is not above it; the first reading above it kills, and every later one
        // kills again (a no-op once a kill took). A failed reading never kills.
        let script = Script::new(vec![
            Ok(Some(100 * MB)),
            Err(io::Error::other("busy")),
            Ok(Some(200 * MB)),
            Ok(Some(200 * MB + 1)),
            Ok(Some(300 * MB)),
            Ok(None),
        ]);
        let (_tx, stop) = mpsc::channel();
        let end = run_every(
            &script,
            &Kill(&script),
            200 * MB,
            &stop,
            Duration::from_millis(1),
        );
        assert_eq!(
            script.kills_at(),
            vec![4, 5],
            "killed after readings 4 and 5"
        );
        assert_eq!(
            end,
            WatchdogEnd {
                kills: 2,
                readings: 4,
                failed: 1
            }
        );
        assert_eq!(script.taken(), 6, "the reaped answer ends the poll");
    }

    #[test]
    fn watchdog_stops_at_reap() {
        // The stop (sent at the reap) ends the wait at once, however long the poll interval.
        let script = Script::new((0..1000).map(|_| Ok(Some(MB))).collect());
        let (tx, stop) = mpsc::channel();
        let poll = Duration::from_secs(3600);
        let started = Instant::now();
        let waiter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            let _ = tx.send(());
        });
        let end = run_every(&script, &Kill(&script), 200 * MB, &stop, poll);
        assert!(started.elapsed() < Duration::from_secs(60));
        assert_eq!(end.readings, 1, "one reading, then the stop");
        assert_eq!(end.kills, 0);
        assert!(waiter.join().is_ok());

        // A dropped sender stops it too (the bridge's stopper dropped without a call).
        let (tx, stop) = mpsc::channel::<()>();
        drop(tx);
        let end = run_every(&script, &Kill(&script), 200 * MB, &stop, poll);
        assert_eq!(end.readings, 1);

        // And the reader's "reaped" answer ends it before any wait.
        let reaped = Script::new(vec![Ok(None)]);
        let (_tx, stop) = mpsc::channel();
        let end = run_every(&reaped, &Kill(&reaped), 200 * MB, &stop, poll);
        assert_eq!(end, WatchdogEnd::default());
        assert!(reaped.kills_at().is_empty());
    }
}
