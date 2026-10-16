//! M8 Task 6 (Δ2 first half, PD-137, M3 final review M-1): the worker split into I/O, a kill
//! handle and a reaper, with fakes only (no process is spawned).
//!
//! The kill handles of the real spawners are [`GuardedKill`]s over one OS call each
//! (`TerminateJobObject`, `pidfd_send_signal`, `kill(2)`), and their reapers follow the
//! [`ReapGuard`] protocol. The fakes below build their parts from the same crate types with a
//! recording signal, so these tests pin the protocol itself; the real calls run in CI
//! (`app/src-tauri/tests/sandbox_runs.rs`).

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use atlas_duck_sandbox_host::kill::{GuardedKill, ReapGuard, reap_after_wait, reap_polling_until};
use atlas_duck_sandbox_host::spawn::{
    ExitKind, KillHandle, Reaper, WorkerIo, WorkerParts, WorkerProcess,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The plan bound for a kill that must not block.
const KILL_BOUND: Duration = Duration::from_millis(50);

/// Counts the signals a kill handle sent.
#[derive(Default)]
struct Signals(AtomicU32);

impl Signals {
    fn sent(&self) -> u32 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A reaper whose "wait without reaping" blocks until the test sends the exit code, holding no
/// lock while it blocks (the `waitid(WNOWAIT)` / `WaitForSingleObject` step).
struct FakeReaper {
    guard: Arc<ReapGuard>,
    exit: Receiver<i32>,
}

impl Reaper for FakeReaper {
    fn wait(self: Box<Self>) -> io::Result<ExitKind> {
        let exit = &self.exit;
        let code = Cell::new(None);
        reap_after_wait(
            &self.guard,
            || {
                code.set(Some(exit.recv().map_err(|_| io::Error::other("no exit"))?));
                Ok(())
            },
            || {
                code.get()
                    .map(ExitKind::Code)
                    .ok_or_else(|| io::Error::other("no code"))
            },
        )
    }
}

/// A worker whose pipes are in-memory pipes and whose "process" ends when the test says so.
struct FakeProcess {
    stdin: io::PipeWriter,
    stdout: io::PipeReader,
    stderr: io::PipeReader,
    signals: Arc<Signals>,
    exit: Receiver<i32>,
}

/// The test's ends of a [`FakeProcess`].
struct FakeEnds {
    /// Feeds the worker's stdout (kept open so a read of it blocks).
    stdout_w: io::PipeWriter,
    _stderr_w: io::PipeWriter,
    _stdin_r: io::PipeReader,
    exit: Sender<i32>,
    signals: Arc<Signals>,
}

fn fake() -> io::Result<(Box<dyn WorkerProcess>, FakeEnds)> {
    let (stdin_r, stdin_w) = io::pipe()?;
    let (stdout_r, stdout_w) = io::pipe()?;
    let (stderr_r, stderr_w) = io::pipe()?;
    let (exit_tx, exit_rx) = mpsc::channel();
    let signals = Arc::new(Signals::default());
    let process = FakeProcess {
        stdin: stdin_w,
        stdout: stdout_r,
        stderr: stderr_r,
        signals: Arc::clone(&signals),
        exit: exit_rx,
    };
    Ok((
        Box::new(process),
        FakeEnds {
            stdout_w,
            _stderr_w: stderr_w,
            _stdin_r: stdin_r,
            exit: exit_tx,
            signals,
        },
    ))
}

impl WorkerProcess for FakeProcess {
    fn pid(&self) -> u32 {
        4242
    }

    fn stdin(&mut self) -> &mut dyn Write {
        &mut self.stdin
    }

    fn read_frame_timeout(&mut self, _max: usize, _d: Duration) -> io::Result<Option<Vec<u8>>> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn close_stdin(&mut self) {}

    fn wait_timeout(&mut self, _d: Duration) -> io::Result<Option<ExitKind>> {
        Ok(None)
    }

    fn kill(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn into_parts(self: Box<Self>) -> io::Result<WorkerParts> {
        let guard = ReapGuard::new();
        let signals = Arc::clone(&self.signals);
        let kill = GuardedKill::new(Arc::clone(&guard), move || {
            signals.0.fetch_add(1, Ordering::SeqCst);
        });
        Ok(WorkerParts {
            pid: 4242,
            io: WorkerIo {
                stdin: Box::new(self.stdin),
                stdout: Box::new(self.stdout),
                stderr: Box::new(self.stderr),
            },
            kill: Arc::new(kill),
            reaper: Box::new(FakeReaper {
                guard,
                exit: self.exit,
            }),
        })
    }
}

#[test]
fn kill_never_blocks_while_reader_holds_its_lock() -> TestResult {
    let (process, mut ends) = fake()?;
    let parts = process.into_parts()?;
    let kill = Arc::clone(&parts.kill);

    // The reader thread takes the worker's I/O mutex and blocks in a read inside it; the reaper
    // thread blocks in its wait. Neither may stop a kill.
    let io = Arc::new(Mutex::new(parts.io));
    let (locked_tx, locked_rx) = mpsc::channel();
    let reader = {
        let io = Arc::clone(&io);
        thread::spawn(move || -> io::Result<usize> {
            let mut io = io.lock().map_err(|_| io::Error::other("poisoned"))?;
            let _ = locked_tx.send(());
            let mut byte = [0u8; 1];
            io.stdout.read(&mut byte)
        })
    };
    let reaper = thread::spawn(move || parts.reaper.wait());
    locked_rx.recv_timeout(Duration::from_secs(5))?;
    assert!(io.try_lock().is_err(), "the reader holds the I/O lock");

    let started = Instant::now();
    kill.kill();
    let took = started.elapsed();
    assert!(took < KILL_BOUND, "kill took {took:?}");
    assert_eq!(ends.signals.sent(), 1, "the kill reached the worker");

    // Let both threads finish.
    ends.stdout_w.write_all(b"x")?;
    assert_eq!(reader.join().map_err(|_| "reader panicked")??, 1);
    ends.exit.send(137)?;
    assert_eq!(
        reaper.join().map_err(|_| "reaper panicked")??,
        ExitKind::Code(137)
    );
    Ok(())
}

#[test]
fn kill_after_reap_is_noop() -> TestResult {
    let (process, ends) = fake()?;
    let parts = process.into_parts()?;
    ends.exit.send(0)?;
    assert_eq!(parts.reaper.wait()?, ExitKind::Code(0));
    let started = Instant::now();
    parts.kill.kill();
    assert!(started.elapsed() < KILL_BOUND);
    assert_eq!(ends.signals.sent(), 0, "no signal after the reap");

    // The polling fallback marks the worker reaped in the same lock as the reap.
    let guard = ReapGuard::new();
    let signals = Arc::new(Signals::default());
    let counted = Arc::clone(&signals);
    let kill = GuardedKill::new(Arc::clone(&guard), move || {
        counted.0.fetch_add(1, Ordering::SeqCst);
    });
    let mut polls = 0;
    let exit = reap_polling_until(
        &guard,
        || {
            polls += 1;
            Ok((polls == 3).then_some(ExitKind::Code(5)))
        },
        Duration::from_millis(1),
        None,
    )?;
    assert_eq!(exit, Some(ExitKind::Code(5)));
    assert!(guard.is_reaped());
    kill.kill();
    assert_eq!(signals.sent(), 0);
    Ok(())
}

#[test]
fn kill_is_idempotent() -> TestResult {
    let (process, ends) = fake()?;
    let parts = process.into_parts()?;
    parts.kill.kill();
    parts.kill.kill();
    // and from several threads at once
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let kill = Arc::clone(&parts.kill);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                kill.kill();
            })
        })
        .collect();
    for t in threads {
        t.join().map_err(|_| "kill thread panicked")?;
    }
    assert_eq!(ends.signals.sent(), 1);
    ends.exit.send(9)?;
    assert_eq!(parts.reaper.wait()?, ExitKind::Code(9));
    Ok(())
}

#[test]
fn a_kill_racing_a_polling_reap_never_signals_after_it() -> TestResult {
    // The guarded-pid fallback (PD-137): the reap attempt runs inside the flag lock, so a kill that
    // starts while it runs waits for it and then sees `reaped`.
    let guard = ReapGuard::new();
    let signals = Arc::new(Signals::default());
    let counted = Arc::clone(&signals);
    let kill = Arc::new(GuardedKill::new(Arc::clone(&guard), move || {
        counted.0.fetch_add(1, Ordering::SeqCst);
    }));
    let (inside_tx, inside_rx) = mpsc::channel();
    let killer = {
        let kill = Arc::clone(&kill);
        thread::spawn(move || {
            let _ = inside_rx.recv();
            kill.kill();
        })
    };
    let exit = reap_polling_until(
        &guard,
        || {
            let _ = inside_tx.send(());
            // the killer is now blocked on the flag lock
            thread::sleep(Duration::from_millis(30));
            Ok(Some(ExitKind::Signal(9)))
        },
        Duration::from_millis(1),
        None,
    )?;
    killer.join().map_err(|_| "killer panicked")?;
    assert_eq!(exit, Some(ExitKind::Signal(9)));
    assert_eq!(signals.sent(), 0, "a signal reached a reaped worker");
    Ok(())
}

#[test]
fn a_polling_reap_gives_up_at_its_deadline() -> TestResult {
    let guard = ReapGuard::new();
    let started = Instant::now();
    let exit = reap_polling_until(
        &guard,
        || Ok(None::<ExitKind>),
        Duration::from_millis(5),
        Some(Instant::now() + Duration::from_millis(40)),
    )?;
    assert_eq!(exit, None);
    assert!(!guard.is_reaped());
    assert!(started.elapsed() < Duration::from_secs(2));
    Ok(())
}

#[test]
fn a_failed_reap_attempt_is_reported_and_leaves_the_worker_unreaped() -> TestResult {
    let guard = ReapGuard::new();
    let err = reap_polling_until(
        &guard,
        || Err::<Option<ExitKind>, _>(io::Error::from(io::ErrorKind::PermissionDenied)),
        Duration::from_millis(1),
        None,
    )
    .err()
    .ok_or("the error is passed on")?;
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(!guard.is_reaped());
    Ok(())
}

#[test]
fn the_default_into_parts_is_unsupported() {
    // Fakes of the probe runner keep compiling: only the real spawners split.
    struct ProbeOnly;
    impl WorkerProcess for ProbeOnly {
        fn pid(&self) -> u32 {
            1
        }
        fn stdin(&mut self) -> &mut dyn Write {
            unreachable_writer()
        }
        fn read_frame_timeout(&mut self, _: usize, _: Duration) -> io::Result<Option<Vec<u8>>> {
            Ok(None)
        }
        fn close_stdin(&mut self) {}
        fn wait_timeout(&mut self, _: Duration) -> io::Result<Option<ExitKind>> {
            Ok(None)
        }
        fn kill(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn unreachable_writer() -> &'static mut dyn Write {
        Box::leak(Box::new(io::sink()))
    }
    let p: Box<dyn WorkerProcess> = Box::new(ProbeOnly);
    assert_eq!(
        p.into_parts().err().map(|e| e.kind()),
        Some(io::ErrorKind::Unsupported)
    );
}
