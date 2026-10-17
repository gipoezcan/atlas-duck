//! The bridge's reading threads (§3.4 "the host always drains the worker's stdout and stderr").
//!
//! - stdout: one thread per worker, one frame at a time, from the ready frame to EOF. It reads the
//!   ready frame, hands it over, then waits for the bridge to tell it what the rest of the stream
//!   is for (a run's state machine, a compile reply) and keeps reading until EOF. When the bridge
//!   refuses the worker, the thread reads and discards to EOF, so the worker never blocks on a
//!   write while it is being killed.
//! - stderr: one thread per worker keeps the first [`super::STDERR_CAP`] bytes and reads and
//!   discards the rest until EOF.
//! - The reaper: one thread per worker blocks in [`Reaper::wait`] (T6: never dropped unwaited).
//! - A worker the bridge gave up on without a run timer (refused, compile done) gets a thread
//!   that kills it again until it is reaped ([`rekill_until_reaped`]).

use std::io::{self, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::Duration;

use atlas_duck_ipc::sandbox::WORKER_FRAME_MAX_BYTES;
use atlas_duck_ipc::sandbox::frame::{FrameError, read_frame};

use super::STDERR_CAP;
use crate::spawn::{ExitKind, KillHandle, Reaper};

/// The worker's stdout, as the reader thread holds it.
pub(crate) type Stdout = Box<dyn Read + Send>;

/// What the stdout thread does with the stream after the ready frame.
pub(crate) type Continuation = Box<dyn FnOnce(Stdout) + Send>;

/// One read from the worker's stdout.
#[derive(Debug)]
pub(crate) enum Frame {
    /// A whole frame's payload.
    Bytes(Vec<u8>),
    /// The header announced more than the cap; the body was not read and the stream is out of
    /// step from here on.
    TooLarge,
    /// EOF, a truncated frame or a read error: nothing more can be read.
    End,
}

/// How far a run's reader got (T9 review I-1), for the finisher's bounded wait for stdout's EOF:
/// a counter that moves with every read that returned bytes and every frame the reader finished
/// with, and whether the reader is inside a read right now. A reader that waits inside a read
/// while the counter stands still is stalled on the pipe; one outside a read is busy (decoding a
/// frame, in the glue's `log`).
#[derive(Debug, Default)]
pub(crate) struct Progress {
    ticks: AtomicU64,
    in_read: AtomicBool,
}

impl Progress {
    /// The reader moved on (bytes read, a frame finished).
    pub(crate) fn tick(&self) {
        self.ticks.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn ticks(&self) -> u64 {
        self.ticks.load(Ordering::SeqCst)
    }

    /// The reader is inside a read of the pipe.
    pub(crate) fn in_read(&self) -> bool {
        self.in_read.load(Ordering::SeqCst)
    }

    pub(crate) fn set_in_read(&self, in_read: bool) {
        self.in_read.store(in_read, Ordering::SeqCst);
    }
}

/// The worker's stdout, reporting each read to a [`Progress`].
pub(crate) struct Tracked {
    inner: Stdout,
    progress: Arc<Progress>,
}

impl Tracked {
    pub(crate) fn new(inner: Stdout, progress: Arc<Progress>) -> Tracked {
        Tracked { inner, progress }
    }
}

impl Read for Tracked {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.progress.set_in_read(true);
        let read = self.inner.read(buf);
        self.progress.set_in_read(false);
        if matches!(read, Ok(n) if n > 0) {
            self.progress.tick();
        }
        read
    }
}

/// Reads one frame of at most `cap` payload bytes.
pub(crate) fn next_frame(stdout: &mut Stdout, cap: usize) -> Frame {
    match read_frame(stdout, cap) {
        Ok(Some(bytes)) => Frame::Bytes(bytes),
        Err(FrameError::TooLarge { .. }) => Frame::TooLarge,
        Ok(None) | Err(FrameError::Truncated) | Err(FrameError::Io(_)) => Frame::End,
    }
}

/// Reads and discards until EOF (or a read error).
pub(crate) fn discard(mut stdout: Stdout) {
    let _ = io::copy(&mut stdout, &mut io::sink());
}

/// The stdout thread: reads the ready frame (at most 1 MiB) and sends it on the returned
/// receiver, then runs the continuation it is given, or discards to EOF when the sender of
/// continuations is dropped instead.
pub(crate) fn spawn_stdout(
    mut stdout: Stdout,
) -> io::Result<(Receiver<Frame>, SyncSender<Continuation>)> {
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (go_tx, go_rx) = mpsc::sync_channel::<Continuation>(1);
    thread::Builder::new()
        .name("sandbox-stdout".to_owned())
        .spawn(move || {
            let first = next_frame(&mut stdout, WORKER_FRAME_MAX_BYTES);
            let readable = matches!(first, Frame::Bytes(_));
            if ready_tx.send(first).is_err() || !readable {
                discard(stdout);
                return;
            }
            match go_rx.recv() {
                Ok(continuation) => continuation(stdout),
                Err(_) => discard(stdout),
            }
        })?;
    Ok((ready_rx, go_tx))
}

/// The stderr thread: the first [`STDERR_CAP`] bytes, decoded lossily, once the stream ends.
pub(crate) fn spawn_stderr(mut stderr: Box<dyn Read + Send>) -> io::Result<Receiver<String>> {
    let (tx, rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("sandbox-stderr".to_owned())
        .spawn(move || {
            let _ = tx.send(drain_head(&mut stderr, STDERR_CAP));
        })?;
    Ok(rx)
}

/// Reads `r` to its end and keeps the first `cap` bytes.
fn drain_head(r: &mut dyn Read, cap: usize) -> String {
    let mut kept = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let room = cap - kept.len();
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&kept).into_owned()
}

/// The reaper thread: how the worker ended, once it is reaped.
pub(crate) fn spawn_reaper(reaper: Box<dyn Reaper>) -> io::Result<Receiver<io::Result<ExitKind>>> {
    let (tx, rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("sandbox-reaper".to_owned())
        .spawn(move || {
            let _ = tx.send(reaper.wait());
        })?;
    Ok(rx)
}

/// After the caller's kill: kills again every `every` until the worker is reaped (`exit`
/// answers, or its reaper thread is gone), on a thread of its own. The backstop for a kill that
/// did not take (T6: that shows only as a worker that never ends) where no run timer is armed.
/// Without that thread the caller's kill is all there is.
pub(crate) fn rekill_until_reaped(
    kill: Arc<dyn KillHandle>,
    exit: Receiver<io::Result<ExitKind>>,
    every: Duration,
) {
    let _ = thread::Builder::new()
        .name("sandbox-rekill".to_owned())
        .spawn(move || {
            while let Err(mpsc::RecvTimeoutError::Timeout) = exit.recv_timeout(every) {
                kill.kill();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stderr_head_is_kept_and_the_rest_read() {
        let mut input: &[u8] = &[b'x'; 100_000];
        assert_eq!(drain_head(&mut input, 10).len(), 10);
        assert!(input.is_empty(), "read to the end");
        let mut short: &[u8] = b"abc";
        assert_eq!(drain_head(&mut short, 10), "abc");
    }

    #[test]
    fn frames_end_at_eof_truncation_or_oversize() {
        let mut ok: Stdout = Box::new(io::Cursor::new(vec![0, 0, 0, 2, b'{', b'}']));
        assert!(matches!(next_frame(&mut ok, 10), Frame::Bytes(b) if b == b"{}"));
        assert!(matches!(next_frame(&mut ok, 10), Frame::End));
        let mut cut: Stdout = Box::new(io::Cursor::new(vec![0, 0, 0, 9, b'{']));
        assert!(matches!(next_frame(&mut cut, 10), Frame::End));
        let mut big: Stdout = Box::new(io::Cursor::new(vec![0, 0, 0, 11]));
        assert!(matches!(next_frame(&mut big, 10), Frame::TooLarge));
    }

    struct Counted(std::sync::atomic::AtomicU32);

    impl KillHandle for Counted {
        fn kill(&self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Waits (bounded) until `cond` holds.
    fn within(cond: impl Fn() -> bool) -> bool {
        let started = std::time::Instant::now();
        while !cond() {
            if started.elapsed() > Duration::from_secs(10) {
                return false;
            }
            thread::sleep(Duration::from_millis(2));
        }
        true
    }

    #[test]
    fn the_rekill_thread_kills_until_the_reap() {
        let kill = Arc::new(Counted(Default::default()));
        let calls = || kill.0.load(std::sync::atomic::Ordering::SeqCst);
        let (tx, rx) = mpsc::sync_channel(1);
        rekill_until_reaped(kill.clone(), rx, Duration::from_millis(5));
        assert!(within(|| calls() >= 3), "killed again and again");
        let _ = tx.send(Ok(ExitKind::Code(0)));
        assert!(
            within(|| Arc::strong_count(&kill) == 1),
            "the thread ended at the reap"
        );

        // A reaper thread that is gone (its sender dropped) ends the loop as well.
        let kill = Arc::new(Counted(Default::default()));
        let (tx, rx) = mpsc::sync_channel::<io::Result<ExitKind>>(1);
        drop(tx);
        rekill_until_reaped(kill.clone(), rx, Duration::from_millis(5));
        assert!(within(|| Arc::strong_count(&kill) == 1));
        assert_eq!(kill.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
