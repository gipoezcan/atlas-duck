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

use std::io::{self, Read};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;

use atlas_duck_ipc::sandbox::WORKER_FRAME_MAX_BYTES;
use atlas_duck_ipc::sandbox::frame::{FrameError, read_frame};

use super::STDERR_CAP;
use crate::spawn::{ExitKind, Reaper};

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
}
