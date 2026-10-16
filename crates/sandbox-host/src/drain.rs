//! The host's reader threads on a worker's stdout and stderr, shared by the
//! spawners, and their hand-over to the bridge ([`WorkerIo`], Δ2).
//!
//! - [`StderrDrain`] (every OS): reads the worker's stderr to EOF so the worker
//!   never blocks on it (§3.4), keeping the head or the tail.
//!   [`StderrDrain::hand_over`] turns what it kept plus everything it reads from
//!   then on into a byte stream.
//! - `ChunkReader` (Windows, macOS): a pipe read has no timeout there, so one
//!   thread forwards raw stdout chunks through a bounded channel and
//!   `next_frame` assembles frames with a deadline over the whole frame (a
//!   worker that trickles bytes cannot hold the host past it; a flooding worker
//!   is stopped by pipe back-pressure). `ChunkReader::hand_over` turns the
//!   bytes not yet returned as a frame plus the rest of the channel into a byte
//!   stream. Linux polls its pipe directly and needs no thread.
//!
//! [`WorkerIo`]: crate::spawn::WorkerIo

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::io::{self, Read};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};

/// Size of one raw read from a worker pipe.
const READ_CHUNK: usize = 16 * 1024;
/// Chunks buffered between a reader thread and its consumer (1 MiB).
const CHANNEL_CHUNKS: usize = 64;

/// What a reader thread forwards.
pub(crate) enum Chunk {
    Data(Vec<u8>),
    Eof,
    Failed(io::ErrorKind),
}

/// A blocking byte stream over a reader thread's channel: `buf[pos..]` first,
/// then each chunk as it arrives; `Ok(0)` once the thread reported EOF or
/// ended; a read error of the thread is returned once, then `Ok(0)`.
pub(crate) struct ChannelRead {
    buf: Vec<u8>,
    pos: usize,
    rx: Receiver<Chunk>,
    done: bool,
}

impl Read for ChannelRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pos < self.buf.len() {
                let n = out.len().min(self.buf.len() - self.pos);
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if self.done {
                return Ok(0);
            }
            match self.rx.recv() {
                Ok(Chunk::Data(bytes)) => {
                    self.buf = bytes;
                    self.pos = 0;
                }
                Ok(Chunk::Eof) | Err(_) => self.done = true,
                Ok(Chunk::Failed(kind)) => {
                    self.done = true;
                    return Err(io::Error::new(kind, "reading the worker's pipe failed"));
                }
            }
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Which bytes of stderr a [`StderrDrain`] keeps before a hand-over.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Keep {
    /// The first n bytes (§3.4: 64 KiB; Linux, Windows).
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Head(usize),
    /// The last n bytes (macOS: 4 KiB, where the `sandbox_init` error text is).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Tail(usize),
}

/// Where the drain thread puts the next chunk.
enum Sink {
    /// Before the hand-over: keep per [`Keep`].
    Keep(Vec<u8>),
    /// After the hand-over: forward to the [`ChannelRead`].
    Forward(mpsc::SyncSender<Chunk>),
    /// The stream was dropped: read and discard.
    Discard,
    /// The thread reached EOF before any hand-over; what it kept.
    Ended(Vec<u8>),
}

/// Drains a worker's stderr on a thread of its own (§3.4: read continuously,
/// keep a capped part, discard the rest).
pub(crate) struct StderrDrain {
    sink: Arc<Mutex<Sink>>,
    thread: Option<JoinHandle<()>>,
}

impl StderrDrain {
    /// Starts the thread `name` on `stderr`.
    pub(crate) fn start(
        stderr: impl Read + Send + 'static,
        keep: Keep,
        name: &str,
    ) -> io::Result<StderrDrain> {
        let sink = Arc::new(Mutex::new(Sink::Keep(Vec::new())));
        let shared = Arc::clone(&sink);
        let thread = thread::Builder::new()
            .name(name.to_string())
            .spawn(move || drain(stderr, &shared, keep))?;
        Ok(StderrDrain {
            sink,
            thread: Some(thread),
        })
    }

    /// The bytes kept so far (empty after a hand-over). For test diagnostics;
    /// never logged.
    pub(crate) fn kept(&self) -> Vec<u8> {
        match &*lock(&self.sink) {
            Sink::Keep(kept) | Sink::Ended(kept) => kept.clone(),
            Sink::Forward(_) | Sink::Discard => Vec::new(),
        }
    }

    /// Waits for the thread to reach EOF (once the worker has exited, so that
    /// nothing it wrote is missing). A no-op after a hand-over.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn join(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Hands the reader over: the bytes kept so far, then every chunk the
    /// thread reads from now on. The thread keeps running (detached); once the
    /// returned stream is dropped it discards.
    pub(crate) fn hand_over(&mut self) -> ChannelRead {
        let (tx, rx) = mpsc::sync_channel(CHANNEL_CHUNKS);
        let mut sink = lock(&self.sink);
        let (kept, done) = match std::mem::replace(&mut *sink, Sink::Discard) {
            Sink::Keep(kept) => {
                *sink = Sink::Forward(tx);
                (kept, false)
            }
            // EOF already reached: the stream ends after the kept bytes.
            Sink::Ended(kept) => (kept, true),
            Sink::Forward(_) | Sink::Discard => (Vec::new(), true),
        };
        drop(sink);
        self.thread = None;
        ChannelRead {
            buf: kept,
            pos: 0,
            rx,
            done,
        }
    }
}

fn drain(mut stderr: impl Read, sink: &Mutex<Sink>, keep: Keep) {
    let mut chunk = vec![0u8; READ_CHUNK];
    let mut failed = None;
    loop {
        let n = match stderr.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                failed = Some(e.kind());
                break;
            }
        };
        // The decision is taken under the lock, the send outside it: a full
        // channel blocks only this thread, never `hand_over` or `kept`.
        let forward = match &mut *lock(sink) {
            Sink::Keep(kept) => {
                keep_bytes(kept, &chunk[..n], keep);
                None
            }
            Sink::Forward(tx) => Some(tx.clone()),
            Sink::Discard | Sink::Ended(_) => None,
        };
        if let Some(tx) = forward
            && tx.send(Chunk::Data(chunk[..n].to_vec())).is_err()
        {
            // The stream was dropped: keep draining so the worker never blocks.
            let mut sink = lock(sink);
            if matches!(*sink, Sink::Forward(_)) {
                *sink = Sink::Discard;
            }
        }
    }
    let forward = {
        let mut sink = lock(sink);
        match std::mem::replace(&mut *sink, Sink::Discard) {
            Sink::Keep(kept) => {
                *sink = Sink::Ended(kept);
                None
            }
            Sink::Forward(tx) => Some(tx),
            other => {
                *sink = other;
                None
            }
        }
    };
    if let Some(tx) = forward {
        let _ = tx.send(failed.map_or(Chunk::Eof, Chunk::Failed));
    }
}

fn keep_bytes(kept: &mut Vec<u8>, bytes: &[u8], keep: Keep) {
    match keep {
        Keep::Head(cap) => {
            let room = cap.saturating_sub(kept.len());
            kept.extend_from_slice(&bytes[..bytes.len().min(room)]);
        }
        Keep::Tail(cap) => {
            kept.extend_from_slice(bytes);
            if kept.len() > cap {
                let excess = kept.len() - cap;
                kept.drain(..excess);
            }
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub(crate) use chunks::ChunkReader;

#[cfg(any(windows, target_os = "macos"))]
mod chunks {
    use std::io::{self, Read};
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{CHANNEL_CHUNKS, ChannelRead, Chunk, READ_CHUNK};

    /// `now + d`, saturating: an `Instant` overflow means "far in the future".
    fn deadline_after(d: Duration) -> Instant {
        let now = Instant::now();
        now.checked_add(d)
            .unwrap_or_else(|| now + Duration::from_secs(60 * 60 * 24 * 365))
    }

    /// Assembles u32 big-endian length-delimited frames (§3.3) from the chunks
    /// a reader thread forwards.
    pub(crate) struct ChunkReader {
        rx: Receiver<Chunk>,
        buf: Vec<u8>,
        eof: bool,
    }

    impl ChunkReader {
        #[cfg(test)]
        pub(crate) fn from_channel(rx: Receiver<Chunk>) -> ChunkReader {
            ChunkReader {
                rx,
                buf: Vec::new(),
                eof: false,
            }
        }

        /// Starts the reader thread `name` on the host end of the worker's
        /// stdout.
        pub(crate) fn spawn(
            mut stdout: impl Read + Send + 'static,
            name: &str,
        ) -> io::Result<ChunkReader> {
            let (tx, rx) = mpsc::sync_channel(CHANNEL_CHUNKS);
            thread::Builder::new()
                .name(name.to_string())
                .spawn(move || {
                    let mut chunk = vec![0u8; READ_CHUNK];
                    loop {
                        match stdout.read(&mut chunk) {
                            Ok(0) => {
                                let _ = tx.send(Chunk::Eof);
                                break;
                            }
                            Ok(n) => {
                                if tx.send(Chunk::Data(chunk[..n].to_vec())).is_err() {
                                    break;
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                            Err(e) => {
                                let _ = tx.send(Chunk::Failed(e.kind()));
                                break;
                            }
                        }
                    }
                })?;
            Ok(ChunkReader {
                rx,
                buf: Vec::new(),
                eof: false,
            })
        }

        /// `WorkerProcess::read_frame_timeout` semantics (see `crate::spawn`).
        pub(crate) fn next_frame(
            &mut self,
            max: usize,
            d: Duration,
        ) -> io::Result<Option<Vec<u8>>> {
            let deadline = deadline_after(d);
            loop {
                if let Some(frame) = self.take_frame(max)? {
                    return Ok(Some(frame));
                }
                if self.eof {
                    return if self.buf.is_empty() {
                        Ok(None)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "truncated frame",
                        ))
                    };
                }
                let left = deadline.saturating_duration_since(Instant::now());
                match self.rx.recv_timeout(left) {
                    Ok(Chunk::Data(bytes)) => self.buf.extend_from_slice(&bytes),
                    Ok(Chunk::Eof) | Err(RecvTimeoutError::Disconnected) => self.eof = true,
                    Ok(Chunk::Failed(kind)) => {
                        self.eof = true;
                        return Err(io::Error::new(kind, "reading the worker's stdout failed"));
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "no complete frame in time",
                        ));
                    }
                }
            }
        }

        /// Removes and returns one complete frame from the buffer, if there is
        /// one.
        fn take_frame(&mut self, max: usize) -> io::Result<Option<Vec<u8>>> {
            let Some(header) = self.buf.first_chunk::<4>() else {
                return Ok(None);
            };
            let len = usize::try_from(u32::from_be_bytes(*header)).unwrap_or(usize::MAX);
            if len > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame larger than the limit",
                ));
            }
            let Some(end) = 4usize.checked_add(len) else {
                return Ok(None);
            };
            if self.buf.len() < end {
                return Ok(None);
            }
            let payload = self.buf[4..end].to_vec();
            self.buf.drain(..end);
            Ok(Some(payload))
        }

        /// Hands the stream over: the bytes not yet returned as a frame, then
        /// every chunk the thread forwards from now on. This reader is at EOF
        /// afterwards.
        pub(crate) fn hand_over(&mut self) -> ChannelRead {
            let (closed, empty) = mpsc::sync_channel(0);
            drop(closed);
            let done = self.eof;
            self.eof = true;
            ChannelRead {
                buf: std::mem::take(&mut self.buf),
                pos: 0,
                rx: std::mem::replace(&mut self.rx, empty),
                done,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const SHORT: Duration = Duration::from_millis(200);
        const LONG: Duration = Duration::from_secs(10);
        const MAX: usize = 1024 * 1024;

        fn frame(payload: &[u8]) -> Vec<u8> {
            let mut v = (payload.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(payload);
            v
        }

        /// A reader that is fed `chunks` and then sees the channel close.
        fn reader(chunks: Vec<Chunk>) -> ChunkReader {
            let (tx, rx) = mpsc::sync_channel(64);
            for c in chunks {
                assert!(tx.send(c).is_ok());
            }
            ChunkReader::from_channel(rx)
        }

        fn read_all(mut r: impl Read) -> io::Result<Vec<u8>> {
            let mut out = Vec::new();
            r.read_to_end(&mut out)?;
            Ok(out)
        }

        #[test]
        fn two_frames_in_one_chunk_then_clean_eof() {
            let mut both = frame(b"one");
            both.extend(frame(b"second"));
            let mut r = reader(vec![Chunk::Data(both), Chunk::Eof]);
            assert_eq!(r.next_frame(MAX, SHORT).ok(), Some(Some(b"one".to_vec())));
            assert_eq!(
                r.next_frame(MAX, SHORT).ok(),
                Some(Some(b"second".to_vec()))
            );
            assert_eq!(r.next_frame(MAX, SHORT).ok(), Some(None));
        }

        #[test]
        fn a_frame_split_across_chunks_is_reassembled() {
            let bytes = frame(b"hello worker");
            let chunks = bytes.chunks(3).map(|c| Chunk::Data(c.to_vec())).collect();
            let mut r = reader(chunks);
            assert_eq!(
                r.next_frame(MAX, SHORT).ok(),
                Some(Some(b"hello worker".to_vec()))
            );
            assert_eq!(r.next_frame(MAX, SHORT).ok(), Some(None));
        }

        #[test]
        fn a_zero_length_frame_is_a_frame() {
            let mut r = reader(vec![Chunk::Data(frame(b"")), Chunk::Eof]);
            assert_eq!(r.next_frame(MAX, SHORT).ok(), Some(Some(Vec::new())));
        }

        #[test]
        fn an_oversize_frame_is_invalid_data() {
            let mut r = reader(vec![Chunk::Data(frame(&[7u8; 100])), Chunk::Eof]);
            let err = r.next_frame(99, SHORT).err();
            assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
            // The limit is inclusive.
            let mut r = reader(vec![Chunk::Data(frame(&[7u8; 100])), Chunk::Eof]);
            assert_eq!(r.next_frame(100, SHORT).ok(), Some(Some(vec![7u8; 100])));
        }

        #[test]
        fn a_frame_cut_off_by_eof_is_invalid_data() {
            let mut bytes = frame(b"abcdef");
            bytes.truncate(bytes.len() - 2);
            let mut r = reader(vec![Chunk::Data(bytes), Chunk::Eof]);
            let err = r.next_frame(MAX, SHORT).err();
            assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
            let mut r = reader(vec![Chunk::Data(vec![0, 0]), Chunk::Eof]);
            let err = r.next_frame(MAX, SHORT).err();
            assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
        }

        #[test]
        fn a_timeout_keeps_the_partial_frame_for_the_next_call() {
            let (tx, rx) = mpsc::sync_channel(64);
            let mut r = ChunkReader::from_channel(rx);
            let bytes = frame(b"late payload");
            assert!(tx.send(Chunk::Data(bytes[..6].to_vec())).is_ok());
            let err = r.next_frame(MAX, Duration::from_millis(50)).err();
            assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::TimedOut));
            assert!(tx.send(Chunk::Data(bytes[6..].to_vec())).is_ok());
            assert_eq!(
                r.next_frame(MAX, LONG).ok(),
                Some(Some(b"late payload".to_vec()))
            );
        }

        #[test]
        fn a_failed_read_surfaces_its_kind() {
            let mut r = reader(vec![Chunk::Failed(io::ErrorKind::BrokenPipe)]);
            let err = r.next_frame(MAX, SHORT).err();
            assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::BrokenPipe));
        }

        #[test]
        fn a_huge_timeout_does_not_overflow_the_deadline() {
            let mut r = reader(vec![Chunk::Data(frame(b"x")), Chunk::Eof]);
            assert_eq!(
                r.next_frame(MAX, Duration::MAX).ok(),
                Some(Some(b"x".to_vec()))
            );
        }

        #[test]
        fn hand_over_after_a_frame_keeps_the_unread_bytes_in_order() -> io::Result<()> {
            // The ready frame and the first half of the next frame arrive together;
            // the bridge must see the rest of the stream from that half on.
            let mut first = frame(b"ready");
            let next = frame(b"script.result");
            first.extend_from_slice(&next[..5]);
            let (tx, rx) = mpsc::sync_channel(64);
            let mut r = ChunkReader::from_channel(rx);
            assert!(tx.send(Chunk::Data(first)).is_ok());
            assert_eq!(r.next_frame(MAX, LONG)?, Some(b"ready".to_vec()));
            let stream = r.hand_over();
            assert!(tx.send(Chunk::Data(next[5..].to_vec())).is_ok());
            assert!(tx.send(Chunk::Eof).is_ok());
            assert_eq!(read_all(stream)?, next);
            // The reader itself is at EOF.
            assert_eq!(r.next_frame(MAX, SHORT)?, None);
            Ok(())
        }

        #[test]
        fn hand_over_before_any_read_is_the_whole_stream() -> io::Result<()> {
            let (tx, rx) = mpsc::sync_channel(64);
            let mut r = ChunkReader::from_channel(rx);
            let stream = r.hand_over();
            assert!(tx.send(Chunk::Data(b"abc".to_vec())).is_ok());
            assert!(tx.send(Chunk::Data(b"def".to_vec())).is_ok());
            drop(tx);
            assert_eq!(read_all(stream)?, b"abcdef");
            Ok(())
        }

        #[test]
        fn hand_over_after_eof_returns_what_is_left() -> io::Result<()> {
            let mut r = reader(vec![Chunk::Data(frame(b"x")), Chunk::Eof]);
            assert_eq!(r.next_frame(MAX, SHORT)?, Some(b"x".to_vec()));
            assert_eq!(r.next_frame(MAX, SHORT)?, None);
            assert_eq!(read_all(r.hand_over())?, b"");
            Ok(())
        }

        #[test]
        fn the_handed_over_stream_reports_a_read_failure_once() {
            let mut r = reader(vec![
                Chunk::Data(b"ab".to_vec()),
                Chunk::Failed(io::ErrorKind::BrokenPipe),
            ]);
            let mut stream = r.hand_over();
            let mut buf = [0u8; 8];
            assert_eq!(stream.read(&mut buf).ok(), Some(2));
            assert_eq!(
                stream.read(&mut buf).err().map(|e| e.kind()),
                Some(io::ErrorKind::BrokenPipe)
            );
            assert_eq!(stream.read(&mut buf).ok(), Some(0));
        }

        #[test]
        fn the_thread_forwards_a_real_pipe() -> io::Result<()> {
            let (pr, mut pw) = io::pipe()?;
            let mut r = ChunkReader::spawn(pr, "test-chunks")?;
            io::Write::write_all(&mut pw, &frame(b"one"))?;
            assert_eq!(r.next_frame(MAX, LONG)?, Some(b"one".to_vec()));
            io::Write::write_all(&mut pw, b"tail")?;
            let stream = r.hand_over();
            drop(pw);
            assert_eq!(read_all(stream)?, b"tail");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::time::{Duration, Instant};

    use super::*;

    fn read_all(mut r: impl Read) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        r.read_to_end(&mut out)?;
        Ok(out)
    }

    /// Waits until the drain thread has kept `n` bytes.
    fn wait_kept(d: &StderrDrain, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while d.kept().len() < n && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn the_head_is_kept_and_the_rest_drained() -> io::Result<()> {
        let (pr, mut pw) = io::pipe()?;
        let mut d = StderrDrain::start(pr, Keep::Head(64 * 1024), "test-err")?;
        // more than a pipe holds: without the drain this write would block
        pw.write_all(&vec![b'e'; 200_000])?;
        drop(pw);
        d.join();
        assert_eq!(d.kept(), vec![b'e'; 64 * 1024]);
        Ok(())
    }

    #[test]
    fn the_tail_is_kept() -> io::Result<()> {
        let (pr, mut pw) = io::pipe()?;
        let mut d = StderrDrain::start(pr, Keep::Tail(4), "test-err")?;
        pw.write_all(b"0123456789")?;
        drop(pw);
        d.join();
        assert_eq!(d.kept(), b"6789");
        Ok(())
    }

    #[test]
    fn hand_over_yields_the_kept_bytes_then_the_rest() -> io::Result<()> {
        let (pr, mut pw) = io::pipe()?;
        let mut d = StderrDrain::start(pr, Keep::Head(1024), "test-err")?;
        pw.write_all(b"before ")?;
        wait_kept(&d, 7);
        let stream = d.hand_over();
        assert!(d.kept().is_empty());
        pw.write_all(b"after")?;
        drop(pw);
        assert_eq!(read_all(stream)?, b"before after");
        Ok(())
    }

    #[test]
    fn hand_over_after_eof_yields_the_kept_bytes() -> io::Result<()> {
        let (pr, mut pw) = io::pipe()?;
        let mut d = StderrDrain::start(pr, Keep::Head(1024), "test-err")?;
        pw.write_all(b"all of it")?;
        drop(pw);
        d.join();
        assert_eq!(read_all(d.hand_over())?, b"all of it");
        Ok(())
    }

    #[test]
    fn a_dropped_stream_does_not_block_the_worker() -> io::Result<()> {
        let (pr, mut pw) = io::pipe()?;
        let mut d = StderrDrain::start(pr, Keep::Head(16), "test-err")?;
        drop(d.hand_over());
        // far more than the channel and a pipe hold together
        pw.write_all(&vec![b'x'; 4 * 1024 * 1024])?;
        Ok(())
    }
}
