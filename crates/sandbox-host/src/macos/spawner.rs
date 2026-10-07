//! `posix_spawn` of the sandbox worker with exactly three pipes (§3.4, macOS).
//!
//! What §3.4 fixes for macOS: `posix_spawn` with `POSIX_SPAWN_CLOEXEC_DEFAULT`,
//! exactly three descriptors (stdin, stdout, stderr), each a pipe owned by the
//! host, an environment cleared to `TZ=UTC0`, working directory `/`, and no
//! parent-death signal (the worker exits on stdin EOF instead).
//!
//! Plan decisions (the spec is silent):
//! - Memory: `SpawnSpec::process_mb` is not applied here. `RLIMIT_AS` is not
//!   enforced on Darwin (§9.4); the host-side `ri_phys_footprint` watchdog is M8.
//! - The signal state is reset (`POSIX_SPAWN_SETSIGDEF` for every signal,
//!   `POSIX_SPAWN_SETSIGMASK` empty), so the worker does not inherit the
//!   host's ignored `SIGPIPE` or a blocked signal mask.
//! - One reader thread per worker (the `WorkerProcess` contract). It forwards
//!   raw stdout chunks through a bounded channel, so a half-received frame is
//!   never lost when `read_frame_timeout` times out, and a flooding worker is
//!   stopped by pipe back-pressure instead of growing host memory. The read
//!   deadline covers the whole frame, so a worker that trickles bytes cannot
//!   hold the host past it (same rule as the Linux routine).
//! - stderr is a pipe drained by a second thread that keeps the last 4 KiB;
//!   [`MacWorker::stderr_tail`] shows it. The `sandbox_init` error text goes
//!   there.
//! - `pipe()` plus `fcntl` is not atomic. `POSIX_SPAWN_CLOEXEC_DEFAULT` makes
//!   this routine immune to its own race; a foreign `fork`/`spawn` that runs
//!   inside the same microsecond window could still inherit a pipe end.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::ptr;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::spawn::{ExitKind, SpawnSpec, WorkerProcess, WorkerSpawner};

/// The worker's whole environment (§3.4: `TZ=UTC0` keeps libc from opening a
/// time-zone file under the confinement).
pub const WORKER_ENV: [(&str, &str); 1] = [("TZ", "UTC0")];

/// Size of one raw read from the worker's stdout.
const READ_CHUNK: usize = 16 * 1024;
/// Chunks buffered between the reader thread and the caller (1 MiB).
const CHANNEL_CHUNKS: usize = 64;
/// How much of the worker's stderr is kept.
const STDERR_TAIL_BYTES: usize = 4096;
/// Poll interval of `wait_timeout` (macOS has no pidfd).
const WAIT_POLL: Duration = Duration::from_millis(10);
/// How long `Drop` waits for the killed worker to be reaped.
const DROP_REAP: Duration = Duration::from_secs(1);

/// `now + d`, saturating: an `Instant` overflow means "far in the future".
fn deadline_after(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d)
        .unwrap_or_else(|| now + Duration::from_secs(60 * 60 * 24 * 365))
}

/// Starts sandbox workers with `posix_spawn`.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacSpawner;

impl MacSpawner {
    /// A spawner. It holds no state; every `spawn` is independent.
    pub fn new() -> MacSpawner {
        MacSpawner
    }

    /// Like [`WorkerSpawner::spawn`], but returns the concrete worker, which
    /// also offers [`MacWorker::stderr_tail`] (used by the probe tests).
    pub fn spawn_mac(&self, spec: &SpawnSpec) -> io::Result<MacWorker> {
        let exe = CString::new(spec.exe.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "exe path contains NUL"))?;
        let env: Vec<CString> = WORKER_ENV
            .iter()
            .map(|(k, v)| CString::new(format!("{k}={v}")))
            .collect::<Result<_, _>>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "env contains NUL"))?;

        // The child ends are closed in the host right after the spawn (or on
        // an early return), which is what lets the host see EOF.
        let (child_stdin, host_stdin) = make_pipe()?;
        let (host_stdout, child_stdout) = make_pipe()?;
        let (host_stderr, child_stderr) = make_pipe()?;

        // The helper threads only hold host ends, so they can start before the
        // spawn; if the spawn fails they see EOF and end on their own.
        let frames = FrameReader::spawn(File::from(host_stdout))?;
        let stderr_tail = Arc::new(Mutex::new(Vec::new()));
        let stderr_thread = spawn_stderr_drain(File::from(host_stderr), Arc::clone(&stderr_tail))?;

        let pid = posix_spawn_worker(
            &exe,
            &env,
            [
                child_stdin.as_raw_fd(),
                child_stdout.as_raw_fd(),
                child_stderr.as_raw_fd(),
            ],
        )?;
        drop((child_stdin, child_stdout, child_stderr));

        Ok(MacWorker {
            pid,
            stdin: StdinPipe(Some(File::from(host_stdin))),
            frames,
            stderr_tail,
            stderr_thread: Some(stderr_thread),
            exit: None,
        })
    }
}

impl WorkerSpawner for MacSpawner {
    fn spawn(&self, spec: &SpawnSpec) -> io::Result<Box<dyn WorkerProcess>> {
        Ok(Box::new(self.spawn_mac(spec)?))
    }
}

/// One `pipe()` with both ends moved above fd 2 and marked close-on-exec.
/// Returns `(read end, write end)`.
fn make_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds: [RawFd; 2] = [-1, -1];
    // SAFETY: `fds` is a valid array of two ints.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `pipe` returned two fresh descriptors that nothing else owns.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    Ok((above_stdio(read)?, above_stdio(write)?))
}

/// Duplicates `fd` to the lowest descriptor >= 3 with `FD_CLOEXEC` set and
/// closes the original. A host that started with a closed stdio would
/// otherwise hand out pipe ends numbered 0 to 2, which would break the
/// `dup2` file actions below.
fn above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
    // SAFETY: `fd` is a valid open descriptor.
    let new = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if new < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` returned a fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

/// Maps a `posix_spawn*` return value (an errno, not -1) to `io::Result`.
fn check(rc: libc::c_int) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}

struct SpawnAttr(libc::posix_spawnattr_t);

impl SpawnAttr {
    fn new() -> io::Result<SpawnAttr> {
        let mut attr: libc::posix_spawnattr_t = ptr::null_mut();
        // SAFETY: `attr` is a valid out pointer.
        check(unsafe { libc::posix_spawnattr_init(&mut attr) })?;
        Ok(SpawnAttr(attr))
    }
}

impl Drop for SpawnAttr {
    fn drop(&mut self) {
        // SAFETY: `self.0` was initialized by `posix_spawnattr_init`.
        unsafe { libc::posix_spawnattr_destroy(&mut self.0) };
    }
}

struct FileActions(libc::posix_spawn_file_actions_t);

impl FileActions {
    fn new() -> io::Result<FileActions> {
        let mut actions: libc::posix_spawn_file_actions_t = ptr::null_mut();
        // SAFETY: `actions` is a valid out pointer.
        check(unsafe { libc::posix_spawn_file_actions_init(&mut actions) })?;
        Ok(FileActions(actions))
    }
}

impl Drop for FileActions {
    fn drop(&mut self) {
        // SAFETY: `self.0` was initialized by `posix_spawn_file_actions_init`.
        unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0) };
    }
}

/// `posix_spawn` of `exe` with `argv = [exe]`, `envp = env`, the three given
/// descriptors as 0, 1 and 2, working directory `/`, and every other
/// descriptor closed in the child.
fn posix_spawn_worker(
    exe: &CString,
    env: &[CString],
    stdio: [RawFd; 3],
) -> io::Result<libc::pid_t> {
    let mut attr = SpawnAttr::new()?;
    let flags = libc::POSIX_SPAWN_CLOEXEC_DEFAULT
        | libc::POSIX_SPAWN_SETSIGDEF
        | libc::POSIX_SPAWN_SETSIGMASK;
    // SAFETY: `attr.0` is initialized.
    check(unsafe { libc::posix_spawnattr_setflags(&mut attr.0, flags as libc::c_short) })?;
    // SAFETY: an all-zero `sigset_t` is a valid value; `sigfillset` and
    // `sigemptyset` then initialize it.
    let mut all: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut none: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers refer to the locals above.
    unsafe {
        libc::sigfillset(&mut all);
        libc::sigemptyset(&mut none);
    }
    // SAFETY: `attr.0` is initialized and the sets are fully initialized.
    check(unsafe { libc::posix_spawnattr_setsigdefault(&mut attr.0, &all) })?;
    check(unsafe { libc::posix_spawnattr_setsigmask(&mut attr.0, &none) })?;

    let mut actions = FileActions::new()?;
    for (target, fd) in stdio.into_iter().enumerate() {
        // SAFETY: `actions.0` is initialized; both descriptors are plain ints.
        check(unsafe {
            libc::posix_spawn_file_actions_adddup2(&mut actions.0, fd, target as libc::c_int)
        })?;
    }
    // SAFETY: `actions.0` is initialized and the path is a NUL-terminated literal.
    check(unsafe { libc::posix_spawn_file_actions_addchdir_np(&mut actions.0, c"/".as_ptr()) })?;

    let argv: [*mut libc::c_char; 2] = [exe.as_ptr().cast_mut(), ptr::null_mut()];
    let mut envp: Vec<*mut libc::c_char> = env.iter().map(|e| e.as_ptr().cast_mut()).collect();
    envp.push(ptr::null_mut());

    let mut pid: libc::pid_t = 0;
    // SAFETY: every pointer is valid for the call; `argv` and `envp` are
    // NULL-terminated arrays of NUL-terminated strings that outlive it.
    check(unsafe {
        libc::posix_spawn(
            &mut pid,
            exe.as_ptr(),
            &actions.0,
            &attr.0,
            argv.as_ptr(),
            envp.as_ptr(),
        )
    })?;
    Ok(pid)
}

/// Host end of the worker's stdin; writing after `close_stdin` fails.
struct StdinPipe(Option<File>);

impl Write for StdinPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0.as_mut() {
            Some(f) => f.write(buf),
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker stdin is closed",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.0.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

enum Chunk {
    Data(Vec<u8>),
    Eof,
    Failed(io::ErrorKind),
}

/// Assembles u32 big-endian length-delimited frames (§3.3) from the chunks
/// the reader thread forwards.
struct FrameReader {
    rx: Receiver<Chunk>,
    buf: Vec<u8>,
    eof: bool,
}

impl FrameReader {
    fn from_channel(rx: Receiver<Chunk>) -> FrameReader {
        FrameReader {
            rx,
            buf: Vec::new(),
            eof: false,
        }
    }

    /// Starts the reader thread on the host end of the worker's stdout.
    fn spawn(mut stdout: File) -> io::Result<FrameReader> {
        let (tx, rx) = mpsc::sync_channel(CHANNEL_CHUNKS);
        thread::Builder::new()
            .name("atlas-duck-worker-out".into())
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
        Ok(FrameReader::from_channel(rx))
    }

    /// `WorkerProcess::read_frame_timeout` semantics (see `crate::spawn`).
    fn next_frame(&mut self, max: usize, d: Duration) -> io::Result<Option<Vec<u8>>> {
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

    /// Removes and returns one complete frame from the buffer, if there is one.
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
}

/// Drains the worker's stderr so a chatty worker can never block on a full
/// pipe, and keeps the last [`STDERR_TAIL_BYTES`] bytes.
fn spawn_stderr_drain(mut stderr: File, tail: Arc<Mutex<Vec<u8>>>) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("atlas-duck-worker-err".into())
        .spawn(move || {
            let mut chunk = [0u8; 1024];
            loop {
                match stderr.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut t = tail.lock().unwrap_or_else(PoisonError::into_inner);
                        t.extend_from_slice(&chunk[..n]);
                        if t.len() > STDERR_TAIL_BYTES {
                            let excess = t.len() - STDERR_TAIL_BYTES;
                            t.drain(..excess);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        })
}

/// One running sandbox worker.
pub struct MacWorker {
    pid: libc::pid_t,
    stdin: StdinPipe,
    frames: FrameReader,
    stderr_tail: Arc<Mutex<Vec<u8>>>,
    stderr_thread: Option<JoinHandle<()>>,
    /// `Some` once the process has been reaped; it is never signalled after
    /// that, so a recycled pid is never hit.
    exit: Option<ExitKind>,
}

impl MacWorker {
    /// The last 4 KiB the worker wrote to stderr (lossy UTF-8). Once the
    /// worker has exited, this waits for the drain thread, so nothing is
    /// missing.
    pub fn stderr_tail(&mut self) -> String {
        if self.exit.is_some()
            && let Some(handle) = self.stderr_thread.take()
        {
            let _ = handle.join();
        }
        let t = self
            .stderr_tail
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&t).into_owned()
    }

    /// Non-blocking `waitpid`.
    fn try_reap(&mut self) -> io::Result<Option<ExitKind>> {
        if let Some(exit) = self.exit {
            return Ok(Some(exit));
        }
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: `status` is a valid out pointer and `pid` is our child.
            let rc = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if rc == 0 {
                return Ok(None);
            }
            if rc == self.pid {
                let st = ExitStatus::from_raw(status);
                let exit = match (st.code(), st.signal()) {
                    (Some(code), _) => ExitKind::Code(code),
                    (None, Some(sig)) => ExitKind::Signal(sig),
                    (None, None) => ExitKind::Code(-1),
                };
                self.exit = Some(exit);
                return Ok(Some(exit));
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

impl WorkerProcess for MacWorker {
    fn pid(&self) -> u32 {
        self.pid as u32
    }

    fn stdin(&mut self) -> &mut dyn Write {
        &mut self.stdin
    }

    fn read_frame_timeout(&mut self, max: usize, d: Duration) -> io::Result<Option<Vec<u8>>> {
        self.frames.next_frame(max, d)
    }

    fn close_stdin(&mut self) {
        self.stdin.0 = None;
    }

    fn wait_timeout(&mut self, d: Duration) -> io::Result<Option<ExitKind>> {
        let deadline = deadline_after(d);
        loop {
            if let Some(exit) = self.try_reap()? {
                return Ok(Some(exit));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            thread::sleep(left.min(WAIT_POLL));
        }
    }

    fn kill(&mut self) -> io::Result<()> {
        // A zombie keeps its pid, so signalling after a failed reap is safe.
        if self.try_reap()?.is_some() {
            return Ok(());
        }
        // SAFETY: `pid` is our un-reaped child.
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                return Err(err);
            }
        }
        Ok(())
    }
}

impl Drop for MacWorker {
    fn drop(&mut self) {
        let _ = self.kill();
        let _ = self.wait_timeout(DROP_REAP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const SHORT: Duration = Duration::from_millis(200);
    const LONG: Duration = Duration::from_secs(10);
    const MAX: usize = 1024 * 1024;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    /// A reader that is fed `chunks` and then sees the channel close.
    fn reader(chunks: Vec<Chunk>) -> FrameReader {
        let (tx, rx) = mpsc::sync_channel(64);
        for c in chunks {
            assert!(tx.send(c).is_ok());
        }
        FrameReader::from_channel(rx)
    }

    // ----------------------------------------------------- frame assembler

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
        let mut r = FrameReader::from_channel(rx);
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

    // ------------------------------------------- real processes (/bin/cat)

    fn cat_spec() -> SpawnSpec {
        SpawnSpec {
            exe: PathBuf::from("/bin/cat"),
            process_mb: 512,
        }
    }

    fn spawn_cat() -> MacWorker {
        match MacSpawner::new().spawn_mac(&cat_spec()) {
            Ok(w) => w,
            Err(e) => panic!("spawning /bin/cat failed: {e}"),
        }
    }

    #[test]
    fn cat_echoes_a_frame_and_exits_zero_after_stdin_eof() {
        let mut w = spawn_cat();
        let payload = vec![0xA5u8; 100_000];
        let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&payload);
        assert!(w.stdin().write_all(&bytes).is_ok());
        assert!(w.stdin().flush().is_ok());
        assert_eq!(w.read_frame_timeout(MAX, LONG).ok(), Some(Some(payload)));
        w.close_stdin();
        w.close_stdin();
        assert!(w.stdin().write_all(b"x").is_err(), "stdin must be closed");
        assert_eq!(w.read_frame_timeout(MAX, LONG).ok(), Some(None));
        assert_eq!(w.wait_timeout(LONG).ok(), Some(Some(ExitKind::Code(0))));
        // The result is cached; a second wait and a kill after the reap are fine.
        assert_eq!(w.wait_timeout(SHORT).ok(), Some(Some(ExitKind::Code(0))));
        assert!(w.kill().is_ok());
    }

    #[test]
    fn a_silent_worker_times_out_and_kill_ends_it_with_sigkill() {
        let mut w = spawn_cat();
        let err = w.read_frame_timeout(MAX, Duration::from_millis(100)).err();
        assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::TimedOut));
        assert_eq!(w.wait_timeout(Duration::from_millis(50)).ok(), Some(None));
        assert!(w.kill().is_ok());
        assert!(w.kill().is_ok());
        assert_eq!(
            w.wait_timeout(LONG).ok(),
            Some(Some(ExitKind::Signal(libc::SIGKILL)))
        );
    }

    #[test]
    fn dropping_a_worker_kills_it() {
        let w = spawn_cat();
        let pid = w.pid() as libc::pid_t;
        drop(w);
        // SAFETY: signal 0 only checks that the pid exists.
        let rc = unsafe { libc::kill(pid, 0) };
        assert_eq!(rc, -1, "the dropped worker must be gone");
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn a_missing_binary_fails_with_enoent() {
        let spec = SpawnSpec {
            exe: PathBuf::from("/nonexistent/atlas-duck-sandbox"),
            process_mb: 512,
        };
        let err = MacSpawner::new().spawn_mac(&spec).err();
        assert_eq!(err.and_then(|e| e.raw_os_error()), Some(libc::ENOENT));
    }

    #[test]
    fn the_worker_has_only_fds_0_1_2_and_cwd_slash() {
        // An inheritable descriptor that must not reach the worker.
        // SAFETY: plain `open` of /dev/null without O_CLOEXEC.
        let leak = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(leak > 2, "test setup: the leak fd is {leak}");

        let w = spawn_cat();
        let pid = w.pid() as libc::c_int;

        let entry = std::mem::size_of::<libc::proc_fdinfo>();
        let mut buf = vec![0u8; entry * 256];
        // SAFETY: `buf` is valid for `buf.len()` bytes.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                buf.as_mut_ptr().cast(),
                buf.len() as libc::c_int,
            )
        };
        assert!(
            n > 0,
            "proc_pidinfo(PROC_PIDLISTFDS): {}",
            io::Error::last_os_error()
        );
        let mut fds: Vec<i32> = buf[..n as usize]
            .chunks_exact(entry)
            .filter_map(|c| c.first_chunk::<4>().map(|b| i32::from_ne_bytes(*b)))
            .collect();
        fds.sort_unstable();
        // SAFETY: `leak` was opened above.
        unsafe { libc::close(leak) };
        assert_eq!(fds, vec![0, 1, 2]);

        // SAFETY: an all-zero `proc_vnodepathinfo` is a valid out buffer.
        let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is valid for its size.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDVNODEPATHINFO,
                0,
                (&mut info as *mut libc::proc_vnodepathinfo).cast(),
                std::mem::size_of::<libc::proc_vnodepathinfo>() as libc::c_int,
            )
        };
        assert!(
            n > 0,
            "proc_pidinfo(PROC_PIDVNODEPATHINFO): {}",
            io::Error::last_os_error()
        );
        let raw: &[libc::c_char] = info.pvi_cdir.vip_path.as_flattened();
        let bytes: Vec<u8> = raw
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        assert_eq!(bytes, b"/");
    }
}
