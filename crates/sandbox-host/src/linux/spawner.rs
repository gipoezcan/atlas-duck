//! The spawner thread, the fork/exec routine and the worker handle (§3.4).

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use libc::{c_char, c_int, c_long};

use super::{
    SPAWNER_THREAD_NAME, STDERR_CAP_BYTES, WORKER_ENV, WORKER_NOFILE, WORKER_STACK_BYTES,
    child_exit,
};
use crate::spawn::{ExitKind, SpawnSpec, WorkerProcess, WorkerSpawner};

/// How often `wait_timeout` polls `waitpid(WNOHANG)`.
const WAIT_POLL: Duration = Duration::from_millis(5);

/// Upper bound of the fallback close loop when `RLIMIT_NOFILE` is unlimited
/// (the kernel's default `fs.nr_open`).
const FALLBACK_SCAN_CAP: c_int = 1 << 20;

/// Handle to the one spawner thread. Cheap to clone.
#[derive(Clone)]
pub struct LinuxSpawner {
    tx: Sender<Job>,
}

/// The sender of the spawner thread, created once per process.
static SPAWNER: Mutex<Option<Sender<Job>>> = Mutex::new(None);

/// One spawn request, fully prepared by the caller so the spawner thread only
/// has to build the pointer arrays.
struct Job {
    exe: CString,
    process_mb: u32,
    force_close_loop: bool,
    reply: Sender<io::Result<Spawned>>,
}

/// The parent's ends of a freshly forked worker.
struct Spawned {
    pid: libc::pid_t,
    stdin: OwnedFd,
    stdout: OwnedFd,
    stderr: OwnedFd,
}

/// Test-only switches of the spawn routine.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SpawnOptions {
    /// Skip `close_range` and take the `close()` loop the child uses when
    /// `close_range` fails (`ENOSYS`, a sandbox that refuses it).
    pub(crate) force_close_loop: bool,
}

impl LinuxSpawner {
    /// Starts the spawner thread, once per process. Every later call returns
    /// a handle to the same thread, so exactly one thread named
    /// [`SPAWNER_THREAD_NAME`] ever exists.
    pub fn start() -> io::Result<Self> {
        let mut slot = SPAWNER.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(tx) = slot.as_ref() {
            return Ok(Self { tx: tx.clone() });
        }
        let (tx, rx) = mpsc::channel::<Job>();
        // The JoinHandle is dropped on purpose: the thread lives as long as
        // the process (the static above keeps a sender alive forever).
        thread::Builder::new()
            .name(SPAWNER_THREAD_NAME.to_string())
            .spawn(move || spawner_main(&rx))?;
        *slot = Some(tx.clone());
        Ok(Self { tx })
    }

    /// Spawns one worker and returns the concrete handle (`Send`, unlike the
    /// `Box<dyn WorkerProcess>` of [`WorkerSpawner::spawn`]).
    ///
    /// The fork happens on the spawner thread, whichever thread calls this.
    /// An error means no process exists. A failure between `fork` and
    /// `execve` is not an error here: the child exits with a code from
    /// [`child_exit`].
    pub fn spawn_process(&self, spec: &SpawnSpec) -> io::Result<LinuxProcess> {
        self.spawn_process_with(spec, SpawnOptions::default())
    }

    pub(crate) fn spawn_process_with(
        &self,
        spec: &SpawnSpec,
        options: SpawnOptions,
    ) -> io::Result<LinuxProcess> {
        if !spec.exe.is_absolute() {
            // chdir("/") runs before execve, so a relative path would be
            // resolved against `/`, not against the caller's directory.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the sandbox worker path must be absolute",
            ));
        }
        if spec.process_mb == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "process_mb must be greater than 0",
            ));
        }
        let exe = CString::new(spec.exe.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the sandbox worker path contains a NUL byte",
            )
        })?;
        let (reply, answer) = mpsc::channel();
        self.tx
            .send(Job {
                exe,
                process_mb: spec.process_mb,
                force_close_loop: options.force_close_loop,
                reply,
            })
            .map_err(|_| io::Error::other("the sandbox spawner thread has ended"))?;
        let spawned = answer
            .recv()
            .map_err(|_| io::Error::other("the sandbox spawner thread has ended"))??;
        LinuxProcess::new(spawned)
    }
}

impl WorkerSpawner for LinuxSpawner {
    fn spawn(&self, spec: &SpawnSpec) -> io::Result<Box<dyn WorkerProcess>> {
        Ok(Box::new(self.spawn_process(spec)?))
    }
}

// ------------------------------------------------------------ spawner thread

fn spawner_main(rx: &mpsc::Receiver<Job>) {
    // Built once, before any fork: the child must not allocate.
    let env: Vec<CString> = WORKER_ENV
        .iter()
        .map(|(name, value)| {
            CString::new(format!("{name}={value}")).expect("static env has no NUL")
        })
        .collect();
    let mut envp: Vec<*const c_char> = env.iter().map(|c| c.as_ptr()).collect();
    envp.push(std::ptr::null());

    while let Ok(job) = rx.recv() {
        let result = spawn_one(&job, &envp);
        // The requester may have gone away; nothing to do about it.
        let _ = job.reply.send(result);
    }
}

/// Everything the child needs, as plain data and raw pointers into storage
/// that outlives the `fork` (it is a copy in the child's address space).
struct ChildArgs {
    stdin_fd: c_int,
    stdout_fd: c_int,
    stderr_fd: c_int,
    /// The host process id, recorded before the fork (§3.4).
    parent_pid: libc::pid_t,
    exe: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    rl_as: libc::rlimit,
    rl_nofile: libc::rlimit,
    rl_stack: libc::rlimit,
    rl_core: libc::rlimit,
    /// Fallback close loop bound: the parent's `RLIMIT_NOFILE` soft limit.
    scan_limit: c_int,
    force_close_loop: bool,
}

fn spawn_one(job: &Job, envp: &[*const c_char]) -> io::Result<Spawned> {
    let (stdin_r, stdin_w) = pipe()?;
    let (stdout_r, stdout_w) = pipe()?;
    let (stderr_r, stderr_w) = pipe()?;

    let argv: [*const c_char; 2] = [job.exe.as_ptr(), std::ptr::null()];
    let process_bytes = u64::from(job.process_mb) * 1024 * 1024;
    let args = ChildArgs {
        stdin_fd: stdin_r.as_raw_fd(),
        stdout_fd: stdout_w.as_raw_fd(),
        stderr_fd: stderr_w.as_raw_fd(),
        // SAFETY: getpid has no preconditions.
        parent_pid: unsafe { libc::getpid() },
        exe: job.exe.as_ptr(),
        argv: argv.as_ptr(),
        envp: envp.as_ptr(),
        rl_as: rlimit(process_bytes),
        rl_nofile: rlimit(WORKER_NOFILE),
        rl_stack: rlimit(WORKER_STACK_BYTES),
        rl_core: rlimit(0),
        scan_limit: nofile_scan_limit(),
        force_close_loop: job.force_close_loop,
    };

    // SAFETY: fork in a multithreaded process; the child below calls only
    // async-signal-safe functions and never returns.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        // SAFETY: we are the child; `args` points at memory that is valid in
        // the child's copy of the address space.
        0 => unsafe { exec_child(&args) },
        pid => {
            // The child's ends are closed when this function returns.
            drop((stdin_r, stdout_w, stderr_w));
            Ok(Spawned {
                pid,
                stdin: stdin_w,
                stdout: stdout_r,
                stderr: stderr_r,
            })
        }
    }
}

/// The child between `fork` and `execve` (§3.4 order). Async-signal-safe
/// only: raw libc calls, no allocation, no panic, no destructor. A failed
/// step ends the child with `_exit(code)`, see [`child_exit`].
///
/// # Safety
///
/// Must be called only in the freshly forked child, with `a` pointing at
/// valid data (NUL-terminated `exe`, NULL-terminated `argv` and `envp`).
unsafe fn exec_child(a: &ChildArgs) -> ! {
    // SAFETY: every call below is async-signal-safe (POSIX.1-2008 lists
    // dup2, close, prctl-as-syscall, getppid, setrlimit, chdir, execve and
    // _exit; close_range is a plain syscall) and gets valid arguments.
    unsafe {
        // 1. exactly fds 0, 1 and 2 (the parent moved every pipe end above 2,
        //    so no dup2 clobbers a source). dup2 clears O_CLOEXEC on the copy.
        if libc::dup2(a.stdin_fd, 0) < 0
            || libc::dup2(a.stdout_fd, 1) < 0
            || libc::dup2(a.stderr_fd, 2) < 0
        {
            libc::_exit(child_exit::DUP2);
        }
        // 2. everything else
        close_inherited(a);
        // 3. die with the spawner thread (and with the host)
        if libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        ) != 0
        {
            libc::_exit(child_exit::PDEATHSIG);
        }
        // 4. the host may have died before step 3 took effect
        if libc::getppid() != a.parent_pid {
            libc::_exit(child_exit::PARENT_DIED);
        }
        // 5. no privilege gain through exec, before the worker runs a line
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) != 0 {
            libc::_exit(child_exit::NO_NEW_PRIVS);
        }
        // 6. rlimits (§9.4)
        if libc::setrlimit(libc::RLIMIT_AS, &a.rl_as) != 0
            || libc::setrlimit(libc::RLIMIT_NOFILE, &a.rl_nofile) != 0
            || libc::setrlimit(libc::RLIMIT_STACK, &a.rl_stack) != 0
            || libc::setrlimit(libc::RLIMIT_CORE, &a.rl_core) != 0
        {
            libc::_exit(child_exit::RLIMIT);
        }
        // 7. working directory `/` (§3.4)
        if libc::chdir(c"/".as_ptr()) != 0 {
            libc::_exit(child_exit::CHDIR);
        }
        // 8. exec with the fixed environment
        libc::execve(a.exe, a.argv, a.envp);
        libc::_exit(child_exit::EXEC)
    }
}

/// `close_range(3, ~0U, 0)`. If it fails (`ENOSYS` before Linux 5.9, or a
/// sandbox that refuses it) or is switched off for a test, close every
/// descriptor from 3 up to the parent's `RLIMIT_NOFILE` soft limit.
///
/// # Safety
///
/// Child-only, see [`exec_child`].
unsafe fn close_inherited(a: &ChildArgs) {
    if !a.force_close_loop {
        // SAFETY: a plain syscall with integer arguments.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3 as c_long,
                u32::MAX as c_long,
                0 as c_long,
            )
        };
        if rc == 0 {
            return;
        }
    }
    let mut fd: c_int = 3;
    while fd < a.scan_limit {
        // SAFETY: closing a descriptor number is always sound; EBADF is ignored.
        unsafe { libc::close(fd) };
        fd += 1;
    }
}

fn rlimit(value: u64) -> libc::rlimit {
    libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    }
}

/// The parent's `RLIMIT_NOFILE` soft limit, bounded by [`FALLBACK_SCAN_CAP`].
fn nofile_scan_limit() -> c_int {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid out-pointer.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    if rc != 0 || lim.rlim_cur == libc::RLIM_INFINITY {
        return FALLBACK_SCAN_CAP;
    }
    c_int::try_from(lim.rlim_cur).map_or(FALLBACK_SCAN_CAP, |n| n.min(FALLBACK_SCAN_CAP))
}

/// A close-on-exec pipe whose both ends are numbered above 2. If the host's
/// own stdio is closed, `pipe2` can return 0, 1 or 2; `dup2(fd, fd)` would
/// then keep `O_CLOEXEC` and the worker would lose that stream.
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (reader, writer) = io::pipe()?; // O_CLOEXEC
    Ok((
        above_stdio(OwnedFd::from(reader))?,
        above_stdio(OwnedFd::from(writer))?,
    ))
}

fn above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
    if fd.as_raw_fd() > 2 {
        return Ok(fd);
    }
    // SAFETY: F_DUPFD_CLOEXEC on an open descriptor returns a new one.
    let moved = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if moved < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `moved` is a fresh descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(moved) })
}

// ------------------------------------------------------------- worker handle

/// A running worker. Dropping it kills and reaps the process.
pub struct LinuxProcess {
    pid: libc::pid_t,
    stdin: Option<File>,
    closed_stdin: ClosedStdin,
    stdout: File,
    /// Bytes read from stdout that do not yet form a complete frame.
    buf: Vec<u8>,
    eof: bool,
    exit: Option<ExitKind>,
    stderr_head: Arc<Mutex<Vec<u8>>>,
}

/// What `stdin()` hands out after `close_stdin()`.
struct ClosedStdin;

impl Write for ClosedStdin {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl LinuxProcess {
    fn new(spawned: Spawned) -> io::Result<Self> {
        let stderr_head = Arc::new(Mutex::new(Vec::new()));
        let process = Self {
            pid: spawned.pid,
            stdin: Some(File::from(spawned.stdin)),
            closed_stdin: ClosedStdin,
            stdout: File::from(spawned.stdout),
            buf: Vec::new(),
            eof: false,
            exit: None,
            stderr_head: Arc::clone(&stderr_head),
        };
        // On error `process` is dropped, which kills and reaps the worker.
        let stderr = spawned.stderr;
        thread::Builder::new()
            .name("atlas-duck-worker-stderr".to_string())
            .spawn(move || drain_stderr(stderr, &stderr_head))?;
        Ok(process)
    }

    /// The first [`STDERR_CAP_BYTES`] bytes the worker wrote to stderr so far
    /// (§3.4: capped at 64 KiB; the rest is read and discarded). Never log
    /// these.
    pub fn stderr_head(&self) -> Vec<u8> {
        self.stderr_head
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Splits one complete frame off the front of `buf`.
    fn take_frame(&mut self, max: usize) -> io::Result<Option<Vec<u8>>> {
        let Some(header) = self.buf.first_chunk::<4>() else {
            return Ok(None);
        };
        let len = usize::try_from(u32::from_be_bytes(*header)).unwrap_or(usize::MAX);
        if len > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("worker frame of {len} bytes exceeds the limit of {max}"),
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

    /// One `waitpid(WNOHANG)`; caches the exit status.
    fn try_reap(&mut self) -> io::Result<Option<ExitKind>> {
        let mut status: c_int = 0;
        loop {
            // SAFETY: `status` is a valid out-pointer; the pid is our child.
            let rc = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if rc == 0 {
                return Ok(None);
            }
            if rc < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let exit = decode_wait_status(status);
            self.exit = Some(exit);
            return Ok(Some(exit));
        }
    }
}

fn decode_wait_status(status: c_int) -> ExitKind {
    if libc::WIFSIGNALED(status) {
        ExitKind::Signal(libc::WTERMSIG(status))
    } else {
        ExitKind::Code(libc::WEXITSTATUS(status))
    }
}

impl WorkerProcess for LinuxProcess {
    fn pid(&self) -> u32 {
        u32::try_from(self.pid).unwrap_or(0)
    }

    fn stdin(&mut self) -> &mut dyn Write {
        match self.stdin.as_mut() {
            Some(file) => file,
            None => &mut self.closed_stdin,
        }
    }

    /// `poll(2)` on the stdout pipe with the remaining time, so no reader
    /// thread is needed on Linux. A partial frame stays buffered across a
    /// `TimedOut`.
    fn read_frame_timeout(&mut self, max: usize, d: Duration) -> io::Result<Option<Vec<u8>>> {
        let deadline = deadline_after(d);
        let mut read_once = false;
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
                        "worker closed stdout in the middle of a frame",
                    ))
                };
            }
            let left = deadline.saturating_duration_since(Instant::now());
            // `poll` with 0 ms still reports waiting bytes, so a worker that
            // trickles bytes would hold the host past `d`: once the deadline
            // has passed and this call has read at least once, stop.
            if read_once && left.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no complete frame from the worker in time",
                ));
            }
            if !poll_readable(self.stdout.as_raw_fd(), left)? {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no complete frame from the worker in time",
                ));
            }
            let mut chunk = [0u8; 8192];
            read_once = true;
            match self.stdout.read(&mut chunk) {
                Ok(0) => self.eof = true,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    fn wait_timeout(&mut self, d: Duration) -> io::Result<Option<ExitKind>> {
        if let Some(exit) = self.exit {
            return Ok(Some(exit));
        }
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
        if self.exit.is_some() {
            // Reaped: the pid may already belong to someone else.
            return Ok(());
        }
        // SAFETY: the pid is our unreaped child (a zombie keeps its pid).
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(e)
        }
    }
}

impl Drop for LinuxProcess {
    fn drop(&mut self) {
        if self.exit.is_none() {
            let _ = self.kill();
            let _ = self.wait_timeout(Duration::from_secs(2));
        }
    }
}

/// `now + d`, saturating: an `Instant` overflow means "far in the future".
fn deadline_after(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d)
        .unwrap_or_else(|| now + Duration::from_secs(60 * 60 * 24 * 365))
}

/// `poll(2)` for `POLLIN` with a timeout rounded up to whole milliseconds.
/// `POLLHUP` and errors count as readable: the following `read` reports them.
fn poll_readable(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let deadline = deadline_after(timeout);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let millis = left.as_millis() + u128::from(!left.subsec_nanos().is_multiple_of(1_000_000));
        let millis = c_int::try_from(millis).unwrap_or(c_int::MAX);
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, millis) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        return Ok(rc > 0);
    }
}

/// Reads the worker's stderr to EOF so it never blocks on a full pipe; keeps
/// the first [`STDERR_CAP_BYTES`] bytes and discards the rest.
fn drain_stderr(fd: OwnedFd, head: &Mutex<Vec<u8>>) {
    let mut file = File::from(fd);
    let mut chunk = [0u8; 4096];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let mut kept = head.lock().unwrap_or_else(PoisonError::into_inner);
                let room = STDERR_CAP_BYTES.saturating_sub(kept.len());
                kept.extend_from_slice(&chunk[..n.min(room)]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use atlas_duck_ipc::sandbox::frame::write_frame;

    use super::*;

    const CAT: &str = "/bin/cat";
    const SH: &str = "/bin/sh";

    fn spec(exe: &str) -> SpawnSpec {
        SpawnSpec {
            exe: PathBuf::from(exe),
            process_mb: 512,
        }
    }

    /// `cat` echoes frames, so a round trip proves the child has exec'd and
    /// is running (its `/proc` entries are then the post-exec ones).
    fn wait_until_running(p: &mut LinuxProcess) {
        write_frame(&mut p.stdin(), b"ping").expect("write ping");
        let echoed = p
            .read_frame_timeout(1024, Duration::from_secs(5))
            .expect("read echo")
            .expect("frame");
        assert_eq!(echoed, b"ping");
    }

    fn fd_numbers(pid: u32) -> Vec<u32> {
        let mut fds: Vec<u32> = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .expect("read /proc/<pid>/fd")
            .map(|e| {
                e.expect("fd entry")
                    .file_name()
                    .to_string_lossy()
                    .parse()
                    .expect("numeric fd")
            })
            .collect();
        fds.sort_unstable();
        fds
    }

    fn open_inheritable(path: &Path) -> c_int {
        let c = CString::new(path.as_os_str().as_bytes()).expect("path");
        // SAFETY: valid NUL-terminated path; no O_CLOEXEC on purpose.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
        assert!(fd >= 0, "open: {}", io::Error::last_os_error());
        fd
    }

    #[test]
    fn close_loop_fallback_closes_inherited_descriptors() {
        let leaked = open_inheritable(Path::new("/dev/null"));
        let spawner = LinuxSpawner::start().expect("start");
        let mut p = spawner
            .spawn_process_with(
                &spec(CAT),
                SpawnOptions {
                    force_close_loop: true,
                },
            )
            .expect("spawn");
        wait_until_running(&mut p);
        assert_eq!(fd_numbers(p.pid()), vec![0, 1, 2], "leaked fd was {leaked}");
        // SAFETY: closing the descriptor opened above.
        unsafe { libc::close(leaked) };
    }

    #[test]
    fn close_range_closes_inherited_descriptors() {
        let leaked = open_inheritable(Path::new("/dev/null"));
        let spawner = LinuxSpawner::start().expect("start");
        let mut p = spawner.spawn_process(&spec(CAT)).expect("spawn");
        wait_until_running(&mut p);
        assert_eq!(fd_numbers(p.pid()), vec![0, 1, 2], "leaked fd was {leaked}");
        // SAFETY: closing the descriptor opened above.
        unsafe { libc::close(leaked) };
    }

    #[test]
    fn the_parent_sets_no_new_privs_before_exec_for_any_binary() {
        let spawner = LinuxSpawner::start().expect("start");
        let mut p = spawner.spawn_process(&spec(CAT)).expect("spawn");
        wait_until_running(&mut p);
        let status = std::fs::read_to_string(format!("/proc/{}/status", p.pid())).expect("status");
        assert!(status.contains("NoNewPrivs:\t1"), "{status}");
        assert_eq!(
            std::fs::read_link(format!("/proc/{}/cwd", p.pid())).expect("cwd"),
            PathBuf::from("/")
        );
    }

    #[test]
    fn a_failed_exec_is_the_exit_code_127() {
        let spawner = LinuxSpawner::start().expect("start");
        let mut p = spawner
            .spawn_process(&spec("/nonexistent/atlas-duck-sandbox"))
            .expect("fork succeeds, exec fails in the child");
        assert_eq!(
            p.wait_timeout(Duration::from_secs(5)).expect("wait"),
            Some(ExitKind::Code(child_exit::EXEC))
        );
        // The stdout of a dead worker is a clean EOF.
        assert!(
            p.read_frame_timeout(1024, Duration::from_secs(1))
                .expect("eof")
                .is_none()
        );
    }

    #[test]
    fn bad_specs_are_refused_before_any_fork() {
        let spawner = LinuxSpawner::start().expect("start");
        let relative = spawner.spawn_process(&spec("atlas-duck-sandbox"));
        assert_eq!(
            relative.err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
        let nul = spawner.spawn_process(&spec("/bin/ca\0t"));
        assert_eq!(
            nul.err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
        let zero = spawner.spawn_process(&SpawnSpec {
            exe: PathBuf::from(CAT),
            process_mb: 0,
        });
        assert_eq!(
            zero.err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn stderr_is_drained_and_capped_at_64_kib() {
        let spawner = LinuxSpawner::start().expect("start");
        let mut p = spawner.spawn_process(&spec(SH)).expect("spawn");
        // 100 000 bytes on stderr: more than a pipe holds, so without the
        // drain thread `head` would block forever.
        p.stdin()
            .write_all(b"head -c 100000 /dev/zero >&2\nexit 3\n")
            .expect("script");
        p.close_stdin();
        assert_eq!(
            p.wait_timeout(Duration::from_secs(10)).expect("wait"),
            Some(ExitKind::Code(3))
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while p.stderr_head().len() < STDERR_CAP_BYTES && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(p.stderr_head().len(), STDERR_CAP_BYTES);
    }

    #[test]
    fn a_dropped_process_is_killed_and_reaped() {
        let spawner = LinuxSpawner::start().expect("start");
        let mut p = spawner.spawn_process(&spec(CAT)).expect("spawn");
        wait_until_running(&mut p);
        let pid = p.pid();
        drop(p);
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "zombie left behind"
        );
    }

    #[test]
    fn a_partial_frame_survives_a_timeout() {
        let spawner = LinuxSpawner::start().expect("start");
        let mut p = spawner.spawn_process(&spec(CAT)).expect("spawn");
        // Header and half of a 4-byte payload; the rest comes later.
        p.stdin()
            .write_all(&[0, 0, 0, 4, b'a', b'b'])
            .expect("part 1");
        let timed_out = p
            .read_frame_timeout(1024, Duration::from_millis(100))
            .expect_err("incomplete frame");
        assert_eq!(timed_out.kind(), io::ErrorKind::TimedOut);
        p.stdin().write_all(b"cd").expect("part 2");
        assert_eq!(
            p.read_frame_timeout(1024, Duration::from_secs(5))
                .expect("frame"),
            Some(b"abcd".to_vec())
        );
    }

    #[test]
    fn a_worker_that_trickles_bytes_cannot_hold_the_host_past_the_deadline() {
        let spawner = LinuxSpawner::start().expect("start");
        let mut p = spawner.spawn_process(&spec(SH)).expect("spawn");
        // A header announcing 65535 bytes, then one byte every 10 ms: the
        // frame never completes within the deadline.
        p.stdin()
            .write_all(b"printf '\\0\\0\\377\\377'\nwhile :; do printf x; sleep 0.01; done\n")
            .expect("script");
        let start = Instant::now();
        let err = p
            .read_frame_timeout(1 << 20, Duration::from_millis(200))
            .expect_err("incomplete frame");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn an_oversize_frame_is_invalid_data() {
        let spawner = LinuxSpawner::start().expect("start");
        let mut p = spawner.spawn_process(&spec(CAT)).expect("spawn");
        p.stdin()
            .write_all(&[0, 0, 4, 0])
            .expect("header of 1024 bytes");
        let err = p
            .read_frame_timeout(512, Duration::from_secs(5))
            .expect_err("too large");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn stdin_after_close_is_a_broken_pipe_and_close_twice_is_a_no_op() {
        let spawner = LinuxSpawner::start().expect("start");
        let mut p = spawner.spawn_process(&spec(CAT)).expect("spawn");
        p.close_stdin();
        p.close_stdin();
        let err = p.stdin().write_all(b"x").expect_err("closed");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        // cat exits on EOF.
        assert_eq!(
            p.wait_timeout(Duration::from_secs(5)).expect("wait"),
            Some(ExitKind::Code(0))
        );
        assert!(p.kill().is_ok(), "kill after reap is Ok");
    }
}
