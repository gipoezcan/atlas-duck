//! Spawner abstraction for the sandbox worker (§3.4).
//!
//! The probe runner ([`crate::probe::run_probes`]) only talks to these
//! traits, so its scoring rules are tested with a fake spawner before any real
//! per-OS spawn routine exists (T16 Linux, T18 macOS, T19 Windows).

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::limits::MemoryWatch;

/// `process_mb` default from the §9.4 limits table.
pub const DEFAULT_PROCESS_MB: u32 = 512;

/// What to spawn. The worker gets exactly three pipes (stdin, stdout,
/// stderr), the fixed environment allowlist and the fixed working directory
/// of §3.4; those are properties of each OS routine, not of the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnSpec {
    /// The canonical sandbox binary in the install dir (§3.4).
    pub exe: PathBuf,
    /// Process memory limit in MiB (Linux `RLIMIT_AS`, Windows job object,
    /// macOS host-side watchdog in M8), §9.4.
    pub process_mb: u32,
}

/// How a worker process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitKind {
    /// Normal exit with this code (on Windows: the process exit code,
    /// including NTSTATUS values such as `0xC0000005` as `i32`).
    Code(i32),
    /// Unix: terminated by this signal number.
    Signal(i32),
}

/// One running worker process.
///
/// Contract for implementations (T16, T18, T19):
/// - `read_frame_timeout` reads one u32-BE length-delimited frame (§3.3) from
///   the worker's stdout and returns its payload. Implementations run one
///   reader thread per worker, because pipe reads have no timeout on Windows.
///   * `Ok(Some(payload))`: one complete frame.
///   * `Ok(None)`: clean EOF before a frame header (the worker closed stdout
///     or exited).
///   * `Err(e)` with `e.kind() == ErrorKind::TimedOut`: no complete frame
///     within `d`.
///   * `Err(e)` with `e.kind() == ErrorKind::InvalidData`: oversize frame
///     (`> max`) or truncated frame. The caller kills the worker.
/// - `close_stdin` closes the host end of stdin; the worker exits on EOF
///   (§3.4). Calling it twice is a no-op.
/// - `wait_timeout` returns `Ok(None)` if the process has not exited within
///   `d`, and reaps it when it has.
/// - `kill` terminates the process (`SIGKILL` / `TerminateJobObject`); killing
///   an already exited process is `Ok(())`.
/// - `into_parts` (M8, Δ2) splits the worker for a script run; see
///   [`WorkerParts`]. The probe runner never calls it and keeps using the
///   methods above.
pub trait WorkerProcess {
    /// OS process id of the worker.
    fn pid(&self) -> u32;
    /// Host end of the worker's stdin pipe.
    fn stdin(&mut self) -> &mut dyn io::Write;
    /// See the trait documentation.
    fn read_frame_timeout(&mut self, max: usize, d: Duration) -> io::Result<Option<Vec<u8>>>;
    /// See the trait documentation.
    fn close_stdin(&mut self);
    /// See the trait documentation.
    fn wait_timeout(&mut self, d: Duration) -> io::Result<Option<ExitKind>>;
    /// See the trait documentation.
    fn kill(&mut self) -> io::Result<()>;

    /// Splits the worker into its three byte streams, a kill handle and a
    /// reaper (Δ2, PD-137), for the bridge's reader, writer, stderr and reaper
    /// threads. It consumes the worker, so it is called once, and the methods
    /// above are gone afterwards. It may follow `read_frame_timeout` calls:
    /// bytes the spawner already read and did not return as a frame are the
    /// first bytes of [`WorkerIo::stdout`].
    ///
    /// The default is `Unsupported`: only the real spawners split (the probe
    /// runner's fakes do not need to). Every real process type must override
    /// it: a script run on a type that inherits the default fails with
    /// `StartRunError::Spawn(Unsupported)`. Requirement for M8 T11: the
    /// degraded Windows process type overrides `into_parts` (as
    /// `WindowsProcess` does), and a `sandbox_runs` test splits a degraded
    /// worker through `Box<dyn WorkerProcess>`.
    fn into_parts(self: Box<Self>) -> io::Result<WorkerParts> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// The host's watch of this worker's memory for a script run (M8 Task 9, §9.4
    /// `process_mb`): Windows the job's completion port, macOS the footprint
    /// watchdog. The bridge takes it once, before [`WorkerProcess::into_parts`].
    ///
    /// The default is `None`: Linux needs none (`RLIMIT_AS` makes the worker
    /// exit `EXIT_PROCESS_LIMIT`, R3), nor do the fakes. Requirement for M8 T11:
    /// the degraded Windows process type overrides it like `WindowsProcess`.
    fn memory_watch(&mut self) -> io::Result<Option<Box<dyn MemoryWatch>>> {
        Ok(None)
    }
}

/// A worker split for a script run (Δ2): the pid, the three pipes, the kill
/// handle and the reaper.
///
/// Dropping every part kills the worker: on Windows the last job handle closes
/// (`KILL_ON_JOB_CLOSE`); on Unix a reaper dropped without
/// [`Reaper::wait`] kills the worker and reaps it for up to 2 s. A bridge
/// always drives the reaper to the end.
pub struct WorkerParts {
    /// OS process id of the worker (for the macOS footprint watchdog and the
    /// Linux `/proc` check; never signalled directly).
    pub pid: u32,
    /// The worker's stdin, stdout and stderr.
    pub io: WorkerIo,
    /// Kills the worker; non-blocking and idempotent (PD-137).
    pub kill: Arc<dyn KillHandle>,
    /// Waits for the worker's exit and reaps it.
    pub reaper: Box<dyn Reaper>,
}

/// The host ends of the worker's three pipes as plain byte streams (§3.4:
/// exactly three handles). Reads block until bytes arrive or the worker's end
/// closes (EOF, `Ok(0)`); a kill closes them.
pub struct WorkerIo {
    /// Host end of the worker's stdin. Dropping it is the stdin EOF the worker
    /// exits on.
    pub stdin: Box<dyn Write + Send>,
    /// Host end of the worker's stdout, starting with any bytes the spawner
    /// had already read and not returned as a frame.
    pub stdout: Box<dyn Read + Send>,
    /// Host end of the worker's stderr: exactly its first 64 KiB (§3.4), in
    /// order and without gaps, on every OS, then EOF once the worker's stderr
    /// closes. The spawner's drain thread hands its reader over: the bytes it
    /// kept so far come first, then what it reads from then on, until the
    /// stream holds 64 KiB. The thread reads to the worker's EOF and discards
    /// the rest, so the worker never blocks on stderr, whether the stream is
    /// read, left unread, or dropped.
    pub stderr: Box<dyn Read + Send>,
}

/// Kills a worker without blocking (PD-137, M3 final review M-1): Windows
/// `TerminateJobObject` on a job handle the handle owns, Linux
/// `pidfd_send_signal(SIGKILL)` (a pid `kill` guarded by the reap flag when the
/// kernel has no pidfd), macOS `kill(SIGKILL)` guarded by the reap flag.
///
/// `kill` never waits for the exit, takes no lock that a reader, writer or
/// reaper thread holds across a blocking call, and never signals a reaped pid.
/// Once one OS call succeeded, a further call is a no-op; a failed OS call is
/// logged and leaves the handle armed, so the next call tries again (Linux
/// falls back to the guarded pid kill and Windows to `TerminateProcess` within
/// the same call). See [`crate::kill`].
///
/// Precondition on Unix: sandbox-host is the worker's sole reaper. `SIGCHLD`
/// must be neither `SIG_IGN` nor `SA_NOCLDWAIT` (the Linux and macOS spawners
/// refuse to spawn otherwise), and nothing else in the process may wait for the
/// worker (no `waitpid(-1)`). A reaper that finds the worker reaped elsewhere
/// (`ECHILD`) returns that error and disarms the handle.
pub trait KillHandle: Send + Sync {
    /// Kills the worker (see the trait documentation).
    fn kill(&self);
}

/// Waits for a worker's exit and reaps it, on a thread of its own.
///
/// On Unix `wait` fails with `ECHILD` when something else reaped the worker
/// (the [`KillHandle`] precondition was broken); the exit status is then lost.
pub trait Reaper: Send {
    /// Blocks until the worker exited, reaps it and returns how it ended.
    fn wait(self: Box<Self>) -> io::Result<ExitKind>;
}

/// Starts worker processes (one per probe, see [`crate::probe::run_probes`]).
pub trait WorkerSpawner {
    /// Spawns one worker. An error means no process exists.
    fn spawn(&self, spec: &SpawnSpec) -> io::Result<Box<dyn WorkerProcess>>;

    /// Windows scoring control (§9.4): the same worker started WITHOUT any
    /// confinement. The probe runner uses it only to run a few probes whose
    /// answer outside the sandbox is the control for the confined answer
    /// (see [`crate::winscore`]); its `probe.ready` is not evidence of
    /// anything. The default is `Unsupported`; only the Windows spawner has it.
    fn spawn_control(&self, _spec: &SpawnSpec) -> io::Result<Box<dyn WorkerProcess>> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Host-side check that runs after the worker sent `probe.ready` (so it has
/// confined itself) and before the probe request is sent.
///
/// Linux (T16 `ProcTaskStatusHook`) reads `/proc/<pid>/task/*/status` from
/// the host. §9.4 words the check as the worker reading
/// `/proc/self/task/*/status`, but the confined worker cannot open files
/// (`open*` returns `EACCES`, Landlock has no rules), so the host reads it.
/// `None` means the check could not be made, which fails the floor.
pub trait SpawnHook {
    /// Inspects the worker with this pid.
    fn after_ready(&self, pid: u32) -> Option<ThreadConfinement>;
}

/// Result of the Linux per-thread confinement check (§9.4: `Seccomp: 2` and
/// `NoNewPrivs: 1` in every task's `status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ThreadConfinement {
    /// Number of tasks (threads) found.
    pub tasks: u32,
    /// Every task shows `Seccomp: 2` (filter mode).
    pub all_seccomp_2: bool,
    /// Every task shows `NoNewPrivs: 1`.
    pub all_no_new_privs_1: bool,
}

impl ThreadConfinement {
    /// True when every thread is confined and at least one task was seen.
    pub fn all_confined(&self) -> bool {
        self.tasks > 0 && self.all_seccomp_2 && self.all_no_new_privs_1
    }
}
