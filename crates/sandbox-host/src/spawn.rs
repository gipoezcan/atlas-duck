//! Spawner abstraction for the sandbox worker (§3.4).
//!
//! The probe runner ([`crate::probe::run_probes`]) only talks to these
//! traits, so its scoring rules are tested with a fake spawner before any real
//! per-OS spawn routine exists (T16 Linux, T18 macOS, T19 Windows).

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;

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
