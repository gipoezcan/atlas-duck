//! Linux spawn routine for the sandbox worker (§3.4, §9.4).
//!
//! Never `std::process::Command`: the worker is forked from **one dedicated,
//! long-lived spawner thread** (`PR_SET_PDEATHSIG` fires when the *thread*
//! that forked the child exits, so a short-lived forking thread would kill
//! the worker shortly after spawn). The child runs only async-signal-safe
//! steps, in this order: `dup2` the pipes to 0/1/2, `close_range(3, ~0U, 0)`,
//! `PR_SET_PDEATHSIG(SIGKILL)`, `getppid()` against the host pid recorded
//! before the fork (`_exit` if the parent already died), `PR_SET_NO_NEW_PRIVS`,
//! rlimits (`AS`, `NOFILE`, `STACK` = 8 MiB, `CORE` = 0), `chdir("/")`, then
//! `execve` with the fixed environment allowlist.

mod spawner;

use std::fs;
use std::path::Path;

use crate::spawn::{SpawnHook, ThreadConfinement};

pub use spawner::{LinuxProcess, LinuxSpawner};

/// Name of the one long-lived thread that forks workers (§3.4). The kernel
/// keeps only the first 15 bytes in `/proc/<pid>/task/<tid>/comm`
/// (`atlas-duck-spaw`).
pub const SPAWNER_THREAD_NAME: &str = "atlas-duck-spawner";

/// The worker's whole environment (§3.4: `TZ=UTC0`, plus `MALLOC_ARENA_MAX=1`
/// on Linux). `TZ=UTC0` keeps libc from opening `/etc/localtime` under the
/// confinement (§9.4).
pub const WORKER_ENV: [(&str, &str); 2] = [("TZ", "UTC0"), ("MALLOC_ARENA_MAX", "1")];

/// `RLIMIT_STACK` of the worker (§9.3, §9.4): the JS thread is the main
/// thread and its native stack is 8 MiB.
pub const WORKER_STACK_BYTES: u64 = 8 * 1024 * 1024;

/// `RLIMIT_NOFILE` of the worker. Plan decision: the spec names `NOFILE`
/// without a value. The worker holds fds 0, 1 and 2 only; 32 leaves room for
/// the Landlock ruleset fd (T17) and a few libc-internal descriptors.
pub const WORKER_NOFILE: u64 = 32;

/// Cap of the worker stderr bytes the host keeps (§3.4: 64 KiB). Bytes past
/// the cap are read and discarded so the worker never blocks on stderr.
pub const STDERR_CAP_BYTES: usize = 64 * 1024;

/// `_exit` codes of the child between `fork` and `execve`. The child cannot
/// report an errno (no allocation, and `close_range` would close an error
/// pipe), so a failed step shows up as the worker's exit code: the probe
/// runner records it as `Evidence::Exited(code)` (or `NoReady`).
pub mod child_exit {
    /// `dup2` of a pipe end onto fd 0, 1 or 2 failed.
    pub const DUP2: i32 = 111;
    /// `PR_SET_PDEATHSIG` failed.
    pub const PDEATHSIG: i32 = 113;
    /// The host process died between `fork` and the `getppid()` check.
    pub const PARENT_DIED: i32 = 114;
    /// `PR_SET_NO_NEW_PRIVS` failed.
    pub const NO_NEW_PRIVS: i32 = 115;
    /// One of the four `setrlimit` calls failed.
    pub const RLIMIT: i32 = 116;
    /// `chdir("/")` failed.
    pub const CHDIR: i32 = 117;
    /// `execve` failed (missing or not executable binary, `ENOEXEC`, ...).
    pub const EXEC: i32 = 127;
}

/// `Seccomp:` and `NoNewPrivs:` of one task, from `/proc/<pid>/task/<tid>/status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskStatus {
    pub(crate) seccomp: u32,
    pub(crate) no_new_privs: u32,
}

/// Parses the two fields out of a `status` file. A missing line (kernel
/// without seccomp, or older than 4.10 for `NoNewPrivs`) reads as 0: the task
/// is then reported as not confined, which fails the floor.
pub(crate) fn parse_task_status(status: &str) -> TaskStatus {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().parse::<u32>().ok())
            .unwrap_or(0)
    };
    TaskStatus {
        seccomp: field("Seccomp:"),
        no_new_privs: field("NoNewPrivs:"),
    }
}

/// Reads `<proc_root>/<pid>/task/*/status` and folds the tasks into a
/// [`ThreadConfinement`]. `None` when the check cannot be made: the task
/// directory is unreadable, no task is left (the worker died), or a status
/// file cannot be read. A task that exits while the directory is walked is
/// skipped.
pub(crate) fn read_thread_confinement(proc_root: &Path, pid: u32) -> Option<ThreadConfinement> {
    let dir = proc_root.join(pid.to_string()).join("task");
    let mut tasks = 0u32;
    let mut all_seccomp_2 = true;
    let mut all_no_new_privs_1 = true;
    for entry in fs::read_dir(&dir).ok()? {
        let entry = entry.ok()?;
        let text = match fs::read_to_string(entry.path().join("status")) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        let status = parse_task_status(&text);
        tasks += 1;
        all_seccomp_2 &= status.seccomp == 2;
        all_no_new_privs_1 &= status.no_new_privs == 1;
    }
    (tasks > 0).then_some(ThreadConfinement {
        tasks,
        all_seccomp_2,
        all_no_new_privs_1,
    })
}

/// [`SpawnHook`] for Linux. §9.4 words the "every thread is confined" check
/// as the worker reading `/proc/self/task/*/status`, but the confined worker
/// cannot open files (`open*` returns `EACCES`, Landlock has no rules), so the
/// host reads `/proc/<worker pid>/task/*/status` after `probe.ready`
/// (`Seccomp: 2` and `NoNewPrivs: 1` in every task).
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcTaskStatusHook;

impl SpawnHook for ProcTaskStatusHook {
    fn after_ready(&self, pid: u32) -> Option<ThreadConfinement> {
        read_thread_confinement(Path::new("/proc"), pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFINED_STATUS: &str = "Name:\tatlas-duck-sand\nUmask:\t0022\nState:\tS (sleeping)\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n";
    const PLAIN_STATUS: &str = "Name:\tcat\nState:\tS (sleeping)\nNoNewPrivs:\t0\nSeccomp:\t0\n";

    fn proc_fixture(tasks: &[(&str, &str)]) -> tempdir::Dir {
        let dir = tempdir::Dir::new();
        for (tid, status) in tasks {
            let task = dir.path().join("77").join("task").join(tid);
            fs::create_dir_all(&task).expect("create task dir");
            fs::write(task.join("status"), status).expect("write status");
        }
        dir
    }

    /// Minimal temp dir (the crate has no `tempfile` dependency).
    mod tempdir {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicUsize, Ordering};

        static N: AtomicUsize = AtomicUsize::new(0);

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new() -> Self {
                let n = N.fetch_add(1, Ordering::SeqCst);
                let p =
                    std::env::temp_dir().join(format!("atlas-duck-t16-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&p).expect("create temp dir");
                Dir(p)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn parses_seccomp_and_no_new_privs() {
        assert_eq!(
            parse_task_status(CONFINED_STATUS),
            TaskStatus {
                seccomp: 2,
                no_new_privs: 1
            }
        );
        assert_eq!(
            parse_task_status(PLAIN_STATUS),
            TaskStatus {
                seccomp: 0,
                no_new_privs: 0
            }
        );
    }

    #[test]
    fn missing_lines_read_as_unconfined() {
        assert_eq!(
            parse_task_status("Name:\tx\n"),
            TaskStatus {
                seccomp: 0,
                no_new_privs: 0
            }
        );
        // "Seccomp_filters:" must not be mistaken for "Seccomp:".
        assert_eq!(
            parse_task_status("Seccomp_filters:\t2\n"),
            TaskStatus {
                seccomp: 0,
                no_new_privs: 0
            }
        );
    }

    #[test]
    fn every_task_must_be_confined() {
        let all = proc_fixture(&[("77", CONFINED_STATUS), ("78", CONFINED_STATUS)]);
        assert_eq!(
            read_thread_confinement(all.path(), 77),
            Some(ThreadConfinement {
                tasks: 2,
                all_seccomp_2: true,
                all_no_new_privs_1: true
            })
        );
        assert!(read_thread_confinement(all.path(), 77).is_some_and(|t| t.all_confined()));

        let one_loose = proc_fixture(&[("77", CONFINED_STATUS), ("78", PLAIN_STATUS)]);
        assert_eq!(
            read_thread_confinement(one_loose.path(), 77),
            Some(ThreadConfinement {
                tasks: 2,
                all_seccomp_2: false,
                all_no_new_privs_1: false
            })
        );
    }

    #[test]
    fn a_missing_pid_or_empty_task_dir_is_not_checkable() {
        let dir = proc_fixture(&[("77", CONFINED_STATUS)]);
        assert_eq!(read_thread_confinement(dir.path(), 999), None);
        fs::create_dir_all(dir.path().join("5").join("task")).expect("empty task dir");
        assert_eq!(read_thread_confinement(dir.path(), 5), None);
    }
}
