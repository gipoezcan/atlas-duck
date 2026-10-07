//! T16: the §3.4 Linux spawn routine, observed from the host through `/proc`.
//!
//! The test process plays "the app": it calls `set_non_dumpable()` first
//! (M1 has no app-side probe wiring before T20). The worker is
//! `CARGO_BIN_EXE_atlas-duck-sandbox`, or the file named by
//! `ATLAS_DUCK_SANDBOX_BIN` (the Fedora job and installed packages).
//!
//! CI: the `rust` job leg `ubuntu-22.04` runs this file in the step
//! "Linux spawn routine (T16, §3.4)"; read `test result: ok. 8 passed`.

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Once;
use std::thread;
use std::time::Duration;

use atlas_duck_app_lib::startup::crash::set_non_dumpable;
use atlas_duck_ipc::sandbox::WORKER_FRAME_MAX_BYTES;
use atlas_duck_ipc::sandbox::frame::write_frame;
use atlas_duck_ipc::sandbox::probe::{
    LOOPBACK_PROBE_ADDR, M_PROBE_READY, M_PROBE_RESULT, M_PROBE_RUN, PUBLIC_PROBE_ADDR, ProbeId,
    ProbeReady, ProbeRequest, ProbeResultMsg, decode_notification, encode_notification,
};
use atlas_duck_sandbox_host::linux::{
    LinuxProcess, LinuxSpawner, ProcTaskStatusHook, SPAWNER_THREAD_NAME, WORKER_ENV, WORKER_NOFILE,
    WORKER_STACK_BYTES,
};
use atlas_duck_sandbox_host::spawn::{
    DEFAULT_PROCESS_MB, ExitKind, SpawnHook, SpawnSpec, WorkerProcess,
};

const WAIT: Duration = Duration::from_secs(10);

fn worker_exe() -> PathBuf {
    std::env::var_os("ATLAS_DUCK_SANDBOX_BIN").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_atlas-duck-sandbox")),
        PathBuf::from,
    )
}

/// The test process is "the app": non-dumpable, like a GUI launch (§2.5).
fn act_as_the_app() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| set_non_dumpable().expect("PR_SET_DUMPABLE 0"));
}

fn spec() -> SpawnSpec {
    SpawnSpec {
        exe: worker_exe(),
        process_mb: DEFAULT_PROCESS_MB,
    }
}

/// A worker that has sent `probe.ready` and now waits for `probe.run`.
struct ReadyWorker {
    process: LinuxProcess,
    ready: ProbeReady,
}

fn spawn_ready() -> ReadyWorker {
    act_as_the_app();
    let spawner = LinuxSpawner::start().expect("start the spawner thread");
    let mut process = spawner.spawn_process(&spec()).expect("spawn the worker");
    let frame = match process.read_frame_timeout(WORKER_FRAME_MAX_BYTES, WAIT) {
        Ok(Some(frame)) => frame,
        other => panic!(
            "no probe.ready from {}: {other:?}; worker stderr: {}",
            worker_exe().display(),
            String::from_utf8_lossy(&process.stderr_head())
        ),
    };
    let (method, params) = decode_notification(&frame).expect("a JSON-RPC notification");
    assert_eq!(method, M_PROBE_READY);
    let ready = serde_json::from_value(params).expect("ProbeReady params");
    ReadyWorker { process, ready }
}

/// Sends one `probe.run`, closes stdin and returns the worker's result.
fn run_probe(process: &mut LinuxProcess, probe: ProbeId) -> ProbeResultMsg {
    let request = ProbeRequest {
        probe,
        app_pid: std::process::id(),
        profile_path: "/nonexistent/atlas-duck-profile-probe".to_string(),
        public_addr: PUBLIC_PROBE_ADDR.to_string(),
        loopback_addr: LOOPBACK_PROBE_ADDR.to_string(),
        handle_value: None,
    };
    write_frame(
        &mut process.stdin(),
        &encode_notification(M_PROBE_RUN, &request),
    )
    .expect("write probe.run");
    process.close_stdin();
    let frame = process
        .read_frame_timeout(WORKER_FRAME_MAX_BYTES, WAIT)
        .expect("read probe.result")
        .expect("worker closed stdout before probe.result");
    let (method, params) = decode_notification(&frame).expect("a JSON-RPC notification");
    assert_eq!(method, M_PROBE_RESULT);
    serde_json::from_value(params).expect("ProbeResultMsg params")
}

fn proc_text(pid: u32, name: &str) -> String {
    fs::read_to_string(format!("/proc/{pid}/{name}"))
        .unwrap_or_else(|e| panic!("read /proc/{pid}/{name}: {e}"))
}

/// `(soft, hard)` of one `/proc/<pid>/limits` row, e.g. `Max stack size`.
fn limit(limits: &str, label: &str) -> (String, String) {
    let row = limits
        .lines()
        .find(|line| line.starts_with(label))
        .unwrap_or_else(|| panic!("no `{label}` row in:\n{limits}"));
    let mut cells = row[label.len()..].split_whitespace();
    let soft = cells.next().expect("soft limit").to_string();
    let hard = cells.next().expect("hard limit").to_string();
    (soft, hard)
}

fn same(value: u64) -> (String, String) {
    (value.to_string(), value.to_string())
}

// ---------------------------------------------------------------- tests

#[test]
fn worker_holds_exactly_fds_0_1_2_and_inherits_nothing() {
    act_as_the_app();
    // std's File::open sets O_CLOEXEC, so open an inheritable descriptor with
    // libc: only close_range stands between it and the worker.
    // SAFETY: valid NUL-terminated path.
    let leaked = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    assert!(leaked > 2, "open: {}", std::io::Error::last_os_error());
    // SAFETY: F_GETFD on the descriptor opened above.
    let flags = unsafe { libc::fcntl(leaked, libc::F_GETFD) };
    assert_eq!(
        flags & libc::FD_CLOEXEC,
        0,
        "precondition: the fd is inheritable"
    );

    let worker = spawn_ready();
    let pid = worker.process.pid();

    let fds: BTreeSet<u32> = fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("read /proc/<worker>/fd")
        .map(|entry| {
            entry
                .expect("fd entry")
                .file_name()
                .to_string_lossy()
                .parse()
                .expect("numeric fd")
        })
        .collect();
    assert_eq!(
        fds,
        BTreeSet::from([0, 1, 2]),
        "descriptor {leaked} leaked into the worker"
    );
    for fd in 0..3 {
        let target = fs::read_link(format!("/proc/{pid}/fd/{fd}")).expect("fd target");
        assert!(
            target.to_string_lossy().starts_with("pipe:["),
            "fd {fd} is {} instead of a pipe",
            target.display()
        );
    }
    // SAFETY: closing the descriptor opened above.
    unsafe { libc::close(leaked) };
}

#[test]
fn worker_environment_is_the_allowlist_cwd_is_root_and_the_envnames_probe_agrees() {
    let mut worker = spawn_ready();
    let pid = worker.process.pid();

    // The initial environment block, values included.
    let environ = fs::read(format!("/proc/{pid}/environ")).expect("read /proc/<worker>/environ");
    let got: BTreeSet<String> = environ
        .split(|b| *b == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8_lossy(entry).into_owned())
        .collect();
    let want: BTreeSet<String> = WORKER_ENV
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    assert_eq!(got, want);
    assert_eq!(
        want,
        BTreeSet::from(["TZ=UTC0".to_string(), "MALLOC_ARENA_MAX=1".to_string()])
    );

    assert_eq!(
        fs::read_link(format!("/proc/{pid}/cwd")).expect("cwd"),
        PathBuf::from("/")
    );

    // The worker's own view: names only, sorted here so the test does not
    // depend on the worker's iteration order.
    let result = run_probe(&mut worker.process, ProbeId::EnvNames);
    let mut names = result.env_names.expect("EnvNames returns env_names");
    names.sort();
    assert_eq!(names, ["MALLOC_ARENA_MAX", "TZ"]);
    assert_eq!(
        worker
            .process
            .wait_timeout(Duration::from_secs(5))
            .expect("wait"),
        Some(ExitKind::Code(0))
    );
}

#[test]
fn worker_rlimits_are_stack_8_mib_core_0_nofile_32_and_as_512_mib() {
    let worker = spawn_ready();
    let limits = proc_text(worker.process.pid(), "limits");

    assert_eq!(WORKER_STACK_BYTES, 8_388_608);
    assert_eq!(limit(&limits, "Max stack size"), same(8_388_608));
    assert_eq!(limit(&limits, "Max core file size"), same(0));
    assert_eq!(WORKER_NOFILE, 32);
    assert_eq!(limit(&limits, "Max open files"), same(32));
    assert_eq!(DEFAULT_PROCESS_MB, 512);
    assert_eq!(limit(&limits, "Max address space"), same(512 * 1024 * 1024));
}

#[test]
fn the_parent_sets_no_new_privs_before_the_worker_runs() {
    // The M1 worker only confines itself from T17 on; until then NoNewPrivs
    // can only come from the spawn routine. (T17's worker sets it again, so
    // the unit test `the_parent_sets_no_new_privs_before_exec_for_any_binary`
    // in `linux/spawner.rs` keeps proving the parent's share with `cat`.)
    let worker = spawn_ready();
    let status = proc_text(worker.process.pid(), "status");
    assert!(status.contains("NoNewPrivs:\t1"), "{status}");
}

#[test]
fn worker_forked_for_a_short_lived_thread_outlives_that_thread() {
    act_as_the_app();
    let spawner = LinuxSpawner::start().expect("start the spawner thread");
    // The requesting thread ends as soon as the spawn returns. If the fork
    // had happened on it, PR_SET_PDEATHSIG would kill the worker now.
    let mut process = thread::spawn(move || spawner.spawn_process(&spec()).expect("spawn"))
        .join()
        .expect("the short-lived thread");
    thread::sleep(Duration::from_millis(500));
    assert_eq!(
        process.wait_timeout(Duration::ZERO).expect("wait"),
        None,
        "the worker died with the thread that asked for it"
    );
    // EOF on stdin is the worker's shutdown signal (§3.4).
    process.close_stdin();
    assert_eq!(
        process.wait_timeout(Duration::from_secs(2)).expect("wait"),
        Some(ExitKind::Code(0))
    );
}

#[test]
fn exactly_one_spawner_thread_exists_after_two_starts() {
    let first = LinuxSpawner::start().expect("first start");
    let second = LinuxSpawner::start().expect("second start");
    // The kernel keeps 15 bytes of a thread name in `comm`.
    let comm = &SPAWNER_THREAD_NAME[..15];
    let count = fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .filter(|task| {
            let path = task.as_ref().expect("task entry").path().join("comm");
            fs::read_to_string(path).is_ok_and(|name| name.trim_end() == comm)
        })
        .count();
    assert_eq!(count, 1, "spawner threads named {comm}");
    drop((first, second));
}

#[test]
fn proc_task_status_hook_reads_the_single_worker_thread() {
    let worker = spawn_ready();
    assert!(!worker.ready.worker_version.is_empty());
    let threads = ProcTaskStatusHook
        .after_ready(worker.process.pid())
        .expect("/proc/<worker>/task is readable by the same uid");
    assert_eq!(threads.tasks, 1, "the worker creates no threads (§9.3)");
    assert!(threads.all_no_new_privs_1);
    if worker.ready.confinement.applied {
        // From T17 on the worker installs seccomp before it says ready.
        assert!(threads.all_confined(), "{threads:?}");
    }
}

#[test]
fn platform_spawner_is_the_linux_spawner() {
    act_as_the_app();
    let spawner = atlas_duck_sandbox_host::platform_spawner().expect("Linux has a spawner");
    let mut process = spawner
        .spawn(&spec())
        .expect("spawn through the trait object");
    let frame = process
        .read_frame_timeout(WORKER_FRAME_MAX_BYTES, WAIT)
        .expect("probe.ready frame")
        .expect("worker closed stdout before probe.ready");
    let (method, _) = decode_notification(&frame).expect("a JSON-RPC notification");
    assert_eq!(method, M_PROBE_READY);
    // Dropping the box kills and reaps the worker.
}
