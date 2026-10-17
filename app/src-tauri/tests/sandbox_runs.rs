#![cfg(feature = "scripted-approver")]
//! `sandbox_runs` (M8 Task 6, Δ2 first half, PD-137, M3 final review M-1): the real
//! `atlas-duck-sandbox` through the platform spawner, split into its pipes, a kill handle that
//! never blocks and a reaper. Later M8 tasks (8, 9, 10, 11) add their real-worker runs here.
//!
//! CI only: every test starts with `harness::opted_in(..)` and skips unless
//! `ATLAS_DUCK_CLI_FLOWS=1` (the `M8 sandbox_runs` step of `ci.yml` sets it on the four `rust`
//! legs and fails on a skip). The OS-specific tests are `#[cfg]` modules, so each leg lists only
//! its own. Run with `--test-threads=1`.
//!
//! Task 8 (S-10, §3.4, §15 V12 worker half, V15) adds the module `s10`: the pipe deadlock check
//! and the handle and environment hygiene of a worker started through the platform spawner, on
//! every leg. The M6 env scrub list (`startup/hardening.rs` `SCRUBBED`) applies to the app's own
//! environment; the worker's comes from the fixed spawner blocks, so these tests read the
//! worker's side (`EnvNames`) and never the scrub list.

#[path = "cli_flows/harness.rs"]
pub mod harness;

use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use atlas_duck_ipc::sandbox::WORKER_FRAME_MAX_BYTES;
use atlas_duck_ipc::sandbox::probe::{M_PROBE_READY, ProbeReady, decode_notification};
use atlas_duck_sandbox_host::spawn::{
    DEFAULT_PROCESS_MB, ExitKind, Reaper, SpawnSpec, WorkerProcess,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// How long a worker may take to answer or to be reaped.
const WAIT: Duration = Duration::from_secs(20);
/// The plan bound for a kill that must not block.
const KILL_BOUND: Duration = Duration::from_millis(50);

fn worker_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_atlas-duck-sandbox"))
}

fn spec() -> SpawnSpec {
    SpawnSpec {
        exe: worker_exe(),
        process_mb: DEFAULT_PROCESS_MB,
    }
}

/// Reads the worker's `probe.ready` through the probe path's own timeout, so the split below
/// also covers the bytes the spawner may already have buffered.
fn read_ready(p: &mut dyn WorkerProcess) -> Result<ProbeReady, Box<dyn std::error::Error>> {
    let frame = p
        .read_frame_timeout(WORKER_FRAME_MAX_BYTES, WAIT)?
        .ok_or("the worker closed stdout before probe.ready")?;
    let (method, params) = decode_notification(&frame)?;
    if method != M_PROBE_READY {
        return Err(format!("first frame is {method}, not {M_PROBE_READY}").into());
    }
    Ok(serde_json::from_value(params)?)
}

/// Runs the reaper on a thread of its own (as the bridge will) and hands its answer back.
fn reap_in_background(reaper: Box<dyn Reaper>) -> mpsc::Receiver<std::io::Result<ExitKind>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(reaper.wait());
    });
    rx
}

/// Kills through `kill` and returns how the worker ended, as its reaper saw it. Fails if the
/// worker had already ended before the kill, if the kill blocked, or if no reap followed.
fn kill_and_reap(
    kill: &dyn atlas_duck_sandbox_host::spawn::KillHandle,
    reaped: &mpsc::Receiver<std::io::Result<ExitKind>>,
) -> Result<ExitKind, Box<dyn std::error::Error>> {
    // Alive: the worker waits for its first host frame, and its stdin is still open.
    if let Ok(early) = reaped.recv_timeout(Duration::from_millis(300)) {
        return Err(format!("the worker ended before the kill: {early:?}").into());
    }
    let started = Instant::now();
    kill.kill();
    let took = started.elapsed();
    if took >= KILL_BOUND {
        return Err(format!("kill took {took:?}").into());
    }
    Ok(reaped
        .recv_timeout(WAIT)
        .map_err(|_| "the worker was not reaped after the kill")??)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Write;

    use atlas_duck_ipc::sandbox::frame::write_frame;
    use atlas_duck_ipc::sandbox::probe::{
        LOOPBACK_PROBE_ADDR, M_PROBE_RESULT, M_PROBE_RUN, PUBLIC_PROBE_ADDR, ProbeId, ProbeRequest,
        ProbeResultMsg, encode_notification,
    };
    use atlas_duck_sandbox_host::linux::{LinuxSpawner, reap_fallbacks};
    use atlas_duck_sandbox_host::spawn::WorkerParts;

    use super::*;

    #[test]
    fn linux_pidfd_kill_reaches_worker() -> TestResult {
        if !harness::opted_in("linux_pidfd_kill_reaches_worker") {
            return Ok(());
        }
        let mut p = LinuxSpawner::start()?.spawn_process(&spec())?;
        let ready = read_ready(&mut p)?;
        assert!(ready.confinement.applied, "{:?}", ready.confinement);
        assert!(p.uses_pidfd(), "pidfd_open is available on the CI kernel");
        let WorkerParts {
            io, kill, reaper, ..
        } = Box::new(p).into_parts()?;
        let reaped = reap_in_background(reaper);
        let exit = kill_and_reap(kill.as_ref(), &reaped)?;
        assert_eq!(exit, ExitKind::Signal(libc::SIGKILL));
        kill.kill(); // after the reap: a no-op
        drop(io);
        println!(
            "M8 linux_pidfd_kill uses_pidfd=true exit={exit:?} reap_fallbacks={}",
            reap_fallbacks()
        );
        Ok(())
    }

    #[test]
    fn v11_pdeathsig_spawner_thread_survives() -> TestResult {
        if !harness::opted_in("v11_pdeathsig_spawner_thread_survives") {
            return Ok(());
        }
        // The spawn is requested from a thread that ends at once. PR_SET_PDEATHSIG fires when
        // the thread that forked the child exits; the fork happens on the long-lived spawner
        // thread (§3.4), so the worker must outlive the requesting thread.
        let spawner = LinuxSpawner::start()?;
        let spec = spec();
        let mut p = thread::spawn(move || spawner.spawn_process(&spec))
            .join()
            .map_err(|_| "the requesting thread panicked")??;
        let _ = read_ready(&mut p)?;
        thread::sleep(Duration::from_secs(2));
        assert_eq!(
            p.wait_timeout(Duration::ZERO)?,
            None,
            "the worker died with the requesting thread"
        );
        let request = ProbeRequest {
            probe: ProbeId::EngineSelfTest,
            app_pid: std::process::id(),
            profile_path: std::env::temp_dir().to_string_lossy().into_owned(),
            public_addr: PUBLIC_PROBE_ADDR.to_string(),
            loopback_addr: LOOPBACK_PROBE_ADDR.to_string(),
            handle_value: None,
        };
        write_frame(&mut p.stdin(), &encode_notification(M_PROBE_RUN, &request))?;
        p.stdin().flush()?;
        p.close_stdin();
        let frame = p
            .read_frame_timeout(WORKER_FRAME_MAX_BYTES, WAIT)?
            .ok_or("no probe.result from the worker")?;
        let (method, params) = decode_notification(&frame)?;
        assert_eq!(method, M_PROBE_RESULT);
        let result: ProbeResultMsg = serde_json::from_value(params)?;
        println!(
            "V11 pdeathsig_survives_short_thread=true ({:?})",
            result.outcome
        );
        Ok(())
    }
}

#[cfg(windows)]
mod windows {
    use std::sync::Once;

    use atlas_duck_sandbox_host::spawn::WorkerParts;
    use atlas_duck_sandbox_host::windows::{WindowsSpawner, grant_aces, worker_ace_files_for_exe};

    use super::*;

    /// The built worker has no (L)PAC ACEs, so grant them once, as the installer does (the
    /// `probes_windows` pattern; CI only).
    pub(super) fn grant_built_worker() -> TestResult {
        static ONCE: Once = Once::new();
        let mut result: TestResult = Ok(());
        ONCE.call_once(|| {
            result = worker_ace_files_for_exe(&worker_exe())
                .and_then(|files| grant_aces(&files))
                .map_err(Into::into);
        });
        result
    }

    #[test]
    fn windows_terminate_job_kills_worker() -> TestResult {
        if !harness::opted_in("windows_terminate_job_kills_worker") {
            return Ok(());
        }
        grant_built_worker()?;
        let mut p = WindowsSpawner::new()?.spawn_process(&spec())?;
        let ready = read_ready(&mut p)?;
        assert!(ready.confinement.applied, "{:?}", ready.confinement);
        let run_dir = p.run_dir().to_path_buf();
        assert!(run_dir.is_dir());
        let WorkerParts {
            io, kill, reaper, ..
        } = Box::new(p).into_parts()?;
        let reaped = reap_in_background(reaper);
        let exit = kill_and_reap(kill.as_ref(), &reaped)?;
        // `TerminateJobObject(job, 1)`: the worker's exit code is 1.
        assert_eq!(exit, ExitKind::Code(1));
        kill.kill(); // after the reap: a no-op
        assert!(
            !run_dir.exists(),
            "the reaper removes the per-run directory after the exit"
        );
        drop(io);
        println!("M8 windows_terminate_job exit={exit:?}");
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use atlas_duck_sandbox_host::macos::MacSpawner;
    use atlas_duck_sandbox_host::spawn::WorkerParts;

    use super::*;

    #[test]
    fn macos_kill_before_reap_only() -> TestResult {
        if !harness::opted_in("macos_kill_before_reap_only") {
            return Ok(());
        }
        let mut p = MacSpawner::new().spawn_mac(&spec())?;
        let ready = read_ready(&mut p)?;
        assert!(ready.confinement.applied, "{:?}", ready.confinement);
        let pid = p.pid() as libc::pid_t;
        let WorkerParts {
            io, kill, reaper, ..
        } = Box::new(p).into_parts()?;
        let reaped = reap_in_background(reaper);
        let exit = kill_and_reap(kill.as_ref(), &reaped)?;
        assert_eq!(exit, ExitKind::Signal(libc::SIGKILL));
        // SAFETY: signal 0 only asks whether the pid exists.
        let rc = unsafe { libc::kill(pid, 0) };
        // ESRCH only: EPERM would mean the pid exists (recycled to another user's process).
        let gone = rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        assert!(gone, "the reaped worker's pid still exists");
        // After the reap the guard holds: the pid may belong to anyone now, and no signal is
        // sent (the local `kill_handle` tests prove the guard; here it must not block either).
        let started = Instant::now();
        kill.kill();
        assert!(started.elapsed() < KILL_BOUND);
        drop(io);
        println!("M8 macos_kill_before_reap_only exit={exit:?} reaper=waitpid_wnohang_locked");
        Ok(())
    }
}

/// S-10 (M8 Task 8; §3.4 pipes and handles, §15 V12 worker half, V15): the channel against the
/// real worker, started through the platform spawner object, on every leg.
mod s10 {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use async_trait::async_trait;
    use atlas_duck_ipc::build_info::BUILD_ID;
    use atlas_duck_ipc::sandbox::frame::write_frame;
    use atlas_duck_ipc::sandbox::probe::{
        LOOPBACK_PROBE_ADDR, M_PROBE_RESULT, M_PROBE_RUN, PUBLIC_PROBE_ADDR, ProbeId, ProbeOutcome,
        ProbeRequest, ProbeResultMsg, encode_notification,
    };
    use atlas_duck_ipc::sandbox::script::{InstanceInfo, WorkerInit};
    use atlas_duck_ipc::sandbox::{HostCall, HostCallResult, ScriptLimits};
    use atlas_duck_sandbox_host::bridge::{
        ExpectedWorker, HostCallSink, HostVerdict, RunOutcome, WorkerEnd, start_run,
    };
    use atlas_duck_sandbox_host::identity::{SandboxBinaryIdentity, file_identity};
    use atlas_duck_sandbox_host::platform_spawner;
    use atlas_duck_sandbox_host::spawn::WorkerSpawner;
    use serde_json::json;

    use super::*;

    /// The §3.4 bound for the whole run of the deadlock case (`timeout_s` is 60).
    const DEADLOCK_BOUND: Duration = Duration::from_secs(10);

    /// The spawner object the glue builds (Task 20): the platform spawner. On Windows the built
    /// worker first gets its (L)PAC ACEs, as the installer grants them.
    fn spawner() -> Result<Box<dyn WorkerSpawner>, Box<dyn std::error::Error>> {
        #[cfg(windows)]
        super::windows::grant_built_worker()?;
        Ok(platform_spawner()?)
    }

    /// What `start_run` expects of the worker: the recorded identity of the built binary.
    fn expected() -> Result<ExpectedWorker, Box<dyn std::error::Error>> {
        let (file_id, size, mtime) = file_identity(&worker_exe())?;
        Ok(ExpectedWorker {
            identity: SandboxBinaryIdentity {
                file_id,
                size,
                mtime,
                embedded_version: BUILD_ID.to_owned(),
            },
            accept_unconfined: false,
        })
    }

    fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
    }

    fn init(source: &str, limits: ScriptLimits) -> WorkerInit {
        WorkerInit {
            source: source.to_owned(),
            args: json!({}),
            limits,
            read_op_ids: vec!["jira.issue.get".to_owned()],
            instances: vec![InstanceInfo {
                alias: "prod".to_owned(),
                product: "jira".to_owned(),
                is_default: true,
            }],
        }
    }

    /// Answers every call after `delay` with `pad` bytes of padding and counts how many were in
    /// flight at once.
    struct SlowSink {
        delay: Duration,
        pad: usize,
        in_flight: AtomicU32,
        peak: AtomicU32,
        calls: AtomicU32,
    }

    impl SlowSink {
        fn new(delay: Duration) -> SlowSink {
            SlowSink::padded(delay, 0)
        }

        fn padded(delay: Duration, pad: usize) -> SlowSink {
            SlowSink {
                delay,
                pad,
                in_flight: AtomicU32::new(0),
                peak: AtomicU32::new(0),
                calls: AtomicU32::new(0),
            }
        }
    }

    #[async_trait]
    impl HostCallSink for SlowSink {
        async fn call(&self, _run_id: &str, c: HostCall) -> HostCallResult {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            HostCallResult::Ok(json!({"id": c.id, "pad": "x".repeat(self.pad)}))
        }

        fn log(&self, _run_id: &str, _line: &str) {}
    }

    /// `start_run` over `spawner` (the call the glue makes through `spawn_blocking`) and its end.
    fn run_script(
        rt: &tokio::runtime::Runtime,
        spawner: &dyn WorkerSpawner,
        source: &str,
        limits: ScriptLimits,
        sink: Arc<dyn HostCallSink>,
    ) -> Result<RunOutcome, Box<dyn std::error::Error>> {
        let handle = start_run(
            spawner,
            &spec(),
            &expected()?,
            init(source, limits),
            sink,
            rt.handle().clone(),
        )?;
        Ok(rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(90), handle.wait()).await
        })?)
    }

    /// Sends one `probe.run`, closes stdin and returns the worker's answer; `None` if the worker
    /// ended without one.
    fn ask(
        p: &mut dyn WorkerProcess,
        probe: ProbeId,
        handle_value: Option<u64>,
    ) -> Result<Option<ProbeResultMsg>, Box<dyn std::error::Error>> {
        let request = ProbeRequest {
            probe,
            app_pid: std::process::id(),
            profile_path: std::env::temp_dir().to_string_lossy().into_owned(),
            public_addr: PUBLIC_PROBE_ADDR.to_string(),
            loopback_addr: LOOPBACK_PROBE_ADDR.to_string(),
            handle_value,
        };
        {
            let mut stdin = p.stdin();
            write_frame(&mut stdin, &encode_notification(M_PROBE_RUN, &request))?;
            std::io::Write::flush(&mut stdin)?;
        }
        p.close_stdin();
        let Some(frame) = p.read_frame_timeout(WORKER_FRAME_MAX_BYTES, WAIT)? else {
            return Ok(None);
        };
        let (method, params) = decode_notification(&frame)?;
        if method != M_PROBE_RESULT {
            return Err(format!("{method} instead of {M_PROBE_RESULT}").into());
        }
        Ok(Some(serde_json::from_value(params)?))
    }

    fn result_text(outcome: &RunOutcome) -> Option<&str> {
        match &outcome.end {
            WorkerEnd::Result { value_json } => Some(value_json.get()),
            _ => None,
        }
    }

    /// Four concurrent `atlas.call`s against a sink that answers after 500 ms each with 256 KiB,
    /// while the script writes 1 MiB of `atlas.log`: the host drains stdout while its answers go
    /// out through the writer, so neither pipe fills into a deadlock (§3.4). The worker writes its
    /// calls and logs during the script and reads stdin only after it yields, so the 1 MiB of
    /// answers fills the stdin pipe while the worker is still writing: a host that wrote its
    /// answers inline from the reader thread would stall there and miss the bound.
    #[test]
    fn s10_four_calls_and_1mib_log_no_deadlock() -> TestResult {
        if !harness::opted_in("s10_four_calls_and_1mib_log_no_deadlock") {
            return Ok(());
        }
        let rt = runtime()?;
        let spawner = spawner()?;
        let sink = Arc::new(SlowSink::padded(Duration::from_millis(500), 256 * 1024));
        // 1024 lines of 1023 bytes: 1 MiB less 1 KiB, inside the 1 MiB log cap.
        let source = "const calls = [1, 2, 3, 4].map((n) => atlas.call('jira.issue.get', { key: 'K-' + n }));\n\
                      const line = 'x'.repeat(1023);\n\
                      for (let i = 0; i < 1024; i++) atlas.log(line);\n\
                      const results = await Promise.all(calls);\n\
                      return results.length;";
        let limits = ScriptLimits {
            timeout_s: 60,
            ..ScriptLimits::default()
        };
        let started = Instant::now();
        let outcome = run_script(&rt, spawner.as_ref(), source, limits, sink.clone())?;
        let took = started.elapsed();
        assert_eq!(outcome.host, HostVerdict::None, "{outcome:?}");
        assert_eq!(result_text(&outcome), Some("4"), "{outcome:?}");
        assert_eq!(sink.calls.load(Ordering::SeqCst), 4);
        // Concurrent, not necessarily all four at once (a loaded runner may stall between frames).
        let peak = sink.peak.load(Ordering::SeqCst);
        assert!(peak >= 2, "the calls were not in flight together: {peak}");
        assert_eq!(outcome.logs.len(), 1024);
        assert_eq!(outcome.logs_truncated, None);
        assert!(took < DEADLOCK_BOUND, "the run took {took:?}");
        println!(
            "M8 s10_four_calls_and_1mib_log elapsed_ms={} peak_in_flight={peak} logs=1024",
            took.as_millis()
        );
        Ok(())
    }

    /// The worker's environment names, as the spawner's fixed block leaves them (Linux and macOS:
    /// the block; Windows: the five names observed, R5).
    fn allowed_env() -> Vec<String> {
        #[cfg(target_os = "linux")]
        let mut names: Vec<String> = atlas_duck_sandbox_host::linux::WORKER_ENV
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        #[cfg(target_os = "macos")]
        let mut names: Vec<String> = atlas_duck_sandbox_host::macos::WORKER_ENV
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        #[cfg(windows)]
        let mut names: Vec<String> = atlas_duck_sandbox_host::windows::WORKER_ENV_OBSERVED
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        names.sort();
        names
    }

    /// Linux: the worker holds descriptors 0, 1 and 2 (pipes) and nothing the host had open
    /// without `O_CLOEXEC`.
    #[cfg(target_os = "linux")]
    fn three_handles(spawner: &dyn WorkerSpawner) -> TestResult {
        use std::collections::BTreeSet;
        use std::os::fd::FromRawFd as _;

        // The test process plays the app: non-dumpable, like a GUI launch (§2.5).
        atlas_duck_app_lib::startup::crash::set_non_dumpable()?;
        // SAFETY: valid NUL-terminated path.
        let raw = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(raw > 2, "open: {}", std::io::Error::last_os_error());
        // SAFETY: `raw` is a fresh descriptor owned by nobody else; the guard closes it on every
        // exit path, so a failed step cannot leak it into a later test of this process.
        let leaked_guard = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        let leaked = raw;
        let mut p = spawner.spawn(&spec())?;
        read_ready(p.as_mut())?;
        let pid = p.pid();
        let fds: BTreeSet<u32> = std::fs::read_dir(format!("/proc/{pid}/fd"))?
            .map(|entry| -> Result<u32, Box<dyn std::error::Error>> {
                Ok(entry?.file_name().to_string_lossy().parse()?)
            })
            .collect::<Result<_, _>>()?;
        drop(leaked_guard);
        assert_eq!(
            fds,
            BTreeSet::from([0, 1, 2]),
            "descriptor {leaked} leaked into the worker"
        );
        println!("M8 s10_handles os=linux fds={fds:?}");
        p.close_stdin();
        assert!(
            p.wait_timeout(WAIT)?.is_some(),
            "the worker ends at stdin EOF"
        );
        Ok(())
    }

    /// macOS: the worker holds descriptors 0, 1 and 2 only.
    #[cfg(target_os = "macos")]
    fn three_handles(spawner: &dyn WorkerSpawner) -> TestResult {
        use std::os::fd::FromRawFd as _;

        // SAFETY: plain `open` of /dev/null without O_CLOEXEC.
        let raw = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(raw > 2, "open: {}", std::io::Error::last_os_error());
        // SAFETY: `raw` is a fresh descriptor owned by nobody else; the guard closes it on every
        // exit path, so a failed step cannot leak it into a later test of this process.
        let leaked_guard = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        let leaked = raw;
        let mut p = spawner.spawn(&spec())?;
        read_ready(p.as_mut())?;
        let entry = std::mem::size_of::<libc::proc_fdinfo>();
        let mut buf = vec![0u8; entry * 256];
        // SAFETY: `buf` is valid for `buf.len()` bytes.
        let n = unsafe {
            libc::proc_pidinfo(
                p.pid() as libc::c_int,
                libc::PROC_PIDLISTFDS,
                0,
                buf.as_mut_ptr().cast(),
                buf.len() as libc::c_int,
            )
        };
        let listed = std::io::Error::last_os_error();
        drop(leaked_guard);
        assert!(n > 0, "PROC_PIDLISTFDS failed: {listed}");
        let mut fds: Vec<i32> = buf[..n as usize]
            .chunks_exact(entry)
            .filter_map(|c| c.first_chunk::<4>().map(|b| i32::from_ne_bytes(*b)))
            .collect();
        fds.sort_unstable();
        assert_eq!(
            fds,
            vec![0, 1, 2],
            "descriptor {leaked} leaked into the worker"
        );
        println!("M8 s10_handles os=macos fds={fds:?}");
        p.close_stdin();
        assert!(
            p.wait_timeout(WAIT)?.is_some(),
            "the worker ends at stdin EOF"
        );
        Ok(())
    }

    /// Windows (`HandleSentinel`, V12): an inheritable event of the host, whose value is too high
    /// to coincide with any handle of a small worker, is not in the worker's table. Touching a
    /// value that is not in an AppContainer process's table raises `STATUS_INVALID_HANDLE`, so the
    /// worker either dies on exactly that or answers `Blocked`; a worker that held the handle
    /// would answer `Allowed`. That the worker holds its three pipe ends and nothing else is the
    /// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` result.
    #[cfg(windows)]
    fn three_handles(spawner: &dyn WorkerSpawner) -> TestResult {
        use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
        use std::ptr::{null, null_mut};

        use windows_sys::Win32::Foundation::TRUE;
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::System::Threading::CreateEventW;

        /// `STATUS_INVALID_HANDLE` as the worker's exit code.
        const STATUS_INVALID_HANDLE: i32 = 0xC000_0008_u32 as i32;

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: TRUE,
        };
        let mut kept = Vec::new();
        let mut value = 0u64;
        for _ in 0..4096 {
            // SAFETY: valid attributes, manual-reset, initially unsignalled, unnamed.
            let h = unsafe { CreateEventW(&sa, TRUE, 0, null()) };
            assert!(
                !h.is_null(),
                "CreateEventW: {}",
                std::io::Error::last_os_error()
            );
            value = h as usize as u64;
            // SAFETY: `h` is a fresh handle owned by us.
            kept.push(unsafe { OwnedHandle::from_raw_handle(h as RawHandle) });
            if value >= 0x800 {
                break;
            }
        }
        assert!(
            value >= 0x800,
            "no inheritable event with a handle value >= 0x800"
        );

        let mut p = spawner.spawn(&spec())?;
        read_ready(p.as_mut())?;
        let answer = ask(p.as_mut(), ProbeId::HandleSentinel, Some(value))?;
        let exit = p.wait_timeout(WAIT)?;
        match answer {
            None => {
                assert_eq!(
                    exit,
                    Some(ExitKind::Code(STATUS_INVALID_HANDLE)),
                    "the worker died for another reason than STATUS_INVALID_HANDLE"
                );
                println!("M8 s10_handles os=windows sentinel={value:#x} STATUS_INVALID_HANDLE");
            }
            Some(msg) => {
                assert_eq!(
                    msg.outcome,
                    ProbeOutcome::Blocked,
                    "the worker holds handle {value:#x}: {msg:?}"
                );
                println!("M8 s10_handles os=windows sentinel={value:#x} Blocked");
            }
        }
        drop(kept);
        Ok(())
    }

    /// The worker's environment (names only, as the worker itself lists it) is the spawner's
    /// fixed allowlist, and it holds three handles and nothing inherited. The script language has
    /// no API that sees either, so both are probes run in Rust by the worker (`EnvNames`,
    /// `HandleSentinel`; PD-132 keeps the mode selectable per worker), sent as the first frames
    /// to a worker that the same spawner object and `SpawnSpec` start as `start_run` uses.
    #[test]
    fn s10_worker_sees_three_handles_and_allowlisted_env() -> TestResult {
        if !harness::opted_in("s10_worker_sees_three_handles_and_allowlisted_env") {
            return Ok(());
        }
        let spawner = spawner()?;

        let mut p = spawner.spawn(&spec())?;
        let ready = read_ready(p.as_mut())?;
        assert!(ready.confinement.applied, "{:?}", ready.confinement);
        let answer = ask(p.as_mut(), ProbeId::EnvNames, None)?.ok_or("no EnvNames answer")?;
        assert_eq!(answer.outcome, ProbeOutcome::Allowed, "{answer:?}");
        let mut names = answer.env_names.ok_or("EnvNames returned no names")?;
        names.sort();
        // libSystem adds `__CF_USER_TEXT_ENCODING` to every macOS process before `main`; it
        // carries no host data.
        #[cfg(target_os = "macos")]
        names.retain(|n| n != "__CF_USER_TEXT_ENCODING");
        assert_eq!(names, allowed_env());
        assert!(
            p.wait_timeout(WAIT)?.is_some(),
            "the worker ends after its probe"
        );
        println!(
            "M8 s10_env_names os={} names={names:?}",
            std::env::consts::OS
        );

        three_handles(spawner.as_ref())
    }

    /// The run path and the probe path share one spawn routine: the worker `start_run` starts over
    /// the spawner object answers a trivial script, and its confinement report (the ready frame)
    /// is the one a probe-path spawn over the same object shows.
    #[test]
    fn s10_run_and_probe_share_the_spawn_routine() -> TestResult {
        if !harness::opted_in("s10_run_and_probe_share_the_spawn_routine") {
            return Ok(());
        }
        let rt = runtime()?;
        let spawner = spawner()?;

        let mut p = spawner.spawn(&spec())?;
        let ready = read_ready(p.as_mut())?;
        let probe = ask(p.as_mut(), ProbeId::EnvNames, None)?.ok_or("no EnvNames answer")?;
        assert_eq!(probe.outcome, ProbeOutcome::Allowed, "{probe:?}");
        assert!(p.wait_timeout(WAIT)?.is_some());

        let sink = Arc::new(SlowSink::new(Duration::ZERO));
        let outcome = run_script(
            &rt,
            spawner.as_ref(),
            "return 40 + 2;",
            ScriptLimits::default(),
            sink,
        )?;
        assert_eq!(outcome.host, HostVerdict::None, "{outcome:?}");
        assert_eq!(result_text(&outcome), Some("42"), "{outcome:?}");
        assert_eq!(outcome.confinement, ready.confinement);
        println!(
            "M8 s10_run_and_probe_share_the_spawn_routine result=42 mechanism={}",
            outcome.confinement.mechanism
        );
        Ok(())
    }
}
