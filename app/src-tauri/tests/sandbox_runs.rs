#![cfg(feature = "scripted-approver")]
//! `sandbox_runs` (M8 Task 6, Δ2 first half, PD-137, M3 final review M-1): the real
//! `atlas-duck-sandbox` through the platform spawner, split into its pipes, a kill handle that
//! never blocks and a reaper. Later M8 tasks (8, 9, 10, 11) add their real-worker runs here.
//!
//! CI only: every test starts with `harness::opted_in(..)` and skips unless
//! `ATLAS_DUCK_CLI_FLOWS=1` (the `M8 sandbox_runs` step of `ci.yml` sets it on the four `rust`
//! legs and fails on a skip). The OS-specific tests are `#[cfg]` modules, so each leg lists only
//! its own. Run with `--test-threads=1`.

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
    fn grant_built_worker() -> TestResult {
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
