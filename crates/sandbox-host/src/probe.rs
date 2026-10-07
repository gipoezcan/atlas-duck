//! The §9.4 confinement probe runner: one worker process per probe, scoring,
//! floor verdict and the sandbox binary identity (§3.4).
//!
//! Plan decisions (spec gaps, digest §10.5 items 1, 2 and 6):
//! - One worker process per probe: under the Linux seccomp default-kill
//!   filter the first forbidden syscall ends the process, so a shared worker
//!   could answer only one probe.
//! - A result frame is the primary evidence. Without one, death by `SIGSYS`
//!   (Linux only, floor probes only) is the single exit scored `Blocked`;
//!   every other exit, crash or timeout is `Error`, never `Blocked`.
//! - The Linux "every thread confined" check is a host-side
//!   `/proc/<worker pid>/task/*/status` read through [`SpawnHook`].
//! - Missing extra layers (Landlock) are reported in `extra_layers` and never
//!   change the floor (§9.4).
//! - Probe results never block startup: callers run [`run_probes`] off the
//!   startup path, and every wait inside it is bounded by
//!   `per_probe_timeout`.

use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use atlas_duck_ipc::sandbox::WORKER_FRAME_MAX_BYTES;
use atlas_duck_ipc::sandbox::frame::write_frame;
use atlas_duck_ipc::sandbox::probe::{
    ConfinementReport, LOOPBACK_PROBE_ADDR, M_PROBE_READY, M_PROBE_RESULT, M_PROBE_RUN,
    PUBLIC_PROBE_ADDR, ProbeId, ProbeOutcome, ProbeReady, ProbeRequest, ProbeResultMsg,
    decode_notification, encode_notification,
};
use serde::Serialize;

use crate::identity::{SandboxBinaryIdentity, file_identity};
use crate::spawn::{
    DEFAULT_PROCESS_MB, ExitKind, SpawnHook, SpawnSpec, ThreadConfinement, WorkerProcess,
    WorkerSpawner,
};

/// Default `ProbeConfig::per_probe_timeout` (plan value; the spec gives none).
pub const DEFAULT_PER_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for a killed worker to be reaped.
const REAP_TIMEOUT: Duration = Duration::from_secs(1);

/// Linux `SIGSYS` (31 on x86_64 and aarch64): seccomp `SECCOMP_RET_KILL_PROCESS`.
#[cfg(target_os = "linux")]
const LINUX_SIGSYS: i32 = 31;

/// Diagnostic probes run after the floor probes. They are recorded but never
/// change the floor. `HandleSentinel` needs a host-chosen handle value and is
/// run by the Windows tests (T19), not here.
const DIAGNOSTIC_PROBES: [ProbeId; 2] = [ProbeId::EngineSelfTest, ProbeId::EnvNames];

/// Probe run parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeConfig {
    /// The canonical sandbox worker binary (install dir, §3.4).
    pub worker: PathBuf,
    /// The app's pid, target of the memory-read probes.
    pub app_pid: u32,
    /// A file in the user profile, target of `FileInProfile`.
    pub profile_path: PathBuf,
    /// Upper bound for the whole of one probe (ready frame, result frame and
    /// exit share one deadline); 10 s by default.
    pub per_probe_timeout: Duration,
}

impl ProbeConfig {
    /// Config with [`DEFAULT_PER_PROBE_TIMEOUT`].
    pub fn new(worker: PathBuf, app_pid: u32, profile_path: PathBuf) -> Self {
        Self {
            worker,
            app_pid,
            profile_path,
            per_probe_timeout: DEFAULT_PER_PROBE_TIMEOUT,
        }
    }
}

/// Why a probe got its outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// The worker sent a `probe.result` frame.
    Reported { os_error: Option<i64> },
    /// Linux: no result frame, the worker died by `SIGSYS` (seccomp kill).
    KilledBySigsys,
    /// No result frame, the worker exited with this code.
    Exited(i32),
    /// No result frame, the worker died by this (non-`SIGSYS`) signal.
    Signaled(i32),
    /// No result frame and no exit before the deadline; the worker was killed.
    Timeout,
    /// The worker could not be started (raw OS error, `-1` if none).
    SpawnFailed(i64),
    /// The worker sent no valid `probe.ready` frame.
    NoReady,
}

/// Outcome of one probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeRecord {
    pub probe: ProbeId,
    pub outcome: ProbeOutcome,
    pub evidence: Evidence,
}

/// Whether the mandatory floor (§9.4) is applied and verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FloorVerdict {
    Met,
    /// `failed` lists, in `floor_probes_for_current_os()` order, every floor
    /// probe that did not pass. It is empty only when the OS has no floor
    /// probes at all (fail closed).
    NotMet {
        failed: Vec<ProbeId>,
    },
}

/// Everything one probe run found. Goes to `APP_START` (M2), Settings (M6)
/// and the M8 script gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeReport {
    /// `worker_version` of the first `probe.ready` frame.
    pub worker_version: Option<String>,
    /// `engine_version` of the first `probe.ready` frame.
    pub engine_version: Option<String>,
    /// File identity of `cfg.worker` plus `worker_version`; `None` if the
    /// file could not be inspected or no worker sent `probe.ready`.
    pub identity: Option<SandboxBinaryIdentity>,
    /// Confinement report of the first `probe.ready` frame.
    pub confinement: Option<ConfinementReport>,
    /// Thread check merged over all workers (`tasks` = max, flags = all);
    /// `None` without a hook or when no check succeeded.
    pub threads: Option<ThreadConfinement>,
    /// One record per probe, in run order.
    pub records: Vec<ProbeRecord>,
    pub floor: FloorVerdict,
    /// Extra layers (not floor), e.g. `("landlock", true)`.
    pub extra_layers: Vec<(String, bool)>,
}

/// Scores one probe from its result frame and the worker's exit.
///
/// - `msg = Some(..)`: the worker's own report wins (`Reported`).
/// - `msg = None, exit = None`: the worker neither answered nor exited in
///   time and was killed (`Error`, `Timeout`). Callers pass `exit = None`
///   after a timeout kill, never the exit status the kill caused.
/// - `msg = None, exit = Signal(SIGSYS)` on Linux for a floor probe:
///   `Blocked`, `KilledBySigsys` (the seccomp filter killed the attempt).
///   For a diagnostic probe the same death is `Error`: a diagnostic must not
///   hit a kill rule.
/// - every other exit: `Error`, with `Exited(code)` or `Signaled(sig)`.
pub fn score(
    probe: ProbeId,
    msg: Option<&ProbeResultMsg>,
    exit: Option<ExitKind>,
) -> (ProbeOutcome, Evidence) {
    if let Some(m) = msg {
        return (
            m.outcome,
            Evidence::Reported {
                os_error: m.os_error,
            },
        );
    }
    match exit {
        None => (ProbeOutcome::Error, Evidence::Timeout),
        Some(ExitKind::Code(code)) => (ProbeOutcome::Error, Evidence::Exited(code)),
        Some(ExitKind::Signal(sig)) => score_signal(probe, sig),
    }
}

#[cfg(target_os = "linux")]
fn score_signal(probe: ProbeId, sig: i32) -> (ProbeOutcome, Evidence) {
    if sig == LINUX_SIGSYS {
        let outcome = if probe.is_floor() {
            ProbeOutcome::Blocked
        } else {
            ProbeOutcome::Error
        };
        return (outcome, Evidence::KilledBySigsys);
    }
    (ProbeOutcome::Error, Evidence::Signaled(sig))
}

#[cfg(not(target_os = "linux"))]
fn score_signal(_probe: ProbeId, sig: i32) -> (ProbeOutcome, Evidence) {
    (ProbeOutcome::Error, Evidence::Signaled(sig))
}

/// Runs every floor probe of the current OS
/// (`ProbeId::floor_probes_for_current_os()`, in that order), then
/// `EngineSelfTest` and `EnvNames`, each in its own worker process, and
/// returns the report. Never panics; one probe takes at most
/// `per_probe_timeout` plus a 1 s reap after a kill.
///
/// Per probe: spawn -> read `probe.ready` -> `hook.after_ready(pid)` ->
/// write one `probe.run` frame -> close stdin -> read `probe.result` ->
/// wait for exit (kill at the deadline) -> [`score`].
///
/// A floor probe passes only if its record is `Blocked`, its worker's
/// `probe.ready` said `confinement.applied == true`, and the thread check
/// passed where one is required (a hook was given, or the OS is Linux,
/// where a missing hook fails the floor).
pub fn run_probes(
    spawner: &dyn WorkerSpawner,
    hook: Option<&dyn SpawnHook>,
    cfg: &ProbeConfig,
) -> ProbeReport {
    let floor_probes = ProbeId::floor_probes_for_current_os();
    let order: Vec<ProbeId> = floor_probes
        .iter()
        .copied()
        .chain(DIAGNOSTIC_PROBES)
        .collect();

    let file_id = file_identity(&cfg.worker);
    let runs: Vec<ProbeRun> = match &file_id {
        // No binary, nothing to spawn: fail fast so startup is never held up.
        Err(e) => {
            let code = os_error_code(e);
            order
                .iter()
                .map(|&probe| ProbeRun::failed(probe, code))
                .collect()
        }
        Ok(_) => order
            .iter()
            .map(|&probe| run_one(spawner, hook, cfg, probe))
            .collect(),
    };

    let first_ready = runs.iter().find_map(|r| r.ready.clone());
    let threads = merge_threads(runs.iter().filter_map(|r| r.threads));
    let thread_check_required = hook.is_some() || cfg!(target_os = "linux");

    let floor = floor_verdict(floor_probes, &runs, thread_check_required);

    let identity = match (&file_id, &first_ready) {
        (Ok((id, size, mtime)), Some(ready)) => Some(SandboxBinaryIdentity {
            file_id: *id,
            size: *size,
            mtime: *mtime,
            embedded_version: ready.worker_version.clone(),
        }),
        _ => None,
    };

    let confinement = first_ready.as_ref().map(|r| r.confinement.clone());
    let extra_layers = extra_layers(confinement.as_ref());

    ProbeReport {
        worker_version: first_ready.as_ref().map(|r| r.worker_version.clone()),
        engine_version: first_ready.as_ref().map(|r| r.engine_version.clone()),
        identity,
        confinement,
        threads,
        records: runs.into_iter().map(|r| r.record).collect(),
        floor,
        extra_layers,
    }
}

/// Fails closed: an empty floor list (an OS without a floor definition) is
/// `NotMet`, never vacuously `Met`. `failed` is then empty, the one case where
/// it is, because no floor probe exists to blame.
fn floor_verdict(
    floor_probes: &[ProbeId],
    runs: &[ProbeRun],
    thread_check_required: bool,
) -> FloorVerdict {
    let failed: Vec<ProbeId> = floor_probes
        .iter()
        .copied()
        .filter(|&probe| {
            !runs
                .iter()
                .find(|r| r.record.probe == probe)
                .is_some_and(|r| r.passes_floor(thread_check_required))
        })
        .collect();
    if floor_probes.is_empty() || !failed.is_empty() {
        FloorVerdict::NotMet { failed }
    } else {
        FloorVerdict::Met
    }
}

/// One probe's worker run.
struct ProbeRun {
    record: ProbeRecord,
    ready: Option<ProbeReady>,
    threads: Option<ThreadConfinement>,
}

impl ProbeRun {
    fn failed(probe: ProbeId, code: i64) -> Self {
        Self::without_ready(probe, Evidence::SpawnFailed(code))
    }

    fn without_ready(probe: ProbeId, evidence: Evidence) -> Self {
        Self {
            record: ProbeRecord {
                probe,
                outcome: ProbeOutcome::Error,
                evidence,
            },
            ready: None,
            threads: None,
        }
    }

    fn passes_floor(&self, thread_check_required: bool) -> bool {
        let applied = self.ready.as_ref().is_some_and(|r| r.confinement.applied);
        let threads_ok = !thread_check_required || self.threads.is_some_and(|t| t.all_confined());
        self.record.outcome == ProbeOutcome::Blocked && applied && threads_ok
    }
}

fn run_one(
    spawner: &dyn WorkerSpawner,
    hook: Option<&dyn SpawnHook>,
    cfg: &ProbeConfig,
    probe: ProbeId,
) -> ProbeRun {
    let spec = SpawnSpec {
        exe: cfg.worker.clone(),
        process_mb: DEFAULT_PROCESS_MB,
    };
    let mut worker = match spawner.spawn(&spec) {
        Ok(w) => w,
        Err(e) => return ProbeRun::failed(probe, os_error_code(&e)),
    };
    let deadline = Instant::now() + cfg.per_probe_timeout;

    // 1. probe.ready (the worker has confined itself before sending it)
    let ready = match worker.read_frame_timeout(WORKER_FRAME_MAX_BYTES, remaining(deadline)) {
        Ok(Some(bytes)) => parse_ready(&bytes),
        Ok(None) => None,
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            kill_and_reap(worker.as_mut());
            return ProbeRun::without_ready(probe, Evidence::Timeout);
        }
        Err(_) => None,
    };
    let Some(ready) = ready else {
        kill_and_reap(worker.as_mut());
        return ProbeRun::without_ready(probe, Evidence::NoReady);
    };

    // 2. host-side check while the worker waits for its request
    let threads = hook.and_then(|h| h.after_ready(worker.pid()));

    // 3. probe.run, then EOF so the worker exits after answering
    let request = ProbeRequest {
        probe,
        app_pid: cfg.app_pid,
        profile_path: cfg.profile_path.to_string_lossy().into_owned(),
        public_addr: PUBLIC_PROBE_ADDR.to_string(),
        loopback_addr: LOOPBACK_PROBE_ADDR.to_string(),
        handle_value: None,
    };
    let payload = encode_notification(M_PROBE_RUN, &request);
    {
        let mut stdin = worker.stdin();
        // A write error means the worker is already gone; its exit is the evidence.
        let _ = write_frame(&mut stdin, &payload).and_then(|()| stdin.flush());
    }
    worker.close_stdin();

    // 4. probe.result
    let (msg, timed_out) =
        match worker.read_frame_timeout(WORKER_FRAME_MAX_BYTES, remaining(deadline)) {
            Ok(Some(bytes)) => (parse_result(&bytes, probe), false),
            Ok(None) => (None, false),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => (None, true),
            Err(_) => (None, false),
        };

    // 5. exit; after a timeout kill the exit status is not evidence
    let exit = if timed_out {
        kill_and_reap(worker.as_mut());
        None
    } else {
        match worker.wait_timeout(remaining(deadline)) {
            Ok(Some(exit)) => Some(exit),
            Ok(None) | Err(_) => {
                kill_and_reap(worker.as_mut());
                None
            }
        }
    };

    let (outcome, evidence) = score(probe, msg.as_ref(), exit);
    ProbeRun {
        record: ProbeRecord {
            probe,
            outcome,
            evidence,
        },
        ready: Some(ready),
        threads,
    }
}

fn parse_ready(bytes: &[u8]) -> Option<ProbeReady> {
    let (method, params) = decode_notification(bytes).ok()?;
    if method != M_PROBE_READY {
        return None;
    }
    serde_json::from_value(params).ok()
}

/// A result frame counts only if it is `probe.result` for the probe asked.
fn parse_result(bytes: &[u8], probe: ProbeId) -> Option<ProbeResultMsg> {
    let (method, params) = decode_notification(bytes).ok()?;
    if method != M_PROBE_RESULT {
        return None;
    }
    let msg: ProbeResultMsg = serde_json::from_value(params).ok()?;
    (msg.probe == probe).then_some(msg)
}

fn kill_and_reap(worker: &mut dyn WorkerProcess) {
    let _ = worker.kill();
    let _ = worker.wait_timeout(REAP_TIMEOUT);
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn os_error_code(e: &io::Error) -> i64 {
    e.raw_os_error().map_or(-1, i64::from)
}

fn merge_threads(mut it: impl Iterator<Item = ThreadConfinement>) -> Option<ThreadConfinement> {
    let first = it.next()?;
    Some(it.fold(first, |acc, t| ThreadConfinement {
        tasks: acc.tasks.max(t.tasks),
        all_seccomp_2: acc.all_seccomp_2 && t.all_seccomp_2,
        all_no_new_privs_1: acc.all_no_new_privs_1 && t.all_no_new_privs_1,
    }))
}

/// Landlock is the only extra layer the spec names (§9.4). It is listed on
/// Linux, and wherever the worker reports a seccomp-based mechanism (so the
/// rule is testable with a fake worker on every OS).
fn extra_layers(confinement: Option<&ConfinementReport>) -> Vec<(String, bool)> {
    let seccomp_based = confinement.is_some_and(|c| c.mechanism.starts_with("seccomp"));
    if cfg!(target_os = "linux") || seccomp_based {
        let landlock = confinement.is_some_and(|c| c.landlock_abi.is_some());
        vec![("landlock".to_string(), landlock)]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_floor_list_is_not_met() {
        assert_eq!(
            floor_verdict(&[], &[], true),
            FloorVerdict::NotMet { failed: Vec::new() }
        );
        assert_eq!(
            floor_verdict(&[], &[], false),
            FloorVerdict::NotMet { failed: Vec::new() }
        );
    }

    #[test]
    fn a_floor_probe_without_a_run_fails() {
        assert_eq!(
            floor_verdict(&[ProbeId::ConnectPublic], &[], false),
            FloorVerdict::NotMet {
                failed: vec![ProbeId::ConnectPublic]
            }
        );
    }
}
