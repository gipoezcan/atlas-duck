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
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use atlas_duck_ipc::sandbox::WORKER_FRAME_MAX_BYTES;
use atlas_duck_ipc::sandbox::frame::write_frame;
use atlas_duck_ipc::sandbox::probe::{
    ConfinementReport, DETAIL_CONNECTED, LOOPBACK_PROBE_ADDR, M_PROBE_READY, M_PROBE_RESULT,
    M_PROBE_RUN, PUBLIC_PROBE_ADDR, ProbeId, ProbeOutcome, ProbeReady, ProbeRequest,
    ProbeResultMsg, decode_notification, encode_notification,
};
use serde::Serialize;

use crate::identity::{SandboxBinaryIdentity, file_identity};
use crate::spawn::{
    DEFAULT_PROCESS_MB, ExitKind, SpawnHook, SpawnSpec, ThreadConfinement, WorkerProcess,
    WorkerSpawner,
};
use crate::winscore::{ERROR_NOT_FOUND, WindowsControl, WindowsScoringContext, rescore};

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
    /// The user's profile directory, target of `FileInProfile` (the worker
    /// opens it, with `FILE_FLAG_BACKUP_SEMANTICS` on Windows; it does not
    /// list it). It travels in `probe.run` as a JSON string, so it must be
    /// valid UTF-8: a path that is not makes every probe `SpawnFailed(-1)`
    /// rather than being converted lossily to a different path.
    pub profile_path: PathBuf,
    /// Upper bound for the whole of one probe (ready frame, result frame and
    /// exit share one deadline); 10 s by default.
    pub per_probe_timeout: Duration,
    /// Windows scoring (§9.4): run a loopback listener and the unconfined
    /// control, and score the probes that need them from that evidence (see
    /// [`crate::winscore`]). On by default on Windows only; other OSes keep
    /// the worker's own scoring. Tests turn it on with a fake spawner.
    pub windows_controls: bool,
}

impl ProbeConfig {
    /// Config with [`DEFAULT_PER_PROBE_TIMEOUT`].
    pub fn new(worker: PathBuf, app_pid: u32, profile_path: PathBuf) -> Self {
        Self {
            worker,
            app_pid,
            profile_path,
            per_probe_timeout: DEFAULT_PER_PROBE_TIMEOUT,
            windows_controls: cfg!(windows),
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
    /// Windows `ConnectLoopback`, scored from the host's listener: whether a
    /// connection `arrived`, and whether the controls proved the listener
    /// reachable (`control_ok`). `Blocked` needs `arrived == false` and
    /// `control_ok == true`.
    ListenerArrival {
        os_error: Option<i64>,
        arrived: bool,
        control_ok: bool,
    },
    /// Windows LPAC: the worker reported that the network stack
    /// (`WSAStartup`) or the credential service (RPC) is unreachable with
    /// `os_error`; `Blocked` only with `control_ok`, the unconfined control
    /// that shows the same call works outside the sandbox.
    StackUnavailable { os_error: i64, control_ok: bool },
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
    /// Windows: what the unconfined control found; `None` when none ran.
    pub control: Option<WindowsControl>,
    /// Windows fallback: the floor probes that failed under LPAC when this
    /// report is the plain-AppContainer rerun that replaced it; `None` otherwise.
    pub lpac_failed: Option<Vec<ProbeId>>,
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
    let mut control = None;
    let runs: Vec<ProbeRun> = match (&file_id, cfg.profile_path.to_str()) {
        // A profile path that cannot be sent as a JSON string would be
        // altered by a lossy conversion and the probe would test another path.
        (_, None) => order
            .iter()
            .map(|&probe| ProbeRun::failed(probe, -1))
            .collect(),
        // No binary, nothing to spawn: fail fast so startup is never held up.
        (Err(e), Some(_)) => {
            let code = os_error_code(e);
            order
                .iter()
                .map(|&probe| ProbeRun::failed(probe, code))
                .collect()
        }
        (Ok(_), Some(profile_path)) => {
            let listener = if cfg.windows_controls {
                LoopbackListener::bind().ok()
            } else {
                None
            };
            let scoring = cfg.windows_controls.then(|| {
                let c = run_control(spawner, cfg, profile_path, listener.as_ref());
                control = Some(c);
                Scoring {
                    control: c,
                    listener: listener.as_ref(),
                }
            });
            order
                .iter()
                .map(|&probe| run_one(spawner, hook, cfg, profile_path, probe, scoring.as_ref()))
                .collect()
        }
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
        control,
        lpac_failed: None,
    }
}

/// [`run_probes`] with the Windows fallback (§9.4): the floor is first run with
/// `spawner` (LPAC where every ACE exists). If that floor is `NotMet` and the
/// worker really ran as LPAC, and `fallback` yields a spawner (plain
/// AppContainer; it is only called then), the whole floor runs again with it. The rerun's report is returned
/// when its floor is `Met` and its worker reported `lpac == false`; its
/// `lpac_failed` then names what failed under LPAC. Otherwise the first report
/// is returned unchanged, so the verdict is never weaker than the first run's.
pub fn run_probes_with_fallback(
    spawner: &dyn WorkerSpawner,
    fallback: &dyn Fn() -> Option<Box<dyn WorkerSpawner>>,
    hook: Option<&dyn SpawnHook>,
    cfg: &ProbeConfig,
) -> ProbeReport {
    let first = run_probes(spawner, hook, cfg);
    let lpac_failed = match &first.floor {
        FloorVerdict::NotMet { failed }
            if first.confinement.as_ref().and_then(|c| c.lpac) == Some(true) =>
        {
            failed.clone()
        }
        _ => return first,
    };
    let Some(fallback) = fallback() else {
        return first;
    };
    let mut second = run_probes(fallback.as_ref(), hook, cfg);
    let plain = second.confinement.as_ref().and_then(|c| c.lpac) == Some(false);
    if second.floor == FloorVerdict::Met && plain {
        second.lpac_failed = Some(lpac_failed);
        second
    } else {
        first
    }
}

/// How long the unconfined control may take in all (it runs two quick probes).
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the host looks for a late arrival after a loopback probe ended. The
/// stack queues a completed handshake at once, so this only covers scheduling.
const ARRIVAL_GRACE: Duration = Duration::from_millis(200);

/// How long the host waits for a connection it expects at the listener.
const ACCEPT_WAIT: Duration = Duration::from_secs(1);

/// A loopback listener on an ephemeral port, owned by the host for one probe
/// run. A connection that completes the TCP handshake is queued by the stack
/// and shows up in [`LoopbackListener::drain`].
struct LoopbackListener {
    listener: TcpListener,
    addr: SocketAddr,
}

impl LoopbackListener {
    fn bind() -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        Ok(Self { listener, addr })
    }

    /// Accepts every queued connection and returns how many there were.
    fn drain(&self) -> usize {
        let mut n = 0;
        while self.listener.accept().is_ok() {
            n += 1;
        }
        n
    }

    /// `drain() > 0`, waiting up to `wait` for the first connection.
    fn arrived_within(&self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        loop {
            if self.drain() > 0 {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The host connects to its own listener and sees it accept: the proof
    /// that "no connection arrived" can be observed at all.
    fn self_check(&self) -> bool {
        let _ = self.drain();
        let Ok(_stream) = TcpStream::connect_timeout(&self.addr, Duration::from_secs(2)) else {
            return false;
        };
        self.arrived_within(ACCEPT_WAIT)
    }
}

/// The host's evidence for [`rescore`]: the control result and the listener.
struct Scoring<'a> {
    control: WindowsControl,
    listener: Option<&'a LoopbackListener>,
}

/// The unconfined control (Windows): the same worker binary, started without
/// any confinement, runs `ConnectLoopback` against the host listener and
/// `CredRead` of the probe's nonexistent target. Winsock must initialise and
/// the connection must arrive, and the credential read must give the normal
/// `ERROR_NOT_FOUND`; each fact that holds is recorded. Anything else (no
/// listener, no control spawn, a timeout, a wrong answer) leaves that fact
/// `false`, which fails the probes that depend on it closed.
fn run_control(
    spawner: &dyn WorkerSpawner,
    cfg: &ProbeConfig,
    profile_path: &str,
    listener: Option<&LoopbackListener>,
) -> WindowsControl {
    let Some(listener) = listener else {
        return WindowsControl::FAILED;
    };
    let mut control = WindowsControl {
        listener: listener.self_check(),
        winsock: false,
        cred: false,
    };
    let spec = SpawnSpec {
        exe: cfg.worker.clone(),
        process_mb: DEFAULT_PROCESS_MB,
    };
    let Ok(mut worker) = spawner.spawn_control(&spec) else {
        return control;
    };
    let deadline = Instant::now() + CONTROL_TIMEOUT;
    let ready = matches!(
        worker.read_frame_timeout(WORKER_FRAME_MAX_BYTES, remaining(deadline)),
        Ok(Some(bytes)) if parse_ready(&bytes).is_some()
    );
    if !ready {
        kill_and_reap(worker.as_mut());
        return control;
    }
    let _ = listener.drain();
    let addr = listener.addr.to_string();
    {
        let mut stdin = worker.stdin();
        for probe in [ProbeId::ConnectLoopback, ProbeId::CredRead] {
            let payload =
                encode_notification(M_PROBE_RUN, &request(cfg, profile_path, probe, &addr));
            if write_frame(&mut stdin, &payload)
                .and_then(|()| stdin.flush())
                .is_err()
            {
                break;
            }
        }
    }
    worker.close_stdin();
    let mut results = Vec::new();
    for probe in [ProbeId::ConnectLoopback, ProbeId::CredRead] {
        match worker.read_frame_timeout(WORKER_FRAME_MAX_BYTES, remaining(deadline)) {
            Ok(Some(bytes)) => results.push(parse_result(&bytes, probe)),
            _ => break,
        }
    }
    kill_and_reap(worker.as_mut());
    if let Some(Some(net)) = results.first() {
        let connected = net.outcome == ProbeOutcome::Allowed
            && net.os_error.is_none()
            && net.detail.as_deref() == Some(DETAIL_CONNECTED);
        control.winsock = connected && listener.arrived_within(ACCEPT_WAIT);
    }
    if let Some(Some(cred)) = results.get(1) {
        control.cred =
            cred.outcome == ProbeOutcome::Allowed && cred.os_error == Some(ERROR_NOT_FOUND);
    }
    control
}

fn request(
    cfg: &ProbeConfig,
    profile_path: &str,
    probe: ProbeId,
    loopback_addr: &str,
) -> ProbeRequest {
    ProbeRequest {
        probe,
        app_pid: cfg.app_pid,
        profile_path: profile_path.to_owned(),
        public_addr: PUBLIC_PROBE_ADDR.to_string(),
        loopback_addr: loopback_addr.to_owned(),
        handle_value: None,
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
    profile_path: &str,
    probe: ProbeId,
    scoring: Option<&Scoring<'_>>,
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
    // Windows: the loopback probe connects to the host's own listener, so that
    // a connection that arrives (or does not) is evidence.
    let listener = scoring
        .and_then(|s| s.listener)
        .filter(|_| probe == ProbeId::ConnectLoopback);
    let loopback_addr =
        listener.map_or_else(|| LOOPBACK_PROBE_ADDR.to_string(), |l| l.addr.to_string());
    let request = request(cfg, profile_path, probe, &loopback_addr);
    if let Some(l) = listener {
        let _ = l.drain();
    }
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

    let (mut outcome, mut evidence) = score(probe, msg.as_ref(), exit);
    if let (Some(scoring), Some(m)) = (scoring, msg.as_ref()) {
        let ctx = WindowsScoringContext {
            lpac: ready.confinement.lpac,
            control: Some(scoring.control),
            loopback_arrived: listener.map(|l| l.arrived_within(ARRIVAL_GRACE)),
        };
        if let Some(scored) = rescore(probe, m, &ctx) {
            (outcome, evidence) = scored;
        }
    }
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
