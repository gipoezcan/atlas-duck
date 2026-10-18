//! §9.4 "On each app start": run the probe worker from the real app so the
//! installed app process is the memory-read target, never on the startup
//! path. The report is held in `AppState` (M2 records it in `APP_START`, M6
//! shows it in Settings, M8 gates scripts on it) and summarised in one
//! diagnostic log line. The probe never blocks startup and only decides
//! whether scripts are enabled.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, UNIX_EPOCH};

use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::paths::base_dirs;
use atlas_duck_ipc::sandbox::probe::{ProbeId, ProbeOutcome};
use atlas_duck_sandbox_host::identity::{FileId, SandboxBinaryIdentity, file_identity};
use atlas_duck_sandbox_host::probe::{
    FloorVerdict, ProbeConfig, ProbeReport, run_probes, run_probes_with_fallback,
};
use atlas_duck_sandbox_host::spawn::{SpawnHook, SpawnSpec, WorkerProcess, WorkerSpawner};
use atlas_duck_sandbox_host::{fallback_spawner, platform_spawner};
use serde_json::{Value, json};
use tauri::Manager;
use tokio::sync::watch;

use crate::state::AppState;

/// Value of the `event` field of the one log line.
pub const LOG_EVENT_SANDBOX_PROBE: &str = "sandbox_probe";

/// Field names this module logs. `run_gui` passes them to
/// `Diag::extend_allowed_fields` right after `Diag::init`.
pub const PROBE_LOG_FIELDS: &[&str] = &[
    "floor",
    "failed",
    "extra_layers",
    "engine_version",
    "worker_version",
    "ace",
    "appcontainer_mode",
    "control_ok",
    "lpac_failed",
];

/// Name of the background thread (§9.4: the probe runs off the startup path).
pub const PROBE_THREAD_NAME: &str = "atlas-duck-probe";

/// Token for an empty list (`failed=none`, `extra_layers=none`).
pub const LABEL_NONE: &str = "none";

/// Token for a version the worker never reported.
pub const LABEL_UNKNOWN: &str = "unknown";

/// Windows: what the start-time ACE check did (§9.4 "At each start, before
/// the probe"). Elsewhere there is no such step and the type has no values,
/// so `Option<AceEnsure>` is always `None`.
#[cfg(windows)]
pub use atlas_duck_sandbox_host::windows::AceEnsure;

#[cfg(not(windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceEnsure {}

/// The startup probe's report, set once per process by the probe thread and shared with the
/// script glue (M8 Task 20, PD-138: "the glue awaits the startup report before its first spawn").
/// Reading never blocks; [`ProbeHolder::wait`] awaits the report with a bound.
#[derive(Debug)]
pub struct ProbeHolder {
    /// The worker binary whose identity is recorded when the report has none
    /// ([`FallbackIdentity`]); `None`: none is recorded.
    worker: Option<PathBuf>,
    resolved: OnceLock<Resolved>,
    /// Flipped to `true` right after `resolved` is set.
    ready: watch::Sender<bool>,
    /// When the probe thread was started (R1: the `APP_START` wait is measured from here); unset
    /// where no probe is started (CLI paths, tests): there is nothing to wait for then.
    started: OnceLock<Instant>,
}

#[derive(Debug)]
struct Resolved {
    report: ProbeReport,
    fallback: Option<FallbackIdentity>,
}

/// The identity of the worker binary as the app records it itself when no probe worker sent its
/// ready frame, so the report has no identity (M8 T20 ruling; Windows below the floor): the file
/// identity of `worker`, read once when the holder resolves (never at a spawn), and this build's
/// `BUILD_ID` as the embedded version, which the bridge checks against each spawned worker's
/// ready frame. Only a degraded spawn under a `NotMet` report may use it (`script_glue`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackIdentity {
    /// The path it was read from: a spawn of any other path cannot use it.
    pub worker: PathBuf,
    /// `None`: the file identity could not be read (every spawn that needs it is refused).
    pub identity: Option<SandboxBinaryIdentity>,
}

impl FallbackIdentity {
    /// Reads `worker`'s file identity now (blocking: a `stat`, on Windows an open).
    pub fn read(worker: &Path) -> FallbackIdentity {
        let identity =
            file_identity(worker)
                .ok()
                .map(|(file_id, size, mtime)| SandboxBinaryIdentity {
                    file_id,
                    size,
                    mtime,
                    embedded_version: BUILD_ID.to_owned(),
                });
        FallbackIdentity {
            worker: worker.to_path_buf(),
            identity,
        }
    }
}

impl Default for ProbeHolder {
    fn default() -> Self {
        ProbeHolder::for_worker(None)
    }
}

impl ProbeHolder {
    /// A holder that records the identity of `worker` when the report it resolves with has none
    /// (the app passes [`canonical_worker`], the path every script spawn uses).
    pub fn for_worker(worker: Option<PathBuf>) -> ProbeHolder {
        ProbeHolder {
            worker,
            resolved: OnceLock::new(),
            ready: watch::channel(false).0,
            started: OnceLock::new(),
        }
    }

    /// Records the instant the probe thread was started (the first call wins).
    pub fn mark_started(&self, at: Instant) {
        let _ = self.started.set(at);
    }

    /// Waits for the report at most as long as `APP_START` may (R1, PD-138): [`APP_START_WAIT`]
    /// counted from the probe's start, not from this call, so the wait overlaps `audit::open` and
    /// the store verification that ran before it. Nothing is waited for when no probe was started or
    /// the report is there. Never fails: a report that is still missing is `pending` in `APP_START`.
    pub async fn wait_for_app_start(&self) {
        let left = app_start_wait_left(self.started.get().copied(), Instant::now());
        if !left.is_zero() {
            let _ = self.wait(left).await;
        }
    }

    /// The report, `None` until the probe has finished.
    pub fn get(&self) -> Option<&ProbeReport> {
        self.resolved.get().map(|r| &r.report)
    }

    /// The identity recorded when the holder resolved with a report without one; `None` before,
    /// when the report has one, or when the holder has no worker path.
    pub fn fallback(&self) -> Option<&FallbackIdentity> {
        self.resolved.get().and_then(|r| r.fallback.as_ref())
    }

    /// Sets the report once; `false` (and the report dropped) when one was set before. A report
    /// without an identity gets the worker's [`FallbackIdentity`], read here, before the report
    /// becomes visible, so a reader never sees the one without the other. Blocking (the probe
    /// thread calls it).
    pub fn set(&self, report: ProbeReport) -> bool {
        if self.resolved.get().is_some() {
            return false;
        }
        let fallback = match (&report.identity, &self.worker) {
            (None, Some(worker)) => Some(FallbackIdentity::read(worker)),
            _ => None,
        };
        if self.resolved.set(Resolved { report, fallback }).is_err() {
            return false;
        }
        self.ready.send_replace(true);
        true
    }

    /// The report, awaited for at most `bound`; `None` if it did not arrive in time.
    pub async fn wait(&self, bound: Duration) -> Option<&ProbeReport> {
        if let Some(report) = self.get() {
            return Some(report);
        }
        let mut ready = self.ready.subscribe();
        // The sender lives in `self`, so the channel cannot close while this borrows it.
        let _ = tokio::time::timeout(bound, ready.wait_for(|set| *set)).await;
        self.get()
    }
}

/// R1 (PD-138): how long `APP_START` waits for the probe report, counted from the probe's start.
pub const APP_START_WAIT: Duration = Duration::from_secs(5);

/// What is left of [`APP_START_WAIT`] at `now` for a probe started at `started`: the 5 s are
/// measured from the probe's start (it runs while `audit::open` and the verification do), so a
/// probe that started 4 s ago leaves 1 s and one that started 6 s ago leaves nothing. `None`
/// (no probe was started): nothing to wait for.
pub fn app_start_wait_left(started: Option<Instant>, now: Instant) -> Duration {
    started.map_or(Duration::ZERO, |at| {
        APP_START_WAIT.saturating_sub(now.saturating_duration_since(at))
    })
}

/// The floor probes that attempt to read the app's memory (S-05): Linux `process_vm_readv` and
/// `/proc/<pid>/mem`, macOS `task_for_pid`, Windows `OpenProcess(PROCESS_VM_READ)`.
const MEMORY_READ_PROBES: [ProbeId; 4] = [
    ProbeId::MemReadProcessVm,
    ProbeId::MemReadProcMem,
    ProbeId::TaskForPid,
    ProbeId::OpenProcessVmRead,
];

/// `memory_read` value: every memory-read probe was blocked.
pub const MEMORY_READ_BLOCKED: &str = "blocked";
/// `memory_read` value: a memory-read probe got through.
pub const MEMORY_READ_ALLOWED: &str = "allowed";
/// `memory_read` value: no memory-read probe gave a clear answer (errored, timed out, was never
/// scored, or is listed as failed by the floor).
pub const MEMORY_READ_INCONCLUSIVE: &str = "inconclusive";

/// The S-05 memory-read result of `report`, failing closed: `allowed` when any memory-read probe
/// got through; `blocked` only when at least one was scored, every scored one was `Blocked` and the
/// floor lists none of them as failed; `inconclusive` otherwise.
pub fn memory_read_label(report: &ProbeReport) -> &'static str {
    let mut scored = false;
    let mut all_blocked = true;
    for record in report
        .records
        .iter()
        .filter(|r| MEMORY_READ_PROBES.contains(&r.probe))
    {
        scored = true;
        match record.outcome {
            ProbeOutcome::Allowed => return MEMORY_READ_ALLOWED,
            ProbeOutcome::Blocked => {}
            ProbeOutcome::Error => all_blocked = false,
        }
    }
    let floor_failed = matches!(
        &report.floor,
        FloorVerdict::NotMet { failed } if failed.iter().any(|p| MEMORY_READ_PROBES.contains(p))
    );
    if scored && all_blocked && !floor_failed {
        MEMORY_READ_BLOCKED
    } else {
        MEMORY_READ_INCONCLUSIVE
    }
}

/// `{file_id, size, mtime, embedded_version}` of a recorded identity: constants and numbers only,
/// no path. `file_id` is a string (`dev_ino:<dev>:<ino>`, `file_index:<volume>:<index>`: the ids
/// can exceed what a JSON number holds exactly), `mtime` whole seconds since the Unix epoch
/// (`null` before it).
fn identity_json(identity: &SandboxBinaryIdentity) -> Value {
    let file_id = match identity.file_id {
        FileId::DevIno { dev, ino } => format!("dev_ino:{dev}:{ino}"),
        FileId::FileIndex {
            volume_serial,
            index,
        } => format!("file_index:{volume_serial}:{index}"),
    };
    let mtime = identity
        .mtime
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs());
    json!({
        "file_id": file_id,
        "size": identity.size,
        "mtime": mtime,
        "embedded_version": identity.embedded_version,
    })
}

/// The `confinement` key of `APP_START` (R1, S-05, §9.4 "results recorded in `APP_START`"): while
/// the report is missing `{state: "pending"}`; otherwise `{floor, failed, extra_layers, mode,
/// memory_read, sandbox_binary}` with the probe's own results (`failed` the failed floor probes by
/// name, `sandbox_binary` the identity the probe recorded, or `{state: "unavailable"}` when no
/// probe worker reached ready). Fixed spellings and numbers only: no path, no worker text.
pub fn app_start_confinement(holder: &ProbeHolder) -> Value {
    let Some(report) = holder.get() else {
        return json!({ "state": "pending" });
    };
    let failed: Vec<&str> = match &report.floor {
        FloorVerdict::Met => Vec::new(),
        FloorVerdict::NotMet { failed } => failed.iter().map(|p| probe_id_name(*p)).collect(),
    };
    let extra_layers: Vec<Value> = report
        .extra_layers
        .iter()
        .map(|(name, on)| json!({ "name": name, "on": on }))
        .collect();
    let sandbox_binary = report
        .identity
        .as_ref()
        .map_or_else(|| json!({ "state": "unavailable" }), identity_json);
    json!({
        "floor": floor_label(&report.floor),
        "failed": failed,
        "extra_layers": extra_layers,
        "mode": mode_label(report),
        "memory_read": memory_read_label(report),
        "sandbox_binary": sandbox_binary,
    })
}

/// `scripts` value of the settings DTO: scripts may run.
pub const SCRIPTS_ENABLED: &str = "enabled";
/// `scripts` value: scripts are refused (floor not met and degraded confinement not allowed, or no
/// report yet).
pub const SCRIPTS_DISABLED: &str = "disabled";
/// `scripts` value: the floor is not met and the user allowed degraded confinement (PD-141).
pub const SCRIPTS_DEGRADED: &str = "degraded";

/// Whether scripts run under `report` and the user's degraded-confinement setting, as the glue
/// admits them (`script_glue::policy::admit`): `enabled` under a `Met` floor, `degraded` under a
/// `NotMet` one with degraded confinement allowed, `disabled` otherwise, including while there is
/// no report (fail closed).
pub fn scripts_state(report: Option<&ProbeReport>, degraded_allowed: bool) -> &'static str {
    match report.map(|r| &r.floor) {
        Some(FloorVerdict::Met) => SCRIPTS_ENABLED,
        Some(FloorVerdict::NotMet { .. }) if degraded_allowed => SCRIPTS_DEGRADED,
        _ => SCRIPTS_DISABLED,
    }
}

/// `<install_dir>/atlas-duck-sandbox` (`.exe` on Windows).
pub fn sandbox_worker_path(install_dir: &Path) -> PathBuf {
    install_dir.join(format!(
        "atlas-duck-sandbox{}",
        std::env::consts::EXE_SUFFIX
    ))
}

/// `<install_dir>/atlas-duck-sandbox[.exe]` of this executable: the one worker path the probe
/// holder's fallback identity and every script spawn use (§3.4); `None` when the install dir is
/// unknown.
pub fn canonical_worker() -> Option<PathBuf> {
    install_dir().ok().map(|dir| sandbox_worker_path(&dir))
}

/// The app's own install directory: the parent of the running executable.
/// Under an AppImage this is the app's own mount, never a CLI's (§3.4).
pub fn install_dir() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    exe.parent().map(Path::to_path_buf).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "current_exe has no parent directory",
        )
    })
}

/// Runs the §9.4 probe once: on Windows the (L)PAC ACE check and re-apply
/// first, then one worker per probe. Blocks until every probe has finished
/// (each is bounded by `ProbeConfig::per_probe_timeout`), so callers run it
/// on a background thread. Never panics on a missing worker: the report is
/// then `NotMet` with every record `SpawnFailed`.
pub fn run_startup_probe(
    install_dir: &Path,
    app_pid: u32,
    profile: &Path,
) -> (ProbeReport, Option<AceEnsure>) {
    run_startup_probe_with(install_dir, app_pid, profile, None)
}

/// `run_startup_probe` with the Windows `WRITE_DAC` answer forced:
/// `Some(false)` makes the ACE step behave as in a per-machine install,
/// `None` probes the real file handle. Ignored off Windows.
pub fn run_startup_probe_with(
    install_dir: &Path,
    app_pid: u32,
    profile: &Path,
    can_write_dac: Option<bool>,
) -> (ProbeReport, Option<AceEnsure>) {
    let ace = ensure_worker_aces(install_dir, can_write_dac);
    let cfg = ProbeConfig::new(
        sandbox_worker_path(install_dir),
        app_pid,
        profile.to_path_buf(),
    );
    (run_with_platform_spawner(&cfg), ace)
}

#[cfg(windows)]
fn ensure_worker_aces(install_dir: &Path, can_write_dac: Option<bool>) -> Option<AceEnsure> {
    use atlas_duck_sandbox_host::windows::{ensure_aces, worker_ace_files};
    let files = match worker_ace_files(install_dir) {
        Ok(files) => files,
        Err(_) => {
            tracing::warn!(
                event = LOG_EVENT_SANDBOX_PROBE,
                reason = "ace_files_unavailable"
            );
            return None;
        }
    };
    match ensure_aces(&files, can_write_dac) {
        Ok(done) => Some(done),
        Err(_) => {
            tracing::warn!(
                event = LOG_EVENT_SANDBOX_PROBE,
                reason = "ace_ensure_failed"
            );
            None
        }
    }
}

#[cfg(not(windows))]
fn ensure_worker_aces(_install_dir: &Path, _can_write_dac: Option<bool>) -> Option<AceEnsure> {
    None
}

/// A spawner whose every spawn fails with the error `platform_spawner()`
/// returned, so the report is still complete: every record `SpawnFailed`,
/// floor `NotMet` (T15's documented caller contract).
struct FailingSpawner {
    kind: io::ErrorKind,
    raw: Option<i32>,
}

impl FailingSpawner {
    fn from_error(e: &io::Error) -> FailingSpawner {
        FailingSpawner {
            kind: e.kind(),
            raw: e.raw_os_error(),
        }
    }
}

impl WorkerSpawner for FailingSpawner {
    fn spawn(&self, _spec: &SpawnSpec) -> io::Result<Box<dyn WorkerProcess>> {
        Err(match self.raw {
            Some(code) => io::Error::from_raw_os_error(code),
            None => io::Error::from(self.kind),
        })
    }
}

fn run_with_platform_spawner(cfg: &ProbeConfig) -> ProbeReport {
    // Linux: the host verifies "every thread of the worker is confined"
    // from /proc/<pid>/task/*/status (§9.4); without the hook T15 fails the
    // floor. Other OSes have no thread check.
    #[cfg(target_os = "linux")]
    let linux_hook = atlas_duck_sandbox_host::linux::ProcTaskStatusHook;
    #[cfg(target_os = "linux")]
    let hook: Option<&dyn SpawnHook> = Some(&linux_hook);
    #[cfg(not(target_os = "linux"))]
    let hook: Option<&dyn SpawnHook> = None;

    // No worker file, nothing to spawn: `run_probes` fails every record at once
    // and never uses the spawner, so do not open the platform's profile (on
    // Windows `CreateAppContainerProfile` has stalled for ~2.7 s, measured).
    if std::fs::metadata(&cfg.worker).is_err() {
        return run_probes(
            &FailingSpawner {
                kind: io::ErrorKind::NotFound,
                raw: None,
            },
            hook,
            cfg,
        );
    }
    match platform_spawner() {
        Ok(spawner) => {
            // Windows: the LPAC floor first; when it is not met, the plain
            // AppContainer floor, and the better of the two is reported.
            run_probes_with_fallback(spawner.as_ref(), &fallback_spawner, hook, cfg)
        }
        Err(e) => run_probes(&FailingSpawner::from_error(&e), hook, cfg),
    }
}

/// What the background thread runs: locate the install dir and the user
/// profile, then probe with this process as the memory-read target. If
/// either location is unknown, the probe still produces a report (worker
/// path empty, so every record is `SpawnFailed` and the floor is `NotMet`)
/// instead of failing startup.
fn startup_job() -> (ProbeReport, Option<AceEnsure>) {
    let app_pid = std::process::id();
    let install = match install_dir() {
        Ok(dir) => dir,
        Err(_) => {
            tracing::warn!(
                event = LOG_EVENT_SANDBOX_PROBE,
                reason = "install_dir_unknown"
            );
            return unavailable(app_pid);
        }
    };
    let profile = match base_dirs() {
        Ok(dirs) => dirs.home,
        Err(_) => {
            tracing::warn!(
                event = LOG_EVENT_SANDBOX_PROBE,
                reason = "profile_dir_unknown"
            );
            return unavailable(app_pid);
        }
    };
    run_startup_probe(&install, app_pid, &profile)
}

fn unavailable(app_pid: u32) -> (ProbeReport, Option<AceEnsure>) {
    let cfg = ProbeConfig::new(PathBuf::new(), app_pid, PathBuf::new());
    (run_with_platform_spawner(&cfg), None)
}

/// Starts the probe on a background thread named `atlas-duck-probe` and
/// returns at once. When it finishes, the report lands in
/// `AppState::probe` and one log line is written. Call it from `setup`,
/// after `AppState` is managed, in every startup state: the probe needs no
/// data dir, and its log line waits in the diagnostic log's memory buffer
/// until a data dir is attached.
///
/// Generic over the runtime so the mock runtime of `tauri::test` can drive
/// it; `run_gui` passes its `AppHandle` (the default `Wry`) unchanged.
pub fn spawn_startup_probe<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Err(e) = spawn_startup_probe_with(app, startup_job) {
        tracing::error!(
            event = LOG_EVENT_SANDBOX_PROBE,
            reason = "thread_spawn_failed",
            error_class = ?e.kind()
        );
    }
}

/// `spawn_startup_probe` with the probe job injected (tests use a gated job
/// to prove the caller is never blocked). Returns the thread handle.
pub fn spawn_startup_probe_with<R, F>(
    app: &tauri::AppHandle<R>,
    job: F,
) -> io::Result<JoinHandle<()>>
where
    R: tauri::Runtime,
    F: FnOnce() -> (ProbeReport, Option<AceEnsure>) + Send + 'static,
{
    let handle = app.clone();
    // R1: the `APP_START` wait counts from here (before the thread exists, so it never undercounts).
    if let Some(state) = app.try_state::<AppState>() {
        state.probe.mark_started(Instant::now());
    }
    std::thread::Builder::new()
        .name(PROBE_THREAD_NAME.to_owned())
        .spawn(move || {
            let (report, ace) = job();
            log_probe_report(&report, ace.as_ref());
            match handle.try_state::<AppState>() {
                Some(state) => {
                    // The report is set once per process (R10: one probe per start, which
                    // the first script awaits through the same holder).
                    let _ = state.probe.set(report);
                }
                None => tracing::warn!(
                    event = LOG_EVENT_SANDBOX_PROBE,
                    reason = "app_state_missing"
                ),
            }
        })
}

/// `snake_case` name of a probe id, the same spelling serde gives it.
pub fn probe_id_name(id: ProbeId) -> &'static str {
    match id {
        ProbeId::FileInProfile => "file_in_profile",
        ProbeId::ConnectLoopback => "connect_loopback",
        ProbeId::ConnectPublic => "connect_public",
        ProbeId::SpawnProcess => "spawn_process",
        ProbeId::RawClone => "raw_clone",
        ProbeId::Clone3 => "clone3",
        ProbeId::MemReadProcessVm => "mem_read_process_vm",
        ProbeId::MemReadProcMem => "mem_read_proc_mem",
        ProbeId::TaskForPid => "task_for_pid",
        ProbeId::OpenProcessVmRead => "open_process_vm_read",
        ProbeId::CredRead => "cred_read",
        ProbeId::OpenClipboard => "open_clipboard",
        ProbeId::MachLookupSecurityd => "mach_lookup_securityd",
        ProbeId::EngineSelfTest => "engine_self_test",
        ProbeId::EnvNames => "env_names",
        ProbeId::HandleSentinel => "handle_sentinel",
    }
}

/// `met` or `not_met`.
pub fn floor_label(floor: &FloorVerdict) -> &'static str {
    match floor {
        FloorVerdict::Met => "met",
        FloorVerdict::NotMet { .. } => "not_met",
    }
}

/// Failed floor probes joined with `+` (`file_in_profile+task_for_pid`), or
/// `none` when the floor is met. `+` keeps the value a bare log token.
pub fn failed_label(floor: &FloorVerdict) -> String {
    match floor {
        FloorVerdict::Met => LABEL_NONE.to_owned(),
        FloorVerdict::NotMet { failed } if failed.is_empty() => LABEL_NONE.to_owned(),
        FloorVerdict::NotMet { failed } => failed
            .iter()
            .map(|p| probe_id_name(*p))
            .collect::<Vec<_>>()
            .join("+"),
    }
}

/// `landlock:on+other:off`, or `none` (extra layers never change the floor).
pub fn extra_layers_label(layers: &[(String, bool)]) -> String {
    if layers.is_empty() {
        return LABEL_NONE.to_owned();
    }
    layers
        .iter()
        .map(|(name, on)| format!("{name}:{}", if *on { "on" } else { "off" }))
        .collect::<Vec<_>>()
        .join("+")
}

/// `present`, `reapplied`, `missing_no_write_dac`, or `n/a` (no ACE step ran).
pub fn ace_label(ace: Option<&AceEnsure>) -> &'static str {
    match ace {
        None => "n/a",
        #[cfg(windows)]
        Some(AceEnsure::Present) => "present",
        #[cfg(windows)]
        Some(AceEnsure::Reapplied) => "reapplied",
        #[cfg(windows)]
        Some(AceEnsure::MissingNoWriteDac) => "missing_no_write_dac",
        #[cfg(not(windows))]
        Some(never) => match *never {},
    }
}

/// `lpac` or `appcontainer`: what the worker's own token said (Windows), or
/// `n/a` when no worker reported one (every other OS, or no `probe.ready`).
pub fn mode_label(report: &ProbeReport) -> &'static str {
    match report.confinement.as_ref().and_then(|c| c.lpac) {
        Some(true) => "lpac",
        Some(false) => "appcontainer",
        None => "n/a",
    }
}

/// `true` or `false`: whether the Windows unconfined control held for every
/// fact (listener, Winsock, credential read); `n/a` where no control ran.
pub fn control_label(report: &ProbeReport) -> &'static str {
    match &report.control {
        Some(c) if c.ok() => "true",
        Some(_) => "false",
        None => "n/a",
    }
}

/// The probes that failed under LPAC when the plain AppContainer fallback
/// replaced the report (`connect_loopback+cred_read`), `n/a` otherwise.
pub fn lpac_failed_label(report: &ProbeReport) -> String {
    match &report.lpac_failed {
        None => "n/a".to_owned(),
        Some(failed) if failed.is_empty() => LABEL_NONE.to_owned(),
        Some(failed) => failed
            .iter()
            .map(|p| probe_id_name(*p))
            .collect::<Vec<_>>()
            .join("+"),
    }
}

/// Writes the one summary line:
/// `event=sandbox_probe floor=<met|not_met> failed=<ids|none>
/// extra_layers=<…|none> engine_version=<v|unknown> worker_version=<v|unknown>
/// ace=<present|reapplied|missing_no_write_dac|n/a>
/// appcontainer_mode=<lpac|appcontainer|n/a> control_ok=<true|false|n/a>
/// lpac_failed=<ids|n/a> dropped_fields=<n>`
/// (`dropped_fields` is appended by the diagnostic log's allowlist layer, T08).
/// It holds no path: not the install dir, the worker, the profile or the
/// binary identity (§7.7 metadata only).
pub fn log_probe_report(report: &ProbeReport, ace: Option<&AceEnsure>) {
    let failed = failed_label(&report.floor);
    let extra_layers = extra_layers_label(&report.extra_layers);
    tracing::info!(
        event = LOG_EVENT_SANDBOX_PROBE,
        floor = floor_label(&report.floor),
        failed = failed.as_str(),
        extra_layers = extra_layers.as_str(),
        engine_version = report.engine_version.as_deref().unwrap_or(LABEL_UNKNOWN),
        worker_version = report.worker_version.as_deref().unwrap_or(LABEL_UNKNOWN),
        ace = ace_label(ace),
        appcontainer_mode = mode_label(report),
        control_ok = control_label(report),
        lpac_failed = lpac_failed_label(report).as_str(),
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use atlas_duck_sandbox_host::probe::{Evidence, ProbeRecord};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn report(floor: FloorVerdict, records: Vec<ProbeRecord>) -> ProbeReport {
        ProbeReport {
            worker_version: None,
            engine_version: None,
            identity: None,
            confinement: None,
            threads: None,
            records,
            floor,
            extra_layers: Vec::new(),
            control: None,
            lpac_failed: None,
        }
    }

    fn record(probe: ProbeId, outcome: ProbeOutcome) -> ProbeRecord {
        ProbeRecord {
            probe,
            outcome,
            evidence: Evidence::Reported { os_error: None },
        }
    }

    fn not_met(failed: Vec<ProbeId>) -> FloorVerdict {
        FloorVerdict::NotMet { failed }
    }

    /// Instants cannot be built from nothing: `None` where the clock is too young to go back.
    fn ago(secs: f64) -> Option<Instant> {
        Instant::now().checked_sub(Duration::from_secs_f64(secs))
    }

    /// R1 (PD-138): the 5 s count from the probe's start. 4 s in, 1 s is left at most; 6 s in,
    /// none; no probe, none.
    #[test]
    fn app_start_wait_is_measured_from_probe_start() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        assert_eq!(APP_START_WAIT, Duration::from_secs(5));
        // The probe started when `audit::open` finished (zero elapsed): the whole bound.
        assert_eq!(app_start_wait_left(Some(t0), t0), Duration::from_secs(5));
        // Started 4 s before `audit::open` finished: at most 1 s to wait.
        assert_eq!(app_start_wait_left(Some(t0), at(4)), Duration::from_secs(1));
        assert_eq!(
            app_start_wait_left(Some(t0), t0 + Duration::from_millis(4_500)),
            Duration::from_millis(500)
        );
        // Started 5 s or 6 s before: none left.
        assert_eq!(app_start_wait_left(Some(t0), at(5)), Duration::ZERO);
        assert_eq!(app_start_wait_left(Some(t0), at(6)), Duration::ZERO);
        assert_eq!(app_start_wait_left(Some(t0), at(600)), Duration::ZERO);
        // A clock reading before the start (never happens, but never a panic or a longer wait).
        assert_eq!(app_start_wait_left(Some(at(3)), t0), Duration::from_secs(5));
        // No probe was started: nothing to wait for.
        assert_eq!(app_start_wait_left(None, t0), Duration::ZERO);
    }

    /// The holder's wait uses the left-over: it returns at once with no probe started or after the
    /// bound, waits out what is left for a missing report, and ends early when the report lands.
    #[tokio::test]
    async fn app_start_wait_helper_waits_only_what_is_left() -> TestResult {
        let bound = Duration::from_secs(30);
        // No probe started: at once, report still missing.
        let none = ProbeHolder::default();
        let t = Instant::now();
        tokio::time::timeout(bound, none.wait_for_app_start()).await?;
        assert!(t.elapsed() < Duration::from_secs(2));
        assert!(none.get().is_none());

        // Started 6 s ago: nothing left.
        let Some(long_ago) = ago(6.0) else {
            return Ok(());
        };
        let late = ProbeHolder::default();
        late.mark_started(long_ago);
        let t = Instant::now();
        tokio::time::timeout(bound, late.wait_for_app_start()).await?;
        assert!(t.elapsed() < Duration::from_secs(2));

        // Started 4.7 s ago, no report: the remaining ~0.3 s are waited out, no more.
        let Some(recent) = ago(4.7) else {
            return Ok(());
        };
        let pending = ProbeHolder::default();
        pending.mark_started(recent);
        let t = Instant::now();
        tokio::time::timeout(bound, pending.wait_for_app_start()).await?;
        let waited = t.elapsed();
        assert!(waited >= Duration::from_millis(200), "{waited:?}");
        assert!(waited < Duration::from_secs(3), "{waited:?}");
        assert!(pending.get().is_none());

        // Started now, the report lands after 100 ms: the wait ends then, not after 5 s.
        let holder = Arc::new(ProbeHolder::default());
        holder.mark_started(Instant::now());
        let setter = holder.clone();
        let t = Instant::now();
        let setting = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            setter.set(report(FloorVerdict::Met, Vec::new()))
        });
        tokio::time::timeout(bound, holder.wait_for_app_start()).await?;
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        assert!(holder.get().is_some());
        assert!(tokio::time::timeout(bound, setting).await??);
        Ok(())
    }

    /// S-05: `blocked` only with every scored memory-read probe `Blocked` and none listed as
    /// failed; any `Allowed` is `allowed`; everything else is `inconclusive`.
    #[test]
    fn memory_read_label_fails_closed() {
        use ProbeOutcome::{Allowed, Blocked, Error};
        let blocked = |p| record(p, Blocked);
        let table: Vec<(ProbeReport, &str, &str)> = vec![
            (
                report(
                    FloorVerdict::Met,
                    vec![
                        blocked(ProbeId::MemReadProcessVm),
                        blocked(ProbeId::MemReadProcMem),
                    ],
                ),
                MEMORY_READ_BLOCKED,
                "linux, both blocked",
            ),
            (
                report(FloorVerdict::Met, vec![blocked(ProbeId::TaskForPid)]),
                MEMORY_READ_BLOCKED,
                "macos",
            ),
            (
                report(
                    not_met(vec![ProbeId::ConnectPublic]),
                    vec![
                        blocked(ProbeId::OpenProcessVmRead),
                        record(ProbeId::ConnectPublic, Allowed),
                    ],
                ),
                MEMORY_READ_BLOCKED,
                "windows: another floor probe failed, the memory read held",
            ),
            (
                report(
                    not_met(vec![ProbeId::OpenProcessVmRead]),
                    vec![record(ProbeId::OpenProcessVmRead, Allowed)],
                ),
                MEMORY_READ_ALLOWED,
                "windows allowed",
            ),
            (
                report(
                    not_met(vec![ProbeId::TaskForPid]),
                    vec![record(ProbeId::TaskForPid, Allowed)],
                ),
                MEMORY_READ_ALLOWED,
                "macos allowed",
            ),
            (
                report(
                    not_met(vec![ProbeId::MemReadProcMem]),
                    vec![
                        record(ProbeId::MemReadProcessVm, Error),
                        record(ProbeId::MemReadProcMem, Allowed),
                    ],
                ),
                MEMORY_READ_ALLOWED,
                "an allowed one after an errored one still wins",
            ),
            (
                report(
                    not_met(vec![ProbeId::MemReadProcessVm]),
                    vec![
                        record(ProbeId::MemReadProcessVm, Error),
                        blocked(ProbeId::MemReadProcMem),
                    ],
                ),
                MEMORY_READ_INCONCLUSIVE,
                "one blocked, one errored",
            ),
            (
                report(
                    not_met(vec![ProbeId::OpenProcessVmRead]),
                    vec![record(ProbeId::OpenProcessVmRead, Error)],
                ),
                MEMORY_READ_INCONCLUSIVE,
                "errored",
            ),
            (
                report(not_met(Vec::new()), Vec::new()),
                MEMORY_READ_INCONCLUSIVE,
                "no record at all",
            ),
            (
                report(
                    FloorVerdict::Met,
                    vec![blocked(ProbeId::FileInProfile), blocked(ProbeId::Clone3)],
                ),
                MEMORY_READ_INCONCLUSIVE,
                "no memory-read record",
            ),
            (
                // A blocked record the floor still lists as failed: not trusted.
                report(
                    not_met(vec![ProbeId::MemReadProcMem]),
                    vec![blocked(ProbeId::MemReadProcessVm)],
                ),
                MEMORY_READ_INCONCLUSIVE,
                "listed as failed without a record",
            ),
        ];
        for (r, want, why) in table {
            assert_eq!(memory_read_label(&r), want, "{why}");
        }
    }

    /// `scripts` as the Settings DTO and the status line see it: only a `NotMet` floor with the
    /// setting on is degraded; no report is disabled.
    #[test]
    fn scripts_state_follows_the_floor_and_the_setting() {
        let met = report(FloorVerdict::Met, Vec::new());
        let unmet = report(not_met(vec![ProbeId::FileInProfile]), Vec::new());
        for (r, allowed, want) in [
            (Some(&met), false, SCRIPTS_ENABLED),
            (Some(&met), true, SCRIPTS_ENABLED),
            (Some(&unmet), false, SCRIPTS_DISABLED),
            (Some(&unmet), true, SCRIPTS_DEGRADED),
            (None, false, SCRIPTS_DISABLED),
            (None, true, SCRIPTS_DISABLED),
        ] {
            assert_eq!(scripts_state(r, allowed), want, "{r:?} {allowed}");
        }
    }

    /// The identity goes into the record as strings and whole seconds, without a path.
    #[test]
    fn identity_json_shape() {
        let identity = SandboxBinaryIdentity {
            file_id: FileId::DevIno {
                dev: 2049,
                ino: 18_446_744_073_709_551_000,
            },
            size: 1234,
            mtime: SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 999_999_999),
            embedded_version: "v1".to_owned(),
        };
        assert_eq!(
            identity_json(&identity),
            json!({
                "file_id": "dev_ino:2049:18446744073709551000",
                "size": 1234,
                "mtime": 1_700_000_000_u64,
                "embedded_version": "v1",
            })
        );
        let windows = SandboxBinaryIdentity {
            file_id: FileId::FileIndex {
                volume_serial: 7,
                index: 9,
            },
            mtime: SystemTime::UNIX_EPOCH - Duration::from_secs(1),
            ..identity
        };
        let v = identity_json(&windows);
        assert_eq!(v["file_id"], json!("file_index:7:9"));
        assert_eq!(v["mtime"], Value::Null);
    }
}
