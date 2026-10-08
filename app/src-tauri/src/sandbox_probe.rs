//! §9.4 "On each app start": run the probe worker from the real app so the
//! installed app process is the memory-read target, never on the startup
//! path. The report is held in `AppState` (M2 records it in `APP_START`, M6
//! shows it in Settings, M8 gates scripts on it) and summarised in one
//! diagnostic log line. The probe never blocks startup and only decides
//! whether scripts are enabled.

use std::io;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;

use atlas_duck_ipc::paths::base_dirs;
use atlas_duck_ipc::sandbox::probe::ProbeId;
use atlas_duck_sandbox_host::platform_spawner;
use atlas_duck_sandbox_host::probe::{FloorVerdict, ProbeConfig, ProbeReport, run_probes};
use atlas_duck_sandbox_host::spawn::{SpawnHook, SpawnSpec, WorkerProcess, WorkerSpawner};
use tauri::Manager;

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

/// `<install_dir>/atlas-duck-sandbox` (`.exe` on Windows).
pub fn sandbox_worker_path(install_dir: &Path) -> PathBuf {
    install_dir.join(format!(
        "atlas-duck-sandbox{}",
        std::env::consts::EXE_SUFFIX
    ))
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

    match platform_spawner() {
        Ok(spawner) => run_probes(spawner.as_ref(), hook, cfg),
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
    std::thread::Builder::new()
        .name(PROBE_THREAD_NAME.to_owned())
        .spawn(move || {
            let (report, ace) = job();
            log_probe_report(&report, ace.as_ref());
            match handle.try_state::<AppState>() {
                Some(state) => {
                    // The report is set once per process; a second run (M8's
                    // "before the first script") needs its own storage.
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

/// Writes the one summary line:
/// `event=sandbox_probe floor=<met|not_met> failed=<ids|none>
/// extra_layers=<…|none> engine_version=<v|unknown> worker_version=<v|unknown>
/// ace=<present|reapplied|missing_no_write_dac|n/a> dropped_fields=<n>`
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
    );
}
