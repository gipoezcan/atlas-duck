//! App-wide state managed by Tauri (`app.manage`). Later milestones read it and add fields.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_ipc::paths::LocalDataDir;
use atlas_duck_ipc::server::ShutdownSignal;
use atlas_duck_sandbox_host::probe::{FloorVerdict, ProbeReport};
use tauri::async_runtime::JoinHandle;

use crate::serve::ServeState;
use crate::tray_host::TrayHost;

/// The startup outcome as the rest of the app sees it. `AlreadyRunning` is not here: that
/// instance exits before any state is managed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupSummary {
    BeforeFirstRun,
    Ready,
    DataDirMissing,
    DataDirNotLocal,
    /// Plan addition (spec silent): an I/O error while checking or locking the data dir.
    DataDirUnusable,
    PinnedUnreadable,
}

impl StartupSummary {
    /// Value of the `startup_state` diagnostic-log field.
    pub fn as_str(self) -> &'static str {
        match self {
            StartupSummary::BeforeFirstRun => "before_first_run",
            StartupSummary::Ready => "ready",
            StartupSummary::DataDirMissing => "data_dir_missing",
            StartupSummary::DataDirNotLocal => "data_dir_not_local",
            StartupSummary::DataDirUnusable => "data_dir_unusable",
            StartupSummary::PinnedUnreadable => "pinned_unreadable",
        }
    }

    /// True when the app serves a store (M2 opens it). False in every error state and
    /// before first run.
    pub fn is_ready(self) -> bool {
        self == StartupSummary::Ready
    }
}

/// Managed via `app.manage(AppState::new(..))` in `setup`.
#[derive(Debug)]
pub struct AppState {
    pub startup: StartupSummary,
    /// Linux: the §2.5 startup check (`present|missing`); `None` elsewhere. M2 records it
    /// in `APP_START`, M4 reports it in `doctor` (§4.7).
    tray_host: Option<TrayHost>,
    /// The §9.4 probe report; set once by the `atlas-duck-probe` thread.
    pub probe: OnceLock<ProbeReport>,
}

impl AppState {
    pub fn new(startup: StartupSummary, tray_host: Option<TrayHost>) -> AppState {
        AppState {
            startup,
            tray_host,
            probe: OnceLock::new(),
        }
    }

    pub fn tray_host(&self) -> Option<TrayHost> {
        self.tray_host
    }

    /// `None` until the startup probe has finished.
    pub fn probe_report(&self) -> Option<&ProbeReport> {
        self.probe.get()
    }

    /// False until a report with `FloorVerdict::Met` exists (§9.4: if the
    /// floor cannot be applied and verified, scripts are disabled).
    pub fn scripts_floor_met(&self) -> bool {
        matches!(self.probe.get().map(|r| &r.floor), Some(FloorVerdict::Met))
    }
}

/// The locked data dir, managed only in the `Ready` state. Keeping it in Tauri state holds
/// `instance.lock` for the app's whole lifetime (§3.1). The M2 audit store opens with
/// `lock()`; the serving code (T19) holds another `Arc` of the same lock.
#[derive(Debug)]
pub struct DataDirHold {
    data: LocalDataDir,
    lock: Arc<InstanceLock>,
}

impl DataDirHold {
    pub fn new(data: LocalDataDir, lock: Arc<InstanceLock>) -> Self {
        DataDirHold { data, lock }
    }

    pub fn data(&self) -> &LocalDataDir {
        &self.data
    }

    pub fn lock(&self) -> &InstanceLock {
        &self.lock
    }
}

/// The serving state (T19), managed in `Ready`. Empty until `serve::start` finished, and for
/// good when the store could not be opened (PD-06) or Quit cancelled the start.
#[derive(Default)]
pub struct ServeSlot {
    state: OnceLock<Arc<ServeState>>,
    /// The `serve::start` task (I-2): Quit cancels [`ServeSlot::quit`], then awaits it.
    starting: Mutex<Option<JoinHandle<()>>>,
    /// Quit during startup: `serve::start` passes it as `StartInputs::quit`.
    quit: ShutdownSignal,
}

impl ServeSlot {
    pub fn get(&self) -> Option<&Arc<ServeState>> {
        self.state.get()
    }

    /// The first state wins; a later one is dropped.
    pub fn set(&self, state: Arc<ServeState>) {
        let _ = self.state.set(state);
    }

    /// Cancelled by the quit path before it awaits [`ServeSlot::take_starting`].
    pub fn quit(&self) -> &ShutdownSignal {
        &self.quit
    }

    pub fn set_starting(&self, task: JoinHandle<()>) {
        *self.starting.lock().unwrap_or_else(PoisonError::into_inner) = Some(task);
    }

    /// The start task, once: the caller awaits it with a bound (the guard is released first).
    pub fn take_starting(&self) -> Option<JoinHandle<()>> {
        self.starting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tray_host::TrayHost;

    #[test]
    fn app_state_holds_the_tray_host_result() {
        let missing = AppState::new(StartupSummary::Ready, Some(TrayHost::Missing));
        assert_eq!(missing.tray_host(), Some(TrayHost::Missing));
        let present = AppState::new(StartupSummary::Ready, Some(TrayHost::Present));
        assert_eq!(present.tray_host(), Some(TrayHost::Present));
        // Off Linux there is no check; `doctor` reports null there (§4.7).
        let none = AppState::new(StartupSummary::BeforeFirstRun, None);
        assert_eq!(none.tray_host(), None);
        assert_eq!(none.startup, StartupSummary::BeforeFirstRun);
    }

    #[test]
    fn serve_slot_shares_quit_and_hands_out_the_start_task_once() {
        let slot = ServeSlot::default();
        assert!(slot.get().is_none());
        // `serve::start` passes a clone; the quit path cancels the slot's.
        let passed = slot.quit().clone();
        assert!(!passed.0.is_cancelled());
        slot.quit().cancel();
        assert!(passed.0.is_cancelled());

        assert!(slot.take_starting().is_none());
        slot.set_starting(tauri::async_runtime::spawn(async {}));
        let task = slot.take_starting();
        assert!(slot.take_starting().is_none());
        let joined = task.map(tauri::async_runtime::block_on);
        assert!(matches!(joined, Some(Ok(()))));
    }
}
