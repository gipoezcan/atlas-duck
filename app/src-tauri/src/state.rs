//! App-wide state managed by Tauri (`app.manage`). Later milestones read it and add fields.

use std::sync::OnceLock;

use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_ipc::paths::LocalDataDir;
use atlas_duck_sandbox_host::probe::{FloorVerdict, ProbeReport};

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
/// `lock()`.
#[derive(Debug)]
pub struct DataDirHold {
    data: LocalDataDir,
    lock: InstanceLock,
}

impl DataDirHold {
    pub fn new(data: LocalDataDir, lock: InstanceLock) -> Self {
        DataDirHold { data, lock }
    }

    pub fn data(&self) -> &LocalDataDir {
        &self.data
    }

    pub fn lock(&self) -> &InstanceLock {
        &self.lock
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
}
