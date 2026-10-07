//! App-wide state managed by Tauri (`app.manage`). Later milestones read it and add fields.

use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_ipc::paths::LocalDataDir;

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

/// Managed via `app.manage(AppState { .. })` in `setup`.
#[derive(Debug)]
pub struct AppState {
    pub startup: StartupSummary,
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
