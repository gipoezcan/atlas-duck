//! Startup gate for GUI and `--background` launches (§2.5 Scope, §3.1, §7.7).
//!
//! Order: this host's pinned `paths.toml` -> data-dir existence and local-filesystem
//! check (§7.7) -> `instance.lock` (§3.1). Nothing is created or written before the
//! lock is taken, and nothing at all in the error states.

use std::path::{Path, PathBuf};

use atlas_duck_audit::lock::{InstanceLock, LockError};
use atlas_duck_ipc::paths::{
    self, DataDirResolution, LocalDataDir, NotLocalKind, PinnedError, PinnedPaths,
};
use tauri::AppHandle;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

use crate::diag::Diag;
use crate::startup::crash::{clear_crashpad_reports, webview_data_dir};
use crate::state::StartupSummary;

/// §7.7 Path stability (verbatim).
pub const MSG_DATA_DIR_NOT_FOUND: &str = "data directory <path> not found";
/// §3.1 Single instance (verbatim).
pub const MSG_RUNNING_ON_OTHER_HOST: &str =
    "atlas-duck is running on another machine (<host>) with this data directory";
/// Spec silent on the text; plan placeholder awaiting user confirmation.
pub const MSG_DATA_DIR_NOT_LOCAL: &str = "data directory <path> is not on a local filesystem";
/// Spec silent (unreadable pinned file); plan placeholder awaiting user confirmation.
pub const MSG_PINNED_UNREADABLE: &str = "atlas-duck path settings <path> could not be read";
/// Spec silent (I/O error while checking or locking the data dir); plan placeholder.
pub const MSG_DATA_DIR_UNUSABLE: &str = "data directory <path> could not be opened";

/// Diagnostic-log fields this module emits (added to the T08 allowlist).
pub const LOG_FIELDS: &[&str] = &["startup_state"];

/// Title of the native error dialogs.
const DIALOG_TITLE: &str = "atlas-duck";

const PLACEHOLDERS: [&str; 2] = ["<path>", "<host>"];

/// Outcome of the startup gate.
#[derive(Debug)]
pub enum StartupState {
    /// This host has no pinned file of its own (§2.5 First run). M1 only keeps the tray running.
    BeforeFirstRun,
    /// Local, existing data dir; this process holds `instance.lock`.
    Ready {
        data: LocalDataDir,
        lock: InstanceLock,
    },
    /// The pinned data dir does not exist: `not_configured`, never a fresh store (§7.7).
    DataDirMissing { path: PathBuf },
    /// The pinned data dir is not on a local filesystem (§7.7).
    DataDirNotLocal { path: PathBuf, kind: NotLocalKind },
    /// Plan addition (spec silent): the locality check or `instance.lock` failed with an
    /// I/O error, for example a data dir this user cannot write to.
    DataDirUnusable { path: PathBuf },
    /// Another instance holds `instance.lock`. `Some(host)` only when its record names a
    /// different host (Unix; on Windows the record is unreadable, §3.1).
    AlreadyRunning { other_host: Option<String> },
    /// Plan addition (spec silent): this host's pinned file exists but cannot be read or parsed.
    PinnedUnreadable { path: PathBuf },
}

impl StartupState {
    /// The summary kept in `AppState`; `None` for `AlreadyRunning`, which exits.
    pub fn summary(&self) -> Option<StartupSummary> {
        match self {
            StartupState::BeforeFirstRun => Some(StartupSummary::BeforeFirstRun),
            StartupState::Ready { .. } => Some(StartupSummary::Ready),
            StartupState::DataDirMissing { .. } => Some(StartupSummary::DataDirMissing),
            StartupState::DataDirNotLocal { .. } => Some(StartupSummary::DataDirNotLocal),
            StartupState::DataDirUnusable { .. } => Some(StartupSummary::DataDirUnusable),
            StartupState::PinnedUnreadable { .. } => Some(StartupSummary::PinnedUnreadable),
            StartupState::AlreadyRunning { .. } => None,
        }
    }

    /// Value of the `startup_state` log field.
    pub fn log_name(&self) -> &'static str {
        match self.summary() {
            Some(summary) => summary.as_str(),
            None => "already_running",
        }
    }
}

/// Runs the gate for this host. `pinned` is the result of reading this host's pinned file
/// (see [`read_this_host_pinned`]) and `host` is this host's `host_name()`, which is
/// recorded in `instance.lock`. An unreadable pinned file reports the path
/// [`this_host_pinned_file`] computes for `host`.
pub fn gate(pinned: Result<Option<PinnedPaths>, PinnedError>, host: &str) -> StartupState {
    gate_in(&this_host_pinned_file(host), pinned, host)
}

/// [`gate`] with the pinned file's path given explicitly. Only `Ready` writes anything,
/// and only `<data>/instance.lock`. The integration tests call this one, because
/// `base_dirs()` never follows the test's environment (§7.7 Path stability).
pub fn gate_in(
    pinned_file: &Path,
    pinned: Result<Option<PinnedPaths>, PinnedError>,
    host: &str,
) -> StartupState {
    let pinned = match pinned {
        Ok(pinned) => pinned,
        // Never BeforeFirstRun: that would let the M6 wizard pin a second data dir
        // while the store behind the unreadable file still exists.
        Err(_) => {
            return StartupState::PinnedUnreadable {
                path: pinned_file.to_path_buf(),
            };
        }
    };
    let data_dir = pinned.as_ref().map(|p| p.data_dir.clone());
    let resolution = match paths::resolve_data_dir(pinned.as_ref()) {
        Ok(resolution) => resolution,
        Err(_) => {
            return StartupState::DataDirUnusable {
                path: data_dir.unwrap_or_default(),
            };
        }
    };
    match resolution {
        DataDirResolution::BeforeFirstRun => StartupState::BeforeFirstRun,
        DataDirResolution::Missing { path } => StartupState::DataDirMissing { path },
        DataDirResolution::NotLocal { path, kind } => StartupState::DataDirNotLocal { path, kind },
        DataDirResolution::Local(data) => take_lock(data, host),
    }
}

fn take_lock(data: LocalDataDir, host: &str) -> StartupState {
    match InstanceLock::acquire(&data, host) {
        Ok(lock) => StartupState::Ready { data, lock },
        Err(LockError::Held(holder)) => StartupState::AlreadyRunning {
            other_host: holder
                .filter(|h| h.host != host)
                // The record is file content: re-sanitize it before it reaches any UI text.
                .map(|h| paths::sanitize_host_component(&h.host)),
        },
        Err(LockError::Io(_)) => StartupState::DataDirUnusable {
            path: data.path().to_path_buf(),
        },
    }
}

/// Where this host's pinned `paths.toml` lives (§7.7). Falls back to the bare file name
/// when the base folders cannot be resolved, so the error text still names the file.
pub fn this_host_pinned_file(host: &str) -> PathBuf {
    match paths::base_dirs() {
        Ok(base) => paths::paths_file(&base, host),
        Err(_) => PathBuf::from("paths.toml"),
    }
}

/// Reads this host's pinned file. Returns the host name and the read result. A failure
/// to resolve the host name or the base folders is reported as `PinnedError::Io`, so the
/// gate fails closed with `PinnedUnreadable`.
pub fn read_this_host_pinned() -> (String, Result<Option<PinnedPaths>, PinnedError>) {
    let host = match paths::host_name() {
        Ok(host) => host,
        Err(e) => return (String::new(), Err(PinnedError::Io(e))),
    };
    let pinned = match paths::base_dirs() {
        Ok(base) => paths::read_pinned(&paths::paths_file(&base, &host)),
        Err(e) => Err(PinnedError::Io(e)),
    };
    (host, pinned)
}

/// Replaces the first `<path>` or `<host>` placeholder in `template` with `value`.
/// The substituted value is never scanned again.
pub fn render_message(template: &str, value: &str) -> String {
    let first = PLACEHOLDERS
        .iter()
        .filter_map(|ph| template.find(ph).map(|at| (at, ph.len())))
        .min_by_key(|&(at, _)| at);
    match first {
        Some((at, len)) => {
            let mut out = String::with_capacity(template.len() + value.len());
            out.push_str(&template[..at]);
            out.push_str(value);
            out.push_str(&template[at + len..]);
            out
        }
        None => template.to_owned(),
    }
}

/// The app-generated text for a state, if it has one.
pub fn startup_message(state: &StartupState) -> Option<String> {
    let with_path =
        |template: &str, path: &Path| render_message(template, &path.display().to_string());
    match state {
        StartupState::DataDirMissing { path } => Some(with_path(MSG_DATA_DIR_NOT_FOUND, path)),
        StartupState::DataDirNotLocal { path, .. } => Some(with_path(MSG_DATA_DIR_NOT_LOCAL, path)),
        StartupState::DataDirUnusable { path } => Some(with_path(MSG_DATA_DIR_UNUSABLE, path)),
        StartupState::PinnedUnreadable { path } => Some(with_path(MSG_PINNED_UNREADABLE, path)),
        StartupState::AlreadyRunning {
            other_host: Some(host),
        } => Some(render_message(MSG_RUNNING_ON_OTHER_HOST, host)),
        StartupState::AlreadyRunning { other_host: None }
        | StartupState::BeforeFirstRun
        | StartupState::Ready { .. } => None,
    }
}

/// Shows an app-generated error text to the user (M1: a native message dialog).
pub trait ErrorPresenter {
    fn show(&self, text: &str);
}

/// Native error dialog via tauri-plugin-dialog (M1's "error window", gap G-7).
pub struct DialogPresenter {
    app: AppHandle,
}

impl DialogPresenter {
    pub fn new(app: AppHandle) -> Self {
        DialogPresenter { app }
    }

    /// Shows `text` on a helper thread, waits until the user dismisses it, then ends the
    /// process with exit code 0. `blocking_show` must not run on the main thread, which
    /// is the thread that draws the dialog.
    pub fn show_then_exit(&self, text: &str) {
        let app = self.app.clone();
        let text = text.to_owned();
        let spawned = std::thread::Builder::new()
            .name("atlas-duck-exit-dialog".to_owned())
            .spawn(move || {
                let _ = app
                    .dialog()
                    .message(text)
                    .title(DIALOG_TITLE)
                    .kind(MessageDialogKind::Error)
                    .buttons(MessageDialogButtons::Ok)
                    .blocking_show();
                std::process::exit(0);
            });
        if spawned.is_err() {
            std::process::exit(0);
        }
    }
}

impl ErrorPresenter for DialogPresenter {
    fn show(&self, text: &str) {
        self.app
            .dialog()
            .message(text)
            .title(DIALOG_TITLE)
            .kind(MessageDialogKind::Error)
            .buttons(MessageDialogButtons::Ok)
            .show(|_| {});
    }
}

/// What `run_gui` does after the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupAction {
    /// Keep running in the tray.
    Stay,
    /// Exit with code 0, after showing `message` when there is one.
    Exit { message: Option<String> },
}

/// Applies the gate's outcome. It logs `startup_state` (the line waits in T08's buffer
/// until a data dir is attached). When `Ready` it attaches the diagnostic log and clears
/// Crashpad reports. It shows each error state's text once. It asks `AlreadyRunning` to
/// exit. Error states and `BeforeFirstRun` write nothing.
pub fn apply_startup_state(
    state: &StartupState,
    diag: &Diag,
    presenter: &dyn ErrorPresenter,
) -> StartupAction {
    diag.extend_allowed_fields(LOG_FIELDS);
    tracing::info!(event = "startup", startup_state = state.log_name());
    match state {
        StartupState::Ready { data, .. } => {
            if diag.attach_dir(data).is_err() {
                tracing::warn!(event = "diag_attach_failed");
            }
            if clear_crashpad_reports(&webview_data_dir(data)).is_err() {
                tracing::warn!(event = "crashpad_clear_failed");
            }
            StartupAction::Stay
        }
        StartupState::BeforeFirstRun => StartupAction::Stay,
        StartupState::AlreadyRunning { .. } => StartupAction::Exit {
            message: startup_message(state),
        },
        StartupState::DataDirMissing { .. }
        | StartupState::DataDirNotLocal { .. }
        | StartupState::DataDirUnusable { .. }
        | StartupState::PinnedUnreadable { .. } => {
            if let Some(text) = startup_message(state) {
                presenter.show(&text);
            }
            StartupAction::Stay
        }
    }
}
