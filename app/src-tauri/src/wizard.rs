//! The first-run wizard, Rust side (§2.5 First run, First-run wizard, Requests before setup
//! completes; §7.7 data dir and pinned files; §8.6 v1 keychain mode; PD-77; M6 T23).
//!
//! Rust holds every rule; the setup page renders [`WizardState`] and sends the six `wizard_*`
//! commands (`commands::setup`). The order is the spec's: the data dir is resolved before anything
//! secret is asked.
//!
//! - **Step (0)** ([`use_dir`]): the default folder or a Rust folder dialog, the §7.7 local-filesystem
//!   check (the nearest existing ancestor first, so nothing is created on a network share), the
//!   folder created, `instance.lock` taken, this host's pinned file written ([`prepare_data_dir`]:
//!   the data dir exists before the pinned file), the Crashpad reports of the data dir's webview
//!   folders cleared, and IPC served in-process ([`ServeStarter`], the same start as `Ready`): with no
//!   `audit.db` the first-run gate answers (exit 9 `not_configured {first_run}`, the refused count in
//!   the tray and in [`WizardState::refused_count`]); with one, the pinned file carries the store's
//!   `install_id` and the normal open path follows (1a, I-34: no passphrase, no note, no `GENESIS`).
//! - **(1b)**, first the optional external anchor directory (M10 T15, §2.5: chosen before
//!   `GENESIS`, so a previous chain in it is detected, §8.5, PD-167): [`anchor_dir`] takes a folder
//!   from Rust's own dialog (shown as text; no confirmation at first run, nothing is weakened),
//!   [`anchor_dir_clear`] drops it. Or, instead of a new log, [`restore`] restores a backup
//!   (PD-168: `serve::restore_first_store`, the T13 flow with no live store) and the wizard goes on
//!   at the instances.
//! - Then ([`begin`]): on Linux the Secret Service check (the §8.6 stop text, nothing written),
//!   then the credential window for the recovery passphrase; the pair comes back over the in-memory
//!   channel (`credential::request_recovery_passphrase`), never in a command response, and goes
//!   straight into `serve::create_first_store` (new ids for every attempt, `GENESIS` with the
//!   anchor dir and an archive's kept confirmation, the pinned `install_id`, `Core::start`, the
//!   cell swapped without a rebind). A pinned file that could not name the new store is offered
//!   again ([`WizardStep::PinRetry`]) before anything else moves on.
//! - Then the recovery note (offered in the credential window), the instances, the CLI and the
//!   onboarding snippet; [`skip_instances`] and [`finish`] move on.
//!
//! What the wizard shows is derived from the serving state each time ([`step_of`]); only what the
//! user did is kept ([`Progress`]).

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use atlas_duck_audit::lock::{INSTANCE_LOCK_FILE, InstanceLock, LockError};
use atlas_duck_audit::types::RustChosenPath;
use atlas_duck_audit::{
    ArchivedDb, DB_FILE, KeyringLocality, latest_archived, read_store_install_id,
};
use atlas_duck_core::{GateState, InstanceView};
use atlas_duck_ipc::paths::{
    self, DataDirResolution, LocalDataDir, PINNED_SCHEMA_VERSION, PinnedError, PinnedPaths,
};
use secrecy::SecretString;
use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::oneshot;

use crate::commands::{CommandError, blocking};
use crate::credential::{self, FirstRunPassphrase, Purpose};
use crate::restore_flow::{NotAsked, wait_passphrase};
use crate::secret_service::{SecretService, SecretServiceCheck};
use crate::serve::{self, FirstStore, FirstStoreFailure, UnlockFailure};
use crate::startup::{
    MSG_DATA_DIR_NOT_LOCAL, MSG_DATA_DIR_UNUSABLE, MSG_RUNNING_ON_OTHER_HOST, render_message,
};
use crate::state::{DataDirHold, ServeSlot};
use crate::tray::MSG_STORE_UNAVAILABLE;
use crate::ui_sink::emit_wizard_changed;
use crate::windows::{self, AppSnapshot, Label, Relaunch, Show, WindowError};

/// §8.6 (verbatim): the wizard stops with this text (and a Quit button) when Linux has no usable
/// Secret Service; nothing is written and the first-run gate keeps answering.
pub const MSG_NEEDS_SECRET_SERVICE: &str = "atlas-duck needs a system keyring (Secret Service, e.g. GNOME Keyring or KWallet). Install or unlock one, then restart atlas-duck.";

/// §8.6 (L39): the wizard stops with this text (and a Quit button) when the keyring's backing
/// directory is not on a local filesystem. It is the text the error window shows for the same
/// state at a later start (§8.7, `GateState::Locked(KeyringNotLocal)`), so tray, error window and
/// wizard say the same; a test pins the equality.
pub const MSG_KEYRING_NOT_LOCAL: &str = "atlas-duck is locked (keyring_not_local)";

/// [`WizardError::class`] of a `wizard_finish` / `wizard_skip_instances` for another step.
pub const CLASS_WRONG_STEP: &str = "wrong_step";

/// `reason` of [`LOG_EVENT_STOPPED`] when the keyring is not local.
const REASON_KEYRING_NOT_LOCAL: &str = "keyring_not_local";

/// A data dir step 0 refused; `error_class` = [`DirRefusal::class`] (never the path).
pub const LOG_EVENT_DIR_REFUSED: &str = "wizard_data_dir_refused";
/// The wizard stopped before (1b); `reason` = the Secret Service answer, or `keyring_not_local`.
pub const LOG_EVENT_STOPPED: &str = "wizard_stopped";
/// The archive folder could not be read for the `GENESIS` link; `error_class` = `integrity|io`.
pub const LOG_EVENT_ARCHIVED_UNREADABLE: &str = "wizard_archived_unreadable";
/// The setup window could not be moved into the data dir's webview folder.
pub const LOG_EVENT_SETUP_NOT_MOVED: &str = "wizard_setup_window_not_moved";
/// Step 0 found an `audit.db` whose `install_id` could not be read (the pinned file is written
/// without one and the open fails as at startup); `error_class` = `integrity|io` (M6 final review
/// M-9).
pub const LOG_EVENT_STORE_ID_UNREADABLE: &str = "wizard_store_id_unreadable";

/// plan text (M10 T15, PD-167): shown from the first store on when its first run recorded a
/// `previous_chain_found` incident.
pub const MSG_PREVIOUS_CHAIN_FOUND: &str = "The anchor directory already holds an atlas-duck log of this computer and user. This was recorded as an integrity incident; see Audit.";

/// plan text (M10 T15, M6 final review M-9): [`WizardStep::PinRetry`]'s text; Begin writes the
/// pinned file again.
pub const MSG_PIN_WRITE_FAILED: &str = "Could not record this installation's id. Try again";

/// [`WizardError::class`] of a folder the anchor-dir dialog returned that is not an absolute UTF-8
/// path (refused before anything keeps it, as the store would refuse it at `GENESIS`).
pub const CLASS_ANCHOR_DIR_INVALID: &str = "anchor_dir_invalid";
/// [`WizardError::class`] of a failed retry of the pinned file.
pub const CLASS_PINNED_WRITE: &str = "pinned_write";

/// How long the move of the setup window waits for Tauri to forget the old one.
const RELOCATE_WAIT: Duration = Duration::from_secs(2);

// ---------- steps ----------

/// The wizard's steps in the §2.5 order (PD-77). `Stopped` carries its fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    /// (0): choose the data dir.
    DataDir,
    /// (1a): the chosen data dir holds an audit DB; it opens like at startup (unlock in the
    /// credential window, or an error window).
    ExistingStore,
    /// (1b), first (M10 T15, §2.5): the optional external anchor directory, or "Restore from a
    /// backup" instead of a new log; Begin goes on to the recovery passphrase.
    AnchorDir,
    /// (1b) instead of `GENESIS` (M10 T15, PD-168): the restore from a backup runs (its native
    /// confirmation, the file dialog, the backup's passphrase in the credential window).
    Restore,
    /// (1b): the credential window waits for the recovery passphrase.
    Passphrase,
    /// `GENESIS` is being written and the core started.
    Genesis,
    /// M10 T15 (M6 final review M-9): the first store serves but the pinned file could not name
    /// its `install_id`; Begin writes it again, and nothing else moves on until it is written.
    PinRetry,
    /// The credential window offers "Save recovery note" (§8.6: only right after `GENESIS`).
    RecoveryNote,
    Instances,
    Cli,
    Onboarding,
    Done,
    Stopped(&'static str),
}

impl WizardStep {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            WizardStep::DataDir => "data_dir",
            WizardStep::ExistingStore => "existing_store",
            WizardStep::AnchorDir => "anchor_dir",
            WizardStep::Restore => "restore",
            WizardStep::Passphrase => "passphrase",
            WizardStep::Genesis => "genesis",
            WizardStep::PinRetry => "pin_retry",
            WizardStep::RecoveryNote => "recovery_note",
            WizardStep::Instances => "instances",
            WizardStep::Cli => "cli",
            WizardStep::Onboarding => "onboarding",
            WizardStep::Done => "done",
            WizardStep::Stopped(_) => "stopped",
        }
    }
}

/// Every wire name of [`WizardStep::as_str`]: what `wizard_finish` and `wizard_skip_instances`
/// accept as the step the page showed (`commands::dto::StepName`).
pub const STEP_NAMES: [&str; 13] = [
    "data_dir",
    "existing_store",
    "anchor_dir",
    "restore",
    "passphrase",
    "genesis",
    "pin_retry",
    "recovery_note",
    "instances",
    "cli",
    "onboarding",
    "done",
    "stopped",
];

/// What runs now (one at a time; a second request is `busy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InFlight {
    DataDir,
    /// Rust's folder dialog for the anchor directory is up (M10 T15).
    AnchorDir,
    /// The restore from a backup runs, from its first dialog to its core start (M10 T15).
    Restore,
    /// The credential window waits for the passphrase pair.
    Passphrase,
    Genesis,
    /// The pinned file is written again (M10 T15).
    Pin,
}

/// Why the last step did nothing: a fixed class, and for a refused folder its app-generated text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WizardError {
    pub class: &'static str,
    pub text: Option<String>,
}

/// What the user did (and what runs); everything else is read from the serving state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Progress {
    /// This host's pinned paths once step 0 wrote them (or as startup read them).
    pub pinned: Option<PinnedPaths>,
    /// Step 0 found an audit DB in the chosen dir (1a).
    pub existing_store: bool,
    /// Step 0 ran in this process (its serving start then routes a (1a) lock or error state).
    pub step0_done: bool,
    pub stopped: Option<&'static str>,
    pub error: Option<WizardError>,
    pub in_flight: Option<InFlight>,
    /// Counts the passphrase requests: a waiter of an older request never touches a newer one.
    pub passphrase_request: u64,
    /// This wizard wrote `GENESIS` (the recovery note step follows).
    pub genesis_written: bool,
    /// M10 T15 (§2.5 (1b)): the anchor directory Rust's dialog returned, for `GENESIS`
    /// (`FirstRunInput.anchor_dir`); never from a webview.
    pub anchor_dir: Option<RustChosenPath>,
    /// M10 T15 (PD-167): the first store's first run recorded a `previous_chain_found` incident.
    pub previous_chain: bool,
    /// M10 T15 (M6 final review M-9): the first store serves, the pinned file lacks its id.
    pub pin_failed: bool,
    /// Whether the instance step is shown, decided once when the core first serves (§2.5 (1a):
    /// skipped when `config.toml` lists instances whose origins the store holds).
    pub instances_wanted: Option<bool>,
    pub instances_done: bool,
    pub cli_done: bool,
    pub finished: bool,
    pub secret_service: Option<SecretService>,
}

/// The serving facts a step is derived from.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    /// Step 0 is done: the data dir is locked (`DataDirHold`).
    pub data_dir_known: bool,
    pub snapshot: &'a AppSnapshot,
    /// The credential window is open for the first-run passphrase.
    pub passphrase_window_open: bool,
}

/// The step `p` is at, given `f` (pure).
pub fn step_of(p: &Progress, f: &Facts<'_>) -> WizardStep {
    if let Some(text) = p.stopped {
        return WizardStep::Stopped(text);
    }
    if p.finished {
        return WizardStep::Done;
    }
    if !f.data_dir_known {
        return WizardStep::DataDir;
    }
    match f.snapshot {
        // The core serves before the wizard has recorded its `GENESIS` (or its restore).
        AppSnapshot::Serving if p.in_flight == Some(InFlight::Genesis) => WizardStep::Genesis,
        AppSnapshot::Serving if p.in_flight == Some(InFlight::Restore) => WizardStep::Restore,
        // M6 final review M-9: nothing moves on while the pinned file lacks the store's id.
        AppSnapshot::Serving if p.pin_failed => WizardStep::PinRetry,
        AppSnapshot::Serving => {
            if p.genesis_written && f.passphrase_window_open {
                WizardStep::RecoveryNote
            } else if !p.instances_done && p.instances_wanted != Some(false) {
                WizardStep::Instances
            } else if !p.cli_done {
                WizardStep::Cli
            } else {
                WizardStep::Onboarding
            }
        }
        // (1b): the anchor-dir step (with the restore alternative) until Begin asks for the
        // passphrase; a closed passphrase window or a failed attempt comes back to it.
        AppSnapshot::Gate(GateState::FirstRun) => match p.in_flight {
            Some(InFlight::Genesis) => WizardStep::Genesis,
            Some(InFlight::Restore) => WizardStep::Restore,
            Some(InFlight::Passphrase) => WizardStep::Passphrase,
            _ => WizardStep::AnchorDir,
        },
        // The start after step 0 is still opening the store.
        AppSnapshot::BeforeFirstRun | AppSnapshot::Starting if !p.existing_store => {
            WizardStep::AnchorDir
        }
        // PD-06: nothing is served; only a restart helps.
        AppSnapshot::StoreUnavailable => WizardStep::Stopped(MSG_STORE_UNAVAILABLE),
        // (1a): locked, store newer, starting; the credential window or the error window says what
        // to do (§8.7).
        _ => WizardStep::ExistingStore,
    }
}

/// The instance step is wanted when there is none yet, or one still needs its native origin
/// confirmation or a URL change accepted (§7.1, §2.5 (1a)).
pub fn instances_need_setup(views: &[InstanceView]) -> bool {
    views.is_empty()
        || views
            .iter()
            .any(|v| v.state == "instance_unconfirmed" || v.pending_url_change.is_some())
}

// ---------- step 0 ----------

/// Why step 0 refused a folder. Nothing was pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirRefusal {
    /// A relative path (never from the dialogs; defence in depth).
    NotAbsolute,
    /// §7.7: the folder, or the existing folder it would be created in, is not on a local
    /// filesystem.
    NotLocal(PathBuf),
    /// The folder cannot be created, checked or locked.
    Unusable(PathBuf),
    /// §3.1: an atlas-duck on another machine holds `instance.lock` there.
    OtherHost(String),
    /// This host has a pinned file now (it had none at startup): never a second data dir.
    AlreadyPinned,
    /// This host's pinned file could not be written.
    PinnedWrite,
}

impl DirRefusal {
    pub fn class(&self) -> &'static str {
        match self {
            DirRefusal::NotAbsolute => "not_absolute",
            DirRefusal::NotLocal(_) => "not_local",
            DirRefusal::Unusable(_) => "unusable",
            DirRefusal::OtherHost(_) => "other_host",
            DirRefusal::AlreadyPinned => "already_pinned",
            DirRefusal::PinnedWrite => "pinned_write",
        }
    }

    /// The app-generated text the page shows (the §7.7 / §3.1 startup texts with the path or host).
    pub fn text(&self) -> Option<String> {
        let path = |t: &str, p: &Path| render_message(t, &p.display().to_string());
        match self {
            DirRefusal::NotLocal(p) => Some(path(MSG_DATA_DIR_NOT_LOCAL, p)),
            DirRefusal::Unusable(p) => Some(path(MSG_DATA_DIR_UNUSABLE, p)),
            DirRefusal::OtherHost(h) => Some(render_message(MSG_RUNNING_ON_OTHER_HOST, h)),
            DirRefusal::NotAbsolute | DirRefusal::AlreadyPinned | DirRefusal::PinnedWrite => None,
        }
    }

    fn error(&self) -> WizardError {
        WizardError {
            class: self.class(),
            text: self.text(),
        }
    }
}

/// The locality check of one folder (`ipc::paths::check_data_dir` in production).
pub type DirCheck = fn(&Path) -> std::io::Result<DataDirResolution>;

/// Writes this host's pinned file (`ipc::paths::write_pinned` in production).
pub type PinnedWriter = Arc<dyn Fn(&Path, &PinnedPaths) -> Result<(), PinnedError> + Send + Sync>;

/// What step 0 leaves: the locked data dir and what was pinned.
#[derive(Debug)]
pub struct Prepared {
    pub data: LocalDataDir,
    pub lock: InstanceLock,
    pub pinned: PinnedPaths,
    pub existing_store: bool,
}

/// `chosen` as a local data dir: checked as it is, or, when it does not exist yet, its nearest
/// existing ancestor is checked first and only then is it created (and checked again), so nothing
/// is ever created on a network filesystem (§7.7).
fn local_or_created(chosen: &Path, check: DirCheck) -> Result<LocalDataDir, DirRefusal> {
    let unusable = || DirRefusal::Unusable(chosen.to_path_buf());
    let not_local = || DirRefusal::NotLocal(chosen.to_path_buf());
    match check(chosen) {
        Ok(DataDirResolution::Local(data)) => return Ok(data),
        Ok(DataDirResolution::NotLocal { .. }) => return Err(not_local()),
        Ok(DataDirResolution::Missing { .. }) => {}
        Ok(DataDirResolution::BeforeFirstRun) | Err(_) => return Err(unusable()),
    }
    let mut ancestor = chosen.parent();
    loop {
        let Some(dir) = ancestor else {
            return Err(unusable());
        };
        match check(dir) {
            Ok(DataDirResolution::Local(_)) => break,
            Ok(DataDirResolution::NotLocal { .. }) => return Err(not_local()),
            Ok(DataDirResolution::Missing { .. }) => ancestor = dir.parent(),
            Ok(DataDirResolution::BeforeFirstRun) | Err(_) => return Err(unusable()),
        }
    }
    std::fs::create_dir_all(chosen).map_err(|_| unusable())?;
    match check(chosen) {
        Ok(DataDirResolution::Local(data)) => Ok(data),
        Ok(DataDirResolution::NotLocal { .. }) => Err(not_local()),
        _ => Err(unusable()),
    }
}

/// The folder a populated pick gets inside it.
pub const NESTED_DATA_DIR: &str = "atlas-duck";

/// `data` (the existing folder `chosen`) holds files of something else: it has entries and is not
/// an atlas-duck data dir (no `audit.db`, no `instance.lock`).
fn holds_other_files(data: &LocalDataDir, chosen: &Path) -> Result<bool, DirRefusal> {
    let unusable = |_| DirRefusal::Unusable(chosen.to_path_buf());
    let dir = data.path();
    if dir.join(DB_FILE).try_exists().map_err(unusable)?
        || dir
            .join(INSTANCE_LOCK_FILE)
            .try_exists()
            .map_err(unusable)?
    {
        return Ok(false);
    }
    Ok(std::fs::read_dir(dir).map_err(unusable)?.next().is_some())
}

/// Step 0 on the file system (§2.5 (0), §7.7, M4 T14), with every path given (the wizard passes
/// this host's): refuses while this host has a pinned file; the data dir is checked and created
/// ([`local_or_created`]); `instance.lock` is taken (§3.1: before the store is touched); an existing
/// `audit.db` is (1a) and its `install_id` is read without the KEK; then the pinned file is written
/// (`write`): the data dir always exists before it. Any refusal pins nothing. `nest_populated` (a
/// folder the user picked): a folder that holds other files and is not an atlas-duck data dir
/// already gets [`NESTED_DATA_DIR`] inside it (the store, the lock, `webview*/` and `archived/`
/// never land in `Documents` or a drive root).
pub fn prepare_data_dir(
    chosen: &Path,
    nest_populated: bool,
    pinned_file: &Path,
    config_dir: &Path,
    host: &str,
    check: DirCheck,
    write: &(dyn Fn(&Path, &PinnedPaths) -> Result<(), PinnedError> + Send + Sync),
) -> Result<Prepared, DirRefusal> {
    if !chosen.is_absolute() {
        return Err(DirRefusal::NotAbsolute);
    }
    match paths::read_pinned(pinned_file) {
        Ok(None) => {}
        Ok(Some(_)) | Err(_) => return Err(DirRefusal::AlreadyPinned),
    }
    let data = local_or_created(chosen, check)?;
    let (chosen, data) = if nest_populated && holds_other_files(&data, chosen)? {
        let nested = chosen.join(NESTED_DATA_DIR);
        let data = local_or_created(&nested, check)?;
        (nested, data)
    } else {
        (chosen.to_path_buf(), data)
    };
    let chosen = chosen.as_path();
    let lock = match InstanceLock::acquire(&data, host) {
        Ok(lock) => lock,
        Err(LockError::Held(Some(holder))) if holder.host != host => {
            // The record is file content: sanitized before it reaches any text.
            return Err(DirRefusal::OtherHost(paths::sanitize_host_component(
                &holder.host,
            )));
        }
        Err(_) => return Err(DirRefusal::Unusable(chosen.to_path_buf())),
    };
    let existing_store = data
        .path()
        .join(DB_FILE)
        .try_exists()
        .map_err(|_| DirRefusal::Unusable(chosen.to_path_buf()))?;
    // (1a): pinned with the store's own id (§8.6: the latest `RESTORE`, else `GENESIS`). An id that
    // cannot be read leaves the pinned file without one (logged, M6 final review M-9); the open then
    // fails as it would at startup.
    let install_id = if existing_store {
        match read_store_install_id(&data) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    event = LOG_EVENT_STORE_ID_UNREADABLE,
                    error_class = open_error_class(&e)
                );
                None
            }
        }
    } else {
        None
    };
    let pinned = PinnedPaths {
        schema_version: PINNED_SCHEMA_VERSION,
        data_dir: chosen.to_path_buf(),
        config_dir: config_dir.to_path_buf(),
        install_id,
    };
    write(pinned_file, &pinned).map_err(|_| DirRefusal::PinnedWrite)?;
    Ok(Prepared {
        data,
        lock,
        pinned,
        existing_store,
    })
}

// ---------- the managed wizard ----------

/// Starts serving a data dir the way startup does in `Ready` (`serve::start` in production; the
/// tests serve over `serve::start_with`). The `DataDirHold` and the `ServeSlot` are managed before
/// it is called; it calls [`serving_started`] once the start ended.
pub trait ServeStarter<R: Runtime>: Send + Sync {
    fn start(
        &self,
        app: &AppHandle<R>,
        data: LocalDataDir,
        lock: Arc<InstanceLock>,
        pinned: &PinnedPaths,
    );
}

/// Rust's folder dialog (the advanced data-dir override, §7.7); `None` when cancelled.
pub type FolderPicker<R> = Arc<dyn Fn(&AppHandle<R>) -> Option<PathBuf> + Send + Sync>;

/// plan text (T23): the title of the data-dir folder dialog.
const DATA_DIR_DIALOG_TITLE: &str = "Choose the atlas-duck data folder (a local disk)";

/// The production [`FolderPicker`]: the dialog plugin's native folder dialog, Rust-side only (no
/// window holds the plugin's commands, §10.3). Blocks until the user answers: the blocking pool.
pub fn pick_folder_dialog<R: Runtime>(app: &AppHandle<R>) -> Option<PathBuf> {
    use tauri_plugin_dialog::DialogExt;
    app.dialog()
        .file()
        .set_title(DATA_DIR_DIALOG_TITLE)
        .blocking_pick_folder()
        .and_then(|chosen| chosen.into_path().ok())
}

/// The production anchor-dir picker (M10 T15, §2.5 (1b)): Rust's own folder dialog, on the
/// blocking pool only; no §7.7 local-filesystem check (an anchor dir is meant to be a network
/// share, §8.5). `None` when cancelled, or when the answer names no filesystem path.
pub fn pick_anchor_dir_dialog<R: Runtime>(app: &AppHandle<R>) -> Option<RustChosenPath> {
    use tauri_plugin_dialog::DialogExt;
    let chosen = app
        .dialog()
        .file()
        .set_title(crate::recovery_tier::ANCHOR_DIR_DIALOG_TITLE)
        .blocking_pick_folder()?;
    let folder = chosen.into_path().ok()?;
    Some(RustChosenPath::from_native_dialog(folder))
}

/// Everything the wizard takes from the app (the tests pass their own).
// The two dialogs that answer a `RustChosenPath` are spelled out: `ci/check-dialog-proofs.mjs`
// (rule 4) refuses a `type` alias of that type, since it would hide where one is built.
#[allow(clippy::type_complexity)]
pub struct WizardEnv<R: Runtime> {
    /// This host's pinned `paths.toml` (§7.7, host-qualified off Windows).
    pub pinned_file: PathBuf,
    /// The §7.7 default data dir ("Use the default folder").
    pub default_data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub host: String,
    pub secret_service: Arc<dyn SecretServiceCheck>,
    pub starter: Arc<dyn ServeStarter<R>>,
    pub pick_folder: FolderPicker<R>,
    /// M10 T15: Rust's folder dialog for the anchor directory ([`pick_anchor_dir_dialog`] in
    /// production); `None` when cancelled.
    pub pick_anchor_dir: Arc<dyn Fn(&AppHandle<R>) -> Option<RustChosenPath> + Send + Sync>,
    /// M10 T15 (PD-168): Rust's file dialog for the backup to restore
    /// (`restore_flow::pick_restore_source` in production); `None` when cancelled.
    pub pick_restore: Arc<dyn Fn(&AppHandle<R>) -> Option<RustChosenPath> + Send + Sync>,
    pub write_pinned: PinnedWriter,
    pub check_dir: DirCheck,
    /// Where the keyring entries live (§8.6): what `KeyStore::locality` answers, with no keyring
    /// call (`OsKeyStore::locality` in production).
    pub keyring_locality: KeyringLocalityCheck,
}

/// The §8.6 keyring locality check, asked before the passphrase.
pub type KeyringLocalityCheck = Arc<dyn Fn() -> KeyringLocality + Send + Sync>;

/// The wizard, managed by `setup` (`app.manage`).
pub struct Wizard<R: Runtime> {
    env: WizardEnv<R>,
    progress: Mutex<Progress>,
}

impl<R: Runtime> Wizard<R> {
    /// `pinned`: this host's pinned paths when startup read them (`Ready`; the first-run gate of a
    /// pinned data dir, or after "Archive old DB and start fresh").
    pub fn new(env: WizardEnv<R>, pinned: Option<PinnedPaths>) -> Wizard<R> {
        Wizard {
            env,
            progress: Mutex::new(Progress {
                pinned,
                ..Progress::default()
            }),
        }
    }

    fn progress(&self) -> MutexGuard<'_, Progress> {
        self.progress.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A copy of the progress (tests).
    pub fn progress_now(&self) -> Progress {
        self.progress().clone()
    }
}

fn wizard<R: Runtime>(app: &AppHandle<R>) -> Result<tauri::State<'_, Wizard<R>>, CommandError> {
    app.try_state::<Wizard<R>>().ok_or(CommandError::NotReady)
}

/// What [`WizardState`] reads besides the progress.
fn facts_now<R: Runtime>(app: &AppHandle<R>) -> (AppSnapshot, bool, bool) {
    (
        windows::snapshot(app),
        app.try_state::<DataDirHold>().is_some(),
        credential::current_purpose(app) == Some(Purpose::RecoveryPassphrase),
    )
}

/// The step now; the instance-step decision is taken here the first time the core serves.
fn current_step<R: Runtime>(
    app: &AppHandle<R>,
    p: &mut Progress,
    instances: Option<&[InstanceView]>,
) -> WizardStep {
    let (snapshot, data_dir_known, passphrase_window_open) = facts_now(app);
    if snapshot == AppSnapshot::Serving
        && p.instances_wanted.is_none()
        && let Some(views) = instances
    {
        p.instances_wanted = Some(instances_need_setup(views));
    }
    step_of(
        p,
        &Facts {
            data_dir_known,
            snapshot: &snapshot,
            passphrase_window_open,
        },
    )
}

/// `wizard_state`'s answer (and every `wizard_*` command's): what the setup page shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WizardState {
    /// [`WizardStep::as_str`].
    pub step: &'static str,
    /// The fixed text of `stopped` (§8.6 verbatim for the Secret Service stop); `null` otherwise.
    pub stopped_text: Option<&'static str>,
    /// The data dir in use (display only: no command takes a path); `null` before step 0.
    pub data_dir: Option<String>,
    /// The folder "Use the default folder" takes (§7.7).
    pub default_dir: String,
    /// "Setup required — N requests refused" (§2.5); `null` while no gate serves.
    pub refused_count: Option<u64>,
    /// The data dir holds an audit DB (§2.5 (1a)).
    pub existing_store: bool,
    /// Linux §8.6: `ok | missing | locked`; `n/a` elsewhere.
    pub secret_service: &'static str,
    /// The credential window waits for the recovery passphrase.
    pub passphrase_window: bool,
    /// Why the last step did nothing (fixed class; app-generated text for a refused folder).
    pub error: Option<WizardError>,
    /// The instances (the setup window has no `settings_get`, M6 T25); empty until the core
    /// serves.
    pub instances: Vec<InstanceView>,
    /// M10 T15: the anchor directory chosen for `GENESIS` (display only, escaped onto one line:
    /// no command takes a path); `null` when none is chosen.
    pub anchor_dir: Option<String>,
    /// M10 T15: Rust's fixed text for the step shown ([`MSG_PIN_WRITE_FAILED`] at `pin_retry`);
    /// `null` otherwise.
    pub step_text: Option<&'static str>,
    /// M10 T15 (PD-167): [`MSG_PREVIOUS_CHAIN_FOUND`] from the first store on when its first run
    /// recorded a previous chain; `null` otherwise.
    pub notice: Option<&'static str>,
}

fn state_of<R: Runtime>(
    app: &AppHandle<R>,
    w: &Wizard<R>,
    instances: Vec<InstanceView>,
) -> WizardState {
    let mut p = w.progress();
    let step = current_step(app, &mut p, Some(&instances));
    let refused_count = app
        .try_state::<ServeSlot>()
        .and_then(|s| s.get().and_then(|st| st.refused()));
    WizardState {
        step: step.as_str(),
        stopped_text: match step {
            WizardStep::Stopped(text) => Some(text),
            _ => None,
        },
        data_dir: p
            .pinned
            .as_ref()
            .map(|pp| pp.data_dir.display().to_string()),
        default_dir: w.env.default_data_dir.display().to_string(),
        refused_count,
        existing_store: p.existing_store,
        secret_service: p.secret_service.map_or("n/a", SecretService::as_str),
        passphrase_window: p.in_flight == Some(InFlight::Passphrase),
        error: p.error.clone(),
        instances,
        anchor_dir: p
            .anchor_dir
            .as_ref()
            .map(|d| crate::recovery_tier::one_line(&d.path().display().to_string())),
        step_text: match step {
            WizardStep::PinRetry => Some(MSG_PIN_WRITE_FAILED),
            _ => None,
        },
        notice: p.previous_chain.then_some(MSG_PREVIOUS_CHAIN_FOUND),
    }
}

/// `wizard_state {}`: the state now (the instance list and the Secret Service check on the blocking
/// pool).
pub async fn state<R: Runtime>(app: &AppHandle<R>) -> Result<WizardState, CommandError> {
    let check = wizard(app)?.env.secret_service.clone();
    let admin = crate::commands::core(app).ok().map(|c| c.instances());
    let (instances, secret_service) = blocking(move || {
        let views = admin.map(|a| a.list()).unwrap_or_default();
        Ok((views, check.check()))
    })
    .await?;
    let w = wizard(app)?;
    w.progress().secret_service = secret_service;
    Ok(state_of(app, &w, instances))
}

/// The state after a command changed something: the page hears `wizard_changed` too.
async fn answer<R: Runtime>(app: &AppHandle<R>) -> Result<WizardState, CommandError> {
    emit_wizard_changed(app);
    state(app).await
}

/// Which folder step 0 takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirChoice {
    Default,
    /// Rust's folder dialog (cancel: nothing changes).
    Pick,
}

/// Step 0 (`wizard_use_default_dir` / `wizard_choose_dir`, §2.5 (0), PD-77): [`prepare_data_dir`] on
/// the blocking pool, then, in the app: the diagnostic log goes to the data dir, the Crashpad
/// reports of its webview folders are cleared (§2.5 crash artifacts, before any webview uses them),
/// the data dir and the serving slot are managed, IPC is served in-process ([`ServeStarter`]) and
/// the setup window moves into the data dir's webview folder. A refused folder is the state's
/// `error` (the page offers the choice again); a second call while one runs is `busy`; after step
/// 0 it is `not_ready`.
pub async fn use_dir<R: Runtime>(
    app: &AppHandle<R>,
    choice: DirChoice,
) -> Result<WizardState, CommandError> {
    {
        let w = wizard(app)?;
        let mut p = w.progress();
        if app.try_state::<DataDirHold>().is_some() || p.stopped.is_some() || p.finished {
            return Err(CommandError::NotReady);
        }
        if p.in_flight.is_some() {
            return Err(CommandError::Busy);
        }
        p.in_flight = Some(InFlight::DataDir);
        p.error = None;
    }
    let outcome = run_step0(app, choice).await;
    let w = wizard(app)?;
    match outcome {
        Ok(Some(prepared)) => {
            let Prepared {
                data,
                lock,
                pinned,
                existing_store,
            } = prepared;
            {
                let mut p = w.progress();
                p.pinned = Some(pinned.clone());
                p.existing_store = existing_store;
                p.step0_done = true;
            }
            // `in_flight` stays `DataDir` until the data dir is managed: a second step-0 call in
            // between would pass the guards and end in a spurious `already_pinned`.
            serve_data_dir(app, &w, data, lock, &pinned);
            w.progress().in_flight = None;
        }
        // The folder dialog was cancelled.
        Ok(None) => w.progress().in_flight = None,
        Err(refusal) => {
            tracing::warn!(event = LOG_EVENT_DIR_REFUSED, error_class = refusal.class());
            let mut p = w.progress();
            p.error = Some(refusal.error());
            p.in_flight = None;
        }
    }
    answer(app).await
}

async fn run_step0<R: Runtime>(
    app: &AppHandle<R>,
    choice: DirChoice,
) -> Result<Option<Prepared>, DirRefusal> {
    let Ok(w) = wizard(app) else {
        return Err(DirRefusal::PinnedWrite);
    };
    let env = (
        w.env.pinned_file.clone(),
        w.env.default_data_dir.clone(),
        w.env.config_dir.clone(),
        w.env.host.clone(),
        w.env.check_dir,
        w.env.write_pinned.clone(),
        w.env.pick_folder.clone(),
    );
    let handle = app.clone();
    let done = tauri::async_runtime::spawn_blocking(move || {
        let (pinned_file, default_dir, config_dir, host, check, write, pick) = env;
        let chosen = match choice {
            DirChoice::Default => default_dir,
            // The dialog blocks until the user answers: the blocking pool, never the main thread.
            DirChoice::Pick => match pick(&handle) {
                Some(dir) => dir,
                None => return Ok(None),
            },
        };
        let nest = choice == DirChoice::Pick;
        prepare_data_dir(
            &chosen,
            nest,
            &pinned_file,
            &config_dir,
            &host,
            check,
            &*write,
        )
        .map(Some)
    })
    .await;
    done.unwrap_or(Err(DirRefusal::PinnedWrite))
}

/// The app half of step 0 (see [`use_dir`]).
fn serve_data_dir<R: Runtime>(
    app: &AppHandle<R>,
    w: &Wizard<R>,
    data: LocalDataDir,
    lock: InstanceLock,
    pinned: &PinnedPaths,
) {
    if let Some(diag) = crate::diag::Diag::get()
        && diag.attach_dir(&data).is_err()
    {
        tracing::warn!(event = "diag_attach_failed");
    }
    crate::startup::gate::clear_webview_crashpad(&data);
    let lock = Arc::new(lock);
    app.manage(DataDirHold::new(data.clone(), lock.clone()));
    app.manage(ServeSlot::default());
    w.env.starter.start(app, data, lock, pinned);
    relocate_setup_window(app);
}

/// Moves the setup window into the data dir's webview folder (T6 handoff): a webview's data folder
/// is fixed when it is built, so the window built before a data dir existed (Tauri's default
/// folder, incognito, with nothing secret typed into it) is destroyed and built again from
/// `window_spec`, which now names `<data>/webview`. Its state is Rust's, so the new page only reads
/// it again. Off the main thread.
fn relocate_setup_window<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let label = Label::Setup.as_str();
        let Some(old) = app.get_webview_window(label) else {
            return;
        };
        let _ = old.destroy();
        // The destroy is carried out on the main thread; the label is free once Tauri forgot it.
        let started = Instant::now();
        while app.get_webview_window(label).is_some() {
            if started.elapsed() > RELOCATE_WAIT {
                tracing::warn!(event = LOG_EVENT_SETUP_NOT_MOVED);
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // `open` logs its own failure; the tray's "Open approvals" reaches the wizard again.
        let _ = windows::open(&app, Label::Setup, Show::Focus);
    });
}

/// Every serving start ended (`serve::start`, the tests' starter): after step 0 of a data dir that
/// holds a store (1a), a lock or error state opens its window as a cold start would (the credential
/// window for "Recover this log", the error window); the page re-reads.
pub fn serving_started<R: Runtime>(app: &AppHandle<R>) {
    let Some(w) = app.try_state::<Wizard<R>>() else {
        return;
    };
    let route = {
        let p = w.progress();
        p.step0_done && p.existing_store
    };
    if route {
        let action = windows::route_relaunch(&windows::snapshot(app), &[]);
        if matches!(
            action,
            Relaunch::OpenCredential(_) | Relaunch::ShowErrorDialog(_)
        ) {
            let app = app.clone();
            tauri::async_runtime::spawn_blocking(move || windows::perform(&app, action));
        }
    }
    emit_wizard_changed(app);
}

/// The serving state changed (`serve::ServeWatcher`): the page re-reads.
pub fn serving_changed<R: Runtime>(app: &AppHandle<R>) {
    if app.try_state::<Wizard<R>>().is_some() {
        emit_wizard_changed(app);
    }
}

// ---------- (1b) ----------

/// `wizard_begin {}` (PD-77): at the anchor-dir step (the first-run gate serves) the Linux Secret
/// Service check (§8.6: no usable provider stops the wizard with the fixed text, before any id
/// exists and with nothing written), then the credential window for the recovery passphrase;
/// while it waits (the passphrase step), the window is brought back. At `pin_retry` the pinned
/// file is written again with the store's `install_id` (M10 T15). In the (1a) step it opens what
/// the store's state needs again (the credential window to unlock, or the error window). While a
/// restore or the anchor-dir dialog runs `busy`; elsewhere `not_ready`.
pub async fn begin<R: Runtime>(app: &AppHandle<R>) -> Result<WizardState, CommandError> {
    let step = {
        let w = wizard(app)?;
        let mut p = w.progress();
        let step = current_step(app, &mut p, None);
        match step {
            WizardStep::AnchorDir | WizardStep::Passphrase => {
                // Only once the first-run gate serves (the start after step 0 may still be
                // opening): a pair taken earlier could only fail.
                if windows::snapshot(app) != AppSnapshot::Gate(GateState::FirstRun) {
                    return Err(CommandError::NotReady);
                }
                match p.in_flight {
                    Some(InFlight::Passphrase) => {}
                    Some(_) => return Err(CommandError::Busy),
                    None => {
                        p.in_flight = Some(InFlight::Passphrase);
                        p.error = None;
                    }
                }
            }
            WizardStep::PinRetry => {
                if p.in_flight.is_some() {
                    return Err(CommandError::Busy);
                }
                p.in_flight = Some(InFlight::Pin);
                p.error = None;
            }
            WizardStep::Restore => return Err(CommandError::Busy),
            _ => {}
        }
        step
    };
    match step {
        WizardStep::AnchorDir | WizardStep::Passphrase => request_passphrase(app).await?,
        WizardStep::PinRetry => retry_pin(app).await,
        WizardStep::ExistingStore => {
            let action = windows::route_relaunch(&windows::snapshot(app), &[]);
            if matches!(
                action,
                Relaunch::OpenCredential(_) | Relaunch::ShowErrorDialog(_)
            ) {
                let handle = app.clone();
                blocking(move || {
                    windows::perform(&handle, action);
                    Ok(())
                })
                .await?;
            }
        }
        _ => return Err(CommandError::NotReady),
    }
    answer(app).await
}

/// The passphrase step with `in_flight` set to `Passphrase` by [`begin`].
async fn request_passphrase<R: Runtime>(app: &AppHandle<R>) -> Result<(), CommandError> {
    let (check, locality) = {
        let w = wizard(app)?;
        (w.env.secret_service.clone(), w.env.keyring_locality.clone())
    };
    let handle = app.clone();
    let waiting = credential::current_purpose(app) == Some(Purpose::RecoveryPassphrase);
    let asked = blocking(move || {
        if waiting {
            // The window waits already: bring it back, the request stays.
            return credential::open(&handle, Purpose::RecoveryPassphrase, Show::Focus)
                .map(|()| Asked::Waiting)
                .map_err(window_error);
        }
        let found = check.check();
        if matches!(found, Some(SecretService::Missing | SecretService::Locked)) {
            return Ok(Asked::Stopped {
                found,
                text: MSG_NEEDS_SECRET_SERVICE,
                reason: found.map_or("", SecretService::as_str),
            });
        }
        // §8.6 (L39): the keyring's directories are checked before the passphrase is asked for
        // (no keyring call). `Unknown` goes on: the store's own check at `GENESIS` is the backstop
        // and a retry can succeed.
        if matches!(locality(), KeyringLocality::NotLocal { .. }) {
            return Ok(Asked::Stopped {
                found,
                text: MSG_KEYRING_NOT_LOCAL,
                reason: REASON_KEYRING_NOT_LOCAL,
            });
        }
        credential::request_recovery_passphrase(&handle, Show::Focus)
            .map(|rx| Asked::Window { found, rx })
            .map_err(window_error)
    })
    .await;
    let w = wizard(app)?;
    match asked {
        Ok(Asked::Waiting) => Ok(()),
        Ok(Asked::Stopped {
            found,
            text,
            reason,
        }) => {
            let mut p = w.progress();
            if found.is_some() {
                p.secret_service = found;
            }
            tracing::warn!(event = LOG_EVENT_STOPPED, reason);
            p.stopped = Some(text);
            p.in_flight = None;
            Ok(())
        }
        Ok(Asked::Window { found, rx }) => {
            let mut p = w.progress();
            if found.is_some() {
                p.secret_service = found;
            }
            p.passphrase_request = p.passphrase_request.wrapping_add(1);
            let request = p.passphrase_request;
            drop(p);
            let handle = app.clone();
            tauri::async_runtime::spawn(async move { await_passphrase(handle, rx, request).await });
            Ok(())
        }
        Err(e) => {
            if !waiting {
                w.progress().in_flight = None;
            }
            Err(e)
        }
    }
}

/// What asking for the passphrase came to.
enum Asked {
    /// The credential window waited already and was brought back.
    Waiting,
    /// The wizard stops (Quit only): `text` is shown, `reason` is logged.
    Stopped {
        found: Option<SecretService>,
        text: &'static str,
        reason: &'static str,
    },
    /// The credential window waits for the pair.
    Window {
        found: Option<SecretService>,
        rx: oneshot::Receiver<FirstRunPassphrase>,
    },
}

fn window_error(e: WindowError) -> CommandError {
    match e {
        WindowError::Busy => CommandError::Busy,
        _ => CommandError::Internal,
    }
}

/// What the page shows of a first store that did not happen: its class, and for a refused anchor
/// dir the store's fixed text (no path).
fn failure_error(f: FirstStoreFailure) -> WizardError {
    WizardError {
        class: f.class(),
        text: f.text().map(str::to_owned),
    }
}

/// The serving state of the data dir (step 0 managed it).
fn serving_state<R: Runtime>(app: &AppHandle<R>) -> Option<Arc<serve::ServeState>> {
    app.try_state::<ServeSlot>().and_then(|s| s.get().cloned())
}

/// The pin retry with `in_flight` set to `Pin` by [`begin`] (M6 final review M-9): the pinned
/// file is written again with the serving store's `install_id`; a failure is logged with its
/// class and shown as [`CLASS_PINNED_WRITE`], and the step stays.
async fn retry_pin<R: Runtime>(app: &AppHandle<R>) {
    let Ok(w) = wizard(app) else {
        return;
    };
    let pin = pin_writer(&w);
    let install_id = serving_state(app).and_then(|s| s.note_facts()).map(|f| f.0);
    let written = blocking(move || {
        Ok(match (pin, install_id) {
            (Some(pin), Some(id)) => serve::pin_store_id(&pin, &id),
            _ => false,
        })
    })
    .await
    .unwrap_or(false);
    let mut p = w.progress();
    p.in_flight = None;
    if written {
        p.pin_failed = false;
    } else {
        p.error = Some(WizardError {
            class: CLASS_PINNED_WRITE,
            text: None,
        });
    }
}

/// `wizard_anchor_dir {}` (M10 T15, §2.5 (1b), §8.5): at the anchor-dir step, Rust's folder dialog
/// (no §7.7 local-filesystem check: a share is what an anchor dir is for); the folder is kept for
/// `GENESIS` and shown as text. A path the store would refuse (not absolute, not UTF-8) is refused
/// here with [`CLASS_ANCHOR_DIR_INVALID`] and nothing is kept; whether the folder can be read is
/// the store's check at `GENESIS` (PD-167; its refusal comes back to this step). No confirmation:
/// at first run nothing is weakened, and `GENESIS` records the setting (`CONFIG_CHANGED {key:
/// anchor_dir, old: null}`). A cancelled dialog changes nothing; a second request while the dialog
/// is up is `busy`; elsewhere `not_ready`.
pub async fn anchor_dir<R: Runtime>(app: &AppHandle<R>) -> Result<WizardState, CommandError> {
    let pick = {
        let w = wizard(app)?;
        let mut p = w.progress();
        if current_step(app, &mut p, None) != WizardStep::AnchorDir {
            return Err(CommandError::NotReady);
        }
        if p.in_flight.is_some() {
            return Err(CommandError::Busy);
        }
        p.in_flight = Some(InFlight::AnchorDir);
        p.error = None;
        w.env.pick_anchor_dir.clone()
    };
    let handle = app.clone();
    // The dialog blocks until the user answers: the blocking pool, never the main thread.
    let picked = tauri::async_runtime::spawn_blocking(move || pick(&handle))
        .await
        .unwrap_or(None);
    {
        let w = wizard(app)?;
        let mut p = w.progress();
        p.in_flight = None;
        match picked {
            None => {}
            Some(dir) if usable_anchor_dir(dir.path()) => p.anchor_dir = Some(dir),
            Some(_) => {
                p.error = Some(WizardError {
                    class: CLASS_ANCHOR_DIR_INVALID,
                    text: None,
                });
            }
        }
    }
    answer(app).await
}

/// What `create_new_store` takes as the wizard's anchor dir: absolute, non-empty UTF-8 text.
fn usable_anchor_dir(dir: &Path) -> bool {
    dir.is_absolute() && dir.to_str().is_some_and(|s| !s.is_empty())
}

/// `wizard_anchor_dir_clear {}` (M10 T15): at the anchor-dir step, no anchor directory for
/// `GENESIS`; `busy` while the folder dialog is up, elsewhere `not_ready`.
pub async fn anchor_dir_clear<R: Runtime>(app: &AppHandle<R>) -> Result<WizardState, CommandError> {
    {
        let w = wizard(app)?;
        let mut p = w.progress();
        if current_step(app, &mut p, None) != WizardStep::AnchorDir {
            return Err(CommandError::NotReady);
        }
        if p.in_flight.is_some() {
            return Err(CommandError::Busy);
        }
        p.anchor_dir = None;
        p.error = None;
    }
    answer(app).await
}

/// `wizard_restore {}` (M10 T15, §2.5 (1b), §8.11, PD-168): "Restore from a backup" instead of a
/// new log, at the anchor-dir step once the first-run gate serves. The restore runs in the
/// background ([`serve::restore_first_store`]: the native "Restore backup" confirmation, Rust's
/// file dialog, the backup's passphrase in the credential window, purpose `restore_backup`, new
/// ids, `restore_from_source`, the pinned `install_id`, the core start) while the wizard shows
/// `restore`; afterwards it goes on at the instances (no `GENESIS`, no first-run passphrase, no
/// recovery note). The answer is the state at once. A cancel at any question comes back to the
/// anchor-dir step with nothing changed, a failure with its class. `busy` while another step runs;
/// elsewhere `not_ready`.
pub async fn restore<R: Runtime>(app: &AppHandle<R>) -> Result<WizardState, CommandError> {
    let state = {
        let w = wizard(app)?;
        let mut p = w.progress();
        if current_step(app, &mut p, None) != WizardStep::AnchorDir
            || windows::snapshot(app) != AppSnapshot::Gate(GateState::FirstRun)
        {
            return Err(CommandError::NotReady);
        }
        if p.in_flight.is_some() {
            return Err(CommandError::Busy);
        }
        let state = serving_state(app).ok_or(CommandError::NotReady)?;
        p.in_flight = Some(InFlight::Restore);
        p.error = None;
        state
    };
    let handle = app.clone();
    tauri::async_runtime::spawn(async move { run_restore(handle, state).await });
    answer(app).await
}

/// The wizard's restore task (see [`restore`]).
async fn run_restore<R: Runtime>(app: AppHandle<R>, state: Arc<serve::ServeState>) {
    let Some(w) = app.try_state::<Wizard<R>>() else {
        return;
    };
    let result = match pin_writer(&w) {
        None => Err(FirstStoreFailure::PinnedWrite),
        Some(pin) => {
            let (pick_app, pass_app, pick) = (app.clone(), app.clone(), w.env.pick_restore.clone());
            serve::restore_first_store(
                &state,
                Box::new(move || pick(&pick_app)),
                Box::new(move |stop| restore_passphrase(&pass_app, stop)),
                pin,
            )
            .await
        }
    };
    {
        let mut p = w.progress();
        p.in_flight = None;
        match result {
            Ok(first) => {
                p.pin_failed = !first.pin_written;
                // The restored store keeps the backup's own anchor-dir setting (§8.11).
                p.anchor_dir = None;
            }
            // The user's choice: back at the anchor-dir step, no error.
            Err(FirstStoreFailure::Restore(UnlockFailure::Cancelled)) => {}
            Err(f) => p.error = Some(failure_error(f)),
        }
    }
    if result.is_ok() {
        // The Settings and setup windows re-read the instances of the restored store.
        crate::ui_sink::emit_settings_changed(&app);
    }
    emit_wizard_changed(&app);
}

/// The backup's passphrase for the wizard's restore (PD-168): the credential window opens for
/// `restore_backup` (`busy` while it is open for anything else) and the one entry comes back over
/// the in-memory channel; `stop` (Quit) ends the wait and the window. The window closes itself
/// after its submit.
fn restore_passphrase<R: Runtime>(
    app: &AppHandle<R>,
    stop: &dyn Fn() -> bool,
) -> Result<SecretString, NotAsked> {
    let request =
        credential::request_restore_passphrase(app, Show::Focus).map_err(|e| match e {
            WindowError::Busy => NotAsked::Busy,
            _ => NotAsked::NoWindow,
        })?;
    let got = wait_passphrase(&request.rx, stop);
    if got.is_err() {
        credential::close_if(app, request.generation);
    }
    got
}

/// The wizard's end of the passphrase channel: the pair goes straight into
/// `serve::create_first_store` (never into a response, a log or the progress). A window closed
/// before a pair was accepted is the user's choice: back to the passphrase step, no error. A failed
/// attempt closes the credential window (its page shows "accepted" and has no form any more) and
/// the step offers Begin again: a new pair, new ids.
async fn await_passphrase<R: Runtime>(
    app: AppHandle<R>,
    rx: oneshot::Receiver<FirstRunPassphrase>,
    request: u64,
) {
    let received = rx.await;
    let Some(w) = app.try_state::<Wizard<R>>() else {
        return;
    };
    {
        let mut p = w.progress();
        let mine = p.passphrase_request == request && p.in_flight == Some(InFlight::Passphrase);
        match (&received, mine) {
            (Ok(_), true) => p.in_flight = Some(InFlight::Genesis),
            (Err(_), true) => p.in_flight = None,
            // A newer request replaced this one (its window was built again): nothing to do; a
            // pair that still came (it cannot: the sender went with the old window) is dropped.
            (_, false) => return,
        }
    }
    emit_wizard_changed(&app);
    let Ok(pair) = received else {
        return;
    };
    let generation = credential::current_window(&app).map(|(_, g)| g);
    let result = genesis(&app, &w, pair).await;
    // A failure closes the window before the state shows the failure: whoever sees the class sees
    // the window gone.
    if let (Err(_), Some(generation)) = (result, generation) {
        let handle = app.clone();
        let _ =
            tauri::async_runtime::spawn_blocking(move || credential::close_if(&handle, generation))
                .await;
    }
    {
        let mut p = w.progress();
        p.in_flight = None;
        match result {
            Ok(first) => {
                p.genesis_written = true;
                p.previous_chain = first.previous_chain_found;
                p.pin_failed = !first.pin_written;
            }
            // Back at the anchor-dir step, which names the failure (a refused anchor dir with the
            // store's own fixed text).
            Err(f) => p.error = Some(failure_error(f)),
        }
    }
    if result.is_ok() {
        // The page offers "Save recovery note" now (§8.6: right after `GENESIS`); the Settings and
        // setup windows re-read the instances.
        credential::context_changed(&app);
        crate::ui_sink::emit_settings_changed(&app);
    }
    emit_wizard_changed(&app);
}

/// `GENESIS` for this data dir: the archived store an archive left (in memory, else derived again
/// from the archive folder), the anchor dir chosen at the anchor-dir step, the pinned-file writer,
/// then `serve::create_first_store`.
async fn genesis<R: Runtime>(
    app: &AppHandle<R>,
    w: &Wizard<R>,
    pair: FirstRunPassphrase,
) -> Result<FirstStore, FirstStoreFailure> {
    let state = app
        .try_state::<ServeSlot>()
        .and_then(|s| s.get().cloned())
        .ok_or(FirstStoreFailure::NotFirstRun)?;
    let data = app
        .try_state::<DataDirHold>()
        .map(|h| h.data().clone())
        .ok_or(FirstStoreFailure::NotFirstRun)?;
    let pin = pin_writer(w).ok_or(FirstStoreFailure::PinnedWrite)?;
    let anchor_dir = w.progress().anchor_dir.clone();
    let archived = match credential::take_archived(app) {
        Some(a) => Some(a),
        None => tauri::async_runtime::spawn_blocking(move || archived_on_disk(&data))
            .await
            .unwrap_or(None),
    };
    serve::create_first_store(&state, pair, archived, anchor_dir, pin).await
}

/// The archive [`latest_archived`] finds (T20 review I-1); an unreadable folder names none (the
/// archive itself is untouched; only the link in the new `GENESIS` is lost, logged).
fn archived_on_disk(data: &LocalDataDir) -> Option<ArchivedDb> {
    match latest_archived(data) {
        Ok(found) => found,
        Err(e) => {
            tracing::warn!(
                event = LOG_EVENT_ARCHIVED_UNREADABLE,
                error_class = open_error_class(&e)
            );
            None
        }
    }
}

/// The diagnostic class of a read of the store's files that failed: `integrity|io` (never the
/// error's text, which can name a path).
fn open_error_class(e: &atlas_duck_audit::OpenError) -> &'static str {
    match e {
        atlas_duck_audit::OpenError::Integrity(_) => "integrity",
        _ => "io",
    }
}

/// The diagnostic class of a pinned-file write that failed ([`serve::PinWriter`]; never a path).
pub fn pinned_error_class(e: &PinnedError) -> &'static str {
    match e {
        PinnedError::NonUtf8Path(_) => "non_utf8",
        PinnedError::NotAbsolutePath(_) => "not_absolute",
        PinnedError::Parse => "parse",
        PinnedError::NewerSchema { .. } => "newer_schema",
        PinnedError::Io(_) => "io",
    }
}

/// The pinned-file writer of a first store: this host's pinned paths with the `install_id` given.
fn pin_writer<R: Runtime>(w: &Wizard<R>) -> Option<serve::PinWriter> {
    let pinned = w.progress().pinned.clone()?;
    let (file, write) = (w.env.pinned_file.clone(), w.env.write_pinned.clone());
    Some(Box::new(move |install_id| {
        let p = PinnedPaths {
            install_id: install_id.map(str::to_owned),
            ..pinned.clone()
        };
        write(&file, &p).map_err(|e| pinned_error_class(&e))
    }))
}

// ---------- the rest ----------

/// The answer to a `wizard_finish` / `wizard_skip_instances` that names another step than the
/// wizard is at (a double click, a stale page): nothing changed, the state says so in `error`
/// (not kept: the next answer does not carry it) and the page shows the step it holds.
async fn wrong_step<R: Runtime>(app: &AppHandle<R>) -> Result<WizardState, CommandError> {
    let mut s = state(app).await?;
    s.error = Some(WizardError {
        class: CLASS_WRONG_STEP,
        text: None,
    });
    Ok(s)
}

/// `wizard_skip_instances {step}`: leaves the instance step (with or without instances added).
/// `expected` is the step the page showed ([`WizardStep::as_str`]); any other step is
/// `wrong_step`.
pub async fn skip_instances<R: Runtime>(
    app: &AppHandle<R>,
    expected: &str,
) -> Result<WizardState, CommandError> {
    // The lock is not held across an await: the block answers whether the step matched.
    let matched = {
        let w = wizard(app)?;
        let mut p = w.progress();
        let step = current_step(app, &mut p, None);
        if step.as_str() != expected {
            false
        } else if step != WizardStep::Instances {
            return Err(CommandError::NotReady);
        } else {
            p.instances_done = true;
            true
        }
    };
    if !matched {
        return wrong_step(app).await;
    }
    answer(app).await
}

/// `wizard_finish {step}`: the step shown is done. The recovery note: the credential window closes;
/// the CLI step: on to the onboarding snippet; the onboarding snippet: the wizard is done, the
/// setup window goes and Approvals opens. `expected` is the step the page showed
/// ([`WizardStep::as_str`]): any other step is `wrong_step` and nothing moves, so a repeated
/// request never skips a step. Elsewhere `not_ready`.
pub async fn finish<R: Runtime>(
    app: &AppHandle<R>,
    expected: &str,
) -> Result<WizardState, CommandError> {
    // The lock is not held across an await: the block answers the step, or `None` for a mismatch.
    let step = {
        let w = wizard(app)?;
        let mut p = w.progress();
        let step = current_step(app, &mut p, None);
        if step.as_str() != expected {
            None
        } else {
            match step {
                WizardStep::RecoveryNote => {}
                WizardStep::Cli => p.cli_done = true,
                WizardStep::Onboarding => p.finished = true,
                _ => return Err(CommandError::NotReady),
            }
            Some(step)
        }
    };
    let Some(step) = step else {
        return wrong_step(app).await;
    };
    let handle = app.clone();
    match step {
        WizardStep::RecoveryNote => {
            if let Some((Purpose::RecoveryPassphrase, generation)) = credential::current_window(app)
            {
                blocking(move || {
                    credential::close_if(&handle, generation);
                    Ok(())
                })
                .await?;
            }
        }
        WizardStep::Onboarding => {
            tauri::async_runtime::spawn_blocking(move || {
                if let Some(setup) = handle.get_webview_window(Label::Setup.as_str()) {
                    let _ = setup.destroy();
                }
                let _ = windows::open(&handle, Label::Approvals, Show::Focus);
            });
        }
        _ => {}
    }
    answer(app).await
}

#[cfg(test)]
mod tests {
    use atlas_duck_audit::{LockedReason, RecoveryOffer};

    use super::*;

    fn facts(snapshot: &AppSnapshot) -> Facts<'_> {
        Facts {
            data_dir_known: true,
            snapshot,
            passphrase_window_open: false,
        }
    }

    #[test]
    fn steps_follow_the_serving_state() {
        let p = Progress::default();
        let first_run = AppSnapshot::Gate(GateState::FirstRun);
        let no_dir = Facts {
            data_dir_known: false,
            ..facts(&first_run)
        };
        assert_eq!(step_of(&p, &no_dir), WizardStep::DataDir);
        // M10 T15 (§2.5 (1b)): the anchor-dir step first; the passphrase step only while the
        // credential window waits for the pair; the restore while it runs.
        assert_eq!(step_of(&p, &facts(&first_run)), WizardStep::AnchorDir);
        for (in_flight, step) in [
            (InFlight::AnchorDir, WizardStep::AnchorDir),
            (InFlight::Passphrase, WizardStep::Passphrase),
            (InFlight::Restore, WizardStep::Restore),
        ] {
            let p = Progress {
                in_flight: Some(in_flight),
                ..Progress::default()
            };
            assert_eq!(step_of(&p, &facts(&first_run)), step, "{in_flight:?}");
        }
        // The core of a restore serves before the wizard recorded it.
        let restoring = Progress {
            in_flight: Some(InFlight::Restore),
            ..Progress::default()
        };
        assert_eq!(
            step_of(&restoring, &facts(&AppSnapshot::Serving)),
            WizardStep::Restore
        );
        // M6 final review M-9: a pinned file without the store's id holds every later step.
        let unpinned = Progress {
            genesis_written: true,
            pin_failed: true,
            ..Progress::default()
        };
        let note_window = Facts {
            passphrase_window_open: true,
            ..facts(&AppSnapshot::Serving)
        };
        assert_eq!(step_of(&unpinned, &note_window), WizardStep::PinRetry);
        let genesis = Progress {
            in_flight: Some(InFlight::Genesis),
            ..Progress::default()
        };
        assert_eq!(step_of(&genesis, &facts(&first_run)), WizardStep::Genesis);
        // The core already serves; the wizard has not recorded its GENESIS yet.
        assert_eq!(
            step_of(&genesis, &facts(&AppSnapshot::Serving)),
            WizardStep::Genesis
        );
        assert_eq!(
            step_of(&p, &facts(&AppSnapshot::Starting)),
            WizardStep::AnchorDir
        );
        let existing = Progress {
            existing_store: true,
            ..Progress::default()
        };
        for s in [
            AppSnapshot::Starting,
            AppSnapshot::Gate(GateState::Locked(LockedReason::KeychainLost {
                offer: RecoveryOffer::RecoverThisLog,
            })),
            AppSnapshot::Gate(GateState::StoreNewer),
        ] {
            assert_eq!(
                step_of(&existing, &facts(&s)),
                WizardStep::ExistingStore,
                "{s:?}"
            );
        }
        assert_eq!(
            step_of(&existing, &facts(&AppSnapshot::StoreUnavailable)),
            WizardStep::Stopped(MSG_STORE_UNAVAILABLE)
        );

        // Serving: the note (only after this wizard's GENESIS, while the window is open), the
        // instances (unless not wanted), the CLI, the onboarding snippet.
        let serving = AppSnapshot::Serving;
        let written = Progress {
            genesis_written: true,
            ..Progress::default()
        };
        let note_open = Facts {
            passphrase_window_open: true,
            ..facts(&serving)
        };
        assert_eq!(step_of(&written, &note_open), WizardStep::RecoveryNote);
        assert_eq!(
            step_of(&p, &note_open),
            WizardStep::Instances,
            "(1a): no note"
        );
        assert_eq!(step_of(&written, &facts(&serving)), WizardStep::Instances);
        let unwanted = Progress {
            instances_wanted: Some(false),
            ..Progress::default()
        };
        assert_eq!(step_of(&unwanted, &facts(&serving)), WizardStep::Cli);
        let skipped = Progress {
            instances_done: true,
            ..Progress::default()
        };
        assert_eq!(step_of(&skipped, &facts(&serving)), WizardStep::Cli);
        let cli = Progress {
            cli_done: true,
            ..skipped.clone()
        };
        assert_eq!(step_of(&cli, &facts(&serving)), WizardStep::Onboarding);
        let done = Progress {
            finished: true,
            ..cli
        };
        assert_eq!(step_of(&done, &facts(&serving)), WizardStep::Done);
        // Stopped wins over everything.
        let stopped = Progress {
            stopped: Some(MSG_NEEDS_SECRET_SERVICE),
            finished: true,
            ..Progress::default()
        };
        assert_eq!(
            step_of(&stopped, &no_dir),
            WizardStep::Stopped(MSG_NEEDS_SECRET_SERVICE)
        );
    }

    #[test]
    fn step_names_are_distinct() {
        let all = [
            WizardStep::DataDir,
            WizardStep::ExistingStore,
            WizardStep::AnchorDir,
            WizardStep::Restore,
            WizardStep::Passphrase,
            WizardStep::Genesis,
            WizardStep::PinRetry,
            WizardStep::RecoveryNote,
            WizardStep::Instances,
            WizardStep::Cli,
            WizardStep::Onboarding,
            WizardStep::Done,
            WizardStep::Stopped(MSG_NEEDS_SECRET_SERVICE),
        ];
        let names: std::collections::BTreeSet<&str> = all.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), all.len());
        // The accepted step names are exactly the wire names.
        assert_eq!(names, STEP_NAMES.iter().copied().collect());
    }

    /// §8.6: the stop text is the spec's sentence, verbatim.
    #[test]
    fn the_secret_service_stop_text_is_the_spec_sentence() {
        let spec = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/superpowers/specs/2026-10-07-atlas-duck-design.md");
        let text = std::fs::read_to_string(&spec).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            text.contains(&format!("\"{MSG_NEEDS_SECRET_SERVICE}\"")),
            "§8.6 text drifted"
        );
    }

    /// The keyring stop says what the error window says for the same state (§8.7).
    #[test]
    fn the_keyring_stop_text_is_the_error_window_text() {
        let gate = GateState::Locked(atlas_duck_audit::LockedReason::KeyringNotLocal);
        let shown = gate.envelope().error.map(|e| e.message);
        assert_eq!(shown.as_deref(), Some(MSG_KEYRING_NOT_LOCAL));
    }

    /// M6 final review M-9 (M10 T15): an `audit.db` whose `install_id` cannot be read at step 0 is
    /// still (1a) and pinned without an id, as before, but the diagnostic log now says so with a
    /// class (never the path or the error's text).
    #[test]
    fn an_unreadable_store_id_is_logged() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("data");
        std::fs::create_dir(&dir)?;
        std::fs::write(dir.join(DB_FILE), b"this is not an audit log")?;
        let pinned_file = tmp.path().join("paths.toml");
        let (got, log) = crate::restore_flow::tests::diag_lines(|| {
            prepare_data_dir(
                &dir,
                false,
                &pinned_file,
                tmp.path(),
                "thishost",
                paths::check_data_dir,
                &|_: &Path, _: &PinnedPaths| Ok::<(), PinnedError>(()),
            )
        });
        let prepared = got.map_err(|r| format!("{r:?}"))?;
        assert!(prepared.existing_store);
        assert_eq!(prepared.pinned.install_id, None);
        assert!(
            log.contains("event=wizard_store_id_unreadable error_class=integrity dropped_fields=0")
                || log.contains("event=wizard_store_id_unreadable error_class=io dropped_fields=0"),
            "{log}"
        );
        assert!(!log.contains("this is not"), "{log}");
        Ok(())
    }

    /// The pinned-file write's classes (M10 T15): fixed names, never the path a variant carries.
    #[test]
    fn pinned_error_classes_name_no_path() {
        let p = PathBuf::from("/home/alice/secret-dir");
        for (e, class) in [
            (PinnedError::NonUtf8Path(p.clone()), "non_utf8"),
            (PinnedError::NotAbsolutePath(p), "not_absolute"),
            (PinnedError::Parse, "parse"),
            (
                PinnedError::NewerSchema { schema_version: 9 },
                "newer_schema",
            ),
            (PinnedError::Io(std::io::Error::other("x")), "io"),
        ] {
            assert_eq!(pinned_error_class(&e), class);
        }
    }

    /// M10 T15: the wizard's anchor dir must be what `create_new_store` takes (absolute, non-empty
    /// UTF-8 text); anything else is refused before it is kept.
    #[test]
    fn a_usable_anchor_dir_is_absolute_utf8() {
        assert!(!usable_anchor_dir(Path::new("relative/anchors")));
        assert!(!usable_anchor_dir(Path::new("")));
        let abs = std::env::temp_dir().join("anchors");
        assert!(usable_anchor_dir(&abs));
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let raw = std::ffi::OsStr::from_bytes(b"/mnt/\xff-anchors");
            assert!(!usable_anchor_dir(Path::new(raw)));
        }
    }

    #[test]
    fn refusal_texts_are_the_startup_texts() {
        let p = PathBuf::from("/mnt/share/atlas");
        assert_eq!(
            DirRefusal::NotLocal(p.clone()).text().as_deref(),
            Some(
                format!(
                    "data directory {} is not on a local filesystem",
                    p.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            DirRefusal::OtherHost("build-02".into()).text().as_deref(),
            Some("atlas-duck is running on another machine (build-02) with this data directory")
        );
        assert_eq!(DirRefusal::AlreadyPinned.text(), None);
        assert_eq!(DirRefusal::PinnedWrite.class(), "pinned_write");
    }
}
