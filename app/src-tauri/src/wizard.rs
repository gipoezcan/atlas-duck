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
//! - **(1b)** ([`begin`]): on Linux the Secret Service check (the §8.6 stop text, nothing written),
//!   then the credential window for the recovery passphrase; the pair comes back over the in-memory
//!   channel (`credential::request_recovery_passphrase`), never in a command response, and goes
//!   straight into `serve::create_first_store` (new ids for every attempt, `GENESIS`, the pinned
//!   `install_id`, `Core::start`, the cell swapped without a rebind).
//! - Then the recovery note (offered in the credential window), the instances, the CLI and the
//!   onboarding snippet; [`skip_instances`] and [`finish`] move on.
//!
//! What the wizard shows is derived from the serving state each time ([`step_of`]); only what the
//! user did is kept ([`Progress`]).

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use atlas_duck_audit::lock::{InstanceLock, LockError};
use atlas_duck_audit::{ArchivedDb, DB_FILE, latest_archived, read_store_install_id};
use atlas_duck_core::{GateState, InstanceView};
use atlas_duck_ipc::paths::{
    self, DataDirResolution, LocalDataDir, PINNED_SCHEMA_VERSION, PinnedError, PinnedPaths,
};
use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::oneshot;

use crate::commands::{CommandError, blocking};
use crate::credential::{self, FirstRunPassphrase, Purpose};
use crate::secret_service::{SecretService, SecretServiceCheck};
use crate::serve::{self, FirstStoreFailure};
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

/// A data dir step 0 refused; `error_class` = [`DirRefusal::class`] (never the path).
pub const LOG_EVENT_DIR_REFUSED: &str = "wizard_data_dir_refused";
/// The wizard stopped before (1b); `reason` = the Secret Service answer.
pub const LOG_EVENT_STOPPED: &str = "wizard_stopped";
/// The archive folder could not be read for the `GENESIS` link; `error_class` = `integrity|io`.
pub const LOG_EVENT_ARCHIVED_UNREADABLE: &str = "wizard_archived_unreadable";
/// The setup window could not be moved into the data dir's webview folder.
pub const LOG_EVENT_SETUP_NOT_MOVED: &str = "wizard_setup_window_not_moved";

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
    /// (1b): the recovery passphrase (Begin, then the credential window).
    Passphrase,
    /// `GENESIS` is being written and the core started.
    Genesis,
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
            WizardStep::Passphrase => "passphrase",
            WizardStep::Genesis => "genesis",
            WizardStep::RecoveryNote => "recovery_note",
            WizardStep::Instances => "instances",
            WizardStep::Cli => "cli",
            WizardStep::Onboarding => "onboarding",
            WizardStep::Done => "done",
            WizardStep::Stopped(_) => "stopped",
        }
    }
}

/// What runs now (one at a time; a second request is `busy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InFlight {
    DataDir,
    /// The credential window waits for the passphrase pair.
    Passphrase,
    Genesis,
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
        AppSnapshot::Gate(GateState::FirstRun) if p.in_flight == Some(InFlight::Genesis) => {
            WizardStep::Genesis
        }
        AppSnapshot::Gate(GateState::FirstRun) => WizardStep::Passphrase,
        // The start after step 0 is still opening the store.
        AppSnapshot::BeforeFirstRun | AppSnapshot::Starting if !p.existing_store => {
            WizardStep::Passphrase
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

/// Step 0 on the file system (§2.5 (0), §7.7, M4 T14), with every path given (the wizard passes
/// this host's): refuses while this host has a pinned file; the data dir is checked and created
/// ([`local_or_created`]); `instance.lock` is taken (§3.1: before the store is touched); an existing
/// `audit.db` is (1a) and its `install_id` is read without the KEK; then the pinned file is written
/// (`write`): the data dir always exists before it. Any refusal pins nothing.
pub fn prepare_data_dir(
    chosen: &Path,
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
    // cannot be read leaves the pinned file without one; the open then fails as it would at startup.
    let install_id = if existing_store {
        read_store_install_id(&data).ok().flatten()
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

/// Everything the wizard takes from the app (the tests pass their own).
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
    pub write_pinned: PinnedWriter,
    pub check_dir: DirCheck,
}

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
    {
        let mut p = w.progress();
        p.in_flight = None;
        match outcome {
            Ok(Some(prepared)) => {
                let Prepared {
                    data,
                    lock,
                    pinned,
                    existing_store,
                } = prepared;
                p.pinned = Some(pinned.clone());
                p.existing_store = existing_store;
                p.step0_done = true;
                drop(p);
                serve_data_dir(app, &w, data, lock, &pinned);
            }
            // The folder dialog was cancelled.
            Ok(None) => {}
            Err(refusal) => {
                tracing::warn!(event = LOG_EVENT_DIR_REFUSED, error_class = refusal.class());
                p.error = Some(refusal.error());
            }
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
        prepare_data_dir(&chosen, &pinned_file, &config_dir, &host, check, &*write).map(Some)
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

/// `wizard_begin {}` (PD-77): in the passphrase step (the first-run gate serves) the Linux Secret
/// Service check (§8.6: no usable provider stops the wizard with the fixed text, before any id
/// exists and with nothing written), then the credential window for the recovery passphrase;
/// while it waits, the window is brought back. In the (1a) step it opens what the store's state
/// needs again (the credential window to unlock, or the error window). Elsewhere `not_ready`.
pub async fn begin<R: Runtime>(app: &AppHandle<R>) -> Result<WizardState, CommandError> {
    let step = {
        let w = wizard(app)?;
        let mut p = w.progress();
        let step = current_step(app, &mut p, None);
        if step == WizardStep::Passphrase {
            match p.in_flight {
                Some(InFlight::Passphrase) => {}
                Some(_) => return Err(CommandError::Busy),
                None => {
                    p.in_flight = Some(InFlight::Passphrase);
                    p.error = None;
                }
            }
        }
        step
    };
    match step {
        WizardStep::Passphrase => request_passphrase(app).await?,
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
    let check = wizard(app)?.env.secret_service.clone();
    let handle = app.clone();
    let waiting = credential::current_purpose(app) == Some(Purpose::RecoveryPassphrase);
    let asked = blocking(move || {
        if waiting {
            // The window waits already: bring it back, the request stays.
            return credential::open(&handle, Purpose::RecoveryPassphrase, Show::Focus)
                .map(|()| (None, None))
                .map_err(window_error);
        }
        let found = check.check();
        if matches!(found, Some(SecretService::Missing | SecretService::Locked)) {
            return Ok((found, None));
        }
        credential::request_recovery_passphrase(&handle, Show::Focus)
            .map(|rx| (found, Some(rx)))
            .map_err(window_error)
    })
    .await;
    let w = wizard(app)?;
    match asked {
        Ok((found, rx)) => {
            let mut p = w.progress();
            if found.is_some() {
                p.secret_service = found;
            }
            if let Some(found @ (SecretService::Missing | SecretService::Locked)) = found {
                tracing::warn!(event = LOG_EVENT_STOPPED, reason = found.as_str());
                p.stopped = Some(MSG_NEEDS_SECRET_SERVICE);
                p.in_flight = None;
                return Ok(());
            }
            if let Some(rx) = rx {
                p.passphrase_request = p.passphrase_request.wrapping_add(1);
                let request = p.passphrase_request;
                drop(p);
                let handle = app.clone();
                tauri::async_runtime::spawn(
                    async move { await_passphrase(handle, rx, request).await },
                );
            }
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

fn window_error(e: WindowError) -> CommandError {
    match e {
        WindowError::Busy => CommandError::Busy,
        _ => CommandError::Internal,
    }
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
    {
        let mut p = w.progress();
        p.in_flight = None;
        match result {
            Ok(()) => p.genesis_written = true,
            Err(f) => {
                p.error = Some(WizardError {
                    class: f.class(),
                    text: None,
                });
            }
        }
    }
    match result {
        // The page offers "Save recovery note" now (§8.6: right after `GENESIS`); the Settings and
        // setup windows re-read the instances.
        Ok(()) => {
            credential::context_changed(&app);
            crate::ui_sink::emit_settings_changed(&app);
        }
        Err(_) => {
            if let Some(generation) = generation {
                let handle = app.clone();
                let _ = tauri::async_runtime::spawn_blocking(move || {
                    credential::close_if(&handle, generation)
                })
                .await;
            }
        }
    }
    emit_wizard_changed(&app);
}

/// `GENESIS` for this data dir: the archived store an archive left (in memory, else derived again
/// from the archive folder), the pinned-file writer, then `serve::create_first_store`.
async fn genesis<R: Runtime>(
    app: &AppHandle<R>,
    w: &Wizard<R>,
    pair: FirstRunPassphrase,
) -> Result<(), FirstStoreFailure> {
    let state = app
        .try_state::<ServeSlot>()
        .and_then(|s| s.get().cloned())
        .ok_or(FirstStoreFailure::NotFirstRun)?;
    let data = app
        .try_state::<DataDirHold>()
        .map(|h| h.data().clone())
        .ok_or(FirstStoreFailure::NotFirstRun)?;
    let pinned = w
        .progress()
        .pinned
        .clone()
        .ok_or(FirstStoreFailure::PinnedWrite)?;
    let archived = match credential::take_archived(app) {
        Some(a) => Some(a),
        None => tauri::async_runtime::spawn_blocking(move || archived_on_disk(&data))
            .await
            .unwrap_or(None),
    };
    let (file, write) = (w.env.pinned_file.clone(), w.env.write_pinned.clone());
    let pin: serve::PinWriter = Box::new(move |install_id| {
        let p = PinnedPaths {
            install_id: install_id.map(str::to_owned),
            ..pinned.clone()
        };
        write(&file, &p).is_ok()
    });
    serve::create_first_store(&state, pair, archived, pin).await
}

/// The archive [`latest_archived`] finds (T20 review I-1); an unreadable folder names none (the
/// archive itself is untouched; only the link in the new `GENESIS` is lost, logged).
fn archived_on_disk(data: &LocalDataDir) -> Option<ArchivedDb> {
    match latest_archived(data) {
        Ok(found) => found,
        Err(e) => {
            let class = match e {
                atlas_duck_audit::OpenError::Integrity(_) => "integrity",
                _ => "io",
            };
            tracing::warn!(event = LOG_EVENT_ARCHIVED_UNREADABLE, error_class = class);
            None
        }
    }
}

// ---------- the rest ----------

/// `wizard_skip_instances {}`: leaves the instance step (with or without instances added).
pub async fn skip_instances<R: Runtime>(app: &AppHandle<R>) -> Result<WizardState, CommandError> {
    {
        let w = wizard(app)?;
        let mut p = w.progress();
        if current_step(app, &mut p, None) != WizardStep::Instances {
            return Err(CommandError::NotReady);
        }
        p.instances_done = true;
    }
    answer(app).await
}

/// `wizard_finish {}`: the step shown is done. The recovery note: the credential window closes;
/// the CLI step: on to the onboarding snippet; the onboarding snippet: the wizard is done, the
/// setup window goes and Approvals opens. Elsewhere `not_ready`.
pub async fn finish<R: Runtime>(app: &AppHandle<R>) -> Result<WizardState, CommandError> {
    let step = {
        let w = wizard(app)?;
        let mut p = w.progress();
        let step = current_step(app, &mut p, None);
        match step {
            WizardStep::RecoveryNote => {}
            WizardStep::Cli => p.cli_done = true,
            WizardStep::Onboarding => p.finished = true,
            _ => return Err(CommandError::NotReady),
        }
        step
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
        assert_eq!(step_of(&p, &facts(&first_run)), WizardStep::Passphrase);
        let genesis = Progress {
            in_flight: Some(InFlight::Genesis),
            ..Progress::default()
        };
        assert_eq!(step_of(&genesis, &facts(&first_run)), WizardStep::Genesis);
        assert_eq!(
            step_of(&p, &facts(&AppSnapshot::Starting)),
            WizardStep::Passphrase
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
            WizardStep::Passphrase,
            WizardStep::Genesis,
            WizardStep::RecoveryNote,
            WizardStep::Instances,
            WizardStep::Cli,
            WizardStep::Onboarding,
            WizardStep::Done,
            WizardStep::Stopped(MSG_NEEDS_SECRET_SERVICE),
        ];
        let names: std::collections::BTreeSet<&str> = all.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), all.len());
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
