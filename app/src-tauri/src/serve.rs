//! App startup orchestration and IPC serving (§2.5, §3.1, §8.7 steps 1–5; PD-05, PD-06, PD-41).
//!
//! In the `Ready` startup state, off the main thread: delete a stale `<data>/endpoint` → the
//! install id (PD-41) → keystore → `audit::open` → map the outcome: `Ready` starts `Core`, every
//! other outcome builds the gate handler for its state, an error binds nothing (PD-06) → bind
//! the endpoint (writes `<data>/endpoint`) → serve one swappable cell. While the store is
//! `Locked(keychain_unavailable)` a retry loop re-runs keystore + `open` and swaps the cell to
//! `Core` on `Ready` without rebinding. No request reaches `Core` before `open` answered `Ready`
//! and `Core::start` returned; the endpoint exists only once one of the two handlers is ready.

mod app_handler;

use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::types::RustChosenPath;
use atlas_duck_audit::{
    ArchivedDb, Confirmed, DB_FILE, EntryName, FirstRunInput, KeyStore, KeyStoreError,
    KeyringLocality, LockedReason, OpenConfig, OpenError, OsKeyStore, RecoveryOffer, RestoreReport,
    StartupOutcome, Store, SystemClock, keychain_retry_schedule, new_ids, read_store_install_id,
};
use atlas_duck_core::{
    Confirm, Core, GateHandler, GateState, NativeConfirmer, ShutdownReason, ShutdownReport, UiSink,
};
use atlas_duck_ipc::paths::{EndpointLocation, LocalDataDir, PinnedPaths, remove_endpoint_file};
use atlas_duck_ipc::proto::RequestHandler;
use atlas_duck_ipc::server::{HandlerCell, IpcServer, ShutdownSignal};
use atlas_duck_ipc::transport::diag;
use secrecy::SecretString;
use tauri::{AppHandle, Manager, Runtime};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use zeroize::Zeroizing;

pub use app_handler::{AppHandler, DoctorExtras};

use crate::compose::{self, CoreInputs};
use crate::confirm::DialogConfirmer;
use crate::credential::FirstRunPassphrase;
use crate::credential::follow::AppWatcher;
use crate::credential::raise::{RaiseGate, RaiseHandle, RaiseSink, TauriRaiseEnv};
use crate::os_hooks;
use crate::script_glue::{InstanceSource, ScriptInputs};
use crate::secret_service::{CachedSecretService, SecretServiceCheck};
use crate::state::{AppState, ServeSlot};
use crate::tray;
use crate::tray_host::TrayHost;
use crate::ui_sink::TauriUiSink;

/// Diagnostic-log fields this module emits (added to the T08 allowlist). The ipc server's
/// PD-29 fields (`event`, `reason`, `connection_id`, `peer_pid`) are on the base list already.
pub const LOG_FIELDS: &[&str] = &["serve_state", "attempt"];

/// Serving started: `serve_state` = `core|first_run|locked|store_newer`, `reason` = the locked
/// reason.
pub const LOG_EVENT_SERVING: &str = "serve_started";
/// PD-06: the store could not be opened or the core not started; `error_class` =
/// `integrity|io|migration|core_start`. Never the error text.
pub const LOG_EVENT_STORE_OPEN_FAILED: &str = "store_open_failed";
/// One keychain retry (§8.7): `attempt`, then `serve_state` (+ `reason`) of its outcome.
pub const LOG_EVENT_KEYCHAIN_RETRY: &str = "keychain_retry";
/// The retry schedule ran out while the keychain stayed unavailable; the app stays locked.
pub const LOG_EVENT_KEYCHAIN_RETRY_EXHAUSTED: &str = "keychain_retry_exhausted";
/// Quit was requested during startup; nothing was bound (I-2).
pub const LOG_EVENT_START_CANCELLED: &str = "serve_start_cancelled";
/// PD-25: the 6-hourly touch of the socket file and its dir failed (Unix).
pub const LOG_EVENT_TOUCH_FAILED: &str = "ipc_touch_failed";
/// The quit path stopped waiting for a step; `reason` =
/// `start|retry|unlock|audit_job|core|served|store`.
pub const LOG_EVENT_QUIT_WAIT_EXPIRED: &str = "quit_wait_expired";
/// M6 T20: an unlock, archive or manual retry from the credential window did nothing;
/// `error_class` = [`UnlockFailure::class`]. Never a passphrase, a path or an error text.
pub const LOG_EVENT_UNLOCK_FAILED: &str = "credential_unlock_failed";
/// `Core::shutdown` ended without a report (its task panicked).
pub const LOG_EVENT_QUIT_CORE_LOST: &str = "quit_core_lost";
/// T33 review I-4: the shutdown path ended in order: the core's `APP_STOP` is in the audit log
/// (`reason` = `quit|os_shutdown|installer`, the same word as the record's). Absent after a crash
/// and when the outer bound expired, so a support log tells an orderly stop from a killed app.
pub const LOG_EVENT_APP_STOP: &str = "app_stop";

/// L78: how long `audit::open` may block before the status line `keychain_prompt` says the app is
/// waiting for a keychain authorization (an unsigned dev build re-prompts after every rebuild).
pub const KEYCHAIN_PROMPT_AFTER: Duration = Duration::from_secs(10);

/// L78: whether the platform's credential store can show an authorization prompt that blocks
/// `audit::open` (macOS keychain, Secret Service unlock). Windows' Credential Manager shows none,
/// so a slow `open` there is never a prompt and the hint would be false.
pub const PLATFORM_HAS_KEYCHAIN_PROMPT: bool = cfg!(not(windows));

/// L78: `audit::open`, started at `open_started`, still blocks at `now`: the status line
/// `keychain_prompt` (PD-90) is shown. Pure over the two instants.
pub fn keychain_prompt_hint(open_started: Instant, now: Instant) -> bool {
    prompt_due(open_started, now, KEYCHAIN_PROMPT_AFTER)
}

fn prompt_due(open_started: Instant, now: Instant, after: Duration) -> bool {
    now.saturating_duration_since(open_started) >= after
}

/// What the app wants to hear when the serving state changes behind a command's back: the
/// keychain retry ended or swapped the cell, an unlock or an archive did, the store failed, the
/// keychain prompt hint came or went (M6 T22). The tray and an open credential window follow it.
pub trait ServeWatcher: Send + Sync {
    /// Called after the change, with no lock of the serving state held, on a thread of the serve
    /// runtime: it must not block (the app's own spawns the real work).
    fn serving_changed(&self);
}

/// What the app hands the serving state beyond the data it serves (M6 T22). `Default` is what the
/// tests that need none of it use.
#[derive(Clone)]
pub struct ServeHooks {
    pub watcher: Option<Arc<dyn ServeWatcher>>,
    /// Set while `audit::open` has blocked past [`ServeHooks::keychain_prompt_after`] (L78); the
    /// app's `ServeSlot` owns the flag, so it is readable before any `ServeState` exists.
    pub keychain_prompt: Arc<AtomicBool>,
    /// [`KEYCHAIN_PROMPT_AFTER`] in production.
    pub keychain_prompt_after: Duration,
    /// [`PLATFORM_HAS_KEYCHAIN_PROMPT`] in production; without it the hint is never raised.
    pub keychain_prompt_enabled: bool,
    /// M8 Task 20: the startup probe's holder and the update flag the app's `AppState` owns, for
    /// the script glue of every core this state starts. `Default`: no probe report ever arrives,
    /// so every script is refused (`probe_pending`).
    pub scripts: ScriptInputs,
    /// Tests: the next `n` `Core::start`s of this serving state fail (the store is shut down).
    #[doc(hidden)]
    pub fail_core_start: Option<Arc<AtomicU32>>,
    /// Tests: the next `n` retry `open`s of this serving state fail with an I/O error.
    #[doc(hidden)]
    pub fail_retry_open: Option<Arc<AtomicU32>>,
    /// Tests: the next `n` retry `open`s of this serving state fail with an integrity error (a
    /// class that is final until a restart, unlike the I/O error of `fail_retry_open`).
    #[doc(hidden)]
    pub fail_retry_open_integrity: Option<Arc<AtomicU32>>,
}

impl Default for ServeHooks {
    fn default() -> ServeHooks {
        ServeHooks {
            watcher: None,
            keychain_prompt: Arc::new(AtomicBool::new(false)),
            keychain_prompt_after: KEYCHAIN_PROMPT_AFTER,
            keychain_prompt_enabled: PLATFORM_HAS_KEYCHAIN_PROMPT,
            scripts: ScriptInputs::default(),
            fail_core_start: None,
            fail_retry_open: None,
            fail_retry_open_integrity: None,
        }
    }
}

impl ServeHooks {
    fn notify(&self) {
        if let Some(w) = &self.watcher {
            w.serving_changed();
        }
    }

    fn set_prompt(&self, on: bool) {
        if self.keychain_prompt.swap(on, Ordering::SeqCst) != on {
            self.notify();
        }
    }
}

/// Runs `open` (a keystore + `audit::open`, which blocks while the OS shows a keychain
/// authorization prompt, L78); past [`ServeHooks::keychain_prompt_after`] the hint is up until it
/// returns.
async fn with_prompt_hint<T>(open: impl Future<Output = T>, hooks: &ServeHooks) -> T {
    if !hooks.keychain_prompt_enabled {
        return open.await;
    }
    tokio::pin!(open);
    let started = Instant::now();
    tokio::select! {
        biased;
        out = &mut open => return out,
        () = tokio::time::sleep(hooks.keychain_prompt_after) => {}
    }
    hooks.set_prompt(prompt_due(
        started,
        Instant::now(),
        hooks.keychain_prompt_after,
    ));
    let out = open.await;
    hooks.set_prompt(false);
    out
}

/// PD-25: how often the socket file and its dir are touched (Unix).
pub const TOUCH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// PD-38: the outer bound of the whole quit path. `Core::shutdown` waits at most 60 s for
/// writes that are `executing` (§2.5 step 4); this leaves 15 s for the rest.
pub const SHUTDOWN_OUTER: Duration = Duration::from_secs(75);
/// How long the quit path waits for the start task to notice the quit request.
pub const START_WAIT: Duration = Duration::from_secs(15);
/// How long the quit path waits for a keychain retry that is mid-`open` or mid-`Core::start`.
pub const RETRY_WAIT: Duration = Duration::from_secs(20);
/// PD-38: `serve` returns within 2 s of the shutdown signal.
pub const SERVE_STOP_WAIT: Duration = Duration::from_secs(2);
/// How long the quit path waits for `Store::shutdown` (it joins the writer thread).
pub const STORE_WAIT: Duration = Duration::from_secs(10);

// ---------- keystore ----------

/// Builds the keystore for an install id (PD-41). Production: `OsKeyStore`; Task 21 swaps in
/// the test keystore under `scripted-approver`. Called on a blocking thread (on Linux
/// `OsKeyStore::new` may talk to the Secret Service).
pub trait KeysFactory: Send + Sync {
    fn keys(&self, install_id: &str) -> Result<Arc<dyn KeyStore>, KeyStoreError>;
}

/// The OS keychain.
pub struct OsKeysFactory;

impl KeysFactory for OsKeysFactory {
    fn keys(&self, install_id: &str) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
        Ok(Arc::new(OsKeyStore::new(install_id)?))
    }
}

/// PD-41: a keystore that cannot be built is `keyring_not_local` when it said so, else
/// `keychain_unavailable` (retried like an `open` that answered it).
pub fn locked_reason_for(e: &KeyStoreError) -> LockedReason {
    match e {
        KeyStoreError::NotLocal => LockedReason::KeyringNotLocal,
        KeyStoreError::Unavailable
        | KeyStoreError::Locked
        | KeyStoreError::Corrupt
        | KeyStoreError::Other(_) => LockedReason::KeychainUnavailable,
    }
}

/// The keystore of the no-store path. `audit::open` decides `FirstRun` (or refuses a WAL
/// without its DB) before it reads a key, so this is never asked; if it were, it refuses
/// everything and reports an unknown locality, which keeps a store locked (fail closed). The
/// OS keychain is never touched before first run (PD-41).
struct NoKeyStore;

const MSG_NO_KEYSTORE: &str = "no keystore before first run";

impl KeyStore for NoKeyStore {
    fn install_id(&self) -> &str {
        ""
    }
    fn get(&self, _e: &EntryName) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        Err(KeyStoreError::Unavailable)
    }
    fn set(&self, _e: &EntryName, _v: &[u8]) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::Unavailable)
    }
    fn delete(&self, _e: &EntryName) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::Unavailable)
    }
    fn locality(&self) -> KeyringLocality {
        KeyringLocality::Unknown {
            reason: MSG_NO_KEYSTORE.to_owned(),
        }
    }
}

// ---------- outcomes and failures ----------

/// What a startup outcome serves (C.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    Core,
    Gate(GateState),
}

/// `Ready` → `Core`; `FirstRun`, `Locked(r)`, `StoreNewer` → the gate in that state.
pub fn map_outcome(o: &StartupOutcome) -> Served {
    match o {
        StartupOutcome::Ready { .. } => Served::Core,
        StartupOutcome::FirstRun => Served::Gate(GateState::FirstRun),
        StartupOutcome::Locked(r) => Served::Gate(GateState::Locked(*r)),
        StartupOutcome::StoreNewer { .. } => Served::Gate(GateState::StoreNewer),
    }
}

/// The `serve_state` log value.
fn served_name(s: &Served) -> &'static str {
    match s {
        Served::Core => "core",
        Served::Gate(GateState::FirstRun) => "first_run",
        Served::Gate(GateState::Locked(_)) => "locked",
        Served::Gate(GateState::StoreNewer) => "store_newer",
        Served::Gate(GateState::NotConfigured(_)) => "not_configured",
        Served::Gate(GateState::ShuttingDown) => "shutting_down",
        Served::Gate(GateState::StoreFailed) => "store_failed",
    }
}

/// The PD-06 static class of a store failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFailure {
    Integrity,
    Io,
    Migration,
    CoreStart,
}

impl StoreFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            StoreFailure::Integrity => "integrity",
            StoreFailure::Io => "io",
            StoreFailure::Migration => "migration",
            StoreFailure::CoreStart => "core_start",
        }
    }

    fn of(e: &OpenError) -> StoreFailure {
        match e {
            OpenError::Io(_) | OpenError::Sqlite(_) => StoreFailure::Io,
            OpenError::MigrationFailed { .. } => StoreFailure::Migration,
            _ => StoreFailure::Integrity,
        }
    }

    fn log(self) {
        tracing::error!(
            event = LOG_EVENT_STORE_OPEN_FAILED,
            error_class = self.as_str()
        );
    }
}

/// Why nothing is served: no endpoint was bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupFailure {
    /// PD-06: `audit::open` failed, the store's install id could not be read (PD-41), or
    /// `Core::start` refused. The app keeps `instance.lock` and shows
    /// [`tray::MSG_STORE_UNAVAILABLE`].
    Store(StoreFailure),
    /// Quit was requested ([`StartInputs::quit`]) before the bind; a store or core this start
    /// opened is shut down again.
    Cancelled,
}

// ---------- the serving state ----------

/// What the app keeps while it serves (managed through [`ServeSlot`]). The quit path (T20)
/// reads it.
///
/// The quit path ([`quit`], T20) runs in this order: cancel [`ServeSlot::quit`] and await
/// [`ServeSlot::take_starting`] with a bound (a start that has not bound yet ends `Cancelled` and
/// shuts down what it opened); then [`shutdown`]: [`ServeState::freeze_for_shutdown`] (no swap
/// after it; with no core the cell answers `app_shutting_down`); take the handle out of `retry`
/// and await it with a bound, the `Mutex` guard dropped before the await. Never `abort()` the
/// retry task: it owns a store or core it is starting and ends them itself once it sees the
/// freeze. Then the Audit window's job (cancelled and awaited, PD-181), the core's shutdown,
/// `shutdown.cancel()`, `served` (<= 2 s) and `Store::shutdown` on a blocking thread.
pub struct ServeState {
    pub cell: Arc<HandlerCell>,
    pub shutdown: ShutdownSignal,
    /// Set once `Core` serves (at start or by the keychain retry).
    pub core: OnceLock<Arc<Core>>,
    /// The gate handler while one serves (PD-35: its refused counter).
    pub gate: Mutex<Option<Arc<GateHandler>>>,
    /// The open store handle while `Core` serves (`Store::shutdown` on quit).
    pub store: Mutex<Option<Store>>,
    /// The `serve` task (it returns within 2 s of `shutdown`, PD-38); `None` when the endpoint
    /// could not be bound (logged as `ipc_bind_failed`).
    pub served: Mutex<Option<JoinHandle<()>>>,
    /// The keychain retry loop, while one runs. Awaited with a bound after the freeze, never
    /// aborted (see above).
    pub retry: Mutex<Option<JoinHandle<()>>>,
    /// True once the quit path called [`ServeState::freeze`] or
    /// [`ServeState::freeze_for_shutdown`]: no swap happens after that.
    frozen: Mutex<bool>,
    /// Cancelled by the freeze: wakes a retry loop that sleeps between attempts (the server's
    /// `shutdown` signal only fires at the end of the quit path).
    retry_stop: ShutdownSignal,
    extras: Arc<DoctorExtras>,
    ui: Arc<dyn UiSink>,
    /// What the credential window's unlock, archive and manual keychain retry reuse from the
    /// start (M6 T20); set by [`start_with`].
    restart: OnceLock<Restart>,
    /// One unlock or archive at a time (M6 T20). The guard (`try_lock_owned`) moves into the task
    /// that does the work, so a command future that is dropped cannot release it early (M6 T22).
    unlocking: Arc<tokio::sync::Mutex<()>>,
    /// The task of an unlock or archive in flight: the quit path awaits it with a bound, like the
    /// keychain retry, and never aborts it (it owns the store it opens).
    unlock_task: Mutex<Option<JoinHandle<()>>>,
    /// The keychain retry (scheduled or manual) is running: set when it is spawned, cleared by
    /// the task itself right before it tells the watcher it ended (a `JoinHandle` only reports
    /// "finished" after the task returned).
    retrying: AtomicBool,
    /// An open or a core start failed after the endpoint was bound (M6 T22, M4 T19 m-4): the app
    /// says the store is unusable (tray text, relaunch dialog), offers no unlock, archive or
    /// retry, and (M9 Δ4) serves the `StoreFailed` gate. Only a restart clears it.
    store_failed: AtomicBool,
    hooks: ServeHooks,
    /// The one long audit job (M10 T12/T13, PD-181): an export, a backup or a Settings restore,
    /// from its dialogs to its end. The quit path sets its cancel flag (and cancels a restore's
    /// store call that has not begun) and waits for it before the core's shutdown.
    audit_job: Mutex<Option<AuditJob>>,
}

/// The kind of an Audit-window job (`audit_job {job}`, PD-181). A Settings restore (M10 T13) is one
/// too: one long job at a time, and the quit path treats it the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditJobKind {
    Export,
    Backup,
    Restore,
}

/// One running Audit-window job: its blocking task, the cancel flag its `ExportControl` reads and,
/// for a restore, its store call.
struct AuditJob {
    kind: AuditJobKind,
    cancel: Arc<AtomicBool>,
    call: Option<Arc<StoreCall>>,
    task: JoinHandle<()>,
}

/// Why an Audit-window job did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobRefused {
    /// Another export or backup runs (one job at a time, PD-181).
    Busy,
    /// The quit path began.
    ShuttingDown,
}

/// A restore job's store call (PD-181, M10 T13): `restore_cancel` and the quit path end the flow
/// only while no call runs; a running call runs to its end (`Store::restore` has no cancel). A
/// first call that asks for the rollback confirmation changed nothing, so the flow [`reopen`]s
/// for that dialog and must `begin` again for the second call (T13 review I-1). One
/// compare-and-swap decides which came first, so a cancel answered `cancelled: true` never races a
/// call that starts anyway.
///
/// [`reopen`]: StoreCall::reopen
#[derive(Debug, Default)]
pub struct StoreCall(std::sync::atomic::AtomicU8);

const CALL_OPEN: u8 = 0;
const CALL_CANCELLED: u8 = 1;
const CALL_STARTED: u8 = 2;

impl StoreCall {
    /// The flow is about to call the store: `false` when it was cancelled first (it then calls
    /// nothing).
    pub fn begin(&self) -> bool {
        self.0
            .compare_exchange(CALL_OPEN, CALL_STARTED, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// The store call returned having changed nothing (the rollback needs its own confirmation):
    /// until the next [`StoreCall::begin`] a cancel ends the flow again.
    pub fn reopen(&self) {
        let _ =
            self.0
                .compare_exchange(CALL_STARTED, CALL_OPEN, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// Cancels the flow while no store call runs: `false` while one runs.
    pub fn cancel(&self) -> bool {
        match self.0.compare_exchange(
            CALL_OPEN,
            CALL_CANCELLED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => true,
            Err(now) => now == CALL_CANCELLED,
        }
    }

    /// The flow was cancelled before its store call.
    pub fn cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst) == CALL_CANCELLED
    }

    /// A store call runs.
    pub fn started(&self) -> bool {
        self.0.load(Ordering::SeqCst) == CALL_STARTED
    }
}

/// What `restore_cancel` did (PD-181).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreCancel {
    /// The restore ended while no store call ran: before it, or in the rollback dialog after a
    /// first call that changed nothing (or no restore runs: `false`).
    Cancelled(bool),
    /// A store call runs: it cannot be cancelled.
    Running,
}

/// The store opener and the core starter of this start (M6 T20): the data dir, `instance.lock`,
/// the keystore factory and install id, the config dir, the UI sink (whose attention feed a core
/// started later keeps) and the confirmer.
struct Restart {
    opener: Arc<Opener>,
    starter: Arc<CoreStarter>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ServeState {
    /// The cell serves `initial` (wrapped in [`AppHandler`]); no endpoint is bound yet.
    fn new(
        initial: Arc<dyn RequestHandler>,
        gate: Option<Arc<GateHandler>>,
        store: Option<Store>,
        extras: Arc<DoctorExtras>,
        ui: Arc<dyn UiSink>,
        hooks: ServeHooks,
    ) -> ServeState {
        ServeState {
            cell: Arc::new(HandlerCell::new(AppHandler::new(initial, extras.clone()))),
            shutdown: ShutdownSignal::new(),
            core: OnceLock::new(),
            gate: Mutex::new(gate),
            store: Mutex::new(store),
            served: Mutex::new(None),
            retry: Mutex::new(None),
            frozen: Mutex::new(false),
            retry_stop: ShutdownSignal::new(),
            extras,
            ui,
            restart: OnceLock::new(),
            unlocking: Arc::new(tokio::sync::Mutex::new(())),
            unlock_task: Mutex::new(None),
            retrying: AtomicBool::new(false),
            store_failed: AtomicBool::new(false),
            hooks,
            audit_job: Mutex::new(None),
        }
    }

    /// Starts `work` on the blocking pool as the Audit window's one job (PD-181), unless another
    /// one runs (`Busy`) or the quit path froze the state (`ShuttingDown`). `work` gets the job's
    /// cancel flag (`export_cancel` and the quit path set it); its answer comes through the
    /// receiver. The handle is stored under the `frozen` lock, so a freeze either comes first
    /// (and nothing starts) or finds the job and waits for it.
    pub fn spawn_audit_job<T, F>(
        &self,
        kind: AuditJobKind,
        work: F,
    ) -> Result<tokio::sync::oneshot::Receiver<T>, JobRefused>
    where
        T: Send + 'static,
        F: FnOnce(Arc<AtomicBool>) -> T + Send + 'static,
    {
        self.spawn_job(kind, None, move |cancel, _| work(cancel))
    }

    /// A Settings restore as the one audit job (M10 T13, PD-181), like [`ServeState::spawn_audit_job`]:
    /// `work` also gets the job's [`StoreCall`], which `restore_cancel` and the quit path cancel
    /// before the store call begins.
    pub fn spawn_restore_job<T, F>(
        &self,
        work: F,
    ) -> Result<tokio::sync::oneshot::Receiver<T>, JobRefused>
    where
        T: Send + 'static,
        F: FnOnce(Arc<AtomicBool>, Arc<StoreCall>) -> T + Send + 'static,
    {
        let call = Arc::new(StoreCall::default());
        self.spawn_job(
            AuditJobKind::Restore,
            Some(call.clone()),
            move |cancel, _| work(cancel, call),
        )
    }

    fn spawn_job<T, F>(
        &self,
        kind: AuditJobKind,
        call: Option<Arc<StoreCall>>,
        work: F,
    ) -> Result<tokio::sync::oneshot::Receiver<T>, JobRefused>
    where
        T: Send + 'static,
        F: FnOnce(Arc<AtomicBool>, Option<Arc<StoreCall>>) -> T + Send + 'static,
    {
        let frozen = lock(&self.frozen);
        if !self.swaps_allowed(*frozen) {
            return Err(JobRefused::ShuttingDown);
        }
        let mut slot = lock(&self.audit_job);
        if slot.as_ref().is_some_and(|job| !job.task.is_finished()) {
            return Err(JobRefused::Busy);
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let job_call = call.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::task::spawn_blocking(move || {
            let _ = tx.send(work(flag, job_call));
        });
        *slot = Some(AuditJob {
            kind,
            cancel,
            call,
            task,
        });
        drop(slot);
        drop(frozen);
        Ok(rx)
    }

    /// `export_cancel` (PD-181): sets the cancel flag of a running export; `false` when none runs
    /// (a backup cannot be cancelled).
    pub fn cancel_export(&self) -> bool {
        let slot = lock(&self.audit_job);
        match slot.as_ref() {
            Some(job) if job.kind == AuditJobKind::Export && !job.task.is_finished() => {
                job.cancel.store(true, Ordering::SeqCst);
                true
            }
            _ => false,
        }
    }

    /// `restore_cancel` (PD-181, M10 T13): a running Settings restore ends while no store call
    /// runs (`Cancelled(true)`: no further store call, no `RESTORE`; also in the rollback dialog);
    /// while a call runs it is `Running`. `Cancelled(false)` when no restore runs.
    pub fn cancel_restore(&self) -> RestoreCancel {
        let slot = lock(&self.audit_job);
        match slot.as_ref() {
            Some(AuditJob {
                kind: AuditJobKind::Restore,
                cancel,
                call: Some(call),
                task,
            }) if !task.is_finished() => {
                if call.cancel() {
                    cancel.store(true, Ordering::SeqCst);
                    RestoreCancel::Cancelled(true)
                } else {
                    RestoreCancel::Running
                }
            }
            _ => RestoreCancel::Cancelled(false),
        }
    }

    /// The quit path's part (PD-181): the running job's cancel flag is set (an export ends before
    /// its next row and removes its partial directory; a restore with no store call running, also
    /// one in its rollback dialog, calls the store no more) and its task is handed over to be
    /// waited for. Called after the freeze, so no job starts afterwards. A job held in a native
    /// dialog is waited for within the quit path's bound only; its later answer changes nothing.
    fn stop_audit_job(&self) -> Option<JoinHandle<()>> {
        let job = lock(&self.audit_job).take()?;
        if let Some(call) = &job.call {
            call.cancel();
        }
        job.cancel.store(true, Ordering::SeqCst);
        Some(job.task)
    }

    /// The native confirmer the core was started with (M6 T28: "Prepare for removal" draws its own
    /// dialogs through it); `None` before `start_with` set the restart inputs.
    pub fn confirmer(&self) -> Option<Arc<dyn NativeConfirmer>> {
        self.restart.get().map(|r| r.starter.confirmer.clone())
    }

    /// The open store handle (M6 T28: the full backup); `None` while no store is open.
    pub fn open_store(&self) -> Option<Store> {
        lock(&self.store).clone()
    }

    /// PD-35: the kept gate handler's refused count; `None` while `Core` serves.
    pub fn refused(&self) -> Option<u64> {
        lock(&self.gate).as_ref().map(|g| g.refused())
    }

    /// The state of the gate serving now; `None` while `Core` serves.
    pub fn gate_state(&self) -> Option<GateState> {
        lock(&self.gate).as_ref().map(|g| g.state())
    }

    /// True while the keychain retry loop (§8.7) runs.
    pub fn keychain_retrying(&self) -> bool {
        self.retrying.load(Ordering::SeqCst)
    }

    /// True once an open or a core start failed with the endpoint bound (see the field).
    pub fn store_failed(&self) -> bool {
        self.store_failed.load(Ordering::SeqCst)
    }

    /// An unlock or archive of the credential window runs (it closes its own window after the
    /// answer, so the watcher leaves that window alone).
    pub fn unlock_busy(&self) -> bool {
        self.unlocking.try_lock().is_err()
    }

    /// The store is unusable (the retry's `open` failed, or a core start did): see the field.
    /// With no core serving, the cell also serves the `StoreFailed` gate from the next request
    /// on, so an agent no longer gets the stale `locked` or `first_run` answer (M9 Δ4, L217).
    /// The flag is set first: the watcher that hears of the swap already sees a failed store.
    fn mark_store_failed(&self) {
        self.store_failed.store(true, Ordering::SeqCst);
        // `install_gate` tells the watcher itself; it refuses once a core serves or the quit
        // path froze the state (the `ShuttingDown` gate stays), and then only the flag changed.
        if !self.install_gate(GateState::StoreFailed) {
            self.hooks.notify();
        }
    }

    /// True while the `serve` task runs.
    pub fn serving(&self) -> bool {
        lock(&self.served)
            .as_ref()
            .is_some_and(|h| !h.is_finished())
    }

    /// The keychain retry loop swaps nothing after this. Returns the `Core` serving now, if any.
    /// A retry that starts a `Core` after the freeze shuts that core down itself. The quit path
    /// calls [`ServeState::freeze_for_shutdown`], which also swaps a gate to `ShuttingDown`.
    pub fn freeze(&self) -> Option<Arc<Core>> {
        let mut frozen = lock(&self.frozen);
        *frozen = true;
        self.retry_stop.cancel();
        self.core.get().cloned()
    }

    /// The quit path's freeze (T20): as [`ServeState::freeze`], and with no `Core` serving the
    /// cell is swapped to the `ShuttingDown` gate in the same step, so no retry can swap in
    /// between. Returns the `Core` serving now, if any; it keeps serving until its own shutdown
    /// refuses new submits.
    pub fn freeze_for_shutdown(&self) -> Option<Arc<Core>> {
        let mut frozen = lock(&self.frozen);
        *frozen = true;
        self.retry_stop.cancel();
        let core = self.core.get().cloned();
        if core.is_none() {
            let gate = GateHandler::new(GateState::ShuttingDown, self.ui.clone());
            self.cell.swap(self.handler_for(gate.clone()));
            *lock(&self.gate) = Some(gate);
        }
        drop(frozen);
        core
    }

    fn handler_for(&self, inner: Arc<dyn RequestHandler>) -> Arc<dyn RequestHandler> {
        AppHandler::new(inner, self.extras.clone())
    }

    /// Whether the retry loop may still swap the cell; called with the `frozen` lock held. No
    /// swap after the freeze or once the shutdown signal fired (m-6).
    fn swaps_allowed(&self, frozen: bool) -> bool {
        !frozen && !self.shutdown.0.is_cancelled()
    }

    /// Serves `core` from the next request on (no rebind). False after [`ServeState::freeze`]
    /// or the shutdown signal.
    fn install_core(&self, core: Arc<Core>, store: Store) -> bool {
        let frozen = lock(&self.frozen);
        if !self.swaps_allowed(*frozen) || self.core.set(core.clone()).is_err() {
            return false;
        }
        *lock(&self.store) = Some(store);
        self.cell.swap(self.handler_for(core.handler()));
        *lock(&self.gate) = None;
        drop(frozen);
        self.hooks.notify();
        true
    }

    /// Serves the gate in `state` from the next request on. False after the freeze, the shutdown
    /// signal, or once `Core` serves. Once the store failed only `StoreFailed` itself installs
    /// (permanent until a restart, by construction rather than by every caller's guard); the
    /// quit path's `ShuttingDown` swap does not go through here.
    fn install_gate(&self, state: GateState) -> bool {
        let frozen = lock(&self.frozen);
        if !self.swaps_allowed(*frozen) || self.core.get().is_some() {
            return false;
        }
        if self.store_failed() && state != GateState::StoreFailed {
            return false;
        }
        let gate = GateHandler::new(state, self.ui.clone());
        self.cell.swap(self.handler_for(gate.clone()));
        *lock(&self.gate) = Some(gate);
        drop(frozen);
        self.hooks.notify();
        true
    }

    /// What the recovery note names of the store `Core` serves (§8.6): its `install_id`, its
    /// `chain_id` and the data dir; `None` while no store is open.
    pub fn note_facts(&self) -> Option<(String, String, PathBuf)> {
        let data = self.extras.data.as_ref()?.path().to_path_buf();
        let store = lock(&self.store);
        let store = store.as_ref()?;
        Some((store.install_id().to_owned(), store.head().2, data))
    }

    /// Starts `work` as the one unlock or archive task (M6 T20), unless the quit path froze the
    /// state: the handle is stored under the `frozen` lock, so a freeze either comes first (and
    /// nothing starts) or finds the handle and awaits it.
    fn spawn_unlock_work<T, F>(
        &self,
        work: F,
    ) -> Result<tokio::sync::oneshot::Receiver<T>, UnlockFailure>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let frozen = lock(&self.frozen);
        if !self.swaps_allowed(*frozen) {
            return Err(UnlockFailure::ShuttingDown);
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = tx.send(work.await);
        });
        *lock(&self.unlock_task) = Some(task);
        drop(frozen);
        Ok(rx)
    }

    /// The `keychain_lost` gate is serving, with no core: the only state an unlock or archive
    /// may touch the store in (no `Store` of this data dir is open then).
    fn keychain_lost(&self) -> Option<RecoveryOffer> {
        if self.core.get().is_some() || self.store_failed() {
            return None;
        }
        match self.gate_state() {
            Some(GateState::Locked(LockedReason::KeychainLost { offer })) => Some(offer),
            _ => None,
        }
    }
}

// ---------- the credential window's unlock, archive and keychain retry (M6 T20) ----------

/// The credential window's way out of `keychain_lost` (§8.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockKind {
    RecoverThisLog,
    FinishRestore,
}

/// Why an unlock or archive did nothing (or, for `CoreStart`, opened no core). Classes only:
/// never an error text (a store or keychain message can name paths).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockFailure {
    /// The gate is not `keychain_lost` with the matching offer, or a core serves.
    NotLocked,
    /// Another unlock or archive runs.
    Busy,
    /// The quit path began.
    ShuttingDown,
    /// The native confirmation was cancelled (archive).
    Cancelled,
    WrongPassphrase,
    KeychainUnavailable,
    KeyringNotLocal,
    StoreNewer,
    Integrity,
    Io,
    /// The store refused the call as such (e.g. nothing to recover: the keychain KEK opens it).
    Invalid,
    /// The store was recovered but the core did not start (the store was shut down again).
    CoreStart,
    /// M10 T13 (restore from a backup): the chosen file or folder is not an atlas-duck backup
    /// (no bundle, or its files do not match its manifest). Nothing changed.
    NotABackup,
    /// M10 T13: the restore committed but did not complete; the next start completes it (§8.7;
    /// the window's text is the UI's `COMMITTED_INCOMPLETE_TEXT`).
    CommittedIncomplete,
    /// M10 T13 (M2 T16 M-4): the locked store's own records cannot be read, so a restore cannot
    /// move it aside; "Archive old DB and start fresh" comes first. No dialog was shown.
    ArchiveFirst,
    /// M10 T13 (review M-2): the chosen backup failed its check (its chain or its schema); the
    /// locked log is not concerned. Nothing changed.
    Broken,
    /// M10 T13 (review M-2): the chosen backup does not match the anchor directory's lines.
    /// Nothing changed.
    AnchorDirMismatch,
}

impl UnlockFailure {
    pub fn class(self) -> &'static str {
        match self {
            UnlockFailure::NotLocked => "not_locked",
            UnlockFailure::Busy => "busy",
            UnlockFailure::ShuttingDown => "shutting_down",
            UnlockFailure::Cancelled => "cancelled",
            UnlockFailure::WrongPassphrase => "wrong_passphrase",
            UnlockFailure::KeychainUnavailable => "keychain_unavailable",
            UnlockFailure::KeyringNotLocal => "keyring_not_local",
            UnlockFailure::StoreNewer => "store_newer",
            UnlockFailure::Integrity => "integrity",
            UnlockFailure::Io => "io",
            UnlockFailure::Invalid => "invalid",
            UnlockFailure::CoreStart => "core_start",
            UnlockFailure::NotABackup => "not_a_backup",
            UnlockFailure::CommittedIncomplete => "committed_incomplete",
            UnlockFailure::ArchiveFirst => "archive_first",
            UnlockFailure::Broken => "broken",
            UnlockFailure::AnchorDirMismatch => "anchor_dir_mismatch",
        }
    }

    pub(crate) fn of(e: &OpenError) -> UnlockFailure {
        use atlas_duck_audit::RestoreError;
        match e {
            OpenError::Restore(RestoreError::WrongPassphrase) => UnlockFailure::WrongPassphrase,
            OpenError::Restore(RestoreError::NotABundle | RestoreError::ManifestMismatch) => {
                UnlockFailure::NotABackup
            }
            OpenError::Restore(RestoreError::SnapshotNewer { .. }) => UnlockFailure::StoreNewer,
            OpenError::Restore(RestoreError::CommittedIncomplete { .. }) => {
                UnlockFailure::CommittedIncomplete
            }
            // The chosen backup failed its check, not the locked log (T13 review M-2).
            OpenError::Restore(RestoreError::ChainBroken(_)) => UnlockFailure::Broken,
            OpenError::Restore(RestoreError::AnchorDirMismatch(_)) => {
                UnlockFailure::AnchorDirMismatch
            }
            // Never leaves the flow, which asks the rollback dialog; a refusal of the call as such.
            OpenError::Restore(RestoreError::RollbackNeedsConfirmation { .. }) => {
                UnlockFailure::Invalid
            }
            OpenError::WrongPassphrase => UnlockFailure::WrongPassphrase,
            OpenError::KeyStore(KeyStoreError::NotLocal) => UnlockFailure::KeyringNotLocal,
            OpenError::KeyStore(_) => UnlockFailure::KeychainUnavailable,
            OpenError::NewerStore(_) => UnlockFailure::StoreNewer,
            OpenError::Integrity(_) => UnlockFailure::Integrity,
            OpenError::Io(_) | OpenError::Sqlite(_) | OpenError::MigrationFailed { .. } => {
                UnlockFailure::Io
            }
            OpenError::AlreadyExists
            | OpenError::NotFirstRun
            | OpenError::PassphraseTooShort
            | OpenError::PassphraseMismatch
            | OpenError::Invalid(_) => UnlockFailure::Invalid,
        }
    }

    fn log(self) {
        tracing::warn!(event = LOG_EVENT_UNLOCK_FAILED, error_class = self.class());
    }
}

/// "Recover this log" / "Finish restore" (§8.7) with the passphrase the credential window took:
/// the audit call on a blocking thread (the passphrase is dropped, zeroized, when it returns),
/// then `Core::start` with the store's `pats_deleted` and the cell swapped to the core without a
/// rebind (the endpoint stays; T8 replays each connection's `hello`). Only while the gate is
/// `keychain_lost` with the matching offer and no core serves. The quit path awaits it (bounded);
/// a core started after the freeze is shut down again.
pub async fn unlock(
    state: &Arc<ServeState>,
    kind: UnlockKind,
    passphrase: SecretString,
) -> Result<(), UnlockFailure> {
    let failed = |f: UnlockFailure| {
        f.log();
        Err(f)
    };
    let Some(restart) = state.restart.get() else {
        return failed(UnlockFailure::NotLocked);
    };
    // The guard belongs to the task that does the work (below), not to this future.
    let Ok(one) = state.unlocking.clone().try_lock_owned() else {
        return failed(UnlockFailure::Busy);
    };
    let want = match kind {
        UnlockKind::RecoverThisLog => RecoveryOffer::RecoverThisLog,
        UnlockKind::FinishRestore => RecoveryOffer::FinishRestore,
    };
    if state.keychain_lost() != Some(want) {
        return failed(UnlockFailure::NotLocked);
    }
    let (st, opener, starter) = (
        state.clone(),
        restart.opener.clone(),
        restart.starter.clone(),
    );
    let done = state.spawn_unlock_work(async move {
        let _one_unlock_at_a_time = one;
        let opened = run_blocking_unlock(move || opener.unlock_blocking(kind, &passphrase)).await;
        let (store, keys, pats_deleted) = opened?;
        if *lock(&st.frozen) {
            shutdown_store(store).await;
            return Err(UnlockFailure::ShuttingDown);
        }
        let core = match starter.start(store.clone(), keys, pats_deleted).await {
            Ok(core) => core,
            Err(f) => {
                f.log();
                // The recovery took: the keychain holds the KEK again and the store was shut
                // down. "Keychain lost" and its "Recover this log" would be stale (a second try
                // fails `invalid`: nothing is left to recover). The gate says what is true: the
                // keychain is not the problem, a start is, and "Retry keychain" runs one
                // more `open` + start (M6 T22, m-8).
                st.install_gate(GateState::Locked(LockedReason::KeychainUnavailable));
                return Err(UnlockFailure::CoreStart);
            }
        };
        if !st.install_core(core.clone(), store.clone()) {
            core.shutdown(ShutdownReason::Quit).await;
            shutdown_store(store).await;
            return Err(UnlockFailure::ShuttingDown);
        }
        tracing::info!(event = LOG_EVENT_SERVING, serve_state = "core");
        Ok(())
    });
    let result = match done {
        Ok(rx) => rx.await.unwrap_or(Err(UnlockFailure::Io)),
        Err(f) => Err(f),
    };
    match result {
        Ok(()) => Ok(()),
        Err(f) => failed(f),
    }
}

/// Runs a blocking unlock step; a lost thread is an I/O failure.
async fn run_blocking_unlock<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, UnlockFailure> + Send + 'static,
) -> Result<T, UnlockFailure> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or(Err(UnlockFailure::Io))
}

/// plan text (T20, §8.7, §10.3): the native confirmation of "Archive old DB and start fresh";
/// `<archived>` is the data dir's archive folder.
pub const ARCHIVE_CONFIRM_TEXT: &str = "Archive this audit log and start a new one? audit.db (with its WAL) is moved to <archived> as audit-<chain_id>-<last record>-<time>.db; it is never deleted. Keep it for its remaining retention period: it can be read later only with its own recovery passphrase, through a restore. Next, a new audit log is set up with a new recovery passphrase, and every token must be entered again.";

/// The data-dir folder `audit::archive_and_start_fresh` moves a store into (its `ARCHIVE_DIR`).
pub const ARCHIVED_DIR: &str = "archived";

/// The archive confirmation text for `data`.
pub fn archive_confirm_text(data: &LocalDataDir) -> String {
    let dir = data.path().join(ARCHIVED_DIR);
    ARCHIVE_CONFIRM_TEXT.replace("<archived>", &dir.display().to_string())
}

/// "Archive old DB and start fresh" (§8.7): a Rust-drawn native confirmation (§10.3), then the
/// audit call moves the store aside (never deleting it), and the cell serves the first-run gate
/// (no store exists now) until the wizard's `GENESIS` (Task 23), which names the returned
/// [`ArchivedDb`]. Only in `keychain_lost` (either offer) with no core. Nothing is logged: there is
/// no open store; the new `GENESIS` records it.
pub async fn archive_and_start_fresh(state: &Arc<ServeState>) -> Result<ArchivedDb, UnlockFailure> {
    let failed = |f: UnlockFailure| {
        f.log();
        Err(f)
    };
    let Some(restart) = state.restart.get() else {
        return failed(UnlockFailure::NotLocked);
    };
    let Ok(one) = state.unlocking.clone().try_lock_owned() else {
        return failed(UnlockFailure::Busy);
    };
    if state.keychain_lost().is_none() {
        return failed(UnlockFailure::NotLocked);
    }
    let text = archive_confirm_text(&restart.opener.data);
    let confirmer = restart.starter.confirmer.clone();
    // The dialog blocks until the user answers: never on the async runtime or the main thread.
    // The guard goes into that thread and comes back out of it, so a dropped caller leaves the
    // archive "in progress" for as long as the dialog is up.
    let shown = text.clone();
    let asked = tokio::task::spawn_blocking(move || (confirmer.confirm(&shown), one)).await;
    let Ok((answer, one)) = asked else {
        return failed(UnlockFailure::Cancelled);
    };
    if answer != Confirm::Ok {
        return failed(UnlockFailure::Cancelled);
    }
    let confirmed = confirmed_by(&text);
    let (st, opener) = (state.clone(), restart.opener.clone());
    let done = state.spawn_unlock_work(async move {
        let _one_archive_at_a_time = one;
        if *lock(&st.frozen) {
            return Err(UnlockFailure::ShuttingDown);
        }
        let archived = run_blocking_unlock(move || {
            atlas_duck_audit::archive_and_start_fresh(&opener.data, &opener.lock, confirmed)
                .map_err(|e| UnlockFailure::of(&e))
        })
        .await?;
        // No store is left: requests get the first-run answer until `GENESIS` (§2.5).
        st.install_gate(GateState::FirstRun);
        Ok(archived)
    });
    let result = match done {
        Ok(rx) => rx.await.unwrap_or(Err(UnlockFailure::Io)),
        Err(f) => Err(f),
    };
    match result {
        Ok(a) => Ok(a),
        Err(f) => failed(f),
    }
}

/// The wait for the backup's passphrase (the credential window set in place to `restore_backup`;
/// `Cancelled` when it goes without a submit, or when the argument, the stop test, answers true).
pub type AwaitPassphrase = Box<
    dyn FnOnce(&dyn Fn() -> bool) -> Result<SecretString, crate::restore_flow::NotAsked> + Send,
>;

/// "Restore a backup instead" (M10 T13, PD-168, §8.11, §10.3): only in `keychain_lost` with no core
/// (one at a time with unlocks and archives). On a blocking thread, `restore_flow::
/// restore_without_store` (an unreadable locked store first: `archive_first`, M2 T16 M-4; then the
/// native "Restore backup" confirmation, `pick`, `passphrase` and `restore_from_source` under this
/// install's id with the locked store moved aside), then `Core::start` with the report's
/// `pats_deleted` (`APP_START` logs them, PD-28, and the core start reconciles the config file) and
/// the cell swapped to the core as an unlock does. The quit path awaits it (bounded); a freeze ends
/// the wait for the passphrase, and a core started after the freeze is shut down again.
pub async fn restore_from_backup(
    state: &Arc<ServeState>,
    pick: Box<dyn FnOnce() -> Option<RustChosenPath> + Send>,
    passphrase: AwaitPassphrase,
) -> Result<(), UnlockFailure> {
    let failed = |f: UnlockFailure| {
        f.log();
        Err(f)
    };
    let Some(restart) = state.restart.get() else {
        return failed(UnlockFailure::NotLocked);
    };
    let Ok(one) = state.unlocking.clone().try_lock_owned() else {
        return failed(UnlockFailure::Busy);
    };
    if state.keychain_lost().is_none() {
        return failed(UnlockFailure::NotLocked);
    }
    let (st, opener, starter) = (
        state.clone(),
        restart.opener.clone(),
        restart.starter.clone(),
    );
    let done = state.spawn_unlock_work(async move {
        let _one_restore_at_a_time = one;
        let (frozen, confirmer) = (st.clone(), starter.confirmer.clone());
        let restored = run_blocking_unlock(move || {
            let stop = || *lock(&frozen.frozen);
            opener.restore_blocking(&*confirmer, pick, passphrase, &stop)
        })
        .await;
        let (store, keys, report) = restored?;
        if *lock(&st.frozen) {
            shutdown_store(store).await;
            return Err(UnlockFailure::ShuttingDown);
        }
        let core = match starter
            .start(store.clone(), keys, report.pats_deleted)
            .await
        {
            Ok(core) => core,
            Err(f) => {
                f.log();
                // As after an unlock: the restore took (the keychain holds its KEK), the store
                // was shut down; the next "Retry keychain" opens it.
                st.install_gate(GateState::Locked(LockedReason::KeychainUnavailable));
                return Err(UnlockFailure::CoreStart);
            }
        };
        if !st.install_core(core.clone(), store.clone()) {
            core.shutdown(ShutdownReason::Quit).await;
            shutdown_store(store).await;
            return Err(UnlockFailure::ShuttingDown);
        }
        tracing::info!(event = LOG_EVENT_SERVING, serve_state = "core");
        Ok(())
    });
    let result = match done {
        Ok(rx) => rx.await.unwrap_or(Err(UnlockFailure::Io)),
        Err(f) => Err(f),
    };
    match result {
        Ok(()) => Ok(()),
        Err(f) => failed(f),
    }
}

/// The audit store's proof of a native confirmation: the SHA-256 of the dialog text. Every caller
/// draws that dialog first and calls this on its Ok path (`ci/check-dialog-proofs.mjs` rule 3).
pub(crate) fn confirmed_by(text: &str) -> Confirmed {
    let hex = atlas_duck_core::payloads::sha256_hex(text.as_bytes());
    let mut digest = [0u8; 32];
    for (i, b) in digest.iter_mut().enumerate() {
        *b = hex
            .get(2 * i..2 * i + 2)
            .and_then(|h| u8::from_str_radix(h, 16).ok())
            .unwrap_or(0);
    }
    Confirmed {
        dialog_text_sha256: digest,
    }
}

// ---------- the first store: the wizard's `GENESIS` (M6 T23) ----------

/// The pinned file was rewritten, `install_id` given or not (a `GENESIS` was written but the
/// pinned file still lacks its id); `error_class` is never logged with a path.
pub const LOG_EVENT_PINNED_WRITE_FAILED: &str = "pinned_write_failed";
/// The wizard's `GENESIS` (or the core after it) did not happen; `error_class` =
/// [`FirstStoreFailure::class`].
pub const LOG_EVENT_FIRST_STORE_FAILED: &str = "first_store_failed";

/// Why the wizard's first store was not created, or was created without a serving core. Classes
/// only (the setup page maps them to fixed texts); never an error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstStoreFailure {
    /// The first-run gate is not serving (a core serves, the store failed, another state).
    NotFirstRun,
    /// An unlock, archive or another `GENESIS` runs.
    Busy,
    ShuttingDown,
    /// This host's pinned file could not be rewritten first: nothing was created.
    PinnedWrite,
    /// The audit store's own count of the passphrase (NFC) found it too short (§8.6).
    PassphraseTooShort,
    /// The second entry did not unwrap the KEK (§8.6: nothing committed).
    PassphraseMismatch,
    KeychainUnavailable,
    KeyringNotLocal,
    /// `audit.db` exists now: never a `GENESIS` over or beside it (§2.5).
    StoreExists,
    Integrity,
    Io,
    Invalid,
    /// `GENESIS` is written, the core did not start: the store is unusable until a restart (which
    /// opens it as any start does).
    CoreStart,
}

impl FirstStoreFailure {
    pub fn class(self) -> &'static str {
        match self {
            FirstStoreFailure::NotFirstRun => "not_first_run",
            FirstStoreFailure::Busy => "busy",
            FirstStoreFailure::ShuttingDown => "shutting_down",
            FirstStoreFailure::PinnedWrite => "pinned_write",
            FirstStoreFailure::PassphraseTooShort => "passphrase_too_short",
            FirstStoreFailure::PassphraseMismatch => "passphrase_mismatch",
            FirstStoreFailure::KeychainUnavailable => "keychain_unavailable",
            FirstStoreFailure::KeyringNotLocal => "keyring_not_local",
            FirstStoreFailure::StoreExists => "store_exists",
            FirstStoreFailure::Integrity => "integrity",
            FirstStoreFailure::Io => "io",
            FirstStoreFailure::Invalid => "invalid",
            FirstStoreFailure::CoreStart => "core_start",
        }
    }

    fn of(e: &OpenError) -> FirstStoreFailure {
        match e {
            OpenError::PassphraseTooShort => FirstStoreFailure::PassphraseTooShort,
            OpenError::PassphraseMismatch => FirstStoreFailure::PassphraseMismatch,
            OpenError::KeyStore(KeyStoreError::NotLocal) => FirstStoreFailure::KeyringNotLocal,
            OpenError::KeyStore(_) => FirstStoreFailure::KeychainUnavailable,
            OpenError::AlreadyExists => FirstStoreFailure::StoreExists,
            OpenError::Integrity(_) | OpenError::Restore(_) => FirstStoreFailure::Integrity,
            OpenError::Io(_) | OpenError::Sqlite(_) | OpenError::MigrationFailed { .. } => {
                FirstStoreFailure::Io
            }
            OpenError::NotFirstRun
            | OpenError::WrongPassphrase
            | OpenError::NewerStore(_)
            | OpenError::Invalid(_) => FirstStoreFailure::Invalid,
        }
    }

    fn log(self) {
        tracing::warn!(
            event = LOG_EVENT_FIRST_STORE_FAILED,
            error_class = self.class()
        );
    }
}

/// Rewrites this host's pinned file (§7.7) with the `install_id` given, or without one; `false`
/// when it could not be written. The wizard builds it over its pinned paths.
pub type PinWriter = Box<dyn Fn(Option<&str>) -> bool + Send>;

/// The wizard's `GENESIS` (§2.5 step (1b), PD-77), only while the first-run gate serves with no
/// core: in one task the quit path awaits (bounded, like an unlock), one at a time with unlocks and
/// archives. In order, on a blocking thread: the pinned file loses any `install_id` (an archive left
/// the old one there; a `GENESIS` must never sit beside a pinned id of another store), new ids
/// (`new_ids()` before every `create_new_store` attempt, M2 handoff: an id a failed attempt used may
/// have left keychain entries), the keystore for them, `create_new_store` (the passphrase pair moves
/// in and is dropped, zeroized, there; the store refuses an existing DB), then the pinned file names
/// the new `install_id` (a failed write is logged: the next start reads the store's own id, PD-41).
/// Then `Core::start` on the start's own `CoreStarter` (the same UI sink and attention feed) and the
/// cell swapped to it without a rebind (`install_core` also keeps the store for the recovery note).
/// A core that does not start leaves the store failed (PD-06; a restart opens it).
pub async fn create_first_store(
    state: &Arc<ServeState>,
    pair: FirstRunPassphrase,
    archived: Option<ArchivedDb>,
    pin: PinWriter,
) -> Result<(), FirstStoreFailure> {
    let failed = |f: FirstStoreFailure| {
        f.log();
        Err(f)
    };
    let Some(restart) = state.restart.get() else {
        return failed(FirstStoreFailure::NotFirstRun);
    };
    let Ok(one) = state.unlocking.clone().try_lock_owned() else {
        return failed(FirstStoreFailure::Busy);
    };
    if state.core.get().is_some()
        || state.store_failed()
        || state.gate_state() != Some(GateState::FirstRun)
    {
        return failed(FirstStoreFailure::NotFirstRun);
    }
    let (st, opener, starter) = (
        state.clone(),
        restart.opener.clone(),
        restart.starter.clone(),
    );
    let done = state.spawn_unlock_work(async move {
        let _one_at_a_time = one;
        let created =
            tokio::task::spawn_blocking(move || opener.create_blocking(pair, archived, &pin))
                .await
                .unwrap_or(Err(FirstStoreFailure::Io));
        let (store, keys) = created?;
        if *lock(&st.frozen) {
            shutdown_store(store).await;
            return Err(FirstStoreFailure::ShuttingDown);
        }
        let core = match starter.start(store.clone(), keys, Vec::new()).await {
            Ok(core) => core,
            Err(f) => {
                // `CoreStarter::start` shut the store down.
                f.log();
                st.mark_store_failed();
                return Err(FirstStoreFailure::CoreStart);
            }
        };
        if !st.install_core(core.clone(), store.clone()) {
            core.shutdown(ShutdownReason::Quit).await;
            shutdown_store(store).await;
            return Err(FirstStoreFailure::ShuttingDown);
        }
        tracing::info!(event = LOG_EVENT_SERVING, serve_state = "core");
        Ok(())
    });
    let result = match done {
        Ok(rx) => rx.await.unwrap_or(Err(FirstStoreFailure::Io)),
        Err(_) => Err(FirstStoreFailure::ShuttingDown),
    };
    match result {
        Ok(()) => Ok(()),
        Err(f) => failed(f),
    }
}

/// What a manual keychain retry did (PD-89).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryNow {
    /// One more keystore + `open` runs now, through the retry loop's own path.
    Started,
    /// The retry loop still runs; nothing new was started.
    AlreadyRunning,
    /// The gate is not `keychain_unavailable` (or a core serves).
    NotLocked,
    ShuttingDown,
}

/// The manual keychain retry (PD-89: the credential window's "Retry keychain", Task 22's tray
/// item): one more attempt of [`retry_keychain`] with no delay, only while the gate is
/// `keychain_unavailable` and no retry runs (two concurrent `open`s would race for the cell).
pub fn retry_keychain_now(state: &Arc<ServeState>) -> RetryNow {
    let Some(restart) = state.restart.get() else {
        return RetryNow::NotLocked;
    };
    let frozen = lock(&state.frozen);
    if !state.swaps_allowed(*frozen) {
        return RetryNow::ShuttingDown;
    }
    if state.core.get().is_some()
        || state.store_failed()
        || state.gate_state() != Some(GateState::Locked(LockedReason::KeychainUnavailable))
    {
        return RetryNow::NotLocked;
    }
    if state.retrying.swap(true, Ordering::SeqCst) {
        return RetryNow::AlreadyRunning;
    }
    let task = spawn_retry(
        state.clone(),
        restart.opener.clone(),
        restart.starter.clone(),
        vec![Duration::ZERO],
        true,
    );
    *lock(&state.retry) = Some(task);
    drop(frozen);
    // The tray shows "Waiting for keyring" at once, whichever surface started the retry.
    state.hooks.notify();
    RetryNow::Started
}

/// The tray's "Retry keychain" (PD-89): [`retry_keychain_now`] on the state `slot` holds; `None`
/// while nothing serves (startup, a failed start).
pub fn retry_keychain_from_menu(slot: Option<&ServeSlot>) -> Option<RetryNow> {
    slot.and_then(ServeSlot::get).map(retry_keychain_now)
}

// ---------- quit ----------

/// What the quit path did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownOutcome {
    /// `Core::shutdown`'s report; `None` without a core, when the outer bound ended the wait
    /// first (`timed_out`), or when the core's task was lost.
    pub report: Option<ShutdownReport>,
    /// The outer bound expired while `Core::shutdown` still ran (a write that is `executing`
    /// holds it). The sweep goes on in its own task; the app exits without `APP_STOP` and the
    /// next start reconciles what is open like after a crash.
    pub timed_out: bool,
}

/// Awaits `f` for at most `d`, and never past `deadline`. `false`: the wait expired (the future
/// is dropped; a task handle only detaches).
async fn bounded<F: Future>(f: F, d: Duration, deadline: Instant, what: &'static str) -> bool {
    let until = (Instant::now() + d).min(deadline);
    let done = tokio::time::timeout_at(until, f).await.is_ok();
    if !done {
        tracing::warn!(event = LOG_EVENT_QUIT_WAIT_EXPIRED, reason = what);
    }
    done
}

/// Runs the core's shutdown in a task of its own and joins it until `deadline`. The task owns
/// the sweep: a caller that is dropped or times out cannot stop it or start a second one (M3
/// M-5). `(report, timed_out)`.
async fn run_core_shutdown<F>(shutdown: F, deadline: Instant) -> (Option<ShutdownReport>, bool)
where
    F: Future<Output = ShutdownReport> + Send + 'static,
{
    let task = tokio::spawn(shutdown);
    match tokio::time::timeout_at(deadline, task).await {
        Ok(Ok(report)) => (Some(report), false),
        Ok(Err(_)) => {
            tracing::error!(event = LOG_EVENT_QUIT_CORE_LOST);
            (None, false)
        }
        Err(_) => {
            tracing::warn!(event = LOG_EVENT_QUIT_WAIT_EXPIRED, reason = "core");
            (None, true)
        }
    }
}

/// The §2.5 shutdown path for a serving state (PD-38), `outer` bounding the whole of it:
/// freeze (a gate answers `app_shutting_down` from here on), wait for a keychain retry that is
/// mid-flight, `Core::shutdown` (refuses new submits, cancels pending, kills running scripts,
/// lets an in-flight write finish, appends `APP_STOP`), stop the server (it removes
/// `<data>/endpoint` as soon as it stops accepting, within 2 s), then the store. Idempotent;
/// [`quit`] is what makes a second Quit wait for the first. A write that outlives `outer` is
/// left to the next start's crash reconciliation (`outcome_unknown`); the store is shut down
/// regardless, so a late outcome append from it fails.
///
/// Public for tests only: a quit path (tray, test control) must call [`shutdown_then_exit`],
/// whose [`quit`] runs this same path once per [`ServeSlot`], after a start in flight ended.
#[doc(hidden)]
pub async fn shutdown(
    state: &ServeState,
    reason: ShutdownReason,
    outer: Duration,
) -> ShutdownOutcome {
    shutdown_until(state, reason, Instant::now() + outer).await
}

async fn shutdown_until(
    state: &ServeState,
    reason: ShutdownReason,
    deadline: Instant,
) -> ShutdownOutcome {
    shutdown_with(state, deadline, |core| {
        core.map(|core| async move { core.shutdown(reason).await })
    })
    .await
}

/// [`shutdown_until`] with the core stage passed in: `core_stage` gets the core the freeze
/// returned and gives the future [`run_core_shutdown`] joins until `deadline` (`None`: no core
/// stage). Tests pass a stage that never finishes.
async fn shutdown_with<S, F>(
    state: &ServeState,
    deadline: Instant,
    core_stage: S,
) -> ShutdownOutcome
where
    S: FnOnce(Option<Arc<Core>>) -> Option<F>,
    F: Future<Output = ShutdownReport> + Send + 'static,
{
    let core = state.freeze_for_shutdown();

    // Never `abort()`: the retry owns a store or core it is starting and ends them itself once
    // it sees the freeze. The guard is dropped before the await.
    let retry = lock(&state.retry).take();
    if let Some(retry) = retry {
        bounded(retry, RETRY_WAIT, deadline, "retry").await;
    }
    // M6 T20: likewise an unlock or archive of the credential window (it sees the freeze).
    let unlock = lock(&state.unlock_task).take();
    if let Some(unlock) = unlock {
        bounded(unlock, RETRY_WAIT, deadline, "unlock").await;
    }
    // M10 T12 (PD-181): an Audit-window export ends before its next row once its cancel flag is
    // set, and removes its partial directory; waiting for it here, before the core's shutdown,
    // lets that cleanup run and keeps `APP_STOP` after any record the job appends. A backup sees
    // the flag only once its folder dialog was answered (it then backs up nothing); once
    // `Store::backup` runs it is waited for the same way. Bounded by `STORE_WAIT`. A Settings
    // restore (M10 T13) that has not called the store yet calls nothing (its wait for the
    // passphrase ends at once); once `Store::restore` runs it is waited for the same way. If it
    // still runs when the process exits: before its commit rename the live store is unchanged
    // (the staging file goes at the next start), after it the next start completes the restore
    // (§8.7 interrupted restore, or "Finish restore" when the KEK was not re-sealed yet).
    let job = state.stop_audit_job();
    if let Some(job) = job {
        bounded(job, STORE_WAIT, deadline, "audit_job").await;
    }

    let (report, timed_out) = match core_stage(core) {
        Some(stage) => run_core_shutdown(stage, deadline).await,
        None => (None, false),
    };

    // The server removes `<data>/endpoint` itself when it stops accepting.
    state.shutdown.cancel();
    let served = lock(&state.served).take();
    if let Some(served) = served {
        let stopped = bounded(
            served,
            SERVE_STOP_WAIT,
            Instant::now() + SERVE_STOP_WAIT,
            "served",
        );
        if !stopped.await
            && let Some(data) = &state.extras.data
        {
            // A stuck server must not leave an endpoint file pointing at a dying app.
            let _ = remove_endpoint_file(data);
        }
    }

    let store = lock(&state.store).take();
    if let Some(store) = store {
        let stopped = tokio::task::spawn_blocking(move || store.shutdown());
        bounded(stopped, STORE_WAIT, Instant::now() + STORE_WAIT, "store").await;
    }
    ShutdownOutcome { report, timed_out }
}

/// Quit from the tray (§2.5): cancels a start that is still running and waits for it, then
/// [`shutdown`]s the state it left in `slot` (none when the start failed or was cancelled).
/// `outer` bounds all of it. One run per slot: a second Quit while one runs waits for it and
/// gets the same outcome.
///
/// When `Core::start` is still running after `START_WAIT` it is not waited for any longer: quit
/// returns without a store shutdown (logged as `quit_wait_expired`) and the next start recovers
/// the WAL.
pub async fn quit(slot: &ServeSlot, reason: ShutdownReason, outer: Duration) -> ShutdownOutcome {
    *slot
        .quit_done()
        .get_or_init(|| async move {
            let deadline = Instant::now() + outer;
            slot.quit().cancel();
            // The start task ends `Cancelled` (and shuts down what it opened) or leaves its
            // state in the slot before it finishes.
            let starting = slot.take_starting();
            if let Some(starting) = starting {
                bounded(starting, START_WAIT, deadline, "start").await;
            }
            let outcome = match slot.get() {
                Some(state) => shutdown_until(state, reason, deadline).await,
                None => ShutdownOutcome {
                    report: None,
                    timed_out: false,
                },
            };
            log_app_stop(&outcome, reason);
            outcome
        })
        .await
}

/// Logs [`LOG_EVENT_APP_STOP`] when the core's shutdown finished inside its bound and appended
/// `APP_STOP`. Nothing is logged without a core, after `timed_out`, a lost core task or a failed
/// append: those end like a crash and the next start reconciles.
fn log_app_stop(outcome: &ShutdownOutcome, reason: ShutdownReason) {
    let logged = outcome
        .report
        .is_some_and(|report| report.app_stop_logged && !outcome.timed_out);
    if logged {
        let reason = match reason {
            ShutdownReason::Quit => "quit",
            ShutdownReason::OsShutdown => "os_shutdown",
            ShutdownReason::Installer => "installer",
        };
        tracing::info!(event = LOG_EVENT_APP_STOP, reason);
    }
}

/// The one shutdown path of the process (§2.5): every Quit (tray, the `quit` command, the error
/// windows) and every OS end-session source (M6 T29, `os_hooks`). The first call runs [`quit`]
/// with [`SHUTDOWN_OUTER`] on the async runtime (the menu handler runs on the main thread and must
/// not block), ends the path's ticket and runs what the OS hooks left for its end (they release
/// their block, `os_hooks::ShutdownPath::end`), then `app.exit(0)` (after
/// `os_hooks::EXIT_GRACE` when the OS ends the process itself, and `std::process::exit(0)` one
/// grace later if the process still runs then). A later call joins the run: the
/// same ticket, nothing started again, the first call's reason kept. Without a [`ServeSlot`] (no
/// store is served in this startup state) the path ends at once.
pub fn shutdown_then_exit<R: Runtime>(
    app: &AppHandle<R>,
    reason: ShutdownReason,
) -> os_hooks::ShutdownTicket {
    os_hooks::path_of(app).begin(reason, |_| {
        let handle = app.clone();
        tauri::async_runtime::spawn(async move {
            if let Some(slot) = handle.try_state::<ServeSlot>() {
                quit(&slot, reason, SHUTDOWN_OUTER).await;
            }
            if os_hooks::path_of(&handle).end() {
                tokio::time::sleep(os_hooks::EXIT_GRACE).await;
                handle.exit(0);
                // The OS's reply and `exit(0)` both reach the main thread; when neither ended
                // the process (macOS: a modal loop that serves neither route), it ends here. The
                // path is over: the store is shut down.
                tokio::time::sleep(os_hooks::EXIT_GRACE).await;
                tracing::warn!(
                    event = os_hooks::LOG_EVENT_OS_HOOK_FAILED,
                    reason = "exit",
                    error_class = "main_thread"
                );
                std::process::exit(0);
            }
            handle.exit(0);
        });
    })
}

/// True while the serving core has a write request on the wire (§2.5 step 4): what the OS
/// end-session hooks hold the OS back for (M6 T29). False while no core serves.
pub fn write_in_flight(slot: Option<&ServeSlot>) -> bool {
    slot.and_then(ServeSlot::get)
        .and_then(|state| state.core.get())
        .is_some_and(|core| core.write_on_the_wire())
}

// ---------- start ----------

/// Everything [`start_with`] needs; [`start`] builds it from the Tauri app.
pub struct StartInputs {
    pub data: LocalDataDir,
    pub lock: Arc<InstanceLock>,
    /// This host's sanitized host name (Unix socket dir).
    pub host: String,
    /// `pinned.install_id` (PD-41).
    pub install_id: Option<String>,
    /// `pinned.config_dir`.
    pub config_dir: PathBuf,
    pub keys: Arc<dyn KeysFactory>,
    pub ui: Arc<dyn UiSink>,
    pub confirmer: Arc<dyn NativeConfirmer>,
    pub tray_host: Option<TrayHost>,
    pub secret_service: Arc<dyn SecretServiceCheck>,
    /// The delays between keychain retries; production: `keychain_retry_schedule()`.
    pub retry_schedule: Vec<Duration>,
    /// Quit during startup (I-2): [`ServeSlot::quit`]. Checked before `Core::start` and before
    /// the bind; once cancelled the start ends [`StartupFailure::Cancelled`] without binding.
    pub quit: ShutdownSignal,
    /// Tests: bind here instead of this user's endpoint location (`IpcServer::bind_at`).
    #[doc(hidden)]
    pub endpoint: Option<EndpointLocation>,
    /// The watcher, the keychain-prompt flag (M6 T22); `ServeHooks::default()` for none.
    pub hooks: ServeHooks,
}

/// Starts serving for the Tauri app: returns at once; the work runs on `tauri::async_runtime`
/// (the `setup` closure must not block the main thread). On success the state goes into the
/// managed [`ServeSlot`]; on a PD-06 failure the tray shows [`tray::MSG_STORE_UNAVAILABLE`]. The
/// slot's quit signal is the start's [`StartInputs::quit`] and the slot keeps the start task.
pub fn start(
    app: &AppHandle,
    data: LocalDataDir,
    lock: Arc<InstanceLock>,
    pinned: &PinnedPaths,
    host: &str,
    tray_host: Option<TrayHost>,
    keys: Arc<dyn KeysFactory>,
) {
    let slot = app.try_state::<ServeSlot>();
    // `setup` manages the slot before calling this; without one Quit cannot reach the start.
    let quit = slot
        .as_ref()
        .map_or_else(ShutdownSignal::new, |s| s.quit().clone());
    // PD-03: the test build tees the core's events to the scripted approver.
    #[cfg(feature = "scripted-approver")]
    let tee = Some(crate::testing::approver::ui_tee());
    #[cfg(not(feature = "scripted-approver"))]
    let tee = None;
    // M6 T19: the attention engine follows the same events (raise rules, toast, tray count).
    let mut ui = TauriUiSink::new(app.clone(), tee);
    if let Some(feed) = crate::attention::install(app, tray_host) {
        ui = ui.with_attention(feed);
    }
    // M6 T22: a refused request while a gate serves raises its window at most once per 5 minutes
    // (UI-04), and the tray follows every one.
    let raise = Arc::new(RaiseGate::new(
        Arc::new(TauriRaiseEnv::new(app.clone())),
        Arc::new(atlas_duck_audit::SystemClock::new()),
    ));
    app.manage(RaiseHandle(raise.clone()));
    ui = ui.with_raise(Arc::new(RaiseSink::new(raise)));
    // M8 Task 20: the glue awaits the report of the probe `setup` started, through `AppState`.
    let scripts = app
        .try_state::<AppState>()
        .map(|s| s.script_inputs())
        .unwrap_or_default();
    // The glue raising the update flag (`updated_restart`) asks the header to re-read the status.
    let status_app = app.clone();
    scripts
        .status
        .set(move || crate::ui_sink::emit_status_changed(&status_app));
    let hooks = ServeHooks {
        watcher: Some(Arc::new(AppWatcher::new(app.clone()))),
        keychain_prompt: slot
            .as_ref()
            .map_or_else(Arc::default, |s| s.keychain_prompt_flag()),
        scripts,
        ..ServeHooks::default()
    };
    let inputs = StartInputs {
        data,
        lock,
        host: host.to_owned(),
        install_id: pinned.install_id.clone(),
        config_dir: pinned.config_dir.clone(),
        keys,
        ui: Arc::new(ui),
        confirmer: Arc::new(DialogConfirmer::new(app.clone())),
        tray_host,
        secret_service: Arc::new(CachedSecretService::new()),
        retry_schedule: keychain_retry_schedule().to_vec(),
        quit,
        endpoint: None,
        hooks,
    };
    let handle = app.clone();
    let task = tauri::async_runtime::spawn(async move {
        // The test build's `delay-startup-ms` control file (I-17), before the first `open`.
        #[cfg(feature = "scripted-approver")]
        crate::testing::control::startup_delay(&inputs.data, &inputs.quit).await;
        match start_with(inputs).await {
            Ok(state) => {
                if let Some(slot) = handle.try_state::<ServeSlot>() {
                    slot.set(state);
                }
            }
            Err(StartupFailure::Store(_)) => {
                if let Some(slot) = handle.try_state::<ServeSlot>() {
                    slot.mark_store_failed();
                }
            }
            Err(StartupFailure::Cancelled) => {}
        }
        // M6 T6: the tray shows the state startup ended in (PD-06: [`tray::MSG_STORE_UNAVAILABLE`]),
        // and a cold start without `--background` opens its window now (§2.5).
        tray::refresh(&handle);
        crate::windows::startup_completed(&handle);
        // M6 T23: a start the wizard's step 0 began routes a (1a) lock or error state itself.
        crate::wizard::serving_started(&handle);
    });
    // The task may have finished already; its handle is still what Quit awaits.
    if let Some(slot) = slot {
        slot.set_starting(task);
    }
}

/// [`start`] without Tauri: the UI sink and the confirmer come in directly (tests drive it).
/// Must run inside a multi-thread tokio runtime with IO and time enabled; every task it spawns
/// runs there.
pub async fn start_with(i: StartInputs) -> Result<Arc<ServeState>, StartupFailure> {
    let opener = Arc::new(Opener {
        data: i.data.clone(),
        lock: i.lock.clone(),
        keys: i.keys.clone(),
        pinned_install_id: i.install_id.clone(),
        install_id: OnceLock::new(),
    });
    let starter = Arc::new(CoreStarter {
        config_dir: i.config_dir.clone(),
        ui: i.ui.clone(),
        confirmer: i.confirmer.clone(),
        tray_host: i.tray_host,
        scripts: i.hooks.scripts.clone(),
        fail_next: i.hooks.fail_core_start.clone(),
    });

    // Steps 1–4: stale endpoint file, install id, keystore, `open`. A keychain authorization
    // prompt blocks the last (L78): past 10 s the status line `keychain_prompt` says so.
    let first = with_prompt_hint(opener.clone().first_open(), &i.hooks).await;
    let (outcome, keys) = match first {
        Ok(opened) => opened,
        Err(f) => {
            f.log();
            return Err(StartupFailure::Store(f));
        }
    };
    let served = map_outcome(&outcome);
    let extras = Arc::new(DoctorExtras {
        tray_host: i.tray_host,
        secret_service: i.secret_service.clone(),
        data: Some(i.data.clone()),
    });

    // Step 5: what the cell holds first. The store is shut down if the core does not start.
    let (initial, core, gate, store): (Arc<dyn RequestHandler>, _, _, _) = match outcome {
        StartupOutcome::Ready {
            store,
            pats_deleted,
            ..
        } => {
            let Some(keys) = keys else {
                shutdown_store(store).await;
                StoreFailure::Integrity.log();
                return Err(StartupFailure::Store(StoreFailure::Integrity));
            };
            // I-2: Quit during `open` starts no core.
            if i.quit.0.is_cancelled() {
                return Err(abandon(None, Some(store)).await);
            }
            match starter.start(store.clone(), keys, pats_deleted).await {
                Ok(core) => (core.handler(), Some(core), None, Some(store)),
                Err(f) => {
                    f.log();
                    return Err(StartupFailure::Store(f));
                }
            }
        }
        _ => {
            let Served::Gate(state) = served else {
                // Only `Ready` maps to `Core`.
                StoreFailure::Integrity.log();
                return Err(StartupFailure::Store(StoreFailure::Integrity));
            };
            let gate = GateHandler::new(state, i.ui.clone());
            (
                gate.clone() as Arc<dyn RequestHandler>,
                None,
                Some(gate),
                None,
            )
        }
    };
    // I-2: Quit before the bind binds nothing; what this start opened is shut down. A Quit
    // after this check finds the state in the slot and shuts it down the usual way.
    if i.quit.0.is_cancelled() {
        return Err(abandon(core, store).await);
    }
    let state = Arc::new(ServeState::new(
        initial,
        gate,
        store,
        extras,
        i.ui.clone(),
        i.hooks.clone(),
    ));
    let _ = state.restart.set(Restart {
        opener: opener.clone(),
        starter: starter.clone(),
    });
    let cell = state.cell.clone();
    if let Some(core) = core {
        let _ = state.core.set(core);
    }

    // §3.1: the lock is held; bind (writes `<data>/endpoint`) and serve.
    let bound = match &i.endpoint {
        Some(location) => IpcServer::bind_at(&i.data, location.clone()),
        None => IpcServer::bind(&i.data, &i.host),
    };
    // A bind error is logged as `ipc_bind_failed` by the ipc crate. The state is kept, so the
    // quit path still shuts a started core down cleanly.
    if let Ok(server) = bound {
        #[cfg(unix)]
        spawn_socket_upkeep(server.endpoint_name(), state.shutdown.clone());
        let task = tokio::spawn(server.serve(cell, state.shutdown.clone()));
        *lock(&state.served) = Some(task);
        match served {
            Served::Gate(GateState::Locked(r)) => tracing::info!(
                event = LOG_EVENT_SERVING,
                serve_state = served_name(&served),
                reason = r.as_str()
            ),
            _ => tracing::info!(
                event = LOG_EVENT_SERVING,
                serve_state = served_name(&served)
            ),
        }
    }

    // §8.7 step 2: only `keychain_unavailable` is retried (M2 handoff).
    if served == Served::Gate(GateState::Locked(LockedReason::KeychainUnavailable)) {
        state.retrying.store(true, Ordering::SeqCst);
        let task = spawn_retry(state.clone(), opener, starter, i.retry_schedule, false);
        *lock(&state.retry) = Some(task);
    }
    Ok(state)
}

/// Opens the store; shared by the first attempt and the retries.
struct Opener {
    data: LocalDataDir,
    lock: Arc<InstanceLock>,
    keys: Arc<dyn KeysFactory>,
    pinned_install_id: Option<String>,
    /// The id the keystore is built for, fixed by the first attempt (PD-41).
    install_id: OnceLock<String>,
}

type Opened = (StartupOutcome, Option<Arc<dyn KeyStore>>);
/// A recovered store, its keystore and the instance ids whose PAT the recovery deleted.
type Unlocked = (Store, Arc<dyn KeyStore>, Vec<String>);

impl Opener {
    /// The first attempt (on a blocking thread): the stale endpoint file goes first (PD-05),
    /// then the install id (PD-41): the pinned one; without one and without `audit.db`, `open`
    /// runs with [`NoKeyStore`] (first run, or a refused WAL without its DB); without one but
    /// with a DB, the store's own id (read-only), anything else is a failure.
    async fn first_open(self: Arc<Self>) -> Result<Opened, StoreFailure> {
        run_blocking(move || {
            if remove_endpoint_file(&self.data).is_err() {
                // Bind replaces the file atomically; a store failure leaves it for the CLI's
                // liveness probe.
                tracing::warn!(
                    event = diag::EVENT_BIND_FAILED,
                    reason = diag::REASON_ENDPOINT_REMOVE
                );
            }
            let has_db = self
                .data
                .path()
                .join(DB_FILE)
                .try_exists()
                .map_err(|_| StoreFailure::Io)?;
            if !has_db {
                return self.open_without_store();
            }
            let id = match &self.pinned_install_id {
                Some(id) => id.clone(),
                None => match read_store_install_id(&self.data) {
                    Ok(Some(id)) => id,
                    Ok(None) => return Err(StoreFailure::Integrity),
                    Err(e) => return Err(StoreFailure::of(&e)),
                },
            };
            let _ = self.install_id.set(id);
            self.open_blocking()
        })
        .await
    }

    /// A retry: keystore + `open` for the install id of the first attempt.
    async fn retry_open(self: Arc<Self>) -> Result<Opened, StoreFailure> {
        run_blocking(move || self.open_blocking()).await
    }

    fn open_without_store(&self) -> Result<Opened, StoreFailure> {
        let cfg = OpenConfig::new(Arc::new(SystemClock::new()), Arc::new(NoKeyStore));
        match atlas_duck_audit::open(&self.data, &self.lock, cfg) {
            Ok(StartupOutcome::FirstRun) => Ok((StartupOutcome::FirstRun, None)),
            Ok(StartupOutcome::Ready { store, .. }) => {
                store.shutdown();
                Err(StoreFailure::Integrity)
            }
            // A DB appeared after the check: refuse rather than guess (PD-41).
            Ok(_) => Err(StoreFailure::Integrity),
            Err(e) => Err(StoreFailure::of(&e)),
        }
    }

    /// The audit call of an unlock (§8.7), with a keystore built for the install id of the first
    /// attempt: the recovered store, that keystore and the instance ids whose PAT it deleted.
    fn unlock_blocking(
        &self,
        kind: UnlockKind,
        passphrase: &SecretString,
    ) -> Result<Unlocked, UnlockFailure> {
        let Some(id) = self.install_id.get() else {
            return Err(UnlockFailure::Integrity);
        };
        let keys = self
            .keys
            .keys(id)
            .map_err(|e| match locked_reason_for(&e) {
                LockedReason::KeyringNotLocal => UnlockFailure::KeyringNotLocal,
                _ => UnlockFailure::KeychainUnavailable,
            })?;
        let mut cfg = OpenConfig::new(Arc::new(SystemClock::new()), keys.clone());
        cfg.pinned_install_id = self.pinned_install_id.clone();
        let unlocked = match kind {
            UnlockKind::RecoverThisLog => {
                atlas_duck_audit::recover_this_log(&self.data, &self.lock, cfg, passphrase)
                    .map(|(store, report)| (store, report.pats_deleted))
            }
            UnlockKind::FinishRestore => {
                atlas_duck_audit::finish_restore(&self.data, &self.lock, cfg, passphrase)
                    .map(|(store, _verify, pats_deleted)| (store, pats_deleted))
            }
        };
        unlocked
            .map(|(store, pats_deleted)| (store, keys, pats_deleted))
            .map_err(|e| UnlockFailure::of(&e))
    }

    /// The blocking half of [`restore_from_backup`]: the keystore of the install id of the first
    /// attempt (the restored store keeps this install's id, §8.11 step 3), a fresh config per
    /// store call, then `restore_flow::restore_without_store`. The running store, that keystore
    /// and the report.
    fn restore_blocking(
        &self,
        confirmer: &dyn NativeConfirmer,
        pick: Box<dyn FnOnce() -> Option<RustChosenPath> + Send>,
        passphrase: AwaitPassphrase,
        stop: &dyn Fn() -> bool,
    ) -> Result<(Store, Arc<dyn KeyStore>, RestoreReport), UnlockFailure> {
        let Some(id) = self.install_id.get() else {
            return Err(UnlockFailure::Integrity);
        };
        let keys = self
            .keys
            .keys(id)
            .map_err(|e| match locked_reason_for(&e) {
                LockedReason::KeyringNotLocal => UnlockFailure::KeyringNotLocal,
                _ => UnlockFailure::KeychainUnavailable,
            })?;
        let config = || {
            let mut cfg = OpenConfig::new(Arc::new(SystemClock::new()), keys.clone());
            cfg.pinned_install_id = self.pinned_install_id.clone();
            cfg
        };
        let (store, report) = crate::restore_flow::restore_without_store(
            &self.data, &self.lock, &config, confirmer, pick, passphrase, stop,
        )?;
        Ok((store, keys, report))
    }

    /// The blocking half of [`create_first_store`] (see there for the order).
    fn create_blocking(
        &self,
        pair: FirstRunPassphrase,
        archived: Option<ArchivedDb>,
        pin: &PinWriter,
    ) -> Result<(Store, Arc<dyn KeyStore>), FirstStoreFailure> {
        if !pin(None) {
            tracing::warn!(event = LOG_EVENT_PINNED_WRITE_FAILED);
            return Err(FirstStoreFailure::PinnedWrite);
        }
        // Never the id of `Opener::install_id`: after an archive it names the old store.
        let (install_id, chain_id) = new_ids().map_err(|e| FirstStoreFailure::of(&e))?;
        let keys = self
            .keys
            .keys(&install_id)
            .map_err(|e| match locked_reason_for(&e) {
                LockedReason::KeyringNotLocal => FirstStoreFailure::KeyringNotLocal,
                _ => FirstStoreFailure::KeychainUnavailable,
            })?;
        let cfg = OpenConfig::new(Arc::new(SystemClock::new()), keys.clone());
        let FirstRunPassphrase {
            passphrase,
            confirm,
        } = pair;
        let store = atlas_duck_audit::create_new_store(
            &self.data,
            &self.lock,
            cfg,
            FirstRunInput {
                install_id: install_id.clone(),
                chain_id,
                passphrase,
                passphrase_confirm: confirm,
                archived_db: archived,
                // The wizard's anchor-dir step and the archive confirmation it carries are
                // Task 15's (PD-167, PD-171).
                anchor_dir: None,
                archive_confirmed: None,
            },
        )
        .map_err(|e| FirstStoreFailure::of(&e))?;
        // `GENESIS` is committed: the pinned file names its store (§7.7, §8.6).
        if !pin(Some(&install_id)) {
            tracing::warn!(event = LOG_EVENT_PINNED_WRITE_FAILED);
        }
        Ok((store, keys))
    }

    fn open_blocking(&self) -> Result<Opened, StoreFailure> {
        let Some(id) = self.install_id.get() else {
            return Err(StoreFailure::Integrity);
        };
        let keys = match self.keys.keys(id) {
            Ok(keys) => keys,
            Err(e) => return Ok((StartupOutcome::Locked(locked_reason_for(&e)), None)),
        };
        let mut cfg = OpenConfig::new(Arc::new(SystemClock::new()), keys.clone());
        cfg.pinned_install_id = self.pinned_install_id.clone();
        match atlas_duck_audit::open(&self.data, &self.lock, cfg) {
            Ok(outcome) => Ok((outcome, Some(keys))),
            Err(e) => Err(StoreFailure::of(&e)),
        }
    }
}

/// Runs `f` on a blocking thread; a lost thread is an I/O failure.
async fn run_blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, StoreFailure> + Send + 'static,
) -> Result<T, StoreFailure> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or(Err(StoreFailure::Io))
}

async fn shutdown_store(store: Store) {
    let _ = tokio::task::spawn_blocking(move || store.shutdown()).await;
}

/// A start that Quit cancelled before the bind: the core (if one started) shuts down, then the
/// store. Returns [`StartupFailure::Cancelled`].
async fn abandon(core: Option<Arc<Core>>, store: Option<Store>) -> StartupFailure {
    if let Some(core) = core {
        core.shutdown(ShutdownReason::Quit).await;
    }
    if let Some(store) = store {
        shutdown_store(store).await;
    }
    tracing::info!(event = LOG_EVENT_START_CANCELLED);
    StartupFailure::Cancelled
}

/// Starts `Core` on an open store (PD-05); shared by the first attempt and the retries.
struct CoreStarter {
    config_dir: PathBuf,
    ui: Arc<dyn UiSink>,
    confirmer: Arc<dyn NativeConfirmer>,
    tray_host: Option<TrayHost>,
    /// [`ServeHooks::scripts`].
    scripts: ScriptInputs,
    /// Tests ([`ServeHooks::fail_core_start`]): how many of the next starts fail.
    fail_next: Option<Arc<AtomicU32>>,
}

impl CoreStarter {
    /// `compose::start_core`, then the hourly UTC offset (PD-32). On failure the store is shut
    /// down (PD-06: `core_start`).
    async fn start(
        &self,
        store: Store,
        keys: Arc<dyn KeyStore>,
        pats_deleted: Vec<String>,
    ) -> Result<Arc<Core>, StoreFailure> {
        let injected = self.fail_next.as_ref().is_some_and(|n| {
            n.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
                .is_ok()
        });
        if injected {
            shutdown_store(store).await;
            return Err(StoreFailure::CoreStart);
        }
        // R1 (PD-138): `APP_START` is appended inside `Core::start`, so the probe report is awaited
        // here, for at most what is left of 5 s counted from the probe's start (it ran while the
        // store was opened and verified). A report still missing is `pending` in `APP_START`; the
        // probe never blocks startup beyond this bound.
        self.scripts.probe.wait_for_app_start().await;
        // The glue of this core reads this core's instances (`atlas.instances()`), once it runs.
        let instances = InstanceSource::default();
        let inputs = CoreInputs {
            store: store.clone(),
            keys,
            config_dir: self.config_dir.clone(),
            pats_deleted,
            ui: self.ui.clone(),
            confirmer: self.confirmer.clone(),
            tray_host: self.tray_host,
            scripts: ScriptInputs {
                instances: instances.clone(),
                ..self.scripts.clone()
            },
        };
        match compose::start_core(inputs).await {
            Ok(core) => {
                let core = Arc::new(core);
                // Weak: the glue is the core's own (`CoreDeps.scripts`).
                let weak = Arc::downgrade(&core);
                instances.set(move || {
                    weak.upgrade()
                        .map(|core| core.script_instances())
                        .unwrap_or_default()
                });
                compose::spawn_offset_updater(core.clone());
                Ok(core)
            }
            Err(_) => {
                shutdown_store(store).await;
                Err(StoreFailure::CoreStart)
            }
        }
    }
}

/// §8.7: while the keychain is unavailable, `open` is re-run after each delay of `schedule`.
/// `Ready` starts `Core` and swaps the cell (no rebind; T8 replays each connection's `hello`);
/// another locked reason, `StoreNewer` or `FirstRun` swaps to that gate and stops; a failure
/// (`Err`, or `Core::start` refusing) is logged and marks the store failed
/// ([`ServeState::store_failed`]: the tray and the relaunch say so; the cell swaps to the
/// `StoreFailed` gate, M9 Δ4; the endpoint is already bound, PD-06 cannot apply), except an I/O
/// error of the `open`, which only ends this run and keeps the locked gate (a manual retry may
/// try again). After the schedule the app stays locked; the tray's and the
/// credential window's "Retry keychain" run one more attempt (`manual`, PD-89). Ends early on the
/// shutdown signal and after [`ServeState::freeze`].
async fn retry_keychain(
    state: Arc<ServeState>,
    opener: Arc<Opener>,
    starter: Arc<CoreStarter>,
    schedule: Vec<Duration>,
    manual: bool,
) {
    for (n, delay) in schedule.iter().enumerate() {
        let attempt = n + 1;
        tokio::select! {
            biased;
            () = state.shutdown.0.cancelled() => return,
            () = state.retry_stop.0.cancelled() => return,
            () = tokio::time::sleep(*delay) => {}
        }
        if *lock(&state.frozen) {
            return;
        }
        let opened = if take_one(state.hooks.fail_retry_open.as_deref()) {
            Err(StoreFailure::Io)
        } else if take_one(state.hooks.fail_retry_open_integrity.as_deref()) {
            Err(StoreFailure::Integrity)
        } else {
            with_prompt_hint(opener.clone().retry_open(), &state.hooks).await
        };
        let (outcome, keys) = match opened {
            Ok(opened) => opened,
            Err(f) => {
                f.log();
                // An I/O error of the `open` (a transient AV or backup lock on Windows) is not a
                // verdict on the store: the gate stays locked and "Retry keychain" can try again
                // (T20). Any other class (integrity, migration) is final until a restart.
                if f != StoreFailure::Io {
                    state.mark_store_failed();
                }
                return;
            }
        };
        let served = map_outcome(&outcome);
        match &served {
            Served::Gate(GateState::Locked(r)) => tracing::info!(
                event = LOG_EVENT_KEYCHAIN_RETRY,
                attempt,
                serve_state = served_name(&served),
                reason = r.as_str()
            ),
            _ => tracing::info!(
                event = LOG_EVENT_KEYCHAIN_RETRY,
                attempt,
                serve_state = served_name(&served)
            ),
        }
        match (outcome, keys) {
            (StartupOutcome::Locked(LockedReason::KeychainUnavailable), _) => continue,
            (
                StartupOutcome::Ready {
                    store,
                    pats_deleted,
                    ..
                },
                Some(keys),
            ) => {
                if *lock(&state.frozen) {
                    shutdown_store(store).await;
                    return;
                }
                let core = match starter.start(store.clone(), keys, pats_deleted).await {
                    Ok(core) => core,
                    Err(f) => {
                        f.log();
                        state.mark_store_failed();
                        return;
                    }
                };
                if !state.install_core(core.clone(), store.clone()) {
                    // The quit path froze the state while the core started.
                    core.shutdown(ShutdownReason::Quit).await;
                    shutdown_store(store).await;
                }
                return;
            }
            (StartupOutcome::Ready { store, .. }, None) => {
                shutdown_store(store).await;
                StoreFailure::Integrity.log();
                state.mark_store_failed();
                return;
            }
            (_, _) => {
                if let Served::Gate(g) = served {
                    state.install_gate(g);
                }
                return;
            }
        }
    }
    // A manual retry is one attempt by design; its outcome is logged above.
    if !manual {
        tracing::warn!(event = LOG_EVENT_KEYCHAIN_RETRY_EXHAUSTED);
    }
}

/// Tests: consumes one of the failures a counter in `hooks` still holds.
fn take_one(counter: Option<&AtomicU32>) -> bool {
    counter.is_some_and(|c| {
        c.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
    })
}

/// Spawns [`retry_keychain`]; the caller has set [`ServeState::retrying`]. When the task ends, by
/// whatever way, the flag goes and the watcher hears of it (the tray's "Waiting for keyring"
/// goes, an open credential window follows the state it was left in).
fn spawn_retry(
    state: Arc<ServeState>,
    opener: Arc<Opener>,
    starter: Arc<CoreStarter>,
    schedule: Vec<Duration>,
    manual: bool,
) -> JoinHandle<()> {
    struct Ended(Arc<ServeState>);
    impl Drop for Ended {
        fn drop(&mut self) {
            self.0.retrying.store(false, Ordering::SeqCst);
            self.0.hooks.notify();
        }
    }
    tokio::spawn(async move {
        let _ended = Ended(state.clone());
        retry_keychain(state, opener, starter, schedule, manual).await;
    })
}

/// PD-25: every [`TOUCH_INTERVAL`] the socket file and its dir get a fresh mtime
/// (systemd-tmpfiles skips recent files), until the shutdown signal.
#[cfg(unix)]
fn spawn_socket_upkeep(socket: &str, shutdown: ShutdownSignal) {
    let socket = PathBuf::from(socket);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = shutdown.0.cancelled() => return,
                () = tokio::time::sleep(TOUCH_INTERVAL) => {}
            }
            let path = socket.clone();
            let touched = tokio::task::spawn_blocking(move || {
                atlas_duck_ipc::transport::unix::touch_socket(&path)
            })
            .await;
            if !matches!(touched, Ok(Ok(()))) {
                tracing::warn!(event = LOG_EVENT_TOUCH_FAILED);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use atlas_duck_audit::RecoveryOffer;
    use tracing_subscriber::Registry;
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    #[test]
    fn gate_state_mapping() {
        assert_eq!(
            map_outcome(&StartupOutcome::FirstRun),
            Served::Gate(GateState::FirstRun)
        );
        for r in [
            LockedReason::KeychainUnavailable,
            LockedReason::KeyringNotLocal,
            LockedReason::KeychainLost {
                offer: RecoveryOffer::RecoverThisLog,
            },
            LockedReason::KeychainLost {
                offer: RecoveryOffer::FinishRestore,
            },
        ] {
            assert_eq!(
                map_outcome(&StartupOutcome::Locked(r)),
                Served::Gate(GateState::Locked(r))
            );
        }
        assert_eq!(
            map_outcome(&StartupOutcome::StoreNewer {
                found: "schema 99".into()
            }),
            Served::Gate(GateState::StoreNewer)
        );
        // `Ready` (needs a real store) is covered by `startup_ipc::ready_store_serves_core`.
    }

    #[test]
    fn keystore_error_mapping() {
        assert_eq!(
            locked_reason_for(&KeyStoreError::NotLocal).as_str(),
            "keyring_not_local"
        );
        for e in [
            KeyStoreError::Unavailable,
            KeyStoreError::Locked,
            KeyStoreError::Corrupt,
            KeyStoreError::Other("x".into()),
        ] {
            assert_eq!(
                locked_reason_for(&e).as_str(),
                "keychain_unavailable",
                "{e:?}"
            );
        }
    }

    #[test]
    fn store_failure_classes() {
        assert_eq!(
            StoreFailure::of(&OpenError::Io(io::Error::other("x"))),
            StoreFailure::Io
        );
        assert_eq!(
            StoreFailure::of(&OpenError::Sqlite("x".into())),
            StoreFailure::Io
        );
        assert_eq!(
            StoreFailure::of(&OpenError::MigrationFailed {
                from: 1,
                to: 2,
                message: "x".into()
            }),
            StoreFailure::Migration
        );
        assert_eq!(
            StoreFailure::of(&OpenError::Integrity("x".into())),
            StoreFailure::Integrity
        );
        assert_eq!(
            StoreFailure::of(&OpenError::KeyStore(KeyStoreError::Unavailable)),
            StoreFailure::Integrity
        );
        let names: Vec<&str> = [
            StoreFailure::Integrity,
            StoreFailure::Io,
            StoreFailure::Migration,
            StoreFailure::CoreStart,
        ]
        .iter()
        .map(|f| f.as_str())
        .collect();
        assert_eq!(names, ["integrity", "io", "migration", "core_start"]);
    }

    struct NoUi;
    impl UiSink for NoUi {
        fn emit(&self, _: atlas_duck_core::UiEvent) {}
    }

    struct NoCheck;
    impl SecretServiceCheck for NoCheck {
        fn check(&self) -> Option<crate::secret_service::SecretService> {
            None
        }
    }

    /// A serving state with the gate in `gs` and no core (no endpoint, no store).
    fn gate_serving(gs: GateState) -> ServeState {
        gate_serving_with(gs, ServeHooks::default())
    }

    fn gate_serving_with(gs: GateState, hooks: ServeHooks) -> ServeState {
        let ui: Arc<dyn UiSink> = Arc::new(NoUi);
        let gate = GateHandler::new(gs, ui.clone());
        let extras = Arc::new(DoctorExtras {
            tray_host: None,
            secret_service: Arc::new(NoCheck),
            data: None,
        });
        ServeState::new(gate.clone(), Some(gate), None, extras, ui, hooks)
    }

    /// M6 T29: without a serving core (no slot, nothing started, a gate) no write is on the wire;
    /// the core's own answer is `core/tests/shutdown.rs::write_on_the_wire_only_while_a_write_executes`.
    #[tokio::test]
    async fn no_write_in_flight_without_a_core() {
        assert!(!write_in_flight(None));
        let slot = ServeSlot::default();
        assert!(!write_in_flight(Some(&slot)));
        slot.set(Arc::new(gate_serving(GateState::FirstRun)));
        assert!(!write_in_flight(Some(&slot)));
    }

    async fn gate_label(state: &ServeState) -> serde_json::Value {
        state.cell.current().doctor().await.data.unwrap_or_default()["gate"].clone()
    }

    #[tokio::test]
    async fn install_gate_refuses_after_freeze() {
        let state = gate_serving(GateState::Locked(LockedReason::KeychainUnavailable));
        assert!(state.install_gate(GateState::StoreNewer));
        assert_eq!(gate_label(&state).await, "store_newer");
        assert!(state.freeze().is_none());
        assert!(!state.install_gate(GateState::FirstRun));
        assert_eq!(gate_label(&state).await, "store_newer");
    }

    /// m-6: once the shutdown signal fired, no swap happens even without a freeze.
    #[tokio::test]
    async fn install_gate_refuses_after_the_shutdown_signal() {
        let state = gate_serving(GateState::Locked(LockedReason::KeychainUnavailable));
        state.shutdown.cancel();
        assert!(!state.install_gate(GateState::StoreNewer));
        assert_eq!(gate_label(&state).await, "locked");
    }

    struct NoKeysFactory;
    impl KeysFactory for NoKeysFactory {
        fn keys(&self, _: &str) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
            Err(KeyStoreError::Unavailable)
        }
    }

    type RetryRig = (Arc<ServeState>, Arc<Opener>, Arc<CoreStarter>);

    /// A `keychain_unavailable` serving state (no endpoint, no store) with an opener and a core
    /// starter for [`retry_keychain`]; the failures the tests inject happen before the opener is
    /// used.
    fn retry_rig(
        tmp: &tempfile::TempDir,
        hooks: ServeHooks,
    ) -> Result<RetryRig, Box<dyn std::error::Error>> {
        use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};

        let dir = tmp.path().join("data");
        std::fs::create_dir(&dir)?;
        let DataDirResolution::Local(data) = check_data_dir(&dir)? else {
            return Err("the temp dir is not a local data dir".into());
        };
        let lock = Arc::new(InstanceLock::acquire(&data, "thishost")?);
        let opener = Arc::new(Opener {
            data,
            lock,
            keys: Arc::new(NoKeysFactory),
            pinned_install_id: None,
            install_id: OnceLock::new(),
        });
        let starter = Arc::new(CoreStarter {
            config_dir: tmp.path().to_owned(),
            ui: Arc::new(NoUi),
            confirmer: Arc::new(NoConfirm),
            tray_host: None,
            scripts: ScriptInputs::default(),
            fail_next: None,
        });
        let state = Arc::new(gate_serving_with(
            GateState::Locked(LockedReason::KeychainUnavailable),
            hooks,
        ));
        Ok((state, opener, starter))
    }

    /// What a submit gets from the cell now.
    async fn submit_answer(state: &ServeState) -> atlas_duck_ipc::envelope::Envelope {
        let meta = atlas_duck_ipc::proto::ConnectionMeta {
            connection_id: "c1".to_owned(),
            peer: atlas_duck_ipc::proto::PeerInfo::default(),
        };
        let params = atlas_duck_ipc::proto::SubmitParams {
            op_id: "jira.issue.get".to_owned(),
            params: serde_json::json!({"key": "ABC-1"}),
            instance: None,
            reason: None,
        };
        state.cell.current().submit(&meta, params).await.envelope
    }

    fn reason_of(env: &atlas_duck_ipc::envelope::Envelope) -> Option<&str> {
        env.error
            .as_ref()?
            .details
            .as_ref()?
            .get("reason")?
            .as_str()
    }

    /// M9 Δ4 (L217): a store failure of a class that is final until a restart (here an
    /// integrity failure of the keychain retry's `open`) installs the `StoreFailed` gate, so the
    /// served handler answers `unreachable {store_unavailable}`, not retryable, instead of the
    /// stale `locked {keychain_unavailable}`; the watcher hears of it once. An I/O failure of
    /// the same retry (`fail_retry_open`) is not a verdict on the store and still keeps the
    /// locked gate and a manual retry possible, as before.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn store_failure_installs_store_failed_gate() -> Result<(), Box<dyn std::error::Error>> {
        use atlas_duck_ipc::envelope::{ErrorCode, Status};

        // Integrity: final until a restart.
        let tmp = tempfile::tempdir()?;
        let told = Arc::new(Told::default());
        let fail = Arc::new(AtomicU32::new(1));
        let hooks = ServeHooks {
            fail_retry_open_integrity: Some(fail.clone()),
            ..watched(&told)
        };
        let (state, opener, starter) = retry_rig(&tmp, hooks)?;
        assert_eq!(gate_label(&state).await, "locked");
        let stale = submit_answer(&state).await;
        assert_eq!(reason_of(&stale), Some("keychain_unavailable"));
        retry_keychain(state.clone(), opener, starter, vec![Duration::ZERO], true).await;
        assert_eq!(fail.load(Ordering::SeqCst), 0, "the failure was used");
        assert!(state.store_failed());
        assert_eq!(state.gate_state(), Some(GateState::StoreFailed));
        assert_eq!(gate_label(&state).await, "store_failed");
        assert_eq!(told.count(), 1, "one change, heard once");
        let env = submit_answer(&state).await;
        assert_eq!(env.status, Status::Failed);
        let err = env.error.as_ref().ok_or("no error object")?;
        assert_eq!(err.code, ErrorCode::Unreachable);
        assert!(!err.retryable);
        assert_eq!(reason_of(&env), Some("store_unavailable"));
        assert_eq!(state.refused(), Some(1), "the kept gate counts the refusal");
        // The gate stays: a later swap cannot replace it (`install_gate` keeps `StoreFailed`).
        assert!(!state.install_gate(GateState::FirstRun));
        assert_eq!(state.gate_state(), Some(GateState::StoreFailed));
        assert_eq!(told.count(), 1, "a refused swap is not a change");

        // I/O: the locked gate stays, nothing is marked failed.
        let tmp = tempfile::tempdir()?;
        let fail = Arc::new(AtomicU32::new(1));
        let hooks = ServeHooks {
            fail_retry_open: Some(fail.clone()),
            ..ServeHooks::default()
        };
        let (state, opener, starter) = retry_rig(&tmp, hooks)?;
        retry_keychain(state.clone(), opener, starter, vec![Duration::ZERO], true).await;
        assert_eq!(fail.load(Ordering::SeqCst), 0, "the failure was used");
        assert!(!state.store_failed());
        assert_eq!(
            state.gate_state(),
            Some(GateState::Locked(LockedReason::KeychainUnavailable))
        );
        assert_eq!(
            reason_of(&submit_answer(&state).await),
            Some("keychain_unavailable")
        );
        Ok(())
    }

    /// The quit path wins over a failed store: after the freeze the cell keeps answering
    /// `app_shutting_down`, only the flag changes (and the watcher is told of that).
    #[tokio::test]
    async fn a_failed_store_after_the_freeze_keeps_the_shutting_down_gate() {
        let told = Arc::new(Told::default());
        let state = gate_serving_with(GateState::FirstRun, watched(&told));
        assert!(state.freeze_for_shutdown().is_none());
        state.mark_store_failed();
        assert!(state.store_failed());
        assert_eq!(state.gate_state(), Some(GateState::ShuttingDown));
        assert_eq!(gate_label(&state).await, "shutting_down");
        assert_eq!(told.count(), 1);
    }

    #[tokio::test]
    async fn freeze_for_shutdown_swaps_a_gate_to_shutting_down() {
        let state = gate_serving(GateState::FirstRun);
        assert_eq!(gate_label(&state).await, "first_run");
        assert!(state.freeze_for_shutdown().is_none());
        assert_eq!(gate_label(&state).await, "shutting_down");
        assert_eq!(state.refused(), Some(0));
        // Frozen: the retry loop cannot swap it back.
        assert!(!state.install_gate(GateState::FirstRun));
        assert_eq!(gate_label(&state).await, "shutting_down");
        // A second call keeps the shutting-down gate.
        assert!(state.freeze_for_shutdown().is_none());
        assert_eq!(gate_label(&state).await, "shutting_down");
    }

    /// M-5: the core's shutdown runs in a task of its own. The outer bound only ends the wait;
    /// the sweep goes on and is never started twice.
    #[tokio::test]
    async fn outer_bound_ends_the_wait_not_the_sweep() {
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = finished.clone();
        let started = Instant::now();
        let (report, timed_out) = run_core_shutdown(
            async move {
                tokio::time::sleep(Duration::from_millis(400)).await;
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                ShutdownReport::default()
            },
            Instant::now() + Duration::from_millis(50),
        )
        .await;
        assert!(timed_out);
        assert!(report.is_none());
        assert!(started.elapsed() < Duration::from_millis(300));
        assert!(!finished.load(std::sync::atomic::Ordering::SeqCst));
        // Nobody joins it any more; it still completes.
        let waited = Instant::now();
        while !finished.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(waited.elapsed() < Duration::from_secs(10), "sweep stopped");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn core_shutdown_report_is_passed_on_and_a_lost_task_is_not_a_timeout() {
        let want = ShutdownReport {
            cancelled: 2,
            writes_waited: 1,
            app_stop_logged: true,
        };
        let far = Instant::now() + Duration::from_secs(30);
        let got = run_core_shutdown(async move { want }, far).await;
        assert_eq!(got, (Some(want), false));
        let lost = run_core_shutdown(
            async {
                let lost: Result<ShutdownReport, &str> =
                    std::hint::black_box(Err("the core's shutdown task panicked"));
                lost.unwrap_or_else(|m| panic!("{m}"))
            },
            far,
        )
        .await;
        assert_eq!(lost, (None, false));
    }

    /// A state serving a gate over a bound endpoint, holding a real store that did a read (its
    /// reader is open, so the WAL exists until an orderly store shutdown).
    async fn bound_with_store(
        tmp: &tempfile::TempDir,
    ) -> Result<(ServeState, LocalDataDir), Box<dyn std::error::Error>> {
        use atlas_duck_audit::testing::{FreeSpaceStub, MemKeyStore, MemKeyring};
        use atlas_duck_audit::{FirstRunInput, create_new_store, new_ids};
        use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};
        use secrecy::SecretString;

        const HOST: &str = "thishost";
        let dir = tmp.path().join("data");
        std::fs::create_dir(&dir)?;
        let DataDirResolution::Local(data) = check_data_dir(&dir)? else {
            return Err("the temp dir is not a local data dir".into());
        };
        let instance = InstanceLock::acquire(&data, HOST)?;
        let (install_id, chain_id) = new_ids()?;
        let keys: Arc<dyn KeyStore> = Arc::new(MemKeyStore::new(MemKeyring::new(), &install_id));
        let mut cfg = OpenConfig::new(Arc::new(SystemClock::new()), keys);
        cfg.free_space = Some(FreeSpaceStub::new(u64::MAX));
        let pass = "correct horse battery";
        let store = create_new_store(
            &data,
            &instance,
            cfg,
            FirstRunInput {
                install_id,
                chain_id,
                passphrase: SecretString::from(pass.to_owned()),
                passphrase_confirm: SecretString::from(pass.to_owned()),
                archived_db: None,
                anchor_dir: None,
                archive_confirmed: None,
            },
        )?;
        store.recent_headers(Duration::from_secs(60))?;

        let ui: Arc<dyn UiSink> = Arc::new(NoUi);
        let gate = GateHandler::new(
            GateState::Locked(LockedReason::KeychainUnavailable),
            ui.clone(),
        );
        let extras = Arc::new(DoctorExtras {
            tray_host: None,
            secret_service: Arc::new(NoCheck),
            data: Some(data.clone()),
        });
        let state = ServeState::new(
            gate.clone(),
            Some(gate),
            Some(store),
            extras,
            ui,
            ServeHooks::default(),
        );
        #[cfg(unix)]
        let location = {
            let dir = tmp.path().join("s");
            atlas_duck_ipc::paths::ensure_socket_dir(&dir)?;
            EndpointLocation::UnixSocket(dir.join("atlas-duck.sock"))
        };
        #[cfg(windows)]
        let location = atlas_duck_ipc::paths::endpoint_location(&data, HOST)?;
        let server = IpcServer::bind_at(&data, location)?;
        let task = tokio::spawn(server.serve(state.cell.clone(), state.shutdown.clone()));
        *lock(&state.served) = Some(task);
        Ok((state, data))
    }

    /// I-1 (T20 review): a core stage that never finishes is ended by the outer bound, and the
    /// server and the store are still torn down: no endpoint file, no WAL left behind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn outer_timeout_ends_a_hung_core_stage_and_still_tears_down()
    -> Result<(), Box<dyn std::error::Error>> {
        use atlas_duck_ipc::paths::read_endpoint_file;

        let tmp = tempfile::tempdir()?;
        let (state, data) = bound_with_store(&tmp).await?;
        assert!(state.serving());
        assert!(read_endpoint_file(&data)?.is_some());
        let wal = data.path().join(format!("{DB_FILE}-wal"));
        assert!(wal.exists(), "the open store has its WAL");

        let bound = Duration::from_millis(300);
        let started = Instant::now();
        let outcome = shutdown_with(&state, started + bound, |_| {
            Some(std::future::pending::<ShutdownReport>())
        })
        .await;
        let took = started.elapsed();
        assert_eq!(
            outcome,
            ShutdownOutcome {
                report: None,
                timed_out: true
            }
        );
        assert!(took >= bound, "{took:?}");
        // The bound plus the server stop and the store shutdown, which have nothing to wait for.
        assert!(took < bound + SERVE_STOP_WAIT, "{took:?}");
        assert!(state.shutdown.0.is_cancelled());
        assert!(!state.serving());
        assert!(lock(&state.served).is_none());
        assert!(lock(&state.store).is_none(), "store taken");
        assert!(read_endpoint_file(&data)?.is_none(), "endpoint file gone");
        assert!(!wal.exists(), "the store was shut down");
        assert_eq!(gate_label(&state).await, "shutting_down");
        Ok(())
    }

    // ---- the Audit window's job (M10 T12, PD-181) ----

    use crate::commands::CommandError;
    use crate::commands::audit::tests::{Answers, Events, PASS, Rig, chosen, count, entries, rig};
    use crate::commands::audit::{ExportDoneDto, run_export};

    /// A serving state (a gate, no endpoint) that holds `rig`'s store, as the quit path finds it.
    fn serving_store(rig: &Rig) -> ServeState {
        let ui: Arc<dyn UiSink> = Arc::new(NoUi);
        let gate = GateHandler::new(GateState::FirstRun, ui.clone());
        let extras = Arc::new(DoctorExtras {
            tray_host: None,
            secret_service: Arc::new(NoCheck),
            data: None,
        });
        ServeState::new(
            gate.clone(),
            Some(gate),
            Some(rig.store.clone()),
            extras,
            ui,
            ServeHooks::default(),
        )
    }

    /// The job's answer, a receiver that hears when the export reached its first row, and a flag
    /// the job sets as its last step (after `run_export` returned, before the task ends).
    type PausedExport = (
        tokio::sync::oneshot::Receiver<Result<ExportDoneDto, CommandError>>,
        std::sync::mpsc::Receiver<()>,
        Arc<AtomicBool>,
    );

    /// The export of `rig` as the audit job: its first row waits (bounded, 30 s) until the job's
    /// cancel flag is set, so the job is known to be inside `Store::export` when the test acts, and
    /// then lingers 50 ms, so a caller that does not wait for the job finds it still running.
    fn paused_export(
        state: &ServeState,
        rig: &Rig,
    ) -> Result<PausedExport, Box<dyn std::error::Error>> {
        let flag: Arc<OnceLock<Arc<AtomicBool>>> = Arc::new(OnceLock::new());
        let (reached_tx, reached) = std::sync::mpsc::channel();
        let first = Arc::new(AtomicBool::new(true));
        {
            let flag = flag.clone();
            rig.faults.on_hit(
                atlas_duck_audit::testing::FaultPoint::ExportRow,
                move || {
                    if !first.swap(false, Ordering::SeqCst) {
                        return;
                    }
                    let _ = reached_tx.send(());
                    let until = std::time::Instant::now() + Duration::from_secs(30);
                    while std::time::Instant::now() < until
                        && !flag.get().is_some_and(|c| c.load(Ordering::SeqCst))
                    {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                },
            );
        }
        let (store, out) = (rig.store.clone(), rig.out.clone());
        let finished = Arc::new(AtomicBool::new(false));
        let ended = finished.clone();
        let rx = state
            .spawn_audit_job(AuditJobKind::Export, move |cancel| {
                let _ = flag.set(cancel.clone());
                let answer = run_export(
                    &store,
                    &Answers::new(&[Confirm::Ok]),
                    || Some(chosen(&out)),
                    atlas_duck_audit::TimeRange::all(),
                    &cancel,
                    &Events::default(),
                );
                ended.store(true, Ordering::SeqCst);
                answer
            })
            .map_err(|e| format!("{e:?}"))?;
        Ok((rx, reached, finished))
    }

    /// PD-181 (`export_cancel`): the running export's flag is set through the serving state; the
    /// export ends at its next row, its partial directory is removed and no `EXPORT` is logged. With
    /// no export running nothing is cancelled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn export_cancel_removes_partial_dir() -> Result<(), Box<dyn std::error::Error>> {
        let rig = rig(4)?;
        let state = serving_store(&rig);
        assert!(!state.cancel_export(), "nothing runs");
        let (rx, reached, _) = paused_export(&state, &rig)?;
        reached.recv_timeout(Duration::from_secs(30))?;
        assert_eq!(entries(&rig.out).len(), 1, "the partial directory exists");
        assert!(state.cancel_export());
        let answer = tokio::time::timeout(Duration::from_secs(30), rx).await??;
        assert_eq!(answer, Err(CommandError::Cancelled));
        assert!(entries(&rig.out).is_empty(), "{:?}", entries(&rig.out));
        assert_eq!(count(&rig.store, atlas_duck_audit::EventType::EXPORT)?, 0);
        assert!(!state.cancel_export(), "the job ended");
        Ok(())
    }

    /// PD-181: one Audit-window job at a time (`busy`), none after the freeze; the next one starts
    /// once the first ended.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_audit_job_at_a_time() -> Result<(), Box<dyn std::error::Error>> {
        let state = gate_serving(GateState::FirstRun);
        let (go_tx, go) = std::sync::mpsc::channel::<()>();
        let first = state
            .spawn_audit_job(AuditJobKind::Backup, move |_| {
                go.recv_timeout(Duration::from_secs(30)).is_ok()
            })
            .map_err(|e| format!("{e:?}"))?;
        for kind in [AuditJobKind::Export, AuditJobKind::Backup] {
            assert_eq!(
                state.spawn_audit_job(kind, |_| ()).err(),
                Some(JobRefused::Busy),
                "{kind:?}"
            );
        }
        assert!(!state.cancel_export(), "a backup is not cancelled");
        go_tx.send(())?;
        assert!(tokio::time::timeout(Duration::from_secs(30), first).await??);
        // The task has ended once its answer is sent; wait for it to be reported finished.
        let until = Instant::now() + Duration::from_secs(30);
        let second = loop {
            match state.spawn_audit_job(AuditJobKind::Export, |_| 7) {
                Err(JobRefused::Busy) if Instant::now() < until => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                other => break other.map_err(|e| format!("{e:?}"))?,
            }
        };
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(30), second).await??,
            7
        );
        state.freeze_for_shutdown();
        assert_eq!(
            state.spawn_audit_job(AuditJobKind::Export, |_| ()).err(),
            Some(JobRefused::ShuttingDown)
        );
        Ok(())
    }

    /// PD-181 (§2.5): Quit while an export runs sets its cancel flag and waits for it before the
    /// core's shutdown and the store's: when the core stage starts (it appends `APP_STOP`), the
    /// job has ended and its partial directory is gone (T12 review I-1: recorded by the stage
    /// itself); the log holds no `EXPORT` (the store is opened again to look). The wait ends with
    /// the export, far inside `STORE_WAIT`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quit_during_export_removes_partial_dir() -> Result<(), Box<dyn std::error::Error>> {
        let rig = rig(4)?;
        let state = serving_store(&rig);
        let (rx, reached, finished) = paused_export(&state, &rig)?;
        reached.recv_timeout(Duration::from_secs(30))?;
        assert_eq!(entries(&rig.out).len(), 1, "the partial directory exists");

        let at_core_stage: OnceLock<(bool, Vec<String>)> = OnceLock::new();
        let started = Instant::now();
        let outcome = shutdown_with(&state, started + Duration::from_secs(60), |_| {
            let _ = at_core_stage.set((finished.load(Ordering::SeqCst), entries(&rig.out)));
            Some(std::future::ready(ShutdownReport::default()))
        })
        .await;
        assert_eq!(
            at_core_stage.get(),
            Some(&(true, Vec::new())),
            "(job finished, export folder entries) when the core stage started"
        );
        assert_eq!(outcome.report, Some(ShutdownReport::default()));
        assert!(started.elapsed() < STORE_WAIT, "{:?}", started.elapsed());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(30), rx).await??,
            Err(CommandError::Cancelled)
        );
        assert!(entries(&rig.out).is_empty(), "{:?}", entries(&rig.out));
        assert!(lock(&state.store).is_none(), "store shut down");

        let cfg = crate::commands::audit::tests::config(&rig.ring, &rig.install_id, &rig.faults);
        let StartupOutcome::Ready { store, .. } =
            atlas_duck_audit::open(&rig.data, &rig.lock, cfg)?
        else {
            return Err("the store did not open again".into());
        };
        assert_eq!(count(&store, atlas_duck_audit::EventType::EXPORT)?, 0);
        store.shutdown();
        Ok(())
    }

    /// PD-181 (`restore_cancel`): a Settings restore ends before its store call (`Cancelled(true)`,
    /// the job sees its cancel flag and calls nothing); once the call began it is `Running` and the
    /// job is not cancelled. With no restore running nothing is cancelled, and `export_cancel`
    /// leaves a restore alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restore_cancel_after_start_is_busy() -> Result<(), Box<dyn std::error::Error>> {
        let state = gate_serving(GateState::FirstRun);
        assert_eq!(state.cancel_restore(), RestoreCancel::Cancelled(false));
        let (began_tx, began) = std::sync::mpsc::channel::<()>();
        let (go_tx, go) = std::sync::mpsc::channel::<()>();
        let running = state
            .spawn_restore_job(move |cancel, call| {
                let begun = call.begin();
                let _ = began_tx.send(());
                let _ = go.recv_timeout(Duration::from_secs(30));
                (begun, cancel.load(Ordering::SeqCst))
            })
            .map_err(|e| format!("{e:?}"))?;
        began.recv_timeout(Duration::from_secs(30))?;
        assert_eq!(state.cancel_restore(), RestoreCancel::Running);
        assert!(!state.cancel_export(), "not an export");
        go_tx.send(())?;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(30), running).await??,
            (true, false),
            "(the store call began, the job was cancelled)"
        );

        // Before the store call: the cancel wins and the call never begins.
        let until = Instant::now() + Duration::from_secs(30);
        let (waiting_tx, waiting) = std::sync::mpsc::channel::<()>();
        let waiting_job = loop {
            let tx = waiting_tx.clone();
            match state.spawn_restore_job(move |cancel, call| {
                let _ = tx.send(());
                let until = std::time::Instant::now() + Duration::from_secs(30);
                while !call.cancelled() && std::time::Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(5));
                }
                (call.begin(), cancel.load(Ordering::SeqCst))
            }) {
                Err(JobRefused::Busy) if Instant::now() < until => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                other => break other.map_err(|e| format!("{e:?}"))?,
            }
        };
        waiting.recv_timeout(Duration::from_secs(30))?;
        assert_eq!(state.cancel_restore(), RestoreCancel::Cancelled(true));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(30), waiting_job).await??,
            (false, true)
        );
        Ok(())
    }

    /// The answer of a paused restore job, a receiver that hears when it reached its pause, and a
    /// flag the job sets as its last step.
    type PausedRestore = (
        tokio::sync::oneshot::Receiver<Result<RestoreReport, CommandError>>,
        std::sync::mpsc::Receiver<()>,
        Arc<AtomicBool>,
    );

    /// A Settings restore of the bundle `source` into `rig`'s store as the audit job (answers:
    /// "Restore backup", then the rollback when the bundle is `rig`'s own), held at `point`
    /// (bounded, 30 s) until the job's cancel flag is set, then failing there as the process
    /// ending at that point would.
    fn paused_restore(
        state: &ServeState,
        rig: &Rig,
        source: std::path::PathBuf,
        point: atlas_duck_audit::testing::FaultPoint,
    ) -> Result<PausedRestore, Box<dyn std::error::Error>> {
        let flag: Arc<OnceLock<Arc<AtomicBool>>> = Arc::new(OnceLock::new());
        let (reached_tx, reached) = std::sync::mpsc::channel();
        let first = Arc::new(AtomicBool::new(true));
        {
            let flag = flag.clone();
            rig.faults.on_hit(point, move || {
                if !first.swap(false, Ordering::SeqCst) {
                    return;
                }
                let _ = reached_tx.send(());
                let until = std::time::Instant::now() + Duration::from_secs(30);
                while std::time::Instant::now() < until
                    && !flag.get().is_some_and(|c| c.load(Ordering::SeqCst))
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                // A quit path that does not wait finds the job still running.
                std::thread::sleep(Duration::from_millis(50));
            });
        }
        rig.faults.fail(point, 1);
        let store = rig.store.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let ended = finished.clone();
        let rx = state
            .spawn_restore_job(move |cancel, call| {
                let _ = flag.set(cancel.clone());
                let answer = crate::restore_flow::run_live_restore(
                    &store,
                    &Answers::new(&[Confirm::Ok, Confirm::Ok]),
                    || Some(chosen(&source)),
                    |_| Ok(SecretString::from(PASS.to_owned())),
                    &call,
                    &cancel,
                    &Events::default(),
                );
                ended.store(true, Ordering::SeqCst);
                answer
            })
            .map_err(|e| format!("{e:?}"))?;
        Ok((rx, reached, finished))
    }

    /// PD-181 (§8.7, §8.11 step 5; T13 Step 0): Quit while a Settings restore runs its store call
    /// waits for it (the job has ended when the core stage starts), then the process ends. Where
    /// the process ended decides the next start: before the commit rename the live store is as it
    /// was (no `RESTORE`, no staging file); after the KEK re-seal (or, for a backup of this store,
    /// whose KEK the keychain already holds, right after the commit) `open` completes the restore
    /// (interrupted restore reconciled, no incident); between the commit and the re-seal of
    /// another store's backup it offers "Finish restore" (the backup's passphrase), which
    /// completes it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quit_during_restore_completes_or_reconciles() -> Result<(), Box<dyn std::error::Error>>
    {
        use atlas_duck_audit::testing::FaultPoint;
        use atlas_duck_audit::{EventType, FindingKind};

        for point in [
            FaultPoint::RestoreBarrierHeld,
            FaultPoint::AfterKekReseal,
            FaultPoint::AfterRestoreCommit,
        ] {
            let rig = rig(3)?;
            // Another store's backup (another KEK) where the re-seal matters.
            let other = crate::commands::audit::tests::rig(2)?;
            let source = if point == FaultPoint::AfterRestoreCommit {
                other.store.backup(chosen(&other.out))?.bundle_dir
            } else {
                rig.store.backup(chosen(&rig.out))?.bundle_dir
            };
            let state = serving_store(&rig);
            let before = rig.store.head();
            let (rx, reached, finished) = paused_restore(&state, &rig, source, point)?;
            reached.recv_timeout(Duration::from_secs(30))?;

            let at_core_stage: OnceLock<bool> = OnceLock::new();
            let started = Instant::now();
            let outcome = shutdown_with(&state, started + Duration::from_secs(60), |_| {
                let _ = at_core_stage.set(finished.load(Ordering::SeqCst));
                Some(std::future::ready(ShutdownReport::default()))
            })
            .await;
            assert_eq!(at_core_stage.get(), Some(&true), "{point:?}: job ended");
            assert_eq!(outcome.report, Some(ShutdownReport::default()));
            let answer = tokio::time::timeout(Duration::from_secs(30), rx).await??;
            assert!(lock(&state.store).is_none(), "store shut down");
            assert!(
                !rig.data.path().join("audit.db.restoring").exists(),
                "{point:?}: no staging file"
            );

            let cfg =
                crate::commands::audit::tests::config(&rig.ring, &rig.install_id, &rig.faults);
            match point {
                FaultPoint::RestoreBarrierHeld => {
                    assert!(
                        matches!(answer, Err(CommandError::Restore(_))),
                        "{answer:?}"
                    );
                    let StartupOutcome::Ready { store, .. } =
                        atlas_duck_audit::open(&rig.data, &rig.lock, cfg)?
                    else {
                        return Err("the store did not open again".into());
                    };
                    assert_eq!(count(&store, EventType::RESTORE)?, 0);
                    assert_eq!(store.head().2, before.2, "the same chain");
                    assert!(store.open_incidents().is_empty());
                    store.shutdown();
                }
                FaultPoint::AfterKekReseal => {
                    assert_eq!(
                        answer,
                        Err(CommandError::Restore(
                            crate::commands::RestoreFailure::CommittedIncomplete
                        ))
                    );
                    let StartupOutcome::Ready { store, verify, .. } =
                        atlas_duck_audit::open(&rig.data, &rig.lock, cfg)?
                    else {
                        return Err("the restore was not completed at the next start".into());
                    };
                    let kinds: Vec<FindingKind> = verify.findings.iter().map(|f| f.kind).collect();
                    assert_eq!(kinds, [FindingKind::InterruptedRestoreReconciled]);
                    assert_ne!(store.head().2, before.2, "the restored chain");
                    assert_eq!(count(&store, EventType::RESTORE)?, 1);
                    assert!(store.open_incidents().is_empty());
                    store.shutdown();
                }
                _ => {
                    assert_eq!(
                        answer,
                        Err(CommandError::Restore(
                            crate::commands::RestoreFailure::CommittedIncomplete
                        ))
                    );
                    match atlas_duck_audit::open(&rig.data, &rig.lock, cfg)? {
                        StartupOutcome::Locked(LockedReason::KeychainLost {
                            offer: RecoveryOffer::FinishRestore,
                        }) => {}
                        other => return Err(format!("expected Finish restore: {other:?}").into()),
                    }
                    let cfg = crate::commands::audit::tests::config(
                        &rig.ring,
                        &rig.install_id,
                        &rig.faults,
                    );
                    let (store, _, _) = atlas_duck_audit::finish_restore(
                        &rig.data,
                        &rig.lock,
                        cfg,
                        &SecretString::from(PASS.to_owned()),
                    )?;
                    assert_ne!(store.head().2, before.2, "the restored chain");
                    assert!(store.open_incidents().is_empty());
                    store.shutdown();
                }
            }
        }
        Ok(())
    }

    /// Answers Ok to the "Restore backup" dialog; holds the rollback dialog up (bounded, 30 s)
    /// until the job's cancel flag is set, then answers Ok, as a user who clicks Ok after a Quit
    /// or a cancel would. `up` hears when the rollback dialog is shown.
    struct HeldRollback {
        flag: Arc<OnceLock<Arc<AtomicBool>>>,
        up: Mutex<std::sync::mpsc::Sender<()>>,
    }

    impl NativeConfirmer for HeldRollback {
        fn confirm(&self, text: &str) -> Confirm {
            if text == crate::restore_flow::RESTORE_CONFIRM_TEXT {
                return Confirm::Ok;
            }
            if let Ok(up) = self.up.lock() {
                let _ = up.send(());
            }
            let until = std::time::Instant::now() + Duration::from_secs(30);
            while std::time::Instant::now() < until
                && !self.flag.get().is_some_and(|c| c.load(Ordering::SeqCst))
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Confirm::Ok
        }
    }

    /// A Settings restore of `rig`'s own bundle (a same-machine rollback) as the audit job, held
    /// in its rollback dialog (see [`HeldRollback`]); the receiver hears when the dialog is up.
    fn held_rollback(
        state: &ServeState,
        rig: &Rig,
    ) -> Result<PausedRestore, Box<dyn std::error::Error>> {
        let source = rig.store.backup(chosen(&rig.out))?.bundle_dir;
        let flag: Arc<OnceLock<Arc<AtomicBool>>> = Arc::new(OnceLock::new());
        let (up_tx, up) = std::sync::mpsc::channel();
        let confirmer = HeldRollback {
            flag: flag.clone(),
            up: Mutex::new(up_tx),
        };
        let store = rig.store.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let ended = finished.clone();
        let rx = state
            .spawn_restore_job(move |cancel, call| {
                let _ = flag.set(cancel.clone());
                let answer = crate::restore_flow::run_live_restore(
                    &store,
                    &confirmer,
                    || Some(chosen(&source)),
                    |_| Ok(SecretString::from(PASS.to_owned())),
                    &call,
                    &cancel,
                    &Events::default(),
                );
                ended.store(true, Ordering::SeqCst);
                answer
            })
            .map_err(|e| format!("{e:?}"))?;
        Ok((rx, up, finished))
    }

    /// T13 review I-1 (PD-181): while a Settings restore's rollback dialog is up (its first store
    /// call changed nothing) `restore_cancel` cancels it (`Cancelled(true)`, not `Running`), and
    /// the dialog's later Ok calls the store no more.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restore_cancel_in_the_rollback_dialog_cancels()
    -> Result<(), Box<dyn std::error::Error>> {
        let rig = rig(3)?;
        let state = serving_store(&rig);
        let (rx, up, _) = held_rollback(&state, &rig)?;
        up.recv_timeout(Duration::from_secs(30))?;
        let before = rig.store.head();
        assert_eq!(state.cancel_restore(), RestoreCancel::Cancelled(true));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(30), rx).await??,
            Err(CommandError::Cancelled)
        );
        assert_eq!(rig.store.head(), before);
        assert_eq!(count(&rig.store, atlas_duck_audit::EventType::RESTORE)?, 0);
        Ok(())
    }

    /// T13 review I-1 (PD-181, L202): Quit while the rollback dialog is up cancels the restore
    /// (the call cancelled, the job's flag set); the dialog's Ok then calls the store no more, so
    /// the job has ended without a restore when the core stage starts, and the next start opens
    /// the same chain with no `RESTORE`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quit_in_the_rollback_dialog_restores_nothing() -> Result<(), Box<dyn std::error::Error>>
    {
        let rig = rig(3)?;
        let state = serving_store(&rig);
        let (rx, up, finished) = held_rollback(&state, &rig)?;
        up.recv_timeout(Duration::from_secs(30))?;
        let chain = rig.store.head().2;
        let at_core_stage: OnceLock<bool> = OnceLock::new();
        let started = Instant::now();
        let outcome = shutdown_with(&state, started + Duration::from_secs(60), |_| {
            let _ = at_core_stage.set(finished.load(Ordering::SeqCst));
            Some(std::future::ready(ShutdownReport::default()))
        })
        .await;
        assert_eq!(at_core_stage.get(), Some(&true), "job ended");
        assert_eq!(outcome.report, Some(ShutdownReport::default()));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(30), rx).await??,
            Err(CommandError::Cancelled)
        );
        assert!(lock(&state.store).is_none(), "store shut down");
        let cfg = crate::commands::audit::tests::config(&rig.ring, &rig.install_id, &rig.faults);
        let StartupOutcome::Ready { store, .. } =
            atlas_duck_audit::open(&rig.data, &rig.lock, cfg)?
        else {
            return Err("the store did not open again".into());
        };
        assert_eq!(count(&store, atlas_duck_audit::EventType::RESTORE)?, 0);
        assert_eq!(store.head().2, chain, "the same chain");
        store.shutdown();
        Ok(())
    }

    struct NoConfirm;
    impl NativeConfirmer for NoConfirm {
        fn confirm(&self, _: &str) -> Confirm {
            Confirm::Cancel
        }
    }

    type StoreParts = (Store, Arc<dyn KeyStore>, InstanceLock);

    /// A first-run store in `dir` (a fresh data dir), with its keys and instance lock.
    fn first_run_store(dir: &std::path::Path) -> Result<StoreParts, Box<dyn std::error::Error>> {
        use atlas_duck_audit::testing::{FreeSpaceStub, MemKeyStore, MemKeyring};
        use atlas_duck_audit::{create_new_store, new_ids};
        use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};

        let dir = dir.join("data");
        std::fs::create_dir(&dir)?;
        let DataDirResolution::Local(data) = check_data_dir(&dir)? else {
            return Err("the temp dir is not a local data dir".into());
        };
        let lock = InstanceLock::acquire(&data, "thishost")?;
        let (install_id, chain_id) = new_ids()?;
        let keys: Arc<dyn KeyStore> = Arc::new(MemKeyStore::new(MemKeyring::new(), &install_id));
        let mut cfg = OpenConfig::new(Arc::new(SystemClock::new()), keys.clone());
        cfg.free_space = Some(FreeSpaceStub::new(u64::MAX));
        let pass = "correct horse battery";
        let store = create_new_store(
            &data,
            &lock,
            cfg,
            FirstRunInput {
                install_id,
                chain_id,
                passphrase: SecretString::from(pass.to_owned()),
                passphrase_confirm: SecretString::from(pass.to_owned()),
                archived_db: None,
                anchor_dir: None,
                archive_confirmed: None,
            },
        )?;
        Ok((store, keys, lock))
    }

    /// The `confinement` key of the newest `APP_START` record in `store`.
    fn app_start_confinement_in(
        store: &Store,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        use atlas_duck_audit::EventType;

        let mut headers = store.recent_headers(Duration::from_secs(3600))?;
        headers.sort_by_key(|h| h.seq);
        let start = headers
            .iter()
            .rev()
            .find(|h| h.event_type == EventType::APP_START)
            .ok_or("no APP_START record")?;
        let payload: serde_json::Value = serde_json::from_slice(&store.read_payload(start.seq)?)?;
        Ok(payload["confinement"].clone())
    }

    fn met_report() -> atlas_duck_sandbox_host::probe::ProbeReport {
        atlas_duck_sandbox_host::probe::ProbeReport {
            worker_version: None,
            engine_version: None,
            identity: None,
            confinement: None,
            threads: None,
            records: Vec::new(),
            floor: atlas_duck_sandbox_host::probe::FloorVerdict::Met,
            extra_layers: Vec::new(),
            control: None,
            lpac_failed: None,
        }
    }

    /// R1 (PD-138), the lifecycle step: `Core::start` appends `APP_START`, so the starter awaits the
    /// probe report before it, counted from the probe's start. A report that lands while the core
    /// starts is in the record; one that is still missing when the 5 s (from the probe's start) are
    /// over leaves `{state: "pending"}` and the core starts all the same.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn core_start_awaits_the_probe_report_before_app_start()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let bound = Duration::from_secs(120);
        let starter_for = |probe: &Arc<crate::sandbox_probe::ProbeHolder>,
                           root: &std::path::Path| CoreStarter {
            config_dir: root.to_owned(),
            ui: Arc::new(NoUi),
            confirmer: Arc::new(NoConfirm),
            tray_host: None,
            scripts: ScriptInputs {
                probe: probe.clone(),
                ..ScriptInputs::default()
            },
            fail_next: None,
        };

        // The report lands once the starter is parked on it (no wall-clock delay): a starter that
        // never waits leaves the setter spinning and `APP_START` `pending`.
        let root = tmp.path().join("ready");
        std::fs::create_dir(&root)?;
        let (store, keys, _lock) = first_run_store(&root)?;
        let probe = Arc::new(crate::sandbox_probe::ProbeHolder::default());
        probe.mark_started(std::time::Instant::now());
        let late = probe.clone();
        let setting = tokio::spawn(async move {
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            while late.waiters() == 0 && std::time::Instant::now() < deadline {
                tokio::task::yield_now().await;
            }
            late.set(met_report())
        });
        let core = tokio::time::timeout(
            bound,
            starter_for(&probe, &root).start(store.clone(), keys, Vec::new()),
        )
        .await?
        .map_err(|_| "the core did not start")?;
        let confinement = app_start_confinement_in(&store)?;
        assert_eq!(
            confinement["floor"],
            serde_json::json!("met"),
            "{confinement}"
        );
        assert!(setting.await?);
        let _ = abandon(Some(core), Some(store)).await;

        // The probe started 4 s ago (the store is ready, so the start is measured from here) and
        // never reports: the starter does wait for the 1 s that are left (seen as a waiter parked
        // on the holder), and the core starts without a report when they are over.
        let root = tmp.path().join("pending");
        std::fs::create_dir(&root)?;
        let (store, keys, _lock) = first_run_store(&root)?;
        let probe = Arc::new(crate::sandbox_probe::ProbeHolder::default());
        let Some(started) = std::time::Instant::now().checked_sub(Duration::from_secs(4)) else {
            return Ok(());
        };
        probe.mark_started(started);
        let parked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (spy_probe, spy_flag) = (probe.clone(), parked.clone());
        let spy = tokio::spawn(async move {
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            while std::time::Instant::now() < deadline {
                if spy_probe.waiters() > 0 {
                    spy_flag.store(true, Ordering::SeqCst);
                    return;
                }
                tokio::task::yield_now().await;
            }
        });
        let core = tokio::time::timeout(
            bound,
            starter_for(&probe, &root).start(store.clone(), keys, Vec::new()),
        )
        .await?
        .map_err(|_| "the core did not start without a probe report")?;
        spy.abort();
        assert!(
            parked.load(Ordering::SeqCst),
            "the starter did not wait for the probe"
        );
        assert_eq!(
            app_start_confinement_in(&store)?,
            serde_json::json!({"state": "pending"})
        );
        let _ = abandon(Some(core), Some(store)).await;
        Ok(())
    }

    #[tokio::test]
    async fn bounded_waits_at_most_d_and_never_past_the_deadline() {
        let now = Instant::now();
        let far = now + Duration::from_secs(30);
        assert!(bounded(async {}, Duration::from_secs(5), far, "x").await);
        let slow = || tokio::time::sleep(Duration::from_secs(30));
        assert!(!bounded(slow(), Duration::from_millis(50), far, "x").await);
        // The deadline wins over a longer `d`.
        let t = Instant::now();
        let early = t + Duration::from_millis(50);
        assert!(!bounded(slow(), Duration::from_secs(30), early, "x").await);
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    /// The freeze wakes a retry loop that sleeps (it would otherwise sleep until the server's
    /// shutdown signal, which fires at the very end of the quit path).
    #[test]
    fn freeze_cancels_the_retry_stop_signal() {
        let state = gate_serving(GateState::Locked(LockedReason::KeychainUnavailable));
        assert!(!state.retry_stop.0.is_cancelled());
        state.freeze();
        assert!(state.retry_stop.0.is_cancelled());
        let state = gate_serving(GateState::Locked(LockedReason::KeychainUnavailable));
        state.freeze_for_shutdown();
        assert!(state.retry_stop.0.is_cancelled());
    }

    /// Counts what the watcher is told.
    #[derive(Default)]
    struct Told(AtomicU32);

    impl ServeWatcher for Told {
        fn serving_changed(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Told {
        fn count(&self) -> u32 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn watched(told: &Arc<Told>) -> ServeHooks {
        ServeHooks {
            watcher: Some(told.clone()),
            ..ServeHooks::default()
        }
    }

    #[test]
    fn keychain_prompt_hint_after_10s() {
        let t0 = Instant::now();
        assert_eq!(KEYCHAIN_PROMPT_AFTER, Duration::from_secs(10));
        assert!(!keychain_prompt_hint(t0, t0));
        assert!(!keychain_prompt_hint(t0, t0 + Duration::from_millis(9_999)));
        assert!(keychain_prompt_hint(t0, t0 + Duration::from_secs(10)));
        assert!(keychain_prompt_hint(t0, t0 + Duration::from_secs(600)));
        // An `open` that started after `now` has not waited at all.
        assert!(!keychain_prompt_hint(t0 + Duration::from_secs(60), t0));
    }

    /// L78: the hint is up only while an `open` blocks past the limit, and the watcher hears of
    /// it going up and going down; an `open` that returns in time tells nobody.
    #[tokio::test]
    async fn the_prompt_hint_is_up_only_while_open_blocks_past_the_limit() {
        // Real time (the runtime has no paused clock): the limit is shortened through the hooks.
        let told = Arc::new(Told::default());
        let hooks = ServeHooks {
            keychain_prompt_after: Duration::from_millis(300),
            keychain_prompt_enabled: true,
            ..watched(&told)
        };
        let flag = hooks.keychain_prompt.clone();
        let quick = with_prompt_hint(
            async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                1
            },
            &hooks,
        )
        .await;
        assert_eq!(quick, 1);
        assert!(!flag.load(Ordering::SeqCst));
        assert_eq!(told.count(), 0);

        let slow_hooks = hooks.clone();
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let slow = tokio::spawn(async move {
            with_prompt_hint(
                async {
                    let _ = released.await;
                    2
                },
                &slow_hooks,
            )
            .await
        });
        let started = Instant::now();
        while !flag.load(Ordering::SeqCst) {
            assert!(started.elapsed() < Duration::from_secs(20), "never came up");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "not before the limit"
        );
        assert_eq!(told.count(), 1);
        assert!(release.send(()).is_ok());
        assert_eq!(slow.await.ok(), Some(2));
        assert!(!flag.load(Ordering::SeqCst));
        assert_eq!(told.count(), 2);
    }

    /// L78: Windows' Credential Manager shows no authorization prompt, so there the hint is never
    /// raised, however long `open` blocks; the production default follows the platform.
    #[tokio::test]
    async fn no_prompt_hint_where_the_platform_has_no_keychain_prompt() {
        assert_eq!(PLATFORM_HAS_KEYCHAIN_PROMPT, cfg!(not(windows)));
        assert_eq!(
            ServeHooks::default().keychain_prompt_enabled,
            PLATFORM_HAS_KEYCHAIN_PROMPT
        );
        let told = Arc::new(Told::default());
        let hooks = ServeHooks {
            keychain_prompt_after: Duration::from_millis(20),
            keychain_prompt_enabled: false,
            ..watched(&told)
        };
        let seen = Arc::new(AtomicBool::new(false));
        let (flag, probe) = (hooks.keychain_prompt.clone(), seen.clone());
        let out = with_prompt_hint(
            async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                probe.store(flag.load(Ordering::SeqCst), Ordering::SeqCst);
                3
            },
            &hooks,
        )
        .await;
        assert_eq!(out, 3);
        assert!(!seen.load(Ordering::SeqCst), "no hint while blocked");
        assert_eq!(told.count(), 0);
    }

    /// The watcher (tray, credential window) hears every swap and a failed store, and nothing
    /// after the freeze; a failed store offers no unlock or archive.
    #[test]
    fn the_watcher_hears_swaps_and_a_failed_store() {
        let told = Arc::new(Told::default());
        let state = gate_serving_with(
            GateState::Locked(LockedReason::KeychainLost {
                offer: RecoveryOffer::RecoverThisLog,
            }),
            watched(&told),
        );
        assert_eq!(state.keychain_lost(), Some(RecoveryOffer::RecoverThisLog));
        assert!(state.install_gate(GateState::StoreNewer));
        assert_eq!(told.count(), 1);
        assert!(
            state.install_gate(GateState::Locked(LockedReason::KeychainLost {
                offer: RecoveryOffer::RecoverThisLog
            }))
        );
        assert_eq!(told.count(), 2);
        assert!(!state.store_failed());
        state.mark_store_failed();
        assert_eq!(told.count(), 3);
        assert!(state.store_failed());
        assert_eq!(state.keychain_lost(), None, "nothing to unlock or archive");
        // The failed store is permanent in the cell: no other gate replaces it.
        assert!(!state.install_gate(GateState::FirstRun));
        assert!(!state.install_gate(GateState::Locked(LockedReason::KeychainUnavailable)));
        assert_eq!(state.gate_state(), Some(GateState::StoreFailed));
        assert_eq!(told.count(), 3, "a refused swap is not a change");
        state.freeze();
        assert!(!state.install_gate(GateState::FirstRun));
        assert_eq!(told.count(), 3, "a refused swap is not a change");
    }

    #[test]
    fn no_keystore_refuses_everything() {
        let k = NoKeyStore;
        assert!(k.get(&EntryName::Kek).is_err());
        assert!(k.set(&EntryName::Kek, b"x").is_err());
        assert!(k.delete(&EntryName::Kek).is_err());
        assert!(matches!(k.locality(), KeyringLocality::Unknown { .. }));
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Capture {
            self.clone()
        }
    }

    /// T33 review I-4: `app_stop` passes the allowlist with its reason and nothing else, and only
    /// an orderly shutdown logs it (negative controls: no core, timed out, append failed).
    #[test]
    fn app_stop_is_logged_only_after_an_orderly_shutdown() {
        let report = |app_stop_logged| ShutdownReport {
            cancelled: 0,
            writes_waited: 0,
            app_stop_logged,
        };
        let run = |outcome: ShutdownOutcome, reason| {
            crate::diag::fields::extend_allowed(LOG_FIELDS);
            let cap = Capture::default();
            let subscriber =
                Registry::default().with(crate::diag::fields::allowlist_layer(cap.clone()));
            tracing::subscriber::with_default(subscriber, || log_app_stop(&outcome, reason));
            String::from_utf8(cap.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
                .unwrap_or_default()
        };
        for (reason, word) in [
            (ShutdownReason::Quit, "quit"),
            (ShutdownReason::OsShutdown, "os_shutdown"),
            (ShutdownReason::Installer, "installer"),
        ] {
            let out = run(
                ShutdownOutcome {
                    report: Some(report(true)),
                    timed_out: false,
                },
                reason,
            );
            assert_eq!(out.lines().count(), 1, "{out}");
            assert!(
                out.contains(&format!("event=app_stop reason={word} dropped_fields=0")),
                "{out}"
            );
        }
        for outcome in [
            ShutdownOutcome {
                report: None,
                timed_out: false,
            },
            ShutdownOutcome {
                report: None,
                timed_out: true,
            },
            ShutdownOutcome {
                report: Some(report(false)),
                timed_out: false,
            },
            ShutdownOutcome {
                report: Some(report(true)),
                timed_out: true,
            },
        ] {
            let out = run(outcome, ShutdownReason::Quit);
            assert!(out.is_empty(), "{outcome:?}: {out}");
        }
    }

    /// The ipc server's PD-29 events reach the diagnostic log with their `event`, `reason`,
    /// `connection_id` and `peer_pid` (the message is never written), and so do this module's.
    #[test]
    fn ipc_and_serve_events_pass_the_diag_allowlist() {
        crate::diag::fields::extend_allowed(LOG_FIELDS);
        let cap = Capture::default();
        let subscriber =
            Registry::default().with(crate::diag::fields::allowlist_layer(cap.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(
                target: "atlas_duck_ipc::server",
                event = diag::EVENT_BIND_FAILED,
                reason = diag::REASON_STOPPED_ACCEPTING,
                "ipc server stopped accepting"
            );
            for reason in [
                diag::REASON_BIND,
                diag::REASON_TEMP_SWEEP,
                diag::REASON_ENDPOINT_REMOVE,
                diag::REASON_REBIND,
            ] {
                tracing::error!(
                    target: "atlas_duck_ipc::server",
                    event = diag::EVENT_BIND_FAILED,
                    reason,
                    "ipc bind failed"
                );
            }
            tracing::warn!(
                target: "atlas_duck_ipc::server",
                event = diag::EVENT_ACCEPT_FAILED,
                "ipc accept failed"
            );
            tracing::error!(
                target: "atlas_duck_ipc::server",
                event = diag::EVENT_REJECT,
                peer_pid = 42u32,
                reason = diag::REASON_INTERNAL,
                "ipc connection id unavailable"
            );
            tracing::warn!(
                target: "atlas_duck_ipc::server",
                event = diag::EVENT_PROTOCOL_ERROR,
                connection_id = "conn_00ff",
                peer_pid = 42u32,
                reason = "hello_timeout",
                "ipc protocol error"
            );
            StoreFailure::CoreStart.log();
            tracing::info!(
                event = LOG_EVENT_KEYCHAIN_RETRY,
                attempt = 2usize,
                serve_state = "locked",
                reason = "keychain_unavailable"
            );
        });
        let out = String::from_utf8(cap.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_default();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 10, "{out}");
        assert!(
            lines[0].contains("event=ipc_bind_failed reason=stopped_accepting dropped_fields=1"),
            "{out}"
        );
        for (line, reason) in
            lines[1..5]
                .iter()
                .zip(["bind", "temp_sweep", "endpoint_remove", "rebind"])
        {
            assert!(
                line.contains(&format!(
                    "event=ipc_bind_failed reason={reason} dropped_fields=1"
                )),
                "{line}"
            );
        }
        assert!(
            lines[5].contains("event=ipc_accept_failed dropped_fields=1"),
            "{out}"
        );
        assert!(
            lines[6].contains("event=ipc_reject peer_pid=42 reason=internal dropped_fields=1"),
            "{out}"
        );
        assert!(
            lines[7].contains(
                "event=ipc_protocol_error connection_id=conn_00ff peer_pid=42 reason=hello_timeout dropped_fields=1"
            ),
            "{out}"
        );
        assert!(
            lines[8].contains("event=store_open_failed error_class=core_start dropped_fields=0"),
            "{out}"
        );
        assert!(
            lines[9].contains(
                "event=keychain_retry attempt=2 serve_state=locked reason=keychain_unavailable dropped_fields=0"
            ),
            "{out}"
        );
        assert!(
            !out.contains("stopped accepting"),
            "the message is never written: {out}"
        );
    }
}
