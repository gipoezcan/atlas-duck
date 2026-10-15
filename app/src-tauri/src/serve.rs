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
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::{
    ArchivedDb, Confirmed, DB_FILE, EntryName, KeyStore, KeyStoreError, KeyringLocality,
    LockedReason, OpenConfig, OpenError, OsKeyStore, RecoveryOffer, StartupOutcome, Store,
    SystemClock, keychain_retry_schedule, read_store_install_id,
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
use crate::secret_service::{CachedSecretService, SecretServiceCheck};
use crate::state::ServeSlot;
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
/// The quit path stopped waiting for a step; `reason` = `start|retry|unlock|core|served|store`.
pub const LOG_EVENT_QUIT_WAIT_EXPIRED: &str = "quit_wait_expired";
/// M6 T20: an unlock, archive or manual retry from the credential window did nothing;
/// `error_class` = [`UnlockFailure::class`]. Never a passphrase, a path or an error text.
pub const LOG_EVENT_UNLOCK_FAILED: &str = "credential_unlock_failed";
/// `Core::shutdown` ended without a report (its task panicked).
pub const LOG_EVENT_QUIT_CORE_LOST: &str = "quit_core_lost";

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
/// freeze. Then the core's shutdown, `shutdown.cancel()`, `served` (<= 2 s) and
/// `Store::shutdown` on a blocking thread.
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
    /// One unlock or archive at a time (M6 T20).
    unlocking: tokio::sync::Mutex<()>,
    /// The task of an unlock or archive in flight: the quit path awaits it with a bound, like the
    /// keychain retry, and never aborts it (it owns the store it opens).
    unlock_task: Mutex<Option<JoinHandle<()>>>,
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
            unlocking: tokio::sync::Mutex::new(()),
            unlock_task: Mutex::new(None),
        }
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
        lock(&self.retry).as_ref().is_some_and(|h| !h.is_finished())
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
        true
    }

    /// Serves the gate in `state` from the next request on. False after the freeze, the shutdown
    /// signal, or once `Core` serves.
    fn install_gate(&self, state: GateState) -> bool {
        let frozen = lock(&self.frozen);
        if !self.swaps_allowed(*frozen) || self.core.get().is_some() {
            return false;
        }
        let gate = GateHandler::new(state, self.ui.clone());
        self.cell.swap(self.handler_for(gate.clone()));
        *lock(&self.gate) = Some(gate);
        drop(frozen);
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
        if self.core.get().is_some() {
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
        }
    }

    fn of(e: &OpenError) -> UnlockFailure {
        match e {
            OpenError::WrongPassphrase => UnlockFailure::WrongPassphrase,
            OpenError::KeyStore(KeyStoreError::NotLocal) => UnlockFailure::KeyringNotLocal,
            OpenError::KeyStore(_) => UnlockFailure::KeychainUnavailable,
            OpenError::NewerStore(_) => UnlockFailure::StoreNewer,
            OpenError::Integrity(_) | OpenError::Restore(_) => UnlockFailure::Integrity,
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
    let Ok(_one) = state.unlocking.try_lock() else {
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
    let Ok(_one) = state.unlocking.try_lock() else {
        return failed(UnlockFailure::Busy);
    };
    if state.keychain_lost().is_none() {
        return failed(UnlockFailure::NotLocked);
    }
    let text = archive_confirm_text(&restart.opener.data);
    let confirmer = restart.starter.confirmer.clone();
    // The dialog blocks until the user answers: never on the async runtime or the main thread.
    let shown = text.clone();
    let answer = tokio::task::spawn_blocking(move || confirmer.confirm(&shown))
        .await
        .unwrap_or(Confirm::Cancel);
    if answer != Confirm::Ok {
        return failed(UnlockFailure::Cancelled);
    }
    let confirmed = confirmed_by(&text);
    let (st, opener) = (state.clone(), restart.opener.clone());
    let done = state.spawn_unlock_work(async move {
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

/// The audit store's proof of a native confirmation: the SHA-256 of the dialog text.
fn confirmed_by(text: &str) -> Confirmed {
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
        || state.gate_state() != Some(GateState::Locked(LockedReason::KeychainUnavailable))
    {
        return RetryNow::NotLocked;
    }
    let mut retry = lock(&state.retry);
    if retry.as_ref().is_some_and(|h| !h.is_finished()) {
        return RetryNow::AlreadyRunning;
    }
    *retry = Some(tokio::spawn(retry_keychain(
        state.clone(),
        restart.opener.clone(),
        restart.starter.clone(),
        vec![Duration::ZERO],
    )));
    drop(retry);
    drop(frozen);
    RetryNow::Started
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
            match slot.get() {
                Some(state) => shutdown_until(state, reason, deadline).await,
                None => ShutdownOutcome {
                    report: None,
                    timed_out: false,
                },
            }
        })
        .await
}

/// Every Quit (tray, the `quit` command, the error windows): [`quit`] with [`SHUTDOWN_OUTER`] on
/// the async runtime (the menu handler runs on the main thread and must not block), then
/// `app.exit(0)`. Without a [`ServeSlot`] (no store is served in this startup state) it exits at
/// once.
pub fn shutdown_then_exit<R: Runtime>(app: &AppHandle<R>, reason: ShutdownReason) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(slot) = handle.try_state::<ServeSlot>() {
            quit(&slot, reason, SHUTDOWN_OUTER).await;
        }
        handle.exit(0);
    });
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
    });

    // Steps 1–4: stale endpoint file, install id, keystore, `open`.
    let first = opener.clone().first_open().await;
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
    let state = Arc::new(ServeState::new(initial, gate, store, extras, i.ui.clone()));
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
        let task = tokio::spawn(retry_keychain(
            state.clone(),
            opener,
            starter,
            i.retry_schedule,
        ));
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
        let inputs = CoreInputs {
            store: store.clone(),
            keys,
            config_dir: self.config_dir.clone(),
            pats_deleted,
            ui: self.ui.clone(),
            confirmer: self.confirmer.clone(),
            tray_host: self.tray_host,
        };
        match compose::start_core(inputs).await {
            Ok(core) => {
                let core = Arc::new(core);
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
/// (`Err`, or `Core::start` refusing) is logged and keeps the locked gate (the endpoint is
/// already bound, PD-06 cannot apply). After the schedule the app stays locked (manual retry is
/// M6). Ends early on the shutdown signal and after [`ServeState::freeze`].
async fn retry_keychain(
    state: Arc<ServeState>,
    opener: Arc<Opener>,
    starter: Arc<CoreStarter>,
    schedule: Vec<Duration>,
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
        let (outcome, keys) = match opener.clone().retry_open().await {
            Ok(opened) => opened,
            Err(f) => {
                f.log();
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
    tracing::warn!(event = LOG_EVENT_KEYCHAIN_RETRY_EXHAUSTED);
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
        let ui: Arc<dyn UiSink> = Arc::new(NoUi);
        let gate = GateHandler::new(gs, ui.clone());
        let extras = Arc::new(DoctorExtras {
            tray_host: None,
            secret_service: Arc::new(NoCheck),
            data: None,
        });
        ServeState::new(gate.clone(), Some(gate), None, extras, ui)
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
        let state = ServeState::new(gate.clone(), Some(gate), Some(store), extras, ui);
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
