//! App-wide state managed by Tauri (`app.manage`). Later milestones read it and add fields.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};

use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_core::StoreHealthView;
use atlas_duck_ipc::paths::LocalDataDir;
use atlas_duck_ipc::server::ShutdownSignal;
use atlas_duck_sandbox_host::probe::{FloorVerdict, ProbeReport};
use tauri::async_runtime::JoinHandle;

use crate::i18n::{self, Lang, LangPref};
use crate::sandbox_probe::{ProbeHolder, canonical_worker};
use crate::script_glue::{InstanceSource, ScriptInputs, StatusPing};
use crate::serve::{ServeState, ShutdownOutcome};
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
    /// The §9.4 probe report; set once by the `atlas-duck-probe` thread. Shared with the script
    /// glue, which awaits it before its first spawn (M8 Task 20, PD-138). It records the canonical
    /// worker's identity itself when no probe worker reached ready (M8 T20 ruling).
    pub probe: Arc<ProbeHolder>,
    /// PD-133: the script glue found the sandbox binary replaced since the probe (an upgrade
    /// under the running app): scripts stay refused until restart, and the status line
    /// `updated_restart` is due (`status::gather_app_state`).
    update_pending: Arc<AtomicBool>,
    /// The startup error text (`startup::startup_message`) of the four data-dir error states,
    /// re-shown on a GUI relaunch (§2.5, PD-85).
    startup_text: Option<String>,
    /// The pending count the tray shows ("Open approvals (N)", tooltip); Task 19 feeds it.
    pending: AtomicU32,
    /// The no-tray-host hint was shown (§2.5: dismissal is UI state, in memory, not audited).
    tray_hint_shown: AtomicBool,
    /// The last store-health snapshot the app read from the core (`StoreHealthView`: the very view
    /// Settings and the header's status lines are built from), for the tray: it is built on the main
    /// thread, which must not wait on the store. Filled by [`crate::status::note_health`] wherever
    /// the app reads the health; `None` while no core serves.
    health: Mutex<Option<StoreHealthView>>,
    /// Rebuilds the tray menu and tooltip; registered by `setup` once the tray exists (the status
    /// code is generic over the runtime, the tray is not).
    tray_refresh: OnceLock<TrayRefresh>,
    /// M15 T3 (PD-294): the folder of the `ui-lang` file (the pinned local data dir; `None`
    /// outside `Ready`, where nothing can be stored and the preference is `auto`).
    ui_lang_dir: Option<PathBuf>,
    /// The language preference and the language it resolved to.
    lang: RwLock<UiLang>,
}

/// The desktop language preference and its resolved language (`lang_changed`'s payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct UiLang {
    pub pref: LangPref,
    pub lang: Lang,
}

impl UiLang {
    /// `pref` resolved against the OS locale ([`i18n::os_locale`]).
    pub fn of(pref: LangPref) -> UiLang {
        UiLang {
            pref,
            lang: i18n::resolve(pref, i18n::os_locale().as_deref()),
        }
    }
}

/// What [`AppState::set_tray_refresh`] holds.
struct TrayRefresh(Box<dyn Fn() + Send + Sync>);

impl std::fmt::Debug for TrayRefresh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrayRefresh")
    }
}

impl AppState {
    pub fn new(startup: StartupSummary, tray_host: Option<TrayHost>) -> AppState {
        AppState {
            startup,
            tray_host,
            probe: Arc::new(ProbeHolder::for_worker(canonical_worker())),
            update_pending: Arc::default(),
            startup_text: None,
            pending: AtomicU32::new(0),
            tray_hint_shown: AtomicBool::new(false),
            health: Mutex::new(None),
            tray_refresh: OnceLock::new(),
            ui_lang_dir: None,
            lang: RwLock::new(UiLang::of(LangPref::Auto)),
        }
    }

    /// M15 T3: the `ui-lang` folder; the stored preference is read from it now.
    pub fn with_ui_lang_dir(mut self, dir: Option<PathBuf>) -> AppState {
        let pref = dir.as_deref().map(crate::ui_lang::load).unwrap_or_default();
        self.lang = RwLock::new(UiLang::of(pref));
        self.ui_lang_dir = dir;
        self
    }

    pub fn ui_lang_dir(&self) -> Option<&Path> {
        self.ui_lang_dir.as_deref()
    }

    /// The language preference and the language it resolved to.
    pub fn ui_lang(&self) -> UiLang {
        *self.lang.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// The language of the Rust-rendered texts (T10).
    pub fn lang(&self) -> Lang {
        self.ui_lang().lang
    }

    pub fn set_ui_lang(&self, ui: UiLang) {
        *self.lang.write().unwrap_or_else(PoisonError::into_inner) = ui;
    }

    /// Registers the tray rebuild ([`AppState::refresh_tray`]); the first registration wins.
    pub fn set_tray_refresh(&self, f: impl Fn() + Send + Sync + 'static) {
        let _ = self.tray_refresh.set(TrayRefresh(Box::new(f)));
    }

    /// Rebuilds the tray menu and tooltip from the current state; nothing before the tray exists.
    pub fn refresh_tray(&self) {
        if let Some(f) = self.tray_refresh.get() {
            (f.0)();
        }
    }

    /// The cached store-health snapshot (a copy; a short lock, never the store).
    pub fn health(&self) -> Option<StoreHealthView> {
        self.health
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Replaces the cached snapshot; true when it differs from the one it replaces.
    pub fn set_health(&self, h: Option<StoreHealthView>) -> bool {
        let mut slot = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        let changed = *slot != h;
        *slot = h;
        changed
    }

    /// The startup error text of this state (the same app-generated text the tray shows).
    pub fn with_startup_text(mut self, text: Option<String>) -> AppState {
        self.startup_text = text;
        self
    }

    pub fn startup_text(&self) -> Option<&str> {
        self.startup_text.as_deref()
    }

    pub fn pending(&self) -> u32 {
        self.pending.load(Ordering::Relaxed)
    }

    pub fn set_pending(&self, n: u32) {
        self.pending.store(n, Ordering::Relaxed);
    }

    /// True exactly once per process, and only when the tray-host check found no host (§2.5).
    pub fn claim_tray_hint(&self) -> bool {
        self.tray_host == Some(TrayHost::Missing)
            && !self.tray_hint_shown.swap(true, Ordering::SeqCst)
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

    /// The flag the script glue sets on an identity mismatch (PD-133); the serving start hands
    /// a clone to the glue.
    pub fn update_pending_flag(&self) -> Arc<AtomicBool> {
        self.update_pending.clone()
    }

    /// The sandbox binary was replaced under the running app (PD-133).
    pub fn update_pending(&self) -> bool {
        self.update_pending.load(Ordering::SeqCst)
    }

    /// What the script glue of every core takes from this state: the startup probe's holder and
    /// the update flag (the same `Arc`s [`AppState::probe_report`] and [`AppState::update_pending`]
    /// read, so the status line and the Settings DTO see what the glue sees). The instance list is
    /// the core's own, set once it started.
    pub fn script_inputs(&self) -> ScriptInputs {
        ScriptInputs {
            probe: self.probe.clone(),
            update_pending: self.update_pending_flag(),
            status: StatusPing::default(),
            instances: InstanceSource::default(),
        }
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
    /// The one quit run (`serve::quit`): a second Quit waits for it.
    quit_done: tokio::sync::OnceCell<ShutdownOutcome>,
    /// PD-06: the store could not be opened (or the core not started); nothing is served.
    store_failed: AtomicBool,
    /// L78: `audit::open` has blocked on a keychain prompt past 10 s. Shared with
    /// `serve::start_with` (`ServeHooks::keychain_prompt`); it lives here because the first `open`
    /// runs before any `ServeState` exists.
    keychain_prompt: Arc<AtomicBool>,
}

impl ServeSlot {
    pub fn get(&self) -> Option<&Arc<ServeState>> {
        self.state.get()
    }

    /// Set by `serve::start` on a PD-06 failure: the GUI relaunch shows the error window then.
    pub fn mark_store_failed(&self) {
        self.store_failed.store(true, Ordering::SeqCst);
    }

    pub fn store_failed(&self) -> bool {
        self.store_failed.load(Ordering::SeqCst)
    }

    /// The flag `serve::start` hands `serve::start_with` (`ServeHooks::keychain_prompt`).
    pub fn keychain_prompt_flag(&self) -> Arc<AtomicBool> {
        self.keychain_prompt.clone()
    }

    /// The status line `keychain_prompt` is due (L78).
    pub fn keychain_prompt(&self) -> bool {
        self.keychain_prompt.load(Ordering::SeqCst)
    }

    /// The first state wins; a later one is dropped.
    pub fn set(&self, state: Arc<ServeState>) {
        let _ = self.state.set(state);
    }

    /// Cancelled by the quit path before it awaits [`ServeSlot::take_starting`].
    pub fn quit(&self) -> &ShutdownSignal {
        &self.quit
    }

    /// Holds the outcome of the one quit run.
    pub fn quit_done(&self) -> &tokio::sync::OnceCell<ShutdownOutcome> {
        &self.quit_done
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

    /// T36b item 1: the store-health snapshot the tray reads. Empty at start, replaced as a whole,
    /// and `set_health` says whether it changed (so a refresh only follows a real change).
    #[test]
    fn app_state_caches_the_store_health_snapshot() {
        use atlas_duck_core::StoreHealthView;
        let state = AppState::new(StartupSummary::Ready, None);
        assert_eq!(state.health(), None);
        let mut h = StoreHealthView {
            storage_low: false,
            anchor_write_failing: false,
            anchor_thread_dead: false,
            anchors_blocked: false,
            open_incidents: 0,
            prune_backlog_days: 0,
            prune_backlog: None,
            last_prune_failed: false,
            shred_checkpoint_pending: false,
            settings_unreadable: false,
            anchor_dir_write_failing: false,
            anchor_dir_lines_pending: 0,
            anchors_missing: None,
            re_anchor_offered: false,
        };
        assert!(state.set_health(Some(h.clone())), "None -> Some changes");
        assert_eq!(state.health(), Some(h.clone()));
        assert!(!state.set_health(Some(h.clone())), "the same snapshot");
        h.storage_low = true;
        assert!(state.set_health(Some(h.clone())));
        assert_eq!(state.health(), Some(h));
        assert!(state.set_health(None), "cleared");
        assert!(!state.set_health(None));
        assert_eq!(state.health(), None);
    }

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
    fn tray_hint_is_claimed_once_and_only_without_a_tray_host() {
        let missing = AppState::new(StartupSummary::Ready, Some(TrayHost::Missing));
        assert!(missing.claim_tray_hint());
        assert!(!missing.claim_tray_hint(), "one-time hint");
        let present = AppState::new(StartupSummary::Ready, Some(TrayHost::Present));
        assert!(!present.claim_tray_hint());
        assert!(!AppState::new(StartupSummary::Ready, None).claim_tray_hint());
    }

    #[test]
    fn startup_text_and_pending_count() {
        let state = AppState::new(StartupSummary::DataDirMissing, None)
            .with_startup_text(Some("data directory /x not found".into()));
        assert_eq!(state.startup_text(), Some("data directory /x not found"));
        assert_eq!(state.pending(), 0);
        state.set_pending(3);
        assert_eq!(state.pending(), 3);
        let slot = ServeSlot::default();
        assert!(!slot.store_failed());
        slot.mark_store_failed();
        assert!(slot.store_failed());
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
