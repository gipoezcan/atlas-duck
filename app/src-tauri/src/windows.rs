//! Window registry (C.10 + Δ1, PD-72; §2.5, §6.4, §10.3; M6 T6): the seven window labels, the
//! one builder every window goes through ([`WindowSpec`], applied by [`open`]), the navigation
//! allowlist ([`nav_allowed`]) and the GUI relaunch routing ([`route_relaunch`]).
//!
//! Rust builds every window (`tauri.conf.json` `app.windows` is empty) under its fixed label, so
//! the capability file of that label (§10.3) is the window's whole grant. A window is built once
//! and shown again afterwards; closing hides it (§2.5, `tray::on_run_event`).
//!
//! Building a window waits for the main thread, so [`open`] must never run on it: the tray, the
//! single-instance callback and the run-event handler go through [`spawn_relaunch`] (blocking
//! pool), commands through `commands::blocking`.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use atlas_duck_audit::{LockedReason, RecoveryOffer};
use atlas_duck_core::{GateState, ShutdownReason};
use atlas_duck_ipc::paths::LocalDataDir;
use tauri::webview::NewWindowResponse;
use tauri::{AppHandle, Manager, Runtime, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

use crate::credential::{CredentialState, Purpose};
use crate::early_argv::{EarlyMode, classify_argv};
use crate::i18n::{Lang, T, localize};
use crate::serve;
use crate::startup::crash::webview_data_dir;
use crate::startup::hardening::DEVTOOLS_ALLOWED;
use crate::state::{AppState, DataDirHold, ServeSlot, StartupSummary};
use crate::tray::MSG_STORE_UNAVAILABLE;

/// Diagnostic-log fields this module emits (added to the T08 allowlist): the window label, never
/// a URL (a blocked URL can come from preview content).
pub const LOG_FIELDS: &[&str] = &["window"];
/// A window could not be built or shown; `window`, `error_class`.
pub const LOG_EVENT_WINDOW_OPEN_FAILED: &str = "window_open_failed";
/// A window was built or brought up; `window` only (the S-03 flow reads it as "a window opened").
pub const LOG_EVENT_WINDOW_OPENED: &str = "window_opened";
/// A navigation outside [`nav_allowed`] was refused; `window` only.
pub const LOG_EVENT_NAVIGATION_BLOCKED: &str = "navigation_blocked";
/// A `window.open` / `target=_blank` request was refused; `window` only.
pub const LOG_EVENT_NEW_WINDOW_BLOCKED: &str = "new_window_blocked";

/// The app origin a main frame may show, macOS and Linux (`tauri://localhost`).
pub const APP_ORIGIN: &str = "tauri://localhost";
/// The app origin on Windows (`useHttpsScheme` stays off, `ci/check-csp.mjs`).
pub const APP_ORIGIN_WINDOWS: &str = "http://tauri.localhost";
/// The `srcdoc` preview iframe's URL (§6.4, PD-67).
pub const ABOUT_SRCDOC: &str = "about:srcdoc";

/// WebView2 browser arguments of every window (Windows). Setting them replaces wry's default
/// `--disable-features=…`, so that default is repeated; `--disable-crash-reporter` turns off the
/// crash-report upload (§15 V30). Every window sharing a WebView2 user data folder must pass the
/// same arguments, so there is one constant.
pub const WINDOWS_BROWSER_ARGS: &str =
    "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --disable-crash-reporter";
/// `<data>/webview-credential`: the credential window's own webview data (§10.3, §15 V35).
pub const CREDENTIAL_DATA_DIR: &str = "webview-credential";

/// Title of the native dialogs this module shows.
const DIALOG_TITLE: &str = "atlas-duck";
/// Buttons of the no-store error window (§2.5 "with a Quit button"; plan text).
pub const ERROR_DIALOG_QUIT: T = T::new("Quit", "Beenden");
pub const ERROR_DIALOG_CLOSE: T = T::new("Close", "Schließen");
/// The one-time no-tray-host hint (§2.5: it names the GNOME "AppIndicator and KStatusNotifierItem
/// Support" extension, verbatim; the rest is plan text).
pub const MSG_NO_TRAY_HOST: T = T::new(
    "No system tray was found, so the atlas-duck tray menu is not shown. On GNOME, install the \"AppIndicator and KStatusNotifierItem Support\" extension. Until then, start atlas-duck again from the app menu: it opens the Approvals window, whose header reaches every other window and Quit.",
    "Es wurde kein System-Tray gefunden, daher wird das Tray-Menü von atlas-duck nicht angezeigt. Installieren Sie unter GNOME die Erweiterung \"AppIndicator and KStatusNotifierItem Support\". Starten Sie atlas-duck bis dahin erneut über das App-Menü: Es öffnet das Fenster Freigaben, dessen Kopfzeile jedes andere Fenster und Beenden erreicht.",
);
/// M15 T10: the window titles (plan text, T6), by [`Label`].
const TITLES: [(Label, T); 8] = [
    (
        Label::Approvals,
        T::new("atlas-duck: Approvals", "atlas-duck: Freigaben"),
    ),
    (
        Label::Settings,
        T::new("atlas-duck: Settings", "atlas-duck: Einstellungen"),
    ),
    (
        Label::Audit,
        T::new("atlas-duck: Audit", "atlas-duck: Audit-Protokoll"),
    ),
    (
        Label::RunningScripts,
        T::new(
            "atlas-duck: Running scripts",
            "atlas-duck: Laufende Skripte",
        ),
    ),
    (
        Label::Onboarding,
        T::new("atlas-duck: Onboarding", "atlas-duck: Einführung"),
    ),
    (
        Label::Credential,
        T::new("atlas-duck: Credentials", "atlas-duck: Anmeldedaten"),
    ),
    (
        Label::Setup,
        T::new("atlas-duck: Setup", "atlas-duck: Einrichtung"),
    ),
    (Label::Help, T::new("atlas-duck: Help", "atlas-duck: Hilfe")),
];
/// The core gate messages a no-store error window shows (`GateState::envelope`, core's English;
/// `keyring_not_local` is the wizard's [`crate::wizard::TEXT_KEYRING_NOT_LOCAL`]).
pub const GATE_STORE_NEWER: T = T::new(
    "the audit store was written by a newer atlas-duck; upgrade atlas-duck",
    "Der Audit-Speicher wurde von einem neueren atlas-duck geschrieben; aktualisieren Sie atlas-duck",
);
pub const GATE_NOT_CONFIGURED: T = T::new(
    "atlas-duck is not configured (<reason>)",
    "atlas-duck ist nicht eingerichtet (<reason>)",
);

/// The texts of this module, for [`crate::i18n::all`].
pub const TEXTS: &[&T] = &[
    &ERROR_DIALOG_QUIT,
    &ERROR_DIALOG_CLOSE,
    &MSG_NO_TRAY_HOST,
    &TITLES[0].1,
    &TITLES[1].1,
    &TITLES[2].1,
    &TITLES[3].1,
    &TITLES[4].1,
    &TITLES[5].1,
    &TITLES[6].1,
    &TITLES[7].1,
    &GATE_STORE_NEWER,
    &GATE_NOT_CONFIGURED,
];

/// The eight window labels (C.10 + Δ1, PD-72, M16 PD-328); one capability file each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Label {
    Approvals,
    Settings,
    Audit,
    RunningScripts,
    Onboarding,
    Credential,
    Setup,
    /// M16 (PD-328): the user guide; static pages, no app permission.
    Help,
}

impl Label {
    pub const ALL: [Label; 8] = [
        Label::Approvals,
        Label::Settings,
        Label::Audit,
        Label::RunningScripts,
        Label::Onboarding,
        Label::Credential,
        Label::Setup,
        Label::Help,
    ];

    /// The window label, which is also its capability file's identifier and `windows` entry.
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Approvals => "approvals",
            Label::Settings => "settings",
            Label::Audit => "audit",
            Label::RunningScripts => "running_scripts",
            Label::Onboarding => "onboarding",
            Label::Credential => "credential",
            Label::Setup => "setup",
            Label::Help => "help",
        }
    }

    /// The window's HTML entry (T5's Vite inputs; PD-71: one `credential.html` on every platform).
    pub fn entry(self) -> &'static str {
        match self {
            Label::Approvals => "approvals.html",
            Label::Settings => "settings.html",
            Label::Audit => "audit.html",
            Label::RunningScripts => "running_scripts.html",
            Label::Onboarding => "onboarding.html",
            Label::Credential => "credential.html",
            Label::Setup => "setup.html",
            // The entry is the guide's index; `open_help` builds it at the page asked for.
            Label::Help => "help/en/index.html",
        }
    }

    /// The title bar text (plan text, T6; app-generated, §5.6).
    pub fn title(self) -> &'static str {
        self.title_in(Lang::En)
    }

    /// [`Label::title`] in `lang` (M15 T10).
    pub fn title_in(self, lang: Lang) -> &'static str {
        TITLES
            .iter()
            .find(|(l, _)| *l == self)
            .map_or("atlas-duck", |(_, t)| t.get(lang))
    }

    /// Initial inner size in logical pixels.
    fn size(self) -> (f64, f64) {
        match self {
            Label::Approvals => (1180.0, 780.0),
            Label::Settings => (880.0, 680.0),
            Label::Audit | Label::RunningScripts => (760.0, 540.0),
            Label::Onboarding | Label::Setup => (780.0, 660.0),
            Label::Credential => (560.0, 600.0),
            Label::Help => (940.0, 720.0),
        }
    }

    pub fn from_label(label: &str) -> Option<Label> {
        Label::ALL.into_iter().find(|l| l.as_str() == label)
    }
}

/// How a window comes to the front.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Show {
    /// Shown and focused (a user's request: relaunch, tray, header).
    Focus,
    /// Shown without taking the focus (attention mode "show without activating", Task 19).
    WithoutActivating,
    /// Shown and focused by the attention engine, not by the user (attention mode "show and
    /// focus", Task 19): the Approvals window gets `window_focus {requested: false}` first, so its
    /// page swallows input for 1 s (§5.6, PD-75).
    FocusUnrequested,
}

impl Show {
    /// True when the window takes the focus.
    fn focuses(self) -> bool {
        matches!(self, Show::Focus | Show::FocusUnrequested)
    }
}

/// Everything [`open`] passes to the window builder, decided by [`window_spec`] (pure).
#[derive(Debug, Clone, PartialEq)]
pub struct WindowSpec {
    pub label: Label,
    pub entry: &'static str,
    pub title: &'static str,
    pub size: (f64, f64),
    /// `<data>/webview` (credential: `<data>/webview-credential`); `None` before a data dir
    /// exists (first run, setup window only), where Tauri uses its default folder and the window
    /// is incognito. T23 moves the setup window's data into the data dir once it exists.
    pub data_directory: Option<PathBuf>,
    pub incognito: bool,
    pub devtools: bool,
    /// Windows only ([`WINDOWS_BROWSER_ARGS`]); `None` elsewhere.
    pub browser_args: Option<&'static str>,
    pub focused: bool,
}

/// The builder settings of `label` (§2.5, §10.3, §15 V30, V35): every window gets the app entry,
/// `<data>/webview` (the Crashpad reports there are cleared before the first webview), devtools
/// only in debug builds and, on Windows, the browser arguments without crash-report upload. The
/// credential window is incognito **and** has its own data dir, so without a data dir it is
/// refused ([`WindowError::NoDataDir`]): it never falls back to Tauri's default webview folder,
/// which other windows share. Any other window opened before a data dir exists is incognito (the
/// setup window before first run keeps that default profile; T23 moves its data once the data
/// dir exists).
pub fn window_spec(
    label: Label,
    how: Show,
    data: Option<&LocalDataDir>,
    windows: bool,
) -> Result<WindowSpec, WindowError> {
    let credential = label == Label::Credential;
    if credential && data.is_none() {
        return Err(WindowError::NoDataDir);
    }
    let data_directory = data.map(|d| {
        if credential {
            d.path().join(CREDENTIAL_DATA_DIR)
        } else {
            webview_data_dir(d)
        }
    });
    Ok(WindowSpec {
        label,
        entry: label.entry(),
        title: label.title(),
        size: label.size(),
        incognito: credential || data_directory.is_none(),
        data_directory,
        devtools: DEVTOOLS_ALLOWED,
        browser_args: windows.then_some(WINDOWS_BROWSER_ARGS),
        focused: how.focuses(),
    })
}

/// Every webview data folder under `data` (`<data>/webview`, `<data>/webview-credential`), for
/// the startup Crashpad clearing (§2.5, §15 V35). Derived from [`window_spec`], so a new folder
/// there cannot be missed here.
pub fn webview_data_dirs(data: &LocalDataDir) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Label::ALL
        .into_iter()
        .filter_map(|l| window_spec(l, Show::WithoutActivating, Some(data), false).ok())
        .filter_map(|s| s.data_directory)
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs
}

// ---------- navigation ----------

/// Which frame a navigation is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame {
    Main,
    Sub,
    /// The webview does not say (wry on WebKitGTK and WKWebView calls the handler for every
    /// frame with the URL only): the subframe set applies, see [`RUNTIME_FRAME`].
    Unreported,
}

/// The frame [`build`]'s navigation handler reports. WebView2 calls it for the main frame only
/// (wry registers `NavigationStarting`, not `FrameNavigationStarting`), so Windows enforces the
/// main-frame rule at run time. WebKitGTK and WKWebView call it for every frame without saying
/// which, so there the closure must admit the subframe set (`about:srcdoc` for the preview
/// iframe; Tauri itself passes the isolation iframe before the handler runs); the main-frame
/// rule then rests on the CSP (`frame-src`, `frame-ancestors 'none'`) and T32's S-09 flow.
pub const RUNTIME_FRAME: Frame = if cfg!(windows) {
    Frame::Main
} else {
    Frame::Unreported
};

/// The origins navigation may reach (§6.4, §10.3): the app origin of this platform and this
/// build's isolation origin, taken from the context's pattern (`csp::isolation_origin`), never a
/// constant (Tauri 2.12 mints a new one per build, V34).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavPolicy {
    app_origin: &'static str,
    isolation_origin: String,
}

impl NavPolicy {
    pub fn new(isolation_origin: String, windows: bool) -> NavPolicy {
        NavPolicy {
            app_origin: if windows {
                APP_ORIGIN_WINDOWS
            } else {
                APP_ORIGIN
            },
            isolation_origin,
        }
    }

    /// The policy of this platform; `isolation_origin` is `None` without the isolation pattern,
    /// and then no isolation origin is admitted.
    pub fn for_this_platform(isolation_origin: Option<String>) -> NavPolicy {
        NavPolicy::new(isolation_origin.unwrap_or_default(), cfg!(windows))
    }
}

/// `scheme://host[:port]` of `url`; `None` for a URL without a host or with user info.
fn origin_of(url: &Url) -> Option<String> {
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    })
}

/// The navigation allowlist (§6.4, §10.3): a main frame stays on the app origin; a subframe may
/// also load this build's isolation origin and `about:srcdoc`. Everything else (remote pages,
/// `file:`, `data:`, `about:blank`, `javascript:`) is refused.
pub fn nav_allowed(url: &Url, frame: Frame, policy: &NavPolicy) -> bool {
    let origin = origin_of(url);
    if origin.as_deref() == Some(policy.app_origin) {
        return true;
    }
    match frame {
        Frame::Main => false,
        Frame::Sub | Frame::Unreported => {
            url.as_str() == ABOUT_SRCDOC
                || (!policy.isolation_origin.is_empty()
                    && origin.as_deref() == Some(policy.isolation_origin.as_str()))
        }
    }
}

/// [`nav_allowed`] for the window `label`: the Help window's main frame also stays under
/// `/help/` (M16, PD-328), so its pages cannot navigate into the app's own windows.
pub fn nav_allowed_for(label: Label, url: &Url, frame: Frame, policy: &NavPolicy) -> bool {
    nav_allowed(url, frame, policy)
        && (label != Label::Help
            || frame != Frame::Main
            || origin_of(url).as_deref() != Some(policy.app_origin)
            || url.path().starts_with(HELP_PATH_PREFIX))
}

/// Where the guide's pages sit in the app's assets (`app/ui/public/help`).
const HELP_PATH_PREFIX: &str = "/help/";

// ---------- GUI relaunch ----------

/// What the credential window opens for when the app is locked (§2.5, §8.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unlock {
    /// `keychain_unavailable`: the window offers "Retry keychain" (PD-89).
    Unlock,
    /// `keychain_lost`: "Recover this log".
    Recover,
    /// `keychain_lost` after an unfinished restore: "Finish restore".
    FinishRestore,
}

/// The app's state as the relaunch routing sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppSnapshot {
    /// No pinned file on this host (§2.5 First run).
    BeforeFirstRun,
    /// One of the four data-dir error states, with its startup text (§7.7).
    StartupError(String),
    /// `Ready`: the store is being opened.
    Starting,
    /// `Core` serves.
    Serving,
    /// A gate serves (first run in a pinned dir, locked, store newer).
    Gate(GateState),
    /// PD-06: the store could not be opened; nothing is served.
    StoreUnavailable,
    /// Quit is running.
    ShuttingDown,
}

/// What a GUI relaunch (or a cold start) does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relaunch {
    Nothing,
    /// Startup has not finished: open once it has.
    Defer,
    OpenApprovals,
    OpenCredential(Unlock),
    /// The first-run wizard (PD-72, PD-77).
    OpenSetup,
    /// A no-store state's error window (PD-85: a native dialog with a Quit button).
    ShowErrorDialog(String),
}

/// The fixed message of a gate state's envelope (the app-generated text the agent sees too).
fn gate_text(state: GateState) -> String {
    state
        .envelope()
        .error
        .map(|e| e.message)
        .unwrap_or_default()
}

/// The no-argument path (§2.5): Approvals, or the credential window when locked, the wizard
/// before first run, the error window in a no-store state.
fn route_open(state: &AppSnapshot) -> Relaunch {
    match state {
        AppSnapshot::BeforeFirstRun | AppSnapshot::Gate(GateState::FirstRun) => Relaunch::OpenSetup,
        AppSnapshot::StartupError(text) => Relaunch::ShowErrorDialog(text.clone()),
        AppSnapshot::Starting => Relaunch::Defer,
        AppSnapshot::Serving => Relaunch::OpenApprovals,
        AppSnapshot::Gate(GateState::Locked(reason)) => match reason {
            LockedReason::KeychainUnavailable => Relaunch::OpenCredential(Unlock::Unlock),
            LockedReason::KeychainLost {
                offer: RecoveryOffer::RecoverThisLog,
            } => Relaunch::OpenCredential(Unlock::Recover),
            LockedReason::KeychainLost {
                offer: RecoveryOffer::FinishRestore,
            } => Relaunch::OpenCredential(Unlock::FinishRestore),
            // §8.7: nothing to unlock; the error window instead of the credential window.
            LockedReason::KeyringNotLocal => {
                Relaunch::ShowErrorDialog(gate_text(GateState::Locked(*reason)))
            }
        },
        AppSnapshot::Gate(state @ (GateState::StoreNewer | GateState::NotConfigured(_))) => {
            Relaunch::ShowErrorDialog(gate_text(*state))
        }
        // The `StoreFailed` gate serves with `store_failed` set, so `serving_snapshot` reports
        // `StoreUnavailable` first; the arm keeps the routing total (M9 Δ4).
        AppSnapshot::StoreUnavailable | AppSnapshot::Gate(GateState::StoreFailed) => {
            Relaunch::ShowErrorDialog(MSG_STORE_UNAVAILABLE.en.into())
        }
        AppSnapshot::Gate(GateState::ShuttingDown) | AppSnapshot::ShuttingDown => Relaunch::Nothing,
    }
}

/// A forwarded launch (`argv` as the second instance got it, `argv[0]` the program) or macOS
/// `RunEvent::Reopen` (no arguments) (§2.5, §15 V33): with no `--background` the no-argument
/// path; a forwarded `--background` (CLI §4.7, autostart) opens and raises nothing.
pub fn route_relaunch(state: &AppSnapshot, argv: &[OsString]) -> Relaunch {
    match classify_argv(argv) {
        EarlyMode::Gui { background: false } => route_open(state),
        EarlyMode::Gui { background: true } | EarlyMode::Cli(_) | EarlyMode::VerifyExport(_) => {
            Relaunch::Nothing
        }
    }
}

/// The cold start, once startup completed (§2.5 "A cold GUI start with no arguments takes the
/// same path once startup completes"). The four data-dir error states showed their dialog in
/// `startup::apply_startup_state` already. Under `--background` (autostart at login) only what the
/// user cannot do without opens: the first-run wizard (L46) and the credential window of a locked
/// store (§2.5 "opens for unlock automatically only at startup (also under `--background`)").
/// Approvals and the no-store error windows wait for the user (the tray shows the state).
pub fn route_cold_start(state: &AppSnapshot, background: bool) -> Relaunch {
    match state {
        AppSnapshot::StartupError(_) => Relaunch::Nothing,
        state if background => match route_open(state) {
            action @ (Relaunch::OpenSetup | Relaunch::OpenCredential(_)) => action,
            _ => Relaunch::Nothing,
        },
        state => route_open(state),
    }
}

/// When the cold start opens its window: at once outside `Ready`, else when `serve::start`
/// finished. A no-argument relaunch that arrives while startup runs is kept here and opens then.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartupRoute {
    completed: bool,
    /// `Some(background)`: route once startup completed.
    pending: Option<bool>,
}

impl StartupRoute {
    /// `Ready`: the cold start routes when `serve::start` finished.
    pub fn awaiting(background: bool) -> StartupRoute {
        StartupRoute {
            completed: false,
            pending: Some(background),
        }
    }

    /// Every other startup state: nothing waits.
    pub fn completed() -> StartupRoute {
        StartupRoute {
            completed: true,
            pending: None,
        }
    }

    /// A no-argument relaunch during startup: false once startup completed (route it now). It
    /// replaces a pending `--background` cold start (the user asked for a window).
    pub fn defer_open(&mut self) -> bool {
        if self.completed {
            return false;
        }
        self.pending = Some(false);
        true
    }

    /// Startup completed: the pending route's `background` flag, once.
    pub fn complete(&mut self) -> Option<bool> {
        self.completed = true;
        self.pending.take()
    }
}

// ---------- the registry ----------

/// Why a window could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowError {
    /// No [`WindowRegistry`] is managed (before `setup`).
    NotRegistered,
    /// The credential window needs a data dir of its own and none exists yet.
    NoDataDir,
    /// The credential window is open for another purpose; it keeps it (§10.3, M6 T20).
    Busy,
    Build,
    Show,
}

impl WindowError {
    /// The class the log line and the error's text use.
    pub fn as_str(self) -> &'static str {
        match self {
            WindowError::NotRegistered => "not_registered",
            WindowError::NoDataDir => "no_data_dir",
            WindowError::Busy => "busy",
            WindowError::Build => "build",
            WindowError::Show => "show",
        }
    }
}

impl std::fmt::Display for WindowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for WindowError {}

/// Managed in `setup` (`app.manage`): the navigation policy, the startup routing state and the
/// credential window's state.
pub struct WindowRegistry {
    nav: NavPolicy,
    route: Mutex<StartupRoute>,
    /// Serializes [`open`]: one build per label.
    opening: Mutex<()>,
    /// What the credential window is open for, and its passphrase hand-over (M6 T20): set by
    /// Rust only (`credential::open`, under `opening`), never by a webview.
    credential: Mutex<CredentialState>,
    /// One error window at a time.
    error_dialog_open: Arc<AtomicBool>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl WindowRegistry {
    pub fn new(nav: NavPolicy, route: StartupRoute) -> WindowRegistry {
        WindowRegistry {
            nav,
            route: Mutex::new(route),
            opening: Mutex::new(()),
            credential: Mutex::new(CredentialState::default()),
            error_dialog_open: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn nav(&self) -> &NavPolicy {
        &self.nav
    }

    /// The purpose the open credential window has (Rust set it).
    pub fn credential_purpose(&self) -> Option<Purpose> {
        lock(&self.credential).purpose().cloned()
    }

    /// The credential window's state. Taken after `opening` when both are held, never before.
    pub(crate) fn credential_state(&self) -> std::sync::MutexGuard<'_, CredentialState> {
        lock(&self.credential)
    }

    /// The `opening` lock, waiting for an open that holds it (never on the main thread: an open
    /// waits for the main thread to build its window).
    pub(crate) fn lock_opening(&self) -> std::sync::MutexGuard<'_, ()> {
        lock(&self.opening)
    }

    /// The `opening` lock if no open holds it (never waits: for the main thread). Public for the
    /// tests that hold it to stand in for an open in flight.
    #[doc(hidden)]
    pub fn try_opening(&self) -> Option<std::sync::MutexGuard<'_, ()>> {
        match self.opening.try_lock() {
            Ok(g) => Some(g),
            Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }
}

fn log_open_failed(label: Label, class: &'static str) {
    tracing::warn!(
        event = LOG_EVENT_WINDOW_OPEN_FAILED,
        window = label.as_str(),
        error_class = class
    );
}

fn bring_up<R: Runtime>(w: &WebviewWindow<R>, how: Show) -> Result<(), WindowError> {
    // PD-75: the Approvals page learns whether the focus it is about to get was requested, before
    // it gets it (its 1 s inert periods start on this event; an unrequested one swallows input).
    // Also for `WithoutActivating`: tao's `show()` activates an already-built window on Windows, so
    // a "show without activating" may end in a focus nobody asked for; the page takes the longer
    // period of all it hears, so this is harmless where no activation follows. (A window built just
    // now has no listening page yet: the page covers that itself, see `useWindowInert`.)
    if w.label() == Label::Approvals.as_str() {
        crate::ui_sink::emit_window_focus(w.app_handle(), w.label(), how == Show::Focus);
    }
    w.show().map_err(|_| WindowError::Show)?;
    if how.focuses() {
        w.unminimize().map_err(|_| WindowError::Show)?;
        w.set_focus().map_err(|_| WindowError::Show)?;
    }
    Ok(())
}

/// Builds `spec` (the thin half of the builder; every setting comes from [`window_spec`]).
fn build<R: Runtime>(
    app: &AppHandle<R>,
    spec: &WindowSpec,
    nav: NavPolicy,
    entry: &str,
) -> Result<WebviewWindow<R>, WindowError> {
    let label = spec.label;
    let mut builder =
        WebviewWindowBuilder::new(app, label.as_str(), WebviewUrl::App(PathBuf::from(entry)))
            .title(label.title_in(ui_lang(app)))
            .inner_size(spec.size.0, spec.size.1)
            .devtools(spec.devtools)
            .incognito(spec.incognito)
            .focused(spec.focused)
            .on_navigation(move |url| {
                let allowed = nav_allowed_for(label, url, RUNTIME_FRAME, &nav);
                if !allowed {
                    tracing::warn!(
                        event = LOG_EVENT_NAVIGATION_BLOCKED,
                        window = label.as_str()
                    );
                }
                allowed
            })
            .on_new_window(move |_url, _features| {
                tracing::warn!(
                    event = LOG_EVENT_NEW_WINDOW_BLOCKED,
                    window = label.as_str()
                );
                NewWindowResponse::Deny
            });
    if let Some(dir) = &spec.data_directory {
        builder = builder.data_directory(dir.clone());
    }
    if let Some(args) = spec.browser_args {
        builder = builder.additional_browser_args(args);
    }
    builder.build().map_err(|_| WindowError::Build)
}

/// Opens `label`: builds it the first time (from [`window_spec`] with the locked data dir, if
/// any), then shows it (§2.5). Never on the main thread (see the module docs).
pub fn open<R: Runtime>(app: &AppHandle<R>, label: Label, how: Show) -> Result<(), WindowError> {
    open_with(app, label, how, |_, _| Ok(()))
}

/// [`open`], with `decide(registry, exists)` run first under the same `opening` lock (`exists`:
/// the window is built already); its `Err` opens nothing. The credential window decides its
/// purpose there (`credential::open`), so a purpose and the window it belongs to cannot be set
/// apart by a second request.
pub(crate) fn open_with<R: Runtime>(
    app: &AppHandle<R>,
    label: Label,
    how: Show,
    decide: impl FnOnce(&WindowRegistry, bool) -> Result<(), WindowError>,
) -> Result<(), WindowError> {
    let registry = app
        .try_state::<WindowRegistry>()
        .ok_or(WindowError::NotRegistered)?;
    let _one_at_a_time = lock(&registry.opening);
    let existing = app.get_webview_window(label.as_str());
    let result = match decide(&registry, existing.is_some()).and(Ok(existing)) {
        Err(e) => Err(e),
        Ok(Some(w)) => bring_up(&w, how),
        Ok(None) => {
            let data = app.try_state::<DataDirHold>().map(|h| h.data().clone());
            window_spec(label, how, data.as_ref(), cfg!(windows))
                .and_then(|spec| build(app, &spec, registry.nav.clone(), spec.entry))
                .inspect(|_| crate::attention::apply_overlay_to_new_window(app, label))
                .and_then(|w| match how {
                    Show::Focus | Show::FocusUnrequested => bring_up(&w, how),
                    Show::WithoutActivating => Ok(()),
                })
        }
    };
    match &result {
        Ok(()) => tracing::info!(event = LOG_EVENT_WINDOW_OPENED, window = label.as_str()),
        Err(e) => log_open_failed(label, e.as_str()),
    }
    result
}

/// Opens the Help window at `path` (`help/<lang>/<page>.html[#anchor]`, validated by
/// `commands::help`): builds it the first time, otherwise navigates the open one and brings it up
/// (M16, PD-328). Never on the main thread (see the module docs).
pub fn open_help<R: Runtime>(app: &AppHandle<R>, path: &str) -> Result<(), WindowError> {
    let label = Label::Help;
    let registry = app
        .try_state::<WindowRegistry>()
        .ok_or(WindowError::NotRegistered)?;
    let _one_at_a_time = lock(&registry.opening);
    let result = match app.get_webview_window(label.as_str()) {
        Some(w) => w
            .url()
            .map_err(|_| WindowError::Show)
            .and_then(|current| {
                current
                    .join(&format!("/{path}"))
                    .map_err(|_| WindowError::Show)
            })
            .and_then(|url| w.navigate(url).map_err(|_| WindowError::Show))
            .and_then(|()| bring_up(&w, Show::Focus)),
        None => {
            let data = app.try_state::<DataDirHold>().map(|h| h.data().clone());
            window_spec(label, Show::Focus, data.as_ref(), cfg!(windows))
                .and_then(|spec| build(app, &spec, registry.nav.clone(), path))
                .and_then(|w| bring_up(&w, Show::Focus))
        }
    };
    match &result {
        Ok(()) => tracing::info!(event = LOG_EVENT_WINDOW_OPENED, window = label.as_str()),
        Err(e) => log_open_failed(label, e.as_str()),
    }
    result
}

/// Opens the guide's index (the tray's "Help") in the UI language, off the main thread.
pub fn spawn_open_help<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let path = format!("help/{}/index.html", ui_lang_dir(ui_lang(&app)));
        let _ = open_help(&app, &path);
    });
}

/// The guide's folder of `lang`: `help/<this>/...`.
pub fn ui_lang_dir(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "en",
        Lang::De => "de",
    }
}

/// Opens the credential window for `unlock`; the purpose is fixed by Rust, under the window's
/// `opening` lock (§10.3, `credential::open`).
pub fn open_credential<R: Runtime>(
    app: &AppHandle<R>,
    unlock: Unlock,
    how: Show,
) -> Result<(), WindowError> {
    crate::credential::open(app, Purpose::from(unlock), how)
}

/// The app's state for the relaunch routing.
pub fn snapshot<R: Runtime>(app: &AppHandle<R>) -> AppSnapshot {
    let Some(state) = app.try_state::<AppState>() else {
        return AppSnapshot::Starting;
    };
    match state.startup {
        StartupSummary::BeforeFirstRun => {
            first_run_snapshot(app.try_state::<ServeSlot>().as_deref())
        }
        StartupSummary::Ready => serving_snapshot(app.try_state::<ServeSlot>().as_deref()),
        StartupSummary::DataDirMissing
        | StartupSummary::DataDirNotLocal
        | StartupSummary::DataDirUnusable
        | StartupSummary::PinnedUnreadable => {
            // Stored in English; shown in the current UI language (M15 T10 review M2).
            AppSnapshot::StartupError(localize(
                state.lang(),
                state.startup_text().unwrap_or_default(),
            ))
        }
    }
}

/// The `BeforeFirstRun` part of [`snapshot`] (M6 T23): the wizard's step 0 manages a `ServeSlot`
/// and serves in-process, and from then on the app is in whatever state that serving is (the
/// first-run gate, a core after `GENESIS`, the (1a) lock states), as a pinned start would be. Until
/// that start has left its state in the slot it is still before first run (the wizard).
pub fn first_run_snapshot(slot: Option<&ServeSlot>) -> AppSnapshot {
    match slot.map(|s| serving_snapshot(Some(s))) {
        None | Some(AppSnapshot::Starting) => AppSnapshot::BeforeFirstRun,
        Some(state) => state,
    }
}

/// The `Ready` part of [`snapshot`].
pub fn serving_snapshot(slot: Option<&ServeSlot>) -> AppSnapshot {
    let Some(slot) = slot else {
        return AppSnapshot::Starting;
    };
    if slot.quit().0.is_cancelled() {
        return AppSnapshot::ShuttingDown;
    }
    if slot.store_failed() {
        return AppSnapshot::StoreUnavailable;
    }
    match slot.get() {
        None => AppSnapshot::Starting,
        // M6 T22: a retry's `open` or a core start failed with the endpoint bound.
        Some(served) if served.store_failed() => AppSnapshot::StoreUnavailable,
        Some(served) if served.core.get().is_some() => AppSnapshot::Serving,
        Some(served) => served
            .gate_state()
            .map_or(AppSnapshot::Starting, AppSnapshot::Gate),
    }
}

/// Carries out `action` (off the main thread).
pub fn perform<R: Runtime>(app: &AppHandle<R>, action: Relaunch) {
    perform_with(app, action, Show::Focus);
}

/// [`perform`] with `how` the windows come to the front (the locked-mode re-raise does not take
/// the focus, §2.5 / UI-04).
pub fn perform_with<R: Runtime>(app: &AppHandle<R>, action: Relaunch, how: Show) {
    // `open` logs its own failure.
    let _ = match action {
        Relaunch::Nothing | Relaunch::Defer => Ok(()),
        Relaunch::OpenApprovals => open(app, Label::Approvals, how),
        Relaunch::OpenSetup => open(app, Label::Setup, how),
        Relaunch::OpenCredential(unlock) => open_credential(app, unlock, how),
        Relaunch::ShowErrorDialog(text) => {
            show_error_dialog(app, &text);
            Ok(())
        }
    };
}

/// A GUI relaunch (§2.5): routes on the current state; during startup a no-argument launch is
/// kept and opens when startup completed ([`startup_completed`]). Off the main thread.
pub fn relaunch<R: Runtime>(app: &AppHandle<R>, argv: &[OsString]) {
    let action = route_relaunch(&snapshot(app), argv);
    if action != Relaunch::Defer {
        return perform(app, action);
    }
    let deferred = app
        .try_state::<WindowRegistry>()
        .is_some_and(|r| lock(&r.route).defer_open());
    if !deferred {
        // Startup completed in between: route on the state it left.
        perform(app, route_relaunch(&snapshot(app), argv));
    }
}

/// [`relaunch`] on the blocking pool, for callers on the main thread (single-instance callback,
/// tray menu, `RunEvent::Reopen`).
pub fn spawn_relaunch<R: Runtime>(app: &AppHandle<R>, argv: Vec<OsString>) {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || relaunch(&app, &argv));
}

/// Called once `serve::start` finished (served, failed or cancelled): the cold start's window,
/// or a relaunch kept during startup (§2.5).
pub fn startup_completed<R: Runtime>(app: &AppHandle<R>) {
    let pending = app
        .try_state::<WindowRegistry>()
        .and_then(|r| lock(&r.route).complete());
    if let Some(background) = pending {
        let app = app.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let action = route_cold_start(&snapshot(&app), background);
            // §2.5: a window raised at startup starts the 5 minutes before the next raise.
            if matches!(action, Relaunch::OpenCredential(_) | Relaunch::OpenSetup) {
                crate::credential::raise::note_startup_raise(&app);
            }
            perform(&app, action);
        });
    }
}

/// The UI language of the app (English without an `AppState`).
pub fn ui_lang<R: Runtime>(app: &AppHandle<R>) -> Lang {
    app.try_state::<AppState>()
        .map(|s| s.lang())
        .unwrap_or_default()
}

/// Sets every open window's title in `lang` (a language change, M15 T10).
pub fn retitle<R: Runtime>(app: &AppHandle<R>, lang: Lang) {
    for label in Label::ALL {
        if let Some(w) = app.get_webview_window(label.as_str()) {
            let _ = w.set_title(label.title_in(lang));
        }
    }
}

/// A no-store state's error window (§2.5, PD-85): app-generated `text` and a Quit button that
/// runs the shutdown path. One at a time; closing it changes nothing.
pub fn show_error_dialog<R: Runtime>(app: &AppHandle<R>, text: &str) {
    let Some(registry) = app.try_state::<WindowRegistry>() else {
        return;
    };
    let open = registry.error_dialog_open.clone();
    if open.swap(true, Ordering::SeqCst) {
        return;
    }
    let handle = app.clone();
    // M15 T10: the window's texts in the UI language (an English text of this app or core's gate
    // text maps to its German form; anything else is shown as it is).
    let lang = ui_lang(app);
    app.dialog()
        .message(localize(lang, text))
        .title(DIALOG_TITLE)
        .kind(MessageDialogKind::Error)
        .buttons(MessageDialogButtons::OkCancelCustom(
            ERROR_DIALOG_QUIT.get(lang).into(),
            ERROR_DIALOG_CLOSE.get(lang).into(),
        ))
        .show(move |quit| {
            open.store(false, Ordering::SeqCst);
            if quit {
                serve::shutdown_then_exit(&handle, ShutdownReason::Quit);
            }
        });
}

/// The one-time no-tray-host hint (§2.5, Linux): shown when the startup check found no tray host,
/// once per process; dismissing it is UI state only (not audited, not stored).
pub fn show_no_tray_host_hint<R: Runtime>(app: &AppHandle<R>) {
    let claimed = app
        .try_state::<AppState>()
        .is_some_and(|s| s.claim_tray_hint());
    if claimed {
        app.dialog()
            .message(MSG_NO_TRAY_HOST.get(ui_lang(app)))
            .title(DIALOG_TITLE)
            .kind(MessageDialogKind::Info)
            .buttons(MessageDialogButtons::Ok)
            .show(|_| {});
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};

    /// M15 T10: the window titles and the no-store window's texts in German; core's gate texts
    /// map to their German form, any other text stays as it is.
    #[test]
    fn titles_and_error_window_in_german() {
        for label in Label::ALL {
            assert_eq!(label.title(), label.title_in(Lang::En));
            assert!(
                label.title_in(Lang::De).starts_with("atlas-duck: "),
                "{label:?}"
            );
            assert_ne!(
                label.title_in(Lang::De),
                label.title_in(Lang::En),
                "{label:?}"
            );
        }
        assert_eq!(Label::Approvals.title_in(Lang::De), "atlas-duck: Freigaben");
        let gate = |s: GateState| localize(Lang::De, &gate_text(s));
        assert_eq!(gate(GateState::StoreNewer), GATE_STORE_NEWER.de);
        assert_eq!(
            gate(GateState::NotConfigured("data_dir_missing")),
            "atlas-duck ist nicht eingerichtet (data_dir_missing)"
        );
        assert_eq!(
            gate(GateState::Locked(LockedReason::KeyringNotLocal)),
            crate::wizard::TEXT_KEYRING_NOT_LOCAL.de
        );
        assert_eq!(
            gate_text(GateState::StoreNewer),
            GATE_STORE_NEWER.en,
            "core's text is the table's English"
        );
    }
    const ISO_MAC: &str = "isolation-0b9e1d2c-3f4a-4b5c-8d6e-7f8091a2b3c4://localhost";
    const ISO_WIN: &str = "http://isolation-0b9e1d2c-3f4a-4b5c-8d6e-7f8091a2b3c4.localhost";

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    fn os(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    #[test]
    fn navigation_allowlist_main_frame_only() {
        let mac = NavPolicy::new(ISO_MAC.into(), false);
        let win = NavPolicy::new(ISO_WIN.into(), true);
        let frames = [Frame::Main, Frame::Sub, Frame::Unreported];

        // The app origin of each platform passes in every frame, any path.
        for f in frames {
            assert!(nav_allowed(
                &url("tauri://localhost/approvals.html"),
                f,
                &mac
            ));
            assert!(nav_allowed(&url("tauri://localhost/"), f, &mac));
            assert!(nav_allowed(
                &url("http://tauri.localhost/approvals.html"),
                f,
                &win
            ));
            assert!(nav_allowed(
                &url("http://tauri.localhost:80/settings.html?x#y"),
                f,
                &win
            ));
            // ... and not the other platform's.
            assert!(!nav_allowed(
                &url("http://tauri.localhost/approvals.html"),
                f,
                &mac
            ));
            assert!(!nav_allowed(
                &url("tauri://localhost/approvals.html"),
                f,
                &win
            ));
        }

        // Foreign main-frame targets fail everywhere.
        for p in [&mac, &win] {
            for bad in [
                "https://evil.example/",
                "http://evil.example/",
                "file:///etc/passwd",
                "file:///C:/Windows/win.ini",
                "about:blank",
                "data:text/html,<script>1</script>",
                "blob:https://tauri.localhost/0b9e1d2c-3f4a-4b5c-8d6e-7f8091a2b3c4",
                "blob:tauri://localhost/0b9e1d2c-3f4a-4b5c-8d6e-7f8091a2b3c4",
                "javascript:alert(1)",
                "https://tauri.localhost/",
                "http://tauri.localhost.evil.example/",
                "http://tauri.localhost:8080/",
                "http://user@tauri.localhost/",
                "tauri://user:pw@localhost/",
                "tauri://localhost.evil/",
                "ipc://localhost/app_status",
                "http://ipc.localhost/app_status",
            ] {
                for f in frames {
                    assert!(!nav_allowed(&url(bad), f, p), "{bad} in {f:?}");
                }
            }
            // `about:srcdoc` and the isolation origin: subframes only.
            assert!(!nav_allowed(&url(ABOUT_SRCDOC), Frame::Main, p));
            assert!(nav_allowed(&url(ABOUT_SRCDOC), Frame::Sub, p));
            assert!(nav_allowed(&url(ABOUT_SRCDOC), Frame::Unreported, p));
            // Only that exact URL, not about:srcdoc with extras.
            assert!(!nav_allowed(&url("about:srcdoc?x"), Frame::Sub, p));
            assert!(!nav_allowed(&url("about:blank"), Frame::Sub, p));
        }
        for (p, iso) in [(&mac, ISO_MAC), (&win, ISO_WIN)] {
            let page = url(&format!("{iso}/index.html"));
            assert!(!nav_allowed(&page, Frame::Main, p), "{iso}");
            assert!(nav_allowed(&page, Frame::Sub, p), "{iso}");
            assert!(nav_allowed(&page, Frame::Unreported, p), "{iso}");
        }
        // The isolation origin is this build's (from the pattern), not any `isolation-*` one.
        let other = url("isolation-11111111-2222-3333-4444-555555555555://localhost/");
        assert!(!nav_allowed(&other, Frame::Sub, &mac));
        let other_win = url("http://isolation-11111111-2222-3333-4444-555555555555.localhost/");
        assert!(!nav_allowed(&other_win, Frame::Sub, &win));
        // The other platform's isolation spelling is refused.
        assert!(!nav_allowed(&url(&format!("{ISO_WIN}/")), Frame::Sub, &mac));
        // Without an isolation pattern no isolation origin is admitted.
        let none = NavPolicy::for_this_platform(None);
        assert!(!nav_allowed(
            &url(&format!("{ISO_MAC}/")),
            Frame::Sub,
            &none
        ));
        assert!(!nav_allowed(
            &url(&format!("{ISO_WIN}/")),
            Frame::Sub,
            &none
        ));
        // The run-time frame: Windows reports main frames only and enforces the main rule.
        assert_eq!(RUNTIME_FRAME == Frame::Main, cfg!(windows));
    }

    /// The navigation policy of the shipped config takes this build's isolation origin from the
    /// generated context's pattern.
    #[test]
    fn help_window_navigation_stays_under_help() {
        let mac = NavPolicy::new(ISO_MAC.into(), false);
        let win = NavPolicy::new(ISO_WIN.into(), true);
        for (p, origin) in [
            (&mac, "tauri://localhost"),
            (&win, "http://tauri.localhost"),
        ] {
            for ok in [
                "/help/en/index.html",
                "/help/de/approvals.html#queue",
                "/help/de/",
            ] {
                let u = url(&format!("{origin}{ok}"));
                assert!(nav_allowed_for(Label::Help, &u, Frame::Main, p), "{u}");
            }
            for bad in [
                "/",
                "/approvals.html",
                "/settings.html",
                "/helpx/a.html",
                "/assets/x.js",
            ] {
                let u = url(&format!("{origin}{bad}"));
                assert!(!nav_allowed_for(Label::Help, &u, Frame::Main, p), "{u}");
                // Every other window keeps the app-origin rule.
                assert!(nav_allowed_for(Label::Settings, &u, Frame::Main, p), "{u}");
            }
            // Remote pages stay refused, as everywhere.
            let remote = url("https://example.com/help/en/index.html");
            assert!(!nav_allowed_for(Label::Help, &remote, Frame::Main, p));
        }
    }

    #[test]
    fn nav_policy_uses_this_builds_isolation_origin() {
        let context: tauri::Context<tauri::test::MockRuntime> =
            tauri::generate_context!(assets = tauri::test::noop_assets(), test = true);
        let origin = crate::csp::isolation_origin(context.pattern());
        assert!(origin.is_some(), "the isolation pattern is configured");
        let policy = NavPolicy::for_this_platform(origin.clone());
        let page = url(&format!("{}/index.html", origin.unwrap_or_default()));
        assert!(nav_allowed(&page, Frame::Sub, &policy));
        assert!(!nav_allowed(&page, Frame::Main, &policy));
    }

    fn locked(reason: LockedReason) -> AppSnapshot {
        AppSnapshot::Gate(GateState::Locked(reason))
    }

    #[test]
    fn route_relaunch_table() {
        let none = os(&["atlas-duck-app"]);
        let reopen: Vec<OsString> = Vec::new();
        let background = os(&["atlas-duck-app", "--background"]);
        let late_background = os(&["atlas-duck-app", "x", "--background"]);
        let error = "data directory /d not found".to_owned();
        let store_newer = gate_text(GateState::StoreNewer);
        let not_local = gate_text(GateState::Locked(LockedReason::KeyringNotLocal));
        assert_eq!(
            store_newer,
            "the audit store was written by a newer atlas-duck; upgrade atlas-duck"
        );
        assert_eq!(not_local, "atlas-duck is locked (keyring_not_local)");

        let table: Vec<(AppSnapshot, Relaunch)> = vec![
            (AppSnapshot::BeforeFirstRun, Relaunch::OpenSetup),
            (
                AppSnapshot::StartupError(error.clone()),
                Relaunch::ShowErrorDialog(error.clone()),
            ),
            (AppSnapshot::Starting, Relaunch::Defer),
            (AppSnapshot::Serving, Relaunch::OpenApprovals),
            (AppSnapshot::Gate(GateState::FirstRun), Relaunch::OpenSetup),
            (
                locked(LockedReason::KeychainUnavailable),
                Relaunch::OpenCredential(Unlock::Unlock),
            ),
            (
                locked(LockedReason::KeychainLost {
                    offer: RecoveryOffer::RecoverThisLog,
                }),
                Relaunch::OpenCredential(Unlock::Recover),
            ),
            (
                locked(LockedReason::KeychainLost {
                    offer: RecoveryOffer::FinishRestore,
                }),
                Relaunch::OpenCredential(Unlock::FinishRestore),
            ),
            (
                locked(LockedReason::KeyringNotLocal),
                Relaunch::ShowErrorDialog(not_local),
            ),
            (
                AppSnapshot::Gate(GateState::StoreNewer),
                Relaunch::ShowErrorDialog(store_newer),
            ),
            (
                AppSnapshot::StoreUnavailable,
                Relaunch::ShowErrorDialog("audit store could not be opened".into()),
            ),
            (
                AppSnapshot::Gate(GateState::StoreFailed),
                Relaunch::ShowErrorDialog("audit store could not be opened".into()),
            ),
            (AppSnapshot::ShuttingDown, Relaunch::Nothing),
            (
                AppSnapshot::Gate(GateState::ShuttingDown),
                Relaunch::Nothing,
            ),
        ];
        for (state, expected) in &table {
            assert_eq!(&route_relaunch(state, &none), expected, "{state:?} no args");
            assert_eq!(
                &route_relaunch(state, &reopen),
                expected,
                "{state:?} Reopen"
            );
            // Other arguments are still a GUI launch (classify_argv), e.g. macOS's `-psn_…`.
            assert_eq!(
                &route_relaunch(state, &os(&["atlas-duck-app", "-psn_0_1"])),
                expected,
                "{state:?} extra arg"
            );
            assert_eq!(
                route_relaunch(state, &background),
                Relaunch::Nothing,
                "{state:?} --background"
            );
            assert_eq!(route_relaunch(state, &late_background), Relaunch::Nothing);
            // Early-argv modes are never forwarded; if one were, it opens nothing.
            assert_eq!(
                route_relaunch(state, &os(&["atlas-duck-app", "__cli", "doctor"])),
                Relaunch::Nothing
            );

            // The cold start: the same path without `--background` (the data-dir errors were
            // shown by `apply_startup_state`), nothing under it.
            let cold = route_cold_start(state, false);
            match state {
                AppSnapshot::StartupError(_) => assert_eq!(cold, Relaunch::Nothing),
                _ => assert_eq!(&cold, expected, "{state:?} cold start"),
            }
            // The cold start under `--background` (autostart at login, §2.5): the wizard and the
            // locked-mode credential window open at startup anyway (L46, "also under
            // `--background`"); Approvals and the no-store error windows wait for the user.
            let quiet = match expected {
                Relaunch::OpenSetup | Relaunch::OpenCredential(_) => expected.clone(),
                _ => Relaunch::Nothing,
            };
            assert_eq!(
                route_cold_start(state, true),
                quiet,
                "{state:?} cold start --background"
            );
        }
        // Spelled out, so a changed row is seen: what a `--background` cold start opens.
        let opens = |state: &AppSnapshot| route_cold_start(state, true);
        assert_eq!(opens(&AppSnapshot::BeforeFirstRun), Relaunch::OpenSetup);
        assert_eq!(
            opens(&AppSnapshot::Gate(GateState::FirstRun)),
            Relaunch::OpenSetup
        );
        assert_eq!(
            opens(&locked(LockedReason::KeychainUnavailable)),
            Relaunch::OpenCredential(Unlock::Unlock)
        );
        assert_eq!(
            opens(&locked(LockedReason::KeychainLost {
                offer: RecoveryOffer::RecoverThisLog
            })),
            Relaunch::OpenCredential(Unlock::Recover)
        );
        for quiet in [
            AppSnapshot::Serving,
            AppSnapshot::Starting,
            AppSnapshot::StoreUnavailable,
            AppSnapshot::Gate(GateState::StoreNewer),
            locked(LockedReason::KeyringNotLocal),
            AppSnapshot::StartupError("x".into()),
        ] {
            assert_eq!(opens(&quiet), Relaunch::Nothing, "{quiet:?}");
        }
    }

    #[test]
    fn startup_route_defers_until_completion_once() {
        let mut route = StartupRoute::awaiting(true);
        assert!(route.defer_open(), "a relaunch during startup is kept");
        assert_eq!(route.complete(), Some(false), "it wins over --background");
        assert_eq!(route.complete(), None, "once");
        assert!(!route.defer_open(), "after completion: route at once");

        let mut cold = StartupRoute::awaiting(false);
        assert_eq!(cold.complete(), Some(false));
        let mut quiet = StartupRoute::awaiting(true);
        assert_eq!(quiet.complete(), Some(true));
        let mut done = StartupRoute::completed();
        assert!(!done.defer_open());
        assert_eq!(done.complete(), None);
    }

    #[test]
    fn serving_snapshot_reads_the_slot() {
        assert_eq!(serving_snapshot(None), AppSnapshot::Starting);
        let slot = ServeSlot::default();
        assert_eq!(serving_snapshot(Some(&slot)), AppSnapshot::Starting);
        slot.mark_store_failed();
        assert_eq!(serving_snapshot(Some(&slot)), AppSnapshot::StoreUnavailable);
        slot.quit().cancel();
        assert_eq!(serving_snapshot(Some(&slot)), AppSnapshot::ShuttingDown);
    }

    /// M6 T23: before first run the app is in the state the wizard's serving is in, once there is
    /// one (`tests/wizard.rs` covers the gate and the core).
    #[test]
    fn first_run_snapshot_follows_the_wizards_serving() {
        assert_eq!(first_run_snapshot(None), AppSnapshot::BeforeFirstRun);
        let slot = ServeSlot::default();
        assert_eq!(
            first_run_snapshot(Some(&slot)),
            AppSnapshot::BeforeFirstRun,
            "the start is still running"
        );
        slot.mark_store_failed();
        assert_eq!(
            first_run_snapshot(Some(&slot)),
            AppSnapshot::StoreUnavailable
        );
        slot.quit().cancel();
        assert_eq!(first_run_snapshot(Some(&slot)), AppSnapshot::ShuttingDown);
    }

    fn data_dir(tmp: &tempfile::TempDir) -> LocalDataDir {
        match check_data_dir(tmp.path()) {
            Ok(DataDirResolution::Local(data)) => data,
            other => panic!("{}: {other:?}", tmp.path().display()),
        }
    }

    #[test]
    fn credential_builder_incognito_or_own_dir() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let data = data_dir(&tmp);
        for windows in [false, true] {
            let specs: Vec<WindowSpec> = Label::ALL
                .into_iter()
                .map(|l| {
                    window_spec(l, Show::Focus, Some(&data), windows)
                        .unwrap_or_else(|e| panic!("{e:?}"))
                })
                .collect();
            let credential = specs
                .iter()
                .find(|s| s.label == Label::Credential)
                .unwrap_or_else(|| panic!("no credential spec"));
            assert!(credential.incognito, "credential is incognito");
            assert_eq!(
                credential.data_directory,
                Some(data.path().join("webview-credential"))
            );
            for other in specs.iter().filter(|s| s.label != Label::Credential) {
                assert_ne!(
                    other.data_directory, credential.data_directory,
                    "{:?} shares the credential data dir",
                    other.label
                );
                assert_eq!(other.data_directory, Some(webview_data_dir(&data)));
                assert!(!other.incognito, "{:?}", other.label);
                // One WebView2 environment per data dir: the same arguments everywhere.
                assert_eq!(other.browser_args, credential.browser_args);
            }
            for s in &specs {
                assert_eq!(s.devtools, DEVTOOLS_ALLOWED);
                assert_eq!(s.entry, s.label.entry());
                assert!(s.focused);
                match s.browser_args {
                    Some(args) => {
                        assert!(windows);
                        assert!(args.split(' ').any(|a| a == "--disable-crash-reporter"));
                        // wry's default switches survive the override.
                        assert!(args.contains(
                            "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection"
                        ));
                        assert!(!args.contains("remote-debugging"));
                    }
                    None => assert!(!windows),
                }
            }
        }
        // Before any data dir exists (first run) the credential window is refused (never the
        // shared default folder); every other window is incognito, with no data dir.
        for l in Label::ALL {
            let r = window_spec(l, Show::WithoutActivating, None, cfg!(windows));
            if l == Label::Credential {
                assert_eq!(r, Err(WindowError::NoDataDir));
                continue;
            }
            let s = r.unwrap_or_else(|e| panic!("{l:?}: {e:?}"));
            assert!(s.incognito && s.data_directory.is_none(), "{l:?}");
            assert!(!s.focused);
            // T19: the attention engine's "show and focus" takes the focus like a user's request.
            let unrequested = window_spec(l, Show::FocusUnrequested, None, cfg!(windows));
            assert_eq!(unrequested.map(|s| s.focused), Ok(true), "{l:?}");
        }
        #[cfg(not(debug_assertions))]
        assert!(!DEVTOOLS_ALLOWED);
    }

    #[test]
    fn webview_data_dirs_lists_both_folders() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let data = data_dir(&tmp);
        let mut want = vec![
            webview_data_dir(&data),
            data.path().join(CREDENTIAL_DATA_DIR),
        ];
        want.sort();
        assert_eq!(webview_data_dirs(&data), want);
    }

    #[test]
    fn labels_match_the_capability_files_and_entries() {
        let caps = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
        for l in Label::ALL {
            let file = caps.join(format!("{}.json", l.as_str()));
            let text = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
            let json: serde_json::Value =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(json["identifier"], l.as_str());
            assert_eq!(json["windows"], serde_json::json!([l.as_str()]));
            assert_eq!(Label::from_label(l.as_str()), Some(l));
            // The Help window's entry is a static guide page (M16), not a Vite input.
            let (entry, root) = if l == Label::Help {
                (l.entry().to_owned(), "../ui/public")
            } else {
                (format!("{}.html", l.as_str()), "../ui")
            };
            assert_eq!(l.entry(), entry);
            let ui = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(root)
                .join(l.entry());
            assert!(ui.is_file(), "{} has no UI entry", l.as_str());
        }
        assert_eq!(Label::from_label("main"), None);
        assert_eq!(Label::from_label("Approvals"), None);
    }

    #[test]
    fn hint_names_the_gnome_extension_verbatim() {
        for text in [MSG_NO_TRAY_HOST.en, MSG_NO_TRAY_HOST.de] {
            assert!(text.contains("\"AppIndicator and KStatusNotifierItem Support\""));
            assert!(text.contains("GNOME"));
        }
    }

    // `open` and the run loop under the mock runtime: `tests/windows_registry.rs` (the lib's
    // unit-test executable carries no Common-Controls v6 manifest, `build.rs`).
}
