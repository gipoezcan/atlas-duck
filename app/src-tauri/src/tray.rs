//! Tray shell (§2.5): the tray menu ("Open approvals (N)", "Unlock…", "Presentation mode",
//! "Retry keychain", Quit), the tray-only lifecycle (closing a window hides it, an exit without a
//! code is prevented), the single-instance and autostart plugins and the GUI relaunch they
//! forward. All tray text is app-generated (§5.6).

use std::ffi::{OsStr, OsString};

use atlas_duck_audit::LockedReason;
use atlas_duck_core::{GateState, ShutdownReason};
use tauri::menu::{IsMenuItem, Menu, MenuEvent, MenuItem};
use tauri::plugin::TauriPlugin;
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Manager, RunEvent, Runtime, WindowEvent, Wry};

use crate::attention;
use crate::early_argv::FLAG_BACKGROUND;
use crate::i18n::{Lang, T, count};
use crate::os_hooks;
use crate::serve;
use crate::startup::{StartupState, startup_message};
use crate::state::{AppState, ServeSlot};
use crate::status::{self, StatusInputs};
use crate::windows::{self, AppSnapshot, Label};

/// Id of the app's one tray icon.
pub const TRAY_ID: &str = "main";
/// Menu id of the Quit item.
pub const MENU_ID_QUIT: &str = "quit";
/// Menu id of the disabled status item shown in the startup error states (§7.7).
pub const MENU_ID_STATUS: &str = "status";
/// Menu id of "Open approvals (N)".
pub const MENU_ID_OPEN_APPROVALS: &str = "open_approvals";
/// Menu id of "Unlock…" (locked only).
pub const MENU_ID_UNLOCK: &str = "unlock";
/// Menu id of "Presentation mode" (T19: it toggles `attention::toggle_presentation`).
pub const MENU_ID_PRESENTATION_MODE: &str = "presentation_mode";
/// Menu id of "Retry keychain" (`keychain_unavailable` only; Task 22 wires it, PD-89).
pub const MENU_ID_RETRY_KEYCHAIN: &str = "retry_keychain";
/// Label of the Quit item (app-generated constant, §5.6).
pub const MENU_LABEL_QUIT: T = T::new("Quit", "Beenden");
/// §2.5 (verbatim): "Open approvals (N)"; `<n>` is the pending count.
pub const MENU_LABEL_OPEN_APPROVALS: T = T::new("Open approvals (<n>)", "Freigaben öffnen (<n>)");
/// §2.5 (verbatim).
pub const MENU_LABEL_UNLOCK: T = T::new("Unlock…", "Entsperren…");
/// §5.6 (verbatim): switches to "badge only" without confirmation (T19).
pub const MENU_LABEL_PRESENTATION_MODE: T = T::new("Presentation mode", "Präsentationsmodus");
/// plan text (PD-89).
pub const MENU_LABEL_RETRY_KEYCHAIN: T = T::new("Retry keychain", "Schlüsselbund erneut versuchen");
/// plan text (T6): the tooltip outside the error states; `<n>` is the pending count.
pub const TOOLTIP_PENDING: T = T::new("atlas-duck: <n> pending", "atlas-duck: <n> ausstehend");
/// plan text (T19): the tooltip's second line while Presentation mode is on (badge only, until the
/// same menu item switches it off).
pub const TOOLTIP_PRESENTATION: T = T::new(
    "Presentation mode: badge only",
    "Präsentationsmodus: nur Kennzeichen",
);
/// PD-06: the tray status text when the audit store could not be opened (plan text; no path,
/// no error text).
pub const MSG_STORE_UNAVAILABLE: T = T::new(
    "audit store could not be opened",
    "Der Audit-Speicher konnte nicht geöffnet werden",
);

/// The texts of this module, for [`crate::i18n::all`].
pub const TEXTS: &[&T] = &[
    &MENU_LABEL_QUIT,
    &MENU_LABEL_OPEN_APPROVALS,
    &MENU_LABEL_UNLOCK,
    &MENU_LABEL_PRESENTATION_MODE,
    &MENU_LABEL_RETRY_KEYCHAIN,
    &TOOLTIP_PENDING,
    &TOOLTIP_PRESENTATION,
    &MSG_STORE_UNAVAILABLE,
];

/// Log event when the tray icon cannot be created (startup continues).
pub const LOG_EVENT_TRAY_BUILD_FAILED: &str = "tray_build_failed";
/// Log event when the macOS menu-bar count could not be set (the tooltip and menu still show it).
pub const LOG_EVENT_TRAY_TITLE_FAILED: &str = "tray_title_failed";
/// Log event when tauri-plugin-single-instance forwards a second launch.
pub const LOG_EVENT_FORWARDED_LAUNCH: &str = "forwarded_launch";
/// Log event when the CI-only autostart probe cannot enable autostart.
pub const LOG_EVENT_AUTOSTART_PROBE_FAILED: &str = "autostart_probe_failed";
/// Diagnostic-log fields this task adds to the T08 allowlist.
pub const LOG_FIELDS: &[&str] = &["tray_host"];

/// Name of the autostart entry on every OS. `tauri-plugin-autostart` would otherwise take
/// `package_info().name`, which is `Atlas Duck` on Windows and macOS but `atlas-duck` on
/// Linux (T12 overrides `productName` there). The spec fixes no entry name.
pub const AUTOSTART_APP_NAME: &str = "atlas-duck";
/// CI-only flag: enable autostart once, then exit (Linux, `CI=true`; see `run_autostart_probe`).
pub const FLAG_AUTOSTART_PROBE: &str = "--autostart-probe";

/// What a tray menu item does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    /// The GUI relaunch path (§2.5): Approvals, or the window the state needs instead.
    OpenApprovals,
    /// The credential window for unlock; the same routing as a relaunch while locked.
    Unlock,
    /// T19: Presentation mode, on or off again (§5.6).
    PresentationMode,
    /// Task 22: one more keychain attempt (PD-89).
    RetryKeychain,
    /// The §2.5 shutdown path, then `app.exit(0)` (`serve::shutdown_then_exit`).
    Quit,
}

/// One tray menu item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuEntry {
    pub id: &'static str,
    pub label: String,
    pub enabled: bool,
}

impl MenuEntry {
    fn item(id: &'static str, label: impl Into<String>) -> MenuEntry {
        MenuEntry {
            id,
            label: label.into(),
            enabled: true,
        }
    }
}

/// The PD-90 status lines the tray shows (the others need the core and live in the Approvals
/// header): `locked_refused`, `setup_refused`, `waiting_keyring`, `updated_restart` (the glue's
/// flag lives in `AppState`, M8 Task 21), `store_newer`, `ipc_not_accepting`, `keychain_prompt`, and
/// the store-health lines of [`TRAY_HEALTH_LINE_IDS`] (T36b, §8.5: Settings and the tray).
/// Their text is `status::lines`' (§2.5 verbatim for the first three). `scripts_degraded` is not
/// here: it needs the core's setting, and the menu is built on the main thread without a core call.
pub const TRAY_LINE_IDS: [&str; 12] = [
    "locked_refused",
    "setup_refused",
    "waiting_keyring",
    "updated_restart",
    "store_newer",
    "ipc_not_accepting",
    "keychain_prompt",
    "storage_low",
    "anchor_write_failing",
    "anchor_dir_write_failing",
    "anchor_dir_lines_pending",
    "anchors_missing",
];

/// The part of [`TRAY_LINE_IDS`] built from the store-health snapshot (`AppState::health`, filled
/// from the same `StoreHealthView` the header reads). Shown only while `Core` serves: a locked or
/// starting app has no health to report.
pub const TRAY_HEALTH_LINE_IDS: [&str; 5] = [
    "storage_low",
    "anchor_write_failing",
    "anchor_dir_write_failing",
    "anchor_dir_lines_pending",
    "anchors_missing",
];

/// The menu ids of the disabled status items, in order; more lines than ids are dropped (the
/// tooltip carries them all).
pub const MENU_ID_STATUS_LINES: [&str; 4] = [MENU_ID_STATUS, "status_2", "status_3", "status_4"];

/// The status lines the tray shows for `state` (M6 T22): the startup error text (§7.7) or the PD-06
/// text (a store that could not be opened, or failed under a retry); otherwise the gate's lines
/// from `inputs` ("Locked — N requests refused", "Setup required — N requests refused",
/// "Waiting for keyring", the keychain prompt hint, the endpoint that is not accepting).
pub fn status_lines(state: &AppSnapshot, inputs: &StatusInputs) -> Vec<String> {
    let lang = inputs.lang;
    match state {
        AppSnapshot::StartupError(text) => vec![text.clone()],
        AppSnapshot::StoreUnavailable => vec![MSG_STORE_UNAVAILABLE.get(lang).to_owned()],
        _ => {
            let serving = state == &AppSnapshot::Serving;
            status::lines(inputs)
                .into_iter()
                .filter(|l| TRAY_LINE_IDS.contains(&l.id))
                .filter(|l| serving || !TRAY_HEALTH_LINE_IDS.contains(&l.id))
                .map(|l| l.text)
                .collect()
        }
    }
}

/// True when the credential window can unlock `state` (`keyring_not_local` has nothing to
/// unlock, §8.7).
fn unlockable(state: &AppSnapshot) -> bool {
    matches!(
        state,
        AppSnapshot::Gate(GateState::Locked(
            LockedReason::KeychainUnavailable | LockedReason::KeychainLost { .. }
        ))
    )
}

/// The tray menu for `state` with `pending` requests, in menu order (§2.5): the disabled status
/// items (`status`: [`status_lines`]), "Open approvals (N)" (always: it takes the GUI relaunch
/// path), "Unlock…" (locked), "Retry keychain" (`keychain_unavailable`; disabled while a retry
/// runs, `keychain_retrying`), "Presentation mode" (while `Core` serves), Quit.
pub fn menu_entries(
    lang: Lang,
    state: &AppSnapshot,
    pending: u32,
    status: &[String],
    keychain_retrying: bool,
) -> Vec<MenuEntry> {
    let mut entries = Vec::with_capacity(9);
    for (id, text) in MENU_ID_STATUS_LINES.iter().zip(status) {
        entries.push(MenuEntry {
            id,
            label: text.clone(),
            enabled: false,
        });
    }
    entries.push(MenuEntry::item(
        MENU_ID_OPEN_APPROVALS,
        MENU_LABEL_OPEN_APPROVALS
            .get(lang)
            .replace("<n>", &count(lang, u64::from(pending))),
    ));
    if unlockable(state) {
        entries.push(MenuEntry::item(MENU_ID_UNLOCK, MENU_LABEL_UNLOCK.get(lang)));
    }
    if state == &AppSnapshot::Gate(GateState::Locked(LockedReason::KeychainUnavailable)) {
        // PD-89: a retry the user may start is the one after the automatic schedule; while a retry
        // runs the entry is listed but disabled (a click would be a silent no-op).
        entries.push(MenuEntry {
            id: MENU_ID_RETRY_KEYCHAIN,
            label: MENU_LABEL_RETRY_KEYCHAIN.get(lang).to_owned(),
            enabled: !keychain_retrying,
        });
    }
    if state == &AppSnapshot::Serving {
        entries.push(MenuEntry::item(
            MENU_ID_PRESENTATION_MODE,
            MENU_LABEL_PRESENTATION_MODE.get(lang),
        ));
    }
    entries.push(MenuEntry::item(MENU_ID_QUIT, MENU_LABEL_QUIT.get(lang)));
    entries
}

/// The tooltip: the status lines when there are any (Linux shows no tooltip, so the status items
/// carry them there), then the pending count (§5.6 "The tray badge/tooltip always shows the
/// pending count"); a last line says while Presentation mode is on.
pub fn tooltip_text(lang: Lang, status: &[String], pending: u32, presentation: bool) -> String {
    let count = TOOLTIP_PENDING
        .get(lang)
        .replace("<n>", &count(lang, u64::from(pending)));
    let mut text = String::new();
    for line in status {
        text.push_str(line);
        text.push('\n');
    }
    text.push_str(&count);
    if presentation {
        text.push('\n');
        text.push_str(TOOLTIP_PRESENTATION.get(lang));
    }
    text
}

/// The macOS menu-bar title next to the tray icon (PD-173): the pending count, or none at 0. The
/// app is an `Accessory` app with no Dock tile, so this is its badge. Digits only: the text is
/// app-generated and carries no agent string (§5.6).
pub fn tray_title(pending: u32) -> Option<String> {
    (pending > 0).then(|| pending.to_string())
}

/// The tray status text of a startup state: `startup_message(state)` for the four error
/// states (§7.7 "shows the error in the tray and a window"), `None` otherwise. It is the
/// same app-generated text the dialog shows, never agent- or file-supplied text (§5.6).
/// `AlreadyRunning` exits before any tray exists, so it has no tray text.
pub fn tray_status_text(lang: Lang, state: &StartupState) -> Option<String> {
    match state {
        StartupState::DataDirMissing { .. }
        | StartupState::DataDirNotLocal { .. }
        | StartupState::DataDirUnusable { .. }
        | StartupState::PinnedUnreadable { .. } => startup_message(lang, state),
        StartupState::BeforeFirstRun
        | StartupState::Ready { .. }
        | StartupState::AlreadyRunning { .. } => None,
    }
}

/// Maps a menu id to its action; unknown ids (and the status item) do nothing.
pub fn action_for_menu_id(id: &str) -> Option<TrayAction> {
    match id {
        MENU_ID_OPEN_APPROVALS => Some(TrayAction::OpenApprovals),
        MENU_ID_UNLOCK => Some(TrayAction::Unlock),
        MENU_ID_PRESENTATION_MODE => Some(TrayAction::PresentationMode),
        MENU_ID_RETRY_KEYCHAIN => Some(TrayAction::RetryKeychain),
        MENU_ID_QUIT => Some(TrayAction::Quit),
        _ => None,
    }
}

/// What closing a window does (§2.5 "Closing windows hides them; the app exits only through the
/// shutdown path").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseAction {
    /// The window is hidden and keeps its state.
    Hide,
    /// The credential window is destroyed instead, so no typed, unsubmitted secret stays in a
    /// hidden webview (§10.1); Rust builds it again, incognito, when it is next needed. The app
    /// keeps running either way (the code-less exit request is prevented).
    Destroy,
}

/// The close rule per window label.
pub fn close_action(label: &str) -> CloseAction {
    if label == Label::Credential.as_str() {
        CloseAction::Destroy
    } else {
        CloseAction::Hide
    }
}

/// The run-loop handler passed to `App::run`. The app exits only through the shutdown path (§2.5,
/// M6 T29): the exit request that follows the last window closing is prevented, any other one
/// runs the path, and the path's own exit goes ahead (`os_hooks::exit_request`); a loop that ends
/// without the path runs it first (`os_hooks::on_loop_exit`). A window close hides the window
/// ([`close_action`]), and macOS `RunEvent::Reopen` (Dock, Finder, Spotlight) takes the GUI
/// relaunch path (§2.5).
pub fn on_run_event<R: Runtime>(app: &AppHandle<R>, event: RunEvent) {
    match event {
        // The guard decides (and starts the path when the request is a quit); an honoured request
        // falls through to `_`.
        RunEvent::ExitRequested { code, api, .. } if os_hooks::on_exit_requested(app, code) => {
            api.prevent_exit();
        }
        RunEvent::Exit => os_hooks::on_loop_exit(app),
        RunEvent::MainEventsCleared => os_hooks::path_of(app).note_loop_iteration(),
        RunEvent::WindowEvent {
            label,
            event: WindowEvent::CloseRequested { api, .. },
            ..
        } => match close_action(&label) {
            CloseAction::Hide => {
                api.prevent_close();
                if let Some(window) = app.get_webview_window(&label) {
                    let _ = window.hide();
                }
            }
            // Destroyed after this callback (the mock runtime reports no `Destroyed`).
            CloseAction::Destroy => os_hooks::path_of(app).note_window_destroyed(),
        },
        RunEvent::WindowEvent {
            label,
            event: WindowEvent::Destroyed,
            ..
        } => {
            os_hooks::path_of(app).note_window_destroyed();
            // M6 T20: a destroyed credential window takes its purpose and a pending passphrase
            // request with it (the next one is built for its own purpose).
            if label == Label::Credential.as_str() {
                crate::credential::window_destroyed(app);
            }
        }
        // PD-75: whenever the Approvals window gains the focus the page hears whether it was
        // requested. One the engine took (`Show::FocusUnrequested`) already announced
        // `requested: false`, and the page keeps the stricter of the two; any other (the user's
        // click, alt-tab, the tray) is the user's own.
        RunEvent::WindowEvent {
            label,
            event: WindowEvent::Focused(true),
            ..
        } => on_window_focused(app, &label),
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => windows::spawn_relaunch(app, Vec::new()),
        _ => {}
    }
}

/// Window `label` gained the focus. Only the Approvals page listens to `window_focus` (its inert
/// periods, PD-75); a focus nobody asked the engine for is the user's own: `requested: true`.
pub fn on_window_focused<R: Runtime>(app: &AppHandle<R>, label: &str) {
    if label == Label::Approvals.as_str() {
        crate::ui_sink::emit_window_focus(app, label, true);
    }
}

/// The current state, its menu and tooltip.
fn tray_view(app: &AppHandle) -> (Vec<MenuEntry>, String) {
    let state = windows::snapshot(app);
    let pending = app.try_state::<AppState>().map_or(0, |s| s.pending());
    // The gate's lines only: no core call (the menu is built on the main thread, too).
    let inputs = status::gather_gate(app);
    let status = status_lines(&state, &inputs);
    (
        menu_entries(
            inputs.lang,
            &state,
            pending,
            &status,
            inputs.keychain_retrying,
        ),
        tooltip_text(
            inputs.lang,
            &status,
            pending,
            attention::presentation_on(app),
        ),
    )
}

/// Builds the tray icon `TRAY_ID` with the menu and tooltip of the current state.
pub fn build_tray(app: &AppHandle) -> tauri::Result<TrayIcon> {
    let (entries, tooltip) = tray_view(app);
    let menu = tray_menu(app, &entries)?;
    let icon = app.default_window_icon().cloned().ok_or_else(|| {
        tauri::Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "bundle has no default window icon",
        ))
    })?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .menu(&menu)
        .tooltip(tooltip)
        .show_menu_on_left_click(true)
        .on_menu_event(on_menu_event)
        .build(app)
}

/// The menu of `entries`.
fn tray_menu(app: &AppHandle, entries: &[MenuEntry]) -> tauri::Result<Menu<Wry>> {
    let items = entries
        .iter()
        .map(|e| MenuItem::with_id(app, e.id, &e.label, e.enabled, None::<&str>))
        .collect::<tauri::Result<Vec<_>>>()?;
    let refs: Vec<&dyn IsMenuItem<Wry>> = items.iter().map(|i| i as &dyn IsMenuItem<Wry>).collect();
    Menu::with_items(app, &refs)
}

/// Rebuilds the menu and tooltip from the current state (after startup, on a pending-count
/// change). Callable from any thread (Tauri runs the menu calls on the main thread). Without a
/// tray, or on failure, it logs `event=tray_build_failed`.
pub fn refresh(app: &AppHandle) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        tracing::warn!(event = LOG_EVENT_TRAY_BUILD_FAILED, error_class = "no_tray");
        return;
    };
    let (entries, tooltip) = tray_view(app);
    let pending = app.try_state::<AppState>().map_or(0, |s| s.pending());
    let updated = tray_menu(app, &entries)
        .and_then(|menu| tray.set_menu(Some(menu)))
        .and_then(|()| tray.set_tooltip(Some(tooltip)));
    if updated.is_err() {
        tracing::warn!(
            event = LOG_EVENT_TRAY_BUILD_FAILED,
            error_class = "tauri_tray"
        );
    }
    // The menu-bar count is macOS's badge (PD-173); the other platforms ignore a title or show it
    // as a label next to the icon, which is not wanted there.
    if cfg!(target_os = "macos") && tray.set_title(tray_title(pending)).is_err() {
        tracing::warn!(
            event = LOG_EVENT_TRAY_TITLE_FAILED,
            error_class = "tauri_tray"
        );
    }
}

/// The pending count of "Open approvals (N)" and the tooltip (Task 19 calls it on queue changes).
pub fn set_pending(app: &AppHandle, pending: u32) {
    if let Some(state) = app.try_state::<AppState>() {
        state.set_pending(pending);
    }
    refresh(app);
}

/// Builds the tray; a failure is logged as `event=tray_build_failed` and startup
/// continues (§2.5: the app must not depend on a tray host; §15 V33).
pub fn build_tray_or_log(app: &AppHandle) {
    if build_tray(app).is_err() {
        tracing::warn!(
            event = LOG_EVENT_TRAY_BUILD_FAILED,
            error_class = "tauri_tray"
        );
    }
}

fn on_menu_event(app: &AppHandle, event: MenuEvent) {
    match action_for_menu_id(event.id().as_ref()) {
        // The menu handler runs on the main thread; the relaunch builds windows elsewhere.
        Some(TrayAction::OpenApprovals | TrayAction::Unlock) => {
            windows::spawn_relaunch(app, Vec::new());
        }
        Some(TrayAction::Quit) => {
            serve::shutdown_then_exit(app, ShutdownReason::Quit);
        }
        // The store write runs on the blocking pool (`toggle_presentation`).
        Some(TrayAction::PresentationMode) => attention::toggle_presentation(app),
        // PD-89: one more keystore + `open`; the watcher hears how it ended.
        Some(TrayAction::RetryKeychain) => retry_keychain(app),
        None => {}
    }
}

/// The tray's "Retry keychain" (PD-89): one more attempt through the retry loop's own path
/// (`serve::retry_keychain_now`). The menu handler runs on the main thread, and the retry spawns
/// onto the async runtime, so it goes through that runtime; the watcher rebuilds the tray when the
/// retry starts ("Waiting for keyring") and when the attempt ended.
fn retry_keychain(app: &AppHandle) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = serve::retry_keychain_from_menu(handle.try_state::<ServeSlot>().as_deref());
    });
}

/// tauri-plugin-single-instance: forwards a relaunch to the running instance only (§2.5). It
/// logs `event=forwarded_launch` (no argv, no cwd) and takes the GUI relaunch path with the
/// forwarded argv: no arguments open Approvals (or what the state needs), `--background` opens
/// nothing (§15 V33).
pub fn single_instance_plugin<R: Runtime>() -> TauriPlugin<R> {
    tauri_plugin_single_instance::init(|app, argv, _cwd| {
        tracing::info!(event = LOG_EVENT_FORWARDED_LAUNCH);
        windows::spawn_relaunch(app, argv.into_iter().map(OsString::from).collect());
    })
}

/// tauri-plugin-autostart with `--background` (§2.5) and the fixed entry name
/// `AUTOSTART_APP_NAME`. Registered only; the app never enables it by itself in M1
/// (enabling is a Settings/wizard action, M6). The one caller of `enable` is the CI-only
/// `--autostart-probe` path (`run_autostart_probe`).
pub fn autostart_plugin<R: Runtime>() -> TauriPlugin<R> {
    tauri_plugin_autostart::Builder::new()
        .app_name(AUTOSTART_APP_NAME)
        .args([FLAG_BACKGROUND])
        .build()
}

/// Second guard of the CI-only autostart probe: the scripts that call it export this as `1`.
pub const ENV_AUTOSTART_PROBE: &str = "ATLAS_DUCK_TEST_AUTOSTART_PROBE";

/// True iff `args` (argv, `args[0]` is the program) holds the exact `--autostart-probe`
/// flag after the program name, `ci` (the `CI` environment variable) is `true` and `gate`
/// (`ATLAS_DUCK_TEST_AUTOSTART_PROBE`) is `1`. The `CI` guard is the one
/// `ci/pinned-fixture.sh` uses; the second variable keeps a CI-hosted release binary from
/// acting on the flag unless the probe script asked for it.
pub fn autostart_probe_requested(
    args: &[OsString],
    ci: Option<&OsStr>,
    gate: Option<&OsStr>,
) -> bool {
    ci == Some(OsStr::new("true"))
        && gate == Some(OsStr::new("1"))
        && args
            .iter()
            .skip(1)
            .any(|a| a == OsStr::new(FLAG_AUTOSTART_PROBE))
}

/// Enables autostart once and returns the process exit code: 0 when the entry was
/// written, 1 otherwise (`event=autostart_probe_failed`). Called only from `setup` on
/// Linux when `autostart_probe_requested` holds. It exists so `ci/appimage-smoke.sh`
/// can read the entry the plugin writes (§15 V14); nothing else calls it.
pub fn run_autostart_probe<R: Runtime>(app: &AppHandle<R>) -> i32 {
    use tauri_plugin_autostart::ManagerExt;
    match app.autolaunch().enable() {
        Ok(()) => 0,
        Err(_) => {
            tracing::error!(
                event = LOG_EVENT_AUTOSTART_PROBE_FAILED,
                error_class = "autostart_enable"
            );
            1
        }
    }
}

/// Registers the T11 plugins first on a fresh builder: single-instance must be the
/// first plugin (research A0/F18), autostart second. T10's dialog plugin comes after.
pub fn register_plugins<R: Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    builder
        .plugin(single_instance_plugin())
        .plugin(autostart_plugin())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M15 T10 (Review Focus 1): Windows cuts a tray tooltip at 127 UTF-16 units. The German
    /// tooltip of the longest tray state still fits: the longest gate line, the pending count of a
    /// full queue and the Presentation-mode line.
    #[test]
    fn tray_tooltip_de_fits_127_utf16() {
        let gate = StatusInputs {
            gate: Some(GateState::Locked(LockedReason::KeychainUnavailable)),
            refused: 99_999,
            keychain_retrying: true,
            keychain_prompt: true,
            lang: Lang::De,
            ..StatusInputs::default()
        };
        let lines = status_lines(&locked(LockedReason::KeychainUnavailable), &gate);
        assert!(lines.len() >= 2, "{lines:?}");
        for line in &lines {
            let one = tooltip_text(Lang::De, std::slice::from_ref(line), 99_999, true);
            assert!(
                one.encode_utf16().count() <= 127,
                "{} > 127: {one}",
                one.encode_utf16().count()
            );
        }
        for t in TEXTS {
            assert!(t.de.encode_utf16().count() <= 127, "{t:?}");
        }
        for t in crate::status::TEXTS {
            assert!(t.de.encode_utf16().count() <= 127, "{t:?}");
        }
    }

    #[test]
    fn menu_and_tooltip_in_german() {
        let menu = menu_entries(Lang::De, &AppSnapshot::Serving, 1234, &[], false);
        let labels: Vec<&str> = menu.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(
            labels,
            ["Freigaben öffnen (1.234)", "Präsentationsmodus", "Beenden"]
        );
        assert_eq!(
            tooltip_text(Lang::De, &[], 3, true),
            "atlas-duck: 3 ausstehend\nPräsentationsmodus: nur Kennzeichen"
        );
        let ids_en: Vec<&str> = menu_entries(Lang::En, &AppSnapshot::Serving, 1, &[], false)
            .iter()
            .map(|e| e.id)
            .collect();
        let ids_de: Vec<&str> = menu.iter().map(|e| e.id).collect();
        assert_eq!(ids_en, ids_de, "the ids do not depend on the language");
    }
    use atlas_duck_audit::lock::InstanceLock;
    use atlas_duck_ipc::paths::{DataDirResolution, NotLocalKind, check_data_dir};
    use std::path::PathBuf;

    #[test]
    fn store_unavailable_text_is_the_plan_constant() {
        // PD-06: constant text, no path and no error text.
        assert_eq!(MSG_STORE_UNAVAILABLE.en, "audit store could not be opened");
        assert!(!MSG_STORE_UNAVAILABLE.en.contains('<'));
    }

    fn ids(entries: &[MenuEntry]) -> Vec<&'static str> {
        entries.iter().map(|e| e.id).collect()
    }

    fn locked(reason: LockedReason) -> AppSnapshot {
        AppSnapshot::Gate(GateState::Locked(reason))
    }

    #[test]
    fn tray_menu_items_per_state() {
        use atlas_duck_audit::RecoveryOffer;
        assert_eq!(TRAY_ID, "main");
        assert_eq!(MENU_LABEL_QUIT.en, "Quit");
        assert_eq!(MENU_LABEL_UNLOCK.en, "Unlock\u{2026}");
        assert_eq!(MENU_LABEL_PRESENTATION_MODE.en, "Presentation mode");

        // Serving: the count, presentation mode, Quit.
        let serving = menu_entries(Lang::En, &AppSnapshot::Serving, 3, &[], false);
        assert_eq!(
            ids(&serving),
            ["open_approvals", "presentation_mode", "quit"]
        );
        assert_eq!(serving[0].label, "Open approvals (3)");
        assert!(serving.iter().all(|e| e.enabled));
        assert_eq!(
            menu_entries(Lang::En, &AppSnapshot::Serving, 0, &[], false)[0].label,
            "Open approvals (0)"
        );
        assert_eq!(
            menu_entries(Lang::En, &AppSnapshot::Serving, 1234, &[], false)[0].label,
            "Open approvals (1234)"
        );

        // Locked: "Unlock…"; "Retry keychain" only while the keychain is unavailable.
        let unavailable = menu_entries(
            Lang::En,
            &locked(LockedReason::KeychainUnavailable),
            6,
            &[],
            false,
        );
        assert_eq!(
            ids(&unavailable),
            ["open_approvals", "unlock", "retry_keychain", "quit"]
        );
        assert_eq!(unavailable[1].label, "Unlock\u{2026}");
        assert_eq!(unavailable[2].label, "Retry keychain");
        assert!(unavailable[2].enabled);
        // While a retry runs the entry stays listed, disabled (PD-89: after the schedule).
        let running = menu_entries(
            Lang::En,
            &locked(LockedReason::KeychainUnavailable),
            6,
            &[],
            true,
        );
        assert_eq!(ids(&running), ids(&unavailable));
        assert!(!running[2].enabled);
        assert!(running[1].enabled, "Unlock stays usable");
        for offer in [RecoveryOffer::RecoverThisLog, RecoveryOffer::FinishRestore] {
            assert_eq!(
                ids(&menu_entries(
                    Lang::En,
                    &locked(LockedReason::KeychainLost { offer }),
                    0,
                    &[],
                    false
                )),
                ["open_approvals", "unlock", "quit"]
            );
        }
        // Nothing to unlock: no "Unlock…" (§8.7).
        assert_eq!(
            ids(&menu_entries(
                Lang::En,
                &locked(LockedReason::KeyringNotLocal),
                0,
                &[],
                false
            )),
            ["open_approvals", "quit"]
        );

        // The error states: a disabled status item above the rest.
        let state = AppSnapshot::StartupError("data directory /d not found".into());
        let error = menu_entries(
            Lang::En,
            &state,
            0,
            &status_lines(&state, &StatusInputs::default()),
            false,
        );
        assert_eq!(ids(&error), ["status", "open_approvals", "quit"]);
        assert_eq!(error[0].label, "data directory /d not found");
        assert!(!error[0].enabled);
        let state = AppSnapshot::StoreUnavailable;
        let failed = menu_entries(
            Lang::En,
            &state,
            0,
            &status_lines(&state, &StatusInputs::default()),
            false,
        );
        assert_eq!(ids(&failed), ["status", "open_approvals", "quit"]);
        assert_eq!(failed[0].label, MSG_STORE_UNAVAILABLE.en);

        // More lines than the four status items are dropped from the menu (the tooltip has all).
        let many: Vec<String> = (1..=6).map(|n| format!("line {n}")).collect();
        let crowded = menu_entries(Lang::En, &AppSnapshot::Serving, 0, &many, false);
        assert_eq!(
            ids(&crowded),
            [
                "status",
                "status_2",
                "status_3",
                "status_4",
                "open_approvals",
                "presentation_mode",
                "quit"
            ]
        );
        assert!(crowded[..4].iter().all(|e| !e.enabled));
        for id in MENU_ID_STATUS_LINES {
            assert_eq!(action_for_menu_id(id), None, "{id} does nothing");
        }

        for state in [
            AppSnapshot::BeforeFirstRun,
            AppSnapshot::Starting,
            AppSnapshot::ShuttingDown,
            AppSnapshot::Gate(GateState::FirstRun),
            AppSnapshot::Gate(GateState::StoreNewer),
        ] {
            assert_eq!(
                ids(&menu_entries(Lang::En, &state, 0, &[], false)),
                ["open_approvals", "quit"],
                "{state:?}"
            );
        }
    }

    #[test]
    fn tooltip_shows_the_pending_count() {
        assert_eq!(
            tooltip_text(Lang::En, &[], 3, false),
            "atlas-duck: 3 pending"
        );
        assert_eq!(
            tooltip_text(
                Lang::En,
                &["audit store could not be opened".to_owned()],
                0,
                false
            ),
            "audit store could not be opened\natlas-duck: 0 pending"
        );
        // Presentation mode adds one fixed line, after the count.
        assert_eq!(
            tooltip_text(Lang::En, &[], 2, true),
            "atlas-duck: 2 pending\nPresentation mode: badge only"
        );
        // Every status line, in order, above the count.
        assert_eq!(
            tooltip_text(Lang::En, &["a".to_owned(), "b".to_owned()], 1, false),
            "a\nb\natlas-duck: 1 pending"
        );
    }

    #[test]
    fn macos_tray_title_is_count_only() {
        assert_eq!(tray_title(0), None, "nothing pending: no title");
        assert_eq!(tray_title(1).as_deref(), Some("1"));
        assert_eq!(tray_title(7).as_deref(), Some("7"));
        assert_eq!(tray_title(120).as_deref(), Some("120"));
        for pending in [1, 9, 10, 99, 1000, u32::MAX] {
            let title = tray_title(pending).expect("a count");
            assert_eq!(title, pending.to_string());
            assert!(title.chars().all(|c| c.is_ascii_digit()), "{title}");
        }
    }

    fn gate_inputs(gate: GateState, refused: u64) -> StatusInputs {
        StatusInputs {
            gate: Some(gate),
            refused,
            ..StatusInputs::default()
        }
    }

    /// UI-04, §2.5: the tray's count follows every refused request ("Locked — N requests
    /// refused", app-generated text verbatim), in the lock states and before setup.
    #[test]
    fn ui04_tray_count_six() {
        let state = locked(LockedReason::KeychainUnavailable);
        for n in [0u64, 1, 6, 1234] {
            let inputs = gate_inputs(GateState::Locked(LockedReason::KeychainUnavailable), n);
            assert_eq!(
                status_lines(&state, &inputs),
                [format!("Locked \u{2014} {n} requests refused")]
            );
        }
        let inputs = gate_inputs(GateState::FirstRun, 6);
        assert_eq!(
            status_lines(&AppSnapshot::Gate(GateState::FirstRun), &inputs),
            ["Setup required \u{2014} 6 requests refused"]
        );
        // The count is in the menu and in the tooltip.
        let inputs = gate_inputs(GateState::Locked(LockedReason::KeychainUnavailable), 6);
        let lines = status_lines(&state, &inputs);
        let menu = menu_entries(Lang::En, &state, 0, &lines, false);
        assert_eq!(menu[0].id, MENU_ID_STATUS);
        assert_eq!(menu[0].label, "Locked \u{2014} 6 requests refused");
        assert!(!menu[0].enabled);
        assert!(
            tooltip_text(Lang::En, &lines, 0, false)
                .starts_with("Locked \u{2014} 6 requests refused\n")
        );
    }

    /// The other gate lines the tray carries (and only those): the keyring wait, the keychain
    /// prompt hint (L78), `store_newer`, the endpoint that does not accept (bind failure, M4 T19);
    /// the lines that need the core are the header's.
    #[test]
    fn the_tray_carries_the_gate_lines_only() {
        let unavailable = GateState::Locked(LockedReason::KeychainUnavailable);
        let state = locked(LockedReason::KeychainUnavailable);
        let waiting = StatusInputs {
            keychain_retrying: true,
            ..gate_inputs(unavailable, 2)
        };
        assert_eq!(
            status_lines(&state, &waiting),
            [
                "Locked \u{2014} 2 requests refused".to_owned(),
                "Waiting for keyring".to_owned()
            ]
        );
        // L78: the first `open` blocks before any state exists.
        let prompt = StatusInputs {
            keychain_prompt: true,
            ..StatusInputs::default()
        };
        assert_eq!(
            status_lines(&AppSnapshot::Starting, &prompt),
            ["waiting for keychain authorization"]
        );
        // M4 T19: a bind failure leaves a serving core that agents cannot reach.
        let unbound = StatusInputs {
            ipc_accepting: false,
            ..StatusInputs::default()
        };
        assert_eq!(
            status_lines(&AppSnapshot::Serving, &unbound),
            ["not accepting agent requests; see doctor"]
        );
        assert_eq!(
            status_lines(
                &AppSnapshot::Gate(GateState::StoreNewer),
                &gate_inputs(GateState::StoreNewer, 0)
            ),
            [status::TEXT_STORE_NEWER.en]
        );
        // Needs-attention, the degraded-scripts caution and the like need the core: not in the tray.
        let busy = StatusInputs {
            needs_attention: 3,
            scripts_degraded: true,
            ..StatusInputs::default()
        };
        assert!(status_lines(&AppSnapshot::Serving, &busy).is_empty());
        // §12.2 / PD-133: the update flag is app state, no core call: the tray carries it.
        let updated = StatusInputs {
            update_pending: true,
            ..StatusInputs::default()
        };
        assert_eq!(
            status_lines(&AppSnapshot::Serving, &updated),
            [status::TEXT_UPDATED_RESTART.en]
        );
        // The error states show their own text, whatever else is set.
        assert_eq!(
            status_lines(&AppSnapshot::StoreUnavailable, &waiting),
            [MSG_STORE_UNAVAILABLE.en]
        );
    }

    fn health_view() -> atlas_duck_core::StoreHealthView {
        atlas_duck_core::StoreHealthView {
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
        }
    }

    /// T36b item 1 (T21b review M-1, §8.5 "Settings and the tray"): while the core serves, the tray
    /// carries the store-health lines `status::lines` words for the header, with the very same
    /// texts: `storage_low`, `anchor_write_failing`, `anchor_dir_write_failing`,
    /// `anchor_dir_lines_pending` and `anchors_missing` (nothing else of the health: incidents and
    /// the prune backlog stay the header's). Outside the serving state they are not shown (the
    /// snapshot is the last one the core gave).
    #[test]
    fn the_tray_carries_the_store_health_lines_while_serving() {
        use atlas_duck_core::StoreHealthView;
        let inputs = |h: StoreHealthView| StatusInputs {
            health: Some(h),
            ..StatusInputs::default()
        };
        let text = |h: &StoreHealthView, id: &str| {
            status::lines(&inputs(h.clone()))
                .into_iter()
                .find(|l| l.id == id)
                .map(|l| l.text)
                .unwrap_or_else(|| panic!("status::lines has no {id}"))
        };
        let all = StoreHealthView {
            storage_low: true,
            anchor_write_failing: true,
            anchor_dir_write_failing: true,
            anchor_dir_lines_pending: 4,
            anchors_missing: Some("both"),
            open_incidents: 2,
            prune_backlog: Some("pruning is 3 days behind".into()),
            ..health_view()
        };
        let lines = status_lines(&AppSnapshot::Serving, &inputs(all.clone()));
        assert_eq!(
            lines,
            [
                text(&all, "storage_low"),
                text(&all, "anchor_write_failing"),
                text(&all, "anchor_dir_write_failing"),
                text(&all, "anchors_missing"),
            ],
            "same texts as the header, incidents and the prune backlog left out"
        );
        // Pending shows while nothing is failing.
        let pending = StoreHealthView {
            anchor_dir_lines_pending: 2,
            ..health_view()
        };
        assert_eq!(
            status_lines(&AppSnapshot::Serving, &inputs(pending.clone())),
            [text(&pending, "anchor_dir_lines_pending")]
        );
        // Nothing to report: no line.
        assert!(status_lines(&AppSnapshot::Serving, &inputs(health_view())).is_empty());
        // Not serving: the cached snapshot is not shown (a locked or starting app has no health).
        for state in [
            AppSnapshot::Starting,
            AppSnapshot::Gate(GateState::FirstRun),
            locked(LockedReason::KeychainUnavailable),
        ] {
            assert!(
                status_lines(&state, &inputs(all.clone()))
                    .iter()
                    .all(|l| !l.contains("anchor") && !l.contains("storage")),
                "{state:?}"
            );
        }
        // The menu has room for four status items; the tooltip carries every line.
        let menu = menu_entries(Lang::En, &AppSnapshot::Serving, 0, &lines, false);
        assert_eq!(menu.iter().filter(|e| !e.enabled).count(), 4);
        for line in &lines {
            assert!(tooltip_text(Lang::En, &lines, 0, false).contains(line.as_str()));
        }
    }

    #[test]
    fn menu_ids_map_to_actions() {
        assert_eq!(action_for_menu_id("quit"), Some(TrayAction::Quit));
        assert_eq!(
            action_for_menu_id("open_approvals"),
            Some(TrayAction::OpenApprovals)
        );
        assert_eq!(action_for_menu_id("unlock"), Some(TrayAction::Unlock));
        assert_eq!(
            action_for_menu_id("presentation_mode"),
            Some(TrayAction::PresentationMode)
        );
        assert_eq!(
            action_for_menu_id("retry_keychain"),
            Some(TrayAction::RetryKeychain)
        );
        assert_eq!(action_for_menu_id("Quit"), None);
        assert_eq!(action_for_menu_id(""), None);
        assert_eq!(
            action_for_menu_id(MENU_ID_STATUS),
            None,
            "the status item does nothing"
        );
        // Every enabled item of every state has an action.
        for state in [
            AppSnapshot::Serving,
            locked(LockedReason::KeychainUnavailable),
            AppSnapshot::StoreUnavailable,
        ] {
            for e in menu_entries(Lang::En, &state, 1, &[], false)
                .iter()
                .filter(|e| e.enabled)
            {
                assert!(action_for_menu_id(e.id).is_some(), "{} has no action", e.id);
            }
        }
    }

    /// The close rule; `tests/windows_registry.rs::close_hides_never_exits_under_the_run_loop`
    /// drives `on_run_event` through the mock runtime's event loop (the lib's unit-test
    /// executable carries no Common-Controls v6 manifest, `build.rs`).
    #[test]
    fn close_hides_never_exits() {
        for label in Label::ALL {
            let want = if label == Label::Credential {
                CloseAction::Destroy
            } else {
                CloseAction::Hide
            };
            assert_eq!(close_action(label.as_str()), want, "{label:?}");
        }
        assert_eq!(close_action("unknown"), CloseAction::Hide);
    }

    #[test]
    fn status_text_is_the_startup_message_in_the_four_error_states() {
        let path = PathBuf::from("/some/data");
        let states = [
            StartupState::DataDirMissing { path: path.clone() },
            StartupState::DataDirNotLocal {
                path: path.clone(),
                kind: NotLocalKind::Unc,
            },
            StartupState::DataDirUnusable { path: path.clone() },
            StartupState::PinnedUnreadable { path: path.clone() },
        ];
        for state in &states {
            let text = tray_status_text(Lang::En, state);
            assert!(text.is_some(), "{state:?} has no tray text");
            assert_eq!(
                text,
                startup_message(Lang::En, state),
                "{state:?}: startup_message is the only text source (§5.6)"
            );
        }
        assert_eq!(
            tray_status_text(Lang::En, &states[0]).as_deref(),
            Some("data directory /some/data not found")
        );
    }

    #[test]
    fn status_text_is_none_when_there_is_no_startup_error() {
        assert_eq!(
            tray_status_text(Lang::En, &StartupState::BeforeFirstRun),
            None
        );
        // Exits before any tray exists, so it has no tray text even with a named host.
        let running = StartupState::AlreadyRunning {
            other_host: Some("otherhost".to_owned()),
        };
        assert_eq!(tray_status_text(Lang::En, &running), None);

        let tmp = tempfile::tempdir().expect("tempdir");
        let data = match check_data_dir(tmp.path()).expect("check_data_dir") {
            DataDirResolution::Local(data) => data,
            _ => panic!("{} is not a local data dir", tmp.path().display()),
        };
        let lock = InstanceLock::acquire(&data, "thishost").expect("lock");
        assert_eq!(
            tray_status_text(Lang::En, &StartupState::Ready { data, lock }),
            None
        );
    }

    #[test]
    fn autostart_uses_background_flag() {
        assert_eq!(crate::early_argv::FLAG_BACKGROUND, "--background");
    }

    #[test]
    fn log_fields_name_tray_host() {
        assert_eq!(LOG_FIELDS, &["tray_host"]);
    }

    #[test]
    fn autostart_entry_name_is_one_value_on_every_os() {
        // Not derived from productName ("Atlas Duck" vs "atlas-duck" on Linux, T12).
        assert_eq!(AUTOSTART_APP_NAME, "atlas-duck");
    }

    #[test]
    fn autostart_probe_needs_the_flag_and_ci_true() {
        let probe = |items: &[&str], ci: Option<&str>| {
            let argv: Vec<OsString> = items.iter().map(OsString::from).collect();
            autostart_probe_requested(&argv, ci.map(OsStr::new), Some(OsStr::new("1")))
        };
        assert_eq!(FLAG_AUTOSTART_PROBE, "--autostart-probe");
        assert!(probe(&["app", "--autostart-probe"], Some("true")));
        assert!(probe(
            &["app", "--background", "--autostart-probe"],
            Some("true")
        ));
        assert!(!probe(&["app", "--autostart-probe"], None));
        assert!(!probe(&["app", "--autostart-probe"], Some("1")));
        assert!(!probe(&["app", "--background"], Some("true")));
        assert!(!probe(&["app", "--autostart-probe=1"], Some("true")));
        // argv[0] is the program, never a flag.
        assert!(!probe(&["--autostart-probe"], Some("true")));
        assert!(!probe(&[], Some("true")));
        // The second guard: CI=true alone is not enough.
        let argv = [OsString::from("app"), OsString::from("--autostart-probe")];
        let ci = Some(OsStr::new("true"));
        assert!(!autostart_probe_requested(&argv, ci, None));
        assert!(!autostart_probe_requested(
            &argv,
            ci,
            Some(OsStr::new("true"))
        ));
        assert!(!autostart_probe_requested(&argv, ci, Some(OsStr::new("0"))));
        assert_eq!(ENV_AUTOSTART_PROBE, "ATLAS_DUCK_TEST_AUTOSTART_PROBE");
    }
}
