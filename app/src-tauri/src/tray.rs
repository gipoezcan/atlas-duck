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
use crate::serve;
use crate::startup::{StartupState, startup_message};
use crate::state::AppState;
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
pub const MENU_LABEL_QUIT: &str = "Quit";
/// §2.5 (verbatim): "Open approvals (N)"; `<n>` is the pending count.
pub const MENU_LABEL_OPEN_APPROVALS: &str = "Open approvals (<n>)";
/// §2.5 (verbatim).
pub const MENU_LABEL_UNLOCK: &str = "Unlock…";
/// §5.6 (verbatim): switches to "badge only" without confirmation (T19).
pub const MENU_LABEL_PRESENTATION_MODE: &str = "Presentation mode";
/// plan text (PD-89).
pub const MENU_LABEL_RETRY_KEYCHAIN: &str = "Retry keychain";
/// plan text (T6): the tooltip outside the error states; `<n>` is the pending count.
pub const TOOLTIP_PENDING: &str = "atlas-duck: <n> pending";
/// plan text (T19): the tooltip's second line while Presentation mode is on (badge only, until the
/// same menu item switches it off).
pub const TOOLTIP_PRESENTATION: &str = "Presentation mode: badge only";
/// PD-06: the tray status text when the audit store could not be opened (plan text; no path,
/// no error text).
pub const MSG_STORE_UNAVAILABLE: &str = "audit store could not be opened";

/// Log event when the tray icon cannot be created (startup continues).
pub const LOG_EVENT_TRAY_BUILD_FAILED: &str = "tray_build_failed";
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

/// The status text the tray shows for `state`: the startup error text (§7.7) or the PD-06 text;
/// `None` otherwise (Task 22 adds the locked and no-store lines).
pub fn status_text(state: &AppSnapshot) -> Option<String> {
    match state {
        AppSnapshot::StartupError(text) => Some(text.clone()),
        AppSnapshot::StoreUnavailable => Some(MSG_STORE_UNAVAILABLE.to_owned()),
        _ => None,
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
/// item (error states), "Open approvals (N)" (always: it takes the GUI relaunch path), "Unlock…"
/// (locked), "Retry keychain" (`keychain_unavailable`), "Presentation mode" (while `Core` serves),
/// Quit.
pub fn menu_entries(state: &AppSnapshot, pending: u32) -> Vec<MenuEntry> {
    let mut entries = Vec::with_capacity(6);
    if let Some(text) = status_text(state) {
        entries.push(MenuEntry {
            id: MENU_ID_STATUS,
            label: text,
            enabled: false,
        });
    }
    entries.push(MenuEntry::item(
        MENU_ID_OPEN_APPROVALS,
        MENU_LABEL_OPEN_APPROVALS.replace("<n>", &pending.to_string()),
    ));
    if unlockable(state) {
        entries.push(MenuEntry::item(MENU_ID_UNLOCK, MENU_LABEL_UNLOCK));
    }
    if state == &AppSnapshot::Gate(GateState::Locked(LockedReason::KeychainUnavailable)) {
        entries.push(MenuEntry::item(
            MENU_ID_RETRY_KEYCHAIN,
            MENU_LABEL_RETRY_KEYCHAIN,
        ));
    }
    if state == &AppSnapshot::Serving {
        entries.push(MenuEntry::item(
            MENU_ID_PRESENTATION_MODE,
            MENU_LABEL_PRESENTATION_MODE,
        ));
    }
    entries.push(MenuEntry::item(MENU_ID_QUIT, MENU_LABEL_QUIT));
    entries
}

/// The tooltip: the status text when there is one (Linux shows no tooltip, so the status item
/// carries it there), else the pending count (§5.6 "The tray badge/tooltip always shows the
/// pending count"); a second line says while Presentation mode is on.
pub fn tooltip_text(status: Option<&str>, pending: u32, presentation: bool) -> String {
    let count = TOOLTIP_PENDING.replace("<n>", &pending.to_string());
    let mut text = match status {
        Some(text) => format!("{text}\n{count}"),
        None => count,
    };
    if presentation {
        text.push('\n');
        text.push_str(TOOLTIP_PRESENTATION);
    }
    text
}

/// The tray status text of a startup state: `startup_message(state)` for the four error
/// states (§7.7 "shows the error in the tray and a window"), `None` otherwise. It is the
/// same app-generated text the dialog shows, never agent- or file-supplied text (§5.6).
/// `AlreadyRunning` exits before any tray exists, so it has no tray text.
pub fn tray_status_text(state: &StartupState) -> Option<String> {
    match state {
        StartupState::DataDirMissing { .. }
        | StartupState::DataDirNotLocal { .. }
        | StartupState::DataDirUnusable { .. }
        | StartupState::PinnedUnreadable { .. } => startup_message(state),
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

/// `RunEvent::ExitRequested { code: None }` comes from the last window closing
/// (or the OS); the tray app keeps running. `Some(_)` comes from `AppHandle::exit`
/// (Quit) and is honoured.
pub fn should_prevent_exit(code: Option<i32>) -> bool {
    code.is_none()
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

/// The run-loop handler passed to `App::run`: a code-less exit request is prevented, a window
/// close hides the window ([`close_action`]), and macOS `RunEvent::Reopen` (Dock, Finder,
/// Spotlight) takes the GUI relaunch path (§2.5).
pub fn on_run_event<R: Runtime>(app: &AppHandle<R>, event: RunEvent) {
    match event {
        RunEvent::ExitRequested { code, api, .. } if should_prevent_exit(code) => {
            api.prevent_exit();
        }
        RunEvent::WindowEvent {
            label,
            event: WindowEvent::CloseRequested { api, .. },
            ..
        } if close_action(&label) == CloseAction::Hide => {
            api.prevent_close();
            if let Some(window) = app.get_webview_window(&label) {
                let _ = window.hide();
            }
        }
        // M6 T20: a destroyed credential window takes its purpose and a pending passphrase
        // request with it (the next one is built for its own purpose).
        RunEvent::WindowEvent {
            label,
            event: WindowEvent::Destroyed,
            ..
        } if label == Label::Credential.as_str() => crate::credential::window_destroyed(app),
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
    let status = status_text(&state);
    (
        menu_entries(&state, pending),
        tooltip_text(status.as_deref(), pending, attention::presentation_on(app)),
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
    let updated = tray_menu(app, &entries)
        .and_then(|menu| tray.set_menu(Some(menu)))
        .and_then(|()| tray.set_tooltip(Some(tooltip)));
    if updated.is_err() {
        tracing::warn!(
            event = LOG_EVENT_TRAY_BUILD_FAILED,
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
        Some(TrayAction::Quit) => serve::shutdown_then_exit(app, ShutdownReason::Quit),
        // The store write runs on the blocking pool (`toggle_presentation`).
        Some(TrayAction::PresentationMode) => attention::toggle_presentation(app),
        // Task 22 (PD-89) wires this.
        Some(TrayAction::RetryKeychain) | None => {}
    }
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
    use atlas_duck_audit::lock::InstanceLock;
    use atlas_duck_ipc::paths::{DataDirResolution, NotLocalKind, check_data_dir};
    use std::path::PathBuf;

    #[test]
    fn exit_is_prevented_only_without_code() {
        assert!(should_prevent_exit(None));
        assert!(!should_prevent_exit(Some(0)));
        assert!(!should_prevent_exit(Some(1)));
    }

    #[test]
    fn store_unavailable_text_is_the_plan_constant() {
        // PD-06: constant text, no path and no error text.
        assert_eq!(MSG_STORE_UNAVAILABLE, "audit store could not be opened");
        assert!(!MSG_STORE_UNAVAILABLE.contains('<'));
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
        assert_eq!(MENU_LABEL_QUIT, "Quit");
        assert_eq!(MENU_LABEL_UNLOCK, "Unlock\u{2026}");
        assert_eq!(MENU_LABEL_PRESENTATION_MODE, "Presentation mode");

        // Serving: the count, presentation mode, Quit.
        let serving = menu_entries(&AppSnapshot::Serving, 3);
        assert_eq!(
            ids(&serving),
            ["open_approvals", "presentation_mode", "quit"]
        );
        assert_eq!(serving[0].label, "Open approvals (3)");
        assert!(serving.iter().all(|e| e.enabled));
        assert_eq!(
            menu_entries(&AppSnapshot::Serving, 0)[0].label,
            "Open approvals (0)"
        );
        assert_eq!(
            menu_entries(&AppSnapshot::Serving, 1234)[0].label,
            "Open approvals (1234)"
        );

        // Locked: "Unlock…"; "Retry keychain" only while the keychain is unavailable.
        let unavailable = menu_entries(&locked(LockedReason::KeychainUnavailable), 6);
        assert_eq!(
            ids(&unavailable),
            ["open_approvals", "unlock", "retry_keychain", "quit"]
        );
        assert_eq!(unavailable[1].label, "Unlock\u{2026}");
        assert_eq!(unavailable[2].label, "Retry keychain");
        for offer in [RecoveryOffer::RecoverThisLog, RecoveryOffer::FinishRestore] {
            assert_eq!(
                ids(&menu_entries(
                    &locked(LockedReason::KeychainLost { offer }),
                    0
                )),
                ["open_approvals", "unlock", "quit"]
            );
        }
        // Nothing to unlock: no "Unlock…" (§8.7).
        assert_eq!(
            ids(&menu_entries(&locked(LockedReason::KeyringNotLocal), 0)),
            ["open_approvals", "quit"]
        );

        // The error states: a disabled status item above the rest.
        let error = menu_entries(
            &AppSnapshot::StartupError("data directory /d not found".into()),
            0,
        );
        assert_eq!(ids(&error), ["status", "open_approvals", "quit"]);
        assert_eq!(error[0].label, "data directory /d not found");
        assert!(!error[0].enabled);
        let failed = menu_entries(&AppSnapshot::StoreUnavailable, 0);
        assert_eq!(ids(&failed), ["status", "open_approvals", "quit"]);
        assert_eq!(failed[0].label, MSG_STORE_UNAVAILABLE);

        for state in [
            AppSnapshot::BeforeFirstRun,
            AppSnapshot::Starting,
            AppSnapshot::ShuttingDown,
            AppSnapshot::Gate(GateState::FirstRun),
            AppSnapshot::Gate(GateState::StoreNewer),
        ] {
            assert_eq!(
                ids(&menu_entries(&state, 0)),
                ["open_approvals", "quit"],
                "{state:?}"
            );
        }
    }

    #[test]
    fn tooltip_shows_the_pending_count() {
        assert_eq!(tooltip_text(None, 3, false), "atlas-duck: 3 pending");
        assert_eq!(
            tooltip_text(Some("audit store could not be opened"), 0, false),
            "audit store could not be opened\natlas-duck: 0 pending"
        );
        // Presentation mode adds one fixed line, after the count.
        assert_eq!(
            tooltip_text(None, 2, true),
            "atlas-duck: 2 pending\nPresentation mode: badge only"
        );
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
            for e in menu_entries(&state, 1).iter().filter(|e| e.enabled) {
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
            let text = tray_status_text(state);
            assert!(text.is_some(), "{state:?} has no tray text");
            assert_eq!(
                text,
                startup_message(state),
                "{state:?}: startup_message is the only text source (§5.6)"
            );
        }
        assert_eq!(
            tray_status_text(&states[0]).as_deref(),
            Some("data directory /some/data not found")
        );
    }

    #[test]
    fn status_text_is_none_when_there_is_no_startup_error() {
        assert_eq!(tray_status_text(&StartupState::BeforeFirstRun), None);
        // Exits before any tray exists, so it has no tray text even with a named host.
        let running = StartupState::AlreadyRunning {
            other_host: Some("otherhost".to_owned()),
        };
        assert_eq!(tray_status_text(&running), None);

        let tmp = tempfile::tempdir().expect("tempdir");
        let data = match check_data_dir(tmp.path()).expect("check_data_dir") {
            DataDirResolution::Local(data) => data,
            _ => panic!("{} is not a local data dir", tmp.path().display()),
        };
        let lock = InstanceLock::acquire(&data, "thishost").expect("lock");
        assert_eq!(tray_status_text(&StartupState::Ready { data, lock }), None);
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
