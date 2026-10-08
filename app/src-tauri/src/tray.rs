//! Tray shell (§2.5): tray icon with a Quit item, tray-only lifecycle, the
//! single-instance and autostart plugins. All tray text is app-generated (§5.6).

use std::ffi::{OsStr, OsString};

use tauri::menu::{IsMenuItem, Menu, MenuEvent, MenuItem};
use tauri::plugin::TauriPlugin;
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, RunEvent, Runtime, Wry};

use crate::early_argv::FLAG_BACKGROUND;
use crate::startup::{StartupState, startup_message};

/// Id of the app's one tray icon.
pub const TRAY_ID: &str = "main";
/// Menu id of the Quit item.
pub const MENU_ID_QUIT: &str = "quit";
/// Menu id of the disabled status item shown in the startup error states (§7.7).
pub const MENU_ID_STATUS: &str = "status";
/// Label of the Quit item (app-generated constant, §5.6).
pub const MENU_LABEL_QUIT: &str = "Quit";

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

const MENU_ITEM_IDS: &[&str] = &[MENU_ID_QUIT];
const MENU_ITEM_IDS_WITH_STATUS: &[&str] = &[MENU_ID_STATUS, MENU_ID_QUIT];

/// What a tray menu item does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    /// M1: `app.exit(0)`. M3 replaces it with the §2.5 shutdown path.
    Quit,
}

/// Menu item ids in menu order. Without a status text the menu holds only Quit. With one
/// (the four startup error states) a disabled status item sits above Quit.
pub fn menu_item_ids(status: Option<&str>) -> &'static [&'static str] {
    if status.is_some() {
        MENU_ITEM_IDS_WITH_STATUS
    } else {
        MENU_ITEM_IDS
    }
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

/// Maps a menu id to its action; unknown ids do nothing.
pub fn action_for_menu_id(id: &str) -> Option<TrayAction> {
    match id {
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

/// The run-loop handler passed to `App::run`.
pub fn on_run_event<R: Runtime>(_app: &AppHandle<R>, event: RunEvent) {
    if let RunEvent::ExitRequested { code, api, .. } = event
        && should_prevent_exit(code)
    {
        api.prevent_exit();
    }
}

/// Builds the tray icon `TRAY_ID`. The menu is Quit; with `status` it gains a disabled item
/// with that text above Quit, and the tray tooltip carries the same text (Linux shows no
/// tooltip, so there the menu item is the place where the text appears, §2.5).
pub fn build_tray(app: &AppHandle, status: Option<&str>) -> tauri::Result<TrayIcon> {
    let status_item = status
        .map(|text| MenuItem::with_id(app, MENU_ID_STATUS, text, false, None::<&str>))
        .transpose()?;
    let quit = MenuItem::with_id(app, MENU_ID_QUIT, MENU_LABEL_QUIT, true, None::<&str>)?;
    let mut items: Vec<&dyn IsMenuItem<Wry>> = Vec::with_capacity(2);
    if let Some(item) = &status_item {
        items.push(item);
    }
    items.push(&quit);
    let menu = Menu::with_items(app, &items)?;
    let icon = app.default_window_icon().cloned().ok_or_else(|| {
        tauri::Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "bundle has no default window icon",
        ))
    })?;
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(on_menu_event);
    if let Some(text) = status {
        builder = builder.tooltip(text);
    }
    builder.build(app)
}

/// Builds the tray; a failure is logged as `event=tray_build_failed` and startup
/// continues (§2.5: the app must not depend on a tray host; §15 V33).
pub fn build_tray_or_log(app: &AppHandle, status: Option<&str>) {
    if build_tray(app, status).is_err() {
        tracing::warn!(
            event = LOG_EVENT_TRAY_BUILD_FAILED,
            error_class = "tauri_tray"
        );
    }
}

fn on_menu_event(app: &AppHandle, event: MenuEvent) {
    match action_for_menu_id(event.id().as_ref()) {
        Some(TrayAction::Quit) => app.exit(0),
        None => {}
    }
}

/// tauri-plugin-single-instance: forwards a relaunch to the running instance only
/// (§2.5). M1 logs `event=forwarded_launch` and nothing else (no argv, no cwd);
/// the GUI relaunch rule is M6.
pub fn single_instance_plugin<R: Runtime>() -> TauriPlugin<R> {
    tauri_plugin_single_instance::init(|_app, _argv, _cwd| {
        tracing::info!(event = LOG_EVENT_FORWARDED_LAUNCH);
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
    fn menu_holds_only_quit_without_a_status() {
        assert_eq!(menu_item_ids(None), &["quit"]);
        assert_eq!(MENU_ID_QUIT, "quit");
        assert_eq!(MENU_LABEL_QUIT, "Quit");
        assert_eq!(TRAY_ID, "main");
    }

    #[test]
    fn menu_gains_one_status_item_above_quit_with_a_status() {
        assert_eq!(MENU_ID_STATUS, "status");
        assert_eq!(menu_item_ids(Some("text")), &["status", "quit"]);
        assert_eq!(
            menu_item_ids(Some("text")).len(),
            menu_item_ids(None).len() + 1
        );
    }

    #[test]
    fn menu_ids_map_to_actions() {
        assert_eq!(action_for_menu_id("quit"), Some(TrayAction::Quit));
        assert_eq!(action_for_menu_id("Quit"), None);
        assert_eq!(action_for_menu_id(""), None);
        assert_eq!(
            action_for_menu_id(MENU_ID_STATUS),
            None,
            "the status item does nothing"
        );
        for id in menu_item_ids(None) {
            assert!(
                action_for_menu_id(id).is_some(),
                "menu id {id} has no action"
            );
        }
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
