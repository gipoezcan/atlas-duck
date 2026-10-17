//! atlas-duck app library: the GUI / `--background` orchestration behind the three thin
//! `main`s (§12.1).

// §13: the headless test build (test home, file keystore, scripted approver, plain http to the
// mock) exists only in test builds; a release build must never carry it.
#[cfg(all(feature = "scripted-approver", not(debug_assertions)))]
compile_error!("scripted-approver must never reach a release build");

pub mod attention;
pub mod cli_install;
pub mod commands;
pub mod compose;
pub mod confirm;
pub mod credential;
pub mod csp;
pub mod diag;
pub mod early_argv;
pub mod os_hooks;
pub mod removal;
pub mod sandbox_probe;
pub mod script_glue;
pub mod secret_service;
pub mod serve;
pub mod startup;
pub mod state;
pub mod status;
#[cfg(feature = "scripted-approver")]
pub mod testing;
pub mod tray;
pub mod tray_host;
pub mod ui_sink;
pub mod windows;
pub mod wizard;

use std::sync::Arc;

use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_ipc::paths::{self, LocalDataDir, PinnedPaths};
use tauri::Manager;

use crate::startup::{DialogPresenter, StartupAction, StartupState};
use crate::state::{AppState, DataDirHold, ServeSlot};
use crate::tray_host::TrayHost;
use crate::windows::{NavPolicy, StartupRoute, WindowRegistry};
use crate::wizard::{ServeStarter, Wizard, WizardEnv};

/// The wizard's serving start (M6 T23): the one `Ready` uses (`serve::start`), with the same
/// keystore factory and, in the test build, the control dir and the scripted approver.
struct AppStarter {
    host: String,
    tray_host: Option<TrayHost>,
    keys: Arc<dyn serve::KeysFactory>,
}

impl ServeStarter<tauri::Wry> for AppStarter {
    fn start(
        &self,
        app: &tauri::AppHandle,
        data: LocalDataDir,
        lock: Arc<InstanceLock>,
        pinned: &PinnedPaths,
    ) {
        #[cfg(feature = "scripted-approver")]
        testing::spawn(app, &data);
        serve::start(
            app,
            data,
            lock,
            pinned,
            &self.host,
            self.tray_host,
            self.keys.clone(),
        );
    }
}

/// What the wizard takes from this host (§7.7): its pinned file, the default data and config dirs
/// (the pinned ones when startup read a pinned file), the Secret Service check, Rust's folder
/// dialog and the shared path functions. `None` when the base folders cannot be resolved (then
/// startup did not reach `BeforeFirstRun` either).
fn wizard_env(
    host: &str,
    pinned: Option<&PinnedPaths>,
    tray_host: Option<TrayHost>,
    keys: Arc<dyn serve::KeysFactory>,
) -> Option<WizardEnv<tauri::Wry>> {
    let (default_data_dir, config_dir) = match pinned {
        Some(p) => (p.data_dir.clone(), p.config_dir.clone()),
        None => {
            let base = paths::base_dirs().ok()?;
            // §7.7: XDG overrides are honoured only here, at first run, and then pinned.
            let d = paths::first_run_defaults(&base, &|name| std::env::var_os(name));
            (d.data_dir, d.config_dir)
        }
    };
    Some(WizardEnv {
        pinned_file: startup::this_host_pinned_file(host),
        default_data_dir,
        config_dir,
        host: host.to_owned(),
        secret_service: Arc::new(secret_service::CachedSecretService::new()),
        starter: Arc::new(AppStarter {
            host: host.to_owned(),
            tray_host,
            keys,
        }),
        pick_folder: Arc::new(|app: &tauri::AppHandle| wizard::pick_folder_dialog(app)),
        write_pinned: Arc::new(paths::write_pinned),
        check_dir: paths::check_data_dir,
        // What `OsKeyStore::locality` answers (no keyring call, §8.6).
        keyring_locality: Arc::new(|| match paths::keyring::keyring_dirs() {
            Ok(dirs) => paths::keyring::keyring_locality(&dirs),
            Err(e) => paths::keyring::KeyringLocality::Unknown {
                reason: e.to_string(),
            },
        }),
    })
}

/// GUI and `--background` launches. Order (§2.5, §3.1, §7.7): startup hardening and crash
/// settings (M6 T2, T09, in `main.rs`, before this call) -> diagnostic log -> Tauri builder -> in
/// `setup`: the startup gate (pinned file -> data-dir check -> `instance.lock`; in `Ready` it clears
/// the Crashpad reports before any webview).
pub fn run_gui(background: bool) -> ! {
    // T21 review I-1: the test build never starts against the real home, store or keychain.
    #[cfg(feature = "scripted-approver")]
    testing::require_test_home();
    // §7.7: metadata-only diagnostic log, buffered in memory until the gate attaches the
    // checked data dir; payload-free panic hook.
    let diag = diag::Diag::init();
    diag::install_panic_hook(diag::PANIC_CATEGORY_APP);
    // §2.5: one warning per scrubbed variable name and per failed mitigation (buffered until attach).
    if let Some(hardening) = startup::hardening::applied() {
        startup::hardening::log(hardening);
    }
    let mut context = tauri::generate_context!();
    // §6.4 (M6 T4): the main CSP's `frame-src` names this build's isolation origin.
    if csp::patch_context(&mut context).is_err() {
        eprintln!("atlas-duck-app: failed to start the application shell");
        std::process::exit(1);
    }
    // §6.4, §10.3 (M6 T6): navigation stays on the app origin; subframes may also load this
    // build's isolation origin (from the pattern, never a constant).
    let nav = NavPolicy::for_this_platform(csp::isolation_origin(context.pattern()));
    // The test build: apps of different test homes never forward to each other.
    #[cfg(feature = "scripted-approver")]
    testing::scope_identifier(context.config_mut());

    // single-instance first (research A0/F18), then autostart; the dialog plugin after them. The
    // command list (M6 T3) is the app manifest's (`build.rs`); no capability grants one yet.
    let app = match commands::register(tray::register_plugins(tauri::Builder::default()))
        // The dialog plugin serves Rust-side error dialogs only. The capability set is
        // empty (§10.3), so no webview can call its commands.
        .plugin(tauri_plugin_dialog::init())
        // The attention toast (§5.6, M6 T19) is sent from Rust (`attention::TauriNotifier`) only;
        // no capability grants the plugin's commands to a window.
        .plugin(tauri_plugin_notification::init())
        .setup(move |app| {
            // S-16 (test build only): command responses and event payloads are recorded, in a bounded\n            // ring buffer per channel (nothing drains it).
            #[cfg(feature = "scripted-approver")]
            commands::capture::install(app.handle(), commands::capture::bounded());

            // macOS menu-bar app, no Dock icon (§2.5).
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // CI-only autostart probe (§15 V14), before the startup gate so it needs no pinned
            // paths file. Linux, CI=true and ATLAS_DUCK_TEST_AUTOSTART_PROBE=1 only; `ci/appimage-smoke.sh` is the caller.
            #[cfg(target_os = "linux")]
            {
                let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
                let ci = std::env::var_os("CI");
                let gate = std::env::var_os(tray::ENV_AUTOSTART_PROBE);
                if tray::autostart_probe_requested(&argv, ci.as_deref(), gate.as_deref()) {
                    std::process::exit(tray::run_autostart_probe(app.handle()));
                }
            }

            // After tauri-plugin-single-instance had its chance to forward a same-host
            // relaunch (T11 registers it before this plugin): only a launch that was not
            // forwarded reaches the lock.
            let (host, pinned) = startup::read_this_host_pinned();
            // T19: serving needs the pinned config dir and install id; the gate consumes `pinned`.
            let pinned_paths = pinned.as_ref().ok().cloned().flatten();
            let state = startup::gate(pinned, &host);
            let presenter = DialogPresenter::new(app.handle().clone());
            if let StartupAction::Exit { message } =
                startup::apply_startup_state(&state, diag, &presenter)
            {
                // §3.1: a second instance exits immediately, after showing the
                // "running on another machine" text when the holder is on another host.
                match message {
                    Some(text) => presenter.show_then_exit(&text),
                    None => std::process::exit(0),
                }
                return Ok(());
            }
            // M6 T29 (§2.5, §15 V20): every OS end-session source (and Cmd+Q) takes the one
            // shutdown path, in every startup state that keeps the app running.
            os_hooks::install(app.handle());
            // The tray text, taken before the `Ready` arm below moves the state.
            let tray_status = tray::tray_status_text(&state);

            // Linux tray-host check (bounded by TRAY_HOST_TIMEOUT); the allowlist must know the
            // field before the line is written.
            diag.extend_allowed_fields(tray::LOG_FIELDS);
            let tray_host = tray_host::check_tray_host();
            tray_host::log_tray_host(tray_host);

            if let Some(summary) = state.summary() {
                app.manage(AppState::new(summary, tray_host).with_startup_text(tray_status));
            }
            // M6 T6: the window registry. In `Ready` the cold start opens its window once
            // `serve::start` finished (§2.5); in every other state nothing waits.
            diag.extend_allowed_fields(windows::LOG_FIELDS);
            let route = match state {
                StartupState::Ready { .. } => StartupRoute::awaiting(background),
                _ => StartupRoute::completed(),
            };
            app.manage(WindowRegistry::new(nav, route));
            // M6 T28: the one "Prepare for removal" procedure of this process (§12.5).
            app.manage(removal::RemovalState::default());
            let mut serve_args = None;
            let mut first_run = false;
            match state {
                StartupState::Ready { data, lock } => {
                    let lock = Arc::new(lock);
                    app.manage(DataDirHold::new(data.clone(), lock.clone()));
                    serve_args = Some((data, lock));
                }
                StartupState::BeforeFirstRun => first_run = true,
                _ => {}
            }
            #[cfg(not(feature = "scripted-approver"))]
            let keys: Arc<dyn serve::KeysFactory> = Arc::new(serve::OsKeysFactory);
            // PD-02: the file keystore when `ATLAS_DUCK_TEST_KEYSTORE` is set.
            #[cfg(feature = "scripted-approver")]
            let keys = testing::keys_factory();
            // M6 T23: the first-run wizard, before first run and in a pinned data dir (whose
            // first-run gate serves after an interrupted setup or an archived store). Managed before
            // the setup window can ask for it.
            if first_run || serve_args.is_some() {
                diag.extend_allowed_fields(serve::LOG_FIELDS);
                if let Some(env) = wizard_env(&host, pinned_paths.as_ref(), tray_host, keys.clone())
                {
                    app.manage(Wizard::new(env, pinned_paths.clone()));
                }
            }

            // T20: the §9.4 probe runs on its own thread, in every startup state that reaches
            // this point (AlreadyRunning returned above). It needs no data dir; its log line
            // waits in the diagnostic log's memory buffer until `Diag::attach_dir` runs. The
            // allowlist must know the six fields before the line is written.
            diag.extend_allowed_fields(sandbox_probe::PROBE_LOG_FIELDS);
            sandbox_probe::spawn_startup_probe(app.handle());

            // The tray is built in every startup state; in the four error states it also shows
            // the startup message (§7.7). A failure is logged and startup continues (§15 V33).
            tray::build_tray_or_log(app.handle());
            // §2.5: no tray host (Linux) → the one-time hint naming the GNOME extension.
            windows::show_no_tray_host_hint(app.handle());
            // §2.5 First run: the cold start opens the wizard (the setup window) at once.
            if first_run {
                let snapshot = windows::AppSnapshot::BeforeFirstRun;
                let action = windows::route_cold_start(&snapshot, background);
                let handle = app.handle().clone();
                tauri::async_runtime::spawn_blocking(move || windows::perform(&handle, action));
            }

            // T19 (PD-05): in `Ready`, open the store and serve IPC. `serve::start` returns at
            // once; the work runs on the async runtime, never on this (the main) thread.
            if let (Some((data, lock)), Some(pinned)) = (serve_args, pinned_paths.as_ref()) {
                app.manage(ServeSlot::default());
                #[cfg(feature = "scripted-approver")]
                testing::spawn(app.handle(), &data);
                serve::start(app.handle(), data, lock, pinned, &host, tray_host, keys);
            }
            Ok(())
        })
        .build(context)
    {
        Ok(app) => app,
        Err(_) => {
            // A fixed line: the error value is never printed (it could carry paths).
            eprintln!("atlas-duck-app: failed to start the application shell");
            std::process::exit(1);
        }
    };
    // The app exits only through the shutdown path (M6 T29, `os_hooks`): the exit request after
    // the last window closed is prevented, any other one runs the path, whose own `app.exit(0)` is
    // honoured. Closing a window hides it; macOS `Reopen` is a GUI relaunch (§2.5).
    app.run(tray::on_run_event);
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use std::alloc::{Layout, LayoutError, alloc};

    /// Plan M8 PD-134: the app links the worker crate, which only exports `ExitOnOomAlloc`; the
    /// app's global allocator stays the system one. With the worker's wrapper installed, the
    /// refused allocation below would end this test process with exit code 103 instead of
    /// returning null (with `ci/check-workspace.mjs` `GLOBAL_ALLOCATOR_FILES` this keeps the
    /// wrapper out of the app).
    #[test]
    fn app_global_allocator_is_not_the_worker_wrapper() -> Result<(), LayoutError> {
        // Larger than any address space: every system allocator refuses it at once.
        let layout = Layout::from_size_align(isize::MAX as usize, 1)?;
        // SAFETY: a non-zero size; the only possible block would be freed below, but the system
        // refuses this size, so `alloc` returns null and nothing is allocated.
        let block = unsafe { alloc(layout) };
        if !block.is_null() {
            // SAFETY: `block` came from `alloc` with this layout.
            unsafe { std::alloc::dealloc(block, layout) };
        }
        assert!(block.is_null());
        Ok(())
    }
}
