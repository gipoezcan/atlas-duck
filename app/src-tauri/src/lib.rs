//! atlas-duck app library: the GUI / `--background` orchestration behind the three thin
//! `main`s (§12.1).

// §13: the headless test build (test home, file keystore, scripted approver, plain http to the
// mock) exists only in test builds; a release build must never carry it.
#[cfg(all(feature = "scripted-approver", not(debug_assertions)))]
compile_error!("scripted-approver must never reach a release build");

pub mod commands;
pub mod compose;
pub mod confirm;
pub mod diag;
pub mod early_argv;
pub mod sandbox_probe;
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

use std::sync::Arc;

use tauri::Manager;

use crate::startup::{DialogPresenter, StartupAction, StartupState};
use crate::state::{AppState, DataDirHold, ServeSlot};

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
    // M6 decides what a cold start without `--background` opens; M1 opens no window.
    let _ = background;

    #[cfg_attr(not(feature = "scripted-approver"), allow(unused_mut))]
    let mut context = tauri::generate_context!();
    // The test build: apps of different test homes never forward to each other.
    #[cfg(feature = "scripted-approver")]
    testing::scope_identifier(context.config_mut());

    // single-instance first (research A0/F18), then autostart; the dialog plugin after them. The
    // command list (M6 T3) is the app manifest's (`build.rs`); no capability grants one yet.
    let app = match commands::register(tray::register_plugins(tauri::Builder::default()))
        // The dialog plugin serves Rust-side error dialogs only. The capability set is
        // empty (§10.3), so no webview can call its commands.
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            // S-16 (test build only): command responses and event payloads are recorded.
            #[cfg(feature = "scripted-approver")]
            commands::capture::install(
                app.handle(),
                atlas_duck_core::testing::capture::Capture::new(),
            );

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
            // The tray text, taken before the `Ready` arm below moves the state.
            let tray_status = tray::tray_status_text(&state);

            // Linux tray-host check (bounded by TRAY_HOST_TIMEOUT); the allowlist must know the
            // field before the line is written.
            diag.extend_allowed_fields(tray::LOG_FIELDS);
            let tray_host = tray_host::check_tray_host();
            tray_host::log_tray_host(tray_host);

            if let Some(summary) = state.summary() {
                app.manage(AppState::new(summary, tray_host));
            }
            let mut serve_args = None;
            if let StartupState::Ready { data, lock } = state {
                let lock = Arc::new(lock);
                app.manage(DataDirHold::new(data.clone(), lock.clone()));
                serve_args = Some((data, lock));
            }

            // T20: the §9.4 probe runs on its own thread, in every startup state that reaches
            // this point (AlreadyRunning returned above). It needs no data dir; its log line
            // waits in the diagnostic log's memory buffer until `Diag::attach_dir` runs. The
            // allowlist must know the six fields before the line is written.
            diag.extend_allowed_fields(sandbox_probe::PROBE_LOG_FIELDS);
            sandbox_probe::spawn_startup_probe(app.handle());

            // The tray is built in every startup state; in the four error states it also shows
            // the startup message (§7.7). A failure is logged and startup continues (§15 V33).
            tray::build_tray_or_log(app.handle(), tray_status.as_deref());

            // T19 (PD-05): in `Ready`, open the store and serve IPC. `serve::start` returns at
            // once; the work runs on the async runtime, never on this (the main) thread.
            if let (Some((data, lock)), Some(pinned)) = (serve_args, pinned_paths.as_ref()) {
                diag.extend_allowed_fields(serve::LOG_FIELDS);
                app.manage(ServeSlot::default());
                #[cfg(not(feature = "scripted-approver"))]
                let keys: Arc<dyn serve::KeysFactory> = Arc::new(serve::OsKeysFactory);
                // PD-02: the file keystore when `ATLAS_DUCK_TEST_KEYSTORE` is set.
                #[cfg(feature = "scripted-approver")]
                let keys = testing::keys_factory();
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
    // An exit request without a code (last window closed, OS) is prevented; Quit calls
    // `app.exit(0)`, which carries a code and is honoured.
    app.run(tray::on_run_event);
    std::process::exit(0)
}
