//! atlas-duck app library: the GUI / `--background` orchestration behind the three thin
//! `main`s (§12.1).

pub mod diag;
pub mod early_argv;
pub mod startup;
pub mod state;

use tauri::Manager;

use crate::startup::{DialogPresenter, StartupAction, StartupState};
use crate::state::{AppState, DataDirHold};

/// GUI and `--background` launches. Order (§2.5, §3.1, §7.7): crash settings (T09, in
/// `main.rs`, before this call) -> diagnostic log -> Tauri builder -> in `setup`: the
/// startup gate (pinned file -> data-dir check -> `instance.lock`).
pub fn run_gui(background: bool) -> ! {
    // §7.7: metadata-only diagnostic log, buffered in memory until the gate attaches the
    // checked data dir; payload-free panic hook.
    let diag = diag::Diag::init();
    diag::install_panic_hook(diag::PANIC_CATEGORY_APP);
    // M6 decides what a cold start without `--background` opens; M1 opens no window.
    let _ = background;

    let app = match tauri::Builder::default()
        // The dialog plugin serves Rust-side error dialogs only. The capability set is
        // empty (§10.3), so no webview can call its commands.
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            // After tauri-plugin-single-instance had its chance to forward a same-host
            // relaunch (T11 registers it before this plugin): only a launch that was not
            // forwarded reaches the lock.
            let (host, pinned) = startup::read_this_host_pinned();
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
            if let Some(summary) = state.summary() {
                app.manage(AppState { startup: summary });
            }
            if let StartupState::Ready { data, lock } = state {
                app.manage(DataDirHold::new(data, lock));
            }
            Ok(())
        })
        .build(tauri::generate_context!())
    {
        Ok(app) => app,
        Err(_) => {
            // A fixed line: the error value is never printed (it could carry paths).
            eprintln!("atlas-duck-app: failed to start the application shell");
            std::process::exit(1);
        }
    };
    app.run(|_handle, _event| {});
    std::process::exit(0)
}
