//! `atlas-duck-app` library: early-argv classification and the GUI entry (§12.1, §2.5).

pub mod diag;
pub mod early_argv;
pub mod startup;

/// Runs the tray app for a GUI or `--background` launch (§2.5 Scope). Never returns.
///
/// Task 4: a bare Tauri builder with no windows (`app.windows = []`, no capabilities) and no tray.
/// Tasks 9 to 11 and 20 add crash settings, the startup gate, the plugins, the tray and the probe.
pub fn run_gui(background: bool) -> ! {
    // §7.7: metadata-only diagnostic log, buffered in memory until T10
    // attaches the checked data dir; payload-free panic hook (GUI and
    // `--background` only; `__cli` and `__verify-export` never get here).
    let _diag = diag::Diag::init();
    diag::install_panic_hook(diag::PANIC_CATEGORY_APP);
    // Task 11 consumes `background`: a `--background` launch opens and raises nothing (§2.5).
    let _ = background;
    let code = match tauri::Builder::default().build(tauri::generate_context!()) {
        Ok(app) => {
            app.run(|_handle, _event| {});
            0
        }
        Err(_) => {
            // A fixed line: the error value is never printed (it could carry paths).
            eprintln!("atlas-duck-app: failed to start the application shell");
            1
        }
    };
    std::process::exit(code)
}
