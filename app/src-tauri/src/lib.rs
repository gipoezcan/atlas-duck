//! `atlas-duck-app` library: early-argv classification and the GUI entry (§12.1, §2.5).

pub mod early_argv;

/// Runs the tray app for a GUI or `--background` launch (§2.5 Scope). Never returns.
///
/// Task 4: a bare Tauri builder with no windows (`app.windows = []`, no capabilities) and no tray.
/// Tasks 9 to 11 and 20 add crash settings, the startup gate, the plugins, the tray and the probe.
pub fn run_gui(background: bool) -> ! {
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
