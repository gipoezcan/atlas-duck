// Release builds of the tray app have no console window on Windows (hence `--verify-export` is only
// an alias there, §12.1). The CLI and sandbox bins are console bins and do not carry this attribute.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::ffi::OsString;

use atlas_duck_app_lib::early_argv::{EarlyMode, classify_argv, verify_export_stub};
use atlas_duck_app_lib::startup::crash::apply_process_crash_settings;

fn main() {
    // §12.1 / §2.5 Scope: the early-argv modes run first, before the Tauri builder, the
    // single-instance plugin, startup hardening, the stderr redirect, the data-dir check and
    // `instance.lock`, and they keep their stdio. They never become a tray instance.
    let args: Vec<OsString> = std::env::args_os().collect();
    match classify_argv(&args) {
        EarlyMode::Cli(rest) => std::process::exit(atlas_duck_cli::run(rest)),
        EarlyMode::VerifyExport(rest) => std::process::exit(verify_export_stub(rest)),
        EarlyMode::Gui { background } => {
            // §2.5 Crash artifacts: GUI and `--background` launches only, before any webview.
            // The report is kept for later logging (`applied_report`); no failure blocks startup.
            let _ = apply_process_crash_settings();
            atlas_duck_app_lib::run_gui(background)
        }
    }
}
