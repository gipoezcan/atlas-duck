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
    // The test build only: the OS keychain served to the `os_keychain_smoke` harness, so the
    // entries the app reads were written by this executable (never in a release build).
    #[cfg(feature = "scripted-approver")]
    if let Some(code) = atlas_duck_app_lib::testing::os_keystore_proxy::run_if_requested(&args) {
        std::process::exit(code);
    }
    match classify_argv(&args) {
        EarlyMode::Cli(rest) => std::process::exit(atlas_duck_cli::run(rest)),
        EarlyMode::VerifyExport(rest) => std::process::exit(verify_export_stub(rest)),
        EarlyMode::Gui { background } => {
            // PD-33: before any other thread exists; `__cli` and `__verify-export` keep glibc's default.
            let _ = atlas_duck_app_lib::compose::set_mmap_threshold();
            // §2.5 Crash artifacts: GUI and `--background` launches only, before any webview.
            // The report is kept for later logging (`applied_report`); no failure blocks startup.
            let _ = apply_process_crash_settings();
            atlas_duck_app_lib::run_gui(background)
        }
    }
}
