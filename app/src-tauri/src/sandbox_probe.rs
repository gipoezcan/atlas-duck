//! §9.4 "On each app start": the startup probe. Since M14 (PD-247) the probe, its holder and its
//! labels live in `atlas-duck-script-glue` (re-exported here under the old paths); this module
//! keeps the Tauri part: the probe thread started from `setup`, its report put into `AppState`.

use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::thread::JoinHandle;

use atlas_duck_sandbox_host::probe::ProbeReport;
use tauri::Manager;

pub use atlas_duck_script_glue::probe::*;

use crate::state::AppState;

/// Starts the probe on a background thread named `atlas-duck-probe` and
/// returns at once. When it finishes, the report lands in
/// `AppState::probe` and one log line is written. Call it from `setup`,
/// after `AppState` is managed, in every startup state: the probe needs no
/// data dir, and its log line waits in the diagnostic log's memory buffer
/// until a data dir is attached.
///
/// Generic over the runtime so the mock runtime of `tauri::test` can drive
/// it; `run_gui` passes its `AppHandle` (the default `Wry`) unchanged.
pub fn spawn_startup_probe<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Err(e) = spawn_startup_probe_with(app, startup_job) {
        tracing::error!(
            event = LOG_EVENT_SANDBOX_PROBE,
            reason = "thread_spawn_failed",
            error_class = ?e.kind()
        );
    }
}

/// `spawn_startup_probe` with the probe job injected (tests use a gated job
/// to prove the caller is never blocked). Returns the thread handle.
pub fn spawn_startup_probe_with<R, F>(
    app: &tauri::AppHandle<R>,
    job: F,
) -> io::Result<JoinHandle<()>>
where
    R: tauri::Runtime,
    F: FnOnce() -> (ProbeReport, Option<AceEnsure>) + Send + 'static,
{
    let handle = app.clone();
    let holder = app.try_state::<AppState>().map(|s| s.probe.clone());
    spawn_marked(holder.as_deref(), || {
        std::thread::Builder::new()
            .name(PROBE_THREAD_NAME.to_owned())
            .spawn(move || {
                // A job that panics leaves no report: the waits for it end (fail closed) instead
                // of running out the bound, and the log says so.
                let Ok((report, ace)) = catch_unwind(AssertUnwindSafe(job)) else {
                    tracing::error!(event = LOG_EVENT_SANDBOX_PROBE, reason = "probe_panicked");
                    if let Some(state) = handle.try_state::<AppState>() {
                        state.probe.abandon();
                    }
                    return;
                };
                log_probe_report(&report, ace.as_ref());
                match handle.try_state::<AppState>() {
                    Some(state) => {
                        // The report is set once per process (R10: one probe per start, which
                        // the first script awaits through the same holder).
                        let _ = state.probe.set(report);
                        // `scripts_degraded` is derived from the report: the header re-reads.
                        crate::ui_sink::emit_status_changed(&handle);
                    }
                    None => tracing::warn!(
                        event = LOG_EVENT_SANDBOX_PROBE,
                        reason = "app_state_missing"
                    ),
                }
            })
    })
}
