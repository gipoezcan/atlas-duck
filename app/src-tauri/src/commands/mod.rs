//! The command layer (C.10 + Δ1, §2.4, §10.3; PD-66): the only way a webview reaches Rust.
//!
//! Every command is `async` (Tauri runs a sync command on the main thread), takes its whole
//! invoke body as one typed argument struct (`dto::Args`, `deny_unknown_fields`, bounded newtypes)
//! and answers `Result<T, CommandError>`; synchronous core calls go through [`blocking`] (M3
//! PD-13). [`register`] is the one handler list, [`COMMANDS`] the one name list (`build.rs` turns
//! it into the app manifest, so a command outside a window's capability is refused by Tauri's ACL
//! before it gets here). Each response passes through [`finish`], which the test build records
//! (S-16, `capture`).

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod approvals;
mod blocking;
#[cfg(feature = "scripted-approver")]
pub mod capture;
pub mod credential;
pub mod dto;
mod errors;
mod names;
pub mod window;

use std::sync::Arc;

use atlas_duck_core::Core;
use serde::Serialize;
use tauri::{AppHandle, Builder, Manager, Runtime};

pub use blocking::blocking;
pub use errors::CommandError;
pub use names::COMMANDS;

use crate::state::ServeSlot;
use crate::status;
use dto::{AppStatusArgs, Args, StatusLineDto};

/// Registers every command of [`COMMANDS`] (one `generate_handler!` list; `lib.rs` and the
/// mock-runtime tests share it).
pub fn register<R: Runtime>(builder: Builder<R>) -> Builder<R> {
    builder.invoke_handler(tauri::generate_handler![
        app_status,
        approvals::acknowledge_attention,
        approvals::decide,
        approvals::decide_batch,
        approvals::deny_batch,
        approvals::deny_session,
        approvals::preview_fetch,
        approvals::queue_get,
        approvals::queue_list,
        approvals::raw_page,
        approvals::recent_list,
        approvals::redaction_preview,
        credential::archive_and_start_fresh,
        credential::credential_context,
        credential::retry_keychain,
        credential::save_recovery_note,
        credential::submit_secret,
        window::open_window,
        window::quit
    ])
}

/// The serving `Core`; `NotReady` before first run, while locked or starting, and when the store
/// could not be opened.
pub fn core<R: Runtime>(app: &AppHandle<R>) -> Result<Arc<Core>, CommandError> {
    app.try_state::<ServeSlot>()
        .and_then(|slot| slot.get().and_then(|s| s.core.get().cloned()))
        .ok_or(CommandError::NotReady)
}

/// Every command's response passes through here: the test build records it (S-16).
pub fn finish<R: Runtime, T: Serialize>(
    app: &AppHandle<R>,
    response: Result<T, CommandError>,
) -> Result<T, CommandError> {
    #[cfg(feature = "scripted-approver")]
    match &response {
        Ok(v) => capture::command(app, v),
        Err(e) => capture::command(app, e),
    }
    #[cfg(not(feature = "scripted-approver"))]
    let _ = app;
    response
}

/// `app_status {}` (Δ1, PD-90): the status lines the tray tooltip and the header banner show.
/// The inputs come from synchronous core calls, so they are gathered on the blocking pool.
#[tauri::command]
pub async fn app_status<R: Runtime>(
    app: AppHandle<R>,
    args: Args<AppStatusArgs>,
) -> Result<Vec<StatusLineDto>, CommandError> {
    let Args(AppStatusArgs {}) = args;
    let gather = app.clone();
    let response = blocking(move || Ok(status::lines(&status::gather(&gather)))).await;
    finish(&app, response)
}
