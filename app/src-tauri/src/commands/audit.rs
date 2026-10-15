//! The Audit window's one M6 command (C.10 + Δ1, PD-82, P8; M6 T30): `verify_now {}`. Granted to
//! `audit` only; the rest of the window (query, payloads, export, backup, incident
//! acknowledgement) is M10's.
//!
//! Core decides (`SettingsAdmin::verify_now`: a full verification that appends `VERIFY`; an error
//! is `did_not_complete`, never a pass); this layer runs it on the blocking pool and passes the
//! answer through: `{result, count?, text}` with the PD-82 text chosen in core, so the page never
//! maps a result to a sentence of its own.

use atlas_duck_core::VerifyNow;
use serde::Deserialize;
use tauri::{AppHandle, Runtime};

use super::dto::Args;
use super::{CommandError, blocking, core, finish};

/// `verify_now {}`: no key (the store is the one the app serves).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyNowArgs {}

/// `verify_now {}` (Δ1, §8.7 "Verify now"): runs the full verification once. A call while one runs
/// is the page's guard to stop; core serializes verification on the store's own lock anyway.
#[tauri::command]
pub async fn verify_now<R: Runtime>(
    app: AppHandle<R>,
    args: Args<VerifyNowArgs>,
) -> Result<VerifyNow, CommandError> {
    let Args(VerifyNowArgs {}) = args;
    let response = match core(&app) {
        Ok(core) => {
            let settings = core.settings();
            blocking(move || Ok(settings.verify_now())).await
        }
        Err(e) => Err(e),
    };
    finish(&app, response)
}
