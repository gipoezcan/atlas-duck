//! S-16 Tauri half (Δ7, §13 Security "every Tauri command response and event payload (via a
//! test-build hook)"): the test build records every command response and every emitted event
//! through `core::testing::capture`, so a canary sweep searches one place. Compiled only with
//! `scripted-approver`; a release build has none of this.

use std::sync::Arc;

use atlas_duck_core::testing::capture::{Capture, Channel, Limits};
use serde::Serialize;
use serde_json::{Value, json};
use tauri::{AppHandle, Manager, Runtime};

/// The cap per channel of the app's recorder. The app records for its whole life and nothing
/// drains it, so each channel is a ring buffer: the newest 1 024 records or 32 MiB of JSON
/// (`raw_page` and `preview_fetch` responses are up to 4 MiB each), whichever is hit first;
/// older ones are dropped and counted (`Capture::dropped`). A sweep that must see every record
/// asserts `dropped(..) == 0` first.
pub const LIMITS: Limits = Limits {
    max_records: 1024,
    max_bytes: 32 << 20,
};

/// The bounded recorder the test-build app installs.
pub fn bounded() -> Arc<Capture> {
    Capture::bounded(LIMITS)
}

/// The recorder an app instance writes to (managed state).
pub struct TauriCapture(pub Arc<Capture>);

/// Makes `cap` the recorder of `app`; false when one was installed already (the first stays).
pub fn install<R: Runtime>(app: &AppHandle<R>, cap: Arc<Capture>) -> bool {
    app.manage(TauriCapture(cap))
}

/// The recorder of `app`, if one is installed.
pub fn of<R: Runtime>(app: &AppHandle<R>) -> Option<Arc<Capture>> {
    app.try_state::<TauriCapture>().map(|c| c.0.clone())
}

/// One command response, as the webview receives it (the `Ok` value or the error).
pub fn command<R: Runtime, T: Serialize + ?Sized>(app: &AppHandle<R>, response: &T) {
    if let Some(cap) = of(app) {
        cap.record(Channel::TauriCommand, response);
    }
}

/// One emitted event: `{event, payload}`.
pub fn event<R: Runtime>(app: &AppHandle<R>, name: &str, payload: &Value) {
    if let Some(cap) = of(app) {
        cap.record(
            Channel::TauriEvent,
            &json!({ "event": name, "payload": payload }),
        );
    }
}
