//! S-16 Tauri half (Δ7, §13 Security "every Tauri command response and event payload (via a
//! test-build hook)"): the test build records every command response and every emitted event
//! through `core::testing::capture`, so a canary sweep searches one place. Compiled only with
//! `scripted-approver`; a release build has none of this.

use std::sync::Arc;

use atlas_duck_core::testing::capture::{Capture, Channel};
use serde::Serialize;
use serde_json::{Value, json};
use tauri::{AppHandle, Manager, Runtime};

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
