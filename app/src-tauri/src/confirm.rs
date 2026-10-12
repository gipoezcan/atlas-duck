//! The native confirmation dialog behind `NativeConfirmer` (§2.2). The text is built by the
//! core from app-known values; no webview is involved.

use atlas_duck_core::{Confirm, NativeConfirmer};
use tauri::AppHandle;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

/// Title of every confirmation dialog.
pub const DIALOG_TITLE: &str = "atlas-duck";

pub struct DialogConfirmer {
    app: AppHandle,
}

impl DialogConfirmer {
    pub fn new(app: AppHandle) -> DialogConfirmer {
        DialogConfirmer { app }
    }
}

/// The button the user pressed, as the core's answer.
pub fn answer(pressed_ok: bool) -> Confirm {
    if pressed_ok {
        Confirm::Ok
    } else {
        Confirm::Cancel
    }
}

impl NativeConfirmer for DialogConfirmer {
    /// Blocks until the user answers. The core calls it from a dedicated thread (M3 PD-13,
    /// PD-25), never from the main thread that draws the dialog.
    fn confirm(&self, text: &str) -> Confirm {
        debug_assert!(
            !is_main_thread(),
            "the confirmation dialog must not block the main thread"
        );
        let ok = self
            .app
            .dialog()
            .message(text)
            .title(DIALOG_TITLE)
            .buttons(MessageDialogButtons::OkCancel)
            .blocking_show();
        answer(ok)
    }
}

/// Best effort: the main thread is the one named "main" (Rust's main thread; the Tauri event
/// loop runs there on every desktop OS).
fn is_main_thread() -> bool {
    std::thread::current().name() == Some("main")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buttons_map_to_the_core_answer() {
        assert_eq!(answer(true), Confirm::Ok);
        assert_eq!(answer(false), Confirm::Cancel);
    }

    #[test]
    fn a_worker_thread_is_not_the_main_thread() {
        let named = std::thread::Builder::new()
            .name("atlas-duck-confirm".to_owned())
            .spawn(is_main_thread)
            .ok()
            .and_then(|h| h.join().ok());
        assert_eq!(named, Some(false));
    }
}
