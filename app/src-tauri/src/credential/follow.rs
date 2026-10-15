//! The credential window follows the serving state (§2.5, §8.7; M6 T22): when the keychain retry,
//! an unlock or an archive changes what is served behind the window's back, the tray is rebuilt
//! and an open lock-state window either moves to the purpose of the new lock state (the retry can
//! turn `keychain_unavailable` into `keychain_lost`, `credential_context_changed` tells the page)
//! or closes (the core serves now, or there is nothing left to unlock).

use tauri::{AppHandle, Manager, Runtime, Wry};

use super::{Purpose, context_changed, purpose_for_gate, registry};
use crate::serve::ServeWatcher;
use crate::state::ServeSlot;
use crate::windows::{AppSnapshot, Label, serving_snapshot};
use atlas_duck_core::GateState;

/// What an open lock-state window does when the serving state is `snapshot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Follow {
    /// Nothing to change (the same purpose, or a state that decides nothing yet).
    Leave,
    /// Nothing left to unlock: the window goes.
    Close,
    /// Another lock state: the window keeps open for its purpose.
    To(Purpose),
}

/// The pure rule. A PAT or first-run window is not a lock-state window and has its own life.
/// Startup and quit states decide nothing: the window stays as it is.
pub fn decide(current: &Purpose, snapshot: &AppSnapshot) -> Follow {
    if !current.is_lock_state() {
        return Follow::Leave;
    }
    match snapshot {
        AppSnapshot::BeforeFirstRun
        | AppSnapshot::StartupError(_)
        | AppSnapshot::Starting
        | AppSnapshot::ShuttingDown
        | AppSnapshot::Gate(GateState::ShuttingDown) => Follow::Leave,
        AppSnapshot::Gate(g) => match purpose_for_gate(*g) {
            Some(p) if p == *current => Follow::Leave,
            Some(p) => Follow::To(p),
            None => Follow::Close,
        },
        AppSnapshot::Serving | AppSnapshot::StoreUnavailable => Follow::Close,
    }
}

/// Moves or closes an open lock-state credential window per [`decide`]; never builds a window.
/// A window an unlock or archive is answering for (`ServeState::unlock_busy`) is not closed here:
/// that command closes it after its answer, so the page gets the answer first. Off the main
/// thread (it waits for `opening` and destroys the window).
pub fn follow_serving<R: Runtime>(app: &AppHandle<R>) {
    let Ok(r) = registry(app) else {
        return;
    };
    let Some(slot) = app.try_state::<ServeSlot>() else {
        return;
    };
    let snapshot = serving_snapshot(Some(&slot));
    let busy = slot.get().is_some_and(|s| s.unlock_busy());
    let announce = {
        let _no_open_in_between = r.lock_opening();
        if app.get_webview_window(Label::Credential.as_str()).is_none() {
            return;
        }
        let mut st = r.credential_state();
        let Some(current) = st.purpose.clone() else {
            return;
        };
        match decide(&current, &snapshot) {
            Follow::Leave => false,
            Follow::To(p) => {
                st.purpose = Some(p);
                true
            }
            Follow::Close => {
                if busy {
                    return;
                }
                st.reset();
                drop(st);
                if let Some(w) = app.get_webview_window(Label::Credential.as_str()) {
                    let _ = w.destroy();
                }
                false
            }
        }
    };
    if announce {
        context_changed(app);
    }
}

/// The app's [`ServeWatcher`]: the tray is rebuilt and the credential window follows, on the
/// blocking pool (both wait for the main thread).
pub struct AppWatcher {
    app: AppHandle<Wry>,
}

impl AppWatcher {
    pub fn new(app: AppHandle<Wry>) -> AppWatcher {
        AppWatcher { app }
    }
}

impl ServeWatcher for AppWatcher {
    fn serving_changed(&self) {
        let app = self.app.clone();
        tauri::async_runtime::spawn_blocking(move || {
            crate::tray::refresh(&app);
            follow_serving(&app);
        });
    }
}

#[cfg(test)]
mod tests {
    use atlas_duck_audit::{LockedReason, RecoveryOffer};

    use super::*;

    fn lost(offer: RecoveryOffer) -> AppSnapshot {
        AppSnapshot::Gate(GateState::Locked(LockedReason::KeychainLost { offer }))
    }

    /// m-5: the retry turning `keychain_unavailable` into `keychain_lost` moves an open Unlock
    /// window to "Recover this log"; the rest of the table.
    #[test]
    fn a_lock_window_follows_the_serving_state() {
        let unavailable = AppSnapshot::Gate(GateState::Locked(LockedReason::KeychainUnavailable));
        let target = super::super::PatTarget {
            alias: "a".into(),
            product: "jira",
            origin: "https://a.example".into(),
        };
        let table: Vec<(Purpose, AppSnapshot, Follow)> = vec![
            (
                Purpose::Unlock,
                lost(RecoveryOffer::RecoverThisLog),
                Follow::To(Purpose::RecoverThisLog),
            ),
            (
                Purpose::Unlock,
                lost(RecoveryOffer::FinishRestore),
                Follow::To(Purpose::FinishRestore),
            ),
            (
                Purpose::RecoverThisLog,
                unavailable.clone(),
                Follow::To(Purpose::Unlock),
            ),
            (Purpose::Unlock, unavailable.clone(), Follow::Leave),
            (
                Purpose::RecoverThisLog,
                lost(RecoveryOffer::RecoverThisLog),
                Follow::Leave,
            ),
            // The core serves (a retry or an unlock succeeded): nothing left to unlock.
            (Purpose::Unlock, AppSnapshot::Serving, Follow::Close),
            (Purpose::RecoverThisLog, AppSnapshot::Serving, Follow::Close),
            // `keyring_not_local`, `store_newer`, a failed store and first run: no unlock offered.
            (
                Purpose::Unlock,
                AppSnapshot::Gate(GateState::Locked(LockedReason::KeyringNotLocal)),
                Follow::Close,
            ),
            (
                Purpose::Unlock,
                AppSnapshot::Gate(GateState::StoreNewer),
                Follow::Close,
            ),
            (
                Purpose::Unlock,
                AppSnapshot::StoreUnavailable,
                Follow::Close,
            ),
            (
                Purpose::RecoverThisLog,
                AppSnapshot::Gate(GateState::FirstRun),
                Follow::Close,
            ),
            // Startup and quit decide nothing.
            (Purpose::Unlock, AppSnapshot::Starting, Follow::Leave),
            (Purpose::Unlock, AppSnapshot::ShuttingDown, Follow::Leave),
            (
                Purpose::Unlock,
                AppSnapshot::Gate(GateState::ShuttingDown),
                Follow::Leave,
            ),
            // A PAT or first-run window is none of this module's business.
            (
                Purpose::AddPat(target.clone()),
                AppSnapshot::Serving,
                Follow::Leave,
            ),
            (
                Purpose::ReplacePat(target),
                lost(RecoveryOffer::RecoverThisLog),
                Follow::Leave,
            ),
            (
                Purpose::RecoveryPassphrase,
                AppSnapshot::Gate(GateState::FirstRun),
                Follow::Leave,
            ),
        ];
        for (current, snapshot, want) in table {
            assert_eq!(
                decide(&current, &snapshot),
                want,
                "{current:?} / {snapshot:?}"
            );
        }
    }
}
