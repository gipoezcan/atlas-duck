//! The credential-entry window, Rust side (§10.3, §7.1, §8.6, §8.7; C.10 + Δ1; M6 T20).
//!
//! Rust fixes what the window is for when it opens it ([`Purpose`], kept in the
//! `WindowRegistry` under its `opening` lock) and never takes it from the triggering window: a
//! settings page can ask for "the PAT of alias A", but the alias, product and normalized base URL
//! the window shows and tests against are the ones Rust read from the instance table then
//! ([`PatTarget`]). While the window is open its purpose stays; another request is refused
//! ([`WindowError::Busy`]), except that the lock states may follow each other (the keychain retry
//! can move `keychain_unavailable` to `keychain_lost`), which re-announces the context
//! (`credential_context_changed`).
//!
//! Secrets enter only through `submit_secret` (`commands::credential`) as `secrecy::SecretString`
//! and leave Rust never: a PAT goes to `InstanceAdmin::set_token`, the first-run recovery
//! passphrase to the wizard through [`request_recovery_passphrase`]'s in-memory channel (Task 23),
//! the passphrase of "Recover this log" / "Finish restore" to the audit store
//! (`serve::unlock`), a backup's passphrase to the waiting restore (M10 T13), and the new
//! recovery passphrase of Settings' "Change recovery passphrase…" to
//! `Store::change_recovery_passphrase` (M10 T14). The recovery note ([`note_text`]) is built from
//! facts that hold no secret.
//!
//! The window also follows what is served behind its back ([`follow`], M6 T22: the retry turning
//! one lock state into another, a core that started) and a gate's refused requests raise it at
//! most once per 5 minutes ([`raise`], UI-04).

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod follow;
pub mod raise;

use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

use atlas_duck_audit::{ArchivedDb, LockedReason, RecoveryOffer};
use atlas_duck_core::config::instances::product_str;
use atlas_duck_core::{AdminError, GateState, InstanceView, UiEvent};
use secrecy::{ExposeSecret, SecretString};
use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::oneshot;

use crate::i18n::Lang;
use crate::ui_sink::{EventOut, emit_wizard_changed, wire};
use crate::windows::{self, Label, Show, Unlock, WindowError, WindowRegistry};

/// The minimum length of the recovery passphrase in characters (§8.6; the audit store counts the
/// NFC form and has the last word when it wraps the KEK).
pub use atlas_duck_audit::MIN_PASSPHRASE_CHARS;

/// §8.6 (verbatim): the one fixed line that states the recovery passphrase's purpose, shown at
/// entry and printed at the top of the recovery note.
pub const PASSPHRASE_PURPOSE: &str = "Unlocks and restores the audit log (after a keychain loss, from a backup, or on a new machine). Stored tokens are never recovered (from a backup or after a keychain loss); you re-enter them. It is not your Atlassian password. Store it where your compliance owner can retrieve it.";

/// M15 T7 (PD-297): the German purpose line; the page's own table (`credential/i18n.ts`) holds
/// the same literal.
pub const PASSPHRASE_PURPOSE_DE: &str = "Entsperrt und stellt das Audit-Protokoll wieder her (nach einem Verlust des Schlüsselbunds, aus einem Backup oder auf einem neuen Computer). Gespeicherte Token werden nie wiederhergestellt (weder aus einem Backup noch nach einem Verlust des Schlüsselbunds); Sie geben sie erneut ein. Sie ist nicht Ihr Atlassian-Passwort. Bewahren Sie sie so auf, dass Ihr Compliance-Verantwortlicher sie abrufen kann.";

/// The purpose line in `lang`.
pub fn passphrase_purpose(lang: Lang) -> &'static str {
    match lang {
        Lang::En => PASSPHRASE_PURPOSE,
        Lang::De => PASSPHRASE_PURPOSE_DE,
    }
}

/// The PAT a credential window takes: the instance as Rust read it when it opened the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatTarget {
    pub alias: String,
    /// `jira` | `confluence`.
    pub product: &'static str,
    /// The normalized base URL in force when the window opened (§7.1).
    pub origin: String,
}

/// What the credential window is open for (§10.3 context header). Fixed by Rust when it opens
/// the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    AddPat(PatTarget),
    ReplacePat(PatTarget),
    /// The first-run recovery passphrase, entered twice (§8.6, wizard step (1b)).
    RecoveryPassphrase,
    /// Locked `keychain_unavailable`: nothing to type in v1 (L39); the window offers "Retry
    /// keychain" (PD-89) and Quit.
    Unlock,
    /// Locked `keychain_lost`: "Recover this log" with the store's recovery passphrase (§8.7).
    RecoverThisLog,
    /// Locked `keychain_lost` after an unfinished restore: "Finish restore" (§8.7).
    FinishRestore,
    /// M10 T13 (PD-168): the recovery passphrase of the backup a restore runs from, one entry,
    /// handed to the waiting restore (never a command response). Opened by Settings "Restore
    /// backup…" in a serving app, or set in place of "Recover this log"/"Finish restore" by the
    /// locked window's "Restore a backup instead". Not a lock state: the window follows no gate
    /// while it waits (the restore that opened it ends it).
    RestoreBackup,
    /// M10 T14 (PD-169, §8.6): Settings "Change recovery passphrase…" in a serving app: the new
    /// passphrase, entered twice, re-wraps the store's KEK (`Store::change_recovery_passphrase`);
    /// the recovery note is offered right after. Not a lock state.
    ChangeRecoveryPassphrase,
}

impl Purpose {
    /// The wire name `credential_context` reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            Purpose::AddPat(_) => "add_pat",
            Purpose::ReplacePat(_) => "replace_pat",
            Purpose::RecoveryPassphrase => "recovery_passphrase",
            Purpose::Unlock => "unlock",
            Purpose::RecoverThisLog => "recover_this_log",
            Purpose::FinishRestore => "finish_restore",
            Purpose::RestoreBackup => "restore_backup",
            Purpose::ChangeRecoveryPassphrase => "change_recovery_passphrase",
        }
    }

    /// The three locked-mode purposes (§2.5): Rust moves between them as the lock changes.
    pub fn is_lock_state(&self) -> bool {
        matches!(
            self,
            Purpose::Unlock | Purpose::RecoverThisLog | Purpose::FinishRestore
        )
    }

    pub fn pat_target(&self) -> Option<&PatTarget> {
        match self {
            Purpose::AddPat(t) | Purpose::ReplacePat(t) => Some(t),
            _ => None,
        }
    }
}

impl From<Unlock> for Purpose {
    fn from(u: Unlock) -> Purpose {
        match u {
            Unlock::Unlock => Purpose::Unlock,
            Unlock::Recover => Purpose::RecoverThisLog,
            Unlock::FinishRestore => Purpose::FinishRestore,
        }
    }
}

/// The purpose a gate state opens the credential window for (§2.5, §8.7): the three unlockable
/// lock states; `keyring_not_local` has nothing to unlock (its error window instead), and no other
/// state opens it.
pub fn purpose_for_gate(state: GateState) -> Option<Purpose> {
    match state {
        GateState::Locked(LockedReason::KeychainUnavailable) => Some(Purpose::Unlock),
        GateState::Locked(LockedReason::KeychainLost {
            offer: RecoveryOffer::RecoverThisLog,
        }) => Some(Purpose::RecoverThisLog),
        GateState::Locked(LockedReason::KeychainLost {
            offer: RecoveryOffer::FinishRestore,
        }) => Some(Purpose::FinishRestore),
        _ => None,
    }
}

/// The first-run recovery passphrase, both entries (§8.6: the store unwraps the KEK once with
/// the second and compares before it commits). `Debug` shows neither.
#[derive(Debug)]
pub struct FirstRunPassphrase {
    pub passphrase: SecretString,
    pub confirm: SecretString,
}

/// Why a first-run passphrase pair was refused (the window says so and stays open).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseRefusal {
    TooShort,
    Mismatch,
}

impl PassphraseRefusal {
    pub fn class(self) -> &'static str {
        match self {
            PassphraseRefusal::TooShort => "passphrase_too_short",
            PassphraseRefusal::Mismatch => "passphrase_mismatch",
        }
    }
}

/// The window's own check of a first-run pair: at least [`MIN_PASSPHRASE_CHARS`] characters,
/// typed twice the same. The audit store checks again (on the NFC form) when it wraps the KEK.
pub fn check_passphrase_pair(
    passphrase: &SecretString,
    confirm: &SecretString,
) -> Result<(), PassphraseRefusal> {
    if passphrase.expose_secret().chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(PassphraseRefusal::TooShort);
    }
    if passphrase.expose_secret() != confirm.expose_secret() {
        return Err(PassphraseRefusal::Mismatch);
    }
    Ok(())
}

/// The credential window's state, kept in the `WindowRegistry` (one lock with the window's
/// build, `windows::open_with`).
#[derive(Debug, Default)]
pub struct CredentialState {
    pub(crate) purpose: Option<Purpose>,
    /// The wizard's end of a first-run passphrase request (Task 23).
    passphrase: Option<oneshot::Sender<FirstRunPassphrase>>,
    /// The first-run passphrase went to the wizard (the recovery note becomes available once a
    /// store serves).
    handed_over: bool,
    /// "Archive old DB and start fresh" moved this store aside; the wizard's `GENESIS` names it
    /// (Task 23 takes it). Kept when the window closes.
    archived: Option<ArchivedDb>,
    /// Which window the purpose belongs to: bumped by every open that builds a new one. A close
    /// that was meant for one window ([`close_if`]) leaves its successor alone (M6 T22, m-2).
    generation: Generation,
    /// M10 T13 (PD-168): the waiting restore's end of the `restore_backup` passphrase. A reset (the
    /// window closed or another purpose took it) drops it, which ends that restore with no store
    /// call and no event.
    restore: Option<SyncSender<SecretString>>,
    /// The lock-state purpose a `restore_backup` window was set in place of (`keychain_lost`),
    /// which it goes back to when that restore ends without a store; `None` for a window
    /// Settings opened.
    restore_return: Option<Purpose>,
    /// M10 T14 (PD-169): this window's recovery-passphrase change committed (the recovery note is
    /// offered from then on).
    passphrase_changed: bool,
}

/// Identifies one credential window (its purpose and its passphrase request).
pub type Generation = u64;

impl CredentialState {
    pub fn purpose(&self) -> Option<&Purpose> {
        self.purpose.as_ref()
    }

    /// A new window: the purpose and the passphrase request of the old one go (a dropped sender
    /// tells the wizard the window closed); an archived store stays for the wizard.
    fn reset(&mut self) {
        self.purpose = None;
        self.passphrase = None;
        self.handed_over = false;
        self.restore = None;
        self.restore_return = None;
        self.passphrase_changed = false;
    }
}

/// What an open hands to the window it opens for (one of the two in-memory channels).
enum Handoff {
    /// The wizard's end of the first-run pair (Task 23).
    FirstRun(oneshot::Sender<FirstRunPassphrase>),
    /// A restore's end of the backup's passphrase (M10 T13).
    Restore(SyncSender<SecretString>),
}

/// A restore's end of a `restore_backup` request (M10 T13): the window it waits on and the
/// receiver `submit_secret` hands the one entry to. The receiver disconnects when the window goes
/// (closed by the user or by Rust, or given another purpose) before a submit.
#[derive(Debug)]
pub struct RestorePassphrase {
    pub generation: Generation,
    pub rx: Receiver<SecretString>,
}

fn registry<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<tauri::State<'_, WindowRegistry>, WindowError> {
    app.try_state::<WindowRegistry>()
        .ok_or(WindowError::NotRegistered)
}

/// `credential_context_changed` (C.10; no payload): the page reads `credential_context` again.
pub fn context_changed<R: Runtime>(app: &AppHandle<R>) {
    let (name, payload) = wire(&UiEvent::CredentialContextChanged);
    EventOut::emit(app, name, payload);
}

/// Opens the credential window for `purpose` (§10.3), deciding under the registry's `opening`
/// lock: no window yet → this purpose; the same purpose → shown again; one lock state for
/// another → the new one, announced; anything else while the window is open → `Busy` (the open
/// window keeps its purpose). Never on the main thread (it builds the window).
pub fn open<R: Runtime>(
    app: &AppHandle<R>,
    purpose: Purpose,
    how: Show,
) -> Result<(), WindowError> {
    open_inner(app, purpose, None, how).map(drop)
}

/// The window's generation once it is open for `purpose` (see [`open`]).
fn open_inner<R: Runtime>(
    app: &AppHandle<R>,
    purpose: Purpose,
    handoff: Option<Handoff>,
    how: Show,
) -> Result<Generation, WindowError> {
    enum Decide {
        New,
        Same,
        NextLockState,
        Busy,
    }
    let mut announce = false;
    let mut generation = 0;
    let opened = windows::open_with(app, Label::Credential, how, |registry, exists| {
        let mut st = registry.credential_state();
        // M6 T28 (T20 m-9), the credential half of the two-sided interlock: a window for a token is
        // not registered while a "Prepare for removal" call runs. The check is made under the
        // credential-state lock, right before the purpose is set; the removal side claims `busy`
        // first and reads the purpose (through the same lock) second, so one of the two always
        // sees the other: there is no check-then-register gap.
        if purpose.pat_target().is_some()
            && app
                .try_state::<crate::removal::RemovalState>()
                .is_some_and(|r| r.busy())
        {
            return Err(WindowError::Busy);
        }
        let decide = match (st.purpose.as_ref(), exists) {
            (_, false) => Decide::New,
            (Some(current), true) if *current == purpose => Decide::Same,
            (Some(current), true) if current.is_lock_state() && purpose.is_lock_state() => {
                Decide::NextLockState
            }
            (_, true) => Decide::Busy,
        };
        // M10 T14 review I-2, the window half of the recovery-tier interlock: a window for a
        // recovery-passphrase change is not opened while the serving state's job slot is held (a
        // recovery-tier flow, an export, a backup or a restore). Checked here, under the
        // credential-state lock, right before the purpose is set; a flow claims the slot first
        // and reads the purpose (through the same lock) second, so one of the two always sees
        // the other. The window already open for it is shown again (nothing new is set).
        if matches!(decide, Decide::New)
            && purpose == Purpose::ChangeRecoveryPassphrase
            && app
                .try_state::<crate::state::ServeSlot>()
                .and_then(|slot| slot.get().cloned())
                .is_some_and(|state| state.job_running())
        {
            return Err(WindowError::Busy);
        }
        match decide {
            Decide::Busy => return Err(WindowError::Busy),
            Decide::Same => {}
            Decide::NextLockState => {
                st.purpose = Some(purpose);
                announce = true;
            }
            Decide::New => {
                st.reset();
                st.generation = st.generation.wrapping_add(1);
                st.purpose = Some(purpose);
            }
        }
        match handoff {
            Some(Handoff::FirstRun(tx)) => {
                st.passphrase = Some(tx);
                st.handed_over = false;
            }
            // A second request for the same purpose replaces the first: its restore ends.
            Some(Handoff::Restore(tx)) => st.restore = Some(tx),
            None => {}
        }
        generation = st.generation;
        Ok(())
    });
    if announce {
        context_changed(app);
    }
    opened.map(|()| generation)
}

/// Asks for the first-run recovery passphrase (§2.5 wizard step (1b), §8.6; Task 23): opens the
/// window for [`Purpose::RecoveryPassphrase`] and returns the wizard's end of the in-memory
/// channel `submit_secret` hands the checked pair to (never a command response). The receiver
/// errors when the window closes before a pair was accepted.
pub fn request_recovery_passphrase<R: Runtime>(
    app: &AppHandle<R>,
    how: Show,
) -> Result<oneshot::Receiver<FirstRunPassphrase>, WindowError> {
    let (tx, rx) = oneshot::channel();
    open_inner(
        app,
        Purpose::RecoveryPassphrase,
        Some(Handoff::FirstRun(tx)),
        how,
    )?;
    Ok(rx)
}

/// Asks for a backup's recovery passphrase (Settings "Restore backup…", M10 T13, PD-168): opens
/// the window for [`Purpose::RestoreBackup`] (`Busy` while it is open for anything else) and
/// returns the restore's end of the one-entry channel `submit_secret` hands the entry to.
pub fn request_restore_passphrase<R: Runtime>(
    app: &AppHandle<R>,
    how: Show,
) -> Result<RestorePassphrase, WindowError> {
    let (tx, rx) = sync_channel(1);
    let generation = open_inner(app, Purpose::RestoreBackup, Some(Handoff::Restore(tx)), how)?;
    Ok(RestorePassphrase { generation, rx })
}

/// "Restore a backup instead" in the locked window (`keychain_lost`, M10 T13, PD-168): the open
/// window `generation`, while it is "Recover this log" or "Finish restore", becomes
/// [`Purpose::RestoreBackup`] in place (same window, announced), remembering the purpose it goes
/// back to ([`leave_restore`]). `Busy` when that window is gone or has another purpose.
pub fn enter_restore<R: Runtime>(
    app: &AppHandle<R>,
    generation: Generation,
) -> Result<RestorePassphrase, WindowError> {
    let r = registry(app)?;
    let rx = {
        let _no_open_in_between = r.lock_opening();
        if app.get_webview_window(Label::Credential.as_str()).is_none() {
            return Err(WindowError::Busy);
        }
        let mut st = r.credential_state();
        let back = match st.purpose.clone() {
            Some(p @ (Purpose::RecoverThisLog | Purpose::FinishRestore))
                if st.generation == generation =>
            {
                p
            }
            _ => return Err(WindowError::Busy),
        };
        let (tx, rx) = sync_channel(1);
        st.purpose = Some(Purpose::RestoreBackup);
        st.restore = Some(tx);
        st.restore_return = Some(back);
        rx
    };
    context_changed(app);
    Ok(RestorePassphrase { generation, rx })
}

/// The restore of window `generation` ended without a store (cancelled, refused, failed): a
/// window set in place by [`enter_restore`] goes back to its lock-state purpose (announced); any
/// other window is left alone. The pending channel goes either way.
pub fn leave_restore<R: Runtime>(app: &AppHandle<R>, generation: Generation) {
    let Ok(r) = registry(app) else {
        return;
    };
    let announce = {
        let _no_open_in_between = r.lock_opening();
        let mut st = r.credential_state();
        if st.generation != generation || st.purpose != Some(Purpose::RestoreBackup) {
            return;
        }
        st.restore = None;
        match st.restore_return.take() {
            Some(back) => {
                st.purpose = Some(back);
                true
            }
            None => false,
        }
    };
    if announce {
        context_changed(app);
    }
}

/// Hands the backup's passphrase to the restore waiting on this window (`submit_secret`, M10
/// T13). `Err(secret)` when none waits (no request, or the restore ended): the caller drops it
/// (zeroized). `Ok(in_place)`: whether the window was set in place of a lock-state purpose (it
/// then stays open for the restore's answer; a window Settings opened closes after the submit).
pub fn hand_restore_passphrase<R: Runtime>(
    app: &AppHandle<R>,
    secret: SecretString,
) -> Result<bool, SecretString> {
    let Ok(registry) = registry(app) else {
        return Err(secret);
    };
    let mut st = registry.credential_state();
    if st.purpose != Some(Purpose::RestoreBackup) {
        return Err(secret);
    }
    let Some(tx) = st.restore.take() else {
        return Err(secret);
    };
    tx.try_send(secret).map_err(|e| match e {
        std::sync::mpsc::TrySendError::Full(s) | std::sync::mpsc::TrySendError::Disconnected(s) => {
            s
        }
    })?;
    Ok(st.restore_return.is_some())
}

/// The purpose the open window has (`None`: no window, or the registry is missing).
pub fn current_purpose<R: Runtime>(app: &AppHandle<R>) -> Option<Purpose> {
    registry(app)
        .ok()
        .and_then(|r| r.credential_state().purpose.clone())
}

/// The open window's purpose and which window it is, read together: a command that later closes
/// "its" window passes the generation to [`close_if`].
pub fn current_window<R: Runtime>(app: &AppHandle<R>) -> Option<(Purpose, Generation)> {
    let r = registry(app).ok()?;
    let st = r.credential_state();
    st.purpose.clone().map(|p| (p, st.generation))
}

/// True once the first-run passphrase went to the wizard (this window).
pub fn handed_over<R: Runtime>(app: &AppHandle<R>) -> bool {
    registry(app).is_ok_and(|r| r.credential_state().handed_over)
}

/// The recovery-passphrase change of window `generation` committed (M10 T14, PD-169): from now on
/// it offers the recovery note. False (nothing marked) when that window is gone or has another
/// purpose: the change took minutes of Argon2id on a slow machine, and the window may have closed.
pub fn mark_passphrase_changed<R: Runtime>(app: &AppHandle<R>, generation: Generation) -> bool {
    let Ok(r) = registry(app) else {
        return false;
    };
    let mut st = r.credential_state();
    if st.generation != generation || st.purpose != Some(Purpose::ChangeRecoveryPassphrase) {
        return false;
    }
    st.passphrase_changed = true;
    true
}

/// True once this window's recovery-passphrase change committed (M10 T14).
pub fn passphrase_changed<R: Runtime>(app: &AppHandle<R>) -> bool {
    registry(app).is_ok_and(|r| r.credential_state().passphrase_changed)
}

/// Opens the window for [`Purpose::ChangeRecoveryPassphrase`] (Settings "Change recovery
/// passphrase…", M10 T14): `Busy` while it is open for anything else. Never on the main thread.
pub fn open_for_passphrase_change<R: Runtime>(app: &AppHandle<R>) -> Result<(), WindowError> {
    open(app, Purpose::ChangeRecoveryPassphrase, Show::Focus)
}

/// Hands a checked first-run pair to the wizard. `Err(pair)` when no wizard waits (no request, or
/// its receiver is gone): the pair is dropped (zeroized) by the caller.
pub fn hand_over<R: Runtime>(
    app: &AppHandle<R>,
    pair: FirstRunPassphrase,
) -> Result<(), FirstRunPassphrase> {
    let Ok(registry) = registry(app) else {
        return Err(pair);
    };
    let mut st = registry.credential_state();
    if st.purpose != Some(Purpose::RecoveryPassphrase) {
        return Err(pair);
    }
    let Some(tx) = st.passphrase.take() else {
        return Err(pair);
    };
    tx.send(pair)?;
    st.handed_over = true;
    Ok(())
}

/// Keeps the store "Archive old DB and start fresh" moved aside, for the wizard (Task 23).
pub fn set_archived<R: Runtime>(app: &AppHandle<R>, archived: ArchivedDb) {
    if let Ok(r) = registry(app) {
        r.credential_state().archived = Some(archived);
    }
}

/// The archived store the next `GENESIS` names (§8.7), once (Task 23).
pub fn take_archived<R: Runtime>(app: &AppHandle<R>) -> Option<ArchivedDb> {
    registry(app)
        .ok()
        .and_then(|r| r.credential_state().archived.take())
}

/// The window was destroyed (closed by the user or by Rust): its purpose and a pending
/// passphrase request go (`tray::on_run_event`; Tauri forgets the window before that callback
/// runs), so a sender never outlives its window. A window built again since then has its own
/// purpose, which stays. Runs on the main thread, which never waits for `opening` (an open
/// holding it waits for the main thread to build its window): with no open running the reset is
/// done here; otherwise it is retried off the main thread once that open is over, and whichever
/// open it was (any label shares the lock), the destroyed window's state goes (M6 T22, m-1).
pub fn window_destroyed<R: Runtime>(app: &AppHandle<R>) {
    window_destroyed_if(app, |app| {
        app.get_webview_window(Label::Credential.as_str()).is_none()
    });
}

/// [`window_destroyed`] with the "the window is gone" check passed in (the mock runtime keeps
/// reporting a destroyed window, so a test cannot reach the real check).
#[doc(hidden)]
pub fn window_destroyed_if<R: Runtime>(app: &AppHandle<R>, gone: fn(&AppHandle<R>) -> bool) {
    let Ok(r) = registry(app) else {
        return;
    };
    if let Some(_no_open_running) = r.try_opening() {
        if gone(app) {
            r.credential_state().reset();
            // The wizard's recovery-note step ends with the window (M6 T23).
            emit_wizard_changed(app);
        }
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let Ok(r) = registry(&app) else {
            return;
        };
        let _open_is_over = r.lock_opening();
        if gone(&app) {
            r.credential_state().reset();
            emit_wizard_changed(&app);
        }
    });
}

/// Forgets the window's purpose, then destroys the window (its webview and anything typed in it,
/// §10.1): from here on its commands answer `not_ready`. Under `opening`, so a concurrent open
/// sees the window and its purpose either both there or both gone. Off the main thread.
pub fn close<R: Runtime>(app: &AppHandle<R>) {
    close_matching(app, None);
}

/// [`close`], but only the window `generation` names (from [`current_window`]): a command that
/// answered for one window must not destroy the next one a later open built meanwhile (M6 T22,
/// m-2). False when that window is gone already.
pub fn close_if<R: Runtime>(app: &AppHandle<R>, generation: Generation) -> bool {
    close_matching(app, Some(generation))
}

fn close_matching<R: Runtime>(app: &AppHandle<R>, generation: Option<Generation>) -> bool {
    let Ok(r) = registry(app) else {
        return false;
    };
    let _no_open_in_between = r.lock_opening();
    {
        let mut st = r.credential_state();
        if generation.is_some_and(|g| st.purpose.is_none() || st.generation != g) {
            return false;
        }
        st.reset();
    }
    if let Some(w) = app.get_webview_window(Label::Credential.as_str()) {
        let _ = w.destroy();
    }
    emit_wizard_changed(app);
    true
}

/// The PAT target of `alias` from the instance list (§7.1, §10.3): refused for an unknown alias,
/// an `http://` instance (`insecure_scheme`) and an instance whose origin is not natively
/// confirmed yet (`instance_unconfirmed`), so the window cannot open for them.
pub fn pat_target(views: &[InstanceView], alias: &str) -> Result<PatTarget, AdminError> {
    let view = views
        .iter()
        .find(|v| v.alias == alias)
        .ok_or(AdminError::NotFound)?;
    match view.state {
        "insecure_scheme" => return Err(AdminError::InsecureScheme),
        "instance_unconfirmed" => return Err(AdminError::Unconfirmed),
        _ => {}
    }
    let origin = view.origin.clone().ok_or(AdminError::Unconfirmed)?;
    Ok(PatTarget {
        alias: view.alias.clone(),
        product: product_str(view.product),
        origin,
    })
}

/// Why the window did not open for a PAT.
#[derive(Debug, Clone, PartialEq)]
pub enum PatOpenError {
    Instance(AdminError),
    Window(WindowError),
}

/// The kind only (an `AdminError` is shown by its kind, never a message).
impl std::fmt::Display for PatOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatOpenError::Instance(e) => write!(f, "instance: {e}"),
            PatOpenError::Window(e) => write!(f, "window: {e}"),
        }
    }
}

impl std::error::Error for PatOpenError {}

/// Opens the window to add (or replace) the PAT of `alias` (the Settings trigger, Task 25). The
/// instance list is read here, by Rust; `views` is `InstanceAdmin::list()` (a sync call: the
/// caller runs on the blocking pool, which this needs anyway to build the window).
pub fn open_for_pat<R: Runtime>(
    app: &AppHandle<R>,
    views: &[InstanceView],
    alias: &str,
    replace: bool,
) -> Result<(), PatOpenError> {
    let target = pat_target(views, alias).map_err(PatOpenError::Instance)?;
    let purpose = if replace {
        Purpose::ReplacePat(target)
    } else {
        Purpose::AddPat(target)
    };
    open(app, purpose, Show::Focus).map_err(PatOpenError::Window)
}

// ---------- the recovery note (§8.6) ----------

/// What the recovery note names. Nothing here is secret, and nothing secret can be passed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteFacts {
    pub host: String,
    pub os_user: String,
    pub install_id: String,
    pub chain_id: String,
    pub data_dir: String,
}

/// plan text (T20): the file name the save dialog proposes.
pub const NOTE_FILE_NAME: &str = "atlas-duck-recovery-note.txt";
/// plan text (T20): the title of the recovery note.
const NOTE_TITLE: &str = "atlas-duck recovery note";
/// plan text (T20): the recovery and restore steps the note gives (§8.7 "Recover this log",
/// "Archive old DB and start fresh", §8.11 restore).
const NOTE_STEPS: &str = "\
If this machine's keychain is lost (password reset, profile wipe, reinstall), atlas-duck starts locked and its credential window offers \"Recover this log\": enter the recovery passphrase. The log is verified, an integrity incident is recorded (it needs an acknowledgement), and every stored token must be entered again.
After an interrupted restore the window offers \"Finish restore\": enter the recovery passphrase of the restored backup.
To move to a new machine, or to go back to a backup: restore the full backup in atlas-duck and enter that backup's recovery passphrase. Tokens are never restored; enter them again.
Without the passphrase the only way on is \"Archive old DB and start fresh\": the old log is moved to the archived folder of the data directory, never deleted. Keep it for its retention period; it can be read later only with this passphrase.";

/// M15 T7: the German note. The button names are the credential page's German labels.
const NOTE_TITLE_DE: &str = "atlas-duck Wiederherstellungsnotiz";
const NOTE_STEPS_DE: &str = "\
Geht der Schlüsselbund dieses Computers verloren (Passwort zurückgesetzt, Profil gelöscht, Neuinstallation), startet atlas-duck gesperrt und das Anmeldedatenfenster bietet „Dieses Protokoll wiederherstellen“ an: Geben Sie die Wiederherstellungs-Passphrase ein. Das Protokoll wird geprüft, ein Integritätsvorfall wird aufgezeichnet (er muss zur Kenntnis genommen werden), und jedes gespeicherte Token muss erneut eingegeben werden.
Nach einer unterbrochenen Wiederherstellung bietet das Fenster „Wiederherstellung abschließen“ an: Geben Sie die Wiederherstellungs-Passphrase des wiederhergestellten Backups ein.
Für einen neuen Computer oder die Rückkehr zu einem Backup: Stellen Sie das Vollbackup in atlas-duck wieder her und geben Sie die Wiederherstellungs-Passphrase dieses Backups ein. Token werden nie wiederhergestellt; geben Sie sie erneut ein.
Ohne die Passphrase bleibt nur „Alte DB archivieren und neu beginnen“: Das alte Protokoll wird in den Archivordner des Datenverzeichnisses verschoben, nie gelöscht. Bewahren Sie es für seine Aufbewahrungsfrist auf; es ist später nur mit dieser Passphrase lesbar.";

/// The recovery note (§8.6): the purpose line, host, OS user, `install_id`, `chain_id`, the data
/// directory, the recovery and restore steps, and a blank line to write the passphrase on by
/// hand, in `lang` (M15 T7; the field names `install_id` and `chain_id` stay as they are). It
/// never contains the passphrase: this function cannot be given one.
pub fn note_text(f: &NoteFacts, lang: Lang) -> String {
    let (title, steps, host, user, data, blank) = match lang {
        Lang::En => (
            NOTE_TITLE,
            NOTE_STEPS,
            "Host",
            "OS user",
            "Data directory",
            "Recovery passphrase (write it here by hand)",
        ),
        Lang::De => (
            NOTE_TITLE_DE,
            NOTE_STEPS_DE,
            "Host",
            "Betriebssystem-Benutzer",
            "Datenverzeichnis",
            "Wiederherstellungs-Passphrase (hier von Hand eintragen)",
        ),
    };
    format!(
        "{title}\n\n{}\n\n{host}: {}\n{user}: {}\ninstall_id: {}\nchain_id: {}\n{data}: {}\n\n{steps}\n\n{blank}:\n\n________________________________________\n",
        passphrase_purpose(lang),
        f.host,
        f.os_user,
        f.install_id,
        f.chain_id,
        f.data_dir
    )
}
/// The OS user the note names (best effort; never fails).
pub fn os_user() -> String {
    ["USERNAME", "USER", "LOGNAME"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::{AppSnapshot, Relaunch, route_relaunch};

    fn locked(r: LockedReason) -> GateState {
        GateState::Locked(r)
    }

    /// U-18 (window half): a wiped keychain leaves the store locked `keychain_lost`; the credential
    /// window it opens (at startup, from the tray's "Unlock…" and on a relaunch) offers "Recover
    /// this log".
    #[test]
    fn u18_keychain_lost_opens_recover_this_log() {
        let lost = locked(LockedReason::KeychainLost {
            offer: RecoveryOffer::RecoverThisLog,
        });
        assert_eq!(purpose_for_gate(lost), Some(Purpose::RecoverThisLog));
        let routed = route_relaunch(&AppSnapshot::Gate(lost), &[]);
        assert_eq!(routed, Relaunch::OpenCredential(Unlock::Recover));
        let Relaunch::OpenCredential(unlock) = routed else {
            panic!("{routed:?}");
        };
        assert_eq!(Purpose::from(unlock), Purpose::RecoverThisLog);
        assert_eq!(Purpose::RecoverThisLog.as_str(), "recover_this_log");
    }

    #[test]
    fn finish_restore_offer_opens_finish_restore() {
        let unfinished = locked(LockedReason::KeychainLost {
            offer: RecoveryOffer::FinishRestore,
        });
        assert_eq!(purpose_for_gate(unfinished), Some(Purpose::FinishRestore));
        let routed = route_relaunch(&AppSnapshot::Gate(unfinished), &[]);
        assert_eq!(routed, Relaunch::OpenCredential(Unlock::FinishRestore));
        assert_eq!(Purpose::from(Unlock::FinishRestore), Purpose::FinishRestore);
        assert_eq!(Purpose::FinishRestore.as_str(), "finish_restore");
    }

    /// Every gate state: the mapping here and the relaunch routing agree on which states open the
    /// credential window and for what.
    #[test]
    fn purpose_for_gate_agrees_with_the_relaunch_routing() {
        let states = [
            GateState::FirstRun,
            GateState::StoreNewer,
            GateState::ShuttingDown,
            GateState::StoreFailed,
            GateState::NotConfigured("data_dir_missing"),
            locked(LockedReason::KeychainUnavailable),
            locked(LockedReason::KeyringNotLocal),
            locked(LockedReason::KeychainLost {
                offer: RecoveryOffer::RecoverThisLog,
            }),
            locked(LockedReason::KeychainLost {
                offer: RecoveryOffer::FinishRestore,
            }),
        ];
        for s in states {
            let routed = match route_relaunch(&AppSnapshot::Gate(s), &[]) {
                Relaunch::OpenCredential(u) => Some(Purpose::from(u)),
                _ => None,
            };
            assert_eq!(purpose_for_gate(s), routed, "{s:?}");
            if let Some(p) = routed {
                assert!(p.is_lock_state(), "{s:?}");
            }
        }
        assert_eq!(
            purpose_for_gate(locked(LockedReason::KeychainUnavailable)),
            Some(Purpose::Unlock)
        );
        assert_eq!(
            purpose_for_gate(locked(LockedReason::KeyringNotLocal)),
            None
        );
    }

    #[test]
    fn purposes_have_distinct_wire_names_and_lock_states() {
        let t = PatTarget {
            alias: "a".into(),
            product: "jira",
            origin: "https://jira.example/jira".into(),
        };
        let all = [
            Purpose::AddPat(t.clone()),
            Purpose::ReplacePat(t.clone()),
            Purpose::RecoveryPassphrase,
            Purpose::Unlock,
            Purpose::RecoverThisLog,
            Purpose::FinishRestore,
            // M10 T13: not a lock state (the restore that opened it ends it, no gate moves it).
            Purpose::RestoreBackup,
            // M10 T14: Settings opens it in a serving app; no gate moves it either.
            Purpose::ChangeRecoveryPassphrase,
        ];
        let names: std::collections::BTreeSet<&str> = all.iter().map(Purpose::as_str).collect();
        assert_eq!(names.len(), all.len());
        assert_eq!(Purpose::RestoreBackup.as_str(), "restore_backup");
        assert_eq!(
            Purpose::ChangeRecoveryPassphrase.as_str(),
            "change_recovery_passphrase"
        );
        let lock: Vec<&str> = all
            .iter()
            .filter(|p| p.is_lock_state())
            .map(Purpose::as_str)
            .collect();
        assert_eq!(lock, ["unlock", "recover_this_log", "finish_restore"]);
        assert_eq!(all[0].pat_target(), Some(&t));
        assert_eq!(all[2].pat_target(), None);
    }

    #[test]
    fn passphrase_pair_needs_twelve_characters_twice() {
        let s = |v: &str| SecretString::from(v);
        let twelve = "abcdefghijkl";
        assert_eq!(check_passphrase_pair(&s(twelve), &s(twelve)), Ok(()));
        // Characters, not bytes: twelve two-byte characters pass, eleven do not.
        let wide = "é".repeat(12);
        assert_eq!(check_passphrase_pair(&s(&wide), &s(&wide)), Ok(()));
        let short = "é".repeat(11);
        assert_eq!(
            check_passphrase_pair(&s(&short), &s(&short)),
            Err(PassphraseRefusal::TooShort)
        );
        assert_eq!(
            check_passphrase_pair(&s(twelve), &s("abcdefghijkL")),
            Err(PassphraseRefusal::Mismatch)
        );
        assert_eq!(
            check_passphrase_pair(&s(twelve), &s("")),
            Err(PassphraseRefusal::Mismatch)
        );
        assert_eq!(MIN_PASSPHRASE_CHARS, 12);
        // The pair's `Debug` shows neither entry.
        let pair = FirstRunPassphrase {
            passphrase: s("canary-passphrase-1"),
            confirm: s("canary-passphrase-1"),
        };
        assert!(!format!("{pair:?}").contains("canary"), "{pair:?}");
    }

    #[test]
    fn note_text_names_the_install_and_leaves_the_passphrase_line_blank() {
        let f = NoteFacts {
            host: "build-01".into(),
            os_user: "alice".into(),
            install_id: "0123456789abcdef0123456789abcdef".into(),
            chain_id: "fedcba9876543210fedcba9876543210".into(),
            data_dir: "/home/alice/.local/share/atlas-duck".into(),
        };
        let text = note_text(&f, Lang::En);
        assert!(text.contains(PASSPHRASE_PURPOSE));
        for v in [&f.host, &f.os_user, &f.install_id, &f.chain_id, &f.data_dir] {
            assert!(text.contains(v.as_str()), "{v}");
        }
        assert!(text.contains("Recover this log") && text.contains("Finish restore"));
        assert!(text.ends_with("Recovery passphrase (write it here by hand):\n\n________________________________________\n"));
        assert!(PASSPHRASE_PURPOSE.starts_with("Unlocks and restores the audit log"));
        // M15 T7: the German note carries the German purpose and labels, the same facts and the
        // same blank line.
        let de = note_text(&f, Lang::De);
        assert!(de.starts_with("atlas-duck Wiederherstellungsnotiz\n\n"));
        assert!(de.contains(PASSPHRASE_PURPOSE_DE));
        assert!(!de.contains(PASSPHRASE_PURPOSE));
        for v in [&f.host, &f.os_user, &f.install_id, &f.chain_id, &f.data_dir] {
            assert!(de.contains(v.as_str()), "{v}");
        }
        assert!(de.contains("Dieses Protokoll wiederherstellen"));
        assert!(
            de.ends_with(
                "(hier von Hand eintragen):\n\n________________________________________\n"
            )
        );
    }

    /// M15 T7 (PD-297): the purpose texts, pinned in both languages.
    #[test]
    fn passphrase_purpose_texts_pinned() {
        assert_eq!(passphrase_purpose(Lang::En), PASSPHRASE_PURPOSE);
        assert_eq!(passphrase_purpose(Lang::De), PASSPHRASE_PURPOSE_DE);
        assert!(PASSPHRASE_PURPOSE_DE.starts_with("Entsperrt und stellt das Audit-Protokoll"));
        assert_ne!(PASSPHRASE_PURPOSE, PASSPHRASE_PURPOSE_DE);
    }

    /// M15 T7: the credential page's table holds each purpose line as one literal, verbatim (PD-71:
    /// the page imports nothing, so the two copies are compared here).
    #[test]
    fn passphrase_purpose_matches_the_page_in_both_languages() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../ui/src/credential/i18n.ts");
        let page = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(!page.is_empty(), "{}", path.display());
        for lang in [Lang::En, Lang::De] {
            let literal = format!("'{}'", passphrase_purpose(lang));
            assert!(page.contains(&literal), "{lang:?}: the page's line differs");
        }
    }
}
