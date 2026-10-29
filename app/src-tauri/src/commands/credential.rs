//! The credential window's commands (C.10 + Δ1, §10.3; M6 T20): `credential_context`,
//! `submit_secret`, `save_recovery_note`, `archive_and_start_fresh`, `retry_keychain`,
//! `close_credential` (M6 T25; `quit` is `window::quit`). Granted to the `credential` window only.
//!
//! What a call may do is decided by the purpose Rust opened the window for
//! (`credential::Purpose`), never by an argument. A secret arrives only in `submit_secret`, is a
//! `secrecy::SecretString` from the DTO on ([`Secret`]: no `Serialize`, a redacting `Debug`,
//! zeroized on drop) and goes to `InstanceAdmin::set_token`, the wizard's channel, a waiting
//! restore or the audit store (M10 T14: the new recovery passphrase of purpose
//! `change_recovery_passphrase`, typed twice); no response, event, log line or capture record holds
//! it. A PAT's answer is the connection test's outcome only (§10.3).

use std::fmt;
use std::sync::Arc;

use atlas_duck_core::{AdminError, ConnectionFailure, ConnectionReport, InstanceAdmin, NaiveDate};
use secrecy::{ExposeSecret, SecretString};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use tauri::{AppHandle, Manager, Runtime};
use zeroize::Zeroize;

use super::dto::{Args, refuse};
use super::{CommandError, blocking, finish};
use crate::credential::{self, FirstRunPassphrase, NoteFacts, PatTarget, Purpose};
use crate::i18n::{Lang, T};
use crate::serve::{self, ServeState, UnlockKind};
use crate::state::{AppState, ServeSlot};
use crate::windows::{self, Label, Show, WindowError};

/// plan text (T20): a secret (PAT or passphrase) is 1 to 1 024 bytes of UTF-8 without `\0`.
pub const SECRET_MAX_BYTES: usize = 1024;

/// One secret as the credential page typed it. Built straight from the borrowed JSON string into
/// a `SecretString` (no intermediate `String` of its own); refused values are dropped, zeroized.
fn secret_from<'de, D: Deserializer<'de>>(
    d: D,
    field: &'static str,
) -> Result<SecretString, D::Error> {
    struct SecretVisitor;
    impl Visitor<'_> for SecretVisitor {
        type Value = SecretString;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<SecretString, E> {
            Ok(SecretString::from(v))
        }
        fn visit_string<E: de::Error>(self, mut v: String) -> Result<SecretString, E> {
            let s = SecretString::from(v.as_str());
            v.zeroize();
            Ok(s)
        }
    }
    let s = d
        .deserialize_str(SecretVisitor)
        .map_err(|_| refuse::<D::Error>(field))?;
    let t = s.expose_secret();
    if t.is_empty() || t.len() > SECRET_MAX_BYTES || t.contains('\0') {
        return Err(refuse(field));
    }
    Ok(s)
}

/// `secret`: a PAT or a passphrase. `Debug` never shows it; there is no `Serialize`.
pub struct Secret(SecretString);

impl Secret {
    pub fn into_inner(self) -> SecretString {
        self.0
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        secret_from(d, "secret").map(Secret)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

/// `secret_confirm`: the second entry of the first-run recovery passphrase (§8.6).
pub struct SecretConfirm(SecretString);

impl SecretConfirm {
    pub fn into_inner(self) -> SecretString {
        self.0
    }
}

impl<'de> Deserialize<'de> for SecretConfirm {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        secret_from(d, "secret_confirm").map(SecretConfirm)
    }
}

impl fmt::Debug for SecretConfirm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretConfirm([redacted])")
    }
}

/// `expires_on`: the PAT's "token expires on" date (§7.1), `YYYY-MM-DD`, a real calendar date.
/// Not secret; recorded in `CREDENTIAL_CHANGED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiryDate(pub NaiveDate);

impl ExpiryDate {
    pub fn parse(s: &str) -> Option<ExpiryDate> {
        let b = s.as_bytes();
        let shaped = b.len() == 10
            && b[4] == b'-'
            && b[7] == b'-'
            && b.iter()
                .enumerate()
                .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit());
        if !shaped {
            return None;
        }
        let year: i32 = s.get(0..4)?.parse().ok()?;
        let month: u32 = s.get(5..7)?.parse().ok()?;
        let day: u32 = s.get(8..10)?.parse().ok()?;
        NaiveDate::from_ymd_opt(year, month, day).map(ExpiryDate)
    }
}

impl<'de> Deserialize<'de> for ExpiryDate {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d).map_err(|_| refuse::<D::Error>("expires_on"))?;
        ExpiryDate::parse(&s).ok_or_else(|| refuse("expires_on"))
    }
}

/// `submit_secret {secret, secret_confirm?, expires_on?}` (Δ1). Which keys a purpose takes is
/// checked by the handler: a PAT takes `expires_on`, the first-run passphrase `secret_confirm`,
/// the unlock passphrases neither.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitSecretArgs {
    pub secret: Secret,
    pub secret_confirm: Option<SecretConfirm>,
    pub expires_on: Option<ExpiryDate>,
}

/// Redacting: whether the secrets are there, never what they are.
impl fmt::Debug for SubmitSecretArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubmitSecretArgs")
            .field("secret", &self.secret)
            .field("secret_confirm", &self.secret_confirm)
            .field("expires_on", &self.expires_on)
            .finish()
    }
}

/// `credential_context {}` (read-only).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialContextArgs {}

/// `save_recovery_note {}` (Rust save dialog; no path argument).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveRecoveryNoteArgs {}

/// `archive_and_start_fresh {}` (Rust confirms natively).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveAndStartFreshArgs {}

/// `retry_keychain {}` (PD-89).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryKeychainArgs {}

/// `restore_from_backup {}` (M10 T13, PD-168): Rust draws the dialogs; no path, no secret in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreFromBackupArgs {}

/// `close_credential {}` (M6 T25, T21 review I-4): the page's own Close / Cancel.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseCredentialArgs {}

/// The read-only context header (§10.3): the purpose, for a PAT the instance as Rust read it when
/// it opened the window, for the locked and first-run purposes the refused count (§2.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialContextDto {
    pub purpose: &'static str,
    pub alias: Option<String>,
    pub product: Option<&'static str>,
    /// The normalized base URL (§7.1).
    pub base_url: Option<String>,
    /// "Locked — N requests refused" / "Setup required — N requests refused" (§2.5).
    pub refused_count: Option<u64>,
    /// §15 V26: no hint in M6 (the user types the expiry date); always `null`.
    pub product_version_hint: Option<String>,
    /// "Save recovery note" is offered: the first-run passphrase went to the wizard and the new
    /// store serves (§8.6: right after `GENESIS`).
    pub note_available: bool,
    /// M15 T7 (PD-297): the UI language Rust resolved (`ui_lang`); the page has no other source.
    pub lang: Lang,
}

/// "Connected as <user>, Jira <version>" (§10.3), plus the version warnings (§7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Connected {
    pub atlassian_user: String,
    pub product: &'static str,
    pub version: String,
    pub warnings: Vec<String>,
}

impl From<ConnectionReport> for Connected {
    fn from(r: ConnectionReport) -> Connected {
        Connected {
            atlassian_user: r.atlassian_user,
            product: atlas_duck_core::config::instances::product_str(r.product),
            version: r.version,
            warnings: r.warnings,
        }
    }
}

/// Why a submit did nothing: a fixed class (§10.3 connection-test classes, §11.2 `conn`, the
/// passphrase and unlock classes); the window stays open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SubmitFailure {
    pub class: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn: Option<&'static str>,
}

impl SubmitFailure {
    pub fn class(class: &'static str) -> SubmitFailure {
        SubmitFailure { class, conn: None }
    }
}

/// plan text (T20): the instance changed (URL, state) since the window opened; it must be opened
/// again for the instance as it is now.
pub const CLASS_CONTEXT_CHANGED: &str = "context_changed";

/// The connection test's failure as the window shows it.
pub fn connection_failure(f: &ConnectionFailure) -> SubmitFailure {
    SubmitFailure {
        class: f.kind(),
        conn: f.conn_class(),
    }
}

/// `submit_secret`'s answer: `{"ok": {..}}` (PAT stored), `{"accepted": {}}` (first-run passphrase
/// handed to the wizard), `{"unlocked": {}}` (the store serves again; the window closes) or
/// `{"failed": {"class", "conn"?}}` (nothing stored; the window stays open).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmitOutcome {
    Ok(Connected),
    Accepted {},
    Unlocked {},
    Failed(SubmitFailure),
}

/// `save_recovery_note`'s answer: false when the save dialog was cancelled. Never the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NoteSaved {
    pub saved: bool,
}

/// `archive_and_start_fresh`'s answer: the archived file (relative to the data dir, §8.7), or a
/// failure class (`cancelled` when the confirmation was declined).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveOutcome {
    Archived { archived_file: String },
    Failed(SubmitFailure),
}

/// `retry_keychain`'s answer: false when a retry is still running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RetryStarted {
    pub started: bool,
}

fn serve_state<R: Runtime>(app: &AppHandle<R>) -> Option<Arc<ServeState>> {
    app.try_state::<ServeSlot>().and_then(|s| s.get().cloned())
}

/// The context header of `purpose`.
pub fn context_dto(
    purpose: &Purpose,
    refused_count: Option<u64>,
    note_available: bool,
    lang: Lang,
) -> CredentialContextDto {
    let target = purpose.pat_target();
    CredentialContextDto {
        purpose: purpose.as_str(),
        alias: target.map(|t| t.alias.clone()),
        product: target.map(|t| t.product),
        base_url: target.map(|t| t.origin.clone()),
        refused_count: if target.is_some() {
            None
        } else {
            refused_count
        },
        product_version_hint: None,
        note_available,
        lang,
    }
}

/// `credential_context {}` (Δ1, §10.3): the header of the purpose Rust opened the window for.
#[tauri::command]
pub async fn credential_context<R: Runtime>(
    app: AppHandle<R>,
    args: Args<CredentialContextArgs>,
) -> Result<CredentialContextDto, CommandError> {
    let Args(CredentialContextArgs {}) = args;
    let response = match credential::current_purpose(&app) {
        None => Err(CommandError::NotReady),
        Some(purpose) => {
            let serve = serve_state(&app);
            let refused = serve.as_ref().and_then(|s| s.refused());
            let note = note_available(&app, &purpose, serve.as_deref());
            Ok(context_dto(&purpose, refused, note, ui_lang(&app)))
        }
    };
    finish(&app, response)
}

/// The UI language of this process (`en` without an `AppState`).
fn ui_lang<R: Runtime>(app: &AppHandle<R>) -> Lang {
    app.try_state::<AppState>()
        .map(|s| s.lang())
        .unwrap_or_default()
}

fn note_available<R: Runtime>(
    app: &AppHandle<R>,
    purpose: &Purpose,
    serve: Option<&ServeState>,
) -> bool {
    note_offered(app, purpose) && serve.is_some_and(|s| s.note_facts().is_some())
}

/// The window offers the recovery note (§8.6): after the first-run passphrase went to the wizard,
/// and (M10 T14, PD-169) after this window's recovery-passphrase change committed.
fn note_offered<R: Runtime>(app: &AppHandle<R>, purpose: &Purpose) -> bool {
    match purpose {
        Purpose::RecoveryPassphrase => credential::handed_over(app),
        Purpose::ChangeRecoveryPassphrase => credential::passphrase_changed(app),
        _ => false,
    }
}

/// plan text (T14): the class of a recovery-passphrase change the store refused for another reason
/// than the two entries (a restore replaced the KEK meanwhile, a failed write): nothing changed.
pub const CLASS_PASSPHRASE_NOT_CHANGED: &str = "passphrase_not_changed";

/// "Change recovery passphrase" (M10 T14, PD-169, §8.6): the window's own check of the pair, then
/// `Store::change_recovery_passphrase` on the blocking pool (two Argon2id runs, seconds on a slow
/// machine; T9 handoff), which re-wraps the KEK and commits the `recovery` row with its
/// `CREDENTIAL_CHANGED {change: recovery_passphrase}`. A refused pair or a refused change is a
/// `failed` outcome with nothing changed; a closed store is `not_ready`. The answer holds no secret.
pub async fn change_passphrase_dto(
    store: atlas_duck_audit::Store,
    args: SubmitSecretArgs,
) -> Result<SubmitOutcome, CommandError> {
    use atlas_duck_audit::{AuditError, PASSPHRASE_MISMATCH, PASSPHRASE_TOO_SHORT};
    let pair = match passphrase_pair(args)? {
        Ok(pair) => pair,
        Err(failed) => return Ok(failed),
    };
    let changed = blocking(move || {
        let FirstRunPassphrase {
            passphrase,
            confirm,
        } = pair;
        Ok(store.change_recovery_passphrase(&passphrase, &confirm))
    })
    .await?;
    let class = match changed {
        Ok(_) => return Ok(SubmitOutcome::Accepted {}),
        Err(AuditError::Closed) => return Err(CommandError::NotReady),
        Err(AuditError::Invalid(PASSPHRASE_TOO_SHORT)) => {
            credential::PassphraseRefusal::TooShort.class()
        }
        Err(AuditError::Invalid(PASSPHRASE_MISMATCH)) => {
            credential::PassphraseRefusal::Mismatch.class()
        }
        Err(_) => CLASS_PASSPHRASE_NOT_CHANGED,
    };
    Ok(SubmitOutcome::Failed(SubmitFailure::class(class)))
}

/// A PAT for `target` (§7.1, §10.3): the instance must still be the one the window shows
/// (`context_changed` otherwise); then `InstanceAdmin::set_token` runs the connection test with
/// the entered token before storing anything (a failure stores nothing and keeps the old PAT) and
/// asks the native owner-change confirmation itself.
pub async fn submit_pat_dto(
    admin: Arc<dyn InstanceAdmin>,
    target: &PatTarget,
    args: SubmitSecretArgs,
) -> Result<SubmitOutcome, CommandError> {
    let SubmitSecretArgs {
        secret,
        secret_confirm,
        expires_on,
    } = args;
    if secret_confirm.is_some() {
        return Err(CommandError::InvalidArgument {
            field: "secret_confirm",
        });
    }
    let list = admin.clone();
    let views = blocking(move || Ok(list.list())).await?;
    match credential::pat_target(&views, &target.alias) {
        Ok(now) if now == *target => {}
        Ok(_) => {
            return Ok(SubmitOutcome::Failed(SubmitFailure::class(
                CLASS_CONTEXT_CHANGED,
            )));
        }
        Err(e) => return Err(CommandError::Admin(e)),
    }
    match admin
        .set_token(&target.alias, secret.into_inner(), expires_on.map(|d| d.0))
        .await
    {
        Ok(report) => Ok(SubmitOutcome::Ok(Connected::from(report))),
        Err(AdminError::ConnectionFailed(f)) => Ok(SubmitOutcome::Failed(connection_failure(&f))),
        Err(e) => Err(CommandError::Admin(e)),
    }
}

/// The first-run pair (§8.6): `secret_confirm` is required, `expires_on` refused; a pair the
/// window's check refuses is a `failed` outcome (nothing is handed on, nothing committed).
pub fn passphrase_pair(
    args: SubmitSecretArgs,
) -> Result<Result<FirstRunPassphrase, SubmitOutcome>, CommandError> {
    let SubmitSecretArgs {
        secret,
        secret_confirm,
        expires_on,
    } = args;
    if expires_on.is_some() {
        return Err(CommandError::InvalidArgument {
            field: "expires_on",
        });
    }
    let Some(confirm) = secret_confirm else {
        return Err(CommandError::InvalidArgument {
            field: "secret_confirm",
        });
    };
    let pair = FirstRunPassphrase {
        passphrase: secret.into_inner(),
        confirm: confirm.into_inner(),
    };
    Ok(
        match credential::check_passphrase_pair(&pair.passphrase, &pair.confirm) {
            Ok(()) => Ok(pair),
            Err(r) => Err(SubmitOutcome::Failed(SubmitFailure::class(r.class()))),
        },
    )
}

/// The passphrase of "Recover this log" / "Finish restore": one entry, nothing else.
pub fn unlock_passphrase(args: SubmitSecretArgs) -> Result<SecretString, CommandError> {
    let SubmitSecretArgs {
        secret,
        secret_confirm,
        expires_on,
    } = args;
    if secret_confirm.is_some() {
        return Err(CommandError::InvalidArgument {
            field: "secret_confirm",
        });
    }
    if expires_on.is_some() {
        return Err(CommandError::InvalidArgument {
            field: "expires_on",
        });
    }
    Ok(secret.into_inner())
}

/// Destroys the credential window once this command has answered (the page is gone with it): the
/// window this command was called from (`generation`), never one a later open built meanwhile.
fn close_after_answer<R: Runtime>(app: &AppHandle<R>, generation: credential::Generation) {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || credential::close_if(&handle, generation));
}

async fn submit<R: Runtime>(
    app: &AppHandle<R>,
    args: SubmitSecretArgs,
) -> Result<SubmitOutcome, CommandError> {
    let (purpose, generation) = credential::current_window(app).ok_or(CommandError::NotReady)?;
    match purpose {
        Purpose::AddPat(target) | Purpose::ReplacePat(target) => {
            // M6 T28 (T20 m-9): a token is not stored while "Prepare for removal" deletes tokens
            // or finishes: a window that outlived the claim (opened before it, or kept alive by a
            // submit already under way) cannot put a PAT in the keychain meanwhile.
            if app
                .try_state::<crate::removal::RemovalState>()
                .is_some_and(|r| r.busy())
            {
                return Err(CommandError::Busy);
            }
            let core = super::core(app)?;
            let outcome = submit_pat_dto(core.instances(), &target, args).await;
            if matches!(outcome, Ok(SubmitOutcome::Ok(_))) {
                // The token and the instance's state changed: an open Settings window re-reads.
                crate::ui_sink::emit_settings_changed(app);
            }
            outcome
        }
        Purpose::RecoveryPassphrase => {
            let pair = match passphrase_pair(args)? {
                Ok(pair) => pair,
                Err(failed) => return Ok(failed),
            };
            // No wizard waits: nothing is handed on (the pair is dropped, zeroized).
            if credential::hand_over(app, pair).is_err() {
                return Err(CommandError::NotReady);
            }
            Ok(SubmitOutcome::Accepted {})
        }
        Purpose::RecoverThisLog | Purpose::FinishRestore => {
            let passphrase = unlock_passphrase(args)?;
            let state = serve_state(app).ok_or(CommandError::NotReady)?;
            let kind = if purpose == Purpose::RecoverThisLog {
                UnlockKind::RecoverThisLog
            } else {
                UnlockKind::FinishRestore
            };
            match serve::unlock(&state, kind, passphrase).await {
                Ok(()) => {
                    close_after_answer(app, generation);
                    Ok(SubmitOutcome::Unlocked {})
                }
                Err(f) => Ok(SubmitOutcome::Failed(SubmitFailure::class(f.class()))),
            }
        }
        Purpose::RestoreBackup => {
            let passphrase = unlock_passphrase(args)?;
            match credential::hand_restore_passphrase(app, passphrase) {
                // A window Settings opened has done its part; the restore answers in Settings.
                Ok(false) => close_after_answer(app, generation),
                // Set in place of the locked purpose: `restore_from_backup` answers here.
                Ok(true) => {}
                // No restore waits (it ended): the entry is dropped, zeroized.
                Err(_) => return Err(CommandError::NotReady),
            }
            Ok(SubmitOutcome::Accepted {})
        }
        Purpose::ChangeRecoveryPassphrase => {
            let state = serve_state(app).ok_or(CommandError::NotReady)?;
            let store = state.open_store().ok_or(CommandError::NotReady)?;
            // Not once the quit path began (no record after `APP_STOP`).
            if state.shutting_down() {
                return Err(CommandError::NotReady);
            }
            let outcome = change_passphrase_dto(store, args).await?;
            if matches!(outcome, SubmitOutcome::Accepted {}) {
                // The window offers the recovery note now (if it is still this window); Settings
                // and the Audit window (the `CREDENTIAL_CHANGED` record, T14 review M-6) re-read.
                credential::mark_passphrase_changed(app, generation);
                crate::ui_sink::emit_settings_changed(app);
                crate::ui_sink::emit_audit_changed(app);
            }
            Ok(outcome)
        }
        // `keychain_unavailable`: nothing to type in v1 (L39); "Retry keychain" instead.
        Purpose::Unlock => Err(CommandError::NotReady),
    }
}

/// `submit_secret {secret, secret_confirm?, expires_on?}` (Δ1, §10.3): the secret for the purpose
/// Rust opened the window for. The answer never holds the secret.
#[tauri::command]
pub async fn submit_secret<R: Runtime>(
    app: AppHandle<R>,
    args: Args<SubmitSecretArgs>,
) -> Result<SubmitOutcome, CommandError> {
    let Args(args) = args;
    let response = submit(&app, args).await;
    finish(&app, response)
}

/// plan text (T20): the save dialog's title and file-type filter.
const NOTE_DIALOG_TITLE: T = T::new(
    "Save the atlas-duck recovery note",
    "Wiederherstellungsnotiz von atlas-duck speichern",
);

/// The texts of this module, for [`crate::i18n::all`].
pub const TEXTS: &[&T] = &[&NOTE_DIALOG_TITLE];
const NOTE_FILTER: &str = "Text";

/// `save_recovery_note {}` (§8.6, §10.3): after the first-run passphrase went to the wizard and
/// the new store serves, Rust opens a native save dialog and writes the recovery note there. The
/// note never contains the passphrase; the path never reaches the webview.
#[tauri::command]
pub async fn save_recovery_note<R: Runtime>(
    app: AppHandle<R>,
    args: Args<SaveRecoveryNoteArgs>,
) -> Result<NoteSaved, CommandError> {
    let Args(SaveRecoveryNoteArgs {}) = args;
    let response = save_note(&app).await;
    finish(&app, response)
}

async fn save_note<R: Runtime>(app: &AppHandle<R>) -> Result<NoteSaved, CommandError> {
    let handle = app.clone();
    save_note_with(app, move || pick_note_file(&handle)).await
}

/// Rust's save dialog for the recovery note; `None` when cancelled. Blocks until the user answers:
/// the blocking pool only.
fn pick_note_file<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<Option<std::path::PathBuf>, CommandError> {
    use tauri_plugin_dialog::DialogExt;
    let Some(chosen) = app
        .dialog()
        .file()
        .set_title(NOTE_DIALOG_TITLE.get(crate::windows::ui_lang(app)))
        .set_file_name(credential::NOTE_FILE_NAME)
        .add_filter(NOTE_FILTER, &["txt"])
        .blocking_save_file()
    else {
        return Ok(None);
    };
    chosen
        .into_path()
        .map(Some)
        .map_err(|_| CommandError::Internal)
}

/// `save_recovery_note` with its save dialog passed in (`pick`, M10 T14: the tests' seam, so the
/// note written is the one this path builds): only while the window offers the note, built from
/// facts that hold no secret ([`credential::note_text`]), written where `pick` answered. `pick`
/// runs on the blocking pool.
pub async fn save_note_with<R, F>(app: &AppHandle<R>, pick: F) -> Result<NoteSaved, CommandError>
where
    R: Runtime,
    F: FnOnce() -> Result<Option<std::path::PathBuf>, CommandError> + Send + 'static,
{
    let offered = credential::current_purpose(app).is_some_and(|p| note_offered(app, &p));
    if !offered {
        return Err(CommandError::NotReady);
    }
    let (install_id, chain_id, data) = serve_state(app)
        .and_then(|s| s.note_facts())
        .ok_or(CommandError::NotReady)?;
    let lang = ui_lang(app);
    let facts = NoteFacts {
        host: atlas_duck_ipc::paths::host_name().unwrap_or_default(),
        os_user: credential::os_user(),
        install_id,
        chain_id,
        data_dir: data.display().to_string(),
    };
    // The dialog blocks until the user answers: on the blocking pool, never the main thread.
    blocking(move || {
        let Some(path) = pick()? else {
            return Ok(NoteSaved { saved: false });
        };
        std::fs::write(&path, credential::note_text(&facts, lang))
            .map_err(|_| CommandError::Internal)?;
        Ok(NoteSaved { saved: true })
    })
    .await
}

/// `archive_and_start_fresh {}` (§8.7, §10.3): only for a `keychain_lost` window. Rust shows the
/// native confirmation naming the archive folder, moves the store aside (never deleting it), keeps
/// the [`atlas_duck_audit::ArchivedDb`] for the wizard's `GENESIS` (Task 23), closes this window
/// and opens the setup window (wizard step (1b)).
#[tauri::command]
pub async fn archive_and_start_fresh<R: Runtime>(
    app: AppHandle<R>,
    args: Args<ArchiveAndStartFreshArgs>,
) -> Result<ArchiveOutcome, CommandError> {
    let Args(ArchiveAndStartFreshArgs {}) = args;
    let response = archive(&app).await;
    finish(&app, response)
}

async fn archive<R: Runtime>(app: &AppHandle<R>) -> Result<ArchiveOutcome, CommandError> {
    let window = credential::current_window(app);
    let Some((Purpose::RecoverThisLog | Purpose::FinishRestore, generation)) = window else {
        return Err(CommandError::NotReady);
    };
    let state = serve_state(app).ok_or(CommandError::NotReady)?;
    match serve::archive_and_start_fresh(&state).await {
        Ok(archived) => {
            let archived_file = archived.file.clone();
            credential::set_archived(app, archived);
            let handle = app.clone();
            tauri::async_runtime::spawn_blocking(move || {
                credential::close_if(&handle, generation);
                // `open` logs its own failure.
                let _ = windows::open(&handle, Label::Setup, Show::Focus);
            });
            Ok(ArchiveOutcome::Archived { archived_file })
        }
        Err(f) => Ok(ArchiveOutcome::Failed(SubmitFailure::class(f.class()))),
    }
}

/// `restore_from_backup {}` (M10 T13, PD-168, Δ-M10-3): "Restore a backup instead", only for a
/// `keychain_lost` window ("Recover this log" / "Finish restore"). Rust shows the native "Restore
/// backup" confirmation and its file dialog, then sets this window in place to `restore_backup`
/// (announced) for the backup's passphrase (`submit_secret`), then `restore_from_source` moves the
/// locked store aside and the core starts on the restored one (`serve::restore_from_backup`). The
/// answer: `unlocked {}` (the window closes) or `failed {class}` (the window goes back to its
/// locked purpose; `cancelled`, `archive_first`, `wrong_passphrase`, `not_a_backup`,
/// `committed_incomplete`, ...).
#[tauri::command]
pub async fn restore_from_backup<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RestoreFromBackupArgs>,
) -> Result<SubmitOutcome, CommandError> {
    let Args(RestoreFromBackupArgs {}) = args;
    let response = restore_in_place(&app).await;
    finish(&app, response)
}

async fn restore_in_place<R: Runtime>(app: &AppHandle<R>) -> Result<SubmitOutcome, CommandError> {
    let window = credential::current_window(app);
    let Some((Purpose::RecoverThisLog | Purpose::FinishRestore, generation)) = window else {
        return Err(CommandError::NotReady);
    };
    let state = serve_state(app).ok_or(CommandError::NotReady)?;
    let (pick_app, pass_app) = (app.clone(), app.clone());
    let restored = serve::restore_from_backup(
        &state,
        Box::new(move || crate::restore_flow::pick_restore_source(&pick_app)),
        Box::new(move |stop| {
            use crate::restore_flow::NotAsked;
            let request =
                credential::enter_restore(&pass_app, generation).map_err(|e| match e {
                    WindowError::Busy => NotAsked::Busy,
                    _ => NotAsked::NoWindow,
                })?;
            crate::restore_flow::wait_passphrase(&request.rx, stop)
        }),
    )
    .await;
    match restored {
        Ok(()) => {
            close_after_answer(app, generation);
            Ok(SubmitOutcome::Unlocked {})
        }
        Err(f) => {
            let handle = app.clone();
            // `leave_restore` waits for `opening`: off the async workers.
            let _ = tauri::async_runtime::spawn_blocking(move || {
                credential::leave_restore(&handle, generation)
            })
            .await;
            Ok(SubmitOutcome::Failed(SubmitFailure::class(f.class())))
        }
    }
}

/// `close_credential {}` (M6 T25, §10.3): the window closes itself. Rust forgets the purpose (and a
/// pending first-run passphrase request, which the wizard sees as "the window closed") and then
/// destroys the window and its webview, exactly as the OS close button does, so it adds no
/// capability; `credential::close` runs on the blocking pool because it takes the registry's
/// `opening` lock. The answer is sent before the page is gone (or fails to be, which the page
/// cannot tell and does not need to).
#[tauri::command]
pub async fn close_credential<R: Runtime>(
    app: AppHandle<R>,
    args: Args<CloseCredentialArgs>,
) -> Result<(), CommandError> {
    let Args(CloseCredentialArgs {}) = args;
    let handle = app.clone();
    let response = match credential::current_window(&app) {
        None => Err(CommandError::NotReady),
        Some((_, generation)) => {
            // The window that is open when this handler runs (Tauri hands the handler the label,
            // not the webview instance): a window opened *after* the handler read its generation
            // is left alone, but one built between the page's click and this read is closed. That
            // is what the OS close button would do; the user reopens it.
            tauri::async_runtime::spawn_blocking(move || credential::close_if(&handle, generation));
            Ok(())
        }
    };
    finish(&app, response)
}

/// `retry_keychain {}` (PD-89): one more keystore + `open` while the app is locked
/// `keychain_unavailable`; `not_ready` in any other state.
#[tauri::command]
pub async fn retry_keychain<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RetryKeychainArgs>,
) -> Result<RetryStarted, CommandError> {
    let Args(RetryKeychainArgs {}) = args;
    let response = match serve_state(&app).map(|s| serve::retry_keychain_now(&s)) {
        Some(serve::RetryNow::Started) => Ok(RetryStarted { started: true }),
        Some(serve::RetryNow::AlreadyRunning) => Ok(RetryStarted { started: false }),
        Some(serve::RetryNow::NotLocked | serve::RetryNow::ShuttingDown) | None => {
            Err(CommandError::NotReady)
        }
    };
    finish(&app, response)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::commands::dto::{FIELD_PAYLOAD, parse};

    const CANARY: &str = "canary-PAT-7f3a9c";

    fn field(body: Value) -> Option<&'static str> {
        match parse::<SubmitSecretArgs>(&body) {
            Err(CommandError::InvalidArgument { field }) => Some(field),
            _ => None,
        }
    }

    #[test]
    fn submit_secret_args_parse_and_bound_every_field() {
        let ok = parse::<SubmitSecretArgs>(&json!({
            "secret": CANARY,
            "secret_confirm": CANARY,
            "expires_on": "2027-02-28",
        }))
        .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(ok.secret.0.expose_secret(), CANARY);
        assert_eq!(
            ok.expires_on,
            NaiveDate::from_ymd_opt(2027, 2, 28).map(ExpiryDate)
        );
        // Optional keys may be absent or null.
        let bare = parse::<SubmitSecretArgs>(&json!({"secret": CANARY, "secret_confirm": null}))
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert!(bare.secret_confirm.is_none() && bare.expires_on.is_none());

        let max = "x".repeat(SECRET_MAX_BYTES);
        assert!(parse::<SubmitSecretArgs>(&json!({ "secret": max })).is_ok());
        for bad in [
            json!({"secret": "x".repeat(SECRET_MAX_BYTES + 1)}),
            json!({"secret": ""}),
            json!({"secret": "a\u{0}b"}),
            json!({"secret": 7}),
            json!({"secret": ["c", "a"]}),
            json!({"secret": null}),
            json!({}),
        ] {
            assert_eq!(field(bad.clone()), Some("secret"), "{bad}");
        }
        assert_eq!(
            field(json!({"secret": CANARY, "secret_confirm": ""})),
            Some("secret_confirm")
        );
        for date in [
            "2027-02-30",
            "2027-2-28",
            "27-02-28",
            "2027/02/28",
            "2027-02-28T00:00",
            "+027-02-28",
            "",
        ] {
            assert_eq!(
                field(json!({"secret": CANARY, "expires_on": date})),
                Some("expires_on"),
                "{date}"
            );
        }
        assert_eq!(
            field(json!({"secret": CANARY, "expires_on": 20270228})),
            Some("expires_on")
        );
        // Unknown keys and non-object bodies: the payload.
        assert_eq!(
            field(json!({"secret": CANARY, "alias": "other"})),
            Some(FIELD_PAYLOAD)
        );
        assert_eq!(field(json!([CANARY])), Some(FIELD_PAYLOAD));
    }

    /// The secret is in no `Debug` of the arguments, of a refusal or of its wire form.
    #[test]
    fn no_debug_or_error_shows_the_secret() {
        let args = parse::<SubmitSecretArgs>(&json!({
            "secret": CANARY,
            "secret_confirm": CANARY,
            "expires_on": "2027-01-31",
        }))
        .unwrap_or_else(|e| panic!("{e:?}"));
        let debug = format!("{args:?} {:#?}", args);
        assert!(!debug.contains(CANARY), "{debug}");
        assert!(debug.contains("[redacted]") && debug.contains("2027-01-31"));

        // A refused secret: the error names the field only.
        let long = format!("{CANARY}{}", "x".repeat(SECRET_MAX_BYTES));
        for body in [
            json!({ "secret": long }),
            json!({"secret": CANARY, "extra": CANARY}),
            json!({"secret": format!("{CANARY}\u{0}")}),
        ] {
            let e = match parse::<SubmitSecretArgs>(&body) {
                Err(e) => e,
                Ok(_) => panic!("accepted {body}"),
            };
            let shown = format!(
                "{e:?} {e} {}",
                serde_json::to_string(&e).unwrap_or_default()
            );
            assert!(!shown.contains(CANARY), "{shown}");
        }
    }

    fn payload<T>() -> Result<T, CommandError> {
        Err(CommandError::InvalidArgument {
            field: FIELD_PAYLOAD,
        })
    }

    #[test]
    fn empty_argument_structs_take_nothing() {
        assert_eq!(
            parse::<CredentialContextArgs>(&json!({})),
            Ok(CredentialContextArgs {})
        );
        assert_eq!(
            parse::<CredentialContextArgs>(&json!({"alias": "b"})),
            payload()
        );
        assert_eq!(
            parse::<SaveRecoveryNoteArgs>(&json!({"file": "/tmp/x"})),
            payload()
        );
        assert_eq!(
            parse::<ArchiveAndStartFreshArgs>(&json!({"confirmed": true})),
            payload()
        );
        assert_eq!(parse::<RetryKeychainArgs>(&json!({"now": true})), payload());
        assert_eq!(
            parse::<RetryKeychainArgs>(&json!({})),
            Ok(RetryKeychainArgs {})
        );
    }

    #[test]
    fn keys_per_purpose() {
        let args = |v: Value| parse::<SubmitSecretArgs>(&v).unwrap_or_else(|e| panic!("{e:?}"));
        let twelve = "twelve-chars";
        // First run: the confirmation is required, the expiry refused, the pair checked.
        assert!(matches!(
            passphrase_pair(args(json!({ "secret": twelve }))),
            Err(CommandError::InvalidArgument {
                field: "secret_confirm"
            })
        ));
        assert!(matches!(
            passphrase_pair(args(
                json!({"secret": twelve, "secret_confirm": twelve, "expires_on": "2027-01-01"})
            )),
            Err(CommandError::InvalidArgument {
                field: "expires_on"
            })
        ));
        let mismatch = passphrase_pair(args(
            json!({"secret": twelve, "secret_confirm": "twelve-charZ"}),
        ));
        assert!(matches!(
            mismatch,
            Ok(Err(SubmitOutcome::Failed(SubmitFailure {
                class: "passphrase_mismatch",
                conn: None
            })))
        ));
        let short = passphrase_pair(args(json!({"secret": "short", "secret_confirm": "short"})));
        assert!(matches!(
            short,
            Ok(Err(SubmitOutcome::Failed(SubmitFailure {
                class: "passphrase_too_short",
                ..
            })))
        ));
        assert!(matches!(
            passphrase_pair(args(json!({"secret": twelve, "secret_confirm": twelve}))),
            Ok(Ok(_))
        ));
        // Unlock: one entry only.
        assert!(unlock_passphrase(args(json!({ "secret": twelve }))).is_ok());
        assert!(matches!(
            unlock_passphrase(args(json!({"secret": twelve, "secret_confirm": twelve}))),
            Err(CommandError::InvalidArgument {
                field: "secret_confirm"
            })
        ));
        assert!(matches!(
            unlock_passphrase(args(json!({"secret": twelve, "expires_on": "2027-01-01"}))),
            Err(CommandError::InvalidArgument {
                field: "expires_on"
            })
        ));
    }

    #[test]
    fn outcomes_have_their_wire_shapes() {
        let v = |o: &SubmitOutcome| serde_json::to_value(o).unwrap_or_default();
        assert_eq!(v(&SubmitOutcome::Accepted {}), json!({"accepted": {}}));
        assert_eq!(v(&SubmitOutcome::Unlocked {}), json!({"unlocked": {}}));
        assert_eq!(
            v(&SubmitOutcome::Failed(SubmitFailure::class(
                "wrong_passphrase"
            ))),
            json!({"failed": {"class": "wrong_passphrase"}})
        );
        assert_eq!(
            v(&SubmitOutcome::Failed(connection_failure(
                &ConnectionFailure::Http401
            ))),
            json!({"failed": {"class": "http_401"}})
        );
        let ok = SubmitOutcome::Ok(Connected {
            atlassian_user: "alice".into(),
            product: "jira",
            version: "9.12.0".into(),
            warnings: vec![],
        });
        assert_eq!(
            v(&ok),
            json!({"ok": {"atlassian_user": "alice", "product": "jira", "version": "9.12.0", "warnings": []}})
        );
        let target = PatTarget {
            alias: "work".into(),
            product: "jira",
            origin: "https://jira.example/jira".into(),
        };
        let pat = context_dto(&Purpose::ReplacePat(target), Some(4), false, Lang::De);
        assert_eq!(
            serde_json::to_value(&pat).unwrap_or_default(),
            json!({"purpose": "replace_pat", "alias": "work", "product": "jira",
                   "base_url": "https://jira.example/jira", "refused_count": null,
                   "product_version_hint": null, "note_available": false, "lang": "de"})
        );
        let locked = context_dto(&Purpose::RecoverThisLog, Some(6), false, Lang::En);
        assert_eq!(locked.refused_count, Some(6));
        assert_eq!(locked.alias, None);
    }

    /// M10 T14 review I-3 (PD-169): a pair the window accepts but the store does not commit (the
    /// writer refuses or fails: a restore that replaced the store meanwhile, a failed write) is
    /// the failed outcome `passphrase_not_changed`, with nothing recorded and the old passphrase
    /// still the one; a store that no longer serves is `not_ready`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_change_the_store_does_not_commit_is_passphrase_not_changed()
    -> Result<(), Box<dyn std::error::Error>> {
        use atlas_duck_audit::EventType;
        use atlas_duck_audit::testing::FaultPoint;

        use crate::commands::audit::tests::{count, rig};
        let r = rig(0)?;
        let pair = || {
            parse::<SubmitSecretArgs>(
                &json!({"secret": "a changed passphrase", "secret_confirm": "a changed passphrase"}),
            )
        };
        let before = count(&r.store, EventType::CREDENTIAL_CHANGED)?;
        r.faults.fail(FaultPoint::RecoveryRowWritten, 1);
        assert_eq!(
            change_passphrase_dto(r.store.clone(), pair()?).await,
            Ok(SubmitOutcome::Failed(SubmitFailure::class(
                CLASS_PASSPHRASE_NOT_CHANGED
            )))
        );
        assert_eq!(count(&r.store, EventType::CREDENTIAL_CHANGED)?, before);

        r.store.shutdown();
        assert_eq!(
            change_passphrase_dto(r.store.clone(), pair()?).await,
            Err(CommandError::NotReady)
        );
        Ok(())
    }
}
