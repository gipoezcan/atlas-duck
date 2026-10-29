//! The Audit window's commands (C.10 + Δ1, Δ-M10-3; §8.10, §10.3 Audit row, PD-180, PD-181; M6 T30,
//! M10 T12): `verify_now`, the read-only queries (`audit_query`, `audit_trail`, `audit_status`),
//! the payload view (`audit_payload`), the incident acknowledgement (`acknowledge_incident`) and
//! the export and backup triggers (`export_trigger`, `export_cancel`, `backup_trigger`). Granted to
//! `audit` only, except `backup_trigger`, which Settings holds too (M10 T13).
//!
//! - **No path, no bytes in.** Every argument struct is closed (`deny_unknown_fields`) and bounded
//!   while it is parsed; the export and backup folders come from Rust's own folder dialog.
//! - **Payload bytes leave only through `audit_payload`**, as the sandboxed document (`srcdoc`,
//!   [`render::audit_payload_document`]) and the PD-68 display text of the page; never logged, never
//!   in an error. Every other answer carries plaintext columns only, display-escaped here.
//! - **The acknowledgement is confirmed natively first (PD-180):** the dialog names the `VERIFY`
//!   record's seq, result and detected-at time as the record holds them (never the arguments); a
//!   `Cancel` appends nothing.
//! - **One long job at a time (PD-181):** an export or a backup runs as the serving state's audit job
//!   ([`ServeState::spawn_audit_job`]), dialogs included; `audit_job` events report it, and the quit
//!   path cancels and waits for an export before the core's shutdown.
//!
//! Core decides `verify_now` (`SettingsAdmin::verify_now`: a full verification that appends
//! `VERIFY`; an error is `did_not_complete`, never a pass); the rest talks to the open store.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use atlas_duck_audit::types::RustChosenPath;
use atlas_duck_audit::{
    AuditError, EXPORT_DIR_EXISTS, EXPORT_NO_RECORDS, ExportControl, Store, TimeRange, UtcInstant,
};
use atlas_duck_core::decision::audit_wire::{self, AuditReadError};
// M14 T16 (PD-251): the read DTOs are core's, shared with the server.
pub use atlas_duck_core::decision::audit_wire::{
    AuditPageDto, AuditPayloadArgs, AuditPayloadDto, AuditQueryArgs, AuditStatusArgs,
    AuditStatusDto, AuditTrailArgs, AuditTrailDto, CredentialChangeFailure, CursorArgs, CursorDto,
    DEFAULT_PAGE_ROWS, DeliveriesDto, EventHeaderDto, FilterArgs, IncidentDto,
    MAX_LISTED_INCIDENTS, from_utc, to_utc,
};
use atlas_duck_core::{Confirm, NativeConfirmer, VerifyNow};
use atlas_duck_preview::Platform;
use serde::{Deserialize, Deserializer, Serialize};
use tauri::{AppHandle, Manager, Runtime};

use super::dto::{Args, refuse};
use super::{AuditReadFailure, CommandError, ExportFailure, blocking, core, finish};
use crate::i18n::{Lang, T};
use crate::removal::{self, BackupAnswer, RemovalState};
use crate::serve::{AuditJobKind, JobRefused, ServeState};
use crate::state::ServeSlot;
use crate::ui_sink::{EventOut, emit_audit_changed, emit_audit_job, emit_status_changed};

/// plan text (PD-161): the native warning before the export's folder dialog.
pub const EXPORT_WARNING_TEXT: &str = EXPORT_WARNING.en;
/// [`EXPORT_WARNING_TEXT`] in both languages (M15 T10).
pub const EXPORT_WARNING: T = T::new(
    "The export contains decrypted audit payloads. Any program running as your user can read these files. Exports and backups are outside retention and crypto-shredding: you are responsible for keeping and deleting them.",
    "Der Export enthält entschlüsselte Audit-Nutzdaten. Jedes Programm, das unter Ihrem Benutzer läuft, kann diese Dateien lesen. Exporte und Backups liegen außerhalb von Aufbewahrung und Crypto-Shredding: Sie sind dafür verantwortlich, sie aufzubewahren und zu löschen.",
);
/// The title of the export's folder dialog.
const EXPORT_DIALOG_TITLE: T = T::new(
    "Choose the folder for the atlas-duck export",
    "Wählen Sie den Ordner für den Export von atlas-duck",
);

/// The texts of this module, for [`crate::i18n::all`].
pub const TEXTS: &[&T] = &[&EXPORT_WARNING, &EXPORT_DIALOG_TITLE];
/// PD-180: an acknowledgement's note is at most 1 000 characters.
pub const NOTE_MAX_CHARS: usize = 1_000;

/// PD-180 (plan text): the acknowledgement's native confirmation, from the record's facts.
pub fn acknowledge_text(lang: Lang, verify_seq: u64, result: &str, detected_at: &str) -> String {
    if lang == Lang::De {
        return format!(
            "Integritätsvorfall {verify_seq} ({result}, erkannt {detected_at}) zur Kenntnis \
             nehmen? Das rote Banner verschwindet für diesen Vorfall."
        );
    }
    format!(
        "Acknowledge integrity incident {verify_seq} ({result}, detected {detected_at})? The red \
         banner is cleared for this incident."
    )
}

// ---------- arguments ----------

/// `verify_now {}`: no key (the store is the one the app serves).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyNowArgs {}

/// The acknowledgement's note (PD-180): at most [`NOTE_MAX_CHARS`] characters, no NUL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note(String);

impl Note {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Note {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d).map_err(|_| refuse::<D::Error>("note"))?;
        if s.contains('\0') || s.chars().count() > NOTE_MAX_CHARS {
            return Err(refuse("note"));
        }
        Ok(Note(s))
    }
}

/// `acknowledge_incident {verify_seq, note}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeIncidentArgs {
    pub verify_seq: u64,
    pub note: Note,
}

/// `export_trigger {from_utc, to_utc}`: inclusive UTC bounds (PD-160); `null` (or absent) is open
/// on that side, both `null` is the full range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportTriggerArgs {
    #[serde(default, deserialize_with = "from_utc")]
    pub from_utc: Option<UtcInstant>,
    #[serde(default, deserialize_with = "to_utc")]
    pub to_utc: Option<UtcInstant>,
}

impl ExportTriggerArgs {
    /// The range to export; `to_utc` before `from_utc` is refused before any dialog.
    pub fn range(&self) -> Result<TimeRange, CommandError> {
        let all = TimeRange::all();
        let range = TimeRange {
            from_utc: self.from_utc.unwrap_or(all.from_utc),
            to_utc: self.to_utc.unwrap_or(all.to_utc),
        };
        if range.from_utc > range.to_utc {
            return Err(CommandError::InvalidArgument { field: "to_utc" });
        }
        Ok(range)
    }
}

/// `export_cancel {}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportCancelArgs {}

/// `backup_trigger {}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupTriggerArgs {}

/// `acknowledge_incident`'s answer: the incident and the `INTEGRITY_ACK` that closed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AcknowledgedDto {
    pub verify_seq: u64,
    pub ack_seq: u64,
}

/// `export_trigger`'s answer: what the recipient instructions name (PD-161). `dir_name` is the new
/// directory's name inside the chosen folder (never a path).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportDoneDto {
    pub manifest_sha256: String,
    pub dir_name: String,
    pub rows: u64,
}

/// `export_cancel`'s answer: `false` when no export runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExportCancelDto {
    pub cancelled: bool,
}

// ---------- the work (sync; the commands run it on the blocking pool) ----------

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// M14 T16 (PD-251): the read DTOs and their reads live in `core::decision::audit_wire`, shared
/// with the server; here their errors become the app's `CommandError`.
fn wire_error(e: AuditReadError) -> CommandError {
    match e {
        AuditReadError::InvalidArgument { field } => CommandError::InvalidArgument { field },
        AuditReadError::NotFound => CommandError::NotFound,
        AuditReadError::NotReady => CommandError::NotReady,
        AuditReadError::Unreadable { seq } => {
            CommandError::Audit(AuditReadFailure::Unreadable { seq })
        }
        AuditReadError::Failed => CommandError::Audit(AuditReadFailure::Failed),
    }
}

/// `audit_query`: one page of matching headers (plaintext columns only; L38).
pub fn query_dto(store: &Store, args: AuditQueryArgs) -> Result<AuditPageDto, CommandError> {
    audit_wire::query(store, args).map_err(wire_error)
}

/// `audit_trail`: every header of a request and its delivery summary.
pub fn trail_dto(store: &Store, request_id: &str) -> Result<AuditTrailDto, CommandError> {
    audit_wire::trail(store, request_id).map_err(wire_error)
}

/// `audit_payload`: page `page` of record `seq`'s decrypted payload (PD-68 paging).
pub fn payload_dto(
    store: &Store,
    seq: u64,
    page: u32,
    platform: Platform,
) -> Result<AuditPayloadDto, CommandError> {
    audit_wire::payload(store, seq, page, platform).map_err(wire_error)
}

/// The result and detected-at time of the `VERIFY` record `seq` (fail closed: `unreadable`).
pub fn incident_facts(store: &Store, seq: u64) -> Result<(String, String), CommandError> {
    audit_wire::incident_facts(store, seq).map_err(wire_error)
}

/// `audit_status`: the open incidents with their facts, the health and the anchor directory.
pub fn status_dto(store: &Store) -> Result<AuditStatusDto, CommandError> {
    audit_wire::status(store).map_err(wire_error)
}

/// `acknowledge_incident` (§8.7, PD-180): only an open incident; the native confirmation names the
/// record's seq, result and detected-at time; `Cancel` appends nothing. Then `INTEGRITY_ACK
/// {verify_seq, os_user, note}`, `audit_changed` and `status_banner` (T12 review I-2: the headers'
/// red `integrity_incident` line comes from the open incidents and is read again).
pub fn acknowledge_dto(
    store: &Store,
    confirmer: &dyn NativeConfirmer,
    verify_seq: u64,
    note: &str,
    os_user: &str,
    out: &dyn EventOut,
) -> Result<AcknowledgedDto, CommandError> {
    if !store.open_incidents().contains(&verify_seq) {
        return Err(CommandError::NotFound);
    }
    let (result, detected_at) = incident_facts(store, verify_seq)?;
    if confirmer.confirm(&acknowledge_text(
        out.lang(),
        verify_seq,
        &result,
        &detected_at,
    )) != Confirm::Ok
    {
        return Err(CommandError::Cancelled);
    }
    match store.acknowledge_incident(verify_seq, os_user, note) {
        Ok(ack) => {
            emit_audit_changed(out);
            emit_status_changed(out);
            Ok(AcknowledgedDto {
                verify_seq,
                ack_seq: ack.seq,
            })
        }
        // Acknowledged meanwhile (a second window's click, a race with this one).
        Err(AuditError::Invalid(_)) => Err(CommandError::NotFound),
        Err(AuditError::Closed) => Err(CommandError::NotReady),
        Err(_) => Err(CommandError::Audit(AuditReadFailure::Failed)),
    }
}

/// The export (§8.10, PD-159..PD-161, PD-181), on the audit job's thread: the PD-161 warning as a
/// native dialog, then Rust's folder dialog (`pick`), then `Store::export` with `cancel` and the
/// progress as `audit_job` events. Either dialog cancelled, or `cancel` set before the export, is
/// `cancelled` with nothing written and no event.
pub fn run_export(
    store: &Store,
    confirmer: &dyn NativeConfirmer,
    pick: impl FnOnce() -> Option<RustChosenPath>,
    range: TimeRange,
    cancel: &AtomicBool,
    out: &dyn EventOut,
) -> Result<ExportDoneDto, CommandError> {
    use std::sync::atomic::Ordering;
    let job = AuditJobKind::Export;
    if confirmer.confirm(EXPORT_WARNING.get(out.lang())) != Confirm::Ok {
        return Err(CommandError::Cancelled);
    }
    if cancel.load(Ordering::SeqCst) {
        return Err(CommandError::Cancelled);
    }
    let Some(dir) = pick() else {
        return Err(CommandError::Cancelled);
    };
    if cancel.load(Ordering::SeqCst) {
        return Err(CommandError::Cancelled);
    }
    emit_audit_job(out, job, "started", None);
    let progress =
        |done: u64, total: u64| emit_audit_job(out, job, "progress", Some((done, total)));
    let r = store.export(
        range,
        dir,
        &ExportControl {
            progress: &progress,
            cancel,
        },
    );
    match r {
        Ok(receipt) => {
            emit_audit_job(out, job, "done", None);
            emit_audit_changed(out);
            Ok(ExportDoneDto {
                manifest_sha256: hex(&receipt.manifest_sha256),
                dir_name: receipt.dir_name,
                rows: receipt.rows,
            })
        }
        // Complete and logged under its staging name: `done` (the record is in the log), with the
        // receipt in the error so the window shows the hash and asks for the rename.
        Err(AuditError::ExportNotRenamed(receipt)) => {
            emit_audit_job(out, job, "done", None);
            emit_audit_changed(out);
            Err(CommandError::Export(ExportFailure::NotRenamed {
                manifest_sha256: hex(&receipt.manifest_sha256),
                dir_name: receipt.dir_name,
                rows: receipt.rows,
            }))
        }
        Err(AuditError::Cancelled) => {
            emit_audit_job(out, job, "cancelled", None);
            Err(CommandError::Cancelled)
        }
        Err(e) => {
            emit_audit_job(out, job, "failed", None);
            Err(CommandError::Export(export_failure(e)))
        }
    }
}

/// The window's kind of a failed export (not `Cancelled`, not `ExportNotRenamed`): the cases the
/// user can act on by name, `failed` for the rest. The leftover's cause is dropped (OS text).
fn export_failure(e: AuditError) -> ExportFailure {
    match e {
        AuditError::ExportLeftover { dir_name, .. } => ExportFailure::Leftover { dir_name },
        AuditError::Invalid(EXPORT_NO_RECORDS) => ExportFailure::EmptyRange,
        AuditError::Invalid(EXPORT_DIR_EXISTS) => ExportFailure::Exists,
        _ => ExportFailure::Failed,
    }
}

/// The backup (§8.10) the Audit window triggers, inside `removal::backup`'s claim (the M6 path of
/// "Prepare for removal" step 1): Rust's folder dialog (`pick`; `Ok(false)` when cancelled), then
/// `Store::backup`, which logs `BACKUP` itself. `audit_job` is indeterminate (PD-181). `cancel`
/// set while the dialog was open (Quit, T12 review I-3) is `cancelled` with nothing written: no
/// `BACKUP` after the quit path moved on. Once `Store::backup` runs it is not interrupted.
pub fn run_backup(
    store: &Store,
    pick: impl FnOnce() -> Result<Option<RustChosenPath>, CommandError>,
    cancel: &AtomicBool,
    out: &dyn EventOut,
) -> Result<bool, CommandError> {
    let job = AuditJobKind::Backup;
    let Some(dir) = pick()? else {
        return Ok(false);
    };
    if cancel.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(CommandError::Cancelled);
    }
    emit_audit_job(out, job, "started", None);
    match store.backup(dir) {
        Ok(_) => {
            emit_audit_job(out, job, "done", None);
            emit_audit_changed(out);
            Ok(true)
        }
        Err(_) => {
            emit_audit_job(out, job, "failed", None);
            Err(CommandError::Backup)
        }
    }
}

/// Rust's folder dialog for the export (no window holds the dialog plugin's commands, §10.3; also
/// "Prepare for removal"'s export, M10 T16); `None` when cancelled. Blocks until the user answers:
/// the audit job's thread only.
pub(crate) fn pick_export_folder<R: Runtime>(app: &AppHandle<R>) -> Option<RustChosenPath> {
    use tauri_plugin_dialog::DialogExt;
    let chosen = app
        .dialog()
        .file()
        .set_title(EXPORT_DIALOG_TITLE.get(crate::windows::ui_lang(app)))
        .blocking_pick_folder()?;
    let path = chosen.into_path().ok()?;
    Some(RustChosenPath::from_native_dialog(path))
}

// ---------- the commands ----------

/// The serving state; `not_ready` before first run, while locked or starting.
fn serving<R: Runtime>(app: &AppHandle<R>) -> Result<Arc<ServeState>, CommandError> {
    app.try_state::<ServeSlot>()
        .and_then(|slot| slot.get().cloned())
        .ok_or(CommandError::NotReady)
}

/// The open store; `not_ready` while none is open.
fn open_store<R: Runtime>(app: &AppHandle<R>) -> Result<Store, CommandError> {
    serving(app)?.open_store().ok_or(CommandError::NotReady)
}

/// Why a job did not start, as the windows see it: another job holds the serving state's slot is
/// `busy` (not `removal {running}`, which is a removal call's own claim, T28 m-8); the quit path
/// began is `not_ready`.
pub fn job_refused(e: JobRefused) -> CommandError {
    match e {
        JobRefused::Busy => CommandError::Busy,
        JobRefused::ShuttingDown => CommandError::NotReady,
    }
}

/// `verify_now {}` (Δ1, §8.7 "Verify now"): runs the full verification once. A call while one runs
/// is the page's guard to stop: core takes no lock for it (each call opens its own read-only
/// connection and appends its own `VERIFY` record).
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
    verify_now_events(&app, &response);
    finish(&app, response)
}

/// After `verify_now`: an incident it found opened the headers' red `integrity_incident` line, so
/// they read `app_status` again (`status_banner`, T12 review I-2), and the Audit window re-reads
/// its status (`audit_changed`). Any other answer opened none.
pub fn verify_now_events(out: &dyn EventOut, response: &Result<VerifyNow, CommandError>) {
    if let Ok(VerifyNow::Incident { .. }) = response {
        emit_audit_changed(out);
        emit_status_changed(out);
    }
}

/// `audit_query {filter, cursor?}` (§8.10): one page of headers, newest first.
#[tauri::command]
pub async fn audit_query<R: Runtime>(
    app: AppHandle<R>,
    args: Args<AuditQueryArgs>,
) -> Result<AuditPageDto, CommandError> {
    let Args(args) = args;
    let response = match open_store(&app) {
        Ok(store) => blocking(move || query_dto(&store, args)).await,
        Err(e) => Err(e),
    };
    finish(&app, response)
}

/// `audit_trail {request_id}` (§8.10): a request's headers with its deliveries.
#[tauri::command]
pub async fn audit_trail<R: Runtime>(
    app: AppHandle<R>,
    args: Args<AuditTrailArgs>,
) -> Result<AuditTrailDto, CommandError> {
    let Args(AuditTrailArgs { request_id }) = args;
    let response = match open_store(&app) {
        Ok(store) => blocking(move || trail_dto(&store, request_id.as_str())).await,
        Err(e) => Err(e),
    };
    finish(&app, response)
}

/// `audit_payload {seq, page?}` (§8.10, PD-67, PD-68): one page of a record's decrypted payload as
/// the sandboxed document and its display text.
#[tauri::command]
pub async fn audit_payload<R: Runtime>(
    app: AppHandle<R>,
    args: Args<AuditPayloadArgs>,
) -> Result<AuditPayloadDto, CommandError> {
    let Args(AuditPayloadArgs { seq, page }) = args;
    let response = match open_store(&app) {
        Ok(store) => {
            blocking(move || payload_dto(&store, seq, page.unwrap_or(0), Platform::current())).await
        }
        Err(e) => Err(e),
    };
    finish(&app, response)
}

/// `audit_status {}` (§8.10, L134): open incidents, their count, health and the anchor directory.
#[tauri::command]
pub async fn audit_status<R: Runtime>(
    app: AppHandle<R>,
    args: Args<AuditStatusArgs>,
) -> Result<AuditStatusDto, CommandError> {
    let Args(AuditStatusArgs {}) = args;
    let response = match open_store(&app) {
        Ok(store) => blocking(move || status_dto(&store)).await,
        Err(e) => Err(e),
    };
    finish(&app, response)
}

/// `acknowledge_incident {verify_seq, note}` (§8.7, PD-180): Rust's native confirmation first, then
/// `INTEGRITY_ACK` with this OS user; `audit_changed` and `status_banner` after it.
#[tauri::command]
pub async fn acknowledge_incident<R: Runtime>(
    app: AppHandle<R>,
    args: Args<AcknowledgeIncidentArgs>,
) -> Result<AcknowledgedDto, CommandError> {
    let Args(AcknowledgeIncidentArgs { verify_seq, note }) = args;
    let response = async {
        let state = serving(&app)?;
        let store = state.open_store().ok_or(CommandError::NotReady)?;
        let confirmer = state.confirmer().ok_or(CommandError::NotReady)?;
        let os_user = crate::credential::os_user();
        let handle = app.clone();
        blocking(move || {
            acknowledge_dto(
                &store,
                &*confirmer,
                verify_seq,
                note.as_str(),
                &os_user,
                &handle,
            )
        })
        .await
    }
    .await;
    finish(&app, response)
}

/// `export_trigger {from_utc, to_utc}` (§8.10, PD-159..PD-161, PD-181): the PD-161 warning and the
/// folder dialog in Rust, then the export on the audit job's thread with `audit_job` progress;
/// answers the recipient's facts once the export ended.
#[tauri::command]
pub async fn export_trigger<R: Runtime>(
    app: AppHandle<R>,
    args: Args<ExportTriggerArgs>,
) -> Result<ExportDoneDto, CommandError> {
    let Args(args) = args;
    let response = async {
        let range = args.range()?;
        let state = serving(&app)?;
        let store = state.open_store().ok_or(CommandError::NotReady)?;
        let confirmer = state.confirmer().ok_or(CommandError::NotReady)?;
        let handle = app.clone();
        let rx = state
            .spawn_audit_job(AuditJobKind::Export, move |cancel| {
                run_export(
                    &store,
                    &*confirmer,
                    || pick_export_folder(&handle),
                    range,
                    &cancel,
                    &handle,
                )
            })
            .map_err(job_refused)?;
        rx.await.map_err(|_| CommandError::Internal)?
    }
    .await;
    finish(&app, response)
}

/// `export_cancel {}` (PD-181): sets the running export's cancel flag; it ends before its next row,
/// removes its partial directory and logs no `EXPORT`.
#[tauri::command]
pub async fn export_cancel<R: Runtime>(
    app: AppHandle<R>,
    args: Args<ExportCancelArgs>,
) -> Result<ExportCancelDto, CommandError> {
    let Args(ExportCancelArgs {}) = args;
    let cancelled = serving(&app).is_ok_and(|state| state.cancel_export());
    finish(&app, Ok(ExportCancelDto { cancelled }))
}

/// `backup_trigger {}` (§8.10, PD-181): Rust's folder dialog and `Store::backup` through
/// `removal::backup`'s path, as the audit job ([`backup_job`]); `saved: false` is a cancelled
/// dialog.
#[tauri::command]
pub async fn backup_trigger<R: Runtime>(
    app: AppHandle<R>,
    args: Args<BackupTriggerArgs>,
) -> Result<BackupAnswer, CommandError> {
    let Args(BackupTriggerArgs {}) = args;
    let response = backup_job(&app).await;
    finish(&app, response)
}

/// The full backup of `backup_trigger` and of "Prepare for removal"'s `removal_backup` (M10 T16
/// review I-2: one body for both): the serving state's one job (`busy` while another holds the
/// slot; the quit path sets its cancel flag and waits for it), inside `removal::backup`'s claim
/// (`removal {running}` while a removal call runs), [`run_backup`] (a cancel set while the folder
/// dialog was open backs up nothing).
pub(crate) async fn backup_job<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<BackupAnswer, CommandError> {
    let state = serving(app)?;
    let store = state.open_store().ok_or(CommandError::NotReady)?;
    let handle = app.clone();
    let rx = state
        .spawn_audit_job(AuditJobKind::Backup, move |cancel| {
            let removal = handle
                .try_state::<RemovalState>()
                .ok_or(CommandError::NotReady)?;
            removal::backup(&removal, || {
                run_backup(
                    &store,
                    || super::settings::pick_backup_folder(&handle),
                    &cancel,
                    &handle,
                )
            })
        })
        .map_err(job_refused)?;
    rx.await.map_err(|_| CommandError::Internal)?
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    use atlas_duck_audit::lock::InstanceLock;
    use atlas_duck_audit::testing::{FaultPoint, Faults, FreeSpaceStub, MemKeyStore, MemKeyring};
    use atlas_duck_audit::verify::{FindingKind, VerifyFinding};
    use atlas_duck_audit::{
        AuditCursor, AuditFilter, DecisionColumn, EventFlags, EventType, FirstRunInput,
        MAX_AUDIT_PAGE_ROWS, NewEvent, OpenConfig, SystemClock, new_ids,
    };
    use atlas_duck_ipc::paths::{DataDirResolution, LocalDataDir, check_data_dir};
    use secrecy::SecretString;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use super::*;

    pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A store with `rows` `READ_FETCHED` records after its `GENESIS`, export batches of 2 rows, and
    /// an empty folder `out` to export into.
    pub(crate) struct Rig {
        /// Removes the data dir and `out` on drop.
        pub _tmp: tempfile::TempDir,
        pub data: LocalDataDir,
        pub lock: InstanceLock,
        pub ring: Arc<MemKeyring>,
        pub install_id: String,
        pub store: Store,
        pub faults: Arc<Faults>,
        pub out: PathBuf,
    }

    pub(crate) const PASS: &str = "correct horse battery";

    pub(crate) fn config(
        ring: &Arc<MemKeyring>,
        install_id: &str,
        faults: &Arc<Faults>,
    ) -> OpenConfig {
        let keys = Arc::new(MemKeyStore::new(ring.clone(), install_id));
        let mut cfg = OpenConfig::new(Arc::new(SystemClock::new()), keys);
        cfg.free_space = Some(FreeSpaceStub::new(u64::MAX));
        cfg.hooks.faults = Some(faults.clone());
        cfg.hooks.export_batch_rows = Some(2);
        cfg
    }

    pub(crate) fn rig(rows: usize) -> Result<Rig, Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("data");
        std::fs::create_dir(&dir)?;
        let DataDirResolution::Local(data) = check_data_dir(&dir)? else {
            return Err("the temp dir is not a local data dir".into());
        };
        let lock = InstanceLock::acquire(&data, "thishost")?;
        let (install_id, chain_id) = new_ids()?;
        let ring = MemKeyring::new();
        let faults = Faults::new();
        let store = atlas_duck_audit::create_new_store(
            &data,
            &lock,
            config(&ring, &install_id, &faults),
            FirstRunInput {
                install_id: install_id.clone(),
                chain_id,
                passphrase: SecretString::from(PASS.to_owned()),
                passphrase_confirm: SecretString::from(PASS.to_owned()),
                archived_db: None,
                anchor_dir: None,
                archive_confirmed: None,
            },
        )?;
        for i in 0..rows {
            store.append(NewEvent {
                event_type: EventType::READ_FETCHED,
                request_id: Some("req_0123456789abcdefghij".into()),
                op_id: Some("jira.issue.get".into()),
                op_class: Some("read".into()),
                instance_id: None,
                target: Some(format!("PROJ-{i}\u{202E}")),
                actor: atlas_duck_audit::Actor {
                    agent_name: Some("agent <b>x</b>".into()),
                    ..Default::default()
                },
                decision: None,
                flags: EventFlags::default(),
                payload: json!({"i": i, "body": "<script>alert(1)</script>"}),
            })?;
        }
        let out = tmp.path().join("out");
        std::fs::create_dir(&out)?;
        Ok(Rig {
            _tmp: tmp,
            data,
            lock,
            ring,
            install_id,
            store,
            faults,
            out,
        })
    }

    /// Appends one `VERIFY {result: chain_broken}` flagged `integrity_incident`; its seq.
    pub(crate) fn incident(store: &Store) -> Result<u64, Box<dyn std::error::Error>> {
        let (_, generation) = store.testing_full_verify_run()?;
        let finding = VerifyFinding {
            kind: FindingKind::ChainBroken,
            expected_seq: None,
            expected_hash: None,
            observed_seq: None,
            observed_hash: None,
            detail: "test incident".into(),
        };
        Ok(store
            .testing_full_verify_append(&[finding], generation)?
            .seq)
    }

    /// The confirmer's answers, in order, and every text it was shown (or `Cancel` when out of
    /// answers); `log` gets one `confirm` line per dialog.
    #[derive(Default)]
    pub(crate) struct Answers {
        pub answers: Mutex<VecDeque<Confirm>>,
        pub texts: Mutex<Vec<String>>,
        pub log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl Answers {
        pub fn new(answers: &[Confirm]) -> Answers {
            Answers {
                answers: Mutex::new(answers.iter().copied().collect()),
                ..Answers::default()
            }
        }

        pub fn texts(&self) -> Vec<String> {
            self.texts.lock().map(|t| t.clone()).unwrap_or_default()
        }
    }

    impl NativeConfirmer for Answers {
        fn confirm(&self, text: &str) -> Confirm {
            if let Ok(mut t) = self.texts.lock() {
                t.push(text.to_owned());
            }
            if let Ok(mut l) = self.log.lock() {
                l.push("confirm");
            }
            self.answers
                .lock()
                .ok()
                .and_then(|mut a| a.pop_front())
                .unwrap_or(Confirm::Cancel)
        }
    }

    /// Every event a webview would get.
    #[derive(Default)]
    pub(crate) struct Events(pub Mutex<Vec<(String, Value)>>);

    impl EventOut for Events {
        fn emit(&self, name: &str, payload: Value) {
            if let Ok(mut e) = self.0.lock() {
                e.push((name.to_owned(), payload));
            }
        }
    }

    impl Events {
        pub fn all(&self) -> Vec<(String, Value)> {
            self.0.lock().map(|e| e.clone()).unwrap_or_default()
        }

        /// The `audit_job` phases, in order.
        pub fn phases(&self) -> Vec<String> {
            self.all()
                .iter()
                .filter(|(n, _)| n == "audit_job")
                .filter_map(|(_, p)| p["phase"].as_str().map(str::to_owned))
                .collect()
        }
    }

    pub(crate) fn chosen(p: &Path) -> RustChosenPath {
        RustChosenPath::from_native_dialog(p.to_path_buf())
    }

    pub(crate) fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    /// How many records of `t` the store holds.
    pub(crate) fn count(store: &Store, t: EventType) -> Result<usize, Box<dyn std::error::Error>> {
        let page = store.query(
            &AuditFilter {
                event_types: vec![t],
                ..AuditFilter::default()
            },
            AuditCursor::first(MAX_AUDIT_PAGE_ROWS),
        )?;
        Ok(page.rows.len())
    }

    /// §8.10, PD-161 (Δ-M10-3 `export_trigger`): the warning is a native dialog drawn before Rust's
    /// folder dialog, the export goes into the folder that dialog returned, and the answer carries
    /// the manifest's SHA-256 (the recipient's trust root), the new directory's name and the row
    /// count; `audit_job` reports `started`, a `progress` per batch with row counts, then `done`,
    /// and `audit_changed` follows. A cancelled warning never opens the folder dialog; a cancelled
    /// folder dialog writes nothing; neither emits an event.
    #[test]
    fn export_trigger_runs_dialogs_in_rust_and_reports_hash() -> TestResult {
        let r = rig(5)?;
        let confirmer = Answers::new(&[Confirm::Ok]);
        let log = confirmer.log.clone();
        let picked = log.clone();
        let events = Events::default();
        let cancel = AtomicBool::new(false);
        let done = run_export(
            &r.store,
            &confirmer,
            || {
                if let Ok(mut l) = picked.lock() {
                    l.push("pick");
                }
                Some(chosen(&r.out))
            },
            TimeRange::all(),
            &cancel,
            &events,
        )?;
        assert_eq!(*log.lock().map_err(|_| "log")?, ["confirm", "pick"]);
        assert_eq!(confirmer.texts(), [EXPORT_WARNING_TEXT]);
        assert_eq!(entries(&r.out), std::slice::from_ref(&done.dir_name));
        assert!(!done.dir_name.ends_with(".partial"), "{}", done.dir_name);
        let manifest = std::fs::read(r.out.join(&done.dir_name).join("manifest.json"))?;
        assert_eq!(done.manifest_sha256, hex(&Sha256::digest(&manifest)));
        let (head, _, _) = r.store.head();
        // Every record up to the head is exported; `EXPORT` follows the export.
        assert_eq!(done.rows + 1, head);
        assert_eq!(count(&r.store, EventType::EXPORT)?, 1);
        let all = events.all();
        let phases = events.phases();
        assert_eq!(phases.first().map(String::as_str), Some("started"));
        assert_eq!(phases.last().map(String::as_str), Some("done"));
        let progress: Vec<&Value> = all
            .iter()
            .filter(|(_, p)| p["phase"] == "progress")
            .map(|(_, p)| p)
            .collect();
        assert!(progress.len() >= 3, "a progress per 2-row batch: {all:?}");
        for p in &progress {
            assert_eq!(p["job"], "export");
            assert_eq!(p["total"], json!(done.rows));
            let keys: Vec<&String> = p
                .as_object()
                .map(|m| m.keys().collect())
                .unwrap_or_default();
            assert_eq!(keys, ["done", "job", "phase", "total"], "counts only");
        }
        assert_eq!(
            progress.last().map(|p| p["done"].clone()),
            Some(json!(done.rows))
        );
        assert_eq!(all.last().map(|(n, _)| n.as_str()), Some("audit_changed"));

        // The warning cancelled: no folder dialog, nothing written, no event.
        let confirmer = Answers::new(&[Confirm::Cancel]);
        let events = Events::default();
        let asked = AtomicBool::new(false);
        let res = run_export(
            &r.store,
            &confirmer,
            || {
                asked.store(true, Ordering::SeqCst);
                Some(chosen(&r.out))
            },
            TimeRange::all(),
            &cancel,
            &events,
        );
        assert_eq!(res, Err(CommandError::Cancelled));
        assert!(!asked.load(Ordering::SeqCst), "the folder dialog opened");
        assert!(events.all().is_empty());
        // The folder dialog cancelled: nothing written, no event.
        let res = run_export(
            &r.store,
            &Answers::new(&[Confirm::Ok]),
            || None,
            TimeRange::all(),
            &cancel,
            &events,
        );
        assert_eq!(res, Err(CommandError::Cancelled));
        assert!(events.all().is_empty());
        assert_eq!(entries(&r.out).len(), 1);
        assert_eq!(count(&r.store, EventType::EXPORT)?, 1);
        Ok(())
    }

    /// PD-181: a cancel set while the export runs ends it before its next row: the partial
    /// directory is removed, no `EXPORT` is logged, `audit_job` ends `cancelled`. A range that holds
    /// no record is `export/empty_range` with nothing written.
    #[test]
    fn export_cancelled_mid_run_leaves_nothing() -> TestResult {
        let r = rig(6)?;
        let cancel = Arc::new(AtomicBool::new(false));
        let rows = Arc::new(AtomicU32::new(0));
        {
            let (cancel, rows) = (cancel.clone(), rows.clone());
            r.faults.on_hit(FaultPoint::ExportRow, move || {
                if rows.fetch_add(1, Ordering::SeqCst) == 2 {
                    cancel.store(true, Ordering::SeqCst);
                }
            });
        }
        let events = Events::default();
        let res = run_export(
            &r.store,
            &Answers::new(&[Confirm::Ok]),
            || Some(chosen(&r.out)),
            TimeRange::all(),
            &cancel,
            &events,
        );
        assert_eq!(res, Err(CommandError::Cancelled));
        assert_eq!(
            rows.load(Ordering::SeqCst),
            3,
            "ended at the row the cancel came before"
        );
        assert!(entries(&r.out).is_empty(), "{:?}", entries(&r.out));
        assert_eq!(count(&r.store, EventType::EXPORT)?, 0);
        let phases = events.phases();
        assert_eq!(phases.first().map(String::as_str), Some("started"));
        assert_eq!(phases.last().map(String::as_str), Some("cancelled"));
        assert!(events.all().iter().all(|(n, _)| n != "audit_changed"));

        let empty = TimeRange {
            from_utc: UtcInstant(0),
            to_utc: UtcInstant(1),
        };
        let events = Events::default();
        let res = run_export(
            &r.store,
            &Answers::new(&[Confirm::Ok]),
            || Some(chosen(&r.out)),
            empty,
            &AtomicBool::new(false),
            &events,
        );
        assert_eq!(res, Err(CommandError::Export(ExportFailure::EmptyRange)));
        assert!(entries(&r.out).is_empty());
        assert_eq!(events.phases(), ["started", "failed"]);
        Ok(())
    }

    /// T12 review M-5: the failures the user can act on keep their kind (a taken directory name
    /// is `exists`, not `failed`); a leftover keeps its directory's name and drops its cause (OS
    /// text); everything else is `failed`.
    #[test]
    fn export_failures_keep_the_cases_the_user_can_act_on() {
        assert_eq!(
            export_failure(AuditError::Invalid(EXPORT_DIR_EXISTS)),
            ExportFailure::Exists
        );
        assert_eq!(
            export_failure(AuditError::Invalid(EXPORT_NO_RECORDS)),
            ExportFailure::EmptyRange
        );
        assert_eq!(
            export_failure(AuditError::ExportLeftover {
                dir_name: "d.partial".into(),
                cause: Box::new(AuditError::Io("C:\\Users\\x: denied".into())),
            }),
            ExportFailure::Leftover {
                dir_name: "d.partial".into()
            }
        );
        for other in [
            AuditError::Invalid("the export location is not a directory"),
            AuditError::Io("disk full".into()),
            AuditError::Closed,
        ] {
            assert_eq!(export_failure(other), ExportFailure::Failed);
        }
    }

    /// PD-180: the acknowledgement asks Rust's native confirmation first. Its text names the
    /// incident's seq, result and detected-at time as the `VERIFY` record holds them; `Cancel`
    /// appends no `INTEGRITY_ACK` and keeps the incident open. A seq that is no open incident gets
    /// no dialog.
    #[test]
    fn acknowledge_incident_needs_native_confirmation() -> TestResult {
        let r = rig(0)?;
        let seq = incident(&r.store)?;
        let record: Value = serde_json::from_slice(&r.store.read_payload(seq)?)?;
        let (result, detected_at) = (
            record["result"].as_str().ok_or("result")?,
            record["detected_at"].as_str().ok_or("detected_at")?,
        );
        assert_eq!(result, "chain_broken");

        let confirmer = Answers::new(&[Confirm::Cancel]);
        let events = Events::default();
        let res = acknowledge_dto(&r.store, &confirmer, seq, "looked at it", "alice", &events);
        assert_eq!(res, Err(CommandError::Cancelled));
        assert_eq!(
            confirmer.texts(),
            [format!(
                "Acknowledge integrity incident {seq} ({result}, detected {detected_at})? The \
                 red banner is cleared for this incident."
            )]
        );
        assert_eq!(count(&r.store, EventType::INTEGRITY_ACK)?, 0);
        assert_eq!(r.store.open_incidents(), [seq]);

        // Not an open incident: no dialog, nothing appended.
        let confirmer = Answers::new(&[Confirm::Ok]);
        for other in [seq + 1, 1] {
            assert_eq!(
                acknowledge_dto(&r.store, &confirmer, other, "", "alice", &events),
                Err(CommandError::NotFound)
            );
        }
        assert!(confirmer.texts().is_empty());
        assert_eq!(count(&r.store, EventType::INTEGRITY_ACK)?, 0);
        assert!(events.all().is_empty(), "{:?}", events.all());
        Ok(())
    }

    /// §8.7: after `Ok` the store appends `INTEGRITY_ACK {verify_seq, os_user, note}` with the OS
    /// user in its plaintext column, and the incident is closed; a second acknowledgement of it is
    /// `not_found`. The Audit window (`audit_changed`) and the headers (`status_banner`, no line
    /// named: the red `integrity_incident` line clears, T12 review I-2) read their status again.
    #[test]
    fn acknowledge_incident_records_os_user_and_note() -> TestResult {
        let r = rig(0)?;
        let seq = incident(&r.store)?;
        let events = Events::default();
        let acked = acknowledge_dto(
            &r.store,
            &Answers::new(&[Confirm::Ok]),
            seq,
            "restored from backup <b>",
            "alice",
            &events,
        )?;
        assert_eq!(
            events.all(),
            [
                ("audit_changed".to_owned(), Value::Null),
                ("status_banner".to_owned(), json!({"line_ids": []}))
            ]
        );
        assert_eq!(acked.verify_seq, seq);
        let payload: Value = serde_json::from_slice(&r.store.read_payload(acked.ack_seq)?)?;
        assert_eq!(
            payload,
            json!({"verify_seq": seq, "os_user": "alice", "note": "restored from backup <b>"})
        );
        let page = r.store.query(
            &AuditFilter {
                event_types: vec![EventType::INTEGRITY_ACK],
                ..AuditFilter::default()
            },
            AuditCursor::first(10),
        )?;
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].actor.os_user.as_deref(), Some("alice"));
        assert!(r.store.open_incidents().is_empty());
        assert_eq!(
            acknowledge_dto(
                &r.store,
                &Answers::new(&[Confirm::Ok]),
                seq,
                "",
                "alice",
                &events
            ),
            Err(CommandError::NotFound)
        );
        assert_eq!(events.all().len(), 2, "nothing more: {:?}", events.all());
        Ok(())
    }

    /// T12 review I-2: a `verify_now` that found an incident opened the headers' red line: they
    /// read `app_status` again (`status_banner`) and the Audit window its status (`audit_changed`).
    /// Any other answer, or an error, opened none: no event.
    #[test]
    fn verify_now_incident_announces_the_status_change() {
        let events = Events::default();
        for quiet in [
            Ok(VerifyNow::Verified),
            Ok(VerifyNow::DidNotComplete),
            Err(CommandError::NotReady),
        ] {
            verify_now_events(&events, &quiet);
        }
        assert!(events.all().is_empty(), "{:?}", events.all());
        verify_now_events(&events, &Ok(VerifyNow::Incident { count: 2 }));
        assert_eq!(
            events.all(),
            [
                ("audit_changed".to_owned(), Value::Null),
                ("status_banner".to_owned(), json!({"line_ids": []}))
            ]
        );
    }

    /// L134: `audit_status` counts the open incidents and lists them newest first with their
    /// result and detected-at time read from the records; an acknowledged one drops out. Health is
    /// the store's.
    #[test]
    fn audit_status_counts_incidents() -> TestResult {
        let r = rig(0)?;
        let empty = status_dto(&r.store)?;
        assert_eq!(empty.incident_count, 0);
        assert!(empty.open_incidents.is_empty());
        assert_eq!(empty.anchor_dir, None);
        let first = incident(&r.store)?;
        let second = incident(&r.store)?;
        let status = status_dto(&r.store)?;
        assert_eq!(status.incident_count, 2);
        assert_eq!(status.health.open_incidents, 2);
        let seqs: Vec<u64> = status.open_incidents.iter().map(|i| i.verify_seq).collect();
        assert_eq!(seqs, [second, first]);
        for i in &status.open_incidents {
            assert_eq!(i.result.as_deref(), Some("chain_broken"));
            let at = i.detected_at.as_deref().ok_or("detected_at")?;
            assert!(UtcInstant::parse_rfc3339_ms(at).is_some(), "{at}");
        }
        acknowledge_dto(
            &r.store,
            &Answers::new(&[Confirm::Ok]),
            first,
            "",
            "alice",
            &Events::default(),
        )?;
        let status = status_dto(&r.store)?;
        assert_eq!(status.incident_count, 1);
        assert_eq!(status.open_incidents[0].verify_seq, second);
        let wire = serde_json::to_value(&status)?;
        assert!(
            wire["health"]["anchor_dir_write_failing"].is_boolean(),
            "{wire}"
        );
        Ok(())
    }

    /// §8.10, L38: a query page carries plaintext columns only, display-escaped, newest first, with
    /// flags by name; a filter narrows on plaintext columns. The trail has the request's headers
    /// and deliveries. The payload view's tree is the sandboxed document of the decrypted payload,
    /// HTML in it is text.
    #[test]
    fn audit_query_trail_and_payload_answers() -> TestResult {
        let r = rig(3)?;
        let reads_before = r.store.testing_payload_reads();
        let filter: FilterArgs = serde_json::from_value(json!({
            "event_types": ["READ_FETCHED"], "agent_name": "agent <b>x</b>"
        }))?;
        let page = query_dto(
            &r.store,
            AuditQueryArgs {
                filter,
                cursor: Some(CursorArgs {
                    before_seq: None,
                    limit: 2,
                }),
            },
        )?;
        assert_eq!(page.rows.len(), 2);
        assert!(page.next.is_some());
        assert!(page.rows[0].seq > page.rows[1].seq, "newest first");
        let row = &page.rows[0];
        assert_eq!(row.event_type, "READ_FETCHED");
        assert_eq!(row.agent_name.as_deref(), Some("agent <b>x</b>"));
        assert_eq!(
            row.target.as_deref(),
            Some("PROJ-2⟨U+202E⟩"),
            "display-escaped"
        );
        assert!(row.flags.is_empty());
        assert_eq!(
            r.store.testing_payload_reads(),
            reads_before,
            "a query opens no payload"
        );
        let wire = serde_json::to_value(&page)?;
        assert!(
            !wire.to_string().contains("<script>"),
            "no payload in a page"
        );

        let trail = trail_dto(&r.store, "req_0123456789abcdefghij")?;
        assert_eq!(trail.headers.len(), 3);
        assert_eq!(trail.deliveries.count, 0);
        assert!(!trail.deliveries.to_other_peer);

        let p = payload_dto(&r.store, row.seq, 0, Platform::MacOsLinux)?;
        assert_eq!((p.page, p.page_count), (0, 1));
        assert!(p.srcdoc.starts_with("<!doctype html>"), "{}", p.srcdoc);
        assert!(
            p.srcdoc.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "{}",
            p.srcdoc
        );
        assert!(!p.srcdoc.contains("<script>"), "{}", p.srcdoc);
        assert!(
            p.display.contains("<script>alert(1)</script>"),
            "{}",
            p.display
        );
        assert_eq!(
            payload_dto(&r.store, row.seq, 1, Platform::MacOsLinux),
            Err(CommandError::InvalidArgument { field: "page" })
        );
        assert_eq!(
            payload_dto(&r.store, 999, 0, Platform::MacOsLinux),
            Err(CommandError::NotFound)
        );
        Ok(())
    }

    /// A payload larger than one page is paged as Raw text; a UTF-8 sequence cut by a page boundary
    /// is carried into the next page (derived from the previous page's bytes, never the UI's).
    #[test]
    fn audit_payload_pages_carry_a_cut_sequence() -> TestResult {
        let r = rig(0)?;
        // JCS of {"s": "<padding>é…"}: `{"s":"` is 6 bytes, so the padding puts the first `é`
        // (two bytes) across the 256 KiB boundary.
        let pad = atlas_duck_audit::PAYLOAD_PAGE_BYTES - 6 - 1;
        let text = format!("{}{}", "a".repeat(pad), "é".repeat(10));
        let c = r.store.append(NewEvent {
            event_type: EventType::READ_FETCHED,
            request_id: None,
            op_id: None,
            op_class: None,
            instance_id: None,
            target: None,
            actor: Default::default(),
            decision: None,
            flags: EventFlags::default(),
            payload: json!({ "s": text }),
        })?;
        let first = payload_dto(&r.store, c.seq, 0, Platform::MacOsLinux)?;
        let second = payload_dto(&r.store, c.seq, 1, Platform::MacOsLinux)?;
        assert_eq!(first.page_count, 2);
        assert!(
            !first.display.contains('⟨'),
            "the cut byte is carried, not escaped"
        );
        assert!(
            second.display.starts_with("éééééééééé\"}"),
            "{}",
            second.display
        );
        assert!(
            second.srcdoc.contains("<pre><code><bdi>éééééééééé"),
            "{}",
            second.srcdoc
        );
        Ok(())
    }

    /// L126: a `CREDENTIAL_CHANGED` record whose `change` is `store_failed` or `delete_failed`
    /// answers that word as `credential_change`, on every page; any other change, a `change` that
    /// is not that exact text, and every other record kind answer `null`.
    #[test]
    fn audit_payload_names_a_failed_credential_change() -> TestResult {
        let r = rig(0)?;
        let append = |event_type: EventType, change: Value| {
            r.store.append(NewEvent {
                event_type,
                request_id: None,
                op_id: None,
                op_class: None,
                instance_id: Some("inst-1".into()),
                target: None,
                actor: Default::default(),
                decision: None,
                flags: EventFlags::default(),
                payload: json!({
                    "change": change,
                    "old_user_key": null,
                    "new_user_key": "JIRAUSER10100",
                    "expires_at": null,
                }),
            })
        };
        let credential = EventType::CREDENTIAL_CHANGED;
        for (event_type, change, want) in [
            (
                credential,
                json!("store_failed"),
                Some(CredentialChangeFailure::StoreFailed),
            ),
            (
                credential,
                json!("delete_failed"),
                Some(CredentialChangeFailure::DeleteFailed),
            ),
            (credential, json!("added"), None),
            (credential, json!("deleted"), None),
            (credential, json!("Store_failed"), None),
            (credential, json!("store_failed "), None),
            (credential, json!(["store_failed"]), None),
            (credential, json!(null), None),
            (EventType::READ_FETCHED, json!("store_failed"), None),
            (EventType::CONFIG_CHANGED, json!("delete_failed"), None),
        ] {
            let c = append(event_type, change.clone())?;
            let reads = r.store.testing_payload_reads();
            let p = payload_dto(&r.store, c.seq, 0, Platform::MacOsLinux)?;
            assert_eq!(p.credential_change, want, "{event_type:?} {change}");
            // The view's own read, plus one more only for a `CREDENTIAL_CHANGED` record: the kind
            // comes from the header row, so no other record is decrypted a second time.
            let expected = if event_type == credential { 2 } else { 1 };
            assert_eq!(
                r.store.testing_payload_reads() - reads,
                expected,
                "{event_type:?} {change}"
            );
        }
        let c = append(credential, json!("delete_failed"))?;
        let wire = serde_json::to_value(payload_dto(&r.store, c.seq, 0, Platform::MacOsLinux)?)?;
        assert_eq!(wire["credential_change"], json!("delete_failed"));
        let c = append(EventType::READ_FETCHED, json!("x"))?;
        let wire = serde_json::to_value(payload_dto(&r.store, c.seq, 0, Platform::MacOsLinux)?)?;
        assert_eq!(wire["credential_change"], Value::Null);
        Ok(())
    }

    /// The field holds on every page of a payload longer than one (a record no real
    /// `CREDENTIAL_CHANGED` reaches, but the rule does not depend on the page).
    #[test]
    fn audit_payload_credential_change_on_every_page() -> TestResult {
        let r = rig(0)?;
        let c = r.store.append(NewEvent {
            event_type: EventType::CREDENTIAL_CHANGED,
            request_id: None,
            op_id: None,
            op_class: None,
            instance_id: Some("inst-1".into()),
            target: None,
            actor: Default::default(),
            decision: None,
            flags: EventFlags::default(),
            payload: json!({
                "change": "store_failed",
                "pad": "a".repeat(atlas_duck_audit::PAYLOAD_PAGE_BYTES),
            }),
        })?;
        for page in 0..2 {
            let p = payload_dto(&r.store, c.seq, page, Platform::MacOsLinux)?;
            assert_eq!(p.page_count, 2);
            assert_eq!(
                p.credential_change,
                Some(CredentialChangeFailure::StoreFailed)
            );
        }
        Ok(())
    }

    /// `backup_trigger`'s work: Rust's folder dialog, then `Store::backup` (it logs `BACKUP`);
    /// `audit_job` is indeterminate (`started`, then `done`). A cancelled dialog is `false` with no
    /// event.
    #[test]
    fn backup_trigger_rust_dialog_and_indeterminate_job() -> TestResult {
        let r = rig(1)?;
        let events = Events::default();
        let cancel = AtomicBool::new(false);
        assert!(!run_backup(&r.store, || Ok(None), &cancel, &events)?);
        assert!(events.all().is_empty());
        assert!(run_backup(
            &r.store,
            || Ok(Some(chosen(&r.out))),
            &cancel,
            &events
        )?);
        assert_eq!(events.phases(), ["started", "done"]);
        assert_eq!(
            events.all().last().map(|(n, _)| n.clone()).as_deref(),
            Some("audit_changed")
        );
        assert_eq!(count(&r.store, EventType::BACKUP)?, 1);
        assert_eq!(entries(&r.out).len(), 1, "one bundle directory");
        Ok(())
    }

    /// T12 review I-3: Quit sets the job's cancel flag while the backup's folder dialog is open;
    /// the folder the user then picks is not backed up: `cancelled`, no `BACKUP` (it would follow
    /// `APP_STOP` once the quit path stopped waiting), nothing written, no event.
    #[test]
    fn backup_trigger_cancelled_while_its_dialog_was_open_backs_up_nothing() -> TestResult {
        let r = rig(1)?;
        let events = Events::default();
        let cancel = AtomicBool::new(false);
        let res = run_backup(
            &r.store,
            || {
                cancel.store(true, Ordering::SeqCst);
                Ok(Some(chosen(&r.out)))
            },
            &cancel,
            &events,
        );
        assert_eq!(res, Err(CommandError::Cancelled));
        assert_eq!(count(&r.store, EventType::BACKUP)?, 0);
        assert!(entries(&r.out).is_empty(), "{:?}", entries(&r.out));
        assert!(events.all().is_empty(), "{:?}", events.all());
        Ok(())
    }

    /// The bodies parse into the store's own filter; the time texts are the `ts_utc` form.
    #[test]
    fn audit_args_parse_into_the_store_filter() -> TestResult {
        let args: AuditQueryArgs = serde_json::from_value(json!({
            "filter": {"from_utc": "2026-10-01T00:00:00.000Z", "flags_any": ["clock_behind", "clock_behind"],
                       "decision": "deny", "target": "PROJ-"},
            "cursor": {"before_seq": 40, "limit": 25}
        }))?;
        let f = args.filter.clone().into_filter();
        assert_eq!(
            f.from_utc,
            UtcInstant::parse_rfc3339_ms("2026-10-01T00:00:00.000Z")
        );
        assert_eq!(f.flags_any, [EventFlags::BEHIND], "deduplicated");
        assert_eq!(f.decision, Some(DecisionColumn::Deny));
        assert_eq!(f.target.as_deref(), Some("PROJ-"));
        assert_eq!(
            args.cursor.map(|c| (c.before_seq, c.limit)),
            Some((Some(40), 25))
        );
        let range = ExportTriggerArgs {
            from_utc: None,
            to_utc: None,
        }
        .range()?;
        assert_eq!(range, TimeRange::all());
        Ok(())
    }
}
