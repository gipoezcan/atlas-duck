//! Backup restore from the app (M10 T13; §8.11 steps 1–5, §8.7, §10.3; PD-168, PD-181; L40, L54;
//! M2 handoffs T16 M-3, M-4, M-10).
//!
//! Both entry points ask in one order (PD-168): the native "Restore backup" confirmation first (a
//! security-weakening setting, §10.3), then Rust's file dialog for the source (a backup bundle's
//! `manifest.json`, which stands for its folder, or an `archived/*.db` file), then the backup's
//! recovery passphrase through the credential window (purpose `restore_backup`; it enters only
//! through `submit_secret` and reaches the store through an in-memory channel, never a command
//! response), then the store call. A same-machine rollback (§8.11 step 4) asks its own native
//! confirmation naming `records_lost`, and asks again with the new count when the live head moved
//! while the dialog was up (M2 T16 M-3). The store records both answers after the restore
//! (`CONFIG_CHANGED {key: restore_backup}`). Closing the credential window before a submit ends
//! the flow: no store call, no event.
//!
//! - Settings "Restore backup…" ([`run_live_restore`]): `Store::restore` on the serving store, as
//!   the serving state's audit job (PD-181: `audit_job {job: restore}` is indeterminate, `started`
//!   right before the store call (appends wait from there on, M2 T16 M-10), then `done`, `failed`
//!   or `cancelled`; `restore_cancel` ends the flow while no store call runs (before it, and in
//!   the rollback dialog after a first call that changed nothing); Quit cancels it then too, else
//!   waits for the running call within `STORE_WAIT`). The caller then runs
//!   `Core::after_restore` (the config file reconciled again, `needs_token` per deleted PAT).
//! - The locked window's "Restore a backup instead" (`keychain_lost`, [`restore_without_store`]):
//!   `restore_from_source` with the locked store moved aside; `serve::restore_from_backup` then
//!   starts the core with the report's `pats_deleted` (logged at `APP_START`, PD-28).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::types::RustChosenPath;
use atlas_duck_audit::{
    AuditError, Confirmed, OpenConfig, OpenError, RestoreError, RestoreReport, Store,
    live_store_blocks_restore, restore_from_source,
};
use atlas_duck_core::{Confirm, NativeConfirmer};
use atlas_duck_ipc::paths::LocalDataDir;
use secrecy::SecretString;
use tauri::{AppHandle, Runtime};

use crate::commands::{CommandError, RestoreFailure};
use crate::serve::{AuditJobKind, StoreCall, UnlockFailure};
use crate::ui_sink::{EventOut, emit_audit_changed, emit_audit_job};

/// plan text (PD-168, §8.11, §10.3): the native "Restore backup" confirmation, before any dialog
/// or store call. True for both entry points and for a data dir without a log (T13 review I-2):
/// the current log is moved aside only if there is one, its open incidents stay with it, and this
/// computer's tokens are deleted.
pub const RESTORE_CONFIRM_TEXT: &str = "Restore a backup? The current audit log, if there is \
     one, is moved to the archived folder of the data directory (never deleted), and the backup's \
     log continues as a new segment. Open integrity incidents of the current log stay with its \
     archived copy. You need the backup's recovery passphrase, which becomes this log's recovery \
     passphrase. This computer's stored tokens are deleted and none are restored: every instance \
     needs its token again. Requests wait while the restore runs.";

/// plan text (§8.11 step 4): the native confirmation of a same-machine rollback, with the number
/// of records it gives up. The store counts from the current log file and from this install's
/// keychain head anchor, whichever reaches further (T13 review I-2): records beyond what the file
/// holds (no file, or one cut short) are in no archived copy, so the text promises none for them.
pub fn rollback_text(records_lost: u64) -> String {
    format!(
        "This backup is older than this computer's audit log: restoring it gives up the last \
         {records_lost} records of the log. The count is taken from the current log file and from \
         the newest record this computer's keychain remembers for the log. Records still in the \
         current log file stay in its archived copy; records that file does not hold (because it \
         is missing or was cut short) are kept nowhere. Restore it anyway?"
    )
}

/// The diagnostic event of a completed restore whose confirmation record could not be appended
/// (T13 review I-3; `RestoreReport::confirmation_seq` is `None`): the §10.3 evidence is missing
/// from the log, so the diagnostic log says so (its class only, never a path or text).
pub const LOG_EVENT_CONFIRMATION_UNRECORDED: &str = "restore_confirmation_unrecorded";

/// The diagnostic event of a source dialog whose answer is not a filesystem path (a portal's
/// document URI): the flow ends as if cancelled (T13 review M-9).
pub const LOG_EVENT_SOURCE_NOT_A_PATH: &str = "restore_source_not_a_path";

/// Logs a completed restore whose confirmation record is missing (T13 review I-3, L192).
fn note_confirmation(report: &RestoreReport) {
    if report.confirmation_seq.is_none() {
        tracing::warn!(
            event = LOG_EVENT_CONFIRMATION_UNRECORDED,
            error_class = "restore"
        );
    }
}

/// The file a backup bundle is chosen by (`backup.rs` `MANIFEST_FILE`): it stands for its folder.
pub const BUNDLE_MANIFEST: &str = "manifest.json";

const SOURCE_DIALOG_TITLE: &str =
    "Choose the atlas-duck backup to restore (its manifest.json, or an archived .db file)";
const SOURCE_FILTER: &str = "atlas-duck backup";
const SOURCE_EXTENSIONS: &[&str] = &["json", "db"];

/// How often a flow that waits for the passphrase looks at its cancel flag.
const PASSPHRASE_POLL: Duration = Duration::from_millis(100);

/// The path a restore reads: a bundle's `manifest.json` stands for its folder; any other file (an
/// archived `.db`) is itself. The store checks what it finds there (`NotABundle` otherwise).
pub fn source_of(picked: PathBuf) -> PathBuf {
    let is_manifest = picked
        .file_name()
        .is_some_and(|n| n.eq_ignore_ascii_case(BUNDLE_MANIFEST));
    match picked.parent() {
        Some(dir) if is_manifest && dir != Path::new("") => dir.to_path_buf(),
        _ => picked,
    }
}

/// Rust's file dialog for the restore source (§10.3: no path from a webview); `None` when
/// cancelled. Blocks until the user answers: a blocking thread only.
pub fn pick_restore_source<R: Runtime>(app: &AppHandle<R>) -> Option<RustChosenPath> {
    use tauri_plugin_dialog::DialogExt;
    let chosen = app
        .dialog()
        .file()
        .set_title(SOURCE_DIALOG_TITLE)
        .add_filter(SOURCE_FILTER, SOURCE_EXTENSIONS)
        .blocking_pick_file()?;
    let path = match chosen.into_path() {
        Ok(p) => p,
        Err(_) => {
            // A portal's answer that names no filesystem path (T13 review M-9): no restore can
            // read it, and it is not the user's cancel.
            tracing::warn!(event = LOG_EVENT_SOURCE_NOT_A_PATH, error_class = "restore");
            return None;
        }
    };
    let source = source_of(path);
    Some(RustChosenPath::from_native_dialog(source))
}

/// Why a question before the store call gave no answer (nothing was changed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAsked {
    /// A dialog was cancelled, the credential window went without a submit, or the flow's stop
    /// test answered true (restore cancel, Quit).
    Cancelled,
    /// The credential window is open for something else (a PAT, the recovery note): it keeps
    /// that purpose and the passphrase cannot be asked now.
    Busy,
    /// The credential window could not be opened.
    NoWindow,
}

/// Waits for the one passphrase entry of a `restore_backup` window, looking at `stop` between
/// bounded waits: `Cancelled` when the window went without a submit (the sender dropped) or
/// `stop` answered true (restore cancel, Quit). Never blocks unbounded.
pub fn wait_passphrase(
    rx: &Receiver<SecretString>,
    stop: &dyn Fn() -> bool,
) -> Result<SecretString, NotAsked> {
    loop {
        if stop() {
            return Err(NotAsked::Cancelled);
        }
        match rx.recv_timeout(PASSPHRASE_POLL) {
            Ok(secret) => return Ok(secret),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(NotAsked::Cancelled),
        }
    }
}

/// The window's kind of a refused or failed restore (no path, no text).
pub fn restore_failure(e: &AuditError) -> RestoreFailure {
    match e {
        AuditError::Restore(RestoreError::WrongPassphrase) => RestoreFailure::WrongPassphrase,
        AuditError::Restore(RestoreError::NotABundle | RestoreError::ManifestMismatch) => {
            RestoreFailure::NotABackup
        }
        AuditError::Restore(RestoreError::SnapshotNewer { .. }) => RestoreFailure::Newer,
        AuditError::Restore(RestoreError::ChainBroken(_)) => RestoreFailure::Broken,
        AuditError::Restore(RestoreError::AnchorDirMismatch(_)) => {
            RestoreFailure::AnchorDirMismatch
        }
        AuditError::Restore(RestoreError::CommittedIncomplete { .. }) => {
            RestoreFailure::CommittedIncomplete
        }
        AuditError::KeyStore(_) => RestoreFailure::Keychain,
        _ => RestoreFailure::Failed,
    }
}

/// What the three questions before the store call gave.
pub(crate) struct Asked {
    source: RustChosenPath,
    passphrase: SecretString,
    confirmed: Confirmed,
}

/// The native "Restore backup" confirmation, then the source dialog, then the passphrase (in this
/// order, PD-168). An error as soon as one is cancelled or cannot be asked, or `stop` answers
/// true between them; nothing was changed then.
pub(crate) fn ask_restore(
    confirmer: &dyn NativeConfirmer,
    pick: impl FnOnce() -> Option<RustChosenPath>,
    passphrase: impl FnOnce(&dyn Fn() -> bool) -> Result<SecretString, NotAsked>,
    stop: &dyn Fn() -> bool,
) -> Result<Asked, NotAsked> {
    if confirmer.confirm(RESTORE_CONFIRM_TEXT) != Confirm::Ok {
        return Err(NotAsked::Cancelled);
    }
    let confirmed = crate::serve::confirmed_by(RESTORE_CONFIRM_TEXT);
    if stop() {
        return Err(NotAsked::Cancelled);
    }
    let source = pick().ok_or(NotAsked::Cancelled)?;
    if stop() {
        return Err(NotAsked::Cancelled);
    }
    let passphrase = passphrase(stop)?;
    Ok(Asked {
        source,
        passphrase,
        confirmed,
    })
}

/// The rollback confirmation (§8.11 step 4) for `records_lost`, asked again with the new count
/// while `head` (the live head's seq) moved during the dialog (M2 T16 M-3): records appended
/// meanwhile are lost too. `None` when cancelled, or when `stop` answers true before a dialog or
/// after its answer: a `restore_cancel` or Quit while the dialog was up wins over its Ok (T13
/// review I-1).
fn ask_rollback(
    confirmer: &dyn NativeConfirmer,
    records_lost: u64,
    head: &dyn Fn() -> u64,
    stop: &dyn Fn() -> bool,
) -> Option<Confirmed> {
    let mut count = records_lost;
    loop {
        if stop() {
            return None;
        }
        let before = head();
        let text = rollback_text(count);
        if confirmer.confirm(&text) != Confirm::Ok {
            return None;
        }
        if stop() {
            return None;
        }
        let after = head();
        if after == before {
            return Some(crate::serve::confirmed_by(&text));
        }
        count = count.saturating_add(after.saturating_sub(before));
    }
}

/// Settings "Restore backup…" on the job's thread (PD-168, PD-181): the questions, then
/// `Store::restore` (with the rollback confirmation when the store asks for it), `audit_job
/// {job: restore}` `started` right before the store call and `done`/`failed`/`cancelled` after it,
/// `audit_changed` after a restore. `call` decides between `restore_cancel` and each store call;
/// `cancel` is the job's quit flag. Every refusal before the store call is `cancelled` (`busy`
/// when the credential window is open for something else) with no event and nothing changed. A
/// first store call that asks for the rollback confirmation changed nothing either: while that
/// dialog is up, `restore_cancel` and Quit end the flow again (`cancelled`, T13 review I-1).
pub fn run_live_restore(
    store: &Store,
    confirmer: &dyn NativeConfirmer,
    pick: impl FnOnce() -> Option<RustChosenPath>,
    passphrase: impl FnOnce(&dyn Fn() -> bool) -> Result<SecretString, NotAsked>,
    call: &StoreCall,
    cancel: &AtomicBool,
    out: &dyn EventOut,
) -> Result<RestoreReport, CommandError> {
    let job = AuditJobKind::Restore;
    let stop = || cancel.load(Ordering::SeqCst) || call.cancelled();
    let asked = ask_restore(confirmer, pick, passphrase, &stop).map_err(|n| match n {
        NotAsked::Cancelled => CommandError::Cancelled,
        NotAsked::Busy => CommandError::Busy,
        NotAsked::NoWindow => CommandError::Internal,
    })?;
    if cancel.load(Ordering::SeqCst) || !call.begin() {
        return Err(CommandError::Cancelled);
    }
    emit_audit_job(out, job, "started", None);
    let mut rollback = None;
    let r = loop {
        match store.restore(
            asked.source.clone(),
            &asked.passphrase,
            asked.confirmed,
            rollback,
        ) {
            Err(AuditError::Restore(RestoreError::RollbackNeedsConfirmation { records_lost }))
                if rollback.is_none() =>
            {
                // Nothing changed: until the next store call a cancel or Quit ends the flow.
                call.reopen();
                match ask_rollback(confirmer, records_lost, &|| store.head().0, &stop) {
                    Some(c) if !cancel.load(Ordering::SeqCst) && call.begin() => rollback = Some(c),
                    _ => {
                        emit_audit_job(out, job, "cancelled", None);
                        return Err(CommandError::Cancelled);
                    }
                }
            }
            other => break other,
        }
    };
    match r {
        Ok(report) => {
            note_confirmation(&report);
            emit_audit_job(out, job, "done", None);
            emit_audit_changed(out);
            Ok(report)
        }
        Err(e) => {
            emit_audit_job(out, job, "failed", None);
            Err(CommandError::Restore(restore_failure(&e)))
        }
    }
}

/// The locked window's "Restore a backup instead" on a blocking thread (PD-168, M2 T16 M-4): a
/// locked store whose records cannot be read is `archive_first` before any dialog; then the
/// questions and `restore_from_source` (a fresh `config()` per attempt), with the rollback
/// confirmation when it asks (no store runs, so its count cannot move). `stop` (Quit) ends the
/// wait for the passphrase, and the flow after the rollback dialog (T13 review I-1): its later Ok
/// calls `restore_from_source` no more. Returns the running store and the report.
pub fn restore_without_store(
    data: &LocalDataDir,
    lock: &InstanceLock,
    config: &dyn Fn() -> OpenConfig,
    confirmer: &dyn NativeConfirmer,
    pick: impl FnOnce() -> Option<RustChosenPath>,
    passphrase: impl FnOnce(&dyn Fn() -> bool) -> Result<SecretString, NotAsked>,
    stop: &dyn Fn() -> bool,
) -> Result<(Store, RestoreReport), UnlockFailure> {
    if live_store_blocks_restore(data) {
        return Err(UnlockFailure::ArchiveFirst);
    }
    let asked = ask_restore(confirmer, pick, passphrase, stop).map_err(not_asked_failure)?;
    restore_asked(data, lock, config, confirmer, &asked, stop)
}

/// The [`UnlockFailure`] of a question [`ask_restore`] got no answer to (nothing was changed).
pub(crate) fn not_asked_failure(n: NotAsked) -> UnlockFailure {
    match n {
        NotAsked::Cancelled => UnlockFailure::Cancelled,
        NotAsked::Busy => UnlockFailure::Busy,
        NotAsked::NoWindow => UnlockFailure::Io,
    }
}

/// The store half of [`restore_without_store`], once the questions were answered (the wizard's
/// restore takes its ids in between, M10 T15 fix-q): `restore_from_source` with a fresh `config()`
/// per attempt, and the rollback confirmation when it asks.
pub(crate) fn restore_asked(
    data: &LocalDataDir,
    lock: &InstanceLock,
    config: &dyn Fn() -> OpenConfig,
    confirmer: &dyn NativeConfirmer,
    asked: &Asked,
    stop: &dyn Fn() -> bool,
) -> Result<(Store, RestoreReport), UnlockFailure> {
    let mut rollback = None;
    loop {
        match restore_from_source(
            data,
            lock,
            config(),
            asked.source.clone(),
            &asked.passphrase,
            asked.confirmed,
            rollback,
        ) {
            Err(OpenError::Restore(RestoreError::RollbackNeedsConfirmation { records_lost }))
                if rollback.is_none() =>
            {
                match ask_rollback(confirmer, records_lost, &|| 0, stop) {
                    Some(c) => rollback = Some(c),
                    None => return Err(UnlockFailure::Cancelled),
                }
            }
            Ok((store, report)) => {
                note_confirmation(&report);
                return Ok((store, report));
            }
            Err(e) => return Err(UnlockFailure::of(&e)),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;
    use std::sync::mpsc::sync_channel;

    use atlas_duck_audit::{
        AuditCursor, AuditFilter, EventFlags, EventType, MAX_AUDIT_PAGE_ROWS, NewEvent,
    };
    use atlas_duck_core::payloads::sha256_hex;
    use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};
    use serde_json::{Value, json};

    use super::*;
    use crate::commands::audit::tests::{
        Answers, Events, PASS, Rig, TestResult, chosen, config, count, rig,
    };

    fn pass() -> SecretString {
        SecretString::from(PASS.to_owned())
    }

    /// A bundle of `r`'s store. Its `BACKUP` record follows the snapshot, so restoring the bundle
    /// into the same store gives up at least that record (a same-machine rollback, §8.11 step 4).
    fn bundle(r: &Rig) -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(r.store.backup(chosen(&r.out))?.bundle_dir)
    }

    /// One more record on `store` (the head moves).
    fn one_more(store: &Store) -> Result<(), AuditError> {
        store
            .append(NewEvent {
                event_type: EventType::READ_FETCHED,
                request_id: None,
                op_id: None,
                op_class: None,
                instance_id: None,
                target: None,
                actor: atlas_duck_audit::Actor::default(),
                decision: None,
                flags: EventFlags::default(),
                payload: json!({"more": true}),
            })
            .map(drop)
    }

    /// The payload of the newest record of type `t`.
    fn newest(store: &Store, t: EventType) -> Result<Value, Box<dyn std::error::Error>> {
        let page = store.query(
            &AuditFilter {
                event_types: vec![t],
                ..AuditFilter::default()
            },
            AuditCursor::first(MAX_AUDIT_PAGE_ROWS),
        )?;
        let seq = page.rows.first().ok_or("no such record")?.seq;
        Ok(serde_json::from_slice(&store.read_payload(seq)?)?)
    }

    /// The questions a flow asked besides the native dialogs, in order.
    #[derive(Default)]
    struct Asked(Mutex<Vec<&'static str>>);

    impl Asked {
        fn push(&self, what: &'static str) {
            if let Ok(mut v) = self.0.lock() {
                v.push(what);
            }
        }

        fn all(&self) -> Vec<&'static str> {
            self.0.lock().map(|v| v.clone()).unwrap_or_default()
        }
    }

    /// A fresh local data dir with its instance lock and no store.
    fn empty_data_dir()
    -> Result<(tempfile::TempDir, LocalDataDir, InstanceLock), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("data");
        std::fs::create_dir(&dir)?;
        let DataDirResolution::Local(data) = check_data_dir(&dir)? else {
            return Err("the temp dir is not a local data dir".into());
        };
        let lock = InstanceLock::acquire(&data, "thishost")?;
        Ok((tmp, data, lock))
    }

    /// PD-168, L54 (§10.3 "restore backup" is security-weakening): the native "Restore backup"
    /// confirmation comes first. A `Cancel` opens no file dialog, asks no passphrase, sends no
    /// event and calls no store, from both entry points.
    #[test]
    fn restore_needs_native_confirmation_first() -> TestResult {
        let r = rig(2)?;
        let source = bundle(&r)?;
        let head = r.store.head();
        let confirmer = Answers::new(&[Confirm::Cancel]);
        let asked = Asked::default();
        let events = Events::default();
        let (call, cancel) = (StoreCall::default(), AtomicBool::new(false));
        let got = run_live_restore(
            &r.store,
            &confirmer,
            || {
                asked.push("pick");
                Some(chosen(&source))
            },
            |_| {
                asked.push("passphrase");
                Ok(pass())
            },
            &call,
            &cancel,
            &events,
        );
        assert_eq!(got, Err(CommandError::Cancelled));
        assert_eq!(confirmer.texts(), [RESTORE_CONFIRM_TEXT]);
        assert_eq!(asked.all(), Vec::<&str>::new());
        assert_eq!(events.all(), Vec::new());
        assert!(!call.started());
        assert_eq!(r.store.head(), head);
        assert_eq!(count(&r.store, EventType::RESTORE)?, 0);

        // The locked window's entry: the same order.
        let (_tmp, data, lock) = empty_data_dir()?;
        let confirmer = Answers::new(&[Confirm::Cancel]);
        let got = restore_without_store(
            &data,
            &lock,
            &|| config(&r.ring, &r.install_id, &r.faults),
            &confirmer,
            || {
                asked.push("pick");
                Some(chosen(&source))
            },
            |_| {
                asked.push("passphrase");
                Ok(pass())
            },
            &|| false,
        );
        assert!(matches!(got, Err(UnlockFailure::Cancelled)));
        assert_eq!(confirmer.texts(), [RESTORE_CONFIRM_TEXT]);
        assert_eq!(asked.all(), Vec::<&str>::new());
        assert!(!data.path().join(atlas_duck_audit::DB_FILE).exists());
        Ok(())
    }

    /// A native confirmer that answers Ok and moves the live head once, while the first rollback
    /// dialog is up (records appended while the user reads it).
    struct MovingHead {
        store: Store,
        texts: Mutex<Vec<String>>,
        moved: AtomicBool,
    }

    impl NativeConfirmer for MovingHead {
        fn confirm(&self, text: &str) -> Confirm {
            if let Ok(mut t) = self.texts.lock() {
                t.push(text.to_owned());
            }
            if text != RESTORE_CONFIRM_TEXT && !self.moved.swap(true, Ordering::SeqCst) {
                let _ = one_more(&self.store);
            }
            Confirm::Ok
        }
    }

    /// M2 T16 M-3 (§8.11 step 4): the rollback confirmation names `records_lost`, and when the
    /// live head moved while its dialog was up it is asked again with the new count; the store
    /// call carries the last answer, whose text hash the confirmation record keeps (PD-168).
    #[test]
    fn restore_rollback_reasked_when_head_moved() -> TestResult {
        let r = rig(2)?;
        let source = bundle(&r)?;
        let confirmer = MovingHead {
            store: r.store.clone(),
            texts: Mutex::new(Vec::new()),
            moved: AtomicBool::new(false),
        };
        let (call, cancel) = (StoreCall::default(), AtomicBool::new(false));
        let report = run_live_restore(
            &r.store,
            &confirmer,
            || Some(chosen(&source)),
            |_| Ok(pass()),
            &call,
            &cancel,
            &Events::default(),
        )?;
        let texts = confirmer
            .texts
            .lock()
            .map(|t| t.clone())
            .unwrap_or_default();
        let lost = report.records_lost;
        assert_eq!(
            texts,
            [
                RESTORE_CONFIRM_TEXT.to_owned(),
                rollback_text(lost - 1),
                rollback_text(lost),
            ]
        );
        assert_eq!(newest(&r.store, EventType::RESTORE)?["records_lost"], lost);
        assert_eq!(
            newest(&r.store, EventType::CONFIG_CHANGED)?["rollback_dialog_text_sha256"],
            sha256_hex(rollback_text(lost).as_bytes())
        );
        Ok(())
    }

    /// A native confirmer that answers Ok to every dialog and runs `during` while each rollback
    /// dialog is up (a `restore_cancel` or a Quit while the user reads it).
    struct DuringRollback<'a> {
        during: &'a (dyn Fn() + Sync),
        texts: Mutex<Vec<String>>,
    }

    impl<'a> DuringRollback<'a> {
        fn new(during: &'a (dyn Fn() + Sync)) -> DuringRollback<'a> {
            DuringRollback {
                during,
                texts: Mutex::new(Vec::new()),
            }
        }

        fn texts(&self) -> Vec<String> {
            self.texts.lock().map(|t| t.clone()).unwrap_or_default()
        }
    }

    impl NativeConfirmer for DuringRollback<'_> {
        fn confirm(&self, text: &str) -> Confirm {
            if let Ok(mut t) = self.texts.lock() {
                t.push(text.to_owned());
            }
            if text != RESTORE_CONFIRM_TEXT {
                (self.during)();
            }
            Confirm::Ok
        }
    }

    /// T13 review I-1 (PD-181): a same-machine rollback's first store call changes nothing and
    /// asks for the rollback confirmation. A `restore_cancel` while that dialog is up is answered
    /// `cancelled` and ends the flow, and so does a Quit (the call cancelled, then the job's
    /// flag, as `stop_audit_job` does): the dialog's later Ok calls the store no more.
    #[test]
    fn cancel_or_quit_in_the_rollback_dialog_calls_nothing() -> TestResult {
        for quit in [false, true] {
            let r = rig(2)?;
            let source = bundle(&r)?;
            let head = r.store.head();
            let (call, cancel) = (StoreCall::default(), AtomicBool::new(false));
            let answered = AtomicBool::new(false);
            let during = || {
                answered.store(call.cancel(), Ordering::SeqCst);
                if quit {
                    cancel.store(true, Ordering::SeqCst);
                }
            };
            let confirmer = DuringRollback::new(&during);
            let events = Events::default();
            let got = run_live_restore(
                &r.store,
                &confirmer,
                || Some(chosen(&source)),
                |_| Ok(pass()),
                &call,
                &cancel,
                &events,
            );
            assert_eq!(got, Err(CommandError::Cancelled), "quit: {quit}");
            if !quit {
                assert!(answered.load(Ordering::SeqCst), "restore_cancel: cancelled");
            }
            assert_eq!(confirmer.texts().len(), 2, "quit: {quit}");
            assert_eq!(events.phases(), ["started", "cancelled"], "quit: {quit}");
            assert_eq!(r.store.head(), head, "quit: {quit}");
            assert_eq!(count(&r.store, EventType::RESTORE)?, 0, "quit: {quit}");
        }
        Ok(())
    }

    /// T13 review I-1 (no store): a Quit (the freeze, the flow's stop test) while the rollback
    /// dialog of the locked store's own backup is up ends the flow: `restore_from_source` is not
    /// called again, the locked store stays in place and nothing is recorded.
    #[test]
    fn quit_in_the_rollback_dialog_without_a_store_calls_nothing() -> TestResult {
        let l = rig(2)?;
        let source = bundle(&l)?;
        one_more(&l.store)?;
        l.store.shutdown();
        l.ring.wipe_install(&l.install_id);
        let before = atlas_duck_audit::testing::event_types(&l.data)?;
        let frozen = AtomicBool::new(false);
        let during = || frozen.store(true, Ordering::SeqCst);
        let confirmer = DuringRollback::new(&during);
        let got = restore_without_store(
            &l.data,
            &l.lock,
            &|| config(&l.ring, &l.install_id, &l.faults),
            &confirmer,
            || Some(chosen(&source)),
            |_| Ok(pass()),
            &|| frozen.load(Ordering::SeqCst),
        );
        assert!(
            matches!(got, Err(UnlockFailure::Cancelled)),
            "{:?}",
            got.as_ref().map(|_| ()).map_err(|f| f.class())
        );
        assert_eq!(confirmer.texts().len(), 2);
        assert_eq!(atlas_duck_audit::testing::event_types(&l.data)?, before);
        Ok(())
    }

    /// The diagnostic lines `f` writes on this thread, through the allowlist (§7.7).
    pub(crate) fn diag_lines<T>(f: impl FnOnce() -> T) -> (T, String) {
        use tracing_subscriber::Registry;
        use tracing_subscriber::layer::SubscriberExt;

        #[derive(Clone, Default)]
        struct Capture(std::sync::Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if let Ok(mut v) = self.0.lock() {
                    v.extend_from_slice(buf);
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
            type Writer = Capture;
            fn make_writer(&'a self) -> Capture {
                self.clone()
            }
        }

        let cap = Capture::default();
        let subscriber =
            Registry::default().with(crate::diag::fields::allowlist_layer(cap.clone()));
        let out = tracing::subscriber::with_default(subscriber, f);
        let text = cap
            .0
            .lock()
            .map(|v| String::from_utf8_lossy(&v).into_owned())
            .unwrap_or_default();
        (out, text)
    }

    /// T13 review I-3 (PD-168, L192): a confirmation record whose append failed is a warn line
    /// in the diagnostic log (its event and class only), from both entry points; the restore is
    /// complete and answered as such. A recorded one writes no such line.
    #[test]
    fn unrecorded_confirmation_is_logged() -> TestResult {
        use atlas_duck_audit::testing::FaultPoint;

        let r = rig(2)?;
        let source = bundle(&r)?;
        r.faults.fail(FaultPoint::RestoreConfirmationAppend, 1);
        let (got, log) = diag_lines(|| {
            run_live_restore(
                &r.store,
                &Answers::new(&[Confirm::Ok, Confirm::Ok]),
                || Some(chosen(&source)),
                |_| Ok(pass()),
                &StoreCall::default(),
                &AtomicBool::new(false),
                &Events::default(),
            )
        });
        let report = got?;
        assert_eq!(report.confirmation_seq, None);
        assert_eq!(count(&r.store, EventType::RESTORE)?, 1);
        assert!(
            log.contains(&format!(
                "event={LOG_EVENT_CONFIRMATION_UNRECORDED} error_class=restore dropped_fields=0"
            )),
            "{log}"
        );

        // The locked window's entry.
        let a = rig(2)?;
        let source = bundle(&a)?;
        let l = rig(3)?;
        l.store.shutdown();
        l.ring.wipe_install(&l.install_id);
        l.faults.fail(FaultPoint::RestoreConfirmationAppend, 1);
        let (got, log) = diag_lines(|| {
            restore_without_store(
                &l.data,
                &l.lock,
                &|| config(&l.ring, &l.install_id, &l.faults),
                &Answers::new(&[Confirm::Ok]),
                || Some(chosen(&source)),
                |_| Ok(pass()),
                &|| false,
            )
        });
        let (store, report) = got.map_err(|f| f.class())?;
        store.shutdown();
        assert_eq!(report.confirmation_seq, None);
        assert!(
            log.contains(&format!("event={LOG_EVENT_CONFIRMATION_UNRECORDED}")),
            "{log}"
        );

        // Recorded: no line.
        let r = rig(2)?;
        let source = bundle(&r)?;
        let (got, log) = diag_lines(|| {
            run_live_restore(
                &r.store,
                &Answers::new(&[Confirm::Ok, Confirm::Ok]),
                || Some(chosen(&source)),
                |_| Ok(pass()),
                &StoreCall::default(),
                &AtomicBool::new(false),
                &Events::default(),
            )
        });
        got?.confirmation_seq.ok_or("no confirmation record")?;
        assert!(!log.contains(LOG_EVENT_CONFIRMATION_UNRECORDED), "{log}");
        Ok(())
    }

    /// T13 review M-1: a credential window that cannot be had for the passphrase (it opened for
    /// something else while the native dialogs were up) is `busy`, not a user cancel, and one
    /// that cannot be opened is a failure; nothing was called and no event was sent.
    #[test]
    fn passphrase_window_not_had_is_not_a_cancel() -> TestResult {
        let r = rig(2)?;
        let source = bundle(&r)?;
        let head = r.store.head();
        for (not_asked, want) in [
            (NotAsked::Busy, CommandError::Busy),
            (NotAsked::NoWindow, CommandError::Internal),
        ] {
            let events = Events::default();
            let call = StoreCall::default();
            let got = run_live_restore(
                &r.store,
                &Answers::new(&[Confirm::Ok]),
                || Some(chosen(&source)),
                |_| Err(not_asked),
                &call,
                &AtomicBool::new(false),
                &events,
            );
            assert_eq!(got, Err(want), "{not_asked:?}");
            assert_eq!(events.all(), Vec::new());
            assert!(!call.started());
        }
        assert_eq!(r.store.head(), head);

        // The locked window's entry.
        let (_tmp, data, lock) = empty_data_dir()?;
        for (not_asked, want) in [
            (NotAsked::Busy, UnlockFailure::Busy),
            (NotAsked::NoWindow, UnlockFailure::Io),
        ] {
            let got = restore_without_store(
                &data,
                &lock,
                &|| config(&r.ring, &r.install_id, &r.faults),
                &Answers::new(&[Confirm::Ok]),
                || Some(chosen(&source)),
                |_| Err(not_asked),
                &|| false,
            );
            assert_eq!(
                got.as_ref().map(|_| ()).map_err(|f| *f),
                Err(want),
                "{not_asked:?}"
            );
        }
        assert!(!data.path().join(atlas_duck_audit::DB_FILE).exists());
        Ok(())
    }

    /// T13 review M-2: the locked window's classes for a restore's refusals name the backup, not
    /// the locked log: a backup whose chain or schema fails its check is `broken`, one that does
    /// not match the anchor dir `anchor_dir_mismatch` (never `integrity`, which reads as the
    /// live log failing).
    #[test]
    fn unlock_failures_of_restore_errors() {
        let cases = [
            (RestoreError::WrongPassphrase, "wrong_passphrase"),
            (RestoreError::NotABundle, "not_a_backup"),
            (RestoreError::ManifestMismatch, "not_a_backup"),
            (
                RestoreError::SnapshotNewer { found: "x".into() },
                "store_newer",
            ),
            (RestoreError::ChainBroken("x".into()), "broken"),
            (
                RestoreError::AnchorDirMismatch("x".into()),
                "anchor_dir_mismatch",
            ),
            (
                RestoreError::RollbackNeedsConfirmation { records_lost: 3 },
                "invalid",
            ),
            (
                RestoreError::CommittedIncomplete {
                    restore_seq: 3,
                    reason: "x".into(),
                },
                "committed_incomplete",
            ),
        ];
        for (e, class) in cases {
            let what = e.to_string();
            assert_eq!(
                UnlockFailure::of(&OpenError::Restore(e)).class(),
                class,
                "{what}"
            );
        }
    }

    /// PD-181 (L116 restore progress): `audit_job {job: restore}` is indeterminate: `started` right
    /// before the store call, then `done` (with `audit_changed`) or `failed`; no counts.
    #[test]
    fn restore_job_events_started_then_done() -> TestResult {
        let r = rig(2)?;
        let source = bundle(&r)?;
        let events = Events::default();
        run_live_restore(
            &r.store,
            &Answers::new(&[Confirm::Ok, Confirm::Ok]),
            || Some(chosen(&source)),
            |_| Ok(pass()),
            &StoreCall::default(),
            &AtomicBool::new(false),
            &events,
        )?;
        assert_eq!(
            events.all(),
            [
                (
                    "audit_job".to_owned(),
                    json!({"job": "restore", "phase": "started"})
                ),
                (
                    "audit_job".to_owned(),
                    json!({"job": "restore", "phase": "done"})
                ),
                ("audit_changed".to_owned(), Value::Null),
            ]
        );

        // A refused passphrase: `started`, then `failed`; nothing changed.
        let r = rig(2)?;
        let source = bundle(&r)?;
        let head = r.store.head();
        let events = Events::default();
        let got = run_live_restore(
            &r.store,
            &Answers::new(&[Confirm::Ok]),
            || Some(chosen(&source)),
            |_| Ok(SecretString::from("not the passphrase".to_owned())),
            &StoreCall::default(),
            &AtomicBool::new(false),
            &events,
        );
        assert_eq!(
            got,
            Err(CommandError::Restore(RestoreFailure::WrongPassphrase))
        );
        assert_eq!(events.phases(), ["started", "failed"]);
        assert_eq!(r.store.head(), head);
        Ok(())
    }

    /// PD-168 (§10.3 "logged as `CONFIG_CHANGED`"): after the restore the store records the
    /// hashes of exactly the dialog texts the user answered: the "Restore backup" text and the
    /// rollback text with its count. The second store call (the confirmed rollback) began through
    /// the job's `StoreCall`, so a cancel meanwhile is refused (T13 review I-1).
    #[test]
    fn restore_confirmation_recorded_after_restore() -> TestResult {
        let r = rig(2)?;
        let source = bundle(&r)?;
        let confirmer = Answers::new(&[Confirm::Ok, Confirm::Ok]);
        let call = StoreCall::default();
        let report = run_live_restore(
            &r.store,
            &confirmer,
            || Some(chosen(&source)),
            |_| Ok(pass()),
            &call,
            &AtomicBool::new(false),
            &Events::default(),
        )?;
        assert!(call.started() && !call.cancel(), "the second call began");
        let texts = confirmer.texts();
        assert_eq!(
            texts,
            [
                RESTORE_CONFIRM_TEXT.to_owned(),
                rollback_text(report.records_lost)
            ]
        );
        let seq = report.confirmation_seq.ok_or("no confirmation record")?;
        assert_eq!(seq, report.restore_seq + 1);
        assert_eq!(
            serde_json::from_slice::<Value>(&r.store.read_payload(seq)?)?,
            json!({
                "source": "app",
                "key": "restore_backup",
                "dialog_text_sha256": sha256_hex(RESTORE_CONFIRM_TEXT.as_bytes()),
                "rollback_dialog_text_sha256": sha256_hex(texts[1].as_bytes()),
            })
        );
        Ok(())
    }

    /// PD-181: closing the `restore_backup` credential window without a submit (its sender drops)
    /// ends the flow: no store call, no event.
    #[test]
    fn restore_credential_window_closed_cancels() -> TestResult {
        let r = rig(2)?;
        let source = bundle(&r)?;
        let head = r.store.head();
        let (tx, rx) = sync_channel::<SecretString>(1);
        drop(tx);
        let events = Events::default();
        let call = StoreCall::default();
        let got = run_live_restore(
            &r.store,
            &Answers::new(&[Confirm::Ok]),
            || Some(chosen(&source)),
            |stop| wait_passphrase(&rx, stop),
            &call,
            &AtomicBool::new(false),
            &events,
        );
        assert_eq!(got, Err(CommandError::Cancelled));
        assert_eq!(events.all(), Vec::new());
        assert!(!call.started());
        assert_eq!(r.store.head(), head);
        Ok(())
    }

    /// PD-181 (`restore_cancel`): a cancel while the flow waits for the passphrase ends the wait
    /// and the flow (no store call, no event); a cancel once the store call began is refused, and
    /// the store call runs to its end.
    #[test]
    fn restore_cancel_before_the_store_call_ends_the_flow() -> TestResult {
        let r = rig(2)?;
        let source = bundle(&r)?;
        let head = r.store.head();
        let (_tx, rx) = sync_channel::<SecretString>(1);
        let events = Events::default();
        let call = StoreCall::default();
        let got = run_live_restore(
            &r.store,
            &Answers::new(&[Confirm::Ok]),
            || Some(chosen(&source)),
            |stop| {
                assert!(call.cancel(), "nothing started yet");
                wait_passphrase(&rx, stop)
            },
            &call,
            &AtomicBool::new(false),
            &events,
        );
        assert_eq!(got, Err(CommandError::Cancelled));
        assert_eq!(events.all(), Vec::new());
        assert!(call.cancelled() && !call.started());
        assert_eq!(r.store.head(), head);

        // A cancel that lands after the passphrase arrived and before the store call: still no
        // store call.
        let call = StoreCall::default();
        let got = run_live_restore(
            &r.store,
            &Answers::new(&[Confirm::Ok, Confirm::Ok]),
            || Some(chosen(&source)),
            |_| {
                assert!(call.cancel(), "nothing started yet");
                Ok(pass())
            },
            &call,
            &AtomicBool::new(false),
            &events,
        );
        assert_eq!(got, Err(CommandError::Cancelled));
        assert_eq!(events.all(), Vec::new());
        assert_eq!(r.store.head(), head);
        assert_eq!(count(&r.store, EventType::RESTORE)?, 0);

        // Once begun, a cancel is refused and the call is not marked cancelled.
        let call = StoreCall::default();
        assert!(call.begin());
        assert!(!call.cancel());
        assert!(call.started() && !call.cancelled());
        // Cancelled first: the call never begins.
        let call = StoreCall::default();
        assert!(call.cancel());
        assert!(!call.begin());
        Ok(())
    }

    /// The wait for the passphrase is bounded by its stop test (Quit, restore cancel) and by the
    /// window (a dropped sender), and returns the one entry the window handed over.
    #[test]
    fn wait_passphrase_returns_the_entry_or_stops() {
        let (tx, rx) = sync_channel::<SecretString>(1);
        assert!(tx.send(pass()).is_ok());
        assert!(wait_passphrase(&rx, &|| false).is_ok());
        assert!(
            matches!(wait_passphrase(&rx, &|| true), Err(NotAsked::Cancelled)),
            "stop"
        );
        drop(tx);
        assert!(
            matches!(wait_passphrase(&rx, &|| false), Err(NotAsked::Cancelled)),
            "the window went"
        );
    }

    /// PD-168 (`keychain_lost`): "Restore a backup instead" runs `restore_from_source`: the locked
    /// store (its KEK gone from the keychain) is moved aside as `replaced_db`, the restored store
    /// runs under this install's id with the backup's chain continued in a new segment, and the
    /// confirmation is recorded. A cross-machine backup asks no rollback.
    #[test]
    fn keychain_lost_restore_from_backup_uses_restore_from_source() -> TestResult {
        let a = rig(2)?;
        let source = bundle(&a)?;
        let a_chain = a.store.head().2;
        let l = rig(3)?;
        let l_chain = l.store.head().2;
        l.store.shutdown();
        // The keychain lost this install's entries (password reset, profile wipe).
        l.ring.wipe_install(&l.install_id);
        let confirmer = Answers::new(&[Confirm::Ok]);
        let (store, report) = restore_without_store(
            &l.data,
            &l.lock,
            &|| config(&l.ring, &l.install_id, &l.faults),
            &confirmer,
            || Some(chosen(&source)),
            |_| Ok(pass()),
            &|| false,
        )
        .map_err(|f| f.class())?;
        assert_eq!(confirmer.texts(), [RESTORE_CONFIRM_TEXT]);
        assert_eq!(report.source_chain_id, a_chain);
        assert_eq!(
            report.replaced_db.as_ref().map(|d| d.chain_id.clone()),
            Some(l_chain)
        );
        assert_eq!(store.install_id(), l.install_id);
        assert_eq!(store.head().2, report.new_chain_id);
        assert_eq!(
            newest(&store, EventType::CONFIG_CHANGED)?["dialog_text_sha256"],
            sha256_hex(RESTORE_CONFIRM_TEXT.as_bytes())
        );
        store.shutdown();
        Ok(())
    }

    /// M2 T16 M-4: a locked store whose records cannot be read blocks `restore_from_source` (it
    /// cannot be named and moved aside): the flow answers `archive_first` before any dialog, and
    /// the file stays as it was.
    #[test]
    fn unreadable_live_db_offers_archive_first() -> TestResult {
        let r = rig(0)?;
        let (_tmp, data, lock) = empty_data_dir()?;
        let db = data.path().join(atlas_duck_audit::DB_FILE);
        std::fs::write(&db, b"not an sqlite database at all")?;
        let confirmer = Answers::new(&[Confirm::Ok]);
        let asked = Asked::default();
        let got = restore_without_store(
            &data,
            &lock,
            &|| config(&r.ring, &r.install_id, &r.faults),
            &confirmer,
            || {
                asked.push("pick");
                None
            },
            |_| {
                asked.push("passphrase");
                Err(NotAsked::Cancelled)
            },
            &|| false,
        );
        assert!(matches!(got, Err(UnlockFailure::ArchiveFirst)));
        assert_eq!(confirmer.texts(), Vec::<String>::new());
        assert_eq!(asked.all(), Vec::<&str>::new());
        assert_eq!(std::fs::read(&db)?, b"not an sqlite database at all");
        Ok(())
    }

    /// The source dialog's answer: a bundle's `manifest.json` stands for its folder; any other
    /// file is itself.
    #[test]
    fn a_manifest_stands_for_its_bundle() {
        let dir = PathBuf::from("backups").join("atlas-duck-backup-x");
        assert_eq!(source_of(dir.join("manifest.json")), dir);
        assert_eq!(source_of(dir.join("MANIFEST.JSON")), dir);
        let db = PathBuf::from("archived").join("audit-c-9-20261019T000000000Z.db");
        assert_eq!(source_of(db.clone()), db);
        assert_eq!(
            source_of(PathBuf::from("manifest.json")),
            PathBuf::from("manifest.json")
        );
    }

    /// The window's kinds for every refusal the store can give (no path, no text).
    #[test]
    fn restore_failures_have_fixed_kinds() {
        let cases = [
            (
                AuditError::Restore(RestoreError::WrongPassphrase),
                RestoreFailure::WrongPassphrase,
            ),
            (
                AuditError::Restore(RestoreError::NotABundle),
                RestoreFailure::NotABackup,
            ),
            (
                AuditError::Restore(RestoreError::ManifestMismatch),
                RestoreFailure::NotABackup,
            ),
            (
                AuditError::Restore(RestoreError::SnapshotNewer { found: "x".into() }),
                RestoreFailure::Newer,
            ),
            (
                AuditError::Restore(RestoreError::ChainBroken("x".into())),
                RestoreFailure::Broken,
            ),
            (
                AuditError::Restore(RestoreError::AnchorDirMismatch("x".into())),
                RestoreFailure::AnchorDirMismatch,
            ),
            (
                AuditError::Restore(RestoreError::CommittedIncomplete {
                    restore_seq: 3,
                    reason: "x".into(),
                }),
                RestoreFailure::CommittedIncomplete,
            ),
            (
                AuditError::KeyStore(atlas_duck_audit::KeyStoreError::Unavailable),
                RestoreFailure::Keychain,
            ),
            (AuditError::Io("x".into()), RestoreFailure::Failed),
            (AuditError::Closed, RestoreFailure::Failed),
        ];
        for (e, want) in cases {
            assert_eq!(restore_failure(&e), want, "{e:?}");
        }
    }
}
