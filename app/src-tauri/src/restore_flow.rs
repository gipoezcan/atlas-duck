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
//!   or `cancelled`; `restore_cancel` ends the flow only before the store call; Quit cancels it
//!   before the call, else waits for it within `STORE_WAIT`). The caller then runs
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
/// or store call.
pub const RESTORE_CONFIRM_TEXT: &str = "Restore a backup? The current audit log is moved to the \
     archived folder of the data directory (never deleted) and the backup's log continues as a new \
     segment. You need the backup's recovery passphrase, which becomes this log's recovery \
     passphrase. Stored tokens are never restored: every instance needs its token again. Requests \
     wait while the restore runs.";

/// plan text (§8.11 step 4): the native confirmation of a same-machine rollback, with the number
/// of records it gives up.
pub fn rollback_text(records_lost: u64) -> String {
    format!(
        "This backup is older than this computer's audit log: restoring it gives up the last \
         {records_lost} records of the log (they stay in the archived copy of the current log). \
         Restore it anyway?"
    )
}

/// plan text (PD-181, §8.7): what the windows say after `committed_incomplete` (with a restart
/// prompt).
pub const COMMITTED_INCOMPLETE_TEXT: &str = "Restore will be completed at the next start";

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
    let path = chosen.into_path().ok()?;
    let source = source_of(path);
    Some(RustChosenPath::from_native_dialog(source))
}

/// Waits for the one passphrase entry of a `restore_backup` window, looking at `stop` between
/// bounded waits: `None` when the window went without a submit (the sender dropped) or `stop`
/// answered true (restore cancel, Quit). Never blocks unbounded.
pub fn wait_passphrase(
    rx: &Receiver<SecretString>,
    stop: &dyn Fn() -> bool,
) -> Option<SecretString> {
    loop {
        if stop() {
            return None;
        }
        match rx.recv_timeout(PASSPHRASE_POLL) {
            Ok(secret) => return Some(secret),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return None,
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
struct Asked {
    source: RustChosenPath,
    passphrase: SecretString,
    confirmed: Confirmed,
}

/// The native "Restore backup" confirmation, then the source dialog, then the passphrase (in this
/// order, PD-168). `None` as soon as one is cancelled, or `stop` answers true between them;
/// nothing was changed then.
fn ask_restore(
    confirmer: &dyn NativeConfirmer,
    pick: impl FnOnce() -> Option<RustChosenPath>,
    passphrase: impl FnOnce(&dyn Fn() -> bool) -> Option<SecretString>,
    stop: &dyn Fn() -> bool,
) -> Option<Asked> {
    if confirmer.confirm(RESTORE_CONFIRM_TEXT) != Confirm::Ok {
        return None;
    }
    let confirmed = crate::serve::confirmed_by(RESTORE_CONFIRM_TEXT);
    if stop() {
        return None;
    }
    let source = pick()?;
    if stop() {
        return None;
    }
    let passphrase = passphrase(stop)?;
    Some(Asked {
        source,
        passphrase,
        confirmed,
    })
}

/// The rollback confirmation (§8.11 step 4) for `records_lost`, asked again with the new count
/// while `head` (the live head's seq) moved during the dialog (M2 T16 M-3): records appended
/// meanwhile are lost too. `None` when cancelled.
fn ask_rollback(
    confirmer: &dyn NativeConfirmer,
    records_lost: u64,
    head: &dyn Fn() -> u64,
) -> Option<Confirmed> {
    let mut count = records_lost;
    loop {
        let before = head();
        let text = rollback_text(count);
        if confirmer.confirm(&text) != Confirm::Ok {
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
/// `audit_changed` after a restore. `call` decides between `restore_cancel` and the store call;
/// `cancel` is the job's quit flag. Every refusal before the store call is `cancelled` with no
/// event and nothing changed.
pub fn run_live_restore(
    store: &Store,
    confirmer: &dyn NativeConfirmer,
    pick: impl FnOnce() -> Option<RustChosenPath>,
    passphrase: impl FnOnce(&dyn Fn() -> bool) -> Option<SecretString>,
    call: &StoreCall,
    cancel: &AtomicBool,
    out: &dyn EventOut,
) -> Result<RestoreReport, CommandError> {
    let job = AuditJobKind::Restore;
    let stop = || cancel.load(Ordering::SeqCst) || call.cancelled();
    let Some(asked) = ask_restore(confirmer, pick, passphrase, &stop) else {
        return Err(CommandError::Cancelled);
    };
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
                match ask_rollback(confirmer, records_lost, &|| store.head().0) {
                    Some(c) => rollback = Some(c),
                    None => {
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
/// confirmation when it asks (no store runs, so its count cannot move). `stop` ends the wait for
/// the passphrase (Quit). Returns the running store and the report.
pub fn restore_without_store(
    data: &LocalDataDir,
    lock: &InstanceLock,
    config: &dyn Fn() -> OpenConfig,
    confirmer: &dyn NativeConfirmer,
    pick: impl FnOnce() -> Option<RustChosenPath>,
    passphrase: impl FnOnce(&dyn Fn() -> bool) -> Option<SecretString>,
    stop: &dyn Fn() -> bool,
) -> Result<(Store, RestoreReport), UnlockFailure> {
    if live_store_blocks_restore(data) {
        return Err(UnlockFailure::ArchiveFirst);
    }
    let Some(asked) = ask_restore(confirmer, pick, passphrase, stop) else {
        return Err(UnlockFailure::Cancelled);
    };
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
                match ask_rollback(confirmer, records_lost, &|| 0) {
                    Some(c) => rollback = Some(c),
                    None => return Err(UnlockFailure::Cancelled),
                }
            }
            other => return other.map_err(|e| UnlockFailure::of(&e)),
        }
    }
}

#[cfg(test)]
mod tests {
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
                Some(pass())
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
                Some(pass())
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
            |_| Some(pass()),
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
            |_| Some(pass()),
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
            |_| Some(SecretString::from("not the passphrase".to_owned())),
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
    /// rollback text with its count.
    #[test]
    fn restore_confirmation_recorded_after_restore() -> TestResult {
        let r = rig(2)?;
        let source = bundle(&r)?;
        let confirmer = Answers::new(&[Confirm::Ok, Confirm::Ok]);
        let report = run_live_restore(
            &r.store,
            &confirmer,
            || Some(chosen(&source)),
            |_| Some(pass()),
            &StoreCall::default(),
            &AtomicBool::new(false),
            &Events::default(),
        )?;
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
                Some(pass())
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
        assert!(wait_passphrase(&rx, &|| false).is_some());
        assert!(wait_passphrase(&rx, &|| true).is_none(), "stop");
        drop(tx);
        assert!(wait_passphrase(&rx, &|| false).is_none(), "the window went");
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
            |_| Some(pass()),
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
                None
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
