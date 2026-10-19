//! "Prepare for removal" (§12.5, §8.7 offboarding, L27; M6 T28, PD-88): the step machine.
//!
//! The procedure, in the spec's order: (1) a full backup is offered (it never holds a token, §8.10);
//! (2) `begin` confirms natively, then deletes the stored tokens (`InstanceAdmin::delete_token` logs
//! `CREDENTIAL_CHANGED` before the keychain delete) and lists, per instance, the step
//! [`REVOKE_STEP`] with the alias and the token identity the user must tick as revoked or mark as
//! skipped; (3) `finish` is refused until every instance is ticked or skipped, confirms natively,
//! records one `CONFIG_CHANGED` with the choices *before* anything is removed, then removes
//! autostart, the PATH entry / link / wrapper / launcher and `cli.toml`; (4) the KEK, the anchors
//! and the audit DB are never touched: nothing in this module opens a key, an anchor or a database.
//!
//! The checklist lives in memory (one procedure per process; a second concurrent call is
//! `removal {running}`). It survives a restart through the audit log, not a progress file (PD-176):
//! the first removal call of a process reads the newest `CONFIG_CHANGED {key:
//! prepare_for_removal}` back ([`read_log`], [`RemovalState::hydrate`]); a choices record that no
//! outcome record followed is a procedure whose effects did not all run, and it is resumed with its
//! answers, token identities and backup flag, recorded (a retried `finish` does not record the
//! choices again; a token stored since puts its item back to "not deleted"). A resumed procedure
//! ends only with `finish` (M10 T16 review I-3: no abandon). A `RESTORE` newer than the choices
//! record ends the scan with nothing resumed. Before that record exists, the procedure is
//! resumable by idempotence: after a restart, `begin` again deletes only what is still stored and
//! logs nothing for what is gone, and the checklist lists *every* confirmed instance and every
//! other one whose delete succeeded (M10 T16 review I-1), so a token deleted before the restart is
//! still offered for revocation (its identity is no longer known: `delete_token` clears it, so the
//! page says so).
//!
//! Core decides, the page asks: nothing here takes a path, an origin or a token from a webview.
//! Every dialog is drawn by Rust through the injected [`NativeConfirmer`] on the blocking pool.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use atlas_duck_audit::types::RustChosenPath;
use atlas_duck_audit::{
    AuditCursor, AuditError, AuditFilter, EventType, MAX_AUDIT_PAGE_ROWS, Store, TimeRange,
    UtcInstant,
};
use atlas_duck_core::config::instances::{MAX_ALIAS_CHARS, product_str};
use atlas_duck_core::{
    AdminError, Confirm, InstanceAdmin, InstanceView, NativeConfirmer, SettingsAdmin, SettingsError,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli_install::{self, InstallError, Kind, Layout, PlatformOps};
use crate::commands::CommandError;
use crate::commands::audit::{ExportDoneDto, run_export};
use crate::commands::settings::cli_uninstall_dto;
use crate::recovery_tier::DIALOG_LIST_MAX;
use crate::ui_sink::EventOut;

/// §12.5 step 2 (verbatim): shown per instance with its alias and token identity.
pub const REVOKE_STEP: &str =
    "Revoke this token in Jira/Confluence (Profile → Personal Access Tokens)";

/// The `CONFIG_CHANGED {source: app}` key of the procedure's one record (§12.5).
pub const KEY_REMOVAL: &str = "prepare_for_removal";
/// The `CONFIG_CHANGED {source: app}` key of the autostart removal (audit before effect).
pub const KEY_AUTOSTART: &str = "autostart";

/// Log event of a refused or failed removal call (kind only).
pub const LOG_EVENT_REMOVAL_FAILED: &str = "removal_failed";

/// PD-176: the most `CONFIG_CHANGED` payloads [`read_log`] decrypts looking for the newest
/// `prepare_for_removal` record. The key is in the encrypted payload only (§8.2 keeps `target` for
/// its listed values), so the records newer than it are read too; past this many the log is taken to
/// hold no open procedure (logged).
pub const MAX_LOG_SCAN_RECORDS: usize = 10_000;

/// PD-176: the most instances a choices record is read back with; a longer list is not resumed.
const MAX_RECORDED_ITEMS: usize = 1_024;

/// PD-176: the longest token identity (in characters) the choices record keeps per instance, so the
/// record stays far below core's bound on an app record's value.
pub const MAX_RECORDED_IDENTITY_CHARS: usize = 128;

/// The user's answer for one instance's revoke step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Choice {
    /// Not answered yet: the procedure cannot finish.
    Pending,
    /// The user revoked the token on the server.
    Done,
    /// The user explicitly skipped it (the PAT stays valid server-side until revoked).
    Skipped,
}

impl Choice {
    fn recorded(self) -> &'static str {
        match self {
            Choice::Pending => "pending",
            Choice::Done => "done",
            Choice::Skipped => "skipped",
        }
    }

    /// The answer a choices record names (`done` or `skipped`); anything else is not an answer.
    fn from_recorded(s: &str) -> Option<Choice> {
        match s {
            "done" => Some(Choice::Done),
            "skipped" => Some(Choice::Skipped),
            _ => None,
        }
    }
}

/// Why a removal call was refused, beyond the errors core and the command layer already have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalError {
    /// `mark` or `finish` before `begin`: there is no procedure.
    NoProcedure,
    /// `finish` while an instance is not ticked or skipped, or its token is not deleted.
    Unticked,
    /// `finish` found a token stored again for a listed instance (a PAT entered during the
    /// procedure): nothing was removed; `begin` deletes it again.
    TokenStored,
    /// Autostart could not be read or removed; the record of the attempt was undone.
    Autostart,
    /// `mark` after the choices were written to the audit log (a failed effect left the procedure
    /// in place for a retry): the recorded answers are not changed afterwards.
    Recorded,
    /// Another removal call runs (its dialog, its token deletes): wait for it (T28 m-8). Also the
    /// answer of `credential_window_open` meanwhile. Another *job* holding the serving state's slot
    /// (an export, a backup, a restore) is plain `busy`.
    Running,
}

impl RemovalError {
    pub fn kind(self) -> &'static str {
        match self {
            Self::NoProcedure => "no_procedure",
            Self::Unticked => "unticked",
            Self::TokenStored => "token_stored",
            Self::Autostart => "autostart",
            Self::Recorded => "recorded",
            Self::Running => "running",
        }
    }
}

/// The kind only, like the other errors' `Display`.
impl std::fmt::Display for RemovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind())
    }
}

impl std::error::Error for RemovalError {}

impl Serialize for RemovalError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(1))?;
        m.serialize_entry("kind", self.kind())?;
        m.end()
    }
}

/// Autostart (the login item), as the procedure needs it. The real implementation is over
/// `tauri-plugin-autostart`; tests use a fake. Errors are kinds without text.
pub trait AutostartPort: Send + Sync {
    fn is_enabled(&self) -> Result<bool, AutostartFailed>;
    fn disable(&self) -> Result<(), AutostartFailed>;
}

/// The autostart entry could not be read or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutostartFailed;

/// The real autostart over `tauri-plugin-autostart` (registered in `tray::plugins`). A missing
/// plugin state is a failure, never a panic.
pub struct PluginAutostart<R: tauri::Runtime>(pub tauri::AppHandle<R>);

impl<R: tauri::Runtime> AutostartPort for PluginAutostart<R> {
    fn is_enabled(&self) -> Result<bool, AutostartFailed> {
        use tauri::Manager;
        let manager = self
            .0
            .try_state::<tauri_plugin_autostart::AutoLaunchManager>()
            .ok_or(AutostartFailed)?;
        manager.is_enabled().map_err(|_| AutostartFailed)
    }

    fn disable(&self) -> Result<(), AutostartFailed> {
        use tauri::Manager;
        let manager = self
            .0
            .try_state::<tauri_plugin_autostart::AutoLaunchManager>()
            .ok_or(AutostartFailed)?;
        manager.disable().map_err(|_| AutostartFailed)
    }
}

/// The retention facts the page shows beside the backup offer (§12.5 step 1: "the remaining
/// retention days of the newest record").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// The setting.
    pub days: u32,
    pub legal_hold: bool,
    /// The newest record's remaining retention in days (PD-176): `days` less the age in days of its
    /// effective epoch, at least 0; `None` while a legal hold is on (kept indefinitely).
    pub left_days: Option<u32>,
}

impl Retention {
    /// PD-176: `newest_epoch` is the newest record's `epoch` column (`YYYY-MM-DD`), `today` the
    /// current UTC time. That record has no later record to take an effective epoch from, so a
    /// `NULL` epoch (written while the clock was behind) has none: it is not prunable until a later
    /// record has one (L36), and the setting itself is the truthful "at least". So is an epoch after
    /// today.
    pub fn of(days: u32, legal_hold: bool, newest_epoch: Option<&str>, today: UtcInstant) -> Self {
        let age = newest_epoch
            .and_then(atlas_duck_audit::clock::parse_epoch)
            .map_or(0, |epoch| {
                today.date().signed_duration_since(epoch).num_days().max(0)
            });
        let left = i64::from(days).saturating_sub(age).max(0);
        Retention {
            days,
            legal_hold,
            left_days: (!legal_hold).then(|| u32::try_from(left).unwrap_or(0)),
        }
    }
}

/// The newest record's `epoch` (§12.5 step 1: the log's head; PD-176), for [`retention_shown`].
pub fn newest_epoch(store: &Store) -> Result<Option<String>, AuditError> {
    let page = store.query(&AuditFilter::default(), AuditCursor::first(1))?;
    Ok(page.rows.first().and_then(|h| h.epoch.clone()))
}

/// The retention facts the page shows (PD-176), `newest` being [`newest_epoch`]'s answer. They are
/// display only (M10 T16 review M-2): a log whose head cannot be read shows the setting itself (a
/// truthful "at least"), logged by class, and the removal call goes on. `today` is the system
/// clock's, not the corroborated date prune uses: a clock behind shows at most the setting, a clock
/// ahead a smaller number.
pub fn retention_shown(
    days: u32,
    legal_hold: bool,
    newest: Result<Option<String>, AuditError>,
    today: UtcInstant,
) -> Retention {
    let epoch = newest.unwrap_or_else(|_| {
        tracing::warn!(event = LOG_EVENT_REMOVAL_FAILED, error_class = "audit");
        None
    });
    Retention::of(days, legal_hold, epoch.as_deref(), today)
}

/// One instance of the checklist as the page sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemDto {
    pub alias: String,
    pub product: &'static str,
    pub origin: Option<String>,
    /// The token's identity (`executes_as`) read before the token was deleted; `None` when it is
    /// no longer known (deleted before a restart) or the instance had no token.
    pub identity: Option<String>,
    /// The token is no longer stored.
    pub token_deleted: bool,
    /// Why the delete failed (core's error kind), `None` when it did not.
    pub error: Option<String>,
    pub choice: Choice,
}

/// `removal_state`'s answer (and what `removal_begin`, `removal_mark` answer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemovalDto {
    /// A procedure is under way: `begin` ran in this process, or the audit log holds its choices
    /// record and no outcome record (PD-176); `finish` has not completed.
    pub active: bool,
    /// The answers are in the audit log (a failed effect left the procedure for a retry): they are
    /// final, `removal_mark` is refused (T28 m-4).
    pub recorded: bool,
    /// A full backup was made in this procedure.
    pub backup_made: bool,
    /// The retention setting.
    pub retention_days: u32,
    pub legal_hold: bool,
    /// [`Retention::left_days`]: the newest record's remaining retention; `null` while a legal hold
    /// is on.
    pub retention_left_days: Option<u32>,
    pub instances: Vec<ItemDto>,
}

/// `removal_backup`'s answer: `saved: false` is a cancelled file dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BackupAnswer {
    pub saved: bool,
}

/// `removal_finish`'s answer: what was removed, as fixed words the page maps to its own text.
/// `cli`: `removed`, `already_on_path` (deb/rpm: the package owns the CLI), `not_found` (the fixed
/// paths hold nothing of ours) or `not_removed` (the layout of this run could not be named, so not
/// everything could be looked at; `cli_reason` is the error kind, `None` otherwise). `autostart`:
/// `removed` or `was_off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FinishAnswer {
    pub cli: &'static str,
    pub cli_reason: Option<&'static str>,
    pub autostart: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Item {
    alias: String,
    product: &'static str,
    origin: Option<String>,
    identity: Option<String>,
    deleted: bool,
    error: Option<String>,
    choice: Choice,
}

#[derive(Debug, Default)]
struct Procedure {
    items: Vec<Item>,
    /// `prepare_for_removal` is in the log: a retried `finish` does not record it again.
    recorded: bool,
    /// An earlier `finish` of this procedure removed autostart (its later step failed): a retry
    /// finds it off and still answers `removed` (M6 M-12, T28 m-5).
    autostart_removed: bool,
}

#[derive(Debug, Default)]
struct Inner {
    backup_made: bool,
    procedure: Option<Procedure>,
    /// The audit log was read back for an open procedure (PD-176), once per process.
    hydrated: bool,
}

/// What the audit log says about the procedure (PD-176), from its newest `CONFIG_CHANGED {key:
/// prepare_for_removal}`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogFacts {
    /// That record is a choices record (written before the effects) and no outcome record followed:
    /// the procedure it records did not end.
    pub open: Option<OpenProcedure>,
}

/// A procedure the audit log records as not ended (PD-176).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenProcedure {
    /// A full backup was made in it.
    pub backup: bool,
    pub items: Vec<RecordedItem>,
    /// The newest `autostart` record after the choices record says it was removed (and no undo
    /// followed): the next `finish` finds it off and answers `removed`.
    pub autostart_removed: bool,
}

/// One instance of a choices record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedItem {
    pub alias: String,
    pub product: &'static str,
    /// The token's identity when the token was deleted (bounded, PD-176).
    pub identity: Option<String>,
    pub choice: Choice,
}

/// The one procedure of this process, managed by Tauri (`app.manage`). A call that changes it holds
/// the `busy` claim for its whole run (dialogs included), so two calls never overlap.
#[derive(Debug, Default)]
pub struct RemovalState {
    inner: Mutex<Inner>,
    busy: AtomicBool,
}

/// Holds the `busy` claim; released on drop, also when the call's future is dropped.
pub struct Claim<'a>(&'a AtomicBool);

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl RemovalState {
    /// `Busy` while another removal call runs.
    pub fn claim(&self) -> Result<Claim<'_>, CommandError> {
        if self.busy.swap(true, Ordering::SeqCst) {
            Err(CommandError::Removal(RemovalError::Running))
        } else {
            Ok(Claim(&self.busy))
        }
    }

    /// The audit log has not been read back for an open procedure yet (PD-176): the command layer
    /// reads it ([`read_log`]) and calls [`RemovalState::hydrate`] before the call.
    pub fn needs_log(&self) -> bool {
        !self.lock().hydrated
    }

    /// PD-176: resumes the procedure the audit log records as not ended, unless this process
    /// already holds one; `views` (the live instance list) give each item its origin. Once per
    /// process.
    pub fn hydrate(&self, facts: LogFacts, views: &[InstanceView]) {
        let mut inner = self.lock();
        if inner.hydrated {
            return;
        }
        inner.hydrated = true;
        let Some(open) = facts.open else {
            return;
        };
        if inner.procedure.is_some() {
            return;
        }
        let items = open
            .items
            .into_iter()
            .map(|r| Item {
                origin: views
                    .iter()
                    .find(|v| v.alias == r.alias)
                    .and_then(|v| v.origin.clone()),
                alias: r.alias,
                product: r.product,
                identity: r.identity,
                // `finish` wrote the record only once every token was deleted.
                deleted: true,
                error: None,
                choice: r.choice,
            })
            .collect();
        let mut procedure = Procedure {
            items,
            recorded: true,
            autostart_removed: open.autostart_removed,
        };
        // M10 T16 review I-3: a token stored since (entered after the failed effect) is what the
        // live table says, not the record: that item is "not deleted, not answered" with the
        // identity shown now, and the recorded choices no longer describe the procedure.
        reconcile(&mut procedure, views, false);
        inner.procedure = Some(procedure);
        // A backup made in this process before the first hydrating call (the Audit window's "Back
        // up now") belongs to the open procedure too.
        inner.backup_made |= open.backup;
    }

    /// The command layer's step before a removal call (PD-176): `read` is [`read_log`]'s answer,
    /// `views` the live instance list. A closed store is `not_ready`, and the log is read again by
    /// the next call; any other error resumes nothing (logged by class), so the procedure starts
    /// over as before PD-176, and the log is not read again in this process.
    pub fn hydrate_from(
        &self,
        read: Result<LogFacts, AuditError>,
        views: &[InstanceView],
    ) -> Result<(), CommandError> {
        let facts = match read {
            Ok(facts) => facts,
            Err(AuditError::Closed) => return Err(CommandError::NotReady),
            Err(_) => {
                tracing::warn!(event = LOG_EVENT_REMOVAL_FAILED, error_class = "audit");
                LogFacts::default()
            }
        };
        self.hydrate(facts, views);
        Ok(())
    }

    /// A removal call is running now (the credential window must not open meanwhile).
    pub fn busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The checklist as the page shows it.
    pub fn dto(&self, retention: Retention) -> RemovalDto {
        let inner = self.lock();
        RemovalDto {
            active: inner.procedure.is_some(),
            recorded: inner.procedure.as_ref().is_some_and(|p| p.recorded),
            backup_made: inner.backup_made,
            retention_days: retention.days,
            legal_hold: retention.legal_hold,
            retention_left_days: retention.left_days,
            instances: inner
                .procedure
                .as_ref()
                .map(|p| {
                    p.items
                        .iter()
                        .map(|i| ItemDto {
                            alias: i.alias.clone(),
                            product: i.product,
                            origin: i.origin.clone(),
                            identity: i.identity.clone(),
                            token_deleted: i.deleted,
                            error: i.error.clone(),
                            choice: i.choice,
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

/// A token is stored for the instance, as far as the table knows: core keeps the identity of the
/// stored token and clears it when the token is deleted (`delete_token`). Used for what the dialog
/// names and for the check at `finish`; never to decide whether to call `delete_token`.
fn token_stored(view: &InstanceView) -> bool {
    view.executes_as.is_some()
}

/// Instances on the checklist: every one that can hold a token. An `http://` instance and one
/// still unconfirmed cannot have been given a PAT (§7.1), unless the table still shows an
/// identity for it (a confirmed instance that `config.toml` has since turned `insecure_scheme`
/// keeps its token). Every other instance is listed whether or not a token is stored now: a token
/// deleted before a restart still has to be revoked.
fn listed(view: &InstanceView) -> bool {
    !matches!(view.state, "instance_unconfirmed" | "insecure_scheme") || token_stored(view)
}

/// The aliases `begin` deletes the token of. No procedure yet: every instance, listed or not (T28
/// m-1: a table that lost an identity, or failed closed with every instance unconfirmed, must not
/// leave a keychain entry behind; `delete_token` logs nothing when nothing is stored). Otherwise
/// what is not deleted, every instance whose token the table shows (a token entered since), and
/// every listed instance the checklist does not have yet.
fn begin_targets(procedure: Option<&Procedure>, views: &[InstanceView]) -> Vec<String> {
    let Some(p) = procedure else {
        return views.iter().map(|v| v.alias.clone()).collect();
    };
    let mut targets: Vec<String> = Vec::new();
    let mut add = |alias: &str| {
        if !targets.iter().any(|t| t == alias) {
            targets.push(alias.to_owned());
        }
    };
    for item in p.items.iter().filter(|i| !i.deleted) {
        add(&item.alias);
    }
    for v in views {
        let known = p.items.iter().any(|i| i.alias == v.alias);
        if token_stored(v) || (listed(v) && !known) {
            add(&v.alias);
        }
    }
    targets
}

/// Brings the checklist in line with the live instance list (what `InstanceAdmin` shows at this
/// moment, not what the checklist listed at `begin`): an instance whose token is stored is "not
/// deleted, not answered" with the identity the table shows now (a new token is a new thing to
/// revoke: an earlier tick is stale), and one the checklist lacks joins it (`add_unstored`: every
/// listed instance; otherwise only one holding a token). `true` when a token was found stored. The
/// choices written to the audit log earlier no longer describe the procedure then, nor once an
/// instance joined (it needs an answer, which `mark` refuses for recorded choices: M10 T16).
fn reconcile(p: &mut Procedure, views: &[InstanceView], add_unstored: bool) -> bool {
    let mut found = false;
    let mut joined = false;
    for v in views {
        let stored = token_stored(v);
        match p.items.iter_mut().find(|i| i.alias == v.alias) {
            Some(item) if stored => {
                item.deleted = false;
                item.error = None;
                item.choice = Choice::Pending;
                item.identity = v.executes_as.clone();
                found = true;
            }
            Some(_) => {}
            None if stored || (add_unstored && listed(v)) => {
                p.items.push(Item {
                    alias: v.alias.clone(),
                    product: product_str(v.product),
                    origin: v.origin.clone(),
                    identity: v.executes_as.clone(),
                    deleted: false,
                    error: None,
                    choice: Choice::Pending,
                });
                found |= stored;
                joined = true;
            }
            None => {}
        }
    }
    if found || joined {
        p.recorded = false;
    }
    found
}

async fn run_blocking<T, F>(f: F) -> Result<T, CommandError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| CommandError::Internal)
}

/// Draws the dialog on the blocking pool (the confirmer blocks until the user answers); `Cancel`
/// is `Cancelled` and the caller changed nothing.
async fn confirmed(confirmer: &Arc<dyn NativeConfirmer>, text: String) -> Result<(), CommandError> {
    let confirmer = confirmer.clone();
    match run_blocking(move || confirmer.confirm(&text)).await? {
        Confirm::Ok => Ok(()),
        Confirm::Cancel => Err(CommandError::Settings(SettingsError::Cancelled)),
    }
}

/// PD-176: the newest `CONFIG_CHANGED {source: app, key: prepare_for_removal}` of `store`, read
/// back. Newest first over the `CONFIG_CHANGED` headers, decrypting each (the key is in the payload
/// only), at most [`MAX_LOG_SCAN_RECORDS`]; on the way it notes the newest `autostart` record newer
/// than that record. A `RESTORE` newer than that record ends the scan with no procedure (M10 T16
/// review M-6): a choices record older than a restore came in with the restored backup (another
/// machine's procedure, §8.7, or one the rollback took back), and is not resumed. A store that
/// cannot be read is the caller's to handle.
pub fn read_log(store: &Store) -> Result<LogFacts, AuditError> {
    read_log_capped(store, MAX_LOG_SCAN_RECORDS)
}

/// [`read_log`] with at most `cap` payloads decrypted (tests lower it).
pub(crate) fn read_log_capped(store: &Store, cap: usize) -> Result<LogFacts, AuditError> {
    let filter = AuditFilter {
        event_types: vec![EventType::CONFIG_CHANGED, EventType::RESTORE],
        ..AuditFilter::default()
    };
    let mut cursor = AuditCursor::first(MAX_AUDIT_PAGE_ROWS);
    // The newest `autostart` record seen so far (so: newer than any removal record still ahead).
    let mut autostart_enabled: Option<bool> = None;
    let mut read = 0usize;
    loop {
        let page = store.query(&filter, cursor)?;
        for header in &page.rows {
            if header.event_type == EventType::RESTORE {
                return Ok(LogFacts::default());
            }
            if read == cap {
                tracing::warn!(
                    event = LOG_EVENT_REMOVAL_FAILED,
                    error_class = "log_scan_limit"
                );
                return Ok(LogFacts::default());
            }
            read += 1;
            let bytes = store.read_payload(header.seq)?;
            let Ok(payload) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            if payload.get("source").and_then(Value::as_str) != Some("app") {
                continue;
            }
            match payload.get("key").and_then(Value::as_str) {
                Some(KEY_AUTOSTART) if autostart_enabled.is_none() => {
                    autostart_enabled = payload
                        .get("new")
                        .and_then(|n| n.get("enabled"))
                        .and_then(Value::as_bool);
                }
                Some(KEY_REMOVAL) => {
                    let open = payload
                        .get("new")
                        .and_then(|new| open_procedure(new, autostart_enabled == Some(false)));
                    return Ok(LogFacts { open });
                }
                _ => {}
            }
        }
        match page.next {
            Some(next) => cursor = next,
            None => return Ok(LogFacts::default()),
        }
    }
}

/// A choices record's `new` value (`{prepared: false, backup, instances: [{alias, product,
/// identity, revoke}]}`) as the procedure it records; `None` for an outcome record (no
/// `instances`) and for one this version cannot read whole: it is read as data, bounded, and every
/// field must have the shape `finish` writes.
fn open_procedure(new: &Value, autostart_removed: bool) -> Option<OpenProcedure> {
    let instances = new.get("instances")?.as_array()?;
    if instances.len() > MAX_RECORDED_ITEMS {
        return None;
    }
    let items = instances
        .iter()
        .map(|item| {
            let alias = item.get("alias")?.as_str()?;
            let alias_ok = (1..=MAX_ALIAS_CHARS).contains(&alias.len())
                && alias
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
            if !alias_ok {
                return None;
            }
            let product = match item.get("product")?.as_str()? {
                "jira" => "jira",
                "confluence" => "confluence",
                _ => return None,
            };
            let identity = match item.get("identity") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => Some(bounded_identity(s)),
                Some(_) => return None,
            };
            Some(RecordedItem {
                alias: alias.to_owned(),
                product,
                identity,
                choice: Choice::from_recorded(item.get("revoke")?.as_str()?)?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    // `finish` names each instance once (M10 T16 review M-9).
    let mut seen = std::collections::HashSet::new();
    if !items.iter().all(|i| seen.insert(i.alias.as_str())) {
        return None;
    }
    Some(OpenProcedure {
        backup: new.get("backup").and_then(Value::as_bool).unwrap_or(false),
        items,
        autostart_removed,
    })
}

/// A token identity as the choices record keeps it: at most [`MAX_RECORDED_IDENTITY_CHARS`]
/// characters (server text; the page shows it as such).
fn bounded_identity(s: &str) -> String {
    s.chars().take(MAX_RECORDED_IDENTITY_CHARS).collect()
}

/// §12.5 step 1: the compliance export the procedure offers next to the backup: the Audit window's
/// export (PD-159..PD-161, M10 T12) over the full range, the PD-161 warning and the folder dialog
/// drawn by Rust, run as the serving state's one job by the caller (`removal_export`). It changes
/// no token, so it needs no removal claim.
pub fn export(
    store: &Store,
    confirmer: &dyn NativeConfirmer,
    pick: impl FnOnce() -> Option<RustChosenPath>,
    cancel: &AtomicBool,
    out: &dyn EventOut,
) -> Result<ExportDoneDto, CommandError> {
    run_export(store, confirmer, pick, TimeRange::all(), cancel, out)
}

/// plan text (M6 T28, T28 m-2; the step is §12.5's): what `begin` asks. `targets` are the instances
/// whose token is deleted, each with whether the instance table knows the stored token's identity.
/// Aliases are Rust-validated names (`A-Za-z0-9._-`, at most 64); no server text (no identity) is
/// in the text. At most [`DIALOG_LIST_MAX`] are named, the rest counted (M10 T16 review M-10).
pub fn begin_text(targets: &[(String, bool)]) -> String {
    let tokens = if targets.is_empty() {
        "No instance is set up, so no token is deleted.".to_owned()
    } else {
        let mut list = targets
            .iter()
            .take(DIALOG_LIST_MAX)
            .map(|(alias, known)| {
                if *known {
                    alias.clone()
                } else {
                    format!("{alias} (identity unknown)")
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        if targets.len() > DIALOG_LIST_MAX {
            list.push_str(&format!(" and {} more", targets.len() - DIALOG_LIST_MAX));
        }
        // M10 T16 review I-1: such an instance is on the next step's list too, to be skipped
        // there when it never had a token.
        let unknown = if targets.iter().any(|(_, known)| !known) {
            "An instance marked \"identity unknown\" has no token identity on record: a token \
             stored for it is deleted too, and the next step lists it as well (skip it there if \
             it never had a token). "
        } else {
            ""
        };
        format!(
            "Any token stored for these instances will be deleted: {list}. {unknown}A deleted \
             token stays valid on the Jira/Confluence server until you revoke it there; the next \
             step lists each one."
        )
    };
    format!(
        "Prepare atlas-duck for removal?\n\n{tokens}\n\n\
         The audit log, its keys and anchors are kept, so the log stays verifiable until its \
         retention period has passed."
    )
}

/// plan text (M6 T28; the step is §12.5 step 3's): what `finish` asks.
pub fn finish_text() -> String {
    "Finish removal?\n\n\
     atlas-duck will stop starting at login, and its command-line launcher will be removed (the \
     PATH entry, link or wrapper, launcher entry and cli.toml, where they exist). Your answer for \
     each token (revoked or skipped) is recorded in the audit log.\n\n\
     The audit log, its keys and anchors are kept."
        .to_owned()
}

/// §12.5 step 1: the full backup. `pick_and_back_up` opens Rust's folder dialog and runs
/// `Store::backup` (the webview supplies no path); `Ok(false)` is a cancelled dialog. The backup
/// holds no token (§8.10) and appends its own `BACKUP` record, so nothing is recorded here.
pub fn backup(
    state: &RemovalState,
    pick_and_back_up: impl FnOnce() -> Result<bool, CommandError>,
) -> Result<BackupAnswer, CommandError> {
    let _claim = state.claim()?;
    let saved = pick_and_back_up()?;
    if saved {
        state.lock().backup_made = true;
    }
    Ok(BackupAnswer { saved })
}

/// `begin` (§12.5 step 2): refuses (`busy`) while `held_off` says the credential window is open
/// for a token (a submit in flight could store one after the delete; T20 m-9) or the serving
/// state's job slot is held (a restore could take the log back meanwhile; M10 T16 review M-6),
/// before the dialog and again after it; confirms natively; deletes the stored tokens. A second
/// `begin` deletes only what is still stored (a failed delete, or a token entered since) and shows
/// the same dialog again. `ShuttingDown` ends the call at once.
pub async fn begin(
    state: &RemovalState,
    instances: Arc<dyn InstanceAdmin>,
    confirmer: Arc<dyn NativeConfirmer>,
    held_off: impl Fn() -> bool,
    retention: Retention,
) -> Result<RemovalDto, CommandError> {
    let _claim = state.claim()?;
    if held_off() {
        return Err(CommandError::Busy);
    }
    let views = {
        let admin = instances.clone();
        run_blocking(move || admin.list()).await?
    };
    let first_run = state.lock().procedure.is_none();
    // `delete_token` is called for every instance on a first run, listed or not, not only for
    // those the table says hold a token: it is idempotent and logs nothing when nothing is stored,
    // and a keychain entry must not outlive the delete because the table lost the identity (T28
    // m-1). Afterwards a run retries what is not deleted, and looks at the live list again: an
    // instance added or confirmed since, or one given a token since, is deleted too.
    let targets = {
        let inner = state.lock();
        begin_targets(inner.procedure.as_ref(), &views)
    };
    if !first_run && targets.is_empty() {
        return Ok(state.dto(retention));
    }
    // The dialog names every instance whose token is deleted, and which of them has no identity on
    // record (T28 m-2).
    let named: Vec<(String, bool)> = targets
        .iter()
        .map(|alias| {
            let known = views.iter().any(|v| &v.alias == alias && token_stored(v));
            (alias.clone(), known)
        })
        .collect();
    confirmed(&confirmer, begin_text(&named)).await?;
    // The dialog may have been up for minutes: a job that took the slot meanwhile holds it off.
    if held_off() {
        return Err(CommandError::Busy);
    }
    {
        let mut inner = state.lock();
        let procedure = inner.procedure.get_or_insert_with(Procedure::default);
        reconcile(procedure, &views, true);
    }
    for alias in targets {
        let result = instances.delete_token(&alias).await;
        if let Err(AdminError::ShuttingDown) = result {
            return Err(CommandError::Admin(AdminError::ShuttingDown));
        }
        let mut inner = state.lock();
        let Some(p) = inner.procedure.as_mut() else {
            continue;
        };
        match (result, p.items.iter_mut().find(|i| i.alias == alias)) {
            // Core answered without an error: no token is stored for the instance now.
            (Ok(_), Some(item)) => {
                item.deleted = true;
                item.error = None;
            }
            // M10 T16 review I-1: an instance off the checklist (unconfirmed, or `http://`, with no
            // identity on record: a table that failed closed lists none of them) whose token was
            // deleted, if one was stored: it joins the checklist as deleted, identity unknown, so
            // its revoke step is offered before the procedure completes; the user skips it when it
            // never had a token. (Only a first run gets here: afterwards `reconcile` already put
            // every target on the checklist.)
            (Ok(_), None) => {
                if let Some(v) = views.iter().find(|v| v.alias == alias) {
                    p.recorded = false;
                    p.items.push(Item {
                        alias,
                        product: product_str(v.product),
                        origin: v.origin.clone(),
                        identity: v.executes_as.clone(),
                        deleted: true,
                        error: None,
                        choice: Choice::Pending,
                    });
                }
            }
            (Err(e), Some(item)) => item.error = Some(e.to_string()),
            // An instance off the checklist whose delete failed may still hold a token: it joins
            // the checklist as not deleted, so `finish` waits for a `begin` that deletes it.
            (Err(e), None) => {
                if let Some(v) = views.iter().find(|v| v.alias == alias) {
                    p.recorded = false;
                    p.items.push(Item {
                        alias,
                        product: product_str(v.product),
                        origin: v.origin.clone(),
                        identity: v.executes_as.clone(),
                        deleted: false,
                        error: Some(e.to_string()),
                        choice: Choice::Pending,
                    });
                }
            }
        }
    }
    Ok(state.dto(retention))
}

/// `mark` (§12.5 step 2): the user's answer for one instance. Only an instance whose token is
/// deleted can be answered (a token still stored is revoked after it is deleted, not before).
pub fn mark(
    state: &RemovalState,
    alias: &str,
    choice: Choice,
    retention: Retention,
) -> Result<RemovalDto, CommandError> {
    let _claim = state.claim()?;
    {
        let mut inner = state.lock();
        let procedure = inner
            .procedure
            .as_mut()
            .ok_or(CommandError::Removal(RemovalError::NoProcedure))?;
        let item = procedure
            .items
            .iter_mut()
            .find(|i| i.alias == alias)
            .ok_or(CommandError::InvalidArgument { field: "alias" })?;
        // Once the choices are in the audit log they are final for this procedure.
        if procedure.recorded {
            return Err(CommandError::Removal(RemovalError::Recorded));
        }
        if !item.deleted {
            return Err(CommandError::InvalidArgument { field: "alias" });
        }
        item.choice = choice;
    }
    Ok(state.dto(retention))
}

/// A second `record_app_change` that undoes the first after its effect failed (`SettingsAdmin`:
/// "an app effect that fails afterwards appends a second call with `new = old`"). Its own failure
/// cannot improve the answer; it is logged by kind.
fn record_undo(settings: &dyn SettingsAdmin, key: &str, old: Value, new: Value) {
    if let Err(e) = settings.record_app_change(key, new, old) {
        tracing::warn!(
            event = LOG_EVENT_REMOVAL_FAILED,
            error_class = "settings",
            error_kind = e.to_string().as_str()
        );
    }
}

/// The autostart step: record, then remove; a failure undoes the record. `Ok(true)` removed it,
/// `Ok(false)` it was off already (nothing recorded).
fn remove_autostart(
    settings: &dyn SettingsAdmin,
    port: &dyn AutostartPort,
) -> Result<bool, CommandError> {
    let on = port
        .is_enabled()
        .map_err(|_| CommandError::Removal(RemovalError::Autostart))?;
    if !on {
        return Ok(false);
    }
    let (old, new) = (json!({"enabled": true}), json!({"enabled": false}));
    settings.record_app_change(KEY_AUTOSTART, old.clone(), new.clone())?;
    if port.disable().is_err() {
        record_undo(settings, KEY_AUTOSTART, old, new);
        return Err(CommandError::Removal(RemovalError::Autostart));
    }
    Ok(true)
}

/// The CLI step (§12.3, §12.5 step 3): `cli_uninstall_dto` for everything this app installs
/// (record first, undo on failure); deb/rpm own the CLI, so only a leftover `cli.toml` goes. No
/// stable path (or any other layout error) does not mean nothing was installed: the link, the
/// wrapper and `cli.toml` sit at fixed paths, so `fallback` (the removal-only layout, when the
/// machine could be read at all) removes what is ours by content, and the step reports its own
/// outcome (a fixed word and the error kind) instead of failing `finish` after its record.
fn remove_cli(
    settings: &dyn SettingsAdmin,
    ops: &dyn PlatformOps,
    layout: Result<Layout, InstallError>,
    fallback: Option<Layout>,
) -> Result<CliStep, CommandError> {
    let layout = match layout {
        Ok(l) => l,
        Err(cause) => return Ok(remove_cli_without_layout(ops, &cause, fallback)),
    };
    if matches!(layout.kind, Kind::Packaged) {
        cli_install::uninstall(ops, &layout)?;
        return Ok(CliStep::done("already_on_path"));
    }
    cli_uninstall_dto(settings, ops, Ok(layout))?;
    Ok(CliStep::done("removed"))
}

/// No layout could be derived: remove by content what sits at fixed paths. Those removals are
/// covered by the choices record written before (as the deb/rpm `cli.toml` removal is).
fn remove_cli_without_layout(
    ops: &dyn PlatformOps,
    cause: &InstallError,
    fallback: Option<Layout>,
) -> CliStep {
    let not_removed = |reason: &InstallError| CliStep {
        cli: CLI_NOT_REMOVED,
        reason: Some(reason.kind()),
    };
    let Some(fallback) = fallback else {
        return not_removed(cause);
    };
    match cli_install::uninstall(ops, &fallback) {
        Err(e) => not_removed(&e),
        // Only `cli.toml` has a fixed path here (Windows): the PATH entry stays unknown.
        Ok(_) if matches!(fallback.kind, Kind::Packaged) => not_removed(cause),
        Ok(report) if report.changed.is_empty() => CliStep::done("not_found"),
        Ok(_) => CliStep::done("removed"),
    }
}

/// The CLI step's own outcome: a fixed word, and for `not_removed` the kind of what stopped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CliStep {
    cli: &'static str,
    reason: Option<&'static str>,
}

impl CliStep {
    fn done(cli: &'static str) -> CliStep {
        CliStep { cli, reason: None }
    }

    /// Every effect of the CLI step succeeded (nothing of ours is left).
    fn complete(&self) -> bool {
        self.cli != CLI_NOT_REMOVED
    }
}

/// `removal_finish`'s `cli` word when the CLI step could not remove what it could not name.
const CLI_NOT_REMOVED: &str = "not_removed";

/// Looks at the live instance list (not the checklist's) and puts every token found stored on the
/// checklist as "not deleted, not answered": `TokenStored`, nothing removed (`begin` deletes it
/// again). Called before the dialog (no pointless dialog) and after it (it can stay open for
/// minutes).
async fn recheck_tokens(
    state: &RemovalState,
    instances: &Arc<dyn InstanceAdmin>,
) -> Result<(), CommandError> {
    let views = {
        let admin = instances.clone();
        run_blocking(move || admin.list()).await?
    };
    let mut inner = state.lock();
    let procedure = inner
        .procedure
        .as_mut()
        .ok_or(CommandError::Removal(RemovalError::NoProcedure))?;
    if reconcile(procedure, &views, false) {
        return Err(CommandError::Removal(RemovalError::TokenStored));
    }
    Ok(())
}

/// `finish` (§12.5 steps 2 to 4): refused until every listed instance is ticked or skipped with
/// its token deleted, and while `held_off` (as for [`begin`]: the credential window open for a
/// token, the job slot held; again after the dialog); a token found stored again flips its item
/// back to "not deleted" and removes nothing. Then the native confirmation, one
/// `CONFIG_CHANGED {key: prepare_for_removal}` with the choices (once: a retry after a failed
/// effect does not repeat it), autostart, the CLI. Nothing here touches the KEK, the anchors or
/// the DB. A failed effect leaves the procedure in place for a retry.
#[allow(clippy::too_many_arguments)]
pub async fn finish(
    state: &RemovalState,
    instances: Arc<dyn InstanceAdmin>,
    settings: Arc<dyn SettingsAdmin>,
    confirmer: Arc<dyn NativeConfirmer>,
    autostart: Arc<dyn AutostartPort>,
    ops: Arc<dyn PlatformOps>,
    layout: Result<Layout, InstallError>,
    fallback: Option<Layout>,
    held_off: impl Fn() -> bool,
) -> Result<FinishAnswer, CommandError> {
    let _claim = state.claim()?;
    if held_off() {
        return Err(CommandError::Busy);
    }
    {
        let inner = state.lock();
        let procedure = inner
            .procedure
            .as_ref()
            .ok_or(CommandError::Removal(RemovalError::NoProcedure))?;
        if procedure
            .items
            .iter()
            .any(|i| !i.deleted || i.choice == Choice::Pending)
        {
            return Err(CommandError::Removal(RemovalError::Unticked));
        }
    }
    // A PAT entered since `begin` would stay valid and stored: look at every instance again before
    // the dialog, and again after it (the user may take minutes; `begin` and the credential window
    // are held off by the claim, but a submit already under way is not).
    recheck_tokens(state, &instances).await?;
    confirmed(&confirmer, finish_text()).await?;
    if held_off() {
        return Err(CommandError::Busy);
    }
    recheck_tokens(state, &instances).await?;
    let (items, recorded, backup_made) = {
        let inner = state.lock();
        let procedure = inner
            .procedure
            .as_ref()
            .ok_or(CommandError::Removal(RemovalError::NoProcedure))?;
        (
            procedure.items.clone(),
            procedure.recorded,
            inner.backup_made,
        )
    };
    if !recorded {
        // PD-176: product and token identity per instance too (bounded), so a restart before the
        // outcome record resumes the checklist as it is; no origin (the live table has it).
        let choices: Vec<Value> = items
            .iter()
            .map(|i| {
                json!({
                    "alias": i.alias,
                    "product": i.product,
                    "identity": i.identity.as_deref().map(bounded_identity),
                    "revoke": i.choice.recorded(),
                })
            })
            .collect();
        let admin = settings.clone();
        // Audit before effect: a record that cannot be written stops the call, nothing is removed.
        // It says `prepared: false`: the machine is prepared only once every effect succeeded, which
        // the record after the effects says (a failure without a corrective record stays "false").
        run_blocking(move || {
            admin.record_app_change(
                KEY_REMOVAL,
                json!({"prepared": false}),
                json!({"prepared": false, "backup": backup_made, "instances": choices}),
            )
        })
        .await??;
        if let Some(p) = state.lock().procedure.as_mut() {
            p.recorded = true;
        }
    }
    let removed_now = {
        let settings = settings.clone();
        run_blocking(move || remove_autostart(&*settings, &*autostart)).await??
    };
    // Kept on the procedure the moment it is done: a later step that fails leaves the procedure
    // for a retry, which finds autostart off and must still answer `removed` (M6 M-12).
    let autostart_removed = {
        let mut inner = state.lock();
        match inner.procedure.as_mut() {
            Some(p) => {
                p.autostart_removed |= removed_now;
                p.autostart_removed
            }
            None => removed_now,
        }
    };
    let cli = {
        let settings = settings.clone();
        run_blocking(move || remove_cli(&*settings, &*ops, layout, fallback)).await??
    };
    // Every effect is done (or the CLI step says what it could not do): the record that says so.
    // Its own failure cannot undo the effects; the log then keeps `prepared: false`, the safe side.
    let outcome = if cli.complete() {
        json!({"prepared": true, "cli": cli.cli})
    } else {
        json!({"prepared": false, "cli": cli.cli, "cli_reason": cli.reason})
    };
    let recorded_end = run_blocking(move || {
        settings.record_app_change(KEY_REMOVAL, json!({"prepared": false}), outcome)
    })
    .await?;
    if let Err(e) = recorded_end {
        tracing::warn!(
            event = LOG_EVENT_REMOVAL_FAILED,
            error_class = "settings",
            error_kind = e.to_string().as_str()
        );
    }
    // The procedure ended in this process: the log is not read back for it again (if the outcome
    // record failed, the next process resumes it from the choices record, PD-176, and its retry
    // finds every effect done).
    *state.lock() = Inner {
        hydrated: true,
        ..Inner::default()
    };
    Ok(FinishAnswer {
        cli: cli.cli,
        cli_reason: cli.reason,
        autostart: if autostart_removed {
            "removed"
        } else {
            "was_off"
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The §12.5 step text reaches the user through the page's own copy (`shared/strings.ts`); the
    /// Rust constant, that copy and the spec's sentence must be one string: each is read from its
    /// file, none is compared with itself.
    #[test]
    fn the_revoke_step_is_the_spec_sentence_and_the_pages_copy() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let read = |rel: &str| {
            std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
        };
        let spec = read("docs/superpowers/specs/2026-10-07-atlas-duck-design.md");
        assert!(
            spec.contains(&format!("\"{REVOKE_STEP}\"")),
            "the spec (12.5) differs"
        );
        let page = read("app/ui/src/shared/strings.ts");
        assert!(
            page.contains(&format!("'{REVOKE_STEP}'")),
            "the page's copy differs"
        );
    }

    #[test]
    fn the_dialogs_say_what_goes_and_what_stays() {
        let begin = begin_text(&[("a".into(), true), ("b".into(), true)]);
        assert!(begin.contains("a, b"), "{begin}");
        assert!(begin.contains("stays valid"), "{begin}");
        assert!(
            begin.contains("audit log, its keys and anchors are kept"),
            "{begin}"
        );
        let finish = finish_text();
        assert!(finish.contains("stop starting at login"), "{finish}");
        assert!(finish.contains("cli.toml"), "{finish}");
        assert!(
            finish.contains("audit log, its keys and anchors are kept"),
            "{finish}"
        );
    }

    #[test]
    fn errors_have_fixed_wire_kinds() {
        for (e, kind) in [
            (RemovalError::NoProcedure, "no_procedure"),
            (RemovalError::Unticked, "unticked"),
            (RemovalError::TokenStored, "token_stored"),
            (RemovalError::Autostart, "autostart"),
            (RemovalError::Recorded, "recorded"),
            (RemovalError::Running, "running"),
        ] {
            assert_eq!(e.to_string(), kind);
            assert_eq!(serde_json::to_value(e).ok(), Some(json!({ "kind": kind })));
        }
        assert_eq!(
            serde_json::to_value(Choice::Skipped).ok(),
            Some(json!("skipped"))
        );
    }

    fn at(ts: &str) -> UtcInstant {
        UtcInstant::parse_rfc3339_ms(ts).unwrap_or(UtcInstant(0))
    }

    /// §12.5 step 1, PD-176: the remaining retention is the newest record's, from its effective
    /// epoch: the setting less the record's age in days, never below 0. A record with no epoch
    /// (written while the clock was behind) or one dated after today keeps the whole setting.
    #[test]
    fn retention_from_newest_record() {
        let today = at("2026-10-19T12:00:00.000Z");
        let left = |epoch: Option<&str>| Retention::of(92, false, epoch, today).left_days;
        assert_eq!(left(Some("2026-10-19")), Some(92), "written today");
        assert_eq!(left(Some("2026-10-09")), Some(82), "ten days old");
        assert_eq!(left(Some("2026-07-19")), Some(0), "exactly the setting old");
        assert_eq!(left(Some("2025-01-01")), Some(0), "older than the setting");
        assert_eq!(left(None), Some(92), "no effective epoch yet");
        assert_eq!(left(Some("2026-10-25")), Some(92), "dated after today");
        assert_eq!(left(Some("not a date")), Some(92));
        let r = Retention::of(92, false, Some("2026-10-09"), today);
        assert_eq!((r.days, r.legal_hold), (92, false), "the setting is kept");
        // The page gets both: the setting and the newest record's remaining days.
        let dto = RemovalState::default().dto(r);
        assert_eq!(
            (dto.retention_days, dto.retention_left_days),
            (92, Some(82))
        );
    }

    /// PD-176: while a legal hold is on the newest record is kept indefinitely: no day count.
    #[test]
    fn legal_hold_shows_indefinite() {
        let today = at("2026-10-19T12:00:00.000Z");
        for epoch in [Some("2026-10-09"), None, Some("2020-01-01")] {
            let r = Retention::of(92, true, epoch, today);
            assert_eq!(r.left_days, None, "{epoch:?}");
            assert!(r.legal_hold);
        }
        let dto = RemovalState::default().dto(Retention::of(30, true, None, today));
        assert!(dto.legal_hold);
        assert_eq!(dto.retention_left_days, None);
        assert_eq!(
            serde_json::to_value(&dto)
                .ok()
                .map(|v| v["retention_left_days"].clone()),
            Some(Value::Null)
        );
    }

    /// A row of the instance table as the removal sees it.
    fn view(alias: &str, state: &'static str, identity: Option<&str>) -> InstanceView {
        InstanceView {
            alias: alias.into(),
            product: atlas_duck_core::Product::Jira,
            origin: Some(format!("https://{alias}.example")),
            state,
            executes_as: identity.map(str::to_owned),
            expires_at: None,
            pac_configured: false,
            proxy_effective: None,
            pending_url_change: None,
            note: None,
            expiry_warning: None,
            days_left: None,
        }
    }

    /// T28 m-1: the first `begin` deletes the token of *every* instance, not only of the ones the
    /// checklist lists: a table that lost an identity (or failed closed, every instance
    /// `instance_unconfirmed`) must not leave a keychain entry behind. `delete_token` is idempotent
    /// and logs nothing when nothing is stored.
    #[test]
    fn begin_covers_every_instance_with_a_token() {
        let views = [
            view("ok", "ok", Some("Alice")),
            view("lost", "instance_unconfirmed", None),
            view("plain", "insecure_scheme", None),
            view("waiting", "needs_token", None),
        ];
        let mut targets = begin_targets(None, &views);
        targets.sort();
        assert_eq!(targets, ["lost", "ok", "plain", "waiting"]);
        // The checklist still lists only what can have been given a PAT (or shows an identity).
        let mut p = Procedure::default();
        reconcile(&mut p, &views, true);
        let mut listed: Vec<&str> = p.items.iter().map(|i| i.alias.as_str()).collect();
        listed.sort_unstable();
        assert_eq!(listed, ["ok", "waiting"]);
    }

    /// A procedure whose choices are recorded (resumed after a restart, PD-176, or after a failed
    /// effect) that gains an instance (added or confirmed since) needs an answer for it, which
    /// `mark` refuses while the choices are recorded: the join reopens them, and `finish` records
    /// the choices again with the new instance.
    #[test]
    fn an_instance_joining_reopens_recorded_choices() {
        let mut p = Procedure {
            items: vec![Item {
                alias: "ok".into(),
                product: "jira",
                origin: None,
                identity: Some("Alice".into()),
                deleted: true,
                error: None,
                choice: Choice::Done,
            }],
            recorded: true,
            autostart_removed: false,
        };
        let old = [view("ok", "needs_token", None)];
        assert!(!reconcile(&mut p, &old, true));
        assert!(p.recorded, "the same instances: still recorded");
        let new = [
            view("ok", "needs_token", None),
            view("new", "needs_token", None),
        ];
        assert!(!reconcile(&mut p, &new, true), "no token was found");
        assert!(!p.recorded, "the new instance needs an answer");
    }

    /// T28 m-2: the begin dialog names every instance whose token is deleted, marks the ones with
    /// no identity on record, and says so in a sentence of its own; with no instance at all it
    /// does not claim a deletion. No identity (server text) is in the dialog.
    #[test]
    fn begin_dialog_names_unknown_identity() {
        let text = begin_text(&[("ok".into(), true), ("lost".into(), false)]);
        assert!(text.contains("ok, lost (identity unknown)"), "{text}");
        assert!(
            text.contains("\"identity unknown\" has no token identity on record"),
            "{text}"
        );
        assert!(text.contains("the next step lists it as well"), "{text}");
        assert!(text.contains("stays valid"), "{text}");
        assert!(!text.contains('\u{201C}'), "no quoted identity: {text}");
        let none = begin_text(&[]);
        assert!(none.contains("No instance is set up"), "{none}");
        assert!(!none.contains("deleted:"), "{none}");
        assert!(
            none.contains("audit log, its keys and anchors are kept"),
            "{none}"
        );
    }

    /// M10 T16 review M-10: the begin dialog names at most [`DIALOG_LIST_MAX`] instances and
    /// counts the rest; the "identity unknown" sentence stays when only an uncounted one is so.
    #[test]
    fn begin_dialog_is_bounded() {
        let alias = |i: usize| format!("{i:02}-{}", "a".repeat(60));
        let mut targets: Vec<(String, bool)> =
            (0..DIALOG_LIST_MAX + 5).map(|i| (alias(i), true)).collect();
        if let Some(last) = targets.last_mut() {
            last.1 = false;
        }
        let text = begin_text(&targets);
        assert!(text.contains(&alias(DIALOG_LIST_MAX - 1)), "{text}");
        assert!(!text.contains(&alias(DIALOG_LIST_MAX)), "{text}");
        assert!(text.contains(" and 5 more."), "{text}");
        assert!(text.contains("\"identity unknown\" has no token identity"));
        assert!(
            text.chars().count() < DIALOG_LIST_MAX * (MAX_ALIAS_CHARS + 20) + 1_000,
            "{} characters",
            text.chars().count()
        );
        let exactly = begin_text(&targets[..DIALOG_LIST_MAX]);
        assert!(!exactly.contains("more"), "{exactly}");
    }

    /// A `CONFIG_CHANGED {source: app}` as `SettingsAdmin::record_app_change` writes it.
    fn app_change(store: &Store, key: &str, old: Value, new: Value) -> Result<u64, AuditError> {
        Ok(store
            .append(atlas_duck_audit::NewEvent {
                event_type: EventType::CONFIG_CHANGED,
                request_id: None,
                op_id: None,
                op_class: None,
                instance_id: None,
                target: None,
                actor: atlas_duck_audit::Actor::default(),
                decision: None,
                flags: atlas_duck_audit::EventFlags::default(),
                payload: json!({"source": "app", "key": key, "old": old, "new": new,
                                "applied": true}),
            })?
            .seq)
    }

    fn choices(backup: bool) -> Value {
        json!({"prepared": false, "backup": backup, "instances": [
            {"alias": "jira-main", "product": "jira", "identity": "Alice Example", "revoke": "done"},
            {"alias": "wiki", "product": "confluence", "identity": null, "revoke": "skipped"},
        ]})
    }

    /// PD-176: the newest `prepare_for_removal` record decides. A choices record with no outcome
    /// after it is an open procedure (its answers, identities and backup flag); an outcome record
    /// ends it; other keys' records in between are passed over, except the newest `autostart`
    /// after the choices, which says whether an earlier `finish` removed the login item.
    #[test]
    fn read_log_finds_the_open_procedure() -> Result<(), Box<dyn std::error::Error>> {
        let r = crate::commands::audit::tests::rig(2)?;
        assert_eq!(read_log(&r.store)?, LogFacts::default(), "no record");
        app_change(
            &r.store,
            KEY_REMOVAL,
            json!({"prepared": false}),
            choices(true),
        )?;
        app_change(&r.store, "cli_install", json!({"a": 1}), json!({"a": 2}))?;
        let open = read_log(&r.store)?.open.ok_or("no open procedure")?;
        assert!(open.backup);
        assert!(!open.autostart_removed);
        assert_eq!(
            open.items,
            [
                RecordedItem {
                    alias: "jira-main".into(),
                    product: "jira",
                    identity: Some("Alice Example".into()),
                    choice: Choice::Done,
                },
                RecordedItem {
                    alias: "wiki".into(),
                    product: "confluence",
                    identity: None,
                    choice: Choice::Skipped,
                },
            ]
        );
        let (on, off) = (json!({"enabled": true}), json!({"enabled": false}));
        app_change(&r.store, KEY_AUTOSTART, on.clone(), off.clone())?;
        let open = read_log(&r.store)?.open.ok_or("no open procedure")?;
        assert!(open.autostart_removed, "removed after the choices");
        // Its undo (the disable failed) follows: not removed.
        app_change(&r.store, KEY_AUTOSTART, off.clone(), on.clone())?;
        let open = read_log(&r.store)?.open.ok_or("no open procedure")?;
        assert!(!open.autostart_removed, "undone");
        // The outcome record ends the procedure.
        app_change(
            &r.store,
            KEY_REMOVAL,
            json!({"prepared": false}),
            json!({"prepared": true, "cli": "removed"}),
        )?;
        assert_eq!(read_log(&r.store)?, LogFacts::default(), "ended");
        // An autostart record before a later procedure's choices is not that procedure's.
        app_change(&r.store, KEY_AUTOSTART, on, off)?;
        app_change(
            &r.store,
            KEY_REMOVAL,
            json!({"prepared": false}),
            choices(false),
        )?;
        let open = read_log(&r.store)?.open.ok_or("no open procedure")?;
        assert!(!open.autostart_removed);
        assert!(!open.backup);
        Ok(())
    }

    /// PD-176: a choices record this version cannot read whole (an unknown product or answer, an
    /// alias that is no alias, an overlong list) resumes nothing; an overlong identity is cut.
    #[test]
    fn read_log_resumes_only_a_well_formed_record() -> Result<(), Box<dyn std::error::Error>> {
        let r = crate::commands::audit::tests::rig(0)?;
        let one = |item: Value| json!({"prepared": false, "backup": false, "instances": [item]});
        for bad in [
            json!({"alias": "a", "product": "bitbucket", "identity": null, "revoke": "done"}),
            json!({"alias": "a", "product": "jira", "identity": null, "revoke": "pending"}),
            json!({"alias": "a b", "product": "jira", "identity": null, "revoke": "done"}),
            json!({"alias": "", "product": "jira", "identity": null, "revoke": "done"}),
            json!({"alias": "a", "product": "jira", "identity": 7, "revoke": "done"}),
            json!("a"),
        ] {
            app_change(
                &r.store,
                KEY_REMOVAL,
                json!({"prepared": false}),
                one(bad.clone()),
            )?;
            assert_eq!(read_log(&r.store)?, LogFacts::default(), "{bad}");
        }
        let many: Vec<Value> = (0..=MAX_RECORDED_ITEMS)
            .map(|i| {
                json!({"alias": format!("a{i}"), "product": "jira", "identity": null,
                            "revoke": "done"})
            })
            .collect();
        app_change(
            &r.store,
            KEY_REMOVAL,
            json!({"prepared": false}),
            json!({"prepared": false, "backup": false, "instances": many}),
        )?;
        assert_eq!(read_log(&r.store)?, LogFacts::default(), "too many");
        let long = "x".repeat(MAX_RECORDED_IDENTITY_CHARS + 50);
        app_change(
            &r.store,
            KEY_REMOVAL,
            json!({"prepared": false}),
            one(json!({"alias": "a", "product": "jira", "identity": long, "revoke": "done"})),
        )?;
        let open = read_log(&r.store)?.open.ok_or("no open procedure")?;
        let shown = open.items[0].identity.clone().unwrap_or_default();
        assert_eq!(
            shown.chars().count(),
            MAX_RECORDED_IDENTITY_CHARS,
            "{shown}"
        );
        Ok(())
    }

    /// PD-176: the resumed procedure is recorded, its items deleted with their answers and
    /// identities, their origins from the live table (none for an instance gone since); a process
    /// that holds a procedure of its own keeps it; the log is read once.
    #[test]
    fn hydrate_resumes_the_recorded_procedure() {
        let facts = LogFacts {
            open: Some(OpenProcedure {
                backup: true,
                autostart_removed: true,
                items: vec![
                    RecordedItem {
                        alias: "ok".into(),
                        product: "jira",
                        identity: Some("Alice".into()),
                        choice: Choice::Done,
                    },
                    RecordedItem {
                        alias: "gone".into(),
                        product: "confluence",
                        identity: None,
                        choice: Choice::Skipped,
                    },
                ],
            }),
        };
        let views = [view("ok", "needs_token", None)];
        let st = RemovalState::default();
        assert!(st.needs_log());
        st.hydrate(facts.clone(), &views);
        assert!(!st.needs_log());
        let ret = Retention::of(92, false, None, UtcInstant(0));
        let dto = st.dto(ret);
        assert!(dto.active && dto.recorded && dto.backup_made);
        assert_eq!(
            dto.instances,
            [
                ItemDto {
                    alias: "ok".into(),
                    product: "jira",
                    origin: Some("https://ok.example".into()),
                    identity: Some("Alice".into()),
                    token_deleted: true,
                    error: None,
                    choice: Choice::Done,
                },
                ItemDto {
                    alias: "gone".into(),
                    product: "confluence",
                    origin: None,
                    identity: None,
                    token_deleted: true,
                    error: None,
                    choice: Choice::Skipped,
                },
            ]
        );
        // A backup made in this process before the log was read (Audit window) is kept.
        let backed_up = RemovalState::default();
        backed_up.lock().backup_made = true;
        let mut unbacked = facts.clone();
        if let Some(open) = unbacked.open.as_mut() {
            open.backup = false;
        }
        backed_up.hydrate(unbacked, &views);
        assert!(backed_up.dto(ret).backup_made);
        // A procedure begun in this process is not replaced by the log's.
        let own = RemovalState::default();
        own.lock().procedure = Some(Procedure::default());
        own.hydrate(facts, &views);
        assert!(own.dto(ret).instances.is_empty());
        assert!(!own.dto(ret).recorded);
    }

    /// M10 T16 review I-3: a token stored since the choices record (entered after the failed
    /// effect) is taken from the live table, not from the record: that item is "not deleted, not
    /// answered" with the identity shown now, and the choices are open again; the others keep
    /// their recorded answers.
    #[test]
    fn hydrate_takes_a_token_stored_since_from_the_live_table() {
        let facts = LogFacts {
            open: Some(OpenProcedure {
                backup: false,
                autostart_removed: false,
                items: vec![
                    RecordedItem {
                        alias: "ok".into(),
                        product: "jira",
                        identity: Some("Alice".into()),
                        choice: Choice::Done,
                    },
                    RecordedItem {
                        alias: "wiki".into(),
                        product: "confluence",
                        identity: None,
                        choice: Choice::Skipped,
                    },
                ],
            }),
        };
        let views = [
            view("ok", "ok", Some("Bob")),
            view("wiki", "needs_token", None),
        ];
        let st = RemovalState::default();
        st.hydrate(facts, &views);
        let dto = st.dto(Retention::of(92, false, None, UtcInstant(0)));
        assert!(dto.active && !dto.recorded, "{dto:?}");
        let shown: Vec<(&str, bool, Choice, Option<&str>)> = dto
            .instances
            .iter()
            .map(|i| {
                (
                    i.alias.as_str(),
                    i.token_deleted,
                    i.choice,
                    i.identity.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            shown,
            [
                ("ok", false, Choice::Pending, Some("Bob")),
                ("wiki", true, Choice::Skipped, None),
            ]
        );
    }

    /// M10 T16 review M-1, the command layer's reading of the log: a closed store is `not_ready`
    /// and the log is read again by the next call; any other read error resumes nothing, and the
    /// log is not read again in this process; a readable log resumes its procedure.
    #[test]
    fn hydrate_from_reads_the_log_once_unless_the_store_is_closed() {
        let views = [view("ok", "needs_token", None)];
        let st = RemovalState::default();
        assert_eq!(
            st.hydrate_from(Err(AuditError::Closed), &views),
            Err(CommandError::NotReady)
        );
        assert!(st.needs_log(), "read again by the next call");
        assert_eq!(
            st.hydrate_from(Err(AuditError::Invalid("unreadable")), &views),
            Ok(())
        );
        assert!(!st.needs_log(), "not read again");
        assert!(!st.dto(Retention::of(92, false, None, UtcInstant(0))).active);
        let open = LogFacts {
            open: Some(OpenProcedure {
                backup: false,
                autostart_removed: false,
                items: vec![RecordedItem {
                    alias: "ok".into(),
                    product: "jira",
                    identity: None,
                    choice: Choice::Skipped,
                }],
            }),
        };
        let fresh = RemovalState::default();
        assert_eq!(fresh.hydrate_from(Ok(open), &views), Ok(()));
        assert!(
            fresh
                .dto(Retention::of(92, false, None, UtcInstant(0)))
                .active
        );
    }

    /// PD-176, M10 T16 review M-1: past the scan's cap of decrypted `CONFIG_CHANGED` payloads the
    /// log is taken to hold no open procedure; within it the procedure is found. A store that is
    /// closed is an error for the caller.
    #[test]
    fn read_log_stops_at_its_cap() -> Result<(), Box<dyn std::error::Error>> {
        let r = crate::commands::audit::tests::rig(0)?;
        app_change(
            &r.store,
            KEY_REMOVAL,
            json!({"prepared": false}),
            choices(false),
        )?;
        for i in 0..3 {
            app_change(
                &r.store,
                "cli_install",
                json!({"a": i}),
                json!({"a": i + 1}),
            )?;
        }
        assert!(
            read_log_capped(&r.store, 4)?.open.is_some(),
            "the 4th is it"
        );
        assert_eq!(read_log_capped(&r.store, 3)?, LogFacts::default());
        assert!(read_log(&r.store)?.open.is_some());
        r.store.shutdown();
        assert!(matches!(read_log(&r.store), Err(AuditError::Closed)));
        Ok(())
    }

    /// M10 T16 review M-6: a choices record older than a `RESTORE` came in with the restored
    /// backup (another machine's procedure, or one the rollback took back) and is not resumed; a
    /// procedure begun after the restore is.
    #[test]
    fn read_log_resumes_nothing_from_before_a_restore() -> Result<(), Box<dyn std::error::Error>> {
        use crate::commands::audit::tests::{Answers, Events, PASS, chosen, count};
        let r = crate::commands::audit::tests::rig(0)?;
        app_change(
            &r.store,
            KEY_REMOVAL,
            json!({"prepared": false}),
            choices(true),
        )?;
        let bundle = r.store.backup(chosen(&r.out))?.bundle_dir;
        // The restore, then the rollback of the `BACKUP` record that followed the snapshot.
        crate::restore_flow::run_live_restore(
            &r.store,
            &Answers::new(&[Confirm::Ok, Confirm::Ok]),
            || Some(chosen(&bundle)),
            |_| Ok(secrecy::SecretString::from(PASS.to_owned())),
            &crate::serve::StoreCall::default(),
            &AtomicBool::new(false),
            &Events::default(),
        )?;
        assert_eq!(count(&r.store, EventType::RESTORE)?, 1, "premise");
        assert_eq!(read_log(&r.store)?, LogFacts::default());
        app_change(
            &r.store,
            KEY_REMOVAL,
            json!({"prepared": false}),
            choices(false),
        )?;
        let open = read_log(&r.store)?.open.ok_or("no open procedure")?;
        assert!(!open.backup, "the newer record");
        Ok(())
    }

    /// M10 T16 review M-9: a choices record that names an instance twice is not one `finish`
    /// wrote: nothing is resumed.
    #[test]
    fn read_log_refuses_a_record_with_an_alias_twice() -> Result<(), Box<dyn std::error::Error>> {
        let r = crate::commands::audit::tests::rig(0)?;
        let item = json!({"alias": "a", "product": "jira", "identity": null, "revoke": "done"});
        app_change(
            &r.store,
            KEY_REMOVAL,
            json!({"prepared": false}),
            json!({"prepared": false, "backup": false, "instances": [item.clone(), item]}),
        )?;
        assert_eq!(read_log(&r.store)?, LogFacts::default());
        Ok(())
    }

    /// §12.5 step 1, PD-176, M10 T16 review M-2: the remaining retention is counted from the log's
    /// head (the newest record), not from an older one; a head that cannot be read shows the
    /// setting itself (display only, the call goes on), and nothing under a legal hold.
    #[test]
    fn retention_reads_the_newest_record() -> Result<(), Box<dyn std::error::Error>> {
        use std::time::{Duration, Instant, SystemTime};
        let start = at("2026-10-01T12:00:00.000Z");
        let (_tmp, _lock, clock, store) = fake_clock_store(start)?;
        let observe = |clock: &atlas_duck_audit::testing::FakeClock| {
            let now = atlas_duck_audit::Clock::now_utc(clock);
            let ms = u64::try_from(now.0).unwrap_or(0);
            store.observe_server_date(
                "jira-main",
                SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
                Instant::now(),
            );
        };
        // The oldest records (GENESIS) have no epoch: no date was corroborated yet.
        observe(&clock);
        app_change(&store, "cli_install", json!({"a": 1}), json!({"a": 2}))?;
        clock.advance(Duration::from_secs(10 * 86_400));
        observe(&clock);
        app_change(&store, "cli_install", json!({"a": 2}), json!({"a": 3}))?;
        assert_eq!(newest_epoch(&store)?.as_deref(), Some("2026-10-11"));
        let today = at("2026-10-21T12:00:00.000Z");
        assert_eq!(
            retention_shown(92, false, newest_epoch(&store), today).left_days,
            Some(82)
        );
        let unreadable = retention_shown(92, false, Err(AuditError::Closed), today);
        assert_eq!((unreadable.days, unreadable.left_days), (92, Some(92)));
        assert_eq!(
            retention_shown(92, true, Err(AuditError::Closed), today).left_days,
            None
        );
        store.shutdown();
        Ok(())
    }

    /// A new store over a [`atlas_duck_audit::testing::FakeClock`] standing at `start`.
    #[allow(clippy::type_complexity)]
    fn fake_clock_store(
        start: UtcInstant,
    ) -> Result<
        (
            tempfile::TempDir,
            atlas_duck_audit::lock::InstanceLock,
            Arc<atlas_duck_audit::testing::FakeClock>,
            Store,
        ),
        Box<dyn std::error::Error>,
    > {
        use atlas_duck_audit::testing::{FakeClock, FreeSpaceStub, MemKeyStore, MemKeyring};
        use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("data");
        std::fs::create_dir(&dir)?;
        let DataDirResolution::Local(data) = check_data_dir(&dir)? else {
            return Err("the temp dir is not a local data dir".into());
        };
        let lock = atlas_duck_audit::lock::InstanceLock::acquire(&data, "thishost")?;
        let (install_id, chain_id) = atlas_duck_audit::new_ids()?;
        let clock = Arc::new(FakeClock::new(start));
        let keys = Arc::new(MemKeyStore::new(MemKeyring::new(), &install_id));
        let mut cfg = atlas_duck_audit::OpenConfig::new(clock.clone(), keys);
        cfg.free_space = Some(FreeSpaceStub::new(u64::MAX));
        let pass = crate::commands::audit::tests::PASS;
        let store = atlas_duck_audit::create_new_store(
            &data,
            &lock,
            cfg,
            atlas_duck_audit::FirstRunInput {
                install_id,
                chain_id,
                passphrase: secrecy::SecretString::from(pass.to_owned()),
                passphrase_confirm: secrecy::SecretString::from(pass.to_owned()),
                archived_db: None,
                anchor_dir: None,
                archive_confirmed: None,
            },
        )?;
        Ok((tmp, lock, clock, store))
    }

    /// §12.5 step 1 (PD-176): "Prepare for removal" offers the compliance export: the Audit
    /// window's flow (the PD-161 warning, then Rust's folder dialog) over the full range, every
    /// record up to the head, logged by one `EXPORT`.
    #[test]
    fn removal_offers_export() -> Result<(), Box<dyn std::error::Error>> {
        use crate::commands::audit::tests::{Answers, Events, chosen, count, entries, rig};
        let r = rig(4)?;
        let confirmer = Answers::new(&[Confirm::Ok]);
        let events = Events::default();
        let done = export(
            &r.store,
            &confirmer,
            || Some(chosen(&r.out)),
            &AtomicBool::new(false),
            &events,
        )?;
        assert_eq!(
            confirmer.texts(),
            [crate::commands::audit::EXPORT_WARNING_TEXT]
        );
        let (head, _, _) = r.store.head();
        assert_eq!(done.rows + 1, head, "every record before the EXPORT");
        assert_eq!(entries(&r.out), std::slice::from_ref(&done.dir_name));
        assert_eq!(count(&r.store, EventType::EXPORT)?, 1);
        assert_eq!(
            events.phases().last().map(String::as_str),
            Some("done"),
            "{:?}",
            events.all()
        );
        // The warning cancelled: no folder dialog, nothing written, nothing logged.
        let asked = AtomicBool::new(false);
        let res = export(
            &r.store,
            &Answers::new(&[Confirm::Cancel]),
            || {
                asked.store(true, Ordering::SeqCst);
                Some(chosen(&r.out))
            },
            &AtomicBool::new(false),
            &Events::default(),
        );
        assert_eq!(res, Err(CommandError::Cancelled));
        assert!(!asked.load(Ordering::SeqCst), "the folder dialog opened");
        assert_eq!(count(&r.store, EventType::EXPORT)?, 1);
        Ok(())
    }
}
