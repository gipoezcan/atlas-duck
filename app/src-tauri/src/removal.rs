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
//! The checklist lives in memory (one procedure per process; a second concurrent call is `busy`).
//! It is resumable by idempotence, not by a progress file: after a restart, `begin` again deletes
//! only what is still stored and logs nothing for what is gone, and the checklist lists *every*
//! confirmed instance, so a token deleted before the restart is still offered for revocation
//! (its identity is no longer known: `delete_token` clears it, so the page says so).
//!
//! Core decides, the page asks: nothing here takes a path, an origin or a token from a webview.
//! Every dialog is drawn by Rust through the injected [`NativeConfirmer`] on the blocking pool.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use atlas_duck_core::config::instances::product_str;
use atlas_duck_core::{
    AdminError, Confirm, InstanceAdmin, InstanceView, NativeConfirmer, SettingsAdmin, SettingsError,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli_install::{self, InstallError, Kind, Layout, PlatformOps};
use crate::commands::CommandError;
use crate::commands::settings::cli_uninstall_dto;

/// §12.5 step 2 (verbatim): shown per instance with its alias and token identity.
pub const REVOKE_STEP: &str =
    "Revoke this token in Jira/Confluence (Profile → Personal Access Tokens)";

/// The `CONFIG_CHANGED {source: app}` key of the procedure's one record (§12.5).
pub const KEY_REMOVAL: &str = "prepare_for_removal";
/// The `CONFIG_CHANGED {source: app}` key of the autostart removal (audit before effect).
pub const KEY_AUTOSTART: &str = "autostart";

/// Log event of a refused or failed removal call (kind only).
pub const LOG_EVENT_REMOVAL_FAILED: &str = "removal_failed";

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
}

impl RemovalError {
    pub fn kind(self) -> &'static str {
        match self {
            Self::NoProcedure => "no_procedure",
            Self::Unticked => "unticked",
            Self::TokenStored => "token_stored",
            Self::Autostart => "autostart",
            Self::Recorded => "recorded",
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

/// The retention facts the page shows beside the backup offer (§12.5 step 1). The newest record is
/// the one written at this moment, so its remaining retention is the setting itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    pub days: u32,
    pub legal_hold: bool,
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
    /// `begin` ran in this process and `finish` has not completed.
    pub active: bool,
    /// A full backup was made in this procedure.
    pub backup_made: bool,
    pub retention_days: u32,
    pub legal_hold: bool,
    pub instances: Vec<ItemDto>,
}

/// `removal_backup`'s answer: `saved: false` is a cancelled file dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BackupAnswer {
    pub saved: bool,
}

/// `removal_finish`'s answer: what was removed, as fixed words the page maps to its own text.
/// `cli`: `removed`, `already_on_path` (deb/rpm: the package owns the CLI) or `nothing` (no stable
/// path: nothing of the CLI was ever installed from here). `autostart`: `removed` or `was_off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FinishAnswer {
    pub cli: &'static str,
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
}

#[derive(Debug, Default)]
struct Inner {
    backup_made: bool,
    procedure: Option<Procedure>,
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
            Err(CommandError::Busy)
        } else {
            Ok(Claim(&self.busy))
        }
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
            backup_made: inner.backup_made,
            retention_days: retention.days,
            legal_hold: retention.legal_hold,
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

/// §12.5: what `begin` asks. Aliases are Rust-validated names (`A-Za-z0-9._-`), no server text.
pub fn begin_text(aliases: &[String]) -> String {
    let list = if aliases.is_empty() {
        "none".to_owned()
    } else {
        aliases.join(", ")
    };
    format!(
        "Prepare atlas-duck for removal?\n\n\
         The stored tokens of these instances will be deleted: {list}. A deleted token stays valid \
         on the Jira/Confluence server until you revoke it there; the next step lists each one.\n\n\
         The audit log, its keys and anchors are kept, so the log stays verifiable until its \
         retention period has passed."
    )
}

/// §12.5 step 3: what `finish` asks.
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

/// `begin` (§12.5 step 2): refuses while the credential window is open for a token (a submit in
/// flight could store one after the delete; T20 m-9); confirms natively; deletes the stored
/// tokens. A second `begin` deletes only what is still stored (a failed delete, or a token entered
/// since) and shows the same dialog again. `ShuttingDown` ends the call at once.
pub async fn begin(
    state: &RemovalState,
    instances: Arc<dyn InstanceAdmin>,
    confirmer: Arc<dyn NativeConfirmer>,
    pat_window_open: impl Fn() -> bool,
    retention: Retention,
) -> Result<RemovalDto, CommandError> {
    let _claim = state.claim()?;
    if pat_window_open() {
        return Err(CommandError::Busy);
    }
    let views = {
        let admin = instances.clone();
        run_blocking(move || admin.list()).await?
    };
    let first_run = state.lock().procedure.is_none();
    // `delete_token` is called for every listed instance on a first run, not only for those the
    // table says hold a token: it is idempotent and logs nothing when nothing is stored, and a
    // keychain entry must not outlive the delete because the table lost the identity. Afterwards a
    // run retries only what is not deleted.
    let targets: Vec<String> = if first_run {
        views
            .iter()
            .filter(|v| listed(v))
            .map(|v| v.alias.clone())
            .collect()
    } else {
        state
            .lock()
            .procedure
            .as_ref()
            .map(|p| {
                p.items
                    .iter()
                    .filter(|i| !i.deleted)
                    .map(|i| i.alias.clone())
                    .collect()
            })
            .unwrap_or_default()
    };
    if !first_run && targets.is_empty() {
        return Ok(state.dto(retention));
    }
    // The dialog names what is actually stored.
    let stored: Vec<String> = views
        .iter()
        .filter(|v| targets.contains(&v.alias) && token_stored(v))
        .map(|v| v.alias.clone())
        .collect();
    confirmed(&confirmer, begin_text(&stored)).await?;
    if first_run {
        let items = views
            .iter()
            .filter(|v| listed(v))
            .map(|v| Item {
                alias: v.alias.clone(),
                product: product_str(v.product),
                origin: v.origin.clone(),
                identity: v.executes_as.clone(),
                deleted: false,
                error: None,
                choice: Choice::Pending,
            })
            .collect();
        state.lock().procedure = Some(Procedure {
            items,
            recorded: false,
        });
    }
    for alias in targets {
        let result = instances.delete_token(&alias).await;
        let mut inner = state.lock();
        let Some(item) = inner
            .procedure
            .as_mut()
            .and_then(|p| p.items.iter_mut().find(|i| i.alias == alias))
        else {
            continue;
        };
        match result {
            // Core answered without an error: no token is stored for the instance now.
            Ok(_) => {
                item.deleted = true;
                item.error = None;
            }
            Err(AdminError::ShuttingDown) => {
                return Err(CommandError::Admin(AdminError::ShuttingDown));
            }
            Err(e) => item.error = Some(e.to_string()),
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
/// stable path means no CLI was ever installed from this run: nothing to remove.
fn remove_cli(
    settings: &dyn SettingsAdmin,
    ops: &dyn PlatformOps,
    layout: Result<Layout, InstallError>,
) -> Result<&'static str, CommandError> {
    let layout = match layout {
        Ok(l) => l,
        Err(InstallError::NoStablePath) => return Ok("nothing"),
        Err(e) => return Err(CommandError::CliInstall(e)),
    };
    if matches!(layout.kind, Kind::Packaged) {
        cli_install::uninstall(ops, &layout)?;
        return Ok("already_on_path");
    }
    cli_uninstall_dto(settings, ops, Ok(layout))?;
    Ok("removed")
}

/// `finish` (§12.5 steps 2 to 4): refused until every listed instance is ticked or skipped with
/// its token deleted, and while the credential window is open; a token found stored again flips
/// its item back to "not deleted" and removes nothing. Then the native confirmation, one
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
    pat_window_open: impl Fn() -> bool,
) -> Result<FinishAnswer, CommandError> {
    let _claim = state.claim()?;
    if pat_window_open() {
        return Err(CommandError::Busy);
    }
    let items = {
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
        procedure.items.clone()
    };
    // A PAT entered since `begin` would stay valid and stored: look again before removing anything.
    let views = {
        let admin = instances.clone();
        run_blocking(move || admin.list()).await?
    };
    let stored: Vec<&str> = items
        .iter()
        .filter(|i| views.iter().any(|v| v.alias == i.alias && token_stored(v)))
        .map(|i| i.alias.as_str())
        .collect();
    if !stored.is_empty() {
        let mut inner = state.lock();
        if let Some(p) = inner.procedure.as_mut() {
            for item in p
                .items
                .iter_mut()
                .filter(|i| stored.contains(&i.alias.as_str()))
            {
                // A new token is a new thing to revoke: the earlier tick is stale.
                item.deleted = false;
                item.error = None;
                item.choice = Choice::Pending;
                item.identity = views
                    .iter()
                    .find(|v| v.alias == item.alias)
                    .and_then(|v| v.executes_as.clone());
            }
            // The choices recorded earlier (if any) no longer describe the procedure.
            p.recorded = false;
        }
        return Err(CommandError::Removal(RemovalError::TokenStored));
    }
    confirmed(&confirmer, finish_text()).await?;
    let (recorded, backup_made) = {
        let inner = state.lock();
        (
            inner.procedure.as_ref().is_some_and(|p| p.recorded),
            inner.backup_made,
        )
    };
    if !recorded {
        let choices: Vec<Value> = items
            .iter()
            .map(|i| json!({"alias": i.alias, "revoke": i.choice.recorded()}))
            .collect();
        let admin = settings.clone();
        // Audit before effect: a record that cannot be written stops the call, nothing is removed.
        run_blocking(move || {
            admin.record_app_change(
                KEY_REMOVAL,
                json!({"prepared": false}),
                json!({"prepared": true, "backup": backup_made, "instances": choices}),
            )
        })
        .await??;
        if let Some(p) = state.lock().procedure.as_mut() {
            p.recorded = true;
        }
    }
    let answer = run_blocking(move || -> Result<FinishAnswer, CommandError> {
        let removed = remove_autostart(&*settings, &*autostart)?;
        let cli = remove_cli(&*settings, &*ops, layout)?;
        Ok(FinishAnswer {
            cli,
            autostart: if removed { "removed" } else { "was_off" },
        })
    })
    .await??;
    *state.lock() = Inner::default();
    Ok(answer)
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
        let begin = begin_text(&["a".into(), "b".into()]);
        assert!(begin.contains("a, b"), "{begin}");
        assert!(begin.contains("stays valid"), "{begin}");
        assert!(
            begin.contains("audit log, its keys and anchors are kept"),
            "{begin}"
        );
        assert!(begin_text(&[]).contains("none"));
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
        ] {
            assert_eq!(e.to_string(), kind);
            assert_eq!(serde_json::to_value(e).ok(), Some(json!({ "kind": kind })));
        }
        assert_eq!(
            serde_json::to_value(Choice::Skipped).ok(),
            Some(json!("skipped"))
        );
    }
}
