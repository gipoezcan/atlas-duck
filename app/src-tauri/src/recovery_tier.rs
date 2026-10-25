//! The recovery tier and the anchor directory from Settings (M10 T14; §8.5, §8.6, §8.7, §10.3;
//! PD-166, PD-169, PD-170; L116, L134 T20 m-9).
//!
//! Every change here is security-relevant and asks Rust's native confirmation before it is made
//! (L54), built only from facts Rust read itself (the store's settings and health, the keychain,
//! the archived stores' names, the folder Rust's own dialog returned), every one display-escaped;
//! nothing a webview sent reaches a dialog text but an install id that must be on the current
//! orphan list. The facts a text named are read again after its dialog: a text that no longer
//! holds changes nothing. The proof of each answer is `serve::confirmed_by` on its Ok path
//! (`ci/check-dialog-proofs.mjs`).
//!
//! - [`set_anchor_dir`] / [`remove_anchor_dir`]: (set) Rust's folder dialog first (`pick`; no
//!   §7.7 local-filesystem check: an anchor directory is meant to be a share, §8.5), then the
//!   confirmation, which names the folder chosen (T14 review I-1: the proof the store records
//!   names what it records), then `Store::change_anchor_dir`, whose first step opens the new
//!   directory's chain file for append or creates it (PD-166): that is the writability check, it
//!   deletes and renames nothing, so an append-only (WORM) share passes. The store logs
//!   `CONFIG_CHANGED {key: anchor_dir}` with the dialog's hash and writes `ANCHOR_DETACHED` to
//!   the old directory.
//! - [`re_anchor`]: offered only while `core::settings::re_anchor_offered` holds (a keychain
//!   anchor entry is missing and no barrier holds the anchors); the confirmation says it is an
//!   integrity incident; then `Store::re_anchor`.
//! - [`orphans`] / [`forget`]: the installs only an archived store names, with the keychain
//!   entries they still have (listing reads those entries: on macOS an item an older or
//!   re-signed build wrote may raise a keychain prompt, T9 review M-7). "Forget" acts only on an
//!   install of a fresh list; its confirmation names the entries; a second native dialog asks
//!   about the archived log's keys (Cancel keeps them). `CONFIG_CHANGED {source: app, key:
//!   forget_install}` is recorded before anything is deleted (audit before effect), and a second
//!   record says what was and was not deleted when the keychain stops it (T9 rulings 3, M-1).
//!
//! Each flow runs on a blocking thread (dialogs block), one at a time and never beside an audit
//! job or an open credential window (the serving state's job slot, T14 review I-2;
//! `commands::settings`); `stop` is the quit path's freeze: a dialog answered after it changes
//! nothing.

use std::path::Path;

use atlas_duck_audit::anchor_dir::{file_name, same_dir};
use atlas_duck_audit::types::RustChosenPath;
use atlas_duck_audit::{AuditError, KeyStore, MissingAnchor, OrphanInstall, Store};
use atlas_duck_core::settings::re_anchor_offered;
use atlas_duck_core::{Confirm, NativeConfirmer, SettingsError};
use atlas_duck_ipc::paths::LocalDataDir;
use atlas_duck_preview::invisible::escape_for_display;
use serde::Serialize;
use serde_json::{Value, json};

use crate::commands::{AnchorDirFailure, CommandError, ForgetFailure, ReAnchorFailure};
use crate::ui_sink::{EVENT_SETTINGS_CHANGED, EventOut, emit_audit_changed, emit_status_changed};

/// plan text (T14): the title of Rust's folder dialog for the anchor directory.
pub const ANCHOR_DIR_DIALOG_TITLE: &str =
    "Choose the anchor directory for the atlas-duck audit log";

/// `CONFIG_CHANGED.key` of "Forget old install" (PD-170).
pub const KEY_FORGET_INSTALL: &str = "forget_install";

/// At most this many entries or files are named in a dialog; the rest are counted ("and N more").
/// The record names all.
pub const DIALOG_LIST_MAX: usize = 20;

/// At most this many characters of one listed item are shown (then "…"; T14 review M-4: an
/// instance id may be 256 bytes, and escaped up to ten times as long). The record keeps it whole.
pub const DIALOG_ITEM_MAX: usize = 120;

/// The keychain entries of an archived log's keys (the second dialog, PD-170), as account names.
const KEY_ACCOUNTS: [&str; 3] = ["kek", "head_anchor", "first_retained_anchor"];

/// `anchor_dir_set` / `anchor_dir_remove`'s answer: the anchor directory in force now (display
/// text; `null` when none).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorDirDto {
    pub anchor_dir: Option<String>,
}

/// `re_anchor`'s answer: the `VERIFY {result: re_anchored}` incident it recorded (acknowledged in
/// the Audit window like any other).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ReAnchoredDto {
    pub verify_seq: u64,
}

/// One row of `orphan_installs`: an install only archived stores name, the archived files that
/// name it (`archived/<name>`, relative to the data dir) and its keychain entries left (account
/// names: `kek`, `head_anchor`, `first_retained_anchor`, `canary`, `pat/<instance_id>`). Every
/// string display-escaped (an instance id comes from an archived store's plaintext column).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrphanInstallDto {
    pub install_id: String,
    pub archived_files: Vec<String>,
    pub entries: Vec<String>,
}

/// `forget_install`'s answer: the account names deleted, in order, and whether the archived log's
/// keys went too (the second dialog).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForgottenDto {
    pub install_id: String,
    pub deleted: Vec<String>,
    pub keys_deleted: bool,
}

/// `items` for a dialog: the first [`DIALOG_LIST_MAX`], each cut to [`DIALOG_ITEM_MAX`]
/// characters, comma-separated, then "and N more".
fn listed(items: &[String]) -> String {
    let shown: Vec<String> = items
        .iter()
        .take(DIALOG_LIST_MAX)
        .map(|item| {
            if item.chars().count() > DIALOG_ITEM_MAX {
                let mut cut: String = item.chars().take(DIALOG_ITEM_MAX).collect();
                cut.push('…');
                cut
            } else {
                item.clone()
            }
        })
        .collect();
    let mut s = shown.join(", ");
    if items.len() > DIALOG_LIST_MAX {
        s.push_str(&format!(" and {} more", items.len() - DIALOG_LIST_MAX));
    }
    s
}

/// plan text (T14, PD-166, §8.5; T14 review I-1): the native confirmation of "Change anchor
/// directory…", after Rust's folder dialog, so it names what the store records: `chosen` (the
/// folder picked), `current` (the directory in force, which gets the detached line; `None`: no
/// directory is set) and `chain_file` (the chain's `<chain_id>.jsonl`), all display-escaped by
/// the caller. True whether the file is already in the folder or not (PD-166's two branches).
pub fn anchor_dir_set_text(chosen: &str, current: Option<&str>, chain_file: &str) -> String {
    let files = format!(
        "atlas-duck adds the file {chain_file} to that folder, or appends lines to it if it is \
         already there, and never deletes or rewrites anything in the folder (a network share is \
         fine)"
    );
    match current {
        Some(dir) => format!(
            "Change the anchor directory of the audit log to {chosen}? It is now {dir}; that \
             directory gets a last line that marks it detached, and its lines stay as they are. \
             {files}."
        ),
        None => format!(
            "Set {chosen} as the anchor directory of the audit log? No anchor directory is set \
             now. {files}, so a copy of the log's anchors is kept outside this computer's \
             keychain."
        ),
    }
}

/// plan text (T14, PD-166, §8.5): the native confirmation of "Remove anchor directory".
pub fn anchor_dir_remove_text(current: &str) -> String {
    format!(
        "Remove the anchor directory {current}? From now on the audit log is anchored in this \
         computer's keychain only, with no copy of its anchors outside it. The directory gets a \
         last line that marks it detached; nothing in it is deleted."
    )
}

/// plan text (T14, PD-170, §8.7): the native confirmation of "Re-anchor", naming the missing
/// entry and saying it is an incident; truthful about a rollback (T9 review I-2(a): with no anchor
/// directory, a rolled-back log whose anchors were deleted is re-anchored too) and about the
/// effect (T14 review M-1: `Store::re_anchor` writes both anchors, PD-170).
pub fn re_anchor_text(missing: MissingAnchor) -> String {
    let which = match missing {
        MissingAnchor::Head => "the head anchor of the audit log",
        MissingAnchor::FirstRetained => "the first-retained anchor of the audit log",
        MissingAnchor::Both => "both anchors of the audit log",
    };
    format!(
        "Re-anchor the audit log? This computer's keychain no longer holds {which}. The whole log \
         is verified first, and only if it verifies are both anchors written again from it. This \
         is recorded as an integrity incident (re_anchored) that needs an \
         acknowledgement in the Audit window. A log that was rolled back or edited while its \
         anchors were missing also verifies, unless an anchor directory holds its lines: \
         re-anchoring then makes that log the reference."
    )
}

/// What the first "Forget old install" dialog names (display-escaped by the caller): the install,
/// the archived files that name it, its token entries that go, and whether its canary entry and
/// its archived log's keys are in the keychain (Rust read them; the text never guesses).
pub struct ForgetFacts<'a> {
    pub install_id: &'a str,
    pub archived_files: &'a [String],
    pub tokens: &'a [String],
    pub canary: bool,
    pub keys_left: bool,
}

/// plan text (T14, PD-170): the first native confirmation of "Forget old install" (T14 review
/// M-2, M-5: it names the canary entry only when there is one, and the archived files in number).
pub fn forget_text(f: &ForgetFacts<'_>) -> String {
    let tokens = if f.tokens.is_empty() {
        "No stored token of it is left.".to_owned()
    } else {
        format!("Its stored tokens are deleted: {}.", listed(f.tokens))
    };
    let canary = if f.canary {
        " Its canary entry is deleted too."
    } else {
        ""
    };
    let archived = match f.archived_files {
        [one] => {
            format!("Only the archived log {one} names this install; that file is not touched.")
        }
        many => format!(
            "Only the archived logs {} name this install; those files are not touched.",
            listed(many)
        ),
    };
    let keys = if f.keys_left {
        " The archived log's keys are still in the keychain: you are asked next whether to delete \
         them as well."
    } else {
        ""
    };
    format!(
        "Forget the old install {}? {tokens}{canary} {archived}{keys}",
        f.install_id
    )
}

/// plan text (T14, PD-170): the second native dialog, "also delete the archived log's keys",
/// naming the key entries present. Cancel keeps them.
pub fn forget_keys_text(install_id: &str, keys: &[String]) -> String {
    format!(
        "Also delete the keys of the archived log of install {install_id} ({})? Without them that \
         log can be opened only with its own recovery passphrase, through a restore. Cancel keeps \
         them; the tokens are deleted either way.",
        listed(keys)
    )
}

/// `s` as a dialog or the Settings window may show it: `escape_for_display` (invisible and bidi
/// characters as `⟨U+XXXX⟩`, injective), and tab, line feed and carriage return too, which it
/// keeps: a dialog text is one paragraph, and a name that broke it into lines could fake a
/// sentence of the dialog (an instance id from an archived store, a Unix path).
pub fn one_line(s: &str) -> String {
    escape_for_display(s)
        .replace('\t', "⟨U+0009⟩")
        .replace('\n', "⟨U+000A⟩")
        .replace('\r', "⟨U+000D⟩")
}

/// The display form of each of `items` (an account or file name can hold an archived store's
/// plaintext, a same-user file).
fn shown(items: &[String]) -> Vec<String> {
    items.iter().map(|s| one_line(s)).collect()
}

/// The anchor directory in force, display-escaped.
fn anchor_dir_shown(store: &Store) -> Option<String> {
    store.settings().anchor_dir.as_deref().map(one_line)
}

/// The window's kind of a refused or failed `Store::change_anchor_dir` (matched by the store's
/// consts); a closed store is `not_ready`.
fn anchor_dir_failure(e: &AuditError) -> CommandError {
    use atlas_duck_audit::{ANCHOR_DIR_NOT_WRITABLE, ANCHOR_DIR_WRITER_BUSY, SETTING_UNCHANGED};
    CommandError::AnchorDir(match e {
        AuditError::Closed => return CommandError::NotReady,
        AuditError::Invalid(ANCHOR_DIR_NOT_WRITABLE) => AnchorDirFailure::NotWritable,
        AuditError::Invalid(ANCHOR_DIR_WRITER_BUSY) => AnchorDirFailure::WriterBusy,
        AuditError::Invalid(SETTING_UNCHANGED) => AnchorDirFailure::Unchanged,
        _ => AnchorDirFailure::Failed,
    })
}

/// After a committed anchor-dir change: the windows re-read (Settings its view, the Audit window
/// its status, the status line `anchor_dir_write_failing`, which the switch may turn on or off)
/// and the answer names the directory in force.
fn anchor_dir_changed(store: &Store, out: &dyn EventOut) -> AnchorDirDto {
    out.emit(EVENT_SETTINGS_CHANGED, Value::Null);
    emit_audit_changed(out);
    emit_status_changed(out);
    AnchorDirDto {
        anchor_dir: anchor_dir_shown(store),
    }
}

/// diag event (§7.7): a confirmation was answered Ok, but a fact its text named changed while it was
/// up, so nothing was done and the answer is `cancelled` (T14 review I-2); `reason` names the flow.
pub const LOG_EVENT_TEXT_STALE: &str = "recovery_text_stale";

/// The answer when a fact the confirmation named changed during it: logged (a `cancelled` is
/// otherwise not), then `cancelled`.
fn stale(flow: &'static str) -> CommandError {
    tracing::info!(event = LOG_EVENT_TEXT_STALE, reason = flow);
    CommandError::Cancelled
}

/// What a confirmation of the anchor directory named of the store: the directory in force and the
/// chain whose file goes there. Read again after the dialog: a text that no longer holds changes
/// nothing (T14 review I-2).
fn anchor_dir_facts(store: &Store) -> (Option<String>, String) {
    (store.settings().anchor_dir, store.head().2)
}

/// "Change anchor directory…" (PD-166, T14 review I-1) on a blocking thread: Rust's folder dialog
/// (`pick`) first; then, with no dialog, a path the store would refuse (not absolute, not UTF-8)
/// is `anchor_dir {failed}` and the directory in force `anchor_dir {unchanged}`; then the one
/// native confirmation, which names the chosen folder, the directory in force (it gets the
/// detached line) and the chain file added or appended there; its proof goes to
/// `Store::change_anchor_dir(Some)`, whose first step opens or creates that file, so a `Cancel`
/// leaves the folder untouched. A cancelled dialog is `cancelled`, `stop` after one `not_ready`,
/// a fact the text named that changed meanwhile `cancelled`, nothing changed. The store's
/// refusals are `anchor_dir {not_writable | writer_busy | unchanged | failed}`, nothing committed.
/// After a change: `settings_changed`, `audit_changed` and `status_banner`.
pub fn set_anchor_dir(
    store: &Store,
    confirmer: &dyn NativeConfirmer,
    pick: impl FnOnce() -> Option<RustChosenPath>,
    stop: &dyn Fn() -> bool,
    out: &dyn EventOut,
) -> Result<AnchorDirDto, CommandError> {
    let dir = pick().ok_or(CommandError::Cancelled)?;
    if stop() {
        return Err(CommandError::NotReady);
    }
    let Some(path) = dir
        .path()
        .to_str()
        .filter(|s| !s.is_empty() && dir.path().is_absolute())
    else {
        return Err(CommandError::AnchorDir(AnchorDirFailure::Failed));
    };
    let facts = anchor_dir_facts(store);
    let (current, chain_id) = &facts;
    if same_dir(Some(Path::new(path)), current.as_deref().map(Path::new)) {
        return Err(CommandError::AnchorDir(AnchorDirFailure::Unchanged));
    }
    let set_text = anchor_dir_set_text(
        &one_line(path),
        current.as_deref().map(one_line).as_deref(),
        &one_line(&file_name(chain_id)),
    );
    if confirmer.confirm(&set_text) != Confirm::Ok {
        return Err(CommandError::Cancelled);
    }
    let confirmed = crate::serve::confirmed_by(&set_text);
    if stop() {
        return Err(CommandError::NotReady);
    }
    if anchor_dir_facts(store) != facts {
        return Err(stale("anchor_dir_set"));
    }
    store
        .change_anchor_dir(Some(dir), confirmed)
        .map_err(|e| anchor_dir_failure(&e))?;
    Ok(anchor_dir_changed(store, out))
}

/// "Remove anchor directory" (PD-166): `not_set` before any dialog when none is set; the native
/// confirmation naming it; then `Store::change_anchor_dir(None)` (the store writes the record and
/// `ANCHOR_DETACHED` to the old directory). A directory in force that changed during the dialog
/// is `cancelled`, nothing changed. Events as [`set_anchor_dir`].
pub fn remove_anchor_dir(
    store: &Store,
    confirmer: &dyn NativeConfirmer,
    stop: &dyn Fn() -> bool,
    out: &dyn EventOut,
) -> Result<AnchorDirDto, CommandError> {
    let facts = anchor_dir_facts(store);
    let Some(current) = facts.0.as_deref() else {
        return Err(CommandError::AnchorDir(AnchorDirFailure::NotSet));
    };
    let remove_text = anchor_dir_remove_text(&one_line(current));
    if confirmer.confirm(&remove_text) != Confirm::Ok {
        return Err(CommandError::Cancelled);
    }
    let confirmed = crate::serve::confirmed_by(&remove_text);
    if stop() {
        return Err(CommandError::NotReady);
    }
    if anchor_dir_facts(store) != facts {
        return Err(stale("anchor_dir_remove"));
    }
    store
        .change_anchor_dir(None, confirmed)
        .map_err(|e| anchor_dir_failure(&e))?;
    Ok(anchor_dir_changed(store, out))
}

/// The window's kind of a refused or failed `Store::re_anchor` (T9 handoff: the `RE_ANCHOR_*`
/// texts and `anchors::BARRIER_TAKEN`, matched by their consts); a closed store is `not_ready`.
pub fn re_anchor_failure(e: &AuditError) -> CommandError {
    use atlas_duck_audit::anchors::BARRIER_TAKEN;
    use atlas_duck_audit::{
        RE_ANCHOR_DOES_NOT_VERIFY, RE_ANCHOR_HELD, RE_ANCHOR_NOTHING_MISSING, RE_ANCHOR_RESTORED,
    };
    CommandError::ReAnchor(match e {
        AuditError::Closed => return CommandError::NotReady,
        AuditError::Invalid(RE_ANCHOR_NOTHING_MISSING) => ReAnchorFailure::NothingMissing,
        AuditError::Invalid(RE_ANCHOR_HELD) => ReAnchorFailure::Held,
        AuditError::Invalid(RE_ANCHOR_DOES_NOT_VERIFY) => ReAnchorFailure::DoesNotVerify,
        AuditError::Invalid(RE_ANCHOR_RESTORED | BARRIER_TAKEN) => ReAnchorFailure::Restored,
        AuditError::KeyStore(_) => ReAnchorFailure::Keychain,
        _ => ReAnchorFailure::Failed,
    })
}

/// The missing anchor entry "Re-anchor" is offered for, or why it is not (`held`, `nothing_missing`).
fn re_anchor_gate(store: &Store) -> Result<MissingAnchor, CommandError> {
    let health = store.health();
    match health.anchors_missing {
        Some(m) if re_anchor_offered(&health) => Ok(m),
        Some(_) => Err(CommandError::ReAnchor(ReAnchorFailure::Held)),
        None => Err(CommandError::ReAnchor(ReAnchorFailure::NothingMissing)),
    }
}

/// "Re-anchor" (PD-170): refused before any dialog unless offered (`nothing_missing`, `held`);
/// the native confirmation; the same check again after it (a barrier or a change of the missing
/// entry during the dialog: its kind, or `cancelled` when another entry is missing now); then
/// `Store::re_anchor`. The store's refusals by kind, after `audit_changed` and `status_banner`.
/// After the incident: `audit_changed`, `status_banner` and `settings_changed`.
pub fn re_anchor(
    store: &Store,
    confirmer: &dyn NativeConfirmer,
    stop: &dyn Fn() -> bool,
    out: &dyn EventOut,
) -> Result<ReAnchoredDto, CommandError> {
    let missing = re_anchor_gate(store)?;
    let re_text = re_anchor_text(missing);
    if confirmer.confirm(&re_text) != Confirm::Ok {
        return Err(CommandError::Cancelled);
    }
    let confirmed = crate::serve::confirmed_by(&re_text);
    if stop() {
        return Err(CommandError::NotReady);
    }
    if re_anchor_gate(store)? != missing {
        return Err(stale("re_anchor"));
    }
    match store.re_anchor(confirmed) {
        Ok(verify) => {
            emit_audit_changed(out);
            emit_status_changed(out);
            out.emit(EVENT_SETTINGS_CHANGED, Value::Null);
            Ok(ReAnchoredDto {
                verify_seq: verify.seq,
            })
        }
        Err(e) => {
            // A refused or failed store call may still have changed what the windows show: a
            // `VERIFY` incident (the refusing run's `does_not_verify`, or the `re_anchored` one
            // whose anchor write failed or whose store a restore replaced before the write), or
            // the health (both entries found back): they read their status again.
            emit_audit_changed(out);
            emit_status_changed(out);
            Err(re_anchor_failure(&e))
        }
    }
}

/// `orphan_installs` (PD-170, L116): `audit::orphan_installs` over the data dir and the live
/// keystore, as display rows. A keychain or listing failure is `forget {unreadable}`.
pub fn orphans(
    data: &LocalDataDir,
    keys: &dyn KeyStore,
) -> Result<Vec<OrphanInstallDto>, CommandError> {
    let list = atlas_duck_audit::orphan_installs(data, keys)
        .map_err(|_| CommandError::Forget(ForgetFailure::Unreadable))?;
    Ok(list
        .iter()
        .map(|o| OrphanInstallDto {
            install_id: o.install_id().to_owned(),
            archived_files: shown(o.archived_files()),
            entries: shown(o.entries()),
        })
        .collect())
}

/// The second dialog of "Forget old install" (PD-170, T9 review M-2): its own text naming the
/// archived log's keys, so its proof can never be the first dialog's. `Ok` deletes them too; any
/// other answer keeps them (`None`). Its own function, so the proof check sees this dialog alone.
fn ask_keys(
    confirmer: &dyn NativeConfirmer,
    install_id: &str,
    key_entries: &[String],
) -> (String, Option<atlas_duck_audit::Confirmed>) {
    let text = forget_keys_text(install_id, &shown(key_entries));
    let confirmed = if confirmer.confirm(&text) == Confirm::Ok {
        Some(crate::serve::confirmed_by(&text))
    } else {
        None
    };
    (text, confirmed)
}

/// The entries `orphan` lists that are its archived log's keys, and the others (tokens, canary).
fn split_keys(orphan: &OrphanInstall) -> (Vec<String>, Vec<String>) {
    orphan
        .entries()
        .iter()
        .cloned()
        .partition(|e| KEY_ACCOUNTS.contains(&e.as_str()))
}

/// The orphan `install_id` of a fresh `orphan_installs` (`forget {unreadable}` when the list
/// cannot be read).
fn listed_orphan(
    data: &LocalDataDir,
    keys: &dyn KeyStore,
    install_id: &str,
) -> Result<Option<OrphanInstall>, CommandError> {
    let list = atlas_duck_audit::orphan_installs(data, keys)
        .map_err(|_| CommandError::Forget(ForgetFailure::Unreadable))?;
    Ok(list.into_iter().find(|o| o.install_id() == install_id))
}

/// "Forget old install" (PD-170) on a blocking thread, for `install_id` of a fresh
/// `orphan_installs` (`not_found` with no dialog otherwise): the first native confirmation naming
/// the tokens and the canary entry that go (Cancel: `cancelled`, nothing recorded or deleted);
/// when any of its keys (`kek`, anchors) is left, the second dialog asks about them (Cancel keeps
/// them). Nothing to delete then (only keys were left, and they are kept) is `cancelled` with
/// nothing recorded; so is an install whose listing changed during the dialogs (the list is read
/// again after the last one: the texts must still be true). Then `record(key, old, new)`
/// (`SettingsAdmin::record_app_change`, `CONFIG_CHANGED {source: app, key: forget_install}` with
/// both dialogs' hashes) BEFORE `audit::forget_install`: a record that cannot be written deletes
/// nothing. A keychain error ends the deletion; a second record names what was and was not
/// deleted (best effort) and the answer is `forget {keychain, deleted, not_deleted}`. Answers and
/// records name only entries that were there. After a record: `audit_changed`; after a deletion
/// also `settings_changed`.
pub fn forget(
    data: &LocalDataDir,
    keys: &dyn KeyStore,
    record: &dyn Fn(&str, Value, Value) -> Result<(), SettingsError>,
    confirmer: &dyn NativeConfirmer,
    install_id: &str,
    stop: &dyn Fn() -> bool,
    out: &dyn EventOut,
) -> Result<ForgottenDto, CommandError> {
    use atlas_duck_core::payloads::sha256_hex;
    let Some(orphan) = listed_orphan(data, keys, install_id)? else {
        return Err(CommandError::NotFound);
    };
    let id = orphan.install_id().to_owned();
    let (key_entries, others) = split_keys(&orphan);
    let tokens: Vec<String> = others.iter().filter(|e| *e != "canary").cloned().collect();
    let first_text = forget_text(&ForgetFacts {
        install_id: &id,
        archived_files: &shown(orphan.archived_files()),
        tokens: &shown(&tokens),
        canary: others.len() > tokens.len(),
        keys_left: !key_entries.is_empty(),
    });
    if confirmer.confirm(&first_text) != Confirm::Ok {
        return Err(CommandError::Cancelled);
    }
    let confirmed = crate::serve::confirmed_by(&first_text);
    if stop() {
        return Err(CommandError::NotReady);
    }
    // The second dialog only while keys are left; its Cancel keeps them (not a cancel of the call).
    let keys_asked = !key_entries.is_empty();
    let (keys_text, keys_confirmed) = if keys_asked {
        let (t, c) = ask_keys(confirmer, &id, &key_entries);
        (Some(t), c)
    } else {
        (None, None)
    };
    if stop() {
        return Err(CommandError::NotReady);
    }
    let with_keys = keys_confirmed.is_some();
    let mut delete = others;
    if with_keys {
        delete.extend(key_entries);
    }
    if delete.is_empty() {
        // Only keys were left and they stay: nothing would change (T14 review M-3).
        return Err(CommandError::Cancelled);
    }
    if listed_orphan(data, keys, install_id)?.as_ref() != Some(&orphan) {
        return Err(stale("forget_install"));
    }
    // `forget_install` deletes every candidate (an absent one "succeeds"): name only those there.
    let present = |names: &[String]| -> Vec<String> {
        names
            .iter()
            .filter(|n| delete.contains(n))
            .cloned()
            .collect()
    };
    let old = json!({
        "install_id": id,
        "entries": orphan.entries(),
        "archived_files": orphan.archived_files(),
    });
    let new = json!({
        "install_id": id,
        "delete": delete,
        "keys": with_keys,
        "keys_asked": keys_asked,
        "dialog_text_sha256": sha256_hex(first_text.as_bytes()),
        "keys_dialog_text_sha256": keys_text
            .filter(|_| with_keys)
            .map(|t| sha256_hex(t.as_bytes())),
    });
    // Audit before effect: a record that cannot be written deletes nothing.
    record(KEY_FORGET_INSTALL, old, new.clone()).map_err(CommandError::Settings)?;
    emit_audit_changed(out);
    match atlas_duck_audit::forget_install(keys, &orphan, confirmed, keys_confirmed) {
        Ok(report) => {
            out.emit(EVENT_SETTINGS_CHANGED, Value::Null);
            Ok(ForgottenDto {
                install_id: report.install_id,
                deleted: shown(&present(&report.deleted)),
                keys_deleted: report.keys_deleted,
            })
        }
        Err(e) => {
            let keychain = matches!(e.error, atlas_duck_audit::OpenError::KeyStore(_));
            let (deleted, not_deleted) = (present(&e.deleted), present(&e.not_deleted));
            let after = json!({
                "install_id": id,
                "deleted": deleted,
                "not_deleted": not_deleted,
                "error": if keychain { "keychain" } else { "failed" },
            });
            // The record above said what would be deleted; this one says what was (best effort:
            // its own failure cannot improve the answer, T9 ruling 3).
            match record(KEY_FORGET_INSTALL, new, after) {
                Ok(()) => emit_audit_changed(out),
                Err(err) => log_forget_record_failed(&err),
            }
            if !deleted.is_empty() {
                out.emit(EVENT_SETTINGS_CHANGED, Value::Null);
            }
            Err(CommandError::Forget(if keychain {
                ForgetFailure::Keychain {
                    deleted: shown(&deleted),
                    not_deleted: shown(&not_deleted),
                }
            } else {
                ForgetFailure::Failed
            }))
        }
    }
}

/// The fields this module's line adds to the diagnostic allowlist (M10 T36, M6 M-1): the kind of
/// the failed settings record (a fixed kind, never a message or a value).
pub const LOG_FIELDS: &[&str] = &["error_kind"];

/// The best-effort record after a failed forget-install, logged by kind.
fn log_forget_record_failed(err: &impl std::fmt::Display) {
    tracing::warn!(
        event = crate::commands::settings::LOG_EVENT_SETTINGS_FAILED,
        error_class = "forget",
        error_kind = err.to_string().as_str()
    );
}

#[cfg(test)]
mod log_tests {
    use super::*;

    /// M10 T36 (M6 M-1): the forget-install record failure's line carries `error_kind`.
    #[test]
    fn diag_lines_carry_error_kind_recovery_tier() {
        assert_eq!(
            LOG_FIELDS,
            ["error_kind"],
            "the allowlist is shared: pin this module's own"
        );
        let out = crate::diag::fields::test_support::lines_after_extending(LOG_FIELDS, || {
            log_forget_record_failed(&SettingsError::Conflict)
        });
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(
            out.contains(
                "event=settings_failed error_class=forget error_kind=conflict dropped_fields=0"
            ),
            "{out}"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    use atlas_duck_audit::anchor_dir::{AnchorLine, file_name, parse_line};
    use atlas_duck_audit::keystore::{EntryName, service_name};
    use atlas_duck_audit::testing::{KeyOpKind, MemKeyStore, MemKeyring};
    use atlas_duck_audit::{
        AuditCursor, AuditFilter, EventFlags, EventType, FirstRunInput, KeyStoreError,
        MAX_AUDIT_PAGE_ROWS, NewEvent, OpenConfig, StartupOutcome, SystemClock,
        archive_and_start_fresh, create_new_store, new_ids,
    };
    use atlas_duck_core::payloads::sha256_hex;
    use atlas_duck_core::settings::{StoreHealthView, re_anchor_offered};
    use secrecy::SecretString;
    use serde_json::json;

    use super::*;
    use crate::commands::audit::tests::{Answers, Events, PASS, Rig, TestResult, chosen, rig};

    fn never() -> bool {
        false
    }

    /// The payload of the newest record of type `t`, and its seq.
    fn newest(store: &Store, t: EventType) -> Result<(u64, Value), Box<dyn std::error::Error>> {
        let page = store.query(
            &AuditFilter {
                event_types: vec![t],
                ..AuditFilter::default()
            },
            AuditCursor::first(MAX_AUDIT_PAGE_ROWS),
        )?;
        let seq = page.rows.first().ok_or("no such record")?.seq;
        Ok((seq, serde_json::from_slice(&store.read_payload(seq)?)?))
    }

    fn count(store: &Store, t: EventType) -> Result<usize, Box<dyn std::error::Error>> {
        crate::commands::audit::tests::count(store, t)
    }

    /// A folder for anchor files beside the rig's data dir.
    fn anchor_folder(r: &Rig, name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = r.out.join(name);
        std::fs::create_dir(&dir)?;
        Ok(dir)
    }

    /// The lines of the rig chain's file in `dir`, after the anchor-dir thread drained.
    fn lines(r: &Rig, dir: &Path) -> Result<Vec<AnchorLine>, Box<dyn std::error::Error>> {
        assert!(
            r.store.testing_anchor_dir_drain(),
            "the anchor-dir queue drained"
        );
        let text = std::fs::read_to_string(dir.join(file_name(&r.store.head().2)))?;
        Ok(text
            .lines()
            .map(|l| parse_line(l).map_err(|e| format!("{e}: {l}")))
            .collect::<Result<_, _>>()?)
    }

    /// Every file under `dirs` with its bytes.
    fn snapshot(dirs: &[&Path]) -> Vec<(PathBuf, Vec<u8>)> {
        let mut all = Vec::new();
        for d in dirs {
            if let Ok(rd) = std::fs::read_dir(d) {
                for e in rd.flatten() {
                    all.push((e.path(), std::fs::read(e.path()).unwrap_or_default()));
                }
            }
        }
        all.sort();
        all
    }

    /// Nothing of `before` was deleted, shortened or rewritten: each file is still there and starts
    /// with its earlier bytes.
    fn only_appended(before: &[(PathBuf, Vec<u8>)]) {
        for (path, bytes) in before {
            let now = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert!(now.starts_with(bytes), "{} was rewritten", path.display());
        }
    }

    /// [`Answers`], and while dialog `n` (from 0) is up `during(n)` runs: something else happens
    /// before the user answers (the store or the keychain changes).
    struct OnAsk<'a> {
        answers: Answers,
        during: Box<dyn Fn(usize) + Send + Sync + 'a>,
    }

    impl<'a> OnAsk<'a> {
        fn new(answers: &[Confirm], during: impl Fn(usize) + Send + Sync + 'a) -> OnAsk<'a> {
            OnAsk {
                answers: Answers::new(answers),
                during: Box::new(during),
            }
        }
    }

    impl NativeConfirmer for OnAsk<'_> {
        fn confirm(&self, text: &str) -> Confirm {
            (self.during)(self.answers.texts().len());
            self.answers.confirm(text)
        }
    }

    fn confirmed_test() -> atlas_duck_audit::Confirmed {
        atlas_duck_audit::Confirmed {
            dialog_text_sha256: [2; 32],
        }
    }

    /// T14 review I-2: the facts a confirmation named are read again after it; one that changed
    /// while the dialog was up (another change of the anchor directory, a barrier taken, an
    /// install's entries) makes the Ok change nothing: `cancelled` (re-anchor under a barrier:
    /// `held`), nothing recorded, the chosen folder untouched.
    #[test]
    fn a_text_that_no_longer_holds_changes_nothing() -> TestResult {
        let r = rig(1)?;
        let (a, b) = (anchor_folder(&r, "a")?, anchor_folder(&r, "b")?);
        let b_text = b.to_str().ok_or("utf-8")?.to_owned();
        let configs = count(&r.store, EventType::CONFIG_CHANGED)?;
        let set_meanwhile = OnAsk::new(&[Confirm::Ok], |_| {
            let _ = r
                .store
                .testing_set_anchor_dir(Some(b_text.clone()), confirmed_test());
        });
        let (got, log) = crate::restore_flow::tests::diag_lines(|| {
            set_anchor_dir(
                &r.store,
                &set_meanwhile,
                || Some(chosen(&a)),
                &never,
                &Events::default(),
            )
        });
        assert_eq!(got, Err(CommandError::Cancelled));
        // Unlike a user's Cancel, the refusal is in the diagnostic log (its flow only).
        assert!(
            log.contains(LOG_EVENT_TEXT_STALE) && log.contains("anchor_dir_set"),
            "{log}"
        );
        assert_eq!(
            r.store.settings().anchor_dir.as_deref(),
            Some(b_text.as_str())
        );
        assert_eq!(count(&r.store, EventType::CONFIG_CHANGED)?, configs + 1);
        assert!(std::fs::read_dir(&a)?.next().is_none(), "a is untouched");

        let remove_meanwhile = OnAsk::new(&[Confirm::Ok], |_| {
            let _ = r.store.testing_set_anchor_dir(None, confirmed_test());
        });
        let got = remove_anchor_dir(&r.store, &remove_meanwhile, &never, &Events::default());
        assert_eq!(got, Err(CommandError::Cancelled));
        assert_eq!(count(&r.store, EventType::CONFIG_CHANGED)?, configs + 2);
        assert_eq!(r.store.settings().anchor_dir, None);
        drop((set_meanwhile, remove_meanwhile));

        // Re-anchor: a barrier taken while the dialog was up.
        let r = first_retained_lost(r)?;
        let incidents = r.store.open_incidents();
        let guard = Mutex::new(None);
        let meanwhile = OnAsk::new(&[Confirm::Ok], |_| {
            if let Ok(mut g) = guard.lock() {
                *g = r.store.testing_rewrite_barrier(r.store.head().0).ok();
            }
        });
        let verifies = count(&r.store, EventType::VERIFY)?;
        let events = Events::default();
        let got = re_anchor(&r.store, &meanwhile, &never, &events);
        assert!(
            guard.lock().map_err(|_| "guard")?.is_some(),
            "the barrier was taken"
        );
        assert_eq!(got, Err(CommandError::ReAnchor(ReAnchorFailure::Held)));
        assert_eq!(
            r.store.open_incidents(),
            incidents,
            "no re_anchored incident"
        );
        // Refused by the check after the dialog: the store was not called.
        assert!(events.all().is_empty(), "{:?}", events.all());
        assert_eq!(count(&r.store, EventType::VERIFY)?, verifies);

        // Forget: one of the install's tokens went while the first dialog was up.
        let o = orphaned()?;
        let records = Records::default();
        let a_keys = MemKeyStore::new(o.r.ring.clone(), &o.a_id);
        let meanwhile = OnAsk::new(&[Confirm::Ok, Confirm::Ok], |n| {
            if n == 0 {
                let _ = a_keys.delete(&EntryName::Pat("i2".into()));
            }
        });
        let got = forget(
            &o.r.data,
            &*o.b_keys,
            &records.recorder(&o.r.ring, &o.a_id, false),
            &meanwhile,
            &o.a_id,
            &never,
            &Events::default(),
        );
        assert_eq!(got, Err(CommandError::Cancelled));
        assert!(records.all().is_empty(), "nothing recorded");
        assert!(
            raw(&o.r.ring, &o.a_id, "pat/i1").is_some(),
            "nothing deleted"
        );
        assert!(raw(&o.r.ring, &o.a_id, "kek").is_some(), "nothing deleted");
        Ok(())
    }

    // ---------- the anchor directory (PD-166) ----------

    /// The confirmation [`set_anchor_dir`] shows for `dir` in `r`'s store as it is now.
    fn set_text_for(r: &Rig, dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
        let current = r.store.settings().anchor_dir;
        Ok(anchor_dir_set_text(
            &one_line(dir.to_str().ok_or("utf-8")?),
            current.as_deref().map(one_line).as_deref(),
            &one_line(&file_name(&r.store.head().2)),
        ))
    }

    /// A pick that logs `"pick"` beside the confirmer's `"confirm"` lines, then answers `dir`.
    fn logged_pick<'a>(
        confirmer: &'a Answers,
        dir: &'a Path,
    ) -> impl FnOnce() -> Option<RustChosenPath> + 'a {
        move || {
            if let Ok(mut l) = confirmer.log.lock() {
                l.push("pick");
            }
            Some(chosen(dir))
        }
    }

    /// PD-166, L54 (§10.3 "change or remove the anchor directory" weakens the anchoring; T14 review
    /// I-1): Rust's folder dialog comes first, then the one native confirmation, which names the
    /// chosen folder (display-escaped: a bidi override in its name), the directory in force that
    /// gets the detached line (or that none is set) and the chain file that is added or appended;
    /// its hash is the one the store records. A cancelled folder dialog asks nothing; a `Cancel` of
    /// the confirmation leaves the chosen folder untouched; the quit path's freeze after either
    /// dialog changes nothing. After the change the windows re-read (also the status line: the
    /// write state of the anchor directory may change with it).
    #[test]
    fn anchor_dir_set_needs_confirmation_and_rust_dialog() -> TestResult {
        let r = rig(1)?;
        let a = anchor_folder(&r, "anchors-a\u{202E}x")?;
        let a_text = a.to_str().ok_or("utf-8")?.to_owned();
        let events = Events::default();
        let configs = count(&r.store, EventType::CONFIG_CHANGED)?;

        // The folder dialog cancelled: no confirmation.
        let confirmer = Answers::new(&[Confirm::Ok]);
        let got = set_anchor_dir(&r.store, &confirmer, || None, &never, &events);
        assert_eq!(got, Err(CommandError::Cancelled));
        assert!(confirmer.texts().is_empty(), "no confirmation");
        // The quit path froze the state while the folder dialog was up: no confirmation either.
        let confirmer = Answers::new(&[Confirm::Ok]);
        let got = set_anchor_dir(&r.store, &confirmer, || Some(chosen(&a)), &|| true, &events);
        assert_eq!(got, Err(CommandError::NotReady));
        assert!(
            confirmer.texts().is_empty(),
            "no confirmation after the freeze"
        );

        // The folder first, then the confirmation naming it; a Cancel leaves it untouched.
        let confirmer = Answers::new(&[Confirm::Cancel]);
        let got = set_anchor_dir(
            &r.store,
            &confirmer,
            logged_pick(&confirmer, &a),
            &never,
            &events,
        );
        assert_eq!(got, Err(CommandError::Cancelled));
        assert_eq!(
            *confirmer.log.lock().map_err(|_| "log")?,
            ["pick", "confirm"]
        );
        let text = set_text_for(&r, &a)?;
        assert_eq!(confirmer.texts(), std::slice::from_ref(&text));
        assert!(
            text.contains(&one_line(&a_text)) && text.contains("anchors-a⟨U+202E⟩x"),
            "{text}"
        );
        assert!(text.contains("No anchor directory is set now"), "{text}");
        assert!(text.contains(&file_name(&r.store.head().2)), "{text}");
        assert!(!text.contains('\u{202E}'), "{text}");
        assert!(
            std::fs::read_dir(&a)?.next().is_none(),
            "the folder is untouched"
        );
        // The freeze came while the confirmation was up: its Ok changes nothing.
        let confirmer = Answers::new(&[Confirm::Ok]);
        let asked = || !confirmer.texts().is_empty();
        let got = set_anchor_dir(&r.store, &confirmer, || Some(chosen(&a)), &asked, &events);
        assert_eq!(got, Err(CommandError::NotReady));
        assert_eq!(count(&r.store, EventType::CONFIG_CHANGED)?, configs);
        assert_eq!(r.store.settings().anchor_dir, None);
        assert!(std::fs::read_dir(&a)?.next().is_none(), "nothing written");
        assert!(events.all().is_empty(), "no event: {:?}", events.all());

        // Ok: the store records the hash of the text that named the folder.
        let confirmer = Answers::new(&[Confirm::Ok]);
        let set = set_anchor_dir(&r.store, &confirmer, || Some(chosen(&a)), &never, &events)?;
        assert_eq!(set.anchor_dir, Some(one_line(&a_text)));
        assert_eq!(
            r.store.settings().anchor_dir.as_deref(),
            Some(a_text.as_str())
        );
        let (_, p) = newest(&r.store, EventType::CONFIG_CHANGED)?;
        assert_eq!(p["key"], "anchor_dir");
        assert_eq!(p["new"], json!(a_text));
        assert_eq!(
            p["confirmed"]["dialog_text_sha256"],
            json!(sha256_hex(text.as_bytes()))
        );
        assert!(matches!(
            lines(&r, &a)?.first(),
            Some(AnchorLine::Header { .. })
        ));
        let names: Vec<String> = events.all().into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            [EVENT_SETTINGS_CHANGED, "audit_changed", "status_banner"]
        );

        // A second change names the new folder and the directory in force, which gets the
        // detached line.
        let b = anchor_folder(&r, "anchors-b")?;
        let confirmer = Answers::new(&[Confirm::Cancel]);
        let _ = set_anchor_dir(&r.store, &confirmer, || Some(chosen(&b)), &never, &events);
        let shown = set_text_for(&r, &b)?;
        assert_eq!(confirmer.texts(), std::slice::from_ref(&shown));
        let b_text = one_line(b.to_str().ok_or("utf-8")?);
        assert!(
            shown.contains(&format!("to {b_text}?"))
                && shown.contains(&format!("It is now {}", one_line(&a_text))),
            "{shown}"
        );
        assert!(std::fs::read_dir(&b)?.next().is_none(), "b is untouched");
        Ok(())
    }

    /// T14 review I-1: a folder the store would refuse for its path alone (not absolute, not
    /// UTF-8) is `anchor_dir {failed}`, and the directory in force (however it is spelled) is
    /// `unchanged`, both with no confirmation: the user never confirms a refused path or a no-op.
    /// On Unix a line break in the folder's name reaches the confirmation escaped.
    #[test]
    fn anchor_dir_set_checks_the_path_before_asking() -> TestResult {
        let r = rig(1)?;
        #[cfg(unix)]
        let not_utf8 = {
            use std::os::unix::ffi::OsStrExt;
            r.out.join(std::ffi::OsStr::from_bytes(b"not-utf8-\xff"))
        };
        #[cfg(windows)]
        let not_utf8 = {
            use std::os::windows::ffi::OsStringExt;
            let mut wide: Vec<u16> = r.out.as_os_str().to_string_lossy().encode_utf16().collect();
            wide.extend([u16::from(b'\\'), 0xD800]);
            PathBuf::from(std::ffi::OsString::from_wide(&wide))
        };
        for bad in [PathBuf::from("relative-anchors"), not_utf8] {
            let confirmer = Answers::new(&[Confirm::Ok]);
            let got = set_anchor_dir(
                &r.store,
                &confirmer,
                || Some(chosen(&bad)),
                &never,
                &Events::default(),
            );
            assert_eq!(
                got,
                Err(CommandError::AnchorDir(AnchorDirFailure::Failed)),
                "{}",
                bad.display()
            );
            assert!(confirmer.texts().is_empty(), "{}: no dialog", bad.display());
        }

        let a = anchor_folder(&r, "anchors")?;
        set_anchor_dir(
            &r.store,
            &Answers::new(&[Confirm::Ok]),
            || Some(chosen(&a)),
            &never,
            &Events::default(),
        )?;
        let configs = count(&r.store, EventType::CONFIG_CHANGED)?;
        let mut again = a.clone().into_os_string();
        again.push(std::path::MAIN_SEPARATOR_STR);
        let confirmer = Answers::new(&[Confirm::Ok]);
        let got = set_anchor_dir(
            &r.store,
            &confirmer,
            || Some(chosen(Path::new(&again))),
            &never,
            &Events::default(),
        );
        assert_eq!(
            got,
            Err(CommandError::AnchorDir(AnchorDirFailure::Unchanged))
        );
        assert!(
            confirmer.texts().is_empty(),
            "no dialog for the dir in force"
        );
        assert_eq!(count(&r.store, EventType::CONFIG_CHANGED)?, configs);

        #[cfg(unix)]
        {
            let broken = anchor_folder(&r, "x\nThe folder is kept.\ty")?;
            let confirmer = Answers::new(&[Confirm::Cancel]);
            let _ = set_anchor_dir(
                &r.store,
                &confirmer,
                || Some(chosen(&broken)),
                &never,
                &Events::default(),
            );
            let texts = confirmer.texts();
            assert!(
                texts[0].contains("x⟨U+000A⟩The folder is kept.⟨U+0009⟩y"),
                "{}",
                texts[0]
            );
            assert!(!texts[0].contains(['\n', '\t']), "{}", texts[0]);
        }
        Ok(())
    }

    /// PD-166 (plan text "This folder cannot be written"): a folder whose chain file cannot be
    /// created or opened for append (it does not exist, or it is a file) is refused with
    /// `anchor_dir {not_writable}`; nothing is committed and the setting stays. The folder in force
    /// again is `unchanged`.
    #[test]
    fn anchor_dir_set_refuses_unwritable_dir() -> TestResult {
        let r = rig(1)?;
        let configs = count(&r.store, EventType::CONFIG_CHANGED)?;
        let missing = r.out.join("no-such-folder");
        let a_file = r.out.join("a-file");
        std::fs::write(&a_file, b"not a folder")?;
        for bad in [&missing, &a_file] {
            let confirmer = Answers::new(&[Confirm::Ok]);
            let got = set_anchor_dir(
                &r.store,
                &confirmer,
                || Some(chosen(bad)),
                &never,
                &Events::default(),
            );
            assert_eq!(
                got,
                Err(CommandError::AnchorDir(AnchorDirFailure::NotWritable)),
                "{}",
                bad.display()
            );
        }
        assert_eq!(count(&r.store, EventType::CONFIG_CHANGED)?, configs);
        assert_eq!(r.store.settings().anchor_dir, None);
        assert!(!missing.exists(), "no folder made");
        assert_eq!(std::fs::read(&a_file)?, b"not a folder");

        // A real folder that exists but cannot be written (Unix 0500, no chain file in it; T14
        // review I-3): the chain file cannot be created. As root the mode restricts nothing: the
        // probe file is then made, and this half is skipped.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let ro = anchor_folder(&r, "read-only")?;
            std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500))?;
            let privileged = std::fs::File::create(ro.join("probe")).is_ok();
            let got = (!privileged).then(|| {
                set_anchor_dir(
                    &r.store,
                    &Answers::new(&[Confirm::Ok]),
                    || Some(chosen(&ro)),
                    &never,
                    &Events::default(),
                )
            });
            std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700))?;
            if let Some(got) = got {
                assert_eq!(
                    got,
                    Err(CommandError::AnchorDir(AnchorDirFailure::NotWritable))
                );
                assert!(std::fs::read_dir(&ro)?.next().is_none(), "nothing in it");
                assert_eq!(count(&r.store, EventType::CONFIG_CHANGED)?, configs);
            }
        }

        let a = anchor_folder(&r, "anchors")?;
        let ok = Answers::new(&[Confirm::Ok, Confirm::Ok]);
        set_anchor_dir(
            &r.store,
            &ok,
            || Some(chosen(&a)),
            &never,
            &Events::default(),
        )?;
        assert_eq!(
            set_anchor_dir(
                &r.store,
                &ok,
                || Some(chosen(&a)),
                &never,
                &Events::default()
            ),
            Err(CommandError::AnchorDir(AnchorDirFailure::Unchanged))
        );
        Ok(())
    }

    /// PD-166, §8.5 (an append-only/WORM share administered by someone else): a folder whose chain
    /// file exists is only opened for append (switching back to an earlier directory): no second
    /// header, no other file, nothing rewritten. On Unix the folder is then made read-only (no
    /// file can be created, renamed or deleted in it; the chain file stays writable): it is still
    /// accepted. (As root, which a Unix CI leg may be, the mode restricts nothing; the switch-back
    /// half still holds.)
    #[test]
    fn anchor_dir_set_accepts_append_only_dir() -> TestResult {
        let r = rig(1)?;
        let a = anchor_folder(&r, "worm")?;
        let ok = || Answers::new(&[Confirm::Ok]);
        set_anchor_dir(
            &r.store,
            &ok(),
            || Some(chosen(&a)),
            &never,
            &Events::default(),
        )?;
        remove_anchor_dir(&r.store, &ok(), &never, &Events::default())?;
        let headers = |l: &[AnchorLine]| {
            l.iter()
                .filter(|x| matches!(x, AnchorLine::Header { .. }))
                .count()
        };
        let before_lines = lines(&r, &a)?;
        assert_eq!(headers(&before_lines), 1);
        let before = snapshot(&[&a]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o500))?;
        }
        let back = set_anchor_dir(
            &r.store,
            &ok(),
            || Some(chosen(&a)),
            &never,
            &Events::default(),
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o700))?;
        }
        back?;
        only_appended(&before);
        let after = lines(&r, &a)?;
        assert_eq!(headers(&after), 1, "no second header");
        assert!(
            after.len() > before_lines.len(),
            "the switch back was appended"
        );
        assert_eq!(
            snapshot(&[&a]).len(),
            before.len(),
            "no new file in the folder"
        );
        Ok(())
    }

    /// PD-166 (§8.5 "append-only"): set, remove, set another, set the first again: every file in
    /// either folder is still there and only grew. White box: this module's flows name no call
    /// that deletes, renames, truncates or rewrites a file (the store's own scan covers
    /// `Store::change_anchor_dir`, T5).
    #[test]
    fn anchor_dir_set_never_deletes() -> TestResult {
        let r = rig(2)?;
        let (a, b) = (anchor_folder(&r, "a")?, anchor_folder(&r, "b")?);
        let ok = || Answers::new(&[Confirm::Ok]);
        let none = Events::default();
        set_anchor_dir(&r.store, &ok(), || Some(chosen(&a)), &never, &none)?;
        let mut seen = snapshot(&[&a, &b]);
        remove_anchor_dir(&r.store, &ok(), &never, &none)?;
        assert!(r.store.testing_anchor_dir_drain());
        only_appended(&seen);
        seen = snapshot(&[&a, &b]);
        set_anchor_dir(&r.store, &ok(), || Some(chosen(&b)), &never, &none)?;
        assert!(r.store.testing_anchor_dir_drain());
        only_appended(&seen);
        seen = snapshot(&[&a, &b]);
        set_anchor_dir(&r.store, &ok(), || Some(chosen(&a)), &never, &none)?;
        assert!(r.store.testing_anchor_dir_drain());
        only_appended(&seen);

        let src = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/recovery_tier.rs"),
        )?;
        let flows = src.split("#[cfg(test)]").next().ok_or("no source")?;
        for banned in [
            "remove_file",
            "remove_dir",
            "rename(",
            "set_len",
            "truncate(",
            "fs::write",
            "File::create",
            "write(true)",
        ] {
            assert!(!flows.contains(banned), "recovery_tier.rs names {banned}");
        }
        Ok(())
    }

    /// PD-166, §8.5: "Remove" asks first, naming the directory; `Cancel` changes nothing; `Ok`
    /// removes it, the store commits `CONFIG_CHANGED {anchor_dir: old -> null}` and the old
    /// directory's file ends with `ANCHOR_DETACHED` naming that record. With no directory set the
    /// call is `anchor_dir {not_set}` before any dialog.
    #[test]
    fn anchor_dir_remove_writes_detached() -> TestResult {
        let r = rig(1)?;
        let none = Answers::new(&[]);
        assert_eq!(
            remove_anchor_dir(&r.store, &none, &never, &Events::default()),
            Err(CommandError::AnchorDir(AnchorDirFailure::NotSet))
        );
        assert!(none.texts().is_empty(), "no dialog");

        let a = anchor_folder(&r, "anchors")?;
        set_anchor_dir(
            &r.store,
            &Answers::new(&[Confirm::Ok]),
            || Some(chosen(&a)),
            &never,
            &Events::default(),
        )?;
        let a_text = a.to_str().ok_or("utf-8")?.to_owned();
        let shown = anchor_dir_remove_text(&one_line(&a_text));
        let cancel = Answers::new(&[Confirm::Cancel]);
        assert_eq!(
            remove_anchor_dir(&r.store, &cancel, &never, &Events::default()),
            Err(CommandError::Cancelled)
        );
        assert_eq!(cancel.texts(), std::slice::from_ref(&shown));
        assert!(shown.contains(&one_line(&a_text)), "{shown}");
        assert_eq!(
            r.store.settings().anchor_dir.as_deref(),
            Some(a_text.as_str())
        );
        // The quit path froze the state while the confirmation was up: its Ok changes nothing.
        let configs = count(&r.store, EventType::CONFIG_CHANGED)?;
        let frozen = Answers::new(&[Confirm::Ok]);
        let asked = || !frozen.texts().is_empty();
        assert_eq!(
            remove_anchor_dir(&r.store, &frozen, &asked, &Events::default()),
            Err(CommandError::NotReady)
        );
        assert_eq!(frozen.texts().len(), 1);
        assert_eq!(count(&r.store, EventType::CONFIG_CHANGED)?, configs);
        assert_eq!(
            r.store.settings().anchor_dir.as_deref(),
            Some(a_text.as_str())
        );

        let events = Events::default();
        let removed = remove_anchor_dir(&r.store, &Answers::new(&[Confirm::Ok]), &never, &events)?;
        assert_eq!(removed.anchor_dir, None);
        assert_eq!(r.store.settings().anchor_dir, None);
        let (seq, p) = newest(&r.store, EventType::CONFIG_CHANGED)?;
        assert_eq!(
            (p["key"].clone(), p["new"].clone()),
            (json!("anchor_dir"), Value::Null)
        );
        assert_eq!(
            p["confirmed"]["dialog_text_sha256"],
            json!(sha256_hex(shown.as_bytes()))
        );
        match lines(&r, &a)?.last() {
            Some(AnchorLine::Detached { seq: s, .. }) => assert_eq!(*s, seq),
            other => panic!("the last line is {other:?}"),
        }
        let names: Vec<String> = events.all().into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            [EVENT_SETTINGS_CHANGED, "audit_changed", "status_banner"]
        );
        Ok(())
    }

    // ---------- re-anchor (PD-170) ----------

    /// The rig's store reopened after its first-retained keychain entry was deleted: re-anchor is
    /// offered.
    fn first_retained_lost(r: Rig) -> Result<Rig, Box<dyn std::error::Error>> {
        r.store.flush_head_anchor()?;
        r.store.shutdown();
        MemKeyStore::new(r.ring.clone(), &r.install_id).delete(&EntryName::FirstRetainedAnchor)?;
        let cfg = crate::commands::audit::tests::config(&r.ring, &r.install_id, &r.faults);
        let StartupOutcome::Ready { store, .. } = atlas_duck_audit::open(&r.data, &r.lock, cfg)?
        else {
            return Err("not ready".into());
        };
        Ok(Rig { store, ..r })
    }

    /// PD-170, T9 review M-6: "Re-anchor" is offered (the Settings view's `re_anchor_offered`, the
    /// same rule as the command's check) only while a keychain anchor entry is missing; otherwise
    /// the call is refused before any dialog. When offered, a `Cancel` records nothing; an `Ok`
    /// records the `re_anchored` incident with the dialog's hash, and the windows hear of it.
    #[test]
    fn re_anchor_hidden_unless_anchor_missing() -> TestResult {
        let r = rig(3)?;
        let h = r.store.health();
        assert!(!re_anchor_offered(&h));
        assert!(!StoreHealthView::of(&h).re_anchor_offered);
        let none = Answers::new(&[]);
        assert_eq!(
            re_anchor(&r.store, &none, &never, &Events::default()),
            Err(CommandError::ReAnchor(ReAnchorFailure::NothingMissing))
        );
        assert!(
            none.texts().is_empty(),
            "no dialog while nothing is missing"
        );

        let r = first_retained_lost(r)?;
        let h = r.store.health();
        assert_eq!(h.anchors_missing, Some(MissingAnchor::FirstRetained));
        assert!(StoreHealthView::of(&h).re_anchor_offered);
        let incidents = r.store.open_incidents();
        let cancel = Answers::new(&[Confirm::Cancel]);
        assert_eq!(
            re_anchor(&r.store, &cancel, &never, &Events::default()),
            Err(CommandError::Cancelled)
        );
        assert_eq!(
            cancel.texts(),
            [re_anchor_text(MissingAnchor::FirstRetained)]
        );
        assert_eq!(r.store.open_incidents(), incidents, "nothing recorded");
        assert_eq!(
            re_anchor(
                &r.store,
                &Answers::new(&[Confirm::Ok]),
                &|| true,
                &Events::default()
            ),
            Err(CommandError::NotReady),
            "an Ok after the freeze changes nothing"
        );
        assert_eq!(r.store.open_incidents(), incidents);

        let events = Events::default();
        let done = re_anchor(&r.store, &Answers::new(&[Confirm::Ok]), &never, &events)?;
        let p: Value = serde_json::from_slice(&r.store.read_payload(done.verify_seq)?)?;
        assert_eq!(p["result"], "re_anchored");
        assert_eq!(
            p["dialog_text_sha256"],
            json!(sha256_hex(
                re_anchor_text(MissingAnchor::FirstRetained).as_bytes()
            ))
        );
        assert!(r.store.open_incidents().contains(&done.verify_seq));
        let names: Vec<String> = events.all().into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            ["audit_changed", "status_banner", EVENT_SETTINGS_CHANGED]
        );
        let text = re_anchor_text(MissingAnchor::FirstRetained);
        assert!(text.contains("integrity incident"), "{text}");
        Ok(())
    }

    /// The store's refusals reach the window by kind (T9 handoff: `RE_ANCHOR_*`, `BARRIER_TAKEN`).
    #[test]
    fn re_anchor_refusals_map_to_kinds() {
        use atlas_duck_audit::anchors::BARRIER_TAKEN;
        use atlas_duck_audit::{
            RE_ANCHOR_DOES_NOT_VERIFY, RE_ANCHOR_HELD, RE_ANCHOR_NOTHING_MISSING,
            RE_ANCHOR_RESTORED,
        };
        for (e, want) in [
            (
                AuditError::Invalid(RE_ANCHOR_NOTHING_MISSING),
                ReAnchorFailure::NothingMissing,
            ),
            (AuditError::Invalid(RE_ANCHOR_HELD), ReAnchorFailure::Held),
            (
                AuditError::Invalid(RE_ANCHOR_DOES_NOT_VERIFY),
                ReAnchorFailure::DoesNotVerify,
            ),
            (
                AuditError::Invalid(RE_ANCHOR_RESTORED),
                ReAnchorFailure::Restored,
            ),
            (
                AuditError::Invalid(BARRIER_TAKEN),
                ReAnchorFailure::Restored,
            ),
            (
                AuditError::KeyStore(KeyStoreError::Unavailable),
                ReAnchorFailure::Keychain,
            ),
            (AuditError::Invalid("other"), ReAnchorFailure::Failed),
        ] {
            assert_eq!(re_anchor_failure(&e), CommandError::ReAnchor(want), "{e:?}");
        }
        assert_eq!(
            re_anchor_failure(&AuditError::Closed),
            CommandError::NotReady
        );
    }

    fn event_names(events: &Events) -> Vec<String> {
        events.all().into_iter().map(|(n, _)| n).collect()
    }

    /// The `VERIFY` records with `result` `want`.
    fn verify_results(store: &Store, want: &str) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
        let page = store.query(
            &AuditFilter {
                event_types: vec![EventType::VERIFY],
                ..AuditFilter::default()
            },
            AuditCursor::first(MAX_AUDIT_PAGE_ROWS),
        )?;
        let mut out = Vec::new();
        for row in page.rows {
            let p: Value = serde_json::from_slice(&store.read_payload(row.seq)?)?;
            if p["result"] == want {
                out.push(row.seq);
            }
        }
        Ok(out)
    }

    /// T14 review I-3: the store's refusals and failures of a confirmed re-anchor, through the
    /// flow: a barrier holding the anchors (`held`, before any dialog), a store that does not
    /// verify (another incident: an anchor-directory line that contradicts the log;
    /// `does_not_verify`, its full verification logged), a restore that replaced the store before
    /// the anchors were written (`restored`), the keychain refusing the write (`keychain`, the
    /// `re_anchored` incident stands). After each store call the windows read their status
    /// again (`audit_changed`, `status_banner`); none of them answers success.
    #[test]
    fn re_anchor_refusals_reach_the_window_by_kind() -> TestResult {
        use atlas_duck_audit::anchor_dir::to_line;
        use atlas_duck_audit::testing::FaultPoint;

        // Held: another re-anchor's barrier holds the anchors (the entry stays missing meanwhile);
        // no dialog.
        let r = first_retained_lost(rig(2)?)?;
        let guard = r.store.testing_rewrite_barrier(r.store.head().0)?;
        assert!(r.store.health().anchors_missing.is_some());
        let none = Answers::new(&[]);
        assert_eq!(
            re_anchor(&r.store, &none, &never, &Events::default()),
            Err(CommandError::ReAnchor(ReAnchorFailure::Held))
        );
        assert!(none.texts().is_empty(), "no dialog under a barrier");
        drop(guard);

        // Restored: the store was replaced after the incident, before the anchors were written.
        let store = r.store.clone();
        let once = std::sync::atomic::AtomicBool::new(true);
        r.faults
            .on_hit(FaultPoint::ReAnchorBeforeComplete, move || {
                if once.swap(false, Ordering::SeqCst) {
                    store.testing_bump_generation();
                }
            });
        let events = Events::default();
        assert_eq!(
            re_anchor(&r.store, &Answers::new(&[Confirm::Ok]), &never, &events),
            Err(CommandError::ReAnchor(ReAnchorFailure::Restored))
        );
        assert_eq!(event_names(&events), ["audit_changed", "status_banner"]);
        r.store.shutdown();

        // Keychain: the first-retained entry cannot be written; the incident stands.
        let r = first_retained_lost(rig(2)?)?;
        r.ring.fail_next(
            KeyOpKind::Set,
            Some(EntryName::FirstRetainedAnchor),
            KeyStoreError::Unavailable,
            u32::MAX,
        );
        let events = Events::default();
        assert_eq!(
            re_anchor(&r.store, &Answers::new(&[Confirm::Ok]), &never, &events),
            Err(CommandError::ReAnchor(ReAnchorFailure::Keychain))
        );
        assert_eq!(event_names(&events), ["audit_changed", "status_banner"]);
        let incident = verify_results(&r.store, "re_anchored")?;
        assert_eq!(incident.len(), 1);
        assert!(r.store.open_incidents().contains(&incident[0]));
        r.ring.clear_faults();
        r.store.shutdown();

        // Does not verify: the anchor directory holds a line whose record_hash the log's GENESIS
        // does not have.
        let r = rig(2)?;
        let dir = anchor_folder(&r, "anchors")?;
        set_anchor_dir(
            &r.store,
            &Answers::new(&[Confirm::Ok]),
            || Some(chosen(&dir)),
            &never,
            &Events::default(),
        )?;
        assert!(r.store.testing_anchor_dir_drain());
        let forged = to_line(&AnchorLine::Record {
            seq: 1,
            record_hash: [7; 32],
            epoch: None,
            clock_behind: false,
        });
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join(file_name(&r.store.head().2)))?;
        std::io::Write::write_all(&mut file, format!("{forged}\n").as_bytes())?;
        drop(file);
        let r = first_retained_lost(r)?;
        assert_eq!(
            r.store.health().anchors_missing,
            Some(MissingAnchor::FirstRetained)
        );
        let before = count(&r.store, EventType::VERIFY)?;
        let events = Events::default();
        assert_eq!(
            re_anchor(&r.store, &Answers::new(&[Confirm::Ok]), &never, &events),
            Err(CommandError::ReAnchor(ReAnchorFailure::DoesNotVerify))
        );
        assert_eq!(event_names(&events), ["audit_changed", "status_banner"]);
        assert_eq!(
            count(&r.store, EventType::VERIFY)?,
            before + 1,
            "the run is logged"
        );
        assert!(verify_results(&r.store, "re_anchored")?.is_empty());
        Ok(())
    }

    // ---------- forget old install (PD-170) ----------

    /// Install A ran a store naming instances `i1`, `i2` and held their tokens; it was archived and
    /// install B (the rig's live one) started beside it. A's keychain also holds its KEK and
    /// anchors.
    struct Orphaned {
        r: Rig,
        a_id: String,
        b_keys: Arc<MemKeyStore>,
    }

    fn orphaned() -> Result<Orphaned, Box<dyn std::error::Error>> {
        orphaned_with(&["i1", "i2"])
    }

    /// [`orphaned`] with the instances `ids`, each with a token of A.
    fn orphaned_with(ids: &[&str]) -> Result<Orphaned, Box<dyn std::error::Error>> {
        let r = rig(0)?;
        let a_id = r.install_id.clone();
        let a_keys = MemKeyStore::new(r.ring.clone(), &a_id);
        for id in ids {
            r.store.append(NewEvent {
                event_type: EventType::READ_FETCHED,
                request_id: None,
                op_id: None,
                op_class: None,
                instance_id: Some((*id).into()),
                target: None,
                actor: atlas_duck_audit::Actor::default(),
                decision: None,
                flags: EventFlags::default(),
                payload: json!({ "id": id }),
            })?;
            a_keys.set(&EntryName::Pat((*id).into()), b"a token")?;
        }
        r.store.flush_head_anchor()?;
        r.store.shutdown();
        let archived = archive_and_start_fresh(
            &r.data,
            &r.lock,
            atlas_duck_audit::Confirmed {
                dialog_text_sha256: [1; 32],
            },
        )?;
        let (b_id, b_chain) = new_ids()?;
        let b_keys = Arc::new(MemKeyStore::new(r.ring.clone(), &b_id));
        let mut cfg = OpenConfig::new(Arc::new(SystemClock::new()), b_keys.clone());
        cfg.free_space = Some(atlas_duck_audit::testing::FreeSpaceStub::new(u64::MAX));
        let store = create_new_store(
            &r.data,
            &r.lock,
            cfg,
            FirstRunInput {
                install_id: b_id.clone(),
                chain_id: b_chain,
                passphrase: SecretString::from(PASS.to_owned()),
                passphrase_confirm: SecretString::from(PASS.to_owned()),
                archived_db: Some(archived),
                anchor_dir: None,
                archive_confirmed: None,
            },
        )?;
        Ok(Orphaned {
            r: Rig {
                store,
                install_id: b_id,
                ..r
            },
            a_id,
            b_keys,
        })
    }

    fn raw(ring: &MemKeyring, install_id: &str, account: &str) -> Option<Vec<u8>> {
        ring.raw_get(&service_name(install_id), account)
    }

    /// One `record` call: key, old, new, and A's entries present when it was made.
    type Recorded = (String, Value, Value, Vec<&'static str>);

    /// What `record` was called with, and the A entries present at each call.
    #[derive(Default)]
    struct Records(Mutex<Vec<Recorded>>);

    impl Records {
        fn recorder<'a>(
            &'a self,
            ring: &'a MemKeyring,
            a_id: &'a str,
            fail: bool,
        ) -> impl Fn(&str, Value, Value) -> Result<(), SettingsError> + 'a {
            move |key, old, new| {
                let present: Vec<&'static str> = ["pat/i1", "pat/i2", "canary", "kek"]
                    .into_iter()
                    .filter(|a| raw(ring, a_id, a).is_some())
                    .collect();
                if let Ok(mut v) = self.0.lock() {
                    v.push((key.to_owned(), old, new, present));
                }
                if fail {
                    Err(SettingsError::ShuttingDown)
                } else {
                    Ok(())
                }
            }
        }

        fn all(&self) -> Vec<Recorded> {
            self.0.lock().map(|v| v.clone()).unwrap_or_default()
        }
    }

    /// PD-170, L116: the list names the installs only archived stores name (never the live one)
    /// with their entries; "Forget" acts only on an install of a fresh list: the live install, an
    /// unknown id and a malformed one are `not_found` with no dialog, nothing recorded or deleted.
    /// A `Cancel` of the first dialog changes nothing either.
    #[test]
    fn forget_install_only_listed_orphans() -> TestResult {
        let o = orphaned()?;
        let list = orphans(&o.r.data, &*o.b_keys)?;
        assert_eq!(list.len(), 1, "{list:?}");
        assert_eq!(list[0].install_id, o.a_id);
        assert_eq!(list[0].archived_files.len(), 1);
        assert!(list[0].archived_files[0].starts_with("archived/audit-"));
        assert_eq!(
            list[0].entries,
            [
                "first_retained_anchor",
                "head_anchor",
                "kek",
                "pat/i1",
                "pat/i2"
            ]
        );
        let records = Records::default();
        let (unknown, _) = new_ids()?;
        for id in [o.r.install_id.as_str(), unknown.as_str(), "not-an-id", ""] {
            let none = Answers::new(&[]);
            assert_eq!(
                forget(
                    &o.r.data,
                    &*o.b_keys,
                    &records.recorder(&o.r.ring, &o.a_id, false),
                    &none,
                    id,
                    &never,
                    &Events::default(),
                ),
                Err(CommandError::NotFound),
                "{id}"
            );
            assert!(none.texts().is_empty(), "{id}: no dialog");
        }
        let cancel = Answers::new(&[Confirm::Cancel]);
        assert_eq!(
            forget(
                &o.r.data,
                &*o.b_keys,
                &records.recorder(&o.r.ring, &o.a_id, false),
                &cancel,
                &o.a_id,
                &never,
                &Events::default(),
            ),
            Err(CommandError::Cancelled)
        );
        assert_eq!(cancel.texts().len(), 1);
        assert!(records.all().is_empty(), "nothing recorded");
        assert!(
            raw(&o.r.ring, &o.a_id, "pat/i1").is_some(),
            "nothing deleted"
        );
        assert_eq!(orphans(&o.r.data, &*o.b_keys)?, list);
        Ok(())
    }

    /// PD-170 (T9 review M-2, ruling 3): the first dialog names the tokens and the canary that go,
    /// the second (only while keys are left) names the archived log's keys; Cancel there keeps
    /// them. `CONFIG_CHANGED {key: forget_install}` is recorded before any delete, with both
    /// dialogs' hashes (distinct: two dialogs, two texts). A record that cannot be written deletes
    /// nothing; a keychain error mid-way gives a second record naming what was and was not deleted.
    #[test]
    fn forget_install_two_dialogs_for_keys() -> TestResult {
        // Ok, Cancel: the tokens and the canary go, the keys stay.
        let o = orphaned()?;
        let records = Records::default();
        let confirmer = Answers::new(&[Confirm::Ok, Confirm::Cancel]);
        let events = Events::default();
        let done = forget(
            &o.r.data,
            &*o.b_keys,
            &records.recorder(&o.r.ring, &o.a_id, false),
            &confirmer,
            &o.a_id,
            &never,
            &events,
        )?;
        assert!(!done.keys_deleted);
        // Only the entries that were there (T14 review M-2: A never had a canary entry).
        assert_eq!(done.deleted, ["pat/i1", "pat/i2"]);
        for gone in ["pat/i1", "pat/i2", "canary"] {
            assert!(raw(&o.r.ring, &o.a_id, gone).is_none(), "{gone}");
        }
        for kept in KEY_ACCOUNTS {
            assert!(raw(&o.r.ring, &o.a_id, kept).is_some(), "{kept}");
        }
        let texts = confirmer.texts();
        assert_eq!(texts.len(), 2);
        assert!(
            texts[0].contains("pat/i1") && texts[0].contains(&o.a_id),
            "{}",
            texts[0]
        );
        assert!(texts[1].contains("kek"), "{}", texts[1]);
        let recs = records.all();
        assert_eq!(recs.len(), 1);
        let (key, _, new, present) = &recs[0];
        assert_eq!(key, KEY_FORGET_INSTALL);
        assert_eq!(
            present,
            &["pat/i1", "pat/i2", "kek"],
            "recorded before the delete"
        );
        assert_eq!(new["install_id"], json!(o.a_id));
        assert_eq!(new["delete"], json!(["pat/i1", "pat/i2"]));
        assert_eq!(new["keys"], json!(false));
        assert_eq!(
            new["keys_asked"],
            json!(true),
            "the second dialog was shown"
        );
        assert_eq!(
            new["dialog_text_sha256"],
            json!(sha256_hex(texts[0].as_bytes()))
        );
        assert_eq!(new["keys_dialog_text_sha256"], Value::Null);
        // The record (the Audit window) and the deletion (Settings).
        assert_eq!(
            events.all().into_iter().map(|(n, _)| n).collect::<Vec<_>>(),
            ["audit_changed", EVENT_SETTINGS_CHANGED]
        );

        // Ok, Ok: the keys go too; the two hashes are the two texts'.
        let o = orphaned()?;
        let records = Records::default();
        let confirmer = Answers::new(&[Confirm::Ok, Confirm::Ok]);
        let done = forget(
            &o.r.data,
            &*o.b_keys,
            &records.recorder(&o.r.ring, &o.a_id, false),
            &confirmer,
            &o.a_id,
            &never,
            &Events::default(),
        )?;
        assert!(done.keys_deleted);
        for gone in [
            "pat/i1",
            "pat/i2",
            "canary",
            "kek",
            "head_anchor",
            "first_retained_anchor",
        ] {
            assert!(raw(&o.r.ring, &o.a_id, gone).is_none(), "{gone}");
        }
        let texts = confirmer.texts();
        let new = &records.all()[0].2;
        assert_eq!(new["keys"], json!(true));
        let (h1, h2) = (
            sha256_hex(texts[0].as_bytes()),
            sha256_hex(texts[1].as_bytes()),
        );
        assert_ne!(h1, h2);
        assert_eq!(new["dialog_text_sha256"], json!(h1));
        assert_eq!(new["keys_dialog_text_sha256"], json!(h2));
        assert!(
            orphans(&o.r.data, &*o.b_keys)?.is_empty(),
            "nothing left to forget"
        );

        // The record cannot be written: nothing is deleted.
        let o = orphaned()?;
        let records = Records::default();
        let r = forget(
            &o.r.data,
            &*o.b_keys,
            &records.recorder(&o.r.ring, &o.a_id, true),
            &Answers::new(&[Confirm::Ok, Confirm::Ok]),
            &o.a_id,
            &never,
            &Events::default(),
        );
        assert_eq!(r, Err(CommandError::Settings(SettingsError::ShuttingDown)));
        assert!(raw(&o.r.ring, &o.a_id, "pat/i1").is_some());
        assert!(raw(&o.r.ring, &o.a_id, "kek").is_some());

        // A keychain error on the second token: the first is gone, the record of what happened
        // follows the first one.
        let o = orphaned()?;
        let records = Records::default();
        o.r.ring.fail_next(
            KeyOpKind::Delete,
            Some(EntryName::Pat("i2".into())),
            KeyStoreError::Unavailable,
            1,
        );
        let r = forget(
            &o.r.data,
            &*o.b_keys,
            &records.recorder(&o.r.ring, &o.a_id, false),
            &Answers::new(&[Confirm::Ok, Confirm::Cancel]),
            &o.a_id,
            &never,
            &Events::default(),
        );
        assert_eq!(
            r,
            Err(CommandError::Forget(ForgetFailure::Keychain {
                deleted: vec!["pat/i1".into()],
                // A had no canary entry: it is not named as left behind (T14 review M-2).
                not_deleted: vec!["pat/i2".into()],
            }))
        );
        let recs = records.all();
        assert_eq!(recs.len(), 2, "{recs:?}");
        assert_eq!(recs[1].0, KEY_FORGET_INSTALL);
        assert_eq!(
            recs[1].1, recs[0].2,
            "the second record starts from the first one's new"
        );
        assert_eq!(recs[1].2["deleted"], json!(["pat/i1"]));
        assert_eq!(recs[1].2["not_deleted"], json!(["pat/i2"]));
        Ok(())
    }

    /// `inner`, whose `for_install` answers `None` once it answered `left` calls: a keystore that
    /// lists another install's entries and then cannot address it any more.
    struct Addressable {
        inner: Arc<MemKeyStore>,
        left: AtomicU32,
    }

    impl KeyStore for Addressable {
        fn install_id(&self) -> &str {
            self.inner.install_id()
        }
        fn get(&self, e: &EntryName) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, KeyStoreError> {
            self.inner.get(e)
        }
        fn set(&self, e: &EntryName, v: &[u8]) -> Result<(), KeyStoreError> {
            self.inner.set(e, v)
        }
        fn delete(&self, e: &EntryName) -> Result<(), KeyStoreError> {
            self.inner.delete(e)
        }
        fn locality(&self) -> atlas_duck_audit::KeyringLocality {
            self.inner.locality()
        }
        fn for_install(&self, install_id: &str) -> Option<Box<dyn KeyStore>> {
            self.left
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .ok()
                .and_then(|_| self.inner.for_install(install_id))
        }
    }

    /// T14 review I-3, M-3: "Forget" stops with nothing recorded or deleted when the quit path
    /// begins after either dialog, and when nothing would be deleted (only the archived log's keys
    /// are left and their dialog is cancelled); a list that cannot be read (before the dialogs, or
    /// when it is read again after them) is `forget {unreadable}`; a keystore that cannot address
    /// the install any more is `forget {failed}` after the first record, with the corrective one.
    #[test]
    fn forget_stops_and_failures_record_what_happened() -> TestResult {
        let untouched = |o: &Orphaned| {
            for kept in ["pat/i1", "pat/i2", "kek"] {
                assert!(raw(&o.r.ring, &o.a_id, kept).is_some(), "{kept}");
            }
        };
        // The freeze after the first dialog: no second dialog.
        let o = orphaned()?;
        let records = Records::default();
        let confirmer = Answers::new(&[Confirm::Ok, Confirm::Ok]);
        let after_first = || !confirmer.texts().is_empty();
        let got = forget(
            &o.r.data,
            &*o.b_keys,
            &records.recorder(&o.r.ring, &o.a_id, false),
            &confirmer,
            &o.a_id,
            &after_first,
            &Events::default(),
        );
        assert_eq!(got, Err(CommandError::NotReady));
        assert_eq!(
            confirmer.texts().len(),
            1,
            "no keys dialog after the freeze"
        );
        assert!(records.all().is_empty());
        untouched(&o);
        // The freeze after the second dialog.
        let confirmer = Answers::new(&[Confirm::Ok, Confirm::Ok]);
        let after_second = || confirmer.texts().len() >= 2;
        let got = forget(
            &o.r.data,
            &*o.b_keys,
            &records.recorder(&o.r.ring, &o.a_id, false),
            &confirmer,
            &o.a_id,
            &after_second,
            &Events::default(),
        );
        assert_eq!(got, Err(CommandError::NotReady));
        assert!(records.all().is_empty());
        untouched(&o);

        // The list cannot be read: before any dialog, and when read again after the last one.
        // (Only A's token entry fails: the live store's own threads read other entries.)
        let fail_token = |ring: &MemKeyring| {
            ring.fail_next(
                KeyOpKind::Get,
                Some(EntryName::Pat("i1".into())),
                KeyStoreError::Unavailable,
                1,
            )
        };
        fail_token(&o.r.ring);
        assert_eq!(
            orphans(&o.r.data, &*o.b_keys),
            Err(CommandError::Forget(ForgetFailure::Unreadable))
        );
        fail_token(&o.r.ring);
        let none = Answers::new(&[]);
        let got = forget(
            &o.r.data,
            &*o.b_keys,
            &records.recorder(&o.r.ring, &o.a_id, false),
            &none,
            &o.a_id,
            &never,
            &Events::default(),
        );
        assert_eq!(got, Err(CommandError::Forget(ForgetFailure::Unreadable)));
        assert!(none.texts().is_empty(), "no dialog");
        let ring = o.r.ring.clone();
        let late = OnAsk::new(&[Confirm::Ok, Confirm::Ok], move |n| {
            if n == 1 {
                fail_token(&ring);
            }
        });
        let got = forget(
            &o.r.data,
            &*o.b_keys,
            &records.recorder(&o.r.ring, &o.a_id, false),
            &late,
            &o.a_id,
            &never,
            &Events::default(),
        );
        assert_eq!(got, Err(CommandError::Forget(ForgetFailure::Unreadable)));
        assert!(records.all().is_empty());
        untouched(&o);

        // The keystore cannot address the install when the deletion begins: the first record
        // stands, the corrective one says nothing was deleted.
        // Two answers: the listing before the dialogs and the one after them; the deletion's own
        // `for_install` is the third call, and gets none.
        let addressable = Addressable {
            inner: o.b_keys.clone(),
            left: AtomicU32::new(2),
        };
        let events = Events::default();
        let got = forget(
            &o.r.data,
            &addressable,
            &records.recorder(&o.r.ring, &o.a_id, false),
            &Answers::new(&[Confirm::Ok, Confirm::Cancel]),
            &o.a_id,
            &never,
            &events,
        );
        assert_eq!(got, Err(CommandError::Forget(ForgetFailure::Failed)));
        let recs = records.all();
        assert_eq!(recs.len(), 2, "{recs:?}");
        assert_eq!(recs[1].2["error"], "failed");
        assert_eq!(recs[1].2["deleted"], json!([]));
        assert_eq!(recs[1].2["not_deleted"], json!(["pat/i1", "pat/i2"]));
        assert_eq!(event_names(&events), ["audit_changed", "audit_changed"]);
        untouched(&o);

        // Only the archived log's keys are left, and they are kept: nothing would change.
        let o = orphaned_with(&[])?;
        let records = Records::default();
        let confirmer = Answers::new(&[Confirm::Ok, Confirm::Cancel]);
        let got = forget(
            &o.r.data,
            &*o.b_keys,
            &records.recorder(&o.r.ring, &o.a_id, false),
            &confirmer,
            &o.a_id,
            &never,
            &Events::default(),
        );
        assert_eq!(got, Err(CommandError::Cancelled));
        let texts = confirmer.texts();
        assert_eq!(texts.len(), 2);
        assert!(
            texts[0].contains("No stored token of it is left."),
            "{}",
            texts[0]
        );
        assert!(records.all().is_empty(), "a no-op is not recorded");
        assert!(raw(&o.r.ring, &o.a_id, "kek").is_some());
        Ok(())
    }

    /// The facts of a first "Forget" dialog for `tokens`, with one archived file.
    fn facts<'a>(archived: &'a [String], tokens: &'a [String]) -> ForgetFacts<'a> {
        ForgetFacts {
            install_id: "0123456789abcdef0123456789abcdef",
            archived_files: archived,
            tokens,
            canary: false,
            keys_left: false,
        }
    }

    /// The dialogs list at most [`DIALOG_LIST_MAX`] items and count the rest, and show at most
    /// [`DIALOG_ITEM_MAX`] characters of each (T14 review M-4); an instance id that came from an
    /// archived store (a same-user file, its plaintext column) reaches the list and both dialogs
    /// display-escaped only. The first dialog names the canary entry and the keys only when they
    /// are there, and the archived files in number (M-2, M-5).
    #[test]
    fn forget_texts_are_bounded_and_escaped() -> TestResult {
        let one = ["archived/x.db".to_owned()];
        let many: Vec<String> = (0..30).map(|i| format!("pat/i{i}")).collect();
        let t = forget_text(&facts(&one, &many));
        assert!(t.contains("pat/i19") && !t.contains("pat/i20"), "{t}");
        assert!(t.contains("and 10 more"), "{t}");
        assert!(
            t.contains("Only the archived log archived/x.db names"),
            "{t}"
        );
        assert!(!t.contains("canary") && !t.contains("keys"), "{t}");
        let two = ["archived/x.db".to_owned(), "archived/y.db".to_owned()];
        let t = forget_text(&ForgetFacts {
            canary: true,
            keys_left: true,
            ..facts(&two, &many)
        });
        assert!(
            t.contains("Only the archived logs archived/x.db, archived/y.db name this install"),
            "{t}"
        );
        assert!(t.contains("Its canary entry is deleted too."), "{t}");
        assert!(t.contains("you are asked next"), "{t}");
        // One very long item: cut, and the whole text stays bounded.
        let long: Vec<String> = (0..DIALOG_LIST_MAX + 5)
            .map(|i| format!("pat/{i}{}", "⟨U+202E⟩".repeat(300)))
            .collect();
        let t = forget_text(&facts(&one, &long));
        assert!(t.contains('…'), "{t}");
        assert!(
            t.chars().count() < DIALOG_LIST_MAX * (DIALOG_ITEM_MAX + 3) + 1000,
            "{} chars",
            t.chars().count()
        );
        let keys_text = forget_keys_text("0123456789abcdef0123456789abcdef", &long);
        assert!(
            keys_text.chars().count() < DIALOG_LIST_MAX * (DIALOG_ITEM_MAX + 3) + 1000,
            "{} chars",
            keys_text.chars().count()
        );

        // A bidi override, and a line break that would fake a sentence of the dialog.
        let o = orphaned_with(&["a\u{202E}b", "x\nThe keys are kept.\ty"])?;
        let list = orphans(&o.r.data, &*o.b_keys)?;
        let escaped = "pat/a⟨U+202E⟩b".to_owned();
        let broken = "pat/x⟨U+000A⟩The keys are kept.⟨U+0009⟩y".to_owned();
        assert!(list[0].entries.contains(&escaped), "{:?}", list[0].entries);
        assert!(list[0].entries.contains(&broken), "{:?}", list[0].entries);
        let confirmer = Answers::new(&[Confirm::Cancel]);
        let _ = forget(
            &o.r.data,
            &*o.b_keys,
            &|_, _, _| Ok(()),
            &confirmer,
            &o.a_id,
            &never,
            &Events::default(),
        );
        let texts = confirmer.texts();
        assert!(
            texts[0].contains(&escaped) && texts[0].contains(&broken),
            "{}",
            texts[0]
        );
        assert!(!texts[0].contains(['\u{202E}', '\n', '\t']), "{}", texts[0]);
        assert!(
            texts[0].contains("you are asked next") && !texts[0].contains("canary"),
            "{}",
            texts[0]
        );
        assert_eq!(one_line("⟨U+000A⟩"), "⟨U+27E8⟩U+000A⟨U+27E9⟩", "injective");
        Ok(())
    }
}
