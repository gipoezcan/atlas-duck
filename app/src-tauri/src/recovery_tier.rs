//! The recovery tier and the anchor directory from Settings (M10 T14; §8.5, §8.6, §8.7, §10.3;
//! PD-166, PD-169, PD-170; L116, L134 T20 m-9).
//!
//! Every change here is security-relevant and asks Rust's native confirmation first (L54), built
//! only from facts Rust read itself (the store's settings and health, the keychain, the archived
//! stores' names), every one display-escaped; nothing a webview sent reaches a dialog text but an
//! install id that must be on the current orphan list. The proof of each answer is
//! `serve::confirmed_by` on its Ok path (`ci/check-dialog-proofs.mjs`).
//!
//! - [`set_anchor_dir`] / [`remove_anchor_dir`]: the confirmation, then (set) Rust's folder dialog
//!   (`pick`; no §7.7 local-filesystem check: an anchor directory is meant to be a share, §8.5),
//!   then `Store::change_anchor_dir`, whose first step opens the new directory's chain file for
//!   append or creates it (PD-166): that is the writability check, it deletes and renames
//!   nothing, so an append-only (WORM) share passes. The store logs `CONFIG_CHANGED {key:
//!   anchor_dir}` with the dialog's hash and writes `ANCHOR_DETACHED` to the old directory.
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
//! Each flow runs on a blocking thread (dialogs block); `stop` is the quit path's freeze: a dialog
//! answered after it changes nothing.

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

/// `items` for a dialog: the first [`DIALOG_LIST_MAX`], comma-separated, then "and N more".
fn listed(items: &[String]) -> String {
    let shown: Vec<&str> = items
        .iter()
        .take(DIALOG_LIST_MAX)
        .map(String::as_str)
        .collect();
    let mut s = shown.join(", ");
    if items.len() > DIALOG_LIST_MAX {
        s.push_str(&format!(" and {} more", items.len() - DIALOG_LIST_MAX));
    }
    s
}

/// plan text (T14, PD-166, §8.5): the native confirmation of "Change anchor directory…", before
/// Rust's folder dialog (so it cannot name the folder chosen next; the user picks it in the OS
/// dialog, and the record names it). `current`: the anchor directory in force, display-escaped.
pub fn anchor_dir_set_text(current: Option<&str>) -> String {
    const NEXT: &str = "The log's anchor lines then go to the folder you choose next (a network \
                        share is fine; atlas-duck only adds lines to it, and never deletes or \
                        rewrites anything there)";
    match current {
        Some(dir) => format!(
            "Change the anchor directory of the audit log? It is now {dir}. {NEXT}. The current \
             directory gets a last line that marks it detached; its lines stay as they are."
        ),
        None => format!(
            "Set an anchor directory for the audit log? {NEXT}, so a copy of the log's anchors \
             is kept outside this computer's keychain."
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
/// directory, a rolled-back log whose anchors were deleted is re-anchored too).
pub fn re_anchor_text(missing: MissingAnchor) -> String {
    let which = match missing {
        MissingAnchor::Head => "the head anchor of the audit log",
        MissingAnchor::FirstRetained => "the first-retained anchor of the audit log",
        MissingAnchor::Both => "both anchors of the audit log",
    };
    format!(
        "Re-anchor the audit log? This computer's keychain no longer holds {which}. The whole log \
         is verified first, and only if it verifies are the missing anchors written again from \
         it. This is recorded as an integrity incident (re_anchored) that needs an \
         acknowledgement in the Audit window. A log that was rolled back or edited while its \
         anchors were missing also verifies, unless an anchor directory holds its lines: \
         re-anchoring then makes that log the reference."
    )
}

/// plan text (T14, PD-170): the first native confirmation of "Forget old install": the install,
/// its archived files and the token entries that go (display-escaped by the caller).
pub fn forget_text(install_id: &str, archived_files: &[String], deleted: &[String]) -> String {
    let tokens = if deleted.is_empty() {
        "No stored token of it is left".to_owned()
    } else {
        format!("Its stored tokens are deleted: {}", listed(deleted))
    };
    format!(
        "Forget the old install {install_id}? {tokens}; its canary entry goes too, if there is \
         one. Only the archived log {} names this install; that file is not touched. If the \
         archived log's keys are left, you are asked next whether to delete them as well.",
        listed(archived_files)
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
/// its status) and the answer names the directory in force.
fn anchor_dir_changed(store: &Store, out: &dyn EventOut) -> AnchorDirDto {
    out.emit(EVENT_SETTINGS_CHANGED, Value::Null);
    emit_audit_changed(out);
    AnchorDirDto {
        anchor_dir: anchor_dir_shown(store),
    }
}

/// "Change anchor directory…" (PD-166) on a blocking thread: the native confirmation naming the
/// directory in force, then Rust's folder dialog (`pick`), then `Store::change_anchor_dir(Some)`.
/// A cancelled dialog, or `stop` after one, is `cancelled` with nothing changed. The store's
/// refusals are `anchor_dir {not_writable | writer_busy | unchanged | failed}`, nothing committed.
/// After a change: `settings_changed` and `audit_changed`.
pub fn set_anchor_dir(
    store: &Store,
    confirmer: &dyn NativeConfirmer,
    pick: impl FnOnce() -> Option<RustChosenPath>,
    stop: &dyn Fn() -> bool,
    out: &dyn EventOut,
) -> Result<AnchorDirDto, CommandError> {
    let text = anchor_dir_set_text(anchor_dir_shown(store).as_deref());
    if confirmer.confirm(&text) != Confirm::Ok {
        return Err(CommandError::Cancelled);
    }
    let confirmed = crate::serve::confirmed_by(&text);
    if stop() {
        return Err(CommandError::NotReady);
    }
    let dir = pick().ok_or(CommandError::Cancelled)?;
    if stop() {
        return Err(CommandError::NotReady);
    }
    store
        .change_anchor_dir(Some(dir), confirmed)
        .map_err(|e| anchor_dir_failure(&e))?;
    Ok(anchor_dir_changed(store, out))
}

/// "Remove anchor directory" (PD-166): `not_set` before any dialog when none is set; the native
/// confirmation naming it; then `Store::change_anchor_dir(None)` (the store writes the record and
/// `ANCHOR_DETACHED` to the old directory). Events as [`set_anchor_dir`].
pub fn remove_anchor_dir(
    store: &Store,
    confirmer: &dyn NativeConfirmer,
    stop: &dyn Fn() -> bool,
    out: &dyn EventOut,
) -> Result<AnchorDirDto, CommandError> {
    let Some(current) = anchor_dir_shown(store) else {
        return Err(CommandError::AnchorDir(AnchorDirFailure::NotSet));
    };
    let text = anchor_dir_remove_text(&current);
    if confirmer.confirm(&text) != Confirm::Ok {
        return Err(CommandError::Cancelled);
    }
    let confirmed = crate::serve::confirmed_by(&text);
    if stop() {
        return Err(CommandError::NotReady);
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

/// "Re-anchor" (PD-170): refused before any dialog unless offered (`nothing_missing`, `held`);
/// the native confirmation; then `Store::re_anchor`. The store's refusals by kind. After the
/// incident: `audit_changed`, `status_banner` and `settings_changed`.
pub fn re_anchor(
    store: &Store,
    confirmer: &dyn NativeConfirmer,
    stop: &dyn Fn() -> bool,
    out: &dyn EventOut,
) -> Result<ReAnchoredDto, CommandError> {
    let health = store.health();
    let missing = match health.anchors_missing {
        Some(m) if re_anchor_offered(&health) => m,
        Some(_) => return Err(CommandError::ReAnchor(ReAnchorFailure::Held)),
        None => return Err(CommandError::ReAnchor(ReAnchorFailure::NothingMissing)),
    };
    let text = re_anchor_text(missing);
    if confirmer.confirm(&text) != Confirm::Ok {
        return Err(CommandError::Cancelled);
    }
    let confirmed = crate::serve::confirmed_by(&text);
    if stop() {
        return Err(CommandError::NotReady);
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
            let failure = re_anchor_failure(&e);
            // Both leave a `VERIFY` incident behind (the refusing run's, or the `re_anchored` one
            // whose anchor write failed): the windows read their status again.
            if matches!(
                failure,
                CommandError::ReAnchor(ReAnchorFailure::DoesNotVerify | ReAnchorFailure::Keychain)
            ) {
                emit_audit_changed(out);
                emit_status_changed(out);
            }
            Err(failure)
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

/// "Forget old install" (PD-170) on a blocking thread, for `install_id` of a fresh
/// `orphan_installs` (`not_found` with no dialog otherwise): the first native confirmation naming
/// the tokens and the canary that go (Cancel: `cancelled`, nothing recorded or deleted); when any
/// of its keys (`kek`, anchors) is left, the second dialog asks about them (Cancel keeps them);
/// then `record(key, old, new)` (`SettingsAdmin::record_app_change`, `CONFIG_CHANGED {source: app,
/// key: forget_install}` with both dialogs' hashes) BEFORE `audit::forget_install`: a record that
/// cannot be written deletes nothing. A keychain error ends the deletion; a second record names
/// what was and was not deleted (best effort) and the answer is `forget {keychain, deleted,
/// not_deleted}`. After a deletion: `settings_changed`.
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
    let list = atlas_duck_audit::orphan_installs(data, keys)
        .map_err(|_| CommandError::Forget(ForgetFailure::Unreadable))?;
    let Some(orphan) = list.into_iter().find(|o| o.install_id() == install_id) else {
        return Err(CommandError::NotFound);
    };
    let id = orphan.install_id().to_owned();
    let (key_entries, others) = split_keys(&orphan);
    let tokens: Vec<String> = others.iter().filter(|e| *e != "canary").cloned().collect();
    let text = forget_text(&id, &shown(orphan.archived_files()), &shown(&tokens));
    if confirmer.confirm(&text) != Confirm::Ok {
        return Err(CommandError::Cancelled);
    }
    let confirmed = crate::serve::confirmed_by(&text);
    if stop() {
        return Err(CommandError::NotReady);
    }
    // The second dialog only while keys are left; its Cancel keeps them (not a cancel of the call).
    let (keys_text, keys_confirmed) = if key_entries.is_empty() {
        (None, None)
    } else {
        let (t, c) = ask_keys(confirmer, &id, &key_entries);
        (Some(t), c)
    };
    if stop() {
        return Err(CommandError::NotReady);
    }
    let with_keys = keys_confirmed.is_some();
    let mut delete = others;
    if with_keys {
        delete.extend(key_entries);
    }
    let old = json!({
        "install_id": id,
        "entries": orphan.entries(),
        "archived_files": orphan.archived_files(),
    });
    let new = json!({
        "install_id": id,
        "delete": delete,
        "keys": with_keys,
        "dialog_text_sha256": sha256_hex(text.as_bytes()),
        "keys_dialog_text_sha256": keys_text
            .filter(|_| with_keys)
            .map(|t| sha256_hex(t.as_bytes())),
    });
    // Audit before effect: a record that cannot be written deletes nothing.
    record(KEY_FORGET_INSTALL, old, new.clone()).map_err(CommandError::Settings)?;
    match atlas_duck_audit::forget_install(keys, &orphan, confirmed, keys_confirmed) {
        Ok(report) => {
            out.emit(EVENT_SETTINGS_CHANGED, Value::Null);
            Ok(ForgottenDto {
                install_id: report.install_id,
                deleted: shown(&report.deleted),
                keys_deleted: report.keys_deleted,
            })
        }
        Err(e) => {
            let keychain = matches!(e.error, atlas_duck_audit::OpenError::KeyStore(_));
            let after = json!({
                "install_id": id,
                "deleted": e.deleted,
                "not_deleted": e.not_deleted,
                "error": if keychain { "keychain" } else { "failed" },
            });
            // The record above said what would be deleted; this one says what was (best effort:
            // its own failure cannot improve the answer, T9 ruling 3).
            if let Err(err) = record(KEY_FORGET_INSTALL, new, after) {
                tracing::warn!(
                    event = crate::commands::settings::LOG_EVENT_SETTINGS_FAILED,
                    error_class = "forget",
                    error_kind = err.to_string().as_str()
                );
            }
            if !e.deleted.is_empty() {
                out.emit(EVENT_SETTINGS_CHANGED, Value::Null);
            }
            Err(CommandError::Forget(if keychain {
                ForgetFailure::Keychain {
                    deleted: shown(&e.deleted),
                    not_deleted: shown(&e.not_deleted),
                }
            } else {
                ForgetFailure::Failed
            }))
        }
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

    // ---------- the anchor directory (PD-166) ----------

    /// PD-166, L54 (§10.3 "change or remove the anchor directory" weakens the anchoring): the
    /// native confirmation comes first and names the directory in force; a `Cancel` opens no folder
    /// dialog and changes nothing; on `Ok` the folder comes from Rust's dialog only, the store
    /// commits `CONFIG_CHANGED {key: anchor_dir}` with that dialog's hash, the new directory holds
    /// the chain's file with its header, and the windows hear of it. A cancelled folder dialog, or
    /// the quit path's freeze after the confirmation, changes nothing.
    #[test]
    fn anchor_dir_set_needs_confirmation_and_rust_dialog() -> TestResult {
        let r = rig(1)?;
        let a = anchor_folder(&r, "anchors-a")?;
        let picks = AtomicU32::new(0);
        let events = Events::default();
        let configs = count(&r.store, EventType::CONFIG_CHANGED)?;

        // Cancel: no folder dialog, nothing changed.
        let confirmer = Answers::new(&[Confirm::Cancel]);
        let r1 = set_anchor_dir(
            &r.store,
            &confirmer,
            || {
                picks.fetch_add(1, Ordering::SeqCst);
                Some(chosen(&a))
            },
            &never,
            &events,
        );
        assert_eq!(r1, Err(CommandError::Cancelled));
        assert_eq!(picks.load(Ordering::SeqCst), 0, "no folder dialog");
        assert_eq!(confirmer.texts(), [anchor_dir_set_text(None)]);
        // The quit path froze the state while the dialog was up: its Ok changes nothing.
        let confirmer = Answers::new(&[Confirm::Ok]);
        let r2 = set_anchor_dir(&r.store, &confirmer, || Some(chosen(&a)), &|| true, &events);
        assert_eq!(r2, Err(CommandError::NotReady));
        // The folder dialog cancelled.
        let confirmer = Answers::new(&[Confirm::Ok]);
        let r3 = set_anchor_dir(&r.store, &confirmer, || None, &never, &events);
        assert_eq!(r3, Err(CommandError::Cancelled));
        assert_eq!(count(&r.store, EventType::CONFIG_CHANGED)?, configs);
        assert_eq!(r.store.settings().anchor_dir, None);
        assert!(std::fs::read_dir(&a)?.next().is_none(), "nothing written");
        assert!(events.all().is_empty(), "no event: {:?}", events.all());

        // Ok, then the folder.
        let confirmer = Answers::new(&[Confirm::Ok]);
        let set = set_anchor_dir(
            &r.store,
            &confirmer,
            || {
                picks.fetch_add(1, Ordering::SeqCst);
                Some(chosen(&a))
            },
            &never,
            &events,
        )?;
        assert_eq!(picks.load(Ordering::SeqCst), 1);
        let a_text = a.to_str().ok_or("utf-8")?.to_owned();
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
            json!(sha256_hex(anchor_dir_set_text(None).as_bytes()))
        );
        assert!(matches!(
            lines(&r, &a)?.first(),
            Some(AnchorLine::Header { .. })
        ));
        let names: Vec<String> = events.all().into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, [EVENT_SETTINGS_CHANGED, "audit_changed"]);

        // A second change names the directory in force in its dialog.
        let b = anchor_folder(&r, "anchors-b")?;
        let confirmer = Answers::new(&[Confirm::Cancel]);
        let _ = set_anchor_dir(&r.store, &confirmer, || Some(chosen(&b)), &never, &events);
        let shown = anchor_dir_set_text(Some(&one_line(&a_text)));
        assert_eq!(confirmer.texts(), std::slice::from_ref(&shown));
        assert!(shown.contains(&one_line(&a_text)), "{shown}");
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
        assert_eq!(names, [EVENT_SETTINGS_CHANGED, "audit_changed"]);
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
        assert!(
            done.deleted.contains(&"pat/i1".to_owned())
                && done.deleted.contains(&"canary".to_owned())
        );
        assert!(
            !done
                .deleted
                .iter()
                .any(|d| KEY_ACCOUNTS.contains(&d.as_str()))
        );
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
        assert_eq!(new["keys"], json!(false));
        assert_eq!(
            new["dialog_text_sha256"],
            json!(sha256_hex(texts[0].as_bytes()))
        );
        assert_eq!(new["keys_dialog_text_sha256"], Value::Null);
        assert_eq!(
            events.all().into_iter().map(|(n, _)| n).collect::<Vec<_>>(),
            [EVENT_SETTINGS_CHANGED]
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
                not_deleted: vec!["pat/i2".into(), "canary".into()],
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
        assert_eq!(recs[1].2["not_deleted"], json!(["pat/i2", "canary"]));
        Ok(())
    }

    /// The dialogs list at most [`DIALOG_LIST_MAX`] items and count the rest; an instance id that
    /// came from an archived store (a same-user file, its plaintext column) reaches the list and
    /// both dialogs display-escaped only.
    #[test]
    fn forget_texts_are_bounded_and_escaped() -> TestResult {
        let many: Vec<String> = (0..30).map(|i| format!("pat/i{i}")).collect();
        let t = forget_text(
            "0123456789abcdef0123456789abcdef",
            &["archived/x.db".into()],
            &many,
        );
        assert!(t.contains("pat/i19") && !t.contains("pat/i20"), "{t}");
        assert!(t.contains("and 10 more"), "{t}");

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
        assert_eq!(one_line("⟨U+000A⟩"), "⟨U+27E8⟩U+000A⟨U+27E9⟩", "injective");
        Ok(())
    }
}
