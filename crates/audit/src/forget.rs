//! "Forget old install" (PD-170, L116, M6 T20 m-9): the keychain entries of an install that only
//! an archived store names. "Archive old DB and start fresh" moves a store aside and the wizard
//! starts a new install beside it, keeping the old install's entries as evidence; its stored
//! tokens (`pat/<instance_id>`) then outlive their use. [`orphan_installs`] lists such installs,
//! [`forget_install`] deletes their tokens and canary, and their `kek`, `head_anchor` and
//! `first_retained_anchor` only on a second confirmation: without them the archived store opens
//! only with its own recovery passphrase, through a restore (§8.7). Nothing here touches the
//! live install, a store file or the log: the caller records the change (`CONFIG_CHANGED {source:
//! app, key: forget_install, install_id, deleted}`) in the live store.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;

use atlas_duck_ipc::paths::LocalDataDir;
use rusqlite::types::ValueRef;

use crate::error::OpenError;
use crate::keystore::{EntryName, KeyStore, KeyStoreError};
use crate::open::{is_id, sql, with_suffix};
use crate::recover::{ARCHIVE_DIR, parse_archive_name, remove_if_present};
use crate::schema;
use crate::types::Confirmed;

/// At most this many distinct instance ids are taken from one archived store, each at most this
/// many bytes long; longer ones are skipped (they name no token entry M3 writes).
const MAX_INSTANCES: i64 = 1024;
const MAX_INSTANCE_ID_BYTES: usize = 256;

const NO_OTHER_INSTALL: &str = "this keystore cannot address another install";

/// An install that only archived stores name (not the live one), with keychain entries left.
/// Built by [`orphan_installs`] only: [`forget_install`] acts on what was listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanInstall {
    install_id: String,
    archived_files: Vec<String>,
    instance_ids: Vec<String>,
    entries: Vec<String>,
}

impl OrphanInstall {
    pub fn install_id(&self) -> &str {
        &self.install_id
    }

    /// The archived stores that name it (`archived/<name>`, relative to the data dir, sorted).
    pub fn archived_files(&self) -> &[String] {
        &self.archived_files
    }

    /// Its keychain entries present when it was listed, by account name (`kek`, `head_anchor`,
    /// `first_retained_anchor`, `canary`, `pat/<instance_id>`), sorted: what the confirmation
    /// names. An entry whose bytes do not decode counts as present.
    pub fn entries(&self) -> &[String] {
        &self.entries
    }
}

/// What [`forget_install`] deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgetReport {
    pub install_id: String,
    /// The account names deleted, in order (deleting an absent entry succeeds; it is listed).
    pub deleted: Vec<String>,
    /// The archived log's `kek` and anchors were deleted too (the second confirmation).
    pub keys_deleted: bool,
}

/// Why [`forget_install`] stopped, and what it had done by then: the caller's corrective record
/// names both lists. `deleted` and `not_deleted` together are every entry it was to delete, in
/// order.
#[derive(Debug)]
pub struct ForgetError {
    /// `Invalid`: refused before anything was deleted (the live install, a keystore that cannot
    /// address another install). `KeyStore`: the deletion of `not_deleted[0]` failed.
    pub error: OpenError,
    /// The account names deleted before it stopped, in order.
    pub deleted: Vec<String>,
    /// The account names not deleted: the one that failed first, then those not attempted.
    pub not_deleted: Vec<String>,
}

impl std::fmt::Display for ForgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({} of {} entries deleted)",
            self.error,
            self.deleted.len(),
            self.deleted.len() + self.not_deleted.len()
        )
    }
}

impl std::error::Error for ForgetError {}

/// The installs named by an `archived/audit-<chain_id>-<head_seq>-<stamp>.db` store and not by
/// `keys` (the live install), with the keychain entries they still have (C.3, Δ-M10-1, PD-170).
/// An archive names the installs in the plaintext `target` of its `GENESIS`, `RESTORE` and
/// `APP_START` records (`APP_START` covers a store whose `GENESIS` was pruned); its token entries
/// are `pat/<id>` for the ids of its plaintext `instance_id` column. Read-only: every archive is
/// read on a sidecar-free read-only connection (a `-shm` it leaves is removed, as in
/// `latest_archived`); an archive that cannot be read names nobody. An install none of whose
/// entries is left is not listed. Sorted by `install_id`.
///
/// `KeyStore` errors of the presence checks are returned; `Invalid` when `keys` cannot address
/// another install ([`KeyStore::for_install`]).
pub fn orphan_installs(
    data: &LocalDataDir,
    keys: &dyn KeyStore,
) -> Result<Vec<OrphanInstall>, OpenError> {
    let live = keys.install_id();
    let dir = data.path().join(ARCHIVE_DIR);
    let listing = match std::fs::read_dir(&dir) {
        Ok(l) => l,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    // install id -> (its archived files, the instance ids of those files)
    let mut named: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    for entry in listing {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if parse_archive_name(&name).is_none() || !entry.file_type()?.is_file() {
            continue;
        }
        let path = dir.join(&name);
        let read = read_archive(&path);
        // A read-only open of a store with a WAL may have created `-shm`; it is derived state.
        let _ = remove_if_present(&with_suffix(&path, "-shm"));
        let Ok((installs, instances)) = read else {
            continue;
        };
        for id in installs.into_iter().filter(|id| id != live) {
            let (files, ids) = named.entry(id).or_default();
            files.insert(format!("{ARCHIVE_DIR}/{name}"));
            ids.extend(instances.iter().cloned());
        }
    }
    let mut out = Vec::new();
    for (install_id, (files, instances)) in named {
        let ks = keys
            .for_install(&install_id)
            .ok_or(OpenError::Invalid(NO_OTHER_INSTALL))?;
        let instance_ids: Vec<String> = instances.into_iter().collect();
        let entries = present(&*ks, &instance_ids)?;
        if entries.is_empty() {
            continue;
        }
        out.push(OrphanInstall {
            install_id,
            archived_files: files.into_iter().collect(),
            instance_ids,
            entries,
        });
    }
    Ok(out)
}

/// "Forget old install" (C.3, Δ-M10-1, PD-170) for an install [`orphan_installs`] listed, after
/// its native confirmation: deletes its `pat/<instance_id>` entries and its `canary`; with
/// `keys_confirmed` (the second confirmation, "also delete the archived log's keys") also its
/// `first_retained_anchor`, `head_anchor` and, last, `kek`. Never the live install (`keys`'):
/// `Invalid`. The first keychain error ends it (`KeyStore`); what was deleted before stays
/// deleted, the error lists what was and was not, and a retry deletes the rest. Logging the
/// change is the caller's.
pub fn forget_install(
    keys: &dyn KeyStore,
    orphan: &OrphanInstall,
    confirmed: Confirmed,
    keys_confirmed: Option<Confirmed>,
) -> Result<ForgetReport, ForgetError> {
    let _ = confirmed;
    let with_keys = keys_confirmed.is_some();
    let todo = candidates(&orphan.instance_ids, with_keys);
    let refused = |error| ForgetError {
        error,
        deleted: Vec::new(),
        not_deleted: todo.iter().map(EntryName::account).collect(),
    };
    if orphan.install_id == keys.install_id() || !is_id(&orphan.install_id) {
        return Err(refused(OpenError::Invalid(
            "the live install is never forgotten",
        )));
    }
    let ks = keys
        .for_install(&orphan.install_id)
        .ok_or_else(|| refused(OpenError::Invalid(NO_OTHER_INSTALL)))?;
    let mut deleted = Vec::new();
    for (i, e) in todo.iter().enumerate() {
        if let Err(err) = ks.delete(e) {
            return Err(ForgetError {
                error: err.into(),
                deleted,
                not_deleted: todo[i..].iter().map(EntryName::account).collect(),
            });
        }
        deleted.push(e.account());
    }
    Ok(ForgetReport {
        install_id: orphan.install_id.clone(),
        deleted,
        keys_deleted: with_keys,
    })
}

/// The entries forgetting an install deletes, in order: its tokens, its canary, then (with
/// `with_keys`) the archived log's anchors and its KEK last.
fn candidates(instance_ids: &[String], with_keys: bool) -> Vec<EntryName> {
    let mut v: Vec<EntryName> = instance_ids
        .iter()
        .map(|id| EntryName::Pat(id.clone()))
        .collect();
    v.push(EntryName::Canary);
    if with_keys {
        v.extend([
            EntryName::FirstRetainedAnchor,
            EntryName::HeadAnchor,
            EntryName::Kek,
        ]);
    }
    v
}

/// The account names of the candidate entries `ks` holds, sorted.
fn present(ks: &dyn KeyStore, instance_ids: &[String]) -> Result<Vec<String>, OpenError> {
    let mut out = Vec::new();
    for e in candidates(instance_ids, true) {
        match ks.get(&e) {
            Ok(Some(_)) | Err(KeyStoreError::Corrupt) => out.push(e.account()),
            Ok(None) => {}
            Err(err) => return Err(err.into()),
        }
    }
    out.sort();
    Ok(out)
}

/// `(install ids, instance ids)` an archived store names in plaintext columns.
fn read_archive(path: &Path) -> Result<(BTreeSet<String>, BTreeSet<String>), OpenError> {
    let conn = schema::open_peek(path)?;
    let text = |v: ValueRef<'_>| match v {
        ValueRef::Text(t) => std::str::from_utf8(t).ok().map(str::to_owned),
        _ => None,
    };
    let mut installs = BTreeSet::new();
    {
        let mut st = conn
            .prepare(
                "SELECT DISTINCT target FROM events \
                 WHERE event_type IN ('GENESIS', 'RESTORE', 'APP_START') AND target IS NOT NULL",
            )
            .map_err(sql)?;
        let mut rows = st.query([]).map_err(sql)?;
        while let Some(r) = rows.next().map_err(sql)? {
            if let Some(id) = text(r.get_ref(0).map_err(sql)?).filter(|t| is_id(t)) {
                installs.insert(id);
            }
        }
    }
    let mut instances = BTreeSet::new();
    {
        let mut st = conn
            .prepare(
                "SELECT DISTINCT instance_id FROM events WHERE instance_id IS NOT NULL LIMIT ?1",
            )
            .map_err(sql)?;
        let mut rows = st.query([MAX_INSTANCES]).map_err(sql)?;
        while let Some(r) = rows.next().map_err(sql)? {
            if let Some(id) = text(r.get_ref(0).map_err(sql)?)
                .filter(|t| !t.is_empty() && t.len() <= MAX_INSTANCE_ID_BYTES)
            {
                instances.insert(id);
            }
        }
    }
    drop(conn);
    Ok((installs, instances))
}
