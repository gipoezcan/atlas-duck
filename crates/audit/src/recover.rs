//! The two ways out of `keychain_lost` (§8.7): "Recover this log" re-seals the KEK from the
//! store's recovery blob and rebuilds the keychain anchors after logging that they were lost;
//! "Archive old DB and start fresh" moves the old DB aside (never deleting it) so the first-run
//! wizard can create a new store whose `GENESIS` names it.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use atlas_duck_ipc::paths::LocalDataDir;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension};
use secrecy::SecretString;

use crate::anchor_dir::{self, AnchorDirLines, PreviousChain, Witness};
use crate::anchors::{self, AnchorLoadError, FirstRetainedAnchor};
use crate::clock::UtcInstant;
use crate::crypto::{Kek, KekEntryError, ct_eq};
use crate::encoding::{FIELD_LIST, RowFields, ZERO_HASH};
use crate::error::OpenError;
use crate::keystore::{EntryName, KeyStore, KeyStoreError, KeyringLocality, canary_self_test};
use crate::lock::InstanceLock;
use crate::open::{
    ArchivedDb, RecoveryOffer, audit_err, durable_rename, is_id, kek_opens_store,
    kek_unwraps_a_key, recovery_offer, remove_staging_leftovers, sql, start_existing, sync_dir,
    with_suffix, with_written_by,
};
use crate::recovery::{RecoveryError, open_recovery};
use crate::schema;
use crate::settings;
use crate::store::{OpenConfig, Store};
use crate::types::Confirmed;
use crate::verify::{self, FindingKind, KeychainAnchors, VerifyFinding};

/// The data-dir subdirectory archived stores are moved into.
pub const ARCHIVE_DIR: &str = "archived";

/// What "Recover this log" did (C.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverReport {
    /// The recovery `VERIFY {scope: "recover"}` (an open integrity incident).
    pub verify_seq: u64,
    pub key_recovered_seq: u64,
    /// Instance ids whose `pat/<id>` entry was deleted (absent entries included): every one
    /// needs its token again. M3 logs `INSTANCE_STATE_CHANGED {needs_token}` for them.
    pub pats_deleted: Vec<String>,
}

fn not_found() -> OpenError {
    OpenError::Io(io::Error::new(
        io::ErrorKind::NotFound,
        "audit.db does not exist",
    ))
}

/// `audit.db` must exist; a WAL without it is never treated as a missing store.
pub(crate) fn existing_db(data: &LocalDataDir) -> Result<PathBuf, OpenError> {
    let db = schema::db_path(data);
    if !db.try_exists()? {
        if with_suffix(&db, "-wal").try_exists()? {
            return Err(OpenError::Integrity(
                "audit.db-wal exists without audit.db".into(),
            ));
        }
        return Err(not_found());
    }
    Ok(db)
}

/// The KEK sealed in the store's `recovery` row (§8.7 step 1).
pub(crate) fn recovered_kek(
    conn: &Connection,
    passphrase: &SecretString,
) -> Result<Kek, OpenError> {
    let blob: Option<Vec<u8>> = conn
        .query_row("SELECT blob FROM recovery WHERE id = 1", [], |r| r.get(0))
        .optional()
        .map_err(sql)?;
    let blob = blob.ok_or_else(|| OpenError::Integrity("the store has no recovery row".into()))?;
    open_recovery(passphrase, &blob).map_err(|e| match e {
        RecoveryError::WrongPassphrase => OpenError::WrongPassphrase,
        RecoveryError::NewerLayout(n) => OpenError::NewerStore(format!("recovery layout {n}")),
        RecoveryError::Malformed => OpenError::Integrity("the recovery blob is malformed".into()),
        RecoveryError::KdfFailed => {
            OpenError::Io(io::Error::other("recovery key derivation failed"))
        }
    })
}

/// Recovery is for a lost keychain only (§8.7 "entries missing or undecryptable"): the `kek`
/// entry is absent, does not decode, or holds a key that does not open the store. A keychain
/// KEK that opens the store means nothing is lost (`Invalid`: `open` serves it). One equal to
/// the recovered KEK (constant time) that still does not open the store means the store's key
/// rows are damaged, not the keychain (`Integrity`): rebuilding the anchors over such a store
/// would replace the keychain evidence.
fn check_keychain_lost(
    conn: &Connection,
    keys: &dyn KeyStore,
    recovered: &Kek,
) -> Result<(), OpenError> {
    let current = match keys.get(&EntryName::Kek) {
        Ok(None) | Err(KeyStoreError::Corrupt) => return Ok(()),
        Err(e) => return Err(e.into()),
        Ok(Some(b)) => match Kek::from_entry_bytes(&b) {
            Ok(k) => k,
            Err(KekEntryError::Malformed) => return Ok(()),
            Err(KekEntryError::NewerLayout(n)) => {
                return Err(OpenError::NewerStore(format!("keychain kek layout {n}")));
            }
        },
    };
    if kek_opens_store(conn, &current)? {
        return Err(OpenError::Invalid(
            "the keychain KEK opens this store: there is nothing to recover",
        ));
    }
    if current == *recovered {
        return Err(OpenError::Integrity(
            "the store's data keys do not open with its own KEK".into(),
        ));
    }
    Ok(())
}

/// The anchor entries that survived the loss, for the recovery verification: a surviving
/// anchor still proves (or disproves) a tail truncation, so it is checked before it is
/// rebuilt. An entry whose bytes do not decode counts as lost; a newer layout is refused like
/// at startup.
fn surviving_anchors(keys: &dyn KeyStore) -> Result<KeychainAnchors, OpenError> {
    fn survived<T>(r: Result<Option<T>, AnchorLoadError>) -> Result<Option<T>, OpenError> {
        match r {
            Ok(a) => Ok(a),
            Err(AnchorLoadError::KeyStore(KeyStoreError::Corrupt)) => Ok(None),
            Err(AnchorLoadError::KeyStore(e)) => Err(e.into()),
            Err(AnchorLoadError::Newer(n)) => {
                Err(OpenError::NewerStore(format!("keychain anchor layout {n}")))
            }
        }
    }
    // Head first, as everywhere (the anchor thread writes first-retained before head).
    let head = survived(anchors::load_head(keys))?;
    let first_retained = survived(anchors::load_first_retained(keys))?;
    Ok(KeychainAnchors {
        head,
        first_retained,
        head_newer: None,
        first_retained_newer: None,
    })
}

/// The recovery `VERIFY`'s findings: `anchor_missing` first, so it is the `result` (§8.7 step
/// 3), then every other finding. When every anchor survived, one is still recorded: the
/// keychain this store relied on was lost.
fn recovery_findings(found: Vec<VerifyFinding>) -> Vec<VerifyFinding> {
    let (mut out, rest): (Vec<_>, Vec<_>) = found
        .into_iter()
        .partition(|f| f.kind == FindingKind::AnchorMissing);
    if out.is_empty() {
        out.push(VerifyFinding::new(
            FindingKind::AnchorMissing,
            "the keychain KEK of this install was lost",
        ));
    }
    out.extend(rest);
    out
}

/// "Recover this log" (§8.7, C.3) for a store whose keychain is lost, with the store's
/// recovery passphrase. In order:
///
/// 1. leftover staging files are deleted (never a store, as in `open`; the only file change
///    before the passphrase is checked); `audit.db` must exist (`Io(NotFound)`); the version gate
///    (`NewerStore`); keyring locality (`KeyStore(NotLocal | Unavailable)`, no keyring access);
/// 2. the KEK is unwrapped from the `recovery` row before any keychain call: a wrong passphrase
///    is `WrongPassphrase` and the DB and the keychain are untouched. Still before the first
///    keychain call: a keystore of another install than the store names is `Invalid`; an
///    unfinished `RESTORE` of this install is `Invalid` (its "Finish restore" is restore's); the
///    recovered KEK must unwrap a data key (`Integrity` otherwise: a swapped recovery row). Then
///    the canary, and the keychain must really be lost (`Invalid` if its KEK opens the store,
///    `Integrity` if it equals the recovered KEK);
/// 3. full verification of the chain from the first retained record, the `prune_log` and the
///    anchor dir, with whatever anchor entries survived;
/// 4. the writer starts (anchor writes disabled), runs the migrations (`SCHEMA_MIGRATED`), then
///    commits `VERIFY {scope: "recover", result: "anchor_missing"}` (flag `integrity_incident`,
///    every finding of step 3 included) together with `KEY_RECOVERED`;
/// 5. this install's `pat/<instance-id>` entries are deleted for every instance of the settings
///    view (every instance needs its token: L53); both anchors are rebuilt from the DB
///    (first-retained, then head at the `KEY_RECOVERED` head); the KEK is re-sealed **last**;
///    only then are anchor writes enabled.
///
/// The `chain_id` is unchanged: recovery is not a segment boundary. Any failure after the writer
/// started shuts it down and returns the error. Because the KEK is written last, a failure or a
/// crash anywhere before it leaves the keychain lost (anchors, if written, match the DB) and
/// recovery simply runs again, with its own `VERIFY` and `KEY_RECOVERED`; the PATs go first, so
/// a store never opens again with them.
pub fn recover_this_log(
    data: &LocalDataDir,
    lock: &InstanceLock,
    cfg: OpenConfig,
    passphrase: &SecretString,
) -> Result<(Store, RecoverReport), OpenError> {
    if lock.path().parent() != Some(data.path()) {
        return Err(OpenError::Invalid("instance.lock of another data dir"));
    }
    remove_staging_leftovers(data)?;
    let db = existing_db(data)?;
    let versions = schema::read_versions(&db)?;
    if let Err(found) = schema::gate_up_to(&versions, cfg.hooks.schema_head()) {
        return Err(OpenError::NewerStore(with_written_by(found, &versions)));
    }
    match cfg.keys.locality() {
        KeyringLocality::Local => {}
        KeyringLocality::NotLocal { .. } => return Err(KeyStoreError::NotLocal.into()),
        KeyringLocality::Unknown { .. } => return Err(KeyStoreError::Unavailable.into()),
    }
    let ro = schema::open_peek(&db)?;
    let kek = recovered_kek(&ro, passphrase)?;
    // The KEK is re-sealed under the keystore's install_id: it must be the store's own
    // (§8.6; unknown only when no retained record names one).
    if verify::store_install_id(&ro)
        .map_err(sql)?
        .is_some_and(|id| id != cfg.keys.install_id())
    {
        return Err(OpenError::Invalid(
            "the keystore's install_id is not the store's install_id",
        ));
    }
    if recovery_offer(&ro, cfg.keys.install_id())? == RecoveryOffer::FinishRestore {
        return Err(OpenError::Invalid(
            "the newest record is an unfinished RESTORE: finish the restore instead",
        ));
    }
    if !kek_unwraps_a_key(&ro, &kek)? {
        return Err(OpenError::Integrity(
            "the recovered KEK opens none of the store's data keys".into(),
        ));
    }
    canary_self_test(&*cfg.keys)?;
    check_keychain_lost(&ro, &*cfg.keys, &kek)?;

    // Verification (§8.7 step 2), as `preflight` reads the anchor dir.
    let anchors = surviving_anchors(&*cfg.keys)?;
    let (view, view_trusted) = settings::load_view(&ro, &kek)?;
    let dir = anchor_dir::resolve(view.anchor_dir.as_deref(), cfg.anchor_dir.as_deref());
    let mut lines = anchor_dir::load(dir.as_deref(), &ro)?;
    if !view_trusted {
        AnchorDirLines::note_setting_unreadable(&mut lines);
    }
    let findings =
        recovery_findings(verify::full(&ro, &kek, &anchors, lines.as_ref()).map_err(audit_err)?);
    // Deleting a PAT only ever asks for a token again: the best-effort view of an untrusted
    // log is used as well.
    let pats: Vec<String> = view.instances.keys().cloned().collect();
    let head_chain: Option<String> = ro
        .query_row(
            "SELECT chain_id FROM events ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    // `genesis_hash` is informational once `GENESIS` is pruned (plan decision): a surviving
    // first-retained anchor of this chain that verification did not flag keeps its value,
    // else 32 zero bytes.
    let first_retained_flagged = findings
        .iter()
        .any(|f| f.kind == FindingKind::FirstRetainedMismatch);
    let genesis_hash = match verify::retained_genesis_hash(&ro).map_err(sql)? {
        Some(g) => g,
        None => anchors
            .first_retained
            .as_ref()
            .filter(|f| !first_retained_flagged && Some(&f.chain_id) == head_chain.as_ref())
            .map_or(ZERO_HASH, |f| f.genesis_hash),
    };
    let (first_retained_seq, first_retained_prev_hash) =
        verify::latest_prune_values(&ro).map_err(sql)?;
    drop(ro);

    let keys = cfg.keys.clone();
    #[cfg(any(test, feature = "testing"))]
    let hooks = cfg.hooks.clone();
    let kek_entry = kek.to_entry_bytes();
    let store = start_existing(data, cfg, kek, Some(genesis_hash))?;
    let finish = || -> Result<RecoverReport, OpenError> {
        store.run_migrations()?;
        let (verify, recovered) = store.append_recovery(&findings).map_err(audit_err)?;
        for id in &pats {
            keys.delete(&EntryName::Pat(id.clone()))?;
        }
        let (_, _, chain_id) = store.head();
        store
            .rebuild_anchors(FirstRetainedAnchor {
                chain_id,
                genesis_hash,
                first_retained_seq,
                first_retained_prev_hash,
            })
            .map_err(audit_err)?;
        #[cfg(any(test, feature = "testing"))]
        hooks
            .fault(crate::testing::FaultPoint::AfterRecoveryAnchors)
            .map_err(audit_err)?;
        keys.set(&EntryName::Kek, &kek_entry)?;
        store.enable_anchors();
        // Advisory (§8.13): the recovery itself is complete, its report must reach the caller.
        let _ = store.update_written_by();
        Ok(RecoverReport {
            verify_seq: verify.seq,
            key_recovered_seq: recovered.seq,
            pats_deleted: pats.clone(),
        })
    };
    match finish() {
        Ok(report) => Ok((store, report)),
        Err(e) => {
            store.shutdown();
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------------------
// Archive old DB and start fresh

/// The plaintext head of a store: `(seq, record_hash, chain_id)`, read on a sidecar-free
/// read-only connection that is closed again before returning.
pub(crate) fn plaintext_head(db: &Path) -> Result<(u64, [u8; 32], String), OpenError> {
    let conn = schema::open_peek(db)?;
    let head = conn
        .query_row(
            "SELECT seq, record_hash, chain_id FROM events ORDER BY seq DESC LIMIT 1",
            [],
            |r| {
                let seq = match r.get_ref(0)? {
                    ValueRef::Integer(i) => u64::try_from(i).ok(),
                    _ => None,
                };
                let hash = match r.get_ref(1)? {
                    ValueRef::Blob(b) => <[u8; 32]>::try_from(b).ok(),
                    _ => None,
                };
                let chain = match r.get_ref(2)? {
                    ValueRef::Text(t) => std::str::from_utf8(t).ok().map(str::to_owned),
                    _ => None,
                };
                Ok((seq, hash, chain))
            },
        )
        .optional()
        .map_err(sql)?;
    drop(conn);
    match head {
        None => Err(OpenError::Integrity("the store has no records".into())),
        Some((Some(seq), Some(hash), Some(chain))) => Ok((seq, hash, chain)),
        Some(_) => Err(OpenError::Integrity(
            "the store's head record is unreadable".into(),
        )),
    }
}

/// `YYYYMMDDTHHMMSSmmmZ` of the wall clock: an RFC 3339 instant without its separators (`:` is
/// not allowed in Windows file names).
pub(crate) fn file_stamp() -> Result<String, OpenError> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .and_then(|ms| UtcInstant(ms).try_to_rfc3339_ms())
        .ok_or_else(|| OpenError::Io(io::Error::other("the wall clock is out of range")))?;
    Ok(ms
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'T' || *c == 'Z')
        .collect())
}

pub(crate) fn remove_if_present(p: &Path) -> io::Result<()> {
    match std::fs::remove_file(p) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

pub(crate) fn file_len(p: &Path) -> io::Result<Option<u64>> {
    match std::fs::metadata(p) {
        Ok(m) => Ok(Some(m.len())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// "Archive old DB and start fresh" (§8.7, C.3): the only alternative to recovery when the
/// passphrase is unavailable; `confirmed` is the Rust-drawn native confirmation (§10.3). The
/// caller then runs `create_new_store` with the returned [`ArchivedDb`] (and new ids). No
/// store of this data dir may be running.
///
/// It does not check that the keychain is lost: the caller decides when it is offered
/// (`keychain_lost`, or after recovery refused with `Integrity`).
///
/// The old DB is moved, never deleted or opened read-write: its plaintext head is read on a
/// read-only connection (closed again), `audit.db` is renamed to
/// `archived/audit-<chain_id>-<head_seq>-<UTC stamp>.db` first, then `audit.db-wal` (if any)
/// beside it (a crash in between leaves `audit.db-wal` without `audit.db`, which `open` and
/// `create_new_store` refuse, rather than a DB without its WAL; the repair is manual: move the
/// WAL next to the archived file). Then `audit.db-shm` is deleted, the dirs are synced and the
/// archived file must report the same head and sizes. If any step after the renames fails,
/// both files are moved back and its error is returned.
///
/// `Io(NotFound)` without `audit.db`; `NewerStore` for a store of a newer build (nothing is
/// moved: upgrading opens it; the gate is this build's schema head, without test migrations);
/// `Integrity` for a `chain_id` that is not 32 lowercase hex (it names the file);
/// `AlreadyExists` if the archive name is taken. That check precedes the rename (which would
/// replace a file); the instance lock and the millisecond stamp leave no realistic race.
pub fn archive_and_start_fresh(
    data: &LocalDataDir,
    lock: &InstanceLock,
    confirmed: Confirmed,
) -> Result<ArchivedDb, OpenError> {
    let _ = confirmed;
    if lock.path().parent() != Some(data.path()) {
        return Err(OpenError::Invalid("instance.lock of another data dir"));
    }
    let db = existing_db(data)?;
    let wal = with_suffix(&db, "-wal");
    let versions = schema::read_versions(&db)?;
    if let Err(found) = schema::gate(&versions) {
        return Err(OpenError::NewerStore(with_written_by(found, &versions)));
    }
    let (head_seq, head_hash, chain_id) = plaintext_head(&db)?;
    if !is_id(&chain_id) {
        return Err(OpenError::Integrity(
            "the store's chain_id is not 32 lowercase hex characters".into(),
        ));
    }
    let name = format!("audit-{chain_id}-{head_seq}-{}.db", file_stamp()?);
    let dir = data.path().join(ARCHIVE_DIR);
    let target = dir.join(&name);
    let target_wal = with_suffix(&target, "-wal");
    let sizes = (file_len(&db)?, file_len(&wal)?);
    std::fs::create_dir_all(&dir)?;
    for p in [&target, &target_wal, &with_suffix(&target, "-shm")] {
        if p.try_exists()? {
            return Err(OpenError::AlreadyExists);
        }
    }

    durable_rename(&db, &target)?;
    if sizes.1.is_some()
        && let Err(e) = durable_rename(&wal, &target_wal)
    {
        let _ = durable_rename(&target, &db);
        // Best effort, as after the move-back below.
        let _ = sync_dir(&dir);
        let _ = sync_dir(data.path());
        return Err(e.into());
    }

    // Everything after both renames is checked: a failure moves both files back, so the caller
    // never ends up without `audit.db` and without the `ArchivedDb` that names it.
    let finish = || -> Result<(), OpenError> {
        remove_if_present(&with_suffix(&db, "-shm"))?;
        sync_dir(&dir)?;
        sync_dir(data.path())?;
        // The archived store is still the old one: same sizes, same head (its WAL included).
        let same_sizes = (file_len(&target)?, file_len(&target_wal)?) == sizes;
        let after = plaintext_head(&target);
        // A read-only open of a store with a WAL may have created `-shm`; it is derived state.
        let _ = remove_if_present(&with_suffix(&target, "-shm"));
        let after = after?;
        if !(same_sizes && after.0 == head_seq && after.1 == head_hash && after.2 == chain_id) {
            return Err(OpenError::Integrity(
                "the archived store does not match the store that was moved".into(),
            ));
        }
        Ok(())
    };
    if let Err(e) = finish() {
        let back = durable_rename(&target, &db).and_then(|()| match sizes.1 {
            Some(_) => durable_rename(&target_wal, &wal),
            None => Ok(()),
        });
        if back.is_err() {
            // Both faults: say where the old store is, so it can be moved back by hand.
            return Err(OpenError::Integrity(format!(
                "archiving failed ({e}) and the store could not be moved back from {ARCHIVE_DIR}/{name}"
            )));
        }
        let _ = sync_dir(data.path());
        return Err(e);
    }
    Ok(ArchivedDb {
        file: format!("{ARCHIVE_DIR}/{name}"),
        chain_id,
        head_seq,
        head_hash,
    })
}

/// The archive exemption of a first run (§8.5 "Exempt: the chain recorded as `archived_db`",
/// PD-167): whether the archived store `a`, which the same `GENESIS` names, covers every anchor
/// of `chain`. All of these must hold, else the previous chain raises the incident:
/// - `chain` is `a`'s chain and its file was read whole with every line valid (`named`);
/// - `a.file` is `archived/<name>` with a name [`archive_and_start_fresh`] writes for that chain
///   and head seq (nothing outside `archived/` is opened), a regular file whose plaintext head
///   is `a`'s `(head_seq, head_hash, chain_id)`;
/// - no anchored seq lies beyond that head;
/// - the archive's `prune_log` is sound (rows readable, row-hash chain, contiguity, the first
///   retained record against the latest row) and bound to the chain file: its latest row is one
///   of the file's `Prune` lines (`first_retained_seq`, `last_pruned_record_hash` as
///   `first_retained_prev_hash`, `cutoff_epoch`) and no line names a later first retained seq;
///   a file without a `Prune` line requires a `prune_log` without rows. An archive whose own
///   rows claimed the anchored records pruned would otherwise cover nothing (T6 review C-1);
/// - every anchored `(seq, record_hash)` at or after that first retained seq names a row of the
///   archive whose stored `record_hash` is the line's and whose columns hash to it (recomputed:
///   a `record_hash` column copied from the lines does not cover anything). Lines below the
///   first retained seq were pruned from the archive.
///
/// Read-only (a sidecar-free reader; a `-shm` it leaves is removed, as in [`latest_archived`]).
/// Any error reads as "not covered".
pub(crate) fn archive_covers(data: &LocalDataDir, a: &ArchivedDb, chain: &PreviousChain) -> bool {
    let Some(witness) = chain
        .witness
        .as_ref()
        .filter(|_| chain.chain_id == a.chain_id)
    else {
        return false;
    };
    let Some(name) = a.file.strip_prefix(&format!("{ARCHIVE_DIR}/")) else {
        return false;
    };
    if !parse_archive_name(name).is_some_and(|(c, seq, _)| c == a.chain_id && seq == a.head_seq) {
        return false;
    }
    let path = data.path().join(ARCHIVE_DIR).join(name);
    if !std::fs::metadata(&path).is_ok_and(|m| m.is_file()) {
        return false;
    }
    let covered = covers(&path, a, witness);
    // A read-only open of a store with a WAL may have created `-shm`; it is derived state.
    let _ = remove_if_present(&with_suffix(&path, "-shm"));
    covered.unwrap_or(false)
}

fn covers(path: &Path, a: &ArchivedDb, witness: &Witness) -> Result<bool, OpenError> {
    let named = &witness.named;
    let (head_seq, head_hash, head_chain) = plaintext_head(path)?;
    if head_seq != a.head_seq || !ct_eq(&head_hash, &a.head_hash) || head_chain != a.chain_id {
        return Ok(false);
    }
    if named.iter().any(|(seq, _)| *seq > head_seq) {
        return Ok(false);
    }
    let conn = schema::open_peek(path)?;
    let Some((first_retained, last_pruned, cutoff)) =
        verify::checked_prune_values(&conn).map_err(sql)?
    else {
        return Ok(false);
    };
    // Which records the archive no longer holds is the chain file's word, not the archive's: its
    // latest prune_log row must be a `Prune` line of the file, and no line may name a later
    // prune (as full verification matches a `Prune` line to a row); without a `Prune` line,
    // nothing was pruned.
    let bound = match cutoff {
        None => witness.prunes.is_empty(),
        Some(cutoff) => {
            let mut prunes = witness.prunes.iter();
            let named = prunes.clone().any(|(seq, hash, c)| {
                *seq == first_retained && ct_eq(hash, &last_pruned) && *c == cutoff
            });
            named && prunes.all(|(seq, ..)| *seq <= first_retained)
        }
    };
    if !bound {
        return Ok(false);
    }
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {}, record_hash FROM events WHERE seq = ?1",
            FIELD_LIST.join(", ")
        ))
        .map_err(sql)?;
    for (seq, line_hash) in named.iter().filter(|(seq, _)| *seq >= first_retained) {
        let Ok(at) = i64::try_from(*seq) else {
            return Ok(false);
        };
        let mut rows = stmt.query([at]).map_err(sql)?;
        let Some(r) = rows.next().map_err(sql)? else {
            return Ok(false);
        };
        let stored = match r.get_ref(FIELD_LIST.len()).map_err(sql)? {
            ValueRef::Blob(b) => <[u8; 32]>::try_from(b).ok(),
            _ => None,
        };
        let recomputed = RowFields::from_row(r).and_then(|f| f.record_hash()).ok();
        let genuine = matches!((stored, recomputed), (Some(s), Some(h))
            if ct_eq(&s, line_hash) && ct_eq(&h, &s));
        if !genuine {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `(chain_id, head_seq, stamp)` of an archive file name `audit-<chain_id>-<head_seq>-<stamp>.db`
/// as [`archive_and_start_fresh`] writes it; `None` for any other name (its WAL and `-shm` files,
/// a stray file).
fn parse_archive_name(name: &str) -> Option<(String, u64, String)> {
    let rest = name.strip_prefix("audit-")?.strip_suffix(".db")?;
    let (chain_id, rest) = rest.split_once('-')?;
    let (seq, stamp) = rest.split_once('-')?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let stamp_ok = !stamp.is_empty()
        && stamp
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'T' || b == b'Z');
    if !is_id(chain_id) || !digits(seq) || !stamp_ok {
        return None;
    }
    Some((chain_id.to_owned(), seq.parse().ok()?, stamp.to_owned()))
}

/// The archived store a first run in `data` names in its `GENESIS` when the one
/// [`archive_and_start_fresh`] returned is no longer in memory (a quit or crash between the archive
/// and the wizard's `GENESIS`; M6 T23, T20 review I-1): the newest
/// `archived/audit-<chain_id>-<head_seq>-<stamp>.db` by its UTC stamp (fixed width, so the text
/// order is the time order), with its head read again on a read-only connection and checked
/// against its name. No archive folder or no archive file: `Ok(None)`.
///
/// Called only while `data` holds no `audit.db`. The newest archive is never named by a `GENESIS`
/// yet: a chain that names an archive was started after that archive was made, so if it was
/// archived itself its file is the newer one. `Integrity` when the newest file's head does not
/// match its name.
pub fn latest_archived(data: &LocalDataDir) -> Result<Option<ArchivedDb>, OpenError> {
    let dir = data.path().join(ARCHIVE_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    // (stamp, file name, chain_id, head_seq) of the newest archive so far.
    let mut newest: Option<(String, String, String, u64)> = None;
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some((chain_id, seq, stamp)) = parse_archive_name(&name) else {
            continue;
        };
        if !entry.file_type()?.is_file() {
            continue;
        }
        let newer = newest
            .as_ref()
            .is_none_or(|(s, n, ..)| (stamp.as_str(), name.as_str()) > (s.as_str(), n.as_str()));
        if newer {
            newest = Some((stamp, name, chain_id, seq));
        }
    }
    let Some((_, name, chain_id, seq)) = newest else {
        return Ok(None);
    };
    let path = dir.join(&name);
    let head = plaintext_head(&path);
    // A read-only open of a store with a WAL may have created `-shm`; it is derived state.
    let _ = remove_if_present(&with_suffix(&path, "-shm"));
    let (head_seq, head_hash, head_chain) = head?;
    if head_chain != chain_id || head_seq != seq {
        return Err(OpenError::Integrity(
            "an archived store does not match its file name".into(),
        ));
    }
    Ok(Some(ArchivedDb {
        file: format!("{ARCHIVE_DIR}/{name}"),
        chain_id,
        head_seq,
        head_hash,
    }))
}
