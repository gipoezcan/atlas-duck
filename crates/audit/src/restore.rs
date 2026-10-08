//! Restore-as-continuation (§8.11) and "Finish restore" (§8.7 interrupted restore).
//!
//! A restore stages the source (a backup bundle, or a single DB file such as an `archived/`
//! store) into `<data>/audit.db.restoring` with `VACUUM INTO`, verifies the copy, opens its
//! KEK with the backup's recovery passphrase and writes `RESTORE` (and any `SCHEMA_MIGRATED`)
//! on the copy; until then nothing of the live store or the keychain changed (plan decision).
//! The "`RESTORE` commit" is one atomic rename of the staging file over `audit.db`; the
//! replaced store is kept as a hard link under `archived/` made just before (never deleted,
//! recoverable with its own passphrase through a later restore). Then the KEK is re-sealed
//! under this install's entries and the anchors are reset to the restored chain, a crash
//! between those steps being completed at the next start: by `open()` when the KEK was
//! re-sealed (interrupted restore), else by [`finish_restore`] with the restored store's
//! passphrase.
//!
//! In order (`restore_core` steps; the plan's 12 steps with the anchor-dir check after the
//! rollback check, which bounds it):
//!  1. stage: bundle files checked against the manifest (`ManifestMismatch`), `VACUUM INTO`
//!  2. the staging copy's versions (`SnapshotNewer`)
//!  3. its chain and `prune_log` from the first retained record; a bundle's head must be the
//!     manifest's (`ChainBroken`)
//!  4. its KEK from its `recovery` row (`WrongPassphrase`), the latest `PRUNE`, the head and
//!     every `RESTORE` decrypted and checked (`ChainBroken`)
//!  5. the keychain head anchor of this install (the anchor thread is held still): another
//!     chain is only recorded (`prior_keychain_anchor`); the snapshot's chain ahead of the
//!     snapshot is a same-machine rollback (`RollbackNeedsConfirmation`)
//!  6. the anchor-dir lines of the snapshot's chains (`AnchorDirMismatch`)
//!  7. on the staging copy, one transaction: `vault` dropped, migrations, a new DEK,
//!     `RESTORE`, `SCHEMA_MIGRATED`; vacuumed, back in WAL mode, closed with no `-wal`
//!  8. this install's PAT entries deleted for every instance of the live and the restored
//!     settings views (stored tokens are never restored, L53): before the commit, so no
//!     restored store ever opens next to a token of its instance ids
//!  9. the live store's connections closed, `archived/<name>` hard-linked to it, the staging
//!     file renamed over `audit.db` ← the `RESTORE` commit
//! 10. the KEK re-sealed (a failure stops a live store: the next start offers "Finish restore")
//! 11. the writer starts over on the restored store; the restore barrier is armed with the
//!     anchor reset (first-retained, then head, new `chain_id`), which the anchor thread
//!     retries with backoff (§8.11 step 5: never an incident)

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use atlas_duck_ipc::paths::LocalDataDir;
use rusqlite::OptionalExtension;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

use crate::anchor_dir::{self, AnchorDirLines, LostSpan};
use crate::anchors::{
    self, AnchorLoadError, Barrier, FirstRetainedAnchor, HeadAnchor, RestoreReset,
};
use crate::backup::{Manifest, RECOVERY_FILE, SNAPSHOT_FILE, file_sha256, sql_literal};
use crate::clock::Clock;
use crate::crypto::{Kek, KekEntryError, ct_eq};
use crate::encoding::ZERO_HASH;
use crate::error::{AuditError, OpenError, RestoreError};
use crate::keystore::{EntryName, KeyStore, KeyStoreError, KeyringLocality, canary_self_test};
use crate::lock::InstanceLock;
use crate::open::{
    ArchivedDb, RESTORING_DB_FILE, RecoveryOffer, audit_err, is_id, kek_opens_store,
    kek_unwraps_a_key, random_id, recovery_offer, remove_staging_leftovers, start_existing,
    sync_dir, with_suffix, with_written_by,
};
use crate::recover::{
    ARCHIVE_DIR, existing_db, file_len, file_stamp, plaintext_head, recovered_kek,
    remove_if_present,
};
use crate::recovery::{RecoveryError, open_recovery};
use crate::schema::{self, DB_FILE};
use crate::settings;
use crate::store::{Hooks, OpenConfig, Store};
use crate::types::{Committed, Confirmed, RustChosenPath};
use crate::verify::{self, StartupInputs, VerifyFinding, VerifyOutcome};
use crate::writer::{Shared, Writer, WriterParts, lock};

/// What a restore did (C.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    pub restore_seq: u64,
    pub new_chain_id: String,
    /// The snapshot's store `install_id` (§8.6); empty when no retained record names one and
    /// the source is not a bundle (`RESTORE.source_install_id` is then `null`).
    pub source_install_id: String,
    pub source_chain_id: String,
    /// The live store that was moved aside (`archived/…`), if there was one.
    pub replaced_db: Option<ArchivedDb>,
    pub records_lost: u64,
    /// Always `true` in v1: stored tokens are never restored.
    pub pats_lost: bool,
    /// Instance ids whose `pat/<id>` entry of this install was deleted (absent entries
    /// included): every one needs its token again. M3 logs `INSTANCE_STATE_CHANGED
    /// {needs_token}` for them.
    pub pats_deleted: Vec<String>,
}

fn restore_err(e: RestoreError) -> AuditError {
    AuditError::Restore(e)
}

fn sql(e: rusqlite::Error) -> AuditError {
    AuditError::Io(format!("database error: {e}"))
}

fn io_err(e: io::Error) -> AuditError {
    AuditError::Io(e.to_string())
}

fn open_to_audit(e: OpenError) -> AuditError {
    match e {
        OpenError::KeyStore(k) => AuditError::KeyStore(k),
        OpenError::Restore(r) => AuditError::Restore(r),
        other => AuditError::Io(other.to_string()),
    }
}

/// The C.3 error of `restore_from_source`/`finish_restore` for a step that reports an
/// `AuditError`.
fn audit_to_open(e: AuditError) -> OpenError {
    match e {
        AuditError::Restore(r) => OpenError::Restore(r),
        other => audit_err(other),
    }
}

/// `kind: detail (seq)` of the first finding.
fn summary(findings: &[VerifyFinding]) -> String {
    findings.first().map_or_else(String::new, |f| {
        let at = f.observed_seq.or(f.expected_seq);
        match at {
            Some(seq) => format!("{} at seq {seq}: {}", f.kind.as_str(), f.detail),
            None => format!("{}: {}", f.kind.as_str(), f.detail),
        }
    })
}

/// Removes `path` and its SQLite side files.
fn remove_db_files(path: &Path) -> io::Result<()> {
    for p in [
        path.to_path_buf(),
        with_suffix(path, "-wal"),
        with_suffix(path, "-shm"),
        with_suffix(path, "-journal"),
    ] {
        remove_if_present(&p)?;
    }
    Ok(())
}

/// The staging copy; deleted (with its side files) when dropped, which after the commit
/// rename finds nothing left to delete.
struct Staging {
    path: PathBuf,
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = remove_db_files(&self.path);
    }
}

/// A verified restore source (steps 1–4), held as the staging copy.
struct Staged {
    staging: Staging,
    kek: Kek,
    head_seq: u64,
    head_hash: [u8; 32],
    chain_id: String,
    /// `(first_retained_seq, last_pruned_record_hash)` of its latest `prune_log` row.
    first_retained: (u64, [u8; 32]),
    /// The retained `GENESIS`, else the manifest's value, else zero (informational once
    /// `GENESIS` is pruned).
    genesis_hash: [u8; 32],
    source_install_id: Option<String>,
    backup_created_at: Option<String>,
}

/// A store's head as its plaintext columns name it.
struct LiveHead {
    seq: u64,
    hash: [u8; 32],
    chain_id: String,
}

/// Steps 1–4. Writes nothing but the staging file, which every error path deletes.
fn stage(
    data_dir: &Path,
    source: &Path,
    passphrase: &SecretString,
    schema_head: u32,
) -> Result<Staged, AuditError> {
    // 1. The source: a bundle's files must be the manifest's.
    let (snapshot, manifest) = if source.is_dir() {
        let m = Manifest::read(source).map_err(restore_err)?;
        if m.user_version > schema_head {
            return Err(restore_err(RestoreError::SnapshotNewer {
                found: format!("user_version {}", m.user_version),
            }));
        }
        let snapshot = source.join(SNAPSHOT_FILE);
        let matches =
            |file: &Path, want: &[u8; 32]| file_sha256(file).is_ok_and(|h| ct_eq(&h, want));
        if !matches(&snapshot, &m.snapshot_sha256)
            || !matches(&source.join(RECOVERY_FILE), &m.recovery_sha256)
        {
            return Err(restore_err(RestoreError::ManifestMismatch));
        }
        (snapshot, Some(m))
    } else if source.is_file() {
        (source.to_path_buf(), None)
    } else {
        return Err(restore_err(RestoreError::NotABundle));
    };
    let staging = Staging {
        path: data_dir.join(RESTORING_DB_FILE),
    };
    remove_db_files(&staging.path).map_err(io_err)?;
    {
        // Read-only and sidecar-free when the source has no WAL (a bundle never has one); an
        // archived store's WAL is read with it.
        let not_a_db = |_| restore_err(RestoreError::NotABundle);
        let src = schema::open_peek(&snapshot).map_err(not_a_db)?;
        src.execute_batch(&format!("VACUUM INTO {}", sql_literal(&staging.path)?))
            .map_err(|e| match e.sqlite_error_code() {
                Some(rusqlite::ErrorCode::NotADatabase) => restore_err(RestoreError::NotABundle),
                _ => sql(e),
            })?;
    }
    // 2. Versions (§8.13): a snapshot of a newer build is refused before anything else.
    let versions = schema::read_versions(&staging.path).map_err(open_to_audit)?;
    if let Err(found) = schema::gate_up_to(&versions, schema_head) {
        return Err(restore_err(RestoreError::SnapshotNewer { found }));
    }
    // 3. The chain, plaintext only.
    let conn = schema::open_peek(&staging.path).map_err(open_to_audit)?;
    let findings = verify::snapshot_chain(&conn).map_err(sql)?;
    if !findings.is_empty() {
        return Err(restore_err(RestoreError::ChainBroken(summary(&findings))));
    }
    let head: Option<(i64, Vec<u8>, String)> = conn
        .query_row(
            "SELECT seq, record_hash, chain_id FROM events ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(sql)?;
    let broken = |m: &str| restore_err(RestoreError::ChainBroken(m.into()));
    let (head_seq, head_hash, chain_id) = match head {
        Some((s, h, c)) => (
            u64::try_from(s).map_err(|_| broken("the head seq is negative"))?,
            <[u8; 32]>::try_from(h).map_err(|_| broken("the head record_hash is not 32 bytes"))?,
            c,
        ),
        None => return Err(broken("the backup has no records")),
    };
    if !is_id(&chain_id) {
        return Err(broken(
            "the head chain_id is not 32 lowercase hex characters",
        ));
    }
    let first_retained = verify::latest_prune_values(&conn).map_err(sql)?;
    if let Some(m) = &manifest {
        if m.head_seq != head_seq || !ct_eq(&m.head_hash, &head_hash) {
            return Err(broken("the snapshot does not end at the manifest's head"));
        }
        if m.chain_id != chain_id
            || m.first_retained_seq != first_retained.0
            || !ct_eq(&m.first_retained_prev_hash, &first_retained.1)
        {
            return Err(restore_err(RestoreError::ManifestMismatch));
        }
    }
    // 4. The KEK sealed in the snapshot (§8.11 step 2).
    let blob: Option<Vec<u8>> = conn
        .query_row("SELECT blob FROM recovery WHERE id = 1", [], |r| r.get(0))
        .optional()
        .map_err(sql)?;
    let blob = blob.ok_or_else(|| broken("the backup has no recovery row"))?;
    if manifest.is_some() && std::fs::read(source.join(RECOVERY_FILE)).map_err(io_err)? != blob {
        return Err(restore_err(RestoreError::ManifestMismatch));
    }
    let kek = open_recovery(passphrase, &blob).map_err(|e| match e {
        RecoveryError::WrongPassphrase => restore_err(RestoreError::WrongPassphrase),
        RecoveryError::NewerLayout(n) => restore_err(RestoreError::SnapshotNewer {
            found: format!("recovery layout {n}"),
        }),
        RecoveryError::Malformed => broken("the recovery blob is malformed"),
        RecoveryError::KdfFailed => AuditError::Io("recovery key derivation failed".into()),
    })?;
    if !kek_unwraps_a_key(&conn, &kek).map_err(open_to_audit)? {
        return Err(broken(
            "the recovered KEK opens none of the backup's data keys",
        ));
    }
    let keyed = verify::snapshot_keyed(&conn, &kek).map_err(sql)?;
    if !keyed.is_empty() {
        return Err(restore_err(RestoreError::ChainBroken(summary(&keyed))));
    }
    let mut source_install_id = verify::store_install_id(&conn).map_err(sql)?;
    if let Some(m) = &manifest {
        match &source_install_id {
            Some(id) if *id != m.install_id => {
                return Err(restore_err(RestoreError::ManifestMismatch));
            }
            Some(_) => {}
            None => source_install_id = Some(m.install_id.clone()),
        }
    }
    let genesis_hash = verify::retained_genesis_hash(&conn)
        .map_err(sql)?
        .or(manifest.as_ref().map(|m| m.genesis_hash))
        .unwrap_or(ZERO_HASH);
    drop(conn);
    Ok(Staged {
        staging,
        kek,
        head_seq,
        head_hash,
        chain_id,
        first_retained,
        genesis_hash,
        source_install_id,
        backup_created_at: manifest.map(|m| m.created_at),
    })
}

/// This install's keychain head anchor (read only). A newer layout or an unreadable keychain
/// stops the restore: what it records as `prior_keychain_anchor` must be what is there.
fn read_prior(keys: &dyn KeyStore) -> Result<Option<HeadAnchor>, AuditError> {
    match anchors::load_head(keys) {
        Ok(a) => Ok(a),
        Err(AnchorLoadError::KeyStore(e)) => Err(AuditError::KeyStore(e)),
        Err(AnchorLoadError::Newer(n)) => Err(AuditError::Io(format!(
            "the keychain head anchor has the newer layout {n}"
        ))),
    }
}

/// Step 5 (§8.11 step 4): records of the snapshot's chain beyond its head (by this install's
/// head anchor, and by a live store of the same chain) would be lost: a confirmation is
/// needed. An anchor or store of another chain is never compared.
fn records_lost(
    staged: &Staged,
    prior: Option<&HeadAnchor>,
    live: Option<&LiveHead>,
    confirm: Option<&Confirmed>,
) -> Result<u64, RestoreError> {
    let beyond = |chain: &str, seq: u64| {
        if chain == staged.chain_id {
            seq.saturating_sub(staged.head_seq)
        } else {
            0
        }
    };
    let lost = prior
        .map_or(0, |a| beyond(&a.chain_id, a.seq))
        .max(live.map_or(0, |l| beyond(&l.chain_id, l.seq)));
    if lost > 0 && confirm.is_none() {
        return Err(RestoreError::RollbackNeedsConfirmation { records_lost: lost });
    }
    Ok(lost)
}

/// Step 6: the snapshot against the anchor dir's lines for its chains, when one is configured.
/// Lines of the snapshot's chain for the records a confirmed rollback gives up are accounted
/// for exactly as the `RESTORE` will record them (`prior`, `records_lost`).
fn check_anchor_dir(
    staged: &Staged,
    dir: Option<&Path>,
    prior: Option<&HeadAnchor>,
    records_lost: u64,
) -> Result<(), AuditError> {
    let conn = schema::open_peek(&staged.staging.path).map_err(open_to_audit)?;
    let lines: Option<AnchorDirLines> = anchor_dir::load(dir, &conn).map_err(open_to_audit)?;
    let rollback = LostSpan::of(
        &staged.chain_id,
        staged.head_seq,
        prior.map(|a| (a.chain_id.as_str(), a.seq)),
        records_lost,
    );
    let found =
        verify::snapshot_anchor_dir(&conn, &staged.kek, lines.as_ref(), rollback).map_err(sql)?;
    if !found.is_empty() {
        return Err(restore_err(RestoreError::AnchorDirMismatch(summary(
            &found,
        ))));
    }
    Ok(())
}

/// The archive name of a live store about to be replaced (F.1).
fn replaced_name(live: &LiveHead) -> Result<ArchivedDb, AuditError> {
    if !is_id(&live.chain_id) {
        return Err(AuditError::Invalid(
            "the live store's chain_id is not 32 lowercase hex characters",
        ));
    }
    let stamp = file_stamp().map_err(open_to_audit)?;
    Ok(ArchivedDb {
        file: format!(
            "{ARCHIVE_DIR}/audit-{}-{}-{stamp}.db",
            live.chain_id, live.seq
        ),
        chain_id: live.chain_id.clone(),
        head_seq: live.seq,
        head_hash: live.hash,
    })
}

/// The decisions the `RESTORE` record carries.
struct Plan {
    install_id: String,
    new_chain_id: String,
    prior: Option<HeadAnchor>,
    replaced_db: Option<ArchivedDb>,
    records_lost: u64,
}

/// `RESTORE` (F.11, §8.11 step 5 fields verbatim).
fn restore_payload(staged: &Staged, plan: &Plan) -> Value {
    json!({
        "install_id": plan.install_id,
        "source_install_id": staged.source_install_id,
        "source_chain_id": staged.chain_id,
        "source_head_seq": staged.head_seq,
        "source_head_hash": hex::encode(staged.head_hash),
        "new_chain_id": plan.new_chain_id,
        "backup_created_at": staged.backup_created_at,
        "prior_keychain_anchor": plan.prior.as_ref().map(|a| json!({
            "chain_id": a.chain_id,
            "seq": a.seq,
            "record_hash": hex::encode(a.record_hash),
        })),
        "replaced_db": plan.replaced_db.as_ref().map(|r| json!({
            "file": r.file,
            "chain_id": r.chain_id,
            "head_seq": r.head_seq,
            "head_hash": hex::encode(r.head_hash),
        })),
        "records_lost": plan.records_lost,
        "pats_lost": true,
    })
}

/// What step 7 wrote.
struct Written {
    restore: Committed,
    head: Committed,
    /// The instance ids of the restored settings view (best effort when untrusted: deleting a
    /// PAT only ever asks for the token again).
    instances: Vec<String>,
}

/// Step 7, on a writer of its own over the staging copy (KEK of the snapshot).
fn write_staging(
    staged: &Staged,
    plan: &Plan,
    clock: Arc<dyn Clock>,
    hooks: &Hooks,
) -> Result<Written, AuditError> {
    let parts = WriterParts {
        clock,
        kek: staged.kek.clone(),
        shared: Shared::new(&staged.kek),
        hooks: hooks.clone(),
        genesis_hash: Some(staged.genesis_hash),
    };
    let mut w = Writer::open(&staged.staging.path, parts).map_err(open_to_audit)?;
    let instances = w.st.settings.instances.keys().cloned().collect();
    let start = schema::user_version(&w.conn).map_err(sql)?;
    let steps = schema::pending_steps(start, &hooks.migrations()).map_err(open_to_audit)?;
    let (restore, head) = w.write_restore(
        &restore_payload(staged, plan),
        &plan.install_id,
        &plan.new_chain_id,
        &steps,
    )?;
    w.finish_staging(&staged.staging.path)?;
    Ok(Written {
        restore,
        head,
        instances,
    })
}

/// Step 8: deletes this install's PAT entries of `ids`.
fn delete_pats(keys: &dyn KeyStore, ids: &BTreeSet<String>) -> Result<Vec<String>, AuditError> {
    for id in ids {
        keys.delete(&EntryName::Pat(id.clone()))?;
    }
    Ok(ids.iter().cloned().collect())
}

/// Step 9, every connection to `audit.db` closed: the replaced store becomes
/// `archived/<name>` (a hard link, so `audit.db` stays the live store until the rename), then
/// the staging file is renamed over `audit.db` (atomic) ← the `RESTORE` commit. A WAL that
/// still holds frames refuses (renaming it with the store is not atomic, and it must never
/// meet the restored file). Before the rename every error leaves the live store as it was.
fn commit_swap(
    data_dir: &Path,
    staging: &Path,
    replaced: Option<&ArchivedDb>,
) -> Result<(), AuditError> {
    let db = data_dir.join(DB_FILE);
    let wal = with_suffix(&db, "-wal");
    let mut linked: Option<PathBuf> = None;
    match replaced {
        Some(r) => {
            if file_len(&wal).map_err(io_err)?.is_some_and(|n| n > 0) {
                return Err(AuditError::Io(
                    "the live store's write-ahead log is not empty (is it still open?)".into(),
                ));
            }
            remove_if_present(&wal).map_err(io_err)?;
            remove_if_present(&with_suffix(&db, "-shm")).map_err(io_err)?;
            let dir = data_dir.join(ARCHIVE_DIR);
            std::fs::create_dir_all(&dir).map_err(io_err)?;
            let target = data_dir.join(&r.file);
            for p in [
                &target,
                &with_suffix(&target, "-wal"),
                &with_suffix(&target, "-shm"),
            ] {
                if p.try_exists().map_err(io_err)? {
                    return Err(AuditError::Io(format!("{} already exists", r.file)));
                }
            }
            std::fs::hard_link(&db, &target).map_err(io_err)?;
            linked = Some(target);
            if let Err(e) = sync_dir(&dir) {
                let _ = linked.as_deref().map(std::fs::remove_file);
                return Err(io_err(e));
            }
        }
        None => {
            if db.try_exists().map_err(io_err)? || wal.try_exists().map_err(io_err)? {
                return Err(AuditError::Io(
                    "audit.db appeared during the restore".into(),
                ));
            }
        }
    }
    if let Err(e) = std::fs::rename(staging, &db) {
        if let Some(t) = &linked {
            let _ = std::fs::remove_file(t);
        }
        return Err(io_err(e));
    }
    // From here on the restored store is the store; a failed dir sync is not undone.
    sync_dir(data_dir).map_err(io_err)
}

/// A fault point of the `testing` hooks (a simulated crash); `Ok` in release builds.
macro_rules! crash {
    ($hooks:expr, $point:ident) => {{
        #[cfg(any(test, feature = "testing"))]
        let r = $hooks.fault(crate::testing::FaultPoint::$point);
        #[cfg(not(any(test, feature = "testing")))]
        let r: Result<(), AuditError> = {
            let _ = &$hooks;
            Ok(())
        };
        r
    }};
}

/// The anchors the reset writes for the restored store (§8.11 step 5).
fn reset_for(staged: &Staged, plan: &Plan, written: &Written) -> RestoreReset {
    RestoreReset {
        head: HeadAnchor {
            chain_id: plan.new_chain_id.clone(),
            seq: written.head.seq,
            record_hash: written.head.record_hash,
        },
        first_retained: FirstRetainedAnchor {
            chain_id: plan.new_chain_id.clone(),
            genesis_hash: staged.genesis_hash,
            first_retained_seq: staged.first_retained.0,
            first_retained_prev_hash: staged.first_retained.1,
        },
    }
}

fn report(staged: &Staged, plan: Plan, written: &Written, pats: Vec<String>) -> RestoreReport {
    RestoreReport {
        restore_seq: written.restore.seq,
        new_chain_id: plan.new_chain_id,
        source_install_id: staged.source_install_id.clone().unwrap_or_default(),
        source_chain_id: staged.chain_id.clone(),
        replaced_db: plan.replaced_db,
        records_lost: plan.records_lost,
        pats_lost: true,
        pats_deleted: pats,
    }
}

// ---------------------------------------------------------------------------------------
// Store::restore (a live store; on its writer thread)

/// `Store::restore`'s inputs for the writer.
pub(crate) struct RestoreRequest {
    pub(crate) source: PathBuf,
    pub(crate) passphrase: SecretString,
    pub(crate) confirm: Option<Confirmed>,
    pub(crate) keys: Arc<dyn KeyStore>,
    pub(crate) data_dir: PathBuf,
    /// `OpenConfig.anchor_dir` (used while the store's own setting names none).
    pub(crate) anchor_dir: Option<PathBuf>,
    pub(crate) install_id: String,
}

impl RestoreRequest {
    pub(crate) fn new(
        source: &RustChosenPath,
        passphrase: &SecretString,
        confirm: Option<Confirmed>,
        keys: Arc<dyn KeyStore>,
        data_dir: PathBuf,
        anchor_dir: Option<PathBuf>,
        install_id: String,
    ) -> RestoreRequest {
        RestoreRequest {
            source: source.path().to_path_buf(),
            passphrase: SecretString::from(passphrase.expose_secret().to_owned()),
            confirm,
            keys,
            data_dir,
            anchor_dir,
            install_id,
        }
    }
}

/// Puts the barrier the restore replaced back unless the restore committed.
struct HeldBarrier<'a> {
    anchors: &'a crate::anchors::AnchorShared,
    old: Option<Option<Barrier>>,
}

impl HeldBarrier<'_> {
    /// The restore committed: its barrier stays until the reset lifts it.
    fn keep(&mut self) {
        self.old = None;
    }
}

impl Drop for HeldBarrier<'_> {
    fn drop(&mut self) {
        if let Some(old) = self.old.take() {
            self.anchors.restore_barrier(old);
        }
    }
}

impl Writer {
    /// `Store::restore` (C.3, §8.11) on the writer thread, so no append interleaves; see the
    /// module doc for the steps. Before the commit rename every error leaves the live store,
    /// the keychain (but deleted PAT entries) and the anchor barrier as they were. After it a
    /// simulated crash or a failed KEK re-seal stops the writer (the next start completes the
    /// restore); a failed anchor reset is retried in the background.
    pub(crate) fn restore_run(&mut self, req: RestoreRequest) -> Result<RestoreReport, AuditError> {
        let staged = stage(
            &req.data_dir,
            &req.source,
            &req.passphrase,
            self.st.hooks.schema_head(),
        )?;
        let shared = self.st.shared.clone();
        // The keychain names the live head where it can (best effort), so the rollback check
        // counts what the store holds; then the anchor thread is held still while the anchor
        // is read and until the reset (a head write in between would not be the prior anchor
        // the RESTORE records).
        let _ = shared.anchors.flush();
        let restore_seq = staged.head_seq + 1;
        let old = shared.anchors.swap_barrier(Some(Barrier::Restore {
            seq: restore_seq,
            reset: None,
        }))?;
        let mut held = HeldBarrier {
            anchors: &shared.anchors,
            old: Some(old),
        };
        let prior = read_prior(&*req.keys)?;
        let live = LiveHead {
            seq: self.st.head.seq,
            hash: self.st.head.hash,
            chain_id: self.st.head.chain_id.clone(),
        };
        let lost = records_lost(&staged, prior.as_ref(), Some(&live), req.confirm.as_ref())
            .map_err(restore_err)?;
        let dir = anchor_dir::resolve(
            self.st.settings.anchor_dir.as_deref(),
            req.anchor_dir.as_deref(),
        );
        check_anchor_dir(&staged, dir.as_deref(), prior.as_ref(), lost)?;
        let plan = Plan {
            install_id: req.install_id.clone(),
            new_chain_id: random_id().map_err(open_to_audit)?,
            prior,
            replaced_db: Some(replaced_name(&live)?),
            records_lost: lost,
        };
        let written = write_staging(&staged, &plan, self.st.clock.clone(), &self.st.hooks)?;
        let mut ids: BTreeSet<String> = self.st.settings.instances.keys().cloned().collect();
        ids.extend(written.instances.iter().cloned());
        let pats = delete_pats(&*req.keys, &ids)?;

        // The commit: no connection to `audit.db` may stay open (the reader is held closed).
        let db = req.data_dir.join(DB_FILE);
        let mut reader = lock(&shared.reader);
        *reader = None;
        let swapped = self.close_live().and_then(|()| {
            commit_swap(
                &req.data_dir,
                &staged.staging.path,
                plan.replaced_db.as_ref(),
            )
        });
        if let Err(e) = swapped {
            // Nothing was replaced: the writer goes on with the live store.
            if self.reopen_live(&db).is_err() {
                self.st.crashed = true;
            }
            return Err(e);
        }
        held.keep();
        let after_commit = |w: &mut Writer, r: Result<(), AuditError>| {
            if r.is_err() {
                w.st.crashed = true;
            }
            r
        };
        let hooks = self.st.hooks.clone();
        after_commit(self, crash!(&hooks, AfterRestoreCommit))?;
        let sealed = req
            .keys
            .set(&EntryName::Kek, &staged.kek.to_entry_bytes())
            .map_err(AuditError::KeyStore);
        after_commit(self, sealed)?;
        after_commit(self, crash!(&hooks, AfterKekReseal))?;
        let reopened = self
            .reopen_on(&db, staged.kek.clone(), Some(staged.genesis_hash))
            .map_err(open_to_audit);
        after_commit(self, reopened)?;
        drop(reader);
        let reset = reset_for(&staged, &plan, &written);
        shared.anchors.publish_head(reset.head.clone());
        let rx = shared.anchors.arm_restore_reset(restore_seq, reset)?;
        let _ = shared.anchors.wait_reset(rx);
        drop(held);
        Ok(report(&staged, plan, &written, pats))
    }
}

// ---------------------------------------------------------------------------------------
// restore_from_source (no live store)

/// The locality rule before any keyring access (§8.6).
fn require_local(keys: &dyn KeyStore) -> Result<(), OpenError> {
    match keys.locality() {
        KeyringLocality::Local => Ok(()),
        KeyringLocality::NotLocal { .. } => Err(KeyStoreError::NotLocal.into()),
        KeyringLocality::Unknown { .. } => Err(KeyStoreError::Unavailable.into()),
    }
}

/// The instance ids of a live store this keychain opens (best effort: a locked store's view
/// cannot be read, and deleting a PAT only ever asks for the token again).
fn live_instances(db: &Path, keys: &dyn KeyStore) -> Vec<String> {
    let kek = match keys.get(&EntryName::Kek) {
        Ok(Some(b)) => match Kek::from_entry_bytes(&b) {
            Ok(k) => k,
            Err(_) => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    let Ok(conn) = schema::open_peek(db) else {
        return Vec::new();
    };
    if !kek_opens_store(&conn, &kek).unwrap_or(false) {
        return Vec::new();
    }
    settings::load_view(&conn, &kek)
        .map(|(v, _)| v.instances.keys().cloned().collect())
        .unwrap_or_default()
}

/// Checkpoints a closed live store whose WAL still holds frames (a crash left them), so the
/// store can be moved aside as one file. The frames are replayed into the file, nothing else
/// changes.
fn checkpoint_closed(db: &Path) -> Result<(), OpenError> {
    if file_len(&with_suffix(db, "-wal"))?.is_none_or(|n| n == 0) {
        return Ok(());
    }
    let conn = schema::open_rw(db)?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| OpenError::Sqlite(e.to_string()))?;
    conn.close()
        .map_err(|(_, e)| OpenError::Sqlite(e.to_string()))
}

/// Restore when no store of this data dir is running (C.3): a new machine (no `audit.db`,
/// `FirstRun`) or a live store that cannot be opened (locked). The steps are those of
/// [`Store::restore`] (module doc); the live store, if any, is moved to `archived/` at the
/// commit and recorded as `replaced_db`, and its PAT entries are deleted only when this
/// keychain still opens it (a locked store's instances cannot be read). The KEK is re-sealed
/// under `cfg.keys`' install, which the restored store keeps (`RESTORE.install_id`). Returns the
/// running store (anchor writes enabled, the reset armed) and the report.
///
/// Errors before the commit leave the data dir and the keychain as they were (but deleted PAT
/// entries): `Restore(..)` for the source, `KeyStore` for the keychain, `Invalid` for a lock of
/// another data dir. After the commit, an `Err` means the restore must be completed by the
/// next start (`open`: interrupted restore, or "Finish restore").
pub fn restore_from_source(
    data: &LocalDataDir,
    lock: &InstanceLock,
    cfg: OpenConfig,
    source: RustChosenPath,
    passphrase: &SecretString,
    confirm_rollback: Option<Confirmed>,
) -> Result<(Store, RestoreReport), OpenError> {
    if lock.path().parent() != Some(data.path()) {
        return Err(OpenError::Invalid("instance.lock of another data dir"));
    }
    remove_staging_leftovers(data)?;
    let db = schema::db_path(data);
    let live = if db.try_exists()? {
        let (seq, hash, chain_id) = plaintext_head(&db)?;
        Some(LiveHead {
            seq,
            hash,
            chain_id,
        })
    } else {
        if with_suffix(&db, "-wal").try_exists()? {
            return Err(OpenError::Integrity(
                "audit.db-wal exists without audit.db".into(),
            ));
        }
        None
    };
    require_local(&*cfg.keys)?;
    let staged = stage(
        data.path(),
        source.path(),
        passphrase,
        cfg.hooks.schema_head(),
    )
    .map_err(audit_to_open)?;
    canary_self_test(&*cfg.keys)?;
    let prior = read_prior(&*cfg.keys).map_err(audit_to_open)?;
    let lost = records_lost(
        &staged,
        prior.as_ref(),
        live.as_ref(),
        confirm_rollback.as_ref(),
    )?;
    check_anchor_dir(&staged, cfg.anchor_dir.as_deref(), prior.as_ref(), lost)
        .map_err(audit_to_open)?;
    let plan = Plan {
        install_id: cfg.keys.install_id().to_string(),
        new_chain_id: random_id()?,
        prior,
        replaced_db: live
            .as_ref()
            .map(replaced_name)
            .transpose()
            .map_err(audit_to_open)?,
        records_lost: lost,
    };
    let written =
        write_staging(&staged, &plan, cfg.clock.clone(), &cfg.hooks).map_err(audit_to_open)?;
    let mut ids: BTreeSet<String> = written.instances.iter().cloned().collect();
    if live.is_some() {
        ids.extend(live_instances(&db, &*cfg.keys));
    }
    let pats = delete_pats(&*cfg.keys, &ids).map_err(audit_to_open)?;
    if live.is_some() {
        checkpoint_closed(&db)?;
    }
    commit_swap(data.path(), &staged.staging.path, plan.replaced_db.as_ref())
        .map_err(audit_to_open)?;
    crash!(&cfg.hooks, AfterRestoreCommit).map_err(audit_to_open)?;
    cfg.keys
        .set(&EntryName::Kek, &staged.kek.to_entry_bytes())?;
    crash!(&cfg.hooks, AfterKekReseal).map_err(audit_to_open)?;
    let store = start_existing(data, cfg, staged.kek.clone(), Some(staged.genesis_hash))?;
    let reset = reset_for(&staged, &plan, &written);
    if let Err(e) = store.start_restore_reset(written.restore.seq, reset) {
        store.shutdown();
        return Err(audit_err(e));
    }
    // Advisory (§8.13): the restore itself is complete, its report must reach the caller.
    let _ = store.update_written_by();
    let report = report(&staged, plan, &written, pats);
    Ok((store, report))
}

// ---------------------------------------------------------------------------------------
// Finish restore (§8.7)

/// "Finish restore" (§8.7, `RecoveryOffer::FinishRestore`): the newest record is a `RESTORE`
/// of this install whose KEK re-seal did not happen (a crash right after the commit), so the
/// keychain KEK does not open the store. In order: leftover staging files deleted; `audit.db`
/// must exist; the version gate (`NewerStore`); keyring locality; the newest record must be
/// that `RESTORE` (`Integrity`); its KEK from the store's `recovery` row with the restored
/// store's passphrase (`WrongPassphrase`, nothing written) and it must open a data key
/// (`Integrity`); the canary; a keychain KEK that already opens the store is `Invalid` (`open`
/// completes that restore); the startup verification must reconcile the interrupted restore
/// (`Integrity` otherwise, also while the anchor dir cannot be read: finish once it can). Then
/// the KEK is re-sealed, the writer starts, pending migrations run, `VERIFY {result:
/// interrupted_restore_reconciled}` is appended and the anchor reset armed (as `open` does).
/// The PAT entries were deleted before the restore committed.
pub fn finish_restore(
    data: &LocalDataDir,
    lock: &InstanceLock,
    cfg: OpenConfig,
    passphrase: &SecretString,
) -> Result<(Store, VerifyOutcome), OpenError> {
    if lock.path().parent() != Some(data.path()) {
        return Err(OpenError::Invalid("instance.lock of another data dir"));
    }
    remove_staging_leftovers(data)?;
    let db = existing_db(data)?;
    let versions = schema::read_versions(&db)?;
    if let Err(found) = schema::gate_up_to(&versions, cfg.hooks.schema_head()) {
        return Err(OpenError::NewerStore(with_written_by(found, &versions)));
    }
    require_local(&*cfg.keys)?;
    let ro = schema::open_peek(&db)?;
    if recovery_offer(&ro, cfg.keys.install_id())? != RecoveryOffer::FinishRestore {
        return Err(OpenError::Integrity(
            "the newest record is not an unfinished RESTORE of this install".into(),
        ));
    }
    let kek = recovered_kek(&ro, passphrase)?;
    if !kek_unwraps_a_key(&ro, &kek)? {
        return Err(OpenError::Integrity(
            "the recovered KEK opens none of the store's data keys".into(),
        ));
    }
    canary_self_test(&*cfg.keys)?;
    match cfg.keys.get(&EntryName::Kek) {
        Ok(None) | Err(KeyStoreError::Corrupt) => {}
        Err(e) => return Err(e.into()),
        Ok(Some(b)) => match Kek::from_entry_bytes(&b) {
            Ok(current) if kek_opens_store(&ro, &current)? => {
                return Err(OpenError::Invalid(
                    "the keychain KEK opens this store: open() completes the restore",
                ));
            }
            Ok(_) | Err(KekEntryError::Malformed) => {}
            Err(KekEntryError::NewerLayout(n)) => {
                return Err(OpenError::NewerStore(format!("keychain kek layout {n}")));
            }
        },
    }
    let (head_anchor, first_retained) = match anchors::load_anchors(&*cfg.keys) {
        Ok(a) => a,
        Err(AnchorLoadError::Newer(n)) => {
            return Err(OpenError::NewerStore(format!("keychain anchor layout {n}")));
        }
        Err(AnchorLoadError::KeyStore(e)) => return Err(e.into()),
    };
    let (view, view_trusted) = settings::load_view(&ro, &kek)?;
    let dir = anchor_dir::resolve(view.anchor_dir.as_deref(), cfg.anchor_dir.as_deref());
    let mut anchor_lines = anchor_dir::load(dir.as_deref(), &ro)?;
    if !view_trusted {
        AnchorDirLines::note_setting_unreadable(&mut anchor_lines);
    }
    let verdict = verify::startup(&StartupInputs {
        conn: &ro,
        kek: &kek,
        head_anchor,
        first_retained,
        store_install_id: verify::store_install_id(&ro).map_err(crate::open::sql)?,
        pinned_install_id: cfg.pinned_install_id.clone(),
        anchor_lines,
    })?;
    drop(ro);
    let Some(rc) = verdict.anchor_actions.complete_restore.clone() else {
        return Err(OpenError::Integrity(
            if verdict.anchor_actions.defer_restore.is_some() {
                "the anchor directory could not be read: finish the restore once it can".into()
            } else {
                format!(
                    "the store is not an interrupted restore ({})",
                    summary(&verdict.findings)
                )
            },
        ));
    };
    // Re-seal first: a VERIFY appended before a failed re-seal would make the newest record
    // not the RESTORE, and the next start would offer "Recover this log" instead.
    cfg.keys.set(&EntryName::Kek, &kek.to_entry_bytes())?;
    let store = start_existing(data, cfg, kek, Some(rc.first_retained.genesis_hash))?;
    let finish = || -> Result<VerifyOutcome, OpenError> {
        store.run_migrations()?;
        let verify = store.apply_startup(&verdict).map_err(audit_err)?;
        let _ = store.update_written_by();
        Ok(verify)
    };
    match finish() {
        Ok(verify) => Ok((store, verify)),
        Err(e) => {
            store.shutdown();
            Err(e)
        }
    }
}
