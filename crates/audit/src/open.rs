//! Startup (§8.7 steps 1–4) and first run (§2.5 step (1b), §8.4, §8.6). `open` runs the
//! version gate, the keychain cases and the pre-migration verification of an existing store,
//! then migrations, the startup `VERIFY` and only then anchor writes. `create_new_store` writes
//! a new store whose first record is `GENESIS`.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use atlas_duck_ipc::paths::LocalDataDir;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension};
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::anchor_dir::{self, AnchorDirLines};
use crate::anchors::{self, AnchorLoadError, FirstRetainedAnchor, HeadAnchor};
use crate::crypto::{self, Kek, KekEntryError, fill_random};
use crate::encoding::ZERO_HASH;
use crate::error::{AuditError, OpenError};
use crate::keystore::{EntryName, KeyStore, KeyStoreError, KeyringLocality, canary_self_test};
use crate::lock::InstanceLock;
use crate::recovery::{check_new_passphrase, new_recovery_blob};
use crate::schema::{self, StoreVersions};
use crate::settings;
use crate::store::{AnchorInit, OpenConfig, Store};
use crate::verify::{self, StartupInputs, StartupVerdict, VerifyOutcome};
use crate::writer::{Writer, WriterParts};

/// First-run staging file: the new DB is renamed to `audit.db` only once `GENESIS` committed
/// (plan decision), so a crash never leaves an `audit.db` without `GENESIS`.
pub const NEW_DB_FILE: &str = "audit.db.new";

/// Restore staging file (F.1); a leftover is deleted at the next start.
pub const RESTORING_DB_FILE: &str = "audit.db.restoring";

/// Why the store is not served (§4.3 `details.reason`, exit 9). While locked nothing after
/// startup step 2 runs: no migration, no write (§8.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockedReason {
    /// The keychain did not answer (or is locked): retry with [`keychain_retry_schedule`].
    KeychainUnavailable,
    /// This install's KEK is absent or does not open the store (§8.7 keychain cases).
    KeychainLost { offer: RecoveryOffer },
    /// The keyring's backing files are not on a local disk (§8.6); no keyring entry was read.
    KeyringNotLocal,
}

impl LockedReason {
    /// `keychain_unavailable` | `keychain_lost` | `keyring_not_local` (§4.3).
    pub fn as_str(&self) -> &'static str {
        match self {
            LockedReason::KeychainUnavailable => "keychain_unavailable",
            LockedReason::KeychainLost { .. } => "keychain_lost",
            LockedReason::KeyringNotLocal => "keyring_not_local",
        }
    }
}

/// Which credential-window purpose M6 shows for `keychain_lost` (§8.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOffer {
    /// "Recover this log" with the store's recovery passphrase.
    RecoverThisLog,
    /// The newest record is a `RESTORE` of this install whose KEK re-seal did not happen:
    /// "Finish restore" with the restored store's recovery passphrase.
    FinishRestore,
}

/// What `open` found (C.3).
#[derive(Debug)]
pub enum StartupOutcome {
    /// Verified and serving; `verify` is the startup verification (its `VERIFY` row, if any).
    /// `pats_deleted`: the instance ids whose `pat/<id>` entries this start deleted because it
    /// completed (or deferred) an unfinished restore whose `RESTORE` is still the newest record
    /// (L53); every one needs its token again, and M3 logs `INSTANCE_STATE_CHANGED
    /// {needs_token}` for each (PD-28). Empty on every other start.
    Ready {
        store: Store,
        verify: VerifyOutcome,
        pats_deleted: Vec<String>,
    },
    /// No `audit.db` in the data dir (§2.5).
    FirstRun,
    Locked(LockedReason),
    /// Written by a newer build (§8.13); nothing was written. `found` names what is newer and,
    /// when recorded, the version that wrote the store.
    StoreNewer {
        found: String,
    },
}

/// The delays between `open` attempts while it returns `Locked(KeychainUnavailable)`: 90 s in
/// all, inside the 60–120 s window of §8.7 (plan decision). The app then stays locked and
/// offers a manual retry.
pub fn keychain_retry_schedule() -> &'static [Duration] {
    const SCHEDULE: [Duration; 6] = [
        Duration::from_secs(2),
        Duration::from_secs(4),
        Duration::from_secs(8),
        Duration::from_secs(16),
        Duration::from_secs(30),
        Duration::from_secs(30),
    ];
    &SCHEDULE
}

/// What the wizard collected (§2.5 step (1b)): ids from [`new_ids`], the recovery passphrase
/// typed twice, and the archived DB when started fresh beside one (§8.7).
pub struct FirstRunInput {
    pub install_id: String,
    pub chain_id: String,
    pub passphrase: SecretString,
    pub passphrase_confirm: SecretString,
    pub archived_db: Option<ArchivedDb>,
}

/// `GENESIS.archived_db` (F.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedDb {
    /// Relative to the data dir, `/` separators.
    pub file: String,
    pub chain_id: String,
    pub head_seq: u64,
    pub head_hash: [u8; 32],
}

pub(crate) fn random_id() -> Result<String, OpenError> {
    let mut b = [0u8; 16];
    fill_random(&mut b).map_err(|_| OpenError::Io(io::Error::other("OS random source failed")))?;
    Ok(hex::encode(b))
}

/// `(install_id, chain_id)`: 16 random bytes each, lowercase hex (F.1).
pub fn new_ids() -> Result<(String, String), OpenError> {
    Ok((random_id()?, random_id()?))
}

pub(crate) fn is_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Deletes `file` in the data dir and its SQLite side files.
fn remove_with_side_files(data: &LocalDataDir, file: &str) -> io::Result<()> {
    let path = data.path().join(file);
    for p in [
        path.clone(),
        with_suffix(&path, "-wal"),
        with_suffix(&path, "-shm"),
        with_suffix(&path, "-journal"),
    ] {
        match std::fs::remove_file(&p) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

/// Deletes a leftover `audit.db.new` and its SQLite side files (never `audit.db`).
pub(crate) fn remove_new_leftovers(data: &LocalDataDir) -> io::Result<()> {
    remove_with_side_files(data, NEW_DB_FILE)
}

/// Deletes the staging files a crashed first run or restore left (never `audit.db`): neither
/// ever counts as a store.
pub(crate) fn remove_staging_leftovers(data: &LocalDataDir) -> io::Result<()> {
    remove_new_leftovers(data)?;
    remove_with_side_files(data, RESTORING_DB_FILE)
}

/// Makes a rename inside `dir` durable (Unix); NTFS journals the rename itself.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

pub(crate) fn audit_err(e: AuditError) -> OpenError {
    match e {
        AuditError::KeyStore(k) => OpenError::KeyStore(k),
        other => OpenError::Io(io::Error::other(other.to_string())),
    }
}

/// Best-effort removal of everything a failed first run may have put in the keychain.
fn forget_entries(keys: &dyn KeyStore) {
    for e in [
        EntryName::Kek,
        EntryName::HeadAnchor,
        EntryName::FirstRetainedAnchor,
    ] {
        let _ = keys.delete(&e);
    }
}

struct FirstRun {
    new: PathBuf,
    db: PathBuf,
    dir: PathBuf,
    keys: Arc<dyn KeyStore>,
    recovery_blob: Vec<u8>,
    install_id: String,
    chain_id: String,
    archived_db: Option<Value>,
    renamed: Arc<AtomicBool>,
}

impl FirstRun {
    /// Runs on the writer thread: `GENESIS` under `audit.db.new`, close and fsync, both
    /// anchors, rename to `audit.db`, then the writer's read-write open of `audit.db`.
    fn run(self, parts: WriterParts) -> Result<Writer, OpenError> {
        #[cfg(any(test, feature = "testing"))]
        let hooks = parts.hooks.clone();
        let mut w = Writer::create(&self.new, parts, &self.chain_id)?;
        let genesis = w
            .write_genesis(&self.recovery_blob, &self.install_id, self.archived_db)
            .map_err(audit_err)?;
        if genesis.seq != 1 {
            return Err(OpenError::Integrity("GENESIS did not get seq 1".into()));
        }
        let parts = w.close_for_rename(&self.new)?;
        let head = HeadAnchor {
            chain_id: self.chain_id.clone(),
            seq: genesis.seq,
            record_hash: genesis.record_hash,
        }
        .to_entry()
        .map_err(audit_err)?;
        let first_retained = FirstRetainedAnchor {
            chain_id: self.chain_id,
            genesis_hash: genesis.record_hash,
            first_retained_seq: 1,
            first_retained_prev_hash: ZERO_HASH,
        }
        .to_entry()
        .map_err(audit_err)?;
        // Before the rename: an `audit.db` therefore never exists without its anchors.
        self.keys.set(&EntryName::HeadAnchor, &head)?;
        self.keys
            .set(&EntryName::FirstRetainedAnchor, &first_retained)?;
        #[cfg(any(test, feature = "testing"))]
        hooks
            .fault(crate::testing::FaultPoint::FirstRunBeforeRename)
            .map_err(audit_err)?;
        if self.db.try_exists()? {
            return Err(OpenError::AlreadyExists);
        }
        std::fs::rename(&self.new, &self.db)?;
        self.renamed.store(true, Ordering::SeqCst);
        sync_dir(&self.dir)?;
        Writer::open(&self.db, parts)
    }
}

/// Starts the writer on an existing `audit.db` (it runs the version gate on its own
/// connection and loads the head and the open incidents). Anchor writes start disabled, as
/// `open()` requires until the startup `VERIFY` is committed (§8.7); `Store::apply_startup`
/// enables them. The store's `install_id` is the keystore's. `genesis_hash` is the
/// first-retained anchor's (a retained `GENESIS` row wins).
pub(crate) fn start_existing(
    data: &LocalDataDir,
    cfg: OpenConfig,
    kek: Kek,
    genesis_hash: Option<[u8; 32]>,
) -> Result<Store, OpenError> {
    let db = schema::db_path(data);
    if !db.try_exists()? {
        return Err(OpenError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "audit.db does not exist",
        )));
    }
    let install_id = cfg.keys.install_id().to_string();
    let anchors = AnchorInit {
        enabled: false,
        head_anchored: false,
        genesis_hash,
    };
    Store::start(data, cfg, kek, install_id, anchors, move |parts| {
        Writer::open(&db, parts)
    })
}

pub(crate) fn sql(e: rusqlite::Error) -> OpenError {
    OpenError::Sqlite(e.to_string())
}

/// `meta.written_by` is plaintext and outside the chain: shown only if it looks like a
/// version string, never as arbitrary text.
pub(crate) fn with_written_by(found: String, v: &StoreVersions) -> String {
    let plausible = |w: &str| {
        !w.is_empty()
            && w.len() <= 64
            && w.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-+_".contains(&b))
    };
    match v.written_by.as_deref() {
        Some(w) if plausible(w) => format!("{found}; written by atlas-duck {w}"),
        Some(_) => format!("{found}; written by an unrecognised atlas-duck version"),
        None => found,
    }
}

/// A keychain error at startup: `NotLocal` keeps that reason, every other error is "not
/// reachable (yet)" and is retried (§8.7).
fn keyring_reason(e: &KeyStoreError) -> LockedReason {
    match e {
        KeyStoreError::NotLocal => LockedReason::KeyringNotLocal,
        _ => LockedReason::KeychainUnavailable,
    }
}

fn text(v: ValueRef<'_>) -> Option<String> {
    match v {
        ValueRef::Text(t) => std::str::from_utf8(t).ok().map(str::to_string),
        _ => None,
    }
}

/// The latest `RESTORE` record, as far as an unfinished restore needs it.
pub(crate) struct LatestRestore {
    /// Its plaintext `target` (the install it was restored for).
    pub(crate) target: Option<String>,
    /// Nothing but its own `SCHEMA_MIGRATED` rows follows it (L50: a restore of an older
    /// snapshot appends them after the `RESTORE` in the same transaction).
    pub(crate) newest: bool,
}

/// The latest `RESTORE`, if any (plaintext columns only).
pub(crate) fn latest_restore(conn: &Connection) -> Result<Option<LatestRestore>, OpenError> {
    let latest: Option<(i64, Option<String>)> = conn
        .query_row(
            "SELECT seq, target FROM events WHERE event_type = 'RESTORE' \
             ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, text(r.get_ref(1)?))),
        )
        .optional()
        .map_err(sql)?;
    let Some((seq, target)) = latest else {
        return Ok(None);
    };
    let others_after: i64 = conn
        .query_row(
            "SELECT count(*) FROM events WHERE seq > ?1 \
             AND event_type IS NOT 'SCHEMA_MIGRATED'",
            [seq],
            |r| r.get(0),
        )
        .map_err(sql)?;
    Ok(Some(LatestRestore {
        target,
        newest: others_after == 0,
    }))
}

/// `FinishRestore` iff the newest records are a `RESTORE` naming this install in its plaintext
/// `target`, followed by nothing but its own `SCHEMA_MIGRATED` rows — §8.7 interrupted
/// restore before the KEK re-seal.
pub(crate) fn recovery_offer(
    conn: &Connection,
    install_id: &str,
) -> Result<RecoveryOffer, OpenError> {
    Ok(match latest_restore(conn)? {
        Some(r) if r.newest && r.target.as_deref() == Some(install_id) => {
            RecoveryOffer::FinishRestore
        }
        _ => RecoveryOffer::RecoverThisLog,
    })
}

/// One `keys` row as stored; `None` where a value has the wrong type.
struct KeyRow {
    key_id: Option<u64>,
    month: Option<Option<String>>,
    wrapped: Option<Vec<u8>>,
}

impl KeyRow {
    /// `key_id`, `month`, `wrapped_dek` from the columns `at..at + 3`.
    fn read(r: &rusqlite::Row<'_>, at: usize) -> rusqlite::Result<KeyRow> {
        Ok(KeyRow {
            key_id: match r.get_ref(at)? {
                ValueRef::Integer(i) => u64::try_from(i).ok(),
                _ => None,
            },
            month: match r.get_ref(at + 1)? {
                ValueRef::Null => Some(None),
                v => text(v).map(Some),
            },
            wrapped: match r.get_ref(at + 2)? {
                ValueRef::Blob(b) => Some(b.to_vec()),
                _ => None,
            },
        })
    }

    /// Whether `kek` unwraps this key; `None` when the row cannot be tried.
    fn unwraps(&self, kek: &Kek) -> Option<bool> {
        let (Some(id), Some(month), Some(w)) = (self.key_id, &self.month, &self.wrapped) else {
            return None;
        };
        Some(crypto::unwrap_dek(kek, id, month.as_deref(), w).is_ok())
    }
}

/// Whether `kek` is this store's KEK. `false` (§8.7 "undecryptable", `keychain_lost`) only
/// when the newest record's data key exists and does not unwrap **and** no other key row with
/// a wrapped key unwraps either: a tampered newest key row next to keys that open is not a
/// lost keychain but an incident, which verification reports. A missing, destroyed or
/// unreadable key row of the newest record is left to verification as well.
pub(crate) fn kek_opens_store(conn: &Connection, kek: &Kek) -> Result<bool, OpenError> {
    let newest: Option<(bool, KeyRow)> = conn
        .query_row(
            "SELECT k.key_id IS NOT NULL, e.key_id, k.month, k.wrapped_dek FROM events e              LEFT JOIN keys k ON k.key_id = e.key_id ORDER BY e.seq DESC LIMIT 1",
            [],
            |r| Ok((r.get::<_, bool>(0)?, KeyRow::read(r, 1)?)),
        )
        .optional()
        .map_err(sql)?;
    let Some((found, newest)) = newest else {
        return Err(OpenError::Integrity("the store has no records".into()));
    };
    if !found || newest.unwraps(kek) != Some(false) {
        return Ok(true);
    }
    let mut st = conn
        .prepare(
            "SELECT key_id, month, wrapped_dek FROM keys WHERE wrapped_dek IS NOT NULL              ORDER BY key_id DESC",
        )
        .map_err(sql)?;
    let mut rows = st.query([]).map_err(sql)?;
    while let Some(r) = rows.next().map_err(sql)? {
        let k = KeyRow::read(r, 0).map_err(sql)?;
        if k.key_id != newest.key_id && k.unwraps(kek) == Some(true) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `kek` unwraps at least one of the store's data keys: positive evidence that a KEK
/// from outside the keychain (the recovery blob) belongs to this store.
pub(crate) fn kek_unwraps_a_key(conn: &Connection, kek: &Kek) -> Result<bool, OpenError> {
    let mut st = conn
        .prepare(
            "SELECT key_id, month, wrapped_dek FROM keys WHERE wrapped_dek IS NOT NULL \
             ORDER BY key_id DESC",
        )
        .map_err(sql)?;
    let mut rows = st.query([]).map_err(sql)?;
    while let Some(r) = rows.next().map_err(sql)? {
        if KeyRow::read(r, 0).map_err(sql)?.unwraps(kek) == Some(true) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `open()` steps 1–3 (§8.7): an outcome that stops startup, or the KEK and the verdict held
/// in memory for step 4.
pub(crate) enum Preflight {
    Stop(StartupOutcome),
    Verified {
        kek: Kek,
        verdict: Box<StartupVerdict>,
        /// The first-retained anchor's `genesis_hash`, if the entry exists.
        genesis_hash: Option<[u8; 32]>,
        /// The instance ids of the settings view when the verdict is an unfinished restore
        /// (reconciled or deferred) whose `RESTORE` is still the newest record: their PAT
        /// entries are deleted before the store is served.
        restore_pats: Vec<String>,
    },
}

/// Steps 1–3: the version gate (read-only, writes nothing), the keychain cases (locality before
/// any keyring access, then the canary, then the KEK), the anchors and the pre-migration
/// verification. Writes nothing but the canary of the self-test; the DB is opened only by
/// sidecar-free readers (`schema::open_peek`), and only after the keychain answered.
pub(crate) fn preflight(data: &LocalDataDir, cfg: &OpenConfig) -> Result<Preflight, OpenError> {
    let db = schema::db_path(data);
    if !db.try_exists()? {
        if with_suffix(&db, "-wal").try_exists()? {
            // As in `create_new_store`: a WAL without its DB is never a first run.
            return Err(OpenError::Integrity(
                "audit.db-wal exists without audit.db".into(),
            ));
        }
        return Ok(Preflight::Stop(StartupOutcome::FirstRun));
    }
    let locked = |r: LockedReason| Ok(Preflight::Stop(StartupOutcome::Locked(r)));
    // 1. Version gate (§8.13).
    let versions = schema::read_versions(&db)?;
    let newer = |found: String| {
        Ok(Preflight::Stop(StartupOutcome::StoreNewer {
            found: with_written_by(found, &versions),
        }))
    };
    if let Err(found) = schema::gate_up_to(&versions, cfg.hooks.schema_head()) {
        return newer(found);
    }
    // 2. KEK (§8.6, §8.7).
    match cfg.keys.locality() {
        KeyringLocality::Local => {}
        KeyringLocality::NotLocal { .. } => return locked(LockedReason::KeyringNotLocal),
        KeyringLocality::Unknown { .. } => return locked(LockedReason::KeychainUnavailable),
    }
    if let Err(e) = canary_self_test(&*cfg.keys) {
        return locked(keyring_reason(&e));
    }
    let install_id = cfg.keys.install_id();
    let lost = |conn: &Connection| {
        let offer = recovery_offer(conn, install_id)?;
        locked(LockedReason::KeychainLost { offer })
    };
    let kek = match cfg.keys.get(&EntryName::Kek) {
        // An entry whose bytes do not decode is "undecryptable" (§8.7): only recovery (a
        // re-seal) clears it, never a retry.
        Err(KeyStoreError::Corrupt) => return lost(&schema::open_peek(&db)?),
        Err(e) => return locked(keyring_reason(&e)),
        Ok(None) => return lost(&schema::open_peek(&db)?),
        Ok(Some(b)) => match Kek::from_entry_bytes(&b) {
            Ok(k) => k,
            Err(KekEntryError::NewerLayout(n)) => return newer(format!("keychain kek layout {n}")),
            Err(KekEntryError::Malformed) => return lost(&schema::open_peek(&db)?),
        },
    };
    let ro = schema::open_peek(&db)?;
    if !kek_opens_store(&ro, &kek)? {
        return lost(&ro);
    }
    // 3. Anchors, head first, then the anchor-dir lines (the dir the store's setting names,
    // else `cfg.anchor_dir`), then the verification of the pre-migration store (§8.7).
    let (head_anchor, first_retained) = match anchors::load_anchors(&*cfg.keys) {
        Ok(a) => a,
        Err(AnchorLoadError::Newer(n)) => return newer(format!("keychain anchor layout {n}")),
        Err(AnchorLoadError::KeyStore(e)) => return locked(keyring_reason(&e)),
    };
    let store_install_id = verify::store_install_id(&ro).map_err(sql)?;
    let (view, view_trusted) = settings::load_view(&ro, &kek)?;
    let dir = anchor_dir::resolve(view.anchor_dir.as_deref(), cfg.anchor_dir.as_deref());
    let mut anchor_lines = anchor_dir::load(dir.as_deref(), &ro)?;
    if !view_trusted {
        AnchorDirLines::note_setting_unreadable(&mut anchor_lines);
    }
    let genesis_hash = first_retained.as_ref().map(|f| f.genesis_hash);
    let instances: Vec<String> = view.instances.keys().cloned().collect();
    let verdict = verify::startup(&StartupInputs {
        conn: &ro,
        kek: &kek,
        head_anchor,
        first_retained,
        store_install_id,
        pinned_install_id: cfg.pinned_install_id.clone(),
        anchor_lines,
    })?;
    let a = &verdict.anchor_actions;
    // Only while nothing but `SCHEMA_MIGRATED` follows the `RESTORE`: every completion that
    // appends anything after it (the restore itself, "Finish restore", this start) deleted the
    // tokens first, and a failure after the commit stops the writer before any append. So a
    // later start whose reset is still deferred or failing never deletes the tokens the user
    // entered again since.
    let unfinished = a.complete_restore.is_some() || a.defer_restore.is_some();
    let restore_pats = if unfinished && latest_restore(&ro)?.is_some_and(|r| r.newest) {
        instances
    } else {
        Vec::new()
    };
    Ok(Preflight::Verified {
        kek,
        verdict: Box::new(verdict),
        genesis_hash,
        restore_pats,
    })
}

/// Startup (C.3, §8.7 steps 1–4) of the store in `data`. In order: leftover staging files are
/// deleted → `FirstRun` iff there is no `audit.db` → 1. the version gate (`StoreNewer`, nothing
/// written) → 2. keyring locality, canary and KEK (`Locked`, nothing written, no migration) →
/// 3. the anchors and the pre-migration verification, held in memory → 4. the writer starts
/// with anchor writes disabled, runs the migrations (`SCHEMA_MIGRATED` in the same
/// transaction), appends the step-3 `VERIFY` (none for a clean start), and only then performs
/// the anchor actions and enables anchor writes; `meta.written_by` is updated last.
///
/// A keychain that is unavailable, lost or not local is a `Locked` outcome, never `FirstRun`
/// and never an `Err`. A failed migration rolls back and is `Err(MigrationFailed)` (not an
/// incident; the store is shut down and the next `open` retries it).
pub fn open(
    data: &LocalDataDir,
    lock: &InstanceLock,
    cfg: OpenConfig,
) -> Result<StartupOutcome, OpenError> {
    if lock.path().parent() != Some(data.path()) {
        return Err(OpenError::Invalid("instance.lock of another data dir"));
    }
    remove_staging_leftovers(data)?;
    let (kek, verdict, genesis_hash, restore_pats) = match preflight(data, &cfg)? {
        Preflight::Stop(outcome) => return Ok(outcome),
        Preflight::Verified {
            kek,
            verdict,
            genesis_hash,
            restore_pats,
        } => (kek, verdict, genesis_hash, restore_pats),
    };
    // An unfinished restore deletes its restored view's tokens before re-sealing the KEK, but a
    // restore of a store under the same KEK (a same-machine restore) opens here even when it
    // stopped between its commit and that deletion: the tokens go now, before anything is
    // served (L53), idempotently, and are reported. A keychain that refuses keeps the store
    // locked (retried).
    for id in &restore_pats {
        if let Err(e) = cfg.keys.delete(&EntryName::Pat(id.clone())) {
            return Ok(StartupOutcome::Locked(keyring_reason(&e)));
        }
    }
    let store = match start_existing(data, cfg, kek, genesis_hash) {
        Ok(s) => s,
        // The writer's WAL-aware re-check of the gate. Not write-free like the step-1 gate:
        // the writer's read-write connection was opened and closed (a close may checkpoint).
        // Practically unreachable, since step 1 read through the same WAL.
        Err(OpenError::NewerStore(found)) => {
            let found = match schema::read_versions(&schema::db_path(data)) {
                Ok(v) => with_written_by(found, &v),
                Err(_) => found,
            };
            return Ok(StartupOutcome::StoreNewer { found });
        }
        Err(e) => return Err(e),
    };
    let step4 = || -> Result<VerifyOutcome, OpenError> {
        store.run_migrations()?;
        let verify = store.apply_startup(&verdict).map_err(audit_err)?;
        store.update_written_by()?;
        Ok(verify)
    };
    match step4() {
        Ok(verify) => Ok(StartupOutcome::Ready {
            store,
            verify,
            pats_deleted: restore_pats,
        }),
        Err(e) => {
            store.shutdown();
            Err(e)
        }
    }
}

/// The store's `install_id` (§8.6: the latest `RESTORE`, else `GENESIS`, else the newest
/// retained `APP_START`), read from the plaintext `target` column without the KEK and without
/// writing anything; for the wizard path (1a) that pins this host to an existing store (§2.5).
/// `Ok(None)`: no record names one. `Err(Io(NotFound))`: there is no `audit.db`. A value that
/// is not 32 lowercase hex characters is `Integrity` (it would name keychain entries).
pub fn read_store_install_id(data: &LocalDataDir) -> Result<Option<String>, OpenError> {
    let db = schema::db_path(data);
    if !db.try_exists()? {
        return Err(OpenError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "audit.db does not exist",
        )));
    }
    let conn = schema::open_peek(&db)?;
    match verify::store_install_id(&conn).map_err(sql)? {
        Some(id) if is_id(&id) => Ok(Some(id)),
        Some(_) => Err(OpenError::Integrity(
            "the store's install_id is not 32 lowercase hex characters".into(),
        )),
        None => Ok(None),
    }
}

/// Wizard step (1b): a new store with `GENESIS` (C.3). In order: refuse an existing DB →
/// `install_id` must be the keystore's → the passphrase rules (pure, before any keychain
/// access) → keyring locality (no keyring call unless `Local`) → canary → no `kek`/anchor
/// entry may exist yet under this `install_id` (`Invalid`, never overwritten) → KEK and the
/// recovery blob (sealed, reopened with the second entry and compared) → KEK to the keychain
/// → `GENESIS` under `audit.db.new` → anchors → rename. Any failure before the rename leaves
/// no DB file and deletes the keychain entries it wrote (best effort).
pub fn create_new_store(
    data: &LocalDataDir,
    lock: &InstanceLock,
    cfg: OpenConfig,
    input: FirstRunInput,
) -> Result<Store, OpenError> {
    if lock.path().parent() != Some(data.path()) {
        return Err(OpenError::Invalid("instance.lock of another data dir"));
    }
    let db = schema::db_path(data);
    if db.try_exists()? {
        return Err(OpenError::AlreadyExists);
    }
    if with_suffix(&db, "-wal").try_exists()? {
        // A WAL without its DB would be replayed into the new file: never start over it.
        return Err(OpenError::Integrity(
            "audit.db-wal exists without audit.db".into(),
        ));
    }
    remove_new_leftovers(data)?;
    if cfg.keys.install_id() != input.install_id {
        return Err(OpenError::Invalid(
            "install_id differs from the keystore's install_id",
        ));
    }
    if !is_id(&input.install_id) || !is_id(&input.chain_id) {
        return Err(OpenError::Invalid(
            "install_id and chain_id must be 32 lowercase hex characters",
        ));
    }
    check_new_passphrase(&input.passphrase, &input.passphrase_confirm)?;
    match cfg.keys.locality() {
        KeyringLocality::Local => {}
        KeyringLocality::NotLocal { .. } => return Err(KeyStoreError::NotLocal.into()),
        KeyringLocality::Unknown { .. } => return Err(KeyStoreError::Unavailable.into()),
    }
    canary_self_test(&*cfg.keys)?;
    // Never overwrite an existing install's entries (§8.6): a used install_id needs new ids.
    for e in [
        EntryName::Kek,
        EntryName::HeadAnchor,
        EntryName::FirstRetainedAnchor,
    ] {
        if cfg.keys.get(&e)?.is_some() {
            return Err(OpenError::Invalid(
                "keychain entries already exist for this install_id",
            ));
        }
    }
    let kek = Kek::generate().map_err(audit_err)?;
    let recovery_blob = new_recovery_blob(&input.passphrase, &input.passphrase_confirm, &kek)?;
    if let Err(e) = cfg.keys.set(&EntryName::Kek, &kek.to_entry_bytes()) {
        // A failed set may still have stored something (Windows persistence readback).
        let _ = cfg.keys.delete(&EntryName::Kek);
        return Err(e.into());
    }
    let archived_db = input.archived_db.map(|a| {
        json!({
            "file": a.file,
            "chain_id": a.chain_id,
            "head_seq": a.head_seq,
            "head_hash": hex::encode(a.head_hash),
        })
    });
    let keys = cfg.keys.clone();
    let renamed = Arc::new(AtomicBool::new(false));
    let first_run = FirstRun {
        new: data.path().join(NEW_DB_FILE),
        db,
        dir: data.path().to_path_buf(),
        keys: keys.clone(),
        recovery_blob,
        install_id: input.install_id.clone(),
        chain_id: input.chain_id,
        archived_db,
        renamed: renamed.clone(),
    };
    // First run wrote both anchors itself; there is no earlier state to verify.
    let anchors = AnchorInit {
        enabled: true,
        head_anchored: true,
        genesis_hash: None,
    };
    match Store::start(data, cfg, kek, input.install_id, anchors, move |parts| {
        first_run.run(parts)
    }) {
        Ok(store) => Ok(store),
        Err(e) => {
            // After the rename the DB is a complete store encrypted under this KEK: keep both.
            if !renamed.load(Ordering::SeqCst) {
                forget_entries(&*keys);
                let _ = remove_new_leftovers(data);
            }
            Err(e)
        }
    }
}
