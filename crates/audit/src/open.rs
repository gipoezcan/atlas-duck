//! First run (§2.5 step (1b), §8.4, §8.6): `create_new_store` writes a new store whose first
//! record is `GENESIS`. `open()` of an existing store comes with T10.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use atlas_duck_ipc::paths::LocalDataDir;
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::anchors::{FirstRetainedAnchor, HeadAnchor};
use crate::crypto::{Kek, fill_random};
use crate::encoding::ZERO_HASH;
use crate::error::{AuditError, OpenError};
use crate::keystore::{EntryName, KeyStore, KeyStoreError, KeyringLocality, canary_self_test};
use crate::lock::InstanceLock;
use crate::recovery::{check_new_passphrase, new_recovery_blob};
use crate::schema;
use crate::store::{OpenConfig, Store};
use crate::writer::{Writer, WriterParts};

/// First-run staging file: the new DB is renamed to `audit.db` only once `GENESIS` committed
/// (plan decision), so a crash never leaves an `audit.db` without `GENESIS`.
pub const NEW_DB_FILE: &str = "audit.db.new";

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

fn random_id() -> Result<String, OpenError> {
    let mut b = [0u8; 16];
    fill_random(&mut b).map_err(|_| OpenError::Io(io::Error::other("OS random source failed")))?;
    Ok(hex::encode(b))
}

/// `(install_id, chain_id)`: 16 random bytes each, lowercase hex (F.1).
pub fn new_ids() -> Result<(String, String), OpenError> {
    Ok((random_id()?, random_id()?))
}

fn is_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Deletes a leftover `audit.db.new` and its SQLite side files (never `audit.db`).
pub(crate) fn remove_new_leftovers(data: &LocalDataDir) -> io::Result<()> {
    let new = data.path().join(NEW_DB_FILE);
    for p in [
        new.clone(),
        with_suffix(&new, "-wal"),
        with_suffix(&new, "-shm"),
        with_suffix(&new, "-journal"),
    ] {
        match std::fs::remove_file(&p) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

/// Makes a rename inside `dir` durable (Unix); NTFS journals the rename itself.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn audit_err(e: AuditError) -> OpenError {
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

/// Wizard step (1b): a new store with `GENESIS` (C.3). In order: refuse an existing DB →
/// `install_id` must be the keystore's → the passphrase rules (pure, before any keychain
/// access) → keyring locality (no keyring call unless `Local`) → canary → KEK and the
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
    match Store::start(data, cfg, kek, input.install_id, move |parts| {
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
