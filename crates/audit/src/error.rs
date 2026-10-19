//! Error types of the store API (F.12). Every `Display` is manual and prints names, numbers
//! and caller-supplied messages only, never record or key bytes.

use std::fmt;

use crate::keystore::KeyStoreError;
use crate::types::ExportReceipt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreError {
    SnapshotNewer {
        found: String,
    },
    NotABundle,
    ManifestMismatch,
    ChainBroken(String),
    WrongPassphrase,
    RollbackNeedsConfirmation {
        records_lost: u64,
    },
    AnchorDirMismatch(String),
    /// The restore committed (`audit.db` is the restored store, ending with its `RESTORE` at
    /// `restore_seq`) but a later step did not complete; the store handle is stopped. The next
    /// start completes it: `open` (interrupted restore) or "Finish restore". Every other
    /// restore error means nothing was committed.
    CommittedIncomplete {
        restore_seq: u64,
        reason: String,
    },
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RestoreError::SnapshotNewer { found } => {
                write!(f, "backup was written by a newer version ({found})")
            }
            RestoreError::NotABundle => f.write_str("not a backup bundle"),
            RestoreError::ManifestMismatch => {
                f.write_str("backup manifest does not match its files")
            }
            RestoreError::ChainBroken(m) => write!(f, "backup chain is broken: {m}"),
            RestoreError::WrongPassphrase => f.write_str("wrong recovery passphrase"),
            RestoreError::RollbackNeedsConfirmation { records_lost } => {
                write!(
                    f,
                    "restore would discard {records_lost} records and needs confirmation"
                )
            }
            RestoreError::AnchorDirMismatch(m) => write!(f, "anchor directory mismatch: {m}"),
            RestoreError::CommittedIncomplete {
                restore_seq,
                reason,
            } => write!(
                f,
                "the restore committed (RESTORE at seq {restore_seq}) but did not complete \
                 ({reason}); restart to finish it"
            ),
        }
    }
}

impl std::error::Error for RestoreError {}

#[derive(Debug)]
pub enum OpenError {
    Io(std::io::Error),
    Sqlite(String),
    MigrationFailed {
        from: u32,
        to: u32,
        message: String,
    },
    AlreadyExists,
    /// The store was written by a newer build (version gate); carries what was found.
    NewerStore(String),
    NotFirstRun,
    PassphraseTooShort,
    PassphraseMismatch,
    KeyStore(KeyStoreError),
    WrongPassphrase,
    Integrity(String),
    Restore(RestoreError),
    /// A caller-supplied first-run input is unusable (e.g. an `install_id` that differs from
    /// the keystore's).
    Invalid(&'static str),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Io(e) => write!(f, "i/o error: {e}"),
            OpenError::Sqlite(m) => write!(f, "database error: {m}"),
            OpenError::MigrationFailed { from, to, message } => {
                write!(f, "migration from schema {from} to {to} failed: {message}")
            }
            OpenError::AlreadyExists => f.write_str("an audit store already exists"),
            OpenError::NewerStore(found) => {
                write!(f, "the audit store is newer than this build ({found})")
            }
            OpenError::NotFirstRun => f.write_str("not a first run"),
            OpenError::PassphraseTooShort => f.write_str("recovery passphrase is too short"),
            OpenError::PassphraseMismatch => f.write_str("recovery passphrases do not match"),
            OpenError::KeyStore(e) => write!(f, "{e}"),
            OpenError::WrongPassphrase => f.write_str("wrong recovery passphrase"),
            OpenError::Integrity(m) => write!(f, "integrity failure: {m}"),
            OpenError::Restore(e) => write!(f, "{e}"),
            OpenError::Invalid(what) => write!(f, "invalid input: {what}"),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<std::io::Error> for OpenError {
    fn from(e: std::io::Error) -> Self {
        OpenError::Io(e)
    }
}

impl From<KeyStoreError> for OpenError {
    fn from(e: KeyStoreError) -> Self {
        OpenError::KeyStore(e)
    }
}

impl From<RestoreError> for OpenError {
    fn from(e: RestoreError) -> Self {
        OpenError::Restore(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    AppendFailed(String),
    StorageLow,
    Closed,
    /// The anchor thread panicked; no anchor will be written until restart.
    AnchorThreadDead,
    /// The anchor thread did not answer in time (a hung keychain call).
    AnchorFlushTimeout,
    /// A restore completion timed out while the anchor thread was already writing it: the
    /// anchors and the barrier may or may not have been updated.
    AnchorOutcomeUnknown,
    Decrypt {
        seq: u64,
    },
    PayloadHash {
        seq: u64,
    },
    NotFound {
        seq: u64,
    },
    NeedsConfirmation(&'static str),
    Invalid(&'static str),
    /// A stored record whose payload or columns have an unexpected shape.
    InvalidRecord {
        seq: u64,
        what: &'static str,
    },
    KeyStore(KeyStoreError),
    Restore(RestoreError),
    Io(String),
    /// A long job (the compliance export) was cancelled through its control (PD-181). The
    /// export's staging directory was removed; when that removal fails the export returns
    /// [`AuditError::ExportLeftover`] instead.
    Cancelled,
    /// A failed or cancelled export could not remove its staging directory `dir_name` (a
    /// `….partial` subdirectory of the chosen directory; its `manifest.json` is gone or never
    /// existed). It may hold decrypted records and is never a valid export: the user must
    /// delete it. `cause` is why the export ended; no `EXPORT` was logged.
    ExportLeftover {
        dir_name: String,
        cause: Box<AuditError>,
    },
    /// The export is complete and logged (`receipt.export_seq`), but its directory could not be
    /// renamed from the staging name to its final name (the final name appeared meanwhile, or
    /// the chosen directory refused the rename): it is still called `receipt.dir_name` (ending
    /// in `.partial`) and is a valid export under that name. Not to be retried as a failure:
    /// a retry logs another `EXPORT`.
    ExportNotRenamed(Box<ExportReceipt>),
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditError::AppendFailed(m) => write!(f, "append failed: {m}"),
            AuditError::StorageLow => f.write_str("audit storage is low"),
            AuditError::Closed => f.write_str("audit store is closed"),
            AuditError::AnchorThreadDead => f.write_str("the anchor thread stopped unexpectedly"),
            AuditError::AnchorOutcomeUnknown => {
                f.write_str("the restore anchors may or may not have been written")
            }
            AuditError::AnchorFlushTimeout => {
                f.write_str("the keychain did not answer in time to write the anchor")
            }
            AuditError::Decrypt { seq } => write!(f, "cannot decrypt the payload of record {seq}"),
            AuditError::PayloadHash { seq } => write!(f, "payload hash mismatch on record {seq}"),
            AuditError::NotFound { seq } => write!(f, "record {seq} not found"),
            AuditError::NeedsConfirmation(what) => write!(f, "{what} needs confirmation"),
            AuditError::Invalid(what) => write!(f, "invalid input: {what}"),
            AuditError::InvalidRecord { seq, what } => {
                write!(f, "record {seq} is unusable: {what}")
            }
            AuditError::KeyStore(e) => write!(f, "{e}"),
            AuditError::Restore(e) => write!(f, "{e}"),
            AuditError::Io(m) => write!(f, "i/o error: {m}"),
            AuditError::Cancelled => f.write_str("cancelled"),
            AuditError::ExportLeftover { dir_name, cause } => write!(
                f,
                "the failed export directory {dir_name} could not be removed and may hold \
                 decrypted records; delete it ({cause})"
            ),
            AuditError::ExportNotRenamed(r) => write!(
                f,
                "the export is complete and logged (record {}) but its directory is still \
                 named {}",
                r.export_seq, r.dir_name
            ),
        }
    }
}

impl std::error::Error for AuditError {}

impl From<KeyStoreError> for AuditError {
    fn from(e: KeyStoreError) -> Self {
        AuditError::KeyStore(e)
    }
}

impl From<RestoreError> for AuditError {
    fn from(e: RestoreError) -> Self {
        AuditError::Restore(e)
    }
}
