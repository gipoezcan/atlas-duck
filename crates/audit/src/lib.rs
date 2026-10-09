//! atlas-duck audit crate.
//!
//! M1 holds only `instance.lock` (§3.1). The M2 audit store's `open()` takes an
//! [`lock::InstanceLock`], so the store cannot be opened without the lock (type-enforced).
//!
//! The crate root re-exports the C.3 API (types, errors, keystore, clock) that `core` (M3),
//! `app` (M4/M6) and M10 use; the modules stay public for the less common items.

// No panicking shortcut in library code (plan "no unwrap/expect in audit", final review M-1):
// the release profile aborts on panic. Unit tests (`cfg(test)`) are exempt; `testing` opts
// out where it needs to.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod lock;

pub mod admission;
pub mod anchor_dir;
pub mod anchors;
mod backup;
pub mod clock;
// Key constructors, seal/open and the query key (I-4): production builds keep them inside the
// crate; the `testing` feature opens them to the golden-vector and tamper tests.
#[cfg(any(test, feature = "testing"))]
pub mod crypto;
#[cfg(not(any(test, feature = "testing")))]
mod crypto;
pub mod encoding;
pub mod error;
mod incidents;
pub mod keystore;
pub mod open;
mod prune;
pub mod recover;
// The recovery blob (Argon2id, the KEK it seals): crate-internal in production, like `crypto`.
#[cfg(any(test, feature = "testing"))]
pub mod recovery;
#[cfg(not(any(test, feature = "testing")))]
mod recovery;
pub mod request_set;
pub mod requests;
mod restore;
// Read-write connections, DDL and the migration runner (I-4: the writer thread is the only
// read-write user of `audit.db`); production builds re-export only the names below.
#[cfg(any(test, feature = "testing"))]
pub mod schema;
#[cfg(not(any(test, feature = "testing")))]
mod schema;
mod settings;
pub mod store;
pub mod types;
// Production builds export only the C.3 result types (re-exported below); the verdict
// internals are public for the `testing` shim and integration tests.
#[cfg(any(test, feature = "testing"))]
pub mod verify;
#[cfg(not(any(test, feature = "testing")))]
mod verify;
mod writer;

pub use admission::FreeSpaceProbe;
pub use anchor_dir::{AnchorLine, AnchorLineError};
pub use anchors::BarrierKind;
pub use backup::BackupReceipt;
pub use clock::{Clock, SystemClock};
pub use crypto::MAX_PAYLOAD_LEN;
pub use error::{AuditError, OpenError, RestoreError};
pub use keystore::{EntryName, KeyStore, KeyStoreError, KeyringLocality, OsKeyStore};
pub use open::{
    ArchivedDb, FirstRunInput, LockedReason, RecoveryOffer, StartupOutcome, create_new_store,
    keychain_retry_schedule, new_ids, open, read_store_install_id,
};
pub use prune::{PruneOutcome, PruneSkip};
pub use recover::{RecoverReport, archive_and_start_fresh, recover_this_log};
pub use recovery::MIN_PASSPHRASE_CHARS;
pub use request_set::{RequestRecord, request_set_hash};
pub use requests::{ReconcileReport, ReconciledWrite, ScriptFailedFlags, is_terminal};
pub use restore::{RestoreReport, finish_restore, restore_from_source};
pub use schema::{DB_FILE, SCHEMA_HEAD};
pub use settings::{
    FilePolicy, InstancePolicy, RETENTION_DEFAULT, RETENTION_MIN, SettingChange, Settings,
};
pub use store::{Hooks, OpenConfig, Store, StoreHealth};
pub use types::{
    Actor, Committed, Confirmed, DecisionColumn, EventFlags, EventHeader, EventType, NewEvent,
    QueryKind, RustChosenPath, UtcInstant,
};
pub use verify::{FindingKind, VerifyFinding, VerifyOutcome};

#[cfg(any(test, feature = "testing"))]
pub mod testing;
