//! atlas-duck audit crate.
//!
//! M1 holds only `instance.lock` (§3.1). The M2 audit store's `open()` takes an
//! [`lock::InstanceLock`], so the store cannot be opened without the lock (type-enforced).

pub mod lock;

pub mod admission;
pub mod anchors;
pub mod clock;
pub mod crypto;
pub mod encoding;
pub mod error;
mod incidents;
pub mod keystore;
pub mod open;
pub mod recovery;
pub mod request_set;
pub mod schema;
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
pub use open::{
    ArchivedDb, FirstRunInput, LockedReason, RecoveryOffer, StartupOutcome, create_new_store,
    keychain_retry_schedule, new_ids, open, read_store_install_id,
};
pub use request_set::{RequestRecord, request_set_hash};
pub use store::{Hooks, OpenConfig, Store, StoreHealth};
pub use verify::{FindingKind, VerifyFinding, VerifyOutcome};

#[cfg(any(test, feature = "testing"))]
pub mod testing;
