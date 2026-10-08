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
pub mod keystore;
pub mod open;
pub mod recovery;
pub mod request_set;
pub mod schema;
pub mod store;
pub mod types;
mod writer;

pub use admission::FreeSpaceProbe;
pub use open::{ArchivedDb, FirstRunInput, create_new_store, new_ids};
pub use request_set::{RequestRecord, request_set_hash};
pub use store::{Hooks, OpenConfig, Store, StoreHealth};

#[cfg(any(test, feature = "testing"))]
pub mod testing;
