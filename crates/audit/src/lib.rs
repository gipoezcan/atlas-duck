//! atlas-duck audit crate.
//!
//! M1 holds only `instance.lock` (§3.1). The M2 audit store's `open()` takes an
//! [`lock::InstanceLock`], so the store cannot be opened without the lock (type-enforced).

pub mod lock;

pub mod clock;
pub mod crypto;
pub mod encoding;
pub mod error;
pub mod keystore;
pub mod recovery;
pub mod request_set;
pub mod types;

pub use request_set::{RequestRecord, request_set_hash};

#[cfg(any(test, feature = "testing"))]
pub mod testing;
