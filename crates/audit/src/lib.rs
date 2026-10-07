//! atlas-duck audit crate.
//!
//! M1 holds only `instance.lock` (§3.1). The M2 audit store's `open()` takes an
//! [`lock::InstanceLock`], so the store cannot be opened without the lock (type-enforced).

pub mod lock;
