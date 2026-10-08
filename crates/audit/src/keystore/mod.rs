//! The keychain abstraction (C.3, F.6): the `KeyStore` trait, entry naming, `OsKeyStore` over
//! keyring-core with one store per OS, the keyring locality check (I-44) and the canary
//! self-test (§8.6).

mod locality;
mod os;
#[cfg(windows)]
mod windows;

use std::fmt;
use std::path::PathBuf;

use zeroize::Zeroizing;

pub use locality::{keyring_dirs, keyring_locality};
pub use os::{MappedError, OsKeyStore, map_keyring_error};
#[cfg(windows)]
pub use windows::credential_persist;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryName {
    Kek,
    HeadAnchor,
    FirstRetainedAnchor,
    Canary,
    /// Owned by M3; the payload is the `instance_id`.
    Pat(String),
}

impl EntryName {
    /// `kek` | `head_anchor` | `first_retained_anchor` | `canary` | `pat/<instance_id>`.
    pub fn account(&self) -> String {
        match self {
            EntryName::Kek => "kek".into(),
            EntryName::HeadAnchor => "head_anchor".into(),
            EntryName::FirstRetainedAnchor => "first_retained_anchor".into(),
            EntryName::Canary => "canary".into(),
            EntryName::Pat(id) => format!("pat/{id}"),
        }
    }

    /// `atlas-duck/<install_id>/<account>`.
    pub fn full_name(&self, install_id: &str) -> String {
        format!("{}/{}", service_name(install_id), self.account())
    }
}

/// `atlas-duck/<install_id>`.
pub fn service_name(install_id: &str) -> String {
    format!("atlas-duck/{install_id}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStoreError {
    Unavailable,
    Locked,
    NotLocal,
    Other(String),
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyStoreError::Unavailable => f.write_str("keychain unavailable"),
            KeyStoreError::Locked => f.write_str("keychain locked"),
            KeyStoreError::NotLocal => f.write_str("keychain is not on a local disk"),
            KeyStoreError::Other(m) => write!(f, "keychain error: {m}"),
        }
    }
}

impl std::error::Error for KeyStoreError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyringLocality {
    Local,
    NotLocal { dir: PathBuf },
    Unknown { reason: String },
}

pub trait KeyStore: Send + Sync {
    fn install_id(&self) -> &str;
    /// Absent entry: `Ok(None)`.
    fn get(&self, e: &EntryName) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError>;
    fn set(&self, e: &EntryName, v: &[u8]) -> Result<(), KeyStoreError>;
    /// Absent entry: `Ok(())`.
    fn delete(&self, e: &EntryName) -> Result<(), KeyStoreError>;
    fn locality(&self) -> KeyringLocality {
        KeyringLocality::Local
    }
}

/// §8.6 canary: write a random value to the `Canary` entry, read it back, compare, delete it.
/// A mismatch is `Other` (never a silent fallback); the entry is removed on every path.
pub fn canary_self_test(ks: &dyn KeyStore) -> Result<(), KeyStoreError> {
    let mut want = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *want).map_err(|_| KeyStoreError::Other("no system randomness".into()))?;
    let outcome =
        ks.set(&EntryName::Canary, &*want)
            .and_then(|()| match ks.get(&EntryName::Canary)? {
                Some(got) if got.as_slice() == want.as_slice() => Ok(()),
                Some(_) => Err(KeyStoreError::Other(
                    "canary read back a different value".into(),
                )),
                None => Err(KeyStoreError::Other("canary missing after write".into())),
            });
    let cleanup = ks.delete(&EntryName::Canary);
    outcome.and(cleanup)
}
