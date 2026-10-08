//! `OsKeyStore`: keyring-core's `(service, user)` model over the per-OS store crates (F.6).
//! The process-wide default store is never set; each `OsKeyStore` owns its store handle.

use std::path::PathBuf;
use std::sync::Arc;

use keyring_core::{CredentialStore, Entry};
use zeroize::Zeroizing;

use super::locality::{keyring_dirs, keyring_locality};
use super::{EntryName, KeyStore, KeyStoreError, KeyringLocality, service_name};

/// What a `keyring_core::Error` means for a caller: the entry is absent, or a `KeyStoreError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappedError {
    /// `NoEntry`: `Ok(None)` for `get`, `Ok(())` for `delete`.
    Absent,
    Error(KeyStoreError),
}

/// The error table of the plan. Carries no secret bytes (`BadEncoding`/`BadDataFormat` payloads
/// are dropped).
pub fn map_keyring_error(e: keyring_core::Error) -> MappedError {
    use keyring_core::Error as E;
    let other = |m: String| MappedError::Error(KeyStoreError::Other(m));
    match e {
        E::NoEntry => MappedError::Absent,
        E::NoStorageAccess(_) => MappedError::Error(KeyStoreError::Locked),
        E::PlatformFailure(_) | E::NoDefaultStore => MappedError::Error(KeyStoreError::Unavailable),
        E::Ambiguous(_) => other("ambiguous entry".into()),
        E::BadEncoding(_) | E::BadDataFormat(_, _) => other("bad data".into()),
        E::TooLong(a, n) => other(format!("{a} too long (max {n})")),
        E::Invalid(p, _) => other(format!("invalid {p}")),
        // BadStoreFormat, NotSupportedByStore and any future (non-exhaustive) variant.
        _ => other("keyring error".into()),
    }
}

fn map_err(e: keyring_core::Error) -> KeyStoreError {
    match map_keyring_error(e) {
        // `NoEntry` outside get/delete (e.g. while building an entry) is not expected.
        MappedError::Absent => KeyStoreError::Other("keyring error".into()),
        MappedError::Error(e) => e,
    }
}

pub struct OsKeyStore {
    install_id: String,
    service: String,
    store: Arc<CredentialStore>,
    dirs: Vec<PathBuf>,
}

impl OsKeyStore {
    /// Uses the real keyring dirs of this OS for the locality check. Does not touch the keyring.
    pub fn new(install_id: &str) -> Result<OsKeyStore, KeyStoreError> {
        Self::with_keyring_dirs(install_id, keyring_dirs())
    }

    /// Tests and the I-44 phase pass their own dirs. Does not touch the keyring.
    pub fn with_keyring_dirs(
        install_id: &str,
        dirs: Vec<PathBuf>,
    ) -> Result<OsKeyStore, KeyStoreError> {
        Ok(OsKeyStore {
            install_id: install_id.to_string(),
            service: service_name(install_id),
            store: Self::platform_store()?,
            dirs,
        })
    }

    fn platform_store() -> Result<Arc<CredentialStore>, KeyStoreError> {
        #[cfg(windows)]
        {
            windows_native_keyring_store::Store::new()
                .map(|s| s as Arc<CredentialStore>)
                .map_err(map_err)
        }
        #[cfg(target_os = "macos")]
        {
            apple_native_keyring_store::keychain::Store::new()
                .map(|s| s as Arc<CredentialStore>)
                .map_err(map_err)
        }
        #[cfg(target_os = "linux")]
        {
            zbus_secret_service_keyring_store::Store::new()
                .map(|s| s as Arc<CredentialStore>)
                .map_err(map_err)
        }
    }

    fn entry(&self, e: &EntryName) -> Result<Entry, KeyStoreError> {
        let account = e.account();
        #[cfg(windows)]
        {
            // Credential Manager shows the spec name, and persistence is Local on every build:
            // the store default is Enterprise, which roams (RF-3).
            let target = e.full_name(&self.install_id);
            let mods = std::collections::HashMap::from([
                ("target", target.as_str()),
                ("persistence", "Local"),
            ]);
            self.store
                .build(&self.service, &account, Some(&mods))
                .map_err(map_err)
        }
        #[cfg(not(windows))]
        {
            self.store
                .build(&self.service, &account, None)
                .map_err(map_err)
        }
    }
}

impl KeyStore for OsKeyStore {
    fn install_id(&self) -> &str {
        &self.install_id
    }

    fn get(&self, e: &EntryName) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        match self.entry(e)?.get_secret() {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(err) => match map_keyring_error(err) {
                MappedError::Absent => Ok(None),
                MappedError::Error(e) => Err(e),
            },
        }
    }

    fn set(&self, e: &EntryName, v: &[u8]) -> Result<(), KeyStoreError> {
        self.entry(e)?.set_secret(v).map_err(map_err)?;
        #[cfg(windows)]
        {
            // Fail closed instead of trusting the modifier.
            let full = e.full_name(&self.install_id);
            if super::windows::credential_persist(&full)? != Some(super::windows::PERSIST_LOCAL) {
                return Err(KeyStoreError::Other(
                    "credential persistence is not local".into(),
                ));
            }
        }
        Ok(())
    }

    fn delete(&self, e: &EntryName) -> Result<(), KeyStoreError> {
        match self.entry(e)?.delete_credential() {
            Ok(()) => Ok(()),
            Err(err) => match map_keyring_error(err) {
                MappedError::Absent => Ok(()),
                MappedError::Error(e) => Err(e),
            },
        }
    }

    fn locality(&self) -> KeyringLocality {
        keyring_locality(&self.dirs)
    }
}
