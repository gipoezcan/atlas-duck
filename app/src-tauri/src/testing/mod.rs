//! The `scripted-approver` test build (§13 "headless scripted approver"; PD-01..PD-03, PD-35).
//! Compiled only with the feature, which `lib.rs` refuses in a release build. It forwards
//! `atlas-duck-ipc/test-paths` (the test home, PD-01), `atlas-duck-cli/test-env` (a CLI-launched
//! app keeps the two test variables) and `atlas-duck-core/testing` (plain http to the mock).
//!
//! - [`keystore`]: the file keystore under `ATLAS_DUCK_TEST_KEYSTORE` (PD-02).
//! - [`approver`]: decisions scripted by the request's reason, over the real `DecisionApi` (PD-03).
//! - [`control`]: the `<data>/test-control/` dir (quit, env names, refused counter, start delay,
//!   Windows V12 marker).

pub mod approver;
pub mod control;
pub mod keystore;

use std::path::PathBuf;
use std::sync::Arc;

use atlas_duck_audit::{KeyStore, KeyStoreError};
use atlas_duck_ipc::paths::LocalDataDir;
use tauri::AppHandle;

pub use keystore::{FileKeyStore, provision};

use crate::serve::{KeysFactory, OsKeysFactory};

/// PD-02: the directory of the file keystore. Unset: the OS keychain (the `os_keychain_smoke`
/// test runs this build against the real keychain).
pub const ENV_TEST_KEYSTORE: &str = "ATLAS_DUCK_TEST_KEYSTORE";

/// The file keystore in a fixed directory.
pub struct FileKeysFactory {
    dir: PathBuf,
}

/// Static texts of the factory's refusals.
const MSG_KEYSTORE_NOT_ABSOLUTE: &str = "ATLAS_DUCK_TEST_KEYSTORE must be an absolute path";

impl FileKeysFactory {
    pub fn new(dir: PathBuf) -> FileKeysFactory {
        FileKeysFactory { dir }
    }
}

impl KeysFactory for FileKeysFactory {
    fn keys(&self, install_id: &str) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
        // Never a fallback to the OS keychain once the variable is set.
        if !self.dir.is_absolute() {
            return Err(KeyStoreError::Other(MSG_KEYSTORE_NOT_ABSOLUTE.to_owned()));
        }
        Ok(Arc::new(FileKeyStore::open(&self.dir, install_id)))
    }
}

/// The keystore factory of the test build: [`FileKeysFactory`] when [`ENV_TEST_KEYSTORE`] is
/// set, else the OS keychain.
pub fn keys_factory() -> Arc<dyn KeysFactory> {
    match std::env::var_os(ENV_TEST_KEYSTORE) {
        Some(dir) => Arc::new(FileKeysFactory::new(PathBuf::from(dir))),
        None => Arc::new(OsKeysFactory),
    }
}

/// Starts the control dir watcher and the scripted approver for the app (`setup`, `Ready`). Both
/// find the serving state through the managed `ServeSlot` when they need it, so they work while
/// the store opens, after a keychain retry swapped `Core` in, and when nothing could be served.
pub fn spawn(app: &AppHandle, data: &LocalDataDir) {
    control::Control::spawn(data.clone(), app.clone());
    approver::ScriptedApp::spawn_for_app(app.clone());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_keystore_dir_is_refused_not_replaced() {
        let f = FileKeysFactory::new(PathBuf::from("relative/keys"));
        assert!(matches!(f.keys("id"), Err(KeyStoreError::Other(_))));
    }

    #[test]
    fn an_absolute_keystore_dir_builds_the_file_keystore() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let f = FileKeysFactory::new(dir.path().to_owned());
        let keys = f.keys("7e57")?;
        assert_eq!(keys.install_id(), "7e57");
        assert_eq!(
            keys.locality(),
            atlas_duck_audit::KeyringLocality::Local,
            "no mode file: ok"
        );
        Ok(())
    }
}
