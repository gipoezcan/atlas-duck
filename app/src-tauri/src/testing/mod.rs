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

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use atlas_duck_audit::{KeyStore, KeyStoreError};
use atlas_duck_ipc::paths::LocalDataDir;
use tauri::AppHandle;

pub use keystore::{FileKeyStore, provision};

/// PD-01: the test home variable. Re-exported from the ipc crate, where it exists only with
/// `test-paths`: dropping that forward from `scripted-approver` fails to compile here.
pub const ENV_TEST_HOME: &str = atlas_duck_ipc::paths::TEST_HOME_ENV;

/// The one refusal text of [`test_home_problem`] (a fixed line, never a path).
pub const MSG_NO_TEST_HOME: &str = "atlas-duck-app: the scripted-approver build refuses to start without ATLAS_DUCK_TEST_HOME (an absolute existing directory)";

/// T21 review I-1: why the test build must not start, `None` when it may. It needs
/// `ATLAS_DUCK_TEST_HOME` set to an absolute path AND `base_dirs()` to have honoured it
/// (`resolved_home` is that call's `home`): a build whose ipc crate lacks `test-paths` would
/// resolve the real home and open the real store and keychain.
pub fn test_home_problem(
    env: Option<&OsStr>,
    resolved_home: Option<&Path>,
) -> Option<&'static str> {
    let honoured = match (env, resolved_home) {
        (Some(var), Some(home)) => Path::new(var).is_absolute() && Path::new(var) == home,
        _ => false,
    };
    (!honoured).then_some(MSG_NO_TEST_HOME)
}

/// Called first thing in `run_gui`, before the startup gate reads any pinned file: ends the
/// process with a non-zero status unless the test home is really in effect.
pub fn require_test_home() {
    let env = std::env::var_os(ENV_TEST_HOME);
    let home = atlas_duck_ipc::paths::base_dirs().ok().map(|b| b.home);
    if let Some(msg) = test_home_problem(env.as_deref(), home.as_deref()) {
        eprintln!("{msg}");
        std::process::exit(2);
    }
}

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
    fn the_test_build_refuses_unless_the_test_home_is_in_effect() {
        let abs = std::env::temp_dir();
        let var = abs.as_os_str();
        // Set and honoured: starts.
        assert_eq!(test_home_problem(Some(var), Some(&abs)), None);
        // Unset, a relative value, base_dirs() not honouring it, or failing: refused.
        assert_eq!(test_home_problem(None, Some(&abs)), Some(MSG_NO_TEST_HOME));
        assert_eq!(
            test_home_problem(Some(OsStr::new("rel")), Some(Path::new("rel"))),
            Some(MSG_NO_TEST_HOME)
        );
        assert_eq!(
            test_home_problem(Some(var), Some(Path::new("/the/real/home"))),
            Some(MSG_NO_TEST_HOME)
        );
        assert_eq!(test_home_problem(Some(var), None), Some(MSG_NO_TEST_HOME));
        assert_eq!(test_home_problem(None, None), Some(MSG_NO_TEST_HOME));
    }

    #[test]
    fn the_test_home_variable_is_the_one_the_ipc_crate_reads() {
        assert_eq!(ENV_TEST_HOME, "ATLAS_DUCK_TEST_HOME");
    }

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
