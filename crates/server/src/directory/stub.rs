//! The test directory stub (SM-9.5, PD-198): users from a JSON file, enabled only by
//! `ATLAS_DUCK_TEST_DIRECTORY_FILE` and refused in production by the configuration.
//! File: `{"users": [{"username", "password", "groups": [...], "disabled": false}]}`.
//! Passwords are compared in constant time over their SHA-256 (no length signal), and an unknown
//! username costs the same compare.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{Directory, DirectoryError, DirectoryUser};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUser {
    username: String,
    password: String,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    disabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    users: Vec<FileUser>,
}

struct StubUser {
    username: String,
    password_sha256: [u8; 32],
    groups: Vec<String>,
    disabled: bool,
}

pub struct StubDirectory {
    users: Vec<StubUser>,
    calls: AtomicU64,
    /// The file it was read from: `probe` checks it is still readable.
    file: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubError {
    Unreadable,
    Invalid,
}

fn sha(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

impl StubDirectory {
    pub fn from_file(path: &Path) -> Result<StubDirectory, StubError> {
        let text = zeroize::Zeroizing::new(
            std::fs::read_to_string(path).map_err(|_| StubError::Unreadable)?,
        );
        let mut d = Self::from_json(&text)?;
        d.file = Some(path.to_path_buf());
        Ok(d)
    }

    pub fn from_json(text: &str) -> Result<StubDirectory, StubError> {
        let file: File = serde_json::from_str(text).map_err(|_| StubError::Invalid)?;
        Ok(StubDirectory {
            users: file
                .users
                .into_iter()
                .map(|u| {
                    // Only the hash stays; the plaintext is wiped as it drops.
                    let password = zeroize::Zeroizing::new(u.password);
                    StubUser {
                        username: u.username.to_lowercase(),
                        password_sha256: sha(&password),
                        groups: u.groups,
                        disabled: u.disabled,
                    }
                })
                .collect(),
            calls: AtomicU64::new(0),
            file: None,
        })
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    /// The offboarding check's view (M13 T9): the file as it is now (re-read; unreadable or
    /// invalid is `Unavailable`), else the users loaded at start.
    pub fn account_state_now(
        &self,
        username: &str,
    ) -> Result<super::account::AccountState, DirectoryError> {
        use super::account::AccountState;
        let wanted = username.to_lowercase();
        let state = |disabled: bool| {
            if disabled {
                AccountState::Disabled
            } else {
                AccountState::Active
            }
        };
        match &self.file {
            Some(p) => {
                let fresh = Self::from_file(p).map_err(|_| DirectoryError::Unavailable)?;
                Ok(fresh
                    .users
                    .iter()
                    .find(|u| u.username == wanted)
                    .map_or(AccountState::Gone, |u| state(u.disabled)))
            }
            None => Ok(self
                .users
                .iter()
                .find(|u| u.username == wanted)
                .map_or(AccountState::Gone, |u| state(u.disabled))),
        }
    }

    /// How many `authenticate` calls reached the stub (tests: limited logins never do).
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Directory for StubDirectory {
    async fn authenticate(
        &self,
        username: &str,
        password: &SecretString,
    ) -> Result<DirectoryUser, DirectoryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let given = sha(password.expose_secret());
        let wanted = username.to_lowercase();
        let found = self.users.iter().find(|u| u.username == wanted);
        let reference = found.map_or([0u8; 32], |u| u.password_sha256);
        let ok: bool = given.ct_eq(&reference).into();
        match found {
            Some(u) if ok && !password.expose_secret().is_empty() => Ok(DirectoryUser {
                username: u.username.clone(),
                display_name: None,
                groups: u.groups.clone(),
                disabled: u.disabled,
            }),
            _ => Err(DirectoryError::InvalidCredentials),
        }
    }

    /// The stub's "directory" is its file: it must still be readable.
    async fn probe(&self) -> Result<(), DirectoryError> {
        match &self.file {
            Some(p) if std::fs::metadata(p).is_err() => Err(DirectoryError::Unavailable),
            _ => Ok(()),
        }
    }

    fn kind(&self) -> &'static str {
        "stub"
    }
}
