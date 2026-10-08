//! Credential types and the injected provider (§2.2, §10.1).

use std::fmt;

use secrecy::{ExposeSecret, SecretString};

use crate::types::redacted_name;
use crate::url::UrlHash;

/// A personal access token. Not `Serialize`, not `Clone`, `Debug` is redacted;
/// memory is zeroized on drop (`secrecy`).
///
/// ```compile_fail,E0277
/// fn needs_ser<T: serde::Serialize>() {}
/// needs_ser::<atlas_duck_atlassian::PatSecret>();
/// ```
pub struct PatSecret(SecretString);

impl PatSecret {
    /// Takes ownership of `token`. If the caller's `String` has spare capacity, a copy of the
    /// token may remain in the freed allocation; build from a `SecretString` where possible.
    pub fn new(token: String) -> Self {
        PatSecret(SecretString::from(token))
    }

    /// Only for the Authorization header and keychain I/O.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for PatSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PatSecret([REDACTED])")
    }
}

impl From<SecretString> for PatSecret {
    fn from(s: SecretString) -> Self {
        PatSecret(s)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoredIdentity {
    pub atlassian_user: String,
    pub atlassian_user_key: String,
}

impl fmt::Debug for StoredIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredIdentity")
            .field("atlassian_user", &redacted_name(&self.atlassian_user))
            .field(
                "atlassian_user_key",
                &redacted_name(&self.atlassian_user_key),
            )
            .finish()
    }
}

pub struct StoredCredential {
    pub pat: PatSecret,
    pub base_url_hash: UrlHash,
    pub identity: StoredIdentity,
    pub expires_at: Option<chrono::NaiveDate>,
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredCredential")
            .field("pat", &self.pat)
            .field("base_url_hash", &self.base_url_hash)
            .field("identity", &self.identity)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialError {
    Unavailable,
    Locked,
    NotLocal,
    Corrupt,
    Other(String),
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialError::Unavailable => f.write_str("credential store unavailable"),
            CredentialError::Locked => f.write_str("credential store locked"),
            CredentialError::NotLocal => f.write_str("credential store is not local"),
            CredentialError::Corrupt => f.write_str("stored credential is corrupt"),
            CredentialError::Other(m) => write!(f, "credential store error: {m}"),
        }
    }
}

impl std::error::Error for CredentialError {}

/// Supplied by `core` (keychain) or a test double; `atlassian` never touches a keychain.
pub trait CredentialProvider: Send + Sync {
    fn load(&self, instance_id: &str) -> Result<Option<StoredCredential>, CredentialError>;
    fn store(&self, instance_id: &str, c: StoredCredential) -> Result<(), CredentialError>;
    fn delete(&self, instance_id: &str) -> Result<(), CredentialError>;
}
