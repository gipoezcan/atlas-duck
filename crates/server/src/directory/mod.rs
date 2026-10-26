//! The directory behind domain login (SM-2.1, SM-2.3, SM-9.5): the `Directory` trait, the LDAPS
//! client (PD-200), the test directory stub (PD-198), RFC 4515 filter escaping and the TLS client
//! configuration (SM-9.2: verification is never turned off).

pub mod escape;
pub mod ldap;
pub mod stub;
pub mod tls;

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use secrecy::SecretString;

/// What the directory says about a user after a successful bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryUser {
    pub username: String,
    pub display_name: Option<String>,
    /// Group DNs verbatim (`memberOf`); role mapping is the login's (case-insensitive).
    pub groups: Vec<String>,
    pub disabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryError {
    /// Wrong username or password (LDAP result 49), or an empty password.
    InvalidCredentials,
    /// Connect, TLS, timeout, I/O or any other directory failure.
    Unavailable,
    /// The bind worked but no user entry was found (`auth/not_permitted` at the login).
    NotFound,
}

#[async_trait]
pub trait Directory: Send + Sync {
    async fn authenticate(
        &self,
        username: &str,
        password: &SecretString,
    ) -> Result<DirectoryUser, DirectoryError>;
    /// `/readyz`: TCP + TLS handshake only, no bind.
    async fn probe(&self) -> Result<(), DirectoryError>;
    /// `"ldap"` or `"stub"` (audit payloads, `/readyz`).
    fn kind(&self) -> &'static str;
}
