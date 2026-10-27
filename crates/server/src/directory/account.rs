//! Account-state lookups for the daily offboarding check (SM-6.5, M13 T9, PD-M13-14): is a known
//! user still active in the directory, disabled, or gone? Only the scheduler asks, never a login.
//! The LDAP lookup binds with the optional read-only service account
//! ([`super::ldap::LdapServiceLookup`]); the test directory answers from its file, re-read on
//! every lookup so the review drill can disable a user without a restart. Any doubt is an error,
//! and an error never deactivates anyone.

use async_trait::async_trait;

use super::DirectoryError;
use super::stub::StubDirectory;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountState {
    Active,
    Disabled,
    /// No entry for the user any more.
    Gone,
}

#[async_trait]
pub trait AccountLookup: Send + Sync {
    async fn account_state(&self, username: &str) -> Result<AccountState, DirectoryError>;
}

#[async_trait]
impl AccountLookup for StubDirectory {
    async fn account_state(&self, username: &str) -> Result<AccountState, DirectoryError> {
        self.account_state_now(username)
    }
}
