//! Jira DC REST v2 + Agile 1.0 client, Confluence DC REST client, rate
//! limiter (§2.2). Credentials arrive through an injected `CredentialProvider`.
//!
//! `clippy::unwrap_used` and `clippy::expect_used` are errors here (§7.7).

// §13: plain http exists only for the test mock; a release build must never carry it.
#[cfg(all(feature = "insecure-test-http", not(debug_assertions)))]
compile_error!("insecure-test-http must never reach a release build");

pub mod credentials;
pub mod identity;
pub mod origin;
pub mod url;

pub use credentials::{
    CredentialError, CredentialProvider, PatSecret, StoredCredential, StoredIdentity,
};
pub use identity::username_matches;
pub use origin::{OriginRefused, origin_guard};
pub use url::{BaseUrlError, NormalizedBaseUrl, UrlHash, normalize_base_url, url_hash};
