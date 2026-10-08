//! Jira DC REST v2 + Agile 1.0 client, Confluence DC REST client, rate
//! limiter (§2.2). Credentials arrive through an injected `CredentialProvider`.
//!
//! `clippy::unwrap_used` and `clippy::expect_used` are errors here (§7.7).

// §13: plain http exists only for the test mock; a release build must never carry it.
#[cfg(all(feature = "insecure-test-http", not(debug_assertions)))]
compile_error!("insecure-test-http must never reach a release build");

pub mod cover;
pub mod credentials;
pub mod guard;
pub mod identity;
pub mod origin;
pub mod types;
pub mod url;

pub use cover::{AuditCover, CommitProbe, CoverIssuer, DateObserver, NotCommitted};
pub use credentials::{
    CredentialError, CredentialProvider, PatSecret, StoredCredential, StoredIdentity,
};
pub use guard::{ALLOWED_READ_POSTS, MethodRefused};
pub use identity::username_matches;
pub use origin::{OriginRefused, origin_guard};
pub use types::{
    ApprovedWrite, BodyFailure, ConnClass, ExpectedBody, FetchFailure, FetchOutcome, GetCall,
    HttpRequestSpec, IdentityObserved, PagedCall, PostSendKind, ReadBudget, SearchCall,
    SuccessExpectation, UnavailableReason, UnknownReason, UpstreamResponse, WriteOutcome,
};
pub use url::{
    BaseUrlError, NormalizedBaseUrl, TemplateError, UrlHash, build_url, normalize_base_url,
    url_hash,
};
