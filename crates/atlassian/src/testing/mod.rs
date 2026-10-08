//! Test harness (feature `testing`, §13): the wiremock Data Center double, a raw-socket HTTP
//! server for scripted byte streams, a local TLS server with a generated CA, and minimal
//! credential / `Date` / commit-probe doubles. `core`'s in-memory credential provider is its own
//! (C.7); the doubles here serve `atlassian`'s tests.

pub mod fixtures;
mod mock_dc;
mod raw_server;

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Instant, SystemTime};

pub use mock_dc::{MockDc, UserKind, XAuser};
pub use raw_server::{RawHttpServer, RawStep, TestTlsServer, generate_ca_pem};

use crate::client::{BuildError, ClientConfig, InstanceClient, Product, ProxyChoice, Timeouts};
use crate::cover::{AuditCover, CommitProbe, CoverIssuer, DateObserver, NotCommitted};
use crate::credentials::{
    CredentialError, CredentialProvider, PatSecret, StoredCredential, StoredIdentity,
};
use crate::url::{BaseUrlError, NormalizedBaseUrl, UrlHash, normalize_base_url, url_hash};

pub const TEST_INSTANCE: &str = "ins_00000000000000000000000000000001";
pub const TEST_PAT: &str = "test-pat-not-a-secret";
pub const TEST_USER: &str = "jdoe";
pub const TEST_USER_KEY: &str = "JIRAUSER1";

/// `atlas-duck/<version>` as `core` builds it.
pub fn user_agent() -> String {
    format!("atlas-duck/{}", env!("CARGO_PKG_VERSION"))
}

/// Defaults for a test instance: direct, no custom CA, default timeouts.
pub fn config_for_base(product: Product, base: NormalizedBaseUrl) -> ClientConfig {
    ClientConfig {
        instance_id: TEST_INSTANCE.to_owned(),
        product,
        base,
        custom_ca_pem: None,
        proxy: ProxyChoice::Direct,
        user_agent: user_agent(),
        timeouts: Timeouts::default(),
    }
}

pub fn test_config(product: Product, base_url: &str) -> Result<ClientConfig, BaseUrlError> {
    Ok(config_for_base(product, normalize_base_url(base_url)?))
}

/// One PAT for one instance, bound to a URL hash, with a stored identity.
pub struct StaticCredentials {
    instance_id: String,
    entry: Mutex<Option<Entry>>,
}

struct Entry {
    pat: String,
    base_url_hash: UrlHash,
    identity: StoredIdentity,
}

impl StaticCredentials {
    pub fn new(instance_id: &str, pat: &str, bound: UrlHash, user: &str, user_key: &str) -> Self {
        StaticCredentials {
            instance_id: instance_id.to_owned(),
            entry: Mutex::new(Some(Entry {
                pat: pat.to_owned(),
                base_url_hash: bound,
                identity: StoredIdentity {
                    atlassian_user: user.to_owned(),
                    atlassian_user_key: user_key.to_owned(),
                },
            })),
        }
    }

    /// `TEST_PAT` for `TEST_USER`, bound to the config's own base URL.
    pub fn for_config(cfg: &ClientConfig) -> Self {
        Self::new(
            &cfg.instance_id,
            TEST_PAT,
            url_hash(&cfg.base),
            TEST_USER,
            TEST_USER_KEY,
        )
    }

    /// Replaces the stored user name (rename and mismatch tests).
    pub fn set_user(&self, user: &str) {
        if let Some(e) = self.lock().as_mut() {
            e.identity.atlassian_user = user.to_owned();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Entry>> {
        self.entry.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl CredentialProvider for StaticCredentials {
    fn load(&self, instance_id: &str) -> Result<Option<StoredCredential>, CredentialError> {
        if instance_id != self.instance_id {
            return Ok(None);
        }
        Ok(self.lock().as_ref().map(|e| StoredCredential {
            pat: PatSecret::new(e.pat.clone()),
            base_url_hash: e.base_url_hash,
            identity: e.identity.clone(),
            expires_at: None,
        }))
    }

    fn store(&self, instance_id: &str, c: StoredCredential) -> Result<(), CredentialError> {
        if instance_id != self.instance_id {
            return Err(CredentialError::Other("unknown instance".to_owned()));
        }
        *self.lock() = Some(Entry {
            pat: c.pat.expose_secret().to_owned(),
            base_url_hash: c.base_url_hash,
            identity: c.identity,
        });
        Ok(())
    }

    fn delete(&self, instance_id: &str) -> Result<(), CredentialError> {
        if instance_id == self.instance_id {
            *self.lock() = None;
        }
        Ok(())
    }
}

/// A `DateObserver` that keeps every call.
#[derive(Default)]
pub struct RecordingDates {
    calls: Mutex<Vec<(String, SystemTime)>>,
}

impl RecordingDates {
    pub fn calls(&self) -> Vec<(String, SystemTime)> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl DateObserver for RecordingDates {
    fn observe(&self, instance_id: &str, server_date: SystemTime, _at: Instant) {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((instance_id.to_owned(), server_date));
    }
}

/// A probe that reports every id as committed: tests that are not about the audit guard.
pub struct AllCommitted;

impl CommitProbe for AllCommitted {
    fn request_committed(&self, _request_id: &str) -> bool {
        true
    }
    fn system_fetch_started(&self, _fetch_id: &str) -> bool {
        true
    }
}

/// A cover for `req_test` from `AllCommitted`.
pub fn test_cover() -> Result<AuditCover, NotCommitted> {
    CoverIssuer::new(Arc::new(AllCommitted)).for_request("req_test")
}

/// A built client with its doubles.
pub struct TestClient {
    pub client: Arc<InstanceClient>,
    pub creds: Arc<StaticCredentials>,
    pub dates: Arc<RecordingDates>,
}

/// Builds `cfg` with `StaticCredentials::for_config` and a fresh `RecordingDates`.
pub fn test_client(cfg: ClientConfig) -> Result<TestClient, BuildError> {
    let creds = Arc::new(StaticCredentials::for_config(&cfg));
    test_client_with(cfg, creds)
}

pub fn test_client_with(
    cfg: ClientConfig,
    creds: Arc<StaticCredentials>,
) -> Result<TestClient, BuildError> {
    let dates = Arc::new(RecordingDates::default());
    let client = Arc::new(InstanceClient::build(cfg, creds.clone(), dates.clone())?);
    Ok(TestClient {
        client,
        creds,
        dates,
    })
}
