//! Instances: the runtime table routing reads (`state`) and the `InstanceAdmin` surface the
//! settings and credential windows call (C.7, §7.1, §10.3).
//!
//! Task 19 declares the trait with the Task 25 method set and answers `list` from the runtime
//! table; every other method is Task 25's (`AdminError::Unsupported` until then). Every return
//! type is `Serialize` (PD-12: the capture hook records them).

pub mod state;

use std::sync::Arc;

use atlas_duck_atlassian::{ConnClass, CredentialError};
use atlas_duck_audit::AuditError;
use atlas_duck_registry::Product;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::config::instances::product_str;
use crate::engine::Engine;
use crate::proxy::ProxySetting;

pub use state::{InstanceRuntime, InstanceState, InstanceTable, RouteError};

fn ser_product<S: Serializer>(p: &Product, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(product_str(*p))
}

/// One instance as the settings window shows it. UI-only: unlike `instances.list` it names the
/// origin and the user (§10.3); it never reaches an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstanceView {
    pub alias: String,
    #[serde(serialize_with = "ser_product")]
    pub product: Product,
    /// The normalized base URL in force (audit-authoritative from Task 25 on).
    pub origin: Option<String>,
    /// C.2 state name.
    pub state: &'static str,
    /// "Executes as <user>" (§5.6), from the stored identity (Task 25).
    pub executes_as: Option<String>,
    /// `YYYY-MM-DD`.
    pub expires_at: Option<String>,
    pub pac_configured: bool,
    /// `"host:port"` or `"direct"` (Task 25).
    pub proxy_effective: Option<String>,
    /// "config.toml requests a URL change for <alias>" (I-31, Task 25).
    pub pending_url_change: Option<String>,
}

/// The add-instance form (§7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddInstance {
    pub alias: String,
    pub product: Product,
    pub base_url: String,
    pub proxy: ProxySetting,
    pub ca_pem: Option<Vec<u8>>,
    pub is_default: bool,
}

/// Why a connection test failed (§7.1, §10.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionFailure {
    Http401,
    Tls(ConnClass),
    Proxy(ConnClass),
    Network(ConnClass),
    VersionBelowFloor,
    IdentityHeaderMissing,
    IdentityHeaderMismatch,
    NotKnownUser,
    Unavailable,
}

impl ConnectionFailure {
    fn kind(&self) -> &'static str {
        match self {
            Self::Http401 => "http_401",
            Self::Tls(_) => "tls",
            Self::Proxy(_) => "proxy",
            Self::Network(_) => "network",
            Self::VersionBelowFloor => "version_below_floor",
            Self::IdentityHeaderMissing => "identity_header_missing",
            Self::IdentityHeaderMismatch => "identity_header_mismatch",
            Self::NotKnownUser => "not_known_user",
            Self::Unavailable => "unavailable",
        }
    }
}

impl Serialize for ConnectionFailure {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("kind", self.kind())?;
        if let Self::Tls(c) | Self::Proxy(c) | Self::Network(c) = self {
            m.serialize_entry("class", &format!("{c:?}"))?;
        }
        m.end()
    }
}

/// "Connected as <user>, Jira <version>" (§10.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionReport {
    pub atlassian_user: String,
    #[serde(serialize_with = "ser_product")]
    pub product: Product,
    pub version: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AdminError {
    InsecureScheme,
    InvalidUrl,
    Cancelled,
    Unconfirmed,
    NotFound,
    ConfigReadOnly,
    ConnectionFailed(ConnectionFailure),
    Audit(AuditError),
    Keychain(CredentialError),
    /// Task 19 skeleton: the method is implemented by Task 25, which removes this variant.
    Unsupported,
}

impl AdminError {
    fn kind(&self) -> &'static str {
        match self {
            Self::InsecureScheme => "insecure_scheme",
            Self::InvalidUrl => "invalid_url",
            Self::Cancelled => "cancelled",
            Self::Unconfirmed => "unconfirmed",
            Self::NotFound => "not_found",
            Self::ConfigReadOnly => "config_read_only",
            Self::ConnectionFailed(_) => "connection_failed",
            Self::Audit(_) => "audit",
            Self::Keychain(_) => "keychain",
            Self::Unsupported => "unsupported",
        }
    }
}

/// `{kind, failure?}`: no error text (an `AuditError` or keychain message can name paths).
impl Serialize for AdminError {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("kind", self.kind())?;
        if let Self::ConnectionFailed(f) = self {
            m.serialize_entry("failure", f)?;
        }
        m.end()
    }
}

/// C.7: add/change base URL (native confirmation), proxy, token set/re-test (Task 25).
#[async_trait::async_trait]
pub trait InstanceAdmin: Send + Sync {
    fn list(&self) -> Vec<InstanceView>;
    fn add(&self, req: AddInstance) -> Result<InstanceView, AdminError>;
    fn confirm_config_instance(&self, alias: &str) -> Result<InstanceView, AdminError>;
    fn accept_config_url_change(&self, alias: &str) -> Result<InstanceView, AdminError>;
    fn change_base_url(&self, alias: &str, new_url: &str) -> Result<InstanceView, AdminError>;
    fn set_proxy(&self, alias: &str, proxy: ProxySetting) -> Result<InstanceView, AdminError>;
    async fn set_token(
        &self,
        alias: &str,
        pat: secrecy::SecretString,
        expires_at: Option<chrono::NaiveDate>,
    ) -> Result<ConnectionReport, AdminError>;
    async fn retest_token(&self, alias: &str) -> Result<ConnectionReport, AdminError>;
}

/// The core's `InstanceAdmin` (skeleton until Task 25).
pub struct CoreInstances {
    engine: Arc<Engine>,
}

impl CoreInstances {
    pub(crate) fn new(engine: Arc<Engine>) -> CoreInstances {
        CoreInstances { engine }
    }

    /// `NotFound` for an unknown alias, else the skeleton's `Unsupported`.
    fn refuse(&self, alias: &str) -> AdminError {
        match self.engine.instances().by_alias(alias) {
            Some(_) => AdminError::Unsupported,
            None => AdminError::NotFound,
        }
    }
}

fn view(i: &InstanceRuntime) -> InstanceView {
    InstanceView {
        alias: i.alias.clone(),
        product: i.product,
        origin: i.base.as_ref().map(|b| b.as_str()),
        state: i.state.as_str(),
        executes_as: None,
        expires_at: None,
        pac_configured: false,
        proxy_effective: None,
        pending_url_change: None,
    }
}

#[async_trait::async_trait]
impl InstanceAdmin for CoreInstances {
    fn list(&self) -> Vec<InstanceView> {
        self.engine.instances().list().iter().map(view).collect()
    }
    fn add(&self, _req: AddInstance) -> Result<InstanceView, AdminError> {
        Err(AdminError::Unsupported)
    }
    fn confirm_config_instance(&self, alias: &str) -> Result<InstanceView, AdminError> {
        Err(self.refuse(alias))
    }
    fn accept_config_url_change(&self, alias: &str) -> Result<InstanceView, AdminError> {
        Err(self.refuse(alias))
    }
    fn change_base_url(&self, alias: &str, _new_url: &str) -> Result<InstanceView, AdminError> {
        Err(self.refuse(alias))
    }
    fn set_proxy(&self, alias: &str, _proxy: ProxySetting) -> Result<InstanceView, AdminError> {
        Err(self.refuse(alias))
    }
    async fn set_token(
        &self,
        alias: &str,
        _pat: secrecy::SecretString,
        _expires_at: Option<chrono::NaiveDate>,
    ) -> Result<ConnectionReport, AdminError> {
        Err(self.refuse(alias))
    }
    async fn retest_token(&self, alias: &str) -> Result<ConnectionReport, AdminError> {
        Err(self.refuse(alias))
    }
}
