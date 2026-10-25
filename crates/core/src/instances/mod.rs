//! Instances: the runtime table routing reads (`state`) and the `InstanceAdmin` surface the
//! settings and credential windows call (C.7, §7.1, §10.3).
//!
//! `state` is the runtime table, `admin` the `InstanceAdmin` implementation and
//! `connection_test` the credential window's test (Task 25). Every return type is `Serialize`
//! (PD-12: the capture hook records them).

pub mod admin;
pub mod connection_test;
pub mod state;
pub(crate) mod work;

use atlas_duck_atlassian::{ConnClass, CredentialError};
use atlas_duck_audit::AuditError;
use atlas_duck_registry::Product;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::config::instances::product_str;
use crate::proxy::ProxySetting;

pub use admin::CoreInstances;
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
    /// Why the state is what it is, for the settings window (Task 26): "token now resolves to
    /// <user>" after a recheck found another user, the admin hint of the identity-header states.
    pub note: Option<String>,
    /// PD-84: the tightest of the 14, 7 and 1 day thresholds the stored expiry date is within,
    /// counted from the local date (an expired token is `1`). A hint only: it never gates a
    /// request (I-27).
    pub expiry_warning: Option<u8>,
    /// PD-84: the days from the local date to `expires_at` (`0`: it expires today; negative: it
    /// expired), for the status texts; set whenever `expires_at` is.
    pub days_left: Option<i64>,
}

/// The add-instance form (§7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddInstance {
    pub alias: String,
    pub product: Product,
    pub base_url: String,
    pub proxy: ProxySetting,
    /// A custom CA bundle (PEM). M6 HANDOFF (spec §10.3, review I-5): these bytes must come from
    /// a file the RUST side chose in a native file dialog it opened itself and read itself;
    /// never from a webview command argument. The core shows the certificates' subjects and
    /// fingerprints in its own dialog and pins the confirmed bytes, but it cannot tell where
    /// the caller got them.
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
    /// The stored token resolves to another user than the one it was stored for (Task 26): the
    /// instance is `needs_token`.
    OtherUser,
    NotKnownUser,
    Unavailable,
}

impl ConnectionFailure {
    /// The connection class of a TLS, proxy or network failure (`tls_unknown_issuer`,
    /// `proxy_connect_407`, …: the §11.2 hint the credential window shows, M6 T20); `None` for the
    /// other failures.
    pub fn conn_class(&self) -> Option<&'static str> {
        match self {
            Self::Tls(c) | Self::Proxy(c) | Self::Network(c) => {
                Some(crate::engine::read::class_name(*c))
            }
            _ => None,
        }
    }

    /// The failure's wire name (`http_401`, `tls`, `version_below_floor`, …).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Http401 => "http_401",
            Self::Tls(_) => "tls",
            Self::Proxy(_) => "proxy",
            Self::Network(_) => "network",
            Self::VersionBelowFloor => "version_below_floor",
            Self::IdentityHeaderMissing => "identity_header_missing",
            Self::IdentityHeaderMismatch => "identity_header_mismatch",
            Self::OtherUser => "other_user",
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
    /// The shutdown began (M3 M-4): the call did nothing.
    ShuttingDown,
    /// M10 T36 (L217): `add` refused an alias that another instance already has.
    DuplicateAlias,
    /// M10 T36 (L217): `add` asked for a default for a product that already has one.
    SecondDefault {
        product: Product,
    },
    /// M10 T36 (L217): the CA bundle `add` was given cannot be used; `reason` is a closed kind.
    UnusableCaBundle {
        reason: CaBundleReason,
    },
}

/// Why a CA bundle is unusable (closed: the wire carries the kind only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaBundleReason {
    /// No PEM certificate in the file, or one that does not parse.
    NoCertificate,
}

impl CaBundleReason {
    pub fn kind(self) -> &'static str {
        match self {
            Self::NoCertificate => "no_certificate",
        }
    }
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
            Self::ShuttingDown => "shutting_down",
            Self::DuplicateAlias => "duplicate_alias",
            Self::SecondDefault { .. } => "second_default",
            Self::UnusableCaBundle { .. } => "unusable_ca_bundle",
        }
    }
}

/// The kind only: an `AuditError` or keychain message can name paths.
impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed(c) => write!(f, "connection_failed ({})", c.kind()),
            other => f.write_str(other.kind()),
        }
    }
}

impl std::error::Error for AdminError {}

/// `{kind, failure?, product?, reason?}`: no error text (an `AuditError` or keychain message can name paths).
impl Serialize for AdminError {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("kind", self.kind())?;
        match self {
            Self::ConnectionFailed(f) => m.serialize_entry("failure", f)?,
            Self::SecondDefault { product } => {
                m.serialize_entry("product", product_str(*product))?
            }
            Self::UnusableCaBundle { reason } => m.serialize_entry("reason", reason.kind())?,
            _ => {}
        }
        m.end()
    }
}

/// C.7: add/change base URL (native confirmation), proxy, token set/re-test/delete (§7.1,
/// §10.3). Every call that can write or send is refused `ShuttingDown` once `Core::shutdown`
/// began (M3 M-4).
#[async_trait::async_trait]
pub trait InstanceAdmin: Send + Sync {
    fn list(&self) -> Vec<InstanceView>;
    /// M10 T36 (L217): the checks of `add` that need no dialog and write nothing (URL scheme and
    /// shape, config writable, alias, default, a CA bundle if one is given), in `add`'s order.
    /// The app runs it before it opens the CA file dialog, so a request `add` would refuse never
    /// shows one.
    fn check_add(&self, req: &AddInstance) -> Result<(), AdminError>;
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
    /// Δ4 ("Prepare for removal", PD-88): deletes the stored PAT. `CREDENTIAL_CHANGED {change:
    /// deleted}` commits before the keychain delete (audit before effect); the instance is
    /// `needs_token` afterwards. No stored PAT: nothing is logged. The native confirmation is the
    /// caller's (the removal procedure's `begin` step).
    async fn delete_token(&self, alias: &str) -> Result<InstanceView, AdminError>;
}
