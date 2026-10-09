//! The per-instance runtime table: what routing (§3.3, PD-01…PD-03), `instances.list` and
//! `doctor` (PD-11) read. Built from `config.toml` at start (PD-22); Task 25 adds the audit-side
//! derivation (confirmed origins, stored PATs, the identity-header states) and the clients.

use std::path::PathBuf;

use atlas_duck_atlassian::{BaseUrlError, NormalizedBaseUrl, normalize_base_url};
use atlas_duck_registry::{Product, Version};

use crate::config::ConfigState;
use crate::config::instances::{InstanceConfig, instances};
use crate::proxy::ProxySetting;

/// C.2 `InstanceRow.state` (§3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceState {
    Ok,
    NeedsToken,
    IdentityHeaderMissing,
    IdentityHeaderMismatch,
    InsecureScheme,
    InstanceUnconfirmed,
}

impl InstanceState {
    /// The C.2 wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NeedsToken => "needs_token",
            Self::IdentityHeaderMissing => "identity_header_missing",
            Self::IdentityHeaderMismatch => "identity_header_mismatch",
            Self::InsecureScheme => "insecure_scheme",
            Self::InstanceUnconfirmed => "instance_unconfirmed",
        }
    }
}

/// One configured instance as the core runs it.
#[derive(Debug, Clone)]
pub struct InstanceRuntime {
    /// `None` until `ensure_ids` wrote one (PD-04); such an instance is `InstanceUnconfirmed`.
    pub id: Option<String>,
    pub alias: String,
    pub product: Product,
    /// `None` when the configured URL does not normalize (then the state is not `Ok`).
    pub base: Option<NormalizedBaseUrl>,
    pub is_default: bool,
    pub state: InstanceState,
    /// The server version from the last connection test (Task 25); `None` = unknown, and an
    /// unknown version makes every op available (§7.1, `validate`).
    pub version: Option<Version>,
    /// The instance's proxy setting (L42), resolved against the OS reading when its client is
    /// built.
    pub proxy: ProxySetting,
    /// The custom CA bundle (PEM path, read by Rust only, §7.2).
    pub ca_bundle: Option<PathBuf>,
}

impl InstanceRuntime {
    /// Until Task 25 derives states from the audit settings and the keychain, an instance with an
    /// id and a usable base URL is `Ok`.
    fn from_config(c: &InstanceConfig) -> InstanceRuntime {
        let base = normalize_base_url(&c.base_url_raw);
        let state = match (&c.id, &base) {
            (_, Err(BaseUrlError::InsecureScheme)) => InstanceState::InsecureScheme,
            (None, _) | (_, Err(BaseUrlError::Invalid(_))) => InstanceState::InstanceUnconfirmed,
            (Some(_), Ok(_)) => InstanceState::Ok,
        };
        InstanceRuntime {
            id: c.id.clone(),
            alias: c.alias.clone(),
            product: c.product,
            base: base.ok(),
            is_default: c.is_default,
            state,
            version: None,
            proxy: c.proxy.clone(),
            ca_bundle: c.ca_bundle.clone(),
        }
    }
}

/// Why no instance could be chosen for a submit (PD-01, PD-02) or a listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError {
    /// `config.toml` does not parse, or its `[[instances]]` are malformed (§7.7).
    ConfigUnreadable,
    /// PD-02.
    UnknownAlias,
    /// A known alias of the other product (plan decision: refused like an unknown alias).
    WrongProduct,
    /// PD-01: no instance of the op's product, or several and none is the default.
    NoInstance,
}

/// Every configured instance, in file order.
#[derive(Debug, Clone, Default)]
pub struct InstanceTable {
    config_unreadable: bool,
    list: Vec<InstanceRuntime>,
}

impl InstanceTable {
    pub fn from_config(cfg: &ConfigState) -> InstanceTable {
        if matches!(cfg, ConfigState::Unreadable { .. }) {
            return InstanceTable {
                config_unreadable: true,
                list: Vec::new(),
            };
        }
        match instances(cfg) {
            Ok(list) => InstanceTable {
                config_unreadable: false,
                list: list.iter().map(InstanceRuntime::from_config).collect(),
            },
            Err(_) => InstanceTable {
                config_unreadable: true,
                list: Vec::new(),
            },
        }
    }

    pub fn config_unreadable(&self) -> bool {
        self.config_unreadable
    }

    pub fn list(&self) -> &[InstanceRuntime] {
        &self.list
    }

    pub fn by_alias(&self, alias: &str) -> Option<&InstanceRuntime> {
        self.list.iter().find(|i| i.alias == alias)
    }

    pub fn by_id(&self, id: &str) -> Option<&InstanceRuntime> {
        self.list.iter().find(|i| i.id.as_deref() == Some(id))
    }

    /// §3.3 routing: the named alias, else the product's default instance. Plan decision (spec
    /// silent): with no `default = true` instance of the product, a single instance of it is the
    /// default; with several and none marked, there is none (PD-01).
    pub fn resolve(
        &self,
        product: Product,
        alias: Option<&str>,
    ) -> Result<&InstanceRuntime, RouteError> {
        if self.config_unreadable {
            return Err(RouteError::ConfigUnreadable);
        }
        if let Some(alias) = alias {
            let inst = self.by_alias(alias).ok_or(RouteError::UnknownAlias)?;
            return if inst.product == product {
                Ok(inst)
            } else {
                Err(RouteError::WrongProduct)
            };
        }
        let mut of_product = self.list.iter().filter(|i| i.product == product);
        if let Some(d) = self
            .list
            .iter()
            .find(|i| i.product == product && i.is_default)
        {
            return Ok(d);
        }
        match (of_product.next(), of_product.next()) {
            (Some(only), None) => Ok(only),
            _ => Err(RouteError::NoInstance),
        }
    }
}
