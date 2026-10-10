//! The per-instance runtime table: what routing (§3.3, PD-01…PD-03), `instances.list` and
//! `doctor` (PD-11) read. `from_config` is the config-only pass; `derive` (Task 25) adds the
//! audit-side derivation: confirmed origins, stored PATs, file-side edits that are not applied.

use std::path::PathBuf;

use atlas_duck_atlassian::{
    BaseUrlError, CredentialProvider, NormalizedBaseUrl, StoredIdentity, normalize_base_url,
    url_hash,
};
use atlas_duck_audit::{InstancePolicy, Settings};
use atlas_duck_registry::{Product, Version};
use serde_json::{Value, json};

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

/// §7.1: normalizes a base URL and refuses `http://`. A release build refuses it inside
/// `normalize_base_url`; a build with the test-only `insecure-test-http` feature accepts it
/// there, so the scheme is checked here too, unless a test allowed plain http for its mocks
/// (`TestHooks::allow_http`).
pub fn normalize_origin(raw: &str, allow_http: bool) -> Result<NormalizedBaseUrl, BaseUrlError> {
    let u = normalize_base_url(raw)?;
    if !allow_http && u.as_str().starts_with("http://") {
        return Err(BaseUrlError::InsecureScheme);
    }
    Ok(u)
}

/// One configured instance as the core runs it.
#[derive(Debug, Clone)]
pub struct InstanceRuntime {
    /// `None` until `ensure_ids` wrote one (PD-04); such an instance is `InstanceUnconfirmed`.
    pub id: Option<String>,
    pub alias: String,
    pub product: Product,
    /// The origin in force: the confirmed one; for an unconfirmed instance the file's, shown
    /// only. `None` when the configured URL does not normalize.
    pub base: Option<NormalizedBaseUrl>,
    pub is_default: bool,
    pub state: InstanceState,
    /// The server version from the last connection test (Task 25); `None` = unknown, and an
    /// unknown version makes every op available (§7.1, `validate`).
    pub version: Option<Version>,
    /// The instance's proxy setting in force (L42), resolved against the OS reading when its
    /// client is built.
    pub proxy: ProxySetting,
    /// The custom CA bundle (PEM path, read by Rust only, §7.2); `None` also when the file names
    /// a CA whose fingerprint was never confirmed (it is not trusted, I-31).
    pub ca_bundle: Option<PathBuf>,
    /// Who the stored PAT belongs to (`None` without a usable PAT).
    pub identity: Option<StoredIdentity>,
    /// The stored PAT's expiry.
    pub expires_at: Option<chrono::NaiveDate>,
    /// `config.toml` names another URL than the confirmed origin (I-31): the URL not applied.
    pub pending_url_change: Option<String>,
}

impl InstanceRuntime {
    /// The config-only state: an instance with an id and a usable base URL is `Ok`.
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
            identity: None,
            expires_at: None,
            pending_url_change: None,
        }
    }
}

/// What `InstanceTable::derive` reads besides `config.toml` (§7.1, I-31).
pub struct DeriveCtx<'a> {
    /// The audit-authoritative settings (confirmed origin, CA fingerprint, proxy per instance id).
    pub settings: &'a Settings,
    pub creds: &'a dyn CredentialProvider,
    /// Test builds only: accept `http://` origins (the mocks).
    pub allow_http: bool,
    /// The table in force: an instance keeps its detected server version across a rebuild.
    pub previous: Option<&'a InstanceTable>,
}

/// A file-side edit that was not applied (`CONFIG_CHANGED {source: file, applied: false}`).
#[derive(Debug, Clone, PartialEq)]
pub struct FileSideChange {
    pub key: String,
    pub old: Value,
    pub new: Value,
}

fn opt_json(s: Option<&str>) -> Value {
    s.map_or(Value::Null, |v| json!(v))
}

/// SHA-256 (hex) over the certificates of a PEM bundle, in order (for one certificate: its
/// usual fingerprint). `None` for a bundle without a readable certificate.
pub fn ca_fingerprint(pem: &[u8]) -> Option<String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(pem).ok()?;
    let mut hasher = Sha256::new();
    let mut found = false;
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let end = after.find(END)?;
        let body: String = after[..end].split_whitespace().collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .ok()?;
        hasher.update(&der);
        found = true;
        rest = &after[end + END.len()..];
    }
    found.then(|| hex::encode(hasher.finalize()))
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

    /// The table from `config.toml` and the audit-authoritative settings (§7.1, §7.7, I-31,
    /// PD-22): an instance is usable only with a confirmed origin
    /// (`settings.instances[id].origin`) and a stored PAT bound to that origin; file-side edits
    /// of the origin, the CA or the proxy are kept out and returned for logging. Reads the
    /// keychain and the CA files: not for an async context.
    pub fn derive(cfg: &ConfigState, ctx: &DeriveCtx<'_>) -> (InstanceTable, Vec<FileSideChange>) {
        let mut table = InstanceTable::from_config(cfg);
        let mut changes = Vec::new();
        let configs = instances(cfg).unwrap_or_default();
        for (rt, c) in table.list.iter_mut().zip(&configs) {
            derive_one(rt, c, ctx, &mut changes);
        }
        (table, changes)
    }

    /// Changes one instance in place (a PAT was stored, its state moved).
    pub(crate) fn update(&mut self, id: &str, f: impl FnOnce(&mut InstanceRuntime)) {
        if let Some(i) = self.list.iter_mut().find(|i| i.id.as_deref() == Some(id)) {
            f(i);
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

fn derive_one(
    rt: &mut InstanceRuntime,
    c: &InstanceConfig,
    ctx: &DeriveCtx<'_>,
    changes: &mut Vec<FileSideChange>,
) {
    let Some(id) = c.id.clone() else {
        rt.state = InstanceState::InstanceUnconfirmed;
        return;
    };
    let policy = ctx.settings.instances.get(&id);
    let stored_origin = policy.and_then(|p| p.origin.as_deref());
    let file_url = normalize_origin(&c.base_url_raw, ctx.allow_http);
    rt.version = ctx
        .previous
        .and_then(|t| t.by_id(&id))
        .and_then(|i| i.version);
    let origin_key = format!("instance.{id}.origin");
    // The confirmed origin is the one in force; the file only ever proposes.
    let confirmed = stored_origin.and_then(|o| normalize_origin(o, ctx.allow_http).ok());
    if matches!(file_url, Err(BaseUrlError::InsecureScheme)) {
        rt.state = InstanceState::InsecureScheme;
        rt.base = confirmed;
        changes.push(FileSideChange {
            key: origin_key,
            old: opt_json(stored_origin),
            new: json!(c.base_url_raw.trim()),
        });
        return;
    }
    let Some(origin) = confirmed else {
        rt.state = InstanceState::InstanceUnconfirmed;
        rt.base = file_url.ok();
        return;
    };
    // Confirmed. A different file URL is a request, not a change (I-31).
    if file_url.as_ref().ok() != Some(&origin) {
        let new = c.base_url_raw.trim().to_owned();
        changes.push(FileSideChange {
            key: origin_key,
            old: opt_json(stored_origin),
            new: json!(new),
        });
        rt.pending_url_change = Some(new);
    }
    rt.base = Some(origin.clone());
    derive_proxy_and_ca(rt, c, &id, policy, changes);
    // A usable PAT: stored, readable and bound to the confirmed origin.
    rt.state = match ctx.creds.load(&id) {
        Ok(Some(cred)) if cred.base_url_hash == url_hash(&origin) => {
            rt.identity = Some(cred.identity.clone());
            rt.expires_at = cred.expires_at;
            InstanceState::Ok
        }
        _ => InstanceState::NeedsToken,
    };
}

/// The proxy and the CA in force are the audit settings' (confirmed) values; a different file
/// value is logged and not applied.
fn derive_proxy_and_ca(
    rt: &mut InstanceRuntime,
    c: &InstanceConfig,
    id: &str,
    policy: Option<&InstancePolicy>,
    changes: &mut Vec<FileSideChange>,
) {
    let stored_proxy = policy.and_then(|p| p.proxy.as_deref());
    let setting = stored_proxy
        .and_then(|p| ProxySetting::parse(p).ok())
        .unwrap_or(ProxySetting::Os);
    if setting != c.proxy {
        let file = (c.proxy != ProxySetting::Os).then(|| c.proxy.as_config_str());
        changes.push(FileSideChange {
            key: format!("instance.{id}.proxy"),
            old: opt_json(stored_proxy),
            new: opt_json(file.as_deref()),
        });
    }
    rt.proxy = setting;
    let stored_fp = policy.and_then(|p| p.ca_fingerprint.as_deref());
    let file_fp = c
        .ca_bundle
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|pem| ca_fingerprint(&pem));
    if file_fp.as_deref() != stored_fp {
        changes.push(FileSideChange {
            key: format!("instance.{id}.ca_fingerprint"),
            old: opt_json(stored_fp),
            new: opt_json(file_fp.as_deref()),
        });
        rt.ca_bundle = None;
    }
}
