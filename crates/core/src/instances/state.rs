//! The per-instance runtime table: what routing (§3.3, PD-01…PD-03), `instances.list` and
//! `doctor` (PD-11) read. `from_config` is the config-only pass; `derive` (Task 25) adds the
//! audit-side derivation: confirmed origins, stored PATs, file-side edits that are not applied.

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
    /// The custom CA in force: the bytes whose fingerprint the user confirmed (§7.2, I-31),
    /// pinned when the table was derived. `None` also when the file names a CA that was never
    /// confirmed, or that cannot be read: it is not trusted. Clients are built from these bytes,
    /// never from the path (review I-1).
    pub ca: Option<PinnedCa>,
    /// Who the stored PAT belongs to (`None` without a usable PAT).
    pub identity: Option<StoredIdentity>,
    /// The stored PAT's expiry.
    pub expires_at: Option<chrono::NaiveDate>,
    /// `config.toml` names another URL than the confirmed origin (I-31): the URL not applied.
    pub pending_url_change: Option<String>,
    /// Why the state is what it is (Task 26): see `InstanceView::note`. Cleared when a PAT is
    /// stored.
    pub note: Option<String>,
}

impl InstanceRuntime {
    /// The config-only state: an instance with an id and a usable base URL is `Ok`. Routing
    /// only: nothing here is confirmed (see `InstanceTable::from_config`).
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
            ca: None,
            identity: None,
            expires_at: None,
            pending_url_change: None,
            note: None,
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

/// One certificate of a custom CA bundle, as the confirmation dialog shows it (§10.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaCert {
    /// The certificate's own SHA-256 (hex, what other tools show).
    pub sha256: String,
    pub subject: String,
    pub issuer: String,
    /// `YYYY-MM-DD`.
    pub not_before: String,
    pub not_after: String,
}

/// A parsed PEM bundle: every certificate in order and the bundle fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaBundle {
    pub certs: Vec<CaCert>,
    /// SHA-256 (hex) over the DER of all certificates, in order (for one certificate: its usual
    /// fingerprint). This is what the audit settings store (`InstanceCaFingerprint`).
    pub fingerprint: String,
}

/// Parses a PEM bundle. `None` unless it holds at least one certificate and every
/// `CERTIFICATE` block is valid base64 holding exactly one parsable X.509 certificate (a bundle
/// the dialog could not describe is not offered for confirmation).
pub fn parse_ca(pem: &[u8]) -> Option<CaBundle> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(pem).ok()?;
    let mut bundle = Sha256::new();
    let mut certs = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let end = after.find(END)?;
        let body: String = after[..end].split_whitespace().collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .ok()?;
        let (left, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
        if !left.is_empty() {
            return None;
        }
        let day = |t: x509_parser::time::ASN1Time| t.to_datetime().date().to_string();
        certs.push(CaCert {
            sha256: hex::encode(Sha256::digest(&der)),
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            not_before: day(cert.validity().not_before),
            not_after: day(cert.validity().not_after),
        });
        bundle.update(&der);
        rest = &after[end + END.len()..];
    }
    (!certs.is_empty()).then(|| CaBundle {
        certs,
        fingerprint: hex::encode(bundle.finalize()),
    })
}

/// The bundle fingerprint of a PEM bundle (see [`CaBundle::fingerprint`]).
pub fn ca_fingerprint(pem: &[u8]) -> Option<String> {
    parse_ca(pem).map(|b| b.fingerprint)
}

/// A custom CA whose fingerprint the user confirmed: the PEM bytes that were hashed. The only
/// constructor checks the bytes against the confirmed fingerprint, so a client built from a
/// `PinnedCa` never trusts anything else, whatever happens to the file afterwards (review I-1).
#[derive(Clone, PartialEq, Eq)]
pub struct PinnedCa {
    pem: Vec<u8>,
    fingerprint: String,
}

impl PinnedCa {
    /// `Some` only when `pem` is a valid bundle whose fingerprint equals `confirmed`.
    pub fn confirmed(pem: Vec<u8>, confirmed: &str) -> Option<PinnedCa> {
        let fingerprint = ca_fingerprint(&pem)?;
        (fingerprint == confirmed).then_some(PinnedCa { pem, fingerprint })
    }

    pub fn pem(&self) -> &[u8] {
        &self.pem
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl std::fmt::Debug for PinnedCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PinnedCa({})", self.fingerprint)
    }
}

/// A URL as the audit log may carry it: no userinfo, query or fragment (review M-3). A string
/// without a scheme is not echoed at all.
pub(crate) fn loggable_url(raw: &str) -> String {
    let raw = raw.trim();
    let Some((scheme, rest)) = raw.split_once("://") else {
        return "<unparsable url>".to_owned();
    };
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let host = authority.rsplit('@').next().unwrap_or_default();
    format!("{scheme}://{host}{path}")
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
    /// The config-only pass: every instance with an id and a usable URL is `Ok`, whatever the
    /// audit settings and the keychain say. Routing tests only; NEVER a production table
    /// (review I-2): `Core::start` and `reload` use `derive`, and `fail_closed` when that
    /// cannot run.
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

    /// The table when `derive` could not run (its task panicked): every configured instance is
    /// `instance_unconfirmed` with no origin, no CA and no identity, so nothing is routed, no
    /// token is used and no request leaves (review I-2).
    pub fn fail_closed(cfg: &ConfigState) -> InstanceTable {
        let mut table = InstanceTable::from_config(cfg);
        for rt in &mut table.list {
            rt.state = InstanceState::InstanceUnconfirmed;
            rt.base = None;
            rt.ca = None;
            rt.identity = None;
            rt.expires_at = None;
        }
        table
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
            new: json!(loggable_url(&c.base_url_raw)),
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
        // The normalized URL when there is one; else the raw text without userinfo, query and
        // fragment (M-3). Only a URL that normalizes can be accepted later.
        let new = match &file_url {
            Ok(u) => u.as_str(),
            Err(_) => loggable_url(&c.base_url_raw),
        };
        changes.push(FileSideChange {
            key: origin_key,
            old: opt_json(stored_origin),
            new: json!(new),
        });
        rt.pending_url_change = file_url.is_ok().then_some(new);
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
    // The CA file is read once; what is trusted are those bytes, and only when their
    // fingerprint is the confirmed one (review I-1). A file that cannot be read, or that names
    // a CA nobody confirmed, leaves the instance without a custom CA: nothing later reads the
    // path again.
    let stored_fp = policy.and_then(|p| p.ca_fingerprint.as_deref());
    let file_pem = c.ca_bundle.as_ref().and_then(|p| std::fs::read(p).ok());
    let file_fp = file_pem.as_deref().and_then(ca_fingerprint);
    if file_fp.as_deref() != stored_fp {
        changes.push(FileSideChange {
            key: format!("instance.{id}.ca_fingerprint"),
            old: opt_json(stored_fp),
            new: opt_json(file_fp.as_deref()),
        });
    }
    rt.ca = stored_fp
        .zip(file_pem)
        .and_then(|(fp, pem)| PinnedCa::confirmed(pem, fp));
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_duck_atlassian::testing::generate_ca_pem;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn loggable_url_drops_userinfo_query_and_fragment() {
        assert_eq!(
            loggable_url(" https://user:secret@host.example:8443/jira/?a=b#c "),
            "https://host.example:8443/jira/"
        );
        assert_eq!(loggable_url("https://host.example"), "https://host.example");
        // A password that holds an `@` or a `/` stays out as well.
        assert_eq!(
            loggable_url("https://user:p@ss@host.example/x"),
            "https://host.example/x"
        );
        assert_eq!(loggable_url("secret-without-scheme"), "<unparsable url>");
    }

    #[test]
    fn pinned_ca_only_for_the_confirmed_fingerprint() -> TestResult {
        let pem = generate_ca_pem()?;
        let other = generate_ca_pem()?;
        let fp = ca_fingerprint(pem.as_bytes()).ok_or("no fingerprint")?;
        let other_fp = ca_fingerprint(other.as_bytes()).ok_or("no fingerprint")?;
        assert_ne!(fp, other_fp);
        let pinned = PinnedCa::confirmed(pem.clone().into_bytes(), &fp).ok_or("not pinned")?;
        assert_eq!(pinned.pem(), pem.as_bytes());
        assert_eq!(pinned.fingerprint(), fp);
        // Other bytes, or other confirmed text, never pin.
        assert!(PinnedCa::confirmed(other.into_bytes(), &fp).is_none());
        assert!(PinnedCa::confirmed(pem.into_bytes(), &other_fp).is_none());
        assert!(PinnedCa::confirmed(b"nothing".to_vec(), &fp).is_none());
        Ok(())
    }

    #[test]
    fn a_bundle_lists_every_certificate_and_one_fingerprint() -> TestResult {
        let (a, b) = (generate_ca_pem()?, generate_ca_pem()?);
        let one = parse_ca(a.as_bytes()).ok_or("not parsed")?;
        assert_eq!(one.certs.len(), 1);
        assert!(one.certs[0].subject.contains("atlas-duck other test CA"));
        // For one certificate the bundle fingerprint is that certificate's own.
        assert_eq!(one.fingerprint, one.certs[0].sha256);
        let both = parse_ca(format!("{a}\n{b}").as_bytes()).ok_or("not parsed")?;
        assert_eq!(both.certs.len(), 2);
        assert_ne!(both.fingerprint, one.fingerprint);
        // A block that is no certificate refuses the whole bundle.
        let broken = format!("{a}\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----");
        assert!(parse_ca(broken.as_bytes()).is_none());
        Ok(())
    }
}
