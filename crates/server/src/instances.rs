//! Admin-defined instances (SM-4.1, PD-196). The `instances` table of the server store is the one
//! instance list of every user; each user runtime gets it as a generated `config.toml` (read by
//! core's own parser, so the base-spec validation is core's) and as confirmed origins in the
//! user's audit settings (the admin's confirmation stands for every user).
//!
//! Instance ids are derived from the alias (`"ins_" + 32 hex of SHA-256("atlas-duck/instance/v1\0"
//! || alias)`), so every user's store and PAT names the same id without a shared column.

use std::fmt::Write as _;
use std::path::Path;

use atlas_duck_atlassian::normalize_base_url;
use atlas_duck_audit::EventType;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::errors::ApiError;
use crate::runtime::Registry;
use crate::store::{InstanceRecord, ServerStore, StoreError};

const INSTANCE_ID_DOMAIN: &[u8] = b"atlas-duck/instance/v1\0";
/// The only `ca_ref` M12 knows: the mounted organisation bundle (L219).
pub const CA_REF_ORG: &str = "org";

pub fn instance_id_for(alias: &str) -> String {
    let mut h = Sha256::new();
    h.update(INSTANCE_ID_DOMAIN);
    h.update(alias.as_bytes());
    format!("ins_{}", hex::encode(&h.finalize()[..16]))
}

/// The alias whose derived id is `instance_id`, among the admin instances.
pub fn alias_for_id(store: &dyn ServerStore, instance_id: &str) -> Option<String> {
    store
        .instance_list()
        .ok()?
        .into_iter()
        .map(|i| i.alias)
        .find(|a| instance_id_for(a) == instance_id)
}

/// A TOML basic string (JSON's escapes are TOML's).
fn quoted(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// The `config.toml` of a user runtime: every admin instance with its derived id; `ca_ref =
/// "org"` names the organisation bundle.
pub fn config_toml(list: &[InstanceRecord], org_ca: Option<&Path>) -> String {
    let mut s = String::from("schema_version = 1\n");
    for i in list {
        let _ = write!(
            s,
            "\n[[instances]]\nid = {}\nalias = {}\nproduct = {}\nbase_url = {}\ndefault = {}\n",
            quoted(&instance_id_for(&i.alias)),
            quoted(&i.alias),
            quoted(&i.product),
            quoted(&i.base_url),
            i.is_default
        );
        if let Some(p) = &i.proxy {
            let _ = writeln!(s, "proxy = {}", quoted(p));
        }
        if i.ca_ref.as_deref() == Some(CA_REF_ORG)
            && let Some(path) = org_ca
        {
            let _ = writeln!(s, "ca_bundle = {}", quoted(&path.display().to_string()));
        }
    }
    s
}

// ---- admin operations (T13), shared by the routes and the transitional CLI ----------------

/// `POST /api/admin/instances` body (and the CLI's flags).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceSpec {
    pub alias: String,
    pub product: String,
    pub base_url: String,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub ca_ref: Option<String>,
    #[serde(default)]
    pub is_default: bool,
}

/// What the admin endpoints answer for an instance: never a PAT, a user or audit data (SM-2.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstanceView {
    pub alias: String,
    pub product: String,
    pub base_url: String,
    pub proxy: Option<String>,
    pub ca_ref: Option<String>,
    pub is_default: bool,
}

impl From<&InstanceRecord> for InstanceView {
    fn from(i: &InstanceRecord) -> Self {
        InstanceView {
            alias: i.alias.clone(),
            product: i.product.clone(),
            base_url: i.base_url.clone(),
            proxy: i.proxy.clone(),
            ca_ref: i.ca_ref.clone(),
            is_default: i.is_default,
        }
    }
}

fn store_err(_: StoreError) -> ApiError {
    ApiError::STORE_UNAVAILABLE
}

/// The base-spec checks, by core's own parser over the whole resulting list (alias shape, product,
/// proxy, one default per product), plus an `https://` origin (§7.1; `allow_http` in tests only).
pub fn validate(
    list: &[InstanceRecord],
    candidate: &InstanceRecord,
    allow_http: bool,
) -> Result<(), ApiError> {
    if !matches!(candidate.ca_ref.as_deref(), None | Some(CA_REF_ORG)) {
        return Err(ApiError::INSTANCE_INVALID);
    }
    let origin = normalize_base_url(&candidate.base_url).map_err(|_| ApiError::INSTANCE_INVALID)?;
    if !(origin.as_str().starts_with("https://") || allow_http) {
        return Err(ApiError::INSTANCE_INVALID);
    }
    let mut all = list.to_vec();
    all.push(candidate.clone());
    let mut name = [0u8; 16];
    getrandom::fill(&mut name).map_err(|_| ApiError::INTERNAL)?;
    let path =
        std::env::temp_dir().join(format!("atlas-duck-instances-{}.toml", hex::encode(name)));
    std::fs::write(&path, config_toml(&all, None)).map_err(|_| ApiError::INTERNAL)?;
    let parsed = atlas_duck_core::config::load_config(&path)
        .ok()
        .map(|cfg| atlas_duck_core::config::instances::instances(&cfg).is_ok());
    let _ = std::fs::remove_file(&path);
    match parsed {
        Some(true) => Ok(()),
        _ => Err(ApiError::INSTANCE_INVALID),
    }
}

pub fn list(store: &dyn ServerStore) -> Result<Vec<InstanceView>, ApiError> {
    Ok(store
        .instance_list()
        .map_err(store_err)?
        .iter()
        .map(InstanceView::from)
        .collect())
}

/// Adds an instance (409 when the alias exists) and tells every open runtime.
pub async fn add(
    store: &dyn ServerStore,
    registry: &Registry,
    spec: InstanceSpec,
) -> Result<InstanceView, ApiError> {
    let rec = InstanceRecord {
        alias: spec.alias,
        product: spec.product,
        base_url: spec.base_url,
        proxy: spec.proxy,
        ca_ref: spec.ca_ref,
        is_default: spec.is_default,
    };
    let current = store.instance_list().map_err(store_err)?;
    if current.iter().any(|i| i.alias == rec.alias) {
        return Err(ApiError::INSTANCE_EXISTS);
    }
    validate(&current, &rec, registry.deps().allow_http)?;
    match store.instance_put(&rec) {
        Ok(()) => {}
        Err(StoreError::Duplicate) => return Err(ApiError::INSTANCE_EXISTS),
        Err(e) => return Err(store_err(e)),
    }
    registry.instances_changed().await;
    Ok(InstanceView::from(&rec))
}

/// Removes an instance: the row, then every user's PAT for it with `CREDENTIAL_CHANGED {alias,
/// change: deleted, reason: instance_removed}` in that user's chain (opening the runtime if it is
/// closed), then tells every open runtime (PD-196).
pub async fn remove(
    store: &dyn ServerStore,
    registry: &Registry,
    alias: &str,
) -> Result<(), ApiError> {
    if !store.instance_delete(alias).map_err(store_err)? {
        return Err(ApiError::INSTANCE_UNKNOWN);
    }
    // The record goes into the user's chain before the PAT goes (audit before effect).
    for pat in store.pats_for_alias(alias).map_err(store_err)? {
        let mut payload = Map::new();
        payload.insert("alias".into(), Value::from(alias));
        payload.insert("instance_id".into(), Value::from(instance_id_for(alias)));
        payload.insert("change".into(), Value::from("deleted"));
        payload.insert("reason".into(), Value::from("instance_removed"));
        let rt = registry
            .open_user(&pat.user_id)
            .await
            .map_err(|e| e.api())?;
        rt.append_server_record(EventType::CREDENTIAL_CHANGED, payload)
            .await?;
        store.pat_delete(&pat.user_id, alias).map_err(store_err)?;
    }
    registry.instances_changed().await;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_stable_and_core_shaped() {
        let id = instance_id_for("work");
        assert_eq!(id, instance_id_for("work"));
        assert_ne!(id, instance_id_for("wiki"));
        assert!(atlas_duck_core::config::instances::is_valid_instance_id(
            &id
        ));
    }

    #[test]
    fn generated_config_parses_with_cores_parser() {
        let list = vec![
            InstanceRecord {
                alias: "work".into(),
                product: "jira".into(),
                base_url: "https://jira.example.test".into(),
                proxy: Some("direct".into()),
                ca_ref: Some("org".into()),
                is_default: true,
            },
            InstanceRecord {
                alias: "wiki".into(),
                product: "confluence".into(),
                base_url: "https://wiki.example.test/conf".into(),
                proxy: None,
                ca_ref: None,
                is_default: false,
            },
        ];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let ca = dir.path().join("org\\ca\"q.pem");
        std::fs::write(&path, config_toml(&list, Some(&ca))).unwrap();
        let cfg = atlas_duck_core::config::load_config(&path).unwrap();
        let parsed = atlas_duck_core::config::instances::instances(&cfg).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[0].id.as_deref(),
            Some(instance_id_for("work").as_str())
        );
        assert_eq!(parsed[0].ca_bundle.as_deref(), Some(ca.as_path()));
        assert!(parsed[0].is_default);
        assert_eq!(parsed[1].ca_bundle, None);
    }
}

#[cfg(test)]
#[path = "tests/instances.rs"]
mod admin_tests;
