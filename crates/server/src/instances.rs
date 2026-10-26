//! Admin-defined instances (SM-4.1, PD-196). The `instances` table of the server store is the one
//! instance list of every user; each user runtime gets it as a generated `config.toml` (read by
//! core's own parser, so the base-spec validation is core's) and as confirmed origins in the
//! user's audit settings (the admin's confirmation stands for every user).
//!
//! Instance ids are derived from the alias (`"ins_" + 32 hex of SHA-256("atlas-duck/instance/v1\0"
//! || alias)`), so every user's store and PAT names the same id without a shared column.

use std::fmt::Write as _;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::store::{InstanceRecord, ServerStore};

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
