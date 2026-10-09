//! Typed `[[instances]]` accessors for `config.toml` (PD-04, §7.7).
//!
//! Keys per instance table: `id` (`"ins_" + 32 lowercase hex`, written by atlas-duck), `alias`,
//! `product` (`"jira" | "confluence"`), `base_url`, `ca_bundle` (a path, read by Rust only),
//! `proxy` (`"host:port"` or `"direct"`; absent = the OS setting) and `default` (bool). The file
//! is authoritative only for what it says; whether an origin is confirmed lives in the audit
//! settings (Task 25).
//!
//! Plan decisions (spec silent): an alias is 1–64 characters of `A-Z a-z 0-9 . _ -` (it is what
//! agents pass as `--instance` and what every envelope's `instance` field carries); a malformed
//! entry, a repeated alias or id, or two `default = true` instances of one product make the whole
//! list an error (fail closed: requests then answer `not_configured {config_unreadable}`).

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use atlas_duck_registry::Product;
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, value};

use super::{CONFIG_SCHEMA_HEAD, Config, ConfigState, ConfigWriteError, load_config, save_config};
use crate::ids::InstanceId;
use crate::proxy::ProxySetting;

/// The `config.toml` array of tables holding the instances.
pub const KEY_INSTANCES: &str = "instances";
/// The longest alias, in characters.
pub const MAX_ALIAS_CHARS: usize = 64;

/// One `[[instances]]` table as written in `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceConfig {
    /// `None` for a hand-written instance that has no id yet (PD-04: `ensure_ids` writes one when
    /// the config is writable; until then the instance is refused `instance_unconfirmed`).
    pub id: Option<String>,
    pub alias: String,
    pub product: Product,
    /// As written; normalized (and checked for https) where it is used (§7.1).
    pub base_url_raw: String,
    pub ca_bundle: Option<PathBuf>,
    pub proxy: ProxySetting,
    pub is_default: bool,
}

/// Why the `[[instances]]` list cannot be used. Positions are 0-based table indexes; no value
/// from the file is echoed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstancesError {
    /// `instances` is not an array of tables.
    NotAnArrayOfTables,
    Malformed {
        index: usize,
        key: &'static str,
        reason: &'static str,
    },
    DuplicateAlias {
        index: usize,
    },
    DuplicateId {
        index: usize,
    },
    /// More than one `default = true` instance of one product.
    DuplicateDefault {
        index: usize,
    },
}

impl fmt::Display for InstancesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnArrayOfTables => {
                f.write_str("config.toml: instances must be [[instances]] tables")
            }
            Self::Malformed { index, key, reason } => {
                write!(f, "config.toml: instances[{index}].{key}: {reason}")
            }
            Self::DuplicateAlias { index } => {
                write!(f, "config.toml: instances[{index}].alias is used twice")
            }
            Self::DuplicateId { index } => {
                write!(f, "config.toml: instances[{index}].id is used twice")
            }
            Self::DuplicateDefault { index } => write!(
                f,
                "config.toml: instances[{index}] is a second default instance of its product"
            ),
        }
    }
}

impl std::error::Error for InstancesError {}

/// `"jira"` / `"confluence"`.
pub fn product_str(p: Product) -> &'static str {
    match p {
        Product::Jira => "jira",
        Product::Confluence => "confluence",
    }
}

fn is_valid_alias(s: &str) -> bool {
    let n = s.chars().count();
    (1..=MAX_ALIAS_CHARS).contains(&n)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `"ins_" + 32 lowercase hex` (PD-04).
pub fn is_valid_instance_id(s: &str) -> bool {
    s.strip_prefix(InstanceId::PREFIX).is_some_and(|h| {
        h.len() == 32
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn doc_of(cfg: &ConfigState) -> Option<&DocumentMut> {
    match cfg {
        ConfigState::Writable(c) | ConfigState::ReadOnly { config: c, .. } => Some(&c.doc),
        ConfigState::Absent | ConfigState::Unreadable { .. } => None,
    }
}

fn tables(doc: &DocumentMut) -> Result<Option<&ArrayOfTables>, InstancesError> {
    match doc.get(KEY_INSTANCES) {
        None => Ok(None),
        Some(item) => item
            .as_array_of_tables()
            .map(Some)
            .ok_or(InstancesError::NotAnArrayOfTables),
    }
}

fn opt_str<'a>(
    t: &'a Table,
    index: usize,
    key: &'static str,
) -> Result<Option<&'a str>, InstancesError> {
    match t.get(key) {
        None => Ok(None),
        Some(item) => item.as_str().map(Some).ok_or(InstancesError::Malformed {
            index,
            key,
            reason: "must be a string",
        }),
    }
}

fn req_str<'a>(t: &'a Table, index: usize, key: &'static str) -> Result<&'a str, InstancesError> {
    opt_str(t, index, key)?.ok_or(InstancesError::Malformed {
        index,
        key,
        reason: "is required",
    })
}

fn parse_table(t: &Table, index: usize) -> Result<InstanceConfig, InstancesError> {
    let bad = |key, reason| InstancesError::Malformed { index, key, reason };
    let id = match opt_str(t, index, "id")? {
        Some(id) if is_valid_instance_id(id) => Some(id.to_owned()),
        Some(_) => return Err(bad("id", "must be \"ins_\" + 32 lowercase hex")),
        None => None,
    };
    let alias = req_str(t, index, "alias")?;
    if !is_valid_alias(alias) {
        return Err(bad("alias", "must be 1-64 characters of A-Z a-z 0-9 . _ -"));
    }
    let product = match req_str(t, index, "product")? {
        "jira" => Product::Jira,
        "confluence" => Product::Confluence,
        _ => return Err(bad("product", "must be \"jira\" or \"confluence\"")),
    };
    let base_url_raw = req_str(t, index, "base_url")?.to_owned();
    let ca_bundle = opt_str(t, index, "ca_bundle")?
        .filter(|p| !p.is_empty())
        .map(PathBuf::from);
    let proxy = match opt_str(t, index, "proxy")? {
        Some(p) => ProxySetting::parse(p)
            .map_err(|_| bad("proxy", "must be \"direct\" or \"host:port\""))?,
        None => ProxySetting::Os,
    };
    let is_default = match t.get("default") {
        None => false,
        Some(item) => item
            .as_bool()
            .ok_or(bad("default", "must be true or false"))?,
    };
    Ok(InstanceConfig {
        id,
        alias: alias.to_owned(),
        product,
        base_url_raw,
        ca_bundle,
        proxy,
        is_default,
    })
}

/// The configured instances in file order; empty for an absent or unreadable config (§7.7: no
/// instances come from a file that does not parse).
pub fn instances(cfg: &ConfigState) -> Result<Vec<InstanceConfig>, InstancesError> {
    let Some(doc) = doc_of(cfg) else {
        return Ok(Vec::new());
    };
    let Some(aot) = tables(doc)? else {
        return Ok(Vec::new());
    };
    let mut out: Vec<InstanceConfig> = Vec::with_capacity(aot.len());
    for (index, t) in aot.iter().enumerate() {
        let inst = parse_table(t, index)?;
        if out.iter().any(|o| o.alias == inst.alias) {
            return Err(InstancesError::DuplicateAlias { index });
        }
        if inst.id.is_some() && out.iter().any(|o| o.id == inst.id) {
            return Err(InstancesError::DuplicateId { index });
        }
        if inst.is_default
            && out
                .iter()
                .any(|o| o.is_default && o.product == inst.product)
        {
            return Err(InstancesError::DuplicateDefault { index });
        }
        out.push(inst);
    }
    Ok(out)
}

fn write_error(e: ConfigWriteError) -> io::Error {
    match e {
        ConfigWriteError::Io(e) => e,
        other => io::Error::other(other.to_string()),
    }
}

/// PD-04: give every `[[instances]]` table without an `id` a fresh one and write the file back,
/// only when the file on disk is `Writable` (a read-only or unreadable file is never written,
/// §7.7). The file is read again here, so an edit made since the caller loaded it is kept, and
/// a malformed `[[instances]]` list is left alone (it is refused as a whole). Nothing is written
/// when every table already has an id.
pub fn ensure_ids(path: &Path) -> io::Result<()> {
    let state = load_config(path)?;
    if instances(&state).is_err() {
        return Ok(());
    }
    let ConfigState::Writable(mut config) = state else {
        return Ok(());
    };
    let Some(aot) = config
        .doc
        .get_mut(KEY_INSTANCES)
        .and_then(Item::as_array_of_tables_mut)
    else {
        return Ok(());
    };
    let mut changed = false;
    for t in aot.iter_mut() {
        if t.get("id").is_none() {
            let id = InstanceId::new().map_err(|e| io::Error::other(e.to_string()))?;
            t.insert("id", value(id.0));
            changed = true;
        }
    }
    if changed {
        save_config(path, &config).map_err(write_error)?;
    }
    Ok(())
}

fn to_table(inst: &InstanceConfig) -> Table {
    let mut t = Table::new();
    if let Some(id) = &inst.id {
        t.insert("id", value(id.as_str()));
    }
    t.insert("alias", value(inst.alias.as_str()));
    t.insert("product", value(product_str(inst.product)));
    t.insert("base_url", value(inst.base_url_raw.as_str()));
    if let Some(ca) = &inst.ca_bundle {
        t.insert("ca_bundle", value(ca.to_string_lossy().as_ref()));
    }
    if inst.proxy != ProxySetting::Os {
        t.insert("proxy", value(inst.proxy.as_config_str()));
    }
    if inst.is_default {
        t.insert("default", value(true));
    }
    t
}

/// The writable config at `path`, or a new empty one when the file is absent.
fn writable(path: &Path) -> Result<Config, ConfigWriteError> {
    match load_config(path)? {
        ConfigState::Writable(c) => Ok(c),
        ConfigState::Absent => Ok(Config {
            schema_version: CONFIG_SCHEMA_HEAD,
            written_by: None,
            doc: DocumentMut::new(),
        }),
        ConfigState::ReadOnly { .. } => Err(ConfigWriteError::ReadOnly),
        ConfigState::Unreadable { .. } => Err(ConfigWriteError::Unreadable),
    }
}

/// Appends `inst` as a new `[[instances]]` table (the caller validated it: alias unique, id set,
/// URL normalized and confirmed, Task 25) and writes the file atomically.
pub fn add_instance(path: &Path, inst: &InstanceConfig) -> Result<(), ConfigWriteError> {
    let mut config = writable(path)?;
    let doc = &mut config.doc;
    if doc.get(KEY_INSTANCES).is_none() {
        doc.insert(KEY_INSTANCES, Item::ArrayOfTables(ArrayOfTables::new()));
    }
    let aot = doc
        .get_mut(KEY_INSTANCES)
        .and_then(Item::as_array_of_tables_mut)
        .ok_or(ConfigWriteError::Unreadable)?;
    aot.push(to_table(inst));
    save_config(path, &config)
}

/// Sets `base_url` of the instance with `id`; `Ok(false)` when no table has that id.
pub fn set_base_url(path: &Path, id: &str, url: &str) -> Result<bool, ConfigWriteError> {
    let mut config = writable(path)?;
    let Some(t) = config
        .doc
        .get_mut(KEY_INSTANCES)
        .and_then(Item::as_array_of_tables_mut)
        .and_then(|aot| {
            aot.iter_mut()
                .find(|t| t.get("id").and_then(Item::as_str) == Some(id))
        })
    else {
        return Ok(false);
    };
    t.insert("base_url", value(url));
    save_config(path, &config)?;
    Ok(true)
}
