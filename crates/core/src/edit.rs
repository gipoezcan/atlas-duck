//! Edit engine (§5.4 step 4): applies the human's edits to a write's params, keeps targets and
//! conflict baselines immutable, re-validates, and derives `executed_params` and `edited_keys`.
//!
//! Fail closed: any edit that touches a target or baseline param rejects the whole edit and
//! nothing is applied (§5.1 inv. 5). `executed_params` is exactly what the executor receives:
//! the agent's own keys with the edited values, never a key the agent did not send, and a removed
//! key is absent, never `null`.

use std::collections::BTreeSet;
use std::fmt;

use atlas_duck_registry::OperationSpec;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::validate::{ValidateCtx, ValidationError, validate};

/// The baseline map of ops with `conflict_baselines: ["expected"]`; addressable per sub-key so
/// that an edit of it ends in the target/baseline rejection, not in a bad key.
const EXPECTED_MAP: &str = "expected";

/// C.7: the human's edits. A key is a top-level param name or `<map_param>.<sub>`
/// (`fields.customfield_10200`); a removed key is absent from the executed params, never `null`.
#[derive(Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Edits {
    pub set: Map<String, Value>,
    pub remove: Vec<String>,
}

impl fmt::Debug for Edits {
    /// Values never reach a log through `Debug` (§7.7); key names do.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Edits")
            .field("set", &self.set.keys().collect::<Vec<_>>())
            .field("remove", &self.remove)
            .finish()
    }
}

/// Names only (no values), sorted; `fields.<id>` for a map sub-key.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct EditedKeys {
    pub changed: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Clone, PartialEq)]
pub struct EditResult {
    /// The params after the edits and re-validation.
    pub params: Value,
    /// Exactly what runs: the agent's own keys with their edited values.
    pub executed_params: Value,
    pub edited_keys: EditedKeys,
    /// An edited key's first segment is enrichment-relevant: the engine re-enriches.
    pub rerun_enrichment: bool,
}

impl fmt::Debug for EditResult {
    /// Params never reach a log through `Debug` (§7.7).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EditResult")
            .field("params_bytes", &self.params.to_string().len())
            .field("edited_keys", &self.edited_keys)
            .field("rerun_enrichment", &self.rerun_enrichment)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EditError {
    /// An edit changes a `target_params` value or a conflict baseline; the whole edit is refused.
    TargetParamEdit,
    /// The edited params fail validation; the request stays unchanged (C.7, no audit reason).
    Rejected(ValidationError),
    /// Not a top-level param name or `<map_param>.<sub>`.
    BadKey(String),
}

impl fmt::Display for EditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetParamEdit => f.write_str("edit touches a target or baseline param"),
            Self::Rejected(e) => write!(f, "edit rejected: {e}"),
            Self::BadKey(key) => write!(f, "bad edit key: {key}"),
        }
    }
}

impl std::error::Error for EditError {}

/// Params whose value is a map addressed per sub-key: the op's fields map and the `expected`
/// baseline.
fn map_params(spec: &OperationSpec) -> Vec<&'static str> {
    let mut maps: Vec<&'static str> = Vec::new();
    if let Some(name) = spec.field_rules.and_then(|r| r.fields_map_param) {
        maps.push(name);
    }
    if spec.conflict_baselines.contains(&EXPECTED_MAP) {
        maps.push(EXPECTED_MAP);
    }
    maps
}

/// Splits an edit key into (param, optional sub-key); `BadKey` for anything else.
fn parse_key<'k>(maps: &[&str], key: &'k str) -> Result<(&'k str, Option<&'k str>), EditError> {
    let bad = || EditError::BadKey(key.to_owned());
    match key.split_once('.') {
        None if key.is_empty() => Err(bad()),
        None => Ok((key, None)),
        Some((name, sub)) => {
            if sub.is_empty() || sub.contains('.') || !maps.contains(&name) {
                return Err(bad());
            }
            Ok((name, Some(sub)))
        }
    }
}

fn set_key(
    params: &mut Map<String, Value>,
    name: &str,
    sub: Option<&str>,
    value: &Value,
) -> Result<(), EditError> {
    let Some(sub) = sub else {
        params.insert(name.to_owned(), value.clone());
        return Ok(());
    };
    let slot = params
        .entry(name.to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if slot.is_null() {
        *slot = Value::Object(Map::new());
    }
    match slot.as_object_mut() {
        Some(map) => {
            map.insert(sub.to_owned(), value.clone());
            Ok(())
        }
        None => Err(EditError::BadKey(format!("{name}.{sub}"))),
    }
}

fn remove_key(params: &mut Map<String, Value>, name: &str, sub: Option<&str>) {
    match sub {
        None => {
            params.remove(name);
        }
        Some(sub) => {
            if let Some(map) = params.get_mut(name).and_then(Value::as_object_mut) {
                map.remove(sub);
            }
        }
    }
}

/// Every key name of `value`: top-level names, and `<map>.<sub>` for map params whose value is
/// an object on this side.
fn key_set(maps: &[&str], value: &Map<String, Value>) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for (name, v) in value {
        match v.as_object() {
            Some(sub) if maps.contains(&name.as_str()) => {
                keys.extend(sub.keys().map(|s| format!("{name}.{s}")));
            }
            _ => {
                keys.insert(name.clone());
            }
        }
    }
    keys
}

/// The value at a `key_set` name, `None` when absent.
fn lookup<'v>(value: &'v Map<String, Value>, key: &str) -> Option<&'v Value> {
    value.get(key).or_else(|| {
        let (name, sub) = key.split_once('.')?;
        value.get(name)?.as_object()?.get(sub)
    })
}

fn edited_keys(
    maps: &[&str],
    agent: &Map<String, Value>,
    params: &Map<String, Value>,
) -> EditedKeys {
    let before = key_set(maps, agent);
    let after = key_set(maps, params);
    let mut out = EditedKeys::default();
    for key in before.union(&after) {
        match (lookup(agent, key), lookup(params, key)) {
            (Some(a), Some(p)) if a != p => out.changed.push(key.clone()),
            (None, Some(_)) => out.added.push(key.clone()),
            (Some(_), None) => out.removed.push(key.clone()),
            _ => {}
        }
    }
    out
}

fn executed_params(
    maps: &[&str],
    agent: &Map<String, Value>,
    params: &Map<String, Value>,
) -> Value {
    let mut out = Map::new();
    for (name, agent_value) in agent {
        let Some(value) = params.get(name) else {
            continue;
        };
        let narrowed = match (agent_value.as_object(), value.as_object()) {
            (Some(sent), Some(now)) if maps.contains(&name.as_str()) => Value::Object(
                sent.keys()
                    .filter_map(|k| now.get(k).map(|v| (k.clone(), v.clone())))
                    .collect(),
            ),
            _ => value.clone(),
        };
        out.insert(name.clone(), narrowed);
    }
    Value::Object(out)
}

/// Apply `edits` to `current_params` (§5.4 step 4). `agent_params` are the params the agent sent
/// (the base of `executed_params` and `edited_keys`); `enrich_keys` are the param names whose
/// change re-runs enrichment.
pub fn apply_edits(
    spec: &OperationSpec,
    agent_params: &Value,
    current_params: &Value,
    edits: &Edits,
    enrich_keys: &[&str],
    ctx: &ValidateCtx<'_>,
) -> Result<EditResult, EditError> {
    let maps = map_params(spec);
    let current = current_params.as_object().cloned().unwrap_or_default();
    let mut params = current.clone();
    for (key, value) in &edits.set {
        let (name, sub) = parse_key(&maps, key)?;
        set_key(&mut params, name, sub, value)?;
    }
    for key in &edits.remove {
        let (name, sub) = parse_key(&maps, key)?;
        remove_key(&mut params, name, sub);
    }

    let immutable = spec.target_params.iter().chain(spec.conflict_baselines);
    for name in immutable {
        if current.get(*name) != params.get(*name) {
            return Err(EditError::TargetParamEdit);
        }
    }

    let validated = validate(spec, &Value::Object(params), ctx).map_err(EditError::Rejected)?;
    let params = validated.params;
    let new = params.as_object().cloned().unwrap_or_default();
    let agent = agent_params.as_object().cloned().unwrap_or_default();

    let edited = edited_keys(&maps, &agent, &new);
    let rerun_enrichment = [&edited.changed, &edited.added, &edited.removed]
        .into_iter()
        .flatten()
        .any(|key| {
            let first = key.split_once('.').map_or(key.as_str(), |(n, _)| n);
            enrich_keys.contains(&first)
        });
    Ok(EditResult {
        executed_params: executed_params(&maps, &agent, &new),
        params,
        edited_keys: edited,
        rerun_enrichment,
    })
}
