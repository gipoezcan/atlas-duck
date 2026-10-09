//! Edit engine (§5.4 step 4): applies the human's edits to a write's params, keeps targets and
//! conflict baselines immutable, re-validates, and derives `executed_params` and `edited_keys`.
//!
//! Fail closed: any edit that touches a target or baseline param rejects the whole edit and
//! nothing is applied (§5.1 inv. 5). `params` is what the executor runs and what `WRITE_APPROVED`
//! hashes (human-added keys included). `executed_params` is the §4.2 delivery view, what the
//! agent is told: the agent's own keys and sub-keys with their edited values, human-added keys
//! cut, a removed key absent, never `null`.

use std::collections::BTreeSet;
use std::fmt;

use atlas_duck_registry::OperationSpec;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::validate::{ValidateCtx, ValidationError, echo, validate};

/// C.7: the human's edits. A key is a top-level param name or `<object_param>.<sub>`
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

/// Names only (no values), sorted; `fields.<id>` for an object param's sub-key.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct EditedKeys {
    pub changed: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Clone, PartialEq)]
pub struct EditResult {
    /// The params after the edits and re-validation: what the executor runs and what
    /// `WRITE_APPROVED` hashes.
    pub params: Value,
    /// The §4.2 delivery view (what the agent is told, never what runs): the agent's own keys
    /// and sub-keys with their edited values; added keys cut, removed keys absent.
    pub executed_params: Value,
    /// Agent params against `params`.
    pub edited_keys: EditedKeys,
    /// This edit (current to new params) touched an enrichment-relevant key: re-enrich.
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
    /// Not a top-level param name or `<object_param>.<sub>`, or two keys of one `Edits`
    /// overlap. The text is bounded and display-escaped like a validation echo.
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

/// Params addressed per sub-key (`<param>.<sub>`): every `type: object` property of the params
/// schema (the fields map, `update`, a transition's `fields`, the `expected` baseline), plus the
/// registry's `fields_map_param`.
fn map_params(spec: &OperationSpec) -> Vec<String> {
    let mut maps: Vec<String> = spec
        .params_schema_json()
        .get("properties")
        .and_then(Value::as_object)
        .map(|props| {
            props
                .iter()
                .filter(|(_, p)| p.get("type").and_then(Value::as_str) == Some("object"))
                .map(|(name, _)| name.clone())
                .collect()
        })
        .unwrap_or_default();
    let declared = spec.field_rules.and_then(|r| r.fields_map_param);
    if let Some(name) = declared.filter(|n| !maps.iter().any(|m| m == n)) {
        maps.push(name.to_owned());
    }
    maps
}

/// No key may contain another (`fields` and `fields.summary`) or repeat across `set` and
/// `remove`: the outcome would depend on the order they are applied in.
fn check_overlap(edits: &Edits) -> Result<(), EditError> {
    let keys: Vec<&str> = edits
        .set
        .keys()
        .map(String::as_str)
        .chain(edits.remove.iter().map(String::as_str))
        .collect();
    let nested = |outer: &str, inner: &str| {
        inner
            .strip_prefix(outer)
            .is_some_and(|rest| rest.starts_with('.'))
    };
    for (i, a) in keys.iter().enumerate() {
        for b in &keys[i + 1..] {
            if a == b || nested(a, b) || nested(b, a) {
                return Err(EditError::BadKey(echo(a)));
            }
        }
    }
    Ok(())
}

/// Splits an edit key into (param, optional sub-key); `BadKey` for anything else.
fn parse_key<'k>(maps: &[String], key: &'k str) -> Result<(&'k str, Option<&'k str>), EditError> {
    let bad = || EditError::BadKey(echo(key));
    match key.split_once('.') {
        None if key.is_empty() => Err(bad()),
        None => Ok((key, None)),
        Some((name, sub)) => {
            if sub.is_empty() || sub.contains('.') || !maps.iter().any(|m| m == name) {
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
        None => Err(EditError::BadKey(echo(&format!("{name}.{sub}")))),
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

/// Key names that differ between two param maps: top-level names, and `<param>.<sub>` whenever
/// a param is an object on both sides. An object present on one side only lists its sub-keys,
/// or its own name when it is empty. Names only, sorted.
fn diff(before: &Map<String, Value>, after: &Map<String, Value>) -> EditedKeys {
    let names: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    let mut out = EditedKeys::default();
    for name in names {
        match (before.get(name), after.get(name)) {
            (Some(Value::Object(a)), Some(Value::Object(p))) => {
                let subs: BTreeSet<&String> = a.keys().chain(p.keys()).collect();
                for sub in subs {
                    let key = format!("{name}.{sub}");
                    match (a.get(sub), p.get(sub)) {
                        (Some(x), Some(y)) if x != y => out.changed.push(key),
                        (None, Some(_)) => out.added.push(key),
                        (Some(_), None) => out.removed.push(key),
                        _ => {}
                    }
                }
            }
            (None, Some(Value::Object(o))) => push_object(&mut out.added, name, o),
            (Some(Value::Object(o)), None) => push_object(&mut out.removed, name, o),
            (None, Some(_)) => out.added.push(name.clone()),
            (Some(_), None) => out.removed.push(name.clone()),
            (Some(a), Some(p)) if a != p => out.changed.push(name.clone()),
            _ => {}
        }
    }
    out
}

fn push_object(list: &mut Vec<String>, name: &str, object: &Map<String, Value>) {
    if object.is_empty() {
        list.push(name.to_owned());
    } else {
        list.extend(object.keys().map(|sub| format!("{name}.{sub}")));
    }
}

/// The §4.2 delivery view: the agent's own keys with the new values; an object param is cut to
/// the sub-keys the agent sent (human-added sub-keys are never delivered).
fn executed_params(agent: &Map<String, Value>, params: &Map<String, Value>) -> Value {
    let mut out = Map::new();
    for (name, agent_value) in agent {
        let Some(value) = params.get(name) else {
            continue;
        };
        let narrowed = match (agent_value.as_object(), value.as_object()) {
            (Some(sent), Some(now)) => Value::Object(
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
/// change re-runs enrichment (judged on `current_params` against the new params, so reverting an
/// enrichment-relevant key re-enriches). The executor runs `EditResult::params`.
pub fn apply_edits(
    spec: &OperationSpec,
    agent_params: &Value,
    current_params: &Value,
    edits: &Edits,
    enrich_keys: &[&str],
    ctx: &ValidateCtx<'_>,
) -> Result<EditResult, EditError> {
    check_overlap(edits)?;
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

    let edited = diff(&agent, &new);
    let delta = diff(&current, &new);
    let rerun_enrichment = [&delta.changed, &delta.added, &delta.removed]
        .into_iter()
        .flatten()
        .any(|key| {
            let first = key.split_once('.').map_or(key.as_str(), |(n, _)| n);
            enrich_keys.contains(&first)
        });
    Ok(EditResult {
        executed_params: executed_params(&agent, &new),
        params,
        edited_keys: edited,
        rerun_enrichment,
    })
}
