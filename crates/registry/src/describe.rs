//! `ops describe` (§2.3): the agent-facing description of one operation.

use serde_json::{Map, Value, json};

use crate::model::{FlagKind, OpClass, OperationSpec, Version};
use crate::{PAGINATION_GUIDANCE, WRITE_GUIDANCE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitsSource {
    Default,
    Effective,
}

/// What the caller knows beyond the static spec: whether `caps`/`script_limits` are the built-in
/// defaults or the configured values, and the per-instance availability (only with `--instance`).
#[derive(Debug, Clone, PartialEq)]
pub struct DescribeEnv {
    pub limits_source: LimitsSource,
    pub available: Option<bool>,
    /// `Null` = the spec's own cap defaults.
    pub caps: Value,
    pub script_limits: Value,
}

pub fn describe(spec: &OperationSpec, env: &DescribeEnv) -> Value {
    let write = spec.class == OpClass::Write;
    let schema = spec.params_schema_json();
    let minimal = schema
        .get("examples")
        .and_then(|e| e.get(0))
        .cloned()
        .unwrap_or_else(|| json!({}));

    let mut out = Map::new();
    out.insert("op_id".into(), json!(spec.id));
    out.insert("class".into(), json!(if write { "write" } else { "read" }));
    out.insert(
        "approval".into(),
        json!(if write { "approve" } else { "release" }),
    );
    out.insert("description".into(), json!(description(spec)));
    out.insert("params_schema".into(), schema);
    out.insert("cli".into(), cli(spec));
    out.insert("defaults".into(), defaults(spec));
    out.insert(
        "caps".into(),
        if env.caps.is_null() {
            default_caps(spec)
        } else {
            env.caps.clone()
        },
    );
    if let Some(page) = &spec.paginated {
        out.insert("items_key".into(), json!(page.items_key));
    }
    out.insert("field_rules".into(), field_rules(spec));
    out.insert(
        "min_version".into(),
        spec.min_version.map_or(Value::Null, |v| json!(version(v))),
    );
    out.insert("result_example".into(), spec.result_example_json());
    out.insert(
        "result_example_sparse".into(),
        spec.result_example_sparse_json(),
    );
    out.insert("script_limits".into(), env.script_limits.clone());
    out.insert(
        "examples".into(),
        json!({
            "cli": cli_example(spec, &minimal),
            "call": format!("atlas-duck call {} --params {}", spec.id, shell_word(&minimal.to_string())),
        }),
    );
    out.insert(
        "limits_source".into(),
        json!(match env.limits_source {
            LimitsSource::Default => "default",
            LimitsSource::Effective => "effective",
        }),
    );
    if let Some(available) = env.available {
        out.insert("available".into(), json!(available));
    }
    Value::Object(out)
}

fn description(spec: &OperationSpec) -> String {
    let mut parts = Vec::new();
    if spec.write_guidance || spec.class == OpClass::Write {
        parts.push(WRITE_GUIDANCE.to_string());
    }
    if spec.paginated.is_some() {
        parts.push(format!("Paginated: {PAGINATION_GUIDANCE}."));
    }
    parts.join(" ")
}

fn version(v: Version) -> String {
    format!("{}.{}.{}", v.major, v.minor, v.patch)
}

fn usage(spec: &OperationSpec) -> String {
    let mut usage = format!("atlas-duck {}", spec.cli.noun_path.join(" "));
    if let Some(p) = spec.cli.positional {
        usage.push_str(&format!(" <{p}>"));
    }
    for f in spec.cli.flags {
        let arg = match f.kind {
            FlagKind::Bool => String::new(),
            FlagKind::Int => " <n>".to_string(),
            FlagKind::Str | FlagKind::Json | FlagKind::CsvList => " <value>".to_string(),
            FlagKind::KeyJsonPairs => " <id>=<json>".to_string(),
        };
        usage.push_str(&format!(" [{}{arg}]", f.flag));
        if f.file_variant {
            usage.push_str(&format!(" [{}-file <path>]", f.flag));
        }
    }
    usage
}

fn cli(spec: &OperationSpec) -> Value {
    let flags: Vec<Value> = spec
        .cli
        .flags
        .iter()
        .map(|f| {
            json!({
                "param": f.param,
                "flag": f.flag,
                "kind": match f.kind {
                    FlagKind::Str => "str",
                    FlagKind::Int => "int",
                    FlagKind::Bool => "bool",
                    FlagKind::Json => "json",
                    FlagKind::CsvList => "csv_list",
                    FlagKind::KeyJsonPairs => "key_json_pairs",
                },
            })
        })
        .collect();
    let file_variants: Vec<String> = spec
        .cli
        .flags
        .iter()
        .filter(|f| f.file_variant)
        .map(|f| format!("{}-file", f.flag))
        .collect();
    json!({
        "usage": usage(spec),
        "positional": spec.cli.positional,
        "flags": flags,
        "file_variants": file_variants,
    })
}

/// A runnable invocation built from the schema's minimal params object.
fn cli_example(spec: &OperationSpec, minimal: &Value) -> String {
    let mut line = format!("atlas-duck {}", spec.cli.noun_path.join(" "));
    if let Some(v) = spec.cli.positional.and_then(|p| minimal.get(p)) {
        line.push(' ');
        line.push_str(&shell_word(&plain(v)));
    }
    for f in spec.cli.flags {
        let Some(v) = minimal.get(f.param) else {
            continue;
        };
        match f.kind {
            FlagKind::Bool => {
                if v == &Value::Bool(true) {
                    line.push_str(&format!(" {}", f.flag));
                }
            }
            FlagKind::Int | FlagKind::Str => {
                line.push_str(&format!(" {} {}", f.flag, shell_word(&plain(v))));
            }
            FlagKind::Json => {
                line.push_str(&format!(" {} {}", f.flag, shell_word(&v.to_string())));
            }
            FlagKind::CsvList => {
                let joined = v.as_array().map_or_else(
                    || plain(v),
                    |a| a.iter().map(plain).collect::<Vec<_>>().join(","),
                );
                line.push_str(&format!(" {} {}", f.flag, shell_word(&joined)));
            }
            FlagKind::KeyJsonPairs => {
                for (k, val) in v.as_object().into_iter().flatten() {
                    line.push_str(&format!(
                        " {} {}",
                        f.flag,
                        shell_word(&format!("{k}={val}"))
                    ));
                }
            }
        }
    }
    line
}

fn plain(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn shell_word(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.,:/=@+".contains(c));
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn defaults(spec: &OperationSpec) -> Value {
    let mut out = Map::new();
    if let Some(max) = spec.caps.max {
        out.insert(max.param.into(), json!(max.default));
    }
    // §7.3: the `fields` applied when the agent sends none.
    match spec.id {
        "jira.issue.get" => {
            out.insert("fields".into(), json!(crate::ISSUE_GET_DEFAULT_FIELDS));
        }
        "jira.search" => {
            out.insert("fields".into(), json!(crate::SEARCH_DEFAULT_FIELDS));
        }
        _ => {}
    }
    Value::Object(out)
}

fn default_caps(spec: &OperationSpec) -> Value {
    let c = &spec.caps;
    let mut out = Map::new();
    if let Some(max) = c.max {
        out.insert(
            "max".into(),
            json!({
                "param": max.param,
                "default": max.default,
                "hard_cap": max.hard_cap_default,
                "configurable": max.configurable,
            }),
        );
    }
    if let Some(n) = c.move_limit {
        out.insert("move_limit".into(), json!(n));
    }
    if let Some(n) = c.comments_cap {
        out.insert("comments_cap".into(), json!(n));
    }
    if let Some(n) = c.upload_max_bytes {
        out.insert("upload_max_bytes".into(), json!(n));
    }
    out.insert(
        "static_result_cap_bytes".into(),
        json!(c.static_result_cap_bytes),
    );
    Value::Object(out)
}

fn field_rules(spec: &OperationSpec) -> Value {
    match &spec.field_rules {
        None => Value::Null,
        Some(r) => json!({
            "fields_param": r.fields_param,
            "fields_map_param": r.fields_map_param,
            "expand_param": r.expand_param,
            "expand_allow": r.expand_allow,
        }),
    }
}
