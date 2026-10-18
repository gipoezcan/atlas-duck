//! The MCP tool catalog (PD-118, PD-119, PD-120), generated from the registry at runtime: no
//! connection and no app are needed for `tools/list`. Also the pure argument checks the server runs
//! before any connection (rmcp does not validate `arguments` against `inputSchema`).

// The plan's interface (T6, T8) returns the `usage` envelope itself as the error.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use atlas_duck_ipc::envelope::Envelope;
use atlas_duck_registry::{OpClass, OperationSpec, all, describe, get};
use rmcp::model::{Tool, ToolAnnotations};
use serde_json::{Map, Value, json};

use super::config::ToolSet;
use crate::local;

/// The eight tools both sets carry (`call` is the generic set's ninth).
pub(crate) const FIXED_TOOLS: [&str; 8] = [
    "script_run",
    "request_await",
    "request_status",
    "request_cancel",
    "request_list",
    "ops_list",
    "ops_describe",
    "instances_list",
];

/// The generic set's own tool.
pub(crate) const CALL_TOOL: &str = "call";

/// PD-119: the Write ops that change or remove existing state (`destructiveHint: true`). Every other
/// Write op only adds something.
pub(crate) const DESTRUCTIVE: &[&str] = &[
    "jira.issue.edit",
    "jira.issue.transition",
    "jira.issue.assign",
    "jira.sprint.move_issues",
    "jira.backlog.move_issues",
    "confluence.page.update",
    "confluence.page.move",
    "confluence.label.remove",
    "confluence.attachment.upload",
];

/// The `limits` keys of `script_run` (§9.4).
const LIMIT_KEYS: [&str; 8] = [
    "timeout_s",
    "heap_mb",
    "process_mb",
    "max_calls",
    "max_fetch_mb",
    "max_call_result_mb",
    "max_result_mb",
    "max_concurrent_calls",
];

const REASON_MAX_CHARS: usize = 1000;

/// `tools/list`: the catalog of one tool set, op tools first in registry order.
pub(crate) fn catalog(set: ToolSet) -> Vec<Tool> {
    let mut tools = Vec::new();
    match set {
        ToolSet::Full => tools.extend(all().iter().map(op_tool)),
        ToolSet::Generic => tools.push(call_tool()),
    }
    tools.push(script_run_tool());
    tools.extend(request_and_ops_tools());
    tools
}

/// The op id with `.` replaced by `_` (MCP tool names have no dot).
pub(crate) fn tool_name(op_id: &str) -> String {
    op_id.replace('.', "_")
}

/// The registry op a tool name stands for.
pub(crate) fn op_for_tool(name: &str) -> Option<&'static OperationSpec> {
    all().iter().find(|spec| tool_name(spec.id) == name)
}

/// The op tool's `reason`/`instance` split from its params: `(params, reason, instance)`. The
/// params keep every other key unchanged; the app validates them. A wrong type is a `usage`
/// envelope naming the argument.
// The op tool bodies (Task 8) consume it.
#[allow(dead_code)]
pub(crate) fn split_op_args(
    mut args: Map<String, Value>,
) -> Result<(Value, Option<String>, Option<String>), Envelope> {
    let reason = take_reason(&mut args)?;
    let instance = take_instance(&mut args)?;
    Ok((Value::Object(args), reason, instance))
}

/// PD-118 "Validation": the fixed tools' arguments (and `call`'s) before any connection. A
/// violation is a `usage` envelope with `details.arg` naming the argument.
pub(crate) fn validate_fixed_args(tool: &str, args: &Map<String, Value>) -> Result<(), Envelope> {
    match tool {
        "script_run" => script_run_args(args),
        "request_await" | "request_status" | "request_cancel" => {
            only_keys(args, &["request_id"])?;
            request_id(args)
        }
        "request_list" => request_list_args(args),
        "ops_list" => {
            only_keys(args, &["instance"])?;
            check_instance(args)
        }
        "ops_describe" => {
            only_keys(args, &["op_id", "instance"])?;
            op_id(args)?;
            check_instance(args)
        }
        "instances_list" => only_keys(args, &[]),
        CALL_TOOL => {
            only_keys(args, &["op_id", "params", "reason", "instance"])?;
            op_id(args)?;
            match args.get("params") {
                Some(Value::Object(_)) => {}
                Some(_) => return Err(arg_error("params", "must be an object")),
                None => return Err(arg_error("params", "is required")),
            }
            check_reason(args)?;
            check_instance(args)
        }
        _ => Err(arg_error("tool", "unknown tool")),
    }
}

// ---- argument checks ------------------------------------------------------------------------

fn arg_error(arg: &str, why: &str) -> Envelope {
    // The key is caller text: cap what is echoed, like the CLI does for its own arguments.
    let arg = crate::argv::clip(arg);
    let mut details = Map::new();
    details.insert("arg".into(), Value::from(arg.as_str()));
    local::usage(&format!("{arg} {why}"), details)
}

fn only_keys(args: &Map<String, Value>, allowed: &[&str]) -> Result<(), Envelope> {
    match args.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(key) => Err(arg_error(key, "is not an argument of this tool")),
        None => Ok(()),
    }
}

fn is_request_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("req_") else {
        return false;
    };
    (20..=64).contains(&rest.len())
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn request_id(args: &Map<String, Value>) -> Result<(), Envelope> {
    match args.get("request_id") {
        Some(Value::String(s)) if is_request_id(s) => Ok(()),
        Some(Value::String(_)) => Err(arg_error(
            "request_id",
            "must match ^req_[A-Za-z0-9_-]{20,64}$",
        )),
        Some(_) => Err(arg_error("request_id", "must be a string")),
        None => Err(arg_error("request_id", "is required")),
    }
}

fn op_id(args: &Map<String, Value>) -> Result<(), Envelope> {
    match args.get("op_id") {
        Some(Value::String(s)) if get(s).is_some() => Ok(()),
        Some(Value::String(_)) => Err(arg_error("op_id", "is not a registry operation (ops_list)")),
        Some(_) => Err(arg_error("op_id", "must be a string")),
        None => Err(arg_error("op_id", "is required")),
    }
}

fn optional_string<'a>(
    args: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, Envelope> {
    match args.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(arg_error(key, "must be a string")),
    }
}

fn check_reason(args: &Map<String, Value>) -> Result<(), Envelope> {
    match optional_string(args, "reason")? {
        Some(s) if s.chars().count() > REASON_MAX_CHARS => Err(arg_error(
            "reason",
            &format!("must be at most {REASON_MAX_CHARS} characters"),
        )),
        _ => Ok(()),
    }
}

fn check_instance(args: &Map<String, Value>) -> Result<(), Envelope> {
    match optional_string(args, "instance")? {
        Some("") => Err(arg_error("instance", "must not be empty")),
        _ => Ok(()),
    }
}

fn take_reason(args: &mut Map<String, Value>) -> Result<Option<String>, Envelope> {
    check_reason(args)?;
    Ok(args.remove("reason").and_then(into_string))
}

fn take_instance(args: &mut Map<String, Value>) -> Result<Option<String>, Envelope> {
    check_instance(args)?;
    Ok(args.remove("instance").and_then(into_string))
}

fn into_string(v: Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s),
        _ => None,
    }
}

fn script_run_args(args: &Map<String, Value>) -> Result<(), Envelope> {
    only_keys(args, &["source", "args", "limits", "dry_run", "reason"])?;
    match args.get("source") {
        Some(Value::String(_)) => {}
        Some(_) => return Err(arg_error("source", "must be a string")),
        None => return Err(arg_error("source", "is required")),
    }
    match args.get("dry_run") {
        None => {}
        Some(Value::String(s)) if s == "full" || s == "sparse" => {}
        Some(_) => return Err(arg_error("dry_run", "must be \"full\" or \"sparse\"")),
    }
    match args.get("limits") {
        None => {}
        Some(Value::Object(limits)) => {
            for (key, value) in limits {
                let path = format!("limits.{key}");
                if !LIMIT_KEYS.contains(&key.as_str()) {
                    return Err(arg_error(&path, "is not a script limit"));
                }
                if value.as_u64().is_none_or(|n| n < 1) {
                    return Err(arg_error(&path, "must be an integer of at least 1"));
                }
            }
        }
        Some(_) => return Err(arg_error("limits", "must be an object")),
    }
    check_reason(args)
}

fn request_list_args(args: &Map<String, Value>) -> Result<(), Envelope> {
    only_keys(args, &["agent", "state", "match_params"])?;
    optional_string(args, "agent")?;
    match args.get("state") {
        None => {}
        Some(Value::String(s)) if s == "pending" || s == "recent" => {}
        Some(_) => return Err(arg_error("state", "must be \"pending\" or \"recent\"")),
    }
    match args.get("match_params") {
        None => Ok(()),
        Some(Value::Object(m)) => {
            if let Some(key) = m
                .keys()
                .find(|k| !["op_id", "params", "instance"].contains(&k.as_str()))
            {
                return Err(arg_error(
                    &format!("match_params.{key}"),
                    "is not a match_params key",
                ));
            }
            op_id(m).map_err(|e| prefixed(e, "match_params"))?;
            if !matches!(m.get("params"), Some(Value::Object(_))) {
                return Err(arg_error("match_params.params", "must be an object"));
            }
            check_instance(m).map_err(|e| prefixed(e, "match_params"))
        }
        Some(_) => Err(arg_error("match_params", "must be an object")),
    }
}

/// Re-names the argument of a nested check (`op_id` -> `match_params.op_id`).
fn prefixed(e: Envelope, parent: &str) -> Envelope {
    let arg = e
        .error
        .as_ref()
        .and_then(|err| err.details.as_ref())
        .and_then(|d| d.get("arg"))
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string();
    let why = e
        .error
        .as_ref()
        .map(|err| {
            err.message
                .strip_prefix(&arg)
                .unwrap_or(&err.message)
                .trim_start()
        })
        .unwrap_or("is invalid")
        .to_string();
    arg_error(&format!("{parent}.{arg}"), &why)
}

// ---- catalog --------------------------------------------------------------------------------

fn annotations(read_only: bool, destructive: bool) -> ToolAnnotations {
    ToolAnnotations::new()
        .read_only(read_only)
        .destructive(destructive)
        .idempotent(false)
        .open_world(true)
}

fn object(v: Value) -> Arc<Map<String, Value>> {
    match v {
        Value::Object(m) => Arc::new(m),
        _ => Arc::new(Map::new()),
    }
}

fn op_tool(spec: &'static OperationSpec) -> Tool {
    let write = spec.class == OpClass::Write;
    let d = describe(spec, &local::describe_env());
    let guidance = d["description"].as_str().unwrap_or_default();
    let mut description = format!(
        "{} ({}; approval: {}).",
        spec.id,
        if write { "write" } else { "read" },
        if write { "approve" } else { "release" },
    );
    if !guidance.is_empty() {
        description.push(' ');
        description.push_str(guidance);
    }
    description.push_str(" Result shapes: ops_describe.");

    let mut schema = spec.params_schema_json();
    if let Some(root) = schema.as_object_mut() {
        let props = root
            .entry("properties")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(props) = props.as_object_mut() {
            props.insert(
                "reason".into(),
                json!({"type": "string", "maxLength": REASON_MAX_CHARS}),
            );
            props.insert("instance".into(), json!({"type": "string", "minLength": 1}));
        }
    }
    let destructive = write && DESTRUCTIVE.contains(&spec.id);
    Tool::new(tool_name(spec.id), description, object(schema))
        .with_annotations(annotations(!write, destructive))
}

fn limits_sentence() -> String {
    let limits = local::describe_env().script_limits;
    let pairs: Vec<String> = limits
        .as_object()
        .map(|m| m.iter().map(|(k, v)| format!("{k}={v}")).collect())
        .unwrap_or_default();
    pairs.join(", ")
}

fn script_run_tool() -> Tool {
    let description = format!(
        "Run a read-only script in the sandbox; the user approves only the final result. Run every \
         new or changed script with dry_run sparse and dry_run full first (no approval needed; \
         results come from documented examples, meta.dry_run: true), then run it for real once. \
         Default limits: {}; the effective limits for an instance: ops_describe with op_id and \
         instance (field script_limits).",
        limits_sentence()
    );
    let limit_props: Map<String, Value> = LIMIT_KEYS
        .iter()
        .map(|k| ((*k).to_string(), json!({"type": "integer", "minimum": 1})))
        .collect();
    let schema = json!({
        "type": "object",
        "properties": {
            "source": {"type": "string"},
            "args": {},
            "limits": {
                "type": "object",
                "properties": limit_props,
                "additionalProperties": false,
            },
            "dry_run": {"enum": ["full", "sparse"]},
            "reason": {"type": "string", "maxLength": REASON_MAX_CHARS},
        },
        "required": ["source"],
        "additionalProperties": false,
    });
    Tool::new("script_run", description, object(schema)).with_annotations(annotations(true, false))
}

fn call_tool() -> Tool {
    let schema = json!({
        "type": "object",
        "properties": {
            "op_id": {"type": "string", "enum": op_ids()},
            "params": {"type": "object"},
            "reason": {"type": "string", "maxLength": REASON_MAX_CHARS},
            "instance": {"type": "string", "minLength": 1},
        },
        "required": ["op_id", "params"],
        "additionalProperties": false,
    });
    Tool::new(
        CALL_TOOL,
        "Submit any registry operation by id with its params (ops_list, ops_describe). A write \
         needs the user's approval. Never resubmit a pending request.",
        object(schema),
    )
    .with_annotations(annotations(false, true))
}

fn op_ids() -> Vec<&'static str> {
    all().iter().map(|spec| spec.id).collect()
}

fn request_id_schema() -> Value {
    json!({"type": "string", "pattern": "^req_[A-Za-z0-9_-]{20,64}$"})
}

fn request_and_ops_tools() -> Vec<Tool> {
    let by_id = json!({
        "type": "object",
        "properties": {"request_id": request_id_schema()},
        "required": ["request_id"],
        "additionalProperties": false,
    });
    let instance = json!({"type": "string", "minLength": 1});
    vec![
        Tool::new(
            "request_await",
            "Wait for a request's decision (up to ATLAS_DUCK_MCP_TIMEOUT). Never resubmit a \
             pending request.",
            object(by_id.clone()),
        )
        .with_annotations(annotations(true, false)),
        Tool::new(
            "request_status",
            "Report where a request stands. Never blocks and never returns data.",
            object(by_id.clone()),
        )
        .with_annotations(annotations(true, false)),
        Tool::new(
            "request_cancel",
            "Cancel a request by id. Only this tool cancels: dropping or cancelling a tool call \
             never does.",
            object(by_id),
        )
        .with_annotations(annotations(false, false)),
        Tool::new(
            "request_list",
            "List pending or recent requests. Metadata only; recover a lost id with match_params.",
            object(json!({
                "type": "object",
                "properties": {
                    "agent": {"type": "string"},
                    "state": {"enum": ["pending", "recent"]},
                    "match_params": {
                        "type": "object",
                        "properties": {
                            "op_id": {"type": "string", "enum": op_ids()},
                            "params": {"type": "object"},
                            "instance": instance.clone(),
                        },
                        "required": ["op_id", "params"],
                        "additionalProperties": false,
                    },
                },
                "additionalProperties": false,
            })),
        )
        .with_annotations(annotations(true, false)),
        Tool::new(
            "ops_list",
            "List the operations with class, approval and description.",
            object(json!({
                "type": "object",
                "properties": {"instance": instance.clone()},
                "additionalProperties": false,
            })),
        )
        .with_annotations(annotations(true, false)),
        Tool::new(
            "ops_describe",
            "Describe one operation: params schema, result shapes, caps and script_limits \
             (effective with an instance).",
            object(json!({
                "type": "object",
                "properties": {
                    "op_id": {"type": "string", "enum": op_ids()},
                    "instance": instance,
                },
                "required": ["op_id"],
                "additionalProperties": false,
            })),
        )
        .with_annotations(annotations(true, false)),
        Tool::new(
            "instances_list",
            "List the configured instances.",
            object(json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            })),
        )
        .with_annotations(annotations(true, false)),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use atlas_duck_registry::WRITE_GUIDANCE;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// PD-119: the Write ops that only add something.
    const ADDITIVE: &[&str] = &[
        "jira.issue.create",
        "jira.comment.add",
        "jira.worklog.add",
        "jira.issuelink.create",
        "confluence.page.create",
        "confluence.comment.add",
        "confluence.label.add",
    ];

    fn json_of(t: &Tool) -> Value {
        serde_json::to_value(t).unwrap_or(Value::Null)
    }

    fn by_name(set: ToolSet, name: &str) -> Value {
        catalog(set)
            .iter()
            .map(json_of)
            .find(|t| t["name"] == name)
            .unwrap_or(Value::Null)
    }

    #[test]
    fn script_run_description_states_default_limits() {
        let tool = by_name(ToolSet::Full, "script_run");
        let text = tool["description"].as_str().unwrap_or_default();
        let limits = local::describe_env().script_limits;
        let map = limits.as_object().expect("script_limits is an object");
        assert_eq!(map.len(), 8);
        for (k, v) in map {
            assert!(text.contains(&format!("{k}={v}")), "{k}: {text}");
        }
        assert!(
            text.contains("ops_describe with op_id and instance"),
            "{text}"
        );
        assert!(text.contains("script_limits"), "{text}");
    }

    #[test]
    fn limit_keys_match_the_script_limits_fields() {
        let limits = local::describe_env().script_limits;
        let map = limits.as_object().expect("script_limits is an object");
        let mut fields: Vec<&str> = map.keys().map(String::as_str).collect();
        let mut keys = LIMIT_KEYS.to_vec();
        fields.sort_unstable();
        keys.sort_unstable();
        assert_eq!(fields, keys, "LIMIT_KEYS is out of step with ScriptLimits");
    }

    #[test]
    fn unknown_argument_keys_are_capped_in_the_error() {
        // Multi-byte chars so a byte cut would land mid-character.
        let key = "\u{e4}".repeat(5000);
        let top = json!({ key.clone(): 1 });
        let nested = json!({"source": "1", "limits": { key.clone(): 1 }});
        let matched = json!({"match_params": { "op_id": "jira.issue.get", key.clone(): 1 }});
        for (tool, args) in [
            ("script_run", top.clone()),
            ("script_run", nested),
            ("request_list", matched),
            ("ops_list", top),
        ] {
            let Value::Object(map) = args else {
                panic!("object expected")
            };
            let Err(env) = validate_fixed_args(tool, &map) else {
                panic!("{tool}: an unknown key must be refused");
            };
            let arg = env
                .error
                .as_ref()
                .and_then(|e| e.details.as_ref())
                .and_then(|d| d.get("arg"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let message = env.error.as_ref().map(|e| e.message.as_str()).unwrap_or("");
            assert!(arg.contains('\u{e4}'), "{tool}: the key is echoed: {arg}");
            assert!(arg.len() < 600, "{tool}: {}", arg.len());
            assert!(message.len() < 700, "{tool}: {}", message.len());
        }
    }

    fn rid() -> String {
        format!("req_{}", "a".repeat(22))
    }

    #[test]
    fn validate_fixed_args_table() {
        let rid = rid();
        let table: Vec<(&str, Value, Option<&str>)> = vec![
            ("script_run", json!({"source": "1"}), None),
            (
                "script_run",
                json!({"source": "1", "args": [1, {"a": null}], "limits": {"heap_mb": 8}, "dry_run": "sparse", "reason": "r"}),
                None,
            ),
            ("script_run", json!({}), Some("source")),
            ("script_run", json!({"source": 1}), Some("source")),
            (
                "script_run",
                json!({"source": "1", "dry_run": "none"}),
                Some("dry_run"),
            ),
            (
                "script_run",
                json!({"source": "1", "dry_run": true}),
                Some("dry_run"),
            ),
            (
                "script_run",
                json!({"source": "1", "limits": []}),
                Some("limits"),
            ),
            (
                "script_run",
                json!({"source": "1", "limits": {"nope": 1}}),
                Some("limits.nope"),
            ),
            (
                "script_run",
                json!({"source": "1", "limits": {"heap_mb": 0}}),
                Some("limits.heap_mb"),
            ),
            (
                "script_run",
                json!({"source": "1", "limits": {"heap_mb": 1.5}}),
                Some("limits.heap_mb"),
            ),
            (
                "script_run",
                json!({"source": "1", "limits": {"heap_mb": "8"}}),
                Some("limits.heap_mb"),
            ),
            (
                "script_run",
                json!({"source": "1", "reason": 3}),
                Some("reason"),
            ),
            (
                "script_run",
                json!({"source": "1", "extra": 1}),
                Some("extra"),
            ),
            ("request_await", json!({"request_id": rid}), None),
            ("request_status", json!({"request_id": rid}), None),
            ("request_cancel", json!({"request_id": rid}), None),
            ("request_await", json!({}), Some("request_id")),
            (
                "request_await",
                json!({"request_id": 5}),
                Some("request_id"),
            ),
            (
                "request_status",
                json!({"request_id": "req_short"}),
                Some("request_id"),
            ),
            (
                "request_cancel",
                json!({"request_id": "x".repeat(30)}),
                Some("request_id"),
            ),
            (
                "request_cancel",
                json!({"request_id": format!("req_{}", "a".repeat(65))}),
                Some("request_id"),
            ),
            (
                "request_cancel",
                json!({"request_id": format!("req_{}!", "a".repeat(22))}),
                Some("request_id"),
            ),
            (
                "request_await",
                json!({"request_id": rid, "x": 1}),
                Some("x"),
            ),
            ("request_list", json!({}), None),
            (
                "request_list",
                json!({"agent": "a", "state": "pending"}),
                None,
            ),
            (
                "request_list",
                json!({"match_params": {"op_id": "jira.issue.get", "params": {}, "instance": "i"}}),
                None,
            ),
            ("request_list", json!({"agent": 1}), Some("agent")),
            ("request_list", json!({"state": "all"}), Some("state")),
            (
                "request_list",
                json!({"match_params": 1}),
                Some("match_params"),
            ),
            (
                "request_list",
                json!({"match_params": {"params": {}}}),
                Some("match_params.op_id"),
            ),
            (
                "request_list",
                json!({"match_params": {"op_id": "nope", "params": {}}}),
                Some("match_params.op_id"),
            ),
            (
                "request_list",
                json!({"match_params": {"op_id": "jira.issue.get"}}),
                Some("match_params.params"),
            ),
            (
                "request_list",
                json!({"match_params": {"op_id": "jira.issue.get", "params": {}, "z": 1}}),
                Some("match_params.z"),
            ),
            (
                "request_list",
                json!({"match_params": {"op_id": "jira.issue.get", "params": {}, "instance": ""}}),
                Some("match_params.instance"),
            ),
            ("request_list", json!({"q": 1}), Some("q")),
            ("ops_list", json!({}), None),
            ("ops_list", json!({"instance": "i"}), None),
            ("ops_list", json!({"instance": ""}), Some("instance")),
            ("ops_list", json!({"instance": 1}), Some("instance")),
            ("ops_describe", json!({"op_id": "jira.issue.get"}), None),
            (
                "ops_describe",
                json!({"op_id": "jira.issue.get", "instance": "i"}),
                None,
            ),
            ("ops_describe", json!({}), Some("op_id")),
            ("ops_describe", json!({"op_id": "jira.nope"}), Some("op_id")),
            ("ops_describe", json!({"op_id": 1}), Some("op_id")),
            ("instances_list", json!({}), None),
            ("instances_list", json!({"instance": "i"}), Some("instance")),
            (
                "call",
                json!({"op_id": "jira.issue.get", "params": {}}),
                None,
            ),
            (
                "call",
                json!({"op_id": "jira.issue.get", "params": {"a": 1}, "reason": "r", "instance": "i"}),
                None,
            ),
            ("call", json!({"op_id": "jira.issue.get"}), Some("params")),
            (
                "call",
                json!({"op_id": "jira.issue.get", "params": []}),
                Some("params"),
            ),
            (
                "call",
                json!({"op_id": "nope", "params": {}}),
                Some("op_id"),
            ),
            (
                "call",
                json!({"op_id": "jira.issue.get", "params": {}, "reason": "x".repeat(1001)}),
                Some("reason"),
            ),
            (
                "call",
                json!({"op_id": "jira.issue.get", "params": {}, "k": 1}),
                Some("k"),
            ),
            ("not_a_tool", json!({}), Some("tool")),
        ];
        for (tool, args, want) in table {
            let map = args.as_object().cloned().unwrap_or_default();
            let got = validate_fixed_args(tool, &map);
            match (got, want) {
                (Ok(()), None) => {}
                (Err(e), Some(arg)) => {
                    let err = e.error.as_ref().expect("usage carries an error");
                    assert_eq!(
                        serde_json::to_value(err.code).unwrap_or(Value::Null),
                        json!("usage"),
                        "{tool} {args}"
                    );
                    let details = err.details.as_ref().expect("details.arg");
                    assert_eq!(
                        details.get("arg"),
                        Some(&json!(arg)),
                        "{tool} {args}: {}",
                        err.message
                    );
                }
                (got, want) => assert_eq!(
                    got.is_ok(),
                    want.is_none(),
                    "{tool} {args}: got {got:?}, want {want:?}"
                ),
            }
        }
    }

    #[test]
    fn fixed_tools_const_matches_the_catalog() {
        let names: BTreeSet<String> = catalog(ToolSet::Generic)
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        for f in FIXED_TOOLS {
            assert!(names.contains(f), "{f}");
        }
    }

    #[test]
    fn full_set_has_one_tool_per_op_plus_eight() {
        let tools = catalog(ToolSet::Full);
        assert_eq!(all().len(), 46);
        assert_eq!(tools.len(), 54);
        for spec in all() {
            let name = tool_name(spec.id);
            assert_eq!(
                tools.iter().filter(|t| t.name == name).count(),
                1,
                "{}",
                spec.id
            );
            assert_eq!(op_for_tool(&name).map(|s| s.id), Some(spec.id));
        }
        for f in FIXED_TOOLS {
            assert_eq!(tools.iter().filter(|t| t.name == f).count(), 1, "{f}");
            assert!(op_for_tool(f).is_none(), "{f}");
        }
        assert!(op_for_tool("call").is_none());
        assert!(!tools.iter().any(|t| t.name == CALL_TOOL));
    }

    #[test]
    fn generic_set_is_call_plus_eight() {
        let tools = catalog(ToolSet::Generic);
        assert_eq!(tools.len(), 9);
        let names: BTreeSet<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        let mut want: BTreeSet<&str> = FIXED_TOOLS.into_iter().collect();
        want.insert(CALL_TOOL);
        assert_eq!(names, want);
    }

    #[test]
    fn tool_names_match_mcp_charset_and_are_unique() {
        let tools = catalog(ToolSet::Full);
        let mut seen = BTreeSet::new();
        for t in &tools {
            let n = t.name.as_ref();
            assert!((1..=64).contains(&n.len()), "{n}");
            assert!(
                n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                "{n}"
            );
            assert!(seen.insert(n.to_string()), "duplicate {n}");
        }
        for spec in all() {
            let n = tool_name(spec.id);
            assert!(!FIXED_TOOLS.contains(&n.as_str()) && n != CALL_TOOL, "{n}");
        }
    }

    #[test]
    fn no_op_param_named_reason_or_instance() {
        for spec in all() {
            let schema = spec.params_schema_json();
            let props = schema["properties"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            for banned in ["reason", "instance", "op_id", "dry_run"] {
                assert!(!props.contains_key(banned), "{} has {banned}", spec.id);
            }
        }
    }

    #[test]
    fn input_schema_is_params_schema_plus_reason_and_instance() {
        for spec in all() {
            let params = spec.params_schema_json();
            let tool = by_name(ToolSet::Full, &tool_name(spec.id));
            let schema = &tool["inputSchema"];
            let want_props = params["properties"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            let got_props = schema["properties"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            for (k, v) in &want_props {
                assert_eq!(got_props.get(k), Some(v), "{} {k}", spec.id);
            }
            assert_eq!(got_props.len(), want_props.len() + 2, "{}", spec.id);
            assert_eq!(
                got_props["reason"],
                json!({"type": "string", "maxLength": 1000})
            );
            assert_eq!(
                got_props["instance"],
                json!({"type": "string", "minLength": 1})
            );
            assert_eq!(schema["required"], params["required"], "{}", spec.id);
            assert_eq!(schema["additionalProperties"], json!(false), "{}", spec.id);
            assert_eq!(schema["$schema"], params["$schema"], "{}", spec.id);
            assert_eq!(schema["examples"], params["examples"], "{}", spec.id);
        }
    }

    #[test]
    fn no_tool_declares_output_schema() {
        for set in [ToolSet::Full, ToolSet::Generic] {
            for t in catalog(set) {
                assert!(t.output_schema.is_none(), "{}", t.name);
                assert!(json_of(&t).get("outputSchema").is_none(), "{}", t.name);
            }
        }
    }

    fn hints(t: &Value) -> (Option<bool>, Option<bool>, Option<bool>, Option<bool>) {
        let a = &t["annotations"];
        (
            a["readOnlyHint"].as_bool(),
            a["destructiveHint"].as_bool(),
            a["idempotentHint"].as_bool(),
            a["openWorldHint"].as_bool(),
        )
    }

    #[test]
    fn annotations_read_only_and_destructive_table() {
        let write_ids: BTreeSet<&str> = all()
            .iter()
            .filter(|s| s.class == OpClass::Write)
            .map(|s| s.id)
            .collect();
        let destructive: BTreeSet<&str> = DESTRUCTIVE.iter().copied().collect();
        let additive: BTreeSet<&str> = ADDITIVE.iter().copied().collect();
        assert_eq!(
            destructive.len(),
            DESTRUCTIVE.len(),
            "DESTRUCTIVE has a duplicate"
        );
        assert_eq!(additive.len(), ADDITIVE.len());
        assert!(
            destructive.is_subset(&write_ids),
            "DESTRUCTIVE names a non-write op"
        );
        assert!(destructive.is_disjoint(&additive));
        let union: BTreeSet<&str> = destructive.union(&additive).copied().collect();
        assert_eq!(
            union, write_ids,
            "every write op is destructive or additive, once"
        );

        for spec in all() {
            let t = by_name(ToolSet::Full, &tool_name(spec.id));
            let write = spec.class == OpClass::Write;
            let want = (
                Some(!write),
                Some(write && destructive.contains(spec.id)),
                Some(false),
                Some(true),
            );
            assert_eq!(hints(&t), want, "{}", spec.id);
        }
        let rw = |set, name: &str| hints(&by_name(set, name));
        for name in [
            "script_run",
            "request_await",
            "request_status",
            "request_list",
            "ops_list",
            "ops_describe",
            "instances_list",
        ] {
            assert_eq!(
                rw(ToolSet::Full, name),
                (Some(true), Some(false), Some(false), Some(true)),
                "{name}"
            );
        }
        assert_eq!(
            rw(ToolSet::Full, "request_cancel"),
            (Some(false), Some(false), Some(false), Some(true))
        );
        assert_eq!(
            rw(ToolSet::Generic, "call"),
            (Some(false), Some(true), Some(false), Some(true))
        );
    }

    #[test]
    fn descriptions_carry_registry_guidance() {
        for spec in all() {
            let t = by_name(ToolSet::Full, &tool_name(spec.id));
            let text = t["description"].as_str().unwrap_or_default();
            assert!(text.starts_with(spec.id), "{text}");
            assert!(text.ends_with("Result shapes: ops_describe."), "{text}");
            if spec.paginated.is_some() {
                assert!(
                    text.contains("continue only from meta.page.next_start"),
                    "{}",
                    spec.id
                );
            }
            if spec.class == OpClass::Write {
                assert!(text.contains(WRITE_GUIDANCE), "{}", spec.id);
                assert!(text.contains("(write; approval: approve)"), "{}", spec.id);
            } else {
                assert!(text.contains("(read; approval: release)"), "{}", spec.id);
            }
        }
        let wait = by_name(ToolSet::Full, "request_await");
        let text = wait["description"].as_str().unwrap_or_default();
        assert!(text.contains("Never resubmit a pending request."), "{text}");
    }

    #[test]
    fn split_op_args_table() {
        let obj = |v: Value| v.as_object().cloned().unwrap_or_default();
        let (params, reason, instance) = split_op_args(obj(json!({
            "key": "A-1", "reason": "why", "instance": "prod", "n": 2
        })))
        .expect("valid");
        assert_eq!(params, json!({"key": "A-1", "n": 2}));
        assert_eq!(reason.as_deref(), Some("why"));
        assert_eq!(instance.as_deref(), Some("prod"));

        let (params, reason, instance) = split_op_args(obj(json!({}))).expect("valid");
        assert_eq!(params, json!({}));
        assert_eq!((reason, instance), (None, None));

        for (bad, arg) in [
            (json!({"reason": 1}), "reason"),
            (json!({"reason": null}), "reason"),
            (json!({"instance": 1}), "instance"),
            (json!({"instance": ""}), "instance"),
            (json!({"reason": "x".repeat(1001)}), "reason"),
        ] {
            let e = split_op_args(obj(bad.clone())).expect_err("usage");
            let err = e.error.as_ref().expect("error");
            let details = err.details.as_ref().expect("details");
            assert_eq!(details.get("arg"), Some(&json!(arg)), "{bad}");
        }
        // 1000 characters (not bytes) are fine.
        assert!(split_op_args(obj(json!({"reason": "é".repeat(1000)}))).is_ok());
    }

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    fn check_golden(set: ToolSet, name: &str) -> TestResult {
        let mut got = serde_json::to_string_pretty(&catalog(set))?;
        got.push('\n');
        let path = fixture(name);
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&path, &got)?;
        }
        let want = std::fs::read_to_string(&path)
            .map_err(|e| format!("{}: {e} (run with UPDATE_GOLDEN=1)", path.display()))?
            .replace("\r\n", "\n");
        assert!(
            got == want,
            "{name} differs from the catalog (review the diff, then UPDATE_GOLDEN=1)"
        );
        Ok(())
    }

    #[test]
    fn tool_catalog_golden() -> TestResult {
        check_golden(ToolSet::Full, "mcp_tools_full.json")?;
        check_golden(ToolSet::Generic, "mcp_tools_generic.json")
    }
}
