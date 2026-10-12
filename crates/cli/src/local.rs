//! Commands that run entirely in the CLI (§4.1 "Local parsing"): `ops list` and `ops describe`
//! without `--instance` (PD-10), `--help` (PD-12), and the usage failures argv parsing produces.
//! They never connect to the app and never launch it.

use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::sandbox::ScriptLimits;
use atlas_duck_registry::{DescribeEnv, LimitsSource, describe, get, ops_list_json};
use serde_json::{Value, json};

use crate::argv::ParseError;
use crate::help::help_text;

/// The built-in defaults: what `core::gate` answers for a local `ops list`/`ops describe`, so the
/// two cannot drift (`u05_cli_ops_equal_core`).
pub(crate) fn describe_env() -> DescribeEnv {
    DescribeEnv {
        limits_source: LimitsSource::Default,
        available: None,
        caps: Value::Null,
        script_limits: serde_json::to_value(ScriptLimits::default()).unwrap_or(Value::Null),
    }
}

fn succeeded(data: Value) -> Envelope {
    Envelope {
        request_id: None,
        op_id: None,
        instance: None,
        status: Status::Succeeded,
        data: Some(data),
        edited: false,
        redacted: false,
        redaction_note: None,
        message: None,
        error: None,
        meta: None,
    }
}

/// A `usage` failure with optional `error.details`.
pub(crate) fn usage(message: &str, details: serde_json::Map<String, Value>) -> Envelope {
    let mut env = Envelope::failed(ErrorCode::Usage, false, message);
    if let Some(err) = env.error.as_mut()
        && !details.is_empty()
    {
        err.details = Some(details);
    }
    env
}

pub(crate) fn parse_error(e: ParseError) -> Envelope {
    usage(&e.message, e.details)
}

pub(crate) fn ops_list() -> Envelope {
    succeeded(ops_list_json(&describe_env()))
}

pub(crate) fn ops_describe(op_id: &str) -> Envelope {
    match get(op_id) {
        Some(spec) => succeeded(describe(spec, &describe_env())),
        None => {
            let mut details = serde_json::Map::new();
            details.insert("op_id".into(), json!(op_id));
            usage(&format!("unknown op id: {op_id}"), details)
        }
    }
}

pub(crate) fn help(path: &[String]) -> Envelope {
    match help_text(path) {
        Some(text) => succeeded(json!({ "help": text })),
        None => {
            let mut details = serde_json::Map::new();
            details.insert("command".into(), json!(path.join(" ")));
            usage(&format!("unknown command: {}", path.join(" ")), details)
        }
    }
}

/// `mcp` and `verify-export` (M9, M10).
pub(crate) fn not_in_this_build(command: &str) -> Envelope {
    let mut details = serde_json::Map::new();
    details.insert("command".into(), json!(command));
    usage("not available in this build", details)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_list_matches_registry_json() {
        let env = ops_list();
        assert_eq!(env.status, Status::Succeeded);
        assert_eq!(env.request_id, None);
        assert_eq!(env.data, Some(ops_list_json(&describe_env())));
    }

    #[test]
    fn ops_describe_known_op() {
        let env = ops_describe("jira.issue.get");
        assert_eq!(env.status, Status::Succeeded);
        let data = env.data.unwrap_or(Value::Null);
        assert_eq!(data["op_id"], "jira.issue.get");
        assert_eq!(data["limits_source"], "default");
        assert!(data.get("available").is_none());
    }

    #[test]
    fn ops_describe_unknown_usage() {
        let env = ops_describe("jira.nope");
        assert_eq!(env.status, Status::Failed);
        let err = env.error.unwrap_or_else(|| panic!("error"));
        assert_eq!(err.code, ErrorCode::Usage);
        assert_eq!(
            err.details.and_then(|d| d.get("op_id").cloned()),
            Some(json!("jira.nope"))
        );
    }

    #[test]
    fn mcp_and_verify_export_not_in_this_build() {
        for name in ["mcp", "verify-export"] {
            let env = not_in_this_build(name);
            let err = env.error.unwrap_or_else(|| panic!("error"));
            assert_eq!(err.code, ErrorCode::Usage);
            assert_eq!(err.message, "not available in this build");
        }
    }
}
