//! Commands that run entirely in the CLI (§4.1 "Local parsing"): `ops list` and `ops describe`
//! without `--instance` (PD-10), `--help` (PD-12), and the usage failures argv parsing produces.
//! They never connect to the app and never launch it. (`verify-export` runs the app's verifier
//! as a child process; see `verify_export`.)

use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_registry::{describe, get, ops_list_json};
use serde_json::{Value, json};

use crate::argv::{ParseError, clip};
use crate::help::help_text;

/// The built-in describe environment and the `usage` envelope, shared with the MCP tool layer
/// (`atlas-duck-mcp-tools`, M12 PD-193).
pub(crate) use atlas_duck_mcp_tools::local::{describe_env, usage};

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

pub(crate) fn parse_error(e: ParseError) -> Envelope {
    if e.deadline_expired {
        // §4.1: the `--timeout` deadline ran out before submission; nothing was queued.
        let mut env = Envelope::failed(ErrorCode::Unreachable, true, &e.message);
        if let Some(err) = env.error.as_mut() {
            let mut details = serde_json::Map::new();
            details.insert("reason".into(), json!("launch_timeout"));
            err.details = Some(details);
        }
        return env;
    }
    usage(&e.message, e.details)
}

pub(crate) fn ops_list() -> Envelope {
    succeeded(ops_list_json(&describe_env()))
}

pub(crate) fn ops_describe(op_id: &str) -> Envelope {
    match get(op_id) {
        Some(spec) => succeeded(describe(spec, &describe_env())),
        None => {
            let op_id = clip(op_id);
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
            let command = clip(&path.join(" "));
            let mut details = serde_json::Map::new();
            details.insert("command".into(), json!(command));
            usage(&format!("unknown command: {command}"), details)
        }
    }
}

/// What `execute` answers for a valid `mcp` invocation: `run` serves instead of printing it.
pub(crate) fn mcp_serving() -> Envelope {
    succeeded(Value::Null)
}

/// `verify-export` reached argv parsing: a global flag came before the command word (`run` starts
/// `verify-export` only when it is the first argument, because the app owns its flags).
pub(crate) fn verify_export_misplaced() -> Envelope {
    let mut details = serde_json::Map::new();
    details.insert("command".into(), json!("verify-export"));
    usage(
        "verify-export must be the first argument: atlas-duck verify-export <dir> [--anchor-dir <dir>] [--manifest-sha256 <64 lowercase hex>]",
        details,
    )
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
    fn echoed_op_id_and_command_are_clipped() {
        let long = "x".repeat(10_000);
        let env = ops_describe(&long);
        let err = env.error.unwrap_or_else(|| panic!("error"));
        assert!(err.message.chars().count() <= "unknown op id: ".len() + 83);
        let op_id = err.details.and_then(|d| d.get("op_id").cloned());
        assert_eq!(
            op_id.and_then(|v| v.as_str().map(|s| s.chars().count())),
            Some(83)
        );

        let path = vec![long];
        let env = help(&path);
        let err = env.error.unwrap_or_else(|| panic!("error"));
        assert!(err.message.chars().count() <= "unknown command: ".len() + 83);
    }

    #[test]
    fn verify_export_misplaced_is_a_usage_failure_with_the_usage_line() {
        let env = verify_export_misplaced();
        let err = env.error.unwrap_or_else(|| panic!("error"));
        assert_eq!(err.code, ErrorCode::Usage);
        assert!(
            err.message.contains("must be the first argument"),
            "{}",
            err.message
        );
        assert!(err.message.contains("--manifest-sha256"), "{}", err.message);
    }
}
