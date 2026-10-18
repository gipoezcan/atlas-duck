//! An envelope as an MCP tool result (PD-121, PD-123): `structuredContent` is the envelope
//! unchanged, `isError` follows the CLI's exit code, and the text blocks are at most one fixed
//! sentence followed by the envelope as one JSON line.

use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::Value;

use super::tools::FIXED_TOOLS;
use crate::exit::{CallKind, exit_for_kind};
use crate::flow::REASON_CONNECTION_LOST;

/// §4.6, verbatim.
pub(crate) const RESTART_TEXT: &str = "atlas-duck was restarted or upgraded; restart this MCP server (or your MCP client) if this persists";
/// Δ4: a failed audit store; restarting the MCP server cannot help it (PD-123 exception).
pub(crate) const REASON_STORE_UNAVAILABLE: &str = "store_unavailable";

/// §4.6, verbatim with `<id>` substituted.
pub(crate) fn timeout_text(request_id: &str) -> String {
    format!("Approval pending. Call request_await with request_id={request_id}. Do not resubmit.")
}

/// What a tool does, as far as the result mapping cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolKind {
    /// An op tool, `call` or `script_run`: submits and waits.
    Submit,
    /// `request_await`.
    Await,
    /// `request_status`: a known id is never an error (§4.4).
    Status,
    /// Every other tool.
    Short,
}

impl ToolKind {
    /// The kind of the tool named `tool` (op tools and `call` submit).
    pub(crate) fn of(tool: &str) -> ToolKind {
        match tool {
            "script_run" => ToolKind::Submit,
            "request_await" => ToolKind::Await,
            "request_status" => ToolKind::Status,
            other if FIXED_TOOLS.contains(&other) => ToolKind::Short,
            _ => ToolKind::Submit,
        }
    }

    fn call_kind(self) -> CallKind {
        match self {
            ToolKind::Submit => CallKind::Submit,
            ToolKind::Await => CallKind::Await,
            ToolKind::Status => CallKind::Status,
            ToolKind::Short => CallKind::Short,
        }
    }
}

fn reason(env: &Envelope) -> Option<&str> {
    env.error
        .as_ref()
        .and_then(|e| e.details.as_ref())
        .and_then(|d| d.get("reason"))
        .and_then(Value::as_str)
}

fn code(env: &Envelope) -> Option<ErrorCode> {
    env.error.as_ref().map(|e| e.code)
}

/// PD-121: an error unless the CLI would exit 0 or 4, and always for a `pending` whose connection
/// was lost (also over `request_status`'s exit-0 rule for a known id).
pub(crate) fn is_error(kind: ToolKind, env: &Envelope) -> bool {
    let exit = exit_for_kind(kind.call_kind(), env);
    let lost = env.status == Status::Pending && reason(env) == Some(REASON_CONNECTION_LOST);
    !(exit == 0 || exit == 4) || lost
}

/// PD-123: `protocol_mismatch`, any `unreachable` reason (a lost connection included) except
/// `store_unavailable`; never `server_identity`.
pub(crate) fn wants_restart_text(env: &Envelope) -> bool {
    match code(env) {
        Some(ErrorCode::ProtocolMismatch) => true,
        Some(ErrorCode::Unreachable) => reason(env) != Some(REASON_STORE_UNAVAILABLE),
        _ => false,
    }
}

/// The §4.6 timeout sentence applies to an undecided request of a waiting tool whose id is known
/// and whose envelope carries no error (a lost connection gets the restart text instead).
fn timeout_text_for(kind: ToolKind, env: &Envelope) -> Option<String> {
    let waits = matches!(kind, ToolKind::Submit | ToolKind::Await);
    match (&env.request_id, env.status, &env.error) {
        (Some(id), Status::Pending, None) if waits => Some(timeout_text(id)),
        _ => None,
    }
}

/// The tool result for `env`: `structuredContent` = the envelope, `isError` per PD-121, the text
/// blocks = the fixed sentence (if one applies) then the envelope as one JSON line.
pub(crate) fn to_tool_result(kind: ToolKind, env: &Envelope) -> CallToolResult {
    let value = serde_json::to_value(env).unwrap_or(Value::Null);
    let mut result = if is_error(kind, env) {
        CallToolResult::structured_error(value)
    } else {
        CallToolResult::structured(value)
    };
    let sentence = if wants_restart_text(env) {
        Some(RESTART_TEXT.to_owned())
    } else {
        timeout_text_for(kind, env)
    };
    if let Some(sentence) = sentence {
        result.content.insert(0, ContentBlock::text(sentence));
    }
    result
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, json};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const ID: &str = "req_00000000000000000000000000000001";

    fn env(status: Status, code: Option<ErrorCode>, reason: Option<&str>) -> Envelope {
        let mut e = Envelope::failed(code.unwrap_or(ErrorCode::Internal), false, "m");
        e.status = status;
        if code.is_none() {
            e.error = None;
        }
        if let (Some(r), Some(err)) = (reason, e.error.as_mut()) {
            let mut d = Map::new();
            d.insert("reason".to_owned(), Value::from(r));
            err.details = Some(d);
        }
        e
    }

    fn with_id(mut e: Envelope) -> Envelope {
        e.request_id = Some(ID.to_owned());
        e
    }

    fn texts(r: &CallToolResult) -> Vec<String> {
        r.content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.clone()))
            .collect()
    }

    /// The §4.3 rows a tool result can carry, with whether each is an error.
    #[test]
    fn is_error_table() {
        use ErrorCode as C;
        use Status as S;
        let script_error = |status| {
            let mut e = env(status, None, None);
            e.data = Some(json!({"script_error": {"class": "Error"}}));
            e
        };
        let mut rows: Vec<(ToolKind, Envelope, bool, &str)> = vec![
            (
                ToolKind::Submit,
                env(S::Succeeded, None, None),
                false,
                "succeeded",
            ),
            (
                ToolKind::Await,
                env(S::Released, None, None),
                false,
                "released",
            ),
            (
                ToolKind::Submit,
                with_id(env(S::Pending, None, None)),
                false,
                "pending",
            ),
            (
                ToolKind::Await,
                with_id(env(S::Executing, None, None)),
                false,
                "executing",
            ),
            (
                ToolKind::Submit,
                env(S::Pending, Some(C::Unreachable), Some("connection_lost")),
                true,
                "pending + connection_lost (unknown id)",
            ),
            (
                ToolKind::Await,
                with_id(env(
                    S::Pending,
                    Some(C::Unreachable),
                    Some("connection_lost"),
                )),
                true,
                "pending + connection_lost (known id)",
            ),
            (
                // The lost connection beats the status exit-0 rule for a known id.
                ToolKind::Status,
                with_id(env(
                    S::Pending,
                    Some(C::Unreachable),
                    Some("connection_lost"),
                )),
                true,
                "request_status: pending + connection_lost (known id)",
            ),
            (
                // The clause is about `pending` only (PD-121): another status keeps the
                // §4.4 exit-0 rule of a known id.
                ToolKind::Status,
                with_id(env(
                    S::Released,
                    Some(C::Unreachable),
                    Some("connection_lost"),
                )),
                false,
                "request_status: not pending, reason connection_lost",
            ),
            (
                ToolKind::Await,
                env(S::Denied, Some(C::Denied), None),
                true,
                "denied",
            ),
            (
                ToolKind::Await,
                env(S::Expired, Some(C::Expired), None),
                true,
                "expired",
            ),
            (
                ToolKind::Await,
                env(S::Cancelled, Some(C::Cancelled), Some("by_client")),
                true,
                "cancelled by_client",
            ),
            (
                ToolKind::Await,
                env(S::Abandoned, Some(C::Abandoned), None),
                true,
                "abandoned",
            ),
            (
                ToolKind::Await,
                env(S::OutcomeUnknown, Some(C::UpstreamUnknownOutcome), None),
                true,
                "outcome_unknown",
            ),
            (
                ToolKind::Await,
                env(S::Released, Some(C::ResultEvicted), None),
                true,
                "result_evicted",
            ),
            (
                ToolKind::Await,
                script_error(S::Released),
                true,
                "released script error",
            ),
            (
                ToolKind::Submit,
                script_error(S::Succeeded),
                true,
                "dry run with script error",
            ),
            (
                ToolKind::Submit,
                env(S::Failed, Some(C::Busy), None),
                true,
                "busy",
            ),
            (
                ToolKind::Short,
                env(S::Failed, Some(C::Usage), None),
                true,
                "usage",
            ),
            (
                ToolKind::Submit,
                env(
                    S::Failed,
                    Some(C::Unreachable),
                    Some(REASON_STORE_UNAVAILABLE),
                ),
                true,
                "unreachable store_unavailable",
            ),
            (
                ToolKind::Status,
                with_id(env(S::Denied, Some(C::Denied), None)),
                false,
                "status of a known denied id",
            ),
            (
                ToolKind::Status,
                env(S::Failed, Some(C::UnknownRequest), None),
                true,
                "status of an unknown id",
            ),
            (
                ToolKind::Status,
                env(S::Failed, Some(C::Unreachable), Some("not_running")),
                true,
                "status without the app",
            ),
        ];
        for code in [C::Internal, C::Validation, C::UpstreamHttp, C::Locked] {
            rows.push((
                ToolKind::Submit,
                env(S::Failed, Some(code), None),
                true,
                "failed",
            ));
        }
        // §4.3 `failed`/8: a script that could not run.
        for code in [C::ScriptSyntax, C::ScriptLimit, C::SandboxUnavailable] {
            rows.push((
                ToolKind::Submit,
                env(S::Failed, Some(code), None),
                true,
                "failed, exit 8",
            ));
        }
        for (kind, e, want, label) in rows {
            assert_eq!(is_error(kind, &e), want, "{label}: {e:?}");
            assert_eq!(to_tool_result(kind, &e).is_error, Some(want), "{label}");
        }
    }

    #[test]
    fn pending_timeout_text_verbatim_with_id() {
        let pending = with_id(env(Status::Pending, None, None));
        for kind in [ToolKind::Submit, ToolKind::Await] {
            let r = to_tool_result(kind, &pending);
            let texts = texts(&r);
            assert_eq!(texts.len(), 2, "{kind:?}: {texts:?}");
            assert_eq!(
                texts.first().map(String::as_str),
                Some(
                    "Approval pending. Call request_await with request_id=req_00000000000000000000000000000001. Do not resubmit."
                )
            );
            assert_eq!(r.is_error, Some(false));
        }
        // Not for a status call, an executing request, an id-less or a lost-connection pending.
        let executing = with_id(env(Status::Executing, None, None));
        let lost = with_id(env(
            Status::Pending,
            Some(ErrorCode::Unreachable),
            Some("connection_lost"),
        ));
        let id_less = env(Status::Pending, None, None);
        for (kind, e) in [
            (ToolKind::Status, &pending),
            (ToolKind::Short, &pending),
            (ToolKind::Await, &executing),
            (ToolKind::Submit, &id_less),
            (ToolKind::Await, &lost),
        ] {
            let texts = texts(&to_tool_result(kind, e));
            assert!(
                !texts.iter().any(|t| t.starts_with("Approval pending")),
                "{kind:?} {e:?}: {texts:?}"
            );
        }
    }

    #[test]
    fn restart_text_on_mismatch_unreachable_and_drop() {
        let mut with_text = vec![
            env(Status::Failed, Some(ErrorCode::ProtocolMismatch), None),
            env(
                Status::Pending,
                Some(ErrorCode::Unreachable),
                Some("connection_lost"),
            ),
            with_id(env(
                Status::Pending,
                Some(ErrorCode::Unreachable),
                Some("connection_lost"),
            )),
            env(Status::Failed, Some(ErrorCode::Unreachable), None),
        ];
        for reason in [
            "not_running",
            "launch_timeout",
            "no_gui_session",
            "launch_blocked_by_job",
            "app_upgraded",
            "app_shutting_down",
            "store_newer",
        ] {
            with_text.push(env(
                Status::Failed,
                Some(ErrorCode::Unreachable),
                Some(reason),
            ));
        }
        for e in &with_text {
            let r = to_tool_result(ToolKind::Submit, e);
            let texts = texts(&r);
            assert_eq!(
                texts.first().map(String::as_str),
                Some(RESTART_TEXT),
                "{e:?}"
            );
            assert_eq!(texts.len(), 2, "{e:?}");
            assert_eq!(r.is_error, Some(true), "{e:?}");
        }
        let without = [
            env(Status::Failed, Some(ErrorCode::ServerIdentity), None),
            env(
                Status::Failed,
                Some(ErrorCode::Unreachable),
                Some(REASON_STORE_UNAVAILABLE),
            ),
            env(Status::Failed, Some(ErrorCode::Busy), None),
            env(Status::Denied, Some(ErrorCode::Denied), None),
        ];
        for e in &without {
            let r = to_tool_result(ToolKind::Submit, e);
            assert_eq!(texts(&r).len(), 1, "{e:?}");
            assert_eq!(r.is_error, Some(true), "{e:?}");
        }
    }

    #[test]
    fn structured_content_is_the_envelope_unchanged() -> TestResult {
        let mut e = with_id(env(Status::Released, None, None));
        e.op_id = Some("jira.issue.get".to_owned());
        e.instance = Some("work".to_owned());
        e.data = Some(json!({"fields": {"summary": "s", "x-unknown": [1, {"y": null}]}}));
        e.meta = Some(json!({"released_at": "t", "future_key": {"a": 1}}));
        e.redacted = true;
        e.redaction_note = Some("note".to_owned());
        let mut failed = env(Status::Failed, Some(ErrorCode::Busy), None);
        if let Some(err) = failed.error.as_mut() {
            let mut d = Map::new();
            d.insert("retry_after_s".to_owned(), json!(5));
            d.insert("unknown_detail".to_owned(), json!({"nested": true}));
            err.details = Some(d);
        }
        for (kind, e) in [(ToolKind::Await, &e), (ToolKind::Submit, &failed)] {
            let r = to_tool_result(kind, e);
            let want = serde_json::to_value(e)?;
            assert_eq!(r.structured_content.as_ref(), Some(&want));
            // Round trip through the wire shape: still the same value.
            let wire = serde_json::to_value(&r)?;
            assert_eq!(wire.get("structuredContent"), Some(&want));
        }
        Ok(())
    }

    #[test]
    fn envelope_json_text_block_always_last() -> TestResult {
        let cases = [
            (ToolKind::Submit, with_id(env(Status::Pending, None, None))),
            (
                ToolKind::Submit,
                env(Status::Failed, Some(ErrorCode::ProtocolMismatch), None),
            ),
            (ToolKind::Short, env(Status::Succeeded, None, None)),
            (
                ToolKind::Await,
                env(Status::Denied, Some(ErrorCode::Denied), None),
            ),
        ];
        for (kind, e) in cases {
            let texts = texts(&to_tool_result(kind, &e));
            let last = texts.last().ok_or("no text block")?;
            assert!(!last.contains('\n'), "one line: {last:?}");
            let parsed: Value = serde_json::from_str(last)?;
            assert_eq!(parsed, serde_json::to_value(&e)?);
        }
        Ok(())
    }
}
