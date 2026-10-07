//! The §4.2 output envelope, the stable `error.code` list and the §4.3 exit codes.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Envelope `status` (§4.2, §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Executing,
    Succeeded,
    Released,
    Denied,
    Expired,
    Cancelled,
    Failed,
    OutcomeUnknown,
    Abandoned,
}

/// `error.code` (§4.2: "Codes (stable, machine-readable)"), in the order the spec lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Usage,
    Validation,
    MarkdownPlaceholders,
    OpUnsupportedByInstance,
    Internal,
    AuditFailure,
    AuditStorageLow,
    Busy,
    Unreachable,
    ServerIdentity,
    ProtocolMismatch,
    UpstreamHttp,
    UpstreamNetwork,
    UpstreamUnavailable,
    UpstreamUnknownOutcome,
    ResultTooLarge,
    NeedsToken,
    Locked,
    NotConfigured,
    ScriptSyntax,
    ScriptLimit,
    SandboxUnavailable,
    ResultEvicted,
    Denied,
    ResolutionFailed,
    Expired,
    Cancelled,
    Abandoned,
    UnknownRequest,
    ProtocolError,
}

impl ErrorCode {
    /// Every code, in §4.2 order.
    pub const ALL: [ErrorCode; 30] = [
        ErrorCode::Usage,
        ErrorCode::Validation,
        ErrorCode::MarkdownPlaceholders,
        ErrorCode::OpUnsupportedByInstance,
        ErrorCode::Internal,
        ErrorCode::AuditFailure,
        ErrorCode::AuditStorageLow,
        ErrorCode::Busy,
        ErrorCode::Unreachable,
        ErrorCode::ServerIdentity,
        ErrorCode::ProtocolMismatch,
        ErrorCode::UpstreamHttp,
        ErrorCode::UpstreamNetwork,
        ErrorCode::UpstreamUnavailable,
        ErrorCode::UpstreamUnknownOutcome,
        ErrorCode::ResultTooLarge,
        ErrorCode::NeedsToken,
        ErrorCode::Locked,
        ErrorCode::NotConfigured,
        ErrorCode::ScriptSyntax,
        ErrorCode::ScriptLimit,
        ErrorCode::SandboxUnavailable,
        ErrorCode::ResultEvicted,
        ErrorCode::Denied,
        ErrorCode::ResolutionFailed,
        ErrorCode::Expired,
        ErrorCode::Cancelled,
        ErrorCode::Abandoned,
        ErrorCode::UnknownRequest,
        ErrorCode::ProtocolError,
    ];
}

/// The `error` object: `{code, retryable, message, details?}` (§4.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvelopeError {
    pub code: ErrorCode,
    pub retryable: bool,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Map<String, Value>>,
}

/// The one JSON object every CLI invocation prints on stdout (§4.2). All eleven keys are always
/// serialized; absent values are `null`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub request_id: Option<String>,
    pub op_id: Option<String>,
    pub instance: Option<String>,
    pub status: Status,
    pub data: Option<Value>,
    pub edited: bool,
    pub redacted: bool,
    pub redaction_note: Option<String>,
    pub message: Option<String>,
    pub error: Option<EnvelopeError>,
    pub meta: Option<Value>,
}

/// Printed if serialization ever failed. It cannot fail for these types, but the CLI must still
/// print exactly one envelope (§4.2).
const INTERNAL_FALLBACK_LINE: &str = "{\"request_id\":null,\"op_id\":null,\"instance\":null,\"status\":\"failed\",\"data\":null,\"edited\":false,\"redacted\":false,\"redaction_note\":null,\"message\":null,\"error\":{\"code\":\"internal\",\"retryable\":false,\"message\":\"internal error\"},\"meta\":null}\n";

impl Envelope {
    /// A `failed` envelope for a request that was never queued (`request_id: null`, §4.2).
    pub fn failed(code: ErrorCode, retryable: bool, message: &str) -> Envelope {
        Envelope {
            request_id: None,
            op_id: None,
            instance: None,
            status: Status::Failed,
            data: None,
            edited: false,
            redacted: false,
            redaction_note: None,
            message: None,
            error: Some(EnvelopeError {
                code,
                retryable,
                message: message.to_owned(),
                details: None,
            }),
            meta: None,
        }
    }

    /// Compact JSON followed by exactly one `\n`.
    pub fn to_json_line(&self) -> String {
        match serde_json::to_string(self) {
            Ok(mut s) => {
                s.push('\n');
                s
            }
            Err(_) => INTERNAL_FALLBACK_LINE.to_owned(),
        }
    }
}

/// Exit codes of the main CLI (§4.3).
pub mod exit {
    pub const OK: i32 = 0;
    pub const FAILED_INTERNAL: i32 = 1;
    pub const USAGE_VALIDATION: i32 = 2;
    pub const DENIED: i32 = 3;
    pub const PENDING: i32 = 4;
    pub const UNREACHABLE: i32 = 5;
    pub const UPSTREAM: i32 = 6;
    pub const EXPIRED_CANCELLED_ABANDONED: i32 = 7;
    pub const SCRIPT: i32 = 8;
    pub const LOCKED_CONFIG_TOKEN: i32 = 9;
    pub const RESULT_EVICTED: i32 = 10;
    pub const BUSY: i32 = 11;
}

/// `verify-export` usage or I/O error (§12.1: "`22` = usage or I/O error").
pub const VERIFY_EXPORT_USAGE_IO: i32 = 22;

#[cfg(test)]
mod tests {
    use super::*;

    /// The §4.2 list, copied verbatim and in order.
    const SPEC_CODES: [&str; 30] = [
        "usage",
        "validation",
        "markdown_placeholders",
        "op_unsupported_by_instance",
        "internal",
        "audit_failure",
        "audit_storage_low",
        "busy",
        "unreachable",
        "server_identity",
        "protocol_mismatch",
        "upstream_http",
        "upstream_network",
        "upstream_unavailable",
        "upstream_unknown_outcome",
        "result_too_large",
        "needs_token",
        "locked",
        "not_configured",
        "script_syntax",
        "script_limit",
        "sandbox_unavailable",
        "result_evicted",
        "denied",
        "resolution_failed",
        "expired",
        "cancelled",
        "abandoned",
        "unknown_request",
        "protocol_error",
    ];

    #[test]
    fn error_codes_serialize_to_the_spec_names() {
        for (code, name) in ErrorCode::ALL.iter().zip(SPEC_CODES) {
            assert_eq!(
                serde_json::to_value(code).unwrap(),
                Value::String(name.to_owned())
            );
            let back: ErrorCode = serde_json::from_value(Value::String(name.to_owned())).unwrap();
            assert_eq!(back, *code);
        }
    }

    #[test]
    fn statuses_serialize_to_the_spec_names() {
        let all = [
            (Status::Pending, "pending"),
            (Status::Executing, "executing"),
            (Status::Succeeded, "succeeded"),
            (Status::Released, "released"),
            (Status::Denied, "denied"),
            (Status::Expired, "expired"),
            (Status::Cancelled, "cancelled"),
            (Status::Failed, "failed"),
            (Status::OutcomeUnknown, "outcome_unknown"),
            (Status::Abandoned, "abandoned"),
        ];
        for (status, name) in all {
            assert_eq!(
                serde_json::to_value(status).unwrap(),
                Value::String(name.to_owned())
            );
        }
    }

    #[test]
    fn failed_envelope_has_all_eleven_keys_on_one_line() {
        let line = Envelope::failed(ErrorCode::Usage, false, "m").to_json_line();
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1);
        let v: Value = serde_json::from_str(&line).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "data",
                "edited",
                "error",
                "instance",
                "message",
                "meta",
                "op_id",
                "redacted",
                "redaction_note",
                "request_id",
                "status"
            ]
        );
        assert_eq!(v["request_id"], Value::Null);
        assert_eq!(v["status"], "failed");
        assert_eq!(v["error"]["code"], "usage");
        assert_eq!(v["error"]["retryable"], false);
        assert!(v["error"].get("details").is_none());
    }

    #[test]
    fn fallback_line_parses_as_an_internal_failure() {
        let env: Envelope = serde_json::from_str(INTERNAL_FALLBACK_LINE).unwrap();
        assert_eq!(env.status, Status::Failed);
        assert_eq!(env.error.unwrap().code, ErrorCode::Internal);
    }

    #[test]
    fn exit_codes_match_section_4_3() {
        assert_eq!(
            [
                exit::OK,
                exit::FAILED_INTERNAL,
                exit::USAGE_VALIDATION,
                exit::DENIED,
                exit::PENDING,
                exit::UNREACHABLE,
                exit::UPSTREAM,
                exit::EXPIRED_CANCELLED_ABANDONED,
                exit::SCRIPT,
                exit::LOCKED_CONFIG_TOKEN,
                exit::RESULT_EVICTED,
                exit::BUSY
            ],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        );
        assert_eq!(VERIFY_EXPORT_USAGE_IO, 22);
    }
}
