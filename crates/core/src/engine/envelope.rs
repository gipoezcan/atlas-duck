//! Every envelope the core hands to an agent is built here (§4.2, §4.3), so what an agent can see
//! is reviewable in one file. The opacity rule (§4.5) is structural: a `pending`/`executing`
//! envelope comes only from [`pending_envelope`], which takes the request id, the op id, the
//! instance alias and the open status and nothing else; it has no access to a candidate, a
//! phase, a size or a count.

use atlas_duck_audit::EventType;
use atlas_duck_ipc::envelope::{Envelope, EnvelopeError, ErrorCode, Status};
use atlas_duck_registry::Product;
use serde_json::{Map, Value, json};

use super::RequestHead;
use crate::validate::echo;

/// §4.4 (verbatim): the fixed message of a reduced `status` error.
pub const MSG_USE_AWAIT: &str = "use await for details";
/// §4.3 (verbatim, L56): `not_configured {no_instance}` for a Jira op.
pub const MSG_NO_JIRA_INSTANCE: &str = "no Jira instance is configured in atlas-duck";
/// §4.3 (verbatim, L56): `not_configured {no_instance}` for a Confluence op.
pub const MSG_NO_CONFLUENCE_INSTANCE: &str = "no Confluence instance is configured in atlas-duck";
/// §4.4 (verbatim, L59): `details.message` of a params integer JCS cannot represent.
pub const MSG_INTEGER_RANGE: &str = "integer outside ±(2^53−1)";
/// §7.2 (verbatim): the hint of the identity-header states.
pub const MSG_IDENTITY_HEADER: &str = "X-AUSERNAME not received, possibly stripped by a reverse proxy in front of Jira; ask the Jira administrator";

pub(crate) const MSG_AUDIT_FAILURE: &str = "the audit log could not record the request";
pub(crate) const MSG_OUTCOME_UNKNOWN: &str =
    "the write was sent but its outcome is unknown; check the target before retrying";
const MSG_HELLO_FIRST: &str = "hello is required before any other method";
const MSG_UNKNOWN_REQUEST: &str = "unknown request id";
const MSG_AUDIT_UNREADABLE: &str = "the audit log could not be read";
const MSG_EXPIRED: &str = "the request expired";
const MSG_CANCELLED: &str = "the request was cancelled";
const MSG_ABANDONED: &str = "the request was abandoned when atlas-duck stopped";
const MSG_DENIED: &str = "denied";

/// The only statuses a request shows before it is terminal (§4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenStatus {
    Pending,
    Executing,
}

impl OpenStatus {
    /// `Some` for `pending`/`executing`, `None` for a terminal status.
    pub fn of(s: Status) -> Option<OpenStatus> {
        match s {
            Status::Pending => Some(OpenStatus::Pending),
            Status::Executing => Some(OpenStatus::Executing),
            _ => None,
        }
    }
}

fn base(
    request_id: Option<&str>,
    op_id: Option<&str>,
    instance: Option<&str>,
    status: Status,
) -> Envelope {
    Envelope {
        request_id: request_id.map(str::to_owned),
        op_id: op_id.map(str::to_owned),
        instance: instance.map(str::to_owned),
        status,
        data: None,
        edited: false,
        redacted: false,
        redaction_note: None,
        message: None,
        error: None,
        meta: None,
    }
}

fn error(
    code: ErrorCode,
    retryable: bool,
    message: &str,
    details: Option<Map<String, Value>>,
) -> EnvelopeError {
    EnvelopeError {
        code,
        retryable,
        message: message.to_owned(),
        details: details.filter(|d| !d.is_empty()),
    }
}

fn details(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

/// §4.5: `{request_id, op_id, instance, status}`; every other field null/false. `instance` is
/// `None` only for a request answered from the log whose instance is no longer configured.
pub fn pending_envelope(
    request_id: &str,
    op_id: Option<&str>,
    instance: Option<&str>,
    status: OpenStatus,
) -> Envelope {
    let status = match status {
        OpenStatus::Pending => Status::Pending,
        OpenStatus::Executing => Status::Executing,
    };
    base(Some(request_id), op_id, instance, status)
}

/// `failed` for a request that was never queued (`request_id: null`, §4.2).
pub fn failed_direct(
    code: ErrorCode,
    retryable: bool,
    message: &str,
    details: Option<Map<String, Value>>,
) -> Envelope {
    let mut env = base(None, None, None, Status::Failed);
    env.error = Some(error(code, retryable, message, details));
    env
}

/// `failed` for a request the log knows (its `REQUEST_RECEIVED` committed).
pub fn failed_request(
    head: &RequestHead,
    code: ErrorCode,
    retryable: bool,
    message: &str,
    details: Option<Map<String, Value>>,
) -> Envelope {
    let mut env = base(
        Some(&head.request_id),
        Some(&head.op_id),
        Some(&head.instance),
        Status::Failed,
    );
    env.error = Some(error(code, retryable, message, details));
    env
}

/// `succeeded` without a request (listings, `doctor`).
pub fn succeeded(data: Value) -> Envelope {
    let mut env = base(None, None, None, Status::Succeeded);
    env.data = Some(data);
    env
}

/// §3.3: a method before `hello` (M4 enforces the order; the core checks defensively).
pub fn protocol_error() -> Envelope {
    failed_direct(ErrorCode::ProtocolError, false, MSG_HELLO_FIRST, None)
}

/// §4.4: `status`/`await` of an id the log does not know.
pub fn unknown_request() -> Envelope {
    failed_direct(ErrorCode::UnknownRequest, false, MSG_UNKNOWN_REQUEST, None)
}

/// An unknown op id: `usage`, `details {op_id}` (bounded, display-escaped), nothing logged.
pub fn unknown_op(op_id: &str) -> Envelope {
    failed_direct(
        ErrorCode::Usage,
        false,
        "unknown op id",
        Some(details(&[("op_id", Value::String(echo(op_id)))])),
    )
}

/// PD-02: an unknown `instance` alias (or one of the other product): `validation`, exit 2.
pub fn unknown_instance(alias: &str) -> Envelope {
    failed_direct(
        ErrorCode::Validation,
        false,
        "unknown instance alias",
        Some(details(&[
            ("param", json!("instance")),
            ("value", Value::String(echo(alias))),
        ])),
    )
}

/// PD-01: the op's product has no instance (L56): exit 9, `retryable: true`.
pub fn no_instance(product: Product) -> Envelope {
    let message = match product {
        Product::Jira => MSG_NO_JIRA_INSTANCE,
        Product::Confluence => MSG_NO_CONFLUENCE_INSTANCE,
    };
    failed_direct(
        ErrorCode::NotConfigured,
        true,
        message,
        Some(details(&[("reason", json!("no_instance"))])),
    )
}

/// `not_configured {reason}` (§4.3 exit 9: `config_unreadable`, `insecure_scheme`,
/// `instance_unconfirmed`), `retryable: true`.
pub fn not_configured(reason: &str) -> Envelope {
    failed_direct(
        ErrorCode::NotConfigured,
        true,
        &format!("atlas-duck is not configured ({reason})"),
        Some(details(&[("reason", Value::String(reason.to_owned()))])),
    )
}

/// PD-03: the instance has no usable token; exit 9, `retryable: true`.
pub fn needs_token() -> Envelope {
    failed_direct(
        ErrorCode::NeedsToken,
        true,
        "the instance needs a token: set it in the atlas-duck credential window",
        None,
    )
}

/// PD-03 / §7.2 *Header lost*: `upstream_unavailable {identity_header_*}`, `retryable: false`.
pub fn identity_header(reason: &str) -> Envelope {
    failed_direct(
        ErrorCode::UpstreamUnavailable,
        false,
        MSG_IDENTITY_HEADER,
        Some(details(&[("reason", Value::String(reason.to_owned()))])),
    )
}

/// PD-27 / L59: `validation`, exit 2, nothing logged.
pub fn integer_out_of_range() -> Envelope {
    failed_direct(
        ErrorCode::Validation,
        false,
        "params contain an integer that cannot be hashed exactly",
        Some(details(&[("message", json!(MSG_INTEGER_RANGE))])),
    )
}

/// §5.1 inv. 1: the start record did not commit, so nothing exists (`request_id: null`).
pub fn audit_failure(retryable: bool) -> Envelope {
    failed_direct(ErrorCode::AuditFailure, retryable, MSG_AUDIT_FAILURE, None)
}

/// `internal`, exit 1, `retryable: false`.
pub fn internal(message: &str) -> Envelope {
    failed_direct(ErrorCode::Internal, false, message, None)
}

/// The log could not be read for a status/await/list answer.
pub fn audit_unreadable() -> Envelope {
    internal(MSG_AUDIT_UNREADABLE)
}

/// A terminal error with the message and details `await` delivers (Task 21 adds data).
#[derive(Debug, Clone, PartialEq)]
pub struct RecordError {
    pub code: ErrorCode,
    pub retryable: bool,
    pub message: Option<String>,
    pub details: Option<Map<String, Value>>,
}

/// What the committed records say about a request.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordStatus {
    pub request_id: String,
    pub op_id: Option<String>,
    /// The alias of the start record's instance, if it is still configured.
    pub instance: Option<String>,
    pub status: Status,
    /// `Some` for a terminal non-success.
    pub error: Option<RecordError>,
}

/// The envelope of a request as its records say: an open one is the pending envelope, a
/// terminal one carries its routing fields, status and `err` of its error.
fn record_envelope(rs: &RecordStatus, err: impl FnOnce(&RecordError) -> EnvelopeError) -> Envelope {
    if let Some(open) = OpenStatus::of(rs.status) {
        return pending_envelope(
            &rs.request_id,
            rs.op_id.as_deref(),
            rs.instance.as_deref(),
            open,
        );
    }
    let mut env = base(
        Some(&rs.request_id),
        rs.op_id.as_deref(),
        rs.instance.as_deref(),
        rs.status,
    );
    env.error = rs.error.as_ref().map(err);
    env
}

/// §4.4 `status`: routing fields and status; a terminal non-success error reduced to
/// `{code, retryable}` with the fixed message and no details. Never data, never `meta`. A
/// request the log shows as still open (no terminal record yet) gets the pending envelope.
pub fn status_envelope(rs: &RecordStatus) -> Envelope {
    record_envelope(rs, |e| error(e.code, e.retryable, MSG_USE_AWAIT, None))
}

/// `await` of a request answered from the records (Task 21 adds data delivery and
/// `DELIVERED`).
pub fn await_envelope(rs: &RecordStatus) -> Envelope {
    record_envelope(rs, |e| {
        let message = e
            .message
            .clone()
            .unwrap_or_else(|| default_message(e.code).to_owned());
        error(e.code, e.retryable, &message, e.details.clone())
    })
}

/// The same view of a terminal state only memory knows (an append failure).
pub fn unlogged_envelope(
    head: &RequestHead,
    status: Status,
    e: &super::TerminalError,
    reduced: bool,
) -> Envelope {
    let rs = RecordStatus {
        request_id: head.request_id.clone(),
        op_id: Some(head.op_id.clone()),
        instance: Some(head.instance.clone()),
        status,
        error: Some(RecordError {
            code: e.code,
            retryable: e.retryable,
            message: Some(e.message.clone()),
            details: None,
        }),
    };
    if reduced {
        status_envelope(&rs)
    } else {
        await_envelope(&rs)
    }
}

fn default_message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::Expired => MSG_EXPIRED,
        ErrorCode::Cancelled => MSG_CANCELLED,
        ErrorCode::Abandoned => MSG_ABANDONED,
        ErrorCode::UpstreamUnknownOutcome => MSG_OUTCOME_UNKNOWN,
        ErrorCode::AuditFailure => MSG_AUDIT_FAILURE,
        ErrorCode::Denied => MSG_DENIED,
        _ => "the request failed",
    }
}

/// Whether [`record_status`] reads the terminal record's payload.
pub fn needs_payload(t: EventType) -> bool {
    matches!(
        t,
        EventType::REQUEST_REJECTED
            | EventType::REQUEST_FAILED
            | EventType::READ_FAILED
            | EventType::READ_RELEASED
            | EventType::READ_DENIED
            | EventType::WRITE_DENIED
            | EventType::SCRIPT_DENIED
            | EventType::WRITE_FAILED
            | EventType::CANCELLED
            | EventType::SCRIPT_FAILED
    )
}

fn code_of(v: Option<&Value>) -> Option<ErrorCode> {
    serde_json::from_value(v?.clone()).ok()
}

fn str_of<'a>(payload: Option<&'a Value>, key: &str) -> Option<&'a str> {
    payload?.get(key)?.as_str()
}

/// §4.3 retryable for a data-free failure returned directly (reads and enrichment).
fn direct_retryable(code: ErrorCode, payload: Option<&Value>, op_class: Option<&str>) -> bool {
    let reason = payload
        .and_then(|p| p.get("details"))
        .and_then(|d| d.get("reason"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    match code {
        ErrorCode::UpstreamNetwork | ErrorCode::NeedsToken | ErrorCode::NotConfigured => true,
        ErrorCode::UpstreamUnavailable => !reason.starts_with("identity_header"),
        ErrorCode::AuditFailure => op_class != Some("write"),
        _ => false,
    }
}

/// The status a terminal record means (§4.4 mapping table; payload-dependent rows read
/// `payload`). Plan notes: a `READ_RELEASED` of an outcome item (`{code, hint}`) is `failed` with
/// that code, like `agent_status`; a released upstream-error item cannot be told from a data
/// release by this payload yet (Task 21). `WRITE_FAILED` names its code by `class` when that is
/// one, else `upstream_http` for an answered failure (Task 22).
pub fn record_status(
    t: EventType,
    payload: Option<&Value>,
    op_class: Option<&str>,
) -> (Status, Option<RecordError>) {
    let fail = |code: ErrorCode,
                retryable: bool,
                message: Option<String>,
                details: Option<Map<String, Value>>| {
        Some(RecordError {
            code,
            retryable,
            message,
            details,
        })
    };
    let message = |key: &str| str_of(payload, key).map(str::to_owned);
    let details = payload
        .and_then(|p| p.get("details"))
        .and_then(Value::as_object)
        .cloned();
    match t {
        EventType::REQUEST_REJECTED => {
            let code =
                code_of(payload.and_then(|p| p.get("code"))).unwrap_or(ErrorCode::Validation);
            (
                Status::Failed,
                fail(code, false, message("message"), details),
            )
        }
        EventType::REQUEST_FAILED | EventType::READ_FAILED => {
            let code = code_of(payload.and_then(|p| p.get("code"))).unwrap_or(ErrorCode::Internal);
            let retryable = direct_retryable(code, payload, op_class);
            (Status::Failed, fail(code, retryable, None, details))
        }
        EventType::READ_RELEASED => match code_of(payload.and_then(|p| p.get("code"))) {
            Some(code) => (Status::Failed, fail(code, false, message("hint"), None)),
            None => (Status::Released, None),
        },
        EventType::READ_DENIED | EventType::SCRIPT_DENIED => (
            Status::Denied,
            fail(ErrorCode::Denied, false, message("reason"), None),
        ),
        EventType::WRITE_DENIED => {
            let code = code_of(
                payload
                    .and_then(|p| p.get("hint"))
                    .and_then(|h| h.get("code")),
            )
            .unwrap_or(ErrorCode::Denied);
            (Status::Denied, fail(code, false, message("reason"), None))
        }
        EventType::WRITE_EXECUTED | EventType::SCRIPT_DRY_RUN => (Status::Succeeded, None),
        EventType::SCRIPT_RELEASED => (Status::Released, None),
        EventType::WRITE_FAILED => {
            let code = code_of(payload.and_then(|p| p.get("class"))).unwrap_or(
                if payload.and_then(|p| p.get("response")).is_some() {
                    ErrorCode::UpstreamHttp
                } else {
                    ErrorCode::Internal
                },
            );
            (Status::Failed, fail(code, false, None, None))
        }
        EventType::WRITE_OUTCOME_UNKNOWN => (
            Status::OutcomeUnknown,
            fail(ErrorCode::UpstreamUnknownOutcome, false, None, None),
        ),
        EventType::EXPIRED => (Status::Expired, fail(ErrorCode::Expired, false, None, None)),
        EventType::CANCELLED => {
            let reason = str_of(payload, "reason").unwrap_or("by_client");
            let mut d = Map::new();
            d.insert("reason".into(), Value::String(reason.to_owned()));
            (
                Status::Cancelled,
                fail(ErrorCode::Cancelled, reason != "by_client", None, Some(d)),
            )
        }
        EventType::ABANDONED => (
            Status::Abandoned,
            fail(ErrorCode::Abandoned, true, None, None),
        ),
        EventType::SCRIPT_FAILED => {
            let reason = str_of(payload, "reason").unwrap_or_default();
            if reason == "audit_failure" {
                (
                    Status::Failed,
                    fail(ErrorCode::AuditFailure, true, None, None),
                )
            } else {
                // Task 27 fixes the direct script failure codes (`script_syntax`, ...).
                let code =
                    code_of(payload.and_then(|p| p.get("reason"))).unwrap_or(ErrorCode::Internal);
                (Status::Failed, fail(code, false, None, details))
            }
        }
        _ => (Status::Pending, None),
    }
}
