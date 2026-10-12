//! JSON-RPC 2.0 messages between the CLI/MCP front ends and the server (§3.3, PD-28).
//! Types and framing only; the transport lives in `server`/`client`.

pub mod frame;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::envelope::{Envelope, ErrorCode};
use crate::proto::{ListState, MatchParams};

/// §3.3 method names.
pub mod method {
    pub const HELLO: &str = "hello";
    pub const OPS_LIST: &str = "ops.list";
    pub const OPS_DESCRIBE: &str = "ops.describe";
    pub const INSTANCES_LIST: &str = "instances.list";
    pub const REQUEST_SUBMIT: &str = "request.submit";
    pub const REQUEST_AWAIT: &str = "request.await";
    pub const REQUEST_STATUS: &str = "request.status";
    pub const REQUEST_CANCEL: &str = "request.cancel";
    pub const REQUESTS_LIST: &str = "requests.list";
    pub const SCRIPT_SUBMIT: &str = "script.submit";
    pub const DOCTOR: &str = "doctor";
    /// Server-to-client notification.
    pub const REQUEST_PROGRESS: &str = "request.progress";

    /// Every method a client may call (not the progress notification).
    pub const ALL: [&str; 11] = [
        HELLO,
        OPS_LIST,
        OPS_DESCRIBE,
        INSTANCES_LIST,
        REQUEST_SUBMIT,
        REQUEST_AWAIT,
        REQUEST_STATUS,
        REQUEST_CANCEL,
        REQUESTS_LIST,
        SCRIPT_SUBMIT,
        DOCTOR,
    ];
}

/// PD-28 error codes.
pub mod codes {
    pub const PARSE: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    /// An application refusal carried as an envelope (hello build mismatch, connection limit).
    pub const APP_REFUSAL: i64 = -32000;
}

/// The `"jsonrpc":"2.0"` marker; any other value fails to deserialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TwoPointZero;

impl Serialize for TwoPointZero {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str("2.0")
    }
}

impl<'de> Deserialize<'de> for TwoPointZero {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = String::deserialize(d)?;
        if v == "2.0" {
            Ok(TwoPointZero)
        } else {
            Err(de::Error::custom("jsonrpc must be \"2.0\""))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub jsonrpc: TwoPointZero,
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notification {
    pub jsonrpc: TwoPointZero,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Envelope>,
}

// The error variant carries a whole envelope; boxing it would complicate every match for no gain
// (messages are short-lived).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseBody {
    Result(Value),
    Error(RpcError),
}

/// `id` is `None` (JSON `null`) when the request id is unknown (parse error, oversize frame).
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub jsonrpc: TwoPointZero,
    pub id: Option<u64>,
    pub body: ResponseBody,
}

impl Response {
    pub fn result(id: u64, value: Value) -> Response {
        Response {
            jsonrpc: TwoPointZero,
            id: Some(id),
            body: ResponseBody::Result(value),
        }
    }
}

impl Serialize for Response {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(3))?;
        m.serialize_entry("jsonrpc", &self.jsonrpc)?;
        m.serialize_entry("id", &self.id)?;
        match &self.body {
            ResponseBody::Result(v) => m.serialize_entry("result", v)?,
            ResponseBody::Error(e) => m.serialize_entry("error", e)?,
        }
        m.end()
    }
}

/// `result` may legitimately be `null`, so absent and null are told apart here.
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResponse {
    #[serde(rename = "jsonrpc")]
    _jsonrpc: TwoPointZero,
    /// Absent is refused; `null` is the unknown-id case, so it is told apart here too.
    #[serde(default, deserialize_with = "present")]
    id: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    result: Option<Value>,
    #[serde(default)]
    error: Option<RpcError>,
}

impl<'de> Deserialize<'de> for Response {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = RawResponse::deserialize(d)?;
        let id = match raw.id {
            None => return Err(de::Error::custom("a response carries an id")),
            Some(Value::Null) => None,
            Some(v) => Some(serde_json::from_value::<u64>(v).map_err(de::Error::custom)?),
        };
        let body = match (raw.result, raw.error) {
            (Some(v), None) => ResponseBody::Result(v),
            (None, Some(e)) => ResponseBody::Error(e),
            _ => {
                return Err(de::Error::custom(
                    "a response carries exactly one of result and error",
                ));
            }
        };
        Ok(Response {
            jsonrpc: TwoPointZero,
            id,
            body,
        })
    }
}

/// One decoded frame: shape decides (`method` + `id` request, `method` alone notification,
/// otherwise response).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    Request(Request),
    Response(Response),
    Notification(Notification),
}

impl<'de> Deserialize<'de> for Incoming {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        let obj = v
            .as_object()
            .ok_or_else(|| de::Error::custom("a JSON-RPC message is an object"))?;
        let has_method = obj.contains_key("method");
        let has_id = obj.contains_key("id");
        let r = if has_method && has_id {
            serde_json::from_value(v).map(Incoming::Request)
        } else if has_method {
            serde_json::from_value(v).map(Incoming::Notification)
        } else {
            serde_json::from_value(v).map(Incoming::Response)
        };
        r.map_err(de::Error::custom)
    }
}

impl Serialize for Incoming {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Incoming::Request(r) => r.serialize(s),
            Incoming::Response(r) => r.serialize(s),
            Incoming::Notification(n) => n.serialize(s),
        }
    }
}

/// The closed set of `details.reason` values a `protocol_error` carries (PD-28).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolReason {
    /// A method before `hello` on the connection (wording as the core's `MSG_HELLO_FIRST`).
    HelloRequired,
}

impl ProtocolReason {
    fn as_str(self) -> &'static str {
        match self {
            ProtocolReason::HelloRequired => "hello_required",
        }
    }

    fn message(self) -> &'static str {
        match self {
            ProtocolReason::HelloRequired => "hello is required before any other method",
        }
    }
}

/// `failed` / `protocol_error`, not retryable, `details.reason` = `reason` (PD-28).
pub fn protocol_error(reason: ProtocolReason) -> Envelope {
    let mut e = Envelope::failed(ErrorCode::ProtocolError, false, reason.message());
    if let Some(err) = e.error.as_mut() {
        let mut d = Map::new();
        d.insert("reason".to_owned(), json!(reason.as_str()));
        err.details = Some(d);
    }
    e
}

/// An error response whose `data` is `envelope`; `message` is the envelope's error message.
pub fn error_response(id: Option<u64>, code: i64, envelope: Envelope) -> Response {
    let message = envelope
        .error
        .as_ref()
        .map_or_else(|| "error".to_owned(), |e| e.message.clone());
    Response {
        jsonrpc: TwoPointZero,
        id,
        body: ResponseBody::Error(RpcError {
            code,
            message,
            data: Some(envelope),
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpsListParams {
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpsDescribeParams {
    pub op_id: String,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdParams {
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestsListParams {
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub state: Option<ListState>,
    #[serde(default)]
    pub match_params: Option<MatchParams>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyParams {}
