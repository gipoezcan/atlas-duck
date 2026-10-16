//! Script protocol of the sandbox channel (spec §3.3 JSON-RPC 2.0, §3.4 method names and frame
//! caps, §9.1 step 3; plan M8 Δ1, PD-132, R9).
//!
//! The host's first frame after `probe.ready` picks the worker mode: `script.compile` (compile
//! only) or `script.run` (one run). Both are notifications built with
//! [`super::probe::encode_notification`]. The worker answers with the frames
//! [`decode_worker_frame`] accepts; its `host.call` is a JSON-RPC request that the host answers
//! with [`encode_response`]. Frame size checks belong to the bridge, not to the decoder.
//!
//! Limits of the decoder, by design:
//! - Only top-level duplicate keys are detected. Below that, `HostCall.params` and
//!   `WorkerInit.args` are `Value` trees that keep the last of a duplicate key, while a
//!   `script.result` value keeps its text untouched. Do not use a `Value` for forensic
//!   comparison of what a worker sent.
//! - serde_json's recursion limit (128) applies to every `Value` built here: a `host.call` whose
//!   `params` nest about 126 levels or more is rejected as a protocol violation. A
//!   `script.result` value is skipped as text without that limit, so it decodes at any depth
//!   (whoever parses it later must bound the depth). The worker run loop (M8 T4) must check
//!   the depth of a call's params before it sends the frame and report an over-deep value as a
//!   script error.

use std::collections::HashSet;
use std::fmt;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;

use super::{HostCall, HostCallResult, MAX_FRAME_BYTES, ScriptLimits};

/// Host → worker, first frame (notification), params [`WorkerInit`].
pub const M_SCRIPT_RUN: &str = "script.run";
/// Host → worker, first frame (notification), params [`CompileRequest`].
pub const M_SCRIPT_COMPILE: &str = "script.compile";
/// Worker → host: the source compiled (params `{}`).
pub const M_SCRIPT_COMPILED: &str = "script.compiled";
/// Worker → host: the source did not compile (params [`SyntaxParams`]).
pub const M_SCRIPT_SYNTAX: &str = "script.syntax";
/// Worker → host: a call from the script, a JSON-RPC **request** whose `id` equals
/// `HostCall.id` (params [`HostCall`]).
pub const M_HOST_CALL: &str = "host.call";
/// Worker → host: one log line (params [`LogParams`]).
pub const M_HOST_LOG: &str = "host.log";
/// Worker → host, terminal: the script's result (params [`ResultParams`]).
pub const M_SCRIPT_RESULT: &str = "script.result";
/// Worker → host, terminal: the script failed (params [`ErrorParams`]).
pub const M_SCRIPT_ERROR: &str = "script.error";

/// §3.3/§3.4: the host → worker cap is the channel's general frame cap.
pub const HOST_TO_WORKER_MAX: usize = MAX_FRAME_BYTES;

const MIB: usize = 1024 * 1024;
const TERMINAL_FRAME_SLACK: usize = 64 * 1024;

/// The §3.4 cap for the worker's terminal frame (`script.result`, `script.error`):
/// `max_result_mb` MiB + 64 KiB. Every other worker → host frame is capped at
/// [`super::WORKER_FRAME_MAX_BYTES`].
pub fn terminal_frame_max(limits: &ScriptLimits) -> usize {
    (limits.max_result_mb as usize)
        .saturating_mul(MIB)
        .saturating_add(TERMINAL_FRAME_SLACK)
}

/// One configured instance as `atlas.instances()` shows it: the `instances.list` row without
/// `state`, and never a URL (R9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceInfo {
    pub alias: String,
    pub product: String,
    pub is_default: bool,
}

/// Params of `script.run` (§9.1 step 3 plus `instances`, R9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerInit {
    pub source: String,
    pub args: Value,
    pub limits: ScriptLimits,
    pub read_op_ids: Vec<String>,
    pub instances: Vec<InstanceInfo>,
}

/// Params of `script.compile`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileRequest {
    pub source: String,
}

/// Params of `script.compiled`: the empty object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyParams {}

/// Params of `script.syntax`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntaxParams {
    pub line: u32,
    pub column: u32,
    pub message: String,
}

/// Params of `host.log`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogParams {
    pub line: String,
}

/// Params of `script.error`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorParams {
    pub class: String,
    pub message: String,
    pub stack: String,
}

/// Params of `script.result`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultParams {
    pub value: RawJsonText,
}

/// [`ResultParams`] as the decoder reads it: the value borrowed from the frame, copied once.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultParamsIn<'a> {
    #[serde(borrow)]
    value: &'a RawValue,
}

/// A JSON value kept as its source text. The host forwards a script's result to core without
/// re-encoding it, and PD-131 keeps big values out of `Value` trees.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RawJsonText(Box<RawValue>);

impl RawJsonText {
    /// Wraps `text` after checking that it is one JSON value.
    pub fn from_string(text: String) -> Result<Self, serde_json::Error> {
        RawValue::from_string(text).map(RawJsonText)
    }

    /// The value's JSON text, exactly as received.
    pub fn get(&self) -> &str {
        self.0.get()
    }
}

impl PartialEq for RawJsonText {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl Eq for RawJsonText {}

/// A frame the worker may send once it runs a script or a compile.
#[derive(Debug, Clone, PartialEq)]
pub enum WorkerFrame {
    Call {
        id: u64,
        call: HostCall,
    },
    Log {
        line: String,
    },
    Result {
        value: Box<RawJsonText>,
    },
    Error {
        class: String,
        message: String,
        stack: String,
    },
    Compiled,
    Syntax {
        line: u32,
        column: u32,
        message: String,
    },
}

/// Why [`decode_worker_frame`] rejected a frame payload. Every variant is a protocol violation.
#[derive(Debug)]
pub enum DecodeError {
    /// Not valid JSON.
    Json(serde_json::Error),
    /// Valid JSON but not an object.
    NotObject,
    /// `jsonrpc` is missing or not `"2.0"`.
    WrongVersion,
    /// `method` is missing or not a string.
    MissingMethod,
    /// A method this decoder does not accept from the worker.
    UnknownMethod(String),
    /// A top-level member other than `jsonrpc`, `method`, `params`, `id`.
    ExtraKey(String),
    /// A top-level member that appears twice.
    DuplicateKey(String),
    /// A JSON-RPC response (`result`/`error`, no `method`): the host issues no ids, so every
    /// response from the worker answers an id the host never issued (§3.4).
    WorkerResponse,
    /// `host.call` without an `id` that is a positive integer.
    BadId,
    /// An `id` on a method that is a notification.
    UnexpectedId,
    /// The `host.call` envelope `id` differs from `params.id`.
    IdMismatch { envelope: u64, call: u64 },
    /// `params` does not match the method's shape.
    BadParams {
        method: String,
        source: serde_json::Error,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Json(e) => write!(f, "invalid JSON: {e}"),
            DecodeError::NotObject => f.write_str("message is not a JSON object"),
            DecodeError::WrongVersion => f.write_str("jsonrpc is not \"2.0\""),
            DecodeError::MissingMethod => f.write_str("method missing or not a string"),
            DecodeError::UnknownMethod(m) => write!(f, "unknown method {m:?}"),
            DecodeError::ExtraKey(k) => write!(f, "unexpected top-level key {k:?}"),
            DecodeError::DuplicateKey(k) => write!(f, "duplicate top-level key {k:?}"),
            DecodeError::WorkerResponse => f.write_str("response from the worker"),
            DecodeError::BadId => f.write_str("host.call id is not a positive integer"),
            DecodeError::UnexpectedId => f.write_str("notification carries an id"),
            DecodeError::IdMismatch { envelope, call } => {
                write!(
                    f,
                    "host.call envelope id {envelope} differs from params id {call}"
                )
            }
            DecodeError::BadParams { method, source } => {
                write!(f, "bad params for {method}: {source}")
            }
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DecodeError::Json(e) | DecodeError::BadParams { source: e, .. } => Some(e),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct RequestOut<'a, T: Serialize> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: &'a T,
}

/// Encodes a JSON-RPC 2.0 request `{"jsonrpc":"2.0","id":..,"method":..,"params":..}`. The
/// result is one frame payload for [`super::frame::write_frame`].
///
/// # Panics
/// Only if `T`'s `Serialize` impl fails; the protocol types here are plain derived structs and
/// `Value` trees, which cannot fail.
pub fn encode_request<T: Serialize>(method: &str, id: u64, params: &T) -> Vec<u8> {
    let msg = RequestOut {
        jsonrpc: "2.0",
        id,
        method,
        params,
    };
    serde_json::to_vec(&msg).expect("serializing a script request cannot fail")
}

#[derive(Serialize)]
struct ResponseOut<'a> {
    jsonrpc: &'static str,
    id: u64,
    result: &'a HostCallResult,
}

/// Encodes the host's answer to a `host.call`:
/// `{"jsonrpc":"2.0","id":n,"result":<HostCallResult>}`.
///
/// # Panics
/// Never in practice: a `Value` has string keys and finite numbers only.
pub fn encode_response(id: u64, result: &HostCallResult) -> Vec<u8> {
    let msg = ResponseOut {
        jsonrpc: "2.0",
        id,
        result,
    };
    serde_json::to_vec(&msg).expect("serializing a host call response cannot fail")
}

/// The members of the top-level object, each value kept as raw text, in order.
struct Members<'a>(Vec<(String, &'a RawValue)>);

impl<'de> Deserialize<'de> for Members<'de> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Members<'de>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Members<'de>, A::Error> {
                let mut out = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    out.push((key, map.next_value::<&'de RawValue>()?));
                }
                Ok(Members(out))
            }
        }
        d.deserialize_map(V)
    }
}

fn parse_params<'a, T: Deserialize<'a>>(
    method: &str,
    raw: Option<&'a RawValue>,
) -> Result<T, DecodeError> {
    // An absent `params` is read as `{}`: valid for `script.compiled`, a missing-field error for
    // every method that has required members.
    let text = raw.map_or("{}", RawValue::get);
    serde_json::from_str(text).map_err(|source| DecodeError::BadParams {
        method: method.to_string(),
        source,
    })
}

/// Decodes one worker → host frame payload (§3.3, §3.4).
///
/// Rejects anything that is not a JSON-RPC 2.0 object, an unknown method, a `host.call` without a
/// positive integer id or whose envelope id differs from `params.id`, a worker-sent response, an
/// id on a notification, and any top-level key beyond `jsonrpc`, `method`, `params`, `id`. The
/// `script.result` value stays text; no `Value` is built for it.
pub fn decode_worker_frame(bytes: &[u8]) -> Result<WorkerFrame, DecodeError> {
    if bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return match serde_json::from_slice::<IgnoredAny>(bytes) {
            Ok(_) => Err(DecodeError::NotObject),
            Err(e) => Err(DecodeError::Json(e)),
        };
    }
    let Members(members) = serde_json::from_slice(bytes).map_err(DecodeError::Json)?;

    let mut seen = HashSet::new();
    let mut jsonrpc = None;
    let mut method = None;
    let mut params = None;
    let mut id = None;
    let mut response_key = false;
    for (key, value) in &members {
        if !seen.insert(key.as_str()) {
            return Err(DecodeError::DuplicateKey(key.clone()));
        }
        match key.as_str() {
            "jsonrpc" => jsonrpc = Some(*value),
            "method" => method = Some(*value),
            "params" => params = Some(*value),
            "id" => id = Some(*value),
            "result" | "error" => response_key = true,
            other => return Err(DecodeError::ExtraKey(other.to_string())),
        }
    }

    if jsonrpc.and_then(|v| serde_json::from_str::<&str>(v.get()).ok()) != Some("2.0") {
        return Err(DecodeError::WrongVersion);
    }
    let Some(method) = method else {
        return Err(if response_key {
            DecodeError::WorkerResponse
        } else {
            DecodeError::MissingMethod
        });
    };
    if response_key {
        // `method` next to `result`/`error` is no request, notification or response.
        let key = if seen.contains("result") {
            "result"
        } else {
            "error"
        };
        return Err(DecodeError::ExtraKey(key.to_string()));
    }
    let method: String =
        serde_json::from_str(method.get()).map_err(|_| DecodeError::MissingMethod)?;

    if method == M_HOST_CALL {
        let envelope = id
            .and_then(|v| serde_json::from_str::<u64>(v.get()).ok())
            .filter(|n| *n > 0)
            .ok_or(DecodeError::BadId)?;
        let call: HostCall = parse_params(&method, params)?;
        if call.id != envelope {
            return Err(DecodeError::IdMismatch {
                envelope,
                call: call.id,
            });
        }
        return Ok(WorkerFrame::Call { id: envelope, call });
    }
    if !matches!(
        method.as_str(),
        M_HOST_LOG | M_SCRIPT_RESULT | M_SCRIPT_ERROR | M_SCRIPT_COMPILED | M_SCRIPT_SYNTAX
    ) {
        return Err(DecodeError::UnknownMethod(method));
    }
    if id.is_some() {
        return Err(DecodeError::UnexpectedId);
    }
    Ok(match method.as_str() {
        M_HOST_LOG => {
            let p: LogParams = parse_params(&method, params)?;
            WorkerFrame::Log { line: p.line }
        }
        M_SCRIPT_RESULT => {
            let p: ResultParamsIn = parse_params(&method, params)?;
            WorkerFrame::Result {
                value: Box::new(RawJsonText(p.value.to_owned())),
            }
        }
        M_SCRIPT_ERROR => {
            let p: ErrorParams = parse_params(&method, params)?;
            WorkerFrame::Error {
                class: p.class,
                message: p.message,
                stack: p.stack,
            }
        }
        M_SCRIPT_SYNTAX => {
            let p: SyntaxParams = parse_params(&method, params)?;
            WorkerFrame::Syntax {
                line: p.line,
                column: p.column,
                message: p.message,
            }
        }
        _ => {
            let EmptyParams {} = parse_params(&method, params)?;
            WorkerFrame::Compiled
        }
    })
}
