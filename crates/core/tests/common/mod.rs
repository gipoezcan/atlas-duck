//! Shared helpers for the `core::testing` suites (each test file uses a subset).
#![allow(dead_code)]

use atlas_duck_ipc::envelope::Envelope;
use atlas_duck_ipc::proto::exit_code;
use serde_json::Value;

pub type TestResult = Result<(), Box<dyn std::error::Error>>;
pub type TestError = Box<dyn std::error::Error>;

/// The envelope as the agent sees it.
pub fn json(env: &Envelope) -> Result<Value, TestError> {
    Ok(serde_json::to_value(env)?)
}

pub fn exit(env: &Envelope) -> i32 {
    exit_code(env)
}

/// `error.code` as its wire name, or `""`.
pub fn code(env: &Envelope) -> String {
    env.error
        .as_ref()
        .and_then(|e| serde_json::to_value(e.code).ok())
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// `error.details.<key>`, or `Null`.
pub fn detail(env: &Envelope, key: &str) -> Value {
    env.error
        .as_ref()
        .and_then(|e| e.details.as_ref())
        .and_then(|d| d.get(key).cloned())
        .unwrap_or(Value::Null)
}

/// The request id of a pending envelope.
pub fn request_id(env: &Envelope) -> Result<String, TestError> {
    env.request_id
        .clone()
        .ok_or_else(|| format!("no request_id in {}", env.to_json_line()).into())
}
