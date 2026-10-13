//! Shared helpers for the `core::testing` suites (each test file uses a subset).
#![allow(dead_code)]

use atlas_duck_ipc::envelope::Envelope;
use atlas_duck_ipc::proto::exit_code;
use serde_json::Value;

pub mod flows;
pub mod jira;

pub type TestResult = Result<(), Box<dyn std::error::Error>>;
pub type TestError = Box<dyn std::error::Error>;

/// The requests `mock` received apart from the Jira field-name cache's `GET /rest/api/2/field`
/// (PD-46): every Jira harness fills the cache at start, and a token set or a stale map at a
/// preview build fills it again, outside the test's own steps. Any other method on that path is
/// counted: the cache only ever sends a GET.
pub async fn test_hits(mock: &atlas_duck_atlassian::testing::MockDc) -> Vec<wiremock::Request> {
    let field = mock.path("/rest/api/2/field");
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.url.path() != field || r.method.as_str() != "GET")
        .collect()
}

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

/// A `DecisionError` (`Debug`, not `Error`) as a test error.
pub fn de(e: atlas_duck_core::DecisionError) -> TestError {
    format!("{e:?}").into()
}

/// `error.message`, or `""`.
pub fn message(env: &Envelope) -> String {
    env.error
        .as_ref()
        .map(|e| e.message.clone())
        .unwrap_or_default()
}

/// The request id of a pending envelope.
pub fn request_id(env: &Envelope) -> Result<String, TestError> {
    env.request_id
        .clone()
        .ok_or_else(|| format!("no request_id in {}", env.to_json_line()).into())
}
