//! `host.call` request and result (§3.4, §9.2), shared by the host bridge and the worker.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One call from a script to the host. `all` is false for `atlas.call` and true for `atlas.all`,
/// which the host pages internally (accepted only for ops with a `PageSpec`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCall {
    pub id: u64,
    pub op_id: String,
    pub params: Value,
    pub instance: Option<String>,
    pub all: bool,
}

/// Wire form: `{"ok": value}` or `{"rejected": {"class", "details"}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostCallResult {
    Ok(Value),
    Rejected { class: String, details: Value },
}
