//! Wire types between `core` and the CLI/MCP front ends (§3.3, §4.2-§4.5): handler trait,
//! hello, submit/await parameters, progress, `params_sha256`, request ids and the exit matrix.
//! Types only; the transport lives in `server`/`client` (M4).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::envelope::{Envelope, ErrorCode, Status};
use crate::jcs::{self, JcsError};

/// §3.3 hello `client_kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientKind {
    Cli,
    Mcp,
}

/// §3.3 hello `agent_name_source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentNameSource {
    #[serde(rename = "flag")]
    Flag,
    #[serde(rename = "env")]
    Env,
    #[serde(rename = "mcp-clientInfo")]
    McpClientInfo,
    #[serde(rename = "none")]
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub build_id: String,
    pub client_kind: ClientKind,
    pub agent_name: Option<String>,
    pub agent_name_source: AgentNameSource,
    pub cwd_basename: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloReply {
    pub build_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitParams {
    pub op_id: String,
    pub params: Value,
    pub instance: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwaitParams {
    pub request_id: String,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerHop {
    pub pid: u32,
    pub start_time: u64,
    pub exe: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerInfo {
    pub peer_pid: Option<u32>,
    pub peer_exe: Option<PathBuf>,
    /// At most 4 hops.
    pub peer_chain: Vec<PeerHop>,
    pub peer_origin_exe: Option<PathBuf>,
    pub peer_origin_start_time: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionMeta {
    pub connection_id: String,
    pub peer: PeerInfo,
}

/// §4.4 `requests list` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRow {
    pub request_id: String,
    pub op_id: String,
    pub instance: Option<String>,
    pub target_display: String,
    pub params_sha256: String,
    pub status: Status,
    pub submitted_at: String,
}

/// §3.3 `instances` row; `state` is one of ok, needs_token, identity_header_missing,
/// identity_header_mismatch, insecure_scheme, instance_unconfirmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceRow {
    pub alias: String,
    pub product: String,
    pub is_default: bool,
    pub state: String,
}

/// §4.5: nothing but id and status before a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressNotification {
    pub request_id: String,
    pub status: Status,
}

/// §4.2 `meta`; a `None` field is omitted on the wire.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redactions: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversion: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<Value>,
}

/// `requests list --state` (§4.4): pending, or decided within 24 h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListState {
    Pending,
    Recent,
}

/// `--match-params-file` (§4.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchParams {
    pub op_id: String,
    pub params: Value,
    pub instance: Option<String>,
}

#[async_trait::async_trait]
pub trait RequestHandler: Send + Sync {
    async fn hello(&self, conn: &ConnectionMeta, h: Hello) -> Result<HelloReply, Envelope>;
    async fn ops_list(&self, instance: Option<&str>) -> Envelope;
    async fn ops_describe(&self, op_id: &str, instance: Option<&str>) -> Envelope;
    async fn instances_list(&self) -> Envelope;
    /// Returns at acceptance: `pending` (+ request_id) or an immediate terminal envelope.
    async fn submit(&self, conn: &ConnectionMeta, p: SubmitParams) -> Envelope;
    /// `params` = `{source, args, limits, dry_run?}`.
    async fn submit_script(&self, conn: &ConnectionMeta, p: SubmitParams) -> Envelope;
    /// The only delivering call besides MCP `request_await`.
    async fn await_request(
        &self,
        conn: &ConnectionMeta,
        a: AwaitParams,
        progress: &dyn ProgressSink,
    ) -> Envelope;
    /// Never blocks, carries no data, is never DELIVERED.
    async fn status(&self, request_id: &str) -> Envelope;
    async fn cancel(&self, request_id: &str) -> Envelope;
    async fn requests_list(
        &self,
        agent: Option<&str>,
        state: Option<ListState>,
        match_params: Option<MatchParams>,
    ) -> Envelope;
    async fn doctor(&self) -> Envelope;
}

pub trait ProgressSink: Send + Sync {
    fn progress(&self, n: ProgressNotification);
}

/// SHA-256 over the JCS bytes of `{"op_id", "instance_id", "params"}` (§4.4). `instance_id` is
/// the resolved instance id (`null` for `script.run`). An integer beyond ±(2^53 − 1) is an error.
pub fn params_sha256(
    op_id: &str,
    instance_id: Option<&str>,
    params: &Value,
) -> Result<[u8; 32], JcsError> {
    let bytes = jcs::to_jcs_vec(&json!({
        "op_id": op_id,
        "instance_id": instance_id,
        "params": params,
    }))?;
    Ok(Sha256::digest(&bytes).into())
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Lowercase hex of [`params_sha256`].
pub fn params_sha256_hex(
    op_id: &str,
    instance_id: Option<&str>,
    params: &Value,
) -> Result<String, JcsError> {
    Ok(hex_lower(&params_sha256(op_id, instance_id, params)?))
}

/// `"req_"` + 32 lowercase hex chars from 128 CSPRNG bits. A `getrandom` failure is
/// unrecoverable; callers map it to `internal`.
pub fn new_request_id() -> Result<String, getrandom::Error> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b)?;
    Ok(format!("req_{}", hex_lower(&b)))
}

/// Seconds a client should wait before retrying after the per-connection limit (L44).
pub const BUSY_RETRY_CONNECTION_S: u64 = 5;
/// Seconds a client should wait before retrying after the pending-request limit (L44).
pub const BUSY_RETRY_PENDING_S: u64 = 30;

/// `failed` / `busy`, retryable, with `details.retry_after_s`; `request_id: null`.
pub fn busy_envelope(retry_after_s: u64) -> Envelope {
    let mut e = Envelope::failed(ErrorCode::Busy, true, "busy");
    if let Some(err) = e.error.as_mut() {
        err.details = json!({ "retry_after_s": retry_after_s })
            .as_object()
            .cloned();
    }
    e
}

/// §4.3 status ↔ exit matrix (normative). Agents branch on status + error.code, not this.
pub fn exit_code(env: &Envelope) -> i32 {
    use crate::envelope::{ErrorCode as C, Status as S, exit};
    let code = env.error.as_ref().map(|e| e.code);
    if code == Some(C::ResultEvicted) {
        return exit::RESULT_EVICTED;
    }
    let script_error = env
        .data
        .as_ref()
        .and_then(|d| d.get("script_error"))
        .is_some();
    match env.status {
        S::Pending | S::Executing => exit::PENDING,
        S::Succeeded | S::Released => {
            if script_error {
                exit::SCRIPT
            } else {
                exit::OK
            }
        }
        S::Denied => exit::DENIED,
        S::Expired | S::Cancelled | S::Abandoned => exit::EXPIRED_CANCELLED_ABANDONED,
        S::OutcomeUnknown => exit::UPSTREAM,
        S::Failed => match code {
            Some(C::Internal | C::ProtocolError | C::AuditFailure | C::AuditStorageLow) | None => {
                exit::FAILED_INTERNAL
            }
            Some(
                C::Usage
                | C::Validation
                | C::MarkdownPlaceholders
                | C::OpUnsupportedByInstance
                | C::UnknownRequest,
            ) => exit::USAGE_VALIDATION,
            Some(C::Unreachable | C::ProtocolMismatch | C::ServerIdentity) => exit::UNREACHABLE,
            Some(
                C::UpstreamNetwork
                | C::UpstreamUnavailable
                | C::UpstreamHttp
                | C::ResultTooLarge
                | C::UpstreamUnknownOutcome,
            ) => exit::UPSTREAM,
            Some(C::ScriptSyntax | C::ScriptLimit | C::SandboxUnavailable) => exit::SCRIPT,
            Some(C::Locked | C::NotConfigured | C::NeedsToken) => exit::LOCKED_CONFIG_TOKEN,
            Some(C::Busy) => exit::BUSY,
            // Never produced with status failed (they come with their own status).
            Some(C::Denied | C::ResolutionFailed) => exit::DENIED,
            Some(C::Expired | C::Cancelled | C::Abandoned) => exit::EXPIRED_CANCELLED_ABANDONED,
            Some(C::ResultEvicted) => exit::RESULT_EVICTED,
        },
    }
}
