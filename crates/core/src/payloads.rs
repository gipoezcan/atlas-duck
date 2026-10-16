//! §8.3 payload builders: one per event kind `core` writes, each returning a `NewEvent` with the
//! plaintext columns filled (decision column and caller-settable flags included) and a JSON
//! payload with the §8.3 field names (`SCRIPT_*` builders: Task 27).
//!
//! Plan decisions (spec silent): every hash is lowercase hex; a body is stored losslessly as
//! `{"text"}`, `{"text", "tail_b64"}` or `{"b64"}` (padded RFC 4648), never larger than
//! base64 of the whole body (`body_json`; Task 17 review I-3); an upstream response is
//! `{status, content_type, body}`; process start times are decimal strings (a Windows FILETIME
//! exceeds the ±(2^53−1) integers JCS accepts); paths are lossy UTF-8.
//!
//! No builder takes a PAT (`atlassian::PatSecret`); nothing here can put our token into a record.

use std::borrow::Cow;

use atlas_duck_atlassian::{UnknownReason, UpstreamResponse};
use atlas_duck_audit::request_set::requests_to_json;
use atlas_duck_audit::{
    Actor, DecisionColumn, EventFlags, EventType, NewEvent, RequestRecord, request_set_hash,
};
use atlas_duck_ipc::build_info::APP_VERSION;
use atlas_duck_ipc::envelope::ErrorCode;
use atlas_duck_ipc::peer::MAX_HOPS;
use atlas_duck_ipc::proto::{AgentNameSource, ClientKind, ConnectionMeta, Hello, PeerHop};
use atlas_duck_preview::CandidateRev;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::lifecycle::model::CancelReason;
use crate::normalize::{normalize_hello, normalize_reason};
use crate::redact::RedactionOp;

/// The plaintext columns a record carries besides its type, decision and flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventCtx {
    pub request_id: Option<String>,
    pub op_id: Option<String>,
    /// `"read"`, `"write"` or `"script"`.
    pub op_class: Option<String>,
    pub instance_id: Option<String>,
    /// Issue key / page id / space key / `jql:<tag>` / `cql:<tag>` (§8.2).
    pub target: Option<String>,
    pub actor: Actor,
}

fn event(ctx: &EventCtx, event_type: EventType, payload: Value) -> NewEvent {
    NewEvent {
        event_type,
        request_id: ctx.request_id.clone(),
        op_id: ctx.op_id.clone(),
        op_class: ctx.op_class.clone(),
        instance_id: ctx.instance_id.clone(),
        target: ctx.target.clone(),
        actor: ctx.actor.clone(),
        decision: None,
        flags: EventFlags::default(),
        payload,
    }
}

fn decided(mut ev: NewEvent, d: DecisionColumn) -> NewEvent {
    ev.decision = Some(d);
    ev
}

fn flagged(mut ev: NewEvent, f: EventFlags) -> NewEvent {
    ev.flags |= f;
    ev
}

/// A per-item decision of a confirmed batch (§5.6): flag `batch` and `batch_id` in the payload.
pub fn with_batch(mut ev: NewEvent, batch_id: &str) -> NewEvent {
    ev.flags |= EventFlags::BATCH;
    if let Some(o) = ev.payload.as_object_mut() {
        o.insert("batch_id".into(), Value::String(batch_id.to_owned()));
    }
    ev
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The bytes of `s` inside a JCS string literal (RFC 8785, as ECMAScript `JSON.stringify`),
/// quotes excluded: `"`, `\` and `\b \t \n \f \r` take 2, other controls below U+0020 take 6.
pub fn jcs_escaped_len(s: &str) -> u64 {
    s.bytes()
        .map(|b| match b {
            b'"' | b'\\' | 0x08 | 0x09 | 0x0A | 0x0C | 0x0D => 2,
            0x00..=0x1F => 6,
            _ => 1,
        })
        .sum()
}

/// Padded base64 length of `n` bytes.
pub const fn b64_len(n: u64) -> u64 {
    n.div_ceil(3) * 4
}

/// Upper bound on the JCS bytes of `body_json` of `n` bytes: never more than base64 of the
/// whole body plus the object's keys and the rounding of a text/tail split.
pub const fn body_json_bound(n: u64) -> u64 {
    b64_len(n) + 32
}

/// A body (§8.3 "full response", "every byte received"), losslessly and within
/// `body_json_bound`: `{"text": ..}` for UTF-8; for bytes that stop being UTF-8 (a body cut
/// inside a multibyte character, binary content) `{"text": <valid prefix>, "tail_b64": <rest>}`;
/// `{"b64": ..}` when JSON escaping would make the text longer than its base64.
pub fn body_json(bytes: &[u8]) -> Value {
    let (prefix, tail) = match std::str::from_utf8(bytes) {
        Ok(s) => (s, &[][..]),
        Err(e) => {
            let (head, tail) = bytes.split_at(e.valid_up_to());
            match std::str::from_utf8(head) {
                Ok(s) => (s, tail),
                Err(_) => ("", bytes),
            }
        }
    };
    let n = u64::try_from(prefix.len()).unwrap_or(u64::MAX);
    // Built by hand: `json!` serializes an expression into a new `Value`, a second full-size
    // copy of the body (I-37).
    let mut m = Map::new();
    if (prefix.is_empty() && !tail.is_empty()) || jcs_escaped_len(prefix) > b64_len(n) {
        m.insert("b64".into(), Value::String(STANDARD.encode(bytes)));
    } else {
        m.insert("text".into(), Value::String(prefix.to_owned()));
        if !tail.is_empty() {
            m.insert("tail_b64".into(), Value::String(STANDARD.encode(tail)));
        }
    }
    Value::Object(m)
}

/// The bytes `body_json` stored (rebuild, M10 export); `None` for any other shape.
pub fn body_from_json(v: &Value) -> Option<Vec<u8>> {
    body_ref_from_json(v).map(Cow::into_owned)
}

/// [`body_from_json`] that borrows a `{"text"}` body from `v` instead of copying it (I-37: the
/// candidate is parsed straight from the record).
pub fn body_ref_from_json(v: &Value) -> Option<Cow<'_, [u8]>> {
    let o = v.as_object()?;
    let decode = |k: &str| STANDARD.decode(o.get(k)?.as_str()?).ok();
    let text = || o.get("text")?.as_str().map(str::as_bytes);
    match o.len() {
        1 if o.contains_key("b64") => decode("b64").map(Cow::Owned),
        1 => text().map(Cow::Borrowed),
        2 => {
            let mut out = text()?.to_vec();
            out.extend(decode("tail_b64")?);
            Some(Cow::Owned(out))
        }
        _ => None,
    }
}

/// The bytes one `READ_FETCHED` can carry: the 50 MiB fetch cap (§5.2 step 2) plus one byte (the
/// cut keeps the byte that shows the cap was passed, T11 review I-2; 1 MiB of slack is kept).
pub const READ_FETCHED_MAX_BODY_BYTES: u64 = 51 * 1024 * 1024;
/// Framing allowance of one `READ_FETCHED` beside its bodies (per page `{status, content_type}`
/// and keys, `user_resolutions`).
pub const READ_FETCHED_FRAMING_BYTES: u64 = 16 * 1024 * 1024;

// The largest record core writes fits the store's payload limit (Task 17 review I-3).
const _: () = assert!(
    body_json_bound(READ_FETCHED_MAX_BODY_BYTES) + READ_FETCHED_FRAMING_BYTES
        <= atlas_duck_audit::MAX_PAYLOAD_LEN
);

/// Task 27: the largest `SCRIPT_FINISHED` carries a result of at most `max_result_mb` (16 MiB,
/// §9.4) beside the run's logs and stderr, each at most one 24 MiB worker frame (§3.4); the
/// largest `SCRIPT_CALL` is a `READ_FETCHED`-shaped record (the bound above) plus its params.
/// A run whose record is larger than the store takes fails closed (`audit_failure`).
pub const SCRIPT_RESULT_MAX_BYTES: u64 = 16 * 1024 * 1024;
pub const SCRIPT_LOGS_MAX_BYTES: u64 = 2 * 24 * 1024 * 1024;

const _: () = assert!(
    SCRIPT_RESULT_MAX_BYTES + SCRIPT_LOGS_MAX_BYTES + READ_FETCHED_FRAMING_BYTES
        <= atlas_duck_audit::MAX_PAYLOAD_LEN
);

/// `{status, content_type, body}`.
pub fn response_json(r: &UpstreamResponse) -> Value {
    // The body is moved in: `json!` would serialize it into a copy (I-37).
    let mut m = Map::new();
    m.insert("status".into(), r.status.into());
    m.insert("content_type".into(), json!(r.content_type));
    m.insert("body".into(), body_json(&r.body));
    Value::Object(m)
}

fn rev_json(rev: &CandidateRev) -> Value {
    json!({ "counter": rev.counter, "candidate_hash": hex::encode(rev.candidate_hash) })
}

fn code_json(code: ErrorCode) -> Value {
    // A unit variant always serializes to its snake_case name.
    serde_json::to_value(code).unwrap_or(Value::Null)
}

fn client_kind_str(k: ClientKind) -> &'static str {
    match k {
        ClientKind::Cli => "cli",
        ClientKind::Mcp => "mcp",
    }
}

fn agent_name_source_str(s: AgentNameSource) -> &'static str {
    match s {
        AgentNameSource::Flag => "flag",
        AgentNameSource::Env => "env",
        AgentNameSource::McpClientInfo => "mcp-clientInfo",
        AgentNameSource::None => "none",
    }
}

fn path_json(p: Option<&std::path::Path>) -> Value {
    p.map_or(Value::Null, |p| {
        Value::String(p.to_string_lossy().into_owned())
    })
}

/// §3.1 connection info with the raw (unnormalized) agent strings.
fn connection_json(hello: &Hello, conn: &ConnectionMeta) -> Map<String, Value> {
    let chain: Vec<Value> = conn
        .peer
        .peer_chain
        .iter()
        .map(|h| {
            json!({
                "pid": h.pid,
                "start_time": h.start_time.to_string(),
                "exe": h.exe.to_string_lossy(),
            })
        })
        .collect();
    let mut m = Map::new();
    m.insert(
        "client_kind".into(),
        client_kind_str(hello.client_kind).into(),
    );
    m.insert("agent_name".into(), json!(hello.agent_name));
    m.insert(
        "agent_name_source".into(),
        agent_name_source_str(hello.agent_name_source).into(),
    );
    m.insert("cwd_basename".into(), hello.cwd_basename.clone().into());
    m.insert("peer_pid".into(), json!(conn.peer.peer_pid));
    m.insert("peer_exe".into(), path_json(conn.peer.peer_exe.as_deref()));
    m.insert("peer_chain".into(), Value::Array(chain));
    m.insert(
        "peer_origin_exe".into(),
        path_json(conn.peer.peer_origin_exe.as_deref()),
    );
    m.insert(
        "peer_origin_start_time".into(),
        json!(conn.peer.peer_origin_start_time.map(|t| t.to_string())),
    );
    m.insert("connection_id".into(), conn.connection_id.clone().into());
    m
}

/// The agent identity columns (§8.2) of a connection: the normalized `agent_name` (§3.3), the
/// raw one stays in the payload. `os_user`/`atlassian_user*` stay `None`.
pub fn agent_actor(hello: &Hello, conn: &ConnectionMeta) -> Actor {
    Actor {
        agent_name: normalize_hello(hello).agent_name,
        agent_name_source: Some(agent_name_source_str(hello.agent_name_source).to_owned()),
        client_kind: Some(client_kind_str(hello.client_kind).to_owned()),
        connection_id: Some(conn.connection_id.clone()),
        peer_pid: conn.peer.peer_pid,
        peer_exe: conn.peer.peer_exe.clone(),
        peer_origin_exe: conn.peer.peer_origin_exe.clone(),
        ..Actor::default()
    }
}

/// What a queued entry keeps of its connection for the Request tab: the agent columns and the
/// peer chain cut to `MAX_HOPS`. Never written into `ctx.actor` (see `RequestEntry::connection`).
pub fn connection_facts(hello: &Hello, conn: &ConnectionMeta) -> (Actor, Vec<PeerHop>) {
    let chain = conn
        .peer
        .peer_chain
        .iter()
        .take(MAX_HOPS)
        .cloned()
        .collect();
    (agent_actor(hello, conn), chain)
}

/// The agent columns of `hello`/`conn` over `ctx.actor`'s approver fields.
fn with_agent(mut ev: NewEvent, hello: &Hello, conn: &ConnectionMeta) -> NewEvent {
    ev.actor = Actor {
        os_user: ev.actor.os_user,
        atlassian_user: ev.actor.atlassian_user,
        atlassian_user_key: ev.actor.atlassian_user_key,
        ..agent_actor(hello, conn)
    };
    ev
}

// ---- Lifecycle -------------------------------------------------------------------------------

/// `REQUEST_RECEIVED`: full params, `params_sha256`, the connection with raw agent strings, the
/// raw `reason` and the §3.3 normalized forms. The agent columns come from `hello`/`conn`
/// (`ctx.actor`'s approver fields are kept).
pub fn request_received(
    ctx: &EventCtx,
    params: &Value,
    params_sha256: &[u8; 32],
    hello: &Hello,
    conn: &ConnectionMeta,
    reason: Option<&str>,
) -> NewEvent {
    let n = normalize_hello(hello);
    let (reason_norm, reason_unusual) = match reason.map(normalize_reason) {
        Some((r, u)) => (Some(r), u),
        None => (None, false),
    };
    let ev = event(
        ctx,
        EventType::REQUEST_RECEIVED,
        json!({
            "params": params,
            "params_sha256": hex::encode(params_sha256),
            "connection": connection_json(hello, conn),
            "reason": reason,
            "normalized": {
                "agent_name": n.agent_name,
                "cwd_basename": n.cwd_basename,
                "reason": reason_norm,
                "unusual": n.unusual || reason_unusual,
            },
        }),
    );
    with_agent(ev, hello, conn)
}

/// `REQUEST_REJECTED` (terminal), decision `reject`.
pub fn request_rejected(
    ctx: &EventCtx,
    code: ErrorCode,
    message: &str,
    details: &Value,
) -> NewEvent {
    decided(
        event(
            ctx,
            EventType::REQUEST_REJECTED,
            json!({ "code": code_json(code), "message": message, "details": details }),
        ),
        DecisionColumn::Reject,
    )
}

/// `REQUEST_FAILED {code}` (terminal; data-free enrichment-phase failures and `internal`).
pub fn request_failed(ctx: &EventCtx, code: ErrorCode) -> NewEvent {
    event(
        ctx,
        EventType::REQUEST_FAILED,
        json!({ "code": code_json(code) }),
    )
}

/// `REQUEST_FAILED {code, message, details}` of a data-free direct enrichment failure (§5.4 step
/// 2) plus its cause (`class` of a connection-level failure, `reason` of a status/header-decided
/// one), like `read_failed`: `message` and `details` are what `await` delivers, the cause stays
/// in the record.
pub fn request_failed_direct(
    ctx: &EventCtx,
    code: ErrorCode,
    message: &str,
    details: &Value,
    cause: Option<(&str, &str)>,
) -> NewEvent {
    let mut ev = request_failed(ctx, code);
    if let Some(m) = ev.payload.as_object_mut() {
        m.insert("message".into(), message.into());
        m.insert("details".into(), details.clone());
        if let Some((k, v)) = cause {
            m.insert(k.into(), v.into());
        }
    }
    ev
}

/// `PREVIEW_FETCH.purpose`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewFetchPurpose {
    Enrich,
    StaleCheck,
    Refresh,
    Resolve,
}

impl PreviewFetchPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enrich => "enrich",
            Self::StaleCheck => "stale_check",
            Self::Refresh => "refresh",
            Self::Resolve => "resolve",
        }
    }
}

/// `outcome` of a GET that did not complete or whose JSON body failed to parse (§5.4 step 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeKind {
    Timeout,
    Network,
    TooLarge,
    Unparsable,
}

impl OutcomeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Network => "network",
            Self::TooLarge => "too_large",
            Self::Unparsable => "unparsable",
        }
    }
}

/// What one app-initiated call produced: the full response, or an outcome with every byte
/// received (`cancelled_in_flight` included).
#[derive(Debug, Clone, Copy)]
pub enum FetchRecord<'a> {
    Response(&'a UpstreamResponse),
    Outcome {
        outcome: OutcomeKind,
        status: Option<u16>,
        content_type: Option<&'a str>,
        received: &'a [u8],
    },
    CancelledInFlight {
        reason: InFlightReason,
        received: &'a [u8],
    },
}

fn fetch_record_fields(m: &mut Map<String, Value>, r: &FetchRecord<'_>) {
    match r {
        FetchRecord::Response(resp) => {
            m.insert("status".into(), resp.status.into());
            m.insert("response".into(), response_json(resp));
        }
        FetchRecord::Outcome {
            outcome,
            status,
            content_type,
            received,
        } => {
            m.insert("status".into(), json!(status));
            m.insert("outcome".into(), outcome.as_str().into());
            m.insert("content_type".into(), json!(content_type));
            m.insert("received".into(), body_json(received));
        }
        FetchRecord::CancelledInFlight { reason, received } => {
            m.insert("status".into(), Value::Null);
            m.insert("outcome".into(), "cancelled_in_flight".into());
            m.insert("reason".into(), reason.as_str().into());
            m.insert("received".into(), body_json(received));
        }
    }
}

/// `PREVIEW_FETCH {purpose, method, path, status, response | outcome}` (§8.3).
pub fn preview_fetch(
    ctx: &EventCtx,
    purpose: PreviewFetchPurpose,
    method: &str,
    path: &str,
    record: &FetchRecord<'_>,
) -> NewEvent {
    let mut m = Map::new();
    m.insert("purpose".into(), purpose.as_str().into());
    m.insert("method".into(), method.into());
    m.insert("path".into(), path.into());
    fetch_record_fields(&mut m, record);
    event(ctx, EventType::PREVIEW_FETCH, Value::Object(m))
}

/// The decision a rejected decision record names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmittedDecision {
    Approve,
    Release,
    Deny,
    Edit,
    /// Plan addition (Task 21 step 6): a `preview_fetch` of a revision that is no longer
    /// current is recorded like a stale decision.
    Preview,
}

impl SubmittedDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Release => "release",
            Self::Deny => "deny",
            Self::Edit => "edit",
            Self::Preview => "preview",
        }
    }
}

/// `DECISION_STALE {submitted_rev, current_rev, decision, batch}` (non-terminal). `batch` is
/// payload only: the `batch` flag marks per-item decisions (`with_batch`).
pub fn decision_stale(
    ctx: &EventCtx,
    submitted_rev: u64,
    current_rev: u64,
    decision: SubmittedDecision,
    batch: bool,
) -> NewEvent {
    event(
        ctx,
        EventType::DECISION_STALE,
        json!({
            "submitted_rev": submitted_rev,
            "current_rev": current_rev,
            "decision": decision.as_str(),
            "batch": batch,
        }),
    )
}

/// `DECISION_INVALID.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidReason {
    TargetParamEdit,
    NotOpened,
    NotApprovable,
    BatchItemFlagged,
}

impl InvalidReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TargetParamEdit => "target_param_edit",
            Self::NotOpened => "not_opened",
            Self::NotApprovable => "not_approvable",
            Self::BatchItemFlagged => "batch_item_flagged",
        }
    }
}

/// `DECISION_INVALID {reason, submitted_rev, decision, batch}` (non-terminal).
pub fn decision_invalid(
    ctx: &EventCtx,
    reason: InvalidReason,
    submitted_rev: u64,
    decision: SubmittedDecision,
    batch: bool,
) -> NewEvent {
    event(
        ctx,
        EventType::DECISION_INVALID,
        json!({
            "reason": reason.as_str(),
            "submitted_rev": submitted_rev,
            "decision": decision.as_str(),
            "batch": batch,
        }),
    )
}

/// `PREVIEW_SHOWN {candidate_rev, warning_ids, preview_builder_version}` (non-terminal).
pub fn preview_shown(
    ctx: &EventCtx,
    rev: &CandidateRev,
    warning_ids: &[String],
    preview_builder_version: &str,
) -> NewEvent {
    event(
        ctx,
        EventType::PREVIEW_SHOWN,
        json!({
            "candidate_rev": rev_json(rev),
            "warning_ids": warning_ids,
            "preview_builder_version": preview_builder_version,
        }),
    )
}

/// `BATCH_CONFIRMED {batch_id, items: [{request_id, candidate_rev}], dialog_text_sha256}`
/// (`request_id` column null; `actor` is the approver). Payload only: no `batch` flag, which
/// marks the per-item decisions that follow it.
pub fn batch_confirmed(
    actor: &Actor,
    batch_id: &str,
    items: &[(String, CandidateRev)],
    dialog_text_sha256: &[u8; 32],
) -> NewEvent {
    let items: Vec<Value> = items
        .iter()
        .map(|(id, rev)| json!({ "request_id": id, "candidate_rev": rev_json(rev) }))
        .collect();
    let ctx = EventCtx {
        actor: actor.clone(),
        ..EventCtx::default()
    };
    event(
        &ctx,
        EventType::BATCH_CONFIRMED,
        json!({
            "batch_id": batch_id,
            "items": items,
            "dialog_text_sha256": hex::encode(dialog_text_sha256),
        }),
    )
}

/// `DELIVERED {connection_id, client_kind, agent_name(+source), cwd_basename, peer_pid,
/// peer_exe, peer_chain, payload_sha256}` (PD-23) for the connection it was handed to, which
/// may differ from the submitter's: the agent columns come from `hello`/`conn`, as in
/// `request_received`.
pub fn delivered(
    ctx: &EventCtx,
    hello: &Hello,
    conn: &ConnectionMeta,
    payload_sha256: &[u8; 32],
) -> NewEvent {
    let mut m = connection_json(hello, conn);
    m.insert(
        "payload_sha256".into(),
        Value::String(hex::encode(payload_sha256)),
    );
    with_agent(
        event(ctx, EventType::DELIVERED, Value::Object(m)),
        hello,
        conn,
    )
}

// ---- Reads -----------------------------------------------------------------------------------

/// Why a read or GET was aborted in flight (§5.2 step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InFlightReason {
    ByClient,
    Expired,
    AppQuit,
    OsShutdown,
    /// A script run that ended by itself (timeout, crash, limit, user kill) with this host
    /// call still in flight (§9.5).
    RunEnded,
}

impl InFlightReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ByClient => "by_client",
            Self::Expired => "expired",
            Self::AppQuit => "app_quit",
            Self::OsShutdown => "os_shutdown",
            Self::RunEnded => "run_ended",
        }
    }
}

/// The cap or budget an outcome item hit (§5.2 step 6, §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapOrBudget {
    ReleaseCap16MiB,
    ResponseCap32MiB,
    FetchCap50MiB,
    ReadBudget120s,
    CallTimeout30s,
}

impl CapOrBudget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseCap16MiB => "release_cap_16mib",
            Self::ResponseCap32MiB => "response_cap_32mib",
            Self::FetchCap50MiB => "fetch_cap_50mib",
            Self::ReadBudget120s => "read_budget_120s",
            Self::CallTimeout30s => "call_timeout_30s",
        }
    }
}

/// What a read fetched. `responses` are the completed pages in full; `partial` is the bytes of
/// the page that did not complete; `size` counts every byte received.
#[derive(Debug, Clone, Copy)]
pub enum ReadFetched<'a> {
    Pages {
        responses: &'a [UpstreamResponse],
    },
    /// The last response is the non-2xx answer that becomes the upstream-error card.
    UpstreamError {
        responses: &'a [UpstreamResponse],
    },
    /// A data-free direct failure that still received an answer (§7.2: status/header-decided,
    /// or a failed identity check): the last response is that answer, audit-only (RF-2a).
    Unavailable {
        responses: &'a [UpstreamResponse],
        reason: &'a str,
    },
    Outcome {
        outcome: OutcomeKind,
        cap_or_budget: Option<CapOrBudget>,
        responses: &'a [UpstreamResponse],
        partial: &'a [u8],
        size: u64,
    },
    CancelledInFlight {
        reason: InFlightReason,
        responses: &'a [UpstreamResponse],
        partial: &'a [u8],
        size: u64,
    },
}

/// `READ_FETCHED` (§8.3, §5.2 step 3): the pages, or `{outcome, cap_or_budget, size, pages}`
/// beside every byte received, or `{outcome: cancelled_in_flight, reason, pages, size}`; plus
/// the `user_resolutions` map of a Markdown-converted Confluence body (§7.6).
pub fn read_fetched(
    ctx: &EventCtx,
    fetched: &ReadFetched<'_>,
    user_resolutions: Option<&Value>,
) -> NewEvent {
    let pages = |r: &[UpstreamResponse]| -> Vec<Value> { r.iter().map(response_json).collect() };
    let mut m = Map::new();
    match fetched {
        ReadFetched::Pages { responses } => {
            m.insert("pages".into(), responses.len().into());
            m.insert("responses".into(), pages(responses).into());
        }
        ReadFetched::UpstreamError { responses } => {
            m.insert("pages".into(), responses.len().into());
            m.insert("responses".into(), pages(responses).into());
            m.insert("upstream_error".into(), true.into());
        }
        ReadFetched::Unavailable { responses, reason } => {
            m.insert("pages".into(), responses.len().into());
            m.insert("responses".into(), pages(responses).into());
            m.insert("unavailable".into(), (*reason).into());
        }
        ReadFetched::Outcome {
            outcome,
            cap_or_budget,
            responses,
            partial,
            size,
        } => {
            m.insert("outcome".into(), outcome.as_str().into());
            m.insert(
                "cap_or_budget".into(),
                json!(cap_or_budget.map(CapOrBudget::as_str)),
            );
            m.insert("size".into(), (*size).into());
            m.insert("pages".into(), responses.len().into());
            m.insert("responses".into(), pages(responses).into());
            m.insert("partial".into(), body_json(partial));
        }
        ReadFetched::CancelledInFlight {
            reason,
            responses,
            partial,
            size,
        } => {
            m.insert("outcome".into(), "cancelled_in_flight".into());
            m.insert("reason".into(), reason.as_str().into());
            m.insert("size".into(), (*size).into());
            m.insert("pages".into(), responses.len().into());
            m.insert("responses".into(), pages(responses).into());
            m.insert("partial".into(), body_json(partial));
        }
    }
    if let Some(u) = user_resolutions {
        m.insert("user_resolutions".into(), u.clone());
    }
    event(ctx, EventType::READ_FETCHED, Value::Object(m))
}

/// `READ_RELEASED` of data: the released bytes, the redaction ops that produced them and their
/// SHA-256 (the `DELIVERED.payload_sha256` of the hand-off, inv. 2) and the `candidate_rev` of the
/// released revision (PD-57: U-32 compares it with the `PREVIEW_SHOWN` of the same request).
/// Decision `release`, or `release_redacted` with flag `redacted` when any op applied.
pub fn read_released(
    ctx: &EventCtx,
    rev: &CandidateRev,
    released: &[u8],
    redaction_ops: &[RedactionOp],
) -> Result<NewEvent, serde_json::Error> {
    let ops = serde_json::to_value(redaction_ops)?;
    let ev = event(
        ctx,
        EventType::READ_RELEASED,
        json!({
            "candidate_rev": rev_json(rev),
            "released": body_json(released),
            "redaction_ops": ops,
            "released_sha256": sha256_hex(released),
        }),
    );
    Ok(if redaction_ops.is_empty() {
        decided(ev, DecisionColumn::Release)
    } else {
        flagged(
            decided(ev, DecisionColumn::ReleaseRedacted),
            EventFlags::REDACTED,
        )
    })
}

/// What a data `READ_RELEASED` hands over (§4.3): the result, or an upstream-error item's
/// details (delivered as `failed`, `upstream_http`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleasedItem {
    Result,
    UpstreamError,
}

impl ReleasedItem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Result => "result",
            Self::UpstreamError => "upstream_error",
        }
    }
}

/// `READ_RELEASED` of a release item with what its delivery needs from the record alone: the
/// `item` marker (a released upstream error is told from a data release by it; no caller-settable
/// flag is free for a plaintext marker) and `meta` (`page`, `redactions`; §4.2, §7.5).
pub fn read_released_item(
    ctx: &EventCtx,
    rev: &CandidateRev,
    released: &[u8],
    redaction_ops: &[RedactionOp],
    item: ReleasedItem,
    meta: &Value,
) -> Result<NewEvent, serde_json::Error> {
    let mut ev = read_released(ctx, rev, released, redaction_ops)?;
    if let Some(o) = ev.payload.as_object_mut() {
        o.insert("item".into(), item.as_str().into());
        o.insert("meta".into(), meta.clone());
    }
    Ok(ev)
}

/// `READ_RELEASED` of an outcome item: the outcome-only payload `{candidate_rev, code, hint}`.
pub fn read_released_outcome(
    ctx: &EventCtx,
    rev: &CandidateRev,
    code: ErrorCode,
    hint: &str,
) -> NewEvent {
    decided(
        event(
            ctx,
            EventType::READ_RELEASED,
            json!({ "candidate_rev": rev_json(rev), "code": code_json(code), "hint": hint }),
        ),
        DecisionColumn::Release,
    )
}

/// `READ_DENIED {reason}`, decision `deny`.
pub fn read_denied(ctx: &EventCtx, reason: Option<&str>) -> NewEvent {
    decided(
        event(ctx, EventType::READ_DENIED, json!({ "reason": reason })),
        DecisionColumn::Deny,
    )
}

/// `READ_FAILED {code, message, details}` (terminal; data-free outcomes only, §5.2 step 6) plus
/// its cause (`class` of a connection-level failure, `reason` of a status/header-decided one).
/// `message` and `details` are what `await` delivers; the cause stays in the record.
pub fn read_failed(
    ctx: &EventCtx,
    code: ErrorCode,
    message: &str,
    details: &Value,
    cause: Option<(&str, &str)>,
) -> NewEvent {
    let mut m = Map::new();
    m.insert("code".into(), code_json(code));
    m.insert("message".into(), message.into());
    m.insert("details".into(), details.clone());
    if let Some((k, v)) = cause {
        m.insert(k.into(), v.into());
    }
    event(ctx, EventType::READ_FAILED, Value::Object(m))
}

// ---- Scripts (Task 27, §8.3) -----------------------------------------------------------------

/// The host's own view of a script run's error (§9.5): the worker's self-reported class, message
/// and stack are untrusted payload, stored only for the release preview. Serialized as the
/// candidate's `script_error` object `{class, message, stack, elapsed, logs, stderr}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptErrorDetails {
    pub class: String,
    pub message: String,
    pub stack: String,
    pub elapsed_ms: u64,
    pub logs: Vec<String>,
    pub stderr: String,
}

impl ScriptErrorDetails {
    pub fn to_value(&self) -> Value {
        json!({
            "class": self.class,
            "message": self.message,
            "stack": self.stack,
            "elapsed": self.elapsed_ms,
            "logs": self.logs,
            "stderr": self.stderr,
        })
    }
}

/// `SCRIPT_STARTED {source, args, limits, queued}` (§9.1 step 2): the full source, so the log
/// can show what ran.
pub fn script_started(
    ctx: &EventCtx,
    source: &str,
    args: &Value,
    limits: &atlas_duck_ipc::sandbox::ScriptLimits,
    queued: bool,
) -> NewEvent {
    event(
        ctx,
        EventType::SCRIPT_STARTED,
        json!({
            "source": source,
            "args": args,
            "limits": serde_json::to_value(limits).unwrap_or(Value::Null),
            "queued": queued,
        }),
    )
}

/// `SCRIPT_CALL_SENT {call_id, op_id, instance}` (non-terminal): the run is now dispatched.
pub fn script_call_sent(
    ctx: &EventCtx,
    call_id: u64,
    op_id: &str,
    instance: Option<&str>,
) -> NewEvent {
    event(
        ctx,
        EventType::SCRIPT_CALL_SENT,
        json!({ "call_id": call_id, "op_id": op_id, "instance": instance }),
    )
}

/// What identifies one internal read of a script.
#[derive(Debug, Clone, Copy)]
pub struct ScriptCallMeta<'a> {
    pub call_id: u64,
    pub op: &'a str,
    pub params: &'a Value,
    /// The instance alias.
    pub instance: Option<&'a str>,
    /// The PAT's Atlassian user key (never the PAT).
    pub user_key: Option<&'a str>,
    /// The class the script saw when the call was rejected (`upstream_http`, `result_too_large`,
    /// ...); `None` when the result was handed over.
    pub rejection: Option<&'a str>,
}

/// `SCRIPT_CALL` (§8.3): the op, params, instance and user, with every byte received laid out as
/// `READ_FETCHED` does (`responses`, or `outcome` with the partial bytes), then `bytes`.
pub fn script_call(
    ctx: &EventCtx,
    meta: &ScriptCallMeta<'_>,
    fetched: &ReadFetched<'_>,
    bytes: u64,
    user_resolutions: Option<&Value>,
) -> NewEvent {
    script_call_from(read_fetched(ctx, fetched, user_resolutions), meta, bytes)
}

/// [`script_call`] over an already built `READ_FETCHED`-shaped record (a classified fetch's own
/// `record`): retyped, with the call's identity and `bytes` added.
pub fn script_call_from(mut ev: NewEvent, meta: &ScriptCallMeta<'_>, bytes: u64) -> NewEvent {
    ev.event_type = EventType::SCRIPT_CALL;
    if let Some(m) = ev.payload.as_object_mut() {
        m.insert("call_id".into(), meta.call_id.into());
        m.insert("op".into(), meta.op.into());
        m.insert("params".into(), meta.params.clone());
        m.insert("instance".into(), json!(meta.instance));
        m.insert("user_key".into(), json!(meta.user_key));
        m.insert("rejection".into(), json!(meta.rejection));
        m.insert("bytes".into(), bytes.into());
    }
    ev
}

/// `SCRIPT_FINISHED {result, logs, stderr}`: the release candidate of a run that returned.
pub fn script_finished_result(
    ctx: &EventCtx,
    value: &Value,
    logs: &[String],
    stderr: &str,
) -> NewEvent {
    event(
        ctx,
        EventType::SCRIPT_FINISHED,
        json!({ "result": value, "logs": logs, "stderr": stderr }),
    )
}

/// `SCRIPT_FINISHED {error}`: the release candidate of a run that raised.
pub fn script_finished_error(ctx: &EventCtx, error: &ScriptErrorDetails) -> NewEvent {
    event(
        ctx,
        EventType::SCRIPT_FINISHED,
        json!({ "error": error.to_value() }),
    )
}

/// The flags and text of a `SCRIPT_FAILED` (§8.3): `direct` is exactly the §9.5 single rule.
#[derive(Debug, Clone, Copy)]
pub struct ScriptFailed<'a> {
    pub reason: &'a str,
    pub queued: bool,
    pub dispatched: bool,
    pub direct: bool,
    /// `{line, column, message}` of a syntax error.
    pub details: Option<&'a Value>,
    /// The error-details candidate of a non-direct failure that is a release item.
    pub candidate: Option<&'a Value>,
}

/// `SCRIPT_FAILED {reason, queued, dispatched, data_free, direct, details?, candidate?}`.
pub fn script_failed(ctx: &EventCtx, f: &ScriptFailed<'_>) -> NewEvent {
    let mut m = Map::new();
    m.insert("reason".into(), f.reason.into());
    m.insert("queued".into(), f.queued.into());
    m.insert("dispatched".into(), f.dispatched.into());
    m.insert("data_free".into(), (!f.dispatched).into());
    m.insert("direct".into(), f.direct.into());
    if let Some(d) = f.details {
        m.insert("details".into(), d.clone());
    }
    if let Some(c) = f.candidate {
        m.insert("candidate".into(), c.clone());
    }
    event(ctx, EventType::SCRIPT_FAILED, Value::Object(m))
}

/// What a `SCRIPT_RELEASED` hands over (§4.3): the result, or the error details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptReleasedItem {
    Result,
    Error,
}

impl ScriptReleasedItem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Result => "result",
            Self::Error => "script_error",
        }
    }
}

/// `SCRIPT_RELEASED`: the released bytes (the candidate, `{result}` or `{script_error}`), the
/// redaction ops that produced them and their SHA-256, like `READ_RELEASED`.
pub fn script_released(
    ctx: &EventCtx,
    rev: &CandidateRev,
    released: &[u8],
    redaction_ops: &[RedactionOp],
    item: ScriptReleasedItem,
    meta: Option<&Value>,
) -> Result<NewEvent, serde_json::Error> {
    let mut ev = read_released(ctx, rev, released, redaction_ops)?;
    ev.event_type = EventType::SCRIPT_RELEASED;
    if let Some(o) = ev.payload.as_object_mut() {
        o.insert("item".into(), item.as_str().into());
        // `meta.redactions` of a redacted release, from the record alone like a read's (§4.2).
        if let Some(m) = meta {
            o.insert("meta".into(), m.clone());
        }
    }
    Ok(ev)
}

/// `SCRIPT_DENIED {reason}`, decision `deny`.
pub fn script_denied(ctx: &EventCtx, reason: Option<&str>) -> NewEvent {
    let mut ev = read_denied(ctx, reason);
    ev.event_type = EventType::SCRIPT_DENIED;
    ev
}

/// `SCRIPT_DRY_RUN {mode, calls, outcome, result | error | details, logs}` (terminal; no
/// `SCRIPT_STARTED`, no `SCRIPT_CALL`).
pub fn script_dry_run(
    ctx: &EventCtx,
    mode: &str,
    calls: &[Value],
    outcome: &str,
    body: (&str, &Value),
    logs: &[String],
) -> NewEvent {
    let mut m = Map::new();
    m.insert("mode".into(), mode.into());
    m.insert("calls".into(), calls.to_vec().into());
    m.insert("outcome".into(), outcome.into());
    m.insert(body.0.into(), body.1.clone());
    m.insert("logs".into(), logs.to_vec().into());
    event(ctx, EventType::SCRIPT_DRY_RUN, Value::Object(m))
}

// ---- Writes ----------------------------------------------------------------------------------

/// `WRITE_EDITED {original, edited}`, flag `edited`.
pub fn write_edited(ctx: &EventCtx, original: &Value, edited: &Value) -> NewEvent {
    flagged(
        event(
            ctx,
            EventType::WRITE_EDITED,
            json!({ "original": original, "edited": edited }),
        ),
        EventFlags::EDITED,
    )
}

/// `WRITE_APPROVED {candidate_rev, request_set_hash, requests}` (§5.4 step 4): `requests` in the
/// F.8 shape M2 verifies, the hash computed here from the same records. Decision `approve`, or
/// `approve_edited` with flag `edited` for a request that was ever edited (PD-20).
pub fn write_approved(
    ctx: &EventCtx,
    rev: &CandidateRev,
    requests: &[RequestRecord],
    edited: bool,
) -> NewEvent {
    let ev = event(
        ctx,
        EventType::WRITE_APPROVED,
        json!({
            "candidate_rev": rev_json(rev),
            "request_set_hash": hex::encode(request_set_hash(requests)),
            "requests": requests_to_json(requests),
        }),
    );
    if edited {
        flagged(
            decided(ev, DecisionColumn::ApproveEdited),
            EventFlags::EDITED,
        )
    } else {
        decided(ev, DecisionColumn::Approve)
    }
}

/// `WRITE_DENIED {reason, hint}` (the attached hint, if any, §5.4 step 2), decision `deny`.
pub fn write_denied(ctx: &EventCtx, reason: Option<&str>, hint: Option<&Value>) -> NewEvent {
    decided(
        event(
            ctx,
            EventType::WRITE_DENIED,
            json!({ "reason": reason, "hint": hint }),
        ),
        DecisionColumn::Deny,
    )
}

/// `WRITE_STALE.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteStaleReason {
    Changed,
    RecheckFailed,
    VersionConflict,
    CredentialChanged,
    IdentityMismatch,
    InstanceChanged,
    UserRenamed,
}

impl WriteStaleReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Changed => "changed",
            Self::RecheckFailed => "recheck_failed",
            Self::VersionConflict => "version_conflict",
            Self::CredentialChanged => "credential_changed",
            Self::IdentityMismatch => "identity_mismatch",
            Self::InstanceChanged => "instance_changed",
            Self::UserRenamed => "user_renamed",
        }
    }
}

/// `WRITE_STALE {reason, class?}` (`class` e.g. `network`, `origin_mismatch`,
/// `identity_header_missing`), flag `stale`.
pub fn write_stale(ctx: &EventCtx, reason: WriteStaleReason, class: Option<&str>) -> NewEvent {
    flagged(
        event(
            ctx,
            EventType::WRITE_STALE,
            json!({ "reason": reason.as_str(), "class": class }),
        ),
        EventFlags::STALE,
    )
}

/// `WRITE_EXECUTED {request_index, response, server_user}` (`X-AUSERNAME` on Jira, §5.4 step 6).
pub fn write_executed(
    ctx: &EventCtx,
    request_index: u32,
    response: &UpstreamResponse,
    server_user: Option<&str>,
) -> NewEvent {
    event(
        ctx,
        EventType::WRITE_EXECUTED,
        json!({
            "request_index": request_index,
            "response": response_json(response),
            "server_user": server_user,
        }),
    )
}

/// What a failed write left: the refusal with the details `await` delivers (§11.2: status and
/// the capped `errorMessages`/`errors`), or the class of a failure without a usable answer and
/// every byte received (audit-only, §7.2).
#[derive(Debug, Clone, Copy)]
pub enum WriteFailure<'a> {
    Response {
        response: &'a UpstreamResponse,
        details: &'a Value,
    },
    Class {
        class: &'a str,
        status: Option<u16>,
        received: &'a [u8],
    },
}

/// `WRITE_FAILED {request_index, code, message, response + details | class, status, received}`:
/// `code`, `message` and `details` are what `await` delivers (Task 22).
pub fn write_failed(
    ctx: &EventCtx,
    request_index: u32,
    code: ErrorCode,
    message: &str,
    failure: &WriteFailure<'_>,
) -> NewEvent {
    let mut m = Map::new();
    m.insert("request_index".into(), request_index.into());
    m.insert("code".into(), code_json(code));
    m.insert("message".into(), message.into());
    match failure {
        WriteFailure::Response { response, details } => {
            m.insert("response".into(), response_json(response));
            m.insert("details".into(), (*details).clone());
        }
        WriteFailure::Class {
            class,
            status,
            received,
        } => {
            m.insert("class".into(), (*class).into());
            m.insert("status".into(), json!(status));
            m.insert("received".into(), body_json(received));
        }
    }
    event(ctx, EventType::WRITE_FAILED, Value::Object(m))
}

fn unknown_reason_str(r: &UnknownReason) -> &'static str {
    match r {
        UnknownReason::Timeout => "timeout",
        UnknownReason::ResetAfterSend => "reset_after_send",
        UnknownReason::ServerError5xx => "server_error_5xx",
        UnknownReason::UndeclaredSuccess => "undeclared_success",
        UnknownReason::IdentityMismatch { .. } => "identity_mismatch",
        UnknownReason::Cancelled => "cancelled",
    }
}

/// `WRITE_OUTCOME_UNKNOWN {request_index, reason, server_user, status, received}`: `received`
/// is every byte of the answer (audit-only, §7.2; `take_captured().partial` where the outcome
/// carries no response). `reason: crash` is the store's (§11.3, Q1), never built here.
pub fn write_outcome_unknown(
    ctx: &EventCtx,
    request_index: u32,
    reason: &UnknownReason,
    status: Option<u16>,
    received: &[u8],
) -> NewEvent {
    let server_user = match reason {
        UnknownReason::IdentityMismatch { server_user } => server_user.as_deref(),
        _ => None,
    };
    event(
        ctx,
        EventType::WRITE_OUTCOME_UNKNOWN,
        json!({
            "request_index": request_index,
            "reason": unknown_reason_str(reason),
            "server_user": server_user,
            "status": status,
            "received": body_json(received),
        }),
    )
}

// ---- Terminal --------------------------------------------------------------------------------

/// `EXPIRED`, decision `expire`.
pub fn expired(ctx: &EventCtx) -> NewEvent {
    decided(
        event(ctx, EventType::EXPIRED, json!({})),
        DecisionColumn::Expire,
    )
}

fn cancel_reason_str(r: CancelReason) -> &'static str {
    match r {
        CancelReason::ByClient => "by_client",
        CancelReason::AppQuit => "app_quit",
        CancelReason::OsShutdown => "os_shutdown",
    }
}

/// `CANCELLED {reason: by_client|app_quit|os_shutdown}`, decision `cancel`.
pub fn cancelled(ctx: &EventCtx, reason: CancelReason) -> NewEvent {
    decided(
        event(
            ctx,
            EventType::CANCELLED,
            json!({ "reason": cancel_reason_str(reason) }),
        ),
        DecisionColumn::Cancel,
    )
}

// ---- System ----------------------------------------------------------------------------------

/// `SYSTEM_FETCH.purpose` (§8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemFetchPurpose {
    ConnectionTest,
    VersionDetect,
    MetadataCache,
    Doctor,
    TokenRecheck,
}

impl SystemFetchPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionTest => "connection_test",
            Self::VersionDetect => "version_detect",
            Self::MetadataCache => "metadata_cache",
            Self::Doctor => "doctor",
            Self::TokenRecheck => "token_recheck",
        }
    }
}

fn instance_ctx(instance_id: &str) -> EventCtx {
    EventCtx {
        instance_id: Some(instance_id.to_owned()),
        ..EventCtx::default()
    }
}

/// `SYSTEM_FETCH {purpose, instance_id, fetch_id, phase: start, planned: [{method, path}]}`
/// (`request_id` null), committed through `commit_system_fetch_start` before the first call.
pub fn system_fetch_start(
    purpose: SystemFetchPurpose,
    instance_id: &str,
    fetch_id: &str,
    planned: &[(&str, &str)],
) -> NewEvent {
    let planned: Vec<Value> = planned
        .iter()
        .map(|(method, path)| json!({ "method": method, "path": path }))
        .collect();
    event(
        &instance_ctx(instance_id),
        EventType::SYSTEM_FETCH,
        json!({
            "purpose": purpose.as_str(),
            "instance_id": instance_id,
            "fetch_id": fetch_id,
            "phase": "start",
            "planned": planned,
        }),
    )
}

/// `SYSTEM_FETCH {purpose, instance_id, fetch_id, phase: result, method, path, status,
/// response | outcome}`, one per call.
pub fn system_fetch_result(
    purpose: SystemFetchPurpose,
    instance_id: &str,
    fetch_id: &str,
    method: &str,
    path: &str,
    record: &FetchRecord<'_>,
) -> NewEvent {
    let mut m = Map::new();
    m.insert("purpose".into(), purpose.as_str().into());
    m.insert("instance_id".into(), instance_id.into());
    m.insert("fetch_id".into(), fetch_id.into());
    m.insert("phase".into(), "result".into());
    m.insert("method".into(), method.into());
    m.insert("path".into(), path.into());
    fetch_record_fields(&mut m, record);
    event(
        &instance_ctx(instance_id),
        EventType::SYSTEM_FETCH,
        Value::Object(m),
    )
}

/// `INSTANCE_STATE_CHANGED {state, ..details}` (`needs_token`,
/// `identity_header_missing|identity_header_mismatch`, `user_renamed` with
/// `{old, new, user_key}`, …). `state` wins over a `details` key of the same name.
pub fn instance_state_changed(
    instance_id: &str,
    state: &str,
    details: &Map<String, Value>,
) -> NewEvent {
    let mut m = details.clone();
    m.insert("state".into(), state.into());
    event(
        &instance_ctx(instance_id),
        EventType::INSTANCE_STATE_CHANGED,
        Value::Object(m),
    )
}

/// What happened to a stored PAT (§7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialChange {
    Added,
    Replaced,
    Deleted,
    /// Corrective record: the keychain write that followed an `added`/`replaced` record failed,
    /// so the token did not change (the keys are those of that record).
    StoreFailed,
    /// Corrective record: the keychain delete that followed a `deleted` record failed, so the
    /// token is still stored (the keys are those of that record).
    DeleteFailed,
}

impl CredentialChange {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Replaced => "replaced",
            Self::Deleted => "deleted",
            Self::StoreFailed => "store_failed",
            Self::DeleteFailed => "delete_failed",
        }
    }
}

/// `CREDENTIAL_CHANGED {change: added|replaced|deleted|store_failed|delete_failed, old_user_key, new_user_key, expires_at}`
/// for a PAT (§7.1); never the secret. `expires_at` is `YYYY-MM-DD`. The keys are data; the
/// caller names the operation (a deletion may not know the old key).
pub fn credential_changed(
    instance_id: &str,
    change: CredentialChange,
    old_user_key: Option<&str>,
    new_user_key: Option<&str>,
    expires_at: Option<&str>,
) -> NewEvent {
    event(
        &instance_ctx(instance_id),
        EventType::CREDENTIAL_CHANGED,
        json!({
            "change": change.as_str(),
            "old_user_key": old_user_key,
            "new_user_key": new_user_key,
            "expires_at": expires_at,
        }),
    )
}

/// `CONFIG_CHANGED.source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    App,
    File,
}

impl ConfigSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::File => "file",
        }
    }
}

/// `CONFIG_CHANGED {source, key, old, new, applied}` for the keys `core` owns (effective
/// proxies, instances, "Prepare for removal"). Policy keys (`instance.<id>.origin` and the
/// like) change only through `apply_setting`; the store accepts them here only as
/// `{source: file, applied: false}` (Q5).
pub fn config_changed(
    source: ConfigSource,
    key: &str,
    old: &Value,
    new: &Value,
    applied: bool,
) -> NewEvent {
    event(
        &EventCtx::default(),
        EventType::CONFIG_CHANGED,
        json!({
            "source": source.as_str(),
            "key": key,
            "old": old,
            "new": new,
            "applied": applied,
        }),
    )
}

/// `APP_START {install_id, app_version, ..extra}` with `target` = `install_id` (§8.2). `extra`
/// carries the effective proxy per instance, `config_read_only`, and the app's fields
/// (PD-21: `tray_host`, `engine_version`, sandbox identity); it cannot override the first two.
pub fn app_start(install_id: &str, extra: &Map<String, Value>) -> NewEvent {
    let mut m = extra.clone();
    m.insert("install_id".into(), install_id.into());
    m.insert("app_version".into(), APP_VERSION.into());
    let ctx = EventCtx {
        target: Some(install_id.to_owned()),
        ..EventCtx::default()
    };
    event(&ctx, EventType::APP_START, Value::Object(m))
}

/// `APP_STOP.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppStopReason {
    Quit,
    OsShutdown,
    Installer,
}

impl AppStopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quit => "quit",
            Self::OsShutdown => "os_shutdown",
            Self::Installer => "installer",
        }
    }
}

/// `APP_STOP {reason: quit|os_shutdown|installer}`.
pub fn app_stop(reason: AppStopReason) -> NewEvent {
    event(
        &EventCtx::default(),
        EventType::APP_STOP,
        json!({ "reason": reason.as_str() }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_are_text_or_base64() {
        assert_eq!(body_json(b"{\"a\":1}"), json!({ "text": "{\"a\":1}" }));
        assert_eq!(body_json(&[0xff, 0x00]), json!({ "b64": "/wA=" }));
        assert_eq!(body_json(b""), json!({ "text": "" }));
        // Cut inside a multibyte character: the valid prefix stays text.
        assert_eq!(
            body_json("Müller".as_bytes().split_at(2).0),
            json!({ "text": "M", "tail_b64": "ww==" })
        );
        // Control-heavy text is longer escaped than as base64.
        assert_eq!(body_json(&[1, 2, 3]), json!({ "b64": "AQID" }));
    }

    fn jcs_len(v: &Value) -> u64 {
        atlas_duck_ipc::jcs::to_jcs_vec(v).map_or(u64::MAX, |b| b.len() as u64)
    }

    proptest::proptest! {
        /// Lossless, within the bound, and the escape estimate equals what JCS writes.
        #[test]
        fn body_json_roundtrips_within_bound(
            bytes in proptest::collection::vec(
                proptest::prop_oneof![
                    proptest::prelude::any::<u8>(),
                    proptest::sample::select(vec![b'"', b'\\', b'\n', 0x01, b'a', 0xC3, 0xBC]),
                ],
                0..300,
            )
        ) {
            let v = body_json(&bytes);
            proptest::prop_assert_eq!(body_from_json(&v), Some(bytes.clone()));
            proptest::prop_assert!(jcs_len(&v) <= body_json_bound(bytes.len() as u64));
            if let Ok(s) = std::str::from_utf8(&bytes) {
                proptest::prop_assert_eq!(jcs_len(&json!(s)), jcs_escaped_len(s) + 2);
            }
        }
    }

    /// Type-level: no builder has a PAT parameter, so none can put our token into a record
    /// (the Task 29 capture test checks the bytes).
    #[test]
    fn no_builder_takes_a_pat() {
        let needle = concat!("Pat", "Secret");
        let code = include_str!("payloads.rs")
            .lines()
            .take_while(|l| !l.starts_with("#[cfg(test)]"))
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!code.contains(needle));
        assert!(!code.contains("SecretString"));
    }

    #[test]
    fn with_batch_sets_flag_and_id() {
        let ev = with_batch(read_denied(&EventCtx::default(), None), "bat_1");
        assert!(ev.flags.contains(EventFlags::BATCH));
        assert_eq!(ev.payload["batch_id"], "bat_1");
        assert_eq!(ev.decision, Some(DecisionColumn::Deny));
    }

    #[test]
    fn delivered_names_the_awaiting_connection() {
        let hello = Hello {
            build_id: "b".into(),
            client_kind: ClientKind::Mcp,
            agent_name: Some("waiter\u{202E}".into()),
            agent_name_source: AgentNameSource::McpClientInfo,
            cwd_basename: "w".into(),
        };
        let conn = ConnectionMeta {
            connection_id: "conn_await".into(),
            peer: Default::default(),
        };
        let ctx = EventCtx {
            request_id: Some("req_1".into()),
            actor: Actor {
                agent_name: Some("submitter".into()),
                connection_id: Some("conn_submit".into()),
                os_user: Some("jdoe".into()),
                ..Actor::default()
            },
            ..EventCtx::default()
        };
        let ev = delivered(&ctx, &hello, &conn, &[0; 32]);
        assert_eq!(ev.actor.agent_name.as_deref(), Some("waiter"));
        assert_eq!(ev.actor.connection_id.as_deref(), Some("conn_await"));
        assert_eq!(ev.actor.client_kind.as_deref(), Some("mcp"));
        assert_eq!(ev.actor.os_user.as_deref(), Some("jdoe"));
        assert_eq!(ev.payload["agent_name"], "waiter\u{202E}");
        assert_eq!(ev.payload["agent_name_source"], "mcp-clientInfo");
    }

    #[test]
    fn app_start_fields_cannot_be_overridden() {
        let mut extra = Map::new();
        extra.insert("install_id".into(), "spoofed".into());
        extra.insert("tray_host".into(), "present".into());
        let ev = app_start("inst_a", &extra);
        assert_eq!(ev.target.as_deref(), Some("inst_a"));
        assert_eq!(ev.payload["install_id"], "inst_a");
        assert_eq!(ev.payload["app_version"], APP_VERSION);
        assert_eq!(ev.payload["tray_host"], "present");
    }
}
