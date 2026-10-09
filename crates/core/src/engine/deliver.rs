//! `await` hands a terminal request over (§4.4, §5.1 inv. 1–2, PD-23).
//!
//! Every answer comes from the committed records, never from memory: a released read is the
//! `READ_RELEASED` payload decrypted for this delivery, its bytes checked against
//! `released_sha256` (inv. 2), within 1 h of the decision; later the request's true status with
//! `result_evicted` (exit 10; an outcome answer `{code, hint}` is fixed text and never
//! evicted). Each terminal envelope `await` returns is logged as `DELIVERED`
//! for the awaiting connection **before** it is handed over (inv. 1): if that append fails, the
//! agent gets `audit_failure` and no data. Pending and executing envelopes are never logged.

use std::collections::HashMap;
use std::sync::Arc;

use atlas_duck_audit::{EventHeader, EventType, UtcInstant};
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::proto::{ConnectionMeta, Hello};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::envelope::{self, OpenStatus, RecordStatus};
use super::{Engine, audit_failure_retryable, kind_of, status_at, terminal_of, terminal_payload};
use crate::audit_port::AuditPort;
use crate::lifecycle::model::Kind;
use crate::payloads::{self, EventCtx, body_from_json, sha256_hex};

/// §4.4: released data stays deliverable for 1 h after the decision.
pub const DELIVERY_WINDOW_MS: i64 = 3_600_000;

impl Engine {
    /// The `await` answer of a request the log knows, with its `DELIVERED` record (the caller
    /// checked it is not open in memory). `conn` must have said `hello`.
    pub async fn deliver(self: &Arc<Self>, request_id: &str, conn: &ConnectionMeta) -> Envelope {
        let Some(session) = self.session(&conn.connection_id) else {
            return envelope::protocol_error();
        };
        let aliases: HashMap<String, String> = self
            .instances()
            .list()
            .iter()
            .filter_map(|i| Some((i.id.clone()?, i.alias.clone())))
            .collect();
        let now = self.clock().now_utc();
        let (id, conn) = (request_id.to_owned(), conn.clone());
        self.blocking(move |p| {
            Ok(deliver_from_records(
                p,
                &id,
                &session.hello,
                &conn,
                now,
                &aliases,
            ))
        })
        .await
        .unwrap_or_else(|_| envelope::audit_unreadable())
    }
}

/// What one delivery hands over and the hash its `DELIVERED` names (PD-23).
struct Handoff {
    env: Envelope,
    payload_sha256: [u8; 32],
}

/// PD-23: SHA-256 of the JCS bytes of the envelope's `error` object (`null` when none).
fn error_hash(env: &Envelope) -> [u8; 32] {
    let v = env
        .error
        .as_ref()
        .and_then(|e| serde_json::to_value(e).ok())
        .unwrap_or(Value::Null);
    let bytes = atlas_duck_ipc::jcs::to_jcs_vec(&v).unwrap_or_else(|_| b"null".to_vec());
    Sha256::digest(&bytes).into()
}

fn with_error_hash(env: Envelope) -> Handoff {
    Handoff {
        payload_sha256: error_hash(&env),
        env,
    }
}

fn deliver_from_records(
    p: &dyn AuditPort,
    request_id: &str,
    hello: &Hello,
    conn: &ConnectionMeta,
    now: UtcInstant,
    aliases: &HashMap<String, String>,
) -> Envelope {
    let Ok(headers) = p.headers_for_request(request_id) else {
        return envelope::audit_unreadable();
    };
    let Some(start) = headers.first() else {
        return envelope::unknown_request();
    };
    // One scan for the terminal record and one decrypt of its payload (the hot path of `await`).
    let terminal = terminal_of(p, &headers);
    let payload = terminal_payload(p, terminal);
    let rs = RecordStatus {
        instance: start
            .instance_id
            .as_ref()
            .and_then(|i| aliases.get(i).cloned()),
        ..status_at(start, terminal, payload.as_ref())
    };
    if OpenStatus::of(rs.status).is_some() {
        return envelope::await_envelope(&rs);
    }
    let kind = start
        .op_id
        .as_deref()
        .and_then(atlas_duck_registry::get)
        .map_or(Kind::Read, kind_of);
    let handoff = match terminal {
        Some(t) if t.event_type == EventType::READ_RELEASED => {
            released(&headers, t, payload, &rs, now, kind)
        }
        _ => with_error_hash(envelope::await_envelope(&rs)),
    };
    // §5.1 inv. 1: the hand-off happens only after its `DELIVERED` committed.
    let ctx = EventCtx {
        request_id: start.request_id.clone(),
        op_id: start.op_id.clone(),
        op_class: start.op_class.clone(),
        instance_id: start.instance_id.clone(),
        target: start.target.clone(),
        actor: Default::default(),
    };
    match p.append(payloads::delivered(
        &ctx,
        hello,
        conn,
        &handoff.payload_sha256,
    )) {
        Ok(_) => handoff.env,
        // Nothing handed over: `failed`, `audit_failure` (exit 1), whatever the request's status.
        Err(_) => envelope::record_failure(
            &RecordStatus {
                status: Status::Failed,
                ..rs
            },
            ErrorCode::AuditFailure,
            audit_failure_retryable(kind),
            envelope::MSG_AUDIT_FAILURE,
        ),
    }
}

/// A `READ_RELEASED` hand-off: the outcome-only answer, or the released bytes (checked against
/// their committed hash) as data or as upstream-error details.
fn released(
    headers: &[EventHeader],
    t: &EventHeader,
    payload: Option<Value>,
    rs: &RecordStatus,
    now: UtcInstant,
    kind: Kind,
) -> Handoff {
    // An outcome item: `{code, hint}`, fixed text and no data (§5.2 step 6), so it is answered
    // whenever asked, like a deny reason (ruling 3: never evicted).
    if payload.as_ref().is_some_and(|p| p.get("code").is_some()) {
        return with_error_hash(envelope::await_envelope(rs));
    }
    // Released data and released upstream-error details: 1 h after the decision (§4.4).
    let decided = UtcInstant::parse_rfc3339_ms(&t.ts_utc);
    if decided.is_none_or(|d| now.0.saturating_sub(d.0) > DELIVERY_WINDOW_MS) {
        return with_error_hash(envelope::result_evicted(rs, audit_failure_retryable(kind)));
    }
    let Some(payload) = payload else {
        return with_error_hash(envelope::delivery_internal(rs));
    };
    let bytes = payload.get("released").and_then(body_from_json);
    let expected = payload.get("released_sha256").and_then(Value::as_str);
    let (Some(bytes), Some(expected)) = (bytes, expected) else {
        return with_error_hash(envelope::delivery_internal(rs));
    };
    // Inv. 2: only the bytes the release committed, byte for byte.
    if sha256_hex(&bytes) != expected {
        return with_error_hash(envelope::delivery_internal(rs));
    }
    let (Ok(value), Ok(sha)) = (
        serde_json::from_slice::<Value>(&bytes),
        hex::decode(expected).map(<[u8; 32]>::try_from),
    ) else {
        return with_error_hash(envelope::delivery_internal(rs));
    };
    let Ok(payload_sha256) = sha else {
        return with_error_hash(envelope::delivery_internal(rs));
    };
    drop(bytes);
    let redacted = payload
        .get("redaction_ops")
        .and_then(Value::as_array)
        .is_some_and(|ops| !ops.is_empty());
    let mut meta = payload
        .get("meta")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let fetched_at = headers
        .iter()
        .find(|h| h.event_type == EventType::READ_FETCHED)
        .map(|h| Value::String(h.ts_utc.clone()))
        .unwrap_or(Value::Null);
    meta.insert("fetched_at".into(), fetched_at);
    meta.insert("released_at".into(), Value::String(t.ts_utc.clone()));
    let env = match payload.get("item").and_then(Value::as_str) {
        Some("upstream_error") => match value {
            Value::Object(details) => {
                envelope::released_upstream_error(rs, details, redacted, Value::Object(meta))
            }
            _ => return with_error_hash(envelope::delivery_internal(rs)),
        },
        _ => envelope::released_data(rs, value, redacted, Value::Object(meta)),
    };
    Handoff {
        env,
        payload_sha256,
    }
}
