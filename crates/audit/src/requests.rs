//! The request-level API M3 consumes (C.3, T17): the §8.3 terminal predicate, the plaintext
//! header queries and the §11.3 crash reconciliation.
//!
//! Header queries read plaintext columns only (P6). Payloads are opened for exactly the rows a
//! decision needs: a `SCRIPT_FAILED` whose terminal status depends on its flags, and the
//! `WRITE_APPROVED` of a write that is reconciled to `WRITE_OUTCOME_UNKNOWN`.

use std::time::Duration;

use rusqlite::{Connection, Row};
use serde_json::{Value, json};

use crate::encoding::os_path_from_bytes;
use crate::error::AuditError;
use crate::store::Store;
use crate::types::{
    Actor, DecisionColumn, EventFlags, EventHeader, EventType, NewEvent, UtcInstant,
};

/// `recent_headers` looks back at most this far (C.3).
pub const RECENT_HEADERS_CAP: Duration = Duration::from_secs(24 * 3600);

/// The two fields of a `SCRIPT_FAILED` payload that decide whether it is terminal (§8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptFailedFlags {
    pub direct: bool,
    pub reason: String,
}

/// The §8.3 verdict by type alone; `None` for `SCRIPT_FAILED`, which needs its flags.
fn terminal_by_type(t: EventType) -> Option<bool> {
    use EventType as T;
    match t {
        T::SCRIPT_FAILED => None,
        T::REQUEST_REJECTED
        | T::REQUEST_FAILED
        | T::READ_RELEASED
        | T::READ_DENIED
        | T::READ_FAILED
        | T::WRITE_EXECUTED
        | T::WRITE_FAILED
        | T::WRITE_OUTCOME_UNKNOWN
        | T::WRITE_DENIED
        | T::SCRIPT_RELEASED
        | T::SCRIPT_DENIED
        | T::SCRIPT_DRY_RUN
        | T::EXPIRED
        | T::CANCELLED
        | T::ABANDONED => Some(true),
        _ => Some(false),
    }
}

fn flags_terminal(f: &ScriptFailedFlags) -> bool {
    f.direct || f.reason == "audit_failure"
}

/// Whether this event ends its request (§8.3). `SCRIPT_FAILED` is terminal iff `direct` or
/// `reason = audit_failure`; without `script_failed` flags it is `false` (the caller must
/// decrypt, see [`Store::script_failed_flags`]). The flags are ignored for every other type.
pub fn is_terminal(h: &EventHeader, script_failed: Option<&ScriptFailedFlags>) -> bool {
    terminal_by_type(h.event_type).unwrap_or_else(|| script_failed.is_some_and(flags_terminal))
}

/// A write that §11.3 reconciled to `WRITE_OUTCOME_UNKNOWN`: what the startup notice lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciledWrite {
    pub request_id: String,
    pub op_id: Option<String>,
    pub instance_id: Option<String>,
    pub target: Option<String>,
    pub request_index: u64,
}

/// What `reconcile_after_crash` appended, in append order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    pub outcome_unknown: Vec<ReconciledWrite>,
    pub abandoned: Vec<String>,
}

const HEADER_COLUMNS: &str = "seq, ts_utc, epoch, chain_id, event_type, request_id, op_id, \
     op_class, instance_id, target, decision, flags, agent_name, agent_name_source, \
     client_kind, connection_id, peer_pid, peer_exe, peer_origin_exe, os_user, \
     atlassian_user, atlassian_user_key, payload_len, key_id";

fn io(e: rusqlite::Error) -> AuditError {
    AuditError::Io(e.to_string())
}

fn db_u64(row: &Row<'_>, i: usize) -> Result<u64, AuditError> {
    let v: i64 = row.get(i).map_err(io)?;
    u64::try_from(v).map_err(|_| AuditError::Invalid("events integer column is negative"))
}

fn db_path(row: &Row<'_>, i: usize) -> Result<Option<std::path::PathBuf>, AuditError> {
    let b: Option<Vec<u8>> = row.get(i).map_err(io)?;
    b.as_deref().map(os_path_from_bytes).transpose()
}

fn decision_of(s: &str) -> Option<DecisionColumn> {
    use DecisionColumn as D;
    [
        D::Approve,
        D::ApproveEdited,
        D::Release,
        D::ReleaseRedacted,
        D::Deny,
        D::Expire,
        D::Cancel,
        D::Reject,
    ]
    .into_iter()
    .find(|d| d.as_str() == s)
}

fn header_from_row(row: &Row<'_>) -> Result<EventHeader, AuditError> {
    let text = |i: usize| -> Result<Option<String>, AuditError> { row.get(i).map_err(io) };
    let event_type = text(4)?
        .as_deref()
        .and_then(EventType::parse)
        .ok_or(AuditError::Invalid("events row has an unknown event_type"))?;
    let decision = match text(10)? {
        None => None,
        Some(d) => {
            Some(decision_of(&d).ok_or(AuditError::Invalid("events row has an unknown decision"))?)
        }
    };
    let req = |v: Option<String>, what: &'static str| v.ok_or(AuditError::Invalid(what));
    Ok(EventHeader {
        seq: db_u64(row, 0)?,
        ts_utc: req(text(1)?, "events ts_utc is NULL")?,
        epoch: text(2)?,
        chain_id: req(text(3)?, "events chain_id is NULL")?,
        event_type,
        request_id: text(5)?,
        op_id: text(6)?,
        op_class: text(7)?,
        instance_id: text(8)?,
        target: text(9)?,
        decision,
        flags: EventFlags::from_bits(db_u64(row, 11)?),
        actor: Actor {
            agent_name: text(12)?,
            agent_name_source: text(13)?,
            client_kind: text(14)?,
            connection_id: text(15)?,
            peer_pid: row
                .get::<_, Option<i64>>(16)
                .map_err(io)?
                .map(|p| {
                    u32::try_from(p)
                        .map_err(|_| AuditError::Invalid("events peer_pid is not a u32"))
                })
                .transpose()?,
            peer_exe: db_path(row, 17)?,
            peer_origin_exe: db_path(row, 18)?,
            os_user: text(19)?,
            atlassian_user: text(20)?,
            atlassian_user_key: text(21)?,
        },
        payload_len: db_u64(row, 22)?,
        key_id: db_u64(row, 23)?,
    })
}

fn query_headers(
    conn: &Connection,
    filter: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<EventHeader>, AuditError> {
    let sql = format!("SELECT {HEADER_COLUMNS} FROM events WHERE {filter} ORDER BY seq");
    let mut stmt = conn.prepare_cached(&sql).map_err(io)?;
    let mut rows = stmt.query(params).map_err(io)?;
    let mut out = Vec::new();
    while let Some(r) = rows.next().map_err(io)? {
        out.push(header_from_row(r)?);
    }
    Ok(out)
}

/// One request's retained events, in seq order, that §11.3 still has to judge.
struct Group {
    request_id: String,
    events: Vec<(u64, EventType)>,
}

impl Group {
    fn first_seq(&self) -> u64 {
        self.events.first().map_or(0, |e| e.0)
    }

    fn latest(&self, t: EventType) -> Option<u64> {
        self.events.iter().rev().find(|e| e.1 == t).map(|e| e.0)
    }

    /// Terminal by an event whose type alone decides it. A write outcome counts only after
    /// the latest `WRITE_APPROVED` (§8.3: the outcome of the request that approval named); an
    /// older one does not end the request, which fails closed to `WRITE_OUTCOME_UNKNOWN`.
    fn terminal_by_type(&self) -> bool {
        use EventType as T;
        let approved = self.latest(T::WRITE_APPROVED);
        self.events.iter().any(|&(seq, t)| match t {
            T::WRITE_EXECUTED | T::WRITE_FAILED | T::WRITE_OUTCOME_UNKNOWN => {
                approved.is_none_or(|a| seq > a)
            }
            _ => terminal_by_type(t) == Some(true),
        })
    }

    /// §11.3 step 1: the latest `WRITE_APPROVED` is not followed by `WRITE_STALE`,
    /// `WRITE_EDITED` or `WRITE_DENIED`.
    fn pending_approval(&self) -> Option<u64> {
        let approved = self.latest(EventType::WRITE_APPROVED)?;
        let returned = [
            EventType::WRITE_STALE,
            EventType::WRITE_EDITED,
            EventType::WRITE_DENIED,
        ]
        .iter()
        .filter_map(|t| self.latest(*t))
        .any(|s| s > approved);
        (!returned).then_some(approved)
    }
}

/// `requests[0].index` of a `WRITE_APPROVED` payload (every v1 write is one request); 0 when
/// the payload has no (or an empty) `requests`.
fn request_index(payload: &Value) -> Result<u64, AuditError> {
    let Some(requests) = payload.get("requests") else {
        return Ok(0);
    };
    let items = requests.as_array().ok_or(AuditError::Invalid(
        "WRITE_APPROVED requests is not an array",
    ))?;
    let Some(first) = items.first() else {
        return Ok(0);
    };
    first
        .get("index")
        .and_then(Value::as_u64)
        .ok_or(AuditError::Invalid(
            "WRITE_APPROVED requests[0].index is not an integer",
        ))
}

fn system_event(t: EventType, request_id: &str, payload: Value) -> NewEvent {
    NewEvent {
        event_type: t,
        request_id: Some(request_id.to_string()),
        op_id: None,
        op_class: None,
        instance_id: None,
        target: None,
        actor: Actor::default(),
        decision: None,
        flags: EventFlags::default(),
        payload,
    }
}

impl Store {
    /// The plaintext columns of every retained event of `request_id`, in seq order; never
    /// decrypts (C.3, P6).
    pub fn headers_for_request(&self, request_id: &str) -> Result<Vec<EventHeader>, AuditError> {
        self.with_reader(|c| query_headers(c, "request_id = ?1", [request_id]))
    }

    /// The plaintext columns of every retained event with `ts_utc >= now - since` (`since` is
    /// capped at 24 h), in seq order; never decrypts (C.3, P6).
    pub fn recent_headers(&self, since: Duration) -> Result<Vec<EventHeader>, AuditError> {
        let since_ms = i64::try_from(since.min(RECENT_HEADERS_CAP).as_millis())
            .unwrap_or(RECENT_HEADERS_CAP.as_millis() as i64);
        let cutoff = UtcInstant(self.now_utc().0.saturating_sub(since_ms)).to_rfc3339_ms();
        // `ts_utc` is fixed-width UTC text, so text order is time order.
        self.with_reader(|c| query_headers(c, "ts_utc >= ?1", [cutoff.as_str()]))
    }

    fn header_at(&self, seq: u64) -> Result<EventHeader, AuditError> {
        let seq_i = i64::try_from(seq).map_err(|_| AuditError::NotFound { seq })?;
        self.with_reader(|c| query_headers(c, "seq = ?1", [seq_i]))?
            .pop()
            .ok_or(AuditError::NotFound { seq })
    }

    /// Opens the `SCRIPT_FAILED` row `seq` (and only that row) for its `direct` and `reason`.
    /// `Invalid` if the row is another event type or the payload lacks either field.
    pub fn script_failed_flags(&self, seq: u64) -> Result<ScriptFailedFlags, AuditError> {
        if self.header_at(seq)?.event_type != EventType::SCRIPT_FAILED {
            return Err(AuditError::Invalid("record is not a SCRIPT_FAILED"));
        }
        let plain = self.read_payload(seq)?;
        let p: Value = serde_json::from_slice(&plain)
            .map_err(|_| AuditError::Invalid("SCRIPT_FAILED payload is not JSON"))?;
        let direct = p
            .get("direct")
            .and_then(Value::as_bool)
            .ok_or(AuditError::Invalid(
                "SCRIPT_FAILED payload has no direct flag",
            ))?;
        let reason = p
            .get("reason")
            .and_then(Value::as_str)
            .ok_or(AuditError::Invalid("SCRIPT_FAILED payload has no reason"))?;
        Ok(ScriptFailedFlags {
            direct,
            reason: reason.to_string(),
        })
    }

    /// §11.3, run by M3 at startup before `APP_START`: every request id with no terminal
    /// event is closed, in one `append_batch`. Writes whose latest approval was not returned
    /// to the queue get `WRITE_OUTCOME_UNKNOWN {request_index, reason: "crash"}` (first, with
    /// `op_id`/`op_class`/`instance_id`/`target` of that approval), then every other
    /// non-terminal request gets `ABANDONED {reason: "crash"}`. Both lists are in order of the
    /// requests' first record. Idempotent: the records it writes are terminal.
    ///
    /// Fails closed: a `SCRIPT_FAILED` or `WRITE_APPROVED` that cannot be read or has an
    /// unexpected payload shape is an `Err` and nothing is appended.
    pub fn reconcile_after_crash(&self) -> Result<ReconcileReport, AuditError> {
        // One indexed scan of (request_id, seq, event_type); only requests that no
        // type-decided terminal event closes are kept.
        let mut candidates = self.with_reader(|conn| {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT request_id, seq, event_type FROM events \
                     WHERE request_id IS NOT NULL ORDER BY request_id, seq",
                )
                .map_err(io)?;
            let mut rows = stmt.query([]).map_err(io)?;
            let mut out: Vec<Group> = Vec::new();
            let mut cur: Option<Group> = None;
            while let Some(r) = rows.next().map_err(io)? {
                let rid: String = r.get(0).map_err(io)?;
                let seq = db_u64(r, 1)?;
                let t: String = r.get(2).map_err(io)?;
                let t = EventType::parse(&t)
                    .ok_or(AuditError::Invalid("events row has an unknown event_type"))?;
                if cur.as_ref().is_none_or(|g| g.request_id != rid) {
                    out.extend(cur.take().filter(|g| !g.terminal_by_type()));
                    cur = Some(Group {
                        request_id: rid,
                        events: Vec::new(),
                    });
                }
                if let Some(g) = cur.as_mut() {
                    g.events.push((seq, t));
                }
            }
            out.extend(cur.take().filter(|g| !g.terminal_by_type()));
            Ok(out)
        })?;

        // Only now (the reader lock is released) decrypt: a `SCRIPT_FAILED` can still end its
        // request by its flags.
        let mut open = Vec::new();
        for g in candidates.drain(..) {
            let mut closed = false;
            for &(seq, t) in &g.events {
                if t == EventType::SCRIPT_FAILED && flags_terminal(&self.script_failed_flags(seq)?)
                {
                    closed = true;
                    break;
                }
            }
            if !closed {
                open.push(g);
            }
        }
        open.sort_by_key(Group::first_seq);

        let mut report = ReconcileReport::default();
        let mut evs = Vec::new();
        let mut abandoned = Vec::new();
        for g in &open {
            match g.pending_approval() {
                Some(approved) => {
                    let h = self.header_at(approved)?;
                    let plain = self.read_payload(approved)?;
                    let p: Value = serde_json::from_slice(&plain)
                        .map_err(|_| AuditError::Invalid("WRITE_APPROVED payload is not JSON"))?;
                    let request_index = request_index(&p)?;
                    let mut e = system_event(
                        EventType::WRITE_OUTCOME_UNKNOWN,
                        &g.request_id,
                        json!({ "request_index": request_index, "reason": "crash" }),
                    );
                    e.op_id = h.op_id.clone();
                    e.op_class = h.op_class;
                    e.instance_id = h.instance_id.clone();
                    e.target = h.target.clone();
                    evs.push(e);
                    report.outcome_unknown.push(ReconciledWrite {
                        request_id: g.request_id.clone(),
                        op_id: h.op_id,
                        instance_id: h.instance_id,
                        target: h.target,
                        request_index,
                    });
                }
                None => abandoned.push(system_event(
                    EventType::ABANDONED,
                    &g.request_id,
                    json!({ "reason": "crash" }),
                )),
            }
        }
        report.abandoned = abandoned
            .iter()
            .filter_map(|e| e.request_id.clone())
            .collect();
        evs.extend(abandoned);
        self.append_batch(evs)?;
        Ok(report)
    }
}
