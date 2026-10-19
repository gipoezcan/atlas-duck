//! Audit window read APIs (T10, §8.10): filtered keyset pages over the plaintext columns, a
//! request's trail with its delivery summary, and paged decrypted payloads.
//!
//! A query reads plaintext columns only (P6, L38: there is no payload search). Payloads are
//! opened for exactly two purposes: the delivery comparison of [`Store::trail`] (the submit
//! record and each `DELIVERED` of one request) and [`Store::payload_view`] (one row, on the
//! user's request).

use std::path::PathBuf;

use rusqlite::params_from_iter;
use rusqlite::types::Value as Sql;
use serde::Deserialize;

use crate::error::AuditError;
use crate::requests::{HEADER_COLUMNS, header_from_row};
use crate::store::Store;
use crate::types::{
    AuditCursor, AuditFilter, AuditPage, AuditTrail, DeliverySummary, EventFlags, EventHeader,
    EventType, MAX_AUDIT_PAGE_ROWS, PAYLOAD_PAGE_BYTES, PayloadPage,
};

/// The longest text a filter field may carry (bytes); targets, ids and agent names are short.
pub const MAX_FILTER_TEXT_BYTES: usize = 2048;

fn io(e: rusqlite::Error) -> AuditError {
    AuditError::Io(e.to_string())
}

fn text(v: &Option<String>) -> Result<Option<&str>, AuditError> {
    match v.as_deref() {
        Some(s) if s.len() > MAX_FILTER_TEXT_BYTES => {
            Err(AuditError::Invalid("an audit filter text is too long"))
        }
        other => Ok(other),
    }
}

/// `WHERE` conditions and their positional values for `f` (all values are bound, never
/// spliced into the statement).
fn conditions(f: &AuditFilter) -> Result<(Vec<String>, Vec<Sql>), AuditError> {
    let mut sql: Vec<String> = Vec::new();
    let mut args = Vec::new();
    if let Some(t) = f.from_utc {
        // `ts_utc` is fixed-width UTC text, so text order is time order.
        sql.push("ts_utc >= ?".into());
        args.push(Sql::Text(t.to_rfc3339_ms()));
    }
    if let Some(t) = f.to_utc {
        sql.push("ts_utc <= ?".into());
        args.push(Sql::Text(t.to_rfc3339_ms()));
    }
    for (col, v) in [
        ("agent_name = ?", &f.agent_name),
        ("op_id = ?", &f.op_id),
        ("op_class = ?", &f.op_class),
        ("instance_id = ?", &f.instance_id),
    ] {
        if let Some(v) = text(v)? {
            sql.push(col.into());
            args.push(Sql::Text(v.to_owned()));
        }
    }
    if let Some(prefix) = text(&f.target)?.filter(|p| !p.is_empty()) {
        // Byte-exact prefix without LIKE (whose `%`, `_` and ASCII case folding would leak
        // into the match): the range bound keeps the comparison on the column's collation,
        // `substr` (characters) makes it a prefix.
        sql.push("target >= ?".into());
        args.push(Sql::Text(prefix.to_owned()));
        sql.push("substr(target, 1, ?) = ?".into());
        args.push(Sql::Integer(
            i64::try_from(prefix.chars().count()).unwrap_or(i64::MAX),
        ));
        args.push(Sql::Text(prefix.to_owned()));
    }
    if let Some(d) = f.decision {
        sql.push("decision = ?".into());
        args.push(Sql::Text(d.as_str().to_owned()));
    }
    if !f.flags_any.is_empty() {
        let mut mask = 0u64;
        for flag in &f.flags_any {
            let b = flag.bits();
            if b == 0 || !b.is_power_of_two() || b > EventFlags::INTEGRITY_INCIDENT.bits() {
                return Err(AuditError::Invalid(
                    "an audit filter flag is not a defined single flag bit",
                ));
            }
            mask |= b;
        }
        sql.push("(flags & ?) != 0".into());
        args.push(Sql::Integer(i64::try_from(mask).unwrap_or(i64::MAX)));
    }
    if !f.event_types.is_empty() {
        let mut types: Vec<EventType> = f.event_types.clone();
        types.sort();
        types.dedup();
        // One placeholder per distinct type; the statement text only ever holds `?` marks.
        sql.push(format!(
            "event_type IN ({})",
            vec!["?"; types.len()].join(",")
        ));
        args.extend(types.iter().map(|t| Sql::Text(t.as_str().to_owned())));
    }
    Ok((sql, args))
}

impl Store {
    /// One page of the retained events that match `f`, newest first (keyset on `seq`, so a
    /// row appended meanwhile never shifts a page). Plaintext columns only; never decrypts.
    /// `Invalid` for a `limit` outside 1..=[`MAX_AUDIT_PAGE_ROWS`], an over-long filter text or a
    /// `flags_any` entry that is not one defined flag bit.
    pub fn query(&self, f: &AuditFilter, page: AuditCursor) -> Result<AuditPage, AuditError> {
        if page.limit == 0 || page.limit > MAX_AUDIT_PAGE_ROWS {
            return Err(AuditError::Invalid("the audit page limit is out of range"));
        }
        let (mut sql, mut args) = conditions(f)?;
        if let Some(before) = page.before_seq {
            sql.push("seq < ?".into());
            args.push(Sql::Integer(i64::try_from(before).unwrap_or(i64::MAX)));
        }
        let filter = if sql.is_empty() {
            "1 = 1".to_owned()
        } else {
            sql.join(" AND ")
        };
        // One extra row tells whether another page follows.
        let limit = page.limit;
        args.push(Sql::Integer(i64::from(limit) + 1));
        let stmt =
            format!("SELECT {HEADER_COLUMNS} FROM events WHERE {filter} ORDER BY seq DESC LIMIT ?");
        let mut rows = self.with_reader(|conn| {
            let mut stmt = conn.prepare(&stmt).map_err(io)?;
            let mut it = stmt.query(params_from_iter(args.iter())).map_err(io)?;
            let mut out = Vec::new();
            while let Some(r) = it.next().map_err(io)? {
                out.push(header_from_row(r)?);
            }
            Ok(out)
        })?;
        let more = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let next = match (more, rows.last()) {
            (true, Some(last)) => Some(AuditCursor {
                before_seq: Some(last.seq),
                limit,
            }),
            _ => None,
        };
        let scanned = rows.len() as u64;
        Ok(AuditPage {
            rows,
            next,
            scanned,
        })
    }

    /// Every retained header of `request_id`, seq ascending (`DELIVERED` records included),
    /// and the delivery summary (§8.10). `to_other_peer` compares each `DELIVERED` with the
    /// submitter (the first `REQUEST_RECEIVED`) on the `peer_origin_exe` column and the origin
    /// start time, which only the payloads carry (`connection.peer_origin_start_time` of the
    /// submit, `peer_origin_start_time` of a `DELIVERED`): a peer whose origin is unknown on one
    /// side only counts as another peer. Without a retained submit record (pruned) the
    /// deliveries are compared with the first of them. Fails closed: a payload that does not
    /// decrypt, or that lacks the expected shape, fails the trail.
    pub fn trail(&self, request_id: &str) -> Result<AuditTrail, AuditError> {
        let headers = self.headers_for_request(request_id)?;
        let mut reference: Option<Peer> = headers
            .iter()
            .find(|h| h.event_type == EventType::REQUEST_RECEIVED)
            .map(|h| self.peer_of(h))
            .transpose()?;
        let mut count = 0u64;
        let mut to_other_peer = false;
        for h in headers
            .iter()
            .filter(|h| h.event_type == EventType::DELIVERED)
        {
            count += 1;
            let peer = self.peer_of(h)?;
            match &reference {
                Some(r) => to_other_peer |= *r != peer,
                None => reference = Some(peer),
            }
        }
        Ok(AuditTrail {
            headers,
            deliveries: DeliverySummary {
                count,
                to_other_peer,
            },
        })
    }

    fn peer_of(&self, h: &EventHeader) -> Result<Peer, AuditError> {
        let plain = self.read_payload(h.seq)?;
        let bad = AuditError::InvalidRecord {
            seq: h.seq,
            what: "payload has no readable peer origin start time",
        };
        let start = if h.event_type == EventType::REQUEST_RECEIVED {
            serde_json::from_slice::<SubmitPeer>(&plain)
                .map_err(|_| bad)?
                .connection
                .and_then(|c| c.peer_origin_start_time)
        } else {
            serde_json::from_slice::<DeliveredPeer>(&plain)
                .map_err(|_| bad)?
                .peer_origin_start_time
        };
        Ok(Peer {
            exe: h.actor.peer_origin_exe.clone(),
            start,
        })
    }

    /// Page `page` (0-based) of the decrypted payload of record `seq`: at most
    /// [`PAYLOAD_PAGE_BYTES`] of its JCS bytes, from [`Store::read_payload`] (so the digest is
    /// checked first). `Invalid` past the last page, `NotFound` for an unknown `seq`.
    pub fn payload_view(&self, seq: u64, page: u32) -> Result<PayloadPage, AuditError> {
        let plain = self.read_payload(seq)?;
        let total = plain.len();
        let page_count = u32::try_from(total.div_ceil(PAYLOAD_PAGE_BYTES).max(1))
            .map_err(|_| AuditError::Invalid("the payload has too many pages"))?;
        if page >= page_count {
            return Err(AuditError::Invalid("the payload page is out of range"));
        }
        let start = page as usize * PAYLOAD_PAGE_BYTES;
        let end = (start + PAYLOAD_PAGE_BYTES).min(total);
        Ok(PayloadPage {
            seq,
            page,
            page_count,
            total_bytes: total as u64,
            bytes: zeroize::Zeroizing::new(plain[start..end].to_vec()),
        })
    }
}

/// Who a record names as its origin peer: the `peer_origin_exe` column and the start time
/// from the payload (`None` where the peer chain had no origin).
#[derive(PartialEq, Eq)]
struct Peer {
    exe: Option<PathBuf>,
    start: Option<String>,
}

#[derive(Deserialize)]
struct SubmitPeer {
    connection: Option<ConnectionPeer>,
}

#[derive(Deserialize)]
struct ConnectionPeer {
    peer_origin_start_time: Option<String>,
}

#[derive(Deserialize)]
struct DeliveredPeer {
    peer_origin_start_time: Option<String>,
}
