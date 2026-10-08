//! Open integrity incidents (§8.7 "Integrity incidents persist"): the seqs of `VERIFY` rows
//! flagged `integrity_incident` without a later `INTEGRITY_ACK` naming them. Loaded once when
//! the writer opens the store, then kept by the writer: a `VERIFY` with the flag opens one,
//! an `INTEGRITY_ACK {verify_seq}` closes it (one ack acknowledges the whole run).

use std::collections::BTreeSet;

use rusqlite::Connection;
use serde_json::Value;

use crate::crypto::Kek;
use crate::encoding::{FIELD_LIST, RowFields};
use crate::error::OpenError;
use crate::types::EventFlags;
use crate::verify::Deks;

fn sqlite(e: rusqlite::Error) -> OpenError {
    OpenError::Sqlite(e.to_string())
}

/// Scans the plaintext `event_type`/`flags` columns and decrypts only the (small)
/// `INTEGRITY_ACK` payloads. An ack that does not decrypt, does not parse or names a later
/// seq closes nothing (fail closed: the incident stays open).
pub(crate) fn load_open(conn: &Connection, kek: &Kek) -> Result<BTreeSet<u64>, OpenError> {
    let mut open = BTreeSet::new();
    {
        let mut stmt = conn
            .prepare("SELECT seq, flags FROM events WHERE event_type = 'VERIFY' ORDER BY seq")
            .map_err(sqlite)?;
        let mut rows = stmt.query([]).map_err(sqlite)?;
        while let Some(r) = rows.next().map_err(sqlite)? {
            let (Ok(seq), Ok(flags)) = (r.get::<_, i64>(0), r.get::<_, i64>(1)) else {
                continue;
            };
            let flagged = u64::try_from(flags)
                .is_ok_and(|f| EventFlags::from_bits(f).contains(EventFlags::INTEGRITY_INCIDENT));
            if let (true, Ok(seq)) = (flagged, u64::try_from(seq)) {
                open.insert(seq);
            }
        }
    }
    if open.is_empty() {
        return Ok(open);
    }
    let mut deks = Deks::new(kek);
    let sql = format!(
        "SELECT {} FROM events WHERE event_type = 'INTEGRITY_ACK' ORDER BY seq",
        FIELD_LIST.join(", ")
    );
    let mut stmt = conn.prepare(&sql).map_err(sqlite)?;
    let mut rows = stmt.query([]).map_err(sqlite)?;
    while let Some(r) = rows.next().map_err(sqlite)? {
        let Ok(f) = RowFields::from_row(r) else {
            continue;
        };
        let Ok(Some(payload)) = deks.decrypt_json(conn, &f).map_err(sqlite)? else {
            continue;
        };
        if let Some(v) = payload.get("verify_seq").and_then(Value::as_u64)
            && v < f.seq
        {
            open.remove(&v);
        }
    }
    Ok(open)
}
