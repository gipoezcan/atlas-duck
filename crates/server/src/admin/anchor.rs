//! `admin anchor verify` (SM-6.3, M13 T8): the server anchor chain is recomputed
//! (`anchor::verify`), then every user's most recently anchored head is looked up in that user's
//! own chain: the record at the anchored seq must exist, belong to the anchored chain and carry
//! the anchored hash. A chain shorter than its anchor (truncated), a different record there
//! (rewritten) or a missing store is a finding. Findings name the user and the seq, never a
//! payload; any finding makes the command fail (exit 1) with the report.

use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use super::{AdminCtx, Response};
use crate::anchor::{AnchorError, verify};
use crate::store::AnchorHead;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// `anchor_chain`, `store_missing`, `truncated`, `chain_mismatch`, `head_mismatch` or
    /// `chain_deleted_unrecorded`.
    pub kind: &'static str,
    pub username: Option<String>,
    pub seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub anchor_rows: u64,
    pub users_checked: usize,
    pub findings: Vec<Finding>,
}

/// What the user's chain holds at the anchored seq.
fn check_user(db: &Path, head: &AnchorHead) -> Option<&'static str> {
    if !db.is_file() {
        return Some("store_missing");
    }
    let Ok(c) =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
    else {
        return Some("store_missing");
    };
    let Ok(seq) = i64::try_from(head.head_seq) else {
        return Some("truncated");
    };
    let row: Result<(String, Vec<u8>), _> = c.query_row(
        "SELECT chain_id, record_hash FROM events WHERE seq = ?1",
        [seq],
        |r| Ok((r.get(0)?, r.get(1)?)),
    );
    match row {
        Err(rusqlite::Error::QueryReturnedNoRows) => Some("truncated"),
        Err(_) => Some("store_missing"),
        Ok((chain, _)) if chain != head.chain_id => Some("chain_mismatch"),
        Ok((_, hash)) if hash.as_slice() != head.record_hash.as_slice() => Some("head_mismatch"),
        Ok(_) => None,
    }
}

pub fn run(ctx: &AdminCtx) -> Result<VerifyReport, &'static str> {
    let store = ctx.store.as_ref();
    let mut findings = Vec::new();
    let anchor_rows = match verify(store) {
        Ok(r) => r.rows,
        Err(e) => {
            let seq = match e {
                AnchorError::BrokenLink { seq }
                | AnchorError::BadHash { seq }
                | AnchorError::Gap { seq }
                | AnchorError::LeafMismatch { seq } => Some(seq),
                AnchorError::Store(_) => None,
            };
            findings.push(Finding {
                kind: "anchor_chain",
                username: None,
                seq,
            });
            0
        }
    };
    let users = store.users_all().map_err(|_| "store/unavailable")?;
    let heads = store
        .anchor_latest_heads()
        .map_err(|_| "store/unavailable")?;
    let data = ctx.registry.deps().data_dir.clone();
    let mut checked = 0;
    // M5: a deleted chain must be explained by a CHAIN_DELETED row naming the user.
    let deleted_rows: std::collections::HashSet<String> = store
        .anchor_all()
        .map_err(|_| "store/unavailable")?
        .into_iter()
        .filter(|r| r.kind == crate::anchor::KIND_CHAIN_DELETED)
        .filter_map(|r| serde_json::from_slice::<Value>(&r.body_jcs).ok())
        .filter_map(|v| v["user_id"].as_str().map(str::to_owned))
        .collect();
    for (u, s) in &users {
        if s.chain_deleted_at.is_some() {
            if !deleted_rows.contains(&u.user_id) {
                findings.push(Finding {
                    kind: "chain_deleted_unrecorded",
                    username: Some(u.username.clone()),
                    seq: None,
                });
            }
            continue;
        }
        let Some(head) = heads.iter().find(|h| h.user_id == u.user_id) else {
            continue; // never anchored: no store was ever opened
        };
        checked += 1;
        let db = crate::users::user_dir(&data, &u.user_id).join(atlas_duck_audit::DB_FILE);
        if let Some(kind) = check_user(&db, head) {
            findings.push(Finding {
                kind,
                username: Some(u.username.clone()),
                seq: Some(head.head_seq),
            });
        }
    }
    Ok(VerifyReport {
        ok: findings.is_empty(),
        anchor_rows,
        users_checked: checked,
        findings,
    })
}

/// `admin anchor verify`: a report with findings is a failure (`anchor/verify_failed`).
pub fn admin(ctx: &AdminCtx) -> Response {
    match run(ctx) {
        Err(code) => Response::err(code),
        Ok(report) => {
            let data = serde_json::to_value(&report).unwrap_or(Value::Null);
            if report.ok {
                Response::ok(data)
            } else {
                Response::err_with("anchor/verify_failed", data)
            }
        }
    }
}
