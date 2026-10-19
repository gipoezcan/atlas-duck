//! Audit window query benchmark and the schema v2 gate (M10 T3, PD-158, §8.10, §8.13).
//!
//! `Store::query` filters the plaintext columns of `events`; only `seq` is indexed for those
//! filters, so a filter that matches little scans. The per-call row budget
//! ([`QUERY_ROW_BUDGET`]) bounds one call; this benchmark measures what a call costs on a
//! 1 000 000-row store, per filter kind, and what following the continuation cursors to the end
//! costs. PD-158's gate is the CI runner's number: every call (the first page included) of every
//! filter kind must take at most [`GATE`]; if not, schema v2 indexes are proposed to the lead.
//!
//! The rows are bulk-inserted with plaintext columns only (the query never reads the chain
//! columns), so the store is not a valid chain and is never reopened.
//!
//! - `bench_filters_match_raw_sql_on_small_store` runs everywhere: 30 000 rows (more than one
//!   budget), correctness only.
//! - `audit_query_bench` is `#[ignore]`d: the `ci.yml` step runs it in release (with debug
//!   assertions, the `testing` feature needs them) with `ATLAS_DUCK_BENCH_ENFORCE=1`. Without
//!   `ENFORCE` it only checks correctness on the small store, so a stray unoptimized run cannot
//!   produce gate numbers. `ATLAS_DUCK_BENCH_ROWS` sets the row count (default 1 000 000).

mod common;

use std::time::{Duration, Instant};

use atlas_duck_audit::encoding::FORMAT_VERSION;
use atlas_duck_audit::testing::MemKeyring;
use atlas_duck_audit::types::{AuditCursor, AuditFilter, DecisionColumn, EventFlags, EventType};
use atlas_duck_audit::{QUERY_ROW_BUDGET, Store, UtcInstant};
use common::*;
use rusqlite::Connection;

/// PD-158: the longest one `query` call may take on the reference store.
const GATE: Duration = Duration::from_secs(1);
const SMALL_ROWS: u64 = 30_000;
const PAGE: u32 = 500;
/// Rows per bulk-insert transaction (keeps the WAL small).
const CHUNK: u64 = 100_000;

/// One filter kind: the filter and the raw SQL condition that says what it must match.
struct Case {
    name: &'static str,
    filter: AuditFilter,
    raw: String,
}

fn ts_of(c: &Connection, seq: u64) -> String {
    c.query_row(
        "SELECT ts_utc FROM events WHERE seq = ?1",
        [seq as i64],
        |r| r.get(0),
    )
    .expect("ts of a seq")
}

/// Appends a handful of real rows (the store's own genesis rows are there already), then
/// bulk-inserts `rows` plaintext-only rows after them. The value mix: 6 event types, 20 agents
/// (the oldest 1000 rows belong to `agent-old` alone), 8 ops, 3 classes, 4 instances, 5000
/// targets, 3 decisions, `EDITED` on every 50th row and `STALE` on a rare one.
fn bulk_store(rows: u64) -> (Store, Fixture) {
    let (s, f) = new_store(fake_clock(START), MemKeyring::new());
    s.append(ev(
        EventType::REQUEST_RECEIVED,
        Some("r-bench"),
        serde_json::json!({}),
    ))
    .expect("append");
    let conn = raw_conn(&f);
    conn.pragma_update(None, "synchronous", "OFF")
        .expect("synchronous");
    let first: i64 = conn
        .query_row("SELECT max(seq) + 1 FROM events", [], |r| r.get(0))
        .expect("next seq");
    let types = [
        EventType::REQUEST_RECEIVED,
        EventType::READ_RELEASED,
        EventType::READ_FETCHED,
        EventType::WRITE_APPROVED,
        EventType::WRITE_DENIED,
        EventType::DELIVERED,
    ];
    let type_case: String = types
        .iter()
        .enumerate()
        .map(|(i, t)| format!("WHEN {i} THEN '{}'", t.as_str()))
        .collect::<Vec<_>>()
        .join(" ");
    let decision_case = format!(
        "CASE (j % 3) WHEN 0 THEN '{}' WHEN 1 THEN '{}' ELSE '{}' END",
        DecisionColumn::Release.as_str(),
        DecisionColumn::Approve.as_str(),
        DecisionColumn::Deny.as_str()
    );
    let sql = format!(
        "WITH RECURSIVE c(j) AS (SELECT ?1 UNION ALL SELECT j + 1 FROM c WHERE j < ?2) \
         INSERT INTO events(seq, format_version, chain_id, ts_utc, event_type, op_id, op_class, \
             instance_id, target, agent_name, decision, flags, payload_len, payload_sha256, \
             key_id, nonce, payload_ct, prev_hash, record_hash) \
         SELECT ?3 + j, {fv}, ?4, \
             strftime('%Y-%m-%dT%H:%M:%f', '2026-10-08 12:00:00', '+' || (j + 1) || ' seconds') || 'Z', \
             CASE (j % 6) {type_case} END, \
             'op.' || (j % 8), \
             CASE (j % 3) WHEN 0 THEN 'read' WHEN 1 THEN 'write' ELSE 'admin' END, \
             'i-' || (j % 4), \
             'PROJ-' || (j % 5000), \
             CASE WHEN j < 1000 THEN 'agent-old' ELSE 'agent-' || (j % 20) END, \
             {decision_case}, \
             CASE WHEN j % 50 = 0 THEN {edited} WHEN j % 1000 = 1 THEN {stale} ELSE 0 END, \
             16, zeroblob(32), 1, zeroblob(12), zeroblob(16), zeroblob(32), zeroblob(32) \
         FROM c",
        fv = FORMAT_VERSION,
        edited = EventFlags::EDITED.bits(),
        stale = EventFlags::STALE.bits(),
    );
    let mut j = 0u64;
    while j < rows {
        let hi = (j + CHUNK).min(rows) - 1;
        conn.execute_batch("BEGIN").expect("begin");
        conn.execute(
            &sql,
            rusqlite::params![j as i64, hi as i64, first, f.chain_id],
        )
        .expect("bulk insert");
        conn.execute_batch("COMMIT").expect("commit");
        j = hi + 1;
    }
    (s, f)
}

fn cases(c: &Connection, rows: u64) -> Vec<Case> {
    let last: u64 = c
        .query_row("SELECT max(seq) FROM events", [], |r| r.get::<_, i64>(0))
        .expect("head") as u64;
    let utc = |t: &str| UtcInstant::parse_rfc3339_ms(t).expect("ts");
    let recent_from = ts_of(c, last - 3599.min(rows - 1));
    let mid = last - rows / 2;
    let (old_from, old_to) = (ts_of(c, mid), ts_of(c, mid + 3599.min(rows / 4)));
    let text = |s: &str| Some(s.to_string());
    let case = |name, filter, raw: &str| Case {
        name,
        filter,
        raw: raw.to_string(),
    };
    vec![
        case("none (empty filter)", AuditFilter::default(), "1=1"),
        Case {
            name: "time: newest hour",
            filter: AuditFilter {
                from_utc: Some(utc(&recent_from)),
                ..Default::default()
            },
            raw: format!("ts_utc >= '{recent_from}'"),
        },
        Case {
            name: "time: hour in the middle",
            filter: AuditFilter {
                from_utc: Some(utc(&old_from)),
                to_utc: Some(utc(&old_to)),
                ..Default::default()
            },
            raw: format!("ts_utc >= '{old_from}' AND ts_utc <= '{old_to}'"),
        },
        case(
            "agent (1 in 20)",
            AuditFilter {
                agent_name: text("agent-3"),
                ..Default::default()
            },
            "agent_name = 'agent-3'",
        ),
        case(
            "agent (oldest 1000 rows only)",
            AuditFilter {
                agent_name: text("agent-old"),
                ..Default::default()
            },
            "agent_name = 'agent-old'",
        ),
        case(
            "op_id (1 in 8)",
            AuditFilter {
                op_id: text("op.5"),
                ..Default::default()
            },
            "op_id = 'op.5'",
        ),
        case(
            "op_class (1 in 3)",
            AuditFilter {
                op_class: text("write"),
                ..Default::default()
            },
            "op_class = 'write'",
        ),
        case(
            "instance_id (1 in 4)",
            AuditFilter {
                instance_id: text("i-2"),
                ..Default::default()
            },
            "instance_id = 'i-2'",
        ),
        case(
            "target prefix PROJ-12 (about 1 in 450)",
            AuditFilter {
                target: text("PROJ-12"),
                ..Default::default()
            },
            "substr(target, 1, 7) = 'PROJ-12'",
        ),
        case(
            "decision (1 in 3)",
            AuditFilter {
                decision: Some(DecisionColumn::Deny),
                ..Default::default()
            },
            &format!("decision = '{}'", DecisionColumn::Deny.as_str()),
        ),
        case(
            "flags_any STALE (1 in 1000)",
            AuditFilter {
                flags_any: vec![EventFlags::STALE],
                ..Default::default()
            },
            &format!("(flags & {}) != 0", EventFlags::STALE.bits()),
        ),
        case(
            "event_types (2 of 6)",
            AuditFilter {
                event_types: vec![EventType::WRITE_DENIED, EventType::DELIVERED],
                ..Default::default()
            },
            &format!(
                "event_type IN ('{}','{}')",
                EventType::WRITE_DENIED.as_str(),
                EventType::DELIVERED.as_str()
            ),
        ),
        case(
            "combined (agent, class, decision, type)",
            AuditFilter {
                agent_name: text("agent-3"),
                op_class: text("write"),
                decision: Some(DecisionColumn::Approve),
                event_types: vec![EventType::READ_RELEASED],
                ..Default::default()
            },
            &format!(
                "agent_name = 'agent-3' AND op_class = 'write' AND decision = '{}' \
                 AND event_type = '{}'",
                DecisionColumn::Approve.as_str(),
                EventType::READ_RELEASED.as_str()
            ),
        ),
        case(
            "no match (agent nobody)",
            AuditFilter {
                agent_name: text("nobody"),
                ..Default::default()
            },
            "agent_name = 'nobody'",
        ),
        case(
            "no match (target prefix, nothing starts with it)",
            AuditFilter {
                target: text("NOPE-"),
                ..Default::default()
            },
            "substr(target, 1, 5) = 'NOPE-'",
        ),
    ]
}

struct Walk {
    calls: u64,
    first_call: Duration,
    max_call: Duration,
    total: Duration,
    /// Calls and elapsed time until the first page with rows (`None`: it never came).
    first_rows: Option<(u64, Duration)>,
    seqs: Vec<u64>,
    scanned: u64,
}

/// Follows the continuation cursors to the end; bounded, so a paging bug fails, not hangs.
fn walk(s: &Store, f: &AuditFilter, rows: u64) -> Walk {
    let bound = rows / QUERY_ROW_BUDGET + rows / u64::from(PAGE) + 64;
    let mut w = Walk {
        calls: 0,
        first_call: Duration::ZERO,
        max_call: Duration::ZERO,
        total: Duration::ZERO,
        first_rows: None,
        seqs: Vec::new(),
        scanned: 0,
    };
    let mut cursor = AuditCursor::first(PAGE);
    loop {
        assert!(w.calls < bound, "paging did not end within {bound} calls");
        let t = Instant::now();
        let page = s.query(f, cursor).expect("query");
        let d = t.elapsed();
        w.calls += 1;
        if w.calls == 1 {
            w.first_call = d;
        }
        w.max_call = w.max_call.max(d);
        w.total += d;
        w.scanned += page.scanned;
        if w.first_rows.is_none() && !page.rows.is_empty() {
            w.first_rows = Some((w.calls, w.total));
        }
        w.seqs.extend(page.rows.iter().map(|h| h.seq));
        match page.next {
            Some(n) => cursor = n,
            None => return w,
        }
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn run(rows: u64, enforce: bool) {
    let (s, f) = bulk_store(rows);
    let raw = raw_conn(&f);
    let stored: u64 = raw
        .query_row("SELECT count(*) FROM events", [], |r| r.get::<_, i64>(0))
        .expect("count") as u64;
    println!("BENCH rows={stored} enforce={enforce} budget={QUERY_ROW_BUDGET} page={PAGE}");
    let mut slow = Vec::new();
    for case in cases(&raw, rows) {
        let w = walk(&s, &case.filter, stored);
        let sql = |what: &str| format!("SELECT {what} FROM events WHERE {}", case.raw);
        let want: i64 = raw
            .query_row(&sql("count(*)"), [], |r| r.get(0))
            .expect("raw count");
        assert_eq!(w.seqs.len() as i64, want, "{}: matching rows", case.name);
        assert!(
            want > 0 || case.name.starts_with("no match"),
            "{}: the generated rows must match this filter",
            case.name
        );
        let newest: Option<i64> = raw
            .query_row(&sql("max(seq)"), [], |r| r.get(0))
            .expect("raw max");
        assert_eq!(
            w.seqs.first().map(|&q| q as i64),
            newest,
            "{}: newest match first",
            case.name
        );
        assert!(
            w.seqs.windows(2).all(|p| p[0] > p[1]),
            "{}: seq descending",
            case.name
        );
        // A full page counts its probe row (the next page's first row) again in the next call,
        // so only a walk without full pages counts every row exactly once.
        if want == 0 {
            assert_eq!(w.scanned, stored, "{}: every row examined once", case.name);
        } else {
            assert!(w.scanned >= stored, "{}: every row examined", case.name);
        }
        let (fr_calls, fr_ms) = w.first_rows.map_or((0, f64::NAN), |(c, d)| (c, ms(d)));
        println!(
            "BENCH filter=\"{}\" matches={want} first_call_ms={:.1} max_call_ms={:.1} \
             calls_to_first_rows={fr_calls} ms_to_first_rows={fr_ms:.1} walk_calls={} \
             walk_total_ms={:.1}",
            case.name,
            ms(w.first_call),
            ms(w.max_call),
            w.calls,
            ms(w.total)
        );
        if w.first_call > GATE || w.max_call > GATE {
            slow.push(case.name);
        }
    }
    if enforce {
        assert!(
            slow.is_empty(),
            "PD-158 gate: a query call took more than {GATE:?} for {slow:?}; schema v2 indexes \
             need the lead's approval with these numbers"
        );
    }
}

#[test]
fn bench_filters_match_raw_sql_on_small_store() {
    run(SMALL_ROWS, false);
}

#[test]
#[ignore = "CI: ci.yml audit-query benchmark step (release, Linux)"]
fn audit_query_bench() {
    let enforce = std::env::var("ATLAS_DUCK_BENCH_ENFORCE").as_deref() == Ok("1");
    let rows = if enforce {
        std::env::var("ATLAS_DUCK_BENCH_ROWS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1_000_000)
    } else {
        SMALL_ROWS
    };
    run(rows, enforce);
}
