//! Audit window read APIs (M10 T10, §8.10, L38): filters over plaintext columns, keyset
//! pages, the request trail with its delivery summary, and payload paging.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use atlas_duck_audit::error::AuditError;
use atlas_duck_audit::testing::MemKeyring;
use atlas_duck_audit::types::{
    Actor, AuditCursor, AuditFilter, DecisionColumn, EventFlags, EventHeader, EventType,
    MAX_AUDIT_PAGE_ROWS, PAYLOAD_PAGE_BYTES,
};
use atlas_duck_audit::{RETENTION_MIN, Store, UtcInstant};
use common::*;
use serde_json::{Value, json};

use EventType as T;

const WORD: &str = "zebra-unique-payload-word";

fn store() -> (Store, Fixture) {
    new_store(fake_clock(START), MemKeyring::new())
}

/// Every header the store holds, by paging through `query` with an empty filter; bounded so a
/// paging bug fails instead of hanging.
fn all(s: &Store) -> Vec<EventHeader> {
    pages(s, &AuditFilter::default(), 500)
}

fn pages(s: &Store, f: &AuditFilter, limit: u32) -> Vec<EventHeader> {
    let mut out = Vec::new();
    let mut cursor = AuditCursor::first(limit);
    for _ in 0..10_000 {
        let page = s.query(f, cursor).expect("page");
        out.extend(page.rows);
        match page.next {
            Some(n) => cursor = n,
            None => return out,
        }
    }
    panic!("paging did not end");
}

fn seqs(rows: &[EventHeader]) -> Vec<u64> {
    rows.iter().map(|h| h.seq).collect()
}

struct Row {
    t: EventType,
    agent: Option<&'static str>,
    op: Option<&'static str>,
    class: Option<&'static str>,
    inst: Option<&'static str>,
    target: Option<&'static str>,
    decision: Option<DecisionColumn>,
    flags: EventFlags,
}

fn row(t: EventType) -> Row {
    Row {
        t,
        agent: None,
        op: None,
        class: None,
        inst: None,
        target: None,
        decision: None,
        flags: EventFlags::default(),
    }
}

fn put(s: &Store, r: &Row) -> u64 {
    let mut e = ev(r.t, Some("r-filter"), json!({ "word": WORD }));
    e.actor.agent_name = r.agent.map(str::to_string);
    e.op_id = r.op.map(str::to_string);
    e.op_class = r.class.map(str::to_string);
    e.instance_id = r.inst.map(str::to_string);
    e.target = r.target.map(str::to_string);
    e.decision = r.decision;
    e.flags = r.flags;
    s.append(e).expect("append").seq
}

#[test]
fn audit_query_filters_plaintext_only() {
    let (s, f) = store();
    let rows = [
        Row {
            agent: Some("alice"),
            op: Some("jira.issue.get"),
            class: Some("read"),
            inst: Some("i-1"),
            target: Some("PROJ-1"),
            decision: Some(DecisionColumn::Release),
            ..row(T::READ_RELEASED)
        },
        Row {
            agent: Some("bob"),
            op: Some("jira.issue.edit"),
            class: Some("write"),
            inst: Some("i-1"),
            target: Some("PROJ-12"),
            decision: Some(DecisionColumn::Approve),
            flags: EventFlags::EDITED,
            ..row(T::WRITE_APPROVED)
        },
        Row {
            agent: Some("alice"),
            op: Some("jira.issue.edit"),
            class: Some("write"),
            inst: Some("i-2"),
            target: Some("proj-1"),
            decision: Some(DecisionColumn::Deny),
            flags: EventFlags::STALE,
            ..row(T::WRITE_DENIED)
        },
        Row {
            agent: Some("alice"),
            target: Some("PR%J-1"),
            flags: EventFlags::BATCH | EventFlags::EDITED,
            ..row(T::WRITE_EDITED)
        },
        Row {
            target: Some("PRXJ-9"),
            ..row(T::REQUEST_RECEIVED)
        },
        Row {
            target: Some("_ROJ"),
            ..row(T::REQUEST_RECEIVED)
        },
        Row {
            target: Some("PROJ-\u{e9}x"),
            ..row(T::READ_FETCHED)
        },
    ];
    for r in &rows {
        f.clock.advance(Duration::from_secs(3600));
        put(&s, r);
    }
    let everything = all(&s);
    assert!(everything.len() >= rows.len(), "genesis rows are kept too");

    let check = |name: &str, filter: AuditFilter, pred: &dyn Fn(&EventHeader) -> bool| {
        let want: Vec<u64> = everything
            .iter()
            .filter(|h| pred(h))
            .map(|h| h.seq)
            .collect();
        let got = seqs(&pages(&s, &filter, 3));
        assert_eq!(got, want, "{name}");
        assert!(
            !want.is_empty() || name.contains("none"),
            "{name} matches nothing"
        );
    };

    let agent = |h: &EventHeader, a: &str| h.actor.agent_name.as_deref() == Some(a);
    check(
        "agent",
        AuditFilter {
            agent_name: Some("alice".into()),
            ..Default::default()
        },
        &|h| agent(h, "alice"),
    );
    check(
        "op_id",
        AuditFilter {
            op_id: Some("jira.issue.edit".into()),
            ..Default::default()
        },
        &|h| h.op_id.as_deref() == Some("jira.issue.edit"),
    );
    check(
        "op_class",
        AuditFilter {
            op_class: Some("write".into()),
            ..Default::default()
        },
        &|h| h.op_class.as_deref() == Some("write"),
    );
    check(
        "instance",
        AuditFilter {
            instance_id: Some("i-1".into()),
            ..Default::default()
        },
        &|h| h.instance_id.as_deref() == Some("i-1"),
    );
    check(
        "decision",
        AuditFilter {
            decision: Some(DecisionColumn::Deny),
            ..Default::default()
        },
        &|h| h.decision == Some(DecisionColumn::Deny),
    );
    check(
        "event types",
        AuditFilter {
            event_types: vec![T::WRITE_APPROVED, T::READ_RELEASED, T::WRITE_APPROVED],
            ..Default::default()
        },
        &|h| matches!(h.event_type, T::WRITE_APPROVED | T::READ_RELEASED),
    );
    check(
        "flags any one",
        AuditFilter {
            flags_any: vec![EventFlags::EDITED],
            ..Default::default()
        },
        &|h| h.flags.contains(EventFlags::EDITED),
    );
    check(
        "flags any two",
        AuditFilter {
            flags_any: vec![EventFlags::EDITED, EventFlags::STALE],
            ..Default::default()
        },
        &|h| h.flags.contains(EventFlags::EDITED) || h.flags.contains(EventFlags::STALE),
    );
    check(
        "target prefix",
        AuditFilter {
            target: Some("PROJ-1".into()),
            ..Default::default()
        },
        &|h| h.target.as_deref().is_some_and(|t| t.starts_with("PROJ-1")),
    );
    check(
        "target prefix percent is literal",
        AuditFilter {
            target: Some("PR%".into()),
            ..Default::default()
        },
        &|h| h.target.as_deref() == Some("PR%J-1"),
    );
    check(
        "target prefix underscore is literal",
        AuditFilter {
            target: Some("_".into()),
            ..Default::default()
        },
        &|h| h.target.as_deref() == Some("_ROJ"),
    );
    check(
        "target prefix non-ascii",
        AuditFilter {
            target: Some("PROJ-\u{e9}".into()),
            ..Default::default()
        },
        &|h| h.target.as_deref() == Some("PROJ-\u{e9}x"),
    );
    // Both ends inclusive.
    // `everything` is newest first.
    let from = everything[everything.len() - 3].ts_utc.clone();
    let to = everything[everything.len() - 5].ts_utc.clone();
    assert!(from < to, "the fixture rows are an hour apart");
    check(
        "time range",
        AuditFilter {
            from_utc: UtcInstant::parse_rfc3339_ms(&from),
            to_utc: UtcInstant::parse_rfc3339_ms(&to),
            ..Default::default()
        },
        &|h| h.ts_utc >= from && h.ts_utc <= to,
    );
    // Conditions combine with AND.
    check(
        "combined",
        AuditFilter {
            agent_name: Some("alice".into()),
            op_class: Some("write".into()),
            flags_any: vec![EventFlags::STALE],
            ..Default::default()
        },
        &|h| {
            agent(h, "alice")
                && h.op_class.as_deref() == Some("write")
                && h.flags.contains(EventFlags::STALE)
        },
    );
    // L38: there is no payload search; a payload word matches no plaintext column.
    let reads = s.testing_payload_reads();
    for filter in [
        AuditFilter {
            agent_name: Some(WORD.into()),
            ..Default::default()
        },
        AuditFilter {
            target: Some("zebra".into()),
            ..Default::default()
        },
        AuditFilter {
            op_id: Some(WORD.into()),
            ..Default::default()
        },
    ] {
        assert!(pages(&s, &filter, 50).is_empty(), "{filter:?}");
    }
    assert_eq!(
        s.testing_payload_reads(),
        reads,
        "a query never opens a payload"
    );
}

#[test]
fn audit_query_rejects_bad_cursors_and_filters() {
    let (s, _f) = store();
    let none = AuditFilter::default();
    for limit in [0, MAX_AUDIT_PAGE_ROWS + 1, u32::MAX] {
        assert!(
            matches!(
                s.query(&none, AuditCursor::first(limit)),
                Err(AuditError::Invalid(_))
            ),
            "limit {limit}"
        );
    }
    assert!(
        s.query(&none, AuditCursor::first(MAX_AUDIT_PAGE_ROWS))
            .is_ok()
    );
    let long = AuditFilter {
        target: Some("x".repeat(100_000)),
        ..Default::default()
    };
    assert!(matches!(
        s.query(&long, AuditCursor::first(10)),
        Err(AuditError::Invalid(_))
    ));
    // A flag entry that is not a defined single bit selects nothing safely: refused.
    for bad in [
        EventFlags::from_bits(0),
        EventFlags::from_bits(1 << 40),
        EventFlags::EDITED | EventFlags::STALE,
    ] {
        let f = AuditFilter {
            flags_any: vec![bad],
            ..Default::default()
        };
        assert!(
            matches!(
                s.query(&f, AuditCursor::first(10)),
                Err(AuditError::Invalid(_))
            ),
            "{bad:?}"
        );
    }
    // A cursor beyond the head is an empty last page, not an error.
    let page = s
        .query(
            &none,
            AuditCursor {
                before_seq: Some(1),
                limit: 10,
            },
        )
        .expect("page");
    assert!(page.rows.is_empty() && page.next.is_none());
}

#[test]
fn audit_query_keyset_pages_cover_all_rows_once() {
    let (s, _f) = store();
    for n in [20usize, 3] {
        s.append_batch(day_events(n)).expect("append");
    }
    let total = all(&s).len();
    assert!(total >= 23);
    // 7 does not divide the count, 1 and the exact multiple hit the boundary cases.
    for limit in [1u32, 7, 12, u32::try_from(total).expect("fits"), 500] {
        let mut seen = Vec::new();
        let mut cursor = AuditCursor::first(limit);
        let mut page_no = 0;
        loop {
            let page = s.query(&AuditFilter::default(), cursor).expect("page");
            page_no += 1;
            assert!(page_no < 1000, "paging did not end");
            assert!(page.rows.len() <= limit as usize);
            // Examined rows: the page plus the probe row when another page follows.
            let probe = u64::from(page.next.is_some());
            assert_eq!(page.scanned, page.rows.len() as u64 + probe);
            seen.extend(seqs(&page.rows));
            match page.next {
                Some(n) => {
                    assert_eq!(
                        page.rows.len(),
                        limit as usize,
                        "next only after a full page"
                    );
                    assert_eq!(n.limit, limit);
                    assert_eq!(n.before_seq, seen.last().copied());
                    cursor = n;
                }
                None => break,
            }
        }
        let distinct: BTreeSet<u64> = seen.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            seen.len(),
            "limit {limit}: a row came twice"
        );
        assert_eq!(seen.len(), total, "limit {limit}: every row once");
        assert!(
            seen.windows(2).all(|w| w[0] > w[1]),
            "limit {limit}: seq descending"
        );
    }
    // A row appended between two pages does not shift the next page (keyset, not offset).
    let first = s
        .query(&AuditFilter::default(), AuditCursor::first(5))
        .expect("page");
    s.append(ev(T::APP_START, None, json!({}))).expect("append");
    let second = s
        .query(&AuditFilter::default(), first.next.expect("more"))
        .expect("page");
    assert_eq!(
        second.rows.first().map(|h| h.seq),
        first.rows.last().map(|h| h.seq - 1)
    );
}

fn peer(exe: &str) -> Actor {
    Actor {
        peer_origin_exe: Some(PathBuf::from(exe)),
        ..Actor::default()
    }
}

fn received(s: &Store, rid: &str, exe: &str, start: Option<&str>) -> u64 {
    let mut e = ev(
        T::REQUEST_RECEIVED,
        Some(rid),
        json!({
            "params": { "peer_origin_start_time": "decoy" },
            "connection": {
                "peer_origin_exe": exe,
                "peer_origin_start_time": start,
            },
        }),
    );
    e.actor = peer(exe);
    s.append(e).expect("append").seq
}

fn delivered(s: &Store, rid: &str, exe: &str, start: Option<&str>) -> u64 {
    let mut e = ev(
        T::DELIVERED,
        Some(rid),
        json!({ "peer_origin_exe": exe, "peer_origin_start_time": start }),
    );
    e.actor = peer(exe);
    s.append(e).expect("append").seq
}

fn terminal(s: &Store, rid: &str) -> u64 {
    s.append(ev(T::READ_RELEASED, Some(rid), json!({})))
        .expect("append")
        .seq
}

#[test]
fn trail_includes_deliveries_and_summary() {
    let (s, _f) = store();
    let a = received(&s, "r1", "agent-a", Some("100"));
    let b = terminal(&s, "r1");
    let c = delivered(&s, "r1", "agent-a", Some("100"));
    // Another request and a request-less record are not part of the trail.
    received(&s, "r2", "agent-a", Some("100"));
    s.append(ev(T::APP_START, None, json!({}))).expect("append");

    let t = s.trail("r1").expect("trail");
    assert_eq!(
        seqs(&t.headers),
        vec![a, b, c],
        "seq ascending, DELIVERED included"
    );
    assert_eq!(t.deliveries.count, 1);
    assert!(!t.deliveries.to_other_peer);

    let none = s.trail("no-such-request").expect("trail");
    assert!(none.headers.is_empty());
    assert_eq!(none.deliveries.count, 0);
    assert!(!none.deliveries.to_other_peer);

    // Only the submit and DELIVERED payloads are opened: one read each.
    let reads = s.testing_payload_reads();
    s.trail("r1").expect("trail");
    assert_eq!(s.testing_payload_reads() - reads, 2);
}

#[test]
fn multi_delivery_and_different_peer_flagged() {
    let (s, _f) = store();
    received(&s, "multi", "agent-a", Some("100"));
    terminal(&s, "multi");
    delivered(&s, "multi", "agent-a", Some("100"));
    delivered(&s, "multi", "agent-a", Some("100"));
    let t = s.trail("multi").expect("trail");
    assert_eq!(
        t.deliveries.count, 2,
        "two deliveries to the submitter's peer"
    );
    assert!(
        !t.deliveries.to_other_peer,
        "count alone is not another peer"
    );

    received(&s, "other", "agent-a", Some("100"));
    terminal(&s, "other");
    delivered(&s, "other", "agent-b", Some("100"));
    let t = s.trail("other").expect("trail");
    assert_eq!(t.deliveries.count, 1);
    assert!(t.deliveries.to_other_peer, "another origin executable");

    // A delivery whose origin is unknown while the submitter's was known is another peer.
    received(&s, "unknown", "agent-a", Some("100"));
    let mut e = ev(T::DELIVERED, Some("unknown"), json!({}));
    e.actor = Actor::default();
    s.append(e).expect("append");
    assert!(s.trail("unknown").expect("trail").deliveries.to_other_peer);

    // Without any DELIVERED there is nothing to flag.
    received(&s, "quiet", "agent-a", Some("100"));
    let t = s.trail("quiet").expect("trail");
    assert_eq!(t.deliveries.count, 0);
    assert!(!t.deliveries.to_other_peer);
}

#[test]
fn same_exe_different_start_time_is_other_peer() {
    let (s, _f) = store();
    received(&s, "restarted", "agent-a", Some("100"));
    delivered(&s, "restarted", "agent-a", Some("200"));
    assert!(
        s.trail("restarted")
            .expect("trail")
            .deliveries
            .to_other_peer,
        "same exe, another process start"
    );

    // The start time is read from the submit's connection, never from agent params.
    received(&s, "same", "agent-a", Some("100"));
    delivered(&s, "same", "agent-a", Some("100"));
    assert!(!s.trail("same").expect("trail").deliveries.to_other_peer);

    received(&s, "null-start", "agent-a", None);
    delivered(&s, "null-start", "agent-a", None);
    assert!(
        !s.trail("null-start")
            .expect("trail")
            .deliveries
            .to_other_peer,
        "start time unknown on both sides: the exe decides"
    );

    received(&s, "start-lost", "agent-a", Some("100"));
    delivered(&s, "start-lost", "agent-a", None);
    assert!(
        s.trail("start-lost")
            .expect("trail")
            .deliveries
            .to_other_peer
    );
}

#[test]
fn trail_without_a_submit_record_compares_deliveries_with_each_other() {
    let (s, _f) = store();
    // The REQUEST_RECEIVED was pruned: no submitter to compare with.
    delivered(&s, "tail", "agent-a", Some("100"));
    delivered(&s, "tail", "agent-a", Some("100"));
    assert!(!s.trail("tail").expect("trail").deliveries.to_other_peer);
    delivered(&s, "tail", "agent-b", Some("100"));
    assert!(s.trail("tail").expect("trail").deliveries.to_other_peer);
}

#[test]
fn trail_fails_closed_on_an_undecryptable_payload() {
    let (s, f) = store();
    received(&s, "r", "agent-a", Some("100"));
    let d = delivered(&s, "r", "agent-a", Some("100"));
    raw_conn(&f)
        .execute(
            "UPDATE events SET payload_ct = ?1 WHERE seq = ?2",
            rusqlite::params![vec![0u8; 48], i64::try_from(d).expect("seq")],
        )
        .expect("tamper");
    assert!(matches!(
        s.trail("r"),
        Err(AuditError::Decrypt { .. } | AuditError::PayloadHash { .. })
    ));
}

#[test]
fn trail_fails_closed_on_a_submit_payload_without_a_connection_object() {
    let (s, _f) = store();
    // A submit whose `connection` is not an object cannot name a peer: never read as "same".
    let mut e = ev(T::REQUEST_RECEIVED, Some("odd"), json!({ "connection": 7 }));
    e.actor = peer("agent-a");
    s.append(e).expect("append");
    delivered(&s, "odd", "agent-a", Some("100"));
    assert!(matches!(
        s.trail("odd"),
        Err(AuditError::InvalidRecord { .. })
    ));
}

fn put_payload(s: &Store, payload: Value) -> u64 {
    s.append(ev(T::SYSTEM_FETCH, Some("big"), payload))
        .expect("append")
        .seq
}

#[test]
fn payload_view_pages_concat_equals_payload() {
    let (s, _f) = store();
    // About 2.5 pages of JCS payload.
    let blob = "x\u{e9}\u{1F600}".repeat(PAYLOAD_PAGE_BYTES * 5 / 2 / 7);
    let seq = put_payload(&s, json!({ "blob": blob }));
    let whole = s.read_payload(seq).expect("payload");
    assert!(whole.len() > 2 * PAYLOAD_PAGE_BYTES && whole.len() < 3 * PAYLOAD_PAGE_BYTES);

    let first = s.payload_view(seq, 0).expect("page 0");
    assert_eq!(first.seq, seq);
    assert_eq!(first.total_bytes, whole.len() as u64);
    assert_eq!(first.page_count, 3);
    let mut joined = Vec::new();
    for p in 0..first.page_count {
        let page = s.payload_view(seq, p).expect("page");
        assert_eq!(page.page, p);
        assert_eq!(page.page_count, first.page_count);
        assert_eq!(page.total_bytes, first.total_bytes);
        if p + 1 < page.page_count {
            assert_eq!(page.bytes.len(), PAYLOAD_PAGE_BYTES);
        }
        joined.extend_from_slice(&page.bytes);
    }
    assert_eq!(joined.as_slice(), whole.as_slice());

    // Past the last page is an error, not an empty page.
    assert!(matches!(
        s.payload_view(seq, first.page_count),
        Err(AuditError::Invalid(_))
    ));
    assert!(matches!(
        s.payload_view(seq + 1000, 0),
        Err(AuditError::NotFound { .. })
    ));
}

#[test]
fn payload_view_small_payload_is_one_page_and_debug_hides_bytes() {
    let (s, _f) = store();
    let seq = put_payload(&s, json!({ "k": WORD }));
    let page = s.payload_view(seq, 0).expect("page");
    assert_eq!(page.page_count, 1);
    assert_eq!(page.total_bytes, page.bytes.len() as u64);
    assert!(page.bytes.windows(WORD.len()).any(|w| w == WORD.as_bytes()));
    let shown = format!("{page:?}");
    assert!(!shown.contains(WORD), "{shown}");
    assert!(!shown.contains("120"), "no byte values either: {shown}");
}

/// Follows `next` until it ends; bounded so a continuation bug fails instead of hanging.
/// Returns the rows and every page's `(rows, scanned)`.
fn walk_budgeted(
    s: &Store,
    f: &AuditFilter,
    limit: u32,
    budget: u64,
) -> (Vec<EventHeader>, Vec<(usize, u64)>) {
    let mut out = Vec::new();
    let mut shape = Vec::new();
    let mut cursor = AuditCursor::first(limit);
    for _ in 0..10_000 {
        let page = s.testing_query_budgeted(f, cursor, budget).expect("page");
        assert!(
            page.scanned <= budget,
            "a call examines at most the budget: {} > {budget}",
            page.scanned
        );
        shape.push((page.rows.len(), page.scanned));
        out.extend(page.rows);
        match page.next {
            Some(n) => cursor = n,
            None => return (out, shape),
        }
    }
    panic!("continuation did not end");
}

#[test]
fn query_row_budget_bounds_a_no_match_scan_and_continues() {
    let (s, _f) = store();
    for agent in ["alice", "bob"] {
        let events: Vec<_> = (0..40)
            .map(|i| {
                let mut e = ev(T::APP_START, None, json!({ "i": i }));
                e.actor.agent_name = Some(agent.to_owned());
                e
            })
            .collect();
        s.append_batch(events).expect("append");
    }
    let total = all(&s).len() as u64;
    assert!(total >= 80);

    // Nothing matches: every call stops at the budget with an empty page and a continuation.
    let nobody = AuditFilter {
        agent_name: Some("nobody".into()),
        ..Default::default()
    };
    let first = s
        .testing_query_budgeted(&nobody, AuditCursor::first(5), 10)
        .expect("page");
    assert!(first.rows.is_empty());
    assert_eq!(first.scanned, 10, "ten rows examined, none matched");
    let next = first.next.expect("a continuation, not the end");
    assert_eq!(next.limit, 5);
    let (rows, shape) = walk_budgeted(&s, &nobody, 5, 10);
    assert!(rows.is_empty());
    assert_eq!(
        shape.iter().map(|p| p.1).sum::<u64>(),
        total,
        "continuing examines every row exactly once"
    );
    assert!(shape.len() as u64 >= total / 10);

    // A sparse match: the continued walk returns exactly the unbudgeted result.
    let alice = AuditFilter {
        agent_name: Some("alice".into()),
        ..Default::default()
    };
    let want = seqs(&pages(&s, &alice, 500));
    assert_eq!(want.len(), 40);
    for (limit, budget) in [(4u32, 7u64), (1, 1), (500, 13), (3, 20), (7, 10_000)] {
        let (got, _) = walk_budgeted(&s, &alice, limit, budget);
        assert_eq!(seqs(&got), want, "limit {limit} budget {budget}");
    }
    // The budget landing exactly on the end of the store leaves no phantom continuation.
    let (_, shape) = walk_budgeted(&s, &nobody, 5, total);
    assert_eq!(shape, vec![(0, total)]);
}

#[test]
fn query_default_budget_stops_a_large_no_match_scan() {
    let (s, _f) = store();
    let budget = atlas_duck_audit::QUERY_ROW_BUDGET;
    let batch = 5_000usize;
    let batches = (budget as usize / batch) + 1;
    for _ in 0..batches {
        s.append_batch(day_events(batch)).expect("append");
    }
    assert!(all(&s).len() as u64 > budget);
    let nobody = AuditFilter {
        agent_name: Some("nobody".into()),
        ..Default::default()
    };
    let page = s.query(&nobody, AuditCursor::first(10)).expect("page");
    assert!(page.rows.is_empty());
    assert_eq!(page.scanned, budget);
    assert!(page.next.is_some(), "more rows follow the budget window");
}

#[test]
fn query_pages_with_a_filter_over_equal_timestamps() {
    let (s, _f) = store();
    // The clock never moves: every row shares one `ts_utc`, so only `seq` orders them.
    let events: Vec<_> = (0..30)
        .map(|i| {
            let mut e = ev(T::APP_START, None, json!({ "i": i }));
            e.actor.agent_name = Some(if i % 3 == 0 { "alice" } else { "bob" }.to_owned());
            e
        })
        .collect();
    s.append_batch(events).expect("append");
    let alice = AuditFilter {
        agent_name: Some("alice".into()),
        ..Default::default()
    };
    let want: Vec<u64> = all(&s)
        .iter()
        .filter(|h| h.actor.agent_name.as_deref() == Some("alice"))
        .map(|h| h.seq)
        .collect();
    assert_eq!(want.len(), 10);
    for limit in [1u32, 3, 4, 10] {
        assert_eq!(seqs(&pages(&s, &alice, limit)), want, "limit {limit}");
    }
}

#[test]
fn trail_after_a_real_prune_compares_with_the_first_delivery() {
    let (s, f) = new_store_with(fake_clock(START), MemKeyring::new(), |cfg| {
        cfg.hooks.synchronous_normal = true;
    });
    corroborate_now(&s, &f.clock);
    prune_ready(&s, RETENTION_MIN);
    let submit = received(&s, "aged", "agent-a", Some("100"));
    for _ in 0..60 {
        day(&s, &f.clock, 1);
    }
    let d1 = delivered(&s, "aged", "agent-a", Some("100"));
    for _ in 0..45 {
        day(&s, &f.clock, 1);
    }
    let headers = s.headers_for_request("aged").expect("headers");
    assert_eq!(
        seqs(&headers),
        vec![d1],
        "the submit (seq {submit}) is past retention and gone"
    );
    let t = s.trail("aged").expect("trail");
    assert_eq!(t.deliveries.count, 1);
    assert!(!t.deliveries.to_other_peer);
    delivered(&s, "aged", "agent-b", Some("100"));
    assert!(s.trail("aged").expect("trail").deliveries.to_other_peer);
}

#[test]
fn unknown_submit_origin_with_a_known_delivery_is_another_peer() {
    let (s, _f) = store();
    let mut e = ev(
        T::REQUEST_RECEIVED,
        Some("blind"),
        json!({ "connection": { "peer_origin_start_time": null } }),
    );
    e.actor = Actor::default();
    s.append(e).expect("append");
    delivered(&s, "blind", "agent-a", Some("100"));
    assert!(s.trail("blind").expect("trail").deliveries.to_other_peer);
}

#[test]
fn payload_view_page_boundary_is_exact() {
    let (s, _f) = store();
    // `{"blob":"` + n + `"}` is 11 bytes around the blob in JCS.
    let n = PAYLOAD_PAGE_BYTES - 11;
    let exact = put_payload(&s, json!({ "blob": "x".repeat(n) }));
    assert_eq!(
        s.read_payload(exact).expect("payload").len(),
        PAYLOAD_PAGE_BYTES
    );
    let page = s.payload_view(exact, 0).expect("page");
    assert_eq!(page.page_count, 1);
    assert_eq!(page.bytes.len(), PAYLOAD_PAGE_BYTES);
    assert!(matches!(
        s.payload_view(exact, 1),
        Err(AuditError::Invalid(_))
    ));
    let over = put_payload(&s, json!({ "blob": "x".repeat(n + 1) }));
    let page = s.payload_view(over, 1).expect("page 1");
    assert_eq!(page.page_count, 2);
    assert_eq!(page.bytes.len(), 1);
}

#[test]
fn query_and_trail_after_shutdown_are_closed() {
    let (s, _f) = store();
    s.shutdown();
    assert!(matches!(
        s.query(&AuditFilter::default(), AuditCursor::first(5)),
        Err(AuditError::Closed)
    ));
    assert!(matches!(s.trail("r"), Err(AuditError::Closed)));
    assert!(matches!(s.payload_view(1, 0), Err(AuditError::Closed)));
}
