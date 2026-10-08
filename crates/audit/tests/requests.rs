//! M3-facing request API (T17): the §8.3 terminal predicate, §11.3 crash reconciliation and
//! the plaintext header queries.

mod common;

use std::time::Duration;

use atlas_duck_audit::Store;
use atlas_duck_audit::error::AuditError;
use atlas_duck_audit::requests::{ReconcileReport, ScriptFailedFlags, is_terminal};
use atlas_duck_audit::testing::MemKeyring;
use atlas_duck_audit::types::{Actor, EventFlags, EventHeader, EventType};
use common::*;
use serde_json::{Value, json};

use EventType as T;

fn header(t: EventType) -> EventHeader {
    EventHeader {
        seq: 1,
        ts_utc: START.to_string(),
        epoch: None,
        chain_id: "c".into(),
        event_type: t,
        request_id: Some("r".into()),
        op_id: None,
        op_class: None,
        instance_id: None,
        target: None,
        decision: None,
        flags: EventFlags::default(),
        actor: Actor::default(),
        payload_len: 0,
        key_id: 0,
    }
}

fn flags(direct: bool, reason: &str) -> ScriptFailedFlags {
    ScriptFailedFlags {
        direct,
        reason: reason.into(),
    }
}

fn store() -> (Store, Fixture) {
    new_store(fake_clock(START), MemKeyring::new())
}

fn put(s: &Store, t: EventType, rid: &str, payload: Value) -> u64 {
    s.append(ev(t, Some(rid), payload)).expect("append").seq
}

fn approved(s: &Store, rid: &str) -> u64 {
    let mut e = write_approved(0, true);
    e.request_id = Some(rid.into());
    e.op_id = Some("jira.issue.create".into());
    e.op_class = Some("write".into());
    e.instance_id = Some("inst-1".into());
    e.target = Some("PROJ-1".into());
    s.append(e).expect("append").seq
}

fn script_failed(s: &Store, rid: &str, direct: bool, reason: &str) -> u64 {
    put(
        s,
        T::SCRIPT_FAILED,
        rid,
        json!({ "reason": reason, "queued": false, "dispatched": true,
                "data_free": false, "direct": direct }),
    )
}

fn types_of(s: &Store, rid: &str) -> Vec<EventType> {
    s.headers_for_request(rid)
        .expect("headers")
        .iter()
        .map(|h| h.event_type)
        .collect()
}

#[test]
fn terminal_table() {
    // §8.3, written literally; SCRIPT_FAILED is decided by its flags.
    let terminal = [
        T::REQUEST_REJECTED,
        T::REQUEST_FAILED,
        T::READ_RELEASED,
        T::READ_DENIED,
        T::READ_FAILED,
        T::WRITE_EXECUTED,
        T::WRITE_FAILED,
        T::WRITE_OUTCOME_UNKNOWN,
        T::WRITE_DENIED,
        T::SCRIPT_RELEASED,
        T::SCRIPT_DENIED,
        T::SCRIPT_DRY_RUN,
        T::EXPIRED,
        T::CANCELLED,
        T::ABANDONED,
    ];
    for t in EventType::ALL {
        let expect = terminal.contains(&t);
        assert_eq!(is_terminal(&header(t), None), expect, "{t:?}");
        // Flags only matter to SCRIPT_FAILED.
        assert_eq!(
            is_terminal(&header(t), Some(&flags(false, "killed_by_user"))),
            expect,
            "{t:?} with flags"
        );
    }
    let sf = header(T::SCRIPT_FAILED);
    assert!(is_terminal(&sf, Some(&flags(true, "script_syntax"))));
    assert!(is_terminal(&sf, Some(&flags(false, "audit_failure"))));
    for r in ["killed_by_user", "app_quit", "cancelled_by_client"] {
        assert!(!is_terminal(&sf, Some(&flags(false, r))), "{r}");
    }
    assert!(!is_terminal(&sf, None), "callers must decrypt");
}

#[test]
fn script_failed_flags_reads_exactly_one_row() {
    let (s, _f) = store();
    let a = script_failed(&s, "s1", true, "script_syntax");
    let b = script_failed(&s, "s2", false, "killed_by_user");
    let other = put(&s, T::SCRIPT_STARTED, "s2", json!({}));
    let before = s.testing_payload_reads();
    assert_eq!(
        s.script_failed_flags(a).unwrap(),
        flags(true, "script_syntax")
    );
    assert_eq!(
        s.script_failed_flags(b).unwrap(),
        flags(false, "killed_by_user")
    );
    assert_eq!(s.testing_payload_reads() - before, 2);
    assert!(matches!(
        s.script_failed_flags(other),
        Err(AuditError::InvalidRecord { .. })
    ));
    assert!(matches!(
        s.script_failed_flags(9999),
        Err(AuditError::NotFound { seq: 9999 })
    ));
}

#[test]
fn script_failed_flags_rejects_unreadable_payload() {
    let (s, _f) = store();
    let no_direct = put(&s, T::SCRIPT_FAILED, "s1", json!({ "reason": "x" }));
    let no_reason = put(&s, T::SCRIPT_FAILED, "s2", json!({ "direct": false }));
    let bad = put(
        &s,
        T::SCRIPT_FAILED,
        "s3",
        json!({ "direct": "yes", "reason": "x" }),
    );
    for seq in [no_direct, no_reason, bad] {
        assert!(
            matches!(
                s.script_failed_flags(seq),
                Err(AuditError::InvalidRecord { .. })
            ),
            "{seq}"
        );
    }
}

#[test]
fn reconcile_write_trailing_events() {
    let (s, _f) = store();
    put(&s, T::REQUEST_RECEIVED, "w1", json!({}));
    put(&s, T::PREVIEW_SHOWN, "w1", json!({}));
    approved(&s, "w1");
    put(
        &s,
        T::PREVIEW_FETCH,
        "w1",
        json!({ "purpose": "stale_check" }),
    );
    put(&s, T::DECISION_STALE, "w1", json!({}));
    put(&s, T::DELIVERED, "w1", json!({}));

    let report = s.reconcile_after_crash().expect("reconcile");
    assert_eq!(report.abandoned, Vec::<String>::new());
    assert_eq!(report.outcome_unknown.len(), 1);
    let w = &report.outcome_unknown[0];
    assert_eq!(w.request_id, "w1");
    assert_eq!(w.op_id.as_deref(), Some("jira.issue.create"));
    assert_eq!(w.instance_id.as_deref(), Some("inst-1"));
    assert_eq!(w.target.as_deref(), Some("PROJ-1"));
    assert_eq!(w.request_index, 0);

    let hs = s.headers_for_request("w1").unwrap();
    let last = hs.last().unwrap();
    assert_eq!(last.event_type, T::WRITE_OUTCOME_UNKNOWN);
    assert_eq!(last.op_id.as_deref(), Some("jira.issue.create"));
    assert_eq!(last.instance_id.as_deref(), Some("inst-1"));
    assert_eq!(last.target.as_deref(), Some("PROJ-1"));
    let p: Value =
        serde_json::from_slice(&s.read_payload(last.seq).unwrap()).expect("payload json");
    assert_eq!(p, json!({ "request_index": 0, "reason": "crash" }));
}

#[test]
fn reconcile_write_request_index_from_payload() {
    let (s, _f) = store();
    let mut e = write_approved(0, true);
    e.request_id = Some("w1".into());
    e.payload["requests"][0]["index"] = json!(3);
    s.append(e).unwrap();
    let mut e = write_approved(0, true);
    e.request_id = Some("w2".into());
    e.payload = json!({ "candidate_rev": 1 });
    s.append(e).unwrap();
    let report = s.reconcile_after_crash().unwrap();
    let idx = |id: &str| {
        report
            .outcome_unknown
            .iter()
            .find(|w| w.request_id == id)
            .map(|w| w.request_index)
    };
    assert_eq!(idx("w1"), Some(3));
    assert_eq!(
        idx("w2"),
        Some(0),
        "no requests in the payload defaults to 0"
    );
}

#[test]
fn reconcile_write_malformed_requests_fails_closed() {
    let (s, _f) = store();
    let mut e = write_approved(0, true);
    e.request_id = Some("w1".into());
    e.payload["requests"] = json!([{ "index": "zero" }]);
    s.append(e).unwrap();
    let head = s.head().0;
    assert!(matches!(
        s.reconcile_after_crash(),
        Err(AuditError::InvalidRecord { .. })
    ));
    assert_eq!(s.head().0, head, "nothing is appended on error");
}

#[test]
fn reconcile_latest_approval_wins() {
    let (s, _f) = store();
    // approved, sent back by WRITE_STALE, approved again: pending again.
    approved(&s, "w1");
    put(&s, T::WRITE_STALE, "w1", json!({}));
    approved(&s, "w1");
    // approved, stale, approved, edited: back in the queue.
    approved(&s, "w2");
    put(&s, T::WRITE_STALE, "w2", json!({}));
    approved(&s, "w2");
    put(&s, T::WRITE_EDITED, "w2", json!({}));
    let report = s.reconcile_after_crash().unwrap();
    assert_eq!(
        report
            .outcome_unknown
            .iter()
            .map(|w| w.request_id.as_str())
            .collect::<Vec<_>>(),
        ["w1"]
    );
    assert_eq!(report.abandoned, ["w2"]);
}

#[test]
fn reconcile_write_stale_then_refresh_is_abandoned() {
    let (s, _f) = store();
    approved(&s, "w1");
    put(&s, T::WRITE_STALE, "w1", json!({}));
    put(&s, T::PREVIEW_FETCH, "w1", json!({ "purpose": "refresh" }));
    let report = s.reconcile_after_crash().unwrap();
    assert!(report.outcome_unknown.is_empty());
    assert_eq!(report.abandoned, ["w1"]);
    assert_eq!(types_of(&s, "w1").last(), Some(&T::ABANDONED));
}

#[test]
fn reconcile_write_edited_is_abandoned() {
    let (s, _f) = store();
    approved(&s, "w1");
    put(&s, T::WRITE_EDITED, "w1", json!({}));
    let report = s.reconcile_after_crash().unwrap();
    assert!(report.outcome_unknown.is_empty());
    assert_eq!(report.abandoned, ["w1"]);
}

#[test]
fn reconcile_write_outcome_before_latest_approval_does_not_count() {
    // An outcome event older than the latest approval does not end the request: fail closed
    // in the safe direction (check the target).
    let (s, _f) = store();
    approved(&s, "w1");
    put(&s, T::WRITE_FAILED, "w1", json!({}));
    approved(&s, "w1");
    let report = s.reconcile_after_crash().unwrap();
    assert_eq!(report.outcome_unknown.len(), 1);
    assert_eq!(report.outcome_unknown[0].request_id, "w1");
}

#[test]
fn reconcile_reads_and_scripts() {
    let (s, _f) = store();
    put(&s, T::REQUEST_RECEIVED, "read1", json!({}));
    put(&s, T::READ_FETCHED, "read1", json!({}));

    put(&s, T::REQUEST_RECEIVED, "kill1", json!({}));
    put(&s, T::SCRIPT_STARTED, "kill1", json!({}));
    script_failed(&s, "kill1", false, "killed_by_user");

    put(&s, T::REQUEST_RECEIVED, "quit1", json!({}));
    script_failed(&s, "quit1", false, "app_quit");
    put(&s, T::CANCELLED, "quit1", json!({ "reason": "app_quit" }));

    put(&s, T::REQUEST_RECEIVED, "direct1", json!({}));
    script_failed(&s, "direct1", true, "script_syntax");

    put(&s, T::REQUEST_RECEIVED, "audit1", json!({}));
    script_failed(&s, "audit1", false, "audit_failure");

    let n = types_of(&s, "quit1").len();
    let report = s.reconcile_after_crash().unwrap();
    assert!(report.outcome_unknown.is_empty());
    let mut abandoned = report.abandoned.clone();
    abandoned.sort();
    assert_eq!(abandoned, ["kill1", "read1"]);
    assert_eq!(types_of(&s, "quit1").len(), n);
    assert_eq!(types_of(&s, "direct1").last(), Some(&T::SCRIPT_FAILED));
    assert_eq!(types_of(&s, "audit1").last(), Some(&T::SCRIPT_FAILED));
    assert_eq!(types_of(&s, "kill1").last(), Some(&T::ABANDONED));
    assert_eq!(types_of(&s, "read1").last(), Some(&T::ABANDONED));
}

#[test]
fn reconcile_decrypts_only_what_it_needs() {
    let (s, _f) = store();
    // Terminal by another event: its SCRIPT_FAILED is not opened.
    put(&s, T::REQUEST_RECEIVED, "a", json!({}));
    script_failed(&s, "a", false, "killed_by_user");
    put(&s, T::SCRIPT_DENIED, "a", json!({}));
    // A plain read: nothing to decrypt.
    put(&s, T::REQUEST_RECEIVED, "b", json!({}));
    let before = s.testing_payload_reads();
    let report = s.reconcile_after_crash().unwrap();
    assert_eq!(report.abandoned, ["b"]);
    assert_eq!(s.testing_payload_reads(), before);
}

#[test]
fn reconcile_unreadable_script_failed_fails_closed() {
    let (s, _f) = store();
    put(&s, T::REQUEST_RECEIVED, "s1", json!({}));
    put(&s, T::SCRIPT_FAILED, "s1", json!({ "reason": "x" }));
    let head = s.head().0;
    assert!(s.reconcile_after_crash().is_err());
    assert_eq!(s.head().0, head);
}

#[test]
fn reconcile_leaves_terminal_requests() {
    let (s, _f) = store();
    for (rid, ts) in [
        ("released", vec![T::READ_FETCHED, T::READ_RELEASED]),
        ("denied", vec![T::READ_FETCHED, T::READ_DENIED]),
        ("expired", vec![T::PREVIEW_SHOWN, T::EXPIRED]),
        ("executed", vec![T::WRITE_APPROVED, T::WRITE_EXECUTED]),
        ("failed", vec![T::WRITE_APPROVED, T::WRITE_FAILED]),
        ("rejected", vec![T::REQUEST_REJECTED]),
        ("wdenied", vec![T::PREVIEW_SHOWN, T::WRITE_DENIED]),
    ] {
        put(&s, T::REQUEST_RECEIVED, rid, json!({}));
        for t in ts {
            if t == T::WRITE_APPROVED {
                approved(&s, rid);
            } else {
                put(&s, t, rid, json!({}));
            }
        }
    }
    let head = s.head().0;
    let report = s.reconcile_after_crash().unwrap();
    assert_eq!(report, ReconcileReport::default());
    assert_eq!(s.head().0, head);
}

#[test]
fn reconcile_skips_groups_whose_terminal_event_was_pruned() {
    // Only post-terminal DELIVERED records survive of these requests.
    let (s, _f) = store();
    put(&s, T::DELIVERED, "tail1", json!({}));
    put(&s, T::DELIVERED, "tail2", json!({}));
    put(&s, T::DELIVERED, "tail2", json!({}));
    let head = s.head().0;
    assert_eq!(
        s.reconcile_after_crash().unwrap(),
        ReconcileReport::default()
    );
    assert_eq!(s.head().0, head);
    // A pending request that was also delivered is still reconciled.
    put(&s, T::REQUEST_RECEIVED, "live", json!({}));
    put(&s, T::DELIVERED, "live", json!({}));
    assert_eq!(s.reconcile_after_crash().unwrap().abandoned, ["live"]);
}

#[test]
fn reconcile_ignores_rows_without_request_id() {
    let (s, _f) = store();
    s.append(ev(T::APP_START, None, json!({}))).unwrap();
    let head = s.head().0;
    assert_eq!(
        s.reconcile_after_crash().unwrap(),
        ReconcileReport::default()
    );
    assert_eq!(s.head().0, head);
}

#[test]
fn reconcile_order_and_idempotence() {
    let (s, _f) = store();
    // Interleave: a read, a write, a read, a write.
    put(&s, T::REQUEST_RECEIVED, "r1", json!({}));
    approved(&s, "w1");
    put(&s, T::REQUEST_RECEIVED, "r2", json!({}));
    approved(&s, "w2");
    let report = s.reconcile_after_crash().unwrap();
    assert_eq!(report.outcome_unknown.len(), 2);
    assert_eq!(report.abandoned, ["r1", "r2"]);

    let seq_of = |rid: &str, t: EventType| {
        s.headers_for_request(rid)
            .unwrap()
            .into_iter()
            .find(|h| h.event_type == t)
            .map(|h| h.seq)
            .expect("reconciliation record")
    };
    let unknown = [
        seq_of("w1", T::WRITE_OUTCOME_UNKNOWN),
        seq_of("w2", T::WRITE_OUTCOME_UNKNOWN),
    ];
    let abandoned = [seq_of("r1", T::ABANDONED), seq_of("r2", T::ABANDONED)];
    assert!(unknown.iter().max() < abandoned.iter().min());

    let head = s.head().0;
    assert_eq!(
        s.reconcile_after_crash().unwrap(),
        ReconcileReport::default()
    );
    assert_eq!(s.head().0, head, "a second call appends nothing");
}

#[test]
fn headers_are_plaintext_only() {
    let (s, _f) = store();
    let mut e = ev(T::REQUEST_RECEIVED, Some("r1"), json!({ "secret": "x" }));
    e.op_id = Some("op".into());
    e.target = Some("PROJ-9".into());
    e.flags = EventFlags::EDITED;
    e.actor = Actor {
        agent_name: Some("agent".into()),
        peer_pid: Some(77),
        peer_exe: Some(std::path::PathBuf::from("C:\\tools\\agent.exe")),
        ..Actor::default()
    };
    let first = s.append(e).unwrap().seq;
    put(&s, T::READ_FETCHED, "r1", json!({}));
    put(&s, T::READ_RELEASED, "r1", json!({}));
    put(&s, T::REQUEST_RECEIVED, "other", json!({}));

    let before = s.testing_payload_reads();
    let hs = s.headers_for_request("r1").unwrap();
    assert_eq!(s.testing_payload_reads(), before, "no decrypt");
    assert_eq!(
        hs.iter().map(|h| h.event_type).collect::<Vec<_>>(),
        [T::REQUEST_RECEIVED, T::READ_FETCHED, T::READ_RELEASED]
    );
    assert!(hs.windows(2).all(|w| w[0].seq < w[1].seq));
    let h = &hs[0];
    assert_eq!(h.seq, first);
    assert_eq!(h.request_id.as_deref(), Some("r1"));
    assert_eq!(h.op_id.as_deref(), Some("op"));
    assert_eq!(h.target.as_deref(), Some("PROJ-9"));
    assert_eq!(h.ts_utc, START);
    assert!(h.flags.contains(EventFlags::EDITED));
    assert_eq!(h.actor.agent_name.as_deref(), Some("agent"));
    assert_eq!(h.actor.peer_pid, Some(77));
    assert_eq!(
        h.actor.peer_exe.as_deref(),
        Some(std::path::Path::new("C:\\tools\\agent.exe"))
    );
    assert!(h.payload_len > 0);
    assert_eq!(h.chain_id, s.head().2);

    assert!(s.headers_for_request("nope").unwrap().is_empty());
}

#[test]
fn recent_headers_window() {
    let clock = fake_clock("2026-10-07T00:00:00.000Z");
    let (s, _f) = new_store(clock.clone(), MemKeyring::new());
    let mark = |name: &str| {
        let mut e = ev(T::APP_START, None, json!({}));
        e.target = Some(name.into());
        s.append(e).unwrap();
    };
    // Now is 2026-10-08T06:00: the three rows are 30 h, 23 h and 1 h old.
    mark("h30");
    clock.advance(Duration::from_secs(7 * 3600));
    mark("h23");
    clock.advance(Duration::from_secs(22 * 3600));
    mark("h1");
    clock.advance(Duration::from_secs(3600));

    let targets = |since: Duration| -> Vec<Option<String>> {
        s.recent_headers(since)
            .unwrap()
            .into_iter()
            .map(|h| h.target)
            .collect()
    };
    let want = vec![Some("h23".to_string()), Some("h1".to_string())];
    assert_eq!(targets(Duration::from_secs(24 * 3600)), want);
    assert_eq!(
        targets(Duration::from_secs(48 * 3600)),
        want,
        "since is capped at 24 h"
    );
    assert_eq!(
        targets(Duration::from_secs(2 * 3600)),
        vec![Some("h1".into())]
    );
    assert!(targets(Duration::ZERO).is_empty());
    // The boundary is inclusive: a row exactly `since` old is returned.
    assert_eq!(targets(Duration::from_secs(23 * 3600)).len(), 2);
}

#[test]
fn queries_after_shutdown_are_closed() {
    let (s, _f) = store();
    put(&s, T::REQUEST_RECEIVED, "r", json!({}));
    s.shutdown();
    assert_eq!(s.headers_for_request("r"), Err(AuditError::Closed));
    assert_eq!(
        s.recent_headers(Duration::from_secs(60)),
        Err(AuditError::Closed)
    );
    assert!(matches!(s.reconcile_after_crash(), Err(AuditError::Closed)));
}

#[test]
fn path_bytes_round_trip() {
    use atlas_duck_audit::encoding::{os_path_bytes, os_path_from_bytes};
    for p in [r"C:\tools\agent.exe", "/usr/bin/ägent-\u{1F986}", ""] {
        let p = std::path::Path::new(p);
        assert_eq!(os_path_from_bytes(&os_path_bytes(p)).unwrap(), p);
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let lone = std::path::PathBuf::from(std::ffi::OsString::from_wide(&[0x61, 0xD800, 0x62]));
        assert_eq!(os_path_from_bytes(&os_path_bytes(&lone)).unwrap(), lone);
        assert!(os_path_from_bytes(&[0xFF]).is_err());
        assert!(os_path_from_bytes(&[0xE2, 0x82]).is_err());
    }
}
