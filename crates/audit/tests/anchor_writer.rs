//! The anchor-directory writer (§8.5, §8.7, PD-156, PD-157; U-06 writer half): the
//! `audit-anchor-dir` thread appends header, daily, `APP_STOP`, immediate and prune lines to
//! `<anchor_dir>/<chain_id>.jsonl` after each commit, never before startup verification, and
//! its output passes (and, once a record is altered, fails) the M2 verifier.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atlas_duck_audit::anchor_dir::{AnchorLine, file_name, parse_line, writer};
use atlas_duck_audit::testing::{self, FakePrune, FaultPoint, Faults, MemKeyring};
use atlas_duck_audit::types::{Confirmed, EventFlags, EventType};
use atlas_duck_audit::verify::{FindingKind, StartupVerdict, VerifyFinding};
use atlas_duck_audit::{
    FilePolicy, OpenConfig, SettingChange, Settings, StartupOutcome, Store, open,
};
use common::*;
use serde_json::json;
use tempfile::TempDir;

// ---------------------------------------------------------------------------------------
// helpers

fn confirmed() -> Confirmed {
    Confirmed {
        dialog_text_sha256: [7; 32],
    }
}

fn dir_text(dir: &Path) -> String {
    dir.to_string_lossy().into_owned()
}

/// A new store whose `anchor_dir` setting (confirmed) names `dir`.
fn store_on(dir: &Path, tweak: impl FnOnce(&mut OpenConfig)) -> (Store, Fixture) {
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), tweak);
    store
        .apply_setting(
            SettingChange::AnchorDir(Some(dir_text(dir))),
            Some(confirmed()),
        )
        .expect("anchor dir setting");
    (store, f)
}

/// A store anchored in a fresh temp dir.
fn anchored() -> (Store, Fixture, TempDir) {
    let dir = tempfile::tempdir().expect("anchor dir");
    let (store, f) = store_on(dir.path(), |_| {});
    (store, f, dir)
}

/// Waits until every queued line is written (the writer thread is asked for one attempt now).
fn drain(store: &Store) {
    assert!(
        store.testing_anchor_dir_drain(),
        "anchor-dir queue not drained"
    );
}

/// The `PRUNE` settings snapshot that keeps the anchor dir in the view.
fn snapshot(dir: &Path) -> serde_json::Value {
    Settings {
        retention_days: 100,
        anchor_dir: Some(dir_text(dir)),
        ..Settings::default()
    }
    .to_json()
}

fn chain_file(dir: &Path, chain_id: &str) -> PathBuf {
    dir.join(file_name(chain_id))
}

/// Every line of the chain file, parsed (each must be a valid anchor line).
fn lines(dir: &Path, chain_id: &str) -> Vec<AnchorLine> {
    let text = std::fs::read_to_string(chain_file(dir, chain_id)).expect("chain file");
    assert!(text.ends_with('\n'), "every line ends with a newline");
    text.lines()
        .map(|l| parse_line(l).unwrap_or_else(|e| panic!("bad line {l:?}: {e}")))
        .collect()
}

/// `(seq, clock_behind, epoch)` of every `Record` line.
fn records(ls: &[AnchorLine]) -> Vec<(u64, bool, Option<String>)> {
    ls.iter()
        .filter_map(|l| match l {
            AnchorLine::Record {
                seq,
                clock_behind,
                epoch,
                ..
            } => Some((*seq, *clock_behind, epoch.clone())),
            _ => None,
        })
        .collect()
}

/// `(seq, event_type)` of every `Immediate` line.
fn immediates(ls: &[AnchorLine]) -> Vec<(u64, String)> {
    ls.iter()
        .filter_map(|l| match l {
            AnchorLine::Immediate {
                seq, event_type, ..
            } => Some((*seq, event_type.clone())),
            _ => None,
        })
        .collect()
}

fn headers(ls: &[AnchorLine]) -> usize {
    ls.iter()
        .filter(|l| matches!(l, AnchorLine::Header { .. }))
        .count()
}

fn row(f: &Fixture, seq: u64) -> RawRow {
    dump_rows(f)
        .into_iter()
        .find(|r| r.seq == seq)
        .unwrap_or_else(|| panic!("row {seq}"))
}

fn flagged(r: &RawRow) -> bool {
    EventFlags::from_bits(r.flags).contains(EventFlags::BEHIND)
}

fn open_ready(f: &Fixture, cfg: OpenConfig) -> (Store, Vec<VerifyFinding>) {
    match open(&f.data, &f.lock, cfg).expect("open") {
        StartupOutcome::Ready { store, verify, .. } => (store, verify.findings),
        other => panic!("not ready: {other:?}"),
    }
}

/// `full_verify` on a fresh handle (anchor writes stay disabled there).
fn full_verify_fresh(f: &Fixture) -> Vec<VerifyFinding> {
    let store = testing::open_existing(&f.data, &f.lock, f.config()).expect("open_existing");
    let out = store.full_verify();
    store.shutdown();
    out
}

fn has(fs: &[VerifyFinding], kind: FindingKind, seq: u64) -> bool {
    fs.iter()
        .any(|x| x.kind == kind && (x.expected_seq == Some(seq) || x.observed_seq == Some(seq)))
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(20);
    while !cond() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn append_one(store: &Store, t: EventType) -> u64 {
    store
        .append(ev(t, None, json!({ "t": t.as_str() })))
        .expect("append")
        .seq
}

// ---------------------------------------------------------------------------------------
// header

#[test]
fn header_line_first_and_fsynced() {
    let (store, f, dir) = anchored();
    corroborate(&store);
    store.append_batch(mixed(3)).expect("append");
    drain(&store);

    let ls = lines(dir.path(), &f.chain_id);
    match &ls[0] {
        AnchorLine::Header {
            chain_id,
            install_id,
            host,
            os_user,
            created_at,
        } => {
            assert_eq!(chain_id, &f.chain_id);
            assert_eq!(install_id, &f.install_id);
            assert!(!host.is_empty() && !os_user.is_empty());
            assert_eq!(created_at, START, "the store's clock");
        }
        other => panic!("line 1 is not a header: {other:?}"),
    }
    assert_eq!(headers(&ls), 1);
    assert!(ls.len() > 1, "the daily line follows the header");

    // The new file, then the directory entry, were flushed; every append flushes the file.
    let file = chain_file(dir.path(), &f.chain_id);
    let syncs = writer::testing_synced_under(dir.path());
    assert!(syncs.len() >= 2, "{syncs:?}");
    assert_eq!(syncs[0], file, "{syncs:?}");
    assert_eq!(syncs[1], dir.path(), "{syncs:?}");
    assert_eq!(syncs.last(), Some(&file), "{syncs:?}");
}

// ---------------------------------------------------------------------------------------
// immediate lines

#[test]
fn u06_immediate_lines_for_six_types() {
    let (store, f, dir) = anchored();
    // seq 1 GENESIS, seq 2 the anchor dir setting (NULL epochs): pruned below.
    corroborate(&store);
    store.append_batch(mixed(4)).expect("append");
    let prune = testing::insert_fake_prune(
        &store,
        FakePrune {
            first_retained_seq: 3,
            cutoff: "2026-06-01".into(),
            settings: snapshot(dir.path()),
            update_first_retained: true,
        },
    )
    .expect("fake prune")
    .seq;
    store.flush_head_anchor().expect("flush");
    let retention = store
        .apply_setting(SettingChange::RetentionDays(120), None)
        .expect("retention")
        .seq;
    let hold = store
        .apply_setting(SettingChange::LegalHold(true), Some(confirmed()))
        .expect("legal hold")
        .seq;
    // An integrity incident and its acknowledgement.
    let verify = testing::apply_startup(
        &store,
        &StartupVerdict {
            findings: vec![VerifyFinding {
                kind: FindingKind::AnchorMissing,
                expected_seq: None,
                expected_hash: None,
                observed_seq: None,
                observed_hash: None,
                detail: "test incident".into(),
            }],
            ..StartupVerdict::default()
        },
    )
    .expect("incident")
    .verify_seq
    .expect("VERIFY");
    let ack = store
        .acknowledge_incident(verify, "alice", "checked")
        .expect("ack")
        .seq;
    // A server three days behind the local clock: a local-ahead CLOCK_ANOMALY.
    let before = store.head().0;
    store.observe_server_date(
        "i1",
        server_time("2026-10-05T12:00:00.000Z"),
        Instant::now(),
    );
    sync_writer(&store);
    let anomaly = store.head().0;
    assert_eq!(anomaly, before + 1);
    assert_eq!(row(&f, anomaly).event_type, "CLOCK_ANOMALY");
    drain(&store);

    let ls = lines(dir.path(), &f.chain_id);
    let got = immediates(&ls);
    for (seq, t) in [
        (prune, "PRUNE"),
        (retention, "CONFIG_CHANGED"),
        (hold, "LEGAL_HOLD_CHANGED"),
        (ack, "INTEGRITY_ACK"),
        (anomaly, "CLOCK_ANOMALY"),
    ] {
        assert!(got.contains(&(seq, t.to_string())), "{t} at {seq}: {got:?}");
    }
    // The incident VERIFY itself and the ordinary rows get none.
    assert!(!got.iter().any(|(s, _)| *s == verify), "{got:?}");
    assert_eq!(got.len(), 5, "{got:?}");
    // RESTORE is the sixth type; its lines come from the restore paths (Task 5).
    for t in [
        "PRUNE",
        "RESTORE",
        "LEGAL_HOLD_CHANGED",
        "INTEGRITY_ACK",
        "CLOCK_ANOMALY",
    ] {
        assert!(writer::gets_immediate_line(t, None), "{t}");
    }
    assert!(writer::gets_immediate_line(
        "CONFIG_CHANGED",
        Some("retention_days")
    ));
    assert!(!writer::gets_immediate_line("VERIFY", None));
    assert!(!writer::gets_immediate_line("APP_STOP", None));
    store.shutdown();

    let fs = full_verify_fresh(&f);
    assert!(fs.is_empty(), "writer lines match the store: {fs:?}");
}

#[test]
fn config_changed_non_policy_key_gets_no_line() {
    let (store, f, dir) = anchored();
    corroborate(&store);
    let ui = store
        .append(ev(
            EventType::CONFIG_CHANGED,
            None,
            json!({ "key": "ui.theme", "old": "light", "new": "dark" }),
        ))
        .expect("append")
        .seq;
    // Instance policy is a policy key of the settings view, but not an audit-policy key (L185).
    let origin = store
        .apply_setting(
            SettingChange::InstanceOrigin {
                instance_id: "jira1".into(),
                origin: Some("https://jira.example.com".into()),
            },
            Some(confirmed()),
        )
        .expect("origin")
        .seq;
    let retention = store
        .apply_setting(SettingChange::RetentionDays(120), None)
        .expect("retention")
        .seq;
    drain(&store);
    let got = immediates(&lines(dir.path(), &f.chain_id));
    assert_eq!(got, vec![(retention, "CONFIG_CHANGED".to_string())]);
    assert!(!got.iter().any(|(s, _)| *s == ui || *s == origin));
    assert!(!writer::gets_immediate_line(
        "CONFIG_CHANGED",
        Some("ui.theme")
    ));
    assert!(!writer::gets_immediate_line(
        "CONFIG_CHANGED",
        Some("instance.jira1.origin")
    ));
    assert!(!writer::gets_immediate_line("CONFIG_CHANGED", None));
}

#[test]
fn allow_degraded_scripts_change_gets_immediate_line() {
    let (store, f, dir) = anchored();
    corroborate(&store);
    let on = store
        .apply_setting(SettingChange::AllowDegradedScripts(true), Some(confirmed()))
        .expect("on")
        .seq;
    let off = store
        .apply_setting(SettingChange::AllowDegradedScripts(false), None)
        .expect("off")
        .seq;
    drain(&store);
    let got = immediates(&lines(dir.path(), &f.chain_id));
    assert_eq!(
        got,
        vec![
            (on, "CONFIG_CHANGED".to_string()),
            (off, "CONFIG_CHANGED".to_string())
        ]
    );
    assert!(writer::gets_immediate_line(
        "CONFIG_CHANGED",
        Some("allow_degraded_scripts")
    ));
}

// ---------------------------------------------------------------------------------------
// daily lines

#[test]
fn daily_line_once_per_epoch_day() {
    let (store, f, dir) = anchored();
    corroborate(&store);
    let first = store.append_batch(mixed(5)).expect("append")[0].seq;
    store.append_batch(mixed(3)).expect("append");
    f.clock.advance(DAY);
    corroborate_now(&store, &f.clock);
    let second = store.append_batch(day_events(3)).expect("append")[0].seq;
    store.flush_head_anchor().expect("flush");
    store.shutdown();

    let want = vec![
        (first, false, Some("2026-10-08".to_string())),
        (second, false, Some("2026-10-09".to_string())),
    ];
    assert_eq!(records(&lines(dir.path(), &f.chain_id)), want);

    // A restart on the same epoch day adds no second daily line, before or after the
    // corroboration of the new process.
    let (store, _) = open_ready(&f, f.config());
    store.append_batch(day_events(2)).expect("append");
    corroborate_now(&store, &f.clock);
    store.append_batch(day_events(2)).expect("append");
    drain(&store);
    assert_eq!(records(&lines(dir.path(), &f.chain_id)), want);

    // The next day gets its line.
    f.clock.advance(DAY);
    corroborate_now(&store, &f.clock);
    let third = append_one(&store, EventType::APP_START);
    drain(&store);
    let got = records(&lines(dir.path(), &f.chain_id));
    assert_eq!(got.len(), 3, "{got:?}");
    assert_eq!(got[2], (third, false, Some("2026-10-10".to_string())));
    store.shutdown();
}

#[test]
fn null_epoch_records_get_no_daily_line() {
    let (store, f, dir) = anchored();
    // Nothing corroborated: every record has a NULL epoch.
    store.append_batch(mixed(6)).expect("append");
    let retention = store
        .apply_setting(SettingChange::RetentionDays(120), None)
        .expect("retention")
        .seq;
    drain(&store);
    assert!(dump_rows(&f).iter().all(|r| r.epoch.is_none()));
    let ls = lines(dir.path(), &f.chain_id);
    assert!(records(&ls).is_empty(), "{ls:?}");
    // An immediate line names a NULL-epoch record with `epoch: null`.
    assert!(ls.iter().any(|l| matches!(l,
        AnchorLine::Immediate { seq, epoch: None, .. } if *seq == retention)));
}

#[test]
fn daily_line_never_past_corroborated_date() {
    // First process: the dates up to 2026-10-13 were corroborated; no anchor dir yet.
    let clock = fake_clock("2026-10-13T12:00:00.000Z");
    let (store, f) = new_store(clock.clone(), MemKeyring::new());
    corroborate_now(&store, &clock);
    store.append_batch(day_events(2)).expect("append");
    let dir = tempfile::tempdir().expect("anchor dir");
    store
        .apply_setting(
            SettingChange::AnchorDir(Some(dir_text(dir.path()))),
            Some(confirmed()),
        )
        .expect("anchor dir");
    store.flush_head_anchor().expect("flush");
    store.shutdown();

    // Second process: before any corroboration the epoch stays at 2026-10-13, uncorroborated
    // in this process; then a server says 2026-10-10. No daily line names a date past the
    // corroborated one.
    let (store, _) = open_ready(&f, f.config());
    store.append_batch(day_events(2)).expect("append");
    store.observe_server_date(
        "i1",
        server_time("2026-10-10T12:00:00.000Z"),
        Instant::now(),
    );
    store.append_batch(day_events(2)).expect("append");
    drain(&store);
    let ls = lines(dir.path(), &f.chain_id);
    assert!(records(&ls).is_empty(), "{ls:?}");
    assert!(
        dump_rows(&f)
            .iter()
            .filter(|r| r.seq > 4)
            .all(|r| r.epoch.as_deref() == Some("2026-10-13")),
        "the epoch stayed at the earlier corroborated date"
    );

    // Once the corroborated date reaches 2026-10-13, the next record gets the day's line.
    store.observe_server_date(
        "i1",
        server_time("2026-10-13T12:00:00.000Z"),
        Instant::now(),
    );
    let seq = append_one(&store, EventType::APP_START);
    drain(&store);
    assert_eq!(
        records(&lines(dir.path(), &f.chain_id)),
        vec![(seq, false, Some("2026-10-13".to_string()))]
    );
    store.shutdown();
}

#[test]
fn first_unflagged_after_clock_behind_gets_line() {
    // A: the first corroboration finds the local clock 2 days behind: the first corroborated
    // record (the CLOCK_ANOMALY) is flagged and its daily line says `clock_behind: true`.
    let dir_a = tempfile::tempdir().expect("anchor dir");
    let (store, f) = store_on(dir_a.path(), |_| {});
    f.clock.set_wall(at("2026-10-07T12:00:00.000Z"));
    store.observe_server_date(
        "i1",
        server_time("2026-10-09T12:00:00.000Z"),
        Instant::now(),
    );
    store.append_batch(day_events(2)).expect("append");
    f.clock.set_wall(at("2026-10-08T12:00:00.000Z"));
    store.append_batch(day_events(2)).expect("append");
    drain(&store);
    let ls = lines(dir_a.path(), &f.chain_id);
    let recs = records(&ls);
    assert_eq!(recs.len(), 2, "{recs:?}");
    for (seq, behind, epoch) in &recs {
        let r = row(&f, *seq);
        assert_eq!(*behind, flagged(&r), "clock_behind exactly when flagged");
        assert_eq!(epoch, &r.epoch);
    }
    assert!(recs[0].1 && !recs[1].1);
    store.shutdown();
    drop(f);

    // B: daily line on 2026-10-08, then a backward episode whose records keep that epoch, then
    // the clock is corrected while the epoch is still 2026-10-08: only the witness rule gives
    // the first unflagged record its line.
    let dir_b = tempfile::tempdir().expect("anchor dir");
    let (store, f) = store_on(dir_b.path(), |_| {});
    corroborate(&store);
    let daily = append_one(&store, EventType::APP_START);
    f.clock.jump_wall_days(-1);
    store.observe_server_date(
        "i1",
        server_time("2026-10-09T12:00:00.000Z"),
        Instant::now(),
    );
    store.append_batch(day_events(2)).expect("append");
    f.clock.set_wall(at("2026-10-08T12:30:00.000Z"));
    let after = store.append_batch(day_events(3)).expect("append");
    drain(&store);
    let rows = dump_rows(&f);
    let behind: Vec<u64> = rows.iter().filter(|r| flagged(r)).map(|r| r.seq).collect();
    assert!(behind.len() >= 3, "episode flagged: {behind:?}");
    let witness = after[0].seq;
    assert_eq!(witness, behind.last().copied().expect("flagged") + 1);
    assert!(!flagged(&row(&f, witness)));
    assert_eq!(row(&f, witness).epoch.as_deref(), Some("2026-10-08"));
    assert_eq!(
        records(&lines(dir_b.path(), &f.chain_id)),
        vec![
            (daily, false, Some("2026-10-08".to_string())),
            (witness, false, Some("2026-10-08".to_string())),
        ]
    );
    store.shutdown();
}

// ---------------------------------------------------------------------------------------
// APP_STOP

#[test]
fn app_stop_line_after_app_stop_commit_and_shutdown_drains() {
    let (store, f, dir) = anchored();
    corroborate(&store);
    store.append_batch(mixed(4)).expect("append");
    let stop = append_one(&store, EventType::APP_STOP);
    let t = Instant::now();
    store.shutdown();
    assert!(t.elapsed() < Duration::from_secs(5), "bounded drain");
    let ls = lines(dir.path(), &f.chain_id);
    let r = row(&f, stop);
    assert_eq!(
        ls.last(),
        Some(&AnchorLine::Record {
            seq: stop,
            record_hash: r.record_hash,
            epoch: r.epoch.clone(),
            clock_behind: false,
        })
    );
}

#[test]
fn pending_app_stop_line_written_at_next_start() {
    let base = tempfile::tempdir().expect("base");
    let dir = base.path().join("anchors");
    let (store, f) = store_on(&dir, |_| {});
    corroborate(&store);
    store.append_batch(mixed(3)).expect("append");
    let stop = append_one(&store, EventType::APP_STOP);
    store.flush_head_anchor().expect("flush");
    let t = Instant::now();
    store.shutdown();
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "a failing drain is bounded"
    );
    assert!(!dir.exists(), "the share was offline");

    // The share is back: the next start writes the pending APP_STOP line once.
    std::fs::create_dir(&dir).expect("anchor dir");
    let (store, _) = open_ready(&f, f.config());
    drain(&store);
    let stop_lines = |ls: &[AnchorLine]| {
        records(ls)
            .into_iter()
            .filter(|(s, _, _)| *s == stop)
            .count()
    };
    let ls = lines(&dir, &f.chain_id);
    assert!(matches!(ls[0], AnchorLine::Header { .. }));
    assert_eq!(stop_lines(&ls), 1, "{ls:?}");
    store.shutdown();

    // A later start does not write it again.
    let (store, _) = open_ready(&f, f.config());
    drain(&store);
    store.shutdown();
    assert_eq!(stop_lines(&lines(&dir, &f.chain_id)), 1);
    assert!(full_verify_fresh(&f).is_empty());
}

// ---------------------------------------------------------------------------------------
// prune lines

#[test]
fn prune_writes_prune_and_immediate_lines() {
    let (store, f, dir) = anchored();
    store
        .apply_setting(SettingChange::RetentionDays(92), Some(confirmed()))
        .expect("retention");
    store
        .reconcile_config_file(&FilePolicy::default())
        .expect("reconciled");
    corroborate(&store);
    store.append_batch(day_events(3)).expect("append");
    // 100 days later the head's epoch advance runs a prune (clamped to baseline + 2).
    f.clock.advance(DAY * 100);
    corroborate_now(&store, &f.clock);
    append_one(&store, EventType::APP_START);
    sync_writer(&store);
    store.flush_head_anchor().expect("flush");
    drain(&store);

    let c = raw_conn(&f);
    let mut st = c
        .prepare(
            "SELECT prune_seq, first_retained_seq, last_pruned_record_hash, cutoff_epoch \
             FROM prune_log ORDER BY prune_seq",
        )
        .expect("prepare");
    let log: Vec<(u64, u64, Vec<u8>, String)> = st
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, i64>(1)? as u64,
                r.get(2)?,
                r.get(3)?,
            ))
        })
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    assert!(!log.is_empty(), "a prune ran");
    let ls = lines(dir.path(), &f.chain_id);
    let got = immediates(&ls);
    for (prune_seq, frs, last, cutoff) in &log {
        let want = AnchorLine::Prune {
            first_retained_seq: *frs,
            first_retained_prev_hash: last.clone().try_into().expect("32 bytes"),
            cutoff_epoch: cutoff.clone(),
        };
        assert!(ls.contains(&want), "{want:?} in {ls:?}");
        assert!(got.contains(&(*prune_seq, "PRUNE".to_string())), "{got:?}");
    }
    store.shutdown();
    let fs = full_verify_fresh(&f);
    assert!(fs.is_empty(), "{fs:?}");
}

#[test]
fn interrupted_prune_appends_missing_prune_line() {
    let (store, f, dir) = anchored();
    corroborate(&store);
    store.append_batch(mixed(10)).expect("append");
    store.flush_head_anchor().expect("flush");
    drain(&store);
    // A crash right after the PRUNE commit: neither the first-retained update nor the
    // anchor-dir lines happened.
    store.testing_pause_anchors();
    let prune = testing::insert_fake_prune(
        &store,
        FakePrune {
            first_retained_seq: 3,
            cutoff: "2026-06-01".into(),
            settings: snapshot(dir.path()),
            update_first_retained: false,
        },
    )
    .expect("fake prune")
    .seq;
    store.shutdown();
    let is_prune_line = |l: &AnchorLine| matches!(l, AnchorLine::Prune { .. });
    assert!(!lines(dir.path(), &f.chain_id).iter().any(is_prune_line));

    let (store, findings) = open_ready(&f, f.config());
    assert!(
        findings
            .iter()
            .any(|x| x.kind == FindingKind::InterruptedPruneReconciled),
        "{findings:?}"
    );
    drain(&store);
    store.shutdown();
    let ls = lines(dir.path(), &f.chain_id);
    let p = ls.iter().filter(|l| is_prune_line(l)).count();
    assert_eq!(p, 1, "{ls:?}");
    assert!(ls.contains(&AnchorLine::Prune {
        first_retained_seq: 3,
        first_retained_prev_hash: row_hash_of(&f, 2),
        cutoff_epoch: "2026-06-01".into(),
    }));
    assert!(immediates(&ls).contains(&(prune, "PRUNE".to_string())));
    let fs = full_verify_fresh(&f);
    assert!(fs.is_empty(), "{fs:?}");
}

/// The `last_pruned_record_hash` of the `prune_log` row whose first retained seq is `seq + 1`.
fn row_hash_of(f: &Fixture, seq: u64) -> [u8; 32] {
    let h: Vec<u8> = raw_conn(f)
        .query_row(
            "SELECT last_pruned_record_hash FROM prune_log WHERE first_retained_seq = ?1",
            [(seq + 1) as i64],
            |r| r.get(0),
        )
        .expect("prune_log row");
    h.try_into().expect("32 bytes")
}

// ---------------------------------------------------------------------------------------
// the enable() gate

#[test]
fn no_anchor_dir_line_before_verification() {
    let (store, f, dir) = anchored();
    corroborate(&store);
    store.append_batch(mixed(3)).expect("append");
    let stop = append_one(&store, EventType::APP_STOP);
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    let file = chain_file(dir.path(), &f.chain_id);
    std::fs::remove_file(&file).expect("remove chain file");

    // open(): nothing is written until the startup VERIFY step is behind it.
    let faults = Faults::new();
    let seen = Arc::new(Mutex::new(None::<bool>));
    {
        let (seen, file) = (seen.clone(), file.clone());
        faults.on_hit(FaultPoint::AfterStartupVerifyAppend, move || {
            *seen.lock().expect("lock") = Some(file.exists());
        });
    }
    let mut cfg = f.config();
    cfg.hooks.faults = Some(faults);
    let (store, _) = open_ready(&f, cfg);
    assert_eq!(
        *seen.lock().expect("lock"),
        Some(false),
        "no file before enable"
    );
    drain(&store);
    let ls = lines(dir.path(), &f.chain_id);
    assert!(matches!(ls[0], AnchorLine::Header { .. }));
    assert!(records(&ls).iter().any(|(s, _, _)| *s == stop), "{ls:?}");
    store.shutdown();

    // A handle whose anchor writes are disabled writes nothing, also for immediate types.
    std::fs::remove_file(&file).expect("remove chain file");
    let store = testing::open_existing(&f.data, &f.lock, f.config()).expect("open_existing");
    let retention = store
        .apply_setting(SettingChange::RetentionDays(120), None)
        .expect("retention")
        .seq;
    assert!(!store.testing_anchor_dir_drain(), "held until enable");
    assert!(!file.exists());
    assert!(store.health().anchor_dir_lines_pending > 0);
    store.testing_enable_anchors();
    drain(&store);
    assert!(
        immediates(&lines(dir.path(), &f.chain_id)).contains(&(retention, "CONFIG_CHANGED".into()))
    );
    assert_eq!(store.health().anchor_dir_lines_pending, 0);
    store.shutdown();
}

// ---------------------------------------------------------------------------------------
// failures

#[test]
fn write_failure_sets_health_and_retries_no_incident() {
    let base = tempfile::tempdir().expect("base");
    let dir = base.path().join("offline");
    let (store, f) = store_on(&dir, |cfg| cfg.hooks.fast_anchor_backoff = true);
    corroborate(&store);
    let retention = store
        .apply_setting(SettingChange::RetentionDays(120), None)
        .expect("retention")
        .seq;
    wait_until("write failure in health", || {
        store.health().anchor_dir_write_failing
    });
    let h = store.health();
    assert!(h.anchor_dir_lines_pending > 0, "{h:?}");
    assert!(
        !h.anchor_write_failing,
        "the keychain anchors are fine: {h:?}"
    );
    // Commits go on while the anchor dir fails.
    append_one(&store, EventType::APP_START);

    std::fs::create_dir(&dir).expect("share back");
    wait_until("retry succeeded", || {
        let h = store.health();
        !h.anchor_dir_write_failing && h.anchor_dir_lines_pending == 0
    });
    let ls = lines(&dir, &f.chain_id);
    assert!(matches!(ls[0], AnchorLine::Header { .. }));
    assert!(immediates(&ls).contains(&(retention, "CONFIG_CHANGED".into())));
    assert!(store.open_incidents().is_empty());
    store.shutdown();
    let types = testing::event_types(&f.data).expect("event types");
    assert!(!types.iter().any(|t| t == "VERIFY"), "{types:?}");
}

#[test]
fn missing_current_chain_file_recreated_with_header() {
    let (store, f, dir) = anchored();
    corroborate(&store);
    store.append_batch(mixed(3)).expect("append");
    drain(&store);
    let file = chain_file(dir.path(), &f.chain_id);
    std::fs::remove_file(&file).expect("remove");

    // While running: the next line recreates it, header first.
    let retention = store
        .apply_setting(SettingChange::RetentionDays(120), None)
        .expect("retention")
        .seq;
    drain(&store);
    let ls = lines(dir.path(), &f.chain_id);
    assert!(matches!(ls[0], AnchorLine::Header { .. }), "{ls:?}");
    assert_eq!(headers(&ls), 1);
    assert_eq!(immediates(&ls), vec![(retention, "CONFIG_CHANGED".into())]);
    store.flush_head_anchor().expect("flush");
    store.shutdown();

    // At a start: the current chain's file is created with its header, no line needed.
    std::fs::remove_file(&file).expect("remove");
    let (store, _) = open_ready(&f, f.config());
    drain(&store);
    let ls = lines(dir.path(), &f.chain_id);
    assert_eq!(ls.len(), 1, "{ls:?}");
    assert!(matches!(ls[0], AnchorLine::Header { .. }));
    store.shutdown();
}

// ---------------------------------------------------------------------------------------
// U-06: writer output against the verifier

#[test]
fn u06_writer_lines_then_tamper_fails_verify() {
    let (store, f, dir) = anchored();
    corroborate(&store);
    store.append_batch(mixed(6)).expect("append");
    day(&store, &f.clock, 4);
    store
        .apply_setting(SettingChange::RetentionDays(120), None)
        .expect("retention");
    day(&store, &f.clock, 4);
    append_one(&store, EventType::APP_STOP);
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    assert!(
        full_verify_fresh(&f).is_empty(),
        "the writer's lines verify"
    );

    let recs = records(&lines(dir.path(), &f.chain_id));
    assert!(recs.len() >= 4, "{recs:?}");
    // An attacker without the anchor dir rewrites the record of the second daily line and
    // rehashes everything after it, keychain head anchor included.
    let k = recs[1].0;
    raw_conn(&f)
        .execute(
            "UPDATE events SET target = 'PROJ-forged' WHERE seq = ?1",
            [k as i64],
        )
        .expect("tamper");
    let head = rehash_from(&f, k);
    set_keychain_head(&f, &head);
    let fs = full_verify_fresh(&f);
    assert!(
        !fs.iter().any(|x| matches!(
            x.kind,
            FindingKind::ChainBroken | FindingKind::AnchorMismatch
        )),
        "the chain and the keychain are consistent: {fs:?}"
    );
    assert!(has(&fs, FindingKind::AnchorDirMismatch, k), "{fs:?}");
}
