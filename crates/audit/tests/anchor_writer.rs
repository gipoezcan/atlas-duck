//! The anchor-directory writer (§8.5, §8.7, PD-156, PD-157, PD-164..PD-166; U-06 writer half):
//! the `audit-anchor-dir` thread appends header, daily, `APP_STOP`, immediate, prune and
//! `RESTORE` lines to `<anchor_dir>/<chain_id>.jsonl` after each commit, never before startup
//! verification, and its output passes (and, once a record is altered, fails) the M2 verifier.
//! `Store::change_anchor_dir` opens the new dir's file first and leaves an `ANCHOR_DETACHED`
//! line in the old one; incident files sit beside the chain files; a torn last line is
//! tolerated by both the writer and the verifier.

mod common;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atlas_duck_audit::anchor_dir::{AnchorLine, file_name, parse_line, to_line, writer};
use atlas_duck_audit::error::AuditError;
use atlas_duck_audit::testing::{self, FakePrune, FaultPoint, Faults, MemKeyring};
use atlas_duck_audit::types::{Confirmed, EventFlags, EventType, RustChosenPath};
use atlas_duck_audit::verify::{FindingKind, StartupVerdict, VerifyFinding};
use atlas_duck_audit::{
    FilePolicy, LockedReason, OpenConfig, RecoveryOffer, SettingChange, Settings, StartupOutcome,
    Store, finish_restore, open, restore_from_source,
};
use common::*;
use secrecy::SecretString;
use serde_json::{Value, json};
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

fn chosen(p: &Path) -> RustChosenPath {
    RustChosenPath::from_native_dialog(p.to_path_buf())
}

/// A new store whose anchor dir is `dir` (an existing dir), set by `change_anchor_dir`.
fn store_on(dir: &Path, tweak: impl FnOnce(&mut OpenConfig)) -> (Store, Fixture) {
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), tweak);
    store
        .change_anchor_dir(Some(chosen(dir)), confirmed())
        .expect("anchor dir setting");
    (store, f)
}

/// The same for a dir that does not exist (an offline share): `change_anchor_dir` refuses it
/// (PD-166: the new dir's file is opened first), so the testing setter logs the setting.
fn store_on_offline(dir: &Path, tweak: impl FnOnce(&mut OpenConfig)) -> (Store, Fixture) {
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), tweak);
    store
        .testing_set_anchor_dir(Some(dir_text(dir)), confirmed())
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
        // The anchor dir setting itself (PD-166: its line reaches the new dir).
        (2, "CONFIG_CHANGED"),
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
    assert_eq!(got.len(), 6, "{got:?}");
    // RESTORE is the sixth type; its lines come from the restore paths
    // (`restore_writes_restore_line_to_new_chain_file`).
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
    assert_eq!(
        got,
        vec![
            (2, "CONFIG_CHANGED".to_string()),
            (retention, "CONFIG_CHANGED".to_string())
        ]
    );
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
    // A legal hold change is its own type, `LEGAL_HOLD_CHANGED` (L185), never a
    // `CONFIG_CHANGED` key.
    assert!(!writer::gets_immediate_line(
        "CONFIG_CHANGED",
        Some("legal_hold")
    ));
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
            (2, "CONFIG_CHANGED".to_string()),
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
        .change_anchor_dir(Some(chosen(dir.path())), confirmed())
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
    let (store, f) = store_on_offline(&dir, |_| {});
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

#[test]
fn committed_prune_lines_lost_with_the_dir_are_written_at_next_start() {
    let base = tempfile::tempdir().expect("base");
    let dir = base.path().join("anchors");
    std::fs::create_dir(&dir).expect("anchor dir");
    let (store, f) = store_on(&dir, |_| {});
    corroborate(&store);
    store.append_batch(mixed(10)).expect("append");
    store.flush_head_anchor().expect("flush");
    drain(&store);
    // The share goes offline; the PRUNE commits and its first-retained update reaches the
    // keychain, but its anchor-dir lines are lost at quit.
    let away = base.path().join("away");
    std::fs::rename(&dir, &away).expect("share offline");
    let prune = testing::insert_fake_prune(
        &store,
        FakePrune {
            first_retained_seq: 3,
            cutoff: "2026-06-01".into(),
            settings: snapshot(&dir),
            update_first_retained: true,
        },
    )
    .expect("fake prune")
    .seq;
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    std::fs::rename(&away, &dir).expect("share back");
    let is_prune_line = |l: &AnchorLine| matches!(l, AnchorLine::Prune { .. });
    assert!(!lines(&dir, &f.chain_id).iter().any(is_prune_line));

    // The next start appends them once; not an interrupted prune (the keychain has it).
    let counts = |ls: &[AnchorLine]| {
        (
            ls.iter().filter(|l| is_prune_line(l)).count(),
            immediates(ls)
                .iter()
                .filter(|i| **i == (prune, "PRUNE".to_string()))
                .count(),
        )
    };
    let (store, findings) = open_ready(&f, f.config());
    assert!(
        !findings
            .iter()
            .any(|x| x.kind == FindingKind::InterruptedPruneReconciled),
        "{findings:?}"
    );
    drain(&store);
    store.shutdown();
    let ls = lines(&dir, &f.chain_id);
    assert_eq!(counts(&ls), (1, 1), "{ls:?}");
    assert!(ls.contains(&AnchorLine::Prune {
        first_retained_seq: 3,
        first_retained_prev_hash: row_hash_of(&f, 2),
        cutoff_epoch: "2026-06-01".into(),
    }));

    // A later start does not write them again.
    let (store, _) = open_ready(&f, f.config());
    drain(&store);
    store.shutdown();
    assert_eq!(counts(&lines(&dir, &f.chain_id)), (1, 1));
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
    let (store, f) = store_on_offline(&dir, |cfg| cfg.hooks.fast_anchor_backoff = true);
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

/// Whether the chain file holds `(seq, event_type)` as an immediate line; tolerates a file
/// being appended to meanwhile (a torn last line is skipped).
fn holds_immediate(dir: &Path, chain_id: &str, want: &(u64, String)) -> bool {
    let Ok(text) = std::fs::read_to_string(chain_file(dir, chain_id)) else {
        return false;
    };
    let ls: Vec<AnchorLine> = text.lines().filter_map(|l| parse_line(l).ok()).collect();
    immediates(&ls).contains(want)
}

#[test]
fn failing_old_dir_does_not_block_the_new_dirs_lines() {
    let base = tempfile::tempdir().expect("base");
    let old = base.path().join("offline");
    let (store, f) = store_on_offline(&old, |_| {});
    corroborate(&store);
    store.append_batch(mixed(3)).expect("append");
    wait_until("old dir failing", || {
        store.health().anchor_dir_write_failing
    });

    // The user switches to a reachable dir: its lines are written right after their commit,
    // without a forced attempt, while the old dir's lines stay queued.
    let new = base.path().join("local");
    std::fs::create_dir(&new).expect("new dir");
    store
        .change_anchor_dir(Some(chosen(&new)), confirmed())
        .expect("switch");
    let retention = store
        .apply_setting(SettingChange::RetentionDays(120), None)
        .expect("retention")
        .seq;
    let want = (retention, "CONFIG_CHANGED".to_string());
    wait_until("the new dir's line", || {
        holds_immediate(&new, &f.chain_id, &want)
    });
    let h = store.health();
    assert!(h.anchor_dir_write_failing, "the old dir still fails: {h:?}");
    assert!(h.anchor_dir_lines_pending > 0, "{h:?}");

    // A forced attempt (as at quit) writes the new dir's lines and leaves the old dir's queued.
    let hold = store
        .apply_setting(SettingChange::LegalHold(true), Some(confirmed()))
        .expect("legal hold")
        .seq;
    assert!(!store.testing_anchor_dir_drain(), "the old dir's lines");
    let ls = lines(&new, &f.chain_id);
    assert!(matches!(ls[0], AnchorLine::Header { .. }), "{ls:?}");
    assert_eq!(headers(&ls), 1);
    let got = immediates(&ls);
    assert!(got.contains(&want), "{got:?}");
    assert!(
        got.contains(&(hold, "LEGAL_HOLD_CHANGED".to_string())),
        "{got:?}"
    );
    assert!(store.health().anchor_dir_write_failing);
    assert!(!old.exists());
    let t = Instant::now();
    store.shutdown();
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "a failing drain is bounded"
    );
}

#[test]
fn first_run_creates_the_chain_file_with_its_header() {
    let dir = tempfile::tempdir().expect("anchor dir");
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |cfg| {
        cfg.anchor_dir = Some(dir.path().to_path_buf());
    });
    // No line is due yet (GENESIS has a NULL epoch), but the file and its header exist.
    drain(&store);
    let ls = lines(dir.path(), &f.chain_id);
    assert_eq!(ls.len(), 1, "{ls:?}");
    assert!(matches!(ls[0], AnchorLine::Header { .. }), "{ls:?}");
    store.shutdown();
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

// ---------------------------------------------------------------------------------------
// Task 5 helpers

fn pass(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn kinds(fs: &[VerifyFinding]) -> Vec<FindingKind> {
    fs.iter().map(|x| x.kind).collect()
}

fn payload(store: &Store, seq: u64) -> Value {
    serde_json::from_slice(&store.read_payload(seq).expect("read_payload")).expect("json")
}

fn immediate_of(r: &RawRow) -> AnchorLine {
    AnchorLine::Immediate {
        seq: r.seq,
        record_hash: r.record_hash,
        epoch: r.epoch.clone(),
        event_type: r.event_type.clone(),
    }
}

fn record_of(r: &RawRow) -> AnchorLine {
    AnchorLine::Record {
        seq: r.seq,
        record_hash: r.record_hash,
        epoch: r.epoch.clone(),
        clock_behind: flagged(r),
    }
}

/// The first half of a valid line: what a crash in the middle of an append leaves behind.
fn fragment() -> String {
    let full = to_line(&AnchorLine::Record {
        seq: 99,
        record_hash: [3; 32],
        epoch: Some("2026-10-08".into()),
        clock_behind: false,
    });
    full[..full.len() / 2].to_string()
}

fn append_raw(path: &Path, bytes: &[u8]) {
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open for append")
        .write_all(bytes)
        .expect("append");
}

/// Every line of the chain file except `skip` (a planted fragment), parsed.
fn lines_but(dir: &Path, chain_id: &str, skip: &str) -> Vec<AnchorLine> {
    let text = std::fs::read_to_string(chain_file(dir, chain_id)).expect("chain file");
    assert!(text.ends_with('\n'), "every line ends with a newline");
    text.lines()
        .filter(|l| *l != skip)
        .map(|l| parse_line(l).unwrap_or_else(|e| panic!("bad line {l:?}: {e}")))
        .collect()
}

fn incident_file(dir: &Path, chain_id: &str, verify_seq: u64) -> PathBuf {
    dir.join(format!("{chain_id}.incident-{verify_seq}.json"))
}

/// An integrity-incident verdict (its `VERIFY` is flagged).
fn incident(detail: &str) -> StartupVerdict {
    StartupVerdict {
        findings: vec![VerifyFinding {
            kind: FindingKind::AnchorMissing,
            expected_seq: Some(1),
            expected_hash: Some([1; 32]),
            observed_seq: Some(2),
            observed_hash: None,
            detail: detail.into(),
        }],
        ..StartupVerdict::default()
    }
}

/// The restored chain's file: one header naming it, then exactly one `Record` and one
/// `Immediate` line for its `RESTORE`.
fn assert_restore_lines(dir: &Path, f: &Fixture, chain_id: &str, restore_seq: u64) {
    let r = row(f, restore_seq);
    assert_eq!(r.event_type, "RESTORE");
    assert_eq!(r.chain_id, chain_id);
    let ls = lines(dir, chain_id);
    match &ls[0] {
        AnchorLine::Header {
            chain_id: c,
            install_id,
            ..
        } => {
            assert_eq!(c, chain_id);
            assert_eq!(install_id, &f.install_id);
        }
        other => panic!("line 1 is not a header: {other:?}"),
    }
    assert_eq!(headers(&ls), 1, "{ls:?}");
    let count = |want: &AnchorLine| ls.iter().filter(|l| *l == want).count();
    assert_eq!(count(&record_of(&r)), 1, "{ls:?}");
    assert_eq!(count(&immediate_of(&r)), 1, "{ls:?}");
}

/// Every file under `base` (one level of subdirectories), with its bytes.
fn files_under(base: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(base).expect("read_dir") {
        let p = e.expect("entry").path();
        if p.is_dir() {
            for e in std::fs::read_dir(&p).expect("read_dir") {
                let q = e.expect("entry").path();
                out.insert(q.clone(), std::fs::read(&q).expect("read"));
            }
        } else {
            out.insert(p.clone(), std::fs::read(&p).expect("read"));
        }
    }
    out
}

/// Every file of `before` still exists and starts with its earlier bytes (append-only).
fn only_appended(before: &BTreeMap<PathBuf, Vec<u8>>, after: &BTreeMap<PathBuf, Vec<u8>>) {
    for (p, old) in before {
        let new = after
            .get(p)
            .unwrap_or_else(|| panic!("{} was deleted or renamed", p.display()));
        assert!(
            new.starts_with(old),
            "{} was truncated or rewritten",
            p.display()
        );
    }
}

/// Seq of the newest `RESTORE` and its `new_chain_id`, read from a closed store.
fn latest_restore(f: &Fixture) -> (u64, String) {
    let r = dump_rows(f)
        .into_iter()
        .rfind(|r| r.event_type == "RESTORE")
        .expect("a RESTORE row");
    (r.seq, r.chain_id)
}

// ---------------------------------------------------------------------------------------
// change and removal of the anchor dir (PD-166)

#[test]
fn u06_change_anchor_dir_writes_detached_first() {
    let base = tempfile::tempdir().expect("base");
    let (a, b) = (base.path().join("a"), base.path().join("b"));
    std::fs::create_dir(&a).expect("a");
    std::fs::create_dir(&b).expect("b");
    let (store, f) = store_on(&a, |_| {});
    corroborate(&store);
    store.append_batch(mixed(3)).expect("append");
    drain(&store);

    let c = store
        .change_anchor_dir(Some(chosen(&b)), confirmed())
        .expect("switch");
    drain(&store);
    assert_eq!(store.settings().anchor_dir, Some(dir_text(&b)));
    let p = payload(&store, c.seq);
    assert_eq!(p["key"], "anchor_dir");
    assert_eq!(p["source"], "app");
    assert_eq!(p["old"], dir_text(&a).as_str());
    assert_eq!(p["new"], dir_text(&b).as_str());
    assert_eq!(p["applied"], true);
    assert_eq!(p["confirmed"]["dialog_text_sha256"], hex::encode([7u8; 32]));

    // The old dir: the record's immediate line, then ANCHOR_DETACHED naming it.
    let r = row(&f, c.seq);
    let old = lines(&a, &f.chain_id);
    let n = old.len();
    assert_eq!(old[n - 2], immediate_of(&r), "{old:?}");
    assert_eq!(
        old[n - 1],
        AnchorLine::Detached {
            seq: c.seq,
            record_hash: r.record_hash,
            epoch: r.epoch.clone(),
            detached_at: START.into(),
        },
        "{old:?}"
    );
    // The new dir starts with a header, then the same immediate line.
    let new = lines(&b, &f.chain_id);
    assert!(matches!(new[0], AnchorLine::Header { .. }), "{new:?}");
    assert_eq!(new[1..].to_vec(), vec![immediate_of(&r)]);
    // Order: the new file was created (and fsynced) first, the old dir's ANCHOR_DETACHED went
    // out before the new dir's line.
    let syncs = writer::testing_synced_under(base.path());
    let last = |p: &Path| syncs.iter().rposition(|s| s == p).expect("synced");
    let first = |p: &Path| syncs.iter().position(|s| s == p).expect("synced");
    let (fa, fb) = (chain_file(&a, &f.chain_id), chain_file(&b, &f.chain_id));
    assert!(first(&fb) < last(&fa), "{syncs:?}");
    assert!(last(&fa) < last(&fb), "{syncs:?}");

    // Later lines go to the new dir only.
    let before = std::fs::read(&fa).expect("old file");
    let retention = store
        .apply_setting(SettingChange::RetentionDays(120), None)
        .expect("retention")
        .seq;
    drain(&store);
    assert_eq!(std::fs::read(&fa).expect("old file"), before);
    assert!(immediates(&lines(&b, &f.chain_id)).contains(&(retention, "CONFIG_CHANGED".into())));
    store.shutdown();
    let fs = full_verify_fresh(&f);
    assert!(fs.is_empty(), "{fs:?}");
}

#[test]
fn remove_anchor_dir_writes_detached_only() {
    let base = tempfile::tempdir().expect("base");
    let a = base.path().join("a");
    std::fs::create_dir(&a).expect("a");
    let (store, f) = store_on(&a, |_| {});
    corroborate(&store);
    store.append_batch(mixed(3)).expect("append");
    let c = store.change_anchor_dir(None, confirmed()).expect("remove");
    drain(&store);
    assert_eq!(store.settings().anchor_dir, None);
    let p = payload(&store, c.seq);
    assert_eq!(p["old"], dir_text(&a).as_str());
    assert_eq!(p["new"], Value::Null);

    let r = row(&f, c.seq);
    let ls = lines(&a, &f.chain_id);
    let n = ls.len();
    assert_eq!(ls[n - 2], immediate_of(&r), "{ls:?}");
    assert!(
        matches!(&ls[n - 1], AnchorLine::Detached { seq, .. } if *seq == c.seq),
        "{ls:?}"
    );
    // Nothing is written anywhere afterwards: not on a new day, not at quit, not at a start.
    let file = chain_file(&a, &f.chain_id);
    let before = std::fs::read(&file).expect("file");
    f.clock.advance(DAY);
    corroborate_now(&store, &f.clock);
    store.append_batch(day_events(2)).expect("append");
    append_one(&store, EventType::APP_STOP);
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    let (store, _) = open_ready(&f, f.config());
    store.append_batch(day_events(2)).expect("append");
    drain(&store);
    store.shutdown();
    assert_eq!(std::fs::read(&file).expect("file"), before);
    assert_eq!(files_under(base.path()).len(), 1, "no other file was made");
}

#[test]
fn old_dir_write_failure_does_not_block_switch() {
    let base = tempfile::tempdir().expect("base");
    let old = base.path().join("offline");
    let new = base.path().join("local");
    std::fs::create_dir(&new).expect("new dir");
    let (store, f) = store_on_offline(&old, |cfg| cfg.hooks.fast_anchor_backoff = true);
    corroborate(&store);
    store.append_batch(mixed(3)).expect("append");
    wait_until("old dir failing", || {
        store.health().anchor_dir_write_failing
    });

    // The old dir cannot take its ANCHOR_DETACHED line: the switch happens anyway.
    let c = store
        .change_anchor_dir(Some(chosen(&new)), confirmed())
        .expect("switch despite the old dir");
    assert_eq!(store.settings().anchor_dir, Some(dir_text(&new)));
    let want = (c.seq, "CONFIG_CHANGED".to_string());
    wait_until("the new dir's line", || {
        holds_immediate(&new, &f.chain_id, &want)
    });
    let h = store.health();
    assert!(h.anchor_dir_write_failing, "shown in health: {h:?}");
    assert!(h.anchor_dir_lines_pending > 0, "{h:?}");
    assert!(store.open_incidents().is_empty());
    let ls = lines(&new, &f.chain_id);
    assert!(matches!(ls[0], AnchorLine::Header { .. }), "{ls:?}");
    assert_eq!(headers(&ls), 1);

    // The old share comes back: its queued lines end with the ANCHOR_DETACHED line.
    std::fs::create_dir(&old).expect("share back");
    wait_until("the old dir's lines", || {
        let h = store.health();
        !h.anchor_dir_write_failing && h.anchor_dir_lines_pending == 0
    });
    let r = row(&f, c.seq);
    let ls = lines(&old, &f.chain_id);
    let n = ls.len();
    assert_eq!(ls[n - 2], immediate_of(&r), "{ls:?}");
    assert!(
        matches!(&ls[n - 1], AnchorLine::Detached { seq, .. } if *seq == c.seq),
        "{ls:?}"
    );
    store.shutdown();
}

#[test]
fn switch_back_to_earlier_dir_appends_without_new_header() {
    let base = tempfile::tempdir().expect("base");
    let (a, b) = (base.path().join("a"), base.path().join("b"));
    std::fs::create_dir(&a).expect("a");
    std::fs::create_dir(&b).expect("b");
    let (store, f) = store_on(&a, |_| {});
    corroborate(&store);
    store.append_batch(mixed(2)).expect("append");
    let to_b = store
        .change_anchor_dir(Some(chosen(&b)), confirmed())
        .expect("to b")
        .seq;
    drain(&store);
    // A crash had torn A's last line (PD-165): the switch back closes it first.
    let fa = chain_file(&a, &f.chain_id);
    let frag = fragment();
    append_raw(&fa, frag.as_bytes());
    let a_before = std::fs::read(&fa).expect("a");

    let back = store
        .change_anchor_dir(Some(chosen(&a)), confirmed())
        .expect("back to a")
        .seq;
    drain(&store);
    let after = std::fs::read(&fa).expect("a");
    assert!(after.starts_with(&a_before), "only appended to");
    let ls = lines_but(&a, &f.chain_id, &frag);
    assert_eq!(headers(&ls), 1, "no second header: {ls:?}");
    assert!(matches!(ls[0], AnchorLine::Header { .. }));
    assert_eq!(ls.last(), Some(&immediate_of(&row(&f, back))), "{ls:?}");
    // The fragment became a line of its own, followed by a Record line.
    let text = String::from_utf8(after).expect("utf-8");
    let raw: Vec<&str> = text.lines().collect();
    let i = raw.iter().position(|l| *l == frag).expect("fragment line");
    assert!(
        matches!(parse_line(raw[i + 1]), Ok(AnchorLine::Record { .. })),
        "{raw:?}"
    );
    // B: its header, the line of the switch to it, the switch back's lines (its daily line
    // too: B had none of that day) and ANCHOR_DETACHED last.
    let lb = lines(&b, &f.chain_id);
    assert!(matches!(lb[0], AnchorLine::Header { .. }));
    assert_eq!(headers(&lb), 1);
    assert_eq!(
        immediates(&lb),
        vec![
            (to_b, "CONFIG_CHANGED".to_string()),
            (back, "CONFIG_CHANGED".to_string())
        ]
    );
    assert!(
        matches!(lb.last(), Some(AnchorLine::Detached { seq, .. }) if *seq == back),
        "{lb:?}"
    );
    store.shutdown();
    let fs = full_verify_fresh(&f);
    assert_eq!(kinds(&fs), vec![FindingKind::AnchorDirTornLine], "{fs:?}");
}

#[test]
fn writer_does_not_duplicate_header_after_change_anchor_dir() {
    // The setting names a dir the writer already created the file in (first run against
    // `OpenConfig.anchor_dir`): change_anchor_dir finds the file and writes no header.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |cfg| {
        cfg.anchor_dir = Some(dir.path().to_path_buf());
    });
    drain(&store);
    let c = store
        .change_anchor_dir(Some(chosen(dir.path())), confirmed())
        .expect("same dir as the setting");
    corroborate(&store);
    store.append_batch(mixed(5)).expect("append");
    drain(&store);
    let ls = lines(dir.path(), &f.chain_id);
    assert!(matches!(ls[0], AnchorLine::Header { .. }), "{ls:?}");
    assert_eq!(headers(&ls), 1, "{ls:?}");
    assert!(immediates(&ls).contains(&(c.seq, "CONFIG_CHANGED".into())));

    // A new dir: change_anchor_dir writes the header, the thread only appends, also after a
    // restart (whose "ensure file" item finds the file).
    let other = tempfile::tempdir().expect("other dir");
    let c2 = store
        .change_anchor_dir(Some(chosen(other.path())), confirmed())
        .expect("other dir");
    store.append_batch(mixed(5)).expect("append");
    drain(&store);
    store.shutdown();
    let (store, _) = open_ready(&f, f.config());
    store.append_batch(mixed(2)).expect("append");
    drain(&store);
    store.shutdown();
    let ls = lines(other.path(), &f.chain_id);
    assert!(matches!(ls[0], AnchorLine::Header { .. }), "{ls:?}");
    assert_eq!(headers(&ls), 1, "{ls:?}");
    assert!(immediates(&ls).contains(&(c2.seq, "CONFIG_CHANGED".into())));

    // An existing empty file (a crash between its creation and its header) gets one header.
    let empty = tempfile::tempdir().expect("empty dir");
    std::fs::write(chain_file(empty.path(), &f.chain_id), b"").expect("empty file");
    let (store, _) = open_ready(&f, f.config());
    let c3 = store
        .change_anchor_dir(Some(chosen(empty.path())), confirmed())
        .expect("empty file");
    drain(&store);
    store.shutdown();
    let ls = lines(empty.path(), &f.chain_id);
    assert!(matches!(ls[0], AnchorLine::Header { .. }), "{ls:?}");
    assert_eq!(headers(&ls), 1, "{ls:?}");
    assert!(immediates(&ls).contains(&(c3.seq, "CONFIG_CHANGED".into())));
    assert!(full_verify_fresh(&f).is_empty());
}

#[test]
fn unwritable_new_dir_commits_nothing() {
    let (store, f, dir) = anchored();
    drain(&store);
    let base = tempfile::tempdir().expect("base");
    let missing = base.path().join("missing");
    let not_a_dir = base.path().join("file");
    std::fs::write(&not_a_dir, b"x").expect("file");
    let (head, settings) = (store.head(), store.settings());
    let rows = dump_rows(&f).len();
    for p in [
        missing.clone(),
        not_a_dir.clone(),
        PathBuf::from("relative-anchors"),
        // The dir in force already: nothing to change.
        dir.path().to_path_buf(),
    ] {
        let e = store
            .change_anchor_dir(Some(chosen(&p)), confirmed())
            .expect_err("refused");
        assert!(
            matches!(e, AuditError::Invalid(_)),
            "{}: {e:?}",
            p.display()
        );
    }
    assert_eq!(store.head(), head);
    assert_eq!(store.settings(), settings);
    assert_eq!(dump_rows(&f).len(), rows, "nothing committed");
    assert!(!missing.exists());
    assert_eq!(std::fs::read(&not_a_dir).expect("file"), b"x");
    assert!(!Path::new("relative-anchors").exists());
    store.shutdown();
}

#[test]
fn change_anchor_dir_never_deletes() {
    // Black box: across a switch, a switch back over a torn line, an incident file, a removal
    // and a restart, every file in either dir only grows.
    let base = tempfile::tempdir().expect("base");
    let (a, b) = (base.path().join("a"), base.path().join("b"));
    std::fs::create_dir(&a).expect("a");
    std::fs::create_dir(&b).expect("b");
    let (store, f) = store_on(&a, |_| {});
    corroborate(&store);
    store.append_batch(mixed(4)).expect("append");
    drain(&store);
    let step = |store: &Store, what: &dyn Fn(&Store)| {
        let before = files_under(base.path());
        what(store);
        drain(store);
        only_appended(&before, &files_under(base.path()));
    };
    step(&store, &|s| {
        s.change_anchor_dir(Some(chosen(&b)), confirmed())
            .expect("to b");
    });
    append_raw(&chain_file(&a, &f.chain_id), fragment().as_bytes());
    step(&store, &|s| {
        s.change_anchor_dir(Some(chosen(&a)), confirmed())
            .expect("back to a");
    });
    step(&store, &|s| {
        testing::apply_startup(s, &incident("never deletes")).expect("incident");
    });
    step(&store, &|s| {
        s.change_anchor_dir(None, confirmed()).expect("remove");
    });
    step(&store, &|s| {
        s.change_anchor_dir(Some(chosen(&b)), confirmed())
            .expect("b again");
    });
    let before = files_under(base.path());
    store.shutdown();
    let (store, _) = open_ready(&f, f.config());
    store.append_batch(mixed(2)).expect("append");
    drain(&store);
    store.shutdown();
    only_appended(&before, &files_under(base.path()));

    // White box: the anchor-dir code asks the file system for no deletion, rename or
    // truncation at all (a file is only ever created with create-new or opened to append).
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("anchor_dir");
    for e in std::fs::read_dir(&src).expect("anchor_dir sources") {
        let p = e.expect("entry").path();
        let text = std::fs::read_to_string(&p).expect("source");
        for needle in [
            "remove_file",
            "remove_dir",
            "rename(",
            "set_len",
            "truncate(",
            "fs::write",
            "File::create",
            "write(true)",
        ] {
            assert!(!text.contains(needle), "{} asks for {needle}", p.display());
        }
    }
}

#[test]
fn apply_setting_anchor_dir_refused() {
    let (store, f, dir) = anchored();
    let other = tempfile::tempdir().expect("other");
    let (head, settings) = (store.head(), store.settings());
    for change in [
        SettingChange::AnchorDir(Some(dir_text(other.path()))),
        SettingChange::AnchorDir(None),
        SettingChange::AnchorDir(Some(dir_text(dir.path()))),
    ] {
        for confirm in [None, Some(confirmed())] {
            match store.apply_setting(change.clone(), confirm) {
                Err(AuditError::Invalid(why)) => assert_eq!(why, "use change_anchor_dir"),
                other => panic!("{change:?}: {other:?}"),
            }
        }
    }
    assert_eq!(store.head(), head);
    assert_eq!(store.settings(), settings);
    drain(&store);
    assert!(!chain_file(other.path(), &f.chain_id).exists());
    store.shutdown();
}

// ---------------------------------------------------------------------------------------
// RESTORE lines (§8.5, §8.7 interrupted restore, §8.11 step 5)

#[test]
fn restore_writes_restore_line_to_new_chain_file() {
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a, fa) = store_on(dir.path(), |_| {});
    corroborate(&a);
    a.append_batch(mixed(10)).expect("append");
    a.flush_head_anchor().expect("flush");
    let out = tempfile::tempdir().expect("out dir");
    let bundle = a.backup(chosen(out.path())).expect("backup");
    a.append_batch(mixed(3)).expect("append");
    a.flush_head_anchor().expect("flush");

    // Store::restore on the live store (a same-machine rollback, confirmed).
    let rep = a
        .restore(
            chosen(&bundle.bundle_dir),
            &pass(PASSPHRASE),
            Some(confirmed()),
        )
        .expect("restore");
    drain(&a);
    assert_eq!(a.settings().anchor_dir, Some(dir_text(dir.path())));
    assert_restore_lines(dir.path(), &fa, &rep.new_chain_id, rep.restore_seq);
    assert_eq!(a.full_verify(), vec![]);
    a.shutdown();

    // restore_from_source on a new machine: the restored view names the same anchor dir.
    let fb = fixture(fake_clock(START), MemKeyring::new());
    let (b, rep) = restore_from_source(
        &fb.data,
        &fb.lock,
        fb.config(),
        chosen(&bundle.bundle_dir),
        &pass(PASSPHRASE),
        None,
    )
    .expect("restore_from_source");
    drain(&b);
    assert_restore_lines(dir.path(), &fb, &rep.new_chain_id, rep.restore_seq);
    assert_eq!(b.full_verify(), vec![]);
    b.shutdown();
}

#[test]
fn finish_restore_and_interrupted_restore_write_missing_restore_line() {
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a, _fa) = store_on(dir.path(), |_| {});
    corroborate(&a);
    a.append_batch(mixed(10)).expect("append");
    a.flush_head_anchor().expect("flush");
    let out = tempfile::tempdir().expect("out dir");
    let bundle = a.backup(chosen(out.path())).expect("backup");
    a.shutdown();
    let machine = |faults: &Arc<Faults>| {
        let faults = faults.clone();
        let (s, f) = new_store_with(fake_clock(START), MemKeyring::new(), move |cfg| {
            cfg.hooks.faults = Some(faults);
            cfg.hooks.fast_anchor_backoff = true;
        });
        s.append_batch(mixed(3)).expect("append");
        s.flush_head_anchor().expect("flush");
        (s, f)
    };

    // Interrupted restore: a crash between the KEK re-seal and the anchor reset.
    let faults = Faults::new();
    let (b, fb) = machine(&faults);
    faults.fail(FaultPoint::AfterKekReseal, 1);
    assert!(
        b.restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None)
            .is_err()
    );
    drop(b);
    let (restore_seq, chain) = latest_restore(&fb);
    assert!(
        !chain_file(dir.path(), &chain).exists(),
        "nothing before the restore completes"
    );
    let mut cfg = fb.config();
    cfg.pinned_install_id = Some(fb.install_id.clone());
    let (s, findings) = open_ready(&fb, cfg);
    assert_eq!(
        kinds(&findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    drain(&s);
    s.shutdown();
    assert_restore_lines(dir.path(), &fb, &chain, restore_seq);
    // A later start writes them no second time.
    let (s, _) = open_ready(&fb, fb.config());
    drain(&s);
    s.shutdown();
    assert_restore_lines(dir.path(), &fb, &chain, restore_seq);

    // "Finish restore": a crash right after the commit, before the re-seal.
    let faults = Faults::new();
    let (c, fc) = machine(&faults);
    faults.fail(FaultPoint::AfterRestoreCommit, 1);
    assert!(
        c.restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None)
            .is_err()
    );
    drop(c);
    match open(&fc.data, &fc.lock, fc.config()).expect("open") {
        StartupOutcome::Locked(LockedReason::KeychainLost {
            offer: RecoveryOffer::FinishRestore,
        }) => {}
        other => panic!("expected FinishRestore, got {other:?}"),
    }
    let (restore_seq, chain) = latest_restore(&fc);
    assert!(!chain_file(dir.path(), &chain).exists());
    let (s, v, _) =
        finish_restore(&fc.data, &fc.lock, fc.config(), &pass(PASSPHRASE)).expect("finish");
    assert_eq!(
        kinds(&v.findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    drain(&s);
    assert_eq!(s.full_verify(), vec![]);
    s.shutdown();
    assert_restore_lines(dir.path(), &fc, &chain, restore_seq);
}

// ---------------------------------------------------------------------------------------
// incident files (PD-164)

#[test]
fn incident_file_written_once_per_verify_seq() {
    let (store, f, dir) = anchored();
    let first = testing::apply_startup(&store, &incident("one"))
        .expect("incident")
        .verify_seq
        .expect("VERIFY");
    drain(&store);
    let file1 = incident_file(dir.path(), &f.chain_id, first);
    let bytes = std::fs::read(&file1).expect("incident file");
    let v: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        bytes,
        atlas_duck_ipc::jcs::to_jcs_vec(&v).expect("jcs"),
        "JCS"
    );
    let r = row(&f, first);
    assert_eq!(
        v,
        json!({
            "chain_id": f.chain_id,
            "verify_seq": first,
            "record_hash": hex::encode(r.record_hash),
            "result": "anchor_missing",
            "expected_seq": 1,
            "expected_hash": hex::encode([1u8; 32]),
            "observed_seq": 2,
            "observed_hash": null,
            "detected_at": START,
        })
    );

    // A VERIFY that is not an incident gets no file.
    let info = testing::apply_startup(
        &store,
        &StartupVerdict {
            findings: vec![VerifyFinding {
                kind: FindingKind::UnanchoredTail,
                expected_seq: None,
                expected_hash: None,
                observed_seq: None,
                observed_hash: None,
                detail: "informational".into(),
            }],
            ..StartupVerdict::default()
        },
    )
    .expect("info")
    .verify_seq
    .expect("VERIFY");
    drain(&store);
    assert!(!incident_file(dir.path(), &f.chain_id, info).exists());

    // Create-new: a file already at the next incident's name is never overwritten.
    let next = store.head().0 + 1;
    let planted = incident_file(dir.path(), &f.chain_id, next);
    std::fs::write(&planted, b"planted").expect("planted");
    let second = testing::apply_startup(&store, &incident("two"))
        .expect("incident")
        .verify_seq
        .expect("VERIFY");
    assert_eq!(second, next);
    drain(&store);
    assert!(!store.health().anchor_dir_write_failing);
    assert_eq!(std::fs::read(&planted).expect("planted"), b"planted");
    assert_eq!(std::fs::read(&file1).expect("file"), bytes);
    store.shutdown();

    // A restart writes no incident file again.
    let (store, _) = open_ready(&f, f.config());
    drain(&store);
    store.shutdown();
    assert_eq!(std::fs::read(&file1).expect("file"), bytes);
    let incident_files = std::fs::read_dir(dir.path())
        .expect("read_dir")
        .filter(|e| {
            e.as_ref()
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .contains(".incident-")
        })
        .count();
    assert_eq!(incident_files, 2);
}

#[test]
fn load_ignores_incident_files() {
    let (store, f, dir) = anchored();
    corroborate(&store);
    store.append_batch(mixed(4)).expect("append");
    let v = testing::apply_startup(&store, &incident("load"))
        .expect("incident")
        .verify_seq
        .expect("VERIFY");
    drain(&store);
    assert!(incident_file(dir.path(), &f.chain_id, v).exists());
    // Another incident file that is not even JSON.
    std::fs::write(incident_file(dir.path(), &f.chain_id, 999_999), b"not json")
        .expect("junk incident file");
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    let (store, findings) = open_ready(&f, f.config());
    assert!(findings.is_empty(), "{findings:?}");
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    let fs = full_verify_fresh(&f);
    assert!(fs.is_empty(), "{fs:?}");
}

// ---------------------------------------------------------------------------------------
// torn lines (PD-165)

#[test]
fn torn_last_line_tolerated_both_sides() {
    let (store, f, dir) = anchored();
    corroborate(&store);
    store.append_batch(mixed(4)).expect("append");
    append_one(&store, EventType::APP_STOP);
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    // A crash in the middle of an append: half a line, no newline.
    let file = chain_file(dir.path(), &f.chain_id);
    let frag = fragment();
    append_raw(&file, frag.as_bytes());

    // Verifier: an informational finding, no incident, at a full verification and at a start.
    let fs = full_verify_fresh(&f);
    assert_eq!(kinds(&fs), vec![FindingKind::AnchorDirTornLine], "{fs:?}");
    assert!(!FindingKind::AnchorDirTornLine.is_incident());
    assert_eq!(
        FindingKind::AnchorDirTornLine.as_str(),
        "anchor_dir_torn_line"
    );
    // (The VERIFY that full verification appended is an unanchored tail record now.)
    let (store, findings) = open_ready(&f, f.config());
    assert_eq!(
        kinds(&findings),
        vec![FindingKind::AnchorDirTornLine, FindingKind::UnanchoredTail],
        "{findings:?}"
    );
    assert!(store.open_incidents().is_empty());

    // Writer: before its next append the fragment is closed by a newline and followed by a
    // Record line for the head; then the lines go on.
    let retention = store
        .apply_setting(SettingChange::RetentionDays(120), None)
        .expect("retention")
        .seq;
    drain(&store);
    store.shutdown();
    let text = std::fs::read_to_string(&file).expect("file");
    let raw: Vec<&str> = text.lines().collect();
    let i = raw.iter().position(|l| *l == frag).expect("fragment line");
    let head = match parse_line(raw[i + 1]) {
        Ok(AnchorLine::Record { seq, .. }) => seq,
        other => panic!("not a Record line after the fragment: {other:?}"),
    };
    assert_eq!(parse_line(raw[i + 1]).ok(), Some(record_of(&row(&f, head))));
    let ls = lines_but(dir.path(), &f.chain_id, &frag);
    assert!(immediates(&ls).contains(&(retention, "CONFIG_CHANGED".into())));
    let fs = full_verify_fresh(&f);
    assert_eq!(kinds(&fs), vec![FindingKind::AnchorDirTornLine], "{fs:?}");
}

#[test]
fn garbage_line_still_mismatch() {
    let (store, f, dir) = anchored();
    corroborate(&store);
    store.append_batch(mixed(3)).expect("append");
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    let file = chain_file(dir.path(), &f.chain_id);
    let original = std::fs::read_to_string(&file).expect("file");
    let valid = to_line(&record_of(&row(&f, 1)));
    let frag = fragment();
    let with = |bad: &str| {
        std::fs::write(&file, format!("{original}{bad}\n{valid}\n")).expect("write");
        full_verify_fresh(&f)
    };
    // Control: a torn-looking line followed by a valid line is informational.
    assert_eq!(kinds(&with(&frag)), vec![FindingKind::AnchorDirTornLine]);
    for (what, bad) in [
        ("not JSON", "not an anchor line".to_string()),
        (
            "complete JSON, unknown key",
            r#"{"seq":1,"x":2}"#.to_string(),
        ),
        ("complete JSON, not canonical", format!("{valid} ")),
        ("an empty line", String::new()),
        (
            "a torn-looking line followed by a bad line",
            format!("{frag}\nnot an anchor line"),
        ),
        ("a fragment without the opening", frag[2..].to_string()),
    ] {
        let fs = with(&bad);
        assert!(
            fs.iter().any(|x| x.kind == FindingKind::AnchorDirMismatch
                && x.detail.contains("is not a valid anchor line")),
            "{what}: {fs:?}"
        );
    }
    // Both lines are judged in the torn-then-bad case.
    let fs = with(&format!("{frag}\nnot an anchor line"));
    let bad = fs
        .iter()
        .filter(|x| {
            x.kind == FindingKind::AnchorDirMismatch && x.detail.contains("not a valid anchor line")
        })
        .count();
    assert_eq!(bad, 2, "{fs:?}");
    assert!(!kinds(&fs).contains(&FindingKind::AnchorDirTornLine));
}
