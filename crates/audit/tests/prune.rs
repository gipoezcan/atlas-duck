//! Prune (§8.8, §8.5, §8.1, L36, L37; U-09, U-12 core, U-22 prune half, X-02 store half,
//! RF-1b core): the pure prefix rule, then whole stores driven day by day with a fake clock
//! whose server `Date` agrees with the local clock unless a test says otherwise.

mod common;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use atlas_duck_audit::anchors::{FirstRetainedAnchor, HeadAnchor};
use atlas_duck_audit::clock::{Clock, UtcInstant, parse_epoch};
use atlas_duck_audit::crypto::{self, Dek, Kek};
use atlas_duck_audit::error::AuditError;
use atlas_duck_audit::keystore::{EntryName, KeyStoreError, service_name};
use atlas_duck_audit::testing::{
    FaultPoint, Faults, KeyOpKind, MemKeyring, PruneRow, effective_epochs,
    guarded_effective_epochs, prunable_prefix_len,
};
use atlas_duck_audit::types::{Confirmed, EventFlags, EventType};
use atlas_duck_audit::{
    FindingKind, Hooks, OpenConfig, PruneOutcome, PruneSkip, Settings, StartupOutcome, Store,
    VerifyOutcome, open,
};
use chrono::{Days, NaiveDate};
use common::*;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------------------
// The prefix rule (pure)

fn d(s: &str) -> NaiveDate {
    parse_epoch(s).expect("test date")
}

fn prow(seq: u64, epoch: Option<&str>, ts_date: &str, flags: EventFlags) -> PruneRow {
    PruneRow {
        seq,
        epoch: epoch.map(d),
        ts: at(&format!("{ts_date}T12:00:00.000Z")),
        flags,
        record_hash: [seq as u8; 32],
    }
}

fn plain(seq: u64, epoch: &str, ts_date: &str) -> PruneRow {
    prow(seq, Some(epoch), ts_date, EventFlags::default())
}

fn prefix(rows: &[PruneRow], cutoff: &str) -> usize {
    let eff = effective_epochs(&rows.iter().map(|r| r.epoch).collect::<Vec<_>>());
    prunable_prefix_len(rows, &eff, d(cutoff))
}

#[test]
fn effective_epoch_backward_fill() {
    let (d1, d2) = (d("2026-04-01"), d("2026-04-02"));
    assert_eq!(
        effective_epochs(&[None, None, Some(d1), None, Some(d2), None]),
        vec![Some(d1), Some(d1), Some(d1), Some(d2), Some(d2), None]
    );
}

#[test]
fn prefix_requires_epoch_and_ts() {
    // Row 3 was held back on an old epoch but written later (`ts_utc` newer than the cutoff),
    // and no later unflagged record is older than the cutoff: the prefix stops there.
    let rows = [
        plain(1, "2026-04-01", "2026-04-01"),
        plain(2, "2026-04-02", "2026-04-02"),
        plain(3, "2026-04-03", "2026-04-20"),
        plain(4, "2026-04-20", "2026-04-20"),
    ];
    assert_eq!(prefix(&rows, "2026-04-10"), 2);
}

#[test]
fn prefix_any_later_record_clause() {
    // Row 1 was stamped during an uncorroborated forward jump (no flag); row 2 is older than
    // the cutoff by its own `ts_utc`, which releases row 1 as well.
    let rows = [
        plain(1, "2026-04-01", "2027-01-01"),
        plain(2, "2026-04-02", "2026-04-02"),
        plain(3, "2026-04-20", "2026-04-20"),
    ];
    assert_eq!(prefix(&rows, "2026-04-10"), 2);
}

#[test]
fn prefix_clock_behind_ts_never_counts() {
    let behind = prow(1, Some("2026-04-01"), "2026-03-01", EventFlags::BEHIND);
    let rows = [behind.clone(), plain(2, "2026-04-20", "2026-04-20")];
    assert_eq!(prefix(&rows, "2026-04-10"), 0);
    // A later unflagged record older than the cutoff releases it.
    let rows = [
        behind,
        plain(2, "2026-04-05", "2026-04-05"),
        plain(3, "2026-04-20", "2026-04-20"),
    ];
    assert_eq!(prefix(&rows, "2026-04-10"), 2);
}

#[test]
fn prefix_clock_forward_needs_only_epoch() {
    let rows = [
        prow(1, Some("2026-04-01"), "2027-01-01", EventFlags::FORWARD),
        plain(2, "2026-04-20", "2026-04-20"),
    ];
    assert_eq!(prefix(&rows, "2026-04-10"), 1);
    // Without the flag the future `ts_utc` holds it.
    let rows = [
        plain(1, "2026-04-01", "2027-01-01"),
        plain(2, "2026-04-20", "2026-04-20"),
    ];
    assert_eq!(prefix(&rows, "2026-04-10"), 0);
}

#[test]
fn prefix_stops_at_null_effective_epoch() {
    let rows = [
        plain(1, "2026-04-01", "2026-04-01"),
        prow(2, None, "2026-04-01", EventFlags::default()),
        prow(3, None, "2026-04-01", EventFlags::default()),
    ];
    assert_eq!(prefix(&rows, "2026-04-10"), 1);
    assert_eq!(prefix(&rows[1..], "2026-04-10"), 0);
}

#[test]
fn null_epochs_never_take_a_behind_epoch() {
    // T06 ruling: a first corroboration while the local clock was behind stamps a past date
    // flagged `clock_behind`; the NULL-epoch records before it (GENESIS) must not resolve to
    // that past date, but to the first later epoch that is not flagged.
    let rows = [
        prow(1, None, "2026-01-01", EventFlags::default()),
        prow(2, Some("2025-11-01"), "2025-11-01", EventFlags::BEHIND),
        prow(3, Some("2025-11-01"), "2025-11-02", EventFlags::BEHIND),
        plain(4, "2026-01-03", "2026-01-03"),
    ];
    assert_eq!(
        guarded_effective_epochs(&rows),
        vec![
            Some(d("2026-01-03")),
            Some(d("2025-11-01")),
            Some(d("2025-11-01")),
            Some(d("2026-01-03")),
        ]
    );
    // Only flagged epochs after it: no effective epoch, never prunable.
    assert_eq!(
        guarded_effective_epochs(&rows[..3]),
        vec![None, Some(d("2025-11-01")), Some(d("2025-11-01"))]
    );
}

// ---------------------------------------------------------------------------------------
// Store driver

const RETENTION: u32 = 92;

fn confirmed() -> Confirmed {
    Confirmed {
        dialog_text_sha256: [7; 32],
    }
}

/// A store, its fixture and the hooks it reopens with.
struct Sim {
    store: Store,
    f: Fixture,
    hooks: Hooks,
    retention: u32,
}

impl Sim {
    /// A new store at `start` (prune-ready, not corroborated yet) with `synchronous=NORMAL`.
    fn start(start: &str, retention: u32, tweak: impl FnOnce(&mut OpenConfig)) -> Sim {
        let mut hooks = Hooks::default();
        let (store, f) = new_store_with(fake_clock(start), MemKeyring::new(), |cfg| {
            cfg.hooks.synchronous_normal = true;
            tweak(cfg);
            hooks = cfg.hooks.clone();
        });
        prune_ready(&store, retention);
        Sim {
            store,
            f,
            hooks,
            retention,
        }
    }

    /// The server agrees with the local clock from now on.
    fn corroborated(self) -> Sim {
        corroborate_now(&self.store, &self.f.clock);
        self
    }

    fn new(retention: u32) -> Sim {
        Sim::start(START, retention, |_| {}).corroborated()
    }

    fn config(&self) -> OpenConfig {
        let mut cfg = self.f.config();
        cfg.hooks = self.hooks.clone();
        cfg
    }

    /// `n` events today, then the queued attempt and the anchors.
    fn events(&self, n: usize) {
        self.store.append_batch(day_events(n)).expect("append");
        sync_writer(&self.store);
        self.store.flush_head_anchor().expect("flush");
    }

    fn day(&self, n: usize) {
        day(&self.store, &self.f.clock, n);
    }

    fn days(&self, k: usize, n: usize) {
        for _ in 0..k {
            self.day(n);
        }
    }

    fn today(&self) -> NaiveDate {
        self.f.clock.now_utc().date()
    }

    /// Shutdown, then `open()`; prune-ready again (the settings view is T12's).
    fn restart(&mut self) -> VerifyOutcome {
        self.store.shutdown();
        let (store, verify) = open_ready(&self.f, self.config());
        prune_ready(&store, self.retention);
        self.store = store;
        verify
    }

    /// The app is off for `days`, then starts again (no corroboration yet).
    fn off(&mut self, days: u64) {
        self.store.shutdown();
        self.f.clock.advance(DAY * days as u32);
        let (store, _) = open_ready(&self.f, self.config());
        prune_ready(&store, self.retention);
        self.store = store;
    }

    fn payload(&self, seq: u64) -> Value {
        serde_json::from_slice(&self.store.read_payload(seq).expect("read_payload")).expect("json")
    }

    fn latest_prune(&self) -> Option<LogRow> {
        prune_log(&self.f).pop()
    }
}

fn open_ready(f: &Fixture, cfg: OpenConfig) -> (Store, VerifyOutcome) {
    match open(&f.data, &f.lock, cfg).expect("open") {
        StartupOutcome::Ready { store, verify } => (store, verify),
        other => panic!("not ready: {other:?}"),
    }
}

#[derive(Debug, Clone)]
struct LogRow {
    prune_seq: u64,
    range_start: u64,
    cutoff: String,
    last_pruned: [u8; 32],
    first_retained_seq: u64,
    row_hash: [u8; 32],
}

fn prune_log(f: &Fixture) -> Vec<LogRow> {
    let c = raw_conn(f);
    let mut st = c
        .prepare(
            "SELECT prune_seq, range_start, cutoff_epoch, last_pruned_record_hash, \
             first_retained_seq, row_hash FROM prune_log ORDER BY prune_seq",
        )
        .expect("prepare");
    st.query_map([], |r| {
        Ok(LogRow {
            prune_seq: r.get::<_, i64>(0)? as u64,
            range_start: r.get::<_, i64>(1)? as u64,
            cutoff: r.get(2)?,
            last_pruned: r.get::<_, Vec<u8>>(3)?.try_into().expect("32"),
            first_retained_seq: r.get::<_, i64>(4)? as u64,
            row_hash: r.get::<_, Vec<u8>>(5)?.try_into().expect("32"),
        })
    })
    .expect("query")
    .map(|r| r.expect("row"))
    .collect()
}

/// `seq → (ts_utc, epoch, event_type, key_id)` of every retained row.
fn rows(f: &Fixture) -> BTreeMap<u64, (String, Option<String>, String, u64)> {
    let c = raw_conn(f);
    let mut st = c
        .prepare("SELECT seq, ts_utc, epoch, event_type, key_id FROM events ORDER BY seq")
        .expect("prepare");
    st.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)? as u64,
            (r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, i64>(4)? as u64),
        ))
    })
    .expect("query")
    .map(|r| r.expect("row"))
    .collect()
}

/// `(key_id, month, live, destroyed_at)` of every `keys` row.
fn keys(f: &Fixture) -> Vec<(u64, Option<String>, bool, Option<String>)> {
    let c = raw_conn(f);
    let mut st = c
        .prepare(
            "SELECT key_id, month, wrapped_dek IS NOT NULL, destroyed_at FROM keys ORDER BY key_id",
        )
        .expect("prepare");
    st.query_map([], |r| {
        Ok((r.get::<_, i64>(0)? as u64, r.get(1)?, r.get(2)?, r.get(3)?))
    })
    .expect("query")
    .map(|r| r.expect("row"))
    .collect()
}

fn keychain_first_retained(f: &Fixture) -> FirstRetainedAnchor {
    let b = f
        .ring
        .raw_get(&service_name(&f.install_id), "first_retained_anchor")
        .expect("first_retained_anchor entry");
    FirstRetainedAnchor::from_entry(&b).expect("layout")
}

fn keychain_head(f: &Fixture) -> HeadAnchor {
    let b = f
        .ring
        .raw_get(&service_name(&f.install_id), "head_anchor")
        .expect("head_anchor entry");
    HeadAnchor::from_entry(&b).expect("layout")
}

fn assert_keychain_matches_latest_row(f: &Fixture) {
    let latest = prune_log(f).pop().expect("a prune_log row");
    let fr = keychain_first_retained(f);
    assert_eq!(
        (fr.first_retained_seq, fr.first_retained_prev_hash),
        (latest.first_retained_seq, latest.last_pruned)
    );
}

fn count_events(f: &Fixture, event_type: &str) -> usize {
    rows(f)
        .values()
        .filter(|(_, _, t, _)| t == event_type)
        .count()
}

fn prune_epochs(f: &Fixture) -> Vec<String> {
    rows(f)
        .values()
        .filter(|(_, _, t, _)| t == "PRUNE")
        .map(|(_, e, _, _)| e.clone().expect("PRUNE epoch"))
        .collect()
}

/// Every row that disappeared since the last call was written at least `retention` days
/// before today (by `ts_utc`; the local clock is right in these tests).
struct EarlyPruneCheck {
    seen: BTreeMap<u64, String>,
    retention: u64,
}

impl EarlyPruneCheck {
    fn new(retention: u32) -> Self {
        EarlyPruneCheck {
            seen: BTreeMap::new(),
            retention: u64::from(retention),
        }
    }

    fn check(&mut self, sim: &Sim) -> usize {
        let now = rows(&sim.f);
        let today = sim.today();
        let mut deleted = 0;
        for (seq, ts) in &self.seen {
            if !now.contains_key(seq) {
                let written = UtcInstant::parse_rfc3339_ms(ts).expect("ts").date();
                assert!(
                    (today - written).num_days() >= self.retention as i64,
                    "seq {seq} written {written} deleted on {today}"
                );
                deleted += 1;
            }
        }
        self.seen = now.into_iter().map(|(s, (ts, ..))| (s, ts)).collect();
        deleted
    }
}

fn pruned(o: PruneOutcome) -> (u64, u64, u64, u64, NaiveDate, NaiveDate, bool, Vec<u64>) {
    match o {
        PruneOutcome::Pruned {
            prune_seq,
            range_start,
            first_retained_seq,
            count,
            cutoff,
            baseline,
            clamped,
            destroyed_key_ids,
        } => (
            prune_seq,
            range_start,
            first_retained_seq,
            count,
            cutoff,
            baseline,
            clamped,
            destroyed_key_ids,
        ),
        other => panic!("not pruned: {other:?}"),
    }
}

fn no_incident(fs: &[atlas_duck_audit::VerifyFinding]) {
    assert!(!fs.iter().any(|f| f.kind.is_incident()), "{fs:?}");
}

// ---------------------------------------------------------------------------------------
// U-09 and cadence

#[test]
fn prune_daily_keeps_verifiability() {
    let sim = Sim::new(RETENTION);
    sim.events(4);
    let mut early = EarlyPruneCheck::new(RETENTION);
    early.check(&sim);
    let mut genesis_gone = false;
    for k in 1..=200u64 {
        sim.day(4);
        let deleted = early.check(&sim);
        let log = prune_log(&sim.f);
        if k < 93 {
            assert!(log.is_empty(), "day {k}: {log:?}");
            assert_eq!(count_events(&sim.f, "PRUNE"), 0);
            continue;
        }
        // One PRUNE (and prune_log row) per epoch day from day 93 on.
        assert_eq!(log.len() as u64, k - 92, "day {k}");
        let today = epoch_of(sim.today());
        assert_eq!(
            prune_epochs(&sim.f).iter().filter(|e| **e == today).count(),
            1,
            "day {k}"
        );
        // Contiguous from range_start 1.
        let mut first = 1;
        for r in &log {
            assert_eq!(r.range_start, first, "day {k}");
            first = r.first_retained_seq;
        }
        assert_eq!(rows(&sim.f).keys().next().copied(), Some(first));
        if k == 93 {
            assert!(deleted > 4, "day 93 removes GENESIS and day 0");
        }
        let has_genesis = rows(&sim.f).contains_key(&1);
        genesis_gone |= !has_genesis;
        assert!(!(genesis_gone && has_genesis));
        assert_keychain_matches_latest_row(&sim.f);
        assert_eq!(sim.store.health().prune_backlog_days, 0);
        if k % 20 == 0 {
            let fs = sim.store.full_verify();
            assert!(fs.is_empty(), "day {k}: {fs:?}");
        }
    }
    assert!(genesis_gone);
}

fn epoch_of(d: NaiveDate) -> String {
    d.format("%Y-%m-%d").to_string()
}

#[test]
fn cadence_one_run_per_epoch_day() {
    let mut sim = Sim::new(RETENTION);
    sim.events(2);
    sim.days(94, 2);
    sim.f.clock.advance(DAY);
    let today = epoch_of(sim.today());
    for _ in 0..3 {
        sim.restart();
        corroborate_now(&sim.store, &sim.f.clock);
        sim.events(1);
        assert_eq!(
            sim.store.prune(None),
            Ok(PruneOutcome::Skipped(PruneSkip::AlreadyRanThisEpoch))
        );
    }
    let today_runs = prune_epochs(&sim.f).iter().filter(|e| **e == today).count();
    assert_eq!(today_runs, 1);
}

#[test]
fn no_prune_without_corroboration_in_process() {
    let mut sim = Sim::new(RETENTION);
    sim.events(2);
    sim.days(94, 2);
    let before = prune_log(&sim.f).len();
    sim.f.clock.advance(DAY);
    sim.restart();
    sim.events(2);
    assert_eq!(
        sim.store.prune(None),
        Ok(PruneOutcome::Skipped(PruneSkip::NotCorroborated))
    );
    assert_eq!(prune_log(&sim.f).len(), before);
}

#[test]
fn no_prune_while_head_epoch_null() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    prune_ready(&store, RETENTION);
    assert_eq!(
        store.prune(None),
        Ok(PruneOutcome::Skipped(PruneSkip::NotCorroborated))
    );
    // Corroborated in this process, but no record carries an epoch yet.
    corroborate_now(&store, &f.clock);
    sync_writer(&store);
    assert_eq!(
        store.prune(Some(confirmed())),
        Ok(PruneOutcome::Skipped(PruneSkip::HeadEpochNull))
    );
    assert!(prune_log(&f).is_empty());
}

#[test]
fn prune_waits_for_config_reconcile() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    corroborate_now(&store, &f.clock);
    store.append_batch(day_events(2)).expect("append");
    assert_eq!(
        store.prune(Some(confirmed())),
        Ok(PruneOutcome::Skipped(PruneSkip::ConfigNotReconciled))
    );
}

#[test]
fn legal_hold_pauses_prune_and_shredding() {
    let sim = Sim::new(RETENTION);
    sim.events(2);
    sim.days(92, 2);
    sim.store
        .testing_set_settings(Settings {
            retention_days: RETENTION,
            legal_hold: true,
            ..Settings::default()
        })
        .expect("hold on");
    sim.days(2, 2);
    assert_eq!(
        sim.store.prune(Some(confirmed())),
        Ok(PruneOutcome::Skipped(PruneSkip::LegalHold))
    );
    assert!(prune_log(&sim.f).is_empty());
    assert!(keys(&sim.f).iter().all(|k| k.2 && k.3.is_none()));
    // Lifted (the confirmation is T12's): the next day's run prunes and shreds.
    prune_ready(&sim.store, RETENTION);
    sim.day(2);
    let latest = sim.latest_prune().expect("a prune");
    let p = sim.payload(latest.prune_seq);
    assert_eq!(p["settings"]["legal_hold"], json!(false));
    assert_eq!(p["destroyed_key_ids"], json!([1]), "{p}");
    assert!(!keys(&sim.f)[0].2);
}

// ---------------------------------------------------------------------------------------
// L37 baseline and clamp (RF-1b core)

#[test]
fn clamp_after_gap_no_dialog() {
    let mut sim = Sim::new(RETENTION);
    sim.events(2);
    sim.days(120, 2);
    let mut early = EarlyPruneCheck::new(RETENTION);
    early.check(&sim);
    sim.off(30);
    let mut last_gap: Option<i64> = None;
    let mut clamped_runs = 0;
    for _ in 0..40 {
        sim.day(2);
        early.check(&sim);
        let latest = sim.latest_prune().expect("prune");
        let p = sim.payload(latest.prune_seq);
        let cutoff = d(p["cutoff"].as_str().expect("cutoff"));
        let baseline = d(p["baseline"].as_str().expect("baseline"));
        let raw = sim.today() - Days::new(u64::from(RETENTION));
        let gap = (raw - cutoff).num_days();
        assert_eq!(
            sim.store.health().prune_backlog_days,
            u32::try_from(gap).expect("gap")
        );
        if p["clamped"] == json!(true) {
            clamped_runs += 1;
            assert_eq!(cutoff, baseline + Days::new(2));
            if let Some(g) = last_gap {
                assert_eq!(gap, g - 1, "the backlog shrinks by one day per day");
            }
            last_gap = Some(gap);
        } else {
            assert_eq!(gap, 0);
            assert!(cutoff <= baseline + Days::new(2));
            break;
        }
    }
    assert_eq!(clamped_runs, 29);
    assert_eq!(last_gap, Some(1));
    assert!(sim.store.full_verify().is_empty());
}

#[test]
fn first_prune_baseline_is_genesis_effective_epoch() {
    let mut sim = Sim::new(RETENTION);
    let day0 = sim.today();
    sim.events(3);
    assert!(rows(&sim.f)[&1].1.is_none(), "GENESIS has a NULL epoch");
    sim.off(100);
    corroborate_now(&sim.store, &sim.f.clock);
    sim.events(1);
    let log = prune_log(&sim.f);
    assert_eq!(log.len(), 1);
    let p = sim.payload(log[0].prune_seq);
    assert_eq!(p["baseline"], json!(epoch_of(day0)));
    assert_eq!(p["cutoff"], json!(epoch_of(day0 + Days::new(2))));
    assert_eq!(p["clamped"], json!(true));
    assert_eq!(sim.store.health().prune_backlog_days, 100 - 92 - 2);
}

#[test]
fn confirmed_run_lifts_clamp_once() {
    let mut sim = Sim::new(RETENTION);
    sim.events(2);
    sim.days(95, 2);
    sim.off(20);
    sim.day(2);
    let auto = sim.latest_prune().expect("prune");
    assert_eq!(sim.payload(auto.prune_seq)["clamped"], json!(true));
    let raw = sim.today() - Days::new(u64::from(RETENTION));
    let (_, range_start, _, _, cutoff, baseline, clamped, _) =
        pruned(sim.store.prune(Some(confirmed())).expect("confirmed run"));
    assert!(!clamped);
    assert_eq!(cutoff, raw);
    assert_eq!(baseline, d(&auto.cutoff));
    assert_eq!(range_start, auto.first_retained_seq);
    assert_eq!(sim.store.health().prune_backlog_days, 0);
    // The next automatic run is unclamped: one day past the new baseline.
    sim.day(2);
    let next = sim.latest_prune().expect("prune");
    let p = sim.payload(next.prune_seq);
    assert_eq!(p["clamped"], json!(false));
    assert_eq!(p["baseline"], json!(epoch_of(raw)));
    assert_eq!(p["cutoff"], json!(epoch_of(raw + Days::new(1))));
    assert!(sim.store.full_verify().is_empty());
}

#[test]
fn empty_range_prune_written() {
    let sim = Sim::new(RETENTION);
    sim.events(2);
    sim.days(9, 2); // days 1..9
    sim.days(10, 0); // days 10..19: no record at all
    sim.days(83, 2); // days 20..102
    let mut cutoffs = Vec::new();
    for _ in 103..=112 {
        sim.day(2);
        let r = sim.latest_prune().expect("prune");
        assert_eq!(r.range_start, r.first_retained_seq, "{r:?}");
        let p = sim.payload(r.prune_seq);
        assert_eq!(p["count"], json!(0));
        assert_eq!(p["range"], json!([r.range_start, r.range_start]));
        cutoffs.push(d(&r.cutoff));
    }
    for w in cutoffs.windows(2) {
        assert_eq!(w[1], w[0] + Days::new(1), "the cutoff keeps advancing");
    }
    // Day 113 reaches the records of day 20 again.
    sim.day(2);
    let r = sim.latest_prune().expect("prune");
    assert!(r.first_retained_seq > r.range_start);
    assert!(sim.store.full_verify().is_empty());
}

// ---------------------------------------------------------------------------------------
// Clock guards

fn prune_skip_anomalies(sim: &Sim) -> Vec<Value> {
    rows(&sim.f)
        .iter()
        .filter(|(_, (_, _, t, _))| t == "CLOCK_ANOMALY")
        .map(|(seq, _)| sim.payload(*seq))
        .filter(|p| p["kind"] == json!("prune_skipped"))
        .collect()
}

/// Day 96 is appended under legal hold, so its run has not happened yet.
fn sim_with_due_prune() -> Sim {
    let sim = Sim::new(RETENTION);
    sim.events(2);
    sim.days(95, 2);
    sim.store
        .testing_set_settings(Settings {
            retention_days: RETENTION,
            legal_hold: true,
            ..Settings::default()
        })
        .expect("hold");
    sim.day(2);
    prune_ready(&sim.store, RETENTION);
    sim
}

#[test]
fn clock_guards_skip_and_log_once() {
    let sim = sim_with_due_prune();
    let runs = prune_log(&sim.f).len();
    let now = sim.f.clock.now_utc();
    sim.f.clock.set_wall(UtcInstant(now.0 - 10 * 60_000));
    assert_eq!(
        sim.store.prune(None),
        Ok(PruneOutcome::Skipped(PruneSkip::ClockBeforeHead))
    );
    let logged = prune_skip_anomalies(&sim);
    assert_eq!(logged.len(), 1);
    assert_eq!(logged[0]["reason"], json!("now_before_head"));
    assert!(logged[0]["server"].is_string());
    // Its own anomaly row does not disarm the guard, and it is logged once per process.
    assert_eq!(
        sim.store.prune(None),
        Ok(PruneOutcome::Skipped(PruneSkip::ClockBeforeHead))
    );
    assert_eq!(prune_skip_anomalies(&sim).len(), 1);
    assert_eq!(prune_log(&sim.f).len(), runs);
    // Clock restored: the run happens.
    sim.f.clock.set_wall(UtcInstant(now.0 + 60_000));
    pruned(sim.store.prune(None).expect("prune"));
    assert_eq!(prune_log(&sim.f).len(), runs + 1);
}

#[test]
fn clock_floor_ends_with_the_next_record() {
    let sim = sim_with_due_prune();
    let now = sim.f.clock.now_utc();
    sim.f.clock.set_wall(UtcInstant(now.0 - 10 * 60_000));
    assert_eq!(
        sim.store.prune(None),
        Ok(PruneOutcome::Skipped(PruneSkip::ClockBeforeHead))
    );
    // A record written with the corrected (here: unchanged) clock is the head now: the guard
    // compares with its ts_utc again, not with the head the skip was measured against.
    sim.store.append_batch(day_events(1)).expect("append");
    sync_writer(&sim.store);
    let runs = prune_log(&sim.f).len();
    pruned(sim.store.prune(None).expect("prune"));
    assert_eq!(prune_log(&sim.f).len(), runs + 1);
}

#[test]
fn clock_guard_before_last_prune() {
    let sim = Sim::new(RETENTION);
    sim.events(2);
    sim.days(95, 2);
    let now = sim.f.clock.now_utc();
    sim.f.clock.set_wall(UtcInstant(now.0 - 10 * 60_000));
    sim.store.append_batch(day_events(1)).expect("append");
    assert_eq!(
        sim.store.prune(Some(confirmed())),
        Ok(PruneOutcome::Skipped(PruneSkip::ClockBeforeLastPrune))
    );
    let logged = prune_skip_anomalies(&sim);
    assert_eq!(logged.len(), 1);
    assert_eq!(logged[0]["reason"], json!("now_before_last_prune"));
}

#[test]
fn no_prune_while_local_clock_behind() {
    let sim = sim_with_due_prune();
    // Local date two days behind the corroborated one: records are `clock_behind`.
    let now = sim.f.clock.now_utc();
    sim.f.clock.set_wall(UtcInstant(now.0 - 2 * 86_400_000));
    sim.store.append_batch(day_events(1)).expect("append");
    let runs = prune_log(&sim.f).len();
    assert_eq!(
        sim.store.prune(Some(confirmed())),
        Ok(PruneOutcome::Skipped(PruneSkip::ClockBehind))
    );
    assert_eq!(prune_log(&sim.f).len(), runs);
}

#[test]
fn behind_first_corroboration_never_prunes_genesis_early() {
    // First run 60 days behind: GENESIS and the first records carry a past local date; the
    // first corroborated records are stamped with that past date and flagged `clock_behind`.
    let real = at(START);
    let sim = Sim::start("2026-08-09T12:00:00.000Z", RETENTION, |_| {});
    let server = |sim: &Sim, days: u64| {
        sim.store.observe_server_date(
            "i1",
            std::time::UNIX_EPOCH
                + Duration::from_millis((real.0 + days as i64 * 86_400_000) as u64),
            Instant::now(),
        );
    };
    server(&sim, 0);
    sim.events(2);
    for k in 1..=5 {
        sim.f.clock.advance(DAY);
        server(&sim, k);
        sim.events(2);
    }
    // Clock corrected on real day 6.
    sim.f.clock.set_wall(UtcInstant(real.0 + 6 * 86_400_000));
    let mut early = EarlyPruneCheck::new(RETENTION);
    for _ in 0..100 {
        sim.day(2);
        // Real time == local time from here on; GENESIS was written on real day 0.
        early.check(&sim);
        if !rows(&sim.f).contains_key(&1) {
            let real_age = (sim.today() - real.date()).num_days();
            assert!(real_age >= 92, "GENESIS pruned on real day {real_age}");
            break;
        }
    }
    assert!(
        !rows(&sim.f).contains_key(&1),
        "GENESIS is pruned eventually"
    );
    no_incident(&sim.store.full_verify());
}

// ---------------------------------------------------------------------------------------
// Crypto-shredding (U-12 core)

#[test]
fn crypto_shredding_reference_checked() {
    let mut sim = Sim::start("2026-01-01T12:00:00.000Z", RETENTION, |_| {}).corroborated();
    sim.events(2);
    while sim.today() < d("2026-05-31") {
        sim.day(2);
    }
    let month_key = |sim: &Sim, m: &str| {
        keys(&sim.f)
            .into_iter()
            .find(|k| k.1.as_deref() == Some(m))
            .map(|k| k.0)
            .expect("month key")
    };
    let april = month_key(&sim, "2026-04");
    let may = month_key(&sim, "2026-05");
    // Restart on June 2 and write records before any server response: held back on May 31.
    sim.off(2);
    sim.store.append_batch(day_events(3)).expect("append");
    let held: Vec<u64> = rows(&sim.f)
        .iter()
        .filter(|(_, (ts, e, _, _))| ts.starts_with("2026-06-02") && e.is_some())
        .map(|(s, _)| *s)
        .collect();
    assert!(held.len() >= 3);
    for s in &held {
        let (_, e, _, k) = &rows(&sim.f)[s];
        assert_eq!(e.as_deref(), Some("2026-05-31"));
        assert_eq!(*k, may);
    }
    corroborate_now(&sim.store, &sim.f.clock);
    sync_writer(&sim.store);
    let mut april_destroyed_at: Option<u64> = None;
    let mut may_destroyed_at: Option<u64> = None;
    while sim.today() < d("2026-09-10") {
        sim.day(2);
        let r = rows(&sim.f);
        let ks = keys(&sim.f);
        // Never a destroyed key that a retained row references; never the current one.
        for (key_id, _, live, destroyed) in &ks {
            if !live {
                assert!(destroyed.is_some());
                assert!(!r.values().any(|v| v.3 == *key_id), "key {key_id}");
            }
        }
        let head_key = r.values().last().expect("head").3;
        assert!(ks.iter().any(|k| k.0 == head_key && k.2));
        let latest = sim.latest_prune().expect("prune");
        let destroyed = sim.payload(latest.prune_seq)["destroyed_key_ids"].clone();
        let april_rows = r
            .values()
            .any(|v| v.1.as_deref().is_some_and(|e| e.starts_with("2026-04")));
        let may_rows = r
            .values()
            .any(|v| v.1.as_deref().is_some_and(|e| e.starts_with("2026-05")));
        let live = |k: u64| ks.iter().any(|x| x.0 == k && x.2);
        assert_eq!(live(april), april_rows);
        if !april_rows && april_destroyed_at.is_none() {
            assert!(destroyed.as_array().expect("ids").contains(&json!(april)));
            april_destroyed_at = Some(latest.prune_seq);
        }
        assert_eq!(live(may), may_rows);
        if may_rows {
            for s in &held {
                if r.contains_key(s) {
                    sim.store.read_payload(*s).expect("held-back row decrypts");
                }
            }
        } else if may_destroyed_at.is_none() {
            assert!(destroyed.as_array().expect("ids").contains(&json!(may)));
            assert!(held.iter().all(|s| !r.contains_key(s)));
            may_destroyed_at = Some(latest.prune_seq);
        }
    }
    let (a, m) = (
        april_destroyed_at.expect("April DEK destroyed"),
        may_destroyed_at.expect("May DEK destroyed"),
    );
    assert!(a < m);
    let fs = sim.store.full_verify();
    assert!(
        !fs.iter()
            .any(|f| f.kind == FindingKind::DestroyedKeyReferenced),
        "{fs:?}"
    );
    assert!(fs.is_empty(), "{fs:?}");
}

#[test]
fn current_dek_never_destroyed() {
    // A fresh DEK for the current month that no record uses yet (as a key rotation leaves
    // it) is the one new records get: the prune keeps it although nothing references it.
    let sim = sim_with_due_prune();
    let kek = Kek::from_entry_bytes(
        &sim.f
            .ring
            .raw_get(&service_name(&sim.f.install_id), "kek")
            .expect("kek"),
    )
    .expect("kek layout");
    let month = sim.today().format("%Y-%m").to_string();
    let id = keys(&sim.f).last().expect("keys").0 + 1;
    let wrapped =
        crypto::wrap_dek(&kek, id, Some(&month), &Dek::generate().expect("dek")).expect("wrap");
    raw_conn(&sim.f)
        .execute(
            "INSERT INTO keys(key_id, month, wrapped_dek, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id as i64, month, wrapped, "2027-01-12T12:00:00.000Z"],
        )
        .expect("insert key");
    let (_, _, _, _, _, _, _, destroyed) = pruned(sim.store.prune(None).expect("prune"));
    assert!(!destroyed.contains(&id), "{destroyed:?}");
    assert!(keys(&sim.f).iter().any(|k| k.0 == id && k.2));
    let c = sim
        .store
        .append(ev(EventType::APP_START, None, json!({})))
        .expect("append");
    assert_eq!(rows(&sim.f)[&c.seq].3, id);
}

// ---------------------------------------------------------------------------------------
// Vacuum, payload, crash and keychain failure

/// `len` hex characters that zstd cannot shrink much.
fn noise(seed: u64, len: usize) -> String {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len / 16)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            format!("{x:016x}")
        })
        .collect()
}

#[test]
fn post_prune_vacuum_and_checkpoint() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    prune_ready(&store, RETENTION);
    corroborate_now(&store, &f.clock);
    let big: Vec<_> = (0..150u64)
        .map(|i| {
            ev(
                EventType::READ_FETCHED,
                Some("r"),
                json!({ "i": i, "body": noise(i, 4000) }),
            )
        })
        .collect();
    store.append_batch(big).expect("append");
    for _ in 1..=93 {
        day(&store, &f.clock, 1);
    }
    let log = prune_log(&f);
    assert_eq!(log.len(), 1);
    assert!(log[0].first_retained_seq - log[0].range_start > 100);
    assert_eq!(store.testing_pragma("freelist_count"), Ok(0));
    let mut wal = f.db_path().into_os_string();
    wal.push("-wal");
    assert_eq!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0), 0);
}

#[test]
fn blocked_checkpoint_is_retried_and_shown() {
    let sim = Sim::new(RETENTION);
    sim.events(4);
    sim.days(92, 1);
    let mut wal = sim.f.db_path().into_os_string();
    wal.push("-wal");
    let wal_len = || std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    // A reader holding a snapshot from before the prune keeps TRUNCATE from completing.
    let reader = raw_conn(&sim.f);
    reader.execute_batch("BEGIN").expect("begin");
    let _: i64 = reader
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .expect("snapshot");
    sim.day(1);
    assert_eq!(prune_log(&sim.f).len(), 1);
    let h = sim.store.health();
    assert!(h.shred_checkpoint_pending);
    assert_eq!(h.last_prune_error, None, "the prune itself succeeded");
    assert!(wal_len() > 0);
    // Released: an idle writer turn retries and truncates.
    reader.execute_batch("COMMIT").expect("commit");
    drop(reader);
    let deadline = Instant::now() + Duration::from_secs(10);
    while sim.store.health().shred_checkpoint_pending {
        assert!(
            Instant::now() < deadline,
            "the checkpoint was never retried"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(wal_len(), 0);
    assert_eq!(sim.store.testing_pragma("busy_timeout"), Ok(5000));
}

#[test]
fn prune_payload_and_settings_snapshot() {
    let sim = Sim::new(RETENTION);
    sim.events(3);
    sim.days(93, 1);
    let r = sim.latest_prune().expect("prune");
    let p = sim.payload(r.prune_seq);
    assert_eq!(p["range"], json!([r.range_start, r.first_retained_seq]));
    assert_eq!(p["count"], json!(r.first_retained_seq - r.range_start));
    assert_eq!(p["cutoff"], json!(r.cutoff));
    assert_eq!(p["clamped"], json!(false));
    assert_eq!(p["baseline"], json!(epoch_of(d(&r.cutoff) - Days::new(1))));
    assert_eq!(p["destroyed_key_ids"], json!([1]));
    assert_eq!(p["prune_log_row_hash"], json!(hex::encode(r.row_hash)));
    assert_eq!(
        p["settings"],
        json!({ "anchor_dir": null, "instances": {}, "legal_hold": false, "retention_days": 92 })
    );
    let keys_row = &keys(&sim.f)[0];
    assert!(!keys_row.2);
    assert!(keys_row.3.is_some());
}

#[test]
fn u22_crash_after_prune_commit_reconciles() {
    let faults = Faults::new();
    let fc = faults.clone();
    let mut sim =
        Sim::start(START, RETENTION, move |cfg| cfg.hooks.faults = Some(fc)).corroborated();
    sim.events(2);
    sim.days(94, 2);
    let before = keychain_first_retained(&sim.f);
    faults.fail(FaultPoint::AfterPruneCommit, 1);
    sim.f.clock.advance(DAY);
    corroborate_now(&sim.store, &sim.f.clock);
    sim.store
        .append_batch(day_events(2))
        .expect("append before the prune attempt");
    // The writer stopped right after the PRUNE commit: no barrier, no anchor update.
    assert_eq!(
        sim.store.testing_pragma("user_version"),
        Err(AuditError::Closed)
    );
    let latest = sim.latest_prune().expect("prune");
    assert_eq!(latest.range_start, before.first_retained_seq);
    assert_eq!(keychain_first_retained(&sim.f), before);
    assert!(keychain_head(&sim.f).seq < latest.prune_seq);
    let verify = sim.restart();
    no_incident(&verify.findings);
    assert!(
        verify
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::InterruptedPruneReconciled),
        "{:?}",
        verify.findings
    );
    let vseq = verify.verify_seq.expect("VERIFY row");
    let v = sim.payload(vseq);
    // The PRUNE itself is past the head anchor, so `result` names the first finding,
    // `unanchored_tail`; the reconciliation is among the findings, and nothing is an incident.
    assert!(
        v["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|x| x["kind"] == json!("interrupted_prune_reconciled")),
        "{v}"
    );
    let flags: i64 = raw_conn(&sim.f)
        .query_row(
            "SELECT flags FROM events WHERE seq = ?1",
            [vseq as i64],
            |r| r.get(0),
        )
        .expect("VERIFY row");
    assert_eq!(flags as u64 & EventFlags::INTEGRITY_INCIDENT.bits(), 0);
    sim.store.flush_head_anchor().expect("flush");
    assert_keychain_matches_latest_row(&sim.f);
    assert_eq!(keychain_head(&sim.f).seq, sim.store.head().0);
    assert!(sim.store.full_verify().is_empty());
}

#[test]
fn u22_keychain_failure_after_prune_retried() {
    let sim = Sim::start(START, RETENTION, |cfg| {
        cfg.hooks.fast_anchor_backoff = true;
        cfg.hooks.anchor_batch_window = Some(Duration::from_millis(10));
    })
    .corroborated();
    sim.events(2);
    sim.days(92, 2);
    sim.f.ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::FirstRetainedAnchor),
        KeyStoreError::Unavailable,
        3,
    );
    sim.f.clock.advance(DAY);
    corroborate_now(&sim.store, &sim.f.clock);
    sim.store.append_batch(day_events(2)).expect("append");
    sync_writer(&sim.store);
    let prune_seq = sim.latest_prune().expect("prune").prune_seq;
    let h = sim.store.health();
    assert!(h.first_retained_update_pending);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_failing = false;
    while sim.store.health().first_retained_update_pending {
        assert!(
            Instant::now() < deadline,
            "first-retained update never succeeded"
        );
        saw_failing |= sim.store.health().anchor_write_failing;
        sim.store.append_batch(day_events(1)).expect("append");
        std::thread::sleep(Duration::from_millis(20));
        if let Some(b) = sim
            .f
            .ring
            .raw_get(&service_name(&sim.f.install_id), "head_anchor")
        {
            let head = HeadAnchor::from_entry(&b).expect("layout");
            if sim.store.health().first_retained_update_pending {
                assert!(head.seq <= prune_seq, "head anchor passed the PRUNE");
            }
        }
    }
    assert!(saw_failing);
    sim.store.flush_head_anchor().expect("flush");
    let h = sim.store.health();
    assert!(!h.first_retained_update_pending && !h.anchor_write_failing);
    assert_keychain_matches_latest_row(&sim.f);
    assert!(keychain_head(&sim.f).seq > prune_seq);
    let fs = sim.store.full_verify();
    assert!(fs.is_empty(), "{fs:?}");
    assert_eq!(count_events(&sim.f, "VERIFY"), 1);
}

#[test]
fn prune_rolls_back_before_commit() {
    let faults = Faults::new();
    let fc = faults.clone();
    let sim = Sim::start(START, RETENTION, move |cfg| cfg.hooks.faults = Some(fc)).corroborated();
    sim.events(2);
    sim.days(92, 2);
    faults.fail(FaultPoint::AfterPruneTxBeforeCommit, 1);
    let before = (rows(&sim.f), keys(&sim.f), sim.store.head());
    sim.day(2); // the automatic run fails inside its transaction
    assert!(prune_log(&sim.f).is_empty());
    let err = sim
        .store
        .health()
        .last_prune_error
        .expect("the failure is shown");
    assert!(err.contains("AfterPruneTxBeforeCommit"), "{err}");
    let after = rows(&sim.f);
    assert!(before.0.keys().all(|s| after.contains_key(s)));
    assert_eq!(keys(&sim.f), before.1);
    assert_eq!(sim.store.health().anchors_blocked, None);
    // Nothing of the failed run is left in memory: the next run chains from scratch.
    let (prune_seq, range_start, ..) = pruned(sim.store.prune(Some(confirmed())).expect("retry"));
    assert_eq!(prune_seq, sim.store.head().0);
    assert_eq!(range_start, 1);
    assert_eq!(sim.store.health().last_prune_error, None);
    sim.store.flush_head_anchor().expect("flush");
    assert!(sim.store.full_verify().is_empty());
}

#[test]
fn prune_refused_while_first_retained_update_pending() {
    let sim =
        Sim::start(START, RETENTION, |cfg| cfg.hooks.fast_anchor_backoff = true).corroborated();
    sim.events(2);
    sim.days(92, 2);
    sim.f.ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::FirstRetainedAnchor),
        KeyStoreError::Unavailable,
        u32::MAX,
    );
    sim.f.clock.advance(DAY);
    corroborate_now(&sim.store, &sim.f.clock);
    sim.store.append_batch(day_events(2)).expect("append");
    sync_writer(&sim.store);
    assert_eq!(prune_log(&sim.f).len(), 1);
    assert!(sim.store.health().first_retained_update_pending);
    // A second PRUNE now would leave the keychain two prunes behind (§8.7 (a)).
    sim.f.clock.advance(DAY);
    corroborate_now(&sim.store, &sim.f.clock);
    sim.store.append_batch(day_events(2)).expect("append");
    assert_eq!(
        sim.store.prune(Some(confirmed())),
        Err(AuditError::Invalid(
            "an anchor barrier is already installed"
        ))
    );
    assert_eq!(prune_log(&sim.f).len(), 1);
    sim.f.ring.clear_faults();
    sim.store.flush_head_anchor().expect("flush");
    assert!(!sim.store.health().first_retained_update_pending);
    pruned(sim.store.prune(None).expect("prune"));
    sim.store.flush_head_anchor().expect("flush");
    assert_keychain_matches_latest_row(&sim.f);
    assert!(sim.store.full_verify().is_empty());
}

#[test]
fn shredded_dek_leaves_the_cache() {
    let sim = Sim::new(RETENTION);
    sim.events(2);
    // GENESIS's key 1 was cached when it was created.
    assert!(sim.store.testing_dek_cached(1));
    sim.days(93, 1);
    assert!(!keys(&sim.f)[0].2);
    assert!(!sim.store.testing_dek_cached(1));
    assert!(matches!(
        sim.store.read_payload(1),
        Err(AuditError::NotFound { seq: 1 })
    ));
}
