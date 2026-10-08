//! Clock scenarios over simulated months (§8.2, §8.6, §8.8, L36, L37; U-10..U-14, RF-1a,
//! RF-1b). The driver is `common::Sim`: the server `Date` is the real time, the local clock
//! is whatever the scenario makes of it, and after every step the driver checks what was
//! deleted and what was written against the real time.

mod common;

use std::time::Duration;

use atlas_duck_audit::clock::parse_epoch;
use atlas_duck_audit::types::{Confirmed, EventFlags, EventType};
use atlas_duck_audit::{SettingChange, VerifyFinding};
use chrono::{Days, NaiveDate};
use common::*;
use serde_json::{Value, json};

const RETENTION: u32 = 92;
const T0: &str = "2026-01-05T12:00:00.000Z";
/// Five years of local clock error, in days.
const FIVE_YEARS: i64 = 1826;

fn d(s: &str) -> NaiveDate {
    parse_epoch(s).expect("date")
}

fn flagged(r: &RawRow, f: EventFlags) -> bool {
    EventFlags::from_bits(r.flags).contains(f)
}

fn no_incident(fs: &[VerifyFinding]) {
    assert!(!fs.iter().any(|f| f.kind.is_incident()), "{fs:?}");
}

/// `(prune_seq, cutoff_epoch)` of every `prune_log` row.
fn cutoffs(sim: &Sim) -> Vec<(u64, NaiveDate)> {
    let c = raw_conn(&sim.f);
    let mut st = c
        .prepare("SELECT prune_seq, cutoff_epoch FROM prune_log ORDER BY prune_seq")
        .expect("prepare");
    st.query_map([], |r| {
        Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
    })
    .expect("query")
    .map(|r| {
        let (s, e) = r.expect("row");
        (s, d(&e))
    })
    .collect()
}

fn payload(sim: &Sim, seq: u64) -> Value {
    serde_json::from_slice(&sim.store.read_payload(seq).expect("read_payload")).expect("json")
}

/// Rows with a seq in `lo..=hi`.
fn between(sim: &Sim, lo: u64, hi: u64) -> Vec<RawRow> {
    dump_rows(&sim.f)
        .into_iter()
        .filter(|r| (lo..=hi).contains(&r.seq))
        .collect()
}

fn head_seq(sim: &Sim) -> u64 {
    sim.store.head().0
}

fn key_live(sim: &Sim, key_id: u64) -> bool {
    raw_conn(&sim.f)
        .query_row(
            "SELECT wrapped_dek IS NOT NULL FROM keys WHERE key_id = ?1",
            [key_id as i64],
            |r| r.get(0),
        )
        .expect("key row")
}

/// Releases and denials, the records a suspended app writes before its next server response.
fn decisions(n: usize) -> Vec<atlas_duck_audit::types::NewEvent> {
    (0..n)
        .map(|i| {
            let t = if i % 2 == 0 {
                EventType::READ_RELEASED
            } else {
                EventType::WRITE_DENIED
            };
            ev(t, Some("r1"), json!({ "i": i }))
        })
        .collect()
}

/// A corroborated start: one response and a few records on the first day.
fn running(real_start: &str, retention: u32) -> Sim {
    let mut sim = Sim::new(real_start, retention, 0);
    sim.server_date();
    sim.append(4);
    sim
}

fn finish_clean(sim: &Sim, retention: u32) {
    sim.assert_no_early_prune(retention);
    sim.assert_no_future_epoch_or_dek();
    no_incident(&sim.store.full_verify());
}

// ---------------------------------------------------------------------------------------
// U-10

#[test]
fn u10_forward_jump_never_over_prunes() {
    let mut sim = running(T0, RETENTION);
    sim.days(120, 4);
    assert!(
        sim.deleted_count() > 0,
        "pruning is running before the jump"
    );
    sim.set_wall_offset_days(40);
    sim.days(5, 4);
    sim.set_wall_offset_days(0);
    sim.days(100, 4);
    assert_eq!(sim.episode_anomalies("local_ahead").len(), 1);
    assert!(sim.episode_anomalies("local_behind").is_empty());
    finish_clean(&sim, RETENTION);
}

#[test]
fn u10_backward_jump_never_over_prunes() {
    let mut sim = running(T0, RETENTION);
    sim.days(120, 4);
    assert!(
        sim.deleted_count() > 0,
        "pruning is running before the jump"
    );
    sim.set_wall_offset_days(-40);
    sim.days(5, 4);
    sim.set_wall_offset_days(0);
    sim.days(100, 4);
    assert_eq!(sim.episode_anomalies("local_behind").len(), 1);
    assert!(sim.episode_anomalies("local_ahead").is_empty());
    finish_clean(&sim, RETENTION);
}

// ---------------------------------------------------------------------------------------
// U-11

#[test]
fn u11_five_year_forward_jump_at_start() {
    let mut sim = Sim::new(T0, RETENTION, FIVE_YEARS);
    let day0 = sim.real_date();
    assert!(sim.wall_date() > day0 + chrono::Months::new(12 * 4));
    // Instance traffic on the first day: the server says what day it really is.
    sim.server_date();
    let genesis_and_before = head_seq(&sim);
    sim.append(4);
    let first = between(&sim, genesis_and_before + 1, head_seq(&sim));
    assert!(!first.is_empty());
    let first_epoch = first
        .iter()
        .find_map(|r| r.epoch.clone())
        .expect("epoch from the first corroborated record");
    assert_eq!(
        d(&first_epoch),
        day0,
        "min(today, corroborated) = the real date"
    );
    assert!(
        dump_rows(&sim.f)[0].epoch.is_none(),
        "GENESIS is uncorroborated"
    );
    assert_eq!(sim.episode_anomalies("local_ahead").len(), 1);

    sim.days(2, 4);
    sim.set_wall_offset_days(0);
    let mut first_prune_day = None;
    for k in 3..=95u64 {
        sim.day(4);
        if first_prune_day.is_none() && !cutoffs(&sim).is_empty() {
            first_prune_day = Some(k);
        }
    }
    assert_eq!(sim.episode_anomalies("local_ahead").len(), 1);
    // The first prune runs on real day 93 and its cutoff is real day 1: the wrong clock moved
    // nothing.
    assert_eq!(first_prune_day, Some(93));
    let (_, cutoff) = cutoffs(&sim)[0];
    assert_eq!(cutoff, day0 + Days::new(1));
    // No month key beyond the real month was ever created.
    for (_, month, _) in key_rows(&sim.f) {
        assert!(month.as_deref().is_none_or(|m| m <= "2026-04"), "{month:?}");
    }
    finish_clean(&sim, RETENTION);
}

#[test]
fn u11_five_year_forward_jump_mid_process() {
    let mut sim = running(T0, RETENTION);
    sim.days(50, 4);
    sim.set_wall_offset_days(FIVE_YEARS);
    sim.days(2, 4);
    sim.set_wall_offset_days(0);
    sim.days(110, 4);
    assert_eq!(sim.episode_anomalies("local_ahead").len(), 1);
    assert!(
        sim.deleted_count() > 0,
        "pruning continued after the correction"
    );
    // The epoch followed the real date through and after the jump.
    let rows = dump_rows(&sim.f);
    let latest = rows.iter().filter_map(|r| r.epoch.as_deref()).max();
    assert_eq!(latest.map(d), Some(sim.real_date()));
    finish_clean(&sim, RETENTION);
}

// ---------------------------------------------------------------------------------------
// U-12

#[test]
fn u12_records_before_first_corroboration_after_30_day_gap() {
    // History ending on 2026-05-20, 30 days in which the app is off.
    let mut sim = running("2026-04-20T12:00:00.000Z", RETENTION);
    sim.days(30, 4);
    assert_eq!(sim.real_date(), d("2026-05-20"));
    sim.off(30);
    assert_eq!(sim.real_date(), d("2026-06-19"));

    let before = head_seq(&sim);
    sim.store
        .append_batch(day_events(5))
        .expect("held-back records");
    sim.settle();
    let held: Vec<RawRow> = between(&sim, before + 1, head_seq(&sim));
    assert_eq!(held.len(), 5);
    let may_key = held[0].key_id;
    for r in &held {
        assert_eq!(r.epoch.as_deref(), Some("2026-05-20"), "held back");
        assert!(r.ts_utc.starts_with("2026-06-19"), "current ts_utc");
        assert_eq!(r.key_id, may_key, "the May DEK");
    }
    let may = key_rows(&sim.f)
        .into_iter()
        .find(|k| k.0 == may_key)
        .expect("May key row");
    assert_eq!(may.1.as_deref(), Some("2026-05"));

    // Daily from here on, until the 5 rows are pruned. Every other May-epoch row goes first,
    // and a shred pass runs, while the held-back rows stay readable.
    let mut others_pruned_at = None;
    let mut gone_at = None;
    for _ in 0..120 {
        sim.day(2);
        let rows = dump_rows(&sim.f);
        let held_left = rows.iter().filter(|r| held.iter().any(|h| h.seq == r.seq));
        let held_left = held_left.count();
        let other_may = rows.iter().any(|r| {
            r.epoch.as_deref().is_some_and(|e| e.starts_with("2026-05"))
                && !held.iter().any(|h| h.seq == r.seq)
                && r.seq <= before
        });
        if !other_may && others_pruned_at.is_none() {
            others_pruned_at = Some(sim.real_date());
        }
        if held_left == 5 {
            for h in &held {
                sim.store.read_payload(h.seq).expect("still decrypts");
            }
            assert!(key_live(&sim, may_key), "May DEK on {}", sim.real_date());
        } else {
            assert_eq!(held_left, 0, "the five go together");
            gone_at = Some(sim.real_date());
            break;
        }
        if sim.real_date() == d("2026-09-19") {
            no_incident(&sim.store.full_verify());
            assert_eq!(sim.store.full_verify(), vec![], "decrypt pass clean");
        }
    }
    let others_pruned_at = others_pruned_at.expect("other May rows pruned");
    let gone_at = gone_at.expect("held-back rows pruned");
    assert!(others_pruned_at < gone_at, "the shred pass ran before");
    // 92 real days after 2026-06-19 is not enough: the cutoff must pass the rows' own date.
    assert!(
        gone_at >= d("2026-06-19") + Days::new(92),
        "pruned on {gone_at}"
    );
    // The PRUNE that took them also destroyed the May DEK.
    let log = cutoffs(&sim);
    let prune_seq = log.last().expect("prune_log").0;
    let p = payload(&sim, prune_seq);
    assert!(
        p["destroyed_key_ids"]
            .as_array()
            .expect("destroyed_key_ids")
            .contains(&json!(may_key)),
        "{p}"
    );
    assert!(!key_live(&sim, may_key));
    finish_clean(&sim, RETENTION);
}

#[test]
fn u12_restart_across_month_boundary_before_corroboration() {
    let mut sim = running("2026-07-28T12:00:00.000Z", RETENTION);
    sim.days(3, 4);
    assert_eq!(sim.real_date(), d("2026-07-31"));
    let july = key_rows(&sim.f).last().cloned().expect("a key");
    assert_eq!(july.1.as_deref(), Some("2026-07"));

    sim.off(1);
    assert_eq!(sim.real_date(), d("2026-08-01"));
    let before = head_seq(&sim);
    sim.store.append_batch(day_events(3)).expect("append");
    sim.settle();
    for r in between(&sim, before + 1, head_seq(&sim)) {
        assert_eq!(r.epoch.as_deref(), Some("2026-07-31"), "seq {}", r.seq);
        assert_eq!(r.key_id, july.0, "the July DEK");
    }
    assert!(
        key_rows(&sim.f)
            .iter()
            .all(|k| k.1.as_deref() != Some("2026-08")),
        "no August DEK before a corroboration"
    );

    // The first response ends it: August from then on.
    sim.server_date();
    sim.append(2);
    let last = dump_rows(&sim.f).pop().expect("row");
    assert_eq!(last.epoch.as_deref(), Some("2026-08-01"));
    assert!(
        key_rows(&sim.f)
            .iter()
            .any(|k| k.1.as_deref() == Some("2026-08")),
        "the August DEK exists now"
    );
    finish_clean(&sim, RETENTION);
}

// ---------------------------------------------------------------------------------------
// U-13

fn suspended_app(suspend: Duration) {
    let mut sim = running(T0, RETENTION);
    sim.days(10, 4);
    sim.suspend(suspend);
    // Releases and denials before the next response.
    let before = head_seq(&sim);
    sim.store.append_batch(decisions(6)).expect("append");
    sim.settle();
    let after_suspend = between(&sim, before + 1, head_seq(&sim));
    assert_eq!(after_suspend.len(), 6);
    for r in &after_suspend {
        assert!(
            !flagged(r, EventFlags::FORWARD),
            "seq {} clock_forward",
            r.seq
        );
        assert!(
            !flagged(r, EventFlags::BEHIND),
            "seq {} clock_behind",
            r.seq
        );
    }
    assert!(sim.anomalies().is_empty(), "{:?}", sim.anomalies());

    // The next response corroborates again; the records live on for the whole retention.
    sim.days(120, 4);
    assert!(sim.anomalies().iter().all(|a| a["kind"] == "prune_skipped"));
    let remaining: Vec<u64> = dump_rows(&sim.f).iter().map(|r| r.seq).collect();
    assert!(
        after_suspend.iter().all(|r| !remaining.contains(&r.seq)),
        "after 130 days the suspend-time records are pruned, not before"
    );
    finish_clean(&sim, RETENTION);
}

#[test]
fn u13_suspend_14_days() {
    suspended_app(Duration::from_secs(14 * 86_400));
}

#[test]
fn u13_suspend_2_5_days() {
    suspended_app(Duration::from_secs(60 * 3_600));
}

// ---------------------------------------------------------------------------------------
// U-14

/// A corroborated history, then the local clock `-days` behind for 60 real days, then right.
fn backward_mid_life(days: i64) {
    let mut sim = running(T0, RETENTION);
    sim.days(100, 4);
    assert!(sim.deleted_count() > 0);
    sim.set_wall_offset_days(-days);
    let first = head_seq(&sim) + 1;
    sim.days(60, 4);
    let last = head_seq(&sim);
    let episode: Vec<RawRow> = between(&sim, first, last)
        .into_iter()
        .filter(|r| r.event_type == "APP_START")
        .collect();
    assert_eq!(episode.len(), 240);
    for r in &episode {
        assert!(
            flagged(r, EventFlags::BEHIND),
            "seq {} lacks clock_behind",
            r.seq
        );
    }
    sim.set_wall_offset_days(0);
    sim.days(100, 4);
    assert_eq!(sim.episode_anomalies("local_behind").len(), 1);
    let rows = dump_rows(&sim.f);
    let after = rows.iter().filter(|r| r.seq > last).count();
    assert!(after > 0);
    assert!(
        rows.iter()
            .filter(|r| r.seq > last && r.event_type == "APP_START")
            .all(|r| !flagged(r, EventFlags::BEHIND)),
        "corrected records are unflagged"
    );
    finish_clean(&sim, RETENTION);
}

#[test]
fn u14_backward_60_days_mid_life() {
    backward_mid_life(60);
}

#[test]
fn u14_backward_10_days_mid_life() {
    backward_mid_life(10);
}

#[test]
fn u14_backward_first_run_variant() {
    let mut sim = Sim::new(T0, RETENTION, -60);
    // Two days without any server traffic.
    for _ in 0..2 {
        sim.tick();
        sim.append(3);
    }
    let uncorroborated = head_seq(&sim);
    for r in between(&sim, 1, uncorroborated) {
        assert!(r.epoch.is_none(), "seq {} {:?}", r.seq, r.epoch);
        assert!(
            !flagged(&r, EventFlags::BEHIND),
            "seq {} ({}) carries clock_behind before any corroboration",
            r.seq,
            r.event_type
        );
    }
    assert_eq!(between(&sim, 1, 1)[0].event_type, "GENESIS");
    // Traffic from day 3 on, the clock corrected after 60 days.
    sim.days(60, 4);
    let behind_until = head_seq(&sim);
    let during: Vec<RawRow> = between(&sim, uncorroborated + 1, behind_until)
        .into_iter()
        .filter(|r| r.event_type == "APP_START")
        .collect();
    assert_eq!(during.len(), 240);
    for r in &during {
        assert!(
            flagged(r, EventFlags::BEHIND),
            "seq {} lacks clock_behind",
            r.seq
        );
    }
    sim.set_wall_offset_days(0);
    sim.days(160, 4);
    assert_eq!(sim.episode_anomalies("local_behind").len(), 1);
    assert!(sim.deleted_count() > 0);
    finish_clean(&sim, RETENTION);
}

// ---------------------------------------------------------------------------------------
// RF-1a

#[test]
fn rf1a_first_run_forward_clock() {
    let retention = 100;
    let mut sim = Sim::new(T0, retention, 365);
    let day0 = sim.real_date();
    // An instance is added, traffic follows: the first response corroborates the real date.
    sim.server_date();
    sim.store
        .apply_setting(
            SettingChange::InstanceOrigin {
                instance_id: "i1".into(),
                origin: Some("https://jira.example".into()),
            },
            Some(Confirmed {
                dialog_text_sha256: [7; 32],
            }),
        )
        .expect("instance added");
    sim.append(4);
    let rows = dump_rows(&sim.f);
    assert!(rows[0].epoch.is_none(), "GENESIS is uncorroborated");
    for r in rows.iter().filter_map(|r| r.epoch.as_deref()) {
        assert_eq!(d(r), day0, "the first corroborated epoch is the real date");
    }
    assert_eq!(sim.episode_anomalies("local_ahead").len(), 1);

    sim.days(4, 4);
    sim.set_wall_offset_days(0);
    sim.days(200, 4);
    assert_eq!(sim.episode_anomalies("local_ahead").len(), 1);
    assert!(sim.deleted_count() > 0, "pruning ran after the correction");
    // No DEK for a month after the real one, whatever the clock said.
    let latest_month = key_rows(&sim.f)
        .into_iter()
        .filter_map(|k| k.1)
        .max()
        .expect("month DEK");
    let today = sim.real_date().format("%Y-%m").to_string();
    assert!(latest_month <= today, "{latest_month} > {today}");
    finish_clean(&sim, retention);
}

// ---------------------------------------------------------------------------------------
// RF-1b

/// Every automatic run advances its cutoff at most 2 epochs beyond its baseline (the previous
/// cutoff, or `GENESIS`'s effective epoch for the first); the backlog shrinks by a net day per
/// day. No `Store::prune` call is made, so no confirmation can ever have been involved.
fn assert_clamped_catch_up(sim: &mut Sim, genesis_epoch: NaiveDate, days: usize) {
    let mut baseline = cutoffs(sim).last().map_or(genesis_epoch, |c| c.1);
    let mut backlog: Option<u32> = None;
    for _ in 0..days {
        sim.day(3);
        let log = cutoffs(sim);
        let latest = log.last().expect("a prune ran").1;
        assert!(
            latest <= baseline + Days::new(2),
            "cutoff {latest} beyond baseline {baseline} + 2"
        );
        if latest != baseline {
            baseline = latest;
        }
        let now = sim.store.health().prune_backlog_days;
        if let Some(prev) = backlog
            && prev > 0
        {
            assert_eq!(now, prev - 1, "backlog on {}", sim.real_date());
        }
        backlog = Some(now);
        if now == 0 {
            break;
        }
    }
    assert_eq!(backlog, Some(0), "the backlog cleared");
}

#[test]
fn rf1b_prune_after_long_gap_no_baseline() {
    // (a) The app runs until just before the first prune would be due, is off for 3 days past
    // day 95 and only then prunes for the first time.
    let mut sim = running(T0, RETENTION);
    let day0 = sim.real_date();
    sim.days(92, 3);
    assert!(cutoffs(&sim).is_empty(), "no prune before day 93");
    sim.off(6);
    assert_eq!(sim.real_date(), day0 + Days::new(98));
    sim.server_date();
    sim.append(3);
    let first = cutoffs(&sim);
    assert_eq!(first.len(), 1, "the first-ever prune ran after the gap");
    let first_cutoff = first[0].1;
    let genesis_effective = d(dump_rows(&sim.f)
        .iter()
        .find_map(|r| r.epoch.clone())
        .expect("an epoch")
        .as_str());
    assert!(
        first_cutoff <= genesis_effective + Days::new(2),
        "first cutoff {first_cutoff}, GENESIS effective epoch {genesis_effective}"
    );
    assert!(sim.store.health().prune_backlog_days > 0);
    let mut backlog = sim.store.health().prune_backlog_days;
    while backlog > 0 {
        sim.day(3);
        let now = sim.store.health().prune_backlog_days;
        assert_eq!(now, backlog - 1);
        backlog = now;
    }
    let log = cutoffs(&sim);
    for w in log.windows(2) {
        assert!(w[1].1 <= w[0].1 + Days::new(2), "{w:?}");
    }
    sim.assert_no_early_prune(RETENTION);
    sim.assert_no_future_epoch_or_dek();
    no_incident(&sim.store.full_verify());

    // (b) A 30-day gap after a steady state.
    let mut sim = running(T0, RETENTION);
    sim.days(120, 3);
    let genesis_epoch = day0;
    let steady = cutoffs(&sim).last().expect("steady prunes").1;
    sim.off(30);
    sim.server_date();
    sim.append(3);
    let after_gap = cutoffs(&sim).last().expect("prune_log").1;
    assert_eq!(after_gap, steady + Days::new(2), "clamped, not skipped");
    assert!(sim.store.health().prune_backlog_days > 20);
    assert_clamped_catch_up(&mut sim, genesis_epoch, 60);
    finish_clean(&sim, RETENTION);
}
