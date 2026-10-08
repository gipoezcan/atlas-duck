use std::time::Duration;

use atlas_duck_audit::clock::{
    AnomalyKind, Clock, ClockState, SystemClock, UtcInstant, date_of, epoch_text, month_text,
    parse_epoch,
};
use atlas_duck_audit::types::EventFlags;
use chrono::NaiveDate;
use proptest::prelude::*;

const DAY: i64 = 86_400_000;
const H: i64 = 3_600_000;

fn ts(s: &str) -> UtcInstant {
    UtcInstant::parse_rfc3339_ms(s).expect("test instant")
}

fn d(s: &str) -> NaiveDate {
    parse_epoch(s).expect("test date")
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

const T0: &str = "2026-10-08T10:00:00.000Z";

#[test]
fn genesis_is_null_and_unflagged() {
    let mut s = ClockState::default();
    let st = s.stamp(ts(T0), Duration::ZERO);
    assert_eq!(st.epoch, None);
    assert_eq!(st.clock_flags, EventFlags::default());
}

#[test]
fn uncorroborated_records_stay_null_and_unflagged() {
    let mut s = ClockState::default();
    let t = ts(T0);
    s.stamp(t, Duration::ZERO);
    for i in 1..=3 {
        let st = s.stamp(UtcInstant(t.0 + i * 1000), secs(i as u64));
        assert_eq!(st.epoch, None);
        assert!(!st.clock_flags.contains(EventFlags::BEHIND));
    }
}

#[test]
fn first_corroboration_sets_min_today_corroborated() {
    let mut s = ClockState::default();
    let wall = ts("2027-10-08T10:00:00.000Z");
    s.stamp(wall, Duration::ZERO);
    let server = ts(T0);
    let a = s.observe(server, wall, Duration::ZERO).expect("anomaly");
    assert_eq!(a.kind, AnomalyKind::LocalAhead);
    assert!(s.observe(server, wall, Duration::ZERO).is_none());
    let st = s.stamp(wall, Duration::ZERO);
    assert_eq!(st.epoch, Some(d("2026-10-08")));
    assert!(st.clock_flags.contains(EventFlags::FORWARD));
    assert!(!st.clock_flags.contains(EventFlags::BEHIND));
}

#[test]
fn extrapolation_caps_epoch() {
    let mut s = ClockState::default();
    let server = ts("2026-10-08T23:00:00.000Z");
    s.observe(server, server, Duration::ZERO);
    let now = UtcInstant(server.0 + 2 * H);
    let st = s.stamp(now, secs(7200));
    assert_eq!(st.epoch, Some(d("2026-10-09")));
}

#[test]
fn mono_undercount_holds_epoch_back() {
    let mut s = ClockState::default();
    let server = ts(T0);
    s.observe(server, server, Duration::ZERO);
    let now = UtcInstant(server.0 + 14 * DAY);
    assert!(s.behind_transition(now, Duration::ZERO).is_none());
    let st = s.stamp(now, Duration::ZERO);
    assert_eq!(st.epoch, Some(d("2026-10-08")));
    assert_eq!(st.clock_flags, EventFlags::default());
}

#[test]
fn backward_clock_sets_behind_once() {
    for days in [60, 10] {
        let mut s = ClockState::default();
        let server = ts(T0);
        s.observe(server, server, Duration::ZERO);
        let first = s.stamp(server, Duration::ZERO);
        assert_eq!(first.epoch, Some(d("2026-10-08")));

        let back = UtcInstant(server.0 - days * DAY);
        let a = s.behind_transition(back, secs(1)).expect("episode starts");
        assert_eq!(a.kind, AnomalyKind::LocalBehind);
        let st = s.stamp(back, secs(1));
        assert!(st.clock_flags.contains(EventFlags::BEHIND));
        assert_eq!(st.epoch, Some(d("2026-10-08")));
        for _ in 0..100 {
            assert!(s.behind_transition(back, secs(1)).is_none());
        }

        // Corrected: episode ends.
        let fixed = UtcInstant(server.0 + 1000);
        assert!(s.behind_transition(fixed, secs(1)).is_none());
        let st = s.stamp(fixed, secs(1));
        assert!(!st.clock_flags.contains(EventFlags::BEHIND));

        // New backward step: second anomaly.
        assert!(s.behind_transition(back, secs(2)).is_some());
    }
}

#[test]
fn ten_day_backward_variant() {
    let mut s = ClockState::default();
    let server = ts(T0);
    s.observe(server, server, Duration::ZERO);
    let back = UtcInstant(server.0 - 10 * DAY);
    assert!(s.behind_transition(back, Duration::ZERO).is_some());
    assert!(
        s.stamp(back, Duration::ZERO)
            .clock_flags
            .contains(EventFlags::BEHIND)
    );
}

#[test]
fn clock_backwards_step_flag() {
    let mut s = ClockState::default();
    let t = ts(T0);
    s.stamp(t, Duration::ZERO);
    let st = s.stamp(UtcInstant(t.0 - 6000), Duration::ZERO);
    assert!(st.clock_flags.contains(EventFlags::BACKWARDS));

    let mut s = ClockState::default();
    s.stamp(t, Duration::ZERO);
    let st = s.stamp(UtcInstant(t.0 - 5000), Duration::ZERO);
    assert!(!st.clock_flags.contains(EventFlags::BACKWARDS));
}

#[test]
fn cmos_reset_before_corroboration() {
    let mut s = ClockState::from_head(Some(d("2026-10-08")), ts(T0), EventFlags::default());
    let wall = ts("2000-01-01T00:00:00.000Z");
    let st = s.stamp(wall, Duration::ZERO);
    assert!(st.clock_flags.contains(EventFlags::BEHIND));
    assert_eq!(st.epoch, Some(d("2026-10-08")));
    let st = s.stamp(UtcInstant(wall.0 + 1000), secs(1));
    assert!(st.clock_flags.contains(EventFlags::BEHIND));
    assert_eq!(st.epoch, Some(d("2026-10-08")));
}

#[test]
fn genesis_with_wrong_clock_not_flagged() {
    let mut s = ClockState::default();
    let wall = ts("2000-01-01T00:00:00.000Z");
    for i in 0..3 {
        let st = s.stamp(UtcInstant(wall.0 + i * 1000), secs(i as u64));
        assert_eq!(st.epoch, None);
        assert_eq!(st.clock_flags, EventFlags::default());
    }
    let now = UtcInstant(wall.0 + 3000);
    assert!(s.observe(ts(T0), now, secs(3)).is_none());
    let a = s.behind_transition(now, secs(3)).expect("behind");
    assert_eq!(a.kind, AnomalyKind::LocalBehind);
    let st = s.stamp(now, secs(3));
    assert!(st.clock_flags.contains(EventFlags::BEHIND));
}

#[test]
fn ahead_episode_ends_when_header_agrees() {
    let mut s = ClockState::default();
    let wall = ts("2027-10-08T10:00:00.000Z");
    s.observe(ts(T0), wall, Duration::ZERO);
    assert!(
        s.stamp(wall, Duration::ZERO)
            .clock_flags
            .contains(EventFlags::FORWARD)
    );
    // Header now within a day of the local clock.
    assert!(s.observe(wall, wall, secs(1)).is_none());
    assert!(
        !s.stamp(wall, secs(1))
            .clock_flags
            .contains(EventFlags::FORWARD)
    );
}

#[test]
fn system_clock_monotonic() {
    let c = SystemClock::new();
    let a = c.suspend_aware_elapsed();
    std::thread::sleep(Duration::from_millis(50));
    let b = c.suspend_aware_elapsed();
    assert!(b >= a + Duration::from_millis(40), "{a:?} -> {b:?}");
    let sys = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    assert!((c.now_utc().0 - sys).abs() < 5000);
}

#[test]
fn out_of_range_instants_never_become_1970() {
    let far = UtcInstant(i64::MAX);
    assert_eq!(far.to_rfc3339_ms(), "9999-12-31T23:59:59.999Z");
    assert!(far.try_to_rfc3339_ms().is_none());
    assert_eq!(far.date().to_string(), "9999-12-31");
    let low = UtcInstant(i64::MIN);
    assert_eq!(low.to_rfc3339_ms(), "0000-01-01T00:00:00.000Z");
    assert!(low.try_to_rfc3339_ms().is_none());
    assert_eq!(low.date().to_string(), "0000-01-01");
    assert!(UtcInstant(0).try_to_rfc3339_ms().is_some());
}

#[test]
fn date_text_helpers() {
    let t = ts(T0);
    assert_eq!(epoch_text(date_of(t)), "2026-10-08");
    assert_eq!(month_text(date_of(t)), "2026-10");
    assert!(parse_epoch("2026-10-08").is_some());
    for bad in [
        "2026-1-08",
        "2026-10-8",
        "2026-10-08 ",
        "20261008",
        "2026-02-30",
    ] {
        assert!(parse_epoch(bad).is_none(), "{bad}");
    }
}

#[derive(Clone, Debug)]
enum Op {
    Observe(i64),
    Stamp,
    WallJump(i64),
    Mono(u64),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (-5i64 * 365..=5 * 365).prop_map(Op::Observe),
        Just(Op::Stamp),
        (-5i64 * 365..=5 * 365).prop_map(Op::WallJump),
        (0u64..=3 * 86_400).prop_map(Op::Mono),
    ]
}

proptest! {
    #[test]
    fn epoch_never_decreases_and_never_exceeds_corroborated(ops in proptest::collection::vec(op(), 1..60)) {
        let base = ts(T0).0;
        let mut wall = base;
        let mut mono = Duration::ZERO;
        let mut s = ClockState::default();
        let mut last: Option<NaiveDate> = None;
        for o in ops {
            match o {
                Op::Observe(off) => {
                    let server = UtcInstant(base + off * DAY);
                    s.observe(server, UtcInstant(wall), mono);
                }
                Op::WallJump(dd) => wall += dd * DAY,
                Op::Mono(n) => mono += secs(n),
                Op::Stamp => {
                    let st = s.stamp(UtcInstant(wall), mono);
                    match (last, st.epoch) {
                        (Some(_), None) => prop_assert!(false, "epoch went back to NULL"),
                        (Some(p), Some(e)) => prop_assert!(e >= p),
                        _ => {}
                    }
                    if let Some(e) = st.epoch {
                        let cd = s.corroborated_date(mono).expect("non-NULL epoch needs corroboration");
                        prop_assert!(e <= cd);
                        last = Some(e);
                    }
                }
            }
        }
    }
}
