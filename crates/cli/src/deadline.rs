//! The `--timeout` deadline (§4.1, PD-17): wall-clock from process start, shared by every
//! pre-submission step and the wait after it.

use std::time::{Duration, Instant};

/// §4.1 / L04: the default `--timeout` in seconds, as a duration.
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(100);

/// The longest `--timeout` honored (ten years). Larger values clamp here, so `Instant + Duration`
/// stays in range for every deadline the CLI builds (I-1).
pub(crate) const MAX_TIMEOUT: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadline {
    pub start: Instant,
    /// `None` = no bound (`--timeout 0`: the pre-submission steps use their own limits only).
    pub total: Option<Duration>,
}

// Task 16 (connected commands) is the first non-test caller of everything below.
#[allow(dead_code)]
impl Deadline {
    pub(crate) fn new(start: Instant, total: Option<Duration>) -> Deadline {
        Deadline { start, total }
    }

    /// `--timeout` as parsed: absent = `DEFAULT_TIMEOUT`, `0` = unbounded, and any larger value
    /// is capped at `MAX_TIMEOUT`.
    pub(crate) fn from_timeout(start: Instant, timeout_s: Option<u64>) -> Deadline {
        let total = match timeout_s {
            None => Some(DEFAULT_TIMEOUT),
            Some(0) => None,
            Some(s) => Some(Duration::from_secs(s).min(MAX_TIMEOUT)),
        };
        Deadline { start, total }
    }

    /// Time left; `None` = no bound.
    pub(crate) fn remaining(&self) -> Option<Duration> {
        self.total.map(|t| t.saturating_sub(self.start.elapsed()))
    }

    /// The instant the total limit runs out. `None` = no bound (`--timeout 0`), or a limit `Instant`
    /// cannot represent; never panics.
    pub(crate) fn at(&self) -> Option<Instant> {
        self.total.and_then(|t| self.start.checked_add(t))
    }

    /// `min(own, remaining)`: the limit for one step that has its own limit.
    pub(crate) fn cap(&self, own: Duration) -> Duration {
        match self.remaining() {
            Some(left) => own.min(left),
            None => own,
        }
    }

    pub(crate) fn expired(&self) -> bool {
        self.remaining() == Some(Duration::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn deadline_caps_each_step() {
        let d = Deadline::new(Instant::now(), Some(Duration::from_secs(1)));
        assert!(d.cap(Duration::from_secs(5)) <= Duration::from_secs(1));
        assert_eq!(d.cap(Duration::from_millis(10)), Duration::from_millis(10));
        assert!(!d.expired());

        let short = Deadline::new(Instant::now(), Some(Duration::from_millis(20)));
        std::thread::sleep(Duration::from_millis(60));
        assert!(short.expired());
        assert_eq!(short.remaining(), Some(Duration::ZERO));
        assert_eq!(short.cap(Duration::from_secs(5)), Duration::ZERO);

        let open = Deadline::new(Instant::now(), None);
        assert_eq!(open.remaining(), None);
        assert_eq!(open.cap(Duration::from_secs(5)), Duration::from_secs(5));
        assert!(!open.expired());
    }

    #[test]
    fn timeout_maps_to_total() {
        let now = Instant::now();
        assert_eq!(
            Deadline::from_timeout(now, None).total,
            Some(DEFAULT_TIMEOUT)
        );
        assert_eq!(Deadline::from_timeout(now, Some(0)).total, None);
        assert_eq!(Deadline::from_timeout(now, Some(0)).at(), None);
        assert_eq!(
            Deadline::from_timeout(now, Some(7)).total,
            Some(Duration::from_secs(7))
        );
    }

    fn no_env(_: &str) -> Option<OsString> {
        None
    }

    #[test]
    fn huge_timeout_clamps_without_panicking() {
        let args = [
            OsString::from("--timeout"),
            OsString::from("18446744073709551615"),
            OsString::from("instances"),
        ];
        let (opts, _) = match crate::argv::parse(
            &args,
            &no_env,
            &mut crate::input::Inputs::new(std::io::empty()),
        ) {
            Ok(v) => v,
            Err(e) => panic!("parse failed: {}", e.message),
        };
        assert_eq!(opts.timeout, Some(u64::MAX));

        let d = Deadline::from_timeout(Instant::now(), opts.timeout);
        assert_eq!(d.total, Some(MAX_TIMEOUT));
        assert!(
            d.remaining()
                .is_some_and(|left| left > Duration::from_secs(1))
        );
        assert_eq!(d.cap(Duration::from_secs(5)), Duration::from_secs(5));
        assert!(d.at().is_some());
        assert!(!d.expired());
    }
}
