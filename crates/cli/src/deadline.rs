//! The `--timeout` deadline (§4.1, PD-17): wall-clock from process start, shared by every
//! pre-submission step and the wait after it.

use std::time::{Duration, Instant};

/// §4.1 / L04: the default `--timeout` in seconds, as a duration.
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(100);

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

    /// `--timeout` as parsed: absent = `DEFAULT_TIMEOUT`, `0` = unbounded.
    pub(crate) fn from_timeout(start: Instant, timeout_s: Option<u64>) -> Deadline {
        let total = match timeout_s {
            None => Some(DEFAULT_TIMEOUT),
            Some(0) => None,
            Some(s) => Some(Duration::from_secs(s)),
        };
        Deadline { start, total }
    }

    /// Time left; `None` = no bound.
    pub(crate) fn remaining(&self) -> Option<Duration> {
        self.total.map(|t| t.saturating_sub(self.start.elapsed()))
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
        assert_eq!(
            Deadline::from_timeout(now, Some(7)).total,
            Some(Duration::from_secs(7))
        );
    }
}
