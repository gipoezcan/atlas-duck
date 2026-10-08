//! The injectable clock (C.3). `SystemClock` and `ClockState` arrive in T06; this file
//! holds the trait and the instant type everything else is built on.

use std::time::Duration;

use chrono::{DateTime, NaiveDate, NaiveDateTime};

/// Milliseconds since 1970-01-01T00:00:00Z (F.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcInstant(pub i64);

const RFC3339_MS: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";

impl UtcInstant {
    /// `YYYY-MM-DDTHH:MM:SS.mmmZ`, always 24 ASCII bytes (the `ts_utc` column text).
    pub fn to_rfc3339_ms(self) -> String {
        DateTime::from_timestamp_millis(self.0)
            .unwrap_or_default()
            .format(RFC3339_MS)
            .to_string()
    }

    /// Strict inverse of [`UtcInstant::to_rfc3339_ms`]: exactly milliseconds and a `Z`.
    pub fn parse_rfc3339_ms(s: &str) -> Option<UtcInstant> {
        if s.len() != 24 || !s.is_ascii() {
            return None;
        }
        let naive = NaiveDateTime::parse_from_str(s, RFC3339_MS).ok()?;
        let t = UtcInstant(naive.and_utc().timestamp_millis());
        (t.to_rfc3339_ms() == s).then_some(t)
    }

    /// The UTC calendar day (the `epoch` column and DEK months derive from it).
    pub fn date(self) -> NaiveDate {
        DateTime::from_timestamp_millis(self.0)
            .unwrap_or_default()
            .date_naive()
    }
}

pub trait Clock: Send + Sync {
    /// Wall clock.
    fn now_utc(&self) -> UtcInstant;
    /// CLOCK_BOOTTIME / mach_continuous_time / Windows interrupt time (V27).
    fn suspend_aware_elapsed(&self) -> Duration;
}
