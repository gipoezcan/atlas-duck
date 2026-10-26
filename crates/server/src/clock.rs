//! Wall-clock seconds for sessions, rate limits and API keys, injectable so tests move time
//! without sleeping.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

pub trait Clock: Send + Sync {
    /// Unix seconds.
    fn now(&self) -> i64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }
}

/// A clock the test sets and advances.
#[derive(Default)]
pub struct ManualClock(AtomicI64);

impl ManualClock {
    pub fn at(secs: i64) -> Arc<ManualClock> {
        Arc::new(ManualClock(AtomicI64::new(secs)))
    }

    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// RFC 3339 UTC with milliseconds (`2026-10-26T09:00:00.000Z`) of unix seconds.
pub fn rfc3339(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}
