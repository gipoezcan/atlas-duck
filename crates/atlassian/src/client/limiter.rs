//! The per-instance limiter (§7.2): at most 4 concurrent requests, shared by direct reads,
//! enrichment and scripts, with pacing from `X-RateLimit-*`.

use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use tokio::sync::{Semaphore, SemaphorePermit};
use tokio::time::{Instant, sleep_until};

use super::FetchControl;
use super::classify::{MAX_WAIT, rate_limit_pause};

pub(crate) const MAX_CONCURRENT: usize = 4;

pub(crate) struct Limiter {
    permits: Semaphore,
    /// Set from a response with `X-RateLimit-Remaining: 0`; new permits wait until then.
    pace_until: Mutex<Option<Instant>>,
}

impl Limiter {
    pub(crate) fn new() -> Self {
        Limiter {
            permits: Semaphore::new(MAX_CONCURRENT),
            pace_until: Mutex::new(None),
        }
    }

    /// A permit, after any rate-limit pause; `None` when `ctl` was cancelled while waiting.
    pub(crate) async fn acquire(&self, ctl: &FetchControl) -> Option<SemaphorePermit<'_>> {
        let permit = tokio::select! {
            biased;
            () = ctl.cancelled() => return None,
            p = self.permits.acquire() => p.ok()?,
        };
        if let Some(until) = self.pause_deadline() {
            tokio::select! {
                biased;
                () = ctl.cancelled() => return None,
                () = sleep_until(until) => {}
            }
        }
        Some(permit)
    }

    /// Records the pacing headers of a response.
    pub(crate) fn observe(&self, headers: &reqwest::header::HeaderMap) {
        let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
        let Some(wait) = rate_limit_pause(
            get("x-ratelimit-remaining"),
            get("x-ratelimit-reset"),
            get("retry-after"),
            SystemTime::now(),
        ) else {
            return;
        };
        let until = Instant::now() + wait;
        let mut pace = self
            .pace_until
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if pace.is_none_or(|p| p < until) {
            *pace = Some(until);
        }
    }

    fn pause_deadline(&self) -> Option<Instant> {
        let mut pace = self
            .pace_until
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        match *pace {
            Some(until) if until > now => Some(until.min(now + MAX_WAIT)),
            Some(_) => {
                *pace = None;
                None
            }
            None => None,
        }
    }
}
