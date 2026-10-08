//! The per-instance limiter (§7.2): at most 4 concurrent requests, shared by direct reads,
//! enrichment and scripts, with pacing from `X-RateLimit-*`.

use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use tokio::sync::{Semaphore, SemaphorePermit};
use tokio::time::{Instant, sleep_until};

use super::FetchControl;
use super::classify::{MAX_WAIT, rate_limit_pause};

pub(crate) const MAX_CONCURRENT: usize = 4;

pub(crate) enum Acquired<'a> {
    Permit(SemaphorePermit<'a>),
    Cancelled,
    /// The overall budget ran out while waiting; nothing of this attempt was sent.
    Expired,
}

/// Never completes without a deadline.
async fn until(deadline: Option<Instant>) {
    match deadline {
        Some(d) => sleep_until(d).await,
        None => std::future::pending().await,
    }
}

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

    /// A permit, after any rate-limit pause. Both waits end early on a cancel or when the call's
    /// overall budget (`deadline`) runs out.
    pub(crate) async fn acquire(
        &self,
        ctl: &FetchControl,
        deadline: Option<Instant>,
    ) -> Acquired<'_> {
        let permit = tokio::select! {
            biased;
            () = ctl.cancelled() => return Acquired::Cancelled,
            () = until(deadline) => return Acquired::Expired,
            p = self.permits.acquire() => match p {
                Ok(p) => p,
                // The semaphore is never closed.
                Err(_) => return Acquired::Cancelled,
            },
        };
        if let Some(pause) = self.pause_deadline() {
            tokio::select! {
                biased;
                () = ctl.cancelled() => return Acquired::Cancelled,
                () = until(deadline) => return Acquired::Expired,
                () = sleep_until(pause) => {}
            }
        }
        Acquired::Permit(permit)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn waits_end_on_budget_or_cancel() -> TestResult {
        let l = Limiter::new();
        let ctl = FetchControl::new();
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT {
            match l.acquire(&ctl, None).await {
                Acquired::Permit(p) => held.push(p),
                _ => return Err("permit expected".into()),
            }
        }
        let soon = Instant::now() + Duration::from_millis(50);
        assert!(matches!(
            l.acquire(&ctl, Some(soon)).await,
            Acquired::Expired
        ));
        let cancelled = FetchControl::new();
        cancelled.cancel();
        assert!(matches!(
            l.acquire(&cancelled, None).await,
            Acquired::Cancelled
        ));
        drop(held);

        // The rate-limit pause is bounded by the budget as well.
        let paced = Limiter::new();
        *paced
            .pace_until
            .lock()
            .unwrap_or_else(PoisonError::into_inner) =
            Some(Instant::now() + Duration::from_secs(10));
        let soon = Instant::now() + Duration::from_millis(50);
        assert!(matches!(
            paced.acquire(&ctl, Some(soon)).await,
            Acquired::Expired
        ));
        Ok(())
    }
}
