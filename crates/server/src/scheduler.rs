//! The in-process scheduler (SM-6.5, M13 T9, PD-M13-2): a daily offboarding check and a daily
//! retention sweep at `ATLAS_DUCK_OFFBOARDING_AT` (UTC). Not a CronJob: a second pod could not
//! mount the ReadWriteOnce volume and would be a second store opener (ADR 0003). The 15-minute
//! anchor tick stays the `AnchorWriter`'s.
//!
//! Each job's last run and last success live in the server store (`scheduler_state`), so a run
//! missed while the pod was down executes once at the next start. A failed run is retried an hour
//! later. Jobs never overlap each other, and they hold the admin operation lock, so they never
//! overlap an admin command either.
//!
//! Offboarding (PD-M13-14): only with an account lookup (the optional LDAP service bind, or the
//! test directory's file). Active users whose account is disabled or gone are deactivated through
//! the one deactivation path (`admin::users::deactivate`, by `offboarding`). A lookup error never
//! deactivates anyone, and a run that would deactivate implausibly many users (more than
//! `max(3, users / 4)`) deactivates nobody: a directory permission change must not offboard the
//! whole organisation overnight. Without a lookup the job runs and does nothing: offboarding is
//! manual (`users deactivate`), reported as `offboarding: "manual"` and `offboarding_enabled 0`.

use std::sync::Arc;
use std::time::Duration;

use crate::admin::AdminCtx;
use crate::admin::users::{DeactivatedBy, deactivate};
use crate::directory::account::{AccountLookup, AccountState};
use crate::store::JobState;

pub const JOB_OFFBOARDING: &str = "offboarding";
pub const JOB_RETENTION: &str = "retention";
/// A failed run is retried this long after it started.
pub const RETRY_SECS: i64 = 3600;
/// How often the loop looks for due jobs.
pub const CHECK_EVERY: Duration = Duration::from_secs(60);
const DAY: i64 = 86_400;

pub struct Scheduler {
    ctx: Arc<AdminCtx>,
    lookup: Option<Arc<dyn AccountLookup>>,
    at: (u32, u32),
    running: tokio::sync::Mutex<()>,
}

impl Scheduler {
    pub fn new(
        ctx: Arc<AdminCtx>,
        lookup: Option<Arc<dyn AccountLookup>>,
        at: (u32, u32),
    ) -> Scheduler {
        Scheduler {
            ctx,
            lookup,
            at,
            running: tokio::sync::Mutex::new(()),
        }
    }

    pub fn offboarding_enabled(&self) -> bool {
        self.lookup.is_some()
    }

    /// The most recent daily slot at or before `now` (unix seconds, UTC).
    pub fn last_slot(&self, now: i64) -> i64 {
        let slot =
            now.div_euclid(DAY) * DAY + i64::from(self.at.0) * 3600 + i64::from(self.at.1) * 60;
        if slot <= now { slot } else { slot - DAY }
    }

    fn due(&self, state: &JobState, now: i64) -> bool {
        let Some(run) = state.last_run_at else {
            return true;
        };
        if run < self.last_slot(now) {
            return true;
        }
        let failed = state.last_success_at.is_none_or(|s| s < run);
        failed && now >= run + RETRY_SECS
    }

    /// Runs every due job once, in order; answers `(job, succeeded)` of each run. Empty when
    /// nothing is due, or when a run is already going on (jobs never overlap).
    pub async fn run_due(&self) -> Vec<(&'static str, bool)> {
        let Ok(_one) = self.running.try_lock() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for job in [JOB_OFFBOARDING, JOB_RETENTION] {
            let now = self.ctx.clock.now();
            let Ok(state) = self.ctx.store.scheduler_get(job) else {
                tracing::error!(event = "scheduler_state_unavailable", job);
                continue;
            };
            if !self.due(&state, now) {
                continue;
            }
            let ok = match job {
                JOB_OFFBOARDING => self.offboarding().await,
                _ => self.retention().await,
            };
            let next = JobState {
                last_run_at: Some(now),
                last_success_at: if ok { Some(now) } else { state.last_success_at },
            };
            if self.ctx.store.scheduler_put(job, &next).is_err() {
                tracing::error!(event = "scheduler_state_unavailable", job);
            }
            tracing::info!(event = "scheduler_job", job, ok);
            out.push((job, ok));
        }
        out
    }

    async fn offboarding(&self) -> bool {
        let Some(lookup) = &self.lookup else {
            return true;
        };
        let _ops = self.ctx.lock_ops().await;
        let Ok(users) = self.ctx.store.users_all() else {
            return false;
        };
        let active: Vec<_> = users
            .into_iter()
            .filter(|(_, s)| s.deactivated_at.is_none())
            .collect();
        let mut errors = 0usize;
        let mut leaving = Vec::new();
        for (u, _) in &active {
            match lookup.account_state(&u.username).await {
                Ok(AccountState::Active) => {}
                Ok(AccountState::Disabled | AccountState::Gone) => leaving.push(u.user_id.clone()),
                Err(_) => errors += 1,
            }
        }
        if leaving.len() > (active.len() / 4).max(3) {
            tracing::error!(
                event = "offboarding_implausible",
                leaving = leaving.len(),
                users = active.len()
            );
            return false;
        }
        for user_id in &leaving {
            if deactivate(&self.ctx, user_id, DeactivatedBy::Offboarding)
                .await
                .is_err()
            {
                errors += 1;
            }
        }
        if errors > 0 {
            tracing::warn!(event = "offboarding_incomplete", errors);
        }
        errors == 0
    }

    async fn retention(&self) -> bool {
        let _ops = self.ctx.lock_ops().await;
        crate::admin::retention::run(&self.ctx, false).await.is_ok()
    }

    /// The loop: a check at once (missed runs), then every [`CHECK_EVERY`].
    pub fn spawn(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let s = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                s.run_due().await;
                tokio::time::sleep(CHECK_EVERY).await;
            }
        })
    }
}

#[cfg(test)]
#[path = "tests/scheduler.rs"]
mod tests;
