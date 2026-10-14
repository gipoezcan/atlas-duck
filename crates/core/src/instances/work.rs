//! The admin work of the settings and credential windows at shutdown (§2.5 step 5, M3 M-4).
//!
//! Every `InstanceAdmin` call that can write (a record, `config.toml`, the keychain) or send (a
//! connection test) runs as a [`Job`]. A job is entered under the lock [`AdminWork::close`]
//! takes, after `Engine::begin_shutdown` stored its flag: a call either entered before the close
//! (and is cancelled and waited for by the shutdown) or sees the shutdown and does nothing
//! (`AdminError::ShuttingDown`, no I/O). The connection-test GETs of a job run under controls the
//! close cancels, so the drain ends with their result records (`class: cancelled`), never with a
//! start record after `APP_STOP`. The shutdown waits for [`AdminWork::idle`], bounded like the
//! field-cache and re-check drains.
//!
//! In-house rather than `tokio_util::task::TaskTracker`: that type needs `tokio-util`'s `rt`
//! feature, which the locked dependency graph does not enable. This is the
//! `identity::Gates` pattern (enter under the shutdown's lock, a guard that leaves on drop).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use atlas_duck_atlassian::FetchControl;

use super::AdminError;
use crate::engine::Engine;

/// The running admin jobs (M3 M-4).
#[derive(Default)]
pub(crate) struct AdminWork {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    closed: bool,
    next: u64,
    running: HashMap<u64, Arc<JobCtl>>,
}

/// The cancel state of one job: the controls of its GETs.
#[derive(Default)]
struct JobCtl {
    controls: Mutex<Controls>,
}

#[derive(Default)]
struct Controls {
    cancelled: bool,
    list: Vec<FetchControl>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl JobCtl {
    fn cancel(&self) {
        let mut c = lock(&self.controls);
        c.cancelled = true;
        for ctl in &c.list {
            ctl.cancel();
        }
    }
}

/// One admin call's place in [`AdminWork`]; it leaves when dropped.
pub(crate) struct Job {
    work: Arc<AdminWork>,
    n: u64,
    ctl: Arc<JobCtl>,
}

impl Drop for Job {
    fn drop(&mut self) {
        lock(&self.work.inner).running.remove(&self.n);
    }
}

impl AdminWork {
    fn register(self: &Arc<Self>, inner: &mut Inner) -> Job {
        inner.next += 1;
        let (n, ctl) = (inner.next, Arc::new(JobCtl::default()));
        inner.running.insert(n, ctl.clone());
        Job {
            work: self.clone(),
            n,
            ctl,
        }
    }

    /// A job starts unless the shutdown began (read under the lock `close` takes).
    pub(crate) fn enter(self: &Arc<Self>, engine: &Engine) -> Result<Job, AdminError> {
        let mut inner = lock(&self.inner);
        if inner.closed || engine.is_shutting_down() {
            return Err(AdminError::ShuttingDown);
        }
        Ok(self.register(&mut inner))
    }

    /// §2.5: no job starts from now on; every running one is cancelled (its GETs end with a
    /// `cancelled` result), never waited for here. Idempotent.
    pub(crate) fn close(&self) {
        let mut inner = lock(&self.inner);
        inner.closed = true;
        for ctl in inner.running.values() {
            ctl.cancel();
        }
    }

    /// No job is running (the shutdown waits for this before `APP_STOP`).
    pub(crate) fn idle(&self) -> bool {
        lock(&self.inner).running.is_empty()
    }
}

impl Job {
    /// A second place for work this job hands off (the detached follow-up of its writes): taken
    /// while this job still holds its own, so the shutdown never sees the work idle in between.
    pub(crate) fn fork(&self) -> Job {
        let job = {
            let mut inner = lock(&self.work.inner);
            self.work.register(&mut inner)
        };
        if self.cancelled() {
            job.ctl.cancel();
        }
        job
    }

    /// The control a GET of this job runs under: already cancelled once the shutdown began.
    pub(crate) fn fetch_control(&self) -> FetchControl {
        let ctl = FetchControl::new();
        let mut c = lock(&self.ctl.controls);
        if c.cancelled {
            ctl.cancel();
        }
        c.list.push(ctl.clone());
        ctl
    }

    /// The shutdown cancelled this job.
    pub(crate) fn cancelled(&self) -> bool {
        lock(&self.ctl.controls).cancelled
    }
}
