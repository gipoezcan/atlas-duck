//! App launch (§4.7): when the CLI starts the app, how, and the poll that follows.
//!
//! `ensure_running` is the decision table: a refused data dir or a present endpoint never
//! launches; a missing app file or a missing desktop session fails without launching; otherwise
//! the launch lock (PD-22) serializes concurrent CLIs, the endpoint is checked again under it, the
//! app is started detached with the allowlisted environment (`env`, PD-23 `unix`, Task 15 on
//! Windows) and the endpoint (before first run: this host's pinned file, PD-04) is polled every
//! 100 ms for `min(20 s, remaining deadline)`. The function blocks (it sleeps between polls), so an
//! async caller runs it on a blocking thread.
pub(crate) mod env;
mod lock;
pub(crate) mod plan;
pub(crate) mod session;
pub(crate) mod stub;
#[cfg(unix)]
pub(crate) mod unix;
#[cfg(windows)]
pub(crate) mod windows;

use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use atlas_duck_ipc::envelope::{Envelope, ErrorCode};
use atlas_duck_ipc::paths::{BaseDirs, LocalDataDir};
use serde_json::{Map, Value};

use crate::deadline::Deadline;
use crate::discover::{self, AppLocation, DataState, Discovery, REASON_NOT_RUNNING};

/// §4.7: the post-launch poll's own limit.
pub(crate) const POLL_LIMIT: Duration = Duration::from_secs(20);
/// §4.7 / PD-04: poll interval (endpoint, or the pinned file before first run).
pub(crate) const POLL_EVERY: Duration = Duration::from_millis(100);
/// The launch-lock wait's own limit (the deadline caps it further). The holder keeps the lock for
/// its spawn plus at most `POLL_LIMIT`, so a waiter with time left outlasts it.
pub(crate) const LOCK_WAIT_LIMIT: Duration = Duration::from_secs(30);

pub(crate) const REASON_LAUNCH_TIMEOUT: &str = "launch_timeout";
pub(crate) const REASON_NO_GUI_SESSION: &str = "no_gui_session";
pub(crate) const REASON_FIRST_RUN: &str = "first_run";
pub(crate) const REASON_LAUNCH_BLOCKED_BY_JOB: &str = "launch_blocked_by_job";
/// §4.7 Windows step 3 (verbatim).
pub(crate) const MSG_LAUNCH_BLOCKED_BY_JOB: &str =
    "start atlas-duck from the desktop or enable autostart";
/// PD-24 (plan wording for the spec's "hint to start the app from the desktop").
pub(crate) const MSG_NO_GUI_SESSION: &str = "no desktop session: start atlas-duck from the desktop";
/// §2.5 G1 fixed message, reused by PD-04 for a launch that never finished first run.
pub(crate) const MSG_FIRST_RUN: &str =
    "atlas-duck is not set up yet: finish the setup window on the desktop";
pub(crate) const MSG_LAUNCH_TIMEOUT: &str =
    "the atlas-duck app did not become reachable in time; nothing was queued";
pub(crate) const MSG_LAUNCH_FAILED: &str =
    "the atlas-duck app could not be started: start atlas-duck from the desktop";

/// Why starting the app failed.
// The causes in `Io`/`ChildFailed` are kept for Debug output (never read); `Unsupported` is built
// only on hosts that are neither Unix nor Windows.
#[derive(Debug)]
pub(crate) enum LaunchError {
    /// A path, argument or environment entry the OS cannot take (embedded NUL, `=` in a name).
    InvalidArgument,
    /// `fork`/`open`/`waitpid` and friends.
    Io(#[allow(dead_code)] io::Error),
    /// The intermediate launcher process exited with this code.
    ChildFailed(#[allow(dead_code)] i32),
    /// Windows: no shell parent, and this process's job allows no breakaway (§4.7 step 3).
    #[cfg_attr(not(windows), allow(dead_code))]
    BlockedByJob,
    /// No launcher on this OS (neither Unix nor Windows), or the stub run off Windows.
    #[cfg_attr(windows, allow(dead_code))]
    Unsupported,
    /// The deadline, not the step's own limit, ran out during the Windows stub wait (L81).
    #[cfg_attr(not(windows), allow(dead_code))]
    DeadlineExpired,
}

/// PD-21: how long the CLI waits for the Windows launch stub's exit code.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const STUB_WAIT: Duration = Duration::from_secs(5);

/// How long to wait for the stub and whether the deadline (not `own`) set that limit.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StubWait {
    pub wait: Duration,
    pub capped: bool,
}

/// L81 / PD-130: `min(own, remaining)`; an expired deadline is `DeadlineExpired` without waiting.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn stub_wait(deadline: &Deadline, own: Duration) -> Result<StubWait, LaunchError> {
    if deadline.expired() {
        return Err(LaunchError::DeadlineExpired);
    }
    let wait = deadline.cap(own);
    Ok(StubWait {
        wait,
        capped: wait < own,
    })
}

/// The OS seams of `ensure_running`; `OsLaunchSys` is the real one, tests inject doubles.
pub(crate) trait LaunchSys: Sync {
    /// PD-24.
    fn gui_session(&self) -> bool;
    /// The launched app's environment (§4.7 allowlist).
    fn launch_env(&self) -> Vec<(OsString, OsString)>;
    /// Starts `app --background` detached with exactly `env` (PD-23 / Task 15). Any probe it runs
    /// first (Linux's `systemd-run`) stays within `deadline`.
    fn spawn_app(
        &self,
        app: &Path,
        env: &[(OsString, OsString)],
        deadline: &Deadline,
    ) -> Result<(), LaunchError>;
    /// Whether the app answers on this user's endpoint: a liveness probe, not just the file, so a
    /// stale endpoint left by a crashed app neither stops a launch nor ends the poll early.
    fn endpoint_present(&self, data: &LocalDataDir, host: &str) -> bool;
    /// This user's base folders: where the pinned files and the first-run lock live.
    fn base_dirs(&self) -> io::Result<BaseDirs>;
}

/// The real OS.
pub(crate) struct OsLaunchSys;

impl LaunchSys for OsLaunchSys {
    fn gui_session(&self) -> bool {
        session::gui_session()
    }

    fn launch_env(&self) -> Vec<(OsString, OsString)> {
        env::launch_env(std::env::vars_os())
    }

    fn spawn_app(
        &self,
        app: &Path,
        env: &[(OsString, OsString)],
        deadline: &Deadline,
    ) -> Result<(), LaunchError> {
        #[cfg(unix)]
        {
            unix::launch_app(app, env, deadline)
        }
        #[cfg(windows)]
        {
            windows::launch_app(app, env, deadline)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (app, env, deadline);
            Err(LaunchError::Unsupported)
        }
    }

    fn endpoint_present(&self, data: &LocalDataDir, host: &str) -> bool {
        #[cfg(unix)]
        {
            unix::endpoint_answers(data, host)
        }
        #[cfg(not(unix))]
        {
            discover::endpoint_present(data, host)
        }
    }

    fn base_dirs(&self) -> io::Result<BaseDirs> {
        atlas_duck_ipc::paths::base_dirs()
    }
}

fn with_reason(mut env: Envelope, reason: &str) -> Envelope {
    if let Some(err) = env.error.as_mut() {
        let mut details = Map::new();
        details.insert("reason".to_owned(), Value::from(reason));
        err.details = Some(details);
    }
    env
}

pub(crate) fn unreachable(reason: &str, message: &str) -> Box<Envelope> {
    Box::new(with_reason(
        Envelope::failed(ErrorCode::Unreachable, true, message),
        reason,
    ))
}

/// `unreachable {launch_timeout}`, exit 5: the poll's own 20 s ran out, or the `--timeout`
/// deadline expired before submission (§4.1, §4.7).
pub(crate) fn launch_timeout() -> Box<Envelope> {
    unreachable(REASON_LAUNCH_TIMEOUT, MSG_LAUNCH_TIMEOUT)
}

/// `unreachable {no_gui_session}`, exit 5 (PD-24).
pub(crate) fn no_gui_session() -> Box<Envelope> {
    unreachable(REASON_NO_GUI_SESSION, MSG_NO_GUI_SESSION)
}

/// `not_configured {first_run}`, exit 9 (PD-04): launched, but no pinned file appeared in time.
pub(crate) fn first_run() -> Box<Envelope> {
    Box::new(with_reason(
        Envelope::failed(ErrorCode::NotConfigured, true, MSG_FIRST_RUN),
        REASON_FIRST_RUN,
    ))
}

/// The app could not be started (spawn or launch-lock failure). The spec's `unreachable` reasons
/// are a closed set, so this is `not_running` with a desktop hint; a launch the agent's job blocks
/// is `launch_blocked_by_job` (§4.7 Windows step 3).
pub(crate) fn launch_failed(e: &LaunchError) -> Box<Envelope> {
    match e {
        LaunchError::BlockedByJob => {
            unreachable(REASON_LAUNCH_BLOCKED_BY_JOB, MSG_LAUNCH_BLOCKED_BY_JOB)
        }
        LaunchError::DeadlineExpired => launch_timeout(),
        _ => unreachable(REASON_NOT_RUNNING, MSG_LAUNCH_FAILED),
    }
}

/// Where this host's data dir stands right now: `Ok(None)` before first run, the refusal when the
/// pinned file turned unusable.
fn current_data(base: &BaseDirs, host: &str) -> Result<Option<LocalDataDir>, Box<Envelope>> {
    match discover::discover_with(base, host, &|_| None, None).data {
        DataState::BeforeFirstRun => Ok(None),
        DataState::Local(dir) => Ok(Some(dir)),
        DataState::Refused(env) => Err(env),
    }
}

/// Makes sure the app is running, launching it if needed (§4.7 "When to launch", PD-04, PD-22).
/// `Ok` carries the data dir whose endpoint is present; `Err` is the envelope to print (nothing
/// was queued).
pub(crate) fn ensure_running(
    d: &Discovery,
    deadline: &Deadline,
    sys: &dyn LaunchSys,
) -> Result<LocalDataDir, Box<Envelope>> {
    // (1) A refused data dir never launches; (2) a present endpoint needs no launch (and no GUI
    // session: an SSH session reaches a running app). Busy is the connect layer's concern.
    let mut data = match &d.data {
        DataState::Refused(env) => return Err(env.clone()),
        DataState::Local(dir) if sys.endpoint_present(dir, &d.host) => return Ok(dir.clone()),
        DataState::Local(dir) => Some(dir.clone()),
        DataState::BeforeFirstRun => None,
    };
    // (3) No app file: nothing to launch.
    let AppLocation::Found(app) = &d.app else {
        return Err(Box::new(discover::app_not_found()));
    };
    // (4) PD-24.
    if !sys.gui_session() {
        return Err(no_gui_session());
    }
    if deadline.expired() {
        return Err(launch_timeout());
    }

    // (5) PD-22: the lock, waited for within the deadline.
    // Before first run there is no data dir: the lock lives in the pinned dir, whose base folders
    // are also where the poll re-reads the pinned file.
    let (lock_path, base) = match &data {
        Some(dir) => (lock::data_lock_path(dir), None),
        None => {
            let base = sys
                .base_dirs()
                .map_err(|e| launch_failed(&LaunchError::Io(e)))?;
            lock::ensure_pinned_dir(&base).map_err(|e| launch_failed(&LaunchError::Io(e)))?;
            (lock::first_run_lock_path(&base, &d.host), Some(base))
        }
    };
    let _lock = match lock::acquire(&lock_path, deadline.cap(LOCK_WAIT_LIMIT)) {
        Ok(held) => held,
        Err(lock::LockError::TimedOut) => return Err(launch_timeout()),
        Err(lock::LockError::Io(e)) => return Err(launch_failed(&LaunchError::Io(e))),
    };
    // Another CLI may have launched while this one waited.
    if let Some(base) = &base {
        data = current_data(base, &d.host)?;
    }
    if let Some(dir) = &data
        && sys.endpoint_present(dir, &d.host)
    {
        return Ok(dir.clone());
    }
    if deadline.expired() {
        return Err(launch_timeout());
    }

    // (6) Detached spawn with the allowlisted environment.
    let env = sys.launch_env();
    sys.spawn_app(app, &env, deadline)
        .map_err(|e| launch_failed(&e))?;

    // (7) Poll for min(20 s, remaining).
    let until = Instant::now() + deadline.cap(POLL_LIMIT);
    // A pinned file that is refused mid-poll may be the wizard's write racing its own mkdir: it is
    // re-read on every tick and only the last refusal is printed when the poll ends.
    let mut refused = None;
    loop {
        if data.is_none()
            && let Some(base) = &base
        {
            // PD-04: a pinned file that appears continues with the normal path (the endpoint).
            match current_data(base, &d.host) {
                Ok(now) => {
                    data = now;
                    refused = None;
                }
                Err(env) => refused = Some(env),
            }
        }
        if let Some(dir) = &data
            && sys.endpoint_present(dir, &d.host)
        {
            return Ok(dir.clone());
        }
        let now = Instant::now();
        if now >= until {
            break;
        }
        std::thread::sleep(POLL_EVERY.min(until - now));
    }
    Err(match (data, refused) {
        (None, Some(env)) => env,
        (None, None) => first_run(),
        (Some(_), _) => launch_timeout(),
    })
}

#[cfg(test)]
mod tests;
