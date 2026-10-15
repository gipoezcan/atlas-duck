//! OS end-session hooks (§2.5 "Shutdown path", §15 V20, I-40, L83, M6 T29). Every way the app is
//! asked to stop runs the one shutdown path ([`serve::shutdown_then_exit`]) once, through a
//! [`ShutdownPort`]; the hooks only say when, with which reason, and how long the OS waits:
//!
//! - Windows ([`windows`]): a hidden top-level window answers `WM_QUERYENDSESSION` (FALSE with
//!   `ShutdownBlockReasonCreate` while a write is on the wire) and `WM_ENDSESSION`.
//! - macOS ([`macos`]): `applicationShouldTerminate:` on the app delegate answers
//!   `NSTerminateLater` and replies at the end of the path. Cmd+Q, the Dock's Quit and the
//!   logout's quit event all arrive there (L83); a logout, restart or shutdown is `OsShutdown`,
//!   the others `Quit`.
//! - Linux ([`linux`]): logind `PrepareForShutdown(true)`, with a `delay` inhibitor held from the
//!   start until the end of the path.
//! - Unix: `SIGTERM` and `SIGINT` (`tokio::signal::unix`).
//! - The run loop ([`on_exit_requested`], [`on_loop_exit`]): an exit request that does not follow
//!   the last window closing runs the path with `Quit`; a loop that ends without the path (tao's
//!   `WM_ENDSESSION`, AppKit's `terminate:` without the delegate method) runs it before it ends.
//!
//! Every source logs `APP_STOP` through the path: `os_shutdown` for the OS end-session sources,
//! `quit` for Cmd+Q, the tray, the header and the credential window. PD-83 (L111): each OS grants a
//! bounded delay; when it ends the process first, the write that was on the wire is reconciled
//! `outcome_unknown {crash}` at the next start (§11.3).

pub mod linux;
pub mod macos;
pub mod windows;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use atlas_duck_core::ShutdownReason;
use tauri::{AppHandle, Manager, Runtime, State};

use crate::serve;
use crate::state::ServeSlot;

/// The longest the shutdown path takes (PD-38): the 75 s outer bound, the server's 2 s and the
/// store's 10 s, and one second more. A hook that waits for the path waits at most this long.
pub const PATH_WAIT: Duration = Duration::from_secs(
    serve::SHUTDOWN_OUTER.as_secs()
        + serve::SERVE_STOP_WAIT.as_secs()
        + serve::STORE_WAIT.as_secs()
        + 1,
);

/// When the OS ends the process at the end of the path (macOS `replyToApplicationShouldTerminate:`),
/// the path's own `exit(0)` follows after this, in case the OS did not.
pub const EXIT_GRACE: Duration = Duration::from_secs(2);

/// Log event: an OS end-session source fired (`reason`: which one).
pub const LOG_EVENT_OS_END_SESSION: &str = "os_end_session";
/// Log event: a hook could not be installed or an OS call failed (`reason`: the hook,
/// `error_class`: the step). The app runs on; the run loop's fallback ([`on_loop_exit`]) stays.
pub const LOG_EVENT_OS_HOOK_FAILED: &str = "os_hook_failed";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One run of the shutdown path: its reason, and whether it ended. Clones share the run.
#[derive(Clone)]
pub struct ShutdownTicket(Arc<Ticket>);

struct Ticket {
    reason: ShutdownReason,
    ended: Mutex<bool>,
    wake: Condvar,
}

impl ShutdownTicket {
    pub fn new(reason: ShutdownReason) -> ShutdownTicket {
        ShutdownTicket(Arc::new(Ticket {
            reason,
            ended: Mutex::new(false),
            wake: Condvar::new(),
        }))
    }

    /// The reason of the run (the first source's).
    pub fn reason(&self) -> ShutdownReason {
        self.0.reason
    }

    /// The path ended: the store is shut down and the exit follows.
    pub fn is_done(&self) -> bool {
        *lock(&self.0.ended)
    }

    /// Waits until the path ended, at most `d` (blocking: never on the async runtime's threads).
    /// True when it ended.
    pub fn wait_timeout(&self, d: Duration) -> bool {
        let deadline = Instant::now().checked_add(d);
        let mut ended = lock(&self.0.ended);
        while !*ended {
            let left = deadline.map_or(d, |at| at.saturating_duration_since(Instant::now()));
            if left.is_zero() {
                return false;
            }
            ended = self
                .0
                .wake
                .wait_timeout(ended, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }

    /// The path ended: every waiter wakes.
    pub fn complete(&self) {
        *lock(&self.0.ended) = true;
        self.0.wake.notify_all();
    }
}

impl std::fmt::Debug for ShutdownTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownTicket")
            .field("reason", &self.reason())
            .field("done", &self.is_done())
            .finish()
    }
}

/// What an OS hook needs from the app. The app's is [`AppPort`]; tests inject a fake.
pub trait ShutdownPort: Send + Sync {
    /// Starts the one shutdown path with `reason`, or joins the one that runs: a later call never
    /// starts a second run, and its reason does not change the first's. The ticket ends at the end
    /// of the path, right before the exit.
    fn begin(&self, reason: ShutdownReason) -> ShutdownTicket;
    /// True while a write request is on the wire (§2.5 step 4): the one thing the hooks hold the
    /// OS back for.
    fn write_in_flight(&self) -> bool;
}

/// An action run at the end of the path, before the exit (a hook releasing its OS block).
pub type BeforeExit = Box<dyn FnOnce() + Send>;

#[derive(Default)]
struct Finish {
    ended: bool,
    actions: Vec<BeforeExit>,
}

/// The shutdown path of this process (managed by the app; [`path_of`]): its one ticket, the
/// actions to run at its end, and what the run loop needs to tell a window close from a quit.
#[derive(Default)]
pub struct ShutdownPath {
    ticket: OnceLock<ShutdownTicket>,
    finish: Mutex<Finish>,
    os_ends_process: AtomicBool,
    window_destroyed: AtomicBool,
}

impl ShutdownPath {
    /// The run's ticket. `start` runs for the first call only, with the new ticket: it starts the
    /// path, which calls [`ShutdownPath::end`] when it is done. Later calls (concurrent ones too)
    /// get the first call's ticket and start nothing.
    pub fn begin(
        &self,
        reason: ShutdownReason,
        start: impl FnOnce(ShutdownTicket),
    ) -> ShutdownTicket {
        let mut first = false;
        let ticket = self
            .ticket
            .get_or_init(|| {
                first = true;
                ShutdownTicket::new(reason)
            })
            .clone();
        if first {
            start(ticket.clone());
        }
        ticket
    }

    /// The run's ticket, once one began.
    pub fn ticket(&self) -> Option<ShutdownTicket> {
        self.ticket.get().cloned()
    }

    /// The path ran to its end.
    pub fn ended(&self) -> bool {
        self.ticket.get().is_some_and(ShutdownTicket::is_done)
    }

    /// Runs `action` at the end of the path, after the ticket ended and before the exit. False
    /// when the path already ended: then nothing is kept, and the caller acts at once.
    pub fn before_exit(&self, action: BeforeExit) -> bool {
        let mut finish = lock(&self.finish);
        if finish.ended {
            return false;
        }
        finish.actions.push(action);
        true
    }

    /// The OS ends the process itself at the end of the path (macOS, after the reply): the path's
    /// own exit then waits [`EXIT_GRACE`] first.
    pub fn set_os_ends_process(&self) {
        self.os_ends_process.store(true, Ordering::SeqCst);
    }

    /// The end of the path (its task calls this once, right before the exit): the ticket ends, the
    /// before-exit actions run in the order they came. True when the OS ends the process.
    pub fn end(&self) -> bool {
        let actions = {
            let mut finish = lock(&self.finish);
            finish.ended = true;
            std::mem::take(&mut finish.actions)
        };
        if let Some(ticket) = self.ticket.get() {
            ticket.complete();
        }
        for action in actions {
            action();
        }
        self.os_ends_process.load(Ordering::SeqCst)
    }

    /// A window was destroyed (or closed without being hidden): a code-less exit request right
    /// after it is the last window closing.
    pub fn note_window_destroyed(&self) {
        self.window_destroyed.store(true, Ordering::SeqCst);
    }

    /// One run-loop iteration ended: the exit request that follows a window's destruction comes
    /// in the same iteration, so an older note no longer counts.
    pub fn note_loop_iteration(&self) {
        self.window_destroyed.store(false, Ordering::SeqCst);
    }

    fn take_window_destroyed(&self) -> bool {
        self.window_destroyed.swap(false, Ordering::SeqCst)
    }
}

/// What an exit request of the run loop does (§2.5 "the app exits only through the shutdown path").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitRequest {
    /// The path ended (it calls `exit(0)` itself): the exit goes ahead.
    Honour,
    /// The last window closed (a code-less request right after a window was destroyed): the tray
    /// app keeps running.
    Prevent,
    /// Anything else (an app-level quit that did not come through the path): prevented, and the
    /// path runs with `Quit`; it exits at its end.
    RunPath,
}

/// The run-loop mapping (L83: an OS-initiated quit such as Cmd+Q was swallowed by the old
/// "prevent every code-less exit" rule).
pub fn exit_request(
    code: Option<i32>,
    after_window_destroyed: bool,
    path_ended: bool,
) -> ExitRequest {
    if path_ended {
        ExitRequest::Honour
    } else if code.is_none() && after_window_destroyed {
        ExitRequest::Prevent
    } else {
        ExitRequest::RunPath
    }
}

/// `RunEvent::ExitRequested` through `port`: true when the request must be prevented.
pub fn exit_requested_with(
    port: &dyn ShutdownPort,
    path: &ShutdownPath,
    code: Option<i32>,
) -> bool {
    match exit_request(code, path.take_window_destroyed(), path.ended()) {
        ExitRequest::Honour => false,
        ExitRequest::Prevent => true,
        ExitRequest::RunPath => {
            port.begin(ShutdownReason::Quit);
            true
        }
    }
}

/// `RunEvent::Exit` through `port`: the run loop ends. After the path this is its own exit, and
/// nothing happens. Otherwise the loop ends without the path (tao ends it on `WM_ENDSESSION` and
/// calls `exit(0)` right after this callback; AppKit's `terminate:` when the delegate method could
/// not be added): the path runs now with `OsShutdown`, and this (the main) thread waits for it, at
/// most `wait`, before it lets the loop end. True when it ran the path.
pub fn loop_exit_with(port: &dyn ShutdownPort, path: &ShutdownPath, wait: Duration) -> bool {
    if path.ended() {
        return false;
    }
    tracing::warn!(event = LOG_EVENT_OS_END_SESSION, reason = "loop_exit");
    if !port.begin(ShutdownReason::OsShutdown).wait_timeout(wait) {
        tracing::warn!(
            event = LOG_EVENT_OS_HOOK_FAILED,
            reason = "loop_exit",
            error_class = "path_wait_expired"
        );
    }
    true
}

/// `SIGTERM` or `SIGINT` (Unix): the path runs with `OsShutdown`; a second signal joins it.
pub fn on_signal(port: &dyn ShutdownPort) -> ShutdownTicket {
    port.begin(ShutdownReason::OsShutdown)
}

/// The app's [`ShutdownPath`], managed on first use (the app manages it in `setup`; tests that
/// build an app without it get one here).
pub fn path_of<R: Runtime>(app: &AppHandle<R>) -> State<'_, ShutdownPath> {
    if let Some(path) = app.try_state::<ShutdownPath>() {
        return path;
    }
    // A concurrent first use: `manage` keeps the one that came first.
    app.manage(ShutdownPath::default());
    app.state::<ShutdownPath>()
}

/// The app's port: the path is [`serve::shutdown_then_exit`]; the write on the wire is the
/// serving core's ([`serve::write_in_flight`]).
pub struct AppPort<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> AppPort<R> {
    pub fn new(app: AppHandle<R>) -> AppPort<R> {
        AppPort { app }
    }
}

impl<R: Runtime> ShutdownPort for AppPort<R> {
    fn begin(&self, reason: ShutdownReason) -> ShutdownTicket {
        serve::shutdown_then_exit(&self.app, reason)
    }

    fn write_in_flight(&self) -> bool {
        serve::write_in_flight(self.app.try_state::<ServeSlot>().as_deref())
    }
}

/// `RunEvent::ExitRequested`: true when the request must be prevented ([`exit_request`]).
pub fn on_exit_requested<R: Runtime>(app: &AppHandle<R>, code: Option<i32>) -> bool {
    exit_requested_with(&AppPort::new(app.clone()), &path_of(app), code)
}

/// `RunEvent::Exit` ([`loop_exit_with`], at most [`PATH_WAIT`]).
pub fn on_loop_exit<R: Runtime>(app: &AppHandle<R>) {
    loop_exit_with(&AppPort::new(app.clone()), &path_of(app), PATH_WAIT);
}

/// Installs this OS's hooks (from `setup`, on the main thread): Windows' end-session window,
/// the macOS delegate method, Linux's logind inhibitor and the Unix signal handlers. A hook that
/// cannot be installed is logged ([`LOG_EVENT_OS_HOOK_FAILED`]) and the app runs on.
pub fn install<R: Runtime>(app: &AppHandle<R>) {
    let _ = path_of(app);
    let port: Arc<dyn ShutdownPort> = Arc::new(AppPort::new(app.clone()));
    #[cfg(windows)]
    windows::install(port);
    #[cfg(unix)]
    {
        #[cfg(target_os = "macos")]
        install_macos(app, port.clone());
        #[cfg(target_os = "linux")]
        linux::install(port.clone());
        spawn_signal_hooks(port);
    }
}

/// macOS: the delegate method, whose reply runs at the end of the path on the main thread.
#[cfg(target_os = "macos")]
fn install_macos<R: Runtime>(app: &AppHandle<R>, port: Arc<dyn ShutdownPort>) {
    let handle = app.clone();
    let defer_reply = move || -> bool {
        let main = handle.clone();
        let path = path_of(&handle);
        let deferred = path.before_exit(Box::new(move || {
            if main.run_on_main_thread(macos::reply_terminate).is_err() {
                tracing::warn!(
                    event = LOG_EVENT_OS_HOOK_FAILED,
                    reason = "macos_reply",
                    error_class = "main_thread"
                );
            }
        }));
        if deferred {
            path.set_os_ends_process();
        }
        deferred
    };
    if let Err(step) = macos::install(port, Box::new(defer_reply)) {
        tracing::warn!(
            event = LOG_EVENT_OS_HOOK_FAILED,
            reason = "macos_delegate",
            error_class = step
        );
    }
}

/// Unix: `SIGTERM` and `SIGINT` run the path ([`on_signal`]). Once a handler is registered the
/// signal no longer ends the process by itself.
#[cfg(unix)]
fn spawn_signal_hooks(port: Arc<dyn ShutdownPort>) {
    use tokio::signal::unix::{SignalKind, signal};
    for (kind, name) in [
        (SignalKind::terminate(), "sigterm"),
        (SignalKind::interrupt(), "sigint"),
    ] {
        let port = port.clone();
        tauri::async_runtime::spawn(async move {
            let Ok(mut signals) = signal(kind) else {
                tracing::warn!(
                    event = LOG_EVENT_OS_HOOK_FAILED,
                    reason = name,
                    error_class = "signal"
                );
                return;
            };
            while signals.recv().await.is_some() {
                tracing::info!(event = LOG_EVENT_OS_END_SESSION, reason = name);
                on_signal(&*port);
            }
        });
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! A [`ShutdownPort`] whose path ends when the test says so.

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use atlas_duck_core::ShutdownReason;

    use super::{ShutdownPath, ShutdownPort, ShutdownTicket};

    /// The path's begins are recorded; the path itself does nothing until [`FakePort::finish`]
    /// (or, with `instant`, ends inside `begin`).
    #[derive(Default)]
    pub struct FakePort {
        pub path: ShutdownPath,
        pub begins: Mutex<Vec<ShutdownReason>>,
        pub starts: Mutex<u32>,
        pub write: AtomicBool,
        pub instant: AtomicBool,
    }

    impl FakePort {
        pub fn new() -> Arc<FakePort> {
            Arc::new(FakePort::default())
        }

        /// The path ended (the store is shut down): what the app's path task does at its end.
        pub fn finish(&self) {
            self.write.store(false, Ordering::SeqCst);
            self.path.end();
        }

        pub fn begins(&self) -> Vec<ShutdownReason> {
            self.begins.lock().map(|b| b.clone()).unwrap_or_default()
        }

        pub fn starts(&self) -> u32 {
            self.starts.lock().map(|s| *s).unwrap_or_default()
        }
    }

    impl ShutdownPort for FakePort {
        fn begin(&self, reason: ShutdownReason) -> ShutdownTicket {
            if let Ok(mut b) = self.begins.lock() {
                b.push(reason);
            }
            let ticket = self.path.begin(reason, |_| {
                if let Ok(mut s) = self.starts.lock() {
                    *s += 1;
                }
            });
            if self.instant.load(Ordering::SeqCst) {
                self.finish();
            }
            ticket
        }

        fn write_in_flight(&self) -> bool {
            self.write.load(Ordering::SeqCst)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use atlas_duck_core::ShutdownReason;

    use super::fake::FakePort;
    use super::*;

    #[test]
    fn path_wait_is_the_pd38_budget() {
        // PD-38: quit <= 75 s outer + 2 s (server) + the store's shutdown (10 s); one more second.
        assert_eq!(PATH_WAIT, Duration::from_secs(75 + 2 + 10 + 1));
        assert!(EXIT_GRACE < Duration::from_secs(5));
    }

    #[test]
    fn a_ticket_ends_once_and_wakes_its_waiters() {
        let ticket = ShutdownTicket::new(ShutdownReason::OsShutdown);
        assert_eq!(ticket.reason(), ShutdownReason::OsShutdown);
        assert!(!ticket.is_done());
        assert!(!ticket.wait_timeout(Duration::from_millis(20)));
        let waiter = {
            let t = ticket.clone();
            std::thread::spawn(move || t.wait_timeout(Duration::from_secs(10)))
        };
        std::thread::sleep(Duration::from_millis(50));
        ticket.complete();
        assert_eq!(waiter.join().ok(), Some(true));
        assert!(ticket.is_done());
        assert!(ticket.wait_timeout(Duration::ZERO));
    }

    /// `second_signal_does_not_restart_path`: a second source (a second signal, a Quit after
    /// the OS hook, a concurrent call) joins the first run: one start, one ticket, the first's
    /// reason.
    #[test]
    fn second_signal_does_not_restart_path() {
        let port = FakePort::new();
        let first = on_signal(&*port);
        let second = on_signal(&*port);
        let quit = port.begin(ShutdownReason::Quit);
        assert_eq!(port.starts(), 1, "one start");
        assert_eq!(
            port.begins(),
            [
                ShutdownReason::OsShutdown,
                ShutdownReason::OsShutdown,
                ShutdownReason::Quit
            ]
        );
        assert_eq!(
            quit.reason(),
            ShutdownReason::OsShutdown,
            "the first reason stays"
        );
        assert!(Arc::ptr_eq(&first.0, &second.0) && Arc::ptr_eq(&first.0, &quit.0));
        port.finish();
        assert!(first.is_done() && second.is_done() && quit.is_done());
        // After the end too.
        let late = on_signal(&*port);
        assert_eq!(port.starts(), 1);
        assert!(late.is_done());

        // Concurrent first calls: still one start.
        let port = FakePort::new();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let port = port.clone();
                std::thread::spawn(move || on_signal(&*port))
            })
            .collect();
        for t in threads {
            let _ = t.join();
        }
        assert_eq!(port.starts(), 1);
    }

    #[test]
    fn before_exit_actions_run_after_the_ticket_ended_and_not_after_the_end() {
        let path = ShutdownPath::default();
        let ticket = path.begin(ShutdownReason::Quit, |_| {});
        let seen: Arc<Mutex<Vec<bool>>> = Arc::default();
        for _ in 0..2 {
            let (seen, ticket) = (seen.clone(), ticket.clone());
            assert!(path.before_exit(Box::new(move || {
                if let Ok(mut s) = seen.lock() {
                    s.push(ticket.is_done());
                }
            })));
        }
        assert!(seen.lock().map(|s| s.is_empty()).unwrap_or(false));
        assert!(!path.ended());
        assert!(!path.end(), "no OS ends this process");
        assert_eq!(seen.lock().map(|s| s.clone()).ok(), Some(vec![true, true]));
        assert!(path.ended());
        // Too late: the caller acts itself.
        assert!(!path.before_exit(Box::new(|| {})));

        let path = ShutdownPath::default();
        path.begin(ShutdownReason::Quit, |_| {});
        path.set_os_ends_process();
        assert!(path.end());
    }

    /// `cmd_q_runs_shutdown_path` (L83): the run-loop mapping. An exit request that does not
    /// follow the last window's destruction (a platform quit, an exit code nobody on the path
    /// asked for) is prevented and runs the path with `Quit`; the last window closing keeps the
    /// tray app running; once the path ended its own exit goes ahead. Cmd+Q itself arrives at the
    /// macOS delegate method (`macos::tests`).
    #[test]
    fn cmd_q_runs_shutdown_path() {
        use ExitRequest::*;
        assert_eq!(exit_request(None, false, false), RunPath);
        assert_eq!(exit_request(None, true, false), Prevent);
        assert_eq!(exit_request(Some(0), false, false), RunPath);
        assert_eq!(exit_request(Some(0), true, false), RunPath);
        assert_eq!(exit_request(Some(1), false, false), RunPath);
        for (code, closed) in [
            (None, false),
            (None, true),
            (Some(0), false),
            (Some(1), true),
        ] {
            assert_eq!(exit_request(code, closed, true), Honour);
        }

        // Through a port: a code-less request with no window destroyed before it.
        let port = FakePort::new();
        assert!(exit_requested_with(&*port, &port.path, None));
        assert_eq!(port.begins(), [ShutdownReason::Quit]);
        // The last window closing: prevented, no path.
        let port = FakePort::new();
        port.path.note_window_destroyed();
        assert!(exit_requested_with(&*port, &port.path, None));
        assert!(port.begins().is_empty());
        // The note counts for the request right after it only.
        assert!(exit_requested_with(&*port, &port.path, None));
        assert_eq!(port.begins(), [ShutdownReason::Quit]);
        // A note older than one loop iteration does not count.
        let port = FakePort::new();
        port.path.note_window_destroyed();
        port.path.note_loop_iteration();
        assert!(exit_requested_with(&*port, &port.path, None));
        assert_eq!(port.begins(), [ShutdownReason::Quit]);
        // The path's own `exit(0)` after its end.
        port.finish();
        assert!(!exit_requested_with(&*port, &port.path, Some(0)));
        assert_eq!(port.begins(), [ShutdownReason::Quit], "no second begin");
    }

    /// The run loop ending without the path (tao's `WM_ENDSESSION`, AppKit's `terminate:`): the
    /// path runs with `OsShutdown` and the loop waits for it; after the path nothing happens.
    #[test]
    fn a_loop_ending_without_the_path_runs_it_first() {
        let port = FakePort::new();
        let finisher = {
            let port = port.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                port.finish();
            })
        };
        let began = Instant::now();
        assert!(loop_exit_with(&*port, &port.path, Duration::from_secs(10)));
        assert!(
            began.elapsed() >= Duration::from_millis(100),
            "waited for the path"
        );
        assert!(port.path.ended());
        assert_eq!(port.begins(), [ShutdownReason::OsShutdown]);
        let _ = finisher.join();
        // After the path: its own exit.
        assert!(!loop_exit_with(&*port, &port.path, Duration::from_secs(10)));
        assert_eq!(port.begins().len(), 1);
        // A path that outlives the wait: the loop ends anyway.
        let port = FakePort::new();
        port.write.store(true, Ordering::SeqCst);
        assert!(loop_exit_with(
            &*port,
            &port.path,
            Duration::from_millis(30)
        ));
        assert!(!port.path.ended());
    }
}
