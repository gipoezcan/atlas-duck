//! Raise coalescing of the locked and first-run windows (§2.5, §13 UI-04; M6 T22). While the app
//! serves a gate, every refused request (`GateHandler::refuse`) emits `credential_context_changed`.
//! The count shown in the tray and in the window's header follows every one of them, but the
//! window itself is raised again at most once per 5 minutes and never while it is open: an agent
//! that retries in a loop must not keep a secret-entry window jumping in front of the user.
//!
//! [`RaiseGate`] is pure over [`RaiseEnv`] and a `Clock` (a fake in the tests); [`RaiseSink`] feeds
//! it from the UI sink without ever blocking the IPC task that refused the request;
//! [`TauriRaiseEnv`] is the Tauri side.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use atlas_duck_audit::Clock;
use atlas_duck_core::{UiEvent, UiSink};
use tauri::{AppHandle, Manager, Wry};

use crate::windows::{self, Label, Relaunch, Show};

/// §2.5: the window is raised again at most once per 5 minutes.
pub const RAISE_MIN_GAP: Duration = Duration::from_secs(5 * 60);

/// What the gate asks of the app. Called on a worker thread, never on the IPC task.
pub trait RaiseEnv: Send + Sync {
    /// The window the state needs (credential, setup) is open: shown, not hidden.
    fn window_open(&self) -> bool;
    /// Brings the window the state needs to the user's notice again, without taking the focus from
    /// whatever the user is typing in: a window that does not exist is built unfocused; one that
    /// exists but is hidden is never shown again (on Windows `show()` activates it), the taskbar
    /// entry flashes instead ([`raise_window`]).
    fn raise(&self);
    /// The tray shows the refused count now.
    fn refresh_tray(&self);
}

/// When a refused request raises the window again.
pub struct RaiseGate {
    env: Arc<dyn RaiseEnv>,
    clock: Arc<dyn Clock>,
    last_raise: Mutex<Option<Duration>>,
}

impl RaiseGate {
    pub fn new(env: Arc<dyn RaiseEnv>, clock: Arc<dyn Clock>) -> RaiseGate {
        RaiseGate {
            env,
            clock,
            last_raise: Mutex::new(None),
        }
    }

    /// The window was raised now (the cold start's open at startup, §2.5): the 5 minutes run from
    /// here.
    pub fn raised(&self) {
        *self
            .last_raise
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(self.clock.suspend_aware_elapsed());
    }

    /// The refused count of the gate changed (one more request refused): the tray follows every
    /// increment; the window is raised only when it is closed and the last raise is 5 minutes
    /// back.
    pub fn refused_changed(&self) {
        self.env.refresh_tray();
        if self.due(self.env.window_open()) {
            self.env.raise();
        }
    }

    /// Whether to raise now; records the raise when so.
    fn due(&self, window_open: bool) -> bool {
        if window_open {
            return false;
        }
        let now = self.clock.suspend_aware_elapsed();
        let mut last = self
            .last_raise
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|t| now.saturating_sub(t) < RAISE_MIN_GAP) {
            return false;
        }
        *last = Some(now);
        true
    }
}

/// The gate's side of the UI sink: `credential_context_changed` is a refused request. The work
/// runs on one worker of the blocking pool (it asks the main thread about windows), never blocking
/// the emitter. `dirty` says an increment is not served yet and `running` that the worker lives:
/// the worker serves every increment that arrives while it runs with one more run (the tray reads
/// the latest count itself), so rebuilds are serialized and the last one starts after the last
/// increment; however many refusals arrive, at most one worker exists.
pub struct RaiseSink {
    shared: Arc<SinkShared>,
}

struct SinkShared {
    gate: Arc<RaiseGate>,
    dirty: AtomicBool,
    running: AtomicBool,
}

impl SinkShared {
    /// The worker: runs while increments keep arriving. It clears `running` before its last look at
    /// `dirty`, so an increment that lands in between either sees `running` cleared and starts the
    /// next worker, or is seen here.
    fn work(&self) {
        loop {
            while self.dirty.swap(false, Ordering::SeqCst) {
                self.gate.refused_changed();
            }
            self.running.store(false, Ordering::SeqCst);
            if !self.dirty.load(Ordering::SeqCst) || self.running.swap(true, Ordering::SeqCst) {
                return;
            }
        }
    }
}

impl RaiseSink {
    pub fn new(gate: Arc<RaiseGate>) -> RaiseSink {
        RaiseSink {
            shared: Arc::new(SinkShared {
                gate,
                dirty: AtomicBool::new(false),
                running: AtomicBool::new(false),
            }),
        }
    }
}

impl UiSink for RaiseSink {
    fn emit(&self, e: UiEvent) {
        if !matches!(e, UiEvent::CredentialContextChanged) {
            return;
        }
        self.shared.dirty.store(true, Ordering::SeqCst);
        if self.shared.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let shared = self.shared.clone();
        tauri::async_runtime::spawn_blocking(move || shared.work());
    }
}

/// The gate of this app, managed by `serve::start`: the cold start tells it about its raise.
pub struct RaiseHandle(pub Arc<RaiseGate>);

/// The cold start raised the window (`windows::startup_completed`).
pub fn note_startup_raise<R: tauri::Runtime>(app: &AppHandle<R>) {
    if let Some(h) = app.try_state::<RaiseHandle>() {
        h.0.raised();
    }
}

/// The re-raise of `action`'s window (`OpenCredential`, `OpenSetup`; anything else does nothing)
/// that never takes the focus (§2.5, UI-04, PD-75). A window that is built already is hidden (an
/// open one is never raised): showing it would activate it on Windows, and an agent decides when a
/// refused request lands, so it must not move a wizard in front of what the user is typing in.
/// That one only gets the taskbar flash / dock bounce, and the tray count tells the rest. A
/// window that is gone (the credential window is destroyed on close) is built again unfocused.
pub fn raise_window<R: tauri::Runtime>(app: &AppHandle<R>, action: Relaunch) {
    raise_window_with(app, action, |action| {
        windows::perform_with(app, action, Show::WithoutActivating);
    });
}

/// [`raise_window`], with `build` what builds a window that is gone (the tests count its calls: an
/// existing window must never reach it, since showing it is what activates it).
pub fn raise_window_with<R: tauri::Runtime>(
    app: &AppHandle<R>,
    action: Relaunch,
    build: impl FnOnce(Relaunch),
) {
    let label = match action {
        Relaunch::OpenCredential(_) => Label::Credential,
        Relaunch::OpenSetup => Label::Setup,
        _ => return,
    };
    if let Some(w) = app.get_webview_window(label.as_str()) {
        let _ = w.request_user_attention(Some(tauri::UserAttentionType::Informational));
        return;
    }
    build(action);
}

/// The Tauri half of [`RaiseEnv`].
pub struct TauriRaiseEnv {
    app: AppHandle<Wry>,
}

impl TauriRaiseEnv {
    pub fn new(app: AppHandle<Wry>) -> TauriRaiseEnv {
        TauriRaiseEnv { app }
    }
}

impl RaiseEnv for TauriRaiseEnv {
    fn window_open(&self) -> bool {
        [Label::Credential, Label::Setup].into_iter().any(|l| {
            self.app
                .get_webview_window(l.as_str())
                .is_some_and(|w| w.is_visible().unwrap_or(false))
        })
    }

    fn raise(&self) {
        // The window the state needs, as a relaunch would open it (`OpenCredential` for the lock
        // states, `OpenSetup` for first run); any other state needs none.
        let action = windows::route_cold_start(&windows::snapshot(&self.app), true);
        raise_window(&self.app, action);
    }

    fn refresh_tray(&self) {
        // The rebuild reads the refused count itself when it runs.
        crate::tray::refresh(&self.app);
        // The wizard's header shows the same count ("Setup required — N requests refused", §2.5).
        crate::wizard::serving_changed(&self.app);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;

    use atlas_duck_audit::clock::UtcInstant;
    use atlas_duck_audit::testing::FakeClock;

    use super::*;

    /// Counts what the gate asks for; a raise opens the window unless the test says it did not
    /// (the user closed it again).
    #[derive(Default)]
    struct Env {
        open: AtomicBool,
        raises: AtomicU32,
        tray: AtomicU32,
        raise_opens: AtomicBool,
        /// How long a tray rebuild takes (a main-thread round trip).
        tray_ms: AtomicU32,
        in_flight: AtomicU32,
        max_in_flight: AtomicU32,
        /// How many refused requests the test has emitted so far, and how many a rebuild saw when
        /// it started (the tray reads the count when it runs).
        emitted: AtomicU32,
        last_seen: AtomicU32,
    }

    impl RaiseEnv for Env {
        fn window_open(&self) -> bool {
            self.open.load(Ordering::SeqCst)
        }
        fn raise(&self) {
            self.raises.fetch_add(1, Ordering::SeqCst);
            self.open
                .store(self.raise_opens.load(Ordering::SeqCst), Ordering::SeqCst);
        }
        fn refresh_tray(&self) {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            self.last_seen
                .store(self.emitted.load(Ordering::SeqCst), Ordering::SeqCst);
            self.tray.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(u64::from(
                self.tray_ms.load(Ordering::SeqCst),
            )));
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl Env {
        fn raises(&self) -> u32 {
            self.raises.load(Ordering::SeqCst)
        }
        fn tray(&self) -> u32 {
            self.tray.load(Ordering::SeqCst)
        }
    }

    fn rig(raise_opens: bool) -> (Arc<Env>, Arc<FakeClock>, RaiseGate) {
        let env = Arc::new(Env::default());
        env.raise_opens.store(raise_opens, Ordering::SeqCst);
        let clock = Arc::new(FakeClock::new(UtcInstant(0)));
        let gate = RaiseGate::new(env.clone(), clock.clone());
        (env, clock, gate)
    }

    /// UI-04: six refused requests in a row raise the window once (it was raised at startup by
    /// the cold start's open, then the user closed it).
    #[test]
    fn ui04_six_locked_requests_raise_once() {
        let (env, clock, gate) = rig(false);
        gate.raised();
        for _ in 0..6 {
            clock.advance(Duration::from_secs(1));
            gate.refused_changed();
        }
        assert_eq!(env.raises(), 0, "inside the 5 minutes of the startup raise");

        // With no startup raise the first refused request raises, the other five do not, even
        // though the user closes the window each time.
        let (env, clock, gate) = rig(false);
        for _ in 0..6 {
            clock.advance(Duration::from_secs(1));
            gate.refused_changed();
        }
        assert_eq!(env.raises(), 1);
    }

    /// UI-04: never while the window is open, however long ago the last raise was.
    #[test]
    fn ui04_no_raise_while_open() {
        let (env, clock, gate) = rig(true);
        env.open.store(true, Ordering::SeqCst);
        for _ in 0..6 {
            clock.advance(Duration::from_secs(3600));
            gate.refused_changed();
        }
        assert_eq!(env.raises(), 0);
        assert_eq!(env.tray(), 6, "the count still follows");
        // The user closes it: the next request raises (nothing raised before).
        env.open.store(false, Ordering::SeqCst);
        gate.refused_changed();
        assert_eq!(env.raises(), 1);
    }

    /// UI-04: the tray follows every increment, whether or not the window was raised.
    #[test]
    fn ui04_tray_count_six() {
        let (env, _clock, gate) = rig(true);
        for _ in 0..6 {
            gate.refused_changed();
        }
        assert_eq!(env.tray(), 6);
        assert_eq!(env.raises(), 1);
    }

    #[test]
    fn raise_again_after_5_minutes() {
        let (env, clock, gate) = rig(false);
        gate.refused_changed();
        assert_eq!(env.raises(), 1);
        clock.advance(RAISE_MIN_GAP - Duration::from_secs(1));
        gate.refused_changed();
        assert_eq!(env.raises(), 1, "299 s: not yet");
        clock.advance(Duration::from_secs(1));
        gate.refused_changed();
        assert_eq!(env.raises(), 2, "300 s");
        // The next 5 minutes run from that raise, not from the first.
        clock.advance(Duration::from_secs(299));
        gate.refused_changed();
        assert_eq!(env.raises(), 2);
        clock.advance(Duration::from_secs(1));
        gate.refused_changed();
        assert_eq!(env.raises(), 3);
        assert_eq!(RAISE_MIN_GAP, Duration::from_secs(300));
    }

    /// The sink reacts to `credential_context_changed` only, and coalesces what arrives while a
    /// run is queued.
    #[test]
    fn the_sink_follows_only_refused_requests() {
        let (env, _clock, gate) = rig(true);
        let sink = RaiseSink::new(Arc::new(gate));
        sink.emit(UiEvent::RunningScriptsChanged);
        sink.emit(UiEvent::NeedsAttentionChanged { count: 1 });
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(env.tray(), 0);
        sink.emit(UiEvent::CredentialContextChanged);
        let started = std::time::Instant::now();
        // The raise follows the tray rebuild on the worker: wait for the last step.
        while env.raises() == 0 {
            assert!(started.elapsed() < Duration::from_secs(10), "never ran");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(env.tray(), 1);
    }

    /// UI-04 / I-2: a flood of refused requests against a slow tray rebuild runs one worker: the
    /// rebuilds never overlap, far fewer run than requests came, and the last one starts after
    /// the last request (the tray never ends on a count below the real one).
    #[test]
    fn a_flood_of_refusals_is_coalesced_serialized_and_ends_current() {
        const FLOOD: u32 = 1000;
        let (env, _clock, gate) = rig(true);
        env.tray_ms.store(20, Ordering::SeqCst);
        let sink = RaiseSink::new(Arc::new(gate));
        let began = std::time::Instant::now();
        for _ in 0..FLOOD {
            env.emitted.fetch_add(1, Ordering::SeqCst);
            sink.emit(UiEvent::CredentialContextChanged);
        }
        assert!(
            began.elapsed() < Duration::from_millis(500),
            "emitting never waits for a rebuild"
        );
        while env.last_seen.load(Ordering::SeqCst) != FLOOD {
            assert!(began.elapsed() < Duration::from_secs(20), "never caught up");
            std::thread::sleep(Duration::from_millis(5));
        }
        // Let a (wrongly) concurrent or queued run show itself.
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(env.in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(
            env.max_in_flight.load(Ordering::SeqCst),
            1,
            "rebuilds are serialized"
        );
        assert!(
            env.tray() < FLOOD / 10,
            "{} rebuilds for {FLOOD} requests",
            env.tray()
        );
        // The worker is gone: the next request starts a new one.
        let before = env.tray();
        env.emitted.fetch_add(1, Ordering::SeqCst);
        sink.emit(UiEvent::CredentialContextChanged);
        let started = std::time::Instant::now();
        while env.tray() == before {
            assert!(started.elapsed() < Duration::from_secs(10), "never ran");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(env.last_seen.load(Ordering::SeqCst), FLOOD + 1);
    }
}
