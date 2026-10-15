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
    /// Opens it again, without taking the focus from whatever the user is typing in.
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
/// runs on the blocking pool (it asks the main thread about windows), coalesced: increments that
/// arrive while a run is queued ride on it, and the tray reads the count itself.
pub struct RaiseSink {
    gate: Arc<RaiseGate>,
    queued: Arc<AtomicBool>,
}

impl RaiseSink {
    pub fn new(gate: Arc<RaiseGate>) -> RaiseSink {
        RaiseSink {
            gate,
            queued: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl UiSink for RaiseSink {
    fn emit(&self, e: UiEvent) {
        if !matches!(e, UiEvent::CredentialContextChanged)
            || self.queued.swap(true, Ordering::SeqCst)
        {
            return;
        }
        let (gate, queued) = (self.gate.clone(), self.queued.clone());
        tauri::async_runtime::spawn_blocking(move || {
            // Cleared first: an increment during the run queues the next one.
            queued.store(false, Ordering::SeqCst);
            gate.refused_changed();
        });
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
        if matches!(action, Relaunch::OpenCredential(_) | Relaunch::OpenSetup) {
            windows::perform_with(&self.app, action, Show::WithoutActivating);
        }
    }

    fn refresh_tray(&self) {
        // The rebuild reads the refused count itself when it runs.
        crate::tray::refresh(&self.app);
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
            self.tray.fetch_add(1, Ordering::SeqCst);
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
        while env.tray() == 0 {
            assert!(started.elapsed() < Duration::from_secs(10), "never ran");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(env.raises(), 1);
    }
}
