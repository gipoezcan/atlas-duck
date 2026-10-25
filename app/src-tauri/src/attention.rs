//! The attention engine (§5.6, §2.5, §10.3; M6 T19, PD-75): how a new pending request asks for the
//! user's attention. It follows the core's `UiEvent`s and owns the attention mode (the persisted
//! `[ui] attention_mode` is only the default; "Presentation mode" is in-memory session state on
//! top of it), the raise rules, the coalesced toast and the tray count. Everything it shows is
//! app-generated: toast text carries counts only, never a string an agent supplied (§5.6).
//!
//! [`AttentionEngine`] is pure: it talks to the OS through [`Notifier`] and to time through
//! `Clock::suspend_aware_elapsed` (a fake in the tests). [`TauriNotifier`] is the Tauri side;
//! [`spawn_worker`] runs the engine on its own thread so the core's `UiSink::emit` never waits on
//! `queue_list()`, a window call or the keychain-backed settings read.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use atlas_duck_audit::Clock;
use atlas_duck_core::{
    AttentionKind, AttentionMode, Core, QueueItem, SettingsAdmin, SettingsError, UiEvent, UiSink,
};
use serde_json::{Value, json};
use tauri::{AppHandle, Manager, Runtime, UserAttentionType, Wry};
use tauri_plugin_notification::NotificationExt;

use crate::tray_host::TrayHost;
use crate::windows::{self, Label, Show};

/// §5.6: the window is raised at most once per 60 s.
pub const RAISE_MIN_GAP: Duration = Duration::from_secs(60);
/// §5.6: at most one toast per 30 s.
pub const TOAST_MIN_GAP: Duration = Duration::from_secs(30);
/// The `CONFIG_CHANGED.key` of a Presentation-mode switch (`attention_mode` itself is reserved to
/// `SettingsAdmin::apply`).
pub const KEY_PRESENTATION_MODE: &str = "presentation_mode";
/// Title of the toast (app-generated).
pub const TOAST_TITLE: &str = "atlas-duck";
/// Log event when a Presentation-mode switch could not be recorded (nothing changed).
pub const LOG_EVENT_PRESENTATION_FAILED: &str = "presentation_mode_failed";
/// Log event when the engine's thread could not be started (no attention, the app keeps running).
pub const LOG_EVENT_ATTENTION_START_FAILED: &str = "attention_start_failed";

/// What the engine asks of the OS (PD-75). Called on the worker thread, never under a lock of the
/// core.
pub trait Notifier: Send + Sync {
    /// Shows the Approvals window; `focus`: also takes the focus ("show and focus").
    fn raise(&self, focus: bool);
    /// The platform's weaker signal (taskbar flash, dock bounce, urgency hint).
    fn flash(&self);
    /// One OS toast; `text` is app-generated.
    fn toast(&self, text: &str);
    /// The tray badge and tooltip show `pending` requests.
    fn set_badge(&self, pending: u32);
}

/// The pending queue by class (§5.6 "N pending: x reads, y writes, z scripts").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub reads: u32,
    pub writes: u32,
    pub scripts: u32,
}

impl Counts {
    pub fn of(items: &[QueueItem]) -> Counts {
        let n = |class: &str| {
            u32::try_from(items.iter().filter(|i| i.class == class).count()).unwrap_or(u32::MAX)
        };
        Counts {
            reads: n("read"),
            writes: n("write"),
            scripts: n("script"),
        }
    }

    pub fn pending(self) -> u32 {
        self.reads
            .saturating_add(self.writes)
            .saturating_add(self.scripts)
    }
}

/// The toast text (§5.6, counts only). `N pending: x reads, y writes, z scripts` is §5.6's
/// wording; the `; M need attention` suffix (failed or unknown write outcomes unacknowledged) is
/// PD-90 plan text (L114), not §5.6. `None` when there is nothing to say.
pub fn toast_text(counts: Counts, needs_attention: u32) -> Option<String> {
    let mut parts = Vec::with_capacity(2);
    if counts.pending() > 0 {
        parts.push(format!(
            "{} pending: {} reads, {} writes, {} scripts",
            counts.pending(),
            counts.reads,
            counts.writes,
            counts.scripts
        ));
    }
    if needs_attention > 0 {
        parts.push(format!("{needs_attention} need attention"));
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// Where a Presentation-mode switch is recorded (`CONFIG_CHANGED {source: app}`): every
/// `SettingsAdmin`, and the tests' fakes.
pub trait AppChangeLog: Send + Sync {
    fn record(&self, key: &str, old: Value, new: Value) -> Result<(), SettingsError>;
}

impl<T: SettingsAdmin + ?Sized> AppChangeLog for T {
    fn record(&self, key: &str, old: Value, new: Value) -> Result<(), SettingsError> {
        self.record_app_change(key, old, new)
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug)]
struct State {
    /// The queue was empty before the next new request (initially true; set again whenever the
    /// queue is seen empty): the 0 -> 1 transition.
    idle: bool,
    last_raise: Option<Duration>,
    last_toast: Option<Duration>,
    /// An attention event waits for a toast slot (coalescing: one toast for the lot).
    toast_wanted: bool,
    /// The unacknowledged failed / outcome-unknown writes (`NeedsAttentionChanged`).
    needs: u32,
    /// What the badge shows now.
    badge: Option<u32>,
}

pub struct AttentionEngine {
    notifier: Arc<dyn Notifier>,
    clock: Arc<dyn Clock>,
    /// `false` on Linux without a tray host (§2.5): "badge only" then has no badge to show.
    tray_present: bool,
    /// `[ui] attention_mode`, refreshed by the worker from `SettingsAdmin::view`.
    configured: Mutex<AttentionMode>,
    /// Presentation mode: in memory, this process only (§5.6; never persisted).
    presentation: AtomicBool,
    /// Serializes Presentation-mode switches so each record's `old` is the true previous value.
    switching: Mutex<()>,
    state: Mutex<State>,
}

impl AttentionEngine {
    pub fn new(
        notifier: Arc<dyn Notifier>,
        clock: Arc<dyn Clock>,
        tray_host: Option<TrayHost>,
    ) -> AttentionEngine {
        AttentionEngine {
            notifier,
            clock,
            tray_present: tray_host != Some(TrayHost::Missing),
            configured: Mutex::new(AttentionMode::default()),
            presentation: AtomicBool::new(false),
            switching: Mutex::new(()),
            state: Mutex::new(State {
                idle: true,
                last_raise: None,
                last_toast: None,
                toast_wanted: false,
                needs: 0,
                badge: None,
            }),
        }
    }

    /// The persisted mode (the default Presentation mode sits on top of).
    pub fn set_configured_mode(&self, mode: AttentionMode) {
        *lock(&self.configured) = mode;
    }

    pub fn presentation(&self) -> bool {
        self.presentation.load(Ordering::SeqCst)
    }

    /// What a new request does now: Presentation mode is "badge only"; "badge only" without a tray
    /// host has no badge, so it shows the window without activating it (§2.5).
    pub fn effective_mode(&self) -> AttentionMode {
        let mode = if self.presentation() {
            AttentionMode::BadgeOnly
        } else {
            *lock(&self.configured)
        };
        if mode == AttentionMode::BadgeOnly && !self.tray_present {
            AttentionMode::ShowWithoutActivating
        } else {
            mode
        }
    }

    /// Switches Presentation mode on or off (§5.6, §10.3): a plain `CONFIG_CHANGED`, no
    /// confirmation. The record comes first and the mode changes only once it committed (audit
    /// before effect); on `Err` nothing changed. `Ok(false)`: it was in that state already.
    /// Synchronous store write: call it from the blocking pool.
    pub fn set_presentation<L: AppChangeLog + ?Sized>(
        &self,
        on: bool,
        log: &L,
    ) -> Result<bool, SettingsError> {
        let _one_switch_at_a_time = lock(&self.switching);
        self.switch_locked(on, log)
    }

    /// Flips Presentation mode; the previous value is read under the switch lock, so two quick
    /// clicks are two flips (not two "on"s). Returns the new state.
    pub fn toggle_presentation<L: AppChangeLog + ?Sized>(
        &self,
        log: &L,
    ) -> Result<bool, SettingsError> {
        let _one_switch_at_a_time = lock(&self.switching);
        let on = !self.presentation();
        self.switch_locked(on, log)?;
        Ok(on)
    }

    fn switch_locked<L: AppChangeLog + ?Sized>(
        &self,
        on: bool,
        log: &L,
    ) -> Result<bool, SettingsError> {
        let old = self.presentation();
        if old == on {
            return Ok(false);
        }
        log.record(KEY_PRESENTATION_MODE, json!(old), json!(on))?;
        self.presentation.store(on, Ordering::SeqCst);
        Ok(true)
    }

    /// One core event, with the queue as it is now. `window_hidden`: the Approvals window is not
    /// visible (never built, hidden, minimized).
    pub fn on_event(&self, e: &UiEvent, counts: Counts, window_hidden: bool) {
        let now = self.clock.suspend_aware_elapsed();
        let mut st = lock(&self.state);
        match e {
            UiEvent::QueueChanged { .. } => {
                if counts.pending() == 0 {
                    st.idle = true;
                }
                self.show_badge(&mut st, counts.pending());
            }
            UiEvent::NeedsAttentionChanged { count } => st.needs = *count,
            UiEvent::Attention { kind, .. } => {
                self.attention(&mut st, *kind, counts, window_hidden, now);
            }
            UiEvent::StatusBanner { .. }
            | UiEvent::RunningScriptsChanged
            | UiEvent::CredentialContextChanged => {}
        }
    }

    fn show_badge(&self, st: &mut State, pending: u32) {
        if st.badge != Some(pending) {
            st.badge = Some(pending);
            self.notifier.set_badge(pending);
        }
    }

    /// One attention call per attention event (§5.6): raise per mode, then the toast slot.
    fn attention(
        &self,
        st: &mut State,
        kind: AttentionKind,
        counts: Counts,
        window_hidden: bool,
        now: Duration,
    ) {
        // The badge follows the queue even when only an attention event told us.
        self.show_badge(st, counts.pending());
        let mode = self.effective_mode();
        // §5.6: raised only on pending 0 -> 1 or while hidden, at most once per 60 s.
        let eligible = st.idle || window_hidden;
        if kind == AttentionKind::New {
            st.idle = false;
        }
        if mode != AttentionMode::BadgeOnly {
            let due = st
                .last_raise
                .is_none_or(|t| now.saturating_sub(t) >= RAISE_MIN_GAP);
            if eligible && due {
                st.last_raise = Some(now);
                self.notifier.raise(mode == AttentionMode::ShowAndFocus);
            } else if kind != AttentionKind::New {
                // A stale return or a failed write is told even when the window stays put.
                self.notifier.flash();
            }
        }
        st.toast_wanted = true;
        self.flush_toast(st, counts, now);
    }

    /// Sends the waiting toast when the 30 s since the last one passed.
    fn flush_toast(&self, st: &mut State, counts: Counts, now: Duration) {
        if !st.toast_wanted {
            return;
        }
        if st
            .last_toast
            .is_some_and(|t| now.saturating_sub(t) < TOAST_MIN_GAP)
        {
            return;
        }
        st.toast_wanted = false;
        if let Some(text) = toast_text(counts, st.needs) {
            st.last_toast = Some(now);
            self.notifier.toast(&text);
        }
    }

    /// How long until a waiting toast may go out; `None` when none waits.
    pub fn toast_due_in(&self) -> Option<Duration> {
        let st = lock(&self.state);
        if !st.toast_wanted {
            return None;
        }
        let now = self.clock.suspend_aware_elapsed();
        Some(st.last_toast.map_or(Duration::ZERO, |t| {
            TOAST_MIN_GAP.saturating_sub(now.saturating_sub(t))
        }))
    }

    /// The coalesced toast of what arrived while the 30 s limit held it back.
    pub fn tick(&self, counts: Counts) {
        let now = self.clock.suspend_aware_elapsed();
        let mut st = lock(&self.state);
        self.flush_toast(&mut st, counts, now);
    }
}

// ---------- the engine on its own thread ----------

/// What the worker reads from the app (a fake in the tests).
pub trait AttentionEnv: Send + Sync {
    /// The pending queue by class; `None` while no core serves.
    fn counts(&self) -> Option<Counts>;
    /// The Approvals window is not visible.
    fn window_hidden(&self) -> bool;
    /// `[ui] attention_mode` as `SettingsAdmin::view` shows it; `None` while no core serves.
    fn configured_mode(&self) -> Option<AttentionMode>;
}

/// The queue by class, from the serving core.
pub fn core_counts(core: &Core) -> Counts {
    Counts::of(&core.decisions().queue_list())
}

/// How many `Attention` events wait for the worker at most; the oldest is dropped beyond that
/// (each only asks for one raise/toast, and those are rate-limited anyway).
pub const INBOX_ATTENTION_CAP: usize = 32;

/// The worker's queue: bounded by coalescing, and `push` never blocks (the core's `emit` must not
/// wait on a stalled worker). Only the latest `QueueChanged` and `NeedsAttentionChanged` matter (the
/// worker reads the queue itself), so a newer one replaces a waiting one; waiting `Attention`
/// events are capped at [`INBOX_ATTENTION_CAP`], dropping the oldest.
#[derive(Default)]
struct Inbox {
    state: Mutex<InboxState>,
    wake: Condvar,
}

#[derive(Default)]
struct InboxState {
    events: VecDeque<UiEvent>,
    closed: bool,
}

impl Inbox {
    fn push(&self, e: UiEvent) {
        let mut st = lock(&self.state);
        match &e {
            UiEvent::QueueChanged { .. } => st
                .events
                .retain(|w| !matches!(w, UiEvent::QueueChanged { .. })),
            UiEvent::NeedsAttentionChanged { .. } => st
                .events
                .retain(|w| !matches!(w, UiEvent::NeedsAttentionChanged { .. })),
            _ => {
                let waiting = |w: &&UiEvent| matches!(w, UiEvent::Attention { .. });
                if st.events.iter().filter(waiting).count() >= INBOX_ATTENTION_CAP
                    && let Some(oldest) = st
                        .events
                        .iter()
                        .position(|w| matches!(w, UiEvent::Attention { .. }))
                {
                    st.events.remove(oldest);
                }
            }
        }
        st.events.push_back(e);
        self.wake.notify_one();
    }

    fn close(&self) {
        lock(&self.state).closed = true;
        self.wake.notify_all();
    }

    /// The next event; waits at most `wait` (`None`: without limit). `Disconnected` once the feed
    /// is gone and the queue drained.
    fn recv(&self, wait: Option<Duration>) -> Result<UiEvent, RecvTimeoutError> {
        let deadline = wait.map(|w| std::time::Instant::now() + w);
        let mut st = lock(&self.state);
        loop {
            if let Some(e) = st.events.pop_front() {
                return Ok(e);
            }
            if st.closed {
                return Err(RecvTimeoutError::Disconnected);
            }
            st = match deadline {
                None => self.wake.wait(st).unwrap_or_else(PoisonError::into_inner),
                Some(d) => {
                    let left = d.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() {
                        return Err(RecvTimeoutError::Timeout);
                    }
                    self.wake
                        .wait_timeout(st, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
            };
        }
    }
}

/// The first half of the §5.6 sink: queues the events the engine follows for the worker.
pub struct AttentionFeed {
    inbox: Arc<Inbox>,
}

impl Drop for AttentionFeed {
    fn drop(&mut self) {
        self.inbox.close();
    }
}

impl UiSink for AttentionFeed {
    fn emit(&self, e: UiEvent) {
        let wanted = matches!(
            e,
            UiEvent::QueueChanged { .. }
                | UiEvent::Attention { .. }
                | UiEvent::NeedsAttentionChanged { .. }
        );
        if wanted {
            self.inbox.push(e);
        }
    }
}

/// Starts the engine's thread; the returned feed goes to `TauriUiSink::with_attention`. The thread
/// ends when the feed (and with it the sender) is dropped.
pub fn spawn_worker(
    engine: Arc<AttentionEngine>,
    env: Arc<dyn AttentionEnv>,
) -> std::io::Result<AttentionFeed> {
    let inbox = Arc::new(Inbox::default());
    let rx = inbox.clone();
    std::thread::Builder::new()
        .name("atlas-duck-attention".into())
        .spawn(move || {
            loop {
                let next = rx.recv(engine.toast_due_in());
                match next {
                    Ok(event) => handle(&engine, &*env, &event),
                    Err(RecvTimeoutError::Timeout) => {
                        if let Some(counts) = env.counts() {
                            engine.tick(counts);
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        })?;
    Ok(AttentionFeed { inbox })
}

/// One event through the engine, with the app's state as it is now.
fn handle(engine: &AttentionEngine, env: &dyn AttentionEnv, event: &UiEvent) {
    let Some(counts) = env.counts() else {
        return;
    };
    if matches!(event, UiEvent::Attention { .. })
        && let Some(mode) = env.configured_mode()
    {
        engine.set_configured_mode(mode);
    }
    engine.on_event(event, counts, env.window_hidden());
}

// ---------- Taskbar overlay (PD-173) ----------

/// The Windows taskbar overlay image for a pending count: the digit 1-9, or "9+" from ten up. Zero
/// has none (the overlay is cleared). App-generated, count only (§5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayIcon {
    Digit(u8),
    NinePlus,
}

/// The overlay image for `pending`; `None` clears it.
pub fn overlay_for(pending: u32) -> Option<OverlayIcon> {
    match pending {
        0 => None,
        1..=9 => u8::try_from(pending).ok().map(OverlayIcon::Digit),
        _ => Some(OverlayIcon::NinePlus),
    }
}

/// Where the overlay goes: the Approvals window's taskbar button on Windows, nowhere on the other
/// platforms (macOS: the tray title, `tray::tray_title`; Linux: the tray menu and tooltip).
pub trait OverlaySink {
    fn set_overlay(&self, icon: Option<OverlayIcon>);
}

/// Drives the overlay for the pending count: the image for 1 or more, cleared at 0.
pub fn drive_overlay(sink: &dyn OverlaySink, pending: u32) {
    sink.set_overlay(overlay_for(pending));
}

/// The Approvals window was just built: the overlay is on its taskbar button only while the window
/// exists (PD-173), so a window created after the count was set (tray menu, relaunch, startup, a
/// raise) gets the current `pending` here. Other windows have no overlay.
pub fn overlay_for_new_window(sink: &dyn OverlaySink, label: Label, pending: u32) {
    if label == Label::Approvals {
        drive_overlay(sink, pending);
    }
}

/// The overlay of a window `windows::open` just built, with the count of [`AppState`]. A stale
/// read is harmless: the next `set_badge` (every queue change) drives the overlay again, and the
/// worker that calls it is the only writer of the count.
///
/// [`AppState`]: crate::state::AppState
pub fn apply_overlay_to_new_window<R: Runtime>(app: &AppHandle<R>, label: Label) {
    let pending = app
        .try_state::<crate::state::AppState>()
        .map_or(0, |s| s.pending());
    overlay_for_new_window(&AppOverlay(app), label, pending);
}

/// §5.6: a default-mode raise shows the window without activating it; only where `show()` may not
/// activate-or-surface it (Windows) does it also flash the taskbar button. macOS and Linux no longer
/// flash on that raise (M6 final review M-6, L217).
pub fn flash_after_default_raise(os: &str) -> bool {
    os == "windows"
}

/// The largest width or height `decode_overlay` accepts.
#[cfg(any(windows, test))]
const MAX_OVERLAY_SIDE: u32 = 256;

/// Decodes one committed overlay PNG (`icons/overlay-*.png`) into `(width, height, RGBA)`. The
/// generator (`ci/gen-overlay-icons.mjs`) writes 8-bit RGBA, no interlace, filter none and a stored
/// (level 0) deflate stream, and that is all this reads: `tauri::image::Image::from_bytes` would
/// need tauri's `image-png` feature and with it the `image` crate, which the workspace does not link.
#[cfg(any(windows, test))]
pub fn decode_overlay(png: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let be32 = |b: &[u8]| -> Option<u32> { Some(u32::from_be_bytes(b.get(..4)?.try_into().ok()?)) };
    let mut rest = png.strip_prefix(&SIGNATURE)?;
    let mut header: Option<(u32, u32)> = None;
    let mut idat = Vec::new();
    loop {
        let len = usize::try_from(be32(rest)?).ok()?;
        let kind = rest.get(4..8)?;
        let data = rest.get(8..8usize.checked_add(len)?)?;
        // The 4 CRC bytes after the data are not checked: the file is ours, compiled in.
        rest = rest.get(8usize.checked_add(len)?.checked_add(4)?..)?;
        match kind {
            b"IHDR" => {
                // 8 bit, RGBA, deflate, adaptive filtering, no interlace.
                if data.get(8..13)? != [8, 6, 0, 0, 0] {
                    return None;
                }
                header = Some((be32(data)?, be32(data.get(4..)?)?));
            }
            b"IDAT" => idat.extend_from_slice(data),
            b"IEND" => break,
            _ => {}
        }
    }
    let (width, height) = header?;
    // Before any buffer is sized from the header: the overlays are 16x16.
    if width > MAX_OVERLAY_SIDE || height > MAX_OVERLAY_SIDE {
        return None;
    }
    let row = usize::try_from(width).ok()?.checked_mul(4)?;
    let want = row
        .checked_add(1)?
        .checked_mul(usize::try_from(height).ok()?)?;
    // zlib: two header bytes, then stored blocks only (BTYPE 00), the Adler-32 trailer ignored.
    let mut stream = idat.get(2..)?;
    let mut raw = Vec::with_capacity(want);
    loop {
        let flags = *stream.first()?;
        if flags & 0b110 != 0 {
            return None;
        }
        let len = usize::from(u16::from_le_bytes(stream.get(1..3)?.try_into().ok()?));
        let nlen = u16::from_le_bytes(stream.get(3..5)?.try_into().ok()?);
        if nlen != !u16::try_from(len).ok()? {
            return None;
        }
        raw.extend_from_slice(stream.get(5..5usize.checked_add(len)?)?);
        stream = stream.get(5usize.checked_add(len)?..)?;
        if flags & 1 == 1 {
            break;
        }
    }
    if raw.len() != want {
        return None;
    }
    let mut rgba = Vec::with_capacity(want);
    for line in raw.chunks_exact(row.checked_add(1)?) {
        let (filter, pixels) = line.split_first()?;
        if *filter != 0 {
            return None;
        }
        rgba.extend_from_slice(pixels);
    }
    Some((width, height, rgba))
}

#[cfg(any(windows, test))]
impl OverlayIcon {
    /// The committed PNG of this image (`icons/overlay-{1..9,9plus}.png`, `ci/gen-overlay-icons.mjs`).
    pub fn png(self) -> &'static [u8] {
        match self {
            OverlayIcon::Digit(1) => include_bytes!("../icons/overlay-1.png"),
            OverlayIcon::Digit(2) => include_bytes!("../icons/overlay-2.png"),
            OverlayIcon::Digit(3) => include_bytes!("../icons/overlay-3.png"),
            OverlayIcon::Digit(4) => include_bytes!("../icons/overlay-4.png"),
            OverlayIcon::Digit(5) => include_bytes!("../icons/overlay-5.png"),
            OverlayIcon::Digit(6) => include_bytes!("../icons/overlay-6.png"),
            OverlayIcon::Digit(7) => include_bytes!("../icons/overlay-7.png"),
            OverlayIcon::Digit(8) => include_bytes!("../icons/overlay-8.png"),
            OverlayIcon::Digit(_) => include_bytes!("../icons/overlay-9.png"),
            OverlayIcon::NinePlus => include_bytes!("../icons/overlay-9plus.png"),
        }
    }
}

// ---------- Tauri ----------

/// The Tauri half of [`Notifier`]: the Approvals window, the taskbar, the notification plugin and
/// the tray. The notification plugin is used from Rust only; no window capability grants it.
pub struct TauriNotifier {
    app: AppHandle<Wry>,
}

impl TauriNotifier {
    pub fn new(app: AppHandle<Wry>) -> TauriNotifier {
        TauriNotifier { app }
    }
}

/// The overlay of an app's Approvals window. The overlay only shows "while the window exists"
/// (PD-173): `set_badge` drives it for a window that is there, and `windows::open` applies the
/// current count to a window it builds ([`apply_overlay_to_new_window`]), on every path that
/// opens it (raise, tray menu, relaunch, startup).
struct AppOverlay<'a, R: Runtime>(&'a AppHandle<R>);

impl<R: Runtime> OverlaySink for AppOverlay<'_, R> {
    #[cfg(windows)]
    fn set_overlay(&self, icon: Option<OverlayIcon>) {
        let Some(w) = self.0.get_webview_window(Label::Approvals.as_str()) else {
            return;
        };
        let image = icon
            .and_then(|i| decode_overlay(i.png()))
            .map(|(width, height, rgba)| tauri::image::Image::new_owned(rgba, width, height));
        // The OS refusing an overlay is not an error of ours; the tray still shows the count.
        let _ = w.set_overlay_icon(image);
    }

    /// macOS (no Dock tile, the tray title carries the count) and Linux have no overlay.
    #[cfg(not(windows))]
    fn set_overlay(&self, _icon: Option<OverlayIcon>) {
        let _ = self.0;
    }
}

impl OverlaySink for TauriNotifier {
    fn set_overlay(&self, icon: Option<OverlayIcon>) {
        AppOverlay(&self.app).set_overlay(icon);
    }
}

impl Notifier for TauriNotifier {
    fn raise(&self, focus: bool) {
        // "Show without activating", or "show and focus" with `window_focus {requested: false}`
        // sent first (`windows::open` -> `Show::FocusUnrequested`). `open` logs its own failure.
        let how = if focus {
            Show::FocusUnrequested
        } else {
            Show::WithoutActivating
        };
        let _ = windows::open(&self.app, Label::Approvals, how);
        if !focus && flash_after_default_raise(std::env::consts::OS) {
            // Where `show()` may not activate or surface the window (Windows) the taskbar flash
            // says so (§5.6); macOS and Linux do not flash on a default-mode raise (L217 M-6).
            self.flash();
        }
    }

    fn flash(&self) {
        if let Some(w) = self.app.get_webview_window(Label::Approvals.as_str()) {
            let _ = w.request_user_attention(Some(UserAttentionType::Informational));
        }
    }

    fn toast(&self, text: &str) {
        // An OS refusal (Do Not Disturb, no notification service) is not an error of ours.
        let _ = self
            .app
            .notification()
            .builder()
            .title(TOAST_TITLE)
            .body(text)
            .show();
    }

    fn set_badge(&self, pending: u32) {
        // The tray's "Open approvals (N)", tooltip and (macOS) menu-bar title, and the Windows
        // taskbar overlay icon (PD-173). The macOS app has no Dock tile (§2.5).
        crate::tray::set_pending(&self.app, pending);
        drive_overlay(self, pending);
    }
}

/// The worker's view of the running app.
pub struct TauriEnv<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> TauriEnv<R> {
    pub fn new(app: AppHandle<R>) -> TauriEnv<R> {
        TauriEnv { app }
    }
}

impl<R: Runtime> AttentionEnv for TauriEnv<R> {
    fn counts(&self) -> Option<Counts> {
        crate::commands::core(&self.app)
            .ok()
            .map(|core| core_counts(&core))
    }

    fn window_hidden(&self) -> bool {
        self.app
            .get_webview_window(Label::Approvals.as_str())
            .is_none_or(|w| !w.is_visible().unwrap_or(false) || w.is_minimized().unwrap_or(false))
    }

    fn configured_mode(&self) -> Option<AttentionMode> {
        crate::commands::core(&self.app)
            .ok()
            .map(|core| core.settings().view().attention_mode)
    }
}

/// The engine of this app, managed by `serve::start`, with the feed that drives it: a later
/// `install` (T20's handler swap) hands out the same feed, so the engine and the tray keep
/// following the one worker.
pub struct AttentionHandle(pub Arc<AttentionEngine>, Arc<dyn UiSink>);

/// Builds the engine over the real clock and the Tauri notifier, manages it (the tray reads it) and
/// starts its thread; the feed goes into the UI sink. Idempotent: a second call returns the feed of
/// the first (the engine, its worker and the tray's handle stay the same). On a thread failure the
/// app runs without attention (logged; the queue itself does not depend on it, but the tray badge
/// is driven by the worker, so it stays at 0).
pub fn install(app: &AppHandle<Wry>, tray_host: Option<TrayHost>) -> Option<Arc<dyn UiSink>> {
    if let Some(h) = app.try_state::<AttentionHandle>() {
        return Some(h.1.clone());
    }
    let engine = Arc::new(AttentionEngine::new(
        Arc::new(TauriNotifier::new(app.clone())),
        Arc::new(atlas_duck_audit::SystemClock::new()),
        tray_host,
    ));
    match spawn_worker(engine.clone(), Arc::new(TauriEnv::new(app.clone()))) {
        Ok(feed) => {
            let feed: Arc<dyn UiSink> = Arc::new(feed);
            app.manage(AttentionHandle(engine, feed.clone()));
            Some(feed)
        }
        Err(_) => {
            tracing::warn!(
                event = LOG_EVENT_ATTENTION_START_FAILED,
                error_class = "thread"
            );
            None
        }
    }
}

/// True while Presentation mode is on (the tray tooltip says so).
pub fn presentation_on<R: Runtime>(app: &AppHandle<R>) -> bool {
    app.try_state::<AttentionHandle>()
        .is_some_and(|h| h.0.presentation())
}

/// The tray's "Presentation mode": switches it on, or off again (§5.6). Runs the store write on
/// the blocking pool; a failure is logged (`SettingsError`'s Display: its kind) and changes
/// nothing. Callable from the main thread.
pub fn toggle_presentation(app: &AppHandle<Wry>) {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let Some(engine) = app.try_state::<AttentionHandle>().map(|h| h.0.clone()) else {
            return;
        };
        let Ok(core) = crate::commands::core(&app) else {
            return;
        };
        let settings = core.settings();
        match engine.toggle_presentation(&*settings) {
            Ok(_) => crate::tray::refresh(&app),
            Err(e) => tracing::warn!(
                event = LOG_EVENT_PRESENTATION_FAILED,
                error_class = %e
            ),
        }
    });
}

#[cfg(test)]
mod tests {
    use atlas_duck_audit::clock::UtcInstant;
    use atlas_duck_audit::testing::FakeClock;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Raise(bool),
        Flash,
        Toast(String),
        Badge(u32),
    }

    #[derive(Default)]
    struct Mock(Mutex<Vec<Call>>);

    impl Mock {
        fn calls(&self) -> Vec<Call> {
            lock(&self.0).clone()
        }

        fn take(&self) -> Vec<Call> {
            std::mem::take(&mut *lock(&self.0))
        }

        fn raises(&self) -> usize {
            self.calls()
                .iter()
                .filter(|c| matches!(c, Call::Raise(_)))
                .count()
        }

        fn toasts(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Toast(t) => Some(t),
                    _ => None,
                })
                .collect()
        }
    }

    impl Notifier for Mock {
        fn raise(&self, focus: bool) {
            lock(&self.0).push(Call::Raise(focus));
        }
        fn flash(&self) {
            lock(&self.0).push(Call::Flash);
        }
        fn toast(&self, text: &str) {
            lock(&self.0).push(Call::Toast(text.to_owned()));
        }
        fn set_badge(&self, pending: u32) {
            lock(&self.0).push(Call::Badge(pending));
        }
    }

    struct Rig {
        engine: AttentionEngine,
        mock: Arc<Mock>,
        clock: Arc<FakeClock>,
    }

    fn rig_with(tray_host: Option<TrayHost>) -> Rig {
        let mock = Arc::new(Mock::default());
        let clock = Arc::new(FakeClock::new(UtcInstant(0)));
        let engine = AttentionEngine::new(mock.clone(), clock.clone(), tray_host);
        Rig {
            engine,
            mock,
            clock,
        }
    }

    fn rig() -> Rig {
        rig_with(Some(TrayHost::Present))
    }

    fn counts(reads: u32, writes: u32, scripts: u32) -> Counts {
        Counts {
            reads,
            writes,
            scripts,
        }
    }

    fn new_req() -> UiEvent {
        UiEvent::Attention {
            kind: AttentionKind::New,
            count: 1,
        }
    }

    fn queue(n: usize) -> UiEvent {
        UiEvent::QueueChanged {
            request_ids: (0..n).map(|i| format!("req_{i}")).collect(),
        }
    }

    /// One submit as the core reports it: the queue changes, then the attention event.
    fn submit(r: &Rig, now_counts: Counts, hidden: bool) {
        r.engine.on_event(&queue(1), now_counts, hidden);
        r.engine.on_event(&new_req(), now_counts, hidden);
    }

    struct Recorder(Mutex<Vec<String>>);

    impl AppChangeLog for Recorder {
        fn record(&self, key: &str, old: Value, new: Value) -> Result<(), SettingsError> {
            lock(&self.0).push(format!("{key}:{old}->{new}"));
            Ok(())
        }
    }

    struct Refusing;

    impl AppChangeLog for Refusing {
        fn record(&self, _: &str, _: Value, _: Value) -> Result<(), SettingsError> {
            Err(SettingsError::NoConfigFile)
        }
    }

    #[test]
    fn ui03_one_attention_per_submit_per_mode() {
        for (mode, want) in [
            (
                AttentionMode::ShowWithoutActivating,
                vec![Call::Raise(false)],
            ),
            (AttentionMode::ShowAndFocus, vec![Call::Raise(true)]),
            (AttentionMode::BadgeOnly, vec![]),
        ] {
            let r = rig();
            r.engine.set_configured_mode(mode);
            submit(&r, counts(1, 0, 0), true);
            let attention: Vec<Call> = r
                .mock
                .calls()
                .into_iter()
                .filter(|c| matches!(c, Call::Raise(_) | Call::Flash))
                .collect();
            assert_eq!(attention, want, "{mode:?}");
            // Every mode: the badge and one toast.
            assert!(r.mock.calls().contains(&Call::Badge(1)), "{mode:?}");
            assert_eq!(
                r.mock.toasts(),
                vec!["1 pending: 1 reads, 0 writes, 0 scripts".to_owned()],
                "{mode:?}"
            );
        }
    }

    #[test]
    fn ui03_raise_rules() {
        let r = rig();
        // 0 -> 1 raises.
        submit(&r, counts(1, 0, 0), false);
        assert_eq!(r.mock.raises(), 1);
        // 1 -> 2 with the window visible does not (even a minute later).
        r.clock.advance(Duration::from_secs(61));
        r.engine.on_event(&queue(2), counts(2, 0, 0), false);
        r.engine.on_event(&new_req(), counts(2, 0, 0), false);
        assert_eq!(r.mock.raises(), 1, "visible and not 0 -> 1");
        // A new request that stays put is not flashed (only stale/failed ones are told that way).
        assert!(
            !r.mock.calls().contains(&Call::Flash),
            "no flash for a new request"
        );
        // Hidden raises (the limiter has released after 61 s).
        r.engine.on_event(&queue(3), counts(3, 0, 0), true);
        r.engine.on_event(&new_req(), counts(3, 0, 0), true);
        assert_eq!(r.mock.raises(), 2, "hidden");
        // A second one within 60 s is suppressed, hidden or not.
        r.clock.advance(Duration::from_secs(59));
        r.engine.on_event(&new_req(), counts(4, 0, 0), true);
        assert_eq!(r.mock.raises(), 2, "60 s limit");
        // ... and released again after the minute.
        r.clock.advance(Duration::from_secs(2));
        r.engine.on_event(&new_req(), counts(4, 0, 0), true);
        assert_eq!(r.mock.raises(), 3, "limit released");
        // The queue drained: the next request is a 0 -> 1 again (after the limit).
        r.clock.advance(Duration::from_secs(61));
        r.engine.on_event(&queue(0), Counts::default(), false);
        submit(&r, counts(1, 0, 0), false);
        assert_eq!(r.mock.raises(), 4, "0 -> 1 again");
        // The limit is "at most once per 60 s": exactly 60 s later is released, 1 ms short is not.
        r.clock.advance(Duration::from_millis(59_999));
        r.engine.on_event(&new_req(), counts(2, 0, 0), true);
        assert_eq!(r.mock.raises(), 4, "59.999 s");
        r.clock.advance(Duration::from_millis(1));
        r.engine.on_event(&new_req(), counts(2, 0, 0), true);
        assert_eq!(r.mock.raises(), 5, "exactly 60 s");
    }

    #[test]
    fn ui03_toast_coalescing() {
        let r = rig();
        // Ten submits in five seconds: one toast, at the first.
        for i in 1..=10u32 {
            submit(&r, counts(i / 2 + i % 2, i / 2, 0), false);
            r.clock.advance(Duration::from_millis(500));
        }
        assert_eq!(r.mock.toasts().len(), 1, "{:?}", r.mock.calls());
        assert_eq!(r.engine.toast_due_in(), Some(Duration::from_millis(25_000)));
        // Held back: nothing before the 30 s are over, even when ticked.
        r.clock.advance(Duration::from_secs(24));
        r.engine.tick(counts(5, 5, 0));
        assert_eq!(r.mock.toasts().len(), 1);
        // Then the coalesced one, with the counts of that moment (x reads, y writes, z scripts).
        r.clock.advance(Duration::from_secs(1));
        r.engine.tick(counts(6, 3, 1));
        assert_eq!(
            r.mock.toasts(),
            vec![
                "1 pending: 1 reads, 0 writes, 0 scripts".to_owned(),
                "10 pending: 6 reads, 3 writes, 1 scripts".to_owned()
            ]
        );
        assert_eq!(r.engine.toast_due_in(), None);
        // Nothing waits any more: a tick sends nothing.
        r.clock.advance(Duration::from_secs(120));
        r.engine.tick(counts(6, 3, 1));
        assert_eq!(r.mock.toasts().len(), 2);
    }

    #[test]
    fn ui03_stale_and_failed_write_attention() {
        let r = rig();
        // A first request puts the window up and starts both limits.
        submit(&r, counts(1, 0, 0), false);
        r.mock.take();
        r.clock.advance(Duration::from_secs(10));
        r.engine.on_event(
            &UiEvent::NeedsAttentionChanged { count: 1 },
            counts(1, 0, 0),
            false,
        );
        for kind in [
            AttentionKind::Stale,
            AttentionKind::Failed,
            AttentionKind::OutcomeUnknown,
        ] {
            let before = r.mock.calls().len();
            r.engine.on_event(
                &UiEvent::Attention { kind, count: 1 },
                counts(1, 0, 0),
                false,
            );
            // Each is one attention call: the window is up and the raise is rate limited, so a flash.
            assert_eq!(
                r.mock.calls()[before..]
                    .iter()
                    .filter(|c| **c == Call::Flash)
                    .count(),
                1,
                "{kind:?}: {:?}",
                r.mock.calls()
            );
        }
        // Hidden and the limit released: the failure raises the window. The core tells the count
        // first, then the attention event (final review I-1).
        r.clock.advance(Duration::from_secs(61));
        r.mock.take();
        r.engine.on_event(
            &UiEvent::NeedsAttentionChanged { count: 1 },
            Counts::default(),
            true,
        );
        r.engine.on_event(
            &UiEvent::Attention {
                kind: AttentionKind::Failed,
                count: 1,
            },
            Counts::default(),
            true,
        );
        assert_eq!(
            r.mock.calls(),
            vec![
                Call::Badge(0),
                Call::Raise(false),
                Call::Toast("1 need attention".to_owned())
            ]
        );
        // The toast of a failure with an empty queue names the count only.
        assert_eq!(r.mock.toasts(), vec!["1 need attention".to_owned()]);
        // Badge only: no raise, no flash, the toast stays.
        let r = rig();
        r.engine.set_configured_mode(AttentionMode::BadgeOnly);
        r.engine.on_event(
            &UiEvent::Attention {
                kind: AttentionKind::Stale,
                count: 1,
            },
            counts(1, 0, 0),
            true,
        );
        assert!(
            r.mock
                .calls()
                .iter()
                .all(|c| !matches!(c, Call::Raise(_) | Call::Flash))
        );
        assert_eq!(r.mock.toasts().len(), 1);
    }

    /// Final review I-1: a failed write has left the queue (pending 0), so the toast and the
    /// tooltip line rest on the count the core told before the attention event, in every mode.
    #[test]
    fn ui03_failed_write_with_empty_queue_is_toasted_in_every_mode() {
        enum Setup {
            Mode(AttentionMode),
            Presentation,
        }
        for setup in [
            Setup::Mode(AttentionMode::ShowWithoutActivating),
            Setup::Mode(AttentionMode::ShowAndFocus),
            Setup::Mode(AttentionMode::BadgeOnly),
            Setup::Presentation,
        ] {
            for kind in [AttentionKind::Failed, AttentionKind::OutcomeUnknown] {
                let fail = UiEvent::Attention { kind, count: 1 };
                let told = UiEvent::NeedsAttentionChanged { count: 1 };
                let build = || {
                    let r = rig();
                    match &setup {
                        Setup::Mode(m) => r.engine.set_configured_mode(*m),
                        Setup::Presentation => {
                            r.engine
                                .set_presentation(true, &Recorder(Mutex::default()))
                                .ok();
                        }
                    }
                    r
                };
                // The core's order: the count, then the attention event.
                let r = build();
                r.engine.on_event(&told, Counts::default(), true);
                r.engine.on_event(&fail, Counts::default(), true);
                assert_eq!(
                    r.mock.toasts(),
                    vec!["1 need attention".to_owned()],
                    "{kind:?}: {:?}",
                    r.mock.calls()
                );
                // Negative control: the old order (attention first) sends no toast, which is
                // what this test catches if the core ever reverts.
                let r = build();
                r.engine.on_event(&fail, Counts::default(), true);
                r.engine.on_event(&told, Counts::default(), true);
                assert!(r.mock.toasts().is_empty(), "{kind:?}: {:?}", r.mock.calls());
            }
        }
    }

    #[test]
    fn presentation_mode_switches_to_badge_only_and_logs() {
        let r = rig();
        let log = Recorder(Mutex::default());
        assert_eq!(
            r.engine.effective_mode(),
            AttentionMode::ShowWithoutActivating
        );
        assert_eq!(r.engine.set_presentation(true, &log), Ok(true));
        assert!(r.engine.presentation());
        assert_eq!(r.engine.effective_mode(), AttentionMode::BadgeOnly);
        // One plain record, `old -> new`, under a key `apply` does not own.
        assert_eq!(
            *lock(&log.0),
            vec!["presentation_mode:false->true".to_owned()]
        );
        // It beats "show and focus": nothing is raised.
        r.engine.set_configured_mode(AttentionMode::ShowAndFocus);
        submit(&r, counts(0, 1, 0), true);
        assert_eq!(r.mock.raises(), 0);
        assert_eq!(r.mock.toasts().len(), 1, "badge and toast remain");
        // Already on: nothing recorded. Off again: recorded, the configured mode is back.
        assert_eq!(r.engine.set_presentation(true, &log), Ok(false));
        assert_eq!(r.engine.set_presentation(false, &log), Ok(true));
        assert_eq!(
            *lock(&log.0),
            vec![
                "presentation_mode:false->true".to_owned(),
                "presentation_mode:true->false".to_owned()
            ]
        );
        assert_eq!(r.engine.effective_mode(), AttentionMode::ShowAndFocus);
    }

    #[test]
    fn a_failed_record_leaves_presentation_mode_off() {
        let r = rig();
        assert_eq!(
            r.engine.set_presentation(true, &Refusing),
            Err(SettingsError::NoConfigFile)
        );
        assert!(!r.engine.presentation());
        assert_eq!(
            r.engine.effective_mode(),
            AttentionMode::ShowWithoutActivating
        );
        // The same switch that commits: the control for the check above.
        assert_eq!(
            r.engine.set_presentation(true, &Recorder(Mutex::default())),
            Ok(true)
        );
        assert!(r.engine.presentation());
    }

    #[test]
    fn no_tray_host_badge_only_shows_without_activating() {
        let r = rig_with(Some(TrayHost::Missing));
        r.engine.set_configured_mode(AttentionMode::BadgeOnly);
        assert_eq!(
            r.engine.effective_mode(),
            AttentionMode::ShowWithoutActivating
        );
        submit(&r, counts(1, 0, 0), true);
        assert_eq!(r.mock.raises(), 1);
        assert!(r.mock.calls().contains(&Call::Raise(false)));
        // Presentation mode is the same "badge only": it shows without activating there too.
        let p = rig_with(Some(TrayHost::Missing));
        assert_eq!(
            p.engine.set_presentation(true, &Recorder(Mutex::default())),
            Ok(true)
        );
        assert_eq!(
            p.engine.effective_mode(),
            AttentionMode::ShowWithoutActivating
        );
        // Control: with a tray (or on a platform without the check) badge only raises nothing.
        for host in [Some(TrayHost::Present), None] {
            let r = rig_with(host);
            r.engine.set_configured_mode(AttentionMode::BadgeOnly);
            submit(&r, counts(1, 0, 0), true);
            assert_eq!(r.mock.raises(), 0, "{host:?}");
        }
        // The other modes are untouched by the missing host.
        let r = rig_with(Some(TrayHost::Missing));
        r.engine.set_configured_mode(AttentionMode::ShowAndFocus);
        assert_eq!(r.engine.effective_mode(), AttentionMode::ShowAndFocus);
    }

    #[test]
    fn badge_follows_the_queue() {
        let r = rig();
        r.engine.on_event(&queue(2), counts(1, 1, 0), false);
        r.engine.on_event(&queue(2), counts(1, 1, 0), false);
        r.engine.on_event(&queue(0), Counts::default(), false);
        assert_eq!(r.mock.take(), vec![Call::Badge(2), Call::Badge(0)]);
    }

    #[derive(Default)]
    struct FakeOverlay(Mutex<Vec<Option<OverlayIcon>>>);

    impl OverlaySink for FakeOverlay {
        fn set_overlay(&self, icon: Option<OverlayIcon>) {
            lock(&self.0).push(icon);
        }
    }

    #[test]
    fn badge_overlay_counts_and_clears() {
        let sink = FakeOverlay::default();
        for pending in [1, 2, 9, 10, 11, u32::MAX, 0] {
            drive_overlay(&sink, pending);
        }
        assert_eq!(
            *lock(&sink.0),
            vec![
                Some(OverlayIcon::Digit(1)),
                Some(OverlayIcon::Digit(2)),
                Some(OverlayIcon::Digit(9)),
                Some(OverlayIcon::NinePlus),
                Some(OverlayIcon::NinePlus),
                Some(OverlayIcon::NinePlus),
                None,
            ]
        );
        // Every image the counts name decodes to a 16x16 RGBA picture of its own.
        let mut seen = Vec::new();
        for icon in (1..=9)
            .map(OverlayIcon::Digit)
            .chain([OverlayIcon::NinePlus])
        {
            let (w, h, rgba) = decode_overlay(icon.png()).expect("committed PNG decodes");
            assert_eq!((w, h, rgba.len()), (16, 16, 16 * 16 * 4), "{icon:?}");
            assert!(rgba.chunks(4).any(|p| p[3] == 0), "{icon:?}: clear corners");
            assert!(
                rgba.chunks(4).any(|p| p == [0xff, 0xff, 0xff, 0xff]),
                "{icon:?}: drawn count"
            );
            assert!(!seen.contains(&rgba), "{icon:?} repeats an image");
            seen.push(rgba);
        }
    }

    #[test]
    fn overlay_decoder_refuses_what_it_does_not_read() {
        let png = OverlayIcon::Digit(1).png();
        assert_eq!(decode_overlay(&[]), None);
        assert_eq!(decode_overlay(&png[..png.len() - 1]), None);
        let mut bad_signature = png.to_vec();
        bad_signature[1] = b'X';
        assert_eq!(decode_overlay(&bad_signature), None);
        // A palette image (colour type 3) is not what the generator writes.
        let mut palette = png.to_vec();
        palette[25] = 3;
        assert_eq!(decode_overlay(&palette), None);
        // A compressed (non-stored) deflate block is refused, not misread.
        let mut compressed = png.to_vec();
        let idat = compressed
            .windows(4)
            .position(|w| w == b"IDAT")
            .expect("IDAT chunk");
        compressed[idat + 4 + 2] = 0x03;
        assert_eq!(decode_overlay(&compressed), None);
    }

    /// The committed PNG with `edit(png, idat_data_start)` applied; the zlib header sits at
    /// `idat_data_start`, the block flags at `+2`, LEN at `+3`, NLEN at `+5`, the first filter byte
    /// at `+7`.
    fn mutated(edit: impl FnOnce(&mut Vec<u8>, usize)) -> Vec<u8> {
        let mut png = OverlayIcon::Digit(1).png().to_vec();
        let idat = png
            .windows(4)
            .position(|w| w == b"IDAT")
            .expect("IDAT chunk");
        edit(&mut png, idat + 4);
        png
    }

    #[test]
    fn overlay_decoder_refuses_each_malformed_stream() {
        // Control: the unedited file decodes (the refusals below are the edits' doing).
        assert!(decode_overlay(&mutated(|_, _| {})).is_some());
        // NLEN is not the complement of LEN.
        assert_eq!(decode_overlay(&mutated(|p, d| p[d + 5] ^= 0x01)), None);
        // A filter byte other than none.
        assert_eq!(decode_overlay(&mutated(|p, d| p[d + 7] = 1)), None);
        // A stored length that overruns the stream (NLEN kept consistent).
        assert_eq!(
            decode_overlay(&mutated(
                |p, d| p[d + 3..d + 7].copy_from_slice(&[0xff, 0xff, 0, 0])
            )),
            None
        );
        // No IDAT chunk, no IEND chunk.
        assert_eq!(decode_overlay(&mutated(|p, d| p[d - 1] = b'X')), None);
        let no_iend = {
            let mut png = OverlayIcon::Digit(1).png().to_vec();
            let end = png
                .windows(4)
                .position(|w| w == b"IEND")
                .expect("IEND chunk");
            png[end + 3] = b'X';
            png
        };
        assert_eq!(decode_overlay(&no_iend), None);
        // The header says another size than the pixels hold; and sizes that would ask for an
        // absurd buffer are refused before any is allocated.
        for (width, height) in [
            (15u32, 16u32),
            (16, 17),
            (0, 0),
            (257, 16),
            (1 << 20, 1 << 20),
        ] {
            let png = mutated(|p, _| {
                p[16..20].copy_from_slice(&width.to_be_bytes());
                p[20..24].copy_from_slice(&height.to_be_bytes());
            });
            assert_eq!(decode_overlay(&png), None, "{width}x{height}");
        }
    }

    #[test]
    fn a_new_approvals_window_gets_the_current_overlay() {
        let sink = FakeOverlay::default();
        overlay_for_new_window(&sink, Label::Approvals, 3);
        overlay_for_new_window(&sink, Label::Approvals, 12);
        overlay_for_new_window(&sink, Label::Approvals, 0);
        assert_eq!(
            *lock(&sink.0),
            vec![
                Some(OverlayIcon::Digit(3)),
                Some(OverlayIcon::NinePlus),
                None
            ]
        );
        // No other window has an overlay.
        let other = FakeOverlay::default();
        for label in Label::ALL.into_iter().filter(|l| *l != Label::Approvals) {
            overlay_for_new_window(&other, label, 3);
        }
        assert!(lock(&other.0).is_empty());
    }

    #[test]
    fn default_raise_flashes_only_on_windows() {
        assert!(flash_after_default_raise("windows"));
        assert!(!flash_after_default_raise("macos"));
        assert!(!flash_after_default_raise("linux"));
        assert!(!flash_after_default_raise("freebsd"));
    }

    #[test]
    fn toast_text_has_the_fixed_shape_and_counts_only() {
        assert_eq!(
            toast_text(counts(3, 2, 1), 0).as_deref(),
            Some("6 pending: 3 reads, 2 writes, 1 scripts")
        );
        assert_eq!(
            toast_text(counts(1, 0, 0), 2).as_deref(),
            Some("1 pending: 1 reads, 0 writes, 0 scripts; 2 need attention")
        );
        assert_eq!(toast_text(Counts::default(), 0), None);
        assert_eq!(
            Counts {
                reads: u32::MAX,
                writes: 1,
                scripts: 0
            }
            .pending(),
            u32::MAX
        );
    }

    #[test]
    fn two_quick_toggles_are_two_flips() {
        struct Slow(Mutex<Vec<String>>);
        impl AppChangeLog for Slow {
            fn record(&self, key: &str, old: Value, new: Value) -> Result<(), SettingsError> {
                std::thread::sleep(Duration::from_millis(100));
                lock(&self.0).push(format!("{key}:{old}->{new}"));
                Ok(())
            }
        }
        let r = rig();
        let engine = Arc::new(r.engine);
        let log = Arc::new(Slow(Mutex::default()));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let (e, l) = (engine.clone(), log.clone());
                std::thread::spawn(move || e.toggle_presentation(&*l))
            })
            .collect();
        for t in threads {
            assert!(t.join().expect("thread").is_ok());
        }
        // Off again: the second click was not lost to a stale read of "off".
        assert!(!engine.presentation());
        assert_eq!(
            *lock(&log.0),
            vec![
                "presentation_mode:false->true".to_owned(),
                "presentation_mode:true->false".to_owned()
            ]
        );
    }

    #[test]
    fn the_inbox_is_bounded_by_coalescing_and_never_blocks() {
        let inbox = Arc::new(Inbox::default());
        let feed = AttentionFeed {
            inbox: inbox.clone(),
        };
        // A stalled worker: nothing reads while the core keeps emitting.
        for i in 0..1_000 {
            feed.emit(queue(i % 5));
            feed.emit(UiEvent::NeedsAttentionChanged { count: i as u32 });
            feed.emit(new_req());
        }
        let waiting = lock(&inbox.state).events.len();
        assert_eq!(waiting, 2 + INBOX_ATTENTION_CAP);
        // The latest of the coalesced ones survives, in the order they were pushed.
        let mut seen = Vec::new();
        while let Ok(e) = inbox.recv(Some(Duration::ZERO)) {
            seen.push(e);
        }
        assert!(seen.contains(&queue(4)), "{seen:?}");
        assert!(seen.contains(&UiEvent::NeedsAttentionChanged { count: 999 }));
        assert_eq!(
            seen.iter()
                .filter(|e| matches!(e, UiEvent::Attention { .. }))
                .count(),
            INBOX_ATTENTION_CAP
        );
        // Closed and drained: the worker is told.
        drop(feed);
        assert!(matches!(
            inbox.recv(None),
            Err(RecvTimeoutError::Disconnected)
        ));
    }

    /// A held-back toast goes out by the worker itself (the `Timeout -> tick` path) once the
    /// engine's clock says the 30 s are over.
    #[test]
    fn the_worker_sends_the_trailing_toast_by_itself() {
        struct Env;
        impl AttentionEnv for Env {
            fn counts(&self) -> Option<Counts> {
                Some(counts(1, 0, 0))
            }
            fn window_hidden(&self) -> bool {
                true
            }
            fn configured_mode(&self) -> Option<AttentionMode> {
                Some(AttentionMode::BadgeOnly)
            }
        }
        let r = rig();
        let (mock, clock) = (r.mock.clone(), r.clock.clone());
        let feed = spawn_worker(Arc::new(r.engine), Arc::new(Env)).expect("thread");
        let wait_for = |toasts: usize| {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while mock.toasts().len() < toasts && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        feed.emit(new_req());
        wait_for(1);
        assert_eq!(mock.toasts().len(), 1, "the leading toast");
        // 29.99 s later: held back, due in 10 ms (the worker's real wait).
        clock.advance(Duration::from_millis(29_990));
        feed.emit(new_req());
        // Let the worker take it (it must not send: 10 ms of the 30 s are left on the clock).
        std::thread::sleep(Duration::from_millis(5));
        clock.advance(Duration::from_millis(10));
        wait_for(2);
        assert_eq!(
            mock.toasts().len(),
            2,
            "the trailing toast, sent by the tick"
        );
    }

    /// The worker: events in, one engine call each, with the env's counts; the held-back toast goes
    /// out by itself when its 30 s are over (the engine's clock is the fake, so the test moves it).
    #[test]
    fn the_worker_drives_the_engine_off_the_senders_thread() {
        struct Env {
            counts: Mutex<Counts>,
            mode: Mutex<AttentionMode>,
        }
        impl AttentionEnv for Env {
            fn counts(&self) -> Option<Counts> {
                Some(*lock(&self.counts))
            }
            fn window_hidden(&self) -> bool {
                true
            }
            fn configured_mode(&self) -> Option<AttentionMode> {
                Some(*lock(&self.mode))
            }
        }
        let r = rig();
        let engine = Arc::new(r.engine);
        let env = Arc::new(Env {
            counts: Mutex::new(counts(2, 1, 0)),
            mode: Mutex::new(AttentionMode::ShowAndFocus),
        });
        let feed = spawn_worker(engine.clone(), env).expect("thread");
        feed.emit(queue(3));
        feed.emit(UiEvent::RunningScriptsChanged); // not forwarded
        feed.emit(new_req());
        // Dropping the feed ends the worker after it drained its queue: the join is the wait.
        drop(feed);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while r.mock.toasts().is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            r.mock.calls(),
            vec![
                Call::Badge(3),
                Call::Raise(true),
                Call::Toast("3 pending: 2 reads, 1 writes, 0 scripts".to_owned())
            ]
        );
    }
}
