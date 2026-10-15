//! Windows end-session hook (§2.5 step 4, §15 V20, M6 T29): a hidden top-level window on a thread
//! of its own. (A message-only window gets no `WM_QUERYENDSESSION`: Windows sends it to top-level
//! windows only.) The decisions are [`EndSession`]'s, plain Rust that every OS compiles and tests;
//! only the window glue is Windows code.
//!
//! - `WM_QUERYENDSESSION`: the block goes up (`ShutdownBlockReasonCreate`) and the path begins
//!   with `OsShutdown`. The answer waits for the path, at most [`QUERY_WAIT`] (under the 5 s after
//!   which Windows lists the app as not responding): the path ended, the block goes and the
//!   answer is TRUE; a write is on the wire, or the path outlives the wait, the answer is FALSE
//!   and the block stays (Windows shows the reason) until a timer sees the path end. TRUE never
//!   comes before the path ended: tao's own window answers `WM_ENDSESSION (TRUE)` with `exit(0)`
//!   (tao 0.37 `event_loop.rs`), which would cut the path.
//! - The block's text is the one that is true now: [`BLOCK_REASON`] only while a write is on the
//!   wire, [`BLOCK_REASON_NO_WRITE`] otherwise; it changes when the write ends while the block is
//!   up (`ShutdownBlockReasonCreate` again replaces the text).
//! - `WM_ENDSESSION`: TRUE (the session ends: the user chose to shut down anyway, or the shutdown
//!   is forced) waits for the path, at most [`super::PATH_WAIT`]; FALSE (cancelled) changes
//!   nothing: the path that began runs to its end and the app exits.
//!
//! PD-83: when Windows ends the process first, the write on the wire is reconciled
//! `outcome_unknown {crash}` at the next start.

use std::time::{Duration, Instant};

use atlas_duck_core::ShutdownReason;

use super::{ShutdownPort, ShutdownTicket};

/// plan text (M6 T29): the reason Windows shows while the app holds the shutdown back for a
/// write on the wire.
pub const BLOCK_REASON: &str = "atlas-duck is finishing an approved write";
/// The reason Windows shows while the app holds the shutdown back with no write on the wire (the
/// rest of the path: the cancellations, `APP_STOP` and the store's shutdown).
pub const BLOCK_REASON_NO_WRITE: &str = "atlas-duck is saving its log before shutdown";
/// How long a `WM_QUERYENDSESSION` answer waits for the path (below Windows' 5 s).
pub const QUERY_WAIT: Duration = Duration::from_secs(4);
/// How often the answer looks at the write on the wire while it waits.
const QUERY_POLL: Duration = Duration::from_millis(50);
/// How often the window's timer looks for the end of the path once it answered FALSE.
pub const TIMER_INTERVAL: Duration = Duration::from_millis(100);

/// The OS block of the hook's window.
pub trait ShutdownBlock {
    /// Sets the block with `reason`, or replaces its text when it is up; false when Windows
    /// refused it.
    fn create(&self, reason: &str) -> bool;
    fn destroy(&self);
}

/// The block's text that is true now (see the module text).
fn block_text(port: &dyn ShutdownPort) -> &'static str {
    if port.write_in_flight() {
        BLOCK_REASON
    } else {
        BLOCK_REASON_NO_WRITE
    }
}

/// The hook window's end-session state (its thread only).
#[derive(Debug, Default)]
pub struct EndSession {
    ticket: Option<ShutdownTicket>,
    blocked: bool,
    /// The text last set while the block is up.
    text: Option<&'static str>,
}

impl EndSession {
    /// The run, begun here with `OsShutdown` unless another source began it.
    fn ticket(&mut self, port: &dyn ShutdownPort) -> ShutdownTicket {
        self.ticket
            .get_or_insert_with(|| port.begin(ShutdownReason::OsShutdown))
            .clone()
    }

    fn release(&mut self, block: &dyn ShutdownBlock) {
        if self.blocked {
            block.destroy();
            self.blocked = false;
            self.text = None;
        }
    }

    /// While the block is up: its text follows the write on the wire. A refused replacement is
    /// not retried until the text changes again (the old text stays up; the block logs it).
    fn retext(&mut self, port: &dyn ShutdownPort, block: &dyn ShutdownBlock) {
        let text = block_text(port);
        if self.blocked && self.text != Some(text) {
            block.create(text);
            self.text = Some(text);
        }
    }

    /// The block is up.
    pub fn blocked(&self) -> bool {
        self.blocked
    }

    /// The text of the block while it is up.
    pub fn text(&self) -> Option<&'static str> {
        self.text
    }

    /// `WM_QUERYENDSESSION`: the answer (TRUE: the session may end). See the module text.
    pub fn query(
        &mut self,
        port: &dyn ShutdownPort,
        block: &dyn ShutdownBlock,
        wait: Duration,
    ) -> bool {
        if !self.blocked {
            let text = block_text(port);
            self.blocked = block.create(text);
            self.text = self.blocked.then_some(text);
        }
        let ticket = self.ticket(port);
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if ticket.wait_timeout(QUERY_POLL.min(left)) {
                self.release(block);
                return true;
            }
            if port.write_in_flight() || left.is_zero() {
                self.retext(port, block);
                return false;
            }
        }
    }

    /// `WM_ENDSESSION`: `ending` (wParam TRUE) waits for the path, at most `wait`, then releases
    /// the block (Windows ends the process once this returns). True when the path ended.
    pub fn end(
        &mut self,
        port: &dyn ShutdownPort,
        block: &dyn ShutdownBlock,
        ending: bool,
        wait: Duration,
    ) -> bool {
        if !ending {
            return self.ticket.as_ref().is_some_and(ShutdownTicket::is_done);
        }
        let ended = self.ticket(port).wait_timeout(wait);
        self.release(block);
        ended
    }

    /// The window's timer after a FALSE answer: while the path runs the block's text follows the
    /// write on the wire; once the path ended the block goes. True when nothing is left to watch
    /// (the timer stops).
    pub fn poll(&mut self, port: &dyn ShutdownPort, block: &dyn ShutdownBlock) -> bool {
        if self.ticket.as_ref().is_some_and(|t| !t.is_done()) {
            self.retext(port, block);
            return false;
        }
        self.release(block);
        true
    }
}

#[cfg(windows)]
pub use self::window::install;

#[cfg(windows)]
mod window {
    use std::cell::RefCell;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::{Arc, OnceLock};

    use windows_sys::Win32::Foundation::{GetLastError, HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Shutdown::{
        ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, KillTimer, MSG,
        RegisterClassExW, SetTimer, TranslateMessage, WM_ENDSESSION, WM_QUERYENDSESSION, WM_TIMER,
        WNDCLASSEXW, WS_EX_TOOLWINDOW, WS_OVERLAPPED,
    };

    use super::super::{LOG_EVENT_OS_END_SESSION, LOG_EVENT_OS_HOOK_FAILED, PATH_WAIT};
    use super::{EndSession, QUERY_WAIT, ShutdownBlock, ShutdownPort, TIMER_INTERVAL};

    const THREAD_NAME: &str = "atlas-duck-end-session";
    const CLASS_NAME: &str = "atlas-duck-end-session";
    /// The window is never shown; Windows lists a blocking app by its window's title.
    const WINDOW_TITLE: &str = "atlas-duck";
    const TIMER_ID: usize = 1;

    static PORT: OnceLock<Arc<dyn ShutdownPort>> = OnceLock::new();

    thread_local! {
        static STATE: RefCell<EndSession> = RefCell::new(EndSession::default());
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn failed(step: &'static str) {
        tracing::warn!(
            event = LOG_EVENT_OS_HOOK_FAILED,
            reason = "windows",
            error_class = step
        );
    }

    /// A Win32 call failed: logged with its `GetLastError` code. Called right after the failed
    /// call, before anything else can change the thread's last error.
    fn failed_call(step: &'static str) {
        // SAFETY: reads this thread's last-error code; no arguments.
        let os_error = unsafe { GetLastError() };
        tracing::warn!(
            event = LOG_EVENT_OS_HOOK_FAILED,
            reason = "windows",
            error_class = step,
            os_error
        );
    }

    /// Starts the window's thread (once per process). A failure is logged; the run loop's
    /// fallback (`os_hooks::on_loop_exit`) stays.
    pub fn install(port: Arc<dyn ShutdownPort>) {
        if PORT.set(port).is_err() {
            return;
        }
        let spawned = std::thread::Builder::new()
            .name(THREAD_NAME.to_owned())
            .spawn(run_window);
        if spawned.is_err() {
            failed("thread");
        }
    }

    /// Registers the class, creates the hidden top-level window and pumps its messages for the
    /// rest of the process (the thread is never joined). A failed step is logged where it failed.
    fn run_window() {
        let class = wide(CLASS_NAME);
        let title = wide(WINDOW_TITLE);
        // SAFETY: a null name asks for the handle of this process's own exe module; it is not
        // owned (never freed).
        let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
        if instance.is_null() {
            return failed_call("module_handle");
        }
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: class.as_ptr(),
            ..WNDCLASSEXW::default()
        };
        // SAFETY: `wc` is initialized, its size set; `class` is NUL-terminated and outlives the
        // call (Windows copies the name).
        if unsafe { RegisterClassExW(&wc) } == 0 {
            return failed_call("register_class");
        }
        // SAFETY: the class was registered above; both strings are NUL-terminated and outlive the
        // call; no parent (a top-level window, never shown: no WS_VISIBLE), no menu, no create
        // parameter.
        let hwnd = unsafe {
            CreateWindowExW(
                WS_EX_TOOLWINDOW,
                class.as_ptr(),
                title.as_ptr(),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                instance,
                std::ptr::null(),
            )
        };
        if hwnd.is_null() {
            return failed_call("create_window");
        }
        let mut msg = MSG::default();
        loop {
            // SAFETY: `msg` is a valid out pointer; a null window takes every message of this
            // thread.
            let got = unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) };
            // 0: WM_QUIT (nothing posts it); -1: an error. The window then answers no more.
            if got == -1 {
                return failed_call("message_loop");
            }
            if got == 0 {
                return failed("message_loop");
            }
            // SAFETY: `msg` was filled by `GetMessageW`.
            unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    /// The block on this thread's own window (`hwnd` never leaves the window procedure).
    struct WindowBlock(HWND);

    impl ShutdownBlock for WindowBlock {
        fn create(&self, reason: &str) -> bool {
            let reason = wide(reason);
            // SAFETY: `self.0` is the live window whose procedure runs on this thread (the only
            // thread allowed to set its block); `reason` is NUL-terminated and outlives the call.
            let ok = unsafe { ShutdownBlockReasonCreate(self.0, reason.as_ptr()) } != 0;
            if !ok {
                failed_call("block_reason_create");
            }
            ok
        }

        fn destroy(&self) {
            // SAFETY: as in `create`.
            if unsafe { ShutdownBlockReasonDestroy(self.0) } == 0 {
                failed_call("block_reason_destroy");
            }
        }
    }

    /// Starts the timer that releases the block at the end of the path.
    fn start_timer(hwnd: HWND) {
        // SAFETY: `hwnd` is this thread's live window; no callback (WM_TIMER is posted).
        if unsafe { SetTimer(hwnd, TIMER_ID, TIMER_INTERVAL.as_millis() as u32, None) } == 0 {
            failed_call("set_timer");
        }
    }

    fn stop_timer(hwnd: HWND) {
        // SAFETY: as in `start_timer`.
        unsafe { KillTimer(hwnd, TIMER_ID) };
    }

    /// The decisions for one of our messages (`WM_QUERYENDSESSION`, `WM_ENDSESSION`, `WM_TIMER`);
    /// `None`: not ours (the default procedure answers). Without the state or the port the answer
    /// is 0 (FALSE for `WM_QUERYENDSESSION`), never the default procedure's TRUE.
    fn on_message(hwnd: HWND, msg: u32, wparam: WPARAM) -> Option<LRESULT> {
        if msg == WM_TIMER && wparam != TIMER_ID {
            return None;
        }
        STATE.with(|state| {
            // No message is pumped while the state is borrowed, so this never fails.
            let Ok(mut state) = state.try_borrow_mut() else {
                failed("state_busy");
                return Some(0);
            };
            // Set before the window exists (`install`).
            let Some(port) = PORT.get() else {
                return Some(0);
            };
            let block = WindowBlock(hwnd);
            match msg {
                WM_QUERYENDSESSION => {
                    tracing::info!(
                        event = LOG_EVENT_OS_END_SESSION,
                        reason = "wm_queryendsession"
                    );
                    let answer = state.query(&**port, &block, QUERY_WAIT);
                    if !answer {
                        start_timer(hwnd);
                    }
                    Some(LRESULT::from(answer))
                }
                WM_ENDSESSION => {
                    let ending = wparam != 0;
                    if ending {
                        tracing::info!(event = LOG_EVENT_OS_END_SESSION, reason = "wm_endsession");
                    }
                    if !state.end(&**port, &block, ending, PATH_WAIT) && ending {
                        failed("path_wait_expired");
                    }
                    Some(0)
                }
                WM_TIMER => {
                    if state.poll(&**port, &block) {
                        stop_timer(hwnd);
                    }
                    Some(0)
                }
                _ => None,
            }
        })
    }

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let ours = match msg {
            // A panic must not unwind into Windows. In builds that unwind (dev and test) it is
            // caught here and answers 0 (FALSE: Windows keeps waiting; the run loop's fallback
            // runs the path if the session ends anyway). Release builds use `panic = "abort"`
            // (workspace Cargo.toml): there a panic ends the process at once, before this catch,
            // with no path, no `APP_STOP` and no cancellations; the next start reconciles (§11.3).
            WM_QUERYENDSESSION | WM_ENDSESSION | WM_TIMER => {
                catch_unwind(AssertUnwindSafe(|| on_message(hwnd, msg, wparam))).unwrap_or(Some(0))
            }
            _ => None,
        };
        match ours {
            Some(answer) => answer,
            // SAFETY: the arguments are the ones Windows passed to this procedure.
            None => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A busy state answers 0 (FALSE for `WM_QUERYENDSESSION`), not the default procedure's
        /// TRUE. No Win32 call is reached: the answer comes before the port and the window.
        #[test]
        fn a_busy_state_answers_false() {
            STATE.with(|state| {
                let _held = state.borrow_mut();
                for (msg, wparam) in [(WM_QUERYENDSESSION, 0), (WM_ENDSESSION, 1)] {
                    assert_eq!(on_message(std::ptr::null_mut(), msg, wparam), Some(0));
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use atlas_duck_core::ShutdownReason;

    use super::super::fake::FakePort;
    use super::*;

    /// The block as the window sees it: up or not, its text, and how often it was set.
    #[derive(Default)]
    struct FakeBlock {
        up: Cell<bool>,
        creates: Cell<u32>,
        refuse: Cell<bool>,
        shown: Cell<Option<&'static str>>,
    }

    impl ShutdownBlock for FakeBlock {
        fn create(&self, reason: &str) -> bool {
            self.creates.set(self.creates.get() + 1);
            if self.refuse.get() {
                return false;
            }
            self.up.set(true);
            self.shown.set(
                [BLOCK_REASON, BLOCK_REASON_NO_WRITE]
                    .into_iter()
                    .find(|t| *t == reason),
            );
            true
        }

        fn destroy(&self) {
            self.up.set(false);
            self.shown.set(None);
        }
    }

    #[test]
    fn the_reason_is_the_plan_text() {
        assert_eq!(BLOCK_REASON, "atlas-duck is finishing an approved write");
        assert_eq!(
            BLOCK_REASON_NO_WRITE,
            "atlas-duck is saving its log before shutdown"
        );
        assert!(QUERY_WAIT < Duration::from_secs(5), "under Windows' 5 s");
    }

    /// I-40 (Windows half, injected port): `WM_QUERYENDSESSION` begins the path once with
    /// `OsShutdown`; while a write is on the wire it answers FALSE and the block stays up until
    /// the path ended (the timer); then the block goes. A second query joins the run.
    #[test]
    fn i40_os_hook_runs_shutdown_path() {
        let port = FakePort::new();
        port.write.store(true, Ordering::SeqCst);
        let block = FakeBlock::default();
        let mut s = EndSession::default();
        let began = Instant::now();
        assert!(
            !s.query(&*port, &block, QUERY_WAIT),
            "FALSE while the write is on the wire"
        );
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "no wait for the write"
        );
        assert_eq!(port.begins(), [ShutdownReason::OsShutdown]);
        assert!(block.up.get() && s.blocked());
        assert_eq!(block.shown.get(), Some(BLOCK_REASON));
        // The timer: still running.
        assert!(!s.poll(&*port, &block));
        assert!(block.up.get());
        // The user retries the shutdown: the run is joined, still FALSE, still blocked.
        assert!(!s.query(&*port, &block, QUERY_WAIT));
        assert_eq!(port.starts(), 1);
        assert_eq!(
            port.begins(),
            [ShutdownReason::OsShutdown],
            "the window keeps its ticket"
        );
        assert!(block.up.get());
        assert_eq!(block.shown.get(), Some(BLOCK_REASON));
        // The path ended: the timer releases the block and stops.
        port.finish();
        assert!(s.poll(&*port, &block));
        assert!(!block.up.get() && !s.blocked());
        // A query after the end: TRUE at once.
        assert!(s.query(&*port, &block, QUERY_WAIT));
        assert!(!block.up.get());
    }

    /// The block says "approved write" only while a write is on the wire: the other text when the
    /// path outlives the answer without one, and a switch whenever the write starts or ends while
    /// the block is up. An unchanged text is not set again.
    #[test]
    fn the_block_text_follows_the_write() {
        let port = FakePort::new();
        let block = FakeBlock::default();
        let mut s = EndSession::default();
        assert!(!s.query(&*port, &block, Duration::from_millis(120)));
        assert_eq!(block.shown.get(), Some(BLOCK_REASON_NO_WRITE));
        assert_eq!(s.text(), Some(BLOCK_REASON_NO_WRITE));
        assert_eq!(block.creates.get(), 1);
        // The timer while nothing changed: no new text.
        assert!(!s.poll(&*port, &block));
        assert_eq!(block.creates.get(), 1);
        // A write goes on the wire while the block is up, then finishes; the path runs on.
        port.write.store(true, Ordering::SeqCst);
        assert!(!s.poll(&*port, &block));
        assert_eq!(block.shown.get(), Some(BLOCK_REASON));
        port.write.store(false, Ordering::SeqCst);
        assert!(!s.poll(&*port, &block));
        assert_eq!(block.shown.get(), Some(BLOCK_REASON_NO_WRITE));
        assert!(block.up.get() && s.blocked());
        assert_eq!(block.creates.get(), 3);

        // The write that held the answer finishes while the block is up.
        let port = FakePort::new();
        port.write.store(true, Ordering::SeqCst);
        let block = FakeBlock::default();
        let mut s = EndSession::default();
        assert!(!s.query(&*port, &block, QUERY_WAIT));
        assert_eq!(block.shown.get(), Some(BLOCK_REASON));
        port.write.store(false, Ordering::SeqCst);
        assert!(!s.poll(&*port, &block));
        assert_eq!(block.shown.get(), Some(BLOCK_REASON_NO_WRITE));
        port.finish();
        assert!(s.poll(&*port, &block));
        assert_eq!(
            (block.up.get(), block.shown.get(), s.text()),
            (false, None, None)
        );
    }

    /// No write on the wire: the answer waits for the path and is TRUE only after it ended (tao's
    /// window would `exit(0)` on the `WM_ENDSESSION` that follows a TRUE).
    #[test]
    fn true_only_after_the_path_ended() {
        let port = FakePort::new();
        let finisher = {
            let port = port.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(150));
                port.finish();
            })
        };
        let block = FakeBlock::default();
        let mut s = EndSession::default();
        let began = Instant::now();
        assert!(s.query(&*port, &block, QUERY_WAIT));
        assert!(
            began.elapsed() >= Duration::from_millis(150),
            "answered before the end"
        );
        assert!(port.path.ended());
        assert_eq!(
            block.creates.get(),
            1,
            "the block was up while the answer waited"
        );
        assert!(!block.up.get(), "and released with the TRUE");
        let _ = finisher.join();

        // A path that outlives the wait without a write: FALSE, the block stays, and it does not
        // name a write.
        let port = FakePort::new();
        let block = FakeBlock::default();
        let mut s = EndSession::default();
        assert!(!s.query(&*port, &block, Duration::from_millis(120)));
        assert!(block.up.get());
        assert_eq!(block.shown.get(), Some(BLOCK_REASON_NO_WRITE));
        assert_eq!(port.begins(), [ShutdownReason::OsShutdown]);

        // A refused block does not stop the path: FALSE while the write is on the wire.
        let port = FakePort::new();
        port.write.store(true, Ordering::SeqCst);
        let block = FakeBlock::default();
        block.refuse.set(true);
        let mut s = EndSession::default();
        assert!(!s.query(&*port, &block, QUERY_WAIT));
        assert_eq!(port.starts(), 1);
        assert!(!s.blocked());
        // The next query tries the block again.
        block.refuse.set(false);
        assert!(!s.query(&*port, &block, QUERY_WAIT));
        assert!(s.blocked() && block.creates.get() == 2);
    }

    /// `WM_ENDSESSION (TRUE)` waits for the path (begun there when no query came first) and
    /// releases the block; FALSE (cancelled) neither waits nor releases.
    #[test]
    fn end_session_waits_for_the_path() {
        let port = FakePort::new();
        port.write.store(true, Ordering::SeqCst);
        let block = FakeBlock::default();
        let mut s = EndSession::default();
        assert!(!s.query(&*port, &block, QUERY_WAIT));
        assert!(!s.end(&*port, &block, false, Duration::from_secs(10)));
        assert!(
            block.up.get(),
            "a cancelled shutdown keeps the block until the path ended"
        );
        let finisher = {
            let port = port.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                port.finish();
            })
        };
        assert!(s.end(&*port, &block, true, Duration::from_secs(10)));
        assert!(!block.up.get());
        let _ = finisher.join();

        // Forced: no query came first.
        let port = FakePort::new();
        port.instant.store(true, Ordering::SeqCst);
        let mut s = EndSession::default();
        assert!(s.end(&*port, &FakeBlock::default(), true, Duration::from_secs(10)));
        assert_eq!(port.begins(), [ShutdownReason::OsShutdown]);
        // A path that outlives the wait: Windows ends the process after the answer.
        let port = FakePort::new();
        let mut s = EndSession::default();
        assert!(!s.end(
            &*port,
            &FakeBlock::default(),
            true,
            Duration::from_millis(30)
        ));
    }
}
