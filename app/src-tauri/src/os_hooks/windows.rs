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
//! - The reason (M10 T23, PD-172, L129): an end session whose `lParam` has `ENDSESSION_CLOSEAPP`
//!   (Restart Manager closing the app so an installer can replace its files, Tauri's own
//!   `CheckIfAppIsRunning` among them) runs the path with `Installer`; every other end session
//!   (logoff, shutdown, critical) with `OsShutdown` ([`end_session_reason`]).
//! - The installer's quit request (§2.5, §12.2): the registered message [`INSTALLER_QUIT_MESSAGE`],
//!   sent by `windows/hooks.nsh` to the window found by [`WINDOW_CLASS`], runs the path with
//!   `Installer` and is answered 1 after the path ended, at most [`super::PATH_WAIT`]; no block
//!   goes up (no session ends). The installer waits for the app's process only after that 1: a
//!   failed send, or `DefWindowProcW`'s 0 when the app could not register the message, means it
//!   terminates the app at once.
//! - Who can send the quit request: any process on the same desktop at the app's integrity level
//!   or higher (the same user's medium-IL programs, an elevated installer), as with
//!   `WM_QUERYENDSESSION`, which such a process can send as well (or it ends the app outright).
//!   Low-IL and AppContainer senders, the script sandbox's worker among them, are blocked: UIPI
//!   drops their messages (the app never calls `ChangeWindowMessageFilterEx`), and the worker's job
//!   has `JOB_OBJECT_UILIMIT_ALL` (no USER handles outside the job).
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
/// rest of the path: the cancellations, `APP_STOP` and the store's shutdown). Plan text (M6 T29
/// review wording, in no spec sentence; the lead's docs record it).
pub const BLOCK_REASON_NO_WRITE: &str = "atlas-duck is saving its log before shutdown";
/// How long a `WM_QUERYENDSESSION` answer waits for the path (below Windows' 5 s).
pub const QUERY_WAIT: Duration = Duration::from_secs(4);
/// How often the answer looks at the write on the wire while it waits.
const QUERY_POLL: Duration = Duration::from_millis(50);
/// How often the window's timer looks for the end of the path once it answered FALSE.
pub const TIMER_INTERVAL: Duration = Duration::from_millis(100);
/// The hidden window's class: the installer finds the window by it (`hooks.nsh`
/// `ATLAS_DUCK_ENDSESSION_CLASS`, the same string; a test compares them).
pub const WINDOW_CLASS: &str = "atlas-duck-end-session";
/// The name of the installer's registered quit message (`RegisterWindowMessageW`; `hooks.nsh`
/// `ATLAS_DUCK_INSTALLER_QUIT_MESSAGE`, the same string).
pub const INSTALLER_QUIT_MESSAGE: &str = "AtlasDuckInstallerQuit";
/// The app's answer to the quit request: it took it (`hooks.nsh` compares the answer with this
/// value; `DefWindowProcW` answers 0).
pub const INSTALLER_QUIT_TAKEN: isize = 1;
/// `ENDSESSION_CLOSEAPP` (WinUser.h; every OS compiles the mapping, the Windows build checks the
/// value against `windows-sys`).
pub const ENDSESSION_CLOSEAPP: u32 = 0x0000_0001;

/// The reason an end-session message's `lParam` names: `ENDSESSION_CLOSEAPP` is an installer (or
/// an update) closing the app to replace its files, `Installer`; anything else is the session
/// ending, `OsShutdown`.
pub fn end_session_reason(lparam: isize) -> ShutdownReason {
    if lparam & ENDSESSION_CLOSEAPP as isize != 0 {
        ShutdownReason::Installer
    } else {
        ShutdownReason::OsShutdown
    }
}

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
    /// The run, begun here with `reason` unless this window or another source began it.
    fn ticket(&mut self, port: &dyn ShutdownPort, reason: ShutdownReason) -> ShutdownTicket {
        self.ticket
            .get_or_insert_with(|| port.begin(reason))
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

    /// `WM_QUERYENDSESSION`: the answer (TRUE: the session may end). `reason` is its `lParam`'s
    /// ([`end_session_reason`]). See the module text.
    pub fn query(
        &mut self,
        port: &dyn ShutdownPort,
        block: &dyn ShutdownBlock,
        reason: ShutdownReason,
        wait: Duration,
    ) -> bool {
        if !self.blocked {
            let text = block_text(port);
            self.blocked = block.create(text);
            self.text = self.blocked.then_some(text);
        }
        let ticket = self.ticket(port, reason);
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

    /// `WM_ENDSESSION`: `ending` (wParam TRUE) waits for the path (begun with `reason`, its
    /// `lParam`'s, when no query came first), at most `wait`, then releases the block (Windows
    /// ends the process once this returns). True when the path ended.
    pub fn end(
        &mut self,
        port: &dyn ShutdownPort,
        block: &dyn ShutdownBlock,
        ending: bool,
        reason: ShutdownReason,
        wait: Duration,
    ) -> bool {
        if !ending {
            return self.ticket.as_ref().is_some_and(ShutdownTicket::is_done);
        }
        let ended = self.ticket(port, reason).wait_timeout(wait);
        self.release(block);
        ended
    }

    /// The installer's quit request ([`INSTALLER_QUIT_MESSAGE`]): the path begins with
    /// `Installer` (or the one that runs is joined) and the answer waits for its end, at most
    /// `wait`. No block goes up: no session ends. True when the path ended.
    pub fn installer_quit(&mut self, port: &dyn ShutdownPort, wait: Duration) -> bool {
        self.ticket(port, ShutdownReason::Installer)
            .wait_timeout(wait)
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
        RegisterClassExW, RegisterWindowMessageW, SetTimer, TranslateMessage, WM_ENDSESSION,
        WM_QUERYENDSESSION, WM_TIMER, WNDCLASSEXW, WS_EX_TOOLWINDOW, WS_OVERLAPPED,
    };

    use super::super::{LOG_EVENT_OS_END_SESSION, LOG_EVENT_OS_HOOK_FAILED, PATH_WAIT};
    use super::{
        EndSession, INSTALLER_QUIT_MESSAGE, INSTALLER_QUIT_TAKEN, QUERY_WAIT, ShutdownBlock,
        ShutdownPort, TIMER_INTERVAL, WINDOW_CLASS, end_session_reason,
    };

    const THREAD_NAME: &str = "atlas-duck-end-session";
    /// The window is never shown; Windows lists a blocking app by its window's title.
    const WINDOW_TITLE: &str = "atlas-duck";
    const TIMER_ID: usize = 1;

    static PORT: OnceLock<Arc<dyn ShutdownPort>> = OnceLock::new();
    /// The id Windows gave [`INSTALLER_QUIT_MESSAGE`] (set before the window exists; unset when
    /// the registration failed: `DefWindowProcW` then answers the request 0, and the installer
    /// terminates the app at once instead of waiting for it).
    static QUIT_MESSAGE: OnceLock<u32> = OnceLock::new();

    /// `msg` is the installer's quit request.
    fn is_installer_quit(msg: u32) -> bool {
        QUIT_MESSAGE.get() == Some(&msg)
    }

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
        let class = wide(WINDOW_CLASS);
        let title = wide(WINDOW_TITLE);
        let quit = wide(INSTALLER_QUIT_MESSAGE);
        // SAFETY: `quit` is NUL-terminated and outlives the call.
        match unsafe { RegisterWindowMessageW(quit.as_ptr()) } {
            0 => failed_call("register_message"),
            id => {
                let _ = QUIT_MESSAGE.set(id);
            }
        }
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

    /// The decisions for one of our messages (`WM_QUERYENDSESSION`, `WM_ENDSESSION`, `WM_TIMER`,
    /// the installer's quit request); `None`: not ours (the default procedure answers). Without
    /// the state or the port the answer is 0 (FALSE for `WM_QUERYENDSESSION`), never the default
    /// procedure's TRUE.
    fn on_message(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> Option<LRESULT> {
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
                m if is_installer_quit(m) => {
                    tracing::info!(event = LOG_EVENT_OS_END_SESSION, reason = "installer_quit");
                    if !state.installer_quit(&**port, PATH_WAIT) {
                        failed("path_wait_expired");
                    }
                    // 1: the app took the request (`hooks.nsh` waits for its process only then).
                    Some(INSTALLER_QUIT_TAKEN)
                }
                WM_QUERYENDSESSION => {
                    tracing::info!(
                        event = LOG_EVENT_OS_END_SESSION,
                        reason = "wm_queryendsession"
                    );
                    let reason = end_session_reason(lparam);
                    let answer = state.query(&**port, &block, reason, QUERY_WAIT);
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
                    let reason = end_session_reason(lparam);
                    if !state.end(&**port, &block, ending, reason, PATH_WAIT) && ending {
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
            m if m == WM_QUERYENDSESSION
                || m == WM_ENDSESSION
                || m == WM_TIMER
                || is_installer_quit(m) =>
            {
                catch_unwind(AssertUnwindSafe(|| on_message(hwnd, msg, wparam, lparam)))
                    .unwrap_or(Some(0))
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

        /// M10 T36 (M6 M-1): a failed Win32 call's line carries `os_error` (the `GetLastError`
        /// number) through the allowlist; it was counted as dropped.
        #[test]
        fn diag_lines_carry_os_error() {
            assert_eq!(
                crate::os_hooks::LOG_FIELDS,
                ["os_error"],
                "the allowlist is shared: pin this module's own"
            );
            let out = crate::diag::fields::test_support::lines_after_extending(
                crate::os_hooks::LOG_FIELDS,
                || {
                    // SAFETY: sets this thread's last-error code; no pointers.
                    unsafe { windows_sys::Win32::Foundation::SetLastError(1400) };
                    failed_call("create_window");
                },
            );
            assert_eq!(out.lines().count(), 1, "{out}");
            assert!(
                out.contains(
                    "event=os_hook_failed reason=windows error_class=create_window os_error=1400 dropped_fields=0"
                ),
                "{out}"
            );
        }

        /// A busy state answers 0 (FALSE for `WM_QUERYENDSESSION`), not the default procedure's
        /// TRUE. No Win32 call is reached: the answer comes before the port and the window.
        #[test]
        fn a_busy_state_answers_false() {
            STATE.with(|state| {
                let _held = state.borrow_mut();
                for (msg, wparam) in [(WM_QUERYENDSESSION, 0), (WM_ENDSESSION, 1)] {
                    assert_eq!(on_message(std::ptr::null_mut(), msg, wparam, 0), Some(0));
                }
            });
        }

        /// The portable mapping's constant is WinUser.h's.
        #[test]
        fn endsession_closeapp_is_the_windows_value() {
            use windows_sys::Win32::UI::WindowsAndMessaging::ENDSESSION_CLOSEAPP as WIN;
            assert_eq!(super::super::ENDSESSION_CLOSEAPP, WIN);
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

    /// A plain end session's reason (`lParam` 0).
    const OS: ShutdownReason = ShutdownReason::OsShutdown;

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
            !s.query(&*port, &block, OS, QUERY_WAIT),
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
        assert!(!s.query(&*port, &block, OS, QUERY_WAIT));
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
        assert!(s.query(&*port, &block, OS, QUERY_WAIT));
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
        assert!(!s.query(&*port, &block, OS, Duration::from_millis(120)));
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
        assert!(!s.query(&*port, &block, OS, QUERY_WAIT));
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
        assert!(s.query(&*port, &block, OS, QUERY_WAIT));
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
        assert!(!s.query(&*port, &block, OS, Duration::from_millis(120)));
        assert!(block.up.get());
        assert_eq!(block.shown.get(), Some(BLOCK_REASON_NO_WRITE));
        assert_eq!(port.begins(), [ShutdownReason::OsShutdown]);

        // A refused block does not stop the path: FALSE while the write is on the wire.
        let port = FakePort::new();
        port.write.store(true, Ordering::SeqCst);
        let block = FakeBlock::default();
        block.refuse.set(true);
        let mut s = EndSession::default();
        assert!(!s.query(&*port, &block, OS, QUERY_WAIT));
        assert_eq!(port.starts(), 1);
        assert!(!s.blocked());
        // The next query tries the block again.
        block.refuse.set(false);
        assert!(!s.query(&*port, &block, OS, QUERY_WAIT));
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
        assert!(!s.query(&*port, &block, OS, QUERY_WAIT));
        assert!(!s.end(&*port, &block, false, OS, Duration::from_secs(10)));
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
        assert!(s.end(&*port, &block, true, OS, Duration::from_secs(10)));
        assert!(!block.up.get());
        let _ = finisher.join();

        // Forced: no query came first.
        let port = FakePort::new();
        port.instant.store(true, Ordering::SeqCst);
        let mut s = EndSession::default();
        assert!(s.end(
            &*port,
            &FakeBlock::default(),
            true,
            OS,
            Duration::from_secs(10)
        ));
        assert_eq!(port.begins(), [ShutdownReason::OsShutdown]);
        // A path that outlives the wait: Windows ends the process after the answer.
        let port = FakePort::new();
        let mut s = EndSession::default();
        assert!(!s.end(
            &*port,
            &FakeBlock::default(),
            true,
            OS,
            Duration::from_millis(30)
        ));
    }

    /// M10 T23 (§2.5, §12.2, PD-172): the installer's quit request runs the path with `Installer`
    /// and is answered only after the path ended; no block goes up. A later end session joins the
    /// run (its reason does not replace the first).
    #[test]
    fn installer_quit_message_maps_to_installer_reason() {
        let port = FakePort::new();
        let finisher = {
            let port = port.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(150));
                port.finish();
            })
        };
        let mut s = EndSession::default();
        let began = Instant::now();
        assert!(s.installer_quit(&*port, Duration::from_secs(10)));
        assert!(
            began.elapsed() >= Duration::from_millis(150),
            "answered before the end"
        );
        assert!(port.path.ended());
        assert_eq!(port.begins(), [ShutdownReason::Installer]);
        assert!(!s.blocked(), "no session ends: no block");
        let _ = finisher.join();
        // An end session after the request joins the installer's run.
        let block = FakeBlock::default();
        assert!(s.query(&*port, &block, OS, QUERY_WAIT));
        assert_eq!(port.begins(), [ShutdownReason::Installer]);
        assert_eq!(port.starts(), 1);

        // A path that outlives the wait: the answer comes anyway, false.
        let port = FakePort::new();
        let mut s = EndSession::default();
        assert!(!s.installer_quit(&*port, Duration::from_millis(30)));
        assert_eq!(port.begins(), [ShutdownReason::Installer]);
        assert!(!port.path.ended());
    }

    /// `ENDSESSION_CLOSEAPP` (Restart Manager closing the app for an installer; Tauri's
    /// `CheckIfAppIsRunning`) is the installer's reason, alone or with other flags, on the query
    /// and on a forced `WM_ENDSESSION` that no query preceded (L129: `lParam` was not read).
    #[test]
    fn endsession_closeapp_maps_to_installer() {
        const LOGOFF: isize = 0x8000_0000_u32 as isize;
        const CRITICAL: isize = 0x4000_0000;
        for lparam in [1, 1 | CRITICAL, 1 | LOGOFF] {
            assert_eq!(
                end_session_reason(lparam),
                ShutdownReason::Installer,
                "{lparam:#x}"
            );
        }
        let port = FakePort::new();
        port.instant.store(true, Ordering::SeqCst);
        let mut s = EndSession::default();
        let block = FakeBlock::default();
        assert!(s.query(&*port, &block, end_session_reason(1), QUERY_WAIT));
        assert_eq!(port.begins(), [ShutdownReason::Installer]);

        let port = FakePort::new();
        port.instant.store(true, Ordering::SeqCst);
        let mut s = EndSession::default();
        let reason = end_session_reason(ENDSESSION_CLOSEAPP as isize);
        assert!(s.end(
            &*port,
            &FakeBlock::default(),
            true,
            reason,
            Duration::from_secs(10)
        ));
        assert_eq!(port.begins(), [ShutdownReason::Installer]);
    }

    /// A shutdown, logoff or critical end session without `ENDSESSION_CLOSEAPP` stays
    /// `OsShutdown`.
    #[test]
    fn plain_endsession_stays_os_shutdown() {
        const LOGOFF: isize = 0x8000_0000_u32 as isize;
        const CRITICAL: isize = 0x4000_0000;
        for lparam in [0, LOGOFF, CRITICAL, LOGOFF | CRITICAL, 0x2] {
            assert_eq!(
                end_session_reason(lparam),
                ShutdownReason::OsShutdown,
                "{lparam:#x}"
            );
        }
        let port = FakePort::new();
        port.instant.store(true, Ordering::SeqCst);
        let mut s = EndSession::default();
        let block = FakeBlock::default();
        assert!(s.query(&*port, &block, end_session_reason(LOGOFF), QUERY_WAIT));
        assert_eq!(port.begins(), [ShutdownReason::OsShutdown]);
    }

    /// The `!define` value of `name` in `hooks.nsh` (`!define NAME "value"`).
    fn nsh_define<'a>(nsh: &'a str, name: &str) -> Option<&'a str> {
        nsh.lines().find_map(|line| {
            let rest = line.trim().strip_prefix("!define")?.trim_start();
            let (key, value) = rest.split_once(char::is_whitespace)?;
            if key != name {
                return None;
            }
            value.trim().strip_prefix('"')?.strip_suffix('"')
        })
    }

    const HOOKS_NSH: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/windows/hooks.nsh"));

    /// The drain's command as nsExec receives it: the backtick string of the one
    /// `nsExec::ExecToLog /TIMEOUT=` line, `$$` written `$`, `${NAME}` the define's value and
    /// `$SYSDIR` a 19-character System32 path. `None` when the line or a define is missing, or when
    /// the string holds any other NSIS `$` (a variable NSIS would expand into the command).
    fn drain_command(nsh: &str) -> Option<String> {
        let mut lines = nsh
            .lines()
            .filter(|l| l.trim_start().starts_with("nsExec::ExecToLog /TIMEOUT="));
        let line = lines.next()?;
        if lines.next().is_some() {
            return None;
        }
        let raw = line.split_once('`')?.1.rsplit_once('`')?.0;
        let mut out = String::new();
        let mut rest = raw;
        while let Some(i) = rest.find('$') {
            out.push_str(&rest[..i]);
            let tail = &rest[i..];
            rest = if let Some(t) = tail.strip_prefix("$$") {
                out.push('$');
                t
            } else if let Some(t) = tail.strip_prefix("$SYSDIR") {
                out.push_str(r"C:\Windows\System32");
                t
            } else {
                let (name, t) = tail.strip_prefix("${")?.split_once('}')?;
                out.push_str(nsh_define(nsh, name)?);
                t
            };
        }
        out.push_str(rest);
        Some(out)
    }

    /// The `[[bin]]` names of a Cargo manifest.
    fn cargo_bins(toml: &str) -> Vec<&str> {
        let mut bins = Vec::new();
        let mut in_bin = false;
        for line in toml.lines().map(str::trim) {
            if line.starts_with('[') {
                in_bin = line == "[[bin]]";
                continue;
            }
            let value = line
                .strip_prefix("name")
                .and_then(|r| r.trim_start().strip_prefix('='))
                .and_then(|v| v.trim().strip_prefix('"')?.strip_suffix('"'));
            if let (true, Some(v)) = (in_bin, value) {
                bins.push(v);
            }
        }
        bins
    }

    /// I-1 (T23 review, PD-172): the drain selects a process by its full image path, the install
    /// directory AND one of the images the installer ships (`tauri.conf.json` `mainBinaryName` and
    /// the Cargo `[[bin]]`s), never by directory alone (a `/D=C:\Tools` install must not kill the
    /// other programs there) nor by name alone. The app's window is matched the same way.
    #[test]
    fn drain_selects_atlas_duck_images_in_instdir_only() {
        let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
        let conf: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tauri.conf.json"
        )))
        .expect("tauri.conf.json");
        let main = conf["mainBinaryName"].as_str().expect("mainBinaryName");
        let mut shipped: Vec<String> = cargo_bins(manifest)
            .into_iter()
            .chain([main])
            .map(|b| format!("{b}.exe"))
            .collect();
        shipped.sort();
        shipped.dedup();
        assert_eq!(shipped.len(), 3, "{shipped:?}");
        let images = nsh_define(HOOKS_NSH, "ATLAS_DUCK_IMAGES").expect("ATLAS_DUCK_IMAGES");
        let mut listed: Vec<String> = images
            .split(',')
            .map(|i| i.strip_prefix('\'')?.strip_suffix('\'').map(str::to_owned))
            .collect::<Option<_>>()
            .expect("a PowerShell list of quoted names");
        listed.sort();
        assert_eq!(listed, shipped);
        assert_eq!(
            nsh_define(HOOKS_NSH, "ATLAS_DUCK_APP_IMAGE"),
            Some(format!("{main}.exe").as_str())
        );

        let cmd = drain_command(HOOKS_NSH).expect("the drain command");
        assert!(
            cmd.contains(&format!(r"$f=@({images}|%{{$d+'\'+$_}});")),
            "the full image paths: {cmd}"
        );
        assert!(
            cmd.contains(
                "$l=@($p|?{$s -notcontains $_.ProcessId -and $f -contains $_.ExecutablePath});"
            ),
            "selection by full image path only: {cmd}"
        );
        assert!(!cmd.contains("LastIndexOf"), "no directory-only selection");
        // The window: its process image is the app's in $INSTDIR (no directory-only match).
        assert_eq!(
            HOOKS_NSH
                .matches(r#"$2 == "$INSTDIR\${ATLAS_DUCK_APP_IMAGE}""#)
                .count(),
            2
        );
        assert!(!HOOKS_NSH.contains("GetParent"));
    }

    /// I-2, I-3, M-4 (T23 review): the drain fails closed (any error before the kill ends the run,
    /// exit 1, nothing killed), is bounded (nsExec's timeout, above the wait for the app, which is
    /// above the app's own path), and its expanded command fits NSIS's 1024-character strings,
    /// which the build checks too.
    #[test]
    fn drain_command_fails_closed_is_bounded_and_fits() {
        let cmd = drain_command(HOOKS_NSH).expect("the drain command");
        let head = concat!(
            r#""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe""#,
            r#" -NoLogo -NoProfile -NonInteractive -Command ""#
        );
        let script = cmd
            .strip_prefix(head)
            .and_then(|s| s.strip_suffix('"'))
            .expect("powershell.exe -Command \"...\"");
        assert!(!script.contains('"'), "one quoted -Command argument");
        assert!(
            script.starts_with("$ErrorActionPreference='Stop';"),
            "fail closed from the first statement: {script}"
        );
        assert!(cmd.len() < 1000, "{} characters", cmd.len());
        assert!(
            HOOKS_NSH.replace("\r\n", "\n").contains(concat!(
                "!if ${NSIS_MAX_STRLEN} < 1024\n",
                "  !error \"atlas-duck: the drain's PowerShell command needs NSIS_MAX_STRLEN >= 1024\"\n",
                "!endif\n"
            )),
            "the build-time length guard"
        );

        // `!define NAME 123`
        let ms = |name: &str| -> u64 {
            HOOKS_NSH
                .lines()
                .find_map(|l| {
                    l.trim()
                        .strip_prefix("!define ")?
                        .strip_prefix(name)?
                        .strip_prefix(' ')
                })
                .and_then(|v| v.trim().parse().ok())
                .expect(name)
        };
        let drain = ms("ATLAS_DUCK_DRAIN_MS");
        let timeout = ms("ATLAS_DUCK_DRAIN_TIMEOUT_MS");
        assert!(super::super::PATH_WAIT.as_millis() < u128::from(drain));
        assert!(
            drain + 30_000 <= timeout,
            "{drain} ms wait, {timeout} ms bound"
        );
        let exec = HOOKS_NSH
            .lines()
            .filter(|l| l.contains("nsExec::"))
            .filter(|l| l.contains("powershell.exe"))
            .collect::<Vec<_>>();
        assert_eq!(exec.len(), 1);
        assert!(
            exec[0]
                .trim_start()
                .starts_with("nsExec::ExecToLog /TIMEOUT=${ATLAS_DUCK_DRAIN_TIMEOUT_MS} `"),
            "{}",
            exec[0]
        );

        // M-3: the child's module path is the system's only, set right before the run and unset
        // after it (no module from the user's Documents folder in an elevated drain).
        let lines: Vec<&str> = HOOKS_NSH.lines().map(str::trim).collect();
        let at = |text: &str| {
            let found: Vec<usize> = (0..lines.len()).filter(|&i| lines[i] == text).collect();
            assert_eq!(found.len(), 1, "{text}");
            found[0]
        };
        let set = at(
            r#"System::Call 'kernel32::SetEnvironmentVariableW(w "PSModulePath", w "$SYSDIR\WindowsPowerShell\v1.0\Modules")'"#,
        );
        let unset =
            at(r#"System::Call 'kernel32::SetEnvironmentVariableW(w "PSModulePath", p 0)'"#);
        let run = lines
            .iter()
            .position(|l| l.starts_with("nsExec::ExecToLog /TIMEOUT="))
            .expect("the run");
        assert!(set < run && run < unset, "{set} < {run} < {unset}");

        // The expansion itself: an NSIS variable left in the command is refused.
        let stray = HOOKS_NSH.replacen("$$d=$$env:", "$$d=$INSTDIR;$$env:", 1);
        assert_eq!(drain_command(&stray), None);
        assert!(drain_command("nsExec::ExecToLog /TIMEOUT=1 `a $$b ${X}`").is_none());
        assert_eq!(
            drain_command("!define X \"x\"\nnsExec::ExecToLog /TIMEOUT=1 `a $$b ${X} $SYSDIR`")
                .as_deref(),
            Some(r"a $b x C:\Windows\System32")
        );
    }

    /// M-1 (T23 review): the installer waits for the app's process only when the send succeeded
    /// and the app answered [`INSTALLER_QUIT_TAKEN`]; a failed send or `DefWindowProcW`'s 0 (the
    /// app could not register the message) skips the wait.
    #[test]
    fn the_quit_answer_matches_hooks_nsh() {
        let send = HOOKS_NSH
            .lines()
            .find(|l| l.contains("user32::SendMessageTimeoutW("))
            .expect("the send");
        assert!(
            send.trim_end().ends_with("*p .r7) p .r2'"),
            "answer in $7, result in $2: {send}"
        );
        let wait = format!("${{If}} $2 <> 0\n      ${{AndIf}} $7 = {INSTALLER_QUIT_TAKEN}\n");
        assert!(HOOKS_NSH.replace("\r\n", "\n").contains(&wait), "{wait}");
    }

    /// The installer finds the window by its class and sends the registered message by its name:
    /// one string each, shared by this file and `windows/hooks.nsh`.
    #[test]
    fn endsession_class_name_matches_hooks_nsh() {
        let nsh = HOOKS_NSH;
        assert_eq!(
            nsh_define(nsh, "ATLAS_DUCK_ENDSESSION_CLASS"),
            Some(WINDOW_CLASS)
        );
        assert_eq!(
            nsh_define(nsh, "ATLAS_DUCK_INSTALLER_QUIT_MESSAGE"),
            Some(INSTALLER_QUIT_MESSAGE)
        );
        // Each is defined once, and the hooks use the defines, not a second copy of the strings.
        for value in [WINDOW_CLASS, INSTALLER_QUIT_MESSAGE] {
            assert_eq!(nsh.matches(&format!("\"{value}\"")).count(), 1, "{value}");
        }
        assert_eq!(nsh_define("!define X \"y\"", "X"), Some("y"));
        assert_eq!(nsh_define("!define XY \"y\"", "X"), None);
    }
}
