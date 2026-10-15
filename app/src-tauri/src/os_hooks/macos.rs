//! macOS quit hook (§2.5, §15 V20, L83, M6 T29): `applicationShouldTerminate:` on the app delegate.
//! tao's delegate class has no such method (tao 0.37 `app_delegate.rs`), so AppKit's `terminate:`
//! (Cmd+Q and the app menu's Quit, the Dock's Quit, a quit Apple event, the logout's quit event)
//! went straight to `applicationWillTerminate:` and ended the process without the shutdown path.
//! The method is added to the delegate's class at runtime (raw Objective-C runtime calls: the app
//! crate links no Objective-C crate). It answers `NSTerminateLater` and begins the path; the reply
//! (`replyToApplicationShouldTerminate:YES`) runs on the main thread at the end of the path, and
//! AppKit then ends the process. The decisions ([`should_terminate`], [`quit_reason`]) are plain
//! Rust that every OS compiles and tests; only the runtime glue is macOS code.
//!
//! The reason: a quit Apple event that carries a logout, restart or shutdown reason
//! (`kAEQuitReason`) is `OsShutdown`; anything else (Cmd+Q has no Apple event, the Dock's Quit
//! sends one without a reason) is `Quit`.
//!
//! PD-83: AppKit sets no bound on `NSTerminateLater`; at logout the login window gives up on an
//! app that does not quit and cancels the logout, and a forced restart ends the process, whose
//! write on the wire is then reconciled `outcome_unknown {crash}` at the next start.

use atlas_duck_core::ShutdownReason;

use super::ShutdownPort;

/// `NSTerminateNow`.
pub const NS_TERMINATE_NOW: usize = 1;
/// `NSTerminateLater`.
pub const NS_TERMINATE_LATER: usize = 2;

/// `kCoreEventClass` ('aevt').
pub const K_CORE_EVENT_CLASS: u32 = u32::from_be_bytes(*b"aevt");
/// `kAEQuitApplication` ('quit').
pub const K_AE_QUIT_APPLICATION: u32 = u32::from_be_bytes(*b"quit");
/// `kAEQuitReason` ('why?'): the attribute that says why a quit event was sent.
pub const K_AE_QUIT_REASON: u32 = u32::from_be_bytes(*b"why?");
/// The `kAEQuitReason` values of a session end: `kAELogOut`, `kAEReallyLogOut`,
/// `kAEShowRestartDialog`, `kAEShowShutdownDialog`, `kAERestart`, `kAEShutDown`.
pub const SESSION_END_REASONS: [u32; 6] = [
    u32::from_be_bytes(*b"logo"),
    u32::from_be_bytes(*b"rlgo"),
    u32::from_be_bytes(*b"rrst"),
    u32::from_be_bytes(*b"rsdn"),
    u32::from_be_bytes(*b"rest"),
    u32::from_be_bytes(*b"shut"),
];

/// The Apple event AppKit is handling when it asks whether to terminate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppleEvent {
    pub event_class: u32,
    pub event_id: u32,
    /// The `kAEQuitReason` attribute's code, if the event has one.
    pub quit_reason: Option<u32>,
}

/// The path's reason for a `terminate:` during `current` (none for Cmd+Q and the menu).
pub fn quit_reason(current: Option<AppleEvent>) -> ShutdownReason {
    match current {
        Some(AppleEvent {
            event_class: K_CORE_EVENT_CLASS,
            event_id: K_AE_QUIT_APPLICATION,
            quit_reason: Some(why),
        }) if SESSION_END_REASONS.contains(&why) => ShutdownReason::OsShutdown,
        _ => ShutdownReason::Quit,
    }
}

/// `applicationShouldTerminate:`. `defer_reply` keeps the reply for the end of the path (false:
/// the path already ended, so the app may go at once). Otherwise the path begins with `reason`
/// (or is joined) and AppKit waits for the reply.
pub fn should_terminate(
    port: &dyn ShutdownPort,
    reason: ShutdownReason,
    defer_reply: &dyn Fn() -> bool,
) -> usize {
    if !defer_reply() {
        return NS_TERMINATE_NOW;
    }
    port.begin(reason);
    NS_TERMINATE_LATER
}

#[cfg(target_os = "macos")]
pub use self::runtime::{install, reply_terminate};

#[cfg(target_os = "macos")]
mod runtime {
    use std::ffi::{CStr, c_char, c_void};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::{Arc, OnceLock};

    use super::super::{LOG_EVENT_OS_END_SESSION, ShutdownPort};
    use super::{AppleEvent, K_AE_QUIT_REASON, NS_TERMINATE_NOW, quit_reason, should_terminate};

    type Id = *mut c_void;
    type Sel = *mut c_void;
    type Class = *mut c_void;
    /// `IMP`: what `class_addMethod` takes (cast from the method's real signature).
    type Imp = unsafe extern "C" fn();

    /// `BOOL`: `bool` on arm64, `signed char` on x86_64.
    #[cfg(target_arch = "aarch64")]
    type ObjcBool = bool;
    #[cfg(not(target_arch = "aarch64"))]
    type ObjcBool = i8;

    #[cfg(target_arch = "aarch64")]
    const YES: ObjcBool = true;
    #[cfg(not(target_arch = "aarch64"))]
    const YES: ObjcBool = 1;

    #[link(name = "objc", kind = "dylib")]
    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> Class;
        fn sel_registerName(name: *const c_char) -> Sel;
        fn object_getClass(obj: Id) -> Class;
        fn class_addMethod(cls: Class, name: Sel, imp: Imp, types: *const c_char) -> ObjcBool;
        /// Called through a pointer cast to each message's own signature (never variadic).
        fn objc_msgSend();
    }

    /// The `defer_reply` of [`super::should_terminate`] (`os_hooks::install_macos`).
    pub type DeferReply = Box<dyn Fn() -> bool + Send + Sync>;

    struct Hook {
        port: Arc<dyn ShutdownPort>,
        defer_reply: DeferReply,
    }

    static HOOK: OnceLock<Hook> = OnceLock::new();

    fn sel(name: &CStr) -> Sel {
        // SAFETY: `name` is NUL-terminated; selectors are registered for the process lifetime.
        unsafe { sel_registerName(name.as_ptr()) }
    }

    fn class(name: &CStr) -> Class {
        // SAFETY: `name` is NUL-terminated; null when no such class is loaded.
        unsafe { objc_getClass(name.as_ptr()) }
    }

    // The message senders: each casts `objc_msgSend` to the exact signature of the method it
    // sends (arm64 requires it). Callers pass a live receiver or check for null first.

    /// `[recv sel]` returning an object (or nil).
    unsafe fn send_id(recv: Id, sel: Sel) -> Id {
        // SAFETY: `objc_msgSend` with the receiver and selector of a method that takes no
        // argument and returns an object.
        unsafe {
            let f = std::mem::transmute::<
                unsafe extern "C" fn(),
                unsafe extern "C" fn(Id, Sel) -> Id,
            >(objc_msgSend);
            f(recv, sel)
        }
    }

    /// `[recv sel]` returning a `FourCharCode`/`OSType` (32 bits).
    unsafe fn send_u32(recv: Id, sel: Sel) -> u32 {
        // SAFETY: as in `send_id`, for a method that returns a 32-bit code.
        unsafe {
            let f = std::mem::transmute::<
                unsafe extern "C" fn(),
                unsafe extern "C" fn(Id, Sel) -> u32,
            >(objc_msgSend);
            f(recv, sel)
        }
    }

    /// `[recv sel:code]` returning an object (or nil).
    unsafe fn send_id_with_u32(recv: Id, sel: Sel, code: u32) -> Id {
        // SAFETY: as in `send_id`, for a method that takes one 32-bit code.
        unsafe {
            let f = std::mem::transmute::<
                unsafe extern "C" fn(),
                unsafe extern "C" fn(Id, Sel, u32) -> Id,
            >(objc_msgSend);
            f(recv, sel, code)
        }
    }

    /// `[recv sel:object]` returning nothing.
    unsafe fn send_with_id(recv: Id, sel: Sel, arg: Id) {
        // SAFETY: as in `send_id`, for a method that takes one object and returns void.
        unsafe {
            let f = std::mem::transmute::<unsafe extern "C" fn(), unsafe extern "C" fn(Id, Sel, Id)>(
                objc_msgSend,
            );
            f(recv, sel, arg)
        }
    }

    /// `[recv sel:flag]` returning nothing.
    unsafe fn send_with_bool(recv: Id, sel: Sel, flag: ObjcBool) {
        // SAFETY: as in `send_id`, for a method that takes one `BOOL` and returns void.
        unsafe {
            let f = std::mem::transmute::<
                unsafe extern "C" fn(),
                unsafe extern "C" fn(Id, Sel, ObjcBool),
            >(objc_msgSend);
            f(recv, sel, flag)
        }
    }

    /// `[recv sel]` returning a `BOOL`.
    unsafe fn send_bool(recv: Id, sel: Sel) -> bool {
        // SAFETY: as in `send_id`, for a method that takes no argument and returns a `BOOL`.
        let flag = unsafe {
            let f = std::mem::transmute::<
                unsafe extern "C" fn(),
                unsafe extern "C" fn(Id, Sel) -> ObjcBool,
            >(objc_msgSend);
            f(recv, sel)
        };
        flag == YES
    }

    /// `NSApp` (`[NSApplication sharedApplication]`); null when AppKit is not loaded.
    fn shared_application() -> Id {
        let cls = class(c"NSApplication");
        if cls.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: `cls` is the NSApplication class; `sharedApplication` returns the app object.
        unsafe { send_id(cls, sel(c"sharedApplication")) }
    }

    /// True on the main thread (`[NSThread isMainThread]`).
    fn on_main_thread() -> bool {
        let cls = class(c"NSThread");
        // SAFETY: `cls` is the NSThread class (checked); `isMainThread` returns a `BOOL`.
        !cls.is_null() && unsafe { send_bool(cls, sel(c"isMainThread")) }
    }

    /// The Apple event AppKit is handling now, if any. Main thread only.
    fn current_apple_event() -> Option<AppleEvent> {
        let manager_class = class(c"NSAppleEventManager");
        if manager_class.is_null() {
            return None;
        }
        // SAFETY: each receiver is checked for nil before it is sent anything; the selectors are
        // NSAppleEventManager's and NSAppleEventDescriptor's own, with their documented
        // signatures (`eventClass`/`eventID`/`enumCodeValue` return 32-bit codes,
        // `attributeDescriptorForKeyword:` takes one).
        unsafe {
            let manager = send_id(manager_class, sel(c"sharedAppleEventManager"));
            if manager.is_null() {
                return None;
            }
            let event = send_id(manager, sel(c"currentAppleEvent"));
            if event.is_null() {
                return None;
            }
            let why = send_id_with_u32(
                event,
                sel(c"attributeDescriptorForKeyword:"),
                K_AE_QUIT_REASON,
            );
            Some(AppleEvent {
                event_class: send_u32(event, sel(c"eventClass")),
                event_id: send_u32(event, sel(c"eventID")),
                quit_reason: (!why.is_null()).then(|| send_u32(why, sel(c"enumCodeValue"))),
            })
        }
    }

    /// The added `applicationShouldTerminate:` (AppKit calls it on the main thread).
    extern "C" fn application_should_terminate(_this: Id, _cmd: Sel, _sender: Id) -> usize {
        // A panic must not unwind into AppKit: it answers "now", and the run loop's fallback
        // (`os_hooks::on_loop_exit`) runs the path before the process ends.
        catch_unwind(AssertUnwindSafe(|| {
            let Some(hook) = HOOK.get() else {
                return NS_TERMINATE_NOW;
            };
            let reason = quit_reason(current_apple_event());
            tracing::info!(event = LOG_EVENT_OS_END_SESSION, reason = "terminate");
            should_terminate(&*hook.port, reason, &*hook.defer_reply)
        }))
        .unwrap_or(NS_TERMINATE_NOW)
    }

    /// Adds `applicationShouldTerminate:` to the class of `NSApp`'s delegate (tao's), on the main
    /// thread (`setup`). `Err`: the step that failed (the app runs on; the run loop's fallback
    /// stays).
    pub fn install(
        port: Arc<dyn ShutdownPort>,
        defer_reply: DeferReply,
    ) -> Result<(), &'static str> {
        if !on_main_thread() {
            return Err("not_main_thread");
        }
        if HOOK.set(Hook { port, defer_reply }).is_err() {
            return Err("installed_twice");
        }
        let app = shared_application();
        if app.is_null() {
            return Err("no_application");
        }
        // SAFETY: `app` is NSApp (checked); `delegate` returns its delegate or nil.
        let delegate = unsafe { send_id(app, sel(c"delegate")) };
        if delegate.is_null() {
            return Err("no_delegate");
        }
        // SAFETY: `delegate` is a live object (NSApp's delegate, which tao keeps alive).
        let cls = unsafe { object_getClass(delegate) };
        if cls.is_null() {
            return Err("no_delegate_class");
        }
        // SAFETY: `application_should_terminate` has the C signature of the method ("Q@:@":
        // NSUInteger return, self, _cmd, sender); `class_addMethod` only takes it as an untyped
        // IMP. It refuses (NO) when the class already has the method; nothing is replaced.
        let added = unsafe {
            let imp = std::mem::transmute::<extern "C" fn(Id, Sel, Id) -> usize, Imp>(
                application_should_terminate,
            );
            class_addMethod(
                cls,
                sel(c"applicationShouldTerminate:"),
                imp,
                c"Q@:@".as_ptr(),
            )
        };
        if added != YES {
            return Err("add_method");
        }
        // NSApp may have looked at what the delegate answers when it was set: set it again so the
        // new method is seen. NSApp does not retain its delegate (tao keeps it alive).
        // SAFETY: `app` and `delegate` as above; `setDelegate:` takes one object (nil allowed).
        unsafe {
            send_with_id(app, sel(c"setDelegate:"), std::ptr::null_mut());
            send_with_id(app, sel(c"setDelegate:"), delegate);
        }
        Ok(())
    }

    /// `[NSApp replyToApplicationShouldTerminate:YES]`: AppKit ends the process. Main thread only
    /// (anywhere else it does nothing).
    pub fn reply_terminate() {
        if !on_main_thread() {
            return;
        }
        let app = shared_application();
        if app.is_null() {
            return;
        }
        // SAFETY: `app` is NSApp (checked), on the main thread; the method takes one `BOOL`.
        unsafe { send_with_bool(app, sel(c"replyToApplicationShouldTerminate:"), YES) };
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use atlas_duck_core::ShutdownReason;

    use super::super::fake::FakePort;
    use super::*;

    fn quit_event(why: Option<&[u8; 4]>) -> Option<AppleEvent> {
        Some(AppleEvent {
            event_class: K_CORE_EVENT_CLASS,
            event_id: K_AE_QUIT_APPLICATION,
            quit_reason: why.map(|w| u32::from_be_bytes(*w)),
        })
    }

    #[test]
    fn four_char_codes() {
        assert_eq!(K_CORE_EVENT_CLASS, 0x6165_7674);
        assert_eq!(K_AE_QUIT_APPLICATION, 0x7175_6974);
        assert_eq!(K_AE_QUIT_REASON, 0x7768_793f);
        assert_eq!((NS_TERMINATE_NOW, NS_TERMINATE_LATER), (1, 2));
    }

    /// L83: Cmd+Q (no Apple event) and the Dock's Quit (a quit event without a reason) are `Quit`;
    /// the logout's, restart's and shutdown's quit events are `OsShutdown`.
    #[test]
    fn cmd_q_is_quit_and_a_logout_is_os_shutdown() {
        assert_eq!(quit_reason(None), ShutdownReason::Quit);
        assert_eq!(quit_reason(quit_event(None)), ShutdownReason::Quit);
        for why in [b"logo", b"rlgo", b"rrst", b"rsdn", b"rest", b"shut"] {
            assert_eq!(
                quit_reason(quit_event(Some(why))),
                ShutdownReason::OsShutdown
            );
        }
        assert_eq!(quit_reason(quit_event(Some(b"abcd"))), ShutdownReason::Quit);
        // Another event that happens to carry the attribute.
        let other = AppleEvent {
            event_class: K_CORE_EVENT_CLASS,
            event_id: u32::from_be_bytes(*b"oapp"),
            quit_reason: Some(u32::from_be_bytes(*b"shut")),
        };
        assert_eq!(quit_reason(Some(other)), ShutdownReason::Quit);
    }

    /// I-40 (macOS half, injected port): `applicationShouldTerminate:` keeps the reply for the end
    /// of the path, begins the path once and answers `NSTerminateLater`; a second terminate joins
    /// the run; after the end it answers `NSTerminateNow`.
    #[test]
    fn i40_os_hook_runs_shutdown_path() {
        let port = FakePort::new();
        let replies = Cell::new(0u32);
        let defer = || {
            // What `os_hooks::install_macos` does: the reply runs at the end of the path.
            let deferred = port.path.before_exit(Box::new(|| {}));
            if deferred {
                replies.set(replies.get() + 1);
            }
            deferred
        };
        let reason = quit_reason(quit_event(Some(b"shut")));
        assert_eq!(should_terminate(&*port, reason, &defer), NS_TERMINATE_LATER);
        assert_eq!(port.begins(), [ShutdownReason::OsShutdown]);
        assert_eq!(replies.get(), 1);
        assert!(!port.path.ended());
        // Cmd+Q while it runs: joined, not restarted, the first reason stays.
        assert_eq!(
            should_terminate(&*port, quit_reason(None), &defer),
            NS_TERMINATE_LATER
        );
        assert_eq!(port.starts(), 1);
        assert_eq!(
            port.path.ticket().map(|t| t.reason()),
            Some(ShutdownReason::OsShutdown)
        );
        port.finish();
        assert_eq!(should_terminate(&*port, reason, &defer), NS_TERMINATE_NOW);
        assert_eq!(port.begins().len(), 2, "no begin after the end");
    }

    /// The reply really runs at the end of the path, after the ticket ended.
    #[test]
    fn the_reply_waits_for_the_end_of_the_path() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let port = FakePort::new();
        let replied = Arc::new(AtomicBool::new(false));
        let defer = || {
            let replied = replied.clone();
            port.path
                .before_exit(Box::new(move || replied.store(true, Ordering::SeqCst)))
        };
        assert_eq!(
            should_terminate(&*port, ShutdownReason::Quit, &defer),
            NS_TERMINATE_LATER
        );
        assert!(!replied.load(Ordering::SeqCst));
        port.finish();
        assert!(replied.load(Ordering::SeqCst));
        assert!(port.path.ended());
    }
}
