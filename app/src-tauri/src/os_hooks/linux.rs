//! Linux logind hook (§2.5 step 4, §15 V20, M6 T29): a `delay` inhibitor lock for `shutdown`,
//! taken at start (`org.freedesktop.login1.Manager.Inhibit`) and held until the end of the
//! shutdown path, which `PrepareForShutdown(true)` begins with `OsShutdown`. The system bus is
//! used with the existing `zbus` (blocking API) on a thread of its own, as `secret_service.rs`
//! does. No system bus, no logind or a refused lock (polkit) is logged and the app runs on;
//! `SIGTERM` (`os_hooks::spawn_signal_hooks`) still runs the path. The decisions
//! ([`follow_logind`]) are plain Rust that every OS compiles and tests; only the bus glue is Linux
//! code.
//!
//! PD-83: logind waits for a delay lock at most `InhibitDelayMaxSec` (logind.conf, 5 s by
//! default), then the shutdown goes on: systemd sends `SIGTERM` (the path is already running) and
//! `SIGKILL` after the unit's stop timeout. A write still on the wire is then reconciled
//! `outcome_unknown {crash}` at the next start.

use std::time::Duration;

use atlas_duck_core::ShutdownReason;

use super::ShutdownPort;

/// The inhibitor's `who`.
pub const INHIBIT_WHO: &str = "atlas-duck";
/// The inhibitor's `why`. Plan text (M10 T36, M6 M-8; in no spec sentence): the lock is held from
/// start, so `systemd-inhibit --list` shows it while the app is idle, and it must not claim a
/// write (Windows' `BLOCK_REASON` does, but only while one is on the wire).
pub const INHIBIT_WHY: &str = "atlas-duck is finishing audit work";

/// Follows logind's `PrepareForShutdown` signals with the delay lock `lock` held: the first
/// `true` begins the path with `OsShutdown` (or joins it) and waits for its end, at most `wait`;
/// then the lock is released (dropped). `false` (a shutdown was cancelled) changes nothing. When
/// the signals end (the bus went away) the lock is released too. True when the path ended.
pub fn follow_logind<L>(
    port: &dyn ShutdownPort,
    lock: L,
    signals: impl IntoIterator<Item = bool>,
    wait: Duration,
) -> bool {
    let mut ended = false;
    for start in signals {
        if start {
            ended = port.begin(ShutdownReason::OsShutdown).wait_timeout(wait);
            break;
        }
    }
    drop(lock);
    ended
}

/// Marks `fd` close-on-exec, so no child process inherits it. The inhibitor lock arrives through
/// `recvmsg` without `MSG_CMSG_CLOEXEC` (zbus), and a child that kept it (`xdg-open` and the
/// browser it starts, the CLI install's `sh`, the tray host) would hold the lock after the app
/// quit: every later shutdown would wait `InhibitDelayMaxSec` for it. A child forked by another
/// thread between `recvmsg` and this call can still inherit it; nothing closes that gap.
#[cfg(unix)]
pub fn close_on_exec(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let raw = fd.as_raw_fd();
    // SAFETY: `raw` is a live descriptor, borrowed for the whole call; `F_GETFD` and `F_SETFD`
    // read and set only its descriptor flags.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub use self::logind::install;

#[cfg(target_os = "linux")]
mod logind {
    use std::os::fd::AsFd;
    use std::sync::Arc;

    use super::super::{LOG_EVENT_OS_END_SESSION, LOG_EVENT_OS_HOOK_FAILED, PATH_WAIT};
    use super::{INHIBIT_WHO, INHIBIT_WHY, ShutdownPort, close_on_exec, follow_logind};

    const THREAD_NAME: &str = "atlas-duck-logind";
    const LOGIND: &str = "org.freedesktop.login1";
    const LOGIND_PATH: &str = "/org/freedesktop/login1";
    const MANAGER: &str = "org.freedesktop.login1.Manager";

    fn failed(step: &'static str) {
        tracing::warn!(
            event = LOG_EVENT_OS_HOOK_FAILED,
            reason = "logind",
            error_class = step
        );
    }

    /// Starts the logind thread (it lives as long as the process or the bus).
    pub fn install(port: Arc<dyn ShutdownPort>) {
        let spawned = std::thread::Builder::new()
            .name(THREAD_NAME.to_owned())
            .spawn(move || {
                if let Err(step) = follow(&*port) {
                    failed(step);
                }
            });
        if spawned.is_err() {
            failed("thread");
        }
    }

    fn follow(port: &dyn ShutdownPort) -> Result<(), &'static str> {
        let connection = zbus::blocking::Connection::system().map_err(|_| "system_bus")?;
        let manager = zbus::blocking::Proxy::new(&connection, LOGIND, LOGIND_PATH, MANAGER)
            .map_err(|_| "proxy")?;
        // Subscribed before the lock is taken, so no signal falls between the two.
        let signals = manager
            .receive_signal("PrepareForShutdown")
            .map_err(|_| "subscribe")?;
        // The lock is the file descriptor logind returns; it is released when it is closed.
        let lock: zbus::zvariant::OwnedFd = manager
            .call("Inhibit", &("shutdown", INHIBIT_WHO, INHIBIT_WHY, "delay"))
            .map_err(|_| "inhibit")?;
        // Without the flag the lock is still held for the path; only a child could keep it longer.
        if close_on_exec(lock.as_fd()).is_err() {
            failed("cloexec");
        }
        let starts = signals.filter_map(|message| message.body().deserialize::<bool>().ok());
        let starts = starts.inspect(|start| {
            if *start {
                tracing::info!(
                    event = LOG_EVENT_OS_END_SESSION,
                    reason = "prepare_for_shutdown"
                );
            }
        });
        if !follow_logind(port, lock, starts, PATH_WAIT) {
            failed("path_wait_expired");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use atlas_duck_core::ShutdownReason;

    use super::super::fake::FakePort;
    use super::*;

    /// The lock: released when dropped.
    struct FakeLock(Arc<AtomicBool>);

    impl Drop for FakeLock {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// I-40 (Linux half, injected port): `PrepareForShutdown(true)` begins the path once with
    /// `OsShutdown`; the delay lock is held while the write is on the wire and released only
    /// after the path ended.
    #[test]
    fn i40_os_hook_runs_shutdown_path() {
        let port = FakePort::new();
        port.write.store(true, Ordering::SeqCst);
        let released = Arc::new(AtomicBool::new(false));
        let watcher = {
            let (port, released) = (port.clone(), released.clone());
            std::thread::spawn(move || {
                // While the path runs the lock is held.
                std::thread::sleep(Duration::from_millis(150));
                let held_during_write = port.write_in_flight() && !released.load(Ordering::SeqCst);
                port.finish();
                held_during_write
            })
        };
        let began = Instant::now();
        assert!(follow_logind(
            &*port,
            FakeLock(released.clone()),
            [false, true, true],
            Duration::from_secs(10)
        ));
        assert!(began.elapsed() >= Duration::from_millis(150));
        assert_eq!(
            watcher.join().ok(),
            Some(true),
            "the lock was held during the write"
        );
        assert!(released.load(Ordering::SeqCst), "released after the end");
        assert_eq!(port.begins(), [ShutdownReason::OsShutdown], "one begin");
    }

    #[test]
    fn a_cancelled_shutdown_or_a_lost_bus_begins_nothing() {
        let port = FakePort::new();
        let released = Arc::new(AtomicBool::new(false));
        assert!(!follow_logind(
            &*port,
            FakeLock(released.clone()),
            [false, false],
            Duration::from_secs(10)
        ));
        assert!(port.begins().is_empty());
        assert!(
            released.load(Ordering::SeqCst),
            "the bus went away: nothing to hold for"
        );
        // A path that outlives logind's wait: the lock goes anyway.
        let port = FakePort::new();
        let released = Arc::new(AtomicBool::new(false));
        assert!(!follow_logind(
            &*port,
            FakeLock(released.clone()),
            [true],
            Duration::from_millis(30)
        ));
        assert!(released.load(Ordering::SeqCst));
        assert_eq!(INHIBIT_WHO, "atlas-duck");
    }

    /// M10 T36 (M6 M-8): the lock is held from start, so `systemd-inhibit --list` shows its text
    /// while the app is idle: it claims no write (it was Windows' "finishing an approved write").
    #[test]
    fn linux_inhibitor_text_claims_no_write() {
        assert_eq!(INHIBIT_WHY, "atlas-duck is finishing audit work");
        for word in ["write", "approved", "sending", "request"] {
            assert!(!INHIBIT_WHY.contains(word), "{INHIBIT_WHY}");
        }
        assert_ne!(INHIBIT_WHY, super::super::windows::BLOCK_REASON);
    }

    /// The lock's descriptor is close-on-exec after `close_on_exec`. `dup` makes a descriptor
    /// without the flag, as `recvmsg` does for the lock.
    #[cfg(unix)]
    #[test]
    fn the_lock_is_close_on_exec() {
        use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
        let file = std::fs::File::open("/dev/null").expect("/dev/null");
        // SAFETY: `file` is open; `dup` returns a new descriptor (or -1, checked below).
        let raw = unsafe { libc::dup(file.as_raw_fd()) };
        assert!(raw >= 0, "dup");
        // SAFETY: `raw` is the new descriptor `dup` returned; nothing else owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: `fd` is open; `F_GETFD` reads its descriptor flags.
        let flags = || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags() & libc::FD_CLOEXEC, 0, "dup leaves the flag off");
        assert!(close_on_exec(fd.as_fd()).is_ok());
        assert_eq!(flags() & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    }
}
