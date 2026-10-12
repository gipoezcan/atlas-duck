//! Interrupts during a connected wait (§4.1, PD-16).
//!
//! `Guard` registers the process's interrupt handlers (Unix: SIGINT, SIGTERM, SIGHUP; Windows:
//! Ctrl-C, Ctrl-Break, console close) and, on Unix, also treats a hung-up stdout as an interrupt
//! (polled every 500 ms). Handlers exist only for the commands that wait (`op`, `call`,
//! `script run`, `await`): the short calls keep the default signal behaviour. An interrupt never
//! cancels a request; what is printed instead is decided by `connected`.

use std::future::Future;
use std::io;
use std::pin::Pin;
#[cfg(unix)]
use std::time::Duration;

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Where interrupts come from: the real `Guard`, a never-firing source, or a test double.
pub(crate) trait Interrupts {
    /// Completes when the process was asked to stop (or stdout hung up). Cancel-safe.
    fn next(&mut self) -> BoxFuture<'_, ()>;
}

/// No interrupt source: the command keeps the default signal behaviour.
pub(crate) struct Never;

impl Interrupts for Never {
    fn next(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
}

/// Hang-up poll period on Unix (PD-16).
#[cfg(unix)]
const HANGUP_POLL: Duration = Duration::from_millis(500);

#[cfg(unix)]
pub(crate) struct Guard {
    int: tokio::signal::unix::Signal,
    term: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
}

#[cfg(windows)]
pub(crate) struct Guard {
    c: tokio::signal::windows::CtrlC,
    brk: tokio::signal::windows::CtrlBreak,
    close: tokio::signal::windows::CtrlClose,
}

#[cfg(not(any(unix, windows)))]
pub(crate) struct Guard;

impl Guard {
    /// Registers the handlers; call inside the runtime, before connecting.
    #[cfg(unix)]
    pub(crate) fn install() -> io::Result<Guard> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Guard {
            int: signal(SignalKind::interrupt())?,
            term: signal(SignalKind::terminate())?,
            hup: signal(SignalKind::hangup())?,
        })
    }

    #[cfg(windows)]
    pub(crate) fn install() -> io::Result<Guard> {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close};
        Ok(Guard {
            c: ctrl_c()?,
            brk: ctrl_break()?,
            close: ctrl_close()?,
        })
    }

    #[cfg(not(any(unix, windows)))]
    pub(crate) fn install() -> io::Result<Guard> {
        Ok(Guard)
    }
}

impl Interrupts for Guard {
    #[cfg(unix)]
    fn next(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let mut poll = tokio::time::interval(HANGUP_POLL);
            loop {
                tokio::select! {
                    _ = self.int.recv() => return,
                    _ = self.term.recv() => return,
                    _ = self.hup.recv() => return,
                    _ = poll.tick() => {
                        if stdout_hung_up() {
                            return;
                        }
                    }
                }
            }
        })
    }

    #[cfg(windows)]
    fn next(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            tokio::select! {
                _ = self.c.recv() => {},
                _ = self.brk.recv() => {},
                _ = self.close.recv() => {},
            }
        })
    }

    #[cfg(not(any(unix, windows)))]
    fn next(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
}

/// True when the reader of fd 1 went away (`POLLERR`/`POLLHUP`, no wait).
#[cfg(unix)]
fn stdout_hung_up() -> bool {
    let mut fd = libc::pollfd {
        fd: 1,
        events: 0,
        revents: 0,
    };
    // SAFETY: `fd` is a valid `pollfd` that outlives the call; one entry, zero timeout.
    let ready = unsafe { libc::poll(&mut fd, 1, 0) };
    ready > 0 && fd.revents & (libc::POLLERR | libc::POLLHUP) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_does_not_fire() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        let Ok(rt) = rt else { return };
        let fired = rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(30), Never.next())
                .await
                .is_ok()
        });
        assert!(!fired);
    }

    #[test]
    fn guard_installs_and_stays_quiet() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        let Ok(rt) = rt else { return };
        rt.block_on(async {
            let guard = Guard::install();
            assert!(guard.is_ok());
            if let Ok(mut guard) = guard {
                // Under `cargo test` stdout is captured (not a hung-up pipe) and no signal comes.
                let fired =
                    tokio::time::timeout(std::time::Duration::from_millis(80), guard.next())
                        .await
                        .is_ok();
                assert!(!fired);
            }
        });
    }
}
