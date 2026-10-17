//! `SIGCHLD` disposition of the app (M8 T6 review I-1, §3.4 "sole reaper").
//!
//! sandbox-host kills a worker by pid and reaps it itself, which is only safe while it is the
//! worker's sole reaper. If the process inherited `SIGCHLD` as `SIG_IGN`, or with `SA_NOCLDWAIT`
//! (a launcher or a service manager can hand that down), the kernel would reap every child at its
//! exit and free its pid, and a later signal could reach a recycled pid. The Linux and macOS
//! spawners therefore refuse to spawn while `SIGCHLD` is ignored; a GUI launch resets it here,
//! once, before the first thread exists, and every spawn then finds the default disposition.

use std::io;

/// Sets `SIGCHLD` to its default disposition without `SA_NOCLDWAIT`. Windows has no such signal:
/// nothing to do there. Call it while the process is still single-threaded (`main`, before
/// `run_gui`); the setting is process-wide.
#[cfg(unix)]
pub fn restore_default_sigchld() -> io::Result<()> {
    // SAFETY: an all-zero `sigaction` is a valid value; the fields that matter are set below.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    action.sa_flags = 0;
    // SAFETY: `sa_mask` is a valid, writable `sigset_t` that `sigemptyset` initialises.
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `action` is fully initialised and outlives the call; a null old-action pointer
    // asks for no copy of the previous one.
    if unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Windows has no `SIGCHLD`.
#[cfg(not(unix))]
pub fn restore_default_sigchld() -> io::Result<()> {
    Ok(())
}
