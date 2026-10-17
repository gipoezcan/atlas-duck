#![cfg(unix)]
//! M8 T8 (T6 review I-1): `main` resets an inherited `SIGCHLD` disposition before the GUI starts,
//! because the Linux and macOS sandbox spawners refuse to spawn while it is `SIG_IGN` or has
//! `SA_NOCLDWAIT`. This file holds one test, so it owns the process-wide signal state.

use atlas_duck_app_lib::startup::child_reaping::restore_default_sigchld;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn disposition() -> Result<(libc::sighandler_t, libc::c_int), std::io::Error> {
    // SAFETY: an all-zero `sigaction` is a valid out-buffer.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: a null new action only reads the current one into `old`.
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut old) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((old.sa_sigaction, old.sa_flags))
}

fn set(handler: libc::sighandler_t, flags: libc::c_int) -> TestResult {
    // SAFETY: an all-zero `sigaction` is a valid value; the fields that matter are set below.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler;
    action.sa_flags = flags;
    // SAFETY: `action` is initialised and outlives the call.
    if unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[test]
fn restore_default_sigchld_clears_ignore_and_nocldwait() -> TestResult {
    // An ignored SIGCHLD (what a launcher can hand down).
    set(libc::SIG_IGN, 0)?;
    assert_eq!(disposition()?.0, libc::SIG_IGN, "precondition");
    restore_default_sigchld()?;
    let (handler, flags) = disposition()?;
    assert_eq!(handler, libc::SIG_DFL);
    assert_eq!(flags & libc::SA_NOCLDWAIT, 0);

    // SA_NOCLDWAIT with the default handler.
    set(libc::SIG_DFL, libc::SA_NOCLDWAIT)?;
    assert_ne!(disposition()?.1 & libc::SA_NOCLDWAIT, 0, "precondition");
    restore_default_sigchld()?;
    let (handler, flags) = disposition()?;
    assert_eq!(handler, libc::SIG_DFL);
    assert_eq!(flags & libc::SA_NOCLDWAIT, 0);

    // Already default: unchanged, still Ok.
    restore_default_sigchld()?;
    assert_eq!(disposition()?.0, libc::SIG_DFL);
    Ok(())
}
