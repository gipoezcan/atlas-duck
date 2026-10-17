//! OS confinement of the worker (§9.4). `apply` is called by `run()` on the
//! worker's main thread before the first stdin read. T17 fills Linux; T18
//! (macOS) and T19 (Windows) add their arms. M8 Task 11 adds the Windows
//! degraded start ([`StartMode`], [`apply_mode`]).

use std::ffi::OsString;

use atlas_duck_ipc::sandbox::LOCKDOWN_TOKEN_ARG;
use atlas_duck_ipc::sandbox::probe::ConfinementReport;

#[cfg(target_os = "linux")]
mod linux;
pub mod macos;
#[cfg(target_os = "linux")]
pub mod seccomp_allowlist;
#[cfg(windows)]
mod windows;

/// Why confinement could not be applied. The worker still answers
/// `probe.ready`, with `applied: false`, so the host scores the floor as not met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfineError {
    /// Short mechanism name for `ConfinementReport.mechanism`.
    pub mechanism: &'static str,
    /// The OS error behind the failure, when there is one.
    pub os_error: Option<i64>,
}

impl std::fmt::Display for ConfineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "confinement `{}` failed (os error {:?})",
            self.mechanism, self.os_error
        )
    }
}

impl std::error::Error for ConfineError {}

/// The mechanism a worker started by the Windows degraded spawner reports (§9.4, plan M8 Task 11).
pub const LOCKDOWN_TOKEN: &str = "lockdown_token";

/// How the spawner started the worker (plan M8 Task 11). Read from the command line only, never
/// from a host frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartMode {
    /// The OS confinement of [`apply`].
    Default,
    /// Windows degraded path (§9.4): a lockdown process token, and a startup impersonation token
    /// on the main thread that the worker drops before its first frame ([`apply_mode`]).
    LockdownToken,
}

impl StartMode {
    /// The mode for the process arguments after the program name: exactly
    /// [`LOCKDOWN_TOKEN_ARG`] is [`StartMode::LockdownToken`], anything else (no argument, other
    /// or more arguments) [`StartMode::Default`].
    pub fn from_args<I: IntoIterator<Item = OsString>>(args: I) -> StartMode {
        let mut args = args.into_iter();
        match (args.next(), args.next()) {
            (Some(only), None) if only == LOCKDOWN_TOKEN_ARG => StartMode::LockdownToken,
            _ => StartMode::Default,
        }
    }
}

/// The report of a worker in [`StartMode::LockdownToken`]: below the floor (§9.4), so `applied`
/// is always false, whatever the token steps found. `os_error` is the error of a step that did
/// not find what the degraded spawner sets up (for example no startup impersonation token).
pub fn lockdown_token_report(os_error: Option<i64>) -> ConfinementReport {
    ConfinementReport {
        applied: false,
        mechanism: LOCKDOWN_TOKEN.to_owned(),
        no_new_privs: None,
        landlock_abi: None,
        seccomp: None,
        lpac: None,
        os_error,
    }
}

/// The report of a worker that applied nothing.
pub fn unconfined() -> ConfinementReport {
    ConfinementReport {
        applied: false,
        mechanism: "none".to_owned(),
        no_new_privs: None,
        landlock_abi: None,
        seccomp: None,
        lpac: None,
        os_error: None,
    }
}

/// Applies the OS confinement to the calling (main, single) thread, before the
/// first stdin read.
///
/// Linux (T17): `tzset`, `PR_SET_NO_NEW_PRIVS`, Landlock, seccomp. A failed step
/// comes back as `Ok` with `applied: false` and the partial evidence in the
/// report, so the worker still sends `probe.ready`. macOS (T18): `tzset`, then
/// `sandbox_init` with the embedded SBPL profile, with the same `Ok` /
/// `applied: false` treatment of a refusal. Windows (T19): the host confines the
/// worker at spawn (AppContainer, job object), so the worker applies nothing; it
/// reports what its own token and job membership say, which is `applied: false`
/// for a worker that was started without the AppContainer.
pub fn apply() -> Result<ConfinementReport, ConfineError> {
    #[cfg(target_os = "linux")]
    {
        Ok(linux::apply())
    }
    #[cfg(target_os = "macos")]
    {
        // §9.4 macOS: sandbox_init with the embedded SBPL profile.
        Ok(macos::apply())
    }
    #[cfg(windows)]
    {
        Ok(windows::apply())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Ok(unconfined())
    }
}

/// [`apply`] for the mode the worker was started in.
///
/// [`StartMode::LockdownToken`] on Windows (§9.4 degraded, plan M8 Task 11): the main thread
/// still runs on the startup impersonation token the degraded spawner gave it, so that the loader
/// could open the worker's DLLs. This loads what Rust loads lazily, drops that token with
/// `RevertToSelf` and checks that the thread no longer impersonates; from then on the worker runs
/// on its lockdown process token. `Err` means the thread may still impersonate: the worker must
/// exit without writing a frame or reading stdin. On the other OSes the argument means nothing
/// and the mode is [`apply`].
pub fn apply_mode(mode: StartMode) -> Result<ConfinementReport, ConfineError> {
    match mode {
        StartMode::Default => apply(),
        #[cfg(windows)]
        StartMode::LockdownToken => windows::drop_startup_token(),
        #[cfg(not(windows))]
        StartMode::LockdownToken => apply(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn only_the_lockdown_argument_alone_selects_the_lockdown_mode() {
        assert_eq!(
            StartMode::from_args(args(&[LOCKDOWN_TOKEN_ARG])),
            StartMode::LockdownToken
        );
        assert_eq!(StartMode::from_args(args(&[])), StartMode::Default);
        assert_eq!(
            StartMode::from_args(args(&["--lockdown"])),
            StartMode::Default
        );
        assert_eq!(
            StartMode::from_args(args(&[LOCKDOWN_TOKEN_ARG, "x"])),
            StartMode::Default
        );
        assert_eq!(
            StartMode::from_args(args(&["x", LOCKDOWN_TOKEN_ARG])),
            StartMode::Default
        );
    }

    #[test]
    fn degraded_report_names_lockdown_token_not_applied() {
        let report = lockdown_token_report(None);
        assert_eq!(
            report,
            ConfinementReport {
                applied: false,
                mechanism: "lockdown_token".to_owned(),
                no_new_privs: None,
                landlock_abi: None,
                seccomp: None,
                lpac: None,
                os_error: None,
            }
        );
        // A step that found something else is evidence, never "applied".
        let report = lockdown_token_report(Some(1008));
        assert!(!report.applied);
        assert_eq!(report.mechanism, LOCKDOWN_TOKEN);
        assert_eq!(report.os_error, Some(1008));
    }
}
