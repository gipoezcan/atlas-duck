//! OS confinement of the worker (§9.4). `apply` is called by `run()` on the
//! worker's main thread before the first stdin read. T17 fills Linux; T18
//! (macOS) and T19 (Windows) add their arms.

use atlas_duck_ipc::sandbox::probe::ConfinementReport;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub mod seccomp_allowlist;

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
/// report, so the worker still sends `probe.ready`. macOS (T18) and Windows
/// (T19) still apply nothing.
pub fn apply() -> Result<ConfinementReport, ConfineError> {
    #[cfg(target_os = "linux")]
    {
        Ok(linux::apply())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(unconfined())
    }
}
