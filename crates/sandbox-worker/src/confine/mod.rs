//! OS confinement of the worker (§9.4). T14 only fixes the entry point; the
//! per-OS bodies arrive in T17 (Linux), T18 (macOS) and T19 (Windows).

use atlas_duck_ipc::sandbox::probe::ConfinementReport;

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
/// first stdin read. T14: applies nothing on any OS.
pub fn apply() -> Result<ConfinementReport, ConfineError> {
    Ok(unconfined())
}
