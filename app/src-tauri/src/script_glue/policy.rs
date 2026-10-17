//! The floor rule and the degraded toggle (§9.4, PD-141): what a spawn is admitted under, read
//! from the startup probe's report and the run policy core hands each call.
//!
//! The one rule: a worker may run unconfined (`ExpectedWorker::accept_unconfined`) only when the
//! policy allows degraded confinement AND the startup probe found the floor not met (PD-141 (d)).
//! With a `Met` report an unconfined ready frame is refused (`FloorNotMet`) whatever the toggle
//! says: a regression after start never silently runs unconfined.

use atlas_duck_core::{ConfinementMode, RunConfinement, RunPolicy, UnavailableReason};
use atlas_duck_ipc::sandbox::probe::ConfinementReport;
use atlas_duck_sandbox_host::bridge::ExpectedWorker;
use atlas_duck_sandbox_host::probe::{FloorVerdict, ProbeReport};

/// Which spawner a spawn uses (§9.4, PD-141 (b)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnerKind {
    /// The platform's floor spawner (Windows: LPAC where every ACE exists).
    Platform,
    /// Windows: the plain AppContainer spawner, whose rerun of the probe met the floor after LPAC
    /// did not (`ProbeReport::lpac_failed`).
    Fallback,
    /// Windows below the floor: the lockdown-token spawner (M8 Task 11).
    Degraded,
}

/// What a spawn is admitted under.
#[derive(Debug, Clone)]
pub struct Admission {
    pub mode: ConfinementMode,
    pub spawner: SpawnerKind,
    /// The probe's recorded identity and whether an unconfined ready frame is accepted.
    pub expect: ExpectedWorker,
    /// The startup probe's own ready-frame report, `None` when no probe worker answered.
    pub probe_report: Option<ConfinementReport>,
}

/// The floor rule under `policy` (§9.4, PD-141). A refusal names why: the floor is not met and
/// degraded confinement is not allowed (`FloorNotMet`), or the probe recorded no identity of the
/// worker binary (no probe worker sent its ready frame), so no spawn can be checked against it
/// (`SpawnFailed`; fail closed).
pub fn admit(report: &ProbeReport, policy: RunPolicy) -> Result<Admission, UnavailableReason> {
    let degraded = match &report.floor {
        FloorVerdict::Met => false,
        FloorVerdict::NotMet { .. } if policy.allow_degraded => true,
        FloorVerdict::NotMet { .. } => return Err(UnavailableReason::FloorNotMet),
    };
    let identity = report
        .identity
        .clone()
        .ok_or(UnavailableReason::SpawnFailed)?;
    let (mode, spawner) = if degraded {
        (ConfinementMode::Degraded, degraded_spawner_kind())
    } else if report.lpac_failed.is_some() {
        (ConfinementMode::Floor, SpawnerKind::Fallback)
    } else {
        (ConfinementMode::Floor, SpawnerKind::Platform)
    };
    Ok(Admission {
        mode,
        spawner,
        expect: ExpectedWorker {
            identity,
            accept_unconfined: degraded,
        },
        probe_report: report.confinement.clone(),
    })
}

/// PD-141 (b): Windows has its own degraded spawner; elsewhere "degraded" is the platform
/// spawner's worker with `applied: false`.
fn degraded_spawner_kind() -> SpawnerKind {
    if cfg!(windows) {
        SpawnerKind::Degraded
    } else {
        SpawnerKind::Platform
    }
}

/// `SCRIPT_STARTED.confinement` for a run admitted now under `policy` (PD-138, T12 fix contract):
/// `None` while no report exists, when the floor rule refuses, and when the probe has no ready
/// frame report to name.
pub fn confinement(report: Option<&ProbeReport>, policy: RunPolicy) -> Option<RunConfinement> {
    let admission = admit(report?, policy).ok()?;
    Some(RunConfinement {
        mode: admission.mode,
        worker_version: admission.expect.identity.embedded_version,
        probe_report: admission.probe_report?,
    })
}
