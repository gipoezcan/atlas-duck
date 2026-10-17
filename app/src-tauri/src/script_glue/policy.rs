//! The floor rule and the degraded toggle (§9.4, PD-141): what a spawn is admitted under, read
//! from the startup probe's report and the run policy core hands each call.
//!
//! The one rule: a worker may run unconfined (`ExpectedWorker::accept_unconfined`) only when the
//! policy allows degraded confinement AND the startup probe found the floor not met (PD-141 (d)).
//! With a `Met` report an unconfined ready frame is refused (`FloorNotMet`) whatever the toggle
//! says: a regression after start never silently runs unconfined.

use std::path::Path;

use atlas_duck_core::{ConfinementMode, RunConfinement, RunPolicy, UnavailableReason};
use atlas_duck_ipc::sandbox::probe::ConfinementReport;
use atlas_duck_sandbox_host::bridge::ExpectedWorker;
use atlas_duck_sandbox_host::probe::{FloorVerdict, ProbeReport};

use crate::sandbox_probe::FallbackIdentity;

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
    /// The startup probe's own ready-frame report, `None` when no probe worker answered (never
    /// stood in for: the run's worker's own report goes to the end record).
    pub probe_report: Option<ConfinementReport>,
}

/// The floor rule under `policy` (§9.4, PD-141), for a spawn of `worker`. A refusal names why: the
/// floor is not met and degraded confinement is not allowed (`FloorNotMet`), or there is no
/// identity of the worker binary to check the spawn against (`SpawnFailed`; fail closed).
///
/// The identity is the probe's. When no probe worker sent its ready frame the probe recorded none,
/// and only a degraded spawn (degraded allowed AND the floor `NotMet`) may use the one the holder
/// recorded itself (`fallback`, M8 T20 ruling), and only for the path it was read from; a `Met`
/// report without an identity is refused whatever the toggle says.
pub fn admit(
    report: &ProbeReport,
    fallback: Option<&FallbackIdentity>,
    worker: Option<&Path>,
    policy: RunPolicy,
) -> Result<Admission, UnavailableReason> {
    let degraded = match &report.floor {
        FloorVerdict::Met => false,
        FloorVerdict::NotMet { .. } if policy.allow_degraded => true,
        FloorVerdict::NotMet { .. } => return Err(UnavailableReason::FloorNotMet),
    };
    let identity = match &report.identity {
        Some(identity) => identity.clone(),
        None if degraded => fallback
            .filter(|f| Some(f.worker.as_path()) == worker)
            .and_then(|f| f.identity.clone())
            .ok_or(UnavailableReason::SpawnFailed)?,
        None => return Err(UnavailableReason::SpawnFailed),
    };
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
/// `None` while no report exists and when the floor rule refuses. A degraded run on the holder's
/// own identity record names no probe report (`probe_report: null`).
pub fn confinement(
    report: Option<&ProbeReport>,
    fallback: Option<&FallbackIdentity>,
    worker: Option<&Path>,
    policy: RunPolicy,
) -> Option<RunConfinement> {
    let admission = admit(report?, fallback, worker, policy).ok()?;
    Some(RunConfinement {
        mode: admission.mode,
        worker_version: admission.expect.identity.embedded_version,
        probe_report: admission.probe_report,
    })
}
