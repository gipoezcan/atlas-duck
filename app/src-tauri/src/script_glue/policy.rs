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
    /// Windows below the floor with no AppContainer worker (no probe worker reached ready): the
    /// lockdown-token spawner (M8 Task 11, §9.4).
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

/// Why [`admit`] refused a spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The floor is not met and degraded confinement is not allowed.
    FloorNotMet,
    /// No identity of the worker binary to check the spawn against: the probe recorded none, and
    /// the holder recorded none either or the spawn is not degraded (a `Met` report).
    NoIdentity,
    /// The holder's own record is of another path than the spawn's.
    FallbackOtherPath,
    /// The holder could not read the binary's identity when it resolved.
    FallbackUnreadable,
}

impl Refusal {
    /// In core's words: every refusal but the floor rule's is `SpawnFailed` (fail closed).
    pub fn reason(self) -> UnavailableReason {
        match self {
            Refusal::FloorNotMet => UnavailableReason::FloorNotMet,
            Refusal::NoIdentity | Refusal::FallbackOtherPath | Refusal::FallbackUnreadable => {
                UnavailableReason::SpawnFailed
            }
        }
    }

    /// The `reason` token of the `script_spawn_failed` log line (T20 review m-1); `None` for the
    /// floor rule, a policy answer rather than a failure.
    pub fn log_token(self) -> Option<&'static str> {
        match self {
            Refusal::FloorNotMet => None,
            Refusal::NoIdentity => Some("no_identity"),
            Refusal::FallbackOtherPath => Some("fallback_other_path"),
            Refusal::FallbackUnreadable => Some("fallback_unreadable"),
        }
    }
}

/// The floor rule under `policy` (§9.4, PD-141), for a spawn of `worker`. A refusal names why: the
/// floor is not met and degraded confinement is not allowed (`FloorNotMet`), or there is no
/// identity of the worker binary to check the spawn against (the others; fail closed).
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
) -> Result<Admission, Refusal> {
    let degraded = match &report.floor {
        FloorVerdict::Met => false,
        FloorVerdict::NotMet { .. } if policy.allow_degraded => true,
        FloorVerdict::NotMet { .. } => return Err(Refusal::FloorNotMet),
    };
    // §9.4: a run uses the spawner whose probe workers reached ready (they gave the identity),
    // also when the floor is `NotMet` (a floor probe was not blocked, or the control re-run
    // invalidated it): on Windows it keeps the AppContainer. The degraded spawner only when no
    // probe worker reached ready (AppContainer unavailable: ACEs missing, profile creation
    // blocked), i.e. exactly when the holder's own record stands in.
    let (identity, spawner) = match &report.identity {
        Some(identity) => (identity.clone(), probe_spawner_kind(report)),
        None if degraded => {
            let record = fallback.ok_or(Refusal::NoIdentity)?;
            if Some(record.worker.as_path()) != worker {
                return Err(Refusal::FallbackOtherPath);
            }
            let identity = record.identity.clone().ok_or(Refusal::FallbackUnreadable)?;
            (identity, degraded_spawner_kind())
        }
        None => return Err(Refusal::NoIdentity),
    };
    let mode = if degraded {
        ConfinementMode::Degraded
    } else {
        ConfinementMode::Floor
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

/// The spawner whose workers produced `report`: the plain AppContainer one when its rerun replaced
/// the LPAC report (`lpac_failed`), else the platform's.
fn probe_spawner_kind(report: &ProbeReport) -> SpawnerKind {
    if report.lpac_failed.is_some() {
        SpawnerKind::Fallback
    } else {
        SpawnerKind::Platform
    }
}

/// PD-141 (b), §9.4: when no probe worker reached ready, Windows has its own degraded spawner
/// (lockdown token); elsewhere "degraded" is the platform spawner's worker with `applied: false`.
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
