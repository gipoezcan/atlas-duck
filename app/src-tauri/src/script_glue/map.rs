//! The bridge's answers in core's terms (C.0): kill causes, spawn refusals, compile verdicts and a
//! run's end (Δ3, PD-133, PD-134, PD-135).
//!
//! Classification uses host state only (§9.5): a run's [`RunOutcome::end`] (the worker's terminal
//! frame, untrusted payload) is read only when the host's verdict is [`HostVerdict::None`], i.e.
//! when that frame decided the run (T7 review m-9). Every other verdict maps from the host's facts
//! alone.

use std::time::Duration;

use atlas_duck_core::{
    CompileError, CompileFailure, KillReason, RunEnd, RunnerError, UnavailableReason,
};
use atlas_duck_sandbox_host::bridge::{
    CompileVerdict, HostVerdict, KillCause, RESULT_NOT_REPRESENTABLE, RunOutcome, StartRunError,
    WorkerEnd,
};
use serde_json::Value;

/// `RunEnd::HostLimit` name of a binary replaced since the probe (Δ3, PD-133).
pub const LIMIT_APP_UPGRADED: &str = "app_upgraded";
/// `RunEnd::HostLimit` name of any other spawn-time unavailability (Δ3).
pub const LIMIT_SANDBOX_UNAVAILABLE: &str = "sandbox_unavailable";
/// The class of the error a result becomes when its text does not read as a `Value` (the
/// bridge's own rule for such a result, T4 fix I-1; unreachable: the bridge already turned every
/// such result into that error).
pub const CLASS_TYPE_ERROR: &str = "TypeError";

/// Core's kill reason as the bridge's cause (one to one; a free function because neither type is
/// the app's, T7 deviation 3).
pub fn kill_cause(why: KillReason) -> KillCause {
    match why {
        KillReason::Client => KillCause::Client,
        KillReason::User => KillCause::User,
        KillReason::Shutdown => KillCause::Shutdown,
        KillReason::Limit(name) => KillCause::Limit(name),
        KillReason::AuditFailure => KillCause::AuditFailure,
    }
}

/// The bridge's kill cause as core's reason (the inverse of [`kill_cause`]).
pub fn kill_reason(cause: KillCause) -> KillReason {
    match cause {
        KillCause::Client => KillReason::Client,
        KillCause::User => KillReason::User,
        KillCause::Shutdown => KillReason::Shutdown,
        KillCause::Limit(name) => KillReason::Limit(name),
        KillCause::AuditFailure => KillReason::AuditFailure,
    }
}

/// Why no worker was started (or used), in core's words (PD-133, PD-141). `start` answers it as
/// `Err(SandboxUnavailable {reason})`, so the record keeps the exact cause (T12 review M-6).
pub fn unavailable_reason(e: &StartRunError) -> UnavailableReason {
    match e {
        StartRunError::IdentityMismatch { .. } => UnavailableReason::AppUpgraded,
        StartRunError::FloorNotMet => UnavailableReason::FloorNotMet,
        StartRunError::Spawn(_) => UnavailableReason::SpawnFailed,
    }
}

/// [`unavailable_reason`] as core's runner error.
pub fn runner_error(reason: UnavailableReason) -> RunnerError {
    RunnerError::SandboxUnavailable { reason }
}

/// A compile-only worker's answer (PD-135, T7 and T11 hand-offs): `Timeout` is the data-free
/// `script_limit {timeout_s}` (never `script_syntax`); a worker that gave no verdict for any other
/// reason (spawn failure, no or a bad ready frame, exit 3) is unavailable, never a syntax error.
pub fn compile_outcome(
    answer: Result<CompileVerdict, StartRunError>,
    timeout_s: u32,
) -> Result<(), CompileFailure> {
    match answer {
        Ok(CompileVerdict::Compiled) => Ok(()),
        Ok(CompileVerdict::Syntax {
            line,
            column,
            message,
        }) => Err(CompileFailure::Syntax(CompileError {
            line,
            column,
            message,
        })),
        Ok(CompileVerdict::Timeout) => Err(CompileFailure::Timeout { timeout_s }),
        Err(e) => Err(CompileFailure::Unavailable(runner_error(
            unavailable_reason(&e),
        ))),
    }
}

/// A run's end as core reads it (PD-134, Δ3). `value_json` already passed the bridge's
/// `reads_as_value`, so the one parse here cannot fail on depth or surrogates; if it did anyway,
/// the run is a release-gated runtime error, never a success and never a crash.
pub fn to_run_end(outcome: RunOutcome) -> RunEnd {
    let RunOutcome {
        end,
        host,
        logs,
        stderr,
        elapsed,
        ..
    } = outcome;
    match host {
        HostVerdict::None => match end {
            WorkerEnd::Result { value_json } => {
                match serde_json::from_str::<Value>(value_json.get()) {
                    Ok(value) => RunEnd::Result {
                        value,
                        logs,
                        stderr,
                    },
                    Err(_) => RunEnd::Error {
                        class: CLASS_TYPE_ERROR.to_owned(),
                        message: RESULT_NOT_REPRESENTABLE.to_owned(),
                        stack: String::new(),
                        elapsed_ms: millis(elapsed),
                        logs,
                        stderr,
                    },
                }
            }
            WorkerEnd::Error {
                class,
                message,
                stack,
            } => RunEnd::Error {
                class,
                message,
                stack,
                // PD-134: the host's clock, never the worker's.
                elapsed_ms: millis(elapsed),
                logs,
                stderr,
            },
            // No terminal frame although no host cause decided: not a state the bridge reports;
            // the conservative reading is a crash (a release item).
            WorkerEnd::None => RunEnd::Crashed,
        },
        HostVerdict::Limit(name) => RunEnd::HostLimit {
            name: name.to_owned(),
        },
        // The cause the host recorded for the run, not the one core asked for (T7 review m-9).
        HostVerdict::Killed(cause) => RunEnd::Killed {
            reason: kill_reason(cause),
        },
        HostVerdict::Violation(_) => RunEnd::ProtocolViolation,
        // T7 fix: the worker could not read what the host sent (a host bug, never the script's
        // doing, never `protocol_violation`). As a crash it is a release item even before any
        // call (the safe direction); the diag `sandbox_host_protocol_exit` names it in the log.
        HostVerdict::HostFault => RunEnd::Crashed,
        HostVerdict::Crashed(_) => RunEnd::Crashed,
        // Never produced by the bridge (`start` refuses through `Err`, which keeps the reason);
        // mapped for completeness as the plan names it.
        HostVerdict::NotSpawned(e) => RunEnd::HostLimit {
            name: match e {
                StartRunError::IdentityMismatch { .. } => LIMIT_APP_UPGRADED,
                StartRunError::FloorNotMet | StartRunError::Spawn(_) => LIMIT_SANDBOX_UNAVAILABLE,
            }
            .to_owned(),
        },
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}
