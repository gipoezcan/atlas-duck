//! The `event` values the script glue writes (M8 Task 20; moved here from the app's
//! `diag::fields` by M14 Task 11, PD-247, which re-exports them for its allowlist).

/// The `event` values the script glue writes. Its own three, and every host fact `sandbox-host`
/// reports in `RunOutcome.diag` (the bridge's `DIAG_*` constants). The glue writes only these,
/// with the run's `request_id` and, for `script_spawn_failed` and `script_identity_mismatch`, a
/// fixed `reason` token; never a worker byte (§3.4: stderr, logs, results and error texts stay in
/// the encrypted run record). A `diag` value missing here is written as [`SCRIPT_DIAG_UNLISTED`].
pub const SCRIPT_GLUE_EVENTS: &[&str] = &[
    "script_identity_mismatch",
    "script_spawn_failed",
    "script_probe_pending",
    "sandbox_reap_failed",
    "sandbox_outcome_lost",
    "sandbox_host_protocol_exit",
    "sandbox_call_result_replaced",
    "sandbox_unread_results",
    "sandbox_watchdog_kill",
    "sandbox_job_memory_limit",
    "sandbox_memory_watch_failed",
    "sandbox_stdout_held_after_exit",
    "sandbox_stdin_held_after_exit",
];

/// What the glue writes for a `RunOutcome.diag` value that [`SCRIPT_GLUE_EVENTS`] does not list.
pub const SCRIPT_DIAG_UNLISTED: &str = "sandbox_diag_unlisted";
