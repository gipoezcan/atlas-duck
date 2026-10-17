//! The Running-scripts window's read model (PD-81, §9.6, Δ4, PD-142): the real script runs that
//! are alive right now. Read-only; the kill button's answer is `KillAnswer` (PD-143).

use std::sync::Arc;

use serde::Serialize;

use crate::engine::Engine;
use crate::lifecycle::model::Phase;

/// One live script run. `agent_name` is agent data (§3.3, normalized): a window shows it as text.
/// Every value is Rust's: the window computes nothing (PD-142).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunningScriptView {
    pub request_id: String,
    pub agent_name: Option<String>,
    /// The aliases of the instances the run called so far, sorted.
    pub instances: Vec<String>,
    /// RFC 3339 UTC, ms: when the run got its slot (the `SCRIPT_STARTED` time, not the submit).
    pub started_at: String,
    /// Host clock since the slot, at list time.
    pub elapsed_ms: u64,
    /// Host calls the run made so far, counted by the host.
    pub host_calls: u32,
    /// Bytes the run's host calls fetched so far, counted by the host.
    pub bytes_fetched: u64,
}

/// What a kill click did (§9.6, PD-143).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KillAnswer {
    /// The kill was asked for: the run becomes a release item.
    Killed,
    /// No such live real run (unknown, a dry run, not a script, or already ended and recorded).
    NotRunning,
    /// A kill reason was already set (cancel, limit, shutdown, an earlier click), or the worker
    /// ended and its record is not appended yet.
    AlreadyStopping,
}

/// The real runs in `Running` that are not ending, oldest first (dry runs are not listed: they
/// have no release item and no kill button, §9.6).
pub(crate) fn list(engine: &Arc<Engine>) -> Vec<RunningScriptView> {
    let now = engine.clock().suspend_aware_elapsed();
    let mut rows: Vec<RunningScriptView> = engine
        .pending_entries()
        .into_iter()
        .filter_map(|e| {
            let st = e.state();
            if st.model.phase() != Phase::Running {
                return None;
            }
            let s = st.script.as_ref()?;
            if s.dry.is_some() {
                return None;
            }
            let shared = s.shared.as_ref()?;
            // A run that ended, or whose kill was asked for, is on its way out: the end record is
            // appended after this point, so the list must not wait for the phase to change.
            if shared.ended() || shared.kill_reason().is_some() {
                return None;
            }
            let (started_at, started_mono) = s.slot.clone()?;
            Some(RunningScriptView {
                request_id: e.head.request_id.clone(),
                agent_name: e.agent_name.clone(),
                instances: shared.aliases().into_iter().collect(),
                started_at,
                elapsed_ms: u64::try_from(now.saturating_sub(started_mono).as_millis())
                    .unwrap_or(u64::MAX),
                host_calls: shared.calls(),
                bytes_fetched: shared.fetched_bytes(),
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        a.started_at
            .cmp(&b.started_at)
            .then_with(|| a.request_id.cmp(&b.request_id))
    });
    rows
}
