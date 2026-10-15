//! The Running-scripts window's read model (PD-81, §9.6): the real script runs that are alive
//! right now. Read-only; the columns and the release-item behaviour of the kill button are M8's.

use std::sync::Arc;

use serde::Serialize;

use crate::engine::Engine;
use crate::lifecycle::model::Phase;

/// One live script run. `agent_name` is agent data (§3.3, normalized): a window shows it as text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunningScriptView {
    pub request_id: String,
    pub agent_name: Option<String>,
    /// RFC 3339 UTC, ms: when the request was received (M8 refines it to the slot's start).
    pub started_at: String,
    /// Host calls the run made so far, counted by the host.
    pub host_calls: u32,
}

/// The real runs in `Running`, oldest first (dry runs are not listed: they have no release item
/// and no kill button, §9.6).
pub(crate) fn list(engine: &Arc<Engine>) -> Vec<RunningScriptView> {
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
            Some(RunningScriptView {
                request_id: e.head.request_id.clone(),
                agent_name: e.agent_name.clone(),
                started_at: e.submitted_at.clone(),
                host_calls: shared.calls(),
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
