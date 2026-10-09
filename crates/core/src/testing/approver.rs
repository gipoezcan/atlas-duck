//! `ScriptedApprover` (C.7 `core::testing`): a headless human over `DecisionApi`. Task 19 lays
//! the skeleton; Task 21 adds `open`, `release`, `release_redacted`, `release_status_only` and
//! `deny`, Task 22 `approve`, `edit` and `deny_with`.

use std::sync::Arc;

use crate::decision::{DecisionApi, QueueItem};

pub struct ScriptedApprover {
    decisions: Arc<dyn DecisionApi>,
}

impl ScriptedApprover {
    pub fn new(decisions: Arc<dyn DecisionApi>) -> ScriptedApprover {
        ScriptedApprover { decisions }
    }

    /// The queue row of `request_id`, if it waits for a decision.
    pub fn item(&self, request_id: &str) -> Option<QueueItem> {
        self.decisions.queue_get(request_id)
    }
}
