//! `DecisionApi::recent` (M6 Δ2, §5.6): the "Recently decided (24 h) / Needs attention" rows.
//!
//! Built from the rows behind `requests list` (§4.4: the plaintext columns of the last 24 h, the
//! row of each recorded terminal built once and memoized; no new decrypt path), plus the writes a
//! stale check returned to the queue (§5.4 step 5: "returned for re-review"). Requests waiting for
//! their first decision are the queue's, not this list's.
//!
//! - `needs_attention`: a write that failed or whose outcome is unknown after its approval
//!   (`WRITE_FAILED`, `WRITE_OUTCOME_UNKNOWN`), and a stale return.
//! - `acknowledged`: a failure or unknown outcome no longer in the engine's in-memory set of
//!   unacknowledged ids: acknowledged, or flagged before the last restart (§5.6: acknowledgement
//!   is UI state that resets on restart, where the §11.3 startup notice covers interrupted
//!   writes). A stale return is never acknowledged: it leaves this list when it is decided.
//! - `error_text`: the capped Atlassian error of a refused write, only while `await` can still
//!   deliver it (1 h after the approval, §4.4, §11.2), display-escaped and capped at 2 KiB; from
//!   the status path's memoized read of the failure record.

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

use atlas_duck_audit::{EventType, UtcInstant};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::cap_error_text;
use atlas_duck_preview::invisible::escape_for_display;
use serde::Serialize;
use serde_json::Value;

use super::decidable;
use crate::engine::Engine;
use crate::engine::deliver::DELIVERY_WINDOW_MS;
use crate::engine::handler::{Decided, ListRow, recorded_rows};
use crate::lifecycle::model::agent_status;

/// One row (C.7, M6 Δ2). Strings are display text: `target_display` as `requests list` shows
/// it, `error_text` display-escaped Atlassian text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecentItem {
    pub request_id: String,
    pub op_id: String,
    /// `"read"`, `"write"` or `"script"`.
    pub class: &'static str,
    /// Empty for a script (or an instance no longer configured).
    pub instance_alias: String,
    pub target_display: String,
    pub status: Status,
    /// RFC 3339 UTC, ms.
    pub decided_at: String,
    pub error_text: Option<String>,
    pub needs_attention: bool,
    pub acknowledged: bool,
}

/// Ends that no human decided: refused or failed before the queue, or a script's direct end.
fn undecided(t: EventType) -> bool {
    matches!(
        t,
        EventType::REQUEST_REJECTED
            | EventType::REQUEST_FAILED
            | EventType::READ_FAILED
            | EventType::SCRIPT_DRY_RUN
            | EventType::SCRIPT_FAILED
    )
}

fn class_of(op_class: Option<&str>) -> &'static str {
    match op_class {
        Some("write") => "write",
        Some("script") => "script",
        _ => "read",
    }
}

/// Within `DELIVERY_WINDOW_MS` of `at` (§4.4).
fn deliverable(at: &str, now: UtcInstant) -> bool {
    UtcInstant::parse_rfc3339_ms(at)
        .is_some_and(|d| now.0.saturating_sub(d.0) <= DELIVERY_WINDOW_MS)
}

pub(super) async fn recent(engine: Arc<Engine>) -> Vec<RecentItem> {
    let unacked: BTreeSet<String> = engine.needs_attention().into_iter().collect();
    let in_memory = engine.pending_entries();
    let mut items = stale_returns(&engine, &in_memory).await;
    let skip: HashSet<String> = in_memory
        .iter()
        .map(|e| e.head.request_id.clone())
        .collect();
    // An unreadable store lists what memory knows.
    let rows = recorded_rows(&engine, skip).await.unwrap_or_default();
    let now = engine.clock().now_utc();
    for ListRow { row, decided, .. } in rows {
        let Some(d) = decided else { continue };
        if undecided(d.terminal) {
            continue;
        }
        let attention = needs_attention(&d);
        let error_text = match &d.approved_at {
            Some(at) if d.terminal == EventType::WRITE_FAILED && deliverable(at, now) => {
                error_text(&engine, &row.request_id).await
            }
            _ => None,
        };
        items.push(RecentItem {
            acknowledged: attention && !unacked.contains(&row.request_id),
            needs_attention: attention,
            class: class_of(d.op_class.as_deref()),
            instance_alias: row.instance.unwrap_or_default(),
            request_id: row.request_id,
            op_id: row.op_id,
            target_display: row.target_display,
            status: row.status,
            decided_at: d.decided_at,
            error_text,
        });
    }
    items.sort_by(|a, b| {
        b.decided_at
            .cmp(&a.decided_at)
            .then_with(|| a.request_id.cmp(&b.request_id))
    });
    items
}

/// A post-approval failure or unknown outcome (§5.6 attention events).
fn needs_attention(d: &Decided) -> bool {
    matches!(
        d.terminal,
        EventType::WRITE_FAILED | EventType::WRITE_OUTCOME_UNKNOWN
    ) && d.approved_at.is_some()
}

/// The refused write's `error_messages` as the status path reads them (memoized per terminal).
async fn error_text(engine: &Arc<Engine>, request_id: &str) -> Option<String> {
    let rs = engine.status_from_records(request_id).await.ok()??;
    let details = rs.error?.details?;
    let text = details.get("error_messages").and_then(Value::as_str)?;
    Some(cap_error_text(&escape_for_display(text)))
}

/// The writes a stale check returned to the queue, as rows decided when they came back.
async fn stale_returns(
    engine: &Arc<Engine>,
    entries: &[Arc<crate::engine::RequestEntry>],
) -> Vec<RecentItem> {
    let mut out = Vec::new();
    for e in entries {
        let status = {
            let st = e.state();
            if !(st.stale && decidable(st.model.phase())) {
                continue;
            }
            agent_status(&st.model)
        };
        let id = e.head.request_id.clone();
        let headers = engine
            .blocking(move |p| p.headers_for_request(&id))
            .await
            .unwrap_or_default();
        let returned_at = headers
            .iter()
            .rfind(|h| h.event_type == EventType::WRITE_STALE)
            .or(headers.last())
            .map(|h| h.ts_utc.clone())
            .unwrap_or_else(|| e.submitted_at.clone());
        out.push(RecentItem {
            request_id: e.head.request_id.clone(),
            op_id: e.head.op_id.clone(),
            class: e.class(),
            instance_alias: e.head.instance.clone(),
            target_display: e.target_display.clone(),
            status,
            decided_at: returned_at,
            error_text: None,
            needs_attention: true,
            acknowledged: false,
        });
    }
    out
}
