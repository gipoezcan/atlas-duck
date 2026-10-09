//! §5.4 step 5 per-op stale rules in M3 (PD-10). The identity call that precedes every write is
//! not one of these (C.7); an op without a rule here has `stale_check: None`.

use atlas_duck_atlassian::GetCall;
use atlas_duck_preview::invisible::escape_for_display;
use serde_json::Value;

use super::confluence::content_version;
use super::jira::{issue_fields_call, transition_calls, transition_facts};
use super::{StaleCtx, StaleRule, StaleVerdict, get_call};

/// Shown when the judge did not get the answers its plan names (fail closed: never `Unchanged`).
const DELTA_UNREADABLE: &str = "the target could not be re-read";

/// `jira.issue.edit`: the current values of exactly the edited fields equal the baseline (the
/// "before" values shown in the diff).
pub static ISSUE_EDIT: StaleRule = StaleRule {
    plan: edit_plan,
    judge: edit_judge,
};

/// `jira.issue.transition`: the current `status.id` equals the from-status **and** the
/// transition is still listed.
pub static ISSUE_TRANSITION: StaleRule = StaleRule {
    plan: transition_plan,
    judge: transition_judge,
};

/// `confluence.page.update`: `version.number` unchanged.
pub static PAGE_UPDATE: StaleRule = StaleRule {
    plan: page_plan,
    judge: page_judge,
};

fn changed(delta: &str) -> StaleVerdict {
    StaleVerdict::Changed {
        delta: escape_for_display(delta),
    }
}

fn baseline_ids(baseline: &Value) -> Vec<String> {
    baseline
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn edit_plan(ctx: &StaleCtx<'_>) -> Vec<GetCall> {
    issue_fields_call(ctx.params, &baseline_ids(ctx.baseline))
        .into_iter()
        .collect()
}

fn edit_judge(ctx: &StaleCtx<'_>, responses: &[Value]) -> StaleVerdict {
    let Some(before) = ctx.baseline.as_object() else {
        return changed(DELTA_UNREADABLE);
    };
    if before.is_empty() {
        return StaleVerdict::Unchanged;
    }
    let Some(now) = responses
        .first()
        .and_then(|r| r.get("fields"))
        .and_then(Value::as_object)
    else {
        return changed(DELTA_UNREADABLE);
    };
    let moved: Vec<&str> = before
        .iter()
        .filter(|(id, was)| now.get(*id).unwrap_or(&Value::Null) != *was)
        .map(|(id, _)| id.as_str())
        .collect();
    if moved.is_empty() {
        StaleVerdict::Unchanged
    } else {
        changed(&format!(
            "fields changed since review: {}",
            moved.join(", ")
        ))
    }
}

fn transition_plan(ctx: &StaleCtx<'_>) -> Vec<GetCall> {
    transition_calls(ctx.params).into()
}

fn transition_judge(ctx: &StaleCtx<'_>, responses: &[Value]) -> StaleVerdict {
    let want = |k: &str| ctx.baseline.get(k).and_then(Value::as_str);
    let (Some((transitions, status)), Some(was_status), Some(transition)) = (
        transition_facts(responses),
        want("status_id"),
        want("transition_id"),
    ) else {
        return changed(DELTA_UNREADABLE);
    };
    if status != was_status {
        return changed("status changed since review");
    }
    let listed = transitions
        .iter()
        .any(|t| t.get("id").and_then(Value::as_str) == Some(transition));
    if !listed {
        return changed("transition no longer available");
    }
    StaleVerdict::Unchanged
}

fn page_plan(ctx: &StaleCtx<'_>) -> Vec<GetCall> {
    vec![get_call(
        "/rest/api/content/{id}",
        ctx.params,
        &[("expand", "version")],
    )]
}

fn page_judge(ctx: &StaleCtx<'_>, responses: &[Value]) -> StaleVerdict {
    let was = ctx.baseline.get("version").and_then(Value::as_u64);
    let now = responses.first().and_then(content_version);
    match (was, now) {
        (Some(was), Some(now)) if was == now => StaleVerdict::Unchanged,
        (Some(was), Some(now)) => changed(&format!(
            "page version changed since review (v{was} → v{now})"
        )),
        _ => changed(DELTA_UNREADABLE),
    }
}
