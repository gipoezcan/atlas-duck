//! `target_display` (§2.3): built from the agent's params only.

use serde_json::Value;

use crate::model::{OperationSpec, TargetDisplay};

const QUERY_SCALARS: usize = 80;
const MISSING: &str = "?";

pub fn target_display(spec: &OperationSpec, params: &Value) -> String {
    match spec.target_display {
        TargetDisplay::Param(p) | TargetDisplay::CreateIn(p) => scalar(params, p),
        TargetDisplay::Query { param } => {
            let Some(text) = params.get(param).and_then(Value::as_str) else {
                return MISSING.to_string();
            };
            let mut shown: String = text.chars().take(QUERY_SCALARS).collect();
            if text.chars().nth(QUERY_SCALARS).is_some() {
                shown.push('…');
            }
            shown
        }
        TargetDisplay::Pair(a, b) => format!("{} → {}", scalar(params, a), scalar(params, b)),
        TargetDisplay::MoveInto {
            sprint_param,
            issues_param,
        } => {
            let count = params
                .get(issues_param)
                .and_then(Value::as_array)
                .map_or_else(|| MISSING.to_string(), |a| a.len().to_string());
            match sprint_param {
                Some(s) => format!("sprint {} · {count} issues", scalar(params, s)),
                None => format!("backlog · {count} issues"),
            }
        }
        TargetDisplay::None => spec.id.to_string(),
    }
}

/// A string as is, a number or bool without quotes, anything else compact JSON; absent `?`.
fn scalar(params: &Value, key: &str) -> String {
    match params.get(key) {
        None | Some(Value::Null) => MISSING.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}
