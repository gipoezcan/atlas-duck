//! `target_display` (§2.3): built from the agent's params only.

use serde_json::Value;

use crate::model::{OperationSpec, TargetDisplay};

/// §2.3: a query shows its first 80 scalars; every other agent-sourced value is cut the same way.
const MAX_SCALARS: usize = 80;
const MISSING: &str = "?";

pub fn target_display(spec: &OperationSpec, params: &Value) -> String {
    match spec.target_display {
        TargetDisplay::Param(p) | TargetDisplay::CreateIn(p) => scalar(params, p),
        TargetDisplay::Query { param } => match params.get(param).and_then(Value::as_str) {
            Some(text) => sanitize(text),
            None => MISSING.to_string(),
        },
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
/// Always sanitized: the value comes from the agent.
fn scalar(params: &Value, key: &str) -> String {
    match params.get(key) {
        None | Some(Value::Null) => MISSING.to_string(),
        Some(Value::String(s)) => sanitize(s),
        Some(other) => sanitize(&other.to_string()),
    }
}

/// The minimal safe filter for agent text that reaches an approval label or a native dialog:
/// control characters (newlines and tabs included), bidi controls and zero-width characters
/// become spaces, whitespace runs collapse, and the result is cut at 80 scalars plus `…`.
/// The full invisible-character classifier (`preview::invisible`) is out of reach of this
/// dependency-free crate (§2.2); the app applies it where dialog text is built.
fn sanitize(text: &str) -> String {
    let spaced: String = text
        .chars()
        .map(|c| {
            if c.is_control() || is_invisible(c) {
                ' '
            } else {
                c
            }
        })
        .collect();
    let collapsed = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut shown: String = collapsed.chars().take(MAX_SCALARS).collect();
    if collapsed.chars().nth(MAX_SCALARS).is_some() {
        shown.push('…');
    }
    shown
}

fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{061C}'
            | '\u{FEFF}'
    )
}
