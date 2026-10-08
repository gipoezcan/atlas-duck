//! `script.run` (§9): not one of the registry entries, submitted through `script.submit`.

use serde_json::Value;

use crate::model::Similarity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptRunSpec {
    pub id: &'static str,
    pub similarity: Similarity,
    pub target_display_format: &'static str,
}

pub const SCRIPT_RUN: &ScriptRunSpec = &ScriptRunSpec {
    id: "script.run",
    similarity: Similarity::None,
    target_display_format: "script · {lines} lines",
};

/// `script · {lines} lines`, lines = number of `\n` in `source` plus one; a missing source
/// renders `?`.
pub fn script_target_display(params: &Value) -> String {
    let Some(source) = params.get("source").and_then(Value::as_str) else {
        return SCRIPT_RUN.target_display_format.replace("{lines}", "?");
    };
    let lines = source.matches('\n').count() + 1;
    SCRIPT_RUN
        .target_display_format
        .replace("{lines}", &lines.to_string())
}
