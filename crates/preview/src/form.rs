//! The edit-form model (§5.4 step 4): the Rust side of what the approvals UI renders for "edit
//! before approve". Display text and values only; core builds it, M6 renders it.

use serde::Serialize;
use serde_json::Value;

/// Most allowed values a `Choice` carries.
pub const CHOICE_MAX_VALUES: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EditForm {
    pub inputs: Vec<EditInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EditInput {
    /// A param name, or `fields.<id>` for a Jira field.
    pub path: String,
    pub label: String,
    pub kind: InputKind,
    /// Target params and conflict baselines (L06): shown, not editable.
    pub read_only: bool,
    pub required: bool,
    /// Added by enrichment (a missing required field), not part of the agent's request.
    pub pre_added: bool,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InputKind {
    Text,
    LongText,
    Integer,
    Boolean,
    Json,
    /// At most [`CHOICE_MAX_VALUES`] values; build with [`InputKind::choice`].
    Choice {
        allowed_values: Vec<String>,
    },
}

impl InputKind {
    /// A `Choice` truncated to [`CHOICE_MAX_VALUES`] values.
    pub fn choice(mut allowed_values: Vec<String>) -> InputKind {
        allowed_values.truncate(CHOICE_MAX_VALUES);
        InputKind::Choice { allowed_values }
    }
}
