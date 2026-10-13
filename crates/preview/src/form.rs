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
    /// At most [`CHOICE_MAX_VALUES`] values; [`AllowedValues`] cannot be built past the cap.
    Choice(AllowedValues),
}

/// The allowed values of a `Choice`; the field is private so the cap cannot be bypassed.
/// Serializes as `{"allowed_values": [..]}` (flattened into the `Choice` tag object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AllowedValues {
    allowed_values: Vec<String>,
}

impl AllowedValues {
    /// Truncated to [`CHOICE_MAX_VALUES`] values.
    pub fn new(mut values: Vec<String>) -> AllowedValues {
        values.truncate(CHOICE_MAX_VALUES);
        AllowedValues {
            allowed_values: values,
        }
    }

    pub fn as_slice(&self) -> &[String] {
        &self.allowed_values
    }
}

impl InputKind {
    /// A `Choice` truncated to [`CHOICE_MAX_VALUES`] values.
    pub fn choice(values: Vec<String>) -> InputKind {
        InputKind::Choice(AllowedValues::new(values))
    }
}
