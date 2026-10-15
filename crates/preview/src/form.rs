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
    /// A decimal number (a JSON-schema or createmeta `number`; `Integer` only where the schema
    /// says `integer`).
    Number,
    Boolean,
    Json,
    /// At most [`CHOICE_MAX_VALUES`] values; [`AllowedValues`] cannot be built past the cap.
    Choice(AllowedValues),
}

/// The allowed values of a `Choice`; the fields are private so the cap cannot be bypassed.
/// Serializes as `{"allowed_values": [..]}` (flattened into the `Choice` tag object): the labels
/// only. The UI sends the picked label back; core maps it to its wire value ([`Self::wire_for`]),
/// which never leaves core (T12 review I1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AllowedValues {
    allowed_values: Vec<String>,
    /// The input takes a list of labels (an `array` field, M5 M-12) instead of one; written only
    /// when set, so a single pick keeps its shape.
    #[serde(skip_serializing_if = "is_false")]
    multiple: bool,
    /// The value each label stands for in the request, by position; `None` when none can be
    /// derived (a pick of it is refused).
    #[serde(skip)]
    wire: Vec<Option<Value>>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Why a picked label has no wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChoiceRefusal {
    /// Not one of the labels.
    NotListed,
    /// More than one value is shown with this label.
    Ambiguous,
    /// The value has no wire form.
    NoWireValue,
}

impl AllowedValues {
    /// Labels without wire values (every pick is refused); truncated to [`CHOICE_MAX_VALUES`].
    pub fn new(values: Vec<String>) -> AllowedValues {
        AllowedValues::with_wire(values.into_iter().map(|v| (v, None)).collect())
    }

    /// `(label, wire value)` pairs, truncated to [`CHOICE_MAX_VALUES`].
    pub fn with_wire(mut pairs: Vec<(String, Option<Value>)>) -> AllowedValues {
        pairs.truncate(CHOICE_MAX_VALUES);
        let (allowed_values, wire) = pairs.into_iter().unzip();
        AllowedValues {
            allowed_values,
            multiple: false,
            wire,
        }
    }

    /// The same choice as a multi-pick: the UI sends a list of labels.
    #[must_use]
    pub fn into_multiple(mut self) -> AllowedValues {
        self.multiple = true;
        self
    }

    pub fn is_multiple(&self) -> bool {
        self.multiple
    }

    pub fn as_slice(&self) -> &[String] {
        &self.allowed_values
    }

    /// The wire value of the one entry shown as `label`.
    pub fn wire_for(&self, label: &str) -> Result<&Value, ChoiceRefusal> {
        let mut hits = self
            .allowed_values
            .iter()
            .zip(&self.wire)
            .filter(|(l, _)| l.as_str() == label);
        match (hits.next(), hits.next()) {
            (None, _) => Err(ChoiceRefusal::NotListed),
            (Some(_), Some(_)) => Err(ChoiceRefusal::Ambiguous),
            (Some((_, wire)), None) => wire.as_ref().ok_or(ChoiceRefusal::NoWireValue),
        }
    }
}

impl InputKind {
    /// A `Choice` truncated to [`CHOICE_MAX_VALUES`] values.
    pub fn choice(values: Vec<String>) -> InputKind {
        InputKind::Choice(AllowedValues::new(values))
    }

    /// A `Choice` of `(label, wire value)` pairs truncated to [`CHOICE_MAX_VALUES`].
    pub fn choice_with_wire(pairs: Vec<(String, Option<Value>)>) -> InputKind {
        InputKind::Choice(AllowedValues::with_wire(pairs))
    }

    /// Like [`Self::choice_with_wire`], for an `array` field: the input takes a list of labels.
    pub fn multi_choice_with_wire(pairs: Vec<(String, Option<Value>)>) -> InputKind {
        InputKind::Choice(AllowedValues::with_wire(pairs).into_multiple())
    }
}
