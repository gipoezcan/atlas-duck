//! The one error type every command answers with (PD-66, §2.4, §10.3).

use atlas_duck_core::{AdminError, DecisionError};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

/// No free text from Atlassian or the agent: every variant is a fixed kind, a static field name or
/// a core error that already serializes without content (`DecisionError`, `AdminError`).
///
/// Wire shape: `{"kind": "invalid_argument", "field": "<name>"}`, `{"kind": "not_found"}`,
/// `{"kind": "not_ready"}`, `{"kind": "internal"}`, and the wrapped core errors nested under
/// `error` (`{"kind": "decision", "error": {"kind": "stale", ..}}`, `{"kind": "admin", "error":
/// {..}}`): the core errors carry their own `kind`, so flattening them would repeat the key.
#[derive(Debug, Clone, PartialEq)]
pub enum CommandError {
    /// A value the DTO layer refused before any core call; `field` names the argument.
    InvalidArgument {
        field: &'static str,
    },
    NotFound,
    /// No `Core` serves yet (before first run, locked, starting, or the store failed).
    NotReady,
    Decision(DecisionError),
    Admin(AdminError),
    /// A blocking task died, or a state the command layer cannot explain.
    Internal,
}

impl CommandError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InvalidArgument { .. } => "invalid_argument",
            Self::NotFound => "not_found",
            Self::NotReady => "not_ready",
            Self::Decision(_) => "decision",
            Self::Admin(_) => "admin",
            Self::Internal => "internal",
        }
    }
}

impl Serialize for CommandError {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("kind", self.kind())?;
        match self {
            Self::InvalidArgument { field } => m.serialize_entry("field", field)?,
            Self::Decision(e) => m.serialize_entry("error", e)?,
            Self::Admin(e) => m.serialize_entry("error", e)?,
            Self::NotFound | Self::NotReady | Self::Internal => {}
        }
        m.end()
    }
}

/// The kind (and the refused field) only, like the core errors' `Display`.
impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument { field } => write!(f, "invalid_argument ({field})"),
            other => f.write_str(other.kind()),
        }
    }
}

impl std::error::Error for CommandError {}

impl From<DecisionError> for CommandError {
    fn from(e: DecisionError) -> Self {
        Self::Decision(e)
    }
}

impl From<AdminError> for CommandError {
    fn from(e: AdminError) -> Self {
        Self::Admin(e)
    }
}

#[cfg(test)]
mod tests {
    use atlas_duck_core::CandidateRev;
    use serde_json::json;

    use super::*;

    #[test]
    fn wire_shape_has_one_kind_and_nests_core_errors() {
        let e = CommandError::InvalidArgument { field: "reason" };
        assert_eq!(
            serde_json::to_value(&e).ok(),
            Some(json!({"kind": "invalid_argument", "field": "reason"}))
        );
        for (e, kind) in [
            (CommandError::NotFound, "not_found"),
            (CommandError::NotReady, "not_ready"),
            (CommandError::Internal, "internal"),
        ] {
            assert_eq!(serde_json::to_value(&e).ok(), Some(json!({ "kind": kind })));
        }
        let stale = CommandError::from(DecisionError::Stale {
            current: CandidateRev {
                counter: 2,
                candidate_hash: [0xab; 32],
            },
        });
        // The text form, not a `Value`: a repeated key would survive only there.
        let text = serde_json::to_string(&stale).unwrap_or_default();
        assert_eq!(text.matches("\"kind\"").count(), 2, "{text}");
        assert!(
            text.starts_with(r#"{"kind":"decision","error":{"kind":"stale""#),
            "{text}"
        );
        let admin = CommandError::from(AdminError::NotFound);
        assert_eq!(
            serde_json::to_value(&admin).ok(),
            Some(json!({"kind": "admin", "error": {"kind": "not_found"}}))
        );
    }
}
