//! The one error type every command answers with (PD-66, §2.4, §10.3).

use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::{AdminError, DecisionError, RELEASE_BLOCKED_INTERNAL, SettingsError};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

/// No free text from Atlassian: every variant is a fixed kind, a static field name or a core error
/// (`DecisionError`, `AdminError`) that serializes a kind and fixed data. One exception:
/// `DecisionError::EditRejected` carries the validator's app-generated message, which can echo
/// values of the user's edit or of the agent's request, bounded and display-escaped by the validator;
/// no secret or path can appear in it. The UI shows it only for an edit, cut to a bounded length and
/// inside `AgentText` after a fixed prefix; every other error it maps from `kind` to fixed strings.
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
    /// `SettingsAdmin` refused or failed (M6 T25): nested like `Admin`, `{"kind": "settings",
    /// "error": {"kind": "invalid", "key": ..}}`. Fixed kinds, keys and the config banner; no text.
    Settings(SettingsError),
    /// M6 T25: the credential window is open for something else (`WindowError::Busy`); close it
    /// first. Nothing was changed.
    Busy,
    /// M5 M-11 (T7 review H1): the candidate could not be built, so a preview or a Raw page has
    /// nothing to show. The text is the core constant, chosen here so the UI never maps an error
    /// kind to it; wire `{"kind": "release_blocked", "text": ..}`.
    ReleaseBlocked,
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
            Self::Settings(_) => "settings",
            Self::Busy => "busy",
            Self::ReleaseBlocked => "release_blocked",
            Self::Internal => "internal",
        }
    }

    /// A refusal of core on a read of the candidate (`preview_fetch`, `raw_page`): `NotApprovable`
    /// there is the rebuild failure of §5.2, shown as the `internal` banner; the rest is as is.
    pub fn from_candidate_read(e: DecisionError) -> Self {
        match e {
            DecisionError::Invalid(InvalidReason::NotApprovable) => Self::ReleaseBlocked,
            other => Self::Decision(other),
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
            Self::Settings(e) => m.serialize_entry("error", e)?,
            Self::ReleaseBlocked => m.serialize_entry("text", RELEASE_BLOCKED_INTERNAL)?,
            Self::NotFound | Self::NotReady | Self::Busy | Self::Internal => {}
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

impl From<SettingsError> for CommandError {
    fn from(e: SettingsError) -> Self {
        Self::Settings(e)
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
            (CommandError::Busy, "busy"),
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
        assert_eq!(
            serde_json::to_value(CommandError::ReleaseBlocked).ok(),
            Some(json!({"kind": "release_blocked", "text": RELEASE_BLOCKED_INTERNAL}))
        );
        // Only a refused read of the candidate becomes the banner; every other refusal is as it was.
        assert_eq!(
            CommandError::from_candidate_read(DecisionError::Invalid(InvalidReason::NotApprovable)),
            CommandError::ReleaseBlocked
        );
        assert_eq!(
            CommandError::from_candidate_read(DecisionError::NotDecidable),
            CommandError::Decision(DecisionError::NotDecidable)
        );
        assert_eq!(
            CommandError::from_candidate_read(DecisionError::Invalid(InvalidReason::NotOpened)),
            CommandError::Decision(DecisionError::Invalid(InvalidReason::NotOpened))
        );
        let admin = CommandError::from(AdminError::NotFound);
        assert_eq!(
            serde_json::to_value(&admin).ok(),
            Some(json!({"kind": "admin", "error": {"kind": "not_found"}}))
        );
        let invalid = CommandError::from(SettingsError::Invalid {
            key: "jira_comments_cap",
        });
        let text = serde_json::to_string(&invalid).unwrap_or_default();
        assert_eq!(text.matches("\"kind\"").count(), 2, "{text}");
        assert_eq!(
            serde_json::to_value(&invalid).ok(),
            Some(json!({"kind": "settings",
                        "error": {"kind": "invalid", "key": "jira_comments_cap"}}))
        );
        assert_eq!(
            CommandError::from(SettingsError::Cancelled).to_string(),
            "settings"
        );
    }
}
