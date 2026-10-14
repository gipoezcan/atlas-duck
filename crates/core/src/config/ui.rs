//! Typed `[ui]` accessors for `config.toml` (§5.6 attention modes, Settings; M6 Δ6).
//!
//! `attention_mode` is how a new pending request asks for the user's attention:
//! `show_without_activating` | `badge_only` | `show_and_focus`; absent = the first. A malformed
//! value makes the table an error naming the key (never echoing the value); the app then runs
//! with the default.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::ConfigState;

/// The `config.toml` table holding the UI settings.
pub const KEY_UI: &str = "ui";
/// §5.6: the attention mode.
pub const KEY_ATTENTION_MODE: &str = "attention_mode";

/// §5.6: what a new pending request does to the Approvals window. Not security-weakening
/// (§10.3): a missed request fails closed (it waits or expires).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionMode {
    /// The window is shown without taking the focus (the default).
    #[default]
    ShowWithoutActivating,
    /// Only the tray badge and the coalesced toast.
    BadgeOnly,
    /// The window is shown and focused (the unrequested-focus input guard applies).
    ShowAndFocus,
}

impl AttentionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShowWithoutActivating => "show_without_activating",
            Self::BadgeOnly => "badge_only",
            Self::ShowAndFocus => "show_and_focus",
        }
    }

    pub fn parse(s: &str) -> Option<AttentionMode> {
        [
            Self::ShowWithoutActivating,
            Self::BadgeOnly,
            Self::ShowAndFocus,
        ]
        .into_iter()
        .find(|m| m.as_str() == s)
    }
}

/// Why `[ui]` cannot be used. No value from the file is echoed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiError {
    /// `ui` is not a table.
    NotATable,
    Malformed {
        key: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for UiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotATable => f.write_str("config.toml: ui must be a [ui] table"),
            Self::Malformed { key, reason } => write!(f, "config.toml: ui.{key}: {reason}"),
        }
    }
}

impl std::error::Error for UiError {}

/// The configured attention mode; `None` for an absent or unreadable config, table or key.
pub fn attention_mode_config(cfg: &ConfigState) -> Result<Option<AttentionMode>, UiError> {
    let doc = match cfg {
        ConfigState::Writable(c) | ConfigState::ReadOnly { config: c, .. } => c.document(),
        ConfigState::Absent | ConfigState::Unreadable { .. } => return Ok(None),
    };
    let Some(item) = doc.get(KEY_UI) else {
        return Ok(None);
    };
    let table = item.as_table_like().ok_or(UiError::NotATable)?;
    let Some(v) = table.get(KEY_ATTENTION_MODE) else {
        return Ok(None);
    };
    v.as_str()
        .and_then(AttentionMode::parse)
        .map(Some)
        .ok_or(UiError::Malformed {
            key: KEY_ATTENTION_MODE,
            reason: "must be show_without_activating, badge_only or show_and_focus",
        })
}

/// The attention mode in force: the configured one, else the default (also for a malformed
/// table).
pub fn attention_mode(cfg: &ConfigState) -> AttentionMode {
    attention_mode_config(cfg)
        .ok()
        .flatten()
        .unwrap_or_default()
}
