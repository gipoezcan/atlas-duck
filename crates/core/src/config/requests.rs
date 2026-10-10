//! Typed `[requests]` accessors for `config.toml` (§4.4 expiry, Settings).
//!
//! `expiry_hours` is how long a request may stay pending before it expires: whole hours in
//! `1..=168`, absent = 24. A malformed value makes the table an error naming the key (never
//! echoing the value); the core then runs with the default.

use std::fmt;
use std::time::Duration;

use super::ConfigState;

/// The `config.toml` table holding the request settings.
pub const KEY_REQUESTS: &str = "requests";
/// §4.4: hours before a pending request expires.
pub const KEY_EXPIRY_HOURS: &str = "expiry_hours";
/// The default expiry (§4.4).
pub const DEFAULT_EXPIRY_HOURS: u64 = 24;
/// The accepted range of `expiry_hours`.
pub const EXPIRY_HOURS_RANGE: std::ops::RangeInclusive<u64> = 1..=168;

/// Why `[requests]` cannot be used. No value from the file is echoed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestsError {
    /// `requests` is not a table.
    NotATable,
    Malformed {
        key: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for RequestsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotATable => f.write_str("config.toml: requests must be a [requests] table"),
            Self::Malformed { key, reason } => write!(f, "config.toml: requests.{key}: {reason}"),
        }
    }
}

impl std::error::Error for RequestsError {}

/// The configured `expiry_hours`; `None` for an absent or unreadable config, table or key.
pub fn expiry_hours(cfg: &ConfigState) -> Result<Option<u64>, RequestsError> {
    let doc = match cfg {
        ConfigState::Writable(c) | ConfigState::ReadOnly { config: c, .. } => c.document(),
        ConfigState::Absent | ConfigState::Unreadable { .. } => return Ok(None),
    };
    let Some(item) = doc.get(KEY_REQUESTS) else {
        return Ok(None);
    };
    let table = item.as_table_like().ok_or(RequestsError::NotATable)?;
    let Some(v) = table.get(KEY_EXPIRY_HOURS) else {
        return Ok(None);
    };
    v.as_integer()
        .and_then(|h| u64::try_from(h).ok())
        .filter(|h| EXPIRY_HOURS_RANGE.contains(h))
        .map(Some)
        .ok_or(RequestsError::Malformed {
            key: KEY_EXPIRY_HOURS,
            reason: "must be a whole number of hours from 1 to 168",
        })
}

/// The expiry as a duration: the configured hours, else 24 h (also for a malformed table).
pub fn expiry(cfg: &ConfigState) -> Duration {
    let hours = expiry_hours(cfg)
        .ok()
        .flatten()
        .unwrap_or(DEFAULT_EXPIRY_HOURS);
    Duration::from_secs(hours * 3600)
}
