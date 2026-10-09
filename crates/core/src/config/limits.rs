//! Typed `[limits]` accessors for `config.toml` (§5.2 memory budget, Settings).
//!
//! Keys: `max_pending_bytes_mb` (the optional admission cap on the sum of static reservations;
//! absent = off) and `candidate_cache_mb` (the candidate LRU; absent = 512). Both are whole MiB in
//! `1..=MAX_LIMIT_MB`. The pending-count limits (32 per agent key, 256 total, §3.3) and the 8
//! fetch slots are fixed by the spec and have no key.
//!
//! A malformed value makes the table an error naming the key, never echoing the value; the core
//! then runs with the defaults (fail safe: the defaults are the spec's limits).

use std::fmt;

use toml_edit::Item;

use super::ConfigState;

/// The `config.toml` table holding the limits.
pub const KEY_LIMITS: &str = "limits";
/// §5.2: the optional admission cap, in MiB.
pub const KEY_MAX_PENDING_BYTES_MB: &str = "max_pending_bytes_mb";
/// §5.2: the candidate LRU size, in MiB.
pub const KEY_CANDIDATE_CACHE_MB: &str = "candidate_cache_mb";
/// The largest accepted value of either key (1 TiB): bounds the MiB-to-bytes product.
pub const MAX_LIMIT_MB: u64 = 1 << 20;

/// What `[limits]` says; `None` = the key is absent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LimitsConfig {
    pub max_pending_bytes_mb: Option<u64>,
    pub candidate_cache_mb: Option<u64>,
}

/// Why `[limits]` cannot be used. No value from the file is echoed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitsError {
    /// `limits` is not a table.
    NotATable,
    Malformed {
        key: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotATable => f.write_str("config.toml: limits must be a [limits] table"),
            Self::Malformed { key, reason } => write!(f, "config.toml: limits.{key}: {reason}"),
        }
    }
}

impl std::error::Error for LimitsError {}

fn mb(item: Option<&Item>, key: &'static str) -> Result<Option<u64>, LimitsError> {
    let Some(item) = item else {
        return Ok(None);
    };
    item.as_integer()
        .and_then(|v| u64::try_from(v).ok())
        .filter(|v| (1..=MAX_LIMIT_MB).contains(v))
        .map(Some)
        .ok_or(LimitsError::Malformed {
            key,
            reason: "must be a whole number of MiB from 1 to 1048576",
        })
}

/// The `[limits]` keys; all `None` for an absent or unreadable config or a missing table.
pub fn limits_config(cfg: &ConfigState) -> Result<LimitsConfig, LimitsError> {
    let doc = match cfg {
        ConfigState::Writable(c) | ConfigState::ReadOnly { config: c, .. } => c.document(),
        ConfigState::Absent | ConfigState::Unreadable { .. } => {
            return Ok(LimitsConfig::default());
        }
    };
    let Some(item) = doc.get(KEY_LIMITS) else {
        return Ok(LimitsConfig::default());
    };
    let table = item.as_table_like().ok_or(LimitsError::NotATable)?;
    Ok(LimitsConfig {
        max_pending_bytes_mb: mb(
            table.get(KEY_MAX_PENDING_BYTES_MB),
            KEY_MAX_PENDING_BYTES_MB,
        )?,
        candidate_cache_mb: mb(table.get(KEY_CANDIDATE_CACHE_MB), KEY_CANDIDATE_CACHE_MB)?,
    })
}
