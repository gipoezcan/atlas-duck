//! Typed `[scripts]` accessors for `config.toml` (§9.4 "Defaults configurable in Settings", PD-139).
//!
//! The eight §9.4 keys, `timeout_s`, `heap_mb`, `process_mb`, `max_calls`, `max_fetch_mb`,
//! `max_call_result_mb`, `max_result_mb` and `max_concurrent_calls`, each a whole number; absent =
//! the spec default (`ScriptLimits::default()`). The configured set is the ceiling of an agent's
//! `--limits` and the `script_limits` of `ops describe --instance`.
//!
//! Every value is bounded, the upper bounds by the spec's fixed caps first: the two result keys
//! at 16 (§3.4 caps host -> worker frames at 24 MiB, and `registry::RELEASE_CAP_BYTES` is 16 MiB),
//! `max_concurrent_calls` in 1..=16 and the other five in 1..=4 x the spec default. The resulting
//! set must also keep both §9.4 memory invariants (`validate::check_script_invariants`).
//!
//! A malformed or out-of-range value, or a set that breaks an invariant, makes the table an error
//! naming the key, never echoing the value; the core then runs with the spec defaults (fail safe,
//! as for `[limits]`). Settings applies the same bounds to its change ([`bound`]).

use std::fmt;
use std::ops::RangeInclusive;

use atlas_duck_ipc::sandbox::ScriptLimits;

use super::ConfigState;
use crate::validate::check_script_invariants;

/// The `config.toml` table holding the script limits.
pub const KEY_SCRIPTS: &str = "scripts";

/// The eight §9.4 keys, in §9.4 order (the order of `ScriptLimits`' fields).
pub const SCRIPT_KEYS: [&str; 8] = [
    "timeout_s",
    "heap_mb",
    "process_mb",
    "max_calls",
    "max_fetch_mb",
    "max_call_result_mb",
    "max_result_mb",
    "max_concurrent_calls",
];

/// The accepted values of `key` (PD-139), or `None` for a name that is not a script limit.
pub fn bound(key: &str) -> Option<RangeInclusive<u32>> {
    let d = ScriptLimits::default();
    let top = match key {
        "timeout_s" => d.timeout_s * 4,
        "heap_mb" => d.heap_mb * 4,
        "process_mb" => d.process_mb * 4,
        "max_calls" => d.max_calls * 4,
        "max_fetch_mb" => d.max_fetch_mb * 4,
        "max_call_result_mb" | "max_result_mb" | "max_concurrent_calls" => 16,
        _ => return None,
    };
    Some(1..=top)
}

/// `key`'s value in `l`.
pub fn get(l: &ScriptLimits, key: &str) -> Option<u32> {
    Some(match key {
        "timeout_s" => l.timeout_s,
        "heap_mb" => l.heap_mb,
        "process_mb" => l.process_mb,
        "max_calls" => l.max_calls,
        "max_fetch_mb" => l.max_fetch_mb,
        "max_call_result_mb" => l.max_call_result_mb,
        "max_result_mb" => l.max_result_mb,
        "max_concurrent_calls" => l.max_concurrent_calls,
        _ => return None,
    })
}

/// Sets `key` in `l`; `false` for a name that is not a script limit.
pub fn set(l: &mut ScriptLimits, key: &str, v: u32) -> bool {
    let slot = match key {
        "timeout_s" => &mut l.timeout_s,
        "heap_mb" => &mut l.heap_mb,
        "process_mb" => &mut l.process_mb,
        "max_calls" => &mut l.max_calls,
        "max_fetch_mb" => &mut l.max_fetch_mb,
        "max_call_result_mb" => &mut l.max_call_result_mb,
        "max_result_mb" => &mut l.max_result_mb,
        "max_concurrent_calls" => &mut l.max_concurrent_calls,
        _ => return false,
    };
    *slot = v;
    true
}

/// Why `[scripts]` cannot be used. No value from the file is echoed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptsError {
    /// `scripts` is not a table.
    NotATable,
    /// A value that is not a whole number in the key's bounds.
    Malformed { key: &'static str },
    /// The set as a whole breaks a §9.4 memory invariant; `key` is the limit that is too low.
    Invariant {
        key: &'static str,
        message: &'static str,
    },
}

impl fmt::Display for ScriptsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotATable => f.write_str("config.toml: scripts must be a [scripts] table"),
            Self::Malformed { key } => {
                write!(
                    f,
                    "config.toml: scripts.{key}: must be a whole number within its bounds"
                )
            }
            Self::Invariant { key, message } => write!(f, "config.toml: scripts.{key}: {message}"),
        }
    }
}

impl std::error::Error for ScriptsError {}

/// The limits the core starts with: the configured set, or the spec defaults. A refused table is
/// logged (the key and the reason class, never a value, as `reconcile` does for `[audit]`):
/// the whole table falls back, so a hand-set cap would otherwise drop without a trace.
pub fn start_limits(cfg: &ConfigState) -> ScriptLimits {
    scripts_config(cfg).unwrap_or_else(|e| {
        tracing::warn!("{e}; the script limits run with the spec defaults");
        ScriptLimits::default()
    })
}

/// The configured script limits: the spec defaults with the `[scripts]` keys applied; the defaults
/// for an absent or unreadable config or a missing table.
pub fn scripts_config(cfg: &ConfigState) -> Result<ScriptLimits, ScriptsError> {
    let doc = match cfg {
        ConfigState::Writable(c) | ConfigState::ReadOnly { config: c, .. } => c.document(),
        ConfigState::Absent | ConfigState::Unreadable { .. } => {
            return Ok(ScriptLimits::default());
        }
    };
    let Some(item) = doc.get(KEY_SCRIPTS) else {
        return Ok(ScriptLimits::default());
    };
    let table = item.as_table_like().ok_or(ScriptsError::NotATable)?;
    let mut out = ScriptLimits::default();
    for key in SCRIPT_KEYS {
        let Some(item) = table.get(key) else {
            continue;
        };
        let value = item
            .as_integer()
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| bound(key).is_some_and(|b| b.contains(v)))
            .ok_or(ScriptsError::Malformed { key })?;
        set(&mut out, key, value);
    }
    if let Err(v) = check_script_invariants(&out) {
        return Err(ScriptsError::Invariant {
            key: v.key(),
            message: v.message(),
        });
    }
    Ok(out)
}
