//! The pure helpers the tool layer shares with the CLI's local commands: the built-in describe
//! environment, the `usage` envelope and the echo cap. The CLI's `local` and `argv` modules
//! re-export them.

use atlas_duck_ipc::envelope::{Envelope, ErrorCode};
use atlas_duck_ipc::sandbox::ScriptLimits;
use atlas_duck_registry::{DescribeEnv, LimitsSource};
use serde_json::Value;

/// The built-in defaults: what `core::gate` answers for a local `ops list`/`ops describe`. The two
/// are pinned to each other by T23's `u05_cli_ops_equal_core`.
pub fn describe_env() -> DescribeEnv {
    DescribeEnv {
        limits_source: LimitsSource::Default,
        available: None,
        caps: Value::Null,
        script_limits: serde_json::to_value(ScriptLimits::default()).unwrap_or(Value::Null),
    }
}

/// A `usage` failure with optional `error.details`.
pub fn usage(message: &str, details: serde_json::Map<String, Value>) -> Envelope {
    let mut env = Envelope::failed(ErrorCode::Usage, false, message);
    if let Some(err) = env.error.as_mut()
        && !details.is_empty()
    {
        err.details = Some(details);
    }
    env
}

/// Longest echo of user text in an error message or detail.
const CLIP_CHARS: usize = 80;

/// `s` cut to `CLIP_CHARS` characters (never mid-character), with `...` when cut. Keeps a huge
/// argument from being echoed whole into an error envelope.
pub fn clip(s: &str) -> String {
    match s.char_indices().nth(CLIP_CHARS) {
        Some((cut, _)) => format!("{}...", &s[..cut]),
        None => s.to_string(),
    }
}
