//! Script limits (spec §9.4 keys and defaults), shared by `core::validate`, the CLI's
//! `--limits` and the worker.

use serde::{Deserialize, Serialize};

/// A partial `--limits` object parses (absent keys take the defaults); an unknown key is an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ScriptLimits {
    pub timeout_s: u32,
    pub heap_mb: u32,
    pub process_mb: u32,
    pub max_calls: u32,
    pub max_fetch_mb: u32,
    pub max_call_result_mb: u32,
    pub max_result_mb: u32,
    pub max_concurrent_calls: u32,
}

impl Default for ScriptLimits {
    fn default() -> Self {
        ScriptLimits {
            timeout_s: 120,
            heap_mb: 256,
            process_mb: 512,
            max_calls: 200,
            max_fetch_mb: 50,
            max_call_result_mb: 16,
            max_result_mb: 16,
            max_concurrent_calls: 4,
        }
    }
}
