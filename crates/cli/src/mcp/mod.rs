//! `atlas-duck mcp`: the MCP front end (§4.6). Task 3 owns the argv and configuration; the server
//! itself arrives with Task 6.

pub(crate) mod config;

pub(crate) use config::{McpConfig, ToolSet};

/// Serves MCP on stdio; returns the process exit code. A stub until Task 6: it serves nothing and
/// writes nothing to stdout (PD-117).
pub(crate) fn run(cfg: McpConfig) -> i32 {
    let _ = cfg;
    1
}
