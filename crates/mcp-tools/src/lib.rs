//! The transport-free part of the M9 MCP front end (§4.6, plan PD-193): the tool catalog, the
//! argument checks and the envelope → tool-result mapping. Shared by `cli` (stdio) and `server`
//! (streamable HTTP); no HTTP and no IPC session.

#![forbid(unsafe_code)]

/// The exit-code rule per kind of call.
pub mod exit;
/// Describe environment, `usage` envelope and echo cap shared with the CLI.
pub mod local;
/// Heartbeat constants of `request_await`.
pub mod progress;
/// Envelope → MCP tool result.
pub mod result;
/// The tool catalog and argument checks.
pub mod tools;
/// Which tool set a front end serves.
pub mod toolset;
