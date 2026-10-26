//! Server mode (spec addendum SM-1.2): one axum binary that serves the web UI, the HTTP API and
//! remote MCP on one origin, with per-user M2 stores under a master key.

#![forbid(unsafe_code)]

// `testing` carries the in-memory store and test constructors; a release build never has it.
#[cfg(all(feature = "testing", not(debug_assertions)))]
compile_error!("testing must never reach a release build");

pub mod anchor;
pub mod api_keys;
pub mod audit_kinds;
pub mod cli;
pub mod clock;
pub mod cmd;
pub mod config;
pub mod credentials;
pub mod csrf;
pub mod directory;
pub mod errors;
pub mod health;
pub mod instances;
pub mod keystore;
pub mod log;
pub mod login;
pub mod master_key;
pub mod mcp;
pub mod ratelimit;
pub mod runtime;
pub mod session;
pub mod sse;
pub mod static_files;
pub mod store;
pub mod users;
pub mod web;
