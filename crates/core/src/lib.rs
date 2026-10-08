//! Op table (executors/previewers/stale checks), request lifecycle, approval
//! queue, redaction/edit engine (§2.2).
//!
//! Depends on `registry`, `atlassian`, `convert`, `preview`, `audit` and `ipc`
//! (§2.2). `clippy::unwrap_used` and `clippy::expect_used` are errors here (§7.7).

/// `config.toml` loading, saving and cross-version rules (§7.7, §8.13).
pub mod config;

/// Per-instance HTTP client construction (§7.2, V17).
pub mod http_factory;
/// Proxy resolution (L42) and the per-OS static proxy readers (V17).
pub mod proxy;
