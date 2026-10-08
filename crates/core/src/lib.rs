//! Op table (executors/previewers/stale checks), request lifecycle, approval
//! queue, redaction/edit engine (§2.2).
//!
//! Depends on `registry`, `atlassian`, `convert`, `preview`, `audit` and `ipc`
//! (§2.2). `clippy::unwrap_used` and `clippy::expect_used` are errors here (§7.7).

/// `config.toml` loading, saving and cross-version rules (§7.7, §8.13).
pub mod config;

/// Per-instance HTTP client construction (§7.2, V17).
pub mod http_factory;
/// Request lifecycle: the pure §5.1 state machine model.
pub mod lifecycle;
/// Proxy resolution (L42) and the per-OS static proxy readers (V17).
pub mod proxy;
/// Redaction engine: drops with copies and mirrors, masks in the canonical match form (§5.3).
pub mod redact;
/// Static params validation: schema, field rules, caps, move limit, `min_version` (§2.3, §5.2).
pub mod validate;
