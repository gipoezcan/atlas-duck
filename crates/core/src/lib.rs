//! Op table (executors/previewers/stale checks), request lifecycle, approval
//! queue, redaction/edit engine (§2.2).
//!
//! Depends on `registry`, `atlassian`, `convert`, `preview`, `audit` and `ipc`
//! (§2.2). `clippy::unwrap_used` and `clippy::expect_used` are errors here (§7.7).

/// The one path to the audit store, the committed set behind the audit cover, the date bridge
/// (§5.1 inv. 1, §8.8, C.3).
pub mod audit_port;
/// `config.toml` loading, saving and cross-version rules (§7.7, §8.13).
pub mod config;
/// The composition root: `CoreDeps`, `Core`, `NativeConfirmer` (C.7).
mod core;
/// The PAT in the OS keychain (PD-05, §7.1).
pub mod credentials;
/// The decision API (C.7, §5.6): queue rows, previews, decisions.
pub mod decision;

/// Edit engine: immutable targets and baselines, `executed_params`, `edited_keys` (§5.4 step 4).
pub mod edit;
/// The request broker: entries, sessions, the `RequestHandler` impl and its envelopes.
pub mod engine;
/// Serving without a store: `GateState`, `gate_handler`, the shared `hello` check (§2.5, L46).
pub mod gate;
/// Per-instance HTTP client construction (§7.2, V17).
pub mod http_factory;
/// Request, instance, batch and system-fetch ids.
pub mod ids;
/// The instance runtime table (routing, PD-01…PD-03) and `InstanceAdmin` (C.7).
pub mod instances;
/// Request lifecycle: the pure §5.1 state machine model.
pub mod lifecycle;
/// Agent-string normalization at `hello`/submit (§3.3, C.0).
pub mod normalize;
/// The op table: an `OpImpl` per registry id, read plans, write executors, enrichment and stale
/// rules, previewers (§2.3, PD-09, PD-10).
pub mod ops;
/// §8.3 payload builders.
pub mod payloads;
/// Proxy resolution (L42) and the per-OS static proxy readers (V17).
pub mod proxy;
/// Redaction engine: drops with copies and mirrors, masks in the canonical match form (§5.3).
pub mod redact;
/// The "possible duplicate" and "similar request" flags and their RF-4 seeding (§5.6, L45).
pub mod similarity;
/// Static params validation: schema, field rules, caps, move limit, `min_version` (§2.3, §5.2).
pub mod validate;

/// Test doubles over a real temp-dir store (feature `testing`, never in a release build).
#[cfg(feature = "testing")]
pub mod testing;

pub use crate::core::{Confirm, Core, CoreDeps, NativeConfirmer, ShutdownReason, StartError};
#[cfg(feature = "testing")]
pub use crate::core::{HookPoint, Pause, TestHooks};
pub use atlas_duck_preview::CandidateRev;
pub use credentials::KeychainCredentials;
pub use decision::{
    BatchFailure, BatchItem, BatchOutcome, Decision, DecisionApi, DecisionError, DecisionKind,
    DecisionOutcome, DenyDetails, PreviewDelivery, QueueItem, RawPage, SessionKey,
};
pub use edit::Edits;
pub use gate::{
    AttentionKind, GateHandler, GateState, MSG_FIRST_RUN, UiEvent, UiSink, gate_handler,
    hello_check, ops_describe_local, ops_list_local,
};
pub use instances::{
    AddInstance, AdminError, ConnectionFailure, ConnectionReport, InstanceAdmin, InstanceView,
};
pub use ops::{OpImpl, op_table};
pub use redact::{DropScope, RedactionOp, RedactionPreset, UrlMode};
