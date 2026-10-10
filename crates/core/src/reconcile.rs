//! The start of `Core` that is not the engine (Task 28): the audit policy `config.toml` asks for
//! (X-01, §8.8), the crash reconciliation (§11.3), the `APP_START` record (§8.3, PD-21) and the
//! records that a restore or recovery owes (PD-28).
//!
//! The §11.3 predicate itself is the store's (`Store::reconcile_after_crash`, M2 Q1); this module
//! only calls it and shapes what `Core` reports.

use atlas_duck_audit::{AuditError, FilePolicy, NewEvent};
use serde_json::{Map, Value, json};
use toml_edit::Item;

use crate::audit_port::AuditPort;
use crate::config::ConfigState;
use crate::payloads;

/// The `config.toml` table holding the audit policy the file may ask for (§8.8): the store is
/// authoritative, the file only requests.
pub const KEY_AUDIT: &str = "audit";
/// `[audit] retention_days`: a whole number of days (the store raises it to its minimum).
pub const KEY_RETENTION_DAYS: &str = "retention_days";
/// `[audit] legal_hold`: a boolean.
pub const KEY_LEGAL_HOLD: &str = "legal_hold";
/// `[audit] anchor_dir`: a path; an empty string asks for no anchor directory.
pub const KEY_ANCHOR_DIR: &str = "anchor_dir";

/// The `UiEvent::StatusBanner` line asking the user to check the targets of writes whose outcome
/// is unknown (§11.3).
pub const LINE_CHECK_TARGET: &str = "check_target";

/// What `[audit]` of `config.toml` asks for. A key that is missing, or malformed (the key is
/// named in the log, never its value), asks for nothing; an unreadable or absent file too.
pub fn file_policy(cfg: &ConfigState) -> FilePolicy {
    let doc = match cfg {
        ConfigState::Writable(c) | ConfigState::ReadOnly { config: c, .. } => c.document(),
        ConfigState::Absent | ConfigState::Unreadable { .. } => return FilePolicy::default(),
    };
    let Some(table) = doc.get(KEY_AUDIT).and_then(Item::as_table_like) else {
        if doc.get(KEY_AUDIT).is_some() {
            tracing::warn!("config.toml: [audit] is not a table; ignored");
        }
        return FilePolicy::default();
    };
    let mut p = FilePolicy::default();
    if let Some(item) = table.get(KEY_RETENTION_DAYS) {
        match item
            .as_integer()
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| *v > 0)
        {
            Some(days) => p.retention_days = Some(days),
            None => tracing::warn!("config.toml: audit.retention_days is malformed; ignored"),
        }
    }
    if let Some(item) = table.get(KEY_LEGAL_HOLD) {
        match item.as_bool() {
            Some(on) => p.legal_hold = Some(on),
            None => tracing::warn!("config.toml: audit.legal_hold is malformed; ignored"),
        }
    }
    if let Some(item) = table.get(KEY_ANCHOR_DIR) {
        match item.as_str() {
            Some("") => p.anchor_dir = Some(None),
            Some(dir) => p.anchor_dir = Some(Some(dir.to_owned())),
            None => tracing::warn!("config.toml: audit.anchor_dir is malformed; ignored"),
        }
    }
    p
}

/// X-01 (§8.8), blocking: logs the file's differences and lets prune run in this process. A
/// failure is not a reason to refuse the start (the file is not authoritative): it is reported,
/// prune stays blocked, and the next start tries again.
pub fn reconcile_config_file(port: &dyn AuditPort, cfg: &ConfigState) {
    if port.reconcile_config_file(&file_policy(cfg)).is_err() {
        tracing::warn!("the config file policy could not be reconciled; prune stays blocked");
    }
}

/// `APP_START {install_id, app_version, ..extra, effective_proxy, config_read_only?,
/// pats_deleted?, similarity_seed_skipped?}` (PD-21, PD-28). The fields the core knows win over the app's `extra`.
pub fn app_start_event(
    install_id: &str,
    extra: &Map<String, Value>,
    cfg: &ConfigState,
    effective_proxy: Map<String, Value>,
    similarity_seed_skipped: u64,
    pats_deleted: &[String],
) -> NewEvent {
    let mut extra = extra.clone();
    extra.insert("effective_proxy".into(), Value::Object(effective_proxy));
    if let Some(info) = cfg.read_only_info() {
        extra.insert(
            "config_read_only".into(),
            json!({ "schema_version": info.schema_version, "parsed": info.parsed }),
        );
    }
    if !pats_deleted.is_empty() {
        extra.insert("pats_deleted".into(), json!(pats_deleted));
    }
    if similarity_seed_skipped > 0 {
        extra.insert(
            "similarity_seed_skipped".into(),
            json!(similarity_seed_skipped),
        );
    }
    payloads::app_start(install_id, &extra)
}

/// One `INSTANCE_STATE_CHANGED {state: needs_token}` per instance whose PAT a restore or recovery
/// deleted (M2 handoff (b), PD-28), in order; stops at the first failure.
pub fn log_pats_deleted(port: &dyn AuditPort, ids: &[String]) -> Result<(), AuditError> {
    for id in ids {
        let mut details = Map::new();
        details.insert("reason".into(), "pat_deleted".into());
        port.append(payloads::instance_state_changed(
            id,
            "needs_token",
            &details,
        ))?;
    }
    Ok(())
}
