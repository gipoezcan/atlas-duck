//! The approvals commands over HTTP (`POST /api/cmd/{command}`, SM-5.1, PD-205): the desktop
//! command set the approvals page needs, minus every command that would ask `NativeConfirmer`
//! (PD-197; `decide_batch` confirms natively on desktop and is therefore not served). Each
//! dispatches to the same `DecisionApi` call as the desktop command, with the shared wire DTOs
//! (`core::decision::wire`) and their `deny_unknown_fields` parsing. Errors are the desktop
//! `CommandError` JSON, so the shared UI code handles them unchanged.

use std::sync::Arc;

use atlas_duck_audit::Store;
use atlas_duck_core::Lang;
use atlas_duck_core::decision::DecisionApi;
use atlas_duck_core::decision::audit_wire::{
    self, AuditPayloadArgs, AuditQueryArgs, AuditReadError, AuditStatusArgs, AuditTrailArgs,
    Platform,
};
use atlas_duck_core::decision::wire::{
    AcknowledgeAttentionArgs, AppStatusArgs, DecideArgs, DenyBatchArgs, DenyCount, DenySessionArgs,
    PreviewFetchArgs, QueueDetail, QueueGetArgs, QueueListArgs, RawPageArgs, RawPageError,
    RecentListArgs, RedactionPreviewArgs, StatusLineDto, parse, preview_fetch_response,
    raw_page_response,
};
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::{DecisionError, RELEASE_BLOCKED_INTERNAL};
use axum::http::StatusCode;
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::Value;

/// PD-197 / T16: the served commands (all desktop `commands::names` entries).
pub const SERVER_COMMANDS: &[&str] = &[
    "queue_list",
    "queue_get",
    "recent_list",
    "acknowledge_attention",
    "app_status",
    "decide",
    "deny_batch",
    "deny_session",
    "redaction_preview",
    "preview_fetch",
    "raw_page",
    // M14 T16 (PD-251, SM-6.4): the user's own chain, read-only (no native confirmation).
    "audit_query",
    "audit_trail",
    "audit_payload",
    "audit_status",
];

/// The audit reads of [`SERVER_COMMANDS`]: answered from the user's own store, never a
/// `DecisionApi` call.
pub const AUDIT_COMMANDS: &[&str] = &[
    "audit_query",
    "audit_trail",
    "audit_payload",
    "audit_status",
];

/// The desktop `CommandError` wire shape for the kinds these commands answer.
#[derive(Debug, Clone, PartialEq)]
pub enum CmdError {
    InvalidArgument {
        field: &'static str,
    },
    NotFound,
    Decision(DecisionError),
    ReleaseBlocked,
    /// No such command here (404, `{"kind": "not_found", "code": "api/unknown_command"}`).
    UnknownCommand,
    /// M14: the store is closed (`{"kind": "not_ready"}`, as on desktop).
    NotReady,
    /// M14: an audit read failed (`{"kind": "audit", "error": {"kind": "unreadable", "seq"}}` or
    /// `{"kind": "failed"}`, the desktop's `AuditReadFailure`).
    AuditUnreadable {
        seq: u64,
    },
    AuditFailed,
    Internal,
}

impl From<AuditReadError> for CmdError {
    fn from(e: AuditReadError) -> CmdError {
        match e {
            AuditReadError::InvalidArgument { field } => CmdError::InvalidArgument { field },
            AuditReadError::NotFound => CmdError::NotFound,
            AuditReadError::NotReady => CmdError::NotReady,
            AuditReadError::Unreadable { seq } => CmdError::AuditUnreadable { seq },
            AuditReadError::Failed => CmdError::AuditFailed,
        }
    }
}

impl CmdError {
    pub fn status(&self) -> StatusCode {
        match self {
            CmdError::InvalidArgument { .. } => StatusCode::BAD_REQUEST,
            CmdError::NotFound | CmdError::UnknownCommand => StatusCode::NOT_FOUND,
            CmdError::Decision(_) | CmdError::ReleaseBlocked => StatusCode::CONFLICT,
            CmdError::NotReady => StatusCode::SERVICE_UNAVAILABLE,
            CmdError::AuditUnreadable { .. } | CmdError::AuditFailed | CmdError::Internal => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// A refused read of the candidate (`preview_fetch`, `raw_page`), as on desktop.
    fn from_candidate_read(e: DecisionError) -> CmdError {
        match e {
            DecisionError::Invalid(InvalidReason::NotApprovable) => CmdError::ReleaseBlocked,
            other => CmdError::Decision(other),
        }
    }
}

impl Serialize for CmdError {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        match self {
            CmdError::InvalidArgument { field } => {
                m.serialize_entry("kind", "invalid_argument")?;
                m.serialize_entry("field", field)?;
            }
            CmdError::NotFound => m.serialize_entry("kind", "not_found")?,
            CmdError::Decision(e) => {
                m.serialize_entry("kind", "decision")?;
                m.serialize_entry("error", e)?;
            }
            CmdError::ReleaseBlocked => {
                m.serialize_entry("kind", "release_blocked")?;
                m.serialize_entry("text", RELEASE_BLOCKED_INTERNAL)?;
            }
            CmdError::UnknownCommand => {
                m.serialize_entry("kind", "not_found")?;
                m.serialize_entry("code", "api/unknown_command")?;
            }
            CmdError::NotReady => m.serialize_entry("kind", "not_ready")?,
            CmdError::AuditUnreadable { seq } => {
                m.serialize_entry("kind", "audit")?;
                m.serialize_entry(
                    "error",
                    &serde_json::json!({"kind": "unreadable", "seq": seq}),
                )?;
            }
            CmdError::AuditFailed => {
                m.serialize_entry("kind", "audit")?;
                m.serialize_entry("error", &serde_json::json!({"kind": "failed"}))?;
            }
            CmdError::Internal => m.serialize_entry("kind", "internal")?,
        }
        m.end()
    }
}

fn args<T: serde::de::DeserializeOwned>(body: &Value) -> Result<T, CmdError> {
    parse(body).map_err(|field| CmdError::InvalidArgument { field })
}

fn json<T: Serialize>(v: T) -> Result<Value, CmdError> {
    serde_json::to_value(v).map_err(|_| CmdError::Internal)
}

/// Runs one command (blocking: `DecisionApi` is synchronous, PD-13).
/// M15 T10b: `lang` is the reader's language for the preview document's own text.
pub fn dispatch(
    d: &dyn DecisionApi,
    cmd: &str,
    body: &Value,
    lang: Lang,
) -> Result<Value, CmdError> {
    match cmd {
        "queue_list" => {
            let QueueListArgs {} = args(body)?;
            json(d.queue_list())
        }
        "queue_get" => {
            let QueueGetArgs { request_id } = args(body)?;
            let item = d.queue_get(request_id.as_str()).ok_or(CmdError::NotFound)?;
            let request = d
                .request_detail(request_id.as_str())
                .ok_or(CmdError::NotFound)?;
            json(QueueDetail { item, request })
        }
        "recent_list" => {
            let RecentListArgs {} = args(body)?;
            json(d.recent())
        }
        "acknowledge_attention" => {
            let AcknowledgeAttentionArgs { request_ids } = args(body)?;
            d.acknowledge_attention(request_ids.as_slice());
            Ok(Value::Null)
        }
        "app_status" => {
            let AppStatusArgs {} = args(body)?;
            // Server mode has no desktop tray lines; its own status lines are M13's.
            json(Vec::<StatusLineDto>::new())
        }
        "decide" => {
            let a: DecideArgs = args(body)?;
            json(d.decide(a.into_decision()).map_err(CmdError::Decision)?)
        }
        "deny_batch" => {
            let DenyBatchArgs {
                request_ids,
                reason,
            } = args(body)?;
            let n = d
                .deny_batch(request_ids.as_slice(), reason.as_str())
                .map_err(CmdError::Decision)?;
            json(DenyCount::of(n))
        }
        "deny_session" => {
            let DenySessionArgs { session_id, reason } = args(body)?;
            let session = d
                .queue_list()
                .into_iter()
                .find(|i| i.session_id == session_id.as_str())
                .map(|i| i.session)
                .ok_or(CmdError::NotFound)?;
            let n = d
                .deny_session(session, reason.as_str())
                .map_err(CmdError::Decision)?;
            json(DenyCount::of(n))
        }
        "redaction_preview" => {
            let a: RedactionPreviewArgs = args(body)?;
            json(
                d.redaction_preview(a.request_id.as_str(), a.candidate_rev.0, &a.ops.0)
                    .map_err(CmdError::Decision)?,
            )
        }
        "preview_fetch" => {
            let PreviewFetchArgs {
                request_id,
                candidate_rev,
            } = args(body)?;
            let delivery = d
                .preview_fetch(request_id.as_str(), candidate_rev.map(|r| r.0))
                .map_err(CmdError::from_candidate_read)?;
            json(preview_fetch_response(delivery, lang))
        }
        "raw_page" => {
            let RawPageArgs {
                request_id,
                candidate_rev,
                page,
            } = args(body)?;
            json(
                raw_page_response(d, request_id.as_str(), candidate_rev.0, page).map_err(|e| {
                    match e {
                        RawPageError::Decision(e) => CmdError::from_candidate_read(e),
                        RawPageError::PageOutOfRange => CmdError::InvalidArgument { field: "page" },
                    }
                })?,
            )
        }
        _ => Err(CmdError::UnknownCommand),
    }
}

/// One audit read of the user's own store (M14 T16), the desktop's DTOs (`core::decision::
/// audit_wire`). The payload document is built for the web (`Platform::current()` of the server).
pub fn dispatch_audit(
    store: &Store,
    cmd: &str,
    body: &Value,
    lang: Lang,
) -> Result<Value, CmdError> {
    match cmd {
        "audit_query" => {
            let a: AuditQueryArgs = args(body)?;
            json(audit_wire::query(store, a)?)
        }
        "audit_trail" => {
            let AuditTrailArgs { request_id } = args(body)?;
            json(audit_wire::trail(store, request_id.as_str())?)
        }
        "audit_payload" => {
            let AuditPayloadArgs { seq, page } = args(body)?;
            json(audit_wire::payload(
                store,
                seq,
                page.unwrap_or(0),
                Platform::current(),
                lang,
            )?)
        }
        "audit_status" => {
            let AuditStatusArgs {} = args(body)?;
            json(audit_wire::status(store)?)
        }
        _ => Err(CmdError::UnknownCommand),
    }
}

/// [`dispatch_audit`] on the blocking pool.
pub async fn run_audit(
    store: Store,
    cmd: String,
    body: Value,
    lang: Lang,
) -> Result<Value, CmdError> {
    if !AUDIT_COMMANDS.contains(&cmd.as_str()) {
        return Err(CmdError::UnknownCommand);
    }
    tokio::task::spawn_blocking(move || dispatch_audit(&store, &cmd, &body, lang))
        .await
        .unwrap_or(Err(CmdError::Internal))
}

/// [`dispatch`] on the blocking pool.
pub async fn run(
    d: Arc<dyn DecisionApi>,
    cmd: String,
    body: Value,
    lang: Lang,
) -> Result<Value, CmdError> {
    if !SERVER_COMMANDS.contains(&cmd.as_str()) {
        return Err(CmdError::UnknownCommand);
    }
    tokio::task::spawn_blocking(move || dispatch(d.as_ref(), &cmd, &body, lang))
        .await
        .unwrap_or(Err(CmdError::Internal))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use serde_json::json;

    use super::*;

    /// The desktop commands that call `NativeConfirmer` (reviewed list, PD-197): none is served.
    const CONFIRMER_COMMANDS: &[&str] = &[
        "decide_batch",
        "restore_begin",
        "anchor_dir_set",
        "anchor_dir_remove",
        "re_anchor",
        "forget_install",
        "removal_begin",
        "removal_finish",
        "removal_export",
        "export_trigger",
        "acknowledge_incident",
        "prune_backlog_now",
        "instance_add",
        "instance_change_url",
        "wizard_restore",
    ];

    #[test]
    fn server_commands_are_desktop_commands() {
        let names = include_str!("../../../app/src-tauri/src/commands/names.rs");
        for c in SERVER_COMMANDS {
            assert!(
                names.contains(&format!("\"{c}\"")),
                "{c} is not a desktop command"
            );
            assert!(
                !CONFIRMER_COMMANDS.contains(c),
                "{c} asks the native confirmer"
            );
        }
        for c in CONFIRMER_COMMANDS {
            assert!(
                names.contains(&format!("\"{c}\"")),
                "{c} is not a desktop command"
            );
        }
    }

    #[test]
    fn error_wire_shapes() {
        assert_eq!(
            serde_json::to_value(CmdError::InvalidArgument { field: "reason" }).unwrap(),
            json!({"kind": "invalid_argument", "field": "reason"})
        );
        assert_eq!(
            serde_json::to_value(CmdError::UnknownCommand).unwrap(),
            json!({"kind": "not_found", "code": "api/unknown_command"})
        );
        assert_eq!(
            serde_json::to_value(CmdError::Decision(DecisionError::NotDecidable)).unwrap()["kind"],
            "decision"
        );
        assert_eq!(CmdError::UnknownCommand.status(), StatusCode::NOT_FOUND);
    }
}
