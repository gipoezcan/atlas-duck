//! Auditor read access (SM-6.4, SM-6.5, SM-2.5; M14 PD-257, PD-258).
//!
//! `/api/auditor/*` is reachable only with a session whose roles hold `auditor`: the `/api/`
//! guard checks the role before any handler or path extraction runs (403 `auth/role_required`;
//! bearers are refused like on every session-only path). The target `user_id` comes from the path
//! (the second documented exception to "no user id from the path", L253) and must name a user
//! with a store (404 `audit/user_unknown`). Admins have no route here (SM-2.5).
//!
//! Every request that returns target data is recorded **before** the body is built (PD-258):
//! `AUDITOR_READ` in the auditor's own chain and an `AUDITOR_READ` row in the anchor chain's
//! operational log; if either append fails the answer is 503 `audit/read_not_recorded` with no
//! target data. Reads go through `Registry::audit_view`, which never starts the target's core (no
//! `APP_START` in the target's chain).

use axum::Json;
use axum::extract::{Path, Request, State};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::{Value, json};

use crate::audit_kinds::{AuditorRead, AuditorScope, UserReadAction, auditor_read};
use crate::cmd::{self, CmdError};
use crate::errors::ApiError;
use crate::runtime::RuntimeError;
use crate::web::AppState;
use crate::web::auth_routes::body_bytes;
use crate::web::extract::SessionUser;

/// The role every route here needs.
pub const ROLE: &str = "auditor";
/// The anchor chain's operational kind of an auditor read.
pub const KIND_AUDITOR_READ: &str = "AUDITOR_READ";

/// A path `user_id` as PD-199 makes them: 32 lowercase hex characters.
pub fn valid_user_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// PD-258: the read is recorded in the auditor's chain and the anchor op-log, both before any
/// target data is produced. Either failure is 503 `audit/read_not_recorded`.
pub async fn record(
    st: &AppState,
    auditor: &SessionUser,
    read: &AuditorRead<'_>,
) -> Result<(), ApiError> {
    let rt = st
        .registry
        .runtime(&auditor.ctx())
        .await
        .map_err(|_| ApiError::AUDIT_READ_NOT_RECORDED)?;
    rt.append_server_record(
        atlas_duck_audit::EventType::AUDITOR_READ,
        auditor_read(read),
    )
    .await
    .map_err(|_| ApiError::AUDIT_READ_NOT_RECORDED)?;
    let (target, action) = match read.scope {
        AuditorScope::ListUsers => (None, "list_users"),
        AuditorScope::User {
            target_user_id,
            action,
        } => (
            Some(target_user_id),
            match action {
                UserReadAction::Query => "query",
                UserReadAction::Trail => "trail",
                UserReadAction::Payload => "payload",
                UserReadAction::Export => "export",
            },
        ),
    };
    let mut body = json!({"auditor_user_id": auditor.0.user_id, "action": action});
    if let Some(t) = target {
        body["target_user_id"] = Value::from(t);
    }
    st.anchor
        .operational(KIND_AUDITOR_READ, &body)
        .map_err(|_| ApiError::AUDIT_READ_NOT_RECORDED)?;
    Ok(())
}

/// One row of the auditor's user list: no secret column.
#[derive(Debug, Serialize)]
pub struct UserView {
    pub user_id: String,
    pub username: String,
    pub display_name: Option<String>,
    /// `active` until M13's deactivation merges (`deactivated` then, SM-6.5).
    pub state: &'static str,
    pub deactivated_at: Option<i64>,
    pub retention_until: Option<i64>,
    /// The chain head's seq while the user's runtime is open; `null` otherwise.
    pub chain_head_seq: Option<u64>,
}

/// `GET /api/auditor/users`, recorded as `AUDITOR_READ {action: list_users}`.
pub async fn list_users(State(st): State<AppState>, user: SessionUser) -> Response {
    if let Err(e) = user.require_role(ROLE) {
        return e.into_response();
    }
    if let Err(e) = record(
        &st,
        &user,
        &AuditorRead {
            scope: AuditorScope::ListUsers,
            range: None,
            request_id: None,
            seq: None,
            page: None,
            job_id: None,
        },
    )
    .await
    {
        return e.into_response();
    }
    let users = match st.store.user_list() {
        Ok(u) => u,
        Err(_) => return ApiError::STORE_UNAVAILABLE.into_response(),
    };
    let open = st.registry.open_runtimes().await;
    let rows: Vec<UserView> = users
        .into_iter()
        .map(|u| UserView {
            chain_head_seq: open
                .iter()
                .find(|r| r.user_id() == u.user_id)
                .map(|r| r.head().1),
            user_id: u.user_id,
            username: u.username,
            display_name: u.display_name,
            state: "active",
            deactivated_at: None,
            retention_until: None,
        })
        .collect();
    Json(rows).into_response()
}

fn cmd_error(e: CmdError) -> Response {
    (e.status(), Json(e)).into_response()
}

/// `(action, range, request_id, seq, page)` of one read.
type Summary = (
    UserReadAction,
    Option<Value>,
    Option<String>,
    Option<u64>,
    Option<u64>,
);

/// The read's `AUDITOR_READ` summary (PD-258): never the filter text.
fn summary(command: &str, body: &Value) -> Result<Summary, CmdError> {
    use atlas_duck_core::decision::audit_wire::{
        AuditPayloadArgs, AuditQueryArgs, AuditStatusArgs, AuditTrailArgs,
    };
    use atlas_duck_core::decision::wire::parse;
    let bad = |field| CmdError::InvalidArgument { field };
    match command {
        "audit_query" => {
            let a: AuditQueryArgs = parse(body).map_err(bad)?;
            let t = |u: Option<atlas_duck_audit::UtcInstant>| u.map(|u| u.to_rfc3339_ms());
            Ok((
                UserReadAction::Query,
                Some(json!({
                    "from_utc": t(a.filter.from_utc),
                    "to_utc": t(a.filter.to_utc),
                    "event_types": a.filter.event_types.len(),
                    "before_seq": a.cursor.and_then(|c| c.before_seq),
                })),
                None,
                None,
                None,
            ))
        }
        // The status lists incidents and health: recorded as a query of that kind.
        "audit_status" => {
            let AuditStatusArgs {} = parse(body).map_err(bad)?;
            Ok((
                UserReadAction::Query,
                Some(json!({"status": true})),
                None,
                None,
                None,
            ))
        }
        "audit_trail" => {
            let AuditTrailArgs { request_id } = parse(body).map_err(bad)?;
            Ok((
                UserReadAction::Trail,
                None,
                Some(request_id.as_str().to_owned()),
                None,
                None,
            ))
        }
        "audit_payload" => {
            let AuditPayloadArgs { seq, page } = parse(body).map_err(bad)?;
            Ok((
                UserReadAction::Payload,
                None,
                None,
                Some(seq),
                Some(u64::from(page.unwrap_or(0))),
            ))
        }
        _ => Err(CmdError::UnknownCommand),
    }
}

/// `POST /api/auditor/users/{user_id}/{command}`: the desktop audit reads of the target's chain,
/// recorded first (PD-258).
pub async fn read(
    State(st): State<AppState>,
    user: SessionUser,
    Path((target, command)): Path<(String, String)>,
    req: Request,
) -> Response {
    if let Err(e) = user.require_role(ROLE) {
        return e.into_response();
    }
    if !cmd::AUDIT_COMMANDS.contains(&command.as_str()) {
        return cmd_error(CmdError::UnknownCommand);
    }
    if !valid_user_id(&target) || !matches!(st.store.user(&target), Ok(Some(_))) {
        return ApiError::AUDIT_USER_UNKNOWN.into_response();
    }
    // M15 T10b: the auditor's own language, not the target's.
    let lang = crate::web::pref_routes::reader_lang(&st, &user.0.user_id, req.headers());
    let bytes = match body_bytes(req.into_body()).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let body: Value = if bytes.is_empty() {
        Value::Object(Default::default())
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return cmd_error(CmdError::InvalidArgument { field: "payload" }),
        }
    };
    let (action, range, request_id, seq, page) = match summary(&command, &body) {
        Ok(s) => s,
        Err(e) => return cmd_error(e),
    };
    // The target's store: the open runtime's, else a view without a core. Opening it yields no
    // data yet.
    let store = match st.registry.audit_view(&target).await {
        Ok(s) => s,
        Err(RuntimeError::UnknownUser) => return ApiError::AUDIT_USER_UNKNOWN.into_response(),
        Err(_) => return ApiError::STORE_UNAVAILABLE.into_response(),
    };
    let read = AuditorRead {
        scope: AuditorScope::User {
            target_user_id: &target,
            action,
        },
        range: range.as_ref(),
        request_id: request_id.as_deref(),
        seq,
        page,
        job_id: None,
    };
    if let Err(e) = record(&st, &user, &read).await {
        return e.into_response();
    }
    match cmd::run_audit(store, command, body, lang).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => cmd_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_ids_from_the_path() {
        assert!(valid_user_id(&"0a".repeat(16)));
        for bad in [
            "",
            "x",
            &"A".repeat(32),
            &"0".repeat(31),
            &"0".repeat(33),
            "../etc/passwd",
        ] {
            assert!(!valid_user_id(bad), "{bad}");
        }
    }
}
