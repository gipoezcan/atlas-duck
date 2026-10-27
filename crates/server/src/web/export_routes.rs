//! Export job routes (M14 PD-254..PD-256) and the anchor head (PD-259):
//!
//! - `POST /api/me/audit/exports`, `GET /api/me/audit/exports/{job}`,
//!   `GET /api/me/audit/exports/{job}/download`: the session user's own chain.
//! - `POST /api/auditor/users/{user_id}/exports`, `GET …/exports/{job}`,
//!   `GET …/exports/{job}/download`: an auditor's export of `user_id`'s chain; the
//!   `AUDITOR_READ {action: export, range, job_id}` is recorded before the job starts (PD-258),
//!   and `AUDITOR_READ {action: export, job_id}` again before each download. Polling and
//!   downloading another user's export need the auditor role still held.
//! - `GET /api/anchor/head`: `{seq, hash}` of the anchor chain's last row (any role).
//!
//! Only the requester polls or downloads a job; anyone else's job id is 404
//! `audit/export_unknown`. The POST body is `{"from_utc": "<RFC 3339 ms>"}` or `{}` (from the
//! first record): the job always exports through the head it anchors (PD-254), so there is no
//! `to`.

use axum::Json;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::audit_kinds::{AuditorRead, AuditorScope, UserReadAction};
use crate::errors::ApiError;
use crate::export_job::{job_json, valid_job_id};
use crate::web::AppState;
use crate::web::auth_routes::body_bytes;
use crate::web::extract::SessionUser;

/// The request's `from_utc` (absent: every record).
async fn from_of(req: Request) -> Result<atlas_duck_audit::UtcInstant, ApiError> {
    let bytes = body_bytes(req.into_body()).await?;
    if bytes.is_empty() {
        return Ok(atlas_duck_audit::TimeRange::all().from_utc);
    }
    let v: Value = serde_json::from_slice(&bytes).map_err(|_| ApiError::BAD_REQUEST)?;
    let Some(obj) = v.as_object() else {
        return Err(ApiError::BAD_REQUEST);
    };
    if obj.keys().any(|k| k != "from_utc") {
        return Err(ApiError::BAD_REQUEST);
    }
    match obj.get("from_utc") {
        None | Some(Value::Null) => Ok(atlas_duck_audit::TimeRange::all().from_utc),
        Some(Value::String(s)) => {
            atlas_duck_audit::UtcInstant::parse_rfc3339_ms(s).ok_or(ApiError::BAD_REQUEST)
        }
        Some(_) => Err(ApiError::BAD_REQUEST),
    }
}

fn started(job: &crate::store::ExportJobRecord) -> Response {
    (StatusCode::ACCEPTED, Json(job_json(job, Some((0, 0))))).into_response()
}

/// `POST /api/me/audit/exports`.
pub async fn start_own(State(st): State<AppState>, user: SessionUser, req: Request) -> Response {
    let from = match from_of(req).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let me = user.0.user_id.clone();
    let r = match st.exports.reserve(&me, &me) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match st.exports.launch(r, from) {
        Ok(job) => started(&job),
        Err(e) => e.into_response(),
    }
}

/// `POST /api/auditor/users/{user_id}/exports`.
pub async fn start_auditor(
    State(st): State<AppState>,
    user: SessionUser,
    Path(target): Path<String>,
    req: Request,
) -> Response {
    if let Err(e) = user.require_role(crate::auditor::ROLE) {
        return e.into_response();
    }
    if !crate::auditor::valid_user_id(&target) || !matches!(st.store.user(&target), Ok(Some(_))) {
        return ApiError::AUDIT_USER_UNKNOWN.into_response();
    }
    let from = match from_of(req).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let r = match st.exports.reserve(&user.0.user_id, &target) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let range = json!({"from_utc": from.try_to_rfc3339_ms()});
    let read = AuditorRead {
        scope: AuditorScope::User {
            target_user_id: &target,
            action: UserReadAction::Export,
        },
        range: Some(&range),
        request_id: None,
        seq: None,
        page: None,
        job_id: Some(&r.job_id),
    };
    // PD-258: recorded before the job starts; unrecorded, nothing is exported (the slot frees).
    if let Err(e) = crate::auditor::record(&st, &user, &read).await {
        return e.into_response();
    }
    match st.exports.launch(r, from) {
        Ok(job) => started(&job),
        Err(e) => e.into_response(),
    }
}

/// A job of this requester, for `target` when given.
fn job_of(
    st: &AppState,
    user: &SessionUser,
    job_id: &str,
    target: Option<&str>,
) -> Result<(crate::store::ExportJobRecord, Option<(u64, u64)>), ApiError> {
    let (job, progress) = st.exports.get(&user.0.user_id, job_id)?;
    if target.is_some_and(|t| t != job.target_user_id) {
        return Err(ApiError::EXPORT_UNKNOWN);
    }
    // Final review m1: another user's export stays the auditor's only while they are one.
    if job.target_user_id != user.0.user_id {
        user.require_role(crate::auditor::ROLE)?;
    }
    Ok((job, progress))
}

fn status(st: &AppState, user: &SessionUser, job_id: &str, target: Option<&str>) -> Response {
    match job_of(st, user, job_id, target) {
        Ok((job, progress)) => Json(job_json(&job, progress)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /api/me/audit/exports/{job}`.
pub async fn status_own(
    State(st): State<AppState>,
    user: SessionUser,
    Path(job_id): Path<String>,
) -> Response {
    let me = user.0.user_id.clone();
    status(&st, &user, &job_id, Some(&me))
}

/// `GET /api/auditor/users/{user_id}/exports/{job}`.
pub async fn status_auditor(
    State(st): State<AppState>,
    user: SessionUser,
    Path((target, job_id)): Path<(String, String)>,
) -> Response {
    if let Err(e) = user.require_role(crate::auditor::ROLE) {
        return e.into_response();
    }
    status(&st, &user, &job_id, Some(&target))
}

/// A file-name-safe rendering of a username.
fn safe_name(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if out.is_empty() { "user".into() } else { out }
}

fn download(st: &AppState, user: &SessionUser, job_id: &str, target: Option<&str>) -> Response {
    if !valid_job_id(job_id) {
        return ApiError::EXPORT_UNKNOWN.into_response();
    }
    let job = match job_of(st, user, job_id, target) {
        Ok((job, _)) => job,
        Err(e) => return e.into_response(),
    };
    let entries = match st.exports.archive(&job) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    if !st.exports.begin_download(job_id) {
        return ApiError::EXPORT_BUSY.into_response();
    }
    let username = st
        .store
        .user(&job.target_user_id)
        .ok()
        .flatten()
        .map_or_else(|| "user".to_owned(), |u| u.username);
    let (first, last) = job
        .file_name
        .as_deref()
        .and_then(|n| {
            let mut parts = n.rsplitn(4, '-');
            let _stamp = parts.next()?;
            let last = parts.next()?;
            let first = parts.next()?;
            Some((first.to_owned(), last.to_owned()))
        })
        .unwrap_or_default();
    let len = crate::tar::archive_len(&entries);
    let mtime = u64::try_from(job.created_at).unwrap_or(0);
    let jobs = st.exports.clone();
    let id = job_id.to_owned();
    let body = crate::tar::stream(
        entries,
        mtime,
        Box::pin(async move { jobs.end_download(&id, true) }),
    );
    // A cut stream releases the download slot when the body is dropped.
    let guard = DownloadGuard {
        jobs: st.exports.clone(),
        job_id: job_id.to_owned(),
    };
    let body = futures::StreamExt::map(body, move |chunk| {
        let _keep = &guard;
        chunk
    });
    let mut res = axum::body::Body::from_stream(body).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-tar"),
    );
    if let Ok(v) = HeaderValue::from_str(&len.to_string()) {
        h.insert(header::CONTENT_LENGTH, v);
    }
    let file = format!(
        "atlas-duck-export-{}-{}-{}.tar",
        safe_name(&username),
        safe_name(&first),
        safe_name(&last)
    );
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{file}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Some(m) = job.manifest_sha256.as_deref()
        && let Ok(v) = HeaderValue::from_str(m)
    {
        h.insert("x-atlas-duck-manifest-sha256", v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Frees the download slot of a stream dropped before its end (a completed stream has already
/// freed it and marked the job; a second release is a no-op).
struct DownloadGuard {
    jobs: std::sync::Arc<crate::export_job::ExportJobs>,
    job_id: String,
}

impl Drop for DownloadGuard {
    fn drop(&mut self) {
        self.jobs.end_download(&self.job_id, false);
    }
}

/// `GET /api/me/audit/exports/{job}/download`.
pub async fn download_own(
    State(st): State<AppState>,
    user: SessionUser,
    Path(job_id): Path<String>,
) -> Response {
    let me = user.0.user_id.clone();
    download(&st, &user, &job_id, Some(&me))
}

/// `GET /api/auditor/users/{user_id}/exports/{job}/download`.
pub async fn download_auditor(
    State(st): State<AppState>,
    user: SessionUser,
    Path((target, job_id)): Path<(String, String)>,
) -> Response {
    if let Err(e) = user.require_role(crate::auditor::ROLE) {
        return e.into_response();
    }
    if let Err(e) = job_of(&st, &user, &job_id, Some(&target)) {
        return e.into_response();
    }
    // Final review m1: the download of another user's chain is an auditor read too, recorded
    // before any byte goes out (PD-258).
    let read = AuditorRead {
        scope: AuditorScope::User {
            target_user_id: &target,
            action: UserReadAction::Export,
        },
        range: None,
        request_id: None,
        seq: None,
        page: None,
        job_id: Some(&job_id),
    };
    if let Err(e) = crate::auditor::record(&st, &user, &read).await {
        return e.into_response();
    }
    download(&st, &user, &job_id, Some(&target))
}

/// `GET /api/anchor/head` (PD-259): the anchor chain's last row, for a recipient's pin. A live
/// server moves past an export's own `HEADS` row; the job page shows that row (`anchor_head`).
pub async fn anchor_head(State(st): State<AppState>, _user: SessionUser) -> Response {
    match crate::anchor::head(st.store.as_ref()) {
        Ok(Some((seq, hash))) => {
            Json(json!({"seq": seq, "hash": hex::encode(hash)})).into_response()
        }
        Ok(None) => ApiError::NOT_FOUND.into_response(),
        Err(_) => ApiError::STORE_UNAVAILABLE.into_response(),
    }
}
