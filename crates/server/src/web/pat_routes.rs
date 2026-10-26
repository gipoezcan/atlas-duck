//! PAT entry (SM-4.2, SM-4.3, base spec §7.1–§7.3; PD-211): `GET /api/instances`,
//! `PUT /api/me/pats/{alias}`, `DELETE /api/me/pats/{alias}`. The credential check, the
//! `CREDENTIAL_CHANGED` record (before the store) and the instance table update are core's own
//! `InstanceAdmin::set_token` / `delete_token`, the calls the desktop credential window makes;
//! the PAT lands sealed in `user_pats` through `ServerCredentials`. No answer carries a PAT.

use atlas_duck_core::{AdminError, ConnectionFailure};
use axum::Json;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};

use super::AppState;
use super::auth_routes::body_bytes;
use super::extract::SessionUser;
use crate::errors::ApiError;

/// Longest PAT accepted (characters).
pub const MAX_PAT_CHARS: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatBody {
    pat: String,
}

fn admin_error(e: AdminError) -> ApiError {
    match e {
        AdminError::NotFound => ApiError::INSTANCE_UNKNOWN,
        AdminError::ConnectionFailed(f) => match f {
            ConnectionFailure::Network(_)
            | ConnectionFailure::Tls(_)
            | ConnectionFailure::Proxy(_)
            | ConnectionFailure::Unavailable => {
                ApiError::PAT_INSTANCE_UNREACHABLE.with_reason(f.kind())
            }
            other => ApiError::PAT_CHECK_FAILED.with_reason(other.kind()),
        },
        // PD-197: a token of another Atlassian user than the stored one needs the owner-change
        // confirmation, which server mode refuses: delete the stored PAT first.
        AdminError::Cancelled => ApiError::PAT_CHECK_FAILED.with_reason("other_user"),
        AdminError::Unconfirmed | AdminError::InsecureScheme | AdminError::InvalidUrl => {
            ApiError::PAT_CHECK_FAILED.with_reason("instance_unusable")
        }
        AdminError::Audit(_) | AdminError::Keychain(_) | AdminError::ShuttingDown => {
            ApiError::STORE_UNAVAILABLE
        }
        _ => ApiError::INTERNAL,
    }
}

fn known_alias(st: &AppState, alias: &str) -> Result<(), ApiError> {
    let known = st
        .store
        .instance_list()
        .map_err(|_| ApiError::STORE_UNAVAILABLE)?
        .iter()
        .any(|i| i.alias == alias);
    if known {
        Ok(())
    } else {
        Err(ApiError::INSTANCE_UNKNOWN)
    }
}

/// `GET /api/instances`: the admin instances with this user's PAT state (`none`, `stored`, or
/// `invalid` when a stored PAT does not make the instance usable) and the PAT's identity name.
pub async fn instances(
    State(st): State<AppState>,
    user: SessionUser,
) -> Result<Response, ApiError> {
    let list = st
        .store
        .instance_list()
        .map_err(|_| ApiError::STORE_UNAVAILABLE)?;
    let pats = st
        .store
        .pat_list(&user.0.user_id)
        .map_err(|_| ApiError::STORE_UNAVAILABLE)?;
    let rt = st.registry.runtime(&user.ctx()).await?;
    let envelope = serde_json::to_value(rt.handler().instances_list().await)
        .map_err(|_| ApiError::INTERNAL)?;
    let state_of = |alias: &str| -> Option<String> {
        envelope["data"]["instances"]
            .as_array()?
            .iter()
            .find(|i| i["alias"] == alias)?["state"]
            .as_str()
            .map(str::to_owned)
    };
    let out: Vec<Value> = list
        .iter()
        .map(|i| {
            let pat = pats.iter().find(|p| p.alias == i.alias);
            let identity = pat
                .and_then(|p| serde_json::from_str::<Value>(&p.identity_json).ok())
                .and_then(|v| v["user"].as_str().map(str::to_owned));
            let state = match pat {
                None => "none",
                Some(_) if state_of(&i.alias).as_deref() == Some("ok") => "stored",
                Some(_) => "invalid",
            };
            json!({"alias": i.alias, "product": i.product, "base_url": i.base_url,
                   "is_default": i.is_default, "pat": state, "identity": identity})
        })
        .collect();
    Ok(Json(out).into_response())
}

/// `PUT /api/me/pats/{alias}` `{pat}`: the credential check, then the sealed store.
pub async fn put(
    State(st): State<AppState>,
    user: SessionUser,
    Path(alias): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    known_alias(&st, &alias)?;
    let bytes = body_bytes(req.into_body()).await?;
    let body: PatBody = serde_json::from_slice(&bytes).map_err(|_| ApiError::BAD_REQUEST)?;
    drop(bytes);
    let n = body.pat.chars().count();
    let pat = SecretString::from(body.pat);
    if !(1..=MAX_PAT_CHARS).contains(&n) {
        return Err(ApiError::BAD_REQUEST);
    }
    let rt = st.registry.runtime(&user.ctx()).await?;
    rt.instances()
        .set_token(&alias, pat, None)
        .await
        .map_err(admin_error)?;
    let identity = st
        .store
        .pat_get(&user.0.user_id, &alias)
        .ok()
        .flatten()
        .and_then(|p| serde_json::from_str::<Value>(&p.identity_json).ok())
        .and_then(|v| v["user"].as_str().map(str::to_owned));
    Ok(Json(json!({"alias": alias, "identity": identity})).into_response())
}

/// `DELETE /api/me/pats/{alias}`: `CREDENTIAL_CHANGED {deleted}`, then the PAT goes.
pub async fn delete(
    State(st): State<AppState>,
    user: SessionUser,
    Path(alias): Path<String>,
) -> Result<Response, ApiError> {
    known_alias(&st, &alias)?;
    let rt = st.registry.runtime(&user.ctx()).await?;
    rt.instances()
        .delete_token(&alias)
        .await
        .map_err(admin_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
