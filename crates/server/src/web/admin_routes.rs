//! `GET/POST /api/admin/instances`, `DELETE /api/admin/instances/{alias}` (SM-4.1, SM-2.5):
//! session (+ CSRF for changes, by the `/api` guard) and role `admin`. The answers are
//! `InstanceView`s only: no PAT, user or audit data.

use axum::Json;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::AppState;
use super::auth_routes::body_bytes;
use super::extract::SessionUser;
use crate::errors::ApiError;
use crate::instances::{self, InstanceSpec};
use crate::login::ROLE_ADMIN;

pub async fn list(State(st): State<AppState>, user: SessionUser) -> Result<Response, ApiError> {
    user.require_role(ROLE_ADMIN)?;
    Ok(Json(instances::list(st.store.as_ref())?).into_response())
}

pub async fn add(
    State(st): State<AppState>,
    user: SessionUser,
    req: Request,
) -> Result<Response, ApiError> {
    user.require_role(ROLE_ADMIN)?;
    let bytes = body_bytes(req.into_body()).await?;
    let spec: InstanceSpec =
        serde_json::from_slice(&bytes).map_err(|_| ApiError::INSTANCE_INVALID)?;
    let view = instances::add(st.store.as_ref(), &st.registry, spec).await?;
    Ok((StatusCode::CREATED, Json(view)).into_response())
}

pub async fn remove(
    State(st): State<AppState>,
    user: SessionUser,
    Path(alias): Path<String>,
) -> Result<Response, ApiError> {
    user.require_role(ROLE_ADMIN)?;
    instances::remove(st.store.as_ref(), &st.registry, &alias).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
