//! OAuth protocol errors in the RFC formats (PD-239): `{"error", "error_description"}` with a fixed
//! English description, `Cache-Control: no-store`; never M12's `{"error": {"code"}}` shape, so
//! standard MCP clients understand them.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthError {
    pub status: StatusCode,
    pub error: &'static str,
    pub description: &'static str,
    pub retry_after: Option<u64>,
}

const fn e(status: StatusCode, error: &'static str, description: &'static str) -> OAuthError {
    OAuthError {
        status,
        error,
        description,
        retry_after: None,
    }
}

impl OAuthError {
    pub const INVALID_REQUEST: OAuthError = e(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "The request is missing a parameter or is malformed.",
    );
    pub const INVALID_CLIENT: OAuthError = e(
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "The client is unknown.",
    );
    pub const INVALID_GRANT: OAuthError = e(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "The grant is invalid, expired or revoked.",
    );
    pub const UNSUPPORTED_GRANT_TYPE: OAuthError = e(
        StatusCode::BAD_REQUEST,
        "unsupported_grant_type",
        "Only authorization_code and refresh_token are supported.",
    );
    pub const INVALID_SCOPE: OAuthError = e(
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "The scope is not allowed.",
    );
    pub const INVALID_TARGET: OAuthError = e(
        StatusCode::BAD_REQUEST,
        "invalid_target",
        "The resource is not this server's MCP endpoint.",
    );
    pub const INVALID_REDIRECT_URI: OAuthError = e(
        StatusCode::BAD_REQUEST,
        "invalid_redirect_uri",
        "A redirect URI is not allowed.",
    );
    pub const INVALID_CLIENT_METADATA: OAuthError = e(
        StatusCode::BAD_REQUEST,
        "invalid_client_metadata",
        "The client metadata is not allowed.",
    );
    pub const SERVER_ERROR: OAuthError = e(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "Internal error.",
    );
    pub const TEMPORARILY_UNAVAILABLE: OAuthError = e(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "The server cannot answer now; try again later.",
    );

    /// 429 with `Retry-After` (registration and token endpoint limits).
    pub fn rate_limited(retry_after_secs: u64) -> OAuthError {
        OAuthError {
            retry_after: Some(retry_after_secs.max(1)),
            ..e(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
                "Too many requests; try again later.",
            )
        }
    }
}

/// `Cache-Control: no-store` and `Pragma: no-cache` (RFC 6749 §5.1) on every protocol answer.
pub fn no_store(res: &mut Response) {
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res.headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let mut res = (
            self.status,
            Json(json!({"error": self.error, "error_description": self.description})),
        )
            .into_response();
        no_store(&mut res);
        if let Some(secs) = self.retry_after
            && let Ok(v) = HeaderValue::from_str(&secs.to_string())
        {
            res.headers_mut().insert(header::RETRY_AFTER, v);
        }
        res
    }
}
