//! API error bodies (plan "Error codes"): `{"error": {"code": "<area>/<name>", "message": "<fixed
//! English text>"}}` with the code's HTTP status. Messages are constants: no caller text, no
//! secret and no internal detail ever reaches a body.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: &'static str,
    /// `Retry-After` seconds (429 only).
    pub retry_after: Option<u64>,
    /// A closed reason kind (`pat/check_failed`, `pat/instance_unreachable`): never text.
    pub reason: Option<&'static str>,
}

const fn e(status: StatusCode, code: &'static str, message: &'static str) -> ApiError {
    ApiError {
        status,
        code,
        message,
        retry_after: None,
        reason: None,
    }
}

impl ApiError {
    pub const INVALID_CREDENTIALS: ApiError = e(
        StatusCode::UNAUTHORIZED,
        "auth/invalid_credentials",
        "The username or password is wrong.",
    );
    pub const EMPTY_PASSWORD: ApiError = e(
        StatusCode::BAD_REQUEST,
        "auth/empty_password",
        "Enter a password.",
    );
    pub const DIRECTORY_UNAVAILABLE: ApiError = e(
        StatusCode::SERVICE_UNAVAILABLE,
        "auth/directory_unavailable",
        "The directory cannot be reached; try again later.",
    );
    pub const NOT_PERMITTED: ApiError = e(
        StatusCode::FORBIDDEN,
        "auth/not_permitted",
        "This account may not use atlas-duck.",
    );
    pub const NO_SESSION: ApiError = e(
        StatusCode::UNAUTHORIZED,
        "auth/no_session",
        "Sign in first.",
    );
    pub const SESSION_EXPIRED: ApiError = e(
        StatusCode::UNAUTHORIZED,
        "auth/session_expired",
        "The session expired; sign in again.",
    );
    pub const CSRF_MISMATCH: ApiError = e(
        StatusCode::FORBIDDEN,
        "auth/csrf_mismatch",
        "The request token does not match the session.",
    );
    pub const ORIGIN_MISMATCH: ApiError = e(
        StatusCode::FORBIDDEN,
        "auth/origin_mismatch",
        "The request comes from another origin.",
    );
    pub const ROLE_REQUIRED: ApiError = e(
        StatusCode::FORBIDDEN,
        "auth/role_required",
        "This needs a role the account does not have.",
    );
    pub const BEARER_NOT_ACCEPTED: ApiError = e(
        StatusCode::FORBIDDEN,
        "auth/bearer_not_accepted",
        "API keys cannot be used here.",
    );
    pub const API_KEY_INVALID: ApiError = e(
        StatusCode::UNAUTHORIZED,
        "auth/api_key_invalid",
        "The API key is not valid.",
    );
    pub const SCOPE_MISSING: ApiError = e(
        StatusCode::FORBIDDEN,
        "auth/scope_missing",
        "The API key lacks the scope this needs.",
    );
    pub const BAD_REQUEST: ApiError = e(
        StatusCode::BAD_REQUEST,
        "api/bad_request",
        "The request is malformed.",
    );
    pub const NOT_FOUND: ApiError = e(StatusCode::NOT_FOUND, "api/not_found", "Not found.");
    pub const UNKNOWN_COMMAND: ApiError = e(
        StatusCode::NOT_FOUND,
        "api/unknown_command",
        "Unknown command.",
    );
    pub const BODY_TOO_LARGE: ApiError = e(
        StatusCode::PAYLOAD_TOO_LARGE,
        "api/body_too_large",
        "The request body is too large.",
    );
    /// Batch-3 review M5: at most `MAX_SSE_STREAMS` open event streams per user.
    pub const TOO_MANY_STREAMS: ApiError = e(
        StatusCode::TOO_MANY_REQUESTS,
        "api/too_many_streams",
        "Too many open event streams.",
    );
    pub const INSTANCE_INVALID: ApiError = e(
        StatusCode::BAD_REQUEST,
        "instance/invalid",
        "The instance is not valid.",
    );
    pub const INSTANCE_EXISTS: ApiError = e(
        StatusCode::CONFLICT,
        "instance/exists",
        "An instance with this alias exists.",
    );
    pub const INSTANCE_UNKNOWN: ApiError = e(
        StatusCode::NOT_FOUND,
        "instance/unknown",
        "No instance has this alias.",
    );
    pub const PAT_CHECK_FAILED: ApiError = e(
        StatusCode::UNPROCESSABLE_ENTITY,
        "pat/check_failed",
        "The token was refused by the instance.",
    );
    pub const PAT_INSTANCE_UNREACHABLE: ApiError = e(
        StatusCode::BAD_GATEWAY,
        "pat/instance_unreachable",
        "The instance cannot be reached.",
    );
    pub const API_KEY_LIMIT_REACHED: ApiError = e(
        StatusCode::CONFLICT,
        "api_key/limit_reached",
        "Revoke a key before creating another.",
    );
    pub const API_KEY_EXPIRY_OUT_OF_RANGE: ApiError = e(
        StatusCode::BAD_REQUEST,
        "api_key/expiry_out_of_range",
        "The expiry must be 1 to 90 days.",
    );
    pub const API_KEY_NAME_INVALID: ApiError = e(
        StatusCode::BAD_REQUEST,
        "api_key/name_invalid",
        "The key name is not valid.",
    );
    pub const API_KEY_SCOPE_INVALID: ApiError = e(
        StatusCode::BAD_REQUEST,
        "api_key/scope_invalid",
        "The scopes are not valid.",
    );
    pub const STORE_UNAVAILABLE: ApiError = e(
        StatusCode::SERVICE_UNAVAILABLE,
        "store/unavailable",
        "The store is not available.",
    );
    pub const INTERNAL: ApiError = e(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "Internal error.",
    );

    /// `auth/rate_limited` 429 with `Retry-After`.
    pub fn rate_limited(retry_after_secs: u64) -> ApiError {
        ApiError {
            retry_after: Some(retry_after_secs.max(1)),
            ..e(
                StatusCode::TOO_MANY_REQUESTS,
                "auth/rate_limited",
                "Too many failed sign-ins; try again later.",
            )
        }
    }

    /// The JSON body.
    /// The same error with a closed reason kind in its body.
    pub fn with_reason(mut self, reason: &'static str) -> ApiError {
        self.reason = Some(reason);
        self
    }

    pub fn body(&self) -> serde_json::Value {
        match self.reason {
            Some(r) => json!({"error": {"code": self.code, "message": self.message, "reason": r}}),
            None => json!({"error": {"code": self.code, "message": self.message}}),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut res = (self.status, Json(self.body())).into_response();
        if let Some(secs) = self.retry_after
            && let Ok(v) = HeaderValue::from_str(&secs.to_string())
        {
            res.headers_mut().insert(header::RETRY_AFTER, v);
        }
        res
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn body_shape() {
        assert_eq!(
            ApiError::CSRF_MISMATCH.body(),
            json!({"error": {"code": "auth/csrf_mismatch",
                             "message": "The request token does not match the session."}})
        );
    }

    #[test]
    fn response_status_header_and_json() {
        let res = ApiError::rate_limited(42).into_response();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(res.headers()[header::RETRY_AFTER], "42");
        assert_eq!(res.headers()[header::CONTENT_TYPE], "application/json");
        let res = ApiError::NO_SESSION.into_response();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(res.headers().get(header::RETRY_AFTER).is_none());
    }

    #[test]
    fn every_code_has_its_area_and_status() {
        for (err, status) in [
            (ApiError::INVALID_CREDENTIALS, 401),
            (ApiError::EMPTY_PASSWORD, 400),
            (ApiError::DIRECTORY_UNAVAILABLE, 503),
            (ApiError::rate_limited(1), 429),
            (ApiError::NOT_PERMITTED, 403),
            (ApiError::NO_SESSION, 401),
            (ApiError::SESSION_EXPIRED, 401),
            (ApiError::CSRF_MISMATCH, 403),
            (ApiError::ORIGIN_MISMATCH, 403),
            (ApiError::ROLE_REQUIRED, 403),
            (ApiError::BEARER_NOT_ACCEPTED, 403),
            (ApiError::API_KEY_INVALID, 401),
            (ApiError::SCOPE_MISSING, 403),
            (ApiError::BAD_REQUEST, 400),
            (ApiError::NOT_FOUND, 404),
            (ApiError::UNKNOWN_COMMAND, 404),
            (ApiError::BODY_TOO_LARGE, 413),
            (ApiError::TOO_MANY_STREAMS, 429),
            (ApiError::INSTANCE_INVALID, 400),
            (ApiError::INSTANCE_EXISTS, 409),
            (ApiError::INSTANCE_UNKNOWN, 404),
            (ApiError::PAT_CHECK_FAILED, 422),
            (ApiError::PAT_INSTANCE_UNREACHABLE, 502),
            (ApiError::API_KEY_LIMIT_REACHED, 409),
            (ApiError::API_KEY_EXPIRY_OUT_OF_RANGE, 400),
            (ApiError::API_KEY_NAME_INVALID, 400),
            (ApiError::API_KEY_SCOPE_INVALID, 400),
            (ApiError::STORE_UNAVAILABLE, 503),
            (ApiError::INTERNAL, 500),
        ] {
            assert_eq!(err.status.as_u16(), status, "{}", err.code);
        }
    }
}
