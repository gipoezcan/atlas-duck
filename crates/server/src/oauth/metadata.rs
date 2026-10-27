//! The discovery documents (PD-233): RFC 9728 protected-resource metadata, served at the bare and
//! the path-suffixed well-known URI, and RFC 8414 authorization-server metadata. Client ID
//! Metadata Documents are not supported (L241), so no field advertises them.

use serde_json::{Value, json};

use super::{OAuth, SCOPES};

pub const PRM_PATH: &str = "/.well-known/oauth-protected-resource";
pub const AS_PATH: &str = "/.well-known/oauth-authorization-server";
pub const AUTHORIZE_PATH: &str = "/oauth/authorize";
pub const TOKEN_PATH: &str = "/oauth/token";
pub const REGISTER_PATH: &str = "/oauth/register";
pub const REVOKE_PATH: &str = "/oauth/revoke";
/// Both discovery documents may be cached this long.
pub const CACHE_CONTROL: &str = "max-age=300";

/// RFC 9728 §2.
pub fn protected_resource(o: &OAuth) -> Value {
    json!({
        "resource": o.resource,
        "authorization_servers": [o.issuer],
        "scopes_supported": SCOPES,
        "bearer_methods_supported": ["header"],
        "resource_name": "atlas-duck",
    })
}

/// RFC 8414 §2.
pub fn authorization_server(o: &OAuth) -> Value {
    let at = |p: &str| format!("{}{p}", o.issuer);
    json!({
        "issuer": o.issuer,
        "authorization_endpoint": at(AUTHORIZE_PATH),
        "token_endpoint": at(TOKEN_PATH),
        "registration_endpoint": at(REGISTER_PATH),
        "revocation_endpoint": at(REVOKE_PATH),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": SCOPES,
        "authorization_response_iss_parameter_supported": true,
    })
}
