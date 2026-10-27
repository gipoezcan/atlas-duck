//! Dynamic client registration (RFC 7591, PD-234, PD-240): public clients only, no secret, no
//! management token. RFC 7591 clients send extra fields, so the body is read against an explicit
//! table instead of `deny_unknown_fields`: accepted fields are checked, a few are ignored, the
//! fields that would make the server show or fetch client-chosen content are refused, and any
//! other unknown field is ignored (RFC 7591 §2).

use serde_json::{Map, Value, json};

use super::error::OAuthError;
use super::redirect::{MAX_URIS, host_of, registered_form};
use super::{CLIENT_PREFIX, OAuth, random_b64};
use crate::anchor::AnchorWriter;
use crate::store::{OAuthClientRecord, ServerStore, StoreError};

/// The largest registration body.
pub const BODY_LIMIT: usize = 16 * 1024;
pub const MAX_NAME_CHARS: usize = 64;
/// The anchor chain's operational kind of a registration.
pub const KIND_CLIENT_REGISTERED: &str = "OAUTH_CLIENT_REGISTERED";

/// Refused: client-chosen content the consent page would show or the server would fetch.
const REFUSED: [&str; 9] = [
    "logo_uri",
    "tos_uri",
    "policy_uri",
    "contacts",
    "jwks",
    "jwks_uri",
    "software_statement",
    "client_secret",
    "client_id",
];

/// What a registration accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
}

/// PD-240: 1..=64 printable characters; control characters and bidi controls refused.
pub fn valid_client_name(name: &str) -> bool {
    let n = name.chars().count();
    (1..=MAX_NAME_CHARS).contains(&n)
        && name.trim() == name
        && !name.chars().any(|c| {
            c.is_control()
                || matches!(c, '\u{200e}' | '\u{200f}' | '\u{061c}')
                || ('\u{202a}'..='\u{202e}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c)
        })
}

fn strings(v: &Value) -> Option<Vec<String>> {
    v.as_array()?
        .iter()
        .map(|x| x.as_str().map(str::to_owned))
        .collect()
}

/// The registration request checked against the PD-234/PD-240 table.
pub fn validate(body: &Map<String, Value>) -> Result<Accepted, OAuthError> {
    let meta = OAuthError::INVALID_CLIENT_METADATA;
    if REFUSED.iter().any(|k| body.contains_key(*k)) {
        return Err(meta);
    }
    let raw_uris = body
        .get("redirect_uris")
        .and_then(strings)
        .ok_or(OAuthError::INVALID_REDIRECT_URI)?;
    if raw_uris.is_empty() || raw_uris.len() > MAX_URIS {
        return Err(OAuthError::INVALID_REDIRECT_URI);
    }
    let uris = raw_uris
        .iter()
        .map(|u| registered_form(u))
        .collect::<Option<Vec<String>>>()
        .ok_or(OAuthError::INVALID_REDIRECT_URI)?;
    let client_name = body
        .get("client_name")
        .and_then(Value::as_str)
        .filter(|n| valid_client_name(n))
        .ok_or(meta)?
        .to_owned();
    // No secret is ever issued: "none" only; absent is read as "none" (we answer "none").
    match body.get("token_endpoint_auth_method") {
        None => {}
        Some(v) if v.as_str() == Some("none") => {}
        Some(_) => return Err(meta),
    }
    let grant_types = match body.get("grant_types") {
        None => vec!["authorization_code".to_owned()],
        Some(v) => strings(v).ok_or(meta)?,
    };
    if !grant_types.iter().any(|g| g == "authorization_code")
        || grant_types
            .iter()
            .any(|g| g != "authorization_code" && g != "refresh_token")
    {
        return Err(meta);
    }
    match body.get("response_types") {
        None => {}
        Some(v) if strings(v).is_some_and(|r| r == ["code"]) => {}
        Some(_) => return Err(meta),
    }
    if let Some(s) = body.get("scope")
        && !s.is_string()
    {
        return Err(meta);
    }
    let mut dedup = grant_types.clone();
    dedup.sort();
    dedup.dedup();
    Ok(Accepted {
        client_name,
        redirect_uris: uris,
        grant_types: dedup,
    })
}

/// Registers a client: rate limit per IP, the client cap (purge, then refuse), the store row, the
/// anchor row. Answers the RFC 7591 response body.
pub fn register(
    o: &OAuth,
    store: &dyn ServerStore,
    anchor: &AnchorWriter,
    ip: &str,
    now: i64,
    body: &[u8],
) -> Result<Value, OAuthError> {
    if body.len() > BODY_LIMIT {
        return Err(OAuthError::INVALID_CLIENT_METADATA);
    }
    let parsed: Map<String, Value> =
        serde_json::from_slice(body).map_err(|_| OAuthError::INVALID_CLIENT_METADATA)?;
    let accepted = validate(&parsed)?;
    o.register_limiter
        .hit(ip, now)
        .map_err(OAuthError::rate_limited)?;
    let store_err = |_: StoreError| OAuthError::TEMPORARILY_UNAVAILABLE;
    if store.oauth_client_count().map_err(store_err)? >= o.cfg.max_clients {
        store.oauth_purge(now).map_err(store_err)?;
        if store.oauth_client_count().map_err(store_err)? >= o.cfg.max_clients {
            tracing::warn!(event = "oauth_client_cap_reached");
            return Err(OAuthError::rate_limited(3600));
        }
    }
    let client_id = format!(
        "{CLIENT_PREFIX}{}",
        random_b64(16).ok_or(OAuthError::SERVER_ERROR)?
    );
    let rec = OAuthClientRecord {
        client_id: client_id.clone(),
        name: accepted.client_name.clone(),
        redirect_uris: accepted.redirect_uris.clone(),
        created_at: now,
        source_ip_hash: o.ip_hash(ip),
    };
    store.oauth_client_insert(&rec).map_err(store_err)?;
    let mut hosts: Vec<String> = accepted.redirect_uris.iter().map(|u| host_of(u)).collect();
    hosts.sort();
    hosts.dedup();
    if anchor
        .operational(
            KIND_CLIENT_REGISTERED,
            &json!({"client_id": client_id, "client_name": accepted.client_name,
                    "redirect_hosts": hosts, "source_ip_hash": rec.source_ip_hash}),
        )
        .is_err()
    {
        tracing::error!(
            event = "anchor_append_failed",
            kind = KIND_CLIENT_REGISTERED
        );
    }
    tracing::info!(event = "oauth_client_registered", client_id = %client_id);
    Ok(json!({
        "client_id": client_id,
        "client_id_issued_at": now,
        "client_name": accepted.client_name,
        "redirect_uris": accepted.redirect_uris,
        "grant_types": accepted.grant_types,
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }))
}
