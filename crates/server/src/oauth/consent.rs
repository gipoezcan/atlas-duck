//! Consent (PD-241, PD-242): the page's details of a stored authorization request, and the
//! user's decision. "Allow" replaces any live grant of the same user and client (`replaced`),
//! records `OAUTH_GRANT_CREATED` in the user's chain before the grant exists, and answers the
//! client redirect with a single-use code; "deny" answers the redirect with `access_denied`. The
//! request is consumed either way. Every authorization asks again (no remembered consent, L244).

use serde::Deserialize;
use serde_json::{Value, json};

use super::authorize::with_params;
use super::redirect::host_of;
use super::{CODE_PREFIX, CODE_TTL_SECS, OAuth, new_token, random_b64, secret_hash};
use crate::audit_kinds::{GrantRevokedBy, oauth_grant_created, oauth_grant_revoked};
use crate::clock::rfc3339;
use crate::errors::ApiError;
use crate::runtime::UserRuntime;
use crate::store::{CodeRecord, ConsentRequestRecord, GrantRecord, ServerStore};

/// The fixed plain-English effect of each scope (the consent page shows these, T9).
pub fn scope_text(scope: &str) -> &'static str {
    match scope {
        "read" => "Read Jira and Confluence data you can read, after you release it.",
        "propose_write" => "Propose changes. Every change still needs your approval here.",
        "scripts" => "Run read-only scripts in the sandbox; you approve each final result.",
        _ => "",
    }
}

/// `POST /api/oauth/consent/{req}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBody {
    pub decision: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

fn store_err<E>(_: E) -> ApiError {
    ApiError::STORE_UNAVAILABLE
}

/// The request of this session, if it is still open.
fn open_request(
    store: &dyn ServerStore,
    req: &str,
    session_hash: &[u8; 32],
    now: i64,
    take: bool,
) -> Result<ConsentRequestRecord, ApiError> {
    let id_hash = secret_hash("consent", req);
    let found = if take {
        store.consent_take(&id_hash, session_hash)
    } else {
        store.consent_get(&id_hash, session_hash)
    }
    .map_err(store_err)?
    .ok_or(ApiError::OAUTH_REQUEST_UNKNOWN)?;
    if now >= found.expires_at {
        return Err(ApiError::OAUTH_REQUEST_EXPIRED);
    }
    Ok(found)
}

/// `GET /api/oauth/consent/{req}`: what the consent page shows.
pub fn details(
    store: &dyn ServerStore,
    req: &str,
    session_hash: &[u8; 32],
    now: i64,
) -> Result<Value, ApiError> {
    let r = open_request(store, req, session_hash, now, false)?;
    let client = store
        .oauth_client_get(&r.client_id)
        .map_err(store_err)?
        .ok_or(ApiError::OAUTH_REQUEST_UNKNOWN)?;
    let scopes: Vec<Value> = r
        .scopes
        .iter()
        .map(|s| json!({"name": s, "text": scope_text(s)}))
        .collect();
    Ok(json!({
        "client_name": client.name,
        "client_id": client.client_id,
        "redirect_host": host_of(&r.redirect_uri),
        "redirect_uri": r.redirect_uri,
        "scopes": scopes,
        "expires_at": rfc3339(r.expires_at),
    }))
}

/// The user's decision on the request; answers the client redirect.
pub async fn decide(
    o: &OAuth,
    store: &dyn ServerStore,
    rt: &UserRuntime,
    req: &str,
    session_hash: &[u8; 32],
    body: DecisionBody,
    now: i64,
) -> Result<String, ApiError> {
    if body.decision != "allow" && body.decision != "deny" {
        return Err(ApiError::BAD_REQUEST);
    }
    let r = open_request(store, req, session_hash, now, true)?;
    if r.user_id != rt.user_id() {
        // A session names exactly one user; a mismatch cannot happen through the router.
        return Err(ApiError::OAUTH_REQUEST_UNKNOWN);
    }
    let base = |pairs: &[(&str, &str)]| {
        let mut all = pairs.to_vec();
        all.push(("state", r.state.as_str()));
        all.push(("iss", o.issuer.as_str()));
        with_params(&r.redirect_uri, &all)
    };
    if body.decision == "deny" {
        return Ok(base(&[("error", "access_denied")]));
    }
    if !crate::users::is_active(store, &r.user_id) {
        return Err(ApiError::NOT_PERMITTED);
    }
    // The user may drop scopes, never add; `read` is implied by every grant (PD-242).
    if body.scopes.iter().any(|s| !r.scopes.contains(s)) {
        return Err(ApiError::BAD_REQUEST);
    }
    let mut scopes: Vec<String> = r
        .scopes
        .iter()
        .filter(|s| *s == "read" || body.scopes.contains(s))
        .cloned()
        .collect();
    if !scopes.iter().any(|s| s == "read") {
        scopes.insert(0, "read".into());
    }
    let client = store
        .oauth_client_get(&r.client_id)
        .map_err(store_err)?
        .ok_or(ApiError::OAUTH_REQUEST_UNKNOWN)?;
    // PD-236: re-consent replaces the live grant of the same user and client.
    for old in store
        .grant_list(&r.user_id)
        .map_err(store_err)?
        .into_iter()
        .filter(|g| g.client_id == r.client_id && g.live(now))
    {
        rt.append_server_record(
            atlas_duck_audit::EventType::OAUTH_GRANT_REVOKED,
            oauth_grant_revoked(&old.grant_id, &old.client_id, GrantRevokedBy::Replaced),
        )
        .await?;
        store
            .grant_revoke(&old.grant_id, GrantRevokedBy::Replaced.as_str(), now)
            .map_err(store_err)?;
    }
    let grant_id = format!("grt_{}", random_b64(16).ok_or(ApiError::INTERNAL)?);
    let expires_at = now + o.cfg.grant_max_secs;
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
    // Audit before effect: the grant exists only once its record does.
    rt.append_server_record(
        atlas_duck_audit::EventType::OAUTH_GRANT_CREATED,
        oauth_grant_created(
            &grant_id,
            &client.client_id,
            &client.name,
            &host_of(&r.redirect_uri),
            &scope_refs,
            &rfc3339(expires_at),
        ),
    )
    .await?;
    store
        .grant_insert(&GrantRecord {
            grant_id: grant_id.clone(),
            user_id: r.user_id.clone(),
            client_id: client.client_id.clone(),
            scopes,
            resource: r.resource.clone(),
            created_at: now,
            expires_at,
            last_used_at: None,
            revoked_at: None,
            revoke_reason: None,
        })
        .map_err(store_err)?;
    let code = new_token(CODE_PREFIX).ok_or(ApiError::INTERNAL)?;
    let code_str = secrecy::ExposeSecret::expose_secret(&code);
    store
        .code_insert(&CodeRecord {
            hash: secret_hash("code", code_str),
            grant_id,
            client_id: client.client_id,
            redirect_uri: r.redirect_uri.clone(),
            code_challenge: r.code_challenge.clone(),
            expires_at: now + CODE_TTL_SECS,
            redeemed_at: None,
        })
        .map_err(store_err)?;
    Ok(base(&[("code", code_str)]))
}
