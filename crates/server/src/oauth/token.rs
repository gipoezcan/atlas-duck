//! The token endpoint (PD-234..PD-237) and the revocation endpoint (RFC 7009, PD-245), and the
//! grant revocations that write records: reuse detection (PD-236) and deactivation (Δ-M14-4).
//!
//! `authorization_code`: the code is single use (a failed redemption burns it; a second
//! redemption revokes the whole grant), bound to its client and redirect URI, and the PKCE
//! verifier must hash to the stored S256 challenge (compared in constant time).
//! `refresh_token`: strict rotation, no grace window (L242): every use issues a new pair and a
//! rotated token presented again revokes the grant.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::authorize::{params, resource_ok};
use super::error::OAuthError;
use super::{
    ACCESS_PREFIX, CODE_PREFIX, OAuth, REFRESH_PREFIX, new_token, secret_hash, token_shape_ok,
};
use crate::anchor::AnchorWriter;
use crate::audit_kinds::{GrantRevokedBy, oauth_grant_revoked};
use crate::runtime::{Registry, UserCtx};
use crate::store::{AccessRecord, GrantRecord, Redeem, RefreshRecord, Rotate, ServerStore};

/// The largest token or revocation body.
pub const BODY_LIMIT: usize = 8 * 1024;
/// The anchor chain's operational kind of a detected reuse.
pub const KIND_REUSE: &str = "OAUTH_REUSE";

/// What the endpoints need.
pub struct Ctx<'a> {
    pub o: &'a OAuth,
    pub store: &'a dyn ServerStore,
    pub registry: &'a Registry,
    pub anchor: &'a AnchorWriter,
    pub now: i64,
}

fn store_err<E>(_: E) -> OAuthError {
    OAuthError::TEMPORARILY_UNAVAILABLE
}

/// PKCE (RFC 7636 §4.1, §4.6): 43..=128 unreserved characters whose S256 is the challenge.
pub fn verifier_matches(verifier: &str, challenge: &str) -> bool {
    let shape = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    if !shape {
        return false;
    }
    let got = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    bool::from(got.as_bytes().ct_eq(challenge.as_bytes()))
}

/// Appends `OAUTH_GRANT_REVOKED` to the grant owner's chain.
async fn record_revoked(registry: &Registry, g: &GrantRecord, by: GrantRevokedBy) {
    let owner = UserCtx::from_authenticated(&g.user_id);
    let appended = match registry.runtime(&owner).await {
        Ok(rt) => rt
            .append_server_record(
                atlas_duck_audit::EventType::OAUTH_GRANT_REVOKED,
                oauth_grant_revoked(&g.grant_id, &g.client_id, by),
            )
            .await
            .is_ok(),
        Err(_) => false,
    };
    if !appended {
        tracing::error!(event = "audit_append_failed", kind = "OAUTH_GRANT_REVOKED");
    }
}

/// PD-236: a reused code or refresh token revokes the whole grant at once, records
/// `OAUTH_GRANT_REVOKED {by: reuse_detected}` and an anchor `OAUTH_REUSE` row.
pub async fn reuse_detected(c: &Ctx<'_>, grant_id: &str, reason: &'static str) {
    let Ok(Some(g)) = c.store.grant_get(grant_id) else {
        return;
    };
    match c.store.grant_revoke(grant_id, reason, c.now) {
        Ok(true) => {}
        // Already revoked (a concurrent reuse recorded it).
        Ok(false) => return,
        Err(_) => {
            tracing::error!(event = "oauth_reuse_revoke_failed");
            return;
        }
    }
    tracing::warn!(event = "oauth_reuse_detected", grant_id = %g.grant_id, reason);
    record_revoked(c.registry, &g, GrantRevokedBy::ReuseDetected).await;
    if c.anchor
        .operational(
            KIND_REUSE,
            &json!({"client_id": g.client_id, "grant_id": g.grant_id}),
        )
        .is_err()
    {
        tracing::error!(event = "anchor_append_failed", kind = KIND_REUSE);
    }
}

/// Δ-M14-4: deactivation revokes every grant of the user (M13's `users::deactivate` calls this
/// at merge); one `OAUTH_GRANT_REVOKED {by: deactivation}` per grant.
pub async fn revoke_all_for_user(
    store: &dyn ServerStore,
    registry: &Registry,
    user_id: &str,
    now: i64,
) -> Result<usize, crate::store::StoreError> {
    let revoked = store.grant_revoke_all(user_id, GrantRevokedBy::Deactivation.as_str(), now)?;
    for g in &revoked {
        record_revoked(registry, g, GrantRevokedBy::Deactivation).await;
    }
    Ok(revoked.len())
}

/// The token response (RFC 6749 §5.1).
fn tokens(c: &Ctx<'_>, grant: &GrantRecord, scopes: &[String]) -> Result<Value, OAuthError> {
    let access = new_token(ACCESS_PREFIX).ok_or(OAuthError::SERVER_ERROR)?;
    let ttl = c.o.cfg.access_ttl_secs;
    c.store
        .access_insert(&AccessRecord {
            hash: secret_hash("access", access.expose_secret()),
            grant_id: grant.grant_id.clone(),
            scopes: scopes.to_vec(),
            expires_at: (c.now + ttl).min(grant.expires_at),
        })
        .map_err(store_err)?;
    Ok(json!({
        "access_token": access.expose_secret(),
        "token_type": "Bearer",
        "expires_in": ttl.min(grant.expires_at - c.now),
        "scope": scopes.join(" "),
    }))
}

fn new_refresh(c: &Ctx<'_>, grant_id: &str) -> Result<(SecretString, RefreshRecord), OAuthError> {
    let t = new_token(REFRESH_PREFIX).ok_or(OAuthError::SERVER_ERROR)?;
    let rec = RefreshRecord {
        hash: secret_hash("refresh", t.expose_secret()),
        grant_id: grant_id.to_owned(),
        created_at: c.now,
        last_used_at: c.now,
        rotated_at: None,
    };
    Ok((t, rec))
}

type Params = std::collections::HashMap<String, String>;

fn required<'p>(p: &'p Params, k: &str) -> Result<&'p str, OAuthError> {
    p.get(k)
        .map(String::as_str)
        .filter(|v| !v.is_empty())
        .ok_or(OAuthError::INVALID_REQUEST)
}

/// The client named by `client_id` (public clients authenticate by id only).
fn client_known(c: &Ctx<'_>, p: &Params) -> Result<String, OAuthError> {
    let id = required(p, "client_id")?;
    match c.store.oauth_client_get(id).map_err(store_err)? {
        Some(cl) => Ok(cl.client_id),
        None => Err(OAuthError::INVALID_CLIENT),
    }
}

async fn authorization_code(c: &Ctx<'_>, p: &Params) -> Result<Value, OAuthError> {
    let code = required(p, "code")?;
    let redirect_uri = required(p, "redirect_uri")?;
    let verifier = required(p, "code_verifier")?;
    let resource = required(p, "resource")?;
    let client_id = client_known(c, p)?;
    if !resource_ok(c.o, resource) {
        return Err(OAuthError::INVALID_TARGET);
    }
    if !token_shape_ok(code, CODE_PREFIX) {
        return Err(OAuthError::INVALID_GRANT);
    }
    let (code_rec, grant) = match c.store.code_redeem(&secret_hash("code", code), c.now) {
        Ok(found) => found,
        Err(Redeem::Reused(grant_id)) => {
            reuse_detected(c, &grant_id, "code_reuse").await;
            return Err(OAuthError::INVALID_GRANT);
        }
        Err(Redeem::Unknown | Redeem::Expired) => return Err(OAuthError::INVALID_GRANT),
        Err(Redeem::Store(_)) => return Err(OAuthError::TEMPORARILY_UNAVAILABLE),
    };
    // From here the code is burned whatever happens (PD-234).
    if code_rec.client_id != client_id
        || code_rec.redirect_uri != redirect_uri
        || !verifier_matches(verifier, &code_rec.code_challenge)
        || !grant.live(c.now)
    {
        return Err(OAuthError::INVALID_GRANT);
    }
    let mut body = tokens(c, &grant, &grant.scopes)?;
    let (refresh, rec) = new_refresh(c, &grant.grant_id)?;
    c.store.refresh_insert(&rec).map_err(store_err)?;
    body["refresh_token"] = Value::from(refresh.expose_secret());
    Ok(body)
}

async fn refresh_token(c: &Ctx<'_>, p: &Params) -> Result<Value, OAuthError> {
    let token = required(p, "refresh_token")?;
    let resource = required(p, "resource")?;
    let client_id = client_known(c, p)?;
    if !resource_ok(c.o, resource) {
        return Err(OAuthError::INVALID_TARGET);
    }
    if !token_shape_ok(token, REFRESH_PREFIX) {
        return Err(OAuthError::INVALID_GRANT);
    }
    let hash = secret_hash("refresh", token);
    let grant_id = c
        .store
        .refresh_grant(&hash)
        .map_err(store_err)?
        .ok_or(OAuthError::INVALID_GRANT)?;
    let grant = c
        .store
        .grant_get(&grant_id)
        .map_err(store_err)?
        .ok_or(OAuthError::INVALID_GRANT)?;
    if grant.client_id != client_id {
        return Err(OAuthError::INVALID_GRANT);
    }
    // A narrower scope only (checked before the token is spent).
    let scopes: Vec<String> = match p.get("scope").map(String::as_str) {
        None | Some("") => grant.scopes.clone(),
        Some(raw) => {
            let asked: Vec<String> = raw
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            if asked.iter().any(|s| !grant.scopes.contains(s)) {
                return Err(OAuthError::INVALID_SCOPE);
            }
            grant
                .scopes
                .iter()
                .filter(|s| asked.contains(s))
                .cloned()
                .collect()
        }
    };
    let (refresh, rec) = new_refresh(c, &grant.grant_id)?;
    let grant = match c
        .store
        .refresh_rotate(&hash, &rec, c.now, c.o.cfg.refresh_idle_secs)
    {
        Ok(g) => g,
        Err(Rotate::Reused(grant_id)) => {
            reuse_detected(c, &grant_id, "refresh_reuse").await;
            return Err(OAuthError::INVALID_GRANT);
        }
        Err(Rotate::Unknown | Rotate::Expired) => return Err(OAuthError::INVALID_GRANT),
        Err(Rotate::Store(_)) => return Err(OAuthError::TEMPORARILY_UNAVAILABLE),
    };
    let mut body = tokens(c, &grant, &scopes)?;
    body["refresh_token"] = Value::from(refresh.expose_secret());
    Ok(body)
}

/// `POST /oauth/token`: the form body, already read (at most [`BODY_LIMIT`]).
pub async fn token(c: &Ctx<'_>, body: &[u8]) -> Result<Value, OAuthError> {
    let text = std::str::from_utf8(body).map_err(|_| OAuthError::INVALID_REQUEST)?;
    let p = params(Some(text)).ok_or(OAuthError::INVALID_REQUEST)?;
    match p
        .get("grant_type")
        .map(String::as_str)
        .filter(|g| !g.is_empty())
    {
        Some("authorization_code") => authorization_code(c, &p).await,
        Some("refresh_token") => refresh_token(c, &p).await,
        Some(_) => Err(OAuthError::UNSUPPORTED_GRANT_TYPE),
        None => Err(OAuthError::INVALID_REQUEST),
    }
}

/// `POST /oauth/revoke` (RFC 7009): revokes the grant of an access or refresh token of this
/// client; an unknown token (or another client's) is answered 200 like a revoked one (§2.2).
pub async fn revoke(c: &Ctx<'_>, body: &[u8]) -> Result<(), OAuthError> {
    let text = std::str::from_utf8(body).map_err(|_| OAuthError::INVALID_REQUEST)?;
    let p = params(Some(text)).ok_or(OAuthError::INVALID_REQUEST)?;
    let token = required(&p, "token")?;
    let client_id = required(&p, "client_id")?;
    let grant_id = if token_shape_ok(token, ACCESS_PREFIX) {
        c.store
            .access_get(&secret_hash("access", token))
            .map_err(store_err)?
            .map(|a| a.grant_id)
    } else if token_shape_ok(token, REFRESH_PREFIX) {
        c.store
            .refresh_grant(&secret_hash("refresh", token))
            .map_err(store_err)?
    } else {
        None
    };
    let Some(grant_id) = grant_id else {
        return Ok(());
    };
    let Some(g) = c.store.grant_get(&grant_id).map_err(store_err)? else {
        return Ok(());
    };
    if g.client_id != client_id {
        return Ok(());
    }
    let by = GrantRevokedBy::RevocationEndpoint;
    if c.store
        .grant_revoke(&grant_id, by.as_str(), c.now)
        .map_err(store_err)?
    {
        record_revoked(c.registry, &g, by).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_rfc7636_vector_and_shape() {
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let ch = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verifier_matches(v, ch));
        assert!(!verifier_matches(v, &ch.replace('E', "F")));
        assert!(!verifier_matches(&v[..42], ch), "too short");
        assert!(!verifier_matches(&"a".repeat(129), ch), "too long");
        assert!(
            !verifier_matches(&format!("{}+", &v[..42]), ch),
            "not unreserved"
        );
        // The plain method is never accepted: the challenge itself as verifier fails.
        assert!(!verifier_matches(ch, ch));
    }
}
