//! The access-token check of `/mcp` (PD-243, PD-245): by hash, then on every request the token's
//! expiry, the grant's revocation and absolute expiry, the resource, and the user's state. No
//! cache: a revocation takes effect on the next request.

use super::{ACCESS_PREFIX, OAuth, secret_hash, token_shape_ok};
use crate::api_keys::KeyCtx;
use crate::runtime::UserCtx;
use crate::store::ServerStore;

/// `last_used_at` of a grant is written at most this often.
pub const TOUCH_EVERY: i64 = 60;

/// Why an access token was not accepted. Every case is the same 401 to the client; a refusal of
/// a known grant is also recorded in its owner's chain (`LOGIN {method: oauth, outcome: refused}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessFail {
    Invalid,
    Refused {
        user_id: String,
        grant_id: String,
        reason: &'static str,
    },
    Store,
}

/// The token's user and scopes, or why not.
pub fn authenticate(
    o: &OAuth,
    store: &dyn ServerStore,
    token: &str,
    now: i64,
) -> Result<KeyCtx, AccessFail> {
    if !token_shape_ok(token, ACCESS_PREFIX) {
        return Err(AccessFail::Invalid);
    }
    let access = store
        .access_get(&secret_hash("access", token))
        .map_err(|_| AccessFail::Store)?
        .ok_or(AccessFail::Invalid)?;
    let grant = store
        .grant_get(&access.grant_id)
        .map_err(|_| AccessFail::Store)?
        .ok_or(AccessFail::Invalid)?;
    let refuse = |reason| AccessFail::Refused {
        user_id: grant.user_id.clone(),
        grant_id: grant.grant_id.clone(),
        reason,
    };
    if grant.revoked_at.is_some() || !crate::users::is_active(store, &grant.user_id) {
        return Err(refuse("revoked"));
    }
    if now >= access.expires_at || now >= grant.expires_at {
        return Err(refuse("expired"));
    }
    if grant.resource != o.resource {
        return Err(refuse("wrong_resource"));
    }
    if grant.last_used_at.is_none_or(|t| now - t >= TOUCH_EVERY) {
        let _ = store.grant_touch(&grant.grant_id, now);
    }
    Ok(KeyCtx {
        user: UserCtx::from_authenticated(&grant.user_id),
        credential: format!("oauth:{}", grant.grant_id),
        key_id: grant.grant_id,
        prefix: String::new(),
        scopes: access.scopes,
    })
}
