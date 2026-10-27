//! The OAuth 2.1 authorization server for remote MCP (SM-3.3, M14 PD-233..PD-245): metadata
//! (RFC 9728, RFC 8414), dynamic registration of public clients (RFC 7591), the authorization
//! endpoint with consent through the domain-login session, the token endpoint (authorization code
//! with PKCE S256, rotating refresh tokens with reuse detection), revocation (RFC 7009) and the
//! bearer check of `/mcp`. AS and RS are one process: tokens are opaque random strings, stored
//! only as `SHA-256("atlas-duck/oauth/v1\0" || kind || token)` (PD-235).

pub mod authorize;
pub mod bearer;
pub mod consent;
pub mod error;
pub mod metadata;
pub mod ratelimit;
pub mod redirect;
pub mod register;
pub mod token;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::SecretString;
/// The hook M13's user deactivation calls (Δ-M14-4): revokes all of a user's OAuth grants, one
/// `OAUTH_GRANT_REVOKED {by: deactivation}` record each. At the M13 merge `users::deactivate`
/// must call it before it appends the `USER_DEACTIVATED` anchor row.
pub use token::revoke_all_for_user;

use std::collections::HashMap;
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::store::ServerStore;
use ratelimit::WindowLimiter;

/// The scopes a grant may hold: the API-key scopes verbatim (PD-242).
pub const SCOPES: [&str; 3] = crate::api_keys::SCOPES;
/// Token prefixes (PD-235).
pub const CODE_PREFIX: &str = "ado_ac_";
pub const ACCESS_PREFIX: &str = "ado_at_";
pub const REFRESH_PREFIX: &str = "ado_rt_";
/// Client ids: `adc_` and 22 base64url characters (16 random bytes).
pub const CLIENT_PREFIX: &str = "adc_";
/// Hash domain of every stored OAuth secret.
const HASH_DOMAIN: &[u8] = b"atlas-duck/oauth/v1\0";
/// Code lifetime (PD-235).
pub const CODE_TTL_SECS: i64 = 60;
/// Consent request lifetime (PD-241).
pub const CONSENT_TTL_SECS: i64 = 600;
/// PD-240: the registration window.
pub const REGISTER_WINDOW_SECS: i64 = 3600;
/// Token endpoint requests per client IP and minute (T8).
pub const TOKEN_PER_IP_MINUTE: u32 = 60;

/// The OAuth settings (plan "Configuration").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthConfig {
    pub enabled: bool,
    pub access_ttl_secs: i64,
    pub refresh_idle_secs: i64,
    pub grant_max_secs: i64,
    pub register_per_ip_hour: u32,
    pub max_clients: u64,
}

impl OAuthConfig {
    pub const DEFAULT: OAuthConfig = OAuthConfig {
        enabled: true,
        access_ttl_secs: 900,
        refresh_idle_secs: 14 * 86_400,
        grant_max_secs: 90 * 86_400,
        register_per_ip_hour: 10,
        max_clients: 1000,
    };
}

/// The authorization server's state.
pub struct OAuth {
    pub cfg: OAuthConfig,
    /// The public URL without a trailing slash (RFC 8414 `issuer`).
    pub issuer: String,
    /// The one resource: `<issuer>/mcp` (PD-237).
    pub resource: String,
    pub register_limiter: WindowLimiter,
    pub token_limiter: WindowLimiter,
    /// The key of [`OAuth::ip_hash`] (batch-1 review M1), derived from the master key.
    ip_key: Zeroizing<[u8; 32]>,
    /// Per grant: when its last refused-token `LOGIN` record was written (batch-2 review m1).
    refusals: Mutex<HashMap<String, i64>>,
}

/// A refused token of one grant is recorded in its owner's chain at most once per this window.
pub const REFUSAL_RECORD_EVERY: i64 = 60;
/// Above this many remembered grants, expired windows are dropped.
const REFUSALS_PRUNE_AT: usize = 4096;

/// The master-key label of the source-IP hash key.
pub const IP_KEY_LABEL: &str = "atlas-duck/oauth/source-ip/v1";

impl OAuth {
    pub fn new(cfg: OAuthConfig, public_origin: &str, ip_key: Zeroizing<[u8; 32]>) -> OAuth {
        let issuer = public_origin.trim_end_matches('/').to_owned();
        OAuth {
            resource: format!("{issuer}{}", crate::mcp::MCP_PATH),
            issuer,
            ip_key,
            refusals: Mutex::new(HashMap::new()),
            register_limiter: WindowLimiter::new(cfg.register_per_ip_hour, REGISTER_WINDOW_SECS),
            token_limiter: WindowLimiter::new(TOKEN_PER_IP_MINUTE, 60),
            cfg,
        }
    }

    /// Hex HMAC-SHA256 of a client IP under the server-held key: what the store and the anchor
    /// row keep of it. Unlike a plain SHA-256 it cannot be reversed by enumerating addresses.
    pub fn ip_hash(&self, ip: &str) -> String {
        hex::encode(crate::master_key::hmac_sha256(&self.ip_key, ip.as_bytes()))
    }

    /// Whether a refused token of `grant_id` is recorded now: once per grant per
    /// [`REFUSAL_RECORD_EVERY`], so a holder of a revoked or expired token cannot grow the
    /// owner's chain (or keep the owner's runtime open) at the request rate.
    pub fn refusal_due(&self, grant_id: &str, now: i64) -> bool {
        let Ok(mut seen) = self.refusals.lock() else {
            return false;
        };
        if seen
            .get(grant_id)
            .is_some_and(|&t| now - t < REFUSAL_RECORD_EVERY)
        {
            return false;
        }
        if seen.len() >= REFUSALS_PRUNE_AT {
            seen.retain(|_, t| now - *t < REFUSAL_RECORD_EVERY);
        }
        seen.insert(grant_id.to_owned(), now);
        true
    }

    /// The protected-resource metadata URL a 401 names (RFC 9728 §5.1).
    pub fn resource_metadata_url(&self) -> String {
        format!(
            "{}{}{}",
            self.issuer,
            metadata::PRM_PATH,
            crate::mcp::MCP_PATH
        )
    }
}

/// The stored hash of an OAuth secret of `kind` (`code`, `access`, `refresh`, `consent`).
pub fn secret_hash(kind: &str, secret: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(HASH_DOMAIN);
    h.update(kind.as_bytes());
    h.update([0u8]);
    h.update(secret.as_bytes());
    h.finalize().into()
}

/// `n` random bytes, base64url without padding.
pub fn random_b64(n: usize) -> Option<String> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).ok()?;
    Some(URL_SAFE_NO_PAD.encode(b))
}

/// A new token: `prefix` and 43 base64url characters (32 random bytes).
pub fn new_token(prefix: &str) -> Option<SecretString> {
    Some(SecretString::from(format!("{prefix}{}", random_b64(32)?)))
}

/// `prefix` + 43 base64url characters, nothing else.
pub fn token_shape_ok(token: &str, prefix: &str) -> bool {
    token.strip_prefix(prefix).is_some_and(|rest| {
        rest.len() == 43
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// The scheduler job `oauth_purge` (PD-240): stale clients and every expired OAuth row. Runs
/// daily from `app.rs` until M13's scheduler merges.
pub fn purge(store: &dyn ServerStore, now: i64) {
    match store.oauth_purge(now) {
        Ok(n) => tracing::info!(event = "oauth_purge", clients = n),
        Err(_) => tracing::error!(event = "oauth_purge_failed"),
    }
}

#[cfg(test)]
#[path = "../tests/oauth.rs"]
mod tests;
