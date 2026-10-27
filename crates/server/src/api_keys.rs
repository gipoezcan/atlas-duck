//! API keys for agents (SM-3.2, PD-213, PD-214): `adk_<prefix>_<secret>` with an 8-character
//! `[a-z0-9]` prefix and 32 random bytes of secret (base64url, 43 characters). The store keeps the
//! argon2id hash of the whole key string (`$argon2id$v=19$m=..,t=..,p=..$<salt>$<hash>`, salt and
//! hash base64 without padding), never the key. Lookup is by prefix, then the hash is verified;
//! an unknown prefix or a malformed key verifies against a fixed dummy hash, so every bad key
//! costs the same and answers the same (`auth/api_key_invalid`). A verified key is cached for 60 s
//! by `SHA-256(key)`; revocation evicts it at once. `last_used_at` is written at most every 60 s.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::errors::ApiError;
use crate::runtime::UserCtx;
use crate::store::{ApiKeyRecord, ServerStore, StoreError};

pub const KEY_PREFIX: &str = "adk_";
pub const PREFIX_LEN: usize = 8;
pub const SECRET_B64_LEN: usize = 43;
pub const SCOPES: [&str; 3] = ["read", "propose_write", "scripts"];
pub const MAX_ACTIVE_KEYS: u64 = 25;
pub const DEFAULT_EXPIRY_DAYS: u64 = 30;
pub const MAX_EXPIRY_DAYS: u64 = 90;
pub const MAX_NAME_CHARS: usize = 64;
/// PD-213: verified keys stay cached this long.
pub const CACHE_SECS: i64 = 60;
/// PD-213: `last_used_at` is written at most this often per key.
pub const LAST_USED_EVERY: i64 = 60;

/// Argon2id parameters (PD-213).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiKeyParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl ApiKeyParams {
    /// OWASP 2023 minimum: m = 19 456 KiB, t = 2, p = 1.
    pub const PRODUCTION: ApiKeyParams = ApiKeyParams {
        m_kib: 19_456,
        t: 2,
        p: 1,
    };
    /// Tests only: m = 8 KiB, t = 1.
    #[cfg(any(test, feature = "testing"))]
    pub const TEST: ApiKeyParams = ApiKeyParams {
        m_kib: 8,
        t: 1,
        p: 1,
    };
}

/// A new key: the key string is shown once.
pub struct CreatedKey {
    pub id: String,
    pub key: SecretString,
    pub view: KeyView,
}

/// A key drawn but not stored yet ([ApiKeys::prepare], then [ApiKeys::insert]).
pub struct Prepared {
    rec: ApiKeyRecord,
    key: SecretString,
}

impl Prepared {
    pub fn view(&self) -> KeyView {
        KeyView::from(&self.rec)
    }
}

/// What lists and answers show of a key: never the key or its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyView {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

impl From<&ApiKeyRecord> for KeyView {
    fn from(r: &ApiKeyRecord) -> Self {
        KeyView {
            id: r.id.clone(),
            name: r.name.clone(),
            prefix: r.prefix.clone(),
            scopes: r.scopes.clone(),
            created_at: r.created_at,
            expires_at: r.expires_at,
            last_used_at: r.last_used_at,
            revoked_at: r.revoked_at,
        }
    }
}

/// An authenticated agent: its user and the credential's scopes. Built by the API-key check and,
/// since M14, the OAuth access-token check (PD-243): `key_id` is then the grant id and `prefix`
/// empty; `credential` tags both (`api_key:<id>` / `oauth:<grant_id>`) for the MCP session
/// binding and the connection id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCtx {
    pub user: UserCtx,
    pub key_id: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub credential: String,
}

/// Why a bearer was not accepted. The answer is the same 401 for every case (PD-214); a revoked
/// or expired key of a known owner is also recorded in the owner's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFail {
    Invalid,
    Refused {
        user_id: String,
        key_id: String,
        prefix: String,
        reason: &'static str,
    },
    Store,
}

struct Cached {
    key_id: String,
    user_id: String,
    prefix: String,
    scopes: Vec<String>,
    expires_at: i64,
    at: i64,
}

#[cfg(test)]
type VerifyHook = Box<dyn Fn(&ApiKeys) + Send>;

pub struct ApiKeys {
    store: Arc<dyn ServerStore>,
    clock: Arc<dyn Clock>,
    params: ApiKeyParams,
    dummy_hash: String,
    cache: Mutex<HashMap<[u8; 32], Cached>>,
    last_used: Mutex<HashMap<String, i64>>,
    dummy_verifies: AtomicU64,
    /// Batch-3 review I2: bumped (under the cache lock) by every invalidation; a verify that saw
    /// another generation does not cache, so a revoke during argon2 is never undone by the cache.
    generation: AtomicU64,
    #[cfg(test)]
    after_verify: Mutex<Option<VerifyHook>>,
}

fn store_err(_: StoreError) -> ApiError {
    ApiError::STORE_UNAVAILABLE
}

fn random(n: usize) -> Result<Vec<u8>, ApiError> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).map_err(|_| ApiError::INTERNAL)?;
    Ok(b)
}

/// 8 characters of `[a-z0-9]`, unbiased (rejection sampling).
fn random_prefix() -> Result<String, ApiError> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(PREFIX_LEN);
    while out.len() < PREFIX_LEN {
        for b in random(16)? {
            if b < 252 && out.len() < PREFIX_LEN {
                out.push(char::from(ALPHABET[usize::from(b % 36)]));
            }
        }
    }
    Ok(out)
}

fn argon(params: ApiKeyParams) -> Option<Argon2<'static>> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(32)).ok()?;
    Some(Argon2::new(Algorithm::Argon2id, Version::V0x13, p))
}

/// The PHC-form hash of `key` under `params` with a fresh salt.
fn hash_key(key: &str, params: ApiKeyParams) -> Result<String, ApiError> {
    let salt = random(16)?;
    let mut out = Zeroizing::new([0u8; 32]);
    argon(params)
        .ok_or(ApiError::INTERNAL)?
        .hash_password_into(key.as_bytes(), &salt, out.as_mut())
        .map_err(|_| ApiError::INTERNAL)?;
    Ok(format!(
        "$argon2id$v=19$m={},t={},p={}${}${}",
        params.m_kib,
        params.t,
        params.p,
        STANDARD_NO_PAD.encode(&salt),
        STANDARD_NO_PAD.encode(out.as_ref())
    ))
}

/// Verifies `key` against a hash [`hash_key`] wrote; anything malformed is `false`.
fn verify_key(key: &str, phc: &str) -> bool {
    let parts: Vec<&str> = phc.split('$').collect();
    let [_, "argon2id", "v=19", params, salt, hash] = parts.as_slice() else {
        return false;
    };
    let mut m = None;
    let mut t = None;
    let mut p = None;
    for kv in params.split(',') {
        match kv.split_once('=') {
            Some(("m", v)) => m = v.parse().ok(),
            Some(("t", v)) => t = v.parse().ok(),
            Some(("p", v)) => p = v.parse().ok(),
            _ => return false,
        }
    }
    let (Some(m_kib), Some(t), Some(p)) = (m, t, p) else {
        return false;
    };
    let (Ok(salt), Ok(want)) = (STANDARD_NO_PAD.decode(salt), STANDARD_NO_PAD.decode(hash)) else {
        return false;
    };
    let Some(a) = argon(ApiKeyParams { m_kib, t, p }) else {
        return false;
    };
    let mut got = Zeroizing::new(vec![0u8; want.len().max(1)]);
    if a.hash_password_into(key.as_bytes(), &salt, &mut got)
        .is_err()
    {
        return false;
    }
    bool::from(got.as_slice().ct_eq(want.as_slice()))
}

/// `adk_<prefix>_<secret>` split; `None` when the shape is wrong.
fn split_key(key: &str) -> Option<(&str, &str)> {
    let rest = key.strip_prefix(KEY_PREFIX)?;
    let (prefix, secret) = rest.split_once('_')?;
    let prefix_ok = prefix.len() == PREFIX_LEN
        && prefix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let secret_ok = secret.len() == SECRET_B64_LEN
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    (prefix_ok && secret_ok).then_some((prefix, secret))
}

pub fn valid_name(name: &str) -> bool {
    let n = name.chars().count();
    (1..=MAX_NAME_CHARS).contains(&n) && !name.chars().any(char::is_control)
}

impl ApiKeys {
    pub fn new(
        store: Arc<dyn ServerStore>,
        clock: Arc<dyn Clock>,
        params: ApiKeyParams,
    ) -> Result<ApiKeys, ApiError> {
        // The dummy: a hash of a random key nobody holds, under the same parameters.
        let dummy_key = URL_SAFE_NO_PAD.encode(random(32)?);
        let dummy_hash = hash_key(&dummy_key, params)?;
        Ok(ApiKeys {
            store,
            clock,
            params,
            dummy_hash,
            cache: Mutex::new(HashMap::new()),
            last_used: Mutex::new(HashMap::new()),
            dummy_verifies: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            #[cfg(test)]
            after_verify: Mutex::new(None),
        })
    }

    fn cache(&self) -> MutexGuard<'_, HashMap<[u8; 32], Cached>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// How often the dummy hash was verified (tests: the unknown-prefix path runs it).
    pub fn dummy_verifies(&self) -> u64 {
        self.dummy_verifies.load(Ordering::SeqCst)
    }

    fn dummy(&self, key: &str) {
        self.dummy_verifies.fetch_add(1, Ordering::SeqCst);
        let _ = verify_key(key, &self.dummy_hash);
    }

    /// Creates and stores a key for `user` (tests and callers that audit afterwards).
    pub fn create(
        &self,
        user: &UserCtx,
        name: &str,
        scopes: &[String],
        expires_in_days: Option<u64>,
    ) -> Result<CreatedKey, ApiError> {
        let p = self.prepare(user, name, scopes, expires_in_days)?;
        self.insert(p)
    }

    /// Final review I2: stores a prepared key. The route appends `API_KEY_CREATED` first, so a
    /// key is never usable before its audit record exists.
    pub fn insert(&self, p: Prepared) -> Result<CreatedKey, ApiError> {
        match self.store.api_key_insert(&p.rec) {
            Ok(()) => Ok(CreatedKey {
                id: p.rec.id.clone(),
                view: KeyView::from(&p.rec),
                key: p.key,
            }),
            Err(StoreError::Duplicate) => Err(ApiError::INTERNAL),
            Err(e) => Err(store_err(e)),
        }
    }

    /// A new key for `user` (PD-213 limits), not yet stored: its id, prefix and view are final.
    pub fn prepare(
        &self,
        user: &UserCtx,
        name: &str,
        scopes: &[String],
        expires_in_days: Option<u64>,
    ) -> Result<Prepared, ApiError> {
        if !valid_name(name) {
            return Err(ApiError::API_KEY_NAME_INVALID);
        }
        let mut sorted: Vec<&str> = scopes.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        sorted.dedup();
        if scopes.is_empty()
            || sorted.len() != scopes.len()
            || !scopes.iter().all(|s| SCOPES.contains(&s.as_str()))
        {
            return Err(ApiError::API_KEY_SCOPE_INVALID);
        }
        let days = expires_in_days.unwrap_or(DEFAULT_EXPIRY_DAYS);
        if !(1..=MAX_EXPIRY_DAYS).contains(&days) {
            return Err(ApiError::API_KEY_EXPIRY_OUT_OF_RANGE);
        }
        let now = self.clock.now();
        let user_id = user.user_id();
        if self
            .store
            .api_key_count_active(user_id, now)
            .map_err(store_err)?
            >= MAX_ACTIVE_KEYS
        {
            return Err(ApiError::API_KEY_LIMIT_REACHED);
        }
        let expires_at = now.saturating_add(i64::try_from(days * 86_400).unwrap_or(i64::MAX));
        // A prefix already taken is drawn again (36^8 prefixes; the insert still refuses a race).
        for _ in 0..5 {
            let prefix = random_prefix()?;
            let secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(random(32)?));
            let key = SecretString::from(format!("{KEY_PREFIX}{prefix}_{}", secret.as_str()));
            let id = format!("key_{}", hex::encode(random(16)?));
            let rec = ApiKeyRecord {
                id: id.clone(),
                user_id: user_id.to_owned(),
                name: name.to_owned(),
                prefix,
                hash: hash_key(key.expose_secret(), self.params)?,
                scopes: scopes.to_vec(),
                created_at: now,
                expires_at,
                last_used_at: None,
                revoked_at: None,
            };
            match self.store.api_key_by_prefix(&rec.prefix) {
                Ok(None) => return Ok(Prepared { rec, key }),
                Ok(Some(_)) => continue,
                Err(e) => return Err(store_err(e)),
            }
        }
        Err(ApiError::INTERNAL)
    }

    pub fn list(&self, user: &UserCtx) -> Result<Vec<KeyView>, ApiError> {
        Ok(self
            .store
            .api_key_list(user.user_id())
            .map_err(store_err)?
            .iter()
            .map(KeyView::from)
            .collect())
    }

    /// Revokes the user's key `id` and evicts it from the cache; `None` when it is not the
    /// user's or already revoked. The caller appends `API_KEY_REVOKED`.
    pub fn revoke(&self, user: &UserCtx, id: &str) -> Result<Option<KeyView>, ApiError> {
        let now = self.clock.now();
        if !self
            .store
            .api_key_revoke(user.user_id(), id, now)
            .map_err(store_err)?
        {
            return Ok(None);
        }
        self.invalidate(id);
        Ok(self
            .store
            .api_key_list(user.user_id())
            .map_err(store_err)?
            .iter()
            .find(|k| k.id == id)
            .map(KeyView::from))
    }

    /// After a restore (M13 T6): nothing cached survives.
    pub fn invalidate_all(&self) {
        let mut cache = self.cache();
        self.generation.fetch_add(1, Ordering::SeqCst);
        cache.clear();
    }

    /// Evicts every cache entry of key `id`.
    pub fn invalidate(&self, id: &str) {
        let mut cache = self.cache();
        self.generation.fetch_add(1, Ordering::SeqCst);
        cache.retain(|_, c| c.key_id != id);
    }

    /// The bearer's key, verified (PD-213, PD-214). A deactivated user's keys are refused at once,
    /// even before their revocation is recorded (M13 batch-1 review I-2, M-3).
    pub fn authenticate(&self, key: &str) -> Result<KeyCtx, AuthFail> {
        let ctx = self.authenticate_key(key)?;
        match self.store.user_state(ctx.user.user_id()) {
            Ok(Some(s)) if s.deactivated_at.is_some() => Err(AuthFail::Invalid),
            Ok(_) => Ok(ctx),
            Err(_) => Err(AuthFail::Store),
        }
    }

    fn authenticate_key(&self, key: &str) -> Result<KeyCtx, AuthFail> {
        let now = self.clock.now();
        let fp: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        if let Some(c) = self.cache().get(&fp)
            && now - c.at < CACHE_SECS
            && now < c.expires_at
        {
            let ctx = KeyCtx {
                user: UserCtx::from_authenticated(&c.user_id),
                key_id: c.key_id.clone(),
                prefix: c.prefix.clone(),
                scopes: c.scopes.clone(),
                credential: format!("api_key:{}", c.key_id),
            };
            self.touch(&c.user_id.clone(), &c.key_id.clone(), now);
            return Ok(ctx);
        }
        let Some((prefix, _)) = split_key(key) else {
            self.dummy(key);
            return Err(AuthFail::Invalid);
        };
        let generation = self.generation.load(Ordering::SeqCst);
        let rec = match self.store.api_key_by_prefix(prefix) {
            Ok(Some(r)) => r,
            Ok(None) => {
                self.dummy(key);
                return Err(AuthFail::Invalid);
            }
            Err(_) => return Err(AuthFail::Store),
        };
        if !verify_key(key, &rec.hash) {
            return Err(AuthFail::Invalid);
        }
        #[cfg(test)]
        if let Some(f) = self
            .after_verify
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            f(self);
        }
        let reason = if rec.revoked_at.is_some() {
            Some("revoked")
        } else if now >= rec.expires_at {
            Some("expired")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(AuthFail::Refused {
                user_id: rec.user_id,
                key_id: rec.id,
                prefix: rec.prefix,
                reason,
            });
        }
        let mut cache = self.cache();
        if self.generation.load(Ordering::SeqCst) == generation {
            cache.insert(
                fp,
                Cached {
                    key_id: rec.id.clone(),
                    user_id: rec.user_id.clone(),
                    prefix: rec.prefix.clone(),
                    scopes: rec.scopes.clone(),
                    expires_at: rec.expires_at,
                    at: now,
                },
            );
        }
        drop(cache);
        self.touch(&rec.user_id, &rec.id, now);
        Ok(KeyCtx {
            user: UserCtx::from_authenticated(&rec.user_id),
            credential: format!("api_key:{}", rec.id),
            key_id: rec.id,
            prefix: rec.prefix,
            scopes: rec.scopes,
        })
    }

    fn touch(&self, user_id: &str, key_id: &str, now: i64) {
        let mut last = self.last_used.lock().unwrap_or_else(|e| e.into_inner());
        if last.get(key_id).is_some_and(|t| now - t < LAST_USED_EVERY) {
            return;
        }
        last.insert(key_id.to_owned(), now);
        drop(last);
        let _ = self.store.api_key_touch_last_used(user_id, key_id, now);
    }
}

#[cfg(test)]
#[path = "tests/api_keys.rs"]
mod tests;
