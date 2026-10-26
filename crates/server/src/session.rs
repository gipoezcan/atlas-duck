//! Cookie sessions with absolute and idle expiry (SM-2.4, PD-202).
//!
//! A session id is 32 random bytes, base64url, sent only in the cookie. Memory and the server
//! store key it by `SHA-256(id)`, so a copy of the database yields no live cookie. The memory map
//! is authoritative while the process runs; `last_seen` reaches the store at most once per
//! `TOUCH_EVERY`. Logout and expiry delete the row. Roles are the login's, never refreshed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::clock::Clock;
use crate::errors::ApiError;
use crate::store::{ServerStore, SessionRecord, StoreError};

pub const COOKIE: &str = "atlas_duck_session";
/// PD-202: the throttle of `last_seen` writes.
pub const TOUCH_EVERY: i64 = 60;

/// A live session as handlers see it (no id, no hash).
#[derive(Clone)]
pub struct Session {
    pub user_id: String,
    pub roles: Vec<String>,
    pub csrf_token: SecretString,
    pub absolute_expiry: i64,
    pub idle_expiry: i64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("user_id", &self.user_id)
            .field("roles", &self.roles)
            .finish_non_exhaustive()
    }
}

struct Live {
    record: SessionRecord,
    /// When `last_seen` was last written to the store.
    stored_last_seen: i64,
}

pub struct SessionTable {
    store: Arc<dyn ServerStore>,
    clock: Arc<dyn Clock>,
    absolute: i64,
    idle: i64,
    live: Mutex<HashMap<[u8; 32], Live>>,
}

fn id_hash(id: &str) -> [u8; 32] {
    Sha256::digest(id.as_bytes()).into()
}

fn random_b64(bytes: usize) -> Result<String, ApiError> {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).map_err(|_| ApiError::INTERNAL)?;
    Ok(URL_SAFE_NO_PAD.encode(b))
}

fn store_err(_: StoreError) -> ApiError {
    ApiError::STORE_UNAVAILABLE
}

/// A fresh session: the cookie value (secret) and the session.
pub struct Created {
    pub cookie_id: SecretString,
    pub session: Session,
}

impl SessionTable {
    /// Loads every stored session (a restart keeps them).
    pub fn new(
        store: Arc<dyn ServerStore>,
        clock: Arc<dyn Clock>,
        absolute_secs: u64,
        idle_secs: u64,
    ) -> Result<SessionTable, StoreError> {
        let mut live = HashMap::new();
        for record in store.sessions_all()? {
            live.insert(
                record.id_hash,
                Live {
                    stored_last_seen: record.last_seen,
                    record,
                },
            );
        }
        Ok(SessionTable {
            store,
            clock,
            absolute: i64::try_from(absolute_secs).unwrap_or(i64::MAX),
            idle: i64::try_from(idle_secs).unwrap_or(i64::MAX),
            live: Mutex::new(live),
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<[u8; 32], Live>> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn create(&self, user_id: &str, roles: Vec<String>) -> Result<Created, ApiError> {
        let id = random_b64(32)?;
        let csrf = random_b64(32)?;
        let now = self.clock.now();
        let record = SessionRecord {
            id_hash: id_hash(&id),
            user_id: user_id.to_owned(),
            roles,
            csrf_token: csrf,
            created_at: now,
            last_seen: now,
            absolute_expiry: now.saturating_add(self.absolute),
            idle_expiry: now.saturating_add(self.idle),
        };
        self.store.session_put(&record).map_err(store_err)?;
        let session = to_session(&record);
        self.lock().insert(
            record.id_hash,
            Live {
                stored_last_seen: now,
                record,
            },
        );
        Ok(Created {
            cookie_id: SecretString::from(id),
            session,
        })
    }

    /// The live session of a cookie value, touched now. Unknown → `auth/no_session`; expired →
    /// `auth/session_expired` (and the session is deleted).
    pub fn lookup(&self, cookie_id: &str) -> Result<Session, ApiError> {
        let key = id_hash(cookie_id);
        let now = self.clock.now();
        let mut map = self.lock();
        let Some(live) = map.get_mut(&key) else {
            return Err(ApiError::NO_SESSION);
        };
        if now >= live.record.absolute_expiry || now >= live.record.idle_expiry {
            map.remove(&key);
            drop(map);
            let _ = self.store.session_delete(&key);
            return Err(ApiError::SESSION_EXPIRED);
        }
        live.record.last_seen = now;
        live.record.idle_expiry = now
            .saturating_add(self.idle)
            .min(live.record.absolute_expiry);
        let session = to_session(&live.record);
        if now - live.stored_last_seen >= TOUCH_EVERY {
            live.stored_last_seen = now;
            let (last, idle) = (live.record.last_seen, live.record.idle_expiry);
            drop(map);
            // The memory map stays authoritative; a failed write is retried at the next touch.
            let _ = self.store.session_touch(&key, last, idle);
        }
        Ok(session)
    }

    /// Logout: deletes the session (memory and store). Unknown ids are a no-op.
    pub fn delete(&self, cookie_id: &str) -> Result<(), ApiError> {
        let key = id_hash(cookie_id);
        self.lock().remove(&key);
        self.store.session_delete(&key).map_err(store_err)?;
        Ok(())
    }

    /// Removes every expired session; answers how many left memory.
    pub fn sweep(&self) -> usize {
        let now = self.clock.now();
        let mut map = self.lock();
        let before = map.len();
        map.retain(|_, l| now < l.record.absolute_expiry && now < l.record.idle_expiry);
        let removed = before - map.len();
        drop(map);
        let _ = self.store.session_delete_expired(now);
        removed
    }

    /// The sweep task: every 60 s until the runtime stops.
    pub fn spawn_sweeper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let table = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                table.sweep();
            }
        })
    }
}

fn to_session(r: &SessionRecord) -> Session {
    Session {
        user_id: r.user_id.clone(),
        roles: r.roles.clone(),
        csrf_token: SecretString::from(r.csrf_token.clone()),
        absolute_expiry: r.absolute_expiry,
        idle_expiry: r.idle_expiry,
    }
}

/// `Set-Cookie` of a new session (PD-203: `Secure` unless dev on plain-HTTP localhost).
pub fn set_cookie(id: &SecretString, secure: bool) -> String {
    format!(
        "{COOKIE}={}; HttpOnly;{} SameSite=Strict; Path=/",
        id.expose_secret(),
        if secure { " Secure;" } else { "" }
    )
}

/// `Set-Cookie` that removes the session cookie.
pub fn clear_cookie(secure: bool) -> String {
    format!(
        "{COOKIE}=; HttpOnly;{} SameSite=Strict; Path=/; Max-Age=0",
        if secure { " Secure;" } else { "" }
    )
}

/// The session cookie's value from a `Cookie` header.
pub fn cookie_value(header: &str) -> Option<&str> {
    header.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == COOKIE && !value.is_empty()).then_some(value)
    })
}
