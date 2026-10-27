//! The `ServerStore` trait and its SQLite implementation (SM-6.1, ADR 0003).
//!
//! The trait is typed: callers never write SQL. Every per-user method takes the `user_id` and
//! filters by it; the only cross-user reads are `pats_for_alias` (admin instance removal) and the
//! session and API-key lookups by their own secret-derived keys (the id hash, the public prefix),
//! which then name their owner. The anchor tables have no update or delete method, and SQLite
//! triggers back that (PD-217). The trait is synchronous; async callers use `spawn_blocking`.

#[cfg(any(test, feature = "testing"))]
pub mod memory;
pub mod migrate;
pub mod schema;
pub mod sqlite;

#[cfg(test)]
mod tests;

use std::fmt;

/// An AES-256-GCM sealed value as stored: the nonce and the ciphertext with its tag.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: Vec<u8>,
    pub ct: Vec<u8>,
}

impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sealed({} bytes)", self.ct.len())
    }
}

/// One user (PD-199, PD-208): `data_key_wrapped` is the `WrappedKey` JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    pub user_id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
    pub data_key_wrapped: String,
    pub created_at: i64,
}

/// Lifecycle columns of a user (schema v2, M13 Δ-M13-3): kept apart from [`UserRecord`] so the
/// login's upsert never touches them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserState {
    pub deactivated_at: Option<i64>,
    /// `admin` or `offboarding`.
    pub deactivated_by: Option<String>,
    pub last_login_at: Option<i64>,
    /// When retention may delete the user's chain (deactivation time + the retention period).
    pub retention_until: Option<i64>,
}

/// A stored PAT (PD-211), sealed with the user's data key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatRecord {
    pub user_id: String,
    pub alias: String,
    pub sealed: Sealed,
    pub identity_json: String,
    pub checked_at: i64,
}

/// A session row (PD-202): the SHA-256 of the session id, never the id.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub id_hash: [u8; 32],
    pub user_id: String,
    pub roles: Vec<String>,
    pub csrf_token: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub absolute_expiry: i64,
    pub idle_expiry: i64,
}

impl fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRecord")
            .field("user_id", &self.user_id)
            .field("roles", &self.roles)
            .field("absolute_expiry", &self.absolute_expiry)
            .field("idle_expiry", &self.idle_expiry)
            .finish_non_exhaustive()
    }
}

/// An API key row (PD-213): `hash` is the argon2id PHC string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyRecord {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub prefix: String,
    pub hash: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

/// An admin-defined instance (SM-4.1, PD-196).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceRecord {
    pub alias: String,
    pub product: String,
    pub base_url: String,
    pub proxy: Option<String>,
    pub ca_ref: Option<String>,
    pub is_default: bool,
}

/// One row of the server anchor chain (PD-217).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRow {
    pub seq: u64,
    pub ts_utc: String,
    pub kind: String,
    pub body_jcs: Vec<u8>,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

/// One user store head anchored by a row (PD-217 `anchor_heads`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorHead {
    pub user_id: String,
    pub chain_id: String,
    pub head_seq: u64,
    pub record_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The database file has a newer schema (`store/newer`).
    Newer(u32),
    /// A unique key is taken (an instance alias, an API key prefix).
    Duplicate,
    /// The database refused or failed; the text is SQLite's, never a value.
    Db(String),
    /// An up-migration failed and was rolled back; the file stays at `from`.
    Migration { from: u32, to: u32 },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Newer(v) => write!(f, "store/newer: schema version {v}"),
            StoreError::Migration { from, to } => {
                write!(f, "store/migration_failed: {from} -> {to}")
            }
            StoreError::Duplicate => f.write_str("store/duplicate"),
            StoreError::Db(e) => write!(f, "store/db: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

pub type StoreResult<T> = Result<T, StoreError>;

/// The row hash of an anchor row, given its seq and its predecessor's hash (the store assigns
/// both inside its transaction; `audit::server_anchor::row_hash` is the function, Task 15).
pub type AnchorHasher<'a> = &'a dyn Fn(u64, &[u8; 32]) -> [u8; 32];

pub trait ServerStore: Send + Sync {
    // ---- users ----
    fn upsert_user(&self, user: &UserRecord) -> StoreResult<()>;
    fn user(&self, user_id: &str) -> StoreResult<Option<UserRecord>>;
    fn user_by_name(&self, username: &str) -> StoreResult<Option<UserRecord>>;
    /// Every user with its lifecycle state, by username (admin `users list`, the scheduler).
    fn users_all(&self) -> StoreResult<Vec<(UserRecord, UserState)>>;
    fn user_state(&self, user_id: &str) -> StoreResult<Option<UserState>>;
    fn user_set_last_login(&self, user_id: &str, at: i64) -> StoreResult<()>;
    /// Marks the user deactivated unless it already is; answers whether this call did it.
    fn user_deactivate(
        &self,
        user_id: &str,
        at: i64,
        by: &str,
        retention_until: i64,
    ) -> StoreResult<bool>;

    // ---- per-user keystore entries (PD-210) ----
    fn ks_get(&self, user_id: &str, entry: &str) -> StoreResult<Option<Sealed>>;
    fn ks_set(&self, user_id: &str, entry: &str, value: &Sealed) -> StoreResult<()>;
    fn ks_delete(&self, user_id: &str, entry: &str) -> StoreResult<bool>;

    // ---- PATs (PD-211) ----
    fn pat_put(&self, pat: &PatRecord) -> StoreResult<()>;
    fn pat_get(&self, user_id: &str, alias: &str) -> StoreResult<Option<PatRecord>>;
    fn pat_list(&self, user_id: &str) -> StoreResult<Vec<PatRecord>>;
    fn pat_delete(&self, user_id: &str, alias: &str) -> StoreResult<bool>;
    /// Admin instance removal only: every user's PAT for `alias`.
    fn pats_for_alias(&self, alias: &str) -> StoreResult<Vec<PatRecord>>;

    // ---- sessions (PD-202) ----
    fn session_put(&self, s: &SessionRecord) -> StoreResult<()>;
    fn session_get(&self, id_hash: &[u8; 32]) -> StoreResult<Option<SessionRecord>>;
    fn session_touch(
        &self,
        id_hash: &[u8; 32],
        last_seen: i64,
        idle_expiry: i64,
    ) -> StoreResult<()>;
    fn session_delete(&self, id_hash: &[u8; 32]) -> StoreResult<bool>;
    /// Deletes every session expired at `now` (absolute or idle); answers how many.
    fn session_delete_expired(&self, now: i64) -> StoreResult<u64>;
    /// Every live session (loaded once at start).
    fn sessions_all(&self) -> StoreResult<Vec<SessionRecord>>;
    /// Deactivation: deletes every session of the user; answers how many.
    fn sessions_delete_for_user(&self, user_id: &str) -> StoreResult<u64>;

    // ---- API keys (PD-213) ----
    fn api_key_insert(&self, k: &ApiKeyRecord) -> StoreResult<()>;
    fn api_key_by_prefix(&self, prefix: &str) -> StoreResult<Option<ApiKeyRecord>>;
    fn api_key_list(&self, user_id: &str) -> StoreResult<Vec<ApiKeyRecord>>;
    /// Marks the user's key revoked at `at`; false if it is not the user's or already revoked.
    fn api_key_revoke(&self, user_id: &str, id: &str, at: i64) -> StoreResult<bool>;
    fn api_key_touch_last_used(&self, user_id: &str, id: &str, at: i64) -> StoreResult<()>;
    /// Keys neither revoked nor expired at `now`.
    fn api_key_count_active(&self, user_id: &str, now: i64) -> StoreResult<u64>;
    /// Deactivation: revokes every unrevoked key of the user at `at`; answers those keys.
    fn api_keys_revoke_all(&self, user_id: &str, at: i64) -> StoreResult<Vec<ApiKeyRecord>>;

    // ---- instances (PD-196) ----
    /// Inserts; `Duplicate` when the alias exists.
    fn instance_put(&self, i: &InstanceRecord) -> StoreResult<()>;
    fn instance_list(&self) -> StoreResult<Vec<InstanceRecord>>;
    fn instance_delete(&self, alias: &str) -> StoreResult<bool>;

    // ---- the server anchor chain (PD-217), append-only ----
    /// Appends one row (seq = last + 1, prev = last hash or zeros) and its `heads` in one
    /// transaction; `hash` computes the row hash from the assigned seq and prev hash.
    fn anchor_append(
        &self,
        kind: &str,
        ts_utc: &str,
        body_jcs: &[u8],
        heads: &[AnchorHead],
        hash: AnchorHasher<'_>,
    ) -> StoreResult<AnchorRow>;
    fn anchor_all(&self) -> StoreResult<Vec<AnchorRow>>;
    fn anchor_last(&self) -> StoreResult<Option<AnchorRow>>;
    fn anchor_heads_for(&self, anchor_seq: u64) -> StoreResult<Vec<AnchorHead>>;
    /// `(anchor_seq, head)` of every head of `chain_id` with `head_seq <= upto_seq`, in order.
    fn anchor_heads_for_chain(
        &self,
        chain_id: &str,
        upto_seq: u64,
    ) -> StoreResult<Vec<(u64, AnchorHead)>>;
}
