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

/// M15 T4 (PD-295): a user's UI language preference, `users.lang_pref` (schema v4). A display
/// preference: not audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LangPref {
    #[default]
    Auto,
    En,
    De,
}

impl LangPref {
    /// The word in the column and on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            LangPref::Auto => "auto",
            LangPref::En => "en",
            LangPref::De => "de",
        }
    }

    /// The inverse of [`LangPref::as_str`]; anything else is `None`.
    pub fn parse(word: &str) -> Option<LangPref> {
        match word {
            "auto" => Some(LangPref::Auto),
            "en" => Some(LangPref::En),
            "de" => Some(LangPref::De),
            _ => None,
        }
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
    /// When retention deleted the user's chain (M13 T8); the row stays so the user stays refused.
    pub chain_deleted_at: Option<i64>,
}

/// A scheduler job's last run and last successful run (M13 T9, `scheduler_state`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JobState {
    pub last_run_at: Option<i64>,
    pub last_success_at: Option<i64>,
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

/// A dynamically registered OAuth public client (M14 PD-240).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClientRecord {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub created_at: i64,
    /// Hex SHA-256 of the registering client IP (never the IP itself).
    pub source_ip_hash: String,
}

/// A pending authorization request awaiting consent (PD-241): bound to the hash of the session
/// that made it; its id is stored hashed.
#[derive(Clone, PartialEq, Eq)]
pub struct ConsentRequestRecord {
    pub id_hash: [u8; 32],
    pub session_hash: [u8; 32],
    pub user_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub state: String,
    pub resource: String,
    pub created_at: i64,
    pub expires_at: i64,
}

impl fmt::Debug for ConsentRequestRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsentRequestRecord")
            .field("user_id", &self.user_id)
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// An OAuth grant (PD-236): the family of every token issued under one consent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecord {
    pub grant_id: String,
    pub user_id: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub resource: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub revoke_reason: Option<String>,
}

impl GrantRecord {
    /// Neither revoked nor past its absolute expiry at `now`.
    pub fn live(&self, now: i64) -> bool {
        self.revoked_at.is_none() && now < self.expires_at
    }
}

/// An authorization code, stored by hash (PD-235); single use.
#[derive(Clone, PartialEq, Eq)]
pub struct CodeRecord {
    pub hash: [u8; 32],
    pub grant_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub expires_at: i64,
    pub redeemed_at: Option<i64>,
}

impl fmt::Debug for CodeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeRecord")
            .field("grant_id", &self.grant_id)
            .field("expires_at", &self.expires_at)
            .field("redeemed_at", &self.redeemed_at)
            .finish_non_exhaustive()
    }
}

/// An access token, stored by hash.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessRecord {
    pub hash: [u8; 32],
    pub grant_id: String,
    /// The grant's scopes, or the subset a refresh asked for.
    pub scopes: Vec<String>,
    pub expires_at: i64,
}

impl fmt::Debug for AccessRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessRecord")
            .field("grant_id", &self.grant_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// A refresh token, stored by hash; `rotated_at` once it was exchanged (PD-236).
#[derive(Clone, PartialEq, Eq)]
pub struct RefreshRecord {
    pub hash: [u8; 32],
    pub grant_id: String,
    pub created_at: i64,
    pub last_used_at: i64,
    pub rotated_at: Option<i64>,
}

impl fmt::Debug for RefreshRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshRecord")
            .field("grant_id", &self.grant_id)
            .field("rotated_at", &self.rotated_at)
            .finish_non_exhaustive()
    }
}

/// Why a code was not redeemed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redeem {
    Unknown,
    /// Past its expiry; the code is burned.
    Expired,
    /// Redeemed before: the grant it belongs to (reuse detection, PD-236).
    Reused(String),
    Store(StoreError),
}

/// Why a refresh token was not rotated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rotate {
    Unknown,
    /// Idle too long, or its grant is revoked or past its absolute expiry.
    Expired,
    /// Rotated before: the grant it belongs to (reuse detection, PD-236).
    Reused(String),
    Store(StoreError),
}

/// A server-side export job (PD-254).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportJobRecord {
    pub job_id: String,
    pub requester_user_id: String,
    pub target_user_id: String,
    /// `running`, `done`, `failed`, `downloaded`.
    pub state: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub manifest_sha256: Option<String>,
    pub size: Option<u64>,
    pub file_name: Option<String>,
    /// The `HEADS` row the job forced (PD-254 s1): the export's `--anchor-chain-head` pin.
    pub anchor_seq: Option<u64>,
    pub anchor_hash: Option<String>,
}

/// PD-240: a client without a grant this long after registration is purged.
pub const CLIENT_UNUSED_SECS: i64 = 24 * 3600;
/// PD-240: a client whose last grant ended this long ago is purged.
pub const CLIENT_ENDED_SECS: i64 = 30 * 24 * 3600;

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
    /// Inserts the user, or refreshes its display name and roles; an existing user's wrapped data
    /// key is never replaced here (only [ServerStore::user_set_wrapped] does, M13 T7).
    fn upsert_user(&self, user: &UserRecord) -> StoreResult<()>;
    /// Rotation: replaces the wrapped data key if it still is `expected`; answers whether it did.
    fn user_set_wrapped(&self, user_id: &str, expected: &str, new: &str) -> StoreResult<bool>;
    fn user(&self, user_id: &str) -> StoreResult<Option<UserRecord>>;
    fn user_by_name(&self, username: &str) -> StoreResult<Option<UserRecord>>;
    /// M14 PD-257: every user, by username (the auditor's list; no secret column is shown).
    fn user_list(&self) -> StoreResult<Vec<UserRecord>>;
    /// Every user with its lifecycle state, by username (admin `users list`, the scheduler).
    fn users_all(&self) -> StoreResult<Vec<(UserRecord, UserState)>>;
    fn user_state(&self, user_id: &str) -> StoreResult<Option<UserState>>;
    fn user_set_last_login(&self, user_id: &str, at: i64) -> StoreResult<()>;
    /// M15 T4 (PD-295): the user's language preference; `Auto` for an unknown user or a value
    /// the column should never hold.
    fn user_lang_pref(&self, user_id: &str) -> StoreResult<LangPref>;
    /// Sets the user's language preference; an unknown user changes nothing.
    fn set_user_lang_pref(&self, user_id: &str, pref: LangPref) -> StoreResult<()>;
    /// Retention (M13 T8), one transaction: the user's keystore entries, PATs, sessions, API
    /// keys, OAuth grants with their codes and tokens, consent requests and export jobs (M14) go, the wrapped data key is wiped and `chain_deleted_at` set. The row stays.
    fn user_purge(&self, user_id: &str, at: i64) -> StoreResult<()>;
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
    /// M14 PD-253: the rows `first..=last` in seq order (an excerpt span, read in batches).
    fn anchor_range(&self, first: u64, last: u64) -> StoreResult<Vec<AnchorRow>>;

    /// The most recently anchored head of every user (backup manifests).
    fn anchor_latest_heads(&self) -> StoreResult<Vec<AnchorHead>>;

    // ---- scheduler (M13 T9) ----
    fn scheduler_get(&self, job: &str) -> StoreResult<JobState>;
    fn scheduler_put(&self, job: &str, state: &JobState) -> StoreResult<()>;
    /// Offboarding (batch-2 review I4): since when the directory has said the user is gone.
    fn gone_since(&self, user_id: &str) -> StoreResult<Option<i64>>;
    /// Records the first gone answer; a later one keeps the first time.
    fn gone_mark(&self, user_id: &str, at: i64) -> StoreResult<()>;
    fn gone_clear(&self, user_id: &str) -> StoreResult<()>;

    // ---- backup and restore (M13 T6) ----
    /// A consistent copy of the whole store into the new file `path`.
    fn snapshot_to(&self, path: &std::path::Path) -> StoreResult<()>;
    /// Replaces the whole store's content with the file at `path`, atomically.
    fn restore_from(&self, path: &std::path::Path) -> StoreResult<()>;
    fn anchor_last(&self) -> StoreResult<Option<AnchorRow>>;
    fn anchor_heads_for(&self, anchor_seq: u64) -> StoreResult<Vec<AnchorHead>>;
    /// `(anchor_seq, head)` of every head of `chain_id` with `head_seq <= upto_seq`, in order.
    fn anchor_heads_for_chain(
        &self,
        chain_id: &str,
        upto_seq: u64,
    ) -> StoreResult<Vec<(u64, AnchorHead)>>;

    // ---- OAuth clients (M14 PD-240) ----
    /// `Duplicate` when the id exists.
    fn oauth_client_insert(&self, c: &OAuthClientRecord) -> StoreResult<()>;
    fn oauth_client_get(&self, client_id: &str) -> StoreResult<Option<OAuthClientRecord>>;
    fn oauth_client_count(&self) -> StoreResult<u64>;
    /// Removes stale clients ([`CLIENT_UNUSED_SECS`], [`CLIENT_ENDED_SECS`]) with their ended
    /// grants and those grants' tokens, expired consent requests, codes and access tokens, and
    /// refresh tokens of ended grants; answers how many clients went.
    fn oauth_purge(&self, now: i64) -> StoreResult<u64>;

    // ---- consent requests (PD-241) ----
    fn consent_put(&self, r: &ConsentRequestRecord) -> StoreResult<()>;
    /// The request if it exists and was made by this session (it stays).
    fn consent_get(
        &self,
        id_hash: &[u8; 32],
        session_hash: &[u8; 32],
    ) -> StoreResult<Option<ConsentRequestRecord>>;
    /// Removes and answers the request if it was made by this session; another session's
    /// attempt leaves it in place.
    fn consent_take(
        &self,
        id_hash: &[u8; 32],
        session_hash: &[u8; 32],
    ) -> StoreResult<Option<ConsentRequestRecord>>;

    // ---- grants (PD-236) ----
    fn grant_insert(&self, g: &GrantRecord) -> StoreResult<()>;
    fn grant_get(&self, grant_id: &str) -> StoreResult<Option<GrantRecord>>;
    /// The user's grants, newest first.
    fn grant_list(&self, user_id: &str) -> StoreResult<Vec<GrantRecord>>;
    /// Marks the grant revoked; false when it already was (or does not exist).
    fn grant_revoke(&self, grant_id: &str, reason: &str, at: i64) -> StoreResult<bool>;
    /// Revokes every unrevoked grant of the user; answers the grants it revoked.
    fn grant_revoke_all(
        &self,
        user_id: &str,
        reason: &str,
        at: i64,
    ) -> StoreResult<Vec<GrantRecord>>;
    fn grant_touch(&self, grant_id: &str, at: i64) -> StoreResult<()>;

    // ---- codes and tokens (PD-235) ----
    fn code_insert(&self, c: &CodeRecord) -> StoreResult<()>;
    /// Check-and-set in one transaction: the code and its grant, the code marked redeemed.
    fn code_redeem(&self, hash: &[u8; 32], now: i64) -> Result<(CodeRecord, GrantRecord), Redeem>;
    fn access_insert(&self, a: &AccessRecord) -> StoreResult<()>;
    fn access_get(&self, hash: &[u8; 32]) -> StoreResult<Option<AccessRecord>>;
    fn refresh_insert(&self, r: &RefreshRecord) -> StoreResult<()>;
    /// Check-and-set in one transaction: marks `hash` rotated and inserts `new` in the same
    /// grant; refuses a token idle `idle_secs` or longer, or whose grant is not live.
    fn refresh_rotate(
        &self,
        hash: &[u8; 32],
        new: &RefreshRecord,
        now: i64,
        idle_secs: i64,
    ) -> Result<GrantRecord, Rotate>;
    /// The grant a refresh token belongs to (revocation endpoint).
    fn refresh_grant(&self, hash: &[u8; 32]) -> StoreResult<Option<String>>;

    // ---- export jobs (PD-254) ----
    fn export_job_insert(&self, j: &ExportJobRecord) -> StoreResult<()>;
    fn export_job_get(&self, job_id: &str) -> StoreResult<Option<ExportJobRecord>>;
    fn export_job_update(&self, j: &ExportJobRecord) -> StoreResult<()>;
    /// Jobs in state `running`, server-wide.
    fn export_jobs_running(&self) -> StoreResult<Vec<ExportJobRecord>>;
    /// Jobs whose expiry is at or before `now`.
    fn export_jobs_expired(&self, now: i64) -> StoreResult<Vec<ExportJobRecord>>;
    fn export_job_delete(&self, job_id: &str) -> StoreResult<bool>;
}
