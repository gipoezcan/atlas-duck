//! Schema of `server.db`: v1 (PD-202, PD-208, PD-210, PD-211, PD-213, PD-217) and the
//! up-migrations after it (M13 Δ-M13-3). A new database is created as v1 and migrated up, so
//! every file reaches the current version by the same path.

/// `PRAGMA user_version` of this build.
pub const SCHEMA_VERSION: u32 = 4;

/// v1 → v2 (M13 T5): user lifecycle columns and the scheduler's last runs (T9).
pub const V1_TO_V2: &str = r#"
ALTER TABLE users ADD COLUMN deactivated_at INTEGER;
ALTER TABLE users ADD COLUMN deactivated_by TEXT;
ALTER TABLE users ADD COLUMN last_login_at INTEGER;
ALTER TABLE users ADD COLUMN retention_until INTEGER;
ALTER TABLE users ADD COLUMN chain_deleted_at INTEGER;
CREATE TABLE offboarding_gone (
    user_id TEXT PRIMARY KEY,
    first_seen_at INTEGER NOT NULL
);
CREATE TABLE scheduler_state (
    job TEXT PRIMARY KEY,
    last_run_at INTEGER,
    last_success_at INTEGER
);
"#;

/// The migration from `from` to `from + 1`.
pub fn up_from(from: u32) -> Option<&'static str> {
    match from {
        1 => Some(V1_TO_V2),
        2 => Some(M14_TABLES),
        3 => Some(V3_TO_V4),
        _ => None,
    }
}

/// v3 → v4 (M15 T4, PD-295): the user's UI language preference; existing users get `auto`.
pub const V3_TO_V4: &str = r#"
ALTER TABLE users ADD COLUMN lang_pref TEXT NOT NULL DEFAULT 'auto';
"#;

pub const V1: &str = r#"
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT,
    roles TEXT NOT NULL,
    data_key_wrapped TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE user_keystore (
    user_id TEXT NOT NULL REFERENCES users(user_id),
    entry_name TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ct BLOB NOT NULL,
    PRIMARY KEY (user_id, entry_name)
);
CREATE TABLE user_pats (
    user_id TEXT NOT NULL REFERENCES users(user_id),
    alias TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ct BLOB NOT NULL,
    identity_json TEXT NOT NULL,
    checked_at INTEGER NOT NULL,
    UNIQUE (user_id, alias)
);
CREATE TABLE sessions (
    id_hash BLOB PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    roles TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    absolute_expiry INTEGER NOT NULL,
    idle_expiry INTEGER NOT NULL
);
CREATE TABLE api_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    name TEXT NOT NULL,
    prefix TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX api_keys_user ON api_keys(user_id);
CREATE TABLE instances (
    alias TEXT PRIMARY KEY,
    product TEXT NOT NULL,
    base_url TEXT NOT NULL,
    proxy TEXT,
    ca_ref TEXT,
    is_default INTEGER NOT NULL
);
CREATE TABLE anchor_chain (
    seq INTEGER PRIMARY KEY,
    ts_utc TEXT NOT NULL,
    kind TEXT NOT NULL,
    body_jcs BLOB NOT NULL,
    prev_hash BLOB NOT NULL,
    hash BLOB NOT NULL
);
CREATE TABLE anchor_heads (
    anchor_seq INTEGER NOT NULL REFERENCES anchor_chain(seq),
    user_id TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    head_seq INTEGER NOT NULL,
    record_hash BLOB NOT NULL
);
CREATE INDEX anchor_heads_seq ON anchor_heads(anchor_seq);
CREATE INDEX anchor_heads_chain ON anchor_heads(chain_id, head_seq);
CREATE TRIGGER anchor_chain_no_update BEFORE UPDATE ON anchor_chain
    BEGIN SELECT RAISE(ABORT, 'anchor_chain is append-only'); END;
CREATE TRIGGER anchor_chain_no_delete BEFORE DELETE ON anchor_chain
    BEGIN SELECT RAISE(ABORT, 'anchor_chain is append-only'); END;
CREATE TRIGGER anchor_heads_no_update BEFORE UPDATE ON anchor_heads
    BEGIN SELECT RAISE(ABORT, 'anchor_heads is append-only'); END;
CREATE TRIGGER anchor_heads_no_delete BEFORE DELETE ON anchor_heads
    BEGIN SELECT RAISE(ABORT, 'anchor_heads is append-only'); END;
"#;

/// v2 → v3 (M14 T3): the OAuth tables and export jobs. Decision (M13 merge): M14's tables are
/// their own step after M13's v2, not folded into it, so a file M13 already moved to v2 climbs
/// the same path.
pub const M14_TABLES: &str = r#"
CREATE TABLE oauth_clients (
    client_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    source_ip_hash TEXT NOT NULL
);
CREATE TABLE oauth_consent_requests (
    id_hash BLOB PRIMARY KEY,
    session_hash BLOB NOT NULL,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    state TEXT NOT NULL,
    resource TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE oauth_grants (
    grant_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    resource TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER,
    revoke_reason TEXT
);
CREATE INDEX oauth_grants_user ON oauth_grants(user_id);
CREATE INDEX oauth_grants_client ON oauth_grants(client_id);
CREATE TABLE oauth_codes (
    hash BLOB PRIMARY KEY,
    grant_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    redeemed_at INTEGER
);
CREATE INDEX oauth_codes_grant ON oauth_codes(grant_id);
CREATE TABLE oauth_access (
    hash BLOB PRIMARY KEY,
    grant_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX oauth_access_grant ON oauth_access(grant_id);
CREATE TABLE oauth_refresh (
    hash BLOB PRIMARY KEY,
    grant_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    rotated_at INTEGER
);
CREATE INDEX oauth_refresh_grant ON oauth_refresh(grant_id);
CREATE TABLE export_jobs (
    job_id TEXT PRIMARY KEY,
    requester_user_id TEXT NOT NULL,
    target_user_id TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    manifest_sha256 TEXT,
    size INTEGER,
    file_name TEXT,
    anchor_seq INTEGER,
    anchor_hash TEXT
);
CREATE INDEX export_jobs_requester ON export_jobs(requester_user_id);
"#;
