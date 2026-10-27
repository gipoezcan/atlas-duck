//! Schema of `server.db`: v1 (PD-202, PD-208, PD-210, PD-211, PD-213, PD-217) and the
//! up-migrations after it (M13 Δ-M13-3). A new database is created as v1 and migrated up, so
//! every file reaches the current version by the same path.

/// `PRAGMA user_version` of this build.
pub const SCHEMA_VERSION: u32 = 2;

/// v1 → v2 (M13 T5): user lifecycle columns and the scheduler's last runs (T9).
pub const V1_TO_V2: &str = r#"
ALTER TABLE users ADD COLUMN deactivated_at INTEGER;
ALTER TABLE users ADD COLUMN deactivated_by TEXT;
ALTER TABLE users ADD COLUMN last_login_at INTEGER;
ALTER TABLE users ADD COLUMN retention_until INTEGER;
ALTER TABLE users ADD COLUMN chain_deleted_at INTEGER;
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
        _ => None,
    }
}

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
