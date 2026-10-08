//! Schema v1 (F.10), connection pragmas, the migration runner and the read-only version gate
//! (§8.1, §8.13). The database is opened only by the single writer thread (T07); this module
//! provides the primitives.

use std::path::{Path, PathBuf};

use atlas_duck_ipc::build_info::APP_VERSION;
use atlas_duck_ipc::paths::LocalDataDir;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};

use crate::encoding::FORMAT_VERSION;
use crate::error::{AuditError, OpenError};
use crate::recovery::{RECOVERY_LAYOUT, recovery_layout};

pub const SCHEMA_HEAD: u32 = 1;
pub const DB_FILE: &str = "audit.db";

/// Key of the plaintext, advisory `meta` row (§8.13 message only, never a security decision).
pub const META_WRITTEN_BY: &str = "written_by";

pub fn db_path(dir: &LocalDataDir) -> PathBuf {
    dir.path().join(DB_FILE)
}

fn sqlite(e: rusqlite::Error) -> OpenError {
    OpenError::Sqlite(e.to_string())
}

const TABLES_V1: &str = "
CREATE TABLE events (
  seq                INTEGER PRIMARY KEY,
  format_version     INTEGER NOT NULL,
  chain_id           TEXT    NOT NULL,
  ts_utc             TEXT    NOT NULL,
  epoch              TEXT,
  request_id         TEXT,
  event_type         TEXT    NOT NULL,
  op_id              TEXT,
  op_class           TEXT,
  instance_id        TEXT,
  target             TEXT,
  agent_name         TEXT,
  agent_name_source  TEXT,
  client_kind        TEXT,
  connection_id      TEXT,
  peer_pid           INTEGER,
  peer_exe           BLOB,
  peer_origin_exe    BLOB,
  os_user            TEXT,
  atlassian_user     TEXT,
  atlassian_user_key TEXT,
  decision           TEXT,
  flags              INTEGER NOT NULL,
  payload_len        INTEGER NOT NULL,
  payload_sha256     BLOB    NOT NULL,
  key_id             INTEGER NOT NULL,
  nonce              BLOB    NOT NULL,
  payload_ct         BLOB    NOT NULL,
  prev_hash          BLOB    NOT NULL,
  record_hash        BLOB    NOT NULL
);
CREATE INDEX events_request_id ON events(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX events_event_type ON events(event_type);
CREATE INDEX events_key_id     ON events(key_id);

CREATE TABLE prune_log (
  prune_seq               INTEGER PRIMARY KEY,
  range_start             INTEGER NOT NULL,
  cutoff_epoch            TEXT    NOT NULL,
  last_pruned_record_hash BLOB    NOT NULL,
  first_retained_seq      INTEGER NOT NULL,
  prev_row_hash           BLOB    NOT NULL,
  row_hash                BLOB    NOT NULL
);

CREATE TABLE keys (
  key_id       INTEGER PRIMARY KEY,
  month        TEXT,
  wrapped_dek  BLOB,
  created_at   TEXT NOT NULL,
  destroyed_at TEXT
);

CREATE TABLE recovery (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  blob       BLOB NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
";

/// Creates schema v1 on a new, empty database file: page size and auto-vacuum first (they only
/// take effect before the first table), then WAL, then the tables, `user_version = 1` and
/// `meta.written_by`. The caller owns the connection and applies [`apply_connection_pragmas`].
pub fn create_v1(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "page_size", 8192)?;
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    let mode: String = conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
            std::io::Error::other(format!("journal_mode WAL refused, got {mode}")),
        )));
    }
    conn.execute_batch(&format!(
        "BEGIN IMMEDIATE;{TABLES_V1}PRAGMA user_version = {SCHEMA_HEAD};COMMIT;"
    ))?;
    set_written_by(conn)
}

/// Records the version of the binary that opened the store read-write (advisory).
pub fn set_written_by(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [META_WRITTEN_BY, APP_VERSION],
    )?;
    Ok(())
}

/// Per-connection pragmas, read-write and read-only alike. Never sets `journal_mode` (it is a
/// property of the file and a write on a read-only open).
pub fn apply_connection_pragmas(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "secure_delete", "ON")?;
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    Ok(())
}

/// Opens an existing database read-write (never creates it) for the single writer thread.
pub fn open_rw(path: &Path) -> Result<Connection, OpenError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sqlite)?;
    apply_connection_pragmas(&conn).map_err(sqlite)?;
    Ok(conn)
}

/// Opens an existing database read-only (reader connections).
pub fn open_ro(path: &Path) -> Result<Connection, OpenError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sqlite)?;
    apply_connection_pragmas(&conn).map_err(sqlite)?;
    Ok(conn)
}

pub struct Migration {
    pub from: u32,
    pub to: u32,
    pub apply: fn(&Transaction) -> rusqlite::Result<()>,
}

/// No migrations exist in v1.
pub const MIGRATIONS: &[Migration] = &[];

fn user_version(conn: &Connection) -> rusqlite::Result<u32> {
    conn.pragma_query_value(None, "user_version", |r| r.get(0))
}

/// Applies every pending step in one transaction: for each step `apply`, then
/// `PRAGMA user_version = to` (transactional under WAL, V22), then `on_step` (the caller appends
/// `SCHEMA_MIGRATED` there). Any error rolls everything back and returns `MigrationFailed`.
/// Returns the `(from, to)` span that was applied, or `None` when nothing was pending.
pub fn run_migrations(
    conn: &mut Connection,
    migrations: &[Migration],
    on_step: &mut dyn FnMut(&Transaction, u32, u32) -> Result<(), AuditError>,
) -> Result<Option<(u32, u32)>, OpenError> {
    let start = user_version(conn).map_err(sqlite)?;
    if !migrations.iter().any(|m| m.from == start) {
        return Ok(None);
    }
    let fail =
        |from: u32, to: u32, message: String| OpenError::MigrationFailed { from, to, message };
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| fail(start, start, e.to_string()))?;
    let mut cur = start;
    while let Some(m) = migrations.iter().find(|m| m.from == cur) {
        (m.apply)(&tx).map_err(|e| fail(m.from, m.to, e.to_string()))?;
        tx.pragma_update(None, "user_version", m.to)
            .map_err(|e| fail(m.from, m.to, e.to_string()))?;
        on_step(&tx, m.from, m.to).map_err(|e| fail(m.from, m.to, e.to_string()))?;
        cur = m.to;
    }
    tx.commit().map_err(|e| fail(start, cur, e.to_string()))?;
    Ok(Some((start, cur)))
}

/// What a read-only peek at a store reports for the version gate (§8.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreVersions {
    pub user_version: u32,
    pub head_format_version: Option<u64>,
    pub recovery_layout: Option<u8>,
    pub written_by: Option<String>,
}

/// Opens read-only, reads the versions and closes. Writes nothing and sets no pragmas.
pub fn read_versions(path: &Path) -> Result<StoreVersions, OpenError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sqlite)?;
    let user_version = user_version(&conn).map_err(sqlite)?;
    let head_format_version = conn
        .query_row(
            "SELECT format_version FROM events ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite)?
        .map(|v| v as u64);
    let recovery_layout = conn
        .query_row("SELECT blob FROM recovery WHERE id=1", [], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .optional()
        .map_err(sqlite)?
        .and_then(|b| recovery_layout(&b));
    let written_by = conn
        .query_row(
            "SELECT value FROM meta WHERE key=?1",
            [META_WRITTEN_BY],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite)?;
    Ok(StoreVersions {
        user_version,
        head_format_version,
        recovery_layout,
        written_by,
    })
}

/// Refuses a store newer than this binary. `Err` carries what was found, e.g. `"user_version 2"`.
pub fn gate(v: &StoreVersions) -> Result<(), String> {
    if v.user_version > SCHEMA_HEAD {
        return Err(format!("user_version {}", v.user_version));
    }
    if let Some(f) = v.head_format_version.filter(|&f| f > FORMAT_VERSION) {
        return Err(format!("format_version {f}"));
    }
    if let Some(l) = v.recovery_layout.filter(|&l| l > RECOVERY_LAYOUT) {
        return Err(format!("recovery layout {l}"));
    }
    Ok(())
}
