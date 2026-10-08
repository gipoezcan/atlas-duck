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

fn other_err(msg: String) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(msg)))
}

/// Creates schema v1 on a new, empty database file: page size and auto-vacuum first (they only
/// take effect before the first table), then WAL, then the tables, `user_version = 1` and
/// `meta.written_by`. The caller owns the connection and applies [`apply_connection_pragmas`].
/// Refuses a file that already holds any schema object or a non-zero `user_version`.
pub fn create_v1(conn: &Connection) -> rusqlite::Result<()> {
    let objects: i64 = conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))?;
    if objects != 0 || user_version(conn)? != 0 {
        return Err(other_err(
            "create_v1 needs a new, empty database file".into(),
        ));
    }
    conn.pragma_update(None, "page_size", 8192)?;
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    let mode: String = conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(other_err(format!("journal_mode WAL refused, got {mode}")));
    }
    conn.execute_batch(&format!(
        "BEGIN IMMEDIATE;{TABLES_V1}PRAGMA user_version = {SCHEMA_HEAD};COMMIT;"
    ))?;
    set_written_by(conn)
}

/// Records the version of the binary that opened the store read-write (advisory). The writer
/// calls it only after the open has been verified (T07/T10).
pub(crate) fn set_written_by(conn: &Connection) -> rusqlite::Result<()> {
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

#[derive(Clone, Copy)]
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
/// A step with `to <= from`, or a gap (a step starting above the reached version but none starting
/// at it), is refused before anything is changed. Returns the `(from, to)` span that was applied,
/// or `None` when nothing was pending.
///
/// Call only after the store has been verified (T10). The table is a parameter so tests can
/// exercise the runner; production passes [`MIGRATIONS`].
#[doc(hidden)]
pub fn run_migrations(
    conn: &mut Connection,
    migrations: &[Migration],
    on_step: &mut dyn FnMut(&Transaction, u32, u32) -> Result<(), AuditError>,
) -> Result<Option<(u32, u32)>, OpenError> {
    let start = user_version(conn).map_err(sqlite)?;
    let fail =
        |from: u32, to: u32, message: String| OpenError::MigrationFailed { from, to, message };
    if let Some(m) = migrations.iter().find(|m| m.to <= m.from) {
        return Err(fail(
            m.from,
            m.to,
            "migration does not increase the version".into(),
        ));
    }
    let mut steps: Vec<&Migration> = Vec::new();
    let mut cur = start;
    while let Some(m) = migrations.iter().find(|m| m.from == cur) {
        steps.push(m);
        cur = m.to;
    }
    if let Some(next) = migrations.iter().map(|m| m.from).filter(|&f| f > cur).min() {
        return Err(fail(
            cur,
            next,
            format!("no migration step from version {cur}"),
        ));
    }
    if steps.is_empty() {
        return Ok(None);
    }
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| fail(start, cur, e.to_string()))?;
    for m in steps {
        (m.apply)(&tx).map_err(|e| fail(m.from, m.to, e.to_string()))?;
        tx.pragma_update(None, "user_version", m.to)
            .map_err(|e| fail(m.from, m.to, e.to_string()))?;
        on_step(&tx, m.from, m.to).map_err(|e| fail(m.from, m.to, e.to_string()))?;
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

fn uri_for(path: &Path) -> Result<String, OpenError> {
    let p = path
        .to_str()
        .ok_or_else(|| OpenError::Io(std::io::Error::other("database path is not UTF-8")))?
        .replace('\\', "/");
    let mut out = String::from("file:");
    if !p.starts_with('/') {
        out.push('/');
    }
    for b in p.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out.push_str("?mode=ro&immutable=1");
    Ok(out)
}

fn versions_from(conn: &Connection) -> Result<StoreVersions, OpenError> {
    let user_version = user_version(conn).map_err(sqlite)?;
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

/// A read-only connection that leaves the database files as they are (the version gate and
/// everything `open()` reads before the writer starts).
///
/// A plain read-only connection to a WAL database creates (and cannot remove) `-wal`/`-shm`
/// sidecars, so when no `-wal` file exists the database is opened `immutable=1` (no sidecars;
/// with no WAL there is nothing it could miss). When a `-wal` exists (a crash left one, or a
/// writer is live) a normal read-only connection is used so the WAL content is seen; the `-wal`
/// is neither modified nor removed (a read-only connection never checkpoints) and only `-shm`
/// may change. Sets no pragmas.
pub(crate) fn open_peek(path: &Path) -> Result<Connection, OpenError> {
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    if Path::new(&wal).exists() {
        Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
    } else {
        Connection::open_with_flags(
            uri_for(path)?,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI,
        )
    }
    .map_err(sqlite)
}

/// Opens read-only (see `open_peek`), reads the versions and closes. Writes nothing and sets
/// no pragmas. The normal open path additionally re-checks through its own WAL-aware
/// connection with [`gate_open_connection`].
pub fn read_versions(path: &Path) -> Result<StoreVersions, OpenError> {
    versions_from(&open_peek(path)?)
}

/// The version gate on an already open, WAL-aware connection (the writer runs it right after
/// [`open_rw`], before touching anything): `NewerStore(found)` for a newer store.
pub fn gate_open_connection(conn: &Connection) -> Result<(), OpenError> {
    gate_open_connection_up_to(conn, SCHEMA_HEAD)
}

/// [`gate_open_connection`] for a binary whose schema head is `head` (test migrations raise it).
pub(crate) fn gate_open_connection_up_to(conn: &Connection, head: u32) -> Result<(), OpenError> {
    gate_up_to(&versions_from(conn)?, head).map_err(OpenError::NewerStore)
}

/// Refuses a store newer than this binary. `Err` carries what was found, e.g. `"user_version 2"`.
pub fn gate(v: &StoreVersions) -> Result<(), String> {
    gate_up_to(v, SCHEMA_HEAD)
}

/// [`gate`] for a binary whose schema head is `head`.
pub(crate) fn gate_up_to(v: &StoreVersions, head: u32) -> Result<(), String> {
    if v.user_version > head {
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
