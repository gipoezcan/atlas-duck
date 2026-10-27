//! The up-migration path of `server.db` (M13 Δ-M13-3): one transaction per step, so a failed step
//! leaves the file at the version before it (`store/migration_failed {from, to}`). There is no
//! down path: a rollback to an older build needs a restore (docs/server/deployment.md).

use rusqlite::Connection;

use super::StoreError;
use super::schema::{SCHEMA_VERSION, up_from};

/// `PRAGMA user_version`.
pub fn version(conn: &Connection) -> Result<u32, StoreError> {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| StoreError::Db(e.to_string()))
}

/// Migrates from `from` to `to`, one committed step at a time.
pub fn migrate(conn: &Connection, from: u32, to: u32) -> Result<(), StoreError> {
    for v in from..to {
        step(conn, v).map_err(|_| StoreError::Migration { from: v, to: v + 1 })?;
        tracing::info!(event = "store_migrated", from = v, to = v + 1);
    }
    Ok(())
}

fn step(conn: &Connection, from: u32) -> Result<(), rusqlite::Error> {
    let sql = up_from(from).ok_or(rusqlite::Error::InvalidQuery)?;
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(sql)?;
    tx.execute_batch(&format!("PRAGMA user_version={};", from + 1))?;
    tx.commit()
}

/// Brings a file at any version up to [`SCHEMA_VERSION`].
pub fn to_current(conn: &Connection) -> Result<(), StoreError> {
    let v = version(conn)?;
    if v > SCHEMA_VERSION {
        return Err(StoreError::Newer(v));
    }
    migrate(conn, v, SCHEMA_VERSION)
}
