//! The SQLite `ServerStore` (`<data>/server/server.db`): WAL, foreign keys, a 5 s busy timeout,
//! schema v1 (PD-217 triggers make the anchor tables append-only). One connection behind a
//! mutex: the server is a single process (ADR 0003) and every call is short.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Row, params};

use super::schema::{SCHEMA_VERSION, V1};
use super::{
    AnchorHasher, AnchorHead, AnchorRow, ApiKeyRecord, InstanceRecord, PatRecord, Sealed,
    ServerStore, SessionRecord, StoreError, StoreResult, UserRecord, UserState,
};

pub struct SqliteStore {
    conn: Mutex<Connection>,
}

fn db(e: rusqlite::Error) -> StoreError {
    if let rusqlite::Error::SqliteFailure(f, _) = &e
        && f.code == rusqlite::ErrorCode::ConstraintViolation
        && (f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
            || f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
    {
        return StoreError::Duplicate;
    }
    StoreError::Db(e.to_string())
}

fn json_list(v: &[String]) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "[]".into())
}

fn parse_list(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

fn hash32(v: Vec<u8>) -> rusqlite::Result<[u8; 32]> {
    v.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            "expected 32 bytes".into(),
        )
    })
}

fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn to_i64(v: u64) -> StoreResult<i64> {
    i64::try_from(v).map_err(|_| StoreError::Db("integer out of range".into()))
}

impl SqliteStore {
    /// Opens (creating when absent) the database at `path`; refuses a newer schema.
    pub fn open(path: &Path) -> StoreResult<SqliteStore> {
        Self::init(Connection::open(path).map_err(db)?)
    }

    /// An in-memory database (tests of code above the store).
    pub fn open_in_memory() -> StoreResult<SqliteStore> {
        Self::init(Connection::open_in_memory().map_err(db)?)
    }

    fn init(conn: Connection) -> StoreResult<SqliteStore> {
        conn.busy_timeout(Duration::from_millis(5000)).map_err(db)?;
        // An in-memory database answers "memory"; a file one "wal".
        let _: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(db)?;
        conn.execute_batch("PRAGMA foreign_keys=ON;").map_err(db)?;
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(db)?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::Newer(version));
        }
        if version == 0 {
            let tx = conn.unchecked_transaction().map_err(db)?;
            tx.execute_batch(V1).map_err(db)?;
            tx.execute_batch("PRAGMA user_version=1;").map_err(db)?;
            tx.commit().map_err(db)?;
        }
        // M13 Δ-M13-3: every file, new or old, climbs the same up-migration path.
        super::migrate::to_current(&conn)?;
        Ok(SqliteStore {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Raw access for tests (tampering, trigger checks).
    #[cfg(test)]
    pub(crate) fn raw(&self) -> MutexGuard<'_, Connection> {
        self.conn()
    }
}

fn user_row(r: &Row<'_>) -> rusqlite::Result<UserRecord> {
    Ok(UserRecord {
        user_id: r.get(0)?,
        username: r.get(1)?,
        display_name: r.get(2)?,
        roles: parse_list(&r.get::<_, String>(3)?),
        data_key_wrapped: r.get(4)?,
        created_at: r.get(5)?,
    })
}

const USER_COLS: &str = "user_id, username, display_name, roles, data_key_wrapped, created_at";
const STATE_COLS: &str = "deactivated_at, deactivated_by, last_login_at, retention_until";

fn state_row(r: &Row<'_>, at: usize) -> rusqlite::Result<UserState> {
    Ok(UserState {
        deactivated_at: r.get(at)?,
        deactivated_by: r.get(at + 1)?,
        last_login_at: r.get(at + 2)?,
        retention_until: r.get(at + 3)?,
    })
}

fn pat_row(r: &Row<'_>) -> rusqlite::Result<PatRecord> {
    Ok(PatRecord {
        user_id: r.get(0)?,
        alias: r.get(1)?,
        sealed: Sealed {
            nonce: r.get(2)?,
            ct: r.get(3)?,
        },
        identity_json: r.get(4)?,
        checked_at: r.get(5)?,
    })
}

const PAT_COLS: &str = "user_id, alias, nonce, ct, identity_json, checked_at";

fn session_row(r: &Row<'_>) -> rusqlite::Result<SessionRecord> {
    Ok(SessionRecord {
        id_hash: hash32(r.get(0)?)?,
        user_id: r.get(1)?,
        roles: parse_list(&r.get::<_, String>(2)?),
        csrf_token: r.get(3)?,
        created_at: r.get(4)?,
        last_seen: r.get(5)?,
        absolute_expiry: r.get(6)?,
        idle_expiry: r.get(7)?,
    })
}

const SESSION_COLS: &str =
    "id_hash, user_id, roles, csrf_token, created_at, last_seen, absolute_expiry, idle_expiry";

fn key_row(r: &Row<'_>) -> rusqlite::Result<ApiKeyRecord> {
    Ok(ApiKeyRecord {
        id: r.get(0)?,
        user_id: r.get(1)?,
        name: r.get(2)?,
        prefix: r.get(3)?,
        hash: r.get(4)?,
        scopes: parse_list(&r.get::<_, String>(5)?),
        created_at: r.get(6)?,
        expires_at: r.get(7)?,
        last_used_at: r.get(8)?,
        revoked_at: r.get(9)?,
    })
}

const KEY_COLS: &str =
    "id, user_id, name, prefix, hash, scopes, created_at, expires_at, last_used_at, revoked_at";

fn instance_row(r: &Row<'_>) -> rusqlite::Result<InstanceRecord> {
    Ok(InstanceRecord {
        alias: r.get(0)?,
        product: r.get(1)?,
        base_url: r.get(2)?,
        proxy: r.get(3)?,
        ca_ref: r.get(4)?,
        is_default: r.get::<_, i64>(5)? != 0,
    })
}

fn anchor_row(r: &Row<'_>) -> rusqlite::Result<AnchorRow> {
    Ok(AnchorRow {
        seq: to_u64(r.get(0)?),
        ts_utc: r.get(1)?,
        kind: r.get(2)?,
        body_jcs: r.get(3)?,
        prev_hash: hash32(r.get(4)?)?,
        hash: hash32(r.get(5)?)?,
    })
}

const ANCHOR_COLS: &str = "seq, ts_utc, kind, body_jcs, prev_hash, hash";

fn head_row(r: &Row<'_>) -> rusqlite::Result<(u64, AnchorHead)> {
    Ok((
        to_u64(r.get(0)?),
        AnchorHead {
            user_id: r.get(1)?,
            chain_id: r.get(2)?,
            head_seq: to_u64(r.get(3)?),
            record_hash: hash32(r.get(4)?)?,
        },
    ))
}

fn collect<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&Row<'_>) -> rusqlite::Result<T>>,
) -> StoreResult<Vec<T>> {
    rows.collect::<rusqlite::Result<Vec<T>>>().map_err(db)
}

impl ServerStore for SqliteStore {
    fn upsert_user(&self, u: &UserRecord) -> StoreResult<()> {
        self.conn()
            .execute(
                "INSERT INTO users (user_id, username, display_name, roles, data_key_wrapped, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(user_id) DO UPDATE SET display_name = excluded.display_name,
                     roles = excluded.roles, data_key_wrapped = excluded.data_key_wrapped",
                params![
                    u.user_id,
                    u.username,
                    u.display_name,
                    json_list(&u.roles),
                    u.data_key_wrapped,
                    u.created_at
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    fn user(&self, user_id: &str) -> StoreResult<Option<UserRecord>> {
        self.conn()
            .query_row(
                &format!("SELECT {USER_COLS} FROM users WHERE user_id = ?1"),
                [user_id],
                user_row,
            )
            .optional()
            .map_err(db)
    }

    fn user_by_name(&self, username: &str) -> StoreResult<Option<UserRecord>> {
        self.conn()
            .query_row(
                &format!("SELECT {USER_COLS} FROM users WHERE username = ?1"),
                [username],
                user_row,
            )
            .optional()
            .map_err(db)
    }

    fn users_all(&self) -> StoreResult<Vec<(UserRecord, UserState)>> {
        let c = self.conn();
        let mut st = c
            .prepare(&format!(
                "SELECT {USER_COLS}, {STATE_COLS} FROM users ORDER BY username"
            ))
            .map_err(db)?;
        collect(
            st.query_map([], |r| Ok((user_row(r)?, state_row(r, 6)?)))
                .map_err(db)?,
        )
    }

    fn user_state(&self, user_id: &str) -> StoreResult<Option<UserState>> {
        self.conn()
            .query_row(
                &format!("SELECT {STATE_COLS} FROM users WHERE user_id = ?1"),
                [user_id],
                |r| state_row(r, 0),
            )
            .optional()
            .map_err(db)
    }

    fn user_set_last_login(&self, user_id: &str, at: i64) -> StoreResult<()> {
        self.conn()
            .execute(
                "UPDATE users SET last_login_at = ?2 WHERE user_id = ?1",
                params![user_id, at],
            )
            .map_err(db)?;
        Ok(())
    }

    fn user_deactivate(
        &self,
        user_id: &str,
        at: i64,
        by: &str,
        retention_until: i64,
    ) -> StoreResult<bool> {
        let n = self
            .conn()
            .execute(
                "UPDATE users SET deactivated_at = ?2, deactivated_by = ?3, retention_until = ?4
                 WHERE user_id = ?1 AND deactivated_at IS NULL",
                params![user_id, at, by, retention_until],
            )
            .map_err(db)?;
        Ok(n > 0)
    }

    fn ks_get(&self, user_id: &str, entry: &str) -> StoreResult<Option<Sealed>> {
        self.conn()
            .query_row(
                "SELECT nonce, ct FROM user_keystore WHERE user_id = ?1 AND entry_name = ?2",
                [user_id, entry],
                |r| {
                    Ok(Sealed {
                        nonce: r.get(0)?,
                        ct: r.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(db)
    }

    fn ks_set(&self, user_id: &str, entry: &str, v: &Sealed) -> StoreResult<()> {
        self.conn()
            .execute(
                "INSERT INTO user_keystore (user_id, entry_name, nonce, ct) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(user_id, entry_name) DO UPDATE SET nonce = excluded.nonce, ct = excluded.ct",
                params![user_id, entry, v.nonce, v.ct],
            )
            .map_err(db)?;
        Ok(())
    }

    fn ks_delete(&self, user_id: &str, entry: &str) -> StoreResult<bool> {
        let n = self
            .conn()
            .execute(
                "DELETE FROM user_keystore WHERE user_id = ?1 AND entry_name = ?2",
                [user_id, entry],
            )
            .map_err(db)?;
        Ok(n > 0)
    }

    fn pat_put(&self, p: &PatRecord) -> StoreResult<()> {
        self.conn()
            .execute(
                "INSERT INTO user_pats (user_id, alias, nonce, ct, identity_json, checked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(user_id, alias) DO UPDATE SET nonce = excluded.nonce, ct = excluded.ct,
                     identity_json = excluded.identity_json, checked_at = excluded.checked_at",
                params![
                    p.user_id,
                    p.alias,
                    p.sealed.nonce,
                    p.sealed.ct,
                    p.identity_json,
                    p.checked_at
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    fn pat_get(&self, user_id: &str, alias: &str) -> StoreResult<Option<PatRecord>> {
        self.conn()
            .query_row(
                &format!("SELECT {PAT_COLS} FROM user_pats WHERE user_id = ?1 AND alias = ?2"),
                [user_id, alias],
                pat_row,
            )
            .optional()
            .map_err(db)
    }

    fn pat_list(&self, user_id: &str) -> StoreResult<Vec<PatRecord>> {
        let c = self.conn();
        let mut st = c
            .prepare(&format!(
                "SELECT {PAT_COLS} FROM user_pats WHERE user_id = ?1 ORDER BY alias"
            ))
            .map_err(db)?;
        collect(st.query_map([user_id], pat_row).map_err(db)?)
    }

    fn pat_delete(&self, user_id: &str, alias: &str) -> StoreResult<bool> {
        let n = self
            .conn()
            .execute(
                "DELETE FROM user_pats WHERE user_id = ?1 AND alias = ?2",
                [user_id, alias],
            )
            .map_err(db)?;
        Ok(n > 0)
    }

    fn pats_for_alias(&self, alias: &str) -> StoreResult<Vec<PatRecord>> {
        let c = self.conn();
        let mut st = c
            .prepare(&format!(
                "SELECT {PAT_COLS} FROM user_pats WHERE alias = ?1 ORDER BY user_id"
            ))
            .map_err(db)?;
        collect(st.query_map([alias], pat_row).map_err(db)?)
    }

    fn session_put(&self, s: &SessionRecord) -> StoreResult<()> {
        self.conn()
            .execute(
                &format!(
                    "INSERT OR REPLACE INTO sessions ({SESSION_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
                ),
                params![
                    s.id_hash.as_slice(),
                    s.user_id,
                    json_list(&s.roles),
                    s.csrf_token,
                    s.created_at,
                    s.last_seen,
                    s.absolute_expiry,
                    s.idle_expiry
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    fn session_get(&self, id_hash: &[u8; 32]) -> StoreResult<Option<SessionRecord>> {
        self.conn()
            .query_row(
                &format!("SELECT {SESSION_COLS} FROM sessions WHERE id_hash = ?1"),
                [id_hash.as_slice()],
                session_row,
            )
            .optional()
            .map_err(db)
    }

    fn session_touch(
        &self,
        id_hash: &[u8; 32],
        last_seen: i64,
        idle_expiry: i64,
    ) -> StoreResult<()> {
        self.conn()
            .execute(
                "UPDATE sessions SET last_seen = ?2, idle_expiry = ?3 WHERE id_hash = ?1",
                params![id_hash.as_slice(), last_seen, idle_expiry],
            )
            .map_err(db)?;
        Ok(())
    }

    fn session_delete(&self, id_hash: &[u8; 32]) -> StoreResult<bool> {
        let n = self
            .conn()
            .execute(
                "DELETE FROM sessions WHERE id_hash = ?1",
                [id_hash.as_slice()],
            )
            .map_err(db)?;
        Ok(n > 0)
    }

    fn session_delete_expired(&self, now: i64) -> StoreResult<u64> {
        let n = self
            .conn()
            .execute(
                "DELETE FROM sessions WHERE absolute_expiry <= ?1 OR idle_expiry <= ?1",
                [now],
            )
            .map_err(db)?;
        Ok(n as u64)
    }

    fn sessions_all(&self) -> StoreResult<Vec<SessionRecord>> {
        let c = self.conn();
        let mut st = c
            .prepare(&format!("SELECT {SESSION_COLS} FROM sessions"))
            .map_err(db)?;
        collect(st.query_map([], session_row).map_err(db)?)
    }

    fn sessions_delete_for_user(&self, user_id: &str) -> StoreResult<u64> {
        let n = self
            .conn()
            .execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])
            .map_err(db)?;
        Ok(n as u64)
    }

    fn api_key_insert(&self, k: &ApiKeyRecord) -> StoreResult<()> {
        self.conn()
            .execute(
                &format!(
                    "INSERT INTO api_keys ({KEY_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
                ),
                params![
                    k.id,
                    k.user_id,
                    k.name,
                    k.prefix,
                    k.hash,
                    json_list(&k.scopes),
                    k.created_at,
                    k.expires_at,
                    k.last_used_at,
                    k.revoked_at
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    fn api_key_by_prefix(&self, prefix: &str) -> StoreResult<Option<ApiKeyRecord>> {
        self.conn()
            .query_row(
                &format!("SELECT {KEY_COLS} FROM api_keys WHERE prefix = ?1"),
                [prefix],
                key_row,
            )
            .optional()
            .map_err(db)
    }

    fn api_key_list(&self, user_id: &str) -> StoreResult<Vec<ApiKeyRecord>> {
        let c = self.conn();
        let mut st = c
            .prepare(&format!(
                "SELECT {KEY_COLS} FROM api_keys WHERE user_id = ?1 ORDER BY created_at, id"
            ))
            .map_err(db)?;
        collect(st.query_map([user_id], key_row).map_err(db)?)
    }

    fn api_key_revoke(&self, user_id: &str, id: &str, at: i64) -> StoreResult<bool> {
        let n = self
            .conn()
            .execute(
                "UPDATE api_keys SET revoked_at = ?3 WHERE user_id = ?1 AND id = ?2 AND revoked_at IS NULL",
                params![user_id, id, at],
            )
            .map_err(db)?;
        Ok(n > 0)
    }

    fn api_key_touch_last_used(&self, user_id: &str, id: &str, at: i64) -> StoreResult<()> {
        self.conn()
            .execute(
                "UPDATE api_keys SET last_used_at = ?3 WHERE user_id = ?1 AND id = ?2",
                params![user_id, id, at],
            )
            .map_err(db)?;
        Ok(())
    }

    fn api_key_count_active(&self, user_id: &str, now: i64) -> StoreResult<u64> {
        let n: i64 = self
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM api_keys WHERE user_id = ?1 AND revoked_at IS NULL AND expires_at > ?2",
                params![user_id, now],
                |r| r.get(0),
            )
            .map_err(db)?;
        Ok(to_u64(n))
    }

    fn api_keys_revoke_all(&self, user_id: &str, at: i64) -> StoreResult<Vec<ApiKeyRecord>> {
        let mut c = self.conn();
        let tx = c.transaction().map_err(db)?;
        let keys = {
            let mut st = tx
                .prepare(&format!(
                    "SELECT {KEY_COLS} FROM api_keys WHERE user_id = ?1 AND revoked_at IS NULL
                     ORDER BY created_at, id"
                ))
                .map_err(db)?;
            collect(st.query_map([user_id], key_row).map_err(db)?)?
        };
        tx.execute(
            "UPDATE api_keys SET revoked_at = ?2 WHERE user_id = ?1 AND revoked_at IS NULL",
            params![user_id, at],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(keys
            .into_iter()
            .map(|k| ApiKeyRecord {
                revoked_at: Some(at),
                ..k
            })
            .collect())
    }

    fn instance_put(&self, i: &InstanceRecord) -> StoreResult<()> {
        self.conn()
            .execute(
                "INSERT INTO instances (alias, product, base_url, proxy, ca_ref, is_default)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    i.alias,
                    i.product,
                    i.base_url,
                    i.proxy,
                    i.ca_ref,
                    i64::from(i.is_default)
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    fn instance_list(&self) -> StoreResult<Vec<InstanceRecord>> {
        let c = self.conn();
        let mut st = c
            .prepare(
                "SELECT alias, product, base_url, proxy, ca_ref, is_default FROM instances ORDER BY alias",
            )
            .map_err(db)?;
        collect(st.query_map([], instance_row).map_err(db)?)
    }

    fn instance_delete(&self, alias: &str) -> StoreResult<bool> {
        let n = self
            .conn()
            .execute("DELETE FROM instances WHERE alias = ?1", [alias])
            .map_err(db)?;
        Ok(n > 0)
    }

    fn anchor_append(
        &self,
        kind: &str,
        ts_utc: &str,
        body_jcs: &[u8],
        heads: &[AnchorHead],
        hash: AnchorHasher<'_>,
    ) -> StoreResult<AnchorRow> {
        let mut c = self.conn();
        let tx = c.transaction().map_err(db)?;
        let last: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT seq, hash FROM anchor_chain ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        let (seq, prev_hash) = match last {
            None => (1u64, [0u8; 32]),
            Some((s, h)) => (to_u64(s) + 1, hash32(h).map_err(db)?),
        };
        let row = AnchorRow {
            seq,
            ts_utc: ts_utc.to_owned(),
            kind: kind.to_owned(),
            body_jcs: body_jcs.to_vec(),
            prev_hash,
            hash: hash(seq, &prev_hash),
        };
        tx.execute(
            &format!("INSERT INTO anchor_chain ({ANCHOR_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"),
            params![
                to_i64(seq)?,
                row.ts_utc,
                row.kind,
                row.body_jcs,
                row.prev_hash.as_slice(),
                row.hash.as_slice()
            ],
        )
        .map_err(db)?;
        for h in heads {
            tx.execute(
                "INSERT INTO anchor_heads (anchor_seq, user_id, chain_id, head_seq, record_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    to_i64(seq)?,
                    h.user_id,
                    h.chain_id,
                    to_i64(h.head_seq)?,
                    h.record_hash.as_slice()
                ],
            )
            .map_err(db)?;
        }
        tx.commit().map_err(db)?;
        Ok(row)
    }

    fn anchor_all(&self) -> StoreResult<Vec<AnchorRow>> {
        let c = self.conn();
        let mut st = c
            .prepare(&format!(
                "SELECT {ANCHOR_COLS} FROM anchor_chain ORDER BY seq"
            ))
            .map_err(db)?;
        collect(st.query_map([], anchor_row).map_err(db)?)
    }

    fn anchor_latest_heads(&self) -> StoreResult<Vec<AnchorHead>> {
        let c = self.conn();
        let mut st = c
            .prepare(
                "SELECT anchor_seq, user_id, chain_id, head_seq, record_hash FROM anchor_heads
                 WHERE rowid IN (SELECT MAX(rowid) FROM anchor_heads GROUP BY user_id)
                 ORDER BY user_id",
            )
            .map_err(db)?;
        let rows = collect(st.query_map([], head_row).map_err(db)?)?;
        Ok(rows.into_iter().map(|(_, h)| h).collect())
    }

    fn snapshot_to(&self, path: &Path) -> StoreResult<()> {
        self.conn()
            .backup(rusqlite::MAIN_DB, path, None)
            .map_err(db)
    }

    fn restore_from(&self, path: &Path) -> StoreResult<()> {
        self.conn()
            .restore(
                rusqlite::MAIN_DB,
                path,
                None::<fn(rusqlite::backup::Progress)>,
            )
            .map_err(db)
    }

    fn anchor_last(&self) -> StoreResult<Option<AnchorRow>> {
        self.conn()
            .query_row(
                &format!("SELECT {ANCHOR_COLS} FROM anchor_chain ORDER BY seq DESC LIMIT 1"),
                [],
                anchor_row,
            )
            .optional()
            .map_err(db)
    }

    fn anchor_heads_for(&self, anchor_seq: u64) -> StoreResult<Vec<AnchorHead>> {
        let c = self.conn();
        let mut st = c
            .prepare(
                "SELECT anchor_seq, user_id, chain_id, head_seq, record_hash FROM anchor_heads
                 WHERE anchor_seq = ?1 ORDER BY rowid",
            )
            .map_err(db)?;
        let rows = collect(st.query_map([to_i64(anchor_seq)?], head_row).map_err(db)?)?;
        Ok(rows.into_iter().map(|(_, h)| h).collect())
    }

    fn anchor_heads_for_chain(
        &self,
        chain_id: &str,
        upto_seq: u64,
    ) -> StoreResult<Vec<(u64, AnchorHead)>> {
        let c = self.conn();
        let mut st = c
            .prepare(
                "SELECT anchor_seq, user_id, chain_id, head_seq, record_hash FROM anchor_heads
                 WHERE chain_id = ?1 AND head_seq <= ?2 ORDER BY anchor_seq, rowid",
            )
            .map_err(db)?;
        collect(
            st.query_map(params![chain_id, to_i64(upto_seq)?], head_row)
                .map_err(db)?,
        )
    }
}
