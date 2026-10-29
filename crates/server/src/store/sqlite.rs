//! The SQLite `ServerStore` (`<data>/server/server.db`): WAL, or the rollback journal with an
//! exclusive lock on a network volume (ADR 0004), foreign keys, a 5 s busy timeout, schema v1
//! (PD-217 triggers make the anchor tables append-only). One connection behind a mutex: the
//! server is a single process (ADR 0003) and every call is short.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use atlas_duck_audit::JournalMode;
use rusqlite::{Connection, OptionalExtension, Row, params};

use super::schema::{SCHEMA_VERSION, V1};
use super::{
    AccessRecord, AnchorHasher, AnchorHead, AnchorRow, ApiKeyRecord, CLIENT_ENDED_SECS,
    CLIENT_UNUSED_SECS, CodeRecord, ConsentRequestRecord, ExportJobRecord, GrantRecord,
    InstanceRecord, JobState, LangPref, OAuthClientRecord, PatRecord, Redeem, RefreshRecord,
    Rotate, Sealed, ServerStore, SessionRecord, StoreError, StoreResult, UserRecord, UserState,
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
        Self::open_with(path, JournalMode::Wal)
    }

    /// [`SqliteStore::open`] in `journal` mode. `Delete` (ADR 0004, a data volume on NFS) also
    /// sets `synchronous=FULL` and `locking_mode=EXCLUSIVE`: this connection is the only one
    /// to the file (every reader goes through the store's mutex, backups through
    /// `snapshot_to`), so the lock only keeps any other process out.
    pub fn open_with(path: &Path, journal: JournalMode) -> StoreResult<SqliteStore> {
        let conn = Connection::open(path).map_err(db)?;
        conn.busy_timeout(Duration::from_millis(5000)).map_err(db)?;
        // Before the first read: the lock mode takes effect on the next lock taken.
        if journal == JournalMode::Delete {
            conn.execute_batch("PRAGMA locking_mode=EXCLUSIVE; PRAGMA synchronous=FULL;")
                .map_err(db)?;
        }
        let want = match journal {
            JournalMode::Wal => "wal",
            JournalMode::Delete => "delete",
        };
        let got: String = conn
            .query_row(&format!("PRAGMA journal_mode={want}"), [], |r| r.get(0))
            .map_err(db)?;
        if !got.eq_ignore_ascii_case(want) {
            return Err(StoreError::Db(format!(
                "journal_mode {want} refused, got {got}"
            )));
        }
        Self::init(conn)
    }

    /// An in-memory database (tests of code above the store).
    pub fn open_in_memory() -> StoreResult<SqliteStore> {
        Self::init(Connection::open_in_memory().map_err(db)?)
    }

    fn init(conn: Connection) -> StoreResult<SqliteStore> {
        conn.busy_timeout(Duration::from_millis(5000)).map_err(db)?;
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
const STATE_COLS: &str =
    "deactivated_at, deactivated_by, last_login_at, retention_until, chain_deleted_at";

fn state_row(r: &Row<'_>, at: usize) -> rusqlite::Result<UserState> {
    Ok(UserState {
        deactivated_at: r.get(at)?,
        deactivated_by: r.get(at + 1)?,
        last_login_at: r.get(at + 2)?,
        retention_until: r.get(at + 3)?,
        chain_deleted_at: r.get(at + 4)?,
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
                     roles = excluded.roles",
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

    fn user_list(&self) -> StoreResult<Vec<UserRecord>> {
        let c = self.conn();
        let mut st = c
            .prepare(&format!("SELECT {USER_COLS} FROM users ORDER BY username"))
            .map_err(db)?;
        collect(st.query_map([], user_row).map_err(db)?)
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

    fn user_lang_pref(&self, user_id: &str) -> StoreResult<LangPref> {
        let word: Option<String> = self
            .conn()
            .query_row(
                "SELECT lang_pref FROM users WHERE user_id = ?1",
                [user_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        Ok(word
            .as_deref()
            .and_then(LangPref::parse)
            .unwrap_or_default())
    }

    fn set_user_lang_pref(&self, user_id: &str, pref: LangPref) -> StoreResult<()> {
        self.conn()
            .execute(
                "UPDATE users SET lang_pref = ?2 WHERE user_id = ?1",
                params![user_id, pref.as_str()],
            )
            .map_err(db)?;
        Ok(())
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

    fn user_purge(&self, user_id: &str, at: i64) -> StoreResult<()> {
        let mut c = self.conn();
        let tx = c.transaction().map_err(db)?;
        for sql in [
            "DELETE FROM user_keystore WHERE user_id = ?1",
            "DELETE FROM user_pats WHERE user_id = ?1",
            "DELETE FROM sessions WHERE user_id = ?1",
            "DELETE FROM api_keys WHERE user_id = ?1",
            // M14: the user's OAuth state and export jobs (their files go with the TTL sweep).
            "DELETE FROM oauth_access WHERE grant_id IN (SELECT grant_id FROM oauth_grants WHERE user_id = ?1)",
            "DELETE FROM oauth_refresh WHERE grant_id IN (SELECT grant_id FROM oauth_grants WHERE user_id = ?1)",
            "DELETE FROM oauth_codes WHERE grant_id IN (SELECT grant_id FROM oauth_grants WHERE user_id = ?1)",
            "DELETE FROM oauth_consent_requests WHERE user_id = ?1",
            "DELETE FROM oauth_grants WHERE user_id = ?1",
            "DELETE FROM export_jobs WHERE target_user_id = ?1 OR requester_user_id = ?1",
        ] {
            tx.execute(sql, [user_id]).map_err(db)?;
        }
        tx.execute(
            "UPDATE users SET data_key_wrapped = '', chain_deleted_at = ?2 WHERE user_id = ?1",
            params![user_id, at],
        )
        .map_err(db)?;
        tx.commit().map_err(db)
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

    fn user_set_wrapped(&self, user_id: &str, expected: &str, new: &str) -> StoreResult<bool> {
        let n = self
            .conn()
            .execute(
                "UPDATE users SET data_key_wrapped = ?3 WHERE user_id = ?1 AND data_key_wrapped = ?2",
                params![user_id, expected, new],
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

    fn anchor_range(&self, first: u64, last: u64) -> StoreResult<Vec<AnchorRow>> {
        let c = self.conn();
        let mut st = c
            .prepare(&format!(
                "SELECT {ANCHOR_COLS} FROM anchor_chain WHERE seq BETWEEN ?1 AND ?2 ORDER BY seq"
            ))
            .map_err(db)?;
        collect(
            st.query_map(params![to_i64(first)?, to_i64(last)?], anchor_row)
                .map_err(db)?,
        )
    }

    fn scheduler_get(&self, job: &str) -> StoreResult<JobState> {
        Ok(self
            .conn()
            .query_row(
                "SELECT last_run_at, last_success_at FROM scheduler_state WHERE job = ?1",
                [job],
                |r| {
                    Ok(JobState {
                        last_run_at: r.get(0)?,
                        last_success_at: r.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(db)?
            .unwrap_or_default())
    }

    fn scheduler_put(&self, job: &str, s: &JobState) -> StoreResult<()> {
        self.conn()
            .execute(
                "INSERT INTO scheduler_state (job, last_run_at, last_success_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(job) DO UPDATE SET last_run_at = excluded.last_run_at,
                     last_success_at = excluded.last_success_at",
                params![job, s.last_run_at, s.last_success_at],
            )
            .map_err(db)?;
        Ok(())
    }

    fn gone_since(&self, user_id: &str) -> StoreResult<Option<i64>> {
        self.conn()
            .query_row(
                "SELECT first_seen_at FROM offboarding_gone WHERE user_id = ?1",
                [user_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)
    }

    fn gone_mark(&self, user_id: &str, at: i64) -> StoreResult<()> {
        self.conn()
            .execute(
                "INSERT OR IGNORE INTO offboarding_gone (user_id, first_seen_at) VALUES (?1, ?2)",
                params![user_id, at],
            )
            .map_err(db)?;
        Ok(())
    }

    fn gone_clear(&self, user_id: &str) -> StoreResult<()> {
        self.conn()
            .execute("DELETE FROM offboarding_gone WHERE user_id = ?1", [user_id])
            .map_err(db)?;
        Ok(())
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

    fn oauth_client_insert(&self, c: &OAuthClientRecord) -> StoreResult<()> {
        self.conn()
            .execute(
                &format!("INSERT INTO oauth_clients ({CLIENT_COLS}) VALUES (?1, ?2, ?3, ?4, ?5)"),
                params![
                    c.client_id,
                    c.name,
                    json_list(&c.redirect_uris),
                    c.created_at,
                    c.source_ip_hash
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    fn oauth_client_get(&self, client_id: &str) -> StoreResult<Option<OAuthClientRecord>> {
        self.conn()
            .query_row(
                &format!("SELECT {CLIENT_COLS} FROM oauth_clients WHERE client_id = ?1"),
                [client_id],
                client_row,
            )
            .optional()
            .map_err(db)
    }

    fn oauth_client_count(&self) -> StoreResult<u64> {
        let n: i64 = self
            .conn()
            .query_row("SELECT COUNT(*) FROM oauth_clients", [], |r| r.get(0))
            .map_err(db)?;
        Ok(to_u64(n))
    }

    fn oauth_purge(&self, now: i64) -> StoreResult<u64> {
        let mut c = self.conn();
        let tx = c.transaction().map_err(db)?;
        // A grant has ended when it is revoked or past its expiry; its end is the earlier.
        let ended_end = "MIN(COALESCE(revoked_at, expires_at), expires_at)";
        let stale: Vec<String> = {
            let mut st = tx
                .prepare(&format!(
                    "SELECT client_id FROM oauth_clients c WHERE
                       (NOT EXISTS (SELECT 1 FROM oauth_grants g WHERE g.client_id = c.client_id)
                        AND c.created_at <= ?1)
                    OR (EXISTS (SELECT 1 FROM oauth_grants g WHERE g.client_id = c.client_id)
                        AND NOT EXISTS (SELECT 1 FROM oauth_grants g WHERE g.client_id = c.client_id
                                        AND g.revoked_at IS NULL AND g.expires_at > ?3)
                        AND (SELECT MAX({ended_end}) FROM oauth_grants g
                             WHERE g.client_id = c.client_id) <= ?2)"
                ))
                .map_err(db)?;
            collect(
                st.query_map(
                    params![now - CLIENT_UNUSED_SECS, now - CLIENT_ENDED_SECS, now],
                    |r| r.get(0),
                )
                .map_err(db)?,
            )?
        };
        for id in &stale {
            for table in ["oauth_codes", "oauth_access", "oauth_refresh"] {
                tx.execute(
                    &format!(
                        "DELETE FROM {table} WHERE grant_id IN
                         (SELECT grant_id FROM oauth_grants WHERE client_id = ?1)"
                    ),
                    [id],
                )
                .map_err(db)?;
            }
            tx.execute("DELETE FROM oauth_grants WHERE client_id = ?1", [id])
                .map_err(db)?;
            tx.execute(
                "DELETE FROM oauth_consent_requests WHERE client_id = ?1",
                [id],
            )
            .map_err(db)?;
            tx.execute("DELETE FROM oauth_clients WHERE client_id = ?1", [id])
                .map_err(db)?;
        }
        tx.execute(
            "DELETE FROM oauth_consent_requests WHERE expires_at <= ?1",
            [now],
        )
        .map_err(db)?;
        tx.execute("DELETE FROM oauth_codes WHERE expires_at <= ?1", [now])
            .map_err(db)?;
        tx.execute("DELETE FROM oauth_access WHERE expires_at <= ?1", [now])
            .map_err(db)?;
        tx.execute(
            "DELETE FROM oauth_refresh WHERE grant_id IN (SELECT grant_id FROM oauth_grants
             WHERE revoked_at IS NOT NULL OR expires_at <= ?1)",
            [now],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(stale.len() as u64)
    }

    fn consent_put(&self, r: &ConsentRequestRecord) -> StoreResult<()> {
        self.conn()
            .execute(
                &format!(
                    "INSERT INTO oauth_consent_requests ({CONSENT_COLS})
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
                ),
                params![
                    r.id_hash.as_slice(),
                    r.session_hash.as_slice(),
                    r.user_id,
                    r.client_id,
                    r.redirect_uri,
                    json_list(&r.scopes),
                    r.code_challenge,
                    r.state,
                    r.resource,
                    r.created_at,
                    r.expires_at
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    fn consent_get(
        &self,
        id_hash: &[u8; 32],
        session_hash: &[u8; 32],
    ) -> StoreResult<Option<ConsentRequestRecord>> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT {CONSENT_COLS} FROM oauth_consent_requests
                     WHERE id_hash = ?1 AND session_hash = ?2"
                ),
                [id_hash.as_slice(), session_hash.as_slice()],
                consent_row,
            )
            .optional()
            .map_err(db)
    }

    fn consent_take(
        &self,
        id_hash: &[u8; 32],
        session_hash: &[u8; 32],
    ) -> StoreResult<Option<ConsentRequestRecord>> {
        let mut c = self.conn();
        let tx = c.transaction().map_err(db)?;
        let found = tx
            .query_row(
                &format!(
                    "SELECT {CONSENT_COLS} FROM oauth_consent_requests
                     WHERE id_hash = ?1 AND session_hash = ?2"
                ),
                [id_hash.as_slice(), session_hash.as_slice()],
                consent_row,
            )
            .optional()
            .map_err(db)?;
        if found.is_some() {
            tx.execute(
                "DELETE FROM oauth_consent_requests WHERE id_hash = ?1",
                [id_hash.as_slice()],
            )
            .map_err(db)?;
        }
        tx.commit().map_err(db)?;
        Ok(found)
    }

    fn grant_insert(&self, g: &GrantRecord) -> StoreResult<()> {
        self.conn()
            .execute(
                &format!(
                    "INSERT INTO oauth_grants ({GRANT_COLS})
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
                ),
                params![
                    g.grant_id,
                    g.user_id,
                    g.client_id,
                    json_list(&g.scopes),
                    g.resource,
                    g.created_at,
                    g.expires_at,
                    g.last_used_at,
                    g.revoked_at,
                    g.revoke_reason
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    fn grant_get(&self, grant_id: &str) -> StoreResult<Option<GrantRecord>> {
        grant_by_id(&self.conn(), grant_id)
    }

    fn grant_list(&self, user_id: &str) -> StoreResult<Vec<GrantRecord>> {
        let c = self.conn();
        let mut st = c
            .prepare(&format!(
                "SELECT {GRANT_COLS} FROM oauth_grants WHERE user_id = ?1
                 ORDER BY created_at DESC, grant_id"
            ))
            .map_err(db)?;
        collect(st.query_map([user_id], grant_row).map_err(db)?)
    }

    fn grant_revoke(&self, grant_id: &str, reason: &str, at: i64) -> StoreResult<bool> {
        let n = self
            .conn()
            .execute(
                "UPDATE oauth_grants SET revoked_at = ?3, revoke_reason = ?2
                 WHERE grant_id = ?1 AND revoked_at IS NULL",
                params![grant_id, reason, at],
            )
            .map_err(db)?;
        Ok(n > 0)
    }

    fn grant_revoke_all(
        &self,
        user_id: &str,
        reason: &str,
        at: i64,
    ) -> StoreResult<Vec<GrantRecord>> {
        let mut c = self.conn();
        let tx = c.transaction().map_err(db)?;
        let live: Vec<GrantRecord> = {
            let mut st = tx
                .prepare(&format!(
                    "SELECT {GRANT_COLS} FROM oauth_grants WHERE user_id = ?1 AND revoked_at IS NULL
                     ORDER BY created_at, grant_id"
                ))
                .map_err(db)?;
            collect(st.query_map([user_id], grant_row).map_err(db)?)?
        };
        tx.execute(
            "UPDATE oauth_grants SET revoked_at = ?3, revoke_reason = ?2
             WHERE user_id = ?1 AND revoked_at IS NULL",
            params![user_id, reason, at],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(live
            .into_iter()
            .map(|mut g| {
                g.revoked_at = Some(at);
                g.revoke_reason = Some(reason.to_owned());
                g
            })
            .collect())
    }

    fn grant_touch(&self, grant_id: &str, at: i64) -> StoreResult<()> {
        self.conn()
            .execute(
                "UPDATE oauth_grants SET last_used_at = ?2 WHERE grant_id = ?1",
                params![grant_id, at],
            )
            .map_err(db)?;
        Ok(())
    }

    fn code_insert(&self, c: &CodeRecord) -> StoreResult<()> {
        self.conn()
            .execute(
                &format!(
                    "INSERT INTO oauth_codes ({CODE_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
                ),
                params![
                    c.hash.as_slice(),
                    c.grant_id,
                    c.client_id,
                    c.redirect_uri,
                    c.code_challenge,
                    c.expires_at,
                    c.redeemed_at
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    fn code_redeem(&self, hash: &[u8; 32], now: i64) -> Result<(CodeRecord, GrantRecord), Redeem> {
        let st = |e: rusqlite::Error| Redeem::Store(db(e));
        let mut c = self.conn();
        let tx = c.transaction().map_err(st)?;
        let Some(code) = tx
            .query_row(
                &format!("SELECT {CODE_COLS} FROM oauth_codes WHERE hash = ?1"),
                [hash.as_slice()],
                code_row,
            )
            .optional()
            .map_err(st)?
        else {
            return Err(Redeem::Unknown);
        };
        if code.redeemed_at.is_some() {
            return Err(Redeem::Reused(code.grant_id));
        }
        // Expired or not, the code is used up now.
        tx.execute(
            "UPDATE oauth_codes SET redeemed_at = ?2 WHERE hash = ?1",
            params![hash.as_slice(), now],
        )
        .map_err(st)?;
        let grant = grant_by_id(&tx, &code.grant_id).map_err(Redeem::Store)?;
        tx.commit().map_err(st)?;
        if now >= code.expires_at {
            return Err(Redeem::Expired);
        }
        let grant = grant.ok_or(Redeem::Unknown)?;
        Ok((
            CodeRecord {
                redeemed_at: Some(now),
                ..code
            },
            grant,
        ))
    }

    fn access_insert(&self, a: &AccessRecord) -> StoreResult<()> {
        self.conn()
            .execute(
                "INSERT INTO oauth_access (hash, grant_id, scopes, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![a.hash.as_slice(), a.grant_id, json_list(&a.scopes), a.expires_at],
            )
            .map_err(db)?;
        Ok(())
    }

    fn access_get(&self, hash: &[u8; 32]) -> StoreResult<Option<AccessRecord>> {
        self.conn()
            .query_row(
                "SELECT hash, grant_id, scopes, expires_at FROM oauth_access WHERE hash = ?1",
                [hash.as_slice()],
                |r| {
                    Ok(AccessRecord {
                        hash: hash32(r.get(0)?)?,
                        grant_id: r.get(1)?,
                        scopes: parse_list(&r.get::<_, String>(2)?),
                        expires_at: r.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(db)
    }

    fn refresh_insert(&self, r: &RefreshRecord) -> StoreResult<()> {
        insert_refresh(&self.conn(), r)
    }

    fn refresh_rotate(
        &self,
        hash: &[u8; 32],
        new: &RefreshRecord,
        now: i64,
        idle_secs: i64,
    ) -> Result<GrantRecord, Rotate> {
        let st = |e: rusqlite::Error| Rotate::Store(db(e));
        let mut c = self.conn();
        let tx = c.transaction().map_err(st)?;
        let Some(old) = tx
            .query_row(
                &format!("SELECT {REFRESH_COLS} FROM oauth_refresh WHERE hash = ?1"),
                [hash.as_slice()],
                refresh_row,
            )
            .optional()
            .map_err(st)?
        else {
            return Err(Rotate::Unknown);
        };
        if old.rotated_at.is_some() {
            return Err(Rotate::Reused(old.grant_id));
        }
        let grant = grant_by_id(&tx, &old.grant_id)
            .map_err(Rotate::Store)?
            .ok_or(Rotate::Unknown)?;
        if !grant.live(now) || now - old.last_used_at >= idle_secs || new.grant_id != grant.grant_id
        {
            return Err(Rotate::Expired);
        }
        tx.execute(
            "UPDATE oauth_refresh SET rotated_at = ?2 WHERE hash = ?1",
            params![hash.as_slice(), now],
        )
        .map_err(st)?;
        insert_refresh(&tx, new).map_err(Rotate::Store)?;
        tx.commit().map_err(st)?;
        Ok(grant)
    }

    fn refresh_grant(&self, hash: &[u8; 32]) -> StoreResult<Option<String>> {
        self.conn()
            .query_row(
                "SELECT grant_id FROM oauth_refresh WHERE hash = ?1",
                [hash.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)
    }

    fn export_job_insert(&self, j: &ExportJobRecord) -> StoreResult<()> {
        self.conn()
            .execute(
                &format!(
                    "INSERT INTO export_jobs ({JOB_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
                ),
                params![
                    j.job_id,
                    j.requester_user_id,
                    j.target_user_id,
                    j.state,
                    j.created_at,
                    j.expires_at,
                    j.manifest_sha256,
                    j.size.map(to_i64).transpose()?,
                    j.file_name,
                    j.anchor_seq.map(to_i64).transpose()?,
                    j.anchor_hash
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    fn export_job_get(&self, job_id: &str) -> StoreResult<Option<ExportJobRecord>> {
        self.conn()
            .query_row(
                &format!("SELECT {JOB_COLS} FROM export_jobs WHERE job_id = ?1"),
                [job_id],
                job_row,
            )
            .optional()
            .map_err(db)
    }

    fn export_job_update(&self, j: &ExportJobRecord) -> StoreResult<()> {
        self.conn()
            .execute(
                "UPDATE export_jobs SET state = ?2, expires_at = ?3, manifest_sha256 = ?4,
                 size = ?5, file_name = ?6, anchor_seq = ?7, anchor_hash = ?8 WHERE job_id = ?1",
                params![
                    j.job_id,
                    j.state,
                    j.expires_at,
                    j.manifest_sha256,
                    j.size.map(to_i64).transpose()?,
                    j.file_name,
                    j.anchor_seq.map(to_i64).transpose()?,
                    j.anchor_hash
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    fn export_jobs_running(&self) -> StoreResult<Vec<ExportJobRecord>> {
        let c = self.conn();
        let mut st = c
            .prepare(&format!(
                "SELECT {JOB_COLS} FROM export_jobs WHERE state = 'running' ORDER BY created_at"
            ))
            .map_err(db)?;
        collect(st.query_map([], job_row).map_err(db)?)
    }

    fn export_jobs_expired(&self, now: i64) -> StoreResult<Vec<ExportJobRecord>> {
        let c = self.conn();
        let mut st = c
            .prepare(&format!(
                "SELECT {JOB_COLS} FROM export_jobs WHERE expires_at <= ?1 ORDER BY created_at"
            ))
            .map_err(db)?;
        collect(st.query_map([now], job_row).map_err(db)?)
    }

    fn export_job_delete(&self, job_id: &str) -> StoreResult<bool> {
        let n = self
            .conn()
            .execute("DELETE FROM export_jobs WHERE job_id = ?1", [job_id])
            .map_err(db)?;
        Ok(n > 0)
    }
}

const CLIENT_COLS: &str = "client_id, name, redirect_uris, created_at, source_ip_hash";

fn client_row(r: &Row<'_>) -> rusqlite::Result<OAuthClientRecord> {
    Ok(OAuthClientRecord {
        client_id: r.get(0)?,
        name: r.get(1)?,
        redirect_uris: parse_list(&r.get::<_, String>(2)?),
        created_at: r.get(3)?,
        source_ip_hash: r.get(4)?,
    })
}

const CONSENT_COLS: &str = "id_hash, session_hash, user_id, client_id, redirect_uri, scopes, \
     code_challenge, state, resource, created_at, expires_at";

fn consent_row(r: &Row<'_>) -> rusqlite::Result<ConsentRequestRecord> {
    Ok(ConsentRequestRecord {
        id_hash: hash32(r.get(0)?)?,
        session_hash: hash32(r.get(1)?)?,
        user_id: r.get(2)?,
        client_id: r.get(3)?,
        redirect_uri: r.get(4)?,
        scopes: parse_list(&r.get::<_, String>(5)?),
        code_challenge: r.get(6)?,
        state: r.get(7)?,
        resource: r.get(8)?,
        created_at: r.get(9)?,
        expires_at: r.get(10)?,
    })
}

const GRANT_COLS: &str = "grant_id, user_id, client_id, scopes, resource, created_at, expires_at, \
     last_used_at, revoked_at, revoke_reason";

fn grant_row(r: &Row<'_>) -> rusqlite::Result<GrantRecord> {
    Ok(GrantRecord {
        grant_id: r.get(0)?,
        user_id: r.get(1)?,
        client_id: r.get(2)?,
        scopes: parse_list(&r.get::<_, String>(3)?),
        resource: r.get(4)?,
        created_at: r.get(5)?,
        expires_at: r.get(6)?,
        last_used_at: r.get(7)?,
        revoked_at: r.get(8)?,
        revoke_reason: r.get(9)?,
    })
}

fn grant_by_id(c: &Connection, grant_id: &str) -> StoreResult<Option<GrantRecord>> {
    c.query_row(
        &format!("SELECT {GRANT_COLS} FROM oauth_grants WHERE grant_id = ?1"),
        [grant_id],
        grant_row,
    )
    .optional()
    .map_err(db)
}

const CODE_COLS: &str =
    "hash, grant_id, client_id, redirect_uri, code_challenge, expires_at, redeemed_at";

fn code_row(r: &Row<'_>) -> rusqlite::Result<CodeRecord> {
    Ok(CodeRecord {
        hash: hash32(r.get(0)?)?,
        grant_id: r.get(1)?,
        client_id: r.get(2)?,
        redirect_uri: r.get(3)?,
        code_challenge: r.get(4)?,
        expires_at: r.get(5)?,
        redeemed_at: r.get(6)?,
    })
}

const REFRESH_COLS: &str = "hash, grant_id, created_at, last_used_at, rotated_at";

fn refresh_row(r: &Row<'_>) -> rusqlite::Result<RefreshRecord> {
    Ok(RefreshRecord {
        hash: hash32(r.get(0)?)?,
        grant_id: r.get(1)?,
        created_at: r.get(2)?,
        last_used_at: r.get(3)?,
        rotated_at: r.get(4)?,
    })
}

fn insert_refresh(c: &Connection, r: &RefreshRecord) -> StoreResult<()> {
    c.execute(
        &format!("INSERT INTO oauth_refresh ({REFRESH_COLS}) VALUES (?1, ?2, ?3, ?4, ?5)"),
        params![
            r.hash.as_slice(),
            r.grant_id,
            r.created_at,
            r.last_used_at,
            r.rotated_at
        ],
    )
    .map_err(db)?;
    Ok(())
}

const JOB_COLS: &str = "job_id, requester_user_id, target_user_id, state, created_at, expires_at, \
     manifest_sha256, size, file_name, anchor_seq, anchor_hash";

fn job_row(r: &Row<'_>) -> rusqlite::Result<ExportJobRecord> {
    Ok(ExportJobRecord {
        job_id: r.get(0)?,
        requester_user_id: r.get(1)?,
        target_user_id: r.get(2)?,
        state: r.get(3)?,
        created_at: r.get(4)?,
        expires_at: r.get(5)?,
        manifest_sha256: r.get(6)?,
        size: r.get::<_, Option<i64>>(7)?.map(to_u64),
        file_name: r.get(8)?,
        anchor_seq: r.get::<_, Option<i64>>(9)?.map(to_u64),
        anchor_hash: r.get(10)?,
    })
}
