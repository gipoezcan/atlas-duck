//! The `ServerStore` contract, run against the SQLite and the in-memory store, plus the
//! SQLite-only checks (triggers, reopen, schema version).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::memory::MemoryStore;
use super::sqlite::SqliteStore;
use super::*;

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn stores() -> Vec<(&'static str, Box<dyn ServerStore>)> {
    vec![
        ("sqlite", Box::new(SqliteStore::open_in_memory().unwrap())),
        ("memory", Box::new(MemoryStore::new())),
    ]
}

fn user(id: &str, name: &str) -> UserRecord {
    UserRecord {
        user_id: id.into(),
        username: name.into(),
        display_name: Some(format!("{name} display")),
        roles: vec!["user".into()],
        data_key_wrapped: format!("{{\"v\":1,\"of\":\"{name}\"}}"),
        created_at: 100,
    }
}

fn sealed(tag: u8) -> Sealed {
    Sealed {
        nonce: vec![tag; 12],
        ct: vec![tag, tag, tag],
    }
}

fn with_users(s: &dyn ServerStore) {
    s.upsert_user(&user(A, "alice")).unwrap();
    s.upsert_user(&user(B, "bob")).unwrap();
}

fn pat(uid: &str, alias: &str, tag: u8) -> PatRecord {
    PatRecord {
        user_id: uid.into(),
        alias: alias.into(),
        sealed: sealed(tag),
        identity_json: format!("{{\"user\":\"{uid}\"}}"),
        checked_at: 5,
    }
}

fn session(tag: u8, uid: &str) -> SessionRecord {
    SessionRecord {
        id_hash: [tag; 32],
        user_id: uid.into(),
        roles: vec!["user".into(), "admin".into()],
        csrf_token: format!("csrf-{tag}"),
        created_at: 10,
        last_seen: 10,
        absolute_expiry: 1000,
        idle_expiry: 500,
    }
}

fn key(id: &str, uid: &str, prefix: &str) -> ApiKeyRecord {
    ApiKeyRecord {
        id: id.into(),
        user_id: uid.into(),
        name: format!("key {id}"),
        prefix: prefix.into(),
        hash: "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA".into(),
        scopes: vec!["read".into()],
        created_at: 10,
        expires_at: 1000,
        last_used_at: None,
        revoked_at: None,
    }
}

fn head(uid: &str, chain: &str, seq: u64) -> AnchorHead {
    AnchorHead {
        user_id: uid.into(),
        chain_id: chain.into(),
        head_seq: seq,
        record_hash: [seq as u8; 32],
    }
}

/// A stand-in row hash: seq and prev folded in (the real one is Task 15's).
fn fake_hash(seq: u64, prev: &[u8; 32]) -> [u8; 32] {
    let mut h = *prev;
    h[0] = h[0].wrapping_add(seq as u8).wrapping_add(1);
    h
}

#[test]
fn users_crud() {
    for (name, s) in stores() {
        let s = s.as_ref();
        with_users(s);
        assert_eq!(s.user(A).unwrap(), Some(user(A, "alice")), "{name}");
        assert_eq!(
            s.user_by_name("bob").unwrap(),
            Some(user(B, "bob")),
            "{name}"
        );
        assert_eq!(s.user("missing").unwrap(), None, "{name}");
        // Upsert updates roles, keeps username, created_at and (M13 T7) the wrapped key: a login
        // racing a rotation must never put the old wrapping back.
        let mut changed = user(A, "alice");
        changed.roles = vec!["user".into(), "auditor".into()];
        changed.data_key_wrapped = "rewrapped".into();
        changed.created_at = 999;
        s.upsert_user(&changed).unwrap();
        let got = s.user(A).unwrap().unwrap();
        assert_eq!(got.roles, changed.roles, "{name}");
        assert_eq!(
            got.data_key_wrapped,
            user(A, "alice").data_key_wrapped,
            "{name}"
        );
        assert_eq!(got.created_at, 100, "{name}");
        // Only a compare-and-set replaces it.
        let old = got.data_key_wrapped;
        assert!(!s.user_set_wrapped(A, "stale", "x").unwrap(), "{name}");
        assert!(s.user_set_wrapped(A, &old, "rewrapped").unwrap(), "{name}");
        assert_eq!(
            s.user(A).unwrap().unwrap().data_key_wrapped,
            "rewrapped",
            "{name}"
        );
        assert!(!s.user_set_wrapped("missing", "x", "y").unwrap(), "{name}");
    }
}

#[test]
fn keystore_crud_is_per_user() {
    for (name, s) in stores() {
        let s = s.as_ref();
        with_users(s);
        s.ks_set(A, "kek", &sealed(1)).unwrap();
        s.ks_set(B, "kek", &sealed(2)).unwrap();
        assert_eq!(s.ks_get(A, "kek").unwrap(), Some(sealed(1)), "{name}");
        assert_eq!(s.ks_get(B, "kek").unwrap(), Some(sealed(2)), "{name}");
        s.ks_set(A, "kek", &sealed(3)).unwrap();
        assert_eq!(s.ks_get(A, "kek").unwrap(), Some(sealed(3)), "{name}");
        assert!(s.ks_delete(A, "kek").unwrap(), "{name}");
        assert!(!s.ks_delete(A, "kek").unwrap(), "{name}");
        assert_eq!(s.ks_get(A, "kek").unwrap(), None, "{name}");
        assert_eq!(s.ks_get(B, "kek").unwrap(), Some(sealed(2)), "{name}");
    }
}

#[test]
fn pats_crud_is_per_user() {
    for (name, s) in stores() {
        let s = s.as_ref();
        with_users(s);
        s.pat_put(&pat(A, "work", 1)).unwrap();
        s.pat_put(&pat(A, "wiki", 2)).unwrap();
        s.pat_put(&pat(B, "work", 3)).unwrap();
        assert_eq!(
            s.pat_get(A, "work").unwrap(),
            Some(pat(A, "work", 1)),
            "{name}"
        );
        assert_eq!(s.pat_get(B, "wiki").unwrap(), None, "{name}");
        let a: Vec<String> = s
            .pat_list(A)
            .unwrap()
            .into_iter()
            .map(|p| p.alias)
            .collect();
        assert_eq!(a, ["wiki", "work"], "{name}");
        assert!(
            s.pat_list(B).unwrap().iter().all(|p| p.user_id == B),
            "{name}"
        );
        s.pat_put(&pat(A, "work", 9)).unwrap();
        assert_eq!(
            s.pat_get(A, "work").unwrap().unwrap().sealed,
            sealed(9),
            "{name}"
        );
        let owners: Vec<String> = s
            .pats_for_alias("work")
            .unwrap()
            .into_iter()
            .map(|p| p.user_id)
            .collect();
        assert_eq!(owners, [A, B], "{name}");
        assert!(s.pat_delete(A, "work").unwrap(), "{name}");
        assert!(!s.pat_delete(A, "work").unwrap(), "{name}");
        assert!(s.pat_get(B, "work").unwrap().is_some(), "{name}");
    }
}

#[test]
fn sessions_crud_and_expiry() {
    for (name, s) in stores() {
        let s = s.as_ref();
        with_users(s);
        s.session_put(&session(1, A)).unwrap();
        s.session_put(&session(2, B)).unwrap();
        assert_eq!(
            s.session_get(&[1; 32]).unwrap(),
            Some(session(1, A)),
            "{name}"
        );
        s.session_touch(&[1; 32], 50, 600).unwrap();
        let t = s.session_get(&[1; 32]).unwrap().unwrap();
        assert_eq!((t.last_seen, t.idle_expiry), (50, 600), "{name}");
        // Session 2 is idle-expired at 500; session 1 now lives to 600.
        assert_eq!(s.session_delete_expired(500).unwrap(), 1, "{name}");
        assert_eq!(s.session_get(&[2; 32]).unwrap(), None, "{name}");
        assert_eq!(s.sessions_all().unwrap().len(), 1, "{name}");
        assert!(s.session_delete(&[1; 32]).unwrap(), "{name}");
        assert!(!s.session_delete(&[1; 32]).unwrap(), "{name}");
        assert!(s.sessions_all().unwrap().is_empty(), "{name}");
    }
}

#[test]
fn api_keys_crud_is_per_user() {
    for (name, s) in stores() {
        let s = s.as_ref();
        with_users(s);
        s.api_key_insert(&key("k1", A, "aaaa1111")).unwrap();
        s.api_key_insert(&key("k2", A, "aaaa2222")).unwrap();
        s.api_key_insert(&key("k3", B, "bbbb3333")).unwrap();
        assert_eq!(
            s.api_key_insert(&key("k4", B, "aaaa1111")),
            Err(StoreError::Duplicate),
            "{name}"
        );
        assert_eq!(
            s.api_key_by_prefix("bbbb3333").unwrap().unwrap().user_id,
            B,
            "{name}"
        );
        assert_eq!(s.api_key_list(A).unwrap().len(), 2, "{name}");
        assert_eq!(s.api_key_count_active(A, 50).unwrap(), 2, "{name}");
        assert_eq!(
            s.api_key_count_active(A, 1000).unwrap(),
            0,
            "expired at 1000: {name}"
        );
        // B cannot revoke or touch A's key.
        assert!(!s.api_key_revoke(B, "k1", 60).unwrap(), "{name}");
        s.api_key_touch_last_used(B, "k1", 61).unwrap();
        assert_eq!(
            s.api_key_by_prefix("aaaa1111")
                .unwrap()
                .unwrap()
                .last_used_at,
            None,
            "{name}"
        );
        assert!(s.api_key_revoke(A, "k1", 60).unwrap(), "{name}");
        assert!(!s.api_key_revoke(A, "k1", 70).unwrap(), "{name}");
        s.api_key_touch_last_used(A, "k2", 62).unwrap();
        let k1 = s.api_key_by_prefix("aaaa1111").unwrap().unwrap();
        let k2 = s.api_key_by_prefix("aaaa2222").unwrap().unwrap();
        assert_eq!(k1.revoked_at, Some(60), "{name}");
        assert_eq!(k2.last_used_at, Some(62), "{name}");
        assert_eq!(s.api_key_count_active(A, 50).unwrap(), 1, "{name}");
        assert_eq!(s.api_key_count_active(B, 50).unwrap(), 1, "{name}");
    }
}

#[test]
fn instances_crud() {
    for (name, s) in stores() {
        let s = s.as_ref();
        let i = InstanceRecord {
            alias: "work".into(),
            product: "jira".into(),
            base_url: "https://jira.example.test".into(),
            proxy: None,
            ca_ref: Some("org".into()),
            is_default: true,
        };
        s.instance_put(&i).unwrap();
        assert_eq!(s.instance_put(&i), Err(StoreError::Duplicate), "{name}");
        assert_eq!(s.instance_list().unwrap(), vec![i.clone()], "{name}");
        assert!(s.instance_delete("work").unwrap(), "{name}");
        assert!(!s.instance_delete("work").unwrap(), "{name}");
        assert!(s.instance_list().unwrap().is_empty(), "{name}");
    }
}

#[test]
fn anchor_append_links_rows_and_heads() {
    for (name, s) in stores() {
        let s = s.as_ref();
        assert_eq!(s.anchor_last().unwrap(), None, "{name}");
        let r1 = s
            .anchor_append("ANCHOR_GENESIS", "t1", b"{}", &[], &fake_hash)
            .unwrap();
        assert_eq!((r1.seq, r1.prev_hash), (1, [0; 32]), "{name}");
        let heads = [head(A, "ca", 7), head(B, "cb", 3)];
        let r2 = s
            .anchor_append("HEADS", "t2", b"{\"leaves\":[]}", &heads, &fake_hash)
            .unwrap();
        assert_eq!((r2.seq, r2.prev_hash), (2, r1.hash), "{name}");
        assert_eq!(r2.hash, fake_hash(2, &r1.hash), "{name}");
        s.anchor_append("HEADS", "t3", b"{}", &[head(A, "ca", 9)], &fake_hash)
            .unwrap();
        assert_eq!(s.anchor_all().unwrap().len(), 3, "{name}");
        assert_eq!(s.anchor_last().unwrap().unwrap().seq, 3, "{name}");
        assert_eq!(s.anchor_heads_for(2).unwrap(), heads.to_vec(), "{name}");
        assert_eq!(
            s.anchor_heads_for_chain("ca", 8).unwrap(),
            vec![(2, head(A, "ca", 7))],
            "{name}"
        );
        assert_eq!(
            s.anchor_heads_for_chain("ca", 9).unwrap().len(),
            2,
            "{name}"
        );
    }
}

/// Every per-user getter answers only the asked user's rows.
#[test]
fn per_user_methods_never_return_another_users_rows() {
    for (name, s) in stores() {
        let s = s.as_ref();
        with_users(s);
        s.ks_set(A, "e", &sealed(1)).unwrap();
        s.pat_put(&pat(A, "work", 1)).unwrap();
        s.api_key_insert(&key("k1", A, "aaaa1111")).unwrap();
        s.session_put(&session(1, A)).unwrap();
        assert_eq!(s.ks_get(B, "e").unwrap(), None, "{name}");
        assert_eq!(s.pat_get(B, "work").unwrap(), None, "{name}");
        assert!(s.pat_list(B).unwrap().is_empty(), "{name}");
        assert!(s.api_key_list(B).unwrap().is_empty(), "{name}");
        assert_eq!(s.api_key_count_active(B, 0).unwrap(), 0, "{name}");
        assert!(!s.ks_delete(B, "e").unwrap(), "{name}");
        assert!(!s.pat_delete(B, "work").unwrap(), "{name}");
        assert!(s.ks_get(A, "e").unwrap().is_some(), "{name}");
        assert!(s.pat_get(A, "work").unwrap().is_some(), "{name}");
    }
}

// ---- SQLite only --------------------------------------------------------------------------

#[test]
fn anchor_tables_are_append_only() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.anchor_append("HEADS", "t", b"{}", &[head(A, "ca", 1)], &fake_hash)
        .unwrap();
    let c = s.raw();
    for sql in [
        "UPDATE anchor_chain SET kind = 'X'",
        "DELETE FROM anchor_chain",
        "UPDATE anchor_heads SET head_seq = 99",
        "DELETE FROM anchor_heads",
    ] {
        let e = c.execute(sql, []).unwrap_err().to_string();
        assert!(e.contains("append-only"), "{sql}: {e}");
    }
}

#[test]
fn reopen_keeps_sessions_and_newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.db");
    {
        let s = SqliteStore::open(&path).unwrap();
        s.upsert_user(&user(A, "alice")).unwrap();
        s.session_put(&session(7, A)).unwrap();
    }
    let s = SqliteStore::open(&path).unwrap();
    assert_eq!(s.session_get(&[7; 32]).unwrap(), Some(session(7, A)));
    s.raw().execute_batch("PRAGMA user_version = 3;").unwrap();
    drop(s);
    assert!(matches!(
        SqliteStore::open(&path),
        Err(StoreError::Newer(3))
    ));
}

#[test]
fn user_state_deactivation_sessions_and_key_revocation() {
    for (name, s) in stores() {
        let s = s.as_ref();
        with_users(s);
        assert_eq!(
            s.user_state(A).unwrap(),
            Some(UserState::default()),
            "{name}"
        );
        assert_eq!(s.user_state("nobody").unwrap(), None, "{name}");
        s.user_set_last_login(A, 50).unwrap();
        assert!(s.user_deactivate(A, 60, "admin", 70).unwrap(), "{name}");
        assert!(
            !s.user_deactivate(A, 99, "offboarding", 99).unwrap(),
            "{name}"
        );
        let want = UserState {
            deactivated_at: Some(60),
            deactivated_by: Some("admin".into()),
            last_login_at: Some(50),
            retention_until: Some(70),
            chain_deleted_at: None,
        };
        assert_eq!(s.user_state(A).unwrap(), Some(want.clone()), "{name}");
        // The login's upsert never clears the lifecycle columns.
        s.upsert_user(&user(A, "alice")).unwrap();
        assert_eq!(s.user_state(A).unwrap(), Some(want.clone()), "{name}");
        let all = s.users_all().unwrap();
        let names: Vec<&str> = all.iter().map(|(u, _)| u.username.as_str()).collect();
        assert_eq!(names, ["alice", "bob"], "{name}");
        assert_eq!(all[0].1, want, "{name}");
        assert_eq!(all[1].1, UserState::default(), "{name}");

        s.session_put(&session(1, A)).unwrap();
        s.session_put(&session(2, A)).unwrap();
        s.session_put(&session(3, B)).unwrap();
        assert_eq!(s.sessions_delete_for_user(A).unwrap(), 2, "{name}");
        let left: Vec<String> = s
            .sessions_all()
            .unwrap()
            .into_iter()
            .map(|r| r.user_id)
            .collect();
        assert_eq!(left, [B.to_owned()], "{name}");

        s.api_key_insert(&key("k1", A, "aaaa0001")).unwrap();
        s.api_key_insert(&key("k2", A, "aaaa0002")).unwrap();
        s.api_key_insert(&key("k3", B, "bbbb0003")).unwrap();
        assert!(s.api_key_revoke(A, "k2", 20).unwrap());
        let revoked = s.api_keys_revoke_all(A, 30).unwrap();
        let ids: Vec<&str> = revoked.iter().map(|k| k.id.as_str()).collect();
        assert_eq!(ids, ["k1"], "{name}: only the unrevoked key");
        assert_eq!(revoked[0].revoked_at, Some(30), "{name}");
        let a_keys = s.api_key_list(A).unwrap();
        assert_eq!(
            a_keys.iter().map(|k| k.revoked_at).collect::<Vec<_>>(),
            [Some(30), Some(20)],
            "{name}: k2 keeps its first revocation"
        );
        assert_eq!(s.api_key_list(B).unwrap()[0].revoked_at, None, "{name}");
        assert!(s.api_keys_revoke_all(A, 40).unwrap().is_empty(), "{name}");
    }
}

/// A v1 file as M12 wrote it: the v1 schema, `user_version = 1`, a user and a session.
fn v1_file(path: &std::path::Path) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch(super::schema::V1).unwrap();
    c.execute_batch("PRAGMA user_version = 1;").unwrap();
    c.execute(
        "INSERT INTO users (user_id, username, display_name, roles, data_key_wrapped, created_at)
         VALUES (?1, 'alice', 'Alice', '[\"user\"]', '{}', 100)",
        [A],
    )
    .unwrap();
    c.execute(
        "INSERT INTO sessions (id_hash, user_id, roles, csrf_token, created_at, last_seen,
             absolute_expiry, idle_expiry) VALUES (?1, ?2, '[\"user\"]', 'csrf-7', 10, 10, 1000, 500)",
        rusqlite::params![[7u8; 32].as_slice(), A],
    )
    .unwrap();
}

fn columns(c: &rusqlite::Connection, table: &str) -> Vec<String> {
    let mut st = c
        .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
        .unwrap();
    st.query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<String>>>()
        .unwrap()
}

#[test]
fn migrate_v1_to_v2_keeps_rows_and_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.db");
    v1_file(&path);
    let s = SqliteStore::open(&path).unwrap();
    let v: u32 = s
        .raw()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, super::schema::SCHEMA_VERSION);
    assert_eq!(v, 2);
    let u = s.user(A).unwrap().unwrap();
    assert_eq!((u.username.as_str(), u.created_at), ("alice", 100));
    assert_eq!(s.user_state(A).unwrap(), Some(UserState::default()));
    assert_eq!(s.sessions_all().unwrap().len(), 1);
    assert_eq!(
        s.session_get(&[7; 32]).unwrap().unwrap().csrf_token,
        "csrf-7"
    );
    assert!(columns(&s.raw(), "scheduler_state").contains(&"last_success_at".to_owned()));
    // Reopening a v2 file migrates nothing and keeps everything.
    drop(s);
    let s = SqliteStore::open(&path).unwrap();
    assert_eq!(s.sessions_all().unwrap().len(), 1);
    // A fresh file climbs the same path.
    let fresh = SqliteStore::open(&dir.path().join("fresh.db")).unwrap();
    assert_eq!(
        columns(&fresh.raw(), "users"),
        columns(&s.raw(), "users"),
        "fresh and migrated files have one schema"
    );
}

#[test]
fn failed_migration_leaves_v1() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.db");
    v1_file(&path);
    // A table the v2 step creates already exists, so the step fails part-way (after the ALTERs).
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE scheduler_state (x INTEGER);")
        .unwrap();
    assert!(matches!(
        SqliteStore::open(&path),
        Err(StoreError::Migration { from: 1, to: 2 })
    ));
    let c = rusqlite::Connection::open(&path).unwrap();
    let v: u32 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 1);
    assert!(
        !columns(&c, "users").contains(&"deactivated_at".to_owned()),
        "the ALTERs were rolled back"
    );
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
}

/// ADR 0004: on the NFS data volume `server.db` runs the rollback journal, `synchronous=FULL`
/// and an exclusive lock that keeps every other connection out; a WAL file is switched over.
#[test]
fn sqlite_delete_mode_is_full_and_exclusive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.db");
    drop(SqliteStore::open(&path).unwrap()); // a WAL file from before
    let s = SqliteStore::open_with(&path, atlas_duck_audit::JournalMode::Delete).unwrap();
    s.upsert_user(&user(A, "alice")).unwrap();
    {
        let c = s.raw();
        let q = |p: &str| -> String {
            c.query_row(&format!("PRAGMA {p}"), [], |r| {
                r.get::<_, rusqlite::types::Value>(0)
            })
            .map(|v| match v {
                rusqlite::types::Value::Text(t) => t,
                rusqlite::types::Value::Integer(i) => i.to_string(),
                other => format!("{other:?}"),
            })
            .unwrap()
        };
        assert_eq!(q("journal_mode"), "delete");
        assert_eq!(q("synchronous"), "2");
        assert_eq!(q("locking_mode"), "exclusive");
    }
    assert!(!dir.path().join("server.db-wal").exists());
    let other = rusqlite::Connection::open(&path).unwrap();
    other.busy_timeout(std::time::Duration::ZERO).unwrap();
    assert!(
        other
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))
            .is_err(),
        "a second connection is locked out"
    );
    drop(other);
    drop(s);
    // Closed: the lock is gone, and the file reopens in the same mode.
    let s = SqliteStore::open_with(&path, atlas_duck_audit::JournalMode::Delete).unwrap();
    assert_eq!(s.users_all().unwrap().len(), 1);
}

#[test]
fn sqlite_file_uses_wal_and_foreign_keys() {
    let dir = tempfile::tempdir().unwrap();
    let s = SqliteStore::open(&dir.path().join("server.db")).unwrap();
    let c = s.raw();
    let mode: String = c
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    let fk: i64 = c
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!((mode.as_str(), fk), ("wal", 1));
    drop(c);
    // A PAT of a user that does not exist is refused.
    assert!(matches!(
        s.pat_put(&pat("nobody", "work", 1)),
        Err(StoreError::Db(_))
    ));
}
