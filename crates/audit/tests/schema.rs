//! Schema v1, pragmas, migration runner, version gate (§8.1, §8.13, V22).

use std::path::{Path, PathBuf};

use atlas_duck_audit::error::{AuditError, OpenError};
use atlas_duck_audit::schema::{
    DB_FILE, Migration, SCHEMA_HEAD, StoreVersions, create_v1, gate, open_ro, open_rw,
    read_versions, run_migrations,
};
use rusqlite::{Connection, Transaction};
use sha2::{Digest, Sha256};

fn new_db() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(DB_FILE);
    (dir, path)
}

fn pragma_i64(conn: &Connection, name: &str) -> i64 {
    conn.pragma_query_value(None, name, |r| r.get(0)).unwrap()
}

fn count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

fn columns(conn: &Connection, table: &str) -> Vec<String> {
    let mut st = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .unwrap();
    st.query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn create_v1_pragmas() {
    let (_d, path) = new_db();
    {
        let conn = Connection::open(&path).unwrap();
        create_v1(&conn).unwrap();
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        assert_eq!(pragma_i64(&conn, "page_size"), 8192);
        assert_eq!(pragma_i64(&conn, "auto_vacuum"), 2);
        assert_eq!(pragma_i64(&conn, "user_version"), 1);
    }
    let conn = open_rw(&path).unwrap();
    assert_eq!(pragma_i64(&conn, "synchronous"), 2);
    assert_eq!(pragma_i64(&conn, "secure_delete"), 1);
    assert_eq!(pragma_i64(&conn, "busy_timeout"), 5000);
    let ro = open_ro(&path).unwrap();
    assert_eq!(pragma_i64(&ro, "synchronous"), 2);
    assert_eq!(pragma_i64(&ro, "secure_delete"), 1);
}

#[test]
fn tables_exist() {
    let (_d, path) = new_db();
    let conn = Connection::open(&path).unwrap();
    create_v1(&conn).unwrap();
    let names: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(names, ["events", "keys", "meta", "prune_log", "recovery"]);
    let events = [
        "seq",
        "format_version",
        "chain_id",
        "ts_utc",
        "epoch",
        "request_id",
        "event_type",
        "op_id",
        "op_class",
        "instance_id",
        "target",
        "agent_name",
        "agent_name_source",
        "client_kind",
        "connection_id",
        "peer_pid",
        "peer_exe",
        "peer_origin_exe",
        "os_user",
        "atlassian_user",
        "atlassian_user_key",
        "decision",
        "flags",
        "payload_len",
        "payload_sha256",
        "key_id",
        "nonce",
        "payload_ct",
        "prev_hash",
        "record_hash",
    ];
    assert_eq!(columns(&conn, "events"), events);
    assert_eq!(
        columns(&conn, "prune_log"),
        [
            "prune_seq",
            "range_start",
            "cutoff_epoch",
            "last_pruned_record_hash",
            "first_retained_seq",
            "prev_row_hash",
            "row_hash"
        ]
    );
    assert_eq!(
        columns(&conn, "keys"),
        [
            "key_id",
            "month",
            "wrapped_dek",
            "created_at",
            "destroyed_at"
        ]
    );
    assert_eq!(columns(&conn, "recovery"), ["id", "blob", "created_at"]);
    assert_eq!(columns(&conn, "meta"), ["key", "value"]);
}

fn create_t2(tx: &Transaction) -> rusqlite::Result<()> {
    tx.execute_batch("CREATE TABLE t2(x)")
}
fn create_t2_then_fail(tx: &Transaction) -> rusqlite::Result<()> {
    tx.execute_batch("CREATE TABLE t2(x)")?;
    Err(rusqlite::Error::InvalidQuery)
}
fn noop(_: &Transaction) -> rusqlite::Result<()> {
    Ok(())
}
fn fail(_: &Transaction) -> rusqlite::Result<()> {
    Err(rusqlite::Error::InvalidQuery)
}

fn table_exists(conn: &Connection, name: &str) -> bool {
    let n: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name=?1",
            [name],
            |r| r.get(0),
        )
        .unwrap();
    n == 1
}

fn insert_scratch(tx: &Transaction, x: i64) -> Result<(), AuditError> {
    tx.execute("INSERT INTO scratch(x) VALUES (?1)", [x])
        .map(|_| ())
        .map_err(|e| AuditError::Io(e.to_string()))
}

#[test]
fn v22_user_version_rolls_back() {
    let (_d, path) = new_db();
    {
        let c = Connection::open(&path).unwrap();
        create_v1(&c).unwrap();
        c.execute_batch("CREATE TABLE scratch(x)").unwrap();
    }
    let mut conn = open_rw(&path).unwrap();

    // A failing 1->2 rolls back the table and user_version.
    let failing = [Migration {
        from: 1,
        to: 2,
        apply: create_t2_then_fail,
    }];
    let err = run_migrations(&mut conn, &failing, &mut |_, _, _| Ok(())).unwrap_err();
    assert!(
        matches!(err, OpenError::MigrationFailed { from: 1, to: 2, .. }),
        "{err:?}"
    );
    assert_eq!(pragma_i64(&conn, "user_version"), 1);
    assert!(!table_exists(&conn, "t2"));

    // A succeeding 1->2: on_step runs once, inside the transaction.
    let ok = [Migration {
        from: 1,
        to: 2,
        apply: create_t2,
    }];
    let mut calls = Vec::new();
    let span = run_migrations(&mut conn, &ok, &mut |tx, f, t| {
        calls.push((f, t));
        insert_scratch(tx, 1)
    })
    .unwrap();
    assert_eq!(span, Some((1, 2)));
    assert_eq!(calls, [(1, 2)]);
    assert_eq!(pragma_i64(&conn, "user_version"), 2);
    assert!(table_exists(&conn, "t2"));
    assert_eq!(count(&conn, "scratch"), 1);

    // 2->3 succeeds, 3->4 fails: the whole run rolls back, including on_step's rows.
    let two_steps = [
        Migration {
            from: 2,
            to: 3,
            apply: noop,
        },
        Migration {
            from: 3,
            to: 4,
            apply: fail,
        },
    ];
    let err =
        run_migrations(&mut conn, &two_steps, &mut |tx, _, _| insert_scratch(tx, 2)).unwrap_err();
    assert!(
        matches!(err, OpenError::MigrationFailed { from: 3, to: 4, .. }),
        "{err:?}"
    );
    assert_eq!(pragma_i64(&conn, "user_version"), 2);
    assert_eq!(count(&conn, "scratch"), 1);

    // An on_step error also rolls the step back.
    let one = [Migration {
        from: 2,
        to: 3,
        apply: noop,
    }];
    let err = run_migrations(&mut conn, &one, &mut |_, _, _| Err(AuditError::Closed)).unwrap_err();
    assert!(
        matches!(err, OpenError::MigrationFailed { from: 2, to: 3, .. }),
        "{err:?}"
    );
    assert_eq!(pragma_i64(&conn, "user_version"), 2);

    // Nothing pending is not an error.
    assert_eq!(
        run_migrations(&mut conn, &[], &mut |_, _, _| Ok(())).unwrap(),
        None
    );
}

fn snapshot(path: &Path) -> Option<(Vec<u8>, std::time::SystemTime)> {
    let bytes = std::fs::read(path).ok()?;
    let mtime = std::fs::metadata(path).ok()?.modified().ok()?;
    Some((Sha256::digest(&bytes).to_vec(), mtime))
}

#[test]
fn read_versions_writes_nothing() {
    let (d, path) = new_db();
    {
        let c = Connection::open(&path).unwrap();
        create_v1(&c).unwrap();
        c.execute(
            "INSERT INTO events(seq, format_version, chain_id, ts_utc, event_type, flags, \
             payload_len, payload_sha256, key_id, nonce, payload_ct, prev_hash, record_hash) \
             VALUES (1, 1, 'c', 't', 'GENESIS', 0, 0, x'00', 1, x'00', x'00', x'00', x'00')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO recovery(id, blob, created_at) VALUES (1, x'0100', 't')",
            [],
        )
        .unwrap();
    }
    let wal = d.path().join(format!("{DB_FILE}-wal"));
    let (db_before, wal_before) = (snapshot(&path), snapshot(&wal));
    assert!(db_before.is_some());

    let v = read_versions(&path).unwrap();
    assert_eq!(
        v,
        StoreVersions {
            user_version: 1,
            head_format_version: Some(1),
            recovery_layout: Some(1),
            written_by: Some(atlas_duck_ipc::build_info::APP_VERSION.to_owned()),
        }
    );

    // `-shm` is SQLite's shared-memory index and may change; it is excluded.
    assert_eq!(snapshot(&path), db_before);
    if wal_before.is_some() {
        assert_eq!(snapshot(&wal), wal_before);
    }
}

fn versions(user_version: u32, fmt: u64, layout: u8) -> StoreVersions {
    StoreVersions {
        user_version,
        head_format_version: Some(fmt),
        recovery_layout: Some(layout),
        written_by: None,
    }
}

#[test]
fn gate_refuses_newer() {
    assert_eq!(
        gate(&versions(SCHEMA_HEAD + 1, 1, 1)),
        Err("user_version 2".to_owned())
    );
    assert_eq!(gate(&versions(1, 2, 1)), Err("format_version 2".to_owned()));
    assert_eq!(
        gate(&versions(1, 1, 2)),
        Err("recovery layout 2".to_owned())
    );
    assert_eq!(gate(&versions(1, 1, 1)), Ok(()));
}

fn listing(dir: &Path) -> Vec<(String, Vec<u8>, std::time::SystemTime)> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            let (h, m) = snapshot(&p).unwrap();
            (name, h, m)
        })
        .collect();
    v.sort();
    v
}

fn seed(c: &Connection) {
    create_v1(c).unwrap();
    c.execute(
        "INSERT INTO recovery(id, blob, created_at) VALUES (1, x'0100', 't')",
        [],
    )
    .unwrap();
}

#[test]
fn read_versions_leaves_directory_untouched_when_clean() {
    let (d, path) = new_db();
    {
        let c = Connection::open(&path).unwrap();
        seed(&c);
    }
    let before = listing(d.path());
    assert!(before.iter().all(|(n, _, _)| n == DB_FILE), "{before:?}");
    read_versions(&path).unwrap();
    assert_eq!(listing(d.path()), before);
}

#[test]
fn read_versions_leaves_live_wal_untouched() {
    let (d, path) = new_db();
    let c = Connection::open(&path).unwrap();
    c.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    seed(&c);
    c.execute("INSERT INTO meta(key, value) VALUES ('x', 'y')", [])
        .unwrap();
    let wal = d.path().join(format!("{DB_FILE}-wal"));
    let (db_before, wal_before) = (snapshot(&path), snapshot(&wal));
    assert!(wal_before.is_some(), "writer should hold a live -wal");
    let v = read_versions(&path).unwrap();
    assert_eq!(v.recovery_layout, Some(1), "reader must see WAL content");
    assert_eq!(snapshot(&path), db_before);
    assert_eq!(snapshot(&wal), wal_before);
    drop(c);
}

#[test]
fn gate_open_connection_sees_newer_version_only_in_wal() {
    let (d, path) = new_db();
    let w = Connection::open(&path).unwrap();
    w.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    seed(&w);
    w.pragma_update(None, "user_version", 2).unwrap();
    let wal = d.path().join(format!("{DB_FILE}-wal"));
    assert!(
        wal.metadata().unwrap().len() > 0,
        "version must sit in the WAL"
    );

    let conn = open_rw(&path).unwrap();
    assert!(matches!(
        atlas_duck_audit::schema::gate_open_connection(&conn),
        Err(OpenError::NewerStore(f)) if f == "user_version 2"
    ));
    // The read-only peek also sees it because a -wal exists.
    assert_eq!(read_versions(&path).unwrap().user_version, 2);
    drop((conn, w));
}

#[test]
fn gate_ok_for_current_store() {
    let (_d, path) = new_db();
    {
        let c = Connection::open(&path).unwrap();
        seed(&c);
    }
    let conn = open_rw(&path).unwrap();
    atlas_duck_audit::schema::gate_open_connection(&conn).unwrap();
}

#[test]
fn gate_accepts_zero_and_absent() {
    let v = StoreVersions {
        user_version: 0,
        head_format_version: None,
        recovery_layout: None,
        written_by: None,
    };
    assert_eq!(gate(&v), Ok(()));
}

#[test]
fn read_versions_missing_path_creates_nothing() {
    let (d, path) = new_db();
    assert!(read_versions(&path).is_err());
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
}

#[test]
fn read_versions_handles_awkward_paths() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("a b#c%d&e");
    std::fs::create_dir(&sub).unwrap();
    let path = sub.join(DB_FILE);
    {
        let c = Connection::open(&path).unwrap();
        seed(&c);
    }
    assert_eq!(read_versions(&path).unwrap().user_version, 1);
}

#[test]
fn open_rw_keeps_wal_mode() {
    let (_d, path) = new_db();
    {
        let c = Connection::open(&path).unwrap();
        seed(&c);
    }
    let conn = open_rw(&path).unwrap();
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
}

#[test]
fn create_v1_refuses_existing_database() {
    let (_d, path) = new_db();
    let c = Connection::open(&path).unwrap();
    create_v1(&c).unwrap();
    assert!(create_v1(&c).is_err());
    let (_d2, path2) = new_db();
    let c2 = Connection::open(&path2).unwrap();
    c2.execute_batch("CREATE TABLE foreign_t(x)").unwrap();
    assert!(create_v1(&c2).is_err());
}

fn mig(from: u32, to: u32) -> Migration {
    Migration {
        from,
        to,
        apply: noop,
    }
}

#[test]
fn run_migrations_refuses_bad_tables() {
    let (_d, path) = new_db();
    let mut conn = Connection::open(&path).unwrap();
    seed(&conn);
    // Non-increasing step.
    for table in [[mig(1, 1)], [mig(1, 0)]] {
        let err = run_migrations(&mut conn, &table, &mut |_, _, _| Ok(())).unwrap_err();
        assert!(matches!(err, OpenError::MigrationFailed { .. }), "{err:?}");
    }
    // Gap: nothing starts at 1 but a step starts at 3.
    let err = run_migrations(&mut conn, &[mig(3, 4)], &mut |_, _, _| Ok(())).unwrap_err();
    assert!(
        matches!(err, OpenError::MigrationFailed { from: 1, to: 3, .. }),
        "{err:?}"
    );
    // Gap after a valid step: nothing is applied.
    let err =
        run_migrations(&mut conn, &[mig(1, 2), mig(3, 4)], &mut |_, _, _| Ok(())).unwrap_err();
    assert!(
        matches!(err, OpenError::MigrationFailed { from: 2, to: 3, .. }),
        "{err:?}"
    );
    assert_eq!(pragma_i64(&conn, "user_version"), 1);
    // Contiguous chain applies end to end in one run.
    let span = run_migrations(&mut conn, &[mig(2, 3), mig(1, 2)], &mut |_, _, _| Ok(())).unwrap();
    assert_eq!(span, Some((1, 3)));
}
