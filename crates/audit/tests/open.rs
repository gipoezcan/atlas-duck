//! `open()` (§8.7 steps 1–4, §8.13, §8.6): first run detection, the version gate, the keychain
//! cases, the `install_id` cross-check, migrations before the startup `VERIFY` before any
//! anchor write, and the committed schema-v1 fixture (U-18 start half, U-19, U-20, U-21 store
//! half).

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use atlas_duck_audit::anchors::HeadAnchor;
use atlas_duck_audit::crypto::Kek;
use atlas_duck_audit::error::OpenError;
use atlas_duck_audit::keystore::{
    EntryName, KeyStore, KeyStoreError, KeyringLocality, service_name,
};
use atlas_duck_audit::open::{NEW_DB_FILE, RESTORING_DB_FILE};
use atlas_duck_audit::schema::{DB_FILE, Migration};
use atlas_duck_audit::testing::{FaultPoint, Faults, KeyOp, KeyOpKind, MemKeyStore, MemKeyring};
use atlas_duck_audit::types::{EventFlags, EventType};
use atlas_duck_audit::{
    FindingKind, LockedReason, OpenConfig, RecoveryOffer, StartupOutcome, Store, VerifyOutcome,
    create_new_store, keychain_retry_schedule, open, read_store_install_id,
};
use atlas_duck_ipc::build_info::APP_VERSION;
use common::*;
use rusqlite::Transaction;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------------------
// helpers

fn migrate_v2(tx: &Transaction) -> rusqlite::Result<()> {
    tx.execute_batch("CREATE TABLE v2_extra (id INTEGER PRIMARY KEY, note TEXT)")
}

fn migrate_fails(tx: &Transaction) -> rusqlite::Result<()> {
    tx.execute_batch("CREATE TABLE v2_extra (id INTEGER PRIMARY KEY)")?;
    tx.execute_batch("THIS IS NOT SQL")
}

fn with_migration(cfg: &mut OpenConfig, apply: fn(&Transaction) -> rusqlite::Result<()>) {
    cfg.hooks.extra_migrations = vec![Migration {
        from: 1,
        to: 2,
        apply,
    }];
}

fn open_cfg(f: &Fixture, cfg: OpenConfig) -> StartupOutcome {
    open(&f.data, &f.lock, cfg).expect("open")
}

/// No start in this file completes a restore, so none deletes a token.
fn ready(o: StartupOutcome) -> (Store, VerifyOutcome) {
    match o {
        StartupOutcome::Ready {
            store,
            verify,
            pats_deleted,
        } => {
            assert_eq!(pats_deleted, Vec::<String>::new());
            (store, verify)
        }
        other => panic!("expected Ready, got {other:?}"),
    }
}

fn locked(o: StartupOutcome) -> LockedReason {
    match o {
        StartupOutcome::Locked(r) => r,
        other => panic!("expected Locked, got {other:?}"),
    }
}

fn newer(o: StartupOutcome) -> String {
    match o {
        StartupOutcome::StoreNewer { found } => found,
        other => panic!("expected StoreNewer, got {other:?}"),
    }
}

/// A store with `n` mixed records after `GENESIS`, its head anchored, shut down.
fn closed_store(n: usize) -> Fixture {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    if n > 0 {
        store.append_batch(mixed(n)).expect("append_batch");
    }
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    f
}

/// Exists, bytes and mtime of `audit.db` and `audit.db-wal`.
#[derive(Debug, PartialEq)]
struct FileState {
    name: &'static str,
    bytes: Option<Vec<u8>>,
    mtime: Option<SystemTime>,
}

fn file_states(f: &Fixture) -> Vec<FileState> {
    ["audit.db", "audit.db-wal"]
        .into_iter()
        .map(|name| {
            let p = f.dir.path().join(name);
            FileState {
                name,
                bytes: std::fs::read(&p).ok(),
                mtime: std::fs::metadata(&p).and_then(|m| m.modified()).ok(),
            }
        })
        .collect()
}

fn user_version(f: &Fixture) -> i64 {
    raw_conn(f)
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .expect("user_version")
}

fn row_count(f: &Fixture) -> usize {
    dump_rows(f).len()
}

fn event_types(f: &Fixture) -> Vec<String> {
    dump_rows(f).into_iter().map(|r| r.event_type).collect()
}

fn ops_since(ring: &MemKeyring, from: usize) -> Vec<KeyOp> {
    ring.ops().into_iter().skip(from).collect()
}

fn is_anchor_or_kek_set(o: &KeyOp, install_id: &str) -> bool {
    o.kind == KeyOpKind::Set
        && [
            EntryName::Kek,
            EntryName::HeadAnchor,
            EntryName::FirstRetainedAnchor,
        ]
        .iter()
        .any(|e| e.full_name(install_id) == o.full_name)
}

fn keychain_head(f: &Fixture) -> Option<HeadAnchor> {
    f.ring
        .raw_get(&service_name(&f.install_id), "head_anchor")
        .map(|b| HeadAnchor::from_entry(&b).expect("head anchor layout"))
}

fn payload(store: &Store, seq: u64) -> Value {
    serde_json::from_slice(&store.read_payload(seq).expect("read_payload")).expect("json")
}

fn head_seq(f: &Fixture) -> u64 {
    dump_rows(f).last().expect("rows").seq
}

/// Appends a raw copy of the head row as `RESTORE` with `target` (no valid chain link: only
/// the plaintext predicate of the recovery offer looks at it).
fn insert_raw_restore(f: &Fixture, target: &str) {
    let cols = atlas_duck_audit::encoding::FIELD_LIST;
    let exprs: Vec<String> = cols
        .iter()
        .map(|c| match *c {
            "seq" => "seq + 1".to_string(),
            "event_type" => "'RESTORE'".to_string(),
            "target" => "?1".to_string(),
            other => other.to_string(),
        })
        .collect();
    let sql = format!(
        "INSERT INTO events ({}, record_hash) SELECT {}, record_hash FROM events \
         WHERE seq = (SELECT max(seq) FROM events)",
        cols.join(", "),
        exprs.join(", ")
    );
    raw_conn(f).execute(&sql, [target]).expect("raw RESTORE");
}

// ---------------------------------------------------------------------------------------
// first run

#[test]
fn open_fresh_dir_is_first_run() {
    let f = fixture(fake_clock(START), MemKeyring::new());
    assert!(matches!(open_cfg(&f, f.config()), StartupOutcome::FirstRun));
    assert!(
        f.ring.ops().is_empty(),
        "no keyring access before a store exists"
    );

    // Staging leftovers of a crashed first run or restore never count as a store.
    for name in [
        NEW_DB_FILE.to_string(),
        format!("{NEW_DB_FILE}-wal"),
        RESTORING_DB_FILE.to_string(),
        format!("{RESTORING_DB_FILE}-shm"),
    ] {
        std::fs::write(f.dir.path().join(name), b"leftover").expect("write leftover");
    }
    assert!(matches!(open_cfg(&f, f.config()), StartupOutcome::FirstRun));
    let left: Vec<_> = std::fs::read_dir(f.dir.path())
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("audit"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
    assert!(f.ring.ops().is_empty());
}

#[test]
fn open_refuses_wal_without_db() {
    let f = fixture(fake_clock(START), MemKeyring::new());
    std::fs::write(f.dir.path().join("audit.db-wal"), b"orphan wal").expect("write");
    match open(&f.data, &f.lock, f.config()) {
        Err(OpenError::Integrity(m)) => assert!(m.contains("audit.db-wal"), "{m}"),
        other => panic!("expected Integrity, got {other:?}"),
    }
    assert!(f.dir.path().join("audit.db-wal").exists(), "never deleted");
    assert!(!f.dir.path().join(DB_FILE).exists());
    assert!(f.ring.ops().is_empty());
}

#[test]
fn open_needs_this_dirs_lock() {
    let f = closed_store(2);
    let (_other_dir, _other_data, other_lock) = tmp_data_dir();
    assert!(matches!(
        open(&f.data, &other_lock, f.config()),
        Err(OpenError::Invalid(_))
    ));
}

// ---------------------------------------------------------------------------------------
// normal start

#[test]
fn open_ready_round_trip() {
    let f = closed_store(10);
    let rows = row_count(&f);
    assert_eq!(rows, 11);
    std::fs::write(f.dir.path().join(RESTORING_DB_FILE), b"x").expect("write leftover");

    let (store, verify) = ready(open_cfg(&f, f.config()));
    assert_eq!(
        verify,
        VerifyOutcome::default(),
        "a clean start appends no VERIFY"
    );
    assert!(!f.dir.path().join(RESTORING_DB_FILE).exists());
    assert_eq!(store.head().0, 11);
    assert!(store.open_incidents().is_empty());
    let c = store
        .append(ev(
            EventType::REQUEST_RECEIVED,
            Some("r9"),
            json!({ "n": 1 }),
        ))
        .expect("append");
    assert_eq!(c.seq, 12);
    store.flush_head_anchor().expect("flush");
    assert_eq!(keychain_head(&f).map(|a| a.seq), Some(12));
    store.shutdown();

    assert_chain(&dump_rows(&f));
    let written_by: String = raw_conn(&f)
        .query_row("SELECT value FROM meta WHERE key = 'written_by'", [], |r| {
            r.get(0)
        })
        .expect("written_by");
    assert_eq!(written_by, APP_VERSION);

    // And again: the second start is clean too.
    let (store, verify) = ready(open_cfg(&f, f.config()));
    assert!(verify.findings.is_empty(), "{:?}", verify.findings);
    assert_eq!(store.head().0, 12);
    store.shutdown();
}

#[test]
fn startup_order_migration_then_verify() {
    // U-20 order: migration and SCHEMA_MIGRATED, then the incident VERIFY of step 3, and no
    // anchor write of any kind before that VERIFY is committed.
    let f = closed_store(10);
    let h = head_seq(&f) - 3;
    raw_conn(&f)
        .execute("DELETE FROM events WHERE seq > ?1", [h as i64])
        .expect("truncate tail");

    let faults = Faults::new();
    let seen: Arc<Mutex<Option<Vec<KeyOp>>>> = Arc::new(Mutex::new(None));
    // Structural order: (point, committed head in the DB at that moment).
    let order: Arc<Mutex<Vec<(&'static str, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let db_head = {
        let db = f.db_path();
        move || -> u64 {
            let c = rusqlite::Connection::open_with_flags(
                &db,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .expect("reader");
            c.query_row("SELECT max(seq) FROM events", [], |r| r.get::<_, i64>(0))
                .expect("head") as u64
        }
    };
    {
        let ring = f.ring.clone();
        let seen = seen.clone();
        let order = order.clone();
        let db_head = db_head.clone();
        faults.on_hit(FaultPoint::AfterStartupVerifyAppend, move || {
            order
                .lock()
                .expect("lock")
                .push(("verify_appended", db_head()));
            // Timing tripwire on top of the structural check below: many batch windows long,
            // so an anchor thread that was already enabled would very likely have written by
            // now (a loaded runner could still miss it; the hit order cannot).
            std::thread::sleep(Duration::from_millis(150));
            *seen.lock().expect("lock") = Some(ring.ops());
        });
    }
    {
        let order = order.clone();
        faults.on_hit(FaultPoint::AnchorsEnabled, move || {
            order
                .lock()
                .expect("lock")
                .push(("anchors_enabled", db_head()));
        });
    }
    let mut cfg = f.config();
    with_migration(&mut cfg, migrate_v2);
    cfg.hooks.faults = Some(faults.clone());
    // A short batch window: an anchor write would have had every chance to happen.
    cfg.hooks.anchor_batch_window = Some(Duration::from_millis(1));
    let baseline = f.ring.ops().len();

    let (store, verify) = ready(open_cfg(&f, cfg));
    assert_eq!(verify.verify_seq, Some(h + 2));
    assert!(
        verify
            .findings
            .iter()
            .any(|x| x.kind == FindingKind::AnchorAhead),
        "{:?}",
        verify.findings
    );
    let rows = dump_rows(&f);
    let appended: Vec<(u64, &str)> = rows
        .iter()
        .filter(|r| r.seq > h)
        .map(|r| (r.seq, r.event_type.as_str()))
        .collect();
    assert_eq!(
        appended,
        vec![(h + 1, "SCHEMA_MIGRATED"), (h + 2, "VERIFY")]
    );
    let verify_row = rows.iter().find(|r| r.seq == h + 2).expect("VERIFY row");
    assert!(EventFlags::from_bits(verify_row.flags).contains(EventFlags::INTEGRITY_INCIDENT));
    assert_eq!(
        payload(&store, h + 1),
        json!({ "from": 1, "to": 2, "app_version": APP_VERSION })
    );
    assert_eq!(store.testing_pragma("user_version").expect("pragma"), 2);

    // Anchors were enabled exactly once, after the migration and the VERIFY had committed.
    assert_eq!(
        *order.lock().expect("lock"),
        vec![("verify_appended", h + 2), ("anchors_enabled", h + 2)]
    );
    let at_verify = seen.lock().expect("lock").clone().expect("observer ran");
    let early_sets: Vec<_> = at_verify
        .iter()
        .skip(baseline)
        .filter(|o| is_anchor_or_kek_set(o, &f.install_id))
        .collect();
    assert!(early_sets.is_empty(), "{early_sets:?}");

    store.flush_head_anchor().expect("flush");
    assert_eq!(keychain_head(&f).map(|a| a.seq), Some(h + 2));
    assert_eq!(store.open_incidents(), vec![h + 2]);
    store.shutdown();
}

#[test]
fn install_id_cross_check() {
    let f = closed_store(4);
    let mut cfg = f.config();
    cfg.pinned_install_id = Some(f.install_id.clone());
    let (store, verify) = ready(open_cfg(&f, cfg));
    assert!(verify.findings.is_empty(), "{:?}", verify.findings);
    store.shutdown();

    let (other, _) = atlas_duck_audit::new_ids().expect("ids");
    let mut cfg = f.config();
    cfg.pinned_install_id = Some(other);
    let (store, verify) = ready(open_cfg(&f, cfg));
    assert!(
        verify
            .findings
            .iter()
            .any(|x| x.kind == FindingKind::InstallIdMismatch),
        "{:?}",
        verify.findings
    );
    let vseq = verify.verify_seq.expect("incident VERIFY");
    assert_eq!(store.open_incidents(), vec![vseq]);
    assert_eq!(
        payload(&store, vseq)["result"],
        json!("install_id_mismatch")
    );
    store.shutdown();
}

// ---------------------------------------------------------------------------------------
// keychain cases

#[test]
fn u20_keychain_unavailable_then_ready() {
    let f = closed_store(5);
    let head = head_seq(&f);
    let before = file_states(&f);
    f.ring.set_unavailable(true);
    let mut cfg = f.config();
    with_migration(&mut cfg, migrate_v2);
    assert_eq!(locked(open_cfg(&f, cfg)), LockedReason::KeychainUnavailable);
    assert_eq!(file_states(&f), before, "DB and WAL untouched");
    assert_eq!(user_version(&f), 1, "no migration while locked");
    assert_eq!(row_count(&f) as u64, head);

    f.ring.set_unavailable(false);
    let mut cfg = f.config();
    with_migration(&mut cfg, migrate_v2);
    let (store, verify) = ready(open_cfg(&f, cfg));
    assert!(verify.findings.is_empty(), "{:?}", verify.findings);
    assert_eq!(store.head().0, head + 1);
    assert_eq!(
        payload(&store, head + 1),
        json!({ "from": 1, "to": 2, "app_version": APP_VERSION })
    );
    store.shutdown();
    assert_eq!(user_version(&f), 2);
    assert_eq!(
        event_types(&f).last().map(String::as_str),
        Some("SCHEMA_MIGRATED")
    );
}

#[test]
fn keychain_locked_maps_to_unavailable() {
    let f = closed_store(3);
    let before = file_states(&f);
    f.ring.fail_next(
        KeyOpKind::Get,
        Some(EntryName::Kek),
        KeyStoreError::Locked,
        1,
    );
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeychainUnavailable
    );
    // A keychain that stops answering at the anchors is still "not reachable", not an incident.
    f.ring.fail_next(
        KeyOpKind::Get,
        Some(EntryName::HeadAnchor),
        KeyStoreError::Unavailable,
        1,
    );
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeychainUnavailable
    );
    // The canary failing is the same case.
    f.ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::Canary),
        KeyStoreError::Unavailable,
        1,
    );
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeychainUnavailable
    );
    assert_eq!(file_states(&f), before);
    let (store, _) = ready(open_cfg(&f, f.config()));
    store.shutdown();
}

#[test]
fn retry_schedule_window() {
    let s = keychain_retry_schedule();
    let total: Duration = s.iter().sum();
    assert!(total >= Duration::from_secs(60) && total <= Duration::from_secs(120));
    assert_eq!(
        s.iter().map(Duration::as_secs).collect::<Vec<_>>(),
        vec![2, 4, 8, 16, 30, 30]
    );
}

#[test]
fn locked_reason_strings() {
    assert_eq!(
        LockedReason::KeychainUnavailable.as_str(),
        "keychain_unavailable"
    );
    for offer in [RecoveryOffer::RecoverThisLog, RecoveryOffer::FinishRestore] {
        assert_eq!(
            LockedReason::KeychainLost { offer }.as_str(),
            "keychain_lost"
        );
    }
    assert_eq!(LockedReason::KeyringNotLocal.as_str(), "keyring_not_local");
}

#[test]
fn u18_keychain_wiped_is_lost_not_first_run() {
    let f = closed_store(6);
    let before = file_states(&f);
    let baseline = f.ring.ops().len();
    f.ring.wipe_install(&f.install_id);
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeychainLost {
            offer: RecoveryOffer::RecoverThisLog
        }
    );
    assert_eq!(file_states(&f), before, "DB byte-identical");
    let genesis = event_types(&f)
        .iter()
        .filter(|t| t.as_str() == "GENESIS")
        .count();
    assert_eq!(genesis, 1, "no new GENESIS");
    let sets: Vec<_> = ops_since(&f.ring, baseline)
        .into_iter()
        .filter(|o| is_anchor_or_kek_set(o, &f.install_id))
        .collect();
    assert!(sets.is_empty(), "{sets:?}");
    assert!(
        f.ring
            .raw_get(&service_name(&f.install_id), "kek")
            .is_none()
    );

    // The wizard's first-run call cannot start over the existing DB either.
    let r = create_new_store(
        &f.data,
        &f.lock,
        f.config(),
        input(&f.install_id, &f.chain_id, PASSPHRASE, PASSPHRASE),
    );
    assert!(matches!(r, Err(OpenError::AlreadyExists)), "{r:?}");
    assert_eq!(file_states(&f), before);
}

#[test]
fn kek_undecryptable_is_lost() {
    let f = closed_store(6);
    let rows = row_count(&f);
    let before = file_states(&f);
    let other = Kek::generate().expect("kek");
    f.keys()
        .set(&EntryName::Kek, &other.to_entry_bytes())
        .expect("swap kek");
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeychainLost {
            offer: RecoveryOffer::RecoverThisLog
        }
    );
    // A malformed entry (layout 0, short) is lost as well, never an incident.
    for bad in [vec![0u8; 33], vec![1u8; 10]] {
        f.keys().set(&EntryName::Kek, &bad).expect("set");
        assert_eq!(
            locked(open_cfg(&f, f.config())),
            LockedReason::KeychainLost {
                offer: RecoveryOffer::RecoverThisLog
            }
        );
    }
    assert_eq!(row_count(&f), rows, "no VERIFY");
    assert_eq!(file_states(&f), before);
}

#[test]
fn tampered_newest_key_row_is_an_incident_not_lost() {
    // Two key rows (uncorroborated + month DEK); the newest record uses the month DEK. A
    // corrupted wrapped key there must not read as a lost keychain: the other key opens, so
    // the KEK is this store's and verification reports the tamper. (A lost-keychain outcome
    // would lead to "Recover this log", which rebuilds the keychain anchors from the DB and
    // so erases the anchor evidence.)
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(3)).expect("append");
    corroborate(&store);
    store.append_batch(mixed(3)).expect("append");
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    let keys = key_rows(&f);
    assert_eq!(keys.len(), 2, "{keys:?}");
    let newest_key = dump_rows(&f).last().expect("rows").key_id;
    assert_eq!(newest_key, keys[1].0);
    let c = raw_conn(&f);
    let mut wrapped: Vec<u8> = c
        .query_row(
            "SELECT wrapped_dek FROM keys WHERE key_id = ?1",
            [newest_key as i64],
            |r| r.get(0),
        )
        .expect("wrapped");
    wrapped[20] ^= 0x01;
    c.execute(
        "UPDATE keys SET wrapped_dek = ?1 WHERE key_id = ?2",
        rusqlite::params![wrapped, newest_key as i64],
    )
    .expect("tamper");
    drop(c);

    let v = atlas_duck_audit::testing::startup_verdict(&f.data, &f.config())
        .expect("verified, not locked");
    assert!(
        v.findings
            .iter()
            .any(|x| x.kind == FindingKind::DecryptFailed && x.kind.is_incident()),
        "{:?}",
        v.findings
    );
    // The incident VERIFY would be encrypted under the same (broken) month DEK, and the
    // writer never creates a DEK for a month this process has not corroborated: startup fails
    // closed with an error naming the key, appends nothing and leaves the anchors as they are.
    let anchor = keychain_head(&f);
    let rows = row_count(&f);
    match open(&f.data, &f.lock, f.config()) {
        Err(OpenError::Io(e)) => {
            assert!(e.to_string().contains("data key 2 does not unwrap"), "{e}")
        }
        other => panic!("expected the VERIFY append to fail, got {other:?}"),
    }
    assert_eq!(keychain_head(&f), anchor);
    assert_eq!(row_count(&f), rows);

    // With the newest key the only one, a wrong KEK and a broken key row are
    // indistinguishable: that stays keychain_lost (fail closed; recovery verifies again).
    let g = closed_store(3);
    assert_eq!(key_rows(&g).len(), 1);
    raw_conn(&g)
        .execute(
            "UPDATE keys SET wrapped_dek = zeroblob(length(wrapped_dek)) WHERE key_id = 1",
            [],
        )
        .expect("tamper");
    assert_eq!(
        locked(open_cfg(&g, g.config())),
        LockedReason::KeychainLost {
            offer: RecoveryOffer::RecoverThisLog
        }
    );
}

#[test]
fn corrupt_kek_entry_is_lost_ambiguous_is_unavailable() {
    let f = closed_store(3);
    let before = file_states(&f);
    // Undecodable stored bytes: deterministic, only recovery (a re-seal) clears it.
    f.ring.fail_next(
        KeyOpKind::Get,
        Some(EntryName::Kek),
        KeyStoreError::Corrupt,
        1,
    );
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeychainLost {
            offer: RecoveryOffer::RecoverThisLog
        }
    );
    // An ambiguous entry (several matching credentials) stays "unavailable": a re-seal would
    // hit the same ambiguity.
    f.ring.fail_next(
        KeyOpKind::Get,
        Some(EntryName::Kek),
        KeyStoreError::Other("ambiguous entry".into()),
        1,
    );
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeychainUnavailable
    );
    assert_eq!(file_states(&f), before);
    // A corrupt KEK of this install's interrupted restore offers "Finish restore".
    insert_raw_restore(&f, &f.install_id);
    f.ring.fail_next(
        KeyOpKind::Get,
        Some(EntryName::Kek),
        KeyStoreError::Corrupt,
        1,
    );
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeychainLost {
            offer: RecoveryOffer::FinishRestore
        }
    );
}

#[test]
fn locked_outcomes_leave_a_persisted_wal_alone() {
    // A crash left `audit.db-wal` behind and no other connection is open: the locked paths
    // (which read the DB only through a read-only connection) neither checkpoint nor delete
    // it.
    let f = closed_store(3);
    {
        let c = raw_conn(&f);
        c.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )
        .expect("no checkpoint on close");
        c.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('written_by', '0.0.1')",
            [],
        )
        .expect("write into the WAL");
    }
    let wal = f.dir.path().join("audit.db-wal");
    assert!(
        std::fs::metadata(&wal).is_ok_and(|m| m.len() > 0),
        "WAL persisted"
    );
    let before = file_states(&f);

    f.ring.set_unavailable(true);
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeychainUnavailable
    );
    assert_eq!(file_states(&f), before);
    f.ring.set_unavailable(false);

    // The lost path reads the DB (recovery offer) through the WAL-aware read-only reader.
    f.ring.wipe_install(&f.install_id);
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeychainLost {
            offer: RecoveryOffer::RecoverThisLog
        }
    );
    assert_eq!(file_states(&f), before);
}

#[test]
fn finish_restore_offer_for_this_installs_restore() {
    let f = closed_store(3);
    insert_raw_restore(&f, &f.install_id);
    f.ring.wipe_install(&f.install_id);
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeychainLost {
            offer: RecoveryOffer::FinishRestore
        }
    );
    // A KEK that does not open the restored store's data key: the same offer.
    f.keys()
        .set(
            &EntryName::Kek,
            &Kek::generate().expect("kek").to_entry_bytes(),
        )
        .expect("set");
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeychainLost {
            offer: RecoveryOffer::FinishRestore
        }
    );

    // A newest RESTORE naming another install is "Recover this log".
    let g = closed_store(3);
    let (other, _) = atlas_duck_audit::new_ids().expect("ids");
    insert_raw_restore(&g, &other);
    g.ring.wipe_install(&g.install_id);
    assert_eq!(
        locked(open_cfg(&g, g.config())),
        LockedReason::KeychainLost {
            offer: RecoveryOffer::RecoverThisLog
        }
    );
}

#[test]
fn keyring_not_local_reads_nothing() {
    let f = closed_store(3);
    let before = file_states(&f);
    let baseline = f.ring.ops().len();
    f.ring.set_locality(KeyringLocality::NotLocal {
        dir: PathBuf::from("/net/home/u/.local/share/keyrings"),
    });
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeyringNotLocal
    );
    assert!(ops_since(&f.ring, baseline).is_empty());

    f.ring.set_locality(KeyringLocality::Unknown {
        reason: "statfs failed".into(),
    });
    assert_eq!(
        locked(open_cfg(&f, f.config())),
        LockedReason::KeychainUnavailable
    );
    assert!(ops_since(&f.ring, baseline).is_empty());
    assert_eq!(file_states(&f), before);
}

// ---------------------------------------------------------------------------------------
// version gate (U-21)

#[test]
fn u21_store_newer_is_byte_identical() {
    let written_by = format!("written by atlas-duck {APP_VERSION}");
    let cases: [(&str, &str); 3] = [
        ("PRAGMA user_version = 2", "user_version 2"),
        (
            "UPDATE events SET format_version = 2 WHERE seq = (SELECT max(seq) FROM events)",
            "format_version 2",
        ),
        ("recovery", "recovery layout 2"),
    ];
    for (sql, what) in cases {
        let f = closed_store(4);
        // The raw connection stays open, so the change sits in the WAL: the gate must see it
        // there and leave both files as they are.
        let conn = raw_conn(&f);
        if sql == "recovery" {
            let mut blob: Vec<u8> = conn
                .query_row("SELECT blob FROM recovery WHERE id = 1", [], |r| r.get(0))
                .expect("recovery blob");
            blob[0] = 2;
            conn.execute("UPDATE recovery SET blob = ?1 WHERE id = 1", [blob])
                .expect("tamper");
        } else {
            conn.execute_batch(sql).expect("tamper");
        }
        assert!(f.dir.path().join("audit.db-wal").exists());
        let before = file_states(&f);
        let baseline = f.ring.ops().len();
        let found = newer(open_cfg(&f, f.config()));
        assert!(found.contains(what), "{found}");
        assert!(found.contains(&written_by), "{found}");
        assert_eq!(file_states(&f), before, "{what}");
        assert!(ops_since(&f.ring, baseline).is_empty(), "{what}");
        drop(conn);
    }

    // (d) A keychain anchor with a newer layout byte: only the canary was written.
    let f = closed_store(4);
    let rows = row_count(&f);
    let before = file_states(&f);
    let mut entry = f
        .ring
        .raw_get(&service_name(&f.install_id), "head_anchor")
        .expect("head anchor");
    entry[0] = 2;
    f.keys().set(&EntryName::HeadAnchor, &entry).expect("set");
    let baseline = f.ring.ops().len();
    let found = newer(open_cfg(&f, f.config()));
    assert!(found.contains("keychain anchor layout 2"), "{found}");
    assert!(found.contains(&written_by), "{found}");
    assert_eq!(file_states(&f), before);
    assert_eq!(row_count(&f), rows, "no VERIFY");
    let sets: Vec<_> = ops_since(&f.ring, baseline)
        .into_iter()
        .filter(|o| o.kind == KeyOpKind::Set && !o.full_name.ends_with("/canary"))
        .collect();
    assert!(sets.is_empty(), "{sets:?}");

    // The KEK entry's layout byte is gated the same way.
    let f = closed_store(2);
    let before = file_states(&f);
    let mut kek = f
        .ring
        .raw_get(&service_name(&f.install_id), "kek")
        .expect("kek");
    kek[0] = 2;
    f.keys().set(&EntryName::Kek, &kek).expect("set");
    let found = newer(open_cfg(&f, f.config()));
    assert!(found.contains("keychain kek layout 2"), "{found}");
    assert_eq!(file_states(&f), before);
}

#[test]
fn store_newer_does_not_echo_odd_written_by() {
    let f = closed_store(2);
    let conn = raw_conn(&f);
    conn.execute_batch(
        "PRAGMA user_version = 2; \
         UPDATE meta SET value = 'v9 <script>' WHERE key = 'written_by';",
    )
    .expect("tamper");
    let found = newer(open_cfg(&f, f.config()));
    assert!(found.contains("user_version 2"), "{found}");
    assert!(!found.contains("<script>"), "{found}");
    drop(conn);
}

// ---------------------------------------------------------------------------------------
// migrations (§8.13)

#[test]
fn migration_failure_is_internal_not_incident() {
    // A store whose startup verification has an incident: a failed migration still appends
    // no VERIFY and writes no anchor.
    let f = closed_store(8);
    let h = head_seq(&f) - 2;
    raw_conn(&f)
        .execute("DELETE FROM events WHERE seq > ?1", [h as i64])
        .expect("truncate tail");
    let anchor = keychain_head(&f);
    let baseline = f.ring.ops().len();
    let mut cfg = f.config();
    with_migration(&mut cfg, migrate_fails);
    cfg.hooks.anchor_batch_window = Some(Duration::from_millis(1));
    match open(&f.data, &f.lock, cfg) {
        Err(OpenError::MigrationFailed { from: 1, to: 2, .. }) => {}
        other => panic!("expected MigrationFailed, got {other:?}"),
    }
    assert_eq!(user_version(&f), 1);
    assert_eq!(head_seq(&f), h, "no SCHEMA_MIGRATED, no VERIFY");
    let c = raw_conn(&f);
    let extra: i64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name = 'v2_extra'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(extra, 0, "rolled back");
    drop(c);
    let sets: Vec<_> = ops_since(&f.ring, baseline)
        .into_iter()
        .filter(|o| is_anchor_or_kek_set(o, &f.install_id))
        .collect();
    assert!(sets.is_empty(), "{sets:?}");
    assert_eq!(keychain_head(&f), anchor);

    // The next start with a working migration goes through.
    let mut cfg = f.config();
    with_migration(&mut cfg, migrate_v2);
    let (store, verify) = ready(open_cfg(&f, cfg));
    assert_eq!(verify.verify_seq, Some(h + 2));
    assert_eq!(store.testing_pragma("user_version").expect("pragma"), 2);
    store.shutdown();
}

// ---------------------------------------------------------------------------------------
// read_store_install_id (wizard path (1a))

#[test]
fn read_store_install_id_reads_plaintext_only() {
    let f = closed_store(3);
    let before = file_states(&f);
    let baseline = f.ring.ops().len();
    assert_eq!(
        read_store_install_id(&f.data).expect("read"),
        Some(f.install_id.clone())
    );
    assert_eq!(file_states(&f), before);
    assert!(
        !f.dir.path().join("audit.db-shm").exists(),
        "no sidecar created"
    );
    assert!(ops_since(&f.ring, baseline).is_empty(), "no keyring access");

    // A value that could not name keychain entries is refused.
    raw_conn(&f)
        .execute(
            "UPDATE events SET target = 'x/../other' WHERE event_type = 'GENESIS'",
            [],
        )
        .expect("tamper");
    assert!(matches!(
        read_store_install_id(&f.data),
        Err(OpenError::Integrity(_))
    ));

    let empty = fixture(fake_clock(START), MemKeyring::new());
    assert!(matches!(
        read_store_install_id(&empty.data),
        Err(OpenError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound
    ));
}

// ---------------------------------------------------------------------------------------
// schema-v1 fixture (U-19)

const FIXTURE_INSTALL_ID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
const FIXTURE_CHAIN_ID: &str = "a0b1c2d3e4f5061728394a5b6c7d8e9f";

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/schema")
}

#[test]
#[ignore = "regenerates the committed schema-v1 fixture (ATLAS_DUCK_REGEN_FIXTURE=1)"]
fn generate_v1_fixture() {
    // Frozen like the golden vectors (their SHA-256 is pinned in tests/golden.rs and
    // ci/check-audit-vectors.mjs): only an explicit local dev flag rewrites it, never CI and
    // never a plain `--ignored` run.
    if std::env::var_os("ATLAS_DUCK_REGEN_FIXTURE").is_none_or(|v| v != "1") {
        eprintln!("generate_v1_fixture: set ATLAS_DUCK_REGEN_FIXTURE=1 to rewrite the fixture");
        return;
    }
    assert!(
        ["CI", "GITHUB_ACTIONS", "GITLAB_CI"]
            .iter()
            .all(|v| std::env::var_os(v).is_none()),
        "generate_v1_fixture is refused under CI: the schema-v1 fixture is frozen"
    );
    let ring = MemKeyring::new();
    let clock = fake_clock("2026-10-08T09:00:00.000Z");
    let (dir, data, lock) = tmp_data_dir();
    let keys = Arc::new(MemKeyStore::new(ring.clone(), FIXTURE_INSTALL_ID));
    let store = create_new_store(
        &data,
        &lock,
        OpenConfig::new(clock.clone(), keys),
        input(FIXTURE_INSTALL_ID, FIXTURE_CHAIN_ID, PASSPHRASE, PASSPHRASE),
    )
    .expect("create_new_store");
    // 15 records before the first corroboration (NULL epoch, the uncorroborated DEK), then
    // 25 after it (epoch 2026-10-08, the month DEK 2026-10).
    let all = mixed(40);
    let (before, after) = all.split_at(15);
    for e in before.iter().cloned() {
        clock.advance(Duration::from_secs(60));
        store.append(e).expect("append");
    }
    store.observe_server_date(
        "i1",
        server_time("2026-10-08T09:15:00.000Z"),
        std::time::Instant::now(),
    );
    for e in after.iter().cloned() {
        clock.advance(Duration::from_secs(60));
        store.append(e).expect("append");
    }
    store.flush_head_anchor().expect("flush");
    store.shutdown();

    let db = dir.path().join(DB_FILE);
    let conn = rusqlite::Connection::open(&db).expect("raw");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint");
    let epochs: (i64, i64) = conn
        .query_row(
            "SELECT count(*) FILTER (WHERE epoch IS NULL), count(*) FILTER (WHERE epoch IS NOT NULL) FROM events",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("epochs");
    assert!(epochs.0 > 0 && epochs.1 > 0, "{epochs:?}");
    let keys: i64 = conn
        .query_row("SELECT count(*) FROM keys", [], |r| r.get(0))
        .expect("keys");
    assert_eq!(keys, 2);
    drop(conn);
    assert!(!dir.path().join("audit.db-wal").exists());

    let out = fixture_dir();
    std::fs::create_dir_all(&out).expect("mkdir");
    std::fs::copy(&db, out.join("v1.db")).expect("copy db");
    let service = service_name(FIXTURE_INSTALL_ID);
    let entry = |account: &str| hex::encode(ring.raw_get(&service, account).expect(account));
    let keyring = json!({
        "install_id": FIXTURE_INSTALL_ID,
        "chain_id": FIXTURE_CHAIN_ID,
        "kek": entry("kek"),
        "head_anchor": entry("head_anchor"),
        "first_retained_anchor": entry("first_retained_anchor"),
    });
    let mut text = serde_json::to_string_pretty(&keyring).expect("json");
    text.push('\n');
    std::fs::write(out.join("v1.keyring.json"), text).expect("write keyring");
}

#[test]
fn u19_v1_fixture_migrates_to_head() {
    let dir = fixture_dir();
    let keyring: Value = serde_json::from_slice(
        &std::fs::read(dir.join("v1.keyring.json")).expect("v1.keyring.json"),
    )
    .expect("json");
    let install_id = keyring["install_id"]
        .as_str()
        .expect("install_id")
        .to_string();
    let ring = MemKeyring::new();
    let keys = Arc::new(MemKeyStore::new(ring.clone(), &install_id));
    for (e, k) in [
        (EntryName::Kek, "kek"),
        (EntryName::HeadAnchor, "head_anchor"),
        (EntryName::FirstRetainedAnchor, "first_retained_anchor"),
    ] {
        let bytes = hex::decode(keyring[k].as_str().expect(k)).expect("hex");
        keys.set(&e, &bytes).expect("seed keyring");
    }
    let (tmp, data, lock) = tmp_data_dir();
    std::fs::copy(dir.join("v1.db"), tmp.path().join(DB_FILE)).expect("copy fixture");

    let mut cfg = OpenConfig::new(fake_clock("2026-10-09T08:00:00.000Z"), keys);
    cfg.pinned_install_id = Some(install_id.clone());
    with_migration(&mut cfg, migrate_v2);
    let (store, verify) = ready(open(&data, &lock, cfg).expect("open"));
    assert!(verify.findings.is_empty(), "{:?}", verify.findings);
    let (head, _, chain_id) = store.head();
    assert_eq!(chain_id, keyring["chain_id"].as_str().expect("chain_id"));
    assert_eq!(
        payload(&store, head),
        json!({ "from": 1, "to": 2, "app_version": APP_VERSION })
    );
    assert_eq!(store.testing_pragma("user_version").expect("pragma"), 2);
    // Every v1 record still verifies (old rows keep their own format_version), both DEKs open.
    store.flush_head_anchor().expect("flush");
    let fs = store.full_verify();
    assert!(fs.iter().all(|x| !x.kind.is_incident()), "{fs:?}");
    for seq in 1..=head {
        store.read_payload(seq).expect("decrypts");
    }
    store.shutdown();
}
