//! Single-writer store: first run with `GENESIS`, append/append_batch atomicity and chain,
//! DEK selection, read API, admission (§8.1, §8.2, §8.4, §8.6, X-03 store half).

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use atlas_duck_audit::anchors::{FirstRetainedAnchor, HeadAnchor};
use atlas_duck_audit::crypto::{self, Kek, query_key, query_tag};
use atlas_duck_audit::encoding::{self, ZERO_HASH, os_path_bytes};
use atlas_duck_audit::error::{AuditError, OpenError};
use atlas_duck_audit::keystore::{EntryName, KeyStoreError, KeyringLocality, service_name};
use atlas_duck_audit::open::NEW_DB_FILE;
use atlas_duck_audit::recovery::open_recovery;
use atlas_duck_audit::testing::{
    FaultPoint, Faults, FreeSpaceStub, KeyOpKind, MemKeyStore, MemKeyring,
};
use atlas_duck_audit::types::{Actor, EventFlags, EventType, NewEvent, QueryKind};
use atlas_duck_audit::{OpenConfig, Store, create_new_store, new_ids};
use common::*;
use rusqlite::OptionalExtension;
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const GIB: u64 = 1024 * 1024 * 1024;

fn kek_of(f: &Fixture) -> Kek {
    let b = f
        .ring
        .raw_get(&service_name(&f.install_id), "kek")
        .expect("kek entry");
    Kek::from_entry_bytes(&b).expect("kek layout")
}

fn files_in(f: &Fixture) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(f.dir.path())
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn payload(store: &Store, seq: u64) -> Value {
    serde_json::from_slice(&store.read_payload(seq).expect("read_payload")).expect("json")
}

fn row_count(f: &Fixture) -> i64 {
    raw_conn(f)
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .expect("count")
}

fn server_time(ts: &str) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(at(ts).0 as u64)
}

fn with_faults(faults: &Arc<Faults>) -> impl FnOnce(&mut OpenConfig) + '_ {
    move |cfg| cfg.hooks.faults = Some(faults.clone())
}

#[test]
fn first_run_creates_genesis() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    assert!(f.db_path().exists());
    assert!(!f.dir.path().join(NEW_DB_FILE).exists());

    let rows = dump_rows(&f);
    assert_eq!(rows.len(), 1);
    let g = &rows[0];
    assert_eq!(g.seq, 1);
    assert_eq!(g.event_type, "GENESIS");
    assert_eq!(g.epoch, None);
    assert_eq!(g.flags, 0);
    assert_eq!(g.target.as_deref(), Some(f.install_id.as_str()));
    assert_eq!(g.prev_hash, ZERO_HASH);
    assert_eq!(g.key_id, 1);
    assert_eq!(g.chain_id, f.chain_id);
    assert_eq!(g.ts_utc, START);
    assert_chain(&rows);

    assert_eq!(key_rows(&f), vec![(1, None, START.to_string())]);

    let c = raw_conn(&f);
    let (blob, created): (Vec<u8>, String) = c
        .query_row("SELECT blob, created_at FROM recovery", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .expect("recovery row");
    assert_eq!(blob.len(), 89);
    assert_eq!(created, START);
    let pass = SecretString::from(PASSPHRASE.to_string());
    assert_eq!(
        open_recovery(&pass, &blob).expect("recovery opens"),
        kek_of(&f)
    );

    let p = payload(&store, 1);
    assert_eq!(p["chain_id"], json!(f.chain_id));
    assert_eq!(p["install_id"], json!(f.install_id));
    assert_eq!(p["created_at"], json!(START));
    assert_eq!(p["archived_db"], Value::Null);
    assert_eq!(p["previous_chain_id"], Value::Null);
    assert_eq!(p["previous_last_anchor"], Value::Null);

    let svc = service_name(&f.install_id);
    let head = HeadAnchor::from_entry(&f.ring.raw_get(&svc, "head_anchor").expect("head"))
        .expect("head layout");
    assert_eq!(
        head,
        HeadAnchor {
            chain_id: f.chain_id.clone(),
            seq: 1,
            record_hash: g.record_hash
        }
    );
    let fr = FirstRetainedAnchor::from_entry(
        &f.ring
            .raw_get(&svc, "first_retained_anchor")
            .expect("first retained"),
    )
    .expect("first retained layout");
    assert_eq!(
        fr,
        FirstRetainedAnchor {
            chain_id: f.chain_id.clone(),
            genesis_hash: g.record_hash,
            first_retained_seq: 1,
            first_retained_prev_hash: ZERO_HASH,
        }
    );
    // The canary was removed again; nothing else is in this install's keyring.
    assert!(f.ring.raw_get(&svc, "canary").is_none());

    assert_eq!(store.head(), (1, g.record_hash, f.chain_id.clone()));
    assert_eq!(store.install_id(), f.install_id);
    store.shutdown();
}

#[test]
fn first_run_records_archived_db() {
    let f = fixture(fake_clock(START), MemKeyring::new());
    let mut inp = input(&f.install_id, &f.chain_id, PASSPHRASE, PASSPHRASE);
    inp.archived_db = Some(atlas_duck_audit::ArchivedDb {
        file: "archived/audit-x-7-20261008T120000Z.db".into(),
        chain_id: "ab".repeat(16),
        head_seq: 7,
        head_hash: [7; 32],
    });
    let store = create_new_store(&f.data, &f.lock, f.config(), inp).expect("create");
    assert_eq!(
        payload(&store, 1)["archived_db"],
        json!({
            "file": "archived/audit-x-7-20261008T120000Z.db",
            "chain_id": "ab".repeat(16),
            "head_seq": 7,
            "head_hash": hex::encode([7u8; 32]),
        })
    );
}

#[test]
fn first_run_refuses_existing_db() {
    let ring = MemKeyring::new();
    let (store, f) = new_store(fake_clock(START), ring.clone());
    store.shutdown();
    let before = std::fs::read(f.db_path()).expect("db bytes");

    let (id2, chain2) = new_ids().expect("ids");
    let cfg = OpenConfig::new(
        f.clock.clone(),
        Arc::new(MemKeyStore::new(ring.clone(), &id2)),
    );
    let r = create_new_store(
        &f.data,
        &f.lock,
        cfg,
        input(&id2, &chain2, PASSPHRASE, PASSPHRASE),
    );
    assert!(matches!(r, Err(OpenError::AlreadyExists)), "{r:?}");
    assert_eq!(std::fs::read(f.db_path()).expect("db bytes"), before);
    let prefix = format!("{}/", service_name(&id2));
    assert!(
        ring.ops()
            .iter()
            .all(|op| !op.full_name.starts_with(&prefix))
    );
}

#[test]
fn first_run_passphrase_rules() {
    for (pass, confirm, want) in [
        ("short", "short", "too_short"),
        (PASSPHRASE, "correct horse batterY", "mismatch"),
    ] {
        let ring = MemKeyring::new();
        let f = fixture(fake_clock(START), ring.clone());
        let r = create_new_store(
            &f.data,
            &f.lock,
            f.config(),
            input(&f.install_id, &f.chain_id, pass, confirm),
        );
        match (want, &r) {
            ("too_short", Err(OpenError::PassphraseTooShort)) => {}
            ("mismatch", Err(OpenError::PassphraseMismatch)) => {}
            _ => panic!("{want}: {r:?}"),
        }
        assert_eq!(files_in(&f), vec!["instance.lock".to_string()]);
        assert!(ring.ops().is_empty(), "{:?}", ring.ops());
    }
}

#[test]
fn first_run_keychain_failure_leaves_nothing() {
    let ring = MemKeyring::new();
    let f = fixture(fake_clock(START), ring.clone());
    ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::Kek),
        KeyStoreError::Unavailable,
        1,
    );
    let r = create_new_store(
        &f.data,
        &f.lock,
        f.config(),
        input(&f.install_id, &f.chain_id, PASSPHRASE, PASSPHRASE),
    );
    assert!(
        matches!(r, Err(OpenError::KeyStore(KeyStoreError::Unavailable))),
        "{r:?}"
    );
    assert_eq!(files_in(&f), vec!["instance.lock".to_string()]);
    assert!(ring.raw_get(&service_name(&f.install_id), "kek").is_none());
}

#[test]
fn first_run_anchor_failure_leaves_nothing() {
    let ring = MemKeyring::new();
    let f = fixture(fake_clock(START), ring.clone());
    ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::FirstRetainedAnchor),
        KeyStoreError::Locked,
        1,
    );
    let r = create_new_store(
        &f.data,
        &f.lock,
        f.config(),
        input(&f.install_id, &f.chain_id, PASSPHRASE, PASSPHRASE),
    );
    assert!(
        matches!(r, Err(OpenError::KeyStore(KeyStoreError::Locked))),
        "{r:?}"
    );
    assert_eq!(files_in(&f), vec!["instance.lock".to_string()]);
    let svc = service_name(&f.install_id);
    for e in ["kek", "head_anchor", "first_retained_anchor", "canary"] {
        assert!(ring.raw_get(&svc, e).is_none(), "{e} left behind");
    }
}

#[test]
fn first_run_crash_before_rename_is_retried_cleanly() {
    let ring = MemKeyring::new();
    let f = fixture(fake_clock(START), ring.clone());
    let faults = Faults::new();
    faults.fail(FaultPoint::FirstRunBeforeRename, 1);
    let mut cfg = f.config();
    cfg.hooks.faults = Some(faults.clone());
    let r = create_new_store(
        &f.data,
        &f.lock,
        cfg,
        input(&f.install_id, &f.chain_id, PASSPHRASE, PASSPHRASE),
    );
    assert!(r.is_err());
    assert!(!f.db_path().exists());

    // A leftover staging file (as after a crash) is removed by the next first run.
    std::fs::write(f.dir.path().join(NEW_DB_FILE), b"half-written").expect("leftover");
    let store = create_new_store(
        &f.data,
        &f.lock,
        f.config(),
        input(&f.install_id, &f.chain_id, PASSPHRASE, PASSPHRASE),
    )
    .expect("retry");
    assert!(!f.dir.path().join(NEW_DB_FILE).exists());
    assert_eq!(store.head().0, 1);
    assert_chain(&dump_rows(&f));
}

#[test]
fn first_run_keyring_not_local() {
    let ring = MemKeyring::new();
    let f = fixture(fake_clock(START), ring.clone());
    ring.set_locality(KeyringLocality::NotLocal {
        dir: PathBuf::from("/net/home/keyrings"),
    });
    let r = create_new_store(
        &f.data,
        &f.lock,
        f.config(),
        input(&f.install_id, &f.chain_id, PASSPHRASE, PASSPHRASE),
    );
    assert!(
        matches!(r, Err(OpenError::KeyStore(KeyStoreError::NotLocal))),
        "{r:?}"
    );
    assert!(ring.ops().is_empty());
    assert_eq!(files_in(&f), vec!["instance.lock".to_string()]);

    ring.set_locality(KeyringLocality::Unknown {
        reason: "statfs failed".into(),
    });
    let r = create_new_store(
        &f.data,
        &f.lock,
        f.config(),
        input(&f.install_id, &f.chain_id, PASSPHRASE, PASSPHRASE),
    );
    assert!(
        matches!(r, Err(OpenError::KeyStore(KeyStoreError::Unavailable))),
        "{r:?}"
    );
    assert!(ring.ops().is_empty());
}

#[test]
fn first_run_checks_ids() {
    let ring = MemKeyring::new();
    let f = fixture(fake_clock(START), ring.clone());
    let (other, _) = new_ids().expect("ids");
    let r = create_new_store(
        &f.data,
        &f.lock,
        f.config(),
        input(&other, &f.chain_id, PASSPHRASE, PASSPHRASE),
    );
    assert!(matches!(r, Err(OpenError::Invalid(_))), "{r:?}");
    let cfg = OpenConfig::new(
        f.clock.clone(),
        Arc::new(MemKeyStore::new(ring.clone(), "NOT-HEX")),
    );
    let r = create_new_store(
        &f.data,
        &f.lock,
        cfg,
        input("NOT-HEX", &f.chain_id, PASSPHRASE, PASSPHRASE),
    );
    assert!(matches!(r, Err(OpenError::Invalid(_))), "{r:?}");
    assert!(ring.ops().is_empty());
    let (a, b) = new_ids().expect("ids");
    assert_ne!(a, b);
    assert!(
        a.len() == 32
            && a.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
}

#[test]
fn first_run_needs_this_dirs_lock() {
    let ring = MemKeyring::new();
    let f = fixture(fake_clock(START), ring.clone());
    let (_other_dir, _other_data, other_lock) = tmp_data_dir();
    let r = create_new_store(
        &f.data,
        &other_lock,
        f.config(),
        input(&f.install_id, &f.chain_id, PASSPHRASE, PASSPHRASE),
    );
    assert!(matches!(r, Err(OpenError::Invalid(_))), "{r:?}");
    assert!(ring.ops().is_empty());
}

#[test]
fn append_chains_and_is_durable() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let reader = raw_conn(&f);
    let types = [
        EventType::REQUEST_RECEIVED,
        EventType::PREVIEW_FETCH,
        EventType::READ_FETCHED,
        EventType::CONFIG_CHANGED,
        EventType::APP_START,
    ];
    for i in 0..100u64 {
        let rid = format!("req-{}", i / 3);
        let rid = (i % 4 != 0).then_some(rid.as_str());
        f.clock.advance(Duration::from_millis(250));
        let c = store
            .append(ev(
                types[i as usize % types.len()],
                rid,
                json!({ "i": i, "s": "x".repeat(i as usize) }),
            ))
            .expect("append");
        assert_eq!(c.seq, i + 2);
        // Committed before `append` returned: a second connection already sees the row.
        let seen: Option<Vec<u8>> = reader
            .query_row(
                "SELECT record_hash FROM events WHERE seq = ?1",
                [c.seq as i64],
                |r| r.get(0),
            )
            .optional()
            .expect("query");
        assert_eq!(seen.as_deref(), Some(&c.record_hash[..]));
    }
    drop(reader);
    let head = store.head();
    store.shutdown();
    assert!(matches!(
        store.append(ev(EventType::APP_STOP, None, json!({}))),
        Err(AuditError::Closed)
    ));

    let rows = dump_rows(&f);
    assert_eq!(rows.len(), 101);
    assert_chain(&rows);
    assert_eq!(head.0, 101);
    assert_eq!(head.1, rows[100].record_hash);
    assert_eq!(rows[6].request_id.as_deref(), Some("req-1")); // seq 7: i = 5
    assert_eq!(rows[1].request_id, None);
}

#[test]
fn append_batch_atomic() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store
        .append(ev(EventType::APP_START, None, json!({})))
        .expect("append");
    let head = store.head();
    let bad = vec![
        ev(EventType::REQUEST_RECEIVED, Some("r"), json!({"a": 1})),
        ev(EventType::PREVIEW_FETCH, Some("r"), json!({"b": 2})),
        ev(
            EventType::READ_FETCHED,
            Some("r"),
            json!({"n": 9_007_199_254_740_993u64}),
        ),
    ];
    assert!(store.append_batch(bad).is_err());
    assert_eq!(row_count(&f), 2);
    assert_eq!(store.head(), head);

    let out = store
        .append_batch(vec![
            ev(EventType::REQUEST_RECEIVED, Some("r"), json!({"a": 1})),
            ev(EventType::READ_FETCHED, Some("r"), json!({"b": 2})),
        ])
        .expect("batch");
    assert_eq!(out.iter().map(|c| c.seq).collect::<Vec<_>>(), vec![3, 4]);
    assert!(store.append_batch(Vec::new()).expect("empty").is_empty());
    assert_chain(&dump_rows(&f));
}

#[test]
fn append_batch_fault_mid_batch_commits_nothing() {
    let faults = Faults::new();
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), with_faults(&faults));
    // The second row's insert fails after the first row of the batch was inserted.
    faults.fail_after(FaultPoint::WriterAfterRow, 1, 1);
    let batch: Vec<NewEvent> = (0..3)
        .map(|i| ev(EventType::SCRIPT_CALL, Some("s"), json!({ "i": i })))
        .collect();
    assert!(matches!(
        store.append_batch(batch),
        Err(AuditError::AppendFailed(_))
    ));
    assert_eq!(row_count(&f), 1);
    assert_eq!(store.head().0, 1);

    faults.fail(FaultPoint::WriterBeforeCommit, 1);
    let batch: Vec<NewEvent> = (0..3)
        .map(|i| ev(EventType::SCRIPT_CALL, Some("s"), json!({ "i": i })))
        .collect();
    assert!(store.append_batch(batch).is_err());
    assert_eq!(row_count(&f), 1);

    let c = store
        .append(ev(EventType::APP_START, None, json!({})))
        .expect("append");
    assert_eq!(c.seq, 2);
    assert_chain(&dump_rows(&f));
}

#[test]
fn append_failure_restores_memory() {
    let faults = Faults::new();
    let clock = fake_clock(START);
    let (store, f) = new_store_with(clock.clone(), MemKeyring::new(), with_faults(&faults));
    let last = store
        .append(ev(EventType::APP_START, None, json!({})))
        .expect("append");

    // A failed transaction that would have created the first month DEK and started a
    // corroboration-derived epoch leaves neither behind.
    store.observe_server_date("i1", server_time(START), Instant::now());
    faults.fail(FaultPoint::WriterBeforeCommit, 1);
    let r = store.append(ev(EventType::REQUEST_RECEIVED, Some("r1"), json!({})));
    assert!(matches!(r, Err(AuditError::AppendFailed(_))), "{r:?}");
    assert_eq!(
        store.head(),
        (last.seq, last.record_hash, f.chain_id.clone())
    );

    let next = store
        .append(ev(EventType::REQUEST_RECEIVED, Some("r1"), json!({})))
        .expect("append");
    assert_eq!(next.seq, last.seq + 1);
    let rows = dump_rows(&f);
    assert_eq!(rows.last().expect("row").prev_hash, last.record_hash);
    assert_eq!(
        rows.last().expect("row").epoch.as_deref(),
        Some("2026-10-08")
    );
    assert_chain(&rows);
    // Exactly one month key, created by the committed append (not a second one, and the
    // rolled-back key id was reused without a stale cached key: the payload decrypts).
    let keys = key_rows(&f);
    assert_eq!(keys.len(), 2, "{keys:?}");
    assert_eq!(keys[1].1.as_deref(), Some("2026-10"));
    assert_eq!(rows.last().expect("row").key_id, 2);
    store.read_payload(next.seq).expect("payload decrypts");
}

#[test]
fn caller_cannot_set_clock_flags() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let mut e = ev(EventType::WRITE_EDITED, Some("w"), json!({}));
    e.flags = EventFlags::FORWARD
        | EventFlags::EDITED
        | EventFlags::INTEGRITY_INCIDENT
        | EventFlags::from_bits(1 << 20);
    let c = store.append(e).expect("append");
    let rows = dump_rows(&f);
    let r = rows.iter().find(|r| r.seq == c.seq).expect("row");
    assert_eq!(r.flags, EventFlags::EDITED.bits());
}

#[test]
fn store_owned_event_types_are_refused() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    for t in [
        EventType::GENESIS,
        EventType::PRUNE,
        EventType::RESTORE,
        EventType::VERIFY,
        EventType::INTEGRITY_ACK,
        EventType::SCHEMA_MIGRATED,
        EventType::KEY_RECOVERED,
        EventType::KEY_ROTATED,
        EventType::CLOCK_ANOMALY,
        EventType::LEGAL_HOLD_CHANGED,
        EventType::BACKUP,
        EventType::EXPORT,
    ] {
        assert!(
            matches!(
                store.append(ev(t, None, json!({}))),
                Err(AuditError::Invalid(_))
            ),
            "{t:?}"
        );
    }
    assert_eq!(row_count(&f), 1);
    // Also inside a batch: the whole batch is refused.
    let r = store.append_batch(vec![
        ev(EventType::APP_START, None, json!({})),
        ev(EventType::LEGAL_HOLD_CHANGED, None, json!({"new": false})),
    ]);
    assert!(matches!(r, Err(AuditError::Invalid(_))), "{r:?}");
    assert_eq!(row_count(&f), 1);
    // CONFIG_CHANGED stays appendable by core (T12 gates the policy keys).
    store
        .append(ev(EventType::CONFIG_CHANGED, None, json!({"key": "proxy"})))
        .expect("CONFIG_CHANGED");
}

#[test]
fn read_payload_after_shutdown_is_closed() {
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    store.read_payload(1).expect("open store reads");
    store.shutdown();
    assert_eq!(store.read_payload(1), Err(AuditError::Closed));
    assert_eq!(store.clone().read_payload(1), Err(AuditError::Closed));
}

#[test]
fn first_run_refuses_existing_keychain_entries() {
    for entry in [
        EntryName::Kek,
        EntryName::HeadAnchor,
        EntryName::FirstRetainedAnchor,
    ] {
        let ring = MemKeyring::new();
        let f = fixture(fake_clock(START), ring.clone());
        let ks = MemKeyStore::new(ring.clone(), &f.install_id);
        atlas_duck_audit::keystore::KeyStore::set(&ks, &entry, b"another install's value")
            .expect("seed");
        let sets_before = ring
            .ops()
            .iter()
            .filter(|o| o.kind == KeyOpKind::Set)
            .count();
        let r = create_new_store(
            &f.data,
            &f.lock,
            f.config(),
            input(&f.install_id, &f.chain_id, PASSPHRASE, PASSPHRASE),
        );
        assert!(matches!(r, Err(OpenError::Invalid(_))), "{entry:?}: {r:?}");
        assert_eq!(
            ring.raw_get(&service_name(&f.install_id), &entry.account()),
            Some(b"another install's value".to_vec()),
            "{entry:?} overwritten or deleted"
        );
        // Only the canary was written; no kek or anchor set.
        let sets: Vec<_> = ring
            .ops()
            .into_iter()
            .filter(|o| o.kind == KeyOpKind::Set)
            .collect();
        assert_eq!(sets.len(), sets_before + 1, "{sets:?}");
        assert!(sets.last().expect("set").full_name.ends_with("/canary"));
        assert_eq!(files_in(&f), vec!["instance.lock".to_string()]);
    }
}

#[test]
fn null_epoch_rows_use_uncorroborated_dek() {
    let clock = fake_clock(START);
    let (store, f) = new_store(clock.clone(), MemKeyring::new());
    for i in 0..3 {
        store
            .append(ev(EventType::APP_START, None, json!({ "i": i })))
            .expect("append");
    }
    let rows = dump_rows(&f);
    assert!(rows.iter().all(|r| r.epoch.is_none() && r.key_id == 1));

    // The wall clock runs five years ahead; the server says 2026-10-08.
    clock.set_wall(at("2031-10-08T12:00:00.000Z"));
    store.observe_server_date("i1", server_time(START), Instant::now());
    let c = store
        .append(ev(EventType::REQUEST_RECEIVED, Some("r"), json!({})))
        .expect("append");
    let rows = dump_rows(&f);
    let r = rows.iter().find(|r| r.seq == c.seq).expect("row");
    assert_eq!(r.epoch.as_deref(), Some("2026-10-08"));
    assert!(EventFlags::from_bits(r.flags).contains(EventFlags::FORWARD));
    // The local-ahead episode was logged once, before the record.
    let anomalies: Vec<_> = rows
        .iter()
        .filter(|r| r.event_type == "CLOCK_ANOMALY")
        .collect();
    assert_eq!(anomalies.len(), 1);
    let a = payload(&store, anomalies[0].seq);
    assert_eq!(a["kind"], json!("local_ahead"));
    assert_eq!(a["server"], json!(START));

    let keys = key_rows(&f);
    assert_eq!(keys[0].1, None);
    assert!(keys.iter().any(|k| k.1.as_deref() == Some("2026-10")));
    assert!(
        keys.iter()
            .all(|k| k.1.as_deref().is_none_or(|m| m <= "2026-10")),
        "{keys:?}"
    );
    let month_key = keys
        .iter()
        .find(|k| k.1.as_deref() == Some("2026-10"))
        .expect("key")
        .0;
    assert_eq!(r.key_id, month_key);
    assert_chain(&rows);
}

#[test]
fn month_dek_rollover() {
    let clock = fake_clock("2026-10-31T23:00:00.000Z");
    let (store, f) = new_store(clock.clone(), MemKeyring::new());
    store.observe_server_date(
        "i1",
        server_time("2026-10-31T23:00:00.000Z"),
        Instant::now(),
    );
    store
        .append(ev(EventType::APP_START, None, json!({})))
        .expect("append");
    let months = |f: &Fixture| key_rows(f).into_iter().map(|k| k.1).collect::<Vec<_>>();
    assert_eq!(months(&f), vec![None, Some("2026-10".into())]);

    clock.advance(Duration::from_secs(30 * 60));
    store
        .append(ev(EventType::APP_START, None, json!({})))
        .expect("append");
    assert_eq!(months(&f), vec![None, Some("2026-10".into())]);

    // 01:00 on November 1st: the corroborated date (server + monotonic time) enters November.
    clock.advance(Duration::from_secs(90 * 60));
    let c = store
        .append(ev(EventType::APP_START, None, json!({})))
        .expect("append");
    let keys = key_rows(&f);
    assert_eq!(keys.len(), 3);
    assert_eq!(keys[2].1.as_deref(), Some("2026-11"));
    let rows = dump_rows(&f);
    let r = rows.iter().find(|r| r.seq == c.seq).expect("row");
    assert_eq!(r.epoch.as_deref(), Some("2026-11-01"));
    assert_eq!(r.key_id, keys[2].0);
    assert_eq!(keys[2].2, r.ts_utc);
    let prev = rows.iter().find(|r| r.seq == c.seq - 1).expect("row");
    assert_eq!(prev.epoch.as_deref(), Some("2026-10-31"));
    assert_eq!(prev.key_id, keys[1].0);
    for r in &rows {
        store.read_payload(r.seq).expect("decrypts");
    }
}

#[test]
fn behind_clock_first_corroboration_is_flagged_and_logged() {
    // Carry-forward from T06: the first non-NULL epoch can be a past date when the wall clock
    // is behind; it is never silent: the row carries `clock_behind` and a CLOCK_ANOMALY
    // {local_behind} precedes it in the same transaction.
    let clock = fake_clock("2026-10-01T12:00:00.000Z");
    let (store, f) = new_store(clock.clone(), MemKeyring::new());
    store.observe_server_date("i1", server_time(START), Instant::now());
    let c = store
        .append(ev(EventType::REQUEST_RECEIVED, Some("r"), json!({})))
        .expect("append");
    let rows = dump_rows(&f);
    let r = rows.iter().find(|r| r.seq == c.seq).expect("row");
    assert_eq!(r.epoch.as_deref(), Some("2026-10-01"));
    assert!(EventFlags::from_bits(r.flags).contains(EventFlags::BEHIND));
    let a = rows.iter().find(|r| r.seq == c.seq - 1).expect("row");
    assert_eq!(a.event_type, "CLOCK_ANOMALY");
    assert_eq!(payload(&store, a.seq)["kind"], json!("local_behind"));
    assert_eq!(
        rows.iter()
            .filter(|r| r.event_type == "CLOCK_ANOMALY")
            .count(),
        1
    );
}

#[test]
fn read_payload_checks_hash() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let c = store
        .append(ev(
            EventType::READ_FETCHED,
            Some("r"),
            json!({"body": "secret text"}),
        ))
        .expect("append");
    assert_eq!(payload(&store, c.seq)["body"], json!("secret text"));
    let raw = raw_conn(&f);
    let seq = c.seq as i64;
    let orig = dump_rows(&f)
        .into_iter()
        .find(|r| r.seq == c.seq)
        .expect("row");

    let mut ct = orig.payload_ct.clone();
    ct[3] ^= 1;
    raw.execute(
        "UPDATE events SET payload_ct = ?1 WHERE seq = ?2",
        rusqlite::params![ct, seq],
    )
    .expect("tamper");
    assert_eq!(
        store.read_payload(c.seq),
        Err(AuditError::Decrypt { seq: c.seq })
    );
    raw.execute(
        "UPDATE events SET payload_ct = ?1 WHERE seq = ?2",
        rusqlite::params![orig.payload_ct, seq],
    )
    .expect("restore");
    store.read_payload(c.seq).expect("restored");

    let mut sha = orig.payload_sha256;
    sha[0] ^= 1;
    raw.execute(
        "UPDATE events SET payload_sha256 = ?1 WHERE seq = ?2",
        rusqlite::params![&sha[..], seq],
    )
    .expect("tamper");
    assert!(matches!(
        store.read_payload(c.seq),
        Err(AuditError::Decrypt { .. } | AuditError::PayloadHash { .. })
    ));

    // A row re-sealed with the key (AAD over the altered hash) still fails the hash check.
    let kek = kek_of(&f);
    let wrapped: Vec<u8> = raw
        .query_row(
            "SELECT wrapped_dek FROM keys WHERE key_id = ?1",
            [orig.key_id as i64],
            |r| r.get(0),
        )
        .expect("key");
    let dek = crypto::unwrap_dek(&kek, orig.key_id, None, &wrapped).expect("unwrap");
    let plain = br#"{"body":"secret text"}"#;
    let mut forged = orig.clone();
    forged.payload_sha256 = sha;
    let aad = encoding::aad(&forged.fields()).expect("aad");
    let ct = crypto::seal(
        &dek,
        &orig.nonce,
        &aad,
        &crypto::compress(plain).expect("zstd"),
    )
    .expect("seal");
    assert_ne!(Sha256::digest(plain).as_slice(), &sha[..]);
    raw.execute(
        "UPDATE events SET payload_ct = ?1 WHERE seq = ?2",
        rusqlite::params![ct, seq],
    )
    .expect("forge");
    assert_eq!(
        store.read_payload(c.seq),
        Err(AuditError::PayloadHash { seq: c.seq })
    );

    assert_eq!(
        store.read_payload(999),
        Err(AuditError::NotFound { seq: 999 })
    );
}

#[test]
fn query_tag_matches_crypto() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let k_q = query_key(&kek_of(&f));
    for (kind, q) in [
        (QueryKind::Jql, "project = ABC ORDER BY created"),
        (QueryKind::Cql, "  space = DOC  "),
    ] {
        assert_eq!(store.query_tag(kind, q), query_tag(&k_q, kind, q));
    }
    assert!(store.query_tag(QueryKind::Jql, "x").starts_with("jql:"));
}

#[test]
fn observe_server_date_never_blocks() {
    let faults = Faults::new();
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), with_faults(&faults));
    faults.pause_writer();
    let s2 = store.clone();
    let blocked = std::thread::spawn(move || s2.append(ev(EventType::APP_START, None, json!({}))));
    assert!(faults.wait_writer_paused(Duration::from_secs(3)));

    let t0 = Instant::now();
    for _ in 0..10_000 {
        store.observe_server_date("i1", server_time(START), Instant::now());
    }
    let took = t0.elapsed();
    assert!(took < Duration::from_secs(1), "{took:?}");
    assert!(store.testing_dropped_observations() > 0);

    faults.resume_writer();
    blocked.join().expect("thread").expect("append");
    let c = store
        .append(ev(EventType::APP_START, None, json!({})))
        .expect("append");
    assert_eq!(
        dump_rows(&f)
            .iter()
            .find(|r| r.seq == c.seq)
            .expect("row")
            .epoch
            .as_deref(),
        Some("2026-10-08")
    );
}

#[test]
fn admission_storage_low() {
    let stub = FreeSpaceStub::new(GIB);
    let s2 = stub.clone();
    let (store, _f) = new_store_with(fake_clock(START), MemKeyring::new(), move |cfg| {
        cfg.free_space = Some(s2);
    });
    assert_eq!(store.admission_check(), Err(AuditError::StorageLow));
    assert!(store.health().storage_low);
    // Admission is the caller's gate; system events still commit (§8.1).
    store
        .append(ev(
            EventType::CONFIG_CHANGED,
            None,
            json!({"key": "retention_days"}),
        ))
        .expect("system event");
    stub.set(3 * GIB);
    assert_eq!(store.admission_check(), Ok(()));
    assert!(!store.health().storage_low);
    stub.set(2 * GIB);
    assert_eq!(store.admission_check(), Err(AuditError::StorageLow));
    stub.set(3 * GIB);
    stub.set_failing(true);
    assert_eq!(store.admission_check(), Err(AuditError::StorageLow));
}

#[test]
fn admission_real_fs() {
    let (store, _f) = new_store_with(fake_clock(START), MemKeyring::new(), |cfg| {
        cfg.min_free_bytes = 1;
    });
    assert_eq!(store.admission_check(), Ok(()));
}

#[test]
fn synchronous_full_by_default() {
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    assert_eq!(store.testing_pragma("synchronous"), Ok(2));
    assert_eq!(store.testing_pragma("secure_delete"), Ok(1));
    let (fast, _g) = new_store_with(fake_clock(START), MemKeyring::new(), |cfg| {
        cfg.hooks.synchronous_normal = true;
    });
    assert_eq!(fast.testing_pragma("synchronous"), Ok(1));
}

#[test]
fn os_path_columns() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let exe = PathBuf::from("Größe").join("agent-ü.exe");
    let origin = PathBuf::from("Ελληνικά").join("host");
    let mut e = ev(EventType::REQUEST_RECEIVED, Some("r"), json!({}));
    e.actor = Actor {
        agent_name: Some("claude".into()),
        peer_pid: Some(4242),
        peer_exe: Some(exe.clone()),
        peer_origin_exe: Some(origin.clone()),
        ..Actor::default()
    };
    let c = store.append(e).expect("append");
    let raw = raw_conn(&f);
    let (kind, bytes, pid): (String, Vec<u8>, i64) = raw
        .query_row(
            "SELECT typeof(peer_exe), peer_exe, peer_pid FROM events WHERE seq = ?1",
            [c.seq as i64],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("row");
    assert_eq!(kind, "blob");
    assert_eq!(bytes, os_path_bytes(&exe));
    assert_eq!(bytes, exe.to_str().expect("utf-8").as_bytes());
    assert_eq!(pid, 4242);
    let row = dump_rows(&f)
        .into_iter()
        .find(|r| r.seq == c.seq)
        .expect("row");
    assert_eq!(row.peer_origin_exe, Some(os_path_bytes(&origin)));
    assert_eq!(row.agent_name.as_deref(), Some("claude"));
}

#[test]
fn concurrent_producers_keep_one_chain() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let s = store.clone();
            std::thread::spawn(move || {
                let mut seqs = Vec::new();
                for i in 0..25 {
                    let c = if i % 5 == 4 {
                        s.append_batch(vec![
                            ev(EventType::SCRIPT_CALL, Some("b"), json!({ "t": t, "i": i })),
                            ev(
                                EventType::SCRIPT_CALL,
                                Some("b"),
                                json!({ "t": t, "i": i, "j": 1 }),
                            ),
                        ])
                        .expect("batch")
                    } else {
                        vec![
                            s.append(ev(
                                EventType::READ_FETCHED,
                                Some("r"),
                                json!({ "t": t, "i": i }),
                            ))
                            .expect("append"),
                        ]
                    };
                    seqs.extend(c.iter().map(|c| c.seq));
                }
                seqs
            })
        })
        .collect();
    let mut all: Vec<u64> = threads
        .into_iter()
        .flat_map(|h| h.join().expect("producer"))
        .collect();
    all.sort_unstable();
    let n = all.len() as u64;
    assert_eq!(n, 8 * 30);
    assert_eq!(all, (2..=n + 1).collect::<Vec<_>>());
    let rows = dump_rows(&f);
    assert_eq!(rows.len() as u64, n + 1);
    assert_chain(&rows);
}

#[test]
fn store_debug_redacts_keys() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let text = format!("{store:?}");
    let kek = f
        .ring
        .raw_get(&service_name(&f.install_id), "kek")
        .expect("kek");
    assert!(!text.contains(&hex::encode(&kek[1..])));
    assert!(text.contains(&f.install_id));
    let k_q = query_key(&kek_of(&f));
    assert!(!text.contains(&format!("{:?}", &k_q[..4])));
}
