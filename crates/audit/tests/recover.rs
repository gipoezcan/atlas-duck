//! "Recover this log" and "Archive old DB and start fresh" (§8.7, §2.5, U-18): recovery with
//! the recovery passphrase on the same chain (its `VERIFY` and `KEY_RECOVERED`, the KEK
//! re-sealed, the anchors rebuilt only afterwards, the PATs deleted), and moving the old DB
//! aside so the wizard can start a new store that names it.

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

use atlas_duck_audit::anchors::{FirstRetainedAnchor, HeadAnchor};
use atlas_duck_audit::crypto::Kek;
use atlas_duck_audit::encoding::ZERO_HASH;
use atlas_duck_audit::error::OpenError;
use atlas_duck_audit::keystore::{
    EntryName, KeyStore, KeyStoreError, KeyringLocality, service_name,
};
use atlas_duck_audit::recovery::seal_recovery;
use atlas_duck_audit::schema::{DB_FILE, Migration};
use atlas_duck_audit::testing::{FaultPoint, Faults, KeyOp, KeyOpKind, MemKeyStore, MemKeyring};
use atlas_duck_audit::types::{Confirmed, EventFlags};
use atlas_duck_audit::{
    LockedReason, OpenConfig, RecoverReport, RecoveryOffer, SettingChange, StartupOutcome, Store,
    archive_and_start_fresh, create_new_store, new_ids, open, recover_this_log,
};
use common::*;
use rusqlite::{OpenFlags, Transaction};
use secrecy::SecretString;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------------------
// helpers

const INSTANCES: [&str; 2] = ["i1", "i2"];

fn confirmed() -> Confirmed {
    Confirmed {
        dialog_text_sha256: [7; 32],
    }
}

fn pass(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn migrate_v2(tx: &Transaction) -> rusqlite::Result<()> {
    tx.execute_batch("CREATE TABLE v2_extra (id INTEGER PRIMARY KEY, note TEXT)")
}

fn with_migration(cfg: &mut OpenConfig) {
    cfg.hooks.extra_migrations = vec![Migration {
        from: 1,
        to: 2,
        apply: migrate_v2,
    }];
}

/// A store with two instances in its settings (origins confirmed), a PAT entry for each,
/// `n` mixed records, its head anchored, shut down.
fn closed_store(n: usize) -> Fixture {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    for id in INSTANCES {
        store
            .apply_setting(
                SettingChange::InstanceOrigin {
                    instance_id: id.into(),
                    origin: Some(format!("https://{id}.example")),
                },
                Some(confirmed()),
            )
            .expect("origin");
        f.keys()
            .set(&EntryName::Pat(id.into()), b"token")
            .expect("pat");
    }
    if n > 0 {
        store.append_batch(mixed(n)).expect("append_batch");
    }
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    f
}

fn locked(o: StartupOutcome) -> LockedReason {
    match o {
        StartupOutcome::Locked(r) => r,
        other => panic!("expected Locked, got {other:?}"),
    }
}

fn ready(o: StartupOutcome) -> (Store, atlas_duck_audit::VerifyOutcome) {
    match o {
        StartupOutcome::Ready { store, verify } => (store, verify),
        other => panic!("expected Ready, got {other:?}"),
    }
}

const LOST: LockedReason = LockedReason::KeychainLost {
    offer: RecoveryOffer::RecoverThisLog,
};

/// Bytes of `audit.db` and `audit.db-wal` (`None` if absent).
fn db_files(dir: &Path) -> Vec<Option<Vec<u8>>> {
    [DB_FILE, "audit.db-wal"]
        .into_iter()
        .map(|n| std::fs::read(dir.join(n)).ok())
        .collect()
}

fn raw_entry(f: &Fixture, account: &str) -> Option<Vec<u8>> {
    f.ring.raw_get(&service_name(&f.install_id), account)
}

fn keychain_head(f: &Fixture) -> Option<HeadAnchor> {
    raw_entry(f, "head_anchor").map(|b| HeadAnchor::from_entry(&b).expect("head anchor"))
}

fn keychain_first_retained(f: &Fixture) -> Option<FirstRetainedAnchor> {
    raw_entry(f, "first_retained_anchor")
        .map(|b| FirstRetainedAnchor::from_entry(&b).expect("first-retained anchor"))
}

fn is_set(o: &KeyOp, install_id: &str, e: &EntryName) -> bool {
    o.kind == KeyOpKind::Set && o.full_name == e.full_name(install_id)
}

fn is_kek_or_anchor_set(o: &KeyOp, install_id: &str) -> bool {
    [
        EntryName::Kek,
        EntryName::HeadAnchor,
        EntryName::FirstRetainedAnchor,
    ]
    .iter()
    .any(|e| is_set(o, install_id, e))
}

fn payload(store: &Store, seq: u64) -> Value {
    serde_json::from_slice(&store.read_payload(seq).expect("read_payload")).expect("json")
}

fn kinds(p: &Value) -> Vec<String> {
    p["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|x| x["kind"].as_str().expect("kind").to_string())
        .collect()
}

fn recover(f: &Fixture, cfg: OpenConfig, p: &str) -> Result<(Store, RecoverReport), OpenError> {
    recover_this_log(&f.data, &f.lock, cfg, &pass(p))
}

// ---------------------------------------------------------------------------------------
// Recover this log

#[test]
fn u18_wiped_keychain_recover_same_chain() {
    let f = closed_store(48);
    let rows_before = dump_rows(&f);
    let h = rows_before.last().expect("rows").seq;
    let kek_before = raw_entry(&f, "kek").expect("kek");
    let genesis_hash = rows_before[0].record_hash;

    f.ring.wipe_install(&f.install_id);
    let mut cfg = f.config();
    with_migration(&mut cfg);
    assert_eq!(locked(open(&f.data, &f.lock, cfg).expect("open")), LOST);

    // A wrong passphrase writes nothing, in the DB or the keychain.
    let files = db_files(f.dir.path());
    let baseline = f.ring.ops().len();
    let mut cfg = f.config();
    with_migration(&mut cfg);
    match recover(&f, cfg, "this is not the passphrase") {
        Err(OpenError::WrongPassphrase) => {}
        other => panic!("expected WrongPassphrase, got {other:?}"),
    }
    assert_eq!(db_files(f.dir.path()), files, "DB bytes unchanged");
    let sets: Vec<_> = f.ring.ops()[baseline..]
        .iter()
        .filter(|o| o.kind == KeyOpKind::Set)
        .cloned()
        .collect();
    assert!(sets.is_empty(), "{sets:?}");

    // The right passphrase recovers the same chain.
    let mut cfg = f.config();
    with_migration(&mut cfg);
    let (store, report) = recover(&f, cfg, PASSPHRASE).expect("recover");
    assert_eq!(store.head().2, f.chain_id, "chain_id unchanged");
    assert_eq!(report.verify_seq, h + 2);
    assert_eq!(report.key_recovered_seq, h + 3);
    assert_eq!(
        report.pats_deleted,
        vec!["i1".to_string(), "i2".to_string()]
    );
    store.flush_head_anchor().expect("flush");

    let rows = dump_rows(&f);
    assert_chain(&rows);
    let tail: Vec<(&str, u64)> = rows[h as usize..]
        .iter()
        .map(|r| (r.event_type.as_str(), r.flags))
        .collect();
    let incident = EventFlags::INTEGRITY_INCIDENT.bits();
    assert_eq!(tail.len(), 3, "{tail:?}");
    assert_eq!(tail[0].0, "SCHEMA_MIGRATED");
    assert_eq!(tail[1], ("VERIFY", incident));
    assert_eq!(tail[2].0, "KEY_RECOVERED");
    assert_eq!(tail[2].1 & incident, 0);
    let v = payload(&store, h + 2);
    assert_eq!(v["scope"], "recover");
    assert_eq!(v["result"], "anchor_missing");
    assert!(kinds(&v).iter().all(|k| k == "anchor_missing"), "{v}");
    assert_eq!(
        payload(&store, h + 3),
        json!({ "what": ["kek", "head_anchor", "first_retained_anchor", "pats_lost"] })
    );
    assert_eq!(store.open_incidents(), vec![h + 2]);

    // KEK re-sealed (the same key), both anchors rebuilt from the DB.
    assert_eq!(raw_entry(&f, "kek"), Some(kek_before));
    let head = keychain_head(&f).expect("head anchor");
    assert_eq!(head.chain_id, f.chain_id);
    assert!(head.seq >= h + 3, "{head:?}");
    assert_eq!(
        keychain_first_retained(&f),
        Some(FirstRetainedAnchor {
            chain_id: f.chain_id.clone(),
            genesis_hash,
            first_retained_seq: 1,
            first_retained_prev_hash: ZERO_HASH,
        })
    );
    for id in INSTANCES {
        assert!(raw_entry(&f, &format!("pat/{id}")).is_none());
    }
    store.shutdown();

    // Restart: a clean start, the recovery incident stays open until acknowledged.
    let mut cfg = f.config();
    with_migration(&mut cfg);
    let (store, verify) = ready(open(&f.data, &f.lock, cfg).expect("open"));
    assert!(verify.findings.is_empty(), "{:?}", verify.findings);
    assert_eq!(verify.verify_seq, None, "no new incident");
    assert_eq!(store.open_incidents(), vec![h + 2]);
    store.shutdown();
}

#[test]
fn recover_no_anchor_write_before_rebuild() {
    let f = closed_store(10);
    f.ring.wipe_install(&f.install_id);
    let faults = Faults::new();
    // The keyring calls and the event types at the moment KEY_RECOVERED committed.
    type Seen = Option<(Vec<KeyOp>, Vec<String>)>;
    let seen: Arc<Mutex<Seen>> = Arc::new(Mutex::new(None));
    {
        let ring = f.ring.clone();
        let seen = seen.clone();
        let db = f.db_path();
        faults.on_hit(FaultPoint::AfterKeyRecoveredAppend, move || {
            let c = rusqlite::Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("reader");
            let types: Vec<String> = c
                .prepare("SELECT event_type FROM events ORDER BY seq")
                .expect("prepare")
                .query_map([], |r| r.get(0))
                .expect("query")
                .map(|r| r.expect("row"))
                .collect();
            *seen.lock().expect("lock") = Some((ring.ops(), types));
        });
    }
    let mut cfg = f.config();
    cfg.hooks.faults = Some(faults);
    cfg.hooks.anchor_batch_window = Some(std::time::Duration::from_millis(1));
    let baseline = f.ring.ops().len();
    let (store, report) = recover(&f, cfg, PASSPHRASE).expect("recover");
    store.flush_head_anchor().expect("flush");

    let (at_hit, types) = seen.lock().expect("lock").take().expect("fault point hit");
    assert_eq!(types.last().map(String::as_str), Some("KEY_RECOVERED"));
    let early: Vec<_> = at_hit[baseline..]
        .iter()
        .filter(|o| is_kek_or_anchor_set(o, &f.install_id))
        .collect();
    assert!(
        early.is_empty(),
        "nothing re-sealed before KEY_RECOVERED: {early:?}"
    );

    let ops = &f.ring.ops()[baseline..];
    let pos = |e: &EntryName| ops.iter().position(|o| is_set(o, &f.install_id, e));
    let kek = pos(&EntryName::Kek).expect("Set(Kek)");
    let head = pos(&EntryName::HeadAnchor).expect("Set(HeadAnchor)");
    let first = pos(&EntryName::FirstRetainedAnchor).expect("Set(FirstRetainedAnchor)");
    assert!(kek < first && kek < head, "{ops:?}");
    assert!(head > at_hit.len() - baseline && first > at_hit.len() - baseline);
    assert!(keychain_head(&f).expect("head").seq >= report.key_recovered_seq);
    store.shutdown();
}

#[test]
fn recover_detects_tamper() {
    let f = closed_store(12);
    let h = dump_rows(&f).last().expect("rows").seq;
    raw_conn(&f)
        .execute("UPDATE events SET target = 'PROJ-666' WHERE seq = 6", [])
        .expect("tamper");
    f.ring.wipe_install(&f.install_id);

    let (store, report) = recover(&f, f.config(), PASSPHRASE).expect("recover completes");
    assert_eq!(report.verify_seq, h + 1);
    let v = payload(&store, report.verify_seq);
    assert_eq!(v["result"], "anchor_missing", "{v}");
    let k = kinds(&v);
    assert!(k.contains(&"anchor_missing".to_string()), "{k:?}");
    assert!(k.contains(&"chain_broken".to_string()), "{k:?}");
    assert_eq!(store.open_incidents(), vec![report.verify_seq]);
    store.shutdown();
}

#[test]
fn recover_keeps_surviving_anchor_evidence() {
    // Only the KEK is gone; the head anchor still names the true head. A tail truncation is
    // recorded in the recovery VERIFY before the anchors are rebuilt from the shorter DB.
    let f = closed_store(10);
    let h = dump_rows(&f).last().expect("rows").seq;
    f.keys().delete(&EntryName::Kek).expect("delete kek");
    raw_conn(&f)
        .execute("DELETE FROM events WHERE seq > ?1", [(h - 3) as i64])
        .expect("truncate tail");
    assert_eq!(
        locked(open(&f.data, &f.lock, f.config()).expect("open")),
        LOST
    );

    let (store, report) = recover(&f, f.config(), PASSPHRASE).expect("recover");
    assert_eq!(report.verify_seq, h - 2);
    let v = payload(&store, report.verify_seq);
    assert_eq!(v["result"], "anchor_missing", "{v}");
    let ahead = v["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .find(|x| x["kind"] == "anchor_ahead")
        .unwrap_or_else(|| panic!("no anchor_ahead: {v}"));
    assert_eq!(ahead["expected_seq"], h);
    assert_eq!(ahead["observed_seq"], h - 3);
    store.flush_head_anchor().expect("flush");
    assert_eq!(
        keychain_head(&f).expect("head").seq,
        report.key_recovered_seq
    );
    store.shutdown();
}

#[test]
fn recover_corrupt_kek_entry_deletes_surviving_pats() {
    // An undecryptable KEK entry (another key) is lost too; the PAT entries survived and are
    // deleted, so every instance needs its token again.
    let f = closed_store(6);
    let other = Kek::generate().expect("kek");
    f.keys()
        .set(&EntryName::Kek, &other.to_entry_bytes())
        .expect("swap kek");
    assert!(raw_entry(&f, "pat/i1").is_some());
    let (store, report) = recover(&f, f.config(), PASSPHRASE).expect("recover");
    assert_eq!(
        report.pats_deleted,
        vec!["i1".to_string(), "i2".to_string()]
    );
    for id in INSTANCES {
        assert!(raw_entry(&f, &format!("pat/{id}")).is_none(), "{id}");
    }
    assert_ne!(
        raw_entry(&f, "kek"),
        Some(other.to_entry_bytes().to_vec()),
        "re-sealed"
    );
    store.shutdown();
    let (store, verify) = ready(open(&f.data, &f.lock, f.config()).expect("open"));
    assert!(verify.findings.is_empty(), "{:?}", verify.findings);
    store.shutdown();
}

#[test]
fn recover_anchor_write_failure_leaves_keychain_lost() {
    // The rebuild of the first-retained anchor fails: the re-sealed KEK is deleted again, so
    // the next start is keychain_lost (and recovery can run again), never a store that opens
    // with its anchors missing.
    let f = closed_store(4);
    f.ring.wipe_install(&f.install_id);
    f.ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::FirstRetainedAnchor),
        KeyStoreError::Unavailable,
        1,
    );
    match recover(&f, f.config(), PASSPHRASE) {
        Err(OpenError::KeyStore(KeyStoreError::Unavailable)) => {}
        other => panic!("expected KeyStore(Unavailable), got {other:?}"),
    }
    assert!(raw_entry(&f, "kek").is_none());
    assert!(
        keychain_head(&f).is_none(),
        "no head anchor without its first-retained one"
    );
    assert_eq!(
        locked(open(&f.data, &f.lock, f.config()).expect("open")),
        LOST
    );

    let h = dump_rows(&f).last().expect("rows").seq;
    let (store, report) = recover(&f, f.config(), PASSPHRASE).expect("second recovery");
    assert_eq!(report.verify_seq, h + 1);
    assert_eq!(
        store.open_incidents().len(),
        2,
        "both recovery VERIFYs stay open"
    );
    store.shutdown();
    let (store, verify) = ready(open(&f.data, &f.lock, f.config()).expect("open"));
    assert!(verify.findings.is_empty(), "{:?}", verify.findings);
    store.shutdown();
}

#[test]
fn recover_refused_when_keychain_kek_opens_the_store() {
    let f = closed_store(4);
    let files = db_files(f.dir.path());
    let baseline = f.ring.ops().len();
    match recover(&f, f.config(), PASSPHRASE) {
        Err(OpenError::Invalid(_)) => {}
        other => panic!("expected Invalid, got {other:?}"),
    }
    assert_eq!(db_files(f.dir.path()), files);
    let writes: Vec<_> = f.ring.ops()[baseline..]
        .iter()
        .filter(|o| is_kek_or_anchor_set(o, &f.install_id) || o.kind == KeyOpKind::Delete)
        .filter(|o| !o.full_name.ends_with("/canary"))
        .cloned()
        .collect();
    assert!(writes.is_empty(), "{writes:?}");
    assert!(raw_entry(&f, "pat/i1").is_some(), "PATs untouched");
}

#[test]
fn recover_refused_when_the_stores_own_kek_does_not_open_it() {
    // One key row whose wrapped DEK was altered: the keychain KEK no longer opens the store
    // (open() says keychain_lost), but it equals the KEK the passphrase unwraps, so the keychain
    // is not what is broken. Recovery would rebuild the anchors over a tampered store: refused.
    let f = closed_store(4);
    assert_eq!(key_rows(&f).len(), 1);
    raw_conn(&f)
        .execute(
            "UPDATE keys SET wrapped_dek = zeroblob(length(wrapped_dek))",
            [],
        )
        .expect("tamper key row");
    assert_eq!(
        locked(open(&f.data, &f.lock, f.config()).expect("open")),
        LOST
    );
    let files = db_files(f.dir.path());
    let baseline = f.ring.ops().len();
    match recover(&f, f.config(), PASSPHRASE) {
        Err(OpenError::Integrity(_)) => {}
        other => panic!("expected Integrity, got {other:?}"),
    }
    assert_eq!(db_files(f.dir.path()), files);
    assert!(
        !f.ring.ops()[baseline..]
            .iter()
            .any(|o| is_kek_or_anchor_set(o, &f.install_id))
    );
}

#[test]
fn recover_swapped_recovery_blob_is_refused() {
    // A recovery row replaced by a blob of another KEK (whose passphrase the attacker knows):
    // the unwrapped KEK opens none of the store's keys, so nothing is re-sealed.
    let f = closed_store(4);
    let other = Kek::generate().expect("kek");
    let blob = seal_recovery(&pass("attacker passphrase 1"), &other).expect("seal");
    raw_conn(&f)
        .execute("UPDATE recovery SET blob = ?1 WHERE id = 1", [blob])
        .expect("swap blob");
    f.ring.wipe_install(&f.install_id);
    let files = db_files(f.dir.path());
    let baseline = f.ring.ops().len();
    match recover(&f, f.config(), "attacker passphrase 1") {
        Err(OpenError::Integrity(_)) => {}
        other => panic!("expected Integrity, got {other:?}"),
    }
    assert_eq!(db_files(f.dir.path()), files);
    assert!(
        !f.ring.ops()[baseline..]
            .iter()
            .any(|o| is_kek_or_anchor_set(o, &f.install_id))
    );
    assert!(raw_entry(&f, "kek").is_none());
}

#[test]
fn recover_keyring_not_local_reads_nothing() {
    let f = closed_store(2);
    f.ring.wipe_install(&f.install_id);
    f.ring.set_locality(KeyringLocality::NotLocal {
        dir: "/net/home".into(),
    });
    let baseline = f.ring.ops().len();
    match recover(&f, f.config(), PASSPHRASE) {
        Err(OpenError::KeyStore(KeyStoreError::NotLocal)) => {}
        other => panic!("expected KeyStore(NotLocal), got {other:?}"),
    }
    assert_eq!(f.ring.ops().len(), baseline);
}

#[test]
fn recover_keychain_unavailable_writes_nothing() {
    let f = closed_store(2);
    f.ring.wipe_install(&f.install_id);
    f.ring.set_unavailable(true);
    let files = db_files(f.dir.path());
    match recover(&f, f.config(), PASSPHRASE) {
        Err(OpenError::KeyStore(KeyStoreError::Unavailable)) => {}
        other => panic!("expected KeyStore(Unavailable), got {other:?}"),
    }
    assert_eq!(db_files(f.dir.path()), files);
}

#[test]
fn recover_needs_this_dirs_lock_and_a_store() {
    let f = closed_store(2);
    let (_d, _data, other_lock) = tmp_data_dir();
    assert!(matches!(
        recover_this_log(&f.data, &other_lock, f.config(), &pass(PASSPHRASE)),
        Err(OpenError::Invalid(_))
    ));
    let g = fixture(fake_clock(START), MemKeyring::new());
    match recover(&g, g.config(), PASSPHRASE) {
        Err(OpenError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        other => panic!("expected Io(NotFound), got {other:?}"),
    }
    assert!(g.ring.ops().is_empty());
}

#[test]
fn recover_newer_store_is_refused_untouched() {
    let f = closed_store(2);
    f.ring.wipe_install(&f.install_id);
    raw_conn(&f)
        .execute_batch("PRAGMA user_version = 9")
        .expect("user_version");
    let files = db_files(f.dir.path());
    let baseline = f.ring.ops().len();
    match recover(&f, f.config(), PASSPHRASE) {
        Err(OpenError::NewerStore(found)) => assert!(found.contains("user_version 9"), "{found}"),
        other => panic!("expected NewerStore, got {other:?}"),
    }
    assert_eq!(db_files(f.dir.path()), files);
    assert_eq!(f.ring.ops().len(), baseline, "no keyring access");
}

// ---------------------------------------------------------------------------------------
// Archive old DB and start fresh

fn entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn archive_requires_existing_db() {
    let f = fixture(fake_clock(START), MemKeyring::new());
    let before = entries(f.dir.path());
    match archive_and_start_fresh(&f.data, &f.lock, confirmed()) {
        Err(OpenError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        other => panic!("expected Io(NotFound), got {other:?}"),
    }
    assert_eq!(entries(f.dir.path()), before, "nothing created");
}

#[test]
fn archive_needs_this_dirs_lock() {
    let f = closed_store(2);
    let (_d, _data, other_lock) = tmp_data_dir();
    assert!(matches!(
        archive_and_start_fresh(&f.data, &other_lock, confirmed()),
        Err(OpenError::Invalid(_))
    ));
    assert!(f.db_path().exists());
}

#[test]
fn archive_and_start_fresh_keeps_old_db() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(20)).expect("append");
    let rows = dump_rows(&f);
    let head = rows.last().expect("rows").clone();
    // A read-only reader keeps the WAL alive across the writer's close (a reader never
    // checkpoints), so the store is archived together with its WAL.
    let reader =
        rusqlite::Connection::open_with_flags(f.db_path(), OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("reader");
    let _: i64 = reader
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .expect("read");
    store.shutdown();
    drop(reader);
    let wal = f.dir.path().join("audit.db-wal");
    assert!(wal.exists(), "the store has a WAL to archive");
    let before = db_files(f.dir.path());
    f.ring.wipe_install(&f.install_id);
    assert_eq!(
        locked(open(&f.data, &f.lock, f.config()).expect("open")),
        LOST
    );

    let a = archive_and_start_fresh(&f.data, &f.lock, confirmed()).expect("archive");
    assert_eq!(a.chain_id, f.chain_id);
    assert_eq!(a.head_seq, head.seq);
    assert_eq!(a.head_hash, head.record_hash);
    let name = a
        .file
        .strip_prefix("archived/")
        .unwrap_or_else(|| panic!("{}", a.file));
    assert!(
        name.starts_with(&format!("audit-{}-{}-", f.chain_id, head.seq)) && name.ends_with(".db"),
        "{name}"
    );
    assert!(!name.contains('/') && !name.contains('\\') && !name.contains(':'));

    // Moved, never deleted: the archived files are the old bytes.
    assert!(!f.db_path().exists());
    assert!(!wal.exists());
    assert!(!f.dir.path().join("audit.db-shm").exists());
    let archived = f.dir.path().join("archived").join(name);
    let mut archived_wal = archived.as_os_str().to_owned();
    archived_wal.push("-wal");
    assert_eq!(
        vec![
            std::fs::read(&archived).ok(),
            std::fs::read(&archived_wal).ok()
        ],
        before
    );
    // And it is still the old store: a checkpointed copy holds every row.
    let scratch = tempfile::tempdir().expect("tempdir");
    let copy = scratch.path().join("copy.db");
    std::fs::copy(&archived, &copy).expect("copy db");
    let mut copy_wal = copy.as_os_str().to_owned();
    copy_wal.push("-wal");
    std::fs::copy(&archived_wal, &copy_wal).expect("copy wal");
    {
        let c = rusqlite::Connection::open(&copy).expect("open copy");
        c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .expect("checkpoint");
        assert_eq!(dump_conn(&c).len(), rows.len());
    }

    // The data dir is a first run now; the new GENESIS names the archived DB.
    assert!(matches!(
        open(&f.data, &f.lock, f.config()).expect("open"),
        StartupOutcome::FirstRun
    ));
    let (install_id, chain_id) = new_ids().expect("ids");
    let keys = Arc::new(MemKeyStore::new(f.ring.clone(), &install_id));
    let mut first = input(&install_id, &chain_id, PASSPHRASE, PASSPHRASE);
    first.archived_db = Some(a.clone());
    let store = create_new_store(
        &f.data,
        &f.lock,
        OpenConfig::new(f.clock.clone(), keys),
        first,
    )
    .expect("create_new_store");
    let genesis = payload(&store, 1);
    assert_eq!(
        genesis["archived_db"],
        json!({
            "file": a.file,
            "chain_id": f.chain_id,
            "head_seq": head.seq,
            "head_hash": hex::encode(head.record_hash),
        })
    );
    store.shutdown();
    assert!(archived.exists(), "the archived DB stays");
}

#[test]
fn archive_refuses_unusable_chain_id() {
    // The plaintext chain_id becomes part of a file name: anything but 32 hex is refused.
    let f = closed_store(2);
    raw_conn(&f)
        .execute(
            "UPDATE events SET chain_id = '../../escape' WHERE seq = (SELECT max(seq) FROM events)",
            [],
        )
        .expect("tamper chain_id");
    let before = db_files(f.dir.path());
    match archive_and_start_fresh(&f.data, &f.lock, confirmed()) {
        Err(OpenError::Integrity(_)) => {}
        other => panic!("expected Integrity, got {other:?}"),
    }
    assert_eq!(db_files(f.dir.path()), before);
    assert!(!f.dir.path().join("archived").exists());
}

#[test]
fn archive_refuses_wal_without_db_and_newer_store() {
    let g = fixture(fake_clock(START), MemKeyring::new());
    std::fs::write(g.dir.path().join("audit.db-wal"), b"orphan").expect("write");
    assert!(matches!(
        archive_and_start_fresh(&g.data, &g.lock, confirmed()),
        Err(OpenError::Integrity(_))
    ));
    assert!(g.dir.path().join("audit.db-wal").exists());

    let f = closed_store(2);
    raw_conn(&f)
        .execute_batch("PRAGMA user_version = 9")
        .expect("user_version");
    let before = db_files(f.dir.path());
    assert!(matches!(
        archive_and_start_fresh(&f.data, &f.lock, confirmed()),
        Err(OpenError::NewerStore(_))
    ));
    assert_eq!(db_files(f.dir.path()), before);
}
