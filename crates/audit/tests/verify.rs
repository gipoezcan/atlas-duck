//! Verification (§8.7, §8.5, §8.11; U-06 tamper suite, U-17 incidents, U-22 prune half):
//! startup verdict through `testing::startup_verdict` (`open()` steps 1–3), full
//! verification on a fresh store handle, persistent incidents and acknowledgement.
//! Tampering runs on a closed store through a raw SQLite connection.

mod common;

use std::time::{Duration, Instant};

use atlas_duck_audit::anchors::{FirstRetainedAnchor, HeadAnchor};
use atlas_duck_audit::crypto::{self, Kek};
use atlas_duck_audit::encoding::{self, FIELD_LIST, ZERO_HASH};
use atlas_duck_audit::error::{AuditError, OpenError};
use atlas_duck_audit::keystore::{EntryName, KeyStore, KeyStoreError, service_name};
use atlas_duck_audit::schema::DB_FILE;
use atlas_duck_audit::testing::{self, FakePrune, Faults, KeyOpKind, MemKeyring};
use atlas_duck_audit::types::{EventFlags, EventType};
use atlas_duck_audit::verify::StartupVerdict;
use atlas_duck_audit::{FindingKind, OpenConfig, Store, VerifyFinding};
use atlas_duck_ipc::jcs::to_jcs_vec;
use common::*;
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------------------
// helpers

/// A `PRUNE` settings snapshot as `Settings::to_json` writes it (a partial one would leave the
/// rebuilt settings view untrusted).
fn settings(retention_days: u64, legal_hold: bool) -> Value {
    json!({
        "anchor_dir": null,
        "instances": {},
        "legal_hold": legal_hold,
        "retention_days": retention_days,
    })
}

/// A fake prune; with `update_first_retained` the anchor thread writes the first-retained
/// anchor right away (flush), so the next prune's barrier is never refused.
fn prune_with(store: &Store, p: FakePrune) -> u64 {
    let update = p.update_first_retained;
    let seq = testing::insert_fake_prune(store, p)
        .expect("fake prune")
        .seq;
    if update {
        store.flush_head_anchor().expect("flush");
    }
    seq
}

fn fake_prune(store: &Store, first_retained_seq: u64, update_first_retained: bool) -> u64 {
    prune_with(
        store,
        FakePrune {
            first_retained_seq,
            cutoff: "2026-06-01".into(),
            settings: settings(92, false),
            update_first_retained,
        },
    )
}

fn append_mixed(store: &Store, n: usize) {
    store.append_batch(mixed(n)).expect("append_batch");
}

fn reopen(f: &Fixture) -> Store {
    testing::open_existing(&f.data, &f.lock, f.config()).expect("open_existing")
}

fn verdict(f: &Fixture) -> StartupVerdict {
    testing::startup_verdict(&f.data, &f.config()).expect("startup verdict")
}

fn verdict_with(f: &Fixture, tweak: impl FnOnce(&mut OpenConfig)) -> StartupVerdict {
    let mut cfg = f.config();
    tweak(&mut cfg);
    testing::startup_verdict(&f.data, &cfg).expect("startup verdict")
}

/// `full_verify` on a fresh handle; the store must still accept appends afterwards.
fn full_verify_fresh(f: &Fixture) -> Vec<VerifyFinding> {
    let store = reopen(f);
    let out = store.full_verify();
    store
        .append(ev(EventType::APP_START, None, json!({ "after": "verify" })))
        .expect("store still usable after verification");
    store.shutdown();
    out
}

fn kinds(fs: &[VerifyFinding]) -> Vec<FindingKind> {
    fs.iter().map(|f| f.kind).collect()
}

/// A finding of `kind` naming `seq` (observed or expected).
fn has(fs: &[VerifyFinding], kind: FindingKind, seq: u64) -> bool {
    fs.iter()
        .any(|f| f.kind == kind && (f.observed_seq == Some(seq) || f.expected_seq == Some(seq)))
}

fn has_kind(fs: &[VerifyFinding], kind: FindingKind) -> bool {
    fs.iter().any(|f| f.kind == kind)
}

fn incidents(fs: &[VerifyFinding]) -> Vec<FindingKind> {
    fs.iter()
        .filter(|f| f.kind.is_incident())
        .map(|f| f.kind)
        .collect()
}

fn kek_of(f: &Fixture) -> Kek {
    let b = f
        .ring
        .raw_get(&service_name(&f.install_id), "kek")
        .expect("kek entry");
    Kek::from_entry_bytes(&b).expect("kek layout")
}

fn keychain_head(f: &Fixture) -> Option<HeadAnchor> {
    f.ring
        .raw_get(&service_name(&f.install_id), "head_anchor")
        .map(|b| HeadAnchor::from_entry(&b).expect("head anchor layout"))
}

fn keychain_first_retained(f: &Fixture) -> FirstRetainedAnchor {
    let b = f
        .ring
        .raw_get(&service_name(&f.install_id), "first_retained_anchor")
        .expect("first_retained_anchor entry");
    FirstRetainedAnchor::from_entry(&b).expect("first-retained layout")
}

/// Enables anchor writes and writes the head anchor now.
fn anchor_head(store: &Store) {
    store.testing_enable_anchors();
    store.flush_head_anchor().expect("flush");
}

fn insert_row(c: &Connection, r: &RawRow) {
    let marks: Vec<String> = (1..=FIELD_LIST.len() + 1)
        .map(|i| format!("?{i}"))
        .collect();
    let sql = format!(
        "INSERT INTO events ({}, record_hash) VALUES ({})",
        FIELD_LIST.join(", "),
        marks.join(", ")
    );
    c.execute(&sql, rusqlite::params_from_iter(row_params(r)))
        .expect("insert row");
}

fn row(f: &Fixture, seq: u64) -> RawRow {
    dump_rows(f)
        .into_iter()
        .find(|r| r.seq == seq)
        .expect("row exists")
}

/// A correctly encrypted row appended at the tail with the head row's DEK (what only a
/// holder of the KEK can do): used to build `RESTORE` boundaries before T16.
fn forge_tail(
    f: &Fixture,
    event_type: &str,
    chain_id: &str,
    target: Option<&str>,
    payload: &Value,
) -> RawRow {
    let c = raw_conn(f);
    let head = dump_conn(&c).pop().expect("head row");
    let (month, wrapped): (Option<String>, Vec<u8>) = c
        .query_row(
            "SELECT month, wrapped_dek FROM keys WHERE key_id = ?1",
            [head.key_id as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("key row");
    let dek = crypto::unwrap_dek(&kek_of(f), head.key_id, month.as_deref(), &wrapped).expect("dek");
    let plain = to_jcs_vec(payload).expect("jcs");
    let mut r = RawRow {
        seq: head.seq + 1,
        chain_id: chain_id.into(),
        event_type: event_type.into(),
        target: target.map(Into::into),
        request_id: None,
        op_id: None,
        op_class: None,
        instance_id: None,
        agent_name: None,
        agent_name_source: None,
        client_kind: None,
        connection_id: None,
        peer_pid: None,
        peer_exe: None,
        peer_origin_exe: None,
        os_user: None,
        atlassian_user: None,
        atlassian_user_key: None,
        decision: None,
        flags: 0,
        payload_len: plain.len() as u64,
        payload_sha256: Sha256::digest(&plain).into(),
        nonce: crypto::random_nonce().expect("nonce"),
        payload_ct: Vec::new(),
        prev_hash: head.record_hash,
        record_hash: ZERO_HASH,
        ..head
    };
    let aad = encoding::aad(&r.fields()).expect("aad");
    let compressed = crypto::compress(&plain).expect("zstd");
    r.payload_ct = crypto::seal(&dek, &r.nonce, &aad, &compressed).expect("seal");
    r.record_hash = r.recompute();
    insert_row(&c, &r);
    r
}

// ---------------------------------------------------------------------------------------
// U-06 tamper suite

#[test]
fn tamper_modify_each_column_class() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 12);
    store.shutdown();
    let target = 6i64;
    for (col, new) in [
        ("agent_name", "'mallory'"),
        ("epoch", "'2026-10-08'"),
        ("flags", "flags | 1"),
        ("payload_len", "payload_len + 1"),
        ("target", "'PROJ-999'"),
    ] {
        let c = raw_conn(&f);
        let old: rusqlite::types::Value = c
            .query_row(
                &format!("SELECT {col} FROM events WHERE seq = ?1"),
                [target],
                |r| r.get(0),
            )
            .expect("old value");
        c.execute(
            &format!("UPDATE events SET {col} = {new} WHERE seq = ?1"),
            [target],
        )
        .expect("tamper");
        drop(c);
        let fs = full_verify_fresh(&f);
        assert!(
            has(&fs, FindingKind::ChainBroken, 6),
            "{col}: {:?}",
            kinds(&fs)
        );
        raw_conn(&f)
            .execute(
                &format!("UPDATE events SET {col} = ?1 WHERE seq = ?2"),
                rusqlite::params![old, target],
            )
            .expect("restore");
    }
    // Restored: clean again.
    assert!(incidents(&full_verify_fresh(&f)).is_empty());
}

#[test]
fn tamper_delete_middle_row() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 12);
    store.shutdown();
    raw_conn(&f)
        .execute("DELETE FROM events WHERE seq = 6", [])
        .expect("delete");
    let fs = full_verify_fresh(&f);
    let gap = fs
        .iter()
        .find(|x| x.kind == FindingKind::SeqGap)
        .expect("SeqGap");
    assert_eq!((gap.expected_seq, gap.observed_seq), (Some(6), Some(7)));
}

#[test]
fn tamper_reorder() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 12);
    store.shutdown();
    let (a, b) = (row(&f, 5), row(&f, 6));
    let c = raw_conn(&f);
    write_row(&c, &RawRow { seq: 5, ..b });
    write_row(&c, &RawRow { seq: 6, ..a });
    drop(c);
    let fs = full_verify_fresh(&f);
    assert!(has(&fs, FindingKind::ChainBroken, 5), "{:?}", kinds(&fs));
    assert!(has(&fs, FindingKind::ChainBroken, 6), "{:?}", kinds(&fs));
}

#[test]
fn tamper_truncate_tail() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 20);
    anchor_head(&store);
    let (head, hash, _) = store.head();
    store.shutdown();
    assert_eq!(keychain_head(&f).map(|a| a.seq), Some(head));
    raw_conn(&f)
        .execute("DELETE FROM events WHERE seq > ?1", [(head - 5) as i64])
        .expect("truncate");
    let v = verdict(&f);
    let a = v
        .findings
        .iter()
        .find(|x| x.kind == FindingKind::AnchorAhead)
        .expect("AnchorAhead");
    assert_eq!(a.expected_seq, Some(head));
    assert_eq!(a.expected_hash, Some(hash));
    assert_eq!(a.observed_seq, Some(head - 5));
    assert!(v.has_incident());
    // The full verification sees it too.
    assert!(has_kind(&full_verify_fresh(&f), FindingKind::AnchorAhead));
}

#[test]
fn tamper_truncate_head() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 20);
    store.shutdown();
    raw_conn(&f)
        .execute("DELETE FROM events WHERE seq <= 10", [])
        .expect("delete");
    assert!(has_kind(
        &verdict(&f).findings,
        FindingKind::FirstRetainedMismatch
    ));
    let fs = full_verify_fresh(&f);
    let m = fs
        .iter()
        .find(|x| x.kind == FindingKind::FirstRetainedMismatch)
        .expect("FirstRetainedMismatch");
    assert_eq!((m.expected_seq, m.observed_seq), (Some(1), Some(11)));
}

#[test]
fn tamper_ciphertext_swap_naive() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 12);
    store.shutdown();
    let (a, b) = (row(&f, 5), row(&f, 6));
    let c = raw_conn(&f);
    write_row(
        &c,
        &RawRow {
            nonce: b.nonce,
            payload_ct: b.payload_ct.clone(),
            ..a.clone()
        },
    );
    write_row(
        &c,
        &RawRow {
            nonce: a.nonce,
            payload_ct: a.payload_ct.clone(),
            ..b
        },
    );
    drop(c);
    let fs = full_verify_fresh(&f);
    assert!(has(&fs, FindingKind::ChainBroken, 5));
    assert!(has(&fs, FindingKind::ChainBroken, 6));
}

#[test]
fn tamper_ciphertext_swap_rehashed() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 12);
    anchor_head(&store);
    store.shutdown();
    let (a, b) = (row(&f, 5), row(&f, 6));
    let c = raw_conn(&f);
    write_row(
        &c,
        &RawRow {
            nonce: b.nonce,
            payload_ct: b.payload_ct.clone(),
            ..a.clone()
        },
    );
    write_row(
        &c,
        &RawRow {
            nonce: a.nonce,
            payload_ct: a.payload_ct.clone(),
            ..b
        },
    );
    drop(c);
    let head = rehash_from(&f, 5);
    set_keychain_head(&f, &head);
    assert_chain(&dump_rows(&f));
    // Startup checks the scope and the head only: it sees only that the settings view cannot be
    // rebuilt (seq 5 is a CONFIG_CHANGED), so which anchor dir is configured is unknown.
    let v = verdict(&f);
    assert_eq!(
        incidents(&v.findings),
        [FindingKind::AnchorDirMismatch],
        "{v:?}"
    );
    assert!(v.findings[0].detail.contains("anchor_dir setting"));
    let fs = full_verify_fresh(&f);
    assert!(!has_kind(&fs, FindingKind::ChainBroken), "{:?}", kinds(&fs));
    assert!(has(&fs, FindingKind::DecryptFailed, 5), "{:?}", kinds(&fs));
    assert!(has(&fs, FindingKind::DecryptFailed, 6), "{:?}", kinds(&fs));
}

#[test]
fn tamper_rewrite_chain_consistently() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 12);
    anchor_head(&store);
    let (head, hash, _) = store.head();
    store.shutdown();
    raw_conn(&f)
        .execute("UPDATE events SET target = 'PROJ-1' WHERE seq = 5", [])
        .expect("tamper");
    rehash_from(&f, 5);
    assert_chain(&dump_rows(&f));
    let v = verdict(&f);
    let m = v
        .findings
        .iter()
        .find(|x| x.kind == FindingKind::AnchorMismatch)
        .expect("AnchorMismatch");
    assert_eq!((m.expected_seq, m.expected_hash), (Some(head), Some(hash)));
    assert_eq!(m.observed_seq, Some(head));
    assert_ne!(m.observed_hash, Some(hash));
}

#[test]
fn tamper_hash_chain_break() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 12);
    store.shutdown();
    // A new prev_hash with the row's own record_hash recomputed: only the link breaks.
    let mut r = row(&f, 6);
    r.prev_hash = [0x5A; 32];
    r.record_hash = r.recompute();
    write_row(&raw_conn(&f), &r);
    let fs = full_verify_fresh(&f);
    let broken: Vec<_> = fs
        .iter()
        .filter(|x| x.kind == FindingKind::ChainBroken)
        .collect();
    assert!(
        broken
            .iter()
            .any(|x| x.observed_seq == Some(6) && x.observed_hash == Some([0x5A; 32]))
    );
    // The next row no longer links either.
    assert!(has(&fs, FindingKind::ChainBroken, 7));
}

#[test]
fn tamper_insert_row_in_the_middle() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 12);
    store.shutdown();
    let rows = dump_rows(&f);
    let c = raw_conn(&f);
    for r in rows.iter().rev().filter(|r| r.seq >= 6) {
        c.execute(
            "UPDATE events SET seq = seq + 1 WHERE seq = ?1",
            [r.seq as i64],
        )
        .expect("shift");
    }
    let copy = RawRow {
        seq: 6,
        ..rows[4].clone()
    };
    insert_row(&c, &copy);
    drop(c);
    let fs = full_verify_fresh(&f);
    assert!(has(&fs, FindingKind::ChainBroken, 6), "{:?}", kinds(&fs));
    assert!(has(&fs, FindingKind::ChainBroken, 7), "{:?}", kinds(&fs));
}

#[test]
fn tamper_insert_forged_tail_row() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 12);
    store.shutdown();
    // A copy of row 5, relinked and rehashed at the tail: the chain is consistent, but the
    // AAD binds seq and prev-free columns, so the payload no longer opens.
    let rows = dump_rows(&f);
    let head = rows.last().expect("head").clone();
    let mut r = RawRow {
        seq: head.seq + 1,
        prev_hash: head.record_hash,
        ..rows[4].clone()
    };
    r.record_hash = r.recompute();
    insert_row(&raw_conn(&f), &r);
    assert_chain(&dump_rows(&f));
    assert!(has(
        &verdict(&f).findings,
        FindingKind::DecryptFailed,
        r.seq
    ));
    let fs = full_verify_fresh(&f);
    assert!(
        has(&fs, FindingKind::DecryptFailed, r.seq),
        "{:?}",
        kinds(&fs)
    );
}

#[test]
fn tamper_fork_same_chain_id() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 10);
    store.shutdown();
    let db = f.dir.path().join(DB_FILE);
    let copy = f.dir.path().join("fork.db");
    std::fs::copy(&db, &copy).expect("copy");
    // The original continues and is anchored.
    let store = reopen(&f);
    append_mixed(&store, 5);
    anchor_head(&store);
    let (head, _, chain) = store.head();
    store.shutdown();
    // The fork (same chain_id, same KEK) continues to the same seq without anchoring.
    std::fs::copy(&copy, &db).expect("swap in the fork");
    let fork = reopen(&f);
    for i in 0..5 {
        fork.append(ev(EventType::APP_START, None, json!({ "fork": i })))
            .expect("append");
    }
    assert_eq!(fork.head().0, head);
    assert_eq!(fork.head().2, chain);
    fork.shutdown();
    let v = verdict(&f);
    assert!(
        has(&v.findings, FindingKind::AnchorMismatch, head),
        "{:?}",
        kinds(&v.findings)
    );
}

#[test]
fn tamper_rolled_back_db_file() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 10);
    store.shutdown();
    let db = f.dir.path().join(DB_FILE);
    let copy = f.dir.path().join("old.db");
    std::fs::copy(&db, &copy).expect("copy");
    let store = reopen(&f);
    append_mixed(&store, 5);
    anchor_head(&store);
    let (head, _, _) = store.head();
    store.shutdown();
    std::fs::copy(&copy, &db).expect("roll back");
    let v = verdict(&f);
    let a = v
        .findings
        .iter()
        .find(|x| x.kind == FindingKind::AnchorAhead)
        .expect("AnchorAhead");
    assert_eq!(
        (a.expected_seq, a.observed_seq),
        (Some(head), Some(head - 5))
    );
}

/// Two prunes whose first-retained updates went through (anchors enabled).
fn store_with_two_prunes() -> (Store, Fixture, u64, u64) {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    corroborate(&store);
    append_mixed(&store, 12);
    let p1 = fake_prune(&store, 6, true);
    append_mixed(&store, 6);
    let p2 = fake_prune(&store, 12, true);
    append_mixed(&store, 3);
    anchor_head(&store);
    assert_eq!(keychain_first_retained(&f).first_retained_seq, 12);
    (store, f, p1, p2)
}

#[test]
fn clean_store_with_prunes_verifies() {
    let (store, f, _, _) = store_with_two_prunes();
    store.shutdown();
    assert!(
        verdict(&f).findings.is_empty(),
        "{:?}",
        kinds(&verdict(&f).findings)
    );
    let fs = full_verify_fresh(&f);
    assert!(fs.is_empty(), "{fs:?}");
}

#[test]
fn tamper_prune_log_delete_row() {
    let (store, f, p1, _) = store_with_two_prunes();
    store.shutdown();
    raw_conn(&f)
        .execute("DELETE FROM prune_log WHERE prune_seq = ?1", [p1 as i64])
        .expect("delete row");
    let fs = full_verify_fresh(&f);
    assert!(
        has_kind(&fs, FindingKind::PruneLogNotContiguous)
            || has_kind(&fs, FindingKind::PruneLogBroken),
        "{:?}",
        kinds(&fs)
    );
}

#[test]
fn tamper_prune_log_delete_latest_row() {
    let (store, f, _, p2) = store_with_two_prunes();
    store.shutdown();
    raw_conn(&f)
        .execute("DELETE FROM prune_log WHERE prune_seq = ?1", [p2 as i64])
        .expect("delete row");
    let fs = full_verify_fresh(&f);
    assert!(
        has(&fs, FindingKind::PruneLogRowMismatch, p2),
        "{:?}",
        kinds(&fs)
    );
    assert!(has_kind(&fs, FindingKind::FirstRetainedMismatch));
}

#[test]
fn tamper_prune_log_alter_cutoff() {
    let (store, f, p1, p2) = store_with_two_prunes();
    store.shutdown();
    let c = raw_conn(&f);
    c.execute(
        "UPDATE prune_log SET cutoff_epoch = '2026-07-30' WHERE prune_seq = ?1",
        [p1 as i64],
    )
    .expect("tamper");
    drop(c);
    let fs = full_verify_fresh(&f);
    assert!(
        has_kind(&fs, FindingKind::PruneLogBroken),
        "{:?}",
        kinds(&fs)
    );

    // Rehash the row chain (no KEK needed): the latest PRUNE payload still names the old hash.
    let c = raw_conn(&f);
    let mut prev = ZERO_HASH;
    let mut st = c
        .prepare(
            "SELECT prune_seq, range_start, cutoff_epoch, last_pruned_record_hash, first_retained_seq \
             FROM prune_log ORDER BY prune_seq",
        )
        .expect("prepare");
    let rows: Vec<(i64, i64, String, Vec<u8>, i64)> = st
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    drop(st);
    for (ps, rs, cutoff, last, frs) in rows {
        let last: [u8; 32] = last.try_into().expect("32");
        let h = encoding::prune_row_hash(&prev, ps as u64, rs as u64, &cutoff, &last, frs as u64);
        c.execute(
            "UPDATE prune_log SET prev_row_hash = ?1, row_hash = ?2 WHERE prune_seq = ?3",
            rusqlite::params![&prev[..], &h[..], ps],
        )
        .expect("rehash row");
        prev = h;
    }
    drop(c);
    let fs = full_verify_fresh(&f);
    assert!(
        !has_kind(&fs, FindingKind::PruneLogBroken),
        "{:?}",
        kinds(&fs)
    );
    assert!(
        has(&fs, FindingKind::PruneLogRowMismatch, p2),
        "{:?}",
        kinds(&fs)
    );
    // The latest PRUNE is reported once, not by both the latest-PRUNE check and the walk.
    let at_p2 = fs
        .iter()
        .filter(|x| {
            x.kind == FindingKind::PruneLogRowMismatch
                && x.observed_seq == Some(p2)
                && x.detail.contains("prune_log_row_hash")
        })
        .count();
    assert_eq!(at_p2, 1, "{fs:?}");
    assert!(has(
        &verdict(&f).findings,
        FindingKind::PruneLogRowMismatch,
        p2
    ));
}

/// Two real prunes (T11): 94 simulated days at retention 92, both first-retained updates done.
fn store_with_two_real_prunes() -> (Store, Fixture, u64, u64) {
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |cfg| {
        cfg.hooks.synchronous_normal = true;
    });
    prune_ready(&store, 92);
    corroborate_now(&store, &f.clock);
    append_mixed(&store, 6);
    for _ in 0..94 {
        day(&store, &f.clock, 2);
    }
    let seqs: Vec<u64> = raw_conn(&f)
        .prepare("SELECT prune_seq FROM prune_log ORDER BY prune_seq")
        .expect("prepare")
        .query_map([], |r| r.get::<_, i64>(0))
        .expect("query")
        .map(|r| r.expect("row") as u64)
        .collect();
    assert_eq!(seqs.len(), 2);
    (store, f, seqs[0], seqs[1])
}

#[test]
fn clean_store_with_real_prunes_verifies() {
    let (store, f, _, p2) = store_with_two_real_prunes();
    assert!(store.full_verify().is_empty());
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    let v = verdict(&f);
    assert!(v.findings.is_empty(), "{:?}", kinds(&v.findings));
    assert!(full_verify_fresh(&f).is_empty());
    assert!(keychain_first_retained(&f).first_retained_seq < p2);
}

#[test]
fn tamper_real_prune_log_delete_row() {
    let (store, f, p1, _) = store_with_two_real_prunes();
    store.shutdown();
    raw_conn(&f)
        .execute("DELETE FROM prune_log WHERE prune_seq = ?1", [p1 as i64])
        .expect("delete row");
    let fs = full_verify_fresh(&f);
    assert!(
        has_kind(&fs, FindingKind::PruneLogNotContiguous)
            || has_kind(&fs, FindingKind::PruneLogBroken),
        "{:?}",
        kinds(&fs)
    );
}

#[test]
fn tamper_real_prune_log_alter_cutoff() {
    let (store, f, p1, _) = store_with_two_real_prunes();
    store.shutdown();
    raw_conn(&f)
        .execute(
            "UPDATE prune_log SET cutoff_epoch = '2026-07-30' WHERE prune_seq = ?1",
            [p1 as i64],
        )
        .expect("tamper");
    let fs = full_verify_fresh(&f);
    assert!(
        has_kind(&fs, FindingKind::PruneLogBroken),
        "{:?}",
        kinds(&fs)
    );
    assert!(verdict(&f).has_incident());
}

#[test]
fn tamper_unknown_flag_bit() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 12);
    store.shutdown();
    raw_conn(&f)
        .execute(
            "UPDATE events SET flags = flags | (1 << 20) WHERE seq = 5",
            [],
        )
        .expect("tamper");
    rehash_from(&f, 5);
    let fs = full_verify_fresh(&f);
    assert!(
        has(&fs, FindingKind::UnknownFlagBits, 5),
        "{:?}",
        kinds(&fs)
    );
    assert!(!has_kind(&fs, FindingKind::ChainBroken));
}

#[test]
fn tamper_destroyed_key_referenced() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 6);
    store.shutdown();
    raw_conn(&f)
        .execute(
            "UPDATE keys SET wrapped_dek = NULL, destroyed_at = '2026-10-08T12:00:00.000Z' WHERE key_id = 1",
            [],
        )
        .expect("destroy");
    let fs = full_verify_fresh(&f);
    let d: Vec<_> = fs
        .iter()
        .filter(|x| x.kind == FindingKind::DestroyedKeyReferenced)
        .collect();
    // Once per key, not once per row.
    assert_eq!(d.len(), 1, "{fs:?}");
    assert_eq!(d[0].observed_seq, Some(1));
}

#[test]
fn tamper_wrong_key() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 3);
    // Later rows (and the VERIFY row) use the month DEK, so the store can still append.
    corroborate(&store);
    append_mixed(&store, 3);
    store.shutdown();
    // A wrapped uncorroborated DEK that does not open under the KEK.
    raw_conn(&f)
        .execute(
            "UPDATE keys SET wrapped_dek = randomblob(60) WHERE key_id = 1",
            [],
        )
        .expect("tamper");
    let fs = full_verify_fresh(&f);
    assert!(
        fs.iter()
            .any(|x| x.kind == FindingKind::DecryptFailed && x.detail.contains("does not unwrap")),
        "{fs:?}"
    );
}

#[test]
fn wrong_kek_is_keychain_lost_before_verification() {
    // A KEK that does not open the newest record's data key is "undecryptable" (§8.7): startup
    // stops at step 2 as `keychain_lost` instead of verifying (T10). The head-decrypt check of
    // step 3 is covered by `tamper_missing_key_row`.
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 6);
    store.shutdown();
    let other = Kek::generate().expect("kek");
    f.keys()
        .set(&EntryName::Kek, &other.to_entry_bytes())
        .expect("swap kek");
    match testing::startup_verdict(&f.data, &f.config()) {
        Err(OpenError::KeyStore(KeyStoreError::Other(reason))) => {
            assert_eq!(reason, "keychain_lost")
        }
        other => panic!("expected keychain_lost, got {other:?}"),
    }
}

#[test]
fn tamper_missing_key_row() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 6);
    let head = store.head().0;
    store.shutdown();
    raw_conn(&f)
        .execute("DELETE FROM keys WHERE key_id = 1", [])
        .expect("delete key");
    assert!(has(&verdict(&f).findings, FindingKind::DecryptFailed, head));
    // Reported once for the key, not once per row.
    let store = reopen(&f);
    let fs = store.full_verify();
    store.shutdown();
    let d: Vec<_> = fs
        .iter()
        .filter(|x| x.kind == FindingKind::DecryptFailed && x.detail.contains("missing"))
        .collect();
    assert_eq!(d.len(), 1, "{fs:?}");
}

#[test]
fn tamper_request_set_hash() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let good = store.append(write_approved(1, true)).expect("append");
    let bad = store.append(write_approved(2, false)).expect("append");
    store.shutdown();
    let fs = full_verify_fresh(&f);
    assert!(
        has(&fs, FindingKind::RequestSetHashMismatch, bad.seq),
        "{fs:?}"
    );
    assert!(!has(&fs, FindingKind::RequestSetHashMismatch, good.seq));
    assert_eq!(incidents(&fs), vec![FindingKind::RequestSetHashMismatch]);
}

#[test]
fn clean_store_verifies_ok() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 150);
    corroborate(&store);
    append_mixed(&store, 150);
    let o = store.try_full_verify().expect("full verify");
    assert!(o.findings.is_empty(), "{:?}", o.findings);
    let seq = o.verify_seq.expect("VERIFY appended");
    assert_eq!(store.head().0, seq);
    let r = row(&f, seq);
    assert_eq!(r.event_type, "VERIFY");
    assert!(!EventFlags::from_bits(r.flags).contains(EventFlags::INTEGRITY_INCIDENT));
    let p: Value =
        serde_json::from_slice(&store.read_payload(seq).expect("payload")).expect("json");
    assert_eq!(p["scope"], json!("full"));
    assert_eq!(p["result"], json!("ok"));
    assert_eq!(p["findings"], json!([]));
    assert_eq!(p["unanchored_tail"], Value::Null);
    assert!(p["detected_at"].is_string());
    assert!(store.open_incidents().is_empty());
    // The C.3 wrapper agrees, and the VERIFY rows themselves verify.
    assert!(store.full_verify().is_empty());
    store.shutdown();
    assert!(full_verify_fresh(&f).is_empty());
}

#[test]
fn full_verify_after_shutdown_is_not_a_pass() {
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    store.shutdown();
    assert_eq!(store.try_full_verify(), Err(AuditError::Closed));
    let fs = store.full_verify();
    assert_eq!(kinds(&fs), vec![FindingKind::ChainBroken]);
    assert!(fs[0].detail.contains("did not complete"));
}

#[test]
fn incident_verify_is_flagged_with_hex_hashes() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 8);
    store.shutdown();
    raw_conn(&f)
        .execute("UPDATE events SET agent_name = 'mallory' WHERE seq = 4", [])
        .expect("tamper");
    let store = reopen(&f);
    let o = store.try_full_verify().expect("runs");
    let seq = o.verify_seq.expect("VERIFY");
    let r = row(&f, seq);
    assert!(EventFlags::from_bits(r.flags).contains(EventFlags::INTEGRITY_INCIDENT));
    let p: Value =
        serde_json::from_slice(&store.read_payload(seq).expect("payload")).expect("json");
    assert_eq!(p["result"], json!("chain_broken"));
    let first = &p["findings"][0];
    assert_eq!(first["kind"], json!("chain_broken"));
    assert_eq!(first["observed_seq"], json!(4));
    assert_eq!(first["observed_hash"].as_str().map(str::len), Some(64));
    assert_eq!(store.open_incidents(), vec![seq]);
    assert_eq!(store.health().open_incidents, 1);
    store.shutdown();
}

#[test]
fn findings_are_capped_per_kind() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 130);
    store.shutdown();
    raw_conn(&f)
        .execute("UPDATE events SET nonce = randomblob(12) WHERE seq > 1", [])
        .expect("tamper");
    rehash_from(&f, 2);
    let fs = full_verify_fresh(&f);
    let n = fs
        .iter()
        .filter(|x| x.kind == FindingKind::DecryptFailed)
        .count();
    assert_eq!(n, atlas_duck_audit::verify::MAX_FINDINGS_PER_KIND + 1);
    let summary = fs.last().expect("summary");
    assert!(
        summary.detail.contains("30 further findings"),
        "{summary:?}"
    );
    // Rows 2..=101 are listed; the omitted ones are 102..=131.
    assert_eq!(
        (summary.expected_seq, summary.observed_seq),
        (Some(102), Some(131))
    );
}

#[test]
fn newer_schema_is_refused_not_an_incident() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 6);
    store.shutdown();
    raw_conn(&f)
        .pragma_update(None, "user_version", 2)
        .expect("pragma");
    match testing::startup_verdict(&f.data, &f.config()) {
        Err(OpenError::NewerStore(found)) => assert!(found.contains("user_version 2")),
        other => panic!("expected NewerStore, got {other:?}"),
    }
    raw_conn(&f)
        .pragma_update(None, "user_version", 1)
        .expect("pragma");
    // A middle row of an unknown format is not recomputed with v1's field list.
    raw_conn(&f)
        .execute("UPDATE events SET format_version = 2 WHERE seq = 4", [])
        .expect("tamper");
    let fs = full_verify_fresh(&f);
    assert!(has(&fs, FindingKind::FormatVersionUnsupported, 4), "{fs:?}");
    assert!(!has(&fs, FindingKind::ChainBroken, 4), "{fs:?}");
}

#[test]
fn prune_inside_retention_is_judged_by_its_snapshot() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    corroborate(&store);
    append_mixed(&store, 12);
    // Allowed under its own 92 days (2026-10-08 − 92 = 2026-07-08).
    let ok = prune_with(
        &store,
        FakePrune {
            first_retained_seq: 4,
            cutoff: "2026-07-08".into(),
            settings: settings(92, false),
            update_first_retained: true,
        },
    );
    // Inside a 150-day retention, and one (otherwise in time) under legal hold.
    let inside = prune_with(
        &store,
        FakePrune {
            first_retained_seq: 6,
            cutoff: "2026-07-08".into(),
            settings: settings(150, false),
            update_first_retained: true,
        },
    );
    let held = prune_with(
        &store,
        FakePrune {
            first_retained_seq: 8,
            cutoff: "2026-07-08".into(),
            settings: settings(92, true),
            update_first_retained: true,
        },
    );
    anchor_head(&store);
    let fs = store.full_verify();
    store.shutdown();
    assert!(!has(&fs, FindingKind::PruneInsideRetention, ok), "{fs:?}");
    assert!(
        has(&fs, FindingKind::PruneInsideRetention, inside),
        "{fs:?}"
    );
    assert!(has(&fs, FindingKind::PruneInsideRetention, held), "{fs:?}");
    assert_eq!(
        incidents(&fs),
        vec![
            FindingKind::PruneInsideRetention,
            FindingKind::PruneInsideRetention
        ],
        "{fs:?}"
    );
    let _ = f;
}

#[test]
fn null_epoch_rows_raise_no_false_incident() {
    // Carry-forward (T06): a behind-clock first run, so the first non-NULL epoch is a past
    // date; NULL-epoch rows before it, behind-flagged rows after it, then a prune of some of
    // the NULL-epoch rows. Nothing of it is an incident.
    let clock = fake_clock("2026-10-01T12:00:00.000Z");
    let (store, f) = new_store(clock.clone(), MemKeyring::new());
    append_mixed(&store, 10);
    store.observe_server_date("i1", server_time(START), Instant::now());
    append_mixed(&store, 5);
    clock.advance(Duration::from_secs(8 * 86_400));
    append_mixed(&store, 5);
    let rows = dump_rows(&f);
    assert!(rows.iter().any(|r| r.epoch.is_none()));
    assert!(
        rows.iter()
            .any(|r| EventFlags::from_bits(r.flags).contains(EventFlags::BEHIND))
    );
    fake_prune(&store, 5, true);
    anchor_head(&store);
    let fs = store.full_verify();
    assert!(fs.is_empty(), "{fs:?}");
    store.shutdown();
    let v = verdict(&f);
    assert!(!v.has_incident(), "{:?}", v.findings);
}

// ---------------------------------------------------------------------------------------
// U-17: unanchored tail, incidents, missing anchors, install_id

#[test]
fn unanchored_tail_is_informational() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.testing_pause_anchors();
    append_mixed(&store, 20);
    store.shutdown();
    assert_eq!(keychain_head(&f).map(|a| a.seq), Some(1));
    let v = verdict(&f);
    assert_eq!(kinds(&v.findings), vec![FindingKind::UnanchoredTail]);
    assert_eq!(v.unanchored_tail, 20);
    assert!(!v.has_incident());
    assert!(v.anchor_actions.advance_head);
    assert!(v.anchor_actions.set_first_retained.is_none());

    // open() step 4: an informational VERIFY, then the head anchor moves.
    let store = reopen(&f);
    let o = testing::apply_startup(&store, &v).expect("apply");
    let seq = o.verify_seq.expect("informational VERIFY");
    let p: Value =
        serde_json::from_slice(&store.read_payload(seq).expect("payload")).expect("json");
    assert_eq!(p["scope"], json!("startup"));
    assert_eq!(p["result"], json!("unanchored_tail"));
    assert_eq!(p["unanchored_tail"], json!(20));
    assert!(!EventFlags::from_bits(row(&f, seq).flags).contains(EventFlags::INTEGRITY_INCIDENT));
    assert!(store.open_incidents().is_empty());
    store.flush_head_anchor().expect("flush");
    assert_eq!(keychain_head(&f).map(|a| a.seq), Some(store.head().0));
    store.shutdown();
    assert!(verdict(&f).findings.is_empty());
}

#[test]
fn incident_persists_until_ack() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 20);
    anchor_head(&store);
    let head = store.head().0;
    store.shutdown();
    raw_conn(&f)
        .execute("DELETE FROM events WHERE seq > ?1", [(head - 5) as i64])
        .expect("truncate");
    let v = verdict(&f);
    assert!(has_kind(&v.findings, FindingKind::AnchorAhead));

    let store = reopen(&f);
    // No anchor write before the VERIFY is committed, not even after a batch window.
    let sets = |f: &Fixture| {
        let name = EntryName::HeadAnchor.full_name(&f.install_id);
        f.ring
            .ops()
            .iter()
            .filter(|o| o.kind == KeyOpKind::Set && o.full_name == name)
            .count()
    };
    let before = sets(&f);
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(sets(&f), before);
    let o = testing::apply_startup(&store, &v).expect("apply");
    let vseq = o.verify_seq.expect("incident VERIFY");
    assert!(EventFlags::from_bits(row(&f, vseq).flags).contains(EventFlags::INTEGRITY_INCIDENT));
    assert_eq!(store.open_incidents(), vec![vseq]);
    store.flush_head_anchor().expect("flush");
    store.shutdown();

    let store = reopen(&f);
    assert_eq!(store.open_incidents(), vec![vseq]);
    assert_eq!(store.health().open_incidents, 1);
    assert_eq!(
        store.acknowledge_incident(vseq - 1, "alice", "x"),
        Err(AuditError::Invalid("not an open integrity incident"))
    );
    assert!(matches!(
        store.acknowledge_incident(vseq, "", "x"),
        Err(AuditError::Invalid(_))
    ));
    let ack = store
        .acknowledge_incident(vseq, "alice", "checked")
        .expect("ack");
    let r = row(&f, ack.seq);
    assert_eq!(r.event_type, "INTEGRITY_ACK");
    assert_eq!(r.os_user.as_deref(), Some("alice"));
    let p: Value =
        serde_json::from_slice(&store.read_payload(ack.seq).expect("payload")).expect("json");
    assert_eq!(
        p,
        json!({ "verify_seq": vseq, "os_user": "alice", "note": "checked" })
    );
    assert!(store.open_incidents().is_empty());
    assert_eq!(
        store.acknowledge_incident(vseq, "alice", "again"),
        Err(AuditError::Invalid("not an open integrity incident"))
    );
    store.shutdown();

    let store = reopen(&f);
    assert!(store.open_incidents().is_empty());
    assert_eq!(store.health().open_incidents, 0);
    store.shutdown();
}

#[test]
fn concurrent_acks_close_once() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 6);
    store.shutdown();
    raw_conn(&f)
        .execute("UPDATE events SET target = 'X' WHERE seq = 3", [])
        .expect("tamper");
    let faults = Faults::new();
    let mut cfg = f.config();
    cfg.hooks.faults = Some(faults.clone());
    let store = testing::open_existing(&f.data, &f.lock, cfg).expect("open_existing");
    let vseq = store
        .try_full_verify()
        .expect("verify")
        .verify_seq
        .expect("seq");
    // Every ack passes the caller-side check while the writer is held; the writer's own
    // check then lets exactly one through.
    faults.pause_writer();
    store.observe_server_date("i1", server_time(START), Instant::now());
    assert!(faults.wait_writer_paused(Duration::from_secs(5)));
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let s = store.clone();
            std::thread::spawn(move || {
                s.acknowledge_incident(vseq, "alice", &format!("n{i}"))
                    .is_ok()
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    faults.resume_writer();
    let ok = handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .filter(|x| *x)
        .count();
    assert_eq!(ok, 1);
    store.shutdown();
    let acks = dump_rows(&f)
        .iter()
        .filter(|r| r.event_type == "INTEGRITY_ACK")
        .count();
    assert_eq!(acks, 1);
}

#[test]
fn anchor_missing_is_incident() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 5);
    store.shutdown();
    f.keys().delete(&EntryName::HeadAnchor).expect("delete");
    let v = verdict(&f);
    assert!(
        v.findings
            .iter()
            .any(|x| x.kind == FindingKind::AnchorMissing && x.detail.contains("head"))
    );
    assert!(v.has_incident());
    f.keys()
        .delete(&EntryName::FirstRetainedAnchor)
        .expect("delete");
    let v = verdict(&f);
    assert_eq!(
        v.findings
            .iter()
            .filter(|x| x.kind == FindingKind::AnchorMissing)
            .count(),
        2
    );
}

#[test]
fn install_id_mismatch() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 3);
    store.shutdown();
    let v = verdict_with(&f, |c| c.pinned_install_id = Some("ab".repeat(16)));
    assert!(
        has_kind(&v.findings, FindingKind::InstallIdMismatch),
        "{:?}",
        kinds(&v.findings)
    );
    let own = f.install_id.clone();
    let v = verdict_with(&f, |c| c.pinned_install_id = Some(own));
    assert!(!has_kind(&v.findings, FindingKind::InstallIdMismatch));
}

// ---------------------------------------------------------------------------------------
// U-22 prune half (fake prunes until T11)

#[test]
fn u22_interrupted_prune_reconciled() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    corroborate(&store);
    append_mixed(&store, 10);
    anchor_head(&store);
    let anchored = store.head().0;
    store.testing_pause_anchors();
    // Crash right after the PRUNE commit: no first-retained update, head anchor before it.
    let prune = fake_prune(&store, 6, false);
    append_mixed(&store, 3);
    store.shutdown();
    assert_eq!(keychain_head(&f).map(|a| a.seq), Some(anchored));
    let before = keychain_first_retained(&f);
    assert_eq!(
        (before.first_retained_seq, before.first_retained_prev_hash),
        (1, ZERO_HASH)
    );

    let v = verdict(&f);
    assert!(!v.has_incident(), "{:?}", v.findings);
    assert!(has_kind(
        &v.findings,
        FindingKind::InterruptedPruneReconciled
    ));
    let last_pruned = {
        // record_hash of seq 5, as the prune_log row holds it.
        raw_conn(&f)
            .query_row("SELECT last_pruned_record_hash FROM prune_log", [], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .expect("row")
    };
    let want = v
        .anchor_actions
        .set_first_retained
        .clone()
        .expect("set_first_retained");
    assert_eq!(want.first_retained_seq, 6);
    assert_eq!(want.first_retained_prev_hash.to_vec(), last_pruned);
    assert_eq!(want.genesis_hash, before.genesis_hash);
    assert_eq!(
        v.anchor_actions.prune_record.as_ref().map(|p| p.seq),
        Some(prune)
    );

    // Applied: first-retained is written before the head anchor passes the PRUNE.
    let store = reopen(&f);
    testing::apply_startup(&store, &v).expect("apply");
    store.flush_head_anchor().expect("flush");
    assert_eq!(keychain_first_retained(&f), want);
    assert_eq!(keychain_head(&f).map(|a| a.seq), Some(store.head().0));
    store.shutdown();
    assert!(
        verdict(&f).findings.is_empty(),
        "{:?}",
        verdict(&f).findings
    );
    assert!(full_verify_fresh(&f).is_empty());
}

#[test]
fn u22_interrupted_prune_with_two_rows() {
    let (store, f, _, _) = store_with_two_prunes();
    store.testing_pause_anchors();
    let p3 = fake_prune(&store, 14, false);
    store.shutdown();
    let v = verdict(&f);
    assert!(!v.has_incident(), "{:?}", v.findings);
    assert_eq!(
        v.anchor_actions.prune_record.as_ref().map(|p| p.seq),
        Some(p3)
    );
    assert_eq!(
        v.anchor_actions
            .set_first_retained
            .map(|a| a.first_retained_seq),
        Some(14)
    );
}

#[test]
fn u22_forged_prune_before_head_anchor() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    corroborate(&store);
    append_mixed(&store, 10);
    // A PRUNE whose first-retained update never happened, yet the head anchor moved past it:
    // the writer never does that (the barrier caps the head), so it was inserted later.
    let prune = fake_prune(&store, 6, false);
    append_mixed(&store, 5);
    anchor_head(&store);
    store.shutdown();
    assert!(keychain_head(&f).expect("anchor").seq > prune);
    let v = verdict(&f);
    assert!(
        has_kind(&v.findings, FindingKind::FirstRetainedMismatch),
        "{:?}",
        kinds(&v.findings)
    );
    assert!(v.anchor_actions.set_first_retained.is_none());
    assert!(!has_kind(
        &v.findings,
        FindingKind::InterruptedPruneReconciled
    ));
}

#[test]
fn u22_first_retained_two_prunes_behind() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    corroborate(&store);
    append_mixed(&store, 12);
    fake_prune(&store, 4, true);
    anchor_head(&store);
    assert_eq!(keychain_first_retained(&f).first_retained_seq, 4);
    store.testing_pause_anchors();
    fake_prune(&store, 6, false);
    fake_prune(&store, 8, false);
    store.shutdown();
    let v = verdict(&f);
    assert!(
        has_kind(&v.findings, FindingKind::FirstRetainedMismatch),
        "{:?}",
        kinds(&v.findings)
    );
    assert!(v.anchor_actions.set_first_retained.is_none());
}

// ---------------------------------------------------------------------------------------
// RESTORE boundary and the interrupted-restore predicate (T16 completes it)

fn restore_payload(
    f: &Fixture,
    head: &RawRow,
    new_chain: &str,
    prior: Option<&HeadAnchor>,
) -> Value {
    json!({
        "install_id": f.install_id,
        "source_install_id": f.install_id,
        "source_chain_id": head.chain_id,
        "source_head_seq": head.seq,
        "source_head_hash": hex::encode(head.record_hash),
        "new_chain_id": new_chain,
        "backup_created_at": START,
        "prior_keychain_anchor": prior.map(|a| json!({
            "chain_id": a.chain_id, "seq": a.seq, "record_hash": hex::encode(a.record_hash),
        })),
        "replaced_db": null,
        "records_lost": 0,
        "pats_lost": [],
    })
}

#[test]
fn interrupted_restore_predicate() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 6);
    anchor_head(&store);
    store.shutdown();
    let prior = keychain_head(&f).expect("anchor");
    let head = dump_rows(&f).pop().expect("head");
    let new_chain = "cd".repeat(16);
    let r = forge_tail(
        &f,
        "RESTORE",
        &new_chain,
        Some(&f.install_id),
        &restore_payload(&f, &head, &new_chain, Some(&prior)),
    );

    let v = verdict(&f);
    assert_eq!(
        kinds(&v.findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    let rc = v
        .anchor_actions
        .complete_restore
        .clone()
        .expect("complete_restore");
    assert_eq!(rc.restore_seq, r.seq);
    assert_eq!(
        rc.head,
        HeadAnchor {
            chain_id: new_chain.clone(),
            seq: r.seq,
            record_hash: r.record_hash
        }
    );
    assert_eq!(rc.first_retained.chain_id, new_chain);
    assert_eq!(rc.first_retained.first_retained_seq, 1);
    assert!(full_verify_fresh(&f).is_empty());

    // Applied: the restore barrier keeps the head anchor where it is until T16's reset.
    let store = reopen(&f);
    testing::apply_startup(&store, &v).expect("apply");
    assert_eq!(
        store.health().anchors_blocked,
        Some(atlas_duck_audit::anchors::BarrierKind::Restore)
    );
    store.flush_head_anchor().expect("flush");
    assert_eq!(keychain_head(&f), Some(prior));
    store.shutdown();
}

#[test]
fn restore_boundary_mismatch() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 6);
    anchor_head(&store);
    store.shutdown();
    let prior = keychain_head(&f).expect("anchor");
    let head = dump_rows(&f).pop().expect("head");
    let new_chain = "cd".repeat(16);
    let mut p = restore_payload(&f, &head, &new_chain, Some(&prior));
    p["source_head_seq"] = json!(head.seq - 1);
    let r = forge_tail(&f, "RESTORE", &new_chain, Some(&f.install_id), &p);
    let fs = full_verify_fresh(&f);
    assert!(
        has(&fs, FindingKind::RestoreBoundaryMismatch, r.seq),
        "{fs:?}"
    );
    // Not reconciled at startup: the anchor names the old chain.
    let v = verdict(&f);
    assert!(!has_kind(
        &v.findings,
        FindingKind::InterruptedRestoreReconciled
    ));
    assert!(
        has_kind(&v.findings, FindingKind::AnchorMismatch),
        "{:?}",
        kinds(&v.findings)
    );
}

#[test]
fn chain_id_change_without_restore() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 6);
    store.shutdown();
    raw_conn(&f)
        .execute(
            "UPDATE events SET chain_id = ?1 WHERE seq >= 5",
            [&"ef".repeat(16)],
        )
        .expect("tamper");
    rehash_from(&f, 5);
    let fs = full_verify_fresh(&f);
    assert!(has(&fs, FindingKind::RestoreBoundaryMismatch, 5), "{fs:?}");
}

#[test]
fn u22_stale_first_retained_with_another_hash_is_not_reconciled() {
    // (a) compares the hash too: right seq, wrong prev_hash → incident.
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    corroborate(&store);
    append_mixed(&store, 10);
    anchor_head(&store);
    store.testing_pause_anchors();
    fake_prune(&store, 6, false);
    store.shutdown();
    let mut fr = keychain_first_retained(&f);
    fr.first_retained_prev_hash = [0x11; 32];
    f.keys()
        .set(
            &EntryName::FirstRetainedAnchor,
            &fr.to_entry().expect("encode"),
        )
        .expect("set");
    let v = verdict(&f);
    assert!(
        has_kind(&v.findings, FindingKind::FirstRetainedMismatch),
        "{:?}",
        kinds(&v.findings)
    );
    assert!(v.anchor_actions.set_first_retained.is_none());
}

#[test]
fn restore_with_another_prior_anchor_is_not_reconciled() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 6);
    anchor_head(&store);
    store.shutdown();
    let mut prior = keychain_head(&f).expect("anchor");
    prior.seq -= 1;
    let head = dump_rows(&f).pop().expect("head");
    let new_chain = "cd".repeat(16);
    forge_tail(
        &f,
        "RESTORE",
        &new_chain,
        Some(&f.install_id),
        &restore_payload(&f, &head, &new_chain, Some(&prior)),
    );
    let v = verdict(&f);
    assert!(v.anchor_actions.complete_restore.is_none());
    assert!(
        has_kind(&v.findings, FindingKind::AnchorMismatch),
        "{:?}",
        kinds(&v.findings)
    );
    // An absent keychain anchor matches only a null prior_keychain_anchor.
    f.keys().delete(&EntryName::HeadAnchor).expect("delete");
    let v = verdict(&f);
    assert!(v.anchor_actions.complete_restore.is_none());
    assert!(has_kind(&v.findings, FindingKind::AnchorMissing));
}

#[test]
fn newer_anchor_layout_mid_process_is_not_skipped() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 4);
    store.shutdown();
    let store = reopen(&f);
    let mut e = f
        .ring
        .raw_get(&service_name(&f.install_id), "head_anchor")
        .expect("head anchor");
    e[0] = 2;
    f.keys().set(&EntryName::HeadAnchor, &e).expect("set");
    // The first-retained anchor is still checked although the head entry is unreadable.
    let mut fr = keychain_first_retained(&f);
    fr.first_retained_seq = 7;
    f.keys()
        .set(
            &EntryName::FirstRetainedAnchor,
            &fr.to_entry().expect("encode"),
        )
        .expect("set");
    let o = store.try_full_verify().expect("runs");
    assert!(
        has_kind(&o.findings, FindingKind::FirstRetainedMismatch),
        "{:?}",
        o.findings
    );
    assert!(
        o.findings
            .iter()
            .any(|x| x.kind == FindingKind::AnchorMismatch && x.detail.contains("newer layout 2")),
        "{:?}",
        o.findings
    );
    let r = row(&f, o.verify_seq.expect("VERIFY"));
    assert!(EventFlags::from_bits(r.flags).contains(EventFlags::INTEGRITY_INCIDENT));
    store.shutdown();
}

#[test]
fn keychain_unavailable_full_verify_does_not_complete() {
    // Without the anchor checks a run is not a pass: no `VERIFY {result: ok}` is appended,
    // and no incident either (an unavailable keychain is never one, §8.8).
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_mixed(&store, 4);
    store.shutdown();
    let store = reopen(&f);
    let head = store.head().0;
    f.ring.set_unavailable(true);
    assert_eq!(
        store.try_full_verify(),
        Err(AuditError::KeyStore(KeyStoreError::Unavailable))
    );
    let fs = store.full_verify();
    f.ring.set_unavailable(false);
    assert_eq!(kinds(&fs), vec![FindingKind::ChainBroken]);
    assert!(fs[0].detail.contains("did not complete"), "{fs:?}");
    assert_eq!(store.head().0, head, "no VERIFY appended");
    assert!(store.open_incidents().is_empty());
    store.shutdown();
}

#[test]
fn u22_latest_prune_that_does_not_decrypt_is_not_reconciled() {
    // (c) needs the latest PRUNE to verify: with its DEK destroyed its row hash is unchecked.
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    corroborate(&store);
    append_mixed(&store, 10);
    anchor_head(&store);
    store.testing_pause_anchors();
    let prune = fake_prune(&store, 6, false);
    store.shutdown();
    assert!(
        !verdict(&f).has_incident(),
        "reconciles before the DEK is destroyed"
    );
    raw_conn(&f)
        .execute(
            "UPDATE keys SET wrapped_dek = NULL, destroyed_at = '2026-10-08T12:00:00.000Z' \
             WHERE key_id = (SELECT key_id FROM events WHERE seq = ?1)",
            [prune as i64],
        )
        .expect("destroy");
    let v = verdict(&f);
    assert!(
        has(&v.findings, FindingKind::DestroyedKeyReferenced, prune),
        "{:?}",
        v.findings
    );
    assert!(
        has_kind(&v.findings, FindingKind::FirstRetainedMismatch),
        "{:?}",
        v.findings
    );
    assert!(!has_kind(
        &v.findings,
        FindingKind::InterruptedPruneReconciled
    ));
    assert!(v.anchor_actions.set_first_retained.is_none());
}
