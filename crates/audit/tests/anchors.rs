//! Keychain anchors (§8.5, §8.7, §8.8): entry layouts, the batching anchor thread, flush,
//! "no anchor before verification", prune/restore barriers and keychain failures.
//! The anchor thread runs on real time (`Instant`), so waits poll with a deadline.

mod common;

use std::time::{Duration, Instant};

use atlas_duck_audit::anchors::{AnchorEntryError, FirstRetainedAnchor, HeadAnchor};
use atlas_duck_audit::error::AuditError;
use atlas_duck_audit::keystore::{EntryName, KeyStoreError, service_name};
use atlas_duck_audit::testing::{KeyOpKind, MemKeyring};
use atlas_duck_audit::types::EventType;
use atlas_duck_audit::{OpenConfig, Store};
use common::*;
use serde_json::json;

fn keychain_head(f: &Fixture) -> HeadAnchor {
    let b = f
        .ring
        .raw_get(&service_name(&f.install_id), "head_anchor")
        .expect("head_anchor entry");
    HeadAnchor::from_entry(&b).expect("head anchor layout")
}

fn keychain_first_retained(f: &Fixture) -> FirstRetainedAnchor {
    let b = f
        .ring
        .raw_get(&service_name(&f.install_id), "first_retained_anchor")
        .expect("first_retained_anchor entry");
    FirstRetainedAnchor::from_entry(&b).expect("first-retained layout")
}

fn sets_of(f: &Fixture, e: EntryName) -> usize {
    let name = e.full_name(&f.install_id);
    f.ring
        .ops()
        .iter()
        .filter(|o| o.kind == KeyOpKind::Set && o.full_name == name)
        .count()
}

fn wait_until(limit: Duration, mut ok: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    loop {
        if ok() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn append_n(store: &Store, n: usize) {
    for i in 0..n {
        store
            .append(ev(EventType::APP_START, None, json!({ "i": i })))
            .expect("append");
    }
}

fn disabled(cfg: &mut OpenConfig) {
    cfg.hooks.anchors_disabled = true;
}

fn fast_backoff(cfg: &mut OpenConfig) {
    cfg.hooks.fast_anchor_backoff = true;
}

fn first_retained_for(store: &Store, seq: u64, hash: [u8; 32]) -> FirstRetainedAnchor {
    FirstRetainedAnchor {
        chain_id: store.head().2,
        genesis_hash: [7; 32],
        first_retained_seq: seq,
        first_retained_prev_hash: hash,
    }
}

#[test]
fn anchor_entry_layouts() {
    let h = HeadAnchor {
        chain_id: "ab".repeat(16),
        seq: 51,
        record_hash: [0xAB; 32],
    };
    let e = h.to_entry().expect("encode");
    assert_eq!(e[0], 0x01);
    let want = format!(
        r#"{{"chain_id":"{}","record_hash":"{}","seq":51}}"#,
        "ab".repeat(16),
        "ab".repeat(32)
    );
    assert_eq!(&e[1..], want.as_bytes());
    assert_eq!(HeadAnchor::from_entry(&e), Ok(h));

    let fr = FirstRetainedAnchor {
        chain_id: "cd".repeat(16),
        genesis_hash: [1; 32],
        first_retained_seq: 5,
        first_retained_prev_hash: [2; 32],
    };
    let e = fr.to_entry().expect("encode");
    assert_eq!(e[0], 0x01);
    let body = std::str::from_utf8(&e[1..]).expect("utf8");
    let order: Vec<usize> = [
        "chain_id",
        "first_retained_prev_hash",
        "first_retained_seq",
        "genesis_hash",
    ]
    .iter()
    .map(|k| body.find(k).expect("key"))
    .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{body}");
    assert_eq!(FirstRetainedAnchor::from_entry(&e), Ok(fr));

    let mut newer = e.clone();
    newer[0] = 2;
    assert_eq!(
        FirstRetainedAnchor::from_entry(&newer),
        Err(AnchorEntryError::NewerLayout(2))
    );
    assert_eq!(
        HeadAnchor::from_entry(&[2, b'{', b'}']),
        Err(AnchorEntryError::NewerLayout(2))
    );
    assert_eq!(
        HeadAnchor::from_entry(&[]),
        Err(AnchorEntryError::Malformed)
    );
    assert_eq!(
        HeadAnchor::from_entry(b"\x01{}"),
        Err(AnchorEntryError::Malformed)
    );
}

#[test]
fn head_anchor_batched_within_one_second() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let before = sets_of(&f, EntryName::HeadAnchor);
    append_n(&store, 50);
    assert_eq!(store.head().0, 51);
    assert!(
        wait_until(Duration::from_millis(1500), || keychain_head(&f).seq == 51),
        "head anchor did not reach seq 51 within 1.5 s"
    );
    let h = keychain_head(&f);
    assert_eq!((h.seq, h.record_hash), (51, store.head().1));
    let writes = sets_of(&f, EntryName::HeadAnchor) - before;
    assert!(
        (1..10).contains(&writes),
        "{writes} head anchor writes for 50 events"
    );
    assert!(!store.health().anchor_write_failing);
}

#[test]
fn flush_on_demand() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_n(&store, 3);
    store.flush_head_anchor().expect("flush");
    let h = keychain_head(&f);
    assert_eq!((h.seq, h.record_hash), (4, store.head().1));
    // Nothing left to write: a second flush writes nothing.
    let n = sets_of(&f, EntryName::HeadAnchor);
    store.flush_head_anchor().expect("flush");
    assert_eq!(sets_of(&f, EntryName::HeadAnchor), n);
}

#[test]
fn flush_after_app_stop_then_shutdown() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_n(&store, 2);
    let stop = store
        .append(ev(EventType::APP_STOP, None, json!({})))
        .expect("APP_STOP");
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    let h = keychain_head(&f);
    assert_eq!((h.seq, h.record_hash), (stop.seq, stop.record_hash));
    assert_eq!(store.flush_head_anchor(), Err(AuditError::Closed));
}

#[test]
fn no_anchor_while_disabled() {
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), disabled);
    let heads = sets_of(&f, EntryName::HeadAnchor);
    let firsts = sets_of(&f, EntryName::FirstRetainedAnchor);
    append_n(&store, 5);
    std::thread::sleep(Duration::from_millis(1300));
    assert_eq!(store.flush_head_anchor(), Ok(()));
    assert_eq!(sets_of(&f, EntryName::HeadAnchor), heads);
    assert_eq!(sets_of(&f, EntryName::FirstRetainedAnchor), firsts);
    assert_eq!(keychain_head(&f).seq, 1);

    store.testing_enable_anchors();
    assert!(
        wait_until(Duration::from_secs(3), || keychain_head(&f).seq == 6),
        "head anchor not written after enable"
    );
}

#[test]
fn head_anchor_stops_at_unfinished_prune() {
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), fast_backoff);
    append_n(&store, 2);
    store.flush_head_anchor().expect("flush");
    let (n, hash, _) = store.head();
    assert_eq!(n, 3);
    let fr = first_retained_for(&store, 3, hash);
    let old_fr = keychain_first_retained(&f);
    f.ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::FirstRetainedAnchor),
        KeyStoreError::Unavailable,
        3,
    );
    store.testing_prune_barrier(n, hash, fr.clone());
    append_n(&store, 10);
    assert!(
        wait_until(Duration::from_secs(3), || {
            let h = store.health();
            h.anchor_write_failing && h.first_retained_update_pending
        }),
        "failing prune update not reported"
    );
    // While the update fails the head anchor never passes the PRUNE seq.
    let mut cleared = false;
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end {
        assert!(keychain_head(&f).seq <= n);
        if keychain_first_retained(&f) == fr {
            cleared = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(cleared, "first-retained entry never updated");
    assert_ne!(old_fr, fr);
    assert!(
        wait_until(Duration::from_secs(3), || keychain_head(&f).seq == 13),
        "head anchor did not reach the newest seq after the update"
    );
    assert!(wait_until(Duration::from_secs(1), || {
        let h = store.health();
        !h.anchor_write_failing && !h.first_retained_update_pending
    }));
}

#[test]
fn prune_update_precedes_head_write() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_n(&store, 2);
    let (n, hash, _) = store.head();
    // A first-retained write that keeps failing holds the barrier.
    f.ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::FirstRetainedAnchor),
        KeyStoreError::Unavailable,
        1000,
    );
    store.testing_prune_barrier(n, hash, first_retained_for(&store, 3, hash));
    append_n(&store, 4);
    // An explicit flush still writes the capped head.
    assert_eq!(
        store.flush_head_anchor(),
        Err(AuditError::KeyStore(KeyStoreError::Unavailable))
    );
    assert_eq!(keychain_head(&f).seq, 1, "first-retained comes first");
}

#[test]
fn restore_barrier_blocks_head() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_n(&store, 2);
    store.flush_head_anchor().expect("flush");
    let heads = sets_of(&f, EntryName::HeadAnchor);
    store.testing_restore_barrier(3);
    append_n(&store, 3);
    std::thread::sleep(Duration::from_millis(1300));
    assert_eq!(store.flush_head_anchor(), Ok(()));
    assert_eq!(sets_of(&f, EntryName::HeadAnchor), heads);
    assert_eq!(keychain_head(&f).seq, 3);

    let (seq, hash, chain_id) = store.head();
    let head = HeadAnchor {
        chain_id,
        seq,
        record_hash: hash,
    };
    let fr = first_retained_for(&store, 1, [0; 32]);
    // A head before the RESTORE record does not describe the restored DB.
    let stale = HeadAnchor {
        seq: 2,
        ..head.clone()
    };
    assert!(matches!(
        store.testing_complete_restore_anchors(stale, fr.clone()),
        Err(AuditError::Invalid(_))
    ));
    store
        .testing_complete_restore_anchors(head.clone(), fr.clone())
        .expect("complete restore");
    assert_eq!(keychain_head(&f), head);
    assert_eq!(keychain_first_retained(&f), fr);

    // The barrier is gone: later commits are anchored again.
    append_n(&store, 1);
    assert!(wait_until(Duration::from_secs(3), || keychain_head(&f).seq == 7));
    // And a second completion has no barrier to lift.
    assert!(matches!(
        store.testing_complete_restore_anchors(head, fr),
        Err(AuditError::Invalid(_))
    ));
}

#[test]
fn drop_never_writes() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let heads = sets_of(&f, EntryName::HeadAnchor);
    append_n(&store, 3);
    store.shutdown();
    drop(store);
    assert_eq!(keychain_head(&f).seq, 1);
    assert_eq!(sets_of(&f, EntryName::HeadAnchor), heads);

    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    append_n(&store, 3);
    drop(store);
    assert_eq!(keychain_head(&f).seq, 1);
}

#[test]
fn anchor_failure_is_not_an_incident() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    f.ring.set_unavailable(true);
    append_n(&store, 4);
    assert!(
        wait_until(Duration::from_secs(3), || store
            .health()
            .anchor_write_failing),
        "failing anchor write not reported"
    );
    std::thread::sleep(Duration::from_secs(1));
    // The chain is untouched: five rows, no VERIFY, appends keep working.
    let rows = dump_rows(&f);
    assert_eq!(rows.len(), 5);
    assert!(rows.iter().all(|r| r.event_type != "VERIFY"));
    assert!(store.health().anchor_write_failing);
    append_n(&store, 1);
    assert_eq!(store.head().0, 6);

    // An explicit flush reports the keychain error and does not clear the state.
    assert_eq!(
        store.flush_head_anchor(),
        Err(AuditError::KeyStore(KeyStoreError::Unavailable))
    );
    assert!(store.health().anchor_write_failing);

    f.ring.set_unavailable(false);
    store.flush_head_anchor().expect("flush after recovery");
    assert_eq!(keychain_head(&f).seq, 6);
    assert!(!store.health().anchor_write_failing);
    assert_eq!(dump_rows(&f).len(), 6);
}
