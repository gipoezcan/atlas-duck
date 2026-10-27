//! The server anchor chain: rows, leaves, verification and the writer over real user runtimes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::clock::ManualClock;
use crate::runtime::tests::Env;
use crate::store::sqlite::SqliteStore;

const LIMIT: Duration = Duration::from_secs(60);

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIMIT, f).await.expect("timed out")
}

fn sqlite() -> SqliteStore {
    SqliteStore::open_in_memory().unwrap()
}

fn head(n: u8) -> AnchorHead {
    AnchorHead {
        user_id: format!("user{n}"),
        chain_id: format!("chain{n}"),
        head_seq: u64::from(n),
        record_hash: [n; 32],
    }
}

/// A HEADS row over `heads`, written the way the writer writes it.
fn heads_row(s: &dyn ServerStore, now: i64, heads: &[AnchorHead]) -> AnchorRow {
    let leaves: Vec<[u8; 32]> = heads
        .iter()
        .map(|h| leaf_hash(&h.user_id, &h.chain_id, h.head_seq, &h.record_hash))
        .collect();
    append_raw(s, now, KIND_HEADS, &heads_body_jcs(&leaves).unwrap(), heads).unwrap()
}

#[test]
fn operational_rows_chain_with_the_v2_hash() {
    let s = sqlite();
    let body =
        json!({"username": "alice", "source_ip": "192.0.2.1", "reason": "invalid_credentials"});
    let r1 = append_operational(&s, 1_800_000_000, KIND_LOGIN_FAILED, &body).unwrap();
    let r2 = append_operational(&s, 1_800_000_001, KIND_LOGIN_FAILED, &body).unwrap();
    assert_eq!(
        r1.body_jcs,
        br#"{"reason":"invalid_credentials","source_ip":"192.0.2.1","username":"alice"}"#
    );
    assert_eq!(
        r1.hash,
        row_hash(1, &r1.ts_utc, "LOGIN_FAILED", &r1.body_jcs, &[0; 32])
    );
    assert_eq!(r2.prev_hash, r1.hash);
    assert_eq!(
        r2.hash,
        row_hash(2, &r2.ts_utc, "LOGIN_FAILED", &r2.body_jcs, &r1.hash)
    );
}

#[test]
fn a_chain_of_100_rows_verifies() {
    let s = sqlite();
    for i in 0..100u8 {
        if i % 3 == 0 {
            heads_row(
                &s,
                1_800_000_000 + i64::from(i),
                &[head(i), head(i.wrapping_add(100))],
            );
        } else {
            append_operational(
                &s,
                1_800_000_000 + i64::from(i),
                KIND_LOGIN_FAILED,
                &json!({"i": i}),
            )
            .unwrap();
        }
    }
    let report = verify(&s).unwrap();
    assert_eq!((report.rows, report.last_seq), (100, 100));
    assert_eq!(report.last_hash, s.anchor_last().unwrap().unwrap().hash);
}

#[test]
fn a_flipped_body_byte_is_bad_hash() {
    let s = sqlite();
    for i in 0..6 {
        append_operational(&s, i, KIND_LOGIN_FAILED, &json!({"i": i})).unwrap();
    }
    {
        let c = s.raw();
        c.execute_batch("DROP TRIGGER anchor_chain_no_update;")
            .unwrap();
        c.execute(
            "UPDATE anchor_chain SET body_jcs = X'7B7D' WHERE seq = 5",
            [],
        )
        .unwrap();
    }
    assert_eq!(verify(&s), Err(AnchorError::BadHash { seq: 5 }));
}

#[test]
fn a_deleted_heads_entry_is_leaf_mismatch() {
    let s = sqlite();
    append_operational(&s, 0, KIND_GENESIS, &json!({})).unwrap();
    heads_row(&s, 1, &[head(1), head(2)]);
    {
        let c = s.raw();
        c.execute_batch("DROP TRIGGER anchor_heads_no_delete;")
            .unwrap();
        c.execute("DELETE FROM anchor_heads WHERE user_id = 'user2'", [])
            .unwrap();
    }
    assert_eq!(verify(&s), Err(AnchorError::LeafMismatch { seq: 2 }));
}

#[test]
fn a_deleted_row_is_a_gap_and_a_relinked_one_a_broken_link() {
    let s = sqlite();
    for i in 0..5 {
        append_operational(&s, i, KIND_LOGIN_FAILED, &json!({"i": i})).unwrap();
    }
    {
        let c = s.raw();
        c.execute_batch(
            "DROP TRIGGER anchor_chain_no_delete; DROP TRIGGER anchor_chain_no_update;",
        )
        .unwrap();
        c.execute("DELETE FROM anchor_chain WHERE seq = 3", [])
            .unwrap();
    }
    assert_eq!(verify(&s), Err(AnchorError::Gap { seq: 3 }));
    let s2 = sqlite();
    for i in 0..3 {
        append_operational(&s2, i, KIND_LOGIN_FAILED, &json!({"i": i})).unwrap();
    }
    {
        let c = s2.raw();
        c.execute_batch("DROP TRIGGER anchor_chain_no_update;")
            .unwrap();
        c.execute(
            "UPDATE anchor_chain SET prev_hash = zeroblob(32) WHERE seq = 2",
            [],
        )
        .unwrap();
    }
    assert_eq!(verify(&s2), Err(AnchorError::BrokenLink { seq: 2 }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_writer_anchors_changed_heads_only_and_names_no_user() {
    let env = Env::new();
    let (a, b) = (env.user("alice"), env.user("bob"));
    let registry = Arc::new(crate::runtime::Registry::new(env.deps(), 10));
    let clock = ManualClock::at(1_800_000_000);
    let w = AnchorWriter::new(env.store.clone(), registry.clone(), clock.clone());
    w.start(&json!({"version": "test"})).unwrap();
    let kinds: Vec<String> = env
        .store
        .anchor_all()
        .unwrap()
        .into_iter()
        .map(|r| r.kind)
        .collect();
    assert_eq!(kinds, [KIND_GENESIS, KIND_SERVER_START]);
    assert_eq!(
        within(w.tick()).await.unwrap(),
        None,
        "nothing open, nothing due"
    );
    let ra = within(registry.open_user(&a)).await.unwrap();
    within(registry.open_user(&b)).await.unwrap();
    let first = within(w.tick()).await.unwrap().unwrap();
    assert_eq!(env.store.anchor_heads_for(first.seq).unwrap().len(), 2);
    let body = String::from_utf8(first.body_jcs.clone()).unwrap();
    assert!(!body.contains(&a) && !body.contains(&b), "{body}");
    assert!(!body.contains("alice"));
    // No change: no row.
    clock.advance(900);
    assert_eq!(within(w.tick()).await.unwrap(), None);
    // A's head moves: only A is anchored.
    within(ra.append_server_record(atlas_duck_audit::EventType::LOGIN, Default::default()))
        .await
        .unwrap();
    clock.advance(900);
    let second = within(w.tick()).await.unwrap().unwrap();
    let heads = env.store.anchor_heads_for(second.seq).unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].user_id, a);
    assert_eq!(
        (
            heads[0].chain_id.clone(),
            heads[0].head_seq,
            heads[0].record_hash
        ),
        ra.head()
    );
    // 24 h later every user is anchored again, changed or not.
    clock.advance(REANCHOR_SECS);
    let daily = within(w.tick()).await.unwrap().unwrap();
    assert_eq!(env.store.anchor_heads_for(daily.seq).unwrap().len(), 2);
    within(w.shutdown()).await.unwrap();
    let kinds: Vec<String> = env
        .store
        .anchor_all()
        .unwrap()
        .into_iter()
        .map(|r| r.kind)
        .collect();
    assert_eq!(kinds.last().map(String::as_str), Some(KIND_SERVER_STOP));
    assert_eq!(
        kinds.iter().filter(|k| *k == KIND_RUNTIME_CLOSED).count(),
        2
    );
    verify(env.store.as_ref()).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eviction_writes_runtime_closed_with_the_heads_leaf() {
    let env = Env::new();
    let (a, b) = (env.user("alice"), env.user("bob"));
    let registry = Arc::new(crate::runtime::Registry::new(env.deps(), 1));
    let w = AnchorWriter::new(
        env.store.clone(),
        registry.clone(),
        ManualClock::at(1_800_000_000),
    );
    within(registry.open_user(&a)).await.unwrap();
    within(registry.open_user(&b)).await.unwrap();
    assert_eq!(w.record_closed().unwrap(), 1);
    let row = env.store.anchor_last().unwrap().unwrap();
    assert_eq!(row.kind, KIND_RUNTIME_CLOSED);
    let entry = &env.store.anchor_heads_for(row.seq).unwrap()[0];
    assert_eq!(entry.user_id, a);
    let leaf = leaf_hash(&a, &entry.chain_id, entry.head_seq, &entry.record_hash);
    assert_eq!(row.body_jcs, leaf_body_jcs(&leaf));
    // The evicted runtime's head is its head after APP_STOP: reopening it continues from there.
    let reopened = within(registry.open_user(&a)).await.unwrap();
    assert!(reopened.head().1 > entry.head_seq);
    within(registry.close_all()).await;
    verify(env.store.as_ref()).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchor_user_now_names_the_users_head_even_unchanged() {
    let env = Env::new();
    let a = env.user("alice");
    let registry = Arc::new(crate::runtime::Registry::new(env.deps(), 10));
    let clock = ManualClock::at(1_800_000_000);
    let w = AnchorWriter::new(env.store.clone(), registry.clone(), clock.clone());
    w.start(&json!({"version": "test"})).unwrap();
    let ra = within(registry.open_user(&a)).await.unwrap();
    within(w.tick()).await.unwrap().unwrap();
    // The head did not change since that tick; anchor-now still writes a row.
    let r = w.anchor_user_now(&a, &ra.head()).unwrap();
    let row = env.store.anchor_last().unwrap().unwrap();
    assert_eq!(
        (row.seq, row.hash, row.kind.as_str()),
        (r.seq, r.hash, KIND_HEADS)
    );
    let (chain, seq, hash) = ra.head();
    assert_eq!(r.head_seq, seq);
    assert_eq!(
        row.body_jcs,
        heads_body_jcs(&[leaf_hash(&a, &chain, seq, &hash)]).unwrap()
    );
    let heads = env.store.anchor_heads_for(r.seq).unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(
        (
            heads[0].user_id.as_str(),
            heads[0].chain_id.clone(),
            heads[0].head_seq,
            heads[0].record_hash
        ),
        (a.as_str(), chain, seq, hash)
    );
    assert_eq!(
        super::head(env.store.as_ref()).unwrap(),
        Some((r.seq, r.hash))
    );
    // It counts as an anchoring: the next tick has nothing due.
    clock.advance(900);
    assert_eq!(within(w.tick()).await.unwrap(), None);
    verify(env.store.as_ref()).unwrap();
}
