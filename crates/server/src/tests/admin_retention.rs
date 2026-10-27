//! `admin retention run` and `admin anchor verify` (M13 T8).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::anchor::{KIND_CHAIN_DELETED, KIND_RETENTION_RUN, verify};
use crate::api_keys::ApiKeyParams;
use crate::clock::ManualClock;
use crate::runtime::tests::Env;

const LIMIT: Duration = Duration::from_secs(60);
const DAY: i64 = 86_400;

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIMIT, f).await.expect("timed out")
}

struct T {
    env: Env,
    ctx: Arc<AdminCtx>,
    clock: Arc<ManualClock>,
}

fn harness() -> T {
    let env = Env::new();
    let clock = ManualClock::at(1_800_000_000);
    let mut deps = env.deps();
    deps.clock = clock.clone();
    let registry = Arc::new(Registry::new(deps, 10));
    let sessions =
        Arc::new(SessionTable::new(env.store.clone(), clock.clone(), 28_800, 1_800).unwrap());
    let api_keys =
        Arc::new(ApiKeys::new(env.store.clone(), clock.clone(), ApiKeyParams::TEST).unwrap());
    let writer = Arc::new(AnchorWriter::new(
        env.store.clone(),
        registry.clone(),
        clock.clone(),
    ));
    writer.start(&json!({})).unwrap();
    let ctx = Arc::new(AdminCtx::new(
        env.store.clone(),
        registry,
        sessions,
        api_keys,
        writer,
        clock.clone(),
        DEFAULT_RETENTION_DAYS,
    ));
    T { env, ctx, clock }
}

impl T {
    /// A user whose store exists and whose head is anchored (opened, then closed).
    async fn anchored_user(&self, name: &str) -> String {
        let uid = self.env.user(name);
        within(self.ctx.registry.open_user(&uid)).await.unwrap();
        let heads = within(self.ctx.registry.quiesce()).await;
        self.ctx.registry.resume();
        self.ctx.writer.record_heads(&heads).unwrap();
        uid
    }

    async fn call(&self, req: Request) -> Response {
        within(handle(&self.ctx, req)).await
    }

    async fn retention(&self, dry_run: bool) -> Value {
        let r = self
            .call(Request::RetentionRun(DryRunArg { dry_run }))
            .await;
        assert!(r.ok, "{r:?}");
        r.data.unwrap()
    }

    fn audit_db(&self, uid: &str) -> std::path::PathBuf {
        crate::users::user_dir(self.env.dir.path(), uid).join(atlas_duck_audit::DB_FILE)
    }

    fn anchored_seq(&self, uid: &str) -> u64 {
        self.env
            .store
            .anchor_latest_heads()
            .unwrap()
            .into_iter()
            .find(|h| h.user_id == uid)
            .unwrap()
            .head_seq
    }
}

/// Opens a user's audit database for tampering (its triggers dropped).
fn tamper(db: &std::path::Path, sql: &str) {
    let c = rusqlite::Connection::open(db).unwrap();
    let triggers: Vec<String> = c
        .prepare("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    for t in triggers {
        c.execute_batch(&format!("DROP TRIGGER \"{t}\";")).unwrap();
    }
    c.execute_batch(sql).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_deletes_deactivated_chain_after_period_and_records_chain_deleted() {
    let t = harness();
    let a = t.anchored_user("alice").await;
    let r = t
        .call(Request::UsersDeactivate(UsernameArg {
            username: "alice".into(),
        }))
        .await;
    assert!(r.ok, "{r:?}");
    within(t.ctx.registry.close_all()).await;
    let dir = crate::users::user_dir(t.env.dir.path(), &a);
    assert!(dir.is_dir());

    // One second before the 365-day period ends: nothing goes.
    t.clock.advance(365 * DAY - 1);
    assert_eq!(t.retention(false).await["deleted"], 0);
    assert!(dir.is_dir());
    t.clock.advance(1);
    let out = t.retention(false).await;
    assert_eq!(out["deleted"], 1);
    assert_eq!(out["due"][0]["username"], "alice");
    assert!(!dir.exists(), "the user's store is gone");
    let st = t.env.store.user_state(&a).unwrap().unwrap();
    assert_eq!(st.chain_deleted_at, Some(t.clock.now()));
    assert!(st.deactivated_at.is_some(), "the user stays refused");
    assert_eq!(t.env.store.user(&a).unwrap().unwrap().data_key_wrapped, "");

    let rows = t.env.store.anchor_all().unwrap();
    assert_eq!(rows.last().unwrap().kind, KIND_RETENTION_RUN);
    let deleted = rows.iter().find(|r| r.kind == KIND_CHAIN_DELETED).unwrap();
    let body: Value = serde_json::from_slice(&deleted.body_jcs).unwrap();
    let head = t
        .env
        .store
        .anchor_latest_heads()
        .unwrap()
        .into_iter()
        .find(|h| h.user_id == a)
        .unwrap();
    assert_eq!(
        body,
        json!({"user_id": a, "chain_id": head.chain_id, "head_seq": head.head_seq})
    );
    verify(t.env.store.as_ref()).unwrap();
    // A second run finds nothing; `users list` says deleted; anchor verify skips the user.
    assert_eq!(t.retention(false).await["deleted"], 0);
    let list = t.call(Request::UsersList(NoArgs {})).await;
    assert_eq!(list.data.unwrap()[0]["state"], "deleted");
    assert!(t.call(Request::AnchorVerify(NoArgs {})).await.ok);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_keeps_active_users_chains() {
    let t = harness();
    let b = t.anchored_user("bob").await;
    let c = t.anchored_user("carol").await;
    // Carol is deactivated but within her period; Bob never was.
    assert!(
        t.call(Request::UsersDeactivate(UsernameArg {
            username: "carol".into()
        }))
        .await
        .ok
    );
    within(t.ctx.registry.close_all()).await;
    t.clock.advance(364 * DAY);
    let out = t.retention(false).await;
    assert_eq!(
        out,
        json!({"dry_run": false, "due": [], "deleted": 0, "failed": 0})
    );
    for uid in [&b, &c] {
        assert!(crate::users::user_dir(t.env.dir.path(), uid).is_dir());
        assert_eq!(
            t.env
                .store
                .user_state(uid)
                .unwrap()
                .unwrap()
                .chain_deleted_at,
            None
        );
    }
    // Years later Bob (active) still stays.
    t.clock.advance(3650 * DAY);
    assert_eq!(t.retention(false).await["deleted"], 1);
    assert!(crate::users::user_dir(t.env.dir.path(), &b).is_dir());
    assert!(!crate::users::user_dir(t.env.dir.path(), &c).exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_dry_run_lists_without_deleting() {
    let t = harness();
    let a = t.anchored_user("alice").await;
    assert!(
        t.call(Request::UsersDeactivate(UsernameArg {
            username: "alice".into()
        }))
        .await
        .ok
    );
    within(t.ctx.registry.close_all()).await;
    t.clock.advance(366 * DAY);
    let rows = t.env.store.anchor_all().unwrap().len();
    let out = t.retention(true).await;
    assert_eq!(out["dry_run"], true);
    assert_eq!(out["deleted"], 0);
    assert_eq!(out["due"][0]["username"], "alice");
    assert_eq!(out["due"][0]["retention_until"], "2028-01-15T08:00:00.000Z");
    assert!(crate::users::user_dir(t.env.dir.path(), &a).is_dir());
    assert_eq!(
        t.env.store.anchor_all().unwrap().len(),
        rows,
        "no anchor rows"
    );
    assert_eq!(
        t.env
            .store
            .user_state(&a)
            .unwrap()
            .unwrap()
            .chain_deleted_at,
        None
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchor_verify_checks_every_user_head_against_anchor_chain() {
    let t = harness();
    let a = t.anchored_user("alice").await;
    let b = t.anchored_user("bob").await;
    let ok = t.call(Request::AnchorVerify(NoArgs {})).await;
    assert!(ok.ok, "{ok:?}");
    assert_eq!(ok.data.as_ref().unwrap()["users_checked"], 2);
    assert!(t.audit_db(&a).is_file());

    // Bob's anchored record rewritten.
    let seq = t.anchored_seq(&b);
    tamper(
        &t.audit_db(&b),
        &format!("UPDATE events SET record_hash = zeroblob(32) WHERE seq = {seq};"),
    );
    let r = t.call(Request::AnchorVerify(NoArgs {})).await;
    assert_eq!(r.error.as_deref(), Some("anchor/verify_failed"));
    let data = r.data.unwrap();
    assert_eq!(
        data["findings"],
        json!([{"kind": "head_mismatch", "username": "bob", "seq": seq}])
    );
    assert_eq!(data["ok"], false);
    // The report carries ids and seqs only.
    let text = data.to_string();
    assert!(
        !text.contains("key_x") && !text.contains("payload"),
        "{text}"
    );

    // A broken anchor chain is reported too.
    t.env
        .store
        .anchor_append("HEADS", "x", b"{}", &[], &|_, _| [9; 32])
        .unwrap();
    let r = t.call(Request::AnchorVerify(NoArgs {})).await;
    let kinds: Vec<&str> = r.data.as_ref().unwrap()["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["anchor_chain", "head_mismatch"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchor_verify_detects_truncated_user_chain() {
    let t = harness();
    let a = t.anchored_user("alice").await;
    let seq = t.anchored_seq(&a);
    tamper(
        &t.audit_db(&a),
        &format!("DELETE FROM events WHERE seq >= {seq};"),
    );
    let r = t.call(Request::AnchorVerify(NoArgs {})).await;
    assert_eq!(r.error.as_deref(), Some("anchor/verify_failed"));
    assert_eq!(
        r.data.unwrap()["findings"],
        json!([{"kind": "truncated", "username": "alice", "seq": seq}])
    );
    // A missing store is a finding as well.
    std::fs::remove_dir_all(crate::users::user_dir(t.env.dir.path(), &a)).unwrap();
    let r = t.call(Request::AnchorVerify(NoArgs {})).await;
    assert_eq!(r.data.unwrap()["findings"][0]["kind"], "store_missing");
}

/// Batch-2 review M3/M4: one user whose deletion fails does not stop the others; the run is
/// recorded as partial, and the failed user's CHAIN_DELETED (anchored before the deletion) is
/// completed by the next run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_deletion_is_partial_and_finished_by_the_next_run() {
    let t = harness();
    let a = t.anchored_user("alice").await;
    let b = t.env.user("bob");
    within(t.ctx.registry.close_all()).await;
    for uid in [&a, &b] {
        t.env.store.user_deactivate(uid, 0, "admin", 0).unwrap();
    }
    // Bob's store path is a file: removing it as a directory fails.
    let bob_dir = crate::users::user_dir(t.env.dir.path(), &b);
    std::fs::create_dir_all(bob_dir.parent().unwrap()).unwrap();
    std::fs::write(&bob_dir, "not a directory").unwrap();
    let out = t.retention(false).await;
    assert_eq!(
        (out["deleted"].clone(), out["failed"].clone()),
        (json!(1), json!(1))
    );
    assert!(
        t.env
            .store
            .user_state(&a)
            .unwrap()
            .unwrap()
            .chain_deleted_at
            .is_some()
    );
    assert!(
        t.env
            .store
            .user_state(&b)
            .unwrap()
            .unwrap()
            .chain_deleted_at
            .is_none()
    );
    let rows = t.env.store.anchor_all().unwrap();
    let body: Value = serde_json::from_slice(&rows.last().unwrap().body_jcs).unwrap();
    assert_eq!(body["failed"], 1);
    let deleted_rows = rows.iter().filter(|r| r.kind == KIND_CHAIN_DELETED).count();
    assert_eq!(
        deleted_rows, 2,
        "intent anchored before the delete, for bob too"
    );
    std::fs::remove_file(&bob_dir).unwrap();
    let out = t.retention(false).await;
    assert_eq!(
        (out["deleted"].clone(), out["failed"].clone()),
        (json!(1), json!(0))
    );
    assert!(t.call(Request::AnchorVerify(NoArgs {})).await.ok);
}

/// Batch-2 review M5: a chain marked deleted without a CHAIN_DELETED row is a finding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchor_verify_reports_a_deleted_chain_without_its_record() {
    let t = harness();
    let a = t.anchored_user("alice").await;
    t.env.store.user_deactivate(&a, 0, "admin", 0).unwrap();
    t.env.store.user_purge(&a, 1).unwrap();
    let r = t.call(Request::AnchorVerify(NoArgs {})).await;
    assert_eq!(r.error.as_deref(), Some("anchor/verify_failed"));
    assert_eq!(
        r.data.unwrap()["findings"],
        json!([{"kind": "chain_deleted_unrecorded", "username": "alice", "seq": null}])
    );
}
