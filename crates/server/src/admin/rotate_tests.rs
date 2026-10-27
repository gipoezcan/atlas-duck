//! `admin rotate-master-key` (M13 T7) over the in-memory store and real user stores.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use super::rotate::run_with;
use super::*;
use crate::anchor::KIND_MASTER_KEY_ROTATED;
use crate::api_keys::ApiKeyParams;
use crate::clock::ManualClock;
use crate::directory::stub::StubDirectory;
use crate::health::Health;
use crate::master_key::{MasterKey, WrappedKey};
use crate::runtime::tests::Env;

const LIMIT: Duration = Duration::from_secs(60);
const OLD: [u8; 32] = [4; 32]; // runtime::tests::Env's key "k1"
const NEW: [u8; 32] = [0x42; 32];

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIMIT, f).await.expect("timed out")
}

/// An admin context over `env`'s store with `master` as the loaded keys.
fn ctx_with(env: &Env, master: Arc<MasterKey>) -> Arc<AdminCtx> {
    let clock = ManualClock::at(1_800_000_000);
    let mut deps = env.deps();
    deps.master = master;
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
    Arc::new(AdminCtx::new(
        env.store.clone(),
        registry,
        sessions,
        api_keys,
        writer,
        clock,
        DEFAULT_RETENTION_DAYS,
    ))
}

fn key_file(dir: &std::path::Path, id: &str, bytes: &[u8]) -> String {
    let p = dir.join(format!("{id}.key"));
    std::fs::write(
        &p,
        format!("atlas-duck-master-key/v1 {id} {}\n", STANDARD.encode(bytes)),
    )
    .unwrap();
    p.display().to_string()
}

async fn rotate(ctx: &AdminCtx, file: &str) -> Response {
    within(handle(
        ctx,
        Request::RotateMasterKey(KeyFileArg {
            new_key_file: file.to_owned(),
        }),
    ))
    .await
}

fn key_ids(env: &Env) -> Vec<String> {
    env.store
        .users_all()
        .unwrap()
        .iter()
        .map(|(u, _)| {
            WrappedKey::from_json(&u.data_key_wrapped)
                .unwrap()
                .master_key_id
        })
        .collect()
}

/// Every user's store opens with `master` alone (so its data key unwraps to the same key).
async fn all_open_with(env: &Env, master: MasterKey) {
    let mut deps = env.deps();
    deps.master = Arc::new(master);
    let reg = Registry::new(deps, 10);
    for (u, _) in env.store.users_all().unwrap() {
        within(reg.open_user(&u.user_id)).await.unwrap();
    }
    within(reg.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotate_rewraps_every_user_data_key_with_new_version() {
    let env = Env::new();
    for name in ["alice", "bob", "carol"] {
        env.user(name);
    }
    // Stores exist (first open), then close: the data keys are now in use.
    all_open_with(&env, MasterKey::for_tests("k1", OLD)).await;
    let ctx = ctx_with(&env, Arc::new(MasterKey::for_tests("k1", OLD)));
    let r = rotate(&ctx, &key_file(env.dir.path(), "k2", &NEW)).await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.data.unwrap()["rewrapped"], 3);
    assert_eq!(key_ids(&env), ["k2", "k2", "k2"]);
    // The loaded ring now wraps new users under k2.
    assert_eq!(ctx.registry.deps().master.id(), "k2");
    let (d, _) = crate::users::ensure_user(
        env.store.as_ref(),
        &ctx.registry.deps().master,
        "dave",
        None,
        vec!["user".into()],
        0,
    )
    .unwrap();
    let w = d.data_key_wrapped;
    assert_eq!(WrappedKey::from_json(&w).unwrap().master_key_id, "k2");
    // The new key alone opens every user; the old one alone opens none.
    all_open_with(&env, MasterKey::for_tests("k2", NEW)).await;
    let mut deps = env.deps();
    deps.master = Arc::new(MasterKey::for_tests("k1", OLD));
    let reg = Registry::new(deps, 10);
    let (u, _) = &env.store.users_all().unwrap()[0];
    assert!(within(reg.open_user(&u.user_id)).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotate_is_crash_safe() {
    let env = Env::new();
    for name in ["alice", "bob", "carol"] {
        env.user(name);
    }
    all_open_with(&env, MasterKey::for_tests("k1", OLD)).await;
    let ctx = ctx_with(&env, Arc::new(MasterKey::for_tests("k1", OLD)));
    // A crash after one row.
    assert_eq!(
        run_with(&ctx, MasterKey::for_tests("k2", NEW), Some(1)).unwrap_err(),
        "rotate/interrupted"
    );
    let mut ids = key_ids(&env);
    ids.sort();
    assert_eq!(ids, ["k1", "k1", "k2"], "every row is under some key");
    // The restarted server loads both keys (ATLAS_DUCK_MASTER_KEY_NEXT_FILE) and opens everyone.
    let both = MasterKey::for_tests("k1", OLD);
    both.accept(MasterKey::for_tests("k2", NEW)).unwrap();
    all_open_with(&env, both).await;
    let both = MasterKey::for_tests("k1", OLD);
    both.accept(MasterKey::for_tests("k2", NEW)).unwrap();
    let ctx = ctx_with(&env, Arc::new(both));
    // Running it again re-wraps only what is left.
    let out = run_with(&ctx, MasterKey::for_tests("k2", NEW), None).unwrap();
    assert_eq!(out["rewrapped"], 2);
    assert_eq!(out["already_rewrapped"], 1);
    assert_eq!(key_ids(&env), ["k2", "k2", "k2"]);
    all_open_with(&env, MasterKey::for_tests("k2", NEW)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotate_refuses_same_key() {
    let env = Env::new();
    env.user("alice");
    let ctx = ctx_with(&env, Arc::new(MasterKey::for_tests("k1", OLD)));
    let dir = env.dir.path();
    for (file, why) in [
        (key_file(dir, "k1", &OLD), "same id and bytes"),
        (key_file(dir, "k9", &OLD), "same bytes under a new id"),
    ] {
        let r = rotate(&ctx, &file).await;
        assert_eq!(r.error.as_deref(), Some("rotate/same_key"), "{why}");
    }
    // Same id, other bytes: refused too (the id must change with the key).
    let other = dir.join("other");
    std::fs::create_dir_all(&other).unwrap();
    let r = rotate(&ctx, &key_file(&other, "k1", &NEW)).await;
    assert_eq!(r.error.as_deref(), Some("rotate/same_key"));
    assert_eq!(key_ids(&env), ["k1"]);
    assert_eq!(ctx.registry.deps().master.ids(), ["k1"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotate_refuses_wrong_length_key_file() {
    let env = Env::new();
    env.user("alice");
    let ctx = ctx_with(&env, Arc::new(MasterKey::for_tests("k1", OLD)));
    let dir = env.dir.path();
    for file in [
        key_file(dir, "k2", &[0x42; 31]),
        key_file(dir, "k3", &[0x42; 33]),
        dir.join("missing.key").display().to_string(),
    ] {
        let r = rotate(&ctx, &file).await;
        assert_eq!(
            r.error.as_deref(),
            Some("rotate/key_file_invalid"),
            "{file}"
        );
    }
    assert_eq!(key_ids(&env), ["k1"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotate_appends_master_key_rotated_with_old_and_new_key_ids_only() {
    let env = Env::new();
    for name in ["alice", "bob"] {
        env.user(name);
    }
    let ctx = ctx_with(&env, Arc::new(MasterKey::for_tests("k1", OLD)));
    assert!(rotate(&ctx, &key_file(env.dir.path(), "k2", &NEW)).await.ok);
    let last = env.store.anchor_last().unwrap().unwrap();
    assert_eq!(last.kind, KIND_MASTER_KEY_ROTATED);
    let body: Value = serde_json::from_slice(&last.body_jcs).unwrap();
    assert_eq!(
        body,
        json!({"old_key_id": "k1", "new_key_id": "k2", "users": 2})
    );
    assert!(env.store.anchor_heads_for(last.seq).unwrap().is_empty());
    crate::anchor::verify(env.store.as_ref()).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_with_old_key_after_completed_rotation_fails_readyz_with_clear_reason() {
    let env = Env::new();
    env.user("alice");
    let ctx = ctx_with(&env, Arc::new(MasterKey::for_tests("k1", OLD)));
    assert!(rotate(&ctx, &key_file(env.dir.path(), "k2", &NEW)).await.ok);
    let stub = Arc::new(StubDirectory::from_json(r#"{"users": []}"#).unwrap());
    // The old key mounted again (the Secret was not swapped): not ready, and it says why.
    let health = Health::new(env.store.clone(), stub.clone(), true)
        .with_master(Arc::new(MasterKey::for_tests("k1", OLD)));
    let res = health.readyz().await;
    assert_eq!(res.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), 1 << 16)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["reasons"], json!(["master_key_mismatch"]));
    assert_eq!(body["checks"]["master_key"], false);
    // With the new key it is ready.
    let health = Health::new(env.store.clone(), stub, true)
        .with_master(Arc::new(MasterKey::for_tests("k2", NEW)));
    assert_eq!(health.readyz().await.status(), axum::http::StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotate_output_contains_no_key_bytes() {
    let env = Env::new();
    let a = env.user("alice");
    let ctx = ctx_with(&env, Arc::new(MasterKey::for_tests("k1", OLD)));
    let before = env.store.user(&a).unwrap().unwrap().data_key_wrapped;
    let r = rotate(&ctx, &key_file(env.dir.path(), "k2", &NEW)).await;
    assert!(r.ok);
    let text = serde_json::to_string(&r).unwrap();
    let after = env.store.user(&a).unwrap().unwrap().data_key_wrapped;
    let ct = |w: &str| WrappedKey::from_json(w).unwrap().ct;
    for secret in [
        STANDARD.encode(OLD),
        STANDARD.encode(NEW),
        hex::encode(OLD),
        hex::encode(NEW),
        ct(&before),
        ct(&after),
    ] {
        assert!(!text.contains(&secret), "{text}");
    }
    assert_eq!(
        r.data.unwrap(),
        json!({"old_key_id": "k1", "new_key_id": "k2", "rewrapped": 1, "already_rewrapped": 0})
    );
    // Debug output of the loaded keys shows ids only.
    let shown = format!("{:?}", ctx.registry.deps().master);
    assert!(
        !shown.contains("66, 66") && !shown.contains("4, 4"),
        "{shown}"
    );
}
