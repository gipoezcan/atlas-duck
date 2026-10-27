//! User runtimes over real per-user M2 stores in a temp data dir.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use super::*;
use crate::clock::ManualClock;
use crate::store::InstanceRecord;
use crate::store::memory::MemoryStore;
use crate::users::ensure_user;

const LIMIT: Duration = Duration::from_secs(60);

pub(crate) struct Env {
    pub dir: tempfile::TempDir,
    pub store: Arc<dyn ServerStore>,
    pub master: Arc<MasterKey>,
    /// M14: the script state the registry's runtimes get (`None`: scripts off).
    pub scripts: Option<Arc<crate::scripts::ServerScripts>>,
}

impl Env {
    pub(crate) fn new() -> Env {
        let store: Arc<dyn ServerStore> = Arc::new(MemoryStore::new());
        store
            .instance_put(&InstanceRecord {
                alias: "work".into(),
                product: "jira".into(),
                base_url: "https://jira.example.test".into(),
                proxy: Some("direct".into()),
                ca_ref: None,
                is_default: true,
            })
            .unwrap();
        Env {
            dir: tempfile::tempdir().unwrap(),
            store,
            master: Arc::new(MasterKey::for_tests("k1", [4; 32])),
            scripts: None,
        }
    }

    pub(crate) fn user(&self, name: &str) -> String {
        let (u, _) = ensure_user(
            self.store.as_ref(),
            &self.master,
            name,
            None,
            vec!["user".into()],
            0,
        )
        .unwrap();
        u.user_id
    }

    pub(crate) fn deps(&self) -> RuntimeDeps {
        RuntimeDeps {
            data_dir: self.dir.path().to_path_buf(),
            store: self.store.clone(),
            master: self.master.clone(),
            org_ca: None,
            clock: ManualClock::at(1_800_000_000),
            allow_http: true,
            sse_capacity: crate::runtime::SSE_CAPACITY,
            scripts: self.scripts.clone(),
        }
    }
}

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIMIT, f).await.expect("timed out")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_opens_and_lists_the_admin_instances() {
    let env = Env::new();
    let uid = env.user("alice");
    let reg = Registry::new(env.deps(), 10);
    let ctx = UserCtx::from_authenticated(&uid);
    let rt = within(reg.runtime(&ctx)).await.unwrap();
    let env_json = serde_json::to_value(within(rt.handler().instances_list()).await).unwrap();
    let text = env_json.to_string();
    assert!(text.contains("\"work\""), "{text}");
    assert_eq!(env_json["status"], "succeeded", "{text}");
    // The user's own store exists under its id.
    assert!(
        env.dir
            .path()
            .join("users")
            .join(&uid)
            .join(atlas_duck_audit::DB_FILE)
            .exists()
    );
    // A second open returns the same runtime.
    let again = within(reg.runtime(&ctx)).await.unwrap();
    assert!(Arc::ptr_eq(&rt, &again));
    within(reg.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reopen_after_close_uses_the_existing_store_and_logs_app_stop() {
    let env = Env::new();
    let uid = env.user("alice");
    let reg = Registry::new(env.deps(), 10);
    let rt = within(reg.open_user(&uid)).await.unwrap();
    let (chain, seq_open, _) = rt.head();
    drop(rt);
    let heads = within(reg.close_all()).await;
    assert_eq!(heads.len(), 1);
    let (_, (chain_after, seq_closed, _)) = &heads[0];
    assert_eq!(chain_after, &chain);
    assert!(*seq_closed > seq_open, "APP_STOP appended at close");
    // A new registry opens the same store (same chain), not a new one.
    let reg = Registry::new(env.deps(), 10);
    let rt = within(reg.open_user(&uid)).await.unwrap();
    assert_eq!(rt.head().0, chain);
    within(reg.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_first_creation_is_retried_on_the_next_open() {
    let env = Env::new();
    let uid = env.user("alice");
    // A file where the user's directory must go: the first open fails.
    let users = env.dir.path().join("users");
    std::fs::create_dir_all(&users).unwrap();
    let blocker = users.join(&uid);
    std::fs::write(&blocker, b"x").unwrap();
    let reg = Registry::new(env.deps(), 10);
    assert!(within(reg.open_user(&uid)).await.is_err());
    std::fs::remove_file(&blocker).unwrap();
    within(reg.open_user(&uid)).await.unwrap();
    within(reg.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_runtime_held_by_a_request_is_not_evicted() {
    // Batch-3 review I3: a bare `Arc` from `runtime()` keeps the runtime open.
    let env = Env::new();
    let (a, b) = (env.user("alice"), env.user("bob"));
    let reg = Registry::new(env.deps(), 1);
    let ra = within(reg.open_user(&a)).await.unwrap();
    let rb = within(reg.open_user(&b)).await.unwrap();
    assert!(reg.take_closed_heads().is_empty(), "A is in use");
    assert_eq!(within(reg.open_runtimes()).await.len(), 2);
    // The request still works on A's runtime.
    let seq = ra.head().1;
    within(ra.append_server_record(
        atlas_duck_audit::EventType::CREDENTIAL_CHANGED,
        serde_json::Map::new(),
    ))
    .await
    .unwrap();
    assert_eq!(ra.head().1, seq + 1);
    drop((ra, rb));
    within(reg.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_streams_are_capped_per_user() {
    let env = Env::new();
    let a = env.user("alice");
    let reg = Registry::new(env.deps(), 4);
    let ra = within(reg.open_user(&a)).await.unwrap();
    let pins: Vec<_> = (0..MAX_SSE_STREAMS)
        .map(|_| ra.try_sse_pin().expect("under the cap"))
        .collect();
    assert!(ra.try_sse_pin().is_none(), "the ninth stream is refused");
    drop(pins);
    assert!(
        ra.try_sse_pin().is_some(),
        "closed streams free their slots"
    );
    drop(ra);
    within(reg.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eviction_honours_pins_and_lru() {
    let env = Env::new();
    let (a, b, c) = (env.user("alice"), env.user("bob"), env.user("carol"));
    let reg = Registry::new(env.deps(), 2);
    let ra = within(reg.open_user(&a)).await.unwrap();
    let rb = within(reg.open_user(&b)).await.unwrap();
    // A streams SSE: it is pinned, so opening C evicts B (not the older A).
    let pin = ra.sse_pin();
    drop((ra, rb));
    within(reg.open_user(&c)).await.unwrap();
    let ids: Vec<String> = within(reg.open_runtimes())
        .await
        .iter()
        .map(|r| r.user_id().to_owned())
        .collect();
    assert!(
        ids.contains(&a) && ids.contains(&c) && !ids.contains(&b),
        "{ids:?}"
    );
    let closed = reg.take_closed_heads();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].0, b);
    // With every runtime pinned, opening goes above the cap.
    let rc = within(reg.open_user(&c)).await.unwrap();
    let pin_c = rc.mcp_pin();
    drop(rc);
    within(reg.open_user(&b)).await.unwrap();
    assert_eq!(within(reg.open_runtimes()).await.len(), 3);
    drop((pin, pin_c));
    within(reg.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_sink_appends_login_to_the_users_chain() {
    let env = Env::new();
    let uid = env.user("alice");
    let reg = Arc::new(Registry::new(env.deps(), 10));
    let sink = RegistrySink(reg.clone());
    let before = within(reg.open_user(&uid)).await.unwrap().head().1;
    let mut payload = Map::new();
    payload.insert("method".into(), Value::from("password"));
    within(crate::login::LoginSink::login_recorded(
        &sink, &uid, payload,
    ))
    .await
    .unwrap();
    let after = within(reg.open_user(&uid)).await.unwrap().head().1;
    assert_eq!(after, before + 1);
    within(reg.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_user_and_bad_wrapped_key_refuse() {
    let env = Env::new();
    let reg = Registry::new(env.deps(), 10);
    assert_eq!(
        within(reg.open_user("0123456789abcdef0123456789abcdef"))
            .await
            .err(),
        Some(RuntimeError::UnknownUser)
    );
    let uid = env.user("alice");
    let u = env.store.user(&uid).unwrap().unwrap();
    assert!(
        env.store
            .user_set_wrapped(&uid, &u.data_key_wrapped, "{\"v\":1}")
            .unwrap()
    );
    assert_eq!(
        within(reg.open_user(&uid)).await.err(),
        Some(RuntimeError::DataKey)
    );
}

#[test]
fn refusing_confirmer_refuses() {
    assert_eq!(RefusingConfirmer.confirm("anything"), Confirm::Cancel);
}

#[test]
fn sse_sink_maps_with_the_desktop_table() {
    let (tx, mut rx) = broadcast::channel(4);
    let sink = SseUiSink { tx };
    sink.emit(UiEvent::NeedsAttentionChanged { count: 2 });
    let e = rx.try_recv().unwrap();
    assert_eq!(e.name, "needs_attention_changed");
    assert_eq!(e.data, serde_json::json!({"count": 2}));
}
