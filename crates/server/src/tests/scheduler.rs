//! The in-process scheduler (M13 T9): offboarding and retention, missed runs, retries, overlap.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use serde_json::{Value, json};

use super::*;
use crate::admin::{AdminCtx, DEFAULT_RETENTION_DAYS};
use crate::anchor::AnchorWriter;
use crate::api_keys::{ApiKeyParams, ApiKeys};
use crate::clock::ManualClock;
use crate::directory::DirectoryError;
use crate::directory::stub::StubDirectory;
use crate::runtime::Registry;
use crate::runtime::tests::Env;
use crate::session::SessionTable;

const LIMIT: Duration = Duration::from_secs(60);
/// 2027-01-15T08:00:00Z: the 02:00 slot of the day has passed.
const T0: i64 = 1_800_000_000;

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIMIT, f).await.expect("timed out")
}

/// A lookup with set answers; unknown users are `Active`. Counts calls.
#[derive(Default)]
struct FakeLookup {
    states: Mutex<HashMap<String, Result<AccountState, DirectoryError>>>,
    calls: AtomicUsize,
    gate: Option<Arc<tokio::sync::Notify>>,
}

impl FakeLookup {
    fn set(&self, user: &str, s: Result<AccountState, DirectoryError>) {
        self.states.lock().unwrap().insert(user.to_owned(), s);
    }
}

#[async_trait]
impl AccountLookup for FakeLookup {
    async fn account_state(&self, username: &str) -> Result<AccountState, DirectoryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(g) = &self.gate {
            g.notified().await;
        }
        self.states
            .lock()
            .unwrap()
            .get(username)
            .copied()
            .unwrap_or(Ok(AccountState::Active))
    }
}

struct T {
    env: Env,
    ctx: Arc<AdminCtx>,
    clock: Arc<ManualClock>,
}

fn harness() -> T {
    let env = Env::new();
    let clock = ManualClock::at(T0);
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
    fn deactivated_by(&self, uid: &str) -> Option<String> {
        self.env
            .store
            .user_state(uid)
            .unwrap()
            .unwrap()
            .deactivated_by
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daily_offboarding_deactivates_disabled_and_missing_users() {
    // The test directory's file: alice active, bob disabled, carol gone.
    let t = harness();
    let (a, b, c) = (t.env.user("alice"), t.env.user("bob"), t.env.user("carol"));
    let file = t.env.dir.path().join("users.json");
    std::fs::write(
        &file,
        r#"{"users": [{"username": "alice", "password": "x"},
                      {"username": "bob", "password": "x", "disabled": true}]}"#,
    )
    .unwrap();
    let stub: Arc<dyn AccountLookup> = Arc::new(StubDirectory::from_file(&file).unwrap());
    let s = Scheduler::new(t.ctx.clone(), Some(stub), (2, 0));
    assert!(s.offboarding_enabled());
    let ran = within(s.run_due()).await;
    assert_eq!(ran, [(JOB_OFFBOARDING, true), (JOB_RETENTION, true)]);
    assert_eq!(t.deactivated_by(&a), None);
    assert_eq!(t.deactivated_by(&b).as_deref(), Some("offboarding"));
    // I4: gone only after a second daily run says so too.
    assert_eq!(t.deactivated_by(&c), None);
    assert_eq!(t.env.store.gone_since(&c).unwrap(), Some(T0));
    t.clock.advance(86_400);
    within(s.run_due()).await;
    assert_eq!(t.deactivated_by(&c).as_deref(), Some("offboarding"));
    assert_eq!(t.env.store.gone_since(&c).unwrap(), None);
    within(t.ctx.registry.close_all()).await;

    // The same over an LDAP-shaped lookup.
    let t = harness();
    let (a, b, c) = (t.env.user("alice"), t.env.user("bob"), t.env.user("carol"));
    let fake = Arc::new(FakeLookup::default());
    fake.set("bob", Ok(AccountState::Disabled));
    fake.set("carol", Ok(AccountState::Gone));
    let s = Scheduler::new(t.ctx.clone(), Some(fake.clone()), (2, 0));
    within(s.run_due()).await;
    assert_eq!(t.deactivated_by(&a), None);
    assert_eq!(t.deactivated_by(&b).as_deref(), Some("offboarding"));
    assert_eq!(t.deactivated_by(&c), None, "one empty answer is no proof");
    t.clock.advance(86_400);
    within(s.run_due()).await;
    assert_eq!(t.deactivated_by(&c).as_deref(), Some("offboarding"));
    // Deactivated users are not looked up again the next day.
    let calls = fake.calls.load(Ordering::SeqCst);
    t.clock.advance(86_400);
    within(s.run_due()).await;
    assert_eq!(fake.calls.load(Ordering::SeqCst), calls + 1, "alice only");
    within(t.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offboarding_skips_when_directory_unreachable_and_retries_next_hour() {
    let t = harness();
    let (a, b) = (t.env.user("alice"), t.env.user("bob"));
    let fake = Arc::new(FakeLookup::default());
    fake.set("alice", Err(DirectoryError::Unavailable));
    fake.set("bob", Err(DirectoryError::Unavailable));
    let s = Scheduler::new(t.ctx.clone(), Some(fake.clone()), (2, 0));
    let ran = within(s.run_due()).await;
    assert_eq!(ran[0], (JOB_OFFBOARDING, false));
    assert_eq!((t.deactivated_by(&a), t.deactivated_by(&b)), (None, None));
    let state = t.env.store.scheduler_get(JOB_OFFBOARDING).unwrap();
    assert_eq!(state.last_run_at, Some(T0));
    assert_eq!(state.last_success_at, None);
    // Not again within the hour, again after it.
    t.clock.advance(RETRY_SECS - 1);
    assert!(within(s.run_due()).await.is_empty());
    fake.set("alice", Ok(AccountState::Active));
    fake.set("bob", Ok(AccountState::Disabled));
    t.clock.advance(1);
    let ran = within(s.run_due()).await;
    assert_eq!(ran, [(JOB_OFFBOARDING, true)]);
    assert_eq!(t.deactivated_by(&a), None);
    assert_eq!(t.deactivated_by(&b).as_deref(), Some("offboarding"));
    within(t.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offboarding_refuses_an_implausible_mass_deactivation() {
    let t = harness();
    let fake = Arc::new(FakeLookup::default());
    let mut uids = Vec::new();
    for i in 0..8 {
        let name = format!("user{i}");
        uids.push(t.env.user(&name));
        if i < 4 {
            fake.set(&name, Ok(AccountState::Disabled));
        }
    }
    let s = Scheduler::new(t.ctx.clone(), Some(fake), (2, 0));
    let ran = within(s.run_due()).await;
    assert_eq!(ran[0], (JOB_OFFBOARDING, false));
    assert!(uids.iter().all(|u| t.deactivated_by(u).is_none()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offboarding_without_service_bind_is_manual_and_reported() {
    let t = harness();
    let a = t.env.user("alice");
    let s = Scheduler::new(t.ctx.clone(), None, (2, 0));
    assert!(!s.offboarding_enabled());
    let ran = within(s.run_due()).await;
    assert_eq!(ran, [(JOB_OFFBOARDING, true), (JOB_RETENTION, true)]);
    assert_eq!(t.deactivated_by(&a), None);
    // /readyz reports the mode as a field, never as a reason for 503.
    let stub = Arc::new(StubDirectory::from_json(r#"{"users": []}"#).unwrap());
    let res = crate::health::Health::new(t.env.store.clone(), stub, true)
        .with_offboarding("manual")
        .readyz()
        .await;
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), 1 << 16)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["offboarding"], "manual");
}

/// Writes `canary` as the service-bind password file and looks a user up against a port where
/// nothing listens, with every log line captured: the password appears nowhere.
#[tokio::test(flavor = "current_thread")]
async fn service_bind_password_never_logged() {
    use std::io::Write;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    const CANARY: &str = "svc-bind-canary-5e1d";
    let buf = Buf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .event_format(crate::log::JsonLine)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("password");
    std::fs::write(&file, format!("{CANARY}\n")).unwrap();
    let password = crate::app::read_secret_file(&file).unwrap();
    let lookup = crate::directory::ldap::LdapServiceLookup::new(
        url::Url::parse("ldaps://127.0.0.1:1").unwrap(),
        "@example.test".into(),
        "dc=example,dc=test".into(),
        crate::directory::tls::client_config(None).unwrap(),
        "cn=svc,dc=example,dc=test".into(),
        password,
    );
    assert_eq!(
        within(lookup.account_state("alice")).await,
        Err(DirectoryError::Unavailable)
    );
    let shown = format!("{lookup:?}");
    let logged = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    // Alone, the lookup's `directory_unavailable` line is captured; in the full parallel suite
    // tracing's per-callsite interest cache can drop it, so only the absence is asserted.
    assert!(!logged.contains(CANARY), "{logged}");
    assert!(!shown.contains(CANARY), "{shown}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_runs_daily() {
    let t = harness();
    let a = t.env.user("alice");
    let r = crate::admin::users::deactivate(&t.ctx, &a, crate::admin::users::DeactivatedBy::Admin)
        .await
        .unwrap();
    assert!(r.newly_deactivated);
    let s = Scheduler::new(t.ctx.clone(), None, (2, 0));
    within(s.run_due()).await;
    // Every day for a year and a day: the daily run, and nothing more on the same day; the
    // last one deletes the chain.
    for _ in 0..366 {
        t.clock.advance(86_400);
        let ran = within(s.run_due()).await;
        assert!(ran.contains(&(JOB_RETENTION, true)), "{ran:?}");
        assert!(within(s.run_due()).await.is_empty());
    }
    assert!(
        t.env
            .store
            .user_state(&a)
            .unwrap()
            .unwrap()
            .chain_deleted_at
            .is_some()
    );
    within(t.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missed_runs_execute_once_at_startup() {
    let t = harness();
    // The pod was down for three days.
    for job in [JOB_OFFBOARDING, JOB_RETENTION] {
        t.env
            .store
            .scheduler_put(
                job,
                &JobState {
                    last_run_at: Some(T0 - 3 * 86_400),
                    last_success_at: Some(T0 - 3 * 86_400),
                },
            )
            .unwrap();
    }
    let fake = Arc::new(FakeLookup::default());
    t.env.user("alice");
    let s = Arc::new(Scheduler::new(t.ctx.clone(), Some(fake.clone()), (2, 0)));
    // The loop's first check runs each job once.
    let task = s.spawn();
    within(async {
        while t
            .env
            .store
            .scheduler_get(JOB_RETENTION)
            .unwrap()
            .last_run_at
            != Some(T0)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    task.abort();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    assert!(
        within(s.run_due()).await.is_empty(),
        "once, not three times"
    );
    // After tomorrow's slot both run again.
    t.clock.advance(86_400);
    let ran = within(s.run_due()).await;
    assert_eq!(ran, [(JOB_OFFBOARDING, true), (JOB_RETENTION, true)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jobs_never_overlap() {
    let t = harness();
    t.env.user("alice");
    let gate = Arc::new(tokio::sync::Notify::new());
    let fake = Arc::new(FakeLookup {
        gate: Some(gate.clone()),
        ..FakeLookup::default()
    });
    let s = Arc::new(Scheduler::new(t.ctx.clone(), Some(fake.clone()), (2, 0)));
    let first = {
        let s = s.clone();
        tokio::spawn(async move { s.run_due().await })
    };
    within(async {
        while fake.calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    // A second check while the first is inside offboarding runs nothing.
    assert!(within(s.run_due()).await.is_empty());
    // M2: the lookups hold no operation lock, so an admin command is not blocked by a slow
    // directory (the deactivations themselves take the lock).
    let ctx = t.ctx.clone();
    let cmd = tokio::spawn(async move {
        crate::admin::handle(
            &ctx,
            crate::admin::Request::UsersList(crate::admin::NoArgs {}),
        )
        .await
    });
    assert!(within(cmd).await.unwrap().ok, "answered during the lookups");
    gate.notify_one();
    assert_eq!(
        within(first).await.unwrap(),
        [(JOB_OFFBOARDING, true), (JOB_RETENTION, true)]
    );
}

#[tokio::test(start_paused = true)]
async fn the_loop_checks_every_minute() {
    let t = harness();
    let s = Arc::new(Scheduler::new(t.ctx.clone(), None, (2, 0)));
    let task = s.spawn();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        t.env
            .store
            .scheduler_get(JOB_RETENTION)
            .unwrap()
            .last_run_at,
        Some(T0)
    );
    // A day passes on the wall clock; the next check (a minute later) runs the jobs again.
    t.clock.advance(86_400);
    tokio::time::sleep(CHECK_EVERY).await;
    assert_eq!(
        t.env
            .store
            .scheduler_get(JOB_RETENTION)
            .unwrap()
            .last_run_at,
        Some(T0 + 86_400)
    );
    task.abort();
}

#[test]
fn last_slot_is_the_latest_daily_time_at_or_before_now() {
    let t = harness();
    let s = Scheduler::new(t.ctx.clone(), None, (2, 0));
    let day = T0.div_euclid(86_400) * 86_400;
    assert_eq!(s.last_slot(T0), day + 2 * 3600);
    assert_eq!(s.last_slot(day + 2 * 3600), day + 2 * 3600);
    assert_eq!(s.last_slot(day + 2 * 3600 - 1), day + 2 * 3600 - 86_400);
}

/// Batch-2 review I3: with part of the lookups failing, nobody is deactivated, even when the
/// answered part says gone or disabled for a few users.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_partial_directory_outage_deactivates_nobody() {
    let t = harness();
    let fake = Arc::new(FakeLookup::default());
    let mut uids = Vec::new();
    for i in 0..10 {
        let name = format!("user{i}");
        uids.push(t.env.user(&name));
        fake.set(
            &name,
            match i {
                0 => Ok(AccountState::Disabled),
                1 => Ok(AccountState::Gone),
                _ => Err(DirectoryError::Unavailable),
            },
        );
    }
    let s = Scheduler::new(t.ctx.clone(), Some(fake), (2, 0));
    let ran = within(s.run_due()).await;
    assert_eq!(ran[0], (JOB_OFFBOARDING, false));
    assert!(uids.iter().all(|u| t.deactivated_by(u).is_none()));
}

/// Batch-2 review I4: a user the directory reports again (a fixed OU permission) is no longer a
/// gone suspect; one empty answer never deactivates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gone_answer_that_is_not_repeated_never_deactivates() {
    let t = harness();
    let a = t.env.user("alice");
    let fake = Arc::new(FakeLookup::default());
    fake.set("alice", Ok(AccountState::Gone));
    let s = Scheduler::new(t.ctx.clone(), Some(fake.clone()), (2, 0));
    within(s.run_due()).await;
    fake.set("alice", Ok(AccountState::Active));
    t.clock.advance(86_400);
    within(s.run_due()).await;
    assert_eq!(t.env.store.gone_since(&a).unwrap(), None);
    fake.set("alice", Ok(AccountState::Gone));
    t.clock.advance(86_400);
    within(s.run_due()).await;
    assert_eq!(t.deactivated_by(&a), None, "the count starts again");
}

/// Batch-2 review M1: a panicking job is a failed run; the scheduler keeps going.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_job_does_not_stop_the_scheduler() {
    struct Panics;
    #[async_trait]
    impl AccountLookup for Panics {
        async fn account_state(&self, _: &str) -> Result<AccountState, DirectoryError> {
            panic!("lookup bug");
        }
    }
    let t = harness();
    t.env.user("alice");
    let s = Scheduler::new(t.ctx.clone(), Some(Arc::new(Panics)), (2, 0));
    let ran = within(s.run_due()).await;
    assert_eq!(ran, [(JOB_OFFBOARDING, false), (JOB_RETENTION, true)]);
    t.clock.advance(RETRY_SECS);
    assert_eq!(within(s.run_due()).await, [(JOB_OFFBOARDING, false)]);
}
