//! Scripts in server mode (M14 T12): the strict policy, the server-wide pools across user cores
//! on top of each core's own slots, readiness, and (Linux CI) the real worker.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_duck_core::testing::{FakeScriptRunner, ScriptPlan};
use atlas_duck_core::{Pause, RunEnd};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_ipc::proto::{
    AgentNameSource, ClientKind, ConnectionMeta, Hello, RequestHandler, SubmitParams,
};
use atlas_duck_sandbox_host::probe::{FloorVerdict, ProbeReport};
use serde_json::json;

use super::*;
use crate::runtime::tests::Env;
use crate::runtime::{Registry, UserCtx};

const LIMIT: Duration = Duration::from_secs(30);

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIMIT, f).await.expect("timed out")
}

fn cfg(runs_max: usize) -> ScriptsConfig {
    ScriptsConfig {
        runs_max,
        ..ScriptsConfig::defaults()
    }
}

fn ok_end() -> RunEnd {
    RunEnd::Result {
        value: json!(1),
        logs: Vec::new(),
        stderr: String::new(),
    }
}

pub(crate) fn report(floor: FloorVerdict) -> ProbeReport {
    ProbeReport {
        worker_version: None,
        engine_version: None,
        identity: None,
        confinement: None,
        threads: None,
        records: Vec::new(),
        floor,
        extra_layers: Vec::new(),
        control: None,
        lpac_failed: None,
    }
}

/// Polls `cond` (structural, no fixed sleep) within [`LIMIT`].
async fn until(mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + LIMIT;
    while !cond() {
        assert!(Instant::now() < deadline, "condition not reached in time");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// A user's handler with a hello done on `conn`.
async fn agent(reg: &Registry, uid: &str, conn: &ConnectionMeta) -> Arc<dyn RequestHandler> {
    let rt = within(reg.runtime(&UserCtx::from_authenticated(uid)))
        .await
        .unwrap();
    let h = rt.handler();
    h.hello(
        conn,
        Hello {
            build_id: atlas_duck_ipc::build_info::BUILD_ID.to_owned(),
            client_kind: ClientKind::Mcp,
            agent_name_source: AgentNameSource::None,
            agent_name: None,
            cwd_basename: "t".into(),
        },
    )
    .await
    .unwrap();
    h
}

async fn submit(h: &Arc<dyn RequestHandler>, conn: &ConnectionMeta) -> String {
    let env = within(h.submit_script(
        conn,
        SubmitParams {
            op_id: "script.run".into(),
            params: json!({"source": "return 1;"}),
            instance: None,
            reason: None,
        },
    ))
    .await
    .envelope;
    assert_eq!(env.status, Status::Pending, "{env:?}");
    env.request_id.unwrap()
}

fn conn(id: &str) -> ConnectionMeta {
    ConnectionMeta {
        connection_id: id.into(),
        peer: Default::default(),
    }
}

/// A runner whose every run holds at its start until `pause` is released once per run.
fn held(n: usize, pause: &Arc<Pause>) -> Arc<FakeScriptRunner> {
    FakeScriptRunner::new(
        (0..n)
            .map(|_| ScriptPlan::new(Vec::new(), ok_end()).with_start_pause(pause.clone()))
            .collect(),
    )
}

#[test]
fn state_labels_and_the_worker_check() {
    assert_eq!(state_label(false, None), "disabled");
    assert_eq!(state_label(true, None), "probing");
    let met = report(FloorVerdict::Met);
    let unmet = report(FloorVerdict::NotMet { failed: Vec::new() });
    assert_eq!(state_label(true, Some(&met)), "met");
    assert_eq!(state_label(true, Some(&unmet)), "not_met");
    assert_eq!(state_label(false, Some(&met)), "disabled");
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("atlas-duck-sandbox");
    std::fs::write(&file, b"x").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(!sandbox_bin_ok(&file), "not executable");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert!(sandbox_bin_ok(&file));
    assert!(!sandbox_bin_ok(dir.path()), "a directory");
    assert!(!sandbox_bin_ok(&dir.path().join("missing")));
    assert!(!sandbox_bin_ok(std::path::Path::new("atlas-duck-sandbox")));
}

/// PD-248: whatever policy core hands over, the glue sees a strict one.
#[tokio::test]
async fn a_degraded_policy_is_replaced_by_the_strict_one() {
    let fake = FakeScriptRunner::new(vec![ScriptPlan::new(Vec::new(), ok_end())]);
    let s = ServerScripts::with_runner(cfg(2), fake.clone());
    let r = s.wrap(fake.clone());
    let degraded = RunPolicy {
        allow_degraded: true,
    };
    within(r.check_available(degraded)).await.unwrap();
    within(r.compile_check("return 1;", &Default::default(), degraded))
        .await
        .unwrap();
    let _ = r.confinement(degraded);
    struct NoCalls;
    #[async_trait::async_trait]
    impl HostCalls for NoCalls {
        async fn call(
            &self,
            _: &str,
            _: atlas_duck_ipc::sandbox::HostCall,
        ) -> atlas_duck_ipc::sandbox::HostCallResult {
            unreachable!("no host call in this plan")
        }
        fn log(&self, _: &str, _: &str) {}
    }
    let spec = RunSpec {
        run_id: "r1".into(),
        source: "return 1;".into(),
        args: json!({}),
        limits: Default::default(),
        dry_run: false,
        policy: degraded,
    };
    within(r.start(spec, Arc::new(NoCalls))).await.unwrap();
    let seen = fake.policies();
    assert_eq!(seen.len(), 4, "{seen:?}");
    assert!(seen.iter().all(|(_, p)| !p.allow_degraded), "{seen:?}");
    assert!(r.shared_slots().is_some());
}

/// PD-246: the server-wide pool bounds runs across users; a run waits (queued) for a free
/// permit and starts as soon as one is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_server_wide_pool_bounds_runs_across_users() {
    let pause = Pause::new();
    let fake = held(3, &pause);
    let mut env = Env::new();
    let scripts = Arc::new(ServerScripts::with_runner(cfg(2), fake.clone()));
    env.scripts = Some(scripts.clone());
    let (a, b) = (env.user("alice"), env.user("bob"));
    let reg = Registry::new(env.deps(), 10);
    let (ca, cb) = (conn("a"), conn("b"));
    let ha = agent(&reg, &a, &ca).await;
    let hb = agent(&reg, &b, &cb).await;
    submit(&ha, &ca).await;
    submit(&ha, &ca).await;
    let b_id = submit(&hb, &cb).await;
    // Two runs start; the third (whoever's it is) waits for the server-wide pool.
    until(|| fake.starts() >= 2).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        fake.starts(),
        2,
        "a third run started past the server-wide cap"
    );
    assert_eq!(scripts.runs_active(), 2);
    assert_eq!(within(hb.status(&b_id)).await.status, Status::Pending);
    // One run ends: the waiting one starts.
    pause.release.notify_one();
    until(|| fake.starts() == 3).await;
    pause.release.notify_one();
    pause.release.notify_one();
    until(|| scripts.runs_active() == 0).await;
}

/// SM-7.1: core's own two slots per user: alice's third run queues while bob's runs at once,
/// under a server-wide pool large enough for all of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_user_slots_are_independent() {
    let pause = Pause::new();
    let fake = held(4, &pause);
    let mut env = Env::new();
    let scripts = Arc::new(ServerScripts::with_runner(cfg(4), fake.clone()));
    env.scripts = Some(scripts.clone());
    let (a, b) = (env.user("alice"), env.user("bob"));
    let reg = Registry::new(env.deps(), 10);
    let (ca, cb) = (conn("a"), conn("b"));
    let ha = agent(&reg, &a, &ca).await;
    let hb = agent(&reg, &b, &cb).await;
    for _ in 0..3 {
        submit(&ha, &ca).await;
    }
    until(|| fake.starts() == 2).await;
    submit(&hb, &cb).await;
    // Bob's run starts although alice's third is still waiting for one of her own slots.
    until(|| fake.starts() == 3).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fake.starts(), 3, "alice ran a third script at once");
    assert_eq!(scripts.runs_active(), 3);
    pause.release.notify_one();
    until(|| fake.starts() == 4).await;
    for _ in 0..3 {
        pause.release.notify_one();
    }
    until(|| scripts.runs_active() == 0).await;
}

/// PD-249 (Δ-M14-3): a runtime with a running script is not evicted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_running_script_pins_its_runtime() {
    let pause = Pause::new();
    let fake = held(1, &pause);
    let mut env = Env::new();
    env.scripts = Some(Arc::new(ServerScripts::with_runner(cfg(2), fake.clone())));
    let a = env.user("alice");
    let reg = Registry::new(env.deps(), 10);
    let ca = conn("a");
    let ha = agent(&reg, &a, &ca).await;
    submit(&ha, &ca).await;
    until(|| fake.starts() == 1).await;
    let rt = within(reg.runtime(&UserCtx::from_authenticated(&a)))
        .await
        .unwrap();
    assert!(
        !rt.evictable(),
        "a runtime with a running script is evictable"
    );
    pause.release.notify_one();
}

#[tokio::test]
async fn readiness_reports_the_floor_without_failing() {
    let s = Arc::new(ServerScripts::new(cfg(2)));
    let env = Env::new();
    let dir: Arc<dyn crate::directory::Directory> =
        Arc::new(crate::directory::stub::StubDirectory::from_json(r#"{"users": []}"#).unwrap());
    let h = crate::health::Health::new(env.store.clone(), dir.clone(), true)
        .with_scripts(Some(s.clone()));
    assert_eq!(h.scripts_state(), "probing");
    s.probe
        .set(report(FloorVerdict::NotMet { failed: Vec::new() }));
    assert_eq!(h.scripts_state(), "not_met");
    let res = h.readyz().await;
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["scripts"], "not_met");
    let off = crate::health::Health::new(env.store.clone(), dir, true);
    assert_eq!(off.scripts_state(), "disabled");
}

/// Linux CI (`server` job): the real worker. `ATLAS_DUCK_SANDBOX_BIN` names the worker cargo
/// built (`target/debug/atlas-duck-sandbox`); the probe meets the floor and a run returns its
/// value through the glue.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_real_worker_meets_the_floor_and_runs_a_script() {
    let bin = std::env::var_os("ATLAS_DUCK_SANDBOX_BIN")
        .expect("ATLAS_DUCK_SANDBOX_BIN must name the built worker (set by the CI step)");
    let dir = tempfile::tempdir().unwrap();
    let s = ServerScripts::start(
        ScriptsConfig {
            sandbox_bin: std::path::PathBuf::from(bin),
            ..cfg(2)
        },
        dir.path(),
    );
    let r = within(s.probe.wait(Duration::from_secs(60)))
        .await
        .expect("no probe report")
        .clone();
    assert_eq!(s.state(), "met", "{}", report_json(&r));
    let runner = s.runner(Default::default());
    within(runner.check_available(RunPolicy::default()))
        .await
        .unwrap();
    within(runner.compile_check("return 1 + 1;", &Default::default(), RunPolicy::default()))
        .await
        .unwrap();
    struct NoCalls;
    #[async_trait::async_trait]
    impl HostCalls for NoCalls {
        async fn call(
            &self,
            _: &str,
            _: atlas_duck_ipc::sandbox::HostCall,
        ) -> atlas_duck_ipc::sandbox::HostCallResult {
            unreachable!("the script makes no host call")
        }
        fn log(&self, _: &str, _: &str) {}
    }
    let handle = within(runner.start(
        RunSpec {
            run_id: "run-1".into(),
            source: "return 1 + 1;".into(),
            args: json!({}),
            limits: Default::default(),
            dry_run: false,
            policy: RunPolicy::default(),
        },
        Arc::new(NoCalls),
    ))
    .await
    .unwrap();
    match within(handle.wait()).await {
        RunEnd::Result { value, .. } => assert_eq!(value, json!(2)),
        other => panic!("not a result: {other:?}"),
    }
}
