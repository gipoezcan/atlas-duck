//! `FakeScriptRunner` (C.7 `core::testing`): a scripted stand-in for the M8 worker glue. Each
//! run follows a [`ScriptPlan`]: the compile verdict, the host calls in order (one at a time,
//! each awaited, as the worker's single-threaded loop does), a hold, then the scripted end. A
//! `kill` interrupts the call in flight or the hold, and `wait` then answers
//! `RunEnd::Killed { reason }`. The runner-wide answers (Δ3): `check_available` (Ok unless
//! [`FakeScriptRunner::fail_available`], held by [`FakeScriptRunner::pause_available`]),
//! `confinement` ([`FakeScriptRunner::set_confinement`]), every policy it was handed
//! ([`FakeScriptRunner::policies`]), and each handle's worker report
//! ([`FakeScriptRunner::set_worker_confinement`]).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use atlas_duck_ipc::sandbox::probe::ConfinementReport;
use atlas_duck_ipc::sandbox::{HostCall, HostCallResult, ScriptLimits};
use tokio::sync::watch;

use crate::core::Pause;
use crate::engine::script::{
    CompileError, CompileFailure, HostCalls, KillReason, RunConfinement, RunEnd, RunHandle,
    RunPolicy, RunSpec, RunnerError, ScriptRunner,
};

/// One scripted run.
#[derive(Debug, Clone)]
pub struct ScriptPlan {
    pub compile: Result<(), CompileFailure>,
    /// Issued in order, each after the previous one's answer.
    pub calls: Vec<HostCall>,
    /// How the run ends unless it is killed first.
    pub end: RunEnd,
    /// Held after the last call, before `end` (a kill interrupts it).
    pub hold_ms: u64,
    /// `compile_check` holds here (after taking its plan) until the test releases it.
    pub compile_pause: Option<Arc<Pause>>,
    /// `start` holds here (after taking its plan, before it answers) until released.
    pub start_pause: Option<Arc<Pause>>,
    /// The run ends by itself with `end` this many ms after it started, even with a host call
    /// in flight (a timeout, a crash, a limit kill: the worker dies, the call is not answered).
    pub interrupt: Option<(u64, RunEnd)>,
    /// With `interrupt`: the call future is not dropped when the worker dies (glue that keeps
    /// the fetch running); it runs on in its own task.
    pub keep_calls: bool,
}

impl ScriptPlan {
    /// Compiles, makes `calls`, then ends with `end` at once.
    pub fn new(calls: Vec<HostCall>, end: RunEnd) -> ScriptPlan {
        ScriptPlan {
            compile: Ok(()),
            calls,
            end,
            hold_ms: 0,
            compile_pause: None,
            start_pause: None,
            interrupt: None,
            keep_calls: false,
        }
    }

    /// A source that does not compile.
    pub fn syntax_error(line: u32, column: u32, message: &str) -> ScriptPlan {
        ScriptPlan::compile_failure(CompileFailure::Syntax(CompileError {
            line,
            column,
            message: message.to_owned(),
        }))
    }

    /// A compile check that fails with `failure` (Δ3: syntax, unavailable, timeout); the run is
    /// never started.
    pub fn compile_failure(failure: CompileFailure) -> ScriptPlan {
        ScriptPlan {
            compile: Err(failure),
            calls: Vec::new(),
            end: RunEnd::Crashed,
            hold_ms: 0,
            compile_pause: None,
            start_pause: None,
            interrupt: None,
            keep_calls: false,
        }
    }

    pub fn holding(mut self, ms: u64) -> ScriptPlan {
        self.hold_ms = ms;
        self
    }

    pub fn with_compile_pause(mut self, pause: Arc<Pause>) -> ScriptPlan {
        self.compile_pause = Some(pause);
        self
    }

    pub fn with_start_pause(mut self, pause: Arc<Pause>) -> ScriptPlan {
        self.start_pause = Some(pause);
        self
    }

    /// The run ends with `end` after `after_ms`, whatever it is doing.
    pub fn interrupted(mut self, after_ms: u64, end: RunEnd) -> ScriptPlan {
        self.interrupt = Some((after_ms, end));
        self
    }

    pub fn keeping_calls(mut self) -> ScriptPlan {
        self.keep_calls = true;
        self
    }
}

/// A `HostCall` for the plans: `atlas.call(op_id, params, {instance})`.
pub fn host_call(id: u64, op_id: &str, params: serde_json::Value) -> HostCall {
    HostCall {
        id,
        op_id: op_id.to_owned(),
        params,
        instance: None,
        all: false,
    }
}

#[derive(Default)]
struct Inner {
    /// Plans waiting for their compile check.
    plans: VecDeque<ScriptPlan>,
    /// Plans that compiled, waiting for `start`.
    compiled: VecDeque<ScriptPlan>,
    /// The startup probe said `NotMet` (PD-141): `start` refuses with `FloorNotMet` unless its
    /// policy allows degraded confinement.
    degraded_only: bool,
    compile_checks: u32,
    starts: u32,
    specs: Vec<RunSpec>,
    handles: Vec<Arc<FakeRun>>,
    /// `start` answers this instead of starting (spawn-time `sandbox_unavailable`).
    start_error: Option<RunnerError>,
    /// `check_available` answers this (submit-time unavailability); `None` = available.
    available_error: Option<RunnerError>,
    /// `check_available` holds here (after recording its policy) until released.
    available_pause: Option<Arc<Pause>>,
    availability_checks: u32,
    /// What `confinement` answers.
    confinement: Option<RunConfinement>,
    /// What every later started run's `worker_confinement` answers.
    worker_confinement: Option<ConfinementReport>,
    /// The policy each runner call was handed, in call order (`available`, `compile`,
    /// `confinement`, `start`).
    policies: Vec<(&'static str, RunPolicy)>,
}

/// The fake runner: plans are consumed in submit order (compile check, then start).
#[derive(Default)]
pub struct FakeScriptRunner {
    inner: Mutex<Inner>,
}

impl FakeScriptRunner {
    pub fn new(plans: Vec<ScriptPlan>) -> Arc<FakeScriptRunner> {
        let runner = FakeScriptRunner::default();
        runner.lock().plans = plans.into();
        Arc::new(runner)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues one more run.
    pub fn push(&self, plan: ScriptPlan) {
        self.lock().plans.push_back(plan);
    }

    /// Makes every later `start` fail with `err`.
    pub fn fail_start(&self, err: RunnerError) {
        self.lock().start_error = Some(err);
    }

    /// Every later `start` spawns only under a policy that allows degraded confinement, else it
    /// answers `FloorNotMet` (a probe-time `NotMet`, PD-141; the spawn is where the glue reads it).
    pub fn require_degraded(&self) {
        self.lock().degraded_only = true;
    }

    /// Makes every later `check_available` fail with `err`.
    pub fn fail_available(&self, err: RunnerError) {
        self.lock().available_error = Some(err);
    }

    /// Makes every later `check_available` hold at `pause` (`None`: answer at once).
    pub fn pause_available(&self, pause: Option<Arc<Pause>>) {
        self.lock().available_pause = pause;
    }

    /// What every later `confinement` answers (`None`: the runner states nothing).
    pub fn set_confinement(&self, c: Option<RunConfinement>) {
        self.lock().confinement = c;
    }

    /// What the handle of every later started run answers for its worker's own ready-frame
    /// report (`None`: the runner states none).
    pub fn set_worker_confinement(&self, report: Option<ConfinementReport>) {
        self.lock().worker_confinement = report;
    }

    pub fn availability_checks(&self) -> u32 {
        self.lock().availability_checks
    }

    /// The policy each `check_available` (`"available"`), `compile_check` (`"compile"`),
    /// `confinement` (`"confinement"`) and `start` (`"start"`) was handed, in call order.
    pub fn policies(&self) -> Vec<(&'static str, RunPolicy)> {
        self.lock().policies.clone()
    }

    pub fn compile_checks(&self) -> u32 {
        self.lock().compile_checks
    }

    pub fn starts(&self) -> u32 {
        self.lock().starts
    }

    /// The `RunSpec` of every started run.
    pub fn specs(&self) -> Vec<RunSpec> {
        self.lock().specs.clone()
    }

    /// Every host-call answer the runs received, in the order they arrived.
    pub fn results(&self) -> Vec<HostCallResult> {
        let runs = self.lock().handles.clone();
        runs.iter().flat_map(|r| r.answers()).collect()
    }

    /// The kill reason each started run was given (`None`: never killed).
    pub fn kills(&self) -> Vec<Option<KillReason>> {
        self.lock().handles.iter().map(|h| h.killed()).collect()
    }
}

#[async_trait]
impl ScriptRunner for FakeScriptRunner {
    async fn check_available(&self, policy: RunPolicy) -> Result<(), RunnerError> {
        let pause = {
            let mut g = self.lock();
            g.availability_checks += 1;
            g.policies.push(("available", policy));
            g.available_pause.clone()
        };
        if let Some(p) = pause {
            p.hold().await;
        }
        self.lock().available_error.map_or(Ok(()), Err)
    }

    async fn compile_check(
        &self,
        _source: &str,
        _limits: &ScriptLimits,
        policy: RunPolicy,
    ) -> Result<(), CompileFailure> {
        let (verdict, pause) = {
            let mut g = self.lock();
            g.compile_checks += 1;
            g.policies.push(("compile", policy));
            let Some(plan) = g.plans.pop_front() else {
                return Ok(());
            };
            let verdict = plan.compile.clone();
            let pause = plan.compile_pause.clone();
            if verdict.is_ok() {
                g.compiled.push_back(plan);
            }
            (verdict, pause)
        };
        if let Some(p) = pause {
            p.hold().await;
        }
        verdict
    }

    fn confinement(&self, policy: RunPolicy) -> Option<RunConfinement> {
        let mut g = self.lock();
        g.policies.push(("confinement", policy));
        g.confinement.clone()
    }

    async fn start(
        &self,
        run: RunSpec,
        calls: Arc<dyn HostCalls>,
    ) -> Result<Arc<dyn RunHandle>, RunnerError> {
        let (plan, fake) = {
            let mut g = self.lock();
            g.starts += 1;
            g.policies.push(("start", run.policy));
            g.specs.push(run.clone());
            if let Some(e) = g.start_error {
                return Err(e);
            }
            if g.degraded_only && !run.policy.allow_degraded {
                return Err(RunnerError::SandboxUnavailable {
                    reason: crate::engine::script::UnavailableReason::FloorNotMet,
                });
            }
            // A run that never had a compile check (a dry run of a runner without plans).
            let plan = g
                .compiled
                .pop_front()
                .or_else(|| g.plans.pop_front())
                .unwrap_or_else(|| {
                    ScriptPlan::new(
                        Vec::new(),
                        RunEnd::Result {
                            value: serde_json::Value::Null,
                            logs: Vec::new(),
                            stderr: String::new(),
                        },
                    )
                });
            let fake = Arc::new(FakeRun::new(g.worker_confinement.clone()));
            g.handles.push(fake.clone());
            (plan, fake)
        };
        if let Some(p) = plan.start_pause.clone() {
            p.hold().await;
        }
        let driver = fake.clone();
        let run_id = run.run_id.clone();
        tokio::spawn(async move { drive(&driver, &run_id, plan, calls).await });
        Ok(fake)
    }
}

async fn drive(run: &Arc<FakeRun>, run_id: &str, plan: ScriptPlan, calls: Arc<dyn HostCalls>) {
    let mut kill = run.kill_rx();
    let deadline = plan
        .interrupt
        .as_ref()
        .map(|(ms, _)| Duration::from_millis(*ms));
    let interrupt = async {
        match deadline {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(interrupt);
    for call in plan.calls {
        let answer = async {
            if plan.keep_calls {
                let (calls, id) = (calls.clone(), run_id.to_owned());
                tokio::spawn(async move { calls.call(&id, call).await })
                    .await
                    .unwrap_or(HostCallResult::Ok(serde_json::Value::Null))
            } else {
                calls.call(run_id, call).await
            }
        };
        tokio::select! {
            result = answer => run.record(result),
            () = &mut interrupt => {
                if let Some((_, end)) = plan.interrupt {
                    run.finish(end);
                }
                return;
            }
            _ = kill.wait_for(Option::is_some) => {
                run.finish_killed();
                return;
            }
        }
    }
    if plan.hold_ms > 0 {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(plan.hold_ms)) => {}
            () = &mut interrupt => {
                if let Some((_, end)) = plan.interrupt {
                    run.finish(end);
                }
                return;
            }
            _ = kill.wait_for(Option::is_some) => {
                run.finish_killed();
                return;
            }
        }
    }
    // A kill that raced the last answer wins: the worker is gone.
    if run.killed().is_some() {
        run.finish_killed();
        return;
    }
    run.finish(plan.end);
}

/// One started run: the handle the engine holds.
pub struct FakeRun {
    kill: watch::Sender<Option<KillReason>>,
    end: watch::Sender<Option<RunEnd>>,
    answers: Mutex<Vec<HostCallResult>>,
    worker: Option<ConfinementReport>,
}

impl FakeRun {
    fn new(worker: Option<ConfinementReport>) -> FakeRun {
        FakeRun {
            kill: watch::channel(None).0,
            end: watch::channel(None).0,
            answers: Mutex::new(Vec::new()),
            worker,
        }
    }

    fn kill_rx(&self) -> watch::Receiver<Option<KillReason>> {
        self.kill.subscribe()
    }

    fn killed(&self) -> Option<KillReason> {
        self.kill.borrow().clone()
    }

    fn finish(&self, end: RunEnd) {
        self.end.send_replace(Some(end));
    }

    fn finish_killed(&self) {
        if let Some(reason) = self.killed() {
            self.finish(RunEnd::Killed { reason });
        }
    }

    fn record(&self, answer: HostCallResult) {
        self.answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(answer);
    }

    fn answers(&self) -> Vec<HostCallResult> {
        self.answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl RunHandle for FakeRun {
    fn kill(&self, why: KillReason) {
        self.kill.send_if_modified(|cur| {
            if cur.is_none() {
                *cur = Some(why);
                true
            } else {
                false
            }
        });
    }

    async fn wait(&self) -> RunEnd {
        let mut rx = self.end.subscribe();
        match rx.wait_for(Option::is_some).await {
            Ok(v) => v.clone().unwrap_or(RunEnd::Crashed),
            Err(_) => RunEnd::Crashed,
        }
    }

    fn worker_confinement(&self) -> Option<ConfinementReport> {
        self.worker.clone()
    }
}
