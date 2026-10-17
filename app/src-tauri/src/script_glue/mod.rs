//! `script_glue`: the real `ScriptRunner` (C.0 "who drives the sandbox", M8 Task 20). Core owns
//! the script lifecycle and has no edge to `sandbox-host` (§2.2); this module implements core's
//! seam over the host bridge (`sandbox-host::bridge`) and hands the bridge a `HostCallSink` that
//! forwards each `host.call` to core's `HostCalls`.
//!
//! Every spawn is admitted by the floor rule ([`policy`], §9.4, PD-141) from the startup probe's
//! report, which the glue awaits for at most [`PROBE_WAIT`] (PD-138, R10), and from the run
//! policy core reads before each call (never captured at submit). Before every spawn the binary's
//! file identity is checked again against the probe's record (PD-133), or, for a degraded run when
//! no probe worker reached ready, against the record the probe holder made itself when it
//! resolved (`FallbackIdentity`, M8 T20 ruling); a mismatch refuses the run
//! as `app_upgraded`, sets the update flag (`updated_restart`), and every later script is refused
//! the same way until restart. The bridge then checks the spawned worker's ready frame (embedded
//! version, confinement) before it sends any source.
//!
//! Fail closed: no report, no recorded identity, no install dir, a failed check or spawn all
//! refuse with `sandbox_unavailable`; an unconfined ready frame is accepted only under a degraded
//! policy with a `NotMet` probe report. Every synchronous `sandbox-host` call (the identity check,
//! `start_run`, `compile_run`, creating a spawner) runs on `spawn_blocking`, never on a runtime
//! worker thread (PD-138). A kill never blocks: it goes straight to the bridge's non-blocking
//! kill. Host calls are the bridge's own tasks and are never dropped (PD-148): the sink only
//! forwards them. The glue logs constants and the request id only ([`SCRIPT_GLUE_EVENTS`]); no
//! worker byte reaches the diagnostic log (§3.4).

#![deny(clippy::unwrap_used, clippy::expect_used)]

mod map;
mod policy;
#[cfg(test)]
mod tests;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use atlas_duck_core::{
    CompileFailure, HostCalls, KillReason, RunConfinement, RunEnd, RunHandle, RunPolicy, RunSpec,
    RunnerError, ScriptRunner, UnavailableReason,
};
use atlas_duck_ipc::sandbox::probe::ConfinementReport;
use atlas_duck_ipc::sandbox::script::{InstanceInfo, WorkerInit};
use atlas_duck_ipc::sandbox::{HostCall, HostCallResult, ScriptLimits};
use atlas_duck_sandbox_host::bridge::{
    self, CompileVerdict, ExpectedWorker, HostCallSink, HostVerdict, KillCause, RunHandleImpl,
    RunOutcome, StartRunError,
};
use atlas_duck_sandbox_host::identity;
use atlas_duck_sandbox_host::spawn::{SpawnSpec, WorkerSpawner};
use tokio::runtime::Handle;

pub use self::policy::SpawnerKind;
use crate::diag::fields::{SCRIPT_DIAG_UNLISTED, SCRIPT_GLUE_EVENTS};
use crate::sandbox_probe::{ProbeHolder, canonical_worker};

/// Plan value (PD-138): how long the glue awaits the startup probe's report before a spawn; the
/// wait sits in `check_available` and counts toward the agent's `--timeout`.
pub const PROBE_WAIT: Duration = Duration::from_secs(60);
/// Plan value (PD-135): the compile check is bounded by this or the submitted `timeout_s`,
/// whichever is lower.
pub const COMPILE_DEADLINE_MAX: Duration = Duration::from_secs(10);

/// Log event: the sandbox binary no longer matches the probe's record (PD-133).
pub const LOG_EVENT_IDENTITY_MISMATCH: &str = "script_identity_mismatch";
/// Log event: no usable worker (`reason` is a fixed token: `floor_not_met`, or the spawn's
/// `io::ErrorKind` name).
pub const LOG_EVENT_SPAWN_FAILED: &str = "script_spawn_failed";
/// Log event: the startup probe's report did not arrive within [`PROBE_WAIT`].
pub const LOG_EVENT_PROBE_PENDING: &str = "script_probe_pending";
/// `reason` of [`LOG_EVENT_SPAWN_FAILED`] for a ready frame without the confinement the run needs.
const REASON_FLOOR_NOT_MET: &str = "floor_not_met";

/// The PD-135 bound of one compile check: `min(10 s, timeout_s)`.
pub fn compile_deadline(limits: &ScriptLimits) -> Duration {
    COMPILE_DEADLINE_MAX.min(Duration::from_secs(u64::from(limits.timeout_s)))
}

/// What the app hands the glue (M8 Task 20): the startup probe's holder, the update flag the
/// status line reads (PD-133) and the core's instance list.
#[derive(Clone, Default)]
pub struct ScriptInputs {
    pub probe: Arc<ProbeHolder>,
    pub update_pending: Arc<AtomicBool>,
    pub instances: InstanceSource,
}

type InstanceList = dyn Fn() -> Vec<InstanceInfo> + Send + Sync;

/// The core's instances as `atlas.instances()` shows them (Δ1, R9), read at each spawn. The glue
/// exists before the core (it is part of `CoreDeps`), so the app sets the getter once the core
/// has started; until then the list is empty.
#[derive(Clone, Default)]
pub struct InstanceSource(Arc<OnceLock<Box<InstanceList>>>);

impl InstanceSource {
    /// Sets the getter once; a later one is ignored.
    pub fn set(&self, list: impl Fn() -> Vec<InstanceInfo> + Send + Sync + 'static) {
        let _ = self.0.set(Box::new(list));
    }

    pub fn list(&self) -> Vec<InstanceInfo> {
        self.0.get().map(|list| list()).unwrap_or_default()
    }
}

/// One compile check for the bridge (PD-132, PD-135).
pub struct CompileJob {
    pub spawner: SpawnerKind,
    pub spec: SpawnSpec,
    pub expect: ExpectedWorker,
    pub source: String,
    pub deadline: Duration,
}

/// One run for the bridge (Δ2).
pub struct StartJob {
    pub spawner: SpawnerKind,
    pub spec: SpawnSpec,
    pub expect: ExpectedWorker,
    pub init: WorkerInit,
    pub sink: Arc<dyn HostCallSink>,
    /// Runs the run's host-call tasks and its timer (it has the time driver).
    pub rt: Handle,
}

/// The bridge as the glue drives it: `sandbox-host`'s `compile_run` and `start_run` over the
/// spawner a job names ([`HostBridge`]); tests put a fake behind it.
#[async_trait]
pub trait BridgePort: Send + Sync {
    async fn compile(&self, job: CompileJob) -> Result<CompileVerdict, StartRunError>;
    async fn start(&self, job: StartJob) -> Result<Arc<dyn RunControl>, StartRunError>;
}

/// A started run as the bridge hands it out (`RunHandleImpl`).
#[async_trait]
pub trait RunControl: Send + Sync {
    /// Non-blocking (M3 M-1, PD-137).
    fn kill(&self, cause: KillCause);
    /// The outcome once the worker is reaped; the same every time.
    async fn wait(&self) -> RunOutcome;
}

#[async_trait]
impl RunControl for RunHandleImpl {
    fn kill(&self, cause: KillCause) {
        RunHandleImpl::kill(self, cause);
    }

    async fn wait(&self) -> RunOutcome {
        RunHandleImpl::wait(self).await
    }
}

type SharedSpawner = Arc<dyn WorkerSpawner + Send + Sync>;

/// The real bridge. Each spawner is created on first use, on a blocking thread, and kept for the
/// app's lifetime (§3.4: on Linux one long-lived spawner thread forks every worker); a spawner that
/// could not be created is tried again at the next spawn.
#[derive(Default)]
pub struct HostBridge {
    spawners: Arc<Spawners>,
}

#[derive(Default)]
struct Spawners {
    platform: Mutex<Option<SharedSpawner>>,
    fallback: Mutex<Option<SharedSpawner>>,
    degraded: Mutex<Option<SharedSpawner>>,
}

impl Spawners {
    /// Blocking: creating a spawner can take seconds (the Windows AppContainer profile).
    fn get(&self, kind: SpawnerKind) -> io::Result<SharedSpawner> {
        let slot = match kind {
            SpawnerKind::Platform => &self.platform,
            SpawnerKind::Fallback => &self.fallback,
            SpawnerKind::Degraded => &self.degraded,
        };
        let mut held = slot.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(spawner) = held.as_ref() {
            return Ok(spawner.clone());
        }
        let made = make_spawner(kind)?;
        *held = Some(made.clone());
        Ok(made)
    }
}

/// The concrete spawners of `sandbox-host` (what `platform_spawner`, `fallback_spawner` and
/// `degraded_spawner` build, without their `Box<dyn WorkerSpawner>`, which is neither `Send` nor
/// `Sync`).
fn make_spawner(kind: SpawnerKind) -> io::Result<SharedSpawner> {
    match kind {
        SpawnerKind::Platform => platform_spawner(),
        SpawnerKind::Fallback => fallback_spawner(),
        SpawnerKind::Degraded => degraded_spawner(),
    }
}

#[cfg(target_os = "linux")]
fn platform_spawner() -> io::Result<SharedSpawner> {
    Ok(Arc::new(
        atlas_duck_sandbox_host::linux::LinuxSpawner::start()?,
    ))
}

#[cfg(target_os = "macos")]
fn platform_spawner() -> io::Result<SharedSpawner> {
    Ok(Arc::new(atlas_duck_sandbox_host::macos::MacSpawner::new()))
}

#[cfg(windows)]
fn platform_spawner() -> io::Result<SharedSpawner> {
    Ok(Arc::new(
        atlas_duck_sandbox_host::windows::WindowsSpawner::new()?,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn platform_spawner() -> io::Result<SharedSpawner> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Windows only (the plain AppContainer rerun of §9.4).
#[cfg(windows)]
fn fallback_spawner() -> io::Result<SharedSpawner> {
    Ok(Arc::new(
        atlas_duck_sandbox_host::windows::WindowsSpawner::new_plain()?,
    ))
}

#[cfg(not(windows))]
fn fallback_spawner() -> io::Result<SharedSpawner> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Windows only (PD-141 (b)); elsewhere a degraded run uses the platform spawner.
#[cfg(windows)]
fn degraded_spawner() -> io::Result<SharedSpawner> {
    Ok(Arc::new(
        atlas_duck_sandbox_host::windows::DegradedSpawner::new(),
    ))
}

#[cfg(not(windows))]
fn degraded_spawner() -> io::Result<SharedSpawner> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// A join error of a blocking bridge call (it panicked): no usable worker.
fn lost_blocking_call() -> StartRunError {
    StartRunError::Spawn(io::ErrorKind::Other)
}

#[async_trait]
impl BridgePort for HostBridge {
    async fn compile(&self, job: CompileJob) -> Result<CompileVerdict, StartRunError> {
        let spawners = self.spawners.clone();
        tokio::task::spawn_blocking(move || {
            let spawner = spawners
                .get(job.spawner)
                .map_err(|e| StartRunError::Spawn(e.kind()))?;
            bridge::compile_run(
                spawner.as_ref(),
                &job.spec,
                &job.expect,
                &job.source,
                job.deadline,
            )
        })
        .await
        .unwrap_or_else(|_| Err(lost_blocking_call()))
    }

    async fn start(&self, job: StartJob) -> Result<Arc<dyn RunControl>, StartRunError> {
        let spawners = self.spawners.clone();
        tokio::task::spawn_blocking(move || {
            let spawner = spawners
                .get(job.spawner)
                .map_err(|e| StartRunError::Spawn(e.kind()))?;
            let handle = bridge::start_run(
                spawner.as_ref(),
                &job.spec,
                &job.expect,
                job.init,
                job.sink,
                job.rt,
            )?;
            Ok(Arc::new(handle) as Arc<dyn RunControl>)
        })
        .await
        .unwrap_or_else(|_| Err(lost_blocking_call()))
    }
}

/// The real `ScriptRunner` (C.0).
pub struct ScriptGlue {
    port: Arc<dyn BridgePort>,
    /// `<install_dir>/atlas-duck-sandbox[.exe]`: the path the startup probe recorded the identity
    /// of (T10 review); `None` when the install dir is unknown (every spawn is refused).
    worker: Option<PathBuf>,
    inputs: ScriptInputs,
    /// `WorkerInit.read_op_ids` (§9.1 step 3): the registry's Read op ids.
    read_op_ids: Vec<String>,
    /// [`PROBE_WAIT`]; tests shorten it.
    probe_wait: Duration,
}

impl ScriptGlue {
    /// The glue over the real bridge, for the worker next to this executable (§3.4: only the
    /// canonical binary of the install dir). Creates no spawner yet.
    pub fn new(inputs: ScriptInputs) -> ScriptGlue {
        ScriptGlue::with_port(Arc::new(HostBridge::default()), canonical_worker(), inputs)
    }

    /// The glue over `port` for the worker at `worker`.
    pub fn with_port(
        port: Arc<dyn BridgePort>,
        worker: Option<PathBuf>,
        inputs: ScriptInputs,
    ) -> ScriptGlue {
        ScriptGlue {
            port,
            worker,
            inputs,
            read_op_ids: atlas_duck_core::read_op_ids()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            probe_wait: PROBE_WAIT,
        }
    }

    /// The sandbox binary was replaced since the probe (PD-133): scripts stay refused until
    /// restart.
    pub fn update_pending(&self) -> bool {
        self.inputs.update_pending.load(Ordering::SeqCst)
    }

    /// What a spawn under `policy` is admitted under, and the worker to spawn: the update flag,
    /// the startup report (awaited, PD-138), the floor rule (PD-141) and the identity re-check of
    /// the binary on disk (PD-133), in that order.
    async fn admission(
        &self,
        policy: RunPolicy,
        request_id: Option<&str>,
    ) -> Result<(policy::Admission, PathBuf), UnavailableReason> {
        if self.update_pending() {
            return Err(UnavailableReason::AppUpgraded);
        }
        let Some(report) = self.inputs.probe.wait(self.probe_wait).await else {
            tracing::warn!(event = LOG_EVENT_PROBE_PENDING, request_id);
            return Err(UnavailableReason::ProbePending);
        };
        let admission = policy::admit(
            report,
            self.inputs.probe.fallback(),
            self.worker.as_deref(),
            policy,
        )?;
        let exe = self.worker.clone().ok_or(UnavailableReason::SpawnFailed)?;
        self.recheck(&admission.expect, &exe, request_id).await?;
        Ok((admission, exe))
    }

    /// PD-133: the file identity of `exe` against the probe's record, on a blocking thread.
    async fn recheck(
        &self,
        expect: &ExpectedWorker,
        exe: &Path,
        request_id: Option<&str>,
    ) -> Result<(), UnavailableReason> {
        let (recorded, path) = (expect.identity.clone(), exe.to_path_buf());
        match tokio::task::spawn_blocking(move || identity::recheck(&recorded, &path)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => {
                self.upgraded(request_id);
                Err(UnavailableReason::AppUpgraded)
            }
            Err(_) => Err(UnavailableReason::SpawnFailed),
        }
    }

    /// PD-133: the binary was replaced; the flag stays set until restart.
    fn upgraded(&self, request_id: Option<&str>) {
        self.inputs.update_pending.store(true, Ordering::SeqCst);
        tracing::warn!(event = LOG_EVENT_IDENTITY_MISMATCH, request_id);
    }

    /// Logs a bridge refusal (constants only) and names it in core's words.
    fn refused(&self, e: &StartRunError, request_id: Option<&str>) -> UnavailableReason {
        match e {
            StartRunError::IdentityMismatch { .. } => self.upgraded(request_id),
            StartRunError::FloorNotMet => {
                tracing::warn!(
                    event = LOG_EVENT_SPAWN_FAILED,
                    reason = REASON_FLOOR_NOT_MET,
                    request_id
                );
            }
            StartRunError::Spawn(kind) => {
                tracing::warn!(event = LOG_EVENT_SPAWN_FAILED, reason = ?kind, request_id);
            }
        }
        map::unavailable_reason(e)
    }
}

#[async_trait]
impl ScriptRunner for ScriptGlue {
    async fn check_available(&self, policy: RunPolicy) -> Result<(), RunnerError> {
        self.admission(policy, None)
            .await
            .map(drop)
            .map_err(map::runner_error)
    }

    async fn compile_check(
        &self,
        source: &str,
        limits: &ScriptLimits,
        policy: RunPolicy,
    ) -> Result<(), CompileFailure> {
        let (admission, exe) = self
            .admission(policy, None)
            .await
            .map_err(|r| CompileFailure::Unavailable(map::runner_error(r)))?;
        let deadline = compile_deadline(limits);
        let timeout_s = u32::try_from(deadline.as_secs()).unwrap_or(u32::MAX);
        let job = CompileJob {
            spawner: admission.spawner,
            spec: SpawnSpec {
                exe,
                process_mb: limits.process_mb,
            },
            expect: admission.expect,
            source: source.to_owned(),
            deadline,
        };
        // The bridge bounds the compile itself; this bound also covers the spawn call and holds
        // if the bridge does not answer (PD-135: a compile worker never pins a dry-pool permit).
        let answer = tokio::time::timeout(deadline, self.port.compile(job))
            .await
            .unwrap_or(Ok(CompileVerdict::Timeout));
        if let Err(e) = &answer {
            self.refused(e, None);
        }
        map::compile_outcome(answer, timeout_s)
    }

    fn confinement(&self, policy: RunPolicy) -> Option<RunConfinement> {
        policy::confinement(
            self.inputs.probe.get(),
            self.inputs.probe.fallback(),
            self.worker.as_deref(),
            policy,
        )
    }

    async fn start(
        &self,
        run: RunSpec,
        calls: Arc<dyn HostCalls>,
    ) -> Result<Arc<dyn RunHandle>, RunnerError> {
        let request_id = run.run_id;
        let (admission, exe) = self
            .admission(run.policy, Some(&request_id))
            .await
            .map_err(map::runner_error)?;
        // The runtime core runs on (the app's, with the time driver) runs the host-call tasks.
        let rt =
            Handle::try_current().map_err(|_| map::runner_error(UnavailableReason::SpawnFailed))?;
        let spec = SpawnSpec {
            exe,
            process_mb: run.limits.process_mb,
        };
        let init = WorkerInit {
            source: run.source,
            args: run.args,
            limits: run.limits,
            read_op_ids: self.read_op_ids.clone(),
            instances: self.inputs.instances.list(),
        };
        let sink = Arc::new(CallsSink {
            calls,
            run_id: request_id.clone(),
        });
        let job = StartJob {
            spawner: admission.spawner,
            spec,
            expect: admission.expect,
            init,
            sink,
            rt,
        };
        match self.port.start(job).await {
            Ok(control) => Ok(Arc::new(RunHandleGlue {
                control,
                request_id,
                update_pending: self.inputs.update_pending.clone(),
                end: tokio::sync::OnceCell::new(),
                worker: OnceLock::new(),
            })),
            Err(e) => Err(map::runner_error(self.refused(&e, Some(&request_id)))),
        }
    }
}

/// The bridge's sink for one run (C.0): `call` forwards to core under core's run id (the bridge's
/// own `run-<n>` id names the channel only); `log` does nothing, the bridge collects the lines into
/// the outcome. Each call is a task of the bridge's that is never aborted (PD-148); this adapter
/// only awaits core's answer.
struct CallsSink {
    calls: Arc<dyn HostCalls>,
    run_id: String,
}

#[async_trait]
impl HostCallSink for CallsSink {
    async fn call(&self, _channel_run_id: &str, c: HostCall) -> HostCallResult {
        self.calls.call(&self.run_id, c).await
    }

    fn log(&self, _channel_run_id: &str, _line: &str) {}
}

/// Core's handle of a started run.
struct RunHandleGlue {
    control: Arc<dyn RunControl>,
    request_id: String,
    update_pending: Arc<AtomicBool>,
    /// The run's end, mapped once.
    end: tokio::sync::OnceCell<RunEnd>,
    /// The worker's own ready-frame report, known once `wait` returned.
    worker: OnceLock<ConfinementReport>,
}

impl RunHandleGlue {
    async fn finish(&self) -> RunEnd {
        let outcome = self.control.wait().await;
        log_diag(&self.request_id, &outcome.diag);
        if matches!(
            outcome.host,
            HostVerdict::NotSpawned(StartRunError::IdentityMismatch { .. })
        ) {
            self.update_pending.store(true, Ordering::SeqCst);
            tracing::warn!(
                event = LOG_EVENT_IDENTITY_MISMATCH,
                request_id = self.request_id.as_str()
            );
        }
        let _ = self.worker.set(outcome.confinement.clone());
        // One parse of a result up to `max_result_mb`: CPU work, off the runtime threads.
        tokio::task::spawn_blocking(move || map::to_run_end(outcome))
            .await
            .unwrap_or(RunEnd::Crashed)
    }
}

#[async_trait]
impl RunHandle for RunHandleGlue {
    fn kill(&self, why: KillReason) {
        self.control.kill(map::kill_cause(why));
    }

    async fn wait(&self) -> RunEnd {
        self.end.get_or_init(|| self.finish()).await.clone()
    }

    fn worker_confinement(&self) -> Option<ConfinementReport> {
        self.worker.get().cloned()
    }
}

/// The host facts of a run's outcome (`RunOutcome::diag`), one line each: the constant and the
/// request id, nothing the worker sent.
fn log_diag(request_id: &str, diag: &[&'static str]) {
    for fact in diag {
        let event = if SCRIPT_GLUE_EVENTS.contains(fact) {
            *fact
        } else {
            SCRIPT_DIAG_UNLISTED
        };
        tracing::info!(event, request_id);
    }
}
