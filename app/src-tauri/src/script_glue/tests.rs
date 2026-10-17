//! Unit tests of the glue over a fake bridge (M8 Task 20). Nothing here spawns a process: the
//! fake port answers for `compile_run` / `start_run`, and the "worker binary" is a plain file that
//! is never executed (the identity re-check reads its metadata only).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU32;
use std::sync::mpsc;
use std::time::Instant;

use atlas_duck_core::{ConfinementMode, RunPolicy};
use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::sandbox::probe::ProbeId;
use atlas_duck_ipc::sandbox::script::RawJsonText;
use atlas_duck_sandbox_host::bridge::{
    DIAG_CALL_RESULT_REPLACED, DIAG_HOST_PROTOCOL_EXIT, DIAG_JOB_MEMORY_LIMIT,
    DIAG_MEMORY_WATCH_FAILED, DIAG_OUTCOME_LOST, DIAG_REAP_FAILED, DIAG_STDIN_HELD,
    DIAG_STDOUT_HELD, DIAG_UNREAD_RESULTS, DIAG_WATCHDOG_KILL, ViolationKind, WorkerEnd,
};
use atlas_duck_sandbox_host::identity::{IdentityPart, SandboxBinaryIdentity, file_identity};
use atlas_duck_sandbox_host::probe::{FloorVerdict, ProbeReport};
use atlas_duck_sandbox_host::spawn::ExitKind;
use serde_json::json;
use tokio::sync::{Semaphore, watch};

use super::*;
use crate::sandbox_probe::FallbackIdentity;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The worker's embedded version the fake probe recorded.
const VERSION: &str = "fake-build-1";
/// Upper bound of every wait in these tests.
const BOUND: Duration = Duration::from_secs(10);
/// A kill is a few non-blocking steps: far below this.
const KILL_BOUND: Duration = Duration::from_millis(200);
/// Upper bound of a whole test body.
const TEST_BOUND: Duration = Duration::from_secs(30);

/// Runs a test body under [`TEST_BOUND`], so a glue that waits for ever fails the test instead
/// of hanging the run (a body that blocks a thread inside a poll is not caught here: the glue's
/// synchronous calls, `kill` and `confinement`, are bounded on threads of their own).
async fn bounded(body: impl std::future::Future<Output = TestResult>) -> TestResult {
    tokio::time::timeout(TEST_BOUND, body)
        .await
        .map_err(|_| "the test body did not finish within its bound")?
}

/// `kill`, from a plain thread (as the kill button and the cancel path call it), within
/// [`KILL_BOUND`].
fn kill_bounded(handle: &Arc<dyn RunHandle>, why: KillReason) -> TestResult {
    let (done_tx, done_rx) = mpsc::channel();
    let killer = handle.clone();
    std::thread::spawn(move || {
        killer.kill(why);
        let _ = done_tx.send(());
    });
    done_rx
        .recv_timeout(KILL_BOUND)
        .map_err(|_| "a kill did not return within its bound".into())
}

fn on() -> RunPolicy {
    RunPolicy {
        allow_degraded: true,
    }
}

fn off() -> RunPolicy {
    RunPolicy {
        allow_degraded: false,
    }
}

/// A plain file that exists and is never executed.
fn worker_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
}

/// A confinement report; the probe's says `mechanism: probe`, a fake worker's `worker`.
fn conf(applied: bool, mechanism: &str) -> ConfinementReport {
    ConfinementReport {
        applied,
        mechanism: mechanism.to_owned(),
        no_new_privs: None,
        landlock_abi: None,
        seccomp: None,
        lpac: None,
        os_error: None,
    }
}

fn not_met() -> FloorVerdict {
    FloorVerdict::NotMet {
        failed: vec![ProbeId::FileInProfile],
    }
}

/// The startup probe's report with the identity of `worker` as it is now.
fn report_for(worker: &Path, floor: FloorVerdict) -> Result<ProbeReport, std::io::Error> {
    let (file_id, size, mtime) = file_identity(worker)?;
    let applied = floor == FloorVerdict::Met;
    Ok(ProbeReport {
        worker_version: Some(VERSION.to_owned()),
        engine_version: Some("engine".to_owned()),
        identity: Some(SandboxBinaryIdentity {
            file_id,
            size,
            mtime,
            embedded_version: VERSION.to_owned(),
        }),
        confinement: Some(conf(applied, "probe")),
        threads: None,
        records: Vec::new(),
        floor,
        extra_layers: Vec::new(),
        control: None,
        lpac_failed: None,
    })
}

/// The startup probe's report when no probe worker sent its ready frame: no identity, no versions,
/// no confinement report.
fn bare_report(floor: FloorVerdict) -> ProbeReport {
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

/// What the holder must record for `worker` as it is now: its file identity and this build's id.
fn fallback_now(worker: &Path) -> Result<SandboxBinaryIdentity, std::io::Error> {
    let (file_id, size, mtime) = file_identity(worker)?;
    Ok(SandboxBinaryIdentity {
        file_id,
        size,
        mtime,
        embedded_version: BUILD_ID.to_owned(),
    })
}

fn outcome(end: WorkerEnd, host: HostVerdict) -> RunOutcome {
    RunOutcome {
        end,
        host,
        logs: vec!["a log line".to_owned()],
        logs_truncated: None,
        stderr: "stderr text".to_owned(),
        elapsed: Duration::from_millis(1234),
        confinement: conf(true, "worker"),
        diag: Vec::new(),
    }
}

fn result_end(json_text: &str) -> Result<WorkerEnd, serde_json::Error> {
    Ok(WorkerEnd::Result {
        value_json: Box::new(RawJsonText::from_string(json_text.to_owned())?),
    })
}

fn spec(policy: RunPolicy) -> RunSpec {
    RunSpec {
        run_id: "req-1".to_owned(),
        source: "return 1;".to_owned(),
        args: json!({ "a": 1 }),
        limits: ScriptLimits::default(),
        dry_run: false,
        policy,
    }
}

// ---- the fake bridge ----------------------------------------------------------------------------

/// What the fake bridge was asked for.
#[derive(Debug, Clone)]
enum Seen {
    Compile {
        spawner: SpawnerKind,
        accept_unconfined: bool,
        spec: SpawnSpec,
        source: String,
        deadline: Duration,
    },
    Start {
        spawner: SpawnerKind,
        accept_unconfined: bool,
        spec: SpawnSpec,
        init: Box<WorkerInit>,
    },
}

/// How the fake compile answers.
enum CompileAnswer {
    Verdict(Result<CompileVerdict, StartRunError>),
    /// Never: a compile worker that does not answer.
    Never,
    /// Answers once the test adds a permit (after the glue's own deadline, say).
    Gated(Arc<Semaphore>, Result<CompileVerdict, StartRunError>),
}

/// The fake bridge: records each job and applies the bridge's own ready-frame rule (PD-133,
/// PD-141) to the ready frame its "worker" would send.
struct FakePort {
    seen: Mutex<Vec<Seen>>,
    /// The fake worker's ready frame: version and confinement report.
    ready: Mutex<(String, ConfinementReport)>,
    compile: Mutex<CompileAnswer>,
    controls: Mutex<Vec<Arc<FakeControl>>>,
    sinks: Mutex<Vec<Arc<dyn HostCallSink>>>,
    /// The identity each job expected, in order.
    expected: Mutex<Vec<SandboxBinaryIdentity>>,
}

impl FakePort {
    fn new() -> Arc<FakePort> {
        Arc::new(FakePort {
            expected: Mutex::new(Vec::new()),
            seen: Mutex::new(Vec::new()),
            ready: Mutex::new((VERSION.to_owned(), conf(true, "worker"))),
            compile: Mutex::new(CompileAnswer::Verdict(Ok(CompileVerdict::Compiled))),
            controls: Mutex::new(Vec::new()),
            sinks: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<Seen> {
        lock(&self.seen).clone()
    }

    fn set_ready(&self, version: &str, report: ConfinementReport) {
        *lock(&self.ready) = (version.to_owned(), report);
    }

    fn set_compile(&self, answer: CompileAnswer) {
        *lock(&self.compile) = answer;
    }

    fn control(&self, n: usize) -> Option<Arc<FakeControl>> {
        lock(&self.controls).get(n).cloned()
    }

    fn sink(&self, n: usize) -> Option<Arc<dyn HostCallSink>> {
        lock(&self.sinks).get(n).cloned()
    }

    fn expected(&self) -> Vec<SandboxBinaryIdentity> {
        lock(&self.expected).clone()
    }

    /// The bridge's `check_ready` (PD-133, PD-141).
    fn check_ready(&self, expect: &ExpectedWorker) -> Result<(), StartRunError> {
        lock(&self.expected).push(expect.identity.clone());
        let (version, report) = lock(&self.ready).clone();
        if version != expect.identity.embedded_version {
            return Err(StartRunError::IdentityMismatch {
                what: IdentityPart::EmbeddedVersion,
            });
        }
        if !report.applied && !expect.accept_unconfined {
            return Err(StartRunError::FloorNotMet);
        }
        Ok(())
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[async_trait]
impl BridgePort for FakePort {
    async fn compile(&self, job: CompileJob) -> Result<CompileVerdict, StartRunError> {
        lock(&self.seen).push(Seen::Compile {
            spawner: job.spawner,
            accept_unconfined: job.expect.accept_unconfined,
            spec: job.spec.clone(),
            source: job.source.clone(),
            deadline: job.deadline,
        });
        self.check_ready(&job.expect)?;
        let (gate, answer) = match &*lock(&self.compile) {
            CompileAnswer::Verdict(v) => (None, Some(v.clone())),
            CompileAnswer::Never => (None, None),
            CompileAnswer::Gated(gate, v) => (Some(gate.clone()), Some(v.clone())),
        };
        if let Some(gate) = gate
            && let Ok(permit) = gate.acquire().await
        {
            permit.forget();
        }
        match answer {
            Some(v) => v,
            None => std::future::pending().await,
        }
    }

    async fn start(&self, job: StartJob) -> Result<Arc<dyn RunControl>, StartRunError> {
        lock(&self.seen).push(Seen::Start {
            spawner: job.spawner,
            accept_unconfined: job.expect.accept_unconfined,
            spec: job.spec.clone(),
            init: Box::new(job.init.clone()),
        });
        self.check_ready(&job.expect)?;
        let control = Arc::new(FakeControl::new(lock(&self.ready).1.clone()));
        lock(&self.controls).push(control.clone());
        lock(&self.sinks).push(job.sink);
        Ok(control)
    }
}

/// A started fake run: kills are recorded; the outcome is published by the test.
struct FakeControl {
    kills: Mutex<Vec<KillCause>>,
    outcome: watch::Sender<Option<RunOutcome>>,
    /// The ready frame's report, for the outcome.
    ready: ConfinementReport,
}

impl FakeControl {
    fn new(ready: ConfinementReport) -> FakeControl {
        FakeControl {
            kills: Mutex::new(Vec::new()),
            outcome: watch::channel(None).0,
            ready,
        }
    }

    fn kills(&self) -> Vec<KillCause> {
        lock(&self.kills).clone()
    }

    /// Ends the run with `outcome` (its confinement replaced by the ready frame's report).
    fn finish(&self, mut outcome: RunOutcome) {
        outcome.confinement = self.ready.clone();
        self.outcome.send_replace(Some(outcome));
    }
}

#[async_trait]
impl RunControl for FakeControl {
    fn kill(&self, cause: KillCause) {
        lock(&self.kills).push(cause);
    }

    async fn wait(&self) -> RunOutcome {
        let mut rx = self.outcome.subscribe();
        match rx.wait_for(Option::is_some).await {
            Ok(v) => v
                .clone()
                .unwrap_or_else(|| outcome(WorkerEnd::None, HostVerdict::Crashed(None))),
            Err(_) => outcome(WorkerEnd::None, HostVerdict::Crashed(None)),
        }
    }
}

/// Core's side of the host calls: records each call, answers once the test opens the gate.
struct GatedCalls {
    seen: Mutex<Vec<(String, u64)>>,
    gate: Semaphore,
    done: AtomicU32,
}

impl GatedCalls {
    fn new() -> Arc<GatedCalls> {
        Arc::new(GatedCalls {
            seen: Mutex::new(Vec::new()),
            gate: Semaphore::new(0),
            done: AtomicU32::new(0),
        })
    }
}

#[async_trait]
impl HostCalls for GatedCalls {
    async fn call(&self, run_id: &str, call: HostCall) -> HostCallResult {
        lock(&self.seen).push((run_id.to_owned(), call.id));
        if let Ok(permit) = self.gate.acquire().await {
            permit.forget();
        }
        self.done.fetch_add(1, Ordering::SeqCst);
        HostCallResult::Ok(json!({ "answer": call.id }))
    }

    fn log(&self, _run_id: &str, _line: &str) {}
}

/// A glue over `port` whose startup probe reported `report` (`None`: no report yet).
fn glue(port: &Arc<FakePort>, worker: &Path, report: Option<ProbeReport>) -> ScriptGlue {
    let inputs = ScriptInputs::default();
    if let Some(r) = report {
        let _ = inputs.probe.set(r);
    }
    ScriptGlue::with_port(port.clone(), Some(worker.to_path_buf()), inputs)
}

/// A glue spawning `worker` whose probe holder records the identity of `holder_worker` when the
/// report has none (the app's holder records the canonical worker's), resolved with `report`.
fn glue_recording(
    port: &Arc<FakePort>,
    worker: &Path,
    holder_worker: &Path,
    report: ProbeReport,
) -> ScriptGlue {
    let inputs = ScriptInputs {
        probe: Arc::new(ProbeHolder::for_worker(Some(holder_worker.to_path_buf()))),
        ..ScriptInputs::default()
    };
    let _ = inputs.probe.set(report);
    ScriptGlue::with_port(port.clone(), Some(worker.to_path_buf()), inputs)
}

fn unavailable(reason: UnavailableReason) -> RunnerError {
    RunnerError::SandboxUnavailable { reason }
}

/// The error of a `start` that must have refused.
fn start_error(r: Result<Arc<dyn RunHandle>, RunnerError>) -> Option<RunnerError> {
    r.err()
}

/// A `start` that must have started.
async fn started(
    g: &ScriptGlue,
    run: RunSpec,
    calls: Arc<dyn HostCalls>,
) -> Result<Arc<dyn RunHandle>, Box<dyn std::error::Error>> {
    g.start(run, calls)
        .await
        .map_err(|e| format!("start refused: {e:?}").into())
}

/// A scratch directory next to the test executable (in the target dir), removed on drop. Only
/// plain data files are written to it; nothing in it is executed.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Result<Scratch, Box<dyn std::error::Error>> {
        let dir = std::env::current_exe()?
            .parent()
            .ok_or("the test executable has no parent")?
            .join(format!("t20-glue-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        Ok(Scratch(dir))
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A new file renamed over `path` (an upgrade's shape): another file id.
fn replace(path: &Path) -> std::io::Result<()> {
    let next = path.with_extension("new");
    fs::write(&next, b"another worker")?;
    fs::rename(&next, path)
}

// ---- the tests ----------------------------------------------------------------------------------

/// Δ3, PD-134, T7 review m-9: every bridge outcome as core reads it; the worker's terminal frame
/// counts only when the host's verdict is `None`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn glue_maps_outcomes_to_run_end() -> TestResult {
    bounded(maps_outcomes_to_run_end()).await
}

async fn maps_outcomes_to_run_end() -> TestResult {
    let error = || WorkerEnd::Error {
        class: "TypeError".to_owned(),
        message: "x is not a function".to_owned(),
        stack: "at main".to_owned(),
    };
    let logs = vec!["a log line".to_owned()];
    let stderr = "stderr text".to_owned();
    let limit = |name: &str| RunEnd::HostLimit {
        name: name.to_owned(),
    };
    let table: Vec<(RunOutcome, RunEnd)> = vec![
        (
            outcome(result_end(r#"{"n":[1,2]}"#)?, HostVerdict::None),
            RunEnd::Result {
                value: json!({ "n": [1, 2] }),
                logs: logs.clone(),
                stderr: stderr.clone(),
            },
        ),
        (
            outcome(error(), HostVerdict::None),
            RunEnd::Error {
                class: "TypeError".to_owned(),
                message: "x is not a function".to_owned(),
                stack: "at main".to_owned(),
                // The host's clock (PD-134).
                elapsed_ms: 1234,
                logs: logs.clone(),
                stderr: stderr.clone(),
            },
        ),
        // A result text that does not read as a `Value` (a lone surrogate): a runtime error, never
        // a success and never a crash (T4 review I-1 rule).
        (
            outcome(result_end(r#""\ud800""#)?, HostVerdict::None),
            RunEnd::Error {
                class: map::CLASS_TYPE_ERROR.to_owned(),
                message: atlas_duck_sandbox_host::bridge::RESULT_NOT_REPRESENTABLE.to_owned(),
                stack: String::new(),
                elapsed_ms: 1234,
                logs: logs.clone(),
                stderr: stderr.clone(),
            },
        ),
        (outcome(WorkerEnd::None, HostVerdict::None), RunEnd::Crashed),
        (
            outcome(WorkerEnd::None, HostVerdict::Limit("timeout_s")),
            limit("timeout_s"),
        ),
        (
            outcome(WorkerEnd::None, HostVerdict::Limit("heap_mb")),
            limit("heap_mb"),
        ),
        // A worker that wrote its result and then went above `process_mb`: the host's verdict.
        (
            outcome(result_end("1")?, HostVerdict::Limit("process_mb")),
            limit("process_mb"),
        ),
        (
            outcome(WorkerEnd::None, HostVerdict::Killed(KillCause::User)),
            RunEnd::Killed {
                reason: KillReason::User,
            },
        ),
        (
            outcome(
                WorkerEnd::None,
                HostVerdict::Killed(KillCause::Limit("max_calls".to_owned())),
            ),
            RunEnd::Killed {
                reason: KillReason::Limit("max_calls".to_owned()),
            },
        ),
        // A second terminal frame: `end` holds the first result, but the host's verdict decides.
        (
            outcome(
                result_end("1")?,
                HostVerdict::Violation(ViolationKind::SecondTerminal),
            ),
            RunEnd::ProtocolViolation,
        ),
        (
            outcome(
                WorkerEnd::None,
                HostVerdict::Violation(ViolationKind::UnreadResults),
            ),
            RunEnd::ProtocolViolation,
        ),
        // Exit 3 without a terminal frame is a host fault, never a protocol violation.
        (
            outcome(WorkerEnd::None, HostVerdict::HostFault),
            RunEnd::Crashed,
        ),
        (
            outcome(
                result_end("1")?,
                HostVerdict::Crashed(Some(ExitKind::Code(101))),
            ),
            RunEnd::Crashed,
        ),
        (
            outcome(WorkerEnd::None, HostVerdict::Crashed(None)),
            RunEnd::Crashed,
        ),
        (
            outcome(
                WorkerEnd::None,
                HostVerdict::NotSpawned(StartRunError::IdentityMismatch {
                    what: IdentityPart::Size,
                }),
            ),
            limit("app_upgraded"),
        ),
        (
            outcome(
                WorkerEnd::None,
                HostVerdict::NotSpawned(StartRunError::FloorNotMet),
            ),
            limit("sandbox_unavailable"),
        ),
        (
            outcome(
                WorkerEnd::None,
                HostVerdict::NotSpawned(StartRunError::Spawn(io::ErrorKind::TimedOut)),
            ),
            limit("sandbox_unavailable"),
        ),
    ];
    for (outcome, expected) in table {
        let shown = format!("{:?} / {:?}", outcome.host, outcome.end);
        assert_eq!(map::to_run_end(outcome), expected, "{shown}");
    }

    // The same through a started run: `wait` answers the mapped end every time, and the worker's
    // own ready-frame report is known once it returned (PD-141 (c)).
    let port = FakePort::new();
    let g = glue(
        &port,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    let handle = started(&g, spec(off()), GatedCalls::new()).await?;
    assert!(
        handle.worker_confinement().is_none(),
        "known only after wait"
    );
    let control = port.control(0).ok_or("no run")?;
    control.finish(outcome(error(), HostVerdict::None));
    let end = tokio::time::timeout(BOUND, handle.wait()).await?;
    assert!(
        matches!(
            &end,
            RunEnd::Error {
                elapsed_ms: 1234,
                ..
            }
        ),
        "{end:?}"
    );
    assert_eq!(tokio::time::timeout(BOUND, handle.wait()).await?, end);
    assert_eq!(handle.worker_confinement(), Some(conf(true, "worker")));

    // A refused spawn answers through `start`, so the record keeps the exact cause (T12 review
    // M-6): the embedded version, the floor, a spawn error.
    port.set_ready("another-build", conf(true, "worker"));
    assert_eq!(
        start_error(g.start(spec(off()), GatedCalls::new()).await),
        Some(unavailable(UnavailableReason::AppUpgraded))
    );
    let fresh = FakePort::new();
    let g = glue(
        &fresh,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    fresh.set_ready(VERSION, conf(false, "worker"));
    assert_eq!(
        start_error(g.start(spec(off()), GatedCalls::new()).await),
        Some(unavailable(UnavailableReason::FloorNotMet))
    );
    assert!(!g.update_pending());
    Ok(())
}

/// PD-133: the file identity is checked at submit and again before every spawn; a mismatch
/// spawns nothing, answers `app_upgraded` and keeps every later script refused until restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn glue_rechecks_identity_before_spawn() -> TestResult {
    bounded(rechecks_identity_before_spawn()).await
}

async fn rechecks_identity_before_spawn() -> TestResult {
    // Replaced before submit: refused at `check_available`.
    let dir = Scratch::new("submit")?;
    let worker = dir.file("atlas-duck-sandbox");
    fs::write(&worker, b"worker")?;
    let port = FakePort::new();
    let g = glue(
        &port,
        &worker,
        Some(report_for(&worker, FloorVerdict::Met)?),
    );
    assert_eq!(g.check_available(off()).await, Ok(()));
    replace(&worker)?;
    assert_eq!(
        g.check_available(off()).await,
        Err(unavailable(UnavailableReason::AppUpgraded))
    );
    assert!(g.update_pending());
    // Sticky: the compile and the spawn are refused too, without reaching the bridge.
    assert_eq!(
        g.compile_check("return 1;", &ScriptLimits::default(), off())
            .await,
        Err(CompileFailure::Unavailable(unavailable(
            UnavailableReason::AppUpgraded
        )))
    );
    assert_eq!(
        start_error(g.start(spec(off()), GatedCalls::new()).await),
        Some(unavailable(UnavailableReason::AppUpgraded))
    );
    assert!(port.seen().is_empty(), "{:?}", port.seen());

    // Replaced after the submit and the compile, before the run's spawn (a queued run): the
    // spawn itself re-checks.
    let dir = Scratch::new("spawn")?;
    let worker = dir.file("atlas-duck-sandbox");
    fs::write(&worker, b"worker")?;
    let port = FakePort::new();
    let g = glue(
        &port,
        &worker,
        Some(report_for(&worker, FloorVerdict::Met)?),
    );
    assert_eq!(g.check_available(off()).await, Ok(()));
    assert_eq!(
        g.compile_check("return 1;", &ScriptLimits::default(), off())
            .await,
        Ok(())
    );
    replace(&worker)?;
    assert_eq!(
        start_error(g.start(spec(off()), GatedCalls::new()).await),
        Some(unavailable(UnavailableReason::AppUpgraded))
    );
    assert!(g.update_pending());
    let starts = port
        .seen()
        .iter()
        .filter(|s| matches!(s, Seen::Start { .. }))
        .count();
    assert_eq!(starts, 0, "nothing spawned from a replaced binary");

    // The same before a compile worker's spawn.
    let dir = Scratch::new("compile")?;
    let worker = dir.file("atlas-duck-sandbox");
    fs::write(&worker, b"worker")?;
    let port = FakePort::new();
    let g = glue(
        &port,
        &worker,
        Some(report_for(&worker, FloorVerdict::Met)?),
    );
    assert_eq!(g.check_available(off()).await, Ok(()));
    fs::remove_file(&worker)?;
    assert_eq!(
        g.compile_check("return 1;", &ScriptLimits::default(), off())
            .await,
        Err(CompileFailure::Unavailable(unavailable(
            UnavailableReason::AppUpgraded
        )))
    );
    assert!(port.seen().is_empty(), "{:?}", port.seen());
    assert!(g.update_pending());

    // The worker's ready frame naming another version (the bridge's half of PD-133) sets the
    // flag too.
    let port = FakePort::new();
    let g = glue(
        &port,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    port.set_ready("another-build", conf(true, "worker"));
    assert_eq!(
        g.compile_check("return 1;", &ScriptLimits::default(), off())
            .await,
        Err(CompileFailure::Unavailable(unavailable(
            UnavailableReason::AppUpgraded
        )))
    );
    assert!(g.update_pending());
    // Refused until restart, even once the worker would answer as recorded again.
    port.set_ready(VERSION, conf(true, "worker"));
    let reached = port.seen().len();
    assert_eq!(
        g.check_available(off()).await,
        Err(unavailable(UnavailableReason::AppUpgraded))
    );
    assert_eq!(
        start_error(g.start(spec(off()), GatedCalls::new()).await),
        Some(unavailable(UnavailableReason::AppUpgraded))
    );
    assert_eq!(port.seen().len(), reached, "nothing reached the bridge");
    Ok(())
}

/// PD-138, R10: the glue awaits the startup report (bounded), then applies the floor rule; with no
/// report in time it answers `probe_pending`. The production bound is 60 s; the test shortens it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn glue_awaits_startup_probe_then_refuses_when_floor_not_met() -> TestResult {
    bounded(awaits_startup_probe_then_refuses_when_floor_not_met()).await
}

async fn awaits_startup_probe_then_refuses_when_floor_not_met() -> TestResult {
    assert_eq!(PROBE_WAIT, Duration::from_secs(60));
    let port = FakePort::new();
    let mut g = glue(&port, &worker_file(), None);
    g.probe_wait = Duration::from_millis(300);
    // No report within the bound.
    let started = Instant::now();
    assert_eq!(
        g.check_available(on()).await,
        Err(unavailable(UnavailableReason::ProbePending))
    );
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(g.confinement(on()).is_none(), "no report, no statement");

    // The report arrives while a check waits: the check answers from it.
    let g = Arc::new({
        let mut g = glue(&port, &worker_file(), None);
        g.probe_wait = BOUND;
        g
    });
    let waiting = {
        let g = g.clone();
        tokio::spawn(async move { g.check_available(off()).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!waiting.is_finished(), "the check awaits the report");
    let _ = g.inputs.probe.set(report_for(&worker_file(), not_met())?);
    let answered = tokio::time::timeout(BOUND, waiting).await??;
    assert_eq!(answered, Err(unavailable(UnavailableReason::FloorNotMet)));
    // Not met and degraded not allowed: every step refuses, nothing reaches the bridge.
    assert_eq!(
        g.compile_check("return 1;", &ScriptLimits::default(), off())
            .await,
        Err(CompileFailure::Unavailable(unavailable(
            UnavailableReason::FloorNotMet
        )))
    );
    assert_eq!(
        start_error(g.start(spec(off()), GatedCalls::new()).await),
        Some(unavailable(UnavailableReason::FloorNotMet))
    );
    assert!(g.confinement(off()).is_none());
    assert!(port.seen().is_empty(), "{:?}", port.seen());

    // A report without a recorded identity (no probe worker answered) in a holder that records
    // none itself (no worker path): fail closed even with degraded allowed.
    let g = glue(&port, &worker_file(), Some(bare_report(not_met())));
    assert!(g.inputs.probe.fallback().is_none());
    assert_eq!(
        g.check_available(on()).await,
        Err(unavailable(UnavailableReason::SpawnFailed))
    );
    assert!(g.confinement(on()).is_none());
    // No install dir: nothing to spawn.
    let inputs = ScriptInputs::default();
    let _ = inputs
        .probe
        .set(report_for(&worker_file(), FloorVerdict::Met)?);
    let g = ScriptGlue::with_port(port.clone(), None, inputs);
    assert_eq!(
        g.check_available(off()).await,
        Err(unavailable(UnavailableReason::SpawnFailed))
    );
    assert!(port.seen().is_empty(), "{:?}", port.seen());
    Ok(())
}

/// PD-141: the degraded toggle covers only a probe-time `NotMet`. (a) the worker's own report is
/// what the end record gets; (b) an unconfined ready frame under a `Met` report is `FloorNotMet`
/// with the toggle on; (c) with a `NotMet` report and the toggle on the run starts degraded, on the
/// spawner whose probe workers reached ready (§9.4: the lockdown-token spawner only when no
/// AppContainer worker could start, see the fallback-identity test).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn glue_degraded_policy_keeps_the_probes_spawner() -> TestResult {
    bounded(degraded_policy_keeps_the_probes_spawner()).await
}

async fn degraded_policy_keeps_the_probes_spawner() -> TestResult {
    // (c) NotMet + toggle on, the probe workers reached ready (the report has an identity; a floor
    // probe was not blocked, or the control re-run invalidated it): the same spawner, so a Windows
    // run keeps its AppContainer; an unconfined worker accepted.
    let degraded_kind = SpawnerKind::Platform;
    let port = FakePort::new();
    port.set_ready(VERSION, conf(false, "lockdown_token"));
    let g = glue(
        &port,
        &worker_file(),
        Some(report_for(&worker_file(), not_met())?),
    );
    let admitted = g.confinement(on()).ok_or("no confinement")?;
    assert_eq!(admitted.mode, ConfinementMode::Degraded);
    assert_eq!(admitted.worker_version, VERSION);
    assert_eq!(
        admitted.probe_report,
        Some(conf(false, "probe")),
        "the probe's report"
    );
    assert_eq!(g.check_available(on()).await, Ok(()));
    assert_eq!(
        g.compile_check("return 1;", &ScriptLimits::default(), on())
            .await,
        Ok(())
    );
    let handle = started(&g, spec(on()), GatedCalls::new()).await?;
    let seen = port.seen();
    assert!(
        matches!(
            seen.as_slice(),
            [
                Seen::Compile { spawner: c, accept_unconfined: true, .. },
                Seen::Start { spawner: s, accept_unconfined: true, .. },
            ] if *c == degraded_kind && *s == degraded_kind
        ),
        "{seen:?}"
    );
    // (a) The run's own worker's report, not the probe's, reaches the end record.
    port.control(0)
        .ok_or("no run")?
        .finish(outcome(result_end("1")?, HostVerdict::None));
    tokio::time::timeout(BOUND, handle.wait()).await?;
    assert_eq!(
        handle.worker_confinement(),
        Some(conf(false, "lockdown_token"))
    );
    // The toggle off at the spawn (revoked after submit): refused, nothing spawned.
    assert_eq!(
        start_error(g.start(spec(off()), GatedCalls::new()).await),
        Some(unavailable(UnavailableReason::FloorNotMet))
    );
    assert_eq!(port.seen().len(), 2);

    // (b) Met + toggle on, and the worker's ready frame says `applied: false`: refused.
    let port = FakePort::new();
    port.set_ready(VERSION, conf(false, "none"));
    let g = glue(
        &port,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    assert_eq!(
        g.confinement(on()).map(|c| c.mode),
        Some(ConfinementMode::Floor)
    );
    assert_eq!(
        start_error(g.start(spec(on()), GatedCalls::new()).await),
        Some(unavailable(UnavailableReason::FloorNotMet))
    );
    assert_eq!(
        g.compile_check("return 1;", &ScriptLimits::default(), on())
            .await,
        Err(CompileFailure::Unavailable(unavailable(
            UnavailableReason::FloorNotMet
        )))
    );
    for s in port.seen() {
        match s {
            Seen::Compile {
                spawner,
                accept_unconfined,
                ..
            }
            | Seen::Start {
                spawner,
                accept_unconfined,
                ..
            } => {
                assert!(!accept_unconfined, "Met: never unconfined");
                assert_eq!(spawner, SpawnerKind::Platform);
            }
        }
    }
    assert!(!g.update_pending());

    // The Windows fallback (the plain AppContainer rerun met the floor): its spawner.
    let port = FakePort::new();
    let mut report = report_for(&worker_file(), FloorVerdict::Met)?;
    report.lpac_failed = Some(vec![ProbeId::ConnectLoopback]);
    let g = glue(&port, &worker_file(), Some(report));
    let _handle = started(&g, spec(on()), GatedCalls::new()).await?;
    assert!(
        matches!(
            port.seen().as_slice(),
            [Seen::Start {
                spawner: SpawnerKind::Fallback,
                accept_unconfined: false,
                ..
            }]
        ),
        "{:?}",
        port.seen()
    );
    Ok(())
}

/// M8 T20 ruling (PD-133, PD-141): when no probe worker reached ready (Windows below the floor) the
/// report has no identity; the holder records the canonical worker's file identity and this
/// build's id itself, once, when it resolves. A degraded run (toggle on, `NotMet`) is checked
/// against that record before every spawn, the bridge checks the ready frame's version against
/// it, and the end record gets the degraded worker's own report; nothing stands in for the
/// probe's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn glue_degraded_windows_without_probe_identity_records_fallback_identity() -> TestResult {
    bounded(degraded_without_probe_identity_records_fallback_identity()).await
}

async fn degraded_without_probe_identity_records_fallback_identity() -> TestResult {
    let degraded_kind = if cfg!(windows) {
        SpawnerKind::Degraded
    } else {
        SpawnerKind::Platform
    };
    let dir = Scratch::new("fallback")?;
    let worker = dir.file("atlas-duck-sandbox");
    fs::write(&worker, b"worker")?;
    let recorded = fallback_now(&worker)?;

    // A report with an identity: the holder records nothing of its own.
    let port = FakePort::new();
    let g = glue_recording(&port, &worker, &worker, report_for(&worker, not_met())?);
    assert!(g.inputs.probe.fallback().is_none());

    // No probe worker reached ready: recorded when the holder resolved.
    let port = FakePort::new();
    port.set_ready(BUILD_ID, conf(false, "lockdown_token"));
    let g = glue_recording(&port, &worker, &worker, bare_report(not_met()));
    assert_eq!(
        g.inputs.probe.fallback(),
        Some(&FallbackIdentity {
            worker: worker.clone(),
            identity: Some(recorded.clone()),
        })
    );
    // `SCRIPT_STARTED` says degraded, with this build's id and no probe report (none exists).
    let admitted = g.confinement(on()).ok_or("no confinement")?;
    assert_eq!(admitted.mode, ConfinementMode::Degraded);
    assert_eq!(admitted.worker_version, BUILD_ID);
    assert_eq!(admitted.probe_report, None);
    // The toggle off: the floor rule refuses first.
    assert!(g.confinement(off()).is_none());
    assert_eq!(
        g.check_available(off()).await,
        Err(unavailable(UnavailableReason::FloorNotMet))
    );
    assert_eq!(g.check_available(on()).await, Ok(()));
    assert_eq!(
        g.compile_check("return 1;", &ScriptLimits::default(), on())
            .await,
        Ok(())
    );
    let handle = started(&g, spec(on()), GatedCalls::new()).await?;
    let seen = port.seen();
    assert!(
        matches!(
            seen.as_slice(),
            [
                Seen::Compile { spawner: c, accept_unconfined: true, .. },
                Seen::Start { spawner: s, accept_unconfined: true, .. },
            ] if *c == degraded_kind && *s == degraded_kind
        ),
        "{seen:?}"
    );
    // The bridge expects the recorded identity (its ready-frame check is the backstop).
    assert_eq!(port.expected(), [recorded.clone(), recorded.clone()]);
    // The end record gets the degraded worker's own ready-frame report.
    port.control(0)
        .ok_or("no run")?
        .finish(outcome(result_end("1")?, HostVerdict::None));
    tokio::time::timeout(BOUND, handle.wait()).await?;
    assert_eq!(
        handle.worker_confinement(),
        Some(conf(false, "lockdown_token"))
    );
    assert!(!g.update_pending());

    // The backstop: a worker whose ready frame names another build is refused as an upgrade.
    port.set_ready("another-build", conf(false, "lockdown_token"));
    assert_eq!(
        start_error(g.start(spec(on()), GatedCalls::new()).await),
        Some(unavailable(UnavailableReason::AppUpgraded))
    );
    assert!(g.update_pending());

    // Recorded once, when the holder resolved, never at a spawn: a binary replaced after that is
    // a mismatch against the record, and nothing is spawned from it.
    let dir = Scratch::new("fallback-replaced")?;
    let worker = dir.file("atlas-duck-sandbox");
    fs::write(&worker, b"worker")?;
    let port = FakePort::new();
    port.set_ready(BUILD_ID, conf(false, "lockdown_token"));
    let g = glue_recording(&port, &worker, &worker, bare_report(not_met()));
    replace(&worker)?;
    assert_eq!(
        start_error(g.start(spec(on()), GatedCalls::new()).await),
        Some(unavailable(UnavailableReason::AppUpgraded))
    );
    assert!(g.update_pending());
    assert!(port.seen().is_empty(), "{:?}", port.seen());
    Ok(())
}

/// M8 T20 ruling: the holder's own record serves a degraded spawn only. Under a `Met` report
/// without an identity every spawn is refused (fail closed) whatever the toggle says, and a
/// record of another path than the one spawned is never used.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn glue_met_report_without_probe_identity_refuses() -> TestResult {
    bounded(met_report_without_probe_identity_refuses()).await
}

async fn met_report_without_probe_identity_refuses() -> TestResult {
    let dir = Scratch::new("fallback-met")?;
    let worker = dir.file("atlas-duck-sandbox");
    fs::write(&worker, b"worker")?;
    let port = FakePort::new();
    port.set_ready(BUILD_ID, conf(true, "worker"));
    let g = glue_recording(&port, &worker, &worker, bare_report(FloorVerdict::Met));
    // Recorded (the report has no identity), and still not used.
    assert!(
        g.inputs
            .probe
            .fallback()
            .is_some_and(|f| f.identity.is_some())
    );
    for policy in [on(), off()] {
        assert!(g.confinement(policy).is_none());
        assert_eq!(
            g.check_available(policy).await,
            Err(unavailable(UnavailableReason::SpawnFailed))
        );
        assert_eq!(
            g.compile_check("return 1;", &ScriptLimits::default(), policy)
                .await,
            Err(CompileFailure::Unavailable(unavailable(
                UnavailableReason::SpawnFailed
            )))
        );
        assert_eq!(
            start_error(g.start(spec(policy), GatedCalls::new()).await),
            Some(unavailable(UnavailableReason::SpawnFailed))
        );
    }
    assert!(port.seen().is_empty(), "{:?}", port.seen());

    // `NotMet` and degraded allowed, but the record is of another path than the spawn's.
    let other = dir.file("other-sandbox");
    fs::write(&other, b"worker")?;
    let port = FakePort::new();
    port.set_ready(BUILD_ID, conf(false, "lockdown_token"));
    let g = glue_recording(&port, &worker, &other, bare_report(not_met()));
    assert!(g.confinement(on()).is_none());
    assert_eq!(
        g.check_available(on()).await,
        Err(unavailable(UnavailableReason::SpawnFailed))
    );
    assert_eq!(
        start_error(g.start(spec(on()), GatedCalls::new()).await),
        Some(unavailable(UnavailableReason::SpawnFailed))
    );
    assert!(port.seen().is_empty(), "{:?}", port.seen());
    assert!(!g.update_pending());
    Ok(())
}

/// M8 T20 ruling: a worker binary whose identity could not be read when the holder resolved is
/// `SpawnFailed` for every degraded spawn, also once the file is there (never read at a spawn).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn glue_fallback_identity_read_failure_refuses() -> TestResult {
    bounded(fallback_identity_read_failure_refuses()).await
}

async fn fallback_identity_read_failure_refuses() -> TestResult {
    let dir = Scratch::new("fallback-missing")?;
    let worker = dir.file("atlas-duck-sandbox");
    let port = FakePort::new();
    port.set_ready(BUILD_ID, conf(false, "lockdown_token"));
    let g = glue_recording(&port, &worker, &worker, bare_report(not_met()));
    assert_eq!(
        g.inputs.probe.fallback(),
        Some(&FallbackIdentity {
            worker: worker.clone(),
            identity: None,
        })
    );
    // The binary appears after the holder resolved.
    fs::write(&worker, b"worker")?;
    assert!(g.confinement(on()).is_none());
    assert_eq!(
        g.check_available(on()).await,
        Err(unavailable(UnavailableReason::SpawnFailed))
    );
    assert_eq!(
        g.compile_check("return 1;", &ScriptLimits::default(), on())
            .await,
        Err(CompileFailure::Unavailable(unavailable(
            UnavailableReason::SpawnFailed
        )))
    );
    assert_eq!(
        start_error(g.start(spec(on()), GatedCalls::new()).await),
        Some(unavailable(UnavailableReason::SpawnFailed))
    );
    assert!(port.seen().is_empty(), "{:?}", port.seen());
    assert!(!g.update_pending(), "a read failure is no upgrade");
    Ok(())
}

/// PD-135: a compile worker that never answers is `Timeout` within `min(10 s, timeout_s)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn glue_compile_check_has_a_deadline() -> TestResult {
    bounded(compile_check_has_a_deadline()).await
}

async fn compile_check_has_a_deadline() -> TestResult {
    let bound = |timeout_s| {
        compile_deadline(&ScriptLimits {
            timeout_s,
            ..ScriptLimits::default()
        })
    };
    assert_eq!(bound(120), Duration::from_secs(10));
    assert_eq!(bound(10), Duration::from_secs(10));
    assert_eq!(bound(3), Duration::from_secs(3));
    assert_eq!(bound(1), Duration::from_secs(1));

    let port = FakePort::new();
    port.set_compile(CompileAnswer::Never);
    let g = glue(
        &port,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    let limits = ScriptLimits {
        timeout_s: 1,
        ..ScriptLimits::default()
    };
    let started = Instant::now();
    let answer = tokio::time::timeout(BOUND, g.compile_check("return 1;", &limits, off())).await?;
    let took = started.elapsed();
    assert_eq!(answer, Err(CompileFailure::Timeout { timeout_s: 1 }));
    // Not before the bound; the upper end leaves a stalled runner room and stays below the
    // 10 s a bound that ignored `timeout_s` would take.
    assert!(
        took >= Duration::from_secs(1) && took < Duration::from_secs(8),
        "{took:?}"
    );
    // The bridge is given the same bound.
    assert!(
        matches!(port.seen().as_slice(), [Seen::Compile { deadline, .. }] if *deadline == Duration::from_secs(1)),
        "{:?}",
        port.seen()
    );
    // The bridge's own deadline answer is the same data-free limit.
    port.set_compile(CompileAnswer::Verdict(Ok(CompileVerdict::Timeout)));
    assert_eq!(
        g.compile_check("return 1;", &ScriptLimits::default(), off())
            .await,
        Err(CompileFailure::Timeout { timeout_s: 10 })
    );
    Ok(())
}

/// T20 review m-3: the glue's compile deadline answers `Timeout` but does not drop the bridge's
/// call: an answer after it (the first spawner's creation can take seconds on Windows) is still
/// seen, and a late identity refusal still sets the update flag (PD-133).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn glue_compile_timeout_keeps_a_late_refusal() -> TestResult {
    bounded(compile_timeout_keeps_a_late_refusal()).await
}

async fn compile_timeout_keeps_a_late_refusal() -> TestResult {
    let port = FakePort::new();
    let gate = Arc::new(Semaphore::new(0));
    port.set_compile(CompileAnswer::Gated(
        gate.clone(),
        Err(StartRunError::IdentityMismatch {
            what: IdentityPart::EmbeddedVersion,
        }),
    ));
    let g = glue(
        &port,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    let limits = ScriptLimits {
        timeout_s: 1,
        ..ScriptLimits::default()
    };
    let answer = tokio::time::timeout(BOUND, g.compile_check("return 1;", &limits, off())).await?;
    assert_eq!(answer, Err(CompileFailure::Timeout { timeout_s: 1 }));
    assert!(!g.update_pending(), "no answer yet");
    // The bridge answers after the deadline: the worker's ready frame names another build.
    gate.add_permits(1);
    let waited = Instant::now();
    while !g.update_pending() && waited.elapsed() < BOUND {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(g.update_pending(), "the late refusal was lost");
    assert_eq!(
        g.check_available(off()).await,
        Err(unavailable(UnavailableReason::AppUpgraded))
    );
    Ok(())
}

/// PD-132: the compile check runs a compile-only worker (`compile_run`), never a run, with the
/// source, the run's memory limit and the floor's spawner; its answers map to core's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn glue_compile_check_uses_compile_mode() -> TestResult {
    bounded(compile_check_uses_compile_mode()).await
}

async fn compile_check_uses_compile_mode() -> TestResult {
    let port = FakePort::new();
    let g = glue(
        &port,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    let limits = ScriptLimits {
        timeout_s: 30,
        process_mb: 300,
        heap_mb: 200,
        ..ScriptLimits::default()
    };
    assert_eq!(g.compile_check("return 2;", &limits, off()).await, Ok(()));
    let seen = port.seen();
    let [
        Seen::Compile {
            spawner,
            accept_unconfined,
            spec,
            source,
            deadline,
        },
    ] = seen.as_slice()
    else {
        return Err(format!("expected one compile and no run: {seen:?}").into());
    };
    assert_eq!(*spawner, SpawnerKind::Platform);
    assert!(!accept_unconfined);
    assert_eq!(spec.exe, worker_file());
    assert_eq!(spec.process_mb, 300);
    assert_eq!(source, "return 2;");
    assert_eq!(*deadline, Duration::from_secs(10));

    port.set_compile(CompileAnswer::Verdict(Ok(CompileVerdict::Syntax {
        line: 3,
        column: 7,
        message: "unexpected token".to_owned(),
    })));
    assert_eq!(
        g.compile_check("x(", &limits, off()).await,
        Err(CompileFailure::Syntax(atlas_duck_core::CompileError {
            line: 3,
            column: 7,
            message: "unexpected token".to_owned(),
        }))
    );
    // A compile worker that gave no verdict (exit 3, a bad reply, a failed spawn) is unavailable,
    // never a syntax error (T7, T11 hand-offs).
    for e in [
        StartRunError::Spawn(io::ErrorKind::InvalidData),
        StartRunError::Spawn(io::ErrorKind::TimedOut),
        StartRunError::Spawn(io::ErrorKind::PermissionDenied),
    ] {
        port.set_compile(CompileAnswer::Verdict(Err(e)));
        assert_eq!(
            g.compile_check("return 1;", &limits, off()).await,
            Err(CompileFailure::Unavailable(unavailable(
                UnavailableReason::SpawnFailed
            )))
        );
    }
    assert!(
        port.seen()
            .iter()
            .all(|s| matches!(s, Seen::Compile { .. })),
        "{:?}",
        port.seen()
    );
    Ok(())
}

/// §9.1 step 3, R9: the init frame carries the run's source, args and limits, the registry's
/// Read op ids only, and the core's instances by alias (never a URL).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn glue_builds_worker_init_with_read_ops_and_instances() -> TestResult {
    bounded(builds_worker_init_with_read_ops_and_instances()).await
}

async fn builds_worker_init_with_read_ops_and_instances() -> TestResult {
    let port = FakePort::new();
    let g = glue(
        &port,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    // Before the core started: no instances.
    let _first = started(&g, spec(off()), GatedCalls::new()).await?;
    g.inputs.instances.set(|| {
        vec![
            InstanceInfo {
                alias: "jira-main".to_owned(),
                product: "jira".to_owned(),
                is_default: true,
            },
            InstanceInfo {
                alias: "wiki".to_owned(),
                product: "confluence".to_owned(),
                is_default: false,
            },
        ]
    });
    let run = RunSpec {
        limits: ScriptLimits {
            max_calls: 7,
            process_mb: 333,
            ..ScriptLimits::default()
        },
        ..spec(off())
    };
    let _second = started(&g, run.clone(), GatedCalls::new()).await?;
    let mut spawned = Vec::new();
    let inits: Vec<WorkerInit> = port
        .seen()
        .into_iter()
        .filter_map(|s| match s {
            Seen::Start { init, spec, .. } => {
                spawned.push(spec);
                Some(*init)
            }
            Seen::Compile { .. } => None,
        })
        .collect();
    // The canonical worker, under the run's own process limit (§9.4 `process_mb`).
    let spawned: Vec<(PathBuf, u32)> = spawned.into_iter().map(|s| (s.exe, s.process_mb)).collect();
    assert_eq!(spawned, [(worker_file(), 512), (worker_file(), 333)]);
    let [first, second] = inits.as_slice() else {
        return Err(format!("two starts expected: {inits:?}").into());
    };
    assert!(first.instances.is_empty());
    assert_eq!(second.source, run.source);
    assert_eq!(second.args, run.args);
    assert_eq!(second.limits, run.limits);
    // Every Read op of the registry, and nothing else.
    let reads: Vec<&str> = atlas_duck_registry::all()
        .iter()
        .filter(|op| op.class == atlas_duck_registry::OpClass::Read)
        .map(|op| op.id)
        .collect();
    assert!(!reads.is_empty());
    assert_eq!(second.read_op_ids, reads);
    assert!(
        atlas_duck_registry::all()
            .iter()
            .any(|op| op.class != atlas_duck_registry::OpClass::Read),
        "the registry has writes the init must leave out"
    );
    // Aliases, products and default flags; no URL anywhere in the frame's instances.
    assert_eq!(
        serde_json::to_value(&second.instances)?,
        json!([
            { "alias": "jira-main", "product": "jira", "is_default": true },
            { "alias": "wiki", "product": "confluence", "is_default": false },
        ])
    );
    Ok(())
}

/// M3 M-1, PD-137: a kill goes straight to the bridge's kill and never waits, not for a pending
/// `wait`, not for the outcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn glue_kill_never_blocks() -> TestResult {
    bounded(kill_never_blocks()).await
}

async fn kill_never_blocks() -> TestResult {
    let port = FakePort::new();
    let g = glue(
        &port,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    let handle = started(&g, spec(off()), GatedCalls::new()).await?;
    // Someone awaits the end (core's run task), which never comes on its own.
    let waiting = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.wait().await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    // The kill, from a plain thread (the UI's kill button, the cancel path), bounded; a second
    // kill as well.
    kill_bounded(&handle, KillReason::User)?;
    kill_bounded(&handle, KillReason::Client)?;
    let control = port.control(0).ok_or("no run")?;
    assert_eq!(control.kills(), [KillCause::User, KillCause::Client]);
    assert!(!waiting.is_finished(), "a kill does not wait for the end");
    // The bridge decides the end (the first cause it recorded).
    control.finish(outcome(
        WorkerEnd::None,
        HostVerdict::Killed(KillCause::User),
    ));
    let end = tokio::time::timeout(BOUND, waiting).await??;
    assert_eq!(
        end,
        RunEnd::Killed {
            reason: KillReason::User
        }
    );
    // A kill after the end is still immediate.
    kill_bounded(&handle, KillReason::Shutdown)?;
    Ok(())
}

/// PD-148: the sink forwards each call to core under core's run id and awaits core's answer; a
/// kill, the run's end and dropping the handle do not drop a call in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn glue_host_calls_spawned_never_dropped() -> TestResult {
    bounded(host_calls_spawned_never_dropped()).await
}

async fn host_calls_spawned_never_dropped() -> TestResult {
    let port = FakePort::new();
    let g = glue(
        &port,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    let calls = GatedCalls::new();
    let handle = started(&g, spec(off()), calls.clone()).await?;
    let sink = port.sink(0).ok_or("no sink")?;
    // The bridge runs each call as its own task (PD-148), under its channel id.
    let tasks: Vec<_> = (1..=3)
        .map(|id| {
            let sink = sink.clone();
            tokio::spawn(async move {
                sink.call(
                    "run-77",
                    HostCall {
                        id,
                        op_id: "jira.issue.get".to_owned(),
                        params: json!({ "key": "ABC-1" }),
                        instance: None,
                        all: false,
                    },
                )
                .await
            })
        })
        .collect();
    for _ in 0..100 {
        if lock(&calls.seen).len() == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(lock(&calls.seen).len(), 3, "every call reached core");
    // The run is killed and ends while the calls are in flight; core's handle goes away.
    kill_bounded(&handle, KillReason::User)?;
    let control = port.control(0).ok_or("no run")?;
    control.finish(outcome(
        WorkerEnd::None,
        HostVerdict::Killed(KillCause::User),
    ));
    tokio::time::timeout(BOUND, handle.wait()).await?;
    drop(handle);
    drop(g);
    // Core takes its time (a slow fetch, a limiter wait): the calls stay with core all along,
    // and no answer reaches the bridge before core's.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(calls.done.load(Ordering::SeqCst), 0, "still in flight");
    assert!(
        tasks.iter().all(|t| !t.is_finished()),
        "a call was answered without core's answer"
    );
    // Core finishes its calls (records committed): each answer comes back whole.
    calls.gate.add_permits(3);
    let mut answers = Vec::new();
    for t in tasks {
        answers.push(tokio::time::timeout(BOUND, t).await??);
    }
    assert_eq!(calls.done.load(Ordering::SeqCst), 3);
    let mut ids: Vec<u64> = answers
        .iter()
        .filter_map(|a| match a {
            HostCallResult::Ok(v) => v["answer"].as_u64(),
            HostCallResult::Rejected { .. } => None,
        })
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, [1, 2, 3]);
    // Core's run id, not the bridge's channel id.
    let seen = lock(&calls.seen).clone();
    assert!(seen.iter().all(|(run_id, _)| run_id == "req-1"), "{seen:?}");
    // A log line goes nowhere but the outcome (collected by the bridge).
    sink.log("run-77", "SENTINEL-LOG");
    Ok(())
}

/// The capture of the diagnostic log through the allowlist layer.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        lock(&self.0).extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

/// The capture of a test's own thread (`with_default` is thread-scoped: an event written on
/// another thread, a `spawn_blocking` closure's say, is not captured).
fn capture_on_this_thread(
    body: impl FnOnce(&Capture) -> TestResult,
) -> Result<String, Box<dyn std::error::Error>> {
    // While exactly one subscriber exists, tracing computes a callsite's interest from the
    // subscriber of the thread that hits it first; a glue callsite first hit by another test's
    // thread (none) would then stay "never" for the capture too. A second, idle subscriber keeps
    // every callsite's interest computed over all live subscribers.
    let _idle = tracing::Dispatch::new(tracing_subscriber::Registry::default());
    let cap = Capture::default();
    let subscriber = tracing_subscriber::layer::SubscriberExt::with(
        tracing_subscriber::Registry::default(),
        crate::diag::fields::allowlist_layer(cap.clone()),
    );
    tracing::subscriber::with_default(subscriber, || body(&cap))?;
    Ok(String::from_utf8(lock(&cap.0).clone())?)
}

/// A current-thread runtime with a single blocking thread (see [`occupy_blocking_pool`]).
fn one_blocking_thread() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
}

/// Holds the runtime's only blocking thread until the returned sender is dropped (also when the
/// test fails: dropping a runtime waits for its running blocking tasks, which then end at once).
fn occupy_blocking_pool() -> mpsc::Sender<()> {
    let (release, released) = mpsc::channel::<()>();
    drop(tokio::task::spawn_blocking(move || {
        let _ = released.recv_timeout(TEST_BOUND);
    }));
    release
}

/// T20 review m-4: a waiter dropped while `wait` maps the end (here: while the result's parse
/// waits for a blocking thread) does not make the next `wait` log the run's host facts again.
#[test]
fn glue_wait_logs_once_when_a_waiter_is_dropped() -> TestResult {
    let out = capture_on_this_thread(|cap| {
        let rt = one_blocking_thread()?;
        rt.block_on(async {
            tokio::time::timeout(TEST_BOUND, dropped_waiter(cap))
                .await
                .map_err(|_| "the test body did not finish within its bound")?
        })
    })?;
    assert_eq!(
        out.matches("event=sandbox_watchdog_kill").count(),
        1,
        "{out}"
    );
    Ok(())
}

async fn dropped_waiter(cap: &Capture) -> TestResult {
    let port = FakePort::new();
    let g = glue(
        &port,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    let handle = started(&g, spec(off()), GatedCalls::new()).await?;
    let mut end = outcome(result_end("1")?, HostVerdict::None);
    end.diag = vec![DIAG_WATCHDOG_KILL];
    port.control(0).ok_or("no run")?.finish(end);
    let pool = occupy_blocking_pool();
    let first = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.wait().await })
    };
    // The first waiter has logged the run's host facts and waits for the parse; it goes away.
    while !String::from_utf8_lossy(&lock(&cap.0)).contains("event=sandbox_watchdog_kill") {
        tokio::task::yield_now().await;
    }
    first.abort();
    assert!(first.await.is_err_and(|e| e.is_cancelled()));
    drop(pool);
    let end = tokio::time::timeout(BOUND, handle.wait()).await?;
    assert!(matches!(end, RunEnd::Result { .. }), "{end:?}");
    assert_eq!(handle.worker_confinement(), Some(conf(true, "worker")));
    Ok(())
}

/// T20 review m-5: only a result's parse goes to a blocking thread; an end the host decided maps
/// at once, also when no blocking thread is free (the runtime shutting down, a busy pool).
#[test]
fn glue_wait_maps_a_host_verdict_without_a_blocking_thread() -> TestResult {
    let rt = one_blocking_thread()?;
    rt.block_on(async {
        tokio::time::timeout(TEST_BOUND, host_verdict_without_a_blocking_thread())
            .await
            .map_err(|_| "the test body did not finish within its bound")?
    })
}

async fn host_verdict_without_a_blocking_thread() -> TestResult {
    let port = FakePort::new();
    let g = glue(
        &port,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    let handle = started(&g, spec(off()), GatedCalls::new()).await?;
    port.control(0).ok_or("no run")?.finish(outcome(
        WorkerEnd::None,
        HostVerdict::Killed(KillCause::Shutdown),
    ));
    let pool = occupy_blocking_pool();
    let end = tokio::time::timeout(Duration::from_secs(2), handle.wait())
        .await
        .map_err(|_| "a host-decided end waited for a blocking thread")?;
    assert_eq!(
        end,
        RunEnd::Killed {
            reason: KillReason::Shutdown
        }
    );
    drop(pool);
    Ok(())
}

/// T20 review m-5: a result's parse that never ran because the runtime shut down (its blocking
/// task cancelled) is the shutdown's kill, not a crash; a parse that panicked is a crash. A
/// `JoinError` cannot be built by hand: these are a real cancelled and a real panicked task's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn glue_lost_parse_maps_shutdown_to_killed() -> TestResult {
    bounded(lost_parse_maps_shutdown_to_killed()).await
}

/// A parse that panics (without the panic hook's message).
fn parse_that_panics() -> RunEnd {
    std::panic::resume_unwind(Box::new("parse"))
}

async fn lost_parse_maps_shutdown_to_killed() -> TestResult {
    let parsed = RunEnd::Result {
        value: json!(1),
        logs: Vec::new(),
        stderr: String::new(),
    };
    assert_eq!(parsed_end(Ok(parsed.clone())), parsed);
    let cancelled = tokio::spawn(std::future::pending::<RunEnd>());
    cancelled.abort();
    let cancelled = cancelled.await.err().ok_or("an aborted task answered")?;
    assert!(cancelled.is_cancelled());
    assert_eq!(
        parsed_end(Err(cancelled)),
        RunEnd::Killed {
            reason: KillReason::Shutdown
        }
    );
    let panicked = tokio::spawn(async { parse_that_panics() })
        .await
        .err()
        .ok_or("a panicking task answered")?;
    assert!(panicked.is_panic());
    assert_eq!(parsed_end(Err(panicked)), RunEnd::Crashed);
    Ok(())
}

/// What the logging test runs: a run whose outcome carries worker text and host facts, a spawn
/// refused for the embedded version, a compile worker that failed to spawn. On one thread, so the
/// thread's scoped subscriber sees every event (the glue logs nothing from a blocking thread), and
/// under [`TEST_BOUND`].
fn log_scenario() -> TestResult {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        tokio::time::timeout(TEST_BOUND, log_scenario_body())
            .await
            .map_err(|_| "the test body did not finish within its bound")?
    })
}

async fn log_scenario_body() -> TestResult {
    let port = FakePort::new();
    let g = glue(
        &port,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    let handle = started(&g, spec(off()), GatedCalls::new()).await?;
    let mut end = outcome(
        WorkerEnd::Error {
            class: "SENTINEL-CLASS".to_owned(),
            message: "SENTINEL-MESSAGE".to_owned(),
            stack: "SENTINEL-STACK".to_owned(),
        },
        HostVerdict::Limit("process_mb"),
    );
    end.logs = vec!["SENTINEL-LOG".to_owned()];
    end.stderr = "SENTINEL-STDERR".to_owned();
    end.diag = vec![DIAG_WATCHDOG_KILL, DIAG_STDIN_HELD, "sandbox_new_fact"];
    port.control(0).ok_or("no run")?.finish(end);
    handle.wait().await;
    // A refused spawn: the ready frame names another version, then a spawn error.
    port.set_ready("SENTINEL-VERSION", conf(true, "SENTINEL-MECHANISM"));
    let _ = g.start(spec(off()), GatedCalls::new()).await;
    let fresh = FakePort::new();
    let g = glue(
        &fresh,
        &worker_file(),
        Some(report_for(&worker_file(), FloorVerdict::Met)?),
    );
    fresh.set_compile(CompileAnswer::Verdict(Err(StartRunError::Spawn(
        io::ErrorKind::TimedOut,
    ))));
    let _ = g
        .compile_check("SENTINEL-SOURCE", &ScriptLimits::default(), off())
        .await;
    // The part that no longer matches (lead ruling L152): the binary gone at a submit check
    // (`Missing`, also what a transient stat error gives), then renamed over before a run's
    // spawn (`FileId`).
    let dir = Scratch::new("log-identity")?;
    let worker = dir.file("atlas-duck-sandbox");
    fs::write(&worker, b"worker")?;
    let g = glue(
        &FakePort::new(),
        &worker,
        Some(report_for(&worker, FloorVerdict::Met)?),
    );
    fs::remove_file(&worker)?;
    let _ = g.check_available(off()).await;
    fs::write(&worker, b"worker")?;
    let g = glue(
        &FakePort::new(),
        &worker,
        Some(report_for(&worker, FloorVerdict::Met)?),
    );
    replace(&worker)?;
    let _ = g.start(spec(off()), GatedCalls::new()).await;
    // Refused at admission with no usable worker (T20 review m-1): no recorded identity, the
    // holder's own record unreadable, no install dir.
    let g = glue(
        &FakePort::new(),
        &worker_file(),
        Some(bare_report(FloorVerdict::Met)),
    );
    let _ = g.check_available(off()).await;
    let missing = dir.file("not-there");
    let g = glue_recording(&FakePort::new(), &missing, &missing, bare_report(not_met()));
    let _ = g.check_available(on()).await;
    let g = glue_recording(&FakePort::new(), &missing, &worker, bare_report(not_met()));
    let _ = g.check_available(on()).await;
    let inputs = ScriptInputs::default();
    let _ = inputs
        .probe
        .set(report_for(&worker_file(), FloorVerdict::Met)?);
    let g = ScriptGlue::with_port(FakePort::new(), None, inputs);
    let _ = g.start(spec(off()), GatedCalls::new()).await;
    Ok(())
}

/// §3.4, §7.7: the glue logs constants and the request id only: the host facts of an outcome,
/// an identity mismatch, a failed spawn; never what the worker sent.
#[test]
fn glue_logs_host_diag_constants_only() -> TestResult {
    // Every host fact the bridge can report, and the glue's own events, are allowlisted.
    for d in [
        DIAG_REAP_FAILED,
        DIAG_OUTCOME_LOST,
        DIAG_HOST_PROTOCOL_EXIT,
        DIAG_CALL_RESULT_REPLACED,
        DIAG_UNREAD_RESULTS,
        DIAG_WATCHDOG_KILL,
        DIAG_JOB_MEMORY_LIMIT,
        DIAG_MEMORY_WATCH_FAILED,
        DIAG_STDOUT_HELD,
        DIAG_STDIN_HELD,
        LOG_EVENT_IDENTITY_MISMATCH,
        LOG_EVENT_SPAWN_FAILED,
        LOG_EVENT_PROBE_PENDING,
    ] {
        assert!(SCRIPT_GLUE_EVENTS.contains(&d), "{d} not allowlisted");
    }

    let out = capture_on_this_thread(|_| log_scenario())?;
    assert!(out.contains("event=sandbox_watchdog_kill"), "{out}");
    assert!(out.contains("event=sandbox_stdin_held_after_exit"), "{out}");
    assert!(out.contains("event=sandbox_diag_unlisted"), "{out}");
    assert!(!out.contains("sandbox_new_fact"), "{out}");
    // Each identity mismatch names the part that did not match, so a missing or unreadable binary
    // (possibly transient) and a ready frame of another build read apart from a replaced file.
    let mismatches: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("event=script_identity_mismatch"))
        .collect();
    for (reason, request) in [
        ("embedded_version", " request_id=req-1"),
        ("missing", " dropped_fields"),
        ("file_id", " request_id=req-1"),
    ] {
        let line = format!("event=script_identity_mismatch reason={reason}{request}");
        assert!(
            mismatches.iter().any(|l| l.contains(&line)),
            "{line}: {out}"
        );
    }
    assert_eq!(mismatches.len(), 3, "{out}");
    for line in [
        "event=script_spawn_failed reason=TimedOut dropped_fields",
        "event=script_spawn_failed reason=no_identity dropped_fields",
        "event=script_spawn_failed reason=fallback_unreadable dropped_fields",
        "event=script_spawn_failed reason=fallback_other_path dropped_fields",
        "event=script_spawn_failed reason=no_install_dir request_id=req-1",
    ] {
        assert!(out.contains(line), "{line}: {out}");
    }
    assert!(out.contains("request_id=req-1"), "{out}");
    assert!(!out.contains("SENTINEL"), "worker text in the log: {out}");
    // Constants and ids only: no field was dropped from any line.
    for line in out.lines() {
        assert!(line.ends_with("dropped_fields=0"), "{line}");
    }
    Ok(())
}
