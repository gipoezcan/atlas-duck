//! M8 Task 7 (C.8, Δ2): the host bridge `start_run` / `compile_run` against a scripted fake worker.
//!
//! The fake worker is a thread behind three in-memory pipes (`std::io::pipe`). Its kill handle and
//! reaper are built from the crate's [`GuardedKill`] / [`ReapGuard`] like the real spawners', so a
//! kill is recorded once and never blocks, and the reaper answers `Signal(9)` for a killed fake.
//! A fake can stop reading its stdin on purpose (the writer then blocks on a full pipe) and can
//! wait for its kill instead of answering. No process is spawned.
//!
//! Every wait is bounded ([`WAIT_BOUND`]) so a regression fails instead of hanging. Assertions are
//! structural (L26), except the plan's 50 ms bound for a kill.

use std::cell::Cell;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use atlas_duck_ipc::sandbox::frame::{read_frame, write_frame};
use atlas_duck_ipc::sandbox::probe::{
    ConfinementReport, M_PROBE_READY, ProbeReady, encode_notification,
};
use atlas_duck_ipc::sandbox::script::{
    EmptyParams, ErrorParams, LogParams, M_HOST_CALL, M_HOST_LOG, M_SCRIPT_COMPILE,
    M_SCRIPT_COMPILED, M_SCRIPT_ERROR, M_SCRIPT_RUN, M_SCRIPT_SYNTAX, SyntaxParams, WorkerInit,
    encode_request,
};
use atlas_duck_ipc::sandbox::{HOST_TO_WORKER_MAX, HostCall, HostCallResult, ScriptLimits};
use atlas_duck_sandbox_host::bridge::{
    CompileVerdict, ExpectedWorker, HostCallSink, HostVerdict, KillCause, LOG_CAP_BYTES,
    LOG_CAP_LINES, RESULT_NOT_REPRESENTABLE, RunHandleImpl, RunOutcome, STDERR_CAP, StartRunError,
    ViolationKind, WorkerEnd, compile_run, log_truncated_marker, start_run,
};
use atlas_duck_sandbox_host::identity::{FileId, IdentityPart, SandboxBinaryIdentity};
use atlas_duck_sandbox_host::kill::{GuardedKill, ReapGuard, reap_after_wait};
use atlas_duck_sandbox_host::spawn::{
    ExitKind, KillHandle, Reaper, SpawnSpec, WorkerIo, WorkerParts, WorkerProcess, WorkerSpawner,
};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Upper bound for every wait in this file: a regression fails, it never hangs.
const WAIT_BOUND: Duration = Duration::from_secs(30);
/// The plan bound for a kill that must not block.
const KILL_BOUND: Duration = Duration::from_millis(50);
/// The embedded version the fake reports and the expected identity records.
const VERSION: &str = "fake-build-1";
const MIB: usize = 1024 * 1024;

// ---- the fake worker -------------------------------------------------------------------------

/// What a test can see of its fake after (or while) it ran.
#[derive(Default)]
struct Observed {
    /// Every host frame the fake read, as JSON.
    received: Mutex<Vec<Value>>,
    killed: Mutex<bool>,
    killed_cv: Condvar,
    /// Signals the kill handle sent (at most one).
    signals: AtomicU32,
    /// Calls of the kill handle, including no-ops and a swallowed one.
    kill_calls: AtomicU32,
    spawns: AtomicU32,
    finished: Mutex<bool>,
    finished_cv: Condvar,
}

impl Observed {
    /// The kill signal. Like a real kill, it changes nothing for a fake that already ended.
    fn kill(&self) {
        self.signals.fetch_add(1, Ordering::SeqCst);
        let dead = self.finished.lock().map(|f| *f).unwrap_or(true);
        if let Ok(mut k) = self.killed.lock()
            && !dead
        {
            *k = true;
        }
        self.killed_cv.notify_all();
    }

    fn is_killed(&self) -> bool {
        self.killed.lock().map(|k| *k).unwrap_or(true)
    }

    fn signals(&self) -> u32 {
        self.signals.load(Ordering::SeqCst)
    }

    fn received(&self) -> Vec<Value> {
        self.received.lock().map(|r| r.clone()).unwrap_or_default()
    }

    fn received_methods(&self) -> Vec<String> {
        self.received()
            .iter()
            .map(|f| {
                f.get("method")
                    .and_then(Value::as_str)
                    .map_or_else(|| "<response>".to_string(), str::to_string)
            })
            .collect()
    }

    /// Waits until the fake's thread ended (its pipes are closed).
    fn wait_finished(&self) -> Result<(), String> {
        let guard = self.finished.lock().map_err(|_| "poisoned")?;
        let (guard, _) = self
            .finished_cv
            .wait_timeout_while(guard, WAIT_BOUND, |f| !*f)
            .map_err(|_| "poisoned")?;
        if *guard {
            Ok(())
        } else {
            Err("the fake worker never finished".into())
        }
    }
}

/// The worker side of the three pipes, with helpers that speak the script protocol.
struct FakeWorker {
    stdin: io::PipeReader,
    stdout: io::PipeWriter,
    stderr: io::PipeWriter,
    observed: Arc<Observed>,
}

fn killed_error() -> io::Error {
    io::Error::other("killed")
}

impl FakeWorker {
    fn ready(&mut self) -> io::Result<()> {
        self.ready_with(VERSION, report(true))
    }

    fn ready_with(&mut self, version: &str, confinement: ConfinementReport) -> io::Result<()> {
        let ready = ProbeReady {
            worker_version: version.to_string(),
            engine_version: "fake-engine".to_string(),
            confinement,
        };
        self.send(&encode_notification(M_PROBE_READY, &ready))
    }

    /// One frame, unless the fake was killed.
    fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        if self.observed.is_killed() {
            return Err(killed_error());
        }
        write_frame(&mut self.stdout, payload)
    }

    /// Raw bytes in one write (several frames land before the host can react).
    fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.observed.is_killed() {
            return Err(killed_error());
        }
        self.stdout.write_all(bytes)?;
        self.stdout.flush()
    }

    /// Reads one host frame and records it; `None` at stdin EOF.
    fn read(&mut self) -> io::Result<Option<Value>> {
        match read_frame(&mut self.stdin, HOST_TO_WORKER_MAX) {
            Ok(Some(bytes)) => {
                let value: Value = serde_json::from_slice(&bytes)?;
                if let Ok(mut r) = self.observed.received.lock() {
                    r.push(value.clone());
                }
                Ok(Some(value))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    /// Reads until stdin EOF.
    fn drain_stdin(&mut self) -> io::Result<()> {
        while self.read()?.is_some() {}
        Ok(())
    }

    fn call(&mut self, id: u64) -> io::Result<()> {
        self.send(&call_frame(id))
    }

    fn log(&mut self, line: &str) -> io::Result<()> {
        self.send(&log_frame(line))
    }

    fn result(&mut self, value_json: &str) -> io::Result<()> {
        self.send(result_frame(value_json).as_bytes())
    }

    fn error(&mut self, class: &str, message: &str) -> io::Result<()> {
        self.send(&error_frame(class, message))
    }

    /// Blocks until the host kills the fake (bounded), then fails like a killed process.
    fn until_killed(&self) -> io::Result<i32> {
        let guard = self.observed.killed.lock().map_err(|_| killed_error())?;
        let _ = self
            .observed
            .killed_cv
            .wait_timeout_while(guard, WAIT_BOUND, |k| !*k);
        Err(killed_error())
    }
}

type Script = Box<dyn FnOnce(&mut FakeWorker) -> io::Result<i32> + Send>;

/// Spawns one fake worker running `script`.
struct FakeSpawner {
    script: Mutex<Option<Script>>,
    observed: Arc<Observed>,
    /// The kill handle swallows its first call (an OS call that failed without a sign).
    flaky_kill: bool,
}

fn fake(
    script: impl FnOnce(&mut FakeWorker) -> io::Result<i32> + Send + 'static,
) -> (Arc<FakeSpawner>, Arc<Observed>) {
    fake_with(false, script)
}

fn fake_with(
    flaky_kill: bool,
    script: impl FnOnce(&mut FakeWorker) -> io::Result<i32> + Send + 'static,
) -> (Arc<FakeSpawner>, Arc<Observed>) {
    let observed = Arc::new(Observed::default());
    let spawner = FakeSpawner {
        script: Mutex::new(Some(Box::new(script))),
        observed: Arc::clone(&observed),
        flaky_kill,
    };
    (Arc::new(spawner), observed)
}

/// A kill handle whose first call does nothing, then behaves like the real one.
struct FlakyKill {
    inner: GuardedKill,
    observed: Arc<Observed>,
}

impl KillHandle for FlakyKill {
    fn kill(&self) {
        if self.observed.kill_calls.fetch_add(1, Ordering::SeqCst) > 0 {
            self.inner.kill();
        }
    }
}

/// Counts every call of the real fake kill handle.
struct CountedKill {
    inner: GuardedKill,
    observed: Arc<Observed>,
}

impl KillHandle for CountedKill {
    fn kill(&self) {
        self.observed.kill_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.kill();
    }
}

impl WorkerSpawner for FakeSpawner {
    fn spawn(&self, _spec: &SpawnSpec) -> io::Result<Box<dyn WorkerProcess>> {
        let script = self
            .script
            .lock()
            .map_err(|_| io::Error::other("poisoned"))?
            .take()
            .ok_or_else(|| io::Error::other("the fake spawns once"))?;
        self.observed.spawns.fetch_add(1, Ordering::SeqCst);
        let (stdin_r, stdin_w) = io::pipe()?;
        let (stdout_r, stdout_w) = io::pipe()?;
        let (stderr_r, stderr_w) = io::pipe()?;
        let (exit_tx, exit_rx) = mpsc::channel();
        let mut worker = FakeWorker {
            stdin: stdin_r,
            stdout: stdout_w,
            stderr: stderr_w,
            observed: Arc::clone(&self.observed),
        };
        let observed = Arc::clone(&self.observed);
        thread::spawn(move || {
            let code = script(&mut worker).unwrap_or(99);
            // The process is dead from here on (a later kill changes nothing); its pipes close
            // when it dies, before it is reaped.
            if let Ok(mut f) = observed.finished.lock() {
                *f = true;
            }
            observed.finished_cv.notify_all();
            drop(worker);
            let _ = exit_tx.send(code);
        });
        Ok(Box::new(FakeProcess {
            stdin: stdin_w,
            stdout: stdout_r,
            stderr: stderr_r,
            exit: exit_rx,
            observed: Arc::clone(&self.observed),
            flaky_kill: self.flaky_kill,
        }))
    }
}

struct FakeProcess {
    stdin: io::PipeWriter,
    stdout: io::PipeReader,
    stderr: io::PipeReader,
    exit: Receiver<i32>,
    observed: Arc<Observed>,
    flaky_kill: bool,
}

impl WorkerProcess for FakeProcess {
    fn pid(&self) -> u32 {
        4242
    }
    fn stdin(&mut self) -> &mut dyn Write {
        &mut self.stdin
    }
    fn read_frame_timeout(&mut self, _: usize, _: Duration) -> io::Result<Option<Vec<u8>>> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn close_stdin(&mut self) {}
    fn wait_timeout(&mut self, _: Duration) -> io::Result<Option<ExitKind>> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn kill(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn into_parts(self: Box<Self>) -> io::Result<WorkerParts> {
        let guard = ReapGuard::new();
        let observed = Arc::clone(&self.observed);
        let inner = GuardedKill::new(Arc::clone(&guard), move || observed.kill());
        let observed = Arc::clone(&self.observed);
        let kill: Arc<dyn KillHandle> = if self.flaky_kill {
            Arc::new(FlakyKill { inner, observed })
        } else {
            Arc::new(CountedKill { inner, observed })
        };
        Ok(WorkerParts {
            pid: 4242,
            io: WorkerIo {
                stdin: Box::new(self.stdin),
                stdout: Box::new(self.stdout),
                stderr: Box::new(self.stderr),
            },
            kill,
            reaper: Box::new(FakeReaper {
                guard,
                exit: self.exit,
                observed: self.observed,
            }),
        })
    }
}

struct FakeReaper {
    guard: Arc<ReapGuard>,
    exit: Receiver<i32>,
    observed: Arc<Observed>,
}

impl Reaper for FakeReaper {
    fn wait(self: Box<Self>) -> io::Result<ExitKind> {
        let code = Cell::new(None);
        reap_after_wait(
            &self.guard,
            || {
                code.set(Some(
                    self.exit.recv().map_err(|_| io::Error::other("no exit"))?,
                ));
                Ok(())
            },
            || {
                if self.observed.is_killed() {
                    Ok(ExitKind::Signal(9))
                } else {
                    code.get()
                        .map(ExitKind::Code)
                        .ok_or_else(|| io::Error::other("no code"))
                }
            },
        )
    }
}

// ---- frames the fake sends ---------------------------------------------------------------------

fn framed(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

fn call_frame(id: u64) -> Vec<u8> {
    let call = HostCall {
        id,
        op_id: "jira.issue.get".to_string(),
        params: json!({"key": "ABC-1"}),
        instance: None,
        all: false,
    };
    encode_request(M_HOST_CALL, id, &call)
}

fn log_frame(line: &str) -> Vec<u8> {
    encode_notification(
        M_HOST_LOG,
        &LogParams {
            line: line.to_string(),
        },
    )
}

fn result_frame(value_json: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","method":"script.result","params":{{"value":{value_json}}}}}"#)
}

fn error_frame(class: &str, message: &str) -> Vec<u8> {
    encode_notification(
        M_SCRIPT_ERROR,
        &ErrorParams {
            class: class.to_string(),
            message: message.to_string(),
            stack: String::new(),
        },
    )
}

/// A `script.result` frame of exactly `len` bytes (a string value padded with `x`).
fn result_frame_of_len(len: usize) -> Vec<u8> {
    let empty = result_frame("\"\"");
    let pad = len - empty.len();
    result_frame(&format!("\"{}\"", "x".repeat(pad))).into_bytes()
}

// ---- host side -----------------------------------------------------------------------------------

fn report(applied: bool) -> ConfinementReport {
    ConfinementReport {
        applied,
        mechanism: if applied { "fake-confined" } else { "none" }.to_string(),
        no_new_privs: None,
        landlock_abi: None,
        seccomp: None,
        lpac: Some(applied),
        os_error: None,
    }
}

fn expect(accept_unconfined: bool) -> ExpectedWorker {
    ExpectedWorker {
        identity: SandboxBinaryIdentity {
            file_id: FileId::FileIndex {
                volume_serial: 7,
                index: 42,
            },
            size: 1000,
            mtime: SystemTime::UNIX_EPOCH,
            embedded_version: VERSION.to_string(),
        },
        accept_unconfined,
    }
}

fn spec() -> SpawnSpec {
    SpawnSpec {
        exe: PathBuf::from("fake-worker"),
        process_mb: 512,
    }
}

fn init(limits: ScriptLimits) -> WorkerInit {
    WorkerInit {
        source: "async function main() { return 1; }".to_string(),
        args: json!({"k": 1}),
        limits,
        read_op_ids: vec!["jira.issue.get".to_string()],
        instances: Vec::new(),
    }
}

/// Records calls and logs; optionally holds every call until released, and pads each result.
#[derive(Default)]
struct TestSink {
    calls: Mutex<Vec<u64>>,
    logs: Mutex<Vec<String>>,
    completed: AtomicU32,
    gate: Option<Arc<tokio::sync::Semaphore>>,
    pad: usize,
    /// Told the id of each call as it arrives.
    seen: Mutex<Option<mpsc::Sender<u64>>>,
}

impl TestSink {
    fn gated() -> (Arc<TestSink>, Arc<tokio::sync::Semaphore>) {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let sink = TestSink {
            gate: Some(Arc::clone(&gate)),
            ..TestSink::default()
        };
        (Arc::new(sink), gate)
    }

    fn padded(pad: usize) -> Arc<TestSink> {
        Arc::new(TestSink {
            pad,
            ..TestSink::default()
        })
    }

    /// A channel that receives each call id when the sink sees it.
    fn watch(&self) -> Receiver<u64> {
        let (tx, rx) = mpsc::channel();
        if let Ok(mut s) = self.seen.lock() {
            *s = Some(tx);
        }
        rx
    }

    fn calls(&self) -> Vec<u64> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }

    fn logs(&self) -> Vec<String> {
        self.logs.lock().map(|c| c.clone()).unwrap_or_default()
    }

    fn completed(&self) -> u32 {
        self.completed.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl HostCallSink for TestSink {
    async fn call(&self, _run_id: &str, c: HostCall) -> HostCallResult {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(c.id);
        }
        if let Ok(seen) = self.seen.lock()
            && let Some(tx) = seen.as_ref()
        {
            let _ = tx.send(c.id);
        }
        if let Some(gate) = &self.gate
            && let Ok(permit) = gate.acquire().await
        {
            permit.forget();
        }
        self.completed.fetch_add(1, Ordering::SeqCst);
        HostCallResult::Ok(json!({"id": c.id, "pad": "x".repeat(self.pad)}))
    }

    fn log(&self, _run_id: &str, line: &str) {
        if let Ok(mut logs) = self.logs.lock() {
            logs.push(line.to_string());
        }
    }
}

/// `start_run` on a blocking thread, as the glue calls it.
async fn start(
    spawner: Arc<FakeSpawner>,
    expect: ExpectedWorker,
    init: WorkerInit,
    sink: Arc<dyn HostCallSink>,
) -> Result<Result<RunHandleImpl, StartRunError>, Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Handle::current();
    Ok(tokio::task::spawn_blocking(move || {
        start_run(spawner.as_ref(), &spec(), &expect, init, sink, rt)
    })
    .await?)
}

/// Starts a run with the expected identity and default limits (overridable) and waits for its end.
async fn run_to_end(
    spawner: Arc<FakeSpawner>,
    limits: ScriptLimits,
    sink: Arc<dyn HostCallSink>,
) -> Result<RunOutcome, Box<dyn std::error::Error>> {
    let handle = start(spawner, expect(false), init(limits), sink).await??;
    Ok(tokio::time::timeout(WAIT_BOUND, handle.wait()).await?)
}

fn sink() -> Arc<TestSink> {
    Arc::new(TestSink::default())
}

fn result_text(outcome: &RunOutcome) -> Option<&str> {
    match &outcome.end {
        WorkerEnd::Result { value_json } => Some(value_json.get()),
        _ => None,
    }
}

/// Waits (bounded) until `cond` holds.
async fn eventually(mut cond: impl FnMut() -> bool) -> TestResult {
    let started = Instant::now();
    while !cond() {
        if started.elapsed() > WAIT_BOUND {
            return Err("condition never held".into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

fn limits_with(f: impl FnOnce(&mut ScriptLimits)) -> ScriptLimits {
    let mut l = ScriptLimits::default();
    f(&mut l);
    l
}

// ---- the channel (§3.4) ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn always_drains_while_writer_blocked() -> TestResult {
    // The answer to call 1 is 2 MiB; the fake does not read it until it wrote 2 MiB of logs. The
    // writer blocks on the full stdin pipe while the reader keeps draining stdout.
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?; // script.run
        w.call(1)?;
        let line = "a".repeat(32 * 1024);
        for _ in 0..64 {
            w.log(&line)?;
        }
        let answer = w.read()?.ok_or_else(|| io::Error::other("no answer"))?;
        assert_eq!(answer["id"], 1);
        w.result("1")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), TestSink::padded(2 * MIB)).await?;
    assert_eq!(result_text(&outcome), Some("1"));
    assert_eq!(outcome.host, HostVerdict::None);
    // 32 lines of 32 KiB fill the 1 MiB cap exactly; the other 32 are discarded.
    assert_eq!(outcome.logs.len(), 33);
    assert_eq!(outcome.logs_truncated, Some(32 * 32 * 1024));
    observed.wait_finished()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn results_written_by_separate_writer() -> TestResult {
    // Call 1's 2 MiB answer is queued while the fake reads nothing; call 2 is still decoded and
    // reaches the sink, so decoding never waits for a write.
    let sink = TestSink::padded(2 * MIB);
    let seen = sink.watch();
    let (spawner, observed) = fake(move |w| {
        w.ready()?;
        w.read()?;
        w.call(1)?;
        let first = seen.recv_timeout(WAIT_BOUND).map_err(io::Error::other)?;
        w.call(2)?;
        let second = seen.recv_timeout(WAIT_BOUND).map_err(io::Error::other)?;
        assert_eq!((first, second), (1, 2));
        let a = w.read()?.ok_or_else(|| io::Error::other("no answer 1"))?;
        let b = w.read()?.ok_or_else(|| io::Error::other("no answer 2"))?;
        let mut ids = [a["id"].as_u64(), b["id"].as_u64()];
        ids.sort();
        assert_eq!(ids, [Some(1), Some(2)]);
        assert_eq!(a["result"]["ok"]["id"], a["id"]);
        w.result("2")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink.clone()).await?;
    assert_eq!(result_text(&outcome), Some("2"));
    assert_eq!(sink.calls(), vec![1, 2]);
    observed.wait_finished()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outstanding_counted_until_result_queued() -> TestResult {
    let one = limits_with(|l| l.max_concurrent_calls = 1);

    // Answered, then the next call: within the limit.
    let (spawner, _) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.call(1)?;
        w.read()?.ok_or_else(|| io::Error::other("no answer"))?;
        w.call(2)?;
        w.read()?.ok_or_else(|| io::Error::other("no answer"))?;
        w.result("2")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, one, sink()).await?;
    assert_eq!(result_text(&outcome), Some("2"));
    assert_eq!(outcome.host, HostVerdict::None);

    // The sink is still working on call 1 (its result is not queued): call 2 is one too many.
    let (gated, gate) = TestSink::gated();
    let seen = gated.watch();
    let (spawner, observed) = fake(move |w| {
        w.ready()?;
        w.read()?;
        w.call(1)?;
        seen.recv_timeout(WAIT_BOUND).map_err(io::Error::other)?;
        w.call(2)?;
        w.until_killed()
    });
    let outcome = run_to_end(spawner, one, gated.clone()).await?;
    assert_eq!(
        outcome.host,
        HostVerdict::Violation(ViolationKind::TooManyCalls)
    );
    assert_eq!(gated.calls(), vec![1]);
    assert_eq!(observed.signals(), 1);
    gate.add_permits(1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_beyond_max_concurrent_is_violation() -> TestResult {
    let (gated, gate) = TestSink::gated();
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.call(1)?;
        w.call(2)?;
        w.call(3)?;
        w.until_killed()
    });
    let two = limits_with(|l| l.max_concurrent_calls = 2);
    let outcome = run_to_end(spawner, two, gated.clone()).await?;
    assert_eq!(
        outcome.host,
        HostVerdict::Violation(ViolationKind::TooManyCalls)
    );
    assert_eq!(outcome.end, WorkerEnd::None);
    assert_eq!(observed.signals(), 1, "the worker was killed");
    // Calls 1 and 2 reached the sink, call 3 never did.
    eventually(|| gated.calls().len() == 2).await?;
    assert_eq!(gated.calls(), vec![1, 2]);
    gate.add_permits(2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ids_must_strictly_increase() -> TestResult {
    for ids in [[2u64, 1], [1, 1]] {
        let (spawner, observed) = fake(move |w| {
            w.ready()?;
            w.read()?;
            w.call(ids[0])?;
            w.call(ids[1])?;
            w.until_killed()
        });
        let (gated, gate) = TestSink::gated();
        let outcome = run_to_end(spawner, ScriptLimits::default(), gated.clone()).await?;
        assert_eq!(
            outcome.host,
            HostVerdict::Violation(ViolationKind::IdNotIncreasing),
            "ids {ids:?}"
        );
        assert_eq!(observed.signals(), 1);
        eventually(|| !gated.calls().is_empty()).await?;
        assert_eq!(gated.calls(), vec![ids[0]]);
        gate.add_permits(1);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_terminal_is_violation() -> TestResult {
    let (spawner, _) = fake(|w| {
        w.ready()?;
        w.read()?;
        // Both terminals in one write: they are in the pipe before the host can react.
        let mut bytes = framed(result_frame("1").as_bytes());
        bytes.extend(framed(&error_frame("Error", "again")));
        w.send_raw(&bytes)?;
        w.drain_stdin()?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(result_text(&outcome), Some("1"));
    assert_eq!(
        outcome.host,
        HostVerdict::Violation(ViolationKind::SecondTerminal)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frames_after_terminal_ignored_and_reaped() -> TestResult {
    let sink = sink();
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        let mut bytes = framed(result_frame("7").as_bytes());
        bytes.extend(framed(&log_frame("late")));
        bytes.extend(framed(&call_frame(1)));
        bytes.extend(framed(b"not json"));
        bytes.extend(framed(&call_frame(1)));
        w.send_raw(&bytes)?;
        w.drain_stdin()?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink.clone()).await?;
    assert_eq!(result_text(&outcome), Some("7"));
    assert_eq!(outcome.host, HostVerdict::None);
    assert!(outcome.logs.is_empty());
    assert!(sink.calls().is_empty(), "no call after the terminal");
    // The outcome is published only after the reap; the fake is gone.
    observed.wait_finished()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_cap_1mib_10000_lines_with_marker() -> TestResult {
    assert_eq!((LOG_CAP_BYTES, LOG_CAP_LINES), (MIB, 10_000));
    assert_eq!(log_truncated_marker(6), "[log truncated: 6 bytes]");

    // The line cap: 10 001 short lines, the last one ("l10000", 6 bytes) is discarded.
    let sink1 = sink();
    let (spawner, _) = fake(|w| {
        w.ready()?;
        w.read()?;
        for i in 0..10_001 {
            w.log(&format!("l{i}"))?;
        }
        w.result("null")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink1.clone()).await?;
    assert_eq!(outcome.logs.len(), 10_001);
    assert_eq!(outcome.logs[9_999], "l9999");
    assert_eq!(outcome.logs[10_000], "[log truncated: 6 bytes]");
    assert_eq!(outcome.logs_truncated, Some(6));
    assert_eq!(sink1.logs().len(), 10_000, "the sink sees kept lines only");

    // The byte cap: ten 100 KiB lines fit, the eleventh does not; once past the cap, even a
    // short line is discarded.
    let (spawner, _) = fake(|w| {
        w.ready()?;
        w.read()?;
        let line = "b".repeat(100 * 1024);
        for _ in 0..11 {
            w.log(&line)?;
        }
        w.log("c")?;
        w.result("null")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(outcome.logs.len(), 11);
    assert_eq!(outcome.logs_truncated, Some(100 * 1024 + 1));
    assert_eq!(outcome.logs[10], log_truncated_marker(100 * 1024 + 1));

    // Below both caps: no marker.
    let (spawner, _) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.log("one")?;
        w.result("null")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(outcome.logs, vec!["one".to_string()]);
    assert_eq!(outcome.logs_truncated, None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stderr_cap_64k_drained() -> TestResult {
    let (spawner, _) = fake(|w| {
        w.ready()?;
        w.read()?;
        let chunk = vec![b'e'; 64 * 1024];
        for _ in 0..16 {
            w.stderr.write_all(&chunk)?;
        }
        w.result("true")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(result_text(&outcome), Some("true"));
    assert_eq!(STDERR_CAP, 64 * 1024);
    assert_eq!(outcome.stderr.len(), STDERR_CAP);
    assert!(outcome.stderr.bytes().all(|b| b == b'e'));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_calls_cancelled_at_terminal() -> TestResult {
    // N-b (T3 re-review): a terminal may follow unanswered host.calls. The run ends with the
    // result; the late answer is never written to the worker.
    let (gated, gate) = TestSink::gated();
    let seen = gated.watch();
    let (spawner, observed) = fake(move |w| {
        w.ready()?;
        w.read()?;
        w.call(1)?;
        seen.recv_timeout(WAIT_BOUND).map_err(io::Error::other)?;
        w.result("\"done\"")?;
        w.drain_stdin()?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), gated.clone()).await?;
    assert_eq!(result_text(&outcome), Some("\"done\""));
    assert_eq!(outcome.host, HostVerdict::None);
    gate.add_permits(1);
    eventually(|| gated.completed() == 1).await?;
    observed.wait_finished()?;
    assert_eq!(observed.received_methods(), vec![M_SCRIPT_RUN.to_string()]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timeout_kills_and_reports_timeout_s() -> TestResult {
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.log("before")?;
        w.until_killed()
    });
    let one_second = limits_with(|l| l.timeout_s = 1);
    let outcome = run_to_end(spawner, one_second, sink()).await?;
    assert_eq!(outcome.host, HostVerdict::Limit("timeout_s"));
    assert_eq!(outcome.end, WorkerEnd::None);
    assert_eq!(outcome.logs, vec!["before".to_string()]);
    assert_eq!(observed.signals(), 1);
    assert!(outcome.elapsed >= Duration::from_secs(1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_timer_kills_again_when_an_earlier_kill_did_not_take() -> TestResult {
    // T6: a kill whose OS call failed shows only as a worker that never ends. The run timer stays
    // armed until the reap and kills again at `timeout_s`, without changing the verdict.
    let one_second = limits_with(|l| l.timeout_s = 1);
    let (spawner, observed) = fake_with(true, |w| {
        w.ready()?;
        w.read()?;
        w.send(b"not json")?;
        w.until_killed()
    });
    let outcome = run_to_end(spawner, one_second, sink()).await?;
    assert_eq!(
        outcome.host,
        HostVerdict::Violation(ViolationKind::Malformed)
    );
    assert!(observed.kill_calls.load(Ordering::SeqCst) >= 2);
    assert_eq!(observed.signals(), 1);
    assert!(
        outcome.elapsed < Duration::from_secs(10),
        "ended by the timer's kill"
    );

    // The caller's kill did not take either.
    let (spawner, observed) = fake_with(true, |w| {
        w.ready()?;
        w.read()?;
        w.until_killed()
    });
    let handle = start(spawner, expect(false), init(one_second), sink()).await??;
    handle.kill(KillCause::Shutdown);
    let outcome = tokio::time::timeout(WAIT_BOUND, handle.wait()).await?;
    assert_eq!(outcome.host, HostVerdict::Killed(KillCause::Shutdown));
    assert_eq!(observed.signals(), 1);
    assert!(outcome.elapsed < Duration::from_secs(10));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversize_frame_kills_violation() -> TestResult {
    // A host.log frame one byte above the 1 MiB cap for non-terminal frames.
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        let empty = log_frame("").len();
        let frame = log_frame(&"o".repeat(MIB + 1 - empty));
        assert_eq!(frame.len(), MIB + 1);
        w.send(&frame)?;
        w.until_killed()
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(
        outcome.host,
        HostVerdict::Violation(ViolationKind::Oversize)
    );
    assert_eq!(observed.signals(), 1);

    // A header announcing more than any cap: refused before a body byte is read.
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.send_raw(&(30 * MIB as u32).to_be_bytes())?;
        w.until_killed()
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(
        outcome.host,
        HostVerdict::Violation(ViolationKind::Oversize)
    );
    assert_eq!(observed.signals(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_frame_cap_is_max_result_plus_64k() -> TestResult {
    let one_mib = limits_with(|l| l.max_result_mb = 1);
    let cap = MIB + 64 * 1024;

    let (spawner, _) = fake(move |w| {
        w.ready()?;
        w.read()?;
        w.send(&result_frame_of_len(cap))?;
        w.drain_stdin()?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, one_mib, sink()).await?;
    assert_eq!(outcome.host, HostVerdict::None);
    assert_eq!(
        result_text(&outcome).map(str::len),
        Some(cap - result_frame("").len())
    );

    let (spawner, observed) = fake(move |w| {
        w.ready()?;
        w.read()?;
        w.send(&result_frame_of_len(cap + 1))?;
        w.until_killed()
    });
    let outcome = run_to_end(spawner, one_mib, sink()).await?;
    assert_eq!(
        outcome.host,
        HostVerdict::Violation(ViolationKind::Oversize)
    );
    assert_eq!(outcome.end, WorkerEnd::None);
    assert_eq!(observed.signals(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_from_another_thread_while_wait_pending() -> TestResult {
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.until_killed()
    });
    let handle = Arc::new(
        start(
            spawner,
            expect(false),
            init(ScriptLimits::default()),
            sink(),
        )
        .await??,
    );
    assert!(handle.run_id().starts_with("run-"), "{}", handle.run_id());
    let waiter = {
        let handle = Arc::clone(&handle);
        tokio::spawn(async move { handle.wait().await })
    };
    let killer = {
        let handle = Arc::clone(&handle);
        thread::spawn(move || {
            let started = Instant::now();
            handle.kill(KillCause::User);
            started.elapsed()
        })
    };
    let took = killer.join().map_err(|_| "killer panicked")?;
    assert!(took < KILL_BOUND, "kill took {took:?}");
    let outcome = tokio::time::timeout(WAIT_BOUND, waiter).await??;
    assert_eq!(outcome.host, HostVerdict::Killed(KillCause::User));
    assert_eq!(observed.signals(), 1);
    // A second kill (another cause) changes nothing; wait answers the same outcome again.
    handle.kill(KillCause::Client);
    let again = tokio::time::timeout(WAIT_BOUND, handle.wait()).await?;
    assert_eq!(again, outcome);
    assert_eq!(observed.signals(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_call_futures_run_to_completion_after_worker_death() -> TestResult {
    // PD-148: the worker dies while the sink still works on its call; the call's task is never
    // dropped and runs to its end after the run's outcome is known.
    let (gated, gate) = TestSink::gated();
    let seen = gated.watch();
    let (spawner, _) = fake(move |w| {
        w.ready()?;
        w.read()?;
        w.call(1)?;
        seen.recv_timeout(WAIT_BOUND).map_err(io::Error::other)?;
        Ok(5) // dies without a terminal frame
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), gated.clone()).await?;
    assert_eq!(outcome.host, HostVerdict::Crashed(ExitKind::Code(5)));
    assert_eq!(gated.completed(), 0);
    gate.add_permits(1);
    eventually(|| gated.completed() == 1).await?;
    Ok(())
}

// ---- spawn-time checks (PD-132, PD-133, PD-141) --------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ready_version_mismatch_is_identity_mismatch_before_any_source_sent() -> TestResult {
    let (spawner, observed) = fake(|w| {
        w.ready_with("another-build", report(true))?;
        w.drain_stdin()?;
        Ok(0)
    });
    let refused = start(
        spawner,
        expect(false),
        init(ScriptLimits::default()),
        sink(),
    )
    .await?;
    assert_eq!(
        refused.err(),
        Some(StartRunError::IdentityMismatch {
            what: IdentityPart::EmbeddedVersion
        })
    );
    observed.wait_finished()?;
    assert!(
        observed.received().is_empty(),
        "no frame reached the worker"
    );
    assert_eq!(observed.signals(), 1, "the worker was killed");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unconfined_ready_is_floor_not_met_unless_degraded() -> TestResult {
    let (spawner, observed) = fake(|w| {
        w.ready_with(VERSION, report(false))?;
        w.drain_stdin()?;
        Ok(0)
    });
    let refused = start(
        spawner,
        expect(false),
        init(ScriptLimits::default()),
        sink(),
    )
    .await?;
    assert_eq!(refused.err(), Some(StartRunError::FloorNotMet));
    observed.wait_finished()?;
    assert!(observed.received().is_empty());
    assert_eq!(observed.signals(), 1);

    // Degraded accepted: the run starts and the outcome carries the unconfined report.
    let (spawner, observed) = fake(|w| {
        w.ready_with(VERSION, report(false))?;
        w.read()?;
        w.result("1")?;
        Ok(0)
    });
    let handle = start(spawner, expect(true), init(ScriptLimits::default()), sink()).await??;
    let outcome = tokio::time::timeout(WAIT_BOUND, handle.wait()).await?;
    assert_eq!(result_text(&outcome), Some("1"));
    assert_eq!(outcome.confinement, report(false));
    assert_eq!(observed.received_methods(), vec![M_SCRIPT_RUN.to_string()]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_ready_frame_is_spawn_timed_out() -> TestResult {
    // No ready frame within the 10 s plan value: the worker is killed before it gets anything.
    let (spawner, observed) = fake(|w| w.until_killed());
    let started = Instant::now();
    let refused = start(
        spawner,
        expect(false),
        init(ScriptLimits::default()),
        sink(),
    )
    .await?;
    assert_eq!(
        refused.err(),
        Some(StartRunError::Spawn(io::ErrorKind::TimedOut))
    );
    assert!(started.elapsed() >= Duration::from_secs(10));
    observed.wait_finished()?;
    assert!(observed.received().is_empty());
    assert_eq!(observed.signals(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outcome_carries_ready_frame_confinement_report() -> TestResult {
    let confinement = ConfinementReport {
        applied: true,
        mechanism: "seccomp+landlock".to_string(),
        no_new_privs: Some(true),
        landlock_abi: Some(3),
        seccomp: Some(true),
        lpac: None,
        os_error: None,
    };
    let sent = confinement.clone();
    let (spawner, observed) = fake(move |w| {
        w.ready_with(VERSION, sent)?;
        let init = w.read()?.ok_or_else(|| io::Error::other("no init"))?;
        assert_eq!(init["method"], M_SCRIPT_RUN);
        assert_eq!(init["params"]["args"], json!({"k": 1}));
        assert_eq!(init["params"]["read_op_ids"], json!(["jira.issue.get"]));
        assert!(init.get("id").is_none(), "script.run is a notification");
        w.result("{\"a\":1}")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(outcome.confinement, confinement);
    assert_eq!(result_text(&outcome), Some("{\"a\":1}"));
    assert_eq!(outcome.host, HostVerdict::None);
    observed.wait_finished()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn init_args_deeper_than_the_worker_reads_are_refused_before_spawn() -> TestResult {
    // The worker decodes `script.run` into a `Value` (serde_json: 127 nested levels at most);
    // the frame adds two levels above `args`.
    fn nested(depth: usize) -> Value {
        let mut v = json!(1);
        for _ in 0..depth {
            v = json!([v]);
        }
        v
    }
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.result("1")?;
        Ok(0)
    });
    let mut ok = init(ScriptLimits::default());
    ok.args = nested(125);
    let handle = start(spawner, expect(false), ok, sink()).await??;
    let outcome = tokio::time::timeout(WAIT_BOUND, handle.wait()).await?;
    assert_eq!(result_text(&outcome), Some("1"));
    assert_eq!(observed.spawns.load(Ordering::SeqCst), 1);

    let (spawner, observed) = fake(|w| w.until_killed());
    let mut deep = init(ScriptLimits::default());
    deep.args = nested(126);
    let refused = start(spawner, expect(false), deep, sink()).await?;
    assert_eq!(
        refused.err(),
        Some(StartRunError::Spawn(io::ErrorKind::InvalidInput))
    );
    assert_eq!(observed.spawns.load(Ordering::SeqCst), 0, "nothing spawned");
    Ok(())
}

// ---- protocol violations (§3.4) ---------------------------------------------------------

/// Runs a fake that sends `payload` as one frame after the init and returns the outcome.
async fn violation_of(payload: Vec<u8>) -> Result<(RunOutcome, u32), Box<dyn std::error::Error>> {
    let (spawner, observed) = fake(move |w| {
        w.ready()?;
        w.read()?;
        w.send(&payload)?;
        w.until_killed()
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    Ok((outcome, observed.signals()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jsonrpc_id_mismatch_is_violation() -> TestResult {
    let call = HostCall {
        id: 2,
        op_id: "jira.issue.get".to_string(),
        params: json!({}),
        instance: None,
        all: false,
    };
    let (outcome, signals) = violation_of(encode_request(M_HOST_CALL, 1, &call)).await?;
    assert_eq!(
        outcome.host,
        HostVerdict::Violation(ViolationKind::IdMismatch)
    );
    assert_eq!(signals, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_sent_jsonrpc_response_is_violation() -> TestResult {
    let response = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":1}}"#.to_vec();
    let (outcome, signals) = violation_of(response).await?;
    assert_eq!(
        outcome.host,
        HostVerdict::Violation(ViolationKind::WorkerResponse)
    );
    assert_eq!(signals, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_and_unknown_frames_are_violations() -> TestResult {
    let cases: Vec<(Vec<u8>, ViolationKind)> = vec![
        (b"not json".to_vec(), ViolationKind::Malformed),
        (vec![0xff, 0xfe, b'{'], ViolationKind::Malformed),
        (b"[1,2]".to_vec(), ViolationKind::Malformed),
        (
            br#"{"jsonrpc":"2.0","method":"host.log","params":{"line":"\ud800 ok"},"x":1}"#
                .to_vec(),
            ViolationKind::Malformed,
        ),
        (
            br#"{"jsonrpc":"2.0","method":"host.exec","params":{}}"#.to_vec(),
            ViolationKind::UnknownMethod,
        ),
        (
            br#"{"jsonrpc":"2.0","method":"probe.result","params":{}}"#.to_vec(),
            ViolationKind::UnknownMethod,
        ),
        // Frames of the compile mode during a run.
        (
            encode_notification(M_SCRIPT_COMPILED, &EmptyParams {}),
            ViolationKind::UnexpectedFrame,
        ),
        (
            encode_notification(
                M_SCRIPT_SYNTAX,
                &SyntaxParams {
                    line: 1,
                    column: 1,
                    message: "x".to_string(),
                },
            ),
            ViolationKind::UnexpectedFrame,
        ),
    ];
    for (payload, kind) in cases {
        let shown = String::from_utf8_lossy(&payload).into_owned();
        let (outcome, signals) = violation_of(payload).await?;
        assert_eq!(outcome.host, HostVerdict::Violation(kind), "{shown}");
        assert_eq!(signals, 1, "{shown}");
    }
    Ok(())
}

// ---- how the run ended ----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn script_error_is_reported_as_worker_payload() -> TestResult {
    let (spawner, _) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.error("TypeError", "x is not a function")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(
        outcome.end,
        WorkerEnd::Error {
            class: "TypeError".to_string(),
            message: "x is not a function".to_string(),
            stack: String::new(),
        }
    );
    assert_eq!(outcome.host, HostVerdict::None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreadable_result_is_a_runtime_type_error() -> TestResult {
    // T4 fix I-1, binding fallback for T7/T20: a result the core cannot read into a `Value` is a
    // worker-reported runtime error, never a violation or a crash.
    let deep = format!("{}1{}", "[".repeat(300), "]".repeat(300));
    let cases = [
        "\"\\ud800\"".to_string(),
        deep,
        r#"{"$serde_json::private::RawValue":"[1]"}"#.to_string(),
    ];
    for value in cases {
        let sent = value.clone();
        let (spawner, _) = fake(move |w| {
            w.ready()?;
            w.read()?;
            w.result(&sent)?;
            Ok(0)
        });
        let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
        assert_eq!(
            outcome.end,
            WorkerEnd::Error {
                class: "TypeError".to_string(),
                message: RESULT_NOT_REPRESENTABLE.to_string(),
                stack: String::new(),
            },
            "{}",
            &value[..value.len().min(40)]
        );
        assert_eq!(outcome.host, HostVerdict::None);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exit_zero_without_terminal_is_crashed() -> TestResult {
    // T4: the worker exits 0 at stdin EOF with no terminal frame; that is never success.
    let (spawner, _) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.log("bye")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(outcome.end, WorkerEnd::None);
    assert_eq!(outcome.host, HostVerdict::Crashed(ExitKind::Code(0)));
    assert_eq!(outcome.logs, vec!["bye".to_string()]);
    Ok(())
}

// ---- compile mode (PD-132, PD-135) ------------------------------------------------------

/// `compile_run` on a blocking thread.
async fn compile(
    spawner: Arc<FakeSpawner>,
    deadline: Duration,
) -> Result<Result<CompileVerdict, StartRunError>, Box<dyn std::error::Error>> {
    Ok(tokio::task::spawn_blocking(move || {
        compile_run(
            spawner.as_ref(),
            &spec(),
            &expect(false),
            "function main( {",
            deadline,
        )
    })
    .await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compile_run_returns_syntax_position() -> TestResult {
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        let req = w.read()?.ok_or_else(|| io::Error::other("no request"))?;
        assert_eq!(req["method"], M_SCRIPT_COMPILE);
        assert_eq!(req["params"]["source"], "function main( {");
        w.send(&encode_notification(
            M_SCRIPT_SYNTAX,
            &SyntaxParams {
                line: 3,
                column: 7,
                message: "unexpected token".to_string(),
            },
        ))?;
        w.drain_stdin()?;
        Ok(0)
    });
    let verdict = compile(spawner, Duration::from_secs(10)).await??;
    assert_eq!(
        verdict,
        CompileVerdict::Syntax {
            line: 3,
            column: 7,
            message: "unexpected token".to_string()
        }
    );
    observed.wait_finished()?;
    assert_eq!(
        observed.received_methods(),
        vec![M_SCRIPT_COMPILE.to_string()]
    );

    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.send(&encode_notification(M_SCRIPT_COMPILED, &EmptyParams {}))?;
        w.drain_stdin()?;
        Ok(0)
    });
    assert_eq!(
        compile(spawner, Duration::from_secs(10)).await??,
        CompileVerdict::Compiled
    );
    observed.wait_finished()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compile_run_deadline_kills_and_returns_timeout() -> TestResult {
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.until_killed()
    });
    let started = Instant::now();
    let verdict = compile(spawner, Duration::from_millis(300)).await??;
    assert_eq!(verdict, CompileVerdict::Timeout);
    assert!(started.elapsed() < WAIT_BOUND);
    assert_eq!(observed.signals(), 1, "the compile worker was killed");

    // The deadline also covers the ready frame.
    let (spawner, observed) = fake(|w| w.until_killed());
    let verdict = compile(spawner, Duration::from_millis(300)).await??;
    assert_eq!(verdict, CompileVerdict::Timeout);
    assert_eq!(observed.signals(), 1);
    assert!(observed.received().is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compile_without_verdict_is_timeout_never_syntax() -> TestResult {
    // T4: a compile worker that ends without a verdict (backstop, op budget, engine fault 101,
    // heap 102, process 103) is never a syntax error.
    for code in [101, 102, 103, 0] {
        let (spawner, _) = fake(move |w| {
            w.ready()?;
            w.read()?;
            Ok(code)
        });
        assert_eq!(
            compile(spawner, Duration::from_secs(10)).await??,
            CompileVerdict::Timeout,
            "exit {code}"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compile_run_refuses_like_start_run() -> TestResult {
    let (spawner, observed) = fake(|w| {
        w.ready_with("another-build", report(true))?;
        w.drain_stdin()?;
        Ok(0)
    });
    assert_eq!(
        compile(spawner, Duration::from_secs(10)).await?,
        Err(StartRunError::IdentityMismatch {
            what: IdentityPart::EmbeddedVersion
        })
    );
    observed.wait_finished()?;
    assert!(observed.received().is_empty());

    let (spawner, _) = fake(|w| {
        w.ready_with(VERSION, report(false))?;
        w.drain_stdin()?;
        Ok(0)
    });
    assert_eq!(
        compile(spawner, Duration::from_secs(10)).await?,
        Err(StartRunError::FloorNotMet)
    );

    // A run frame in compile mode is no verdict the host can use.
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.log("hello")?;
        w.until_killed()
    });
    assert_eq!(
        compile(spawner, Duration::from_secs(10)).await?,
        Err(StartRunError::Spawn(io::ErrorKind::InvalidData))
    );
    assert_eq!(observed.signals(), 1);
    Ok(())
}
