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
use std::io::{self, Read, Write};
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
use atlas_duck_ipc::sandbox::{
    EXIT_PROTOCOL, HOST_TO_WORKER_MAX, HostCall, HostCallResult, ScriptLimits, terminal_frame_max,
};
use atlas_duck_sandbox_host::bridge::{
    CompileVerdict, DIAG_CALL_RESULT_REPLACED, DIAG_HOST_PROTOCOL_EXIT, DIAG_JOB_MEMORY_LIMIT,
    DIAG_MEMORY_WATCH_FAILED, DIAG_OUTCOME_LOST, DIAG_REAP_FAILED, DIAG_STDIN_HELD,
    DIAG_STDOUT_HELD, DIAG_UNREAD_RESULTS, DIAG_WATCHDOG_KILL, ExpectedWorker, HostCallSink,
    HostVerdict, KillCause, LOG_CAP_BYTES, LOG_CAP_LINES, RESULT_NOT_REPRESENTABLE, RunHandleImpl,
    RunOutcome, STDERR_CAP, STDOUT_GRACE, StartRunError, ViolationKind, WorkerEnd, compile_run,
    log_truncated_marker, start_run, unread_results_cap,
};
use atlas_duck_sandbox_host::identity::{
    FileId, IdentityPart, SandboxBinaryIdentity, file_identity,
};
use atlas_duck_sandbox_host::kill::{GuardedKill, ReapGuard, reap_after_wait};
use atlas_duck_sandbox_host::limits::{MemoryWatch, OsMemorySignal};
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
    /// When the kill signal reached the running fake.
    killed_at: Mutex<Option<Instant>>,
    /// Signals the kill handle sent (at most one).
    signals: AtomicU32,
    /// Calls of the kill handle, including no-ops and a swallowed one.
    kill_calls: AtomicU32,
    spawns: AtomicU32,
    finished: Mutex<bool>,
    finished_cv: Condvar,
    /// M8 Task 9: whether the worker was reaped when its memory watch was stopped (`None`: not
    /// stopped).
    watch_stopped_after_reap: Mutex<Option<bool>>,
}

impl Observed {
    /// The kill signal. Like a real kill, it changes nothing for a fake that already ended.
    fn kill(&self) {
        self.signals.fetch_add(1, Ordering::SeqCst);
        let dead = self.finished.lock().map(|f| *f).unwrap_or(true);
        if let Ok(mut k) = self.killed.lock()
            && !dead
        {
            if !*k && let Ok(mut at) = self.killed_at.lock() {
                *at = Some(Instant::now());
            }
            *k = true;
        }
        self.killed_cv.notify_all();
    }

    fn killed_at(&self) -> Option<Instant> {
        self.killed_at.lock().ok().and_then(|at| *at)
    }

    fn kill_calls(&self) -> u32 {
        self.kill_calls.load(Ordering::SeqCst)
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

    fn watch_stopped_after_reap(&self) -> Option<bool> {
        self.watch_stopped_after_reap.lock().ok().and_then(|s| *s)
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
        self.wait_finished_within(WAIT_BOUND)
    }

    /// [`Observed::wait_finished`] with a shorter bound: the fake ends within `bound` only if the
    /// host killed it (a fake waiting for its kill gives up after [`WAIT_BOUND`]).
    fn wait_finished_within(&self, bound: Duration) -> Result<(), String> {
        let guard = self.finished.lock().map_err(|_| "poisoned")?;
        let (guard, _) = self
            .finished_cv
            .wait_timeout_while(guard, bound, |f| !*f)
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
    /// `None` once the fake closed its stdout ([`FakeWorker::close_stdout`]).
    stdout: Option<io::PipeWriter>,
    stderr: io::PipeWriter,
    observed: Arc<Observed>,
    /// Plays the OS's memory reports to the fake's memory watch (M8 Task 9).
    os: mpsc::Sender<WatchMsg>,
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

    /// The open stdout, unless the fake was killed.
    fn stdout(&mut self) -> io::Result<&mut io::PipeWriter> {
        if self.observed.is_killed() {
            return Err(killed_error());
        }
        self.stdout
            .as_mut()
            .ok_or_else(|| io::Error::other("stdout is closed"))
    }

    /// One frame, unless the fake was killed.
    fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        write_frame(self.stdout()?, payload)
    }

    /// Raw bytes in one write (several frames land before the host can react).
    fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        let stdout = self.stdout()?;
        stdout.write_all(bytes)?;
        stdout.flush()
    }

    /// Closes stdout while the fake keeps running (the host reads EOF).
    fn close_stdout(&mut self) {
        self.stdout = None;
    }

    /// Hands stdout to a "child" that outlives the fake (a degraded worker that forked): the
    /// child holds the pipe, silent, until `go` receives (at most `hold`), then sends one log
    /// frame and closes the pipe. Returns a receiver told once that frame was written.
    fn fork_child_holding_stdout(&mut self, go: Receiver<()>, hold: Duration) -> Receiver<()> {
        let stdout = self.stdout.take();
        let (written_tx, written) = mpsc::channel();
        thread::spawn(move || {
            let _ = go.recv_timeout(hold);
            if let Some(mut stdout) = stdout
                && write_frame(&mut stdout, &log_frame("from the child")).is_ok()
            {
                let _ = written_tx.send(());
            }
        });
        written
    }

    /// Hands a copy of stdin to a "child" that outlives the fake (a degraded worker that forked):
    /// it holds the read end, never reading, until `go` receives (at most `hold`).
    fn fork_child_holding_stdin(&mut self, go: Receiver<()>, hold: Duration) -> io::Result<()> {
        let stdin = self.stdin.try_clone()?;
        thread::spawn(move || {
            let _ = go.recv_timeout(hold);
            drop(stdin);
        });
        Ok(())
    }

    /// The OS reports the fake above its memory limit (the Windows job message, the macOS
    /// watchdog's reading).
    fn os_memory_report(&self) -> io::Result<()> {
        self.os
            .send(WatchMsg::Report)
            .map_err(|_| io::Error::other("no memory watch"))
    }

    /// Reads the 4-byte header of the next host frame and nothing more: the writer stays blocked
    /// in that frame once the pipe is full.
    fn read_header(&mut self) -> io::Result<u32> {
        let mut header = [0u8; 4];
        self.stdin.read_exact(&mut header)?;
        Ok(u32::from_be_bytes(header))
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
    opts: FakeOpts,
}

/// How the fake's process handles misbehave.
#[derive(Clone, Copy, Default)]
struct FakeOpts {
    /// The kill handle swallows this many calls first (OS calls that failed without a sign).
    swallow_kills: u32,
    /// The reaper reaps, then reports an error (the exit status is lost).
    reap_fails: bool,
    /// M8 Task 9: the fake has a memory watch reporting this signal.
    watch: Option<OsMemorySignal>,
    /// The memory watch cannot observe the fake (it ends at once with an error).
    watch_fails: bool,
}

/// What the fake's memory watch receives.
enum WatchMsg {
    /// The OS reported the worker above its limit.
    Report,
    /// The bridge stopped the watch.
    Stop,
}

/// The fake's memory watch: each [`WatchMsg::Report`] kills through the bridge's limit handle;
/// it records whether the worker was reaped when it was stopped.
struct FakeWatch {
    signal: OsMemorySignal,
    rx: Receiver<WatchMsg>,
    stop: Option<mpsc::Sender<WatchMsg>>,
    guard: Arc<ReapGuard>,
    observed: Arc<Observed>,
    fails: bool,
}

impl MemoryWatch for FakeWatch {
    fn signal(&self) -> OsMemorySignal {
        self.signal
    }

    fn stopper(&mut self) -> Box<dyn FnOnce() + Send> {
        let stop = self.stop.take();
        Box::new(move || {
            if let Some(stop) = stop {
                let _ = stop.send(WatchMsg::Stop);
            }
        })
    }

    fn run(self: Box<Self>, limit: &dyn KillHandle) -> io::Result<()> {
        if self.fails {
            return Err(io::Error::other("cannot observe the fake"));
        }
        loop {
            match self.rx.recv_timeout(WAIT_BOUND) {
                Ok(WatchMsg::Report) => limit.kill(),
                Ok(WatchMsg::Stop) => {
                    if let Ok(mut s) = self.observed.watch_stopped_after_reap.lock() {
                        *s = Some(self.guard.is_reaped());
                    }
                    return Ok(());
                }
                Err(_) => return Err(io::Error::other("never stopped")),
            }
        }
    }
}

fn fake(
    script: impl FnOnce(&mut FakeWorker) -> io::Result<i32> + Send + 'static,
) -> (Arc<FakeSpawner>, Arc<Observed>) {
    fake_opts(FakeOpts::default(), script)
}

/// A fake whose kill handle swallows its first call.
fn fake_with(
    flaky_kill: bool,
    script: impl FnOnce(&mut FakeWorker) -> io::Result<i32> + Send + 'static,
) -> (Arc<FakeSpawner>, Arc<Observed>) {
    let opts = FakeOpts {
        swallow_kills: u32::from(flaky_kill),
        ..FakeOpts::default()
    };
    fake_opts(opts, script)
}

fn fake_opts(
    opts: FakeOpts,
    script: impl FnOnce(&mut FakeWorker) -> io::Result<i32> + Send + 'static,
) -> (Arc<FakeSpawner>, Arc<Observed>) {
    let observed = Arc::new(Observed::default());
    let spawner = FakeSpawner {
        script: Mutex::new(Some(Box::new(script))),
        observed: Arc::clone(&observed),
        opts,
    };
    (Arc::new(spawner), observed)
}

/// A kill handle whose first `swallow` calls do nothing, then behaves like the real one.
struct FlakyKill {
    inner: GuardedKill,
    observed: Arc<Observed>,
    swallow: u32,
}

impl KillHandle for FlakyKill {
    fn kill(&self) {
        if self.observed.kill_calls.fetch_add(1, Ordering::SeqCst) >= self.swallow {
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
        let (os_tx, os_rx) = mpsc::channel();
        let mut worker = FakeWorker {
            stdin: stdin_r,
            stdout: Some(stdout_w),
            stderr: stderr_w,
            observed: Arc::clone(&self.observed),
            os: os_tx.clone(),
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
            opts: self.opts,
            guard: ReapGuard::new(),
            os: Some((os_tx, os_rx)),
        }))
    }
}

struct FakeProcess {
    stdin: io::PipeWriter,
    stdout: io::PipeReader,
    stderr: io::PipeReader,
    exit: Receiver<i32>,
    observed: Arc<Observed>,
    opts: FakeOpts,
    guard: Arc<ReapGuard>,
    /// The memory watch's channel, until the watch is taken.
    os: Option<(mpsc::Sender<WatchMsg>, Receiver<WatchMsg>)>,
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

    fn memory_watch(&mut self) -> io::Result<Option<Box<dyn MemoryWatch>>> {
        let (Some(signal), Some((tx, rx))) = (self.opts.watch, self.os.take()) else {
            return Ok(None);
        };
        Ok(Some(Box::new(FakeWatch {
            signal,
            rx,
            stop: Some(tx),
            guard: Arc::clone(&self.guard),
            observed: Arc::clone(&self.observed),
            fails: self.opts.watch_fails,
        })))
    }

    fn into_parts(self: Box<Self>) -> io::Result<WorkerParts> {
        let guard = Arc::clone(&self.guard);
        let observed = Arc::clone(&self.observed);
        let inner = GuardedKill::new(Arc::clone(&guard), move || observed.kill());
        let observed = Arc::clone(&self.observed);
        let kill: Arc<dyn KillHandle> = if self.opts.swallow_kills > 0 {
            Arc::new(FlakyKill {
                inner,
                observed,
                swallow: self.opts.swallow_kills,
            })
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
                fails: self.opts.reap_fails,
            }),
        })
    }
}

struct FakeReaper {
    guard: Arc<ReapGuard>,
    exit: Receiver<i32>,
    observed: Arc<Observed>,
    fails: bool,
}

impl Reaper for FakeReaper {
    fn wait(self: Box<Self>) -> io::Result<ExitKind> {
        let code = Cell::new(None);
        let reaped = reap_after_wait(
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
        );
        if self.fails {
            return reaped.and(Err(io::Error::other("the exit status was lost")));
        }
        reaped
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

/// A `script.result` frame of exactly `len` bytes whose value is an array of zeros: per byte, the
/// text the host's representability check (a visitor call per element) takes longest for.
fn zeros_result_frame_of_len(len: usize) -> Vec<u8> {
    let room = len - result_frame("[0]").len();
    let more = room / 2;
    let value = format!("[0{}{}]", ",0".repeat(more), " ".repeat(room - 2 * more));
    result_frame(&value).into_bytes()
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

/// The "worker binary" of these tests: a plain file that exists (the bridge re-checks the file
/// identity of `SpawnSpec.exe` before it spawns, V21); the fake spawner never executes it.
fn worker_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
}

fn expect(accept_unconfined: bool) -> ExpectedWorker {
    let identity = match file_identity(&worker_file()) {
        Ok((file_id, size, mtime)) => SandboxBinaryIdentity {
            file_id,
            size,
            mtime,
            embedded_version: VERSION.to_string(),
        },
        // Unreadable: the identity of no file, so the re-check refuses and the test fails.
        Err(_) => SandboxBinaryIdentity {
            file_id: FileId::FileIndex {
                volume_serial: 7,
                index: 42,
            },
            size: 1000,
            mtime: SystemTime::UNIX_EPOCH,
            embedded_version: VERSION.to_string(),
        },
    };
    ExpectedWorker {
        identity,
        accept_unconfined,
    }
}

fn spec() -> SpawnSpec {
    SpawnSpec {
        exe: worker_file(),
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

/// A sink whose `log` of the line "first" waits (bounded) until `ready` holds, and whose every
/// `log` then takes `delay` (a slow glue on the reader thread). It counts the calls it sees.
struct GatedLogSink {
    ready: Box<dyn Fn() -> bool + Send + Sync>,
    delay: Duration,
    logs: Mutex<Vec<String>>,
    calls: AtomicU32,
}

impl GatedLogSink {
    fn new(ready: impl Fn() -> bool + Send + Sync + 'static, delay: Duration) -> Arc<Self> {
        Arc::new(GatedLogSink {
            ready: Box::new(ready),
            delay,
            logs: Mutex::default(),
            calls: AtomicU32::new(0),
        })
    }

    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl HostCallSink for GatedLogSink {
    async fn call(&self, _run_id: &str, c: HostCall) -> HostCallResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        HostCallResult::Ok(json!(c.id))
    }

    fn log(&self, _run_id: &str, line: &str) {
        let started = Instant::now();
        while line == "first" && !(self.ready)() && started.elapsed() < WAIT_BOUND {
            thread::sleep(Duration::from_millis(2));
        }
        thread::sleep(self.delay);
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

    // Queued is enough, written is not needed: the fake reads only the header of call 1's 2 MiB
    // answer, so the writer stays blocked inside that frame, and call 2 is still within the limit.
    let padded = TestSink::padded(2 * MIB);
    let (spawner, observed) = fake(move |w| {
        w.ready()?;
        w.read()?;
        w.call(1)?;
        let len = w.read_header()?;
        assert!(len as usize > 2 * MIB, "call 1's answer is being written");
        w.call(2)?;
        w.result("2")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, one, padded.clone()).await?;
    assert_eq!(outcome.host, HostVerdict::None);
    assert_eq!(result_text(&outcome), Some("2"));
    eventually(|| padded.calls().len() == 2).await?;
    assert_eq!(padded.calls(), vec![1, 2]);
    observed.wait_finished()?;
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
    // Calls 1 and 2 reached the sink, call 3 never did. Each call is its own task, so the two
    // may reach the sink in either order (T9 review m-1).
    eventually(|| gated.calls().len() == 2).await?;
    let mut calls = gated.calls();
    calls.sort_unstable();
    assert_eq!(calls, vec![1, 2]);
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
    // result; the call's answer, ready only after the terminal decided the run, is never written,
    // although the worker still reads its stdin then: it reads EOF and nothing else.
    let (gated, gate) = TestSink::gated();
    let seen = gated.watch();
    let (answered_tx, answered_rx) = mpsc::channel::<()>();
    let (spawner, observed) = fake(move |w| {
        w.ready()?;
        w.read()?;
        w.call(1)?;
        seen.recv_timeout(WAIT_BOUND).map_err(io::Error::other)?;
        w.result("\"done\"")?;
        answered_rx
            .recv_timeout(WAIT_BOUND)
            .map_err(io::Error::other)?;
        w.drain_stdin()?;
        Ok(0)
    });
    let handle = start(
        spawner,
        expect(false),
        init(ScriptLimits::default()),
        gated.clone(),
    )
    .await??;
    // The terminal decided the run (its kill reached the fake); only now the call completes.
    eventually(|| observed.is_killed()).await?;
    gate.add_permits(1);
    eventually(|| gated.completed() == 1).await?;
    answered_tx.send(())?;
    let outcome = tokio::time::timeout(WAIT_BOUND, handle.wait()).await?;
    assert_eq!(result_text(&outcome), Some("\"done\""));
    assert_eq!(outcome.host, HostVerdict::None);
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
    assert_eq!(outcome.host, HostVerdict::Crashed(Some(ExitKind::Code(5))));
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

/// An expectation whose recorded file identity is not the file at `spec().exe` (a replaced
/// binary), in the part named.
fn expect_changed(part: IdentityPart) -> ExpectedWorker {
    let mut e = expect(false);
    match part {
        IdentityPart::Size => e.identity.size += 1,
        IdentityPart::Mtime => e.identity.mtime = SystemTime::UNIX_EPOCH,
        _ => {
            e.identity.file_id = FileId::FileIndex {
                volume_serial: 7,
                index: 42,
            }
        }
    }
    e
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_run_rechecks_the_file_identity_before_the_spawn() -> TestResult {
    for part in [
        IdentityPart::FileId,
        IdentityPart::Size,
        IdentityPart::Mtime,
    ] {
        let (spawner, observed) = fake(|w| {
            w.ready()?;
            w.drain_stdin()?;
            Ok(0)
        });
        let refused = start(
            spawner,
            expect_changed(part),
            init(ScriptLimits::default()),
            sink(),
        )
        .await?;
        assert_eq!(
            refused.err(),
            Some(StartRunError::IdentityMismatch { what: part })
        );
        assert_eq!(observed.spawns.load(Ordering::SeqCst), 0, "nothing spawned");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_run_with_a_missing_binary_is_identity_mismatch_nothing_spawned() -> TestResult {
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.drain_stdin()?;
        Ok(0)
    });
    let rt = tokio::runtime::Handle::current();
    let gone = SpawnSpec {
        exe: worker_file().with_file_name("no-such-worker"),
        process_mb: 512,
    };
    let refused = tokio::task::spawn_blocking(move || {
        start_run(
            spawner.as_ref(),
            &gone,
            &expect(false),
            init(ScriptLimits::default()),
            sink(),
            rt,
        )
    })
    .await?;
    assert_eq!(
        refused.err(),
        Some(StartRunError::IdentityMismatch {
            what: IdentityPart::Missing
        })
    );
    assert_eq!(observed.spawns.load(Ordering::SeqCst), 0, "nothing spawned");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compile_run_rechecks_the_file_identity_before_the_spawn() -> TestResult {
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.drain_stdin()?;
        Ok(0)
    });
    let refused = tokio::task::spawn_blocking(move || {
        compile_run(
            spawner.as_ref(),
            &spec(),
            &expect_changed(IdentityPart::FileId),
            "function main() {}",
            Duration::from_secs(10),
        )
    })
    .await?;
    assert_eq!(
        refused,
        Err(StartRunError::IdentityMismatch {
            what: IdentityPart::FileId
        })
    );
    assert_eq!(observed.spawns.load(Ordering::SeqCst), 0, "nothing spawned");
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
    assert_eq!(outcome.host, HostVerdict::Crashed(Some(ExitKind::Code(0))));
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

    // A reply above the 1 MiB frame cap: its header is refused, no body byte is read.
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.send_raw(&(MIB as u32 + 1).to_be_bytes())?;
        w.until_killed()
    });
    assert_eq!(
        compile(spawner, Duration::from_secs(10)).await?,
        Err(StartRunError::Spawn(io::ErrorKind::InvalidData))
    );
    assert_eq!(observed.signals(), 1);
    Ok(())
}

// ---- M8 T7 review fixes ----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cap_size_result_never_holds_up_a_kill() -> TestResult {
    // I-1: whether a `script.result` reads as a `Value` takes a full parse of up to
    // `max_result_mb` + 64 KiB. It runs before the run lock is taken, so a kill that lands while
    // the reader handles that frame never waits for it. A kill decides the run (and the frame is
    // then ignored) unless the reader took the lock first, so the kills start at several points of
    // the time the host takes for the frame, measured first.
    let limits = ScriptLimits::default();
    let frame = Arc::new(framed(&zeros_result_frame_of_len(terminal_frame_max(
        &limits,
    ))));
    let handling = {
        let (sent_tx, sent_rx) = mpsc::channel();
        let frame = Arc::clone(&frame);
        let (spawner, observed) = fake(move |w| {
            w.ready()?;
            w.read()?;
            w.send_raw(&frame)?;
            let _ = sent_tx.send(Instant::now());
            w.until_killed()
        });
        let outcome = run_to_end(spawner, limits, sink()).await?;
        assert_eq!(outcome.host, HostVerdict::None);
        let sent = sent_rx.recv_timeout(WAIT_BOUND)?;
        let killed = observed
            .killed_at()
            .ok_or("the terminal's kill never came")?;
        killed.saturating_duration_since(sent)
    };

    let mut slowest = Duration::ZERO;
    for tenths in [2u32, 4, 6, 8] {
        let (sent_tx, sent_rx) = mpsc::channel::<Instant>();
        let frame = Arc::clone(&frame);
        let (spawner, _) = fake(move |w| {
            w.ready()?;
            w.read()?;
            w.send_raw(&frame)?;
            let _ = sent_tx.send(Instant::now());
            w.until_killed()
        });
        let handle = Arc::new(start(spawner, expect(false), init(limits), sink()).await??);
        let killer = {
            let handle = Arc::clone(&handle);
            thread::spawn(move || -> Result<Duration, String> {
                let sent = sent_rx
                    .recv_timeout(WAIT_BOUND)
                    .map_err(|e| e.to_string())?;
                let from = sent + handling * tenths / 10;
                thread::sleep(from.saturating_duration_since(Instant::now()));
                let mut slowest = Duration::ZERO;
                for _ in 0..20 {
                    let started = Instant::now();
                    handle.kill(KillCause::User);
                    slowest = slowest.max(started.elapsed());
                    thread::sleep(Duration::from_millis(2));
                }
                Ok(slowest)
            })
        };
        let outcome = tokio::time::timeout(WAIT_BOUND, handle.wait()).await?;
        assert!(
            matches!(
                outcome.host,
                HostVerdict::None | HostVerdict::Killed(KillCause::User)
            ),
            "{:?}",
            outcome.host
        );
        let took = killer.join().map_err(|_| "the killer panicked")??;
        slowest = slowest.max(took);
    }
    eprintln!("I-1 frame_handling={handling:?} slowest_kill={slowest:?}");
    assert!(
        slowest < KILL_BOUND,
        "a kill took {slowest:?} (the host took {handling:?} for the frame)"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exit_protocol_without_terminal_is_a_host_fault() -> TestResult {
    // T4 hand-off: exit 3 means the worker could not read what the host sent. That is a host bug,
    // never the script's doing: its own verdict plus a diag, never `Crashed`.
    let (spawner, _) = fake(|w| {
        w.ready()?;
        w.read()?;
        Ok(EXIT_PROTOCOL)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(outcome.host, HostVerdict::HostFault);
    assert_eq!(outcome.end, WorkerEnd::None);
    assert_eq!(outcome.diag, vec![DIAG_HOST_PROTOCOL_EXIT]);

    // After an accepted terminal frame the exit does not matter (the terminal's kill is swallowed,
    // so the fake's own exit is reported).
    let opts = FakeOpts {
        swallow_kills: 1,
        ..FakeOpts::default()
    };
    let (spawner, _) = fake_opts(opts, |w| {
        w.ready()?;
        w.read()?;
        w.result("1")?;
        w.drain_stdin()?;
        Ok(EXIT_PROTOCOL)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(outcome.host, HostVerdict::None);
    assert_eq!(result_text(&outcome), Some("1"));
    assert!(outcome.diag.is_empty(), "{:?}", outcome.diag);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compile_exit_protocol_is_unavailable_never_timeout() -> TestResult {
    // T4: "Exit 3 from a compile worker can only be a host protocol fault."
    let (spawner, _) = fake(|w| {
        w.ready()?;
        w.read()?;
        Ok(EXIT_PROTOCOL)
    });
    assert_eq!(
        compile(spawner, Duration::from_secs(10)).await?,
        Err(StartRunError::Spawn(io::ErrorKind::InvalidData))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_timer_kills_until_the_worker_is_reaped() -> TestResult {
    // m-1: from `timeout_s` on, the timer kills again and again until the reap, not just once.
    let opts = FakeOpts {
        swallow_kills: 3,
        ..FakeOpts::default()
    };
    let (spawner, observed) = fake_opts(opts, |w| {
        w.ready()?;
        w.read()?;
        w.send(b"not json")?;
        w.until_killed()
    });
    let one_second = limits_with(|l| l.timeout_s = 1);
    let handle = start(spawner, expect(false), init(one_second), sink()).await??;
    let outcome = tokio::time::timeout(Duration::from_secs(10), handle.wait()).await?;
    assert_eq!(
        outcome.host,
        HostVerdict::Violation(ViolationKind::Malformed)
    );
    assert!(observed.kill_calls() >= 4, "{}", observed.kill_calls());
    assert_eq!(observed.signals(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_and_compile_workers_are_killed_until_reaped() -> TestResult {
    // m-1: a refused worker and a compile worker get no run timer; their kill is retried until the
    // reap as well.
    let opts = FakeOpts {
        swallow_kills: 2,
        ..FakeOpts::default()
    };
    let (spawner, observed) = fake_opts(opts, |w| {
        w.ready_with("another-build", report(true))?;
        w.until_killed()
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
    observed.wait_finished_within(Duration::from_secs(10))?;
    assert!(observed.kill_calls() >= 3, "{}", observed.kill_calls());
    assert_eq!(observed.signals(), 1);

    let (spawner, observed) = fake_opts(opts, |w| {
        w.ready()?;
        w.read()?;
        w.until_killed()
    });
    assert_eq!(
        compile(spawner, Duration::from_millis(300)).await??,
        CompileVerdict::Timeout
    );
    observed.wait_finished_within(Duration::from_secs(10))?;
    assert!(observed.kill_calls() >= 3, "{}", observed.kill_calls());
    assert_eq!(observed.signals(), 1);
    Ok(())
}

#[test]
fn start_run_needs_the_time_driver_before_it_spawns() -> TestResult {
    // m-2: the run timer needs tokio's time driver. Without it `start_run` panics before it
    // spawns anything, not in a timer task where nobody sees it (and no timeout is enforced).
    let rt = tokio::runtime::Builder::new_current_thread().build()?;
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.until_killed()
    });
    let handle = rt.handle().clone();
    let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        start_run(
            spawner.as_ref(),
            &spec(),
            &expect(false),
            init(ScriptLimits::default()),
            sink(),
            handle,
        )
    }));
    assert!(started.is_err(), "start_run must panic");
    assert_eq!(observed.spawns.load(Ordering::SeqCst), 0, "nothing spawned");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_closed_stdout_keeps_its_own_exit_code() -> TestResult {
    // m-4: on Windows a process's handles close before its exit code is set, and a kill in that
    // window would replace the code (102 by 1). At stdout EOF the bridge waits for the exit first.
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.close_stdout();
        thread::sleep(Duration::from_millis(300));
        Ok(102)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    // M8 Task 9: the kept code is the heap limit.
    assert_eq!(outcome.host, HostVerdict::Limit("heap_mb"));
    assert_eq!(observed.signals(), 0, "not killed");

    // A worker that closed its stdout and keeps running is killed after that wait.
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.close_stdout();
        w.until_killed()
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(
        outcome.host,
        HostVerdict::Crashed(Some(ExitKind::Signal(9)))
    );
    assert_eq!(observed.signals(), 1);
    Ok(())
}

/// A sink whose `log` fails: the bridge's reader thread unwinds with it.
struct FailingLogSink;

#[async_trait]
impl HostCallSink for FailingLogSink {
    async fn call(&self, _run_id: &str, _c: HostCall) -> HostCallResult {
        HostCallResult::Ok(Value::Null)
    }

    fn log(&self, _run_id: &str, _line: &str) {
        std::panic::resume_unwind(Box::new("the sink failed"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_outcome_kills_the_worker() -> TestResult {
    // m-5: the reader thread ended without an outcome; the worker is killed at once, not at
    // `timeout_s`.
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.log("boom")?;
        w.until_killed()
    });
    let handle = start(
        spawner,
        expect(false),
        init(ScriptLimits::default()),
        Arc::new(FailingLogSink),
    )
    .await??;
    let outcome = tokio::time::timeout(WAIT_BOUND, handle.wait()).await?;
    assert_eq!(outcome.diag, vec![DIAG_OUTCOME_LOST]);
    assert_eq!(outcome.host, HostVerdict::Crashed(None));
    observed.wait_finished_within(Duration::from_secs(10))?;
    assert_eq!(observed.signals(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_ends_before_ready_is_unexpected_eof() -> TestResult {
    let (spawner, observed) = fake(|_| Ok(0));
    let refused = start(
        spawner,
        expect(false),
        init(ScriptLimits::default()),
        sink(),
    )
    .await?;
    assert_eq!(
        refused.err(),
        Some(StartRunError::Spawn(io::ErrorKind::UnexpectedEof))
    );
    observed.wait_finished()?;
    assert!(observed.received().is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_first_frame_is_invalid_data() -> TestResult {
    // A first frame that is no `probe.ready`, and one above the 1 MiB cap (no body byte read).
    let not_ready: Script = Box::new(|w| {
        w.log("first")?;
        w.until_killed()
    });
    let oversize: Script = Box::new(|w| {
        w.send_raw(&(MIB as u32 + 1).to_be_bytes())?;
        w.until_killed()
    });
    for script in [not_ready, oversize] {
        let (spawner, observed) = fake(script);
        let refused = start(
            spawner,
            expect(false),
            init(ScriptLimits::default()),
            sink(),
        )
        .await?;
        assert_eq!(
            refused.err(),
            Some(StartRunError::Spawn(io::ErrorKind::InvalidData))
        );
        observed.wait_finished()?;
        assert!(observed.received().is_empty());
        assert_eq!(observed.signals(), 1);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_reap_is_reported() -> TestResult {
    let opts = FakeOpts {
        reap_fails: true,
        ..FakeOpts::default()
    };
    let (spawner, _) = fake_opts(opts, |w| {
        w.ready()?;
        w.read()?;
        Ok(5)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(
        outcome.host,
        HostVerdict::Crashed(None),
        "the exit is unknown"
    );
    assert_eq!(outcome.diag, vec![DIAG_REAP_FAILED]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_result_above_the_host_cap_is_rejected_and_logged() -> TestResult {
    // Deviation 9 (unreachable while `max_call_result_mb` <= 16): the worker sees the rejection,
    // and the diag tells the glue that core recorded a result the worker never got.
    let (spawner, _) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.call(1)?;
        let answer = w.read()?.ok_or_else(|| io::Error::other("no answer"))?;
        assert_eq!(answer["result"]["rejected"]["class"], "result_too_large");
        w.result("1")?;
        Ok(0)
    });
    let outcome = run_to_end(
        spawner,
        ScriptLimits::default(),
        TestSink::padded(HOST_TO_WORKER_MAX),
    )
    .await?;
    assert_eq!(result_text(&outcome), Some("1"));
    assert_eq!(outcome.diag, vec![DIAG_CALL_RESULT_REPLACED]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unread_results_beyond_the_cap_are_a_violation() -> TestResult {
    // T8 finding 1 (T7 review m-6): the answers to a worker that never reads its stdin queue for
    // the writer. Above `max_fetch_mb` plus one frame of unwritten bytes the run ends as a
    // violation with one kill, never as a queue that grows until `timeout_s`.
    let limits = limits_with(|l| {
        l.max_fetch_mb = 1;
        l.max_concurrent_calls = 16;
    });
    assert_eq!(unread_results_cap(&limits), MIB + HOST_TO_WORKER_MAX);
    // 16 answers of 2 MiB: the 13th goes above the 25 MiB cap.
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?; // script.run; nothing after it is ever read
        for id in 1..=16 {
            w.call(id)?;
        }
        w.until_killed()
    });
    let outcome = run_to_end(spawner, limits, TestSink::padded(2 * MIB)).await?;
    assert_eq!(
        outcome.host,
        HostVerdict::Violation(ViolationKind::UnreadResults)
    );
    assert_eq!(outcome.end, WorkerEnd::None);
    assert_eq!(outcome.diag, vec![DIAG_UNREAD_RESULTS]);
    assert_eq!(observed.signals(), 1);

    // The cap counts bytes not yet written, not bytes ever sent: a worker that reads each answer
    // gets far more than the cap over the run.
    let (spawner, _) = fake(|w| {
        w.ready()?;
        w.read()?;
        for id in 1..=16 {
            w.call(id)?;
            w.read()?.ok_or_else(|| io::Error::other("no answer"))?;
        }
        w.result("16")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, limits, TestSink::padded(2 * MIB)).await?;
    assert_eq!(outcome.host, HostVerdict::None);
    assert_eq!(result_text(&outcome), Some("16"));
    assert!(outcome.diag.is_empty(), "{:?}", outcome.diag);
    Ok(())
}

// ---- host-measured memory limits (M8 Task 9, PD-134) ---------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn limit_exit_codes_are_heap_and_process_limits() -> TestResult {
    // The worker's own exit after a refused allocation, no terminal frame, no kill.
    for (code, limit) in [(102, "heap_mb"), (103, "process_mb")] {
        let (spawner, observed) = fake(move |w| {
            w.ready()?;
            w.read()?;
            w.log("growing")?;
            Ok(code)
        });
        let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
        assert_eq!(outcome.host, HostVerdict::Limit(limit), "exit {code}");
        assert_eq!(outcome.end, WorkerEnd::None);
        assert!(outcome.diag.is_empty(), "{:?}", outcome.diag);
        assert_eq!(observed.signals(), 0, "the worker ended on its own");
    }
    // After an accepted terminal frame the exit code no longer matters.
    let (spawner, _) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.result("7")?;
        Ok(102)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(outcome.host, HostVerdict::None);
    assert_eq!(result_text(&outcome), Some("7"));
    Ok(())
}

fn watched(signal: OsMemorySignal) -> FakeOpts {
    FakeOpts {
        watch: Some(signal),
        ..FakeOpts::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_os_memory_report_is_process_mb_and_kills() -> TestResult {
    // The Windows job message and the macOS watchdog's reading: the host decides `process_mb`
    // and kills; the watch stops only after the reap.
    for (signal, fact) in [
        (OsMemorySignal::JobMemoryLimit, DIAG_JOB_MEMORY_LIMIT),
        (OsMemorySignal::WatchdogKill, DIAG_WATCHDOG_KILL),
    ] {
        let (spawner, observed) = fake_opts(watched(signal), |w| {
            w.ready()?;
            w.read()?;
            w.os_memory_report()?;
            w.until_killed()
        });
        let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
        assert_eq!(outcome.host, HostVerdict::Limit("process_mb"), "{signal:?}");
        assert_eq!(outcome.end, WorkerEnd::None);
        assert_eq!(outcome.diag, vec![fact]);
        assert_eq!(observed.signals(), 1);
        assert_eq!(
            observed.watch_stopped_after_reap(),
            Some(true),
            "the watch stops at the reap"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminal_already_in_the_pipe_wins_over_an_os_memory_report() -> TestResult {
    // T9 review I-2: the worker wrote a log, a call and its result, then the OS reported it above
    // the limit before the host read past the log (the sink holds the reader in that log until
    // the report's kill reached the fake, which comes after the report is recorded). The report
    // kills, but the terminal read after it decides the run: no verdict, the result stands, the
    // report stays a diag fact. The call read after the report is not dispatched.
    let (spawner, observed) = fake_opts(watched(OsMemorySignal::WatchdogKill), |w| {
        w.ready()?;
        w.read()?;
        let mut tail = framed(&log_frame("first"));
        tail.extend(framed(&call_frame(1)));
        tail.extend(framed(result_frame("1").as_bytes()));
        w.send_raw(&tail)?;
        w.os_memory_report()?;
        w.until_killed()
    });
    let seen = Arc::clone(&observed);
    let gated = GatedLogSink::new(move || seen.kill_calls() > 0, Duration::ZERO);
    let outcome = run_to_end(spawner, ScriptLimits::default(), gated.clone()).await?;
    assert_eq!(outcome.host, HostVerdict::None, "{outcome:?}");
    assert_eq!(result_text(&outcome), Some("1"));
    assert_eq!(outcome.logs, vec!["first".to_string()]);
    assert_eq!(outcome.diag, vec![DIAG_WATCHDOG_KILL]);
    assert_eq!(observed.signals(), 1, "the report's kill");
    assert_eq!(gated.calls(), 0, "no call after the report");
    observed.wait_finished()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_os_memory_report_after_the_terminal_is_ignored() -> TestResult {
    // Rule 2 before rule 4: the result stands; the report stays a fact in the diag. The report
    // comes once the host accepted the terminal (its kill reached the fake), before the exit.
    let (spawner, observed) = fake_opts(watched(OsMemorySignal::JobMemoryLimit), |w| {
        w.ready()?;
        w.read()?;
        w.result("5")?;
        let started = Instant::now();
        while !w.observed.is_killed() && started.elapsed() < WAIT_BOUND {
            thread::sleep(Duration::from_millis(2));
        }
        w.os_memory_report()?;
        Err(killed_error())
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(outcome.host, HostVerdict::None);
    assert_eq!(result_text(&outcome), Some("5"));
    assert_eq!(outcome.diag, vec![DIAG_JOB_MEMORY_LIMIT]);
    assert_eq!(observed.signals(), 1, "the terminal's kill");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_memory_watch_that_cannot_observe_is_reported() -> TestResult {
    let opts = FakeOpts {
        watch_fails: true,
        ..watched(OsMemorySignal::WatchdogKill)
    };
    let (spawner, _) = fake_opts(opts, |w| {
        w.ready()?;
        w.read()?;
        w.result("3")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(outcome.host, HostVerdict::None);
    assert_eq!(result_text(&outcome), Some("3"));
    assert_eq!(outcome.diag, vec![DIAG_MEMORY_WATCH_FAILED]);

    // A watched run that ends normally carries no memory diag, and the watch stopped at the reap.
    let (spawner, observed) = fake_opts(watched(OsMemorySignal::JobMemoryLimit), |w| {
        w.ready()?;
        w.read()?;
        w.result("4")?;
        Ok(0)
    });
    let outcome = run_to_end(spawner, ScriptLimits::default(), sink()).await?;
    assert_eq!(result_text(&outcome), Some("4"));
    assert!(outcome.diag.is_empty(), "{:?}", outcome.diag);
    assert_eq!(observed.watch_stopped_after_reap(), Some(true));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_outcome_does_not_wait_for_a_stdout_held_past_the_exit() -> TestResult {
    // T7 review m-3: a (degraded) worker forks a child that holds its stdout and exits. The
    // outcome is published STDOUT_GRACE after the reap, and a frame the child sends later is
    // ignored.
    // The child writes its frame only once the outcome is out (no timing race with the grace).
    let hold = Duration::from_secs(20);
    let (published_tx, published_rx) = mpsc::channel();
    let (written_tx, written_rx) = mpsc::channel();
    let (spawner, _) = fake(move |w| {
        w.ready()?;
        w.read()?;
        let written = w.fork_child_holding_stdout(published_rx, hold);
        thread::spawn(move || {
            if written.recv_timeout(WAIT_BOUND).is_ok() {
                let _ = written_tx.send(());
            }
        });
        Ok(0)
    });
    let test_sink = sink();
    let handle = start(
        spawner,
        expect(false),
        init(ScriptLimits::default()),
        test_sink.clone(),
    )
    .await??;
    let started = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(10), handle.wait()).await?;
    let took = started.elapsed();
    assert!(took < hold, "published before the child let go ({took:?})");
    let _ = published_tx.send(());
    assert_eq!(outcome.host, HostVerdict::Crashed(Some(ExitKind::Code(0))));
    assert_eq!(outcome.diag, vec![DIAG_STDOUT_HELD], "after {took:?}");
    let written = tokio::task::spawn_blocking(move || written_rx.recv_timeout(WAIT_BOUND)).await?;
    assert!(written.is_ok(), "the child wrote its late frame");
    // The child closed the pipe after its frame, so the reader read that frame, reached EOF and
    // ended; once every thread and task of the run let go of the sink, the frame was read and
    // ignored, not merely not read yet (T9 review m-4).
    drop(handle);
    eventually(|| Arc::strong_count(&test_sink) == 1).await?;
    assert!(test_sink.logs().is_empty(), "{:?}", test_sink.logs());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_outcome_does_not_wait_for_a_stdin_held_past_the_exit() -> TestResult {
    // M8 fuzz fix, review M-2: a (degraded) worker forks a child that holds its stdin without
    // reading it and exits, while an answer is queued for it. The writer stays blocked, so the
    // outcome is published WRITER_GRACE after the reap, with the diag.
    let hold = Duration::from_secs(20);
    let (release_tx, release_rx) = mpsc::channel();
    let sink = TestSink::padded(2 * MIB);
    let seen = Arc::clone(&sink);
    let (spawner, _) = fake(move |w| {
        w.ready()?;
        w.read()?; // script.run; nothing after it is ever read
        w.fork_child_holding_stdin(release_rx, hold)?;
        w.call(1)?;
        // The answer (2 MiB, more than the pipe holds) is queued once the sink completed it.
        let started = Instant::now();
        while seen.completed() < 1 && started.elapsed() < WAIT_BOUND {
            thread::sleep(Duration::from_millis(2));
        }
        thread::sleep(Duration::from_millis(500));
        Ok(0)
    });
    let handle = start(spawner, expect(false), init(ScriptLimits::default()), sink).await??;
    let started = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(10), handle.wait()).await?;
    let took = started.elapsed();
    let _ = release_tx.send(());
    assert!(took < hold, "published before the child let go ({took:?})");
    assert_eq!(outcome.host, HostVerdict::Crashed(Some(ExitKind::Code(0))));
    assert_eq!(outcome.diag, vec![DIAG_STDIN_HELD], "after {took:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_timer_expiring_after_the_reap_does_not_replace_the_exit() -> TestResult {
    // T9 review m-2: the worker exits 102 at once (well within its 1 s `timeout_s`) and leaves a
    // child holding its stdout, so the outcome comes STDOUT_GRACE after the reap. The timer
    // expires in between; the worker is gone by then, so its own exit decides.
    let (go_tx, go_rx) = mpsc::channel();
    let (spawner, observed) = fake(move |w| {
        w.ready()?;
        w.read()?;
        let _written = w.fork_child_holding_stdout(go_rx, WAIT_BOUND);
        Ok(102)
    });
    let one_second = limits_with(|l| l.timeout_s = 1);
    let outcome = run_to_end(spawner, one_second, sink()).await?;
    let _ = go_tx.send(());
    assert_eq!(outcome.host, HostVerdict::Limit("heap_mb"), "{outcome:?}");
    assert_eq!(outcome.diag, vec![DIAG_STDOUT_HELD]);
    assert_eq!(observed.signals(), 0, "the worker ended on its own");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_still_draining_after_the_reap_keeps_the_result() -> TestResult {
    // T9 review I-1: the worker wrote its tail (log lines, a call, the result; about 2 KiB, so it
    // fits any pipe buffer and the worker exits at once) and exited. The glue's `log` is slow,
    // and the first one is held until the worker ended, so the reader drains for about 3 s past
    // the reap. STDOUT_GRACE counts only while the reader waits on the pipe with nothing
    // arriving, so the result stands. The call, read more than 1 s after the reap, is not
    // dispatched: its result could never reach the worker (T9 review m-3).
    const LINES: usize = 30;
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        let mut tail = framed(&log_frame("first"));
        for i in 1..LINES {
            if i == 15 {
                tail.extend(framed(&call_frame(1)));
            }
            tail.extend(framed(&log_frame(&format!("line {i}"))));
        }
        tail.extend(framed(result_frame("1").as_bytes()));
        w.send_raw(&tail)?;
        Ok(0)
    });
    let seen = Arc::clone(&observed);
    let slow = GatedLogSink::new(
        move || seen.finished.lock().map(|f| *f).unwrap_or(true),
        Duration::from_millis(100),
    );
    let started = Instant::now();
    let outcome = run_to_end(spawner, ScriptLimits::default(), slow.clone()).await?;
    let took = started.elapsed();
    assert_eq!(
        outcome.host,
        HostVerdict::None,
        "after {took:?}: {outcome:?}"
    );
    assert_eq!(result_text(&outcome), Some("1"));
    assert!(outcome.diag.is_empty(), "{:?}", outcome.diag);
    assert_eq!(outcome.logs.len(), LINES);
    assert!(
        took > STDOUT_GRACE,
        "the drain outlasted the grace ({took:?})"
    );
    assert_eq!(
        slow.calls(),
        0,
        "the call read after the reap was not dispatched"
    );
    Ok(())
}
