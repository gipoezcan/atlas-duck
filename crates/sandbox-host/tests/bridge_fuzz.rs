//! M8 Task 8 (§13 S-10 "Sandbox channel fuzzing: malformed, oversize and out-of-order frames",
//! §3.4, §15 V12 worker half): hostile frame sequences against the host bridge, over the same kind
//! of scripted fake worker as `tests/bridge.rs` (a thread behind three in-memory pipes; no process
//! is spawned). The real-worker half (pipe deadlock, handle and environment hygiene) is in
//! `app/src-tauri/tests/sandbox_runs.rs`.
//!
//! A counting global allocator measures what the bridge (and the fake) hold at once: a hostile
//! frame never makes the host hold more than the frame being read plus a fixed allowance, so the
//! claimed length of a frame is never trusted. The tests of this file run one at a time
//! ([`SERIAL`]) so the measured window holds one run only.
//!
//! Every wait is bounded ([`WAIT_BOUND`]): a regression fails instead of hanging.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use atlas_duck_ipc::sandbox::frame::{read_frame, write_frame};
use atlas_duck_ipc::sandbox::probe::{
    ConfinementReport, M_PROBE_READY, ProbeReady, encode_notification,
};
use atlas_duck_ipc::sandbox::script::{
    ErrorParams, LogParams, M_HOST_CALL, M_HOST_LOG, M_SCRIPT_ERROR, WorkerInit, encode_request,
};
use atlas_duck_ipc::sandbox::{
    HOST_TO_WORKER_MAX, HostCall, HostCallResult, ScriptLimits, terminal_frame_max,
};
use atlas_duck_sandbox_host::bridge::{
    DIAG_UNREAD_RESULTS, ExpectedWorker, HostCallSink, HostVerdict, LOG_CAP_BYTES, LOG_CAP_LINES,
    RunOutcome, ViolationKind, WorkerEnd, log_truncated_marker, start_run, unread_results_cap,
};
use atlas_duck_sandbox_host::identity::{FileId, SandboxBinaryIdentity};
use atlas_duck_sandbox_host::kill::{GuardedKill, ReapGuard, reap_after_wait};
use atlas_duck_sandbox_host::spawn::{
    ExitKind, KillHandle, Reaper, SpawnSpec, WorkerIo, WorkerParts, WorkerProcess, WorkerSpawner,
};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Upper bound for every wait in this file.
const WAIT_BOUND: Duration = Duration::from_secs(30);
/// The embedded version the fake reports and the expected identity records.
const VERSION: &str = "fake-build-1";
const MIB: usize = 1024 * 1024;
/// `max_result_mb` the oversize cases use (a small terminal cap keeps the frames cheap).
const RESULT_MB: u32 = 1;

// ---- memory measurement ----------------------------------------------------------------------

/// Counts the live heap bytes of the whole test process and their peak.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let now = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

// SAFETY: every method forwards to `System` with the caller's layout and pointer, unchanged; the
// counters only observe the sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is `System`'s contract.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is `System`'s contract.
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: `ptr` and `layout` are the pair the caller got from this allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `ptr` and `layout` are the pair the caller got from this allocator.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Runs `f` and returns its value with the most heap (bytes) that was live at once above the
/// level at the start.
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let value = f();
    let peak = PEAK.load(Ordering::Relaxed);
    (value, peak.saturating_sub(base))
}

/// What the host may hold above the frame being read: the fake's own copy of the frame, the
/// decoder's transient copies, the logs and the stderr head (all capped), the threads' channels.
const HELD_ALLOWANCE: usize = 8 * MIB;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---- the fake worker (the harness of tests/bridge.rs, reduced to what S-10 uses) --------------

#[derive(Default)]
struct Observed {
    killed: Mutex<bool>,
    killed_cv: Condvar,
    /// Signals the kill handle sent.
    signals: AtomicU32,
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

/// The worker side of the three pipes.
struct FakeWorker {
    stdin: io::PipeReader,
    stdout: io::PipeWriter,
    /// Held so the host's stderr thread sees EOF only when the fake dies.
    _stderr: io::PipeWriter,
    observed: Arc<Observed>,
}

fn killed_error() -> io::Error {
    io::Error::other("killed")
}

impl FakeWorker {
    fn ready(&mut self) -> io::Result<()> {
        let ready = ProbeReady {
            worker_version: VERSION.to_string(),
            engine_version: "fake-engine".to_string(),
            confinement: report(),
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

    /// Raw bytes (headers and bodies as the test built them), unless the fake was killed.
    fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.observed.is_killed() {
            return Err(killed_error());
        }
        self.stdout.write_all(bytes)?;
        self.stdout.flush()
    }

    /// Reads one host frame; `None` at stdin EOF.
    fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
        read_frame(&mut self.stdin, HOST_TO_WORKER_MAX).map_err(|e| io::Error::other(e.to_string()))
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
}

fn fake(
    script: impl FnOnce(&mut FakeWorker) -> io::Result<i32> + Send + 'static,
) -> (Arc<FakeSpawner>, Arc<Observed>) {
    let observed = Arc::new(Observed::default());
    let spawner = FakeSpawner {
        script: Mutex::new(Some(Box::new(script))),
        observed: Arc::clone(&observed),
    };
    (Arc::new(spawner), observed)
}

/// Counts nothing: the kill handle of the fake, built from the crate's guard like the spawners'.
struct FakeKill {
    inner: GuardedKill,
}

impl KillHandle for FakeKill {
    fn kill(&self) {
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
        let (stdin_r, stdin_w) = io::pipe()?;
        let (stdout_r, stdout_w) = io::pipe()?;
        let (stderr_r, stderr_w) = io::pipe()?;
        let (exit_tx, exit_rx) = mpsc::channel();
        let mut worker = FakeWorker {
            stdin: stdin_r,
            stdout: stdout_w,
            _stderr: stderr_w,
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
        }))
    }
}

struct FakeProcess {
    stdin: io::PipeWriter,
    stdout: io::PipeReader,
    stderr: io::PipeReader,
    exit: Receiver<i32>,
    observed: Arc<Observed>,
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
        Ok(WorkerParts {
            pid: 4242,
            io: WorkerIo {
                stdin: Box::new(self.stdin),
                stdout: Box::new(self.stdout),
                stderr: Box::new(self.stderr),
            },
            kill: Arc::new(FakeKill { inner }),
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

// ---- frames ------------------------------------------------------------------------------------

fn framed(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

fn call_frame(id: u64) -> Vec<u8> {
    call_frame_in(id, id)
}

/// A `host.call` whose JSON-RPC id is `envelope` and whose `HostCall.id` is `inner`.
fn call_frame_in(envelope: u64, inner: u64) -> Vec<u8> {
    let call = HostCall {
        id: inner,
        op_id: "jira.issue.get".to_string(),
        params: json!({"key": "ABC-1"}),
        instance: None,
        all: false,
    };
    encode_request(M_HOST_CALL, envelope, &call)
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

// ---- host side ----------------------------------------------------------------------------------

fn report() -> ConfinementReport {
    ConfinementReport {
        applied: true,
        mechanism: "fake-confined".to_string(),
        no_new_privs: None,
        landlock_abi: None,
        seccomp: None,
        lpac: Some(true),
        os_error: None,
    }
}

fn expect() -> ExpectedWorker {
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
        accept_unconfined: false,
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

fn limits_with(f: impl FnOnce(&mut ScriptLimits)) -> ScriptLimits {
    let mut l = ScriptLimits::default();
    f(&mut l);
    l
}

/// Records calls and logs; optionally holds every call until released, and pads each result.
#[derive(Default)]
struct TestSink {
    calls: Mutex<Vec<u64>>,
    logs: Mutex<Vec<String>>,
    completed: AtomicU32,
    gate: Option<Arc<tokio::sync::Semaphore>>,
    pad: usize,
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

    /// The ids the sink saw, in id order (each call runs as its own task, so the order in which
    /// they arrive is not the order of the frames).
    fn calls(&self) -> Vec<u64> {
        let mut calls = self.calls.lock().map(|c| c.clone()).unwrap_or_default();
        calls.sort_unstable();
        calls
    }

    /// Calls whose answer is ready (about to be queued for the worker).
    fn completed(&self) -> u32 {
        self.completed.load(Ordering::SeqCst)
    }

    fn log_count(&self) -> usize {
        self.logs.lock().map(|l| l.len()).unwrap_or_default()
    }
}

#[async_trait]
impl HostCallSink for TestSink {
    async fn call(&self, _run_id: &str, c: HostCall) -> HostCallResult {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(c.id);
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

fn runtime() -> Result<tokio::runtime::Runtime, io::Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
}

/// Starts a run on the calling thread (as the glue does through `spawn_blocking`) and waits for
/// its end, bounded.
fn run_to_end(
    rt: &tokio::runtime::Runtime,
    spawner: &Arc<FakeSpawner>,
    limits: ScriptLimits,
    sink: Arc<dyn HostCallSink>,
) -> Result<RunOutcome, String> {
    let handle = start_run(
        spawner.as_ref(),
        &spec(),
        &expect(),
        init(limits),
        sink,
        rt.handle().clone(),
    )
    .map_err(|e| e.to_string())?;
    rt.block_on(async { tokio::time::timeout(WAIT_BOUND, handle.wait()).await })
        .map_err(|_| "the run never ended".to_string())
}

// ---- the attacks ---------------------------------------------------------------------------------

/// One hostile behaviour of the worker after its `script.run` arrived.
#[derive(Debug, Clone)]
enum Attack {
    /// A frame of arbitrary bytes.
    RandomBytes(Vec<u8>),
    /// A `host.log` frame whose line holds bytes that are not UTF-8.
    InvalidUtf8 { head: Vec<u8>, tail: Vec<u8> },
    /// A well-formed notification of a method the worker may not send.
    UnknownMethod(String),
    /// 1 to 3 bytes of a length prefix, then the worker ends.
    TruncatedPrefix(Vec<u8>),
    /// A header that claims `claimed` bytes, `sent` of them (fewer) follow, then the worker ends.
    TruncatedBody { claimed: usize, sent: usize },
    /// A `host.log` frame of 1 MiB + 1 bytes.
    OversizeLog,
    /// A `script.result` frame of the terminal cap + 1 bytes.
    OversizeTerminal,
    /// Only a length header above every cap; no body follows.
    HugeHeader(u32),
    /// `host.call` frames whose ids are not strictly increasing.
    ReorderedIds(Vec<u64>),
    /// A `host.call` whose JSON-RPC id differs from its `HostCall.id`.
    IdMismatch { envelope: u64, inner: u64 },
    /// Two terminal frames in one write.
    TwoTerminals {
        first_result: bool,
        second_result: bool,
    },
    /// A JSON-RPC response from the worker.
    WorkerResponse(u64),
}

/// What the host must conclude.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// The bridge killed the worker for a channel violation (of this kind, if known).
    Violation(Option<ViolationKind>),
    /// The stream ended inside a frame: a truncated frame is EOF (T7 deviation 7), so the exit
    /// decides and the run counts as a crash, never as a result.
    Eof,
}

impl Attack {
    fn verdict(&self) -> Verdict {
        use ViolationKind::*;
        let kind = match self {
            Attack::RandomBytes(_) => None,
            Attack::InvalidUtf8 { .. } => Some(Malformed),
            Attack::UnknownMethod(_) => Some(UnknownMethod),
            Attack::TruncatedPrefix(_) | Attack::TruncatedBody { .. } => return Verdict::Eof,
            Attack::OversizeLog | Attack::OversizeTerminal | Attack::HugeHeader(_) => {
                Some(Oversize)
            }
            Attack::ReorderedIds(_) => Some(IdNotIncreasing),
            Attack::IdMismatch { .. } => Some(IdMismatch),
            Attack::TwoTerminals { .. } => Some(SecondTerminal),
            Attack::WorkerResponse(_) => Some(WorkerResponse),
        };
        Verdict::Violation(kind)
    }

    /// The limits the run is started with.
    fn limits(&self) -> ScriptLimits {
        match self {
            Attack::OversizeTerminal | Attack::HugeHeader(_) => {
                limits_with(|l| l.max_result_mb = RESULT_MB)
            }
            _ => ScriptLimits::default(),
        }
    }

    /// The largest frame the host reads whole for this attack: what it may hold besides the
    /// allowance.
    fn frame_held(&self) -> usize {
        match self {
            Attack::OversizeLog => MIB,
            Attack::OversizeTerminal => terminal_frame_max(&self.limits()),
            _ => 0,
        }
    }

    /// The fake worker's behaviour.
    fn script(&self) -> Script {
        let attack = self.clone();
        let limits = self.limits();
        Box::new(move |w| {
            w.ready()?;
            w.read()?; // script.run
            match attack {
                Attack::RandomBytes(b) => w.send(&b)?,
                Attack::InvalidUtf8 { head, tail } => {
                    let mut line =
                        br#"{"jsonrpc":"2.0","method":"host.log","params":{"line":""#.to_vec();
                    line.extend(head);
                    line.push(0xff);
                    line.extend(tail);
                    line.extend(br#""}}"#);
                    w.send(&line)?;
                }
                Attack::UnknownMethod(m) => {
                    let frame = json!({"jsonrpc": "2.0", "method": m, "params": {}});
                    w.send(frame.to_string().as_bytes())?;
                }
                Attack::TruncatedPrefix(prefix) => {
                    w.send_raw(&prefix)?;
                    return Ok(0);
                }
                Attack::TruncatedBody { claimed, sent } => {
                    let mut bytes = (claimed as u32).to_be_bytes().to_vec();
                    bytes.extend(std::iter::repeat_n(b'{', sent));
                    w.send_raw(&bytes)?;
                    return Ok(0);
                }
                Attack::OversizeLog => {
                    let empty = log_frame("").len();
                    let frame = log_frame(&"o".repeat(MIB + 1 - empty));
                    w.send(&frame)?;
                }
                Attack::OversizeTerminal => {
                    w.send(&result_frame_of_len(terminal_frame_max(&limits) + 1))?;
                }
                Attack::HugeHeader(h) => w.send_raw(&h.to_be_bytes())?,
                Attack::ReorderedIds(ids) => {
                    for id in ids {
                        w.send(&call_frame(id))?;
                    }
                }
                Attack::IdMismatch { envelope, inner } => {
                    w.send(&call_frame_in(envelope, inner))?;
                }
                Attack::TwoTerminals {
                    first_result,
                    second_result,
                } => {
                    let terminal = |result: bool| {
                        if result {
                            result_frame("1").into_bytes()
                        } else {
                            error_frame("Error", "x")
                        }
                    };
                    let mut bytes = framed(&terminal(first_result));
                    bytes.extend(framed(&terminal(second_result)));
                    w.send_raw(&bytes)?;
                    while w.read()?.is_some() {}
                    return Ok(0);
                }
                Attack::WorkerResponse(id) => {
                    let frame = json!({"jsonrpc": "2.0", "id": id, "result": {"ok": 1}});
                    w.send(frame.to_string().as_bytes())?;
                }
            }
            w.until_killed()
        })
    }
}

fn first_non_increasing(ids: &[u64]) -> bool {
    ids.windows(2).any(|w| w[1] <= w[0])
}

fn attack() -> impl Strategy<Value = Attack> {
    // The caps a header must exceed: the terminal cap of `RESULT_MB`.
    let cap = terminal_frame_max(&limits_with(|l| l.max_result_mb = RESULT_MB)) as u32;
    prop_oneof![
        8 => vec(any::<u8>(), 0..512).prop_map(Attack::RandomBytes),
        // ASCII from '#' to '[': no quote and no backslash, so only the 0xff makes the line invalid.
        4 => (vec(0x23u8..0x5c, 0..64), vec(0x23u8..0x5c, 0..64))
            .prop_map(|(head, tail)| Attack::InvalidUtf8 { head, tail }),
        4 => "x[a-z]{0,6}\\.[a-z]{1,8}".prop_map(Attack::UnknownMethod),
        4 => vec(any::<u8>(), 1..=3).prop_map(Attack::TruncatedPrefix),
        4 => (1usize..4096).prop_flat_map(|claimed| (Just(claimed), 0..claimed))
            .prop_map(|(claimed, sent)| Attack::TruncatedBody { claimed, sent }),
        1 => Just(Attack::OversizeLog),
        1 => Just(Attack::OversizeTerminal),
        2 => ((cap + 1)..=u32::MAX).prop_map(Attack::HugeHeader),
        6 => vec(1u64..50, 2..=4)
            .prop_filter("not strictly increasing", |ids| first_non_increasing(ids))
            .prop_map(Attack::ReorderedIds),
        3 => (1u64..50, 1u64..50)
            .prop_filter("ids differ", |(a, b)| a != b)
            .prop_map(|(envelope, inner)| Attack::IdMismatch { envelope, inner }),
        3 => (any::<bool>(), any::<bool>())
            .prop_map(|(first_result, second_result)| Attack::TwoTerminals { first_result, second_result }),
        2 => (0u64..100).prop_map(Attack::WorkerResponse),
    ]
}

/// Runs `attack` and returns the outcome, the fake's observations and the heap it peaked at.
fn play(
    rt: &tokio::runtime::Runtime,
    attack: &Attack,
) -> Result<(RunOutcome, Arc<Observed>, usize), String> {
    let script = attack.script();
    let (spawner, observed) = fake(script);
    let sink: Arc<dyn HostCallSink> = Arc::new(TestSink::default());
    let (outcome, held) = measure(|| run_to_end(rt, &spawner, attack.limits(), sink));
    Ok((outcome?, observed, held))
}

fn check(rt: &tokio::runtime::Runtime, attack: &Attack) -> Result<(), TestCaseError> {
    let (outcome, observed, held) = play(rt, attack).map_err(TestCaseError::fail)?;
    let shown = format!("{attack:?}");
    let shown = &shown[..shown.len().min(200)];
    if !matches!(attack, Attack::TwoTerminals { .. }) {
        // The first terminal of two is kept (the second one is the violation).
        prop_assert_eq!(&outcome.end, &WorkerEnd::None, "{}", shown);
    }
    match attack.verdict() {
        Verdict::Violation(kind) => {
            match (&outcome.host, kind) {
                (HostVerdict::Violation(got), Some(want)) => {
                    prop_assert_eq!(*got, want, "{}", shown)
                }
                (HostVerdict::Violation(_), None) => {}
                (other, _) => prop_assert!(false, "{shown}: host verdict {other:?}"),
            }
            prop_assert_eq!(observed.signals(), 1, "one kill: {}", shown);
        }
        Verdict::Eof => {
            prop_assert!(
                matches!(outcome.host, HostVerdict::Crashed(_)),
                "{shown}: host verdict {:?}",
                outcome.host
            );
        }
    }
    observed.wait_finished().map_err(TestCaseError::fail)?;
    // §3.4: the host never holds more than the frame being read (plus the fixed allowance); a
    // claimed length (`HugeHeader`, `TruncatedBody`) is never allocated.
    let allowed = attack.frame_held() + HELD_ALLOWANCE;
    prop_assert!(
        held <= allowed,
        "{shown}: the run held {held} bytes at once, allowed {allowed}"
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn s10_malformed_oversize_out_of_order_frames_end_in_violation(attack in attack()) {
        let _serial = serial();
        let rt = runtime().map_err(|e| TestCaseError::fail(e.to_string()))?;
        check(&rt, &attack)?;
    }
}

// ---- floods ------------------------------------------------------------------------------------

/// 10 000 log lines of 200 bytes (§13 S-10): the byte cap bites first (1 MiB = 5 242 whole
/// lines); the run still ends with its result and the host holds the capped logs only.
#[test]
fn s10_log_flood_stays_within_caps() -> TestResult {
    let _serial = serial();
    let rt = runtime()?;
    assert_eq!((LOG_CAP_BYTES, LOG_CAP_LINES), (MIB, 10_000));
    let line = "l".repeat(200);
    let (spawner, observed) = fake(move |w| {
        w.ready()?;
        w.read()?;
        for _ in 0..10_000 {
            w.send(&log_frame(&line))?;
        }
        w.send(result_frame("null").as_bytes())?;
        while w.read()?.is_some() {}
        Ok(0)
    });
    let sink = Arc::new(TestSink::default());
    let (outcome, held) =
        measure(|| run_to_end(&rt, &spawner, ScriptLimits::default(), sink.clone()));
    let outcome = outcome?;
    assert_eq!(outcome.host, HostVerdict::None);
    let kept = LOG_CAP_BYTES / 200;
    assert_eq!(kept, 5_242);
    assert_eq!(
        outcome.logs.len(),
        kept + 1,
        "the kept lines and the marker"
    );
    let discarded = (10_000 - kept as u64) * 200;
    assert_eq!(outcome.logs_truncated, Some(discarded));
    assert_eq!(outcome.logs.last(), Some(&log_truncated_marker(discarded)));
    assert_eq!(sink.log_count(), kept, "the sink sees kept lines only");
    observed.wait_finished()?;
    // The capped logs live in the outcome, in the sink and in the run state: a few MiB.
    assert!(held <= HELD_ALLOWANCE + 3 * LOG_CAP_BYTES, "held {held}");
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    /// Any flood of lines: the kept lines never exceed either cap, the rest is counted, and the
    /// run's result arrives.
    #[test]
    fn s10_log_flood_counts_what_it_discards(lines in 1usize..12_000, len in 0usize..400) {
        let _serial = serial();
        let rt = runtime().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let line = "f".repeat(len);
        let (spawner, observed) = fake(move |w| {
            w.ready()?;
            w.read()?;
            let frame = log_frame(&line);
            for _ in 0..lines {
                w.send(&frame)?;
            }
            w.send(result_frame("1").as_bytes())?;
            while w.read()?.is_some() {}
            Ok(0)
        });
        let outcome = run_to_end(&rt, &spawner, ScriptLimits::default(), Arc::new(TestSink::default()))
            .map_err(TestCaseError::fail)?;
        prop_assert_eq!(&outcome.host, &HostVerdict::None);
        let truncated = outcome.logs_truncated.unwrap_or(0);
        let kept_lines = outcome.logs.len() - usize::from(outcome.logs_truncated.is_some());
        prop_assert!(kept_lines <= LOG_CAP_LINES);
        prop_assert!(kept_lines * len <= LOG_CAP_BYTES);
        // Kept plus discarded is what was offered.
        prop_assert_eq!(kept_lines as u64 * len as u64 + truncated, lines as u64 * len as u64);
        observed.wait_finished().map_err(TestCaseError::fail)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// A flood of `host.call` frames the worker never waits for: the call beyond
    /// `max_concurrent_calls` is a violation, and the sink never saw more than the limit.
    #[test]
    fn s10_host_call_flood_is_violation(max in 1u32..=8, extra in 1u64..=300) {
        let _serial = serial();
        let rt = runtime().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let total = u64::from(max) + extra;
        let (spawner, observed) = fake(move |w| {
            w.ready()?;
            w.read()?;
            // All frames in one write: they are in the pipe before the host reacts.
            let mut bytes = Vec::new();
            for id in 1..=total {
                bytes.extend(framed(&call_frame(id)));
            }
            w.send_raw(&bytes)?;
            w.until_killed()
        });
        let (sink, gate) = TestSink::gated();
        let outcome = run_to_end(
            &rt,
            &spawner,
            limits_with(|l| l.max_concurrent_calls = max),
            sink.clone(),
        )
        .map_err(TestCaseError::fail)?;
        gate.add_permits(total as usize);
        prop_assert_eq!(
            &outcome.host,
            &HostVerdict::Violation(ViolationKind::TooManyCalls)
        );
        prop_assert_eq!(&outcome.end, &WorkerEnd::None);
        prop_assert_eq!(observed.signals(), 1);
        // Only the calls within the limit reached the sink; the rest of the flood was discarded.
        // The calls run as tasks of their own, which may not have started when the run ended.
        let started = Instant::now();
        while sink.calls().len() < max as usize && started.elapsed() < WAIT_BOUND {
            thread::sleep(Duration::from_millis(2));
        }
        prop_assert_eq!(sink.calls(), (1..=u64::from(max)).collect::<Vec<_>>());
        observed.wait_finished().map_err(TestCaseError::fail)?;
    }
}

/// T7 review m-6: the worker never reads its stdin while the host answers a flood of calls. The
/// writer blocks on the full pipe; the reader keeps decoding (every call reaches the sink), and
/// the run ends at `timeout_s` with a kill, never as a deadlock. The 32 MiB of answers stay below
/// the default unread-results cap (`max_fetch_mb` 50 MiB plus one 24 MiB frame); the cap itself is
/// `s10_unread_results_are_capped`.
///
/// How many calls the fake sends before the timer depends on the runner's speed (a slow macOS
/// runner sent 48 of the 64), so the calls are checked against what the fake reports: every call
/// of a burst the sink answered reached it, nothing the fake did not send did, and at least two
/// bursts were answered (the second one only while the writer was blocked on the first answer).
#[test]
fn s10_worker_that_never_reads_stdin_is_killed_at_the_timer() -> TestResult {
    let _serial = serial();
    let rt = runtime()?;
    const CALLS: u64 = 64;
    const BURST: u64 = 4;
    // Every answer is 512 KiB: the first fills the pipe, the writer blocks, the rest queue.
    let sink = TestSink::padded(512 * 1024);
    let seen = Arc::clone(&sink);
    // The calls the fake sent, and those of the bursts the sink answered before the next one.
    let sent = Arc::new(AtomicU64::new(0));
    let answered = Arc::new(AtomicU64::new(0));
    let (fake_sent, fake_answered) = (Arc::clone(&sent), Arc::clone(&answered));
    let (spawner, observed) = fake(move |w| {
        w.ready()?;
        w.read()?; // script.run; nothing after it is ever read
        // A burst of calls, then wait until the host has answered them (the answers go to the
        // writer queue, which is where they stay), so the calls in flight stay within the limit.
        for burst in 0..CALLS / BURST {
            for id in burst * BURST + 1..=(burst + 1) * BURST {
                w.send(&call_frame(id))?;
                fake_sent.store(id, Ordering::SeqCst);
            }
            let started = Instant::now();
            while u64::from(seen.completed()) < (burst + 1) * BURST {
                if w.observed.is_killed() {
                    return w.until_killed();
                }
                if started.elapsed() > WAIT_BOUND {
                    return Err(io::Error::other("the sink never answered"));
                }
                thread::sleep(Duration::from_millis(2));
            }
            fake_answered.store((burst + 1) * BURST, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(50));
        }
        w.until_killed()
    });
    let (outcome, held) = measure(|| {
        run_to_end(
            &rt,
            &spawner,
            limits_with(|l| {
                l.timeout_s = 2;
                l.max_concurrent_calls = 2 * BURST as u32;
            }),
            sink.clone(),
        )
    });
    let outcome = outcome?;
    assert_eq!(outcome.host, HostVerdict::Limit("timeout_s"));
    assert_eq!(outcome.end, WorkerEnd::None);
    assert_eq!(observed.signals(), 1);
    assert!(
        outcome.elapsed < Duration::from_secs(10),
        "ended by the timer: {:?}",
        outcome.elapsed
    );
    observed.wait_finished()?;

    // The fake has ended: what it sent and saw answered is final. The calls run as tasks of their
    // own, so wait (bounded) until the sink saw every call sent or its list stopped growing.
    let (sent, answered) = (sent.load(Ordering::SeqCst), answered.load(Ordering::SeqCst));
    let started = Instant::now();
    let mut last = (sink.calls().len(), Instant::now());
    while (last.0 as u64) < sent && started.elapsed() < Duration::from_secs(10) {
        thread::sleep(Duration::from_millis(10));
        let len = sink.calls().len();
        if len != last.0 {
            last = (len, Instant::now());
        } else if last.1.elapsed() > Duration::from_millis(500) {
            break;
        }
    }
    let calls = sink.calls();
    assert!(
        answered >= 2 * BURST,
        "only {answered} calls were answered before the timer"
    );
    assert_eq!(
        calls.get(..answered as usize),
        Some((1..=answered).collect::<Vec<_>>().as_slice()),
        "the reader kept decoding while the writer was blocked: {calls:?}"
    );
    assert!(
        calls.windows(2).all(|w| w[0] < w[1]) && calls.iter().all(|&id| id <= sent),
        "the sink saw only the calls sent, once each: sent {sent}, saw {calls:?}"
    );
    println!(
        "S-10 unread_stdin sent={sent} answered={answered} decoded={} answer_bytes={} queued_peak_bytes={held}",
        calls.len(),
        512 * 1024
    );
    Ok(())
}

/// T8 finding 1: the worker of the test above against a cap it reaches. The answers not yet
/// written to the worker stay within `max_fetch_mb` plus one frame: the flood offers twice that,
/// and the run ends as `UnreadResults` with one kill, while the host held about the cap only.
#[test]
fn s10_unread_results_are_capped() -> TestResult {
    let _serial = serial();
    let rt = runtime()?;
    const ANSWER: usize = 512 * 1024;
    const BURST: u64 = 4;
    let limits = limits_with(|l| {
        l.max_fetch_mb = 1;
        l.max_concurrent_calls = 2 * BURST as u32;
    });
    let cap = unread_results_cap(&limits);
    let calls = (2 * cap / ANSWER) as u64;
    let sink = TestSink::padded(ANSWER);
    let seen = Arc::clone(&sink);
    let (spawner, observed) = fake(move |w| {
        w.ready()?;
        w.read()?; // script.run; nothing after it is ever read
        for burst in 0..calls / BURST {
            for id in burst * BURST + 1..=(burst + 1) * BURST {
                w.send(&call_frame(id))?;
            }
            let started = Instant::now();
            while u64::from(seen.completed()) < (burst + 1) * BURST {
                if w.observed.is_killed() || started.elapsed() > WAIT_BOUND {
                    return w.until_killed();
                }
                thread::sleep(Duration::from_millis(2));
            }
            thread::sleep(Duration::from_millis(20));
        }
        w.until_killed()
    });
    let (outcome, held) = measure(|| run_to_end(&rt, &spawner, limits, sink.clone()));
    let outcome = outcome?;
    assert_eq!(
        outcome.host,
        HostVerdict::Violation(ViolationKind::UnreadResults)
    );
    assert_eq!(outcome.end, WorkerEnd::None);
    assert_eq!(outcome.diag, vec![DIAG_UNREAD_RESULTS]);
    assert_eq!(observed.signals(), 1);
    // The queue (at most the cap), each answer's value and encoding while it is built (one burst),
    // and the fixed allowance.
    let allowed = cap + 2 * BURST as usize * ANSWER + HELD_ALLOWANCE;
    assert!(
        held <= allowed,
        "the run held {held} bytes at once, allowed {allowed}"
    );
    observed.wait_finished()?;
    println!(
        "S-10 unread_results_cap cap_bytes={cap} offered_calls={calls} held_peak_bytes={held}"
    );
    Ok(())
}

/// T7 hand-off (T3 re-review N-b): frames sent by `toJSON` / `describe` getters can precede the
/// terminal frame, and a call may still be unanswered when the terminal arrives: all of it is
/// accepted, the run ends with the result.
#[test]
fn s10_frames_before_the_terminal_are_accepted() -> TestResult {
    let _serial = serial();
    let rt = runtime()?;
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        w.send(&log_frame("from a getter"))?;
        w.send(&call_frame(1))?;
        w.send(&log_frame("another"))?;
        w.send(result_frame("\"done\"").as_bytes())?;
        while w.read()?.is_some() {}
        Ok(0)
    });
    let (sink, gate) = TestSink::gated();
    let outcome = run_to_end(&rt, &spawner, ScriptLimits::default(), sink.clone())?;
    gate.add_permits(1);
    assert_eq!(outcome.host, HostVerdict::None);
    assert!(matches!(outcome.end, WorkerEnd::Result { .. }));
    assert_eq!(outcome.logs, ["from a getter", "another"]);
    assert_eq!(sink.calls(), vec![1]);
    observed.wait_finished()?;
    Ok(())
}
