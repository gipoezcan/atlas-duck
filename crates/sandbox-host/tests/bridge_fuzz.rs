//! M8 Task 8 (§13 S-10 "Sandbox channel fuzzing: malformed, oversize and out-of-order frames",
//! §3.4, §15 V12 worker half): hostile frame sequences against the host bridge, over the same kind
//! of scripted fake worker as `tests/bridge.rs` (a thread behind three in-memory pipes; no process
//! is spawned). The real-worker half (pipe deadlock, handle and environment hygiene) is in
//! `app/src-tauri/tests/sandbox_runs.rs`.
//!
//! A counting global allocator measures what the host holds at once: a hostile frame never makes
//! the host hold more than the frame being read plus a fixed allowance. The fake worker's own
//! thread is exempt from the count (it builds its frames itself), so the figure is the host's. A
//! header's claimed length is allocated up front (`read_frame`), but never beyond the read cap
//! (the terminal cap, at most 24 MiB): `HugeHeader` and `OversizeTerminal` are refused at the
//! header. The tests of this file run one at a time ([`SERIAL`]) so the measured window holds one
//! run only; after each fuzz case the heap must be back at its level before the case, so a leak
//! across cases fails.
//!
//! Every wait is bounded ([`WAIT_BOUND`]): a regression fails instead of hanging.
//!
//! The fuzz runs are deterministic: each `proptest!` has a fixed seed and a fixed case count
//! (`S10_FUZZ_CASES` raises it for a deep local run; a red case replays from the seed), and the
//! hostile cases that matter most are also plain named tests (`s10_fixed_*`).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicIsize, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
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
use atlas_duck_sandbox_host::identity::{FileId, SandboxBinaryIdentity, file_identity};
use atlas_duck_sandbox_host::kill::{GuardedKill, ReapGuard, reap_after_wait};
use atlas_duck_sandbox_host::spawn::{
    ExitKind, KillHandle, Reaper, SpawnSpec, WorkerIo, WorkerParts, WorkerProcess, WorkerSpawner,
};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::{RngAlgorithm, RngSeed, TestCaseError};
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

/// Counts the live heap bytes of the test process (the fake worker's thread excepted) and their
/// peak.
struct Counting;

/// Signed: a block the fake allocated (not counted) and the host frees (counted) takes the count
/// below its true level. Such blocks are a few bytes (channel nodes, `Arc`s).
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

thread_local! {
    /// Set on the fake worker's thread: its allocations and frees are not counted. A `const`
    /// `Cell<bool>` needs no lazy allocation, so the allocator may read it.
    static EXEMPT: Cell<bool> = const { Cell::new(false) };
}

fn exempt() -> bool {
    EXEMPT.try_with(Cell::get).unwrap_or(false)
}

fn grow(by: usize) {
    if exempt() {
        return;
    }
    let now = LIVE.fetch_add(by as isize, Ordering::Relaxed) + by as isize;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

fn shrink(by: usize) {
    if !exempt() {
        LIVE.fetch_sub(by as isize, Ordering::Relaxed);
    }
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
        shrink(layout.size());
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
                shrink(layout.size() - new_size);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Runs `f` and returns its value with the most heap (bytes, the fake worker's excepted) that was
/// live at once above the level at the start.
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let value = f();
    let peak = PEAK.load(Ordering::Relaxed);
    (value, usize::try_from(peak - base).unwrap_or(0))
}

/// What the host may hold above the frame being read (and its decoded copy): the capped logs and
/// stderr head of a short run, the threads' channels and buffers. Measured: about 8 KiB.
const HELD_ALLOWANCE: usize = 512 * 1024;

/// A fuzz case may leave this much behind (the host's threads end a moment after `wait` returns).
const CASE_LEAK_SLACK: usize = 256 * 1024;
/// All the cases of a fuzz run together may leave this much behind.
const RUN_LEAK_SLACK: usize = 4 * MIB;

/// The live heap level now.
fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

/// Waits (bounded) until the heap is within [`CASE_LEAK_SLACK`] of `base`, and returns how far
/// above `base` it is: the threads of a run end a moment after its outcome.
fn settled_above(base: isize) -> isize {
    let started = Instant::now();
    loop {
        let above = live() - base;
        if above <= CASE_LEAK_SLACK as isize || started.elapsed() > Duration::from_secs(5) {
            return above;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// The heap level before the first fuzz case, for the leak check over the whole run.
static RUN_BASE: OnceLock<isize> = OnceLock::new();

/// The deterministic configuration of a fuzz run: a fixed seed and case count, and few shrink
/// steps (a failing case that waits for a kill takes `WAIT_BOUND` per step). Failures persist
/// next to this file (`bridge_fuzz.proptest-regressions`, committed) and are replayed first.
fn fuzz_config(cases: u32, seed: u64) -> ProptestConfig {
    ProptestConfig {
        cases: std::env::var("S10_FUZZ_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(cases),
        max_shrink_iters: 4,
        max_shrink_time: 0,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(seed),
        ..ProptestConfig::default()
    }
}

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
            // What the fake builds and holds is not the host's heap.
            EXEMPT.with(|e| e.set(true));
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
    call_frame_op(envelope, inner, "jira.issue.get")
}

fn call_frame_op(envelope: u64, inner: u64, op_id: &str) -> Vec<u8> {
    let call = HostCall {
        id: inner,
        op_id: op_id.to_string(),
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

/// The "worker binary" of these tests: a plain file that exists (the bridge re-checks the file
/// identity of `SpawnSpec.exe` before it spawns, V21); the fake spawner never executes it.
fn worker_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
}

fn expect() -> ExpectedWorker {
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
        accept_unconfined: false,
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

/// A valid frame a worker sends before it turns hostile.
#[derive(Debug, Clone)]
enum Valid {
    Log(String),
    /// A `host.call` (ids count up from 1 in the order of the calls).
    Call,
}

/// A frame (or the start of one) after a valid terminal.
#[derive(Debug, Clone)]
enum Tail {
    Log(String),
    Call(u64),
    /// A framed payload of arbitrary bytes.
    Garbage(Vec<u8>),
    /// A length header only (any value), no body.
    Header(u32),
    /// 1 to 3 bytes of a length prefix.
    Prefix(Vec<u8>),
}

impl Tail {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Tail::Log(line) => framed(&log_frame(line)),
            Tail::Call(id) => framed(&call_frame(*id)),
            Tail::Garbage(b) => framed(b),
            Tail::Header(h) => h.to_be_bytes().to_vec(),
            Tail::Prefix(p) => p.clone(),
        }
    }
}

/// One hostile behaviour of the worker after its `script.run` arrived.
#[derive(Debug, Clone)]
enum Attack {
    /// A frame of arbitrary bytes.
    RandomBytes(Vec<u8>),
    /// Unframed bytes: the stream is not frames at all (its first four bytes are a header); the
    /// worker ends after them.
    RawStream(Vec<u8>),
    /// A `host.log` frame whose line holds bytes that are not UTF-8.
    InvalidUtf8 { head: Vec<u8>, tail: Vec<u8> },
    /// A well-formed notification of a method the worker may not send.
    UnknownMethod(String),
    /// Valid JSON of a known method (or of no valid envelope at all) with the wrong shape: params
    /// that are null, an array, a string, a wrong type, missing fields, extra members, deep
    /// nesting; a bad `jsonrpc`, `id` or top-level key.
    WrongShape(String),
    /// A well-formed `script.compiled` or `script.syntax`: replies of a compile run, in a script
    /// run.
    CompileReply { syntax: bool },
    /// 1 to 3 bytes of a length prefix, then the worker ends.
    TruncatedPrefix(Vec<u8>),
    /// A header that claims `claimed` bytes, `sent` of them (fewer) follow, then the worker ends.
    TruncatedBody { claimed: usize, sent: usize },
    /// A `host.log` frame of 1 MiB + 1 bytes.
    OversizeLog,
    /// A `host.call` frame of 1 MiB + 1 bytes (a huge `op_id`).
    OversizeCall,
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
    /// Valid frames first (logs and at most one call), then the hostile behaviour.
    Prefixed(Vec<Valid>, Box<Attack>),
    /// A valid terminal, then more frames of any kind but a terminal: the terminal stands.
    AfterTerminal { result: bool, tail: Vec<Tail> },
}

/// What the host must conclude.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// The bridge killed the worker for a channel violation (of this kind, if known).
    Violation(Option<ViolationKind>),
    /// The stream ended inside a frame: a truncated frame is EOF (T7 deviation 7), so the exit
    /// decides and the run counts as a crash, never as a result.
    Eof,
    /// A violation or EOF inside a frame, depending on the bytes; never a result.
    ViolationOrEof,
    /// The terminal was accepted (a result or an error of the script); what follows changes
    /// nothing.
    Accepted { result: bool },
}

impl Attack {
    fn verdict(&self) -> Verdict {
        use ViolationKind::*;
        let kind = match self {
            Attack::RandomBytes(_) => None,
            Attack::RawStream(_) => return Verdict::ViolationOrEof,
            Attack::InvalidUtf8 { .. } | Attack::WrongShape(_) => Some(Malformed),
            Attack::UnknownMethod(_) => Some(UnknownMethod),
            Attack::CompileReply { .. } => Some(UnexpectedFrame),
            Attack::TruncatedPrefix(_) | Attack::TruncatedBody { .. } => return Verdict::Eof,
            Attack::OversizeLog
            | Attack::OversizeCall
            | Attack::OversizeTerminal
            | Attack::HugeHeader(_) => Some(Oversize),
            Attack::ReorderedIds(_) => Some(IdNotIncreasing),
            Attack::IdMismatch { .. } => Some(IdMismatch),
            Attack::TwoTerminals { .. } => Some(SecondTerminal),
            Attack::WorkerResponse(_) => Some(WorkerResponse),
            Attack::Prefixed(_, inner) => return inner.verdict(),
            Attack::AfterTerminal { result, .. } => {
                return Verdict::Accepted { result: *result };
            }
        };
        Verdict::Violation(kind)
    }

    /// The first of two terminals is the run's end (the second one is the violation).
    fn keeps_first_terminal(&self) -> bool {
        match self {
            Attack::TwoTerminals { .. } => true,
            Attack::Prefixed(_, inner) => inner.keeps_first_terminal(),
            _ => false,
        }
    }

    /// The limits the run is started with.
    fn limits(&self) -> ScriptLimits {
        match self {
            Attack::OversizeTerminal | Attack::HugeHeader(_) => {
                limits_with(|l| l.max_result_mb = RESULT_MB)
            }
            Attack::Prefixed(_, inner) => inner.limits(),
            _ => ScriptLimits::default(),
        }
    }

    /// The most the host holds for this attack, besides the allowance: the whole frame of the
    /// `Oversize*` logs and calls (below the read cap, so it is read and decoded before it is
    /// refused),
    /// the claimed length of a header (`read_frame` allocates it up front, up to the cap). A
    /// header above the read cap (`HugeHeader`, `OversizeTerminal`) is refused unread.
    fn frame_held(&self) -> usize {
        // A header of the stream that the host accepts is allocated in full.
        let accepted = |header: u32| {
            let claimed = header as usize;
            if claimed <= default_read_cap() {
                claimed
            } else {
                0
            }
        };
        match self {
            // The frame read (a `Vec`) and the decoder's one copy of it (the log line, the call's
            // fields): measured 2 MiB + 2 for a frame of 1 MiB + 1, plus about 8 KiB.
            Attack::OversizeLog | Attack::OversizeCall => 2 * (MIB + 1),
            Attack::TruncatedBody { claimed, .. } => *claimed,
            // The first four bytes of the stream are a header of any size.
            Attack::RawStream(b) => b
                .first_chunk::<4>()
                .map_or(0, |h| accepted(u32::from_be_bytes(*h))),
            Attack::AfterTerminal { tail, .. } => match tail.last() {
                Some(Tail::Header(h)) => accepted(*h),
                _ => 0,
            },
            Attack::Prefixed(_, inner) => inner.frame_held(),
            _ => 0,
        }
    }

    /// The fake worker's behaviour.
    fn script(&self) -> Script {
        let attack = self.clone();
        Box::new(move |w| {
            w.ready()?;
            w.read()?; // script.run
            attack.act(w)
        })
    }

    fn act(&self, w: &mut FakeWorker) -> io::Result<i32> {
        match self {
            Attack::Prefixed(valid, inner) => {
                let mut next_id = 1;
                for frame in valid {
                    match frame {
                        Valid::Log(line) => w.send(&log_frame(line))?,
                        Valid::Call => {
                            w.send(&call_frame(next_id))?;
                            next_id += 1;
                        }
                    }
                }
                return inner.act(w);
            }
            Attack::RandomBytes(b) => w.send(b)?,
            Attack::RawStream(b) => {
                w.send_raw(b)?;
                return Ok(0);
            }
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
            Attack::WrongShape(frame) => w.send(frame.as_bytes())?,
            Attack::CompileReply { syntax } => {
                let frame = if *syntax {
                    r#"{"jsonrpc":"2.0","method":"script.syntax","params":{"line":1,"column":1,"message":"m"}}"#
                } else {
                    r#"{"jsonrpc":"2.0","method":"script.compiled","params":{}}"#
                };
                w.send(frame.as_bytes())?;
            }
            Attack::TruncatedPrefix(prefix) => {
                w.send_raw(prefix)?;
                return Ok(0);
            }
            Attack::TruncatedBody { claimed, sent } => {
                let mut bytes = (*claimed as u32).to_be_bytes().to_vec();
                bytes.extend(std::iter::repeat_n(b'{', *sent));
                w.send_raw(&bytes)?;
                return Ok(0);
            }
            Attack::OversizeLog => {
                let empty = log_frame("").len();
                w.send(&log_frame(&"o".repeat(MIB + 1 - empty)))?;
            }
            Attack::OversizeCall => {
                let empty = call_frame_op(1, 1, "").len();
                w.send(&call_frame_op(1, 1, &"o".repeat(MIB + 1 - empty)))?;
            }
            Attack::OversizeTerminal => {
                w.send(&result_frame_of_len(terminal_frame_max(&self.limits()) + 1))?;
            }
            Attack::HugeHeader(h) => w.send_raw(&h.to_be_bytes())?,
            Attack::ReorderedIds(ids) => {
                for id in ids {
                    w.send(&call_frame(*id))?;
                }
            }
            Attack::IdMismatch { envelope, inner } => {
                w.send(&call_frame_in(*envelope, *inner))?;
            }
            Attack::TwoTerminals {
                first_result,
                second_result,
            } => {
                let mut bytes = framed(&terminal_frame(*first_result));
                bytes.extend(framed(&terminal_frame(*second_result)));
                w.send_raw(&bytes)?;
                while w.read()?.is_some() {}
                return Ok(0);
            }
            Attack::WorkerResponse(id) => {
                let frame = json!({"jsonrpc": "2.0", "id": id, "result": {"ok": 1}});
                w.send(frame.to_string().as_bytes())?;
            }
            Attack::AfterTerminal { result, tail } => {
                let mut bytes = framed(&terminal_frame(*result));
                for t in tail {
                    bytes.extend(t.bytes());
                }
                w.send_raw(&bytes)?;
            }
        }
        w.until_killed()
    }
}

/// A valid terminal frame: `script.result` or `script.error`.
fn terminal_frame(result: bool) -> Vec<u8> {
    if result {
        result_frame("1").into_bytes()
    } else {
        error_frame("Error", "x")
    }
}

/// The largest length the host accepts a header for under the default limits.
fn default_read_cap() -> usize {
    terminal_frame_max(&ScriptLimits::default()).max(MIB)
}

fn first_non_increasing(ids: &[u64]) -> bool {
    ids.windows(2).any(|w| w[1] <= w[0])
}

/// Frames of valid JSON whose shape no worker may send; the decoder rejects every one of them as
/// malformed. The cross product of the four known methods and the params no method accepts, and
/// one frame for each other way to get the envelope wrong.
fn wrong_shapes() -> Vec<String> {
    let call_params =
        r#"{"id":1,"op_id":"jira.issue.get","params":{},"instance":null,"all":false}"#;
    let bad_params = [
        "null",
        "true",
        "7",
        "-1.5",
        r#""str""#,
        "[]",
        r#"[1,"a",null]"#,
        "{}",
        r#"{"line":5}"#,
        r#"{"line":null}"#,
        r#"{"value":1,"extra":2}"#,
        r#"{"id":"x"}"#,
        r#"{"class":1,"message":2,"stack":3}"#,
        r#"{"id":1,"op_id":5,"params":{},"instance":null,"all":false}"#,
    ];
    let mut out = Vec::new();
    for method in ["host.call", "host.log", "script.result", "script.error"] {
        let id = if method == "host.call" {
            r#""id":1,"#
        } else {
            ""
        };
        for params in bad_params {
            out.push(format!(
                r#"{{"jsonrpc":"2.0",{id}"method":"{method}","params":{params}}}"#
            ));
        }
        // No `params` at all reads as `{}`: missing required members.
        out.push(format!(r#"{{"jsonrpc":"2.0",{id}"method":"{method}"}}"#));
    }
    let log = r#""method":"host.log","params":{"line":"x"}"#;
    for version in [
        r#""jsonrpc":"1.0","#,
        r#""jsonrpc":2,"#,
        r#""jsonrpc":null,"#,
        r#""jsonrpc":"2.0 ","#,
        "",
    ] {
        out.push(format!("{{{version}{log}}}"));
    }
    out.push(r#"{"jsonrpc":"2.0","method":5}"#.to_string());
    out.push(r#"{"jsonrpc":"2.0"}"#.to_string());
    for id in ["0", "-3", r#""1""#, "1.5", "null", "18446744073709551616"] {
        out.push(format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"host.call","params":{call_params}}}"#
        ));
    }
    out.push(format!(
        r#"{{"jsonrpc":"2.0","method":"host.call","params":{call_params}}}"#
    ));
    // An id on a notification; an extra and a duplicate top-level member; a method next to a result.
    out.push(format!(r#"{{"jsonrpc":"2.0","id":1,{log}}}"#));
    out.push(
        r#"{"jsonrpc":"2.0","id":2,"method":"script.result","params":{"value":1}}"#.to_string(),
    );
    out.push(format!(r#"{{"jsonrpc":"2.0",{log},"extra":1}}"#));
    out.push(format!(r#"{{"jsonrpc":"2.0",{log},"method":"host.log"}}"#));
    out.push(r#"{"jsonrpc":"2.0","method":"host.log","result":1}"#.to_string());
    // Valid JSON that is no object.
    for text in ["[]", "null", "7", r#""x""#, "true", "[{}]"] {
        out.push(text.to_string());
    }
    out.push(deep_nesting(130));
    out
}

/// A `host.log` whose `line` is `depth` nested arrays: past serde_json's recursion limit (128)
/// the frame is not even readable, below it the `line` is no string.
fn deep_nesting(depth: usize) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","method":"host.log","params":{{"line":{}{}}}}}"#,
        "[".repeat(depth),
        "]".repeat(depth)
    )
}

/// Attacks that are a single behaviour; `attack()` composes them with valid frames before and
/// after.
fn base_attack() -> impl Strategy<Value = Attack> {
    // The cap a header must exceed: the terminal cap of `RESULT_MB`.
    let cap = terminal_frame_max(&limits_with(|l| l.max_result_mb = RESULT_MB)) as u32;
    let read_cap = default_read_cap();
    prop_oneof![
        8 => vec(any::<u8>(), 0..512).prop_map(Attack::RandomBytes),
        // Random bytes as a raw stream: the first four are a header of any size.
        6 => vec(any::<u8>(), 0..256).prop_map(Attack::RawStream),
        4 => (vec(0x23u8..0x5c, 0..64), vec(0x23u8..0x5c, 0..64))
            // ASCII from '#' to '[': no quote and no backslash, so only the 0xff makes the line invalid.
            .prop_map(|(head, tail)| Attack::InvalidUtf8 { head, tail }),
        4 => "x[a-z]{0,6}\\.[a-z]{1,8}".prop_map(Attack::UnknownMethod),
        6 => prop_oneof![
                4 => prop::sample::select(wrong_shapes()),
                1 => (100usize..400).prop_map(deep_nesting),
            ].prop_map(Attack::WrongShape),
        2 => any::<bool>().prop_map(|syntax| Attack::CompileReply { syntax }),
        4 => vec(any::<u8>(), 1..=3).prop_map(Attack::TruncatedPrefix),
        4 => (1usize..4096).prop_flat_map(|claimed| (Just(claimed), 0..claimed))
            .prop_map(|(claimed, sent)| Attack::TruncatedBody { claimed, sent }),
        // A claim between the log cap and the terminal cap, whose body never arrives.
        2 => ((MIB + 1)..=read_cap, 0usize..4096)
            .prop_map(|(claimed, sent)| Attack::TruncatedBody { claimed, sent }),
        1 => Just(Attack::OversizeLog),
        1 => Just(Attack::OversizeCall),
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

/// Valid frames a worker may send before it turns hostile: logs, and at most one call (more
/// calls could meet `max_concurrent_calls` before the attack's own violation).
fn valid_prefix() -> impl Strategy<Value = Vec<Valid>> {
    let log = "[ -~]{0,40}".prop_map(Valid::Log);
    (vec(log, 0..4), any::<bool>()).prop_map(|(mut frames, call)| {
        if call {
            frames.push(Valid::Call);
        }
        frames
    })
}

/// Whole frames after a terminal, and at most one header or prefix at the end (a stub in the
/// middle would turn the next frame's bytes into a header of the fuzz's own making).
fn tail() -> impl Strategy<Value = Vec<Tail>> {
    let frame = prop_oneof![
        3 => "[ -~]{0,40}".prop_map(Tail::Log),
        2 => (1u64..50).prop_map(Tail::Call),
        3 => vec(any::<u8>(), 0..128).prop_map(Tail::Garbage),
    ];
    let stub = prop::option::of(prop_oneof![
        any::<u32>().prop_map(Tail::Header),
        vec(any::<u8>(), 1..=3).prop_map(Tail::Prefix),
    ]);
    (vec(frame, 0..4), stub).prop_map(|(mut frames, stub)| {
        frames.extend(stub);
        frames
    })
}

fn attack() -> impl Strategy<Value = Attack> {
    prop_oneof![
        10 => base_attack(),
        // Valid frames, then each attack.
        6 => (valid_prefix(), base_attack())
            .prop_map(|(valid, inner)| Attack::Prefixed(valid, Box::new(inner))),
        // Frames after the terminal.
        3 => (any::<bool>(), tail())
            .prop_map(|(result, tail)| Attack::AfterTerminal { result, tail }),
    ]
}

/// Runs `attack` and returns the outcome, the fake's observations and the heap the host peaked at.
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
    let shown: String = format!("{attack:?}").chars().take(200).collect();
    let shown = shown.as_str();
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
        Verdict::ViolationOrEof => match outcome.host {
            // The fake ends after its bytes, so the host may reap it before it kills: 0 or 1.
            HostVerdict::Violation(_) => prop_assert!(observed.signals() <= 1, "{}", shown),
            HostVerdict::Crashed(_) => {}
            ref other => prop_assert!(false, "{shown}: host verdict {other:?}"),
        },
        Verdict::Accepted { result } => {
            prop_assert_eq!(&outcome.host, &HostVerdict::None, "{}", shown);
            let kept = match &outcome.end {
                WorkerEnd::Result { .. } => result,
                WorkerEnd::Error { .. } => !result,
                _ => false,
            };
            prop_assert!(
                kept,
                "{shown}: the terminal did not stand: {:?}",
                outcome.end
            );
            prop_assert_eq!(observed.signals(), 1, "one kill: {}", shown);
        }
    }
    // No terminal is ever accepted from a hostile stream (of two terminals the first stands, and
    // the second one is the violation).
    if matches!(
        attack.verdict(),
        Verdict::Violation(_) | Verdict::Eof | Verdict::ViolationOrEof
    ) && !attack.keeps_first_terminal()
    {
        prop_assert_eq!(&outcome.end, &WorkerEnd::None, "{}", shown);
    }
    observed.wait_finished().map_err(TestCaseError::fail)?;
    // §3.4: the host never holds more than the frame being read (plus the fixed allowance); a
    // length beyond the read cap is never allocated.
    let allowed = attack.frame_held() + HELD_ALLOWANCE;
    prop_assert!(
        held <= allowed,
        "{shown}: the host held {held} bytes at once, allowed {allowed}"
    );
    Ok(())
}

proptest! {
    #![proptest_config(fuzz_config(160, 0x5110_0001))]

    #[test]
    fn s10_malformed_oversize_out_of_order_frames_end_in_violation(attack in attack()) {
        let _serial = serial();
        let before = live();
        let run_base = *RUN_BASE.get_or_init(|| before);
        {
            let rt = runtime().map_err(|e| TestCaseError::fail(e.to_string()))?;
            check(&rt, &attack)?;
        }
        // The case left nothing behind, and no case left a little more than the one before.
        let above = settled_above(before);
        prop_assert!(
            above <= CASE_LEAK_SLACK as isize,
            "the case left {above} bytes on the heap"
        );
        let total = live() - run_base;
        prop_assert!(
            total <= RUN_LEAK_SLACK as isize,
            "the cases left {total} bytes on the heap"
        );
    }
}

// ---- the same hostile cases, by name -------------------------------------------------------------

/// Plays one attack and checks it as the fuzz run does.
fn fixed(attack: Attack) -> TestResult {
    let _serial = serial();
    let rt = runtime()?;
    check(&rt, &attack).map_err(|e| e.to_string())?;
    Ok(())
}

/// A log of 1 MiB + 1 bytes: read whole (it is below the read cap), refused as `Oversize`.
#[test]
fn s10_fixed_log_of_1mib_plus_1() -> TestResult {
    fixed(Attack::OversizeLog)
}

/// A call of 1 MiB + 1 bytes (a huge `op_id`): the same cap, whatever the method.
#[test]
fn s10_fixed_call_of_1mib_plus_1() -> TestResult {
    fixed(Attack::OversizeCall)
}

/// A terminal one byte above its cap: refused at the header, the body is never read.
#[test]
fn s10_fixed_terminal_cap_plus_1() -> TestResult {
    fixed(Attack::OversizeTerminal)
}

/// A header that claims 4 GiB - 1 and no body: refused at the header.
#[test]
fn s10_fixed_header_of_u32_max() -> TestResult {
    fixed(Attack::HugeHeader(u32::MAX))
}

#[test]
fn s10_fixed_two_terminals_keep_the_first() -> TestResult {
    for (first_result, second_result) in
        [(true, true), (true, false), (false, true), (false, false)]
    {
        fixed(Attack::TwoTerminals {
            first_result,
            second_result,
        })?;
    }
    Ok(())
}

/// Every wrong shape of the list is a `Malformed` violation, on its own and after valid frames.
#[test]
fn s10_fixed_every_wrong_shape_is_malformed() -> TestResult {
    let _serial = serial();
    let rt = runtime()?;
    let shapes = wrong_shapes();
    assert!(shapes.len() > 80, "{} shapes", shapes.len());
    for shape in shapes {
        for valid in [Vec::new(), vec![Valid::Log("a".into()), Valid::Call]] {
            let bare = Attack::WrongShape(shape.clone());
            let attack = if valid.is_empty() {
                bare
            } else {
                Attack::Prefixed(valid, Box::new(bare))
            };
            check(&rt, &attack).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Valid frames (a log, a call, a log) and then each kind of hostile frame.
#[test]
fn s10_fixed_valid_prefix_then_hostile() -> TestResult {
    let _serial = serial();
    let rt = runtime()?;
    let hostile = [
        Attack::RandomBytes(vec![0xff, 0x00, 0x7b]),
        Attack::UnknownMethod("x.y".into()),
        Attack::CompileReply { syntax: false },
        Attack::TruncatedPrefix(vec![0, 0]),
        Attack::TruncatedBody {
            claimed: 100,
            sent: 10,
        },
        Attack::OversizeLog,
        Attack::HugeHeader(u32::MAX),
        Attack::ReorderedIds(vec![5, 3]),
        Attack::IdMismatch {
            envelope: 2,
            inner: 3,
        },
        Attack::TwoTerminals {
            first_result: true,
            second_result: true,
        },
        Attack::WorkerResponse(1),
    ];
    for inner in hostile {
        let valid = vec![
            Valid::Log("one".into()),
            Valid::Call,
            Valid::Log("two".into()),
        ];
        check(&rt, &Attack::Prefixed(valid, Box::new(inner))).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// A hostile frame after the terminal changes nothing: the terminal stands, the run is not a
/// violation (only a second terminal is).
#[test]
fn s10_fixed_frames_after_the_terminal_change_nothing() -> TestResult {
    let _serial = serial();
    let rt = runtime()?;
    for result in [true, false] {
        for tail in [
            Tail::Log("late".into()),
            Tail::Call(9),
            Tail::Garbage(vec![0xff, 0xfe]),
            Tail::Header(u32::MAX),
            Tail::Prefix(vec![0, 0, 1]),
        ] {
            let attack = Attack::AfterTerminal {
                result,
                tail: vec![Tail::Log("first".into()), tail],
            };
            check(&rt, &attack).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// A header that claims 8 MiB (below the terminal cap) and a body that never comes: the worker is
/// alive and silent, so only the timer ends the run. The host holds what the header claims (the
/// length is allocated up front, bounded by the read cap) and nothing more, and the run does not
/// hang.
#[test]
fn s10_fixed_stalled_body_below_the_terminal_cap() -> TestResult {
    let _serial = serial();
    let rt = runtime()?;
    const CLAIMED: usize = 8 * MIB;
    let (spawner, observed) = fake(|w| {
        w.ready()?;
        w.read()?;
        let mut bytes = (CLAIMED as u32).to_be_bytes().to_vec();
        bytes.extend(std::iter::repeat_n(b'{', 1024));
        w.send_raw(&bytes)?;
        w.until_killed()
    });
    let (outcome, held) = measure(|| {
        run_to_end(
            &rt,
            &spawner,
            limits_with(|l| l.timeout_s = 2),
            Arc::new(TestSink::default()),
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
    assert!(
        held <= CLAIMED + HELD_ALLOWANCE,
        "the host held {held} bytes for a claim of {CLAIMED}"
    );
    observed.wait_finished()?;
    println!("S-10 stalled_body claimed={CLAIMED} host_held_bytes={held}");
    Ok(())
}

// ---- floods ------------------------------------------------------------------------------------

/// 10 000 log lines of 200 bytes (§13 S-10): the byte cap bites first (1 MiB = 5 242 whole
/// lines); the run still ends with its result. The asserts are byte-exact: what the outcome keeps,
/// what it counts as discarded, what the sink was shown. (A bound on the heap would add nothing:
/// an uncapped flood is 2 MB per copy, which the exact counts above already exclude.)
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
    let outcome = run_to_end(&rt, &spawner, ScriptLimits::default(), sink.clone())?;
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
    Ok(())
}

proptest! {
    #![proptest_config(fuzz_config(12, 0x5110_0002))]

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
    #![proptest_config(fuzz_config(24, 0x5110_0003))]

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
/// `s10_unread_results_are_capped`. What the host holds is what it queued: the answers sent so
/// far plus the one burst being built, nothing more (so nothing is kept twice).
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
    const ANSWER: usize = 512 * 1024;
    // Every answer is 512 KiB: the first fills the pipe, the writer blocks, the rest queue.
    let sink = TestSink::padded(ANSWER);
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
            // The timer must not fire before the fake is done on a slow runner; the elapsed
            // bound below still leaves it 5 s for the kill.
            limits_with(|l| {
                l.timeout_s = 5;
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
    // The queue (every answer sent so far, JSON overhead included), the answers being built (a
    // burst: value and encoding) and the allowance. Below the cap, so the cap is not what holds.
    let allowed = sent as usize * (ANSWER + 4096) + 2 * BURST as usize * ANSWER + HELD_ALLOWANCE;
    assert!(
        held <= allowed,
        "the host held {held} bytes for {sent} answers of {ANSWER}, allowed {allowed}"
    );
    assert!(allowed < unread_results_cap(&ScriptLimits::default()) + 2 * BURST as usize * ANSWER);
    println!(
        "S-10 unread_stdin sent={sent} answered={answered} decoded={} answer_bytes={ANSWER} queued_peak_bytes={held}",
        calls.len(),
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

/// Nothing of a run outlives its outcome: the answers queued for a worker that never read them
/// are released before `RunHandleImpl::wait` answers, not a moment later by the writer thread.
/// Measured at once, without a settle: the CI failure of the fuzz run above was the queue of
/// `s10_worker_that_never_reads_stdin_is_killed_at_the_timer` still being freed while the next
/// fuzz case ran.
#[test]
fn s10_queued_answers_are_released_before_the_outcome() -> TestResult {
    let _serial = serial();
    let rt = runtime()?;
    const CALLS: u64 = 12;
    const ANSWER: usize = 512 * 1024;
    const SEND_DEADLINE: Duration = Duration::from_secs(1);
    let sink = TestSink::padded(ANSWER);
    let seen = Arc::clone(&sink);
    // The calls the fake sent before the timer (a slow runner may not get through all of them).
    let sent = Arc::new(AtomicU64::new(0));
    let fake_sent = Arc::clone(&sent);
    let (spawner, observed) = fake(move |w| {
        w.ready()?;
        w.read()?; // script.run; nothing after it is ever read
        let begun = Instant::now();
        // One call at a time, each answered (and queued) before the next. No call is started
        // after SEND_DEADLINE, well inside the timer, and the loop waits for each answer, so on a
        // slow runner no call task is still in flight when the timer ends the run.
        for id in 1..=CALLS {
            if begun.elapsed() > SEND_DEADLINE {
                break;
            }
            w.send(&call_frame(id))?;
            fake_sent.store(id, Ordering::SeqCst);
            let started = Instant::now();
            while u64::from(seen.completed()) < id {
                if w.observed.is_killed() || started.elapsed() > WAIT_BOUND {
                    return w.until_killed();
                }
                thread::sleep(Duration::from_millis(2));
            }
        }
        w.until_killed()
    });
    let base = live();
    let (outcome, held) = measure(|| {
        run_to_end(
            &rt,
            &spawner,
            limits_with(|l| l.timeout_s = 2),
            sink.clone(),
        )
    });
    let left = live() - base;
    let outcome = outcome?;
    assert_eq!(outcome.host, HostVerdict::Limit("timeout_s"));
    // The answers were queued (the first one blocks the writer on the full pipe, the rest wait):
    // at least one whole answer, more than the slack below, was held while the run lasted. Checked
    // first, so a run that was too slow reports that and not a leak.
    let sent = sent.load(Ordering::SeqCst);
    assert!(sent >= 2, "only {sent} calls were sent before the timer");
    assert!(
        held >= (sent as usize - 1) * ANSWER,
        "the host held {held} bytes at most for {sent} answers, so they were never queued"
    );
    assert!(
        left <= CASE_LEAK_SLACK as isize,
        "the run's outcome is out while {left} bytes of it are still on the heap"
    );
    observed.wait_finished()?;
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
