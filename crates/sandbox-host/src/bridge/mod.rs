//! The host bridge (C.8, M8 Δ2; spec §3.4 channel rules, §9.1 steps 3–5, §9.4, §9.5): one script
//! run ([`start_run`]) or one compile check ([`compile_run`]) in a freshly spawned worker.
//!
//! The host treats the worker as hostile (§3.4). Per worker:
//! - a **reader** thread decodes stdout one frame at a time and never stops before EOF (after a
//!   decision or a violation it reads and discards), so a worker blocked writing never deadlocks
//!   against a host blocked writing;
//! - a **stderr** thread keeps the first 64 KiB and reads and discards the rest;
//! - a **writer** thread owns stdin and writes the queued frames (`script.run`, call results);
//! - a **reaper** thread waits for the exit (T6: never on a runtime thread, never dropped).
//!
//! The per-run state machine is [`state`]. The run lock is held only for short state updates,
//! never across a blocking read, write or wait, nor across a parse of a frame's payload;
//! [`RunHandleImpl::kill`] takes it briefly and then calls the non-blocking [`KillHandle`] (M3
//! M-1). Host calls run as tasks on the caller's runtime that are never aborted (PD-148); a result
//! is queued for the worker only while the run is undecided.
//!
//! Spawn-time checks (PD-132, PD-133, PD-141): the ready frame (`probe.ready`) is read within
//! [`READY_TIMEOUT`]; its `worker_version` must equal the recorded identity's embedded version,
//! and `confinement.applied` must be true unless [`ExpectedWorker::accept_unconfined`]. Either
//! failure kills the worker before it was sent any frame.
//!
//! A kill can fail without a sign (T6: the worker then never ends), so a kill is never sent just
//! once: a run's timer kills again from `timeout_s` on until the reap, and a refused or finished
//! compile worker is killed again every [`KILL_RETRY`] until it is reaped.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod reader;
mod state;
mod writer;

pub use state::ViolationKind;

use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::Poll;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use atlas_duck_ipc::sandbox::probe::{
    ConfinementReport, M_PROBE_READY, ProbeReady, decode_notification, encode_notification,
};
use atlas_duck_ipc::sandbox::script::{
    CompileRequest, M_SCRIPT_COMPILE, M_SCRIPT_RUN, RawJsonText, WorkerFrame, WorkerInit,
    decode_worker_frame,
};
use atlas_duck_ipc::sandbox::{
    EXIT_PROTOCOL, HOST_TO_WORKER_MAX, HostCall, HostCallResult, WORKER_FRAME_MAX_BYTES,
};
use serde_json::Value;
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::time::Sleep;

use self::reader::{Continuation, Frame, Stdout};
use self::state::{Incoming, RunState, Step};
use crate::identity::{IdentityPart, SandboxBinaryIdentity};
use crate::spawn::{ExitKind, KillHandle, SpawnSpec, WorkerParts, WorkerSpawner};

/// Plan value (PD-135): the ready frame must arrive within 10 s of the spawn, else the worker is
/// killed and the answer is `Spawn(TimedOut)`.
pub const READY_TIMEOUT: Duration = Duration::from_secs(10);
/// §3.4 (verbatim): "stderr is read by the host, capped at 64 KiB".
pub const STDERR_CAP: usize = 64 * 1024;
/// §3.4 (verbatim): "the per-run cap of 1 MiB and 10 000 lines" (bytes).
pub const LOG_CAP_BYTES: usize = 1024 * 1024;
/// §3.4 (verbatim): "the per-run cap of 1 MiB and 10 000 lines" (lines).
pub const LOG_CAP_LINES: usize = 10_000;
/// plan text (M8 T4 fix I-1): the message of the `TypeError` a result becomes when the core cannot
/// read it into a `serde_json::Value` (the worker's `RESULT_NOT_REPRESENTABLE`).
pub const RESULT_NOT_REPRESENTABLE: &str =
    "the result is not representable as JSON the host can read";
/// Host fact for [`RunOutcome::diag`]: the reaper failed, so the exit is unknown.
pub const DIAG_REAP_FAILED: &str = "sandbox_reap_failed";
/// Host fact for [`RunOutcome::diag`]: the bridge's reader ended without an outcome.
pub const DIAG_OUTCOME_LOST: &str = "sandbox_outcome_lost";
/// Host fact for [`RunOutcome::diag`]: the worker exited `EXIT_PROTOCOL` without a terminal
/// frame ([`HostVerdict::HostFault`]).
pub const DIAG_HOST_PROTOCOL_EXIT: &str = "sandbox_host_protocol_exit";
/// Host fact for [`RunOutcome::diag`]: a call's result was above the 24 MiB host → worker cap,
/// so the worker got a `result_too_large` rejection while core recorded the result (unreachable
/// while `max_call_result_mb` ≤ 16, PD-139).
pub const DIAG_CALL_RESULT_REPLACED: &str = "sandbox_call_result_replaced";
/// How often a kill is sent again until the worker is reaped (see the module documentation).
pub const KILL_RETRY: Duration = Duration::from_secs(1);

/// How long the outcome waits for the stderr thread after the reap (its pipe is closed by then).
const STDERR_GRACE: Duration = Duration::from_secs(2);
/// How long the bridge waits for the worker's own exit after its stdout ended, before it kills
/// (review m-4: a worker that closed stdout usually exits, and on Windows a kill between its
/// handles closing and its exit code being set would replace that code).
const EXIT_GRACE: Duration = Duration::from_secs(1);
/// serde_json reads at most 127 nested arrays or objects into a `Value`, and the worker decodes
/// the whole `script.run` frame into one, where `args` sits two objects deep.
const MAX_ARGS_NESTING: usize = 125;

/// §3.4 (verbatim form): the one marker kept when log lines were discarded past the caps.
pub fn log_truncated_marker(discarded_bytes: u64) -> String {
    format!("[log truncated: {discarded_bytes} bytes]")
}

/// Where a run's `host.call`s and log lines go (C.8). The glue forwards to `core::HostCalls`.
#[async_trait]
pub trait HostCallSink: Send + Sync {
    /// Runs one call. It runs as its own task and is never cancelled (PD-148); its result
    /// reaches the worker only if the run is undecided when it is ready.
    ///
    /// Return only after the call's `SCRIPT_CALL` record is committed: the bridge queues the
    /// result for the worker as soon as this returns.
    async fn call(&self, run_id: &str, c: HostCall) -> HostCallResult;
    /// One log line within the per-run caps, called on the bridge's reader thread: it must not
    /// block. The lines are also collected in [`RunOutcome::logs`].
    fn log(&self, run_id: &str, line: &str);
}

/// What the spawned worker must show in its ready frame (PD-133, PD-141).
#[derive(Debug, Clone)]
pub struct ExpectedWorker {
    /// The identity the probe recorded; its `embedded_version` must equal the ready frame's
    /// `worker_version`.
    pub identity: SandboxBinaryIdentity,
    /// Accept a ready frame whose `confinement.applied` is false. The glue sets it only when the
    /// policy allows degraded scripts and the startup probe found the floor not met (PD-141 (d)).
    pub accept_unconfined: bool,
}

/// Why the caller killed a run (the glue maps core's `KillReason` onto it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillCause {
    /// The agent's `cancel`.
    Client,
    /// The Running-scripts kill button.
    User,
    /// App shutdown.
    Shutdown,
    /// A limit core measured.
    Limit(String),
    /// An audit append failed.
    AuditFailure,
}

/// Why no run (or compile) started. The worker, if one was spawned, is killed and was sent
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartRunError {
    /// The binary is not the one the probe recorded (PD-133); the bridge itself reports
    /// [`IdentityPart::EmbeddedVersion`] from the ready frame.
    IdentityMismatch { what: IdentityPart },
    /// The ready frame shows no confinement and none was accepted (PD-141).
    FloorNotMet,
    /// No usable worker: the spawn failed (its error kind), no ready frame within
    /// [`READY_TIMEOUT`] (`TimedOut`), an unreadable ready frame (`InvalidData`), the worker
    /// ended before it (`UnexpectedEof`), or the init frame the worker could not read
    /// (`InvalidInput`, nothing spawned).
    Spawn(io::ErrorKind),
}

impl fmt::Display for StartRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartRunError::IdentityMismatch { what } => {
                write!(
                    f,
                    "the sandbox binary no longer matches the probe ({what:?})"
                )
            }
            StartRunError::FloorNotMet => f.write_str("the worker applied no confinement"),
            StartRunError::Spawn(kind) => write!(f, "no usable sandbox worker: {kind}"),
        }
    }
}

impl std::error::Error for StartRunError {}

/// The answer of a compile-only worker (PD-132, PD-135).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileVerdict {
    Compiled,
    Syntax {
        line: u32,
        column: u32,
        message: String,
    },
    /// The deadline expired, or the worker ended without a verdict (never a syntax error).
    Timeout,
}

/// What the worker's terminal frame said (untrusted payload, §9.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerEnd {
    /// `script.result`, the value's JSON text as received (it reads as a `serde_json::Value`).
    Result { value_json: Box<RawJsonText> },
    /// `script.error`, or a result the core could not read (`TypeError`,
    /// [`RESULT_NOT_REPRESENTABLE`]).
    Error {
        class: String,
        message: String,
        stack: String,
    },
    /// No terminal frame was accepted.
    None,
}

/// What the host observed (§9.5: classification uses host state only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostVerdict {
    /// A terminal frame decided the run; how the process exited after it does not matter.
    None,
    /// A limit the host measured (`timeout_s` here; M8 Task 9 adds the memory limits).
    Limit(&'static str),
    /// The caller killed the run.
    Killed(KillCause),
    /// The host killed the worker for a channel violation (`protocol_violation`).
    Violation(ViolationKind),
    /// The worker exited `EXIT_PROTOCOL` without a terminal frame: it could not read what the
    /// host sent. A host bug, never the script's doing (T4); the diag is
    /// [`DIAG_HOST_PROTOCOL_EXIT`].
    HostFault,
    /// The worker ended without a terminal frame (exit 0 included) and nothing above applies.
    /// `None`: the exit is unknown ([`DIAG_REAP_FAILED`], [`DIAG_OUTCOME_LOST`]).
    Crashed(Option<ExitKind>),
    /// For the glue: the run never started.
    NotSpawned(StartRunError),
}

/// How a run ended. [`RunHandleImpl::wait`] answers it once the worker is reaped.
#[derive(Debug, Clone, PartialEq)]
pub struct RunOutcome {
    pub end: WorkerEnd,
    pub host: HostVerdict,
    /// The `host.log` lines kept within the caps; when any was discarded, the last entry is
    /// [`log_truncated_marker`].
    pub logs: Vec<String>,
    /// Bytes of the discarded log lines, when any was discarded.
    pub logs_truncated: Option<u64>,
    /// The first [`STDERR_CAP`] bytes of stderr, lossily decoded.
    pub stderr: String,
    /// Host clock from before the spawn to the accepted terminal frame (to the reap without
    /// one); PD-134.
    pub elapsed: Duration,
    /// The worker's ready-frame report (PD-138, PD-141 (c)).
    pub confinement: ConfinementReport,
    /// Host facts for the glue's diagnostic log (constants only).
    pub diag: Vec<&'static str>,
}

/// A started run (Δ2).
pub struct RunHandleImpl {
    run: Arc<Run>,
    outcome: watch::Receiver<Option<RunOutcome>>,
}

impl RunHandleImpl {
    /// The bridge's id of this run, passed to every [`HostCallSink`] call (§3.4: one worker,
    /// one run id).
    pub fn run_id(&self) -> &str {
        &self.run.run_id
    }

    /// Kills the worker without waiting. The first decision wins: a cause given after the run
    /// was decided (terminal frame, timeout, violation, earlier kill) is not recorded. Never
    /// blocks: a short state lock (never held across a parse), then the non-blocking
    /// [`KillHandle`]. The run timer stays armed until the reap and kills again from `timeout_s`
    /// on if this kill did not take.
    pub fn kill(&self, cause: KillCause) {
        self.run.update(|inner| inner.state.on_kill(cause));
        self.run.kill.kill();
    }

    /// The run's outcome, once the worker is reaped; the same outcome every time. If the reader
    /// thread ended without one ([`DIAG_OUTCOME_LOST`]), the worker is killed.
    pub async fn wait(&self) -> RunOutcome {
        let mut rx = self.outcome.clone();
        let outcome = match rx.wait_for(Option::is_some).await {
            Ok(value) => value.clone(),
            Err(_) => None,
        };
        outcome.unwrap_or_else(|| {
            self.run.kill.kill();
            self.run.lost_outcome()
        })
    }
}

impl fmt::Debug for RunHandleImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunHandleImpl")
            .field("run_id", &self.run.run_id)
            .finish_non_exhaustive()
    }
}

/// Starts one script run (Δ2): spawn, ready frame, checks, `script.run`, then the run's threads.
///
/// Synchronous (spawn and the ready wait): the glue calls it through `spawn_blocking` (PD-138).
/// `rt` runs the host-call tasks and the run timer, so it needs tokio's time driver
/// (`enable_time`/`enable_all`); without it `start_run` panics before it spawns anything. The
/// timer (`timeout_s`, PD-135) is set just before `script.run` is handed to the writer, so the
/// worker never gets more than `timeout_s` from that moment; on expiry the worker is killed and
/// the verdict is `Limit("timeout_s")` unless something decided the run first. It runs until the
/// worker is reaped and kills again every [`KILL_RETRY`] from its expiry on, so it is also the
/// backstop for an earlier kill that did not take (T6: a failed kill shows only as a worker that
/// never ends).
pub fn start_run(
    spawner: &dyn WorkerSpawner,
    spec: &SpawnSpec,
    expect: &ExpectedWorker,
    init: WorkerInit,
    sink: Arc<dyn HostCallSink>,
    rt: Handle,
) -> Result<RunHandleImpl, StartRunError> {
    let started = Instant::now();
    // Created first: a `Sleep` panics at creation when `rt` has no time driver, so that happens
    // here, before the spawn, and not unseen in the timer task. Set below.
    let mut expiry = {
        let _rt = rt.enter();
        Box::pin(tokio::time::sleep(Duration::MAX))
    };
    let init_frame = encode_init(&init)?;
    let launched = launch(spawner, spec)?;
    let ready = match launched.ready(READY_TIMEOUT) {
        Ok(ready) => ready,
        Err(kind) => return Err(launched.refuse(StartRunError::Spawn(kind))),
    };
    if let Err(e) = check_ready(expect, &ready) {
        return Err(launched.refuse(e));
    }
    let Launched {
        kill,
        stdin,
        go,
        exit,
        stderr,
        ..
    } = launched;

    let (frames_tx, frames_rx) = mpsc::channel();
    if let Err(e) = writer::spawn(stdin, frames_rx) {
        give_up(kill, exit);
        return Err(spawn_error(&e));
    }
    let limit = Duration::from_secs(u64::from(init.limits.timeout_s));
    expiry.as_mut().reset(tokio::time::Instant::now() + limit);
    let _ = frames_tx.send(init_frame);

    let (outcome_tx, outcome) = watch::channel(None);
    let run = Arc::new(Run {
        run_id: next_run_id(),
        inner: Mutex::new(Inner {
            state: RunState::new(&init.limits),
            writer: Some(frames_tx),
            terminal_at: None,
            result_replaced: false,
        }),
        kill,
        sink,
        rt: rt.clone(),
        started,
        confinement: ready.confinement,
        read_cap: RunState::read_cap(&init.limits),
    });
    let reading = Arc::clone(&run);
    let continuation: Continuation = Box::new(move |stdout| {
        reading.read_until_end(stdout);
        reading.finish(&exit, &stderr, &outcome_tx);
    });
    if go.send(continuation).is_err() {
        // Unreachable while the stdout thread lives (it waits for this continuation). The
        // reaper's receiver went with the continuation, so this kill is not retried.
        run.kill.kill();
        return Err(StartRunError::Spawn(io::ErrorKind::BrokenPipe));
    }
    rt.spawn(run_timer(Arc::clone(&run), outcome.clone(), expiry));
    Ok(RunHandleImpl { run, outcome })
}

/// One compile check in a compile-only worker (PD-132): spawn, ready frame, `script.compile`, one
/// reply, kill. The ready frame, the compile and the reply are bounded by `deadline` (PD-135); on
/// expiry the worker is killed and the verdict is [`CompileVerdict::Timeout`]. Outside it are the
/// spawn call itself and, when the worker ended without a verdict, a wait of at most 1 s for its
/// exit code. A worker that ends without a verdict (T4: exit 101, 102, 103 or EOF) is `Timeout`
/// too, never `Syntax`; one that exits `EXIT_PROTOCOL` could not read the host's request (a host
/// fault, T4) and is `Spawn(InvalidData)`, like a reply that is no verdict. The worker is killed
/// again every [`KILL_RETRY`] until it is reaped, on a thread of its own: `compile_run` returns
/// without waiting for the reap. Synchronous: the glue calls it through `spawn_blocking`.
pub fn compile_run(
    spawner: &dyn WorkerSpawner,
    spec: &SpawnSpec,
    expect: &ExpectedWorker,
    source: &str,
    deadline: Duration,
) -> Result<CompileVerdict, StartRunError> {
    let started = Instant::now();
    let request = encode_notification(
        M_SCRIPT_COMPILE,
        &CompileRequest {
            source: source.to_owned(),
        },
    );
    if request.len() > HOST_TO_WORKER_MAX {
        return Err(StartRunError::Spawn(io::ErrorKind::InvalidInput));
    }
    let launched = launch(spawner, spec)?;
    let left = deadline.saturating_sub(started.elapsed());
    let ready = match launched.ready(left.min(READY_TIMEOUT)) {
        Ok(ready) => ready,
        Err(io::ErrorKind::TimedOut) if left <= READY_TIMEOUT => {
            launched.abandon();
            return Ok(CompileVerdict::Timeout);
        }
        Err(kind) => return Err(launched.refuse(StartRunError::Spawn(kind))),
    };
    if let Err(e) = check_ready(expect, &ready) {
        return Err(launched.refuse(e));
    }
    let Launched {
        kill,
        stdin,
        go,
        exit,
        ..
    } = launched;

    let (frames_tx, frames_rx) = mpsc::channel();
    if let Err(e) = writer::spawn(stdin, frames_rx) {
        give_up(kill, exit);
        return Err(spawn_error(&e));
    }
    let _ = frames_tx.send(request);
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    let continuation: Continuation = Box::new(move |mut stdout: Stdout| {
        let _ = reply_tx.send(reader::next_frame(&mut stdout, WORKER_FRAME_MAX_BYTES));
        reader::discard(stdout);
    });
    let _ = go.send(continuation);

    let reply = reply_rx.recv_timeout(deadline.saturating_sub(started.elapsed()));
    drop(frames_tx);
    let verdict = match reply {
        Ok(Frame::Bytes(bytes)) => match decode_worker_frame(&bytes) {
            Ok(WorkerFrame::Compiled) => Ok(CompileVerdict::Compiled),
            Ok(WorkerFrame::Syntax {
                line,
                column,
                message,
            }) => Ok(CompileVerdict::Syntax {
                line,
                column,
                message,
            }),
            _ => Err(StartRunError::Spawn(io::ErrorKind::InvalidData)),
        },
        Ok(Frame::TooLarge) => Err(StartRunError::Spawn(io::ErrorKind::InvalidData)),
        // The worker ended without a verdict. Its own exit code is read before any kill (m-4):
        // only `EXIT_PROTOCOL` is no `Timeout`. Once it is reaped (or its reap failed) there is
        // nothing left to kill.
        Ok(Frame::End) => match exit.recv_timeout(EXIT_GRACE) {
            Ok(Ok(ExitKind::Code(EXIT_PROTOCOL))) => {
                return Err(StartRunError::Spawn(io::ErrorKind::InvalidData));
            }
            Ok(_) => return Ok(CompileVerdict::Timeout),
            Err(_) => Ok(CompileVerdict::Timeout),
        },
        // The deadline expired.
        Err(_) => Ok(CompileVerdict::Timeout),
    };
    give_up(kill, exit);
    verdict
}

// ---- spawning and the ready frame --------------------------------------------------------------

/// A spawned, split worker whose threads (stdout, stderr, reaper) run.
struct Launched {
    kill: Arc<dyn KillHandle>,
    stdin: Box<dyn io::Write + Send>,
    /// The ready frame (or why there is none).
    ready: Receiver<Frame>,
    /// Tells the stdout thread what the rest of the stream is for; dropped, it discards.
    go: mpsc::SyncSender<Continuation>,
    exit: Receiver<io::Result<ExitKind>>,
    stderr: Receiver<String>,
}

impl Launched {
    /// The `probe.ready` frame within `wait`; the error kind says why not.
    fn ready(&self, wait: Duration) -> Result<ProbeReady, io::ErrorKind> {
        match self.ready.recv_timeout(wait) {
            Ok(Frame::Bytes(bytes)) => parse_ready(&bytes).ok_or(io::ErrorKind::InvalidData),
            Ok(Frame::TooLarge) => Err(io::ErrorKind::InvalidData),
            Ok(Frame::End) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(io::ErrorKind::UnexpectedEof)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::ErrorKind::TimedOut),
        }
    }

    /// Kills the worker and lets it go ([`give_up`]): stdin closes, the stdout thread discards to
    /// EOF and the reaper thread reaps.
    fn abandon(self) {
        give_up(self.kill, self.exit);
    }

    fn refuse(self, e: StartRunError) -> StartRunError {
        self.abandon();
        e
    }
}

fn launch(spawner: &dyn WorkerSpawner, spec: &SpawnSpec) -> Result<Launched, StartRunError> {
    let process = spawner.spawn(spec).map_err(|e| spawn_error(&e))?;
    let WorkerParts {
        io, kill, reaper, ..
    } = process.into_parts().map_err(|e| spawn_error(&e))?;
    // The reaper first: from here on, a failure kills and the reaper thread reaps. (Without the
    // reaper thread, the reaper's own drop kills and reaps.)
    let exit = reader::spawn_reaper(reaper).map_err(|e| {
        kill.kill();
        spawn_error(&e)
    })?;
    let readers = reader::spawn_stdout(io.stdout)
        .and_then(|(ready, go)| Ok((ready, go, reader::spawn_stderr(io.stderr)?)));
    let (ready, go, stderr) = match readers {
        Ok(readers) => readers,
        Err(e) => {
            give_up(kill, exit);
            return Err(spawn_error(&e));
        }
    };
    Ok(Launched {
        kill,
        stdin: io.stdin,
        ready,
        go,
        exit,
        stderr,
    })
}

/// Kills a worker the bridge no longer uses, and kills it again every [`KILL_RETRY`] until its
/// reaper thread reports the reap (`exit`), without waiting for that.
fn give_up(kill: Arc<dyn KillHandle>, exit: Receiver<io::Result<ExitKind>>) {
    kill.kill();
    reader::rekill_until_reaped(kill, exit, KILL_RETRY);
}

fn spawn_error(e: &io::Error) -> StartRunError {
    StartRunError::Spawn(e.kind())
}

fn parse_ready(bytes: &[u8]) -> Option<ProbeReady> {
    let (method, params) = decode_notification(bytes).ok()?;
    if method != M_PROBE_READY {
        return None;
    }
    serde_json::from_value(params).ok()
}

/// PD-133 (embedded version) and PD-141 (confinement), before any frame is sent.
fn check_ready(expect: &ExpectedWorker, ready: &ProbeReady) -> Result<(), StartRunError> {
    if ready.worker_version != expect.identity.embedded_version {
        return Err(StartRunError::IdentityMismatch {
            what: IdentityPart::EmbeddedVersion,
        });
    }
    if !ready.confinement.applied && !expect.accept_unconfined {
        return Err(StartRunError::FloorNotMet);
    }
    Ok(())
}

/// The `script.run` frame, refused before any spawn when the worker could not read it: above
/// the 24 MiB host → worker cap, or `args` nested deeper than the worker's decoder reads (T4
/// fix hand-off: the worker would exit `EXIT_PROTOCOL` on it).
fn encode_init(init: &WorkerInit) -> Result<Vec<u8>, StartRunError> {
    if nesting(&init.args) > MAX_ARGS_NESTING {
        return Err(StartRunError::Spawn(io::ErrorKind::InvalidInput));
    }
    let frame = encode_notification(M_SCRIPT_RUN, init);
    if frame.len() > HOST_TO_WORKER_MAX {
        return Err(StartRunError::Spawn(io::ErrorKind::InvalidInput));
    }
    Ok(frame)
}

/// The deepest nesting of arrays and objects in `v` (a scalar is 0), without recursion.
fn nesting(v: &Value) -> usize {
    let mut deepest = 0;
    let mut stack = vec![(v, 0usize)];
    while let Some((v, depth)) = stack.pop() {
        let children: Box<dyn Iterator<Item = &Value>> = match v {
            Value::Array(items) => Box::new(items.iter()),
            Value::Object(map) => Box::new(map.values()),
            _ => continue,
        };
        deepest = deepest.max(depth + 1);
        stack.extend(children.map(|c| (c, depth + 1)));
    }
    deepest
}

fn next_run_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("run-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

// ---- one run ------------------------------------------------------------------------------------

/// What the run's threads and tasks share.
struct Run {
    run_id: String,
    inner: Mutex<Inner>,
    kill: Arc<dyn KillHandle>,
    sink: Arc<dyn HostCallSink>,
    rt: Handle,
    started: Instant,
    confinement: ConfinementReport,
    read_cap: usize,
}

struct Inner {
    state: RunState,
    /// The writer's queue; dropped once the run is decided (the worker's stdin closes).
    writer: Option<Sender<Vec<u8>>>,
    terminal_at: Option<Instant>,
    /// A call result was replaced by a rejection ([`DIAG_CALL_RESULT_REPLACED`]).
    result_replaced: bool,
}

impl Run {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `f` under the run lock; once the run is decided, the writer's queue is dropped.
    fn update<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        let mut inner = self.lock();
        let out = f(&mut inner);
        if inner.state.decided() {
            inner.writer = None;
        }
        out
    }

    /// The reader thread's run loop: decodes and classifies every frame until EOF, both before
    /// the run lock is taken (I-1); after a violation it discards the rest of the stream.
    fn read_until_end(self: &Arc<Self>, mut stdout: Stdout) {
        loop {
            match reader::next_frame(&mut stdout, self.read_cap) {
                Frame::End => return,
                Frame::TooLarge => {
                    let step = self.update(|inner| inner.state.on_oversize_header());
                    self.act(step);
                    reader::discard(stdout);
                    return;
                }
                Frame::Bytes(bytes) => {
                    let len = bytes.len();
                    let decoded = decode_worker_frame(&bytes).map(Incoming::from);
                    drop(bytes);
                    let (step, violated) = self.update(|inner| {
                        let step = inner.state.on_frame(len, decoded);
                        if step == Step::Terminal {
                            inner.terminal_at = Some(Instant::now());
                        }
                        (step, inner.state.violated())
                    });
                    self.act(step);
                    if violated {
                        reader::discard(stdout);
                        return;
                    }
                }
            }
        }
    }

    fn act(self: &Arc<Self>, step: Step) {
        match step {
            Step::Nothing => {}
            Step::Log(line) => self.sink.log(&self.run_id, &line),
            Step::Call(call) => self.dispatch(call),
            // The run is decided: the worker is killed (after a terminal frame without a cause,
            // so that it is reaped even if it does not exit). The timer stays armed until the
            // reap, the backstop if this kill does not take.
            Step::Terminal | Step::Violation => self.kill.kill(),
        }
    }

    /// PD-148: each call is its own task on the caller's runtime and is never aborted; it
    /// outlives the worker if need be.
    fn dispatch(self: &Arc<Self>, call: HostCall) {
        let run = Arc::clone(self);
        self.rt.spawn(async move {
            let id = call.id;
            let result = run.sink.call(&run.run_id, call).await;
            run.answer(id, &result);
        });
    }

    /// Queues a call's result while the run is undecided; the call stops counting as
    /// outstanding in the same locked step (§3.4 "until its result has been queued").
    fn answer(&self, id: u64, result: &HostCallResult) {
        let (frame, replaced) = writer::call_response(id, result);
        let mut inner = self.lock();
        if inner.state.complete_call()
            && let Some(writer) = &inner.writer
        {
            let _ = writer.send(frame);
            inner.result_replaced |= replaced;
        }
    }

    /// After stdout's EOF: wait for the reap (the worker exited, or it closed its stdout and is
    /// killed, [`exit_after_eof`]), then publish the outcome. The run timer stops at that.
    fn finish(
        &self,
        exit: &Receiver<io::Result<ExitKind>>,
        stderr: &Receiver<String>,
        outcome: &watch::Sender<Option<RunOutcome>>,
    ) {
        let exit = exit_after_eof(self.kill.as_ref(), exit);
        let stderr = stderr.recv_timeout(STDERR_GRACE).unwrap_or_default();
        let mut diag = Vec::new();
        if exit.is_none() {
            diag.push(DIAG_REAP_FAILED);
        }
        let done = {
            let mut inner = self.lock();
            inner.writer = None;
            if !inner.state.terminal() && exit == Some(ExitKind::Code(EXIT_PROTOCOL)) {
                diag.push(DIAG_HOST_PROTOCOL_EXIT);
            }
            if inner.result_replaced {
                diag.push(DIAG_CALL_RESULT_REPLACED);
            }
            let (logs, logs_truncated) = inner.state.take_logs();
            let ended = inner.terminal_at.unwrap_or_else(Instant::now);
            RunOutcome {
                host: inner.state.verdict(exit),
                end: inner.state.take_end(),
                logs,
                logs_truncated,
                stderr,
                elapsed: ended.saturating_duration_since(self.started),
                confinement: self.confinement.clone(),
                diag,
            }
        };
        outcome.send_replace(Some(done));
    }

    /// The outcome when the reader thread ended without publishing one.
    fn lost_outcome(&self) -> RunOutcome {
        RunOutcome {
            end: WorkerEnd::None,
            host: HostVerdict::Crashed(None),
            logs: Vec::new(),
            logs_truncated: None,
            stderr: String::new(),
            elapsed: self.started.elapsed(),
            confinement: self.confinement.clone(),
            diag: vec![DIAG_OUTCOME_LOST],
        }
    }
}

/// The worker's exit once its stdout ended (`None` when the reap failed). It usually exited, so
/// its own exit code is awaited first, for [`EXIT_GRACE`]; only a worker still running after that
/// is killed (it closed its stdout and must not outlive it). A kill right at EOF could replace
/// the exit code on Windows (m-4). After that kill the wait is unbounded: the run timer kills
/// again until the reap.
fn exit_after_eof(
    kill: &dyn KillHandle,
    exit: &Receiver<io::Result<ExitKind>>,
) -> Option<ExitKind> {
    let reaped = match exit.recv_timeout(EXIT_GRACE) {
        Ok(reaped) => reaped,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            kill.kill();
            exit.recv().ok()?
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => return None,
    };
    reaped.ok()
}

/// PD-135: kills the run at `expiry` (`timeout_s` after `script.run` was handed to the writer),
/// unless the outcome was published first (it is, after the reap). The cause `timeout_s` is
/// recorded only if nothing decided the run before. From the expiry on it kills every
/// [`KILL_RETRY`] until the reap (a no-op unless an earlier kill did not take, T6). If the reader
/// thread ends without an outcome, the worker is killed at once (review m-5).
async fn run_timer(
    run: Arc<Run>,
    mut outcome: watch::Receiver<Option<RunOutcome>>,
    mut expiry: Pin<Box<Sleep>>,
) {
    let before_expiry = {
        let mut published = pin!(published(&mut outcome));
        poll_fn(|cx| match published.as_mut().poll(cx) {
            Poll::Ready(published) => Poll::Ready(Some(published)),
            Poll::Pending => expiry.as_mut().poll(cx).map(|()| None),
        })
        .await
    };
    match before_expiry {
        Some(true) => return,
        Some(false) => {
            run.kill.kill();
            return;
        }
        None => {}
    }
    run.update(|inner| inner.state.on_timeout());
    loop {
        run.kill.kill();
        if tokio::time::timeout(KILL_RETRY, published(&mut outcome))
            .await
            .is_ok()
        {
            return;
        }
    }
}

/// `true` once the outcome is published, `false` once it never will be (the reader thread ended
/// without one).
async fn published(outcome: &mut watch::Receiver<Option<RunOutcome>>) -> bool {
    outcome.wait_for(Option::is_some).await.is_ok()
}

#[cfg(test)]
mod tests {
    use atlas_duck_ipc::sandbox::ScriptLimits;
    use serde_json::json;

    use super::*;

    fn nested(depth: usize) -> Value {
        let mut v = json!(1);
        for _ in 0..depth {
            v = json!([v]);
        }
        v
    }

    #[test]
    fn nesting_counts_arrays_and_objects() {
        assert_eq!(nesting(&json!(1)), 0);
        assert_eq!(nesting(&json!([])), 1);
        assert_eq!(nesting(&json!({"a": [1, {"b": []}]})), 4);
        assert_eq!(nesting(&json!([[1], [[2]], 3])), 3);
        assert_eq!(nesting(&nested(7)), 7);
    }

    /// The host refuses exactly the `args` the worker's decoder (a `Value` of the whole frame)
    /// would refuse.
    #[test]
    fn init_nesting_matches_the_worker_decoder() {
        for depth in [MAX_ARGS_NESTING - 1, MAX_ARGS_NESTING, MAX_ARGS_NESTING + 1] {
            let mut args = json!(0);
            for i in 0..depth {
                args = if i % 2 == 0 {
                    json!([args])
                } else {
                    json!({ "k": args })
                };
            }
            let init = WorkerInit {
                source: String::new(),
                args: args.clone(),
                limits: ScriptLimits::default(),
                read_op_ids: Vec::new(),
                instances: Vec::new(),
            };
            let frame = encode_notification(M_SCRIPT_RUN, &init);
            let worker_reads = decode_notification(&frame).is_ok();
            assert_eq!(encode_init(&init).is_ok(), worker_reads, "depth {depth}");
            assert_eq!(worker_reads, depth <= MAX_ARGS_NESTING, "depth {depth}");
        }
    }

    #[test]
    fn ready_must_match_version_and_confinement() {
        let ready = |version: &str, applied: bool| ProbeReady {
            worker_version: version.to_owned(),
            engine_version: "e".to_owned(),
            confinement: ConfinementReport {
                applied,
                mechanism: "m".to_owned(),
                no_new_privs: None,
                landlock_abi: None,
                seccomp: None,
                lpac: None,
                os_error: None,
            },
        };
        let expect = |accept_unconfined| ExpectedWorker {
            identity: SandboxBinaryIdentity {
                file_id: crate::identity::FileId::DevIno { dev: 1, ino: 2 },
                size: 3,
                mtime: std::time::SystemTime::UNIX_EPOCH,
                embedded_version: "v1".to_owned(),
            },
            accept_unconfined,
        };
        assert_eq!(check_ready(&expect(false), &ready("v1", true)), Ok(()));
        assert_eq!(
            check_ready(&expect(true), &ready("v2", false)),
            Err(StartRunError::IdentityMismatch {
                what: IdentityPart::EmbeddedVersion
            }),
            "the version is checked first"
        );
        assert_eq!(
            check_ready(&expect(false), &ready("v1", false)),
            Err(StartRunError::FloorNotMet)
        );
        assert_eq!(check_ready(&expect(true), &ready("v1", false)), Ok(()));
    }

    #[test]
    fn the_ready_frame_must_be_probe_ready() {
        let frame = encode_notification(M_PROBE_READY, &json!({"worker_version": "v"}));
        assert!(parse_ready(&frame).is_none(), "missing fields");
        let frame = encode_notification("probe.result", &json!({}));
        assert!(parse_ready(&frame).is_none());
        assert!(parse_ready(b"{").is_none());
    }

    #[test]
    fn run_ids_are_unique() {
        assert_ne!(next_run_id(), next_run_id());
    }
}
