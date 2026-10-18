//! The script engine of a run worker (spec §9.2, §9.3, §9.4; plan M8 PD-131, PD-134, PD-135,
//! PD-136, PD-151, PD-152).
//!
//! One [`Engine`] per run, on the worker's main thread: a fresh QuickJS runtime whose allocations
//! go through a [`alloc::LimitAllocator`] of `heap_mb`, the M1 intrinsic set, the `Date` prelude,
//! the `atlas` shim and the agent's source wrapped as
//! `(async function main(args, atlas) {\n<source>\n})`. The run loop (Task 4) drives it:
//! [`Engine::start`], then [`Engine::drain_jobs`] after every entry, [`Engine::deliver`] for each
//! host frame. Host calls and log lines go out synchronously through the [`HostPort`] while the
//! script runs; after a heap refusal nothing more is sent (PD-134).
//!
//! [`compile`] is the compile mode: it evaluates the wrapper in a fresh runtime and reports a
//! syntax error with its position in the agent's source (wrapper line − 1).

#![deny(clippy::unwrap_used, clippy::expect_used, unsafe_code)]

#[allow(unsafe_code)]
pub mod alloc;
pub mod interrupt;
pub(crate) mod loop_;
mod shim;

use std::cell::{Cell, Ref, RefCell, RefMut};
use std::io;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use atlas_duck_ipc::sandbox::script::{WorkerInit, terminal_frame_max};
use atlas_duck_ipc::sandbox::{HostCall, MAX_FRAME_BYTES, ScriptLimits};
use rquickjs::function::This;
use rquickjs::promise::PromiseState;
use rquickjs::runtime::MemoryUsage;
use rquickjs::{
    CatchResultExt, CaughtError, Context, Ctx, Exception, Function, Object, Persistent, Promise,
    Runtime, Value,
};

use crate::engine::{new_context, new_runtime_with_heap_limit};
use alloc::LimitState;
use interrupt::{Deadline, OpBudget, backstop};

pub use shim::{CALL_NOT_DECODABLE, CALL_TOO_LARGE, PRELUDE_JS, SHIM_JS};

const MIB: usize = 1024 * 1024;

/// The slack `terminal_frame_max` adds above `max_result_mb` for the frame envelope (§3.4).
const TERMINAL_FRAME_SLACK: usize = 64 * 1024;

/// The worker's compile-mode backstop: the host's 10 s compile deadline (PD-135) plus the 2 s
/// slack of [`interrupt::BACKSTOP_SLACK`] (plan value).
pub const COMPILE_BACKSTOP: Duration = Duration::from_secs(12);

const WRAPPER_PREFIX: &str = "(async function main(args, atlas) {\n";
const WRAPPER_SUFFIX: &str = "\n})";

/// Plan text: the agent's source closed the wrapper function and added code outside it.
pub const WRAPPER_ESCAPE: &str = "the source closes the wrapper function main";

/// Plan text: QuickJS takes C strings, so a NUL character cannot be compiled.
pub const NUL_IN_SOURCE: &str = "the source contains a NUL character";

/// Plan text (PD-136): the result's JSON text does not fit the terminal frame.
pub const RESULT_TOO_LARGE: &str = "the result is above max_result_mb";

/// Plan text: a thrown value whose text could not be read (as in the shim's `describe`).
pub const UNDESCRIBABLE: &str = "the thrown value could not be described";

/// The wrapper the agent's source is compiled in (§9.2): the body of
/// `async function main(args, atlas)`.
pub fn wrapper_source(source: &str) -> String {
    let mut s = String::with_capacity(WRAPPER_PREFIX.len() + source.len() + WRAPPER_SUFFIX.len());
    s.push_str(WRAPPER_PREFIX);
    s.push_str(source);
    s.push_str(WRAPPER_SUFFIX);
    s
}

/// Where the worker's frames go. Both sends are synchronous and happen while the script runs.
pub trait HostPort {
    /// Writes one `host.call` request.
    fn send_call(&mut self, id: u64, call: &HostCall) -> io::Result<()>;
    /// Writes one `host.log` line.
    fn send_log(&mut self, line: &str) -> io::Result<()>;
}

/// A compile failure, positioned in the agent's source (1-based; 0 when QuickJS gave none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxPos {
    pub line: u32,
    pub column: u32,
    pub message: String,
}

/// Why a run stopped without a settlement of `main`. Sticky: once set, every entry reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Halt {
    /// The QuickJS allocator refused a request above `heap_mb` (PD-134 → `EXIT_HEAP_LIMIT`).
    HeapLimit,
    /// An allocation failed below `heap_mb`: the process is out of memory (→ `EXIT_PROCESS_LIMIT`).
    ProcessLimit,
    /// The worker's backstop deadline (`timeout_s + 2 s`) passed (a runtime error, PD-135).
    Deadline,
    /// The run used up its interrupt-callback budget (a runtime error, PD-135).
    OpBudget,
    /// A send to the host failed (→ `EXIT_IO`).
    Io(io::ErrorKind),
    /// A host frame the dispatcher cannot use (→ `EXIT_PROTOCOL`).
    Protocol(&'static str),
    /// An engine failure that is neither the script's nor the host's.
    Engine(&'static str),
}

/// Why compile mode produced no verdict on the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    Syntax(SyntaxPos),
    Halted(Halt),
}

/// Why a run engine could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// The wrapped source does not compile (a submit-time compile check passed, so this is a
    /// runtime outcome of the run).
    Syntax(SyntaxPos),
    Halted(Halt),
    /// The init data does not fit the shim: an op id that cannot be placed under `atlas` (a
    /// reserved or single segment, an empty segment, a duplicate). The host's fault; every other
    /// set-up failure is `Halted(Halt::Engine(_))`.
    Init(String),
}

/// What `main` threw or rejected with, as untrusted payload (§9.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptError {
    pub class: String,
    pub message: String,
    pub stack: String,
}

/// The state of a run after its job queue is drained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settled {
    /// `main` has not settled; `outstanding` host calls were sent and not answered. With 0
    /// outstanding the script can never settle (the loop's `ScriptStalled`, PD-131).
    Pending {
        outstanding: usize,
    },
    /// `main` fulfilled; the JSON text of its value (`undefined` → `null`), within the terminal
    /// frame's budget.
    Result(String),
    /// `main` rejected, or its value is not JSON or too large (`TypeError`, `ResultTooLarge`).
    Error(ScriptError),
    Halted(Halt),
}

enum Outcome {
    Result(String),
    Error(ScriptError),
}

/// State shared by the engine, the natives and the interrupt handler.
struct Shared<H> {
    host: RefCell<H>,
    meter: Arc<LimitState>,
    halt: Cell<Option<Halt>>,
    outcome: RefCell<Option<Outcome>>,
    outstanding: Cell<usize>,
    /// The id of the last `host.call` sent; the next one must be above it.
    last_call_id: Cell<u64>,
    deadline: Deadline,
}

impl<H> Shared<H> {
    /// The run's halt, if any. A heap refusal wins over everything (PD-134), then an exhausted
    /// process, then the first recorded halt.
    fn halted(&self) -> Option<Halt> {
        meter_halt(&self.meter).or(self.halt.get())
    }

    fn set_halt(&self, halt: Halt) {
        if self.halt.get().is_none() {
            self.halt.set(Some(halt));
        }
    }

    /// The first settlement of `main` wins.
    fn settle(&self, outcome: Outcome) {
        let mut slot = self.outcome.borrow_mut();
        if slot.is_none() {
            *slot = Some(outcome);
        }
    }

    /// The interrupt handler: `true` stops the script with an uncatchable error.
    fn interrupt(&self, budget: &mut OpBudget) -> bool {
        if self.halted().is_some() {
            return true;
        }
        if self.deadline.expired() {
            self.set_halt(Halt::Deadline);
            return true;
        }
        if budget.tick() {
            self.set_halt(Halt::OpBudget);
            return true;
        }
        false
    }
}

fn meter_halt(meter: &LimitState) -> Option<Halt> {
    if meter.heap_refused() {
        Some(Halt::HeapLimit)
    } else if meter.system_null() {
        Some(Halt::ProcessLimit)
    } else {
        None
    }
}

type MainPromise = Persistent<Promise<'static>>;

/// The script engine of one run.
pub struct Engine<H: HostPort + 'static> {
    // The persistent handles come first: they must be dropped while the runtime is alive.
    main: Persistent<Function<'static>>,
    start_fn: Persistent<Function<'static>>,
    deliver_fn: Persistent<Function<'static>>,
    fulfilled_fn: Persistent<Function<'static>>,
    fail_fn: Persistent<Function<'static>>,
    /// The promise `main` returned, once started.
    main_promise: Option<MainPromise>,
    ctx: Context,
    rt: Runtime,
    shared: Rc<Shared<H>>,
    result_max: usize,
    started: bool,
    finished: bool,
}

impl<H: HostPort + 'static> Engine<H> {
    /// Builds the run's runtime, prelude, shim and wrapper, with the worker's backstop deadline
    /// (`timeout_s + 2 s` from now) and the default op budget. Nothing of the body runs yet.
    pub fn new(init: &WorkerInit, host: H) -> Result<Self, EngineError> {
        Self::with_interrupts(
            init,
            host,
            Deadline::after(backstop(&init.limits)),
            OpBudget::default(),
        )
    }

    /// [`Engine::new`] with an explicit deadline and op budget.
    pub fn with_interrupts(
        init: &WorkerInit,
        host: H,
        deadline: Deadline,
        mut ops: OpBudget,
    ) -> Result<Self, EngineError> {
        let heap = (init.limits.heap_mb as usize).saturating_mul(MIB);
        let (rt, meter) = new_runtime_with_heap_limit(heap)
            .map_err(|_| EngineError::Halted(Halt::Engine("the runtime could not be created")))?;
        // From here on a panic after a heap refusal exits `EXIT_HEAP_LIMIT` (PD-134).
        crate::set_run_meter(Arc::clone(&meter));
        let shared = Rc::new(Shared {
            host: RefCell::new(host),
            meter,
            halt: Cell::new(None),
            outcome: RefCell::new(None),
            outstanding: Cell::new(0),
            last_call_id: Cell::new(0),
            deadline,
        });
        let in_handler = Rc::clone(&shared);
        rt.set_interrupt_handler(Some(Box::new(move || in_handler.interrupt(&mut ops))));
        let ctx = new_context(&rt).map_err(|_| halted_or(&shared, Halt::Engine("no context")))?;

        let result_max = terminal_frame_max(&init.limits).saturating_sub(TERMINAL_FRAME_SLACK);
        // The loop's cap for a `script.error` frame (`write_frame` refuses anything above the
        // channel's general cap).
        let error_max = terminal_frame_max(&init.limits).min(MAX_FRAME_BYTES);
        let config = shim::config_json(
            &init.read_op_ids,
            &init.instances,
            &init.args,
            init.limits.max_concurrent_calls,
            result_max,
            error_max,
        )
        .map_err(|_| EngineError::Halted(Halt::Engine("the init data does not serialize")))?;

        type Handles = [Persistent<Function<'static>>; 5];
        let built = ctx.with(|ctx| -> Result<Handles, EngineError> {
            // Captured before any agent code can run (the wrapper's own evaluation included).
            let to_string = function_to_string(&ctx)
                .map_err(|_| engine_fault(&ctx, "Function.prototype.toString"))?;
            shim::install_prelude(&ctx)
                .map_err(|_| engine_fault(&ctx, "the prelude could not be installed"))?;
            // Only the shim's refusal of the init data is the host's fault (`EXIT_PROTOCOL`).
            let api = shim::install_shim(&ctx, &shared, &config).map_err(|err| match err {
                shim::ShimError::Refused(message) => EngineError::Init(message),
                shim::ShimError::Engine => engine_fault(&ctx, "the shim could not be installed"),
            })?;
            let main =
                compile_wrapper(&ctx, &to_string, &init.source).map_err(|err| match err {
                    CompileError::Syntax(pos) => EngineError::Syntax(pos),
                    CompileError::Halted(halt) => EngineError::Halted(halt),
                })?;
            Ok([main, api.start, api.deliver, api.fulfilled, api.fail]
                .map(|function| Persistent::save(&ctx, function)))
        });
        // A halt during set-up (a heap refusal, the deadline) explains any error it caused.
        if let Some(halt) = shared.halted() {
            return Err(EngineError::Halted(halt));
        }
        let [main, start_fn, deliver_fn, fulfilled_fn, fail_fn] = built?;
        Ok(Engine {
            main,
            start_fn,
            deliver_fn,
            fulfilled_fn,
            fail_fn,
            main_promise: None,
            ctx,
            rt,
            shared,
            result_max,
            started: false,
            finished: false,
        })
    }

    /// Calls `main(args, atlas)`: the body runs up to its first `await`. Call once.
    ///
    /// The shim's `start` catches everything agent code can throw, so only a halt (an
    /// uncatchable interrupt) makes the call fail.
    pub fn start(&mut self) -> Result<(), Halt> {
        if let Some(halt) = self.shared.halted() {
            return Err(halt);
        }
        if self.started {
            return Err(Halt::Engine("start called twice"));
        }
        self.started = true;
        let called = self
            .ctx
            .with(|ctx| -> rquickjs::Result<Option<MainPromise>> {
                let start = self.start_fn.clone().restore(&ctx)?;
                let main = self.main.clone().restore(&ctx)?;
                let returned: Value = start
                    .call((main,))
                    .catch(&ctx)
                    .map_err(|_| rquickjs::Error::Unknown)?;
                Ok(returned
                    .into_promise()
                    .map(|promise| Persistent::save(&ctx, promise)))
            });
        if let Some(halt) = self.shared.halted() {
            return Err(halt);
        }
        self.main_promise = called.map_err(|_| Halt::Engine("starting main failed"))?;
        Ok(())
    }

    /// Runs promise jobs until none is pending (PD-131 step 1) and reports the run's state.
    pub fn drain_jobs(&mut self) -> Settled {
        loop {
            if let Some(halt) = self.halt_now() {
                return Settled::Halted(halt);
            }
            if !self.rt.is_job_pending() {
                break;
            }
            if self.rt.execute_pending_job().is_err() {
                if let Some(halt) = self.shared.halted() {
                    return Settled::Halted(halt);
                }
                // Promise reactions turn exceptions into rejections; an exception escapes a job
                // only from a `queueMicrotask` callback. Like an uncaught exception it ends the
                // run as a script error, unless `main` settled first. The shim's `fail` describes
                // it, as it describes a rejection of `main`.
                self.ctx.with(|ctx| {
                    let thrown = ctx.catch();
                    self.observe_main(&ctx);
                    // Once main's state decided the run, describing the thrown value would only
                    // run its getters for a settlement that is discarded.
                    let undecided = self.shared.outcome.borrow().is_none();
                    if undecided && self.shared.halted().is_none() {
                        self.record(&ctx, &self.fail_fn, thrown);
                    }
                });
                if let Some(halt) = self.shared.halted() {
                    return Settled::Halted(halt);
                }
                break;
            }
        }
        if self.finished {
            return Settled::Halted(Halt::Engine("the run already settled"));
        }
        self.ctx.with(|ctx| self.observe_main(&ctx));
        if let Some(halt) = self.shared.halted() {
            return Settled::Halted(halt);
        }
        let outcome = self.shared.outcome.borrow_mut().take();
        match outcome {
            None => Settled::Pending {
                outstanding: self.shared.outstanding.get(),
            },
            Some(outcome) => {
                self.finished = true;
                match outcome {
                    Outcome::Result(text) if text.len() > self.result_max => {
                        Settled::Error(ScriptError {
                            class: "ResultTooLarge".to_owned(),
                            message: RESULT_TOO_LARGE.to_owned(),
                            stack: String::new(),
                        })
                    }
                    Outcome::Result(text) => Settled::Result(text),
                    Outcome::Error(err) => Settled::Error(err),
                }
            }
        }
    }

    /// Hands one host frame's text (a JSON-RPC response to a `host.call`) to the dispatcher,
    /// which parses it once inside QuickJS and settles the call's promise (PD-131 step 3).
    pub fn deliver(&mut self, frame_text: &str) -> Result<(), Halt> {
        if let Some(halt) = self.shared.halted() {
            return Err(halt);
        }
        // As in `drain_jobs`: after the settlement no agent code runs (the loop never delivers
        // then).
        if self.finished {
            return Err(Halt::Engine("the run already settled"));
        }
        let answer = self.ctx.with(|ctx| -> rquickjs::Result<i32> {
            let deliver = self.deliver_fn.clone().restore(&ctx)?;
            deliver
                .call::<_, i32>((frame_text,))
                .catch(&ctx)
                .map_err(|_| rquickjs::Error::Unknown)
        });
        if let Some(halt) = self.shared.halted() {
            return Err(halt);
        }
        match answer {
            Ok(0) => {
                let left = self.shared.outstanding.get().saturating_sub(1);
                self.shared.outstanding.set(left);
                Ok(())
            }
            Ok(1) => Err(Halt::Protocol("the host frame is not JSON")),
            Ok(2) => Err(Halt::Protocol("the host frame is not a host call response")),
            Ok(3) => Err(Halt::Protocol("the host frame answers no outstanding call")),
            _ => Err(Halt::Engine("the dispatcher failed")),
        }
    }

    /// Host calls sent and not yet answered.
    pub fn outstanding(&self) -> usize {
        self.shared.outstanding.get()
    }

    /// The allocator's count and flags (PD-134), for the loop, the panic hook and Task 25.
    pub fn meter(&self) -> &Arc<LimitState> {
        &self.shared.meter
    }

    /// QuickJS's own memory statistics (its `malloc_limit` stays 0: `set_memory_limit` is never
    /// called, PD-134).
    pub fn memory_usage(&self) -> MemoryUsage {
        self.rt.memory_usage()
    }

    /// Runs QuickJS's cycle collector (Task 25 measures what stays after it). A run never calls
    /// this: QuickJS collects by itself.
    pub fn run_gc(&self) {
        self.rt.run_gc();
    }

    /// The host port.
    pub fn host(&self) -> Ref<'_, H> {
        self.shared.host.borrow()
    }

    /// The host port, mutably (never while the script runs).
    pub fn host_mut(&self) -> RefMut<'_, H> {
        self.shared.host.borrow_mut()
    }

    /// Records how `main` settled from its promise's own state (`JS_PromiseState`, no property
    /// lookup, no agent code), when nothing is recorded yet. The shim's observer normally records
    /// it first; QuickJS-NG drops that observer when reading the promise's `constructor` throws
    /// (it rejects the observer's own promise instead of throwing at its `await`).
    fn observe_main(&self, ctx: &Ctx<'_>) {
        if self.shared.outcome.borrow().is_some() {
            return;
        }
        let Some(promise) = &self.main_promise else {
            return;
        };
        let Ok(promise) = promise.clone().restore(ctx) else {
            return;
        };
        let recorder = match promise.state() {
            PromiseState::Pending => return,
            PromiseState::Resolved => &self.fulfilled_fn,
            PromiseState::Rejected => &self.fail_fn,
        };
        // A rejection value comes back as the pending exception.
        let value = match promise.result::<Value>() {
            Some(Ok(value)) => value,
            _ => ctx.catch(),
        };
        self.record(ctx, recorder, value);
    }

    /// Calls the shim's `fulfilled` or `fail` with `value`. Both catch what agent code throws;
    /// should one fail anyway without a halt, the run still ends as a script error.
    fn record<'js>(
        &self,
        ctx: &Ctx<'js>,
        recorder: &Persistent<Function<'static>>,
        value: Value<'js>,
    ) {
        let called = recorder.clone().restore(ctx).and_then(|recorder| {
            recorder
                .call::<_, ()>((value,))
                .catch(ctx)
                .map_err(|_| rquickjs::Error::Unknown)
        });
        if called.is_err() && self.shared.halted().is_none() {
            self.shared.settle(Outcome::Error(ScriptError {
                class: "Error".to_owned(),
                message: UNDESCRIBABLE.to_owned(),
                stack: String::new(),
            }));
        }
    }

    /// The halt, also checking the deadline between promise jobs (a job loop may run without
    /// reaching an interrupt check).
    fn halt_now(&self) -> Option<Halt> {
        if let Some(halt) = self.shared.halted() {
            return Some(halt);
        }
        if self.shared.deadline.expired() {
            self.shared.set_halt(Halt::Deadline);
            return Some(Halt::Deadline);
        }
        None
    }
}

/// Compile mode: evaluates the wrapper in a fresh runtime with the default heap limit and the
/// compile backstop. The body never runs; a source that escapes the wrapper is refused.
pub fn compile(source: &str) -> Result<(), CompileError> {
    let heap = (ScriptLimits::default().heap_mb as usize).saturating_mul(MIB);
    let (rt, meter) = new_runtime_with_heap_limit(heap)
        .map_err(|_| CompileError::Halted(Halt::Engine("the runtime could not be created")))?;
    // As in a run: a panic after a heap refusal exits `EXIT_HEAP_LIMIT` (PD-134).
    crate::set_run_meter(Arc::clone(&meter));
    let deadline = Deadline::after(COMPILE_BACKSTOP);
    let fired: Rc<Cell<Option<Halt>>> = Rc::new(Cell::new(None));
    {
        let meter = Arc::clone(&meter);
        let fired = Rc::clone(&fired);
        let mut budget = OpBudget::default();
        rt.set_interrupt_handler(Some(Box::new(move || {
            if meter_halt(&meter).is_some() || fired.get().is_some() {
                return true;
            }
            let halt = if deadline.expired() {
                Halt::Deadline
            } else if budget.tick() {
                Halt::OpBudget
            } else {
                return false;
            };
            fired.set(Some(halt));
            true
        })));
    }
    let ctx = new_context(&rt).map_err(|_| CompileError::Halted(Halt::Engine("no context")))?;
    let verdict = ctx.with(|ctx| {
        let to_string = function_to_string(&ctx)
            .map_err(|_| CompileError::Halted(Halt::Engine("Function.prototype.toString")))?;
        compile_wrapper(&ctx, &to_string, source).map(|_| ())
    });
    if let Some(halt) = meter_halt(&meter).or(fired.get()) {
        return Err(CompileError::Halted(halt));
    }
    verdict
}

/// `Function.prototype.toString`, captured before any agent code runs.
fn function_to_string<'js>(ctx: &Ctx<'js>) -> rquickjs::Result<Function<'js>> {
    let function: Object = ctx.globals().get("Function")?;
    let prototype: Object = function.get("prototype")?;
    prototype.get("toString")
}

/// Evaluates the wrapper and returns `main`. The returned function's own source text must be the
/// whole wrapper: a source that closes `main` and adds code after it (which QuickJS has then
/// already run once, with no `atlas` and no natives reachable) is refused as [`WRAPPER_ESCAPE`].
fn compile_wrapper<'js>(
    ctx: &Ctx<'js>,
    to_string: &Function<'js>,
    source: &str,
) -> Result<Function<'js>, CompileError> {
    if let Some(nul) = source.find('\0') {
        let (line, column) = position_of(source, nul);
        return Err(CompileError::Syntax(SyntaxPos {
            line,
            column,
            message: NUL_IN_SOURCE.to_owned(),
        }));
    }
    let wrapper = wrapper_source(source);
    let value = match ctx.eval::<Value, _>(wrapper.as_str()).catch(ctx) {
        Ok(value) => value,
        Err(CaughtError::Exception(ex)) => {
            return Err(CompileError::Syntax(syntax_pos(&ex, source)));
        }
        Err(CaughtError::Value(_)) => return Err(escape()),
        Err(CaughtError::Error(_)) => {
            return Err(CompileError::Halted(Halt::Engine(
                "the wrapper could not be evaluated",
            )));
        }
    };
    let Some(main) = value.into_function() else {
        return Err(escape());
    };
    let text: String = to_string
        .call((This(main.clone()),))
        .map_err(|_| escape())?;
    // The wrapper without its outer parentheses: `async function main(args, atlas) {..}`.
    let expected = &wrapper[1..wrapper.len() - 1];
    if text != expected {
        return Err(escape());
    }
    Ok(main)
}

fn escape() -> CompileError {
    CompileError::Syntax(SyntaxPos {
        line: 0,
        column: 0,
        message: WRAPPER_ESCAPE.to_owned(),
    })
}

/// The position and message of a compile exception, mapped to the agent's source. QuickJS-NG puts
/// a parse error's position only in `stack` (`    at <file>:<line>:<column>`).
fn syntax_pos(ex: &Exception<'_>, source: &str) -> SyntaxPos {
    let message = ex.message().unwrap_or_default();
    let name: Option<String> = ex.get("name").ok();
    let message = match name.as_deref() {
        None | Some("SyntaxError") => message,
        Some(name) => format!("{name}: {message}"),
    };
    let (line, column) = ex
        .stack()
        .as_deref()
        .and_then(position_in_stack)
        .map_or((0, 0), |(line, column)| {
            to_agent_position(line, column, source)
        });
    SyntaxPos {
        line,
        column,
        message,
    }
}

/// `(line, column)` of the first stack line, `    at <file>:L:C` or `    at f (<file>:L:C)`.
fn position_in_stack(stack: &str) -> Option<(u32, u32)> {
    let first = stack.lines().next()?.trim().strip_prefix("at ")?;
    let location = match first.rsplit_once('(') {
        Some((_, rest)) => rest.trim_end_matches(')'),
        None => first,
    };
    let mut parts = location.rsplitn(3, ':');
    let column = parts.next()?.parse().ok()?;
    let line = parts.next()?.parse().ok()?;
    Some((line, column))
}

/// Maps a wrapper position to the agent's source: line − 1, clamped to the source (an error
/// QuickJS reports on the wrapper's closing line, e.g. an unclosed comment, lands at the end of
/// the source's last line).
fn to_agent_position(line: u32, column: u32, source: &str) -> (u32, u32) {
    let lines = u32::try_from(source.split('\n').count()).unwrap_or(u32::MAX);
    match line.checked_sub(1) {
        None | Some(0) => (1, 1),
        Some(agent) if agent > lines => {
            let last = source.rsplit('\n').next().map_or(0, str::len);
            (
                lines,
                u32::try_from(last).unwrap_or(u32::MAX).saturating_add(1),
            )
        }
        Some(agent) => (agent, column),
    }
}

/// The 1-based line and byte column of byte offset `at` in `source`.
fn position_of(source: &str, at: usize) -> (u32, u32) {
    let before = &source[..at];
    let line = before.matches('\n').count().saturating_add(1);
    let column = before
        .rfind('\n')
        .map_or(at, |nl| at - nl - 1)
        .saturating_add(1);
    (
        u32::try_from(line).unwrap_or(u32::MAX),
        u32::try_from(column).unwrap_or(u32::MAX),
    )
}

/// A set-up failure that is neither the script's nor the host's; a pending exception is
/// cleared. A halt recorded meanwhile (a heap refusal) is reported instead by the caller.
fn engine_fault(ctx: &Ctx<'_>, what: &'static str) -> EngineError {
    let _ = ctx.catch();
    EngineError::Halted(Halt::Engine(what))
}

fn halted_or<H>(shared: &Shared<H>, fallback: Halt) -> EngineError {
    EngineError::Halted(shared.halted().unwrap_or(fallback))
}
