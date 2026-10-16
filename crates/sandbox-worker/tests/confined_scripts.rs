//! §15 V11 closure and V02 confirmation for the script runtime (plan M8 Task 5; §9.2, §9.3, §9.4;
//! PD-131, PD-134, PD-151). The corpus runs the script worker loop (`run_script_with`) in a child
//! of this test binary that confined itself with `confine::apply()`, with this process as the host
//! on the child's stdin and stdout. No case may be killed by SIGSYS (a syscall missing from the
//! allowlist); every case must end with its expected terminal frame and exit code.
//!
//! `harness = false` (see Cargo.toml): the libtest harness runs tests on extra threads, and the
//! filters cover only the calling thread, so `confine::apply` refuses to run there. This `main` is
//! the process's only thread. The parent run re-executes this binary once per case as the child.
//! CI only: never run it locally, it confines a child of the test binary.
//!
//! Linux and macOS: the child is confined (seccomp + Landlock, `sandbox_init`); the parent checks
//! the confinement report of `probe.ready`, and on Linux `/proc/<child>/task/*/status` for
//! `Seccomp: 2` and `NoNewPrivs: 1` on every task (the check of `sandbox-host`'s
//! `ProcTaskStatusHook`, re-implemented here because the worker takes no edge to the host).
//! Windows: `confine/windows.rs` only reports, and a re-executed test child is in neither the
//! AppContainer nor the job, so the same corpus runs unconfined (an engine corpus) and the
//! evidence says so. The confined Windows evidence is the `sandbox_runs` tests through
//! `WindowsSpawner`.
//!
//! The binary declares the worker's `ExitOnOomAlloc` (PD-134), like `atlas-duck-sandbox`, so a
//! process-level out-of-memory exits 103 here as it does there.
//!
//! CI evidence lines: `V11 os=<os> confined=<bool>`, `V11 corpus=<n> passed=<n>
//! killed_by_sigsys=<n>`, `V02 eval_required=true`. A line `confined child died with signal 31`
//! names a syscall the allowlist lacks: a finding for the lead, the allowlist stays unchanged.

use std::io::Write;
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use atlas_duck_ipc::sandbox::frame::{read_frame, write_frame};
use atlas_duck_ipc::sandbox::probe::{
    M_PROBE_READY, ProbeReady, decode_notification, encode_notification,
};
use atlas_duck_ipc::sandbox::script::{
    CompileRequest, InstanceInfo, M_SCRIPT_COMPILE, M_SCRIPT_RUN, WorkerFrame, WorkerInit,
    decode_worker_frame, encode_response,
};
use atlas_duck_ipc::sandbox::{HostCallResult, MAX_FRAME_BYTES, ScriptLimits};
use atlas_duck_sandbox_worker::script::wrapper_source;
use atlas_duck_sandbox_worker::{
    EXIT_HEAP_LIMIT, EXIT_OK, ExitOnOomAlloc, SCRIPT_STALLED, confine, engine, install_panic_hook,
    run_script_with,
};
use rquickjs::context::intrinsic::{Date, Json, MapSet, Promise, RegExp};
use rquickjs::{CatchResultExt, Context, Value as JsValue};
use serde_json::{Value, json};

/// PD-134: an exhausted process exits `EXIT_PROCESS_LIMIT` (103) at once, as in the worker binary.
#[global_allocator]
static A: ExitOnOomAlloc = ExitOnOomAlloc;

const CHILD_ENV: &str = "ATLAS_DUCK_CONFINED_SCRIPTS_CHILD";
const MODE_WORKER: &str = "worker";
const MODE_ENGINE: &str = "engine";
const SIGSYS: i32 = 31;
const MIB: usize = 1024 * 1024;

/// A case that does not end by itself is killed after this long (the worker's own deadlines are
/// far below it).
const CASE_TIMEOUT: Duration = Duration::from_secs(180);

/// Whether the child confines itself on this OS (see the module docs).
const CONFINED: bool = cfg!(any(target_os = "linux", target_os = "macos"));

const OS: &str = if cfg!(target_os = "linux") {
    "linux"
} else if cfg!(target_os = "macos") {
    "macos"
} else if cfg!(windows) {
    "windows"
} else {
    "other"
};

// ---------------------------------------------------------------------------------------------
// The child
// ---------------------------------------------------------------------------------------------

/// Runs `body` on the main thread (Unix: the confinement covers only that thread, and its stack is
/// 8 MiB) or, on Windows, on an 8 MiB thread (the worker binary reserves 8 MiB there; the test
/// binary's main thread has 1 MiB and nothing is confined).
fn on_worker_stack(body: impl FnOnce() -> i32 + Send + 'static) -> i32 {
    if cfg!(windows) {
        match std::thread::Builder::new()
            .stack_size(8 * MIB)
            .spawn(body)
            .map(|handle| handle.join())
        {
            Ok(Ok(code)) => code,
            _ => 20,
        }
    } else {
        body()
    }
}

/// The report of this process's own confinement; `None` is a failed child (exit codes as in the
/// M1 `confined_workload`).
fn confine_self() -> Result<atlas_duck_ipc::sandbox::probe::ConfinementReport, i32> {
    match confine::apply() {
        Ok(report) => {
            if CONFINED && (!report.applied || report.seccomp == Some(false)) {
                println!("confinement not applied: {report:?}");
                return Err(11);
            }
            Ok(report)
        }
        Err(e) => {
            println!("confine failed: {e}");
            Err(10)
        }
    }
}

/// The worker as `run()` does it (panic hook, confinement, `run_script_with` over stdin and
/// stdout), exiting with its code.
fn worker_child() -> ExitCode {
    let code = on_worker_stack(|| {
        install_panic_hook();
        let report = match confine_self() {
            Ok(report) => report,
            Err(code) => return code,
        };
        let stdin = std::io::stdin();
        run_script_with(report, &mut stdin.lock(), std::io::stdout().lock())
    });
    std::process::exit(code)
}

/// §15 V02 on the script runtime, in a confined process: evaluating the wrapper needs the Eval
/// intrinsic. A context without it refuses with `eval is not supported`; the worker's context
/// evaluates the wrapper to a function.
fn v02_eval_required() -> Result<(), String> {
    let (rt, _meter) =
        engine::new_runtime_with_heap_limit(16 * MIB).map_err(|e| format!("runtime: {e}"))?;
    let wrapper = wrapper_source("return 1;");

    let without = Context::custom::<(Json, Promise, RegExp, MapSet, Date)>(&rt)
        .map_err(|e| format!("context without Eval: {e}"))?;
    let refused = without.with(|ctx| {
        ctx.eval::<JsValue, _>(wrapper.clone())
            .catch(&ctx)
            .map(|_| ())
            .map_err(|err| err.to_string())
    });
    match refused {
        Err(text) if text.contains("eval is not supported") => {}
        other => return Err(format!("without Eval: {other:?}")),
    }

    let with = engine::new_context(&rt).map_err(|e| format!("context with Eval: {e}"))?;
    let is_function = with
        .with(|ctx| {
            ctx.eval::<JsValue, _>(wrapper)
                .catch(&ctx)
                .map(|value| value.is_function())
                .map_err(|err| err.to_string())
        })
        .map_err(|e| format!("with Eval: {e}"))?;
    if is_function {
        Ok(())
    } else {
        Err("with Eval: the wrapper is not a function".to_owned())
    }
}

/// The M1 self-test of the probe worker and the V02 confirmation, both under the filter.
fn engine_child() -> ExitCode {
    let code = on_worker_stack(|| {
        install_panic_hook();
        if let Err(code) = confine_self() {
            return code;
        }
        if let Err(failed) = engine::run_selftest() {
            println!("selftest failed: {failed}");
            return 18;
        }
        println!("SELFTEST ok");
        if let Err(failed) = v02_eval_required() {
            println!("v02 failed: {failed}");
            return 19;
        }
        println!("V02 eval_required=true");
        EXIT_OK
    });
    std::process::exit(code)
}

// ---------------------------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------------------------

/// What the worker sends and exits with.
enum Expect {
    /// `script.result` with this JSON value, exit 0.
    Result(Value),
    /// `script.error` with this class, exit 0.
    Error(&'static str),
    /// `script.compiled`, exit 0.
    Compiled,
    /// `script.syntax`, exit 0.
    Syntax,
    /// No frame after `probe.ready`, exit `EXIT_HEAP_LIMIT` (never SIGSYS).
    HeapLimit,
}

enum Request {
    Run(WorkerInit),
    Compile(&'static str),
}

struct Case {
    name: &'static str,
    request: Request,
    /// The `host.log` lines the case must produce, in order.
    logs: Vec<&'static str>,
    expect: Expect,
}

fn init_with(source: &str, args: Value, limits: ScriptLimits) -> WorkerInit {
    WorkerInit {
        source: source.to_owned(),
        args,
        limits,
        read_op_ids: vec!["jira.issue.get".to_owned(), "jira.search".to_owned()],
        instances: vec![InstanceInfo {
            alias: "prod".to_owned(),
            product: "jira".to_owned(),
            is_default: true,
        }],
    }
}

fn run_case(name: &'static str, source: &str, args: Value, expect: Expect) -> Case {
    Case {
        name,
        request: Request::Run(init_with(source, args, ScriptLimits::default())),
        logs: Vec::new(),
        expect,
    }
}

/// The M1 `confined_workload` script, scaled to fit the default `heap_mb` (256 MiB): allocation-heavy
/// (`mmap`, `mremap`, `munmap`, many `brk`). M1's 300 000 rows (`a` and the parsed `back` live
/// together, about 250 B per row each in QuickJS, plus the JSON text and the Map) come to more than
/// 256 MiB and ended in `EXIT_HEAP_LIMIT` (exit 102) in CI. 100 000 rows hold about 55 MiB for `a` and
/// `back` together, about 6 MiB of JSON text, 2 MiB for `s` (about 4 MiB at the `realloc` peak) and
/// about 30 MiB for the Map: roughly 100 MiB, so at least 2x headroom under the limit.
const ALLOCATION_HEAVY_JS: &str = r#"
const a = [];
for (let i = 0; i < 100000; i++) a.push({ k: i, s: 'x' + i, arr: [i, i + 1, i + 2] });
const back = JSON.parse(JSON.stringify(a));
let s = '';
for (let i = 0; i < 200000; i++) s += 'abcdefghij';
const m = new Map();
for (let i = 0; i < 200000; i++) m.set('k' + i, i);
return [back.length, back[99999].arr[2], s.length, m.size];
"#;

/// Local-time `Date` methods and `toLocale*String` (§15 V11): none may hit a KILL rule. Local time
/// is UTC on every OS (PD-151), so each local method equals its UTC twin. Returns the failed
/// check names.
const DATE_LOCAL_TIME_JS: &str = r#"
const failed = [];
const check = (name, ok) => { if (!ok) failed.push(name); };
const t = new Date(Date.UTC(2026, 6, 15, 23, 45, 30, 123));
check('offset', t.getTimezoneOffset() === 0);
check('local constructor', new Date(2026, 0, 1).getTime() === Date.UTC(2026, 0, 1));
for (const n of ['FullYear', 'Month', 'Date', 'Day', 'Hours', 'Minutes', 'Seconds', 'Milliseconds']) {
  check('get' + n, t['get' + n]() === t['getUTC' + n]());
}
const setters = [['FullYear', [2020, 1, 2]], ['Month', [3, 4]], ['Date', [9]], ['Hours', [5, 6, 7, 8]],
                 ['Minutes', [1, 2, 3]], ['Seconds', [4, 5]], ['Milliseconds', [6]]];
for (const [n, a] of setters) {
  const x = new Date(t.getTime());
  const y = new Date(t.getTime());
  check('set' + n, x['set' + n](...a) === y['setUTC' + n](...a) && x.getTime() === y.getTime());
}
for (const f of ['toString', 'toDateString', 'toTimeString', 'toLocaleString',
                 'toLocaleDateString', 'toLocaleTimeString']) {
  const text = t[f]();
  check(f, typeof text === 'string' && text.length > 0);
}
check('toLocaleString text', new Date(Date.UTC(2026, 0, 1)).toLocaleString() === '01/01/2026, 12:00:00 AM');
check('parse local form', Date.parse('2026-01-01T00:00') === Date.UTC(2026, 0, 1));
check('invalid date', new Date(NaN).toLocaleString() === 'Invalid Date');
check('number toLocaleString', typeof (1234.5).toLocaleString() === 'string');
check('localeCompare', 'a'.localeCompare('b') < 0);
check('toLocaleUpperCase', 'a'.toLocaleUpperCase() === 'A');
return failed;
"#;

/// A heap bomb: allocates until the QuickJS allocator refuses (`heap_mb`).
const BOMB_JS: &str = "function bomb() { const a = []; for (;;) a.push(new Array(65536).fill(1.5)); }\n\
                       atlas.log('before');\nbomb();\nreturn 1;";

fn corpus() -> Vec<Case> {
    let rows: Vec<Value> = (0..48_000u64)
        .map(|k| json!({ "k": k, "s": "x".repeat(80) }))
        .collect();
    let row_sum: u64 = (0..48_000u64).sum();

    let mut cases = vec![
        run_case(
            "return_args",
            "return args.n * 2;",
            json!({"n": 21}),
            Expect::Result(json!(42)),
        ),
        run_case(
            "json_round_trip_4mib_args",
            "const text = JSON.stringify(args);\n\
             const back = JSON.parse(text);\n\
             let sum = 0;\n\
             for (const r of back.rows) sum += r.k;\n\
             return [text.length >= 4 * 1024 * 1024, back.rows.length, sum];",
            json!({ "rows": rows }),
            Expect::Result(json!([true, 48_000, row_sum])),
        ),
        run_case(
            "allocation_heavy",
            ALLOCATION_HEAVY_JS,
            json!({}),
            Expect::Result(json!([100_000, 100_001, 2_000_000, 200_000])),
        ),
        run_case(
            "regexp_captures",
            "const m = /(\\d+)-(\\d+)-(\\d+)/.exec('on 2026-10-07 at noon');\n\
             const r = '2026-10-07'.replace(/(\\d+)-(\\d+)-(\\d+)/, '$3.$2.$1');\n\
             const g = [...'a1b22c333'.matchAll(/([a-z])(\\d+)/g)].map((x) => x[1] + x[2].length);\n\
             return [m[1], m[2], m[3], m.index, r, g, new RegExp('(b+)c').exec('abbbc')[1]];",
            json!({}),
            Expect::Result(json!([
                "2026",
                "10",
                "07",
                3,
                "07.10.2026",
                ["a1", "b2", "c3"],
                "bbb"
            ])),
        ),
        run_case(
            "promise_chain_10000_jobs",
            "let p = Promise.resolve(0);\n\
             for (let i = 0; i < 10000; i++) p = p.then((v) => v + 1);\n\
             const chained = await p;\n\
             const all = await Promise.all(Array.from({ length: 10000 }, (_, i) => Promise.resolve(i)));\n\
             return [chained, all.length, all[9999]];",
            json!({}),
            Expect::Result(json!([10_000, 10_000, 9_999])),
        ),
        run_case(
            "map_set",
            "const m = new Map();\n\
             for (let i = 0; i < 50000; i++) m.set('k' + i, i);\n\
             const s = new Set();\n\
             for (let i = 0; i < 50000; i++) s.add(i % 1000);\n\
             m.delete('k0');\n\
             return [m.size, m.get('k49999'), s.size, [...s].slice(0, 3), [...m.keys()][0]];",
            json!({}),
            Expect::Result(json!([49_999, 49_999, 1000, [0, 1, 2], "k1"])),
        ),
        run_case(
            "date_local_time_and_toLocale",
            DATE_LOCAL_TIME_JS,
            json!({}),
            Expect::Result(json!([])),
        ),
        run_case(
            "deep_recursion_caught_is_range_error",
            "function f() { return f(); }\n\
             try { f(); return 'returned'; }\n\
             catch (err) { return err instanceof RangeError ? 'RangeError' : String(err); }",
            json!({}),
            Expect::Result(json!("RangeError")),
        ),
        run_case(
            "deep_recursion_uncaught_is_range_error",
            "function g() { return g(); }\nreturn g();",
            json!({}),
            Expect::Error("RangeError"),
        ),
        run_case(
            "thrown_error_is_a_script_error",
            "throw new TypeError('boom');",
            json!({}),
            Expect::Error("TypeError"),
        ),
        run_case(
            "unsettled_promise_is_stalled",
            "await new Promise(() => {});",
            json!({}),
            Expect::Error(SCRIPT_STALLED),
        ),
        run_case(
            "excluded_intrinsics_absent",
            "return ['Proxy', 'WeakRef', 'FinalizationRegistry', 'ArrayBuffer', 'Uint8Array',\n\
                     'DataView', 'Atomics', 'SharedArrayBuffer', 'performance', 'Performance',\n\
                     'DOMException'].map((n) => typeof globalThis[n]);",
            json!({}),
            Expect::Result(json!(vec!["undefined"; 11])),
        ),
        run_case(
            "import_rejects",
            "try { await import('x'); return 'resolved'; } catch (err) { return 'rejected'; }",
            json!({}),
            Expect::Result(json!("rejected")),
        ),
        run_case(
            "args_and_atlas_are_frozen",
            "return [Object.isFrozen(args), Object.isFrozen(args.a.b[1]), Object.isFrozen(atlas)];",
            json!({"a": {"b": [1, {"c": 2}]}}),
            Expect::Result(json!([true, true, true])),
        ),
    ];

    // Host calls over the confined pipes, more than `max_concurrent_calls` (4) at once; logs.
    cases.push(Case {
        name: "host_calls_and_logs",
        request: Request::Run(init_with(
            "atlas.log('start');\n\
             const rs = await Promise.all([0, 1, 2, 3, 4, 5].map((i) => atlas.call('jira.search', { q: i })));\n\
             atlas.log('calls done');\n\
             return rs.map((r) => r.echo.q);",
            json!({}),
            ScriptLimits::default(),
        )),
        logs: vec!["start", "calls done"],
        expect: Expect::Result(json!([0, 1, 2, 3, 4, 5])),
    });

    // The heap limit: the allocator refuses, the worker exits `EXIT_HEAP_LIMIT`, never SIGSYS.
    cases.push(Case {
        name: "heap_limit_exits_102",
        request: Request::Run(init_with(
            BOMB_JS,
            json!({}),
            ScriptLimits {
                heap_mb: 8,
                ..ScriptLimits::default()
            },
        )),
        logs: vec!["before"],
        expect: Expect::HeapLimit,
    });

    cases.push(Case {
        name: "compile_ok",
        request: Request::Compile("const x = await Promise.resolve(1);\nreturn x;"),
        logs: Vec::new(),
        expect: Expect::Compiled,
    });
    cases.push(Case {
        name: "compile_syntax_error",
        request: Request::Compile("return (;"),
        logs: Vec::new(),
        expect: Expect::Syntax,
    });
    cases
}

// ---------------------------------------------------------------------------------------------
// The parent (the host side)
// ---------------------------------------------------------------------------------------------

type Shared = Arc<Mutex<Child>>;

/// Spawns this binary as a child in `mode`: an empty environment but `TZ=UTC0` (§3.4) and, per OS,
/// what the process needs to start.
fn spawn_child(mode: &str, stdin: Stdio) -> Result<Child, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut command = Command::new(exe);
    command
        .env_clear()
        .env("TZ", "UTC0")
        .env(CHILD_ENV, mode)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if cfg!(windows) {
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
    } else {
        command.env("MALLOC_ARENA_MAX", "1");
    }
    command.spawn().map_err(|e| format!("spawn the child: {e}"))
}

/// Kills the child if the case is still running after [`CASE_TIMEOUT`].
fn watchdog(child: &Shared, done: &Arc<AtomicBool>) {
    let child = Arc::clone(child);
    let done = Arc::clone(done);
    std::thread::spawn(move || {
        let start = Instant::now();
        while start.elapsed() < CASE_TIMEOUT {
            if done.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        if let Ok(mut child) = child.lock() {
            let _ = child.kill();
        }
    });
}

/// The child's exit: its code, or the signal that ended it.
struct Exit {
    code: Option<i32>,
    signal: Option<i32>,
}

/// Waits for the child to exit (polling under short locks, so the watchdog can still kill it).
fn wait_exit(child: &Shared) -> Result<Exit, String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .try_wait()
            .map_err(|e| format!("wait for the child: {e}"))?;
        if let Some(status) = status {
            #[cfg(unix)]
            let signal = std::os::unix::process::ExitStatusExt::signal(&status);
            #[cfg(not(unix))]
            let signal = None;
            return Ok(Exit {
                code: status.code(),
                signal,
            });
        }
        if Instant::now() > deadline {
            let _ = child.lock().unwrap_or_else(PoisonError::into_inner).kill();
            return Err("the child did not exit after its last frame (killed)".to_owned());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Linux: every task of `pid` carries `Seccomp: 2` and `NoNewPrivs: 1` (the `ProcTaskStatusHook`
/// check of `sandbox-host`).
#[cfg(target_os = "linux")]
fn check_task_status(pid: u32) -> Result<(), String> {
    let dir = format!("/proc/{pid}/task");
    let tasks = std::fs::read_dir(&dir).map_err(|e| format!("read {dir}: {e}"))?;
    let mut seen = 0;
    for task in tasks {
        let task = task.map_err(|e| format!("read {dir}: {e}"))?;
        let path = task.path().join("status");
        let status =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
                .map(str::to_owned)
        };
        if field("Seccomp:").as_deref() != Some("2") {
            return Err(format!(
                "{}: Seccomp is {:?}, not 2",
                path.display(),
                field("Seccomp:")
            ));
        }
        if field("NoNewPrivs:").as_deref() != Some("1") {
            return Err(format!(
                "{}: NoNewPrivs is {:?}, not 1",
                path.display(),
                field("NoNewPrivs:")
            ));
        }
        seen += 1;
    }
    if seen == 0 {
        return Err(format!("{dir} lists no task"));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn check_task_status(_pid: u32) -> Result<(), String> {
    Ok(())
}

/// One frame to the child's stdin (still open until the terminal frame came).
fn send(stdin: &mut Option<std::process::ChildStdin>, payload: &[u8]) -> std::io::Result<()> {
    let Some(stdin) = stdin.as_mut() else {
        return Err(std::io::ErrorKind::BrokenPipe.into());
    };
    write_frame(stdin, payload)?;
    stdin.flush()
}

/// What one child run produced.
struct Outcome {
    terminal: Option<WorkerFrame>,
    logs: Vec<String>,
    exit: Exit,
}

/// Runs one child as the host: reads `probe.ready` and checks the confinement, sends `first`,
/// answers host calls (`{"echo": params}`), collects the frames up to the terminal one, then
/// expects the pipe to end.
fn drive(first: &[u8]) -> Result<Outcome, String> {
    let mut proc = spawn_child(MODE_WORKER, Stdio::piped())?;
    let (Some(stdin), Some(mut stdout)) = (proc.stdin.take(), proc.stdout.take()) else {
        return Err("the child has no pipes".to_owned());
    };
    let mut stdin = Some(stdin);
    let pid = proc.id();
    let child: Shared = Arc::new(Mutex::new(proc));
    let done = Arc::new(AtomicBool::new(false));
    watchdog(&child, &done);
    let result = (|| {
        let ready = read_frame(&mut stdout, MAX_FRAME_BYTES)
            .map_err(|e| format!("read probe.ready: {e:?}"))?
            .ok_or("the child closed stdout before probe.ready")?;
        let (method, params) =
            decode_notification(&ready).map_err(|e| format!("probe.ready: {e:?}"))?;
        if method != M_PROBE_READY {
            return Err(format!("first frame {method}, not probe.ready"));
        }
        let ready: ProbeReady =
            serde_json::from_value(params).map_err(|e| format!("probe.ready params: {e}"))?;
        if CONFINED {
            let c = &ready.confinement;
            if !c.applied {
                return Err(format!("the child reports no confinement: {c:?}"));
            }
            if cfg!(target_os = "linux")
                && (c.seccomp != Some(true) || c.no_new_privs != Some(true))
            {
                return Err(format!("the child reports no seccomp floor: {c:?}"));
            }
            check_task_status(pid)?;
        }

        send(&mut stdin, first).map_err(|e| format!("send the first frame: {e}"))?;

        let mut logs = Vec::new();
        let mut terminal = None;
        loop {
            let frame = read_frame(&mut stdout, MAX_FRAME_BYTES)
                .map_err(|e| format!("read a worker frame: {e:?}"))?;
            let Some(frame) = frame else { break };
            if terminal.is_some() {
                return Err("a frame after the terminal frame".to_owned());
            }
            match decode_worker_frame(&frame).map_err(|e| format!("worker frame: {e:?}"))? {
                WorkerFrame::Call { id, call } => {
                    let answer = HostCallResult::Ok(json!({ "echo": call.params }));
                    send(&mut stdin, &encode_response(id, &answer))
                        .map_err(|e| format!("answer call {id}: {e}"))?;
                }
                WorkerFrame::Log { line } => logs.push(line),
                end => terminal = Some(end),
            }
            if terminal.is_some() {
                // The worker ends after its terminal frame; the next read must be EOF.
                stdin = None;
            }
        }
        Ok((terminal, logs))
    })();
    let exit = wait_exit(&child);
    done.store(true, Ordering::SeqCst);
    let (terminal, logs) = result?;
    Ok(Outcome {
        terminal,
        logs,
        exit: exit?,
    })
}

fn check_outcome(case: &Case, outcome: &Outcome) -> Result<(), String> {
    let clean_exit = |want: i32| {
        if outcome.exit.code == Some(want) && outcome.exit.signal.is_none() {
            Ok(())
        } else {
            Err(format!(
                "exit {:?} / signal {:?}, expected exit {want}",
                outcome.exit.code, outcome.exit.signal
            ))
        }
    };
    let logs: Vec<&str> = outcome.logs.iter().map(String::as_str).collect();
    if logs != case.logs {
        return Err(format!("log lines {logs:?}, expected {:?}", case.logs));
    }
    match (&case.expect, &outcome.terminal) {
        (Expect::HeapLimit, None) => clean_exit(EXIT_HEAP_LIMIT),
        (Expect::HeapLimit, Some(frame)) => Err(format!("a frame after the heap limit: {frame:?}")),
        (_, None) => Err(format!(
            "no terminal frame (exit {:?} / signal {:?})",
            outcome.exit.code, outcome.exit.signal
        )),
        (Expect::Result(want), Some(WorkerFrame::Result { value })) => {
            let got: Value = serde_json::from_str(value.get())
                .map_err(|e| format!("result is not JSON: {e}"))?;
            if &got != want {
                let shown: String = got.to_string().chars().take(300).collect();
                return Err(format!("result {shown}, expected {want}"));
            }
            clean_exit(EXIT_OK)
        }
        (Expect::Error(want), Some(WorkerFrame::Error { class, message, .. })) => {
            if class != want {
                return Err(format!("error class {class} ({message}), expected {want}"));
            }
            clean_exit(EXIT_OK)
        }
        (Expect::Compiled, Some(WorkerFrame::Compiled)) => clean_exit(EXIT_OK),
        (Expect::Syntax, Some(WorkerFrame::Syntax { .. })) => clean_exit(EXIT_OK),
        (_, Some(other)) => {
            let shown: String = format!("{other:?}").chars().take(400).collect();
            Err(format!("unexpected terminal frame {shown}"))
        }
    }
}

fn first_frame(request: &Request) -> Vec<u8> {
    match request {
        Request::Run(init) => encode_notification(M_SCRIPT_RUN, init),
        Request::Compile(source) => encode_notification(
            M_SCRIPT_COMPILE,
            &CompileRequest {
                source: (*source).to_owned(),
            },
        ),
    }
}

/// The engine child: the M1 self-test and V02 under the filter. Returns its evidence lines.
fn run_engine_case() -> (Result<(), String>, bool) {
    let proc = match spawn_child(MODE_ENGINE, Stdio::null()) {
        Ok(proc) => proc,
        Err(e) => return (Err(e), false),
    };
    let output = match proc.wait_with_output() {
        Ok(output) => output,
        Err(e) => return (Err(format!("wait for the engine child: {e}")), false),
    };
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    #[cfg(unix)]
    let signal = std::os::unix::process::ExitStatusExt::signal(&output.status);
    #[cfg(not(unix))]
    let signal: Option<i32> = None;
    let sigsys = signal == Some(SIGSYS);
    if let Some(sig) = signal {
        return (
            Err(format!("died with signal {sig}\nstdout: {stdout}")),
            sigsys,
        );
    }
    if output.status.code() != Some(0)
        || !stdout.contains("SELFTEST ok")
        || !stdout.contains("V02 eval_required=true")
    {
        return (
            Err(format!("exit {:?}\nstdout: {stdout}", output.status.code())),
            sigsys,
        );
    }
    (Ok(()), sigsys)
}

fn parent() -> ExitCode {
    println!("V11 os={OS} confined={CONFINED}");
    let cases = corpus();
    let total = cases.len() + 1;
    let mut passed = 0;
    let mut sigsys = 0;
    let mut failures: Vec<String> = Vec::new();

    let (engine_result, engine_sigsys) = run_engine_case();
    sigsys += usize::from(engine_sigsys);
    match engine_result {
        Ok(()) => {
            passed += 1;
            println!("ok   engine_selftest_and_v02");
            println!("V02 eval_required=true");
        }
        Err(e) => failures.push(format!("engine_selftest_and_v02: {e}")),
    }

    for case in &cases {
        let outcome = drive(&first_frame(&case.request)).and_then(|outcome| {
            if outcome.exit.signal == Some(SIGSYS) {
                sigsys += 1;
                return Err(format!(
                    "confined child died with signal {SIGSYS} (SIGSYS: a syscall missing from the allowlist)"
                ));
            }
            check_outcome(case, &outcome)
        });
        match outcome {
            Ok(()) => {
                passed += 1;
                println!("ok   {}", case.name);
            }
            Err(e) => failures.push(format!("{}: {e}", case.name)),
        }
    }

    println!("V11 corpus={total} passed={passed} killed_by_sigsys={sigsys}");
    if failures.is_empty() && passed == total && sigsys == 0 {
        println!("confined_scripts: ok");
        return ExitCode::SUCCESS;
    }
    for failure in &failures {
        eprintln!("FAILED {failure}");
    }
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    match std::env::var(CHILD_ENV).as_deref() {
        Ok(MODE_WORKER) => worker_child(),
        Ok(MODE_ENGINE) => engine_child(),
        Ok(_) => ExitCode::from(2),
        Err(_) => parent(),
    }
}
