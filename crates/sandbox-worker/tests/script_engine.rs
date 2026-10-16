//! Script engine tests (plan M8 Task 3; spec §9.2, §9.3, §9.4; PD-131, PD-134, PD-135, PD-151,
//! PD-152). In-process only: a fake `HostPort` records the frames, `confine::apply` and `run()`
//! are never called, and no child process is started. Every test that evaluates JS runs its body
//! on an 8 MiB thread (the worker's main-thread stack; the default test thread has 2 MiB and the
//! QuickJS guard is 1 MiB).
//!
//! The M1 engine tests in `tests/engine.rs` stay where they are (that target is CI-only because
//! of its re-exec test). Their script-runtime counterparts here: `import_fails_no_module_loader`
//! (M1 `static_import_does_not_evaluate`, `dynamic_import_rejects`), `excluded_intrinsics_absent`
//! (M1 `excluded_intrinsics_are_undefined`), `deep_recursion_is_a_range_error_not_a_crash` (M1
//! `deep_recursion_is_a_catchable_range_error`), `v02_host_side_eval_still_needs_eval` (M1
//! `v02_host_side_eval_needs_the_eval_intrinsic`).

use std::io;
use std::time::Duration;

use atlas_duck_ipc::sandbox::script::{
    InstanceInfo, WorkerInit, encode_response, terminal_frame_max,
};
use atlas_duck_ipc::sandbox::{HostCall, HostCallResult, ScriptLimits};
use atlas_duck_sandbox_worker::engine::{new_context, new_runtime_with_heap_limit};
use atlas_duck_sandbox_worker::script::alloc::LimitAllocator;
use atlas_duck_sandbox_worker::script::interrupt::{
    Deadline, OP_BUDGET_CALLBACKS, OpBudget, backstop,
};
use atlas_duck_sandbox_worker::script::{
    CALL_NOT_DECODABLE, CALL_TOO_LARGE, CompileError, Engine, EngineError, Halt, HostPort,
    ScriptError, Settled, compile, wrapper_source,
};
use rquickjs::allocator::Allocator;
use rquickjs::context::intrinsic::{Date, Json, MapSet, Promise, RegExp};
use rquickjs::{CatchResultExt, Context, Value};
use serde_json::{Value as Json_, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Runs `body` on an 8 MiB thread and turns its `Err(String)` into a test failure.
fn big_stack(body: impl FnOnce() -> Result<(), String> + Send + 'static) -> TestResult {
    let handle = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(body)?;
    match handle.join() {
        Ok(result) => result.map_err(Into::into),
        Err(_) => Err("the test body panicked".into()),
    }
}

/// One frame the engine sent through the fake host.
#[derive(Debug, Clone, PartialEq)]
enum Sent {
    Call(u64, HostCall),
    Log(String),
}

/// A `HostPort` that records every send, or fails every send with `fail`.
#[derive(Default)]
struct FakeHost {
    sent: Vec<Sent>,
    fail: Option<io::ErrorKind>,
}

impl HostPort for FakeHost {
    fn send_call(&mut self, id: u64, call: &HostCall) -> io::Result<()> {
        if let Some(kind) = self.fail {
            return Err(kind.into());
        }
        self.sent.push(Sent::Call(id, call.clone()));
        Ok(())
    }

    fn send_log(&mut self, line: &str) -> io::Result<()> {
        if let Some(kind) = self.fail {
            return Err(kind.into());
        }
        self.sent.push(Sent::Log(line.to_owned()));
        Ok(())
    }
}

fn init_with(source: &str, args: Json_, limits: ScriptLimits) -> WorkerInit {
    WorkerInit {
        source: source.to_owned(),
        args,
        limits,
        read_op_ids: vec![
            "jira.issue.get".to_owned(),
            "jira.search".to_owned(),
            "confluence.page.get".to_owned(),
        ],
        instances: vec![
            InstanceInfo {
                alias: "prod".to_owned(),
                product: "jira".to_owned(),
                is_default: true,
            },
            InstanceInfo {
                alias: "wiki".to_owned(),
                product: "confluence".to_owned(),
                is_default: false,
            },
        ],
    }
}

fn init(source: &str) -> WorkerInit {
    init_with(source, json!({}), ScriptLimits::default())
}

fn e<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

/// `start` then `drain_jobs`, folding a start halt into `Settled::Halted`.
fn start_and_drain(engine: &mut Engine<FakeHost>) -> Settled {
    match engine.start() {
        Ok(()) => engine.drain_jobs(),
        Err(halt) => Settled::Halted(halt),
    }
}

/// Runs a script that makes no host call to its end; returns the settlement and the sends.
fn run(init: &WorkerInit) -> Result<(Settled, Vec<Sent>), String> {
    let mut engine = Engine::new(init, FakeHost::default()).map_err(e)?;
    let settled = start_and_drain(&mut engine);
    let sent = engine.host().sent.clone();
    Ok((settled, sent))
}

/// The JSON value of a `Settled::Result`.
fn result_json(settled: &Settled) -> Result<Json_, String> {
    match settled {
        Settled::Result(text) => serde_json::from_str(text).map_err(e),
        other => Err(format!("expected a result, got {other:?}")),
    }
}

fn ok_frame(id: u64, value: Json_) -> Result<String, String> {
    String::from_utf8(encode_response(id, &HostCallResult::Ok(value))).map_err(e)
}

fn call_ids(sent: &[Sent]) -> Vec<u64> {
    sent.iter()
        .filter_map(|s| match s {
            Sent::Call(id, _) => Some(*id),
            Sent::Log(_) => None,
        })
        .collect()
}

fn rejected_frame(id: u64) -> Result<String, String> {
    let rejected = HostCallResult::Rejected {
        class: "validation".into(),
        details: json!({"param": "key"}),
    };
    String::from_utf8(encode_response(id, &rejected)).map_err(e)
}

/// Runs a script to its end, answering every sent call in send order with `answer(id)`; returns
/// the settlement and the sends. Stops at the first non-pending state or when nothing is left
/// to answer.
fn drive(
    init: &WorkerInit,
    answer: impl Fn(u64) -> Result<String, String>,
) -> Result<(Settled, Vec<Sent>), String> {
    let mut engine = Engine::new(init, FakeHost::default()).map_err(e)?;
    let mut settled = start_and_drain(&mut engine);
    let mut answered = 0;
    loop {
        if !matches!(settled, Settled::Pending { .. }) {
            break;
        }
        let ids = call_ids(&engine.host().sent);
        let Some(&id) = ids.get(answered) else {
            break;
        };
        answered += 1;
        if let Err(halt) = engine.deliver(&answer(id)?) {
            settled = Settled::Halted(halt);
            break;
        }
        settled = engine.drain_jobs();
    }
    let sent = engine.host().sent.clone();
    Ok((settled, sent))
}

#[test]
fn wrapper_compiles_without_running_body() -> TestResult {
    big_stack(|| {
        // Compile mode: the body would throw if it ran.
        compile("globalThis.ran = true; throw new Error('ran');").map_err(e)?;

        // Run mode: nothing is sent before `start`, then the body runs once.
        let mut engine =
            Engine::new(&init("atlas.log('ran'); return 1;"), FakeHost::default()).map_err(e)?;
        if !engine.host().sent.is_empty() {
            return Err("the body ran before start".into());
        }
        let settled = start_and_drain(&mut engine);
        if result_json(&settled)? != json!(1) {
            return Err(format!("unexpected settlement {settled:?}"));
        }
        if engine.host().sent != vec![Sent::Log("ran".into())] {
            return Err(format!("unexpected sends {:?}", engine.host().sent));
        }
        Ok(())
    })
}

/// A source that closes the wrapper and appends its own function is refused in both modes; in
/// run mode it never reaches `atlas` and nothing is sent.
#[test]
fn wrapper_escape_is_a_syntax_error() -> TestResult {
    big_stack(|| {
        let escape = "});\nglobalThis.escaped = 1;\n(async function main(args, atlas) {\natlas.log('escaped');";
        match compile(escape) {
            Err(CompileError::Syntax(pos)) if pos.message.contains("wrapper") => {}
            other => return Err(format!("compile: unexpected {other:?}")),
        }
        match Engine::new(&init(escape), FakeHost::default()) {
            Err(EngineError::Syntax(pos)) if pos.message.contains("wrapper") => {}
            Err(other) => return Err(format!("run: unexpected {other:?}")),
            Ok(_) => return Err("run: the escape was accepted".into()),
        }
        // Escaping top-level code that throws: a syntax error carrying its message, no result
        // and nothing sent (it ran once, with no natives, `atlas` or `args`).
        let throwing = "});\nthrow new Error('escaped and threw');\n(async function main(args, atlas) {\natlas.log('x');";
        match compile(throwing) {
            Err(CompileError::Syntax(pos)) if pos.message.contains("escaped and threw") => {}
            other => return Err(format!("compile, throwing: unexpected {other:?}")),
        }
        match Engine::new(&init(throwing), FakeHost::default()) {
            Err(EngineError::Syntax(pos)) if pos.message.contains("escaped and threw") => Ok(()),
            Err(other) => Err(format!("run, throwing: unexpected {other:?}")),
            Ok(_) => Err("run, throwing: the escape was accepted".into()),
        }
    })
}

#[test]
fn syntax_error_position_maps_to_agent_source() -> TestResult {
    big_stack(|| {
        let source = "const a = 1;\nconst b = 2;\n    )\nreturn a + b;";
        match compile(source) {
            Err(CompileError::Syntax(pos)) if (pos.line, pos.column) == (3, 5) => {}
            other => return Err(format!("compile: {other:?}")),
        }
        match Engine::new(&init(source), FakeHost::default()) {
            Err(EngineError::Syntax(pos)) if (pos.line, pos.column) == (3, 5) => {}
            Err(other) => return Err(format!("run: {other:?}")),
            Ok(_) => return Err("run: compiled".into()),
        }
        // QuickJS takes C strings: a NUL is refused at its own position.
        match compile("a;\n  \0") {
            Err(CompileError::Syntax(pos)) if (pos.line, pos.column) == (2, 3) => {}
            other => return Err(format!("NUL: {other:?}")),
        }
        // An error QuickJS reports on the wrapper's closing line stays inside the source.
        match compile("let x = 1; /* never closed") {
            Err(CompileError::Syntax(pos)) if pos.line == 1 => Ok(()),
            other => Err(format!("unclosed comment: {other:?}")),
        }
    })
}

#[test]
fn atlas_and_args_deep_frozen() -> TestResult {
    big_stack(|| {
        let source = r#"
            const out = [];
            const attempt = (name, f) => {
              try { f(); out.push(name + ':no-throw'); } catch (err) { out.push(name + ':' + err.name); }
            };
            attempt('args.a', () => { args.a = 1; });
            attempt('args.a.b[1].c', () => { args.a.b[1].c = 3; });
            attempt('args.a.b.push', () => { args.a.b.push(1); });
            attempt('args.new', () => { args.fresh = 1; });
            attempt('atlas.call', () => { atlas.call = null; });
            attempt('atlas.jira.issue.get', () => { atlas.jira.issue.get = null; });
            attempt('atlas.jira.issue.get.x', () => { atlas.jira.issue.get.x = 1; });
            attempt('atlas.new', () => { atlas.fresh = 1; });
            attempt('atlas.ops()', () => { atlas.ops().push('x'); });
            attempt('atlas.instances()[0].alias', () => { atlas.instances()[0].alias = 'x'; });
            attempt('delete atlas.log', () => { delete atlas.log; });
            out.push(Object.isFrozen(args.a.b[1]) && Object.isFrozen(atlas.jira.issue));
            return out;
        "#;
        let init = init_with(
            source,
            json!({"a": {"b": [1, {"c": 2}]}}),
            ScriptLimits::default(),
        );
        let (settled, _) = run(&init)?;
        let expected = json!([
            "args.a:TypeError",
            "args.a.b[1].c:TypeError",
            "args.a.b.push:TypeError",
            "args.new:TypeError",
            "atlas.call:TypeError",
            "atlas.jira.issue.get:TypeError",
            "atlas.jira.issue.get.x:TypeError",
            "atlas.new:TypeError",
            "atlas.ops():TypeError",
            "atlas.instances()[0].alias:TypeError",
            "delete atlas.log:TypeError",
            true
        ]);
        let got = result_json(&settled)?;
        if got != expected {
            return Err(format!("got {got}"));
        }
        Ok(())
    })
}

#[test]
fn atlas_read_ops_generated_from_init() -> TestResult {
    big_stack(|| {
        let source = r#"
            const kinds = [typeof atlas.jira.issue.get, typeof atlas.jira.search,
                           typeof atlas.confluence.page.get];
            atlas.jira.issue.get({ key: 'A-1' }, { instance: 'prod' });
            return { kinds, ops: atlas.ops(), instances: atlas.instances() };
        "#;
        let (settled, sent) = run(&init(source))?;
        let got = result_json(&settled)?;
        let expected = json!({
            "kinds": ["function", "function", "function"],
            "ops": ["jira.issue.get", "jira.search", "confluence.page.get"],
            "instances": [
                {"alias": "prod", "product": "jira", "is_default": true},
                {"alias": "wiki", "product": "confluence", "is_default": false}
            ]
        });
        if got != expected {
            return Err(format!("got {got}"));
        }
        let call = HostCall {
            id: 1,
            op_id: "jira.issue.get".into(),
            params: json!({"key": "A-1"}),
            instance: Some("prod".into()),
            all: false,
        };
        if sent != vec![Sent::Call(1, call)] {
            return Err(format!("sent {sent:?}"));
        }
        Ok(())
    })
}

#[test]
fn write_op_names_absent_from_atlas() -> TestResult {
    big_stack(|| {
        let source = "return [atlas.jira.issue.create === undefined, \
                      atlas.jira.issue.delete === undefined, 'create' in atlas.jira.issue, \
                      Object.keys(atlas).sort()];";
        let (settled, _) = run(&init(source))?;
        let got = result_json(&settled)?;
        let expected = json!([
            true,
            true,
            false,
            [
                "all",
                "call",
                "confluence",
                "instances",
                "jira",
                "log",
                "ops"
            ]
        ]);
        if got != expected {
            return Err(format!("got {got}"));
        }
        Ok(())
    })
}

#[test]
fn import_fails_no_module_loader() -> TestResult {
    big_stack(|| {
        match compile("import x from 'y';\nreturn x;") {
            Err(CompileError::Syntax(_)) => {}
            other => return Err(format!("static import: {other:?}")),
        }
        let source = "try { await import('x'); return 'resolved'; } \
                      catch (err) { return 'rejected'; }";
        let (settled, _) = run(&init(source))?;
        if result_json(&settled)? != json!("rejected") {
            return Err(format!("dynamic import: {settled:?}"));
        }
        Ok(())
    })
}

#[test]
fn excluded_intrinsics_absent() -> TestResult {
    big_stack(|| {
        let source = "return ['Proxy', 'WeakRef', 'FinalizationRegistry', 'ArrayBuffer', \
                      'Uint8Array', 'DataView', 'Atomics', 'SharedArrayBuffer', 'performance', \
                      'Performance', 'DOMException'].map((n) => typeof globalThis[n]);";
        let (settled, _) = run(&init(source))?;
        let got = result_json(&settled)?;
        if got != json!(vec!["undefined"; 11]) {
            return Err(format!("got {got}"));
        }
        let source = "return [typeof JSON, typeof Promise, typeof Map, typeof Set, \
                      typeof Date, typeof RegExp, typeof eval];";
        let (settled, _) = run(&init(source))?;
        let got = result_json(&settled)?;
        let expected = json!([
            "object", "function", "function", "function", "function", "function", "function"
        ]);
        if got != expected {
            return Err(format!("enabled: got {got}"));
        }
        Ok(())
    })
}

/// PD-134: a refused QuickJS allocation sets `heap_refused`; the script catches the
/// `InternalError` but is stopped before any further send, and QuickJS's own `malloc_limit` stays
/// 0 (`set_memory_limit` is never called).
#[test]
fn heap_limit_is_uncatchable_and_flags_heap_mb() -> TestResult {
    big_stack(|| {
        let source = r#"
            function bomb() { const a = []; for (;;) a.push(new Array(65536).fill(1.5)); }
            for (let i = 0; i < 100; i++) {
              try { bomb(); } catch (err) {}
              atlas.log('survived ' + i);
              atlas.call('jira.search', {});
            }
            return 'returned';
        "#;
        let limits = ScriptLimits {
            heap_mb: 8,
            ..ScriptLimits::default()
        };
        let mut engine =
            Engine::new(&init_with(source, json!({}), limits), FakeHost::default()).map_err(e)?;
        if engine.memory_usage().malloc_limit != 0 {
            return Err("set_memory_limit was called".into());
        }
        let settled = start_and_drain(&mut engine);
        if !matches!(settled, Settled::Halted(Halt::HeapLimit)) {
            return Err(format!("settled {settled:?}"));
        }
        if !engine.host().sent.is_empty() {
            return Err(format!("sent after the refusal: {:?}", engine.host().sent));
        }
        let meter = engine.meter();
        if !meter.heap_refused() || meter.system_null() {
            return Err("flags".into());
        }
        if meter.limit() != 8 * 1024 * 1024 {
            return Err(format!("limit {}", meter.limit()));
        }
        // Every further entry reports the same halt without running anything.
        if !matches!(engine.drain_jobs(), Settled::Halted(Halt::HeapLimit)) {
            return Err("second drain".into());
        }
        Ok(())
    })
}

/// An allocator below the wrapper that returns null sets only `system_null`; a request above the
/// limit sets only `heap_refused`; freed blocks leave the count.
#[test]
fn system_null_is_not_heap_refused() -> TestResult {
    struct NullInner;
    // SAFETY: every method returns null or does nothing; nothing is ever handed out.
    unsafe impl Allocator for NullInner {
        fn alloc(&mut self, _size: usize) -> *mut u8 {
            std::ptr::null_mut()
        }
        fn calloc(&mut self, _count: usize, _size: usize) -> *mut u8 {
            std::ptr::null_mut()
        }
        unsafe fn dealloc(&mut self, _ptr: *mut u8) {}
        unsafe fn realloc(&mut self, _ptr: *mut u8, _new_size: usize) -> *mut u8 {
            std::ptr::null_mut()
        }
        unsafe fn usable_size(_ptr: *mut u8) -> usize {
            0
        }
    }

    let (mut null_alloc, null_state) = LimitAllocator::with_inner(1 << 20, NullInner);
    assert!(null_alloc.alloc(64).is_null());
    assert!(null_alloc.calloc(4, 16).is_null());
    assert!(null_state.system_null());
    assert!(!null_state.heap_refused());

    let (mut alloc, state) = LimitAllocator::new(1024);
    assert!(alloc.alloc(4096).is_null());
    assert!(state.heap_refused());
    assert!(!state.system_null());

    let (mut alloc, state) = LimitAllocator::new(1 << 20);
    let block = alloc.alloc(100);
    assert!(!block.is_null());
    assert!(state.in_use() >= 100);
    // SAFETY: `block` came from this allocator and is freed once.
    let grown = unsafe { alloc.realloc(block, 4000) };
    assert!(!grown.is_null());
    assert!(state.in_use() >= 4000);
    assert!(state.peak() >= state.in_use());
    // SAFETY: `grown` came from this allocator and is freed once.
    unsafe { alloc.dealloc(grown) };
    assert_eq!(state.in_use(), 0);
    assert!(!state.heap_refused() && !state.system_null());
    Ok(())
}

/// PD-135: the worker's deadline (a backstop at `timeout_s + 2 s`) and the op budget stop a
/// CPU-bound loop, even one inside `try`, and a promise-job loop.
#[test]
fn interrupt_deadline_and_op_budget_stop_cpu_loop() -> TestResult {
    assert_eq!(backstop(&ScriptLimits::default()), Duration::from_secs(122));
    let mut one = OpBudget::new(1);
    assert!(!one.tick() && one.tick());
    assert_eq!(OP_BUDGET_CALLBACKS, 1 << 25);
    big_stack(|| {
        let deadline_cases = [
            "while (true) {}",
            "try { while (true) {} } catch (err) {} return 'caught';",
            "const f = () => Promise.resolve().then(f); f(); await new Promise(() => {});",
            // Catastrophic backtracking: libregexp polls the interrupt handler (no interpreter
            // tick happens inside the match).
            "try { /(a+)+$/.test('a'.repeat(40) + 'b'); } catch (err) {} return 'caught';",
        ];
        for source in deadline_cases {
            let mut engine = Engine::with_interrupts(
                &init(source),
                FakeHost::default(),
                // Wide enough that building the engine on a slow CI runner never reaches it.
                Deadline::after(Duration::from_secs(1)),
                OpBudget::default(),
            )
            .map_err(e)?;
            let settled = start_and_drain(&mut engine);
            if !matches!(settled, Settled::Halted(Halt::Deadline)) {
                return Err(format!("{source}: {settled:?}"));
            }
        }
        let mut engine = Engine::with_interrupts(
            &init("let i = 0; while (true) { i++; }"),
            FakeHost::default(),
            Deadline::after(Duration::from_secs(3600)),
            OpBudget::new(20),
        )
        .map_err(e)?;
        let settled = start_and_drain(&mut engine);
        if !matches!(settled, Settled::Halted(Halt::OpBudget)) {
            return Err(format!("op budget: {settled:?}"));
        }
        Ok(())
    })
}

#[test]
fn deep_recursion_is_a_range_error_not_a_crash() -> TestResult {
    big_stack(|| {
        let source = "function f() { return f(); } \
                      try { f(); return 'returned'; } \
                      catch (err) { return err instanceof RangeError ? 'RangeError' : String(err); }";
        let (settled, _) = run(&init(source))?;
        if result_json(&settled)? != json!("RangeError") {
            return Err(format!("caught: {settled:?}"));
        }
        let (settled, _) = run(&init("function g() { return g(); } return g();"))?;
        match settled {
            Settled::Error(err) if err.class == "RangeError" => Ok(()),
            other => Err(format!("uncaught: {other:?}")),
        }
    })
}

/// §9.2: at most `max_concurrent_calls` calls are outstanding; the rest wait locally and go out
/// one per settled call, in call order.
#[test]
fn local_concurrency_queue_caps_outstanding_calls() -> TestResult {
    big_stack(|| {
        let source = r#"
            const ps = [];
            for (let i = 1; i <= 8; i++) ps.push(atlas.call('jira.search', { i }));
            return await Promise.all(ps);
        "#;
        let limits = ScriptLimits {
            max_concurrent_calls: 4,
            ..ScriptLimits::default()
        };
        let mut engine =
            Engine::new(&init_with(source, json!({}), limits), FakeHost::default()).map_err(e)?;
        let settled = start_and_drain(&mut engine);
        if !matches!(settled, Settled::Pending { outstanding: 4 }) {
            return Err(format!("after start: {settled:?}"));
        }
        if call_ids(&engine.host().sent) != vec![1, 2, 3, 4] {
            return Err(format!("first wave {:?}", engine.host().sent));
        }
        // Answers arrive out of order; each one releases exactly one queued call.
        let mut expected_sent = vec![1, 2, 3, 4];
        let mut next_queued = 5;
        for id in [3, 1, 4, 2, 6, 5, 8, 7] {
            engine.deliver(&ok_frame(id, json!(id * 10))?).map_err(e)?;
            if next_queued <= 8 {
                expected_sent.push(next_queued);
                next_queued += 1;
            }
            let settled = engine.drain_jobs();
            if call_ids(&engine.host().sent) != expected_sent {
                return Err(format!("after {id}: {:?}", engine.host().sent));
            }
            if id != 7 && !matches!(settled, Settled::Pending { .. }) {
                return Err(format!("after {id}: {settled:?}"));
            }
            if id == 7 {
                let got = result_json(&settled)?;
                if got != json!([10, 20, 30, 40, 50, 60, 70, 80]) {
                    return Err(format!("result {got}"));
                }
            }
        }
        Ok(())
    })
}

#[test]
fn all_sets_the_all_flag() -> TestResult {
    big_stack(|| {
        let source = "atlas.all('jira.search', { jql: 'x' }); \
                      atlas.call('jira.search', {}); \
                      atlas.jira.search(); \
                      return 0;";
        let (_, sent) = run(&init(source))?;
        let flags: Vec<(bool, Json_)> = sent
            .iter()
            .filter_map(|s| match s {
                Sent::Call(_, call) => Some((call.all, call.params.clone())),
                Sent::Log(_) => None,
            })
            .collect();
        let expected = vec![
            (true, json!({"jql": "x"})),
            (false, json!({})),
            (false, json!({})),
        ];
        if flags != expected {
            return Err(format!("got {flags:?}"));
        }
        Ok(())
    })
}

/// R4, PD-151: the local-time surface of `Date` is UTC on every OS. On the Windows dev laptop the
/// test process runs in a non-UTC zone, which makes this the real check (QuickJS-NG ignores TZ
/// there).
#[test]
fn date_local_methods_are_utc() -> TestResult {
    big_stack(|| {
        let source = r#"
            const fails = [];
            const check = (name, ok) => { if (!ok) fails.push(name); };

            // The M1 self-test's UTC assertions.
            const d = new Date(2026, 0, 1);
            check('getHours', d.getHours() === 0);
            check('getTimezoneOffset is 0', d.getTimezoneOffset() === 0);
            check('local equals UTC', d.getTime() === Date.UTC(2026, 0, 1));
            check('component ctor full', new Date(2026, 6, 15, 13, 45, 30, 123).getTime()
                  === Date.UTC(2026, 6, 15, 13, 45, 30, 123));
            check('component ctor 2-digit year', new Date(99, 0).getTime() === Date.UTC(1999, 0));

            const t = new Date(Date.UTC(2026, 6, 15, 23, 45, 30, 123));
            for (const n of ['FullYear', 'Month', 'Date', 'Day', 'Hours', 'Minutes', 'Seconds',
                             'Milliseconds']) {
              check('get' + n, t['get' + n]() === t['getUTC' + n]());
            }
            const setters = [['FullYear', [2020, 1, 2]], ['Month', [3, 4]], ['Date', [9]],
                             ['Hours', [1, 2, 3, 4]], ['Minutes', [5, 6, 7]], ['Seconds', [8, 9]],
                             ['Milliseconds', [10]], ['Hours', [5]]];
            for (const [n, args] of setters) {
              const a = new Date(t.getTime());
              const b = new Date(t.getTime());
              const ra = a['set' + n](...args);
              const rb = b['setUTC' + n](...args);
              check('set' + n + '(' + args + ')', ra === rb && a.getTime() === b.getTime());
            }
            check('getYear', t.getYear() === 126);
            const y = new Date(t.getTime());
            y.setYear(99);
            check('setYear 2-digit', y.getUTCFullYear() === 1999 && y.getUTCHours() === 23);
            y.setYear(2030);
            check('setYear 4-digit', y.getUTCFullYear() === 2030);
            const bad = new Date(NaN);
            check('invalid getTimezoneOffset', Number.isNaN(bad.getTimezoneOffset()));
            check('invalid toString', bad.toString() === 'Invalid Date'
                  && bad.toLocaleString() === 'Invalid Date');

            // Strings: the date-time forms without an offset read as UTC; explicit zones kept.
            check('parse local form', Date.parse('2026-01-01T00:00') === Date.UTC(2026, 0, 1));
            check('new Date(local form)', new Date('2026-01-01T00:00').getTime() === Date.UTC(2026, 0, 1));
            check('parse seconds', Date.parse('2026-01-01T10:20:30.5') === Date.UTC(2026, 0, 1, 10, 20, 30, 500));
            check('parse offset', Date.parse('2026-01-01T00:00+02:00') === Date.UTC(2025, 11, 31, 22));
            check('parse Z', Date.parse('2026-01-01T00:00:00Z') === Date.UTC(2026, 0, 1));
            check('parse date only', Date.parse('2026-01-01') === Date.UTC(2026, 0, 1));
            check('parse other form', Date.parse('Jan 1 2026 10:00') === Date.UTC(2026, 0, 1, 10));
            check('parse other form with zone', Date.parse('Jan 1 2026 10:00 GMT+0200') === Date.UTC(2026, 0, 1, 8));
            check('parse own toString', Date.parse(t.toString()) === Date.UTC(2026, 6, 15, 23, 45, 30));
            check('parse garbage', Number.isNaN(Date.parse('not a date')));

            // Renderings in QuickJS's own formats, in UTC.
            const z = new Date(Date.UTC(2026, 0, 1, 0, 0, 0));
            check('toString', z.toString() === 'Thu Jan 01 2026 00:00:00 GMT+0000');
            check('toDateString', z.toDateString() === 'Thu Jan 01 2026');
            check('toTimeString', z.toTimeString() === '00:00:00 GMT+0000');
            check('toLocaleString', z.toLocaleString() === '01/01/2026, 12:00:00 AM');
            check('toLocaleDateString', z.toLocaleDateString() === '01/01/2026');
            check('toLocaleTimeString', t.toLocaleTimeString() === '11:45:30 PM');
            check('string concatenation', ('' + z) === z.toString());
            check('negative year', new Date(Date.UTC(-1, 0, 1)).toDateString() === 'Fri Jan 01 -0001');
            check('Date() is a UTC string', typeof Date() === 'string' && / GMT\+0000$/.test(Date()));

            // Constructor identity.
            check('instanceof', new Date() instanceof Date);
            check('prototype.constructor', Date.prototype.constructor === Date);
            check('statics', typeof Date.UTC === 'function' && typeof Date.now === 'function'
                  && typeof Date.parse === 'function');
            check('length', Date.length === 7 && Date.name === 'Date');
            check('copy', new Date(z).getTime() === z.getTime());
            check('number', new Date(0).getTime() === 0);
            class Sub extends Date {}
            const s = new Sub(2026, 0, 1);
            check('subclass', s instanceof Sub && s instanceof Date && s.getTime() === Date.UTC(2026, 0, 1));
            check('toISOString', z.toISOString() === '2026-01-01T00:00:00.000Z');
            check('JSON', JSON.stringify({ z }) === '{"z":"2026-01-01T00:00:00.000Z"}');
            return fails;
        "#;
        let (settled, _) = run(&init(source))?;
        let got = result_json(&settled)?;
        if got != json!([]) {
            return Err(format!("failed checks: {got}"));
        }
        Ok(())
    })
}

#[test]
fn atlas_log_stringifies_arguments() -> TestResult {
    big_stack(|| {
        let source = r#"
            atlas.log('a', 1, true, null, undefined, { x: 1 }, [1, 2], Symbol('s'));
            atlas.log();
            atlas.log('lone \ud800 surrogate');
            return 0;
        "#;
        let (settled, sent) = run(&init(source))?;
        if result_json(&settled)? != json!(0) {
            return Err(format!("{settled:?}"));
        }
        let expected = vec![
            Sent::Log("a 1 true null undefined [object Object] 1,2 Symbol(s)".into()),
            Sent::Log(String::new()),
            Sent::Log("lone \u{FFFD} surrogate".into()),
        ];
        if sent != expected {
            return Err(format!("sent {sent:?}"));
        }
        Ok(())
    })
}

/// A log line is cut in the shim to the 1 MiB frame cap in UTF-16 units before it is copied to
/// Rust (the run loop then cuts it exactly in bytes and marks it); a pair split by the cut becomes
/// U+FFFD.
#[test]
fn log_line_is_cut_to_the_frame_cap_before_the_native() -> TestResult {
    big_stack(|| {
        let source = r#"
            atlas.log('x'.repeat(1100000));
            atlas.log('a' + '\u{1F600}'.repeat(600000));
            return 0;
        "#;
        let (settled, sent) = run(&init(source))?;
        if result_json(&settled)? != json!(0) {
            return Err(format!("{settled:?}"));
        }
        let cap = 1024 * 1024;
        match sent.as_slice() {
            [Sent::Log(ascii), Sent::Log(wide)]
                if ascii.len() == cap
                    && wide.encode_utf16().count() == cap
                    && wide.ends_with("\u{1F600}\u{FFFD}") => {}
            other => {
                let lens: Vec<usize> = other
                    .iter()
                    .map(|s| match s {
                        Sent::Log(line) => line.encode_utf16().count(),
                        Sent::Call(..) => 0,
                    })
                    .collect();
                return Err(format!("sent lines of {lens:?} UTF-16 units"));
            }
        }
        Ok(())
    })
}

/// §15 V02 on the script runtime: evaluating the wrapper needs the Eval intrinsic.
#[test]
fn v02_host_side_eval_still_needs_eval() -> TestResult {
    big_stack(|| {
        let (rt, _state) = new_runtime_with_heap_limit(16 * 1024 * 1024).map_err(e)?;
        let wrapper = wrapper_source("return 1;");

        let without = Context::custom::<(Json, Promise, RegExp, MapSet, Date)>(&rt).map_err(e)?;
        let err = without.with(|ctx| {
            ctx.eval::<Value, _>(wrapper.clone())
                .catch(&ctx)
                .map(|_| ())
                .map_err(|err| err.to_string())
        });
        match err {
            Err(text) if text.contains("eval is not supported") => {}
            other => return Err(format!("without Eval: {other:?}")),
        }

        let with = new_context(&rt).map_err(e)?;
        with.with(|ctx| {
            ctx.eval::<Value, _>(wrapper)
                .catch(&ctx)
                .map(|v| v.is_function())
                .map_err(|err| err.to_string())
        })
        .and_then(|is_fn| {
            if is_fn {
                Ok(())
            } else {
                Err("not a function".into())
            }
        })
    })
}

/// A host rejection is a catchable `AtlasError` carrying the host's class and details.
#[test]
fn host_rejection_is_a_catchable_atlas_error() -> TestResult {
    big_stack(|| {
        let source = r#"
            try { await atlas.jira.issue.get({ key: 'A-1' }); return 'resolved'; }
            catch (err) {
              return [err instanceof Error, err.name, err.class, err.details, err.message];
            }
        "#;
        let mut engine = Engine::new(&init(source), FakeHost::default()).map_err(e)?;
        start_and_drain(&mut engine);
        let frame = String::from_utf8(encode_response(
            1,
            &HostCallResult::Rejected {
                class: "validation".into(),
                details: json!({"param": "key"}),
            },
        ))
        .map_err(e)?;
        engine.deliver(&frame).map_err(e)?;
        let got = result_json(&engine.drain_jobs())?;
        let expected = json!([true, "AtlasError", "validation", {"param": "key"},
                              "host call rejected: validation"]);
        if got != expected {
            return Err(format!("got {got}"));
        }
        Ok(())
    })
}

/// A host frame the dispatcher cannot use is a protocol halt, never a settlement.
#[test]
fn malformed_host_frames_are_protocol_halts() -> TestResult {
    big_stack(|| {
        let bad = [
            "not json".to_owned(),
            r#"{"jsonrpc":"2.0","id":1}"#.to_owned(),
            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":1,"rejected":{}}}"#.to_owned(),
            r#"{"jsonrpc":"1.0","id":1,"result":{"ok":1}}"#.to_owned(),
            ok_frame(2, json!(1))?,
        ];
        for frame in bad {
            let mut engine = Engine::new(
                &init("return await atlas.call('jira.search', {});"),
                FakeHost::default(),
            )
            .map_err(e)?;
            start_and_drain(&mut engine);
            match engine.deliver(&frame) {
                Err(Halt::Protocol(_)) => {}
                other => return Err(format!("{frame}: {other:?}")),
            }
        }
        Ok(())
    })
}

/// PD-136 and the JSON result rules: `undefined` is `null`; a top-level value JSON cannot encode
/// is a `TypeError`; a result above the terminal-frame cap is `ResultTooLarge`.
#[test]
fn result_json_rules_and_size_cap() -> TestResult {
    big_stack(|| {
        let (settled, _) = run(&init("return undefined;"))?;
        if result_json(&settled)? != json!(null) {
            return Err(format!("undefined: {settled:?}"));
        }
        let (settled, _) = run(&init("return () => 1;"))?;
        match settled {
            Settled::Error(err) if err.class == "TypeError" => {}
            other => return Err(format!("function: {other:?}")),
        }
        let limits = ScriptLimits {
            max_result_mb: 1,
            ..ScriptLimits::default()
        };
        for source in [
            "return 'x'.repeat(2 * 1024 * 1024);",
            "return '\u{e9}'.repeat(600 * 1024);",
        ] {
            let (settled, _) = run(&init_with(source, json!({}), limits))?;
            match settled {
                Settled::Error(err) if err.class == "ResultTooLarge" => {}
                other => return Err(format!("{source}: {other:?}")),
            }
        }
        Ok(())
    })
}

/// PD-136 at the exact boundary: a result text of exactly the cap in UTF-8 bytes is a result, one
/// byte more is `ResultTooLarge`. ASCII is decided by the shim's UTF-16 pre-check; a multi-byte
/// text whose UTF-16 length is far below the cap is decided by the exact UTF-8 check in Rust.
#[test]
fn result_size_cap_exact_boundary() -> TestResult {
    big_stack(|| {
        let limits = ScriptLimits {
            max_result_mb: 1,
            ..ScriptLimits::default()
        };
        // The engine's cap: the terminal frame minus its 64 KiB envelope slack.
        let cap = terminal_frame_max(&limits) - 64 * 1024;
        // A string's JSON text is its characters plus two quotes.
        let ascii = cap - 2;
        if !ascii.is_multiple_of(2) {
            return Err(format!("cap {cap} is odd"));
        }
        let wide = (cap - 2) / 2;
        let cases = [
            (format!("return 'x'.repeat({ascii});"), Some(cap)),
            (format!("return 'x'.repeat({});", ascii + 1), None),
            (format!("return '\u{e9}'.repeat({wide});"), Some(cap)),
            (format!("return '\u{e9}'.repeat({wide}) + 'a';"), None),
        ];
        for (source, fits) in cases {
            let (settled, _) = run(&init_with(&source, json!({}), limits))?;
            match (fits, settled) {
                (Some(len), Settled::Result(text)) if text.len() == len => {}
                (None, Settled::Error(err)) if err.class == "ResultTooLarge" => {}
                (_, other) => {
                    let shown = match other {
                        Settled::Result(text) => format!("a result of {} bytes", text.len()),
                        other => format!("{other:?}"),
                    };
                    return Err(format!("{source}: {shown}"));
                }
            }
        }
        Ok(())
    })
}

/// A host call the host could not take rejects inside the script and is never sent: params that
/// nest too deep for the host's decoder (one level deeper inside a `HostCall` than in a bare
/// `Value` parse; T2 review note) and a frame above 1 MiB.
#[test]
fn undecodable_or_oversized_calls_reject_in_script_and_send_nothing() -> TestResult {
    big_stack(|| {
        let source = r#"
            const deep = (n) => { let v = 0; for (let i = 0; i < n; i++) v = [v]; return v; };
            const out = [];
            for (let n = 120; n <= 135; n++) {
              atlas.call('jira.search', deep(n)).then(() => {}, (err) => out.push([n, err.name, err.message]));
            }
            const big = await atlas.call('jira.search', { s: 'x'.repeat(1100000) })
              .then(() => 'sent', (err) => [err.name, err.message]);
            return { out, big };
        "#;
        let limits = ScriptLimits {
            max_concurrent_calls: 16,
            ..ScriptLimits::default()
        };
        let (settled, sent) = run(&init_with(source, json!({}), limits))?;
        let got = result_json(&settled)?;
        if got["big"] != json!(["RangeError", CALL_TOO_LARGE]) {
            return Err(format!("big: {got}"));
        }
        let out = got["out"].as_array().ok_or("out")?;
        let first = out
            .first()
            .and_then(|r| r[0].as_u64())
            .ok_or("no call was rejected")?;
        for (i, rejected) in out.iter().enumerate() {
            let expected = json!([first + i as u64, "TypeError", CALL_NOT_DECODABLE]);
            if *rejected != expected {
                return Err(format!("rejected {rejected}, expected {expected}"));
            }
        }
        if first + out.len() as u64 != 136 || call_ids(&sent).len() as u64 != first - 120 {
            return Err(format!(
                "first rejected depth {first}, sent {}",
                call_ids(&sent).len()
            ));
        }
        // The first refused depth still parses as a bare `Value`: only the decoder check refuses it.
        let text = format!(
            "{}0{}",
            "[".repeat(first as usize),
            "]".repeat(first as usize)
        );
        serde_json::from_str::<Json_>(&text).map_err(|err| format!("bare parse: {err}"))?;
        Ok(())
    })
}

/// An exception thrown out of a `queueMicrotask` callback (the only job that can throw past its
/// own handler) ends the run as a script error, never as an engine halt; `main`'s own earlier
/// settlement wins.
#[test]
fn uncaught_microtask_exception_is_a_script_error() -> TestResult {
    big_stack(|| {
        let source = "queueMicrotask(() => { throw new TypeError('from a microtask'); }); \
                      await new Promise(() => {});";
        let mut engine = Engine::new(&init(source), FakeHost::default()).map_err(e)?;
        match start_and_drain(&mut engine) {
            Settled::Error(err)
                if err.class == "TypeError" && err.message == "from a microtask" => {}
            other => return Err(format!("object: {other:?}")),
        }
        // The run is over: no later drain turns it into something else.
        if !matches!(engine.drain_jobs(), Settled::Halted(Halt::Engine(_))) {
            return Err("second drain".into());
        }
        let (settled, _) = run(&init(
            "queueMicrotask(() => { throw 42; }); await new Promise(() => {});",
        ))?;
        match settled {
            Settled::Error(err) if err.class == "Error" && err.message == "42" => {}
            other => return Err(format!("primitive: {other:?}")),
        }
        // `main` settles in the job before the throwing microtask runs.
        let (settled, _) = run(&init(
            "Promise.resolve().then(() => queueMicrotask(() => { throw new Error('late'); })); return 7;",
        ))?;
        if result_json(&settled)? != json!(7) {
            return Err(format!("late: {settled:?}"));
        }
        // `main` fulfilled before the microtask threw, though its observer's job runs after the
        // throwing one: main's promise state at the throw decides, not job order.
        let (settled, _) = run(&init(
            "queueMicrotask(() => { throw new Error('early'); }); return 7;",
        ))?;
        if result_json(&settled)? != json!(7) {
            return Err(format!("early: {settled:?}"));
        }
        Ok(())
    })
}

/// The shim only uses intrinsics it captured and objects agent code cannot reach, so tampering
/// with `Promise`, `Object.prototype`, the `AtlasError` class or `Error` changes what the script
/// itself sees and never the dispatcher: every run ends as a result, a script error or pending,
/// never as `Halt::Engine`, and call ids leave strictly increasing.
#[test]
fn shim_survives_intrinsic_tampering() -> TestResult {
    big_stack(|| {
        type Answer = fn(u64) -> Result<String, String>;
        let ok: Answer = |id| ok_frame(id, json!({"a": id}));
        let rejected: Answer = rejected_frame;
        let cases: [(&str, &str, Answer, Settled); 7] = [
            (
                "species getter",
                r#"
                Object.defineProperty(Promise, Symbol.species, { get() { return 1; } });
                const a = await atlas.call('jira.search', {});
                return a;
                "#,
                ok,
                Settled::Result(r#"{"a":1}"#.into()),
            ),
            (
                // QuickJS-NG rejects an async function's own promise (instead of throwing at the
                // `await`) when reading `constructor` throws; main's value still reaches the host.
                "throwing Promise.prototype.constructor, main returns",
                r#"
                Object.defineProperty(Promise.prototype, 'constructor', {
                  get() { throw new Error('ctor'); }
                });
                return 5;
                "#,
                ok,
                Settled::Result("5".into()),
            ),
            (
                "throwing Promise.prototype.constructor, main awaits",
                r#"
                Object.defineProperty(Promise.prototype, 'constructor', {
                  get() { throw new Error('ctor'); }
                });
                await atlas.call('jira.search', {});
                return 'after';
                "#,
                ok,
                Settled::Error(ScriptError {
                    class: "Error".into(),
                    message: "ctor".into(),
                    stack: String::new(),
                }),
            ),
            (
                "Object.prototype setters",
                r#"
                for (const k of ['class', 'details', 'name', 'message', 'get', 'set', 'value']) {
                  Object.defineProperty(Object.prototype, k, {
                    set() { throw new Error('setter ' + k); }, configurable: true
                  });
                }
                try { await atlas.call('jira.search', {}); return 'resolved'; }
                catch (e) { return [e.name, e.class, e.details, e.message]; }
                "#,
                rejected,
                Settled::Result(
                    r#"["AtlasError","validation",{"param":"key"},"host call rejected: validation"]"#
                        .into(),
                ),
            ),
            (
                "prototype swap of err.constructor, Error statics",
                r#"
                let first;
                try { await atlas.call('jira.search', {}); } catch (e) { first = e; }
                let swapped = 'swapped';
                try { Object.setPrototypeOf(first.constructor, function () { throw 0; }); }
                catch (err) { swapped = err.name; }
                Error.prepareStackTrace = () => { throw 0; };
                Error.stackTraceLimit = { valueOf() { throw 0; } };
                try { await atlas.call('jira.search', {}); return 'resolved'; }
                catch (e) { return [swapped, e.name, e.class, e instanceof first.constructor]; }
                "#,
                rejected,
                Settled::Result(r#"["TypeError","AtlasError","validation",true]"#.into()),
            ),
            (
                "throwing Object.prototype getters",
                r#"
                for (const k of ['then', 'jsonrpc', 'id', 'result', 'ok', 'rejected', 'class',
                                 'details', 'resolve', 'reject', 'length']) {
                  Object.defineProperty(Object.prototype, k, {
                    get() { throw new Error('getter ' + k); }, configurable: true
                  });
                }
                try { return await atlas.call('jira.search', {}); }
                catch (e) { return 'caught ' + e.message; }
                "#,
                ok,
                Settled::Result(r#""caught getter then""#.into()),
            ),
            (
                // The settlement of call 1 runs a then getter that makes call 4 while call 3 is
                // queued: deliver sends 3 before it settles, so 4 queues behind it.
                "settlement makes a call while one is queued",
                r#"
                let made = null;
                Object.defineProperty(Object.prototype, 'then', {
                  get() { if (made === null) made = atlas.call('jira.search', { n: 4 }); },
                  configurable: true
                });
                const a = atlas.call('jira.search', { n: 1 });
                const b = atlas.call('jira.search', { n: 2 });
                const c = atlas.call('jira.search', { n: 3 });
                return [await a, await b, await c, await made];
                "#,
                ok,
                Settled::Result(r#"[{"a":1},{"a":2},{"a":3},{"a":4}]"#.into()),
            ),
        ];
        let limits = ScriptLimits {
            max_concurrent_calls: 2,
            ..ScriptLimits::default()
        };
        for (name, source, answer, expected) in cases {
            let (settled, sent) = drive(&init_with(source, json!({}), limits), answer)?;
            if matches!(settled, Settled::Halted(Halt::Engine(_))) {
                return Err(format!("{name}: an engine halt: {settled:?}"));
            }
            let ids = call_ids(&sent);
            if ids.windows(2).any(|w| w[0] >= w[1]) {
                return Err(format!("{name}: ids not strictly increasing: {ids:?}"));
            }
            let settled = match settled {
                // The stack is engine-formatted; only class and message are pinned here.
                Settled::Error(err) => Settled::Error(ScriptError {
                    stack: String::new(),
                    ..err
                }),
                other => other,
            };
            if settled != expected {
                return Err(format!("{name}: {settled:?}"));
            }
        }
        Ok(())
    })
}

/// Index accessors on `Array.prototype` and `Object.prototype` cannot swallow a queued call or
/// make the dispatcher send a forged one (a reused id): queued calls go out with their own ids
/// and params, in call order.
#[test]
fn queued_calls_survive_index_accessors() -> TestResult {
    big_stack(|| {
        let source = r#"
            const forged = { id: 1, opId: 'jira.search', text: '{"forged":true}', instance: null,
                             all: false, resolve() {}, reject() {} };
            for (const proto of [Array.prototype, Object.prototype]) {
              for (let i = 0; i < 8; i++) {
                Object.defineProperty(proto, String(i), {
                  get() { return forged; }, set(v) {}, configurable: true
                });
              }
            }
            const p1 = atlas.call('jira.search', { n: 1 });
            const p2 = atlas.call('jira.search', { n: 2 });
            const p3 = atlas.call('jira.search', { n: 3 });
            const p4 = atlas.call('jira.search', { n: 4 });
            return [await p1, await p2, await p3, await p4];
        "#;
        let limits = ScriptLimits {
            max_concurrent_calls: 2,
            ..ScriptLimits::default()
        };
        let (settled, sent) = drive(&init_with(source, json!({}), limits), |id| {
            ok_frame(id, json!(id * 10))
        })?;
        if result_json(&settled)? != json!([10, 20, 30, 40]) {
            return Err(format!("settled {settled:?}"));
        }
        let calls: Vec<(u64, Json_)> = sent
            .iter()
            .filter_map(|s| match s {
                Sent::Call(id, call) if call.id == *id => Some((*id, call.params.clone())),
                _ => None,
            })
            .collect();
        let expected: Vec<(u64, Json_)> = (1..=4).map(|n| (n, json!({ "n": n }))).collect();
        if calls != expected || sent.len() != 4 {
            return Err(format!("sent {sent:?}"));
        }
        Ok(())
    })
}

/// A broken pipe on a send halts the run; the script cannot keep running into it.
#[test]
fn send_failure_halts_with_io() -> TestResult {
    big_stack(|| {
        let host = FakeHost {
            fail: Some(io::ErrorKind::BrokenPipe),
            ..FakeHost::default()
        };
        let source = "for (;;) { try { atlas.log('x'); } catch (err) {} }";
        let mut engine = Engine::new(&init(source), host).map_err(e)?;
        match start_and_drain(&mut engine) {
            Settled::Halted(Halt::Io(io::ErrorKind::BrokenPipe)) => Ok(()),
            other => Err(format!("{other:?}")),
        }
    })
}
