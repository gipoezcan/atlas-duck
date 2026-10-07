//! §9.3 engine configuration tests (§15 V02, V03, V11; gap G-5). They run on
//! every CI leg, so the `windows-2022` leg is the V03 evidence for
//! `x86_64-pc-windows-msvc`.

use std::process::Command;

use atlas_duck_sandbox_worker::engine::{
    ENGINE_VERSION, MAX_STACK_BYTES, SELFTEST_JS, new_context, new_runtime, run_selftest,
    run_selftest_in,
};
use rquickjs::context::intrinsic::{Date, Eval, Json, MapSet, Promise, RegExp};
use rquickjs::{CatchResultExt, Coerced, Context, Runtime};

/// Evaluates `src` and returns its string coercion, or the JS error text.
fn eval_string(ctx: &Context, src: &str) -> Result<String, String> {
    ctx.with(|ctx| {
        ctx.eval::<Coerced<String>, _>(src)
            .catch(&ctx)
            .map(|v| v.0)
            .map_err(|e| e.to_string())
    })
}

fn typeof_of(ctx: &Context, name: &str) -> String {
    eval_string(ctx, &format!("typeof {name}")).expect("typeof never throws")
}

/// Runs every pending promise job.
fn drain(rt: &Runtime) {
    while rt.is_job_pending() {
        rt.execute_pending_job().expect("job");
    }
}

fn fresh() -> (Runtime, Context) {
    let rt = new_runtime().expect("runtime");
    let ctx = new_context(&rt).expect("context");
    (rt, ctx)
}

#[test]
fn evaluates_source_with_the_eval_intrinsic() {
    let (_rt, ctx) = fresh();
    assert_eq!(eval_string(&ctx, "1+1").as_deref(), Ok("2"));
}

/// §15 V02. Settled: host-side `eval` of source needs the Eval intrinsic.
/// Without it, `Ctx::eval` fails with "eval is not supported". The Eval
/// intrinsic therefore stays in `new_context`.
#[test]
fn v02_host_side_eval_needs_the_eval_intrinsic() {
    let rt = new_runtime().expect("runtime");
    let without = Context::custom::<(Json, Promise, RegExp, MapSet, Date)>(&rt).expect("context");
    let err = eval_string(&without, "1+1").expect_err("eval must fail without Eval");
    assert!(
        err.contains("eval is not supported"),
        "unexpected error: {err}"
    );
}

#[test]
fn excluded_intrinsics_are_undefined() {
    let (_rt, ctx) = fresh();
    for name in [
        "ArrayBuffer",
        "Uint8Array",
        "DataView",
        "Proxy",
        "WeakRef",
        "Atomics",
        "SharedArrayBuffer",
        "performance",
        "Performance",
        "DOMException",
    ] {
        assert_eq!(
            typeof_of(&ctx, name),
            "undefined",
            "{name} must be excluded"
        );
    }
}

#[test]
fn enabled_intrinsics_are_defined() {
    let (_rt, ctx) = fresh();
    assert_eq!(typeof_of(&ctx, "JSON"), "object");
    for name in [
        "Promise", "Map", "Set", "Date", "RegExp", "eval", "Function",
    ] {
        assert_eq!(typeof_of(&ctx, name), "function", "{name} must be defined");
    }
}

/// Gap G-5, settled: regex literals and `new RegExp(..)` work without the
/// separate `RegExpCompiler` intrinsic, so `new_context` does not add it. If
/// this test ever fails after an rquickjs bump, add `RegExpCompiler` to the
/// tuple in `new_context` and record that in the go/no-go findings.
#[test]
fn g5_regexp_works_without_the_regexp_compiler_intrinsic() {
    let (_rt, ctx) = fresh();
    assert_eq!(eval_string(&ctx, "/a+/.test('aa')").as_deref(), Ok("true"));
    assert_eq!(
        eval_string(&ctx, "new RegExp('b+').test('bb')").as_deref(),
        Ok("true")
    );
    assert_eq!(
        eval_string(&ctx, "'x-1-2'.replace(/(\\d)-(\\d)/, '$2.$1')").as_deref(),
        Ok("x-2.1")
    );
}

#[test]
fn static_import_does_not_evaluate() {
    let (_rt, ctx) = fresh();
    let err = eval_string(&ctx, "import x from 'y'").expect_err("static import must fail");
    assert!(err.contains("Error"), "unexpected error: {err}");
}

#[test]
fn dynamic_import_rejects() {
    let (rt, ctx) = fresh();
    ctx.with(|ctx| {
        ctx.eval::<(), _>(
            "globalThis.outcome = 'pending';\
             import('x').then(function () { globalThis.outcome = 'resolved'; },\
                              function () { globalThis.outcome = 'rejected'; });",
        )
        .catch(&ctx)
        .expect("import() itself must not throw synchronously");
    });
    drain(&rt);
    assert_eq!(eval_string(&ctx, "outcome").as_deref(), Ok("rejected"));
}

/// The 1 MiB JS stack guard turns runaway recursion into a catchable
/// `RangeError`. Runs on an 8 MiB thread like the worker's main thread (the
/// default test thread has 2 MiB).
#[test]
fn deep_recursion_is_a_catchable_range_error() {
    assert_eq!(MAX_STACK_BYTES, 1024 * 1024);
    let handle = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_rt, ctx) = fresh();
            let caught = eval_string(
                &ctx,
                "function f() { return f(); }\
                 var r; try { f(); r = 'returned'; } catch (e) { r = (e instanceof RangeError) ? 'RangeError' : String(e); } r",
            );
            let uncaught = eval_string(&ctx, "function g() { return g(); } g()");
            (caught, uncaught)
        })
        .expect("spawn");
    let (caught, uncaught) = handle
        .join()
        .expect("the recursion must not crash the thread");
    assert_eq!(caught.as_deref(), Ok("RangeError"));
    let err = uncaught.expect_err("uncaught recursion is an error, not a crash");
    assert!(
        err.to_lowercase().contains("stack"),
        "unexpected error: {err}"
    );
}

/// `ENGINE_VERSION` is a constant, pinned against the linked engine's own
/// version string (`JS_GetVersion`). An rquickjs bump that changes the
/// bundled QuickJS-NG fails here until the constant is updated.
#[test]
fn engine_version_matches_the_linked_quickjs() {
    // SAFETY: `JS_GetVersion` returns a pointer to a static NUL-terminated string.
    let linked = unsafe { std::ffi::CStr::from_ptr(rquickjs::qjs::JS_GetVersion()) };
    assert_eq!(linked.to_str().expect("utf-8"), ENGINE_VERSION);
}

#[test]
fn selftest_source_is_text_not_bytecode() {
    assert!(SELFTEST_JS.starts_with("//"));
    assert!(SELFTEST_JS.is_ascii());
}

#[test]
fn selftest_passes_in_process() {
    run_selftest().expect("self-test");
}

/// Negative control: a context without the Date intrinsic must fail the
/// self-test, so a self-test that always passes cannot go unnoticed.
#[test]
fn selftest_fails_when_an_intrinsic_is_missing() {
    let rt = new_runtime().expect("runtime");
    let ctx = Context::custom::<(Eval, Json, Promise, RegExp, MapSet)>(&rt).expect("context");
    let err = run_selftest_in(&rt, &ctx, false).expect_err("must fail without Date");
    assert!(err.contains("Date"), "unexpected error: {err}");
}

/// Body of the child-process self-test. Ignored in a normal run; the parent
/// test below starts this test binary again with `TZ=UTC0` and runs it.
#[test]
#[ignore = "runs in a child process started by selftest_passes_in_a_child_with_tz_utc0"]
fn selftest_child_body() {
    assert_eq!(std::env::var("TZ").as_deref(), Ok("UTC0"));
    run_selftest().expect("self-test under TZ=UTC0");
}

/// §3.4 / §15 V11: the self-test passes in a process started with `TZ=UTC0`.
/// On Unix the self-test also asserts that local time is UTC. On Windows
/// QuickJS-NG reads the system time zone and ignores `TZ` (Task 14 findings),
/// so only the type checks of the `Date` methods apply there.
#[test]
fn selftest_passes_in_a_child_with_tz_utc0() {
    let exe = std::env::current_exe().expect("test binary path");
    let out = Command::new(exe)
        .args([
            "--ignored",
            "--exact",
            "selftest_child_body",
            "--test-threads=1",
        ])
        .env("TZ", "UTC0")
        .output()
        .expect("child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "child failed: status {:?}\nstdout:\n{stdout}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}
