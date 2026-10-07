//! The §9.3 rquickjs engine configuration.
//!
//! One fresh [`Runtime`] per run, on the worker's main thread. The worker
//! creates no other threads, so nothing here needs `parallel`, and the
//! `futures` feature stays off: pending promise jobs are drained by the
//! blocking loop (`Runtime::execute_pending_job`). Whether M8 needs `futures`
//! for the real `atlas.*` host calls is decided there (§15).

use rquickjs::context::intrinsic::{Date, Eval, Json, MapSet, Promise, RegExp};
use rquickjs::{CatchResultExt, Context, Function, Runtime};

/// QuickJS-NG version bundled by `rquickjs-sys` 0.14.0. Pinned against the
/// linked engine's own `JS_GetVersion()` by `tests/engine.rs`.
pub const ENGINE_VERSION: &str = "0.16.2";

/// `set_max_stack_size(1 MiB)` (§9.3). Above 16 MiB QuickJS disables the guard.
pub const MAX_STACK_BYTES: usize = 1024 * 1024;

/// Upper bound on job-queue iterations while draining the self-test.
const MAX_SELFTEST_JOBS: usize = 1000;

/// The embedded self-test: JS source text, never bytecode (§9.3).
pub const SELFTEST_JS: &str = include_str!("engine/selftest.js");

/// A fresh runtime with the 1 MiB JS stack guard.
pub fn new_runtime() -> rquickjs::Result<Runtime> {
    let rt = Runtime::new()?;
    rt.set_max_stack_size(MAX_STACK_BYTES);
    Ok(rt)
}

/// A context with the §9.3 minimal intrinsics: base objects (always present),
/// Eval, JSON, Promise, RegExp, MapSet, Date. Excluded: TypedArrays and
/// ArrayBuffer (also Atomics and SharedArrayBuffer), Proxy, WeakRef,
/// Performance, DOMException. `RegExpCompiler` is not added: regex literals
/// and `new RegExp(..)` work without it (gap G-5, `tests/engine.rs`). There is
/// no module loader, so every `import` fails.
pub fn new_context(rt: &Runtime) -> rquickjs::Result<Context> {
    Context::custom::<(Eval, Json, Promise, RegExp, MapSet, Date)>(rt)
}

/// Whether the self-test asserts that local time is UTC: on Unix, when the
/// process environment carries `TZ=UTC0` (§3.4: the host sets it for the
/// worker). Without it (an in-process test on a host in another time zone) the
/// assertion would fail for a reason that is not the engine's.
fn expects_utc() -> bool {
    cfg!(unix) && std::env::var("TZ").as_deref() == Ok("UTC0")
}

/// Runs [`SELFTEST_JS`] in a fresh runtime and context.
///
/// With `TZ=UTC0` in the environment on Unix (§3.4, the worker's env) the local-time
/// `Date` methods are asserted to be UTC; without it that assertion is skipped. On Windows QuickJS-NG reads the
/// system time zone with `GetTimeZoneInformation` and ignores `TZ`, so that
/// one assertion is skipped (see the Task 14 findings).
pub fn run_selftest() -> Result<(), String> {
    let rt = new_runtime().map_err(|e| format!("runtime: {e}"))?;
    let ctx = new_context(&rt).map_err(|e| format!("context: {e}"))?;
    run_selftest_in(&rt, &ctx, expects_utc())
}

/// Runs [`SELFTEST_JS`] in the given runtime and context, then drains the job
/// queue and collects the failed checks. `Err` lists the failed check names,
/// or the script error when the context lacks an intrinsic the test needs.
pub fn run_selftest_in(rt: &Runtime, ctx: &Context, expect_utc: bool) -> Result<(), String> {
    ctx.with(|ctx| {
        let start: Function = ctx
            .eval(SELFTEST_JS)
            .catch(&ctx)
            .map_err(|e| format!("selftest source: {e}"))?;
        start
            .call::<_, ()>((expect_utc,))
            .catch(&ctx)
            .map_err(|e| format!("selftest start: {e}"))
    })?;

    let mut jobs = 0;
    while rt.is_job_pending() {
        jobs += 1;
        if jobs > MAX_SELFTEST_JOBS {
            return Err("selftest job queue did not drain".to_owned());
        }
        rt.execute_pending_job()
            .map_err(|e| format!("selftest job: {e}"))?;
    }

    let failed: String = ctx.with(|ctx| {
        ctx.eval::<String, _>("__atlas_selftest_finish()")
            .catch(&ctx)
            .map_err(|e| format!("selftest finish: {e}"))
    })?;
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed)
    }
}
