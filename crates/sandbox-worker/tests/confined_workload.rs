//! §15 V11: a heavy JS workload runs under the real §9.4 confinement without
//! hitting a KILL rule. The probe worker only runs the small self-test; this
//! test also reaches the allocator paths that M8-sized heaps use (`mmap`,
//! `mremap`, `munmap`, many `brk` calls), local-time `Date` methods and
//! `toLocale*String` with `TZ=UTC0`.
//!
//! `harness = false` (see Cargo.toml): the libtest harness runs tests on extra
//! threads, and the filters cover only the calling thread, so `confine::apply`
//! refuses to run there. This `main` is the process's only thread. The parent
//! run re-executes this binary as the confined child.
//!
//! CI: `cargo test --workspace --locked` on the `ubuntu-22.04` leg; read
//! `Running tests/confined_workload.rs` followed by no error. A line
//! `confined child died with signal 31` names a syscall the allowlist lacks.
//! On other OSes `main` does nothing.

#[cfg(target_os = "linux")]
mod imp {
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, ExitCode, Stdio};

    use atlas_duck_sandbox_worker::{confine, engine};
    use rquickjs::CatchResultExt;

    const CHILD_ENV: &str = "ATLAS_DUCK_CONFINED_WORKLOAD_CHILD";
    const SIGSYS: i32 = 31;

    /// Allocation-heavy script: 300 000 objects, a JSON round trip, a 2 MB string,
    /// a 200 000-entry Map, local-time Date methods, a regex, Promise jobs.
    const WORKLOAD_JS: &str = r#"
    (function () {
      var a = [];
      for (var i = 0; i < 300000; i++) a.push({ k: i, s: 'x' + i, arr: [i, i + 1, i + 2] });
      var back = JSON.parse(JSON.stringify(a));
      if (back.length !== 300000 || back[299999].arr[2] !== 300001) return 'json round trip';
      var s = '';
      for (var i = 0; i < 200000; i++) s += 'abcdefghij';
      if (s.length !== 2000000) return 'string length';
      var m = new Map();
      for (var i = 0; i < 200000; i++) m.set('k' + i, i);
      if (m.size !== 200000) return 'map size';
      var d = new Date(2026, 0, 1);
      if (d.getHours() !== 0 || d.getTimezoneOffset() !== 0) return 'local time is not UTC0';
      if (typeof d.toLocaleString() !== 'string' || typeof d.toLocaleDateString() !== 'string') return 'toLocale';
      if (!/(a+)b/.test('aaab')) return 'regexp';
      var done = false;
      Promise.resolve(1).then(function () { done = true; });
      globalThis.__done = function () { return done; };
      return 'ok';
    })()
    "#;

    fn child() -> ExitCode {
        let report = match confine::apply() {
            Ok(report) => report,
            Err(e) => {
                println!("confine failed: {e}");
                return ExitCode::from(10);
            }
        };
        if !report.applied || report.seccomp != Some(true) {
            println!("confinement not applied: {report:?}");
            return ExitCode::from(11);
        }
        let Ok(rt) = engine::new_runtime() else {
            return ExitCode::from(12);
        };
        let Ok(ctx) = engine::new_context(&rt) else {
            return ExitCode::from(13);
        };
        let outcome: Result<String, String> = ctx.with(|ctx| {
            ctx.eval::<String, _>(WORKLOAD_JS)
                .catch(&ctx)
                .map_err(|e| e.to_string())
        });
        match outcome {
            Ok(s) if s == "ok" => {}
            Ok(s) => {
                println!("workload check failed: {s}");
                return ExitCode::from(14);
            }
            Err(e) => {
                println!("workload threw: {e}");
                return ExitCode::from(15);
            }
        }
        while rt.is_job_pending() {
            if rt.execute_pending_job().is_err() {
                return ExitCode::from(16);
            }
        }
        let drained: Result<bool, String> = ctx.with(|ctx| {
            ctx.eval::<bool, _>("__done()")
                .catch(&ctx)
                .map_err(|e| e.to_string())
        });
        if drained != Ok(true) {
            println!("promise job did not run: {drained:?}");
            return ExitCode::from(17);
        }
        // The full self-test of the probe worker, under the same filter.
        if let Err(failed) = engine::run_selftest() {
            println!("selftest failed: {failed}");
            return ExitCode::from(18);
        }
        println!("confined workload ok");
        ExitCode::SUCCESS
    }

    pub fn run() -> ExitCode {
        if std::env::var_os(CHILD_ENV).is_some() {
            return child();
        }
        let exe = std::env::current_exe().expect("this test binary");
        let output = Command::new(exe)
            .env_clear()
            .env("TZ", "UTC0")
            .env("MALLOC_ARENA_MAX", "1")
            .env(CHILD_ENV, "1")
            .stdin(Stdio::null())
            .output()
            .expect("run the confined child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if let Some(sig) = output.status.signal() {
            let hint = if sig == SIGSYS {
                " (SIGSYS: a syscall missing from the allowlist)"
            } else {
                ""
            };
            eprintln!(
                "confined child died with signal {sig}{hint}\nstdout: {stdout}\nstderr: {stderr}"
            );
            return ExitCode::FAILURE;
        }
        if output.status.code() != Some(0) || !stdout.contains("confined workload ok") {
            eprintln!(
                "confined child failed: {:?}\nstdout: {stdout}\nstderr: {stderr}",
                output.status
            );
            return ExitCode::FAILURE;
        }
        println!("confined_workload: ok");
        ExitCode::SUCCESS
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    imp::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {}
