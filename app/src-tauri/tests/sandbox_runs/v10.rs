//! V10 (M8 Task 9, §9.4 `heap_mb`/`process_mb`, §9.5, PD-134, §15 V10): host-measured memory
//! limits against the real worker through the platform spawner and `start_run`, per OS.
//!
//! - every OS: a QuickJS heap above `heap_mb` ends the run as `Limit("heap_mb")` (exit 102);
//! - macOS (arm64 and Rosetta): the footprint watchdog kills a worker above `process_mb`
//!   (`Limit("process_mb")`, diag `sandbox_watchdog_kill`); no timing assertion (L26), the kill
//!   time is printed as evidence only;
//! - Windows: the job refuses memory above `process_mb` (`Limit("process_mb")`; the job's
//!   completion-port message, if delivered, is the diag `sandbox_job_memory_limit`);
//! - Linux: the worker's allocation fails under `RLIMIT_AS` and it exits `EXIT_PROCESS_LIMIT`,
//!   never SIGSYS (`Limit("process_mb")`, the PD-134 evidence).
//!
//! The process cases use `heap_mb = 512` and `process_mb = 200`, which break core's invariant 2
//! (`process_mb ≥ heap_mb + 88`) on purpose: they call `start_run` directly, so the process limit
//! is reached first.

use std::sync::Arc;

use async_trait::async_trait;
use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::sandbox::script::{InstanceInfo, WorkerInit};
use atlas_duck_ipc::sandbox::{HostCall, HostCallResult, ScriptLimits};
use atlas_duck_sandbox_host::bridge::{
    ExpectedWorker, HostCallSink, HostVerdict, RunOutcome, start_run,
};
use atlas_duck_sandbox_host::identity::{SandboxBinaryIdentity, file_identity};
use atlas_duck_sandbox_host::platform_spawner;
use atlas_duck_sandbox_host::spawn::{SpawnSpec, WorkerSpawner};
use serde_json::json;

use super::*;

/// Grows the QuickJS heap by 16 KiB arrays with a little work between them (about 40 MB/s on a
/// CI runner), so the macOS watchdog, polling every 100 ms, sees the footprint pass
/// `process_mb` long before the heap reaches `heap_mb`.
const GROW: &str = "const keep = [];\n\
                    for (let i = 0; i < 10000000; i++) {\n\
                      keep.push(new Array(1024).fill(i));\n\
                      let s = 0;\n\
                      for (let j = 0; j < 5000; j++) s += j;\n\
                      if (s < 0) keep.length = 0;\n\
                    }\n\
                    return keep.length;";

/// The process cases' limits (see the module documentation).
const PROCESS_MB: u32 = 200;
const HEAP_MB_OVER_PROCESS: u32 = 512;

fn spawner() -> Result<Box<dyn WorkerSpawner>, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    super::windows::grant_built_worker()?;
    Ok(platform_spawner()?)
}

fn expected() -> Result<ExpectedWorker, Box<dyn std::error::Error>> {
    let (file_id, size, mtime) = file_identity(&worker_exe())?;
    Ok(ExpectedWorker {
        identity: SandboxBinaryIdentity {
            file_id,
            size,
            mtime,
            embedded_version: BUILD_ID.to_owned(),
        },
        accept_unconfined: false,
    })
}

/// No script here calls the host.
struct NoCalls;

#[async_trait]
impl HostCallSink for NoCalls {
    async fn call(&self, _run_id: &str, _c: HostCall) -> HostCallResult {
        HostCallResult::Ok(json!(null))
    }

    fn log(&self, _run_id: &str, _line: &str) {}
}

/// `start_run` of `source` under `limits`, with the spawn's process limit set from them (as the
/// glue does), and its end.
fn run_limited(
    source: &str,
    limits: ScriptLimits,
) -> Result<RunOutcome, Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let spawner = spawner()?;
    let spec = SpawnSpec {
        exe: worker_exe(),
        process_mb: limits.process_mb,
    };
    let init = WorkerInit {
        source: source.to_owned(),
        args: json!({}),
        limits,
        read_op_ids: Vec::new(),
        instances: vec![InstanceInfo {
            alias: "prod".to_owned(),
            product: "jira".to_owned(),
            is_default: true,
        }],
    };
    let handle = start_run(
        spawner.as_ref(),
        &spec,
        &expected()?,
        init,
        Arc::new(NoCalls),
        rt.handle().clone(),
    )?;
    Ok(rt.block_on(async { tokio::time::timeout(Duration::from_secs(150), handle.wait()).await })?)
}

/// The process cases' limits: the process limit is reached before the heap limit.
fn process_limits() -> ScriptLimits {
    ScriptLimits {
        heap_mb: HEAP_MB_OVER_PROCESS,
        process_mb: PROCESS_MB,
        ..ScriptLimits::default()
    }
}

#[test]
fn heap_limit_reported_as_heap_mb() -> TestResult {
    if !harness::opted_in("heap_limit_reported_as_heap_mb") {
        return Ok(());
    }
    let limits = ScriptLimits {
        heap_mb: 32,
        ..ScriptLimits::default()
    };
    let outcome = run_limited(GROW, limits)?;
    assert_eq!(outcome.host, HostVerdict::Limit("heap_mb"), "{outcome:?}");
    println!(
        "V10 heap_limit os={} verdict=heap_mb elapsed_ms={} diag={:?}",
        std::env::consts::OS,
        outcome.elapsed.as_millis(),
        outcome.diag
    );
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn v10_macos_watchdog_kills_footprint_over_process_mb() -> TestResult {
    use atlas_duck_sandbox_host::bridge::DIAG_WATCHDOG_KILL;

    if !harness::opted_in("v10_macos_watchdog_kills_footprint_over_process_mb") {
        return Ok(());
    }
    let outcome = run_limited(GROW, process_limits())?;
    assert_eq!(
        outcome.host,
        HostVerdict::Limit("process_mb"),
        "{outcome:?}"
    );
    assert!(
        outcome.diag.contains(&DIAG_WATCHDOG_KILL),
        "{:?}",
        outcome.diag
    );
    // Evidence only (L26): the time from the spawn to the reap of the killed worker.
    println!(
        "V10 watchdog_kill_ms={} arch={}",
        outcome.elapsed.as_millis(),
        std::env::consts::ARCH
    );
    // The macOS spawner sets no RLIMIT_AS (§9.4: Darwin does not enforce it); the watchdog is
    // the only process limit.
    println!("V10 rlimit_as_enforced=false");
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_job_memory_limit_reported_as_process_mb() -> TestResult {
    use atlas_duck_sandbox_host::bridge::DIAG_JOB_MEMORY_LIMIT;

    if !harness::opted_in("windows_job_memory_limit_reported_as_process_mb") {
        return Ok(());
    }
    let outcome = run_limited(GROW, process_limits())?;
    assert_eq!(
        outcome.host,
        HostVerdict::Limit("process_mb"),
        "{outcome:?}"
    );
    // The job's message is evidence, not asserted: Windows does not guarantee its delivery,
    // and the worker's exit code gives the same verdict without it.
    println!(
        "V10 windows_job_memory_limit verdict=process_mb job_message={} diag={:?}",
        outcome.diag.contains(&DIAG_JOB_MEMORY_LIMIT),
        outcome.diag
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn linux_rlimit_as_reported_as_process_mb() -> TestResult {
    if !harness::opted_in("linux_rlimit_as_reported_as_process_mb") {
        return Ok(());
    }
    let outcome = run_limited(GROW, process_limits())?;
    // `Limit("process_mb")` comes only from exit 103 on Linux (no OS report): a SIGSYS death
    // would be `Crashed(Some(Signal(31)))`.
    assert_eq!(
        outcome.host,
        HostVerdict::Limit("process_mb"),
        "{outcome:?}"
    );
    assert!(outcome.diag.is_empty(), "{:?}", outcome.diag);
    println!("V10 linux_rlimit_as verdict=process_mb via=exit_103 sigsys=false");
    Ok(())
}
