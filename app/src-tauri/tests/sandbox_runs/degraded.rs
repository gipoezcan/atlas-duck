//! The Windows degraded spawner (M8 Task 11, §9.4 degraded path, §8.9): the real worker started
//! with the lockdown token (restricting SID = NULL SID, untrusted integrity after startup) in the
//! floor's job object, below the floor.
//!
//! What is checked from outside, after `probe.ready`: the worker's process token is at untrusted
//! integrity with the NULL SID as its one restricting SID; its main thread no longer impersonates
//! (`OpenThreadToken` fails with `ERROR_NO_TOKEN`); its job has the floor job's limits; its
//! environment names (observed and printed, not R5's five: without an AppContainer process
//! creation adds no `TEMP`/`TMP`); and a script run through `degraded_spawner()` answers, with
//! the worker's report naming `lockdown_token`, `applied: false`.

use std::ptr::null_mut;
use std::sync::Arc;

use async_trait::async_trait;
use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::sandbox::frame::write_frame;
use atlas_duck_ipc::sandbox::probe::{
    LOOPBACK_PROBE_ADDR, M_PROBE_RESULT, M_PROBE_RUN, PUBLIC_PROBE_ADDR, ProbeId, ProbeOutcome,
    ProbeRequest, ProbeResultMsg, encode_notification,
};
use atlas_duck_ipc::sandbox::script::{InstanceInfo, WorkerInit};
use atlas_duck_ipc::sandbox::{HostCall, HostCallResult, ScriptLimits};
use atlas_duck_sandbox_host::bridge::{
    DIAG_MEMORY_WATCH_FAILED, ExpectedWorker, HostCallSink, HostVerdict, StartRunError, WorkerEnd,
    start_run,
};
use atlas_duck_sandbox_host::degraded_spawner;
use atlas_duck_sandbox_host::identity::{SandboxBinaryIdentity, file_identity};
use atlas_duck_sandbox_host::spawn::WorkerSpawner;
use atlas_duck_sandbox_host::windows::{
    DegradedSpawner, NULL_SID, ThreadToken, UNTRUSTED_INTEGRITY, WORKER_ENV_NAMES, WindowsSpawner,
    lockdown_state,
};
use serde_json::json;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_NO_TOKEN, GetLastError, HANDLE, TRUE};
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TokenIntegrityLevel,
};
use windows_sys::Win32::System::Threading::{OpenProcessToken, OpenThreadToken};

use super::*;

/// `SECURITY_MANDATORY_UNTRUSTED_RID`.
const UNTRUSTED_RID: u32 = 0;

/// The worker's own report on the degraded path (`sandbox-worker` `confine::LOCKDOWN_TOKEN`).
const MECHANISM: &str = "lockdown_token";

fn expected(accept_unconfined: bool) -> Result<ExpectedWorker, Box<dyn std::error::Error>> {
    let (file_id, size, mtime) = file_identity(&worker_exe())?;
    Ok(ExpectedWorker {
        identity: SandboxBinaryIdentity {
            file_id,
            size,
            mtime,
            embedded_version: BUILD_ID.to_owned(),
        },
        accept_unconfined,
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

/// The integrity RID of the process token of `process` (a handle this test owns), read with
/// `GetTokenInformation` from outside.
fn integrity_rid(
    process: std::os::windows::io::RawHandle,
) -> Result<u32, Box<dyn std::error::Error>> {
    let mut token: HANDLE = null_mut();
    // SAFETY: `process` is the worker's open process handle (the spawner's full access) and
    // `token` a valid out-pointer.
    if unsafe { OpenProcessToken(process.cast(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut buf = vec![0u64; 16];
    let mut needed = 0u32;
    // SAFETY: `token` is open; `buf` is writable for the byte size passed and 8-byte aligned.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut needed,
        )
    };
    let err = std::io::Error::last_os_error();
    // SAFETY: `token` was opened above and is closed once.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(err.into());
    }
    // SAFETY: on success the buffer starts with a TOKEN_MANDATORY_LABEL whose SID points into
    // the same buffer; the label SID has one sub-authority, the RID.
    let rid = unsafe {
        let sid = (*buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        let count = *GetSidSubAuthorityCount(sid);
        *GetSidSubAuthority(sid, u32::from(count) - 1)
    };
    Ok(rid)
}

/// `OpenThreadToken` on `thread` (a handle the spawner owns): `Ok(())` exactly when it fails
/// with `ERROR_NO_TOKEN`.
fn thread_has_no_token(thread: std::os::windows::io::RawHandle) -> Result<(), String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: `thread` is the worker's open main-thread handle (full access); `token` is a
    // valid out-pointer; `OpenAsSelf = TRUE` checks with this process's token.
    if unsafe { OpenThreadToken(thread.cast(), TOKEN_QUERY, TRUE, &mut token) } != 0 {
        // SAFETY: `token` was just opened and is closed once.
        unsafe { CloseHandle(token) };
        return Err("the main thread still has an impersonation token".to_owned());
    }
    // SAFETY: no preconditions.
    match unsafe { GetLastError() } {
        ERROR_NO_TOKEN => Ok(()),
        other => Err(format!(
            "OpenThreadToken failed with {other}, not ERROR_NO_TOKEN"
        )),
    }
}

/// Sends one `probe.run` for `probe`, closes stdin and returns the worker's answer.
fn ask(
    p: &mut dyn WorkerProcess,
    probe: ProbeId,
) -> Result<ProbeResultMsg, Box<dyn std::error::Error>> {
    let request = ProbeRequest {
        probe,
        app_pid: std::process::id(),
        profile_path: std::env::temp_dir().to_string_lossy().into_owned(),
        public_addr: PUBLIC_PROBE_ADDR.to_string(),
        loopback_addr: LOOPBACK_PROBE_ADDR.to_string(),
        handle_value: None,
    };
    {
        let mut stdin = p.stdin();
        write_frame(&mut stdin, &encode_notification(M_PROBE_RUN, &request))?;
        std::io::Write::flush(&mut stdin)?;
    }
    p.close_stdin();
    let frame = p
        .read_frame_timeout(WORKER_FRAME_MAX_BYTES, WAIT)?
        .ok_or("the degraded worker ended without a probe.result")?;
    let (method, params) = decode_notification(&frame)?;
    if method != M_PROBE_RESULT {
        return Err(format!("{method} instead of {M_PROBE_RESULT}").into());
    }
    Ok(serde_json::from_value(params)?)
}

#[test]
fn windows_degraded_spawner_runs_with_lockdown_token() -> TestResult {
    if !harness::opted_in("windows_degraded_spawner_runs_with_lockdown_token") {
        return Ok(());
    }
    // The floor job, for comparison: the AppContainer worker the platform spawner starts.
    super::windows::grant_built_worker()?;
    let floor_job = {
        let mut floor = WindowsSpawner::new()?.spawn_process(&spec())?;
        read_ready(&mut floor)?;
        floor.job_snapshot()?
    };

    // 1. The concrete worker, from outside, after `probe.ready`.
    let mut p = DegradedSpawner::new().spawn_process(&spec())?;
    let ready = read_ready(&mut p)?;
    assert!(!ready.confinement.applied, "{:?}", ready.confinement);
    assert_eq!(ready.confinement.mechanism, MECHANISM);
    // `None`: the worker found its startup token on the main thread and dropped it.
    assert_eq!(ready.confinement.os_error, None, "{:?}", ready.confinement);

    let rid = integrity_rid(p.process_handle())?;
    assert_eq!(rid, UNTRUSTED_RID, "integrity RID {rid:#x}");
    let thread = p
        .main_thread_handle()
        .ok_or("a degraded worker keeps its main thread handle")?;
    thread_has_no_token(thread)?;
    let state = lockdown_state(p.process_handle(), thread)?;
    assert_eq!(state.integrity, UNTRUSTED_INTEGRITY, "{state:?}");
    assert_eq!(state.restricting, vec![NULL_SID.to_owned()], "{state:?}");
    assert_eq!(state.thread_token, ThreadToken::None, "{state:?}");

    let job = p.job_snapshot()?;
    assert_eq!(
        job.limit_flags, floor_job.limit_flags,
        "{job:?} vs {floor_job:?}"
    );
    assert_eq!(job.active_process_limit, floor_job.active_process_limit);
    assert_eq!(job.process_memory_limit, floor_job.process_memory_limit);
    assert_eq!(job.ui_restrictions, floor_job.ui_restrictions);
    assert_eq!(job.pids, vec![p.pid()], "{job:?}");

    // The environment, as the worker itself lists it (names only).
    let answer = ask(&mut p, ProbeId::EnvNames)?;
    assert_eq!(answer.outcome, ProbeOutcome::Allowed, "{answer:?}");
    let mut names = answer.env_names.ok_or("EnvNames returned no names")?;
    names.sort();
    println!("M8 windows_degraded env_names={names:?}");
    let mut expected_names: Vec<String> =
        WORKER_ENV_NAMES.iter().map(|n| (*n).to_owned()).collect();
    expected_names.sort();
    assert_eq!(names, expected_names);
    assert!(
        p.wait_timeout(WAIT)?.is_some(),
        "the worker ends after its probe"
    );

    // 2. A script run through the degraded spawner object, as the glue will start it under the
    // degraded policy (PD-141: the host accepts `applied: false`). The script touches the clock,
    // the time zone and the random source, which the worker loaded before it dropped its startup
    // token.
    let spawner = degraded_spawner().ok_or("degraded_spawner() is Some on Windows")?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let source = "const t = new Date(0);\n\
                  return [40 + 2, typeof Math.random(), t.toISOString(), \
                  new Date().getTimezoneOffset(), JSON.stringify({ a: [1] })];";
    let init = WorkerInit {
        source: source.to_owned(),
        args: json!({}),
        limits: ScriptLimits::default(),
        read_op_ids: Vec::new(),
        instances: vec![InstanceInfo {
            alias: "prod".to_owned(),
            product: "jira".to_owned(),
            is_default: true,
        }],
    };
    let handle = start_run(
        spawner.as_ref(),
        &spec(),
        &expected(true)?,
        init,
        Arc::new(NoCalls),
        rt.handle().clone(),
    )?;
    let outcome =
        rt.block_on(async { tokio::time::timeout(Duration::from_secs(90), handle.wait()).await })?;
    assert_eq!(outcome.host, HostVerdict::None, "{outcome:?}");
    let WorkerEnd::Result { value_json } = &outcome.end else {
        return Err(format!("no result: {outcome:?}").into());
    };
    let value: serde_json::Value = serde_json::from_str(value_json.get())?;
    assert_eq!(
        value,
        json!([42, "number", "1970-01-01T00:00:00.000Z", 0, "{\"a\":[1]}"]),
        "{outcome:?}"
    );
    assert!(!outcome.confinement.applied, "{:?}", outcome.confinement);
    assert_eq!(outcome.confinement.mechanism, MECHANISM);
    // The degraded worker has the floor's job, and so its memory watch.
    assert!(
        !outcome.diag.contains(&DIAG_MEMORY_WATCH_FAILED),
        "{:?}",
        outcome.diag
    );
    println!(
        "M8 windows_degraded_spawner mechanism={MECHANISM} applied=false integrity_rid={rid:#x} \
         restricting={:?} thread_token=none job_same_as_floor=true result=42 diag={:?}",
        state.restricting, outcome.diag
    );
    Ok(())
}

/// PD-141: a degraded worker reports `applied: false`, so a run that does not accept unconfined
/// workers is refused before any frame is sent.
#[test]
fn windows_degraded_worker_is_refused_without_accept_unconfined() -> TestResult {
    if !harness::opted_in("windows_degraded_worker_is_refused_without_accept_unconfined") {
        return Ok(());
    }
    let spawner: Box<dyn WorkerSpawner> = Box::new(DegradedSpawner::new());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let init = WorkerInit {
        source: "return 1;".to_owned(),
        args: json!({}),
        limits: ScriptLimits::default(),
        read_op_ids: Vec::new(),
        instances: Vec::new(),
    };
    match start_run(
        spawner.as_ref(),
        &spec(),
        &expected(false)?,
        init,
        Arc::new(NoCalls),
        rt.handle().clone(),
    ) {
        Err(StartRunError::FloorNotMet) => {}
        Err(other) => return Err(format!("{other:?} instead of FloorNotMet").into()),
        Ok(_) => return Err("a degraded worker was accepted without accept_unconfined".into()),
    }
    println!("M8 windows_degraded_refused_without_accept_unconfined=true");
    Ok(())
}
