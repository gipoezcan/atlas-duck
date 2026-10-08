//! T19: the section 9.4 Windows confinement, observed through the real
//! `atlas-duck-sandbox.exe` in an AppContainer (LPAC when every file has the
//! `S-1-15-2-2` ACE) inside its job object. These tests, plus the T21 install
//! runs, are the section 15 V03 / V09 / V12 verification.
//!
//! The worker is `CARGO_BIN_EXE_atlas-duck-sandbox`, or the file named by
//! `ATLAS_DUCK_SANDBOX_BIN` (an installed copy: its ACEs come from the
//! installer, so this file then grants nothing).
//!
//! CI: the `rust` job leg `windows-2022` runs this file with the rest of
//! `cargo test --workspace --locked`. The step "Windows probes (T19)" runs it
//! alone with `--nocapture` so that the `T19 ...` lines (error codes, DLL
//! set) land in the log for the go/no-go record.

#![cfg(windows)]

use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::Once;
use std::time::{Duration, Instant};

use atlas_duck_ipc::sandbox::WORKER_FRAME_MAX_BYTES;
use atlas_duck_ipc::sandbox::frame::write_frame;
use atlas_duck_ipc::sandbox::probe::{
    LOOPBACK_PROBE_ADDR, M_PROBE_READY, M_PROBE_RESULT, M_PROBE_RUN, PUBLIC_PROBE_ADDR, ProbeId,
    ProbeOutcome, ProbeReady, ProbeRequest, ProbeResultMsg, decode_notification,
    encode_notification,
};
use atlas_duck_sandbox_host::probe::{
    Evidence, FloorVerdict, ProbeConfig, ProbeReport, run_probes, run_probes_with_fallback,
};
use atlas_duck_sandbox_host::spawn::{
    DEFAULT_PROCESS_MB, ExitKind, SpawnSpec, WorkerProcess, WorkerSpawner,
};
use atlas_duck_sandbox_host::windows::{
    APPCONTAINER_NAME, AceStatus, JobSnapshot, WORKER_ENV_OBSERVED, WindowsProcess, WindowsSpawner,
    check_aces, grant_aces, pe_import_names, worker_ace_files_for_exe,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GetHandleInformation, GetLastError,
    HANDLE, HANDLE_FLAG_INHERIT, TRUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::DataExchange::{CloseClipboard, OpenClipboard};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
};
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSGetActiveConsoleSessionId,
};
use windows_sys::Win32::System::StationsAndDesktops::{
    GetProcessWindowStation, GetUserObjectInformationW, UOI_NAME,
};
use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess, WaitForSingleObject};

const WAIT: Duration = Duration::from_secs(20);

const WINDOWS_FLOOR: [ProbeId; 7] = [
    ProbeId::FileInProfile,
    ProbeId::ConnectLoopback,
    ProbeId::ConnectPublic,
    ProbeId::SpawnProcess,
    ProbeId::OpenProcessVmRead,
    ProbeId::CredRead,
    ProbeId::OpenClipboard,
];

/// `STATUS_INVALID_HANDLE` as the worker's exit code.
const STATUS_INVALID_HANDLE: i32 = 0xC000_0008_u32 as i32;
const ERROR_ACCESS_DENIED: i64 = 5;
const WSAEACCES: i64 = 10013;
const WSASYSCALLFAILURE: i64 = 10107;
const ERROR_NOT_ENOUGH_QUOTA: i64 = 1816;
const RPC_S_INVALID_BINDING: i64 = 1702;

// --------------------------------------------------------------- helpers

fn worker_override() -> Option<PathBuf> {
    std::env::var_os("ATLAS_DUCK_SANDBOX_BIN").map(PathBuf::from)
}

fn worker_exe() -> PathBuf {
    worker_override().unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_atlas-duck-sandbox")))
}

/// The built worker has no (L)PAC ACEs (a new file only inherits its parent's
/// ACL), so grant them once, as the installer does. An installed worker
/// (`ATLAS_DUCK_SANDBOX_BIN`) is left alone.
fn grant_built_worker() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if worker_override().is_some() {
            return;
        }
        let files = worker_ace_files_for_exe(&worker_exe()).expect("worker ACE file set");
        grant_aces(&files).expect("grant the (L)PAC ACEs on the built worker");
    });
}

fn spec_for(exe: &Path) -> SpawnSpec {
    SpawnSpec {
        exe: exe.to_path_buf(),
        process_mb: DEFAULT_PROCESS_MB,
    }
}

fn spawner() -> WindowsSpawner {
    grant_built_worker();
    WindowsSpawner::new().expect("create the AppContainer profile")
}

fn profile_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("USERPROFILE").expect("USERPROFILE"))
}

fn config_for(exe: &Path) -> ProbeConfig {
    ProbeConfig::new(exe.to_path_buf(), std::process::id(), profile_dir())
}

fn read_ready(p: &mut WindowsProcess) -> ProbeReady {
    let frame = match p.read_frame_timeout(WORKER_FRAME_MAX_BYTES, WAIT) {
        Ok(Some(frame)) => frame,
        other => panic!(
            "no probe.ready: {other:?}; worker stderr: {}",
            String::from_utf8_lossy(&p.stderr_head())
        ),
    };
    let (method, params) = decode_notification(&frame).expect("a JSON-RPC notification");
    assert_eq!(method, M_PROBE_READY);
    serde_json::from_value(params).expect("ProbeReady params")
}

/// Sends one `probe.run`, closes stdin and returns the worker's answer.
fn send_run(p: &mut WindowsProcess, probe: ProbeId, handle_value: Option<u64>) -> ProbeResultMsg {
    let request = ProbeRequest {
        probe,
        app_pid: std::process::id(),
        profile_path: profile_dir().to_string_lossy().into_owned(),
        public_addr: PUBLIC_PROBE_ADDR.to_string(),
        loopback_addr: LOOPBACK_PROBE_ADDR.to_string(),
        handle_value,
    };
    write_frame(&mut p.stdin(), &encode_notification(M_PROBE_RUN, &request))
        .expect("write probe.run");
    p.close_stdin();
    let frame = p
        .read_frame_timeout(WORKER_FRAME_MAX_BYTES, WAIT)
        .expect("read probe.result")
        .expect("worker closed stdout before probe.result");
    let (method, params) = decode_notification(&frame).expect("a JSON-RPC notification");
    assert_eq!(method, M_PROBE_RESULT);
    serde_json::from_value(params).expect("ProbeResultMsg params")
}

struct Driven {
    ready: ProbeReady,
    result: ProbeResultMsg,
    exit: Option<ExitKind>,
}

/// One whole probe by hand (what `run_probes` does, but keeping the frames:
/// `ProbeRecord` carries neither `env_names` nor a `handle_value`).
fn drive(spawner: &WindowsSpawner, probe: ProbeId, handle_value: Option<u64>) -> Driven {
    let mut p = spawner
        .spawn_process(&spec_for(&worker_exe()))
        .expect("spawn the worker");
    let ready = read_ready(&mut p);
    let result = send_run(&mut p, probe, handle_value);
    let exit = p.wait_timeout(WAIT).expect("wait for the worker");
    Driven {
        ready,
        result,
        exit,
    }
}

fn print_report(label: &str, report: &ProbeReport) {
    println!("T19 {label}: floor = {:?}", report.floor);
    println!("T19 {label}: confinement = {:?}", report.confinement);
    for r in &report.records {
        println!(
            "T19 {label}: {:?} -> {:?} ({:?})",
            r.probe, r.outcome, r.evidence
        );
    }
}

fn record(report: &ProbeReport, probe: ProbeId) -> (ProbeOutcome, Evidence) {
    let r = report
        .records
        .iter()
        .find(|r| r.probe == probe)
        .unwrap_or_else(|| panic!("no record for {probe:?}"));
    (r.outcome, r.evidence)
}

/// A fresh directory with a copy of the worker (no ACEs on it). It lives under
/// `target/tmp` (`CARGO_TARGET_TMPDIR`), not under `%TEMP%`: security software
/// has blocked executables there. The name is unique per test and process, and
/// the directory is removed on drop, retrying because the image of the killed
/// worker or a scanner may still hold the file for a moment.
struct WorkerCopy {
    dir: PathBuf,
    exe: PathBuf,
}

impl WorkerCopy {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("t19-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the copy dir under target/tmp");
        let exe = dir.join("atlas-duck-sandbox.exe");
        std::fs::copy(worker_exe(), &exe).expect("copy the worker");
        Self { dir, exe }
    }
}

impl Drop for WorkerCopy {
    fn drop(&mut self) {
        for _ in 0..20 {
            if std::fs::remove_dir_all(&self.dir).is_ok() || !self.dir.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// A copy of the worker that has only the `S-1-15-2-1` ACE, so it runs as a
/// plain AppContainer (granted with `icacls`, an independent writer).
fn plain_appcontainer_copy(tag: &str) -> WorkerCopy {
    let copy = WorkerCopy::new(tag);
    let out = std::process::Command::new("icacls")
        .arg(&copy.exe)
        .arg("/grant")
        .arg("*S-1-15-2-1:(RX)")
        .output()
        .expect("run icacls");
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        check_aces(std::slice::from_ref(&copy.exe)).expect("check"),
        AceStatus::AllPresent { lpac_ready: false }
    );
    copy
}

/// `process`'s modules as full paths.
fn loaded_modules(process: HANDLE) -> Vec<PathBuf> {
    let mut modules = vec![null_mut(); 1024];
    let mut needed = 0u32;
    // SAFETY: `modules` is writable for the byte size passed; `process` is a
    // handle with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ (the one
    // CreateProcess returned).
    let ok = unsafe {
        EnumProcessModulesEx(
            process,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<*mut core::ffi::c_void>()) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
    };
    assert_ne!(
        ok,
        0,
        "EnumProcessModulesEx: {}",
        std::io::Error::last_os_error()
    );
    let count = needed as usize / std::mem::size_of::<*mut core::ffi::c_void>();
    modules[..count.min(1024)]
        .iter()
        .map(|&m| {
            let mut buf = vec![0u16; 1024];
            // SAFETY: `buf` is writable for `buf.len()` UTF-16 units.
            let n = unsafe { GetModuleFileNameExW(process, m, buf.as_mut_ptr(), buf.len() as u32) };
            PathBuf::from(String::from_utf16_lossy(&buf[..n as usize]))
        })
        .collect()
}

/// Where this test runs, for the `OpenClipboard` evidence: that probe returns
/// `ERROR_ACCESS_DENIED` in an AppContainer, but also when there is no window
/// station (a non-interactive session), and then a `Blocked` would prove
/// nothing. The line makes a false `Blocked` diagnosable.
fn session_line() -> String {
    let mut session = 0u32;
    // SAFETY: valid out-pointer.
    let ok = unsafe { ProcessIdToSessionId(std::process::id(), &mut session) };
    // SAFETY: no arguments.
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    // SAFETY: no arguments; the pseudo window station handle needs no closing.
    let station = unsafe { GetProcessWindowStation() };
    let mut name = [0u16; 128];
    let mut needed = 0u32;
    // SAFETY: `name` is writable for the byte size passed.
    let got = unsafe {
        GetUserObjectInformationW(
            station,
            UOI_NAME,
            name.as_mut_ptr().cast(),
            std::mem::size_of_val(&name) as u32,
            &mut needed,
        )
    };
    let station_name = if got == 0 {
        format!("unknown ({})", std::io::Error::last_os_error())
    } else {
        let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        String::from_utf16_lossy(&name[..end])
    };
    format!(
        "session id {} ({}), active console session {console}, window station {station_name:?},          interactive window station: {}",
        if ok == 0 { u32::MAX } else { session },
        if ok == 0 { "unknown" } else { "queried" },
        station_name == "WinSta0"
    )
}

/// `OpenClipboard` from this (unconfined) process: the control for the
/// worker's `OpenClipboard` probe. `Ok` means the clipboard is usable in this
/// session, so the worker's `ERROR_ACCESS_DENIED` comes from the AppContainer;
/// `Err(code)` means the probe is not diagnostic here.
fn unconfined_clipboard_control() -> Result<(), u32> {
    for _ in 0..5 {
        // SAFETY: a null owner window is allowed.
        if unsafe { OpenClipboard(null_mut()) } != 0 {
            // SAFETY: this thread opened the clipboard just above.
            unsafe { CloseClipboard() };
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // SAFETY: no arguments.
    Err(unsafe { GetLastError() })
}

// ----------------------------------------------------------------- tests

/// The control for the loopback probe: a connect to `LOOPBACK_PROBE_ADDR` (a
/// closed port) from this unconfined process. A plain stack refuses it at once
/// (WSAECONNREFUSED); on this machine it hangs until the deadline, like the
/// confined worker's, so the worker's timeout on that address proves nothing
/// (security software filters it). The listening-socket test below is the real
/// loopback evidence.
fn unconfined_loopback_control() -> String {
    let addr: std::net::SocketAddr = LOOPBACK_PROBE_ADDR.parse().expect("loopback addr");
    let start = Instant::now();
    let r = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2));
    format!(
        "unconfined connect to {addr}: {:?} after {:?}",
        r.map(|_| ()),
        start.elapsed()
    )
}

fn print_controls() {
    println!("T19 session: {}", session_line());
    match unconfined_clipboard_control() {
        Ok(()) => println!(
            "T19 clipboard control: OpenClipboard works unconfined in this session,              so the worker's denial is the AppContainer's"
        ),
        Err(code) => println!(
            "T19 clipboard control: INCONCLUSIVE, OpenClipboard fails unconfined too              (error {code}); the OpenClipboard Blocked is not independent evidence"
        ),
    }
    println!("T19 loopback control: {}", unconfined_loopback_control());
}

fn assert_reported(report: &ProbeReport, probe: ProbeId, outcome: ProbeOutcome, code: i64) {
    assert_eq!(
        record(report, probe),
        (
            outcome,
            Evidence::Reported {
                os_error: Some(code)
            }
        ),
        "{probe:?}"
    );
}

/// Set locally (`ATLAS_DUCK_EXPECT_WINDOWS_FLOOR_DEVBOX=1`) to also pin the
/// exact verdicts measured on the development machine (Windows 11 build 26200
/// with WithSecure). CI leaves it unset: another Windows image may differ in
/// the exact Winsock / CredRead failure codes under LPAC.
fn expect_devbox() -> bool {
    std::env::var_os("ATLAS_DUCK_EXPECT_WINDOWS_FLOOR_DEVBOX").is_some_and(|v| v == "1")
}

/// `ATLAS_DUCK_EXPECT_WINDOWS_FLOOR_MET=1` (CI's windows-2022 jobs, and the dev
/// box): the floor must be `Met`, in LPAC and in plain AppContainer mode. Unset,
/// only the machine-independent invariants hold and the verdict is printed.
fn expect_floor_met() -> bool {
    std::env::var_os("ATLAS_DUCK_EXPECT_WINDOWS_FLOOR_MET").is_some_and(|v| v == "1")
}

/// Why a `Blocked` record is legitimate: an explicit denial the worker saw, or
/// a host-scored absence that carries its control (`control_ok`).
fn blocked_for_a_real_reason(evidence: Evidence) -> bool {
    match evidence {
        Evidence::Reported { os_error: Some(c) } => {
            [ERROR_ACCESS_DENIED, ERROR_NOT_ENOUGH_QUOTA, WSAEACCES].contains(&c)
        }
        // no connection reached the host's listener, and the listener was
        // proven reachable (host self-check + unconfined worker)
        Evidence::ListenerArrival {
            arrived: false,
            control_ok: true,
            ..
        } => true,
        // the stack / credential service does not exist for the worker, and an
        // unconfined worker proved that it exists outside the sandbox
        Evidence::StackUnavailable {
            os_error,
            control_ok: true,
        } => [WSASYSCALLFAILURE, 10106, RPC_S_INVALID_BINDING, 1722].contains(&os_error),
        _ => false,
    }
}

/// What must hold on every Windows machine, whatever the floor verdict is: the
/// worker started confined, every floor probe has a record, and a probe scores
/// `Blocked` only for a real denial reported by the worker (ERROR_ACCESS_DENIED,
/// the job's ERROR_NOT_ENOUGH_QUOTA or WSAEACCES), never for a crash, a timeout
/// or an unexpected code. Prints the measured verdict as evidence.
fn assert_floor_invariants(label: &str, report: &ProbeReport, lpac: bool) {
    print_report(label, report);
    print_controls();
    println!(
        "T19 {label}: verdict = {}",
        match &report.floor {
            FloorVerdict::Met => "Met".to_string(),
            FloorVerdict::NotMet { failed } => format!("NotMet {failed:?}"),
        }
    );
    assert_eq!(ProbeId::floor_probes_for_current_os(), WINDOWS_FLOOR);
    let confinement = report.confinement.clone().expect("a probe.ready arrived");
    assert!(confinement.applied, "{confinement:?}");
    assert_eq!(confinement.mechanism, "appcontainer");
    assert_eq!(confinement.lpac, Some(lpac), "{confinement:?}");
    let control = report.control.expect("the Windows controls ran");
    println!(
        "T19 {label}: control_ok={} (listener={} winsock={} cred={})",
        control.ok(),
        control.listener,
        control.winsock,
        control.cred
    );
    for probe in WINDOWS_FLOOR {
        let (outcome, evidence) = record(report, probe);
        if outcome == ProbeOutcome::Blocked {
            assert!(
                blocked_for_a_real_reason(evidence),
                "{probe:?} is Blocked for the wrong reason: {evidence:?}"
            );
        }
        if let Evidence::ListenerArrival { arrived, .. } = evidence {
            println!("T19 {label}: loopback_listener_saw_connect={arrived}");
        }
    }
    if report.floor == FloorVerdict::Met {
        for probe in WINDOWS_FLOOR {
            assert_eq!(record(report, probe).0, ProbeOutcome::Blocked, "{probe:?}");
        }
    }
    if expect_floor_met() {
        assert_eq!(report.floor, FloorVerdict::Met, "{label}: {report:#?}");
    }
}

#[test]
fn the_lpac_floor_scores_only_real_denials_as_blocked() {
    // Measured on the dev box (see `expect_devbox`), every file with both
    // (L)PAC ACEs, the worker running as LPAC: FileInProfile, OpenProcessVmRead
    // and OpenClipboard 5; SpawnProcess 1816; ConnectLoopback and ConnectPublic
    // report 10107 (WSAStartup fails, no connect attempted); CredRead reports
    // 1702 (RPC_S_INVALID_BINDING). The host scores the last three Blocked only
    // because an unconfined worker initialises Winsock and reads the credential
    // store normally (`control_ok`).
    let spawner = spawner();
    let report = run_probes(&spawner, None, &config_for(&worker_exe()));
    assert_floor_invariants("floor (LPAC)", &report, true);
    if expect_devbox() {
        assert_reported(
            &report,
            ProbeId::FileInProfile,
            ProbeOutcome::Blocked,
            ERROR_ACCESS_DENIED,
        );
        assert_reported(
            &report,
            ProbeId::OpenProcessVmRead,
            ProbeOutcome::Blocked,
            ERROR_ACCESS_DENIED,
        );
        assert_reported(
            &report,
            ProbeId::OpenClipboard,
            ProbeOutcome::Blocked,
            ERROR_ACCESS_DENIED,
        );
        assert_reported(
            &report,
            ProbeId::SpawnProcess,
            ProbeOutcome::Blocked,
            ERROR_NOT_ENOUGH_QUOTA,
        );
        for (probe, code) in [
            (ProbeId::ConnectLoopback, WSASYSCALLFAILURE),
            (ProbeId::ConnectPublic, WSASYSCALLFAILURE),
            (ProbeId::CredRead, RPC_S_INVALID_BINDING),
        ] {
            assert_eq!(
                record(&report, probe),
                (
                    ProbeOutcome::Blocked,
                    Evidence::StackUnavailable {
                        os_error: code,
                        control_ok: true
                    }
                ),
                "{probe:?}"
            );
        }
        assert_eq!(report.floor, FloorVerdict::Met);
    }
}

#[test]
fn the_report_says_appcontainer_lpac_and_records_the_binary_identity() {
    let spawner = spawner();
    let report = run_probes(&spawner, None, &config_for(&worker_exe()));
    let confinement = report.confinement.clone().expect("a probe.ready arrived");
    assert!(confinement.applied, "{confinement:?}");
    assert_eq!(confinement.mechanism, "appcontainer");
    assert_eq!(
        confinement.lpac,
        Some(true),
        "all ACEs exist, so LPAC: {confinement:?}"
    );
    assert!(report.extra_layers.is_empty(), "{:?}", report.extra_layers);
    let identity = report.identity.expect("identity recorded");
    assert!(matches!(
        identity.file_id,
        atlas_duck_sandbox_host::identity::FileId::FileIndex { .. }
    ));
    assert!(!identity.embedded_version.is_empty());
    println!("T19 identity: {identity:?}");
    println!(
        "T19 versions: worker {:?}, engine {:?}",
        report.worker_version, report.engine_version
    );
}

#[test]
fn the_engine_self_test_passes_inside_the_appcontainer() {
    // V03: rquickjs built for x86_64-pc-windows-msvc runs under the AppContainer
    // (and LPAC), including its allocator and stack use.
    let d = drive(&spawner(), ProbeId::EngineSelfTest, None);
    assert_eq!(
        d.result.outcome,
        ProbeOutcome::Allowed,
        "self-test failed: {:?}",
        d.result
    );
    assert!(d.ready.confinement.applied, "{:?}", d.ready.confinement);
    assert_eq!(
        d.exit,
        Some(ExitKind::Code(0)),
        "the worker exits on stdin EOF"
    );
    println!("T19 engine: {}", d.ready.engine_version);
}

#[test]
fn the_worker_environment_holds_no_host_variables() {
    // Section 3.4 wants `SystemRoot` and `TZ` only. Measured on Windows 11:
    // process creation in an AppContainer needs `LOCALAPPDATA` in the block and
    // adds `TEMP` and `TMP`; all three point into the container's own folder.
    // Nothing else (no PATH, USERPROFILE, ...) may reach the worker.
    let d = drive(&spawner(), ProbeId::EnvNames, None);
    let mut names = d.result.env_names.clone().expect("env_names");
    names.sort();
    assert_eq!(names, WORKER_ENV_OBSERVED.to_vec(), "{:?}", d.result);
    println!("T19 worker env names: {names:?}");
}

/// An inheritable event with a handle value too high to coincide with any
/// handle of a small worker (its table holds the three pipes and a few
/// loader handles). Every event created on the way is inheritable too, and
/// kept open until the test ends.
fn high_inheritable_event() -> (u64, Vec<OwnedHandle>) {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: TRUE,
    };
    let mut kept = Vec::new();
    for _ in 0..4096 {
        // SAFETY: valid attributes, manual-reset, initially unsignalled, unnamed.
        let h = unsafe { CreateEventW(&sa, TRUE, 0, null()) };
        assert!(
            !h.is_null(),
            "CreateEventW: {}",
            std::io::Error::last_os_error()
        );
        let value = h as usize as u64;
        // SAFETY: `h` is a fresh handle owned by us.
        kept.push(unsafe { OwnedHandle::from_raw_handle(h as RawHandle) });
        if value >= 0x800 {
            return (value, kept);
        }
    }
    panic!("could not create an event with a handle value >= 0x800");
}

#[test]
fn handle_list_keeps_an_extra_inheritable_handle_out_of_the_worker() {
    // V12: PROC_THREAD_ATTRIBUTE_HANDLE_LIST with bInheritHandles = TRUE hands
    // the worker its three pipe ends and nothing else.
    let (value, _kept) = high_inheritable_event();
    let mut flags = 0u32;
    // SAFETY: `value` is the value of an open handle in this process.
    let ok = unsafe { GetHandleInformation(value as usize as HANDLE, &mut flags) };
    assert_ne!(ok, 0, "precondition: the event is valid in the host");
    assert_ne!(
        flags & HANDLE_FLAG_INHERIT,
        0,
        "precondition: it is inheritable"
    );

    // An AppContainer process has strict handle checks: touching a handle
    // value that is not in its table raises STATUS_INVALID_HANDLE instead of
    // failing with ERROR_INVALID_HANDLE (measured on Windows 11), so the worker
    // dies while the probe runs and no result frame arrives. That exit, on
    // exactly this value, is the evidence that the value is not in the worker's
    // table; a worker that held the handle would answer `Allowed`.
    let spawner = spawner();
    let mut p = spawner
        .spawn_process(&spec_for(&worker_exe()))
        .expect("spawn the worker");
    let _ = read_ready(&mut p);
    let request = ProbeRequest {
        probe: ProbeId::HandleSentinel,
        app_pid: std::process::id(),
        profile_path: profile_dir().to_string_lossy().into_owned(),
        public_addr: PUBLIC_PROBE_ADDR.to_string(),
        loopback_addr: LOOPBACK_PROBE_ADDR.to_string(),
        handle_value: Some(value),
    };
    write_frame(&mut p.stdin(), &encode_notification(M_PROBE_RUN, &request))
        .expect("write probe.run");
    p.close_stdin();
    let frame = p
        .read_frame_timeout(WORKER_FRAME_MAX_BYTES, WAIT)
        .expect("read after probe.run");
    let exit = p.wait_timeout(WAIT).expect("wait for the worker");
    match frame {
        None => {
            assert_eq!(
                exit,
                Some(ExitKind::Code(STATUS_INVALID_HANDLE)),
                "the worker died for another reason than STATUS_INVALID_HANDLE"
            );
            println!("T19 handle sentinel {value:#x}: worker raised STATUS_INVALID_HANDLE");
        }
        Some(frame) => {
            let (method, params) = decode_notification(&frame).expect("notification");
            assert_eq!(method, M_PROBE_RESULT);
            let msg: ProbeResultMsg = serde_json::from_value(params).expect("params");
            assert_eq!(
                msg.outcome,
                ProbeOutcome::Blocked,
                "the worker holds handle {value:#x}: {msg:?}"
            );
            println!("T19 handle sentinel {value:#x}: {msg:?}");
        }
    }
}

#[test]
fn a_worker_without_aces_cannot_start_and_the_floor_is_never_met() {
    let copy = WorkerCopy::new("noaces");
    let spawner = WindowsSpawner::new().expect("AppContainer profile");
    assert!(matches!(
        check_aces(std::slice::from_ref(&copy.exe)).expect("check"),
        AceStatus::Missing(_)
    ));
    let report = run_probes(&spawner, None, &config_for(&copy.exe));
    print_report("no ACEs", &report);
    for probe in WINDOWS_FLOOR {
        let (outcome, evidence) = record(&report, probe);
        assert_ne!(outcome, ProbeOutcome::Blocked, "{probe:?}");
        assert_eq!(
            evidence,
            Evidence::SpawnFailed(ERROR_ACCESS_DENIED),
            "{probe:?}"
        );
    }
    assert_eq!(
        report.floor,
        FloorVerdict::NotMet {
            failed: WINDOWS_FLOOR.to_vec()
        }
    );
}

#[test]
fn without_the_restricted_ace_the_worker_is_a_plain_appcontainer() {
    // Section 9.4: LPAC "where all needed ACEs exist". With S-1-15-2-1 alone the
    // worker is a plain AppContainer and reports lpac = false. Measured on
    // Windows 11 (build 26200): every floor probe is Blocked with the expected
    // denial (5, 1816, 10013) except ConnectLoopback, whose connect to the
    // host's listener hangs until the worker's 2 s deadline (no WSAEACCES). The
    // worker scores that timeout Allowed (the platform-neutral rule), which says
    // nothing by itself: an unconfined connect to a closed port hangs on this
    // machine too. The host therefore scores it from its own listener: no
    // connection arrived, and the controls proved the listener reachable
    // (the host's own connect, and an unconfined worker's connect).
    let copy = plain_appcontainer_copy("plainac");

    let spawner = WindowsSpawner::new().expect("AppContainer profile");
    let report = run_probes(&spawner, None, &config_for(&copy.exe));
    assert_floor_invariants("floor (plain AppContainer)", &report, false);
    if expect_devbox() {
        assert_reported(
            &report,
            ProbeId::FileInProfile,
            ProbeOutcome::Blocked,
            ERROR_ACCESS_DENIED,
        );
        assert_reported(
            &report,
            ProbeId::OpenProcessVmRead,
            ProbeOutcome::Blocked,
            ERROR_ACCESS_DENIED,
        );
        assert_reported(
            &report,
            ProbeId::CredRead,
            ProbeOutcome::Blocked,
            ERROR_ACCESS_DENIED,
        );
        assert_reported(
            &report,
            ProbeId::OpenClipboard,
            ProbeOutcome::Blocked,
            ERROR_ACCESS_DENIED,
        );
        assert_reported(
            &report,
            ProbeId::SpawnProcess,
            ProbeOutcome::Blocked,
            ERROR_NOT_ENOUGH_QUOTA,
        );
        assert_reported(
            &report,
            ProbeId::ConnectPublic,
            ProbeOutcome::Blocked,
            WSAEACCES,
        );
        assert_eq!(
            record(&report, ProbeId::ConnectLoopback),
            (
                ProbeOutcome::Blocked,
                Evidence::ListenerArrival {
                    os_error: None,
                    arrived: false,
                    control_ok: true
                }
            )
        );
        assert_eq!(report.floor, FloorVerdict::Met);
    }
}

/// A spawner whose unconfined control cannot start: every confined probe still
/// runs, but nothing proves that the listener, Winsock or the credential store
/// work outside the sandbox.
struct NoControl(WindowsSpawner);

impl WorkerSpawner for NoControl {
    fn spawn(&self, spec: &SpawnSpec) -> std::io::Result<Box<dyn WorkerProcess>> {
        self.0.spawn(spec)
    }
}

#[test]
fn without_the_unconfined_control_the_lpac_floor_fails_closed() {
    // The rules of B and A need a control. If it cannot run, the worker's
    // 10107 / 1702 stay Error (never Blocked) and the floor is not met.
    grant_built_worker();
    let spawner = NoControl(WindowsSpawner::new().expect("AppContainer profile"));
    let report = run_probes(&spawner, None, &config_for(&worker_exe()));
    print_report("no control (LPAC)", &report);
    let control = report.control.expect("control attempted");
    assert!(
        !control.winsock && !control.cred && !control.ok(),
        "{control:?}"
    );
    for (probe, code) in [
        (ProbeId::ConnectLoopback, WSASYSCALLFAILURE),
        (ProbeId::ConnectPublic, WSASYSCALLFAILURE),
        (ProbeId::CredRead, RPC_S_INVALID_BINDING),
    ] {
        let (outcome, evidence) = record(&report, probe);
        assert_eq!(outcome, ProbeOutcome::Error, "{probe:?}");
        assert!(
            matches!(evidence, Evidence::StackUnavailable { os_error, control_ok: false } if os_error == code),
            "{probe:?}: {evidence:?}"
        );
    }
    assert_eq!(
        report.floor,
        FloorVerdict::NotMet {
            failed: vec![
                ProbeId::ConnectLoopback,
                ProbeId::ConnectPublic,
                ProbeId::CredRead
            ]
        }
    );
}

#[test]
fn without_the_unconfined_control_a_plain_appcontainer_timeout_is_not_blocked() {
    let copy = plain_appcontainer_copy("nocontrol");
    let spawner = NoControl(WindowsSpawner::new().expect("AppContainer profile"));
    let report = run_probes(&spawner, None, &config_for(&copy.exe));
    print_report("no control (plain AppContainer)", &report);
    // the host's own listener self-check still ran, but the unconfined worker
    // did not, so a connect that timed out is an Error, not a Blocked
    let (outcome, evidence) = record(&report, ProbeId::ConnectLoopback);
    assert_eq!(outcome, ProbeOutcome::Error);
    assert!(
        matches!(
            evidence,
            Evidence::ListenerArrival {
                arrived: false,
                control_ok: false,
                ..
            }
        ),
        "{evidence:?}"
    );
    assert_eq!(
        report.floor,
        FloorVerdict::NotMet {
            failed: vec![ProbeId::ConnectLoopback]
        }
    );
}

#[test]
fn a_failed_lpac_floor_is_rerun_as_a_plain_appcontainer_and_the_better_verdict_wins() {
    // LPAC with a broken control is NotMet; the plain AppContainer rerun has a
    // working control and is Met, so it is reported, with what failed under LPAC.
    grant_built_worker();
    let lpac = NoControl(WindowsSpawner::new().expect("AppContainer profile"));
    let plain = || -> Option<Box<dyn WorkerSpawner>> {
        Some(Box::new(
            WindowsSpawner::new_plain().expect("AppContainer profile"),
        ))
    };
    let report = run_probes_with_fallback(&lpac, &plain, None, &config_for(&worker_exe()));
    print_report("fallback", &report);
    assert_eq!(report.floor, FloorVerdict::Met, "{report:#?}");
    assert_eq!(
        report.confinement.as_ref().and_then(|c| c.lpac),
        Some(false),
        "the reported run is the plain AppContainer"
    );
    assert_eq!(
        report.lpac_failed,
        Some(vec![
            ProbeId::ConnectLoopback,
            ProbeId::ConnectPublic,
            ProbeId::CredRead
        ])
    );
    // a plain-AppContainer rerun that is not better changes nothing
    let both_broken = || -> Option<Box<dyn WorkerSpawner>> {
        Some(Box::new(NoControl(
            WindowsSpawner::new_plain().expect("profile"),
        )))
    };
    let report = run_probes_with_fallback(&lpac, &both_broken, None, &config_for(&worker_exe()));
    assert_ne!(report.floor, FloorVerdict::Met);
    assert_eq!(report.confinement.as_ref().and_then(|c| c.lpac), Some(true));
    assert_eq!(report.lpac_failed, None);
    // and an LPAC floor that is met is returned as it is
    let good = spawner();
    let report = run_probes_with_fallback(&good, &plain, None, &config_for(&worker_exe()));
    assert_eq!(report.lpac_failed, None);
    if expect_floor_met() {
        assert_eq!(report.floor, FloorVerdict::Met);
    }
}

fn accept_within(listener: &std::net::TcpListener, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        match listener.accept() {
            Ok(_) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("accept: {e}"),
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_plain_appcontainer_connect_never_reaches_a_listening_loopback_socket() {
    // The probe's own target (127.0.0.1:9) cannot show a loopback denial on
    // this machine, so this gives the host a listening socket: an unconfined
    // connect arrives at it, the confined worker's connect must not.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("addr");
    std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .expect("control: an unconfined connect to the listener works");
    assert!(
        accept_within(&listener, Duration::from_secs(1)),
        "control: the listener sees the unconfined connect"
    );

    let copy = plain_appcontainer_copy("loopback");
    let spawner = WindowsSpawner::new().expect("AppContainer profile");
    let mut p = spawner
        .spawn_process(&spec_for(&copy.exe))
        .expect("spawn the worker");
    let _ = read_ready(&mut p);
    let request = ProbeRequest {
        probe: ProbeId::ConnectLoopback,
        app_pid: std::process::id(),
        profile_path: profile_dir().to_string_lossy().into_owned(),
        public_addr: PUBLIC_PROBE_ADDR.to_string(),
        loopback_addr: addr.to_string(),
        handle_value: None,
    };
    write_frame(&mut p.stdin(), &encode_notification(M_PROBE_RUN, &request))
        .expect("write probe.run");
    p.close_stdin();
    let frame = p
        .read_frame_timeout(WORKER_FRAME_MAX_BYTES, WAIT)
        .expect("read")
        .expect("probe.result");
    let (_, params) = decode_notification(&frame).expect("notification");
    let msg: ProbeResultMsg = serde_json::from_value(params).expect("params");
    let arrived = accept_within(&listener, Duration::from_millis(500));
    println!(
        "T19 loopback_listener_saw_connect={arrived} (listener {addr}, worker result {msg:?})"
    );
    assert!(!arrived, "the confined worker reached a loopback listener");
}

#[test]
fn the_job_has_the_section_9_4_limits_and_holds_only_the_worker() {
    let spawner = spawner();
    let mut p = spawner
        .spawn_process(&spec_for(&worker_exe()))
        .expect("spawn the worker");
    let _ = read_ready(&mut p);
    let job = p.job_snapshot().expect("QueryInformationJobObject");
    println!("T19 job: {job:?}");

    assert_eq!(job.active_process_limit, 1);
    let want = JobSnapshot::ACTIVE_PROCESS
        | JobSnapshot::KILL_ON_JOB_CLOSE
        | JobSnapshot::DIE_ON_UNHANDLED_EXCEPTION
        | JobSnapshot::PROCESS_MEMORY;
    assert_eq!(job.limit_flags & want, want, "{job:?}");
    assert_eq!(
        job.process_memory_limit,
        u64::from(DEFAULT_PROCESS_MB) * 1024 * 1024
    );
    // On the GitHub windows-2022 runner (itself inside a job) setting all eight
    // UI limits at once is refused with 87 (CI run 3). The spawner then keeps the
    // bits the system accepts; there the test records what holds instead of
    // asserting all of them. Everywhere else all eight must hold.
    println!(
        "T19 job UI restrictions: {:#x} of {:#x}",
        job.ui_restrictions,
        JobSnapshot::UILIMIT_ALL
    );
    if std::env::var_os("GITHUB_ACTIONS").is_none() {
        assert_eq!(job.ui_restrictions, JobSnapshot::UILIMIT_ALL);
    }
    assert_eq!(
        job.pids,
        vec![p.pid()],
        "the worker, and nothing else (no conhost)"
    );
}

#[test]
fn dropping_the_process_kills_the_worker_within_a_second() {
    let spawner = spawner();
    let mut p = spawner
        .spawn_process(&spec_for(&worker_exe()))
        .expect("spawn the worker");
    let _ = read_ready(&mut p); // alive, blocked reading stdin
    let run_dir = p.run_dir().to_path_buf();
    assert!(run_dir.is_dir());

    let mut dup: HANDLE = null_mut();
    // SAFETY: duplicating the process handle we own into this process.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            p.process_handle() as HANDLE,
            GetCurrentProcess(),
            &mut dup,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    assert_ne!(ok, 0, "DuplicateHandle");

    let started = Instant::now();
    drop(p);
    // SAFETY: `dup` is a valid handle.
    let wait = unsafe { WaitForSingleObject(dup, 1000) };
    // SAFETY: `dup` is closed once.
    unsafe { CloseHandle(dup) };
    assert_eq!(
        wait, WAIT_OBJECT_0,
        "the worker was still running 1 s after the drop"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(
        !run_dir.exists(),
        "the per-run directory is removed with the process"
    );
}

#[test]
fn the_run_directory_is_empty_and_inside_the_appcontainer_folder() {
    let spawner = spawner();
    let mut p = spawner
        .spawn_process(&spec_for(&worker_exe()))
        .expect("spawn the worker");
    let _ = read_ready(&mut p);
    let dir = p.run_dir().to_path_buf();
    println!("T19 run dir: {}", dir.display());
    assert_eq!(std::fs::read_dir(&dir).expect("read run dir").count(), 0);
    let text = dir.to_string_lossy().to_ascii_lowercase();
    assert!(
        text.contains("\\packages\\atlas-duck.sandbox\\ac\\"),
        "{text}"
    );
}

#[test]
fn every_module_the_worker_loads_from_its_dir_has_the_aces() {
    // V09: "the exact set of DLLs needing (L)PAC ACEs". Print the static
    // imports (what `dumpbin /dependents` shows) and the modules loaded at
    // runtime, and require that every loaded module from the worker's own
    // directory is in `worker_ace_files`. Modules from elsewhere outside the
    // Windows directory (injected by security software) are printed as
    // `T19 foreign module`.
    let spawner = spawner();
    let exe = worker_exe();
    let mut p = spawner
        .spawn_process(&spec_for(&exe))
        .expect("spawn the worker");
    let _ = read_ready(&mut p);

    let imports = pe_import_names(&std::fs::read(&exe).expect("read worker")).expect("PE imports");
    println!("T19 static imports: {imports:?}");
    let modules = loaded_modules(p.process_handle() as HANDLE);
    for m in &modules {
        println!("T19 loaded module: {}", m.display());
    }
    let ace_files = worker_ace_files_for_exe(&exe).expect("ACE file set");
    println!("T19 ACE file set: {ace_files:?}");

    let windir = std::env::var("SystemRoot")
        .expect("SystemRoot")
        .to_ascii_lowercase();
    let covered: Vec<String> = ace_files
        .iter()
        .map(|f| f.to_string_lossy().to_ascii_lowercase())
        .collect();
    let install_dir = exe
        .parent()
        .expect("worker dir")
        .to_string_lossy()
        .to_ascii_lowercase();
    for m in modules {
        let text = m.to_string_lossy().to_ascii_lowercase();
        if text.starts_with(&windir) {
            continue;
        }
        let text = text.trim_start_matches("\\\\?\\").to_string();
        let covered_here = covered
            .iter()
            .any(|c| c.trim_start_matches("\\\\?\\") == text);
        if text.starts_with(&install_dir) {
            assert!(
                covered_here,
                "{text} is loaded by the worker from its dir but not in worker_ace_files: {covered:?}"
            );
        } else if !covered_here {
            // Not ours to grant: security software injects a hook DLL into
            // every process (seen: F-Secure's `fshook64.dll`).
            println!("T19 foreign module: {text}");
        }
    }
    p.close_stdin();
}

#[test]
fn platform_spawner_is_the_windows_spawner_and_starts_a_worker() {
    grant_built_worker();
    let spawner = atlas_duck_sandbox_host::platform_spawner().expect("platform_spawner");
    let mut worker = spawner
        .spawn(&spec_for(&worker_exe()))
        .expect("spawn through the trait object");
    let frame = worker
        .read_frame_timeout(WORKER_FRAME_MAX_BYTES, WAIT)
        .expect("read")
        .expect("probe.ready frame");
    let (method, _) = decode_notification(&frame).expect("notification");
    assert_eq!(method, M_PROBE_READY);
    worker.close_stdin();
    assert_eq!(
        worker.wait_timeout(WAIT).expect("wait"),
        Some(ExitKind::Code(0))
    );
}

/// Clean-up, not a check: deletes the AppContainer profile `atlas-duck.sandbox`
/// that the tests above create under the current user (HKCU mapping and the
/// `%LOCALAPPDATA%\Packages\atlas-duck.sandbox` folder). It is `#[ignore]`d
/// so that a normal run, in which tests share the profile, never deletes it
/// from under a running test. Run it after the tests, and after a crashed run:
/// `cargo test -p atlas-duck-app --test probes_windows -- --ignored delete_the_appcontainer_profile`.
#[test]
#[ignore = "clean-up: deletes the AppContainer profile"]
fn delete_the_appcontainer_profile() {
    atlas_duck_sandbox_host::windows::delete_appcontainer_profile(APPCONTAINER_NAME)
        .expect("delete the AppContainer profile");
}
