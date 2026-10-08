//! T20: the §9.4 startup probe from the app: never blocks startup, lands in
//! `AppState`, one metadata-only log line, ACE ensure before the probe on
//! Windows.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atlas_duck_app_lib::diag::{ALLOWED_FIELDS, Diag, LOG_DIR_NAME, fields, scan_logs_for};
#[cfg(windows)]
use atlas_duck_app_lib::sandbox_probe::AceEnsure;
use atlas_duck_app_lib::sandbox_probe::{
    LOG_EVENT_SANDBOX_PROBE, PROBE_LOG_FIELDS, PROBE_THREAD_NAME, ace_label, extra_layers_label,
    failed_label, floor_label, log_probe_report, probe_id_name, run_startup_probe,
    sandbox_worker_path, spawn_startup_probe, spawn_startup_probe_with,
};
use atlas_duck_app_lib::state::{AppState, StartupSummary};
use atlas_duck_ipc::paths::{DataDirResolution, base_dirs, check_data_dir};
use atlas_duck_ipc::sandbox::probe::ProbeId;
use atlas_duck_sandbox_host::probe::{Evidence, FloorVerdict, ProbeReport};
use tauri::Manager;
use tauri::test::{MockRuntime, mock_builder, mock_context, noop_assets};
use tracing_subscriber::Registry;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

// ---------------------------------------------------------------- helpers

/// The dev-built worker: `ATLAS_DUCK_SANDBOX_BIN` if set (T16 convention),
/// else the bin cargo built next to this test.
fn real_worker() -> PathBuf {
    std::env::var_os("ATLAS_DUCK_SANDBOX_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_atlas-duck-sandbox")))
}

/// A fresh temp dir. On Windows it lives under the workspace `target/tmp`: the ACE
/// tests grant and remove (L)PAC ACEs on it, which must stay inside the build tree.
/// The `TempDir` guard deletes the dir (and its ACEs) on drop.
fn scratch_dir() -> tempfile::TempDir {
    #[cfg(windows)]
    {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp");
        std::fs::create_dir_all(&root).expect("create target/tmp");
        tempfile::Builder::new()
            .prefix("t20-")
            .tempdir_in(root)
            .expect("tempdir under target/tmp")
    }
    #[cfg(not(windows))]
    tempfile::tempdir().expect("tempdir")
}

/// Windows: `ATLAS_DUCK_EXPECT_WINDOWS_FLOOR_MET=1` makes a `Met` floor mandatory. CI's
/// windows-2022 jobs and the dev box set it: the host scores the LPAC Winsock / RPC
/// failures and the loopback timeout from controls (sandbox-host `winscore`).
#[cfg(windows)]
fn expect_floor_met() -> bool {
    std::env::var_os("ATLAS_DUCK_EXPECT_WINDOWS_FLOOR_MET").is_some_and(|v| v == "1")
}

/// Machine-independent Windows invariants: the worker spawned and confined itself,
/// every floor probe has a record, and the verdict is printed as evidence; `Met` is
/// asserted only under `expect_floor_met`.
#[cfg(windows)]
fn assert_windows_floor_evidence(label: &str, report: &ProbeReport) {
    println!("T20 {label}: floor verdict = {:?}", report.floor);
    let confinement = report.confinement.as_ref().expect("a probe.ready arrived");
    assert!(confinement.applied, "{confinement:?}");
    assert_eq!(confinement.mechanism, "appcontainer");
    for p in ProbeId::floor_probes_for_current_os() {
        assert!(
            report.records.iter().any(|r| r.probe == *p),
            "no record for {p:?}"
        );
    }
    for r in &report.records {
        assert!(
            !matches!(r.evidence, Evidence::SpawnFailed(_)),
            "worker did not spawn: {r:?}"
        );
    }
    if expect_floor_met() {
        assert!(matches!(report.floor, FloorVerdict::Met), "{report:#?}");
        // pinned to LPAC: a silent regression that the plain-AppContainer fallback hides is red
        assert_eq!(confinement.lpac, Some(true), "{label}: {confinement:?}");
        assert_eq!(report.lpac_failed, None, "{label}");
    }
}

/// A throwaway "install dir" holding a copy of the real worker.
fn fake_install_dir() -> tempfile::TempDir {
    let dir = scratch_dir();
    std::fs::copy(real_worker(), sandbox_worker_path(dir.path())).expect("copy worker");
    dir
}

fn home() -> PathBuf {
    base_dirs().expect("base_dirs").home
}

fn empty_report(floor: FloorVerdict) -> ProbeReport {
    ProbeReport {
        worker_version: None,
        engine_version: None,
        identity: None,
        confinement: None,
        threads: None,
        records: vec![],
        floor,
        extra_layers: vec![],
        control: None,
        lpac_failed: None,
    }
}

/// Builds a mock-runtime app whose `setup` hook manages an `AppState` and then
/// calls `setup`, like `run_gui`. Tauri runs the setup hook on the first
/// event-loop iteration, not in `build`, so one iteration is driven here.
fn mock_app_with(
    setup: impl FnOnce(&tauri::AppHandle<MockRuntime>) + Send + 'static,
) -> tauri::App<MockRuntime> {
    let mut app = mock_builder()
        .setup(move |app| {
            app.manage(AppState::new(StartupSummary::Ready, None));
            setup(app.handle());
            Ok(())
        })
        .build(mock_context(noop_assets()))
        .expect("mock app");
    #[allow(deprecated)]
    app.run_iteration(|_, _| {});
    app
}

fn wait_for_report(app: &tauri::App<MockRuntime>, limit: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < limit {
        if app.state::<AppState>().probe_report().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

/// Runs `f` under a scoped allowlist subscriber (as T08's tests do) and
/// returns what it wrote. The six T20 field names are registered first,
/// exactly as `run_gui` does.
fn capture(f: impl FnOnce()) -> String {
    Diag::init().extend_allowed_fields(PROBE_LOG_FIELDS);
    let cap = Capture::default();
    let subscriber = Registry::default().with(fields::allowlist_layer(cap.clone()));
    tracing::subscriber::with_default(subscriber, f);
    let bytes = cap.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

// ------------------------------------------------- pure label and path tests

#[test]
fn worker_path_is_the_sibling_binary() {
    let p = sandbox_worker_path(Path::new("install"));
    assert_eq!(p.parent(), Some(Path::new("install")));
    assert_eq!(
        p.file_name().and_then(|n| n.to_str()),
        Some(format!("atlas-duck-sandbox{}", std::env::consts::EXE_SUFFIX).as_str())
    );
}

#[test]
fn probe_id_names_match_the_serde_names() {
    let all = [
        ProbeId::FileInProfile,
        ProbeId::ConnectLoopback,
        ProbeId::ConnectPublic,
        ProbeId::SpawnProcess,
        ProbeId::RawClone,
        ProbeId::Clone3,
        ProbeId::MemReadProcessVm,
        ProbeId::MemReadProcMem,
        ProbeId::TaskForPid,
        ProbeId::OpenProcessVmRead,
        ProbeId::CredRead,
        ProbeId::OpenClipboard,
        ProbeId::MachLookupSecurityd,
        ProbeId::EngineSelfTest,
        ProbeId::EnvNames,
        ProbeId::HandleSentinel,
    ];
    for id in all {
        let json = serde_json::to_value(id).unwrap();
        assert_eq!(json.as_str(), Some(probe_id_name(id)), "{id:?}");
    }
}

#[test]
fn labels_follow_the_plan_spelling() {
    assert_eq!(floor_label(&FloorVerdict::Met), "met");
    assert_eq!(failed_label(&FloorVerdict::Met), "none");
    let not_met = FloorVerdict::NotMet {
        failed: vec![ProbeId::FileInProfile, ProbeId::TaskForPid],
    };
    assert_eq!(floor_label(&not_met), "not_met");
    assert_eq!(failed_label(&not_met), "file_in_profile+task_for_pid");
    assert_eq!(extra_layers_label(&[]), "none");
    assert_eq!(
        extra_layers_label(&[("landlock".to_owned(), true), ("x".to_owned(), false)]),
        "landlock:on+x:off"
    );
    assert_eq!(ace_label(None), "n/a");
}

#[cfg(windows)]
#[test]
fn ace_labels_follow_the_spec_spelling() {
    assert_eq!(ace_label(Some(&AceEnsure::Present)), "present");
    assert_eq!(ace_label(Some(&AceEnsure::Reapplied)), "reapplied");
    assert_eq!(
        ace_label(Some(&AceEnsure::MissingNoWriteDac)),
        "missing_no_write_dac"
    );
}

// ------------------------------------------------------ missing worker

#[test]
fn missing_worker_is_not_met_with_spawn_failed_records_and_returns_fast() {
    let install = tempfile::tempdir().unwrap();
    let profile = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let (report, ace) = run_startup_probe(install.path(), std::process::id(), profile.path());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
    assert!(!report.records.is_empty());
    for record in &report.records {
        assert!(
            matches!(record.evidence, Evidence::SpawnFailed(_)),
            "{record:?}"
        );
    }
    match &report.floor {
        FloorVerdict::NotMet { failed } => {
            for p in ProbeId::floor_probes_for_current_os() {
                assert!(failed.contains(p), "{p:?} missing from {failed:?}");
            }
        }
        FloorVerdict::Met => panic!("floor met without a worker"),
    }
    assert!(report.identity.is_none());
    #[cfg(not(windows))]
    assert!(ace.is_none());
    #[cfg(windows)]
    assert!(!matches!(
        ace,
        Some(AceEnsure::Present) | Some(AceEnsure::Reapplied)
    ));
}

// ------------------------------------------------------ never blocks startup

#[test]
fn spawn_startup_probe_with_does_not_block_setup() {
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (name_tx, name_rx) = mpsc::channel::<Option<String>>();
    let (handle_tx, handle_rx) = mpsc::channel();
    let spawn_took = Arc::new(Mutex::new(Duration::ZERO));
    let spawn_took_in_setup = Arc::clone(&spawn_took);

    let app = mock_app_with(move |app| {
        let started = Instant::now();
        let handle = spawn_startup_probe_with(app, move || {
            name_tx
                .send(std::thread::current().name().map(str::to_owned))
                .unwrap();
            // Blocks until the test releases it: the probe is "still running".
            release_rx.recv().unwrap();
            (empty_report(FloorVerdict::Met), None)
        })
        .expect("spawn probe thread");
        *spawn_took_in_setup.lock().unwrap() = started.elapsed();
        handle_tx.send(handle).unwrap();
    });

    assert!(
        *spawn_took.lock().unwrap() < Duration::from_millis(200),
        "setup was blocked for {:?}",
        spawn_took.lock().unwrap()
    );
    let state = app.state::<AppState>();
    assert!(!state.scripts_floor_met());
    assert!(state.probe_report().is_none());
    assert_eq!(
        name_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .as_deref(),
        Some(PROBE_THREAD_NAME)
    );

    release_tx.send(()).unwrap();
    handle_rx.recv().unwrap().join().unwrap();
    assert!(state.scripts_floor_met());
    assert_eq!(
        state.probe_report().map(|r| &r.floor),
        Some(&FloorVerdict::Met)
    );
}

#[test]
fn a_not_met_report_keeps_scripts_disabled() {
    let (handle_tx, handle_rx) = mpsc::channel();
    let app = mock_app_with(move |app| {
        let handle = spawn_startup_probe_with(app, || {
            (
                empty_report(FloorVerdict::NotMet {
                    failed: vec![ProbeId::FileInProfile],
                }),
                None,
            )
        })
        .unwrap();
        handle_tx.send(handle).unwrap();
    });
    handle_rx.recv().unwrap().join().unwrap();
    let state = app.state::<AppState>();
    assert!(state.probe_report().is_some());
    assert!(!state.scripts_floor_met());
}

#[test]
fn spawn_startup_probe_returns_at_once_and_the_report_lands() {
    let spawn_took = Arc::new(Mutex::new(Duration::ZERO));
    let spawn_took_in_setup = Arc::clone(&spawn_took);
    let app = mock_app_with(move |app| {
        let started = Instant::now();
        spawn_startup_probe(app);
        *spawn_took_in_setup.lock().unwrap() = started.elapsed();
    });
    assert!(
        *spawn_took.lock().unwrap() < Duration::from_millis(200),
        "setup was blocked for {:?}",
        spawn_took.lock().unwrap()
    );
    assert!(
        wait_for_report(&app, Duration::from_secs(120)),
        "no probe report within 120 s"
    );
    let state = app.state::<AppState>();
    let report = state.probe_report().unwrap();
    assert_eq!(
        state.scripts_floor_met(),
        matches!(report.floor, FloorVerdict::Met)
    );
}

// ------------------------------------------------------ the real worker

/// Linux: the app must be non-dumpable before the memory-read probes, as
/// run_gui's crash settings (T09) make it in a GUI launch.
fn make_test_process_the_app() {
    #[cfg(target_os = "linux")]
    atlas_duck_app_lib::startup::crash::set_non_dumpable().expect("PR_SET_DUMPABLE 0");
}

/// CI: runs on the `rust` job's windows-2022, macos-15 and ubuntu-22.04
/// legs and on `rust-macos-x86_64-rosetta` (`cargo test --workspace`).
#[test]
fn real_worker_in_a_copied_install_dir_meets_the_floor() {
    make_test_process_the_app();
    let install = fake_install_dir();
    let (report, ace) = run_startup_probe(install.path(), std::process::id(), &home());
    #[cfg(windows)]
    assert_windows_floor_evidence("copied install dir", &report);
    #[cfg(not(windows))]
    match &report.floor {
        FloorVerdict::Met => {}
        // macOS: TaskForPid needs the hardened-runtime bundle (T12); the
        // signed installed app is asserted in T21.
        FloorVerdict::NotMet { failed }
            if cfg!(target_os = "macos") && failed.iter().all(|p| *p == ProbeId::TaskForPid) => {}
        FloorVerdict::NotMet { failed } => {
            panic!("floor not met: {failed:?}\n{:#?}", report.records)
        }
    }
    #[cfg(windows)]
    assert!(
        matches!(ace, Some(AceEnsure::Reapplied) | Some(AceEnsure::Present)),
        "{ace:?}"
    );
    #[cfg(not(windows))]
    assert!(ace.is_none());
}

// ------------------------------------------------------ Windows ACE ensure

#[cfg(windows)]
mod windows_aces {
    use super::*;
    use atlas_duck_sandbox_host::windows::{AceStatus, check_aces, worker_ace_files};
    use std::process::Command;

    fn icacls(args: &[&std::ffi::OsStr]) -> String {
        let out = Command::new("icacls").args(args).output().expect("icacls");
        assert!(out.status.success(), "{out:?}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn listing(path: &Path) -> String {
        icacls(&[path.as_os_str()])
    }

    /// A copied install dir that certainly lacks the (L)PAC ACEs: the temp
    /// dir's inherited entries are made explicit, then any entry for
    /// S-1-15-2-1 / S-1-15-2-2 is removed, then the worker is copied in (so it
    /// inherits no such entry). Without this the result would depend on the
    /// runner's temp-dir ACL.
    fn install_dir_without_pac_aces() -> tempfile::TempDir {
        let dir = scratch_dir();
        icacls(&[dir.path().as_os_str(), "/inheritance:d".as_ref()]);
        icacls(&[
            dir.path().as_os_str(),
            "/remove:g".as_ref(),
            "*S-1-15-2-1".as_ref(),
            "*S-1-15-2-2".as_ref(),
        ]);
        std::fs::copy(real_worker(), sandbox_worker_path(dir.path())).expect("copy worker");
        let files = worker_ace_files(dir.path()).expect("worker_ace_files");
        assert!(
            matches!(
                check_aces(&files).expect("check_aces"),
                AceStatus::Missing(_)
            ),
            "precondition: the copied worker must lack the (L)PAC ACEs"
        );
        dir
    }

    /// CI: `rust` job, windows-2022 leg. Read the `ace=` assertion output.
    #[test]
    fn missing_aces_without_write_dac_are_reported_and_the_dacl_is_untouched() {
        let install = install_dir_without_pac_aces();
        let worker = sandbox_worker_path(install.path());
        let before = listing(&worker);
        let (report, ace) = atlas_duck_app_lib::sandbox_probe::run_startup_probe_with(
            install.path(),
            std::process::id(),
            &home(),
            Some(false),
        );
        assert!(matches!(ace, Some(AceEnsure::MissingNoWriteDac)), "{ace:?}");
        assert_eq!(ace_label(ace.as_ref()), "missing_no_write_dac");
        assert!(
            matches!(report.floor, FloorVerdict::NotMet { .. }),
            "a missing ACE must never yield Met: {report:#?}"
        );
        assert_eq!(listing(&worker), before, "DACL changed");
    }

    #[test]
    fn writable_copy_is_reapplied_then_present_and_the_floor_is_met() {
        let install = install_dir_without_pac_aces();
        let (first, ace1) = run_startup_probe(install.path(), std::process::id(), &home());
        assert!(matches!(ace1, Some(AceEnsure::Reapplied)), "{ace1:?}");
        assert_windows_floor_evidence("reapplied", &first);
        let (_, ace2) = run_startup_probe(install.path(), std::process::id(), &home());
        assert!(matches!(ace2, Some(AceEnsure::Present)), "{ace2:?}");
    }
}

// ------------------------------------------------------ the log line

#[test]
fn the_log_line_has_exactly_the_planned_fields() {
    let mut report = empty_report(FloorVerdict::NotMet {
        failed: vec![ProbeId::FileInProfile, ProbeId::MemReadProcMem],
    });
    report.engine_version = Some("0.16.2".to_owned());
    report.worker_version = Some("0.1.0+abcdef123456".to_owned());
    report.extra_layers = vec![("landlock".to_owned(), true)];
    let out = capture(|| log_probe_report(&report, None));
    let line = out.lines().next().expect("one line");
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(
        line.ends_with(
            "event=sandbox_probe floor=not_met failed=file_in_profile+mem_read_proc_mem \
             extra_layers=landlock:on engine_version=0.16.2 \
             worker_version=0.1.0+abcdef123456 ace=n/a appcontainer_mode=n/a control_ok=n/a \
             lpac_failed=n/a dropped_fields=0"
        ),
        "{line}"
    );
    assert_eq!(LOG_EVENT_SANDBOX_PROBE, "sandbox_probe");
    for token in line.split(' ').skip(4) {
        let key = token.split('=').next().unwrap();
        assert!(
            ALLOWED_FIELDS.contains(&key)
                || PROBE_LOG_FIELDS.contains(&key)
                || key == "dropped_fields",
            "unexpected field {key} in {line}"
        );
    }

    let met = capture(|| log_probe_report(&empty_report(FloorVerdict::Met), None));
    assert!(
        met.trim_end().ends_with(
            "event=sandbox_probe floor=met failed=none extra_layers=none \
             engine_version=unknown worker_version=unknown ace=n/a appcontainer_mode=n/a \
             control_ok=n/a lpac_failed=n/a dropped_fields=0"
        ),
        "{met}"
    );
}

#[test]
fn the_log_line_names_the_windows_mode_control_and_lpac_fallback() {
    use atlas_duck_ipc::sandbox::probe::ConfinementReport;
    use atlas_duck_sandbox_host::winscore::WindowsControl;

    fn confinement(lpac: bool) -> Option<ConfinementReport> {
        Some(ConfinementReport {
            applied: true,
            mechanism: "appcontainer".to_owned(),
            no_new_privs: None,
            landlock_abi: None,
            seccomp: None,
            lpac: Some(lpac),
            os_error: None,
        })
    }
    let mut report = empty_report(FloorVerdict::Met);
    report.confinement = confinement(false);
    report.control = Some(WindowsControl {
        listener: true,
        winsock: true,
        cred: true,
    });
    report.lpac_failed = Some(vec![ProbeId::ConnectLoopback, ProbeId::CredRead]);
    let out = capture(|| log_probe_report(&report, None));
    assert!(
        out.trim_end().ends_with(
            "ace=n/a appcontainer_mode=appcontainer control_ok=true \
             lpac_failed=connect_loopback+cred_read dropped_fields=0"
        ),
        "{out}"
    );

    report.confinement = confinement(true);
    report.lpac_failed = None;
    report.control = Some(WindowsControl {
        cred: false,
        ..report.control.unwrap()
    });
    let out = capture(|| log_probe_report(&report, None));
    assert!(
        out.trim_end().ends_with(
            "ace=n/a appcontainer_mode=lpac control_ok=false lpac_failed=n/a dropped_fields=0"
        ),
        "{out}"
    );
}

/// The only test that attaches a data dir to the process-wide `Diag`.
#[test]
fn the_log_line_reaches_the_file_and_holds_no_user_paths() {
    let diag = Diag::init();
    diag.extend_allowed_fields(PROBE_LOG_FIELDS);
    let data = tempfile::tempdir().unwrap();
    let local = match check_data_dir(data.path()).unwrap() {
        DataDirResolution::Local(d) => d,
        _ => panic!("temp dir is not a local data dir"),
    };
    // Logged before the data dir exists: waits in the buffer (T08).
    let install = tempfile::tempdir().unwrap();
    let profile = tempfile::Builder::new()
        .prefix("SENTINEL-PROFILE-t20-")
        .tempdir()
        .unwrap();
    let (mut report, ace) = run_startup_probe(install.path(), std::process::id(), profile.path());
    report.worker_version = Some("t20-file-test".to_owned());
    log_probe_report(&report, ace.as_ref());
    diag.attach_dir(&local).unwrap();

    let logs = data.path().join(LOG_DIR_NAME);
    let text = std::fs::read_to_string(logs.join("diag.log")).unwrap();
    let line = text
        .lines()
        .find(|l| l.contains("worker_version=t20-file-test"))
        .unwrap_or_else(|| panic!("no probe line in {text}"));
    assert!(line.contains("event=sandbox_probe"), "{line}");
    assert!(line.contains("floor=not_met"), "{line}");

    let home = home();
    let needles = [
        home.to_str().unwrap(),
        profile.path().to_str().unwrap(),
        install.path().to_str().unwrap(),
    ];
    assert_eq!(
        scan_logs_for(&logs, &needles).unwrap(),
        Vec::<PathBuf>::new()
    );
}
