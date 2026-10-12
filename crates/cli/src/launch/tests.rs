use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use atlas_duck_ipc::envelope::Status;
use atlas_duck_ipc::paths::{
    DataDirResolution, PinnedPaths, check_data_dir, paths_file, pinned_dir, write_pinned,
};
use atlas_duck_ipc::proto::exit_code;

use super::*;

const HOST: &str = "testhost";

type OnSpawn = Box<dyn FnOnce() + Send>;

/// A `LaunchSys` whose endpoint is a flag; `spawn_app` counts, optionally sleeps, fails, runs a
/// hook, and (by default) makes the endpoint appear.
struct Double {
    gui: bool,
    base: BaseDirs,
    present: AtomicBool,
    present_on_spawn: bool,
    spawn_delay: Duration,
    spawn_fails: bool,
    spawns: AtomicU32,
    on_spawn: Mutex<Option<OnSpawn>>,
    spawned_env: Mutex<Vec<(OsString, OsString)>>,
}

impl Double {
    fn new(base: BaseDirs) -> Double {
        Double {
            gui: true,
            base,
            present: AtomicBool::new(false),
            present_on_spawn: true,
            spawn_delay: Duration::ZERO,
            spawn_fails: false,
            spawns: AtomicU32::new(0),
            on_spawn: Mutex::new(None),
            spawned_env: Mutex::new(Vec::new()),
        }
    }

    fn spawns(&self) -> u32 {
        self.spawns.load(Ordering::SeqCst)
    }
}

impl LaunchSys for Double {
    fn gui_session(&self) -> bool {
        self.gui
    }

    fn launch_env(&self) -> Vec<(OsString, OsString)> {
        vec![(OsString::from("LANG"), OsString::from("C"))]
    }

    fn spawn_app(&self, _app: &Path, env: &[(OsString, OsString)]) -> Result<(), LaunchError> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        *self.spawned_env.lock().unwrap() = env.to_vec();
        std::thread::sleep(self.spawn_delay);
        if self.spawn_fails {
            return Err(LaunchError::ChildFailed(1));
        }
        if let Some(hook) = self.on_spawn.lock().unwrap().take() {
            hook();
        }
        if self.present_on_spawn {
            self.present.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    fn endpoint_present(&self, _data: &LocalDataDir, host: &str) -> bool {
        assert_eq!(host, HOST);
        self.present.load(Ordering::SeqCst)
    }

    fn base_dirs(&self) -> io::Result<BaseDirs> {
        Ok(self.base.clone())
    }
}

/// A temp world: base folders whose pinned-dir parent exists, and a local data dir.
struct World {
    _tmp: tempfile::TempDir,
    base: BaseDirs,
    data_path: PathBuf,
    data: LocalDataDir,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let base = BaseDirs {
        home: tmp.path().join("home"),
        local_app_data: Some(tmp.path().join("home").join("AppData").join("Local")),
        roaming_app_data: Some(tmp.path().join("home").join("AppData").join("Roaming")),
    };
    std::fs::create_dir_all(pinned_dir(&base).parent().unwrap()).unwrap();
    let data_path = tmp.path().join("data");
    std::fs::create_dir(&data_path).unwrap();
    let DataDirResolution::Local(data) = check_data_dir(&data_path).unwrap() else {
        panic!("temp dir is not local");
    };
    World {
        _tmp: tmp,
        base,
        data_path,
        data,
    }
}

fn discovery(data: DataState) -> Discovery {
    Discovery {
        host: HOST.to_owned(),
        data,
        app: AppLocation::Found(PathBuf::from("/opt/atlas-duck/atlas-duck-app")),
    }
}

fn within(ms: u64) -> Deadline {
    Deadline::new(Instant::now(), Some(Duration::from_millis(ms)))
}

fn reason(env: &Envelope) -> Option<&str> {
    env.error
        .as_ref()
        .and_then(|e| e.details.as_ref())
        .and_then(|m| m.get("reason"))
        .and_then(Value::as_str)
}

fn message(env: &Envelope) -> &str {
    env.error.as_ref().map(|e| e.message.as_str()).unwrap_or("")
}

fn retryable(env: &Envelope) -> bool {
    env.error.as_ref().is_some_and(|e| e.retryable)
}

fn pin(base: &BaseDirs, data_dir: &Path) {
    let p = PinnedPaths {
        schema_version: 1,
        data_dir: data_dir.to_path_buf(),
        config_dir: data_dir.join("config"),
        install_id: None,
    };
    write_pinned(&paths_file(base, HOST), &p).unwrap();
}

#[test]
fn busy_never_launches() {
    // Present-but-busy is the connect layer's concern: a present endpoint is never launched over,
    // with or without a desktop session.
    let w = world();
    let mut sys = Double::new(w.base.clone());
    sys.present = AtomicBool::new(true);
    sys.gui = false;
    let got = ensure_running(
        &discovery(DataState::Local(w.data.clone())),
        &within(5_000),
        &sys,
    );
    assert_eq!(got.unwrap(), w.data);
    assert_eq!(sys.spawns(), 0);
    assert!(!w.data_path.join("launch.lock").exists(), "no lock taken");
}

#[test]
fn refused_data_never_launches() {
    let w = world();
    let mut sys = Double::new(w.base.clone());
    sys.present = AtomicBool::new(true);
    let refused = discover::refusal(atlas_duck_ipc::paths::REASON_DATA_DIR_MISSING);
    let got = ensure_running(
        &discovery(DataState::Refused(Box::new(refused.clone()))),
        &within(5_000),
        &sys,
    );
    let env = got.unwrap_err();
    assert_eq!(*env, refused);
    assert_eq!(reason(&env), Some("data_dir_missing"));
    assert_eq!(exit_code(&env), 9);
    assert_eq!(sys.spawns(), 0);
}

#[test]
fn app_not_found_never_launches() {
    let w = world();
    let sys = Double::new(w.base.clone());
    let mut d = discovery(DataState::Local(w.data.clone()));
    d.app = AppLocation::NotFound;
    let env = ensure_running(&d, &within(5_000), &sys).unwrap_err();
    assert_eq!(*env, discover::app_not_found());
    assert_eq!(reason(&env), Some("not_running"));
    assert_eq!(exit_code(&env), 5);
    assert_eq!(sys.spawns(), 0);
}

#[test]
fn no_gui_session_exit5() {
    let w = world();
    let mut sys = Double::new(w.base.clone());
    sys.gui = false;
    for data in [DataState::Local(w.data.clone()), DataState::BeforeFirstRun] {
        let env = ensure_running(&discovery(data), &within(5_000), &sys).unwrap_err();
        assert_eq!(env.status, Status::Failed);
        assert_eq!(env.request_id, None);
        assert_eq!(
            env.error.as_ref().map(|e| e.code),
            Some(ErrorCode::Unreachable)
        );
        assert_eq!(reason(&env), Some("no_gui_session"));
        assert_eq!(
            message(&env),
            "no desktop session: start atlas-duck from the desktop"
        );
        assert!(retryable(&env));
        assert_eq!(exit_code(&env), 5);
    }
    assert_eq!(sys.spawns(), 0);
    assert!(!w.data_path.join("launch.lock").exists());
    assert!(
        !pinned_dir(&w.base).exists(),
        "nothing created without a session"
    );
}

#[test]
fn launch_lock_serializes() {
    let w = world();
    let mut sys = Double::new(w.base.clone());
    sys.spawn_delay = Duration::from_millis(200);
    let d = discovery(DataState::Local(w.data.clone()));
    let deadline = within(10_000);
    let (a, b) = std::thread::scope(|s| {
        let a = s.spawn(|| ensure_running(&d, &deadline, &sys));
        let b = s.spawn(|| ensure_running(&d, &deadline, &sys));
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_eq!(a.unwrap(), w.data);
    assert_eq!(b.unwrap(), w.data);
    assert_eq!(sys.spawns(), 1, "the second CLI re-checks under the lock");
    assert!(w.data_path.join("launch.lock").is_file());
}

/// Makes the double's endpoint answer `after` the first spawn (gives up after 5 s without one).
fn answer_after_spawn(sys: &Double, after: Duration) {
    let until = Instant::now() + Duration::from_secs(5);
    while sys.spawns() == 0 {
        if Instant::now() >= until {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(after);
    sys.present.store(true, Ordering::SeqCst);
}

#[test]
fn launch_lock_is_held_across_the_poll() {
    // The app answers ~150 ms after its spawn. A second CLI that got the lock right after the
    // spawn would find no endpoint and spawn again.
    let w = world();
    let mut sys = Double::new(w.base.clone());
    sys.present_on_spawn = false;
    let d = discovery(DataState::Local(w.data.clone()));
    let deadline = within(10_000);
    let (a, b) = std::thread::scope(|s| {
        let app = s.spawn(|| answer_after_spawn(&sys, Duration::from_millis(150)));
        let a = s.spawn(|| ensure_running(&d, &deadline, &sys));
        let b = s.spawn(|| ensure_running(&d, &deadline, &sys));
        app.join().unwrap();
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_eq!(a.unwrap(), w.data);
    assert_eq!(b.unwrap(), w.data);
    assert_eq!(sys.spawns(), 1, "the lock covers spawn and poll");
}

#[test]
fn stale_endpoint_still_launches_and_the_poll_waits_for_an_answer() {
    // The double's endpoint is the liveness probe: a socket file a crashed app left behind is
    // there, but refused (Unix: `unix::socket_answers`), until the new app listens ~150 ms after
    // its spawn.
    let w = world();
    let mut sys = Double::new(w.base.clone());
    sys.present_on_spawn = false;
    let d = discovery(DataState::Local(w.data.clone()));
    let start = Instant::now();
    let got = std::thread::scope(|s| {
        let app = s.spawn(|| answer_after_spawn(&sys, Duration::from_millis(150)));
        let got = ensure_running(&d, &within(5_000), &sys);
        app.join().unwrap();
        got
    });
    assert_eq!(got.unwrap(), w.data);
    assert!(start.elapsed() >= Duration::from_millis(150));
    assert_eq!(sys.spawns(), 1);
}

#[test]
fn spawn_gets_the_allowlisted_env() {
    let w = world();
    let sys = Double::new(w.base.clone());
    ensure_running(
        &discovery(DataState::Local(w.data.clone())),
        &within(5_000),
        &sys,
    )
    .unwrap();
    assert_eq!(*sys.spawned_env.lock().unwrap(), sys.launch_env());
}

#[test]
fn poll_capped_by_deadline() {
    let w = world();
    let mut sys = Double::new(w.base.clone());
    sys.present_on_spawn = false;
    let start = Instant::now();
    let deadline = Deadline::new(start, Some(Duration::from_millis(300)));
    let env = ensure_running(
        &discovery(DataState::Local(w.data.clone())),
        &deadline,
        &sys,
    )
    .unwrap_err();
    let took = start.elapsed();
    assert!(took < Duration::from_millis(600), "{took:?}");
    assert_eq!(reason(&env), Some("launch_timeout"));
    assert!(retryable(&env));
    assert_eq!(exit_code(&env), 5);
    assert_eq!(sys.spawns(), 1);
}

#[test]
fn expired_deadline_never_launches() {
    let w = world();
    let sys = Double::new(w.base.clone());
    let deadline = Deadline::new(Instant::now(), Some(Duration::ZERO));
    let env = ensure_running(
        &discovery(DataState::Local(w.data.clone())),
        &deadline,
        &sys,
    )
    .unwrap_err();
    assert_eq!(reason(&env), Some("launch_timeout"));
    assert_eq!(exit_code(&env), 5);
    assert_eq!(sys.spawns(), 0);
}

#[test]
fn lock_wait_counts_against_the_deadline() {
    let w = world();
    let sys = Double::new(w.base.clone());
    let held = lock::acquire(&lock::data_lock_path(&w.data), Duration::ZERO).unwrap();
    let start = Instant::now();
    let deadline = Deadline::new(start, Some(Duration::from_millis(300)));
    let env = ensure_running(
        &discovery(DataState::Local(w.data.clone())),
        &deadline,
        &sys,
    )
    .unwrap_err();
    assert!(start.elapsed() < Duration::from_millis(1_000));
    assert_eq!(reason(&env), Some("launch_timeout"));
    assert_eq!(exit_code(&env), 5);
    assert_eq!(sys.spawns(), 0);
    drop(held);
}

#[test]
fn launched_by_another_cli_while_waiting() {
    let w = world();
    let sys = Double::new(w.base.clone());
    let held = lock::acquire(&lock::data_lock_path(&w.data), Duration::ZERO).unwrap();
    let d = discovery(DataState::Local(w.data.clone()));
    let got = std::thread::scope(|s| {
        let waiter = s.spawn(|| ensure_running(&d, &within(5_000), &sys));
        std::thread::sleep(Duration::from_millis(150));
        // The other CLI's app came up; it releases the lock.
        sys.present.store(true, Ordering::SeqCst);
        drop(held);
        waiter.join().unwrap()
    });
    assert_eq!(got.unwrap(), w.data);
    assert_eq!(sys.spawns(), 0);
}

#[test]
fn spawn_failure_is_not_running() {
    let w = world();
    let mut sys = Double::new(w.base.clone());
    sys.spawn_fails = true;
    let env = ensure_running(
        &discovery(DataState::Local(w.data.clone())),
        &within(5_000),
        &sys,
    )
    .unwrap_err();
    assert_eq!(reason(&env), Some("not_running"));
    assert_eq!(
        message(&env),
        "the atlas-duck app could not be started: start atlas-duck from the desktop"
    );
    assert!(retryable(&env));
    assert_eq!(exit_code(&env), 5);
    assert_eq!(sys.spawns(), 1);
}

#[test]
fn before_first_run_poll_first_run_envelope() {
    let w = world();
    let sys = Double::new(w.base.clone());
    let start = Instant::now();
    let deadline = Deadline::new(start, Some(Duration::from_millis(400)));
    let env = ensure_running(&discovery(DataState::BeforeFirstRun), &deadline, &sys).unwrap_err();
    assert!(start.elapsed() < Duration::from_millis(1_000));
    assert_eq!(env.status, Status::Failed);
    assert_eq!(env.request_id, None);
    assert_eq!(
        env.error.as_ref().map(|e| e.code),
        Some(ErrorCode::NotConfigured)
    );
    assert_eq!(reason(&env), Some("first_run"));
    assert_eq!(
        message(&env),
        "atlas-duck is not set up yet: finish the setup window on the desktop"
    );
    assert!(retryable(&env));
    assert_eq!(exit_code(&env), 9);
    assert_eq!(sys.spawns(), 1);

    // PD-22: the pinned dir now exists and holds the lock file and nothing else.
    let entries: Vec<PathBuf> = std::fs::read_dir(pinned_dir(&w.base))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(entries, [lock::first_run_lock_path(&w.base, HOST)]);
}

#[test]
fn before_first_run_pinned_appears() {
    let w = world();
    let sys = Double::new(w.base.clone());
    let base = w.base.clone();
    let data_path = w.data_path.clone();
    *sys.on_spawn.lock().unwrap() = Some(Box::new(move || {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            pin(&base, &data_path);
        });
    }));
    let start = Instant::now();
    let got = ensure_running(&discovery(DataState::BeforeFirstRun), &within(5_000), &sys);
    assert_eq!(got.unwrap().path(), w.data_path.as_path());
    assert!(start.elapsed() < Duration::from_millis(2_000));
    assert_eq!(sys.spawns(), 1);
}

#[test]
fn before_first_run_pinned_but_endpoint_late_waits_for_the_endpoint() {
    // PD-04: once the pinned file appears the normal path (endpoint poll) continues.
    let w = world();
    let mut sys = Double::new(w.base.clone());
    sys.present_on_spawn = false;
    pin(&w.base, &w.data_path);
    let start = Instant::now();
    let deadline = Deadline::new(start, Some(Duration::from_millis(300)));
    // Pinned between discovery and the lock: the CLI re-reads it and polls the endpoint.
    let env = ensure_running(&discovery(DataState::BeforeFirstRun), &deadline, &sys).unwrap_err();
    assert_eq!(reason(&env), Some("launch_timeout"));
    assert_eq!(exit_code(&env), 5);
    assert_eq!(sys.spawns(), 1);
}

#[test]
fn before_first_run_already_running_after_lock() {
    // Another CLI's launch finished first run and the endpoint is up: no second spawn.
    let w = world();
    let mut sys = Double::new(w.base.clone());
    sys.present = AtomicBool::new(true);
    pin(&w.base, &w.data_path);
    let got = ensure_running(&discovery(DataState::BeforeFirstRun), &within(5_000), &sys);
    assert_eq!(got.unwrap().path(), w.data_path.as_path());
    assert_eq!(sys.spawns(), 0);
}

#[test]
fn before_first_run_pinned_to_a_missing_dir_is_refused() {
    let w = world();
    let sys = Double::new(w.base.clone());
    let base = w.base.clone();
    let gone = w.data_path.join("gone");
    *sys.on_spawn.lock().unwrap() = Some(Box::new(move || pin(&base, &gone)));
    let start = Instant::now();
    let deadline = Deadline::new(start, Some(Duration::from_millis(400)));
    let env = ensure_running(&discovery(DataState::BeforeFirstRun), &deadline, &sys).unwrap_err();
    // Mapped when the poll ends, not when the refusal is first seen.
    assert!(start.elapsed() >= Duration::from_millis(350));
    assert_eq!(reason(&env), Some("data_dir_missing"));
    assert_eq!(exit_code(&env), 9);
    assert_eq!(sys.spawns(), 1);
}

#[test]
fn before_first_run_refusal_mid_poll_keeps_polling() {
    // The wizard wrote paths.toml a moment before the data dir: the poll re-reads it and goes on.
    let w = world();
    let sys = Double::new(w.base.clone());
    let base = w.base.clone();
    let late = w.data_path.join("late");
    let late_dir = late.clone();
    *sys.on_spawn.lock().unwrap() = Some(Box::new(move || {
        pin(&base, &late);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            std::fs::create_dir(&late).unwrap();
        });
    }));
    let got = ensure_running(&discovery(DataState::BeforeFirstRun), &within(5_000), &sys);
    assert_eq!(got.unwrap().path(), late_dir.as_path());
    assert_eq!(sys.spawns(), 1);
}

#[test]
fn before_first_run_without_pinned_dir_parent_fails_without_creating_it() {
    let w = world();
    let mut base = w.base.clone();
    let elsewhere = w.data_path.join("no-such-home");
    base.home = elsewhere.clone();
    base.local_app_data = Some(elsewhere.join("AppData").join("Local"));
    let sys = Double::new(base.clone());
    let env =
        ensure_running(&discovery(DataState::BeforeFirstRun), &within(5_000), &sys).unwrap_err();
    assert_eq!(reason(&env), Some("not_running"));
    assert_eq!(exit_code(&env), 5);
    assert_eq!(sys.spawns(), 0);
    assert!(!elsewhere.exists());
}

#[test]
fn envelopes_have_no_request_id() {
    for env in [launch_timeout(), no_gui_session(), first_run()] {
        assert_eq!(env.request_id, None);
        assert_eq!(env.status, Status::Failed);
    }
}

#[test]
fn blocked_by_job_envelope_verbatim() {
    let env = launch_failed(&LaunchError::BlockedByJob);
    assert_eq!(env.status, Status::Failed);
    assert_eq!(env.request_id, None);
    assert_eq!(
        env.error.as_ref().map(|e| e.code),
        Some(ErrorCode::Unreachable)
    );
    assert_eq!(reason(&env), Some("launch_blocked_by_job"));
    assert_eq!(
        message(&env),
        "start atlas-duck from the desktop or enable autostart"
    );
    assert!(retryable(&env));
    assert_eq!(exit_code(&env), 5);
    // Every other launch failure stays `not_running`.
    for e in [
        LaunchError::InvalidArgument,
        LaunchError::ChildFailed(1),
        LaunchError::Unsupported,
    ] {
        assert_eq!(reason(&launch_failed(&e)), Some("not_running"), "{e:?}");
    }
}
