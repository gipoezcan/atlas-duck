use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_duck_ipc::client::{ConnectError, IpcClient};
use atlas_duck_ipc::proto::AgentNameSource;

use super::*;
use crate::argv::{Command, OutputMode};
use crate::discover;
use crate::exit::exit_for;
use crate::interrupt::{BoxFuture, Interrupts};
use crate::test_support::{Fake, Mode, Running, TestConnector, local, serve};

const KEYS: [&str; 15] = [
    "cli_version",
    "build_id",
    "install_mode",
    "app_path",
    "app_path_found",
    "on_path",
    "endpoint",
    "endpoint_exists",
    "data_dir",
    "data_dir_local",
    "data_dir_reason",
    "keyring_local",
    "job_blocks_breakaway",
    "wsl",
    "wsl_warning",
];

struct FakeSys {
    wsl: Option<bool>,
    pinned: Option<PathBuf>,
}

impl FakeSys {
    fn new() -> FakeSys {
        FakeSys {
            wsl: None,
            pinned: None,
        }
    }
}

impl DoctorSys for FakeSys {
    fn env(&self, _key: &str) -> Option<OsString> {
        None
    }
    fn exe(&self) -> Option<PathBuf> {
        None
    }
    fn pinned_data_dir(&self, _host: &str) -> Option<PathBuf> {
        self.pinned.clone()
    }
    fn endpoint(&self, _data: &LocalDataDir, _host: &str) -> Option<String> {
        Some("endpoint-location".to_owned())
    }
    fn endpoint_present(&self, _data: &LocalDataDir, _host: &str) -> bool {
        true
    }
    fn keyring_local(&self) -> Option<bool> {
        None
    }
    fn job_blocks_breakaway(&self) -> Option<bool> {
        None
    }
    fn wsl(&self) -> Option<bool> {
        self.wsl
    }
}

fn opts() -> GlobalOpts {
    GlobalOpts {
        agent: None,
        agent_source: AgentNameSource::None,
        reason: None,
        timeout: None,
        instance: None,
        output: OutputMode::Json,
        help: false,
    }
}

fn within(ms: u64) -> Deadline {
    Deadline::new(Instant::now(), Some(Duration::from_millis(ms)))
}

fn discovery(data: DataState, app: AppLocation) -> Discovery {
    Discovery {
        host: "host".to_owned(),
        data,
        app,
    }
}

/// Reaches the app through `inner` but answers `discover` with its own `Discovery`.
struct Wrapped {
    inner: TestConnector,
    discovery: Discovery,
}

impl Connector for Wrapped {
    fn discover(&self) -> Discovery {
        self.discovery.clone()
    }
    fn launch_sys(&self) -> Arc<dyn LaunchSys + Send> {
        self.inner.launch_sys()
    }
    fn connect<'a>(
        &'a self,
        ctx: &'a atlas_duck_ipc::client::ClientContext,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<IpcClient, ConnectError>> {
        self.inner.connect(ctx, deadline)
    }
    fn interrupts(&self) -> Box<dyn Interrupts> {
        self.inner.interrupts()
    }
    fn notice(&self, request_id: &str, params_sha256: Option<&str>) {
        self.inner.notice(request_id, params_sha256);
    }
}

fn data_obj(env: &Envelope) -> &Map<String, Value> {
    match env.data.as_ref().and_then(Value::as_object) {
        Some(m) => m,
        None => panic!("no data object: {env:?}"),
    }
}

fn refused(reason: &str) -> DataState {
    DataState::Refused(Box::new(discover::refusal(reason)))
}

#[test]
fn doctor_local_fields_shape() {
    let tmp = tempfile::tempdir().unwrap();
    let d = discovery(
        DataState::Local(local(tmp.path())),
        AppLocation::Found(tmp.path().join("atlas-duck-app")),
    );
    let m = local_checks(&d, &FakeSys::new());
    let mut keys: Vec<&str> = m.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut want = KEYS.to_vec();
    want.sort_unstable();
    assert_eq!(keys, want);
    assert_eq!(m["cli_version"], json!(APP_VERSION));
    assert_eq!(m["build_id"], json!(BUILD_ID));
    assert!(m["install_mode"].is_string());
    assert!(m["app_path"].is_string());
    assert_eq!(m["app_path_found"], json!(true));
    assert_eq!(m["on_path"], json!(false));
    assert_eq!(m["endpoint"], json!("endpoint-location"));
    assert_eq!(m["endpoint_exists"], json!(true));
    assert!(m["data_dir"].is_string());
    assert_eq!(m["data_dir_local"], json!(true));
    assert_eq!(m["data_dir_reason"], Value::Null);
    assert_eq!(m["keyring_local"], Value::Null);
    assert_eq!(m["job_blocks_breakaway"], Value::Null);
    assert_eq!(m["wsl"], Value::Null);
    // wsl false: no warning; wsl true: the §4.7 text, verbatim.
    let mut sys = FakeSys::new();
    sys.wsl = Some(false);
    let m = local_checks(&d, &sys);
    assert_eq!(m["wsl"], json!(false));
    assert_eq!(m["wsl_warning"], Value::Null);
    sys.wsl = Some(true);
    let m = local_checks(&d, &sys);
    assert_eq!(m["wsl"], json!(true));
    assert_eq!(m["wsl_warning"], json!(WSL_WARNING));
    assert_eq!(
        WSL_WARNING,
        "running inside WSL: call the Windows `atlas-duck.exe` through interop and do not install the Linux package here"
    );
}

#[test]
fn local_fields_before_first_run_and_refused() {
    let first = discovery(DataState::BeforeFirstRun, AppLocation::NotFound);
    let m = local_checks(&first, &FakeSys::new());
    assert_eq!(m["app_path"], Value::Null);
    assert_eq!(m["app_path_found"], json!(false));
    assert_eq!(m["install_mode"], json!("dev"));
    assert_eq!(m["endpoint"], Value::Null);
    assert_eq!(m["endpoint_exists"], json!(false));
    assert_eq!(m["data_dir"], Value::Null);
    assert_eq!(m["data_dir_local"], Value::Null);
    assert_eq!(m["data_dir_reason"], Value::Null);

    let mut sys = FakeSys::new();
    sys.pinned = Some(PathBuf::from("/pinned/data"));
    for (reason, local) in [
        ("data_dir_missing", Value::Null),
        ("data_dir_not_local", json!(false)),
        ("paths_unreadable", Value::Null),
        ("data_dir_unusable", Value::Null),
    ] {
        let d = discovery(refused(reason), AppLocation::NotFound);
        let m = local_checks(&d, &sys);
        assert_eq!(m["data_dir_reason"], json!(reason));
        assert_eq!(m["data_dir_local"], local, "{reason}");
        assert_eq!(m["data_dir"], json!("/pinned/data"), "{reason}");
        assert_eq!(m["endpoint"], Value::Null);
        assert_eq!(m["endpoint_exists"], json!(false));
    }
}

#[tokio::test]
async fn doctor_runs_without_app() {
    // Refused data dir: local checks only, no connect and no launch.
    let c = Wrapped {
        inner: TestConnector::failing(|| ConnectError::ServerIdentity),
        discovery: discovery(refused("data_dir_missing"), AppLocation::NotFound),
    };
    let env = execute_with(&opts(), &within(2_000), &c, &FakeSys::new()).await;
    assert_eq!(env.status, Status::Succeeded);
    assert_eq!(exit_for(&Command::Doctor, &env), 0);
    assert_eq!(c.inner.connect_count(), 0);
    let data = data_obj(&env);
    assert_eq!(data["app"], Value::Null);
    assert_eq!(
        data["app_unavailable"],
        json!({"code": "not_configured", "reason": "data_dir_missing"})
    );
    assert_eq!(data["local"]["data_dir_reason"], json!("data_dir_missing"));
}

#[tokio::test]
async fn doctor_reports_app_unreachable() {
    let tmp = tempfile::tempdir().unwrap();
    let c = Wrapped {
        inner: TestConnector::failing(|| ConnectError::NotRunning),
        discovery: discovery(DataState::Local(local(tmp.path())), AppLocation::NotFound),
    };
    let env = execute_with(&opts(), &within(2_000), &c, &FakeSys::new()).await;
    assert_eq!(env.status, Status::Succeeded);
    assert_eq!(exit_for(&Command::Doctor, &env), 0);
    let data = data_obj(&env);
    assert_eq!(data["app"], Value::Null);
    assert_eq!(data["app_unavailable"]["code"], json!("unreachable"));
    assert_eq!(data["app_unavailable"]["reason"], json!("not_running"));
    assert!(data["local"].is_object());
}

#[tokio::test]
async fn doctor_passes_the_apps_answer_through() {
    let fake = Arc::new(Fake::new());
    let running: Running = serve(&fake).await;
    let c = Wrapped {
        inner: TestConnector::new(running.data.clone(), Mode::Server(running.location.clone())),
        discovery: discovery(
            DataState::Local(running.data.clone()),
            AppLocation::NotFound,
        ),
    };
    let env = execute_with(&opts(), &within(5_000), &c, &FakeSys::new()).await;
    assert_eq!(exit_for(&Command::Doctor, &env), 0);
    let data = data_obj(&env);
    assert_eq!(data["app"], json!({"method": "doctor"}));
    assert_eq!(data["app_unavailable"], Value::Null);
    running.stop().await;
}

#[test]
fn merge_reports_a_failed_app_answer() {
    let env = Envelope::failed(ErrorCode::Busy, true, "busy");
    let merged = merge(Map::new(), Err(Box::new(env)));
    let data = data_obj(&merged);
    assert_eq!(data["app"], Value::Null);
    assert_eq!(
        data["app_unavailable"],
        json!({"code": "busy", "reason": null})
    );
}

#[test]
fn install_mode_table() {
    let p = Path::new;
    let none: Option<&OsStr> = None;
    let lad = Some(p(r"C:\Users\x\AppData\Local"));
    let win = |app: &str, lad: Option<&Path>| install_mode(Os::Windows, Some(p(app)), none, lad);
    assert_eq!(
        win(
            r"C:\Users\x\AppData\Local\Programs\atlas-duck\atlas-duck-app.exe",
            lad
        ),
        "windows_per_user"
    );
    // The verbatim prefix `canonicalize` adds does not matter.
    assert_eq!(
        win(
            r"\\?\C:\Users\x\AppData\Local\Programs\atlas-duck\a.exe",
            lad
        ),
        "windows_per_user"
    );
    assert_eq!(
        win(r"C:\Program Files\atlas-duck\atlas-duck-app.exe", lad),
        "windows_per_machine"
    );
    assert_eq!(
        win(r"C:\Program Files (x86)\atlas-duck\a.exe", None),
        "windows_per_machine"
    );
    assert_eq!(win(r"C:\src\target\debug\a.exe", lad), "dev");

    let mac = |app: &str| install_mode(Os::Macos, Some(p(app)), none, None);
    assert_eq!(
        mac("/Applications/atlas-duck.app/Contents/MacOS/atlas-duck-app"),
        "macos_bundle"
    );
    assert_eq!(mac("/Users/x/src/target/debug/a"), "dev");

    let image = OsStr::new("/home/x/atlas-duck.AppImage");
    let lin = |app: &str, image: Option<&OsStr>| install_mode(Os::Linux, Some(p(app)), image, None);
    assert_eq!(lin("/home/x/atlas-duck.AppImage", Some(image)), "appimage");
    // $APPIMAGE naming some other file does not make this one an AppImage.
    assert_eq!(lin("/usr/bin/atlas-duck-app", Some(image)), "linux_package");
    assert_eq!(lin("/usr/bin/atlas-duck-app", None), "linux_package");
    assert_eq!(lin("/opt/atlas-duck/atlas-duck-app", None), "linux_package");
    assert_eq!(lin("/usr/binx/a", None), "dev");
    assert_eq!(lin("/home/x/a", None), "dev");
    assert_eq!(install_mode(Os::Linux, None, none, None), "dev");
}

#[test]
fn on_path_checks_dir_and_executable() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("bin");
    let other = tmp.path().join("other");
    std::fs::create_dir(&bin).unwrap();
    std::fs::create_dir(&other).unwrap();
    let exe = bin.join(CLI_FILE_NAME);
    std::fs::write(&exe, b"x").unwrap();
    let exe = exe.canonicalize().unwrap();

    let with = std::env::join_paths([other.clone(), bin.clone()]).unwrap();
    assert!(on_path(Some(&with), Some(&exe)));
    let without = std::env::join_paths([other.clone()]).unwrap();
    assert!(!on_path(Some(&without), Some(&exe)));
    assert!(!on_path(None, Some(&exe)));
    assert!(!on_path(Some(&with), None));
    // A relative entry is the working directory, never an install.
    let relative = std::env::join_paths(["bin"]).unwrap();
    assert!(!on_path(Some(&relative), Some(&exe)));
}

#[cfg(unix)]
#[test]
fn on_path_follows_a_symlink_to_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("app");
    let links = tmp.path().join("links");
    std::fs::create_dir(&real).unwrap();
    std::fs::create_dir(&links).unwrap();
    let exe = real.join("atlas-duck-app");
    std::fs::write(&exe, b"x").unwrap();
    std::os::unix::fs::symlink(&exe, links.join(CLI_FILE_NAME)).unwrap();
    let exe = exe.canonicalize().unwrap();
    let path = std::env::join_paths([links]).unwrap();
    assert!(on_path(Some(&path), Some(&exe)));
}

#[cfg(unix)]
#[test]
fn keyring_local_follows_xdg_data_home() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg");
    // A local disk (the NFS case is Task 24's ignored test). Linux also checks the passwd-home
    // variant, which is local on any CI runner.
    assert_eq!(keyring_local_for(Some(xdg.into_os_string())), Some(true));
}

#[test]
fn doctor_output_has_no_url_or_user() {
    let tmp = tempfile::tempdir().unwrap();
    let d = discovery(
        DataState::Local(local(tmp.path())),
        AppLocation::Found(tmp.path().join("atlas-duck-app")),
    );
    let mut sys = FakeSys::new();
    sys.wsl = Some(true);
    let local = serde_json::to_string(&local_checks(&d, &sys)).unwrap();
    assert!(!local.contains("://"), "{local}");
    assert!(!local.contains("os_user"), "{local}");
    // What the app says passes through unchanged: the CLI adds nothing of its own to it.
    let app = json!({"x": "https://x", "instances": {}});
    let merged = merge(local_checks(&d, &sys), Ok(app.clone()));
    let data = data_obj(&merged);
    assert_eq!(data["app"], app);
    assert!(
        !serde_json::to_string(&data["local"])
            .unwrap()
            .contains("://")
    );
}
