//! The `cli_flows` harness (§13 I-03 "headless scripted approver"; PD-01, PD-02): a `World` is one
//! test home with a real store provisioned in the wizard's order, mock Atlassian servers, and the
//! real `atlas-duck` / `atlas-duck-app` binaries spawned against it.
//!
//! - The test process never sets `ATLAS_DUCK_TEST_HOME` (process-global, `set_var` is unsafe and
//!   tests run in parallel): it builds the `BaseDirs` PD-01's override produces by hand, and only
//!   the spawned binaries receive the variable.
//! - Every test that spawns a binary starts with [`opted_in`]: without `ATLAS_DUCK_CLI_FLOWS=1`
//!   it prints a `skipped:` line and returns (CI sets the variable, Task 26). Provisioning
//!   (`World::new`, `provision_store`, `audit_records`) is in-process and needs no opt-in; with
//!   the OS keychain (CI only) its keystore calls go to an `atlas-duck-app __test-os-keystore`
//!   process.
//! - A `World` must be used from a multi-thread tokio runtime (the mock servers keep serving
//!   while a test awaits a child).

#![allow(dead_code)]

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_duck_app_lib::compose::{self, CoreInputs};
use atlas_duck_app_lib::diag::LOG_DIR_NAME;
use atlas_duck_app_lib::testing::control::{
    CONTROL_DIR, ENV_NAMES_FILE, PID_FILE, QUIT_FILE, REFUSED_FILE,
};
use atlas_duck_app_lib::testing::os_keystore_proxy::{self, ProxyKeyStore};
use atlas_duck_app_lib::testing::provision;
use atlas_duck_atlassian::testing::MockDc;
use atlas_duck_atlassian::testing::fixtures::{CONFLUENCE_8_5_VERSION, JIRA_9_12_VERSION};
use atlas_duck_audit::lock::{InstanceLock, LockError};
use atlas_duck_audit::{
    EntryName, EventType, FirstRunInput, KeyStore, OpenConfig, SystemClock, create_new_store,
    new_ids,
};
use atlas_duck_core::proxy::ProxySetting;
use atlas_duck_core::testing::StubConfirmer;
use atlas_duck_core::testing::capture::NullUi;
use atlas_duck_core::{AddInstance, Confirm, ShutdownReason};
use atlas_duck_ipc::envelope::Envelope;
use atlas_duck_ipc::paths::{
    BaseDirs, DataDirResolution, ENDPOINT_FILE, LocalDataDir, PINNED_SCHEMA_VERSION, PinnedPaths,
    check_data_dir, cli_file, host_name, paths_file, write_pinned,
};
use atlas_duck_registry::Product;
use secrecy::SecretString;
use serde_json::Value;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The variable CI sets to run the tests that spawn the real binaries.
pub const ENV_OPT_IN: &str = "ATLAS_DUCK_CLI_FLOWS";
/// The test home the spawned binaries read (PD-01).
pub const ENV_TEST_HOME: &str = "ATLAS_DUCK_TEST_HOME";
/// The file keystore directory the spawned binaries read (PD-02).
pub const ENV_TEST_KEYSTORE: &str = "ATLAS_DUCK_TEST_KEYSTORE";

pub const CLI_EXE: &str = env!("CARGO_BIN_EXE_atlas-duck");
pub const APP_EXE: &str = env!("CARGO_BIN_EXE_atlas-duck-app");
pub const WORKER_EXE: &str = env!("CARGO_BIN_EXE_atlas-duck-sandbox");

/// The PAT every provisioned instance stores. A flow that searches output, logs and the audit
/// store for it proves the token never leaves the keychain (I-20).
pub const PAT_CANARY: &str = "PATCANARY-5d1c0a62-8f3b-4c1e-9b7a-2e64d0f9a381";

const PASSPHRASE: &str = "correct horse battery";
/// How long the app may take to publish its endpoint after the spawn.
const APP_START_WAIT: Duration = Duration::from_secs(30);
/// PD-38: quit takes at most the 75 s outer bound plus 12 s.
const QUIT_WAIT: Duration = Duration::from_secs(100);
/// Drop: the quit file, then a hard kill after this long.
const DROP_QUIT_WAIT: Duration = Duration::from_secs(10);
const CLI_TIMEOUT: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_millis(100);

// ---- opt-in ----------------------------------------------------------------------------------

/// True when `value` (the content of [`ENV_OPT_IN`]) is `1`.
pub fn opt_in_value(value: Option<&str>) -> bool {
    value == Some("1")
}

/// The skip line of a test that did not run.
pub fn skip_line(test: &str) -> String {
    format!("skipped: {test} spawns the real binaries; set {ENV_OPT_IN}=1")
}

/// Whether the test may spawn the real binaries; prints the skip line when not.
pub fn opted_in(test: &str) -> bool {
    let on = opt_in_value(std::env::var(ENV_OPT_IN).ok().as_deref());
    if !on {
        println!("{}", skip_line(test));
    }
    on
}

/// `os_keychain_smoke` runs only on CI (it writes real keychain entries).
pub fn os_keychain_allowed(ci: Option<&str>) -> bool {
    ci == Some("true")
}

/// Linux: the app needs a display (the runner script provides one, Task 26).
pub fn display_missing(lookup: &dyn Fn(&str) -> Option<OsString>) -> bool {
    lookup("DISPLAY").is_none() && lookup("WAYLAND_DISPLAY").is_none()
}

// ---- environment -----------------------------------------------------------------------------

/// What a spawned binary inherits from the test process (when present).
const PASS_THROUGH: &[&str] = &[
    "PATH",
    "SystemRoot",
    "TEMP",
    "TMP",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
];

/// The whole environment of a spawned binary (it runs after `env_clear`): the test home, the
/// keystore directory (file keystore only), the pass-through names that exist, then the
/// per-test extras (which win).
pub fn child_env(
    lookup: &dyn Fn(&str) -> Option<OsString>,
    home: &Path,
    keystore: Option<&Path>,
    extras: &[(String, String)],
) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = vec![(ENV_TEST_HOME.into(), home.into())];
    if let Some(dir) = keystore {
        env.push((ENV_TEST_KEYSTORE.into(), dir.into()));
    }
    for name in PASS_THROUGH {
        if let Some(value) = lookup(name) {
            env.push(((*name).into(), value));
        }
    }
    for (k, v) in extras {
        env.retain(|(name, _)| name != OsString::from(k).as_os_str());
        env.push((k.into(), v.into()));
    }
    env
}

// ---- parsers of what the binaries write ------------------------------------------------------

/// The one envelope of a `--output json` run, `None` when stdout is anything else.
pub fn parse_envelope(stdout: &str) -> Option<Envelope> {
    serde_json::from_str(stdout.trim()).ok()
}

/// The `refused` control file: `<n>` or `none`.
pub fn parse_refused(text: &str) -> Result<Option<u64>> {
    let t = text.trim();
    if t == "none" {
        return Ok(None);
    }
    Ok(Some(t.parse::<u64>()?))
}

/// `env-names.json`: a JSON array of names.
pub fn parse_env_names(bytes: &[u8]) -> Result<Vec<String>> {
    Ok(serde_json::from_slice(bytes)?)
}

/// The `instances` rows of an `instances` envelope (`data.instances`).
pub fn instance_rows(env: &Envelope) -> Vec<Value> {
    env.data
        .as_ref()
        .and_then(|d| d.get("instances"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The M2 `os_keystore.rs` convention for ids that `create_new_store` accepts and a sweep of
/// leftovers can match as `atlas-duck/7e570000*`: `7e570000` + the first 24 hex digits of `hex`.
pub fn test_install_id(hex: &str) -> Option<String> {
    let tail = hex.get(..24)?;
    Some(format!("7e570000{tail}"))
}

fn short_err(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}

// ---- the world -------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeystoreKind {
    /// PD-02: files under `<root>/keys`, handed to the binaries through `ATLAS_DUCK_TEST_KEYSTORE`.
    #[default]
    File,
    /// The real OS keychain under a `7e570000` test install id (CI only). The test process never
    /// touches it: every entry call goes to an `atlas-duck-app __test-os-keystore` process
    /// ([`os_keystore_proxy`]), so the entries the app reads were written by the app executable
    /// (a macOS keychain item trusts the executable that created it; any other one gets a
    /// confirmation prompt nobody answers on CI).
    Os,
}

#[derive(Debug, Clone, Default)]
pub struct WorldOpts {
    pub keystore: KeystoreKind,
    /// Extra variables for every spawned binary (they win over the pass-through).
    pub extra_env: Vec<(String, String)>,
    /// Runs the CLI and the app from a copy of the three binaries under `<root>/install` (M8
    /// Task 26): the CLI finds the app next to itself and the app finds its worker next to itself
    /// (`canonical_worker`), so a test can replace the copied worker without touching the build
    /// output.
    pub copy_install: bool,
}

impl WorldOpts {
    pub fn with_env(mut self, name: &str, value: &str) -> WorldOpts {
        self.extra_env.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn with_copy_install(mut self) -> WorldOpts {
        self.copy_install = true;
        self
    }
}

/// The binaries of a copied install dir ([`WorldOpts::copy_install`]).
#[derive(Debug, Clone)]
struct Install {
    dir: PathBuf,
    cli: PathBuf,
    app: PathBuf,
    worker: PathBuf,
}

/// Copies the CLI, the app and the sandbox worker into `<root>/install` (next to each other, as in
/// a real install). On Windows every DLL next to the app goes along.
fn copy_install(root: &Path) -> io::Result<Install> {
    let dir = root.join("install");
    create_private_dir(&dir)?;
    let copy = |from: &Path| -> io::Result<PathBuf> {
        let name = from
            .file_name()
            .ok_or_else(|| io::Error::other("a binary path has no file name"))?;
        let to = dir.join(name);
        fs::copy(from, &to)?;
        Ok(to)
    };
    let cli = copy(Path::new(CLI_EXE))?;
    let app = copy(Path::new(APP_EXE))?;
    let worker = copy(Path::new(WORKER_EXE))?;
    #[cfg(windows)]
    if let Some(built) = Path::new(APP_EXE).parent() {
        for entry in fs::read_dir(built)?.flatten() {
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("dll"))
            {
                copy(&path)?;
            }
        }
    }
    Ok(Install {
        dir,
        cli,
        app,
        worker,
    })
}

/// One test home: its pinned file, data and config dirs, keystore, mocks and spawned processes.
pub struct World {
    root: tempfile::TempDir,
    host: String,
    base: BaseDirs,
    data: PathBuf,
    config: PathBuf,
    keys_dir: PathBuf,
    install_id: String,
    opts: WorldOpts,
    install: Option<Install>,
    mocks: Vec<(String, MockDc)>,
    instance_ids: Vec<String>,
}

fn new_root() -> io::Result<tempfile::TempDir> {
    let mut b = tempfile::Builder::new();
    b.prefix("adt-");
    // Unix socket paths are short (104 bytes on macOS): a short root under /tmp.
    #[cfg(unix)]
    {
        b.tempdir_in("/tmp")
    }
    #[cfg(not(unix))]
    {
        b.tempdir()
    }
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
}

impl World {
    /// A test home with the pinned file, the data and config dirs and no store yet. Fails on
    /// Linux without a display, and for the OS keychain outside CI.
    pub fn new(opts: WorldOpts) -> Result<World> {
        #[cfg(target_os = "linux")]
        if display_missing(&|n| std::env::var_os(n)) {
            return Err("cli_flows needs a display: set DISPLAY or WAYLAND_DISPLAY \
                        (ci/cli-flows-linux.sh provides one)"
                .into());
        }
        if opts.keystore == KeystoreKind::Os
            && !os_keychain_allowed(std::env::var("CI").ok().as_deref())
        {
            return Err("the OS keychain flows run only with CI=true".into());
        }
        let root = new_root()?;
        #[cfg(unix)]
        let root_path = root.path().canonicalize()?;
        #[cfg(not(unix))]
        let root_path = root.path().to_path_buf();
        // Exactly what PD-01's override produces.
        let base = BaseDirs {
            home: root_path.clone(),
            local_app_data: Some(root_path.join("AppData").join("Local")),
            roaming_app_data: Some(root_path.join("AppData").join("Roaming")),
        };
        let host = host_name()?;
        let (_, chain) = new_ids().map_err(short_err)?;
        let install_id = test_install_id(&chain).ok_or("short random id")?;
        let data = root_path.join("data");
        let config = root_path.join("config");
        // M6 contract: the data dir exists before paths.toml is written.
        create_private_dir(&data)?;
        create_private_dir(&config)?;
        let install = if opts.copy_install {
            Some(copy_install(&root_path)?)
        } else {
            None
        };
        let world = World {
            keys_dir: root_path.join("keys"),
            root,
            host,
            base,
            data,
            config,
            install_id,
            opts,
            install,
            mocks: Vec::new(),
            instance_ids: Vec::new(),
        };
        write_pinned(
            &world.pinned_file(),
            &PinnedPaths {
                schema_version: PINNED_SCHEMA_VERSION,
                data_dir: world.data.clone(),
                config_dir: world.config.clone(),
                install_id: Some(world.install_id.clone()),
            },
        )
        .map_err(short_err)?;
        Ok(world)
    }

    /// The canonical test home (on macOS `/private/tmp/..`, not `/tmp/..`): the one string the
    /// pinned file, the child environment and every child's `current_dir` are built from.
    pub fn root(&self) -> &Path {
        &self.base.home
    }
    pub fn data_dir(&self) -> &Path {
        &self.data
    }
    pub fn config_dir(&self) -> &Path {
        &self.config
    }
    pub fn keys_dir(&self) -> &Path {
        &self.keys_dir
    }
    pub fn install_id(&self) -> &str {
        &self.install_id
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn base_dirs(&self) -> &BaseDirs {
        &self.base
    }
    /// This host's `paths.toml` under the test home.
    pub fn pinned_file(&self) -> PathBuf {
        paths_file(&self.base, &self.host)
    }
    /// This host's `cli.toml` under the test home.
    pub fn cli_toml(&self) -> PathBuf {
        cli_file(&self.base, &self.host)
    }
    pub fn control_dir(&self) -> PathBuf {
        self.data.join(CONTROL_DIR)
    }
    /// The copied install dir ([`WorldOpts::copy_install`]).
    pub fn install_dir(&self) -> Option<&Path> {
        self.install.as_ref().map(|i| i.dir.as_path())
    }
    /// The sandbox worker next to the copied app ([`WorldOpts::copy_install`]).
    pub fn installed_worker(&self) -> Option<&Path> {
        self.install.as_ref().map(|i| i.worker.as_path())
    }
    /// The `atlas-duck` every CLI run of this world starts: the copy, else the build output.
    fn cli_exe(&self) -> PathBuf {
        self.install
            .as_ref()
            .map_or_else(|| PathBuf::from(CLI_EXE), |i| i.cli.clone())
    }
    /// The `atlas-duck-app` this world starts: the copy, else the build output.
    fn app_exe(&self) -> PathBuf {
        self.install
            .as_ref()
            .map_or_else(|| PathBuf::from(APP_EXE), |i| i.app.clone())
    }
    /// The mock server of `alias` (provisioned instances only).
    pub fn mock(&self, alias: &str) -> Option<&MockDc> {
        self.mocks.iter().find(|(a, _)| a == alias).map(|(_, m)| m)
    }
    /// The instance ids provisioned so far (from the audit log).
    pub fn instance_ids(&self) -> &[String] {
        &self.instance_ids
    }

    fn local_data(&self) -> Result<LocalDataDir> {
        match check_data_dir(&self.data)? {
            DataDirResolution::Local(d) => Ok(d),
            _ => Err("the test data dir is not a local data dir".into()),
        }
    }

    fn keys(&self) -> Result<Arc<dyn KeyStore>> {
        match self.opts.keystore {
            KeystoreKind::File => Ok(Arc::new(provision(&self.keys_dir, &self.install_id)?)),
            KeystoreKind::Os => Ok(Arc::new(ProxyKeyStore::spawn(
                self.command(
                    self.app_exe(),
                    &[os_keystore_proxy::MARKER, &self.install_id],
                ),
                &self.install_id,
            )?)),
        }
    }

    /// The environment of every spawned binary.
    pub fn env(&self) -> Vec<(OsString, OsString)> {
        let keystore = match self.opts.keystore {
            KeystoreKind::File => Some(self.keys_dir.as_path()),
            KeystoreKind::Os => None,
        };
        child_env(
            &|n| std::env::var_os(n),
            &self.base.home,
            keystore,
            &self.opts.extra_env,
        )
    }

    fn command(&self, exe: impl AsRef<std::ffi::OsStr>, args: &[&str]) -> Command {
        let mut c = Command::new(exe);
        c.args(args).env_clear().current_dir(&self.base.home);
        for (k, v) in self.env() {
            c.env(k, v);
        }
        c
    }

    // ---- provisioning ------------------------------------------------------------------------

    /// The wizard's order (§2.5, M3 placement (6)): the instance lock, `create_new_store`, the
    /// core, then per instance a mock server, `add` (native confirmation through the stub) and
    /// `set_token` (the connection test runs against the mock), then `Core::shutdown(Quit)`
    /// and the store and the lock are released. The first instance is the default.
    pub async fn provision_store(&mut self, instances: &[(&str, Product)]) -> Result<()> {
        let data = self.local_data()?;
        let lock = InstanceLock::acquire(&data, &self.host).map_err(|e| e.to_string())?;
        let keys = self.keys()?;
        let cfg = OpenConfig::new(Arc::new(SystemClock::new()), keys.clone());
        let (_, chain_id) = new_ids().map_err(short_err)?;
        let store = create_new_store(
            &data,
            &lock,
            cfg,
            FirstRunInput {
                install_id: self.install_id.clone(),
                chain_id,
                passphrase: SecretString::from(PASSPHRASE.to_owned()),
                passphrase_confirm: SecretString::from(PASSPHRASE.to_owned()),
                archived_db: None,
            },
        )
        .map_err(short_err)?;
        let confirmer = Arc::new(StubConfirmer::new(Vec::new()));
        let core = compose::start_core(CoreInputs {
            store: store.clone(),
            keys,
            config_dir: self.config.clone(),
            pats_deleted: Vec::new(),
            ui: Arc::new(NullUi),
            confirmer: confirmer.clone(),
            tray_host: None,
            scripts: Default::default(),
        })
        .await?;

        let outcome = self.add_instances(&core, &confirmer, instances).await;
        // Also after a failed add: the entries written so far must be swept by Drop.
        let ids = distinct_instance_ids(&store);
        // The shutdown path runs whatever happened above.
        core.shutdown(ShutdownReason::Quit).await;
        drop(core);
        store.shutdown();
        drop(lock);
        self.instance_ids = ids;
        let mocks = outcome?;
        self.mocks.extend(mocks);
        Ok(())
    }

    async fn add_instances(
        &self,
        core: &atlas_duck_core::Core,
        confirmer: &StubConfirmer,
        instances: &[(&str, Product)],
    ) -> Result<Vec<(String, MockDc)>> {
        let mut mocks = Vec::new();
        for (i, (alias, product)) in instances.iter().enumerate() {
            let (atl, context, version) = match product {
                Product::Jira => (
                    atlas_duck_atlassian::Product::Jira,
                    "/jira",
                    JIRA_9_12_VERSION,
                ),
                Product::Confluence => (
                    atlas_duck_atlassian::Product::Confluence,
                    "/wiki",
                    CONFLUENCE_8_5_VERSION,
                ),
            };
            let mock = MockDc::start(atl, context).await;
            // `jira_myself` + `server_info` (or Confluence's equivalents): the connection test
            // and every approved write's stale check need them.
            mock.mount_fixture_set(version).await;
            confirmer.push(Confirm::Ok);
            core.instances()
                .add(AddInstance {
                    alias: (*alias).to_owned(),
                    product: *product,
                    base_url: mock.base_url(),
                    // Never the OS proxy: the mock is on localhost.
                    proxy: ProxySetting::Direct,
                    ca_pem: None,
                    is_default: i == 0,
                })
                .map_err(|e| format!("add {alias}: {e:?}"))?;
            core.instances()
                .set_token(alias, SecretString::from(PAT_CANARY.to_owned()), None)
                .await
                .map_err(|e| format!("set_token {alias}: {e:?}"))?;
            let state = core
                .instances()
                .list()
                .into_iter()
                .find(|v| v.alias == *alias)
                .map(|v| v.state);
            if state != Some("ok") {
                return Err(format!("instance {alias} is {state:?} after set_token").into());
            }
            mocks.push(((*alias).to_owned(), mock));
        }
        Ok(mocks)
    }

    // ---- the real binaries -------------------------------------------------------------------

    /// Runs `atlas-duck <args>` to its end (at most two minutes): stdout, stderr, exit code and
    /// the envelope when stdout holds one. A cold start launches the app through the test home.
    pub async fn cli(&self, args: &[&str]) -> Result<CliRun> {
        let mut cmd = tokio::process::Command::from(self.command(self.cli_exe(), args));
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let child = cmd.spawn()?;
        let out = tokio::time::timeout(CLI_TIMEOUT, child.wait_with_output())
            .await
            .map_err(|_| format!("atlas-duck {args:?} did not end within {CLI_TIMEOUT:?}"))??;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        Ok(CliRun {
            envelope: parse_envelope(&stdout),
            exit: out.status.code().unwrap_or(-1),
            stdout,
            stderr,
        })
    }

    /// `atlas-duck <args>` still running, with piped stdout and stderr and no stdin (kill tests).
    /// The child is killed when dropped.
    pub fn cli_spawn(&self, args: &[&str]) -> Result<tokio::process::Child> {
        let mut cmd = tokio::process::Command::from(self.command(self.cli_exe(), args));
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        Ok(cmd.spawn()?)
    }

    /// `atlas-duck <args>` (normally `["mcp"]`) still running with piped stdin, stdout and stderr,
    /// for a stdio MCP driver. `extra_env` is added for this child only. The child is killed when
    /// dropped.
    pub fn mcp_spawn(
        &self,
        args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> Result<tokio::process::Child> {
        let mut command = self.command(self.cli_exe(), args);
        for (k, v) in extra_env {
            command.env(k, v);
        }
        let mut cmd = tokio::process::Command::from(command);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        Ok(cmd.spawn()?)
    }

    /// Spawns `atlas-duck-app --background` and waits (30 s) for `<data>/endpoint`.
    pub async fn start_app(&self) -> Result<AppProc> {
        self.start_app_with_env(&[]).await
    }

    /// [`World::start_app`] with `env` added to the app process for this one start (the test-only
    /// `ATLAS_DUCK_TEST_SERVER_BUILD_ID` is read from the app's own environment at start only).
    pub async fn start_app_with_env(&self, env: &[(&str, &str)]) -> Result<AppProc> {
        let mut cmd = self.command(self.app_exe(), &["--background"]);
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // A leftover endpoint (a killed app) would read as "started": remove it, and the old
        // pid record, before the spawn. Only inside this world's own data dir.
        let endpoint = self.data.join(ENDPOINT_FILE);
        let _ = fs::remove_file(&endpoint);
        let _ = fs::remove_file(self.control_dir().join(PID_FILE));
        let mut child = cmd.spawn()?;
        let start = Instant::now();
        loop {
            // First: a startup death must fail fast with its status, whatever files exist.
            if let Some(status) = child.try_wait()? {
                return Err(
                    format!("the app ended before it published its endpoint: {status}").into(),
                );
            }
            if endpoint.try_exists()? {
                break;
            }
            if start.elapsed() > APP_START_WAIT {
                let _ = child.kill();
                let _ = child.wait();
                return Err("the app published no endpoint within 30 s".into());
            }
            tokio::time::sleep(POLL).await;
        }
        Ok(AppProc {
            data: self.data.clone(),
            child: Some(child),
        })
    }

    /// Writes a file of the control dir (`delay-startup-ms` before the start, `quit`, ...).
    pub fn write_control(&self, name: &str, content: &str) -> io::Result<()> {
        write_control_file(&self.data, name, content)
    }

    /// True while some process holds `instance.lock` (the app of this home, however started).
    /// The probe takes the lock for a moment when it is free, so an app that is starting at that
    /// instant can lose it and refuse to start: use it only after the CLI run that started the
    /// app has exited (same for [`World::wait_app_gone`] and `lock_free_within`).
    pub fn app_running(&self) -> Result<bool> {
        let data = self.local_data()?;
        Ok(InstanceLock::acquire(&data, &self.host).is_err())
    }

    /// Waits (100 s) until no process holds `instance.lock`: the app, however it was started,
    /// is gone.
    pub async fn wait_app_gone(&self) -> Result<()> {
        let start = Instant::now();
        loop {
            if !self.app_running()? {
                return Ok(());
            }
            if start.elapsed() > QUIT_WAIT {
                return Err("the app still holds instance.lock after 100 s".into());
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// The quit path of the test build: the `quit` control file, then waits until the app is
    /// gone.
    pub async fn quit_app(&self) -> Result<()> {
        self.write_control(QUIT_FILE, "")?;
        self.wait_app_gone().await
    }

    // ---- what the app wrote ------------------------------------------------------------------

    /// `env-names.json` of the running app (names only, I-20).
    pub fn env_names(&self) -> Result<Vec<String>> {
        parse_env_names(&fs::read(self.control_dir().join(ENV_NAMES_FILE))?)
    }

    /// The `refused` control file as it is now: `None` before the app wrote it,
    /// `Some(None)` for `none`, `Some(Some(n))` for a count.
    pub fn refused_now(&self) -> Result<Option<Option<u64>>> {
        match fs::read_to_string(self.control_dir().join(REFUSED_FILE)) {
            Ok(text) => Ok(Some(parse_refused(&text)?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Polls (the file is mirrored every 100 ms and written on change) until the file exists and
    /// `accept` holds for its content; `None` on timeout.
    pub async fn wait_refused(
        &self,
        timeout: Duration,
        accept: impl Fn(Option<u64>) -> bool,
    ) -> Result<Option<Option<u64>>> {
        let start = Instant::now();
        loop {
            if let Some(v) = self.refused_now()?
                && accept(v)
            {
                return Ok(Some(v));
            }
            if start.elapsed() > timeout {
                return Ok(None);
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// The first value the file shows (5 s). A test that needs an exact count uses
    /// [`World::wait_refused`] with a predicate.
    pub async fn refused(&self) -> Result<Option<u64>> {
        self.wait_refused(Duration::from_secs(5), |_| true)
            .await?
            .ok_or_else(|| "the refused control file did not appear within 5 s".into())
    }

    /// Every record of the audit log, in order, decrypted: reopens the store with the test
    /// keystore without startup verification (no `VERIFY` row is added). Needs the app gone.
    pub fn audit_records(&self) -> Result<Vec<(EventType, Value)>> {
        let data = self.local_data()?;
        let lock = InstanceLock::acquire(&data, &self.host)
            .map_err(|e| format!("the app still runs: {e}"))?;
        let mut cfg = OpenConfig::new(Arc::new(SystemClock::new()), self.keys()?);
        cfg.pinned_install_id = Some(self.install_id.clone());
        let store =
            atlas_duck_audit::testing::open_existing(&data, &lock, cfg).map_err(short_err)?;
        let out = (|| -> Result<Vec<(EventType, Value)>> {
            let mut headers = store
                .recent_headers(Duration::from_secs(24 * 3600))
                .map_err(short_err)?;
            headers.sort_by_key(|h| h.seq);
            headers
                .into_iter()
                .map(|h| {
                    let bytes = store.read_payload(h.seq).map_err(short_err)?;
                    Ok((h.event_type, serde_json::from_slice(&bytes)?))
                })
                .collect()
        })();
        store.shutdown();
        drop(lock);
        out
    }

    // ---- diagnostics -------------------------------------------------------------------------

    /// What a failed flow prints after the CLI run that failed (it probes `instance.lock` like
    /// [`World::app_running`]): the data dir listing, the app's diagnostic log, the lock holder
    /// and, on macOS, a one-second stack sample of an app that still runs (a hang shows where it
    /// waits). The cold-started app has no stderr to capture (the CLI launches it detached).
    pub fn diagnostics(&self) -> String {
        let mut out = format!("--- data dir {}\n", self.data.display());
        list_tree(&self.data, &self.data, 0, &mut out);
        let logs = self.data.join(LOG_DIR_NAME);
        let mut log_files: Vec<PathBuf> = fs::read_dir(&logs)
            .map(|rd| rd.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        log_files.sort();
        for file in log_files {
            match fs::read_to_string(&file) {
                Ok(text) => {
                    out.push_str(&format!("--- {}\n", file.display()));
                    push_tail(&text, 200, &mut out);
                }
                Err(e) => out.push_str(&format!("--- {}: {e}\n", file.display())),
            }
        }
        let holder = match self.local_data() {
            Ok(data) => match InstanceLock::acquire(&data, &self.host) {
                Ok(_) => {
                    out.push_str("--- instance.lock: free (no app runs)\n");
                    None
                }
                Err(LockError::Held(holder)) => {
                    let pid = holder.map(|h| h.pid);
                    out.push_str(&format!("--- instance.lock: held by pid {pid:?}\n"));
                    pid
                }
                Err(e) => {
                    out.push_str(&format!("--- instance.lock: {e}\n"));
                    None
                }
            },
            Err(e) => {
                out.push_str(&format!("--- data dir: {e}\n"));
                None
            }
        };
        #[cfg(target_os = "macos")]
        if let Some(pid) = holder {
            let file = self.root().join("app-sample.txt");
            let status = Command::new("/usr/bin/sample")
                .arg(pid.to_string())
                .arg("1")
                .arg("-file")
                .arg(&file)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            match fs::read_to_string(&file) {
                Ok(text) => {
                    out.push_str(&format!("--- sample {pid} 1\n"));
                    push_head(&text, 300, &mut out);
                }
                Err(e) => out.push_str(&format!("--- sample {pid} 1: {status:?} {e}\n")),
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = holder;
        out
    }

    // ---- drop --------------------------------------------------------------------------------

    /// Quits whatever app holds `instance.lock` (the control file; after 10 s a hard kill by the
    /// pid in the lock record, readable on Unix, and by the pid the app wrote to
    /// `test-control/pid`). Both pids come from this world's own records, never from a process
    /// name, and the kill only runs when the world's app ignored the quit file.
    fn stop_app_blocking(&self) {
        let Ok(data) = self.local_data() else { return };
        let pid = match InstanceLock::acquire(&data, &self.host) {
            Ok(_) => return,
            Err(LockError::Held(holder)) => holder.map(|h| h.pid),
            Err(_) => None,
        };
        let _ = write_control_file(&self.data, QUIT_FILE, "");
        if lock_free_within(&data, &self.host, DROP_QUIT_WAIT) {
            return;
        }
        let control_pid = fs::read_to_string(self.control_dir().join(PID_FILE))
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok());
        let mut killed = false;
        for p in [pid, control_pid].into_iter().flatten() {
            kill_pid(p);
            killed = true;
        }
        if killed {
            lock_free_within(&data, &self.host, Duration::from_secs(5));
        }
    }

    /// Removes this install's keychain entries (OS keychain runs only), through the app
    /// executable like every other entry call.
    fn delete_os_entries(&self) {
        let Ok(ks) = self.keys() else {
            return;
        };
        for e in [
            EntryName::Kek,
            EntryName::HeadAnchor,
            EntryName::FirstRetainedAnchor,
            EntryName::Canary,
        ] {
            let _ = ks.delete(&e);
        }
        for id in &self.instance_ids {
            let _ = ks.delete(&EntryName::Pat(id.clone()));
        }
    }
}

impl Drop for World {
    fn drop(&mut self) {
        self.stop_app_blocking();
        if self.opts.keystore == KeystoreKind::Os {
            self.delete_os_entries();
        }
        // The temp root goes with `root` (after this body): no app of this world is left
        // running in it unless the kill above failed.
    }
}

fn distinct_instance_ids(store: &atlas_duck_audit::Store) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for h in store
        .recent_headers(Duration::from_secs(24 * 3600))
        .unwrap_or_default()
    {
        if let Some(id) = h.instance_id
            && !ids.contains(&id)
        {
            ids.push(id);
        }
    }
    ids
}

/// One line per entry under `root` (relative path, and the size of a file), at most four levels.
fn list_tree(root: &Path, dir: &Path, depth: usize, out: &mut String) {
    let mut entries: Vec<fs::DirEntry> = match fs::read_dir(dir) {
        Ok(rd) => rd.flatten().collect(),
        Err(e) => {
            out.push_str(&format!("{}: {e}\n", dir.display()));
            return;
        }
    };
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        match entry.metadata() {
            Ok(md) if md.is_dir() => {
                out.push_str(&format!("{rel}/\n"));
                if depth < 3 {
                    list_tree(root, &path, depth + 1, out);
                }
            }
            Ok(md) => out.push_str(&format!("{rel} ({} bytes)\n", md.len())),
            Err(e) => out.push_str(&format!("{rel}: {e}\n")),
        }
    }
}

/// The last `n` lines of `text`.
fn push_tail(text: &str, n: usize, out: &mut String) {
    let lines: Vec<&str> = text.lines().collect();
    for line in &lines[lines.len().saturating_sub(n)..] {
        out.push_str(line);
        out.push('\n');
    }
}

/// The first `n` lines of `text`.
#[cfg(target_os = "macos")]
fn push_head(text: &str, n: usize, out: &mut String) {
    for line in text.lines().take(n) {
        out.push_str(line);
        out.push('\n');
    }
}

fn write_control_file(data: &Path, name: &str, content: &str) -> io::Result<()> {
    let dir = data.join(CONTROL_DIR);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(name), content)
}

/// True once `instance.lock` can be taken (and is released again at once). Like
/// [`World::app_running`], it can make an app that is starting lose the lock: after the CLI
/// run only.
fn lock_free_within(data: &LocalDataDir, host: &str, wait: Duration) -> bool {
    let start = Instant::now();
    loop {
        if InstanceLock::acquire(data, host).is_ok() {
            return true;
        }
        if start.elapsed() > wait {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

/// Best effort, by the pid in the test home's own lock record.
fn kill_pid(pid: u32) {
    if pid == 0 || pid == std::process::id() {
        return;
    }
    let pid = pid.to_string();
    #[cfg(windows)]
    let mut c = {
        let mut c = Command::new("taskkill");
        c.args(["/PID", &pid, "/T", "/F"]);
        c
    };
    #[cfg(not(windows))]
    let mut c = {
        let mut c = Command::new("kill");
        c.args(["-KILL", &pid]);
        c
    };
    let _ = c
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// The result of one `atlas-duck` run.
#[derive(Debug)]
pub struct CliRun {
    pub stdout: String,
    pub stderr: String,
    pub exit: i32,
    pub envelope: Option<Envelope>,
}

/// An app this test started with [`World::start_app`]. Dropping it quits it (control file, then a
/// hard kill after 10 s).
pub struct AppProc {
    data: PathBuf,
    child: Option<Child>,
}

impl AppProc {
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Ends the process at once (crash tests).
    pub fn kill_hard(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            child.kill()?;
            child.wait()?;
        }
        Ok(())
    }

    /// Waits (100 s) for the process to exit by itself (M6 T29: after a signal sent to it; M6 T32:
    /// after the Windows `WM_QUERYENDSESSION`).
    pub fn wait_exit(&mut self) -> Result<ExitStatus> {
        let Some(child) = self.child.as_mut() else {
            return Err("the app is not running".into());
        };
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                self.child = None;
                return Ok(status);
            }
            if start.elapsed() > QUIT_WAIT {
                return Err("the app did not exit within 100 s".into());
            }
            std::thread::sleep(POLL);
        }
    }

    /// Writes `test-control/quit` and waits (100 s) for the process to exit.
    pub fn quit(&mut self) -> Result<ExitStatus> {
        let Some(child) = self.child.as_mut() else {
            return Err("the app is not running".into());
        };
        write_control_file(&self.data, QUIT_FILE, "")?;
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                self.child = None;
                return Ok(status);
            }
            if start.elapsed() > QUIT_WAIT {
                return Err("the app did not exit within 100 s of the quit file".into());
            }
            std::thread::sleep(POLL);
        }
    }
}

impl Drop for AppProc {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        let _ = write_control_file(&self.data, QUIT_FILE, "");
        let start = Instant::now();
        while start.elapsed() < DROP_QUIT_WAIT {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(POLL);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_in_needs_exactly_one() {
        assert!(opt_in_value(Some("1")));
        for v in [None, Some(""), Some("0"), Some("true"), Some("yes")] {
            assert!(!opt_in_value(v), "{v:?}");
        }
        assert_eq!(
            skip_line("t"),
            "skipped: t spawns the real binaries; set ATLAS_DUCK_CLI_FLOWS=1"
        );
    }

    #[test]
    fn os_keychain_only_on_ci() {
        assert!(os_keychain_allowed(Some("true")));
        assert!(!os_keychain_allowed(Some("1")));
        assert!(!os_keychain_allowed(None));
    }

    #[test]
    fn display_is_missing_only_when_both_are_unset() {
        let none = |_: &str| None;
        let x11 = |n: &str| (n == "DISPLAY").then(|| OsString::from(":0"));
        let wayland = |n: &str| (n == "WAYLAND_DISPLAY").then(|| OsString::from("wayland-0"));
        assert!(display_missing(&none));
        assert!(!display_missing(&x11));
        assert!(!display_missing(&wayland));
    }

    fn names(env: &[(OsString, OsString)]) -> Vec<String> {
        env.iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn child_env_is_the_test_variables_plus_the_names_that_exist() {
        let lookup = |n: &str| match n {
            "PATH" => Some(OsString::from("/bin")),
            "DISPLAY" => Some(OsString::from(":0")),
            // Not on the list: never passed.
            "HOME" | "USERPROFILE" | "ATLAS_DUCK_AGENT" => Some(OsString::from("x")),
            _ => None,
        };
        let env = child_env(
            &lookup,
            Path::new("/tmp/adt-1"),
            Some(Path::new("/tmp/adt-1/keys")),
            &[],
        );
        assert_eq!(
            names(&env),
            [ENV_TEST_HOME, ENV_TEST_KEYSTORE, "PATH", "DISPLAY"]
        );
        // The OS keychain run hands over no keystore directory.
        let env = child_env(&lookup, Path::new("/tmp/adt-1"), None, &[]);
        assert_eq!(names(&env), [ENV_TEST_HOME, "PATH", "DISPLAY"]);
    }

    #[test]
    fn extras_win_over_everything_else() {
        let lookup = |n: &str| (n == "PATH").then(|| OsString::from("/bin"));
        let extras = vec![
            ("PATH".to_owned(), "/other".to_owned()),
            ("EXTRA".to_owned(), "1".to_owned()),
        ];
        let env = child_env(&lookup, Path::new("/h"), None, &extras);
        assert_eq!(names(&env), [ENV_TEST_HOME, "PATH", "EXTRA"]);
        assert_eq!(env[1].1, OsString::from("/other"));
    }

    #[test]
    fn refused_file_parser() -> Result<()> {
        assert_eq!(parse_refused("none")?, None);
        assert_eq!(parse_refused("0")?, Some(0));
        assert_eq!(parse_refused("12\n")?, Some(12));
        assert!(parse_refused("").is_err());
        assert!(parse_refused("-1").is_err());
        assert!(parse_refused("some").is_err());
        Ok(())
    }

    #[test]
    fn env_names_parser() -> Result<()> {
        assert_eq!(
            parse_env_names(br#"["PATH","ATLAS_DUCK_TEST_HOME"]"#)?,
            ["PATH", "ATLAS_DUCK_TEST_HOME"]
        );
        assert!(parse_env_names(br#"{"PATH":"x"}"#).is_err());
        assert!(parse_env_names(b"[1]").is_err());
        Ok(())
    }

    #[test]
    fn envelope_parser_takes_one_object_and_nothing_else() {
        let line = Envelope::failed(
            atlas_duck_ipc::envelope::ErrorCode::Internal,
            true,
            "not running",
        )
        .to_json_line();
        let env = parse_envelope(&line);
        assert!(env.is_some());
        assert_eq!(env.map(|e| e.request_id), Some(None));
        assert!(parse_envelope("").is_none());
        assert!(parse_envelope("Instances:\n  jira-main").is_none());
        assert!(parse_envelope("{}").is_none());
    }

    #[test]
    fn instance_rows_come_from_data_instances() {
        let mut env = Envelope::failed(atlas_duck_ipc::envelope::ErrorCode::Internal, true, "x");
        assert!(instance_rows(&env).is_empty());
        env.data = Some(serde_json::json!({
            "instances": [{"alias": "a", "product": "jira", "is_default": true, "state": "ok"}]
        }));
        let rows = instance_rows(&env);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["alias"], "a");
    }

    #[test]
    fn test_install_ids_follow_the_keystore_convention() {
        let id = test_install_id("0123456789abcdef0123456789abcdef");
        assert_eq!(id.as_deref(), Some("7e5700000123456789abcdef01234567"));
        assert_eq!(id.map(|i| i.len()), Some(32));
        assert_eq!(test_install_id("short"), None);
    }

    /// `World::new` pins this host's paths under its own root without touching the test
    /// process's environment (the file is what the spawned binaries read through PD-01).
    #[test]
    fn a_new_world_pins_its_paths_and_leaves_the_environment_alone() -> Result<()> {
        if cfg!(target_os = "linux") && display_missing(&|n| std::env::var_os(n)) {
            return Ok(());
        }
        let world = World::new(WorldOpts::default())?;
        assert!(std::env::var_os(ENV_TEST_HOME).is_none());
        let pinned = atlas_duck_ipc::paths::read_pinned(&world.pinned_file())
            .map_err(short_err)?
            .ok_or("no pinned file")?;
        assert_eq!(pinned.data_dir, world.data_dir());
        assert_eq!(pinned.config_dir, world.config_dir());
        assert_eq!(pinned.install_id.as_deref(), Some(world.install_id()));
        assert!(pinned.data_dir.starts_with(world.root()) || cfg!(unix));
        assert!(world.pinned_file().starts_with(&world.base_dirs().home));
        assert!(matches!(
            check_data_dir(world.data_dir())?,
            DataDirResolution::Local(_)
        ));
        let env = world.env();
        let home = env
            .iter()
            .find(|(k, _)| k == ENV_TEST_HOME)
            .map(|(_, v)| v.clone());
        assert_eq!(home, Some(world.base_dirs().home.clone().into_os_string()));
        // No lock holder: nothing to quit.
        assert!(!world.app_running()?);
        Ok(())
    }

    /// The provisioning half runs in this process only (no binary): store, core, mock, PAT.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provisioning_leaves_a_quit_store_and_a_stored_token() -> Result<()> {
        if cfg!(target_os = "linux") && display_missing(&|n| std::env::var_os(n)) {
            return Ok(());
        }
        let mut world = World::new(WorldOpts::default())?;
        world
            .provision_store(&[("jira-main", Product::Jira)])
            .await?;
        assert!(world.mock("jira-main").is_some());
        assert_eq!(world.instance_ids().len(), 1);
        let pat = EntryName::Pat(world.instance_ids()[0].clone());
        let keys = world.keys()?;
        let stored = keys.get(&pat).map_err(short_err)?;
        // PD-05: the entry is a JSON blob holding the token.
        let blob: Value = serde_json::from_slice(stored.ok_or("no PAT entry")?.as_slice())?;
        assert_eq!(blob["pat"], PAT_CANARY);
        let records = world.audit_records()?;
        let (last, payload) = records.last().ok_or("no records")?;
        assert_eq!(*last, EventType::APP_STOP);
        assert_eq!(payload["reason"], "quit");
        // The token is in the keystore, never in the log.
        for (_, p) in &records {
            assert!(!p.to_string().contains(PAT_CANARY));
        }
        Ok(())
    }
}
