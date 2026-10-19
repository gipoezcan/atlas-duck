//! M6 T23 (§2.5 First run, First-run wizard, Requests before setup completes; §7.7; §8.6; PD-77;
//! I-34, RF-3b, L46): the first-run wizard over Tauri's mock runtime (no OS window, no webview) with
//! the shipped capability files, serving in-process over `serve::start_with` on a scratch endpoint.
//!
//! Every path is the test's own: the wizard takes this host's pinned file, the default data and
//! config dirs from its `WizardEnv` (never from `ATLAS_DUCK_TEST_HOME`, which is process-wide and
//! would race between tests), so two simulated machines live in one test (RF-3b). Keystores are
//! `MemKeyStore`s over a `MemKeyring` that records every call. No OS keychain, no spawned binary,
//! nothing outside the scratch dirs under cargo's target dir (Unix: and the short socket base under
//! `/tmp`, `common::short_socket_base`).

type TestResult = Result<(), Box<dyn std::error::Error>>;

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atlas_duck_app_lib::commands;
use atlas_duck_app_lib::credential::{self, FirstRunPassphrase, Purpose};
use atlas_duck_app_lib::secret_service::{SecretService, SecretServiceCheck};
use atlas_duck_app_lib::serve::{
    self, FirstStoreFailure, KeysFactory, PinWriter, ServeHooks, ServeState, ServeWatcher,
    StartInputs, StartupFailure, start_with,
};
use atlas_duck_app_lib::state::{AppState, DataDirHold, ServeSlot, StartupSummary};
use atlas_duck_app_lib::windows::{
    self, AppSnapshot, NavPolicy, Relaunch, StartupRoute, WindowRegistry,
};
use atlas_duck_app_lib::wizard::{
    self, InFlight, MSG_KEYRING_NOT_LOCAL, MSG_NEEDS_SECRET_SERVICE, ServeStarter, Wizard,
    WizardEnv,
};
use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::testing::{KeyOpKind, MemKeyStore, MemKeyring, event_types, recovery_row};
use atlas_duck_audit::types::RustChosenPath;
use atlas_duck_audit::{
    ArchivedDb, AuditCursor, AuditFilter, EntryName, EventType, FirstRunInput, KeyStore,
    KeyStoreError, KeyringLocality, MAX_AUDIT_PAGE_ROWS, OpenConfig, SystemClock, create_new_store,
    new_ids,
};
use atlas_duck_core::{Confirm, GateState, NativeConfirmer, ShutdownReason, UiEvent, UiSink};
use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::client::IpcClient;
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::paths::{
    self, DataDirResolution, EndpointLocation, LocalDataDir, NotLocalKind, PinnedPaths,
    check_data_dir, read_endpoint_file, read_pinned,
};
use atlas_duck_ipc::proto::{AgentNameSource, ClientKind, Hello, SubmitParams, SubmitReply};
use secrecy::SecretString;
use serde_json::{Value, json};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{INVOKE_KEY, MockRuntime, get_ipc_response, mock_builder};
use tauri::webview::InvokeRequest;
use tauri::{App, AppHandle, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

const WAIT: Duration = Duration::from_secs(60);
const PASSPHRASE: &str = "correct horse battery";

// ---------- scratch dirs (as in `credential.rs`) ----------

/// A scratch dir under cargo's per-target test dir, not `%TEMP%`: the mock runtime keeps every app
/// and window alive for the rest of the process, and with them the `instance.lock` of the data dir
/// an app holds. Leftovers older than an hour are swept once per run (a younger one may belong to
/// a run that is still going).
fn scratch() -> std::io::Result<tempfile::TempDir> {
    static SWEEP: std::sync::Once = std::sync::Once::new();
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("wizard");
    std::fs::create_dir_all(&root)?;
    SWEEP.call_once(|| {
        let Ok(entries) = std::fs::read_dir(&root) else {
            return;
        };
        for e in entries.flatten() {
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > Duration::from_secs(60 * 60));
            if old {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    });
    tempfile::Builder::new().tempdir_in(&root)
}

// ---------- the mock app ----------

fn window(app: &App<MockRuntime>, label: &str) -> tauri::Result<WebviewWindow<MockRuntime>> {
    match app.get_webview_window(label) {
        Some(w) => Ok(w),
        None => WebviewWindowBuilder::new(app, label, WebviewUrl::default()).build(),
    }
}

fn invoke(w: &WebviewWindow<MockRuntime>, cmd: &str, body: Value) -> Result<Value, Value> {
    let url = w.url().map_err(|e| json!(e.to_string()))?;
    let request = InvokeRequest {
        cmd: cmd.into(),
        callback: CallbackFn(0),
        error: CallbackFn(1),
        url,
        body: InvokeBody::Json(body),
        headers: Default::default(),
        invoke_key: INVOKE_KEY.to_string(),
    };
    get_ipc_response(w, request).map(|b| b.deserialize::<Value>().unwrap_or(Value::Null))
}

/// [`invoke`] off the async test's worker (it blocks until the command answered).
async fn call(w: &WebviewWindow<MockRuntime>, cmd: &str, body: Value) -> Result<Value, Value> {
    let (w, cmd) = (w.clone(), cmd.to_owned());
    tokio::task::spawn_blocking(move || invoke(&w, &cmd, body))
        .await
        .unwrap_or_else(|e| Err(json!(e.to_string())))
}

/// A `{}`-bodied command from `w` that must answer; its rejection is the test's error.
async fn run(
    w: &WebviewWindow<MockRuntime>,
    cmd: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    call(w, cmd, json!({}))
        .await
        .map_err(|e| format!("{cmd}: {e}").into())
}

/// `wizard_finish` / `wizard_skip_instances` from `w`, naming the step the page showed.
async fn run_step(
    w: &WebviewWindow<MockRuntime>,
    cmd: &str,
    step: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    call(w, cmd, json!({ "step": step }))
        .await
        .map_err(|e| format!("{cmd} {step}: {e}").into())
}

async fn wizard_state(
    setup: &WebviewWindow<MockRuntime>,
) -> Result<Value, Box<dyn std::error::Error>> {
    call(setup, "wizard_state", json!({}))
        .await
        .map_err(|e| format!("wizard_state: {e}").into())
}

async fn eventually(what: &str, mut ok: impl FnMut() -> bool) -> TestResult {
    let started = Instant::now();
    while !ok() {
        if started.elapsed() > WAIT {
            return Err(format!("never: {what}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

/// Polls `wizard_state` until `ok` holds; returns that state.
async fn until(
    setup: &WebviewWindow<MockRuntime>,
    what: &str,
    ok: impl Fn(&Value) -> bool,
) -> Result<Value, Box<dyn std::error::Error>> {
    let started = Instant::now();
    loop {
        let s = wizard_state(setup).await?;
        if ok(&s) {
            return Ok(s);
        }
        if started.elapsed() > WAIT {
            return Err(format!("never: {what}; last state {s}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn step_is(step: &'static str) -> impl Fn(&Value) -> bool {
    move |s| s["step"] == step
}

// ---------- the machine ----------

struct NoUi;
impl UiSink for NoUi {
    fn emit(&self, _: UiEvent) {}
}

/// Native confirmations: Ok, except the next `.1` ones (Cancel); every text recorded.
#[derive(Default)]
struct Answers(Mutex<Vec<String>>, AtomicU32);

impl NativeConfirmer for Answers {
    fn confirm(&self, text: &str) -> Confirm {
        if let Ok(mut t) = self.0.lock() {
            t.push(text.to_owned());
        }
        let cancel = self
            .1
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        if cancel { Confirm::Cancel } else { Confirm::Ok }
    }
}

impl Answers {
    fn texts(&self) -> Vec<String> {
        self.0.lock().map(|t| t.clone()).unwrap_or_default()
    }
}

/// `MemKeyStore`s over one keyring; records the install id of every keystore built.
struct RecordingKeys {
    ring: Arc<MemKeyring>,
    ids: Mutex<Vec<String>>,
}

impl RecordingKeys {
    fn ids(&self) -> Vec<String> {
        self.ids.lock().map(|i| i.clone()).unwrap_or_default()
    }
}

impl KeysFactory for RecordingKeys {
    fn keys(&self, install_id: &str) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
        if let Ok(mut ids) = self.ids.lock() {
            ids.push(install_id.to_owned());
        }
        Ok(Arc::new(MemKeyStore::new(self.ring.clone(), install_id)))
    }
}

/// The Secret Service answer the wizard sees (`None`: not Linux).
struct FixedSecretService(Option<SecretService>);
impl SecretServiceCheck for FixedSecretService {
    fn check(&self) -> Option<SecretService> {
        self.0
    }
}

/// One write of the pinned file: the `install_id` written and whether the data dir it names
/// existed at that moment.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PinCall {
    install_id: Option<String>,
    data_dir_existed: bool,
}

/// The tests' locality check: an existing folder with a component named `fake-nfs` is on a network
/// filesystem; everything else (a folder that does not exist yet included: `Missing`, as the real
/// check answers before it looks at the filesystem) is the real check.
fn fake_nfs_check(p: &Path) -> std::io::Result<DataDirResolution> {
    if p.components().any(|c| c.as_os_str() == "fake-nfs") && p.is_dir() {
        return Ok(DataDirResolution::NotLocal {
            path: p.to_path_buf(),
            kind: NotLocalKind::NetworkFs { f_type: 0x6969 },
        });
    }
    check_data_dir(p)
}

/// The app's watcher in the tests: the credential window follows, the wizard's page re-reads.
struct TestWatcher(AppHandle<MockRuntime>);
impl ServeWatcher for TestWatcher {
    fn serving_changed(&self) {
        let app = self.0.clone();
        tauri::async_runtime::spawn_blocking(move || {
            credential::follow::follow_serving(&app);
            wizard::serving_changed(&app);
        });
    }
}

/// The tests' serving start: `serve::start_with` on a scratch endpoint, the state left in the
/// managed `ServeSlot`, then `wizard::serving_started` (as `serve::start` does).
struct TestStarter {
    host: &'static str,
    keys: Arc<RecordingKeys>,
    confirmer: Arc<Answers>,
    /// The machine's [`Machine::sock_base`].
    sock_base: PathBuf,
    /// The start never ends (a store still opening).
    idle: bool,
    /// What the wizard's `in_flight` was each time a start began.
    in_flight_at_start: Arc<Mutex<Vec<Option<InFlight>>>>,
}

impl TestStarter {
    fn inputs(
        &self,
        app: &AppHandle<MockRuntime>,
        data: LocalDataDir,
        lock: Arc<InstanceLock>,
        pinned: &PinnedPaths,
    ) -> Result<StartInputs, Box<dyn std::error::Error>> {
        let location = location(&self.sock_base, &data, self.host)?;
        let quit = app
            .try_state::<ServeSlot>()
            .map(|s| s.quit().clone())
            .unwrap_or_default();
        Ok(StartInputs {
            data,
            lock,
            host: self.host.to_owned(),
            install_id: pinned.install_id.clone(),
            config_dir: pinned.config_dir.clone(),
            keys: self.keys.clone(),
            ui: Arc::new(NoUi),
            confirmer: self.confirmer.clone(),
            tray_host: None,
            secret_service: Arc::new(FixedSecretService(None)),
            retry_schedule: vec![],
            quit,
            endpoint: Some(location),
            hooks: ServeHooks {
                watcher: Some(Arc::new(TestWatcher(app.clone()))),
                ..ServeHooks::default()
            },
        })
    }
}

impl ServeStarter<MockRuntime> for TestStarter {
    fn start(
        &self,
        app: &AppHandle<MockRuntime>,
        data: LocalDataDir,
        lock: Arc<InstanceLock>,
        pinned: &PinnedPaths,
    ) {
        if let (Some(w), Ok(mut seen)) = (
            app.try_state::<Wizard<MockRuntime>>(),
            self.in_flight_at_start.lock(),
        ) {
            seen.push(w.progress_now().in_flight);
        }
        if self.idle {
            return;
        }
        let handle = app.clone();
        let Ok(inputs) = self.inputs(app, data, lock, pinned) else {
            if let Some(slot) = handle.try_state::<ServeSlot>() {
                slot.mark_store_failed();
            }
            return;
        };
        let task = tauri::async_runtime::spawn(async move {
            match start_with(inputs).await {
                Ok(state) => {
                    if let Some(slot) = handle.try_state::<ServeSlot>() {
                        slot.set(state);
                    }
                }
                Err(StartupFailure::Store(_)) => {
                    if let Some(slot) = handle.try_state::<ServeSlot>() {
                        slot.mark_store_failed();
                    }
                }
                Err(StartupFailure::Cancelled) => {}
            }
            wizard::serving_started(&handle);
        });
        if let Some(slot) = app.try_state::<ServeSlot>() {
            slot.set_starting(task);
        }
    }
}

#[cfg(unix)]
fn location(
    sock_base: &Path,
    _data: &LocalDataDir,
    _host: &str,
) -> Result<EndpointLocation, Box<dyn std::error::Error>> {
    common::socket_location(sock_base)
}

#[cfg(windows)]
fn location(
    _sock_base: &Path,
    data: &LocalDataDir,
    host: &str,
) -> Result<EndpointLocation, Box<dyn std::error::Error>> {
    Ok(paths::endpoint_location(data, host)?)
}

#[cfg(unix)]
fn same_user() -> Result<atlas_duck_ipc::transport::unix::SameUser, Box<dyn std::error::Error>> {
    Ok(atlas_duck_ipc::transport::unix::SameUser)
}

#[cfg(windows)]
fn same_user() -> Result<atlas_duck_ipc::transport::windows::SameUser, Box<dyn std::error::Error>> {
    Ok(atlas_duck_ipc::transport::windows::SameUser::current()?)
}

/// One simulated machine: its own home (pinned file), its own default data dir, a keyring.
struct Machine {
    host: &'static str,
    root: PathBuf,
    /// Where the endpoint lives (Unix: `<sock_base>/s/`, a short dir outside the scratch dir,
    /// [`common::short_socket_base`]; Windows: unused, the pipe name comes from the data dir).
    sock_base: PathBuf,
    /// Unix: holds [`Machine::sock_base`] until the machine is dropped.
    _sock: Option<tempfile::TempDir>,
    pinned_file: PathBuf,
    default_dir: PathBuf,
    config_dir: PathBuf,
    ring: Arc<MemKeyring>,
    keys: Arc<RecordingKeys>,
    confirmer: Arc<Answers>,
    pins: Arc<Mutex<Vec<PinCall>>>,
    pick: Arc<Mutex<Option<PathBuf>>>,
    /// M10 T15: what the anchor-dir folder dialog answers, and how often it was shown.
    pick_anchor: Arc<Mutex<Option<PathBuf>>>,
    anchor_dialogs: Arc<AtomicU32>,
    /// M10 T15: what the restore's file dialog answers, and how often it was shown.
    pick_restore: Arc<Mutex<Option<PathBuf>>>,
    restore_dialogs: Arc<AtomicU32>,
    /// M10 T15: the next this many writes of the pinned file that name an `install_id` fail.
    pin_fail: Arc<AtomicU32>,
    secret_service: Option<SecretService>,
    /// Step 0's start never ends.
    idle_start: bool,
    in_flight_at_start: Arc<Mutex<Vec<Option<InFlight>>>>,
}

impl Machine {
    /// `config_dir`: a shared one (RF-3b), else the machine's own.
    fn new(
        tmp: &tempfile::TempDir,
        host: &'static str,
        config_dir: Option<PathBuf>,
        ring: Arc<MemKeyring>,
    ) -> Result<Machine, Box<dyn std::error::Error>> {
        let root = tmp.path().join(host);
        std::fs::create_dir_all(root.join("home"))?;
        let config_dir = match config_dir {
            Some(dir) => dir,
            None => {
                let dir = root.join("config");
                std::fs::create_dir_all(&dir)?;
                dir
            }
        };
        #[cfg(unix)]
        let sock = Some(common::short_socket_base()?);
        #[cfg(windows)]
        let sock: Option<tempfile::TempDir> = None;
        let sock_base = sock
            .as_ref()
            .map_or_else(|| root.clone(), |s| s.path().to_path_buf());
        Ok(Machine {
            host,
            sock_base,
            _sock: sock,
            pinned_file: root.join("home").join("paths.toml"),
            default_dir: root.join("data"),
            config_dir,
            keys: Arc::new(RecordingKeys {
                ring: ring.clone(),
                ids: Mutex::default(),
            }),
            ring,
            confirmer: Arc::default(),
            pins: Arc::default(),
            pick: Arc::default(),
            pick_anchor: Arc::default(),
            anchor_dialogs: Arc::default(),
            pick_restore: Arc::default(),
            restore_dialogs: Arc::default(),
            pin_fail: Arc::default(),
            secret_service: None,
            idle_start: false,
            in_flight_at_start: Arc::default(),
            root,
        })
    }

    fn pins(&self) -> Vec<PinCall> {
        self.pins.lock().map(|p| p.clone()).unwrap_or_default()
    }

    fn starter(&self) -> Arc<TestStarter> {
        Arc::new(TestStarter {
            host: self.host,
            keys: self.keys.clone(),
            confirmer: self.confirmer.clone(),
            sock_base: self.sock_base.clone(),
            idle: self.idle_start,
            in_flight_at_start: self.in_flight_at_start.clone(),
        })
    }

    fn env(&self) -> WizardEnv<MockRuntime> {
        let pins = self.pins.clone();
        let pick = self.pick.clone();
        let (pick_anchor, anchor_dialogs) = (self.pick_anchor.clone(), self.anchor_dialogs.clone());
        let (pick_restore, restore_dialogs) =
            (self.pick_restore.clone(), self.restore_dialogs.clone());
        let pin_fail = self.pin_fail.clone();
        let ring = self.ring.clone();
        WizardEnv {
            pinned_file: self.pinned_file.clone(),
            default_data_dir: self.default_dir.clone(),
            config_dir: self.config_dir.clone(),
            host: self.host.to_owned(),
            secret_service: Arc::new(FixedSecretService(self.secret_service)),
            starter: self.starter(),
            pick_folder: Arc::new(move |_| pick.lock().ok().and_then(|p| p.clone())),
            pick_anchor_dir: Arc::new(move |_| {
                anchor_dialogs.fetch_add(1, Ordering::SeqCst);
                let p = pick_anchor.lock().ok().and_then(|p| p.clone())?;
                Some(RustChosenPath::from_native_dialog(p))
            }),
            pick_restore: Arc::new(move |_| {
                restore_dialogs.fetch_add(1, Ordering::SeqCst);
                let p = pick_restore.lock().ok().and_then(|p| p.clone())?;
                Some(RustChosenPath::from_native_dialog(p))
            }),
            write_pinned: Arc::new(move |file, p| {
                if let Ok(mut calls) = pins.lock() {
                    calls.push(PinCall {
                        install_id: p.install_id.clone(),
                        data_dir_existed: p.data_dir.is_dir(),
                    });
                }
                let fail = p.install_id.is_some()
                    && pin_fail
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_ok();
                if fail {
                    return Err(paths::PinnedError::Io(std::io::Error::other(
                        "the test refuses this write",
                    )));
                }
                paths::write_pinned(file, p)
            }),
            check_dir: fake_nfs_check,
            // What `MemKeyStore::locality` answers: no ring operation is recorded.
            keyring_locality: Arc::new(move || {
                MemKeyStore::new(ring.clone(), "locality-probe").locality()
            }),
        }
    }

    /// The app before first run: no pinned file, the wizard managed, a setup window.
    fn app(
        &self,
    ) -> Result<(App<MockRuntime>, WebviewWindow<MockRuntime>), Box<dyn std::error::Error>> {
        let context = tauri::generate_context!(assets = tauri::test::noop_assets(), test = true);
        let app = commands::register(mock_builder()).build(context)?;
        app.manage(WindowRegistry::new(
            NavPolicy::for_this_platform(None),
            StartupRoute::completed(),
        ));
        app.manage(AppState::new(StartupSummary::BeforeFirstRun, None));
        app.manage(Wizard::new(self.env(), None));
        let setup = window(&app, "setup")?;
        Ok((app, setup))
    }

    /// A store in `dir` created as the wizard would, shut down again; its `install_id`.
    fn provision(&self, dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
        self.provision_with(dir, None, |_| Ok(()))
    }

    /// A store in `dir` created as the wizard would, with `anchor` as its anchor dir; `then` runs on
    /// it before it is shut down (its anchor-dir lines written first). Its `install_id`.
    fn provision_with(
        &self,
        dir: &Path,
        anchor: Option<&Path>,
        then: impl FnOnce(&atlas_duck_audit::Store) -> TestResult,
    ) -> Result<String, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(dir)?;
        let data = local(dir)?;
        let lock = InstanceLock::acquire(&data, self.host)?;
        let (install_id, chain_id) = new_ids()?;
        let keys: Arc<dyn KeyStore> = Arc::new(MemKeyStore::new(self.ring.clone(), &install_id));
        let store = create_new_store(
            &data,
            &lock,
            OpenConfig::new(Arc::new(SystemClock::new()), keys),
            FirstRunInput {
                install_id: install_id.clone(),
                chain_id,
                passphrase: SecretString::from(PASSPHRASE),
                passphrase_confirm: SecretString::from(PASSPHRASE),
                archived_db: None,
                anchor_dir: anchor.map(|a| RustChosenPath::from_native_dialog(a.to_path_buf())),
                archive_confirmed: None,
            },
        )?;
        let done = if anchor.is_some() && !store.testing_anchor_dir_drain() {
            Err("the provisioned store's anchor-dir lines were not written".into())
        } else {
            then(&store)
        };
        store.shutdown();
        done?;
        Ok(install_id)
    }

    /// A backup bundle of a store of another install (its own data dir and ring entries) in
    /// `<root>/backups`, made with [`PASSPHRASE`]: what the wizard's restore picks.
    fn backup_elsewhere(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let out = self.root.join("backups");
        std::fs::create_dir_all(&out)?;
        let bundle = Mutex::new(None);
        self.provision_with(&self.root.join("old-data"), None, |store| {
            let receipt = store.backup(RustChosenPath::from_native_dialog(out.clone()))?;
            *bundle.lock().map_err(|_| "poisoned")? = Some(receipt.bundle_dir);
            Ok(())
        })?;
        let bundle = bundle.into_inner().map_err(|_| "poisoned")?;
        Ok(bundle.ok_or("no backup")?)
    }
}

fn local(dir: &Path) -> Result<LocalDataDir, Box<dyn std::error::Error>> {
    match check_data_dir(dir)? {
        DataDirResolution::Local(d) => Ok(d),
        other => Err(format!("{} is not a local data dir: {other:?}", dir.display()).into()),
    }
}

fn serving(app: &App<MockRuntime>) -> Option<Arc<ServeState>> {
    app.try_state::<ServeSlot>().and_then(|s| s.get().cloned())
}

async fn connect(
    m: &Machine,
    data: &LocalDataDir,
) -> Result<IpcClient, Box<dyn std::error::Error>> {
    let hello = Hello {
        build_id: BUILD_ID.to_owned(),
        client_kind: ClientKind::Cli,
        agent_name: Some("t23".into()),
        agent_name_source: AgentNameSource::Flag,
        cwd_basename: "work".into(),
    };
    let location = location(&m.sock_base, data, m.host)?;
    IpcClient::connect_at(
        &location,
        data,
        &hello,
        &same_user()?,
        Instant::now() + WAIT,
    )
    .await
    .map_err(|e| format!("connect: {e}").into())
}

fn submit_params() -> SubmitParams {
    SubmitParams {
        op_id: "jira.search".into(),
        params: json!({ "jql": "project = X" }),
        instance: None,
        reason: None,
    }
}

fn reason(env: &Envelope) -> Option<&str> {
    env.error
        .as_ref()
        .and_then(|e| e.details.as_ref())
        .and_then(|d| d.get("reason"))
        .and_then(Value::as_str)
}

/// Stops what the start started (server, core, store), so the scratch dir can go.
async fn stop(app: &App<MockRuntime>) -> TestResult {
    if let Some(state) = serving(app) {
        serve::shutdown(&state, ShutdownReason::Quit, WAIT).await;
    }
    Ok(())
}

/// The passphrase pair typed into the credential window the wizard opened.
async fn type_passphrase(app: &App<MockRuntime>, pass: &str) -> Result<Value, Value> {
    let w = window(app, "credential").map_err(|e| json!(e.to_string()))?;
    call(
        &w,
        "submit_secret",
        json!({ "secret": pass, "secret_confirm": pass }),
    )
    .await
}

// ---------- step 0 ----------

/// §2.5 (0), M4 T14: the data dir is checked, created and locked before this host's pinned file
/// is written (without an `install_id`: there is no store yet); a folder that cannot be used pins
/// nothing; step 0 runs once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn step0_writes_data_dir_before_pinned_file() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let (app, setup) = m.app()?;
    let s = wizard_state(&setup).await?;
    assert_eq!(s["step"], "data_dir");
    assert_eq!(s["data_dir"], Value::Null);
    assert_eq!(s["default_dir"], m.default_dir.display().to_string());
    assert_eq!(s["refused_count"], Value::Null);

    // A folder under a regular file cannot be created: refused, nothing pinned.
    std::fs::write(m.root.join("a-file"), b"x")?;
    *m.pick.lock().map_err(|_| "poisoned")? = Some(m.root.join("a-file").join("data"));
    let s = run(&setup, "wizard_choose_dir").await?;
    assert_eq!(s["step"], "data_dir");
    assert_eq!(s["error"]["class"], "unusable", "{s}");
    // A folder whose instance.lock another atlas-duck holds: refused, nothing pinned.
    let held = m.root.join("held");
    std::fs::create_dir(&held)?;
    let other = InstanceLock::acquire(&local(&held)?, "host-z")?;
    *m.pick.lock().map_err(|_| "poisoned")? = Some(held.clone());
    let s = run(&setup, "wizard_choose_dir").await?;
    // Unix reads the holder's record (another host); Windows cannot (share mode 0).
    assert!(
        s["error"]["class"] == "other_host" || s["error"]["class"] == "unusable",
        "{s}"
    );
    drop(other);
    // A cancelled dialog changes nothing.
    *m.pick.lock().map_err(|_| "poisoned")? = None;
    let s = run(&setup, "wizard_choose_dir").await?;
    assert_eq!(
        (s["step"].clone(), s["error"].clone()),
        (json!("data_dir"), Value::Null)
    );
    assert!(!m.pinned_file.exists(), "a refused folder pins nothing");
    assert!(m.pins().is_empty());

    // The default: created, locked, pinned (in that order), and served in-process.
    assert!(!m.default_dir.exists());
    let s = run(&setup, "wizard_use_default_dir").await?;
    assert_eq!(s["data_dir"], m.default_dir.display().to_string());
    assert_eq!(
        m.pins(),
        [PinCall {
            install_id: None,
            data_dir_existed: true
        }]
    );
    let pinned = read_pinned(&m.pinned_file)?.ok_or("no pinned file")?;
    assert_eq!(pinned.data_dir, m.default_dir);
    assert_eq!(pinned.config_dir, m.config_dir);
    assert_eq!(pinned.install_id, None);
    assert!(m.default_dir.join("instance.lock").exists());
    until(&setup, "the first-run gate serves", |s| {
        s["step"] == "anchor_dir" && s["refused_count"] == 0
    })
    .await?;
    let data = local(&m.default_dir)?;
    assert!(read_endpoint_file(&data)?.is_some(), "IPC is served");
    assert_eq!(s["existing_store"], false);
    // Once only.
    for cmd in ["wizard_use_default_dir", "wizard_choose_dir"] {
        assert_eq!(
            call(&setup, cmd, json!({})).await,
            Err(json!({"kind": "not_ready"})),
            "{cmd}"
        );
    }
    assert_eq!(m.pins().len(), 1);
    // T23 m-4: `in_flight` held until the data dir is managed, the start included (a second step-0
    // call in between would pass its guards and end in `already_pinned`).
    assert_eq!(
        *m.in_flight_at_start.lock().map_err(|_| "poisoned")?,
        [Some(InFlight::DataDir)]
    );
    assert_eq!(
        app.state::<Wizard<MockRuntime>>().progress_now().in_flight,
        None
    );
    stop(&app).await
}

/// What `wizard_choose_dir` pinned after picking `pick` (prepared by `prepare`), on a machine of its
/// own.
async fn pinned_after_pick(
    tmp: &tempfile::TempDir,
    host: &'static str,
    prepare: impl FnOnce(&Machine, &Path) -> TestResult,
) -> Result<(PathBuf, PathBuf, Value), Box<dyn std::error::Error>> {
    let m = Machine::new(tmp, host, None, MemKeyring::new())?;
    let pick = m.root.join("picked");
    std::fs::create_dir_all(&pick)?;
    prepare(&m, &pick)?;
    *m.pick.lock().map_err(|_| "poisoned")? = Some(pick.clone());
    let (app, setup) = m.app()?;
    let s = run(&setup, "wizard_choose_dir").await?;
    let pinned = read_pinned(&m.pinned_file)?.ok_or("no pinned file")?;
    stop(&app).await?;
    Ok((pick, pinned.data_dir, s))
}

/// T23 m-11: a picked folder that holds other files gets `atlas-duck` inside it (the store, the
/// lock, `webview*/` and `archived/` never land in `Documents` or a drive root); an empty folder is
/// used as it is, and so is a folder that already is an atlas-duck data dir (`audit.db`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_populated_pick_gets_an_atlas_duck_folder() -> TestResult {
    let tmp = scratch()?;
    // Populated with something else: nested.
    let (pick, pinned, s) = pinned_after_pick(&tmp, "host-a", |_, dir| {
        std::fs::write(dir.join("notes.txt"), b"mine")?;
        Ok(())
    })
    .await?;
    assert_eq!(pinned, pick.join("atlas-duck"));
    assert_eq!(s["data_dir"], pick.join("atlas-duck").display().to_string());
    assert!(pick.join("atlas-duck").join("instance.lock").exists());
    assert!(
        !pick.join("instance.lock").exists(),
        "nothing of ours beside the user's files"
    );
    // Empty: as it is.
    let (pick, pinned, s) = pinned_after_pick(&tmp, "host-b", |_, _| Ok(())).await?;
    assert_eq!(pinned, pick);
    assert_eq!(s["data_dir"], pick.display().to_string());
    // Already an atlas-duck data dir (a store): as it is, and it is (1a).
    let (pick, pinned, s) = pinned_after_pick(&tmp, "host-c", |m, dir| {
        m.provision(dir)?;
        Ok(())
    })
    .await?;
    assert_eq!(pinned, pick);
    assert_eq!(s["existing_store"], true);
    Ok(())
}

/// §7.7: a data dir that is not on a local filesystem is refused with the startup text, and a
/// folder that does not exist yet is never created on one (its nearest existing ancestor is
/// checked first).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_local_dir_refused() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let (_app, setup) = m.app()?;
    let share = m.root.join("fake-nfs");
    std::fs::create_dir(&share)?;
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut picks = vec![
        share.clone(),
        share.join("atlas"),
        share.join("a").join("b"),
    ];
    // Windows: a UNC path is refused before any OS call (no network access).
    #[cfg(windows)]
    picks.push(PathBuf::from(r"\\nas.invalid\home\atlas-duck"));
    for pick in picks {
        *m.pick.lock().map_err(|_| "poisoned")? = Some(pick.clone());
        let s = run(&setup, "wizard_choose_dir").await?;
        assert_eq!(s["step"], "data_dir", "{}", pick.display());
        assert_eq!(s["error"]["class"], "not_local", "{s}");
        assert_eq!(
            s["error"]["text"],
            format!(
                "data directory {} is not on a local filesystem",
                pick.display()
            )
        );
    }
    assert!(
        !share.join("atlas").exists(),
        "nothing created on the share"
    );
    assert!(!share.join("a").exists());
    assert!(!m.pinned_file.exists());
    assert!(m.pins().is_empty());
    Ok(())
}

// ---------- the first-run gate ----------

/// §2.5 "Requests before setup completes" (L46): after step 0 the first-run gate answers in-process
/// (`not_configured {first_run}`, the fixed message), nothing is queued, and every refused submit
/// counts in the wizard's header and the tray; the re-raise of the wizard goes through the setup
/// window's route and never shows an existing window again (T22 I-1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_run_gate_serves_and_counts_refused() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let (app, setup) = m.app()?;
    let handle = app.handle().clone();
    assert_eq!(windows::snapshot(&handle), AppSnapshot::BeforeFirstRun);
    run(&setup, "wizard_use_default_dir").await?;
    until(&setup, "the gate serves", |s| s["refused_count"] == 0).await?;
    assert_eq!(
        windows::snapshot(&handle),
        AppSnapshot::Gate(GateState::FirstRun)
    );

    let data = local(&m.default_dir)?;
    let mut c = connect(&m, &data).await?;
    for n in 1..=3u64 {
        let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
        let env = reply.envelope;
        assert_eq!(env.status, Status::Failed);
        let error = env.error.as_ref().ok_or("no error")?;
        assert_eq!(error.code, ErrorCode::NotConfigured);
        assert_eq!(error.message, atlas_duck_core::gate::MSG_FIRST_RUN);
        assert_eq!(reason(&env), Some("first_run"));
        assert_eq!(env.request_id, None, "nothing queued");
        let s = wizard_state(&setup).await?;
        assert_eq!(s["refused_count"], n, "the header counts every refusal");
    }
    // `doctor` is answered as usual.
    let doctor: Envelope = c.call("doctor", json!({})).await?;
    assert_eq!(doctor.status, Status::Succeeded);
    // The tray shows the same count (§2.5 verbatim).
    let lines = atlas_duck_app_lib::tray::status_lines(
        &windows::snapshot(&handle),
        &atlas_duck_app_lib::status::gather_gate(&handle),
    );
    assert_eq!(lines, ["Setup required \u{2014} 3 requests refused"]);
    // The re-raise opens the wizard (also under `--background`, L46) and never re-shows the
    // existing setup window: it only asks for attention.
    let route = windows::route_cold_start(&windows::snapshot(&handle), true);
    assert_eq!(route, Relaunch::OpenSetup);
    let built = AtomicU32::new(0);
    credential::raise::raise_window_with(&handle, route, |_| {
        built.fetch_add(1, Ordering::SeqCst);
    });
    assert_eq!(
        built.load(Ordering::SeqCst),
        0,
        "the existing setup window is not shown again"
    );
    drop(c);
    stop(&app).await
}

// ---------- (1a) ----------

/// I-34 (§2.5 (1a), §7.7): a data dir that already holds an audit DB is not a first run. The
/// pinned file gets the store's `install_id`; no recovery passphrase is asked, no note offered,
/// no `GENESIS` written; the `recovery` row stays byte-identical; the store opens as at startup and
/// the wizard goes on with the instances.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i34_wizard_existing_db_writes_no_passphrase_or_genesis() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let install_id = m.provision(&m.default_dir)?;
    let data = local(&m.default_dir)?;
    let recovery_before = recovery_row(&data)?.ok_or("no recovery row")?;
    let types_before = event_types(&data)?;
    assert_eq!(types_before.iter().filter(|t| *t == "GENESIS").count(), 1);
    let ops_before = m.ring.ops().len();

    let (app, setup) = m.app()?;
    let s = run(&setup, "wizard_use_default_dir").await?;
    assert_eq!(s["existing_store"], true);
    assert_eq!(
        m.pins(),
        [PinCall {
            install_id: Some(install_id.clone()),
            data_dir_existed: true
        }]
    );
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        Some(install_id.clone())
    );
    let s = until(&setup, "the store serves", step_is("instances")).await?;
    assert_eq!(s["passphrase_window"], false);
    // Nothing can ask for a passphrase now.
    assert_eq!(
        call(&setup, "wizard_begin", json!({})).await,
        Err(json!({"kind": "not_ready"}))
    );
    assert_eq!(credential::current_purpose(app.handle()), None);
    let state = serving(&app).ok_or("not serving")?;
    assert!(state.core.get().is_some());
    assert_eq!(
        state.note_facts().map(|f| f.0),
        Some(install_id.clone()),
        "the existing store serves"
    );

    assert_eq!(
        recovery_row(&data)?.ok_or("no recovery row")?,
        recovery_before,
        "recovery row byte-identical"
    );
    let types = event_types(&data)?;
    assert_eq!(
        types.iter().filter(|t| *t == "GENESIS").count(),
        1,
        "{types:?}"
    );
    assert_eq!(types[..types_before.len()], types_before[..]);
    // No KEK was written (no new install): only reads, the canary self-test and the anchors.
    let kek_written = m.ring.ops()[ops_before..]
        .iter()
        .any(|op| op.kind == KeyOpKind::Set && op.full_name.ends_with("/kek"));
    assert!(!kek_written);
    assert!(m.keys.ids().iter().all(|id| *id == install_id));
    stop(&app).await
}

/// I-34 (§2.5 (1a) "or with keychain_lost → Recover this log"): an existing DB whose keychain
/// entries are gone opens locked; the wizard opens "Recover this log", never the first-run
/// passphrase, and writes no `GENESIS`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i34_existing_db_keychain_lost_opens_recover_this_log() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let install_id = m.provision(&m.default_dir)?;
    m.ring.wipe_install(&install_id);
    let data = local(&m.default_dir)?;
    let recovery_before = recovery_row(&data)?;

    let (app, setup) = m.app()?;
    run(&setup, "wizard_use_default_dir").await?;
    let s = until(&setup, "the store is locked", step_is("existing_store")).await?;
    assert_eq!(s["passphrase_window"], false);
    let handle = app.handle().clone();
    eventually("the credential window offers Recover this log", || {
        credential::current_purpose(&handle) == Some(Purpose::RecoverThisLog)
    })
    .await?;
    // Begin opens what the store needs, nothing else.
    let s = run(&setup, "wizard_begin").await?;
    assert_eq!(s["step"], "existing_store");
    assert_eq!(
        credential::current_purpose(&handle),
        Some(Purpose::RecoverThisLog)
    );
    assert_eq!(recovery_row(&data)?, recovery_before);
    assert_eq!(
        event_types(&data)?
            .iter()
            .filter(|t| *t == "GENESIS")
            .count(),
        1
    );
    stop(&app).await
}

// ---------- (1b) ----------

/// §2.5 (1b), PD-77: Begin opens the credential window for the recovery passphrase; the pair goes
/// to the store, `GENESIS` is written, the pinned file names the new `install_id` (after losing any
/// old one), the core starts and the cell swaps without a rebind (same endpoint, same connection);
/// then the recovery note, the instances, the CLI and the onboarding snippet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wizard_genesis_swaps_handler_without_rebind() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let (app, setup) = m.app()?;
    let handle = app.handle().clone();
    run(&setup, "wizard_use_default_dir").await?;
    until(&setup, "the gate serves", |s| {
        s["step"] == "anchor_dir" && s["refused_count"] == 0
    })
    .await?;
    let data = local(&m.default_dir)?;
    let endpoint = read_endpoint_file(&data)?;
    assert!(endpoint.is_some());
    let state = serving(&app).ok_or("not serving")?;
    let gate = state.cell.current();
    let mut c = connect(&m, &data).await?;
    let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
    assert_eq!(reason(&reply.envelope), Some("first_run"));

    // The steps before the passphrase refuse.
    for cmd in ["wizard_skip_instances", "wizard_finish"] {
        assert_eq!(
            call(&setup, cmd, json!({"step": "anchor_dir"})).await,
            Err(json!({"kind": "not_ready"})),
            "{cmd}"
        );
    }
    let s = run(&setup, "wizard_begin").await?;
    assert_eq!(
        (s["step"].clone(), s["passphrase_window"].clone()),
        (json!("passphrase"), json!(true))
    );
    assert_eq!(
        credential::current_purpose(&handle),
        Some(Purpose::RecoveryPassphrase)
    );
    // A second Begin while the window waits brings it back; nothing new starts.
    let s = run(&setup, "wizard_begin").await?;
    assert_eq!(s["passphrase_window"], true);
    // The window's own check: a mismatch commits nothing and the window stays.
    let w = window(&app, "credential")?;
    assert_eq!(
        call(
            &w,
            "submit_secret",
            json!({"secret": PASSPHRASE, "secret_confirm": "correct horse batterY"})
        )
        .await,
        Ok(json!({"failed": {"class": "passphrase_mismatch"}}))
    );
    assert!(!data.path().join("audit.db").exists());
    assert_eq!(
        type_passphrase(&app, PASSPHRASE).await,
        Ok(json!({"accepted": {}}))
    );

    let s = until(&setup, "GENESIS", step_is("recovery_note")).await?;
    assert!(
        !s.to_string().contains(PASSPHRASE),
        "the passphrase is in no answer"
    );
    let state_now = serving(&app).ok_or("not serving")?;
    assert!(Arc::ptr_eq(&state_now, &state), "the same serving state");
    assert!(state.core.get().is_some(), "the core serves");
    assert_eq!(state.refused(), None, "the gate is gone");
    assert!(
        !Arc::ptr_eq(&state.cell.current(), &gate),
        "the cell swapped"
    );
    assert_eq!(read_endpoint_file(&data)?, endpoint, "no rebind");
    let instances: Envelope = c.call("instances.list", json!({})).await?;
    assert_eq!(instances.status, Status::Succeeded, "{instances:?}");

    // The pinned file: no id (step 0), no id again before GENESIS, then the new store's.
    let new_id = state.note_facts().map(|f| f.0).ok_or("no store")?;
    assert_eq!(
        m.pins()
            .iter()
            .map(|p| p.install_id.clone())
            .collect::<Vec<_>>(),
        [None, None, Some(new_id.clone())]
    );
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        Some(new_id.clone())
    );
    assert_eq!(m.keys.ids(), std::slice::from_ref(&new_id));
    assert_eq!(
        event_types(&data)?.first().map(String::as_str),
        Some("GENESIS")
    );
    // The credential window offers the recovery note now (§8.6: right after GENESIS).
    let ctx = run(&w, "credential_context").await?;
    assert_eq!(ctx["note_available"], true, "{ctx}");

    // The note step ends with the window; then instances (none yet), CLI, onboarding, done.
    // T24 I-1 / T23 m-3: a request for another step than the wizard is at moves nothing and says
    // `wrong_step` (and the answer after it does not carry that error).
    let s = run_step(&setup, "wizard_finish", "cli").await?;
    assert_eq!(s["step"], "recovery_note", "{s}");
    assert_eq!(s["error"]["class"], "wrong_step", "{s}");
    assert_eq!(
        credential::current_purpose(&handle),
        Some(Purpose::RecoveryPassphrase),
        "the note window stays"
    );
    assert_eq!(wizard_state(&setup).await?["error"], Value::Null);
    let s = run_step(&setup, "wizard_finish", "recovery_note").await?;
    assert_eq!(s["step"], "instances");
    assert_eq!(credential::current_purpose(&handle), None);
    // The double click: the second finish names the step the first one left.
    let s = run_step(&setup, "wizard_finish", "recovery_note").await?;
    assert_eq!(
        (s["step"].clone(), s["error"]["class"].clone()),
        (json!("instances"), json!("wrong_step"))
    );
    assert_eq!(
        call(&setup, "wizard_begin", json!({})).await,
        Err(json!({"kind": "not_ready"})),
        "no second GENESIS"
    );
    let s = run_step(&setup, "wizard_skip_instances", "cli").await?;
    assert_eq!(
        (s["step"].clone(), s["error"]["class"].clone()),
        (json!("instances"), json!("wrong_step"))
    );
    let s = run_step(&setup, "wizard_skip_instances", "instances").await?;
    assert_eq!(s["step"], "cli");
    let s = run_step(&setup, "wizard_skip_instances", "instances").await?;
    assert_eq!(
        (s["step"].clone(), s["error"]["class"].clone()),
        (json!("cli"), json!("wrong_step")),
        "a repeated skip does not touch the CLI step"
    );
    let s = run_step(&setup, "wizard_finish", "cli").await?;
    assert_eq!(s["step"], "onboarding");
    // The double click on the CLI step's Continue must not skip the onboarding step.
    let s = run_step(&setup, "wizard_finish", "cli").await?;
    assert_eq!(
        (s["step"].clone(), s["error"]["class"].clone()),
        (json!("onboarding"), json!("wrong_step"))
    );
    let s = run_step(&setup, "wizard_finish", "onboarding").await?;
    assert_eq!(s["step"], "done");
    assert_eq!(
        call(&setup, "wizard_finish", json!({"step": "done"})).await,
        Err(json!({"kind": "not_ready"}))
    );
    // Requests are answered normally now (no instance yet: `no_instance`, §4.3).
    let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
    assert_ne!(reason(&reply.envelope), Some("first_run"));
    drop(c);
    stop(&app).await
}

/// M2 handoff: `new_ids()` before every `create_new_store` attempt. A first attempt that fails
/// (the keychain refuses its canary) creates nothing and leaves the wizard at the passphrase step
/// with the failure's class and the credential window closed; the next attempt uses other ids, and
/// its `GENESIS` and the pinned file carry those.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_ids_before_every_create_attempt() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let (app, setup) = m.app()?;
    let handle = app.handle().clone();
    run(&setup, "wizard_use_default_dir").await?;
    until(&setup, "the gate serves", |s| s["refused_count"] == 0).await?;
    m.ring
        .fail_next(KeyOpKind::Set, None, KeyStoreError::Unavailable, 1);
    run(&setup, "wizard_begin").await?;
    assert_eq!(
        type_passphrase(&app, PASSPHRASE).await,
        Ok(json!({"accepted": {}}))
    );
    let s = until(&setup, "the first attempt failed", |s| {
        !s["error"].is_null()
    })
    .await?;
    // Back at the anchor-dir step (M10 T15), which offers Begin again.
    assert_eq!(s["step"], "anchor_dir");
    assert_eq!(s["error"]["class"], "keychain_unavailable", "{s}");
    assert_eq!(s["passphrase_window"], false);
    assert_eq!(
        credential::current_purpose(&handle),
        None,
        "the window closed"
    );
    let data = local(&m.default_dir)?;
    assert!(!data.path().join("audit.db").exists(), "nothing created");
    let first = m.keys.ids();
    assert_eq!(first.len(), 1);

    // The second attempt (straight through serve: the mock runtime cannot build a second
    // credential window in one app).
    let state = serving(&app).ok_or("not serving")?;
    let pins = m.pins.clone();
    let file = m.pinned_file.clone();
    let pinned = read_pinned(&file)?.ok_or("no pinned file")?;
    let pin: PinWriter = Box::new(move |id| {
        if let Ok(mut calls) = pins.lock() {
            calls.push(PinCall {
                install_id: id.map(str::to_owned),
                data_dir_existed: true,
            });
        }
        paths::write_pinned(
            &file,
            &PinnedPaths {
                install_id: id.map(str::to_owned),
                ..pinned.clone()
            },
        )
        .map_err(|_| "io")
    });
    let pair = FirstRunPassphrase {
        passphrase: SecretString::from(PASSPHRASE),
        confirm: SecretString::from(PASSPHRASE),
    };
    serve::create_first_store(&state, pair, None, None, pin)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let ids = m.keys.ids();
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert_ne!(ids[0], ids[1], "new ids for the second attempt");
    let genesis_id = state.note_facts().map(|f| f.0).ok_or("no store")?;
    assert_eq!(genesis_id, ids[1]);
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        Some(ids[1].clone())
    );
    // A third attempt finds a serving core.
    let pair = FirstRunPassphrase {
        passphrase: SecretString::from(PASSPHRASE),
        confirm: SecretString::from(PASSPHRASE),
    };
    assert_eq!(
        serve::create_first_store(&state, pair, None, None, Box::new(|_| Ok(()))).await,
        Err(FirstStoreFailure::NotFirstRun)
    );
    stop(&app).await
}

/// §8.6 (L39, v1 keychain mode only): on Linux without a usable Secret Service the wizard stops
/// before any id exists, with the fixed text and Quit only; nothing is written (no keyring call,
/// no store, the pinned file without an id) and the first-run gate keeps answering. The answer is
/// injected, so this runs on every OS.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn linux_no_secret_service_stops_with_text() -> TestResult {
    let tmp = scratch()?;
    let mut m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    m.secret_service = Some(SecretService::Missing);
    let (app, setup) = m.app()?;
    run(&setup, "wizard_use_default_dir").await?;
    let s = until(&setup, "the gate serves", |s| s["refused_count"] == 0).await?;
    assert_eq!(s["secret_service"], "missing", "the page can warn early");
    let s = run(&setup, "wizard_begin").await?;
    assert_eq!(s["step"], "stopped");
    assert_eq!(s["stopped_text"], MSG_NEEDS_SECRET_SERVICE);
    assert_eq!(s["passphrase_window"], false);
    assert_eq!(credential::current_purpose(app.handle()), None);
    assert!(m.ring.ops().is_empty(), "no keyring call");
    assert!(m.keys.ids().is_empty(), "no install id");
    let data = local(&m.default_dir)?;
    assert!(!data.path().join("audit.db").exists());
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        None
    );
    for (cmd, body) in [
        ("wizard_begin", json!({})),
        ("wizard_skip_instances", json!({"step": "stopped"})),
        ("wizard_finish", json!({"step": "stopped"})),
    ] {
        assert_eq!(
            call(&setup, cmd, body).await,
            Err(json!({"kind": "not_ready"})),
            "{cmd}"
        );
    }
    let mut c = connect(&m, &data).await?;
    let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
    assert_eq!(reason(&reply.envelope), Some("first_run"));
    drop(c);
    stop(&app).await
}

/// §8.6 (L39): the keyring's directories are checked before the passphrase is asked for. A keyring
/// that is not local stops the wizard at that step with the §8.7 text and Quit only: no credential
/// window, no id, no keyring call, no store; the first-run gate keeps answering. The check is
/// injected, so this runs on every OS.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keyring_not_local_stops_before_the_passphrase() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    m.ring.set_locality(KeyringLocality::NotLocal {
        dir: m.root.join("home-on-nfs"),
    });
    let (app, setup) = m.app()?;
    run(&setup, "wizard_use_default_dir").await?;
    until(&setup, "the gate serves", |s| s["refused_count"] == 0).await?;
    let s = run(&setup, "wizard_begin").await?;
    assert_eq!(s["step"], "stopped", "{s}");
    assert_eq!(s["stopped_text"], MSG_KEYRING_NOT_LOCAL);
    assert_eq!(s["passphrase_window"], false);
    assert_eq!(s["error"], Value::Null);
    assert_eq!(credential::current_purpose(app.handle()), None);
    assert!(m.ring.ops().is_empty(), "no keyring call");
    assert!(m.keys.ids().is_empty(), "no install id");
    let data = local(&m.default_dir)?;
    assert!(!data.path().join("audit.db").exists());
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        None
    );
    // Sticky: Begin again does not ask either, and nothing else moves on.
    for (cmd, body) in [
        ("wizard_begin", json!({})),
        ("wizard_skip_instances", json!({"step": "stopped"})),
        ("wizard_finish", json!({"step": "stopped"})),
    ] {
        assert_eq!(
            call(&setup, cmd, body).await,
            Err(json!({"kind": "not_ready"})),
            "{cmd}"
        );
    }
    assert_eq!(credential::current_purpose(app.handle()), None);
    let mut c = connect(&m, &data).await?;
    let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
    assert_eq!(reason(&reply.envelope), Some("first_run"));
    drop(c);
    stop(&app).await
}

/// The negative control of the above: a keyring that is local, or whose locality cannot be told
/// (`Unknown`: the store's own check at `GENESIS` is the backstop, a retry can succeed), goes on to
/// the passphrase.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_or_unknown_keyring_goes_on_to_the_passphrase() -> TestResult {
    let tmp = scratch()?;
    for (host, locality) in [
        ("host-a", KeyringLocality::Local),
        (
            "host-b",
            KeyringLocality::Unknown {
                reason: "no keyring directories to check".into(),
            },
        ),
    ] {
        let m = Machine::new(&tmp, host, None, MemKeyring::new())?;
        m.ring.set_locality(locality);
        let (app, setup) = m.app()?;
        run(&setup, "wizard_use_default_dir").await?;
        until(&setup, "the gate serves", |s| s["refused_count"] == 0).await?;
        let s = run(&setup, "wizard_begin").await?;
        assert_eq!(
            (s["step"].clone(), s["passphrase_window"].clone()),
            (json!("passphrase"), json!(true)),
            "{host}"
        );
        assert_eq!(
            credential::current_purpose(app.handle()),
            Some(Purpose::RecoveryPassphrase)
        );
        stop(&app).await?;
    }
    Ok(())
}

/// PD-77: the passphrase is asked for only once the first-run gate serves. While the start after
/// step 0 is still opening the data dir, the wizard shows the (1b) anchor-dir step (M10 T15) but
/// Begin opens no window (a pair taken then could only fail), and no restore starts (it needs the
/// first-run gate's serving state).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn begin_waits_for_the_first_run_gate() -> TestResult {
    let tmp = scratch()?;
    let mut m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    m.idle_start = true;
    let (app, setup) = m.app()?;
    let s = run(&setup, "wizard_use_default_dir").await?;
    assert_eq!(s["step"], "anchor_dir");
    assert_eq!(s["refused_count"], Value::Null, "nothing serves yet");
    assert_eq!(windows::snapshot(app.handle()), AppSnapshot::BeforeFirstRun);
    // Nor does the anchor-dir dialog come up before the gate serves (T15 review M-9).
    for cmd in [
        "wizard_begin",
        "wizard_restore",
        "wizard_anchor_dir",
        "wizard_anchor_dir_clear",
    ] {
        assert_eq!(
            call(&setup, cmd, json!({})).await,
            Err(json!({"kind": "not_ready"})),
            "{cmd}"
        );
    }
    assert_eq!(m.anchor_dialogs.load(Ordering::SeqCst), 0);
    assert_eq!(credential::current_purpose(app.handle()), None);
    assert_eq!(wizard_state(&setup).await?["passphrase_window"], false);
    Ok(())
}

// ---------- RF-3b ----------

/// `config.toml` as machine A's app left it (it gave each instance its random id, §7.1).
fn roamed_config() -> &'static str {
    "schema_version = 1\nwritten_by = \"0.1.0\"\n\n\
     [[instances]]\nalias = \"jira-main\"\nproduct = \"jira\"\n\
     base_url = \"https://jira.rf3b.invalid/jira\"\ndefault = true\n\
     id = \"ins_0216b43a41fa400ed08f3a63dfc71303\"\n\n\
     [[instances]]\nalias = \"wiki\"\nproduct = \"confluence\"\n\
     base_url = \"https://wiki.rf3b.invalid/confluence\"\ndefault = true\n\
     id = \"ins_4fdf7f468442c928ebb5970da1371382\"\n"
}

/// Every file under a dir with its bytes.
type DirFiles = Vec<(PathBuf, Vec<u8>)>;

/// The files under `dir`, with their bytes.
fn snapshot_dir(dir: &Path) -> Result<DirFiles, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d)? {
            let e = e?;
            if e.file_type()?.is_dir() {
                todo.push(e.path());
            } else {
                out.push((e.path(), std::fs::read(e.path())?));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// RF-3b (§7.7, §7.1, §8.6): a `config.toml` roamed from machine A, with two instances, over a
/// keyring both machines share. Machine B has no pinned file of its own, so it runs the wizard: its
/// own data dir, its own store (new ids), and both roamed instances are `instance_unconfirmed` (B's
/// store holds no origin) until B confirms each natively, then `needs_token` (no PAT of A's is
/// used). B writes only its own pinned file and keyring entries; A's files, entries and the roamed
/// config are untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf3b_roamed_config_second_machine() -> TestResult {
    let tmp = scratch()?;
    let shared_config = tmp.path().join("roaming-config");
    std::fs::create_dir(&shared_config)?;
    std::fs::write(shared_config.join("config.toml"), roamed_config())?;
    let ring = MemKeyring::new();

    // Machine A: its store, its pinned file.
    let a = Machine::new(&tmp, "host-a", Some(shared_config.clone()), ring.clone())?;
    let id_a = a.provision(&a.default_dir)?;
    paths::write_pinned(
        &a.pinned_file,
        &PinnedPaths {
            schema_version: paths::PINNED_SCHEMA_VERSION,
            data_dir: a.default_dir.clone(),
            config_dir: shared_config.clone(),
            install_id: Some(id_a.clone()),
        },
    )?;
    let a_home = snapshot_dir(&a.root.join("home"))?;
    let a_data = snapshot_dir(&a.default_dir)?;
    let config = std::fs::read(shared_config.join("config.toml"))?;
    let ops_before = ring.ops().len();

    // Machine B runs the wizard.
    let b = Machine::new(&tmp, "host-b", Some(shared_config.clone()), ring.clone())?;
    let (app, setup) = b.app()?;
    run(&setup, "wizard_use_default_dir").await?;
    until(&setup, "B's gate serves", |s| s["refused_count"] == 0).await?;
    run(&setup, "wizard_begin").await?;
    assert_eq!(
        type_passphrase(&app, PASSPHRASE).await,
        Ok(json!({"accepted": {}}))
    );
    until(&setup, "B's GENESIS", step_is("recovery_note")).await?;
    let s = run_step(&setup, "wizard_finish", "recovery_note").await?;
    assert_eq!(s["step"], "instances", "{s}");
    let states = |s: &Value| -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = s["instances"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|i| {
                        (
                            i["alias"].as_str().unwrap_or_default().to_owned(),
                            i["state"].as_str().unwrap_or_default().to_owned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    };
    assert_eq!(
        states(&s),
        [
            ("jira-main".to_owned(), "instance_unconfirmed".to_owned()),
            ("wiki".to_owned(), "instance_unconfirmed".to_owned()),
        ]
    );
    // B confirms each roamed origin natively (the setup window holds the command).
    for alias in ["jira-main", "wiki"] {
        let v = call(&setup, "instance_confirm_config", json!({ "alias": alias }))
            .await
            .map_err(|e| format!("instance_confirm_config: {e}"))?;
        assert_eq!(v["state"], "needs_token", "{v}");
    }
    assert_eq!(b.confirmer.0.lock().map(|t| t.len()).unwrap_or(0), 2);
    let s = wizard_state(&setup).await?;
    assert_eq!(
        states(&s),
        [
            ("jira-main".to_owned(), "needs_token".to_owned()),
            ("wiki".to_owned(), "needs_token".to_owned()),
        ]
    );

    let state = serving(&app).ok_or("not serving")?;
    let id_b = state.note_facts().map(|f| f.0).ok_or("no store")?;
    assert_ne!(id_b, id_a);
    // B's own pinned file, B's own data dir.
    let pinned_b = read_pinned(&b.pinned_file)?.ok_or("no pinned file for B")?;
    assert_eq!(
        (pinned_b.data_dir.clone(), pinned_b.install_id.clone()),
        (b.default_dir.clone(), Some(id_b.clone()))
    );
    assert_eq!(pinned_b.config_dir, shared_config);
    // Nothing of A's changed.
    assert_eq!(
        snapshot_dir(&a.root.join("home"))?,
        a_home,
        "A's pinned file"
    );
    assert_eq!(snapshot_dir(&a.default_dir)?, a_data, "A's data dir");
    assert_eq!(std::fs::read(shared_config.join("config.toml"))?, config);
    let ops = ring.ops();
    let b_ops = &ops[ops_before..];
    assert!(!b_ops.is_empty());
    for op in b_ops {
        assert!(
            op.full_name.contains(&id_b) && !op.full_name.contains(&id_a),
            "B touched {op:?}"
        );
    }
    assert!(b.keys.ids().iter().all(|id| *id == id_b));
    stop(&app).await
}

// ---------- after "Archive old DB and start fresh" ----------

/// T20 review I-1 (§8.7): the `ArchivedDb` of "Archive old DB and start fresh" is held in memory
/// only; when it is gone (the app quit or crashed before the wizard's `GENESIS`), the wizard derives
/// it again from the archive folder, so the new `GENESIS` still names the archived chain. The
/// pinned file loses the old store's `install_id` before `GENESIS` and names the new one after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archived_db_is_derived_again_for_genesis() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let old_id = m.provision(&m.default_dir)?;
    m.ring.wipe_install(&old_id);
    let pinned = PinnedPaths {
        schema_version: paths::PINNED_SCHEMA_VERSION,
        data_dir: m.default_dir.clone(),
        config_dir: m.config_dir.clone(),
        install_id: Some(old_id.clone()),
    };
    paths::write_pinned(&m.pinned_file, &pinned)?;

    // A pinned start (`Ready`): keychain_lost, then the archive (its answer is not kept).
    let context = tauri::generate_context!(assets = tauri::test::noop_assets(), test = true);
    let app = commands::register(mock_builder()).build(context)?;
    app.manage(WindowRegistry::new(
        NavPolicy::for_this_platform(None),
        StartupRoute::completed(),
    ));
    app.manage(AppState::new(StartupSummary::Ready, None));
    app.manage(Wizard::new(m.env(), Some(pinned.clone())));
    let data = local(&m.default_dir)?;
    let lock = Arc::new(InstanceLock::acquire(&data, m.host)?);
    app.manage(DataDirHold::new(data.clone(), lock.clone()));
    app.manage(ServeSlot::default());
    let inputs = m
        .starter()
        .inputs(app.handle(), data.clone(), lock, &pinned)?;
    let state = start_with(inputs).await.map_err(|e| format!("{e:?}"))?;
    if let Some(slot) = app.try_state::<ServeSlot>() {
        slot.set(state.clone());
    }
    let archived = serve::archive_and_start_fresh(&state)
        .await
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(state.gate_state(), Some(GateState::FirstRun));

    let setup = window(&app, "setup")?;
    let s = wizard_state(&setup).await?;
    assert_eq!(s["step"], "anchor_dir", "{s}");
    run(&setup, "wizard_begin").await?;
    assert_eq!(
        type_passphrase(&app, PASSPHRASE).await,
        Ok(json!({"accepted": {}}))
    );
    until(&setup, "GENESIS", step_is("recovery_note")).await?;

    let new_id = state.note_facts().map(|f| f.0).ok_or("no store")?;
    assert_ne!(new_id, old_id);
    let genesis: Value = {
        let store = state.store.lock().map_err(|_| "poisoned")?;
        let store = store.as_ref().ok_or("no store")?;
        serde_json::from_slice(&store.read_payload(1)?)?
    };
    assert_eq!(
        genesis["archived_db"],
        json!({
            "file": archived.file,
            "chain_id": archived.chain_id,
            "head_seq": archived.head_seq,
            "head_hash": hex(&archived.head_hash),
        })
    );
    assert_eq!(
        m.pins()
            .iter()
            .map(|p| p.install_id.clone())
            .collect::<Vec<_>>(),
        [None, Some(new_id.clone())],
        "the old id goes before GENESIS"
    );
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        Some(new_id)
    );
    serve::shutdown(&state, ShutdownReason::Quit, WAIT).await;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------- M10 T15: the anchor-dir step, the restore alternative, the pin retry ----------

/// The payloads of every record of type `t` of the store `state` serves.
fn payloads(state: &ServeState, t: EventType) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let store = state.open_store().ok_or("no store")?;
    let page = store.query(
        &AuditFilter {
            event_types: vec![t],
            ..AuditFilter::default()
        },
        AuditCursor::first(MAX_AUDIT_PAGE_ROWS),
    )?;
    let mut out = Vec::new();
    for row in page.rows {
        out.push(serde_json::from_slice(&store.read_payload(row.seq)?)?);
    }
    Ok(out)
}

/// The `CONFIG_CHANGED` payload of setting `key`.
fn config_changed(state: &ServeState, key: &str) -> Result<Value, Box<dyn std::error::Error>> {
    payloads(state, EventType::CONFIG_CHANGED)?
        .into_iter()
        .find(|p| p["key"] == key)
        .ok_or_else(|| format!("no CONFIG_CHANGED {{key: {key}}}").into())
}

/// The machine's wizard at the anchor-dir step, the first-run gate serving.
async fn at_anchor_step(
    m: &Machine,
) -> Result<(App<MockRuntime>, WebviewWindow<MockRuntime>), Box<dyn std::error::Error>> {
    let (app, setup) = m.app()?;
    run(&setup, "wizard_use_default_dir").await?;
    until(&setup, "the anchor-dir step", |s| {
        s["step"] == "anchor_dir" && s["refused_count"] == 0
    })
    .await?;
    Ok((app, setup))
}

/// Every entry of `dir` (empty when it holds nothing).
fn entries(dir: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut out = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()?;
    out.sort();
    Ok(out)
}

/// §2.5 (1b) order (M10 T15): the optional anchor directory is the first (1b) step, before the
/// passphrase. Its folder comes from Rust's own dialog and is shown as text, with no confirmation
/// (nothing is weakened at first run) and nothing written into it before `GENESIS`; a path the
/// store would refuse (not absolute) is refused at once and nothing is kept; Clear drops the
/// choice; a cancelled dialog changes nothing. Begin goes on to the passphrase, and the anchor
/// commands are not offered while the passphrase window waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anchor_dir_step_before_passphrase() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let anchors = m.root.join("anchors");
    std::fs::create_dir(&anchors)?;
    let (app, setup) = at_anchor_step(&m).await?;
    let s = wizard_state(&setup).await?;
    assert_eq!(
        (s["anchor_dir"].clone(), s["passphrase_window"].clone()),
        (Value::Null, json!(false))
    );
    assert_eq!(credential::current_purpose(app.handle()), None);
    // The step does not move on by itself, nor by the later steps' commands.
    for cmd in ["wizard_skip_instances", "wizard_finish"] {
        assert_eq!(
            call(&setup, cmd, json!({"step": "anchor_dir"})).await,
            Err(json!({"kind": "not_ready"})),
            "{cmd}"
        );
    }
    // A cancelled dialog: nothing.
    let s = run(&setup, "wizard_anchor_dir").await?;
    assert_eq!(m.anchor_dialogs.load(Ordering::SeqCst), 1);
    assert_eq!(
        (
            s["step"].clone(),
            s["anchor_dir"].clone(),
            s["error"].clone()
        ),
        (json!("anchor_dir"), Value::Null, Value::Null)
    );
    // A path `create_new_store` would refuse: refused here, nothing kept.
    *m.pick_anchor.lock().map_err(|_| "poisoned")? = Some(PathBuf::from("relative/anchors"));
    let s = run(&setup, "wizard_anchor_dir").await?;
    assert_eq!(s["error"]["class"], "anchor_dir_invalid", "{s}");
    assert_eq!(s["anchor_dir"], Value::Null);
    // The data dir, or a folder inside it: refused with a fixed text, nothing kept (§8.5, T15
    // review M-11: a log anchored in its own data dir proves nothing).
    let inside = m.default_dir.join("anchors");
    std::fs::create_dir(&inside)?;
    for refused in [m.default_dir.clone(), inside] {
        *m.pick_anchor.lock().map_err(|_| "poisoned")? = Some(refused.clone());
        let s = run(&setup, "wizard_anchor_dir").await?;
        assert_eq!(
            (s["error"].clone(), s["anchor_dir"].clone()),
            (
                json!({"class": "anchor_dir", "text": wizard::ANCHOR_DIR_IN_DATA_DIR}),
                Value::Null
            ),
            "{}",
            refused.display()
        );
    }
    // A folder: shown as text, no native confirmation, nothing written there yet.
    *m.pick_anchor.lock().map_err(|_| "poisoned")? = Some(anchors.clone());
    let s = run(&setup, "wizard_anchor_dir").await?;
    assert_eq!(
        (
            s["step"].clone(),
            s["anchor_dir"].clone(),
            s["error"].clone()
        ),
        (
            json!("anchor_dir"),
            json!(anchors.display().to_string()),
            Value::Null
        )
    );
    assert!(m.confirmer.0.lock().map_err(|_| "poisoned")?.is_empty());
    assert!(entries(&anchors)?.is_empty());
    // Clear drops it; the dialog chooses it again.
    let s = run(&setup, "wizard_anchor_dir_clear").await?;
    assert_eq!(s["anchor_dir"], Value::Null);
    let s = run(&setup, "wizard_anchor_dir").await?;
    assert_eq!(s["anchor_dir"], anchors.display().to_string());
    // Begin: the passphrase step, the chosen folder still shown.
    let s = run(&setup, "wizard_begin").await?;
    assert_eq!(
        (s["step"].clone(), s["passphrase_window"].clone()),
        (json!("passphrase"), json!(true))
    );
    assert_eq!(s["anchor_dir"], anchors.display().to_string());
    for cmd in [
        "wizard_anchor_dir",
        "wizard_anchor_dir_clear",
        "wizard_restore",
    ] {
        assert_eq!(
            call(&setup, cmd, json!({})).await,
            Err(json!({"kind": "not_ready"})),
            "{cmd}"
        );
    }
    assert_eq!(
        m.anchor_dialogs.load(Ordering::SeqCst),
        6,
        "no dialog after Begin"
    );
    assert!(entries(&anchors)?.is_empty(), "nothing before GENESIS");
    stop(&app).await
}

/// PD-167, §8.5 (M10 T15): the anchor directory chosen at the anchor-dir step reaches
/// `create_new_store` (`FirstRunInput.anchor_dir`): `GENESIS` is followed by `CONFIG_CHANGED {key:
/// anchor_dir, old: null, new: <dir>}` and the new chain's file starts in that folder with its
/// header; with no previous chain there, no incident and no notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anchor_dir_passed_to_genesis() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let anchors = m.root.join("anchors");
    std::fs::create_dir(&anchors)?;
    let (app, setup) = at_anchor_step(&m).await?;
    *m.pick_anchor.lock().map_err(|_| "poisoned")? = Some(anchors.clone());
    run(&setup, "wizard_anchor_dir").await?;
    run(&setup, "wizard_begin").await?;
    assert_eq!(
        type_passphrase(&app, PASSPHRASE).await,
        Ok(json!({"accepted": {}}))
    );
    let s = until(&setup, "GENESIS", step_is("recovery_note")).await?;
    assert_eq!(s["notice"], Value::Null, "{s}");
    let state = serving(&app).ok_or("not serving")?;
    let setting = config_changed(&state, "anchor_dir")?;
    assert_eq!(setting["old"], Value::Null, "{setting}");
    assert_eq!(setting["new"], anchors.display().to_string(), "{setting}");
    let store = state.open_store().ok_or("no store")?;
    assert!(store.open_incidents().is_empty());
    assert!(
        store.testing_anchor_dir_drain(),
        "the anchor lines were written"
    );
    let chain = store.head().2;
    let file = anchors.join(format!("{chain}.jsonl"));
    let text = std::fs::read_to_string(&file)?;
    let header: Value = serde_json::from_str(text.lines().next().ok_or("an empty chain file")?)?;
    assert_eq!(header["install_id"], store.install_id(), "{header}");
    stop(&app).await
}

/// PD-167 (M10 T15): when the chosen anchor directory already holds a log of this computer and
/// user, `GENESIS` records the previous-chain incident and the wizard says so with the plan's
/// text, from the first store on (also after the recovery note); nothing before `GENESIS` says it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn previous_chain_text_shown_after_genesis() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let anchors = m.root.join("anchors");
    std::fs::create_dir(&anchors)?;
    // An earlier store of this computer and user wrote its chain file into the folder.
    m.provision_with(&m.root.join("earlier-data"), Some(&anchors), |_| Ok(()))?;
    let earlier = entries(&anchors)?;
    assert_eq!(earlier.len(), 1, "{earlier:?}");
    let (app, setup) = at_anchor_step(&m).await?;
    *m.pick_anchor.lock().map_err(|_| "poisoned")? = Some(anchors.clone());
    let s = run(&setup, "wizard_anchor_dir").await?;
    assert_eq!(s["notice"], Value::Null);
    run(&setup, "wizard_begin").await?;
    assert_eq!(
        type_passphrase(&app, PASSPHRASE).await,
        Ok(json!({"accepted": {}}))
    );
    let s = until(&setup, "GENESIS", step_is("recovery_note")).await?;
    assert_eq!(s["notice"], wizard::MSG_PREVIOUS_CHAIN_FOUND, "{s}");
    assert_eq!(
        wizard::MSG_PREVIOUS_CHAIN_FOUND,
        "The anchor directory already holds an atlas-duck log of this computer and user. This was recorded as an integrity incident; see Audit."
    );
    let state = serving(&app).ok_or("not serving")?;
    let incidents = state.open_store().ok_or("no store")?.open_incidents();
    assert_eq!(incidents.len(), 1, "{incidents:?}");
    let verify = payloads(&state, EventType::VERIFY)?;
    assert!(
        verify.iter().any(|v| v["result"] == "previous_chain_found"),
        "{verify:?}"
    );
    let s = run_step(&setup, "wizard_finish", "recovery_note").await?;
    assert_eq!(
        (s["step"].clone(), s["notice"].clone()),
        (json!("instances"), json!(wizard::MSG_PREVIOUS_CHAIN_FOUND))
    );
    stop(&app).await
}

/// PD-167 (M10 T15): an anchor directory the store cannot check at `GENESIS` (here a file, not a
/// folder) refuses the first store with nothing written; the wizard is back at the anchor-dir step
/// with the store's own fixed text (no path), and a cleared choice lets `GENESIS` go through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_anchor_dir_comes_back_with_its_text() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let not_a_folder = m.root.join("anchors.txt");
    std::fs::write(&not_a_folder, b"x")?;
    let (app, setup) = at_anchor_step(&m).await?;
    *m.pick_anchor.lock().map_err(|_| "poisoned")? = Some(not_a_folder.clone());
    run(&setup, "wizard_anchor_dir").await?;
    run(&setup, "wizard_begin").await?;
    assert_eq!(
        type_passphrase(&app, PASSPHRASE).await,
        Ok(json!({"accepted": {}}))
    );
    let s = until(&setup, "the refusal", |s| !s["error"].is_null()).await?;
    assert_eq!(s["step"], "anchor_dir", "{s}");
    assert_eq!(
        s["error"],
        json!({"class": "anchor_dir", "text": "the anchor directory is not a directory"})
    );
    assert_eq!(s["anchor_dir"], not_a_folder.display().to_string());
    let data = local(&m.default_dir)?;
    assert!(!data.path().join("audit.db").exists(), "nothing created");
    assert_eq!(std::fs::read(&not_a_folder)?, b"x");
    // Without it, the next attempt (straight through serve: one credential window per mock app)
    // writes `GENESIS`.
    let s = run(&setup, "wizard_anchor_dir_clear").await?;
    assert_eq!(
        (s["anchor_dir"].clone(), s["error"].clone()),
        (Value::Null, Value::Null)
    );
    let state = serving(&app).ok_or("not serving")?;
    let pair = FirstRunPassphrase {
        passphrase: SecretString::from(PASSPHRASE),
        confirm: SecretString::from(PASSPHRASE),
    };
    let first = serve::create_first_store(&state, pair, None, None, Box::new(|_| Ok(())))
        .await
        .map_err(|e| format!("{e:?}"))?;
    assert!(first.pin_written && !first.previous_chain_found);
    stop(&app).await
}

/// PD-171 (M10 T15): the proof of the native "Archive old DB and start fresh" confirmation the
/// credential window answered is kept by the serving state until the first store: `GENESIS` is
/// followed by `CONFIG_CHANGED {key: archive_and_start_fresh, archived_db_file,
/// dialog_text_sha256}` naming the archived file and the hash of the text the dialog showed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_confirmation_survives_from_credential_window_to_first_store() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let old_id = m.provision(&m.default_dir)?;
    m.ring.wipe_install(&old_id);
    let pinned = PinnedPaths {
        schema_version: paths::PINNED_SCHEMA_VERSION,
        data_dir: m.default_dir.clone(),
        config_dir: m.config_dir.clone(),
        install_id: Some(old_id.clone()),
    };
    paths::write_pinned(&m.pinned_file, &pinned)?;
    let context = tauri::generate_context!(assets = tauri::test::noop_assets(), test = true);
    let app = commands::register(mock_builder()).build(context)?;
    app.manage(WindowRegistry::new(
        NavPolicy::for_this_platform(None),
        StartupRoute::completed(),
    ));
    app.manage(AppState::new(StartupSummary::Ready, None));
    app.manage(Wizard::new(m.env(), Some(pinned.clone())));
    let data = local(&m.default_dir)?;
    let lock = Arc::new(InstanceLock::acquire(&data, m.host)?);
    app.manage(DataDirHold::new(data.clone(), lock.clone()));
    app.manage(ServeSlot::default());
    let inputs = m
        .starter()
        .inputs(app.handle(), data.clone(), lock, &pinned)?;
    let state = start_with(inputs).await.map_err(|e| format!("{e:?}"))?;
    if let Some(slot) = app.try_state::<ServeSlot>() {
        slot.set(state.clone());
    }
    // The locked window's "Archive old DB and start fresh".
    let handle = app.handle().clone();
    tokio::task::spawn_blocking(move || {
        credential::open(&handle, Purpose::RecoverThisLog, windows::Show::Focus)
    })
    .await?
    .map_err(|e| format!("{e:?}"))?;
    let w = window(&app, "credential")?;
    let answer = run(&w, "archive_and_start_fresh").await?;
    let archived_file = answer["archived"]["archived_file"].clone();
    assert!(archived_file.is_string(), "{answer}");
    assert_eq!(state.gate_state(), Some(GateState::FirstRun));
    let shown = serve::archive_confirm_text(&data);
    assert_eq!(
        *m.confirmer.0.lock().map_err(|_| "poisoned")?,
        std::slice::from_ref(&shown)
    );

    // The first store (straight through serve: one credential window per mock app).
    let archived = credential::take_archived(app.handle());
    assert!(archived.is_some());
    let pair = FirstRunPassphrase {
        passphrase: SecretString::from(PASSPHRASE),
        confirm: SecretString::from(PASSPHRASE),
    };
    serve::create_first_store(&state, pair, archived, None, Box::new(|_| Ok(())))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let record = config_changed(&state, "archive_and_start_fresh")?;
    assert_eq!(record["archived_db_file"], archived_file, "{record}");
    assert_eq!(
        record["dialog_text_sha256"],
        atlas_duck_core::payloads::sha256_hex(shown.as_bytes()),
        "{record}"
    );
    serve::shutdown(&state, ShutdownReason::Quit, WAIT).await;
    Ok(())
}

/// M6 final review M-9 (M10 T15): a pinned file that cannot name the new store's `install_id`
/// after `GENESIS` is no longer passed over: the wizard stops at `pin_retry` with the plan's text,
/// no later step moves on, Begin writes it again (a failed retry says so and stays), and once it
/// is written the wizard goes on with the recovery note.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pin_write_failure_offers_retry() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let (app, setup) = at_anchor_step(&m).await?;
    m.pin_fail.store(1, Ordering::SeqCst);
    run(&setup, "wizard_begin").await?;
    assert_eq!(
        type_passphrase(&app, PASSPHRASE).await,
        Ok(json!({"accepted": {}}))
    );
    let s = until(&setup, "the pin retry", step_is("pin_retry")).await?;
    assert_eq!(s["step_text"], wizard::MSG_PIN_WRITE_FAILED, "{s}");
    assert_eq!(
        wizard::MSG_PIN_WRITE_FAILED,
        "Could not record this installation's id. Try again"
    );
    let state = serving(&app).ok_or("not serving")?;
    assert!(state.core.get().is_some(), "the store serves");
    let new_id = state.note_facts().map(|f| f.0).ok_or("no store")?;
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        None
    );
    // Nothing else moves on.
    for (cmd, step) in [
        ("wizard_finish", "recovery_note"),
        ("wizard_skip_instances", "instances"),
        ("wizard_finish", "cli"),
    ] {
        let s = run_step(&setup, cmd, step).await?;
        assert_eq!(
            (s["step"].clone(), s["error"]["class"].clone()),
            (json!("pin_retry"), json!("wrong_step")),
            "{cmd} {step}"
        );
    }
    // A retry that fails again says so and stays.
    m.pin_fail.store(1, Ordering::SeqCst);
    let s = run(&setup, "wizard_begin").await?;
    assert_eq!(
        (s["step"].clone(), s["error"]["class"].clone()),
        (json!("pin_retry"), json!("pinned_write"))
    );
    // The next one writes it: the note step follows (its window is still open).
    let s = run(&setup, "wizard_begin").await?;
    assert_eq!(s["step"], "recovery_note", "{s}");
    assert_eq!(s["step_text"], Value::Null);
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        Some(new_id.clone())
    );
    assert_eq!(
        m.pins()
            .iter()
            .map(|p| p.install_id.clone())
            .collect::<Vec<_>>(),
        [
            None,
            None,
            Some(new_id.clone()),
            Some(new_id.clone()),
            Some(new_id)
        ]
    );
    stop(&app).await
}

/// The credential window the wizard's restore opened for the backup's passphrase. The flow sets the
/// purpose before it builds the window (one `opening` lock), so the test waits for the built
/// window too: building it here a second time would race the flow's own build (which then fails
/// with no window, `io`).
async fn restore_window(
    app: &App<MockRuntime>,
) -> Result<WebviewWindow<MockRuntime>, Box<dyn std::error::Error>> {
    let handle = app.handle().clone();
    eventually(
        "the credential window asks for the backup's passphrase",
        || {
            credential::current_purpose(&handle) == Some(Purpose::RestoreBackup)
                && handle.get_webview_window("credential").is_some()
        },
    )
    .await?;
    Ok(window(app, "credential")?)
}

/// The wizard's restore driven to its end through the setup and credential windows: the
/// anchor-dir step, `wizard_restore`, the native confirmation, the file dialog, the backup's
/// passphrase in the credential window (`restore_backup`), then the instance step. Returns the
/// app, the setup window, the serving state as it was before the restore, the endpoint, and the
/// last wizard state.
async fn restored_by_wizard(
    m: &Machine,
) -> Result<
    (
        App<MockRuntime>,
        WebviewWindow<MockRuntime>,
        Arc<ServeState>,
        Value,
    ),
    Box<dyn std::error::Error>,
> {
    let bundle = m.backup_elsewhere()?;
    let (app, setup) = at_anchor_step(m).await?;
    let state = serving(&app).ok_or("not serving")?;
    *m.pick_restore.lock().map_err(|_| "poisoned")? = Some(bundle);
    let s = run(&setup, "wizard_restore").await?;
    assert_eq!(s["step"], "restore", "{s}");
    let w = restore_window(&app).await?;
    // While it runs, the other (1b) commands wait: Begin is told the restore runs, the anchor-dir
    // and restore commands belong to a step that is not shown (T15 review M-4).
    for (cmd, kind) in [
        ("wizard_begin", "busy"),
        ("wizard_anchor_dir", "not_ready"),
        ("wizard_anchor_dir_clear", "not_ready"),
        ("wizard_restore", "not_ready"),
    ] {
        assert_eq!(
            call(&setup, cmd, json!({})).await,
            Err(json!({ "kind": kind })),
            "{cmd}"
        );
    }
    assert_eq!(
        call(&w, "submit_secret", json!({ "secret": PASSPHRASE })).await,
        Ok(json!({"accepted": {}}))
    );
    let s = until(&setup, "the restored store serves", step_is("instances")).await?;
    Ok((app, setup, state, s))
}

/// PD-168 (M10 T15): "Restore from a backup" at the (1b) step is the alternative to `GENESIS`: the
/// one native confirmation is "Restore backup", the restored store holds the backup's chain and a
/// `RESTORE` (no new `GENESIS`), the first-run passphrase is never asked (no recovery-passphrase
/// window, no recovery note step), and the wizard goes on at the instances.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wizard_restore_skips_genesis_and_passphrase() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let (app, setup, state, s) = restored_by_wizard(&m).await?;
    assert_eq!(s["passphrase_window"], false);
    assert_eq!(s["error"], Value::Null, "{s}");
    assert_eq!(
        *m.confirmer.0.lock().map_err(|_| "poisoned")?,
        [atlas_duck_app_lib::restore_flow::RESTORE_CONFIRM_TEXT]
    );
    assert_eq!(m.restore_dialogs.load(Ordering::SeqCst), 1);
    assert_eq!(credential::current_purpose(app.handle()), None);
    let data = local(&m.default_dir)?;
    let types = event_types(&data)?;
    assert_eq!(
        types.iter().filter(|t| *t == "GENESIS").count(),
        1,
        "the backup's own GENESIS only: {types:?}"
    );
    assert!(types.iter().any(|t| t == "RESTORE"), "{types:?}");
    // The confirmation is recorded with the restore (PD-168).
    let record = config_changed(&state, "restore_backup")?;
    assert_eq!(
        record["dialog_text_sha256"],
        atlas_duck_core::payloads::sha256_hex(
            atlas_duck_app_lib::restore_flow::RESTORE_CONFIRM_TEXT.as_bytes()
        )
    );
    // No passphrase or GENESIS step can come any more.
    assert_eq!(
        call(&setup, "wizard_begin", json!({})).await,
        Err(json!({"kind": "not_ready"}))
    );
    stop(&app).await
}

/// L109, PD-168 (M10 T15): the restore keeps the install its keystore was built for, so before it
/// the wizard drops any pinned id and after it pins the restored store's (live) `install_id`; the
/// only keystore built is that new install's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wizard_restore_pins_live_install_id() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let (app, _setup, state, _s) = restored_by_wizard(&m).await?;
    let live = state.note_facts().map(|f| f.0).ok_or("no store")?;
    assert_eq!(m.keys.ids(), std::slice::from_ref(&live));
    let restore = payloads(&state, EventType::RESTORE)?;
    assert_eq!(
        restore.first().map(|r| r["install_id"].clone()),
        Some(json!(live.clone())),
        "{restore:?}"
    );
    assert_eq!(
        m.pins()
            .iter()
            .map(|p| p.install_id.clone())
            .collect::<Vec<_>>(),
        [None, None, Some(live.clone())]
    );
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        Some(live)
    );
    stop(&app).await
}

/// PD-168 (M10 T15): after the wizard's restore the serving state swaps in the restored store as
/// `create_first_store` does: the same serving state, a core on the restored store, the cell
/// swapped without a rebind, and a connection made before answers normally now.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wizard_restore_swaps_store_in_serve_state() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let bundle = m.backup_elsewhere()?;
    let (app, setup) = at_anchor_step(&m).await?;
    let data = local(&m.default_dir)?;
    let endpoint = read_endpoint_file(&data)?;
    let state = serving(&app).ok_or("not serving")?;
    let gate = state.cell.current();
    let mut c = connect(&m, &data).await?;
    let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
    assert_eq!(reason(&reply.envelope), Some("first_run"));
    *m.pick_restore.lock().map_err(|_| "poisoned")? = Some(bundle);
    run(&setup, "wizard_restore").await?;
    let w = restore_window(&app).await?;
    call(&w, "submit_secret", json!({ "secret": PASSPHRASE }))
        .await
        .map_err(|e| format!("submit_secret: {e}"))?;
    until(&setup, "the restored store serves", step_is("instances")).await?;
    let now = serving(&app).ok_or("not serving")?;
    assert!(Arc::ptr_eq(&now, &state), "the same serving state");
    assert!(state.core.get().is_some(), "the core serves");
    assert_eq!(state.refused(), None, "the gate is gone");
    assert!(
        !Arc::ptr_eq(&state.cell.current(), &gate),
        "the cell swapped"
    );
    assert_eq!(read_endpoint_file(&data)?, endpoint, "no rebind");
    let store = state.open_store().ok_or("no store")?;
    assert_eq!(
        Some(store.install_id().to_owned()),
        state.note_facts().map(|f| f.0)
    );
    let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
    assert_ne!(reason(&reply.envelope), Some("first_run"));
    drop(c);
    stop(&app).await
}

/// PD-168 (M10 T15): a restore cancelled at one of its questions (here the file dialog, after the
/// native confirmation) changes nothing: no credential window, no store, no pinned id, and the
/// wizard is back at the anchor-dir step with no error (the user's choice).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_wizard_restore_changes_nothing() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let (app, setup) = at_anchor_step(&m).await?;
    let s = run(&setup, "wizard_restore").await?;
    assert_eq!(s["step"], "restore", "{s}");
    let s = until(&setup, "back at the anchor-dir step", step_is("anchor_dir")).await?;
    assert_eq!(s["error"], Value::Null, "{s}");
    assert_eq!(m.restore_dialogs.load(Ordering::SeqCst), 1);
    assert_eq!(
        *m.confirmer.0.lock().map_err(|_| "poisoned")?,
        [atlas_duck_app_lib::restore_flow::RESTORE_CONFIRM_TEXT]
    );
    assert_eq!(credential::current_purpose(app.handle()), None);
    let data = local(&m.default_dir)?;
    assert!(!data.path().join("audit.db").exists());
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        None
    );
    // The ids come only after the last question (T15 review I-2): no keystore was built and the
    // pinned file was written by step 0 only.
    assert!(m.keys.ids().is_empty(), "{:?}", m.keys.ids());
    assert_eq!(m.pins().len(), 1, "{:?}", m.pins());
    // Begin still leads to the passphrase.
    let s = run(&setup, "wizard_begin").await?;
    assert_eq!(s["step"], "passphrase", "{s}");
    stop(&app).await
}

/// L109, M2 handoff (M10 T15): `new_ids()` before every restore attempt, as before every
/// `create_new_store`: an attempt that fails (the wrong passphrase) restores nothing and comes back
/// to the anchor-dir step with its class; the next attempt builds the keystore of other ids, and
/// the restored store and the pinned file carry those.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wizard_restore_calls_new_ids_before_every_attempt() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let bundle = m.backup_elsewhere()?;
    let (app, setup) = at_anchor_step(&m).await?;
    *m.pick_restore.lock().map_err(|_| "poisoned")? = Some(bundle.clone());
    run(&setup, "wizard_restore").await?;
    let w = restore_window(&app).await?;
    call(
        &w,
        "submit_secret",
        json!({ "secret": "not the backup's passphrase" }),
    )
    .await
    .map_err(|e| format!("submit_secret: {e}"))?;
    let s = until(&setup, "the first attempt failed", |s| {
        !s["error"].is_null()
    })
    .await?;
    assert_eq!(
        (s["step"].clone(), s["error"]["class"].clone()),
        (json!("anchor_dir"), json!("wrong_passphrase")),
        "{s}"
    );
    let data = local(&m.default_dir)?;
    assert!(!data.path().join("audit.db").exists(), "nothing restored");
    let first = m.keys.ids();
    assert_eq!(first.len(), 1);

    // The second attempt (straight through serve: one credential window per mock app).
    let state = serving(&app).ok_or("not serving")?;
    let pinned = read_pinned(&m.pinned_file)?.ok_or("no pinned file")?;
    let file = m.pinned_file.clone();
    let pin: PinWriter = Box::new(move |id| {
        paths::write_pinned(
            &file,
            &PinnedPaths {
                install_id: id.map(str::to_owned),
                ..pinned.clone()
            },
        )
        .map_err(|_| "io")
    });
    let first_store = serve::restore_first_store(
        &state,
        Box::new(move || Some(RustChosenPath::from_native_dialog(bundle))),
        Box::new(|_| Ok(SecretString::from(PASSPHRASE))),
        pin,
    )
    .await
    .map_err(|e| format!("{e:?}"))?;
    assert!(first_store.pin_written);
    let ids = m.keys.ids();
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert_ne!(ids[0], ids[1], "new ids for the second attempt");
    assert_eq!(state.note_facts().map(|f| f.0), Some(ids[1].clone()));
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        Some(ids[1].clone())
    );
    stop(&app).await
}

// ---------- T15 review fixes: the archive proof, cancelled and incomplete restores ----------

/// A pinned start (`Ready`) of the machine's store after "Archive old DB and start fresh".
struct ArchivedStart {
    app: App<MockRuntime>,
    setup: WebviewWindow<MockRuntime>,
    state: Arc<ServeState>,
    /// The archived store's `install_id` (the pinned file still names it).
    old_id: String,
    archived: ArchivedDb,
}

/// A store whose keychain entries are gone (`keychain_lost`), started as a pinned start does, then
/// archived as the locked window's "Archive old DB and start fresh" does: its serve half (the
/// native confirmation answered Ok, the proof kept by the serving state) and the archive kept for
/// the wizard (`credential::set_archived`, as the command keeps it). The archive goes straight
/// through serve, so the mock app's one credential window is left for the wizard.
async fn archived_start(m: &Machine) -> Result<ArchivedStart, Box<dyn std::error::Error>> {
    let old_id = m.provision(&m.default_dir)?;
    m.ring.wipe_install(&old_id);
    let pinned = PinnedPaths {
        schema_version: paths::PINNED_SCHEMA_VERSION,
        data_dir: m.default_dir.clone(),
        config_dir: m.config_dir.clone(),
        install_id: Some(old_id.clone()),
    };
    paths::write_pinned(&m.pinned_file, &pinned)?;
    let context = tauri::generate_context!(assets = tauri::test::noop_assets(), test = true);
    let app = commands::register(mock_builder()).build(context)?;
    app.manage(WindowRegistry::new(
        NavPolicy::for_this_platform(None),
        StartupRoute::completed(),
    ));
    app.manage(AppState::new(StartupSummary::Ready, None));
    app.manage(Wizard::new(m.env(), Some(pinned.clone())));
    let data = local(&m.default_dir)?;
    let lock = Arc::new(InstanceLock::acquire(&data, m.host)?);
    app.manage(DataDirHold::new(data.clone(), lock.clone()));
    app.manage(ServeSlot::default());
    let inputs = m.starter().inputs(app.handle(), data, lock, &pinned)?;
    let state = start_with(inputs).await.map_err(|e| format!("{e:?}"))?;
    if let Some(slot) = app.try_state::<ServeSlot>() {
        slot.set(state.clone());
    }
    let archived = serve::archive_and_start_fresh(&state)
        .await
        .map_err(|e| format!("{e:?}"))?;
    credential::set_archived(app.handle(), archived.clone());
    assert_eq!(state.gate_state(), Some(GateState::FirstRun));
    let setup = window(&app, "setup")?;
    until(&setup, "the anchor-dir step", step_is("anchor_dir")).await?;
    Ok(ArchivedStart {
        app,
        setup,
        state,
        old_id,
        archived,
    })
}

/// The `GENESIS` payload of the store `state` serves.
fn genesis_payload(state: &ServeState) -> Result<Value, Box<dyn std::error::Error>> {
    let store = state.open_store().ok_or("no store")?;
    Ok(serde_json::from_slice(&store.read_payload(1)?)?)
}

fn pair() -> FirstRunPassphrase {
    FirstRunPassphrase {
        passphrase: SecretString::from(PASSPHRASE),
        confirm: SecretString::from(PASSPHRASE),
    }
}

/// T15 review I-2 (PD-168, PD-171): after "Archive old DB and start fresh" the pinned file still
/// names the archived store. A wizard restore cancelled at its first question (the native "Restore
/// backup" confirmation) leaves it, the keyring, the data dir and the kept archive confirmation as
/// they were: the ids are taken only after the last question. A restore that then goes through
/// pins the restored store's id and drops the kept confirmation (no `GENESIS` will record it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_cancelled_after_an_archive_keeps_the_pinned_id() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let bundle = m.backup_elsewhere()?;
    let a = archived_start(&m).await?;
    let kept = Some(a.archived.file.clone());
    assert_eq!(a.state.testing_archive_confirmation_file(), kept);
    let ids = m.keys.ids();
    m.confirmer.1.store(1, Ordering::SeqCst);
    let s = run(&a.setup, "wizard_restore").await?;
    assert_eq!(s["step"], "restore", "{s}");
    let s = until(&a.setup, "the restore ended", |s| s["step"] != "restore").await?;
    assert_eq!(
        (s["step"].clone(), s["error"].clone()),
        (json!("anchor_dir"), Value::Null),
        "{s}"
    );
    assert_eq!(
        m.restore_dialogs.load(Ordering::SeqCst),
        0,
        "cancelled at the confirmation"
    );
    assert_eq!(
        m.confirmer.texts().last().map(String::as_str),
        Some(atlas_duck_app_lib::restore_flow::RESTORE_CONFIRM_TEXT)
    );
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        Some(a.old_id.clone())
    );
    assert!(m.pins().is_empty(), "{:?}", m.pins());
    assert_eq!(m.keys.ids(), ids, "no keystore built");
    let data = local(&m.default_dir)?;
    assert!(!data.path().join("audit.db").exists());
    assert_eq!(a.state.testing_archive_confirmation_file(), kept);

    // The restore goes through: the restored store's id is pinned, the kept proof is dropped.
    *m.pick_restore.lock().map_err(|_| "poisoned")? = Some(bundle);
    run(&a.setup, "wizard_restore").await?;
    let w = restore_window(&a.app).await?;
    assert_eq!(
        call(&w, "submit_secret", json!({ "secret": PASSPHRASE })).await,
        Ok(json!({"accepted": {}}))
    );
    until(&a.setup, "the restored store serves", step_is("instances")).await?;
    let live = a.state.note_facts().map(|f| f.0).ok_or("no store")?;
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        Some(live.clone())
    );
    assert_eq!(
        m.pins()
            .iter()
            .map(|p| p.install_id.clone())
            .collect::<Vec<_>>(),
        [None, Some(live)]
    );
    assert_eq!(a.state.testing_archive_confirmation_file(), None);
    serve::shutdown(&a.state, ShutdownReason::Quit, WAIT).await;
    Ok(())
}

/// T15 review I-1 (§8.7, PD-41): a wizard restore that committed but did not complete (here the
/// keychain refuses the KEK's re-seal, the first keyring write after the commit rename) leaves
/// `audit.db` as the restored store under the new install. The pinned file names that install, the
/// store is failed until a restart (which completes the restore), and the wizard stops with the
/// restart text: neither Begin nor another restore is offered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_incomplete_wizard_restore_stops_with_the_new_id_pinned() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let bundle = m.backup_elsewhere()?;
    let (app, setup) = at_anchor_step(&m).await?;
    let state = serving(&app).ok_or("not serving")?;
    *m.pick_restore.lock().map_err(|_| "poisoned")? = Some(bundle);
    m.ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::Kek),
        KeyStoreError::Unavailable,
        1,
    );
    run(&setup, "wizard_restore").await?;
    let w = restore_window(&app).await?;
    call(&w, "submit_secret", json!({ "secret": PASSPHRASE }))
        .await
        .map_err(|e| format!("submit_secret: {e}"))?;
    let s = until(&setup, "the restore ended", |s| {
        s["stopped_text"] == wizard::MSG_RESTORE_COMMITTED_INCOMPLETE || !s["error"].is_null()
    })
    .await?;
    assert_eq!(
        (s["step"].clone(), s["stopped_text"].clone()),
        (
            json!("stopped"),
            json!(wizard::MSG_RESTORE_COMMITTED_INCOMPLETE)
        ),
        "{s}"
    );
    let data = local(&m.default_dir)?;
    assert!(
        data.path().join("audit.db").exists(),
        "the restore committed"
    );
    let ids = m.keys.ids();
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert_eq!(
        read_pinned(&m.pinned_file)?.and_then(|p| p.install_id),
        Some(ids[0].clone())
    );
    assert_eq!(
        m.pins()
            .iter()
            .map(|p| p.install_id.clone())
            .collect::<Vec<_>>(),
        [None, None, Some(ids[0].clone())]
    );
    assert!(state.store_failed(), "no first_run answer any more");
    for cmd in ["wizard_begin", "wizard_restore", "wizard_anchor_dir"] {
        assert_eq!(
            call(&setup, cmd, json!({})).await,
            Err(json!({"kind": "not_ready"})),
            "{cmd}"
        );
    }
    stop(&app).await
}

/// PD-171, T15 review I-3: the kept archive confirmation is recorded only next to the archive it
/// was given for. When the archive the wizard derives again from the archive folder is another file
/// (here a newer copy of it), `GENESIS` names that file and no `CONFIG_CHANGED {key:
/// archive_and_start_fresh}` follows; the kept proof is dropped after the first store either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_archive_proof_names_only_its_own_file() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let a = archived_start(&m).await?;
    // The answer the credential window kept is gone (the wizard derives the archive again).
    assert_eq!(
        credential::take_archived(a.app.handle()),
        Some(a.archived.clone())
    );
    let folder = local(&m.default_dir)?.path().join("archived");
    let kept = a
        .archived
        .file
        .strip_prefix("archived/")
        .ok_or("not in archived/")?;
    let (stem, _stamp) = kept.rsplit_once('-').ok_or("no stamp")?;
    let newer = format!("{stem}-99991231T235959Z.db");
    for suffix in ["", "-wal"] {
        let from = folder.join(format!("{kept}{suffix}"));
        if from.exists() {
            std::fs::copy(&from, folder.join(format!("{newer}{suffix}")))?;
        }
    }
    run(&a.setup, "wizard_begin").await?;
    assert_eq!(
        type_passphrase(&a.app, PASSPHRASE).await,
        Ok(json!({"accepted": {}}))
    );
    until(&a.setup, "GENESIS", step_is("recovery_note")).await?;
    let genesis = genesis_payload(&a.state)?;
    assert_eq!(
        genesis["archived_db"]["file"],
        format!("archived/{newer}"),
        "{genesis}"
    );
    assert!(
        config_changed(&a.state, "archive_and_start_fresh").is_err(),
        "the proof of another archive was recorded"
    );
    assert_eq!(a.state.testing_archive_confirmation_file(), None);
    serve::shutdown(&a.state, ShutdownReason::Quit, WAIT).await;
    Ok(())
}

/// PD-171, T15 review I-3 (the realistic retry): a first `GENESIS` attempt that fails has taken the
/// archive the credential window kept, and the kept confirmation stays; the next attempt derives
/// the archive again from the archive folder and still records the confirmation next to it, which
/// is then dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_archive_proof_survives_a_failed_first_attempt() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let a = archived_start(&m).await?;
    let data = local(&m.default_dir)?;
    // Attempt 1 through the wizard's own GENESIS (as its window hands the pair over; the mock app
    // builds one credential window): the keychain refuses the new install's canary, nothing is
    // created.
    m.ring
        .fail_next(KeyOpKind::Set, None, KeyStoreError::Unavailable, 1);
    assert_eq!(
        wizard::testing_genesis(a.app.handle(), pair()).await,
        Err(FirstStoreFailure::KeychainUnavailable)
    );
    assert_eq!(
        credential::take_archived(a.app.handle()),
        None,
        "the first attempt took it"
    );
    assert!(!data.path().join("audit.db").exists());
    assert_eq!(
        a.state.testing_archive_confirmation_file(),
        Some(a.archived.file.clone())
    );
    // Attempt 2 through the setup and credential windows.
    run(&a.setup, "wizard_begin").await?;
    assert_eq!(
        type_passphrase(&a.app, PASSPHRASE).await,
        Ok(json!({"accepted": {}}))
    );
    until(&a.setup, "GENESIS", step_is("recovery_note")).await?;
    let genesis = genesis_payload(&a.state)?;
    assert_eq!(genesis["archived_db"]["file"], a.archived.file, "{genesis}");
    let record = config_changed(&a.state, "archive_and_start_fresh")?;
    assert_eq!(record["archived_db_file"], a.archived.file, "{record}");
    assert_eq!(
        record["dialog_text_sha256"],
        atlas_duck_core::payloads::sha256_hex(serve::archive_confirm_text(&data).as_bytes()),
        "{record}"
    );
    assert_eq!(a.state.testing_archive_confirmation_file(), None);
    serve::shutdown(&a.state, ShutdownReason::Quit, WAIT).await;
    Ok(())
}

/// T13 ruling 5, T15 review M-1: while the credential window is open for anything, "Restore from a
/// backup" answers `busy` before any dialog: no confirmation, no file dialog, no ids.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wizard_restore_is_busy_while_the_credential_window_is_open() -> TestResult {
    let tmp = scratch()?;
    let m = Machine::new(&tmp, "host-a", None, MemKeyring::new())?;
    let (app, setup) = at_anchor_step(&m).await?;
    let handle = app.handle().clone();
    tokio::task::spawn_blocking(move || {
        credential::open(&handle, Purpose::RecoveryPassphrase, windows::Show::Focus)
    })
    .await?
    .map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        call(&setup, "wizard_restore", json!({})).await,
        Err(json!({"kind": "busy"}))
    );
    assert!(m.confirmer.texts().is_empty());
    assert_eq!(m.restore_dialogs.load(Ordering::SeqCst), 0);
    assert!(m.keys.ids().is_empty());
    assert_eq!(wizard_state(&setup).await?["step"], "anchor_dir");
    stop(&app).await
}

/// §8.6 (L39), T15 review M-2: the restore stops where Begin would, before any dialog. With no
/// usable Secret Service, or a keyring not on a local disk, the wizard shows the same stop text
/// (Quit only): no confirmation, no file dialog, no keyring call, no id, no window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_restore_stops_where_begin_would() -> TestResult {
    let tmp = scratch()?;
    for (host, text) in [
        ("host-a", MSG_NEEDS_SECRET_SERVICE),
        ("host-b", MSG_KEYRING_NOT_LOCAL),
    ] {
        let mut m = Machine::new(&tmp, host, None, MemKeyring::new())?;
        if text == MSG_NEEDS_SECRET_SERVICE {
            m.secret_service = Some(SecretService::Missing);
        } else {
            m.ring.set_locality(KeyringLocality::NotLocal {
                dir: m.root.join("home-on-nfs"),
            });
        }
        let (app, setup) = at_anchor_step(&m).await?;
        let s = run(&setup, "wizard_restore").await?;
        assert_eq!(
            (s["step"].clone(), s["stopped_text"].clone()),
            (json!("stopped"), json!(text)),
            "{host}: {s}"
        );
        assert!(m.confirmer.texts().is_empty(), "{host}");
        assert_eq!(m.restore_dialogs.load(Ordering::SeqCst), 0, "{host}");
        assert!(m.ring.ops().is_empty(), "{host}: no keyring call");
        assert!(m.keys.ids().is_empty(), "{host}");
        assert_eq!(credential::current_purpose(app.handle()), None, "{host}");
        assert_eq!(
            call(&setup, "wizard_restore", json!({})).await,
            Err(json!({"kind": "not_ready"})),
            "{host}"
        );
        stop(&app).await?;
    }
    Ok(())
}
