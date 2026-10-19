//! M6 T20 (§10.3, §7.1, §8.6, §8.7; I-33, U-18, S-16 Tauri half): the credential window's Rust
//! side over Tauri's mock runtime (no OS window, no webview) and the app's own serving state.
//!
//! Three rigs: the generated context with the shipped capability files (the ACL is the real one,
//! as in `commands_acl.rs`); `serve::start_with` over a temp data dir with `MemKeyStore`s (as in
//! `startup_ipc.rs`: a wiped keyring leaves the store `keychain_lost`); and `core::testing::Harness`
//! with `MockDc` for the connection test (`scripted-approver`). No OS keychain, no spawned binary.

type TestResult = Result<(), Box<dyn std::error::Error>>;

mod common;

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atlas_duck_app_lib::commands;
use atlas_duck_app_lib::credential::{self, PatOpenError, Purpose};
use atlas_duck_app_lib::secret_service::{SecretService, SecretServiceCheck};
use atlas_duck_app_lib::serve::{
    KeysFactory, RetryNow, ServeHooks, ServeState, ServeWatcher, StartInputs, UnlockFailure,
    UnlockKind, retry_keychain_from_menu, retry_keychain_now, start_with, unlock,
};
use atlas_duck_app_lib::state::{DataDirHold, ServeSlot};
use atlas_duck_app_lib::status::StatusInputs;
use atlas_duck_app_lib::tray::{MSG_STORE_UNAVAILABLE, status_lines};
use atlas_duck_app_lib::windows::{
    AppSnapshot, NavPolicy, Relaunch, Show, StartupRoute, Unlock, WindowError, WindowRegistry,
    open_credential, route_relaunch, serving_snapshot,
};
use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::testing::{FreeSpaceStub, MemKeyStore, MemKeyring};
use atlas_duck_audit::{
    AuditCursor, AuditFilter, EventType, FirstRunInput, KeyStore, KeyStoreError, LockedReason,
    MAX_AUDIT_PAGE_ROWS, OpenConfig, SystemClock, create_new_store, new_ids,
};
use atlas_duck_core::{
    AdminError, Confirm, GateState, InstanceView, NativeConfirmer, UiEvent, UiSink,
};
use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::client::IpcClient;
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::paths::{
    DataDirResolution, EndpointLocation, LocalDataDir, check_data_dir, read_endpoint_file,
};
use atlas_duck_ipc::proto::{AgentNameSource, ClientKind, Hello, SubmitParams, SubmitReply};
use atlas_duck_ipc::server::ShutdownSignal;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{INVOKE_KEY, MockRuntime, get_ipc_response, mock_builder};
use tauri::webview::InvokeRequest;
use tauri::{App, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

const HOST: &str = "thishost";
const WAIT: Duration = Duration::from_secs(30);
/// The World's recovery passphrase unless a test picks its own.
const PASSPHRASE: &str = "correct horse battery";

// ---------- the mock app ----------

/// A scratch dir under cargo's per-target test dir, not `%TEMP%`: Tauri's mock runtime keeps every
/// window it built alive for the rest of the process (the app and its windows hold each other),
/// and with them the `instance.lock` of the data dir the app manages, so on Windows a dir cannot
/// be deleted while the test binary runs. Leftovers of earlier runs are swept once per run, but
/// only those older than [`SWEEP_AGE`]: a younger one may belong to a run that is still going
/// (nextest, two `cargo test`s on one target dir); `cargo clean` removes the rest (M6 T22 m-6).
fn scratch() -> std::io::Result<tempfile::TempDir> {
    static SWEEP: std::sync::Once = std::sync::Once::new();
    let root = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("credential");
    std::fs::create_dir_all(&root)?;
    SWEEP.call_once(|| sweep_older_than(&root, SWEEP_AGE));
    tempfile::Builder::new().tempdir_in(&root)
}

/// Dirs under the scratch root younger than this are never swept (another run's live data).
const SWEEP_AGE: Duration = Duration::from_secs(60 * 60);

/// Removes the entries of `root` last modified more than `age` ago; an entry whose age cannot be
/// read is kept.
fn sweep_older_than(root: &std::path::Path, age: Duration) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|elapsed| elapsed > age);
        if old {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// M6 T22 review m-6: the sweep keeps what is younger than the age (another run's live data dir)
/// and removes what is older.
#[test]
fn the_sweep_spares_young_dirs() -> TestResult {
    let root = scratch()?;
    let dir = root.path().join("another-runs-data");
    std::fs::create_dir(&dir)?;
    std::fs::write(dir.join("audit.db"), b"x")?;
    std::thread::sleep(Duration::from_millis(60));
    sweep_older_than(root.path(), SWEEP_AGE);
    assert!(dir.join("audit.db").exists(), "a young dir is not swept");
    sweep_older_than(root.path(), Duration::from_millis(10));
    assert!(!dir.exists(), "an old one is");
    Ok(())
}

fn app() -> Result<App<MockRuntime>, Box<dyn std::error::Error>> {
    let context = tauri::generate_context!(assets = tauri::test::noop_assets(), test = true);
    let app = commands::register(mock_builder()).build(context)?;
    app.manage(WindowRegistry::new(
        NavPolicy::for_this_platform(None),
        StartupRoute::completed(),
    ));
    Ok(app)
}

fn window(app: &App<MockRuntime>, label: &str) -> tauri::Result<WebviewWindow<MockRuntime>> {
    match app.get_webview_window(label) {
        Some(w) => Ok(w),
        None => WebviewWindowBuilder::new(app, label, WebviewUrl::default()).build(),
    }
}

/// One invoke from `w`; `Err` is what the webview's promise rejects with.
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

fn local_data_dir(dir: &std::path::Path) -> Result<LocalDataDir, Box<dyn std::error::Error>> {
    match check_data_dir(dir)? {
        DataDirResolution::Local(d) => Ok(d),
        _ => Err("the temp dir is not a local data dir".into()),
    }
}

fn view(alias: &str, state: &'static str, origin: Option<&str>) -> InstanceView {
    InstanceView {
        alias: alias.into(),
        product: atlas_duck_registry::Product::Jira,
        origin: origin.map(str::to_owned),
        state,
        executes_as: None,
        expires_at: None,
        pac_configured: false,
        proxy_effective: None,
        pending_url_change: None,
        note: None,
        expiry_warning: None,
        days_left: None,
    }
}

// ---------- the serving world (as `startup_ipc.rs`) ----------

struct NoUi;
impl UiSink for NoUi {
    fn emit(&self, _: UiEvent) {}
}

/// Scripted native answers (then Ok), and every text it was shown.
#[derive(Default)]
struct Answers {
    queue: Mutex<VecDeque<Confirm>>,
    texts: Mutex<Vec<String>>,
}

impl Answers {
    fn new(answers: Vec<Confirm>) -> Arc<Answers> {
        Arc::new(Answers {
            queue: Mutex::new(answers.into()),
            texts: Mutex::default(),
        })
    }

    fn texts(&self) -> Vec<String> {
        self.texts.lock().map(|t| t.clone()).unwrap_or_default()
    }
}

impl NativeConfirmer for Answers {
    fn confirm(&self, text: &str) -> Confirm {
        if let Ok(mut t) = self.texts.lock() {
            t.push(text.to_owned());
        }
        self.queue
            .lock()
            .ok()
            .and_then(|mut q| q.pop_front())
            .unwrap_or(Confirm::Ok)
    }
}

struct NoSecretService;
impl SecretServiceCheck for NoSecretService {
    fn check(&self) -> Option<SecretService> {
        None
    }
}

/// `MemKeyStore`s over one keyring; every `keys()` fails `Unavailable` while `available` is off,
/// and waits while a test holds it (a keychain authorization prompt that nobody answered yet).
struct MemKeys {
    ring: Arc<MemKeyring>,
    available: AtomicBool,
    calls: std::sync::atomic::AtomicU32,
    held: Mutex<bool>,
    released: std::sync::Condvar,
}

impl MemKeys {
    fn new(ring: Arc<MemKeyring>, available: bool) -> Arc<MemKeys> {
        Arc::new(MemKeys {
            ring,
            available: AtomicBool::new(available),
            calls: std::sync::atomic::AtomicU32::new(0),
            held: Mutex::new(false),
            released: std::sync::Condvar::new(),
        })
    }

    /// `true`: every `keys()` call from now on blocks until `hold(false)`.
    fn hold(&self, on: bool) {
        if let Ok(mut held) = self.held.lock() {
            *held = on;
        }
        self.released.notify_all();
    }

    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl KeysFactory for MemKeys {
    fn keys(&self, install_id: &str) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut held) = self.held.lock() {
            while *held {
                held = self.released.wait(held).unwrap_or_else(|e| e.into_inner());
            }
        }
        if !self.available.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Unavailable);
        }
        Ok(Arc::new(MemKeyStore::new(self.ring.clone(), install_id)))
    }
}

/// Fields drop in declaration order: `tmp` is last so the directory goes after everything that
/// holds `instance.lock` open (on Windows the delete fails silently otherwise, and the directory
/// stays in `%TEMP%`; M6 T22 m-6).
struct World {
    data: LocalDataDir,
    lock: Arc<InstanceLock>,
    location: EndpointLocation,
    tmp: tempfile::TempDir,
    /// Unix: the short base the socket dir is under (removed with the World).
    _sock: Option<tempfile::TempDir>,
}

impl World {
    fn new() -> Result<World, Box<dyn std::error::Error>> {
        let tmp = scratch()?;
        let dir = tmp.path().join("data");
        std::fs::create_dir(&dir)?;
        let data = local_data_dir(&dir)?;
        let lock = Arc::new(InstanceLock::acquire(&data, HOST)?);
        std::fs::create_dir(tmp.path().join("config"))?;
        let (location, _sock) = location(&data)?;
        Ok(World {
            data,
            lock,
            location,
            tmp,
            _sock,
        })
    }

    fn config_dir(&self) -> std::path::PathBuf {
        self.tmp.path().join("config")
    }

    fn inputs(
        &self,
        install_id: Option<String>,
        keys: Arc<dyn KeysFactory>,
        confirmer: Arc<dyn NativeConfirmer>,
        retry_schedule: Vec<Duration>,
    ) -> StartInputs {
        StartInputs {
            data: self.data.clone(),
            lock: self.lock.clone(),
            host: HOST.to_owned(),
            install_id,
            config_dir: self.config_dir(),
            keys,
            ui: Arc::new(NoUi),
            confirmer,
            tray_host: None,
            secret_service: Arc::new(NoSecretService),
            retry_schedule,
            endpoint: Some(self.location.clone()),
            quit: ShutdownSignal::new(),
            hooks: ServeHooks::default(),
        }
    }

    /// A store created by the wizard path (`GENESIS`) with recovery passphrase `pass`.
    fn provision(
        &self,
        ring: &Arc<MemKeyring>,
        pass: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let (install_id, chain_id) = new_ids()?;
        let keys: Arc<dyn KeyStore> = Arc::new(MemKeyStore::new(ring.clone(), &install_id));
        let mut cfg = OpenConfig::new(Arc::new(SystemClock::new()), keys);
        cfg.free_space = Some(FreeSpaceStub::new(u64::MAX));
        let store = create_new_store(
            &self.data,
            &self.lock,
            cfg,
            FirstRunInput {
                install_id: install_id.clone(),
                chain_id,
                passphrase: SecretString::from(pass.to_owned()),
                passphrase_confirm: SecretString::from(pass.to_owned()),
                archived_db: None,
                anchor_dir: None,
                archive_confirmed: None,
            },
        )?;
        store.shutdown();
        Ok(install_id)
    }

    /// A provisioned store whose keychain entries were wiped: `start_with` serves the
    /// `keychain_lost` gate ("Recover this log").
    async fn lost(
        &self,
        pass: &str,
        confirmer: Arc<dyn NativeConfirmer>,
    ) -> Result<Arc<ServeState>, Box<dyn std::error::Error>> {
        Ok(self
            .lost_with(pass, confirmer, ServeHooks::default())
            .await?
            .0)
    }

    /// [`World::lost`] with `hooks`, and the keystore factory the state keeps using.
    async fn lost_with(
        &self,
        pass: &str,
        confirmer: Arc<dyn NativeConfirmer>,
        hooks: ServeHooks,
    ) -> Result<(Arc<ServeState>, Arc<MemKeys>), Box<dyn std::error::Error>> {
        let ring = MemKeyring::new();
        let install_id = self.provision(&ring, pass)?;
        ring.wipe_install(&install_id);
        let keys = MemKeys::new(ring, true);
        let mut inputs = self.inputs(Some(install_id), keys.clone(), confirmer, vec![]);
        inputs.hooks = hooks;
        let state = start_with(inputs).await.map_err(|e| format!("{e:?}"))?;
        assert!(state.core.get().is_none());
        Ok((state, keys))
    }

    /// A provisioned store whose keychain is unavailable: `start_with` serves the
    /// `keychain_unavailable` gate (no automatic retry); `keys.available` brings the keychain
    /// back, and `wipe` first makes it `keychain_lost` instead.
    async fn unavailable(
        &self,
        wipe: bool,
        hooks: ServeHooks,
    ) -> Result<(Arc<ServeState>, Arc<MemKeys>), Box<dyn std::error::Error>> {
        let ring = MemKeyring::new();
        let install_id = self.provision(&ring, PASSPHRASE)?;
        if wipe {
            ring.wipe_install(&install_id);
        }
        let keys = MemKeys::new(ring, false);
        let mut inputs = self.inputs(Some(install_id), keys.clone(), Answers::new(vec![]), vec![]);
        inputs.hooks = hooks;
        let state = start_with(inputs).await.map_err(|e| format!("{e:?}"))?;
        assert!(state.core.get().is_none());
        Ok((state, keys))
    }

    fn files(&self) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
        let mut out = BTreeSet::new();
        for e in std::fs::read_dir(self.data.path())? {
            out.insert(e?.file_name().to_string_lossy().into_owned());
        }
        Ok(out)
    }

    async fn connect(&self) -> Result<IpcClient, Box<dyn std::error::Error>> {
        let hello = Hello {
            build_id: BUILD_ID.to_owned(),
            client_kind: ClientKind::Cli,
            agent_name: Some("t20".into()),
            agent_name_source: AgentNameSource::Flag,
            cwd_basename: "work".into(),
        };
        IpcClient::connect_at(
            &self.location,
            &self.data,
            &hello,
            &same_user()?,
            Instant::now() + WAIT,
        )
        .await
        .map_err(|e| format!("connect: {e}").into())
    }

    /// The mock app serving `state`, with this data dir held (the credential window needs it).
    fn app(&self, state: &Arc<ServeState>) -> Result<App<MockRuntime>, Box<dyn std::error::Error>> {
        let app = app()?;
        app.manage(DataDirHold::new(self.data.clone(), self.lock.clone()));
        let slot = ServeSlot::default();
        slot.set(state.clone());
        app.manage(slot);
        Ok(app)
    }
}

/// The socket lives under a short base, not the scratch dir ([`common::short_socket_base`]).
#[cfg(unix)]
fn location(
    _data: &LocalDataDir,
) -> Result<(EndpointLocation, Option<tempfile::TempDir>), Box<dyn std::error::Error>> {
    let base = common::short_socket_base()?;
    Ok((common::socket_location(base.path())?, Some(base)))
}

#[cfg(windows)]
fn location(
    data: &LocalDataDir,
) -> Result<(EndpointLocation, Option<tempfile::TempDir>), Box<dyn std::error::Error>> {
    Ok((atlas_duck_ipc::paths::endpoint_location(data, HOST)?, None))
}

#[cfg(unix)]
fn same_user() -> Result<atlas_duck_ipc::transport::unix::SameUser, Box<dyn std::error::Error>> {
    Ok(atlas_duck_ipc::transport::unix::SameUser)
}

#[cfg(windows)]
fn same_user() -> Result<atlas_duck_ipc::transport::windows::SameUser, Box<dyn std::error::Error>> {
    Ok(atlas_duck_ipc::transport::windows::SameUser::current()?)
}

/// Stops what `start_with` started (server, core, store).
async fn stop(state: &ServeState) -> TestResult {
    state.shutdown.cancel();
    let task = state.served.lock().map_err(|_| "poisoned")?.take();
    if let Some(task) = task {
        tokio::time::timeout(WAIT, task).await??;
    }
    if let Some(core) = state.core.get() {
        core.shutdown(atlas_duck_core::ShutdownReason::Quit).await;
    }
    let store = state.store.lock().map_err(|_| "poisoned")?.take();
    if let Some(store) = store {
        tokio::task::spawn_blocking(move || store.shutdown()).await?;
    }
    Ok(())
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

// ---------- the context is Rust's ----------

/// §10.3: Rust fixes the context when it opens the window. A second request (the settings
/// trigger for another alias, a forged one) while the window is open changes nothing: the window
/// keeps alias A, and `credential_context` takes no argument that could name another.
#[test]
fn credential_context_is_rust_fixed() -> TestResult {
    // `tmp` first: locals drop in reverse, so the app (which holds `instance.lock` in `tmp`) goes
    // before the directory does.
    let tmp = scratch()?;
    let app = app()?;
    let data = local_data_dir(tmp.path())?;
    let lock = Arc::new(InstanceLock::acquire(&data, HOST)?);
    app.manage(DataDirHold::new(data, lock));
    let handle = app.handle();
    let a = "https://jira-a.example/jira";
    let views = vec![
        view("A", "needs_token", Some(a)),
        view("B", "ok", Some("https://jira-b.example/jira")),
    ];

    credential::open_for_pat(handle, &views, "A", false)?;
    let w = window(&app, "credential")?;
    let context = json!({"purpose": "add_pat", "alias": "A", "product": "jira", "base_url": a,
        "refused_count": null, "product_version_hint": null, "note_available": false});
    assert_eq!(
        invoke(&w, "credential_context", json!({})),
        Ok(context.clone())
    );

    // The second request: refused while the window is open, for any purpose but a lock state
    // following a lock state; the window, its purpose and its context stay.
    assert_eq!(
        credential::open_for_pat(handle, &views, "B", true),
        Err(PatOpenError::Window(WindowError::Busy))
    );
    assert_eq!(
        open_credential(handle, Unlock::Recover, Show::Focus),
        Err(WindowError::Busy)
    );
    assert_eq!(
        credential::request_recovery_passphrase(handle, Show::Focus).err(),
        Some(WindowError::Busy)
    );
    assert_eq!(app.webview_windows().len(), 1);
    assert_eq!(
        invoke(&w, "credential_context", json!({})),
        Ok(context.clone())
    );
    // The same purpose again only shows the window.
    credential::open_for_pat(handle, &views, "A", false)?;
    assert_eq!(invoke(&w, "credential_context", json!({})), Ok(context));
    // No argument can name another alias.
    assert_eq!(
        invoke(&w, "credential_context", json!({"alias": "B"})),
        Err(json!({"kind": "invalid_argument", "field": "payload"}))
    );
    assert_eq!(
        invoke(&w, "submit_secret", json!({"secret": "x", "alias": "B"})),
        Err(json!({"kind": "invalid_argument", "field": "payload"}))
    );

    // Closing forgets the purpose before the window goes: a page still answering meanwhile gets
    // `not_ready` for everything. (The mock runtime never reports the window destroyed, so the
    // next window's own purpose is shown in a fresh app.)
    credential::close(handle);
    assert_eq!(credential::current_purpose(handle), None);
    assert_eq!(
        invoke(&w, "credential_context", json!({})),
        Err(json!({"kind": "not_ready"}))
    );
    assert_eq!(
        invoke(&w, "submit_secret", json!({"secret": "x"})),
        Err(json!({"kind": "not_ready"}))
    );
    let fresh = app_with_data_dir(tmp.path())?;
    credential::open_for_pat(fresh.handle(), &views, "B", true)?;
    let w = window(&fresh, "credential")?;
    assert_eq!(
        invoke(&w, "credential_context", json!({}))
            .ok()
            .and_then(|c| c.get("alias").cloned()),
        Some(json!("B"))
    );
    Ok(())
}

/// M6 T28 (T20 m-9), the credential half of the interlock: while a removal call holds its claim, a
/// window for a token is not registered at all (the check and the purpose are one step under the
/// registry's lock): nothing is built, no purpose is set, and the answer is `busy`. Other windows
/// are not held off, and once the claim is released the token window opens.
#[test]
fn a_token_window_is_not_registered_while_a_removal_call_runs() -> TestResult {
    use atlas_duck_app_lib::removal::RemovalState;
    let tmp = scratch()?;
    let app = app()?;
    let data = local_data_dir(tmp.path())?;
    let lock = Arc::new(InstanceLock::acquire(&data, HOST)?);
    app.manage(DataDirHold::new(data, lock));
    app.manage(RemovalState::default());
    let handle = app.handle();
    let views = vec![view(
        "A",
        "needs_token",
        Some("https://jira-a.example/jira"),
    )];

    let state = app.state::<RemovalState>();
    let claim = state.claim()?;
    assert_eq!(
        credential::open_for_pat(handle, &views, "A", false),
        Err(PatOpenError::Window(WindowError::Busy))
    );
    assert_eq!(credential::current_purpose(handle), None);
    assert_eq!(app.webview_windows().len(), 0, "no window was built");
    drop(claim);
    credential::open_for_pat(handle, &views, "A", false)?;
    assert!(matches!(
        credential::current_purpose(handle),
        Some(Purpose::AddPat(_))
    ));
    Ok(())
}

/// M6 T28 (T20 m-9): a window that is open already (opened before the removal call, or kept by a
/// submit under way) cannot store a token while a removal call runs: `submit_secret` answers `busy`
/// before it reaches core; without a claim it goes on (here: `not_ready`, no core serves).
#[test]
fn a_token_submit_is_refused_while_a_removal_call_runs() -> TestResult {
    use atlas_duck_app_lib::removal::RemovalState;
    let tmp = scratch()?;
    let app = app()?;
    let data = local_data_dir(tmp.path())?;
    let lock = Arc::new(InstanceLock::acquire(&data, HOST)?);
    app.manage(DataDirHold::new(data, lock));
    app.manage(RemovalState::default());
    let handle = app.handle();
    let views = vec![view(
        "A",
        "needs_token",
        Some("https://jira-a.example/jira"),
    )];
    credential::open_for_pat(handle, &views, "A", false)?;
    let w = window(&app, "credential")?;
    let body = json!({"secret": "x"});
    assert_eq!(
        invoke(&w, "submit_secret", body.clone()),
        Err(json!({"kind": "not_ready"})),
        "no claim: the submit reaches the core check"
    );
    let state = app.state::<RemovalState>();
    let claim = state.claim()?;
    assert_eq!(
        invoke(&w, "submit_secret", body.clone()),
        Err(json!({"kind": "busy"}))
    );
    drop(claim);
    assert_eq!(
        invoke(&w, "submit_secret", body),
        Err(json!({"kind": "not_ready"})),
        "the claim was released"
    );
    Ok(())
}

/// A mock app holding `dir` as its (locked) data dir.
fn app_with_data_dir(
    dir: &std::path::Path,
) -> Result<App<MockRuntime>, Box<dyn std::error::Error>> {
    let app = app()?;
    let sub = dir.join(format!("d{}", std::process::id()));
    std::fs::create_dir_all(&sub)?;
    let data = local_data_dir(&sub)?;
    let lock = Arc::new(InstanceLock::acquire(&data, HOST)?);
    app.manage(DataDirHold::new(data, lock));
    Ok(app)
}

/// The window's purpose is gone (Rust destroys the window right after its answer; the mock
/// runtime does not report a destroyed window, so the purpose is what is observable).
async fn closed(handle: &tauri::AppHandle<MockRuntime>) -> TestResult {
    let h = handle.clone();
    eventually("the credential window closed", move || {
        credential::current_purpose(&h).is_none()
    })
    .await
}

/// The lock states follow each other in an open window (the keychain retry can turn
/// `keychain_unavailable` into `keychain_lost`); a PAT purpose never replaces one.
#[test]
fn lock_states_follow_each_other_in_an_open_window() -> TestResult {
    // `tmp` first: locals drop in reverse, so the app (which holds `instance.lock` in `tmp`) goes
    // before the directory does.
    let tmp = scratch()?;
    let app = app()?;
    let data = local_data_dir(tmp.path())?;
    let lock = Arc::new(InstanceLock::acquire(&data, HOST)?);
    app.manage(DataDirHold::new(data, lock));
    let handle = app.handle();
    open_credential(handle, Unlock::Unlock, Show::Focus)?;
    assert_eq!(credential::current_purpose(handle), Some(Purpose::Unlock));
    open_credential(handle, Unlock::Recover, Show::Focus)?;
    assert_eq!(
        credential::current_purpose(handle),
        Some(Purpose::RecoverThisLog)
    );
    let views = vec![view("A", "needs_token", Some("https://a.example"))];
    assert_eq!(
        credential::open_for_pat(handle, &views, "A", false),
        Err(PatOpenError::Window(WindowError::Busy))
    );
    // The command path (`credential_window_open`) answers that refusal as `busy` on the wire.
    let refused = credential::open_for_pat(handle, &views, "A", false)
        .err()
        .ok_or("opened over a recovery window")?;
    let answer = atlas_duck_app_lib::commands::settings::pat_open_error(refused);
    assert_eq!(answer, atlas_duck_app_lib::commands::CommandError::Busy);
    assert_eq!(serde_json::to_value(&answer)?, json!({"kind": "busy"}));
    assert_eq!(
        credential::current_purpose(handle),
        Some(Purpose::RecoverThisLog)
    );
    assert_eq!(app.webview_windows().len(), 1);
    Ok(())
}

/// A recognisable backup passphrase: never in an answer.
const RESTORE_CANARY: &str = "canary-restore-passphrase-t13";

/// §10.3, PD-168 (M10 T13): a backup's recovery passphrase enters only through `submit_secret` in
/// the `restore_backup` window Rust opened: the context header names the purpose; a second entry
/// or an expiry date is refused and nothing is handed on; the one entry reaches the waiting restore
/// through the in-memory channel (the answer holds no secret) and the window Settings opened
/// closes. A window closed without a submit ends the wait (the channel disconnects); with no
/// restore waiting a submit is `not_ready`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restore_passphrase_only_through_submit_secret() -> TestResult {
    let tmp = scratch()?;
    let app = app_with_data_dir(tmp.path())?;
    let handle = app.handle().clone();
    let request = credential::request_restore_passphrase(&handle, Show::Focus)?;
    assert_eq!(
        credential::current_purpose(&handle),
        Some(Purpose::RestoreBackup)
    );
    let w = window(&app, "credential")?;
    assert_eq!(
        call(&w, "credential_context", json!({}))
            .await
            .map_err(|e| e.to_string())?["purpose"],
        "restore_backup"
    );
    for (body, field) in [
        (
            json!({"secret": RESTORE_CANARY, "secret_confirm": RESTORE_CANARY}),
            "secret_confirm",
        ),
        (
            json!({"secret": RESTORE_CANARY, "expires_on": "2027-01-31"}),
            "expires_on",
        ),
    ] {
        assert_eq!(
            call(&w, "submit_secret", body).await,
            Err(json!({"kind": "invalid_argument", "field": field}))
        );
    }
    assert!(request.rx.try_recv().is_err(), "nothing handed on");
    let answer = call(&w, "submit_secret", json!({"secret": RESTORE_CANARY}))
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(answer, json!({"accepted": {}}));
    assert!(!answer.to_string().contains(RESTORE_CANARY));
    let entered = request.rx.recv_timeout(WAIT)?;
    assert_eq!(entered.expose_secret(), RESTORE_CANARY);
    closed(&handle).await?;

    // Closed without a submit: the restore's wait ends. (A new app: the mock runtime keeps the
    // destroyed window, which would make the next open `busy`.)
    let tmp = scratch()?;
    let app = app_with_data_dir(tmp.path())?;
    let handle = app.handle().clone();
    let request = credential::request_restore_passphrase(&handle, Show::Focus)?;
    let w = window(&app, "credential")?;
    call(&w, "close_credential", json!({}))
        .await
        .map_err(|e| e.to_string())?;
    closed(&handle).await?;
    assert!(matches!(
        request.rx.recv_timeout(WAIT),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    ));
    Ok(())
}

/// PD-168 (M10 T13): "Restore a backup instead" sets the locked window (`keychain_lost`) in place
/// to `restore_backup` (same window, `credential_context_changed`); its submit is handed to the
/// waiting restore and the window stays open for that restore's answer; when the restore ends
/// without a store the window goes back to its locked purpose. Another window's generation is
/// refused.
#[test]
fn restore_in_place_goes_back_to_the_locked_purpose() -> TestResult {
    let tmp = scratch()?;
    let app = app_with_data_dir(tmp.path())?;
    let handle = app.handle();
    open_credential(handle, Unlock::Recover, Show::Focus)?;
    let (_, generation) = credential::current_window(handle).ok_or("no window")?;
    assert_eq!(
        credential::enter_restore(handle, generation.wrapping_add(1)).err(),
        Some(WindowError::Busy)
    );
    let request = credential::enter_restore(handle, generation)?;
    assert_eq!(
        credential::current_window(handle),
        Some((Purpose::RestoreBackup, generation))
    );
    let w = window(&app, "credential")?;
    assert_eq!(
        invoke(&w, "submit_secret", json!({"secret": RESTORE_CANARY})),
        Ok(json!({"accepted": {}}))
    );
    assert!(request.rx.recv_timeout(WAIT).is_ok());
    assert_eq!(
        credential::current_window(handle),
        Some((Purpose::RestoreBackup, generation)),
        "the window waits for the restore's answer"
    );
    // A second submit has no restore to go to.
    assert_eq!(
        invoke(&w, "submit_secret", json!({"secret": RESTORE_CANARY})),
        Err(json!({"kind": "not_ready"}))
    );
    credential::leave_restore(handle, generation);
    assert_eq!(
        credential::current_window(handle),
        Some((Purpose::RecoverThisLog, generation))
    );
    // `restore_from_backup` is for the locked purposes only (not_ready otherwise: no gate here).
    assert_eq!(
        invoke(&w, "restore_from_backup", json!({})),
        Err(json!({"kind": "not_ready"}))
    );
    Ok(())
}

/// §7.1, §10.3: the window cannot be opened for an `http://` instance or one whose origin is not
/// natively confirmed; nothing is built.
#[test]
fn credential_refused_for_unconfirmed_or_insecure_instance() -> TestResult {
    // `tmp` first: locals drop in reverse, so the app (which holds `instance.lock` in `tmp`) goes
    // before the directory does.
    let tmp = scratch()?;
    let app = app()?;
    let data = local_data_dir(tmp.path())?;
    let lock = Arc::new(InstanceLock::acquire(&data, HOST)?);
    app.manage(DataDirHold::new(data, lock));
    let views = vec![
        view("plain", "insecure_scheme", Some("http://jira.example")),
        view("new", "instance_unconfirmed", Some("https://jira.example")),
        view("no-origin", "needs_token", None),
    ];
    let handle = app.handle();
    for (alias, want) in [
        ("plain", AdminError::InsecureScheme),
        ("new", AdminError::Unconfirmed),
        ("no-origin", AdminError::Unconfirmed),
        ("missing", AdminError::NotFound),
    ] {
        assert_eq!(
            credential::open_for_pat(handle, &views, alias, false),
            Err(PatOpenError::Instance(want.clone())),
            "{alias}"
        );
        assert_eq!(credential::pat_target(&views, alias), Err(want), "{alias}");
    }
    assert!(app.webview_windows().is_empty(), "no window built");
    assert_eq!(credential::current_purpose(handle), None);
    Ok(())
}

// ---------- the first-run passphrase ----------

/// §8.6: the pair goes to the wizard only when it is at least 12 characters and typed twice the
/// same; a mismatch or a short one is a `failed` answer, hands nothing on and writes nothing; the
/// window stays. Without a waiting wizard nothing is accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_run_passphrase_mismatch_commits_nothing() -> TestResult {
    // `tmp` first: locals drop in reverse, so the app (which holds `instance.lock` in `tmp`) goes
    // before the directory does.
    let tmp = scratch()?;
    let app = app()?;
    let data = local_data_dir(tmp.path())?;
    let lock = Arc::new(InstanceLock::acquire(&data, HOST)?);
    app.manage(DataDirHold::new(data.clone(), lock));
    let handle = app.handle().clone();
    let mut rx = credential::request_recovery_passphrase(&handle, Show::Focus)?;
    let w = window(&app, "credential")?;
    let before = std::fs::read_dir(data.path())?.count();

    let pass = "first-run-passphrase";
    for (body, class) in [
        (
            json!({"secret": pass, "secret_confirm": "first-run-passphrasE"}),
            "passphrase_mismatch",
        ),
        (
            json!({"secret": "eleven-char", "secret_confirm": "eleven-char"}),
            "passphrase_too_short",
        ),
    ] {
        assert_eq!(
            call(&w, "submit_secret", body).await,
            Ok(json!({"failed": {"class": class}}))
        );
        assert!(rx.try_recv().is_err(), "nothing handed on");
        assert!(
            app.get_webview_window("credential").is_some(),
            "window stays"
        );
    }
    // Keys of other purposes are refused before anything is checked.
    assert_eq!(
        call(&w, "submit_secret", json!({ "secret": pass })).await,
        Err(json!({"kind": "invalid_argument", "field": "secret_confirm"}))
    );
    assert_eq!(
        call(
            &w,
            "submit_secret",
            json!({"secret": pass, "secret_confirm": pass, "expires_on": "2030-01-01"})
        )
        .await,
        Err(json!({"kind": "invalid_argument", "field": "expires_on"}))
    );
    assert!(rx.try_recv().is_err());
    // Nothing was written: no store, no file of any kind.
    assert_eq!(std::fs::read_dir(data.path())?.count(), before);
    assert!(!data.path().join("audit.db").exists());

    assert_eq!(
        call(
            &w,
            "submit_secret",
            json!({"secret": pass, "secret_confirm": pass})
        )
        .await,
        Ok(json!({"accepted": {}}))
    );
    let pair = rx.try_recv()?;
    assert_eq!(pair.passphrase.expose_secret(), pass);
    assert_eq!(pair.confirm.expose_secret(), pass);
    // Handed on once: a second submit finds no wizard waiting.
    assert_eq!(
        call(
            &w,
            "submit_secret",
            json!({"secret": pass, "secret_confirm": pass})
        )
        .await,
        Err(json!({"kind": "not_ready"}))
    );
    // A closed window tells the wizard (its receiver errors).
    let rx2 = credential::request_recovery_passphrase(&handle, Show::Focus)?;
    credential::close(&handle);
    assert!(rx2.await.is_err());
    Ok(())
}

/// The `CREDENTIAL_CHANGED {change: recovery_passphrase}` records of the serving store, and every
/// record's decrypted payload as text.
fn passphrase_changes(
    state: &ServeState,
) -> Result<(usize, Vec<String>), Box<dyn std::error::Error>> {
    let store = state.open_store().ok_or("no store")?;
    let page = store.query(
        &AuditFilter::default(),
        AuditCursor::first(MAX_AUDIT_PAGE_ROWS),
    )?;
    let mut changes = 0;
    let mut payloads = Vec::new();
    for row in &page.rows {
        let text = String::from_utf8(store.read_payload(row.seq)?.to_vec())?;
        if row.event_type == EventType::CREDENTIAL_CHANGED
            && text.contains("\"recovery_passphrase\"")
        {
            changes += 1;
        }
        payloads.push(text);
    }
    Ok((changes, payloads))
}

/// The serving world of a provisioned store (recovery passphrase [`PASSPHRASE`]), with the mock
/// app over it.
async fn serving_world()
-> Result<(World, Arc<ServeState>, App<MockRuntime>), Box<dyn std::error::Error>> {
    let w = World::new()?;
    let ring = MemKeyring::new();
    let install_id = w.provision(&ring, PASSPHRASE)?;
    let keys = MemKeys::new(ring, true);
    let state = start_with(w.inputs(Some(install_id), keys, Answers::new(vec![]), vec![]))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let app = w.app(&state)?;
    Ok((w, state, app))
}

/// §8.6, PD-169 (M10 T14): Settings "Change recovery passphrase…" opens the credential window for
/// `change_recovery_passphrase` (no secret in the trigger); the new passphrase enters there only,
/// twice: a mismatch or a short one changes nothing, a good pair re-wraps the KEK (one
/// `CREDENTIAL_CHANGED {change: recovery_passphrase}`) and the window offers the recovery note.
/// While it is open the trigger is `busy`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passphrase_change_opens_credential_purpose_and_offers_note() -> TestResult {
    let (_w, state, app) = serving_world().await?;
    let handle = app.handle().clone();
    let settings = window(&app, "settings")?;
    assert_eq!(
        call(&settings, "recovery_passphrase_change", json!({})).await,
        Ok(Value::Null)
    );
    assert_eq!(
        credential::current_purpose(&handle),
        Some(Purpose::ChangeRecoveryPassphrase)
    );
    let win = window(&app, "credential")?;
    let context = call(&win, "credential_context", json!({}))
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(context["purpose"], "change_recovery_passphrase");
    assert_eq!(context["note_available"], json!(false));
    // Asked again: the same window is shown again (its purpose and state stay).
    assert_eq!(
        call(&settings, "recovery_passphrase_change", json!({})).await,
        Ok(Value::Null)
    );

    let new = "a new recovery passphrase t14";
    for (body, class) in [
        (
            json!({"secret": new, "secret_confirm": "a new recovery passphrase T14"}),
            "passphrase_mismatch",
        ),
        (
            json!({"secret": "eleven-char", "secret_confirm": "eleven-char"}),
            "passphrase_too_short",
        ),
    ] {
        assert_eq!(
            call(&win, "submit_secret", body).await,
            Ok(json!({"failed": {"class": class}}))
        );
    }
    assert_eq!(
        call(&win, "submit_secret", json!({ "secret": new })).await,
        Err(json!({"kind": "invalid_argument", "field": "secret_confirm"}))
    );
    assert_eq!(passphrase_changes(&state)?.0, 0, "nothing changed yet");
    assert_eq!(
        call(&win, "save_recovery_note", json!({})).await,
        Err(json!({"kind": "not_ready"})),
        "no note before the change"
    );

    assert_eq!(
        call(
            &win,
            "submit_secret",
            json!({"secret": new, "secret_confirm": new})
        )
        .await,
        Ok(json!({"accepted": {}}))
    );
    assert_eq!(passphrase_changes(&state)?.0, 1);
    let context = call(&win, "credential_context", json!({}))
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(context["note_available"], json!(true));
    assert_eq!(
        credential::current_purpose(&handle),
        Some(Purpose::ChangeRecoveryPassphrase),
        "the window stays for the note"
    );
    // A window open for something else refuses the trigger.
    credential::close(&handle);
    let tmp = scratch()?;
    let other = app_with_data_dir(tmp.path())?;
    let other_handle = other.handle().clone();
    let _restore = credential::request_restore_passphrase(&other_handle, Show::Focus)?;
    let slot = ServeSlot::default();
    slot.set(state.clone());
    other.manage(slot);
    let other_settings = window(&other, "settings")?;
    assert_eq!(
        call(&other_settings, "recovery_passphrase_change", json!({})).await,
        Err(json!({"kind": "busy"}))
    );
    assert_eq!(
        credential::current_purpose(&other_handle),
        Some(Purpose::RestoreBackup)
    );
    stop(&state).await
}

/// §8.6 (M6 final review M-13: the old test rendered the note from facts it built itself): the
/// recovery note is written through `save_recovery_note`'s own path (its save dialog replaced by a
/// temp file) after a real recovery-passphrase change with a canary passphrase through the window.
/// The note names the install, the chain and the data dir and never the passphrase; neither does
/// any answer or any record of the log.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_note_has_no_passphrase() -> TestResult {
    let canary = "canary-note-passphrase-5d1e";
    let (w, state, app) = serving_world().await?;
    let handle = app.handle().clone();
    let settings = window(&app, "settings")?;
    let opened = call(&settings, "recovery_passphrase_change", json!({})).await;
    assert_eq!(opened, Ok(Value::Null));
    let win = window(&app, "credential")?;
    let answer = call(
        &win,
        "submit_secret",
        json!({"secret": canary, "secret_confirm": canary}),
    )
    .await;
    assert_eq!(answer, Ok(json!({"accepted": {}})));
    let context = call(&win, "credential_context", json!({})).await;
    assert!(!format!("{context:?}").contains(canary));

    let note = w.tmp.path().join("note.txt");
    let target = note.clone();
    let saved = commands::credential::save_note_with(&handle, move || Ok(Some(target))).await;
    assert_eq!(saved.map(|s| s.saved), Ok(true));
    let text = std::fs::read_to_string(&note)?;
    assert!(!text.contains(canary), "{text}");
    let (id, chain_id, data) = state.note_facts().ok_or("no store facts")?;
    for want in [
        id.as_str(),
        chain_id.as_str(),
        &data.display().to_string(),
        credential::PASSPHRASE_PURPOSE,
    ] {
        assert!(text.contains(want), "{want}");
    }
    let (changes, payloads) = passphrase_changes(&state)?;
    assert_eq!(changes, 1, "the note followed a real change");
    assert!(
        payloads.iter().all(|p| !p.contains(canary)),
        "a record holds the passphrase"
    );
    // A cancelled save dialog writes nothing.
    let unsaved = commands::credential::save_note_with(&handle, || Ok(None)).await;
    assert_eq!(unsaved.map(|s| s.saved), Ok(false));
    stop(&state).await
}

// ---------- Recover this log ----------

/// §8.7, PD-05: "Recover this log" with the store's passphrase recovers the store, starts the core
/// and swaps the cell without a rebind: the endpoint file is the same, the same connection is now
/// answered by the core, and the window closes. A wrong passphrase changes nothing and keeps it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recover_this_log_swaps_handler_without_rebind() -> TestResult {
    let w = World::new()?;
    let state = w.lost(PASSPHRASE, Answers::new(vec![])).await?;
    let endpoint = read_endpoint_file(&w.data)?;
    assert!(endpoint.is_some());
    let gate_handler = state.cell.current();
    let mut c = w.connect().await?;
    let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
    assert_eq!(reason(&reply.envelope), Some("keychain_lost"));

    let app = w.app(&state)?;
    let handle = app.handle().clone();
    open_credential(&handle, Unlock::Recover, Show::Focus)?;
    let win = window(&app, "credential")?;
    let context = call(&win, "credential_context", json!({})).await;
    assert_eq!(
        context
            .as_ref()
            .ok()
            .and_then(|c| c.get("purpose").cloned()),
        Some(json!("recover_this_log"))
    );
    assert_eq!(
        context
            .as_ref()
            .ok()
            .and_then(|c| c.get("refused_count").cloned()),
        Some(json!(1))
    );

    assert_eq!(
        call(
            &win,
            "submit_secret",
            json!({"secret": "not the passphrase"})
        )
        .await,
        Ok(json!({"failed": {"class": "wrong_passphrase"}}))
    );
    assert!(state.core.get().is_none());
    assert!(Arc::ptr_eq(&state.cell.current(), &gate_handler));
    assert!(
        app.get_webview_window("credential").is_some(),
        "window stays"
    );
    // One entry only.
    assert_eq!(
        call(
            &win,
            "submit_secret",
            json!({"secret": PASSPHRASE, "secret_confirm": PASSPHRASE})
        )
        .await,
        Err(json!({"kind": "invalid_argument", "field": "secret_confirm"}))
    );

    assert_eq!(
        call(&win, "submit_secret", json!({ "secret": PASSPHRASE })).await,
        Ok(json!({"unlocked": {}}))
    );
    assert!(state.core.get().is_some());
    assert_eq!(state.refused(), None, "the gate is gone");
    assert!(!Arc::ptr_eq(&state.cell.current(), &gate_handler));
    assert_eq!(read_endpoint_file(&w.data)?, endpoint, "no rebind");
    // The same connection, now answered by the core.
    let instances: Envelope = c.call("instances.list", json!({})).await?;
    assert_eq!(instances.status, Status::Succeeded, "{instances:?}");
    closed(&handle).await?;
    assert_eq!(
        call(&win, "submit_secret", json!({ "secret": PASSPHRASE })).await,
        Err(json!({"kind": "not_ready"}))
    );
    // A second unlock finds a serving core.
    assert_eq!(
        unlock(
            &state,
            UnlockKind::RecoverThisLog,
            SecretString::from(PASSPHRASE)
        )
        .await,
        Err(UnlockFailure::NotLocked)
    );
    stop(&state).await
}

/// §8.7: "Archive old DB and start fresh" asks natively first (Cancel moves nothing), then moves
/// the store aside (never deleting it), serves the first-run answer and hands the archived file
/// to the wizard; the credential window closes and the setup window opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_and_start_fresh_confirms_then_moves_the_store_aside() -> TestResult {
    let w = World::new()?;
    let answers = Answers::new(vec![Confirm::Cancel]);
    let state = w.lost(PASSPHRASE, answers.clone()).await?;
    let app = w.app(&state)?;
    let handle = app.handle().clone();
    open_credential(&handle, Unlock::Recover, Show::Focus)?;
    let win = window(&app, "credential")?;
    let files = w.files()?;
    assert!(files.contains("audit.db"));

    assert_eq!(
        call(&win, "archive_and_start_fresh", json!({})).await,
        Ok(json!({"failed": {"class": "cancelled"}}))
    );
    assert_eq!(w.files()?, files, "nothing moved");
    let shown = answers.texts();
    assert_eq!(shown.len(), 1);
    assert!(
        shown[0].contains(&w.data.path().join("archived").display().to_string()),
        "{}",
        shown[0]
    );

    let archived = call(&win, "archive_and_start_fresh", json!({})).await;
    let file = archived
        .as_ref()
        .ok()
        .and_then(|a| a["archived"]["archived_file"].as_str())
        .ok_or(format!("{archived:?}"))?
        .to_owned();
    assert!(file.starts_with("archived/audit-"), "{file}");
    assert!(w.data.path().join(&file).is_file());
    assert!(!w.data.path().join("audit.db").exists());
    let kept = credential::take_archived(&handle).ok_or("no archived db for the wizard")?;
    assert_eq!(kept.file, file);
    // No store now: the first-run answer until `GENESIS` (§2.5).
    let mut c = w.connect().await?;
    let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
    assert_eq!(reason(&reply.envelope), Some("first_run"));
    eventually("the setup window opened", || {
        app.get_webview_window("setup").is_some()
    })
    .await?;
    closed(&handle).await?;
    // The archived store is no longer `keychain_lost`: nothing to archive twice.
    assert_eq!(
        atlas_duck_app_lib::serve::archive_and_start_fresh(&state).await,
        Err(UnlockFailure::NotLocked)
    );
    stop(&state).await
}

/// PD-89: "Retry keychain" runs one more keystore + `open` while locked `keychain_unavailable`
/// (here: the keychain is back, so the core serves); in any other state it is `not_ready`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retry_keychain_runs_one_open() -> TestResult {
    let w = World::new()?;
    let ring = MemKeyring::new();
    let install_id = w.provision(&ring, PASSPHRASE)?;
    let keys = MemKeys::new(ring, false);
    // No schedule: the automatic retries are over.
    let state = start_with(w.inputs(Some(install_id), keys.clone(), Answers::new(vec![]), vec![]))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let app = w.app(&state)?;
    let handle = app.handle().clone();
    open_credential(&handle, Unlock::Unlock, Show::Focus)?;
    let win = window(&app, "credential")?;
    assert_eq!(
        call(&win, "credential_context", json!({}))
            .await
            .ok()
            .and_then(|c| c.get("purpose").cloned()),
        Some(json!("unlock"))
    );
    // Nothing to type while `keychain_unavailable` (L39).
    assert_eq!(
        call(&win, "submit_secret", json!({"secret": "anything"})).await,
        Err(json!({"kind": "not_ready"}))
    );
    let state2 = state.clone();
    eventually("the automatic retries ended", || {
        !state2.keychain_retrying()
    })
    .await?;
    let calls = keys.calls.load(Ordering::SeqCst);
    keys.available.store(true, Ordering::SeqCst);
    assert_eq!(
        call(&win, "retry_keychain", json!({})).await,
        Ok(json!({"started": true}))
    );
    let state3 = state.clone();
    eventually("the core serves", || state3.core.get().is_some()).await?;
    assert_eq!(keys.calls.load(Ordering::SeqCst), calls + 1, "one open");
    assert_eq!(
        call(&win, "retry_keychain", json!({})).await,
        Err(json!({"kind": "not_ready"}))
    );
    stop(&state).await
}

// ---------- M6 T22: the window follows the serving state ----------

/// The app's watcher in the mock runtime: counts the calls and lets an open credential window
/// follow the serving state (`follow_serving`, on a thread of its own as the real one does).
struct Follower {
    app: std::sync::OnceLock<tauri::AppHandle<MockRuntime>>,
    calls: std::sync::atomic::AtomicU32,
}

impl Follower {
    fn new() -> Arc<Follower> {
        Arc::new(Follower {
            app: std::sync::OnceLock::new(),
            calls: std::sync::atomic::AtomicU32::new(0),
        })
    }

    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }

    fn hooks(self: &Arc<Self>) -> ServeHooks {
        ServeHooks {
            watcher: Some(self.clone()),
            ..ServeHooks::default()
        }
    }
}

impl ServeWatcher for Follower {
    fn serving_changed(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(app) = self.app.get() {
            let app = app.clone();
            std::thread::spawn(move || credential::follow::follow_serving(&app));
        }
    }
}

/// M6 T22 m-1: the window is destroyed while another open holds the `opening` lock: the purpose
/// and the first-run sender still go once that open is over, so the wizard's receiver errors
/// instead of waiting for a window that is not there.
// The held guard stands in for an open in flight; nothing else in this test takes `opening`.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn window_destroyed_resets_even_while_another_open_runs() -> TestResult {
    let tmp = scratch()?;
    let app = app()?;
    let data = local_data_dir(tmp.path())?;
    let lock = Arc::new(InstanceLock::acquire(&data, HOST)?);
    app.manage(DataDirHold::new(data, lock));
    let handle = app.handle().clone();
    let mut rx = credential::request_recovery_passphrase(&handle, Show::Focus)?;
    assert_eq!(
        credential::current_purpose(&handle),
        Some(Purpose::RecoveryPassphrase)
    );

    // A window that is still there keeps its purpose (the check is the open's, not a reflex),
    // with no open running and with one running.
    credential::window_destroyed_if(&handle, |_| false);
    let registry = app.state::<WindowRegistry>();
    let other_open = registry.try_opening().ok_or("opening is held")?;
    credential::window_destroyed_if(&handle, |_| false);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        credential::current_purpose(&handle),
        Some(Purpose::RecoveryPassphrase)
    );
    drop(other_open);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        credential::current_purpose(&handle),
        Some(Purpose::RecoveryPassphrase)
    );

    let other_open = registry.try_opening().ok_or("opening is held")?;
    credential::window_destroyed_if(&handle, |_| true);
    // The main thread's call did not wait, and did nothing yet: the other open is in flight.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        credential::current_purpose(&handle),
        Some(Purpose::RecoveryPassphrase),
        "nothing reset while the lock is held"
    );
    drop(other_open);
    let h = handle.clone();
    eventually("the destroyed window's purpose went", move || {
        credential::current_purpose(&h).is_none()
    })
    .await?;
    assert!(
        matches!(
            rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ),
        "the sender went with the window"
    );

    Ok(())
}

/// M6 T22 m-2: a close meant for one window leaves any other alone, and closes nothing once its
/// own window is gone.
#[test]
fn close_if_only_closes_its_own_window() -> TestResult {
    let tmp = scratch()?;
    let app = app()?;
    let data = local_data_dir(tmp.path())?;
    let lock = Arc::new(InstanceLock::acquire(&data, HOST)?);
    app.manage(DataDirHold::new(data, lock));
    let handle = app.handle();
    open_credential(handle, Unlock::Unlock, Show::Focus)?;
    let (purpose, generation) = credential::current_window(handle).ok_or("no window")?;
    assert_eq!(purpose, Purpose::Unlock);

    // Another window's generation: nothing closes.
    assert!(!credential::close_if(handle, generation.wrapping_add(1)));
    assert_eq!(credential::current_purpose(handle), Some(Purpose::Unlock));
    // Its own: closed, and a second close of it finds nothing.
    assert!(credential::close_if(handle, generation));
    assert_eq!(credential::current_purpose(handle), None);
    assert!(!credential::close_if(handle, generation));
    Ok(())
}

/// M6 T22 m-4: a caller that drops its `unlock` future (the command future is dropped when the
/// window goes) does not release the one-at-a-time guard of the work still running: a second
/// unlock is `Busy` until the first finished.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_unlock_caller_keeps_the_guard() -> TestResult {
    let w = World::new()?;
    let (state, keys) = w
        .lost_with(PASSPHRASE, Answers::new(vec![]), ServeHooks::default())
        .await?;
    keys.hold(true);
    let before = keys.calls();
    let st = state.clone();
    let caller = tokio::spawn(async move {
        unlock(
            &st,
            UnlockKind::RecoverThisLog,
            SecretString::from(PASSPHRASE),
        )
        .await
    });
    let k = keys.clone();
    eventually("the unlock reached the keychain", move || {
        k.calls() > before
    })
    .await?;
    caller.abort();
    let _ = caller.await;
    assert!(state.unlock_busy(), "the work still holds the guard");
    assert_eq!(
        unlock(
            &state,
            UnlockKind::RecoverThisLog,
            SecretString::from(PASSPHRASE)
        )
        .await,
        Err(UnlockFailure::Busy)
    );
    keys.hold(false);
    let st = state.clone();
    eventually("the work finished and served", move || {
        st.core.get().is_some() && !st.unlock_busy()
    })
    .await?;
    stop(&state).await
}

/// M6 T22 m-8: a recovery that took but whose core did not start leaves no stale `keychain_lost`
/// gate: the gate says `keychain_unavailable`, and "Retry keychain" starts the core.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_core_start_failure_after_recovery_leaves_no_stale_lost_gate() -> TestResult {
    let w = World::new()?;
    let fail = Arc::new(std::sync::atomic::AtomicU32::new(1));
    let watcher = Follower::new();
    let hooks = ServeHooks {
        fail_core_start: Some(fail.clone()),
        ..watcher.hooks()
    };
    let (state, _keys) = w.lost_with(PASSPHRASE, Answers::new(vec![]), hooks).await?;
    let seen = watcher.calls();
    assert_eq!(
        unlock(
            &state,
            UnlockKind::RecoverThisLog,
            SecretString::from(PASSPHRASE)
        )
        .await,
        Err(UnlockFailure::CoreStart)
    );
    assert_eq!(fail.load(Ordering::SeqCst), 0, "the failure was used");
    assert_eq!(
        state.gate_state(),
        Some(GateState::Locked(LockedReason::KeychainUnavailable))
    );
    assert!(watcher.calls() > seen, "the tray hears of the new gate");
    // A second "Recover this log" has nothing to recover.
    assert_eq!(
        unlock(
            &state,
            UnlockKind::RecoverThisLog,
            SecretString::from(PASSPHRASE)
        )
        .await,
        Err(UnlockFailure::NotLocked)
    );
    assert_eq!(retry_keychain_now(&state), RetryNow::Started);
    let st = state.clone();
    eventually("the retry started the core", move || {
        st.core.get().is_some()
    })
    .await?;
    stop(&state).await
}

/// M6 T22 m-5: the retry turns `keychain_unavailable` into `keychain_lost` behind an open Unlock
/// window: the window moves to "Recover this log" instead of staying on a page with nothing to
/// retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unlock_window_follows_the_retry_into_keychain_lost() -> TestResult {
    let w = World::new()?;
    let watcher = Follower::new();
    let (state, keys) = w.unavailable(true, watcher.hooks()).await?;
    let app = w.app(&state)?;
    let handle = app.handle().clone();
    assert!(watcher.app.set(handle.clone()).is_ok());
    open_credential(&handle, Unlock::Unlock, Show::Focus)?;
    let _win = window(&app, "credential")?;
    let st = state.clone();
    eventually("the automatic retries ended", move || {
        !st.keychain_retrying()
    })
    .await?;
    assert_eq!(credential::current_purpose(&handle), Some(Purpose::Unlock));

    keys.available.store(true, Ordering::SeqCst);
    assert_eq!(retry_keychain_now(&state), RetryNow::Started);
    let h = handle.clone();
    eventually("the window moved to recovery", move || {
        credential::current_purpose(&h) == Some(Purpose::RecoverThisLog)
    })
    .await?;
    assert_eq!(app.webview_windows().len(), 1, "the same window");
    stop(&state).await
}

/// M6 T22 (T20/T21 handoff): a manual retry that starts the core closes the open Unlock window
/// (nothing is left to unlock) and tells the watcher (the tray is rebuilt); a second retry while a
/// core serves is `NotLocked`, and the tray's entry answers the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_manual_retry_closes_the_window_and_refreshes_the_tray() -> TestResult {
    let w = World::new()?;
    let watcher = Follower::new();
    let (state, keys) = w.unavailable(false, watcher.hooks()).await?;
    let app = w.app(&state)?;
    let handle = app.handle().clone();
    assert!(watcher.app.set(handle.clone()).is_ok());
    open_credential(&handle, Unlock::Unlock, Show::Focus)?;
    let _win = window(&app, "credential")?;
    let st = state.clone();
    eventually("the automatic retries ended", move || {
        !st.keychain_retrying()
    })
    .await?;
    let calls = keys.calls();
    let seen = watcher.calls();

    // The tray's "Retry keychain": one open, with the keychain back.
    keys.available.store(true, Ordering::SeqCst);
    let slot_state = app.state::<ServeSlot>();
    let slot: &ServeSlot = &slot_state;
    assert_eq!(
        retry_keychain_from_menu(Some(slot)),
        Some(RetryNow::Started)
    );
    let st = state.clone();
    eventually("the core serves", move || st.core.get().is_some()).await?;
    closed(&handle).await?;
    assert_eq!(keys.calls(), calls + 1, "exactly one open");
    let st = state.clone();
    eventually("the retry ended", move || !st.keychain_retrying()).await?;
    assert!(watcher.calls() > seen, "the tray was told");
    assert_eq!(
        retry_keychain_from_menu(Some(slot)),
        Some(RetryNow::NotLocked)
    );
    assert_eq!(retry_keychain_from_menu(None), None);
    assert_eq!(serving_snapshot(Some(slot)), AppSnapshot::Serving);
    stop(&state).await
}

/// M6 T22 (M4 T19 notes): a core that fails to start under a retry is a failed store, not a gate
/// that waits: the tray says so, a relaunch shows the PD-06 dialog, nothing offers a retry again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_retry_is_a_failed_store_the_relaunch_says_so() -> TestResult {
    let w = World::new()?;
    let watcher = Follower::new();
    let hooks = ServeHooks {
        fail_core_start: Some(Arc::new(std::sync::atomic::AtomicU32::new(1))),
        ..watcher.hooks()
    };
    let (state, keys) = w.unavailable(false, hooks).await?;
    let app = w.app(&state)?;
    let slot_state = app.state::<ServeSlot>();
    let slot: &ServeSlot = &slot_state;
    let st = state.clone();
    eventually("the automatic retries ended", move || {
        !st.keychain_retrying()
    })
    .await?;
    assert!(!state.store_failed());
    assert_eq!(
        serving_snapshot(Some(slot)),
        AppSnapshot::Gate(GateState::Locked(LockedReason::KeychainUnavailable))
    );
    keys.available.store(true, Ordering::SeqCst);
    assert_eq!(retry_keychain_now(&state), RetryNow::Started);
    let st = state.clone();
    eventually("the store is failed", move || {
        st.store_failed() && !st.keychain_retrying()
    })
    .await?;

    let snapshot = serving_snapshot(Some(slot));
    assert_eq!(snapshot, AppSnapshot::StoreUnavailable);
    // The cell serves the failed-store gate, not the stale locked one (M9 Δ4, L217).
    assert_eq!(state.gate_state(), Some(GateState::StoreFailed));
    assert_eq!(
        status_lines(&snapshot, &StatusInputs::default()),
        vec![MSG_STORE_UNAVAILABLE.to_owned()]
    );
    assert_eq!(
        route_relaunch(&snapshot, &[std::ffi::OsString::from("atlas-duck")]),
        Relaunch::ShowErrorDialog(MSG_STORE_UNAVAILABLE.into())
    );
    assert_eq!(retry_keychain_now(&state), RetryNow::NotLocked);
    stop(&state).await
}

/// M6 T22 review m-2: an I/O error of the retry's `open` (a transient lock) is not a failed store:
/// the gate stays locked and "Retry keychain" runs again, and then starts the core.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_io_error_of_the_retry_open_keeps_a_manual_retry_possible() -> TestResult {
    let w = World::new()?;
    let watcher = Follower::new();
    let fail = Arc::new(std::sync::atomic::AtomicU32::new(1));
    let hooks = ServeHooks {
        fail_retry_open: Some(fail.clone()),
        ..watcher.hooks()
    };
    let (state, keys) = w.unavailable(false, hooks).await?;
    let st = state.clone();
    eventually("the automatic retries ended", move || {
        !st.keychain_retrying()
    })
    .await?;
    keys.available.store(true, Ordering::SeqCst);
    assert_eq!(retry_keychain_now(&state), RetryNow::Started);
    let st = state.clone();
    eventually("the failed retry ended", move || !st.keychain_retrying()).await?;
    assert_eq!(fail.load(Ordering::SeqCst), 0, "the failure was used");
    assert!(!state.store_failed());
    assert_eq!(
        state.gate_state(),
        Some(GateState::Locked(LockedReason::KeychainUnavailable))
    );
    assert_eq!(retry_keychain_now(&state), RetryNow::Started);
    let st = state.clone();
    eventually("the second retry started the core", move || {
        st.core.get().is_some()
    })
    .await?;
    stop(&state).await
}

/// M6 T22 review m-3: a retry started from anywhere (the credential window's command included)
/// tells the watcher at once, so the tray shows "Waiting for keyring" while it runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_started_retry_tells_the_watcher_at_once() -> TestResult {
    let w = World::new()?;
    let watcher = Follower::new();
    let (state, keys) = w.unavailable(false, watcher.hooks()).await?;
    let st = state.clone();
    eventually("the automatic retries ended", move || {
        !st.keychain_retrying()
    })
    .await?;
    keys.hold(true);
    let seen = watcher.calls();
    assert_eq!(retry_keychain_now(&state), RetryNow::Started);
    let (running, told) = (state.keychain_retrying(), watcher.calls() > seen);
    // Released before the asserts: a held keystore would hang the runtime's shutdown.
    keys.hold(false);
    assert!(running, "the retry still runs (held)");
    assert!(told, "told when it started");
    let st = state.clone();
    eventually("the retry ended", move || !st.keychain_retrying()).await?;
    stop(&state).await
}

/// M6 T22 (L78): an `open` that blocks past the threshold raises the keychain prompt hint and
/// tells the watcher; it goes again when the open returns. (The threshold is 10 s in production.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blocked_open_raises_the_keychain_prompt_hint() -> TestResult {
    let w = World::new()?;
    let ring = MemKeyring::new();
    let install_id = w.provision(&ring, PASSPHRASE)?;
    let keys = MemKeys::new(ring, true);
    keys.hold(true);
    let watcher = Follower::new();
    let hooks = ServeHooks {
        keychain_prompt_after: Duration::from_millis(150),
        keychain_prompt_enabled: true,
        ..watcher.hooks()
    };
    let flag = hooks.keychain_prompt.clone();
    let mut inputs = w.inputs(Some(install_id), keys.clone(), Answers::new(vec![]), vec![]);
    inputs.hooks = hooks;
    let starting = tokio::spawn(start_with(inputs));
    let f = flag.clone();
    eventually("the hint came up", move || f.load(Ordering::SeqCst)).await?;
    assert!(watcher.calls() >= 1, "the tray hears of the hint");
    assert!(!starting.is_finished(), "the open is still blocked");

    keys.hold(false);
    let state = starting.await?.map_err(|e| format!("{e:?}"))?;
    assert!(!flag.load(Ordering::SeqCst), "the hint went with the open");
    assert!(watcher.calls() >= 2);
    stop(&state).await
}

/// M6 T22 (L78): an `open` that is quick never shows the hint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_quick_open_shows_no_keychain_prompt_hint() -> TestResult {
    let w = World::new()?;
    let ring = MemKeyring::new();
    let install_id = w.provision(&ring, PASSPHRASE)?;
    let keys = MemKeys::new(ring, true);
    let watcher = Follower::new();
    let flag = watcher.hooks().keychain_prompt;
    let mut inputs = w.inputs(Some(install_id), keys, Answers::new(vec![]), vec![]);
    inputs.hooks = ServeHooks {
        keychain_prompt: flag.clone(),
        ..watcher.hooks()
    };
    let state = start_with(inputs).await.map_err(|e| format!("{e:?}"))?;
    assert!(!flag.load(Ordering::SeqCst));
    assert_eq!(
        watcher.calls(),
        0,
        "the hint never came, so nothing to tell"
    );
    stop(&state).await
}

// ---------- the connection test (I-33) ----------

#[cfg(feature = "scripted-approver")]
mod pat {
    use atlas_duck_app_lib::commands::CommandError;
    use atlas_duck_app_lib::commands::credential::{
        SubmitOutcome, SubmitSecretArgs, submit_pat_dto,
    };
    use atlas_duck_app_lib::commands::dto::parse;
    use atlas_duck_app_lib::credential::{self, PatTarget};
    use atlas_duck_atlassian::CredentialProvider;
    use atlas_duck_atlassian::testing::{
        TEST_PAT, TEST_USER, TEST_USER_KEY, TestTlsServer, XAuser,
    };
    use atlas_duck_audit::EventType;
    use atlas_duck_core::AdminError;
    use atlas_duck_core::testing::{Harness, InstanceAt};
    use atlas_duck_registry::Product;
    use serde_json::{Value, json};

    use super::TestResult;

    type Boxed = Box<dyn std::error::Error>;

    const NEW_PAT: &str = "a-new-pat-0f9e8d";

    fn args(v: Value) -> Result<SubmitSecretArgs, Boxed> {
        parse::<SubmitSecretArgs>(&v).map_err(|e| format!("{e:?}").into())
    }

    fn target(h: &Harness, alias: &str) -> Result<PatTarget, Boxed> {
        Ok(credential::pat_target(&h.instances().list(), alias)?)
    }

    fn stored_pat(h: &Harness, alias: &str) -> Result<Option<String>, Boxed> {
        let id = h.instance(alias).ok_or("no instance")?.id.clone();
        Ok(h.credentials()
            .load(&id)?
            .map(|c| c.pat.expose_secret().to_owned()))
    }

    async fn submit(h: &Harness, t: &PatTarget, body: Value) -> Result<SubmitOutcome, Boxed> {
        submit_pat_dto(h.instances(), t, args(body)?)
            .await
            .map_err(|e| format!("{e:?}").into())
    }

    fn failed(class: &str) -> Value {
        json!({ "failed": { "class": class } })
    }

    /// I-33: a failing connection test (401, TLS, version below the floor) stores nothing: no
    /// `CREDENTIAL_CHANGED`, the old PAT kept, and the answer is a `failed` class, on which the
    /// window stays open (only an unlock closes it).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn i33_failing_connection_test_stores_nothing() -> TestResult {
        let h = Harness::jira().await?;
        let t = target(&h, "jira-main")?;
        let mock = h.mock("jira-main").ok_or("no mock")?;
        let body = json!({ "secret": NEW_PAT, "expires_on": "2027-06-30" });

        // A JSON 401 from the identity call.
        mock.server().reset().await;
        mock.json("/rest/api/2/myself", 401, r#"{"message":"no"}"#)
            .await;
        let out = submit(&h, &t, body.clone()).await?;
        assert_eq!(serde_json::to_value(&out)?, failed("http_401"));
        // A version below the floor (§7.1).
        mock.server().reset().await;
        mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
            .await;
        mock.jira_server_info("8.13.0").await;
        let out = submit(&h, &t, body.clone()).await?;
        assert_eq!(serde_json::to_value(&out)?, failed("version_below_floor"));
        assert_eq!(stored_pat(&h, "jira-main")?.as_deref(), Some(TEST_PAT));
        assert!(h.events_of(EventType::CREDENTIAL_CHANGED).await?.is_empty());
        assert_eq!(
            h.instances().list()[0].state,
            "ok",
            "the old token still works"
        );
        Ok(())
    }

    /// The TLS class (§11.2 hint): an https instance whose CA nobody trusts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn i33_tls_failure_stores_nothing() -> TestResult {
        let server = TestTlsServer::start().await?;
        let h = Harness::builder()
            .instance_at(
                "tls",
                Product::Jira,
                InstanceAt {
                    base_url: format!("{}/jira", server.base_url()),
                    ..InstanceAt::default()
                },
            )
            .start()
            .await?;
        let t = target(&h, "tls")?;
        let out = submit(&h, &t, json!({ "secret": NEW_PAT })).await?;
        assert_eq!(
            serde_json::to_value(&out)?,
            json!({"failed": {"class": "tls", "conn": "tls_unknown_issuer"}})
        );
        assert_eq!(stored_pat(&h, "tls")?.as_deref(), Some(TEST_PAT));
        assert!(h.events_of(EventType::CREDENTIAL_CHANGED).await?.is_empty());
        Ok(())
    }

    /// I-33: a passing test answers "Connected as <user>, Jira <version>" and stores the PAT with
    /// its expiry (`CREDENTIAL_CHANGED {expires_at}`); the answer never holds the PAT.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn i33_passing_test_shows_user_and_version() -> TestResult {
        let h = Harness::jira().await?;
        let t = target(&h, "jira-main")?;
        let mock = h.mock("jira-main").ok_or("no mock")?;
        mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
            .await;
        mock.jira_server_info("9.12.0").await;
        let out = submit(
            &h,
            &t,
            json!({ "secret": NEW_PAT, "expires_on": "2027-06-30" }),
        )
        .await?;
        let wire = serde_json::to_value(&out)?;
        assert_eq!(
            wire,
            json!({"ok": {"atlassian_user": TEST_USER, "product": "jira", "version": "9.12.0", "warnings": []}})
        );
        assert!(!wire.to_string().contains(NEW_PAT));
        assert_eq!(stored_pat(&h, "jira-main")?.as_deref(), Some(NEW_PAT));
        let changed = h.events_of(EventType::CREDENTIAL_CHANGED).await?;
        assert_eq!(changed.len(), 1, "{changed:?}");
        assert_eq!(changed[0]["change"], "replaced");
        assert_eq!(changed[0]["expires_at"], "2027-06-30");
        Ok(())
    }

    /// The window shows the instance as it was when Rust opened it: if its URL changed since, the
    /// token is not sent anywhere (`context_changed`); keys of other purposes are refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pat_for_a_changed_instance_is_not_sent() -> TestResult {
        let h = Harness::jira().await?;
        let mut t = target(&h, "jira-main")?;
        t.origin = "https://moved.example/jira".into();
        let out = submit(&h, &t, json!({ "secret": NEW_PAT })).await?;
        assert_eq!(serde_json::to_value(&out)?, failed("context_changed"));
        let mock = h.mock("jira-main").ok_or("no mock")?;
        assert!(
            mock.received()
                .await
                .iter()
                .all(|r| !r.url.path().ends_with("/myself")),
            "no connection test ran"
        );
        let t = target(&h, "jira-main")?;
        let r = submit_pat_dto(
            h.instances(),
            &t,
            args(json!({"secret": NEW_PAT, "secret_confirm": NEW_PAT}))?,
        )
        .await;
        assert_eq!(
            r,
            Err(CommandError::InvalidArgument {
                field: "secret_confirm"
            })
        );
        let mut gone = t.clone();
        gone.alias = "deleted".into();
        let r = submit_pat_dto(h.instances(), &gone, args(json!({ "secret": NEW_PAT }))?).await;
        assert_eq!(r, Err(CommandError::Admin(AdminError::NotFound)));
        assert_eq!(stored_pat(&h, "jira-main")?.as_deref(), Some(TEST_PAT));
        Ok(())
    }

    /// The Harness lists an unconfirmed and an `http://` instance as the window must refuse them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn harness_states_are_refused_for_the_window() -> TestResult {
        let h = Harness::builder()
            .jira("jira-main")
            .unconfirmed()
            .start()
            .await?;
        assert_eq!(
            credential::pat_target(&h.instances().list(), "jira-main"),
            Err(AdminError::Unconfirmed)
        );
        let h = Harness::builder()
            .jira("jira-main")
            .strict_https()
            .start()
            .await?;
        assert_eq!(
            credential::pat_target(&h.instances().list(), "jira-main"),
            Err(AdminError::InsecureScheme)
        );
        Ok(())
    }
}

// ---------- S-16: no secret anywhere ----------

#[cfg(feature = "scripted-approver")]
mod canary {
    use std::io::Write;
    use std::sync::{Arc, Mutex, OnceLock};

    use atlas_duck_app_lib::commands;
    use atlas_duck_app_lib::credential;
    use atlas_duck_app_lib::diag::fields::allowlist_layer;
    use atlas_duck_app_lib::ui_sink::EventOut;
    use atlas_duck_app_lib::windows::{Show, Unlock, open_credential};
    use atlas_duck_atlassian::Product as AtlProduct;
    use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser};
    use atlas_duck_core::testing::capture::Channel;
    use serde_json::{Value, json};
    use tauri::Manager;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;

    use super::{Answers, TestResult, World, call, eventually, stop, window};

    const PAT_CANARY: &str = "canary-pat-S16-91c2e4";
    const PASS_CANARY: &str = "canary-pass-S16-7a3b5f";
    const WRONG_CANARY: &str = "canary-wrong-S16-0d8c";
    const FIRST_RUN_CANARY: &str = "canary-firstrun-S16-44e1";
    /// Logged on purpose at the end (the capture's own negative control).
    const CONTROL_CANARY: &str = "canary-control-S16-b6";

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if let Ok(mut v) = self.0.lock() {
                v.extend_from_slice(b);
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    impl Buf {
        fn text(&self) -> String {
            self.0
                .lock()
                .map(|v| String::from_utf8_lossy(&v).into_owned())
                .unwrap_or_default()
        }
    }

    /// The process-wide log capture of this test binary: the diagnostic log's allowlist layer
    /// (what reaches `<data>/logs`) and, stricter, every event of atlas-duck's own crates with
    /// all its fields and its message.
    fn logs() -> &'static (Buf, Buf) {
        static LOGS: OnceLock<(Buf, Buf)> = OnceLock::new();
        LOGS.get_or_init(|| {
            let (diag, raw) = (Buf::default(), Buf::default());
            let all = tracing_subscriber::fmt::layer()
                .with_writer(raw.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::filter_fn(|m| {
                    m.target().starts_with("atlas_duck")
                }));
            let subscriber = tracing_subscriber::registry()
                .with(allowlist_layer(diag.clone()))
                .with(all);
            let _ = tracing::subscriber::set_global_default(subscriber);
            (diag, raw)
        })
    }

    fn config(mock: &MockDc) -> String {
        format!(
            "schema_version = 1\n\n[[instances]]\nalias = \"jira-main\"\nproduct = \"jira\"\nbase_url = \"{}\"\ndefault = true\n",
            mock.base_url()
        )
    }

    /// S-16 (Tauri half): a PAT and passphrases typed into the credential window (a wrong and a
    /// right recovery passphrase, a PAT failing and passing its test, a first-run pair) appear in
    /// no command response, no event payload, no capture record and no log line, while the PAT
    /// demonstrably reached the server (the sweep is not vacuous).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn s16_tauri_capture_has_no_pat_or_passphrase_canary() -> TestResult {
        let (diag, raw) = logs();
        let w = World::new()?;
        let mock = MockDc::start(AtlProduct::Jira, "/jira").await;
        std::fs::write(w.config_dir().join("config.toml"), config(&mock))?;
        let state = w.lost(PASS_CANARY, Answers::new(vec![])).await?;
        // One recorder for the three windows below (the mock runtime never reports a destroyed
        // window, so each window lives in an app of its own, all serving the same state).
        let cap = commands::capture::bounded();
        let app_for = |w: &World| -> Result<_, Box<dyn std::error::Error>> {
            let app = w.app(&state)?;
            assert!(commands::capture::install(app.handle(), cap.clone()));
            Ok(app)
        };
        let app = app_for(&w)?;
        let handle = app.handle().clone();
        let mut responses: Vec<String> = Vec::new();
        let mut record = |r: &Result<Value, Value>| responses.push(format!("{r:?}"));

        // "Recover this log": wrong, then right.
        open_credential(&handle, Unlock::Recover, Show::Focus)?;
        let win = window(&app, "credential")?;
        record(&call(&win, "credential_context", json!({})).await);
        let r = call(&win, "submit_secret", json!({ "secret": WRONG_CANARY })).await;
        assert_eq!(r, Ok(json!({"failed": {"class": "wrong_passphrase"}})));
        record(&r);
        let r = call(&win, "submit_secret", json!({ "secret": PASS_CANARY })).await;
        assert_eq!(r, Ok(json!({"unlocked": {}})));
        record(&r);
        let h = handle.clone();
        eventually("the window closed", move || {
            credential::current_purpose(&h).is_none()
        })
        .await?;

        // The recovered core: confirm the config instance (stub OK), then its PAT.
        let core = state.core.get().cloned().ok_or("no core")?;
        let admin = core.instances();
        tokio::task::spawn_blocking(move || admin.confirm_config_instance("jira-main")).await??;
        let admin = core.instances();
        let views = tokio::task::spawn_blocking(move || admin.list()).await?;
        let app = app_for(&w)?;
        let handle = app.handle().clone();
        credential::open_for_pat(&handle, &views, "jira-main", false)?;
        let win = window(&app, "credential")?;
        record(&call(&win, "credential_context", json!({})).await);
        mock.json("/rest/api/2/myself", 401, r#"{"message":"no"}"#)
            .await;
        let r = call(&win, "submit_secret", json!({ "secret": PAT_CANARY })).await;
        assert_eq!(r, Ok(json!({"failed": {"class": "http_401"}})));
        assert!(
            app.get_webview_window("credential").is_some(),
            "window stays"
        );
        record(&r);
        mock.server().reset().await;
        mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
            .await;
        mock.jira_server_info("9.12.0").await;
        let r = call(
            &win,
            "submit_secret",
            json!({"secret": PAT_CANARY, "expires_on": "2027-06-30"}),
        )
        .await;
        assert_eq!(
            r.as_ref()
                .ok()
                .and_then(|o| o["ok"]["atlassian_user"].as_str()),
            Some(TEST_USER),
            "{r:?}"
        );
        record(&r);
        // Refused bodies are answered too (and recorded): still no secret in them.
        record(
            &call(
                &win,
                "submit_secret",
                json!({"secret": PAT_CANARY, "token": PAT_CANARY}),
            )
            .await,
        );
        record(
            &call(
                &win,
                "submit_secret",
                json!({"secret": format!("{PAT_CANARY}\u{0}")}),
            )
            .await,
        );

        // The first-run pair.
        credential::close(&handle);
        let app = app_for(&w)?;
        let handle = app.handle().clone();
        let mut rx = credential::request_recovery_passphrase(&handle, Show::Focus)?;
        let win = window(&app, "credential")?;
        let r = call(
            &win,
            "submit_secret",
            json!({"secret": FIRST_RUN_CANARY, "secret_confirm": FIRST_RUN_CANARY}),
        )
        .await;
        assert_eq!(r, Ok(json!({"accepted": {}})));
        record(&r);
        assert!(rx.try_recv().is_ok());
        record(&call(&win, "credential_context", json!({})).await);

        // The event half (M6 T22, m-7). A lock state following a lock state in an open window is
        // announced as `credential_context_changed`, through the app's own emit path (which the
        // test build records); and a payload that does carry a value is found in that channel, so
        // "the canaries are absent from the events" is not vacuous.
        credential::close(&handle);
        let app = app_for(&w)?;
        let handle = app.handle().clone();
        open_credential(&handle, Unlock::Unlock, Show::Focus)?;
        open_credential(&handle, Unlock::Recover, Show::Focus)?;
        EventOut::emit(&handle, "s16_control", json!({ "reason": CONTROL_CANARY }));

        // The PAT reached the server: the sweep below could have found it.
        let sent = mock
            .received()
            .await
            .iter()
            .filter(|r| {
                r.headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.contains(PAT_CANARY))
            })
            .count();
        assert!(sent >= 2, "the PAT was never sent ({sent})");

        let canaries = [PAT_CANARY, PASS_CANARY, WRONG_CANARY, FIRST_RUN_CANARY];
        assert_eq!(cap.dropped(Channel::TauriCommand), 0);
        assert_eq!(cap.dropped(Channel::TauriEvent), 0);
        let commands = cap.on(Channel::TauriCommand);
        assert!(commands.len() >= 9, "{} command records", commands.len());
        let events = cap.on(Channel::TauriEvent);
        assert!(
            events
                .iter()
                .any(|e| e.json.contains("credential_context_changed")),
            "the lock-state change was not announced: {events:?}"
        );
        assert!(
            events.iter().any(|e| e.json.contains(CONTROL_CANARY)),
            "the event channel is blind: {events:?}"
        );
        let records = cap.records();
        let logs_text = format!("{}\n{}", diag.text(), raw.text());
        for c in canaries {
            for rec in &records {
                assert!(
                    !rec.json.contains(c),
                    "capture record holds {c}: {}",
                    rec.json
                );
            }
            for resp in &responses {
                assert!(!resp.contains(c), "a response holds {c}: {resp}");
            }
            assert!(!logs_text.contains(c), "a log line holds {c}");
        }
        assert!(!responses.is_empty() && !logs_text.is_empty());

        // The capture is not blind: a line that does carry a value is found, also when it is
        // logged on another thread.
        tokio::task::spawn_blocking(|| {
            tracing::warn!(
                target: "atlas_duck_app_lib::s16_control",
                event = "s16_control",
                reason = CONTROL_CANARY
            );
        })
        .await?;
        assert!(diag.text().contains(CONTROL_CANARY));
        assert!(raw.text().contains(CONTROL_CANARY));
        stop(&state).await
    }
}
