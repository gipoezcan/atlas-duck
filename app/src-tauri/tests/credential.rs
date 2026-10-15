//! M6 T20 (§10.3, §7.1, §8.6, §8.7; I-33, U-18, S-16 Tauri half): the credential window's Rust
//! side over Tauri's mock runtime (no OS window, no webview) and the app's own serving state.
//!
//! Three rigs: the generated context with the shipped capability files (the ACL is the real one,
//! as in `commands_acl.rs`); `serve::start_with` over a temp data dir with `MemKeyStore`s (as in
//! `startup_ipc.rs`: a wiped keyring leaves the store `keychain_lost`); and `core::testing::Harness`
//! with `MockDc` for the connection test (`scripted-approver`). No OS keychain, no spawned binary.

type TestResult = Result<(), Box<dyn std::error::Error>>;

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atlas_duck_app_lib::commands;
use atlas_duck_app_lib::credential::{self, PatOpenError, Purpose};
use atlas_duck_app_lib::secret_service::{SecretService, SecretServiceCheck};
use atlas_duck_app_lib::serve::{
    KeysFactory, ServeState, StartInputs, UnlockFailure, UnlockKind, start_with, unlock,
};
use atlas_duck_app_lib::state::{DataDirHold, ServeSlot};
use atlas_duck_app_lib::windows::{
    NavPolicy, Show, StartupRoute, Unlock, WindowError, WindowRegistry, open_credential,
};
use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::testing::{FreeSpaceStub, MemKeyStore, MemKeyring};
use atlas_duck_audit::{
    FirstRunInput, KeyStore, KeyStoreError, OpenConfig, SystemClock, create_new_store, new_ids,
};
use atlas_duck_core::{AdminError, Confirm, InstanceView, NativeConfirmer, UiEvent, UiSink};
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

/// `MemKeyStore`s over one keyring; every `keys()` fails `Unavailable` while `available` is off.
struct MemKeys {
    ring: Arc<MemKeyring>,
    available: AtomicBool,
    calls: std::sync::atomic::AtomicU32,
}

impl MemKeys {
    fn new(ring: Arc<MemKeyring>, available: bool) -> Arc<MemKeys> {
        Arc::new(MemKeys {
            ring,
            available: AtomicBool::new(available),
            calls: std::sync::atomic::AtomicU32::new(0),
        })
    }
}

impl KeysFactory for MemKeys {
    fn keys(&self, install_id: &str) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.available.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Unavailable);
        }
        Ok(Arc::new(MemKeyStore::new(self.ring.clone(), install_id)))
    }
}

struct World {
    tmp: tempfile::TempDir,
    data: LocalDataDir,
    lock: Arc<InstanceLock>,
    location: EndpointLocation,
}

impl World {
    fn new() -> Result<World, Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("data");
        std::fs::create_dir(&dir)?;
        let data = local_data_dir(&dir)?;
        let lock = Arc::new(InstanceLock::acquire(&data, HOST)?);
        std::fs::create_dir(tmp.path().join("config"))?;
        let location = location(&tmp, &data)?;
        Ok(World {
            tmp,
            data,
            lock,
            location,
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
        let ring = MemKeyring::new();
        let install_id = self.provision(&ring, pass)?;
        ring.wipe_install(&install_id);
        let keys = MemKeys::new(ring, true);
        let state = start_with(self.inputs(Some(install_id), keys, confirmer, vec![]))
            .await
            .map_err(|e| format!("{e:?}"))?;
        assert!(state.core.get().is_none());
        Ok(state)
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

#[cfg(unix)]
fn location(
    tmp: &tempfile::TempDir,
    _data: &LocalDataDir,
) -> Result<EndpointLocation, Box<dyn std::error::Error>> {
    let dir = tmp.path().join("s");
    atlas_duck_ipc::paths::ensure_socket_dir(&dir)?;
    Ok(EndpointLocation::UnixSocket(dir.join("atlas-duck.sock")))
}

#[cfg(windows)]
fn location(
    _tmp: &tempfile::TempDir,
    data: &LocalDataDir,
) -> Result<EndpointLocation, Box<dyn std::error::Error>> {
    Ok(atlas_duck_ipc::paths::endpoint_location(data, HOST)?)
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
    let app = app()?;
    let tmp = tempfile::tempdir()?;
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
    let app = app()?;
    let tmp = tempfile::tempdir()?;
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
    assert_eq!(
        credential::current_purpose(handle),
        Some(Purpose::RecoverThisLog)
    );
    assert_eq!(app.webview_windows().len(), 1);
    Ok(())
}

/// §7.1, §10.3: the window cannot be opened for an `http://` instance or one whose origin is not
/// natively confirmed; nothing is built.
#[test]
fn credential_refused_for_unconfirmed_or_insecure_instance() -> TestResult {
    let app = app()?;
    let tmp = tempfile::tempdir()?;
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
    let app = app()?;
    let tmp = tempfile::tempdir()?;
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

/// §8.6: the recovery note (offered once the new store serves) names the install and the data
/// dir and never the passphrase, whatever passphrase went through the window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_note_has_no_passphrase() -> TestResult {
    let canary = "canary-note-passphrase-5d1e";
    let w = World::new()?;
    let ring = MemKeyring::new();
    let install_id = w.provision(&ring, canary)?;
    let keys = MemKeys::new(ring, true);
    let state = start_with(w.inputs(Some(install_id.clone()), keys, Answers::new(vec![]), vec![]))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let app = w.app(&state)?;
    let handle = app.handle().clone();
    let mut rx = credential::request_recovery_passphrase(&handle, Show::Focus)?;
    let win = window(&app, "credential")?;
    let note_available = |c: &Result<Value, Value>| {
        c.as_ref()
            .ok()
            .and_then(|c| c.get("note_available").cloned())
    };
    let before = call(&win, "credential_context", json!({})).await;
    assert_eq!(note_available(&before), Some(json!(false)));
    assert_eq!(
        call(
            &win,
            "submit_secret",
            json!({"secret": canary, "secret_confirm": canary})
        )
        .await,
        Ok(json!({"accepted": {}}))
    );
    assert!(rx.try_recv().is_ok());
    let after = call(&win, "credential_context", json!({})).await;
    assert_eq!(note_available(&after), Some(json!(true)));

    let (id, chain_id, data) = state.note_facts().ok_or("no store facts")?;
    assert_eq!(id, install_id);
    let text = credential::note_text(&credential::NoteFacts {
        host: HOST.into(),
        os_user: credential::os_user(),
        install_id: id.clone(),
        chain_id: chain_id.clone(),
        data_dir: data.display().to_string(),
    });
    assert!(!text.contains(canary), "{text}");
    for want in [
        id.as_str(),
        chain_id.as_str(),
        &data.display().to_string(),
        credential::PASSPHRASE_PURPOSE,
    ] {
        assert!(text.contains(want), "{want}");
    }
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
async fn retry_keychain_runs_one_more_open() -> TestResult {
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
