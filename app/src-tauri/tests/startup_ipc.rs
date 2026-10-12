//! T19: startup orchestration over the lib (PD-05, PD-06, PD-41): `serve::start_with` opens the
//! store, serves `Core` or the gate handler on one endpoint, retries a keychain that is
//! unavailable and swaps the cell without rebinding. Feature-less: the keystore is
//! `audit::testing::MemKeyStore` behind an in-test `KeysFactory`; no webview, no OS keychain.
//!
//! Unix binds a socket inside the test's temp dir (`IpcServer::bind_at`), never this user's real
//! socket dir; Windows binds a fresh pipe name under this user's prefix.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atlas_duck_app_lib::secret_service::{SecretService, SecretServiceCheck};
use atlas_duck_app_lib::serve::{
    KeysFactory, ServeState, StartInputs, StartupFailure, StoreFailure, start_with,
};
use atlas_duck_audit::lock::{INSTANCE_LOCK_FILE, InstanceLock};
use atlas_duck_audit::testing::{FreeSpaceStub, MemKeyStore, MemKeyring};
use atlas_duck_audit::{
    FirstRunInput, KeyStore, KeyStoreError, OpenConfig, SystemClock, create_new_store, new_ids,
};
use atlas_duck_core::{Confirm, MSG_FIRST_RUN, NativeConfirmer, UiEvent, UiSink};
use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::client::IpcClient;
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::paths::{
    DataDirResolution, ENDPOINT_FILE, EndpointLocation, LocalDataDir, check_data_dir,
    read_endpoint_file,
};
use atlas_duck_ipc::proto::{
    AgentNameSource, ClientKind, Hello, SubmitParams, SubmitReply, exit_code,
};
use atlas_duck_ipc::server::ShutdownSignal;
use secrecy::SecretString;
use serde_json::{Value, json};

const HOST: &str = "thishost";
const WAL_FILE: &str = "audit.db-wal";
const WAIT: Duration = Duration::from_secs(20);

type TestResult = Result<(), Box<dyn std::error::Error>>;

// ---------- doubles ----------

struct NoUi;
impl UiSink for NoUi {
    fn emit(&self, _: UiEvent) {}
}

struct NoConfirm;
impl NativeConfirmer for NoConfirm {
    fn confirm(&self, _: &str) -> Confirm {
        Confirm::Cancel
    }
}

struct NoSecretService;
impl SecretServiceCheck for NoSecretService {
    fn check(&self) -> Option<SecretService> {
        None
    }
}

/// `MemKeyStore`s over one keyring. While `available` is false every `keys()` fails
/// `Unavailable`. A held factory blocks its first `keys()` (on `open`'s blocking thread) until
/// the test releases it.
struct MemKeys {
    ring: Arc<MemKeyring>,
    available: AtomicBool,
    calls: AtomicU32,
    hold: Mutex<Option<Receiver<()>>>,
    entered: AtomicBool,
}

impl MemKeys {
    fn new(ring: Arc<MemKeyring>, available: bool) -> Arc<MemKeys> {
        Arc::new(MemKeys {
            ring,
            available: AtomicBool::new(available),
            calls: AtomicU32::new(0),
            hold: Mutex::new(None),
            entered: AtomicBool::new(false),
        })
    }

    /// Available, but the first `keys()` waits for a send on the returned sender.
    fn held(ring: Arc<MemKeyring>) -> (Arc<MemKeys>, Sender<()>) {
        let (release, held) = std::sync::mpsc::channel();
        let keys = MemKeys::new(ring, true);
        *keys.hold.lock().unwrap_or_else(|e| e.into_inner()) = Some(held);
        (keys, release)
    }

    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }

    /// Waits until a `keys()` call has started.
    async fn wait_entered(&self) -> TestResult {
        let started = Instant::now();
        while !self.entered.load(Ordering::SeqCst) {
            if started.elapsed() > WAIT {
                return Err("keys() was never called".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }
}

impl KeysFactory for MemKeys {
    fn keys(&self, install_id: &str) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.store(true, Ordering::SeqCst);
        let held = self.hold.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(held) = held {
            let _ = held.recv();
        }
        if !self.available.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Unavailable);
        }
        Ok(Arc::new(MemKeyStore::new(self.ring.clone(), install_id)))
    }
}

// ---------- world ----------

struct World {
    tmp: tempfile::TempDir,
    data: LocalDataDir,
    lock: Arc<InstanceLock>,
    location: EndpointLocation,
    /// The Quit request every start in this world shares.
    quit: ShutdownSignal,
}

impl World {
    fn new() -> Result<World, Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("data");
        std::fs::create_dir(&dir)?;
        let data = match check_data_dir(&dir)? {
            DataDirResolution::Local(d) => d,
            _ => return Err("the temp dir is not a local data dir".into()),
        };
        let lock = Arc::new(InstanceLock::acquire(&data, HOST)?);
        let location = location(&tmp, &data)?;
        Ok(World {
            tmp,
            data,
            lock,
            location,
            quit: ShutdownSignal::new(),
        })
    }

    fn inputs(&self, install_id: Option<String>, keys: Arc<dyn KeysFactory>) -> StartInputs {
        StartInputs {
            data: self.data.clone(),
            lock: self.lock.clone(),
            host: HOST.to_owned(),
            install_id,
            config_dir: self.tmp.path().join("config"),
            keys,
            ui: Arc::new(NoUi),
            confirmer: Arc::new(NoConfirm),
            tray_host: None,
            secret_service: Arc::new(NoSecretService),
            retry_schedule: vec![Duration::from_millis(50); 200],
            endpoint: Some(self.location.clone()),
            quit: self.quit.clone(),
        }
    }

    /// File names in the data dir.
    fn files(&self) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
        let mut out = BTreeSet::new();
        for e in std::fs::read_dir(self.data.path())? {
            out.insert(e?.file_name().to_string_lossy().into_owned());
        }
        Ok(out)
    }

    /// A store created by the wizard path (GENESIS) with `MemKeyStore`s over `ring`.
    fn provision(&self, ring: &Arc<MemKeyring>) -> Result<String, Box<dyn std::error::Error>> {
        let (install_id, chain_id) = new_ids()?;
        let keys: Arc<dyn KeyStore> = Arc::new(MemKeyStore::new(ring.clone(), &install_id));
        let mut cfg = OpenConfig::new(Arc::new(SystemClock::new()), keys);
        cfg.free_space = Some(FreeSpaceStub::new(u64::MAX));
        let pass = "correct horse battery";
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

    async fn connect(&self) -> Result<IpcClient, Box<dyn std::error::Error>> {
        let hello = Hello {
            build_id: BUILD_ID.to_owned(),
            client_kind: ClientKind::Cli,
            agent_name: Some("t19".into()),
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

/// Nothing was bound: no endpoint file and (Unix) no socket.
fn assert_nothing_bound(w: &World) -> TestResult {
    assert!(read_endpoint_file(&w.data)?.is_none(), "no endpoint file");
    #[cfg(unix)]
    if let EndpointLocation::UnixSocket(p) = &w.location {
        assert!(!p.exists(), "no socket bound");
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

// ---------- tests ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_run_serves_gate_over_endpoint() -> TestResult {
    let w = World::new()?;
    let keys = MemKeys::new(MemKeyring::new(), true);
    let state = start_with(w.inputs(None, keys.clone()))
        .await
        .map_err(|e| format!("{e:?}"))?;
    // PD-41: no keystore is built before first run.
    assert_eq!(keys.calls(), 0);
    assert!(state.serving());
    assert!(
        read_endpoint_file(&w.data)?.is_some(),
        "endpoint file written"
    );

    let mut c = w.connect().await?;
    let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
    let env = reply.envelope;
    assert_eq!(env.status, Status::Failed);
    assert_eq!(
        env.error.as_ref().map(|e| e.code),
        Some(ErrorCode::NotConfigured)
    );
    assert_eq!(reason(&env), Some("first_run"));
    assert_eq!(
        env.error.as_ref().map(|e| e.message.as_str()),
        Some(MSG_FIRST_RUN)
    );
    assert_eq!(exit_code(&env), 9);
    assert_eq!(state.refused(), Some(1));

    let doctor: Envelope = c.call("doctor", json!({})).await?;
    assert_eq!(doctor.status, Status::Succeeded);
    let data = doctor.data.unwrap_or_default();
    assert_eq!(data["gate"], "first_run");
    for key in ["tray_host", "secret_service", "ipc_accepting"] {
        assert!(data.get(key).is_some(), "doctor lacks {key}: {data}");
    }
    assert_eq!(data["ipc_accepting"], true);

    let ops: Envelope = c.call("ops.list", json!({})).await?;
    assert_eq!(ops.status, Status::Succeeded);

    stop(&state).await?;
    assert!(
        read_endpoint_file(&w.data)?.is_none(),
        "serve removed the endpoint file"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ready_store_serves_core() -> TestResult {
    let w = World::new()?;
    let ring = MemKeyring::new();
    let install_id = w.provision(&ring)?;
    let keys = MemKeys::new(ring, true);
    let state = start_with(w.inputs(Some(install_id), keys))
        .await
        .map_err(|e| format!("{e:?}"))?;
    assert!(state.core.get().is_some());
    assert_eq!(state.refused(), None);
    assert!(state.store.lock().map_err(|_| "poisoned")?.is_some());

    let mut c = w.connect().await?;
    let instances: Envelope = c.call("instances.list", json!({})).await?;
    assert_eq!(instances.status, Status::Succeeded, "{instances:?}");
    let doctor: Envelope = c.call("doctor", json!({})).await?;
    let data = doctor.data.unwrap_or_default();
    assert!(data.get("instances").is_some(), "{data}");
    assert!(data.get("tray_host").is_some() && data.get("secret_service").is_some());
    // An open store keeps its WAL file; `quit_during_open_binds_nothing` relies on this.
    let files = w.files()?;
    assert!(files.contains(WAL_FILE), "{files:?}");

    // The quit path's freeze hands out the core set at start; with a core the cell stays.
    let core = state.core.get().cloned().ok_or("no core")?;
    let frozen = state.freeze().ok_or("freeze returned no core")?;
    assert!(Arc::ptr_eq(&frozen, &core));
    let again = state.freeze_for_shutdown().ok_or("no core")?;
    assert!(Arc::ptr_eq(&again, &core));
    assert_eq!(state.refused(), None);
    let doctor: Envelope = c.call("doctor", json!({})).await?;
    assert!(doctor.data.unwrap_or_default().get("instances").is_some());

    stop(&state).await
}

/// PD-41: without a pinned install id the store's own id (read-only) builds the keystore.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ready_store_without_pinned_id_uses_the_store_id() -> TestResult {
    let w = World::new()?;
    let ring = MemKeyring::new();
    w.provision(&ring)?;
    let keys = MemKeys::new(ring, true);
    let state = start_with(w.inputs(None, keys.clone()))
        .await
        .map_err(|e| format!("{e:?}"))?;
    assert!(state.core.get().is_some());
    assert_eq!(keys.calls(), 1);
    stop(&state).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn locked_retry_swaps_to_core() -> TestResult {
    let w = World::new()?;
    let ring = MemKeyring::new();
    let install_id = w.provision(&ring)?;
    let keys = MemKeys::new(ring, false);
    let state = start_with(w.inputs(Some(install_id), keys.clone()))
        .await
        .map_err(|e| format!("{e:?}"))?;
    assert!(state.core.get().is_none());
    let endpoint_before = read_endpoint_file(&w.data)?;
    assert!(endpoint_before.is_some());

    let mut c = w.connect().await?;
    let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
    assert_eq!(
        reply.envelope.error.as_ref().map(|e| e.code),
        Some(ErrorCode::Locked)
    );
    assert_eq!(reason(&reply.envelope), Some("keychain_unavailable"));
    assert_eq!(exit_code(&reply.envelope), 9);

    // The initial attempt and at least one retry failed before the keychain comes back.
    let started = Instant::now();
    while keys.calls() < 2 {
        assert!(started.elapsed() < WAIT, "no retry ran");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    keys.available.store(true, Ordering::SeqCst);
    while state.core.get().is_none() {
        assert!(started.elapsed() < WAIT, "the retry never reached Core");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(keys.calls() >= 3);
    assert_eq!(state.refused(), None, "the gate is gone");

    // The same connection, now answered by Core (its hello replayed by the server).
    let instances: Envelope = c.call("instances.list", json!({})).await?;
    assert_eq!(instances.status, Status::Succeeded, "{instances:?}");
    let doctor: Envelope = c.call("doctor", json!({})).await?;
    assert!(doctor.data.unwrap_or_default().get("instances").is_some());
    // No rebind.
    assert_eq!(read_endpoint_file(&w.data)?, endpoint_before);

    stop(&state).await
}

/// A retry that finds another locked reason swaps to that gate and stops retrying.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn locked_retry_swaps_to_another_gate_state() -> TestResult {
    let w = World::new()?;
    let ring = MemKeyring::new();
    let install_id = w.provision(&ring)?;
    let keys = MemKeys::new(ring.clone(), false);
    let state = start_with(w.inputs(Some(install_id.clone()), keys.clone()))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let mut c = w.connect().await?;
    // The keychain comes back without this install's KEK: `keychain_lost`.
    ring.wipe_install(&install_id);
    keys.available.store(true, Ordering::SeqCst);
    let started = Instant::now();
    loop {
        let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
        if reason(&reply.envelope) == Some("keychain_lost") {
            break;
        }
        assert_eq!(reason(&reply.envelope), Some("keychain_unavailable"));
        assert!(started.elapsed() < WAIT, "never swapped to keychain_lost");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let calls = keys.calls();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(keys.calls(), calls, "the retry loop stopped");
    assert!(state.core.get().is_none());
    stop(&state).await
}

/// After `freeze` the retry loop swaps nothing: a keychain that comes back starts no `Core`, the
/// locked gate stays in the cell, and the loop ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn freeze_stops_the_retry_loop() -> TestResult {
    let w = World::new()?;
    let ring = MemKeyring::new();
    let install_id = w.provision(&ring)?;
    let keys = MemKeys::new(ring, false);
    let state = start_with(w.inputs(Some(install_id), keys.clone()))
        .await
        .map_err(|e| format!("{e:?}"))?;
    assert!(state.freeze().is_none());
    keys.available.store(true, Ordering::SeqCst);
    // Several schedule steps (50 ms each).
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(state.core.get().is_none());
    assert_eq!(
        state.refused(),
        Some(0),
        "the locked gate stays in the cell"
    );
    let retry = state.retry.lock().map_err(|_| "poisoned")?.take();
    let retry = retry.ok_or("no retry loop")?;
    tokio::time::timeout(WAIT, retry).await??;
    assert!(state.core.get().is_none());
    let mut c = w.connect().await?;
    let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
    assert_eq!(reason(&reply.envelope), Some("keychain_unavailable"));
    stop(&state).await
}

/// With a gate serving, `freeze_for_shutdown` swaps the cell to the `ShuttingDown` gate (a fresh
/// refused counter) and returns no core.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn freeze_for_shutdown_swaps_a_gate_to_shutting_down() -> TestResult {
    let w = World::new()?;
    let keys = MemKeys::new(MemKeyring::new(), true);
    let state = start_with(w.inputs(None, keys))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let mut c = w.connect().await?;
    let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
    assert_eq!(reason(&reply.envelope), Some("first_run"));
    assert_eq!(state.refused(), Some(1));

    assert!(state.freeze_for_shutdown().is_none());
    assert_eq!(state.refused(), Some(0));
    let reply: SubmitReply = c.call("request.submit", submit_params()).await?;
    assert_eq!(reason(&reply.envelope), Some("app_shutting_down"));
    assert_eq!(state.refused(), Some(1));
    stop(&state).await
}

/// I-2: Quit while `open` runs. The opened store is shut down, nothing is bound and the start
/// ends `Cancelled`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quit_during_open_binds_nothing() -> TestResult {
    let w = World::new()?;
    let ring = MemKeyring::new();
    let install_id = w.provision(&ring)?;
    let before = w.files()?;
    assert!(!before.contains(WAL_FILE), "{before:?}");
    let (keys, release) = MemKeys::held(ring);
    let start = tokio::spawn(start_with(w.inputs(Some(install_id), keys.clone())));
    keys.wait_entered().await?;
    w.quit.cancel();
    release.send(())?;
    let got = tokio::time::timeout(WAIT, start).await??;
    assert!(
        matches!(got, Err(StartupFailure::Cancelled)),
        "{:?}",
        got.as_ref().err()
    );
    assert_nothing_bound(&w)?;
    // The store was opened (`Ready`) and shut down before any read: closing its writer, the
    // last connection, removed the WAL file again.
    assert_eq!(w.files()?, before);
    Ok(())
}

/// I-2: Quit before the bind of a gate state: nothing is bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quit_before_bind_binds_nothing() -> TestResult {
    let w = World::new()?;
    let before = w.files()?;
    let keys = MemKeys::new(MemKeyring::new(), true);
    w.quit.cancel();
    let got = start_with(w.inputs(None, keys.clone())).await;
    assert!(
        matches!(got, Err(StartupFailure::Cancelled)),
        "{:?}",
        got.as_ref().err()
    );
    assert_eq!(keys.calls(), 0);
    assert_nothing_bound(&w)?;
    assert_eq!(w.files()?, before);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_error_binds_nothing() -> TestResult {
    for pinned in [None, Some("0123456789abcdef0123456789abcdef".to_owned())] {
        let w = World::new()?;
        std::fs::write(w.data.path().join(WAL_FILE), b"x")?;
        let before = w.files()?;
        let keys = MemKeys::new(MemKeyring::new(), true);
        let got = start_with(w.inputs(pinned.clone(), keys.clone())).await;
        assert!(
            matches!(got, Err(StartupFailure::Store(StoreFailure::Integrity))),
            "{pinned:?}: {:?}",
            got.as_ref().err()
        );
        // PD-41: no keystore is built without `audit.db`, even with a pinned id.
        assert_eq!(keys.calls(), 0, "{pinned:?}");
        // Nothing written: only `instance.lock` (taken by the gate) and the planted WAL.
        assert_eq!(w.files()?, before);
        assert_eq!(
            before,
            BTreeSet::from([INSTANCE_LOCK_FILE.to_owned(), WAL_FILE.to_owned()])
        );
        assert_nothing_bound(&w)?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_endpoint_file_removed_before_bind() -> TestResult {
    // A store failure: the stale file is gone although nothing was bound, so no CLI is sent to
    // a dead endpoint.
    let w = World::new()?;
    std::fs::write(w.data.path().join(ENDPOINT_FILE), b"stale-endpoint-name")?;
    std::fs::write(w.data.path().join(WAL_FILE), b"x")?;
    let keys = MemKeys::new(MemKeyring::new(), true);
    assert!(start_with(w.inputs(None, keys)).await.is_err());
    assert!(!w.data.path().join(ENDPOINT_FILE).exists());

    // A successful start replaces it with the bound name.
    let w = World::new()?;
    std::fs::write(w.data.path().join(ENDPOINT_FILE), b"stale-endpoint-name")?;
    let keys = MemKeys::new(MemKeyring::new(), true);
    let state = start_with(w.inputs(None, keys))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let name = read_endpoint_file(&w.data)?.ok_or("no endpoint file")?;
    assert_ne!(name, "stale-endpoint-name");
    w.connect().await?;
    stop(&state).await
}
