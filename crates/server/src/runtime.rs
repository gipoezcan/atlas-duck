//! Per-user runtimes and their registry (PD-209, SM-6.1).
//!
//! A `UserRuntime` is one `atlas_duck_core::Core` over the user's own M2 store in
//! `<data>/users/<user_id>/`: the store's keys in the server store under the user's data key
//! (`ServerKeyStore`), the PATs likewise (`ServerCredentials`), no native dialogs
//! (`RefusingConfirmer`, PD-197), UI events to the user's SSE channel (`SseUiSink`), and the admin
//! instances as the user's `config.toml`. Opening a runtime creates the user's store when it does
//! not exist yet, so creation is retried on every open (every login) until it succeeds.
//!
//! The `Registry` hands runtimes out only for a `UserCtx`, which only the session and API-key
//! extractors construct; no handler takes a user id from a path or body.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::{
    Actor, Confirmed, EventFlags, EventType, FirstRunInput, NewEvent, OpenConfig, SettingChange,
    StartupOutcome, Store, SystemClock,
};
use atlas_duck_core::audit_port::DateBridge;
use atlas_duck_core::config::load_config;
use atlas_duck_core::decision::DecisionApi;
use atlas_duck_core::http_factory::HttpFactory;
use atlas_duck_core::proxy::SystemProxySource;
use atlas_duck_core::{Confirm, Core, CoreDeps, NativeConfirmer, ShutdownReason, UiEvent, UiSink};
use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};
use atlas_duck_ipc::proto::RequestHandler;
use secrecy::SecretString;
use serde_json::{Map, Value};
use tokio::sync::broadcast;

use crate::clock::Clock;
use crate::credentials::server_credentials;
use crate::errors::ApiError;
use crate::instances::{config_toml, instance_id_for};
use crate::keystore::ServerKeyStore;
use crate::master_key::{DataKey, MasterKey, WrappedKey};
use crate::store::ServerStore;
use crate::users::user_dir;

/// PD-206: per-user broadcast capacity.
pub const SSE_CAPACITY: usize = 256;
/// The lock holder name of user stores.
const LOCK_HOST: &str = "atlas-duck-server";
const CONFIG_FILE: &str = "config.toml";

/// (chain_id, seq, record_hash) of a user chain's head.
pub type Head = (String, u64, [u8; 32]);
/// A user id with its chain head.
pub type UserHead = (String, Head);

/// One UI event for the user's SSE streams.
#[derive(Debug, Clone, PartialEq)]
pub struct SseEvent {
    pub name: &'static str,
    pub data: Value,
}

/// PD-197: server mode has no native dialogs; every confirmation is refused.
pub struct RefusingConfirmer;

impl NativeConfirmer for RefusingConfirmer {
    fn confirm(&self, _text: &str) -> Confirm {
        Confirm::Cancel
    }
}

/// `UiSink` → the user's broadcast channel, with the desktop's event table.
pub struct SseUiSink {
    tx: broadcast::Sender<SseEvent>,
}

impl UiSink for SseUiSink {
    fn emit(&self, e: UiEvent) {
        let (name, data) = atlas_duck_core::decision::wire::ui_event_json(&e);
        // No receiver (no open stream) is fine.
        let _ = self.tx.send(SseEvent { name, data });
    }
}

/// Who a request acts for. Constructible only inside this crate's extractors (session, API key):
/// the private field keeps any other code from naming a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserCtx {
    user_id: String,
}

impl UserCtx {
    pub(crate) fn from_authenticated(user_id: &str) -> UserCtx {
        UserCtx {
            user_id: user_id.to_owned(),
        }
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }
}

/// What every runtime is built from.
pub struct RuntimeDeps {
    pub data_dir: PathBuf,
    pub store: Arc<dyn ServerStore>,
    pub master: Arc<MasterKey>,
    /// `ATLAS_DUCK_CA_BUNDLE_FILE`: the bundle of instances with `ca_ref = "org"`.
    pub org_ca: Option<PathBuf>,
    pub clock: Arc<dyn Clock>,
    /// Tests: accept `http://` instances (the atlassian mocks). Never set in production.
    pub allow_http: bool,
    /// Per-user SSE broadcast capacity ([`SSE_CAPACITY`]; tests use a small one).
    pub sse_capacity: usize,
    /// M14 PD-246: the process-wide script state; `None` (`ATLAS_DUCK_SCRIPTS=disabled`) answers
    /// every script `sandbox_unavailable`.
    pub scripts: Option<Arc<crate::scripts::ServerScripts>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    UnknownUser,
    /// The wrapped data key does not open (PD-208: `data_key_unwrap_failed`).
    DataKey,
    Store(String),
    Core(String),
}

impl RuntimeError {
    pub fn api(&self) -> ApiError {
        match self {
            RuntimeError::UnknownUser => ApiError::NO_SESSION,
            _ => ApiError::STORE_UNAVAILABLE,
        }
    }
}

fn data_key(deps: &RuntimeDeps, user_id: &str) -> Result<DataKey, RuntimeError> {
    let user = deps
        .store
        .user(user_id)
        .map_err(|e| RuntimeError::Store(e.to_string()))?
        .ok_or(RuntimeError::UnknownUser)?;
    let wrapped =
        WrappedKey::from_json(&user.data_key_wrapped).map_err(|_| RuntimeError::DataKey)?;
    deps.master.unwrap(user_id, &wrapped).map_err(|_| {
        tracing::error!(event = "data_key_unwrap_failed", user_id);
        RuntimeError::DataKey
    })
}

/// A random recovery passphrase that nobody keeps: in server mode the user store's KEK is
/// recovered through the master key (ADR 0002), never through a passphrase.
fn throwaway_passphrase() -> Result<SecretString, RuntimeError> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| RuntimeError::Store("no system randomness".into()))?;
    Ok(SecretString::from(hex::encode(b)))
}

/// Confirms every admin instance's origin (and the org CA) in the user's settings; an unchanged
/// setting is no change.
fn apply_instance_settings(store: &Store, deps: &RuntimeDeps) -> Result<(), RuntimeError> {
    let confirmed = Confirmed {
        dialog_text_sha256: sha2::Digest::finalize(sha2::Digest::chain_update(
            <sha2::Sha256 as sha2::Digest>::new(),
            b"atlas-duck server: admin-defined instance",
        ))
        .into(),
    };
    let list = deps
        .store
        .instance_list()
        .map_err(|e| RuntimeError::Store(e.to_string()))?;
    let org_fp = deps
        .org_ca
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|pem| atlas_duck_core::instances::state::ca_fingerprint(&pem));
    for i in &list {
        let Ok(origin) = atlas_duck_atlassian::normalize_base_url(&i.base_url) else {
            continue;
        };
        let id = instance_id_for(&i.alias);
        let mut changes = vec![(
            SettingChange::InstanceOrigin {
                instance_id: id.clone(),
                origin: Some(origin.as_str()),
            },
            Some(confirmed),
        )];
        if i.ca_ref.as_deref() == Some(crate::instances::CA_REF_ORG)
            && let Some(fp) = &org_fp
        {
            changes.push((
                SettingChange::InstanceCaFingerprint {
                    instance_id: id.clone(),
                    fingerprint: Some(fp.clone()),
                },
                Some(confirmed),
            ));
        }
        for (change, confirm) in changes {
            match store.apply_setting(change, confirm) {
                Ok(_) => {}
                Err(atlas_duck_audit::AuditError::Invalid(m))
                    if m == atlas_duck_audit::SETTING_UNCHANGED => {}
                Err(e) => return Err(RuntimeError::Store(e.to_string())),
            }
        }
    }
    Ok(())
}

pub struct UserRuntime {
    user_id: String,
    core: Core,
    store: Store,
    events: broadcast::Sender<SseEvent>,
    config_path: PathBuf,
    sse_streams: AtomicUsize,
    /// Tests: the next server-record append fails as if the store were unavailable.
    #[cfg(any(test, feature = "testing"))]
    pub fail_next_append: std::sync::atomic::AtomicBool,
    mcp_calls: AtomicUsize,
    last_used: AtomicU64,
    script_instances: atlas_duck_script_glue::InstanceSource,
    _lock: InstanceLock,
}

/// A user's store opened without a core (M14 PD-257: an auditor's read of a user whose runtime
/// is closed), held under the user's instance lock; a runtime that opens later adopts both.
pub struct StoreOnly {
    pub lock: InstanceLock,
    pub store: Store,
}

impl UserRuntime {
    /// The user's store under its instance lock. `create`: create it when it does not exist yet
    /// (a login); otherwise a missing store is `UnknownUser` (an auditor never creates one).
    pub fn open_store(
        user_id: &str,
        deps: &RuntimeDeps,
        create: bool,
    ) -> Result<StoreOnly, RuntimeError> {
        let st = |e: String| RuntimeError::Store(e);
        let dir = user_dir(&deps.data_dir, user_id);
        let exists = dir
            .join(atlas_duck_audit::DB_FILE)
            .try_exists()
            .unwrap_or(false);
        if !exists && !create {
            return Err(RuntimeError::UnknownUser);
        }
        std::fs::create_dir_all(&dir).map_err(|e| st(e.to_string()))?;
        let data = match check_data_dir(&dir) {
            Ok(DataDirResolution::Local(d)) => d,
            _ => return Err(st("user dir is not a local directory".into())),
        };
        let lock = InstanceLock::acquire(&data, LOCK_HOST).map_err(|e| st(format!("{e:?}")))?;
        let keys = Arc::new(ServerKeyStore::new(
            deps.store.clone(),
            user_id,
            data_key(deps, user_id)?,
        ));
        let open_cfg = || {
            let mut c = OpenConfig::new(Arc::new(SystemClock::new()), keys.clone());
            c.pinned_install_id = Some(user_id.to_owned());
            c
        };
        let store = if exists {
            match atlas_duck_audit::open(&data, &lock, open_cfg()) {
                Ok(StartupOutcome::Ready { store, .. }) => store,
                Ok(_) => return Err(st("user store is not ready".into())),
                Err(e) => return Err(st(e.to_string())),
            }
        } else {
            let (_, chain_id) = atlas_duck_audit::new_ids().map_err(|e| st(e.to_string()))?;
            let pass = throwaway_passphrase()?;
            let input = FirstRunInput {
                install_id: user_id.to_owned(),
                chain_id,
                passphrase: pass.clone(),
                passphrase_confirm: pass,
                archived_db: None,
                anchor_dir: None,
                archive_confirmed: None,
            };
            atlas_duck_audit::create_new_store(&data, &lock, open_cfg(), input)
                .map_err(|e| st(e.to_string()))?
        };
        Ok(StoreOnly { lock, store })
    }

    /// Opens (creating on first use) the user's store and starts its core.
    pub async fn open(user_id: &str, deps: &RuntimeDeps) -> Result<UserRuntime, RuntimeError> {
        let opened = Self::open_store(user_id, deps, true)?;
        Self::open_with(user_id, deps, opened).await
    }

    /// Starts the core over a store already open (fresh, or adopted from an audit view).
    pub async fn open_with(
        user_id: &str,
        deps: &RuntimeDeps,
        opened: StoreOnly,
    ) -> Result<UserRuntime, RuntimeError> {
        let st = |e: String| RuntimeError::Store(e);
        let StoreOnly { lock, store } = opened;
        let dir = user_dir(&deps.data_dir, user_id);
        apply_instance_settings(&store, deps)?;
        let config_path = dir.join(CONFIG_FILE);
        write_config(&config_path, deps)?;
        let config = load_config(&config_path).map_err(|e| st(e.to_string()))?;
        let credentials = server_credentials(
            deps.store.clone(),
            user_id,
            data_key(deps, user_id)?,
            deps.clock.clone(),
        );
        let http = HttpFactory::new(
            Arc::new(SystemProxySource::new()),
            credentials.clone(),
            Arc::new(DateBridge(Arc::new(store.clone()))),
        );
        let (events, _) = broadcast::channel(deps.sse_capacity.max(1));
        let mut extra = Map::new();
        extra.insert("mode".into(), Value::from("server"));
        // M14: this core's glue reads this core's instances once it runs ([`Registry`] binds).
        let script_instances = atlas_duck_script_glue::InstanceSource::default();
        let scripts = deps
            .scripts
            .as_ref()
            .map(|s| s.runner(script_instances.clone()));
        let core_deps = CoreDeps {
            audit: store.clone(),
            clock: Arc::new(SystemClock::new()),
            credentials,
            confirmer: Arc::new(RefusingConfirmer),
            ui: Arc::new(SseUiSink { tx: events.clone() }),
            config,
            config_path: Some(config_path.clone()),
            http,
            app_start_extra: extra,
            pats_deleted: Vec::new(),
            scripts,
        };
        let core = start_core(core_deps, &store, deps.allow_http)
            .await
            .map_err(RuntimeError::Core)?;
        Ok(UserRuntime {
            user_id: user_id.to_owned(),
            core,
            store,
            events,
            config_path,
            sse_streams: AtomicUsize::new(0),
            #[cfg(any(test, feature = "testing"))]
            fail_next_append: std::sync::atomic::AtomicBool::new(false),
            mcp_calls: AtomicUsize::new(0),
            last_used: AtomicU64::new(0),
            script_instances,
            _lock: lock,
        })
    }

    /// Lets this core's script glue read its instances (`atlas.instances()`); a weak reference,
    /// as the glue is the core's own.
    fn bind_script_instances(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        self.script_instances.set(move || {
            weak.upgrade()
                .map(|rt| rt.core.script_instances())
                .unwrap_or_default()
        });
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// What the MCP endpoint drives (PD-194).
    pub fn handler(&self) -> Arc<dyn RequestHandler> {
        self.core.handler()
    }

    /// The instance admin of the user's core (PAT entry, T17: the base-spec credential check).
    pub fn instances(&self) -> Arc<dyn atlas_duck_core::InstanceAdmin> {
        self.core.instances()
    }

    /// The approvals commands' API.
    pub fn decisions(&self) -> Arc<dyn DecisionApi> {
        self.core.decisions()
    }

    /// A receiver of the user's UI events (callers hold an [`SsePin`] while they stream).
    pub fn events(&self) -> broadcast::Receiver<SseEvent> {
        self.events.subscribe()
    }

    /// Appends a server-mode record (`LOGIN`, `API_KEY_*`) to the user's chain.
    pub async fn append_server_record(
        &self,
        kind: EventType,
        payload: Map<String, Value>,
    ) -> Result<(), ApiError> {
        #[cfg(any(test, feature = "testing"))]
        if self.fail_next_append.swap(false, Ordering::SeqCst) {
            return Err(ApiError::STORE_UNAVAILABLE);
        }
        let store = self.store.clone();
        let ev = NewEvent {
            event_type: kind,
            request_id: None,
            op_id: None,
            op_class: None,
            instance_id: None,
            target: None,
            actor: Actor::default(),
            decision: None,
            flags: EventFlags::default(),
            payload: Value::Object(payload),
        };
        tokio::task::spawn_blocking(move || store.append(ev))
            .await
            .map_err(|_| ApiError::INTERNAL)?
            .map(drop)
            .map_err(|_| ApiError::STORE_UNAVAILABLE)
    }

    /// `(chain_id, seq, record_hash)` of the user's chain head (the anchor writer's input).
    pub fn head(&self) -> (String, u64, [u8; 32]) {
        let (seq, hash, chain) = self.store.head();
        (chain, seq, hash)
    }

    /// M14 T16: a handle of the user's own audit store for the read-only audit commands.
    pub fn audit_handle(&self) -> Store {
        self.store.clone()
    }

    /// M13 T6 (restore): a full verification of the user's chain, which appends its `VERIFY`
    /// record; `true` when it completed without an incident.
    pub async fn full_verify(&self) -> bool {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || store.try_full_verify())
            .await
            .ok()
            .and_then(Result::ok)
            .is_some_and(|o| !o.findings.iter().any(|f| f.kind.is_incident()))
    }

    /// The user's audit store (integration tests read and verify the chain).
    #[cfg(any(test, feature = "testing"))]
    pub fn audit_store(&self) -> &Store {
        &self.store
    }

    /// PD-196: the admin instances changed; rewrite the config and let core reload it.
    pub async fn instances_changed(&self, deps: &RuntimeDeps) -> Result<(), RuntimeError> {
        apply_instance_settings(&self.store, deps)?;
        write_config(&self.config_path, deps)?;
        self.core.reload_instances().await;
        Ok(())
    }

    /// The core's normal shutdown (`APP_STOP`), then the store.
    pub async fn close(&self) {
        let _ = self.core.shutdown(ShutdownReason::Quit).await;
        let store = self.store.clone();
        let _ = tokio::task::spawn_blocking(move || store.shutdown()).await;
    }

    /// PD-209: may the registry close this runtime now?
    pub fn evictable(&self) -> bool {
        self.sse_streams.load(Ordering::SeqCst) == 0
            && self.mcp_calls.load(Ordering::SeqCst) == 0
            && self.decisions().queue_list().is_empty()
            // M14 PD-249 (Δ-M14-3): a running script pins its runtime (closing would kill it).
            && self.core.running_scripts().is_empty()
    }

    /// An SSE pin unless the user already has [`MAX_SSE_STREAMS`] open (batch-3 review M5).
    pub fn try_sse_pin(self: &Arc<Self>) -> Option<Pin> {
        self.sse_streams
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_SSE_STREAMS).then_some(n + 1)
            })
            .ok()?;
        Some(Pin {
            rt: self.clone(),
            sse: true,
        })
    }

    pub fn sse_pin(self: &Arc<Self>) -> Pin {
        self.sse_streams.fetch_add(1, Ordering::SeqCst);
        Pin {
            rt: self.clone(),
            sse: true,
        }
    }

    pub fn mcp_pin(self: &Arc<Self>) -> Pin {
        self.mcp_calls.fetch_add(1, Ordering::SeqCst);
        Pin {
            rt: self.clone(),
            sse: false,
        }
    }
}

/// Open event streams per user (batch-3 review M5).
pub const MAX_SSE_STREAMS: usize = 8;

/// Keeps a runtime from eviction while an SSE stream or an MCP call is open.
pub struct Pin {
    rt: Arc<UserRuntime>,
    sse: bool,
}

impl Drop for Pin {
    fn drop(&mut self) {
        let c = if self.sse {
            &self.rt.sse_streams
        } else {
            &self.rt.mcp_calls
        };
        c.fetch_sub(1, Ordering::SeqCst);
    }
}

fn write_config(path: &Path, deps: &RuntimeDeps) -> Result<(), RuntimeError> {
    let list = deps
        .store
        .instance_list()
        .map_err(|e| RuntimeError::Store(e.to_string()))?;
    std::fs::write(path, config_toml(&list, deps.org_ca.as_deref()))
        .map_err(|e| RuntimeError::Store(e.to_string()))
}

#[cfg(any(test, feature = "testing"))]
async fn start_core(deps: CoreDeps, store: &Store, allow_http: bool) -> Result<Core, String> {
    use atlas_duck_core::audit_port::AuditPort;
    let port: Arc<dyn AuditPort> = Arc::new(store.clone());
    let hooks = atlas_duck_core::TestHooks {
        allow_http,
        no_field_cache: true,
        ..atlas_duck_core::TestHooks::none()
    };
    Core::start_with_port(deps, port, hooks)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(not(any(test, feature = "testing")))]
async fn start_core(deps: CoreDeps, _store: &Store, _allow_http: bool) -> Result<Core, String> {
    Core::start(deps).await.map_err(|e| e.to_string())
}

/// The open runtimes (PD-209): at most `max_open`, least recently used evicted first among the
/// evictable ones; none evictable → opening goes above the cap (`runtime_cap_exceeded`).
pub struct Registry {
    deps: RuntimeDeps,
    max_open: usize,
    open: tokio::sync::Mutex<HashMap<String, Arc<UserRuntime>>>,
    tick: AtomicU64,
    closed: Mutex<Vec<UserHead>>,
    /// M14 PD-257: stores opened for auditors without a runtime, with their last use.
    views: Mutex<HashMap<String, (StoreOnly, i64)>>,
    /// M14 PD-254: users whose store an export job is using; their view is never closed idle
    /// and their runtime never evicted while a pin is held.
    view_pins: Mutex<HashMap<String, usize>>,
    /// M13 T6: no runtime opens while a backup or restore holds the stores still.
    quiesced: AtomicBool,
    /// M13 T6: `admin maintenance on`: every request but the probes is refused.
    maintenance: AtomicBool,
}

/// Holds a user's store open for an export job ([`Registry::pin_view`]); released on drop.
pub struct ViewPin {
    registry: Arc<Registry>,
    user_id: String,
}

impl Drop for ViewPin {
    fn drop(&mut self) {
        let mut pins = self.registry.pins();
        if let Some(n) = pins.get_mut(&self.user_id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                pins.remove(&self.user_id);
            }
        }
    }
}

/// PD-257: an audit view nobody used for this long is closed.
pub const VIEW_IDLE_SECS: i64 = 300;

impl Registry {
    pub fn new(deps: RuntimeDeps, max_open: usize) -> Registry {
        Registry {
            deps,
            max_open: max_open.max(1),
            open: tokio::sync::Mutex::new(HashMap::new()),
            tick: AtomicU64::new(0),
            closed: Mutex::new(Vec::new()),
            views: Mutex::new(HashMap::new()),
            view_pins: Mutex::new(HashMap::new()),
            quiesced: AtomicBool::new(false),
            maintenance: AtomicBool::new(false),
        }
    }

    pub fn maintenance(&self) -> bool {
        self.maintenance.load(Ordering::SeqCst)
    }

    pub fn set_maintenance(&self, on: bool) {
        self.maintenance.store(on, Ordering::SeqCst);
    }

    /// Closes every runtime and keeps new ones from opening until [`Registry::resume`]; answers
    /// the closed runtimes' last heads (the caller anchors them).
    pub async fn quiesce(&self) -> Vec<UserHead> {
        let mut open = self.open.lock().await;
        self.quiesced.store(true, Ordering::SeqCst);
        let all: Vec<Arc<UserRuntime>> = open.drain().map(|(_, r)| r).collect();
        drop(open);
        let mut heads = Vec::new();
        for rt in all {
            rt.close().await;
            heads.push((rt.user_id.clone(), rt.head()));
        }
        self.close_views(None).await;
        heads
    }

    /// Closes one user's runtime if it is open (retention, M13 T8); answers its last head. An
    /// auditor's view of the user closes too.
    pub async fn close_user(&self, user_id: &str) -> Option<Head> {
        self.close_views(Some(user_id)).await;
        let rt = self.open.lock().await.remove(user_id)?;
        rt.close().await;
        Some(rt.head())
    }

    pub fn resume(&self) {
        self.quiesced.store(false, Ordering::SeqCst);
    }

    /// Closes the audit views of `user` (all users when `None`): a backup, restore or retention
    /// purge must not leave an auditor's store handle open (M13 merge).
    async fn close_views(&self, user: Option<&str>) {
        let closing: Vec<StoreOnly> = {
            let mut views = self.views();
            let keys: Vec<String> = views
                .keys()
                .filter(|k| user.is_none_or(|u| u == k.as_str()))
                .cloned()
                .collect();
            keys.iter()
                .filter_map(|k| views.remove(k).map(|(v, _)| v))
                .collect()
        };
        for v in closing {
            let store = v.store.clone();
            let _ = tokio::task::spawn_blocking(move || store.shutdown()).await;
        }
    }

    fn pins(&self) -> std::sync::MutexGuard<'_, HashMap<String, usize>> {
        self.view_pins.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn pinned(&self, user_id: &str) -> bool {
        self.pins().contains_key(user_id)
    }

    /// M14 PD-254: keeps `user_id`'s audit view (or runtime) open while the pin lives: the idle
    /// sweep and runtime eviction skip it, so an export never loses its store mid-run.
    pub fn pin_view(self: &Arc<Self>, user_id: &str) -> ViewPin {
        *self.pins().entry(user_id.to_owned()).or_insert(0) += 1;
        ViewPin {
            registry: self.clone(),
            user_id: user_id.to_owned(),
        }
    }

    fn views(&self) -> std::sync::MutexGuard<'_, HashMap<String, (StoreOnly, i64)>> {
        self.views.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// M14 PD-257 (Δ-M14-3): `user_id`'s audit store for an auditor. The open runtime's store
    /// when there is one; else the store opened without a core (so an audit read appends no
    /// `APP_START` and no agent-facing runtime exists), held under the user's instance lock and
    /// closed after [`VIEW_IDLE_SECS`] idle. A runtime opening meanwhile adopts it. A user who has
    /// no store is `UnknownUser` (an auditor never creates one).
    pub async fn audit_view(&self, user_id: &str) -> Result<Store, RuntimeError> {
        // Under the registry lock: no runtime of this user opens while the view is made.
        let open = self.open.lock().await;
        if self.quiesced.load(Ordering::SeqCst) {
            return Err(RuntimeError::Store("quiesced".into()));
        }
        if let Some(rt) = open.get(user_id) {
            return Ok(rt.audit_handle());
        }
        let now = self.deps.clock.now();
        let mut views = self.views();
        if let Some((v, at)) = views.get_mut(user_id) {
            *at = now;
            return Ok(v.store.clone());
        }
        let opened = UserRuntime::open_store(user_id, &self.deps, false)?;
        let store = opened.store.clone();
        views.insert(user_id.to_owned(), (opened, now));
        drop(open);
        Ok(store)
    }

    /// Closes every audit view idle for [`VIEW_IDLE_SECS`] (the periodic task; tests call it).
    pub async fn close_idle_views(&self) -> usize {
        let now = self.deps.clock.now();
        let idle: Vec<StoreOnly> = {
            let mut views = self.views();
            let keys: Vec<String> = views
                .iter()
                .filter(|(k, (_, at))| now - at >= VIEW_IDLE_SECS && !self.pinned(k))
                .map(|(k, _)| k.clone())
                .collect();
            keys.iter()
                .filter_map(|k| views.remove(k).map(|(v, _)| v))
                .collect()
        };
        let n = idle.len();
        for v in idle {
            let store = v.store.clone();
            let _ = tokio::task::spawn_blocking(move || store.shutdown()).await;
            drop(v);
        }
        n
    }

    /// Whether `user_id` has an open audit view (tests).
    pub fn has_audit_view(&self, user_id: &str) -> bool {
        self.views().contains_key(user_id)
    }

    pub fn deps(&self) -> &RuntimeDeps {
        &self.deps
    }

    /// The runtime of the request's user, opened on first need.
    pub async fn runtime(&self, ctx: &UserCtx) -> Result<Arc<UserRuntime>, ApiError> {
        self.open_user(&ctx.user_id).await.map_err(|e| e.api())
    }

    /// Opens (or returns) a user's runtime; the open happens under the registry lock, so two
    /// requests never open one store twice.
    pub(crate) async fn open_user(&self, user_id: &str) -> Result<Arc<UserRuntime>, RuntimeError> {
        let mut open = self.open.lock().await;
        if self.quiesced.load(Ordering::SeqCst) {
            return Err(RuntimeError::Store("quiesced".into()));
        }
        let t = self.tick.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(rt) = open.get(user_id) {
            rt.last_used.store(t, Ordering::SeqCst);
            return Ok(rt.clone());
        }
        if open.len() >= self.max_open {
            let victim = open
                .values()
                // Batch-3 review I3: a runtime a request still holds (any `Arc` besides this
                // map's, a pin included) is in use and never closed under it.
                .filter(|r| Arc::strong_count(r) == 1 && r.evictable() && !self.pinned(&r.user_id))
                .min_by_key(|r| r.last_used.load(Ordering::SeqCst))
                .map(|r| r.user_id.clone());
            match victim.and_then(|v| open.remove(&v)) {
                Some(rt) => {
                    let head = rt.head();
                    rt.close().await;
                    self.closed_heads().push((rt.user_id.clone(), head));
                }
                None => tracing::warn!(event = "runtime_cap_exceeded", open = open.len()),
            }
        }
        // PD-257: a store an auditor's view holds is adopted, never opened twice.
        let adopted = self.views().remove(user_id).map(|(v, _)| v);
        let rt = Arc::new(match adopted {
            Some(v) => UserRuntime::open_with(user_id, &self.deps, v).await?,
            None => UserRuntime::open(user_id, &self.deps).await?,
        });
        rt.bind_script_instances();
        rt.last_used.store(t, Ordering::SeqCst);
        open.insert(user_id.to_owned(), rt.clone());
        Ok(rt)
    }

    fn closed_heads(&self) -> std::sync::MutexGuard<'_, Vec<UserHead>> {
        self.closed.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Heads of runtimes closed by eviction since the last call (`RUNTIME_CLOSED`, Task 15).
    pub fn take_closed_heads(&self) -> Vec<UserHead> {
        std::mem::take(&mut *self.closed_heads())
    }

    pub async fn open_runtimes(&self) -> Vec<Arc<UserRuntime>> {
        self.open.lock().await.values().cloned().collect()
    }

    /// PD-196: every open runtime reloads the admin instances.
    pub async fn instances_changed(&self) {
        for rt in self.open_runtimes().await {
            if let Err(e) = rt.instances_changed(&self.deps).await {
                tracing::error!(event = "instances_reload_failed", error = ?e);
            }
        }
    }

    /// Shutdown: closes every runtime (`APP_STOP` in each chain); answers their last heads.
    pub async fn close_all(&self) -> Vec<UserHead> {
        let all: Vec<Arc<UserRuntime>> = self.open.lock().await.drain().map(|(_, r)| r).collect();
        let mut heads = Vec::new();
        for rt in all {
            rt.close().await;
            heads.push((rt.user_id.clone(), rt.head()));
        }
        // M14: audit views close too (no core, so no APP_STOP; an export's record is anchored by
        // the export itself).
        let views: Vec<StoreOnly> = self.views().drain().map(|(_, (v, _))| v).collect();
        for v in views {
            let store = v.store.clone();
            let _ = tokio::task::spawn_blocking(move || store.shutdown()).await;
        }
        heads
    }
}

/// The login's per-user side: opening the runtime creates the user's store if it is missing
/// (every login retries a failed creation), then `LOGIN` goes into the user's chain.
pub struct RegistrySink(pub Arc<Registry>);

#[async_trait::async_trait]
impl crate::login::LoginSink for RegistrySink {
    async fn user_created(&self, user_id: &str) -> Result<(), ApiError> {
        self.0
            .open_user(user_id)
            .await
            .map(drop)
            .map_err(|e| e.api())
    }

    async fn login_recorded(
        &self,
        user_id: &str,
        payload: Map<String, Value>,
    ) -> Result<(), ApiError> {
        let rt = self.0.open_user(user_id).await.map_err(|e| e.api())?;
        rt.append_server_record(EventType::LOGIN, payload).await
    }
}

#[cfg(test)]
#[path = "tests/runtime.rs"]
pub(crate) mod tests;
