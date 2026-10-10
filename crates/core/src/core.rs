//! The composition root (C.7): `CoreDeps` in, a running `Core` out. This is the one place that
//! builds the `CoverIssuer`, over `StoreProbe` of the committed set the audit port fills (§5.1
//! inv. 1; Task 30 checks that no other file calls `CoverIssuer::new`).
//!
//! Task 19 builds the instance table and the engine; Task 28 completes `start` (reconciliation,
//! similarity seeding, `APP_START`, `pats_deleted`) and `shutdown` (§2.5 steps 2–5).

use std::path::PathBuf;
use std::sync::Arc;

use atlas_duck_atlassian::{CoverIssuer, CredentialProvider};
use atlas_duck_audit::{AuditError, Clock, Store};
use atlas_duck_ipc::proto::RequestHandler;
use serde_json::{Map, Value};

use crate::audit_port::{AuditPort, CommittedSet, StoreProbe};
use crate::config::ConfigState;
use crate::config::instances::ensure_ids;
use crate::config::limits::limits_config;
use crate::config::load_config;
use crate::decision::{CoreDecisions, DecisionApi};
use crate::engine::handler::CoreHandler;
use crate::engine::queue::Limits;
use crate::engine::{Engine, EngineDeps};
use crate::gate::UiSink;
use crate::http_factory::HttpFactory;
use crate::instances::state::DeriveCtx;
use crate::instances::{CoreInstances, InstanceAdmin, InstanceTable};
use crate::payloads::{self, ConfigSource};
use crate::similarity::SimilarityIndex;

/// §2.2: the native confirmation dialog (`app`: Tauri; tests: `testing::StubConfirmer`).
pub trait NativeConfirmer: Send + Sync {
    fn confirm(&self, text: &str) -> Confirm;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    Ok,
    Cancel,
}

/// What `Core::start` needs (C.7 + PD-21, PD-28). `scripts: Arc<dyn ScriptRunner>` joins with
/// the `ScriptRunner` seam in Task 27.
pub struct CoreDeps {
    pub audit: Store,
    pub clock: Arc<dyn Clock>,
    pub credentials: Arc<dyn CredentialProvider>,
    pub confirmer: Arc<dyn NativeConfirmer>,
    pub ui: Arc<dyn UiSink>,
    pub config: ConfigState,
    /// Additive (plan Δ C.7): where `config` was read from, so ids can be written back (PD-04)
    /// and Task 25 can add instances; `None` = never write.
    pub config_path: Option<PathBuf>,
    pub http: HttpFactory,
    /// Merged into the `APP_START` payload (PD-21, Task 28).
    pub app_start_extra: Map<String, Value>,
    /// Instance ids whose PAT a restore or recovery deleted (PD-28, Task 28).
    pub pats_deleted: Vec<String>,
}

/// Why `Core::start` refused.
#[derive(Debug)]
pub enum StartError {
    /// The audit store failed during start (Task 28: an integrity problem of
    /// `reconcile_after_crash`, no `APP_START`).
    Audit(AuditError),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::Audit(e) => write!(f, "audit store: {e}"),
        }
    }
}

impl std::error::Error for StartError {}

/// The one §2.5 shutdown path's trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    Quit,
    OsShutdown,
    Installer,
}

/// Where a test freezes the engine (Task 28: crash injection).
#[cfg(feature = "testing")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPoint {
    /// Right after an append of this type committed.
    AfterAppend(atlas_duck_audit::EventType),
}

/// A point where a test holds a flow: the flow signals `reached`, then waits for `release`.
#[cfg(feature = "testing")]
#[derive(Default)]
pub struct Pause {
    pub reached: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
}

#[cfg(feature = "testing")]
impl std::fmt::Debug for Pause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pause")
    }
}

#[cfg(feature = "testing")]
impl Pause {
    pub fn new() -> Arc<Pause> {
        Arc::new(Pause::default())
    }

    /// Signal `reached`, then wait for `release`.
    pub(crate) async fn hold(&self) {
        self.reached.notify_one();
        self.release.notified().await;
    }
}

/// Test-only behaviour installed by `Core::start_with_port` before anything runs (Task 28 acts
/// on `freeze_at` and `panic_on_jql`).
#[cfg(feature = "testing")]
#[derive(Debug, Clone, Default)]
pub struct TestHooks {
    /// `submit` holds right after its `REQUEST_RECEIVED` committed (I-3: a caller dropped there
    /// must not leave the request unapplied).
    pub pause_after_received: Option<Arc<Pause>>,
    /// `Engine::transition` holds after its append committed, before it applies the model.
    pub pause_in_transition: Option<Arc<Pause>>,
    pub freeze_at: Option<HookPoint>,
    /// A read whose JQL contains this text panics after `REQUEST_RECEIVED` (S-15).
    pub panic_on_jql: Option<String>,
    /// Replaces the limits read from `config.toml` (scaled limit tests, Task 20).
    pub limits: Option<Limits>,
    /// Replaces the §7.2 read budget (short budgets for the read-budget outcome, Task 21).
    pub read_budget: Option<atlas_duck_atlassian::ReadBudget>,
    /// A read holds before it asks for a fetch slot (it stays in `Validated`).
    pub pause_before_fetch: Option<Arc<Pause>>,
    /// Replaces the request expiry (`[requests] expiry_hours`, default 24 h; Task 24).
    pub expiry: Option<std::time::Duration>,
    /// Accept `http://` instance origins (the harness's mocks); off, an `http://` origin is
    /// refused like in a release build (§7.1, I-02).
    pub allow_http: bool,
    /// A write holds after one of its app-initiated GETs finished and its record is parked, before
    /// any append commits it (Task 24 review I-2).
    pub pause_after_get: Option<Arc<Pause>>,
}

#[cfg(feature = "testing")]
impl TestHooks {
    pub fn none() -> TestHooks {
        TestHooks::default()
    }
}

/// The running core: one engine behind the handler (IPC), the decision API (UI, approver) and
/// the instance admin (settings).
pub struct Core {
    engine: Arc<Engine>,
    handler: Arc<CoreHandler>,
    decisions: Arc<CoreDecisions>,
    instances: Arc<CoreInstances>,
}

impl Core {
    /// Needs a `Ready` store; without one the app serves `gate_handler` instead (C.7).
    pub async fn start(deps: CoreDeps) -> Result<Core, StartError> {
        let port: Arc<dyn AuditPort> = Arc::new(deps.audit.clone());
        Core::start_inner(deps, port, StartOptions::default()).await
    }

    /// `start` with the audit port replaced (e.g. `FaultyAudit::wrap(..)`) and test hooks
    /// installed. The `Harness` always starts `Core` through this.
    #[cfg(feature = "testing")]
    pub async fn start_with_port(
        deps: CoreDeps,
        port: Arc<dyn AuditPort>,
        hooks: TestHooks,
    ) -> Result<Core, StartError> {
        let opts = StartOptions {
            limits: hooks.limits,
            hooks,
        };
        Core::start_inner(deps, port, opts).await
    }

    async fn start_inner(
        deps: CoreDeps,
        port: Arc<dyn AuditPort>,
        opts: StartOptions,
    ) -> Result<Core, StartError> {
        let limits = opts.limits;
        let config_path = deps.config_path.clone();
        let config = match &deps.config_path {
            Some(path) => assign_ids(path.clone(), deps.config).await,
            None => deps.config,
        };
        // §5.2 Settings keys; a malformed `[limits]` table runs with the spec's defaults.
        let limits = limits.unwrap_or_else(|| {
            limits_config(&config)
                .map(|c| Limits::from_config(&c))
                .unwrap_or_default()
        });
        #[cfg(feature = "testing")]
        let allow_http = opts.hooks.allow_http;
        #[cfg(not(feature = "testing"))]
        let allow_http = false;
        // PD-22: the instance table from `config.toml`, the audit settings and the keychain; the
        // file-side edits it did not apply are logged once per start (I-31).
        let (instances, file_side) = {
            let (port, creds, cfg) = (port.clone(), deps.credentials.clone(), config.clone());
            tokio::task::spawn_blocking(move || {
                let settings = port.settings();
                InstanceTable::derive(
                    &cfg,
                    &DeriveCtx {
                        settings: &settings,
                        creds: &*creds,
                        allow_http,
                        previous: None,
                    },
                )
            })
            .await
            .unwrap_or_else(|_| (InstanceTable::from_config(&config), Vec::new()))
        };
        for c in &file_side {
            let ev = payloads::config_changed(ConfigSource::File, &c.key, &c.old, &c.new, false);
            let port = port.clone();
            // Best effort: a failed append must not stop the app from starting.
            let _ = tokio::task::spawn_blocking(move || port.append(ev)).await;
        }
        let committed = Arc::new(CommittedSet::default());
        // The composition root's one cover issuer: covers only for ids the port committed.
        let covers = CoverIssuer::new(Arc::new(StoreProbe(committed.clone())));
        // Task 28 seeds it at startup step 5 (`SimilarityIndex::seed`, RF-4); until then the
        // index starts empty and is kept current from submits and terminal states.
        let similarity = SimilarityIndex::new(deps.clock.clone());
        let engine = Arc::new(Engine::new(EngineDeps {
            port,
            committed,
            covers,
            http: Arc::new(deps.http),
            credentials: deps.credentials,
            confirmer: deps.confirmer,
            clock: deps.clock,
            ui: deps.ui,
            instances,
            limits,
            runtime: tokio::runtime::Handle::current(),
            similarity,
            expiry: crate::config::requests::expiry(&config),
            #[cfg(feature = "testing")]
            hooks: opts.hooks,
        }));
        Ok(Core {
            handler: Arc::new(CoreHandler::new(engine.clone())),
            decisions: Arc::new(CoreDecisions::new(engine.clone())),
            instances: Arc::new(CoreInstances::new(engine.clone(), config_path)),
            engine,
        })
    }

    /// What `IpcServer` serves.
    pub fn handler(&self) -> Arc<dyn RequestHandler> {
        self.handler.clone()
    }

    /// The Tauri commands and the scripted approver call this, nothing else.
    pub fn decisions(&self) -> Arc<dyn DecisionApi> {
        self.decisions.clone()
    }

    pub fn instances(&self) -> Arc<dyn InstanceAdmin> {
        self.instances.clone()
    }

    /// Tests only: the engine's internals (audit port, covers) are not part of the app surface.
    #[cfg(feature = "testing")]
    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }

    /// §2.5 step 1: from now on every `submit`/`submit_script` is refused `app_shutting_down`;
    /// other methods keep working. Steps 2–5 (cancel, wait for executing writes, `APP_STOP`)
    /// are Task 28's.
    pub async fn shutdown(&self, _reason: ShutdownReason) {
        self.engine.begin_shutdown();
    }
}

/// What `start` and `start_with_port` differ in.
#[derive(Default)]
struct StartOptions {
    limits: Option<Limits>,
    #[cfg(feature = "testing")]
    hooks: TestHooks,
}

/// PD-04: write ids for hand-written instances when the file is writable, then read it again.
/// A failed write or re-read keeps the loaded state: those instances stay unconfirmed.
async fn assign_ids(path: PathBuf, config: ConfigState) -> ConfigState {
    if !matches!(config, ConfigState::Writable(_)) {
        return config;
    }
    let fallback = config.clone();
    tokio::task::spawn_blocking(move || {
        ensure_ids(&path)
            .and_then(|()| load_config(&path))
            .unwrap_or(config)
    })
    .await
    .unwrap_or(fallback)
}
