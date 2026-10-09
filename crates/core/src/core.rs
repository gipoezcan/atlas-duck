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
use crate::config::load_config;
use crate::decision::{CoreDecisions, DecisionApi};
use crate::engine::handler::CoreHandler;
use crate::engine::{Engine, EngineDeps};
use crate::gate::UiSink;
use crate::http_factory::HttpFactory;
use crate::instances::{CoreInstances, InstanceAdmin, InstanceTable};

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

/// Test-only behaviour installed by `Core::start_with_port` (Task 28 acts on it).
#[cfg(feature = "testing")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestHooks {
    pub freeze_at: Option<HookPoint>,
    /// A read whose JQL contains this text panics after `REQUEST_RECEIVED` (S-15).
    pub panic_on_jql: Option<String>,
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
        Core::start_inner(deps, port).await
    }

    /// `start` with the audit port replaced (e.g. `FaultyAudit::wrap(..)`) and test hooks
    /// installed. The `Harness` always starts `Core` through this.
    #[cfg(feature = "testing")]
    pub async fn start_with_port(
        deps: CoreDeps,
        port: Arc<dyn AuditPort>,
        hooks: TestHooks,
    ) -> Result<Core, StartError> {
        let core = Core::start_inner(deps, port).await?;
        core.engine.set_hooks(hooks);
        Ok(core)
    }

    async fn start_inner(deps: CoreDeps, port: Arc<dyn AuditPort>) -> Result<Core, StartError> {
        let config = match &deps.config_path {
            Some(path) => assign_ids(path.clone(), deps.config).await,
            None => deps.config,
        };
        let committed = Arc::new(CommittedSet::default());
        // The composition root's one cover issuer: covers only for ids the port committed.
        let covers = CoverIssuer::new(Arc::new(StoreProbe(committed.clone())));
        let engine = Arc::new(Engine::new(EngineDeps {
            port,
            committed,
            covers,
            http: Arc::new(deps.http),
            credentials: deps.credentials,
            confirmer: deps.confirmer,
            clock: deps.clock,
            ui: deps.ui,
            instances: InstanceTable::from_config(&config),
        }));
        Ok(Core {
            handler: Arc::new(CoreHandler::new(engine.clone())),
            decisions: Arc::new(CoreDecisions::new(engine.clone())),
            instances: Arc::new(CoreInstances::new(engine.clone())),
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

/// PD-04: write ids for hand-written instances when the file is writable, then read it again.
/// A failed write or re-read keeps the loaded state: those instances stay unconfirmed.
async fn assign_ids(path: PathBuf, config: ConfigState) -> ConfigState {
    if !matches!(config, ConfigState::Writable(_)) {
        return config;
    }
    let fallback = config.clone();
    tokio::task::spawn_blocking(move || {
        ensure_ids(&path, &config)
            .and_then(|()| load_config(&path))
            .unwrap_or(config)
    })
    .await
    .unwrap_or(fallback)
}
