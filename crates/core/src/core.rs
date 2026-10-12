//! The composition root (C.7): `CoreDeps` in, a running `Core` out. This is the one place that
//! builds the `CoverIssuer`, over `StoreProbe` of the committed set the audit port fills (§5.1
//! inv. 1; Task 30 checks that no other file calls `CoverIssuer::new`).
//!
//! Task 19 builds the instance table and the engine; Task 28 completes `start` (reconciliation,
//! similarity seeding, `APP_START`, `pats_deleted`) and `shutdown` (§2.5 steps 2–5).

use std::path::PathBuf;
use std::sync::Arc;

use atlas_duck_atlassian::{CoverIssuer, CredentialProvider};
use atlas_duck_audit::{AuditError, Clock, ReconciledWrite, RestoreReport, Store};
use atlas_duck_ipc::proto::RequestHandler;
use serde_json::{Map, Value};

use crate::audit_port::{AuditPort, CommittedSet, StoreProbe};
use crate::config::ConfigState;
use crate::config::instances::ensure_ids;
use crate::config::limits::limits_config;
use crate::config::load_config;
use crate::decision::{CoreDecisions, DecisionApi};
use crate::engine::cancel::ShutdownReason as CancelWhy;
use crate::engine::handler::CoreHandler;
use crate::engine::queue::Limits;
use crate::engine::script::ScriptRunner;
use crate::engine::{Engine, EngineDeps};
use crate::gate::{UiEvent, UiSink};
use crate::http_factory::HttpFactory;
use crate::instances::state::DeriveCtx;
use crate::instances::{CoreInstances, InstanceAdmin, InstanceTable};
use crate::payloads::{self, AppStopReason, ConfigSource};
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

/// What `Core::start` needs (C.7 + PD-21, PD-28).
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
    /// The script worker glue (`app::script_glue`, M8). Additive Δ C.7: `None` (no sandbox in
    /// this build) answers every script `failed`, `sandbox_unavailable` (§9.4), exit 8.
    pub scripts: Option<Arc<dyn ScriptRunner>>,
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
    /// `submit` / `submit_script` hold after their shutdown check, before `REQUEST_RECEIVED`
    /// is appended (review I-1).
    pub pause_before_received: Option<Arc<Pause>>,
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
    /// Replaces the 60 s that `shutdown` waits for writes that are `executing` (§2.5 step 4).
    pub shutdown_write_wait: Option<std::time::Duration>,
}

#[cfg(feature = "testing")]
impl TestHooks {
    pub fn none() -> TestHooks {
        TestHooks::default()
    }
}

/// The running core: one engine behind the handler (IPC), the decision API (UI, approver) and
/// the instance admin (settings).
/// What [`Core::shutdown`] did (§2.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Requests the sweep ended `cancelled` (reads, writes not yet executing, scripts).
    pub cancelled: u32,
    /// Writes that were `executing`, waited for until they logged their outcome.
    pub writes_waited: u32,
    /// `APP_STOP` is in the log. `false`: the append failed; the next start reconciles whatever
    /// is open like after a crash (M6 may warn).
    pub app_stop_logged: bool,
}

pub struct Core {
    /// The one shutdown: later calls wait for it and get its report (review I-3).
    shutdown_done: tokio::sync::OnceCell<ShutdownReport>,
    notice: Vec<ReconciledWrite>,
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
        let install_id = deps.audit.install_id().to_owned();
        // Step 1 (§11.3): close every request the last run left open. The predicate is the
        // store's. An error is an integrity problem: no `APP_START`, nothing deleted.
        let report = {
            let port = port.clone();
            tokio::task::spawn_blocking(move || port.reconcile_after_crash())
                .await
                .unwrap_or(Err(AuditError::Closed))
                .map_err(StartError::Audit)?
        };
        // Startup step 2 (X-01, §8.8): the audit policy the file asks for, logged before
        // anything else appends. It runs after the crash reconciliation (review I-2): prune
        // stays blocked until then, so a start that fails its integrity check deletes nothing.
        {
            let (port, cfg) = (port.clone(), config.clone());
            let _ = tokio::task::spawn_blocking(move || {
                crate::reconcile::reconcile_config_file(&*port, &cfg);
            })
            .await;
        }
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
            // A panic in the derivation fails CLOSED (review I-2): no instance is routable and
            // none has a usable token until a start that derives.
            .unwrap_or_else(|_| (InstanceTable::fail_closed(&config), Vec::new()))
        };
        for c in &file_side {
            let ev = payloads::config_changed(ConfigSource::File, &c.key, &c.old, &c.new, false);
            let port = port.clone();
            // Best effort: a failed append must not stop the app from starting.
            let _ = tokio::task::spawn_blocking(move || port.append(ev)).await;
        }
        // Step 5 (L45, RF-4): the similarity index from the last 24 h of the log, after the
        // reconciliation (a write whose outcome is unknown is a hit "outcome unknown"). The flags
        // are advisory: a scan that fails starts the index empty.
        let seeded = {
            let (port, clock) = (port.clone(), deps.clock.clone());
            tokio::task::spawn_blocking(move || SimilarityIndex::seed(&*port, clock))
                .await
                .ok()
                .and_then(|r| r.ok())
        };
        let seed_failed = seeded.is_none();
        let similarity = seeded.unwrap_or_else(|| {
            tracing::warn!("the similarity index could not be seeded; it starts empty");
            SimilarityIndex::new(deps.clock.clone())
        });
        let seed_skipped = similarity.seed_skipped();
        let committed = Arc::new(CommittedSet::default());
        // The composition root's one cover issuer: covers only for ids the port committed.
        let covers = CoverIssuer::new(Arc::new(StoreProbe(committed.clone())));
        let ui = deps.ui.clone();
        let (app_start_extra, pats_deleted) = (deps.app_start_extra, deps.pats_deleted);
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
            scripts: deps.scripts,
            #[cfg(feature = "testing")]
            hooks: opts.hooks,
        }));
        let core = Core {
            shutdown_done: tokio::sync::OnceCell::new(),
            notice: report.outcome_unknown,
            handler: Arc::new(CoreHandler::new(engine.clone())),
            decisions: Arc::new(CoreDecisions::new(engine.clone())),
            instances: Arc::new(CoreInstances::new(engine.clone(), config_path)),
            engine,
        };
        // Step 6 (PD-21): `APP_START` with the install id in `target`; then step 7 (PD-28): one
        // `needs_token` record per PAT a restore or recovery deleted, in the same batch. The start
        // fails if the log cannot take them: nothing is served that the log does not know about.
        let proxies = core.effective_proxies().await;
        let start = crate::reconcile::app_start_event(
            &install_id,
            &app_start_extra,
            &config,
            proxies,
            seed_skipped,
            seed_failed,
            &pats_deleted,
        );
        core.engine
            .blocking(move |p| {
                // One transaction (M3 review M-7): all or nothing.
                let mut records = vec![start];
                records.extend(crate::reconcile::pats_deleted_events(&pats_deleted));
                p.append_batch(records).map(drop)
            })
            .await
            .map_err(StartError::Audit)?;
        if !core.notice.is_empty() {
            ui.emit(UiEvent::StatusBanner {
                line_ids: vec![crate::reconcile::LINE_CHECK_TARGET.to_owned()],
            });
        }
        Ok(core)
    }

    /// `{alias: "host:port" | "direct"}` for `APP_START` (§8.3). The OS proxy reading can block.
    async fn effective_proxies(&self) -> Map<String, Value> {
        let admin = self.instances.clone();
        tokio::task::spawn_blocking(move || admin.list())
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|v| {
                let proxy = v.proxy_effective.unwrap_or_else(|| "direct".to_owned());
                (v.alias, Value::String(proxy))
            })
            .collect()
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

    /// The local UTC offset in minutes the similarity notice text uses (Δ6); `None` is UTC.
    pub fn set_utc_offset(&self, minutes: Option<i32>) {
        self.engine.similarity().set_utc_offset(minutes);
    }

    /// Tests only: the engine's internals (audit port, covers) are not part of the app surface.
    #[cfg(feature = "testing")]
    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }

    /// The one §2.5 shutdown path (I-40): (1) from now on every `submit` / `submit_script` is
    /// refused `app_shutting_down` (other methods keep working until the app exits); (2, 3)
    /// every request that is not `executing` ends `cancelled` with the app's reason, a running
    /// script is killed first; (4) writes that are `executing` are waited for, at most 60 s;
    /// (5) the head anchor is flushed and `APP_STOP` is appended. A second (concurrent or later)
    /// call changes nothing: it waits for the first to finish and returns the same report. M6
    /// exits right after this returns (a write past its 60 s may still commit after `APP_STOP`).
    /// OS end-session blocking (`ShutdownBlockReasonCreate` etc.) is M6's.
    pub async fn shutdown(&self, reason: ShutdownReason) -> ShutdownReport {
        *self
            .shutdown_done
            .get_or_init(|| self.run_shutdown(reason))
            .await
    }

    async fn run_shutdown(&self, reason: ShutdownReason) -> ShutdownReport {
        // Waits for every submit that passed its check to register its request, then refuses
        // all later ones (review I-1).
        self.engine.begin_shutdown().await;
        let (why, stop) = match reason {
            ShutdownReason::Quit => (CancelWhy::AppQuit, AppStopReason::Quit),
            // The installer path cancels with the app's own reason (§8.3: `app_quit`).
            ShutdownReason::Installer => (CancelWhy::AppQuit, AppStopReason::Installer),
            ShutdownReason::OsShutdown => (CancelWhy::OsShutdown, AppStopReason::OsShutdown),
        };
        #[cfg(feature = "testing")]
        let wait = self
            .engine
            .hooks()
            .shutdown_write_wait
            .unwrap_or(crate::shutdown::WRITE_WAIT);
        #[cfg(not(feature = "testing"))]
        let wait = crate::shutdown::WRITE_WAIT;
        let swept = crate::shutdown::sweep(&self.engine, why, wait).await;
        let app_stop_logged = crate::shutdown::stop(&self.engine, stop).await.is_ok();
        ShutdownReport {
            cancelled: swept.cancelled,
            writes_waited: swept.writes_waited,
            app_stop_logged,
        }
    }

    /// M10's restore UI calls this after an in-process `Store::restore` (M2 handoff 3): the
    /// config file is reconciled again (prune stays blocked until it ran), each instance whose
    /// PAT the restore deleted (`report.pats_deleted`) gets its `INSTANCE_STATE_CHANGED
    /// {needs_token}` record, and the instance table is read again (those are `needs_token`).
    pub async fn after_restore(&self, report: &RestoreReport) -> Result<(), AuditError> {
        let ids = report.pats_deleted.clone();
        let cfg = self.instances.current_config().await;
        self.engine
            .blocking(move |p| {
                crate::reconcile::reconcile_config_file(p, &cfg);
                crate::reconcile::log_pats_deleted(p, &ids)
            })
            .await?;
        self.instances.reload_now().await;
        Ok(())
    }

    /// The writes the crash reconciliation of this start closed as `outcome_unknown` (§11.3):
    /// the startup notice lists their targets ("check the target before resubmitting").
    pub fn startup_notice(&self) -> Vec<ReconciledWrite> {
        self.notice.clone()
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
