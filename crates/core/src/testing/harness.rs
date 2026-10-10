//! `Harness` (C.7 `core::testing`): a real temp-dir store, one wiremock Data Center per
//! instance, the stub confirmer, in-memory credentials and the capture hook around a `Core`
//! started through `Core::start_with_port` (the audit port is always a `FaultyAudit`, so any test
//! can inject append failures through `plan()`).
//!
//! Every handler, decision and instance call made through the harness, and every `UiEvent` the
//! core emits, passes the `Capture` (PD-12).

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_PAT, TEST_USER, TEST_USER_KEY};
use atlas_duck_atlassian::{ReadBudget, Timeouts, normalize_base_url, url_hash};
use atlas_duck_audit::testing::{FakeClock, FreeSpaceStub};
use atlas_duck_audit::{Confirmed, EventType, SettingChange, Store};
use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::envelope::Envelope;
use atlas_duck_ipc::proto::{
    AgentNameSource, AwaitParams, ClientKind, ConnectionMeta, Hello, PeerInfo,
    ProgressNotification, ProgressSink, RequestHandler, SubmitParams,
};
use atlas_duck_registry::Product;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::approver::ScriptedApprover;
use super::capture::{
    Capture, CapturingDecisions, CapturingHandler, CapturingInstances, CapturingUi, NullUi,
};
use super::confirmer::StubConfirmer;
use super::credentials::InMemoryCredentials;
use super::store::{FaultPlan, FaultyAudit, TempStore, TestError};
use crate::audit_port::{AuditPort, DateBridge};
use crate::config::instances::ensure_ids;
use crate::config::instances::product_str;
use crate::config::{CONFIG_FILE_NAME, load_config};
use crate::core::{Confirm, Core, CoreDeps, TestHooks};
use crate::decision::{DecisionApi, QueueItem};
use crate::engine::Engine;
use crate::engine::payload_json;
use crate::engine::queue::Limits;
use crate::gate::UiSink;
use crate::http_factory::HttpFactory;
use crate::ids::InstanceId;
use crate::instances::InstanceAdmin;
use crate::instances::state::ca_fingerprint;
use crate::proxy::{OsProxy, SystemProxySource};

/// The agent name of the harness's default connection.
pub const HARNESS_AGENT: &str = "test-agent";
/// The `cwd_basename` every harness connection reports.
pub const HARNESS_CWD: &str = "workdir";

/// One instance the harness configures, with its own mock server.
pub struct HarnessInstance {
    pub alias: String,
    pub product: Product,
    pub id: String,
    pub is_default: bool,
    pub mock: MockDc,
    /// What `config.toml` names: the mock's URL unless the instance was configured with another
    /// one (`HarnessBuilder::instance_at`; the mock then gets no traffic).
    pub base_url: String,
    proxy: Option<String>,
    ca_bundle: Option<std::path::PathBuf>,
}

struct InstanceSpec {
    alias: String,
    product: Product,
    is_default: bool,
    at: Option<InstanceAt>,
}

/// An instance at a base URL of the test's choosing (raw servers, TLS servers, unreachable
/// hosts), optionally behind a proxy and with a custom CA bundle.
#[derive(Debug, Clone, Default)]
pub struct InstanceAt {
    pub base_url: String,
    /// `"host:port"` (the `config.toml` proxy setting).
    pub proxy: Option<String>,
    /// A PEM bundle written to a file the instance's `ca_bundle` names.
    pub ca_pem: Option<String>,
}

/// Configures a `Harness` before it starts.
pub struct HarnessBuilder {
    instances: Vec<InstanceSpec>,
    plan: Arc<FaultPlan>,
    pat: String,
    answers: Vec<Confirm>,
    config_text: Option<String>,
    extra_config: String,
    omit_ids: bool,
    limits: Option<Limits>,
    hooks: TestHooks,
    timeouts: Option<Timeouts>,
    strict_https: bool,
    seed_origins: bool,
}

impl HarnessBuilder {
    /// A Jira instance (context path `/jira`); the first instance of a product is its default.
    pub fn jira(self, alias: &str) -> Self {
        self.instance(alias, Product::Jira)
    }

    /// A Confluence instance (context path `/wiki`).
    pub fn confluence(self, alias: &str) -> Self {
        self.instance(alias, Product::Confluence)
    }

    fn instance(mut self, alias: &str, product: Product) -> Self {
        let is_default = !self.instances.iter().any(|i| i.product == product);
        self.instances.push(InstanceSpec {
            alias: alias.to_owned(),
            product,
            is_default,
            at: None,
        });
        self
    }

    /// An instance at `at.base_url` instead of its mock (the PAT is bound to that URL).
    pub fn instance_at(mut self, alias: &str, product: Product, at: InstanceAt) -> Self {
        let is_default = !self.instances.iter().any(|i| i.product == product);
        self.instances.push(InstanceSpec {
            alias: alias.to_owned(),
            product,
            is_default,
            at: Some(at),
        });
        self
    }

    /// Refuses `http://` instance origins like a release build (the mocks are plain http, so an
    /// instance then needs `instance_at` an https URL or is the object of an insecure-scheme
    /// test).
    pub fn strict_https(mut self) -> Self {
        self.strict_https = true;
        self
    }

    /// Leaves the audit settings without confirmed origins: every instance starts
    /// `instance_unconfirmed` (a hand-added instance, I-31).
    pub fn unconfirmed(mut self) -> Self {
        self.seed_origins = false;
        self
    }

    /// Connect, per-call and write timeouts of every instance client (§7.2 defaults otherwise).
    pub fn timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = Some(timeouts);
        self
    }

    /// Replaces the §7.2 read budget (e.g. 300 ms for the read-budget outcome).
    pub fn read_budget(mut self, budget: ReadBudget) -> Self {
        self.hooks.read_budget = Some(budget);
        self
    }

    /// The `FaultyAudit` plan of the core's audit port.
    pub fn faults(mut self, plan: Arc<FaultPlan>) -> Self {
        self.plan = plan;
        self
    }

    /// The PAT stored for every instance (default `TEST_PAT`).
    pub fn pat(mut self, pat: &str) -> Self {
        self.pat = pat.to_owned();
        self
    }

    /// The stub confirmer's scripted answers.
    pub fn confirm(mut self, answers: Vec<Confirm>) -> Self {
        self.answers = answers;
        self
    }

    /// Writes the generated `[[instances]]` without `id` (hand-written instances, PD-04): the
    /// core assigns ids at start, so `HarnessInstance::id` is then not the routed one.
    pub fn omit_ids(mut self) -> Self {
        self.omit_ids = true;
        self
    }

    /// Replaces the generated `config.toml` (the instances still get mocks and PATs).
    pub fn config_text(mut self, text: &str) -> Self {
        self.config_text = Some(text.to_owned());
        self
    }

    /// Appended to the generated `config.toml` (e.g. a `[limits]` table).
    pub fn extra_config(mut self, text: &str) -> Self {
        self.extra_config.push_str(text);
        self
    }

    /// Test hooks installed before the core serves anything (`limits` is set by `limits`).
    pub fn hooks(mut self, hooks: TestHooks) -> Self {
        self.hooks = hooks;
        self
    }

    /// Replaces the limits the core would read from `config.toml` (scaled limit tests).
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = Some(limits);
        self
    }

    pub async fn start(self) -> Result<Harness, TestError> {
        let store = TempStore::new()?;
        let capture = Capture::new();
        let credentials = Arc::new(InMemoryCredentials::new());
        let config_dir = tempfile::tempdir()?;
        let mut instances = Vec::new();
        for (n, spec) in self.instances.iter().enumerate() {
            let context = match spec.product {
                Product::Jira => "/jira",
                Product::Confluence => "/wiki",
            };
            let product = match spec.product {
                Product::Jira => atlas_duck_atlassian::Product::Jira,
                Product::Confluence => atlas_duck_atlassian::Product::Confluence,
            };
            let mock = MockDc::start(product, context).await;
            let id = InstanceId::new()?.0;
            let (base_url, bound) = match &spec.at {
                Some(at) => (
                    at.base_url.clone(),
                    url_hash(&normalize_base_url(&at.base_url).map_err(|e| format!("{e:?}"))?),
                ),
                None => (mock.base_url(), url_hash(&mock.base())),
            };
            credentials.put(&id, &self.pat, bound, TEST_USER, TEST_USER_KEY);
            let ca_bundle = match spec.at.as_ref().and_then(|a| a.ca_pem.as_ref()) {
                Some(pem) => {
                    let path = config_dir.path().join(format!("ca-{n}.pem"));
                    std::fs::write(&path, pem)?;
                    Some(path)
                }
                None => None,
            };
            instances.push(HarnessInstance {
                alias: spec.alias.clone(),
                product: spec.product,
                id,
                is_default: spec.is_default,
                mock,
                base_url,
                proxy: spec.at.as_ref().and_then(|a| a.proxy.clone()),
                ca_bundle,
            });
        }
        let config_path = config_dir.path().join(CONFIG_FILE_NAME);
        let mut text = match self.config_text {
            Some(t) => t,
            None => config_toml(&instances, !self.omit_ids),
        };
        text.push('\n');
        text.push_str(&self.extra_config);
        std::fs::write(&config_path, text)?;
        // Hand-written instances (`omit_ids`) get their ids here, as the user's first start would
        // have written them, and are confirmed under those: the core's own id assignment (PD-04)
        // then finds them in place. `unconfirmed()` is the I-31 hand-added instance.
        let mut seed_ids: Vec<String> = instances.iter().map(|i| i.id.clone()).collect();
        if self.omit_ids {
            ensure_ids(&config_path)?;
            let written = crate::config::instances::instances(&load_config(&config_path)?)?;
            for (id, i) in seed_ids.iter_mut().zip(&instances) {
                if let Some(c) = written.iter().find(|c| c.alias == i.alias)
                    && let Some(file_id) = &c.id
                {
                    id.clone_from(file_id);
                    let bound =
                        url_hash(&normalize_base_url(&i.base_url).map_err(|e| format!("{e:?}"))?);
                    credentials.put(file_id, &self.pat, bound, TEST_USER, TEST_USER_KEY);
                }
            }
        }
        let config = load_config(&config_path)?;
        if self.seed_origins {
            seed_settings(&store, &instances, &seed_ids, self.strict_https)?;
        }

        let port: Arc<dyn AuditPort> = Arc::new(FaultyAudit::wrap(store.port(), self.plan.clone()));
        let ui = CapturingUi::wrap(Arc::new(NullUi), capture.clone());
        let confirmer = Arc::new(StubConfirmer::new(self.answers));
        let no_os_proxy = SystemProxySource::with_reader(Box::new(OsProxy::default));
        let mut http = HttpFactory::new(
            Arc::new(no_os_proxy),
            credentials.clone(),
            Arc::new(DateBridge(port.clone())),
        );
        if let Some(t) = self.timeouts {
            http = http.with_timeouts(t);
        }
        let clock: Arc<FakeClock> = store.clock().clone();
        let deps = CoreDeps {
            audit: store.store(),
            clock,
            credentials: credentials.clone(),
            confirmer: confirmer.clone(),
            ui: ui.clone(),
            config,
            config_path: Some(config_path),
            http,
            app_start_extra: Map::new(),
            pats_deleted: Vec::new(),
        };
        let hooks = TestHooks {
            limits: self.limits,
            allow_http: !self.strict_https,
            ..self.hooks
        };
        let core = Core::start_with_port(deps, port.clone(), hooks.clone()).await?;
        let handler = CapturingHandler::wrap(core.handler(), capture.clone());
        let decisions = CapturingDecisions::wrap(core.decisions(), capture.clone());
        let instances_api = CapturingInstances::wrap(core.instances(), capture.clone());
        let h = Harness {
            core,
            handler,
            decisions,
            instances_api,
            ui,
            capture,
            confirmer,
            credentials,
            plan: self.plan,
            port,
            instances,
            next_conn: AtomicU64::new(0),
            default_conn: ConnectionMeta {
                connection_id: String::new(),
                peer: PeerInfo::default(),
            },
            hooks,
            timeouts: self.timeouts,
            _config_dir: config_dir,
            store,
        };
        let default_conn = h.conn(HARNESS_AGENT).await?;
        Ok(Harness { default_conn, ..h })
    }
}

/// The confirmed origin, proxy and CA fingerprint of every instance, as a user's confirmations
/// would have left them in the audit settings (I-31); `config.toml` then agrees with them.
fn seed_settings(
    store: &TempStore,
    instances: &[HarnessInstance],
    ids: &[String],
    strict_https: bool,
) -> Result<(), TestError> {
    let confirmed = Confirmed {
        dialog_text_sha256: Sha256::digest(b"harness seed").into(),
    };
    let audit = store.store();
    for (i, id) in instances.iter().zip(ids) {
        // An instance at an `http://` URL under `strict_https` is the test's subject: its origin
        // is not confirmed, so nothing about it is seeded.
        let Ok(origin) = normalize_base_url(&i.base_url) else {
            continue;
        };
        if strict_https && origin.as_str().starts_with("http://") {
            continue;
        }
        audit.apply_setting(
            SettingChange::InstanceOrigin {
                instance_id: id.clone(),
                origin: Some(origin.as_str()),
            },
            Some(confirmed),
        )?;
        if i.proxy.is_some() {
            audit.apply_setting(
                SettingChange::InstanceProxy {
                    instance_id: id.clone(),
                    proxy: i.proxy.clone(),
                },
                None,
            )?;
        }
        if let Some(path) = &i.ca_bundle
            && let Some(fp) = ca_fingerprint(&std::fs::read(path)?)
        {
            audit.apply_setting(
                SettingChange::InstanceCaFingerprint {
                    instance_id: id.clone(),
                    fingerprint: Some(fp),
                },
                Some(confirmed),
            )?;
        }
    }
    Ok(())
}

fn config_toml(instances: &[HarnessInstance], with_ids: bool) -> String {
    let mut s = String::from("schema_version = 1\n");
    for i in instances {
        let id = if with_ids {
            format!("id = \"{}\"\n", i.id)
        } else {
            String::new()
        };
        let _ = write!(
            s,
            "\n[[instances]]\n{}alias = \"{}\"\nproduct = \"{}\"\nbase_url = \"{}\"\ndefault = {}\n",
            id,
            i.alias,
            product_str(i.product),
            i.base_url,
            i.is_default
        );
        if let Some(p) = &i.proxy {
            let _ = writeln!(s, "proxy = \"{p}\"");
        }
        if let Some(path) = &i.ca_bundle {
            // A TOML literal string: Windows paths carry backslashes.
            let _ = writeln!(s, "ca_bundle = '{}'", path.display());
        }
    }
    s
}

/// Drops every notification.
pub struct NoProgress;

impl ProgressSink for NoProgress {
    fn progress(&self, _n: ProgressNotification) {}
}

pub struct Harness {
    core: Core,
    handler: Arc<CapturingHandler>,
    decisions: Arc<CapturingDecisions>,
    instances_api: Arc<CapturingInstances>,
    ui: Arc<CapturingUi>,
    capture: Arc<Capture>,
    confirmer: Arc<StubConfirmer>,
    credentials: Arc<InMemoryCredentials>,
    plan: Arc<FaultPlan>,
    port: Arc<dyn AuditPort>,
    instances: Vec<HarnessInstance>,
    next_conn: AtomicU64,
    default_conn: ConnectionMeta,
    hooks: TestHooks,
    timeouts: Option<Timeouts>,
    _config_dir: TempDir,
    /// Last: the core lets go of the store before the temp dir goes.
    store: TempStore,
}

impl Harness {
    pub fn builder() -> HarnessBuilder {
        HarnessBuilder {
            instances: Vec::new(),
            plan: FaultPlan::new(),
            pat: TEST_PAT.to_owned(),
            answers: Vec::new(),
            config_text: None,
            extra_config: String::new(),
            omit_ids: false,
            limits: None,
            hooks: TestHooks::none(),
            timeouts: None,
            strict_https: false,
            seed_origins: true,
        }
    }

    /// One Jira instance `jira-main`.
    pub async fn jira() -> Result<Harness, TestError> {
        Harness::builder().jira("jira-main").start().await
    }

    /// One Confluence instance `wiki`.
    pub async fn confluence() -> Result<Harness, TestError> {
        Harness::builder().confluence("wiki").start().await
    }

    /// `jira-main` and `wiki`.
    pub async fn both() -> Result<Harness, TestError> {
        Harness::builder()
            .jira("jira-main")
            .confluence("wiki")
            .start()
            .await
    }

    pub fn core(&self) -> &Core {
        &self.core
    }

    /// The `config.toml` the core was started from.
    pub fn config_path(&self) -> std::path::PathBuf {
        self._config_dir.path().join(CONFIG_FILE_NAME)
    }

    /// Starts a new `Core` over the same store, keychain, config file and mocks (a restart of the
    /// app): `config.toml` is read again, the instance table derived again. The old core's
    /// pending requests are not carried over.
    pub async fn restart(&mut self) -> Result<(), TestError> {
        let config = load_config(&self.config_path())?;
        let no_os_proxy = SystemProxySource::with_reader(Box::new(OsProxy::default));
        let mut http = HttpFactory::new(
            Arc::new(no_os_proxy),
            self.credentials.clone(),
            Arc::new(DateBridge(self.port.clone())),
        );
        if let Some(t) = self.timeouts {
            http = http.with_timeouts(t);
        }
        let deps = CoreDeps {
            audit: self.store.store(),
            clock: self.store.clock().clone(),
            credentials: self.credentials.clone(),
            confirmer: self.confirmer.clone(),
            ui: self.ui.clone(),
            config,
            config_path: Some(self.config_path()),
            http,
            app_start_extra: Map::new(),
            pats_deleted: Vec::new(),
        };
        let core = Core::start_with_port(deps, self.port.clone(), self.hooks.clone()).await?;
        self.handler = CapturingHandler::wrap(core.handler(), self.capture.clone());
        self.decisions = CapturingDecisions::wrap(core.decisions(), self.capture.clone());
        self.instances_api = CapturingInstances::wrap(core.instances(), self.capture.clone());
        self.core = core;
        self.default_conn = self.conn(HARNESS_AGENT).await?;
        Ok(())
    }

    /// The payloads of every record of type `t` from the last 24 h, in seq order, whatever
    /// request (or none) they belong to.
    pub async fn events_of(&self, t: EventType) -> Result<Vec<Value>, TestError> {
        let port = self.port.clone();
        let out = tokio::task::spawn_blocking(move || {
            let headers = port.recent_headers(Duration::from_secs(24 * 3600))?;
            Ok::<_, atlas_duck_audit::AuditError>(
                headers
                    .iter()
                    .filter(|h| h.event_type == t)
                    .map(|h| payload_json(&*port, h.seq).unwrap_or(Value::Null))
                    .collect::<Vec<_>>(),
            )
        })
        .await??;
        Ok(out)
    }

    pub fn engine(&self) -> &Arc<Engine> {
        self.core.engine()
    }

    /// The capturing handler.
    pub fn handler(&self) -> Arc<dyn RequestHandler> {
        self.handler.clone()
    }

    /// The capturing decision API.
    pub fn decisions(&self) -> Arc<dyn DecisionApi> {
        self.decisions.clone()
    }

    /// The capturing instance admin.
    pub fn instances(&self) -> Arc<dyn InstanceAdmin> {
        self.instances_api.clone()
    }

    /// The capturing `UiSink` the core emits into.
    pub fn ui(&self) -> Arc<dyn UiSink> {
        self.ui.clone()
    }

    pub fn capture(&self) -> &Arc<Capture> {
        &self.capture
    }

    pub fn confirmer(&self) -> &Arc<StubConfirmer> {
        &self.confirmer
    }

    /// A scripted approver over the capturing decision API.
    pub fn approver(&self) -> ScriptedApprover {
        ScriptedApprover::new(self.decisions())
    }

    /// Waits until `request_id` is in the queue (its read fetched); `None` after `ms`.
    pub async fn queued(&self, request_id: &str, ms: u64) -> Option<QueueItem> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
        loop {
            if let Some(item) = self.decisions.queue_get(request_id) {
                return Some(item);
            }
            if tokio::time::Instant::now() > deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Waits until `request_id` is no longer pending in memory (terminal); `false` after `ms`.
    pub async fn settled(&self, request_id: &str, ms: u64) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
        loop {
            let open = self
                .core
                .engine()
                .entry(request_id)
                .is_some_and(|e| e.state().unlogged_terminal.is_none());
            if !open {
                return true;
            }
            if tokio::time::Instant::now() > deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub fn credentials(&self) -> &Arc<InMemoryCredentials> {
        &self.credentials
    }

    /// The fault plan of the core's audit port.
    pub fn plan(&self) -> &Arc<FaultPlan> {
        &self.plan
    }

    pub fn clock(&self) -> &Arc<FakeClock> {
        self.store.clock()
    }

    /// The real store (bypasses the fault plan).
    pub fn store(&self) -> Store {
        self.store.store()
    }

    /// The core's audit port (the `FaultyAudit` over the store; the plan applies).
    pub fn port(&self) -> Arc<dyn AuditPort> {
        self.port.clone()
    }

    pub fn instance(&self, alias: &str) -> Option<&HarnessInstance> {
        self.instances.iter().find(|i| i.alias == alias)
    }

    pub fn mock(&self, alias: &str) -> Option<&MockDc> {
        self.instance(alias).map(|i| &i.mock)
    }

    /// The default connection (agent `test-agent`, hello done).
    pub fn default_conn(&self) -> &ConnectionMeta {
        &self.default_conn
    }

    /// A new connection whose `hello` (CLI, `agent_name` via flag) has been answered.
    pub async fn conn(&self, agent: &str) -> Result<ConnectionMeta, TestError> {
        let n = self.next_conn.fetch_add(1, Ordering::SeqCst);
        let conn = ConnectionMeta {
            connection_id: format!("conn-{n}"),
            peer: PeerInfo::default(),
        };
        let hello = Hello {
            build_id: BUILD_ID.to_owned(),
            client_kind: ClientKind::Cli,
            agent_name: Some(agent.to_owned()),
            agent_name_source: AgentNameSource::Flag,
            cwd_basename: HARNESS_CWD.to_owned(),
        };
        self.handler
            .hello(&conn, hello)
            .await
            .map_err(|e| format!("hello refused: {}", e.to_json_line()))?;
        Ok(conn)
    }

    /// `submit` on the default connection, default instance, no reason.
    pub async fn submit(&self, op_id: &str, params: Value) -> Envelope {
        self.submit_with(&self.default_conn, op_id, params, None)
            .await
    }

    pub async fn submit_with(
        &self,
        conn: &ConnectionMeta,
        op_id: &str,
        params: Value,
        instance: Option<&str>,
    ) -> Envelope {
        self.handler
            .submit(
                conn,
                SubmitParams {
                    op_id: op_id.to_owned(),
                    params,
                    instance: instance.map(str::to_owned),
                    reason: None,
                },
            )
            .await
    }

    pub async fn status(&self, request_id: &str) -> Envelope {
        self.handler.status(request_id).await
    }

    /// `await` with a bound in ms on the default connection.
    pub async fn await_(&self, request_id: &str, ms: u64) -> Envelope {
        self.handler
            .await_request(
                &self.default_conn,
                AwaitParams {
                    request_id: request_id.to_owned(),
                    timeout_ms: Some(ms),
                },
                &NoProgress,
            )
            .await
    }

    /// Every record of `request_id` in seq order, payloads decrypted (never `Debug`-formatted).
    pub async fn events(&self, request_id: &str) -> Result<Vec<(EventType, Value)>, TestError> {
        let port = self.port.clone();
        let id = request_id.to_owned();
        let out = tokio::task::spawn_blocking(move || {
            let headers = port.headers_for_request(&id)?;
            Ok::<_, atlas_duck_audit::AuditError>(
                headers
                    .iter()
                    .map(|h| {
                        (
                            h.event_type,
                            payload_json(&*port, h.seq).unwrap_or(Value::Null),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .await??;
        Ok(out)
    }

    /// The event types of `request_id`, in order.
    pub async fn event_types(&self, request_id: &str) -> Result<Vec<EventType>, TestError> {
        Ok(self
            .events(request_id)
            .await?
            .into_iter()
            .map(|(t, _)| t)
            .collect())
    }

    /// How many records the store holds from the last 24 h (any request, system ones too).
    pub async fn event_count(&self) -> Result<usize, TestError> {
        let port = self.port.clone();
        let n = tokio::task::spawn_blocking(move || {
            port.recent_headers(Duration::from_secs(24 * 3600))
                .map(|h| h.len())
        })
        .await??;
        Ok(n)
    }

    /// PD-14: runs the expiry path now; `false` if the request is not pending.
    pub async fn expire_now(&self, request_id: &str) -> bool {
        self.core.engine().expire_now(request_id).await
    }

    /// Free bytes the store's low-space admission check sees (§8.1; `set(0)` → `StorageLow`).
    pub fn free_space(&self) -> &Arc<FreeSpaceStub> {
        self.store.free_space()
    }

    /// Drops the request's cached candidate: the next use rebuilds it from the log (§5.2).
    pub fn evict_candidate(&self, request_id: &str) {
        self.core.engine().candidates().remove(request_id);
    }

    /// Flips the current revision's candidate hash and evicts the candidate, so the next rebuild
    /// mismatches (I-37); `false` if the request is not in memory.
    pub fn corrupt_candidate_hash(&self, request_id: &str) -> bool {
        let Some(entry) = self.core.engine().entry(request_id) else {
            return false;
        };
        for b in entry.state().candidate_hash.iter_mut() {
            *b = !*b;
        }
        self.evict_candidate(request_id);
        true
    }
}
