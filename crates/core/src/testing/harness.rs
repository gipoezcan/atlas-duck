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
    ProgressNotification, ProgressSink, RequestHandler, SubmitParams, SubmitReply,
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
use crate::core::{Confirm, Core, CoreDeps, HookPoint, TestHooks};
use crate::decision::{DecisionApi, QueueItem};
use crate::engine::Engine;
use crate::engine::payload_json;
use crate::engine::queue::Limits;
use crate::engine::script::ScriptRunner;
use crate::gate::UiSink;
use crate::http_factory::HttpFactory;
use crate::ids::InstanceId;
use crate::instances::state::ca_fingerprint;
use crate::instances::{AddInstance, AdminError, ConnectionReport, InstanceAdmin, InstanceView};
use crate::proxy::{OsProxy, ProxySetting, SystemProxySource};

/// The agent name of the harness's default connection.
pub const HARNESS_AGENT: &str = "test-agent";
/// The `cwd_basename` every harness connection reports.
pub const HARNESS_CWD: &str = "workdir";
/// What every harness Jira mock answers the first `GET /rest/api/2/field` with (the start fill of
/// the field-name cache, PD-46); later fills get what the test mounts (404 otherwise).
pub const JIRA_FIELDS: &str = r#"[{"id":"summary","name":"Summary","custom":false,"schema":{"type":"string","system":"summary"}},{"id":"customfield_10100","name":"Story Points","custom":true,"schema":{"type":"number","custom":"com.atlassian.jira.plugin.system.customfieldtypes:float","customId":10100}}]"#;
/// The alias of the instance `HarnessBuilder::live` configures.
pub const LIVE_ALIAS: &str = "jira-live";
/// The alias of the instance `HarnessBuilder::live_confluence` configures.
pub const LIVE_CONFLUENCE_ALIAS: &str = "confluence-live";
/// How long the harness waits for field-name cache fills it started (start, token set).
const FIELD_CACHE_WAIT: Duration = Duration::from_secs(10);

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
    store_faults: Option<Arc<atlas_duck_audit::testing::Faults>>,
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
    scripts: Option<Arc<dyn ScriptRunner>>,
    pats_deleted: Vec<String>,
    app_start_extra: Map<String, Value>,
    live: LiveState,
    /// The alias of the live instance (`LIVE_ALIAS` unless `live_confluence` set it).
    live_alias: &'static str,
}

/// Where `HarnessBuilder::live` stands: not asked for, set up, or refused (not https).
#[derive(Clone, Copy, PartialEq, Eq)]
enum LiveState {
    Off,
    On,
    Refused,
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

    /// A real Jira Data Center instance at `url` instead of a mock (L-01 live tests, never run by
    /// agents or CI): https only, the origin confirmed as a user would have, the PAT stored through
    /// the instance admin's token set (so the identity it keeps is the one the server reports),
    /// and `strict_https` on so no release lock is weakened. A `url` that is not `https://` makes
    /// `start` fail. The PAT is never printed or written to the config.
    pub fn live(self, url: &str, pat: &str) -> Self {
        self.live_instance(LIVE_ALIAS, Product::Jira, url, pat)
    }

    /// `live` for a real Confluence Data Center instance (alias `LIVE_CONFLUENCE_ALIAS`, M7 T25).
    pub fn live_confluence(self, url: &str, pat: &str) -> Self {
        self.live_instance(LIVE_CONFLUENCE_ALIAS, Product::Confluence, url, pat)
    }

    fn live_instance(
        mut self,
        alias: &'static str,
        product: Product,
        url: &str,
        pat: &str,
    ) -> Self {
        if !url.to_ascii_lowercase().starts_with("https://") {
            self.live = LiveState::Refused;
            return self;
        }
        self.live = LiveState::On;
        self.live_alias = alias;
        self.strict_https = true;
        self.pat = pat.to_owned();
        self.instance_at(
            alias,
            product,
            InstanceAt {
                base_url: url.to_owned(),
                ..InstanceAt::default()
            },
        )
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

    /// The store's own fault points (`Faults::pause_writer` etc.), kept over `reopen`.
    pub fn store_faults(mut self, faults: Arc<atlas_duck_audit::testing::Faults>) -> Self {
        self.store_faults = Some(faults);
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

    /// The script runner of the core (`FakeScriptRunner`); without one, scripts answer
    /// `sandbox_unavailable`.
    pub fn scripts(mut self, runner: Arc<dyn ScriptRunner>) -> Self {
        self.scripts = Some(runner);
        self
    }

    /// `CoreDeps.pats_deleted` of the first start (a restore or recovery deleted these PATs).
    pub fn pats_deleted(mut self, ids: Vec<String>) -> Self {
        self.pats_deleted = ids;
        self
    }

    /// `CoreDeps.app_start_extra` of the first start (PD-21).
    pub fn app_start_extra(mut self, extra: Map<String, Value>) -> Self {
        self.app_start_extra = extra;
        self
    }

    pub async fn start(self) -> Result<Harness, TestError> {
        if self.live == LiveState::Refused {
            return Err("a live instance needs an https:// url".into());
        }
        let live = self.live == LiveState::On;
        let store = match self.store_faults.clone() {
            Some(f) => TempStore::with_faults(f)?,
            None => TempStore::new()?,
        };
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
            match spec.product {
                Product::Jira => mock.json_once("/rest/api/2/field", 200, JIRA_FIELDS).await,
                // RF-5a (PD-93): every Confluence read ends with an identity GET; a test mounts
                // its own answer to change it.
                Product::Confluence => {
                    mock.confluence_user_current_default(TEST_USER, TEST_USER_KEY)
                        .await;
                }
            }
            let id = InstanceId::new()?.0;
            let (base_url, bound) = match &spec.at {
                Some(at) => (
                    at.base_url.clone(),
                    url_hash(&normalize_base_url(&at.base_url).map_err(|e| format!("{e:?}"))?),
                ),
                None => (mock.base_url(), url_hash(&mock.base())),
            };
            // The live instance gets the token and the identity the server's own answer names.
            if !(live && spec.alias == self.live_alias) {
                credentials.put(&id, &self.pat, bound, TEST_USER, TEST_USER_KEY);
            }
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

        let faulty = Arc::new(FaultyAudit::wrap(store.port(), self.plan.clone()));
        let port: Arc<dyn AuditPort> = faulty.clone();
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
            app_start_extra: self.app_start_extra,
            pats_deleted: self.pats_deleted,
            scripts: self.scripts.clone(),
        };
        // Raw servers answer scripted connections in order: no background fill may take one.
        let at_raw = self
            .instances
            .iter()
            .any(|i| i.at.is_some() && !(live && i.alias == self.live_alias));
        let hooks = TestHooks {
            limits: self.limits,
            allow_http: !self.strict_https,
            no_field_cache: self.hooks.no_field_cache || at_raw,
            ..self.hooks
        };
        // `freeze_at` is armed on the plan: the crash point lives in the port layer.
        if let Some(HookPoint::AfterAppend(t)) = hooks.freeze_at {
            self.plan.freeze_after(t);
        }
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
            faulty,
            port,
            instances,
            next_conn: AtomicU64::new(0),
            default_conn: ConnectionMeta {
                connection_id: String::new(),
                peer: PeerInfo::default(),
            },
            hooks,
            timeouts: self.timeouts,
            scripts: self.scripts,
            _config_dir: config_dir,
            store,
        };
        let default_conn = h.conn(HARNESS_AGENT).await?;
        let h = Harness { default_conn, ..h };
        if live {
            h.instances()
                .set_token(self.live_alias, secrecy::SecretString::from(self.pat), None)
                .await
                .map_err(|e| format!("live token set failed: {e:?}"))?;
        }
        // The start fills end before the test runs, so their records and hits come first. A
        // fill held by the test's own fault plan just runs out the wait.
        h.field_cache_filled().await;
        Ok(h)
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

/// One committed record with its payload decrypted (`Harness::audit_records`).
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub seq: u64,
    pub event_type: EventType,
    pub request_id: Option<String>,
    pub op_id: Option<String>,
    pub payload: Value,
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
    /// The wrapper behind `port` (`crash_and_restart` kills it).
    faulty: Arc<FaultyAudit>,
    port: Arc<dyn AuditPort>,
    instances: Vec<HarnessInstance>,
    next_conn: AtomicU64,
    default_conn: ConnectionMeta,
    hooks: TestHooks,
    timeouts: Option<Timeouts>,
    scripts: Option<Arc<dyn ScriptRunner>>,
    _config_dir: TempDir,
    /// Last: the core lets go of the store before the temp dir goes.
    store: TempStore,
}

impl Harness {
    pub fn builder() -> HarnessBuilder {
        HarnessBuilder {
            instances: Vec::new(),
            plan: FaultPlan::new(),
            store_faults: None,
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
            scripts: None,
            pats_deleted: Vec::new(),
            app_start_extra: Map::new(),
            live: LiveState::Off,
            live_alias: LIVE_ALIAS,
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
            scripts: self.scripts.clone(),
        };
        let core = Core::start_with_port(deps, self.port.clone(), self.hooks.clone()).await?;
        self.handler = CapturingHandler::wrap(core.handler(), self.capture.clone());
        self.decisions = CapturingDecisions::wrap(core.decisions(), self.capture.clone());
        self.instances_api = CapturingInstances::wrap(core.instances(), self.capture.clone());
        self.core = core;
        self.default_conn = self.conn(HARNESS_AGENT).await?;
        self.field_cache_filled().await;
        Ok(())
    }

    /// A crash and a restart (Task 28): the old `Core` is dropped without `shutdown` and its
    /// store wrapper stays as it is (a core that tripped a `FaultPlan::freeze_after` point is
    /// dead for writes for good); a fresh wrapper over the same store, config file, keychain and
    /// mocks serves the new `Core`, which reconciles the log like a real start (§11.3). The test
    /// hooks `freeze_at` and `panic_on_jql` are not carried over.
    pub async fn crash_and_restart(&mut self) -> Result<(), TestError> {
        self.hooks.freeze_at = None;
        self.hooks.panic_on_jql = None;
        // The dead process writes nothing more: its tasks (a stalled read, a write in flight)
        // may still run, but every append of theirs now fails.
        self.faulty.kill();
        self.faulty = Arc::new(FaultyAudit::wrap(self.store.port(), self.plan.clone()));
        self.port = self.faulty.clone();
        self.restart().await
    }

    /// `crash_and_restart` through a real store reopen (M3 final review I-2): the old wrapper
    /// is killed, the store is shut down and opened again by the real startup (`audit::open`,
    /// so its startup `VERIFY` and anchor checks run), and a new `Core` starts over it.
    pub async fn reopen_and_restart(&mut self) -> Result<(), TestError> {
        self.hooks.freeze_at = None;
        self.hooks.panic_on_jql = None;
        self.faulty.kill();
        self.store.reopen()?;
        self.faulty = Arc::new(FaultyAudit::wrap(self.store.port(), self.plan.clone()));
        self.port = self.faulty.clone();
        self.restart().await
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

    /// The engine's committed set (`Engine::committed` is crate-private, T20 review m3).
    pub fn committed(&self) -> &Arc<crate::audit_port::CommittedSet> {
        self.engine().committed()
    }

    /// The capturing handler.
    pub fn handler(&self) -> Arc<dyn RequestHandler> {
        self.handler.clone()
    }

    /// The capturing decision API.
    pub fn decisions(&self) -> Arc<dyn DecisionApi> {
        self.decisions.clone()
    }

    /// The capturing instance admin. A token set or re-test returns once the field-name cache
    /// fill it started in the background has ended (bounded), so tests see its records first.
    pub fn instances(&self) -> Arc<dyn InstanceAdmin> {
        Arc::new(SettlingInstances {
            inner: self.instances_api.clone(),
            engine: self.engine().clone(),
        })
    }

    /// Waits until no field-name cache fill is running (PD-46); `false` after 10 s.
    pub async fn field_cache_filled(&self) -> bool {
        self.field_cache_filled_within(FIELD_CACHE_WAIT).await
    }

    /// [`Harness::field_cache_filled`] with the bound given.
    pub async fn field_cache_filled_within(&self, bound: Duration) -> bool {
        cache_idle(self.engine(), bound).await
    }

    /// The field names cached for `alias` now (PD-46).
    pub fn field_names(&self, alias: &str) -> Option<Arc<crate::metadata::FieldNames>> {
        let id = self.routed_id(alias)?;
        self.engine().field_cache().snapshot(&id)
    }

    /// Fills of `alias` that ended in `metadata_cache_failed`.
    pub fn field_cache_failures(&self, alias: &str) -> u64 {
        self.routed_id(alias)
            .map_or(0, |id| self.engine().field_cache().failures(&id))
    }

    /// The server version cached for `alias` (the last connection test's; `None` = unknown).
    pub fn instance_version(&self, alias: &str) -> Option<atlas_duck_registry::Version> {
        self.engine()
            .instances()
            .by_alias(alias)
            .and_then(|i| i.version)
    }

    /// Test seam: caches `version` for `alias` as a connection test would. The test itself
    /// refuses a server below the floor (8.14), so a version below an op's `min_version` (8.4
    /// for the createmeta reads) cannot be reached any other way.
    pub fn set_instance_version(&self, alias: &str, version: atlas_duck_registry::Version) -> bool {
        let Some(id) = self.routed_id(alias) else {
            return false;
        };
        self.engine()
            .update_instance(&id, |rt| rt.version = Some(version));
        true
    }

    /// I-37 seam (PD-99): caches `username` for user `key` of `alias` (`None`: "no such user"),
    /// as a lookup answered now would. `false`: no such instance.
    pub fn user_cache_set(&self, alias: &str, key: &str, username: Option<&str>) -> bool {
        let Some(id) = self.routed_id(alias) else {
            return false;
        };
        let now = self.engine().clock().now_utc();
        let cache = self.engine().user_cache();
        cache.put(
            &id,
            cache.generation(&id),
            key,
            username.map(str::to_owned),
            now,
        );
        true
    }

    /// What the user cache of `alias` holds for `key` now (PD-99): `None` when nothing usable is
    /// cached, `Some(None)` for a cached "no such user".
    pub fn user_cached(&self, alias: &str, key: &str) -> Option<Option<String>> {
        let id = self.routed_id(alias)?;
        let now = self.engine().clock().now_utc();
        self.engine().user_cache().get(&id, key, now)
    }

    /// The id the core routes `alias` to.
    fn routed_id(&self, alias: &str) -> Option<String> {
        self.engine()
            .instances()
            .by_alias(alias)
            .and_then(|i| i.id.clone())
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
    /// The store's data directory (the files the audit log lives in).
    pub fn data_dir(&self) -> &std::path::Path {
        self.store.data_dir()
    }

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
        self.conn_with_peer(agent, PeerInfo::default()).await
    }

    /// [`Harness::conn`] with the OS facts of the peer `peer`.
    pub async fn conn_with_peer(
        &self,
        agent: &str,
        peer: PeerInfo,
    ) -> Result<ConnectionMeta, TestError> {
        let n = self.next_conn.fetch_add(1, Ordering::SeqCst);
        let conn = ConnectionMeta {
            connection_id: format!("conn-{n}"),
            peer,
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
        self.submit_reply_with(conn, op_id, params, instance)
            .await
            .envelope
    }

    /// `submit` on the default connection, with the `params_sha256` of the reply.
    pub async fn submit_reply(&self, op_id: &str, params: Value) -> SubmitReply {
        self.submit_reply_with(&self.default_conn, op_id, params, None)
            .await
    }

    pub async fn submit_reply_with(
        &self,
        conn: &ConnectionMeta,
        op_id: &str,
        params: Value,
        instance: Option<&str>,
    ) -> SubmitReply {
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

    /// `submit_script` on the default connection: `{source, args?, limits?, dry_run?}`.
    pub async fn submit_script(&self, params: Value) -> Envelope {
        self.submit_script_with(&self.default_conn, params).await
    }

    pub async fn submit_script_with(&self, conn: &ConnectionMeta, params: Value) -> Envelope {
        self.handler
            .submit_script(
                conn,
                SubmitParams {
                    op_id: "script.run".to_owned(),
                    params,
                    instance: None,
                    reason: None,
                },
            )
            .await
            .envelope
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

    /// Every record of the last 24 h in seq order, payloads decrypted (the property sweeps of
    /// Task 29 read the whole log, system records included).
    pub async fn audit_records(&self) -> Result<Vec<AuditRecord>, TestError> {
        let port = self.port.clone();
        let out = tokio::task::spawn_blocking(move || {
            let mut headers = port.recent_headers(Duration::from_secs(24 * 3600))?;
            headers.sort_by_key(|h| h.seq);
            Ok::<_, atlas_duck_audit::AuditError>(
                headers
                    .iter()
                    .map(|h| AuditRecord {
                        seq: h.seq,
                        event_type: h.event_type,
                        request_id: h.request_id.clone(),
                        op_id: h.op_id.clone(),
                        payload: payload_json(&*port, h.seq).unwrap_or(Value::Null),
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

/// Polls until no field-name cache fill runs; `false` once `bound` passed.
async fn cache_idle(engine: &Engine, bound: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        if engine.field_cache().idle() {
            return true;
        }
        if tokio::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The capturing instance admin whose token set and re-test return after the field-name cache
/// fill they started (PD-46) has ended, so the fill's records and hits never interleave with the
/// test's next step.
struct SettlingInstances {
    inner: Arc<CapturingInstances>,
    engine: Arc<Engine>,
}

#[async_trait::async_trait]
impl InstanceAdmin for SettlingInstances {
    fn list(&self) -> Vec<InstanceView> {
        self.inner.list()
    }
    fn check_add(&self, req: &AddInstance) -> Result<(), AdminError> {
        self.inner.check_add(req)
    }
    fn add(&self, req: AddInstance) -> Result<InstanceView, AdminError> {
        self.inner.add(req)
    }
    fn confirm_config_instance(&self, alias: &str) -> Result<InstanceView, AdminError> {
        self.inner.confirm_config_instance(alias)
    }
    fn accept_config_url_change(&self, alias: &str) -> Result<InstanceView, AdminError> {
        self.inner.accept_config_url_change(alias)
    }
    fn change_base_url(&self, alias: &str, new_url: &str) -> Result<InstanceView, AdminError> {
        self.inner.change_base_url(alias, new_url)
    }
    fn set_proxy(&self, alias: &str, proxy: ProxySetting) -> Result<InstanceView, AdminError> {
        self.inner.set_proxy(alias, proxy)
    }
    async fn set_token(
        &self,
        alias: &str,
        pat: secrecy::SecretString,
        expires_at: Option<chrono::NaiveDate>,
    ) -> Result<ConnectionReport, AdminError> {
        let r = self.inner.set_token(alias, pat, expires_at).await;
        cache_idle(&self.engine, FIELD_CACHE_WAIT).await;
        r
    }
    async fn retest_token(&self, alias: &str) -> Result<ConnectionReport, AdminError> {
        let r = self.inner.retest_token(alias).await;
        cache_idle(&self.engine, FIELD_CACHE_WAIT).await;
        r
    }
    async fn delete_token(&self, alias: &str) -> Result<InstanceView, AdminError> {
        self.inner.delete_token(alias).await
    }
}
