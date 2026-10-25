#![cfg(feature = "scripted-approver")]
//! M10 T29 (§13 canary sweep, S-16 Tauri half; §1.4 SC1/SC4, §10.2): every Tauri command response
//! and every event payload the app's test build records (`core::testing::capture`, the M6 Δ7 hook
//! `commands_acl.rs` `s16_tauri_capture_records_every_response_and_event` and `credential.rs`
//! use) over the canary path list, with the decisions made through the Approvals window's own
//! commands and the log read through the Audit window's.
//!
//! The rig is `credential.rs`'s serving world over Tauri's mock runtime (no OS window, no
//! webview): a store provisioned in the wizard's order (the run's canary recovery passphrase, the
//! file keystore), three Jira instances on canary `MockDc`s (the `cli_flows` harness's canary mode:
//! one canary PAT each), `serve::start_with`, requests submitted over the app's own IPC endpoint.
//!
//! Paths (Jira; the Confluence fixtures are D2): release, release-redacted, deny,
//! deny-with-details, deny-with-hint, expire, cancel, upstream-error, `upstream_unavailable`,
//! outcome-unknown on `jira-a`; stale (the stale check's identity answers without
//! `X-AUSERNAME`) on `jira-b`; recheck-failed (the re-check's `/myself` answers 503) on `jira-c`.
//!
//! Rules: a PAT canary (raw, base64, percent-encoded) and the passphrase canary are in no record
//! and no IPC envelope; the PATs reached the mocks only in `Authorization`; no event payload
//! carries a data canary; a command response carries a data canary only when the command is on
//! the [`DATA_VIEWS`] table (the windows that show Atlassian content to the human), and then only
//! a canary a decrypted audit payload holds (the window shows nothing the log does not).

mod common;
#[path = "cli_flows/harness.rs"]
mod harness;

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use atlas_duck_app_lib::commands;
use atlas_duck_app_lib::compose::{self, CoreInputs};
use atlas_duck_app_lib::secret_service::{SecretService, SecretServiceCheck};
use atlas_duck_app_lib::serve::{ServeHooks, ServeState, StartInputs, start_with};
use atlas_duck_app_lib::state::{DataDirHold, ServeSlot};
use atlas_duck_app_lib::testing::{FileKeysFactory, provision};
use atlas_duck_app_lib::ui_sink::{EventOut, TauriUiSink};
use atlas_duck_app_lib::windows::{NavPolicy, StartupRoute, WindowRegistry};
use atlas_duck_atlassian::testing::{MockDc, XAuser};
use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::{
    AuditCursor, AuditFilter, EventType, FirstRunInput, KeyStore, MAX_AUDIT_PAGE_ROWS, OpenConfig,
    SystemClock, create_new_store, new_ids,
};
use atlas_duck_core::proxy::ProxySetting;
use atlas_duck_core::testing::capture::{Channel, NullUi};
use atlas_duck_core::{AddInstance, Confirm, NativeConfirmer, ShutdownReason, UiEvent, UiSink};
use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::client::IpcClient;
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::paths::{DataDirResolution, EndpointLocation, LocalDataDir, check_data_dir};
use atlas_duck_ipc::proto::{AgentNameSource, ClientKind, Hello, SubmitParams, SubmitReply};
use atlas_duck_ipc::server::ShutdownSignal;
use atlas_duck_registry::Product;
use harness::{
    CANARY_ERR_404, CANARY_ERR_500, CANARY_OUTCOME_UNKNOWN, CANARY_UNAVAILABLE, Canaries,
    canary_issue, canary_jira, hits, secret_forms, test_install_id,
};
use secrecy::SecretString;
use serde_json::{Value, json};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{INVOKE_KEY, MockRuntime, get_ipc_response, mock_builder};
use tauri::webview::InvokeRequest;
use tauri::{App, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Boxed = Box<dyn std::error::Error>;

const HOST: &str = "thishost";
/// Every wait of this test is bounded by this.
const WAIT: Duration = Duration::from_secs(30);
const INSTANCES: [&str; 3] = ["jira-a", "jira-b", "jira-c"];
const COMMENT: &str = "jira.comment.add";
const ISSUE: &str = "jira.issue.get";

/// The commands whose responses may carry Atlassian content (§5.6, §6.4, §8.10: the Approvals
/// window's queue, preview and raw views, its recent list, and the Audit window's queries and
/// payload view show the human what was fetched and logged). Every other command response and
/// every event carries no data canary.
const DATA_VIEWS: [(&str, &str); 8] = [
    ("queue_list", "the queue rows' target display (§5.6)"),
    ("queue_get", "the Request tab and the target display (§5.6)"),
    (
        "preview_fetch",
        "the preview of the fetched candidate (§6.4)",
    ),
    ("raw_page", "the raw bytes of the candidate (PD-68)"),
    ("recent_list", "the recently decided rows (§5.6)"),
    ("audit_query", "the Audit window's rows (§8.10)"),
    (
        "audit_payload",
        "the Audit window's decrypted payload view (§8.10)",
    ),
    ("audit_trail", "the Audit window's request trail (§8.10)"),
];

// ---------- the mock app ----------

/// A scratch dir under cargo's per-target test dir (as `credential.rs`: the mock runtime keeps the
/// app, and with it `instance.lock`, alive for the rest of the process).
fn scratch() -> std::io::Result<tempfile::TempDir> {
    let root = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("canary_tauri");
    std::fs::create_dir_all(&root)?;
    tempfile::Builder::new().tempdir_in(&root)
}

fn app() -> Result<App<MockRuntime>, Boxed> {
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

/// Forwards core's UI events to the app's Tauri sink once the app exists (core starts first).
#[derive(Default)]
struct LateSink(OnceLock<Arc<dyn UiSink>>);

impl UiSink for LateSink {
    fn emit(&self, e: UiEvent) {
        if let Some(sink) = self.0.get() {
            sink.emit(e);
        }
    }
}

/// Every native confirmation is answered OK.
struct AlwaysOk;
impl NativeConfirmer for AlwaysOk {
    fn confirm(&self, _: &str) -> Confirm {
        Confirm::Ok
    }
}

struct NoSecretService;
impl SecretServiceCheck for NoSecretService {
    fn check(&self) -> Option<SecretService> {
        None
    }
}

#[cfg(unix)]
fn location(_data: &LocalDataDir) -> Result<(EndpointLocation, Option<tempfile::TempDir>), Boxed> {
    let base = common::short_socket_base()?;
    Ok((common::socket_location(base.path())?, Some(base)))
}

#[cfg(windows)]
fn location(data: &LocalDataDir) -> Result<(EndpointLocation, Option<tempfile::TempDir>), Boxed> {
    Ok((atlas_duck_ipc::paths::endpoint_location(data, HOST)?, None))
}

#[cfg(unix)]
fn same_user() -> Result<atlas_duck_ipc::transport::unix::SameUser, Boxed> {
    Ok(atlas_duck_ipc::transport::unix::SameUser)
}

#[cfg(windows)]
fn same_user() -> Result<atlas_duck_ipc::transport::windows::SameUser, Boxed> {
    Ok(atlas_duck_ipc::transport::windows::SameUser::current()?)
}

/// The serving world. Fields drop in declaration order: `tmp` last (it holds `instance.lock`).
struct World {
    canaries: Arc<Canaries>,
    mocks: Vec<(String, MockDc)>,
    state: Arc<ServeState>,
    data: LocalDataDir,
    location: EndpointLocation,
    _lock: Arc<InstanceLock>,
    _sock: Option<tempfile::TempDir>,
    _tmp: tempfile::TempDir,
}

impl World {
    /// Provisions the store (canary passphrase), the three canary instances (canary PATs), then
    /// serves it with `ui` as the UI sink.
    async fn start(ui: Arc<dyn UiSink>) -> Result<World, Boxed> {
        let canaries = Canaries::new()?;
        let tmp = scratch()?;
        let dir = tmp.path().join("data");
        std::fs::create_dir(&dir)?;
        let data = match check_data_dir(&dir)? {
            DataDirResolution::Local(d) => d,
            _ => return Err("the scratch dir is not a local data dir".into()),
        };
        let lock = Arc::new(InstanceLock::acquire(&data, HOST)?);
        let config = tmp.path().join("config");
        let keys_dir = tmp.path().join("keys");
        std::fs::create_dir(&config)?;
        let (_, chain_hex) = new_ids()?;
        let install_id = test_install_id(&chain_hex).ok_or("short random id")?;
        let (_, chain_id) = new_ids()?;
        let keys: Arc<dyn KeyStore> = Arc::new(provision(&keys_dir, &install_id)?);
        let pass = canaries.passphrase();
        let store = create_new_store(
            &data,
            &lock,
            OpenConfig::new(Arc::new(SystemClock::new()), keys.clone()),
            FirstRunInput {
                install_id: install_id.clone(),
                chain_id,
                passphrase: SecretString::from(pass.clone()),
                passphrase_confirm: SecretString::from(pass),
                archived_db: None,
                anchor_dir: None,
                archive_confirmed: None,
            },
        )
        .map_err(|e| format!("{e:?}"))?;
        let core = compose::start_core(CoreInputs {
            store: store.clone(),
            keys,
            config_dir: config.clone(),
            pats_deleted: Vec::new(),
            ui: Arc::new(NullUi),
            confirmer: Arc::new(AlwaysOk),
            tray_host: None,
            scripts: Default::default(),
        })
        .await?;
        let mut mocks = Vec::new();
        let added = async {
            for (i, alias) in INSTANCES.iter().enumerate() {
                let mock = canary_jira(&canaries).await;
                core.instances()
                    .add(AddInstance {
                        alias: (*alias).to_owned(),
                        product: Product::Jira,
                        base_url: mock.base_url(),
                        proxy: ProxySetting::Direct,
                        ca_pem: None,
                        is_default: i == 0,
                    })
                    .map_err(|e| format!("add {alias}: {e:?}"))?;
                core.instances()
                    .set_token(alias, SecretString::from(canaries.pat(alias)), None)
                    .await
                    .map_err(|e| format!("set_token {alias}: {e:?}"))?;
                mocks.push(((*alias).to_owned(), mock));
            }
            Ok::<(), Boxed>(())
        }
        .await;
        core.shutdown(ShutdownReason::Quit).await;
        drop(core);
        store.shutdown();
        added?;

        let (location, sock) = location(&data)?;
        let state = start_with(StartInputs {
            data: data.clone(),
            lock: lock.clone(),
            host: HOST.to_owned(),
            install_id: Some(install_id),
            config_dir: config,
            keys: Arc::new(FileKeysFactory::new(keys_dir)),
            ui,
            confirmer: Arc::new(AlwaysOk),
            tray_host: None,
            secret_service: Arc::new(NoSecretService),
            retry_schedule: vec![],
            endpoint: Some(location.clone()),
            quit: ShutdownSignal::new(),
            hooks: ServeHooks::default(),
        })
        .await
        .map_err(|e| format!("{e:?}"))?;
        if state.core.get().is_none() {
            return Err("the serving state has no core".into());
        }
        Ok(World {
            canaries,
            mocks,
            state,
            data,
            location,
            _lock: lock,
            _sock: sock,
            _tmp: tmp,
        })
    }

    fn mock(&self, alias: &str) -> Result<&MockDc, Boxed> {
        self.mocks
            .iter()
            .find(|(a, _)| a == alias)
            .map(|(_, m)| m)
            .ok_or_else(|| format!("no mock {alias}").into())
    }

    fn core(&self) -> Result<Arc<atlas_duck_core::Core>, Boxed> {
        self.state
            .core
            .get()
            .cloned()
            .ok_or_else(|| "no core".into())
    }

    /// The mock app serving this world, with the data dir held.
    fn app(&self) -> Result<App<MockRuntime>, Boxed> {
        let app = app()?;
        app.manage(DataDirHold::new(self.data.clone(), self._lock.clone()));
        let slot = ServeSlot::default();
        slot.set(self.state.clone());
        app.manage(slot);
        Ok(app)
    }

    async fn connect(&self) -> Result<IpcClient, Boxed> {
        let hello = Hello {
            build_id: BUILD_ID.to_owned(),
            client_kind: ClientKind::Cli,
            agent_name: Some("t29-canary".into()),
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

    /// Every decrypted audit payload of the serving store, as text.
    fn audit_payloads(&self) -> Result<Vec<(EventType, String)>, Boxed> {
        let store = self.state.open_store().ok_or("no store")?;
        let mut out = Vec::new();
        let mut cursor = AuditCursor::first(MAX_AUDIT_PAGE_ROWS);
        loop {
            let page = store.query(&AuditFilter::default(), cursor)?;
            for row in &page.rows {
                let text = String::from_utf8(store.read_payload(row.seq)?.to_vec())?;
                out.push((row.event_type, text));
            }
            match page.next {
                Some(next) => cursor = next,
                None => break,
            }
        }
        Ok(out)
    }

    async fn stop(&self) -> TestResult {
        let state = &self.state;
        state.shutdown.cancel();
        let task = state.served.lock().map_err(|_| "poisoned")?.take();
        if let Some(task) = task {
            tokio::time::timeout(WAIT, task).await??;
        }
        if let Some(core) = state.core.get() {
            core.shutdown(ShutdownReason::Quit).await;
        }
        let store = state.store.lock().map_err(|_| "poisoned")?.take();
        if let Some(store) = store {
            tokio::task::spawn_blocking(move || store.shutdown()).await?;
        }
        Ok(())
    }
}

/// Every command response the test made, with its command name (the capture records carry none:
/// each invoke adds exactly one `TauriCommand` record, matched by position).
struct Driver {
    approvals: WebviewWindow<MockRuntime>,
    audit: WebviewWindow<MockRuntime>,
    calls: Vec<(String, Result<Value, Value>)>,
}

impl Driver {
    async fn call(&mut self, win: Win, cmd: &str, body: Value) -> Result<Value, Value> {
        let w = match win {
            Win::Approvals => self.approvals.clone(),
            Win::Audit => self.audit.clone(),
        };
        let name = cmd.to_owned();
        let r = tokio::task::spawn_blocking(move || invoke(&w, &name, body))
            .await
            .unwrap_or_else(|e| Err(json!(e.to_string())));
        self.calls.push((cmd.to_owned(), r.clone()));
        r
    }

    /// Opens the current revision as the UI does (`queue_get`, then `preview_fetch` of its
    /// revision) and returns that revision.
    async fn open(&mut self, id: &str) -> Result<Value, Boxed> {
        let item = self
            .call(Win::Approvals, "queue_get", json!({ "request_id": id }))
            .await
            .map_err(|e| format!("queue_get {id}: {e}"))?;
        let rev = item.get("item").unwrap_or(&item)["candidate_rev"].clone();
        self.call(
            Win::Approvals,
            "preview_fetch",
            json!({ "request_id": id, "candidate_rev": rev }),
        )
        .await
        .map_err(|e| format!("preview_fetch {id}: {e}"))?;
        Ok(rev)
    }

    async fn decide(&mut self, body: Value) -> Result<Value, Value> {
        self.call(Win::Approvals, "decide", body).await
    }
}

#[derive(Clone, Copy)]
enum Win {
    Approvals,
    Audit,
}

async fn submit(
    c: &mut IpcClient,
    alias: &str,
    op: &str,
    params: Value,
) -> Result<Envelope, Boxed> {
    let reply: SubmitReply = c
        .call(
            "request.submit",
            SubmitParams {
                op_id: op.into(),
                params,
                instance: Some(alias.into()),
                reason: Some("t29 canary sweep".into()),
            },
        )
        .await?;
    Ok(reply.envelope)
}

/// Waits until `id` is in the queue and `ready` holds for its row.
async fn queued(
    w: &World,
    id: &str,
    ready: impl Fn(&atlas_duck_core::QueueItem) -> bool,
) -> TestResult {
    let decisions = w.core()?.decisions();
    let start = Instant::now();
    loop {
        if let Some(item) = decisions.queue_get(id)
            && ready(&item)
        {
            return Ok(());
        }
        if start.elapsed() > WAIT {
            return Err(format!(
                "{id} was not ready in the queue within {WAIT:?}: {:?}",
                decisions.queue_get(id)
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn pending(
    c: &mut IpcClient,
    w: &World,
    alias: &str,
    op: &str,
    params: Value,
) -> Result<String, Boxed> {
    let env = submit(c, alias, op, params.clone()).await?;
    let id = env
        .request_id
        .clone()
        .ok_or_else(|| format!("no request id: {}", env.to_json_line()))?;
    queued(w, &id, |i| i.approvable)
        .await
        .map_err(|e| format!("{alias} {op} {params}: {e}"))?;
    Ok(id)
}

async fn await_env(c: &mut IpcClient, id: &str) -> Result<Envelope, Boxed> {
    Ok(c.call(
        "request.await",
        json!({ "request_id": id, "timeout_ms": WAIT.as_millis() as u64 }),
    )
    .await?)
}

/// The Authorization-header PAT reached each mock (the sweep is not vacuous) and the PAT is in no
/// other part of any request the mock received.
async fn pats_only_in_authorization(w: &World) -> TestResult {
    for alias in INSTANCES {
        let pat = w.canaries.pat(alias);
        let forms = secret_forms(&pat);
        let mut sent = 0;
        for r in w.mock(alias)?.received().await {
            let auth = r
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            if auth.contains(&pat) {
                sent += 1;
            }
            let mut rest = r.url.to_string().into_bytes();
            rest.extend_from_slice(&r.body);
            for (name, value) in r.headers.iter() {
                if name.as_str() != "authorization" {
                    rest.extend_from_slice(value.as_bytes());
                }
            }
            let found = hits(&rest, &forms);
            if !found.is_empty() {
                return Err(format!("{alias}: the PAT outside Authorization: {found:?}").into());
            }
        }
        if sent == 0 {
            return Err(format!("{alias}: the PAT never reached the mock").into());
        }
    }
    Ok(())
}

/// S-16 Tauri half over the canary path list (see the module docs for the rules).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s16_canary_sweep_tauri_channels() -> TestResult {
    let late = Arc::new(LateSink::default());
    let w = World::start(late.clone()).await?;
    let app = w.app()?;
    let cap = commands::capture::bounded();
    assert!(commands::capture::install(app.handle(), cap.clone()));
    let _ = late
        .0
        .set(Arc::new(TauriUiSink::new(app.handle().clone(), None)));
    let mut d = Driver {
        approvals: window(&app, "approvals")?,
        audit: window(&app, "audit")?,
        calls: Vec::new(),
    };
    let mut c = w.connect().await?;
    let mut envelopes: Vec<String> = Vec::new();
    let a = "jira-a";

    // release
    let release = pending(&mut c, &w, a, ISSUE, json!({ "key": "CAN-1" })).await?;
    let rev = d.open(&release).await?;
    d.decide(json!({"request_id": release, "decision": "release", "candidate_rev": rev}))
        .await
        .map_err(|e| format!("release: {e}"))?;
    let env = await_env(&mut c, &release).await?;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    envelopes.push(env.to_json_line());

    // release-redacted: the description is dropped before the release.
    let redacted = pending(&mut c, &w, a, ISSUE, json!({ "key": "CAN-2" })).await?;
    let ops = json!([{"drop_field": {"field_loc": "fields.description", "scope": "per_item"}}]);
    let rev = d.open(&redacted).await?;
    d.decide(json!({"request_id": redacted, "decision": "release_redacted", "candidate_rev": rev, "redactions": ops}))
        .await
        .map_err(|e| format!("redact: {e}"))?;
    let rev = d.open(&redacted).await?;
    d.decide(json!({"request_id": redacted, "decision": "release_redacted", "candidate_rev": rev, "redactions": ops}))
        .await
        .map_err(|e| format!("release_redacted: {e}"))?;
    let env = await_env(&mut c, &redacted).await?;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    envelopes.push(env.to_json_line());

    // deny
    let denied = pending(&mut c, &w, a, ISSUE, json!({ "key": "CAN-3" })).await?;
    let rev = d.open(&denied).await?;
    d.decide(
        json!({"request_id": denied, "decision": "deny", "candidate_rev": rev, "reason": "no"}),
    )
    .await
    .map_err(|e| format!("deny: {e}"))?;
    let env = await_env(&mut c, &denied).await?;
    assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
    envelopes.push(env.to_json_line());

    // deny-with-details and deny-with-hint: a transition whose enrichment GET answered 404.
    let hints = [
        vec![json!({"upstream_http": {"include_messages": true}})],
        vec![
            json!({"resolution_failed": {"include_candidates": false}}),
            json!({"missing_fields": {"include_allowed_values": false}}),
            json!("outcome_hint"),
            json!({"upstream_http": {"include_messages": false}}),
        ],
    ];
    for (key, tries) in CANARY_ERR_404.iter().zip(hints) {
        let env = submit(
            &mut c,
            a,
            "jira.issue.transition",
            json!({"key": key, "transition": "Done"}),
        )
        .await?;
        let id = env.request_id.clone().ok_or("no request id")?;
        queued(&w, &id, |_| true).await?;
        // The hint is accepted once the enrichment failure is on the item; until then each try is
        // refused and nothing is logged (bounded).
        let start = Instant::now();
        let mut refusals = Vec::new();
        'tries: loop {
            for details in &tries {
                let rev = d.open(&id).await?;
                let r = d
                    .decide(json!({"request_id": id, "decision": "deny", "candidate_rev": rev, "reason": "no", "deny_details": details}))
                    .await;
                match r {
                    Ok(_) => break 'tries,
                    Err(e) => refusals.push(e),
                }
            }
            if start.elapsed() > WAIT {
                return Err(format!("{key}: no deny hint was accepted: {refusals:?}").into());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let env = await_env(&mut c, &id).await?;
        assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
        envelopes.push(env.to_json_line());
    }

    // expire
    let expired = pending(&mut c, &w, a, ISSUE, json!({ "key": "CAN-4" })).await?;
    d.open(&expired).await?;
    assert!(w.core()?.expire_now(&expired).await, "expire_now");
    let env = await_env(&mut c, &expired).await?;
    assert_eq!(env.status, Status::Expired, "{}", env.to_json_line());
    envelopes.push(env.to_json_line());

    // cancel
    let cancelled = pending(&mut c, &w, a, ISSUE, json!({ "key": "CAN-5" })).await?;
    d.open(&cancelled).await?;
    let env: Envelope = c
        .call("request.cancel", json!({ "request_id": cancelled }))
        .await?;
    envelopes.push(env.to_json_line());
    let env = await_env(&mut c, &cancelled).await?;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    envelopes.push(env.to_json_line());

    // upstream-error: the read outcome item is released.
    let upstream = pending(&mut c, &w, a, ISSUE, json!({ "key": CANARY_ERR_500 })).await?;
    let rev = d.open(&upstream).await?;
    d.decide(json!({"request_id": upstream, "decision": "release", "candidate_rev": rev}))
        .await
        .map_err(|e| format!("release outcome: {e}"))?;
    let env = await_env(&mut c, &upstream).await?;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    envelopes.push(env.to_json_line());

    // `upstream_unavailable`: a 200 HTML page, decided from status and headers, never queued.
    let env = submit(&mut c, a, ISSUE, json!({ "key": CANARY_UNAVAILABLE })).await?;
    let env = match (env.status, env.request_id.clone()) {
        (Status::Pending, Some(id)) => await_env(&mut c, &id).await?,
        _ => env,
    };
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    envelopes.push(env.to_json_line());

    // outcome-unknown: the comment endpoint answers an empty 200.
    let unknown = pending(
        &mut c,
        &w,
        a,
        COMMENT,
        json!({"key": CANARY_OUTCOME_UNKNOWN, "body": "Seen.", "body_format": "wiki"}),
    )
    .await?;
    let rev = d.open(&unknown).await?;
    d.decide(json!({"request_id": unknown, "decision": "approve", "candidate_rev": rev}))
        .await
        .map_err(|e| format!("approve: {e}"))?;
    let env = await_env(&mut c, &unknown).await?;
    assert_eq!(env.status, Status::OutcomeUnknown, "{}", env.to_json_line());
    envelopes.push(env.to_json_line());

    // stale (jira-b): the stale check's identity call and its re-check answer without
    // `X-AUSERNAME`.
    let comment = |key: &str| json!({"key": key, "body": "Seen.", "body_format": "wiki"});
    let stale = pending(&mut c, &w, "jira-b", COMMENT, comment("STL-1")).await?;
    let rev = d.open(&stale).await?;
    let mock_b = w.mock("jira-b")?;
    mock_b.server().reset().await;
    mock_b
        .json(
            "/rest/api/2/issue/STL-1",
            200,
            &canary_issue(&w.canaries, "STL-1"),
        )
        .await;
    let user_b = mock_b.user().to_owned();
    mock_b
        .jira_myself(&user_b, &harness::canary_user_key(&user_b), XAuser::Missing)
        .await;
    d.decide(json!({"request_id": stale, "decision": "approve", "candidate_rev": rev}))
        .await
        .map_err(|e| format!("approve stale: {e}"))?;

    // recheck-failed (jira-c): the stale check's identity call has no header, the re-check's
    // `/myself` answers 503.
    let recheck = pending(&mut c, &w, "jira-c", COMMENT, comment("STL-1")).await?;
    let rev = d.open(&recheck).await?;
    let mock_c = w.mock("jira-c")?;
    mock_c.server().reset().await;
    mock_c
        .json(
            "/rest/api/2/issue/STL-1",
            200,
            &canary_issue(&w.canaries, "STL-1"),
        )
        .await;
    mock_c
        .jira_myself_once(
            mock_c.user(),
            &harness::canary_user_key(mock_c.user()),
            XAuser::Missing,
        )
        .await;
    mock_c.html("/rest/api/2/myself", 503).await;
    d.decide(json!({"request_id": recheck, "decision": "approve", "candidate_rev": rev}))
        .await
        .map_err(|e| format!("approve recheck: {e}"))?;

    // Both end as `WRITE_STALE` records with their reasons (bounded wait).
    let start = Instant::now();
    let stale_payloads = loop {
        let found: Vec<String> = w
            .audit_payloads()?
            .into_iter()
            .filter(|(t, _)| *t == EventType::WRITE_STALE)
            .map(|(_, p)| p)
            .collect();
        if found.iter().any(|p| p.contains("identity_header_missing"))
            && found.iter().any(|p| p.contains("recheck_failed"))
        {
            break found;
        }
        if start.elapsed() > WAIT {
            return Err(format!("no stale and recheck_failed WRITE_STALE: {found:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(!stale_payloads.is_empty());
    for id in [&stale, &recheck] {
        let env: Envelope = c
            .call("request.cancel", json!({ "request_id": id }))
            .await?;
        envelopes.push(env.to_json_line());
    }

    // The Approvals and Audit windows' views of all of it.
    let _ = d.call(Win::Approvals, "queue_list", json!({})).await;
    let _ = d.call(Win::Approvals, "recent_list", json!({})).await;
    let _ = d.call(Win::Approvals, "app_status", json!({})).await;
    let rows = d
        .call(Win::Audit, "audit_query", json!({"filter": {}}))
        .await
        .map_err(|e| format!("audit_query: {e}"))?;
    let seqs: Vec<u64> = rows["rows"]
        .as_array()
        .map(|r| r.iter().filter_map(|row| row["seq"].as_u64()).collect())
        .unwrap_or_default();
    assert!(!seqs.is_empty(), "audit_query rows: {rows}");
    for seq in seqs {
        let _ = d
            .call(Win::Audit, "audit_payload", json!({ "seq": seq }))
            .await;
    }
    for id in [
        &release, &redacted, &denied, &expired, &cancelled, &upstream, &unknown, &stale, &recheck,
    ] {
        let _ = d
            .call(Win::Audit, "audit_trail", json!({ "request_id": id }))
            .await;
    }
    let _ = d.call(Win::Audit, "audit_status", json!({})).await;

    // ---- the sweep ----
    // The negative control: an event that does carry a data canary, through the app's own emit
    // path (which the test build records).
    let control = w.canaries.data("control");
    EventOut::emit(app.handle(), "s16_control", json!({ "reason": control }));
    pats_only_in_authorization(&w).await?;
    let payloads = w.audit_payloads()?;
    let mut secrets: Vec<(String, Vec<String>)> = INSTANCES
        .iter()
        .map(|a| (format!("PAT {a}"), secret_forms(&w.canaries.pat(a))))
        .collect();
    secrets.push(("passphrase".into(), secret_forms(&w.canaries.passphrase())));
    let data: Vec<String> = w.canaries.data_all().into_iter().map(|(_, c)| c).collect();

    assert_eq!(cap.dropped(Channel::TauriCommand), 0);
    assert_eq!(cap.dropped(Channel::TauriEvent), 0);
    let commands = cap.on(Channel::TauriCommand);
    let events = cap.on(Channel::TauriEvent);
    assert_eq!(
        commands.len(),
        d.calls.len(),
        "one command record per invoke"
    );
    assert!(!events.is_empty(), "the event channel is blind");

    let in_log: BTreeSet<&str> = data
        .iter()
        .filter(|c| payloads.iter().any(|(_, p)| p.contains(c.as_str())))
        .map(String::as_str)
        .collect();
    let mut problems = Vec::new();
    for (what, text) in commands
        .iter()
        .zip(&d.calls)
        .map(|(rec, (cmd, _))| (format!("command {cmd}"), rec.json.as_str()))
        .chain(events.iter().map(|e| ("event".to_owned(), e.json.as_str())))
        .chain(
            envelopes
                .iter()
                .map(|e| ("IPC envelope".to_owned(), e.as_str())),
        )
    {
        for (kind, forms) in &secrets {
            let found = hits(text.as_bytes(), forms);
            if !found.is_empty() {
                problems.push(format!("{what} carries the {kind} canary {found:?}"));
            }
        }
        if what == "IPC envelope" {
            continue; // The process half sweeps the agent's channel against the released bytes.
        }
        let carried = hits(text.as_bytes(), &data);
        let view = DATA_VIEWS
            .iter()
            .any(|(cmd, _)| what == format!("command {cmd}"));
        for canary in carried {
            if !view {
                problems.push(format!("{what} carries the data canary {canary}: {text}"));
            } else if !in_log.contains(canary) {
                problems.push(format!(
                    "{what} shows the data canary {canary}, which no audit payload holds"
                ));
            }
        }
    }
    for (t, p) in &payloads {
        for (kind, forms) in &secrets {
            if !hits(p.as_bytes(), forms).is_empty() {
                problems.push(format!("the {t:?} payload carries the {kind} canary"));
            }
        }
    }
    // The negative control: the planted event is the one finding of the event channel.
    let (control_found, problems): (Vec<String>, Vec<String>) =
        problems.into_iter().partition(|p| p.contains(&control));
    assert_eq!(
        control_found.len(),
        1,
        "the sweep missed the control: {control_found:?}"
    );
    assert!(problems.is_empty(), "{}", problems.join("\n"));

    // Every path reached its record (the hint with and without the upstream messages, the two
    // stale reasons, the released outcome item, the data-free failure, the outcome-unknown write).
    let of = |t: EventType| -> Vec<&String> {
        payloads
            .iter()
            .filter(|(e, _)| *e == t)
            .map(|(_, p)| p)
            .collect()
    };
    let denied_writes = of(EventType::WRITE_DENIED);
    assert!(
        denied_writes
            .iter()
            .any(|p| p.contains("upstream_http") && !hits(p.as_bytes(), &data).is_empty()),
        "deny-with-details: {denied_writes:?}"
    );
    assert!(
        denied_writes
            .iter()
            .any(|p| p.contains("\"hint\"") && hits(p.as_bytes(), &data).is_empty()),
        "deny-with-hint: {denied_writes:?}"
    );
    let stale_writes = of(EventType::WRITE_STALE);
    for reason in ["identity_header_missing", "recheck_failed"] {
        assert!(
            stale_writes.iter().any(|p| p.contains(reason)),
            "{reason}: {stale_writes:?}"
        );
    }
    assert!(
        of(EventType::READ_FAILED)
            .iter()
            .any(|p| p.contains("upstream_unavailable")),
        "upstream_unavailable"
    );
    assert!(
        of(EventType::READ_RELEASED)
            .iter()
            .any(|p| p.contains("upstream_error")),
        "upstream-error"
    );
    for t in [
        EventType::READ_DENIED,
        EventType::EXPIRED,
        EventType::CANCELLED,
        EventType::WRITE_OUTCOME_UNKNOWN,
    ] {
        assert!(!of(t).is_empty(), "no {t:?}");
    }

    // Not vacuous: released and dropped canaries where they belong.
    let released: Vec<&String> = payloads
        .iter()
        .filter(|(t, _)| *t == EventType::READ_RELEASED)
        .map(|(_, p)| p)
        .collect();
    let previews: Vec<&str> = commands
        .iter()
        .zip(&d.calls)
        .filter(|(_, (cmd, _))| cmd == "preview_fetch")
        .map(|(r, _)| r.json.as_str())
        .collect();
    assert!(
        released
            .iter()
            .any(|p| !hits(p.as_bytes(), &data).is_empty()),
        "no released payload carries a data canary"
    );
    assert!(
        previews
            .iter()
            .any(|p| !hits(p.as_bytes(), &data).is_empty()),
        "no preview shows a data canary: the Tauri sweep would be blind"
    );
    for (label, canary) in w.canaries.data_all() {
        if label == "issue.description"
            && payloads.iter().any(|(t, p)| {
                *t == EventType::READ_FETCHED && p.contains("CAN-2") && p.contains(&canary)
            })
        {
            assert!(
                !released.iter().any(|p| p.contains(&canary)),
                "the dropped description {canary} was released"
            );
        }
    }
    drop(c);
    w.stop().await
}
