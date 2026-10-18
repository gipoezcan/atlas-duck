//! The in-process MCP rig (M9 Task 6; Tasks 7-10 only add tests): the real `IpcServer` serving
//! the recording `Fake`, a `TestConnector` that reaches it (a launch double: nothing is spawned),
//! the MCP server (`serve_with`) over one in-process pipe and an rmcp client over the other.
//! Between them two pumps copy whole lines: server to client they record every line the server
//! writes (`lines`), client to server they strip the progress token from calls made without one
//! (rmcp's client stamps a token on every request).
//!
//! Real clock only (Global Constraints "Tests"): no paused clock around the pipes or the server.

#![allow(clippy::unwrap_used, clippy::expect_used)]
// Helpers Tasks 7-10 use (cancel, progress, stopping the app) are not all used by Task 6's tests.
#![allow(dead_code)]

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atlas_duck_ipc::client::{ClientContext, ConnectError, IpcClient};
use atlas_duck_ipc::paths::LocalDataDir;
use atlas_duck_ipc::proto::{AgentNameSource, ClientKind, Hello};
use rmcp::model::{
    CallToolRequest, CallToolRequestParams, CallToolResult, ClientCapabilities, ClientConfig,
    ClientRequest, Implementation, ProgressNotificationParam, ProgressToken, RequestId,
    RequestMetaObject, ServerResult, Tool,
};
use rmcp::service::{
    NotificationContext, PeerRequestOptions, RequestHandle, RunningService, ServiceError,
};
use rmcp::{ClientHandler, RoleClient, ServiceExt};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::config::{McpConfig, ToolSet};
use super::serve_with;
use super::server::{AtlasMcp, ToolBodies};
use crate::connected::Connector;
use crate::test_support::{
    Fake, HelloMode, Mode, Running, TestConnector, WAIT, local, location_named, serve_at,
};

/// The build both the rig's Fake and its connector use: a version triple, so a restart with
/// another build tells `app_upgraded` from `protocol_mismatch` (plan review m-16).
pub(crate) const RIG_BUILD: &str = "1.0.0+test";
/// The heartbeat period of the rig's server (PD-125; production: `HEARTBEAT_EVERY`).
pub(crate) const RIG_HEARTBEAT: Duration = Duration::from_millis(200);
/// The default `ATLAS_DUCK_MCP_TIMEOUT` of a rig.
pub(crate) const RIG_TIMEOUT: Duration = Duration::from_secs(5);
/// Each in-process pipe's buffer.
const PIPE_BYTES: usize = 1 << 20;
/// The `_meta` key a call without a progress token carries to the client-to-server pump, which
/// removes it together with `progressToken`.
const NO_PROGRESS: &str = "atlas-duck-rig/no-progress";

pub(crate) struct RigOpts {
    pub tools: ToolSet,
    pub instance: Option<String>,
    pub agent: Option<String>,
    pub agent_source: AgentNameSource,
    pub agent_given: bool,
    /// `ATLAS_DUCK_MCP_TIMEOUT` (`None` = 0).
    pub timeout: Option<Duration>,
    /// The MCP client's `clientInfo.name`.
    pub client_name: String,
    pub heartbeat_every: Duration,
    /// The app; [`RigOpts::default`] sets `HelloMode::Exact` with [`RIG_BUILD`].
    pub fake: Fake,
    /// `false`: the endpoint never appears, so reaching the app runs the launch poll.
    pub present: bool,
    /// Replaces the server's tool bodies.
    pub bodies: Option<Arc<dyn ToolBodies>>,
}

impl Default for RigOpts {
    fn default() -> RigOpts {
        let fake = Fake::new();
        fake.set_hello_mode(HelloMode::Exact);
        fake.set_build(RIG_BUILD);
        RigOpts {
            tools: ToolSet::Full,
            instance: None,
            agent: None,
            agent_source: AgentNameSource::None,
            agent_given: false,
            timeout: Some(RIG_TIMEOUT),
            client_name: "rig-client".to_owned(),
            heartbeat_every: RIG_HEARTBEAT,
            fake,
            present: true,
            bodies: None,
        }
    }
}

impl RigOpts {
    pub(crate) fn config(&self) -> McpConfig {
        McpConfig {
            tools: self.tools,
            instance: self.instance.clone(),
            agent: self.agent.clone(),
            agent_source: self.agent_source,
            agent_given: self.agent_given,
            timeout: self.timeout,
        }
    }
}

// ---------- the app: Fake + IpcServer + connector ----------

/// The app half of the rig, usable without MCP (session tests, the rig self-tests).
pub(crate) struct RigApp {
    pub fake: Arc<Fake>,
    pub connector: Arc<TestConnector>,
    data: LocalDataDir,
    server: tokio::sync::Mutex<Option<Running>>,
    servers: AtomicUsize,
    // Last: removed after the server stopped using it.
    tmp: tempfile::TempDir,
}

impl RigApp {
    /// Serves `fake` on a fresh data dir; the connector reaches it with a hello at
    /// [`RIG_BUILD`]. Must be called inside a tokio runtime.
    pub(crate) fn new(fake: Fake, present: bool) -> RigApp {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("data");
        std::fs::create_dir(&dir).expect("data dir");
        let data = local(&dir);
        let fake = Arc::new(fake);
        let location = location_named(tmp.path(), &data, "atlas-duck-0.sock");
        let running = serve_at(&fake, &data, location.clone());
        let mut connector = TestConnector::new(data.clone(), Mode::Server(location));
        connector.present = present;
        connector.set_hello_build(RIG_BUILD);
        RigApp {
            fake,
            connector: Arc::new(connector),
            data,
            server: tokio::sync::Mutex::new(Some(running)),
            servers: AtomicUsize::new(1),
            tmp,
        }
    }

    /// Stops the server (every connection closes); the next connect finds no app.
    pub(crate) async fn stop_server(&self) {
        let running = self.server.lock().await.take();
        if let Some(running) = running {
            running.stop().await;
        }
    }

    /// An app restart: stops the server, then serves the same Fake on the same data dir with
    /// `build` as the server's build, and points the connector at it.
    pub(crate) async fn restart_server(&self, build: &str) {
        let mut slot = self.server.lock().await;
        if let Some(old) = slot.take() {
            old.stop().await;
        }
        self.fake.set_build(build);
        let n = self.servers.fetch_add(1, Ordering::SeqCst);
        let location = location_named(self.tmp.path(), &self.data, &format!("atlas-duck-{n}.sock"));
        let running = serve_at(&self.fake, &self.data, location.clone());
        self.connector.set_endpoint(location);
        *slot = Some(running);
    }

    /// Closes every connection: a restart with the current build.
    pub(crate) async fn drop_connections(&self) {
        let build = self.fake.build();
        self.restart_server(&build).await;
    }

    /// A CLI hello (the connector replaces its build with its own hello build).
    pub(crate) fn hello(&self) -> Hello {
        Hello {
            build_id: RIG_BUILD.to_owned(),
            client_kind: ClientKind::Cli,
            agent_name: None,
            agent_name_source: AgentNameSource::None,
            cwd_basename: "rig".to_owned(),
        }
    }

    /// A plain IPC client through the connector (no MCP).
    pub(crate) async fn ipc_client(&self) -> Result<IpcClient, ConnectError> {
        let ctx = ClientContext {
            data_dir: self.data.clone(),
            host: "host".to_owned(),
            hello: self.hello(),
        };
        self.connector.connect(&ctx, Instant::now() + WAIT).await
    }
}

// ---------- the MCP client ----------

struct RigClient {
    info: ClientConfig,
    progress: Arc<Mutex<Vec<ProgressNotificationParam>>>,
}

impl ClientHandler for RigClient {
    fn get_info(&self) -> ClientConfig {
        self.info.clone()
    }

    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        self.progress.lock().unwrap().push(params);
    }
}

/// A tool call whose answer has not been read yet.
pub(crate) struct InFlight {
    pub id: RequestId,
    /// The token rmcp's client put on the request (a call without one still has it here; the
    /// pump removed it on the wire).
    pub token: ProgressToken,
    handle: RequestHandle<RoleClient>,
}

impl InFlight {
    /// Sends `notifications/cancelled` for this call.
    pub(crate) async fn cancel(self) {
        self.handle
            .cancel(Some("rig".to_owned()))
            .await
            .expect("send notifications/cancelled");
    }
}

/// A finished tool call.
pub(crate) struct Called {
    pub result: CallToolResult,
    /// The progress notifications that carried this call's token, in arrival order.
    pub progress: Vec<ProgressNotificationParam>,
}

impl Called {
    /// `structuredContent`, i.e. the envelope.
    pub(crate) fn envelope(&self) -> Value {
        self.result
            .structured_content
            .clone()
            .unwrap_or(Value::Null)
    }

    pub(crate) fn is_error(&self) -> bool {
        self.result.is_error == Some(true)
    }

    pub(crate) fn texts(&self) -> Vec<String> {
        self.result
            .content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.clone()))
            .collect()
    }
}

// ---------- the rig ----------

pub(crate) struct Rig {
    pub app: RigApp,
    client: RunningService<RoleClient, RigClient>,
    progress: Arc<Mutex<Vec<ProgressNotificationParam>>>,
    lines: Arc<Mutex<Vec<String>>>,
    close: Arc<Notify>,
    serve: Mutex<Option<JoinHandle<io::Result<()>>>>,
}

impl Rig {
    /// Starts the app, the MCP server and the client, and runs `initialize`.
    pub(crate) async fn new(opts: RigOpts) -> Rig {
        let cfg = opts.config();
        let app = RigApp::new(opts.fake, opts.present);
        let connector: Arc<dyn Connector> = app.connector.clone();
        let mut server = AtlasMcp::new(cfg, connector, opts.heartbeat_every);
        if let Some(bodies) = opts.bodies {
            server = server.with_bodies(bodies);
        }

        let (client_io, client_pump) = tokio::io::duplex(PIPE_BYTES);
        let (server_io, server_pump) = tokio::io::duplex(PIPE_BYTES);
        let (server_read, server_write) = tokio::io::split(server_io);
        let (from_client, to_client) = tokio::io::split(client_pump);
        let (from_server, to_server) = tokio::io::split(server_pump);

        let lines = Arc::new(Mutex::new(Vec::new()));
        let close = Arc::new(Notify::new());
        tokio::spawn(pump_up(from_client, to_server, close.clone()));
        tokio::spawn(pump_down(from_server, to_client, lines.clone()));
        let serve = tokio::spawn(serve_with(server, server_read, server_write));

        let progress = Arc::new(Mutex::new(Vec::new()));
        let handler = RigClient {
            info: ClientConfig::new(
                ClientCapabilities::default(),
                Implementation::new(opts.client_name, "1.0.0"),
            ),
            progress: progress.clone(),
        };
        let client = tokio::time::timeout(WAIT, handler.serve(client_io))
            .await
            .expect("initialize within WAIT")
            .expect("initialize");
        Rig {
            app,
            client,
            progress,
            lines,
            close,
            serve: Mutex::new(Some(serve)),
        }
    }

    pub(crate) fn fake(&self) -> &Arc<Fake> {
        &self.app.fake
    }

    pub(crate) fn connector(&self) -> &Arc<TestConnector> {
        &self.app.connector
    }

    /// Sends `tools/call` for `tool`; `progress: false` sends it without a progress token.
    pub(crate) async fn start(&self, tool: &str, args: Value, progress: bool) -> InFlight {
        let mut meta = RequestMetaObject::new();
        if !progress {
            meta.0.0.insert(NO_PROGRESS.to_owned(), Value::Bool(true));
        }
        self.start_with_meta(tool, args, meta).await
    }

    /// [`Rig::start`] with extra `_meta` keys (rmcp's client adds its progress token).
    pub(crate) async fn start_with_meta(
        &self,
        tool: &str,
        args: Value,
        meta: RequestMetaObject,
    ) -> InFlight {
        let mut params = CallToolRequestParams::new(tool.to_owned());
        if let Value::Object(map) = args {
            params = params.with_arguments(map);
        }
        let options = PeerRequestOptions::no_options().with_meta(meta);
        let handle = self
            .client
            .peer()
            .send_request_with_option(
                ClientRequest::CallToolRequest(CallToolRequest::new(params)),
                options,
            )
            .await
            .expect("send tools/call");
        InFlight {
            id: handle.id.clone(),
            token: handle.progress_token.clone(),
            handle,
        }
    }

    /// The raw JSON-RPC outcome of `call` within `within`: `None` if no answer came.
    pub(crate) async fn outcome_within(
        &self,
        call: InFlight,
        within: Duration,
    ) -> Option<Result<ServerResult, ServiceError>> {
        tokio::time::timeout(within, call.handle.await_response())
            .await
            .ok()
    }

    /// Waits up to `within` for the answer of `call` (a test fails, never hangs).
    pub(crate) async fn finish_within(&self, call: InFlight, within: Duration) -> Called {
        let token = call.token.clone();
        let answer = self
            .outcome_within(call, within)
            .await
            .unwrap_or_else(|| panic!("no answer to tools/call within {within:?}"))
            .expect("tools/call answer");
        let ServerResult::CallToolResult(result) = answer else {
            panic!("not a tool result: {answer:?}");
        };
        Called {
            result,
            progress: self.progress_of(&token),
        }
    }

    pub(crate) async fn finish(&self, call: InFlight) -> Called {
        self.finish_within(call, WAIT).await
    }

    /// One tool call, start to answer.
    pub(crate) async fn call(&self, tool: &str, args: Value, progress: bool) -> Called {
        let call = self.start(tool, args, progress).await;
        self.finish(call).await
    }

    pub(crate) async fn list_tools(&self) -> Vec<Tool> {
        tokio::time::timeout(WAIT, self.client.peer().list_all_tools())
            .await
            .expect("tools/list within WAIT")
            .expect("tools/list")
    }

    /// The progress notifications that carried `token` so far.
    pub(crate) fn progress_of(&self, token: &ProgressToken) -> Vec<ProgressNotificationParam> {
        self.progress
            .lock()
            .unwrap()
            .iter()
            .filter(|p| &p.progress_token == token)
            .cloned()
            .collect()
    }

    /// Every progress notification the client received so far.
    pub(crate) fn all_progress(&self) -> Vec<ProgressNotificationParam> {
        self.progress.lock().unwrap().clone()
    }

    /// Every line the server wrote so far, without its `\n`.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    /// Closes the server's stdin (EOF); its stdout stays observable.
    pub(crate) fn close_stdin(&self) {
        self.close.notify_one();
    }

    /// `serve`'s result once it returned, or `None` if it is still serving after `within`.
    pub(crate) async fn serve_result(&self, within: Duration) -> Option<io::Result<()>> {
        let handle = self.serve.lock().unwrap().take()?;
        let mut handle = handle;
        match tokio::time::timeout(within, &mut handle).await {
            Ok(joined) => Some(joined.expect("serve task")),
            Err(_) => {
                *self.serve.lock().unwrap() = Some(handle);
                None
            }
        }
    }
}

/// Client to server: whole lines, a call marked [`NO_PROGRESS`] loses its progress token; on
/// `close` the server's stdin ends.
async fn pump_up<R, W>(from: R, mut to: W, close: Arc<Notify>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut from = BufReader::new(from);
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = tokio::select! {
            biased;
            () = close.notified() => break,
            read = from.read_until(b'\n', &mut line) => read,
        };
        match read {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let out = strip_progress(&line);
                if to.write_all(&out).await.is_err() || to.flush().await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown().await;
}

/// Server to client: whole lines, each recorded.
async fn pump_down<R, W>(from: R, mut to: W, lines: Arc<Mutex<Vec<String>>>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut from = BufReader::new(from);
    let mut line = Vec::new();
    loop {
        line.clear();
        match from.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let text = String::from_utf8_lossy(&line);
                lines
                    .lock()
                    .unwrap()
                    .push(text.trim_end_matches('\n').to_owned());
                if to.write_all(&line).await.is_err() || to.flush().await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown().await;
}

/// `line` unchanged, unless its `params._meta` carries [`NO_PROGRESS`]: then without that key
/// and without `progressToken`.
fn strip_progress(line: &[u8]) -> Vec<u8> {
    let Ok(mut msg) = serde_json::from_slice::<Value>(line) else {
        return line.to_vec();
    };
    let Some(meta) = msg
        .get_mut("params")
        .and_then(|p| p.get_mut("_meta"))
        .and_then(Value::as_object_mut)
    else {
        return line.to_vec();
    };
    if meta.remove(NO_PROGRESS).is_none() {
        return line.to_vec();
    }
    meta.remove("progressToken");
    let empty = meta.is_empty();
    if empty && let Some(params) = msg.get_mut("params").and_then(Value::as_object_mut) {
        params.remove("_meta");
    }
    let mut out = serde_json::to_vec(&msg).expect("re-encode");
    out.push(b'\n');
    out
}
