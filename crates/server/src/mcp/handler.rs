//! The server's MCP `ServerHandler` (SM-3.1, PD-193, PD-194, PD-195, PD-215). The tool set,
//! argument checks and envelope → tool-result mapping are M9's (`atlas_duck_mcp_tools`); the
//! calls go to the key owner's `Core` through `RequestHandler`, in process. The tool list and
//! every call are filtered by the key's scopes; a pending envelope gains `meta.approval_url`.
//! There is no approval tool (SM-3.4).

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use atlas_duck_ipc::build_info::{APP_VERSION, BUILD_ID};
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::proto::{
    AgentNameSource, AwaitParams, ClientKind, ConnectionMeta, Hello, ListState, MatchParams,
    ProgressNotification, ProgressSink, RequestHandler, SubmitParams,
};
use atlas_duck_mcp_tools::local;
use atlas_duck_mcp_tools::progress::HEARTBEAT_EVERY;
use atlas_duck_mcp_tools::result::{ToolKind, to_tool_result};
use atlas_duck_mcp_tools::tools::{
    FIXED_TOOLS, catalog, op_for_tool, split_op_args, validate_fixed_args,
};
use atlas_duck_mcp_tools::toolset::ToolSet;
use atlas_duck_registry::{OpClass, SCRIPT_RUN};
use axum::http::request::Parts;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, ListToolsResult,
    PaginatedRequestParams, ProgressNotificationParam, ProgressToken, ProtocolVersion,
    ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, Peer, RoleServer, ServerHandler};
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior, interval_at};

use crate::api_keys::KeyCtx;
use crate::runtime::Registry;

/// `serverInfo.name` (as M9).
pub const SERVER_NAME: &str = "atlas-duck";
/// The wait of a submitting tool and `request_await` from the call's receipt (M9's default
/// `ATLAS_DUCK_MCP_TIMEOUT`); undecided after it, the answer is `pending`.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(50);
/// The envelope code of a tool the key's scopes leave out (PD-215, L226; server only).
pub const SCOPE_MISSING: &str = "scope_missing";
/// PD-194: the synthetic peer of every in-process connection.
pub const PEER: &str = "mcp-http";

/// The tools that need `read` besides the read op tools (PD-215).
const READ_FIXED: [&str; 6] = [
    "ops_list",
    "ops_describe",
    "instances_list",
    "request_status",
    "request_list",
    "request_await",
];

fn has(scopes: &[String], s: &str) -> bool {
    scopes.iter().any(|x| x == s)
}

/// PD-215: may a key with `scopes` use `tool`? M14 PD-242 (SM-7.1): `script_run` needs the
/// `scripts` scope (API key or OAuth); awaiting a script's request needs `read` like any other.
pub fn allowed(tool: &str, scopes: &[String]) -> bool {
    match tool {
        "script_run" => has(scopes, "scripts"),
        "request_cancel" => has(scopes, "propose_write"),
        t if READ_FIXED.contains(&t) => has(scopes, "read"),
        t => match op_for_tool(t) {
            Some(spec) if spec.class == OpClass::Write => has(scopes, "propose_write"),
            Some(_) => has(scopes, "read"),
            None => false,
        },
    }
}

/// `tools/list` for a key: M9's `ToolSet::Full` catalog, filtered by scope.
pub fn tools_for(scopes: &[String]) -> Vec<Tool> {
    catalog(ToolSet::Full)
        .into_iter()
        .filter(|t| allowed(&t.name, scopes))
        .collect()
}

/// Whether `ToolSet::Full` has a tool of this name.
fn offered(name: &str) -> bool {
    FIXED_TOOLS.contains(&name) || op_for_tool(name).is_some()
}

#[derive(Clone)]
pub struct ServerMcp {
    registry: Arc<Registry>,
    public_origin: Arc<str>,
    heartbeat_every: Duration,
    timeout: Duration,
}

/// The guard's `KeyCtx` of this request (rmcp hands the HTTP parts to every handler call).
fn key_of(context: &RequestContext<RoleServer>) -> Option<KeyCtx> {
    context
        .extensions
        .get::<Parts>()?
        .extensions
        .get::<KeyCtx>()
        .cloned()
}

fn session_of(context: &RequestContext<RoleServer>) -> Option<String> {
    context
        .extensions
        .get::<Parts>()?
        .headers
        .get(super::SESSION_HEADER)?
        .to_str()
        .ok()
        .map(str::to_owned)
}

fn no_key() -> McpError {
    McpError::internal_error("no authenticated key", None)
}

fn unknown_tool(name: &str) -> Envelope {
    let name = local::clip(name);
    let mut details = Map::new();
    details.insert("tool".to_owned(), Value::from(name.clone()));
    local::usage(&format!("unknown tool: {name}"), details)
}

/// The tool result of a call the key's scopes do not allow (PD-215): the envelope shape with
/// `error.code = "scope_missing"`.
pub fn scope_missing(tool: &str) -> CallToolResult {
    let mut v = serde_json::to_value(Envelope::failed(
        ErrorCode::Usage,
        false,
        "the API key's scopes do not allow this tool",
    ))
    .unwrap_or(Value::Null);
    if let Some(err) = v.get_mut("error").and_then(Value::as_object_mut) {
        err.insert("code".into(), Value::from(SCOPE_MISSING));
        err.insert("details".into(), json!({"tool": local::clip(tool)}));
    }
    CallToolResult::structured_error(v)
}

fn protocol_failure() -> Envelope {
    Envelope::failed(ErrorCode::ProtocolError, false, "protocol error")
}

fn store_unavailable() -> Envelope {
    let mut env = Envelope::failed(
        ErrorCode::Unreachable,
        true,
        "the audit store is unavailable",
    );
    if let Some(err) = env.error.as_mut() {
        let mut d = Map::new();
        d.insert("reason".into(), Value::from("store_unavailable"));
        err.details = Some(d);
    }
    env
}

fn pending_for(request_id: &str) -> Envelope {
    let mut env = Envelope::failed(ErrorCode::Internal, false, "");
    env.status = Status::Pending;
    env.error = None;
    env.request_id = Some(request_id.to_owned());
    env
}

fn string_arg(args: &Map<String, Value>, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn list_state(s: &str) -> Option<ListState> {
    match s {
        "pending" => Some(ListState::Pending),
        "recent" => Some(ListState::Recent),
        _ => None,
    }
}

/// Status changes from `await_request`, handed to the waiting loop.
struct ChannelSink(mpsc::UnboundedSender<ProgressNotification>);

impl ProgressSink for ChannelSink {
    fn progress(&self, n: ProgressNotification) {
        let _ = self.0.send(n);
    }
}

/// The notifications of one tool call (as M9's PD-125: only with a progress token; "submitted",
/// each status change once, heartbeats without a message).
struct Progress {
    token: Option<ProgressToken>,
    counter: u32,
    last: Option<Status>,
    peer: Peer<RoleServer>,
}

impl Progress {
    async fn send(&mut self, message: Option<String>) {
        let Some(token) = self.token.clone() else {
            return;
        };
        self.counter = self.counter.saturating_add(1);
        let mut p = ProgressNotificationParam::new(token, f64::from(self.counter));
        p.message = message;
        let _ = self.peer.notify_progress(p).await;
    }

    async fn status(&mut self, n: ProgressNotification) {
        if self.last == Some(n.status) {
            return;
        }
        self.last = Some(n.status);
        let status = serde_json::to_value(n.status)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        self.send(Some(format!("request_id={} status={status}", n.request_id)))
            .await;
    }
}

/// One tool call on the key owner's runtime.
struct Call<'a> {
    handler: Arc<dyn RequestHandler>,
    conn: ConnectionMeta,
    context: &'a RequestContext<RoleServer>,
    receipt: Instant,
    timeout: Duration,
    heartbeat_every: Duration,
}

impl Call<'_> {
    fn remaining_ms(&self) -> u64 {
        let left = self.timeout.saturating_sub(self.receipt.elapsed());
        u64::try_from(left.as_millis()).unwrap_or(u64::MAX)
    }

    async fn submit_and_wait(&self, sp: SubmitParams, progress: &mut Progress) -> Envelope {
        let reply = if sp.op_id == SCRIPT_RUN.id {
            self.handler.submit_script(&self.conn, sp).await
        } else {
            self.handler.submit(&self.conn, sp).await
        };
        let env = reply.envelope;
        if env.status != Status::Pending {
            return env;
        }
        let Some(id) = env.request_id.clone() else {
            return protocol_failure();
        };
        progress.last = Some(Status::Pending);
        progress
            .send(Some(format!("submitted request_id={id} status=pending")))
            .await;
        self.await_request(&id, &env, progress).await
    }

    /// `await_request` with status changes and heartbeats; a cancelled call stops waiting only
    /// (the request lives on) and answers `base`.
    async fn await_request(&self, id: &str, base: &Envelope, progress: &mut Progress) -> Envelope {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sink = ChannelSink(tx);
        let params = AwaitParams {
            request_id: id.to_owned(),
            timeout_ms: Some(self.remaining_ms()),
        };
        let waiting = self.handler.await_request(&self.conn, params, &sink);
        tokio::pin!(waiting);
        let every = self.heartbeat_every.max(Duration::from_millis(1));
        let mut timer = interval_at(self.receipt + every, every);
        timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let beats = progress.token.is_some();
        let out = loop {
            tokio::select! {
                biased;
                () = self.context.ct.cancelled() => return base.clone(),
                _ = timer.tick(), if beats => progress.send(None).await,
                Some(n) = rx.recv() => progress.status(n).await,
                env = &mut waiting => break env,
            }
        };
        while let Ok(n) = rx.try_recv() {
            progress.status(n).await;
        }
        if out.request_id.as_deref().is_some_and(|got| got != id) {
            return protocol_failure();
        }
        out
    }

    async fn run(&self, name: &str, args: Map<String, Value>, progress: &mut Progress) -> Envelope {
        let h = &self.handler;
        let id = || string_arg(&args, "request_id").unwrap_or_default();
        match name {
            "request_await" => {
                let id = id();
                self.await_request(&id, &pending_for(&id), progress).await
            }
            "request_status" => h.status(&id()).await,
            "request_cancel" => h.cancel(&id()).await,
            "request_list" => {
                let state = args
                    .get("state")
                    .and_then(Value::as_str)
                    .and_then(list_state);
                let match_params = args
                    .get("match_params")
                    .and_then(Value::as_object)
                    .map(|m| MatchParams {
                        op_id: string_arg(m, "op_id").unwrap_or_default(),
                        params: m
                            .get("params")
                            .cloned()
                            .unwrap_or_else(|| Value::Object(Map::new())),
                        instance: string_arg(m, "instance"),
                    });
                h.requests_list(string_arg(&args, "agent").as_deref(), state, match_params)
                    .await
            }
            "ops_list" => h.ops_list(string_arg(&args, "instance").as_deref()).await,
            "ops_describe" => {
                let op_id = string_arg(&args, "op_id").unwrap_or_default();
                h.ops_describe(&op_id, string_arg(&args, "instance").as_deref())
                    .await
            }
            "instances_list" => h.instances_list().await,
            // §9.1 `{source, args, limits?, dry_run?}`; a script names no instance (PD-124).
            "script_run" => {
                let mut params = Map::new();
                params.insert(
                    "source".into(),
                    Value::from(string_arg(&args, "source").unwrap_or_default()),
                );
                params.insert(
                    "args".into(),
                    args.get("args")
                        .cloned()
                        .unwrap_or_else(|| Value::Object(Map::new())),
                );
                if let Some(limits) = args.get("limits") {
                    params.insert("limits".into(), limits.clone());
                }
                if let Some(d) = args
                    .get("dry_run")
                    .and_then(Value::as_str)
                    .filter(|d| *d == "full" || *d == "sparse")
                {
                    params.insert("dry_run".into(), Value::from(d));
                }
                let sp = SubmitParams {
                    op_id: SCRIPT_RUN.id.to_owned(),
                    params: Value::Object(params),
                    instance: None,
                    reason: string_arg(&args, "reason"),
                };
                self.submit_and_wait(sp, progress).await
            }
            op => match op_for_tool(op) {
                Some(spec) => match split_op_args(args) {
                    Ok((params, reason, instance)) => {
                        let sp = SubmitParams {
                            op_id: spec.id.to_owned(),
                            params,
                            instance,
                            reason,
                        };
                        self.submit_and_wait(sp, progress).await
                    }
                    Err(env) => env,
                },
                None => unknown_tool(op),
            },
        }
    }
}

impl ServerMcp {
    pub fn new(registry: Arc<Registry>, public_origin: &str) -> ServerMcp {
        ServerMcp {
            registry,
            public_origin: Arc::from(public_origin.trim_end_matches('/')),
            heartbeat_every: HEARTBEAT_EVERY,
            timeout: CALL_TIMEOUT,
        }
    }

    /// Tests: a shorter wait.
    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: Duration) -> ServerMcp {
        self.timeout = timeout;
        self
    }

    /// PD-195: `meta.approval_url` on every pending envelope with an id (L218: the envelope has
    /// no top-level `details`, so `meta` carries it; core is untouched).
    fn with_approval_url(&self, mut env: Envelope) -> Envelope {
        if env.status != Status::Pending {
            return env;
        }
        let Some(id) = env.request_id.clone() else {
            return env;
        };
        let url = format!("{}/approvals?item={id}", self.public_origin);
        let mut meta = match env.meta.take() {
            Some(Value::Object(m)) => m,
            _ => Map::new(),
        };
        meta.insert("approval_url".into(), Value::from(url));
        env.meta = Some(Value::Object(meta));
        env
    }

    async fn dispatch(
        &self,
        key: &KeyCtx,
        name: &str,
        args: Map<String, Value>,
        context: &RequestContext<RoleServer>,
        receipt: Instant,
    ) -> Envelope {
        if FIXED_TOOLS.contains(&name)
            && let Err(env) = validate_fixed_args(name, &args)
        {
            return env;
        }
        let Ok(rt) = self.registry.runtime(&key.user).await else {
            return store_unavailable();
        };
        // PD-209: the runtime stays open while the call runs.
        let _pin = rt.mcp_pin();
        let handler = rt.handler();
        drop(rt);
        // PD-194: one approval session per MCP session (per key without one).
        let conn = ConnectionMeta {
            connection_id: session_of(context).unwrap_or_else(|| format!("mcp-{}", key.credential)),
            peer: Default::default(),
        };
        let client_name = context
            .client_info()
            .map(|i| i.name)
            .filter(|n| !n.is_empty());
        let hello = Hello {
            build_id: BUILD_ID.to_owned(),
            client_kind: ClientKind::Mcp,
            agent_name_source: if client_name.is_some() {
                AgentNameSource::McpClientInfo
            } else {
                AgentNameSource::None
            },
            agent_name: client_name,
            cwd_basename: PEER.to_owned(),
        };
        // A runtime may have been reopened since the last call, so every call says hello.
        if let Err(env) = handler.hello(&conn, hello).await {
            return env;
        }
        let call = Call {
            handler,
            conn,
            context,
            receipt,
            timeout: self.timeout,
            heartbeat_every: self.heartbeat_every,
        };
        let mut progress = Progress {
            token: context.meta.get_progress_token(),
            counter: 0,
            last: None,
            peer: context.peer.clone(),
        };
        call.run(name, args, &mut progress).await
    }
}

impl ServerHandler for ServerMcp {
    fn get_info(&self) -> ServerConfig {
        let mut capabilities = ServerCapabilities::builder().enable_tools().build();
        if let Some(tools) = capabilities.tools.as_mut() {
            tools.list_changed = Some(false);
        }
        ServerConfig::new(capabilities)
            .with_server_info(Implementation::new(SERVER_NAME, APP_VERSION))
            .with_protocol_version(ProtocolVersion::LATEST_WITH_INITIALIZE)
    }

    /// As M9: up to the newest revision with an `initialize` handshake, so MCP sessions exist and
    /// bind to their creator.
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(ProtocolVersion::known_up_to(
            &ProtocolVersion::LATEST_WITH_INITIALIZE,
        ))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let key = key_of(&context).ok_or_else(no_key)?;
        Ok(ListToolsResult::with_all_items(tools_for(&key.scopes)))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let receipt = Instant::now();
        let key = key_of(&context).ok_or_else(no_key)?;
        let name = request.name.into_owned();
        let kind = ToolKind::of(&name);
        if !offered(&name) {
            return Ok(to_tool_result(kind, &unknown_tool(&name)).into());
        }
        if !allowed(&name, &key.scopes) {
            return Ok(scope_missing(&name).into());
        }
        let args = request.arguments.unwrap_or_default();
        let env = self.dispatch(&key, &name, args, &context, receipt).await;
        Ok(to_tool_result(kind, &self.with_approval_url(env)).into())
    }
}
