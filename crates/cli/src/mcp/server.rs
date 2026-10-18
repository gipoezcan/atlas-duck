//! The MCP `ServerHandler` (§4.6): `initialize` (tools capability only), `tools/list` from the
//! registry without any connection (PD-118), and `tools/call`, which answers argument errors and
//! the app-free `ops_list`/`ops_describe` locally and hands every other call to the tool bodies.
//! Every answer is a tool result carrying the envelope (PD-121); `Err(McpError)` is left to rmcp
//! for malformed JSON-RPC.

use std::borrow::Cow;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_duck_ipc::build_info::APP_VERSION;
use atlas_duck_ipc::envelope::Envelope;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, Implementation, ListToolsResult,
    PaginatedRequestParams, ProgressToken, ProtocolVersion, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde_json::{Map, Value};

use super::call::Bodies;
use super::config::{McpConfig, ToolSet};
use super::result::{ToolKind, to_tool_result};
use super::session::Session;
use super::tools::{CALL_TOOL, FIXED_TOOLS, catalog, op_for_tool, validate_fixed_args};
use crate::argv::clip;
use crate::connected::Connector;
use crate::local;

/// `serverInfo.name`.
pub(crate) const SERVER_NAME: &str = "atlas-duck";

/// A boxed `Send` future (rmcp runs every handler on its own task).
pub(crate) type SendFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the server holds for every tool call.
pub(crate) struct Shared {
    pub cfg: McpConfig,
    /// `progress::HEARTBEAT_EVERY` in production (PD-125; only the rig sets a short one).
    pub heartbeat_every: Duration,
    /// The one IPC connection of this server (PD-115, PD-128).
    pub session: Session,
}

/// One connected tool call, its arguments already checked (fixed tools and `call`: PD-118).
pub(crate) struct ToolCall {
    pub name: String,
    pub args: Map<String, Value>,
    /// Receipt of the tool call: the deadline and the heartbeat timer start here (§4.6, PD-125).
    pub receipt: Instant,
    /// rmcp's context of the call: `ct` is cancelled on `notifications/cancelled` for this call
    /// and when the service ends (stdin EOF; `serve` cancels the service, and every handler's
    /// token is a child of it): stop waiting, never cancel at the app (PD-126). `meta` carries
    /// the progress token, `peer` sends the notifications.
    pub context: RequestContext<RoleServer>,
}

impl ToolCall {
    /// `_meta.progressToken` of the call (PD-125: no token, no notifications).
    pub(crate) fn progress_token(&self) -> Option<ProgressToken> {
        self.context.meta.get_progress_token()
    }

    /// `clientInfo.name` as the client sent it (PD-122 decides what an empty one means): from the
    /// request's own `_meta` when it carries one, else from `initialize`. Both lifecycles carry
    /// it, so a client that never sends `initialize` still names itself (T6 review I-1).
    pub(crate) fn client_name(&self) -> Option<String> {
        self.context.client_info().map(|info| info.name)
    }
}

/// The connected tool bodies (`call::Bodies`; tests replace them).
pub(crate) trait ToolBodies: Send + Sync {
    fn call<'a>(&'a self, shared: &'a Shared, call: ToolCall) -> SendFuture<'a, Envelope>;
}

/// The handler rmcp serves.
#[derive(Clone)]
pub(crate) struct AtlasMcp {
    shared: Arc<Shared>,
    bodies: Arc<dyn ToolBodies>,
}

impl AtlasMcp {
    pub(crate) fn new(
        cfg: McpConfig,
        connector: Arc<dyn Connector>,
        heartbeat_every: Duration,
    ) -> AtlasMcp {
        AtlasMcp {
            shared: Arc::new(Shared {
                session: Session::new(&cfg, connector),
                cfg,
                heartbeat_every,
            }),
            bodies: Arc::new(Bodies),
        }
    }

    /// Replaces the tool bodies (tests: bodies that wait).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn with_bodies(mut self, bodies: Arc<dyn ToolBodies>) -> AtlasMcp {
        self.bodies = bodies;
        self
    }

    /// Whether the configured tool set has a tool of this name.
    fn offers(&self, name: &str) -> bool {
        FIXED_TOOLS.contains(&name)
            || match self.shared.cfg.tools {
                ToolSet::Full => op_for_tool(name).is_some(),
                ToolSet::Generic => name == CALL_TOOL,
            }
    }

    /// The envelope for one tool call.
    async fn dispatch(
        &self,
        name: String,
        args: Map<String, Value>,
        receipt: Instant,
        context: RequestContext<RoleServer>,
    ) -> Envelope {
        if !self.offers(&name) {
            return unknown_tool(&name);
        }
        if (FIXED_TOOLS.contains(&name.as_str()) || name == CALL_TOOL)
            && let Err(env) = validate_fixed_args(&name, &args)
        {
            return env;
        }
        // PD-118: without an instance these stay local and app-free, as in the CLI (PD-10).
        if !args.contains_key("instance") {
            match name.as_str() {
                "ops_list" => return local::ops_list(),
                "ops_describe" => {
                    let op_id = args
                        .get("op_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    return local::ops_describe(op_id);
                }
                _ => {}
            }
        }
        let call = ToolCall {
            name,
            args,
            receipt,
            context,
        };
        self.bodies.call(&self.shared, call).await
    }
}

pub(crate) fn unknown_tool(name: &str) -> Envelope {
    let name = clip(name);
    let mut details = Map::new();
    details.insert("tool".to_owned(), Value::from(name.clone()));
    local::usage(&format!("unknown tool: {name}"), details)
}

impl ServerHandler for AtlasMcp {
    fn get_info(&self) -> ServerConfig {
        let mut capabilities = ServerCapabilities::builder().enable_tools().build();
        if let Some(tools) = capabilities.tools.as_mut() {
            tools.list_changed = Some(false);
        }
        ServerConfig::new(capabilities)
            .with_server_info(Implementation::new(SERVER_NAME, APP_VERSION))
            .with_protocol_version(ProtocolVersion::LATEST_WITH_INITIALIZE)
    }

    /// Up to the newest revision with an `initialize` handshake: a request naming 2026-07-28 is
    /// refused with `unsupported_protocol_version`. A client may still skip `initialize` (its
    /// requests then carry `clientInfo` in `_meta`, which `ToolCall::client_name` reads).
    /// `server/discover` keeps rmcp's answer: refusing it would not make a probing client use
    /// `initialize` (rmcp keeps requiring inline `_meta` once a session opened with a probe, so
    /// the fallback's tool calls would all be refused; M9 T7 report).
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(ProtocolVersion::known_up_to(
            &ProtocolVersion::LATEST_WITH_INITIALIZE,
        ))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(catalog(
            self.shared.cfg.tools,
        )))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let receipt = Instant::now();
        let name = request.name.into_owned();
        let kind = ToolKind::of(&name);
        let args = request.arguments.unwrap_or_default();
        let env = self.dispatch(name, args, receipt, context).await;
        Ok(to_tool_result(kind, &env).into())
    }
}
