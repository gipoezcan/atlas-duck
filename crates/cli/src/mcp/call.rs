//! The connected tool bodies (§4.6): op tools, `call` and `script_run` submit and wait;
//! `request_*`, `ops_*` with an instance and `instances_list` make one short call. Every body
//! goes through the session's one shared connection (PD-115) and maps every outcome with the
//! CLI's own envelope rules (`flow`: PD-16, L63, L131), so the two front ends cannot drift.
//!
//! The deadline is `ATLAS_DUCK_MCP_TIMEOUT` from the tool call's receipt (§4.6); every IPC call
//! is bounded through `SharedClient`'s own `at`, never by dropping its future (Δ1). The call's
//! cancellation token (a client's `notifications/cancelled`, and stdin EOF, whose results are
//! still written) stops a body the way an interrupt stops the CLI, so the answer is true either
//! way: before anything was sent it is `launch_timeout` (nothing queued), a submit runs to its
//! answer (PD-126), and a wait ends with the request still `pending`. Only `request_cancel`
//! sends `request.cancel`. A call with a progress token hears "submitted", the status changes
//! and heartbeats while it waits (PD-125, `progress`); a short call hears nothing.

use std::future::Future;
use std::sync::Arc;

use atlas_duck_ipc::client::{ClientError, SharedClient};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::proto::{AwaitParams, MatchParams, SubmitParams, SubmitReply};
use atlas_duck_ipc::rpc::{
    EmptyParams, IdParams, OpsDescribeParams, OpsListParams, RequestsListParams, method,
};
use atlas_duck_registry::SCRIPT_RUN;
use serde::Serialize;
use serde_json::{Map, Value};

use super::progress::{Progress, ProgressPeer, wait_with_progress};
use super::server::{SendFuture, Shared, ToolBodies, ToolCall, unknown_tool};
use super::tools::{CALL_TOOL, op_for_tool, split_op_args};
use crate::argv::DryRun;
use crate::connected::{AWAIT_SLACK, bound, list_state};
use crate::deadline::Deadline;
use crate::flow::{
    Front, await_error, await_timeout_ms, check_await_reply, check_submit_reply, pending_for,
    protocol_failure, script_params, short_error_for, submit_error_for,
};
use crate::launch;

/// The tool bodies the server runs.
pub(crate) struct Bodies;

impl ToolBodies for Bodies {
    fn call<'a>(&'a self, shared: &'a Shared, call: ToolCall) -> SendFuture<'a, Envelope> {
        Box::pin(async move {
            // PD-125: only the waiting tools use it; a short call sends nothing.
            let peer: Arc<dyn ProgressPeer> = Arc::new(call.context.peer.clone());
            let mut progress = Progress::new(call.progress_token(), peer);
            Body::new(shared, call).run(&mut progress).await
        })
    }
}

/// One connected tool call; its arguments were checked before (PD-118: the fixed tools and
/// `call` by the server, an op tool's `reason`/`instance` here).
struct Body<'a> {
    shared: &'a Shared,
    call: ToolCall,
    /// `ATLAS_DUCK_MCP_TIMEOUT` from the receipt; unbounded for `0`.
    deadline: Deadline,
}

impl<'a> Body<'a> {
    fn new(shared: &'a Shared, call: ToolCall) -> Body<'a> {
        let deadline = Deadline::new(call.receipt, shared.cfg.timeout);
        Body {
            shared,
            call,
            deadline,
        }
    }

    async fn run(&self, progress: &mut Progress) -> Envelope {
        let args = &self.call.args;
        let id = || IdParams {
            request_id: string_arg(args, "request_id").unwrap_or_default(),
        };
        match self.call.name.as_str() {
            "script_run" => self.script_run(progress).await,
            CALL_TOOL => self.generic_call(progress).await,
            "request_await" => {
                let id = id().request_id;
                self.await_tool(&id, progress).await
            }
            "request_status" => self.short(method::REQUEST_STATUS, id()).await,
            "request_cancel" => self.short(method::REQUEST_CANCEL, id()).await,
            "request_list" => self.short(method::REQUESTS_LIST, self.list_params()).await,
            // Without an instance the server answered these locally (PD-118).
            "ops_list" => {
                let params = OpsListParams {
                    instance: string_arg(args, "instance"),
                };
                self.short(method::OPS_LIST, params).await
            }
            "ops_describe" => {
                let params = OpsDescribeParams {
                    op_id: string_arg(args, "op_id").unwrap_or_default(),
                    instance: string_arg(args, "instance"),
                };
                self.short(method::OPS_DESCRIBE, params).await
            }
            "instances_list" => self.short(method::INSTANCES_LIST, EmptyParams {}).await,
            name => match op_for_tool(name) {
                Some(spec) => self.op_tool(spec.id, progress).await,
                None => unknown_tool(name),
            },
        }
    }

    // ---- the tools ----

    async fn op_tool(&self, op_id: &str, progress: &mut Progress) -> Envelope {
        let (params, reason, instance) = match split_op_args(self.call.args.clone()) {
            Ok(split) => split,
            Err(env) => return env,
        };
        let sp = SubmitParams {
            op_id: op_id.to_owned(),
            params,
            instance: self.or_default_instance(instance),
            reason,
        };
        self.submit_and_wait(method::REQUEST_SUBMIT, sp, progress)
            .await
    }

    async fn generic_call(&self, progress: &mut Progress) -> Envelope {
        let args = &self.call.args;
        let sp = SubmitParams {
            op_id: string_arg(args, "op_id").unwrap_or_default(),
            params: args
                .get("params")
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new())),
            instance: self.or_default_instance(string_arg(args, "instance")),
            reason: string_arg(args, "reason"),
        };
        self.submit_and_wait(method::REQUEST_SUBMIT, sp, progress)
            .await
    }

    /// §9.1: `{source, args, limits?, dry_run?}`; §4.4 + PD-124: a script names no instance.
    async fn script_run(&self, progress: &mut Progress) -> Envelope {
        let args = &self.call.args;
        let source = string_arg(args, "source").unwrap_or_default();
        let script_args = args
            .get("args")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));
        let dry_run = match args.get("dry_run").and_then(Value::as_str) {
            Some("full") => Some(DryRun::Full),
            Some("sparse") => Some(DryRun::Sparse),
            _ => None,
        };
        let sp = SubmitParams {
            op_id: SCRIPT_RUN.id.to_owned(),
            params: script_params(&source, &script_args, args.get("limits"), dry_run),
            instance: None,
            reason: string_arg(args, "reason"),
        };
        self.submit_and_wait(method::SCRIPT_SUBMIT, sp, progress)
            .await
    }

    async fn await_tool(&self, request_id: &str, progress: &mut Progress) -> Envelope {
        let client = match self.connect().await {
            Ok(client) => client,
            Err(env) => return env,
        };
        let base = pending_for(request_id, None);
        self.await_request(&client, request_id, &base, progress)
            .await
    }

    /// L66: the agent filter only from the tool's own `agent` argument; PD-124: a match without
    /// an instance gets the default one, so it recomputes the submit's `params_sha256`.
    fn list_params(&self) -> RequestsListParams {
        let args = &self.call.args;
        RequestsListParams {
            agent: string_arg(args, "agent"),
            state: args
                .get("state")
                .and_then(Value::as_str)
                .and_then(list_state),
            match_params: args
                .get("match_params")
                .and_then(Value::as_object)
                .map(|m| MatchParams {
                    op_id: string_arg(m, "op_id").unwrap_or_default(),
                    params: m
                        .get("params")
                        .cloned()
                        .unwrap_or_else(|| Value::Object(Map::new())),
                    instance: self.or_default_instance(string_arg(m, "instance")),
                }),
        }
    }

    // ---- the flow ----

    /// The shared connection. Every body reaches the app through here with the call's
    /// `clientInfo.name`: the hello freezes the agent name at the first attempt, whichever tool
    /// makes it (PD-122, L158).
    async fn connect(&self) -> Result<SharedClient, Envelope> {
        let client_name = self.call.client_name();
        let reached = self
            .shared
            .session
            .client(&self.deadline, client_name.as_deref());
        // Cancelled before anything was sent: nothing queued (the CLI's interrupt during
        // `reach`). A launch already on its blocking thread runs on by itself.
        match self.unless_cancelled(reached).await {
            Some(reached) => reached,
            None => Err(*launch::launch_timeout()),
        }
    }

    /// Submit, then (unless `ATLAS_DUCK_MCP_TIMEOUT=0`) wait for the decision.
    async fn submit_and_wait(
        &self,
        name: &str,
        sp: SubmitParams,
        progress: &mut Progress,
    ) -> Envelope {
        let client = match self.connect().await {
            Ok(client) => client,
            Err(env) => return env,
        };
        // Not cancellable (PD-126): a submit runs to its answer, its deadline or the end of the
        // process, and whatever is answered is true. On a client's cancel rmcp drops the result,
        // so the agent recovers the request with `request_list {match_params}` (L160). A
        // deadline that passes before the writer took the frame is `launch_timeout` (nothing
        // queued); after it, the request may exist with an unknown id (PD-16, L63).
        let sent = client
            .call::<SubmitReply>(name, &sp, Some(bound(&self.deadline)))
            .await;
        let reply = match sent.result {
            Ok(reply) => reply,
            Err(e) => {
                self.note(&client, &e);
                return submit_error_for(e, sent.written, Front::Mcp);
            }
        };
        // L131: a `pending` reply without an id is the app's protocol error.
        let (envelope, _params_sha256) = match check_submit_reply(reply) {
            Ok(checked) => checked,
            Err(env) => return *env,
        };
        if envelope.status != Status::Pending {
            return envelope;
        }
        let Some(request_id) = envelope.request_id.clone() else {
            return protocol_failure();
        };
        // PD-127: no stderr notice in MCP mode; the id reaches the agent through the "submitted"
        // notification (PD-125) and the result. A call the client cancelled meanwhile hears
        // nothing more (PD-126).
        if !self.call.context.ct.is_cancelled() {
            progress.submitted(&request_id).await;
        }
        if self.zero_timeout() {
            return envelope;
        }
        self.await_request(&client, &request_id, &envelope, progress)
            .await
    }

    /// `request.await` for `id` with the time left as `timeout_ms`; `base` is the answer when the
    /// wait ends undecided.
    async fn await_request(
        &self,
        client: &SharedClient,
        id: &str,
        base: &Envelope,
        progress: &mut Progress,
    ) -> Envelope {
        let zero = self.zero_timeout();
        let params = AwaitParams {
            request_id: id.to_owned(),
            timeout_ms: Some(await_timeout_ms(&self.deadline, zero)),
        };
        // The app answers `pending` itself at `timeout_ms`; the slack leaves it time to.
        let at = bound(&self.deadline);
        let at = if zero {
            at
        } else {
            at.checked_add(AWAIT_SLACK).unwrap_or(at)
        };
        let mut on_progress = progress.relay();
        let waiting = client.call_with_progress::<Envelope>(
            method::REQUEST_AWAIT,
            params,
            Some(at),
            &mut on_progress,
        );
        // PD-125: status changes and heartbeats from the receipt while it waits. Cancelled:
        // stop waiting only (PD-126). The dropped call never tears the stream, and the request
        // lives on; rmcp drops this answer after a client's cancel and writes it at stdin EOF,
        // so it says what is true either way: still pending.
        let receipt = tokio::time::Instant::from_std(self.call.receipt);
        let Some(sent) = wait_with_progress(
            waiting,
            progress,
            receipt,
            self.shared.heartbeat_every,
            self.call.context.ct.cancelled(),
        )
        .await
        else {
            return base.clone();
        };
        match sent.result {
            // L131: an answer naming another request is not the answer to this one.
            Ok(env) => check_await_reply(id, env),
            Err(e) => {
                self.note(client, &e);
                await_error(e, id, base)
            }
        }
    }

    /// One call that never queues anything; bounded by its deadline (the app answers at once).
    async fn short<P: Serialize + Send>(&self, name: &str, params: P) -> Envelope {
        let client = match self.connect().await {
            Ok(client) => client,
            Err(env) => return env,
        };
        let sent = client
            .call::<Envelope>(name, params, Some(bound(&self.deadline)))
            .await;
        match sent.result {
            Ok(env) => env,
            Err(e) => {
                self.note(&client, &e);
                short_error_for(e, Front::Mcp)
            }
        }
    }

    // ---- helpers ----

    /// `fut`, unless the tool call is cancelled first (then `fut` is dropped).
    async fn unless_cancelled<T>(&self, fut: impl Future<Output = T>) -> Option<T> {
        tokio::select! {
            biased;
            () = self.call.context.ct.cancelled() => None,
            v = fut => Some(v),
        }
    }

    /// PD-128 / R1: only a lost connection closes the session (the next call reconnects, which
    /// starts a new approval session); a per-call error never does.
    fn note(&self, client: &SharedClient, e: &ClientError) {
        if matches!(e, ClientError::ConnectionLost) || client.is_closed() {
            self.shared.session.mark_closed();
        }
    }

    /// PD-124: `--instance` where the arguments name none.
    fn or_default_instance(&self, instance: Option<String>) -> Option<String> {
        instance.or_else(|| self.shared.cfg.instance.clone())
    }

    /// `ATLAS_DUCK_MCP_TIMEOUT=0`: return `pending` at once (L67).
    fn zero_timeout(&self) -> bool {
        self.shared.cfg.timeout.is_none()
    }
}

/// A string argument (the server checked its type).
fn string_arg(args: &Map<String, Value>, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(str::to_owned)
}
