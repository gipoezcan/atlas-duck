//! Connected commands (§4.1, §4.3, §4.4, §4.7): discover, launch if needed, connect, then submit
//! and wait (`op`, `call`, `script run`) or make one short call (`await`, `status`, `cancel`,
//! `requests list`, `instances`, `ops ... --instance`, `doctor`).
//!
//! Everything before the submit frame is "nothing was queued" (exit 5); once the frame is written
//! the request may exist, and an interrupt, a lost connection or a stuck reply is printed as
//! `pending` (exit 4) and never cancels anything (PD-16). The outer deadline is wall-clock from
//! process start (PD-17); `--timeout 0` bounds the pre-submission steps by their own limits and
//! skips the wait after submission.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::client::{ClientContext, ClientError, ConnectError, IpcClient, UNKNOWN_BUILD};
use atlas_duck_ipc::envelope::{Envelope, EnvelopeError, ErrorCode, Status};
use atlas_duck_ipc::proto::{
    AwaitParams, ClientKind, Hello, ListState, MatchParams, SubmitParams, SubmitReply,
};
use atlas_duck_ipc::rpc::{
    EmptyParams, IdParams, OpsDescribeParams, OpsListParams, RequestsListParams, method,
};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::argv::{Command, DryRun, GlobalOpts};
use crate::busy::connect_busy;
use crate::deadline::Deadline;
use crate::discover::{self, Discovery};
use crate::interrupt::{BoxFuture, Interrupts, Never};
use crate::launch::{self, LaunchSys};

/// Bound for connect + hello and for each call when the deadline is unbounded (`--timeout 0`):
/// those steps have no limit of their own, and a hung app must not hang the CLI.
pub(crate) const OWN_LIMIT: Duration = Duration::from_secs(30);
/// How long past the deadline the client waits for the server's own pending answer to
/// `request.await` before it prints the pending envelope itself.
pub(crate) const AWAIT_SLACK: Duration = Duration::from_secs(2);

pub(crate) const REASON_CONNECTION_LOST: &str = "connection_lost";
pub(crate) const REASON_APP_UPGRADED: &str = "app_upgraded";
const MSG_NOT_RUNNING: &str = "the atlas-duck app is not running";
/// §3.2 (a).
pub(crate) const MSG_SERVER_IDENTITY: &str = "the atlas-duck endpoint is not owned by this user";
/// §3.3, verbatim.
pub(crate) const MSG_APP_UPGRADED: &str = "atlas-duck was upgraded; restart the app";
/// §4.3, verbatim (the `<id>` is literal: the id is in `request_id`).
pub(crate) const MSG_CONNECTION_LOST: &str = "use `await <id>`; the request may be `abandoned`";
/// PD-16 second half (ledger L63).
pub(crate) const MSG_CONNECTION_LOST_NO_ID: &str =
    "the request may have been queued; recover it with requests list --match-params-file";
const MSG_LOST_BEFORE_SUBMIT: &str =
    "the connection to the atlas-duck app was lost before an answer arrived";
const MSG_DEADLINE_SHORT: &str =
    "the --timeout deadline expired before the atlas-duck app answered";
const MSG_PROTOCOL: &str = "the atlas-duck app broke the protocol";
const MSG_TOO_LARGE: &str = "the request is too large to send";
const MSG_INTERNAL: &str = "the request could not be sent";
const MSG_NOT_CONNECTED: &str = "not a connected command";

/// How a connected command reaches the app: every OS-facing step, so tests can inject doubles
/// (the real one is `OsConnector`). Local commands never touch it.
pub(crate) trait Connector: Sync {
    /// What this machine says about the data dir and the app (§3.2). Cheap and synchronous.
    fn discover(&self) -> Discovery;
    /// The launch seam of `launch::ensure_running` (it blocks, so it runs on a blocking thread).
    fn launch_sys(&self) -> Arc<dyn LaunchSys + Send>;
    /// `IpcClient::connect` (tests: `connect_at` against a temp endpoint).
    fn connect<'a>(
        &'a self,
        ctx: &'a ClientContext,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<IpcClient, ConnectError>>;
    /// The interrupt source for a waiting command (PD-16); installed before connecting.
    fn interrupts(&self) -> Box<dyn Interrupts>;
    /// The §4.1 submission notice (PD-19); best effort.
    fn notice(&self, request_id: &str, params_sha256: Option<&str>);
}

/// The real OS.
pub(crate) struct OsConnector;

impl Connector for OsConnector {
    fn discover(&self) -> Discovery {
        discover::discover(&|k| std::env::var_os(k))
    }

    fn launch_sys(&self) -> Arc<dyn LaunchSys + Send> {
        Arc::new(launch::OsLaunchSys)
    }

    fn connect<'a>(
        &'a self,
        ctx: &'a ClientContext,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<IpcClient, ConnectError>> {
        Box::pin(IpcClient::connect(ctx, deadline))
    }

    fn interrupts(&self) -> Box<dyn Interrupts> {
        // A failed registration leaves the default signal behaviour: Ctrl-C then ends the
        // process, which is what the user asked for (the request, if queued, survives).
        match crate::interrupt::Guard::install() {
            Ok(guard) => Box::new(guard),
            Err(_) => Box::new(Never),
        }
    }

    fn notice(&self, request_id: &str, params_sha256: Option<&str>) {
        let _ = crate::output::write_notice(request_id, params_sha256);
    }
}

// ---------- envelopes the CLI builds itself ----------

fn with_details(mut env: Envelope, details: Map<String, Value>) -> Envelope {
    if let Some(err) = env.error.as_mut() {
        err.details = Some(details);
    }
    env
}

fn reason(reason: &str) -> Map<String, Value> {
    let mut d = Map::new();
    d.insert("reason".to_owned(), Value::from(reason));
    d
}

fn not_running() -> Envelope {
    *launch::unreachable(discover::REASON_NOT_RUNNING, MSG_NOT_RUNNING)
}

fn lost_before_submit() -> Envelope {
    *launch::unreachable(discover::REASON_NOT_RUNNING, MSG_LOST_BEFORE_SUBMIT)
}

/// A `failed` `protocol_error` (exit 1): the app broke the protocol. Never echoes a request id.
fn protocol_failure() -> Envelope {
    Envelope::failed(ErrorCode::ProtocolError, false, MSG_PROTOCOL)
}

/// §4.3 `pending` + `connection_lost`: the request exists (`request_id`), the connection dropped
/// after submission. `retryable: false` (use `await`), exit 4.
pub(crate) fn connection_lost_pending(request_id: &str, base: Option<&Envelope>) -> Envelope {
    let mut env = pending_for(request_id, base);
    env.error = Some(EnvelopeError {
        code: ErrorCode::Unreachable,
        retryable: false,
        message: MSG_CONNECTION_LOST.to_owned(),
        details: Some(reason(REASON_CONNECTION_LOST)),
    });
    env
}

/// PD-16 / L63: the frame was written but no reply came (interrupt, loss, stuck app): the request
/// may exist and its id is unknown. `pending`, `request_id: null`, exit 4.
pub(crate) fn unknown_request_pending() -> Envelope {
    let mut env = Envelope::failed(ErrorCode::Unreachable, false, MSG_CONNECTION_LOST_NO_ID);
    env.status = Status::Pending;
    with_details(env, reason(REASON_CONNECTION_LOST))
}

/// The pending envelope of a known request: from the submit reply when there is one, else just
/// the id.
fn pending_for(request_id: &str, base: Option<&Envelope>) -> Envelope {
    match base {
        Some(b) => {
            let mut env = b.clone();
            env.status = Status::Pending;
            env.request_id = Some(request_id.to_owned());
            env
        }
        None => {
            let mut env = Envelope::failed(ErrorCode::Internal, false, "");
            env.status = Status::Pending;
            env.error = None;
            env.request_id = Some(request_id.to_owned());
            env
        }
    }
}

/// PD-08 (§3.3): the two build-mismatch envelopes.
pub(crate) fn build_mismatch(
    client_newer: bool,
    client_build: &str,
    server_build: &str,
) -> Envelope {
    if client_newer {
        return with_details(
            Envelope::failed(ErrorCode::Unreachable, true, MSG_APP_UPGRADED),
            reason(REASON_APP_UPGRADED),
        );
    }
    let mut details = Map::new();
    details.insert("client_build".to_owned(), Value::from(client_build));
    details.insert("server_build".to_owned(), Value::from(server_build));
    let message = format!(
        "atlas-duck app ({}) differs from CLI ({}): quit and relaunch the app, or reinstall",
        version_label(server_build),
        version_label(client_build),
    );
    with_details(
        Envelope::failed(ErrorCode::ProtocolMismatch, true, &message),
        details,
    )
}

/// `v<version half>` of a build id; a refusal that named no build prints "unknown version".
fn version_label(build: &str) -> String {
    let half = build.split_once('+').map_or(build, |(v, _)| v);
    if half.is_empty() || half == UNKNOWN_BUILD {
        "unknown version".to_owned()
    } else {
        format!("v{half}")
    }
}

/// Every `ConnectError` that reaches the user (`NotRunning` only after the retry).
pub(crate) fn connect_error(e: ConnectError) -> Envelope {
    if let Some(busy) = connect_busy(&e) {
        return busy;
    }
    match e {
        ConnectError::NotRunning => not_running(),
        ConnectError::ServerIdentity => {
            Envelope::failed(ErrorCode::ServerIdentity, false, MSG_SERVER_IDENTITY)
        }
        ConnectError::DeadlineExceeded => *launch::launch_timeout(),
        ConnectError::BuildMismatch {
            client_newer,
            client_build,
            server_build,
        } => build_mismatch(client_newer, &client_build, &server_build),
        ConnectError::Hello(env) => env,
        ConnectError::Protocol(_) => protocol_failure(),
        ConnectError::Io(_) => Envelope::failed(ErrorCode::Internal, false, MSG_INTERNAL),
        // `connect_busy` took these.
        ConnectError::PipeBusy | ConnectError::Busy { .. } => {
            Envelope::failed(ErrorCode::Busy, true, "busy")
        }
    }
}

/// A call that gave no answer, outside the submit-wait flow (nothing here echoes a request id).
fn short_error(e: ClientError) -> Envelope {
    match e {
        ClientError::Rpc(rpc) => rpc.data.unwrap_or_else(protocol_failure),
        ClientError::ConnectionLost => lost_before_submit(),
        ClientError::Protocol(_) => protocol_failure(),
        ClientError::DeadlineExceeded => {
            *launch::unreachable(launch::REASON_LAUNCH_TIMEOUT, MSG_DEADLINE_SHORT)
        }
        ClientError::Io(e) if e.kind() == io::ErrorKind::InvalidInput => {
            Envelope::failed(ErrorCode::Usage, false, MSG_TOO_LARGE)
        }
        ClientError::Io(_) => Envelope::failed(ErrorCode::Internal, false, MSG_INTERNAL),
    }
}

// ---------- the flow ----------

enum Wait<T> {
    Done(T),
    Interrupted,
    TimedOut,
}

/// `fut` against the interrupt source and `at`. The interrupt wins a tie, and an `at` that has
/// already passed wins over `fut`: the sleep is polled first, so `fut` (whose first poll may write
/// the request frame) never starts after the deadline.
async fn guarded<T>(
    fut: impl std::future::Future<Output = T>,
    at: Instant,
    intr: &mut dyn Interrupts,
) -> Wait<T> {
    tokio::select! {
        biased;
        () = intr.next() => Wait::Interrupted,
        () = tokio::time::sleep_until(tokio::time::Instant::from_std(at)) => Wait::TimedOut,
        v = fut => Wait::Done(v),
    }
}

/// The instant a pre-submission step or a short call must be done by.
fn bound(deadline: &Deadline) -> Instant {
    deadline.at().unwrap_or_else(|| Instant::now() + OWN_LIMIT)
}

fn hello_for(opts: &GlobalOpts) -> Hello {
    let cwd_basename = std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default();
    Hello {
        build_id: BUILD_ID.to_owned(),
        client_kind: ClientKind::Cli,
        agent_name: opts.agent.clone(),
        agent_name_source: opts.agent_source,
        cwd_basename,
    }
}

/// Runs a connected command and returns the envelope to print.
pub(crate) async fn execute(
    cmd: &Command,
    opts: &GlobalOpts,
    deadline: &Deadline,
    connector: &dyn Connector,
) -> Envelope {
    // `doctor` merges the CLI's local checks into the app's answer and exits 0 without it (T17).
    if matches!(cmd, Command::Doctor) {
        return crate::doctor::execute(opts, deadline, connector).await;
    }
    let waits = matches!(
        cmd,
        Command::Op { .. }
            | Command::Call { .. }
            | Command::ScriptRun { .. }
            | Command::Await { .. }
    );
    let mut intr: Box<dyn Interrupts> = if waits {
        connector.interrupts()
    } else {
        Box::new(Never)
    };
    let mut client = match reach(connector, opts, deadline, &mut *intr).await {
        Ok(client) => client,
        Err(env) => return *env,
    };
    run(cmd, opts, deadline, connector, &mut client, &mut *intr).await
}

/// Discover, launch if needed, connect. `Err` is the envelope to print: nothing was queued.
pub(crate) async fn reach(
    connector: &dyn Connector,
    opts: &GlobalOpts,
    deadline: &Deadline,
    intr: &mut dyn Interrupts,
) -> Result<IpcClient, Box<Envelope>> {
    let hello = hello_for(opts);
    // The endpoint can vanish between the launch step's check and the connect: one more round.
    for attempt in 0..2 {
        let d = connector.discover();
        if d.host.is_empty() {
            // `host_name()` failed: nothing is pinned or findable (PD-07).
            return Err(Box::new(discover::refusal(
                discover::REASON_PATHS_UNREADABLE,
            )));
        }
        let host = d.host.clone();
        let sys = connector.launch_sys();
        let limit = *deadline;
        // `ensure_running` sleeps between polls: not on the runtime thread (the interrupt must
        // stay live), and an interrupted launch leaves its thread to end with the process.
        let launching =
            tokio::task::spawn_blocking(move || launch::ensure_running(&d, &limit, &*sys));
        let data_dir = tokio::select! {
            biased;
            () = intr.next() => return Err(launch::launch_timeout()),
            r = launching => match r {
                Ok(Ok(dir)) => dir,
                Ok(Err(env)) => return Err(env),
                Err(_) => return Err(Box::new(Envelope::failed(
                    ErrorCode::Internal,
                    false,
                    MSG_INTERNAL,
                ))),
            },
        };
        let ctx = ClientContext {
            data_dir,
            host,
            hello: hello.clone(),
        };
        let connected = tokio::select! {
            biased;
            () = intr.next() => return Err(launch::launch_timeout()),
            r = connector.connect(&ctx, bound(deadline)) => r,
        };
        match connected {
            Ok(client) => return Ok(client),
            Err(ConnectError::NotRunning) if attempt == 0 => {}
            Err(e) => return Err(Box::new(connect_error(e))),
        }
    }
    Err(Box::new(not_running()))
}

async fn run(
    cmd: &Command,
    opts: &GlobalOpts,
    deadline: &Deadline,
    connector: &dyn Connector,
    client: &mut IpcClient,
    intr: &mut dyn Interrupts,
) -> Envelope {
    let submit = |op_id: &str, params: Value| SubmitParams {
        op_id: op_id.to_owned(),
        params,
        instance: opts.instance.clone(),
        reason: opts.reason.clone(),
    };
    match cmd {
        Command::Op { op_id, params } | Command::Call { op_id, params } => {
            let sp = submit(op_id, params.clone());
            submit_wait(
                client,
                method::REQUEST_SUBMIT,
                sp,
                opts,
                deadline,
                connector,
                intr,
            )
            .await
        }
        Command::ScriptRun {
            source,
            args,
            limits,
            dry_run,
        } => {
            let sp = submit(
                atlas_duck_registry::SCRIPT_RUN.id,
                script_params(source, args, limits.as_ref(), *dry_run),
            );
            submit_wait(
                client,
                method::SCRIPT_SUBMIT,
                sp,
                opts,
                deadline,
                connector,
                intr,
            )
            .await
        }
        Command::Await { id } => {
            let base = pending_for(id, None);
            await_request(client, id, &base, opts, deadline, intr).await
        }
        Command::Status { id } => {
            short_call(
                client,
                method::REQUEST_STATUS,
                IdParams {
                    request_id: id.clone(),
                },
                deadline,
            )
            .await
        }
        Command::Cancel { id } => {
            short_call(
                client,
                method::REQUEST_CANCEL,
                IdParams {
                    request_id: id.clone(),
                },
                deadline,
            )
            .await
        }
        Command::RequestsList {
            agent,
            state,
            match_params,
        } => {
            let params = RequestsListParams {
                agent: agent.clone(),
                state: state.as_deref().and_then(list_state),
                match_params: match_params.as_ref().map(|m| MatchParams {
                    op_id: m.op_id.clone(),
                    params: m.params.clone(),
                    instance: m.instance.clone(),
                }),
            };
            short_call(client, method::REQUESTS_LIST, params, deadline).await
        }
        Command::Instances => {
            short_call(client, method::INSTANCES_LIST, EmptyParams {}, deadline).await
        }
        Command::OpsList { instance } => {
            let params = OpsListParams {
                instance: instance.clone(),
            };
            short_call(client, method::OPS_LIST, params, deadline).await
        }
        Command::OpsDescribe { op_id, instance } => {
            let params = OpsDescribeParams {
                op_id: op_id.clone(),
                instance: instance.clone(),
            };
            short_call(client, method::OPS_DESCRIBE, params, deadline).await
        }
        // `doctor` is answered by `doctor::execute` before the flow starts.
        Command::Doctor | Command::Help { .. } | Command::NotInThisBuild(_) => {
            Envelope::failed(ErrorCode::Internal, false, MSG_NOT_CONNECTED)
        }
    }
}

fn list_state(s: &str) -> Option<ListState> {
    match s {
        "pending" => Some(ListState::Pending),
        "recent" => Some(ListState::Recent),
        _ => None,
    }
}

/// `script.run` params: `{source, args, limits?, dry_run?}` (`dry_run` is `"full"`/`"sparse"`).
fn script_params(
    source: &str,
    args: &Value,
    limits: Option<&Value>,
    dry_run: Option<DryRun>,
) -> Value {
    let mut params = json!({ "source": source, "args": args });
    if let Some(map) = params.as_object_mut() {
        if let Some(limits) = limits {
            map.insert("limits".to_owned(), limits.clone());
        }
        match dry_run {
            Some(DryRun::Full) => {
                map.insert("dry_run".to_owned(), Value::from("full"));
            }
            Some(DryRun::Sparse) => {
                map.insert("dry_run".to_owned(), Value::from("sparse"));
            }
            None => {}
        }
    }
    params
}

pub(crate) async fn short_call<P: Serialize>(
    client: &mut IpcClient,
    name: &str,
    params: P,
    deadline: &Deadline,
) -> Envelope {
    match guarded(
        client.call::<Envelope>(name, params),
        bound(deadline),
        &mut Never,
    )
    .await
    {
        Wait::Done(Ok(env)) => env,
        Wait::Done(Err(e)) => short_error(e),
        Wait::TimedOut | Wait::Interrupted => {
            *launch::unreachable(launch::REASON_LAUNCH_TIMEOUT, MSG_DEADLINE_SHORT)
        }
    }
}

/// Submit, print the notice, then (unless `--timeout 0`) wait for the decision.
async fn submit_wait(
    client: &mut IpcClient,
    name: &str,
    sp: SubmitParams,
    opts: &GlobalOpts,
    deadline: &Deadline,
    connector: &dyn Connector,
    intr: &mut dyn Interrupts,
) -> Envelope {
    let waited = guarded(client.call::<SubmitReply>(name, &sp), bound(deadline), intr).await;
    let reply = match waited {
        Wait::Done(Ok(reply)) => reply,
        Wait::Done(Err(e)) => return submit_error(e, client.written_request()),
        // Interrupt or expiry before the frame was written: nothing was queued. After it: the
        // request may exist and no id came back (PD-16).
        Wait::Interrupted | Wait::TimedOut => return no_reply(client.written_request()),
    };
    let envelope = reply.envelope;
    let Some(request_id) = envelope.request_id.clone() else {
        return envelope;
    };
    if envelope.status != Status::Pending {
        return envelope;
    }
    // PD-19: only from the returned reply, before any wait.
    connector.notice(&request_id, reply.params_sha256.as_deref());
    if opts.timeout == Some(0) {
        return envelope;
    }
    await_request(client, &request_id, &envelope, opts, deadline, intr).await
}

/// What the agent gets when no reply to a submit arrived.
fn no_reply(written: bool) -> Envelope {
    if written {
        unknown_request_pending()
    } else {
        *launch::launch_timeout()
    }
}

/// A submit call that failed. An envelope from the app is its answer; any other failure after the
/// frame was written leaves a request that may exist, whose id is unknown: pending, exit 4.
fn submit_error(e: ClientError, written: bool) -> Envelope {
    match e {
        ClientError::Rpc(rpc) => match rpc.data {
            Some(env) => env,
            None if written => unknown_request_pending(),
            None => protocol_failure(),
        },
        ClientError::ConnectionLost if written => unknown_request_pending(),
        ClientError::ConnectionLost => lost_before_submit(),
        ClientError::DeadlineExceeded => no_reply(written),
        _ if written => unknown_request_pending(),
        other => short_error(other),
    }
}

/// An `await` call that failed. An envelope from the app is its answer; any other failure means
/// no answer came, and the request (its id is known) lives on: pending, exit 4, `await` again.
fn await_error(e: ClientError, id: &str, base: &Envelope) -> Envelope {
    match e {
        ClientError::Rpc(rpc) if rpc.data.is_some() => short_error(ClientError::Rpc(rpc)),
        ClientError::DeadlineExceeded => base.clone(),
        _ => connection_lost_pending(id, Some(base)),
    }
}

/// `request.await` for `id`; `base` is what to print when the wait ends undecided.
async fn await_request(
    client: &mut IpcClient,
    id: &str,
    base: &Envelope,
    opts: &GlobalOpts,
    deadline: &Deadline,
    intr: &mut dyn Interrupts,
) -> Envelope {
    let timeout_ms = match (opts.timeout, deadline.remaining()) {
        (Some(0), _) | (_, None) => 0,
        (_, Some(left)) => u64::try_from(left.as_millis()).unwrap_or(u64::MAX),
    };
    let params = AwaitParams {
        request_id: id.to_owned(),
        timeout_ms: Some(timeout_ms),
    };
    let at = bound(deadline);
    let at = if opts.timeout == Some(0) {
        at
    } else {
        at.checked_add(AWAIT_SLACK).unwrap_or(at)
    };
    match guarded(
        client.call::<Envelope>(method::REQUEST_AWAIT, params),
        at,
        intr,
    )
    .await
    {
        Wait::Done(Ok(env)) => env,
        Wait::Done(Err(e)) => await_error(e, id, base),
        // The wait ended undecided; the request lives on (`await` it again).
        Wait::Interrupted | Wait::TimedOut => base.clone(),
    }
}

#[cfg(test)]
mod tests;
