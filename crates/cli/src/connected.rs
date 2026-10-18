//! Connected commands (§4.1, §4.3, §4.4, §4.7): discover, launch if needed, connect, then submit
//! and wait (`op`, `call`, `script run`) or make one short call (`await`, `status`, `cancel`,
//! `requests list`, `instances`, `ops ... --instance`, `doctor`).
//!
//! Everything before the submit frame is "nothing was queued" (exit 5); once the frame is written
//! the request may exist, and an interrupt, a lost connection or a stuck reply is printed as
//! `pending` (exit 4) and never cancels anything (PD-16). The outer deadline is wall-clock from
//! process start (PD-17); `--timeout 0` bounds the pre-submission steps by their own limits and
//! skips the wait after submission.

use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::client::{ClientContext, ConnectError, IpcClient};
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::proto::{
    AwaitParams, ClientKind, Hello, ListState, MatchParams, SubmitParams, SubmitReply,
};
use atlas_duck_ipc::rpc::{
    EmptyParams, IdParams, OpsDescribeParams, OpsListParams, RequestsListParams, method,
};
use serde::Serialize;
use serde_json::Value;

use crate::argv::{Command, GlobalOpts};
use crate::deadline::Deadline;
use crate::discover::{self, Discovery};
pub(crate) use crate::flow::connect_error;
use crate::flow::{
    MSG_DEADLINE_SHORT, MSG_INTERNAL, await_error, await_timeout_ms, check_await_reply,
    check_submit_reply, no_reply, not_running, pending_for, protocol_failure, script_params,
    short_error, submit_error,
};
use crate::interrupt::{BoxFuture, Interrupts, Never};
use crate::launch::{self, LaunchSys};

// The CLI-side mapping helpers live in `flow` (shared with the MCP server); the exit-code matrix
// tests and the flow tests reach them through this module.
#[cfg(test)]
pub(crate) use crate::flow::{
    MSG_CONNECTION_LOST_NO_ID, build_mismatch, connection_lost_pending, unknown_request_pending,
};

/// Bound for connect + hello and for each call when the deadline is unbounded (`--timeout 0`):
/// those steps have no limit of their own, and a hung app must not hang the CLI.
pub(crate) const OWN_LIMIT: Duration = Duration::from_secs(30);
/// How long past the deadline the client waits for the server's own pending answer to
/// `request.await` before it prints the pending envelope itself.
pub(crate) const AWAIT_SLACK: Duration = Duration::from_secs(2);

const MSG_NOT_CONNECTED: &str = "not a connected command";

/// How a connected command reaches the app: every OS-facing step, so tests can inject doubles
/// (the real one is `OsConnector`). Local commands never touch it.
pub(crate) trait Connector: Send + Sync {
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
        #[cfg(feature = "test-env")]
        if force_owner_mismatch(&|k| std::env::var_os(k)) {
            return Box::pin(connect_owner_mismatch(ctx, deadline));
        }
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

// ---------- test builds only: a forced server-owner mismatch (§13 S-01 "simulated") ----------

/// With `test-env` only: `=1` makes the server-owner check of every connect answer "mismatch",
/// standing in for an endpoint another account created (T25 `s01_squatter_pipe_cli_sends_nothing_e2e`).
/// Stricter, never weaker: the connect runs the same steps with a check that refuses every
/// server, so it can only turn an accepted server into `server_identity` (exit 5), never the
/// reverse.
#[cfg(any(test, feature = "test-env"))]
pub(crate) const ENV_FORCE_OWNER_MISMATCH: &str = "ATLAS_DUCK_TEST_FORCE_OWNER_MISMATCH";

/// Whether [`ENV_FORCE_OWNER_MISMATCH`] is exactly `1`.
#[cfg(any(test, feature = "test-env"))]
fn force_owner_mismatch(lookup: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    lookup(ENV_FORCE_OWNER_MISMATCH).is_some_and(|v| v == "1")
}

/// The owner check that refuses every server.
#[cfg(any(test, feature = "test-env"))]
struct NeverOwner;

#[cfg(all(any(test, feature = "test-env"), unix))]
impl atlas_duck_ipc::client::ServerCheck for NeverOwner {
    fn server_ok(&self, _peer: &atlas_duck_ipc::transport::unix::PeerCred) -> bool {
        false
    }
}

#[cfg(all(any(test, feature = "test-env"), windows))]
impl atlas_duck_ipc::client::ServerCheck for NeverOwner {
    fn owner_ok(&self, _client: &tokio::net::windows::named_pipe::NamedPipeClient) -> bool {
        false
    }
}

/// `IpcClient::connect` with [`NeverOwner`] in place of the current-user check: the same
/// endpoint (`endpoint_location`; Windows reads `<data>/endpoint` and checks the prefix), the
/// same open, then the refusal before any byte is written. (Its unit test runs on Windows only.)
#[cfg(any(all(test, windows), feature = "test-env"))]
async fn connect_owner_mismatch(
    ctx: &ClientContext,
    deadline: Instant,
) -> Result<IpcClient, ConnectError> {
    let location = atlas_duck_ipc::paths::endpoint_location(&ctx.data_dir, &ctx.host)
        .map_err(ConnectError::Io)?;
    IpcClient::connect_at(&location, &ctx.data_dir, &ctx.hello, &NeverOwner, deadline).await
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

/// The CLI's `hello` (the MCP server builds its own).
pub(crate) fn hello_for(opts: &GlobalOpts) -> Hello {
    Hello {
        build_id: BUILD_ID.to_owned(),
        client_kind: ClientKind::Cli,
        agent_name: opts.agent.clone(),
        agent_name_source: opts.agent_source,
        cwd_basename: cwd_basename(),
    }
}

/// The last component of the process's working directory (empty when it has none).
pub(crate) fn cwd_basename() -> String {
    std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default()
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
    let mut client = match reach(connector, &hello_for(opts), deadline, &mut *intr).await {
        Ok(client) => client,
        Err(env) => return *env,
    };
    run(cmd, opts, deadline, connector, &mut client, &mut *intr).await
}

/// Discover, launch if needed, connect. `Err` is the envelope to print: nothing was queued.
pub(crate) async fn reach(
    connector: &dyn Connector,
    hello: &Hello,
    deadline: &Deadline,
    intr: &mut dyn Interrupts,
) -> Result<IpcClient, Box<Envelope>> {
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
        // `doctor` is answered by `doctor::execute` before the flow starts; `mcp` is served by
        // `run`.
        Command::Doctor
        | Command::Help { .. }
        | Command::Mcp { .. }
        | Command::NotInThisBuild(_) => {
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

pub(crate) async fn short_call<P: Serialize>(
    client: &mut IpcClient,
    name: &str,
    params: P,
    deadline: &Deadline,
) -> Envelope {
    short_call_guarded(client, name, params, deadline, &mut Never).await
}

/// [`short_call`] that an interrupt ends too (`doctor`, whose handlers stay installed once
/// registered): the shape is the launch phase's, nothing was queued.
pub(crate) async fn short_call_guarded<P: Serialize>(
    client: &mut IpcClient,
    name: &str,
    params: P,
    deadline: &Deadline,
    intr: &mut dyn Interrupts,
) -> Envelope {
    match guarded(client.call::<Envelope>(name, params), bound(deadline), intr).await {
        Wait::Done(Ok(env)) => env,
        Wait::Done(Err(e)) => short_error(e),
        Wait::Interrupted => *launch::launch_timeout(),
        Wait::TimedOut => *launch::unreachable(launch::REASON_LAUNCH_TIMEOUT, MSG_DEADLINE_SHORT),
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
    // L83: a `pending` reply names the request; one without an id cannot be awaited, noticed
    // or recovered, so the app broke the protocol.
    let (envelope, params_sha256) = match check_submit_reply(reply) {
        Ok(checked) => checked,
        Err(env) => return *env,
    };
    if envelope.status != Status::Pending {
        return envelope;
    }
    let Some(request_id) = envelope.request_id.clone() else {
        return protocol_failure();
    };
    // PD-19: only from the returned reply, before any wait.
    connector.notice(&request_id, params_sha256.as_deref());
    if opts.timeout == Some(0) {
        return envelope;
    }
    await_request(client, &request_id, &envelope, opts, deadline, intr).await
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
    let params = AwaitParams {
        request_id: id.to_owned(),
        timeout_ms: Some(await_timeout_ms(deadline, opts.timeout == Some(0))),
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
        // L83: an answer naming another request is not the answer to this one.
        Wait::Done(Ok(env)) => check_await_reply(id, env),
        Wait::Done(Err(e)) => await_error(e, id, base),
        // The wait ended undecided; the request lives on (`await` it again).
        Wait::Interrupted | Wait::TimedOut => base.clone(),
    }
}

#[cfg(test)]
mod tests;
