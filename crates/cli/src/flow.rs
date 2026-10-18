//! The envelope rules of the connected flow, shared by the CLI (`connected`) and the MCP server
//! (§4.2, §4.3, §4.4): which envelope a connect failure, a lost connection, a submit that got no
//! reply or an await that got a wrong one turns into (PD-16, L63, L131, PD-08). Pure: no IO, no
//! deadline clock, so both front ends map results the same way and cannot drift.

use std::io;

use atlas_duck_ipc::client::{ClientError, ConnectError, UNKNOWN_BUILD};
use atlas_duck_ipc::envelope::{Envelope, EnvelopeError, ErrorCode, Status};
use atlas_duck_ipc::proto::SubmitReply;
use serde_json::{Map, Value, json};

use crate::argv::DryRun;
use crate::busy::connect_busy;
use crate::deadline::Deadline;
use crate::discover;
use crate::launch;

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
pub(crate) const MSG_DEADLINE_SHORT: &str =
    "the --timeout deadline expired before the atlas-duck app answered";
const MSG_PROTOCOL: &str = "the atlas-duck app broke the protocol";
const MSG_TOO_LARGE: &str = "the request is too large to send";
pub(crate) const MSG_INTERNAL: &str = "the request could not be sent";

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

pub(crate) fn not_running() -> Envelope {
    *launch::unreachable(discover::REASON_NOT_RUNNING, MSG_NOT_RUNNING)
}

fn lost_before_submit() -> Envelope {
    *launch::unreachable(discover::REASON_NOT_RUNNING, MSG_LOST_BEFORE_SUBMIT)
}

/// A `failed` `protocol_error` (exit 1): the app broke the protocol. Never echoes a request id.
pub(crate) fn protocol_failure() -> Envelope {
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
pub(crate) fn pending_for(request_id: &str, base: Option<&Envelope>) -> Envelope {
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
pub(crate) fn short_error(e: ClientError) -> Envelope {
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

/// What the agent gets when no reply to a submit arrived.
pub(crate) fn no_reply(written: bool) -> Envelope {
    if written {
        unknown_request_pending()
    } else {
        *launch::launch_timeout()
    }
}

/// A submit call that failed. An envelope from the app is its answer; any other failure after the
/// frame was written leaves a request that may exist, whose id is unknown: pending, exit 4.
pub(crate) fn submit_error(e: ClientError, written: bool) -> Envelope {
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
pub(crate) fn await_error(e: ClientError, id: &str, base: &Envelope) -> Envelope {
    match e {
        ClientError::Rpc(rpc) if rpc.data.is_some() => short_error(ClientError::Rpc(rpc)),
        ClientError::DeadlineExceeded => base.clone(),
        _ => connection_lost_pending(id, Some(base)),
    }
}

/// L83 / L131: a submit reply that is `pending` names the request; one without an id cannot be
/// awaited, noticed or recovered, so the app broke the protocol (`Err`: print that, exit 1). A
/// reply that is not pending is final and passes through. `Ok` carries the reply's envelope and
/// its `params_sha256`.
pub(crate) fn check_submit_reply(
    reply: SubmitReply,
) -> Result<(Envelope, Option<String>), Box<Envelope>> {
    if reply.envelope.status == Status::Pending && reply.envelope.request_id.is_none() {
        return Err(Box::new(protocol_failure()));
    }
    Ok((reply.envelope, reply.params_sha256))
}

/// L83 / L131: an answer naming another request is not the answer to `id`.
pub(crate) fn check_await_reply(id: &str, env: Envelope) -> Envelope {
    if env.request_id.as_deref().is_some_and(|got| got != id) {
        protocol_failure()
    } else {
        env
    }
}

/// The `timeout_ms` of a `request.await`: the time left on the deadline; 0 (answer at once) for an
/// unbounded deadline or when the caller does not wait (`zero_timeout`).
pub(crate) fn await_timeout_ms(deadline: &Deadline, zero_timeout: bool) -> u64 {
    match (zero_timeout, deadline.remaining()) {
        (true, _) | (_, None) => 0,
        (false, Some(left)) => u64::try_from(left.as_millis()).unwrap_or(u64::MAX),
    }
}

/// `script.run` params: `{source, args, limits?, dry_run?}` (`dry_run` is `"full"`/`"sparse"`).
pub(crate) fn script_params(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn code(env: &Envelope) -> Option<ErrorCode> {
        env.error.as_ref().map(|e| e.code)
    }

    #[test]
    fn pending_reply_without_id_is_protocol_error() {
        let mut env = pending_for("req_1", None);
        env.request_id = None;
        let reply = SubmitReply {
            envelope: env,
            params_sha256: Some("abc".to_owned()),
        };
        let Err(err) = check_submit_reply(reply) else {
            panic!("a pending reply without an id must be refused");
        };
        assert_eq!(code(&err), Some(ErrorCode::ProtocolError));
        assert_eq!(err.request_id, None);

        // With an id it passes, with the digest; a final reply passes untouched.
        let ok = SubmitReply {
            envelope: pending_for("req_1", None),
            params_sha256: Some("abc".to_owned()),
        };
        let Ok((env, sha)) = check_submit_reply(ok) else {
            panic!("a pending reply with an id must pass");
        };
        assert_eq!(env.request_id.as_deref(), Some("req_1"));
        assert_eq!(sha.as_deref(), Some("abc"));
        let mut done = pending_for("req_2", None);
        done.status = Status::Succeeded;
        let reply = SubmitReply {
            envelope: done,
            params_sha256: None,
        };
        assert!(
            matches!(check_submit_reply(reply), Ok((e, None)) if e.status == Status::Succeeded)
        );
    }

    #[test]
    fn await_reply_naming_another_request_is_protocol_error() {
        let mut other = pending_for("req_other", None);
        other.status = Status::Succeeded;
        let err = check_await_reply("req_1", other);
        assert_eq!(code(&err), Some(ErrorCode::ProtocolError));
        assert_eq!(err.request_id, None);

        let mut same = pending_for("req_1", None);
        same.status = Status::Succeeded;
        let env = check_await_reply("req_1", same);
        assert_eq!(env.status, Status::Succeeded);
        assert_eq!(env.request_id.as_deref(), Some("req_1"));
    }

    #[test]
    fn submit_lost_after_write_is_pending_unknown_id() {
        for e in [
            submit_error(ClientError::ConnectionLost, true),
            submit_error(ClientError::DeadlineExceeded, true),
            submit_error(ClientError::Protocol(String::new()), true),
            no_reply(true),
        ] {
            assert_eq!(e.status, Status::Pending, "{e:?}");
            assert_eq!(e.request_id, None, "{e:?}");
            assert_eq!(code(&e), Some(ErrorCode::Unreachable), "{e:?}");
        }
        // Before the frame was taken nothing was queued: not pending.
        let e = submit_error(ClientError::DeadlineExceeded, false);
        assert_ne!(e.status, Status::Pending);
    }

    #[test]
    fn await_timeout_is_zero_when_unbounded_or_not_waiting() {
        let unbounded = Deadline::from_timeout(std::time::Instant::now(), Some(0));
        assert_eq!(await_timeout_ms(&unbounded, false), 0);
        assert_eq!(await_timeout_ms(&unbounded, true), 0);
        let bounded = Deadline::new(
            std::time::Instant::now(),
            Some(std::time::Duration::from_secs(60)),
        );
        assert_eq!(await_timeout_ms(&bounded, true), 0);
        assert!(await_timeout_ms(&bounded, false) > 0);
    }
}
