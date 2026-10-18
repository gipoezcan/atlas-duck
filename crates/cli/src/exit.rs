//! Exit codes (§4.3). The matrix itself is `ipc::proto::exit_code`; this adds the one CLI rule
//! that depends on the command.

use atlas_duck_ipc::envelope::{Envelope, ErrorCode};
use atlas_duck_ipc::proto::exit_code;

use crate::argv::Command;

/// PD-20: `status` exits 0 whenever the request is known (the envelope carries its `request_id`
/// and is not `unknown_request`): the exit code answers "did the command work", the envelope
/// says what happened to the request. Everything else follows the generic matrix.
pub(crate) fn exit_for(cmd: &Command, env: &Envelope) -> i32 {
    let kind = match cmd {
        Command::Op { .. } | Command::Call { .. } | Command::ScriptRun { .. } => CallKind::Submit,
        Command::Await { .. } => CallKind::Await,
        Command::Status { .. } => CallKind::Status,
        _ => CallKind::Short,
    };
    exit_for_kind(kind, env)
}

/// The kinds of call whose exit code differs only for `status` (§4.4); MCP maps its results
/// through this without building a `Command`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallKind {
    Submit,
    Await,
    Status,
    Short,
}

/// [`exit_for`] by kind of call.
pub(crate) fn exit_for_kind(kind: CallKind, env: &Envelope) -> i32 {
    if kind == CallKind::Status
        && env.request_id.is_some()
        && env.error.as_ref().map(|e| e.code) != Some(ErrorCode::UnknownRequest)
    {
        return 0;
    }
    exit_code(env)
}

#[cfg(test)]
mod tests {
    use atlas_duck_ipc::envelope::Status;

    use super::*;

    fn status_cmd() -> Command {
        Command::Status { id: "req_1".into() }
    }

    fn env(status: Status, code: Option<ErrorCode>, id: Option<&str>) -> Envelope {
        let mut e = match code {
            Some(c) => Envelope::failed(c, false, "m"),
            None => Envelope::failed(ErrorCode::Internal, false, "m"),
        };
        e.status = status;
        if code.is_none() {
            e.error = None;
        }
        e.request_id = id.map(str::to_owned);
        e
    }

    #[test]
    fn status_exit_override() {
        let released = env(Status::Released, None, Some("req_1"));
        assert_eq!(exit_for(&status_cmd(), &released), 0);
        let failed = env(Status::Failed, Some(ErrorCode::UpstreamHttp), Some("req_1"));
        assert_eq!(exit_for(&status_cmd(), &failed), 0);
        let unknown = env(Status::Failed, Some(ErrorCode::UnknownRequest), None);
        assert_eq!(exit_for(&status_cmd(), &unknown), 2);
        // Even with an id echoed back, unknown_request stays a usage-class exit.
        let unknown_with_id = env(
            Status::Failed,
            Some(ErrorCode::UnknownRequest),
            Some("req_9"),
        );
        assert_eq!(exit_for(&status_cmd(), &unknown_with_id), 2);
    }

    #[test]
    fn other_commands_use_the_generic_matrix() {
        let failed = env(Status::Failed, Some(ErrorCode::UpstreamHttp), Some("req_1"));
        assert_eq!(
            exit_for(&Command::Cancel { id: "req_1".into() }, &failed),
            6
        );
        let released = env(Status::Released, None, Some("req_1"));
        assert_eq!(
            exit_for(&Command::Await { id: "req_1".into() }, &released),
            0
        );
        // A status call that never reached the app is not "known".
        let down = env(Status::Failed, Some(ErrorCode::Unreachable), None);
        assert_eq!(exit_for(&status_cmd(), &down), 5);
    }

    /// M9 Δ4 (L217): `unreachable` with the reason `store_unavailable` (the app's failed-store
    /// gate, not retryable) is exit 5 for every kind of call; the CLI code is unchanged.
    #[test]
    fn store_unavailable_is_exit_5() {
        let down = app_row(
            Status::Failed,
            Some(ErrorCode::Unreachable),
            Some("store_unavailable"),
        );
        assert_eq!(exit_for(&Command::Instances, &down), 5);
        assert_eq!(exit_for(&status_cmd(), &down), 5);
        assert_eq!(exit_for(&Command::Await { id: "req_1".into() }, &down), 5);
        assert_eq!(exit_for_kind(CallKind::Submit, &down), 5);
    }

    // ---------- I-39: the §4.3 matrix, every row ----------

    use serde_json::{Map, Value, json};

    /// An envelope as the app would send it for one row (only `exit_for` is asserted on these:
    /// their `retryable` is pinned by core's M3 tests and `i39_real_envelopes_match_matrix`, T23).
    fn app_row(status: Status, code: Option<ErrorCode>, reason: Option<&str>) -> Envelope {
        let mut e = env(status, code, None);
        if let (Some(r), Some(err)) = (reason, e.error.as_mut()) {
            let mut d = Map::new();
            d.insert("reason".to_owned(), Value::from(r));
            err.details = Some(d);
        }
        e
    }

    fn with_script_error(mut e: Envelope) -> Envelope {
        e.data = Some(json!({"script_error": {"class": "Error"}}));
        e
    }

    #[test]
    fn i39_exit_matrix_every_row() {
        use ErrorCode as C;
        use Status as S;
        let generic = Command::Instances;
        let mut app: Vec<(Envelope, i32, &str)> = vec![
            (app_row(S::Pending, None, None), 4, "pending"),
            (app_row(S::Executing, None, None), 4, "executing"),
            (app_row(S::Succeeded, None, None), 0, "succeeded"),
            (app_row(S::Released, None, None), 0, "released"),
            (
                with_script_error(app_row(S::Succeeded, None, None)),
                8,
                "dry run with script_error",
            ),
            (
                with_script_error(app_row(S::Released, None, None)),
                8,
                "released script_error",
            ),
            (app_row(S::Expired, Some(C::Expired), None), 7, "expired"),
            (
                app_row(S::Abandoned, Some(C::Abandoned), None),
                7,
                "abandoned",
            ),
            (
                app_row(S::OutcomeUnknown, Some(C::UpstreamUnknownOutcome), None),
                6,
                "outcome_unknown",
            ),
        ];
        for code in [
            C::Denied,
            C::UpstreamHttp,
            C::UpstreamNetwork,
            C::UpstreamUnavailable,
            C::ResultTooLarge,
            C::ResolutionFailed,
        ] {
            app.push((app_row(S::Denied, Some(code), None), 3, "denied"));
        }
        for reason in ["by_client", "app_quit", "os_shutdown"] {
            app.push((
                app_row(S::Cancelled, Some(C::Cancelled), Some(reason)),
                7,
                "cancelled",
            ));
        }
        for code in [
            C::Internal,
            C::ProtocolError,
            C::AuditFailure,
            C::AuditStorageLow,
        ] {
            app.push((app_row(S::Failed, Some(code), None), 1, "failed 1"));
        }
        for code in [
            C::Usage,
            C::Validation,
            C::MarkdownPlaceholders,
            C::OpUnsupportedByInstance,
            C::UnknownRequest,
        ] {
            app.push((app_row(S::Failed, Some(code), None), 2, "failed 2"));
        }
        for reason in [
            "not_running",
            "launch_timeout",
            "no_gui_session",
            "launch_blocked_by_job",
            "app_upgraded",
            "app_shutting_down",
            "store_newer",
            "store_unavailable",
        ] {
            app.push((
                app_row(S::Failed, Some(C::Unreachable), Some(reason)),
                5,
                "unreachable",
            ));
        }
        for code in [C::ProtocolMismatch, C::ServerIdentity] {
            app.push((app_row(S::Failed, Some(code), None), 5, "failed 5"));
        }
        for (code, reason) in [
            (C::UpstreamNetwork, None),
            (C::UpstreamUnavailable, None),
            (C::UpstreamUnavailable, Some("identity_header_missing")),
            (C::UpstreamUnavailable, Some("identity_header_mismatch")),
            (C::UpstreamHttp, None),
            (C::ResultTooLarge, None),
            (C::UpstreamUnknownOutcome, None),
        ] {
            app.push((app_row(S::Failed, Some(code), reason), 6, "failed 6"));
        }
        for code in [C::ScriptSyntax, C::ScriptLimit, C::SandboxUnavailable] {
            app.push((app_row(S::Failed, Some(code), None), 8, "failed 8"));
        }
        app.push((
            app_row(S::Failed, Some(C::SandboxUnavailable), Some("app_upgraded")),
            8,
            "sandbox_unavailable app_upgraded",
        ));
        for reason in [
            "passphrase",
            "keychain_unavailable",
            "keychain_lost",
            "keyring_not_local",
        ] {
            app.push((
                app_row(S::Failed, Some(C::Locked), Some(reason)),
                9,
                "locked",
            ));
        }
        for reason in [
            "data_dir_missing",
            "data_dir_not_local",
            "config_unreadable",
            "insecure_scheme",
            "instance_unconfirmed",
            "first_run",
            "no_instance",
            "paths_unreadable",
            "data_dir_unusable",
        ] {
            app.push((
                app_row(S::Failed, Some(C::NotConfigured), Some(reason)),
                9,
                "not_configured",
            ));
        }
        app.push((
            app_row(S::Failed, Some(C::NeedsToken), None),
            9,
            "needs_token",
        ));
        // `result_evicted` is exit 10 whatever the status (any terminal).
        for status in [S::Released, S::Succeeded, S::Failed, S::Denied] {
            app.push((
                app_row(status, Some(C::ResultEvicted), None),
                10,
                "result_evicted",
            ));
        }
        app.push((app_row(S::Failed, Some(C::Busy), None), 11, "busy"));
        for (e, exit, label) in &app {
            assert_eq!(exit_for(&generic, e), *exit, "{label}: {e:?}");
        }

        // The rows the CLI produces itself, through its own constructors: status, code, reason,
        // exit and `retryable`.
        use crate::{connected, discover, launch};
        use atlas_duck_ipc::client::ConnectError;
        use atlas_duck_ipc::proto::{BUSY_RETRY_CONNECTION_S, busy_envelope};
        type CliRow = (Envelope, Status, ErrorCode, Option<&'static str>, i32, bool);
        let mut cli: Vec<CliRow> = vec![
            (
                connected::connection_lost_pending("req_1", None),
                S::Pending,
                C::Unreachable,
                Some("connection_lost"),
                4,
                false,
            ),
            (
                connected::unknown_request_pending(),
                S::Pending,
                C::Unreachable,
                Some("connection_lost"),
                4,
                false,
            ),
            (
                discover::app_not_found(),
                S::Failed,
                C::Unreachable,
                Some("not_running"),
                5,
                true,
            ),
            (
                *launch::launch_timeout(),
                S::Failed,
                C::Unreachable,
                Some("launch_timeout"),
                5,
                true,
            ),
            (
                *launch::no_gui_session(),
                S::Failed,
                C::Unreachable,
                Some("no_gui_session"),
                5,
                true,
            ),
            (
                *launch::launch_failed(&launch::LaunchError::BlockedByJob),
                S::Failed,
                C::Unreachable,
                Some("launch_blocked_by_job"),
                5,
                true,
            ),
            (
                connected::build_mismatch(true, "2.0.0+a", "1.0.0+b"),
                S::Failed,
                C::Unreachable,
                Some("app_upgraded"),
                5,
                true,
            ),
            (
                connected::build_mismatch(false, "1.0.0+a", "2.0.0+b"),
                S::Failed,
                C::ProtocolMismatch,
                None,
                5,
                true,
            ),
            (
                connected::connect_error(ConnectError::ServerIdentity),
                S::Failed,
                C::ServerIdentity,
                None,
                5,
                false,
            ),
            (
                connected::connect_error(ConnectError::NotRunning),
                S::Failed,
                C::Unreachable,
                Some("not_running"),
                5,
                true,
            ),
            (
                connected::connect_error(ConnectError::Protocol(String::new())),
                S::Failed,
                C::ProtocolError,
                None,
                1,
                false,
            ),
            (
                busy_envelope(BUSY_RETRY_CONNECTION_S),
                S::Failed,
                C::Busy,
                None,
                11,
                true,
            ),
            (
                connected::connect_error(ConnectError::PipeBusy),
                S::Failed,
                C::Busy,
                None,
                11,
                true,
            ),
            (
                *launch::first_run(),
                S::Failed,
                C::NotConfigured,
                Some("first_run"),
                9,
                true,
            ),
        ];
        for reason in [
            "paths_unreadable",
            "data_dir_unusable",
            "data_dir_missing",
            "data_dir_not_local",
        ] {
            cli.push((
                discover::refusal(reason),
                S::Failed,
                C::NotConfigured,
                Some(reason),
                9,
                true,
            ));
        }
        for (e, status, code, reason, exit, retryable) in &cli {
            let err = e.error.as_ref();
            assert_eq!(e.status, *status, "{e:?}");
            assert_eq!(err.map(|x| x.code), Some(*code), "{e:?}");
            assert_eq!(err.map(|x| x.retryable), Some(*retryable), "{e:?}");
            let got = err
                .and_then(|x| x.details.as_ref())
                .and_then(|d| d.get("reason"))
                .and_then(Value::as_str);
            assert_eq!(got, *reason, "{e:?}");
            assert_eq!(exit_for(&generic, e), *exit, "{e:?}");
        }
        // The pending rows carry no data; the one with an id carries it.
        let lost = connected::connection_lost_pending("req_1", None);
        assert_eq!(lost.request_id.as_deref(), Some("req_1"));
        assert_eq!(lost.data, None);
        assert_eq!(connected::unknown_request_pending().request_id, None);
    }
}
