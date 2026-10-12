//! Exit codes (§4.3). The matrix itself is `ipc::proto::exit_code`; this adds the one CLI rule
//! that depends on the command.

use atlas_duck_ipc::envelope::{Envelope, ErrorCode};
use atlas_duck_ipc::proto::exit_code;

use crate::argv::Command;

/// PD-20: `status` exits 0 whenever the request is known (the envelope carries its `request_id`
/// and is not `unknown_request`): the exit code answers "did the command work", the envelope
/// says what happened to the request. Everything else follows the generic matrix.
pub(crate) fn exit_for(cmd: &Command, env: &Envelope) -> i32 {
    if matches!(cmd, Command::Status { .. })
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
}
