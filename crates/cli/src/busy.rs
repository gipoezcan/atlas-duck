//! `busy` from the connect step (§3.3, §4.7, L44): exit 11, never a launch.

use atlas_duck_ipc::client::ConnectError;
use atlas_duck_ipc::envelope::Envelope;
use atlas_duck_ipc::proto::{BUSY_RETRY_CONNECTION_S, busy_envelope};

/// The `busy` envelope for a connect failure that means busy, else `None`. CLI-local busy (Windows
/// `ERROR_PIPE_BUSY` after the 5 s `WaitNamedPipeW`, Unix `EAGAIN`) carries the constant
/// `retry_after_s: 5` and nothing else (RF-2); the server's connection-limit refusal (PD-27)
/// carries the server's value.
pub(crate) fn connect_busy(e: &ConnectError) -> Option<Envelope> {
    match e {
        ConnectError::PipeBusy => Some(busy_envelope(BUSY_RETRY_CONNECTION_S)),
        ConnectError::Busy { retry_after_s } => Some(busy_envelope(*retry_after_s)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use atlas_duck_ipc::envelope::{ErrorCode, Status};
    use atlas_duck_ipc::proto::exit_code;
    use serde_json::{Map, Value};

    use super::*;

    #[test]
    fn rf2_cli_local_busy_constant() {
        let env = connect_busy(&ConnectError::PipeBusy).unwrap();
        assert_eq!(env.status, Status::Failed);
        assert_eq!(env.request_id, None);
        let err = env.error.as_ref().unwrap();
        assert_eq!(err.code, ErrorCode::Busy);
        assert!(err.retryable);
        let mut only = Map::new();
        only.insert("retry_after_s".to_owned(), Value::from(5u64));
        assert_eq!(err.details, Some(only), "exactly {{retry_after_s: 5}}");
        assert_eq!(exit_code(&env), 11);
    }

    #[test]
    fn server_busy_keeps_its_value_and_nothing_else_is_busy() {
        let env = connect_busy(&ConnectError::Busy { retry_after_s: 30 }).unwrap();
        assert_eq!(exit_code(&env), 11);
        assert_eq!(
            env.error
                .and_then(|e| e.details)
                .and_then(|d| d.get("retry_after_s").cloned()),
            Some(Value::from(30u64))
        );
        for other in [
            ConnectError::NotRunning,
            ConnectError::ServerIdentity,
            ConnectError::DeadlineExceeded,
        ] {
            assert!(connect_busy(&other).is_none(), "{other}");
        }
    }
}
