//! The one exit-code rule that depends on the kind of call (§4.3, PD-20). The matrix itself is
//! `ipc::proto::exit_code`; the CLI's `exit` module re-exports these.

use atlas_duck_ipc::envelope::{Envelope, ErrorCode};
use atlas_duck_ipc::proto::exit_code;

/// The kinds of call whose exit code differs only for `status` (§4.4); MCP maps its results
/// through this without building a `Command`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    Submit,
    Await,
    Status,
    Short,
}

/// PD-20: `status` exits 0 whenever the request is known (the envelope carries its `request_id`
/// and is not `unknown_request`); every other kind follows the generic matrix.
pub fn exit_for_kind(kind: CallKind, env: &Envelope) -> i32 {
    if kind == CallKind::Status
        && env.request_id.is_some()
        && env.error.as_ref().map(|e| e.code) != Some(ErrorCode::UnknownRequest)
    {
        return 0;
    }
    exit_code(env)
}
