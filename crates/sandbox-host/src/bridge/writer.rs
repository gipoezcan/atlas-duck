//! The bridge's writer thread (§3.4 "writes host-call results from a separate writer task"): the
//! only owner of the worker's stdin. It writes the frames queued on its channel, in order, and
//! closes stdin (the worker's EOF) when every sender is gone, which the bridge arranges once the
//! run is decided (T6: never earlier). A write that blocks because the worker does not read its
//! stdin blocks only this thread; the reader keeps draining.

use std::io::{self, Write};
use std::sync::mpsc::Receiver;
use std::thread;

use atlas_duck_ipc::sandbox::frame::write_frame;
use atlas_duck_ipc::sandbox::script::encode_response;
use atlas_duck_ipc::sandbox::{HOST_TO_WORKER_MAX, HostCallResult};
use serde_json::json;

/// §9.4 `max_call_result_mb` row: an over-size call result rejects inside the script with this
/// class.
pub(crate) const RESULT_TOO_LARGE: &str = "result_too_large";

/// Starts the writer thread over `stdin`.
pub(crate) fn spawn(mut stdin: Box<dyn Write + Send>, frames: Receiver<Vec<u8>>) -> io::Result<()> {
    thread::Builder::new()
        .name("sandbox-writer".to_owned())
        .spawn(move || {
            for frame in frames {
                // A failed write means the worker's end is gone; it is dying or dead, and the
                // reader and reaper report how it ended.
                if write_frame(&mut stdin, &frame).is_err() {
                    break;
                }
            }
        })?;
    Ok(())
}

/// The JSON-RPC response to call `id`. A response above the 24 MiB host → worker cap (§3.4)
/// would be refused by every reader; it cannot occur while `max_call_result_mb` ≤ 16 (PD-139),
/// and if it does the call rejects with `result_too_large` instead (the §9.4 rejection for a call
/// result above its cap), so the worker never gets an unreadable frame.
pub(crate) fn call_response(id: u64, result: &HostCallResult) -> Vec<u8> {
    let frame = encode_response(id, result);
    if frame.len() <= HOST_TO_WORKER_MAX {
        return frame;
    }
    encode_response(
        id,
        &HostCallResult::Rejected {
            class: RESULT_TOO_LARGE.to_owned(),
            details: json!({}),
        },
    )
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn a_response_above_the_host_cap_becomes_a_rejection() -> Result<(), serde_json::Error> {
        let small = call_response(3, &HostCallResult::Ok(json!({"a": 1})));
        let v: Value = serde_json::from_slice(&small)?;
        assert_eq!(
            v,
            json!({"jsonrpc": "2.0", "id": 3, "result": {"ok": {"a": 1}}})
        );

        let huge = HostCallResult::Ok(Value::String("x".repeat(HOST_TO_WORKER_MAX)));
        let replaced = call_response(4, &huge);
        let v: Value = serde_json::from_slice(&replaced)?;
        assert_eq!(
            v,
            json!({"jsonrpc": "2.0", "id": 4, "result": {"rejected": {"class": "result_too_large", "details": {}}}})
        );
        Ok(())
    }
}
