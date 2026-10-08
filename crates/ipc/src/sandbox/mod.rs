//! Sandbox channel (spec §3.3, §3.4): framing limits, framing, probe-protocol types.

pub mod frame;
pub mod host_call;
pub mod limits;
pub mod probe;

pub use host_call::{HostCall, HostCallResult};
pub use limits::ScriptLimits;

/// §3.3: "max frame 24 MiB" on the IPC and sandbox channels; also the §3.4
/// host→worker cap. Counts payload bytes (the 4-byte header is not included).
pub const MAX_FRAME_BYTES: usize = 24 * 1024 * 1024;

/// §3.4: "worker→host frames ≤ 1 MiB" (the terminal-frame exception,
/// `max_result_mb` + 64 KiB, belongs to the script protocol in M8).
pub const WORKER_FRAME_MAX_BYTES: usize = 1024 * 1024;
