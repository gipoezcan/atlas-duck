//! Heartbeat constants of a waiting tool call.

use std::time::Duration;

/// PD-125 (R11): the heartbeat period of a waiting tool call (the rig sets a short one).
pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(5);
