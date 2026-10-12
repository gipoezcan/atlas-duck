//! Linux: `/proc/<pid>/stat` (ppid, start ticks) and `/proc/<pid>/exe` (PD-36).

use std::path::PathBuf;

use super::{PeerSource, parse_proc_stat};

/// Reads `/proc` on every call. One instance per walk, like the other OSes.
#[derive(Debug, Default)]
pub struct OsPeerSource {
    _per_walk: (),
}

fn stat(pid: u32) -> Option<(u32, u64)> {
    let raw = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    parse_proc_stat(&raw)
}

impl PeerSource for OsPeerSource {
    fn parent(&self, pid: u32) -> Option<u32> {
        stat(pid).map(|(ppid, _)| ppid)
    }

    fn start_time(&self, pid: u32) -> Option<u64> {
        stat(pid).map(|(_, start)| start)
    }

    fn exe(&self, pid: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
}
