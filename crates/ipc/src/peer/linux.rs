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

    fn parent_and_start(&self, pid: u32) -> (Option<u32>, Option<u64>) {
        let stat = stat(pid);
        (stat.map(|(ppid, _)| ppid), stat.map(|(_, start)| start))
    }

    fn exe(&self, pid: u32) -> Option<PathBuf> {
        let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        Some(strip_deleted(path))
    }
}

/// `/proc/<pid>/exe` of a replaced or removed binary reads `<path> (deleted)`.
fn strip_deleted(path: PathBuf) -> PathBuf {
    match path.to_str().and_then(|s| s.strip_suffix(" (deleted)")) {
        Some(stripped) => PathBuf::from(stripped),
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::strip_deleted;
    use crate::peer::is_skipped_hop;

    #[test]
    fn deleted_suffix_is_stripped_before_skip_check() {
        let p = strip_deleted(PathBuf::from("/opt/atlas/atlas-duck (deleted)"));
        assert_eq!(p, PathBuf::from("/opt/atlas/atlas-duck"));
        assert!(is_skipped_hop(&p));
        let q = PathBuf::from("/usr/bin/python3");
        assert_eq!(strip_deleted(q.clone()), q);
    }
}
