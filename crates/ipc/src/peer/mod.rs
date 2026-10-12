//! Peer identity: the direct peer's pid and exe, and the walk up its
//! ancestors to the origin process (§3.1 "Peer origin", PD-36, §15 V07, V18).
//!
//! Best effort and advisory: used for display, grouping and fairness limits,
//! never as an authentication signal (§2.4). Every failure yields a partial
//! chain, never an error.

use std::path::{Path, PathBuf};

use crate::proto::{PeerHop, PeerInfo};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::OsPeerSource;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{OsPeerSource, peer_epid, peer_pid};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::OsPeerSource;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod other;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub use other::OsPeerSource;

/// Longest `peer_chain`, the direct peer included.
pub const MAX_HOPS: usize = 4;

/// Process lookups for the walk. `None` = the lookup failed (process gone,
/// not visible, unreadable); the walk then stops.
pub trait PeerSource: Send + Sync {
    fn parent(&self, pid: u32) -> Option<u32>;
    /// In OS-native units, only ever compared within one OS: Linux clock
    /// ticks since boot, macOS microseconds since the epoch, Windows FILETIME
    /// (100 ns since 1601).
    fn start_time(&self, pid: u32) -> Option<u64>;
    fn exe(&self, pid: u32) -> Option<PathBuf>;
}

/// File names (lowercase, `.exe` stripped) of hops the walk passes through:
/// atlas-duck itself, the AppImage runtime and shells (PD-36).
const SKIPPED_NAMES: &[&str] = &[
    "atlas-duck",
    "atlas-duck-app",
    "apprun",
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "cmd",
    "powershell",
    "pwsh",
];

/// Whether the walk passes through a process with this exe instead of taking
/// it as the origin (PD-36).
pub fn is_skipped_hop(exe: &Path) -> bool {
    if exe.to_string_lossy().starts_with("/tmp/.mount_") {
        return true;
    }
    let Some(name) = exe.file_name() else {
        return false;
    };
    let name = name.to_string_lossy().to_lowercase();
    let stem = name.strip_suffix(".exe").unwrap_or(&name);
    SKIPPED_NAMES.contains(&stem) || stem.ends_with(".appimage")
}

/// Walks from the direct peer up to [`MAX_HOPS`] processes. Each visited
/// process is recorded as a hop; the first one that is not skipped is the
/// origin and ends the walk. The walk also stops at pid 0/1, on a failed
/// lookup, and when a parent did not start strictly before its child (pid
/// reuse). Never fails.
pub fn peer_info(direct_pid: Option<u32>, src: &dyn PeerSource) -> PeerInfo {
    let mut info = PeerInfo {
        peer_pid: direct_pid,
        ..PeerInfo::default()
    };
    let Some(direct) = direct_pid else {
        return info;
    };
    info.peer_exe = src.exe(direct);

    let mut pid = direct;
    let mut child_start: Option<u64> = None;
    while info.peer_chain.len() < MAX_HOPS && pid > 1 {
        let Some(start_time) = src.start_time(pid) else {
            break;
        };
        if child_start.is_some_and(|child| start_time >= child) {
            break;
        }
        let exe = if info.peer_chain.is_empty() {
            info.peer_exe.clone()
        } else {
            src.exe(pid)
        };
        let Some(exe) = exe else {
            break;
        };
        // The pid may have been reused between the two lookups.
        if src.start_time(pid) != Some(start_time) {
            break;
        }
        let skipped = is_skipped_hop(&exe);
        info.peer_chain.push(PeerHop {
            pid,
            start_time,
            exe: exe.clone(),
        });
        if !skipped {
            info.peer_origin_exe = Some(exe);
            info.peer_origin_start_time = Some(start_time);
            break;
        }
        match src.parent(pid) {
            Some(parent) if parent != pid => {
                child_start = Some(start_time);
                pid = parent;
            }
            _ => break,
        }
    }
    info
}

/// `(ppid, starttime)` from a `/proc/<pid>/stat` line: fields 4 and 22, counted
/// after the last `)` because the command name may contain spaces and `)`.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_proc_stat(raw: &[u8]) -> Option<(u32, u64)> {
    let close = raw.iter().rposition(|&b| b == b')')?;
    let rest = std::str::from_utf8(raw.get(close + 1..)?).ok()?;
    // Field 3 (state) is the first one after the `)`.
    let mut fields = rest.split_ascii_whitespace();
    let ppid = fields.nth(1)?.parse().ok()?;
    let start = fields.nth(17)?.parse().ok()?;
    Some((ppid, start))
}

#[cfg(test)]
mod tests {
    use super::parse_proc_stat;

    #[test]
    fn proc_stat_parses_after_last_paren() {
        let line = b"4242 (we ird) (x)) S 4100 4242 4100 34816 4242 4194304 1 0 0 0 0 0 0 0 20 0 1 0 987654 1000 100 18446744073709551615";
        assert_eq!(parse_proc_stat(line), Some((4100, 987654)));
        let plain =
            b"1 (systemd) S 0 1 1 0 -1 4194560 1 2 3 4 5 6 7 8 20 0 1 0 12 170000000 3000\n";
        assert_eq!(parse_proc_stat(plain), Some((0, 12)));
    }

    #[test]
    fn proc_stat_rejects_garbage() {
        assert_eq!(parse_proc_stat(b""), None);
        assert_eq!(parse_proc_stat(b"12 no paren S 1 2"), None);
        assert_eq!(parse_proc_stat(b"12 (short) S 1 2 3"), None);
        assert_eq!(
            parse_proc_stat(b"12 (x) S -1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19"),
            None
        );
        assert_eq!(
            parse_proc_stat(b"12 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 zz"),
            None
        );
    }
}
