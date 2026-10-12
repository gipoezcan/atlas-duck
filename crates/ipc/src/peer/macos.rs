//! macOS: `proc_pidinfo(PROC_PIDTBSDINFO)` (ppid, start time), `proc_pidpath`,
//! and the `LOCAL_PEERPID`/`LOCAL_PEEREPID` socket options (PD-36, V07).

use std::ffi::OsString;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use libc::{c_int, c_void, pid_t, socklen_t};

use super::PeerSource;

/// Asks the kernel on every call. One instance per walk, like the other OSes.
#[derive(Debug, Default)]
pub struct OsPeerSource {
    _per_walk: (),
}

fn bsd_info(pid: u32) -> Option<libc::proc_bsdinfo> {
    let pid = c_int::try_from(pid).ok()?;
    let size = c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: `info` is writable for `size` bytes, the size of the struct
    // PROC_PIDTBSDINFO fills.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast::<c_void>(),
            size,
        )
    };
    if written != size {
        return None;
    }
    // SAFETY: zero-initialised and then filled completely; `proc_bsdinfo` is
    // plain old data, valid for any bit pattern.
    Some(unsafe { info.assume_init() })
}

impl PeerSource for OsPeerSource {
    fn parent(&self, pid: u32) -> Option<u32> {
        bsd_info(pid).map(|info| info.pbi_ppid)
    }

    fn start_time(&self, pid: u32) -> Option<u64> {
        let info = bsd_info(pid)?;
        info.pbi_start_tvsec
            .checked_mul(1_000_000)?
            .checked_add(info.pbi_start_tvusec)
    }

    fn exe(&self, pid: u32) -> Option<PathBuf> {
        let pid = c_int::try_from(pid).ok()?;
        let cap = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE).ok()?;
        let mut buf = vec![0u8; cap];
        let len = u32::try_from(buf.len()).ok()?;
        // SAFETY: `buf` is writable for `len` bytes.
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast::<c_void>(), len) };
        let n = usize::try_from(n)
            .ok()
            .filter(|&n| n > 0 && n <= buf.len())?;
        buf.truncate(n);
        Some(PathBuf::from(OsString::from_vec(buf)))
    }
}

fn local_pid_option(fd: BorrowedFd<'_>, option: c_int) -> Option<u32> {
    let mut pid: pid_t = 0;
    let mut len = socklen_t::try_from(size_of::<pid_t>()).ok()?;
    // SAFETY: `fd` is a live socket for the call; `pid` and `len` are valid
    // out-pointers and `len` holds the size of `pid`.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_LOCAL,
            option,
            (&raw mut pid).cast::<c_void>(),
            &mut len,
        )
    };
    if rc != 0 || usize::try_from(len).ok() != Some(size_of::<pid_t>()) {
        return None;
    }
    u32::try_from(pid).ok().filter(|&p| p > 0)
}

/// The effective peer pid (`LOCAL_PEEREPID`): for a connection made on
/// behalf of another process (XPC, `posix_spawn` helpers) the process it was
/// made for. Preferred over [`peer_pid`] (PD-36, V07). `None` once the peer
/// has closed or on any error.
pub fn peer_epid(fd: BorrowedFd<'_>) -> Option<u32> {
    local_pid_option(fd, libc::LOCAL_PEEREPID)
}

/// The peer pid that made the connection (`LOCAL_PEERPID`); the fallback when
/// [`peer_epid`] fails.
pub fn peer_pid(fd: BorrowedFd<'_>) -> Option<u32> {
    local_pid_option(fd, libc::LOCAL_PEERPID)
}
