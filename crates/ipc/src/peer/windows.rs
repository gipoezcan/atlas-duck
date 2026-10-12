//! Windows: one Toolhelp snapshot per walk (`th32ParentProcessID`),
//! `GetProcessTimes` creation time and `QueryFullProcessImageNameW`, both via
//! `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` (PD-36).

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, FILETIME, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};

use super::PeerSource;

/// Holds the process snapshot of one walk: create a new instance per walk
/// (`OsPeerSource::default()`), or new processes are invisible to it.
/// `th32ParentProcessID` may name a reused pid; `peer_info`'s start-time rule
/// catches that.
#[derive(Debug, Default)]
pub struct OsPeerSource {
    parents: OnceLock<Option<HashMap<u32, u32>>>,
}

/// pid → parent pid for every process, from one Toolhelp snapshot.
fn snapshot_parents() -> Option<HashMap<u32, u32>> {
    // SAFETY: plain call; failure is INVALID_HANDLE_VALUE, checked below.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return None;
    }
    // SAFETY: a fresh snapshot handle that nothing else owns.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    let snapshot = snapshot.as_raw_handle() as HANDLE;

    // SAFETY: PROCESSENTRY32W is plain old data; all-zero is a valid value.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = u32::try_from(size_of::<PROCESSENTRY32W>()).ok()?;
    let mut parents = HashMap::new();
    // SAFETY: `snapshot` is live; `entry` is writable and its dwSize is set.
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while more {
        parents.insert(entry.th32ProcessID, entry.th32ParentProcessID);
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    if parents.is_empty() {
        return None;
    }
    Some(parents)
}

fn open_query(pid: u32) -> Option<OwnedHandle> {
    // SAFETY: plain call; a null result is checked below.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return None;
    }
    // SAFETY: a fresh process handle that nothing else owns.
    Some(unsafe { OwnedHandle::from_raw_handle(raw as _) })
}

const ZERO_FILETIME: FILETIME = FILETIME {
    dwLowDateTime: 0,
    dwHighDateTime: 0,
};

impl PeerSource for OsPeerSource {
    fn parent(&self, pid: u32) -> Option<u32> {
        self.parents
            .get_or_init(snapshot_parents)
            .as_ref()?
            .get(&pid)
            .copied()
    }

    fn start_time(&self, pid: u32) -> Option<u64> {
        let process = open_query(pid)?;
        let (mut created, mut exited, mut kernel, mut user) =
            (ZERO_FILETIME, ZERO_FILETIME, ZERO_FILETIME, ZERO_FILETIME);
        // SAFETY: `process` is live with PROCESS_QUERY_LIMITED_INFORMATION;
        // all four out-pointers are valid FILETIMEs.
        let ok = unsafe {
            GetProcessTimes(
                process.as_raw_handle() as HANDLE,
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        };
        if ok == 0 {
            return None;
        }
        Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    fn exe(&self, pid: u32) -> Option<PathBuf> {
        let process = open_query(pid)?;
        // Long-path aware: grow up to the 32767-character NT path limit.
        for cap in [1024usize, 32_768] {
            let mut buf = vec![0u16; cap];
            let mut len = u32::try_from(cap).ok()?;
            // SAFETY: `process` is live; `buf` is writable for `len` UTF-16
            // units and `len` is a valid in/out pointer.
            let ok = unsafe {
                QueryFullProcessImageNameW(
                    process.as_raw_handle() as HANDLE,
                    PROCESS_NAME_WIN32,
                    buf.as_mut_ptr(),
                    &mut len,
                )
            };
            if ok != 0 {
                let len = usize::try_from(len).ok().filter(|&n| n > 0 && n < cap)?;
                buf.truncate(len);
                return Some(PathBuf::from(OsString::from_wide(&buf)));
            }
            // SAFETY: plain call, reads this thread's last error.
            if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
                return None;
            }
        }
        None
    }
}
