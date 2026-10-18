//! Process facts and Toolhelp/job helpers shared by the `cli_flows` and `mcp_flows` security cases
//! (S-02: the launched app is not part of the launcher's process tree, session or job). Included
//! with `#[path]` by both targets; each target uses only part of it.

// Kept after trying to drop it: `mcp_flows` does not use the job helpers (`Job`, `MAX_JOB_PIDS`)
// or `resume_threads`, which only the `cli_flows` job-close case needs.
#![allow(dead_code)]

#[cfg(target_os = "linux")]
use std::fs;

use crate::harness::Result;

/// The CI-only cases run with `CI=true` only; anywhere else they refuse (an error, not a skip).
pub fn ci_only(step: &str, ci: Option<&str>) -> Result<()> {
    if ci == Some("true") {
        Ok(())
    } else {
        Err(format!(
            "{step}: this test kills processes or uses a job object and runs only with CI=true"
        )
        .into())
    }
}

/// Process ids from `/proc/<pid>/stat` (`proc(5)`): the fields after the command name, which is in
/// parentheses and may itself contain spaces and `)`, so the split is at the LAST `)`. Fields 3..6
/// are state, ppid, pgrp, session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatIds {
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
}

pub fn parse_stat(text: &str) -> Option<StatIds> {
    let rest = text.get(text.rfind(')')? + 1..)?;
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    Some(StatIds {
        ppid: fields.next()?.parse().ok()?,
        pgrp: fields.next()?.parse().ok()?,
        session: fields.next()?.parse().ok()?,
    })
}

/// `szExeFile` of a Toolhelp entry: UTF-16 up to the first NUL.
pub fn utf16_until_nul(units: &[u16]) -> String {
    let len = units.iter().position(|u| *u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..len])
}

// ---- the process facts of another process ------------------------------------------------------------

/// What the OS says about a process: its parent, and on Unix its process group and session.
// Each OS fills and reads only some of it (Windows has no process group or session here).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcFacts {
    pub ppid: u32,
    /// Unix only.
    pub pgid: Option<u32>,
    pub session: Session,
}

// Each OS constructs only some of the variants.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session {
    Id(u32),
    /// macOS `getsid(pid)` refused with `EPERM`: if the OS refuses, the process is not in the
    /// caller's session (POSIX allows `EPERM` for another session; a process of the caller's own
    /// session always answers).
    OtherThanCallers,
    /// Windows: no session ids of this kind.
    None,
}

#[cfg(target_os = "linux")]
pub fn proc_facts(pid: u32) -> Result<ProcFacts> {
    // `/proc/<pid>/stat` is world-readable and shows ppid, pgrp and session even for a
    // non-dumpable process (only the memory and stack fields are hidden).
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|e| format!("/proc/{pid}/stat: {e}"))?;
    let ids = parse_stat(&text).ok_or_else(|| format!("/proc/{pid}/stat: {text:?}"))?;
    Ok(ProcFacts {
        ppid: ids.ppid,
        pgid: Some(ids.pgrp),
        session: Session::Id(ids.session),
    })
}

#[cfg(target_os = "macos")]
pub fn proc_facts(pid: u32) -> Result<ProcFacts> {
    let cpid = libc::c_int::try_from(pid)?;
    // SAFETY: an all-zero `proc_bsdinfo` is a valid value (plain integers and char arrays).
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>())?;
    // SAFETY: `info` is writable for `size` bytes; `PROC_PIDTBSDINFO` fills a `proc_bsdinfo`.
    let got = unsafe {
        libc::proc_pidinfo(
            cpid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&raw mut info).cast(),
            size,
        )
    };
    if got != size {
        return Err(format!(
            "proc_pidinfo({pid}, PROC_PIDTBSDINFO) returned {got} (want {size}): {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    // SAFETY: plain call.
    let sid = unsafe { libc::getsid(cpid) };
    let session = if sid >= 0 {
        Session::Id(u32::try_from(sid)?)
    } else {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EPERM) {
            Session::OtherThanCallers
        } else {
            return Err(format!("getsid({pid}): {e}").into());
        }
    };
    Ok(ProcFacts {
        ppid: info.pbi_ppid,
        pgid: Some(info.pbi_pgid),
        session,
    })
}

#[cfg(windows)]
pub fn proc_facts(pid: u32) -> Result<ProcFacts> {
    let all = win::processes()?;
    let me = all
        .iter()
        .find(|p| p.pid == pid)
        .ok_or_else(|| format!("pid {pid} is not in the process snapshot"))?;
    Ok(ProcFacts {
        ppid: me.ppid,
        pgid: None,
        session: Session::None,
    })
}

/// The test process's own session id (Unix).
#[cfg(unix)]
pub fn own_session() -> Result<u32> {
    // SAFETY: plain call; 0 is the caller.
    let sid = unsafe { libc::getsid(0) };
    if sid < 0 {
        return Err(format!("getsid(0): {}", std::io::Error::last_os_error()).into());
    }
    Ok(u32::try_from(sid)?)
}

/// The parent's name, for the messages (Windows: Toolhelp; elsewhere just the pid).
pub fn describe(pid: u32) -> String {
    #[cfg(windows)]
    {
        if let Ok(all) = win::processes()
            && let Some(p) = all.iter().find(|p| p.pid == pid)
        {
            return format!("{pid} ({})", p.exe);
        }
        format!("{pid} (not running)")
    }
    #[cfg(not(windows))]
    {
        pid.to_string()
    }
}

// ---- Windows: Toolhelp, threads, job objects ----------------------------------------------------------

#[cfg(windows)]
pub mod win {
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

    use windows_sys::Win32::Foundation::{FILETIME, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_BASIC_PROCESS_ID_LIST, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, QueryInformationJobObject,
        SetInformationJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, OpenThread, PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread,
        THREAD_SUSPEND_RESUME,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};

    use super::utf16_until_nul;

    /// The longest parent chain `live_ancestors` follows (a cycle guard).
    const MAX_ANCESTORS: usize = 64;

    /// The most process ids a job list query takes.
    const MAX_JOB_PIDS: usize = 1024;

    #[derive(Debug, Clone)]
    pub struct Proc {
        pub pid: u32,
        pub ppid: u32,
        pub exe: String,
    }

    fn size_u32<T>() -> u32 {
        u32::try_from(std::mem::size_of::<T>()).unwrap_or(u32::MAX)
    }

    fn snapshot(flags: u32) -> io::Result<OwnedHandle> {
        // SAFETY: plain call; failure is `INVALID_HANDLE_VALUE`, checked below.
        let h = unsafe { CreateToolhelp32Snapshot(flags, 0) };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh snapshot handle nothing else owns.
        Ok(unsafe { OwnedHandle::from_raw_handle(h) })
    }

    /// Every process now: pid, parent pid (the creator's, even after it ended: Windows does not
    /// reparent) and image name.
    pub fn processes() -> io::Result<Vec<Proc>> {
        let snap = snapshot(TH32CS_SNAPPROCESS)?;
        let mut entry = PROCESSENTRY32W {
            dwSize: size_u32::<PROCESSENTRY32W>(),
            ..Default::default()
        };
        let mut out = Vec::new();
        // SAFETY: `snap` is a live process snapshot; `entry` has its `dwSize` set.
        let mut ok = unsafe { Process32FirstW(snap.as_raw_handle(), &mut entry) };
        while ok != 0 {
            out.push(Proc {
                pid: entry.th32ProcessID,
                ppid: entry.th32ParentProcessID,
                exe: utf16_until_nul(&entry.szExeFile),
            });
            // SAFETY: as above.
            ok = unsafe { Process32NextW(snap.as_raw_handle(), &mut entry) };
        }
        Ok(out)
    }

    /// When `pid` was created (`GetProcessTimes`, FILETIME ticks). A pid can be reused, a creation
    /// time cannot go backwards: a parent created after its child is a reused pid.
    pub fn creation_time(pid: u32) -> io::Result<u64> {
        // SAFETY: plain call; null on failure.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh process handle nothing else owns.
        let h = unsafe { OwnedHandle::from_raw_handle(h) };
        let (mut created, mut exited, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        // SAFETY: a live process handle with query rights; four writable FILETIMEs.
        let ok = unsafe {
            GetProcessTimes(
                h.as_raw_handle(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    /// The live ancestors of `pid`, nearest first. Windows does not reparent, so a dead parent
    /// stays named by its child: the walk ends at a parent that is not in the process snapshot
    /// (the dead stub is the intended end), or that cannot be opened, or that was created after its
    /// child (a reused pid, not the real parent).
    pub fn live_ancestors(pid: u32) -> io::Result<Vec<Proc>> {
        let all = processes()?;
        let start = all
            .iter()
            .find(|p| p.pid == pid)
            .ok_or_else(|| io::Error::other(format!("process {pid} is not running")))?;
        let mut child_created = creation_time(pid)?;
        let mut next = start.ppid;
        let mut chain = Vec::new();
        while chain.len() < MAX_ANCESTORS {
            let Some(parent) = all.iter().find(|p| p.pid == next) else {
                break;
            };
            let Ok(created) = creation_time(parent.pid) else {
                break;
            };
            if created > child_created {
                break;
            }
            chain.push(parent.clone());
            child_created = created;
            next = parent.ppid;
        }
        Ok(chain)
    }

    /// The transitive descendants of `root` by parent pid in `all`, each created no earlier than
    /// its parent (a stale parent pid of a reused id is skipped). A process that cannot be read is
    /// an error: the caller must not guess.
    pub fn descendants(all: &[Proc], root: u32) -> io::Result<Vec<Proc>> {
        let mut out: Vec<Proc> = Vec::new();
        let mut open = vec![(root, creation_time(root)?)];
        while let Some((parent, parent_created)) = open.pop() {
            for p in all.iter().filter(|p| p.ppid == parent && p.pid != parent) {
                if out.iter().any(|q| q.pid == p.pid) {
                    continue;
                }
                let created = creation_time(p.pid).map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("creation time of {} {}: {e}", p.pid, p.exe),
                    )
                })?;
                if created >= parent_created {
                    out.push(p.clone());
                    open.push((p.pid, created));
                }
            }
        }
        Ok(out)
    }

    /// Whether the desktop has a shell window (`GetShellWindow`): launch step 1 takes its process
    /// as the app's parent.
    pub fn has_shell_window() -> bool {
        // SAFETY: plain call without arguments; null when there is no shell window.
        !unsafe { GetShellWindow() }.is_null()
    }

    /// The pid owning the shell window (`GetShellWindow`), if there is one: what launch step 1
    /// takes as the app's parent.
    pub fn shell_pid() -> Option<u32> {
        // SAFETY: no arguments; null when this desktop has no shell.
        let hwnd = unsafe { GetShellWindow() };
        if hwnd.is_null() {
            return None;
        }
        let mut pid = 0u32;
        // SAFETY: a stale `hwnd` makes the call return 0; `pid` is a local out-parameter.
        let tid = unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
        (tid != 0 && pid != 0).then_some(pid)
    }

    /// `ResumeThread` on every thread of `pid` (a process created suspended has one); returns how
    /// many were resumed.
    pub fn resume_threads(pid: u32) -> io::Result<usize> {
        let snap = snapshot(TH32CS_SNAPTHREAD)?;
        let mut entry = THREADENTRY32 {
            dwSize: size_u32::<THREADENTRY32>(),
            ..Default::default()
        };
        let mut resumed = 0;
        // SAFETY: `snap` is a live thread snapshot; `entry` has its `dwSize` set.
        let mut ok = unsafe { Thread32First(snap.as_raw_handle(), &mut entry) };
        while ok != 0 {
            if entry.th32OwnerProcessID == pid {
                // SAFETY: plain call; null on failure.
                let t = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if t.is_null() {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: a fresh thread handle nothing else owns.
                let t = unsafe { OwnedHandle::from_raw_handle(t) };
                // SAFETY: a live thread handle with THREAD_SUSPEND_RESUME.
                if unsafe { ResumeThread(t.as_raw_handle()) } == u32::MAX {
                    return Err(io::Error::last_os_error());
                }
                resumed += 1;
            }
            // SAFETY: as above.
            ok = unsafe { Thread32Next(snap.as_raw_handle(), &mut entry) };
        }
        Ok(resumed)
    }

    /// A job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and no breakaway flag; dropping it
    /// closes the last handle, which ends every process in it.
    pub struct Job(OwnedHandle);

    impl Job {
        pub fn kill_on_close() -> io::Result<Job> {
            // SAFETY: plain call; null on failure.
            let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if h.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: a fresh job handle nothing else owns.
            let job = Job(unsafe { OwnedHandle::from_raw_handle(h) });
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            // Deliberately no JOB_OBJECT_LIMIT_BREAKAWAY_OK / SILENT_BREAKAWAY_OK.
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: `info` is a local of the stated size and class.
            let set = unsafe {
                SetInformationJobObject(
                    job.raw(),
                    JobObjectExtendedLimitInformation,
                    (&raw const info).cast(),
                    size_u32::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(),
                )
            };
            if set == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        fn raw(&self) -> HANDLE {
            self.0.as_raw_handle()
        }

        pub fn assign(&self, process: RawHandle) -> io::Result<()> {
            // SAFETY: both handles are live (the process handle belongs to the caller's child).
            if unsafe { AssignProcessToJobObject(self.raw(), process) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// `QueryInformationJobObject(JobObjectBasicProcessIdList)`: the live processes in the job.
        pub fn pids(&self) -> io::Result<Vec<u32>> {
            let header = std::mem::size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>();
            let words = header / std::mem::size_of::<usize>() + MAX_JOB_PIDS;
            // `usize` words: the alignment of the struct's `ProcessIdList: [usize; 1]`.
            let mut buf = vec![0usize; words];
            let bytes = u32::try_from(words * std::mem::size_of::<usize>())
                .map_err(|_| io::Error::other("job list buffer too large"))?;
            let list = buf.as_mut_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>();
            // SAFETY: `buf` is writable for `bytes` bytes and aligned for the struct.
            let ok = unsafe {
                QueryInformationJobObject(
                    self.raw(),
                    JobObjectBasicProcessIdList,
                    list.cast(),
                    bytes,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                // ERROR_MORE_DATA only above MAX_JOB_PIDS processes.
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the call filled the header; `n` ids follow it inside `buf`.
            let (n, ids) = unsafe {
                (
                    (*list).NumberOfProcessIdsInList as usize,
                    std::ptr::addr_of!((*list).ProcessIdList).cast::<usize>(),
                )
            };
            if n > MAX_JOB_PIDS {
                return Err(io::Error::other(format!("{n} ids in the job list")));
            }
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                // SAFETY: `i < n <= MAX_JOB_PIDS`, all inside `buf`.
                let id = unsafe { *ids.add(i) };
                out.push(u32::try_from(id).map_err(|_| io::Error::other("pid over u32"))?);
            }
            Ok(out)
        }
    }
}

// ---- unit tests ------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_only_needs_ci_true() -> Result<()> {
        ci_only("CI: test step", Some("true"))?;
        for v in [None, Some(""), Some("1"), Some("TRUE"), Some("yes")] {
            let e = ci_only("CI: test step", v).err().ok_or("accepted")?;
            assert!(e.to_string().contains("CI: test step"), "{e}");
        }
        Ok(())
    }

    #[test]
    fn stat_fields_after_the_last_paren() {
        let line = "4242 (atlas-duck-app) S 1 4240 4240 0 -1 4194560 812 0 0 0 3 1 0 0 20 0 9";
        assert_eq!(
            parse_stat(line),
            Some(StatIds {
                ppid: 1,
                pgrp: 4240,
                session: 4240
            })
        );
        // A command name with spaces and a `)` of its own.
        let odd = "77 (a) b (c)) R 12 13 14 0 -1";
        assert_eq!(
            parse_stat(odd),
            Some(StatIds {
                ppid: 12,
                pgrp: 13,
                session: 14
            })
        );
        assert_eq!(parse_stat(""), None);
        assert_eq!(parse_stat("1 (x) S 1 2"), None);
        assert_eq!(parse_stat("1 (x) S a 2 3"), None);
        assert_eq!(parse_stat("no parens S 1 2 3"), None);
    }

    #[test]
    fn exe_names_end_at_the_first_nul() {
        let mut units = [0u16; 16];
        for (i, u) in "cmd.exe".encode_utf16().enumerate() {
            units[i] = u;
        }
        assert_eq!(utf16_until_nul(&units), "cmd.exe");
        let full: Vec<u16> = "abc".encode_utf16().collect();
        assert_eq!(utf16_until_nul(&full), "abc");
        assert_eq!(utf16_until_nul(&[]), "");
    }
}
