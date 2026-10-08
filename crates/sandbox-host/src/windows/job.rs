//! The job object (§9.4): `ACTIVE_PROCESS = 1`, `KILL_ON_JOB_CLOSE`,
//! `DIE_ON_UNHANDLED_EXCEPTION`, process memory limit, `UILIMIT_ALL`.
//!
//! Measured behaviour of `ACTIVE_PROCESS = 1` (T14 experiment, Windows 11): a
//! second `CreateProcess` by the worker fails with `ERROR_NOT_ENOUGH_QUOTA`
//! (1816); it does not succeed and get killed afterwards. T14's
//! `SpawnProcess` probe scores that code (and `ERROR_ACCESS_DENIED`) `Blocked`.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::null_mut;

use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_BASIC_PROCESS_ID_LIST, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicProcessIdList,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::SystemServices::JOB_OBJECT_UILIMIT_ALL;

/// Limits applied to a worker's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobLimits {
    /// `JOBOBJECT_EXTENDED_LIMIT_INFORMATION::ProcessMemoryLimit` (§9.4
    /// `process_mb`).
    pub process_memory_bytes: u64,
}

impl JobLimits {
    /// `process_mb` MiB.
    pub fn from_process_mb(process_mb: u32) -> Self {
        Self {
            process_memory_bytes: u64::from(process_mb) * 1024 * 1024,
        }
    }
}

/// What a job reports about itself (read back with `QueryInformationJobObject`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSnapshot {
    /// `LimitFlags`.
    pub limit_flags: u32,
    pub active_process_limit: u32,
    pub process_memory_limit: u64,
    /// `UIRestrictionsClass`.
    pub ui_restrictions: u32,
    /// Process ids currently in the job.
    pub pids: Vec<u32>,
}

impl JobSnapshot {
    pub const KILL_ON_JOB_CLOSE: u32 = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    pub const ACTIVE_PROCESS: u32 = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    pub const DIE_ON_UNHANDLED_EXCEPTION: u32 = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    pub const PROCESS_MEMORY: u32 = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    pub const UILIMIT_ALL: u32 = JOB_OBJECT_UILIMIT_ALL;
}

/// An unnamed job object. Closing the last handle kills every process in it
/// (`KILL_ON_JOB_CLOSE`).
pub(crate) struct Job(OwnedHandle);

impl Job {
    pub(crate) fn create(limits: JobLimits) -> io::Result<Self> {
        // SAFETY: no security attributes, no name.
        let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if h.is_null() {
            let err = io::Error::last_os_error();
            eprintln!("CreateJobObjectW failed: {err}");
            return Err(err);
        }
        // SAFETY: `h` is a fresh, owned job handle.
        let job = Self(unsafe { OwnedHandle::from_raw_handle(h as RawHandle) });

        // SAFETY: an all-zero JOBOBJECT_EXTENDED_LIMIT_INFORMATION is valid.
        let mut ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        ext.BasicLimitInformation.ActiveProcessLimit = 1;
        ext.ProcessMemoryLimit = usize::try_from(limits.process_memory_bytes).unwrap_or(usize::MAX);
        // SAFETY: `ext` is a valid structure of the size passed.
        let ok = unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                (&ext as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            eprintln!("SetInformationJobObject(extended limits) failed: {err}");
            return Err(err);
        }

        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_ALL,
        };
        // SAFETY: `ui` is a valid structure of the size passed.
        let ok = unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectBasicUIRestrictions,
                (&ui as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            eprintln!("SetInformationJobObject(UI restrictions) failed: {err}");
            return Err(err);
        }
        Ok(job)
    }

    pub(crate) fn raw(&self) -> *mut core::ffi::c_void {
        self.0.as_raw_handle().cast()
    }

    /// `TerminateJobObject`: kills every process in the job.
    pub(crate) fn terminate(&self) -> io::Result<()> {
        // SAFETY: valid job handle.
        if unsafe { TerminateJobObject(self.raw(), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> io::Result<JobSnapshot> {
        // SAFETY: all-zero is valid for these plain-data structures.
        let mut ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `ext` is writable and of the size passed.
        let ok = unsafe {
            QueryInformationJobObject(
                self.raw(),
                JobObjectExtendedLimitInformation,
                (&mut ext as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: 0,
        };
        // SAFETY: `ui` is writable and of the size passed.
        let ok = unsafe {
            QueryInformationJobObject(
                self.raw(),
                JobObjectBasicUIRestrictions,
                (&mut ui as *mut JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        // The header is followed by the id array; room for 16 ids.
        #[repr(C)]
        struct IdList {
            head: JOBOBJECT_BASIC_PROCESS_ID_LIST,
            more: [usize; 15],
        }
        // SAFETY: all-zero is valid for this plain-data structure.
        let mut list: IdList = unsafe { std::mem::zeroed() };
        // SAFETY: `list` is writable and of the size passed.
        let ok = unsafe {
            QueryInformationJobObject(
                self.raw(),
                JobObjectBasicProcessIdList,
                (&mut list as *mut IdList).cast(),
                std::mem::size_of::<IdList>() as u32,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let n = (list.head.NumberOfProcessIdsInList as usize).min(16);
        let base = list.head.ProcessIdList.as_ptr();
        // SAFETY: the id array starts at `ProcessIdList` and `n <= 16` entries
        // fit in `IdList`.
        let pids = (0..n).map(|i| unsafe { *base.add(i) } as u32).collect();

        Ok(JobSnapshot {
            limit_flags: ext.BasicLimitInformation.LimitFlags,
            active_process_limit: ext.BasicLimitInformation.ActiveProcessLimit,
            process_memory_limit: ext.ProcessMemoryLimit as u64,
            ui_restrictions: ui.UIRestrictionsClass,
            pids,
        })
    }
}
