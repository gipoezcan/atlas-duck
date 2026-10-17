//! The Windows degraded spawner (§9.4, plan M8 Task 11): below the floor.
//!
//! §9.4: when the AppContainer cannot be used (ACEs missing, profile creation
//! blocked), "the only available configuration is then a lockdown token
//! (restricting SID = NULL SID, untrusted integrity, applied after startup) +
//! job object". A host cannot lower a running child's primary token, and a
//! process that runs on such a token from its first instruction cannot load
//! its DLLs, so the worker is started the standard way:
//!
//! 1. Two restricted versions of the host's own token
//!    ([`lockdown_plan`], [`startup_plan`]), both at low integrity:
//!    - the lockdown token, the worker's process token: no privileges but
//!      `SeChangeNotify`, every SID deny-only, one restricting SID, the NULL
//!      SID, which no object grants anything to;
//!    - the startup token, an impersonation token: no privileges but
//!      `SeChangeNotify`, restricted to the host's own enabled SIDs, so the
//!      loader can open what the host can. It is a restricted token because
//!      the process token is one, and at low integrity because a thread may
//!      not impersonate above its process.
//! 2. `CreateProcessAsUserW` with the lockdown token, suspended, with the
//!    floor's job object (`JOB_LIST`), three-handle list and detached console;
//!    the environment is §3.4's `SystemRoot` and `TZ` only, the working
//!    directory the system directory, the command line
//!    [`LOCKDOWN_TOKEN_ARG`]. No ACE check: this path is for when the ACEs
//!    cannot be relied on.
//! 3. `SetThreadToken` on the main thread with the startup token, then
//!    `ResumeThread`.
//! 4. The worker loads its DLLs on the startup token, calls `RevertToSelf`
//!    and only then writes `probe.ready` (`sandbox-worker` `confine`).
//! 5. Once the first frame is in (it is left in the buffer for the caller),
//!    the host lowers the worker's process token to untrusted integrity and
//!    reads the state back: untrusted integrity, the NULL SID as the only
//!    restricting SID, and no impersonation token on the main thread
//!    (`ERROR_NO_TOKEN`). Anything else kills the worker and fails the spawn,
//!    so no frame ever reaches a worker outside that state.
//!
//! The worker's own report is always `applied: false` (mechanism
//! `lockdown_token`): this spawner never meets the floor.

use std::ffi::{OsString, c_void};
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::{null, null_mut};
use std::time::Duration;

use atlas_duck_ipc::sandbox::LOCKDOWN_TOKEN_ARG;
use windows_sys::Win32::Foundation::{ERROR_NO_TOKEN, GetLastError, HANDLE, LocalFree, TRUE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, DuplicateTokenEx, GetLengthSid,
    GetTokenInformation, PSID, SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation,
    TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_IMPERSONATE,
    TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenGroups,
    TokenImpersonation, TokenIntegrityLevel, TokenRestrictedSids, TokenUser,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::SystemServices::{
    SE_GROUP_ENABLED, SE_GROUP_INTEGRITY, SE_GROUP_USE_FOR_DENY_ONLY,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, SetThreadToken,
};

use super::aces::LocalSid;
use super::job::{Job, JobLimits};
use super::pipes::create_stdio_pipes;
use super::spawner::{
    ProcAttrs, SPAWN_LOCK, Started, WORKER_CREATION_FLAGS, WindowsProcess,
    degraded_environment_block, stage,
};
use super::{from_wide_ptr, wide};
use crate::bridge::READY_TIMEOUT;
use crate::spawn::{SpawnSpec, WorkerProcess, WorkerSpawner};

/// The NULL SID, the lockdown token's only restricting SID.
pub const NULL_SID: &str = "S-1-0-0";
/// Low integrity: both tokens carry it at creation.
pub const LOW_INTEGRITY: &str = "S-1-16-4096";
/// Untrusted integrity: the worker's process token after startup.
pub const UNTRUSTED_INTEGRITY: &str = "S-1-16-0";

// windows-sys types the `SE_GROUP_*` bits as `i32`; `SID_AND_ATTRIBUTES` holds a `u32`.
const GROUP_ENABLED: u32 = SE_GROUP_ENABLED as u32;
const GROUP_DENY_ONLY: u32 = SE_GROUP_USE_FOR_DENY_ONLY as u32;
const GROUP_INTEGRITY: u32 = SE_GROUP_INTEGRITY as u32;

/// The rights the host's token is opened with: the restricted tokens made
/// from it get the same (`CreateRestrictedToken`), and `CreateProcessAsUserW`,
/// `DuplicateTokenEx`, `SetTokenInformation` and `SetThreadToken` need them.
const HOST_TOKEN_ACCESS: u32 =
    TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_IMPERSONATE;

/// One group of the host's token (`TokenGroups`), the input of the token plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupSid {
    pub(crate) sid: String,
    /// `SE_GROUP_*` bits.
    pub(crate) attributes: u32,
}

/// What `CreateRestrictedToken` and `SetTokenInformation(TokenIntegrityLevel)` are given for one
/// of the two tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenPlan {
    /// `CreateRestrictedToken` flags.
    pub(crate) flags: u32,
    /// SIDs made deny-only.
    pub(crate) deny_only: Vec<String>,
    /// The restricting SIDs.
    pub(crate) restricting: Vec<String>,
    /// The integrity label set before the worker is created.
    pub(crate) integrity: &'static str,
    /// The integrity label the host sets once the worker has dropped its startup token.
    pub(crate) integrity_after_startup: Option<&'static str>,
}

/// The worker's process token (Chromium's `USER_LOCKDOWN`): every SID of the host's token but
/// the integrity label deny-only, the user's own included; the NULL SID as the one restricting
/// SID; low integrity at creation, untrusted once the worker dropped its startup token.
pub(crate) fn lockdown_plan(user: &str, groups: &[GroupSid]) -> TokenPlan {
    let deny_only = std::iter::once(user.to_owned())
        .chain(
            groups
                .iter()
                .filter(|g| g.attributes & GROUP_INTEGRITY == 0)
                .map(|g| g.sid.clone()),
        )
        .collect();
    TokenPlan {
        flags: DISABLE_MAX_PRIVILEGE,
        deny_only,
        restricting: vec![NULL_SID.to_owned()],
        integrity: LOW_INTEGRITY,
        integrity_after_startup: Some(UNTRUSTED_INTEGRITY),
    }
}

/// The main thread's startup impersonation token (Chromium's `USER_RESTRICTED_SAME_ACCESS`):
/// restricted to the user and every enabled group that is not deny-only or the integrity
/// label, so the loader opens what the host can open; low integrity.
pub(crate) fn startup_plan(user: &str, groups: &[GroupSid]) -> TokenPlan {
    let restricting = std::iter::once(user.to_owned())
        .chain(
            groups
                .iter()
                .filter(|g| {
                    g.attributes & GROUP_ENABLED != 0
                        && g.attributes & (GROUP_DENY_ONLY | GROUP_INTEGRITY) == 0
                })
                .map(|g| g.sid.clone()),
        )
        .collect();
    TokenPlan {
        flags: DISABLE_MAX_PRIVILEGE,
        deny_only: Vec::new(),
        restricting,
        integrity: LOW_INTEGRITY,
        integrity_after_startup: None,
    }
}

/// Whether the worker's main thread still impersonates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadToken {
    /// `OpenThreadToken` failed with `ERROR_NO_TOKEN`.
    None,
    /// `OpenThreadToken` returned a token.
    Present,
    /// `OpenThreadToken` failed with this other error.
    Unknown(i32),
}

/// A degraded worker's token state, read back from the OS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockdownState {
    /// The integrity SID of its process token.
    pub integrity: String,
    /// The restricting SIDs of its process token.
    pub restricting: Vec<String>,
    /// Its main thread's token.
    pub thread_token: ThreadToken,
}

/// The only state a degraded worker may be handed frames in: untrusted integrity, the NULL SID
/// as the one restricting SID, no impersonation token on the main thread.
pub(crate) fn check_lockdown(state: &LockdownState) -> Result<(), &'static str> {
    if state.integrity != UNTRUSTED_INTEGRITY {
        return Err("the worker's token is not at untrusted integrity");
    }
    if state.restricting != [NULL_SID] {
        return Err("the worker's token is not restricted to the NULL SID alone");
    }
    if state.thread_token != ThreadToken::None {
        return Err("the worker's main thread may still impersonate");
    }
    Ok(())
}

/// The spawner of §9.4's degraded path: the lockdown token and the floor's job object. Used
/// only when the run policy allows degraded confinement and the AppContainer floor is not met
/// (`crate::degraded_spawner`); its workers always report `applied: false`.
#[derive(Debug, Default)]
pub struct DegradedSpawner;

impl DegradedSpawner {
    pub fn new() -> Self {
        DegradedSpawner
    }

    /// Like [`WorkerSpawner::spawn`] but returns the concrete worker (the CI test reads its job,
    /// process token and main thread). On success the worker has sent its first frame (still
    /// unread) and is in the checked lockdown state (module docs, step 5).
    pub fn spawn_process(&self, spec: &SpawnSpec) -> io::Result<WindowsProcess> {
        if spec.process_mb == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "process_mb must be greater than 0",
            ));
        }
        let exe = std::path::absolute(&spec.exe).map_err(stage("absolute exe"))?;
        let tokens = Tokens::create().map_err(stage("lockdown tokens"))?;
        let job = Job::create(JobLimits::from_process_mb(spec.process_mb))
            .map_err(stage("Job::create"))?;
        let env = degraded_environment_block().map_err(stage("environment_block"))?;
        let cwd = system_directory().map_err(stage("GetSystemDirectoryW"))?;
        let mut line = OsString::from("\"");
        line.push(exe.as_os_str());
        line.push("\" ");
        line.push(LOCKDOWN_TOKEN_ARG);
        let mut cmdline = wide(&line);
        let exe_w = wide(exe.as_os_str());

        let guard = SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (host, child) = create_stdio_pipes().map_err(stage("create_stdio_pipes"))?;
        let handles: [HANDLE; 3] = [
            child.stdin.as_raw_handle().cast(),
            child.stdout.as_raw_handle().cast(),
            child.stderr.as_raw_handle().cast(),
        ];
        let mut attrs =
            ProcAttrs::new(handles, None, job.raw(), false).map_err(stage("ProcAttrs::new"))?;
        // SAFETY: all-zero STARTUPINFOEXW is a valid starting value.
        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = handles[0];
        si.StartupInfo.hStdOutput = handles[1];
        si.StartupInfo.hStdError = handles[2];
        si.lpAttributeList = attrs.list();
        // SAFETY: all-zero PROCESS_INFORMATION is valid; it is an out-struct.
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // SAFETY: the lockdown token is an open primary token with the rights
        // `CreateProcessAsUserW` needs (a restricted version of the caller's
        // own token, so no privilege is needed); every pointer is valid for
        // the call: NUL-terminated wide strings, a mutable command line, a
        // double-NUL-terminated environment block, a STARTUPINFOEXW whose
        // attribute list (and the values it points at) lives in `attrs` until
        // after the call.
        let ok = unsafe {
            CreateProcessAsUserW(
                tokens.lockdown.as_raw_handle().cast(),
                exe_w.as_ptr(),
                cmdline.as_mut_ptr(),
                null(),
                null(),
                TRUE,
                WORKER_CREATION_FLAGS | CREATE_SUSPENDED,
                env.as_ptr().cast(),
                cwd.as_ptr(),
                &si.StartupInfo,
                &mut pi,
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            eprintln!(
                "CreateProcessAsUserW (degraded) failed: {err}; exe={}",
                exe.display()
            );
            return Err(err);
        }
        // SAFETY: both handles were just returned to us and are owned once.
        let (process, thread) = unsafe {
            (
                OwnedHandle::from_raw_handle(pi.hProcess as RawHandle),
                OwnedHandle::from_raw_handle(pi.hThread as RawHandle),
            )
        };
        drop(attrs);
        drop(child);
        drop(guard);
        let thread_raw: HANDLE = thread.as_raw_handle().cast();
        // From here on, dropping `worker` kills the suspended or running worker (its job).
        let mut worker = WindowsProcess::start(
            host,
            Started {
                job,
                process,
                pid: pi.dwProcessId,
                main_thread: Some(thread),
                lpac: false,
                run_dir: None,
            },
        )?;

        // SAFETY: `thread_raw` is the open handle of the worker's suspended
        // main thread (full access) and lives in `worker`; the startup token
        // is an open impersonation token with `TOKEN_IMPERSONATE`.
        if unsafe { SetThreadToken(&thread_raw, tokens.startup.as_raw_handle().cast()) } == 0 {
            return Err(stage("SetThreadToken")(io::Error::last_os_error()));
        }
        let untrusted = tokens.untrusted;
        drop(tokens);
        // SAFETY: `thread_raw` is the open handle of the suspended main thread.
        if unsafe { ResumeThread(thread_raw) } == u32::MAX {
            return Err(stage("ResumeThread")(io::Error::last_os_error()));
        }

        match worker.wait_first_frame(READY_TIMEOUT) {
            Ok(true) => {}
            Ok(false) => {
                let exit = worker.wait_timeout(Duration::from_secs(1));
                eprintln!("degraded worker ended before its first frame: exit={exit:?}");
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the degraded worker ended before its first frame",
                ));
            }
            Err(e) => {
                eprintln!("degraded worker sent no first frame: {e}");
                return Err(e);
            }
        }
        lower_to_untrusted(worker.process_handle(), untrusted)
            .map_err(stage("lower to untrusted"))?;
        let state = lockdown_state(worker.process_handle(), thread_raw as RawHandle)
            .map_err(stage("read the lockdown state"))?;
        if let Err(what) = check_lockdown(&state) {
            eprintln!("degraded worker refused: {what}: {state:?}");
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, what));
        }
        Ok(worker)
    }
}

impl WorkerSpawner for DegradedSpawner {
    fn spawn(&self, spec: &SpawnSpec) -> io::Result<Box<dyn WorkerProcess>> {
        Ok(Box::new(self.spawn_process(spec)?))
    }
}

/// The two tokens of one degraded spawn.
struct Tokens {
    /// Primary, for `CreateProcessAsUserW`.
    lockdown: OwnedHandle,
    /// Impersonation, for `SetThreadToken`.
    startup: OwnedHandle,
    /// The integrity label the lockdown plan names for after startup.
    untrusted: &'static str,
}

impl Tokens {
    fn create() -> io::Result<Tokens> {
        let mut raw: HANDLE = null_mut();
        // SAFETY: the pseudo handle of this process is always valid and `raw`
        // is a valid out-pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), HOST_TOKEN_ACCESS, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh token handle owned here.
        let host = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        let user = token_user(&host)?;
        let groups = token_groups(&host, TokenGroups)?;

        let lockdown_plan = lockdown_plan(&user, &groups);
        let lockdown = restricted_token(&host, &lockdown_plan)?;
        set_integrity(&lockdown, lockdown_plan.integrity)?;
        let untrusted = lockdown_plan.integrity_after_startup.ok_or_else(|| {
            io::Error::other("the lockdown plan has no integrity for after startup")
        })?;

        let plan = startup_plan(&user, &groups);
        let primary = restricted_token(&host, &plan)?;
        let mut raw: HANDLE = null_mut();
        // SAFETY: `primary` is an open token with `TOKEN_DUPLICATE`; no
        // security attributes; `raw` is a valid out-pointer.
        if unsafe {
            DuplicateTokenEx(
                primary.as_raw_handle().cast(),
                TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut raw,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh token handle owned here.
        let startup = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        set_integrity(&startup, plan.integrity)?;
        Ok(Tokens {
            lockdown,
            startup,
            untrusted,
        })
    }
}

/// `CreateRestrictedToken(host, plan)`; the integrity label is set by the caller.
fn restricted_token(host: &OwnedHandle, plan: &TokenPlan) -> io::Result<OwnedHandle> {
    let parse = |list: &[String]| -> io::Result<Vec<LocalSid>> {
        list.iter().map(|s| LocalSid::parse(s)).collect()
    };
    let entries = |sids: &[LocalSid]| -> Vec<SID_AND_ATTRIBUTES> {
        sids.iter()
            .map(|s| SID_AND_ATTRIBUTES {
                Sid: s.psid(),
                Attributes: 0,
            })
            .collect()
    };
    let ptr = |v: &[SID_AND_ATTRIBUTES]| if v.is_empty() { null() } else { v.as_ptr() };
    // The `LocalSid`s own the SIDs the entries point at: both live to the end.
    let deny_sids = parse(&plan.deny_only)?;
    let restrict_sids = parse(&plan.restricting)?;
    let deny = entries(&deny_sids);
    let restrict = entries(&restrict_sids);
    let mut raw: HANDLE = null_mut();
    // SAFETY: `host` is an open token with `TOKEN_DUPLICATE | TOKEN_QUERY`;
    // each array holds `len` entries whose SIDs live in `deny_sids` and
    // `restrict_sids` until after the call (NULL for an empty list); no
    // privileges are named (`DISABLE_MAX_PRIVILEGE` removes them); `raw` is a
    // valid out-pointer.
    let ok = unsafe {
        CreateRestrictedToken(
            host.as_raw_handle().cast(),
            plan.flags,
            deny.len() as u32,
            ptr(&deny),
            0,
            null(),
            restrict.len() as u32,
            ptr(&restrict),
            &mut raw,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh token handle owned here.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
}

/// `SetTokenInformation(TokenIntegrityLevel)`: lowering needs `TOKEN_ADJUST_DEFAULT` only.
fn set_integrity(token: &OwnedHandle, label: &str) -> io::Result<()> {
    let sid = LocalSid::parse(label)?;
    let info = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: sid.psid(),
            Attributes: GROUP_INTEGRITY,
        },
    };
    // SAFETY: `sid` is a valid SID.
    let len =
        std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + unsafe { GetLengthSid(sid.psid()) };
    // SAFETY: `token` is an open token; `info` and the SID it points at live
    // for the call; the length is the structure plus the SID, as documented.
    let ok = unsafe {
        SetTokenInformation(
            token.as_raw_handle().cast(),
            TokenIntegrityLevel,
            (&info as *const TOKEN_MANDATORY_LABEL).cast::<c_void>(),
            len,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Opens the token of `process` (a handle the host owns) with `access`.
fn process_token(process: RawHandle, access: u32) -> io::Result<OwnedHandle> {
    let mut raw: HANDLE = null_mut();
    // SAFETY: `process` is an open process handle with
    // `PROCESS_QUERY_INFORMATION` (the creator's full access) and `raw` a
    // valid out-pointer.
    if unsafe { OpenProcessToken(process.cast(), access, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh token handle owned here.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
}

/// Step 5: the worker's process token goes to untrusted integrity (lowering needs no
/// privilege). The host's own token has the access to it: the host created it.
fn lower_to_untrusted(process: RawHandle, label: &str) -> io::Result<()> {
    let token = process_token(process, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY)?;
    set_integrity(&token, label)
}

/// Reads a degraded worker's token state back from the OS: `process` and `thread` are the
/// host's handles to the worker and its main thread.
pub fn lockdown_state(process: RawHandle, thread: RawHandle) -> io::Result<LockdownState> {
    let token = process_token(process, TOKEN_QUERY)?;
    let label = token_info(
        &token,
        TokenIntegrityLevel,
        std::mem::size_of::<TOKEN_MANDATORY_LABEL>(),
    )?;
    // SAFETY: on success the buffer starts with a TOKEN_MANDATORY_LABEL whose
    // SID points into the same buffer, which outlives the call.
    let integrity =
        sid_string(unsafe { (*label.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid })?;
    let restricting = token_groups(&token, TokenRestrictedSids)?
        .into_iter()
        .map(|g| g.sid)
        .collect();
    Ok(LockdownState {
        integrity,
        restricting,
        thread_token: thread_token(thread),
    })
}

/// Whether `thread` (a handle the host owns) impersonates.
fn thread_token(thread: RawHandle) -> ThreadToken {
    let mut raw: HANDLE = null_mut();
    // SAFETY: `thread` is an open thread handle with full access and `raw` a
    // valid out-pointer; `OpenAsSelf = TRUE` checks with the host's own token.
    if unsafe { OpenThreadToken(thread.cast(), TOKEN_QUERY, TRUE, &mut raw) } == 0 {
        // SAFETY: no preconditions.
        let e = unsafe { GetLastError() };
        return if e == ERROR_NO_TOKEN {
            ThreadToken::None
        } else {
            ThreadToken::Unknown(e as i32)
        };
    }
    // SAFETY: `raw` is a fresh token handle, closed once on drop.
    drop(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) });
    ThreadToken::Present
}

/// One `GetTokenInformation` class into an 8-byte aligned buffer of at least `min` bytes.
fn token_info(
    token: &OwnedHandle,
    class: TOKEN_INFORMATION_CLASS,
    min: usize,
) -> io::Result<Vec<u64>> {
    let mut needed = 0u32;
    // SAFETY: the documented size query: no buffer, a valid length pointer.
    // It fails with ERROR_INSUFFICIENT_BUFFER and sets `needed`.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            class,
            null_mut(),
            0,
            &mut needed,
        )
    };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u64; (needed as usize).max(min).div_ceil(8)];
    let len = u32::try_from(buf.len() * 8).unwrap_or(u32::MAX);
    // SAFETY: `buf` is writable for `len` bytes and 8-byte aligned.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            class,
            buf.as_mut_ptr().cast(),
            len,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(buf)
}

/// The user SID of `token`.
fn token_user(token: &OwnedHandle) -> io::Result<String> {
    let buf = token_info(token, TokenUser, std::mem::size_of::<TOKEN_USER>())?;
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points
    // into the same buffer, which outlives the call.
    sid_string(unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid })
}

/// The SIDs of a `TOKEN_GROUPS` class of `token` (`TokenGroups`, `TokenRestrictedSids`).
fn token_groups(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<GroupSid>> {
    let buf = token_info(token, class, std::mem::size_of::<TOKEN_GROUPS>())?;
    // SAFETY: the buffer is at least one TOKEN_GROUPS long and, on success,
    // starts with one.
    let head = unsafe { &*buf.as_ptr().cast::<TOKEN_GROUPS>() };
    let first = head.Groups.as_ptr();
    (0..head.GroupCount as usize)
        .map(|i| {
            // SAFETY: `GroupCount` entries follow `Groups` inside the buffer;
            // their SIDs point into it too.
            let entry = unsafe { &*first.add(i) };
            Ok(GroupSid {
                sid: sid_string(entry.Sid)?,
                attributes: entry.Attributes,
            })
        })
        .collect()
}

/// `S-1-...` of a valid SID.
fn sid_string(sid: PSID) -> io::Result<String> {
    let mut p: *mut u16 = null_mut();
    // SAFETY: `sid` is a valid SID; `p` is a valid out-pointer.
    if unsafe { ConvertSidToStringSidW(sid, &mut p) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `p` is a NUL-terminated string allocated by the call above.
    let s = unsafe { from_wide_ptr(p) };
    // SAFETY: allocated by ConvertSidToStringSidW, freed once.
    unsafe { LocalFree(p.cast()) };
    Ok(s)
}

/// The system directory (`System32`), NUL-terminated: the degraded worker's working directory.
/// It has no per-run directory: there is no AppContainer folder to put one in, and below the
/// floor the worker may read files anyway.
fn system_directory() -> io::Result<Vec<u16>> {
    let mut buf = vec![0u16; 260];
    // SAFETY: `buf` is writable for `buf.len()` elements.
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 {
        return Err(io::Error::last_os_error());
    }
    if n >= buf.len() {
        return Err(io::Error::other("the system directory path is too long"));
    }
    buf.truncate(n);
    buf.push(0);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::System::SystemServices::{
        SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_LOGON_ID,
        SE_GROUP_MANDATORY,
    };

    use windows_sys::Win32::Security::{TOKEN_PRIVILEGES, TokenPrivileges};

    use super::*;

    const USER: &str = "S-1-5-21-1-2-3-1001";
    // windows-sys types the `SE_GROUP_*` bits as `i32`; `SID_AND_ATTRIBUTES` holds a `u32`.
    const ON: u32 = (SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED) as u32;
    const LOGON: u32 = SE_GROUP_LOGON_ID as u32;
    const DENY_ONLY: u32 = SE_GROUP_USE_FOR_DENY_ONLY as u32;
    const LABEL: u32 = (SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED) as u32;

    /// A filtered medium-integrity token: an enabled group, a deny-only one (the filtered
    /// Administrators), the logon SID, a disabled group and the integrity label.
    fn groups() -> Vec<GroupSid> {
        let g = |sid: &str, attributes: u32| GroupSid {
            sid: sid.to_owned(),
            attributes,
        };
        vec![
            g("S-1-1-0", ON),
            g("S-1-5-32-544", DENY_ONLY),
            g("S-1-5-32-545", ON),
            g("S-1-5-5-0-12345", ON | LOGON),
            g("S-1-5-99", 0),
            g("S-1-16-8192", LABEL),
        ]
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn degraded_token_has_null_restricting_sid_and_untrusted_label() {
        let plan = lockdown_plan(USER, &groups());
        assert_eq!(plan.restricting, strings(&[NULL_SID]));
        assert_eq!(plan.integrity_after_startup, Some(UNTRUSTED_INTEGRITY));
        assert_eq!(UNTRUSTED_INTEGRITY, "S-1-16-0");
        // Created at low integrity: the startup token on the main thread may not be above it.
        assert_eq!(plan.integrity, LOW_INTEGRITY);
        assert_eq!(plan.flags, DISABLE_MAX_PRIVILEGE);
        // Every SID but the integrity label is deny-only, the user's own too.
        assert_eq!(
            plan.deny_only,
            strings(&[
                USER,
                "S-1-1-0",
                "S-1-5-32-544",
                "S-1-5-32-545",
                "S-1-5-5-0-12345",
                "S-1-5-99"
            ])
        );
    }

    #[test]
    fn startup_token_restricts_to_the_enabled_sids_at_low_integrity() {
        let plan = startup_plan(USER, &groups());
        // The same access as the host for what the loader opens, but a restricted token, as
        // the lockdown process token requires of an impersonation token.
        assert_eq!(
            plan.restricting,
            strings(&[USER, "S-1-1-0", "S-1-5-32-545", "S-1-5-5-0-12345"])
        );
        assert!(plan.deny_only.is_empty());
        assert_eq!(plan.integrity, LOW_INTEGRITY);
        assert_eq!(plan.integrity_after_startup, None);
        assert_eq!(plan.flags, DISABLE_MAX_PRIVILEGE);
    }

    #[test]
    fn the_lockdown_check_accepts_only_the_lockdown_state() {
        let good = LockdownState {
            integrity: UNTRUSTED_INTEGRITY.to_owned(),
            restricting: strings(&[NULL_SID]),
            thread_token: ThreadToken::None,
        };
        assert_eq!(check_lockdown(&good), Ok(()));
        let low = LockdownState {
            integrity: LOW_INTEGRITY.to_owned(),
            ..good.clone()
        };
        assert!(check_lockdown(&low).is_err());
        let unrestricted = LockdownState {
            restricting: Vec::new(),
            ..good.clone()
        };
        assert!(check_lockdown(&unrestricted).is_err());
        let more = LockdownState {
            restricting: strings(&[NULL_SID, "S-1-1-0"]),
            ..good.clone()
        };
        assert!(check_lockdown(&more).is_err());
        for thread_token in [ThreadToken::Present, ThreadToken::Unknown(5)] {
            let still = LockdownState {
                thread_token,
                ..good.clone()
            };
            assert!(check_lockdown(&still).is_err(), "{thread_token:?}");
        }
    }

    /// The token half on the real host token, in the test process, without any process:
    /// both tokens can be built from it, and they read back as planned.
    #[test]
    fn both_tokens_build_from_the_host_token_and_read_back_as_planned() -> io::Result<()> {
        let tokens = Tokens::create()?;
        assert_eq!(integrity_of(&tokens.lockdown)?, LOW_INTEGRITY);
        // The startup token is low too: a thread may not impersonate above its process.
        assert_eq!(integrity_of(&tokens.startup)?, LOW_INTEGRITY);
        let restricting: Vec<String> = token_groups(&tokens.lockdown, TokenRestrictedSids)?
            .into_iter()
            .map(|g| g.sid)
            .collect();
        assert_eq!(restricting, strings(&[NULL_SID]));
        let startup: Vec<String> = token_groups(&tokens.startup, TokenRestrictedSids)?
            .into_iter()
            .map(|g| g.sid)
            .collect();
        assert!(startup.len() >= 2, "{startup:?}");
        assert!(!startup.contains(&NULL_SID.to_owned()), "{startup:?}");

        // Deny-only: the user and every group but the integrity label (Chromium USER_LOCKDOWN).
        let buf = token_info(
            &tokens.lockdown,
            TokenUser,
            std::mem::size_of::<TOKEN_USER>(),
        )?;
        // SAFETY: on success the buffer starts with a TOKEN_USER.
        let user_attributes = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Attributes };
        assert_ne!(
            user_attributes & GROUP_DENY_ONLY,
            0,
            "user {user_attributes:#x}"
        );
        for group in token_groups(&tokens.lockdown, TokenGroups)? {
            if group.attributes & GROUP_INTEGRITY == 0 {
                assert_ne!(group.attributes & GROUP_DENY_ONLY, 0, "{group:?}");
            }
        }
        // DISABLE_MAX_PRIVILEGE: nothing but SeChangeNotify (LUID 23), on both tokens.
        for token in [&tokens.lockdown, &tokens.startup] {
            assert_eq!(privilege_luids(token)?, vec![SE_CHANGE_NOTIFY_LUID]);
        }

        // Lowering further needs no privilege, and the readback sees it.
        // The label production lowers to is the plan's, and it is untrusted.
        assert_eq!(tokens.untrusted, UNTRUSTED_INTEGRITY);
        set_integrity(&tokens.lockdown, tokens.untrusted)?;
        assert_eq!(integrity_of(&tokens.lockdown)?, UNTRUSTED_INTEGRITY);
        Ok(())
    }

    /// `SeChangeNotifyPrivilege`, the one privilege `DISABLE_MAX_PRIVILEGE` leaves.
    const SE_CHANGE_NOTIFY_LUID: u32 = 23;

    fn integrity_of(token: &OwnedHandle) -> io::Result<String> {
        let label = token_info(
            token,
            TokenIntegrityLevel,
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>(),
        )?;
        // SAFETY: as in `lockdown_state`.
        sid_string(unsafe { (*label.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid })
    }

    /// The low parts of the LUIDs of the privileges the token still has.
    fn privilege_luids(token: &OwnedHandle) -> io::Result<Vec<u32>> {
        let buf = token_info(
            token,
            TokenPrivileges,
            std::mem::size_of::<TOKEN_PRIVILEGES>(),
        )?;
        // SAFETY: the buffer is at least one TOKEN_PRIVILEGES long and, on success, starts with
        // one followed by `PrivilegeCount` entries.
        let head = unsafe { &*buf.as_ptr().cast::<TOKEN_PRIVILEGES>() };
        let first = head.Privileges.as_ptr();
        Ok((0..head.PrivilegeCount as usize)
            // SAFETY: `PrivilegeCount` entries follow inside the buffer.
            .map(|i| unsafe { (*first.add(i)).Luid.LowPart })
            .collect())
    }
}
