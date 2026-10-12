//! Windows app launch (§4.7 "How to launch" steps 1-3, PD-21) and the PD-24 session check.
//!
//! 1. Shell parent: the session's shell process (`GetShellWindow`), verified to run as this user
//!    in this session, becomes the app's parent through `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, so
//!    the app inherits the shell's job and parentage, not the agent's.
//! 2. Otherwise, unless this process's job forbids it, the breakaway stub: this executable re-run
//!    as `__launch-stub <app>` with `CREATE_BREAKAWAY_FROM_JOB` (PD-21), waited for up to 5 s; it
//!    starts the app the same way and exits, leaving the app orphaned.
//! 3. Otherwise `LaunchError::BlockedByJob`. Never a plain child, never `ShellExecute`.
//!
//! Every process is created with `bInheritHandles = FALSE`, `STARTF_USESTDHANDLES` with null
//! standard handles (nothing can be inherited, so the child has no stdio at all rather than the
//! null device), `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`, a sorted UTF-16 environment block
//! from the allowlist whose `SystemRoot` and `PATH` come from `GetSystemWindowsDirectoryW` (never
//! from the caller's environment), and the app's install dir as working directory.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, FALSE, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::JobObjects::{
    IsProcessInJob, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    QueryInformationJobObject,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::StationsAndDesktops::{
    GetProcessWindowStation, GetUserObjectInformationW, UOI_FLAGS, USEROBJECTFLAGS,
};
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT,
    CreateProcessW, DETACHED_PROCESS, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, PROCESS_CREATE_PROCESS, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
    UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetShellWindow, GetWindowThreadProcessId, WSF_VISIBLE,
};

use super::LaunchError;
use super::plan::APP_ARGS;
use super::stub::{EXIT_BLOCKED, EXIT_STARTED, STUB_COMMAND};
use crate::discover::APP_FILE_NAME;

/// §4.7 step 1: detached, own process group, the parent attribute, a Unicode environment.
pub(crate) const SHELL_PARENT_FLAGS: u32 = DETACHED_PROCESS
    | CREATE_NEW_PROCESS_GROUP
    | EXTENDED_STARTUPINFO_PRESENT
    | CREATE_UNICODE_ENVIRONMENT;
/// PD-21: the stub and the app the stub starts, before the job decision adds
/// `CREATE_BREAKAWAY_FROM_JOB`.
pub(crate) const DETACHED_FLAGS: u32 =
    DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT;
/// PD-21: how long the CLI waits for the stub's exit code.
const STUB_WAIT: Duration = Duration::from_secs(5);
/// The marker the app's early-argv dispatch hands to the CLI entry (§12.1).
const APP_CLI_MARKER: &str = "__cli";
const VERBATIM_PREFIX: &str = r"\\?\";
/// `GetSystemWindowsDirectoryW` buffer, grown at most this many times.
const WINDIR_TRIES: usize = 3;

/// How `spawn_detached` started the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Started {
    /// §4.7 step 1; `pid` is the app's.
    ShellParent { pid: u32 },
    /// §4.7 step 2: the stub exited 0.
    Stub,
}

/// Starts `app --background` detached (§4.7 Windows steps 1-3).
pub(crate) fn launch_app(app: &Path, env: &[(OsString, OsString)]) -> Result<(), LaunchError> {
    spawn_detached(app, env).map(|_| ())
}

/// §4.7 Windows steps 1-3 for `app --background` with exactly `env` (plus the system `SystemRoot`
/// and `PATH`).
pub(crate) fn spawn_detached(
    app: &Path,
    env: &[(OsString, OsString)],
) -> Result<Started, LaunchError> {
    let target = Target::new(app, APP_ARGS, env)?;
    if let Ok(pid) = via_shell_parent(&target) {
        return Ok(Started::ShellParent { pid });
    }
    let breakaway = job_breakaway();
    let Some(extra) = breakaway.extra_flags() else {
        return Err(LaunchError::BlockedByJob);
    };
    let exe = own_exe()?;
    let stub = create_spec(
        &exe,
        &stub_command(&exe, &target.program),
        DETACHED_FLAGS | extra,
        target.environment.clone(),
        &target.cwd,
    )?;
    let child = create_process(&stub, None).map_err(|e| stub_error(e, breakaway))?;
    wait_for_stub(&child.process)
}

/// The stub's half of PD-21: starts `app --background` detached and out of this process's job
/// (the stub itself was started with `CREATE_BREAKAWAY_FROM_JOB`, so it normally is in none).
pub(crate) fn stub_spawn(app: &Path, env: &[(OsString, OsString)]) -> Result<(), LaunchError> {
    let target = Target::new(app, APP_ARGS, env)?;
    let breakaway = job_breakaway();
    let Some(extra) = breakaway.extra_flags() else {
        return Err(LaunchError::BlockedByJob);
    };
    let spec = target.spec(DETACHED_FLAGS | extra)?;
    create_process(&spec, None)
        .map(drop)
        .map_err(|e| stub_error(e, breakaway))
}

/// What to start: the program (verbatim prefix stripped), its arguments, the environment block
/// and the install dir.
pub(crate) struct Target {
    program: PathBuf,
    argv: Vec<OsString>,
    environment: Vec<u16>,
    cwd: PathBuf,
}

impl Target {
    pub(crate) fn new(
        program: &Path,
        args: &[&str],
        env: &[(OsString, OsString)],
    ) -> Result<Target, LaunchError> {
        let program = strip_verbatim(program);
        let cwd = install_dir(&program)?;
        let windir = system_windows_dir().map_err(LaunchError::Io)?;
        let mut argv = vec![program.as_os_str().to_owned()];
        argv.extend(args.iter().map(OsString::from));
        Ok(Target {
            environment: env_block(env, windir.as_os_str())?,
            program,
            argv,
            cwd,
        })
    }

    fn spec(&self, flags: u32) -> Result<CreateSpec, LaunchError> {
        create_spec(
            &self.program,
            &self.argv,
            flags,
            self.environment.clone(),
            &self.cwd,
        )
    }
}

/// §4.7 step 1: the shell process as parent. Any failure falls through to step 2.
pub(crate) fn via_shell_parent(target: &Target) -> Result<u32, ShellError> {
    let shell = shell_process()?;
    let spec = target
        .spec(SHELL_PARENT_FLAGS)
        .map_err(|_| ShellError::Spec)?;
    let mut attrs = ParentAttribute::new(shell.as_raw_handle()).map_err(ShellError::Io)?;
    // `shell` outlives the call: the attribute list points at its handle value.
    let child = create_process(&spec, Some(&mut attrs)).map_err(ShellError::Io)?;
    drop(attrs);
    drop(shell);
    Ok(child.pid)
}

/// Why the shell-parent path was not taken.
// The cause in `Io` is kept for Debug output.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum ShellError {
    /// `GetShellWindow` returned none (no shell in this session, e.g. a service or CI runner).
    NoShellWindow,
    /// The shell window changed owner while it was being opened.
    Changed,
    /// The shell runs in another session.
    OtherSession,
    /// The shell runs as another user.
    OtherUser,
    /// The command line or environment cannot be passed.
    Spec,
    Io(io::Error),
}

/// The pid owning the shell window, if there is one.
fn shell_pid() -> Option<u32> {
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

/// The shell process, opened with `PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION`
/// and verified to be the shell window's owner, in this session, running as this user.
pub(crate) fn shell_process() -> Result<OwnedHandle, ShellError> {
    let pid = shell_pid().ok_or(ShellError::NoShellWindow)?;
    // SAFETY: plain call; a null result is checked below.
    let raw = unsafe {
        OpenProcess(
            PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid,
        )
    };
    if raw.is_null() {
        return Err(ShellError::Io(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a fresh handle owned by nobody else.
    let shell = unsafe { OwnedHandle::from_raw_handle(raw) };
    // While `shell` is open its pid cannot be reused, so a shell window still owned by `pid` means
    // `shell` is the shell process.
    if shell_pid() != Some(pid) {
        return Err(ShellError::Changed);
    }
    // SAFETY: plain call.
    let own_pid = unsafe { GetCurrentProcessId() };
    if session_of(pid).map_err(ShellError::Io)? != session_of(own_pid).map_err(ShellError::Io)? {
        return Err(ShellError::OtherSession);
    }
    // SAFETY: the pseudo handle of this process; it needs no closing.
    let own = unsafe { GetCurrentProcess() };
    if !same_user(shell.as_raw_handle(), own).map_err(ShellError::Io)? {
        return Err(ShellError::OtherUser);
    }
    Ok(shell)
}

fn session_of(pid: u32) -> io::Result<u32> {
    let mut session = 0u32;
    // SAFETY: `session` is a local out-parameter.
    if unsafe { ProcessIdToSessionId(pid, &mut session) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(session)
}

/// The `TOKEN_USER` of `process`'s token, in a pointer-aligned buffer (the SID points into it).
fn token_user(process: HANDLE) -> io::Result<Vec<usize>> {
    let mut raw: HANDLE = null_mut();
    // SAFETY: `process` has query access; `raw` is a local out-parameter.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh token handle owned by nobody else.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut len = 0u32;
    // SAFETY: a null buffer of length 0 asks for the size (the call fails with
    // ERROR_INSUFFICIENT_BUFFER and sets `len`).
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut len) };
    let bytes = usize::try_from(len).unwrap_or(0);
    if bytes < size_of::<TOKEN_USER>() {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    // SAFETY: `buf` holds at least `len` writable bytes, aligned for `TOKEN_USER`.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buf.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buf)
}

/// Whether both processes' tokens carry the same user SID.
fn same_user(a: HANDLE, b: HANDLE) -> io::Result<bool> {
    let ua = token_user(a)?;
    let ub = token_user(b)?;
    // SAFETY: each buffer starts with a `TOKEN_USER` filled by `GetTokenInformation`, whose SID
    // points into that same buffer, alive for this call.
    let equal = unsafe {
        let sa = (*ua.as_ptr().cast::<TOKEN_USER>()).User.Sid;
        let sb = (*ub.as_ptr().cast::<TOKEN_USER>()).User.Sid;
        EqualSid(sa, sb)
    };
    Ok(equal != 0)
}

/// A `PROC_THREAD_ATTRIBUTE_LIST` holding exactly one attribute, the parent process; deleted on
/// drop.
pub(crate) struct ParentAttribute {
    /// Pointer-aligned storage of the opaque list.
    buf: Vec<usize>,
    /// The list stores a pointer to this value until it is deleted, so it lives in a box.
    _parent: Box<HANDLE>,
    /// The attribute ids set, in order.
    attributes: Vec<usize>,
}

impl ParentAttribute {
    pub(crate) fn new(parent: HANDLE) -> io::Result<ParentAttribute> {
        let mut size = 0usize;
        // SAFETY: a null list asks for the size of a one-attribute list (the call fails with
        // ERROR_INSUFFICIENT_BUFFER and sets `size`).
        unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0usize; size.div_ceil(size_of::<usize>())];
        // SAFETY: `buf` holds `size` writable, pointer-aligned bytes.
        if unsafe { InitializeProcThreadAttributeList(buf.as_mut_ptr().cast(), 1, 0, &mut size) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        // From here on `Drop` deletes the list (moving `buf` keeps its heap storage in place).
        let mut list = ParentAttribute {
            buf,
            _parent: Box::new(parent),
            attributes: Vec::new(),
        };
        let attribute = PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize;
        let value: *const HANDLE = &*list._parent;
        // SAFETY: the list was initialized for one attribute; `value` points to a HANDLE that
        // lives in `list` until the list is deleted.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                list.as_ptr(),
                0,
                attribute,
                value.cast(),
                size_of::<HANDLE>(),
                null_mut(),
                null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        list.attributes.push(attribute);
        Ok(list)
    }

    fn as_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buf.as_mut_ptr().cast()
    }

    #[cfg(test)]
    pub(crate) fn attributes(&self) -> &[usize] {
        &self.attributes
    }
}

impl Drop for ParentAttribute {
    fn drop(&mut self) {
        // SAFETY: the list was initialized in `new` and is deleted exactly once.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

/// Everything `CreateProcessW` gets, as data. `inherit_handles` is always false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreateSpec {
    /// NUL-terminated `lpApplicationName` (no search path is ever used).
    pub application: Vec<u16>,
    /// NUL-terminated `lpCommandLine`.
    pub command_line: Vec<u16>,
    pub flags: u32,
    pub inherit_handles: bool,
    /// The double-NUL-terminated environment block.
    pub environment: Vec<u16>,
    /// NUL-terminated `lpCurrentDirectory`.
    pub current_dir: Vec<u16>,
}

pub(crate) fn create_spec(
    program: &Path,
    argv: &[OsString],
    flags: u32,
    environment: Vec<u16>,
    cwd: &Path,
) -> Result<CreateSpec, LaunchError> {
    Ok(CreateSpec {
        application: wide_nul(program.as_os_str())?,
        command_line: command_line(argv)?,
        flags,
        inherit_handles: false,
        environment,
        current_dir: wide_nul(cwd.as_os_str())?,
    })
}

/// A created process; both handles are closed on drop.
pub(crate) struct Child {
    pub process: OwnedHandle,
    /// Held so the handle closes on drop.
    #[allow(dead_code)]
    pub thread: OwnedHandle,
    pub pid: u32,
}

/// `CreateProcessW` for `spec`, with the attribute list when given. Standard handles are set to
/// null explicitly (`STARTF_USESTDHANDLES`), so no handle value of this process can reach the child.
pub(crate) fn create_process(
    spec: &CreateSpec,
    attrs: Option<&mut ParentAttribute>,
) -> io::Result<Child> {
    let extended = spec.flags & EXTENDED_STARTUPINFO_PRESENT != 0;
    if extended != attrs.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "EXTENDED_STARTUPINFO_PRESENT and the attribute list disagree",
        ));
    }
    let mut si = STARTUPINFOEXW::default();
    let cb = if extended {
        size_of::<STARTUPINFOEXW>()
    } else {
        size_of::<STARTUPINFOW>()
    };
    si.StartupInfo.cb = u32::try_from(cb).unwrap_or(u32::MAX);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = null_mut();
    si.StartupInfo.hStdOutput = null_mut();
    si.StartupInfo.hStdError = null_mut();
    si.lpAttributeList = attrs.map_or(null_mut(), ParentAttribute::as_ptr);
    // CreateProcessW may write into the command line.
    let mut command_line = spec.command_line.clone();
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: every string is NUL-terminated and alive for the call, the environment block is
    // double-NUL-terminated UTF-16 (CREATE_UNICODE_ENVIRONMENT), `si` is a STARTUPINFOEXW whose
    // `cb` matches the flags, and `pi` is a local out-parameter.
    let ok = unsafe {
        CreateProcessW(
            spec.application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            i32::from(spec.inherit_handles),
            spec.flags,
            spec.environment.as_ptr().cast(),
            spec.current_dir.as_ptr(),
            (&raw const si).cast::<STARTUPINFOW>(),
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both handles were just created for us and are owned by nobody else.
    let (process, thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(pi.hProcess),
            OwnedHandle::from_raw_handle(pi.hThread),
        )
    };
    Ok(Child {
        process,
        thread,
        pid: pi.dwProcessId,
    })
}

/// PD-21: the stub must exit within 5 s; its exit code decides (`stub_exit`).
fn wait_for_stub(process: &OwnedHandle) -> Result<Started, LaunchError> {
    let ms = u32::try_from(STUB_WAIT.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: a process handle we own.
    let waited = unsafe { WaitForSingleObject(process.as_raw_handle(), ms) };
    if waited != WAIT_OBJECT_0 {
        return Err(LaunchError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "the launch stub did not exit in time",
        )));
    }
    let mut code = 0u32;
    // SAFETY: a process handle we own; `code` is a local out-parameter.
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
        return Err(LaunchError::Io(io::Error::last_os_error()));
    }
    stub_exit(code)
}

/// The stub's exit code: started, blocked by the job (its own breakaway refused), or failed.
fn stub_exit(code: u32) -> Result<Started, LaunchError> {
    match i32::from_ne_bytes(code.to_ne_bytes()) {
        EXIT_STARTED => Ok(Started::Stub),
        EXIT_BLOCKED => Err(LaunchError::BlockedByJob),
        c => Err(LaunchError::ChildFailed(c)),
    }
}

/// What this process's job lets a process it starts do (§4.7 step 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Breakaway {
    /// In no job: `CREATE_BREAKAWAY_FROM_JOB` has no effect (passed anyway: if a job was assigned
    /// meanwhile, the creation result decides).
    NotInJob,
    /// `JOB_OBJECT_LIMIT_BREAKAWAY_OK`: the child leaves with `CREATE_BREAKAWAY_FROM_JOB`.
    Granted,
    /// Only `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`: every child leaves on its own; the explicit
    /// flag would be refused (it requires `BREAKAWAY_OK`).
    Silent,
    /// In a job with neither flag: a child stays in the job (§4.7 step 3).
    Blocked,
    /// The query failed: try with the flag and let the creation result decide.
    Unknown,
}

impl Breakaway {
    /// The decision table over `IsProcessInJob` and the job's limit flags.
    pub(crate) fn from_job(in_job: Option<bool>, limit_flags: Option<u32>) -> Breakaway {
        match (in_job, limit_flags) {
            (Some(false), _) => Breakaway::NotInJob,
            (Some(true), Some(f)) if f & JOB_OBJECT_LIMIT_BREAKAWAY_OK != 0 => Breakaway::Granted,
            (Some(true), Some(f)) if f & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK != 0 => {
                Breakaway::Silent
            }
            (Some(true), Some(_)) => Breakaway::Blocked,
            (None, _) | (Some(true), None) => Breakaway::Unknown,
        }
    }

    /// Creation flags to add for the stub (and for the app the stub starts); `None` when nothing
    /// may be started.
    pub(crate) fn extra_flags(self) -> Option<u32> {
        match self {
            Breakaway::NotInJob | Breakaway::Granted | Breakaway::Unknown => {
                Some(CREATE_BREAKAWAY_FROM_JOB)
            }
            Breakaway::Silent => Some(0),
            Breakaway::Blocked => None,
        }
    }

    /// `doctor`'s `job_blocks_breakaway`.
    pub(crate) fn blocks(self) -> Option<bool> {
        match self {
            Breakaway::NotInJob | Breakaway::Granted | Breakaway::Silent => Some(false),
            Breakaway::Blocked => Some(true),
            Breakaway::Unknown => None,
        }
    }
}

/// `ERROR_ACCESS_DENIED` from creating a process with `CREATE_BREAKAWAY_FROM_JOB` while in a job
/// means the job (or an enclosing one) refused the breakaway (§4.7 step 2 "or by the
/// `CreateProcess` result"). Only when the query said this process is in a job: after a failed
/// query (`Unknown`) a denial is just an IO error.
fn stub_error(e: io::Error, breakaway: Breakaway) -> LaunchError {
    let denied = e.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED).ok();
    let in_job = matches!(
        breakaway,
        Breakaway::Granted | Breakaway::Silent | Breakaway::Blocked
    );
    if denied && in_job {
        LaunchError::BlockedByJob
    } else {
        LaunchError::Io(e)
    }
}

/// `doctor` (§4.7): `Some(true)` when this process is in a job that allows no breakaway, so a cold
/// start depends on the shell-parent path; `None` when the query failed.
// Task 17 (`doctor`) is the caller.
#[allow(dead_code)]
pub(crate) fn job_blocks_breakaway() -> Option<bool> {
    job_breakaway().blocks()
}

/// This process's job state. `QueryInformationJobObject(NULL)` reads the innermost job; an
/// enclosing job that refuses breakaway shows up only as the creation result.
fn job_breakaway() -> Breakaway {
    let in_job = in_any_job();
    let flags = if in_job == Some(true) {
        job_limit_flags()
    } else {
        None
    };
    Breakaway::from_job(in_job, flags)
}

fn in_any_job() -> Option<bool> {
    let mut result = FALSE;
    // SAFETY: the pseudo handle needs no closing; a null job handle means "any job"; `result` is
    // a local out-parameter.
    let ok = unsafe { IsProcessInJob(GetCurrentProcess(), null_mut(), &mut result) };
    (ok != 0).then_some(result != 0)
}

fn job_limit_flags() -> Option<u32> {
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let len = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).ok()?;
    // SAFETY: a null job handle reads this process's job; `info` is a local of exactly `len`
    // bytes.
    let ok = unsafe {
        QueryInformationJobObject(
            null_mut(),
            JobObjectExtendedLimitInformation,
            (&raw mut info).cast(),
            len,
            null_mut(),
        )
    };
    (ok != 0).then_some(info.BasicLimitInformation.LimitFlags)
}

/// PD-24 inputs, also printed by the `gui_session_probe` test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionProbe {
    pub session_id: Option<u32>,
    pub wsf_visible: Option<bool>,
    pub shell_window: bool,
}

impl SessionProbe {
    /// PD-24: an interactive session (not session 0) whose window station is visible.
    pub(crate) fn is_gui(&self) -> bool {
        self.session_id.is_some_and(|s| s != 0) && self.wsf_visible == Some(true)
    }
}

pub(crate) fn session_probe() -> SessionProbe {
    // SAFETY: plain call.
    let pid = unsafe { GetCurrentProcessId() };
    SessionProbe {
        session_id: session_of(pid).ok(),
        wsf_visible: window_station_visible(),
        // SAFETY: no arguments.
        shell_window: !unsafe { GetShellWindow() }.is_null(),
    }
}

/// PD-24 (Windows).
pub(crate) fn gui_session() -> bool {
    session_probe().is_gui()
}

fn window_station_visible() -> Option<bool> {
    // SAFETY: no arguments; the returned handle must not be closed.
    let station = unsafe { GetProcessWindowStation() };
    if station.is_null() {
        return None;
    }
    let mut flags = USEROBJECTFLAGS::default();
    let len = u32::try_from(size_of::<USEROBJECTFLAGS>()).ok()?;
    let mut needed = 0u32;
    // SAFETY: `flags` is a local of exactly `len` bytes; `needed` is a local out-parameter.
    let ok = unsafe {
        GetUserObjectInformationW(
            station,
            UOI_FLAGS,
            (&raw mut flags).cast(),
            len,
            &mut needed,
        )
    };
    let visible = u32::try_from(WSF_VISIBLE).unwrap_or(0);
    (ok != 0).then_some(flags.dwFlags & visible != 0)
}

/// This executable (PD-21: canonical), as the stub's program.
fn own_exe() -> Result<PathBuf, LaunchError> {
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(LaunchError::Io)?;
    Ok(strip_verbatim(&exe))
}

/// The stub's argv (PD-21): `<exe> __launch-stub <app>`; when this CLI runs through the app's
/// `__cli` dispatch (`exe` is the app binary), `<exe> __cli __launch-stub <app>`, so the app's
/// early-argv dispatch hands it to the CLI instead of starting a tray instance.
pub(crate) fn stub_command(exe: &Path, app: &Path) -> Vec<OsString> {
    let mut argv = vec![exe.as_os_str().to_owned()];
    let is_app = exe
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|n| n.eq_ignore_ascii_case(APP_FILE_NAME));
    if is_app {
        argv.push(OsString::from(APP_CLI_MARKER));
    }
    argv.push(OsString::from(STUB_COMMAND));
    argv.push(app.as_os_str().to_owned());
    argv
}

/// `\\?\C:\x` → `C:\x` (what `canonicalize` returns, which some process-creation paths, notably
/// the working directory, handle badly). Other forms are returned unchanged.
pub(crate) fn strip_verbatim(p: &Path) -> PathBuf {
    if let Some(rest) = p.to_str().and_then(|s| s.strip_prefix(VERBATIM_PREFIX)) {
        let b = rest.as_bytes();
        if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
            return PathBuf::from(rest);
        }
    }
    p.to_path_buf()
}

/// The program's directory: the working directory of the launched process (§4.7).
fn install_dir(program: &Path) -> Result<PathBuf, LaunchError> {
    match program.parent() {
        Some(dir) if program.is_absolute() && !dir.as_os_str().is_empty() => Ok(dir.to_path_buf()),
        _ => Err(LaunchError::InvalidArgument),
    }
}

/// `GetSystemWindowsDirectoryW`: the system's Windows dir, independent of any environment.
pub(crate) fn system_windows_dir() -> io::Result<PathBuf> {
    let mut buf = vec![0u16; 261];
    for _ in 0..WINDIR_TRIES {
        let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `buf` holds `cap` writable UTF-16 units.
        let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), cap) };
        let n = usize::try_from(n).unwrap_or(usize::MAX);
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n < buf.len() {
            buf.truncate(n);
            let dir = PathBuf::from(OsString::from_wide(&buf));
            if !dir.is_absolute() {
                return Err(io::Error::other("the Windows directory is not absolute"));
            }
            return Ok(dir);
        }
        // Too small: `n` is the size needed, terminating NUL included.
        buf = vec![0u16; n.saturating_add(1)];
    }
    Err(io::Error::other("the Windows directory kept growing"))
}

/// The system `PATH` for a Windows dir: `<root>\System32;<root>;<root>\System32\Wbem`.
pub(crate) fn system_path(root: &OsStr) -> OsString {
    let mut path = root.to_owned();
    path.push(r"\System32;");
    path.push(root);
    path.push(";");
    path.push(root);
    path.push(r"\System32\Wbem");
    path
}

fn is_name(units: &[u16], name: &str) -> bool {
    units.len() == name.len()
        && units
            .iter()
            .zip(name.bytes())
            .all(|(u, b)| upper(*u) == u16::from(b.to_ascii_uppercase()))
}

fn upper(u: u16) -> u16 {
    if (u16::from(b'a')..=u16::from(b'z')).contains(&u) {
        u - 32
    } else {
        u
    }
}

/// The `CREATE_UNICODE_ENVIRONMENT` block: `env` without any `SystemRoot`/`PATH` (any case), plus
/// `SystemRoot=<windir>` and the system `PATH`, first occurrence of a name (case-insensitive)
/// wins, sorted case-insensitively by name, each entry `name=value\0`, then a final `\0`. A name
/// that is empty or contains `=` or NUL, or a value with NUL, is refused.
pub(crate) fn env_block(
    env: &[(OsString, OsString)],
    windir: &OsStr,
) -> Result<Vec<u16>, LaunchError> {
    let mut entries: Vec<(Vec<u16>, Vec<u16>)> = Vec::new();
    let fixed = [
        (OsString::from("SystemRoot"), windir.to_owned()),
        (OsString::from("PATH"), system_path(windir)),
    ];
    let given = env
        .iter()
        .filter(|(k, _)| {
            let k: Vec<u16> = k.encode_wide().collect();
            !is_name(&k, "SystemRoot") && !is_name(&k, "PATH")
        })
        .chain(fixed.iter());
    for (name, value) in given {
        let name: Vec<u16> = name.encode_wide().collect();
        let value: Vec<u16> = value.encode_wide().collect();
        if name.is_empty() || name.contains(&u16::from(b'=')) || name.contains(&0) {
            return Err(LaunchError::InvalidArgument);
        }
        if value.contains(&0) {
            return Err(LaunchError::InvalidArgument);
        }
        let key: Vec<u16> = name.iter().copied().map(upper).collect();
        let dup = entries
            .iter()
            .any(|(k, _)| k.iter().copied().map(upper).eq(key.iter().copied()));
        if !dup {
            entries.push((name, value));
        }
    }
    entries.sort_by(|(a, _), (b, _)| {
        a.iter()
            .copied()
            .map(upper)
            .cmp(b.iter().copied().map(upper))
    });
    let mut block = Vec::new();
    for (name, value) in entries {
        block.extend(name);
        block.push(u16::from(b'='));
        block.extend(value);
        block.push(0);
    }
    // Never empty (`SystemRoot` and `PATH` are always there): the final NUL ends the block.
    block.push(0);
    Ok(block)
}

/// UTF-16 with a terminating NUL; an embedded NUL is refused.
fn wide_nul(s: &OsStr) -> Result<Vec<u16>, LaunchError> {
    let mut w: Vec<u16> = s.encode_wide().collect();
    if w.contains(&0) {
        return Err(LaunchError::InvalidArgument);
    }
    w.push(0);
    Ok(w)
}

/// The command line for `argv` (NUL-terminated): `argv[0]` always quoted, other arguments quoted
/// when empty or containing a space or tab (trailing backslashes doubled before the closing
/// quote). An argument with `"` or NUL is refused (no path can contain them).
pub(crate) fn command_line(argv: &[OsString]) -> Result<Vec<u16>, LaunchError> {
    let mut out = Vec::new();
    for (i, arg) in argv.iter().enumerate() {
        let units: Vec<u16> = arg.encode_wide().collect();
        if units.contains(&0) || units.contains(&u16::from(b'"')) {
            return Err(LaunchError::InvalidArgument);
        }
        if i > 0 {
            out.push(u16::from(b' '));
        }
        let quote = i == 0
            || units.is_empty()
            || units
                .iter()
                .any(|u| *u == u16::from(b' ') || *u == u16::from(b'\t'));
        if quote {
            out.push(u16::from(b'"'));
        }
        out.extend(&units);
        if quote {
            if i > 0 {
                let trailing = units
                    .iter()
                    .rev()
                    .take_while(|u| **u == u16::from(b'\\'))
                    .count();
                out.extend(std::iter::repeat_n(u16::from(b'\\'), trailing));
            }
            out.push(u16::from(b'"'));
        }
    }
    out.push(0);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        SetInformationJobObject,
    };
    use windows_sys::Win32::System::Threading::{CREATE_SUSPENDED, ResumeThread};

    use super::*;

    fn text(units: &[u16]) -> String {
        String::from_utf16_lossy(units)
    }

    fn os(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }

    /// PD-24: records what this machine (and the Windows CI runner) reports; asserts nothing.
    #[test]
    fn gui_session_probe() {
        let p = session_probe();
        let session = p
            .session_id
            .map_or_else(|| "none".to_owned(), |s| s.to_string());
        let visible = p
            .wsf_visible
            .map_or_else(|| "none".to_owned(), |v| v.to_string());
        println!(
            "V13 session_id={session} wsf_visible={visible} shell_window={}",
            p.shell_window
        );
    }

    #[test]
    fn gui_session_rule() {
        let p = |session_id, wsf_visible| SessionProbe {
            session_id,
            wsf_visible,
            shell_window: false,
        };
        assert!(p(Some(1), Some(true)).is_gui());
        assert!(p(Some(7), Some(true)).is_gui());
        assert!(!p(Some(0), Some(true)).is_gui(), "session 0 is services");
        assert!(
            !p(Some(1), Some(false)).is_gui(),
            "invisible window station"
        );
        assert!(!p(None, Some(true)).is_gui());
        assert!(!p(Some(1), None).is_gui());
    }

    #[test]
    fn shell_parent_attribute_list_built() {
        // SAFETY: the pseudo handle needs no closing; the list only stores its value.
        let pseudo = unsafe { GetCurrentProcess() };
        let list = ParentAttribute::new(pseudo).unwrap();
        assert_eq!(
            list.attributes(),
            [PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize]
        );
        drop(list);

        let app = Path::new(r"C:\Program Files\atlas-duck\atlas-duck-app.exe");
        let target = Target::new(app, APP_ARGS, &os(&[("LANG", "C")])).unwrap();
        let spec = target.spec(SHELL_PARENT_FLAGS).unwrap();
        assert!(!spec.inherit_handles, "bInheritHandles = FALSE");
        assert_eq!(
            spec.flags,
            DETACHED_PROCESS
                | CREATE_NEW_PROCESS_GROUP
                | EXTENDED_STARTUPINFO_PRESENT
                | CREATE_UNICODE_ENVIRONMENT
        );
        assert_eq!(spec.flags & CREATE_BREAKAWAY_FROM_JOB, 0);
        assert_eq!(text(&spec.application), format!("{}\0", app.display()));
        assert_eq!(
            text(&spec.command_line),
            "\"C:\\Program Files\\atlas-duck\\atlas-duck-app.exe\" --background\0"
        );
        assert_eq!(
            text(&spec.current_dir),
            "C:\\Program Files\\atlas-duck\0",
            "cwd is the install dir"
        );
    }

    #[test]
    fn mismatched_extended_flag_is_refused_before_creation() {
        let app = Path::new(r"C:\x\atlas-duck-app.exe");
        let target = Target::new(app, APP_ARGS, &[]).unwrap();
        let spec = target.spec(SHELL_PARENT_FLAGS).unwrap();
        let err = create_process(&spec, None).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn stub_spec_flags() {
        for (breakaway, flags) in [
            (
                Breakaway::Granted,
                CREATE_BREAKAWAY_FROM_JOB
                    | DETACHED_PROCESS
                    | CREATE_NEW_PROCESS_GROUP
                    | CREATE_UNICODE_ENVIRONMENT,
            ),
            (
                Breakaway::Silent,
                DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
            ),
        ] {
            let extra = breakaway.extra_flags().unwrap();
            assert_eq!(DETACHED_FLAGS | extra, flags, "{breakaway:?}");
        }
        assert_eq!(Breakaway::Blocked.extra_flags(), None);
    }

    #[test]
    fn breakaway_decision_table() {
        let ok = JOB_OBJECT_LIMIT_BREAKAWAY_OK;
        let silent = JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
        // (in a job, limit flags) -> decision, `job_blocks_breakaway`.
        type Row = (Option<bool>, Option<u32>, Breakaway, Option<bool>);
        let rows: [Row; 9] = [
            (Some(false), None, Breakaway::NotInJob, Some(false)),
            (Some(false), Some(0), Breakaway::NotInJob, Some(false)),
            (Some(true), Some(ok), Breakaway::Granted, Some(false)),
            (
                Some(true),
                Some(ok | silent),
                Breakaway::Granted,
                Some(false),
            ),
            (Some(true), Some(silent), Breakaway::Silent, Some(false)),
            (Some(true), Some(0), Breakaway::Blocked, Some(true)),
            (
                Some(true),
                Some(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE),
                Breakaway::Blocked,
                Some(true),
            ),
            (Some(true), None, Breakaway::Unknown, None),
            (None, None, Breakaway::Unknown, None),
        ];
        for (in_job, flags, decision, blocks) in rows {
            let got = Breakaway::from_job(in_job, flags);
            assert_eq!(got, decision, "{in_job:?} {flags:?}");
            assert_eq!(got.blocks(), blocks, "{in_job:?} {flags:?}");
        }
    }

    #[test]
    fn access_denied_on_breakaway_is_blocked_by_job() {
        let denied = || io::Error::from_raw_os_error(5);
        // Only when the query said this process is in a job.
        for b in [Breakaway::Granted, Breakaway::Silent, Breakaway::Blocked] {
            assert!(
                matches!(stub_error(denied(), b), LaunchError::BlockedByJob),
                "{b:?}"
            );
        }
        for b in [Breakaway::NotInJob, Breakaway::Unknown] {
            assert!(
                matches!(stub_error(denied(), b), LaunchError::Io(_)),
                "{b:?}"
            );
        }
        assert!(matches!(
            stub_error(io::Error::from_raw_os_error(2), Breakaway::Granted),
            LaunchError::Io(_)
        ));
    }

    #[test]
    fn stub_exit_codes_map_back() {
        use super::super::stub::{EXIT_BLOCKED, EXIT_FAILED, EXIT_STARTED, EXIT_USAGE};

        let code = |c: i32| u32::from_ne_bytes(c.to_ne_bytes());
        assert!(matches!(stub_exit(code(EXIT_STARTED)), Ok(Started::Stub)));
        assert!(matches!(
            stub_exit(code(EXIT_BLOCKED)),
            Err(LaunchError::BlockedByJob)
        ));
        for c in [EXIT_FAILED, EXIT_USAGE, -1] {
            assert!(
                matches!(stub_exit(code(c)), Err(LaunchError::ChildFailed(got)) if got == c),
                "{c}"
            );
        }
    }

    #[test]
    fn job_blocks_breakaway_answers() {
        // The test process may or may not run in a job (terminals and CI runners often use one).
        let got = job_blocks_breakaway();
        println!("V13 test_process_job_blocks_breakaway={got:?}");
        assert!(got.is_some(), "the query works for the current process");
    }

    #[test]
    fn command_line_quoting() {
        let argv = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        let cl = |a: &[&str]| text(&command_line(&argv(a)).unwrap());
        assert_eq!(
            cl(&[r"C:\a\atlas-duck-app.exe", "--background"]),
            "\"C:\\a\\atlas-duck-app.exe\" --background\0"
        );
        assert_eq!(
            cl(&[
                r"C:\Program Files\x\atlas-duck.exe",
                "__launch-stub",
                r"C:\Program Files\x\atlas-duck-app.exe"
            ]),
            "\"C:\\Program Files\\x\\atlas-duck.exe\" __launch-stub \"C:\\Program Files\\x\\atlas-duck-app.exe\"\0"
        );
        // A quoted argument's trailing backslashes are doubled so the quote stays a quote.
        assert_eq!(
            cl(&["p", r"C:\dir with space\"]),
            "\"p\" \"C:\\dir with space\\\\\"\0"
        );
        assert_eq!(cl(&["p", ""]), "\"p\" \"\"\0");
        assert_eq!(cl(&["p", "a\tb"]), "\"p\" \"a\tb\"\0");
        assert!(matches!(
            command_line(&argv(&["p", "a\"b"])),
            Err(LaunchError::InvalidArgument)
        ));
        assert!(matches!(
            command_line(&argv(&["p\0"])),
            Err(LaunchError::InvalidArgument)
        ));
    }

    #[test]
    fn env_block_sorted_utf16_double_nul_system_root_from_windir() {
        let env = os(&[
            ("TEMP", r"C:\Users\u\AppData\Local\Temp"),
            ("Path", r"C:\evil"),
            ("SYSTEMROOT", r"C:\evil-root"),
            ("lc_all", "C"),
            ("LANG", "C"),
            ("USERPROFILE", r"C:\Users\u"),
            ("Lang", "second"),
        ]);
        let block = env_block(&env, OsStr::new(r"D:\Win")).unwrap();
        assert_eq!(&block[block.len() - 2..], [0, 0], "double-NUL terminated");
        let body = &block[..block.len() - 1];
        let entries: Vec<String> = body
            .split(|u| *u == 0)
            .filter(|e| !e.is_empty())
            .map(text)
            .collect();
        assert_eq!(
            entries,
            [
                "LANG=C",
                "lc_all=C",
                r"PATH=D:\Win\System32;D:\Win;D:\Win\System32\Wbem",
                r"SystemRoot=D:\Win",
                r"TEMP=C:\Users\u\AppData\Local\Temp",
                r"USERPROFILE=C:\Users\u",
            ]
        );
        assert!(!text(&block).contains("evil"));
    }

    #[test]
    fn env_block_refuses_unpassable_entries() {
        for bad in [
            os(&[("", "x")]),
            os(&[("A=B", "x")]),
            os(&[("A\0", "x")]),
            os(&[("A", "x\0y")]),
        ] {
            assert!(
                matches!(
                    env_block(&bad, OsStr::new(r"C:\Windows")),
                    Err(LaunchError::InvalidArgument)
                ),
                "{bad:?}"
            );
        }
        // Nothing allowlisted: still SystemRoot and PATH.
        let block = env_block(&[], OsStr::new(r"C:\Windows")).unwrap();
        assert!(text(&block).starts_with("PATH="));
    }

    #[test]
    fn system_windows_dir_is_absolute_and_not_from_the_environment() {
        let dir = system_windows_dir().unwrap();
        assert!(dir.is_absolute());
        assert!(dir.join("System32").is_dir(), "{}", dir.display());
    }

    #[test]
    fn verbatim_prefix_stripped_for_drive_paths_only() {
        assert_eq!(
            strip_verbatim(Path::new(r"\\?\C:\Program Files\a.exe")),
            Path::new(r"C:\Program Files\a.exe")
        );
        assert_eq!(
            strip_verbatim(Path::new(r"\\?\UNC\server\share\a.exe")),
            Path::new(r"\\?\UNC\server\share\a.exe")
        );
        assert_eq!(
            strip_verbatim(Path::new(r"C:\a.exe")),
            Path::new(r"C:\a.exe")
        );
        // The command line and the working directory never carry the prefix.
        let target = Target::new(Path::new(r"\\?\C:\x\atlas-duck-app.exe"), APP_ARGS, &[]).unwrap();
        let spec = target.spec(DETACHED_FLAGS).unwrap();
        assert_eq!(text(&spec.current_dir), "C:\\x\0");
        assert_eq!(
            text(&spec.command_line),
            "\"C:\\x\\atlas-duck-app.exe\" --background\0"
        );
    }

    #[test]
    fn relative_program_is_refused() {
        assert!(matches!(
            Target::new(Path::new("atlas-duck-app.exe"), APP_ARGS, &[]),
            Err(LaunchError::InvalidArgument)
        ));
    }

    #[test]
    fn stub_command_under_the_cli_and_under_cli_dispatch() {
        let app = Path::new(r"C:\a\atlas-duck-app.exe");
        let strs = |v: Vec<OsString>| {
            v.into_iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            strs(stub_command(Path::new(r"C:\a\atlas-duck.exe"), app)),
            [
                r"C:\a\atlas-duck.exe",
                "__launch-stub",
                r"C:\a\atlas-duck-app.exe"
            ]
        );
        // `atlas-duck-app __cli ...`: the stub must go through the same dispatch.
        assert_eq!(
            strs(stub_command(Path::new(r"C:\a\Atlas-Duck-App.EXE"), app)),
            [
                r"C:\a\Atlas-Duck-App.EXE",
                "__cli",
                "__launch-stub",
                r"C:\a\atlas-duck-app.exe"
            ]
        );
    }

    /// The parent pid of `pid` from a Toolhelp snapshot.
    fn parent_of(pid: u32) -> Option<u32> {
        // SAFETY: plain call; the handle is owned below.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap.is_null() || snap == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: a fresh snapshot handle.
        let snap = unsafe { OwnedHandle::from_raw_handle(snap) };
        let mut entry = PROCESSENTRY32W {
            dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).unwrap(),
            ..Default::default()
        };
        // SAFETY: `entry.dwSize` is set; the snapshot handle is valid.
        let mut more = unsafe { Process32FirstW(snap.as_raw_handle(), &mut entry) } != 0;
        while more {
            if entry.th32ProcessID == pid {
                return Some(entry.th32ParentProcessID);
            }
            // SAFETY: as above.
            more = unsafe { Process32NextW(snap.as_raw_handle(), &mut entry) } != 0;
        }
        None
    }

    /// V13 (§4.7 step 1): a process started through the shell-parent path is the shell's child.
    /// `timeout.exe` refuses to run without a console, so `ping -n 4` keeps the probe alive ~3 s.
    #[test]
    #[ignore = "starts a detached process under the shell; run on the T26 Windows leg with --ignored --nocapture"]
    fn shell_parent_launch_parent_is_explorer() {
        let Some(shell_pid) = shell_pid() else {
            println!("V13 shell_window=none");
            // Without a shell `spawn_detached` goes to the stub (step 2).
            assert!(matches!(shell_process(), Err(ShellError::NoShellWindow)));
            return;
        };
        let windir = system_windows_dir().unwrap();
        let ping = windir.join("System32").join("PING.EXE");
        let env = super::super::env::launch_env(std::env::vars_os());
        let target = Target::new(&ping, &["-n", "4", "127.0.0.1"], &env).unwrap();
        let pid = via_shell_parent(&target).unwrap();
        let parent = parent_of(pid);
        println!("V13 shell_parent pid={pid} parent={parent:?} shell={shell_pid}");
        assert_eq!(parent, Some(shell_pid));
        assert_ne!(parent, Some(std::process::id()));
    }

    const PROBE_OUT: &str = "ATLAS_DUCK_T15_JOB_PROBE_OUT";

    /// The child half of `job_blocks_breakaway_detects`: writes `job_blocks_breakaway()` to the
    /// file named by `PROBE_OUT`; does nothing when run on its own.
    #[test]
    #[ignore = "child half of job_blocks_breakaway_detects"]
    fn job_probe_child() {
        if let Some(out) = std::env::var_os(PROBE_OUT) {
            std::fs::write(out, format!("{:?}", job_blocks_breakaway())).unwrap();
        }
    }

    /// Runs `job_probe_child` in a fresh job with `limit_flags` and returns what it wrote.
    fn probe_in_job(limit_flags: u32) -> String {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("probe.txt");
        // SAFETY: plain call; owned below.
        let job = unsafe { CreateJobObjectW(null(), null()) };
        assert!(!job.is_null());
        // SAFETY: a fresh job handle.
        let job = unsafe { OwnedHandle::from_raw_handle(job) };
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = limit_flags | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `info` is a local of the stated size.
        let set = unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap(),
            )
        };
        assert_ne!(set, 0);

        let exe = std::env::current_exe().unwrap();
        let mut env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        env.push((OsString::from(PROBE_OUT), out.clone().into_os_string()));
        let argv: Vec<OsString> = [
            exe.as_os_str(),
            OsStr::new("--exact"),
            OsStr::new("launch::windows::tests::job_probe_child"),
            OsStr::new("--ignored"),
            OsStr::new("--test-threads=1"),
        ]
        .iter()
        .map(|s| s.to_os_string())
        .collect();
        let windir = system_windows_dir().unwrap();
        let spec = create_spec(
            &exe,
            &argv,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS,
            env_block(&env, windir.as_os_str()).unwrap(),
            tmp.path(),
        )
        .unwrap();
        let child = create_process(&spec, None).unwrap();
        // SAFETY: handles we own.
        unsafe {
            assert_ne!(
                AssignProcessToJobObject(job.as_raw_handle(), child.process.as_raw_handle()),
                0
            );
            assert_ne!(ResumeThread(child.thread.as_raw_handle()), u32::MAX);
        }
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(s) = std::fs::read_to_string(&out)
                && !s.is_empty()
            {
                return s;
            }
            assert!(Instant::now() < until, "the probe child never answered");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    #[ignore = "starts this test binary in a job; run on the T26 Windows leg with --ignored --nocapture"]
    fn job_blocks_breakaway_detects() {
        assert_eq!(probe_in_job(0), "Some(true)");
        assert_eq!(probe_in_job(JOB_OBJECT_LIMIT_BREAKAWAY_OK), "Some(false)");
        assert_eq!(
            probe_in_job(JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK),
            "Some(false)"
        );
        // Not in a job: only observable when this test process itself is in none.
        if in_any_job() == Some(false) {
            assert_eq!(job_blocks_breakaway(), Some(false));
        } else {
            println!("V13 test_process_in_job=true (not-in-job case: decision table only)");
        }
    }
}
