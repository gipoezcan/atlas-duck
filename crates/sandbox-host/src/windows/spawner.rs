//! `CreateProcessW` with `STARTUPINFOEX` (§3.4 Windows).
//!
//! Attributes: `HANDLE_LIST` (the three pipe ends), `SECURITY_CAPABILITIES`
//! (the AppContainer SID, zero capabilities), `JOB_LIST` (the worker is in its
//! job before its first instruction) and, when every file carries the
//! `S-1-15-2-2` ACE, `ALL_APPLICATION_PACKAGES_POLICY = OPT_OUT` (LPAC).

use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, HANDLE, TRUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
use windows_sys::Win32::System::JobObjects::IsProcessInJob;
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DETACHED_PROCESS, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
    WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;

use super::aces::{AceStatus, check_aces, worker_ace_files_for_exe};
use super::appcontainer::AppContainer;
use super::job::{Job, JobLimits, JobSnapshot};
use super::pipes::{FrameReader, StdinPipe, create_stdio_pipes, drain_stderr};
use super::{APPCONTAINER_NAME, WORKER_ENV_NAMES, WORKER_ENV_OS_REQUIRED, wide};
use crate::spawn::{ExitKind, SpawnSpec, WorkerProcess, WorkerSpawner};

/// The worker is a console-subsystem binary (T04), but it never needs a
/// console: its stdio is the three pipes. `DETACHED_PROCESS` gives it none, so
/// no `conhost.exe` is created for it (a second process would also run into
/// the job's `ACTIVE_PROCESS = 1`). If the first CI run shows the worker never
/// sends `probe.ready` with this flag, the documented alternative is
/// `CREATE_NO_WINDOW`.
const WORKER_CREATION_FLAGS: u32 =
    EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS;

/// Names the spawn stage that failed on stderr and passes the error on
/// unchanged (the raw OS code is what the probes report). The first CI run
/// (windows-2022) failed every spawn with a bare 87.
fn stage(name: &'static str) -> impl FnOnce(io::Error) -> io::Error {
    move |e| {
        eprintln!("spawn stage `{name}` failed: {e}");
        e
    }
}

/// Held from the moment the worker's three pipe ends are made inheritable
/// until they are closed again, so that two worker spawns of ours cannot hand
/// each other's pipe ends to a worker. Every handle is created non-inheritable
/// and only those three are ever inheritable (see `pipes.rs`); a child that
/// another part of the app creates inside that window (one `CreateProcessW`
/// call) with inheritance on and no handle list could still receive a copy of
/// the three ends. The worker itself only ever gets the three handles of its own
/// `HANDLE_LIST`.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());
static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// How a worker is started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confinement {
    /// AppContainer; LPAC when every file has the `S-1-15-2-2` ACE.
    Default,
    /// AppContainer, never LPAC (the fallback of section 9.4).
    PlainAppContainer,
    /// No AppContainer, no ACE check: the scoring control only (the probe
    /// runner runs a few probes unconfined to see what a normal answer is). It
    /// is still in its own job.
    Unconfined,
}

/// Starts workers in the AppContainer `atlas-duck.sandbox`.
pub struct WindowsSpawner {
    container: AppContainer,
    plain: bool,
}

impl WindowsSpawner {
    /// Creates (or opens) the AppContainer profile. Fails when profile
    /// creation is blocked; the degraded path is M8, so the caller then
    /// reports every probe as `SpawnFailed` and the floor as not met.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            container: AppContainer::open(APPCONTAINER_NAME)?,
            plain: false,
        })
    }

    /// Like [`WindowsSpawner::new`], but every worker is a plain AppContainer
    /// (never LPAC), even when every file has the `S-1-15-2-2` ACE. This is the
    /// fallback of section 9.4 when the LPAC floor is not met.
    pub fn new_plain() -> io::Result<Self> {
        Ok(Self {
            plain: true,
            ..Self::new()?
        })
    }

    /// The AppContainer SID in string form (`S-1-15-2-...`), for the log.
    pub fn container_sid(&self) -> &str {
        self.container.sid_string()
    }

    /// Like [`WorkerSpawner::spawn`] but returns the concrete worker, which
    /// exposes the job and the LPAC decision (the T19 tests read them).
    pub fn spawn_process(&self, spec: &SpawnSpec) -> io::Result<WindowsProcess> {
        let confinement = if self.plain {
            Confinement::PlainAppContainer
        } else {
            Confinement::Default
        };
        self.spawn_with(spec, confinement)
    }

    /// The scoring control: the worker without AppContainer (see
    /// [`Confinement::Unconfined`]).
    pub fn spawn_unconfined(&self, spec: &SpawnSpec) -> io::Result<WindowsProcess> {
        self.spawn_with(spec, Confinement::Unconfined)
    }

    fn spawn_with(&self, spec: &SpawnSpec, confinement: Confinement) -> io::Result<WindowsProcess> {
        if spec.process_mb == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "process_mb must be greater than 0",
            ));
        }
        let exe = std::path::absolute(&spec.exe).map_err(stage("absolute exe"))?;

        // 1. ACEs: a plain AppContainer needs S-1-15-2-1 on every file; LPAC
        //    additionally S-1-15-2-2. Without them the worker would not load,
        //    so fail here instead of falling back to anything weaker.
        let lpac = if confinement == Confinement::Unconfined {
            false
        } else {
            let files =
                worker_ace_files_for_exe(&exe).map_err(stage("worker_ace_files_for_exe"))?;
            match check_aces(&files).map_err(stage("check_aces"))? {
                AceStatus::AllPresent { lpac_ready } => {
                    lpac_ready && confinement == Confinement::Default
                }
                AceStatus::Missing(_) => {
                    return Err(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32));
                }
            }
        };

        // 2. job, run directory
        let job = Job::create(JobLimits::from_process_mb(spec.process_mb))
            .map_err(stage("Job::create"))?;
        let run_dir = RunDir::create(self.container.run_root()).map_err(stage("RunDir::create"))?;

        // 3. pipes, attribute list, environment, command line
        let _guard = SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (host, child) = create_stdio_pipes().map_err(stage("create_stdio_pipes"))?;
        let handles: [HANDLE; 3] = [
            child.stdin.as_raw_handle().cast(),
            child.stdout.as_raw_handle().cast(),
            child.stderr.as_raw_handle().cast(),
        ];
        let sid = (confinement != Confinement::Unconfined).then(|| self.container.sid());
        let mut attrs =
            ProcAttrs::new(handles, sid, job.raw(), lpac).map_err(stage("ProcAttrs::new"))?;
        let env = environment_block(self.container.local_app_data())
            .map_err(stage("environment_block"))?;
        let mut cmdline = wide(OsStr::new(&format!("\"{}\"", exe.display())));
        let exe_w = wide(exe.as_os_str());
        let cwd_w = wide(run_dir.path().as_os_str());

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

        // SAFETY: every pointer is valid for the call: NUL-terminated wide
        // strings, a mutable command line, a double-NUL-terminated
        // environment block, a STARTUPINFOEXW whose attribute list (and the
        // values it points at) lives in `attrs` until after the call.
        let ok = unsafe {
            CreateProcessW(
                exe_w.as_ptr(),
                cmdline.as_mut_ptr(),
                null(),
                null(),
                TRUE,
                WORKER_CREATION_FLAGS,
                env.as_ptr().cast(),
                cwd_w.as_ptr(),
                &si.StartupInfo,
                &mut pi,
            )
        };
        if ok == 0 {
            // Which call failed is invisible in a bare `SpawnFailed(87)`: the
            // first CI run (windows-2022) failed here with 87 and nothing else.
            let err = io::Error::last_os_error();
            let mut in_job = 0;
            // SAFETY: the pseudo handle of this process and a valid out pointer.
            unsafe { IsProcessInJob(GetCurrentProcess(), null_mut(), &mut in_job) };
            eprintln!(
                "CreateProcessW failed: {err}; lpac={lpac}, flags={WORKER_CREATION_FLAGS:#x}, host_in_job={}, exe={}",
                in_job != 0,
                exe.display()
            );
            return Err(err);
        }
        // SAFETY: both handles were just returned to us.
        let process = unsafe { OwnedHandle::from_raw_handle(pi.hProcess as RawHandle) };
        // SAFETY: the primary thread handle is not needed.
        unsafe { CloseHandle(pi.hThread) };
        // The worker has its ends; closing ours makes EOF reach the reader
        // when the worker exits.
        drop(attrs);
        drop(child);
        drop(_guard);

        let frames = FrameReader::start(host.stdout)?;
        let stderr = drain_stderr(host.stderr)?;
        Ok(WindowsProcess {
            stdin: StdinPipe::new(host.stdin),
            frames,
            stderr,
            job: Some(job),
            process,
            pid: pi.dwProcessId,
            exit: None,
            lpac,
            run_dir,
        })
    }
}

impl WorkerSpawner for WindowsSpawner {
    fn spawn(&self, spec: &SpawnSpec) -> io::Result<Box<dyn WorkerProcess>> {
        Ok(Box::new(self.spawn_process(spec)?))
    }

    fn spawn_control(&self, spec: &SpawnSpec) -> io::Result<Box<dyn WorkerProcess>> {
        Ok(Box::new(self.spawn_unconfined(spec)?))
    }
}

/// One running worker. Dropping it kills the worker (job terminate, then job
/// close, which `KILL_ON_JOB_CLOSE` also covers if the host dies first).
pub struct WindowsProcess {
    stdin: StdinPipe,
    frames: FrameReader,
    stderr: Arc<Mutex<Vec<u8>>>,
    job: Option<Job>,
    process: OwnedHandle,
    pid: u32,
    exit: Option<ExitKind>,
    lpac: bool,
    run_dir: RunDir,
}

impl WindowsProcess {
    /// True when the worker was started with the LPAC opt-out.
    pub fn is_lpac(&self) -> bool {
        self.lpac
    }

    /// The worker's current directory (an empty per-run directory).
    pub fn run_dir(&self) -> &Path {
        self.run_dir.path()
    }

    /// Limits and members of the worker's job, read back from the OS.
    pub fn job_snapshot(&self) -> io::Result<JobSnapshot> {
        match &self.job {
            Some(job) => job.snapshot(),
            None => Err(io::Error::other("job already closed")),
        }
    }

    /// The first 64 KiB the worker wrote to stderr (for test diagnostics; never
    /// logged).
    pub fn stderr_head(&self) -> Vec<u8> {
        self.stderr
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Raw process handle (for tests that inspect the worker from outside).
    pub fn process_handle(&self) -> RawHandle {
        self.process.as_raw_handle()
    }
}

impl WorkerProcess for WindowsProcess {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn stdin(&mut self) -> &mut dyn io::Write {
        &mut self.stdin
    }

    fn read_frame_timeout(&mut self, max: usize, d: Duration) -> io::Result<Option<Vec<u8>>> {
        self.frames.recv(max, d)
    }

    fn close_stdin(&mut self) {
        self.stdin.close();
    }

    fn wait_timeout(&mut self, d: Duration) -> io::Result<Option<ExitKind>> {
        if let Some(e) = self.exit {
            return Ok(Some(e));
        }
        // Rounded up to whole milliseconds; `u32::MAX` is INFINITE, so the
        // longest wait is just under 50 days.
        let millis = d.as_millis() + u128::from(!d.subsec_nanos().is_multiple_of(1_000_000));
        let ms = u32::try_from(millis)
            .unwrap_or(u32::MAX - 1)
            .min(u32::MAX - 1);
        // SAFETY: valid process handle.
        match unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), ms) } {
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                // SAFETY: valid process handle and out-pointer.
                if unsafe { GetExitCodeProcess(self.process.as_raw_handle().cast(), &mut code) }
                    == 0
                {
                    return Err(io::Error::last_os_error());
                }
                // NTSTATUS exit codes such as 0xC0000005 keep their bit pattern.
                let e = ExitKind::Code(code as i32);
                self.exit = Some(e);
                Ok(Some(e))
            }
            WAIT_TIMEOUT => Ok(None),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            other => Err(io::Error::other(format!("unexpected wait result {other}"))),
        }
    }

    fn kill(&mut self) -> io::Result<()> {
        match &self.job {
            Some(job) => job.terminate(),
            None => Ok(()),
        }
    }
}

impl Drop for WindowsProcess {
    fn drop(&mut self) {
        self.stdin.close();
        if let Some(job) = self.job.take() {
            let _ = job.terminate();
            drop(job); // CloseHandle: KILL_ON_JOB_CLOSE
        }
        // Give the kill up to 1 s to land, so the run dir can be removed.
        // SAFETY: valid process handle.
        unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), 1000) };
    }
}

/// An empty directory below the container's `AC` folder, removed on drop.
struct RunDir(PathBuf);

impl RunDir {
    fn create(root: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(root)?;
        // `create_dir` (not `create_dir_all`) so that a directory left behind
        // by a crashed host with the same pid is never reused: the worker's
        // working directory is always new and empty.
        loop {
            let n = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = root.join(format!("{}-{n}", std::process::id()));
            match std::fs::create_dir(&dir) {
                Ok(()) => return Ok(Self(dir)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The worker's environment as a UTF-16 block (sorted by name, double-NUL
/// terminated): `LOCALAPPDATA=<local_app_data>`, `SystemRoot=<windows dir>` and
/// `TZ=UTC0`, built here and never taken from the session (§3.4).
///
/// `LOCALAPPDATA` is not our choice: measured on Windows 11, `CreateProcessW`
/// with `SECURITY_CAPABILITIES` fails with `ERROR_ENVVAR_NOT_FOUND` (203) when
/// the block has no `LOCALAPPDATA`, and then derives the container's own
/// `LOCALAPPDATA`, `TEMP` and `TMP` from it (all three end up inside
/// `Packages\<name>\AC`). The worker therefore sees [`super::WORKER_ENV_OBSERVED`].
fn environment_block(local_app_data: &Path) -> io::Result<Vec<u16>> {
    let mut buf = vec![0u16; 260];
    // SAFETY: `buf` is writable for `buf.len()` elements.
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 {
        return Err(io::Error::last_os_error());
    }
    if n >= buf.len() {
        return Err(io::Error::other("the Windows directory path is too long"));
    }
    // UTF-16 all the way: no lossy conversion of either path.
    let mut block: Vec<u16> = Vec::new();
    let mut entry = |name: &str, value: &[u16]| {
        block.extend(name.encode_utf16());
        block.push(u16::from(b'='));
        block.extend_from_slice(value);
        block.push(0);
    };
    let lad: Vec<u16> = local_app_data.as_os_str().encode_wide().collect();
    entry(WORKER_ENV_OS_REQUIRED, &lad);
    entry(WORKER_ENV_NAMES[0], &buf[..n]);
    entry(
        WORKER_ENV_NAMES[1],
        &"UTC0".encode_utf16().collect::<Vec<u16>>(),
    );
    block.push(0);
    Ok(block)
}

/// A `PROC_THREAD_ATTRIBUTE_LIST` and the values it points at.
struct ProcAttrs {
    /// Backing store of the list (8-byte aligned).
    buf: Vec<u64>,
    _handles: Box<[HANDLE; 3]>,
    _caps: Box<SECURITY_CAPABILITIES>,
    with_caps: bool,
    _jobs: Box<[HANDLE; 1]>,
    _policy: Box<u32>,
}

impl ProcAttrs {
    /// `sid = None` leaves out `SECURITY_CAPABILITIES`: no AppContainer (the
    /// unconfined scoring control); `lpac` is then `false`.
    fn new(
        handles: [HANDLE; 3],
        sid: Option<*mut c_void>,
        job: HANDLE,
        lpac: bool,
    ) -> io::Result<Self> {
        let count: u32 = 2 + u32::from(sid.is_some()) + u32::from(lpac);
        let mut size = 0usize;
        // SAFETY: the documented size query: NULL list, valid size pointer.
        // The call fails with ERROR_INSUFFICIENT_BUFFER and sets `size`.
        unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u64; size.div_ceil(8)];
        let list: LPPROC_THREAD_ATTRIBUTE_LIST = buf.as_mut_ptr().cast();
        // SAFETY: `buf` is at least `size` bytes and suitably aligned.
        if unsafe { InitializeProcThreadAttributeList(list, count, 0, &mut size) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut me = Self {
            buf,
            _handles: Box::new(handles),
            with_caps: sid.is_some(),
            _caps: Box::new(SECURITY_CAPABILITIES {
                AppContainerSid: sid.unwrap_or(null_mut()),
                Capabilities: null_mut(),
                CapabilityCount: 0,
                Reserved: 0,
            }),
            _jobs: Box::new([job]),
            _policy: Box::new(PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT),
        };
        let list = me.list();
        let update = |name: &str, attr: u32, value: *const c_void, size: usize| -> io::Result<()> {
            // SAFETY: `list` was initialised above; `value` points at `size`
            // bytes owned by `me`, which outlives the CreateProcessW call.
            if unsafe {
                UpdateProcThreadAttribute(list, 0, attr as usize, value, size, null_mut(), null())
            } == 0
            {
                let err = io::Error::last_os_error();
                eprintln!("UpdateProcThreadAttribute({name}) failed: {err}");
                return Err(err);
            }
            Ok(())
        };
        update(
            "HANDLE_LIST",
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            me._handles.as_ptr().cast(),
            std::mem::size_of::<[HANDLE; 3]>(),
        )?;
        if me.with_caps {
            update(
                "SECURITY_CAPABILITIES",
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                (&*me._caps as *const SECURITY_CAPABILITIES).cast(),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
            )?;
        }
        update(
            "JOB_LIST",
            PROC_THREAD_ATTRIBUTE_JOB_LIST,
            me._jobs.as_ptr().cast(),
            std::mem::size_of::<[HANDLE; 1]>(),
        )?;
        if lpac {
            update(
                "ALL_APPLICATION_PACKAGES_POLICY",
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                (&*me._policy as *const u32).cast(),
                std::mem::size_of::<u32>(),
            )?;
        }
        Ok(me)
    }

    fn list(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buf.as_mut_ptr().cast()
    }
}

impl Drop for ProcAttrs {
    fn drop(&mut self) {
        // SAFETY: the list was initialised in `new` and is deleted once.
        unsafe { DeleteProcThreadAttributeList(self.buf.as_mut_ptr().cast()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_block_is_localappdata_systemroot_and_tz_only() {
        let block = environment_block(Path::new(r"C:\lad")).expect("environment block");
        assert_eq!(&block[block.len() - 2..], &[0, 0], "double NUL terminator");
        let text = String::from_utf16_lossy(&block[..block.len() - 2]);
        let entries: Vec<&str> = text.split('\0').collect();
        assert_eq!(entries.len(), 3, "{entries:?}");
        assert_eq!(entries[0], r"LOCALAPPDATA=C:\lad");
        assert!(entries[1].starts_with("SystemRoot="), "{entries:?}");
        assert!(entries[1].len() > "SystemRoot=".len(), "{entries:?}");
        assert_eq!(entries[2], "TZ=UTC0");
        let names: Vec<&str> = entries
            .iter()
            .map(|e| e.split('=').next().unwrap_or(""))
            .collect();
        assert_eq!(
            names,
            [
                WORKER_ENV_OS_REQUIRED,
                WORKER_ENV_NAMES[0],
                WORKER_ENV_NAMES[1]
            ]
        );
    }
}
