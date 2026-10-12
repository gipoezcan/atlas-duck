//! Windows named-pipe transport (§3.1 Windows, §3.2 (a), §4.7, V01).
//!
//! Server: `PipeListener::bind` creates the first instance of a fresh random
//! pipe name with `FILE_FLAG_FIRST_PIPE_INSTANCE`, remote clients rejected
//! and the `PipeSecurity` descriptor; `accept` creates the next instance
//! before it hands a connected one off, so one instance always listens.
//! After the `hello` frame was read, `verify_client_sid` impersonates the
//! client and compares its token SID. Client: `connect_checked` opens with
//! `SECURITY_IDENTIFICATION` QoS, waits at most 5 s on `ERROR_PIPE_BUSY`, and
//! runs the server-owner check before the caller can write a byte.

pub mod security;

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::time::{Duration, Instant};

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_CANT_OPEN_ANONYMOUS, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, HANDLE,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::{
    GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
    SECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, SecurityIdentification, TOKEN_QUERY,
    TokenImpersonationLevel,
};
use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, ImpersonateNamedPipeClient,
    WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use self::security::PipeSecurity;
use crate::paths::{current_user_sid_string, hex_lower, pipe_name_has_prefix};
use crate::win_security::{LocalFreeOnDrop, Sid, sid_to_string};

/// Fresh names `bind` tries before giving up (§3.1: the suffix is
/// regenerated on bind failure, never retried without the first-instance
/// flag).
const BIND_ATTEMPTS: usize = 5;
/// Bytes of randomness in the pipe-name suffix (32 hex digits, 128 bits).
const SUFFIX_BYTES: usize = 16;
/// Longest `WaitNamedPipeW` on `ERROR_PIPE_BUSY` (§4.7).
pub(crate) const BUSY_WAIT_MAX: Duration = Duration::from_secs(5);

const MSG_NO_RUNTIME: &str = "the named-pipe transport needs a tokio runtime";
const MSG_FOREIGN_NAME: &str = "pipe name does not carry the expected prefix";
const MSG_NUL: &str = "pipe name contains a NUL";
const MSG_NO_RANDOM: &str = "no system randomness for the pipe name";
const MSG_LISTENER_DONE: &str = "the pipe listener stopped after an accept error";
const MSG_JOIN: &str = "a blocking pipe task did not complete";

/// `prefix` + 32 random lowercase hex digits (§3.1).
pub fn new_pipe_name(prefix: &str) -> io::Result<String> {
    let mut bytes = [0u8; SUFFIX_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other(MSG_NO_RANDOM))?;
    Ok(format!("{prefix}{}", hex_lower(&bytes)))
}

fn require_runtime() -> io::Result<()> {
    tokio::runtime::Handle::try_current()
        .map(drop)
        .map_err(|_| io::Error::other(MSG_NO_RUNTIME))
}

/// Creates one instance of `name` with `security`, remote clients rejected.
fn create_instance(
    name: &str,
    security: &PipeSecurity,
    first: bool,
) -> io::Result<NamedPipeServer> {
    let mut attrs: SECURITY_ATTRIBUTES = security.attributes();
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first).reject_remote_clients(true);
    // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES whose descriptor lives in
    // `security`, borrowed for the whole call; CreateNamedPipeW copies it.
    unsafe { opts.create_with_security_attributes_raw(name, (&raw mut attrs).cast()) }
}

/// The server end: the pipe name and the one instance that listens.
#[derive(Debug)]
pub struct PipeListener {
    name: String,
    security: PipeSecurity,
    /// The listening instance; `None` once an `accept` failed.
    next: Option<NamedPipeServer>,
}

impl PipeListener {
    /// Creates the first instance of `prefix` + a fresh random suffix
    /// (§3.1): `first_pipe_instance(true)`, `reject_remote_clients(true)`,
    /// the `PipeSecurity` descriptor. If the name is taken
    /// (`ERROR_ACCESS_DENIED`, `ERROR_PIPE_BUSY`) a new suffix is drawn, at
    /// most 5 names in all; the flag is never dropped.
    ///
    /// Must be called inside a tokio runtime with IO enabled.
    pub fn bind(prefix: &str) -> io::Result<PipeListener> {
        bind_with_names(prefix, &mut || new_pipe_name(prefix))
    }

    /// The full pipe name (for the endpoint file).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Waits for a client on the listening instance, then creates the next
    /// instance (same descriptor, no first-instance flag) before it returns
    /// the connected one, so a client never finds no listening instance
    /// (§3.1). Returns the connected instance and the client's pid
    /// (`GetNamedPipeClientProcessId`, display only; `None` if unreadable).
    ///
    /// Errors: creating the next instance failed (the connected client is
    /// dropped), or `ConnectNamedPipe` on the listening instance failed (a
    /// client that opens and closes at once is not an error: mio treats
    /// `ERROR_NO_DATA` as connected). Either way the listener is done: it
    /// holds no instance any more and every later `accept` returns an error
    /// at once; the IPC server stops (§3.1).
    ///
    /// Cancel-safe: nothing is awaited after the connect completes.
    pub async fn accept(&mut self) -> io::Result<(NamedPipeServer, Option<u32>)> {
        self.accept_with(|name, security| create_instance(name, security, false))
            .await
    }

    /// `accept` with the next-instance factory injected (tests fail it).
    async fn accept_with(
        &mut self,
        make_next: impl FnOnce(&str, &PipeSecurity) -> io::Result<NamedPipeServer>,
    ) -> io::Result<(NamedPipeServer, Option<u32>)> {
        let Some(listening) = self.next.as_mut() else {
            return Err(io::Error::other(MSG_LISTENER_DONE));
        };
        if let Err(e) = listening.connect().await {
            self.next = None;
            return Err(e);
        }
        match make_next(&self.name, &self.security) {
            Ok(fresh) => {
                let connected = self.next.replace(fresh);
                let Some(connected) = connected else {
                    return Err(io::Error::other(MSG_LISTENER_DONE));
                };
                let pid = client_pid(connected.as_handle());
                Ok((connected, pid))
            }
            Err(e) => {
                // Drops the connected client with the listening instance.
                self.next = None;
                Err(e)
            }
        }
    }
}

/// `PipeListener::bind` with an explicit name source; every name must be
/// `prefix` + 32 hex digits. Production code calls `bind`; tests feed a
/// squatted name to exercise the regenerate path.
#[doc(hidden)]
pub fn bind_with_names(
    prefix: &str,
    next_name: &mut dyn FnMut() -> io::Result<String>,
) -> io::Result<PipeListener> {
    require_runtime()?;
    let security = PipeSecurity::for_current_user()?;
    let mut last = None;
    for _ in 0..BIND_ATTEMPTS {
        let name = next_name()?;
        if !pipe_name_has_prefix(&name, prefix) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                MSG_FOREIGN_NAME,
            ));
        }
        match create_instance(&name, &security, true) {
            Ok(next) => {
                return Ok(PipeListener {
                    name,
                    security,
                    next: Some(next),
                });
            }
            Err(e) if name_taken(&e) => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied)))
}

/// The errors `CreateNamedPipeW` gives for a name some other pipe holds.
fn name_taken(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::PermissionDenied
        || matches!(
            e.raw_os_error(),
            Some(c) if c == ERROR_ACCESS_DENIED as i32 || c == ERROR_PIPE_BUSY as i32
        )
}

fn client_pid(pipe: BorrowedHandle<'_>) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is a live server pipe handle; `pid` is a valid out-pointer.
    let ok = unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) };
    (ok != 0).then_some(pid)
}

// ---------- impersonation check ----------

/// Reverts the calling thread to the process token on drop. If that fails
/// the thread would keep running as the client, so the process aborts
/// (§3.1).
struct RevertOnDrop;

impl Drop for RevertOnDrop {
    fn drop(&mut self) {
        // SAFETY: RevertToSelf has no preconditions.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

/// True iff the client of `pipe` runs as `expected_sid` at impersonation
/// level `SecurityIdentification` or higher (§3.1).
///
/// Impersonation only works after data was read from the pipe, so the
/// server calls this after the `hello` frame was read. The pipe handle is
/// duplicated and the check runs in `spawn_blocking`, so impersonation never
/// spans an `.await` and stays valid even if this future is dropped.
///
/// `Ok(false)`: another SID, or a client that asked for anonymous
/// impersonation. `Err`: impersonation or a token query failed (the caller
/// rejects, PD-29 `impersonation`).
pub async fn verify_client_sid(pipe: &NamedPipeServer, expected_sid: &str) -> io::Result<bool> {
    let handle = pipe.as_handle().try_clone_to_owned()?;
    let expected = expected_sid.to_owned();
    tokio::task::spawn_blocking(move || verify_client_sid_blocking(handle.as_handle(), &expected))
        .await
        .map_err(|_| io::Error::other(MSG_JOIN))?
}

/// The synchronous body of `verify_client_sid`, on the calling thread:
/// `ImpersonateNamedPipeClient` → `OpenThreadToken(TOKEN_QUERY, OpenAsSelf
/// = TRUE)` → `RevertToSelf` (abort on failure) → `TokenUser` and
/// `TokenImpersonationLevel` of that token.
#[doc(hidden)]
pub fn verify_client_sid_blocking(
    pipe: BorrowedHandle<'_>,
    expected_sid: &str,
) -> io::Result<bool> {
    let token = match client_thread_token(pipe)? {
        Some(t) => t,
        None => return Ok(false),
    };
    let sid = Sid::of_token(token.as_handle())?.to_string_sid()?;
    let level = impersonation_level(token.as_handle())?;
    Ok(sid == expected_sid && level >= SecurityIdentification)
}

/// Impersonates the client of `pipe`, opens the thread token and reverts.
/// `None` when the client allowed only anonymous impersonation.
fn client_thread_token(pipe: BorrowedHandle<'_>) -> io::Result<Option<OwnedHandle>> {
    // SAFETY: `pipe` is a live server pipe handle.
    if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle() as HANDLE) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _revert = RevertOnDrop;
    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: the current-thread pseudo handle; `raw` is a valid out-pointer.
    // OpenAsSelf = TRUE: the access check uses the process token.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_CANT_OPEN_ANONYMOUS as i32) {
            return Ok(None);
        }
        return Err(e);
    }
    // SAFETY: a fresh token handle that nothing else owns; it stays valid
    // after the revert below.
    Ok(Some(unsafe { OwnedHandle::from_raw_handle(raw as _) }))
}

fn impersonation_level(token: BorrowedHandle<'_>) -> io::Result<SECURITY_IMPERSONATION_LEVEL> {
    let mut level: SECURITY_IMPERSONATION_LEVEL = -1;
    let mut len = 0u32;
    // SAFETY: `token` is a live token handle; `level` is writable for its size.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenImpersonationLevel,
            (&raw mut level).cast(),
            size_of_u32::<SECURITY_IMPERSONATION_LEVEL>(),
            &mut len,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(level)
}

fn size_of_u32<T>() -> u32 {
    u32::try_from(std::mem::size_of::<T>()).unwrap_or(u32::MAX)
}

// ---------- client ----------

/// Opens `name` for read and write with `SECURITY_SQOS_PRESENT |
/// SECURITY_IDENTIFICATION` (§3.1): the server may identify, not
/// impersonate, the client.
pub fn open_client(name: &str) -> io::Result<NamedPipeClient> {
    ClientOptions::new()
        .read(true)
        .write(true)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(name)
}

/// Decides whether the server at the other end of a fresh pipe connection is
/// acceptable (§3.2 (a)). Called before the client writes any byte.
pub trait PipeOwnerProbe: Send + Sync {
    /// True iff the server behind `client` may be talked to.
    fn owner_ok(&self, client: &NamedPipeClient) -> bool;
}

/// The production probe: `server_owner_ok` against the CLI's own user SID.
#[derive(Debug, Clone)]
pub struct SameUser {
    sid: String,
}

impl SameUser {
    /// The probe for the process token's user SID.
    pub fn current() -> io::Result<SameUser> {
        Ok(SameUser {
            sid: current_user_sid_string()?,
        })
    }

    /// The probe for an explicit SID (tests).
    #[doc(hidden)]
    pub fn with_sid(sid: String) -> SameUser {
        SameUser { sid }
    }
}

impl PipeOwnerProbe for SameUser {
    fn owner_ok(&self, client: &NamedPipeClient) -> bool {
        server_owner_ok(client, &self.sid)
    }
}

/// §3.2 (a): the server process token's user SID
/// (`GetNamedPipeServerProcessId` → `OpenProcess(PROCESS_QUERY_LIMITED_
/// INFORMATION)` → `OpenProcessToken(TOKEN_QUERY)` → `TokenUser`) and the
/// pipe's owner SID (`GetSecurityInfo(OWNER_SECURITY_INFORMATION)`) both
/// equal `my_sid`. Any failure is a mismatch.
pub fn server_owner_ok(client: &NamedPipeClient, my_sid: &str) -> bool {
    let pipe = client.as_handle();
    matches!(server_process_sid(pipe), Ok(s) if s == my_sid)
        && matches!(pipe_owner_sid(pipe), Ok(s) if s == my_sid)
}

fn server_process_sid(pipe: BorrowedHandle<'_>) -> io::Result<String> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is a live client pipe handle; `pid` is a valid out-pointer.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: plain call; a null result is checked below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh process handle that nothing else owns.
    let process = unsafe { OwnedHandle::from_raw_handle(process as _) };
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `process` is live; `token` is a valid out-pointer.
    if unsafe { OpenProcessToken(process.as_raw_handle() as HANDLE, TOKEN_QUERY, &mut token) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh token handle that nothing else owns.
    let token = unsafe { OwnedHandle::from_raw_handle(token as _) };
    Sid::of_token(token.as_handle())?.to_string_sid()
}

fn pipe_owner_sid(pipe: BorrowedHandle<'_>) -> io::Result<String> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `pipe` is a live handle opened with GENERIC_READ (incl.
    // READ_CONTROL); the out-pointers are valid; only the owner is asked for.
    let rc = unsafe {
        GetSecurityInfo(
            pipe.as_raw_handle() as HANDLE,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    let _free = LocalFreeOnDrop(sd);
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(rc).unwrap_or(i32::MAX),
        ));
    }
    // SAFETY: `owner` points into `sd`, freed only when `_free` drops below.
    unsafe { sid_to_string(owner) }
}

/// Why `connect_checked` gave no client.
#[derive(Debug)]
pub enum ConnectFailure {
    /// No pipe of that name (`ERROR_FILE_NOT_FOUND`): not running (§4.7).
    NotFound,
    /// Still `ERROR_PIPE_BUSY` after waiting up to 5 s (§4.7, exit 11
    /// `busy`).
    PipeBusy,
    /// The pipe refused us (`ERROR_ACCESS_DENIED`) or the owner probe said no
    /// (§3.2 (a), exit 5 `server_identity`). Nothing was sent.
    ServerIdentity,
    /// Any other IO error.
    Io(io::Error),
}

impl fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectFailure::NotFound => f.write_str("no pipe at the endpoint"),
            ConnectFailure::PipeBusy => f.write_str("every pipe instance is busy"),
            ConnectFailure::ServerIdentity => f.write_str("server identity check failed"),
            ConnectFailure::Io(e) => write!(f, "connect failed: {e}"),
        }
    }
}

impl std::error::Error for ConnectFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConnectFailure::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Outcome of one `open_client` attempt.
enum Open {
    Client(NamedPipeClient),
    Busy,
}

fn try_open(name: &str) -> Result<Open, ConnectFailure> {
    match open_client(name) {
        Ok(c) => Ok(Open::Client(c)),
        Err(e) => match e.raw_os_error() {
            Some(c) if c == ERROR_PIPE_BUSY as i32 => Ok(Open::Busy),
            Some(c) if c == ERROR_FILE_NOT_FOUND as i32 => Err(ConnectFailure::NotFound),
            Some(c) if c == ERROR_ACCESS_DENIED as i32 => Err(ConnectFailure::ServerIdentity),
            _ => Err(ConnectFailure::Io(e)),
        },
    }
}

/// Connects to the pipe `name` for the CLI (§3.2 (a), §4.7):
///
/// 1. `open_client`: `ERROR_FILE_NOT_FOUND` → `NotFound`,
///    `ERROR_ACCESS_DENIED` → `ServerIdentity`.
/// 2. `ERROR_PIPE_BUSY` → `WaitNamedPipeW(name, min(5 s, time left before
///    deadline))` in `spawn_blocking`, then one more open; still busy →
///    `PipeBusy`. A deadline already past → `PipeBusy` without waiting.
/// 3. `probe.owner_ok`; false → `ServerIdentity`, the client is dropped
///    without a byte written.
///
/// Must be polled inside a tokio runtime with IO enabled.
pub async fn connect_checked(
    name: &str,
    probe: &dyn PipeOwnerProbe,
    deadline: Instant,
) -> Result<NamedPipeClient, ConnectFailure> {
    require_runtime().map_err(ConnectFailure::Io)?;
    let client = match try_open(name)? {
        Open::Client(c) => c,
        Open::Busy => {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(ConnectFailure::PipeBusy);
            }
            wait_named_pipe(name, left.min(BUSY_WAIT_MAX))
                .await
                .map_err(ConnectFailure::Io)?;
            match try_open(name)? {
                Open::Client(c) => c,
                Open::Busy => return Err(ConnectFailure::PipeBusy),
            }
        }
    };
    if !probe.owner_ok(&client) {
        drop(client);
        return Err(ConnectFailure::ServerIdentity);
    }
    Ok(client)
}

/// `WaitNamedPipeW(name, wait)` on a blocking thread. `wait` is at least
/// 1 ms (0 would mean the pipe's default timeout). Its own outcome (an
/// instance free, timeout, pipe gone) does not matter: the caller opens
/// again and maps that result.
async fn wait_named_pipe(name: &str, wait: Duration) -> io::Result<()> {
    let wide = wide_nul(name)?;
    let ms = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX).max(1);
    tokio::task::spawn_blocking(move || {
        // SAFETY: `wide` is NUL-terminated and lives for the call.
        unsafe { WaitNamedPipeW(wide.as_ptr(), ms) };
    })
    .await
    .map_err(|_| io::Error::other(MSG_JOIN))
}

fn wide_nul(s: &str) -> io::Result<Vec<u16>> {
    if s.contains('\0') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, MSG_NUL));
    }
    Ok(OsStr::new(s).encode_wide().chain(Some(0)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_next_instance_poisons_the_listener() {
        let prefix = r"\\.\pipe\atlas-duck-0123456789abcdef-";
        let mut listener = PipeListener::bind(prefix).expect("bind");
        let _client = open_client(listener.name()).expect("open");
        let err = listener
            .accept_with(|_, _| Err(io::Error::other("injected")))
            .await
            .expect_err("accept survived a failed create_instance");
        assert_eq!(err.to_string(), "injected");
        assert!(listener.next.is_none());
        let again = listener.accept().await.expect_err("poisoned accept");
        assert_eq!(again.to_string(), MSG_LISTENER_DONE);
    }
}
