//! Unix socket transport (§3.1 Linux/macOS, §3.2 (a), §4.7, PD-25, PD-29).
//!
//! Server: `Listener::bind` checks (and creates) the socket dir, unlinks only
//! a stale socket owned by the euid, binds and sets mode `0600 | S_ISVTX`;
//! `accept` drops every peer whose uid is not the euid before a byte is read
//! or written. Client: `connect_checked` checks the socket dir without
//! creating it, connects and runs the owner check before handing out the
//! stream, so nothing is sent to a server that fails it.

use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::net::{UnixListener, UnixStream};

use super::{Conn, diag};
use crate::paths::{check_socket_dir, ensure_socket_dir, euid};

/// Socket file mode after bind (PD-25): owner read/write plus the sticky bit,
/// which keeps systemd-tmpfiles from deleting the socket.
const SOCKET_MODE: u32 = 0o1600;
/// The mode used where the OS refuses the sticky bit on a non-directory.
#[cfg(not(target_os = "linux"))]
const SOCKET_MODE_NO_STICKY: u32 = 0o600;

const MSG_NOT_STALE_SOCKET: &str =
    "socket path exists and is not a socket owned by the effective uid";
const MSG_NOT_ABSOLUTE: &str = "socket path is not an absolute path with a parent dir";
const MSG_NO_RUNTIME: &str = "the Unix socket transport needs a tokio runtime";
const MSG_NUL: &str = "path contains a NUL byte";

/// The kernel-reported identity of the other end of a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// The peer's effective uid.
    pub uid: u32,
    /// The peer's pid, when the OS reports one (Linux `SO_PEERCRED`, macOS
    /// `LOCAL_PEEREPID`).
    pub pid: Option<u32>,
}

impl PeerCred {
    fn of(stream: &UnixStream) -> io::Result<PeerCred> {
        let cred = stream.peer_cred()?;
        Ok(PeerCred {
            uid: cred.uid(),
            pid: cred.pid().and_then(|p| u32::try_from(p).ok()),
        })
    }
}

/// The server socket. Holds no file cleanup: the socket file stays after
/// drop, and the next `bind` (under `instance.lock`) unlinks it.
#[derive(Debug)]
pub struct Listener {
    inner: UnixListener,
    expected_uid: u32,
    rejected: AtomicU64,
}

impl Listener {
    /// Binds the socket at `path` (§3.1). The caller holds `instance.lock`,
    /// so a socket file already at `path` belongs to no live app.
    ///
    /// 1. `ensure_socket_dir(parent)`: created 0700 if missing; owner, mode
    ///    and symlink checked (`PermissionDenied` otherwise).
    /// 2. `lstat(path)`: a socket owned by the euid is unlinked; any other
    ///    file type (regular file, symlink, dir) or owner is left alone and
    ///    the result is `AlreadyExists`. No `try_overwrite`.
    /// 3. Bind, then `chmod(0600 | S_ISVTX)` (PD-25; plain 0600 where the OS
    ///    refuses the sticky bit on a socket for a non-root user).
    ///
    /// Must be called inside a tokio runtime with IO enabled.
    pub fn bind(path: &Path) -> io::Result<Listener> {
        bind_expecting_uid(path, euid())
    }

    /// The next connection whose peer uid is the expected uid (the euid in
    /// production). Every other peer, and every peer whose credentials
    /// cannot be read, is dropped unread and unanswered, logged as
    /// `ipc_reject {reason: peer_uid}` (PD-29), and the wait goes on.
    ///
    /// Cancel-safe: nothing is awaited after a stream is accepted.
    pub async fn accept(&self) -> io::Result<(Conn, PeerCred)> {
        loop {
            let (stream, _addr) = self.inner.accept().await?;
            let peer = PeerCred::of(&stream).ok();
            match peer {
                Some(p) if p.uid == self.expected_uid => return Ok((Conn::new(stream), p)),
                _ => {
                    drop(stream);
                    self.rejected.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        event = diag::EVENT_REJECT,
                        reason = diag::REASON_PEER_UID,
                        peer_pid = peer.and_then(|p| p.pid),
                        "ipc connection rejected"
                    );
                }
            }
        }
    }

    /// Number of peers `accept` has rejected so far.
    #[doc(hidden)]
    pub fn rejected_count(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
}

/// `Listener::bind` with an explicit expected peer uid. Production code calls
/// `bind`, which passes `geteuid()`; tests pass another uid to exercise the
/// reject path of the very same code.
#[doc(hidden)]
pub fn bind_expecting_uid(path: &Path, expected_uid: u32) -> io::Result<Listener> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(io::Error::other(MSG_NO_RUNTIME));
    }
    let dir = socket_parent(path)?;
    ensure_socket_dir(dir)?;
    remove_stale_socket(path)?;
    let std_listener = std::os::unix::net::UnixListener::bind(path)?;
    let inner = set_socket_mode(path)
        .and_then(|()| std_listener.set_nonblocking(true))
        .and_then(|()| UnixListener::from_std(std_listener));
    match inner {
        Ok(inner) => Ok(Listener {
            inner,
            expected_uid,
            rejected: AtomicU64::new(0),
        }),
        Err(e) => {
            // Best effort: do not leave a socket nobody listens on behind.
            let _ = fs::remove_file(path);
            Err(e)
        }
    }
}

/// The parent dir of an absolute socket path.
fn socket_parent(path: &Path) -> io::Result<&Path> {
    path.parent()
        .filter(|p| path.is_absolute() && !p.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, MSG_NOT_ABSOLUTE))
}

/// Unlinks `path` iff `lstat` shows a socket owned by the euid; a missing
/// path is fine; anything else is `AlreadyExists` and stays untouched.
fn remove_stale_socket(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(m) if m.file_type().is_socket() && m.uid() == euid() => match fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            MSG_NOT_STALE_SOCKET,
        )),
    }
}

/// `chmod(path, 0600 | S_ISVTX)` (PD-25). Linux accepts the sticky bit on a
/// socket; Darwin and the BSDs refuse it on a non-directory for non-root
/// users (`EFTYPE`), so there the socket gets plain 0600 and relies on
/// `touch_socket` alone.
fn set_socket_mode(path: &Path) -> io::Result<()> {
    let sticky = fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE));
    #[cfg(not(target_os = "linux"))]
    if sticky.is_err() {
        return fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE_NO_STICKY));
    }
    sticky
}

/// Sets the access and modification times of the socket file and its dir
/// to now (PD-25 upkeep; the server calls it every 6 h), without following
/// symlinks.
pub fn touch_socket(path: &Path) -> io::Result<()> {
    touch(path)?;
    touch(socket_parent(path)?)
}

fn touch(path: &Path) -> io::Result<()> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, MSG_NUL))?;
    // SAFETY: `c` is a NUL-terminated path; a null `times` means "now" for both.
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c.as_ptr(),
            std::ptr::null(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Decides whether the server at the other end of a fresh connection is
/// acceptable (§3.2 (a)). Called before the client writes any byte.
pub trait OwnerCheck: Send + Sync {
    /// True iff the server process identified by `peer` may be talked to.
    fn server_ok(&self, peer: &PeerCred) -> bool;
}

/// The production owner check: the server runs as the client's euid.
#[derive(Debug, Clone, Copy, Default)]
pub struct SameUser;

impl OwnerCheck for SameUser {
    fn server_ok(&self, peer: &PeerCred) -> bool {
        peer.uid == euid()
    }
}

/// Why `connect_checked` gave no stream.
#[derive(Debug)]
pub enum ConnectFailure {
    /// No socket dir or no socket file (`ENOENT`): not running (§4.7).
    NotFound,
    /// A socket file nobody listens on (`ECONNREFUSED`): not running (§4.7).
    Refused,
    /// The socket dir failed the §3.1 check, the server's credentials could
    /// not be read, or the owner check said no (§3.2 (a), exit 5
    /// `server_identity`). Nothing was sent.
    ServerIdentity,
    /// Any other IO error.
    Io(io::Error),
}

impl fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectFailure::NotFound => f.write_str("no socket at the endpoint"),
            ConnectFailure::Refused => f.write_str("nothing listens on the endpoint socket"),
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

/// Connects to the socket at `path` for the CLI (§3.1, §3.2 (a)):
///
/// 1. `check_socket_dir(parent)`, check only: a missing dir is `NotFound`
///    (the CLI never creates it); a failed owner/mode/symlink check is
///    `ServerIdentity`.
/// 2. `connect`: `ENOENT` → `NotFound`, `ECONNREFUSED` → `Refused`.
/// 3. The server's credentials (`peer_cred`); unreadable → `ServerIdentity`.
/// 4. `check.server_ok`; false → `ServerIdentity`, the stream is dropped
///    without a byte written.
///
/// Only then is the stream returned. Must be polled inside a tokio runtime
/// with IO enabled.
pub async fn connect_checked(path: &Path, check: &dyn OwnerCheck) -> Result<Conn, ConnectFailure> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(ConnectFailure::Io(io::Error::other(MSG_NO_RUNTIME)));
    }
    let dir = socket_parent(path).map_err(ConnectFailure::Io)?;
    match check_socket_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ConnectFailure::NotFound),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return Err(ConnectFailure::ServerIdentity);
        }
        Err(e) => return Err(ConnectFailure::Io(e)),
    }
    let stream = UnixStream::connect(path)
        .await
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => ConnectFailure::NotFound,
            io::ErrorKind::ConnectionRefused => ConnectFailure::Refused,
            _ => ConnectFailure::Io(e),
        })?;
    let peer = PeerCred::of(&stream).map_err(|_| ConnectFailure::ServerIdentity)?;
    if !check.server_ok(&peer) {
        drop(stream);
        return Err(ConnectFailure::ServerIdentity);
    }
    Ok(Conn::new(stream))
}
