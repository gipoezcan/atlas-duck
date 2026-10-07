//! `instance.lock` (§3.1): the app's exclusive lock on its data dir, held for the
//! app's whole lifetime.
//!
//! - Unix: `flock(LOCK_EX | LOCK_NB)` on `<data>/instance.lock`.
//! - Windows: `CreateFileW` with share mode 0 (std's `OpenOptionsExt::share_mode(0)`
//!   passes `dwShareMode = 0` to `CreateFileW`). While the holder has the file open,
//!   no other process can open it, so a second instance cannot read the holder record
//!   and gets `Held(None)` (known spec limitation; no workaround).
//!
//! The file holds one JSON line `{"host":…,"pid":…}` naming its holder. Dropping the
//! [`InstanceLock`] closes the handle, which releases the lock. The file itself is
//! never deleted.

use std::fmt;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use atlas_duck_ipc::paths::LocalDataDir;
use serde::{Deserialize, Serialize};

/// File name of the lock inside the data dir (§3.1, §12.5).
pub const INSTANCE_LOCK_FILE: &str = "instance.lock";

/// The `{host, pid}` record of the process that holds the lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockHolder {
    pub host: String,
    pub pid: u32,
}

/// Why [`InstanceLock::acquire`] did not return a lock.
#[derive(Debug)]
pub enum LockError {
    /// Another process holds the lock. `Some` carries its record when it could be
    /// read and parsed (Unix only; on Windows share mode 0 keeps it unreadable).
    Held(Option<LockHolder>),
    /// Opening, locking or writing the lock file failed.
    Io(io::Error),
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockError::Held(Some(holder)) => {
                write!(
                    f,
                    "instance.lock is held by pid {} on {}",
                    holder.pid, holder.host
                )
            }
            LockError::Held(None) => f.write_str("instance.lock is held by another process"),
            LockError::Io(e) => write!(f, "instance.lock could not be taken: {e}"),
        }
    }
}

impl std::error::Error for LockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LockError::Io(e) => Some(e),
            LockError::Held(_) => None,
        }
    }
}

/// Proof that this process holds `<data>/instance.lock`. Keeps the OS handle open
/// for its whole lifetime; dropping it releases the lock.
pub struct InstanceLock {
    file: File,
    path: PathBuf,
}

impl fmt::Debug for InstanceLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstanceLock")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl InstanceLock {
    /// Takes the exclusive lock on `<dir>/instance.lock` without blocking and records
    /// `{host, pid}` of this process in it. `dir` is a [`LocalDataDir`], so the §7.7
    /// local-filesystem check has already run.
    pub fn acquire(dir: &LocalDataDir, host: &str) -> Result<InstanceLock, LockError> {
        let path = dir.path().join(INSTANCE_LOCK_FILE);
        let mut file = os::open_exclusive(&path)?;
        let holder = LockHolder {
            host: host.to_owned(),
            pid: std::process::id(),
        };
        write_record(&mut file, &holder).map_err(LockError::Io)?;
        Ok(InstanceLock { file, path })
    }

    /// Full path of the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The open lock file (the M2 audit store requires the lock handle, §3.1).
    pub fn file(&self) -> &File {
        &self.file
    }
}

fn write_record(file: &mut File, holder: &LockHolder) -> io::Result<()> {
    let mut line = serde_json::to_vec(holder).map_err(io::Error::other)?;
    line.push(b'\n');
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&line)?;
    file.sync_all()
}

#[cfg(unix)]
mod os {
    use super::{LockError, LockHolder};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Seek, SeekFrom};
    use std::os::fd::AsRawFd;
    use std::path::Path;

    /// Upper bound for reading a holder record; a real record is far smaller.
    const MAX_RECORD_BYTES: u64 = 4096;

    pub(super) fn open_exclusive(path: &Path) -> Result<File, LockError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(LockError::Io)?;
        // SAFETY: `file` owns an open descriptor that stays valid for this call.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(file);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(LockError::Held(read_holder(&mut file)));
        }
        Err(LockError::Io(err))
    }

    fn read_holder(file: &mut File) -> Option<LockHolder> {
        file.seek(SeekFrom::Start(0)).ok()?;
        let mut text = String::new();
        Read::by_ref(file)
            .take(MAX_RECORD_BYTES)
            .read_to_string(&mut text)
            .ok()?;
        serde_json::from_str(text.lines().next()?).ok()
    }
}

#[cfg(windows)]
mod os {
    use super::LockError;
    use std::fs::{File, OpenOptions};
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::Path;
    use std::time::Duration;

    /// Win32 `ERROR_SHARING_VIOLATION`: another handle with share mode 0 is open.
    const ERROR_SHARING_VIOLATION: i32 = 32;
    /// A sharing violation can also come from a short-lived handle of a scanner or indexer
    /// that opened the fresh file without share-write access. A genuine second instance
    /// keeps its handle for its whole lifetime, so a few short retries tell them apart
    /// without a noticeable delay for the contender case.
    const RETRIES: u32 = 4;
    const RETRY_DELAY: Duration = Duration::from_millis(40);

    pub(super) fn open_exclusive(path: &Path) -> Result<File, LockError> {
        let mut attempt = 0;
        loop {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .share_mode(0)
                .open(path)
            {
                Ok(file) => return Ok(file),
                Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => {
                    if attempt >= RETRIES {
                        return Err(LockError::Held(None));
                    }
                    attempt += 1;
                    std::thread::sleep(RETRY_DELAY);
                }
                Err(e) => return Err(LockError::Io(e)),
            }
        }
    }
}
