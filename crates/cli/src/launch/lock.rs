//! The launch lock (PD-22): one CLI at a time runs the check-spawn-poll sequence.
//!
//! `<data>/launch.lock` once a data dir exists; before first run `<pinned dir>/launch-<host>.lock`
//! (named like the pinned files: not host-qualified on Windows). The pinned dir is the only
//! directory the CLI ever creates, and only for this lock (mode 0700 on Unix, default ACL on
//! Windows); its parent must already exist. The lock file is never removed (removing it would let a
//! waiter and a newcomer lock different files).

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use atlas_duck_ipc::paths::{BaseDirs, LocalDataDir, paths_file, pinned_dir};

const DATA_LOCK_NAME: &str = "launch.lock";
/// How often a waiter retries the lock.
const RETRY_EVERY: Duration = Duration::from_millis(50);

/// Held for the whole check-spawn-poll sequence; released when dropped (the file is closed).
#[derive(Debug)]
pub(crate) struct LaunchLock {
    _file: File,
}

#[derive(Debug)]
pub(crate) enum LockError {
    /// Another CLI held it for the whole wait.
    TimedOut,
    Io(io::Error),
}

pub(crate) fn data_lock_path(data: &LocalDataDir) -> PathBuf {
    data.path().join(DATA_LOCK_NAME)
}

/// `<pinned dir>/launch<suffix>.lock`, where `<suffix>` is what this host's `paths.toml` name
/// carries after `paths` (`-<host>` on Unix, nothing on Windows), so both are sanitized alike.
pub(crate) fn first_run_lock_path(base: &BaseDirs, host: &str) -> PathBuf {
    let paths = paths_file(base, host);
    let suffix = paths
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("paths"))
        .and_then(|n| n.strip_suffix(".toml"))
        .unwrap_or("");
    pinned_dir(base).join(format!("launch{suffix}.lock"))
}

/// Creates the pinned dir itself (not its parents) if it is missing: the only directory the CLI
/// creates (PD-22).
pub(crate) fn ensure_pinned_dir(base: &BaseDirs) -> io::Result<PathBuf> {
    let dir = pinned_dir(base);
    match dir_builder().create(&dir) {
        Ok(()) => Ok(dir),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(dir),
        Err(e) => Err(e),
    }
}

/// Non-recursive; mode 0700 on Unix, the default ACL on Windows.
#[cfg(unix)]
fn dir_builder() -> std::fs::DirBuilder {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
}

#[cfg(not(unix))]
fn dir_builder() -> std::fs::DirBuilder {
    std::fs::DirBuilder::new()
}

fn open_lock_file(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

/// Takes the exclusive lock on `path` (creating the file), retrying until `limit` has passed.
/// A zero `limit` tries once.
pub(crate) fn acquire(path: &Path, limit: Duration) -> Result<LaunchLock, LockError> {
    let file = open_lock_file(path).map_err(LockError::Io)?;
    let until = Instant::now() + limit;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(LaunchLock { _file: file }),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(e)) => return Err(LockError::Io(e)),
        }
        let now = Instant::now();
        if now >= until {
            return Err(LockError::TimedOut);
        }
        std::thread::sleep(RETRY_EVERY.min(until - now));
    }
}

#[cfg(test)]
mod tests {
    use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};

    use super::*;

    fn base(dir: &Path) -> BaseDirs {
        BaseDirs {
            home: dir.to_path_buf(),
            local_app_data: Some(dir.join("AppData").join("Local")),
            roaming_app_data: Some(dir.join("AppData").join("Roaming")),
        }
    }

    #[test]
    fn lock_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let DataDirResolution::Local(data) = check_data_dir(tmp.path()).unwrap() else {
            panic!("temp dir is not local");
        };
        assert_eq!(data_lock_path(&data), tmp.path().join("launch.lock"));

        let b = base(tmp.path());
        let p = first_run_lock_path(&b, "myhost");
        assert_eq!(p.parent(), Some(pinned_dir(&b).as_path()));
        let name = p.file_name().and_then(|n| n.to_str()).unwrap();
        if cfg!(windows) {
            assert_eq!(name, "launch.lock");
        } else {
            assert_eq!(name, "launch-myhost.lock");
        }
    }

    #[test]
    fn exclusive_and_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("launch.lock");
        let held = acquire(&path, Duration::ZERO).unwrap();
        let start = Instant::now();
        assert!(matches!(
            acquire(&path, Duration::from_millis(150)),
            Err(LockError::TimedOut)
        ));
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(150), "{waited:?}");
        assert!(waited < Duration::from_secs(2), "{waited:?}");
        drop(held);
        assert!(acquire(&path, Duration::ZERO).is_ok());
        assert!(path.is_file(), "the lock file stays");
    }

    #[test]
    fn pinned_dir_created_only_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let b = base(tmp.path());
        let dir = pinned_dir(&b);
        let parent = dir.parent().unwrap().to_path_buf();
        // Parent missing: refused, nothing created.
        assert!(ensure_pinned_dir(&b).is_err());
        assert!(!parent.exists());

        std::fs::create_dir_all(&parent).unwrap();
        assert_eq!(ensure_pinned_dir(&b).unwrap(), dir);
        assert!(dir.is_dir());
        // Idempotent.
        assert_eq!(ensure_pinned_dir(&b).unwrap(), dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
    }
}
