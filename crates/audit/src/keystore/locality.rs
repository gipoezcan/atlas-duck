//! Keyring locality (I-44, V29 keyring-dir half): the dirs a Linux/macOS keyring daemon stores
//! its files in must be on a local filesystem. Everything here fails closed: a dir list that
//! cannot be resolved or a dir that cannot be examined is `Unknown`, never `Local`.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use atlas_duck_ipc::paths::{Locality, base_dirs, check_locality};

use super::KeyringLocality;

/// Which OS's keyring layout to resolve (a parameter so every layout is testable everywhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirsOs {
    Linux,
    Macos,
    Windows,
}

impl DirsOs {
    pub const CURRENT: DirsOs = if cfg!(windows) {
        DirsOs::Windows
    } else if cfg!(target_os = "macos") {
        DirsOs::Macos
    } else {
        DirsOs::Linux
    };
}

/// Keyring directories of this OS. Linux: both the `XDG_DATA_HOME` (when set and absolute) and
/// the `<passwd home>/.local/share` variants (checking more dirs can only refuse more). macOS:
/// `<passwd home>/Library/Keychains`. Windows: none (Credential Manager is per machine with
/// persistence Local). An unresolvable home is an error (fail closed), also on Linux where an
/// XDG dir alone would otherwise look sufficient.
pub fn keyring_dirs() -> io::Result<Vec<PathBuf>> {
    keyring_dirs_for(DirsOs::CURRENT, std::env::var_os("XDG_DATA_HOME"), &|| {
        base_dirs().map(|b| b.home)
    })
}

/// The pure part of [`keyring_dirs`]: `home` is the injectable passwd-home resolver.
pub fn keyring_dirs_for(
    os: DirsOs,
    xdg_data_home: Option<OsString>,
    home: &dyn Fn() -> io::Result<PathBuf>,
) -> io::Result<Vec<PathBuf>> {
    match os {
        DirsOs::Windows => Ok(Vec::new()),
        DirsOs::Macos => Ok(vec![home()?.join("Library").join("Keychains")]),
        DirsOs::Linux => {
            let mut out = Vec::new();
            if let Some(x) = xdg_data_home.map(PathBuf::from)
                && x.is_absolute()
            {
                out.push(x.join("keyrings"));
                out.push(x.join("kwalletd"));
            }
            let share = home()?.join(".local").join("share");
            out.push(share.join("keyrings"));
            out.push(share.join("kwalletd"));
            Ok(out)
        }
    }
}

/// What a path probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// Exists (a symlink counts only if its target exists).
    Exists,
    /// Does not exist; try the parent.
    Missing,
    /// A symlink whose target does not exist.
    DanglingLink,
}

/// The real probe: `symlink_metadata`, then `metadata` for a symlink. Only `NotFound` means
/// missing; any other error (EACCES, ENOTDIR, ...) is returned.
pub fn probe_fs(p: &Path) -> io::Result<Probe> {
    match std::fs::symlink_metadata(p) {
        Ok(md) if md.file_type().is_symlink() => match std::fs::metadata(p) {
            Ok(_) => Ok(Probe::Exists),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Probe::DanglingLink),
            Err(e) => Err(e),
        },
        Ok(_) => Ok(Probe::Exists),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Probe::Missing),
        Err(e) => Err(e),
    }
}

/// Nearest ancestor of `p` that exists (a missing dir is judged by where it would be created).
fn nearest_existing<'a>(
    p: &'a Path,
    probe: &dyn Fn(&Path) -> io::Result<Probe>,
) -> io::Result<&'a Path> {
    let mut cur = p;
    loop {
        match probe(cur)? {
            Probe::Exists => return Ok(cur),
            Probe::DanglingLink => {
                return Err(io::Error::other(format!(
                    "dangling symlink {}",
                    cur.display()
                )));
            }
            Probe::Missing => match cur.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => cur = parent,
                _ => return Err(io::Error::from(io::ErrorKind::NotFound)),
            },
        }
    }
}

/// First dir that is not local wins; an I/O error is `Unknown` (callers retry), never local. An
/// empty list is `Local` only on Windows (which has no keyring dirs); elsewhere it is `Unknown`.
pub fn keyring_locality(dirs: &[PathBuf]) -> KeyringLocality {
    keyring_locality_with(dirs, &probe_fs)
}

/// [`keyring_locality`] with an injectable path probe.
pub fn keyring_locality_with(
    dirs: &[PathBuf],
    probe: &dyn Fn(&Path) -> io::Result<Probe>,
) -> KeyringLocality {
    if dirs.is_empty() && DirsOs::CURRENT != DirsOs::Windows {
        return KeyringLocality::Unknown {
            reason: "no keyring directories to check".into(),
        };
    }
    for dir in dirs {
        let checked = nearest_existing(dir, probe).and_then(check_locality);
        match checked {
            Ok(Locality::Local) => {}
            Ok(Locality::NotLocal(_)) => return KeyringLocality::NotLocal { dir: dir.clone() },
            Err(e) => {
                return KeyringLocality::Unknown {
                    reason: format!("{}: {e}", dir.display()),
                };
            }
        }
    }
    KeyringLocality::Local
}
