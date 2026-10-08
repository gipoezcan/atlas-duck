//! Keyring locality (I-44, V29 keyring-dir half): the dirs a Linux/macOS keyring daemon stores
//! its files in must be on a local filesystem.

use std::path::{Path, PathBuf};

#[cfg(not(windows))]
use atlas_duck_ipc::paths::base_dirs;
use atlas_duck_ipc::paths::{Locality, check_locality};

use super::KeyringLocality;

/// Keyring directories of this OS. Linux: both the `XDG_DATA_HOME` (when set and absolute) and
/// the `<passwd home>/.local/share` variants (checking more dirs can only refuse more). macOS:
/// `<passwd home>/Library/Keychains`. Windows: none (Credential Manager is per machine with
/// persistence Local).
pub fn keyring_dirs() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        Vec::new()
    }
    #[cfg(target_os = "macos")]
    {
        base_dirs()
            .map(|b| vec![b.home.join("Library").join("Keychains")])
            .unwrap_or_default()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let mut out = Vec::new();
        if let Some(x) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from)
            && x.is_absolute()
        {
            out.push(x.join("keyrings"));
            out.push(x.join("kwalletd"));
        }
        if let Ok(b) = base_dirs() {
            let share = b.home.join(".local").join("share");
            out.push(share.join("keyrings"));
            out.push(share.join("kwalletd"));
        }
        out
    }
}

/// Nearest ancestor of `p` that exists (a missing dir is judged by where it would be created).
fn nearest_existing(p: &Path) -> &Path {
    let mut cur = p;
    while !cur.exists() {
        match cur.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => cur = parent,
            _ => break,
        }
    }
    cur
}

/// First dir that is not local wins; an I/O error is `Unknown` (callers retry), never local.
pub fn keyring_locality(dirs: &[PathBuf]) -> KeyringLocality {
    for dir in dirs {
        match check_locality(nearest_existing(dir)) {
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
