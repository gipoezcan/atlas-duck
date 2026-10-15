//! An in-memory [`PlatformOps`]: the user PATH value, files with their modes, symlinks and
//! `cli.toml`s, plus counters of the side effects (PATH writes, broadcasts). Used by the unit tests
//! and by the mock-runtime tests in `tests/`; nothing here touches the machine.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use atlas_duck_ipc::paths::{CliToml, PinnedError};

use super::PlatformOps;

/// Everything the fake holds; `PartialEq` so a test can compare "before" with "after".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    /// `HKCU\Environment\Path`.
    pub path: Option<String>,
    /// File contents and unix mode bits.
    pub files: BTreeMap<PathBuf, (Vec<u8>, u32)>,
    /// Symlink -> target.
    pub links: BTreeMap<PathBuf, PathBuf>,
    pub cli_tomls: BTreeMap<PathBuf, CliToml>,
}

#[derive(Debug, Default)]
pub struct FakeOps {
    state: Mutex<State>,
    path_sets: Mutex<usize>,
    path_removes: Mutex<usize>,
    broadcasts: Mutex<usize>,
    /// `write_file` of this path fails (undo tests).
    fail_write: Mutex<Option<PathBuf>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeOps {
    pub fn new() -> FakeOps {
        FakeOps::default()
    }

    pub fn with_state(state: State) -> FakeOps {
        FakeOps {
            state: Mutex::new(state),
            ..FakeOps::default()
        }
    }

    pub fn with_path(path: &str) -> FakeOps {
        FakeOps::with_state(State {
            path: Some(path.to_owned()),
            ..State::default()
        })
    }

    pub fn state(&self) -> State {
        lock(&self.state).clone()
    }

    pub fn path_sets(&self) -> usize {
        *lock(&self.path_sets)
    }

    pub fn path_removes(&self) -> usize {
        *lock(&self.path_removes)
    }

    pub fn broadcasts(&self) -> usize {
        *lock(&self.broadcasts)
    }

    pub fn fail_writes_to(&self, p: &Path) {
        *lock(&self.fail_write) = Some(p.to_path_buf());
    }

    pub fn mode_of(&self, p: &Path) -> Option<u32> {
        lock(&self.state).files.get(p).map(|(_, m)| *m)
    }
}

impl PlatformOps for FakeOps {
    fn user_path_get(&self) -> io::Result<Option<String>> {
        Ok(lock(&self.state).path.clone())
    }

    fn user_path_set(&self, v: &str) -> io::Result<()> {
        *lock(&self.path_sets) += 1;
        lock(&self.state).path = Some(v.to_owned());
        Ok(())
    }

    fn user_path_remove(&self) -> io::Result<()> {
        *lock(&self.path_removes) += 1;
        lock(&self.state).path = None;
        Ok(())
    }

    fn broadcast_setting_change(&self) {
        *lock(&self.broadcasts) += 1;
    }

    fn symlink(&self, src: &Path, dst: &Path) -> io::Result<()> {
        let mut s = lock(&self.state);
        if s.files.contains_key(dst) || s.links.contains_key(dst) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        s.links.insert(dst.to_path_buf(), src.to_path_buf());
        Ok(())
    }

    fn write_file(&self, p: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
        if lock(&self.fail_write).as_deref() == Some(p) {
            return Err(io::Error::other("injected"));
        }
        let mut s = lock(&self.state);
        // A rename over a symlink replaces the link, not its target.
        s.links.remove(p);
        s.files.insert(p.to_path_buf(), (bytes.to_vec(), mode));
        Ok(())
    }

    fn remove(&self, p: &Path) -> io::Result<()> {
        let mut s = lock(&self.state);
        s.files.remove(p);
        s.links.remove(p);
        s.cli_tomls.remove(p);
        Ok(())
    }

    fn read_file(&self, p: &Path) -> io::Result<Option<Vec<u8>>> {
        let s = lock(&self.state);
        if let Some((bytes, _)) = s.files.get(p) {
            return Ok(Some(bytes.clone()));
        }
        // A `cli.toml` is a file too (its bytes are not modelled).
        Ok(s.cli_tomls.get(p).map(|_| b"cli.toml".to_vec()))
    }

    fn read_link(&self, p: &Path) -> io::Result<Option<PathBuf>> {
        let s = lock(&self.state);
        if let Some(t) = s.links.get(p) {
            return Ok(Some(t.clone()));
        }
        if s.files.contains_key(p) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(None)
    }

    fn write_cli_toml(&self, p: &Path, c: &CliToml) -> Result<(), PinnedError> {
        lock(&self.state)
            .cli_tomls
            .insert(p.to_path_buf(), c.clone());
        Ok(())
    }

    fn read_cli_toml(&self, p: &Path) -> Result<Option<CliToml>, PinnedError> {
        Ok(lock(&self.state).cli_tomls.get(p).cloned())
    }
}
