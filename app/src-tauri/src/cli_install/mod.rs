//! "Install CLI to PATH" (§12.3, §12.2 launcher, §7.7 `cli.toml`, §12.5 step 3; M6 T27, P9).
//!
//! One pure `install` / `uninstall` over a [`PlatformOps`] and a [`Layout`]: the layout says what
//! this installation writes (a PATH entry on Windows, a symlink on macOS, a wrapper script plus a
//! `.desktop` launcher for an AppImage, nothing for deb/rpm) and the ops do the OS work. Tests run
//! everything over [`fake::FakeOps`]; the real ops ([`SystemOps`]) are the only code that touches
//! the registry or the file system, and the real Windows registry round trip is an `#[ignore]`d CI
//! test (agent limits: it never runs on a developer machine).
//!
//! Rules this module enforces:
//! - `cli.toml`'s `app_path` is the stable file the user runs: `$APPIMAGE` for an AppImage, the app
//!   binary otherwise; never a `/tmp/.mount_*` path (§12.3). With no stable path nothing is written.
//! - A file this module did not write (no marker) is never replaced and never removed: `install`
//!   answers `occupied`, `uninstall` leaves it.
//! - `uninstall` removes only what `install` writes, found by content (marker, link target, PATH
//!   entry), so it is safe to run when nothing was installed or twice.
//! - A failed `install` undoes the steps it already took.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod linux;
pub mod macos;
pub mod windows;

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use atlas_duck_ipc::paths::{self, CliToml, PinnedError, cli_file, looks_absolute, under_mount};
use serde::Serialize;
use serde::ser::SerializeMap;

/// The `CONFIG_CHANGED {source: app}` key (§12.3, `SettingsAdmin::record_app_change`).
pub const APP_CHANGE_KEY: &str = "cli_install";

/// The most a wrapper, launcher or `cli.toml` this module writes can hold. [`PlatformOps::read_file`]
/// reads one byte more than this, so a caller sees that a file is too big to be ours.
pub const MAX_READ: usize = 64 * 1024;

/// What the app does to the machine. Each method is one OS action the fake can record; the real
/// implementation is [`SystemOps`].
pub trait PlatformOps: Send + Sync {
    /// `HKCU\Environment\Path` as stored (unexpanded), `None` when the value does not exist.
    fn user_path_get(&self) -> io::Result<Option<String>>;
    /// Writes `HKCU\Environment\Path` as `REG_EXPAND_SZ`.
    fn user_path_set(&self, v: &str) -> io::Result<()>;
    /// Deletes the `HKCU\Environment\Path` value; a missing one is `Ok`.
    fn user_path_remove(&self) -> io::Result<()>;
    /// `WM_SETTINGCHANGE "Environment"` to every top-level window, so new processes see the PATH.
    fn broadcast_setting_change(&self);
    /// A symlink `dst` -> `src`; the parent directory is created.
    fn symlink(&self, src: &Path, dst: &Path) -> io::Result<()>;
    /// Writes `bytes` atomically with unix permission bits `mode`; the parent directory is created.
    fn write_file(&self, p: &Path, bytes: &[u8], mode: u32) -> io::Result<()>;
    /// Removes a file or symlink; a missing one is `Ok`.
    fn remove(&self, p: &Path) -> io::Result<()>;
    /// The file's bytes (at most [`MAX_READ`] + 1: a longer file is cut one byte past the limit),
    /// `None` when it does not exist, `InvalidInput` when it is no regular file (a FIFO, a device,
    /// a directory; the real ops never block on one).
    fn read_file(&self, p: &Path) -> io::Result<Option<Vec<u8>>>;
    /// The symlink's target, `None` when nothing exists there; `InvalidInput` when it is no symlink.
    fn read_link(&self, p: &Path) -> io::Result<Option<PathBuf>>;
    /// `cli.toml` (§7.7): atomic, newer-schema files are refused.
    fn write_cli_toml(&self, p: &Path, c: &CliToml) -> Result<(), PinnedError>;
    fn read_cli_toml(&self, p: &Path) -> Result<Option<CliToml>, PinnedError>;
    /// Whether a file exists at `p` (a directory or a missing path is `false`). Reads nothing.
    fn file_exists(&self, p: &Path) -> io::Result<bool> {
        Ok(self.read_file(p)?.is_some())
    }
    /// The `PATH` this process runs with, as a hint for the install text only (§7.7: nothing is
    /// located or executed through it). `None` when unset.
    fn session_path(&self) -> Option<OsString> {
        None
    }
}

/// Why nothing was (or could not be) installed. The kind only: no path, no OS text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallError {
    /// There is no stable absolute file to record (`$APPIMAGE` unset inside an AppImage, or the
    /// running binary sits under `/tmp/.mount_*`).
    NoStablePath,
    /// The app's path holds a character a PATH entry, a shell script or a `.desktop` file cannot
    /// carry safely (control characters, `;`, quotes, `\`, `$`, a backtick, `%`).
    UnsafePath,
    /// A file or link this module did not write is in the way; it is left alone.
    Occupied,
    /// This platform has no such action (e.g. the registry on macOS).
    Unsupported,
    /// The registry could not be read or written.
    Registry,
    /// The user PATH would grow past what the registry value and new processes can carry.
    PathTooLong,
    /// A file or link could not be written or removed.
    Io,
    /// `cli.toml` could not be written (unparsable or newer-schema file, I/O).
    CliToml,
    /// A wrapper or launcher in the way carries a marker of a newer layout: a newer atlas-duck
    /// installed it, so this one leaves it alone (PD-177).
    NewerVersion,
}

impl InstallError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NoStablePath => "no_stable_path",
            Self::UnsafePath => "unsafe_path",
            Self::Occupied => "occupied",
            Self::Unsupported => "unsupported",
            Self::Registry => "registry",
            Self::PathTooLong => "path_too_long",
            Self::Io => "io",
            Self::CliToml => "cli_toml",
            Self::NewerVersion => "newer_version",
        }
    }
}

/// The kind only (it is what the diagnostic log gets).
impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind())
    }
}

impl std::error::Error for InstallError {}

/// `{"kind": ..}`, like core's errors.
impl Serialize for InstallError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(1))?;
        m.serialize_entry("kind", self.kind())?;
        m.end()
    }
}

/// Maps an OS error to the kind that says which part failed; `Unsupported` stays itself.
fn registry_error(e: &io::Error) -> InstallError {
    if e.kind() == io::ErrorKind::Unsupported {
        InstallError::Unsupported
    } else {
        InstallError::Registry
    }
}

fn io_error(e: &io::Error) -> InstallError {
    if e.kind() == io::ErrorKind::Unsupported {
        InstallError::Unsupported
    } else {
        InstallError::Io
    }
}

/// What this installation writes, per platform and packaging (§12.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// Windows: `install_dir` (the folder of `atlas-duck.exe`) is appended to the user PATH.
    Windows { install_dir: PathBuf },
    /// macOS: `link` (`~/.local/bin/atlas-duck`) points at `cli` (`atlas-duck` next to the app).
    Macos { cli: PathBuf, link: PathBuf },
    /// Linux AppImage: a wrapper script and a `.desktop` launcher naming `appimage`.
    AppImage {
        appimage: PathBuf,
        wrapper: PathBuf,
        launcher: PathBuf,
    },
    /// Linux deb/rpm: the CLI is in `/usr/bin` already; only a leftover `cli.toml` is ever removed.
    Packaged,
}

/// [`Kind`] plus the `cli.toml` the install records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub kind: Kind,
    /// The file `cli.toml` names (§12.3): `$APPIMAGE`, else the app binary.
    pub app_path: PathBuf,
    /// This host's `cli.toml` (`ipc::paths::cli_file`).
    pub cli_toml: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Macos,
    Linux,
}

impl Platform {
    pub fn current() -> Platform {
        if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::Macos
        } else {
            Platform::Linux
        }
    }
}

/// What [`Layout::resolve`] decides over. [`Inputs::detect`] reads the real machine; tests build
/// one by hand for each platform.
#[derive(Debug, Clone)]
pub struct Inputs {
    pub platform: Platform,
    pub home: PathBuf,
    /// This host's `cli.toml`.
    pub cli_toml: PathBuf,
    /// The running app binary (`atlas-duck-app`), canonical where the OS allows.
    pub current_exe: PathBuf,
    /// `$APPIMAGE` (Linux), as the environment holds it.
    pub appimage: Option<PathBuf>,
    /// `$APPIMAGE` names an existing regular file.
    pub appimage_is_file: bool,
    /// `$APPDIR` (Linux): the AppImage runtime sets it next to `$APPIMAGE`.
    pub appdir: Option<PathBuf>,
}

/// This process really runs from an AppImage (the rule is shared with the CLI's app discovery:
/// `atlas_duck_ipc::paths::runs_from_appimage`). Children of any AppImage inherit `$APPIMAGE`
/// (a terminal or editor shipped as one, then a deb install started from it), so the variable alone
/// proves nothing.
fn runs_from_appimage(i: &Inputs) -> bool {
    paths::runs_from_appimage(&i.current_exe, i.appdir.as_deref())
}

impl Layout {
    /// §12.3: which artifacts this machine gets, and the stable file `cli.toml` records.
    pub fn resolve(i: &Inputs) -> Result<Layout, InstallError> {
        let exe_dir = i
            .current_exe
            .parent()
            .ok_or(InstallError::NoStablePath)?
            .to_path_buf();
        let mk = |kind, app_path: PathBuf| {
            if under_mount(&app_path) || !looks_absolute(&app_path) {
                return Err(InstallError::NoStablePath);
            }
            Ok(Layout {
                kind,
                app_path,
                cli_toml: i.cli_toml.clone(),
            })
        };
        match i.platform {
            Platform::Windows => {
                let layout = mk(
                    Kind::Windows {
                        install_dir: exe_dir,
                    },
                    i.current_exe.clone(),
                )?;
                windows::check_install_dir(&layout.kind)?;
                Ok(layout)
            }
            Platform::Macos => {
                let cli = exe_dir.join("atlas-duck");
                // M-10: the link points at `cli`, and removal only takes links whose target is a
                // bundle's CLI; a build that is not an app bundle never makes a link it refuses
                // to remove.
                if macos::unstable(&i.current_exe) || !macos::is_ours(&cli) {
                    return Err(InstallError::NoStablePath);
                }
                mk(
                    Kind::Macos {
                        cli,
                        link: macos::link_path(&i.home),
                    },
                    i.current_exe.clone(),
                )
            }
            Platform::Linux => {
                let image = i
                    .appimage
                    .as_ref()
                    .filter(|p| runs_from_appimage(i) && i.appimage_is_file && looks_absolute(p));
                match image {
                    Some(image) => {
                        let layout = mk(
                            Kind::AppImage {
                                appimage: image.clone(),
                                wrapper: linux::wrapper_path(&i.home),
                                launcher: linux::launcher_path(&i.home),
                            },
                            image.clone(),
                        )?;
                        linux::check_appimage_path(image)?;
                        Ok(layout)
                    }
                    // Inside an AppImage with no usable `$APPIMAGE`, the binary is under the mount.
                    None => mk(Kind::Packaged, i.current_exe.clone()),
                }
            }
        }
    }
}

impl Layout {
    /// What "Prepare for removal" can look for when [`Layout::resolve`] failed (no stable path,
    /// an unsafe path, ...): the artifacts that sit at fixed paths, removed by marker or link
    /// target (`uninstall` never reads `app_path`), plus this host's `cli.toml`. Windows has no
    /// fixed artifact (the PATH entry names the install folder, which is the unknown): only
    /// `cli.toml` goes there.
    pub fn for_removal(i: &Inputs) -> Layout {
        let kind = match i.platform {
            Platform::Macos => Kind::Macos {
                cli: PathBuf::new(),
                link: macos::link_path(&i.home),
            },
            Platform::Linux => Kind::AppImage {
                appimage: PathBuf::new(),
                wrapper: linux::wrapper_path(&i.home),
                launcher: linux::launcher_path(&i.home),
            },
            Platform::Windows => Kind::Packaged,
        };
        Layout {
            kind,
            app_path: PathBuf::new(),
            cli_toml: i.cli_toml.clone(),
        }
    }
}

impl Inputs {
    /// The real machine: known folders and passwd home (never the session environment, §7.7),
    /// `$APPIMAGE`, the running binary.
    pub fn detect() -> Result<Inputs, InstallError> {
        let base = atlas_duck_ipc::paths::base_dirs().map_err(|_| InstallError::Io)?;
        let host = atlas_duck_ipc::paths::host_name().map_err(|_| InstallError::Io)?;
        let exe = std::env::current_exe().map_err(|_| InstallError::NoStablePath)?;
        // Windows keeps the path as the OS reports it (a `\\?\` form would end up in the PATH);
        // elsewhere symlinks are resolved so a link next to the app cannot become `app_path`.
        let current_exe = if cfg!(windows) {
            exe
        } else {
            exe.canonicalize().map_err(|_| InstallError::NoStablePath)?
        };
        let appimage: Option<OsString> = std::env::var_os("APPIMAGE").filter(|v| !v.is_empty());
        let appimage = appimage.map(PathBuf::from);
        let appimage_is_file = appimage.as_ref().is_some_and(|p| p.is_file());
        let appdir = std::env::var_os("APPDIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        Ok(Inputs {
            platform: Platform::current(),
            home: base.home.clone(),
            cli_toml: cli_file(&base, &host),
            current_exe,
            appimage,
            appimage_is_file,
            appdir,
        })
    }
}

/// One thing `install` wrote or `uninstall` removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Artifact {
    PathEntry,
    /// Install only: the PATH entry of an earlier install folder that is gone (Windows, PD-177).
    /// `uninstall` never lists it.
    StaleEntry,
    Symlink,
    Wrapper,
    Launcher,
    CliToml,
}

/// The artifacts that changed in one call, in the order they were done. An artifact that was
/// already as wanted is not listed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    pub changed: Vec<Artifact>,
}

/// §12.3: writes the artifacts of `layout`, then `cli.toml`. A failure undoes what this call
/// already did (best effort) and answers the kind of the failure.
pub fn install(ops: &dyn PlatformOps, layout: &Layout) -> Result<Report, InstallError> {
    let mut done = Report::default();
    let result = install_steps(ops, layout, &mut done);
    if result.is_err() {
        // The undo is best effort: its own failures cannot improve the answer.
        let _ = remove_artifacts(ops, layout, Some(&done.changed));
    }
    result.map(|()| done)
}

fn install_steps(
    ops: &dyn PlatformOps,
    layout: &Layout,
    done: &mut Report,
) -> Result<(), InstallError> {
    let mut path_entry = None;
    match &layout.kind {
        Kind::Windows { .. } => {
            path_entry =
                windows::install(ops, &layout.kind, &layout.app_path, &layout.cli_toml, done)?;
        }
        Kind::Macos { .. } => macos::install(ops, &layout.kind, done)?,
        Kind::AppImage { .. } => linux::install(ops, &layout.kind, done)?,
        // §12.3: deb/rpm are already on PATH; nothing to write, not even `cli.toml`.
        Kind::Packaged => return Ok(()),
    }
    // `cli.toml` last: it says "installed" to the CLI, so it exists only after the rest worked.
    let want = CliToml {
        app_path: Some(layout.app_path.clone()),
        path_entry,
    };
    if ops.read_cli_toml(&layout.cli_toml).ok().flatten().as_ref() != Some(&want) {
        ops.write_cli_toml(&layout.cli_toml, &want)
            .map_err(|_| InstallError::CliToml)?;
        done.changed.push(Artifact::CliToml);
    }
    Ok(())
}

/// §12.3, §12.5 step 3: removes what `install` writes (and `cli.toml`), leaving anything that is not
/// ours. Idempotent.
pub fn uninstall(ops: &dyn PlatformOps, layout: &Layout) -> Result<Report, InstallError> {
    remove_artifacts(ops, layout, None).map(|changed| Report { changed })
}

/// Removes the artifacts (`only`: just those, for the undo of a failed install).
fn remove_artifacts(
    ops: &dyn PlatformOps,
    layout: &Layout,
    only: Option<&[Artifact]>,
) -> Result<Vec<Artifact>, InstallError> {
    let wanted = |a: Artifact| only.is_none_or(|o| o.contains(&a));
    let mut removed = Vec::new();
    match &layout.kind {
        Kind::Windows { .. } => windows::uninstall(ops, &layout.kind, wanted, &mut removed)?,
        Kind::Macos { .. } => macos::uninstall(ops, &layout.kind, wanted, &mut removed)?,
        Kind::AppImage { .. } => linux::uninstall(ops, &layout.kind, wanted, &mut removed)?,
        Kind::Packaged => {}
    }
    // `cli.toml` last: a failed removal above leaves it, so the CLI still finds the app. An
    // unparsable file counts as present (it is ours to remove).
    if wanted(Artifact::CliToml)
        && ops
            .read_file(&layout.cli_toml)
            .map_err(|e| io_error(&e))?
            .is_some()
    {
        ops.remove(&layout.cli_toml).map_err(|e| io_error(&e))?;
        removed.push(Artifact::CliToml);
    }
    Ok(removed)
}

/// Whether the CLI is on the PATH as this layout wants it (what `settings_get` reports, §12.3):
/// the artifacts are there and `cli.toml` names `app_path`. deb/rpm are always installed.
pub fn is_installed(ops: &dyn PlatformOps, layout: &Layout) -> bool {
    let artifacts = match &layout.kind {
        Kind::Windows { .. } => windows::present(ops, &layout.kind),
        Kind::Macos { .. } => macos::present(ops, &layout.kind),
        Kind::AppImage { .. } => linux::present(ops, &layout.kind),
        Kind::Packaged => return true,
    };
    artifacts
        && matches!(
            ops.read_cli_toml(&layout.cli_toml),
            Ok(Some(CliToml { app_path: Some(p), .. })) if p == layout.app_path
        )
}

/// `dir` is one of the absolute entries of `path` (PD-177). A relative or empty entry is the
/// current directory, not `dir`; a trailing separator does not matter.
pub fn local_bin_on_path(path: Option<&std::ffi::OsStr>, dir: &Path) -> bool {
    let Some(path) = path else {
        return false;
    };
    looks_absolute(dir)
        && std::env::split_paths(path).any(|entry| looks_absolute(&entry) && entry == dir)
}

/// Whether the folder this layout puts the CLI in (`~/.local/bin`) is on the PATH of this
/// process: `None` where the CLI does not go to such a folder (Windows edits the user PATH itself,
/// deb/rpm are in `/usr/bin`).
pub fn cli_dir_on_path(ops: &dyn PlatformOps, layout: &Layout) -> Option<bool> {
    let dir = match &layout.kind {
        Kind::Macos { link, .. } => link.parent(),
        Kind::AppImage { wrapper, .. } => wrapper.parent(),
        Kind::Windows { .. } | Kind::Packaged => return None,
    };
    Some(dir.is_some_and(|d| local_bin_on_path(ops.session_path().as_deref(), d)))
}

// ---------- the real ops ----------

/// The real machine. Everything off-platform answers `Unsupported`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemOps;

impl PlatformOps for SystemOps {
    fn user_path_get(&self) -> io::Result<Option<String>> {
        #[cfg(windows)]
        {
            windows::registry::RegistryOps::user().path_get()
        }
        #[cfg(not(windows))]
        {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    fn user_path_set(&self, v: &str) -> io::Result<()> {
        #[cfg(windows)]
        {
            windows::registry::RegistryOps::user().path_set(v)
        }
        #[cfg(not(windows))]
        {
            let _ = v;
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    fn user_path_remove(&self) -> io::Result<()> {
        #[cfg(windows)]
        {
            windows::registry::RegistryOps::user().path_remove()
        }
        #[cfg(not(windows))]
        {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    fn broadcast_setting_change(&self) {
        #[cfg(windows)]
        windows::registry::broadcast_environment_change();
    }

    fn symlink(&self, src: &Path, dst: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::os::unix::fs::symlink(src, dst)
        }
        #[cfg(not(unix))]
        {
            let _ = (src, dst);
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    fn write_file(&self, p: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
        use std::io::Write;
        let parent = p
            .parent()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        std::fs::create_dir_all(parent)?;
        let name = p
            .file_name()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut tmp_name = OsString::from(".");
        tmp_name.push(name);
        tmp_name.push(".atlas-duck-tmp");
        let tmp = parent.join(tmp_name);
        // A temp file a crash left behind keeps its old mode (the mode below applies only to a file
        // that is created) and a planted link there would be followed: remove it, then create the
        // file new (`create_new` never follows a link).
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let written = options
            .open(&tmp)
            .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
            .and_then(|()| std::fs::rename(&tmp, p));
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        written
    }

    fn remove(&self, p: &Path) -> io::Result<()> {
        match std::fs::remove_file(p) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    fn read_file(&self, p: &Path) -> io::Result<Option<Vec<u8>>> {
        use std::io::Read;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        // A FIFO opens for reading only once a writer shows up; without this the install would
        // wait for ever on a pipe someone left at the wrapper's path.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = match options.open(p) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        // Checked on the opened handle (not on the path, which could be swapped in between). A
        // handle that cannot even say what it is (a Windows device) is no regular file either.
        if !file.metadata().is_ok_and(|m| m.is_file()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // A wrapper or launcher is a few hundred bytes: one byte past the limit is enough to tell
        // the file is too big to be ours (the marker check refuses such a file).
        let mut bytes = Vec::new();
        file.take(MAX_READ as u64 + 1).read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    fn read_link(&self, p: &Path) -> io::Result<Option<PathBuf>> {
        match std::fs::read_link(p) {
            Ok(t) => Ok(Some(t)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write_cli_toml(&self, p: &Path, c: &CliToml) -> Result<(), PinnedError> {
        atlas_duck_ipc::paths::write_cli_toml(p, c)
    }

    fn read_cli_toml(&self, p: &Path) -> Result<Option<CliToml>, PinnedError> {
        atlas_duck_ipc::paths::read_cli_toml(p)
    }

    fn file_exists(&self, p: &Path) -> io::Result<bool> {
        match std::fs::metadata(p) {
            Ok(m) => Ok(m.is_file()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn session_path(&self) -> Option<OsString> {
        std::env::var_os("PATH")
    }
}

/// The in-memory ops of the unit tests and of the mock-runtime tests in `tests/`.
#[cfg(any(test, feature = "scripted-approver"))]
pub mod fake;

#[cfg(test)]
mod tests;
