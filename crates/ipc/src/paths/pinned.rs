//! The machine-local pinned files `paths.toml` and `cli.toml` (§7.7).
//!
//! Location: Windows `<FOLDERID_LocalAppData>\atlas-duck\paths.toml` and
//! `cli.toml`; macOS `<passwd home>/Library/Application Support/atlas-duck/`
//! and Linux `<passwd home>/.config/atlas-duck/`, there host-qualified as
//! `paths-<host>.toml` and `cli-<host>.toml`. This module only ever opens the
//! one file it is given; it never lists the directory, so another host's
//! files are never read, adopted or rewritten.
//!
//! File format (keys chosen by the plan; the spec names only the pinned data
//! dir, the pinned XDG overrides and `install_id`):
//!
//! ```toml
//! # paths.toml / paths-<host>.toml
//! schema_version = 1
//! data_dir = "/home/user/.local/share/atlas-duck"
//! config_dir = "/home/user/.config/atlas-duck"
//! install_id = "…"            # optional; written by the wizard (M6)
//!
//! # cli.toml / cli-<host>.toml
//! schema_version = 1
//! app_path = "/opt/atlas-duck/atlas-duck-app"   # optional (M10)
//! ```
//!
//! Reads are additive like `config.toml` (§7.7): the known keys are read
//! whatever `schema_version` says and unknown keys are ignored. Writes refuse
//! a file whose `schema_version` is newer than [`PINNED_SCHEMA_VERSION`] or
//! that does not parse, and replace the file atomically (temp file in the same
//! directory, then rename).
//!
//! `data_dir` and `config_dir` must be absolute (`Path::is_absolute`). A
//! relative value would resolve against the process's current directory, which
//! breaks §7.7 path stability: a read of such a file is `Err(Parse)` and a
//! write is refused with `Err(NotAbsolutePath)`.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use toml_edit::{DocumentMut, Item, value};

use super::base_dirs::BaseDirs;
use super::{APP_DIR_NAME, PINNED_SCHEMA_VERSION};

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_DATA_DIR: &str = "data_dir";
const KEY_CONFIG_DIR: &str = "config_dir";
const KEY_INSTALL_ID: &str = "install_id";
const KEY_APP_PATH: &str = "app_path";

/// Contents of this host's `paths.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedPaths {
    /// The file's version as read. `write_pinned` always writes
    /// [`PINNED_SCHEMA_VERSION`].
    pub schema_version: u32,
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    /// `install_id` of the store this file pins (§7.7, §8.6).
    pub install_id: Option<String>,
}

/// Contents of this host's `cli.toml` (§7.7 `cli.toml`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliToml {
    pub app_path: Option<PathBuf>,
}

/// Errors from reading or writing a pinned file. No variant carries file
/// content.
#[derive(Debug)]
pub enum PinnedError {
    /// A path to be written is not valid Unicode; TOML strings cannot hold it
    /// and it is never converted lossily.
    NonUtf8Path(PathBuf),
    /// Write refused: `data_dir` or `config_dir` is not absolute (a relative
    /// path, an empty path, or on Windows a drive-relative or root-relative
    /// one). Carries the caller's own argument.
    NotAbsolutePath(PathBuf),
    /// The file is not valid UTF-8 TOML, lacks a required key of the right
    /// type, or holds a `data_dir` or `config_dir` that is not absolute.
    /// Never treated as "file absent".
    Parse,
    /// Write refused: the existing file was written by a newer version.
    NewerSchema {
        schema_version: u32,
    },
    Io(io::Error),
}

impl fmt::Display for PinnedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUtf8Path(p) => {
                write!(
                    f,
                    "path is not valid Unicode and cannot be pinned: {}",
                    p.display()
                )
            }
            Self::NotAbsolutePath(p) => {
                write!(
                    f,
                    "path is not absolute and cannot be pinned: {}",
                    p.display()
                )
            }
            Self::Parse => f.write_str("pinned file could not be parsed"),
            Self::NewerSchema { schema_version } => write!(
                f,
                "pinned file has schema_version {schema_version}, newer than {PINNED_SCHEMA_VERSION}; not rewritten"
            ),
            Self::Io(e) => write!(f, "pinned file I/O error: {e}"),
        }
    }
}

impl std::error::Error for PinnedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for PinnedError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Directory holding this host's pinned files.
pub fn pinned_dir(b: &BaseDirs) -> PathBuf {
    #[cfg(windows)]
    {
        b.local_app_data_or_default().join(APP_DIR_NAME)
    }
    #[cfg(target_os = "macos")]
    {
        b.home
            .join("Library")
            .join("Application Support")
            .join(APP_DIR_NAME)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        b.home.join(".config").join(APP_DIR_NAME)
    }
}

/// This host's `paths.toml`. `host` is the value of `host_name()`; it is
/// ignored on Windows, where the file is not host-qualified.
pub fn paths_file(b: &BaseDirs, host: &str) -> PathBuf {
    pinned_dir(b).join(pinned_file_name("paths", host))
}

/// This host's `cli.toml`. `host` is the value of `host_name()`; it is
/// ignored on Windows, where the file is not host-qualified.
pub fn cli_file(b: &BaseDirs, host: &str) -> PathBuf {
    pinned_dir(b).join(pinned_file_name("cli", host))
}

#[cfg(windows)]
fn pinned_file_name(stem: &str, _host: &str) -> String {
    format!("{stem}.toml")
}

#[cfg(unix)]
fn pinned_file_name(stem: &str, host: &str) -> String {
    // `host` should already be a sanitized component. Anything that is not a
    // safe component is sanitized here so that it can never name a path
    // outside `pinned_dir`.
    let host = if is_safe_component(host) {
        host.to_owned()
    } else {
        super::host::sanitize_host_component(host)
    };
    format!("{stem}-{host}.toml")
}

/// True when `s` matches `^[a-z0-9._-]{1,240}$`, contains no `..` and does not
/// start or end with `.`.
#[cfg(unix)]
fn is_safe_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= super::MAX_HOST_COMPONENT_LEN
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
        && !s.contains("..")
        && !s.starts_with('.')
        && !s.ends_with('.')
}

/// Reads this host's `paths.toml`. Missing file: `Ok(None)` (before first
/// run). Unparsable file, missing/mistyped required key, or a `data_dir` or
/// `config_dir` that is empty or not absolute: `Err(Parse)`.
pub fn read_pinned(path: &Path) -> Result<Option<PinnedPaths>, PinnedError> {
    let Some(doc) = read_doc(path)? else {
        return Ok(None);
    };
    Ok(Some(PinnedPaths {
        schema_version: schema_version_of(&doc)?,
        data_dir: required_absolute_path(&doc, KEY_DATA_DIR)?,
        config_dir: required_absolute_path(&doc, KEY_CONFIG_DIR)?,
        install_id: optional_str(&doc, KEY_INSTALL_ID)?.map(str::to_owned),
    }))
}

/// Writes this host's `paths.toml` atomically with
/// `schema_version = PINNED_SCHEMA_VERSION`. Refuses, leaving everything
/// untouched, when a path is not Unicode (`NonUtf8Path`), when `data_dir` or
/// `config_dir` is not absolute (`NotAbsolutePath`), when the existing file is
/// newer (`NewerSchema`) or when `read_pinned` would fail on it (`Parse`,
/// `Io`): an unreadable pinned file is never replaced. The arguments are
/// validated before anything is read or created.
pub fn write_pinned(path: &Path, p: &PinnedPaths) -> Result<(), PinnedError> {
    let data_dir = utf8(&p.data_dir)?;
    let config_dir = utf8(&p.config_dir)?;
    require_absolute(&p.data_dir)?;
    require_absolute(&p.config_dir)?;
    if let Some(existing) = read_pinned(path)? {
        refuse_newer(existing.schema_version)?;
    }
    let mut doc = DocumentMut::new();
    doc[KEY_SCHEMA_VERSION] = value(i64::from(PINNED_SCHEMA_VERSION));
    doc[KEY_DATA_DIR] = value(data_dir);
    doc[KEY_CONFIG_DIR] = value(config_dir);
    if let Some(id) = &p.install_id {
        doc[KEY_INSTALL_ID] = value(id.as_str());
    }
    atomic_write(path, doc.to_string().as_bytes())
}

/// Reads this host's `cli.toml`. Missing file: `Ok(None)`. Unparsable file:
/// `Err(Parse)`.
pub fn read_cli_toml(path: &Path) -> Result<Option<CliToml>, PinnedError> {
    let Some(doc) = read_doc(path)? else {
        return Ok(None);
    };
    schema_version_of(&doc)?;
    Ok(Some(CliToml {
        app_path: optional_str(&doc, KEY_APP_PATH)?
            .filter(|s| !s.is_empty())
            .map(PathBuf::from),
    }))
}

/// Writes this host's `cli.toml` atomically, with the same refusals as
/// [`write_pinned`].
pub fn write_cli_toml(path: &Path, c: &CliToml) -> Result<(), PinnedError> {
    let app_path = c.app_path.as_deref().map(utf8).transpose()?;
    if let Some(doc) = read_doc(path)? {
        // Same validation as read_cli_toml: schema_version and app_path type.
        refuse_newer(schema_version_of(&doc)?)?;
        optional_str(&doc, KEY_APP_PATH)?;
    }
    let mut doc = DocumentMut::new();
    doc[KEY_SCHEMA_VERSION] = value(i64::from(PINNED_SCHEMA_VERSION));
    if let Some(app_path) = app_path {
        doc[KEY_APP_PATH] = value(app_path);
    }
    atomic_write(path, doc.to_string().as_bytes())
}

fn utf8(p: &Path) -> Result<&str, PinnedError> {
    p.to_str()
        .ok_or_else(|| PinnedError::NonUtf8Path(p.to_path_buf()))
}

fn read_doc(path: &Path) -> Result<Option<DocumentMut>, PinnedError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PinnedError::Io(e)),
    };
    // Both error values are dropped: they can quote file content.
    let text = String::from_utf8(bytes).map_err(|_| PinnedError::Parse)?;
    let doc = text
        .parse::<DocumentMut>()
        .map_err(|_| PinnedError::Parse)?;
    Ok(Some(doc))
}

fn schema_version_of(doc: &DocumentMut) -> Result<u32, PinnedError> {
    doc.get(KEY_SCHEMA_VERSION)
        .and_then(Item::as_integer)
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v >= 1)
        .ok_or(PinnedError::Parse)
}

/// A required key holding a non-empty absolute path. A relative path would
/// resolve against the process's current directory (§7.7 Path stability).
fn required_absolute_path(doc: &DocumentMut, key: &str) -> Result<PathBuf, PinnedError> {
    match optional_str(doc, key)? {
        Some(s) if !s.is_empty() => {
            let p = PathBuf::from(s);
            if p.is_absolute() {
                Ok(p)
            } else {
                Err(PinnedError::Parse)
            }
        }
        _ => Err(PinnedError::Parse),
    }
}

fn require_absolute(p: &Path) -> Result<(), PinnedError> {
    if p.is_absolute() {
        Ok(())
    } else {
        Err(PinnedError::NotAbsolutePath(p.to_path_buf()))
    }
}

fn optional_str<'d>(doc: &'d DocumentMut, key: &str) -> Result<Option<&'d str>, PinnedError> {
    match doc.get(key) {
        None => Ok(None),
        Some(item) => item.as_str().map(Some).ok_or(PinnedError::Parse),
    }
}

fn refuse_newer(found: u32) -> Result<(), PinnedError> {
    if found > PINNED_SCHEMA_VERSION {
        return Err(PinnedError::NewerSchema {
            schema_version: found,
        });
    }
    Ok(())
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Writes `bytes` to a new temp file next to `path`, flushes it to disk and
/// renames it over `path`. An existing file is replaced whole, never truncated
/// in place. Creates the parent directory when missing.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), PinnedError> {
    let file_name = path.file_name().ok_or_else(|| {
        PinnedError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pinned file path has no file name",
        ))
    })?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    fs::create_dir_all(dir)?;
    let mut tmp_name = OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = dir.join(tmp_name);
    let written = (|| -> io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(PinnedError::Io(e));
    }
    #[cfg(unix)]
    if let Ok(d) = fs::File::open(dir) {
        // Best effort: persist the rename itself.
        let _ = d.sync_all();
    }
    Ok(())
}
