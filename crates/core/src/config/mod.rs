//! `config.toml` loading, saving and the §7.7 cross-version rules.
//!
//! * Head schema (this binary): [`CONFIG_SCHEMA_HEAD`]. An older file is
//!   migrated additively and written back atomically; nothing else is
//!   ever written by `load_config`.
//! * A newer file that parses is [`ConfigState::ReadOnly`]: known keys are
//!   read, the rest ignored, and the file is never rewritten, migrated or
//!   downgraded (§7.7, §8.13).
//! * A file that does not parse, or has no usable `schema_version`, is
//!   [`ConfigState::Unreadable`]: no instances come from it, requests answer
//!   `not_configured` with `details.reason = config_unreadable` (§4.3 exit 9),
//!   and the file is left byte-identical. Same-version corruption and a
//!   missing `schema_version` are treated like the spec's "newer-schema file
//!   that does not parse" (plan reading; the spec is silent on them).
//! * `written_by` records the app version of the last writer, so the M6
//!   banners "config written by vX ..." have a source (plan-added key).

mod migrate;

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use atlas_duck_ipc::build_info::APP_VERSION;
use toml_edit::{DocumentMut, Item, Value};

pub use migrate::{
    KEY_SCHEMA_VERSION, MIGRATIONS, MigrateError, Migration, first_non_additive, leaf_values,
    migrate_with,
};

/// File name inside the config dir (§7.7).
pub const CONFIG_FILE_NAME: &str = "config.toml";
/// The newest `config.toml` schema this binary reads and writes.
pub const CONFIG_SCHEMA_HEAD: u32 = 1;
/// `details.reason` for requests while the config is unreadable (§4.3 exit 9, §7.7).
pub const REASON_CONFIG_UNREADABLE: &str = "config_unreadable";
/// Root key holding the app version of the last writer (plan-added, additive).
pub const KEY_WRITTEN_BY: &str = "written_by";

/// A parsed `config.toml`. The document keeps comments and formatting.
#[derive(Debug, Clone)]
pub struct Config {
    pub schema_version: u32,
    pub written_by: Option<String>,
    doc: DocumentMut,
}

impl Config {
    /// The parsed document, for typed accessors added in M3/M6.
    pub fn document(&self) -> &DocumentMut {
        &self.doc
    }
}

/// What `APP_START {config_read_only: {schema_version, parsed}}` records
/// (§7.7, §8.3), plus the writer version for the M6 banner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigReadOnly {
    pub schema_version: Option<u32>,
    pub parsed: bool,
    pub written_by: Option<String>,
}

/// Result of [`load_config`].
#[derive(Debug, Clone)]
pub enum ConfigState {
    /// No `config.toml` (nothing was created).
    Absent,
    /// Head schema (possibly just migrated); settings may be saved.
    Writable(Config),
    /// Written by a newer schema; read as far as known, never written.
    ReadOnly {
        config: Config,
        info: ConfigReadOnly,
    },
    /// Does not parse or has no usable `schema_version`; no instances.
    Unreadable { info: ConfigReadOnly },
}

impl ConfigState {
    /// `Some` for `ReadOnly` and `Unreadable` (the `APP_START` field), else `None`.
    pub fn read_only_info(&self) -> Option<&ConfigReadOnly> {
        match self {
            Self::ReadOnly { info, .. } | Self::Unreadable { info } => Some(info),
            Self::Absent | Self::Writable(_) => None,
        }
    }

    /// Whether a parsed document exists that instances may be read from:
    /// `true` for `Writable` and `ReadOnly`, `false` for `Unreadable` and
    /// `Absent`.
    pub fn has_instances_source(&self) -> bool {
        matches!(self, Self::Writable(_) | Self::ReadOnly { .. })
    }
}

/// Why [`save_config`] refused or failed.
#[derive(Debug)]
pub enum ConfigWriteError {
    /// The config or the file on disk has a newer schema than this binary.
    ReadOnly,
    /// The file on disk does not parse or has no usable `schema_version`.
    Unreadable,
    Io(io::Error),
}

impl fmt::Display for ConfigWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnly => {
                f.write_str("config.toml was written by a newer atlas-duck; read-only")
            }
            Self::Unreadable => f.write_str("config.toml could not be read; left untouched"),
            Self::Io(e) => write!(f, "config.toml write failed: {e}"),
        }
    }
}

impl std::error::Error for ConfigWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::ReadOnly | Self::Unreadable => None,
        }
    }
}

impl From<io::Error> for ConfigWriteError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Loads `path` with this binary's head and [`MIGRATIONS`].
pub fn load_config(path: &Path) -> io::Result<ConfigState> {
    load_config_with(path, CONFIG_SCHEMA_HEAD, MIGRATIONS)
}

/// [`load_config`] with an explicit head and migration table. Test seam for
/// the migrate-on-load and never-migrate-newer rules; production code calls
/// [`load_config`].
#[doc(hidden)]
pub fn load_config_with(path: &Path, head: u32, table: &[Migration]) -> io::Result<ConfigState> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ConfigState::Absent),
        Err(e) => return Err(e),
    };
    match inspect(&bytes) {
        Inspected::Unparsable {
            schema_version,
            written_by,
        } => Ok(ConfigState::Unreadable {
            info: ConfigReadOnly {
                schema_version,
                parsed: false,
                written_by,
            },
        }),
        Inspected::Parsed {
            schema_version: None,
            written_by,
            ..
        } => Ok(ConfigState::Unreadable {
            info: ConfigReadOnly {
                schema_version: None,
                parsed: true,
                written_by,
            },
        }),
        Inspected::Parsed {
            doc,
            schema_version: Some(version),
            written_by,
        } if version > head => Ok(ConfigState::ReadOnly {
            info: ConfigReadOnly {
                schema_version: Some(version),
                parsed: true,
                written_by: written_by.clone(),
            },
            config: Config {
                schema_version: version,
                written_by,
                doc,
            },
        }),
        Inspected::Parsed {
            doc,
            schema_version: Some(version),
            written_by,
        } if version == head => Ok(ConfigState::Writable(Config {
            schema_version: version,
            written_by,
            doc,
        })),
        Inspected::Parsed {
            mut doc,
            schema_version: Some(version),
            ..
        } => {
            let reached = migrate_with(&mut doc, version, table).map_err(invalid_data)?;
            if reached != head {
                return Err(invalid_data(MigrateError::MissingStep { from: reached }));
            }
            stamp(&mut doc, head);
            write_atomic(path, doc.to_string().as_bytes())?;
            Ok(ConfigState::Writable(Config {
                schema_version: head,
                written_by: Some(APP_VERSION.to_owned()),
                doc,
            }))
        }
    }
}

/// Writes `config` to `path` atomically (sibling temp file + rename) with
/// `schema_version = CONFIG_SCHEMA_HEAD` and `written_by = APP_VERSION`.
/// Refuses a config with a newer schema, and re-reads the file on disk
/// first: if it became newer or unreadable since it was loaded (roaming
/// profile, NFS home), nothing is written (§8.13: config files are written
/// only by a binary whose schema is at least the file's).
pub fn save_config(path: &Path, config: &Config) -> Result<(), ConfigWriteError> {
    if config.schema_version > CONFIG_SCHEMA_HEAD {
        return Err(ConfigWriteError::ReadOnly);
    }
    if config.schema_version < CONFIG_SCHEMA_HEAD {
        return Err(ConfigWriteError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "config is below the head schema; load it through load_config first",
        )));
    }
    match fs::read(path) {
        Ok(bytes) => match inspect(&bytes) {
            Inspected::Unparsable { .. }
            | Inspected::Parsed {
                schema_version: None,
                ..
            } => return Err(ConfigWriteError::Unreadable),
            Inspected::Parsed {
                schema_version: Some(on_disk),
                ..
            } if on_disk > CONFIG_SCHEMA_HEAD => return Err(ConfigWriteError::ReadOnly),
            Inspected::Parsed { .. } => {}
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(ConfigWriteError::Io(e)),
    }
    let mut doc = config.doc.clone();
    stamp(&mut doc, CONFIG_SCHEMA_HEAD);
    write_atomic(path, doc.to_string().as_bytes())?;
    Ok(())
}

enum Inspected {
    Parsed {
        doc: DocumentMut,
        /// `None` when the key is missing or not an integer in `1..=u32::MAX`.
        schema_version: Option<u32>,
        written_by: Option<String>,
    },
    Unparsable {
        schema_version: Option<u32>,
        written_by: Option<String>,
    },
}

fn inspect(bytes: &[u8]) -> Inspected {
    let parsed = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse::<DocumentMut>().ok());
    match parsed {
        Some(doc) => {
            let schema_version = doc
                .get(KEY_SCHEMA_VERSION)
                .and_then(Item::as_integer)
                .and_then(|v| u32::try_from(v).ok())
                .filter(|v| *v >= 1);
            let written_by = doc
                .get(KEY_WRITTEN_BY)
                .and_then(Item::as_str)
                .map(str::to_owned);
            Inspected::Parsed {
                doc,
                schema_version,
                written_by,
            }
        }
        None => {
            let text = String::from_utf8_lossy(bytes);
            Inspected::Unparsable {
                schema_version: scan_schema_version(&text),
                written_by: scan_written_by(&text),
            }
        }
    }
}

/// Lenient `^\s*schema_version\s*=\s*(\d+)` over the root lines (before the
/// first `[` header) of a file that does not parse.
fn scan_schema_version(text: &str) -> Option<u32> {
    root_lines(text).find_map(|line| {
        let rest = assignment_rhs(line, KEY_SCHEMA_VERSION)?;
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    })
}

/// Lenient `^\s*written_by\s*=\s*"([^"]*)"` over the root lines.
fn scan_written_by(text: &str) -> Option<String> {
    root_lines(text).find_map(|line| {
        let rest = assignment_rhs(line, KEY_WRITTEN_BY)?.strip_prefix('"')?;
        let end = rest.find('"')?;
        Some(rest[..end].to_owned())
    })
}

fn root_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .take_while(|line| !line.trim_start().starts_with('['))
}

fn assignment_rhs<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix(key)?.trim_start();
    Some(rest.strip_prefix('=')?.trim_start())
}

fn stamp(doc: &mut DocumentMut, schema_version: u32) {
    migrate::set_root_value(
        doc,
        KEY_SCHEMA_VERSION,
        Value::from(i64::from(schema_version)),
    );
    migrate::set_root_value(doc, KEY_WRITTEN_BY, Value::from(APP_VERSION));
}

fn invalid_data(e: MigrateError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write to a new sibling temp file, fsync, then rename over `path`
/// (`rename` replaces an existing file on Windows too). On failure the temp
/// file is removed and `path` is untouched. On Unix the parent directory is
/// fsynced afterwards (best effort) so the rename survives a crash.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "config path has no file name")
    })?;
    let mut temp_name = OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let temp: PathBuf = path.with_file_name(temp_name);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
        return result;
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}
