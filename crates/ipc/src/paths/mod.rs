//! Shared path API for the app and the CLI (§3.1, §7.7).
//!
//! Base folders come from OS known-folder APIs (Windows) or the passwd home
//! directory (macOS/Linux), never from per-session environment variables
//! (§7.7 Path stability). The machine-local pinned files `paths.toml` and
//! `cli.toml` are host-qualified on macOS/Linux (§7.7 Machine-local files).

mod base_dirs;
mod host;
mod pinned;

pub use base_dirs::{BaseDirs, FirstRunDefaults, base_dirs, first_run_defaults};
pub use host::{MAX_HOST_COMPONENT_LEN, host_name, raw_host_name, sanitize_host_component};
pub use pinned::{
    CliToml, PinnedError, PinnedPaths, cli_file, paths_file, pinned_dir, read_cli_toml,
    read_pinned, write_cli_toml, write_pinned,
};

/// Folder name used under every per-OS base folder.
pub const APP_DIR_NAME: &str = "atlas-duck";

/// Schema version this build writes into `paths.toml` and `cli.toml`.
pub const PINNED_SCHEMA_VERSION: u32 = 1;
