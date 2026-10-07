//! Shared path API for the app and the CLI (§3.1, §7.7).
//!
//! Base folders come from OS known-folder APIs (Windows) or the passwd home
//! directory (macOS/Linux), never from per-session environment variables
//! (§7.7 Path stability). The machine-local pinned files `paths.toml` and
//! `cli.toml` are host-qualified on macOS/Linux (§7.7 Machine-local files).

mod base_dirs;
mod host;
mod locality;
mod pinned;
mod resolve;

pub use base_dirs::{BaseDirs, FirstRunDefaults, base_dirs, first_run_defaults};
pub use host::{MAX_HOST_COMPONENT_LEN, host_name, raw_host_name, sanitize_host_component};
pub use locality::{
    Locality, MACOS_MNT_LOCAL, NotLocalKind, check_locality, classify_linux_f_type,
    classify_macos_mnt_flags, classify_windows_drive_type, win_drive_type,
};
pub use pinned::{
    CliToml, PinnedError, PinnedPaths, cli_file, paths_file, pinned_dir, read_cli_toml,
    read_pinned, write_cli_toml, write_pinned,
};
pub use resolve::{
    DataDirResolution, LocalDataDir, REASON_DATA_DIR_MISSING, REASON_DATA_DIR_NOT_LOCAL,
    check_data_dir, resolve_data_dir,
};

/// Folder name used under every per-OS base folder.
pub const APP_DIR_NAME: &str = "atlas-duck";

/// Schema version this build writes into `paths.toml` and `cli.toml`.
pub const PINNED_SCHEMA_VERSION: u32 = 1;
