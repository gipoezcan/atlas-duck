//! Shared path API for the app and the CLI (§3.1, §7.7).
//!
//! Base folders come from OS known-folder APIs (Windows) or the passwd home
//! directory (macOS/Linux), never from per-session environment variables
//! (§7.7 Path stability). The machine-local pinned files `paths.toml` and
//! `cli.toml` are host-qualified on macOS/Linux (§7.7 Machine-local files).

mod appimage;
mod base_dirs;
mod endpoint;
mod host;
pub mod keyring;
mod locality;
mod pinned;
mod resolve;

pub use appimage::{looks_absolute, runs_from_appimage, under_mount};
pub use base_dirs::{BaseDirs, FirstRunDefaults, base_dirs, first_run_defaults};
// T21 review I-1: exists only with `test-paths`, so the app's test build fails to compile if the
// feature is not forwarded.
#[cfg(feature = "test-paths")]
pub use base_dirs::TEST_HOME_ENV;
#[cfg(windows)]
pub use endpoint::current_user_sid_string;
#[cfg(all(unix, feature = "async"))]
pub(crate) use endpoint::euid;
#[cfg(all(windows, feature = "async"))]
pub(crate) use endpoint::hex_lower;
pub use endpoint::{
    ENDPOINT_FILE, EndpointLocation, MAX_ENDPOINT_NAME_LEN, SOCKET_FILE_NAME, endpoint_location,
    pipe_name_has_prefix, read_endpoint_file, remove_endpoint_file, sweep_endpoint_temps,
    write_endpoint_file,
};
#[cfg(unix)]
pub use endpoint::{check_socket_dir, ensure_socket_dir, socket_dir};
pub use host::{MAX_HOST_COMPONENT_LEN, host_name, raw_host_name, sanitize_host_component};
pub use locality::{
    Locality, MACOS_MNT_LOCAL, NotLocalKind, OVERLAYFS_SUPER_MAGIC, check_locality,
    classify_linux_f_type, classify_macos_mnt_flags, classify_windows_drive_type,
    overlay_layer_paths, win_drive_type,
};
pub use pinned::{
    CliToml, PinnedError, PinnedPaths, cli_file, paths_file, pinned_dir, read_cli_toml,
    read_pinned, write_cli_toml, write_pinned,
};
pub use resolve::{
    DataDirResolution, LocalDataDir, REASON_DATA_DIR_MISSING, REASON_DATA_DIR_NOT_LOCAL,
    check_data_dir, check_data_dir_allowing_network, resolve_data_dir,
};

/// Folder name used under every per-OS base folder.
pub const APP_DIR_NAME: &str = "atlas-duck";

/// Schema version this build writes into `paths.toml` and `cli.toml`.
pub const PINNED_SCHEMA_VERSION: u32 = 1;
