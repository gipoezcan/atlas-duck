//! Keyring locality (I-44, V29 keyring-dir half) now lives in `atlas_duck_ipc::paths::keyring`
//! so the CLI can compute `keyring_local` (§4.7) without depending on `audit`.

pub use atlas_duck_ipc::paths::keyring::{
    DirsOs, KeyringLocality, Probe, keyring_dirs, keyring_dirs_for, keyring_locality,
    keyring_locality_with, probe_fs,
};
