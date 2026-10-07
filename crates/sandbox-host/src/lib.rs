//! `sandbox-host`: spawns, limits and confines the sandbox worker (§2.2, §3.4)
//! and runs the §9.4 confinement probe.
//!
//! M1 (T15) holds the OS-independent probe runner, its scoring rules and the
//! sandbox binary identity. The per-OS spawn routines arrive in T16 (Linux),
//! T18 (macOS) and T19 (Windows) and are returned by [`platform_spawner`].

pub mod identity;
pub mod probe;
pub mod spawn;

use std::io;

use crate::spawn::WorkerSpawner;

/// The spawner for the running OS (§3.4: a dedicated platform routine, never
/// `std::process::Command`).
///
/// T15: no OS has a spawn routine yet, so this returns
/// `ErrorKind::Unsupported` everywhere. T16, T18 and T19 replace the body
/// with a `#[cfg(target_os = ...)]` arm per OS.
pub fn platform_spawner() -> io::Result<Box<dyn WorkerSpawner>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no sandbox worker spawn routine for this OS yet",
    ))
}
