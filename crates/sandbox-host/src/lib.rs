//! `sandbox-host`: spawns, limits and confines the sandbox worker (§2.2, §3.4)
//! and runs the §9.4 confinement probe.
//!
//! M1 holds the OS-independent probe runner, its scoring rules and the
//! sandbox binary identity (T15), and the per-OS spawn routines: Linux (T16,
//! module `linux`), macOS (T18, module `macos`) and Windows (T19). [`platform_spawner`]
//! returns the one for the running OS.

pub mod identity;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod probe;
pub mod spawn;

use std::io;

use crate::spawn::WorkerSpawner;

/// The spawner for the running OS (§3.4: a dedicated platform routine, never
/// `std::process::Command`).
///
/// Linux: [`linux::LinuxSpawner`] (T16). macOS: [`macos::MacSpawner`] (T18).
/// Windows (T19) adds its own `#[cfg(target_os = ...)]` arm; until then it gets
/// `ErrorKind::Unsupported`.
pub fn platform_spawner() -> io::Result<Box<dyn WorkerSpawner>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxSpawner::start()?))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos::MacSpawner::new()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no sandbox worker spawn routine for this OS yet",
        ))
    }
}
