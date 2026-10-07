//! `sandbox-host`: spawns, limits and confines the sandbox worker (§2.2, §3.4)
//! and runs the §9.4 confinement probe.
//!
//! M1 holds the OS-independent probe runner, its scoring rules and the
//! sandbox binary identity (T15), and the per-OS spawn routines: Linux (T16,
//! module `linux`), macOS (T18) and Windows (T19). [`platform_spawner`]
//! returns the one for the running OS.

pub mod identity;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod probe;
pub mod spawn;

use std::io;

use crate::spawn::WorkerSpawner;

/// The spawner for the running OS (§3.4: a dedicated platform routine, never
/// `std::process::Command`).
///
/// Linux: [`linux::LinuxSpawner`] (T16). macOS (T18) and Windows (T19) add
/// their own `#[cfg(target_os = ...)]` arm; until then they get
/// `ErrorKind::Unsupported`.
pub fn platform_spawner() -> io::Result<Box<dyn WorkerSpawner>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxSpawner::start()?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no sandbox worker spawn routine for this OS yet",
        ))
    }
}
