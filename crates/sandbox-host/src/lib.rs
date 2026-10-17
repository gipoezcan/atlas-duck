//! `sandbox-host`: spawns, limits and confines the sandbox worker (§2.2, §3.4)
//! and runs the §9.4 confinement probe.
//!
//! M1 holds the OS-independent probe runner, its scoring rules and the
//! sandbox binary identity (T15), and the per-OS spawn routines: Linux (T16,
//! module `linux`), macOS (T18, module `macos`) and Windows (T19, module
//! `windows`). [`platform_spawner`] returns the one for the running OS.
//!
//! M8 (Δ2, PD-137) splits a spawned worker into its pipes, a non-blocking kill
//! handle and a reaper ([`spawn::WorkerProcess::into_parts`], [`kill`]), and
//! runs scripts and compile checks over the split worker ([`bridge`], C.8).
//! M8 Task 9 attributes a run's end from host-measured facts ([`limits`]) and
//! watches a worker's memory per OS (Windows job completion port, macOS
//! footprint [`watchdog`]).

pub mod bridge;
mod drain;
pub mod identity;
pub mod kill;
pub mod limits;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod probe;
pub mod spawn;
#[cfg(unix)]
mod unix;
pub mod watchdog;
#[cfg(windows)]
pub mod windows;
pub mod winscore;

use std::io;

use crate::spawn::WorkerSpawner;

/// The fallback spawner of §9.4, tried when the floor is not met with
/// [`platform_spawner`]: Windows only, a plain AppContainer (never LPAC). `None`
/// on every other OS, and when the profile cannot be opened.
pub fn fallback_spawner() -> Option<Box<dyn WorkerSpawner>> {
    #[cfg(windows)]
    {
        windows::WindowsSpawner::new_plain()
            .ok()
            .map(|s| Box::new(s) as Box<dyn WorkerSpawner>)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// The spawner for the running OS (§3.4: a dedicated platform routine, never
/// `std::process::Command`).
///
/// Linux: [`linux::LinuxSpawner`] (T16). macOS: [`macos::MacSpawner`] (T18).
/// Windows: [`windows::WindowsSpawner`] (T19); it creates (or opens) the
/// AppContainer profile, so it fails when profile creation is blocked. A caller
/// that gets the error can still produce a report with a spawner whose `spawn`
/// returns that error: every record is then `SpawnFailed` and the floor is
/// `NotMet`.
pub fn platform_spawner() -> io::Result<Box<dyn WorkerSpawner>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxSpawner::start()?))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos::MacSpawner::new()))
    }
    #[cfg(windows)]
    {
        Ok(Box::new(windows::WindowsSpawner::new()?))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no sandbox worker spawn routine for this OS",
        ))
    }
}
