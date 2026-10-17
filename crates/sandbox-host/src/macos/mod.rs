//! macOS worker spawn routine (§3.4): `posix_spawn` with
//! `POSIX_SPAWN_CLOEXEC_DEFAULT`, never `std::process::Command`.
//!
//! The confinement itself (`sandbox_init` with the embedded SBPL profile,
//! §9.4) is applied by the worker to itself; see
//! `atlas_duck_sandbox_worker::confine::macos`. The memory limit is the
//! host-side footprint watchdog (M8 Task 9, `watchdog`).

mod spawner;
mod watchdog;

pub use spawner::{MacSpawner, MacWorker, WORKER_ENV};
