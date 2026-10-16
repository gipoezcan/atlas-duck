//! `atlas-duck-sandbox` worker bin: a thin main over `atlas_duck_sandbox_worker::run` (§12.1).
//! A console-subsystem bin with an 8 MiB stack reserve on Windows MSVC (build.rs, §9.3); it links no
//! Tauri, webview, HTTP, DB or keyring code (§2.1).

/// Plan M8 PD-134: an exhausted process exits `EXIT_PROCESS_LIMIT` (103) at once. This bin and the
/// worker's `confined_scripts` test binary are the only places that declare it: the app library
/// links the worker crate, so a declaration there would become every app binary's allocator.
#[global_allocator]
static A: atlas_duck_sandbox_worker::ExitOnOomAlloc = atlas_duck_sandbox_worker::ExitOnOomAlloc;

fn main() {
    std::process::exit(atlas_duck_sandbox_worker::run())
}
