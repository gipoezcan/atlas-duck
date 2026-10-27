//! The sandbox worker for the server image (M14 T14, PD-250): the same thin main over
//! `atlas_duck_sandbox_worker::run` as the desktop's `atlas-duck-sandbox` bin (which is a target of
//! the Tauri package and cannot be built without it). The image installs it as
//! `/app/atlas-duck-sandbox` (`ATLAS_DUCK_SANDBOX_BIN`). It links no Tauri, webview, HTTP, DB or
//! keyring code (§2.1).

/// Plan M8 PD-134: an exhausted process exits `EXIT_PROCESS_LIMIT` (103) at once, as in the
/// desktop worker bin.
#[global_allocator]
static A: atlas_duck_sandbox_worker::ExitOnOomAlloc = atlas_duck_sandbox_worker::ExitOnOomAlloc;

fn main() {
    std::process::exit(atlas_duck_sandbox_worker::run())
}
