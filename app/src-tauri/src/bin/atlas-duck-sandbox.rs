//! `atlas-duck-sandbox` worker bin: a thin main over `atlas_duck_sandbox_worker::run` (§12.1).
//! A console-subsystem bin with an 8 MiB stack reserve on Windows MSVC (build.rs, §9.3); it links no
//! Tauri, webview, HTTP, DB or keyring code (§2.1).

fn main() {
    std::process::exit(atlas_duck_sandbox_worker::run())
}
