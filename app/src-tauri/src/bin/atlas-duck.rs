//! `atlas-duck` (CLI) bin: a thin main over `atlas_duck_cli::run` (§12.1). A console-subsystem
//! bin; it links no Tauri, webview, TLS, DB or keyring code (§2.1).

fn main() {
    std::process::exit(atlas_duck_cli::run(std::env::args_os().skip(1).collect()))
}
