fn main() {
    // §9.3: the worker's main thread runs QuickJS on an 8 MiB native stack; on Windows that is the
    // linker stack reserve of the sandbox binary only (MSVC linker syntax, so MSVC targets only).
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        println!("cargo:rustc-link-arg-bin=atlas-duck-sandbox=/STACK:8388608");
    }
    tauri_build::build();
}
