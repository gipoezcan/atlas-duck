fn main() {
    // §9.3: the worker's main thread runs QuickJS on an 8 MiB native stack; on Windows that is the
    // linker stack reserve of the sandbox binary only (MSVC linker syntax, so MSVC targets only).
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        println!("cargo:rustc-link-arg-bin=atlas-duck-sandbox=/STACK:8388608");
        // tauri-build embeds the application manifest (Common-Controls v6) into the bins only
        // (`cargo:rustc-link-arg-bins`). Integration-test executables that link Tauri's mock
        // runtime import comctl32 v6 entry points and, without the manifest, exit with
        // STATUS_ENTRYPOINT_NOT_FOUND (0xc0000139) before the first test runs. Give the test
        // executables the same dependency; the bins are not touched.
        println!("cargo:rustc-link-arg-tests=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-tests=/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
        );
    }
    tauri_build::build();
}
