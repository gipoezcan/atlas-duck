//! Bundle identity (§12.1, §12.5): the identifier and the product name differ from the data-dir
//! folder name `atlas-duck` (§7.7), the main binary is `atlas-duck-app`, and the M1 app declares no
//! windows and no capabilities (§10.3).

use std::path::PathBuf;

use serde_json::Value;

/// The data-dir / pinned-files folder name (§7.7: `%LOCALAPPDATA%\atlas-duck`, ...).
const DATA_DIR_FOLDER: &str = "atlas-duck";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn conf() -> Value {
    let text = std::fs::read_to_string(manifest_dir().join("tauri.conf.json"))
        .expect("read tauri.conf.json");
    serde_json::from_str(&text).expect("tauri.conf.json is JSON")
}

#[test]
fn identifier_differs_from_data_dir_folder() {
    let id = conf()["identifier"]
        .as_str()
        .expect("identifier")
        .to_owned();
    assert!(!id.eq_ignore_ascii_case(DATA_DIR_FOLDER), "{id}");
    assert_eq!(id, "dev.atlasduck.desktop");
}

#[test]
fn product_name_differs_from_data_dir_folder() {
    // The per-user NSIS install dir is %LOCALAPPDATA%\Programs\<productName> (installMode both)
    // or %LOCALAPPDATA%\<productName> (single-mode currentUser); it must never be the data dir.
    let name = conf()["productName"]
        .as_str()
        .expect("productName")
        .to_owned();
    assert!(!name.eq_ignore_ascii_case(DATA_DIR_FOLDER), "{name}");
    assert_eq!(name, "Atlas Duck");
}

#[test]
fn main_binary_is_atlas_duck_app() {
    assert_eq!(conf()["mainBinaryName"], "atlas-duck-app");
}

#[test]
fn no_startup_windows_and_no_capabilities() {
    let c = conf();
    assert_eq!(c["app"]["windows"], Value::Array(vec![]));
    assert_eq!(c["app"]["security"]["capabilities"], Value::Array(vec![]));
}

#[test]
fn cargo_manifest_declares_three_bins_and_default_run() {
    let text = std::fs::read_to_string(manifest_dir().join("Cargo.toml")).expect("read Cargo.toml");
    let text = text.replace("\r\n", "\n");
    assert!(text.contains("default-run = \"atlas-duck-app\""));
    for (name, path) in [
        ("atlas-duck-app", "src/main.rs"),
        ("atlas-duck", "src/bin/atlas-duck.rs"),
        ("atlas-duck-sandbox", "src/bin/atlas-duck-sandbox.rs"),
    ] {
        let entry = format!("[[bin]]\nname = \"{name}\"\npath = \"{path}\"");
        assert!(text.contains(&entry), "missing {entry}");
    }
}

#[test]
fn every_bundle_icon_exists() {
    // tauri-build and the bundlers fail late (icon.ico is a Windows resource, icon.icns a macOS one)
    // when a listed icon is missing; this makes the failure early and local.
    let c = conf();
    let icons = c["bundle"]["icon"]
        .as_array()
        .expect("bundle.icon is an array");
    assert!(!icons.is_empty());
    for icon in icons {
        let rel = icon.as_str().expect("icon path");
        assert!(manifest_dir().join(rel).is_file(), "missing icon {rel}");
    }
}
