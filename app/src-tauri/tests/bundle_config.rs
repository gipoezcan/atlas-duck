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

// T12: bundle configuration checks (spec §12.1, §12.2, §2.5 macOS hardened runtime, §13).
// These read the files from disk at run time (not include_str!), so a missing file is a
// test failure with a readable message, not a compile error.
mod t12 {
    use serde_json::Value;
    use std::path::PathBuf;

    const LAUNCHER_TEMPLATE: &str = "linux/atlas-duck.desktop";
    const LAUNCHER_FILE_NAME: &str = "atlas-duck.desktop";
    const LINUX_PRODUCT_NAME: &str = "atlas-duck";

    fn src_tauri() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn read_text(rel: &str) -> String {
        let path = src_tauri().join(rel);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
    }

    fn read_bytes(rel: &str) -> Vec<u8> {
        let path = src_tauri().join(rel);
        std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
    }

    fn json(rel: &str) -> Value {
        serde_json::from_str(&read_text(rel)).unwrap_or_else(|e| panic!("{rel} is not JSON: {e}"))
    }

    fn conf() -> Value {
        json("tauri.conf.json")
    }

    fn at<'a>(v: &'a Value, pointer: &str) -> &'a Value {
        v.pointer(pointer)
            .unwrap_or_else(|| panic!("tauri.conf.json has no {pointer}"))
    }

    fn string_at(v: &Value, pointer: &str) -> String {
        at(v, pointer)
            .as_str()
            .unwrap_or_else(|| panic!("{pointer} is not a string"))
            .to_owned()
    }

    fn strings_at(v: &Value, pointer: &str) -> Vec<String> {
        at(v, pointer)
            .as_array()
            .unwrap_or_else(|| panic!("{pointer} is not an array"))
            .iter()
            .map(|s| {
                s.as_str()
                    .unwrap_or_else(|| panic!("{pointer} has a non-string entry"))
                    .to_owned()
            })
            .collect()
    }

    fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
        const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        if bytes.len() < 24 || bytes[..8] != SIGNATURE || &bytes[12..16] != b"IHDR" {
            return None;
        }
        let width = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
        let height = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
        Some((width, height))
    }

    #[test]
    fn deb_depends_name_webkitgtk_4_1_and_ayatana_appindicator3() {
        let deps = strings_at(&conf(), "/bundle/linux/deb/depends");
        assert!(
            deps.iter().any(|d| d == "libwebkit2gtk-4.1-0"),
            "deb depends {deps:?} lack libwebkit2gtk-4.1-0"
        );
        assert!(
            deps.iter().any(|d| d == "libayatana-appindicator3-1"),
            "deb depends {deps:?} lack libayatana-appindicator3-1"
        );
    }

    #[test]
    fn rpm_depends_name_webkitgtk_4_1_and_ayatana_appindicator3() {
        let deps = strings_at(&conf(), "/bundle/linux/rpm/depends");
        assert!(
            deps.iter().any(|d| d == "webkit2gtk4.1"),
            "rpm depends {deps:?} lack webkit2gtk4.1"
        );
        assert!(
            deps.iter().any(|d| d == "libayatana-appindicator-gtk3"),
            "rpm depends {deps:?} lack libayatana-appindicator-gtk3"
        );
    }

    #[test]
    fn bundle_targets_are_exactly_the_shipped_packages() {
        let c = conf();
        assert_eq!(at(&c, "/bundle/active"), &Value::Bool(true));
        assert_eq!(
            strings_at(&c, "/bundle/targets"),
            ["nsis", "app", "dmg", "deb", "rpm", "appimage"]
        );
    }

    #[test]
    fn nsis_install_mode_is_both_and_webview2_uses_the_bootstrapper() {
        let c = conf();
        assert_eq!(string_at(&c, "/bundle/windows/nsis/installMode"), "both");
        assert_eq!(
            string_at(&c, "/bundle/windows/webviewInstallMode/type"),
            "downloadBootstrapper"
        );
    }

    #[test]
    fn macos_hardened_runtime_entitlements_and_ad_hoc_identity() {
        let c = conf();
        assert_eq!(at(&c, "/bundle/macOS/hardenedRuntime"), &Value::Bool(true));
        assert_eq!(string_at(&c, "/bundle/macOS/entitlements"), "entitlements.plist");
        assert_eq!(string_at(&c, "/bundle/macOS/signingIdentity"), "-");
        assert_eq!(string_at(&c, "/bundle/macOS/minimumSystemVersion"), "13.0");
    }

    #[test]
    fn entitlements_plist_has_no_get_task_allow() {
        let plist = read_text("entitlements.plist");
        assert!(plist.contains("<plist"), "entitlements.plist is not a plist");
        assert!(plist.contains("<dict"), "entitlements.plist has no top-level dict");
        assert!(
            !plist.contains("com.apple.security.get-task-allow"),
            "entitlements.plist must not grant com.apple.security.get-task-allow (§2.5)"
        );
    }

    #[test]
    fn deb_and_rpm_render_the_atlas_duck_launcher_template() {
        let c = conf();
        assert_eq!(string_at(&c, "/bundle/linux/deb/desktopTemplate"), LAUNCHER_TEMPLATE);
        assert_eq!(string_at(&c, "/bundle/linux/rpm/desktopTemplate"), LAUNCHER_TEMPLATE);
    }

    #[test]
    fn launcher_starts_atlas_duck_app_without_arguments() {
        let text = read_text(LAUNCHER_TEMPLATE);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.first().copied(), Some("[Desktop Entry]"));
        let exec: Vec<&str> = lines.iter().copied().filter(|l| l.starts_with("Exec=")).collect();
        assert_eq!(exec, ["Exec=atlas-duck-app"], "Exec must start the app with no arguments");
        assert!(lines.contains(&"Type=Application"));
        assert!(!lines.contains(&"NoDisplay=true"), "the launcher must be visible");
        assert!(
            !text.contains("{{"),
            "the template is literal, so the shipped file equals the repository file"
        );
    }

    #[test]
    fn no_second_launcher_is_installed_through_files() {
        // The bundler already generates the one launcher from `desktopTemplate`. A `files` entry
        // under /usr/share/applications would ship a second one (§12.2: one launcher).
        let c = conf();
        for kind in ["deb", "rpm", "appimage"] {
            let Some(files) = c.pointer(&format!("/bundle/linux/{kind}/files")) else {
                continue;
            };
            let files = files
                .as_object()
                .unwrap_or_else(|| panic!("bundle.linux.{kind}.files is not an object"));
            for dest in files.keys() {
                assert!(
                    !dest.contains("applications") && !dest.ends_with(".desktop"),
                    "bundle.linux.{kind}.files installs {dest}, a second launcher"
                );
            }
        }
    }

    #[test]
    fn linux_product_name_makes_the_generated_launcher_atlas_duck_desktop() {
        // tauri-bundler 2.10.1 names the launcher `<productName>.desktop`
        // (bundle/linux/freedesktop/mod.rs), so only a Linux productName of
        // `atlas-duck` yields /usr/share/applications/atlas-duck.desktop (§12.2).
        let linux = json("tauri.linux.conf.json");
        let obj = linux.as_object().expect("tauri.linux.conf.json is an object");
        let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(keys, ["productName"], "the Linux override changes nothing else");
        assert_eq!(obj["productName"], LINUX_PRODUCT_NAME);
        assert_eq!(format!("{LINUX_PRODUCT_NAME}.desktop"), LAUNCHER_FILE_NAME);
    }

    #[test]
    fn windows_keeps_the_base_product_name() {
        // A Windows override of productName to "atlas-duck" could move the per-user NSIS dir
        // (%LOCALAPPDATA%\Programs\<productName> for installMode both, %LOCALAPPDATA%\<productName>
        // for single-mode currentUser) onto the data dir %LOCALAPPDATA%\atlas-duck.
        for name in ["tauri.windows.conf.json", "tauri.windows.conf.json5", "Tauri.windows.toml"] {
            assert!(!src_tauri().join(name).exists(), "{name} must not exist");
        }
        let product = string_at(&conf(), "/productName");
        assert!(!product.eq_ignore_ascii_case("atlas-duck"), "base productName is {product}");
        assert_eq!(string_at(&conf(), "/mainBinaryName"), "atlas-duck-app");
    }

    #[test]
    fn bundle_icons_exist_and_include_square_pngs() {
        let icons = strings_at(&conf(), "/bundle/icon");
        for required in [
            "icons/32x32.png",
            "icons/128x128.png",
            "icons/128x128@2x.png",
            "icons/icon.icns",
            "icons/icon.ico",
        ] {
            assert!(icons.iter().any(|i| i == required), "bundle.icon lacks {required}");
        }
        for icon in &icons {
            let bytes = read_bytes(icon);
            if icon.ends_with(".png") {
                let (w, h) = png_dimensions(&bytes)
                    .unwrap_or_else(|| panic!("{icon} is not a PNG"));
                assert_eq!(w, h, "{icon} is {w}x{h}; the AppImage bundler needs square icons");
            } else if icon.ends_with(".icns") {
                assert_eq!(&bytes[..4], b"icns", "{icon} is not an icns file");
            } else if icon.ends_with(".ico") {
                assert_eq!(&bytes[..4], &[0u8, 0, 1, 0], "{icon} is not an ico file");
            } else {
                panic!("unexpected icon type {icon}");
            }
        }
    }
}
