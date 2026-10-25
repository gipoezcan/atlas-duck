//! Bundle identity (§12.1, §12.5): the identifier and the product name differ from the data-dir
//! folder name `atlas-duck` (§7.7), the main binary is `atlas-duck-app`, the config declares no
//! windows and one capability per window label, with the M6 frontend lockdown (§2.4, §6.4, §10.3).

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

/// The seven window labels (C.10 + Δ1, PD-72), one capability file each (§10.3).
const WINDOW_LABELS: [&str; 7] = [
    "approvals",
    "settings",
    "audit",
    "running_scripts",
    "onboarding",
    "credential",
    "setup",
];

/// M6 T4 (§2.4, §6.4, §10.3): Rust builds every window (T6), so the config declares none; the
/// capability list is explicit (an empty list would mean "every file in `capabilities/`"), each
/// file grants its own window only, and the frontend lockdown is on.
#[test]
fn capabilities_one_per_window_and_no_static_windows() {
    let c = conf();
    assert_eq!(c["app"]["windows"], Value::Array(vec![]));
    let security = &c["app"]["security"];
    assert_eq!(security["capabilities"], serde_json::json!(WINDOW_LABELS));
    assert_eq!(security["freezePrototype"], Value::Bool(true));
    assert_eq!(
        security["pattern"],
        serde_json::json!({"use": "isolation", "options": {"dir": "../isolation"}})
    );
    let isolation = manifest_dir().join("../isolation/index.html");
    let html = std::fs::read_to_string(&isolation).expect("read app/isolation/index.html");
    assert!(html.contains("__TAURI_ISOLATION_HOOK__"));
    // The CSP: one policy for every platform (no overlay overrides it); `frame-src` carries the
    // placeholder `csp::patch_context` replaces with the build's isolation origin (§6.4, V34;
    // `ci/check-csp.mjs` compares the whole text).
    let csp = security["csp"]
        .as_str()
        .expect("app.security.csp is a string");
    assert!(
        csp.contains(&format!(
            "frame-src 'self' {}",
            atlas_duck_app_lib::csp::ISOLATION_ORIGIN_PLACEHOLDER
        )),
        "{csp}"
    );
    assert!(!csp.contains("unsafe-"), "{csp}");
    assert!(security.get("devCsp").is_none());
    for platform in ["windows", "macos", "linux"] {
        let overlay = manifest_dir().join(format!("tauri.{platform}.conf.json"));
        if let Ok(text) = std::fs::read_to_string(&overlay) {
            let overlay: Value = serde_json::from_str(&text).expect("overlay is JSON");
            assert!(
                overlay.pointer("/app/security").is_none(),
                "tauri.{platform}.conf.json overrides app.security"
            );
        }
    }

    let mut files: Vec<String> = std::fs::read_dir(manifest_dir().join("capabilities"))
        .expect("read capabilities/")
        .map(|e| {
            e.expect("capabilities/ entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    files.sort();
    let mut expected: Vec<String> = WINDOW_LABELS.iter().map(|l| format!("{l}.json")).collect();
    expected.sort();
    assert_eq!(
        files, expected,
        "exactly one capability file per window label"
    );
    for label in WINDOW_LABELS {
        let path = manifest_dir()
            .join("capabilities")
            .join(format!("{label}.json"));
        let text = std::fs::read_to_string(&path).expect("read capability file");
        let cap: Value = serde_json::from_str(&text).expect("capability file is JSON");
        assert_eq!(cap["identifier"], label);
        assert_eq!(cap["windows"], serde_json::json!([label]), "{label}");
        for key in ["webviews", "remote", "local", "platforms"] {
            assert!(cap.get(key).is_none(), "{label}.json sets {key}");
        }
        let permissions = cap["permissions"].as_array().expect("permissions array");
        for p in permissions {
            let p = p.as_str().expect("plain permission identifier");
            assert!(
                p.starts_with("allow-")
                    || p == "core:event:allow-listen"
                    || p == "core:event:allow-unlisten",
                "{label}.json grants {p}"
            );
        }
    }
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
        assert_eq!(
            string_at(&c, "/bundle/macOS/entitlements"),
            "entitlements.plist"
        );
        assert_eq!(string_at(&c, "/bundle/macOS/signingIdentity"), "-");
        assert_eq!(string_at(&c, "/bundle/macOS/minimumSystemVersion"), "13.0");
    }

    #[test]
    fn entitlements_plist_has_no_get_task_allow() {
        let plist = read_text("entitlements.plist");
        assert!(
            plist.contains("<plist"),
            "entitlements.plist is not a plist"
        );
        assert!(
            plist.contains("<dict"),
            "entitlements.plist has no top-level dict"
        );
        assert!(
            !plist.contains("com.apple.security.get-task-allow"),
            "entitlements.plist must not grant com.apple.security.get-task-allow (§2.5)"
        );
    }

    #[test]
    fn deb_and_rpm_render_the_atlas_duck_launcher_template() {
        let c = conf();
        assert_eq!(
            string_at(&c, "/bundle/linux/deb/desktopTemplate"),
            LAUNCHER_TEMPLATE
        );
        assert_eq!(
            string_at(&c, "/bundle/linux/rpm/desktopTemplate"),
            LAUNCHER_TEMPLATE
        );
    }

    #[test]
    fn launcher_starts_atlas_duck_app_without_arguments() {
        let text = read_text(LAUNCHER_TEMPLATE);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.first().copied(), Some("[Desktop Entry]"));
        let exec: Vec<&str> = lines
            .iter()
            .copied()
            .filter(|l| l.starts_with("Exec="))
            .collect();
        assert_eq!(
            exec,
            ["Exec=atlas-duck-app"],
            "Exec must start the app with no arguments"
        );
        assert!(lines.contains(&"Type=Application"));
        assert!(
            !lines.contains(&"NoDisplay=true"),
            "the launcher must be visible"
        );
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
        let obj = linux
            .as_object()
            .expect("tauri.linux.conf.json is an object");
        let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["productName"],
            "the Linux override changes nothing else"
        );
        assert_eq!(obj["productName"], LINUX_PRODUCT_NAME);
        assert_eq!(format!("{LINUX_PRODUCT_NAME}.desktop"), LAUNCHER_FILE_NAME);
    }

    #[test]
    fn windows_keeps_the_base_product_name() {
        // A Windows override of productName to "atlas-duck" could move the per-user NSIS dir
        // (%LOCALAPPDATA%\Programs\<productName> for installMode both, %LOCALAPPDATA%\<productName>
        // for single-mode currentUser) onto the data dir %LOCALAPPDATA%\atlas-duck.
        for name in [
            "tauri.windows.conf.json",
            "tauri.windows.conf.json5",
            "Tauri.windows.toml",
        ] {
            assert!(!src_tauri().join(name).exists(), "{name} must not exist");
        }
        let product = string_at(&conf(), "/productName");
        assert!(
            !product.eq_ignore_ascii_case("atlas-duck"),
            "base productName is {product}"
        );
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
            assert!(
                icons.iter().any(|i| i == required),
                "bundle.icon lacks {required}"
            );
        }
        for icon in &icons {
            let bytes = read_bytes(icon);
            if icon.ends_with(".png") {
                let (w, h) =
                    png_dimensions(&bytes).unwrap_or_else(|| panic!("{icon} is not a PNG"));
                assert_eq!(
                    w, h,
                    "{icon} is {w}x{h}; the AppImage bundler needs square icons"
                );
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

// T21: installer hook and install-probe wiring (spec §9.4 Windows, §12.2, §13 scripts-enabled
// matrix). Appended to the file T12 created; T12's own tests live in `mod t12`. These tests read
// the files from disk at run time, so a missing file is a readable test failure.
mod t21 {
    use serde_json::Value;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    const HOOKS_PATH: &str = "windows/hooks.nsh";
    const WORKER_EXE: &str = "atlas-duck-sandbox.exe";
    const SID_ALL_APP_PACKAGES: &str = "S-1-15-2-1";
    const SID_ALL_RESTRICTED_APP_PACKAGES: &str = "S-1-15-2-2";
    const DATA_DIR_NAME: &str = "atlas-duck";

    fn src_tauri() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// `app/src-tauri` -> repository root.
    fn repo_root() -> PathBuf {
        src_tauri().join("..").join("..")
    }

    fn read_text(path: &Path) -> String {
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
    }

    fn conf() -> Value {
        let text = read_text(&src_tauri().join("tauri.conf.json"));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("tauri.conf.json is not JSON: {e}"))
    }

    fn hooks() -> String {
        read_text(&src_tauri().join(HOOKS_PATH))
    }

    /// The hook file without NSIS comment lines (`;` or `#` first), so a comment that names a
    /// SID or a macro cannot satisfy a test.
    fn hooks_code() -> String {
        hooks()
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with(';') && !t.starts_with('#')
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn tauri_conf_references_the_windows_hooks_file() {
        let c = conf();
        let hooks_ref = c
            .pointer("/bundle/windows/nsis/installerHooks")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("tauri.conf.json has no bundle.windows.nsis.installerHooks"));
        assert_eq!(hooks_ref, HOOKS_PATH);
        assert!(
            src_tauri().join(hooks_ref).is_file(),
            "{hooks_ref} does not exist next to tauri.conf.json"
        );
        // T12's install mode stays: both NSIS modes need the hook (§12.2).
        assert_eq!(
            c.pointer("/bundle/windows/nsis/installMode")
                .and_then(Value::as_str),
            Some("both")
        );
    }

    #[test]
    fn hooks_define_the_post_install_macro_with_both_sids_read_execute() {
        let code = hooks_code();
        assert!(
            code.contains("!macro NSIS_HOOK_POSTINSTALL"),
            "hooks.nsh does not define NSIS_HOOK_POSTINSTALL"
        );
        for sid in [SID_ALL_APP_PACKAGES, SID_ALL_RESTRICTED_APP_PACKAGES] {
            let grant = format!("*{sid}:(RX)");
            assert!(code.contains(&grant), "hooks.nsh has no grant {grant}");
        }
    }

    #[test]
    fn hooks_name_exactly_the_two_package_sids_and_only_read_execute() {
        let code = hooks_code();
        // every SID literal in the code
        let mut sids = BTreeSet::new();
        let mut rest = code.as_str();
        while let Some(at) = rest.find("S-1-") {
            let tail = &rest[at..];
            let end = tail
                .find(|c: char| !(c.is_ascii_digit() || c == '-' || c == 'S'))
                .unwrap_or(tail.len());
            sids.insert(tail[..end].to_owned());
            rest = &tail[end..];
        }
        let expected: BTreeSet<String> = [SID_ALL_APP_PACKAGES, SID_ALL_RESTRICTED_APP_PACKAGES]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(
            sids, expected,
            "hooks.nsh must name exactly the two (L)PAC group SIDs"
        );
        // every permission group is (RX): never write, modify, full or delete
        let mut rest = code.as_str();
        let mut groups = 0;
        while let Some(at) = rest.find(":(") {
            let tail = &rest[at + 1..];
            assert!(
                tail.starts_with("(RX)"),
                "hooks.nsh grants something other than (RX): {tail:.12}"
            );
            groups += 1;
            rest = &tail[4..];
        }
        assert_eq!(groups, 2, "expected one (RX) group per SID");
    }

    #[test]
    fn hooks_cover_the_worker_and_the_dlls_next_to_it() {
        let code = hooks_code();
        assert!(
            code.contains(WORKER_EXE),
            "hooks.nsh does not name {WORKER_EXE}"
        );
        assert!(
            code.contains("*.dll"),
            "hooks.nsh does not walk the DLLs in $INSTDIR"
        );
        assert!(
            code.contains("$INSTDIR"),
            "hooks.nsh must act on the install directory"
        );
    }

    #[test]
    fn hooks_define_the_drain_and_uninstall_macros() {
        // M10 Task 23 (§12.2, PD-172): the upgrade drain (PREINSTALL, PREUNINSTALL) and the
        // uninstall rules (PREUNINSTALL forces the app-data option off, POSTUNINSTALL is an
        // explicit no-op) live in hooks.nsh; the M1 rule that they were absent is retired.
        let code = hooks_code();
        for macro_name in [
            "NSIS_HOOK_PREINSTALL",
            "NSIS_HOOK_PREUNINSTALL",
            "NSIS_HOOK_POSTUNINSTALL",
        ] {
            assert!(
                code.contains(&format!("!macro {macro_name}")),
                "hooks.nsh does not define {macro_name} (M10 Task 23)"
            );
        }
    }

    #[test]
    fn hooks_worker_name_is_the_wer_excluded_sandbox_exe() {
        // T09 excludes the same executable names from WER; the hook and the exclusion must
        // talk about the one worker binary.
        assert!(
            atlas_duck_app_lib::startup::crash::WER_EXCLUDED_EXES.contains(&WORKER_EXE),
            "WER_EXCLUDED_EXES {:?} does not list {WORKER_EXE}",
            atlas_duck_app_lib::startup::crash::WER_EXCLUDED_EXES
        );
    }

    #[test]
    fn per_user_install_dir_never_lands_on_the_data_dir() {
        // %LOCALAPPDATA%\atlas-duck is the data dir and the pinned-file dir (§7.7). The NSIS
        // per-user install dir is %LOCALAPPDATA%\Programs\<productName> (installMode "both",
        // MultiUser.nsh) or %LOCALAPPDATA%\<productName> (installMode "currentUser"); neither
        // may resolve to the data dir, whichever the bundler picks.
        let c = conf();
        let product = c
            .pointer("/productName")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("tauri.conf.json has no productName"));
        let identifier = c
            .pointer("/identifier")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("tauri.conf.json has no identifier"));
        assert!(
            !product.eq_ignore_ascii_case(DATA_DIR_NAME),
            "productName {product} equals the data dir folder name"
        );
        assert!(
            !identifier.eq_ignore_ascii_case(DATA_DIR_NAME),
            "identifier {identifier} equals the data dir folder name"
        );
        for candidate in [format!("Programs\\{product}"), product.to_owned()] {
            assert!(
                !candidate.eq_ignore_ascii_case(DATA_DIR_NAME),
                "per-user install dir %LOCALAPPDATA%\\{candidate} equals the data dir"
            );
        }
    }

    fn workflow() -> String {
        read_text(
            &repo_root()
                .join(".github")
                .join("workflows")
                .join("install-probes.yml"),
        )
    }

    fn script(name: &str) -> String {
        read_text(&repo_root().join("ci").join(name))
    }

    /// The seven probe jobs (T21), in order. M10 Task 27 adds one `install-test-<probe>` job per
    /// probe job after them, each `needs:` its probe job.
    const PROBE_JOBS: [&str; 7] = [
        "windows-per-user",
        "windows-per-machine",
        "macos-arm64",
        "macos-x86_64-rosetta",
        "ubuntu-deb",
        "ubuntu-appimage",
        "fedora-rpm",
    ];
    /// Every job of install-probes.yml: the probes and the install tests.
    const ALL_JOBS: usize = 2 * PROBE_JOBS.len();

    fn is_job_key(l: &str) -> bool {
        l.starts_with("  ") && !l.starts_with("   ") && l.trim_end().ends_with(':')
    }

    fn job_ids(text: &str) -> Vec<&str> {
        text.lines()
            .skip_while(|l| *l != "jobs:")
            .skip(1)
            .filter(|l| is_job_key(l))
            .map(|l| l.trim().trim_end_matches(':'))
            .collect()
    }

    /// The lines of job `id` (after its key line, up to the next job key).
    fn job_block<'a>(text: &'a str, id: &str) -> Vec<&'a str> {
        let key = format!("  {id}:");
        text.lines()
            .skip_while(|l| *l != key)
            .skip(1)
            .take_while(|l| !is_job_key(l))
            .collect()
    }

    #[test]
    fn install_probes_workflow_defines_the_seven_jobs_in_order() {
        let text = workflow();
        let mut want: Vec<String> = PROBE_JOBS.iter().map(|j| (*j).to_owned()).collect();
        want.extend(PROBE_JOBS.iter().map(|j| format!("install-test-{j}")));
        assert_eq!(job_ids(&text), want);
        // M10 Task 27: each install test runs after (needs) the probe job of its package.
        for probe in PROBE_JOBS {
            let block = job_block(&text, &format!("install-test-{probe}"));
            assert!(
                block.iter().any(|l| l.trim() == format!("needs: {probe}")),
                "install-test-{probe} does not need {probe}"
            );
        }
    }

    #[test]
    fn install_probes_workflow_consumes_the_bundle_workflow_artifacts() {
        let text = workflow();
        assert!(
            text.contains("workflows: [bundle]"),
            "the workflow must follow the bundle workflow"
        );
        for artifact in [
            "bundle-x86_64-pc-windows-msvc",
            "bundle-aarch64-apple-darwin",
            "bundle-x86_64-apple-darwin",
            "bundle-x86_64-unknown-linux-gnu",
        ] {
            assert!(
                text.contains(&format!("name: {artifact}")),
                "no download of {artifact}"
            );
        }
        assert!(
            text.contains("run-id:"),
            "artifacts of another run need run-id"
        );
        assert!(
            text.contains("actions: read"),
            "downloading another run's artifacts needs actions: read"
        );
    }

    #[test]
    fn install_probes_workflow_runs_each_script_in_the_right_mode() {
        let text = workflow();
        for command in [
            "./ci/install-probe-windows.ps1 -Mode CurrentUser -InstallerDir dist",
            "./ci/install-probe-windows.ps1 -Mode AllUsers -InstallerDir dist",
            "/bin/bash ci/install-probe-macos.sh dist arm64",
            "/bin/bash ci/install-probe-macos.sh dist x86_64",
            "bash ci/install-probe-linux.sh deb dist",
            "bash ci/install-probe-linux.sh appimage dist",
            "bash ci/install-probe-linux.sh rpm dist",
        ] {
            assert!(
                text.contains(command),
                "the workflow never runs `{command}`"
            );
        }
        // the Fedora job is a container, and the fixture refuses to run without CI=true
        assert!(text.contains("fedora:40"));
        assert!(text.contains("--env CI=true"));
    }

    #[test]
    fn install_probes_workflow_checks_out_the_bundled_commit_without_credentials_or_secrets() {
        // C17: workflow_run executes the PR head's scripts with a token. The checkout is the
        // bundled commit (A39: a manual run names it), credentials are not persisted, no secret
        // is used, forks are skipped and the token is read-only.
        let text = workflow();
        let checkouts = text.matches("uses: actions/checkout@").count();
        assert_eq!(checkouts, ALL_JOBS, "one checkout per job");
        assert_eq!(
            text.matches("ref: ${{ github.event.workflow_run.head_sha || inputs.bundle_sha }}")
                .count(),
            ALL_JOBS,
            "every checkout must be pinned to the bundle run's head sha"
        );
        assert_eq!(text.matches("persist-credentials: false").count(), ALL_JOBS);
        // per job, not only in total (M10 Task 27: the install tests too)
        for id in job_ids(&text) {
            let block = job_block(&text, id).join(
                "
",
            );
            assert_eq!(
                block.matches("uses: actions/checkout@").count(),
                1,
                "{id}: one checkout"
            );
            assert!(
                block.contains(
                    "ref: ${{ github.event.workflow_run.head_sha || inputs.bundle_sha }}"
                ),
                "{id}: checkout not pinned to the bundled commit"
            );
            assert!(
                block.contains("persist-credentials: false"),
                "{id}: credentials persisted"
            );
            assert!(
                block.contains("- name: Cross-check bundle_run_id and bundle_sha"),
                "{id}: no cross-check of the manual inputs"
            );
            assert!(!block.contains("secrets."), "{id} uses a secret");
        }
        assert!(
            text.contains("bundle_sha:"),
            "a manual run must name the bundled commit"
        );
        assert!(!text.contains("secrets."), "the probes need no secret");
        assert!(!text.contains("contents: write") && !text.contains("actions: write"));
        assert!(
            text.contains(
                "github.event.workflow_run.head_repository.full_name == github.repository"
            ),
            "a workflow_run from a fork must not execute here"
        );
    }

    #[test]
    fn install_probes_workflow_cross_checks_the_manual_inputs_against_the_bundle_run() {
        // A manual run names bundle_run_id and bundle_sha separately; every job checks the pair
        // against the API before it checks out or downloads anything.
        let text = workflow();
        assert_eq!(
            text.matches("- name: Cross-check bundle_run_id and bundle_sha")
                .count(),
            ALL_JOBS,
            "one cross-check per job"
        );
        for needle in [
            "actions/runs/$BUNDLE_RUN_ID",
            "BUNDLE_RUN_ID: ${{ inputs.bundle_run_id }}",
            "BUNDLE_SHA: ${{ inputs.bundle_sha }}",
            "GH_TOKEN: ${{ github.token }}",
            "=~ ^[0-9]+$",
            "=~ ^[0-9a-f]{40}$",
            "\"$name\" != \"bundle\"",
            "\"$conclusion\" != \"success\"",
            "\"$head_sha\" != \"$BUNDLE_SHA\"",
        ] {
            assert_eq!(
                text.matches(needle).count(),
                ALL_JOBS,
                "{needle} must appear once per job"
            );
        }
        // the inputs reach the shell through env only, and the check never runs for workflow_run
        let run_blocks: String = text
            .lines()
            .filter(|l| l.contains("inputs.") && !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        for line in run_blocks.lines() {
            assert!(
                line.contains("BUNDLE_RUN_ID: ${{")
                    || line.contains("BUNDLE_SHA: ${{")
                    || line.contains("ref: ${{")
                    || line.contains("run-id: ${{")
                    || line.contains("bundle_sha:")
                    || line.contains("bundle_run_id:")
                    // M10 Task 26 (workflow_call): a job-level `if:` compares the input inside an
                    // Actions expression; nothing is interpolated into a shell there.
                    || (line.trim_start().starts_with("if: ")
                        && !line.contains("${{")
                        && !line.contains("run:")),
                "an input is interpolated outside env, ref, run-id or a job if: {line}"
            );
        }
        assert_eq!(
            text.matches("if: github.event_name == 'workflow_dispatch'\n        shell: bash")
                .count(),
            ALL_JOBS
        );
    }

    #[test]
    fn probe_scripts_poll_the_diag_log_for_the_sandbox_probe_line() {
        for name in [
            "install-probe-windows.ps1",
            "install-probe-macos.sh",
            "install-probe-linux.sh",
        ] {
            let text = script(name);
            assert!(
                text.contains("sandbox_probe"),
                "{name} never looks for event=sandbox_probe"
            );
            assert!(text.contains("diag.log"), "{name} never reads diag.log");
            assert!(text.contains("floor"), "{name} never checks the floor");
            assert!(text.contains("60"), "{name} has no 60 s polling budget");
            assert!(
                text.contains("pinned-fixture"),
                "{name} does not use the CI pinned fixture"
            );
        }
    }

    #[test]
    fn windows_script_covers_both_install_modes_the_aces_and_the_wer_exclusions() {
        let text = script("install-probe-windows.ps1");
        for needle in [
            "'CurrentUser'",
            "'AllUsers'",
            "'/S'",
            SID_ALL_APP_PACKAGES,
            SID_ALL_RESTRICTED_APP_PACKAGES,
            "'reapplied'",
            "ExcludedApplications",
            "atlas-duck-app.exe",
            WORKER_EXE,
        ] {
            assert!(
                text.contains(needle),
                "install-probe-windows.ps1 lacks {needle}"
            );
        }
        // the ACE check must not depend on localized icacls output
        assert!(text.contains("SecurityIdentifier"));
    }

    #[test]
    fn windows_script_asserts_the_floor_is_met() {
        // The Windows floor is met (host-scored LPAC controls, or the plain AppContainer
        // fallback): the leg asserts floor=met failed=none next to what the installer owns
        // (ACEs, location, ace=, WER), and records the mode and the control.
        let text = script("install-probe-windows.ps1");
        assert!(
            !text.contains("-RecordFloor"),
            "the Windows leg must not skip the floor assertion"
        );
        assert!(text.contains("-ne 'met'"), "floor=met is not asserted");
        assert!(text.contains("-ne 'none'"), "failed=none is not asserted");
        assert!(
            text.contains("-ne 'lpac'") && text.contains("lpac_failed"),
            "the LPAC mode is not pinned"
        );
        assert!(text.contains("control_ok"));
        assert!(text.contains("PROBE_RECORD"));
        assert!(text.contains("EVIDENCE_JSON"));
    }

    #[test]
    fn macos_script_never_treats_a_bare_floor_met_as_proof() {
        // T18 ruling: floor=met proves the task-port probe only with an informative unconfined
        // control; otherwise the leg reports FLOOR_INCONCLUSIVE.
        let text = script("install-probe-macos.sh");
        for needle in [
            "task_for_pid_informative",
            "FLOOR_INCONCLUSIVE",
            "classify_verdict",
            "unconfined_kr",
        ] {
            assert!(
                text.contains(needle),
                "install-probe-macos.sh lacks {needle}"
            );
        }
    }
}
