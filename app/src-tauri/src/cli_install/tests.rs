//! Tests over every platform's layout: what `resolve` decides, and that `uninstall` removes exactly
//! what `install` wrote. Per-platform behaviour is tested in each module.

use std::path::{Path, PathBuf};

use serde_json::json;

use super::fake::{FakeOps, State};
use super::*;

fn inputs(platform: Platform) -> Inputs {
    Inputs {
        platform,
        home: PathBuf::from("/home/u"),
        cli_toml: PathBuf::from("/home/u/.config/atlas-duck/cli-h.toml"),
        current_exe: PathBuf::from("/usr/bin/atlas-duck-app"),
        appimage: None,
        appimage_is_file: false,
        appdir: None,
    }
}

/// A macOS run from an installed app bundle.
fn bundle_inputs() -> Inputs {
    Inputs {
        current_exe: PathBuf::from("/Applications/Atlas Duck.app/Contents/MacOS/atlas-duck-app"),
        ..inputs(Platform::Macos)
    }
}

/// An AppImage run: `$APPIMAGE` is the file, the running binary is inside the mount.
fn image(p: &str) -> Inputs {
    Inputs {
        current_exe: PathBuf::from("/tmp/.mount_atlasXYZ123/usr/bin/atlas-duck-app"),
        appimage: Some(PathBuf::from(p)),
        appimage_is_file: true,
        appdir: Some(PathBuf::from("/tmp/.mount_atlasXYZ123")),
        ..inputs(Platform::Linux)
    }
}

/// §12.3: `cli.toml`'s `app_path`, the wrapper and the launcher never name `current_exe` of an
/// AppImage or a `/tmp/.mount_*` path: `$APPIMAGE` is recorded, and with no stable file nothing is
/// resolved (so nothing is written).
#[test]
fn cli_toml_never_tmp_mount() {
    // An AppImage run: `$APPIMAGE` is the file, the running binary is inside the mount.
    let mounted = Inputs {
        current_exe: PathBuf::from("/tmp/.mount_atlasXYZ123/usr/bin/atlas-duck-app"),
        ..image("/home/u/Apps/Atlas Duck.AppImage")
    };
    let layout = Layout::resolve(&mounted).expect("resolve");
    assert_eq!(
        layout.app_path,
        PathBuf::from("/home/u/Apps/Atlas Duck.AppImage")
    );
    assert!(matches!(layout.kind, Kind::AppImage { .. }));
    assert!(!under_mount(&layout.app_path));
    assert_eq!(layout.cli_toml, mounted.cli_toml);

    // No `$APPIMAGE` (unset, relative, or not a file) and the binary in the mount: no stable path.
    let in_mount = PathBuf::from("/tmp/.mount_atlasXYZ123/usr/bin/atlas-duck-app");
    for appimage in [
        None,
        Some(PathBuf::from("relative/Atlas.AppImage")),
        Some(PathBuf::from("/home/u/Apps/gone.AppImage")),
    ] {
        let i = Inputs {
            current_exe: in_mount.clone(),
            appimage,
            appimage_is_file: false,
            ..inputs(Platform::Linux)
        };
        assert_eq!(
            Layout::resolve(&i),
            Err(InstallError::NoStablePath),
            "{i:?}"
        );
    }
    // `$APPIMAGE` itself inside a mount is no stable path either.
    assert_eq!(
        Layout::resolve(&image("/tmp/.mount_abc/Atlas.AppImage")),
        Err(InstallError::NoStablePath)
    );
    // A relative `current_exe` is no stable path.
    let relative = Inputs {
        current_exe: PathBuf::from("atlas-duck-app"),
        ..inputs(Platform::Linux)
    };
    assert_eq!(Layout::resolve(&relative), Err(InstallError::NoStablePath));

    // Whatever resolves is never under a mount.
    for i in [
        inputs(Platform::Linux),
        image("/home/u/Apps/a.AppImage"),
        bundle_inputs(),
    ] {
        let l = Layout::resolve(&i).expect("resolve");
        assert!(!under_mount(&l.app_path), "{l:?}");
    }
    assert!(under_mount(Path::new("/tmp/.mount_x/usr/bin/a")));
    assert!(!under_mount(Path::new("/home/u/.mounts/a")));
}

/// `$APPIMAGE` is inherited by every child of an AppImage (a terminal or editor shipped as one).
/// It counts only when this process runs from an AppImage: the binary under `$APPDIR` or under a
/// `.mount_*` point. A deb/rpm install started from such a terminal stays `Packaged`; the wrapper
/// would otherwise `exec` the other AppImage and shadow the packaged CLI.
#[test]
fn a_leaked_appimage_variable_does_not_make_a_deb_an_appimage() {
    let leaked = Inputs {
        appimage: Some(PathBuf::from("/home/u/Cursor.AppImage")),
        appimage_is_file: true,
        appdir: Some(PathBuf::from("/tmp/.mount_CursorQ1w2E3")),
        ..inputs(Platform::Linux)
    };
    let layout = Layout::resolve(&leaked).expect("deb");
    assert_eq!(layout.kind, Kind::Packaged);
    assert_eq!(layout.app_path, PathBuf::from("/usr/bin/atlas-duck-app"));
    let ops = FakeOps::new();
    assert!(install(&ops, &layout).expect("install").changed.is_empty());
    assert_eq!(ops.state(), State::default(), "no wrapper, no launcher");

    // Same without `$APPDIR`, with a relative one, and with the root as `$APPDIR`.
    for appdir in [None, Some("relative/dir"), Some("/")] {
        let i = Inputs {
            appdir: appdir.map(PathBuf::from),
            ..leaked.clone()
        };
        assert_eq!(Layout::resolve(&i).expect("deb").kind, Kind::Packaged);
    }

    // The same variables are trusted when the binary does run from the AppImage: under the mount
    // (no `$APPDIR` needed) or under `$APPDIR` (an extracted AppImage).
    let mounted = Inputs {
        current_exe: PathBuf::from("/tmp/.mount_atlasXYZ123/usr/bin/atlas-duck-app"),
        appdir: None,
        ..leaked.clone()
    };
    let extracted = Inputs {
        current_exe: PathBuf::from("/opt/atlas-duck-root/usr/bin/atlas-duck-app"),
        appdir: Some(PathBuf::from("/opt/atlas-duck-root")),
        ..leaked
    };
    for i in [mounted, extracted] {
        let l = Layout::resolve(&i).expect("appimage");
        assert!(matches!(l.kind, Kind::AppImage { .. }), "{i:?}");
        assert_eq!(l.app_path, PathBuf::from("/home/u/Cursor.AppImage"));
    }
}

/// macOS: an app on a mounted disk image or under App Translocation has no stable path.
#[test]
fn a_mac_app_on_a_volume_or_translocated_has_no_stable_path() {
    for exe in [
        "/Volumes/Atlas Duck/Atlas Duck.app/Contents/MacOS/atlas-duck-app",
        "/private/var/folders/x/T/AppTranslocation/ID/d/Atlas Duck.app/Contents/MacOS/atlas-duck-app",
    ] {
        let i = Inputs {
            current_exe: PathBuf::from(exe),
            ..inputs(Platform::Macos)
        };
        assert_eq!(
            Layout::resolve(&i),
            Err(InstallError::NoStablePath),
            "{exe}"
        );
    }
}

/// A temp file a crash left behind does not decide the mode of the file that replaces the target,
/// and it does not survive. (The mode assertion runs on unix only.)
#[test]
fn a_stale_temp_file_does_not_decide_the_mode() {
    let dir = tempfile::Builder::new()
        .prefix("atlas-duck-t27f-")
        .tempdir()
        .expect("tempdir");
    let target = dir.path().join("atlas-duck");
    let stale = dir.path().join(".atlas-duck.atlas-duck-tmp");
    std::fs::write(&stale, b"stale, and longer than the new content").expect("stale");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    }
    SystemOps.write_file(&target, b"new", 0o755).expect("write");
    assert_eq!(std::fs::read(&target).expect("read"), b"new");
    assert!(!stale.exists(), "no temp file is left");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&target)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }
}

#[test]
fn each_platform_resolves_to_its_own_artifacts() {
    // deb/rpm: on PATH already.
    let deb = Layout::resolve(&inputs(Platform::Linux)).expect("deb");
    assert_eq!(deb.kind, Kind::Packaged);
    assert_eq!(deb.app_path, PathBuf::from("/usr/bin/atlas-duck-app"));

    let appimage = Layout::resolve(&image("/home/u/Apps/a.AppImage")).expect("appimage");
    match appimage.kind {
        Kind::AppImage {
            appimage,
            wrapper,
            launcher,
        } => {
            assert_eq!(appimage, PathBuf::from("/home/u/Apps/a.AppImage"));
            assert_eq!(wrapper, PathBuf::from("/home/u/.local/bin/atlas-duck"));
            assert_eq!(
                launcher,
                PathBuf::from("/home/u/.local/share/applications/atlas-duck.desktop")
            );
        }
        other => panic!("{other:?}"),
    }

    let mac = Inputs {
        current_exe: PathBuf::from("/Applications/Atlas Duck.app/Contents/MacOS/atlas-duck-app"),
        ..inputs(Platform::Macos)
    };
    match Layout::resolve(&mac).expect("mac").kind {
        Kind::Macos { cli, link } => {
            assert_eq!(
                cli,
                PathBuf::from("/Applications/Atlas Duck.app/Contents/MacOS/atlas-duck")
            );
            assert_eq!(link, PathBuf::from("/home/u/.local/bin/atlas-duck"));
        }
        other => panic!("{other:?}"),
    }

    // Backslash paths split into a directory only where `\` is a separator.
    #[cfg(windows)]
    {
        let win = Inputs {
            current_exe: PathBuf::from(r"C:\Program Files\atlas-duck\atlas-duck-app.exe"),
            ..inputs(Platform::Windows)
        };
        let l = Layout::resolve(&win).expect("win");
        assert!(!under_mount(&l.app_path));
        match l.kind {
            Kind::Windows { install_dir } => {
                assert_eq!(install_dir, PathBuf::from(r"C:\Program Files\atlas-duck"));
            }
            other => panic!("{other:?}"),
        }
        // A directory that cannot be a PATH entry is refused before anything is written.
        let bad = Inputs {
            current_exe: PathBuf::from(r"C:\a;b\atlas-duck-app.exe"),
            ..inputs(Platform::Windows)
        };
        assert_eq!(Layout::resolve(&bad), Err(InstallError::UnsafePath));
        // `%` would be expanded by the `REG_EXPAND_SZ` PATH value (M-11).
        for exe in [
            r"C:\Users\%USERNAME%\atlas-duck\atlas-duck-app.exe",
            r"C:\a%b\atlas-duck-app.exe",
        ] {
            let bad = Inputs {
                current_exe: PathBuf::from(exe),
                ..inputs(Platform::Windows)
            };
            assert_eq!(
                Layout::resolve(&bad),
                Err(InstallError::UnsafePath),
                "{exe}"
            );
        }
    }
    // An AppImage path the script cannot carry is refused at resolve time too.
    assert_eq!(
        Layout::resolve(&image("/home/u/a$b.AppImage")),
        Err(InstallError::UnsafePath)
    );
}

/// A machine with things of its own where the installer works: the user's PATH, a foreign
/// `~/.local/bin` tool, a foreign launcher, another link.
fn lived_in() -> State {
    let mut s = State {
        path: Some(r"%USERPROFILE%\bin;C:\Windows".into()),
        ..State::default()
    };
    s.files.insert(
        PathBuf::from("/home/u/.local/bin/other-tool"),
        (b"#!/bin/sh\n".to_vec(), 0o755),
    );
    s.files.insert(
        PathBuf::from("/home/u/.local/share/applications/other.desktop"),
        (b"[Desktop Entry]\n".to_vec(), 0o644),
    );
    s.links.insert(
        PathBuf::from("/home/u/.local/bin/linked"),
        PathBuf::from("/opt/tool/bin/linked"),
    );
    s
}

/// `uninstall` removes exactly what `install` wrote: everything a layout installs is gone and
/// everything else on the machine is byte for byte as before; a second `uninstall` does nothing.
#[test]
fn uninstall_removes_exactly_what_install_wrote() {
    let layouts = [
        // Built by hand: `resolve` splits `\` paths only on Windows.
        Layout {
            kind: Kind::Windows {
                install_dir: PathBuf::from(r"C:\Program Files\atlas-duck"),
            },
            app_path: PathBuf::from(r"C:\Program Files\atlas-duck\atlas-duck-app.exe"),
            cli_toml: PathBuf::from(r"C:\Users\u\AppData\Local\atlas-duck\cli.toml"),
        },
        Layout::resolve(&Inputs {
            current_exe: PathBuf::from(
                "/Applications/Atlas Duck.app/Contents/MacOS/atlas-duck-app",
            ),
            ..inputs(Platform::Macos)
        })
        .expect("macos"),
        Layout::resolve(&image("/home/u/Apps/Atlas Duck.AppImage")).expect("appimage"),
    ];
    for layout in layouts {
        let ops = FakeOps::with_state(lived_in());
        let before = ops.state();
        let wrote = install(&ops, &layout).expect("install");
        assert!(!wrote.changed.is_empty(), "{layout:?}");
        assert_ne!(ops.state(), before, "{layout:?}");
        assert!(is_installed(&ops, &layout), "{layout:?}");

        let removed = uninstall(&ops, &layout).expect("uninstall");
        assert_eq!(removed.changed, wrote.changed, "{layout:?}");
        assert_eq!(ops.state(), before, "{layout:?}");
        assert!(!is_installed(&ops, &layout), "{layout:?}");
        assert!(uninstall(&ops, &layout).expect("again").changed.is_empty());
        assert_eq!(ops.state(), before, "{layout:?}");
    }
}

#[test]
fn deb_and_rpm_are_already_on_path() {
    let layout = Layout::resolve(&inputs(Platform::Linux)).expect("deb");
    let ops = FakeOps::with_state(lived_in());
    let before = ops.state();
    assert!(is_installed(&ops, &layout));
    let report = install(&ops, &layout).expect("install");
    assert!(report.changed.is_empty());
    assert_eq!(ops.state(), before, "nothing is written");
    // A `cli.toml` left by an earlier AppImage install is the one thing removal takes.
    ops.write_cli_toml(
        &layout.cli_toml,
        &CliToml {
            app_path: Some(PathBuf::from("/home/u/Apps/old.AppImage")),
        },
    )
    .expect("leftover");
    let removed = uninstall(&ops, &layout).expect("uninstall");
    assert_eq!(removed.changed, [Artifact::CliToml]);
    assert_eq!(ops.state(), before);
}

// ---------- PD-177: marker versions, the "on your PATH" text, stale entries ----------

fn marked(line: &str) -> Vec<u8> {
    format!("#!/bin/sh\n{line}\necho rest\n").into_bytes()
}

/// A build that writes v2 still replaces and removes the v1 files an older build wrote, and
/// refuses only a version newer than its own. Anything that is not exactly `<name> v<digits>` is
/// foreign, a newer marker anywhere in the file wins, and the names do not mix.
#[test]
fn marker_v1_recognised_by_current() {
    use linux::{LAUNCHER_MARKER_NAME, MARKER_VERSION, Marker, WRAPPER_MARKER_NAME, marker_state};

    // The constants the files are written with agree with the parsed form.
    assert_eq!(
        linux::WRAPPER_MARKER,
        format!("{WRAPPER_MARKER_NAME} v{MARKER_VERSION}")
    );
    assert_eq!(
        linux::LAUNCHER_MARKER,
        format!("{LAUNCHER_MARKER_NAME} v{MARKER_VERSION}")
    );
    // What this build writes is ours to this build.
    let own = linux::wrapper_script("/home/u/a.AppImage");
    assert_eq!(
        marker_state(own.as_bytes(), WRAPPER_MARKER_NAME, MARKER_VERSION),
        Marker::Ours
    );
    let own = linux::launcher_text("/home/u/a.AppImage");
    assert_eq!(
        marker_state(own.as_bytes(), LAUNCHER_MARKER_NAME, MARKER_VERSION),
        Marker::Ours
    );

    // A later build (current = 2) knows v1 and v2 and refuses v3.
    let at = |line: &str, name: &str| marker_state(&marked(line), name, 2);
    assert_eq!(
        at("# atlas-duck-cli-wrapper v1", WRAPPER_MARKER_NAME),
        Marker::Ours
    );
    assert_eq!(
        at("# atlas-duck-cli-wrapper v2", WRAPPER_MARKER_NAME),
        Marker::Ours
    );
    assert_eq!(
        at("# atlas-duck-cli-wrapper v3", WRAPPER_MARKER_NAME),
        Marker::Newer
    );
    assert_eq!(
        at("# atlas-duck-launcher v1", LAUNCHER_MARKER_NAME),
        Marker::Ours
    );
    assert_eq!(
        at("# atlas-duck-launcher v10", LAUNCHER_MARKER_NAME),
        Marker::Newer
    );

    // Not a marker: another name, another spelling, no plain version number.
    for line in [
        "# atlas-duck-launcher v1",
        "# atlas-duck-cli-wrapper",
        "# atlas-duck-cli-wrapper v",
        "# atlas-duck-cli-wrapper v0",
        "# atlas-duck-cli-wrapper v01",
        "# atlas-duck-cli-wrapper v1x",
        "# atlas-duck-cli-wrapper v-1",
        "# atlas-duck-cli-wrapper v+1",
        "# atlas-duck-cli-wrapper v 1",
        "# atlas-duck-cli-wrapper  v1",
        "# atlas-duck-cli-wrapper v1 ",
        "#atlas-duck-cli-wrapper v1",
        "x# atlas-duck-cli-wrapper v1",
        "# atlas-duck-cli-wrapper v99999999999999999999",
        "# atlas-duck-cli-wrapper v\u{0661}",
    ] {
        assert_eq!(at(line, WRAPPER_MARKER_NAME), Marker::Foreign, "{line:?}");
    }
    assert_eq!(
        marker_state(b"", WRAPPER_MARKER_NAME, 2),
        Marker::Foreign,
        "an empty file"
    );
    assert_eq!(
        marker_state(&[0xff, 0xfe, 0x00], WRAPPER_MARKER_NAME, 2),
        Marker::Foreign,
        "bytes that are no text"
    );

    // Two markers in one file: the newer one decides.
    let both = b"#!/bin/sh\n# atlas-duck-cli-wrapper v1\n# atlas-duck-cli-wrapper v7\n";
    assert_eq!(marker_state(both, WRAPPER_MARKER_NAME, 2), Marker::Newer);
    let crlf = b"#!/bin/sh\r\n# atlas-duck-cli-wrapper v1\r\n";
    assert_eq!(
        marker_state(crlf, WRAPPER_MARKER_NAME, 2),
        Marker::Ours,
        "a file saved with CRLF line ends is still ours"
    );

    // End to end at this build's own version: a stale v1 wrapper and launcher are replaced, then
    // removed again.
    let l = Layout::resolve(&image("/home/u/Apps/a.AppImage")).expect("appimage");
    let Kind::AppImage {
        wrapper, launcher, ..
    } = l.kind.clone()
    else {
        panic!("{l:?}");
    };
    let ops = FakeOps::new();
    ops.write_file(&wrapper, &marked(linux::WRAPPER_MARKER), 0o755)
        .expect("old wrapper");
    ops.write_file(&launcher, &marked(linux::LAUNCHER_MARKER), 0o644)
        .expect("old launcher");
    let wrote = install(&ops, &l).expect("install over v1 files");
    assert_eq!(
        wrote.changed,
        [Artifact::Wrapper, Artifact::Launcher, Artifact::CliToml]
    );
    assert!(is_installed(&ops, &l));
    uninstall(&ops, &l).expect("uninstall");
    assert_eq!(ops.state(), State::default());
}

/// A wrapper or launcher whose marker is newer than this build's is refused with its own kind
/// (the page says "installed by a newer atlas-duck"), before anything is written, and `uninstall`
/// leaves it alone like any file that is not ours.
#[test]
fn newer_marker_refused_with_text() {
    let l = Layout::resolve(&image("/home/u/Apps/a.AppImage")).expect("appimage");
    let Kind::AppImage {
        wrapper, launcher, ..
    } = l.kind.clone()
    else {
        panic!("{l:?}");
    };
    let newer_wrapper = marked("# atlas-duck-cli-wrapper v2");
    let newer_launcher = marked("# atlas-duck-launcher v2");

    for (path, bytes, mode) in [
        (&wrapper, &newer_wrapper, 0o755),
        (&launcher, &newer_launcher, 0o644),
    ] {
        let ops = FakeOps::new();
        ops.write_file(path, bytes, mode).expect("newer file");
        let before = ops.state();
        assert_eq!(
            install(&ops, &l),
            Err(InstallError::NewerVersion),
            "{path:?}"
        );
        assert_eq!(
            ops.state(),
            before,
            "nothing is written, not even the other file: {path:?}"
        );
        let gone = uninstall(&ops, &l).expect("uninstall");
        assert!(gone.changed.is_empty(), "{path:?}");
        assert_eq!(ops.state(), before, "a newer file is not removed: {path:?}");
        assert!(!is_installed(&ops, &l));
    }

    // A foreign file stays `occupied`; the newer kind is only for a marker that is ours-but-newer.
    let ops = FakeOps::new();
    ops.write_file(
        &wrapper,
        b"#!/bin/sh\n# atlas-duck-cli-wrapper v1x\n",
        0o755,
    )
    .expect("foreign");
    assert_eq!(install(&ops, &l), Err(InstallError::Occupied));

    // The kind is a fixed word and the page has fixed text for it.
    assert_eq!(InstallError::NewerVersion.kind(), "newer_version");
    let strings = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ui/src/shared/strings.ts"),
    )
    .expect("strings.ts");
    assert!(strings.contains("newer_version:"), "cli_errors key");
    assert!(strings.contains("installed by a newer atlas-duck"));
}

/// `~/.local/bin` counts as "on your PATH" only when it is an absolute entry of the user's PATH
/// (compared as a path, a trailing separator does not matter); the layouts that do not use that
/// folder have no such answer.
#[test]
fn path_text_reflects_user_path() {
    let home = Path::new("/home/u");
    let dir = home.join(".local").join("bin");
    let join = |parts: &[&str]| std::env::join_paths(parts).expect("join");
    assert!(local_bin_on_path(
        Some(&join(&["/usr/bin", "/home/u/.local/bin"])),
        &dir
    ));
    assert!(local_bin_on_path(
        Some(&join(&["/home/u/.local/bin/", "/usr/bin"])),
        &dir
    ));
    for not in [
        None,
        Some(join(&[])),
        Some(join(&["/usr/bin", "/bin"])),
        Some(join(&["/home/u/.local"])),
        Some(join(&["/home/u/.local/bin2"])),
        Some(join(&["/home/u/.local/bin/sub"])),
        Some(join(&["/home/other/.local/bin"])),
        Some(join(&[".local/bin"])),
        Some(join(&["", "bin"])),
    ] {
        assert!(!local_bin_on_path(not.as_deref(), &dir), "{not:?}");
    }
    // A relative `dir` is never on the PATH (it could name anything).
    assert!(!local_bin_on_path(
        Some(&join(&[".local/bin"])),
        Path::new(".local/bin")
    ));

    let mac = Layout::resolve(&bundle_inputs()).expect("mac");
    let appimage = Layout::resolve(&image("/home/u/Apps/a.AppImage")).expect("appimage");
    let win = Layout {
        kind: Kind::Windows {
            install_dir: PathBuf::from(r"C:\Program Files\atlas-duck"),
        },
        app_path: PathBuf::from(r"C:\Program Files\atlas-duck\atlas-duck-app.exe"),
        cli_toml: PathBuf::from(r"C:\Users\u\AppData\Local\atlas-duck\cli.toml"),
    };
    let deb = Layout::resolve(&inputs(Platform::Linux)).expect("deb");
    for layout in [&mac, &appimage] {
        let ops = FakeOps::new();
        assert_eq!(cli_dir_on_path(&ops, layout), Some(false), "unset PATH");
        ops.set_session_path(Some(join(&["/usr/bin", "/home/u/.local/bin"])));
        assert_eq!(cli_dir_on_path(&ops, layout), Some(true), "{layout:?}");
        ops.set_session_path(Some(join(&["/usr/bin"])));
        assert_eq!(cli_dir_on_path(&ops, layout), Some(false), "{layout:?}");
    }
    let ops = FakeOps::new();
    ops.set_session_path(Some(join(&["/home/u/.local/bin"])));
    assert_eq!(cli_dir_on_path(&ops, &win), None);
    assert_eq!(cli_dir_on_path(&ops, &deb), None);
}

/// M-10: macOS resolves only where the link it would create is one it later removes: the CLI next
/// to the running binary has to sit in `<name>.app/Contents/MacOS`. A source build gets no layout.
#[test]
fn macos_non_bundle_build_has_no_stable_path() {
    for exe in [
        "/Users/u/src/atlas-duck/target/release/atlas-duck-app",
        "/usr/local/bin/atlas-duck-app",
        "/old/.app/Contents/MacOS/atlas-duck-app",
        "/old/Atlas Duck/Contents/MacOS/atlas-duck-app",
        "/old/Atlas Duck.app/Contents/Resources/atlas-duck-app",
    ] {
        let i = Inputs {
            current_exe: PathBuf::from(exe),
            ..inputs(Platform::Macos)
        };
        assert_eq!(
            Layout::resolve(&i),
            Err(InstallError::NoStablePath),
            "{exe}"
        );
        // Removal still finds the link by its target, whatever the build.
        let removal = Layout::for_removal(&i);
        assert!(matches!(removal.kind, Kind::Macos { .. }), "{exe}");
    }
    let ok = Layout::resolve(&bundle_inputs()).expect("a bundle resolves");
    match ok.kind {
        Kind::Macos { cli, link } => {
            assert!(macos_cli_is_in_a_bundle(&cli));
            assert_eq!(link, PathBuf::from("/home/u/.local/bin/atlas-duck"));
        }
        other => panic!("{other:?}"),
    }
}

fn macos_cli_is_in_a_bundle(cli: &Path) -> bool {
    cli.ends_with("Atlas Duck.app/Contents/MacOS/atlas-duck")
}

const OLD_DIR: &str = r"C:\Users\u\AppData\Local\Programs\Atlas Duck";
const NEW_DIR: &str = r"D:\Apps\Atlas Duck";
const WIN_CLI_TOML: &str = r"C:\Users\u\AppData\Local\atlas-duck\cli.toml";

fn win_layout(dir: &str) -> Layout {
    Layout {
        kind: Kind::Windows {
            install_dir: PathBuf::from(dir),
        },
        app_path: PathBuf::from(format!(r"{dir}\atlas-duck-app.exe")),
        cli_toml: PathBuf::from(WIN_CLI_TOML),
    }
}

/// M-11, second half: the app moved. Its own `cli.toml` names the old app file; the old folder's
/// PATH entry goes when that file is gone, in the same write that adds the new folder, and the
/// report says so. Uninstall afterwards restores the machine to before the first install.
#[test]
fn moved_install_replaces_own_stale_path_entry() {
    let original = r"%USERPROFILE%\bin;C:\Windows";
    let ops = FakeOps::with_path(original);
    install(&ops, &win_layout(OLD_DIR)).expect("first install");
    assert_eq!(
        ops.state().path.as_deref(),
        Some(format!("{original};{OLD_DIR}").as_str())
    );
    let (sets, broadcasts) = (ops.path_sets(), ops.broadcasts());

    // The user moved the app: the old file is gone, the install now runs from NEW_DIR.
    let moved = install(&ops, &win_layout(NEW_DIR)).expect("install after the move");
    assert_eq!(
        moved.changed,
        [Artifact::StaleEntry, Artifact::PathEntry, Artifact::CliToml]
    );
    assert_eq!(
        ops.state().path.as_deref(),
        Some(format!("{original};{NEW_DIR}").as_str())
    );
    assert_eq!(
        (ops.path_sets(), ops.broadcasts()),
        (sets + 1, broadcasts + 1),
        "one write, one broadcast"
    );
    assert!(is_installed(&ops, &win_layout(NEW_DIR)));

    // Removal never lists the stale entry and leaves the machine as it was.
    let gone = uninstall(&ops, &win_layout(NEW_DIR)).expect("uninstall");
    assert_eq!(gone.changed, [Artifact::PathEntry, Artifact::CliToml]);
    assert_eq!(ops.state().path.as_deref(), Some(original));

    // The new folder already on the PATH (the user added it by hand): the stale entry still goes.
    let ops = FakeOps::with_path(&format!(r"C:\Windows;{OLD_DIR}\;{NEW_DIR}"));
    ops.write_cli_toml(
        Path::new(WIN_CLI_TOML),
        &CliToml {
            app_path: Some(PathBuf::from(format!(r"{OLD_DIR}\atlas-duck-app.exe"))),
        },
    )
    .expect("old cli.toml");
    let moved = install(&ops, &win_layout(NEW_DIR)).expect("install");
    assert_eq!(moved.changed, [Artifact::StaleEntry, Artifact::CliToml]);
    assert_eq!(
        ops.state().path.as_deref(),
        Some(format!(r"C:\Windows;{NEW_DIR}").as_str())
    );

    // The old app file still exists: that install is alive, its entry stays.
    let ops = FakeOps::with_path(&format!(r"C:\Windows;{OLD_DIR}"));
    let old_app = PathBuf::from(format!(r"{OLD_DIR}\atlas-duck-app.exe"));
    ops.write_cli_toml(
        Path::new(WIN_CLI_TOML),
        &CliToml {
            app_path: Some(old_app.clone()),
        },
    )
    .expect("old cli.toml");
    ops.write_file(&old_app, b"MZ", 0o755).expect("old exe");
    let moved = install(&ops, &win_layout(NEW_DIR)).expect("install");
    assert_eq!(moved.changed, [Artifact::PathEntry, Artifact::CliToml]);
    assert_eq!(
        ops.state().path.as_deref(),
        Some(format!(r"C:\Windows;{OLD_DIR};{NEW_DIR}").as_str())
    );
}

/// An entry that is not provably the old install's is never touched: no `cli.toml`, one naming
/// another program or a folder the PATH cannot carry, a relative or `%`-expanded name, or the
/// folder this install is in.
#[test]
fn foreign_stale_path_entry_left_alone() {
    let path = format!(r"C:\Gone\Tools;{OLD_DIR};%USERPROFILE%\Atlas Duck;C:\Windows");
    let appended = format!("{path};{NEW_DIR}");
    let named = |app: &str| CliToml {
        app_path: Some(PathBuf::from(app)),
    };
    let cases: Vec<(&str, Option<CliToml>)> = vec![
        ("no cli.toml", None),
        ("an empty cli.toml", Some(CliToml { app_path: None })),
        (
            "another program in the folder",
            Some(named(r"C:\Gone\Tools\other-tool.exe")),
        ),
        (
            "a name that only ends the same",
            Some(named(r"C:\Gone\Tools\not-atlas-duck-app.exe")),
        ),
        ("a relative path", Some(named(r"Tools\atlas-duck-app.exe"))),
        ("no folder", Some(named("atlas-duck-app.exe"))),
        (
            "a folder the PATH cannot carry",
            Some(named(r"C:\Gone;Tools\atlas-duck-app.exe")),
        ),
        (
            "an expandable name",
            Some(named(r"%USERPROFILE%\Atlas Duck\atlas-duck-app.exe")),
        ),
        ("a root path", Some(named(r"C:\atlas-duck-app.exe"))),
        (
            "this install's own folder",
            Some(named(&format!(r"{NEW_DIR}\atlas-duck-app.exe"))),
        ),
    ];
    for (what, toml) in cases {
        let ops = FakeOps::with_path(&path);
        if let Some(toml) = &toml {
            ops.write_cli_toml(Path::new(WIN_CLI_TOML), toml)
                .expect("cli.toml");
        }
        let done = install(&ops, &win_layout(NEW_DIR)).expect(what);
        assert!(!done.changed.contains(&Artifact::StaleEntry), "{what}");
        assert_eq!(
            ops.state().path.as_deref(),
            Some(appended.as_str()),
            "{what}: the PATH is only appended to"
        );
    }

    // Uninstall removes this install's entry and nothing else, a stale or foreign one included.
    let ops = FakeOps::with_path(&appended);
    let layout = win_layout(NEW_DIR);
    ops.write_cli_toml(
        Path::new(WIN_CLI_TOML),
        &CliToml {
            app_path: Some(layout.app_path.clone()),
        },
    )
    .expect("cli.toml");
    let gone = uninstall(&ops, &layout).expect("uninstall");
    assert_eq!(gone.changed, [Artifact::PathEntry, Artifact::CliToml]);
    assert_eq!(ops.state().path.as_deref(), Some(path.as_str()));
}

#[test]
fn errors_name_a_kind_and_nothing_else() {
    for (e, kind) in [
        (InstallError::NoStablePath, "no_stable_path"),
        (InstallError::UnsafePath, "unsafe_path"),
        (InstallError::Occupied, "occupied"),
        (InstallError::Unsupported, "unsupported"),
        (InstallError::Registry, "registry"),
        (InstallError::PathTooLong, "path_too_long"),
        (InstallError::Io, "io"),
        (InstallError::CliToml, "cli_toml"),
    ] {
        assert_eq!(e.to_string(), kind);
        assert_eq!(serde_json::to_value(&e).ok(), Some(json!({ "kind": kind })));
    }
}

/// An OS error is never passed on: an unsupported action stays `unsupported`, any other is the
/// kind of the part that failed.
#[test]
fn os_errors_map_to_kinds() {
    let unsupported = io::Error::from(io::ErrorKind::Unsupported);
    let denied = io::Error::from(io::ErrorKind::PermissionDenied);
    assert_eq!(registry_error(&unsupported), InstallError::Unsupported);
    assert_eq!(registry_error(&denied), InstallError::Registry);
    assert_eq!(io_error(&unsupported), InstallError::Unsupported);
    assert_eq!(io_error(&denied), InstallError::Io);
}
