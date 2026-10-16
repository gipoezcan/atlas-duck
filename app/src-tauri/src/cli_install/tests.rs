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
        inputs(Platform::Macos),
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
