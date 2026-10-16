//! Whether a process really runs from an AppImage (M6 final review I-3). Children of any
//! AppImage inherit `$APPIMAGE` (a terminal or editor shipped as one, then a deb or rpm install
//! started from it), so the variable alone proves nothing: the app's `cli_install` and the CLI's
//! app discovery both trust it only through this one function.

use std::path::{Component, Path};

/// A path that starts with `/` counts as absolute on every platform: the layouts of other
/// platforms are resolved in tests too.
pub fn looks_absolute(p: &Path) -> bool {
    p.is_absolute() || p.to_str().is_some_and(|s| s.starts_with('/'))
}

/// An AppImage's mount point (`/tmp/.mount_<random>`): it vanishes with the process.
pub fn under_mount(p: &Path) -> bool {
    p.components().any(|c| match c {
        Component::Normal(n) => n.to_str().is_some_and(|s| s.starts_with(".mount_")),
        _ => false,
    })
}

/// The binary `exe` runs from an AppImage: it is under a `.mount_*` component, or under an
/// absolute, non-root `$APPDIR` (extract-and-run). `$APPDIR` of `/` would contain every path.
pub fn runs_from_appimage(exe: &Path, appdir: Option<&Path>) -> bool {
    under_mount(exe)
        || appdir.is_some_and(|dir| {
            looks_absolute(dir) && dir.parent().is_some() && exe.starts_with(dir)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(exe, $APPDIR, runs from an AppImage)`: the one table both callers rest on.
    const CASES: [(&str, Option<&str>, bool); 9] = [
        // Mounted: the runtime's mount point, `$APPDIR` set or not.
        ("/tmp/.mount_atlasXYZ/usr/bin/atlas-duck", None, true),
        (
            "/tmp/.mount_atlasXYZ/usr/bin/atlas-duck",
            Some("/tmp/.mount_atlasXYZ"),
            true,
        ),
        // Extract-and-run: under `$APPDIR`.
        (
            "/home/u/squashfs-root/usr/bin/atlas-duck",
            Some("/home/u/squashfs-root"),
            true,
        ),
        // A deb or rpm binary with `$APPIMAGE` leaked in from the host terminal or editor.
        ("/usr/bin/atlas-duck", None, false),
        ("/usr/bin/atlas-duck", Some("/tmp/.mount_editorABC"), false),
        // An `$APPDIR` of `/` would contain every path; a relative one is no proof.
        ("/usr/bin/atlas-duck", Some("/"), false),
        ("/usr/bin/atlas-duck", Some("usr"), false),
        // A look-alike name is not a mount point.
        ("/home/u/.mounts/atlas-duck", None, false),
        ("/home/u/mount_x/atlas-duck", None, false),
    ];

    #[test]
    fn only_a_mounted_or_extracted_binary_runs_from_an_appimage() {
        for (exe, appdir, want) in CASES {
            assert_eq!(
                runs_from_appimage(Path::new(exe), appdir.map(Path::new)),
                want,
                "{exe} with APPDIR {appdir:?}"
            );
        }
    }
}
