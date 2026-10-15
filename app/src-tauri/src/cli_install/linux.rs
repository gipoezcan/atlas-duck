//! Linux AppImage (§12.3, §12.2): a wrapper script `~/.local/bin/atlas-duck` with the AppImage's
//! stable absolute path (`$APPIMAGE`) baked in as `APPIMAGE_PATH`, and the `.desktop` launcher in
//! `~/.local/share/applications` whose `Exec` is that same path. The wrapper prints the fixed §4.2
//! `unreachable {not_running}` envelope with the §12.3 hint and exits 5 when the file is missing or
//! not executable (the AppImage was moved: re-run the install), else `exec`s `$APPIMAGE_PATH
//! __cli "$@"` (§12.1). Both files carry a marker line; a file without it is never overwritten or
//! removed.

use std::path::{Path, PathBuf};

use atlas_duck_ipc::envelope::{Envelope, ErrorCode};
use serde_json::{Map, Value};

use super::{Artifact, InstallError, Kind, PlatformOps, Report, io_error};

/// The wrapper's second line: what makes the file ours.
pub const WRAPPER_MARKER: &str = "# atlas-duck-cli-wrapper v1";
/// The launcher's second line.
pub const LAUNCHER_MARKER: &str = "# atlas-duck-launcher v1";

/// `~/.local/bin/atlas-duck`.
pub fn wrapper_path(home: &Path) -> PathBuf {
    home.join(".local").join("bin").join("atlas-duck")
}

/// `~/.local/share/applications/atlas-duck.desktop`.
pub fn launcher_path(home: &Path) -> PathBuf {
    home.join(".local")
        .join("share")
        .join("applications")
        .join("atlas-duck.desktop")
}

/// A path the wrapper and the launcher can carry without a second layer of escaping: no control
/// character, no `"` or `\` (they would need JSON and desktop-entry escapes), no `$`, backtick or
/// `%` (desktop-entry `Exec` expansion). Spaces and `'` are fine (quoted).
pub fn check_appimage_path(p: &Path) -> Result<(), InstallError> {
    let s = p.to_str().ok_or(InstallError::UnsafePath)?;
    if s.chars()
        .any(|c| c.is_control() || matches!(c, '"' | '\\' | '$' | '`' | '%'))
    {
        return Err(InstallError::UnsafePath);
    }
    Ok(())
}

/// §12.3 (verbatim): the hint of the envelope the wrapper prints.
pub fn not_found_hint(appimage: &str) -> String {
    format!("atlas-duck AppImage not found at {appimage}; re-run Install CLI to PATH")
}

/// The envelope the wrapper prints, as one JSON line without the newline: `failed`, `unreachable`,
/// `retryable: true` (§4.3 exit 5), `details.reason = not_running`. Built from the CLI's own
/// envelope type so it cannot drift from what the CLI prints.
pub fn not_running_line(appimage: &str) -> String {
    let mut env = Envelope::failed(ErrorCode::Unreachable, true, &not_found_hint(appimage));
    if let Some(err) = env.error.as_mut() {
        let mut details = Map::new();
        details.insert("reason".to_owned(), Value::from("not_running"));
        err.details = Some(details);
    }
    let mut line = env.to_json_line();
    line.pop();
    line
}

/// `'` quoting for a POSIX shell.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The wrapper script for `appimage` (a path that passed [`check_appimage_path`]).
pub fn wrapper_script(appimage: &str) -> String {
    format!(
        "#!/bin/sh\n\
         {WRAPPER_MARKER}\n\
         # Written by \"Install CLI to PATH\"; removed by \"Prepare for removal\". If the AppImage moves, re-run the install.\n\
         APPIMAGE_PATH={path}\n\
         if [ ! -f \"$APPIMAGE_PATH\" ] || [ ! -x \"$APPIMAGE_PATH\" ]; then\n\
         \x20   printf '%s\\n' {envelope}\n\
         \x20   exit 5\n\
         fi\n\
         exec \"$APPIMAGE_PATH\" __cli \"$@\"\n",
        path = sh_quote(appimage),
        envelope = sh_quote(&not_running_line(appimage)),
    )
}

/// The `.desktop` launcher: the shipped one (`linux/atlas-duck.desktop`) with `Exec` = the AppImage.
pub fn launcher_text(appimage: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         {LAUNCHER_MARKER}\n\
         Type=Application\n\
         Name=Atlas Duck\n\
         Exec=\"{appimage}\"\n\
         Icon=atlas-duck-app\n\
         Terminal=false\n\
         Categories=Utility;\n"
    )
}

fn has_marker(bytes: &[u8], marker: &str) -> bool {
    String::from_utf8_lossy(bytes).lines().any(|l| l == marker)
}

/// A symlink at `p`, dangling or not, is never ours: this module writes regular files. `read_file`
/// follows links, so a dangling one reads as "absent" and the rename would replace it.
fn is_symlink(ops: &dyn PlatformOps, p: &Path) -> Result<bool, InstallError> {
    match ops.read_link(p) {
        Ok(found) => Ok(found.is_some()),
        // `InvalidInput`: a regular file or directory is there.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Ok(false),
        Err(e) => Err(io_error(&e)),
    }
}

/// Writes `bytes` to `p` unless it is already so; refuses a file without `marker` and any symlink.
fn write_owned(
    ops: &dyn PlatformOps,
    p: &Path,
    bytes: &[u8],
    mode: u32,
    marker: &str,
    artifact: Artifact,
    done: &mut Report,
) -> Result<(), InstallError> {
    if is_symlink(ops, p)? {
        return Err(InstallError::Occupied);
    }
    match ops.read_file(p) {
        Ok(None) => {}
        Ok(Some(existing)) if existing == bytes => return Ok(()),
        Ok(Some(existing)) if has_marker(&existing, marker) => {}
        Ok(Some(_)) => return Err(InstallError::Occupied),
        Err(e) => return Err(io_error(&e)),
    }
    ops.write_file(p, bytes, mode).map_err(|e| io_error(&e))?;
    done.changed.push(artifact);
    Ok(())
}

pub fn install(ops: &dyn PlatformOps, kind: &Kind, done: &mut Report) -> Result<(), InstallError> {
    let Kind::AppImage {
        appimage,
        wrapper,
        launcher,
    } = kind
    else {
        return Err(InstallError::Unsupported);
    };
    check_appimage_path(appimage)?;
    let image = appimage.to_str().ok_or(InstallError::UnsafePath)?;
    write_owned(
        ops,
        wrapper,
        wrapper_script(image).as_bytes(),
        0o755,
        WRAPPER_MARKER,
        Artifact::Wrapper,
        done,
    )?;
    write_owned(
        ops,
        launcher,
        launcher_text(image).as_bytes(),
        0o644,
        LAUNCHER_MARKER,
        Artifact::Launcher,
        done,
    )
}

/// Removes `p` when it carries `marker` (never a symlink).
fn remove_owned(
    ops: &dyn PlatformOps,
    p: &Path,
    marker: &str,
    artifact: Artifact,
    removed: &mut Vec<Artifact>,
) -> Result<(), InstallError> {
    if is_symlink(ops, p)? {
        return Ok(());
    }
    match ops.read_file(p) {
        Ok(Some(existing)) if has_marker(&existing, marker) => {
            ops.remove(p).map_err(|e| io_error(&e))?;
            removed.push(artifact);
            Ok(())
        }
        // Not ours or not there: left alone.
        Ok(_) => Ok(()),
        Err(e) => Err(io_error(&e)),
    }
}

pub fn uninstall(
    ops: &dyn PlatformOps,
    kind: &Kind,
    wanted: impl Fn(Artifact) -> bool,
    removed: &mut Vec<Artifact>,
) -> Result<(), InstallError> {
    let Kind::AppImage {
        wrapper, launcher, ..
    } = kind
    else {
        return Err(InstallError::Unsupported);
    };
    if wanted(Artifact::Wrapper) {
        remove_owned(ops, wrapper, WRAPPER_MARKER, Artifact::Wrapper, removed)?;
    }
    if wanted(Artifact::Launcher) {
        remove_owned(ops, launcher, LAUNCHER_MARKER, Artifact::Launcher, removed)?;
    }
    Ok(())
}

/// Both files are there, naming this AppImage.
pub fn present(ops: &dyn PlatformOps, kind: &Kind) -> bool {
    let Kind::AppImage {
        appimage,
        wrapper,
        launcher,
    } = kind
    else {
        return false;
    };
    let Some(image) = appimage.to_str() else {
        return false;
    };
    let same =
        |p: &Path, want: String| matches!(ops.read_file(p), Ok(Some(b)) if b == want.as_bytes());
    same(wrapper, wrapper_script(image)) && same(launcher, launcher_text(image))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_install::fake::{FakeOps, State};
    use crate::cli_install::{Layout, install, is_installed, uninstall};

    const IMAGE: &str = "/home/u/My Apps/atlas'duck.AppImage";

    fn layout(image: &str) -> Layout {
        let home = Path::new("/home/u");
        Layout {
            kind: Kind::AppImage {
                appimage: PathBuf::from(image),
                wrapper: wrapper_path(home),
                launcher: launcher_path(home),
            },
            app_path: PathBuf::from(image),
            cli_toml: PathBuf::from("/home/u/.config/atlas-duck/cli-h.toml"),
        }
    }

    fn wrapper_of(l: &Layout) -> PathBuf {
        match &l.kind {
            Kind::AppImage { wrapper, .. } => wrapper.clone(),
            _ => PathBuf::new(),
        }
    }

    fn launcher_of(l: &Layout) -> PathBuf {
        match &l.kind {
            Kind::AppImage { launcher, .. } => launcher.clone(),
            _ => PathBuf::new(),
        }
    }

    /// The whole script, byte for byte, for a path with a space and an apostrophe: the baked path
    /// is single-quoted (`'` as `'\''`), the envelope line is the CLI's own JSON, the hint is the
    /// §12.3 sentence, the exit code is 5 and the happy path is `exec ... __cli "$@"` (§12.1).
    #[test]
    fn wrapper_script_text_golden() {
        let expected = concat!(
            "#!/bin/sh\n",
            "# atlas-duck-cli-wrapper v1\n",
            "# Written by \"Install CLI to PATH\"; removed by \"Prepare for removal\". If the AppImage moves, re-run the install.\n",
            "APPIMAGE_PATH='/home/u/My Apps/atlas'\\''duck.AppImage'\n",
            "if [ ! -f \"$APPIMAGE_PATH\" ] || [ ! -x \"$APPIMAGE_PATH\" ]; then\n",
            "    printf '%s\\n' '{\"request_id\":null,\"op_id\":null,\"instance\":null,\"status\":\"failed\",\"data\":null,\"edited\":false,\"redacted\":false,\"redaction_note\":null,\"message\":null,\"error\":{\"code\":\"unreachable\",\"retryable\":true,\"message\":\"atlas-duck AppImage not found at /home/u/My Apps/atlas'\\''duck.AppImage; re-run Install CLI to PATH\",\"details\":{\"reason\":\"not_running\"}},\"meta\":null}'\n",
            "    exit 5\n",
            "fi\n",
            "exec \"$APPIMAGE_PATH\" __cli \"$@\"\n",
        );
        assert_eq!(wrapper_script(IMAGE), expected);
    }

    /// The hint is the spec's sentence (§12.3), read from the spec file, with the path in it.
    #[test]
    fn the_hint_is_the_spec_sentence() {
        let spec = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs/superpowers/specs/2026-10-07-atlas-duck-design.md"),
        )
        .expect("spec");
        assert!(
            spec.contains(
                "\"atlas-duck AppImage not found at <path>; re-run Install CLI to PATH\""
            )
        );
        assert_eq!(
            not_found_hint("<path>"),
            "atlas-duck AppImage not found at <path>; re-run Install CLI to PATH"
        );
        let env: Envelope = serde_json::from_str(&not_running_line(IMAGE)).expect("envelope");
        let err = env.error.expect("error");
        assert_eq!(err.code, ErrorCode::Unreachable);
        assert!(err.retryable);
        assert_eq!(
            err.details.and_then(|d| d.get("reason").cloned()),
            Some(Value::from("not_running"))
        );
    }

    /// Run through `sh` against a path that is not there, and one that is not executable: the
    /// fixed envelope on stdout, exit 5, nothing on stderr. The script is the one this module
    /// generates; the AppImage it names is never run. Unix only (`sh`).
    #[cfg(unix)]
    #[test]
    fn moved_appimage_wrapper_prints_not_running_envelope() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("atlas-duck");
        let missing = dir.path().join("Moved Apps").join("atlas'duck.AppImage");
        let plain = dir.path().join("plain file.AppImage");
        std::fs::write(&plain, b"not executable").expect("write");
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        for image in [&missing, &plain] {
            let image = image.to_str().expect("utf-8 path");
            std::fs::write(&script, wrapper_script(image)).expect("write script");
            let out = Command::new("sh")
                .arg(&script)
                .arg("doctor")
                .output()
                .expect("sh");
            assert_eq!(out.status.code(), Some(5), "{image}");
            assert!(
                out.stderr.is_empty(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let stdout = String::from_utf8(out.stdout).expect("utf-8");
            assert_eq!(stdout, format!("{}\n", not_running_line(image)));
            let printed: Envelope = serde_json::from_str(&stdout).expect("one envelope");
            let mut want = Envelope::failed(ErrorCode::Unreachable, true, &not_found_hint(image));
            if let Some(e) = want.error.as_mut() {
                let mut d = Map::new();
                d.insert("reason".into(), Value::from("not_running"));
                e.details = Some(d);
            }
            assert_eq!(printed, want);
        }
    }

    #[test]
    fn the_launcher_is_the_shipped_desktop_file_with_the_appimage_as_exec() {
        let shipped = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("linux/atlas-duck.desktop"),
        )
        .expect("shipped launcher");
        let text = launcher_text("/opt/Atlas Duck.AppImage");
        let ours: Vec<&str> = text.lines().collect();
        for line in shipped.lines() {
            if line.starts_with("Exec=") {
                assert!(ours.contains(&"Exec=\"/opt/Atlas Duck.AppImage\""));
            } else {
                assert!(ours.contains(&line), "missing {line}");
            }
        }
        assert_eq!(
            ours.len(),
            shipped.lines().count() + 1,
            "plus the marker line"
        );
        assert_eq!(ours[1], LAUNCHER_MARKER);
    }

    #[test]
    fn paths_that_need_escaping_are_refused() {
        for bad in [
            "/a\"b",
            "/a\\b",
            "/a$b",
            "/a`b",
            "/a%b",
            "/a\nb",
            "/a\tb",
            "/a\u{7f}b",
        ] {
            assert_eq!(
                check_appimage_path(Path::new(bad)),
                Err(InstallError::UnsafePath),
                "{bad:?}"
            );
        }
        for good in [IMAGE, "/home/ü/Apps/a b.AppImage", "/opt/x-1.2_3.AppImage"] {
            assert_eq!(check_appimage_path(Path::new(good)), Ok(()), "{good}");
        }
        // Nothing is written for a refused path.
        let l = layout("/home/u/a$b.AppImage");
        let ops = FakeOps::new();
        assert_eq!(install(&ops, &l), Err(InstallError::UnsafePath));
        assert_eq!(ops.state(), State::default());
    }

    #[test]
    fn install_writes_an_executable_wrapper_and_the_launcher() {
        let l = layout(IMAGE);
        let ops = FakeOps::new();
        let report = install(&ops, &l).expect("install");
        assert_eq!(
            report.changed,
            [Artifact::Wrapper, Artifact::Launcher, Artifact::CliToml]
        );
        assert_eq!(ops.mode_of(&wrapper_of(&l)), Some(0o755));
        assert_eq!(ops.mode_of(&launcher_of(&l)), Some(0o644));
        assert!(is_installed(&ops, &l));
        // cli.toml records `$APPIMAGE`, not an executable inside the mount.
        let state = ops.state();
        assert_eq!(
            state
                .cli_tomls
                .get(&l.cli_toml)
                .and_then(|c| c.app_path.clone()),
            Some(PathBuf::from(IMAGE))
        );
        assert!(install(&ops, &l).expect("again").changed.is_empty());
    }

    /// "Moving the AppImage requires re-running the install": the wrapper and the launcher follow.
    #[test]
    fn reinstall_after_a_move_replaces_our_files() {
        let ops = FakeOps::new();
        install(&ops, &layout("/old/place/a.AppImage")).expect("install");
        let moved = layout("/new/place/a.AppImage");
        assert!(!is_installed(&ops, &moved));
        let report = install(&ops, &moved).expect("reinstall");
        assert_eq!(
            report.changed,
            [Artifact::Wrapper, Artifact::Launcher, Artifact::CliToml]
        );
        assert!(is_installed(&ops, &moved));
    }

    #[test]
    fn a_file_without_our_marker_is_never_replaced_or_removed() {
        let l = layout(IMAGE);
        for blocked in [wrapper_of(&l), launcher_of(&l)] {
            let ops = FakeOps::new();
            ops.write_file(&blocked, b"#!/bin/sh\necho mine\n", 0o755)
                .expect("foreign");
            let before = ops.state();
            assert_eq!(install(&ops, &l), Err(InstallError::Occupied));
            // The failed install also leaves nothing of its own behind.
            assert_eq!(ops.state(), before);
            assert!(uninstall(&ops, &l).expect("uninstall").changed.is_empty());
            assert_eq!(ops.state(), before);
        }
    }

    /// A symlink at the wrapper or launcher path is someone else's, dangling or not: a dangling one
    /// reads as "absent" through `read_file`, but it is never replaced or removed.
    #[test]
    fn a_symlink_is_never_replaced_or_removed() {
        let l = layout(IMAGE);
        for blocked in [wrapper_of(&l), launcher_of(&l)] {
            let ops = FakeOps::new();
            ops.symlink(Path::new("/gone/elsewhere"), &blocked)
                .expect("link");
            let before = ops.state();
            assert_eq!(install(&ops, &l), Err(InstallError::Occupied));
            assert_eq!(ops.state(), before);
            assert!(uninstall(&ops, &l).expect("uninstall").changed.is_empty());
            assert_eq!(ops.state(), before);
        }
    }

    #[test]
    fn a_failed_install_undoes_its_steps() {
        let l = layout(IMAGE);
        let ops = FakeOps::new();
        ops.fail_writes_to(&launcher_of(&l));
        assert_eq!(install(&ops, &l), Err(InstallError::Io));
        assert_eq!(
            ops.state(),
            State::default(),
            "the wrapper was removed again"
        );
    }
}
