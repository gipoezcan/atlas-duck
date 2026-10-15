//! macOS (§12.3): `~/.local/bin/atlas-duck` is a symlink to the `atlas-duck` CLI next to the app
//! binary in the bundle. The `/usr/local/bin` variant (admin prompt) is out of v1 scope: the user's
//! `~/.local/bin` can always be created, so it is never needed (the report says so).
//!
//! A link is ours when its target is a file named `atlas-duck`: a link left by an earlier install
//! of a moved bundle is replaced, anything else (another tool's `atlas-duck`, a regular file) is
//! `occupied` and left alone. `uninstall` removes only such links.

use std::path::{Path, PathBuf};

use super::{Artifact, InstallError, Kind, PlatformOps, Report, io_error};

/// The CLI's file name inside the bundle and in `~/.local/bin`.
const CLI_NAME: &str = "atlas-duck";

/// `~/.local/bin/atlas-duck`.
pub fn link_path(home: &Path) -> PathBuf {
    home.join(".local").join("bin").join(CLI_NAME)
}

fn is_ours(target: &Path) -> bool {
    target.file_name().is_some_and(|n| n == CLI_NAME)
}

pub fn install(ops: &dyn PlatformOps, kind: &Kind, done: &mut Report) -> Result<(), InstallError> {
    let Kind::Macos { cli, link } = kind else {
        return Err(InstallError::Unsupported);
    };
    match ops.read_link(link) {
        Ok(Some(target)) if target == *cli => return Ok(()),
        Ok(Some(target)) if is_ours(&target) => ops.remove(link).map_err(|e| io_error(&e))?,
        Ok(Some(_)) => return Err(InstallError::Occupied),
        // `InvalidInput`: a regular file or directory is in the way.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            return Err(InstallError::Occupied);
        }
        Err(e) => return Err(io_error(&e)),
        Ok(None) => {}
    }
    ops.symlink(cli, link).map_err(|e| io_error(&e))?;
    done.changed.push(Artifact::Symlink);
    Ok(())
}

pub fn uninstall(
    ops: &dyn PlatformOps,
    kind: &Kind,
    wanted: impl Fn(Artifact) -> bool,
    removed: &mut Vec<Artifact>,
) -> Result<(), InstallError> {
    let Kind::Macos { link, .. } = kind else {
        return Err(InstallError::Unsupported);
    };
    if !wanted(Artifact::Symlink) {
        return Ok(());
    }
    match ops.read_link(link) {
        Ok(Some(target)) if is_ours(&target) => {
            ops.remove(link).map_err(|e| io_error(&e))?;
            removed.push(Artifact::Symlink);
            Ok(())
        }
        // Not ours, not a link, or nothing there: left alone.
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
        Err(e) => Err(io_error(&e)),
    }
}

/// The link points at this bundle's CLI.
pub fn present(ops: &dyn PlatformOps, kind: &Kind) -> bool {
    let Kind::Macos { cli, link } = kind else {
        return false;
    };
    matches!(ops.read_link(link), Ok(Some(t)) if t == *cli)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_install::fake::{FakeOps, State};
    use crate::cli_install::{Layout, install, is_installed, uninstall};

    fn layout() -> Layout {
        let home = Path::new("/Users/u");
        Layout {
            kind: Kind::Macos {
                cli: PathBuf::from("/Applications/Atlas Duck.app/Contents/MacOS/atlas-duck"),
                link: link_path(home),
            },
            app_path: PathBuf::from("/Applications/Atlas Duck.app/Contents/MacOS/atlas-duck-app"),
            cli_toml: PathBuf::from("/Users/u/Library/Application Support/atlas-duck/cli-h.toml"),
        }
    }

    fn link(l: &Layout) -> PathBuf {
        match &l.kind {
            Kind::Macos { link, .. } => link.clone(),
            _ => PathBuf::new(),
        }
    }

    #[test]
    fn the_link_lives_in_local_bin() {
        assert_eq!(
            link_path(Path::new("/Users/u")),
            PathBuf::from("/Users/u/.local/bin/atlas-duck")
        );
    }

    #[test]
    fn install_links_the_cli_and_is_idempotent() {
        let l = layout();
        let ops = FakeOps::new();
        let first = install(&ops, &l).expect("install");
        assert_eq!(first.changed, [Artifact::Symlink, Artifact::CliToml]);
        assert!(is_installed(&ops, &l));
        assert!(install(&ops, &l).expect("again").changed.is_empty());
        // The path is the bundle's CLI, and cli.toml names the app binary.
        let state = ops.state();
        assert_eq!(state.links.len(), 1);
        assert_eq!(
            state
                .cli_tomls
                .get(&l.cli_toml)
                .and_then(|c| c.app_path.clone()),
            Some(l.app_path.clone())
        );
    }

    #[test]
    fn a_stale_link_of_a_moved_bundle_is_replaced_and_a_foreign_one_is_not() {
        let l = layout();
        let ops = FakeOps::new();
        ops.symlink(
            Path::new("/old/Atlas Duck.app/Contents/MacOS/atlas-duck"),
            &link(&l),
        )
        .expect("link");
        install(&ops, &l).expect("install over a stale link");
        assert!(is_installed(&ops, &l));

        let foreign = FakeOps::new();
        foreign
            .symlink(Path::new("/usr/bin/other"), &link(&l))
            .expect("link");
        let before = foreign.state();
        assert_eq!(install(&foreign, &l), Err(InstallError::Occupied));
        assert_eq!(foreign.state(), before, "nothing changed");
        assert!(
            uninstall(&foreign, &l)
                .expect("uninstall")
                .changed
                .is_empty()
        );
        assert_eq!(foreign.state(), before, "a foreign link is not removed");

        let file = FakeOps::new();
        file.write_file(&link(&l), b"#!/bin/sh\n", 0o755)
            .expect("file");
        let before = file.state();
        assert_eq!(install(&file, &l), Err(InstallError::Occupied));
        assert!(uninstall(&file, &l).expect("uninstall").changed.is_empty());
        assert_eq!(file.state(), before);
    }

    #[test]
    fn uninstall_removes_the_link_and_cli_toml_only() {
        let l = layout();
        let ops = FakeOps::with_state(State {
            path: Some("/usr/bin".into()),
            ..State::default()
        });
        let before = ops.state();
        install(&ops, &l).expect("install");
        let gone = uninstall(&ops, &l).expect("uninstall");
        assert_eq!(gone.changed, [Artifact::Symlink, Artifact::CliToml]);
        assert_eq!(ops.state(), before);
    }
}
