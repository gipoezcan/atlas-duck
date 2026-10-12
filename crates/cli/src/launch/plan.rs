//! What the Unix launcher executes (PD-23), as data: the program and its arguments after `argv[0]`.
//! Kept free of OS calls so every variant is tested on every host.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The only argument the app ever gets from the CLI (§4.7: agent argv is never forwarded).
pub(crate) const APP_ARGS: &[&str] = &["--background"];
/// PD-23: only this absolute path is used.
pub(crate) const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
pub(crate) const MAC_OPEN: &str = "/usr/bin/open";

/// How the app is started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Via {
    /// `execve(app, [app, "--background"])` after the double fork.
    Direct,
    /// Linux with a reachable user manager: the app also leaves the caller's cgroup.
    SystemdRun,
    /// macOS app bundle: LaunchServices starts it (not a descendant of the CLI at all).
    MacOpen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecPlan {
    pub program: PathBuf,
    /// Everything after `argv[0]` (which is `program`).
    pub args: Vec<OsString>,
}

/// The program and arguments for `app` started `via`. `MacOpen` falls back to `Direct` when `app`
/// is not inside a bundle.
pub(crate) fn exec_plan(app: &Path, via: Via) -> ExecPlan {
    let app_args = APP_ARGS.iter().map(OsString::from);
    match via {
        Via::SystemdRun => ExecPlan {
            program: PathBuf::from(SYSTEMD_RUN),
            args: ["--user", "--scope", "--quiet", "--collect", "--"]
                .iter()
                .map(OsString::from)
                .chain(std::iter::once(app.as_os_str().to_owned()))
                .chain(app_args)
                .collect(),
        },
        Via::MacOpen => match macos_bundle(app) {
            Some(bundle) => ExecPlan {
                program: PathBuf::from(MAC_OPEN),
                args: ["-n", "-g", "-a"]
                    .iter()
                    .map(OsString::from)
                    .chain(std::iter::once(bundle.as_os_str().to_owned()))
                    .chain(std::iter::once(OsString::from("--args")))
                    .chain(app_args)
                    .collect(),
            },
            None => exec_plan(app, Via::Direct),
        },
        Via::Direct => ExecPlan {
            program: app.to_path_buf(),
            args: app_args.collect(),
        },
    }
}

/// The files the launcher checks for execute permission before it forks: the program and, under
/// `systemd-run`, the app it runs. `open` resolves the bundle itself.
pub(crate) fn must_be_executable<'a>(app: &'a Path, plan: &'a ExecPlan) -> Vec<&'a Path> {
    if plan.program == Path::new(MAC_OPEN) {
        return Vec::new();
    }
    let mut files = vec![plan.program.as_path()];
    if plan.program != app {
        files.push(app);
    }
    files
}

/// The `*.app` bundle whose `Contents/MacOS/` holds `app`, if any (dev builds have none).
pub(crate) fn macos_bundle(app: &Path) -> Option<&Path> {
    let macos_dir = app.parent()?;
    let contents = macos_dir.parent()?;
    let bundle = contents.parent()?;
    let is_bundle = macos_dir.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && bundle
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("app"));
    is_bundle.then_some(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(args: &[OsString]) -> Vec<&str> {
        args.iter()
            .map(|a| a.to_str().unwrap_or("<non-utf8>"))
            .collect()
    }

    #[test]
    fn direct_passes_only_background() {
        let p = exec_plan(Path::new("/opt/atlas-duck/atlas-duck-app"), Via::Direct);
        assert_eq!(p.program, Path::new("/opt/atlas-duck/atlas-duck-app"));
        assert_eq!(strs(&p.args), ["--background"]);
    }

    #[test]
    fn appimage_is_started_by_its_own_path() {
        // §4.7: `$APPIMAGE --background`, no `__cli` marker.
        let p = exec_plan(Path::new("/home/u/Apps/atlas-duck.AppImage"), Via::Direct);
        assert_eq!(p.program, Path::new("/home/u/Apps/atlas-duck.AppImage"));
        assert_eq!(strs(&p.args), ["--background"]);
    }

    #[test]
    fn systemd_run_scope() {
        let p = exec_plan(Path::new("/opt/a/atlas-duck-app"), Via::SystemdRun);
        assert_eq!(p.program, Path::new("/usr/bin/systemd-run"));
        assert_eq!(
            strs(&p.args),
            [
                "--user",
                "--scope",
                "--quiet",
                "--collect",
                "--",
                "/opt/a/atlas-duck-app",
                "--background"
            ]
        );
    }

    #[test]
    fn mac_open_for_bundles_only() {
        let app = Path::new("/Applications/atlas-duck.app/Contents/MacOS/atlas-duck-app");
        let p = exec_plan(app, Via::MacOpen);
        assert_eq!(p.program, Path::new("/usr/bin/open"));
        assert_eq!(
            strs(&p.args),
            [
                "-n",
                "-g",
                "-a",
                "/Applications/atlas-duck.app",
                "--args",
                "--background"
            ]
        );
        // A dev build outside a bundle is started directly.
        let dev = Path::new("/Users/u/src/target/debug/atlas-duck-app");
        assert_eq!(exec_plan(dev, Via::MacOpen), exec_plan(dev, Via::Direct));
    }

    #[test]
    fn executable_checks_per_plan() {
        let app = Path::new("/opt/a/atlas-duck-app");
        let direct = exec_plan(app, Via::Direct);
        assert_eq!(must_be_executable(app, &direct), [app]);
        let scope = exec_plan(app, Via::SystemdRun);
        assert_eq!(
            must_be_executable(app, &scope),
            [Path::new("/usr/bin/systemd-run"), app]
        );
        let bundled = Path::new("/Applications/atlas-duck.app/Contents/MacOS/atlas-duck-app");
        let open = exec_plan(bundled, Via::MacOpen);
        assert!(must_be_executable(bundled, &open).is_empty());
        // A dev build outside a bundle runs directly and is checked.
        let dev = Path::new("/Users/u/target/debug/atlas-duck-app");
        assert_eq!(
            must_be_executable(dev, &exec_plan(dev, Via::MacOpen)),
            [dev]
        );
    }

    #[test]
    fn bundle_detection() {
        assert_eq!(
            macos_bundle(Path::new("/A/X.app/Contents/MacOS/x")),
            Some(Path::new("/A/X.app"))
        );
        assert_eq!(
            macos_bundle(Path::new("/A/X.APP/Contents/MacOS/x")),
            Some(Path::new("/A/X.APP"))
        );
        assert_eq!(macos_bundle(Path::new("/A/X.app/Contents/x")), None);
        assert_eq!(
            macos_bundle(Path::new("/A/X.app/Contents/Resources/x")),
            None
        );
        assert_eq!(macos_bundle(Path::new("/A/X/Contents/MacOS/x")), None);
        assert_eq!(macos_bundle(Path::new("x")), None);
    }
}
