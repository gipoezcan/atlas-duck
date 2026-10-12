//! The breakaway stub (PD-21, §4.7 Windows step 2): `atlas-duck __launch-stub <app>`, run by the
//! CLI with `CREATE_BREAKAWAY_FROM_JOB`, starts the app detached with the allowlisted environment
//! and exits at once, leaving the app orphaned. Internal: dispatched by `run` before argv parsing,
//! absent from `--help`, prints nothing.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::LaunchError;

/// The internal subcommand (PD-21).
pub(crate) const STUB_COMMAND: &str = "__launch-stub";

/// The app was started.
pub(crate) const EXIT_STARTED: i32 = 0;
/// Starting the app failed (on Unix, where the stub is never used, always).
pub(crate) const EXIT_FAILED: i32 = 1;
/// Anything but one existing absolute path: nothing was started.
pub(crate) const EXIT_USAGE: i32 = 2;

/// Runs the stub for `args` (everything after `__launch-stub`); returns the exit code.
pub(crate) fn run_stub(args: &[OsString]) -> i32 {
    run_stub_with(args, &spawn)
}

/// `run_stub` with the spawn injected.
pub(crate) fn run_stub_with(
    args: &[OsString],
    spawn: &dyn Fn(&Path) -> Result<(), LaunchError>,
) -> i32 {
    let Some(app) = target(args) else {
        return EXIT_USAGE;
    };
    match spawn(&app) {
        Ok(()) => EXIT_STARTED,
        Err(_) => EXIT_FAILED,
    }
}

/// Exactly one argument naming an existing file by absolute path.
fn target(args: &[OsString]) -> Option<PathBuf> {
    let [app] = args else {
        return None;
    };
    let app = PathBuf::from(app);
    (app.is_absolute() && app.is_file()).then_some(app)
}

fn spawn(app: &Path) -> Result<(), LaunchError> {
    let env = super::env::launch_env(std::env::vars_os());
    #[cfg(windows)]
    {
        super::windows::stub_spawn(app, &env)
    }
    #[cfg(not(windows))]
    {
        let _ = (app, env);
        Err(LaunchError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn args(list: &[&OsString]) -> Vec<OsString> {
        list.iter().map(|a| (*a).clone()).collect()
    }

    #[test]
    fn stub_rejects_bad_args() {
        let tmp = tempfile::tempdir().unwrap();
        let app = tmp.path().join("atlas-duck-app.exe");
        std::fs::write(&app, b"").unwrap();
        let app = OsString::from(app);
        let missing = OsString::from(tmp.path().join("missing.exe"));
        let dir = OsString::from(tmp.path());
        let relative = OsString::from("atlas-duck-app.exe");

        let calls = Cell::new(0u32);
        let spawn = |_: &Path| {
            calls.set(calls.get() + 1);
            Ok(())
        };
        for bad in [
            args(&[]),
            args(&[&app, &app]),
            args(&[&relative]),
            args(&[&missing]),
            args(&[&dir]),
        ] {
            assert_eq!(run_stub_with(&bad, &spawn), EXIT_USAGE, "{bad:?}");
        }
        assert_eq!(calls.get(), 0, "no spawn for bad arguments");
        // The real entry refuses the same way before any spawn.
        assert_eq!(run_stub(&[]), EXIT_USAGE);
        assert_eq!(run_stub(&args(&[&relative])), EXIT_USAGE);

        assert_eq!(run_stub_with(&args(&[&app]), &spawn), EXIT_STARTED);
        assert_eq!(calls.get(), 1);
        let failing = |_: &Path| Err(LaunchError::ChildFailed(1));
        assert_eq!(run_stub_with(&args(&[&app]), &failing), EXIT_FAILED);
    }

    #[cfg(not(windows))]
    #[test]
    fn stub_never_starts_anything_off_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let app = tmp.path().join("atlas-duck-app");
        std::fs::write(&app, b"").unwrap();
        assert_eq!(run_stub(&[OsString::from(app)]), EXIT_FAILED);
    }
}
