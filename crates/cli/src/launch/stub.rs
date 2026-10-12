//! The breakaway stub (PD-21, §4.7 Windows step 2): `atlas-duck __launch-stub <app>`, run by the
//! CLI with `CREATE_BREAKAWAY_FROM_JOB`, starts the app detached with the allowlisted environment
//! and exits at once, leaving the app orphaned. `<app>` must be the app discovery finds for this
//! executable; anything else starts nothing. Internal: dispatched by `run` before argv parsing,
//! absent from `--help`, prints nothing.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use super::LaunchError;
use crate::discover::{self, APP_FILE_NAME, AppLocation};

/// The internal subcommand (PD-21).
pub(crate) const STUB_COMMAND: &str = "__launch-stub";

/// The app was started.
pub(crate) const EXIT_STARTED: i32 = 0;
/// Starting the app failed (on Unix, where the stub is never used, always).
pub(crate) const EXIT_FAILED: i32 = 1;
/// Anything but the one app this executable would launch: nothing was started.
pub(crate) const EXIT_USAGE: i32 = 2;
/// This process's job refused the app's breakaway (§4.7 step 3); the CLI maps it back to
/// `LaunchError::BlockedByJob`.
pub(crate) const EXIT_BLOCKED: i32 = 3;

/// Runs the stub for `args` (everything after `__launch-stub`); returns the exit code. The only
/// acceptable target is the app discovery finds for this executable (§3.2): the app next to
/// `atlas-duck.exe`, or the running exe itself under `atlas-duck-app __cli`.
pub(crate) fn run_stub(args: &[OsString]) -> i32 {
    let expected = match discover::discover(&|name| std::env::var_os(name)).app {
        AppLocation::Found(app) => Some(app),
        AppLocation::NotFound => None,
    };
    run_stub_with(args, expected.as_deref(), &spawn)
}

/// `run_stub` with the expected app and the spawn injected.
pub(crate) fn run_stub_with(
    args: &[OsString],
    expected: Option<&Path>,
    spawn: &dyn Fn(&Path) -> Result<(), LaunchError>,
) -> i32 {
    let Some(app) = target(args, expected) else {
        return EXIT_USAGE;
    };
    match spawn(&app) {
        Ok(()) => EXIT_STARTED,
        Err(LaunchError::BlockedByJob) => EXIT_BLOCKED,
        Err(_) => EXIT_FAILED,
    }
}

/// Exactly one argument naming an existing file by absolute path, whose file name is the app's
/// and which is the same file as `expected` (both canonicalized).
fn target(args: &[OsString], expected: Option<&Path>) -> Option<PathBuf> {
    let [app] = args else {
        return None;
    };
    let app = PathBuf::from(app);
    let named = app
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|n| n.eq_ignore_ascii_case(APP_FILE_NAME));
    if !(named && app.is_absolute() && app.is_file()) {
        return None;
    }
    let expected = expected?.canonicalize().ok()?;
    (app.canonicalize().ok()? == expected).then_some(app)
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
        let app_path = tmp.path().join(APP_FILE_NAME);
        std::fs::write(&app_path, b"").unwrap();
        let app = OsString::from(&app_path);
        let missing = OsString::from(tmp.path().join("missing.exe"));
        let dir = OsString::from(tmp.path());
        let relative = OsString::from(APP_FILE_NAME);

        let calls = Cell::new(0u32);
        let spawn = |_: &Path| {
            calls.set(calls.get() + 1);
            Ok(())
        };
        let expected = Some(app_path.as_path());
        for bad in [
            args(&[]),
            args(&[&app, &app]),
            args(&[&relative]),
            args(&[&missing]),
            args(&[&dir]),
        ] {
            assert_eq!(run_stub_with(&bad, expected, &spawn), EXIT_USAGE, "{bad:?}");
        }
        assert_eq!(calls.get(), 0, "no spawn for bad arguments");
        // The real entry refuses the same way before any spawn.
        assert_eq!(run_stub(&[]), EXIT_USAGE);
        assert_eq!(run_stub(&args(&[&relative])), EXIT_USAGE);

        assert_eq!(
            run_stub_with(&args(&[&app]), expected, &spawn),
            EXIT_STARTED
        );
        assert_eq!(calls.get(), 1);
        let failing = |_: &Path| Err(LaunchError::ChildFailed(1));
        assert_eq!(
            run_stub_with(&args(&[&app]), expected, &failing),
            EXIT_FAILED
        );
        let blocked = |_: &Path| Err(LaunchError::BlockedByJob);
        assert_eq!(
            run_stub_with(&args(&[&app]), expected, &blocked),
            EXIT_BLOCKED
        );
    }

    #[test]
    fn stub_starts_only_the_discovered_app() {
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().join("install");
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&install).unwrap();
        std::fs::create_dir(&elsewhere).unwrap();
        let app = install.join(APP_FILE_NAME);
        let other_app = elsewhere.join(APP_FILE_NAME);
        let other_file = install.join("cmd.exe");
        for f in [&app, &other_app, &other_file] {
            std::fs::write(f, b"").unwrap();
        }

        let started = std::cell::RefCell::new(Vec::<PathBuf>::new());
        let spawn = |p: &Path| {
            started.borrow_mut().push(p.to_path_buf());
            Ok(())
        };
        let one = |p: &Path| vec![OsString::from(p)];
        // Another existing absolute file, named like the app or not: refused.
        for bad in [&other_app, &other_file] {
            assert_eq!(
                run_stub_with(&one(bad), Some(&app), &spawn),
                EXIT_USAGE,
                "{}",
                bad.display()
            );
        }
        // Even the expected location, when it is not named like the app.
        assert_eq!(
            run_stub_with(&one(&other_file), Some(&other_file), &spawn),
            EXIT_USAGE
        );
        // No discovered app: nothing is acceptable.
        assert_eq!(run_stub_with(&one(&app), None, &spawn), EXIT_USAGE);
        assert!(started.borrow().is_empty(), "{:?}", started.borrow());

        // The discovered app, compared canonically (another spelling of the same file).
        let spelled = install.join(".").join(APP_FILE_NAME);
        assert_eq!(
            run_stub_with(&one(&spelled), Some(&app), &spawn),
            EXIT_STARTED
        );
        assert_eq!(run_stub_with(&one(&app), Some(&app), &spawn), EXIT_STARTED);
        assert_eq!(started.borrow().len(), 2);
    }

    #[cfg(windows)]
    #[test]
    fn stub_app_name_is_case_insensitive_on_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let app = tmp.path().join("Atlas-Duck-App.EXE");
        std::fs::write(&app, b"").unwrap();
        let ok = |_: &Path| Ok(());
        assert_eq!(
            run_stub_with(&[OsString::from(&app)], Some(&app), &ok),
            EXIT_STARTED
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn stub_never_starts_anything_off_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let app = tmp.path().join(APP_FILE_NAME);
        std::fs::write(&app, b"").unwrap();
        assert_eq!(
            run_stub_with(&[OsString::from(&app)], Some(&app), &spawn),
            EXIT_FAILED
        );
    }
}
