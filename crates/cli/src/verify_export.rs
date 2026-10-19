//! `atlas-duck verify-export <dir> [--anchor-dir <dir>] [--manifest-sha256 <hex>]` (§12.1, §4.1,
//! C.9). The CLI links no audit code (§2.2): it finds the app (§3.2, the launch path's code), runs
//! `<app> __verify-export …` with this process's stdio, waits, and passes the exit code through.
//! It prints no envelope: the app's report goes straight to this process's stdout, and the only
//! text the CLI adds is one plain line on stderr when it cannot run the app (exit 22).

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use atlas_duck_ipc::envelope::VERIFY_EXPORT_USAGE_IO;
use atlas_duck_ipc::paths::{BaseDirs, base_dirs, host_name};

use crate::discover::{self, AppLocation, MSG_APP_NOT_FOUND};

/// The command word.
pub(crate) const COMMAND: &str = "verify-export";
/// The app's early-argv marker (`app/src-tauri/src/early_argv.rs`).
const APP_MARKER: &str = "__verify-export";
/// §12.1: a child that ended by a signal has no exit code, which must not read as success.
pub(crate) const MSG_ABNORMAL: &str = "verify-export ended abnormally";
const MSG_NOT_STARTED: &str = "verify-export: the atlas-duck app could not be started";

/// Whether `args` (without the program name) call `verify-export` for real. `verify-export` must
/// come first, because the app owns its flags; a help flag is answered by `--help` (local).
pub(crate) fn is_call(args: &[OsString]) -> bool {
    let Some((first, rest)) = args.split_first() else {
        return false;
    };
    first == COMMAND && !rest.iter().any(|a| a == "--help" || a == "-h")
}

/// `<app> __verify-export <rest>` with this process's stdin, stdout and stderr.
pub(crate) fn child_command(app: &Path, rest: &[OsString]) -> Command {
    let mut command = Command::new(app);
    command
        .arg(APP_MARKER)
        .args(rest)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command
}

/// The exit code for a child's `code` (`None`: ended by a signal), reporting an abnormal end.
pub(crate) fn exit_code_of(code: Option<i32>, stderr: &mut dyn Write) -> i32 {
    match code {
        Some(code) => code,
        None => {
            let _ = writeln!(stderr, "{MSG_ABNORMAL}");
            VERIFY_EXPORT_USAGE_IO
        }
    }
}

/// The command for `rest` when the app can be found, by the §3.2 rules over the given inputs.
pub(crate) fn app_command(
    rest: &[OsString],
    base_host: Option<(&BaseDirs, &str)>,
    env: &dyn Fn(&str) -> Option<OsString>,
    exe: Option<&Path>,
) -> Option<Command> {
    match discover::locate_app(base_host, env, exe) {
        AppLocation::Found(app) => Some(child_command(&app, rest)),
        AppLocation::NotFound => None,
    }
}

/// Runs `command` (`None`: the app was not found) through `spawn`, which waits for the child.
pub(crate) fn run_with(
    command: Option<Command>,
    spawn: &dyn Fn(&mut Command) -> io::Result<ExitStatus>,
    stderr: &mut dyn Write,
) -> i32 {
    let Some(mut command) = command else {
        let _ = writeln!(stderr, "{MSG_APP_NOT_FOUND}");
        return VERIFY_EXPORT_USAGE_IO;
    };
    match spawn(&mut command) {
        Ok(status) => exit_code_of(status.code(), stderr),
        Err(_) => {
            let _ = writeln!(stderr, "{MSG_NOT_STARTED}");
            VERIFY_EXPORT_USAGE_IO
        }
    }
}

/// The `verify-export` run of this process: `rest` is argv after the command word.
pub(crate) fn run(rest: &[OsString]) -> i32 {
    let env = |k: &str| std::env::var_os(k);
    let exe = std::env::current_exe().and_then(|p| p.canonicalize()).ok();
    let host = host_name().unwrap_or_default();
    let base = base_dirs().ok();
    let command = app_command(
        rest,
        base.as_ref().map(|b| (b, host.as_str())),
        &env,
        exe.as_deref(),
    );
    run_with(command, &|c| c.status(), &mut std::io::stderr().lock())
}
#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn os(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    fn no_env(_: &str) -> Option<OsString> {
        None
    }

    fn args_of(c: &Command) -> Vec<OsString> {
        c.get_args().map(OsString::from).collect()
    }

    #[test]
    fn verify_export_child_command_is_marker_plus_args() {
        let app = PathBuf::from("/opt/atlas duck/atlas-duck-app");
        let rest = os(&[
            "dir with space",
            "--anchor-dir=a",
            "--manifest-sha256",
            "ab",
        ]);
        let c = child_command(&app, &rest);
        assert_eq!(c.get_program(), app.as_os_str());
        let mut expected = os(&["__verify-export"]);
        expected.extend(rest);
        assert_eq!(args_of(&c), expected);
        assert_eq!(
            c.get_current_dir(),
            None,
            "the child runs in the caller's cwd"
        );
        assert!(
            c.get_envs().next().is_none(),
            "no environment is added or removed"
        );
    }

    /// Only the command word, first, calls the app; `--help` anywhere after it is the local help.
    #[test]
    fn is_call_needs_the_command_word_first_and_no_help() {
        assert!(is_call(&os(&["verify-export"])));
        assert!(is_call(&os(&["verify-export", "d", "--anchor-dir", "a"])));
        assert!(!is_call(&os(&["verify-export", "--help"])));
        assert!(!is_call(&os(&["verify-export", "d", "-h"])));
        assert!(!is_call(&os(&["--output", "text", "verify-export", "d"])));
        assert!(!is_call(&os(&["ops", "list"])));
        assert!(!is_call(&[]));
    }

    #[test]
    fn missing_app_exits_22_with_hint() {
        let mut err = Vec::new();
        let spawned = std::cell::Cell::new(false);
        let code = run_with(
            None,
            &|_| {
                spawned.set(true);
                Ok(ExitStatus::default())
            },
            &mut err,
        );
        assert_eq!(code, 22);
        assert!(!spawned.get());
        assert_eq!(
            String::from_utf8(err).expect("UTF-8"),
            "atlas-duck app not found; reinstall or re-run Install CLI to PATH\n"
        );
        // No app is found from nowhere: next to a missing exe, with no cli.toml.
        assert!(app_command(&os(&["d"]), None, &no_env, None).is_none());
    }

    #[test]
    fn spawn_failure_exits_22() {
        let mut err = Vec::new();
        let code = run_with(
            Some(Command::new("app")),
            &|_| Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            &mut err,
        );
        assert_eq!(code, 22);
        let text = String::from_utf8(err).expect("UTF-8");
        assert_eq!(text.lines().count(), 1, "{text:?}");
        assert!(text.contains("could not be started"), "{text}");
    }

    /// A `$APPIMAGE` CLI (under a `.mount_*` point) runs the image, §3.2: pure construction, no spawn.
    #[cfg(target_os = "linux")]
    #[test]
    fn appimage_uses_dollar_appimage() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let image = tmp.path().join("App.AppImage");
        std::fs::write(&image, b"x").expect("image");
        let mounted = tmp.path().join(".mount_atlasXYZ/usr/bin/atlas-duck");
        let env = |k: &str| (k == "APPIMAGE").then(|| image.clone().into_os_string());
        let c = app_command(&os(&["d"]), None, &env, Some(&mounted)).expect("app found");
        assert_eq!(c.get_program(), image.as_os_str());
        assert_eq!(args_of(&c), os(&["__verify-export", "d"]));
        // A leaked $APPIMAGE (this CLI is not inside an AppImage) never chooses the app.
        let outside = tmp.path().join("bin/atlas-duck");
        assert!(app_command(&os(&["d"]), None, &env, Some(&outside)).is_none());
    }

    #[test]
    fn app_next_to_the_cli_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let exe = tmp.path().join("atlas-duck-cli");
        let app = tmp.path().join(discover::APP_FILE_NAME);
        std::fs::write(&app, b"x").expect("app");
        let c = app_command(&os(&["d"]), None, &no_env, Some(&exe)).expect("app found");
        assert_eq!(c.get_program(), app.as_os_str());
    }

    #[test]
    fn signal_exit_maps_to_22() {
        let mut err = Vec::new();
        assert_eq!(exit_code_of(None, &mut err), 22);
        assert_eq!(
            String::from_utf8(err).expect("UTF-8"),
            "verify-export ended abnormally\n"
        );
        // Every code the app returns (and any other) passes through, silently.
        for code in [0, 1, 20, 21, 22, 101, -1] {
            let mut err = Vec::new();
            assert_eq!(exit_code_of(Some(code), &mut err), code);
            assert!(err.is_empty(), "code {code}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_real_signal_status_maps_to_22() {
        use std::os::unix::process::ExitStatusExt;

        // SIGABRT (6): what `panic = "abort"` leaves, no exit code.
        let status = ExitStatus::from_raw(6);
        assert_eq!(status.code(), None);
        let mut err = Vec::new();
        let code = run_with(Some(Command::new("app")), &|_| Ok(status), &mut err);
        assert_eq!(code, 22);
        assert_eq!(
            String::from_utf8(err).expect("UTF-8"),
            "verify-export ended abnormally\n"
        );
    }

    #[test]
    fn verify_export_prints_no_envelope() {
        // The child's exit code is passed through and the CLI adds nothing: no stdout at all (the
        // report is the child's own) and nothing on stderr.
        let mut err = Vec::new();
        let code = run_with(
            Some(Command::new("app")),
            &|_| Ok(exit_status(21)),
            &mut err,
        );
        assert_eq!(code, 21);
        assert!(err.is_empty(), "{err:?}");
        // The lines the CLI itself can print are plain text, never an envelope.
        for failure in [None, Some(Command::new("app"))] {
            let spawn: &dyn Fn(&mut Command) -> io::Result<ExitStatus> =
                &|_| Err(io::Error::from(io::ErrorKind::NotFound));
            let mut err = Vec::new();
            run_with(failure, spawn, &mut err);
            let text = String::from_utf8(err).expect("UTF-8");
            assert!(!text.trim_start().starts_with('{'), "{text}");
            assert!(!text.contains("\"status\""), "{text}");
        }
    }

    /// An `ExitStatus` with this exit code.
    fn exit_status(code: i32) -> ExitStatus {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw(code << 8)
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(u32::try_from(code).unwrap_or(0))
        }
    }
}
