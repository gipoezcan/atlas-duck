//! Early-argv dispatch of `atlas-duck-app` (§12.1, §2.5 Scope). `classify_argv` runs first in `main`,
//! before Tauri, the single-instance plugin, startup hardening, the stderr redirect, the data-dir
//! check and `instance.lock`. The markers are entry-point switches, not security controls (§3.2 (b)).

use std::ffi::{OsStr, OsString};
use std::io::Write;

use atlas_duck_ipc::envelope::VERIFY_EXPORT_USAGE_IO;

/// AppImage CLI dispatch marker (§12.1).
pub const MARKER_CLI: &str = "__cli";
/// Export verifier marker (§12.1).
pub const MARKER_VERIFY_EXPORT: &str = "__verify-export";
/// Accepted alias of `__verify-export` (§12.1).
pub const ALIAS_VERIFY_EXPORT: &str = "--verify-export";
/// Autostart / CLI launch flag (§2.5, §4.7).
pub const FLAG_BACKGROUND: &str = "--background";

/// The one stderr line of the M1 verify-export stub (plan text; M10 replaces the stub).
pub const VERIFY_EXPORT_UNAVAILABLE: &str =
    "atlas-duck: verify-export is not available in this build";

/// What `main` does with this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EarlyMode {
    /// `__cli <args>`: run the CLI entry with `<args>`, keep stdio, never become a tray instance.
    Cli(Vec<OsString>),
    /// `__verify-export <args>` or `--verify-export <args>`: run the export verifier and exit.
    VerifyExport(Vec<OsString>),
    /// GUI or `--background` launch: the only mode that becomes a tray instance.
    Gui { background: bool },
}

/// Classifies the full argv (`args[0]` is the program). Only `args[1]` can select an early mode; a
/// marker in any later position is an ordinary argument. Arguments pass through as `OsString`s, so
/// non-UTF-8 values are never altered.
pub fn classify_argv(args: &[OsString]) -> EarlyMode {
    let Some(first) = args.get(1) else {
        return EarlyMode::Gui { background: false };
    };
    let rest = || args.get(2..).unwrap_or_default().to_vec();
    if first == OsStr::new(MARKER_CLI) {
        return EarlyMode::Cli(rest());
    }
    if first == OsStr::new(MARKER_VERIFY_EXPORT) || first == OsStr::new(ALIAS_VERIFY_EXPORT) {
        return EarlyMode::VerifyExport(rest());
    }
    let background = args
        .iter()
        .skip(1)
        .any(|a| a == OsStr::new(FLAG_BACKGROUND));
    EarlyMode::Gui { background }
}

/// M1 stand-in for the §8.10 export verifier: writes one line to stderr and returns 22
/// (§12.1: "`22` = usage or I/O error"; "Every startup, argument or panic failure exits non-zero").
/// Running it can never leave a tray instance behind (§2.5 Scope).
pub fn verify_export_stub(args: Vec<OsString>) -> i32 {
    verify_export_stub_to(args, &mut std::io::stderr())
}

/// `verify_export_stub` with an injectable stderr, so the unit test does not write to the test
/// runner's real stderr.
pub fn verify_export_stub_to<W: Write>(_args: Vec<OsString>, stderr: &mut W) -> i32 {
    let _ = writeln!(stderr, "{VERIFY_EXPORT_UNAVAILABLE}");
    VERIFY_EXPORT_USAGE_IO
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    #[cfg(unix)]
    fn non_utf8() -> OsString {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![b'a', 0xff, b'b'])
    }

    #[cfg(windows)]
    fn non_utf8() -> OsString {
        use std::os::windows::ffi::OsStringExt;
        // A lone surrogate is valid WTF-16 (an OsString on Windows) but not UTF-8.
        OsString::from_wide(&[0x61, 0xD800, 0x62])
    }

    #[test]
    fn cli_marker_strips_marker_and_passes_args_untouched() {
        let raw = non_utf8();
        assert!(raw.to_str().is_none());
        let args = vec![
            OsString::from("atlas-duck-app"),
            OsString::from("__cli"),
            OsString::from("a"),
            raw.clone(),
        ];
        assert_eq!(
            classify_argv(&args),
            EarlyMode::Cli(vec![OsString::from("a"), raw])
        );
    }

    #[test]
    fn cli_marker_with_two_plain_args() {
        assert_eq!(
            classify_argv(&os(&["exe", "__cli", "a", "b"])),
            EarlyMode::Cli(os(&["a", "b"]))
        );
    }

    #[test]
    fn marker_only_counts_in_first_position() {
        assert_eq!(
            classify_argv(&os(&["exe", "x", "__cli"])),
            EarlyMode::Gui { background: false }
        );
        assert_eq!(
            classify_argv(&os(&["exe", "x", "__verify-export"])),
            EarlyMode::Gui { background: false }
        );
    }

    #[test]
    fn background_flag() {
        assert_eq!(
            classify_argv(&os(&["exe", "--background"])),
            EarlyMode::Gui { background: true }
        );
    }

    #[test]
    fn verify_export_marker_and_alias() {
        assert_eq!(
            classify_argv(&os(&["exe", "--verify-export", "d"])),
            EarlyMode::VerifyExport(os(&["d"]))
        );
        assert_eq!(
            classify_argv(&os(&["exe", "__verify-export", "d", "--anchor-dir", "a"])),
            EarlyMode::VerifyExport(os(&["d", "--anchor-dir", "a"]))
        );
    }

    #[test]
    fn no_arguments_is_a_gui_launch() {
        assert_eq!(
            classify_argv(&os(&["exe"])),
            EarlyMode::Gui { background: false }
        );
        assert_eq!(classify_argv(&[]), EarlyMode::Gui { background: false });
    }

    #[test]
    fn marker_matching_is_exact() {
        assert_eq!(
            classify_argv(&os(&["exe", "__CLI"])),
            EarlyMode::Gui { background: false }
        );
        assert_eq!(
            classify_argv(&os(&["exe", "__cli="])),
            EarlyMode::Gui { background: false }
        );
    }

    #[test]
    fn verify_export_stub_exits_22_and_says_why_on_stderr() {
        let mut stderr = Vec::new();
        assert_eq!(verify_export_stub_to(os(&["x"]), &mut stderr), 22);
        assert_eq!(
            String::from_utf8(stderr).expect("UTF-8"),
            format!("{VERIFY_EXPORT_UNAVAILABLE}\n")
        );
    }
}
