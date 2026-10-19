//! Early-argv dispatch of `atlas-duck-app` (§12.1, §2.5 Scope). `classify_argv` runs first in `main`,
//! before Tauri, the single-instance plugin, startup hardening, the stderr redirect, the data-dir
//! check and `instance.lock`. The markers are entry-point switches, not security controls (§3.2 (b)).

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};

use atlas_duck_audit::ExportVerdict;
use atlas_duck_ipc::envelope::VERIFY_EXPORT_USAGE_IO;

/// AppImage CLI dispatch marker (§12.1).
pub const MARKER_CLI: &str = "__cli";
/// Export verifier marker (§12.1).
pub const MARKER_VERIFY_EXPORT: &str = "__verify-export";
/// Accepted alias of `__verify-export` (§12.1).
pub const ALIAS_VERIFY_EXPORT: &str = "--verify-export";
/// Autostart / CLI launch flag (§2.5, §4.7).
pub const FLAG_BACKGROUND: &str = "--background";

/// The usage line `__verify-export` prints on stderr after a usage error (exit 22).
pub const VERIFY_EXPORT_USAGE: &str =
    "usage: verify-export <dir> [--anchor-dir <dir>] [--manifest-sha256 <64 lowercase hex>]";

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

/// What `__verify-export` was asked to verify (§12.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyExportArgs {
    pub dir: PathBuf,
    pub anchor_dir: Option<PathBuf>,
    pub manifest_sha256: Option<[u8; 32]>,
}

/// Parses `<dir> [--anchor-dir <dir>] [--manifest-sha256 <hex>]` (also `--opt=value`, any order).
/// `Err` carries the one-line reason; the caller adds [`VERIFY_EXPORT_USAGE`]. A flag spelled
/// `--opt=value` must be valid UTF-8 as a whole; a non-UTF-8 path goes in the separate form.
pub fn parse_verify_export_args(args: &[OsString]) -> Result<VerifyExportArgs, String> {
    let mut dir: Option<PathBuf> = None;
    let mut anchor_dir: Option<PathBuf> = None;
    let mut manifest_sha256: Option<[u8; 32]> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if !arg.as_encoded_bytes().starts_with(b"-") {
            if arg.is_empty() {
                return Err("the export directory is empty".to_owned());
            }
            if dir.replace(PathBuf::from(arg)).is_some() {
                return Err(format!("unexpected argument: {}", shown(arg)));
            }
            continue;
        }
        let Some(text) = arg.to_str() else {
            return Err(
                "an option is not valid UTF-8 (use --option value for such paths)".to_owned(),
            );
        };
        let (name, inline) = match text.split_once('=') {
            Some((name, value)) => (name, Some(OsString::from(value))),
            None => (text, None),
        };
        if name != "--anchor-dir" && name != "--manifest-sha256" {
            return Err(format!("unknown flag: {}", shown(OsStr::new(name))));
        }
        let value = match inline.or_else(|| rest.next().cloned()) {
            Some(v) if !v.is_empty() => v,
            Some(_) => return Err(format!("{name} needs a non-empty value")),
            None => return Err(format!("{name} needs a value")),
        };
        if name == "--anchor-dir" {
            if anchor_dir.replace(PathBuf::from(value)).is_some() {
                return Err("--anchor-dir given twice".to_owned());
            }
        } else {
            let Some(hash) = value.to_str().and_then(sha256_hex) else {
                return Err("--manifest-sha256 must be 64 lowercase hex digits".to_owned());
            };
            if manifest_sha256.replace(hash).is_some() {
                return Err("--manifest-sha256 given twice".to_owned());
            }
        }
    }
    let Some(dir) = dir else {
        return Err("no export directory given".to_owned());
    };
    Ok(VerifyExportArgs {
        dir,
        anchor_dir,
        manifest_sha256,
    })
}

/// An argument for an error line: lossy, cut to 80 characters.
fn shown(arg: &OsStr) -> String {
    arg.to_string_lossy().chars().take(80).collect()
}

/// 64 lowercase hex digits as 32 bytes.
fn sha256_hex(text: &str) -> Option<[u8; 32]> {
    let digits = text.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let nibble = |d: u8| match d {
        b'0'..=b'9' => Some(d - b'0'),
        b'a'..=b'f' => Some(d - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = nibble(*pair.first()?)? << 4 | nibble(*pair.get(1)?)?;
    }
    Some(out)
}

/// The §8.10 export verifier as a process mode: the report goes to `stdout`, usage errors to
/// `stderr`, and the return value is the exit code (§12.1: 0, 20, 21, 22). It reads only the export
/// directory and the anchor directory the arguments name; it holds no key and touches no store,
/// keychain, data dir or instance lock, so it can never leave a tray instance behind (§2.5 Scope).
/// `verify` is the verifier (`atlas_duck_audit::verify_export` in the process).
pub fn run_verify_export<V, O, E>(
    args: &[OsString],
    verify: V,
    stdout: &mut O,
    stderr: &mut E,
) -> i32
where
    V: FnOnce(&Path, Option<&Path>, Option<[u8; 32]>) -> ExportVerdict,
    O: Write,
    E: Write,
{
    let parsed = match parse_verify_export_args(args) {
        Ok(parsed) => parsed,
        Err(reason) => {
            let _ = writeln!(stderr, "verify-export: {reason}");
            let _ = writeln!(stderr, "{VERIFY_EXPORT_USAGE}");
            return VERIFY_EXPORT_USAGE_IO;
        }
    };
    let verdict = verify(
        &parsed.dir,
        parsed.anchor_dir.as_deref(),
        parsed.manifest_sha256,
    );
    for line in verdict.report() {
        let _ = writeln!(stdout, "{line}");
    }
    let _ = stdout.flush();
    i32::from(verdict.exit_code())
}

/// [`run_verify_export`] on the real verifier and the process's stdio.
pub fn verify_export_main(args: Vec<OsString>) -> i32 {
    run_verify_export(
        &args,
        atlas_duck_audit::verify_export,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
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

    const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn hex_bytes() -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&HEX[2 * i..2 * i + 2], 16).expect("hex");
        }
        out
    }

    fn parsed(items: &[&str]) -> VerifyExportArgs {
        parse_verify_export_args(&os(items)).unwrap_or_else(|e| panic!("{items:?}: {e}"))
    }

    fn only_dir(dir: &str) -> VerifyExportArgs {
        VerifyExportArgs {
            dir: PathBuf::from(dir),
            anchor_dir: None,
            manifest_sha256: None,
        }
    }

    #[test]
    fn verify_export_args_parse_and_reject_unknown() {
        assert_eq!(parsed(&["d"]), only_dir("d"));
        let full = VerifyExportArgs {
            dir: PathBuf::from("d"),
            anchor_dir: Some(PathBuf::from("a")),
            manifest_sha256: Some(hex_bytes()),
        };
        let manifest_flag = format!("--manifest-sha256={HEX}");
        for items in [
            vec!["d", "--anchor-dir", "a", "--manifest-sha256", HEX],
            vec!["d", "--anchor-dir=a", &manifest_flag],
            vec!["--manifest-sha256", HEX, "--anchor-dir", "a", "d"],
            vec!["--anchor-dir=a", "d", &manifest_flag],
        ] {
            assert_eq!(parsed(&items), full, "{items:?}");
        }
        // A value that looks like a flag is still the value of the flag before it.
        assert_eq!(
            parsed(&["d", "--anchor-dir", "--x"]).anchor_dir,
            Some(PathBuf::from("--x"))
        );
        // A value may contain `=`.
        assert_eq!(
            parsed(&["d", "--anchor-dir=a=b"]).anchor_dir,
            Some(PathBuf::from("a=b"))
        );
        // A non-UTF-8 directory passes through untouched.
        let raw = non_utf8();
        assert_eq!(
            parse_verify_export_args(std::slice::from_ref(&raw)).expect("non-UTF-8 dir"),
            VerifyExportArgs {
                dir: PathBuf::from(&raw),
                anchor_dir: None,
                manifest_sha256: None
            }
        );
        assert_eq!(
            parse_verify_export_args(&[
                OsString::from("d"),
                OsString::from("--anchor-dir"),
                raw.clone()
            ])
            .expect("non-UTF-8 anchor dir")
            .anchor_dir,
            Some(PathBuf::from(&raw))
        );

        let bad_hexes = [
            HEX.to_uppercase(),
            HEX[..63].to_owned(),
            format!("{HEX}0"),
            format!("g{}", &HEX[1..]),
            String::new(),
        ];
        let mut bad: Vec<Vec<String>> = [
            &[][..],
            &["a", "b"],
            &["d", "--bogus"],
            &["d", "--bogus=1"],
            &["d", "-x"],
            &["d", "--"],
            &["--help"],
            &["d", "--anchor-dir"],
            &["d", "--manifest-sha256"],
            &["d", "--anchor-dir", "a", "--anchor-dir", "b"],
            &["d", "--anchor-dir=a", "--anchor-dir", "b"],
            &["d", "--anchor-dir="],
            &["d", "--anchor-dir", ""],
            &[""],
            &["--anchor-dir", "a"],
            &["d", "--ANCHOR-DIR", "a"],
        ]
        .iter()
        .map(|a| a.iter().map(|s| (*s).to_owned()).collect())
        .collect();
        for h in &bad_hexes {
            bad.push(vec!["d".into(), "--manifest-sha256".into(), h.clone()]);
            bad.push(vec!["d".into(), format!("--manifest-sha256={h}")]);
        }
        bad.push(vec![
            "d".into(),
            "--manifest-sha256".into(),
            HEX.into(),
            format!("--manifest-sha256={HEX}"),
        ]);
        for items in bad {
            let refs: Vec<&str> = items.iter().map(String::as_str).collect();
            let err = parse_verify_export_args(&os(&refs));
            assert!(
                err.as_ref().is_err_and(|m| !m.is_empty()),
                "{refs:?}: {err:?}"
            );
        }
    }

    #[test]
    fn verify_export_args_reject_pubkey() {
        for items in [
            &["d", "--pubkey", "k"][..],
            &["d", "--pubkey=k"],
            &["--pubkey", "k", "d"],
        ] {
            let err = parse_verify_export_args(&os(items)).expect_err("--pubkey is not a flag");
            assert!(err.contains("--pubkey"), "{err}");
        }
    }

    type Call = (PathBuf, Option<PathBuf>, Option<[u8; 32]>);

    fn run_with(
        items: &[&str],
        verdict: impl FnOnce() -> ExportVerdict,
    ) -> (i32, String, String, Vec<Call>) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut calls: Vec<Call> = Vec::new();
        let code = run_verify_export(
            &os(items),
            |dir, anchor, manifest| {
                calls.push((dir.to_path_buf(), anchor.map(Path::to_path_buf), manifest));
                verdict()
            },
            &mut out,
            &mut err,
        );
        let text = |b: Vec<u8>| String::from_utf8(b).expect("UTF-8");
        (code, text(out), text(err), calls)
    }

    fn lines(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn early_mode_touches_no_tauri_or_data_dir() {
        // The verdicts map to the §12.1 codes; the report goes to stdout, line by line, and
        // nothing reaches stderr.
        let cases = [
            (
                ExportVerdict::Verified {
                    report: lines(&["rows 1", "verified"]),
                },
                0,
            ),
            (
                ExportVerdict::NoTrustRoot {
                    report: lines(&["rows 1", "internally consistent; trust root NOT verified"]),
                },
                20,
            ),
            (
                ExportVerdict::TamperOrFork {
                    report: lines(&["TAMPERED: row 3"]),
                },
                21,
            ),
            (
                ExportVerdict::UsageOrIo {
                    report: lines(&["cannot verify: no manifest"]),
                },
                22,
            ),
        ];
        for (verdict, expected) in cases {
            let report = verdict.report().join("\n") + "\n";
            let (code, out, err, calls) = run_with(
                &["d", "--anchor-dir", "a", "--manifest-sha256", HEX],
                || verdict,
            );
            assert_eq!(code, expected);
            assert_eq!(out, report);
            assert_eq!(err, "");
            assert_eq!(
                calls,
                [(
                    PathBuf::from("d"),
                    Some(PathBuf::from("a")),
                    Some(hex_bytes())
                )]
            );
        }

        // A usage error never reaches the verifier: the reason and the usage line on stderr,
        // stdout empty, exit 22.
        let (code, out, err, calls) = run_with(&["d", "--bogus"], || ExportVerdict::Verified {
            report: Vec::new(),
        });
        assert_eq!(code, 22);
        assert_eq!(out, "");
        assert!(calls.is_empty());
        let mut err_lines = err.lines();
        assert!(
            err_lines.next().is_some_and(|l| l.contains("--bogus")),
            "{err}"
        );
        assert_eq!(err_lines.next(), Some(VERIFY_EXPORT_USAGE));
        assert_eq!(err_lines.next(), None);

        // The mode's code names neither Tauri, the data dir, the instance lock nor a keychain.
        let source = include_str!("early_argv.rs");
        let code_part = source.split("#[cfg(test)]").next().expect("source head");
        for needle in ["tauri", "data_dir", "instance_lock", "keychain", "KeyStore"] {
            let hits: Vec<&str> = code_part
                .lines()
                .filter(|l| !l.trim_start().starts_with("//") && l.contains(needle))
                .collect();
            assert!(hits.is_empty(), "{needle}: {hits:?}");
        }
    }
}
