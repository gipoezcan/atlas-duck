//! The `verify-export` command line (§12.1; M14 PD-259), shared by the desktop app's
//! `__verify-export` mode and `atlas-duck-server verify-export`: the same flags, the same usage
//! line, the same report on stdout and the same exit codes (0, 20, 21, 22; a usage error is 22).
//! Moved from `app/src-tauri/src/early_argv.rs` in M14 so the server needs no app code.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::PathBuf;

use atlas_duck_ipc::envelope::VERIFY_EXPORT_USAGE_IO;

use crate::types::ExportVerdict;
use crate::verify_export::{AnchorChain, MSG_ONE_MODE, verify_export_full};

/// The usage line printed on stderr after a usage error (exit 22).
pub const VERIFY_EXPORT_USAGE: &str = "usage: verify-export <dir> [--anchor-dir <dir> | --anchor-chain <file> [--anchor-chain-head <seq>:<64 lowercase hex>]] [--manifest-sha256 <64 lowercase hex>]";

/// What `verify-export` was asked to verify (§12.1, PD-259).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyExportArgs {
    pub dir: PathBuf,
    pub anchor_dir: Option<PathBuf>,
    pub manifest_sha256: Option<[u8; 32]>,
    /// A server export's `anchor-chain.jsonl`.
    pub anchor_chain: Option<PathBuf>,
    /// The pinned anchor-chain head `(seq, hash)`.
    pub anchor_chain_head: Option<(u64, [u8; 32])>,
}

impl VerifyExportArgs {
    /// Only the export directory.
    pub fn dir_only(dir: impl Into<PathBuf>) -> Self {
        VerifyExportArgs {
            dir: dir.into(),
            anchor_dir: None,
            manifest_sha256: None,
            anchor_chain: None,
            anchor_chain_head: None,
        }
    }
}

const FLAGS: [&str; 4] = [
    "--anchor-dir",
    "--manifest-sha256",
    "--anchor-chain",
    "--anchor-chain-head",
];

/// Parses `<dir> [--anchor-dir <dir>] [--manifest-sha256 <hex>] [--anchor-chain <file>]
/// [--anchor-chain-head <seq>:<hex>]` (also `--opt=value`, any order). `Err` carries the one-line
/// reason; the caller adds [`VERIFY_EXPORT_USAGE`]. A flag spelled `--opt=value` must be valid
/// UTF-8 as a whole; a non-UTF-8 path goes in the separate form.
pub fn parse_verify_export_args(args: &[OsString]) -> Result<VerifyExportArgs, String> {
    let mut out = VerifyExportArgs::dir_only(PathBuf::new());
    let mut dir: Option<PathBuf> = None;
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
        if !FLAGS.contains(&name) {
            return Err(format!("unknown flag: {}", shown(OsStr::new(name))));
        }
        let value = match inline.or_else(|| rest.next().cloned()) {
            Some(v) if !v.is_empty() => v,
            Some(_) => return Err(format!("{name} needs a non-empty value")),
            None => return Err(format!("{name} needs a value")),
        };
        let twice = || format!("{name} given twice");
        match name {
            "--anchor-dir" => {
                if out.anchor_dir.replace(PathBuf::from(value)).is_some() {
                    return Err(twice());
                }
            }
            "--anchor-chain" => {
                if out.anchor_chain.replace(PathBuf::from(value)).is_some() {
                    return Err(twice());
                }
            }
            "--anchor-chain-head" => {
                let Some(head) = value.to_str().and_then(chain_head) else {
                    return Err(
                        "--anchor-chain-head must be <seq>:<64 lowercase hex digits>".to_owned(),
                    );
                };
                if out.anchor_chain_head.replace(head).is_some() {
                    return Err(twice());
                }
            }
            _ => {
                let Some(hash) = value.to_str().and_then(sha256_hex) else {
                    return Err("--manifest-sha256 must be 64 lowercase hex digits".to_owned());
                };
                if out.manifest_sha256.replace(hash).is_some() {
                    return Err(twice());
                }
            }
        }
    }
    let Some(dir) = dir else {
        return Err("no export directory given".to_owned());
    };
    if out.anchor_dir.is_some() && out.anchor_chain.is_some() {
        return Err(MSG_ONE_MODE.to_owned());
    }
    if out.anchor_chain_head.is_some() && out.anchor_chain.is_none() {
        return Err("--anchor-chain-head needs --anchor-chain".to_owned());
    }
    out.dir = dir;
    Ok(out)
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

/// `<seq>:<64 lowercase hex>`: a decimal seq of 1 to 2^53 - 1 without sign or leading zero.
fn chain_head(text: &str) -> Option<(u64, [u8; 32])> {
    let (seq, hex) = text.split_once(':')?;
    if seq.is_empty() || seq.len() > 16 || seq.starts_with('0') {
        return None;
    }
    if !seq.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let seq: u64 = seq.parse().ok()?;
    if seq > atlas_duck_ipc::jcs::MAX_SAFE_INTEGER.unsigned_abs() {
        return None;
    }
    Some((seq, sha256_hex(hex)?))
}

/// The §8.10 export verifier as a process mode: the report goes to `stdout`, usage errors to
/// `stderr`, and the return value is the exit code (§12.1: 0, 20, 21, 22). `verify` is the
/// verifier ([`verify_args`] in the process).
pub fn run_verify_export<V, O, E>(
    args: &[OsString],
    verify: V,
    stdout: &mut O,
    stderr: &mut E,
) -> i32
where
    V: FnOnce(&VerifyExportArgs) -> ExportVerdict,
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
    let verdict = verify(&parsed);
    let written = verdict
        .report()
        .iter()
        .try_for_each(|line| writeln!(stdout, "{line}"))
        .and_then(|()| stdout.flush());
    let code = i32::from(verdict.exit_code());
    if written.is_err() {
        // A closed or full stdout: never exit 0 (or 20) with no report. Tampering stays 21.
        let _ = writeln!(
            stderr,
            "verify-export: could not write the report to stdout"
        );
        if code != 21 {
            return VERIFY_EXPORT_USAGE_IO;
        }
    }
    code
}

/// The real verifier over parsed arguments.
pub fn verify_args(a: &VerifyExportArgs) -> ExportVerdict {
    verify_export_full(
        &a.dir,
        a.anchor_dir.as_deref(),
        a.anchor_chain.as_deref().map(|excerpt| AnchorChain {
            excerpt,
            head: a.anchor_chain_head,
        }),
        a.manifest_sha256,
    )
}

/// [`run_verify_export`] on the real verifier and the process's stdio.
pub fn verify_export_main(args: &[OsString]) -> i32 {
    run_verify_export(
        args,
        verify_args,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn os(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    #[test]
    fn anchor_chain_flags_parse() {
        let head = format!("12:{HEX}");
        let inline_head = format!("--anchor-chain-head={head}");
        for items in [
            vec![
                "d",
                "--anchor-chain",
                "d/anchor-chain.jsonl",
                "--anchor-chain-head",
                &head,
            ],
            vec!["--anchor-chain=d/anchor-chain.jsonl", &inline_head, "d"],
        ] {
            let a = parse_verify_export_args(&os(&items)).unwrap();
            assert_eq!(a.anchor_chain, Some(PathBuf::from("d/anchor-chain.jsonl")));
            let (seq, hash) = a.anchor_chain_head.unwrap();
            assert_eq!((seq, hash[1]), (12, 0x11));
            assert_eq!(a.anchor_dir, None);
        }
        // Without a pin the excerpt is still accepted.
        let a = parse_verify_export_args(&os(&["d", "--anchor-chain", "x"])).unwrap();
        assert_eq!(a.anchor_chain_head, None);
    }

    #[test]
    fn anchor_chain_flag_errors_have_fixed_text() {
        let head = format!("12:{HEX}");
        for (items, want) in [
            (
                vec!["d", "--anchor-dir", "a", "--anchor-chain", "x"],
                MSG_ONE_MODE.to_owned(),
            ),
            (
                vec!["d", "--anchor-chain-head", &head],
                "--anchor-chain-head needs --anchor-chain".to_owned(),
            ),
            (
                vec!["d", "--anchor-chain", "x", "--anchor-chain", "y"],
                "--anchor-chain given twice".to_owned(),
            ),
        ] {
            assert_eq!(
                parse_verify_export_args(&os(&items)),
                Err(want),
                "{items:?}"
            );
        }
        let bad_heads = [
            HEX.to_owned(),
            format!(":{HEX}"),
            format!("0:{HEX}"),
            format!("012:{HEX}"),
            format!("-1:{HEX}"),
            format!("+1:{HEX}"),
            format!("9007199254740992:{HEX}"),
            format!("12:{}", HEX.to_uppercase()),
            format!("12:{}", &HEX[1..]),
            format!("12:{HEX}:1"),
            "12".to_owned(),
        ];
        for h in bad_heads {
            let err = parse_verify_export_args(&os(&[
                "d",
                "--anchor-chain",
                "x",
                "--anchor-chain-head",
                &h,
            ]));
            assert_eq!(
                err,
                Err("--anchor-chain-head must be <seq>:<64 lowercase hex digits>".to_owned()),
                "{h}"
            );
        }
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_verify_export(
            &os(&["d", "--anchor-dir", "a", "--anchor-chain", "x"]),
            |_| unreachable!("a usage error never reaches the verifier"),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 22);
        assert!(out.is_empty());
        let err = String::from_utf8(err).unwrap();
        assert_eq!(
            err,
            format!("verify-export: {MSG_ONE_MODE}\n{VERIFY_EXPORT_USAGE}\n")
        );
    }
}
