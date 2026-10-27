//! Command line: `serve`, `version` (plan "Configuration", exit codes). `admin instances` is
//! Task 13's. M14 T19: `verify-export`, the desktop verifier offline (no configuration, no store).
//!
//! Exit codes: 0 clean shutdown, 1 runtime failure, 2 usage, 78 configuration (`EX_CONFIG`);
//! `verify-export` has its own (§12.1: 0, 20, 21, 22, a usage error included).

use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;

use serde_json::{Map, Value};

use crate::config::{Config, ConfigError};
use crate::log;

pub const EXIT_OK: u8 = 0;
pub const EXIT_RUNTIME: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_CONFIG: u8 = 78;

const USAGE: &str = "usage: atlas-duck-server <serve|version|verify-export <dir> ...>\n";

/// What argv asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Serve,
    Version,
    /// The hidden transitional dmin (PD-212).
    Admin,
    /// M14 T12 (hidden): probe the sandbox worker once, print the report as JSON.
    SandboxProbe,
    /// M14 T19: `verify-export <dir> [flags]`, the flags parsed by the shared verifier CLI.
    VerifyExport,
    Usage,
}

pub fn parse(args: &[String]) -> Command {
    match args {
        [cmd] if cmd == "serve" => Command::Serve,
        [cmd] if cmd == "version" || cmd == "--version" => Command::Version,
        [cmd, ..] if cmd == "admin" => Command::Admin,
        [cmd, ..] if cmd == "verify-export" => Command::VerifyExport,
        [cmd] | [cmd, _] if cmd == "sandbox-probe" && args.get(1).is_none_or(|a| a == "--json") => {
            Command::SandboxProbe
        }
        _ => Command::Usage,
    }
}

/// The `config_error` line `serve` prints on stderr before exiting 78 (code and key only).
pub fn config_error_fields(e: &ConfigError) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("event".into(), Value::from("config_error"));
    m.insert("code".into(), Value::from(e.code));
    m.insert("key".into(), Value::from(e.key));
    m
}

/// Entry point of the binary.
pub fn main() -> ExitCode {
    // `args_os`: a non-UTF-8 path given to verify-export must not panic.
    let os: Vec<OsString> = std::env::args_os().skip(1).collect();
    let args: Vec<String> = os
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    ExitCode::from(match parse(&args) {
        Command::Version => {
            let _ = writeln!(
                std::io::stdout(),
                "atlas-duck-server {}",
                env!("CARGO_PKG_VERSION")
            );
            EXIT_OK
        }
        Command::Usage => {
            let _ = std::io::stderr().write_all(USAGE.as_bytes());
            EXIT_USAGE
        }
        Command::Serve => serve(),
        Command::Admin => crate::admin_offline::run(&args[1..]),
        Command::SandboxProbe => sandbox_probe(),
        Command::VerifyExport => verify_export(
            &os[1..],
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        ),
    })
}

/// `atlas-duck-server verify-export <dir> [--anchor-chain <file> [--anchor-chain-head
/// <seq>:<hex>]] [--manifest-sha256 <hex>]` (PD-259): the desktop verifier, offline; reads no
/// configuration and opens no store. The report and exit codes are the desktop's (§12.1).
pub fn verify_export(args: &[OsString], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    use atlas_duck_audit::verify_export_cli::{run_verify_export, verify_args};
    let code = run_verify_export(args, verify_args, &mut WriteRef(out), &mut WriteRef(err));
    u8::try_from(code).unwrap_or(22)
}

/// A `&mut dyn Write` as a sized writer.
struct WriteRef<'a>(&'a mut dyn Write);

impl Write for WriteRef<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// `atlas-duck-server sandbox-probe --json` (T12 Step 4, T14's container proof): one probe of
/// `ATLAS_DUCK_SANDBOX_BIN` (default `/app/atlas-duck-sandbox`) with `ATLAS_DUCK_DATA_DIR` (else
/// the temp dir) as the profile a worker must not read; prints the report, exits 0 when the floor
/// is met and 1 otherwise. Needs no other configuration and opens no store.
fn sandbox_probe() -> u8 {
    let bin = std::env::var_os(crate::config::SANDBOX_BIN)
        .filter(|v| !v.is_empty())
        .map_or_else(
            || std::path::PathBuf::from(crate::scripts::ScriptsConfig::DEFAULT_BIN),
            std::path::PathBuf::from,
        );
    let profile = std::env::var_os(crate::config::DATA_DIR)
        .filter(|v| !v.is_empty())
        .map_or_else(std::env::temp_dir, std::path::PathBuf::from);
    let report = atlas_duck_script_glue::probe::run_probe_for(&bin, std::process::id(), &profile);
    let _ = writeln!(
        std::io::stdout(),
        "{}",
        crate::scripts::report_json(&report)
    );
    if matches!(
        report.floor,
        atlas_duck_sandbox_host::probe::FloorVerdict::Met
    ) {
        EXIT_OK
    } else {
        EXIT_RUNTIME
    }
}

fn serve() -> u8 {
    let config = Config::from_env(&|k| std::env::var(k).ok(), &|| {
        std::env::vars_os()
            .filter_map(|(k, _)| k.into_string().ok())
            .collect()
    });
    let config = match config {
        Ok(c) => c,
        Err(e) => {
            log::stderr_line("error", config_error_fields(&e));
            return EXIT_CONFIG;
        }
    };
    log::init(&config.rust_log);
    crate::app::serve(config)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn argv_table() {
        assert_eq!(parse(&args(&["serve"])), Command::Serve);
        assert_eq!(parse(&args(&["version"])), Command::Version);
        assert_eq!(parse(&args(&[])), Command::Usage);
        assert_eq!(parse(&args(&["serve", "x"])), Command::Usage);
        assert_eq!(
            parse(&args(&["admin", "instances", "list"])),
            Command::Admin
        );
        assert_eq!(
            parse(&args(&["sandbox-probe", "--json"])),
            Command::SandboxProbe
        );
        assert_eq!(parse(&args(&["sandbox-probe"])), Command::SandboxProbe);
        assert_eq!(parse(&args(&["sandbox-probe", "x"])), Command::Usage);
        assert_eq!(parse(&args(&["verify-export"])), Command::VerifyExport);
        assert_eq!(
            parse(&args(&["verify-export", "d", "--anchor-chain", "x"])),
            Command::VerifyExport
        );
    }

    /// The server subcommand prints exactly the desktop verifier's report and exit code.
    #[test]
    fn verify_export_is_the_desktop_verifier() {
        use atlas_duck_audit::verify_export_cli::{
            VERIFY_EXPORT_USAGE, parse_verify_export_args, verify_args,
        };
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("export-x");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"), b"{}").unwrap();
        let argv: Vec<OsString> = vec![dir.clone().into_os_string()];
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = verify_export(&argv, &mut out, &mut err);
        let want = verify_args(&parse_verify_export_args(&argv).unwrap());
        assert_eq!(code, want.exit_code());
        assert_eq!(code, 22);
        let golden: String = want.report().iter().map(|l| format!("{l}\n")).collect();
        assert_eq!(String::from_utf8(out).unwrap(), golden);
        assert!(err.is_empty());
        // A usage error: 22, the reason and the usage line on stderr.
        let bad: Vec<OsString> = ["d", "--anchor-dir", "a", "--anchor-chain", "c"]
            .iter()
            .map(OsString::from)
            .collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(verify_export(&bad, &mut out, &mut err), 22);
        assert!(out.is_empty());
        let err = String::from_utf8(err).unwrap();
        assert!(err.ends_with(&format!("{VERIFY_EXPORT_USAGE}\n")), "{err}");
    }

    #[test]
    fn config_error_line_has_code_and_key_only() {
        let f = config_error_fields(&ConfigError {
            code: "config/missing_key",
            key: "ATLAS_DUCK_MODE",
        });
        let v = Value::Object(f);
        assert_eq!(
            v,
            serde_json::json!({"event": "config_error", "code": "config/missing_key",
                               "key": "ATLAS_DUCK_MODE"})
        );
    }
}
