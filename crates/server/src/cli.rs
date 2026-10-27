//! Command line: `serve`, `version` (plan "Configuration", exit codes). `admin instances` is
//! Task 13's.
//!
//! Exit codes: 0 clean shutdown, 1 runtime failure, 2 usage, 78 configuration (`EX_CONFIG`).

use std::io::Write;
use std::process::ExitCode;

use serde_json::{Map, Value};

use crate::config::{Config, ConfigError};
use crate::log;

pub const EXIT_OK: u8 = 0;
pub const EXIT_RUNTIME: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_CONFIG: u8 = 78;

const USAGE: &str = "usage: atlas-duck-server <serve|version>\n";

/// What argv asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Serve,
    Version,
    /// The hidden transitional dmin (PD-212).
    Admin,
    /// M14 T12 (hidden): probe the sandbox worker once, print the report as JSON.
    SandboxProbe,
    Usage,
}

pub fn parse(args: &[String]) -> Command {
    match args {
        [cmd] if cmd == "serve" => Command::Serve,
        [cmd] if cmd == "version" || cmd == "--version" => Command::Version,
        [cmd, ..] if cmd == "admin" => Command::Admin,
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
    let args: Vec<String> = std::env::args().skip(1).collect();
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
    })
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
