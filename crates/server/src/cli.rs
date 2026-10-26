//! Command line: `serve`, `version` (plan "Configuration", exit codes).

use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "usage: atlas-duck-server <serve|version>\n";

/// Entry point of the binary. Exit codes: 0 clean, 1 runtime failure, 2 usage, 78 configuration.
pub fn main() -> ExitCode {
    // A failed write to stderr changes nothing about the exit code.
    let _ = std::io::stderr().write_all(USAGE.as_bytes());
    ExitCode::from(2)
}
