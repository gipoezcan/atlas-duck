//! The `atlas-duck` binary's library: CLI + MCP server (§2.2).
//!
//! §2.2: depends only on `ipc` + `registry`. §2.1: never touches keychain or DB.
//! M1 has no commands: every invocation prints the §4.2 usage envelope and exits 2.

use std::ffi::OsString;
use std::io::Write;

use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, exit};

/// `error.message` of the M1 usage envelope (plan text; the spec fixes only status, code and exit).
pub const USAGE_MESSAGE: &str = "unknown command: this atlas-duck build has no commands yet";

/// Runs the CLI. `args` excludes the program name (and, under the app's `__cli` dispatch, the
/// marker). Prints exactly one envelope line on stdout and returns the process exit code (§4.3).
pub fn run(_args: Vec<OsString>) -> i32 {
    // §3.3: build_id is compiled into every binary (M4's `hello` sends it). black_box keeps the
    // constant referenced, so the linker cannot drop it from the executable.
    let _ = std::hint::black_box(BUILD_ID);
    let line = Envelope::failed(ErrorCode::Usage, false, USAGE_MESSAGE).to_json_line();
    let mut out = std::io::stdout().lock();
    match out.write_all(line.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => exit::USAGE_VALIDATION,
        Err(_) => exit::FAILED_INTERNAL,
    }
}
