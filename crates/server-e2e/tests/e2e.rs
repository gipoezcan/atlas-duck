//! The black-box server e2e suite (M14 PD-260). Task 23 adds the cases; until its environment is
//! set the binary prints its usage and exits 2, so it never runs by accident.

use std::process::ExitCode;

const USAGE: &str = "usage: ATLAS_DUCK_E2E_BASE_URL=<url> ATLAS_DUCK_E2E_USERS_FILE=<file> \
[ATLAS_DUCK_E2E_CA_FILE=<pem>] [ATLAS_DUCK_E2E_JIRA=mock|none] cargo test -p atlas-duck-server-e2e";

fn main() -> ExitCode {
    let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    if !set("ATLAS_DUCK_E2E_BASE_URL") || !set("ATLAS_DUCK_E2E_USERS_FILE") {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    eprintln!("no cases yet");
    ExitCode::from(1)
}
