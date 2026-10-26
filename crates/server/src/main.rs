//! `atlas-duck-server`: the server-mode binary (SM-1.2).

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    atlas_duck_server::cli::main()
}
