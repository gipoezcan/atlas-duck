// The app's command names (C.10 + Δ1): one line per command, sorted. `build.rs` includes this
// file (`include!`) for the app manifest (`allow-<command>` / `deny-<command>` permissions, `_`
// written as `-`), `commands::register` lists the same functions, and `ci/check-commands.mjs`
// (Task 4) compares both with the capability files and the isolation allowlist. Plain `//`
// comments only: `include!` in `build.rs` takes items, not inner doc comments.

/// Every app command, sorted. Later tasks append one line each.
#[rustfmt::skip]
pub const COMMANDS: &[&str] = &[
    "app_status",
    "open_window",
    "quit",
];
