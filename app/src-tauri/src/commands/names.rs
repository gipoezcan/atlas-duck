// The app's command names (C.10 + Δ1): one line per command, sorted. `build.rs` includes this
// file (`include!`) for the app manifest (`allow-<command>` / `deny-<command>` permissions, `_`
// written as `-`), `commands::register` lists the same functions, and `ci/check-commands.mjs`
// (Task 4) compares both with the capability files and the isolation allowlist. Plain `//`
// comments only: `include!` in `build.rs` takes items, not inner doc comments.

/// Every app command, sorted. Later tasks append one line each.
#[rustfmt::skip]
pub const COMMANDS: &[&str] = &[
    "acknowledge_attention",
    "app_status",
    "archive_and_start_fresh",
    "credential_context",
    "decide",
    "decide_batch",
    "deny_batch",
    "deny_session",
    "open_window",
    "preview_fetch",
    "queue_get",
    "queue_list",
    "quit",
    "raw_page",
    "recent_list",
    "redaction_preview",
    "retry_keychain",
    "save_recovery_note",
    "submit_secret",
];
