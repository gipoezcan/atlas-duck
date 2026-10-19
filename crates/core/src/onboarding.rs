//! The onboarding page (§12.4, PD-80, PD-175): copy-paste instructions for an agent's
//! CLAUDE.md / AGENTS.md, one independent section per topic, generated from the registry, the
//! `ipc::proto::EXIT_MATRIX` table and the spec's own sentences. The `scripts` and `mcp`
//! sections (script API reference, MCP config) are built on M8/M9 output and are added by M10's
//! D3.
//!
//! The rule sentences are the spec's words (§12.4), not paraphrases: the tests compare this text
//! with the spec file.

use std::fmt::Write as _;

use atlas_duck_ipc::envelope::{ErrorCode, Status, exit};
use atlas_duck_ipc::proto::EXIT_MATRIX;
use atlas_duck_registry as registry;

/// §12.4 bullet "approvals take human time" (verbatim).
pub const RULE_TIMEOUT: &str = "approvals take human time: set `--timeout` at least 10 s below your tool's kill timeout (e.g. `--timeout 100` under a 120 s tool; it counts from CLI start, including an app launch), or use `--timeout 0` and `await`; the request id and `params_sha256` are printed to stderr on submit; **never resubmit a pending request — if the id was lost, find it with `requests list --match-params-file <same params>` and `await` it**";

/// §12.4 bullet "ATLAS_DUCK_AGENT" (verbatim).
pub const RULE_AGENT: &str = "set `ATLAS_DUCK_AGENT=<tool>-<repo>` once per session (e.g. `claude-code-billing-api`) and always pass `--reason`, so the approver can tell sessions apart";

/// §12.4 bullet "results may be redacted or edited" (verbatim).
pub const RULE_REDACTED: &str = "results may be redacted or edited — check `redacted`, `edited`, `meta`. A key missing from an item while named in `meta.redactions.fields_dropped` means withheld, not empty (a real `null` is the server's). If a write comes back `edited: true`, check `edited_keys` and re-read the target before any follow-up edit";

/// §12.4 bullet "with several pending ids" (verbatim).
pub const RULE_PENDING_IDS: &str = "with several pending ids, use `requests list --agent <name>` to see which are decided, `await` only those, and do other work in between; `status` never blocks and never returns data";

/// §12.4 bullet "for the next page" (verbatim).
pub const RULE_PAGING: &str = "for the next page, continue **only** from `meta.page.next_start` (never `start + returned`; redacted items would come back as new approvals); `total` is the server's total";

/// §12.4 bullet "for writes, submit human names" (verbatim).
pub const RULE_WRITES: &str = "for writes, submit human names (project, issue type, transition, user, link type, parent page); the app resolves and validates them — do not pre-read createmeta, transitions or assignable users; if you need metadata, fetch it in one script";

/// §12.4 bullet "batch many reads" (verbatim).
pub const RULE_BATCH: &str =
    "batch many reads into one script instead of many parallel calls; on exit 11 back off";

/// §12.4 bullet "run every new or changed script" (verbatim).
pub const RULE_DRY_RUN: &str = "run every new or changed script with `--dry-run=sparse` and `--dry-run=full` first (no approval needed; results come from documented examples, `meta.dry_run: true`), then run it for real once";

/// §12.4 bullet "branch on `status`" (verbatim).
pub const RULE_STATUS: &str = "branch on `status` + `error.code` + `error.retryable`, never on the exit code alone. Resubmit only if `retryable` is true, with these exceptions: `denied` — resubmit (changed) only if the message asks for a change; `expired` — only if the user asks; `resolution_failed` — fix the named param. `pending` (exit 4, also after `connection_lost`) — `await` the id, never resubmit";

/// §12.4 bullet "on `outcome_unknown`" (verbatim).
pub const RULE_OUTCOME_UNKNOWN: &str = "on `outcome_unknown`, check the target before retrying";

/// §12.4 bullet "on exit 9" (verbatim).
pub const RULE_EXIT_9: &str = "on exit 9 (`locked`, `needs_token`, `not_configured`), do not retry in a loop: tell the user what the app needs (unlock, recover, re-enter the token, configure), wait until they confirm, then retry once";

/// §12.4 bullet "Confluence pages with macros", first sentence (verbatim). The second sentence
/// is the registry's `CONFLUENCE_PLACEHOLDER_GUIDANCE` (PD-112), appended where the section is
/// built.
pub const RULE_CONFLUENCE_MACROS: &str =
    "Confluence pages with macros: edit with `body_format=storage`.";

/// §12.4 bullet "if `jira.issue.create` is denied" (verbatim).
pub const RULE_CREATE_FIELDS: &str = "if `jira.issue.create` is denied with `error.details.missing_fields`, supply those fields via `--field id=<json>` / `fields` and reuse them for later creates in the same project and issue type";

/// §12.4 bullet "page update requires `base_version`" (verbatim).
pub const RULE_CONFLICTS: &str = "page update requires `base_version` = the `version.number` you read; for issue edits pass `expected` with the values you read for each edited field. If someone changed the target since, the request is denied: re-read and resubmit";

/// §12.4 bullet "pass file paths" (verbatim; the spec's line is not quoted).
pub const RULE_WINDOWS_PATHS: &str =
    "pass file paths rather than piping through Windows PowerShell 5.1";

/// §12.4 bullet "agents in WSL (Windows)" (verbatim).
pub const RULE_WSL: &str = "agents in WSL (Windows): call the Windows `atlas-duck.exe` through WSL interop, pass Windows paths (`wslpath -w <file>`) or use stdin, and never install the Linux package inside WSL (it would be a second app with its own credentials and audit log). Agents in containers, VMs or on other hosts are not supported; a same-host SSH session works only while the app is already running on the desktop (§1.3, §4.7)";

/// One independent section of the page: the user copies each on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Stable id (PD-175).
    pub id: &'static str,
    /// Heading the window shows.
    pub title: &'static str,
    /// Plain text (Markdown the user pastes); the window shows it as a text node.
    pub text: String,
}

fn bullets(rules: &[&str]) -> String {
    let mut out = String::new();
    for rule in rules {
        let _ = writeln!(out, "- {rule}");
    }
    out
}

fn name<T: serde::Serialize>(v: T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The same usage lines `atlas-duck --help` prints: one table, one formatter.
fn commands() -> String {
    let mut out = String::new();
    for g in registry::GENERIC_COMMANDS {
        let _ = writeln!(out, "- `{}`", g.usage);
    }
    for spec in registry::all() {
        let _ = writeln!(out, "- `{}`", registry::op_usage(spec));
    }
    out
}

fn envelope() -> String {
    "Every call prints exactly one JSON object on stdout with the keys `request_id`, `op_id`, \
     `instance`, `status`, `data`, `edited`, `redacted`, `redaction_note`, `message`, `error` \
     and `meta`; an absent value is `null`. `error` is `{code, retryable, message, details?}`. \
     The exit code is a summary of the envelope: see the exit matrix.\n"
        .to_owned()
}

/// The §4.3 matrix as `ipc::proto::EXIT_MATRIX` states it, one line per exit code.
fn exit_matrix() -> String {
    let mut out = String::from(
        "Exit code by `status` and `error.code`. `status/code` is that status with that \
         `error.code`; a bare `status` is that status with any other code, or with none.\n\n",
    );
    let mut exits: Vec<i32> = EXIT_MATRIX.iter().map(|(_, _, e)| *e).collect();
    exits.sort_unstable();
    exits.dedup();
    for n in exits {
        let items: Vec<String> = EXIT_MATRIX
            .iter()
            .filter(|(_, _, e)| *e == n)
            .map(|(s, c, _)| match c {
                Some(c) => format!("`{}/{}`", name::<Status>(*s), name::<ErrorCode>(*c)),
                None => format!("`{}`", name::<Status>(*s)),
            })
            .collect();
        let _ = writeln!(out, "- exit {n}: {}", items.join(", "));
    }
    let _ = write!(
        out,
        "\n`result_evicted` wins over every status (exit {}). A `succeeded` or `released` \
         envelope whose `data` holds `script_error` exits {}.\n",
        exit::RESULT_EVICTED,
        exit::SCRIPT,
    );
    out
}

fn confluence() -> String {
    bullets(&[&format!(
        "{RULE_CONFLUENCE_MACROS} {}",
        registry::CONFLUENCE_PLACEHOLDER_GUIDANCE
    )])
}

/// The page's sections (PD-175), in the order the window lists them. `scripts` and `mcp` are
/// D3's.
pub fn sections() -> Vec<Section> {
    let section = |id, title, text| Section { id, title, text };
    vec![
        section("commands", "Commands", commands()),
        section("envelope", "The envelope", envelope()),
        section("exit_matrix", "Exit codes", exit_matrix()),
        section("timeouts", "Timeouts and waiting", bullets(&[RULE_TIMEOUT])),
        section("sessions", "Sessions", bullets(&[RULE_AGENT])),
        section(
            "redaction",
            "Redacted and edited results",
            bullets(&[RULE_REDACTED]),
        ),
        section(
            "parallel",
            "Several requests at once",
            bullets(&[RULE_PENDING_IDS, RULE_BATCH, RULE_DRY_RUN]),
        ),
        section("paging", "Paging", bullets(&[RULE_PAGING])),
        section("writes", "Writes", bullets(&[RULE_WRITES])),
        section("retry", "Reading the status", bullets(&[RULE_STATUS])),
        section(
            "outcome_unknown",
            "Unknown outcome",
            bullets(&[RULE_OUTCOME_UNKNOWN]),
        ),
        section("exit9", "Exit 9", bullets(&[RULE_EXIT_9])),
        section("confluence", "Confluence pages", confluence()),
        section(
            "create_fields",
            "Creating issues",
            bullets(&[RULE_CREATE_FIELDS]),
        ),
        section(
            "conflicts",
            "Editing what changed meanwhile",
            bullets(&[RULE_CONFLICTS]),
        ),
        section(
            "windows_paths",
            "Windows PowerShell",
            bullets(&[RULE_WINDOWS_PATHS]),
        ),
        section("wsl", "WSL and other hosts", bullets(&[RULE_WSL])),
    ]
}

/// The whole page as one Markdown text: every section under its heading.
pub fn text() -> String {
    let mut out =
        String::from("# atlas-duck\n\nJira and Confluence go through the `atlas-duck` CLI.\n\n");
    for s in sections() {
        let _ = write!(out, "## {}\n\n{}\n", s.title, s.text);
    }
    out
}
