//! The onboarding snippet (§12.4, PD-80): copy-paste instructions for an agent's CLAUDE.md /
//! AGENTS.md, generated from the registry. M6 ships the minimal form (commands, the envelope
//! pointer, the rules below); the full page (script API reference, MCP config) is M10's.
//!
//! The rule sentences are the spec's own words (§12.4), not paraphrases: the tests compare this
//! text with the spec file.

use std::fmt::Write as _;

use atlas_duck_registry as registry;

/// §12.4 bullet "approvals take human time", verbatim.
pub const RULE_TIMEOUT: &str = "approvals take human time: set `--timeout` at least 10 s below your tool's kill timeout (e.g. `--timeout 100` under a 120 s tool; it counts from CLI start, including an app launch), or use `--timeout 0` and `await`; the request id and `params_sha256` are printed to stderr on submit; **never resubmit a pending request — if the id was lost, find it with `requests list --match-params-file <same params>` and `await` it**";

/// §12.4 bullet "ATLAS_DUCK_AGENT", verbatim.
pub const RULE_AGENT: &str = "set `ATLAS_DUCK_AGENT=<tool>-<repo>` once per session (e.g. `claude-code-billing-api`) and always pass `--reason`, so the approver can tell sessions apart";

/// §12.4 bullet "branch on `status`", verbatim.
pub const RULE_STATUS: &str = "branch on `status` + `error.code` + `error.retryable`, never on the exit code alone. Resubmit only if `retryable` is true, with these exceptions: `denied` — resubmit (changed) only if the message asks for a change; `expired` — only if the user asks; `resolution_failed` — fix the named param. `pending` (exit 4, also after `connection_lost`) — `await` the id, never resubmit";

/// §12.4 bullet "on `outcome_unknown`", verbatim.
pub const RULE_OUTCOME_UNKNOWN: &str = "on `outcome_unknown`, check the target before retrying";

/// §12.4 bullet "on exit 9", verbatim.
pub const RULE_EXIT_9: &str = "on exit 9 (`locked`, `needs_token`, `not_configured`), do not retry in a loop: tell the user what the app needs (unlock, recover, re-enter the token, configure), wait until they confirm, then retry once";

/// Every rule above, in the order the snippet lists them.
pub const RULES: [&str; 5] = [
    RULE_TIMEOUT,
    RULE_AGENT,
    RULE_STATUS,
    RULE_OUTCOME_UNKNOWN,
    RULE_EXIT_9,
];

/// The commands the CLI offers beside the registry's operations (`atlas-duck help`).
const FIXED_COMMANDS: [&str; 8] = [
    "atlas-duck ops list",
    "atlas-duck ops describe <op>",
    "atlas-duck script run",
    "atlas-duck requests list [--agent <name>] [--match-params-file <file>]",
    "atlas-duck await <request_id>",
    "atlas-duck status <request_id>",
    "atlas-duck cancel <request_id>",
    "atlas-duck instances",
];

/// The snippet: Markdown the user copies into an agent's instruction file. Plain text; the
/// window shows it as a text node.
pub fn text() -> String {
    let mut out = String::new();
    out.push_str("# atlas-duck\n\n");
    out.push_str(
        "Jira and Confluence go through the `atlas-duck` CLI. Every call prints one JSON envelope \
         on stdout (`status`, `error`, `data`, `meta`); the exit code is a summary of it.\n\n",
    );
    out.push_str("## Commands\n\n");
    for line in FIXED_COMMANDS {
        let _ = writeln!(out, "- `{line}`");
    }
    for spec in registry::all() {
        let _ = writeln!(out, "- `{}`", command_line(spec));
    }
    out.push_str("\n## Rules\n\n");
    for rule in RULES {
        let _ = writeln!(out, "- {rule}");
    }
    out
}

/// `atlas-duck <noun path> [<positional>] [--flag ...]` of one operation.
fn command_line(spec: &registry::OperationSpec) -> String {
    let mut line = format!("atlas-duck {}", spec.cli.noun_path.join(" "));
    if let Some(p) = spec.cli.positional {
        let _ = write!(line, " <{p}>");
    }
    for f in spec.cli.flags {
        let _ = write!(line, " [{}]", f.flag);
    }
    line
}
