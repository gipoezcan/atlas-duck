//! `--help` text (PD-12): the generic commands, the noun tree generated from every op's
//! `CliBinding.noun_path`, the global flags and, for a full op path, the op's usage from
//! `describe(..)["cli"]["usage"]`.

use std::fmt::Write;

use atlas_duck_registry::{
    GENERIC_COMMANDS, GenericCommand, OperationSpec, all, describe, op_usage,
};
use serde_json::Value;

use crate::binding::alias_help;
use crate::local::describe_env;

const GLOBAL_FLAGS: &str = "\
Global flags (accepted anywhere before `--`):
  --agent NAME         your agent name (or ATLAS_DUCK_AGENT)
  --reason TEXT        why you are asking; shown in the approval dialog and logged
  --timeout SECONDS    wall-clock limit from process start (default 100; 0 = submit and return pending)
  --instance ALIAS     the Jira or Confluence instance to use
  --output json|text   json (default) is the agent contract; text renders data for people
  --help               show this help";

/// `atlas-duck mcp --help` (PD-116): its own flags, not the generic block.
const MCP_HELP: &str = "\
Usage: atlas-duck mcp [--tools full|generic] [--instance ALIAS] [--agent NAME]

Serve the operations as MCP tools on stdio. stdout carries only JSON-RPC frames.

Flags:
  --tools full|generic  full (default): one tool per operation, plus script_run, request_await,
                        request_status, request_cancel, request_list, ops_list, ops_describe
                        and instances_list; generic: only `call` plus those eight, for
                        clients that limit the number of tools
  --instance ALIAS      the Jira or Confluence instance to use when a tool call names none
  --agent NAME          your agent name (or ATLAS_DUCK_AGENT); overrides the MCP client's name
  --help                show this help

Environment:
  ATLAS_DUCK_MCP_TIMEOUT  seconds a tool call waits for a decision before it returns pending
                          (default 50; 0 = submit and return pending at once)
  ATLAS_DUCK_AGENT        your agent name when --agent is not given

Pass `reason` in each tool call.

After an atlas-duck upgrade, restart the MCP server.
";

/// `atlas-duck verify-export --help` (§12.1): the app's verifier, run as a child process; no
/// envelope, no global flags.
const VERIFY_EXPORT_HELP: &str = "\
Usage: atlas-duck verify-export <dir> [--anchor-dir <dir>] [--manifest-sha256 <64 lowercase hex>]

Verify an audit export directory offline. Needs no running app, no keychain and no key; it
reads only <dir> and the anchor directory. The report goes to stdout (no JSON envelope).

Flags:
  --anchor-dir <dir>            the anchor directory the export was anchored to
  --manifest-sha256 <hex>       the SHA-256 of manifest.json, obtained from the exporter
  --help                        show this help

verify-export must be the first argument; the global flags do not apply to it.
A --help or -h anywhere shows this help, so a directory named like a flag needs a path prefix
(./--help).
A directory ending in .partial is an incomplete export and is refused: rename it after an
interrupted export once you know it is complete.

Exit codes:
  0   verified against a trust root you supplied
  20  internally consistent, but no trust root covers the whole export
  21  tampering or a fork detected
  22  usage or I/O error, or the atlas-duck app was not found
";

/// JSON given on the command line or in a file is read by serde_json.
const JSON_NOTE: &str = "JSON notes: an integer above 18446744073709551615 (u64::MAX) is rounded to a float, and when an
object repeats a key the last one wins.
";

fn starts_with(path: &[&str], prefix: &[String]) -> bool {
    prefix.len() <= path.len() && path.iter().zip(prefix).all(|(a, b)| a == b)
}

fn push_section(out: &mut String, title: &str, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    let _ = writeln!(out, "{title}:");
    for line in lines {
        let _ = writeln!(out, "  {line}");
    }
    out.push('\n');
}

fn top_level() -> String {
    let mut out =
        String::from("atlas-duck: reach Jira and Confluence through the approval app\n\n");
    out.push_str("Usage: atlas-duck <command> [flags]\n\n");
    let generic: Vec<String> = GENERIC_COMMANDS
        .iter()
        .map(|g| format!("{:<16} {}", g.path.join(" "), g.summary))
        .collect();
    let mut generic = generic;
    // Not a registry command (the app's verifier runs as a child process, §12.1).
    generic.push(format!(
        "{:<16} verify an audit export directory offline; the global flags do not apply (atlas-duck verify-export --help)",
        "verify-export"
    ));
    push_section(&mut out, "Commands", &generic);
    let ops: Vec<String> = all().iter().map(|s| s.cli.noun_path.join(" ")).collect();
    push_section(
        &mut out,
        "Operations (atlas-duck <path> --help for flags)",
        &ops,
    );
    out.push_str(GLOBAL_FLAGS);
    out.push('\n');
    out
}

fn op_detail(spec: &OperationSpec) -> String {
    let d = describe(spec, &describe_env());
    let text = |v: &Value| v.as_str().unwrap_or_default().to_owned();
    let mut out = String::new();
    let _ = writeln!(out, "{}\n", text(&d["cli"]["usage"]));
    let _ = writeln!(
        out,
        "{} ({}; approval: {})",
        spec.id,
        text(&d["class"]),
        text(&d["approval"])
    );
    let description = text(&d["description"]);
    if !description.is_empty() {
        let _ = writeln!(out, "{description}");
    }
    out.push('\n');
    let flags: Vec<String> = d["cli"]["flags"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| {
            format!(
                "{:<24} {} ({})",
                text(&f["flag"]),
                text(&f["param"]),
                text(&f["kind"])
            )
        })
        .collect();
    push_section(&mut out, "Flags", &flags);
    push_section(&mut out, "Also accepted", &alias_help(spec));
    let _ = writeln!(out, "Example: {}", text(&d["examples"]["cli"]));
    let _ = writeln!(out, "Details: atlas-duck ops describe {}\n", spec.id);
    out.push_str(GLOBAL_FLAGS);
    out.push('\n');
    out
}

/// The help text for a command path; `None` when the path names nothing.
pub(crate) fn help_text(path: &[String]) -> Option<String> {
    let first = path.first().map(String::as_str);
    if path.is_empty() || path == ["help"] {
        return Some(top_level());
    }
    // Before the generic-command branch below, which would append `GLOBAL_FLAGS`: `--timeout`,
    // `--reason` and `--output` are refused by `mcp` (PD-116).
    if first == Some("mcp") {
        return Some(MCP_HELP.to_owned());
    }
    if first == Some("verify-export") {
        return Some(VERIFY_EXPORT_HELP.to_owned());
    }
    let mut out = String::new();
    let generic: Vec<&GenericCommand> = GENERIC_COMMANDS
        .iter()
        .filter(|g| starts_with(g.path, path))
        .collect();
    if !generic.is_empty() {
        let lines: Vec<String> = generic.iter().map(|g| g.usage.to_owned()).collect();
        push_section(&mut out, "Usage", &lines);
        if generic
            .iter()
            .any(|g| g.usage.contains("json") || g.usage.contains("-file"))
        {
            out.push_str(JSON_NOTE);
            out.push('\n');
        }
        out.push_str(GLOBAL_FLAGS);
        out.push('\n');
        return Some(out);
    }
    let specs: Vec<&OperationSpec> = all()
        .iter()
        .filter(|s| starts_with(s.cli.noun_path, path))
        .collect();
    match specs.as_slice() {
        [] => None,
        [spec] if spec.cli.noun_path.len() == path.len() => Some(op_detail(spec)),
        many => {
            let lines: Vec<String> = many.iter().map(|s| op_usage(s)).collect();
            push_section(&mut out, "Usage", &lines);
            out.push_str(GLOBAL_FLAGS);
            out.push('\n');
            Some(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn every_op_has_help_with_its_usage_line() {
        for spec in all() {
            let usage = op_usage(spec);
            assert!(!usage.is_empty(), "{}", spec.id);
            let words: Vec<String> = spec.cli.noun_path.iter().map(|w| (*w).to_owned()).collect();
            let text = help_text(&words).unwrap_or_default();
            assert!(text.contains(&usage), "{}: {text}", spec.id);
        }
    }

    #[test]
    fn top_level_lists_commands_nouns_and_global_flags() {
        let text = help_text(&[]).unwrap_or_default();
        assert_eq!(help_text(&path(&["help"])), Some(text.clone()));
        for needle in [
            "ops list",
            "requests list",
            "jira issue get",
            "--timeout",
            "--output",
        ] {
            assert!(text.contains(needle), "{needle}");
        }
    }

    /// I-1: `verify-export` is not a registry command, but the top-level help names it, and says
    /// the global flags do not apply to it.
    #[test]
    fn top_level_lists_verify_export() {
        let text = help_text(&[]).unwrap_or_default();
        let line = text
            .lines()
            .find(|l| l.trim_start().starts_with("verify-export"))
            .unwrap_or_default();
        assert!(line.contains("verify-export --help"), "{text}");
        assert!(line.contains("global flags do not apply"), "{line}");
        // In the Commands section, before the operations.
        let at = |needle: &str| text.find(needle).unwrap_or(usize::MAX);
        assert!(at("verify-export") < at("Operations"), "{text}");
    }

    /// M-6: a directory named like a flag needs `./`.
    #[test]
    fn verify_export_help_says_flag_like_directories_need_a_dot_slash() {
        let text = help_text(&path(&["verify-export"])).unwrap_or_default();
        assert!(text.contains("./--help"), "{text}");
    }

    #[test]
    fn noun_prefix_lists_its_ops() {
        let text = help_text(&path(&["jira", "issue"])).unwrap_or_default();
        assert!(text.contains("atlas-duck jira issue get"));
        assert!(!text.contains("atlas-duck confluence"));
        assert!(
            help_text(&path(&["ops"]))
                .unwrap_or_default()
                .contains("ops describe")
        );
    }

    #[test]
    fn op_help_lists_alias_spellings_and_json_notes() {
        let text = help_text(&path(&["confluence", "attachment", "upload"])).unwrap_or_default();
        assert!(text.contains("Also accepted"), "{text}");
        assert!(text.contains("RAW bytes"), "{text}");
        let text = help_text(&path(&["call"])).unwrap_or_default();
        assert!(text.contains("last one wins"), "{text}");
    }

    #[test]
    fn unknown_path_has_no_help() {
        assert_eq!(help_text(&path(&["nope"])), None);
        assert_eq!(help_text(&path(&["jira", "nope"])), None);
    }
}
