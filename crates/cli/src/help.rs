//! `--help` text (PD-12): the generic commands, the noun tree generated from every op's
//! `CliBinding.noun_path`, the global flags and, for a full op path, the op's usage from
//! `describe(..)["cli"]["usage"]`.

use std::fmt::Write;

use atlas_duck_registry::{OperationSpec, all, describe};
use serde_json::Value;

use crate::local::describe_env;

const GLOBAL_FLAGS: &str = "\
Global flags (accepted anywhere before `--`):
  --agent NAME         your agent name (or ATLAS_DUCK_AGENT)
  --reason TEXT        why you are asking; shown in the approval dialog and logged
  --timeout SECONDS    wall-clock limit from process start (default 100; 0 = submit and return pending)
  --instance ALIAS     the Jira or Confluence instance to use
  --output json|text   json (default) is the agent contract; text renders data for people
  --help               show this help";

/// One generic (non-registry) command: its path, usage line and one-line summary.
struct Generic {
    path: &'static [&'static str],
    usage: &'static str,
    summary: &'static str,
}

const GENERIC: &[Generic] = &[
    Generic {
        path: &["call"],
        usage: "atlas-duck call <op-id> (--params '<json>' | --params-file <path|->)",
        summary: "Run any operation with a JSON params object",
    },
    Generic {
        path: &["script", "run"],
        usage: "atlas-duck script run <file|-> [--args <json>] [--limits <json>] [--dry-run[=full|sparse]]",
        summary: "Run a script in the sandbox",
    },
    Generic {
        path: &["ops", "list"],
        usage: "atlas-duck ops list [--instance ALIAS]",
        summary: "List every operation",
    },
    Generic {
        path: &["ops", "describe"],
        usage: "atlas-duck ops describe <op-id> [--instance ALIAS]",
        summary: "Describe one operation: params schema, flags, caps, examples",
    },
    Generic {
        path: &["instances"],
        usage: "atlas-duck instances",
        summary: "List the configured instances",
    },
    Generic {
        path: &["await"],
        usage: "atlas-duck await <id>",
        summary: "Wait for a request to finish",
    },
    Generic {
        path: &["status"],
        usage: "atlas-duck status <id>",
        summary: "Show a request's current state without waiting",
    },
    Generic {
        path: &["cancel"],
        usage: "atlas-duck cancel <id>",
        summary: "Cancel a pending request",
    },
    Generic {
        path: &["requests", "list"],
        usage: "atlas-duck requests list [--agent NAME] [--state pending|recent] [--match-params-file <path|->]",
        summary: "List requests (metadata only)",
    },
    Generic {
        path: &["doctor"],
        usage: "atlas-duck doctor",
        summary: "Install and connectivity diagnostics",
    },
    Generic {
        path: &["help"],
        usage: "atlas-duck help [command...]",
        summary: "Show this help",
    },
];

fn starts_with(path: &[&str], prefix: &[String]) -> bool {
    prefix.len() <= path.len() && path.iter().zip(prefix).all(|(a, b)| a == b)
}

fn op_usage(spec: &OperationSpec) -> String {
    let d = describe(spec, &describe_env());
    d["cli"]["usage"].as_str().unwrap_or_default().to_owned()
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
    let generic: Vec<String> = GENERIC
        .iter()
        .map(|g| format!("{:<16} {}", g.path.join(" "), g.summary))
        .collect();
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
    if let Some(name @ ("mcp" | "verify-export")) = first {
        return Some(format!("{name}: not available in this build\n"));
    }
    let mut out = String::new();
    let generic: Vec<&Generic> = GENERIC
        .iter()
        .filter(|g| starts_with(g.path, path))
        .collect();
    if !generic.is_empty() {
        let lines: Vec<String> = generic.iter().map(|g| g.usage.to_owned()).collect();
        push_section(&mut out, "Usage", &lines);
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
    fn unknown_path_has_no_help() {
        assert_eq!(help_text(&path(&["nope"])), None);
        assert_eq!(help_text(&path(&["jira", "nope"])), None);
    }
}
