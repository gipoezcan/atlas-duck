//! §12.4 / PD-80 / PD-175: the onboarding page carries the spec's sentences verbatim, one
//! command line per registry operation and the exit matrix of the envelope table.

use atlas_duck_core::onboarding::{
    RULE_STATUS, RULE_TIMEOUT, RULE_WRITES, Section, sections, text,
};
use atlas_duck_ipc::envelope::{ErrorCode, Status};
use atlas_duck_ipc::proto::EXIT_MATRIX;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SPEC: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/superpowers/specs/2026-10-07-atlas-duck-design.md"
);

fn spec_section() -> Result<String, Box<dyn std::error::Error>> {
    let spec = std::fs::read_to_string(SPEC)?;
    spec.split("### 12.4 Agent onboarding")
        .nth(1)
        .and_then(|rest| rest.split("### 12.5").next())
        .map(str::to_owned)
        .ok_or_else(|| "no §12.4 in the spec".into())
}

/// The quoted sentence of every §12.4 bullet: between the first and the last `"` of the line.
fn spec_rules() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(spec_section()?
        .lines()
        .filter(|l| l.starts_with("- \""))
        .filter_map(|l| {
            let (first, last) = (l.find('"')?, l.rfind('"')?);
            (last > first).then(|| l[first + 1..last].to_owned())
        })
        .collect())
}

fn section(id: &str) -> Result<Section, Box<dyn std::error::Error>> {
    sections()
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| format!("no section {id}").into())
}

#[test]
fn x14_onboarding_states_three_rules_verbatim() -> TestResult {
    let spec = spec_rules()?;
    assert!(
        spec.len() >= 14,
        "the spec parse found {} bullets",
        spec.len()
    );
    // The three X-14 rules, each a bullet of §12.4 word for word and in its own section.
    for (id, rule, opening) in [
        ("retry", RULE_STATUS, "branch on `status`"),
        ("writes", RULE_WRITES, "for writes, submit human names"),
        ("timeouts", RULE_TIMEOUT, "approvals take human time"),
    ] {
        let from_spec = spec
            .iter()
            .find(|s| s.starts_with(opening))
            .ok_or("bullet missing in the spec")?;
        assert_eq!(rule, from_spec, "{id}: the constant is the spec's sentence");
        assert!(section(id)?.text.contains(rule), "not in section {id}");
    }
    // The timeout sentence names the 10 s margin and the never-resubmit rule.
    assert!(RULE_TIMEOUT.contains("at least 10 s below your tool's kill timeout"));
    assert!(RULE_TIMEOUT.contains("never resubmit a pending request"));
    assert!(RULE_STATUS.contains("`status` + `error.code` + `error.retryable`"));
    Ok(())
}

#[test]
fn onboarding_states_every_spec_sentence_and_lists_the_sections_once() -> TestResult {
    let all = sections();
    for rule in spec_rules()? {
        assert!(
            all.iter().any(|s| s.text.contains(&rule)),
            "not on the page: {rule}"
        );
    }
    // The unquoted bullet about Windows PowerShell, from the spec's own line.
    let windows = section("windows_paths")?;
    assert!(
        spec_section()?.contains(windows.text.trim_start_matches("- ").trim()),
        "{}",
        windows.text
    );
    let ids: Vec<&str> = all.iter().map(|s| s.id).collect();
    assert_eq!(
        ids,
        [
            "commands",
            "envelope",
            "exit_matrix",
            "timeouts",
            "sessions",
            "redaction",
            "parallel",
            "paging",
            "writes",
            "retry",
            "outcome_unknown",
            "exit9",
            "confluence",
            "create_fields",
            "conflicts",
            "windows_paths",
            "wsl",
        ]
    );
    for s in &all {
        assert!(!s.title.is_empty() && !s.text.trim().is_empty(), "{}", s.id);
    }
    // The Confluence sentence is the registry's constant (PD-112), not a copy.
    assert!(
        section("confluence")?
            .text
            .contains(atlas_duck_registry::CONFLUENCE_PLACEHOLDER_GUIDANCE)
    );
    Ok(())
}

#[test]
fn onboarding_lists_every_registry_op() -> TestResult {
    let commands = section("commands")?;
    let lines: Vec<&str> = commands
        .text
        .lines()
        .filter_map(|l| l.strip_prefix("- `").and_then(|l| l.strip_suffix('`')))
        .collect();
    assert!(!atlas_duck_registry::all().is_empty());
    for spec in atlas_duck_registry::all() {
        let usage = atlas_duck_registry::op_usage(spec);
        assert!(lines.contains(&usage.as_str()), "{usage}");
    }
    for g in atlas_duck_registry::GENERIC_COMMANDS {
        assert!(lines.contains(&g.usage), "{}", g.usage);
    }
    Ok(())
}

fn name<T: serde::Serialize>(v: T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The page's exit lines (`- exit N: `a`, `b/c``) read back as `(status, code, exit)` rows.
#[test]
fn onboarding_exit_matrix_matches_envelope_table() -> TestResult {
    let page = section("exit_matrix")?;
    let mut read: Vec<(String, Option<String>, i32)> = Vec::new();
    for line in page.text.lines() {
        let Some(rest) = line.strip_prefix("- exit ") else {
            continue;
        };
        let (n, items) = rest.split_once(": ").ok_or("exit line without a colon")?;
        let exit: i32 = n.parse()?;
        for item in items.split(", ") {
            let item = item.trim().trim_end_matches('.').trim_matches('`');
            match item.split_once('/') {
                Some((status, code)) => {
                    read.push((status.to_owned(), Some(code.to_owned()), exit));
                }
                None => read.push((item.to_owned(), None, exit)),
            }
        }
    }
    let mut want: Vec<(String, Option<String>, i32)> = EXIT_MATRIX
        .iter()
        .map(|(s, c, e)| (name(*s), c.map(name), *e))
        .collect();
    read.sort();
    want.sort();
    assert_eq!(read, want);
    assert!(read.len() > ErrorCode::ALL.len());
    assert!(read.iter().any(|(s, _, _)| *s == name(Status::Pending)));
    // The two rules outside the rows are stated.
    assert!(page.text.contains("result_evicted"));
    assert!(page.text.contains("script_error"));
    Ok(())
}

#[test]
fn onboarding_text_lists_every_command_as_the_cli_prints_it() {
    let snippet = text();
    let lines: Vec<&str> = snippet
        .lines()
        .filter_map(|l| l.strip_prefix("- `").and_then(|l| l.strip_suffix('`')))
        .collect();
    // Every registry op: the usage `ops describe` and `--help` print, placeholders included.
    for spec in atlas_duck_registry::all() {
        let usage = atlas_duck_registry::op_usage(spec);
        assert!(lines.contains(&usage.as_str()), "{usage}");
    }
    // Every generic command, from the table `--help` prints.
    for g in atlas_duck_registry::GENERIC_COMMANDS {
        assert!(lines.contains(&g.usage), "{}", g.usage);
    }
    for needle in [
        "atlas-duck script run <file|-> [--args <json>] [--limits <json>] [--dry-run[=full|sparse]]",
        "atlas-duck requests list [--agent NAME] [--state pending|recent]",
        "atlas-duck call <op-id>",
        "atlas-duck doctor",
        "atlas-duck help",
        "<id>=<json>",
        "-file <path>]",
    ] {
        assert!(snippet.contains(needle), "{needle}");
    }
}
