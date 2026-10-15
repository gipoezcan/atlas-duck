//! §12.4 / PD-80: the onboarding snippet carries the spec's rule sentences verbatim, and one
//! command line per registry operation.

use atlas_duck_core::onboarding::{RULES, text};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SPEC: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/superpowers/specs/2026-10-07-atlas-duck-design.md"
);

/// The quoted sentence of every §12.4 bullet: between the first and the last `"` of the line.
fn spec_rules() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let spec = std::fs::read_to_string(SPEC)?;
    let section = spec
        .split("### 12.4 Agent onboarding")
        .nth(1)
        .and_then(|rest| rest.split("### 12.5").next())
        .ok_or("no §12.4 in the spec")?;
    Ok(section
        .lines()
        .filter(|l| l.starts_with("- \""))
        .filter_map(|l| {
            let (first, last) = (l.find('"')?, l.rfind('"')?);
            (last > first).then(|| l[first + 1..last].to_owned())
        })
        .collect())
}

#[test]
fn onboarding_text_contains_verbatim_rules() -> TestResult {
    let snippet = text();
    let spec = spec_rules()?;
    assert!(
        spec.len() >= 10,
        "the spec parse found {} bullets",
        spec.len()
    );
    // Every rule the snippet lists is a bullet of §12.4, word for word...
    for rule in RULES {
        assert!(spec.iter().any(|s| s == rule), "not in the spec: {rule}");
        assert!(snippet.contains(rule), "not in the snippet: {rule}");
    }
    // ...and the PD-80 four are among them (the spec's own text, found by its opening words).
    for opening in [
        "approvals take human time",
        "branch on `status`",
        "set `ATLAS_DUCK_AGENT=",
    ] {
        let from_spec = spec
            .iter()
            .find(|s| s.starts_with(opening))
            .ok_or("bullet missing in the spec")?;
        assert!(snippet.contains(from_spec.as_str()), "{opening}");
    }
    assert!(snippet.contains("never resubmit a pending request"));
    assert!(snippet.contains("`--timeout`"));
    Ok(())
}

#[test]
fn onboarding_text_lists_every_registry_command() {
    let snippet = text();
    for spec in atlas_duck_registry::all() {
        let name = format!("atlas-duck {}", spec.cli.noun_path.join(" "));
        assert!(snippet.contains(&name), "{name}");
    }
    assert!(snippet.contains("atlas-duck await <request_id>"));
}
