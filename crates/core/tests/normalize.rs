//! §3.3 agent-string normalization (S-13 core half).

use atlas_duck_core::normalize::{
    MAX_AGENT_NAME_CHARS, MAX_CWD_BASENAME_CHARS, MAX_REASON_CHARS, normalize_agent_name,
    normalize_hello, normalize_reason,
};
use atlas_duck_ipc::proto::{AgentNameSource, ClientKind, Hello};
use atlas_duck_preview::invisible::strip;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// §13 S-13 input (the same constant as `crates/preview/tests/invisible.rs`): ESC, NEL, U+3164,
/// U+E0041, U+202E, the ZWJ sequence 👩‍🚀 and ❤️ (U+FE0F).
const S13: &str = "a\u{1B}b\u{85}c\u{3164}d\u{E0041}e\u{202E}f👩\u{200D}🚀g❤\u{FE0F}h";

fn hello(agent_name: Option<&str>, cwd_basename: &str) -> Hello {
    Hello {
        build_id: "0.1.0+000000000000".to_owned(),
        client_kind: ClientKind::Cli,
        agent_name: agent_name.map(str::to_owned),
        agent_name_source: AgentNameSource::Flag,
        cwd_basename: cwd_basename.to_owned(),
    }
}

#[test]
fn s13_agent_string_stripping_matches_classifier() -> TestResult {
    let expected = strip(S13, false).0;
    assert_eq!(expected, "abcdef👩\u{200D}🚀g❤\u{FE0F}h");

    let n = normalize_hello(&hello(Some(S13), "proj"));
    assert_eq!(n.agent_name.as_deref(), Some(expected.as_str()));
    assert!(n.unusual);

    let n = normalize_hello(&hello(Some("claude"), S13));
    assert_eq!(n.agent_name.as_deref(), Some("claude"));
    assert_eq!(n.cwd_basename, expected);
    assert!(n.unusual);

    // `\t`, `\r` and `\n` go in names; `reason` keeps `\n` only.
    let input = format!("{S13}\nline two\t\r");
    let (name, unusual) = normalize_agent_name(&input);
    assert_eq!(name, format!("{expected}line two"));
    assert!(unusual);
    let (reason, unusual) = normalize_reason(&input);
    assert_eq!(reason, format!("{}\nline two", expected));
    assert_eq!(reason, strip(&input, true).0);
    assert!(unusual);
    Ok(())
}

#[test]
fn clean_strings_are_not_unusual() -> TestResult {
    let n = normalize_hello(&hello(Some("codex-cli"), "atlas-duck"));
    assert_eq!(n.agent_name.as_deref(), Some("codex-cli"));
    assert_eq!(n.cwd_basename, "atlas-duck");
    assert!(!n.unusual);

    let n = normalize_hello(&hello(None, "Müller Plan 👩\u{200D}🚀"));
    assert_eq!(n.agent_name, None);
    assert_eq!(n.cwd_basename, "Müller Plan 👩\u{200D}🚀");
    assert!(!n.unusual);

    let (r, unusual) = normalize_reason("first line\nsecond line");
    assert_eq!(r, "first line\nsecond line");
    assert!(!unusual);
    Ok(())
}

#[test]
fn limits_truncate_and_flag() -> TestResult {
    assert_eq!(MAX_AGENT_NAME_CHARS, 64);
    assert_eq!(MAX_CWD_BASENAME_CHARS, 64);
    assert_eq!(MAX_REASON_CHARS, 1_000);

    let name65 = "a".repeat(65);
    let n = normalize_hello(&hello(Some(&name65), "x"));
    assert_eq!(n.agent_name.as_deref(), Some("a".repeat(64).as_str()));
    assert!(n.unusual);

    let name64 = "a".repeat(64);
    let n = normalize_hello(&hello(Some(&name64), "x"));
    assert_eq!(n.agent_name.as_deref(), Some(name64.as_str()));
    assert!(!n.unusual);

    // Unicode scalars, not bytes: 65 × 'ü' (2 bytes each) → 64 scalars.
    let n = normalize_hello(&hello(None, &"ü".repeat(65)));
    assert_eq!(n.cwd_basename, "ü".repeat(64));
    assert!(n.unusual);

    let (r, unusual) = normalize_reason(&"r".repeat(1_001));
    assert_eq!(r.chars().count(), 1_000);
    assert!(unusual);
    let (r, unusual) = normalize_reason(&"r".repeat(1_000));
    assert_eq!(r.chars().count(), 1_000);
    assert!(!unusual);

    // The limit applies after stripping: 64 visible chars plus invisible ones are not cut.
    let padded = format!("{}\u{202E}", "b".repeat(64));
    let (name, unusual) = normalize_agent_name(&padded);
    assert_eq!(name, "b".repeat(64));
    assert!(unusual);
    Ok(())
}
