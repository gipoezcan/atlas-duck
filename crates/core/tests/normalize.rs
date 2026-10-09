//! §3.3 agent-string normalization (S-13 core half).

use atlas_duck_core::normalize::{
    MAX_AGENT_NAME_CHARS, MAX_CWD_BASENAME_CHARS, MAX_REASON_CHARS, normalize_agent_name,
    normalize_cwd_basename, normalize_hello, normalize_reason,
};
use atlas_duck_ipc::proto::{AgentNameSource, ClientKind, Hello};
use atlas_duck_preview::invisible::strip;
use proptest::prelude::*;

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

/// A cut through an RGI sequence must not leave a character the classifier flags (§3.3).
#[test]
fn cut_never_leaves_a_flagged_char() -> TestResult {
    let zwj = format!("{}👩\u{200D}🚀", "a".repeat(62));
    let (out, unusual) = normalize_agent_name(&zwj);
    assert_eq!(out, format!("{}👩", "a".repeat(62)));
    assert!(unusual);
    assert!(!strip(&out, false).1);
    assert_eq!(normalize_agent_name(&out), (out.clone(), false));

    // A five-scalar ZWJ family sequence across the cut, at every offset.
    let family = "👨\u{200D}👩\u{200D}👧";
    assert!(!strip(family, false).1);
    for pad in 60..64 {
        let input = format!("{}{family}", "a".repeat(pad));
        let (out, unusual) = normalize_cwd_basename(&input);
        assert!(!strip(&out, false).1, "pad {pad}: {out:?}");
        assert!(out.chars().count() <= 64);
        assert!(unusual);
        assert_eq!(normalize_cwd_basename(&out), (out.clone(), false));
    }

    // A keycap sequence across the reason limit.
    let input = format!("{}1\u{FE0F}\u{20E3}", "r".repeat(999));
    let (out, unusual) = normalize_reason(&input);
    assert!(!strip(&out, true).1);
    assert!(unusual);
    Ok(())
}

#[test]
fn name_of_only_removed_chars_is_none() -> TestResult {
    let n = normalize_hello(&hello(Some("\u{202E}\u{200B}"), "x"));
    assert_eq!(n.agent_name, None);
    assert!(n.unusual);
    Ok(())
}

fn agent_string() -> impl Strategy<Value = String> {
    // Whole RGI sequences (so cuts land inside them) and single flagged or plain characters.
    let tokens = prop::sample::select(vec![
        "👩\u{200D}🚀",
        "👨\u{200D}👩\u{200D}👧",
        "❤\u{FE0F}",
        "1\u{FE0F}\u{20E3}",
        "👍\u{1F3FD}",
        "a",
        "ü",
        " ",
        "\n",
        "\t",
        "\r",
        "\u{1B}",
        "\u{85}",
        "\u{200B}",
        "\u{200D}",
        "\u{202E}",
        "\u{FE0F}",
        "\u{E0067}",
        "\u{3164}",
    ]);
    // A run of plain characters puts the random tail around the 64-scalar cut.
    (0usize..70, prop::collection::vec(tokens, 0..16))
        .prop_map(|(pad, v)| "a".repeat(pad) + &v.concat())
}

type Normalizer = fn(&str) -> (String, bool);

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Normalized output keeps no flagged character, fits its limit and is a fixpoint.
    #[test]
    fn normalization_is_idempotent(s in agent_string()) {
        let cases: [(Normalizer, bool, usize); 3] = [
            (normalize_agent_name, false, MAX_AGENT_NAME_CHARS),
            (normalize_cwd_basename, false, MAX_CWD_BASENAME_CHARS),
            (normalize_reason, true, MAX_REASON_CHARS),
        ];
        for (f, keep_newlines, max) in cases {
            let (out, _) = f(&s);
            prop_assert!(!strip(&out, keep_newlines).1, "flagged char left in {:?}", out);
            prop_assert!(out.chars().count() <= max);
            prop_assert_eq!(f(&out), (out.clone(), false));
        }
    }
}
