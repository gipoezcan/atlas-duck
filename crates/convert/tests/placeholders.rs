//! The Markdown placeholder check by source span (plan Task 4, spec §7.6, PD-98, U-25).

use atlas_duck_convert::{PlaceholderHit, PlaceholderKind, check_markdown_placeholders};
use pulldown_cmark::{Event, Options, Parser};

fn hit(kind: PlaceholderKind, count: u64) -> PlaceholderHit {
    PlaceholderHit { kind, count }
}

fn kinds(md: &str) -> Vec<(PlaceholderKind, u64)> {
    match check_markdown_placeholders(md) {
        Ok(()) => Vec::new(),
        Err(hits) => hits.into_iter().map(|h| (h.kind, h.count)).collect(),
    }
}

fn golden(name: &str) -> String {
    let path = format!(
        "{}/tests/golden/placeholders/{name}.md",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn text_events(md: &str) -> usize {
    let opts = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
    Parser::new_ext(md, opts)
        .filter(|e| matches!(e, Event::Text(_)))
        .count()
}

#[test]
fn u25_placeholders_golden_rejected_with_counts() {
    let md = golden("page_get");
    assert_eq!(
        check_markdown_placeholders(&md),
        Err(vec![
            hit(PlaceholderKind::Link, 2),
            hit(PlaceholderKind::Image, 1),
            hit(PlaceholderKind::Macro, 1),
            hit(PlaceholderKind::User, 1),
        ])
    );
}

#[test]
fn u25_escaped_lookalikes_pass() {
    let md = golden("escaped");
    assert_eq!(check_markdown_placeholders(&md), Ok(()));
    assert_eq!(
        check_markdown_placeholders("see [confluence: docs](https://example.com/x)"),
        Ok(())
    );
}

#[test]
fn macro_placeholder_split_across_text_events_is_a_hit() {
    let cases = [
        "[macro: toc {}]",
        "intro\n\n[macro: toc {}]",
        "**bold** [macro: toc {}]",
        "- item [macro: toc {}]",
        "- [macro: toc {}]",
    ];
    for md in cases {
        assert!(
            text_events(md) > 1,
            "{md:?}: the parser must split the placeholder, or the test is vacuous"
        );
        assert_eq!(kinds(md), vec![(PlaceholderKind::Macro, 1)], "{md:?}");
    }
}

#[test]
fn escape_gaps_inside_a_run_still_match() {
    // pulldown-cmark leaves the backslash out of the escaped character's range.
    let md = "[macro: m {k=a\\,b}]";
    assert_eq!(kinds(md), vec![(PlaceholderKind::Macro, 1)]);
}

#[test]
fn escaped_at_user_does_not_match() {
    assert_eq!(kinds("\\@user:abc"), vec![]);
    assert_eq!(kinds("\\\\@user:abc"), vec![(PlaceholderKind::User, 1)]);
    assert_eq!(kinds("\\[macro: toc {}]"), vec![]);
    assert_eq!(
        kinds("\\\\[macro: toc {}]"),
        vec![(PlaceholderKind::Macro, 1)]
    );
}

#[test]
fn placeholders_in_code_are_not_hits() {
    let md = "`[macro: toc {}]` and `@user:8a7f`\n\n```\n[macro: toc {}]\n@user:8a7f\n[x](confluence:p/t)\n```\n\n    @user:8a7f\n";
    assert_eq!(check_markdown_placeholders(md), Ok(()));
}

#[test]
fn scheme_is_case_insensitive() {
    assert_eq!(
        kinds("[x](CONFLUENCE:x) ![y](Confluence:attachment/a.png)"),
        vec![(PlaceholderKind::Link, 1), (PlaceholderKind::Image, 1)]
    );
}

#[test]
fn converter_name_and_key_forms_are_found() {
    // T3 fix round: `_` in a name becomes `-`, `%5F` in a user key.
    assert_eq!(
        kinds("[macro: -x- {}] [macro: a-b {}] @user:%5Fa @user:b%5F"),
        vec![(PlaceholderKind::Macro, 2), (PlaceholderKind::User, 2)]
    );
}

#[test]
fn near_misses_are_not_hits() {
    for md in [
        "[macro: {}]",
        "[macro: toc]",
        "[macro: toc {}",
        "@user: abc",
        "@user:",
        "a@user:x",
    ] {
        let expect_user = md == "a@user:x";
        let got = kinds(md);
        if expect_user {
            // The grammar has no word boundary: `@user:` inside prose is a hit.
            assert_eq!(got, vec![(PlaceholderKind::User, 1)], "{md:?}");
        } else {
            assert_eq!(got, vec![], "{md:?}");
        }
    }
}

#[test]
fn placeholder_hits_carry_no_text() {
    let md = "[macro: secretname {k=secretvalue}] @user:secretkey [t](confluence:secretspace/p)";
    let dbg = format!("{:?}", check_markdown_placeholders(md));
    for word in ["secret", "toc", "space"] {
        assert!(!dbg.contains(word), "{dbg}");
    }
    assert!(dbg.contains("count"));
}

#[test]
fn kind_names() {
    assert_eq!(PlaceholderKind::Link.as_str(), "link");
    assert_eq!(PlaceholderKind::Image.as_str(), "image");
    assert_eq!(PlaceholderKind::Macro.as_str(), "macro");
    assert_eq!(PlaceholderKind::User.as_str(), "user");
}
