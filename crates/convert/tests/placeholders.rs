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

/// Raw HTML is written out as text by `markdown_to_storage`, so a placeholder inside an HTML
/// block or inline HTML reaches Confluence as prose and is a hit (fail closed, review I-1).
#[test]
fn raw_html_is_scanned_like_text() {
    let hits = [
        ("<div>\n[macro: toc {}]\n</div>", PlaceholderKind::Macro),
        ("<div>\n@user:8a7f\n</div>", PlaceholderKind::User),
        (
            "<details>\n<summary>s</summary>\n\n@user:8a7f\n</details>",
            PlaceholderKind::User,
        ),
        ("<b>@user:x</b>", PlaceholderKind::User),
        ("a <i>[macro: toc {}]</i> b", PlaceholderKind::Macro),
        ("<span>[macro: toc {}]", PlaceholderKind::Macro),
    ];
    for (md, kind) in hits {
        assert_eq!(kinds(md), vec![(kind, 1)], "{md:?}");
    }
    // The block form really is raw HTML events, not text (the test is not vacuous).
    let opts = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
    assert!(
        Parser::new_ext("<div>\n[macro: toc {}]\n</div>", opts)
            .all(|e| !matches!(e, Event::Text(_)))
    );
    // HTML without a placeholder still passes.
    for md in [
        "<div>\nplain\n</div>",
        "<!-- a comment -->",
        "x <b>bold</b> y",
        "<div>\n[macro: toc]\n@user: x\n</div>",
    ] {
        assert_eq!(check_markdown_placeholders(md), Ok(()), "{md:?}");
    }
}

#[test]
fn macro_name_bound_and_class() {
    let x64 = "x".repeat(64);
    let x65 = "x".repeat(65);
    assert_eq!(
        kinds(&format!("[macro: {x64} {{}}]")),
        vec![(PlaceholderKind::Macro, 1)]
    );
    assert_eq!(kinds(&format!("[macro: {x65} {{}}]")), vec![]);
    assert_eq!(kinds("[macro: x {}]"), vec![(PlaceholderKind::Macro, 1)]);
    // `_` and `.` are name characters, like `-`.
    assert_eq!(
        kinds("[macro: a_b.c {}]"),
        vec![(PlaceholderKind::Macro, 1)]
    );
    // Closing rule: `}]` is needed, a stray space or a missing brace is not a hit.
    assert_eq!(kinds("[macro: toc {x]"), vec![]);
    assert_eq!(kinds("[macro: toc {} ]"), vec![]);
    // An inline tag in the parameters ends the run (documented, review m-4).
    assert_eq!(kinds("[macro: a {k=*x*}]"), vec![]);
}

#[test]
fn user_key_start_class() {
    for md in ["@user:.a", "@user:_a", "@user:-a", "@user:%5Fa", "@user:9"] {
        assert_eq!(kinds(md), vec![(PlaceholderKind::User, 1)], "{md:?}");
    }
    // ASCII only: a non-ASCII letter does not start a key.
    assert_eq!(kinds("@user:\u{e9}"), vec![]);
    assert_eq!(kinds("@user:\u{4e2d}"), vec![]);
}

#[test]
fn link_scheme_needs_the_colon() {
    for md in [
        "[x](confluence-notes.md)",
        "[x](confluence.html)",
        "[x](confluence)",
        "![x](confluence-a.png)",
    ] {
        assert_eq!(check_markdown_placeholders(md), Ok(()), "{md:?}");
    }
    assert_eq!(kinds("[x](confluence:p)"), vec![(PlaceholderKind::Link, 1)]);
}

#[test]
fn autolink_and_reference_forms_are_found() {
    assert_eq!(
        kinds("<confluence:DOC/Page>"),
        vec![(PlaceholderKind::Link, 1)]
    );
    assert_eq!(
        kinds("[a][r]\n\n[r]: confluence:DOC/Page"),
        vec![(PlaceholderKind::Link, 1)]
    );
    assert_eq!(
        kinds("[x](<confluence:DOC/Page>)"),
        vec![(PlaceholderKind::Link, 1)]
    );
    // An unreferenced definition emits no link event and is not a hit.
    assert_eq!(
        check_markdown_placeholders("[r]: confluence:DOC/Page"),
        Ok(())
    );
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
