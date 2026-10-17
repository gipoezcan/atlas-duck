//! Markdown → preview HTML (plan Task 7, spec §6.3 Confluence page "Rendered Markdown", §6.4,
//! §13 S-12, PD-94): semantic elements only, no attributes, links and images as text, raw
//! HTML as escaped text.

mod common;

use std::path::{Path, PathBuf};

use atlas_duck_convert::markdown_to_preview_html;
use proptest::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GOLDEN: [&str; 8] = [
    "basics",
    "lists",
    "tables",
    "code",
    "links_images",
    "image_labels",
    "html",
    "confluence",
];

/// Every element the renderer may write (Task 7 Produces), always without attributes.
const ALLOWED: [&str; 24] = [
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "p",
    "br",
    "hr",
    "strong",
    "em",
    "del",
    "code",
    "pre",
    "blockquote",
    "ul",
    "ol",
    "li",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
];

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/md_preview")
}

/// The tags of `html` in order (`p`, `/p`, …), or the first tag that is not a bare allowed
/// name. Text never holds a raw `<`, so every `<` starts a tag.
fn tags(html: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (i, _) in html.match_indices('<') {
        let rest = &html[i + 1..];
        let end = rest
            .find('>')
            .ok_or_else(|| format!("unclosed tag at {i}"))?;
        let tag = &rest[..end];
        let name = tag.strip_prefix('/').unwrap_or(tag);
        if !ALLOWED.contains(&name) {
            return Err(format!("tag <{tag}> at {i}"));
        }
        out.push(tag.to_owned());
    }
    Ok(out)
}

/// An `on<letters>=` word (an event-handler attribute, as markup or as text).
fn has_handler(html: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    lower.match_indices("on").any(|(i, _)| {
        let word_start = !lower[..i]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric());
        let rest = lower[i + 2..].trim_start_matches(|c: char| c.is_ascii_alphabetic());
        word_start && rest.len() < lower.len() - i - 2 && rest.starts_with('=')
    })
}

fn assert_inert(md: &str, html: &str) {
    if let Err(e) = tags(html) {
        panic!("{e}\ninput: {md:?}\noutput: {html:?}");
    }
    let lower = html.to_ascii_lowercase();
    for needle in [
        "<img", "<script", "<a", "<iframe", "<style", "<svg", "<span", "<div",
    ] {
        assert!(!lower.contains(needle), "{needle} in {html:?}");
    }
}

#[test]
fn md_preview_html_golden() -> TestResult {
    let mut failures = Vec::new();
    for name in GOLDEN {
        let input = std::fs::read_to_string(golden_dir().join(format!("{name}.md")))?;
        let expected = std::fs::read_to_string(golden_dir().join(format!("{name}.html")))?;
        let out = markdown_to_preview_html(&input);
        if out != expected {
            failures.push(format!(
                "{name}:\n--- expected\n{expected}\n+++ actual\n{out}"
            ));
        }
        assert_inert(&input, &out);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

#[test]
fn s12_md_preview_neutralizes_remote_and_scripts() -> TestResult {
    for md in [
        "![x](https://evil.example/a.png)",
        "<script>alert(1)</script>",
        "[a](javascript:alert(1))",
        "text <script>alert(1)</script> inline",
        "[![x](https://evil.example/a.png)](javascript:alert(1))",
        "<https://evil.example/>",
        "[r]\n\n[r]: javascript:alert(1)",
    ] {
        let html = markdown_to_preview_html(md);
        assert_inert(md, &html);
        for needle in ["<img", "<script", "<a", "href", "src", "<iframe"] {
            assert!(!html.contains(needle), "{needle} in {html:?} for {md:?}");
        }
        assert!(!has_handler(&html), "event handler in {html:?}");
    }
    // Raw HTML stays visible as text, so its attributes are text too, never markup.
    let md = "<img src=\"https://evil.example/x.png\" onerror=\"alert(1)\">\n\n\
              a <iframe src=\"https://evil.example/\"></iframe> b";
    let html = markdown_to_preview_html(md);
    assert_inert(md, &html);
    assert!(
        html.contains("&lt;img src=&quot;https://evil.example/x.png&quot;"),
        "{html}"
    );
    assert!(html.contains("&lt;iframe src=&quot;"), "{html}");
    Ok(())
}

#[test]
fn every_text_is_escaped() -> TestResult {
    let html =
        markdown_to_preview_html("# a <b> & \"c\" 'd'\n\n`<i>` [<u>](https://x.example/?a=<b>&c)");
    assert_eq!(
        html,
        "<h1>a &lt;b&gt; &amp; &quot;c&quot; &#39;d&#39;</h1>\n\
         <p><code>&lt;i&gt;</code> &lt;u&gt; (https://x.example/?a=&lt;b&gt;&amp;c)</p>\n"
    );
    // Entity references decode to text, then are escaped again.
    assert_eq!(
        markdown_to_preview_html("&lt;script&gt; &#60;x&#62;"),
        "<p>&lt;script&gt; &lt;x&gt;</p>\n"
    );
    Ok(())
}

#[test]
fn every_heading_level_has_its_own_tag() -> TestResult {
    let md = "# a\n\n## b\n\n### c\n\n#### d\n\n##### e\n\n###### f\n";
    assert_eq!(
        markdown_to_preview_html(md),
        "<h1>a</h1>\n<h2>b</h2>\n<h3>c</h3>\n<h4>d</h4>\n<h5>e</h5>\n<h6>f</h6>\n"
    );
    Ok(())
}

#[test]
fn task_items_and_ordered_starts_are_text_only() -> TestResult {
    let html = markdown_to_preview_html("3. [ ] a\n4. [x] b\n");
    assert_eq!(html, "<ol>\n<li>☐ a</li>\n<li>☑ b</li>\n</ol>\n");
    Ok(())
}

#[test]
fn storage_conversions_render_inertly() -> TestResult {
    // What a Confluence page preview renders: storage → Markdown → preview HTML.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/storage_to_md");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "md") {
            let md = std::fs::read_to_string(&path)?;
            assert_inert(&md, &markdown_to_preview_html(&md));
            seen += 1;
        }
    }
    assert!(seen >= 10, "only {seen} goldens");
    Ok(())
}

#[test]
fn empty_and_blank_inputs() -> TestResult {
    assert_eq!(markdown_to_preview_html(""), "");
    assert_eq!(markdown_to_preview_html("\n\n  \n"), "");
    Ok(())
}

/// Block-level Markdown biased to every element the renderer writes, nested under quote and
/// list prefixes, so the sanitizer property sees tables, task lists and code in containers.
fn block_markdown() -> impl Strategy<Value = String> {
    let block = prop::sample::select(vec![
        "# h1 *e*",
        "###### h6 `c`",
        "para **s** ~~d~~ _e_ <b>raw</b>",
        "line\\\nbreak",
        "| a | b |\n|---|:-:|\n| `c` | <i>d</i> |\n| e |",
        "| only |\n|--|",
        "- [ ] t\n- [x] u\n  - v",
        "1. a\n\n2. b",
        "```x\n<code>\n```",
        "    indented",
        "<div>\nblock\n</div>",
        "---",
        "[l](https://x.example/) ![i](https://x.example/i.png) <https://a.example/>",
        "[macro: toc {}] @user:8a7f [p](confluence:/T)",
        "<!-- c -->",
        "&amp; &#60; &copy;",
    ])
    .prop_map(str::to_owned);
    let prefix = prop::sample::select(vec!["", "> ", "- ", "1. ", "> - ", "- > ", "  "]);
    proptest::collection::vec(
        (prefix, block).prop_map(|(p, b)| {
            b.lines()
                .map(|l| format!("{p}{l}"))
                .collect::<Vec<_>>()
                .join("\n")
        }),
        0..8,
    )
    .prop_map(|v| v.join("\n\n"))
}

fn any_markdown() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => block_markdown(),
        3 => common::markdown(),
        1 => any::<String>(),
        1 => proptest::collection::vec(common::storage_fragment(), 0..40).prop_map(|v| v.concat()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, ..ProptestConfig::default() })]

    #[test]
    fn deterministic_and_never_panics(md in any_markdown()) {
        let a = markdown_to_preview_html(&md);
        prop_assert_eq!(&a, &markdown_to_preview_html(&md));
        let t = tags(&a);
        prop_assert!(t.is_ok(), "{:?} for {:?}: {:?}", t, md, a);
    }

    /// The sanitizer core applies keeps every element the renderer writes, in order: the
    /// output is already in the form `sanitize_html` produces (nothing is re-nested).
    #[test]
    fn sanitizer_keeps_every_tag(md in any_markdown()) {
        let html = markdown_to_preview_html(&md);
        let clean = atlas_duck_preview::sanitize_html(&html);
        prop_assert_eq!(tags(&clean), tags(&html), "{:?}\n{:?}", html, clean);
    }
}
