//! `wiki_to_preview_html` / `wiki_to_text` (spec §7.6, §13 U-23 wiki half and S-12, plan Task 5).
//!
//! The HTML is raw renderer output; core sanitises it (`preview::sanitize_html`) before it
//! reaches the UI. These tests pin the renderer's own guarantees: no live remote element, link
//! or script appears even before sanitising.

mod common;

use std::path::{Path, PathBuf};

use atlas_duck_convert::{markdown_to_wiki, wiki_to_preview_html, wiki_to_text};
use common::markdown;
use proptest::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GOLDEN: &[&str] = &[
    "basics", "lists", "tables", "macros", "links", "code", "entities",
];

fn golden(dir: &str, file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(dir)
        .join(file)
}

/// The `.wiki` input is shared by both projections; `dir` holds the expected output.
fn check_golden(dir: &str, ext: &str, render: fn(&str) -> String) -> TestResult {
    let mut failures = Vec::new();
    for name in GOLDEN {
        let wiki = std::fs::read_to_string(golden(dir, &format!("{name}.wiki")))?;
        let expected = std::fs::read_to_string(golden(dir, &format!("{name}.{ext}")))?;
        // Goldens end with a newline; the renderers do not add one.
        let out = format!("{}\n", render(&wiki));
        if out != expected {
            failures.push(format!(
                "{name}:\n--- expected\n{expected}\n--- actual\n{out}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

#[test]
fn u23_wiki_to_html_golden() -> TestResult {
    check_golden("wiki_html", "html", wiki_to_preview_html)
}

#[test]
fn wiki_to_text_projection_golden() -> TestResult {
    check_golden("wiki_text", "txt", wiki_to_text)
}

/// Something in `html` that would load or run content, or style it. Text is escaped, so a
/// `<` in the output is always a tag the renderer wrote itself.
fn live_markup(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    for p in [
        "<img", "<script", "<a ", "<a>", "<iframe", "<object", "<embed", "<link", "<style", "<svg",
        "<form", "<input", "<meta", "<base",
    ] {
        if lower.contains(p) {
            return Some(p.to_owned());
        }
    }
    // Attributes: only inside a tag the renderer wrote.
    let mut rest = lower.as_str();
    while let Some(i) = rest.find('<') {
        let tag_end = rest
            .get(i..)
            .and_then(|t| t.find('>'))
            .map_or(rest.len(), |e| i + e);
        let tag = rest.get(i..tag_end).unwrap_or("");
        for a in ["href", "src", "style", "srcset", "action", "xlink"] {
            if tag.contains(a) {
                return Some(format!("{a} in {tag:?}"));
            }
        }
        if tag.split_whitespace().any(|w| w.starts_with("on")) {
            return Some(format!("on… attribute in {tag:?}"));
        }
        rest = rest.get(tag_end..).unwrap_or("");
    }
    None
}

#[test]
fn s12_remote_images_and_scripts_neutralized() {
    let inputs = [
        "!https://evil.example/x.png!",
        "!https://evil.example/x.png|width=1,onerror=alert(1)!",
        "{html}<script>alert(1)</script>{html}",
        "{html}\n<script>alert(1)</script>\n{html}",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "[click|javascript:alert(1)]",
        "[javascript:alert(1)]",
        "http://evil.example/a\"onmouseover=\"x",
        "[a\"b|http://x.example/\"><script>]",
        "{code}<script>alert(1)</script>{code}",
        "{noformat}<img src=x>{noformat}",
        "{panel:title=<script>}x{panel}",
        "{<script>}",
        "h1. <b onclick=x>t</b>",
        "||<th onclick=x>||\n|<td>|",
        "[^<img src=x>] [~<script>]",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
    ];
    for wiki in inputs {
        let html = wiki_to_preview_html(wiki);
        assert_eq!(live_markup(&html), None, "input {wiki:?} gave {html:?}");
    }
    assert_eq!(
        wiki_to_preview_html("!https://evil.example/x.png!"),
        "<p>[image: https://evil.example/x.png]</p>"
    );
    assert_eq!(
        wiki_to_preview_html("[click|javascript:alert(1)]"),
        "<p>click (javascript:alert(1))</p>"
    );
    let html = wiki_to_preview_html("{html}<script>alert(1)</script>{html}");
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "{html}"
    );
    assert!(html.contains("[macro: html]"), "{html}");
}

#[test]
fn numeric_character_references_are_decoded_once_then_escaped() {
    assert_eq!(
        wiki_to_preview_html("a&#92;b &#104;1&#46; &#x7e;"),
        "<p>a\\b h1. ~</p>"
    );
    assert_eq!(
        wiki_to_text("a&#92;b &#126;&#94;&#160;&#38;x"),
        "a\\b ~^\u{a0}&x"
    );
    // Decoding never produces markup, and happens exactly once.
    assert_eq!(
        wiki_to_preview_html("&#60;b&#62; &#38;#60;"),
        "<p>&lt;b&gt; &amp;#60;</p>"
    );
    // Malformed, out-of-range, control and invisible references stay literal.
    let kept = "&#; &#x; &#xZ; &#1114112; &#55296; &#0; &#8238; &#8203; &#10;";
    assert_eq!(wiki_to_text(kept), kept);
    // Code bodies are verbatim.
    assert_eq!(wiki_to_text("{code}\na &#92; b\n{code}"), "a &#92; b");
}

#[test]
fn color_and_styling_ignored() {
    assert_eq!(wiki_to_preview_html("{color:red}x{color}"), "<p>x</p>");
    assert_eq!(
        wiki_to_preview_html("a {color:#ff0000}*b*{color} {span:style=x}c{span}"),
        "<p>a <strong>b</strong> c</p>"
    );
    assert_eq!(wiki_to_text("{color:red}x{color}"), "x");
    assert!(!wiki_to_preview_html("{color:red}x{color}").contains("style"));
}

#[test]
fn empty_and_whitespace_input() {
    assert_eq!(wiki_to_preview_html(""), "");
    assert_eq!(wiki_to_text(""), "");
    assert_eq!(wiki_to_text("\n\n"), "");
}

#[test]
fn nested_lists_and_unterminated_code() {
    assert_eq!(
        wiki_to_preview_html("* a\n** b\n* c"),
        "<ul><li>a<ul><li>b</li></ul></li><li>c</li></ul>"
    );
    assert_eq!(wiki_to_preview_html("** deep"), "<ul><li>deep</li></ul>");
    assert_eq!(wiki_to_text("{code}\nx < y"), "x < y");
    assert_eq!(wiki_to_preview_html("{code}\nx < y"), "<pre>x &lt; y</pre>");
}

fn render_all(wiki: &str) -> (String, String) {
    (wiki_to_preview_html(wiki), wiki_to_text(wiki))
}

fn fragments() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            Just("{"),
            Just("}"),
            Just("{code}"),
            Just("{noformat}"),
            Just("{panel}"),
            Just("{quote}"),
            Just("[~u]"),
            Just("[a|b]"),
            Just("!x!"),
            Just("||"),
            Just("|"),
            Just("* "),
            Just("# "),
            Just("h1. "),
            Just("bq. "),
            Just("&#92;"),
            Just("&#"),
            Just("{color:red}"),
            Just("{color}"),
            Just("\n"),
            Just("\\\\"),
            Just("<b>"),
            Just("&"),
            Just("\u{202e}"),
            Just("x"),
        ],
        0..40,
    )
    .prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn deterministic_and_never_panics(
        md in markdown(),
        raw in any::<String>(),
        frag in fragments(),
    ) {
        let (wiki, _) = markdown_to_wiki(&md);
        for input in [wiki, raw, frag] {
            let a = render_all(&input);
            let b = render_all(&input);
            prop_assert_eq!(&a, &b);
            prop_assert_eq!(live_markup(&a.0), None, "input {:?} gave {:?}", input, a.0);
        }
    }
}
