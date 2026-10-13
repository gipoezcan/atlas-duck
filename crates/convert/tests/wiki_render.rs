//! `wiki_to_preview_html` / `wiki_to_text` (spec §7.6, §13 U-23 wiki half and S-12, plan Task 5).
//!
//! The HTML is raw renderer output; core sanitises it (`preview::sanitize_html`) before it
//! reaches the UI. These tests pin the renderer's own guarantees: no live remote element, link
//! or script appears even before sanitising.

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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
/// `<` in the output is always a tag the renderer wrote itself. An allow-list: only the fixed
/// tag set the renderer emits, and no attribute except `data-macro="..."` on an opening `div`.
fn live_markup(html: &str) -> Option<String> {
    const TAGS: &[&str] = &[
        "p",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "strong",
        "em",
        "del",
        "code",
        "br",
        "ul",
        "ol",
        "li",
        "table",
        "tr",
        "th",
        "td",
        "blockquote",
        "pre",
        "hr",
        "div",
    ];
    let mut rest = html;
    while let Some(i) = rest.find('<') {
        let after = rest.get(i + 1..).unwrap_or("");
        let Some(end) = after.find('>') else {
            return Some(format!("unterminated tag in {after:?}"));
        };
        let tag = after.get(..end).unwrap_or("");
        let inner = tag.strip_prefix('/').unwrap_or(tag);
        let name_len = inner
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(inner.len());
        let name = inner.get(..name_len).unwrap_or("");
        let attrs = inner.get(name_len..).unwrap_or("");
        if !TAGS.contains(&name) {
            return Some(format!("tag {tag:?}"));
        }
        let ok = if name == "div" && !tag.starts_with('/') {
            attrs
                .strip_prefix(" data-macro=\"")
                .and_then(|v| v.strip_suffix('"'))
                .is_some_and(|v| !v.contains(['"', '<', '>']))
        } else {
            attrs.is_empty()
        };
        if !ok {
            return Some(format!("attributes in {tag:?}"));
        }
        rest = after.get(end + 1..).unwrap_or("");
    }
    None
}

#[test]
fn live_markup_scanner_flags_known_bad_markup() {
    for bad in [
        "<img src=x>",
        "<p onclick=x>t</p>",
        "<a href=\"x\">t</a>",
        "<script>x</script>",
        "<video src=x></video>",
        "<button>x</button>",
        "<details><summary>s</summary></details>",
        "<math></math>",
        "<p formaction=x>t</p>",
        "<div style=\"x\">t</div>",
        "<div data-macro=\"a\" onclick=\"x\">t</div>",
        "<div>t</div>",
        "<iframe src=x>",
        "<svg onload=x>",
        "<p",
    ] {
        assert!(live_markup(bad).is_some(), "not flagged: {bad:?}");
    }
    for good in [
        "<p>a</p>",
        "<ul><li>a<ul><li>b</li></ul></li></ul>",
        "<div data-macro=\"style\"><p>[macro: style]</p></div>",
        "<div data-macro=\"href src action\"><p>x</p></div>",
        "<table><tr><th>a</th><td>b</td></tr></table><hr><br>",
        "<p>a &lt;img src=x&gt;</p>",
    ] {
        assert_eq!(live_markup(good), None, "{good:?}");
    }
}

#[test]
fn style_like_macro_names_are_not_live_markup() {
    for wiki in [
        "{style}",
        "{href}",
        "{source}",
        "{src}\nx\n{src}",
        "{action:x}",
    ] {
        let html = wiki_to_preview_html(wiki);
        assert_eq!(live_markup(&html), None, "input {wiki:?} gave {html:?}");
    }
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
    assert_eq!(
        wiki_to_text("{code}\na &#92; b\n{code}"),
        "{code}\na &#92; b\n{code}"
    );
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
    assert_eq!(
        wiki_to_text("{code}\nx < y"),
        "{code}
x < y
{code}"
    );
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
            Just("{style}"),
            Just("{include:x}"),
            Just("{quote}{quote}"),
            Just("{code:java}"),
            Just("\r\n"),
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

#[test]
fn macro_params_are_visible_in_both_projections() {
    assert_eq!(
        wiki_to_text("{include:Salary Page}"),
        "[macro: include Salary Page]"
    );
    assert_eq!(
        wiki_to_preview_html("{include:Salary Page}"),
        "<div data-macro=\"include\"><p>[macro: include Salary Page]</p></div>"
    );
    assert_ne!(
        wiki_to_text("{include:Salary Page}"),
        wiki_to_text("{include:Public Page}")
    );
    assert_eq!(
        wiki_to_text("a {jira:key=A-1} b"),
        "a [macro: jira key=A-1] b"
    );
    assert_ne!(
        wiki_to_preview_html("a {jira:key=A-1} b"),
        wiki_to_preview_html("a {jira:key=B-2} b")
    );
    assert_eq!(
        wiki_to_text("a {status:title=Done|colour=Green}OK{status}"),
        "a [macro: status title=Done|colour=Green]OK[macro: status]"
    );
    assert_eq!(
        wiki_to_text("{excerpt-include:Other}\n\n{expand:title=More}\nx\n{expand}"),
        "[macro: excerpt-include Other]\n[macro: expand title=More]\nx"
    );
    // Escaped in HTML.
    assert_eq!(
        wiki_to_preview_html("{include:<b>\"x\"}"),
        "<div data-macro=\"include\"><p>[macro: include &lt;b&gt;&quot;x&quot;]</p></div>"
    );
    // Styling macros still drop to their content.
    assert_eq!(wiki_to_text("{color:red}x{color}"), "x");
    assert_eq!(wiki_to_text("a {span:style=a}x{span}"), "a x");
}

#[test]
fn long_macro_params_are_capped_with_a_marker() {
    let long = "p".repeat(500);
    for out in [
        wiki_to_text(&format!("{{include:{long}}}")),
        wiki_to_preview_html(&format!("{{include:{long}}}")),
    ] {
        assert!(out.contains('\u{2026}'), "{out}");
        assert!(out.len() < 250, "{} bytes", out.len());
    }
    let short = "q".repeat(60);
    assert_eq!(
        wiki_to_text(&format!("{{include:{short}}}")),
        format!("[macro: include {short}]")
    );
}

#[test]
fn text_shows_code_noformat_and_quote_boundaries() {
    assert_eq!(
        wiki_to_text("{code:java}\nint x;\n{code}"),
        "{code:java}\nint x;\n{code}"
    );
    assert_eq!(wiki_to_text("{code}\nx\n{code}"), "{code}\nx\n{code}");
    assert_eq!(
        wiki_to_text("{noformat}\nx\n{noformat}"),
        "{noformat}\nx\n{noformat}"
    );
    assert_ne!(wiki_to_text("{code:java}x{code}"), wiki_to_text("x"));
    assert_ne!(
        wiki_to_text("{code}\nx\n{code}"),
        wiki_to_text("{noformat}\nx\n{noformat}")
    );
    assert_ne!(
        wiki_to_text("{code:java}\nx\n{code}"),
        wiki_to_text("{code:rust}\nx\n{code}")
    );
    // Unterminated bodies still get both markers.
    assert_eq!(wiki_to_text("{code}\nx < y"), "{code}\nx < y\n{code}");
}

#[test]
fn empty_containers_stay_visible_in_text() {
    assert_eq!(
        wiki_to_text("a\n\n{code}{code}\n\nb"),
        "a\n{code}\n{code}\nb"
    );
    assert_eq!(
        wiki_to_text("{noformat}{noformat}"),
        "{noformat}\n{noformat}"
    );
    assert_eq!(wiki_to_text("a\n\n{quote}{quote}\n\nb"), "a\n>\nb");
    assert_ne!(wiki_to_text("bq. "), wiki_to_text(""));
    assert_ne!(wiki_to_text("a\n\n{quote}{quote}"), wiki_to_text("a"));
    assert_ne!(wiki_to_text("a\n\n{code}{code}"), wiki_to_text("a"));
}

#[test]
fn text_list_indent_is_clamped_like_html() {
    assert_eq!(wiki_to_text("*** x"), "\u{2022} x");
    assert_eq!(
        wiki_to_text("* a\n**** b\n* c"),
        "\u{2022} a\n  \u{2022} b\n\u{2022} c"
    );
    assert_eq!(
        wiki_to_text("* a\n** b\n*** c"),
        "\u{2022} a\n  \u{2022} b\n    \u{2022} c"
    );
}

#[test]
fn numeric_references_never_produce_invisible_or_format_characters() {
    for c in [
        '\u{61c}',
        '\u{ad}',
        '\u{34f}',
        '\u{3164}',
        '\u{180b}',
        '\u{fe0f}',
        '\u{2028}',
        '\u{2029}',
        '\u{e0041}',
        '\u{202e}',
        '\u{200b}',
        '\u{85}',
        '\u{7f}',
    ] {
        let r = format!("&#x{:x};", u32::from(c));
        assert_eq!(wiki_to_text(&r), r, "{c:?} decoded");
    }
    // Drift: nothing the §6.4 classifier flags may be produced by a reference.
    let mut leaked = Vec::new();
    for n in 0..=0x10ffffu32 {
        let Some(c) = char::from_u32(n) else { continue };
        if !atlas_duck_preview::invisible::is_flagged(c) {
            continue;
        }
        let r = format!("&#{n};");
        if wiki_to_text(&r) != r {
            leaked.push(n);
        }
    }
    assert!(leaked.is_empty(), "decoded flagged characters: {leaked:x?}");
    // Ordinary references still decode.
    assert_eq!(wiki_to_text("&#92;&#x41;&#160;"), "\\A\u{a0}");
}

#[test]
fn pathological_inputs_finish_with_bounded_output() {
    let inputs = [
        "{quote}".repeat(200),
        format!("{}x{}", "{quote}".repeat(100), "{quote}".repeat(100)),
        "*_".repeat(200),
        format!("{} x", "*".repeat(200)),
        format!("&#{}", "1".repeat(100_000)),
        "&#".repeat(100_000),
        format!("[{}|{}]", "a".repeat(100_000), "b".repeat(100_000)),
        format!("[{}]", "a".repeat(100_000)),
        format!("{{include:{}}}", "p".repeat(100_000)),
    ];
    for input in &inputs {
        let start = Instant::now();
        let (html, text) = render_all(input);
        assert!(start.elapsed() < Duration::from_secs(30), "slow input");
        let bound = 64 * input.len() + 1024;
        assert!(
            html.len() <= bound,
            "html {} for input {}",
            html.len(),
            input.len()
        );
        assert!(
            text.len() <= bound,
            "text {} for input {}",
            text.len(),
            input.len()
        );
        assert_eq!(live_markup(&html), None);
    }
}
