//! `markdown_to_storage`: Markdown → Confluence storage with XML escaping and the code-macro
//! rule (spec §7.6, plan Task 5, PD-96).
//!
//! Every output is checked against the storage parser the hard check uses (`convert::storage`):
//! it must be well-formed, use only the converter's own elements and attributes, and its
//! construct spans must be exactly the code macros the converter recorded.

mod common;

use std::path::{Path, PathBuf};

use atlas_duck_convert::storage::{self, Node, construct_spans};
use atlas_duck_convert::{
    ConstructKind, ContainerKind, EmittedConstructs, StorageReject, UserResolutions,
    check_storage_body, markdown_to_storage, storage_constructs, storage_to_markdown,
};
use common::{
    CODE_MACRO_CLOSE as MACRO_CLOSE, CODE_MACRO_OPEN as MACRO_OPEN,
    check_storage_output as check_output, markdown, only_converter_markup,
};
use proptest::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GOLDEN: [&str; 9] = [
    "basics", "lists", "tables", "code", "links", "html", "specials", "nested", "tasks",
];

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/md_to_storage")
}

/// A line diff (`-` expected, `+` actual) for golden failures.
fn diff(expected: &str, actual: &str) -> String {
    let a: Vec<&str> = expected.lines().collect();
    let b: Vec<&str> = actual.lines().collect();
    let mut lcs = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, String::from("--- expected\n+++ actual\n"));
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            out.push_str(&format!(" {}\n", a[i]));
            i += 1;
            j += 1;
        } else if j < b.len() && (i == a.len() || lcs[i][j + 1] >= lcs[i + 1][j]) {
            out.push_str(&format!("+{}\n", b[j]));
            j += 1;
        } else {
            out.push_str(&format!("-{}\n", a[i]));
            i += 1;
        }
    }
    out
}

fn convert_checked(md: &str) -> Result<(String, EmittedConstructs), String> {
    let (out, e) = markdown_to_storage(md);
    check_output(&out, &e)?;
    Ok((out, e))
}

/// The decoded text of every text node and CDATA section, in document order.
fn all_text(nodes: &[Node], out: &mut String) {
    for n in nodes {
        match n {
            Node::Text(t) => out.push_str(t),
            Node::CData { text, .. } => out.push_str(text),
            Node::Element(e) => all_text(&e.children, out),
        }
    }
}

fn text_of(storage_out: &str) -> String {
    let mut s = String::new();
    all_text(&storage::parse(storage_out).nodes, &mut s);
    s
}

#[test]
fn u23_md_to_storage_golden() -> TestResult {
    let mut failures = Vec::new();
    for name in GOLDEN {
        let md = std::fs::read_to_string(golden_dir().join(format!("{name}.md")))?;
        let expected = std::fs::read_to_string(golden_dir().join(format!("{name}.xml")))?;
        let (out, e) = markdown_to_storage(&md);
        if out != expected {
            failures.push(format!("{name}:\n{}", diff(&expected, &out)));
        }
        if let Err(m) = check_output(&out, &e) {
            failures.push(format!("{name}: {m}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

#[test]
fn golden_outputs_pass_check_storage_body() -> TestResult {
    for name in GOLDEN {
        let md = std::fs::read_to_string(golden_dir().join(format!("{name}.md")))?;
        let (out, _) = markdown_to_storage(&md);
        assert_eq!(check_storage_body(&out), Ok(()), "{name}");
    }
    Ok(())
}

/// Task 2 review M-4: every golden output uses only the parser's `CONVERTER_HTML` elements
/// (no attribute but `href` on `<a>`) and the code macro, so `construct_spans` reports exactly
/// the recorded code macros and nothing else.
#[test]
fn golden_outputs_use_only_converter_markup() -> TestResult {
    let mut macros = 0;
    for name in GOLDEN {
        let md = std::fs::read_to_string(golden_dir().join(format!("{name}.md")))?;
        let (out, e) = markdown_to_storage(&md);
        let doc = storage::parse(&out);
        assert!(doc.xml_ok, "{name}");
        only_converter_markup(&doc.nodes).map_err(|m| format!("{name}: {m}"))?;
        let spans = construct_spans(&doc);
        assert_eq!(spans.len(), e.code_blocks.len(), "{name}: {spans:?}");
        for ((kind, r), c) in spans.iter().zip(&e.code_blocks) {
            assert_eq!(*kind, ConstructKind::Macro, "{name}");
            assert_eq!(*r, c.byte_range, "{name}");
        }
        macros += e.code_blocks.len();
    }
    // Not vacuous: the goldens hold code macros.
    assert!(macros >= 8, "{macros}");
    Ok(())
}

#[test]
fn u23_md_to_storage_escapes_raw_html_and_xml_specials() -> TestResult {
    let md = "Text <script>x</script> <ac:structured-macro ac:name=\"toc\"/> \
              <ri:user ri:userkey=\"x\"/> &nbsp; &amp;nbsp; ]]> 1 < 2 & 3 > 0 \"q\" 'a'\n\n\
              <ri:user ri:userkey=\"y\"/>\n\n\
              <div>\n<ac:link><ri:page ri:content-title=\"X\"/></ac:link>\n</div>\n\n\
              [t](https://x.example/a\"b \"title with \\\" and <b>\")\n";
    let (out, e) = convert_checked(md)?;
    assert!(e.code_blocks.is_empty());
    assert_eq!(
        out,
        "<p>Text &lt;script&gt;x&lt;/script&gt; &lt;ac:structured-macro ac:name=\"toc\"/&gt; \
         &lt;ri:user ri:userkey=\"x\"/&gt; \u{a0} &amp;nbsp; ]]&gt; 1 &lt; 2 &amp; 3 &gt; 0 \
         \"q\" 'a'</p>\n\
         <p>&lt;ri:user ri:userkey=\"y\"/&gt;</p>\n\
         <p>&lt;div&gt;<br/>&lt;ac:link&gt;&lt;ri:page ri:content-title=\"X\"/&gt;&lt;/ac:link&gt;\
         <br/>&lt;/div&gt;</p>\n\
         <p><a href=\"https://x.example/a&quot;b\">t</a></p>"
    );
    let doc = storage::parse(&out);
    assert!(
        construct_spans(&doc).is_empty(),
        "{:?}",
        construct_spans(&doc)
    );
    // The escaped text decodes back to the source characters.
    let text = text_of(&out);
    assert!(
        text.contains("<ac:structured-macro ac:name=\"toc\"/>"),
        "{text}"
    );
    assert!(text.contains("<ri:user ri:userkey=\"x\"/>"), "{text}");
    assert!(text.contains("&nbsp; ]]> 1 < 2 & 3 > 0"), "{text}");
    // The link title is not written (no attribute but `href`); the `"` in the destination is
    // an attribute escape.
    assert!(!out.contains("title with"), "{out}");
    Ok(())
}

#[test]
fn u24_storage_cdata_split_in_fenced_and_inline_code() -> TestResult {
    let (out, e) = convert_checked("```\na ]]> b ]]> c ]]]]> d\n```\n\nInline `x]]>y` code.\n")?;
    assert_eq!(
        out,
        "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body><![CDATA[a ]]]]><![CDATA[> b \
         ]]]]><![CDATA[> c ]]]]]]><![CDATA[> d]]></ac:plain-text-body></ac:structured-macro>\n\
         <p>Inline <code>x]]&gt;y</code> code.</p>"
    );
    assert_eq!(e.code_blocks.len(), 1);
    // The CDATA sections join back to the exact body.
    let doc = storage::parse(&out);
    let mut body = String::new();
    if let Some(Node::Element(m)) = doc.nodes.first() {
        all_text(&m.children, &mut body);
    }
    assert_eq!(body, "a ]]> b ]]> c ]]]]> d");
    // A body that is only `]]>`, and one ending in `]]`.
    let (out, _) = convert_checked("```\n]]>\n```\n\n```\nx]]\n```\n")?;
    assert!(out.contains("<![CDATA[]]]]><![CDATA[>]]>"), "{out}");
    assert!(out.contains("<![CDATA[x]]]]>"), "{out}");
    // (The `\n` is the separator between the two top-level blocks.)
    assert_eq!(text_of(&out), "]]>\nx]]");
    Ok(())
}

/// The code macro is the shape storage → Markdown reads back as the same fenced block (the
/// U-25 round trip itself is Task 6's).
#[test]
fn code_macro_reads_back_as_the_same_fence() -> TestResult {
    let md = "```rust\nlet a = \"]]>\"; // <ri:user ri:userkey=\"x\"/> [macro: toc {}]\n```\n";
    let (out, _) = convert_checked(md)?;
    let (back, report, _) = storage_to_markdown(&out, &UserResolutions::new());
    assert_eq!(back, md);
    assert!(!report.lossy && !report.fallback, "{report:?}");
    Ok(())
}

#[test]
fn code_macro_language_rule() -> TestResult {
    let long = format!("```{}\nx\n```", "a".repeat(33));
    let cases = [
        ("```rust\nx\n```", Some("rust")),
        ("```c++ extra words\nx\n```", Some("c++")),
        ("```c#,foo\nx\n```", Some("c#")),
        ("```{.rust}\nx\n```", None),
        ("```a\"b\nx\n```", None),
        (long.as_str(), None),
        ("    indented\n", None),
    ];
    for (md, lang) in cases {
        let (out, e) = convert_checked(md)?;
        assert_eq!(e.code_blocks.len(), 1, "{md}");
        let param = lang.map(|l| format!("<ac:parameter ac:name=\"language\">{l}</ac:parameter>"));
        assert_eq!(
            out.contains("<ac:parameter"),
            param.is_some(),
            "{md} -> {out}"
        );
        if let Some(p) = param {
            assert!(out.contains(&p), "{md} -> {out}");
        }
    }
    Ok(())
}

#[test]
fn images_become_links_never_ac_image() -> TestResult {
    let (out, _) = convert_checked(
        "![alt text](https://x.example/a.png) ![](https://x.example/b.png) \
         ![x](javascript:y) [![i](https://x.example/i.png) go](https://x.example)",
    )?;
    assert_eq!(
        out,
        "<p><a href=\"https://x.example/a.png\">alt text</a> \
         <a href=\"https://x.example/b.png\">https://x.example/b.png</a> x (javascript:y) \
         <a href=\"https://x.example\">i go</a></p>"
    );
    assert!(!out.contains("ac:image") && !out.contains("<img"));
    let inv = storage_constructs(&out);
    assert!(inv.images.is_empty());
    assert_eq!(
        inv.links,
        [
            "https://x.example/a.png",
            "https://x.example/b.png",
            "https://x.example"
        ]
    );
    Ok(())
}

#[test]
fn links_only_safe_schemes() -> TestResult {
    let (out, _) = convert_checked(
        "[a](javascript:alert(1)) [b](data:text/html,x) [c](/rel) [d](#top) [e](vbscript:x) \
         [f](HTTPS://X.example) [g](http://x.example) [h](mailto:a@b.example) [i]() \
         <javascript:x> <a@b.example> [](javascript:z)",
    )?;
    assert_eq!(
        out,
        "<p>a (javascript:alert(1)) b (data:text/html,x) c (/rel) d (#top) e (vbscript:x) \
         <a href=\"HTTPS://X.example\">f</a> <a href=\"http://x.example\">g</a> \
         <a href=\"mailto:a@b.example\">h</a> i \
         javascript:x <a href=\"mailto:a@b.example\">a@b.example</a> javascript:z</p>"
    );
    let spans = construct_spans(&storage::parse(&out));
    assert!(spans.is_empty(), "{spans:?} in {out}");
    Ok(())
}

#[test]
fn task_items_are_plain_text() -> TestResult {
    let (out, _) = convert_checked("- [ ] open\n- [x] done\n- plain\n")?;
    assert_eq!(
        out,
        "<ul><li>[ ] open</li><li>[x] done</li><li>plain</li></ul>"
    );
    assert!(!out.contains("ac:task"));
    Ok(())
}

#[test]
fn at_mention_stays_text() -> TestResult {
    let (out, _) = convert_checked("ping @jdoe and @user:8a7f and [~jdoe]")?;
    assert_eq!(out, "<p>ping @jdoe and @user:8a7f and [~jdoe]</p>");
    assert!(storage_constructs(&out).mentions.is_empty());
    assert!(!out.contains("ri:user"));
    Ok(())
}

#[test]
fn emitted_code_macro_ranges() -> TestResult {
    let md = "intro\n\n```rust\nfn a() {}\n```\n\n\
              - item\n\n  ```\n  in item ]]>\n  ```\n\n\
              > quote\n>\n>     indented in quote\n\n\
              | a |\n|---|\n| `c` |\n\n\
              ```\n```\n";
    let (out, e) = convert_checked(md)?;
    assert_eq!(e.code_blocks.len(), 4, "{out}");
    let mut prev_end = 0;
    for c in &e.code_blocks {
        assert_eq!(c.kind, ContainerKind::CodeMacro);
        assert!(c.byte_range.start >= prev_end, "sorted, disjoint");
        prev_end = c.byte_range.end;
        let slice = &out[c.byte_range.clone()];
        assert!(slice.starts_with(MACRO_OPEN), "{slice}");
        assert!(slice.ends_with(MACRO_CLOSE), "{slice}");
        // Exactly one macro: the slice parses alone as one `ac:structured-macro`.
        let doc = storage::parse(slice);
        assert!(doc.xml_ok);
        match doc.nodes.as_slice() {
            [Node::Element(m)] => {
                assert_eq!(m.qname(), "ac:structured-macro");
                assert_eq!(m.byte_range, 0..slice.len());
            }
            other => panic!("{other:?}"),
        }
    }
    Ok(())
}

#[test]
fn xml_invalid_chars_replaced() -> TestResult {
    let bad = ['\u{0}', '\u{1}', '\u{1F}', '\u{FFFE}', '\u{FFFF}'];
    for c in bad {
        let md = format!(
            "p{c}q [t{c}](https://x.example/{c}) `i{c}j`\n\n```\nf{c}g\n```\n\n| h{c} |\n|---|\n| d{c} |\n"
        );
        let (out, e) = convert_checked(&md)?;
        assert!(!out.contains(c), "{c:?} in {out:?}");
        assert!(out.contains("p\u{FFFD}q"), "{c:?}: {out:?}");
        assert!(out.contains("t\u{FFFD}"), "{c:?}: {out:?}");
        assert!(out.contains("i\u{FFFD}j"), "{c:?}: {out:?}");
        assert!(out.contains("f\u{FFFD}g"), "{c:?}: {out:?}");
        assert!(out.contains("h\u{FFFD}"), "{c:?}: {out:?}");
        assert!(out.contains("d\u{FFFD}"), "{c:?}: {out:?}");
        assert_eq!(e.code_blocks.len(), 1);
    }
    // TAB, LF and CR are never replaced; CR line ends are normalised to LF (as XML would).
    let (out, _) = convert_checked("a\tb\r\nc\rd\n\n```\nx\ty\r\nz\n```\n")?;
    assert!(!out.contains('\u{FFFD}'), "{out:?}");
    assert!(!out.contains('\r'), "{out:?}");
    assert_eq!(
        out,
        "<p>a\tb\nc\nd</p>\n<ac:structured-macro ac:name=\"code\"><ac:plain-text-body>\
         <![CDATA[x\ty\nz]]></ac:plain-text-body></ac:structured-macro>"
    );
    Ok(())
}

/// No nesting bound: 100 nested quotes stay 100 nested `<blockquote>`s, so the parser refuses
/// the output as too deep and the hard check (Task 6) fails closed on it instead of checking a
/// flattened body.
#[test]
fn deep_nesting_is_written_faithfully() -> TestResult {
    let md = format!("{} deep\n", ">".repeat(100));
    let (out, e) = markdown_to_storage(&md);
    assert!(e.code_blocks.is_empty());
    assert_eq!(out.matches("<blockquote>").count(), 100);
    assert_eq!(check_storage_body(&out), Err(StorageReject::TooDeep));
    assert!(!storage::parse(&out).xml_ok);
    Ok(())
}

#[test]
fn empty_and_blank_input() -> TestResult {
    for md in ["", "\n", "   \n\n", "\r\n"] {
        let (out, e) = convert_checked(md)?;
        assert_eq!(out, "", "{md:?}");
        assert!(e.code_blocks.is_empty());
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, .. ProptestConfig::default() })]

    /// Same output twice; well-formed converter markup, or refused as too deep (only nesting
    /// past the parser's bound can do that).
    #[test]
    fn deterministic_output(md in markdown()) {
        let (a, ea) = markdown_to_storage(&md);
        let (b, eb) = markdown_to_storage(&md);
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(&ea, &eb);
        match check_storage_body(&a) {
            Err(StorageReject::TooDeep) => {}
            _ => {
                if let Err(m) = check_output(&a, &ea) {
                    return Err(TestCaseError::fail(m));
                }
            }
        }
    }
}
