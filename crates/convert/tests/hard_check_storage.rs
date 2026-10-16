//! `hard_check_storage`: the storage re-parse hard check (spec §7.6, §13 U-24, U-25, plan
//! Task 6, PD-97).
//!
//! The converter's output is re-parsed with the storage parser; every `ac:`/`ri:` element,
//! every element outside the converter's own set and every `<a>` with an unsafe `href` must be
//! a code macro the converter recorded, in exactly the converter's shape. A faulty converter is
//! simulated by appending an unrecorded construct to real output (PD-64: no fault API in
//! `convert`).

mod common;

use std::ops::Range;

use atlas_duck_convert::storage::{self, Node};
use atlas_duck_convert::{
    ConstructKind, ContainerKind, EmittedCode, EmittedConstructs, StorageReject, Unrecorded,
    UserResolutions, check_markdown_placeholders, check_storage_body, hard_check_storage,
    markdown_to_storage, storage_to_markdown,
};
use common::{CODE_MACRO_OPEN, check_storage_output, md_fragment, storage_fragment};
use proptest::prelude::*;
use pulldown_cmark::{Event, Options, Parser};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn rec(kind: ContainerKind, byte_range: Range<usize>) -> EmittedCode {
    EmittedCode { kind, byte_range }
}

fn record(list: Vec<EmittedCode>) -> EmittedConstructs {
    EmittedConstructs { code_blocks: list }
}

fn whole(s: &str) -> EmittedConstructs {
    record(vec![rec(ContainerKind::CodeMacro, 0..s.len())])
}

fn unrecorded(kind: ConstructKind, count: u64) -> Result<(), Unrecorded> {
    Err(Unrecorded { kind, count })
}

/// A code macro of the converter's shape around `inner`.
fn code_macro(inner: &str) -> String {
    format!("{CODE_MACRO_OPEN}{inner}</ac:structured-macro>")
}

#[test]
fn u24_storage_code_body_containers() -> TestResult {
    let cases: [(&str, usize); 12] = [
        ("```\nlet a = 1;\n```\n", 1),
        ("```\n{code}\nx\n{code}\n```\n", 1),
        ("```java\n{noformat}\n```\n", 1),
        (
            "```\n{code}\n{noformat}\n```\n\n```\n{noformat}{code}\n```\n",
            2,
        ),
        ("```\nx ]]> y ]]]]> z ]]\n```\n", 1),
        ("~~~xml\n<![CDATA[ a ]]> b\n~~~\n", 1),
        (
            "inline `]]>` and `{code}` and `{noformat}` and `<ac:structured-macro>`\n",
            0,
        ),
        (
            "```\n<ac:structured-macro ac:name=\"include\"><ri:user ri:userkey=\"x\"/>\
             </ac:structured-macro> <!-- c -->\n```\n",
            1,
        ),
        (
            "> a\n>\n> ```\n> {noformat} ]]> <ri:user ri:userkey=\"x\"/>\n> ```\n\n\
             - item\n\n  ```\n  {code} ]]>\n  ```\n",
            2,
        ),
        ("    indented {code} ]]> <ac:x/>\n", 1),
        ("```\n```\n", 1),
        ("| `]]>` | `{code}` |\n|---|---|\n| <ac:link/> | x |\n", 0),
    ];
    for (md, macros) in cases {
        let (out, e) = markdown_to_storage(md);
        assert_eq!(hard_check_storage(&out, &e), Ok(()), "{md:?} -> {out:?}");
        assert_eq!(check_storage_body(&out), Ok(()), "{md:?} -> {out:?}");
        assert_eq!(e.code_blocks.len(), macros, "{md:?} -> {out:?}");
        check_storage_output(&out, &e)?;
        // The records are what makes them pass: without them every code macro is unrecorded.
        if macros > 0 {
            assert_eq!(
                hard_check_storage(&out, &EmittedConstructs::default()),
                unrecorded(ConstructKind::Macro, macros as u64),
                "{md:?}"
            );
        }
    }
    Ok(())
}

/// The faults core's `testing` hook appends (Task 9: `RiUser`, `IncludeMacro`, `AcLink`) and
/// the markup case, each with the kind it must be reported as.
const PLAN_FAULTS: [(&str, ConstructKind); 4] = [
    ("<ri:user ri:userkey=\"x\"/>", ConstructKind::Mention),
    (
        "<ac:structured-macro ac:name=\"include\"/>",
        ConstructKind::Include,
    ),
    (
        "<ac:link><ri:page ri:content-title=\"X\"/></ac:link>",
        ConstructKind::Link,
    ),
    ("<img src=\"https://x\"/>", ConstructKind::Markup),
];

/// More faults, one per PD-97 rule (and the T2 refinement that an `ac:link` to a user or an
/// attachment is reported as `Mention`/`Attachment`, not `Link`).
const MORE_FAULTS: [(&str, ConstructKind); 22] = [
    (
        "<ac:structured-macro ac:name=\"excerpt-include\"/>",
        ConstructKind::Include,
    ),
    (
        "<ac:structured-macro ac:name=\"INCLUDE\"/>",
        ConstructKind::Include,
    ),
    (
        "<ac:structured-macro ac:name=\"toc\"/>",
        ConstructKind::Macro,
    ),
    (
        "<ac:structured-macro ac:name=\"html\"><ac:plain-text-body><![CDATA[<b>x</b>]]>\
         </ac:plain-text-body></ac:structured-macro>",
        ConstructKind::Macro,
    ),
    ("<ac:emoticon ac:name=\"smile\"/>", ConstructKind::Macro),
    ("<ri:url ri:value=\"https://x\"/>", ConstructKind::Macro),
    (
        "<ac:image><ri:attachment ri:filename=\"a.png\"/></ac:image>",
        ConstructKind::Image,
    ),
    (
        "<ri:attachment ri:filename=\"a.pdf\"/>",
        ConstructKind::Attachment,
    ),
    (
        "<ac:link><ri:attachment ri:filename=\"a.pdf\"/></ac:link>",
        ConstructKind::Attachment,
    ),
    (
        "<ac:link><ri:user ri:userkey=\"x\"/></ac:link>",
        ConstructKind::Mention,
    ),
    ("<ri:space ri:space-key=\"S\"/>", ConstructKind::Link),
    (
        "<ri:content-entity ri:content-id=\"1\"/>",
        ConstructKind::Link,
    ),
    ("<p><a href=\"javascript:x\">j</a></p>", ConstructKind::Link),
    (
        "<p><a href=\"https://x\" title=\"t\">t</a></p>",
        ConstructKind::Link,
    ),
    ("<script>x</script>", ConstructKind::Markup),
    ("<iframe src=\"https://x\"/>", ConstructKind::Markup),
    ("<style>p {}</style>", ConstructKind::Markup),
    ("<object/>", ConstructKind::Markup),
    ("<p class=\"c\">x</p>", ConstructKind::Markup),
    (
        "<zz:structured-macro xmlns:zz=\"http://atlassian.com/content\" zz:name=\"include\"/>",
        ConstructKind::Markup,
    ),
    ("<p xmlns=\"u\">x</p>", ConstructKind::Markup),
    ("<!-- c -->", ConstructKind::Markup),
];

/// A real conversion holding prose look-alikes, a code macro (with a language) and a quote.
const BASE_MD: &str = "Intro @jdoe [macro: toc {}] <ri:user ri:userkey=\"x\"/>\n\n\
                       ```rust\nfn main() { \"]]>\" }\n```\n\n> a\n>\n> b [l](https://x.example)\n";

#[test]
fn u24_storage_faulty_converter_detected() -> TestResult {
    let (out, e) = markdown_to_storage(BASE_MD);
    assert_eq!(e.code_blocks.len(), 1, "{out:?}");
    assert_eq!(hard_check_storage(&out, &e), Ok(()));
    for (fault, kind) in PLAN_FAULTS.iter().chain(MORE_FAULTS.iter()) {
        let faulty = format!("{out}{fault}");
        assert_eq!(
            hard_check_storage(&faulty, &e),
            unrecorded(*kind, 1),
            "{faulty:?}"
        );
        // A faulty converter that records its own fault as a code macro is not trusted either.
        let mut forged = e.clone();
        forged
            .code_blocks
            .push(rec(ContainerKind::CodeMacro, out.len()..faulty.len()));
        assert!(hard_check_storage(&faulty, &forged).is_err(), "{faulty:?}");
    }
    Ok(())
}

#[test]
fn hard_check_storage_counts_images_and_links() -> TestResult {
    let none = EmittedConstructs::default();
    assert_eq!(
        hard_check_storage(
            "<p><ac:image><ri:attachment ri:filename=\"a.png\"/></ac:image> \
             <ac:image><ri:url ri:value=\"https://x\"/></ac:image></p>",
            &none
        ),
        unrecorded(ConstructKind::Image, 2)
    );
    assert_eq!(
        hard_check_storage(
            "<p><ac:link><ri:page ri:content-title=\"A\"/></ac:link> \
             <a href=\"javascript:x\">j</a> <ri:space ri:space-key=\"S\"/> \
             <ri:content-entity ri:content-id=\"1\"/> <a href=\"https://x\" title=\"t\">t</a> \
             <a href=\"data:text/html,x\">d</a></p>",
            &none
        ),
        unrecorded(ConstructKind::Link, 6)
    );
    // The first unrecorded construct decides the kind; the count is of that kind only.
    assert_eq!(
        hard_check_storage(
            "<p><ri:attachment ri:filename=\"f\"/><ri:user ri:userkey=\"u\"/>\
             <ac:image/><ri:attachment ri:filename=\"g\"/></p>",
            &none
        ),
        unrecorded(ConstructKind::Attachment, 2)
    );
    assert_eq!(
        hard_check_storage("<p><img src=\"a\"/><ac:image/><img src=\"b\"/></p>", &none),
        unrecorded(ConstructKind::Markup, 2)
    );
    // Outermost constructs only: an image inside a link counts once, as the link.
    assert_eq!(
        hard_check_storage(
            "<ac:link><ri:page ri:content-title=\"A\"/><ac:link-body><ac:image/></ac:link-body>\
             </ac:link>",
            &none
        ),
        unrecorded(ConstructKind::Link, 1)
    );
    // Constructs inside safe links and converter HTML are found.
    assert_eq!(
        hard_check_storage(
            "<p><a href=\"https://x\"><ac:structured-macro ac:name=\"include\"/></a></p>\
             <table><tbody><tr><td><ri:user ri:userkey=\"u\"/></td></tr></tbody></table>",
            &none
        ),
        unrecorded(ConstructKind::Include, 1)
    );
    // Converter output alone passes.
    assert_eq!(
        hard_check_storage(
            "<p>a <a href=\"HTTPS://x\">b</a> <a href=\"mailto:a@b\">c</a></p><hr/>",
            &none
        ),
        Ok(())
    );
    Ok(())
}

#[test]
fn recorded_code_macro_passes() -> TestResult {
    let goods = [
        code_macro(
            "<ac:plain-text-body><![CDATA[<ri:user ri:userkey=\"x\"/> \
             <ac:structured-macro ac:name=\"include\"/> <img src=\"x\"/>]]></ac:plain-text-body>",
        ),
        code_macro(
            "<ac:parameter ac:name=\"language\">c++</ac:parameter><ac:plain-text-body>\
             <![CDATA[a ]]]]><![CDATA[> <ri:user/> ]]]]><![CDATA[>]]></ac:plain-text-body>",
        ),
        code_macro("<ac:plain-text-body><![CDATA[]]></ac:plain-text-body>"),
        code_macro("<ac:plain-text-body><![CDATA[<!-- c --> <!DOCTYPE x>]]></ac:plain-text-body>"),
    ];
    for s in &goods {
        assert_eq!(hard_check_storage(s, &whole(s)), Ok(()), "{s}");
        assert_eq!(
            hard_check_storage(s, &EmittedConstructs::default()),
            unrecorded(ConstructKind::Macro, 1),
            "{s}"
        );
        // A duplicated record is harmless (the same macro).
        let mut twice = whole(s);
        twice.code_blocks.extend(whole(s).code_blocks);
        assert_eq!(hard_check_storage(s, &twice), Ok(()), "{s}");
    }
    // Inside converter markup, at its own range.
    let inner = &goods[1];
    let s = format!("<blockquote><ul><li>{inner}</li></ul></blockquote>");
    let start = "<blockquote><ul><li>".len();
    let e = record(vec![rec(
        ContainerKind::CodeMacro,
        start..start + inner.len(),
    )]);
    assert_eq!(hard_check_storage(&s, &e), Ok(()));
    Ok(())
}

/// PD-97 (d) and the T5 review: the hard check, not the converter, judges a recorded code
/// macro's shape. Only `ac:name="code"`, an optional first `language` parameter holding a
/// pattern-clean word, and one plain-text body of adjacent CDATA sections closing where the
/// record says, written byte for byte as the converter writes them, are trusted.
#[test]
fn a_record_must_be_a_code_macro_of_the_converters_shape() -> TestResult {
    let body = "<ac:plain-text-body><![CDATA[x]]></ac:plain-text-body>";
    let bads = [
        "<ac:structured-macro ac:name=\"toc\"/>".to_owned(),
        format!("<ac:structured-macro ac:name=\"noformat\">{body}</ac:structured-macro>"),
        format!("<ac:structured-macro ac:name=\"CODE\">{body}</ac:structured-macro>"),
        format!(
            "<ac:structured-macro ac:name=\"code\" ac:schema-version=\"1\">{body}\
             </ac:structured-macro>"
        ),
        format!("<ac:structured-macro ac:name=\"c&#111;de\">{body}</ac:structured-macro>"),
        format!("<ac:structured-macro ac:name='code'>{body}</ac:structured-macro>"),
        format!("<ac:structured-macro  ac:name=\"code\">{body}</ac:structured-macro>"),
        code_macro(&format!(
            "<ac:parameter ac:name=\"title\">t</ac:parameter>{body}"
        )),
        code_macro(&format!(
            "<ac:parameter ac:name=\"language\">rust</ac:parameter>\
             <ac:parameter ac:name=\"title\">t</ac:parameter>{body}"
        )),
        code_macro(&format!(
            "<ac:parameter ac:name=\"language\">a b</ac:parameter>{body}"
        )),
        code_macro(&format!(
            "<ac:parameter ac:name=\"language\">&lt;b&gt;</ac:parameter>{body}"
        )),
        code_macro(&format!(
            "<ac:parameter ac:name=\"language\">r&#117;st</ac:parameter>{body}"
        )),
        code_macro(&format!(
            "<ac:parameter ac:name=\"language\">{}</ac:parameter>{body}",
            "a".repeat(33)
        )),
        code_macro(&format!(
            "<ac:parameter ac:name=\"language\"></ac:parameter>{body}"
        )),
        code_macro(&format!(
            "<ac:parameter ac:name=\"language\"><ri:user ri:userkey=\"x\"/></ac:parameter>{body}"
        )),
        code_macro(&format!(
            "{body}<ac:parameter ac:name=\"language\">rust</ac:parameter>"
        )),
        code_macro(&format!(
            "<ac:parameter ac:name=\"language\">rust</ac:parameter> {body}"
        )),
        code_macro(&format!("{body}\n")),
        code_macro(&format!("{body}{body}")),
        code_macro(""),
        code_macro("<ac:plain-text-body></ac:plain-text-body>"),
        code_macro("<ac:plain-text-body/>"),
        code_macro("<ac:plain-text-body>x</ac:plain-text-body>"),
        code_macro("<ac:plain-text-body><![CDATA[x]]>y</ac:plain-text-body>"),
        code_macro("<ac:plain-text-body><![CDATA[a]]><!-- c --><![CDATA[b]]></ac:plain-text-body>"),
        code_macro("<ac:plain-text-body><![CDATA[a\r\nb]]></ac:plain-text-body>"),
        code_macro("<ac:plain-text-body ac:x=\"1\"><![CDATA[x]]></ac:plain-text-body>"),
        code_macro("<ac:plain-text-body><ri:user ri:userkey=\"x\"/></ac:plain-text-body>"),
        code_macro(&format!(
            "<ac:rich-text-body>{}</ac:rich-text-body>",
            code_macro(body)
        )),
        code_macro(&format!(
            "<ac:rich-text-body><p>x</p></ac:rich-text-body>{body}"
        )),
    ];
    for s in &bads {
        let got = hard_check_storage(s, &whole(s));
        assert!(
            matches!(
                got,
                Err(Unrecorded {
                    kind: ConstructKind::Macro,
                    ..
                })
            ),
            "{s}: {got:?}"
        );
    }
    // A good macro under a record that is not exactly its range, or of another kind.
    let s = format!("é{}", code_macro(body));
    let len = s.len();
    let start = 'é'.len_utf8();
    for r in [
        0..len,
        start + 1..len,
        start..len - 1,
        start..len + 1,
        start..start + CODE_MACRO_OPEN.len() + body.len(),
        1..len,
        Range {
            start: len,
            end: start,
        },
        0..usize::MAX,
        usize::MAX - 1..usize::MAX,
    ] {
        let e = record(vec![rec(ContainerKind::CodeMacro, r.clone())]);
        assert_eq!(
            hard_check_storage(&s, &e),
            unrecorded(ConstructKind::Macro, 1),
            "{r:?}"
        );
    }
    for kind in [
        ContainerKind::Code,
        ContainerKind::Noformat,
        ContainerKind::Quote,
    ] {
        let e = record(vec![rec(kind, start..len)]);
        assert_eq!(
            hard_check_storage(&s, &e),
            unrecorded(ConstructKind::Macro, 1),
            "{kind:?}"
        );
    }
    assert_eq!(
        hard_check_storage(&s, &record(vec![rec(ContainerKind::CodeMacro, start..len)])),
        Ok(())
    );
    Ok(())
}

#[test]
fn dropped_records_are_unrecorded() -> TestResult {
    let (out, e) = markdown_to_storage("```\na\n```\n\ntext\n\n```sh\nb ]]> c\n```\n\n    d\n");
    assert_eq!(e.code_blocks.len(), 3);
    assert_eq!(hard_check_storage(&out, &e), Ok(()));
    for skip in 0..3 {
        let fewer = record(
            e.code_blocks
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .map(|(_, c)| c.clone())
                .collect(),
        );
        assert_eq!(
            hard_check_storage(&out, &fewer),
            unrecorded(ConstructKind::Macro, 1)
        );
    }
    assert_eq!(
        hard_check_storage(&out, &EmittedConstructs::default()),
        unrecorded(ConstructKind::Macro, 3)
    );
    Ok(())
}

/// PD-97 (e), plan review I-3 d: when the re-parse of the converter's own output is not
/// `xml_ok`, the body is refused (kind `Markup`), never checked half.
#[test]
fn hard_check_fails_closed_on_unparsable_output() -> TestResult {
    let md = format!("{} deep\n", ">".repeat(100));
    let (out, e) = markdown_to_storage(&md);
    assert_eq!(check_storage_body(&out), Err(StorageReject::TooDeep));
    assert_eq!(
        hard_check_storage(&out, &e),
        unrecorded(ConstructKind::Markup, 1)
    );
    // Deep list nesting, with a code macro at the bottom that is recorded.
    let mut md = String::new();
    for i in 0..40 {
        md.push_str(&"  ".repeat(i));
        md.push_str("- a\n");
    }
    let indent = "  ".repeat(40);
    md.push_str(&format!("{indent}```\n{indent}x\n{indent}```\n"));
    let (out, e) = markdown_to_storage(&md);
    assert_eq!(e.code_blocks.len(), 1, "{out}");
    assert_eq!(check_storage_body(&out), Err(StorageReject::TooDeep));
    assert_eq!(
        hard_check_storage(&out, &e),
        unrecorded(ConstructKind::Markup, 1)
    );
    // Hand-made output that does not parse, with an empty record.
    let none = EmittedConstructs::default();
    for bad in [
        "<p>a",
        "a</p>",
        "<p>a</b>",
        "<p>]]></p>",
        "<p>&#0;</p>",
        "<p>\u{1}</p>",
        "<p>&a b;</p>",
        "<!DOCTYPE x><p>a</p>",
        "<!ENTITY e \"x\"><p>a</p>",
        "<?x y?><p>a</p>",
        "<?xml version=\"1.0\"?><p>a</p>",
        "</ad-storage-root><p>a</p>",
        "<p a=\"<\">x</p>",
    ] {
        assert_eq!(
            hard_check_storage(bad, &none),
            unrecorded(ConstructKind::Markup, 1),
            "{bad:?}"
        );
    }
    // A record cannot rescue an unparsable body.
    let s = format!(
        "{}<p>",
        code_macro("<ac:plain-text-body><![CDATA[x]]></ac:plain-text-body>")
    );
    let e = record(vec![rec(ContainerKind::CodeMacro, 0..s.len() - 3)]);
    assert_eq!(
        hard_check_storage(&s, &e),
        unrecorded(ConstructKind::Markup, 1)
    );
    Ok(())
}

#[test]
fn unrecorded_error_has_no_text() -> TestResult {
    const SENTINEL: &str = "SECRET_PAYLOAD_7f3a";
    let none = EmittedConstructs::default();
    for (s, kind) in [
        (
            format!("<ri:user ri:userkey=\"{SENTINEL}\"/>"),
            ConstructKind::Mention,
        ),
        (
            format!(
                "<ac:structured-macro ac:name=\"include\"><ac:parameter ac:name=\"\">{SENTINEL}</ac:parameter></ac:structured-macro>"
            ),
            ConstructKind::Include,
        ),
        (
            format!("<ac:structured-macro ac:name=\"{SENTINEL}\"/>"),
            ConstructKind::Macro,
        ),
        (
            format!("<ac:image><ri:attachment ri:filename=\"{SENTINEL}\"/></ac:image>"),
            ConstructKind::Image,
        ),
        (
            format!("<ri:attachment ri:filename=\"{SENTINEL}\"/>"),
            ConstructKind::Attachment,
        ),
        (
            format!("<p><a href=\"javascript:{SENTINEL}\">x</a></p>"),
            ConstructKind::Link,
        ),
        (
            format!("<p><img src=\"{SENTINEL}\"/></p>"),
            ConstructKind::Markup,
        ),
        (format!("<p>{SENTINEL}"), ConstructKind::Markup),
    ] {
        let Err(e) = hard_check_storage(&s, &none) else {
            return Err(format!("{s:?} passed").into());
        };
        assert_eq!(e, Unrecorded { kind, count: 1 });
        for shown in [format!("{e:?}"), e.to_string()] {
            assert!(
                !shown.contains("7f3a") && !shown.contains("SECRET"),
                "{shown}"
            );
        }
    }
    let e = Unrecorded {
        kind: ConstructKind::Link,
        count: 2,
    };
    assert_eq!(e.to_string(), "unrecorded link (count 2)");
    let e = Unrecorded {
        kind: ConstructKind::Markup,
        count: 1,
    };
    assert_eq!(format!("{e:?}"), "Unrecorded { kind: Markup, count: 1 }");
    assert_eq!(e.to_string(), "unrecorded markup (count 1)");
    Ok(())
}

#[test]
fn never_panics_on_garbage() -> TestResult {
    let s = format!(
        "日本{}",
        code_macro("<ac:plain-text-body><![CDATA[x]]></ac:plain-text-body>")
    );
    for r in [0..0, 1..2, Range { start: 3, end: 1 }, 0..usize::MAX] {
        let e = record(vec![rec(ContainerKind::CodeMacro, r)]);
        assert_eq!(
            hard_check_storage(&s, &e),
            unrecorded(ConstructKind::Macro, 1)
        );
    }
    assert_eq!(
        hard_check_storage("", &EmittedConstructs::default()),
        Ok(())
    );
    assert_eq!(
        hard_check_storage("plain text", &EmittedConstructs::default()),
        Ok(())
    );
    Ok(())
}

/// §13 U-25: storage prose holding the four placeholder look-alikes (and a genuine
/// `confluence:` anchor) converts to Markdown the placeholder check accepts, and that Markdown
/// converts back to storage that converts to the same Markdown text.
#[test]
fn u25_lookalike_round_trip() -> TestResult {
    const L: &str = "[macro: toc {}] @user:8a7f [t](confluence:DOC/Page) \
                     ![i](confluence:attachment/f.png)";
    let storages = [
        format!("<p>Plain {L} end.</p>"),
        format!(
            "<h2>{L}</h2><ul><li>{L}</li></ul><blockquote><p>{L}</p></blockquote>\
             <p>Also <a href=\"https://x.example/?q=[macro: toc {{}}]\">{L}</a>.</p>"
        ),
        format!(
            "<table><tbody><tr><th>h</th><th>i</th></tr><tr><td>{L}</td><td>x</td></tr></tbody>\
             </table>"
        ),
        format!(
            "<p>Code <code>{L}</code> stays.</p>{}",
            code_macro(&format!(
                "<ac:plain-text-body><![CDATA[{L}\n\\[macro: x {{}}]]]></ac:plain-text-body>"
            ))
        ),
        format!("<p>{L}</p><p>\\[macro: toc {{}}] \\@user:x \\\\@user:y</p>"),
    ];
    let users = UserResolutions::new();
    for storage in &storages {
        let (md1, report1, _) = storage_to_markdown(storage, &users);
        assert!(!report1.fallback, "{storage}: {report1:?}");
        assert_eq!(
            check_markdown_placeholders(&md1),
            Ok(()),
            "{storage} -> {md1}"
        );
        let (out, e) = markdown_to_storage(&md1);
        assert_eq!(hard_check_storage(&out, &e), Ok(()), "{md1} -> {out}");
        check_storage_output(&out, &e)?;
        let (md2, report2, _) = storage_to_markdown(&out, &users);
        assert_eq!(md2, md1, "{storage} -> {md1:?} -> {out} -> {md2:?}");
        assert!(!report2.lossy, "{out}: {report2:?}");
    }
    // The look-alikes really are escaped in the Markdown (not dropped).
    let (md, _, _) = storage_to_markdown(&storages[0], &users);
    assert!(md.contains("\\[macro: toc {}\\]"), "{md}");
    assert!(md.contains("\\@user:8a7f"), "{md}");
    assert!(md.contains("\\[t\\](confluence:DOC/Page)"), "{md}");
    assert!(md.contains("!\\[i\\](confluence:attachment/f.png)"), "{md}");
    // A genuine `<a href="confluence:…">` (PD-95: escaped text). The first Markdown escapes only
    // its `[` (`\[a link](confluence:…)`), the storage → Markdown of that text escapes both
    // brackets (`\[a link\](…)`): the same rendered text and placeholder-free both times, and
    // stable from the second round on (Task 6 report: a Task 3 asymmetry, not a U-25 case).
    let storage = "<p>Also <a href=\"confluence:DOC/Page\">a link</a>.</p>";
    let (md1, _, _) = storage_to_markdown(storage, &users);
    assert_eq!(md1, "Also \\[a link](confluence:DOC/Page).\n");
    let (out1, e1) = markdown_to_storage(&md1);
    assert_eq!(hard_check_storage(&out1, &e1), Ok(()));
    let (md2, _, _) = storage_to_markdown(&out1, &users);
    assert_eq!(md2, "Also \\[a link\\](confluence:DOC/Page).\n");
    let (out2, e2) = markdown_to_storage(&md2);
    assert_eq!(out2, out1);
    assert_eq!(hard_check_storage(&out2, &e2), Ok(()));
    for md in [&md1, &md2] {
        assert_eq!(check_markdown_placeholders(md), Ok(()), "{md}");
    }
    assert_eq!(storage_to_markdown(&out2, &users).0, md2);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The fuzz (§13 U-24).

/// The fuzz alphabet: markup delimiters, `]]>`, CDATA and `ac:`/`ri:` look-alikes, entities,
/// autolinks, link titles with `"`, tables with raw HTML in cells, CR/LF mixes, bidi and line
/// separators, the XML-1.0-invalid characters, declarations, namespace declarations, raw HTML,
/// and Markdown structure.
const FRAGMENTS: &[&str] = &[
    "<",
    ">",
    "&",
    "\"",
    "'",
    "]]>",
    "]]",
    "<![CDATA[",
    "]]]]><![CDATA[>",
    "ac:",
    "ri:",
    "<ac:structured-macro ac:name=\"include\">",
    "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body><![CDATA[x]]></ac:plain-text-body></ac:structured-macro>",
    "</ac:structured-macro>",
    "<ri:user ri:userkey=\"x\"/>",
    "<ac:link><ri:page ri:content-title=\"X\"/></ac:link>",
    "<ac:image><ri:attachment ri:filename=\"f.png\"/></ac:image>",
    "&nbsp;",
    "&amp;",
    "&lt;",
    "&gt;",
    "&quot;",
    "&#0;",
    "&#1;",
    "&#x1F;",
    "&#xFFFE;",
    "&#xFFFF;",
    "&#xD800;",
    "&#123;",
    "&#93;&#93;&#62;",
    "&#60;ri:user/&#62;",
    "&foo;",
    "&uuml;",
    "&amp;lt;",
    "\\&lt;",
    "&e;",
    "<javascript:x>",
    "<JaVaScRiPt:alert(1)>",
    "<https://x.example/a?b=1&c=2>",
    "<mailto:a@b.example>",
    "<a@b.example>",
    "<data:text/html,x>",
    "<confluence:DOC/Page>",
    "[t](https://x.example \"ti\\\"tle\")",
    "[t](https://x.example 'a\"b')",
    "[t](<https://x.example/\u{1} a> \"q\")",
    "[t](javascript:alert(1) \"x\")",
    "[t](confluence:DOC/P)",
    "![i](confluence:attachment/f.png)",
    "![i](https://x.example/i.png \"t\\\"\")",
    "[<ri:user ri:userkey=\"x\"/>](https://x.example)",
    "[x](https://x.example/\"><script>)",
    "![<ac:image/>](https://x.example/\" onerror=\"y)",
    "[r]\n\n[r]: https://x.example \"t\\\"\"\n",
    "[macro: toc {}]",
    "@user:abc",
    "\n| a | <b>x</b> |\n|---|---|\n| <ri:user ri:userkey=\"x\"/> | <img src=x> |\n",
    "\n| <ac:structured-macro ac:name=\"toc\"/> | `]]>` |\n|:--|--:|\n| ]]> | &nbsp; |\n",
    "\n| <!DOCTYPE x> | <?x ?> |\n|---|---|\n| <script>x</script> | \"q\" |\n",
    "\r\n",
    "\r",
    "\n",
    "\n\n",
    "\r\n\r\n",
    "\u{202E}",
    "\u{2028}",
    "\u{2029}",
    "\u{0}",
    "\u{1}",
    "\u{8}",
    "\u{B}",
    "\u{C}",
    "\u{1B}",
    "\u{1F}",
    "\u{7F}",
    "\u{85}",
    "\u{FEFF}",
    "\u{FFFE}",
    "\u{FFFF}",
    "\t",
    "<!DOCTYPE x [<!ENTITY e \"y\">]>",
    "<!ENTITY e \"y\">",
    "<?x ?>",
    "<?xml version=\"1.0\"?>",
    "xmlns:zz=\"u\"",
    "<zz:x xmlns:zz=\"u\">",
    "</zz:x>",
    "<p xmlns=\"u\">",
    "<p xml:lang=\"de\">",
    "<!-- c -->",
    "<script>x</script>",
    "<style>p{}</style>",
    "<iframe src=x>",
    "<img src=\"x\" onerror=\"y\">",
    "<object>",
    "<div>\n",
    "</div>",
    "<b>",
    "</b>",
    "<a href=\"javascript:x\">",
    "</a>",
    "<br/>",
    "`",
    "``",
    "*",
    "**",
    "_",
    "__",
    "~~",
    "\\",
    "[",
    "]",
    "](",
    "(",
    ")",
    "!",
    "#",
    "## ",
    "---\n",
    "- ",
    "> ",
    "1. ",
    "    ",
    "  \n",
    "- [ ] ",
    "- [x] ",
    "|",
    "\n|---|\n",
    "word",
];

/// Info strings for the generated fences.
const INFO: &[&str] = &[
    "",
    "rust",
    "c++",
    "c#",
    "x\"y",
    "<b>",
    "]]>",
    "a b",
    "{code}",
    "&lt;",
    "xml",
    "<ri:user/>",
];

/// A fenced block: backticks or tildes, 3 to 12 long, an info string, a body from the
/// alphabet, and a closing fence of 0 to 13 (so some stay open to the end of their container,
/// and some closers are too short).
fn fence() -> impl Strategy<Value = String> {
    (
        any::<bool>(),
        3..=12usize,
        prop::sample::select(INFO.to_vec()),
        proptest::collection::vec(prop::sample::select(FRAGMENTS.to_vec()), 0..8),
        0..=13usize,
    )
        .prop_map(|(tilde, open, info, body, close)| {
            let c = if tilde { "~" } else { "`" };
            format!(
                "\n{}{info}\n{}\n{}\n",
                c.repeat(open),
                body.concat(),
                c.repeat(close)
            )
        })
}

fn fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        8 => prop::sample::select(FRAGMENTS.to_vec()).prop_map(str::to_owned),
        2 => fence(),
        1 => "[a-z]{1,5}",
        1 => any::<char>().prop_map(String::from),
        1 => md_fragment(),
        1 => storage_fragment(),
    ]
}

fn leaf() -> impl Strategy<Value = String> {
    proptest::collection::vec(fragment(), 0..24).prop_map(|v| v.concat())
}

#[derive(Debug, Clone, Copy)]
enum Container {
    Quote,
    Dash,
    Star,
    Plus,
    Ordered,
    Paren,
    Task,
}

const CONTAINERS: [Container; 7] = [
    Container::Quote,
    Container::Dash,
    Container::Star,
    Container::Plus,
    Container::Ordered,
    Container::Paren,
    Container::Task,
];

/// `child` inside one container: a quote prefixes every line, a list item its first line and
/// indents the others. (Mixed bullet characters keep `- - -` thematic breaks rare.)
fn nest(kind: Container, child: &str) -> String {
    let (first, rest) = match kind {
        Container::Quote => ("> ", "> "),
        Container::Dash => ("- ", "  "),
        Container::Star => ("* ", "  "),
        Container::Plus => ("+ ", "  "),
        Container::Ordered => ("1. ", "   "),
        Container::Paren => ("2) ", "   "),
        Container::Task => ("- [ ] ", "  "),
    };
    let mut out = String::with_capacity(child.len() + 16);
    for (i, line) in child.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(if i == 0 { first } else { rest });
        out.push_str(line);
    }
    out
}

/// Markdown with containers nested up to 16 levels: a chain of 0–16 containers around one
/// leaf, or a tree of containers (up to 16 deep) with one or two children each.
fn nested_markdown() -> impl Strategy<Value = String> {
    let chain = || {
        let kinds = prop_oneof![0..=16usize, 10..=16usize].prop_flat_map(|n| {
            proptest::collection::vec(prop::sample::select(CONTAINERS.to_vec()), n)
        });
        (kinds, leaf()).prop_map(|(kinds, l)| kinds.iter().rev().fold(l, |acc, k| nest(*k, &acc)))
    };
    let tree = leaf().prop_recursive(16, 48, 2, |inner| {
        (
            prop::sample::select(CONTAINERS.to_vec()),
            proptest::collection::vec(inner, 1..3),
        )
            .prop_map(|(k, kids)| nest(k, &kids.join("\n\n")))
    });
    prop_oneof![
        3 => chain(),
        2 => tree,
        1 => proptest::collection::vec(chain(), 1..4).prop_map(|v| v.join("\n\n")),
    ]
}

/// Deepest Markdown tag nesting the fuzz draws (Start/End events of the converter's parser).
/// Each tag becomes at most one output element, plus `<tbody>` under a table and the
/// plain-text body under a code macro, so the output stays well inside `MAX_DEPTH` (64) and
/// `check_storage_body` can be asserted `Ok` for every case; deeper output is
/// `hard_check_fails_closed_on_unparsable_output`'s.
const MAX_TAG_DEPTH: usize = 48;

fn tag_depth(md: &str) -> usize {
    let md = md.replace("\r\n", "\n").replace('\r', "\n");
    let options =
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
    let (mut depth, mut max) = (0usize, 0usize);
    for ev in Parser::new_ext(&md, options) {
        match ev {
            Event::Start(_) => {
                depth += 1;
                max = max.max(depth);
            }
            Event::End(_) => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

fn storage_markdown() -> impl Strategy<Value = String> {
    nested_markdown().prop_filter("tag nesting within MAX_TAG_DEPTH", |md| {
        tag_depth(md) <= MAX_TAG_DEPTH
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    /// §13 U-24: for every generated Markdown input, re-parsing the converted storage finds no
    /// construct the converter did not record, and the output is a storage body the static
    /// check accepts.
    #[test]
    fn u24_storage_fuzz_reparse_finds_nothing_unrecorded(md in storage_markdown()) {
        let (out, e) = markdown_to_storage(&md);
        prop_assert_eq!(hard_check_storage(&out, &e), Ok(()), "md {:?} -> {:?}", md, out);
        prop_assert_eq!(check_storage_body(&out), Ok(()), "md {:?} -> {:?}", md, out);
        check_storage_output(&out, &e).map_err(TestCaseError::fail)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// Any converter output with one unrecorded construct appended fails with that kind,
    /// counted once.
    #[test]
    fn u24_storage_fuzz_appended_fault_detected(
        md in storage_markdown(),
        fault in prop::sample::select(
            PLAN_FAULTS.iter().chain(MORE_FAULTS.iter()).copied().collect::<Vec<_>>()
        ),
    ) {
        let (out, e) = markdown_to_storage(&md);
        let faulty = format!("{out}{}", fault.0);
        prop_assert_eq!(
            hard_check_storage(&faulty, &e),
            unrecorded(fault.1, 1),
            "md {:?} -> {:?}", md, faulty
        );
    }
}

/// The deepest nesting of `blockquote`/`ul`/`ol` elements in parsed storage.
fn container_depth(nodes: &[Node]) -> usize {
    nodes
        .iter()
        .map(|n| match n {
            Node::Element(e) => {
                let own = usize::from(matches!(e.local.as_str(), "blockquote" | "ul" | "ol"));
                own + container_depth(&e.children)
            }
            _ => 0,
        })
        .max()
        .unwrap_or(0)
}

/// The fuzz must keep reaching what it is for: deep container nesting, code macros (split
/// CDATA among them), safe links, escaped raw HTML in table cells; and the depth filter must
/// reject only a small share of draws.
#[test]
fn fuzz_strategy_reaches_nesting_and_code() -> TestResult {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    const DRAWS: usize = 2000;
    let strategy = nested_markdown();
    let mut runner = TestRunner::deterministic();
    let (mut rejected, mut deep, mut code, mut split, mut links, mut cells) = (0, 0, 0, 0, 0, 0);
    for _ in 0..DRAWS {
        let md = strategy
            .new_tree(&mut runner)
            .map_err(|e| e.to_string())?
            .current();
        if tag_depth(&md) > MAX_TAG_DEPTH {
            rejected += 1;
            continue;
        }
        let (out, e) = markdown_to_storage(&md);
        let doc = storage::parse(&out);
        if container_depth(&doc.nodes) >= 10 {
            deep += 1;
        }
        if !e.code_blocks.is_empty() {
            code += 1;
        }
        if out.contains("]]]]><![CDATA[>") {
            split += 1;
        }
        if out.contains("<a href=") {
            links += 1;
        }
        if out.contains("<td>&lt;") || out.contains("<th>&lt;") {
            cells += 1;
        }
    }
    eprintln!(
        "{DRAWS} draws: rejected {rejected}, container depth >= 10 {deep}, code macros {code}, \
         split CDATA {split}, links {links}, raw HTML in cells {cells}"
    );
    assert!(rejected <= DRAWS / 10, "rejected: {rejected}");
    assert!(deep >= DRAWS / 10, "deep: {deep}");
    assert!(code >= DRAWS / 5, "code: {code}");
    assert!(split >= DRAWS / 50, "split: {split}");
    assert!(links >= DRAWS / 10, "links: {links}");
    assert!(cells >= DRAWS / 50, "cells: {cells}");
    Ok(())
}
