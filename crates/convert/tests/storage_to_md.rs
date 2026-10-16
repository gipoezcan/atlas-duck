//! storage → Markdown (plan Task 3, spec §7.6, PD-94, PD-95): placeholders, look-alike escaping,
//! user resolutions and the CDATA-first fallback.

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use atlas_duck_convert::storage::KNOWN_MACROS;
use atlas_duck_convert::{ConversionReport, LostCounts, UserResolutions, storage_to_markdown};
use proptest::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GOLDEN: [&str; 11] = [
    "basics",
    "macros",
    "code_cdata",
    "links_images",
    "mentions",
    "tasks_layouts",
    "entities",
    "lookalikes",
    "lookalikes_code",
    "fallback",
    "dates_tasks",
];

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/storage_to_md")
}

/// The map every golden is converted with.
fn golden_users() -> UserResolutions {
    UserResolutions::from([
        ("8a7f".to_owned(), Some("jdoe".to_owned())),
        ("9b00".to_owned(), None),
    ])
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

fn md(storage: &str) -> String {
    storage_to_markdown(storage, &UserResolutions::new()).0
}

fn report(storage: &str) -> ConversionReport {
    storage_to_markdown(storage, &UserResolutions::new()).1
}

/// Byte offsets of every unescaped `needle` (not preceded by an odd number of backslashes).
fn unescaped(out: &str, needle: &str) -> Vec<usize> {
    out.match_indices(needle)
        .map(|(i, _)| i)
        .filter(|&i| {
            out.as_bytes()[..i]
                .iter()
                .rev()
                .take_while(|&&b| b == b'\\')
                .count()
                % 2
                == 0
        })
        .collect()
}

#[test]
fn u23_storage_to_md_golden() -> TestResult {
    let mut failures = Vec::new();
    for name in GOLDEN {
        let input = std::fs::read_to_string(golden_dir().join(format!("{name}.xml")))?;
        let expected = std::fs::read_to_string(golden_dir().join(format!("{name}.md")))?;
        let (out, _, _) = storage_to_markdown(&input, &golden_users());
        if out != expected {
            failures.push(format!("{name}:\n{}", diff(&expected, &out)));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

#[test]
fn golden_reports() -> TestResult {
    let read = |name: &str| std::fs::read_to_string(golden_dir().join(format!("{name}.xml")));
    let (_, r, _) = storage_to_markdown(&read("macros")?, &golden_users());
    assert_eq!(
        r,
        ConversionReport {
            lossy: true,
            lost: LostCounts {
                macros: 6,
                images: 0,
                links: 0,
                layouts: 0
            },
            unknown_macros: vec!["roadmap-planner".to_owned(), "include".to_owned()],
            unresolved_users: 0,
            fallback: false,
        }
    );
    let (_, r, _) = storage_to_markdown(&read("code_cdata")?, &golden_users());
    assert_eq!(r.lost.macros, 1, "only sql-query is lost: {r:?}");
    assert_eq!(r.unknown_macros, vec!["sql-query".to_owned()]);
    let (_, r, _) = storage_to_markdown(&read("links_images")?, &golden_users());
    assert_eq!(
        r.lost,
        LostCounts {
            macros: 0,
            images: 2,
            links: 4,
            layouts: 0
        }
    );
    let (_, r, users) = storage_to_markdown(&read("mentions")?, &golden_users());
    assert_eq!(r.unresolved_users, 2);
    assert_eq!(
        r.lost.links, 4,
        "three ac:link mentions and one bare ri:user"
    );
    assert_eq!(
        users,
        UserResolutions::from([
            ("8a7f".to_owned(), Some("jdoe".to_owned())),
            ("9b00".to_owned(), None),
            ("key with space/ü".to_owned(), None),
        ])
    );
    let (_, r, _) = storage_to_markdown(&read("tasks_layouts")?, &golden_users());
    assert_eq!(r.lost.layouts, 1);
    assert_eq!(r.lost.macros, 1, "the task list (T3 review I-3)");
    assert!(r.lossy);
    let (_, r, _) = storage_to_markdown(&read("fallback")?, &golden_users());
    assert!(r.fallback && r.lossy, "{r:?}");
    // status, the outer task list (the nested one is not counted again), the emoticon, `_x_`
    // and details; the `ac:link` inside `<a>`; only `_x_` is unknown (Q11), dates are not lost.
    let (_, r, _) = storage_to_markdown(&read("dates_tasks")?, &golden_users());
    assert_eq!(
        r,
        ConversionReport {
            lossy: true,
            lost: LostCounts {
                macros: 5,
                images: 0,
                links: 1,
                layouts: 0
            },
            unknown_macros: vec!["_x_".to_owned()],
            unresolved_users: 0,
            fallback: false,
        }
    );
    for name in ["basics", "entities", "lookalikes", "lookalikes_code"] {
        let (_, r, _) = storage_to_markdown(&read(name)?, &golden_users());
        assert_eq!(r, ConversionReport::default(), "{name}");
    }
    Ok(())
}

#[test]
fn u23_storage_entities_and_mentions() -> TestResult {
    let out = md("<p>&uuml; &#252; a&nbsp;b</p>");
    assert_eq!(out, "ü ü a\u{a0}b\n");
    let users = UserResolutions::from([
        ("8a7f".to_owned(), Some("jdoe".to_owned())),
        ("9b00".to_owned(), None),
    ]);
    let storage = "<p><ac:link><ri:user ri:userkey=\"8a7f\"/></ac:link> \
                   <ac:link><ri:user ri:userkey=\"9b00\"/></ac:link> \
                   <ac:link><ri:user ri:username=\"asmith\"/></ac:link></p>";
    let (out, r, _) = storage_to_markdown(storage, &users);
    assert_eq!(out, "@jdoe @user:9b00 @asmith\n");
    assert_eq!(r.unresolved_users, 1);
    Ok(())
}

#[test]
fn users_map_returned_is_the_map_used() -> TestResult {
    let given = UserResolutions::from([
        ("8a7f".to_owned(), Some("jdoe".to_owned())),
        ("extra".to_owned(), Some("nobody".to_owned())),
    ]);
    let storage = "<p><ac:link><ri:user ri:userkey=\"8a7f\"/></ac:link> \
                   <ri:user ri:userkey=\"missing\"/> <ri:user ri:username=\"legacy\"/></p>";
    let (out, _, used) = storage_to_markdown(storage, &given);
    assert_eq!(out, "@jdoe @user:missing @legacy\n");
    assert_eq!(
        used,
        UserResolutions::from([
            ("8a7f".to_owned(), Some("jdoe".to_owned())),
            ("missing".to_owned(), None),
        ])
    );
    // A user picker parameter is display text of its macro, and its key is in the map too.
    let storage = "<ac:structured-macro ac:name=\"profile\"><ac:parameter ac:name=\"user\">\
                   <ri:user ri:userkey=\"8a7f\"/></ac:parameter></ac:structured-macro>";
    let (out, _, used) = storage_to_markdown(storage, &given);
    assert_eq!(out, "[macro: profile {user=jdoe}]\n");
    assert_eq!(used.len(), 1);
    // An empty key is no key: no entry, and a placeholder instead of a mention.
    let (out, _, used) = storage_to_markdown("<p><ri:user ri:userkey=\"\"/></p>", &given);
    assert_eq!(out, "[macro: user {}]\n");
    assert!(used.is_empty());
    // The fallback renders no mention and uses no map.
    let (_, r, used) = storage_to_markdown("<p><ri:user ri:userkey=\"8a7f\"/>", &given);
    assert!(r.fallback);
    assert!(used.is_empty());
    Ok(())
}

#[test]
fn conversion_report_counts_lossy_constructs() -> TestResult {
    let storage = "<ac:structured-macro ac:name=\"zzz-one\"/>\
                   <p><ac:structured-macro ac:name=\"zzz-two\"/> \
                   <ac:image><ri:attachment ri:filename=\"a.png\"/></ac:image> \
                   <ac:link><ri:page ri:content-title=\"P\"/></ac:link></p>\
                   <ac:structured-macro ac:name=\"zzz-one\"/>\
                   <ac:layout><ac:layout-section ac:type=\"single\"><ac:layout-cell><p>x</p>\
                   </ac:layout-cell></ac:layout-section></ac:layout>";
    let r = report(storage);
    assert_eq!(
        r.lost,
        LostCounts {
            macros: 3,
            images: 1,
            links: 1,
            layouts: 1
        }
    );
    assert!(r.lossy);
    assert_eq!(
        r.unknown_macros,
        vec!["zzz-one".to_owned(), "zzz-two".to_owned()]
    );
    let code = "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body><![CDATA[x]]>\
                </ac:plain-text-body></ac:structured-macro>";
    let r = report(code);
    assert!(!r.lossy, "{r:?}");
    assert_eq!(r, ConversionReport::default());
    let info = format!(
        "{code}<ac:structured-macro ac:name=\"info\"><ac:rich-text-body><p>i</p>\
         </ac:rich-text-body></ac:structured-macro>"
    );
    let r = report(&info);
    assert!(r.lossy);
    assert_eq!(r.lost.macros, 1);
    assert!(r.unknown_macros.is_empty(), "info is a known macro: {r:?}");
    Ok(())
}

#[test]
fn code_macro_cdata_to_fenced_code() -> TestResult {
    let code = |lang: &str, body: &str| {
        format!(
            "<ac:structured-macro ac:name=\"code\"><ac:parameter ac:name=\"language\">{lang}\
             </ac:parameter><ac:plain-text-body><![CDATA[{body}]]></ac:plain-text-body>\
             </ac:structured-macro>"
        )
    };
    assert_eq!(md(&code("rust", "fn x() {}")), "```rust\nfn x() {}\n```\n");
    assert_eq!(md(&code("c++", "x")), "```c++\nx\n```\n");
    assert_eq!(md(&code("c#", "x")), "```c#\nx\n```\n");
    // A language outside `[A-Za-z0-9+#-]{1,32}` is dropped.
    assert_eq!(md(&code("java script", "x")), "```\nx\n```\n");
    assert_eq!(md(&code("x`y", "x")), "```\nx\n```\n");
    assert_eq!(md(&code(&"a".repeat(33), "x")), "```\nx\n```\n");
    // A body holding a fence gets a longer one.
    assert_eq!(
        md(&code("", "a\n```\nb ```` c")),
        "`````\na\n```\nb ```` c\n`````\n"
    );
    // The CDATA split is joined back into one body.
    assert_eq!(md(&code("", "a]]]]><![CDATA[>b")), "```\na]]>b\n```\n");
    // An empty body.
    assert_eq!(md(&code("", "")), "```\n```\n");
    Ok(())
}

#[test]
fn code_in_list_item_and_table_cell() -> TestResult {
    let code = "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body><![CDATA[a\nb | c]]>\
                </ac:plain-text-body></ac:structured-macro>";
    let out = md(&format!("<ul><li>{code}</li></ul>"));
    assert_eq!(out, "- ```\n  a\n  b | c\n  ```\n");
    let out = md(&format!(
        "<table><tbody><tr><th>h</th></tr><tr><td>{code}</td></tr></tbody></table>"
    ));
    assert!(out.contains("| `a b \\| c` |"), "{out}");
    let out = md(&format!("<blockquote>{code}</blockquote>"));
    assert_eq!(out, "> ```\n> a\n> b | c\n> ```\n");
    Ok(())
}

#[test]
fn u23_lookalikes_escaped() -> TestResult {
    assert_eq!(
        md("<p>[macro: toc {}] x</p>"),
        "\\[macro: toc {}\\] x\n",
        "htmd escaped the bracket; nothing is added"
    );
    assert_eq!(md("<p>a @user:abc b</p>"), "a \\@user:abc b\n");
    assert_eq!(md("<p>me@user:x.y</p>"), "me\\@user:x.y\n");
    assert_eq!(md("<p>@user: alone</p>"), "@user: alone\n");
    assert_eq!(
        md("<p><a href=\"confluence:DOC/x\">t</a></p>"),
        "\\[t](confluence:DOC/x)\n"
    );
    assert_eq!(
        md("<p><a href=\"https://x.example/\">confluence:DOC/x</a></p>"),
        "[confluence:DOC/x](https://x.example/)\n"
    );
    // A literal backslash before the look-alike stays a literal backslash.
    assert_eq!(md("<p>\\@user:abc</p>"), "\\\\\\@user:abc\n");
    assert_eq!(md("<p>\\[macro: toc {}]</p>"), "\\\\\\[macro: toc {}\\]\n");
    Ok(())
}

#[test]
fn lookalikes_in_code_are_verbatim() -> TestResult {
    assert_eq!(
        md("<p><code>[macro: toc {}] @user:abc</code></p>"),
        "`[macro: toc {}] @user:abc`\n"
    );
    let out = md("<ac:structured-macro ac:name=\"code\"><ac:plain-text-body>\
                  <![CDATA[[macro: toc {}] @user:abc]]></ac:plain-text-body>\
                  </ac:structured-macro>");
    assert_eq!(out, "```\n[macro: toc {}] @user:abc\n```\n");
    let out = md("<pre>[macro: toc {}] @user:abc [x](confluence:y)</pre>");
    assert_eq!(
        out,
        "```\n[macro: toc {}] @user:abc [x](confluence:y)\n```\n"
    );
    Ok(())
}

#[test]
fn username_from_map_is_escaped() -> TestResult {
    let names = ["a@user:b", "x](y)", "[macro: t {}]", "*bold*", "user:abc"];
    for name in names {
        let users = UserResolutions::from([("k1".to_owned(), Some(name.to_owned()))]);
        let (out, r, _) = storage_to_markdown("<p><ri:user ri:userkey=\"k1\"/> x</p>", &users);
        assert_eq!(r.unresolved_users, 0, "{name}");
        assert!(out.starts_with('@'), "{out}");
        assert!(unescaped(&out, "@user:").is_empty(), "{name}: {out}");
        assert!(unescaped(&out, "[macro:").is_empty(), "{name}: {out}");
        assert!(unescaped(&out, "](").is_empty(), "{name}: {out}");
        for special in ['*', '[', ']', '(', ')', ':'] {
            if name.contains(special) {
                assert!(
                    unescaped(&out, &special.to_string()).is_empty(),
                    "{name}: {special} in {out}"
                );
            }
        }
    }
    let long = "n".repeat(256);
    let ok = "n".repeat(255);
    for (name, expected) in [
        (long.as_str(), "@user:k1 x\n".to_owned()),
        ("bad\u{7}name", "@user:k1 x\n".to_owned()),
        ("", "@user:k1 x\n".to_owned()),
        (ok.as_str(), format!("@{ok} x\n")),
    ] {
        let users = UserResolutions::from([("k1".to_owned(), Some(name.to_owned()))]);
        let (out, r, _) = storage_to_markdown("<p><ri:user ri:userkey=\"k1\"/> x</p>", &users);
        assert_eq!(out, expected);
        assert_eq!(
            r.unresolved_users,
            u64::from(expected.starts_with("@user:"))
        );
    }
    Ok(())
}

#[test]
fn unresolved_key_is_percent_encoded() -> TestResult {
    let (out, _, _) = storage_to_markdown(
        "<p><ri:user ri:userkey=\"a b%c_d.e-f\"/></p>",
        &UserResolutions::new(),
    );
    assert_eq!(out, "@user:a%20b%25c%5Fd.e-f\n");
    Ok(())
}

#[test]
fn macro_params_escaped_and_on_one_line() -> TestResult {
    let out = md(
        "<p><ac:structured-macro ac:name=\"m\"><ac:parameter ac:name=\"b\">x*y_z`w\
                  </ac:parameter><ac:parameter ac:name=\"a\">1\n2, {3}] \\ &amp; &lt;t&gt; ~|!\
                  </ac:parameter></ac:structured-macro></p>",
    );
    assert_eq!(
        out,
        "[macro: m {a=1 2\\, {3\\}\\] \\\\ \\& \\<t> \\~\\|\\!, b=x\\*y\\_z\\`w}]\n"
    );
    // A name outside the placeholder grammar is made to fit it.
    let out = md("<ac:structured-macro ac:name=\"my macro/ü\"/>");
    assert_eq!(out, "[macro: my-macro-- {}]\n");
    let long = "m".repeat(70);
    let out = md(&format!("<ac:structured-macro ac:name=\"{long}\"/>"));
    assert_eq!(out, format!("[macro: {} {{}}]\n", "m".repeat(64)));
    let r = report(&format!("<ac:structured-macro ac:name=\"{long}\"/>"));
    assert_eq!(r.unknown_macros, vec![long]);
    Ok(())
}

#[test]
fn placeholder_adjacency_cannot_form_links_or_images() -> TestResult {
    let toc = "<ac:structured-macro ac:name=\"toc\"/>";
    assert_eq!(
        md(&format!("<p>{toc}(see)</p>")),
        "[macro: toc {}]\\(see)\n"
    );
    assert_eq!(
        md(&format!("<p>{toc}: https://x.example/</p>")),
        "[macro: toc {}]\\: https://x.example/\n"
    );
    let link = "<ac:link><ri:page ri:space-key=\"D\" ri:content-title=\"T\"/></ac:link>";
    assert_eq!(
        md(&format!("<p>Look!{link}</p>")),
        "Look\\![T](confluence:D/T)\n"
    );
    Ok(())
}

#[test]
fn generic_ac_elements_keep_their_content() -> TestResult {
    // An inline-comment marker is written as its text alone but counted as lost: a round
    // trip drops it and detaches the comment (Task 2 review ruling).
    let out = md(
        "<p>Some <ac:inline-comment-marker ac:ref=\"abc\">marked text</ac:inline-comment-marker> \
                  here.</p>",
    );
    assert_eq!(out, "Some marked text here.\n");
    let r = report("<p><ac:inline-comment-marker ac:ref=\"abc\">t</ac:inline-comment-marker></p>");
    assert!(r.lossy);
    assert_eq!(r.lost.macros, 1);
    assert!(r.unknown_macros.is_empty(), "{r:?}");
    // Any other unmapped `ac:` element is a placeholder followed by its content.
    let out = md("<p>Fill <ac:placeholder>your name</ac:placeholder> in.</p>");
    assert_eq!(out, "Fill [macro: placeholder {}]your name in.\n");
    let r = report("<p><ac:placeholder>x</ac:placeholder></p>");
    assert_eq!(r.lost.macros, 1);
    assert!(
        r.unknown_macros.is_empty(),
        "no unknown-macros Info (Q11): {r:?}"
    );
    // A foreign-namespace element is markup: a placeholder, never its content.
    let out = md(
        "<p>a <zz:structured-macro xmlns:zz=\"http://atlassian.com/content\" \
                  zz:name=\"include\">hidden</zz:structured-macro> b</p>",
    );
    assert_eq!(out, "a [macro: structured-macro {}] b\n");
    let r = report("<zz:x xmlns:zz=\"urn:x\"/>");
    assert_eq!(r.unknown_macros, vec!["zz:x".to_owned()]);
    assert_eq!(r.lost.macros, 1);
    Ok(())
}

#[test]
fn html_fallback_on_xml_failure() -> TestResult {
    let storage = "<p>Broken <b>tag</p><ac:structured-macro ac:name=\"code\"><ac:plain-text-body>\
                   <![CDATA[if a < b {\n  x();\n}]]></ac:plain-text-body></ac:structured-macro>";
    let (out, r, users) = storage_to_markdown(storage, &UserResolutions::new());
    assert!(r.fallback);
    assert!(r.lossy);
    assert!(users.is_empty());
    assert!(out.contains("```\nif a < b {\n  x();\n}\n```"), "{out}");
    assert!(out.contains("Broken"), "{out}");
    // A CDATA that never ends runs to the end of the input.
    let (out, r, _) =
        storage_to_markdown("<p>x<![CDATA[code [macro: a {}]", &UserResolutions::new());
    assert!(r.fallback);
    assert!(out.ends_with("```\ncode [macro: a {}]\n```\n"), "{out}");
    Ok(())
}

#[test]
fn fallback_never_recurses_without_bound() -> TestResult {
    // Malformed (so the fallback runs) and nested far deeper than the parser's bound.
    let deep = format!(
        "{}x{}<p>",
        "<div>".repeat(100_000),
        "</div>".repeat(100_000)
    );
    let (out, r, _) = storage_to_markdown(&deep, &UserResolutions::new());
    assert!(r.fallback);
    assert_eq!(out, "x\n");
    let formatting = format!("{}x<p>y", "<b><i><u><span>".repeat(5_000));
    let (out, r, _) = storage_to_markdown(&formatting, &UserResolutions::new());
    assert!(r.fallback);
    assert!(out.contains('x') && out.contains('y'), "{out}");
    // Nesting within the bound still converts through the tree.
    let ok = format!(
        "{}<p>deep</p>{}",
        "<blockquote>".repeat(60),
        "</blockquote>".repeat(60)
    );
    let (out, r, _) = storage_to_markdown(&ok, &UserResolutions::new());
    assert!(!r.fallback);
    assert!(out.trim_end().ends_with("deep"), "{out}");
    Ok(())
}

/// Found by the fix round's property test (T3 review m-8 leaves): `htmd` leaves a `~~~` after
/// a text's leading whitespace unescaped, and the tilde fence would hide the placeholder after
/// it in a code block. Every tilde fence is escaped (the converter writes backtick fences only).
#[test]
fn prose_tilde_fences_cannot_hide_placeholders() -> TestResult {
    let toc = "<ac:structured-macro ac:name=\"toc\"/>";
    let out = md(&format!(
        "<blockquote><ac:structured-macro ac:name=\"info\"><ac:rich-text-body><p> ~~~{toc}</p>\
         </ac:rich-text-body></ac:structured-macro></blockquote>"
    ));
    assert_eq!(out, "> [macro: info {}]\n> \n> \\~~~[macro: toc {}]\n");
    assert_eq!(oracle(&out).macros, 2, "{out}");
    // A tilde block holding further tilde lines: none of them opens a fence afterwards.
    let out = md(&format!(
        "<p> ~~~~</p><p> ~~~</p><p>{toc}</p><p> ~~~</p><p>{toc}</p>"
    ));
    assert_eq!(oracle(&out).macros, 2, "{out}");
    assert!(!out.lines().any(|l| l.starts_with("~~~")), "{out}");
    // A code macro's fence is the converter's own and stays.
    let code = md(
        "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body><![CDATA[~~~\nx]]>\
                   </ac:plain-text-body></ac:structured-macro>",
    );
    assert_eq!(code, "```\n~~~\nx\n```\n");
    Ok(())
}

/// Found by the fix round's property test (20 000 cases): `htmd` can leave a hard break's `\`
/// without its newline right before a construct, where it would escape the placeholder.
#[test]
fn dangling_hard_break_backslash_cannot_hide_placeholders() -> TestResult {
    let storage = "<ac:link-body><ac:link-body><br/></ac:link-body><a name=\"anchor\">\
                   <ri:user ri:userkey=\"8a7f\"/></a></ac:link-body>";
    let (out, r, _) = storage_to_markdown(storage, &UserResolutions::new());
    assert_eq!(out, "\\\\@user:8a7f\n");
    assert_eq!(oracle(&out).users, 1, "{out}");
    assert_eq!(r.unresolved_users, 1);
    let out = md("<p><span><br/></span><ac:structured-macro ac:name=\"toc\"/></p>");
    assert_eq!(oracle(&out).macros, 1, "{out}");
    Ok(())
}

/// T3 review B-1: misnested markup that `html5ever` would rebuild into a tree as deep (the
/// adoption agency) or as large (formatting reconstruction with distinct attributes) as the
/// input chooses never reaches an HTML parser: the fallback strips every tag.
#[test]
fn fallback_strips_misnested_markup() -> TestResult {
    let started = Instant::now();
    let adoption = "<b><div></b>".repeat(20_000);
    let (out, r, users) = storage_to_markdown(&adoption, &UserResolutions::new());
    assert!(r.fallback && r.lossy, "{r:?}");
    assert!(users.is_empty());
    assert_eq!(out, "");
    let with_text = "<b><div>x</b>".repeat(20_000);
    let (out, r, _) = storage_to_markdown(&with_text, &UserResolutions::new());
    assert!(r.fallback);
    assert_eq!(out.matches('x').count(), 20_000);
    let classes: String = (0..3000)
        .map(|k| format!("<p><b class=\"c{k}\">x</p>"))
        .collect();
    let a = storage_to_markdown(&classes, &UserResolutions::new());
    assert!(a.1.fallback && a.1.lossy, "{:?}", a.1);
    assert_eq!(a.0.matches('x').count(), 3000);
    assert_eq!(a, storage_to_markdown(&classes, &UserResolutions::new()));
    // The well-formed `<b><div/></b>`, forced into the fallback by a malformation at the end.
    let self_closed = format!("{}<p>", "<b><div/>x</b>".repeat(20_000));
    let (out, r, _) = storage_to_markdown(&self_closed, &UserResolutions::new());
    assert!(r.fallback);
    assert_eq!(out.matches('x').count(), 20_000);
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "{:?}",
        started.elapsed()
    );
    Ok(())
}

#[test]
fn fallback_text_is_escaped_prose() -> TestResult {
    let storage = "<p>a &amp; b &lt;c&gt; &uuml; &bogus; &#0; x<y 1 < 2</p>\
                   <!-- <p>hidden</p> --><p># not a heading</p><p>1. not a list</p>\
                   <p>- not an item</p><p>*not em* [macro: t {}] @user:q</p>\
                   <p>Due <time datetime=\"2026-10-20\"/>.</p><p title=\"a>b\">attr</p>\
                   <b>unclosed";
    let (out, r, _) = storage_to_markdown(storage, &UserResolutions::new());
    assert!(r.fallback);
    let expected = r"a \& b \<c> ü \&bogus; \&#0; x\<y 1 \< 2

\# not a heading

1\. not a list

\- not an item

\*not em\* \[macro: t {}\] \@user:q

Due 2026-10-20.

attr

unclosed
";
    assert_eq!(out, expected);
    Ok(())
}

/// Lead ruling Q11: the known-macro list, and `ac:` elements that never raise the Info.
#[test]
fn known_macros_and_quiet_elements() -> TestResult {
    let known = [
        "code", "noformat", "info", "note", "tip", "warning", "panel", "expand", "excerpt", "toc",
        "anchor", "status", "details", "section", "column", "toc-zone",
    ];
    assert_eq!(KNOWN_MACROS.len(), known.len());
    for name in known {
        let r = report(&format!("<ac:structured-macro ac:name=\"{name}\"/>"));
        assert!(r.unknown_macros.is_empty(), "{name}: {r:?}");
    }
    for name in [
        "children",
        "jira",
        "include",
        "excerpt-include",
        "pagetree",
        "contentbylabel",
        "jiraissues",
        "html",
        "recently-updated",
    ] {
        let r = report(&format!("<ac:structured-macro ac:name=\"{name}\"/>"));
        assert_eq!(r.unknown_macros, vec![name.to_owned()]);
        assert_eq!(r.lost.macros, 1);
    }
    // Emoticons and instructional placeholders stay placeholders and count, without the Info.
    let storage = "<p><ac:emoticon ac:name=\"tick\"/> <ac:placeholder>x</ac:placeholder></p>";
    assert_eq!(
        md(storage),
        "[macro: emoticon {}] [macro: placeholder {}]x\n"
    );
    let r = report(storage);
    assert_eq!(r.lost.macros, 2);
    assert!(r.lossy);
    assert!(r.unknown_macros.is_empty(), "{r:?}");
    // A nameless macro is listed by the name its placeholder shows (T3 review m-3).
    let (out, r, _) = storage_to_markdown("<ac:structured-macro/>", &UserResolutions::new());
    assert_eq!(out, "[macro: - {}]\n");
    assert_eq!(r.unknown_macros, vec!["-".to_owned()]);
    Ok(())
}

/// T3 review I-3: a Markdown round trip turns tasks into plain list items, so each outermost
/// task list is one lost macro (a nested one is not counted again; a task's content is).
#[test]
fn task_lists_count_as_lost_macros() -> TestResult {
    let task = |body: &str| {
        format!(
            "<ac:task><ac:task-status>incomplete</ac:task-status><ac:task-body>{body}\
             </ac:task-body></ac:task>"
        )
    };
    let list = |tasks: String| format!("<ac:task-list>{tasks}</ac:task-list>");
    let storage = format!(
        "{}{}",
        list(task("a") + &task(&list(task("b")))),
        list(task("<ac:link><ri:user ri:userkey=\"k\"/></ac:link>"))
    );
    let r = report(&storage);
    assert_eq!(
        r.lost,
        LostCounts {
            macros: 2,
            images: 0,
            links: 1,
            layouts: 0
        }
    );
    assert!(r.lossy);
    assert!(r.unknown_macros.is_empty(), "{r:?}");
    Ok(())
}

/// T3 review I-2: a date lozenge keeps its date, as text, and is not counted lost.
#[test]
fn time_lozenges_keep_their_date() -> TestResult {
    assert_eq!(
        md("<p>Due: <time datetime=\"2026-10-20\" /></p>"),
        "Due: 2026-10-20\n"
    );
    assert_eq!(
        md("<p><time datetime=\"2026-10-20\">20 Oct</time></p>"),
        "20 Oct\n"
    );
    assert_eq!(
        md(
            "<table><tbody><tr><th>Due</th></tr><tr><td><time datetime=\"2026-10-20\"/></td>\
            </tr></tbody></table>"
        ),
        "| Due        |\n| ---------- |\n| 2026-10-20 |\n"
    );
    assert_eq!(
        report("<p><time datetime=\"2026-10-20\"/></p>"),
        ConversionReport::default()
    );
    Ok(())
}

#[test]
fn sentinel_like_characters_in_the_fallback_input() -> TestResult {
    let (out, r, _) = storage_to_markdown(
        "<p>a\u{FFFF}0\u{FFFE}b<![CDATA[c]]>",
        &UserResolutions::new(),
    );
    assert!(r.fallback);
    assert!(!out.contains(['\u{FFFF}', '\u{FFFE}']), "{out:?}");
    assert!(out.contains("a\u{FFFD}0\u{FFFD}b"), "{out:?}");
    Ok(())
}

#[test]
fn ordered_list_start_is_not_passed_to_htmd() -> TestResult {
    let out = md("<ol start=\"100000000\"><li>a</li><li>b</li></ol>");
    assert_eq!(out, "1. a\n2. b\n");
    Ok(())
}

#[test]
fn empty_and_whitespace_bodies() -> TestResult {
    assert_eq!(md(""), "");
    assert_eq!(md("  \n "), "");
    assert_eq!(report(""), ConversionReport::default());
    Ok(())
}

/// Placeholders by kind, as the PD-98 grammar counts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Counts {
    links: u64,
    images: u64,
    macros: u64,
    users: u64,
}

impl std::ops::Add for Counts {
    type Output = Counts;
    fn add(self, o: Counts) -> Counts {
        Counts {
            links: self.links + o.links,
            images: self.images + o.images,
            macros: self.macros + o.macros,
            users: self.users + o.users,
        }
    }
}

/// An independent oracle for the PD-98 grammar (Task 4 owns the real check): link and image
/// destinations with the `confluence:` scheme; on runs of `Text` events outside code (joined
/// across the one-byte gap of a backslash escape), `[macro: <name> {…}]` and `@user:<key>`
/// whose first character is not backslash-escaped.
fn oracle(md: &str) -> Counts {
    use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
    fn escaped(md: &str, at: usize) -> bool {
        md.as_bytes()[..at]
            .iter()
            .rev()
            .take_while(|&&b| b == b'\\')
            .count()
            % 2
            == 1
    }
    fn run(md: &str, r: std::ops::Range<usize>, c: &mut Counts) {
        let s = &md[r.clone()];
        for (i, _) in s.match_indices("[macro: ") {
            let rest = &s[i + 8..];
            let name = rest
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || b"_.-".contains(b))
                .count();
            let ok = (1..=64).contains(&name)
                && rest[name..]
                    .strip_prefix(" {")
                    .is_some_and(|p| p.lines().next().unwrap_or("").contains("}]"));
            if ok && !escaped(md, r.start + i) {
                c.macros += 1;
            }
        }
        for (i, _) in s.match_indices("@user:") {
            let key = s[i + 6..]
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b"._%-".contains(&b));
            if key && !escaped(md, r.start + i) {
                c.users += 1;
            }
        }
    }
    let confluence = |d: &str| d.len() >= 11 && d[..11].eq_ignore_ascii_case("confluence:");
    let mut c = Counts::default();
    let mut cur: Option<std::ops::Range<usize>> = None;
    let mut code = false;
    let opts = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
    for (e, r) in Parser::new_ext(md, opts).into_offset_iter() {
        if let Event::Text(_) = e
            && !code
        {
            cur = Some(match cur.take() {
                Some(p)
                    if r.start == p.end
                        || (r.start == p.end + 1 && &md[p.end..r.start] == "\\") =>
                {
                    p.start..r.end
                }
                Some(p) => {
                    run(md, p, &mut c);
                    r
                }
                None => r,
            });
            continue;
        }
        if let Some(p) = cur.take() {
            run(md, p, &mut c);
        }
        match e {
            Event::Start(Tag::CodeBlock(_)) => code = true,
            Event::End(TagEnd::CodeBlock) => code = false,
            Event::Start(Tag::Link { dest_url, .. }) if confluence(&dest_url) => c.links += 1,
            Event::Start(Tag::Image { dest_url, .. }) if confluence(&dest_url) => c.images += 1,
            _ => {}
        }
    }
    if let Some(p) = cur {
        run(md, p, &mut c);
    }
    c
}

/// The map the generated storage is converted with.
fn property_users() -> UserResolutions {
    UserResolutions::from([
        ("u1".to_owned(), None),
        ("u2".to_owned(), Some("jdoe".to_owned())),
        ("u3".to_owned(), Some("user:x](y) [macro: t {}]".to_owned())),
    ])
}

const NONE: Counts = Counts {
    links: 0,
    images: 0,
    macros: 0,
    users: 0,
};

/// Inline storage with the placeholders the converter must emit for it.
fn inline_leaf() -> impl Strategy<Value = (String, Counts)> {
    let user = Counts { users: 1, ..NONE };
    let mac = Counts { macros: 1, ..NONE };
    let link = Counts { links: 1, ..NONE };
    let image = Counts { images: 1, ..NONE };
    prop::sample::select(vec![
        ("a", NONE),
        ("b c", NONE),
        (" ", NONE),
        ("[macro: toc {}]", NONE),
        ("@user:abc", NONE),
        ("@user:", NONE),
        ("user:", NONE),
        ("@", NONE),
        ("\\", NONE),
        ("`", NONE),
        ("*", NONE),
        ("_", NONE),
        ("!", NONE),
        ("(", NONE),
        (")", NONE),
        (":", NONE),
        ("[", NONE),
        ("]", NONE),
        ("](", NONE),
        ("{}", NONE),
        ("|", NONE),
        ("#", NONE),
        ("1.", NONE),
        ("- ", NONE),
        ("&amp;", NONE),
        ("&lt;", NONE),
        ("&amp;lt;", NONE),
        ("&nbsp;", NONE),
        ("confluence:x", NONE),
        ("<br/>", NONE),
        ("<code>[macro: toc {}] @user:a ` x</code>", NONE),
        ("<a href=\"confluence:X/y\">t</a>", NONE),
        ("<a href=\"https://x.example/\">t @user:q</a>", NONE),
        ("<ac:link><ri:user ri:userkey=\"u1\"/></ac:link>", user),
        ("<ac:link><ri:user ri:userkey=\"u2\"/></ac:link>", NONE),
        ("<ac:link><ri:user ri:userkey=\"u3\"/></ac:link>", NONE),
        ("<ac:link><ri:user ri:userkey=\"u4 x\"/></ac:link>", user),
        ("<ri:user ri:username=\"jdoe\"/>", NONE),
        ("<ac:structured-macro ac:name=\"toc\"/>", mac),
        (
            "<ac:structured-macro ac:name=\"status\"><ac:parameter ac:name=\"title\">a*b](c)@user:x \
             [macro: y {}] |</ac:parameter></ac:structured-macro>",
            mac,
        ),
        ("<ac:emoticon ac:name=\"smile\"/>", mac),
        ("<ac:inline-comment-marker ac:ref=\"r\">marked</ac:inline-comment-marker>", NONE),
        ("<ac:placeholder>fill in</ac:placeholder>", mac),
        ("<ac:link><ri:page ri:space-key=\"D\" ri:content-title=\"T x\"/></ac:link>", link),
        (
            "<ac:link><ri:page ri:content-title=\"@user:z [macro: q {}]\"/></ac:link>",
            link,
        ),
        ("<ac:link><ri:attachment ri:filename=\"f (1).png\"/></ac:link>", link),
        ("<ac:link ac:anchor=\"top\"/>", NONE),
        ("<ac:image><ri:attachment ri:filename=\"a].png\"/></ac:image>", image),
        ("<ac:image><ri:url ri:value=\"https://x/(a)\"/></ac:image>", image),
        // T3 review I-1 and m-8: names and keys with `_`, block openers after a hard break.
        ("<ac:structured-macro ac:name=\"_x_\"/>", mac),
        ("<ac:structured-macro ac:name=\"a._b_\"/>", mac),
        ("<ac:emoticon ac:name=\"__a__\"/>", mac),
        ("<ac:_y_/>", mac),
        ("<ri:user ri:userkey=\"_u_\"/>", user),
        ("_x", NONE),
        ("x_", NONE),
        ("~~~", NONE),
        ("<br/>~~~", NONE),
        ("<br/>```", NONE),
        ("<br/>---", NONE),
        ("<br/>===", NONE),
        ("<br/>    x", NONE),
        ("<br/># x", NONE),
        ("<time datetime=\"2026-10-20\"/>", NONE),
    ])
    .prop_map(|(s, c)| (s.to_owned(), c))
}

fn concat(v: Vec<(String, Counts)>) -> (String, Counts) {
    v.into_iter()
        .fold((String::new(), NONE), |(s, c), (s2, c2)| (s + &s2, c + c2))
}

fn wrap(tag: &str, (s, c): (String, Counts)) -> (String, Counts) {
    (format!("<{tag}>{s}</{tag}>"), c)
}

fn inline() -> impl Strategy<Value = (String, Counts)> {
    inline_leaf().prop_recursive(3, 24, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 1..6).prop_map(concat),
            prop::collection::vec(inner.clone(), 1..4).prop_map(|v| wrap("strong", concat(v))),
            prop::collection::vec(inner, 1..4).prop_map(|v| wrap("em", concat(v))),
        ]
    })
}

fn code_macro() -> impl Strategy<Value = (String, Counts)> {
    prop::sample::select(vec![
        "x",
        "[macro: x {}]\n@user:a\n[l](confluence:y)",
        "```\n~~~",
        "",
        "a]]]]><![CDATA[>b",
    ])
    .prop_map(|body| {
        (
            format!(
                "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body><![CDATA[{body}]]>\
                 </ac:plain-text-body></ac:structured-macro>"
            ),
            NONE,
        )
    })
}

fn blocks() -> impl Strategy<Value = (String, Counts)> {
    let leaf = prop_oneof![
        4 => inline().prop_map(|i| wrap("p", i)),
        1 => code_macro(),
        1 => inline_leaf(),
    ];
    leaf.prop_recursive(3, 32, 4, |inner| {
        let items = || prop::collection::vec(inner.clone(), 1..4).prop_map(concat);
        prop_oneof![
            items(),
            items().prop_map(|b| wrap("blockquote", b)),
            prop::collection::vec(items().prop_map(|b| wrap("li", b)), 1..3)
                .prop_map(|v| wrap("ul", concat(v))),
            items().prop_map(|(s, c)| (
                format!("<table><tbody><tr><th>h</th></tr><tr><td>{s}</td></tr></tbody></table>"),
                c
            )),
            items().prop_map(|(s, c)| (
                format!(
                    "<ac:structured-macro ac:name=\"info\"><ac:rich-text-body>{s}\
                     </ac:rich-text-body></ac:structured-macro>"
                ),
                c + Counts { macros: 1, ..NONE }
            )),
            inline().prop_map(|(s, c)| (
                format!(
                    "<ac:task-list><ac:task><ac:task-status>complete</ac:task-status>\
                     <ac:task-body>{s}</ac:task-body></ac:task></ac:task-list>"
                ),
                c
            )),
            items().prop_map(|(s, c)| (
                format!(
                    "<ac:layout><ac:layout-section><ac:layout-cell>{s}</ac:layout-cell>\
                     </ac:layout-section></ac:layout>"
                ),
                c
            )),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, ..ProptestConfig::default() })]

    #[test]
    fn deterministic_and_never_panics(input in common::storage_input()) {
        let users = UserResolutions::from([("x".to_owned(), Some("n".to_owned()))]);
        let a = storage_to_markdown(&input, &users);
        let b = storage_to_markdown(&input, &users);
        prop_assert_eq!(&a, &b);
        prop_assert!(!a.0.contains(['\u{FFFF}', '\u{FFFE}']), "sentinel left in {:?}", a.0);
        prop_assert!(a.0.is_empty() || (a.0.ends_with('\n') && !a.0.ends_with("\n\n")));
        prop_assert_eq!(a.1.lossy, a.1.fallback || a.1.lost != LostCounts::default());
        // Whatever the input, the output holds no placeholder the converter did not write.
        let found = oracle(&a.0);
        prop_assert_eq!(found.users, a.1.unresolved_users, "{:?}", a.0);
        if a.1.fallback {
            prop_assert_eq!(found, Counts::default(), "{:?}", a.0);
        }
    }

    /// Well-formed storage: the placeholder grammar finds exactly the placeholders the
    /// converter wrote, so a resubmitted body is caught (U-25) and prose never is.
    #[test]
    fn placeholders_are_exactly_the_converters((storage, expected) in blocks()) {
        let (out, report, _) = storage_to_markdown(&storage, &property_users());
        prop_assert!(!report.fallback, "{}", storage);
        prop_assert_eq!(oracle(&out), expected, "storage {}\nmarkdown {}", storage, out);
        prop_assert_eq!(report.unresolved_users, expected.users);
    }

    /// T3 review I-1: whatever the macro names and the prose around them, each placeholder is
    /// exactly one hit (the character class keeps the storage well-formed).
    #[test]
    fn any_macro_name_is_one_placeholder(
        a in "[a-z0-9_*.üß -]{0,70}",
        b in "[a-z_*ü]{0,8}",
        prose in "[a-z_* ]{0,6}",
    ) {
        let storage = format!(
            "<p>{prose}<ac:structured-macro ac:name=\"{a}\"/>{prose}\
             <ac:structured-macro ac:name=\"{b}\"/>{prose}</p>"
        );
        let (out, report, _) = storage_to_markdown(&storage, &UserResolutions::new());
        prop_assert!(!report.fallback, "{}", storage);
        prop_assert_eq!(oracle(&out).macros, 2, "storage {}\nmarkdown {}", storage, out);
    }
}
