//! `markdown_to_wiki`: Markdown → Jira wiki markup with full escaping and the code-body rule
//! (spec §7.6, plan Task 3, PD-43, PD-44).
//!
//! Every output is checked against the parser the hard check uses (`convert::wiki`): its
//! construct spans must be exactly the containers the converter recorded, nothing else.

mod common;

use std::path::{Path, PathBuf};

use atlas_duck_convert::escape;
use atlas_duck_convert::wiki::{self, Block, Inline, construct_spans};
use atlas_duck_convert::{ContainerKind, EmittedConstructs, markdown_to_wiki, wiki_constructs};
use common::{markdown, spans_match_record};
use proptest::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GOLDEN: [&str; 8] = [
    "basics", "lists", "tables", "code", "links", "html", "specials", "nested",
];

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/md_to_wiki")
}

/// Text of a document made of paragraphs only: `Text`, `LineBreak` (`\n`) and bare-URL links
/// (their target); paragraphs joined by a blank line. Anything else is an error.
fn project(blocks: &[Block]) -> Result<String, String> {
    let mut paras = Vec::new();
    for b in blocks {
        let Block::Paragraph(inlines) = b else {
            return Err(format!("non-paragraph block {b:?}"));
        };
        let mut s = String::new();
        for i in inlines {
            match i {
                Inline::Text(t) => s.push_str(t),
                Inline::LineBreak => s.push('\n'),
                Inline::Link { text: None, target } => s.push_str(target),
                // A bare URL rewritten as `[url|url]`: both parts are the URL.
                Inline::Link {
                    text: Some(text),
                    target,
                } if text == target => s.push_str(target),
                other => return Err(format!("unexpected inline {other:?}")),
            }
        }
        paras.push(s);
    }
    Ok(paras.join("\n\n"))
}

/// Decodes the decimal character references the escaper writes (`&#92;` → `\`).
fn decode(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(pos) = rest.find("&#") {
        let (head, tail) = rest.split_at(pos);
        out.push_str(head);
        let digits: String = tail[2..].chars().take_while(char::is_ascii_digit).collect();
        let after = 2 + digits.len();
        let ch = digits.parse::<u32>().ok().and_then(char::from_u32);
        match ch {
            Some(c) if !digits.is_empty() && tail[after..].starts_with(';') => {
                out.push(c);
                rest = &tail[after + 1..];
            }
            _ => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
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
    let (out, e) = markdown_to_wiki(md);
    spans_match_record(&out, &e)?;
    if !out.ends_with('\n') || out.ends_with("\n\n") {
        return Err(format!("output must end with exactly one newline: {out:?}"));
    }
    Ok((out, e))
}

fn kinds(e: &EmittedConstructs) -> Vec<ContainerKind> {
    e.code_blocks.iter().map(|c| c.kind).collect()
}

#[test]
fn u23_md_to_wiki_golden() -> TestResult {
    let mut failures = Vec::new();
    for name in GOLDEN {
        let md = std::fs::read_to_string(golden_dir().join(format!("{name}.md")))?;
        let expected = std::fs::read_to_string(golden_dir().join(format!("{name}.wiki")))?;
        let (out, e) = markdown_to_wiki(&md);
        if out != expected {
            failures.push(format!("{name}:\n{}", diff(&expected, &out)));
        }
        if let Err(m) = spans_match_record(&out, &e) {
            failures.push(format!("{name}: {m}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

#[test]
fn u23_escapes_raw_html_and_wiki_specials() -> TestResult {
    let md = "Text <script>x</script> {toc} \\[~jdoe\\] !img.png! {include:A} \\| a\\b \\\\\n";
    let (out, e) = convert_checked(md)?;
    assert_eq!(
        out,
        "Text <script>x</script> \\{toc\\} \\[\\~jdoe\\] \\!img.png\\! \\{include:A\\} \\| \
         a&#92;b &#92;\n"
    );
    assert!(e.code_blocks.is_empty());
    let doc = wiki::parse(&out);
    assert!(construct_spans(&doc).is_empty());
    assert_eq!(
        decode(&project(&doc.blocks)?),
        "Text <script>x</script> {toc} [~jdoe] !img.png! {include:A} | a\\b \\"
    );
    // HTML blocks are text as well, line by line.
    let (out, _) = convert_checked("<div>\n{toc} [~a] !b!\n</div>\n")?;
    assert_eq!(out, "<div>\n\\{toc\\} \\[\\~a\\] \\!b\\!\n</div>\n");
    Ok(())
}

#[test]
fn images_become_links() -> TestResult {
    let (out, _) =
        convert_checked("![alt text](https://x.example/a.png) ![](https://x.example/b.png)")?;
    assert_eq!(
        out,
        "[alt text|https://x.example/a.png] [https://x.example/b.png]\n"
    );
    let inv = wiki_constructs(&out);
    assert!(inv.images.is_empty());
    assert_eq!(
        inv.links,
        ["https://x.example/a.png", "https://x.example/b.png"]
    );
    // An image inside link text is its alt text; one without a target is plain text.
    let (out, _) = convert_checked("[![i](https://x.example/i.png) go](https://x.example) ![x]()")?;
    assert_eq!(out, "[i go|https://x.example] x\n");
    Ok(())
}

#[test]
fn at_mention_stays_text() -> TestResult {
    let (out, _) = convert_checked("ping @jdoe and @j.doe")?;
    assert_eq!(out, "ping @jdoe and @j.doe\n");
    assert!(wiki_constructs(&out).mentions.is_empty());
    Ok(())
}

#[test]
fn code_container_by_content() -> TestResult {
    let md = "```\nlet a = 1;\n```\n\n\
              ```\nx {code} y\n```\n\n\
              ```\n{code} and {noformat}\n\nlast\n```\n\n\
              inline `{noformat}` span\n";
    let (out, e) = convert_checked(md)?;
    assert_eq!(
        out,
        "{code}\nlet a = 1;\n{code}\n\n\
         {noformat}\nx {code} y\n{noformat}\n\n\
         {{\\{code\\} and \\{noformat\\}}}\n{{&#160;}}\n{{last}}\n\n\
         inline {{\\{noformat\\}}} span\n"
    );
    assert_eq!(kinds(&e), [ContainerKind::Code, ContainerKind::Noformat]);
    // The escaped lines are monospace, one per code line.
    let doc = wiki::parse(&out);
    let Some(Block::Paragraph(lines)) = doc.blocks.get(2) else {
        return Err(format!("third block is not a paragraph: {:?}", doc.blocks).into());
    };
    assert_eq!(
        lines,
        &[
            Inline::Monospace("{code} and {noformat}".into()),
            Inline::LineBreak,
            Inline::Monospace("&#160;".into()),
            Inline::LineBreak,
            Inline::Monospace("last".into()),
        ]
    );
    Ok(())
}

#[test]
fn code_container_detection_is_case_insensitive() -> TestResult {
    let (out, e) = convert_checked("```\n{CODE}\n```\n\n```\n{Code} {NoFormat:x}\n```\n")?;
    assert_eq!(
        out,
        "{noformat}\n{CODE}\n{noformat}\n\n{{\\{Code\\} \\{NoFormat:x\\}}}\n"
    );
    assert_eq!(kinds(&e), [ContainerKind::Noformat]);
    Ok(())
}

#[test]
fn code_lang_is_sanitized() -> TestResult {
    let (out, _) = convert_checked(
        "```c++ extra\na\n```\n\n```bad}lang\nb\n```\n\n```java,ignore\nc\n```\n\n    d\n",
    )?;
    assert_eq!(
        out,
        "{code:c++}\na\n{code}\n\n{code}\nb\n{code}\n\n{code:java}\nc\n{code}\n\n{code}\nd\n{code}\n"
    );
    Ok(())
}

#[test]
fn emitted_constructs_ranges_point_at_containers() -> TestResult {
    let md = "text\n\n```java\nclass A {}\n```\n\n```\n{code}\n```\n\n\
              > quoted\n>\n> ```\n> inner\n> ```\n";
    let (out, e) = convert_checked(md)?;
    assert_eq!(
        kinds(&e),
        [
            ContainerKind::Code,
            ContainerKind::Noformat,
            ContainerKind::Quote,
            ContainerKind::Code
        ]
    );
    let slices: Vec<&str> = e
        .code_blocks
        .iter()
        .map(|c| out.get(c.byte_range.clone()).unwrap_or(""))
        .collect();
    assert_eq!(
        slices,
        [
            "{code:java}\nclass A {}\n{code}",
            "{noformat}\n{code}\n{noformat}",
            "{quote}\nquoted\n\n{code}\ninner\n{code}\n{quote}",
            "{code}\ninner\n{code}",
        ]
    );
    // Sorted by start.
    assert!(
        e.code_blocks
            .windows(2)
            .all(|w| w[0].byte_range.start <= w[1].byte_range.start)
    );
    Ok(())
}

#[test]
fn nested_quotes_never_nest_containers() -> TestResult {
    let (out, e) = convert_checked("> a\n>\n> > b\n> >\n> > > c\n> > > d\n>\n> e\n")?;
    assert_eq!(out, "{quote}\na\n\nbq. b\n\nbq. c\\\\d\n\ne\n{quote}\n");
    assert_eq!(kinds(&e), [ContainerKind::Quote]);
    Ok(())
}

#[test]
fn quote_holding_its_own_closer_is_flattened() -> TestResult {
    // The code body holds `{quote}`: a container around it could be closed early by Jira.
    let (out, e) = convert_checked("> a\n>\n> ```\n> {QUOTE}\n> ```\n")?;
    assert_eq!(out, "bq. a\n\n{code}\n{QUOTE}\n{code}\n");
    assert_eq!(kinds(&e), [ContainerKind::Code]);
    // Escaped prose counts as well (fail closed): no container either.
    let (out, e) = convert_checked("> a {quote} b\n>\n> c\n")?;
    assert_eq!(out, "bq. a \\{quote\\} b\n\nbq. c\n");
    assert!(e.code_blocks.is_empty());
    Ok(())
}

#[test]
fn quote_hazard_matches_whitespace_led_closers() -> TestResult {
    // The parser pairs `{ quote}` / `{\tQuote }` as a closer, so these flatten like `{quote}`.
    let (out, e) = convert_checked("> a\n>\n> ```\n> { quote}\n> {include:X}\n> ```\n")?;
    assert_eq!(out, "bq. a\n\n{code}\n{ quote}\n{include:X}\n{code}\n");
    assert_eq!(kinds(&e), [ContainerKind::Code]);
    assert!(wiki_constructs(&out).includes.is_empty());
    let (out, e) = convert_checked("> a\n>\n> ```\n> {\tQuote }\n> ```\n")?;
    assert_eq!(out, "bq. a\n\n{code}\n{\tQuote }\n{code}\n");
    assert_eq!(kinds(&e), [ContainerKind::Code]);
    // Escaped prose.
    let (out, e) = convert_checked("> a { quote} b\n>\n> c\n")?;
    assert_eq!(out, "bq. a \\{ quote\\} b\n\nbq. c\n");
    assert!(e.code_blocks.is_empty());
    // `{` alone, or `{` + whitespace + another word, keeps the container.
    let (_, e) = convert_checked("> a { b\n>\n> c { quo}\n")?;
    assert_eq!(kinds(&e), [ContainerKind::Quote]);
    Ok(())
}

#[test]
fn bare_url_keeps_its_end_next_to_delimiters() -> TestResult {
    let url = "https://x.example/a";
    for (md, out) in [
        (
            "*https://x.example/a*",
            "_[https://x.example/a|https://x.example/a]_\n",
        ),
        (
            "_https://x.example/a_",
            "_[https://x.example/a|https://x.example/a]_\n",
        ),
        (
            "~~https://x.example/a~~ b",
            "-[https://x.example/a|https://x.example/a]- b\n",
        ),
        (
            "https://x.example/a.\\",
            "[https://x.example/a|https://x.example/a].&#92;\n",
        ),
        (
            "https://x.example/a\\",
            "[https://x.example/a|https://x.example/a]&#92;\n",
        ),
        // Nothing glues: the URL stays a bare link.
        ("see https://x.example/a.", "see https://x.example/a.\n"),
        ("**https://x.example/a**", "*https://x.example/a*\n"),
        ("https://x.example/a *b*", "https://x.example/a _b_\n"),
    ] {
        let (got, _) = convert_checked(md)?;
        assert_eq!(got, out, "for {md:?}");
        assert_eq!(wiki_constructs(&got).links, [url], "links of {got:?}");
    }
    // The text of a rewritten link escapes like any text, the target keeps the URL.
    let (got, _) = convert_checked("*https://x.example/a_b-c?d=1&e=2*")?;
    assert_eq!(
        got,
        "_[https://x.example/a_b-c?d=1&e=2|https://x.example/a_b-c?d=1&e=2]_\n"
    );
    assert_eq!(
        wiki_constructs(&got).links,
        ["https://x.example/a_b-c?d=1&e=2"]
    );
    Ok(())
}

#[test]
fn code_language_allowlist_and_aliases() -> TestResult {
    let table = [
        ("java", Some("java")),
        ("Java", Some("java")),
        ("JSON", Some("json")),
        ("c++", Some("c++")),
        ("c#", Some("c#")),
        ("cpp", Some("c++")),
        ("cs", Some("c#")),
        ("csharp", Some("c#")),
        ("js", Some("javascript")),
        ("jsx", Some("javascript")),
        ("ts", Some("javascript")),
        ("typescript", Some("javascript")),
        ("tsx", Some("javascript")),
        ("py", Some("python")),
        ("python", Some("python")),
        ("yml", Some("yaml")),
        ("rb", Some("ruby")),
        ("sh", Some("bash")),
        ("shell", Some("bash")),
        ("console", Some("bash")),
        ("zsh", Some("bash")),
        ("text", Some("none")),
        ("plain", Some("none")),
        ("plaintext", Some("none")),
        ("none", Some("none")),
        ("sql", Some("sql")),
        ("xml", Some("xml")),
        ("html", Some("html")),
        ("go", Some("go")),
        ("objc", Some("objc")),
        ("visualbasic", Some("visualbasic")),
        ("rust", None),
        ("kotlin", None),
        ("kt", None),
        ("toml", None),
        ("diff", None),
        ("nosuchlang", None),
    ];
    for (info, want) in table {
        let (out, _) = convert_checked(&format!("```{info}\nx\n```\n"))?;
        let open = match want {
            Some(l) => format!("{{code:{l}}}"),
            None => "{code}".to_owned(),
        };
        assert_eq!(out, format!("{open}\nx\n{{code}}\n"), "for {info:?}");
    }
    // Only the first word counts, and `{code:lang}` stays the opener of an inner container.
    let (out, _) = convert_checked("```ts extra\nx\n```\n")?;
    assert_eq!(out, "{code:javascript}\nx\n{code}\n");
    Ok(())
}

#[test]
fn single_paragraph_quote_is_bq() -> TestResult {
    let (out, e) = convert_checked("> one\n> two  \n> three\n")?;
    assert_eq!(out, "bq. one\\\\two\\\\three\n");
    assert!(e.code_blocks.is_empty());
    Ok(())
}

#[test]
fn link_url_with_pipe_or_bracket_is_encoded() -> TestResult {
    let (out, _) = convert_checked(
        "[a](<https://x.example/p|q]r[s>) [b](<https://x.example/{t}!\\u v>) [c](~u) [d](^f)",
    )?;
    assert_eq!(
        out,
        "[a|https://x.example/p%7Cq%5Dr%5Bs] [b|https://x.example/%7Bt%7D%21%5Cu%20v] \
         [c|%7Eu] [d|%5Ef]\n"
    );
    assert_eq!(
        wiki_constructs(&out).links,
        [
            "https://x.example/p%7Cq%5Dr%5Bs",
            "https://x.example/%7Bt%7D%21%5Cu%20v",
            "%7Eu",
            "%5Ef"
        ]
    );
    // Autolinks and e-mail links.
    let (out, _) = convert_checked("<https://x.example/~a_b> <me@x.example>")?;
    assert_eq!(
        out,
        "[https://x.example/~a_b|https://x.example/~a_b] [me@x.example|mailto:me@x.example]\n"
    );
    Ok(())
}

#[test]
fn link_text_starting_with_tilde_or_caret_is_not_a_mention() -> TestResult {
    let (out, _) = convert_checked(
        "[~jdoe](https://x.example) [ ^f](https://x.example) [*~e*](https://x.example) [](~u)",
    )?;
    assert_eq!(
        out,
        "[&#126;jdoe|https://x.example] [ &#94;f|https://x.example] \
         [_\\~e_|https://x.example] [%7Eu]\n"
    );
    Ok(())
}

#[test]
fn line_start_markers_after_soft_breaks() -> TestResult {
    let md = "first\nh2. two\nbq. three\n\\# four\n\\- five\n\\* six\n\\| seven\n\\---- eight\n";
    let (out, _) = convert_checked(md)?;
    assert_eq!(
        out,
        "first\n&#104;2. two\n&#98;q. three\n\\# four\n\\- five\n\\* six\n\\| seven\n\
         \\-\\-\\-\\- eight\n"
    );
    let doc = wiki::parse(&out);
    assert_eq!(doc.blocks.len(), 1, "{:?}", doc.blocks);
    // pulldown splits text at escapes and entities (`h1\.` is `h1` + `.`); the converter
    // escapes the joined text, so split markers are still caught.
    let (out, _) = convert_checked("h1\\. x\n\nb\\q. y\n\na\\&amp;b \\&amp;c\\;\n")?;
    assert_eq!(out, "&#104;1. x\n\nb&#92;q. y\n\na&#38;amp;b &#38;amp;c;\n");
    let (out, _) = convert_checked("x\n\nb\\\nq. y\n\nbq\\. z\n")?;
    assert_eq!(out, "x\n\nb\nq. y\n\n&#98;q. z\n");
    Ok(())
}

#[test]
fn emphasis_with_edge_whitespace_moves_the_delimiters() -> TestResult {
    // `&#32;` makes CommonMark emphasis whose content starts or ends with a space.
    let (out, _) = convert_checked("**&#32;a** b **c&#32;** d **&#32;**")?;
    assert_eq!(out, " *a* b *c*  d\n");
    Ok(())
}

#[test]
fn escape_examples() -> TestResult {
    let cases = [
        ("plain text", "plain text"),
        ("{ } [ ] | ! + ~ ^", "\\{ \\} \\[ \\] \\| \\! \\+ \\~ \\^"),
        (
            "a*b *c* _d_ e_f -g- h-i",
            "a*b \\*c\\* \\_d\\_ e_f \\-g\\- h-i",
        ),
        ("why? ?? ok?", "why? \\?\\? ok?"),
        ("#1 and #2", "\\#1 and #2"),
        ("h1. x", "&#104;1. x"),
        ("h7. x", "h7. x"),
        ("bq. x", "&#98;q. x"),
        ("bq x", "bq x"),
        ("C:\\x \\{", "C:&#92;x &#92;\\{"),
        ("&amp; &#92; & a&b c", "&#38;amp; &#38;#92; & a&b c"),
        ("a&b", "a&b"),
        ("h", "h"),
        ("h1", "h1"),
        ("b", "b"),
        // The `;` after a URL is not part of it but still ends the entity.
        (
            "https://x.example/?a=1&#92;",
            "https://x.example/?a=1&#38;#92;",
        ),
        ("----", "\\-\\-\\-\\-"),
        (
            "see https://x.example/a_b~c+d?e#f.",
            "see https://x.example/a_b~c+d?e#f.",
        ),
        ("xhttps://x.example/~a", "xhttps://x.example/\\~a"),
        ("line\n* item\n  - item", "line\n\\* item\n  \\- item"),
        ("@jdoe", "@jdoe"),
    ];
    for (input, expected) in cases {
        assert_eq!(escape::wiki_text(input), expected, "input {input:?}");
    }
    Ok(())
}

#[test]
fn crlf_input_is_normalized() -> TestResult {
    let (out, _) = convert_checked("a\r\nb\r\n\r\n```\r\nc\r\n```\r\n")?;
    assert_eq!(out, "a\nb\n\n{code}\nc\n{code}\n");
    Ok(())
}

#[test]
fn output_ends_with_one_newline() -> TestResult {
    for md in [
        "",
        "\n\n",
        "x",
        "x\n\n\n",
        "```\n```",
        "- ",
        "> ",
        "<div>\n\n",
    ] {
        let (out, _) = convert_checked(md)?;
        assert!(
            out.ends_with('\n') && !out.ends_with("\n\n"),
            "{md:?} → {out:?}"
        );
    }
    assert_eq!(markdown_to_wiki("").0, "\n");
    Ok(())
}

#[test]
fn tables_escape_cells_and_fill_empty_ones() -> TestResult {
    let (out, _) = convert_checked("| a | b |\n|---|:-:|\n| x \\| y | `p\\|q` |\n|  | *e* |\n")?;
    assert_eq!(out, "||a||b||\n|x \\| y|{{p\\|q}}|\n| |_e_|\n");
    let doc = wiki::parse(&out);
    let Some(Block::Table { rows }) = doc.blocks.first() else {
        return Err(format!("not a table: {:?}", doc.blocks).into());
    };
    assert_eq!(
        rows.iter().map(|r| r.cells.len()).collect::<Vec<_>>(),
        [2, 2, 2]
    );
    Ok(())
}

#[test]
fn deep_nesting_is_bounded() -> TestResult {
    let inputs = [
        format!("{} x\n", ">".repeat(5_000)),
        format!("{}x\n", "- ".repeat(3_000)),
        format!("{}x{}\n", "*a ".repeat(3_000), " a*".repeat(3_000)),
        format!("{}x{}\n", "[".repeat(2_000), "](u)".repeat(2_000)),
        "**&#32;**".repeat(5_000),
    ];
    for md in &inputs {
        convert_checked(md)?;
    }
    Ok(())
}

// ------------------------------------------------------------------ properties

/// Single-line text over an alphabet biased to wiki specials (and anything else).
fn line_fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(vec![
            "{",
            "}",
            "{{",
            "}}",
            "[",
            "]",
            "[~",
            "[^",
            "|",
            "||",
            "!",
            "\\",
            "\\\\",
            "*",
            "_",
            "-",
            "+",
            "^",
            "~",
            "?",
            "??",
            "#",
            " ",
            "\t",
            "{code}",
            "{noformat}",
            "{quote}",
            "{toc}",
            "{include:A}",
            "h1. ",
            "h6.",
            "bq. ",
            "* ",
            "# ",
            "- ",
            "----",
            "&#92;",
            "&amp;",
            "&",
            ";",
            "]]>",
            "@jdoe",
            "https://x.example/a_b~c?d=1",
            "http://",
            "mailto:a",
            "é",
            "\u{202E}",
            "日本",
            "\u{a0}",
            "a",
            "h",
            "b",
            "q",
            "1",
            ".",
        ])
        .prop_map(str::to_owned),
        "[a-z]{1,5}",
        any::<char>()
            .prop_filter("single line", |c| *c != '\n' && *c != '\r')
            .prop_map(String::from),
    ]
}

fn line() -> impl Strategy<Value = String> {
    proptest::collection::vec(line_fragment(), 0..24).prop_map(|v| v.concat())
}

/// Backslash-escapes every ASCII punctuation char, so the Markdown text is `s` itself.
fn md_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_punctuation() {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Text chars for the Markdown round trip: no whitespace but the space, no line breaks.
fn md_text_fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(vec![
            "{",
            "}",
            "[",
            "]",
            "[~",
            "[^",
            "|",
            "!",
            "\\",
            "*",
            "_",
            "-",
            "+",
            "^",
            "~",
            "??",
            "#",
            " ",
            "{code}",
            "{toc}",
            "{include:A}",
            "h1. ",
            "bq. ",
            "- ",
            "----",
            "&#92;",
            "&",
            "@jdoe",
            "https://x.example/a_b~c",
            "é",
            "\u{202E}",
            "日本",
            ">",
            "`",
            "<b>",
            "1.",
            "=",
        ])
        .prop_map(str::to_owned),
        "[a-z]{1,5}",
        any::<char>()
            .prop_filter("no whitespace but space", |c| *c == ' '
                || !c.is_whitespace())
            .prop_map(String::from),
    ]
}

fn md_text_lines() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec(
        proptest::collection::vec(md_text_fragment(), 0..10).prop_map(|v| v.concat()),
        1..5,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// `escape::wiki_text` of one line parses back to that line (after the parser's
    /// paragraph trim and decoding the character references), as plain text only.
    #[test]
    fn escaped_text_round_trips(s in line()) {
        let out = escape::wiki_text(&s);
        let doc = wiki::parse(&out);
        prop_assert!(construct_spans(&doc).is_empty(), "spans in {out:?}");
        let text = project(&doc.blocks).map_err(TestCaseError::fail)?;
        prop_assert_eq!(decode(&text), s.trim(), "via {:?}", out);
    }

    /// Markdown whose text is `lines` (all ASCII punctuation backslash-escaped) converts to
    /// wiki text that parses back to the same paragraphs and lines, as plain text only.
    #[test]
    fn markdown_text_round_trips(lines in md_text_lines()) {
        let md = lines.iter().map(|l| md_escape(l)).collect::<Vec<_>>().join("\n");
        let (out, e) = markdown_to_wiki(&md);
        prop_assert!(e.code_blocks.is_empty());
        let doc = wiki::parse(&out);
        prop_assert!(construct_spans(&doc).is_empty(), "spans in {out:?}");
        let text = project(&doc.blocks).map_err(TestCaseError::fail)?;
        let mut paras: Vec<String> = Vec::new();
        let mut cur: Vec<&str> = Vec::new();
        for l in &lines {
            let t = l.trim_matches(' ');
            if t.is_empty() {
                if !cur.is_empty() {
                    paras.push(cur.join("\n"));
                    cur.clear();
                }
            } else {
                cur.push(t);
            }
        }
        if !cur.is_empty() {
            paras.push(cur.join("\n"));
        }
        prop_assert_eq!(decode(&text), paras.join("\n\n"), "md {:?} → {:?}", md, out);
    }

    /// Any Markdown: the parser finds exactly the recorded containers and nothing else; the
    /// output ends with one newline.
    #[test]
    fn markdown_produces_only_recorded_containers(md in markdown()) {
        convert_checked(&md).map_err(TestCaseError::fail)?;
    }

    /// A bare URL next to emphasis, strike or a backslash stays one link with exactly that
    /// target (a delimiter or character reference after it must not extend it).
    #[test]
    fn bare_url_target_survives_adjacent_markup(
        path in "[a-z0-9.-]{0,8}[a-z]",
        wrap in prop::sample::select(vec!["", "*", "**", "_", "__", "~~"]),
        suffix in prop::sample::select(vec!["", ".", ",", ")", "\\", ".\\", "\\\\", " x", "?"]),
        prefix in prop::sample::select(vec!["", "a ", "(", "> "]),
    ) {
        let url = format!("https://x.example/{path}");
        let md = format!("{prefix}{wrap}{url}{wrap}{suffix}\n");
        let (out, _) = convert_checked(&md).map_err(TestCaseError::fail)?;
        prop_assert_eq!(wiki_constructs(&out).links, vec![url], "md {:?} -> {:?}", md, out);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn deterministic_output(md in markdown()) {
        prop_assert_eq!(markdown_to_wiki(&md), markdown_to_wiki(&md));
    }
}
