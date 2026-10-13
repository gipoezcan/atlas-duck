//! `convert::wiki`: the Jira wiki parser shared by the hard check and the preview renderer
//! (spec §7.6, plan PD-44).

use atlas_duck_convert::wiki::{self, Block, CodeKind, Inline, TableCell, TableRow, WikiDoc};
use atlas_duck_convert::{ConstructKind, WikiConstructs, wiki_constructs};
use proptest::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn text(s: &str) -> Inline {
    Inline::Text(s.to_owned())
}

fn cell(header: bool, inlines: Vec<Inline>) -> TableCell {
    TableCell { header, inlines }
}

/// Every inline node of `inlines`, depth first (children after their parent).
fn walk_inlines(inlines: &[Inline], out: &mut Vec<Inline>) {
    for i in inlines {
        out.push(i.clone());
        if let Inline::Strong(c) | Inline::Emphasis(c) | Inline::Strike(c) = i {
            walk_inlines(c, out);
        }
    }
}

/// Every inline node of the document, depth first.
fn all_inlines(blocks: &[Block], out: &mut Vec<Inline>) {
    for b in blocks {
        match b {
            Block::Heading { inlines, .. } | Block::Paragraph(inlines) => {
                walk_inlines(inlines, out)
            }
            Block::List { items, .. } => items.iter().for_each(|(_, i)| walk_inlines(i, out)),
            Block::Table { rows } => rows
                .iter()
                .flat_map(|r| r.cells.iter())
                .for_each(|c| walk_inlines(&c.inlines, out)),
            Block::Quote(inner) | Block::Panel { blocks: inner, .. } => all_inlines(inner, out),
            Block::Code { .. } | Block::Macro { .. } | Block::Rule => {}
        }
    }
}

/// Names of every `Block::Macro` and `Inline::Macro` in document order.
fn macro_names(blocks: &[Block], out: &mut Vec<String>) {
    for b in blocks {
        match b {
            Block::Macro { name, .. } => out.push(name.clone()),
            Block::Quote(inner) | Block::Panel { blocks: inner, .. } => macro_names(inner, out),
            other => {
                let mut inl = Vec::new();
                all_inlines(std::slice::from_ref(other), &mut inl);
                out.extend(inl.into_iter().filter_map(|i| match i {
                    Inline::Macro { name, .. } => Some(name),
                    _ => None,
                }));
            }
        }
    }
}

fn names(doc: &WikiDoc) -> Vec<String> {
    let mut out = Vec::new();
    macro_names(&doc.blocks, &mut out);
    out
}

#[test]
fn parses_headings_lists_tables_quotes() -> TestResult {
    let src = "h1. Title\n\
               h3. Sub *bold*\n\
               \n\
               * one\n\
               ** two\n\
               \n\
               # first\n\
               # second\n\
               \n\
               ||h1||h2||\n\
               |a|[x|https://e.x]|\n\
               \n\
               bq. quoted\n\
               {quote}\n\
               q1\n\
               \n\
               q2\n\
               {quote}\n\
               ----\n\
               {panel:title=Note|borderStyle=solid}\n\
               in panel\n\
               {panel}\n\
               plain _em_ -del- text\n\
               line2";
    let doc = wiki::parse(src);
    let expected = vec![
        Block::Heading {
            level: 1,
            inlines: vec![text("Title")],
        },
        Block::Heading {
            level: 3,
            inlines: vec![text("Sub "), Inline::Strong(vec![text("bold")])],
        },
        Block::List {
            ordered: false,
            items: vec![(1, vec![text("one")]), (2, vec![text("two")])],
        },
        Block::List {
            ordered: true,
            items: vec![(1, vec![text("first")]), (1, vec![text("second")])],
        },
        Block::Table {
            rows: vec![
                TableRow {
                    cells: vec![cell(true, vec![text("h1")]), cell(true, vec![text("h2")])],
                },
                TableRow {
                    cells: vec![
                        cell(false, vec![text("a")]),
                        cell(
                            false,
                            vec![Inline::Link {
                                text: Some("x".to_owned()),
                                target: "https://e.x".to_owned(),
                            }],
                        ),
                    ],
                },
            ],
        },
        Block::Quote(vec![Block::Paragraph(vec![text("quoted")])]),
        Block::Quote(vec![
            Block::Paragraph(vec![text("q1")]),
            Block::Paragraph(vec![text("q2")]),
        ]),
        Block::Rule,
        Block::Panel {
            title: Some("Note".to_owned()),
            blocks: vec![Block::Paragraph(vec![text("in panel")])],
        },
        Block::Paragraph(vec![
            text("plain "),
            Inline::Emphasis(vec![text("em")]),
            text(" "),
            Inline::Strike(vec![text("del")]),
            text(" text"),
            Inline::LineBreak,
            text("line2"),
        ]),
    ];
    assert_eq!(doc.blocks, expected);
    Ok(())
}

#[test]
fn macros_known_and_unknown() -> TestResult {
    let src = "{toc}\nsee {jira:ABC-1} and {color:red}x{color} then {unknownmacro:a=b}";
    let doc = wiki::parse(src);
    assert_eq!(
        doc.blocks.first(),
        Some(&Block::Macro {
            name: "toc".to_owned(),
            params: String::new(),
            body: None,
            byte_range: 0..5,
        })
    );
    assert_eq!(
        names(&doc),
        ["toc", "jira", "color", "color", "unknownmacro"]
    );
    let mut inl = Vec::new();
    all_inlines(&doc.blocks, &mut inl);
    assert!(inl.iter().any(|i| matches!(
        i,
        Inline::Macro { name, params, .. } if name == "jira" && params == "ABC-1"
    )));
    assert!(inl.iter().any(|i| matches!(
        i,
        Inline::Macro { name, params, .. } if name == "unknownmacro" && params == "a=b"
    )));
    // `{color}` keeps its content as ordinary text between the two tags.
    assert!(inl.contains(&text("x")));
    assert_eq!(
        wiki_constructs(src).macros,
        ["toc", "jira", "color", "color", "unknownmacro"]
    );

    // A body macro alone at a line start pairs with its closing tag: one macro, raw body kept.
    let html = "{html}<b>x</b>{html}";
    let doc = wiki::parse(html);
    assert_eq!(
        doc.blocks,
        vec![Block::Macro {
            name: "html".to_owned(),
            params: String::new(),
            body: Some("<b>x</b>".to_owned()),
            byte_range: 0..html.len(),
        }]
    );
    Ok(())
}

#[test]
fn code_and_noformat_bodies_are_opaque() -> TestResult {
    let src = "{code}{include:X}{code}";
    let doc = wiki::parse(src);
    assert_eq!(
        doc.blocks,
        vec![Block::Code {
            kind: CodeKind::Code,
            lang: None,
            body: "{include:X}".to_owned(),
            byte_range: 0..src.len(),
        }]
    );
    assert!(names(&doc).is_empty());
    let inv = wiki_constructs(src);
    assert!(inv.includes.is_empty());
    assert_eq!(inv.macros, ["code"]);

    let src = "{noformat}[~jdoe] {toc} h1. x\n|a|{noformat}";
    let doc = wiki::parse(src);
    assert_eq!(
        doc.blocks,
        vec![Block::Code {
            kind: CodeKind::Noformat,
            lang: None,
            body: "[~jdoe] {toc} h1. x\n|a|".to_owned(),
            byte_range: 0..src.len(),
        }]
    );
    let inv = wiki_constructs(src);
    assert!(inv.mentions.is_empty());
    assert_eq!(inv.macros, ["noformat"]);

    // Language parameter, and a code macro in the middle of a paragraph splits it.
    let doc = wiki::parse("{code:java}\nint x;\n{code}");
    assert!(matches!(
        doc.blocks.as_slice(),
        [Block::Code { kind: CodeKind::Code, lang: Some(l), .. }] if l == "java"
    ));
    let doc = wiki::parse("a {code}b{code} c");
    assert_eq!(
        doc.blocks,
        vec![
            Block::Paragraph(vec![text("a")]),
            Block::Code {
                kind: CodeKind::Code,
                lang: None,
                body: "b".to_owned(),
                byte_range: 2..15
            },
            Block::Paragraph(vec![text("c")]),
        ]
    );

    // A noformat body may hold `{code}`; only `{noformat}` closes it.
    let src = "{noformat}{code}x{code}{noformat}after {toc}";
    let doc = wiki::parse(src);
    assert!(matches!(
        doc.blocks.first(),
        Some(Block::Code { kind: CodeKind::Noformat, body, .. }) if body == "{code}x{code}"
    ));
    assert_eq!(names(&doc), ["toc"]);
    Ok(())
}

#[test]
fn code_tags_are_exact_lowercase() -> TestResult {
    // Only a literal `{code}` closes a code body; other spellings are body text.
    let src = "{code}a{CODE}b{code:x}c{code}";
    let doc = wiki::parse(src);
    assert!(matches!(
        doc.blocks.as_slice(),
        [Block::Code { body, .. }] if body == "a{CODE}b{code:x}c"
    ));
    // Other spellings never open an opaque body: their content is scanned (fail closed).
    for src in [
        "{Code}[~a]{Code}",
        "{ code }\n[~a]\n{ code }",
        "{NOFORMAT}[~a]",
    ] {
        let doc = wiki::parse(src);
        assert!(
            !doc.blocks.iter().any(|b| matches!(b, Block::Code { .. })),
            "{src}: {doc:?}"
        );
        assert_eq!(wiki_constructs(src).mentions, ["a"], "{src}");
    }
    Ok(())
}

#[test]
fn unterminated_code_runs_to_end() -> TestResult {
    let src = "intro\n{code}\n[~jdoe]\n{toc}\n{noformat}";
    let doc = wiki::parse(src);
    assert_eq!(
        doc.blocks,
        vec![
            Block::Paragraph(vec![text("intro")]),
            Block::Code {
                kind: CodeKind::Code,
                lang: None,
                body: "\n[~jdoe]\n{toc}\n{noformat}".to_owned(),
                byte_range: 6..src.len(),
            },
        ]
    );
    let inv = wiki_constructs(src);
    assert!(inv.mentions.is_empty());
    assert_eq!(inv.macros, ["code"]);
    let spans = wiki::construct_spans(&doc);
    assert_eq!(spans, vec![(ConstructKind::Macro, 6..src.len())]);
    Ok(())
}

#[test]
fn mentions_links_images_attachments() -> TestResult {
    let src = "[~jdoe] [text|https://x] [https://x] !https://x/a.png! [^file.txt]";
    let doc = wiki::parse(src);
    assert_eq!(
        doc.blocks,
        vec![Block::Paragraph(vec![
            Inline::Mention("jdoe".to_owned()),
            text(" "),
            Inline::Link {
                text: Some("text".to_owned()),
                target: "https://x".to_owned()
            },
            text(" "),
            Inline::Link {
                text: None,
                target: "https://x".to_owned()
            },
            text(" "),
            Inline::Image("https://x/a.png".to_owned()),
            text(" "),
            Inline::Attachment("file.txt".to_owned()),
        ])]
    );
    let spans = wiki::construct_spans(&doc);
    let kinds: Vec<ConstructKind> = spans.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        kinds,
        [
            ConstructKind::Mention,
            ConstructKind::Image,
            ConstructKind::Attachment
        ]
    );
    let slices: Vec<&str> = spans
        .iter()
        .filter_map(|(_, r)| src.get(r.clone()))
        .collect();
    assert_eq!(slices, ["[~jdoe]", "!https://x/a.png!", "[^file.txt]"]);

    // Image parameters are not part of the target; a user link `[alias|~user]` is a mention.
    let doc = wiki::parse("!a.png|thumbnail! [Jo|~jo] [see|^b.pdf]");
    let mut inl = Vec::new();
    all_inlines(&doc.blocks, &mut inl);
    assert!(inl.contains(&Inline::Image("a.png".to_owned())));
    assert!(inl.contains(&Inline::Mention("jo".to_owned())));
    assert!(inl.contains(&Inline::Attachment("b.pdf".to_owned())));

    // Prose exclamation marks are not images.
    let doc = wiki::parse("Hello! World! Wow!! ok");
    assert_eq!(
        doc.blocks,
        vec![Block::Paragraph(vec![text("Hello! World! Wow!! ok")])]
    );
    Ok(())
}

#[test]
fn backslash_escapes_are_literal() -> TestResult {
    let src = "\\{toc\\} \\[~jdoe\\] \\!x! \\*b\\* \\{\\{m\\}\\} C:\\path";
    let doc = wiki::parse(src);
    assert_eq!(
        doc.blocks,
        vec![Block::Paragraph(vec![text(
            "{toc} [~jdoe] !x! *b* {{m}} C:\\path"
        )])]
    );
    assert_eq!(wiki_constructs(src), WikiConstructs::default());
    assert!(wiki::construct_spans(&doc).is_empty());

    // `\\` is Jira's forced line break.
    let doc = wiki::parse("a\\\\b");
    assert_eq!(
        doc.blocks,
        vec![Block::Paragraph(vec![
            text("a"),
            Inline::LineBreak,
            text("b")
        ])]
    );
    // An escaped backslash does not escape the brace after it.
    assert_eq!(wiki_constructs("a\\\\{toc}").macros, ["toc"]);
    Ok(())
}

#[test]
fn monospace_still_scanned() -> TestResult {
    let doc = wiki::parse("{{ {toc} }}");
    assert_eq!(
        doc.blocks,
        vec![Block::Paragraph(vec![
            Inline::Monospace(" ".to_owned()),
            Inline::Macro {
                name: "toc".to_owned(),
                params: String::new(),
                byte_range: 3..8
            },
            Inline::Monospace(" ".to_owned()),
        ])]
    );
    let inv = wiki_constructs("{{[~jdoe] *x* !i.png!}}");
    assert_eq!(inv.mentions, ["jdoe"]);
    assert_eq!(inv.images, ["i.png"]);
    // Plain monospace has no construct; an unclosed `{{` still exposes the macro after it.
    let doc = wiki::parse("{{toc}}");
    assert_eq!(
        doc.blocks,
        vec![Block::Paragraph(vec![Inline::Monospace("toc".to_owned())])]
    );
    assert_eq!(wiki_constructs("{{toc}").macros, ["toc"]);
    assert_eq!(wiki_constructs("{{x} y}}").macros, ["x"]);
    Ok(())
}

#[test]
fn includes_classified() -> TestResult {
    let inv = wiki_constructs("{include:Space:Page}");
    assert_eq!(inv.includes, ["Space:Page"]);
    assert!(inv.macros.is_empty());
    let src = "x {excerpt-include:Other} y";
    let inv = wiki_constructs(src);
    assert_eq!(inv.includes, ["Other"]);
    assert!(inv.macros.is_empty());
    let doc = wiki::parse(src);
    assert_eq!(
        wiki::construct_spans(&doc),
        vec![(ConstructKind::Include, 2..25)]
    );
    assert_eq!(names(&doc), ["excerpt-include"]);
    Ok(())
}

#[test]
fn wiki_constructs_inventory() -> TestResult {
    let src = "{toc} [~jdoe] {include:S:P} [t|https://l] !https://i/a.png! [^f.txt]";
    assert_eq!(
        wiki_constructs(src),
        WikiConstructs {
            macros: vec!["toc".to_owned()],
            mentions: vec!["jdoe".to_owned()],
            includes: vec!["S:P".to_owned()],
            links: vec!["https://l".to_owned()],
            images: vec!["https://i/a.png".to_owned()],
            attachments: vec!["f.txt".to_owned()],
        }
    );
    // Document order within each list, across blocks.
    let src =
        "h2. {b} [~z]\n* {a} [~y]\n|[~x]|{c}|\n{quote}\n[~w] see https://u.example/p\n{quote}";
    let inv = wiki_constructs(src);
    assert_eq!(inv.macros, ["b", "a", "c", "quote"]);
    assert_eq!(inv.mentions, ["z", "y", "x", "w"]);
    assert_eq!(inv.links, ["https://u.example/p"]);
    Ok(())
}

#[test]
fn constructs_found_in_every_context() -> TestResult {
    // `{toc}` in every context the parser knows; each one must be reported exactly once.
    let contexts = [
        "h3. head {toc}",
        "para {toc}",
        "* item {toc}",
        "# item {toc}",
        "|cell {toc}|",
        "||head {toc}||",
        "|[cell link {toc}|https://x]|",
        "*strong {toc}*",
        "_em {toc}_",
        "-del {toc}-",
        "{{mono {toc}}}",
        "[link {toc}|https://x]",
        "[https://x/{toc}]",
        "!img{toc}.png!",
        "bq. quoted {toc}",
        "{quote}\nq {toc}\n{quote}",
        "{panel:title=T}\np {toc}\n{panel}",
        "{html}h {toc}{html}",
        "{quote}\nunterminated {toc}",
        "{color:red}c {toc}{color}",
    ];
    let src = contexts.join("\n\n");
    let doc = wiki::parse(&src);
    let spans = wiki::construct_spans(&doc);
    let tocs = spans
        .iter()
        .filter(|(k, r)| *k == ConstructKind::Macro && src.get(r.clone()) == Some("{toc}"))
        .count();
    assert_eq!(tocs, contexts.len(), "spans: {spans:?}");
    assert!(
        spans.windows(2).all(|w| w[0].1.start <= w[1].1.start),
        "not sorted: {spans:?}"
    );
    Ok(())
}

#[test]
fn container_and_code_spans_cover_whole_blocks() -> TestResult {
    let src = "{quote}\na\n{quote}\n{code:sh}\nls\n{code}\n{panel}p{panel}";
    let doc = wiki::parse(src);
    let spans = wiki::construct_spans(&doc);
    let slices: Vec<&str> = spans
        .iter()
        .filter_map(|(_, r)| src.get(r.clone()))
        .collect();
    assert_eq!(
        slices,
        [
            "{quote}\na\n{quote}",
            "{code:sh}\nls\n{code}",
            "{panel}p{panel}"
        ]
    );
    assert!(spans.iter().all(|(k, _)| *k == ConstructKind::Macro));
    Ok(())
}

#[test]
fn emphasis_never_splits_constructs() -> TestResult {
    let doc = wiki::parse("*[~a*]* _x [y|https://h/a_b] z_");
    assert_eq!(
        doc.blocks,
        vec![Block::Paragraph(vec![
            Inline::Strong(vec![Inline::Mention("a*".to_owned())]),
            text(" "),
            Inline::Emphasis(vec![
                text("x "),
                Inline::Link {
                    text: Some("y".to_owned()),
                    target: "https://h/a_b".to_owned()
                },
                text(" z"),
            ]),
        ])]
    );
    // Word-internal delimiters are text.
    let doc = wiki::parse("snake_case_name 2020-01-02 a*b*c");
    assert_eq!(
        doc.blocks,
        vec![Block::Paragraph(vec![text(
            "snake_case_name 2020-01-02 a*b*c"
        )])]
    );
    Ok(())
}

#[test]
fn table_cells_keep_links_and_images() -> TestResult {
    let doc = wiki::parse("|[x|https://a]|!i.png|thumbnail!|\\|esc|[~u|v]|");
    assert_eq!(
        doc.blocks,
        vec![Block::Table {
            rows: vec![TableRow {
                cells: vec![
                    cell(
                        false,
                        vec![Inline::Link {
                            text: Some("x".to_owned()),
                            target: "https://a".to_owned(),
                        }],
                    ),
                    cell(false, vec![Inline::Image("i.png".to_owned())]),
                    cell(false, vec![text("|esc")]),
                    cell(false, vec![Inline::Mention("u".to_owned())]),
                ],
            }],
        }]
    );
    Ok(())
}

#[test]
fn crlf_line_endings() -> TestResult {
    let doc = wiki::parse("h1. T\r\n* a\r\n\r\npara\r\nnext");
    assert_eq!(
        doc.blocks,
        vec![
            Block::Heading {
                level: 1,
                inlines: vec![text("T")]
            },
            Block::List {
                ordered: false,
                items: vec![(1, vec![text("a")])]
            },
            Block::Paragraph(vec![text("para"), Inline::LineBreak, text("next")]),
        ]
    );
    Ok(())
}

#[test]
fn deep_nesting_is_bounded() -> TestResult {
    // 5 000 nested body macros: past the depth bound they are plain macros, but every tag
    // and the innermost mention are still reported.
    let n = 5_000;
    let mut src = String::new();
    for i in 0..n {
        src.push_str(&format!("{{m{i}}}\n"));
    }
    src.push_str("[~deep]\n");
    for i in (0..n).rev() {
        src.push_str(&format!("{{m{i}}}\n"));
    }
    let inv = wiki_constructs(&src);
    assert_eq!(inv.mentions, ["deep"]);
    assert!(inv.macros.len() >= n);

    // Long single lines of delimiters stay linear enough to finish.
    let stars = "*a _b -c {{d [e !f ".repeat(20_000);
    let _ = wiki::parse(&stars);
    let nested = format!("{}x{}", "*_-".repeat(3_000), "-_*".repeat(3_000));
    let _ = wiki::parse(&nested);
    Ok(())
}

fn fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("{".to_owned()),
        Just("}".to_owned()),
        Just("{{".to_owned()),
        Just("}}".to_owned()),
        Just("[".to_owned()),
        Just("]".to_owned()),
        Just("[~".to_owned()),
        Just("[^".to_owned()),
        Just("|".to_owned()),
        Just("||".to_owned()),
        Just("!".to_owned()),
        Just("\\".to_owned()),
        Just("\\\\".to_owned()),
        Just("*".to_owned()),
        Just("_".to_owned()),
        Just("-".to_owned()),
        Just("\n".to_owned()),
        Just("\r\n".to_owned()),
        Just("\r".to_owned()),
        Just(" ".to_owned()),
        Just("{code}".to_owned()),
        Just("{code:java}".to_owned()),
        Just("{noformat}".to_owned()),
        Just("{quote}".to_owned()),
        Just("{panel:title=x}".to_owned()),
        Just("{panel}".to_owned()),
        Just("{html}".to_owned()),
        Just("{toc}".to_owned()),
        Just("{include:A:B}".to_owned()),
        Just("{color:red}".to_owned()),
        Just("h1. ".to_owned()),
        Just("bq. ".to_owned()),
        Just("* ".to_owned()),
        Just("# ".to_owned()),
        Just("----".to_owned()),
        Just("https://x.example/a_b".to_owned()),
        Just("é".to_owned()),
        Just("\u{202E}".to_owned()),
        Just("日本".to_owned()),
        "[a-z]{1,4}",
        any::<char>().prop_map(String::from),
    ]
}

fn garbage() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        proptest::collection::vec(fragment(), 0..60).prop_map(|v| v.concat()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn parse_never_panics_on_garbage(src in garbage()) {
        let doc = wiki::parse(&src);
        let spans = wiki::construct_spans(&doc);
        for (_, r) in &spans {
            prop_assert!(r.start <= r.end && r.end <= src.len(), "{r:?} outside {}", src.len());
            prop_assert!(src.is_char_boundary(r.start) && src.is_char_boundary(r.end));
        }
        prop_assert!(spans.windows(2).all(|w| w[0].1.start <= w[1].1.start));
        let _ = wiki_constructs(&src);
        // Deterministic.
        prop_assert_eq!(wiki::parse(&src), doc);
    }
}
