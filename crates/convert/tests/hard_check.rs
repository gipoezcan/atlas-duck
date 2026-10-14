//! `hard_check_wiki`: the re-parse hard check (spec §7.6, §13 U-24, plan Task 4, PD-44).
//!
//! The converter's output is parsed with the preview's parser; every macro, mention, include,
//! image and attachment link it finds must be a container the converter recorded. A faulty
//! converter is simulated by appending an unrecorded construct to real output (PD-64: no fault
//! API in `convert`).

mod common;

use std::ops::Range;

use atlas_duck_convert::wiki::{self, Block, Inline};
use atlas_duck_convert::{
    ConstructKind, ContainerKind, EmittedCode, EmittedConstructs, Unrecorded, hard_check_wiki,
    markdown_to_wiki,
};
use common::{markdown, spans_match_record, tags_only_at_containers};
use proptest::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn rec(kind: ContainerKind, byte_range: Range<usize>) -> EmittedCode {
    EmittedCode { kind, byte_range }
}

fn record(list: Vec<EmittedCode>) -> EmittedConstructs {
    EmittedConstructs { code_blocks: list }
}

fn unrecorded(kind: ConstructKind, count: u64) -> Result<(), Unrecorded> {
    Err(Unrecorded { kind, count })
}

/// Every `{code`/`{noformat` (ASCII case-insensitive) outside a recorded code or noformat
/// container is escaped (`\{`).
fn tags_outside_containers_escaped(out: &str, e: &EmittedConstructs) -> Result<(), String> {
    let bodies: Vec<&Range<usize>> = e
        .code_blocks
        .iter()
        .filter(|c| c.kind != ContainerKind::Quote)
        .map(|c| &c.byte_range)
        .collect();
    let lower = out.to_ascii_lowercase();
    for needle in ["{code", "{noformat"] {
        for (i, _) in lower.match_indices(needle) {
            if bodies.iter().any(|r| r.contains(&i)) {
                continue;
            }
            if i == 0 || out.as_bytes().get(i - 1) != Some(&b'\\') {
                return Err(format!("unescaped {needle} at {i} in {out:?}"));
            }
        }
    }
    Ok(())
}

fn kinds(e: &EmittedConstructs) -> Vec<ContainerKind> {
    e.code_blocks.iter().map(|c| c.kind).collect()
}

#[test]
fn u24_code_body_containers() -> TestResult {
    use ContainerKind::{Code, Noformat, Quote};
    let cases: [(&str, &[ContainerKind]); 10] = [
        ("```\nlet a = 1;\n```\n", &[Code]),
        ("```java\nString s = \"{code}\";\n```\n", &[Noformat]),
        ("```\n{noformat}\n```\n", &[Code]),
        ("```\n{code}\n{noformat}\n```\n", &[]),
        ("```\nx ]]> y\n```\n", &[Code]),
        ("~~~\n]]> {noformat}\n~~~\n", &[Code]),
        ("    {CODE} ]]>\n", &[Noformat]),
        (
            "inline `]]>` and `{code}` and `{noformat}` and `{code}{noformat}`\n",
            &[],
        ),
        (
            "> a\n>\n> ```\n> {noformat} ]]>\n> ```\n\n```\n{code}\n```\n",
            &[Quote, Code, Noformat],
        ),
        (
            "```\n{code}\n```\n\n```\n{noformat}\n```\n\n```\n{code}{noformat}]]>\n```\n",
            &[Noformat, Code],
        ),
    ];
    for (md, want) in cases {
        let (out, e) = markdown_to_wiki(md);
        assert_eq!(hard_check_wiki(&out, &e), Ok(()), "{md:?} -> {out:?}");
        assert_eq!(kinds(&e), want, "{md:?} -> {out:?}");
        tags_outside_containers_escaped(&out, &e)?;
        spans_match_record(&out, &e)?;
    }
    Ok(())
}

#[test]
fn u24_code_and_noformat_both_escaped_monospace() -> TestResult {
    let (out, e) = markdown_to_wiki("```\n{code} ]]> {noformat}\n\n  {toc}\n```\n");
    assert_eq!(
        out,
        "{{\\{code\\} \\]\\]> \\{noformat\\}}}\n{{&#160;}}\n{{&#160;&#160;\\{toc\\}}}\n"
    );
    assert!(e.code_blocks.is_empty());
    assert_eq!(hard_check_wiki(&out, &e), Ok(()));
    let doc = wiki::parse(&out);
    let [Block::Paragraph(lines)] = doc.blocks.as_slice() else {
        return Err(format!("expected one paragraph: {:?}", doc.blocks).into());
    };
    assert!(
        lines
            .iter()
            .all(|i| matches!(i, Inline::Monospace(_) | Inline::LineBreak)),
        "{lines:?}"
    );
    // Inline code holding both tags is escaped monospace too.
    let (out, e) = markdown_to_wiki("a `{code}{noformat}]]>` b\n");
    assert_eq!(out, "a {{\\{code\\}\\{noformat\\}\\]\\]>}} b\n");
    assert_eq!(hard_check_wiki(&out, &e), Ok(()));
    Ok(())
}

/// The faults core's `testing` hook appends (Task 7), each with the kind it must be
/// reported as.
const FAULTS: [(&str, ConstructKind); 9] = [
    ("{include:Injected}", ConstructKind::Include),
    ("{excerpt-include:Injected}", ConstructKind::Include),
    ("[~injected]", ConstructKind::Mention),
    ("[text|~injected]", ConstructKind::Mention),
    ("{html}<b>x</b>{html}", ConstructKind::Macro),
    ("{toc}", ConstructKind::Macro),
    ("x {{ {toc} }} y", ConstructKind::Macro),
    ("!a.png!", ConstructKind::Image),
    ("[^f.txt]", ConstructKind::Attachment),
];

#[test]
fn u24_faulty_converter_detected() -> TestResult {
    let md = "Intro {toc} [~jdoe] !x.png!\n\n```\nfn main() {}\n```\n\n> a\n>\n> b\n";
    let (out, e) = markdown_to_wiki(md);
    assert_eq!(
        kinds(&e),
        [ContainerKind::Code, ContainerKind::Quote],
        "{out:?}"
    );
    assert_eq!(hard_check_wiki(&out, &e), Ok(()));
    for (fault, kind) in [
        ("{include:Injected}", ConstructKind::Include),
        ("[~injected]", ConstructKind::Mention),
        ("{html}<b>x</b>{html}", ConstructKind::Macro),
    ] {
        let faulty = format!("{out}{fault}\n");
        assert_eq!(
            hard_check_wiki(&faulty, &e),
            unrecorded(kind, 1),
            "{faulty:?}"
        );
    }
    Ok(())
}

#[test]
fn hard_check_counts_images_and_attachments() -> TestResult {
    let none = EmittedConstructs::default();
    let wiki = "see !a.png! and [^f] and !b.png|width=3!\n";
    assert_eq!(
        hard_check_wiki(wiki, &none),
        unrecorded(ConstructKind::Image, 2)
    );
    let wiki = "see and [^f] and\n";
    assert_eq!(
        hard_check_wiki(wiki, &none),
        unrecorded(ConstructKind::Attachment, 1)
    );
    // `[text|^file]` is an attachment link as well.
    assert_eq!(
        hard_check_wiki("[a|^f.txt] [^g]\n", &none),
        unrecorded(ConstructKind::Attachment, 2)
    );
    Ok(())
}

#[test]
fn first_failing_kind_is_in_document_order() -> TestResult {
    let none = EmittedConstructs::default();
    // The first unrecorded span decides the kind; the count is of that kind only.
    assert_eq!(
        hard_check_wiki("[^f] !a.png! [~u] [^g]\n", &none),
        unrecorded(ConstructKind::Attachment, 2)
    );
    assert_eq!(
        hard_check_wiki("[~u]\n{include:A}\n{toc}\n[~v]\n", &none),
        unrecorded(ConstructKind::Mention, 2)
    );
    assert_eq!(
        hard_check_wiki("{toc} {include:A}\n", &none),
        unrecorded(ConstructKind::Macro, 1)
    );
    Ok(())
}

#[test]
fn recorded_containers_pass() -> TestResult {
    let wiki = "{code}\n{toc}\n{code}\n";
    let e = record(vec![rec(ContainerKind::Code, 0..wiki.len() - 1)]);
    assert_eq!(hard_check_wiki(wiki, &e), Ok(()));
    // With a language, as a noformat, and a quote holding a code block (nested ranges).
    let wiki = "{code:java}\n{toc} [~u]\n{code}\n";
    let e = record(vec![rec(ContainerKind::Code, 0..wiki.len() - 1)]);
    assert_eq!(hard_check_wiki(wiki, &e), Ok(()));
    let wiki = "{noformat}\n{code} {include:A}\n{noformat}\n";
    let e = record(vec![rec(ContainerKind::Noformat, 0..wiki.len() - 1)]);
    assert_eq!(hard_check_wiki(wiki, &e), Ok(()));
    let wiki = "x\n{quote}\na\n\n{code}\n{toc}\n{code}\n{quote}\n";
    let q = 2..wiki.len() - 1;
    let c = 13..32;
    assert_eq!(wiki.get(c.clone()), Some("{code}\n{toc}\n{code}"));
    let e = record(vec![
        rec(ContainerKind::Quote, q.clone()),
        rec(ContainerKind::Code, c.clone()),
    ]);
    assert_eq!(hard_check_wiki(wiki, &e), Ok(()));
    // Either record alone leaves the other container unrecorded.
    let e = record(vec![rec(ContainerKind::Quote, q)]);
    assert_eq!(
        hard_check_wiki(wiki, &e),
        unrecorded(ConstructKind::Macro, 1)
    );
    let e = record(vec![rec(ContainerKind::Code, c)]);
    assert_eq!(
        hard_check_wiki(wiki, &e),
        unrecorded(ConstructKind::Macro, 1)
    );
    // A macro inside a recorded quote (not a code body) is not covered by the quote.
    let wiki = "{quote}\na {toc}\n\nb\n{quote}\n";
    let e = record(vec![rec(ContainerKind::Quote, 0..wiki.len() - 1)]);
    assert_eq!(
        hard_check_wiki(wiki, &e),
        unrecorded(ConstructKind::Macro, 1)
    );
    Ok(())
}

#[test]
fn a_record_must_be_a_container_of_its_kind() -> TestResult {
    // A faulty converter that records its own fault: the range must slice a whole container
    // of the recorded kind, written as the converter writes it.
    let wiki = "{html}<b>x</b>{html}\n";
    let all = 0..wiki.len() - 1;
    for kind in [
        ContainerKind::Code,
        ContainerKind::Noformat,
        ContainerKind::Quote,
    ] {
        let e = record(vec![rec(kind, all.clone())]);
        assert_eq!(
            hard_check_wiki(wiki, &e),
            unrecorded(ConstructKind::Macro, 1),
            "{kind:?}"
        );
    }
    // The wrong kind for a real container.
    let wiki = "{code}\nx\n{code}\n";
    let e = record(vec![rec(ContainerKind::Noformat, 0..wiki.len() - 1)]);
    assert_eq!(
        hard_check_wiki(wiki, &e),
        unrecorded(ConstructKind::Macro, 1)
    );
    // A shifted, truncated, out-of-bounds or mid-char range.
    let wiki = "é{code}\nx\n{code}\n";
    for r in [
        0..wiki.len() - 1,
        2..wiki.len() - 2,
        2..wiki.len() + 5,
        1..wiki.len() - 1,
    ] {
        let e = record(vec![rec(ContainerKind::Code, r.clone())]);
        assert_eq!(
            hard_check_wiki(wiki, &e),
            unrecorded(ConstructKind::Macro, 1),
            "{r:?}"
        );
    }
    // Parameters the converter never writes.
    let wiki = "{code:title=x|borderStyle=solid}\nx\n{code}\n";
    let e = record(vec![rec(ContainerKind::Code, 0..wiki.len() - 1)]);
    assert_eq!(
        hard_check_wiki(wiki, &e),
        unrecorded(ConstructKind::Macro, 1)
    );
    Ok(())
}

#[test]
fn a_recorded_body_holding_its_own_tag_fails_closed() -> TestResult {
    // The parser closes code only at a literal lowercase `{code}`; Jira might close at
    // `{CODE}`, so a body the converter would never write is not trusted.
    for wiki in [
        "{code}\n{CODE}\n{include:X}\n{code}\n",
        "{noformat}\n{NoFormat}\n{noformat}\n",
    ] {
        let kind = if wiki.starts_with("{code") {
            ContainerKind::Code
        } else {
            ContainerKind::Noformat
        };
        let e = record(vec![rec(kind, 0..wiki.len() - 1)]);
        assert_eq!(
            hard_check_wiki(wiki, &e),
            unrecorded(ConstructKind::Macro, 1),
            "{wiki:?}"
        );
    }
    // A quote whose text holds a quote tag (here inside a recorded code body) is not trusted.
    let wiki = "{quote}\na\n\n{code}\n{ quote}\n{code}\n{quote}\n";
    let c = 11..33;
    assert_eq!(wiki.get(c.clone()), Some("{code}\n{ quote}\n{code}"));
    let e = record(vec![
        rec(ContainerKind::Quote, 0..wiki.len() - 1),
        rec(ContainerKind::Code, c),
    ]);
    assert_eq!(
        hard_check_wiki(wiki, &e),
        unrecorded(ConstructKind::Macro, 1)
    );
    Ok(())
}

#[test]
fn records_must_nest_properly() -> TestResult {
    // The quote's recorded range ends inside the code body (the parser leaves the quote's
    // opening tag unpaired): partially overlapping records are not trusted.
    let wiki = "{quote}\n{code}\nx\n{quote}\n{code}\n";
    let q = 0..24;
    let c = 8..wiki.len() - 1;
    assert_eq!(wiki.get(q.clone()), Some("{quote}\n{code}\nx\n{quote}"));
    assert_eq!(wiki.get(c.clone()), Some("{code}\nx\n{quote}\n{code}"));
    let e = record(vec![
        rec(ContainerKind::Quote, q),
        rec(ContainerKind::Code, c),
    ]);
    assert!(hard_check_wiki(wiki, &e).is_err());
    Ok(())
}

#[test]
fn opening_tag_of_a_recorded_container_alone_stays_fail_closed() -> TestResult {
    // An inline opening tag is accepted as part of its recorded container, but the parser
    // then sees the closing tag on its own, which no record covers.
    let wiki = "x {quote}\na\n{quote}\n";
    let e = record(vec![rec(ContainerKind::Quote, 2..wiki.len() - 1)]);
    assert_eq!(
        hard_check_wiki(wiki, &e),
        unrecorded(ConstructKind::Macro, 1)
    );
    Ok(())
}

#[test]
fn dropped_or_duplicated_records() -> TestResult {
    let (out, e) = markdown_to_wiki("```\na\n```\n\n```\n{code}\n```\n");
    assert_eq!(e.code_blocks.len(), 2);
    assert_eq!(hard_check_wiki(&out, &e), Ok(()));
    for skip in 0..2 {
        let fewer = record(
            e.code_blocks
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .map(|(_, c)| c.clone())
                .collect(),
        );
        assert_eq!(
            hard_check_wiki(&out, &fewer),
            unrecorded(ConstructKind::Macro, 1)
        );
    }
    // A duplicated record is harmless (the same container), an empty one covers nothing.
    let mut twice = e.clone();
    twice.code_blocks.extend(e.code_blocks.iter().cloned());
    assert_eq!(hard_check_wiki(&out, &twice), Ok(()));
    assert_eq!(
        hard_check_wiki(&out, &EmittedConstructs::default()),
        unrecorded(ConstructKind::Macro, 2)
    );
    Ok(())
}

#[test]
fn unrecorded_error_has_no_text() -> TestResult {
    const SENTINEL: &str = "SECRET_PAYLOAD_7f3a";
    let none = EmittedConstructs::default();
    for (wiki, kind) in [
        (format!("{{include:{SENTINEL}}}\n"), ConstructKind::Include),
        (format!("[~{SENTINEL}]\n"), ConstructKind::Mention),
        (format!("{{{SENTINEL}}}\n"), ConstructKind::Macro),
        (format!("!{SENTINEL}.png!\n"), ConstructKind::Image),
        (format!("[^{SENTINEL}]\n"), ConstructKind::Attachment),
    ] {
        let Err(e) = hard_check_wiki(&wiki, &none) else {
            return Err(format!("{wiki:?} passed").into());
        };
        assert_eq!(e, Unrecorded { kind, count: 1 });
        for shown in [format!("{e:?}"), e.to_string()] {
            assert!(!shown.contains(SENTINEL), "{shown}");
            assert!(
                !shown.contains("7f3a") && !shown.contains("SECRET"),
                "{shown}"
            );
        }
    }
    let e = Unrecorded {
        kind: ConstructKind::Include,
        count: 3,
    };
    assert_eq!(format!("{e:?}"), "Unrecorded { kind: Include, count: 3 }");
    assert_eq!(e.to_string(), "unrecorded include (count 3)");
    let as_error: &dyn std::error::Error = &e;
    assert!(as_error.source().is_none());
    Ok(())
}

#[test]
fn never_panics_on_garbage_records() -> TestResult {
    let wiki = "日本{code}\nx\n{code}\n";
    let reversed = Range { start: 3, end: 1 };
    for r in [
        0..0,
        1..2,
        reversed,
        0..usize::MAX,
        usize::MAX - 1..usize::MAX,
    ] {
        let e = record(vec![rec(ContainerKind::Code, r)]);
        assert_eq!(
            hard_check_wiki(wiki, &e),
            unrecorded(ConstructKind::Macro, 1)
        );
    }
    assert_eq!(hard_check_wiki("", &EmittedConstructs::default()), Ok(()));
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    /// §13 U-24: for every generated Markdown input, re-parsing the converted wiki finds no
    /// construct the converter did not record.
    #[test]
    fn u24_fuzz_reparse_finds_nothing_unrecorded(md in markdown()) {
        let (out, e) = markdown_to_wiki(&md);
        prop_assert_eq!(hard_check_wiki(&out, &e), Ok(()), "md {:?} -> {:?}", md, out);
        spans_match_record(&out, &e).map_err(TestCaseError::fail)?;
    }

    /// Any converter output with one unrecorded construct appended fails with that kind,
    /// counted once.
    #[test]
    fn u24_fuzz_appended_fault_detected(
        md in markdown(),
        fault in prop::sample::select(FAULTS.to_vec()),
    ) {
        let (out, e) = markdown_to_wiki(&md);
        let faulty = format!("{out}{}\n", fault.0);
        prop_assert_eq!(
            hard_check_wiki(&faulty, &e),
            unrecorded(fault.1, 1),
            "md {:?} -> {:?}", md, faulty
        );
    }
}

/// T4 review Important 1: a quote tag formed only across the `\n\n` between two children
/// (`\{` ending one, `quote` starting the next) is a hazard for `hard_check_wiki`, so the
/// converter must flatten such quotes instead of recording an untrusted container.
#[test]
fn cross_child_quote_tag_flattens_and_passes() -> TestResult {
    let inputs = [
        "> a {\n>\n> quote b\n",
        "> a {\n>\n> Quote of the day\n",
        "> a {\n>\n> QUOTE\n",
        "> a {\n>\n>  quote\n",
        "> a {\n>\n> quote:x\n",
        "> - x {\n>\n> quote\n",
        "> a &#123;\n>\n> quote b\n",
        "> a \\{\n>\n> quote b\n",
    ];
    for md in inputs {
        let (out, e) = markdown_to_wiki(md);
        assert_eq!(hard_check_wiki(&out, &e), Ok(()), "md {md:?} -> {out:?}");
        assert!(
            !kinds(&e).contains(&ContainerKind::Quote),
            "md {md:?} -> {out:?}"
        );
        spans_match_record(&out, &e)?;
    }
    Ok(())
}

/// The fuzz must keep reaching the quote trust logic (T4 review Minor 1): over a fixed
/// deterministic run of draws, quote containers and quotes nesting code stay common.
#[test]
fn fuzz_strategy_reaches_quote_containers() -> TestResult {
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::TestRunner;

    const DRAWS: usize = 2000;
    let strategy = markdown();
    let mut runner = TestRunner::deterministic();
    let (mut quotes, mut quotes_with_code) = (0, 0);
    for _ in 0..DRAWS {
        let md = strategy
            .new_tree(&mut runner)
            .map_err(|e| e.to_string())?
            .current();
        let (_, e) = markdown_to_wiki(&md);
        for q in e
            .code_blocks
            .iter()
            .filter(|c| c.kind == ContainerKind::Quote)
        {
            quotes += 1;
            if e.code_blocks.iter().any(|c| {
                c.kind != ContainerKind::Quote
                    && c.byte_range.start >= q.byte_range.start
                    && c.byte_range.end <= q.byte_range.end
            }) {
                quotes_with_code += 1;
            }
        }
    }
    eprintln!("quote containers {quotes}, with nested code {quotes_with_code} in {DRAWS} draws");
    assert!(quotes >= DRAWS / 10, "quote containers: {quotes}");
    assert!(
        quotes_with_code >= DRAWS / 10,
        "quotes with nested code: {quotes_with_code}"
    );
    Ok(())
}

/// A `{`, then at least one whitespace or control char, then `code` (ASCII case-insensitive):
/// a closer only a lenient (trimming) scan would see.
fn lenient_code_tag(body: &str) -> bool {
    body.match_indices('{').any(|(i, _)| {
        let rest = body.get(i + 1..).unwrap_or("");
        let t = rest.trim_start_matches(|c: char| c.is_whitespace() || c.is_control());
        t.len() < rest.len()
            && t.as_bytes()
                .get(..4)
                .is_some_and(|w| w.eq_ignore_ascii_case(b"code"))
    })
}

/// The fuzz must keep reaching the final review I-1 shapes: monospace broken by `&#8203;`
/// before a real `{code}`/`{noformat}` container (the pairing case), and code bodies whose only
/// `{code` tag is led by whitespace or a control char (moved to `{noformat}`).
#[test]
fn fuzz_strategy_reaches_tag_shaped_code() -> TestResult {
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::TestRunner;

    const DRAWS: usize = 2000;
    let strategy = markdown();
    let mut runner = TestRunner::deterministic();
    let (mut paired, mut lenient) = (0, 0);
    for _ in 0..DRAWS {
        let md = strategy
            .new_tree(&mut runner)
            .map_err(|e| e.to_string())?
            .current();
        let (out, e) = markdown_to_wiki(&md);
        if let Some(brk) = out.find("{{&#8203;")
            && e.code_blocks
                .iter()
                .any(|c| c.kind != ContainerKind::Quote && c.byte_range.start > brk)
        {
            paired += 1;
        }
        if e.code_blocks.iter().any(|c| {
            c.kind == ContainerKind::Noformat
                && out.get(c.byte_range.clone()).is_some_and(lenient_code_tag)
        }) {
            lenient += 1;
        }
    }
    eprintln!("break before a container {paired}, lenient code tag in noformat {lenient}");
    assert!(paired >= DRAWS / 20, "break before a container: {paired}");
    assert!(
        lenient >= DRAWS / 20,
        "lenient code tag in noformat: {lenient}"
    );
    Ok(())
}

/// The lenient-scan property catches the pre-I-1 shape and accepts the broken one.
#[test]
fn tags_only_at_containers_bites() -> TestResult {
    let none = EmittedConstructs::default();
    for bad in [
        "{{code}}\n",
        "{{ toc }}\n",
        "{{include:X}}\n",
        "x {quote}\n",
    ] {
        assert!(tags_only_at_containers(bad, &none).is_err(), "{bad:?}");
    }
    for good in [
        "{{&#8203;code}}\n",
        "{{a b}}\n",
        "\\{toc\\}\n",
        "{{\\{code\\}}}\n",
    ] {
        assert_eq!(tags_only_at_containers(good, &none), Ok(()), "{good:?}");
    }
    let wiki = "{code}\n{toc}\n{code}\n";
    let e = record(vec![rec(ContainerKind::Code, 0..wiki.len() - 1)]);
    assert_eq!(tags_only_at_containers(wiki, &e), Ok(()));
    Ok(())
}

/// Final review I-1 (b): a code body whose `{code` tag is led by whitespace or a control char
/// goes to `{noformat}` (or monospace lines with a `{noformat` tag of that shape too), and the
/// hard check does not trust a forged `{code}` record over such a body.
#[test]
fn lenient_closers_leave_the_code_container() -> TestResult {
    use ContainerKind::Noformat;
    for tag in [
        "{ code}",
        "{\tcode}",
        "{\u{a0}code}",
        "{\u{1}code}",
        "{ CODE }",
        "{\u{85}code:x}",
    ] {
        let md = format!("```\n{tag}\n[~jdoe] {{toc}} !x.png!\n```\n");
        let (out, e) = markdown_to_wiki(&md);
        assert_eq!(kinds(&e), [Noformat], "{md:?} -> {out:?}");
        assert_eq!(hard_check_wiki(&out, &e), Ok(()), "{md:?} -> {out:?}");
        spans_match_record(&out, &e)?;
        let md = format!("```\n{tag} {{ noformat}}\n```\n");
        let (out, e) = markdown_to_wiki(&md);
        assert!(e.code_blocks.is_empty(), "{md:?} -> {out:?}");
        assert_eq!(hard_check_wiki(&out, &e), Ok(()), "{md:?} -> {out:?}");
        spans_match_record(&out, &e)?;
    }
    for wiki in [
        "{code}\n{ code}\n{include:X}\n{code}\n",
        "{code:java}\n{\u{1}code}\n{code}\n",
        "{noformat}\n{\tnoformat}\n{noformat}\n",
    ] {
        let kind = if wiki.starts_with("{code") {
            ContainerKind::Code
        } else {
            ContainerKind::Noformat
        };
        let e = record(vec![rec(kind, 0..wiki.len() - 1)]);
        assert_eq!(
            hard_check_wiki(wiki, &e),
            unrecorded(ConstructKind::Macro, 1),
            "{wiki:?}"
        );
    }
    Ok(())
}
