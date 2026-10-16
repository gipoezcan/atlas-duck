//! Shared by the `md_to_wiki` and `hard_check` tests (and the wiki renderer's properties):
//! the Markdown fuzz strategy and the strict span/record agreement check.
//!
//! Each integration test binary compiles this module on its own and uses only part of it.
#![allow(dead_code)]

use std::ops::Range;

use atlas_duck_convert::wiki::{self, construct_spans};
use atlas_duck_convert::{ConstructKind, ContainerKind, EmittedConstructs, wiki_constructs};
use proptest::prelude::*;

/// The parser's view of `out` agrees with the record: every construct span is a `Macro`
/// whose range is a recorded container, every recorded container is one span, and each
/// recorded range slices a whole container of its kind; and [`tags_only_at_containers`].
pub fn spans_match_record(out: &str, e: &EmittedConstructs) -> Result<(), String> {
    let doc = wiki::parse(out);
    let mut found: Vec<Range<usize>> = Vec::new();
    for (kind, r) in construct_spans(&doc) {
        if kind != ConstructKind::Macro {
            return Err(format!("unrecorded {kind:?} at {r:?} in {out:?}"));
        }
        found.push(r);
    }
    let mut recorded: Vec<Range<usize>> =
        e.code_blocks.iter().map(|c| c.byte_range.clone()).collect();
    found.sort_by_key(|r| (r.start, r.end));
    recorded.sort_by_key(|r| (r.start, r.end));
    if found != recorded {
        return Err(format!(
            "parser spans {found:?} != recorded {recorded:?} in {out:?}"
        ));
    }
    for c in &e.code_blocks {
        let slice = out
            .get(c.byte_range.clone())
            .ok_or_else(|| format!("range {:?} not on char boundaries", c.byte_range))?;
        let ok = match c.kind {
            ContainerKind::Code => slice.starts_with("{code") && slice.ends_with("{code}"),
            ContainerKind::Noformat => {
                slice.starts_with("{noformat}") && slice.ends_with("{noformat}")
            }
            ContainerKind::Quote => slice.starts_with("{quote}") && slice.ends_with("{quote}"),
            // The storage converter's container; never in wiki output.
            ContainerKind::CodeMacro => false,
        };
        if !ok {
            return Err(format!("{:?} range slices {slice:?}", c.kind));
        }
    }
    let inv = wiki_constructs(out);
    if !(inv.mentions.is_empty()
        && inv.includes.is_empty()
        && inv.images.is_empty()
        && inv.attachments.is_empty())
    {
        return Err(format!("unexpected constructs {inv:?} in {out:?}"));
    }
    tags_only_at_containers(out, e)
}

/// The Jira-side bet the hard check cannot see (final review I-1): a lenient macro scan (no
/// escape awareness inside `{{…}}`, names trimmed of whitespace and controls) finds a tag only
/// where the converter wrote a container's opening or closing tag. A raw `{` (not after `\`)
/// followed by optional whitespace or controls, name chars, optional whitespace or controls
/// and `}` or `:` must be a recorded container's opener or closer; recorded code and noformat
/// bodies are opaque.
pub fn tags_only_at_containers(out: &str, e: &EmittedConstructs) -> Result<(), String> {
    let skip = |c: char| c.is_whitespace() || c.is_control();
    let name = |c: char| c.is_alphanumeric() || matches!(c, '-' | '_' | '.');
    for (i, _) in out.match_indices('{') {
        if out.get(..i).is_some_and(|b| b.ends_with('\\')) {
            continue;
        }
        let rest = out.get(i + 1..).unwrap_or("").trim_start_matches(skip);
        let after = rest.trim_start_matches(name);
        if after.len() == rest.len() {
            continue;
        }
        let after = after.trim_start_matches(skip);
        if !(after.starts_with('}') || after.starts_with(':')) {
            continue;
        }
        let allowed = e.code_blocks.iter().any(|c| {
            let close = match c.kind {
                ContainerKind::Code => "{code}".len(),
                ContainerKind::Noformat => "{noformat}".len(),
                ContainerKind::Quote => "{quote}".len(),
                ContainerKind::CodeMacro => return false,
            };
            let opaque = c.kind != ContainerKind::Quote && c.byte_range.contains(&i);
            opaque || i == c.byte_range.start || Some(i) == c.byte_range.end.checked_sub(close)
        });
        if !allowed {
            return Err(format!(
                "tag-shaped `{{` at {i} outside the containers in {out:?}"
            ));
        }
    }
    Ok(())
}

/// Markdown biased to block and inline syntax plus wiki specials (§13 U-24: `{code}`,
/// `{noformat}`, both, `]]>` in fences and inline code), including fragments that only form a
/// construct together (split links, tag variants with whitespace or odd case).
pub fn md_fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(vec![
            "\n",
            "\n\n",
            "\r\n",
            "\r",
            "> ",
            ">> ",
            "- ",
            "* ",
            "1. ",
            "  ",
            "    ",
            "```\n",
            "```rust\n",
            "```java\n",
            "~~~\n",
            "`",
            "``",
            "*",
            "**",
            "_",
            "~~",
            "~",
            "#",
            "## ",
            "---\n",
            "[a](https://x.example/{y}|z)",
            "[~u](https://x.example)",
            "![i](u)",
            "![](u)",
            "[x]()",
            "<https://x.example>",
            "<a@b.example>",
            "[r]\n\n[r]: https://ref\n",
            "<b>",
            "</b>",
            "<div>\n",
            "<!-- c -->",
            "| a | b |\n|---|---|\n| c | d |\n",
            "{code}",
            "{code:java}",
            "{code:language=java|title=x}",
            "{CODE}",
            "{ code}",
            "{noformat}",
            "{ noformat}",
            "{NOFORMAT}",
            "{quote}",
            "{QUOTE}",
            "{toc}",
            "{include:X}",
            "{excerpt-include:X}",
            "{color:red}",
            "{html}",
            "{panel}",
            "[~jdoe]",
            "[^f]",
            "!img.png!",
            "|",
            "\\",
            "\\\\",
            "h1. ",
            "bq. ",
            "----",
            "&#92;",
            "&amp;",
            "&#32;",
            "&#123;",
            "]]>",
            "@jdoe",
            "é",
            "\u{202E}",
            "https://x.example/a_b~c",
            "*https://x.example/a*",
            "~~https://x.example/a~~",
            "https://x.example/a.\\",
            "{ quote}",
            "{\tquote }",
            "[",
            "](u)",
            "](~u)",
            "](^u)",
            "](|~u)",
            "![",
            "<~a@b.example>",
            "\u{2028}",
            "\u{85}",
            "{{",
            "}}",
            "{",
            "quote",
            " quote",
            "Quote",
            "\n>\n> ",
            "\n> ```\n",
            // Final review I-1: inline code shaped like a tag, and closers led by whitespace or
            // controls inside code bodies.
            "`code`",
            "`code:java`",
            "`  noformat `",
            "`toc`",
            "`quote`",
            "`include:X`",
            "{\tcode}",
            "{\u{a0}code}",
            "{\u{1}noformat}",
            "{ noformat }",
            "\n```\n{ code}\n",
        ])
        .prop_map(str::to_owned),
        "[a-z]{1,5}",
        any::<char>().prop_map(String::from),
    ]
}

/// A block quote opener followed by fragments, with quote-continuation and fence fragments
/// mixed in so quote containers, and quotes nesting code, are common draws.
fn quote_markdown() -> impl Strategy<Value = String> {
    let extra = prop::sample::select(vec![
        "{",
        "quote",
        " quote",
        "Quote",
        "\n>\n> ",
        "\n> ```\n",
        "- ",
        "\\{",
        "{quote}",
    ])
    .prop_map(str::to_owned);
    proptest::collection::vec(prop_oneof![md_fragment(), extra.clone(), extra], 0..24)
        .prop_map(|v| format!("> {}", v.concat()))
}

/// Fragments with tag-shaped inline code, fences and whitespace-led code tags mixed in, so
/// monospace before a real code container (final review I-1) is a common draw.
fn code_pair_markdown() -> impl Strategy<Value = String> {
    let extra = prop::sample::select(vec![
        "`code`",
        "`noformat`",
        "`code:java`",
        "\n```\n",
        "{ code}",
        "{\tcode}",
        "\n\n",
    ])
    .prop_map(str::to_owned);
    proptest::collection::vec(prop_oneof![md_fragment(), extra.clone(), extra], 0..24)
        .prop_map(|v| v.concat())
}

pub fn markdown() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => proptest::collection::vec(md_fragment(), 0..40).prop_map(|v| v.concat()),
        2 => quote_markdown(),
        1 => code_pair_markdown(),
    ]
}

/// Confluence storage fragments (M7 Task 2): markup delimiters, `]]>`, `ac:`/`ri:` elements,
/// entities, unbalanced and foreign tags, declarations, non-ASCII text.
pub fn storage_fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(vec![
            "<",
            ">",
            "&",
            ";",
            "/",
            "\"",
            "'",
            "=",
            "]]>",
            "<![CDATA[",
            "]]]]><![CDATA[>",
            "<!--",
            "-->",
            "ac:",
            "ri:",
            "<p>",
            "</p>",
            "<b>",
            "</b>",
            "<br/>",
            "<p title=\"a&amp;b\">",
            "<a href=\"https://x.example/?a&amp;b\">",
            "<a href=\"javascript:x\">",
            "</a>",
            "<ac:structured-macro ac:name=\"code\">",
            "<ac:structured-macro ac:name=\"include\">",
            "<ac:structured-macro ac:name=\"toc\"/>",
            "</ac:structured-macro>",
            "<ac:parameter ac:name=\"language\">",
            "</ac:parameter>",
            "<ac:plain-text-body>",
            "</ac:plain-text-body>",
            "<ac:rich-text-body>",
            "</ac:rich-text-body>",
            "<ac:link>",
            "</ac:link>",
            "<ac:image>",
            "</ac:image>",
            "<ri:user ri:userkey=\"8a7f\"/>",
            "<ri:user ri:username=\"jdoe\"/>",
            "<ri:page ri:space-key=\"DOC\" ri:content-title=\"T\"/>",
            "<ri:attachment ri:filename=\"f.png\"/>",
            "<ri:url ri:value=\"https://x\"/>",
            "<zz:x xmlns:zz=\"u\">",
            "</zz:x>",
            "<at:var/>",
            "<p xmlns=\"u\">",
            "<!DOCTYPE x [<!ENTITY e \"y\">]>",
            "<!ENTITY e \"y\">",
            "<?php x ?>",
            "<?xml version=\"1.0\"?>",
            "&nbsp;",
            "&uuml;",
            "&#252;",
            "&#x20AC;",
            "&#0;",
            "&#xD800;",
            "&foo;",
            "&amp;",
            "&lt;",
            "</ad-storage-root>",
            "<ad-storage-root>",
            "\u{1}",
            "\u{FFFF}",
            "\r\n",
            "\t",
            "é",
            "😀",
            "\u{202E}",
        ])
        .prop_map(str::to_owned),
        "[a-z]{1,5}",
        any::<char>().prop_map(String::from),
    ]
}

/// Well-formed storage (Task 2 review M-10): nested `ac:`, `ri:`, HTML and foreign elements,
/// text with references, CDATA (split ones included) and comments; attribute values with a raw
/// `>`, references and look-alike attribute text. Chains of 58 to 70 `<div>`s reach past
/// `MAX_DEPTH`, so a few draws are refused as too deep.
pub fn storage_well_formed() -> impl Strategy<Value = String> {
    let leaf = prop::sample::select(vec![
        "a",
        " ",
        "\n",
        "Grüße 😀",
        "&amp;",
        "&lt;ri:user/&gt;",
        "&nbsp;",
        "&#252;",
        "&foo;",
        "]]&gt;",
        "<![CDATA[x <ri:user ri:userkey=\"c\"/> <a href=\"h\">]]>",
        "<![CDATA[a]]]]><![CDATA[>b]]>",
        "<!-- <ri:user ri:userkey=\"m\"/> -->",
        "<br/>",
        "<hr/>",
        "<img src=\"i.png\"/>",
        "<IMG src=\"I.png\"/>",
        "<ri:user ri:userkey=\"8a7f\"/>",
        "<ri:user ri:username=\"jdoe\"/>",
        "<ri:user ri:userkey=\"\" ri:username=\"legacy\"/>",
        "<ri:page ri:space-key=\"DOC\" ri:content-title=\"T &amp; U\"/>",
        "<ri:blog-post ri:content-title=\"B\"/>",
        "<ri:attachment ri:filename=\"f.png\"/>",
        "<ri:url ri:value=\"https://x.example/i.png\"/>",
        "<ri:space ri:space-key=\"S\"/>",
        "<ri:content-entity ri:content-id=\"1\"/>",
        "<ri:shortcut ri:key=\"g\"/>",
        "<ac:structured-macro ac:name=\"toc\"/>",
        "<ac:structured-macro ac:name=\"inc&#108;ude\"/>",
        "<ac:structured-macro ac:title=\"a > b\" ac:name=\"excerpt-include\"/>",
        "<ac:structured-macro ac:title=' ac:name=\"include\"' ac:name=\"toc\"/>",
        "<ac:structured-macro zz:x=\"1\" ac:name=\"include\"/>",
        "<ac:emoticon ac:name=\"smile\"/>",
        "<ac:placeholder>p</ac:placeholder>",
        "<ac:parameter ac:name=\"stray\">v</ac:parameter>",
        "<ac:plain-text-link-body><![CDATA[t]]></ac:plain-text-link-body>",
        "<at:var at:name=\"x\"/>",
        "<p zz:a=\"1\"/>",
        "<p xml:lang=\"de\">x</p>",
        "<p xmlns=\"u\"/>",
        "<zz:x xmlns:zz=\"u\"><ri:user ri:userkey=\"z\"/></zz:x>",
    ])
    .prop_map(str::to_owned);
    let wrappers = prop::sample::select(vec![
        ("<p>", "</p>"),
        ("<div>", "</div>"),
        ("<span style=\"color: red;\">", "</span>"),
        ("<a href=\"https://x.example/?a=1&amp;b\">", "</a>"),
        ("<a title=\"x > y\" href=\"https://y.example/\">", "</a>"),
        ("<A href=\"https://z.example/\">", "</A>"),
        ("<a name=\"anchor\">", "</a>"),
        ("<table><tbody><tr><td>", "</td></tr></tbody></table>"),
        (
            "<ac:structured-macro ac:name=\"code\">",
            "</ac:structured-macro>",
        ),
        (
            "<ac:structured-macro ac:name=\"info\">",
            "</ac:structured-macro>",
        ),
        (
            "<ac:structured-macro ac:name=\"include\">",
            "</ac:structured-macro>",
        ),
        ("<ac:parameter ac:name=\"language\">", "</ac:parameter>"),
        ("<ac:plain-text-body>", "</ac:plain-text-body>"),
        ("<ac:rich-text-body>", "</ac:rich-text-body>"),
        ("<ac:link>", "</ac:link>"),
        ("<ac:link ac:anchor=\"top\">", "</ac:link>"),
        ("<ac:link-body>", "</ac:link-body>"),
        ("<ac:image ac:width=\"200\">", "</ac:image>"),
        ("<ac:caption>", "</ac:caption>"),
        (
            "<ac:layout><ac:layout-section><ac:layout-cell>",
            "</ac:layout-cell></ac:layout-section></ac:layout>",
        ),
        (
            "<ac:task-list><ac:task><ac:task-body>",
            "</ac:task-body></ac:task></ac:task-list>",
        ),
        (
            "<ac:inline-comment-marker ac:ref=\"r\">",
            "</ac:inline-comment-marker>",
        ),
        ("<ri:attachment ri:filename=\"g.png\">", "</ri:attachment>"),
        ("<zz:x xmlns:zz=\"u\">", "</zz:x>"),
        ("<p zz:a=\"1\">", "</p>"),
    ]);
    let tree = leaf.prop_recursive(8, 64, 4, move |inner| {
        (wrappers.clone(), proptest::collection::vec(inner, 0..4))
            .prop_map(|((open, close), kids)| format!("{open}{}{close}", kids.concat()))
    });
    let chain = (58..71usize, tree.clone())
        .prop_map(|(n, inner)| format!("{}{inner}{}", "<div>".repeat(n), "</div>".repeat(n)));
    prop_oneof![
        4 => proptest::collection::vec(tree, 0..6).prop_map(|v| v.concat()),
        1 => chain,
    ]
}

/// Arbitrary strings, fragment sequences biased to storage syntax, and well-formed storage.
pub fn storage_input() -> impl Strategy<Value = String> {
    prop_oneof![
        1 => any::<String>(),
        4 => proptest::collection::vec(storage_fragment(), 0..60).prop_map(|v| v.concat()),
        3 => storage_well_formed(),
    ]
}
