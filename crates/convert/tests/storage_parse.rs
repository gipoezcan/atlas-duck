//! The Confluence storage parser, its construct inventory and the user references (plan Task 2,
//! spec §7.6, PD-94, PD-97).

mod common;

use std::collections::BTreeSet;
use std::ops::Range;

use atlas_duck_convert::storage::{self, Element, Node, Ns, StorageDoc, construct_spans};
use atlas_duck_convert::{
    ConstructKind, StorageReject, StorageUsers, WikiConstructs, check_storage_body,
    storage_constructs, storage_user_refs,
};
use proptest::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Every element of `doc` in document order (depth first).
fn elements(nodes: &[Node]) -> Vec<&Element> {
    let mut out = Vec::new();
    for n in nodes {
        if let Node::Element(e) = n {
            out.push(e);
            out.extend(elements(&e.children));
        }
    }
    out
}

/// The text of every `CData` node, in document order.
fn cdata_texts(nodes: &[Node]) -> Vec<String> {
    let mut out = Vec::new();
    for n in nodes {
        match n {
            Node::CData { text, .. } => out.push(text.clone()),
            Node::Element(e) => out.extend(cdata_texts(&e.children)),
            Node::Text(_) => {}
        }
    }
    out
}

fn find<'a>(doc: &'a StorageDoc, qname: &str) -> Option<&'a Element> {
    elements(&doc.nodes)
        .into_iter()
        .find(|e| e.qname() == qname)
}

fn kinds(spans: &[(ConstructKind, Range<usize>)]) -> Vec<ConstructKind> {
    spans.iter().map(|(k, _)| *k).collect()
}

#[test]
fn parses_namespaced_fragment_with_entities() -> TestResult {
    let src = "<p>a&nbsp;b &uuml; &#252; &amp;lt;</p>\
               <ac:structured-macro ac:name=\"toc\" ac:schema-version=\"1\"/>";
    let doc = storage::parse(src);
    assert!(doc.xml_ok);
    let [Node::Element(p), Node::Element(m)] = doc.nodes.as_slice() else {
        return Err(format!("unexpected nodes {:?}", doc.nodes).into());
    };
    assert_eq!(
        (p.ns, p.local.as_str(), p.prefix.as_deref()),
        (Ns::Html, "p", None)
    );
    assert_eq!(p.children, vec![Node::Text("a\u{a0}b ü ü &lt;".to_owned())]);
    assert_eq!(p.byte_range, 0..src.find("<ac:").ok_or("no ac")?);
    assert_eq!((m.ns, m.local.as_str()), (Ns::Ac, "structured-macro"));
    assert_eq!(m.prefix.as_deref(), Some("ac"));
    assert_eq!(
        m.attrs,
        vec![
            ("ac:name".to_owned(), "toc".to_owned()),
            ("ac:schema-version".to_owned(), "1".to_owned())
        ]
    );
    assert_eq!(m.attr("ac:name"), Some("toc"));
    assert_eq!(m.byte_range.end, src.len());
    assert_eq!(check_storage_body(src), Ok(()));
    Ok(())
}

#[test]
fn attribute_values_use_the_text_entity_resolver() -> TestResult {
    let src = "<a href=\"https://x.example/?a=1&amp;b=&uuml;&#x41;&nbsp;\">x</a>\
               <ri:page ri:content-title=\"T&quot;itle&#10;next\nline\"/>";
    let doc = storage::parse(src);
    assert!(doc.xml_ok);
    let a = find(&doc, "a").ok_or("no a")?;
    assert_eq!(a.attr("href"), Some("https://x.example/?a=1&b=üA\u{a0}"));
    let page = find(&doc, "ri:page").ok_or("no ri:page")?;
    // A raw newline is normalised to a space (XML attribute-value normalisation); a
    // character reference to one is kept.
    assert_eq!(page.attr("ri:content-title"), Some("T\"itle\nnext line"));
    Ok(())
}

#[test]
fn macro_inventory_names_and_params() -> TestResult {
    let src = concat!(
        "<ac:structured-macro ac:name=\"toc\"/>",
        "<ac:structured-macro ac:name=\"code\">",
        "<ac:parameter ac:name=\"language\">java</ac:parameter>",
        "<ac:plain-text-body><![CDATA[int x;]]></ac:plain-text-body>",
        "</ac:structured-macro>",
        "<ac:structured-macro ac:name=\"info\">",
        "<ac:parameter ac:name=\"title\">Note</ac:parameter>",
        "<ac:rich-text-body><p>body <ac:structured-macro ac:name=\"status\"/></p></ac:rich-text-body>",
        "</ac:structured-macro>",
        "<ac:structured-macro ac:name=\"include\">",
        "<ac:parameter ac:name=\"\"><ac:link><ri:page ri:space-key=\"DOC\" ri:content-title=\"Target\"/></ac:link></ac:parameter>",
        "</ac:structured-macro>",
        "<ac:structured-macro ac:name=\"excerpt-include\">",
        "<ac:parameter ac:name=\"\"><ac:link><ri:page ri:content-title=\"Local\"/></ac:link></ac:parameter>",
        "</ac:structured-macro>",
    );
    let doc = storage::parse(src);
    assert!(doc.xml_ok);
    let inv = storage_constructs(src);
    assert_eq!(inv.macros, ["toc", "code", "info", "status"]);
    // Includes are listed by their target, never also as a link or a macro.
    assert_eq!(inv.includes, ["DOC:Target", "Local"]);
    assert!(inv.links.is_empty(), "{inv:?}");
    // The parameters are parsed as elements with their name and value.
    let params: Vec<(Option<&str>, String)> = elements(&doc.nodes)
        .into_iter()
        .filter(|e| e.qname() == "ac:parameter")
        .map(|e| (e.attr("ac:name"), text_of(&e.children)))
        .collect();
    assert_eq!(params[0], (Some("language"), "java".to_owned()));
    assert_eq!(params[1], (Some("title"), "Note".to_owned()));
    // The include targets inside the parameters are constructs of their own to the hard check.
    let spans = construct_spans(&doc);
    assert_eq!(
        kinds(&spans),
        [
            ConstructKind::Macro,
            ConstructKind::Macro,
            ConstructKind::Macro,
            ConstructKind::Macro,
            ConstructKind::Include,
            ConstructKind::Link,
            ConstructKind::Include,
            ConstructKind::Link
        ]
    );
    Ok(())
}

#[test]
fn constructs_inside_code_macro_parts_are_spans() -> TestResult {
    // A faulty converter output: the code macro is the recorded construct, what sits in its
    // parameter or its plain-text body is not (review I-1).
    let cases = [
        concat!(
            "<ac:structured-macro ac:name=\"code\"><ac:parameter ac:name=\"language\">",
            "<ri:user ri:userkey=\"x\"/></ac:parameter>",
            "<ac:plain-text-body><![CDATA[..]]></ac:plain-text-body></ac:structured-macro>"
        ),
        concat!(
            "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body>",
            "<ri:user ri:userkey=\"x\"/><![CDATA[..]]></ac:plain-text-body></ac:structured-macro>"
        ),
    ];
    for src in cases {
        let doc = storage::parse(src);
        assert!(doc.xml_ok, "{src}");
        let user = src.find("<ri:user").ok_or("no user")?;
        let user_end = user + "<ri:user ri:userkey=\"x\"/>".len();
        assert_eq!(
            construct_spans(&doc),
            vec![
                (ConstructKind::Macro, 0..src.len()),
                (ConstructKind::Mention, user..user_end)
            ],
            "{src}"
        );
        // The inventory still lists the macro alone: its parameters and body belong to it.
        assert_eq!(storage_constructs(src).macros, ["code"], "{src}");
        assert!(storage_constructs(src).mentions.is_empty(), "{src}");
    }
    Ok(())
}

fn text_of(nodes: &[Node]) -> String {
    nodes
        .iter()
        .map(|n| match n {
            Node::Text(t) => t.clone(),
            Node::CData { text, .. } => text.clone(),
            Node::Element(e) => text_of(&e.children),
        })
        .collect()
}

#[test]
fn user_refs_userkey_and_legacy_username() -> TestResult {
    let src = "<p>Hi <ac:link><ri:user ri:userkey=\"8a7f\"/></ac:link> and \
               <ri:user ri:username=\"jdoe\"/> and <ac:link><ri:user ri:userkey=\"8a7f\"/></ac:link></p>";
    let users = storage_user_refs(src);
    assert_eq!(
        users,
        StorageUsers {
            keys: BTreeSet::from(["8a7f".to_owned()]),
            usernames: BTreeSet::from(["jdoe".to_owned()]),
        }
    );
    let inv = storage_constructs(src);
    assert_eq!(inv.mentions, ["8a7f", "jdoe", "8a7f"]);
    assert!(inv.links.is_empty());
    let spans = construct_spans(&storage::parse(src));
    assert_eq!(
        kinds(&spans),
        [
            ConstructKind::Mention,
            ConstructKind::Mention,
            ConstructKind::Mention
        ]
    );
    Ok(())
}

#[test]
fn cdata_plain_text_body_is_opaque() -> TestResult {
    let src = concat!(
        "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body>",
        "<![CDATA[a <ri:user ri:userkey=\"x\"/> <ac:structured-macro ac:name=\"include\"/> b]]]]>",
        "<![CDATA[>c]]></ac:plain-text-body></ac:structured-macro>"
    );
    let doc = storage::parse(src);
    assert!(doc.xml_ok);
    assert_eq!(
        cdata_texts(&doc.nodes).concat(),
        "a <ri:user ri:userkey=\"x\"/> <ac:structured-macro ac:name=\"include\"/> b]]>c"
    );
    let inv = storage_constructs(src);
    assert_eq!(inv.macros, ["code"]);
    assert!(
        inv.mentions.is_empty() && inv.includes.is_empty(),
        "{inv:?}"
    );
    assert!(storage_user_refs(src).keys.is_empty());
    assert_eq!(
        construct_spans(&doc),
        vec![(ConstructKind::Macro, 0..src.len())]
    );
    Ok(())
}

#[test]
fn links_images_attachments_inventory() -> TestResult {
    let src = concat!(
        "<p><ac:link><ri:page ri:space-key=\"DOC\" ri:content-title=\"Home\"/></ac:link> ",
        "<a href=\"https://x.example/\">x</a> ",
        "<ac:image ac:width=\"200\"><ri:attachment ri:filename=\"pic.png\"/></ac:image> ",
        "<ac:image><ri:url ri:value=\"https://x.example/i.png\"/></ac:image> ",
        "<ac:link><ri:attachment ri:filename=\"spec.pdf\"/><ac:plain-text-link-body><![CDATA[the spec]]></ac:plain-text-link-body></ac:link> ",
        "<ac:link><ri:page ri:content-title=\"Same space\"/></ac:link></p>",
    );
    let inv = storage_constructs(src);
    assert_eq!(inv.links, ["DOC:Home", "https://x.example/", "Same space"]);
    assert_eq!(inv.images, ["pic.png", "https://x.example/i.png"]);
    assert_eq!(inv.attachments, ["spec.pdf"]);
    assert!(inv.macros.is_empty() && inv.mentions.is_empty() && inv.includes.is_empty());
    let spans = construct_spans(&storage::parse(src));
    assert_eq!(
        kinds(&spans),
        [
            ConstructKind::Link,
            ConstructKind::Image,
            ConstructKind::Image,
            ConstructKind::Attachment,
            ConstructKind::Link
        ]
    );
    Ok(())
}

#[test]
fn construct_spans_follow_the_converter_grammar() -> TestResult {
    // What the Markdown converter writes yields no span at all.
    let ok = "<h1>T</h1><p><em>a</em> <strong>b</strong> <s>c</s> <code>d</code><br/>\
              <a href=\"https://x\">h</a> <a href=\"HTTP://x\">h</a> <a href=\"mailto:a@b\">m</a></p>\
              <ul><li>x</li></ul><ol><li>y</li></ol><blockquote><p>q</p></blockquote><hr/>\
              <table><tbody><tr><th>h</th><td>d</td></tr></tbody></table>";
    let doc = storage::parse(ok);
    assert!(doc.xml_ok);
    assert_eq!(construct_spans(&doc), vec![]);
    // Everything else is a construct, outermost only.
    let cases: [(&str, ConstructKind); 12] = [
        ("<img src=\"https://x\"/>", ConstructKind::Markup),
        ("<script>x</script>", ConstructKind::Markup),
        (
            "<div><ri:user ri:userkey=\"k\"/></div>",
            ConstructKind::Markup,
        ),
        ("<p style=\"x\">a</p>", ConstructKind::Markup),
        ("<a href=\"javascript:alert(1)\">x</a>", ConstructKind::Link),
        ("<a href=\" https://x\">x</a>", ConstructKind::Link),
        ("<a>x</a>", ConstructKind::Link),
        ("<ri:space ri:space-key=\"S\"/>", ConstructKind::Link),
        (
            "<ri:content-entity ri:content-id=\"1\"/>",
            ConstructKind::Link,
        ),
        ("<ri:url ri:value=\"https://x\"/>", ConstructKind::Macro),
        ("<ac:emoticon ac:name=\"smile\"/>", ConstructKind::Macro),
        (
            "<ac:link><ri:user ri:userkey=\"k\"/></ac:link>",
            ConstructKind::Mention,
        ),
    ];
    for (src, kind) in cases {
        let doc = storage::parse(src);
        assert!(doc.xml_ok, "{src}");
        assert_eq!(construct_spans(&doc), vec![(kind, 0..src.len())], "{src}");
    }
    Ok(())
}

#[test]
fn unknown_entity_kept_literal() -> TestResult {
    let src = "<p title=\"x&foo;y\">a &foo; b &Uuml;</p>";
    let doc = storage::parse(src);
    assert!(doc.xml_ok);
    let p = find(&doc, "p").ok_or("no p")?;
    assert_eq!(p.children, vec![Node::Text("a &foo; b Ü".to_owned())]);
    assert_eq!(p.attr("title"), Some("x&foo;y"));
    assert_eq!(check_storage_body(src), Ok(()));
    Ok(())
}

#[test]
fn invalid_xml_reports_fallback() -> TestResult {
    let src = "<p>a<b>c</p>";
    let doc = storage::parse(src);
    assert!(!doc.xml_ok);
    // What was read up to the error is kept.
    let p = find(&doc, "p").ok_or("no p")?;
    assert_eq!(p.children.first(), Some(&Node::Text("a".to_owned())));
    assert_eq!(check_storage_body(src), Err(StorageReject::NotWellFormed));
    for bad in [
        "<p>a & b</p>",
        "<p>a &#0; b</p>",
        "<p>a &#1; b</p>",
        "<p>a \u{1} b</p>",
        "<p>a \u{FFFF} b</p>",
        "<p>a ]]> b</p>",
        "<p title=\"a<b\">x</p>",
        "<p title=x>x</p>",
        "<p a=\"1\" a=\"2\">x</p>",
        "<p>unclosed",
        "</p>",
        "< p>x</p>",
        "<1p>x</1p>",
        "<a:b:c/>",
        "<!-- a -- b -->",
        "<p>&a b;</p>",
    ] {
        assert!(!storage::parse(bad).xml_ok, "{bad:?}");
        assert_eq!(
            check_storage_body(bad),
            Err(StorageReject::NotWellFormed),
            "{bad:?}"
        );
    }
    Ok(())
}

#[test]
fn the_wrapper_cannot_be_closed_from_inside() {
    for bad in [
        "</ad-storage-root><p>x</p><ad-storage-root>",
        "<p>x</p></ad-storage-root>",
        "</ad-storage-root>",
    ] {
        let doc = storage::parse(bad);
        assert!(!doc.xml_ok, "{bad:?}");
        assert_eq!(
            check_storage_body(bad),
            Err(StorageReject::NotWellFormed),
            "{bad:?}"
        );
    }
}

#[test]
fn doctype_entity_pi_fail_the_parse() {
    let cases = [
        (
            "<!DOCTYPE x [<!ENTITY e \"<ri:user ri:userkey='x'/>\">]><p>&e;</p>",
            StorageReject::Doctype,
        ),
        ("<p>a</p><!doctype html><p>b</p>", StorageReject::Doctype),
        ("<!ENTITY e \"x\"><p>&e;</p>", StorageReject::EntityDecl),
        ("<p>a</p><!ENTITY e \"x\">", StorageReject::EntityDecl),
        ("<p>a<?php x ?></p>", StorageReject::ProcessingInstruction),
        (
            "<?xml version=\"1.0\"?><p>a</p>",
            StorageReject::ProcessingInstruction,
        ),
    ];
    for (src, reason) in cases {
        let doc = storage::parse(src);
        assert!(!doc.xml_ok, "{src:?}");
        assert_eq!(check_storage_body(src), Err(reason), "{src:?}");
    }
    // Inside a CDATA body the same text is code, not markup.
    let code = "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body><![CDATA[\
                <!DOCTYPE html><!ENTITY e \"x\"><?php x ?>]]></ac:plain-text-body>\
                </ac:structured-macro>";
    assert!(storage::parse(code).xml_ok);
    assert_eq!(check_storage_body(code), Ok(()));
}

#[test]
fn check_storage_body_names_the_first_reason_in_priority_order() {
    let cases = [
        // A PI before a DOCTYPE: the DOCTYPE still wins.
        ("<?x y?><!DOCTYPE z>", StorageReject::Doctype),
        // A namespace declaration and an unknown prefix together: the declaration.
        ("<zz:x xmlns:zz=\"u\"/>", StorageReject::NamespaceDecl),
        // An unknown prefix after the depth limit is still seen.
        (
            &format!("{}<zz:x/>{}", "<div>".repeat(70), "</div>".repeat(70)),
            StorageReject::UnknownPrefix,
        ),
        // A namespace declaration before a syntax error.
        ("<p xmlns=\"u\">a<b>c</p>", StorageReject::NamespaceDecl),
    ];
    for (src, reason) in cases {
        assert_eq!(check_storage_body(src), Err(reason), "{src:?}");
    }
    assert_eq!(StorageReject::NotWellFormed.as_str(), "not_well_formed");
    assert_eq!(StorageReject::Doctype.as_str(), "doctype");
    assert_eq!(StorageReject::EntityDecl.as_str(), "entity_decl");
    assert_eq!(
        StorageReject::ProcessingInstruction.as_str(),
        "processing_instruction"
    );
    assert_eq!(StorageReject::NamespaceDecl.as_str(), "namespace_decl");
    assert_eq!(StorageReject::UnknownPrefix.as_str(), "unknown_prefix");
    assert_eq!(StorageReject::TooDeep.as_str(), "too_deep");
}

#[test]
fn depth_is_bounded_at_64() {
    let at = |n: usize| format!("{}x{}", "<div>".repeat(n), "</div>".repeat(n));
    let ok = at(64);
    assert!(storage::parse(&ok).xml_ok);
    assert_eq!(check_storage_body(&ok), Ok(()));
    let deep = at(65);
    assert!(!storage::parse(&deep).xml_ok);
    assert_eq!(check_storage_body(&deep), Err(StorageReject::TooDeep));
    let empty_too_deep = format!("{}<br/>{}", "<div>".repeat(64), "</div>".repeat(64));
    assert_eq!(
        check_storage_body(&empty_too_deep),
        Err(StorageReject::TooDeep)
    );
    // Far deeper input stays cheap and bounded.
    let very = at(100_000);
    assert_eq!(check_storage_body(&very), Err(StorageReject::TooDeep));
}

#[test]
fn namespace_alias_is_markup() -> TestResult {
    let cases = [
        (
            "<zz:structured-macro xmlns:zz=\"http://atlassian.com/content\" zz:name=\"include\"/>",
            "zz:structured-macro",
            StorageReject::NamespaceDecl,
        ),
        (
            "<ac:structured-macro xmlns:ac=\"urn:x\" ac:name=\"toc\"/>",
            "ac:structured-macro",
            StorageReject::NamespaceDecl,
        ),
        (
            "<p xmlns=\"http://www.w3.org/1999/xhtml\">a</p>",
            "p",
            StorageReject::NamespaceDecl,
        ),
        (
            "<at:var at:name=\"x\"/>",
            "at:var",
            StorageReject::UnknownPrefix,
        ),
        (
            "<ac:structured-macro zz:name=\"include\" ac:name=\"toc\"/>",
            "ac:structured-macro",
            StorageReject::UnknownPrefix,
        ),
    ];
    for (src, qname, reason) in cases {
        let doc = storage::parse(src);
        // Not a parse failure: the element is read, classified `Other` and counted as markup.
        assert!(doc.xml_ok, "{src}");
        let [Node::Element(e)] = doc.nodes.as_slice() else {
            return Err(format!("unexpected nodes {:?}", doc.nodes).into());
        };
        assert_eq!(e.ns, Ns::Other, "{src}");
        assert_eq!(
            construct_spans(&doc),
            vec![(ConstructKind::Markup, 0..src.len())]
        );
        let inv = storage_constructs(src);
        assert_eq!(inv.macros, [qname], "{src}");
        assert_eq!(check_storage_body(src), Err(reason), "{src}");
    }
    // The subtree of a foreign element is foreign too, whatever its own prefix.
    let src = "<zz:x xmlns:zz=\"u\"><ac:structured-macro ac:name=\"include\"/><ri:user ri:userkey=\"k\"/></zz:x>";
    let doc = storage::parse(src);
    assert!(elements(&doc.nodes).iter().all(|e| e.ns == Ns::Other));
    assert_eq!(
        construct_spans(&doc),
        vec![(ConstructKind::Markup, 0..src.len())]
    );
    assert!(storage_user_refs(src).keys.is_empty());
    Ok(())
}

#[test]
fn partial_parse_lexical_inventory_over_reports() {
    let src = concat!(
        "<p>a<b>c</p>",
        "<ac:structured-macro ac:name=\"toc\"/>",
        "<ac:structured-macro ac:name=\"include\"><ac:parameter ac:name=\"\">",
        "<ac:link><ri:page ri:content-title=\"T\"/></ac:link></ac:parameter></ac:structured-macro>",
        "<ri:user ri:userkey=\"k\"/>",
        "<ac:image><ri:attachment ri:filename=\"f.png\"/></ac:image>",
        "<zz:macro xmlns:zz=\"u\"/>",
        "<AC:Emoticon/>",
    );
    assert!(!storage::parse(src).xml_ok);
    let inv = storage_constructs(src);
    assert!(inv.macros.iter().any(|m| m == "toc"), "{inv:?}");
    assert!(inv.includes.iter().any(|m| m == "include"), "{inv:?}");
    assert!(inv.mentions.iter().any(|m| m == "k"), "{inv:?}");
    assert!(inv.attachments.iter().any(|m| m == "f.png"), "{inv:?}");
    assert!(!inv.images.is_empty(), "{inv:?}");
    assert!(!inv.links.is_empty(), "{inv:?}");
    assert!(inv.macros.iter().any(|m| m == "zz:macro"), "{inv:?}");
    assert!(
        inv.macros
            .iter()
            .any(|m| m.eq_ignore_ascii_case("ac:emoticon")),
        "{inv:?}"
    );
    // A DOCTYPE with an entity is not `xml_ok` either: the lexical scan lists the user it hides.
    let dtd = "<!DOCTYPE x [<!ENTITY e \"<ri:user ri:userkey='x'/>\">]><p>&e;</p>";
    assert!(storage_constructs(dtd).mentions.iter().any(|m| m == "x"));
}

/// The inventory the lexical fallback gives for `src`: a trailing processing instruction makes
/// the parse fail, and is no start tag itself, so the scan sees exactly the tags of `src`.
fn lexical(src: &str) -> Result<WikiConstructs, String> {
    let broken = format!("{src}<?x y?>");
    if storage::parse(&broken).xml_ok {
        return Err(format!("{broken:?} parsed"));
    }
    Ok(storage_constructs(&broken))
}

fn list_lens(inv: &WikiConstructs) -> [(&'static str, usize); 6] {
    [
        ("macros", inv.macros.len()),
        ("includes", inv.includes.len()),
        ("mentions", inv.mentions.len()),
        ("links", inv.links.len()),
        ("images", inv.images.len()),
        ("attachments", inv.attachments.len()),
    ]
}

/// Each list of the lexical inventory of `src` is at least as long as the tree's (PD-94 (3)).
fn lexical_covers_tree(src: &str) -> Result<(), String> {
    let tree = storage_constructs(src);
    let lex = lexical(src)?;
    for ((name, t), (_, l)) in list_lens(&tree).into_iter().zip(list_lens(&lex)) {
        if l < t {
            return Err(format!(
                "lexical {name} {lex:?} shorter than tree {tree:?} for {src:?}"
            ));
        }
    }
    Ok(())
}

#[test]
fn lexical_inventory_follows_the_tree_categories() -> TestResult {
    // Review I-2: the cases where the scan used to list less than the tree, or elsewhere.
    type Expect = fn(&WikiConstructs) -> bool;
    let cases: [(&str, Expect); 9] = [
        ("<p><a href=\"https://x\">x</a></p>", |i| {
            i.links == ["https://x"]
        }),
        ("<A href=\"https://x\">x</A>", |i| i.links == ["https://x"]),
        ("<img src=\"i.png\"/><IMG src=\"j.png\"/>", |i| {
            i.images == ["i.png", "j.png"]
        }),
        ("<ri:url ri:value=\"u\"/>", |i| {
            i.links == ["u"] && i.images.is_empty()
        }),
        ("<ac:structured-macro ac:name=\"inc&#108;ude\"/>", |i| {
            i.includes == ["include"] && i.macros.is_empty()
        }),
        ("<p zz:a=\"1\">x</p>", |i| i.macros == ["p"]),
        (
            "<ac:structured-macro zz:a=\"1\" ac:name=\"include\"/>",
            |i| i.macros.iter().any(|m| m == "ac:structured-macro"),
        ),
        (
            "<ac:structured-macro ac:title=\" ac:name='toc'\" ac:name=\"include\"/>",
            |i| i.includes == ["include"] && i.macros.is_empty(),
        ),
        (
            "<ac:parameter ac:name=\"x\">v</ac:parameter><ac:plain-text-body/><ac:plain-text-link-body/>",
            |i| i.macros.is_empty(),
        ),
    ];
    for (src, expect) in cases {
        assert!(storage::parse(src).xml_ok, "{src}");
        lexical_covers_tree(src)?;
        let lex = lexical(src)?;
        assert!(expect(&lex), "{src}: {lex:?}");
    }
    // A stray parameter or plain-text body is structure in the tree too.
    let stray = "<ac:parameter ac:name=\"x\"><ac:emoticon ac:name=\"smile\"/></ac:parameter>";
    assert_eq!(storage_constructs(stray).macros, ["emoticon"]);
    // A raw `>` in an attribute value does not end the tag for the scan.
    let gt = "<ac:structured-macro ac:title=\"a > b\" ac:name=\"excerpt-include\"/>";
    assert_eq!(lexical(gt)?.includes, ["excerpt-include"]);
    Ok(())
}

#[test]
fn xml_prefix_on_attributes_is_known() -> TestResult {
    // `xml` is bound by the Namespaces spec and cannot be rebound (review M-1).
    let src = "<p xml:lang=\"de\" xml:space=\"preserve\">x</p>";
    let doc = storage::parse(src);
    assert!(doc.xml_ok);
    let [Node::Element(p)] = doc.nodes.as_slice() else {
        return Err(format!("unexpected nodes {:?}", doc.nodes).into());
    };
    assert_eq!(p.ns, Ns::Html);
    assert_eq!(check_storage_body(src), Ok(()));
    // Still not the converter's output: an attribute makes the element markup.
    assert_eq!(
        construct_spans(&doc),
        vec![(ConstructKind::Markup, 0..src.len())]
    );
    assert!(storage_constructs(src).macros.is_empty());
    // As an element prefix it stays foreign.
    assert_eq!(
        check_storage_body("<xml:x/>"),
        Err(StorageReject::UnknownPrefix)
    );
    Ok(())
}

#[test]
fn empty_user_refs_are_skipped() {
    let src = "<ri:user ri:userkey=\"\" ri:username=\"legacy\"/><ri:user ri:userkey=\"\"/>\
               <ri:user ri:username=\"\"/><ri:user ri:userkey=\"k\"/>";
    assert_eq!(
        storage_user_refs(src),
        StorageUsers {
            keys: BTreeSet::from(["k".to_owned()]),
            usernames: BTreeSet::from(["legacy".to_owned()]),
        }
    );
    // Every mention is still listed, by its non-empty key, else its username.
    assert_eq!(storage_constructs(src).mentions, ["legacy", "", "", "k"]);
}

#[test]
fn image_children_and_html_case_are_inventoried() {
    let src = concat!(
        "<ac:image><ri:attachment ri:filename=\"a.png\"><ri:page ri:content-title=\"P\"/></ri:attachment>",
        "<ac:caption><p>see <a href=\"https://x\">x</a> <ac:link><ri:page ri:content-title=\"Q\"/></ac:link></p></ac:caption>",
        "</ac:image>",
        "<IMG src=\"b.png\"/><A href=\"https://y\">y</A><Img/>",
    );
    assert!(storage::parse(src).xml_ok);
    let inv = storage_constructs(src);
    assert_eq!(inv.images, ["a.png", "b.png", ""]);
    // The image's own resource is its label; the caption's content is listed.
    assert_eq!(inv.links, ["https://x", "Q", "https://y"]);
    assert_eq!(inv.macros, ["caption"]);
    assert!(inv.attachments.is_empty());
}

#[test]
fn check_storage_body_accepts_confluence_storage() {
    let page = concat!(
        "<h1>Release notes</h1>",
        "<ac:structured-macro ac:name=\"toc\" ac:schema-version=\"1\" ac:macro-id=\"0b1c\">",
        "<ac:parameter ac:name=\"maxLevel\">2</ac:parameter></ac:structured-macro>",
        "<p>Owner: <ac:link><ri:user ri:userkey=\"8a7f80b2\"/></ac:link>, see ",
        "<ac:link><ri:page ri:space-key=\"DOC\" ri:content-title=\"Home &amp; more\"/>",
        "<ac:plain-text-link-body><![CDATA[home]]></ac:plain-text-link-body></ac:link>.</p>",
        "<p>Gr&uuml;&szlig;e&nbsp;&mdash; &#8364;5 &#x20AC;</p>",
        "<ac:image ac:height=\"250\"><ri:attachment ri:filename=\"diagram.png\">",
        "<ri:page ri:content-title=\"Other\"/></ri:attachment></ac:image>",
        "<ac:structured-macro ac:name=\"code\" ac:schema-version=\"1\">",
        "<ac:parameter ac:name=\"language\">xml</ac:parameter>",
        "<ac:plain-text-body><![CDATA[<a href=\"x\">&amp;</a> ]]]]><![CDATA[>]]></ac:plain-text-body>",
        "</ac:structured-macro>",
        "<ac:task-list><ac:task><ac:task-id>1</ac:task-id><ac:task-status>incomplete</ac:task-status>",
        "<ac:task-body>do it</ac:task-body></ac:task></ac:task-list>",
        "<ac:layout><ac:layout-section ac:type=\"two_equal\"><ac:layout-cell><p>l</p></ac:layout-cell>",
        "<ac:layout-cell><p>r</p></ac:layout-cell></ac:layout-section></ac:layout>",
        "<table><tbody><tr><th>a</th></tr><tr><td><span style=\"color: red;\">b</span></td></tr></tbody></table>",
        "<!-- a comment -->",
    );
    assert!(storage::parse(page).xml_ok);
    assert_eq!(check_storage_body(page), Ok(()));
    let inv = storage_constructs(page);
    assert_eq!(inv.macros, ["toc", "code"]);
    assert_eq!(inv.mentions, ["8a7f80b2"]);
    assert_eq!(inv.links, ["DOC:Home & more"]);
    assert_eq!(inv.images, ["diagram.png"]);
}

/// Checks every element and CDATA range of `nodes` against `src`.
fn check_ranges(src: &str, nodes: &[Node], xml_ok: bool) -> Result<(), String> {
    for n in nodes {
        match n {
            Node::Element(e) => {
                let slice = src
                    .get(e.byte_range.clone())
                    .ok_or_else(|| format!("{:?} off char boundaries in {src:?}", e.byte_range))?;
                let open = format!("<{}", e.qname());
                if !slice.starts_with(&open) {
                    return Err(format!("{slice:?} does not start with {open:?}"));
                }
                // In a complete parse the slice is exactly the element: it parses alone as one
                // element of the same name (an inner `</p>` would leave the outer `<p>` open).
                if xml_ok {
                    let alone = storage::parse(slice);
                    let one = matches!(alone.nodes.as_slice(),
                        [Node::Element(x)] if x.qname() == e.qname() && x.byte_range == (0..slice.len()));
                    if !(alone.xml_ok && one) {
                        return Err(format!("{slice:?} is not one whole {}", e.qname()));
                    }
                }
                check_ranges(src, &e.children, xml_ok)?;
                for c in &e.children {
                    let Node::Element(c) = c else { continue };
                    if c.byte_range.start < e.byte_range.start
                        || c.byte_range.end > e.byte_range.end
                    {
                        return Err(format!(
                            "child {:?} outside {:?}",
                            c.byte_range, e.byte_range
                        ));
                    }
                }
            }
            Node::CData { byte_range, .. } => {
                let slice = src
                    .get(byte_range.clone())
                    .ok_or_else(|| format!("{byte_range:?} off char boundaries in {src:?}"))?;
                if !(slice.starts_with("<![CDATA[") && slice.ends_with("]]>")) {
                    return Err(format!("CDATA range slices {slice:?}"));
                }
            }
            Node::Text(_) => {}
        }
    }
    Ok(())
}

#[test]
fn ranges_slice_the_original_input() -> TestResult {
    let src = concat!(
        "Grüße 😀 <p>é<ac:structured-macro ac:name=\"code\"><ac:plain-text-body>",
        "<![CDATA[ü]]]]><![CDATA[>😀]]></ac:plain-text-body></ac:structured-macro>",
        "<ac:link><ri:user ri:userkey=\"ü\"/></ac:link></p>\n<br/>ß"
    );
    let doc = storage::parse(src);
    assert!(doc.xml_ok);
    check_ranges(src, &doc.nodes, true)?;
    let all = elements(&doc.nodes);
    let user = all
        .iter()
        .find(|e| e.qname() == "ri:user")
        .ok_or("no user")?;
    assert_eq!(
        src.get(user.byte_range.clone()),
        Some("<ri:user ri:userkey=\"ü\"/>")
    );
    let p = all.iter().find(|e| e.qname() == "p").ok_or("no p")?;
    assert_eq!(
        src.get(p.byte_range.clone()).map(|s| s.ends_with("</p>")),
        Some(true)
    );
    assert_eq!(cdata_texts(&doc.nodes), ["ü]]", ">😀"]);
    for (_, r) in construct_spans(&doc) {
        assert!(src.get(r).is_some());
    }
    // Nested elements of one name: the outer range ends at its own end tag.
    let nested = "<div>a<div>b</div>c<p><p/></p></div>";
    let doc = storage::parse(nested);
    check_ranges(nested, &doc.nodes, true)?;
    let [Node::Element(outer)] = doc.nodes.as_slice() else {
        return Err(format!("unexpected nodes {:?}", doc.nodes).into());
    };
    assert_eq!(outer.byte_range, 0..nested.len());
    let inner: Vec<Range<usize>> = elements(&outer.children)
        .iter()
        .map(|e| e.byte_range.clone())
        .collect();
    assert_eq!(inner, [6..18, 19..30, 22..26]);
    // A failed parse still reports valid ranges for what it read.
    let bad = "<p>ü<ac:link>😀<ri:user ri:userkey=\"k\"/>";
    let doc = storage::parse(bad);
    assert!(!doc.xml_ok);
    check_ranges(bad, &doc.nodes, false)?;
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn parse_never_panics_on_garbage(src in common::storage_input()) {
        let doc = storage::parse(&src);
        prop_assert!(check_ranges(&src, &doc.nodes, doc.xml_ok).is_ok(),
            "{:?}", check_ranges(&src, &doc.nodes, doc.xml_ok));
        for (_, r) in construct_spans(&doc) {
            prop_assert!(src.get(r).is_some());
        }
        let checked = check_storage_body(&src);
        prop_assert_eq!(checked.is_ok(), doc.xml_ok && construct_free_of_other(&doc));
        let _ = storage_constructs(&src);
        let _ = storage_user_refs(&src);
        // Deterministic.
        prop_assert_eq!(storage::parse(&src), doc);
    }

    /// PD-94 (3): on a well-formed body the lexical fallback lists at least as much as the tree,
    /// in every list (review I-2).
    #[test]
    fn lexical_inventory_never_under_reports(src in common::storage_well_formed()) {
        if !storage::parse(&src).xml_ok {
            // Too deep: nothing to compare against.
            return Ok(());
        }
        let checked = lexical_covers_tree(&src);
        prop_assert!(checked.is_ok(), "{:?}", checked);
    }
}

/// No element of `doc` is `Ns::Other` (with `xml_ok`, exactly when `check_storage_body` is
/// `Ok`).
fn construct_free_of_other(doc: &StorageDoc) -> bool {
    elements(&doc.nodes).iter().all(|e| e.ns != Ns::Other)
}
