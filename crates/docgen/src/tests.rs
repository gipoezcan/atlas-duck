#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::frontmatter::{self, FrontMatter, Mode};
use crate::render::{Ctx, Set, render_body, strip_modes};
use crate::search::json_str;
use crate::site::{self, Files, SourcePage, Sources};

fn guide_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/user-guide")
}

fn ctx(set: Set) -> Ctx<'static> {
    Ctx {
        set,
        lang: "en",
        page: "approvals",
    }
}

fn page(id: &str, mode: Mode, order: i64, body: &str) -> SourcePage {
    SourcePage {
        fm: FrontMatter {
            id: id.into(),
            title: format!("Title {id}"),
            mode,
            order,
        },
        body: body.into(),
    }
}

fn fixture() -> Sources {
    let mut langs = BTreeMap::new();
    for lang in ["en", "de"] {
        langs.insert(
            lang.to_string(),
            vec![
                page("index", Mode::Both, 1, "## Start {#start}\n\nHello.\n"),
                page("desk", Mode::Desktop, 2, "## Desk {#desk}\n\nonly desktop\n"),
                page("srv", Mode::Server, 3, "## Srv {#srv}\n\nonly server\n"),
                page(
                    "mixed",
                    Mode::Both,
                    4,
                    "## Both {#both}\n\n::: desktop\n\n## D {#d}\n\n:::\n\n::: server\n\n## S {#s}\n\n:::\n",
                ),
            ],
        );
    }
    Sources {
        langs,
        css: "body{}\n".into(),
        js: "// js\n".into(),
    }
}

fn names(files: &Files) -> Vec<&str> {
    files.keys().map(String::as_str).collect()
}

fn text(files: &Files, name: &str) -> String {
    String::from_utf8(
        files
            .get(name)
            .unwrap_or_else(|| panic!("no {name}"))
            .clone(),
    )
    .unwrap()
}

#[test]
fn front_matter_parses_and_rejects_unknown_keys() {
    let (fm, body) = frontmatter::parse(
        "---\nid: a-b\ntitle: Setup: first steps\nmode: both\norder: 30\n---\n\n## X {#x}\n",
    )
    .unwrap();
    assert_eq!(fm.id, "a-b");
    assert_eq!(fm.title, "Setup: first steps");
    assert_eq!(fm.mode, Mode::Both);
    assert_eq!(fm.order, 30);
    assert_eq!(body, "\n## X {#x}\n");

    let err = frontmatter::parse("---\nid: a\ntitle: A\nmode: both\norder: 1\nextra: x\n---\n")
        .unwrap_err();
    assert!(err.contains("extra"), "{err}");
    for bad in [
        "no front matter\n",
        "---\nid: a\ntitle: A\nmode: both\n---\n",
        "---\nid: a\ntitle: A\nmode: neither\norder: 1\n---\n",
        "---\nid: a\ntitle: A\nmode: both\norder: x\n---\n",
        "---\nid: a\nid: b\ntitle: A\nmode: both\norder: 1\n---\n",
        "---\nid: A_b\ntitle: A\nmode: both\norder: 1\n---\n",
        "---\nid: a\ntitle: A\nmode: both\norder: 1\n",
        "---\nid: a\ntitle:\nmode: both\norder: 1\n---\n",
    ] {
        assert!(frontmatter::parse(bad).is_err(), "accepted {bad:?}");
    }
}

#[test]
fn mode_blocks_are_stripped_per_set() {
    let md = "intro\n\n::: desktop\nD text\n:::\n\n::: server\nS text\n:::\n\nend\n";
    let d = strip_modes(md, Mode::Both, Set::Desktop).unwrap();
    assert!(
        d.contains("D text") && !d.contains("S text") && !d.contains(":::"),
        "{d}"
    );
    let s = strip_modes(md, Mode::Both, Set::Server).unwrap();
    assert!(
        s.contains("S text") && !s.contains("D text") && !s.contains(":::"),
        "{s}"
    );
    assert!(d.contains("intro") && d.contains("end"));

    // A fence is literal text, a block marker inside it is not a marker.
    let fenced = "```\n::: server\n```\n";
    assert_eq!(
        strip_modes(fenced, Mode::Both, Set::Desktop).unwrap(),
        fenced
    );

    for (bad, mode) in [
        ("::: desktop\nx\n", Mode::Both),
        (":::\n", Mode::Both),
        ("::: other\nx\n:::\n", Mode::Both),
        ("::: desktop\n::: server\n:::\n:::\n", Mode::Both),
        ("::: desktop\nx\n:::\n", Mode::Desktop),
    ] {
        assert!(
            strip_modes(bad, mode, Set::Desktop).is_err(),
            "accepted {bad:?}"
        );
    }
}

#[test]
fn heading_attributes_become_ids() {
    let r = render_body(
        "## Die Warteschlange {#queue}\n\ntext\n\n### Sub {#sub-1}\n",
        &ctx(Set::Desktop),
    )
    .unwrap();
    assert!(
        r.html.contains("<h2 id=\"queue\">Die Warteschlange</h2>"),
        "{}",
        r.html
    );
    assert!(r.html.contains("<h3 id=\"sub-1\">Sub</h3>"), "{}", r.html);
    let ids: Vec<&str> = r.headings.iter().map(|h| h.id.as_str()).collect();
    assert_eq!(ids, ["queue", "sub-1"]);

    for bad in [
        "## No anchor\n",
        "# Title {#title}\n",
        "## A {#same}\n\n## B {#same}\n",
        "## A {#Upper}\n",
        "## A {#under_score}\n",
        "## A {.cls #a}\n",
    ] {
        assert!(
            render_body(bad, &ctx(Set::Desktop)).is_err(),
            "accepted {bad:?}"
        );
    }
}

#[test]
fn raw_html_is_an_error() {
    for bad in [
        "<div>x</div>\n",
        "a <b>x</b> b\n",
        "<script>alert(1)</script>\n",
        "text\n\n<!-- comment -->\n",
        "![alt](x.png)\n",
    ] {
        assert!(
            render_body(bad, &ctx(Set::Desktop)).is_err(),
            "accepted {bad:?}"
        );
    }
}

#[test]
fn internal_link_resolves_to_relative_href() {
    let md = "[a](settings#language) [b](index) [c](#here) [d](https://example.org/x?a=1&b=2)\n";
    let d = render_body(md, &ctx(Set::Desktop)).unwrap();
    assert!(
        d.html.contains("<a href=\"settings.html#language\">a</a>"),
        "{}",
        d.html
    );
    assert!(
        d.html.contains("<a href=\"index.html\">b</a>"),
        "{}",
        d.html
    );
    assert!(d.html.contains("<a href=\"#here\">c</a>"), "{}", d.html);
    assert!(
        d.html
            .contains("<a href=\"https://example.org/x?a=1&amp;b=2\" rel=\"noreferrer\">d</a>"),
        "{}",
        d.html
    );
    let s = render_body(md, &ctx(Set::Server)).unwrap();
    assert!(
        s.html
            .contains("<a href=\"/docs/en/settings#language\">a</a>"),
        "{}",
        s.html
    );
    assert!(s.html.contains("<a href=\"/docs/en/\">b</a>"), "{}", s.html);

    let pairs: Vec<(String, Option<String>)> = d
        .links
        .iter()
        .map(|l| (l.page.clone(), l.anchor.clone()))
        .collect();
    assert_eq!(
        pairs,
        [
            ("settings".to_string(), Some("language".to_string())),
            ("index".to_string(), None),
            ("approvals".to_string(), Some("here".to_string())),
        ]
    );

    for bad in [
        "[x](javascript:alert(1))",
        "[x](mailto:a@b.c)",
        "[x](../up)",
        "[x](a/b)",
        "[x](Page)",
        "[x](data:text/html,x)",
    ] {
        assert!(
            render_body(bad, &ctx(Set::Desktop)).is_err(),
            "accepted {bad:?}"
        );
    }
}

#[test]
fn links_to_missing_pages_or_anchors_are_errors() {
    let mut src = fixture();
    src.langs.get_mut("en").unwrap()[0].body = "## Start {#start}\n\n[x](srv)\n".into();
    // `srv` is a server page: a desktop link to it dangles, a server link does not.
    assert!(site::generate(&src, Set::Desktop).is_err());
    assert!(site::generate(&src, Set::Server).is_ok());
    src.langs.get_mut("en").unwrap()[0].body = "## Start {#start}\n\n[x](desk#nope)\n".into();
    assert!(site::generate(&src, Set::Desktop).is_err());
    src.langs.get_mut("en").unwrap()[0].body = "## Start {#start}\n\n[x](desk#desk)\n".into();
    assert!(site::generate(&src, Set::Desktop).is_ok());
}

/// Tags of `html`: the text between `<` and `>` (page text is escaped, so every `<` opens a tag).
fn tags(html: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find('<') {
        let after = &rest[i + 1..];
        let Some(j) = after.find('>') else { break };
        out.push(&after[..j]);
        rest = &after[j + 1..];
    }
    out
}

fn inline_violation(tag: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    if lower.starts_with("script") && !lower.contains(" src=") {
        return Some("script without src".into());
    }
    if lower.starts_with("style") {
        return Some("style element".into());
    }
    if lower.contains(" style=") {
        return Some("style attribute".into());
    }
    let bytes = lower.as_bytes();
    let mut i = 0;
    while let Some(p) = lower[i..].find(" on") {
        let start = i + p + 3;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_lowercase() {
            end += 1;
        }
        if end > start && bytes.get(end) == Some(&b'=') {
            return Some("event handler attribute".into());
        }
        i = start;
    }
    None
}

#[test]
fn no_inline_script_or_style() {
    let src = site::load(&guide_dir()).unwrap();
    for set in [Set::Desktop, Set::Server] {
        let files = site::generate(&src, set).unwrap();
        let mut html_files = 0;
        for (name, bytes) in &files {
            if !name.ends_with(".html") {
                continue;
            }
            html_files += 1;
            let html = String::from_utf8(bytes.clone()).unwrap();
            for tag in tags(&html) {
                assert_eq!(inline_violation(tag), None, "{set:?} {name}: <{tag}>");
            }
        }
        assert!(html_files > 0);
    }
    // The detector itself.
    for bad in [
        "script",
        "style",
        "p style=\"x\"",
        "a onclick=\"x()\"",
        "body onload=x",
    ] {
        assert!(inline_violation(bad).is_some(), "{bad}");
    }
    for ok in [
        "script src=\"a.js\" defer",
        "a href=\"x\"",
        "p class=\"one\"",
    ] {
        assert_eq!(inline_violation(ok), None, "{ok}");
    }
}

#[test]
fn desktop_set_excludes_server_pages() {
    let src = fixture();
    let d = site::generate(&src, Set::Desktop).unwrap();
    let s = site::generate(&src, Set::Server).unwrap();
    assert!(
        d.contains_key("en/desk.html") && !d.contains_key("en/srv.html"),
        "{:?}",
        names(&d)
    );
    assert!(
        s.contains_key("en/srv.html") && !s.contains_key("en/desk.html"),
        "{:?}",
        names(&s)
    );
    assert!(d.contains_key("de/mixed.html") && s.contains_key("de/mixed.html"));

    let dm = text(&d, "en/manifest.json");
    assert!(
        dm.contains("\"id\": \"desk\"") && !dm.contains("\"id\": \"srv\""),
        "{dm}"
    );
    assert!(dm.contains("\"d\"") && !dm.contains("\"s\""), "{dm}");
    assert!(!text(&d, "en/desk.html").contains("srv"));
    assert!(!text(&d, "en/mixed.html").contains("id=\"s\""));
    assert!(text(&s, "en/mixed.html").contains("id=\"s\""));
    let idx = text(&d, "en/assets/search-index.js");
    assert!(idx.starts_with("window.ATLAS_HELP_INDEX = ["), "{idx}");
    assert!(!idx.contains("only server"), "{idx}");

    // The real guide: no server-only page in the desktop set and the reverse.
    let real = site::load(&guide_dir()).unwrap();
    let d = site::generate(&real, Set::Desktop).unwrap();
    let s = site::generate(&real, Set::Server).unwrap();
    for lang in ["en", "de"] {
        for p in [
            "admin",
            "auditor",
            "agents-server",
            "getting-started-server",
        ] {
            assert!(
                !d.contains_key(&format!("{lang}/{p}.html")),
                "desktop has {p}"
            );
            assert!(
                s.contains_key(&format!("{lang}/{p}.html")),
                "server lacks {p}"
            );
        }
        for p in ["agents-desktop", "getting-started-desktop"] {
            assert!(
                d.contains_key(&format!("{lang}/{p}.html")),
                "desktop lacks {p}"
            );
            assert!(
                !s.contains_key(&format!("{lang}/{p}.html")),
                "server has {p}"
            );
        }
    }
}

#[test]
fn pages_link_to_the_other_language_and_carry_assets() {
    let src = fixture();
    let d = site::generate(&src, Set::Desktop).unwrap();
    let html = text(&d, "en/mixed.html");
    assert!(html.contains("href=\"../de/mixed.html\""), "{html}");
    assert!(
        html.contains("href=\"assets/help.css\"") && html.contains("src=\"assets/help.js\""),
        "{html}"
    );
    assert!(html.contains("src=\"assets/search-index.js\""), "{html}");
    assert!(text(&d, "de/mixed.html").contains("href=\"../en/mixed.html\""));
    assert_eq!(text(&d, "en/assets/help.css"), "body{}\n");
    let s = site::generate(&src, Set::Server).unwrap();
    assert!(text(&s, "en/mixed.html").contains("href=\"/docs/de/mixed\""));
    assert!(text(&s, "en/index.html").contains("href=\"/docs/de/\""));
}

#[test]
fn output_is_deterministic() {
    let a = site::load(&guide_dir()).unwrap();
    let b = site::load(&guide_dir()).unwrap();
    for set in [Set::Desktop, Set::Server] {
        let x = site::generate(&a, set).unwrap();
        let y = site::generate(&b, set).unwrap();
        assert_eq!(x, y);
        let keys: Vec<_> = x.keys().cloned().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        for (name, bytes) in &x {
            assert!(!bytes.contains(&b'\r'), "{name} has CR");
        }
    }
}

#[test]
fn json_strings_are_escaped_for_json_and_js() {
    assert_eq!(json_str("a\"b\\c\nd\te"), "\"a\\\"b\\\\c\\nd\\te\"");
    assert_eq!(json_str("\u{1}"), "\"\\u0001\"");
    assert_eq!(json_str("\u{2028}\u{2029}"), "\"\\u2028\\u2029\"");
    assert_eq!(json_str("Übersicht <b>"), "\"Übersicht \\u003cb>\"");
}

#[test]
fn check_reports_drift_and_write_repairs_it() {
    let dir = std::env::temp_dir().join(format!("atlas-duck-docgen-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let files = site::generate(&fixture(), Set::Desktop).unwrap();
    assert!(!crate::drift(&dir, &files).unwrap().is_empty());
    crate::write_tree(&dir, &files).unwrap();
    assert_eq!(crate::drift(&dir, &files).unwrap(), Vec::<String>::new());

    // A CRLF checkout (core.autocrlf) is not drift; a changed, deleted or extra file is.
    let page = dir.join("en/index.html");
    let crlf = std::fs::read_to_string(&page)
        .unwrap()
        .replace('\n', "\r\n");
    std::fs::write(&page, crlf).unwrap();
    assert!(crate::drift(&dir, &files).unwrap().is_empty());
    std::fs::write(&page, "changed").unwrap();
    std::fs::remove_file(dir.join("de/index.html")).unwrap();
    std::fs::write(dir.join("en/extra.html"), "x").unwrap();
    assert_eq!(crate::drift(&dir, &files).unwrap().len(), 3);
    crate::write_tree(&dir, &files).unwrap();
    assert!(crate::drift(&dir, &files).unwrap().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn out_dirs_must_not_overlap_the_sources_or_each_other() {
    let src = guide_dir();
    let base =
        std::env::temp_dir().join(format!("atlas-duck-docgen-overlap-{}", std::process::id()));
    let (a, b) = (base.join("a"), base.join("b"));
    assert!(crate::check_disjoint(&src, &a, &b).is_ok());
    assert!(crate::check_disjoint(&src, &src, &b).is_err());
    assert!(crate::check_disjoint(&src, &src.join("en"), &b).is_err());
    assert!(crate::check_disjoint(&src, &a, &src.join("..")).is_err());
    assert!(crate::check_disjoint(&src, &a, &a.join("sub")).is_err());
    assert!(crate::check_disjoint(&src, &a, &a).is_err());
    // Lexical `..` and a not yet existing out dir are resolved.
    assert!(crate::check_disjoint(&src, &base.join("x/../a"), &base.join("a/new")).is_err());
}

/// Windows paths are case-insensitive: a differently cased, not yet existing tail still overlaps.
#[cfg(windows)]
#[test]
fn out_dir_overlap_ignores_case_on_windows() {
    let src = guide_dir();
    let base = std::env::temp_dir().join(format!("atlas-duck-docgen-case-{}", std::process::id()));
    let (a, b) = (base.join("Out"), base.join("b"));
    assert!(crate::check_disjoint(&src, &a, &b).is_ok());
    assert!(crate::check_disjoint(&src, &a, &base.join("OUT").join("new")).is_err());
    assert!(crate::check_disjoint(&src, &a, &base.join("out")).is_err());
}

/// `--check` sees a leftover empty directory (write mode removes it), but not the root itself.
#[test]
fn check_reports_stale_empty_directories() {
    let dir = std::env::temp_dir().join(format!("atlas-duck-docgen-empty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let files = site::generate(&fixture(), Set::Desktop).unwrap();
    crate::write_tree(&dir, &files).unwrap();
    assert!(crate::drift(&dir, &files).unwrap().is_empty());
    std::fs::create_dir_all(dir.join("old/deep")).unwrap();
    let found = crate::drift(&dir, &files).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("old") && found[0].contains("empty directory"),
        "{found:?}"
    );
    crate::write_tree(&dir, &files).unwrap();
    assert!(crate::drift(&dir, &files).unwrap().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A link (symlink, or a junction on Windows) inside an out dir is neither followed nor deleted
/// through: the files it points at survive a write.
#[test]
fn write_tree_does_not_follow_links() {
    let base = std::env::temp_dir().join(format!("atlas-duck-docgen-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (out, outside) = (base.join("out"), base.join("outside"));
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keep.txt"), "keep").unwrap();
    let link = out.join("link");
    #[cfg(windows)]
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&outside)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(&outside, &link).is_ok();
    assert!(made, "could not create a link for the test");

    let files = site::generate(&fixture(), Set::Desktop).unwrap();
    crate::write_tree(&out, &files).unwrap();
    assert_eq!(
        std::fs::read_to_string(outside.join("keep.txt")).unwrap(),
        "keep"
    );
    assert!(crate::drift(&out, &files).unwrap().is_empty());
    // Stale empty directories are removed too.
    std::fs::create_dir_all(out.join("old/deep")).unwrap();
    std::fs::write(out.join("old/deep/x.html"), "x").unwrap();
    crate::write_tree(&out, &files).unwrap();
    assert!(!out.join("old").exists());
    // remove_dir on a junction removes the link only; remove_dir_all could follow it.
    let _ = std::fs::remove_dir(&link);
    std::fs::remove_dir_all(&base).unwrap();
}
