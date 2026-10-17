//! The lossy-update count and the storage line projection (plan Task 7, spec §7.6 "Lossy
//! updates", §6.3 Edit/update, PD-94, PD-104).

mod common;

use atlas_duck_convert::storage::parse;
use atlas_duck_convert::{
    LostCounts, UserResolutions, lossy_update, storage_lines, storage_to_markdown,
};
use proptest::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn lost(macros: u64, images: u64, links: u64, layouts: u64) -> LostCounts {
    LostCounts {
        macros,
        images,
        links,
        layouts,
    }
}

/// What a read of `storage` reports as lost (`meta.conversion.lost`).
fn read_lost(storage: &str) -> LostCounts {
    storage_to_markdown(storage, &UserResolutions::new()).1.lost
}

/// A suffix that no well-formed body can absorb (an end tag without a start tag) and that
/// holds no start tag, so the lexical scan sees the body's own tags only.
const BREAK: &str = "</x-never-opened>";

#[test]
fn lossy_counts_macros_images_links_layouts() -> TestResult {
    let current = concat!(
        "<p>intro <ac:emoticon ac:name=\"smile\"/></p>",
        "<ac:structured-macro ac:name=\"toc\"/>",
        "<ac:structured-macro ac:name=\"jira\"><ac:parameter ac:name=\"key\">A-1</ac:parameter>",
        "</ac:structured-macro>",
        "<ac:structured-macro ac:name=\"info\"><ac:rich-text-body>",
        "<p><ac:image><ri:attachment ri:filename=\"a.png\"/></ac:image></p>",
        "</ac:rich-text-body></ac:structured-macro>",
        "<p><ac:image><ri:url ri:value=\"https://x.example/i.png\"/></ac:image></p>",
        "<p><ac:link><ri:page ri:content-title=\"T\"/></ac:link> and <a href=\"https://x\">x</a></p>",
        "<ac:layout><ac:layout-section><ac:layout-cell><p>a</p></ac:layout-cell>",
        "<ac:layout-cell><p>b</p></ac:layout-cell></ac:layout-section></ac:layout>",
        "<ac:task-list><ac:task><ac:task-id>1</ac:task-id><ac:task-status>incomplete</ac:task-status>",
        "<ac:task-body>do</ac:task-body></ac:task></ac:task-list>",
        "<p><ac:inline-comment-marker ac:ref=\"r\">marked</ac:inline-comment-marker></p>",
        "<p><zz:x xmlns:zz=\"u\">f</zz:x></p>",
    );
    assert!(parse(current).xml_ok);
    let outgoing = "<p>intro</p><p>a</p><p>b</p>";
    // Macros: emoticon, toc, jira, info, task list, inline-comment marker, foreign element.
    let want = lost(7, 2, 1, 1);
    assert_eq!(lossy_update(current, outgoing), want);
    // The update count and the read's `meta.conversion.lost` apply the same rules.
    assert_eq!(read_lost(current), want);
    Ok(())
}

#[test]
fn lossy_counts_nested_link_once() -> TestResult {
    let page = "<p><ac:link><ri:page ri:space-key=\"DOC\" ri:content-title=\"T\"/></ac:link></p>";
    assert_eq!(lossy_update(page, ""), lost(0, 0, 1, 0));
    let body = concat!(
        "<p><ac:link><ri:attachment ri:filename=\"f.pdf\"/>",
        "<ac:plain-text-link-body><![CDATA[file]]></ac:plain-text-link-body></ac:link></p>",
    );
    assert_eq!(lossy_update(body, ""), lost(0, 0, 1, 0));
    let mention = "<p><ac:link><ri:user ri:userkey=\"8a7f\"/></ac:link></p>";
    assert_eq!(lossy_update(mention, ""), lost(0, 0, 1, 0));
    let image = "<p><ac:image><ri:attachment ri:filename=\"a.png\"/></ac:image></p>";
    assert_eq!(lossy_update(image, ""), lost(0, 1, 0, 0));
    let url_image = "<p><ac:image><ri:url ri:value=\"https://x/i.png\"/></ac:image></p>";
    assert_eq!(lossy_update(url_image, ""), lost(0, 1, 0, 0));
    // A bare mention counts under links (the §6.2 text has no mentions term, L146).
    let bare = "<p>hi <ri:user ri:userkey=\"8a7f\"/></p>";
    assert_eq!(lossy_update(bare, ""), lost(0, 0, 1, 0));
    // Nested task lists are one macro; a link inside a task is counted on its own.
    let tasks = concat!(
        "<ac:task-list><ac:task><ac:task-body>a <ri:user ri:userkey=\"k\"/>",
        "<ac:task-list><ac:task><ac:task-body>b</ac:task-body></ac:task></ac:task-list>",
        "</ac:task-body></ac:task></ac:task-list>",
    );
    assert_eq!(lossy_update(tasks, ""), lost(1, 0, 1, 0));
    // A stray task outside any list counts as one macro too.
    let stray = "<ac:task><ac:task-body>x</ac:task-body></ac:task>";
    assert_eq!(lossy_update(stray, ""), lost(1, 0, 0, 0));
    for s in [page, body, mention, image, url_image, bare, tasks, stray] {
        assert_eq!(lossy_update(s, ""), read_lost(s), "{s}");
    }
    Ok(())
}

#[test]
fn lossy_counts_partial_parse_lexically() -> TestResult {
    let current = concat!(
        "<p>a<b>c</p>",
        "<ac:structured-macro ac:name=\"toc\"/>",
        "<ac:structured-macro ac:name=\"jira\"><ac:parameter ac:name=\"key\">A-1</ac:parameter>",
        "</ac:structured-macro>",
        "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body><![CDATA[x]]>",
        "</ac:plain-text-body></ac:structured-macro>",
    );
    assert!(!parse(current).xml_ok);
    assert_eq!(lossy_update(current, "<p>x</p>"), lost(2, 0, 0, 0));
    // Each kind after the error point is seen by the lexical scan.
    let kinds = concat!(
        "<p>a<b>c</p>",
        "<ac:image><ri:attachment ri:filename=\"a.png\"/></ac:image>",
        "<ac:layout><ac:layout-section><ac:layout-cell>x</ac:layout-cell></ac:layout-section>",
        "</ac:layout>",
        "<ac:task-list><ac:task><ac:task-body>t</ac:task-body></ac:task></ac:task-list>",
        "<p xmlns=\"u\">n</p>",
        "<ac:structured-macro ac:name=\"inc&#108;ude\"/>",
    );
    assert!(!parse(kinds).xml_ok);
    let got = lossy_update(kinds, "");
    // Over-reports, never under-reports: the image's `ri:attachment` is a link to the scan,
    // and each `ac:task` start tag a macro.
    assert!(got.macros >= 3, "{got:?}");
    assert!(got.images >= 1, "{got:?}");
    assert!(got.links >= 1, "{got:?}");
    assert!(got.layouts >= 1, "{got:?}");
    Ok(())
}

#[test]
fn lossy_zero_for_identical_and_for_additions() -> TestResult {
    let current = concat!(
        "<p><ac:link><ri:page ri:content-title=\"T\"/></ac:link></p>",
        "<ac:structured-macro ac:name=\"toc\"/>",
        "<ac:image><ri:attachment ri:filename=\"a.png\"/></ac:image>",
    );
    assert_eq!(lossy_update(current, current), LostCounts::default());
    let more = format!("{current}<ac:structured-macro ac:name=\"jira\"/><ac:layout></ac:layout>");
    assert_eq!(lossy_update(current, &more), LostCounts::default());
    assert_eq!(lossy_update("", "<p>x</p>"), LostCounts::default());
    assert_eq!(lossy_update("", ""), LostCounts::default());
    // Per kind and saturating: an added link does not offset a removed macro.
    let swapped = "<p><ac:link><ri:page ri:content-title=\"T\"/></ac:link></p>\
                   <p><ac:link><ri:page ri:content-title=\"U\"/></ac:link></p>";
    assert_eq!(lossy_update(current, swapped), lost(1, 1, 0, 0));
    // Count in current minus count in outgoing.
    let two = "<ac:structured-macro ac:name=\"toc\"/><ac:structured-macro ac:name=\"jira\"/>";
    let one = "<ac:structured-macro ac:name=\"toc\"/>";
    assert_eq!(lossy_update(two, one), lost(1, 0, 0, 0));
    Ok(())
}

#[test]
fn code_macros_are_not_lossy() -> TestResult {
    let current = concat!(
        "<ac:structured-macro ac:name=\"code\"><ac:parameter ac:name=\"language\">rust</ac:parameter>",
        "<ac:plain-text-body><![CDATA[fn main() {} <ri:user ri:userkey=\"x\"/>]]></ac:plain-text-body>",
        "</ac:structured-macro>",
        "<ac:structured-macro ac:name=\"noformat\"><ac:plain-text-body><![CDATA[raw]]>",
        "</ac:plain-text-body></ac:structured-macro>",
        "<ac:structured-macro ac:name=\"CODE\"><ac:plain-text-body><![CDATA[y]]>",
        "</ac:plain-text-body></ac:structured-macro>",
    );
    assert_eq!(
        lossy_update(current, "<p>fn main() {}</p>"),
        LostCounts::default()
    );
    assert_eq!(read_lost(current), LostCounts::default());
    // What Markdown → storage writes for code is a code macro, never counted on either side.
    let (outgoing, _) = atlas_duck_convert::markdown_to_storage("```rust\nfn main() {}\n```\n");
    assert_eq!(lossy_update(current, &outgoing), LostCounts::default());
    Ok(())
}

#[test]
fn lossy_outgoing_side_counted_by_its_own_rules() -> TestResult {
    // An unparsable outgoing side counts as zero constructs (Δ1, T7 review I-1): its lexical
    // scan would over-report and so offset what the update removes. Converter output never
    // gets here either: the hard check refuses an unparsable conversion first (PD-97 e).
    let current = "<ac:structured-macro ac:name=\"toc\"/><ac:structured-macro ac:name=\"jira\"/>";
    let outgoing = "<p>a<b>c</p><ac:structured-macro ac:name=\"toc\"/>";
    assert!(!parse(outgoing).xml_ok);
    assert_eq!(lossy_update(current, outgoing), lost(2, 0, 0, 0));
    // A macro quoted inside a code body of an unparsable outgoing side offsets nothing.
    let quoted = format!(
        "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body>\
         <![CDATA[<ac:structured-macro ac:name=\"toc\"/>]]></ac:plain-text-body>\
         </ac:structured-macro>{BREAK}"
    );
    assert!(!parse(&quoted).xml_ok);
    assert_eq!(lossy_update(current, &quoted), lost(2, 0, 0, 0));
    Ok(())
}

#[test]
fn storage_lines_split_at_block_ends() -> TestResult {
    let s = concat!(
        "<h1>T</h1><p>a<br/>b<br />c</p><ul><li>x</li><li>y</li></ul>",
        "<table><tbody><tr><td>1</td></tr><tr><td>2</td></tr></tbody></table>",
        "<hr/><blockquote><p>q</p></blockquote><pre>p</pre>\n",
        "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body><![CDATA[l1</p>\nl2<br/>]]>",
        "</ac:plain-text-body></ac:structured-macro>",
        "<ac:structured-macro ac:name=\"toc\"/>",
        "<ac:layout><ac:layout-section><ac:layout-cell><p>c</p></ac:layout-cell></ac:layout-section>",
        "</ac:layout><!-- </p> --><P>u</P>tail",
    );
    let want = vec![
        "<h1>T</h1>",
        "<p>a<br/>",
        "b<br />",
        "c</p>",
        "<ul><li>x</li>",
        "<li>y</li>",
        "</ul><table><tbody><tr><td>1</td></tr>",
        "<tr><td>2</td></tr>",
        "</tbody></table>",
        "<hr/>",
        "<blockquote><p>q</p>",
        "</blockquote>",
        "<pre>p</pre>",
        "\n",
        // Inside CDATA no tag ends a line; a line end still does.
        "<ac:structured-macro ac:name=\"code\"><ac:plain-text-body><![CDATA[l1</p>\n",
        "l2<br/>]]></ac:plain-text-body></ac:structured-macro>",
        "<ac:structured-macro ac:name=\"toc\"/>",
        "<ac:layout><ac:layout-section><ac:layout-cell><p>c</p>",
        "</ac:layout-cell></ac:layout-section>",
        // Nor inside a comment; HTML names compare ASCII case-insensitively.
        "</ac:layout><!-- </p> --><P>u</P>",
        "tail",
    ];
    assert_eq!(storage_lines(s), want);
    assert_eq!(storage_lines(s).concat(), s);
    assert!(storage_lines("").is_empty());
    assert_eq!(storage_lines("a\nb\n"), vec!["a\n", "b\n"]);
    assert_eq!(storage_lines("<p>x</p >y"), vec!["<p>x</p >", "y"]);
    // An unterminated CDATA section runs to the end; a `<p>` lookalike name is no `</p>`.
    assert_eq!(
        storage_lines("<![CDATA[</p><br/>\nz"),
        vec!["<![CDATA[</p><br/>\n", "z"]
    );
    assert_eq!(storage_lines("</pre-x>a</br>"), vec!["</pre-x>a</br>"]);
    Ok(())
}

#[test]
fn storage_lines_every_heading_level_ends_a_line() -> TestResult {
    let s = "<h1>a</h1><h2>b</h2><h3>c</h3><h4>d</h4><h5>e</h5><h6>f</h6>g";
    assert_eq!(
        storage_lines(s),
        vec![
            "<h1>a</h1>",
            "<h2>b</h2>",
            "<h3>c</h3>",
            "<h4>d</h4>",
            "<h5>e</h5>",
            "<h6>f</h6>",
            "g"
        ]
    );
    Ok(())
}

#[test]
fn storage_lines_tag_edge_cases() -> TestResult {
    // An end tag with junk before its `>` is no end tag.
    assert_eq!(storage_lines("<p>x</p junk>y"), vec!["<p>x</p junk>y"]);
    // A `>` inside a quoted attribute value does not end the tag.
    assert_eq!(
        storage_lines("<br title=\"a>b\"/>x"),
        vec!["<br title=\"a>b\"/>", "x"]
    );
    assert_eq!(
        storage_lines("<br title='a>b'>x"),
        vec!["<br title='a>b'>", "x"]
    );
    // A `\n` inside a line-ending tag ends the line, as the doc says; the tag does not.
    assert_eq!(storage_lines("<p>x</p\n>y"), vec!["<p>x</p\n", ">y"]);
    assert_eq!(storage_lines("a<br\n/>b"), vec!["a<br\n", "/>b"]);
    assert_eq!(
        storage_lines("<ac:structured-macro\nac:name=\"toc\"/>z"),
        vec!["<ac:structured-macro\n", "ac:name=\"toc\"/>z"]
    );
    for s in ["<p>x</p\n>y", "a<br\n/>b", "<br title=\"a\nb\"/>c"] {
        assert_eq!(storage_lines(s).concat(), s);
        let lines = storage_lines(s);
        let (last, init) = lines.split_last().ok_or("no lines")?;
        assert!(init.iter().all(|l| l.ends_with('\n')), "{lines:?}");
        assert!(!last.is_empty());
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 500, ..ProptestConfig::default() })]

    #[test]
    fn storage_lines_concatenate_to_input(s in common::storage_input()) {
        let lines = storage_lines(&s);
        prop_assert_eq!(lines.concat(), s.clone());
        prop_assert!(lines.iter().all(|l| !l.is_empty()));
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, ..ProptestConfig::default() })]

    /// One rule set: an update that drops everything loses exactly what a read reports lost.
    #[test]
    fn lossy_matches_the_conversion_report(s in common::storage_well_formed()) {
        prop_assume!(parse(&s).xml_ok);
        prop_assert_eq!(lossy_update(&s, ""), read_lost(&s));
        prop_assert_eq!(lossy_update(&s, &s), LostCounts::default());
    }

    /// The lexical scan over-reports, never under-reports (PD-94): the same body made
    /// unparsable counts at least as much in every kind.
    #[test]
    fn lexical_count_never_under_reports(s in common::storage_well_formed()) {
        prop_assume!(parse(&s).xml_ok);
        let broken = format!("{s}{BREAK}");
        prop_assert!(!parse(&broken).xml_ok);
        let tree = lossy_update(&s, "");
        let lexical = lossy_update(&broken, "");
        prop_assert!(lexical.macros >= tree.macros, "{:?} < {:?}", lexical, tree);
        prop_assert!(lexical.images >= tree.images, "{:?} < {:?}", lexical, tree);
        prop_assert!(lexical.links >= tree.links, "{:?} < {:?}", lexical, tree);
        prop_assert!(lexical.layouts >= tree.layouts, "{:?} < {:?}", lexical, tree);
    }

    /// An outgoing side that does not parse counts as zero: it never offsets a loss.
    #[test]
    fn unparsable_outgoing_counts_as_zero(s in common::storage_well_formed()) {
        let broken = format!("{s}{BREAK}");
        prop_assert!(!parse(&broken).xml_ok);
        prop_assert_eq!(lossy_update(&s, &broken), lossy_update(&s, ""));
    }

    #[test]
    fn lossy_and_lines_never_panic(a in common::storage_input(), b in common::storage_input()) {
        let first = lossy_update(&a, &b);
        prop_assert_eq!(first, lossy_update(&a, &b));
        // An unparsable body is over-counted as current and zero as outgoing, so only a body
        // that parses loses nothing against itself.
        if parse(&a).xml_ok {
            prop_assert_eq!(lossy_update(&a, &a), LostCounts::default());
        }
        prop_assert_eq!(storage_lines(&b).concat(), b.clone());
    }
}
