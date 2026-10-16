//! M6 T10 (Δ5, PD-67, PD-69, PD-79; S-06 Rust half, S-12): the sandboxed preview document.
//!
//! Goldens live in `tests/golden/render/<name>.html` (macOS/Linux origin); `UPDATE_GOLDENS=1`
//! rewrites them (and then fails, so a rewrite is never mistaken for a pass). A golden or
//! `preview.css` change needs a new `renderN` (`render_output_change_bumps_the_render_version`).

type TestResult = Result<(), Box<dyn std::error::Error>>;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use atlas_duck_preview::diff::{DiffLine, DiffOp, line_diff};
use atlas_duck_preview::invisible::{self, escape_for_display};
use atlas_duck_preview::render::{self, DOC_MAX_BYTES, DOC_MAX_DIFF_LINES, DOC_MAX_ROWS, ws};
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_preview::{
    BodyView, CandidateRev, CommentView, ConfluenceComment, ConstructList, ConversionFacts,
    FieldRow, IssueCard, ItemCount, OutcomeKind, PREVIEW_BUILDER_VERSION, PREVIEW_CSS,
    PREVIEW_CSS_HASH, Platform, Preview, PreviewBody, PreviewHeader, RENDER_VERSIONS, RawPager,
    RequestView, json_tree, sanitize_html,
};
use proptest::prelude::*;
use serde_json::json;

// ---- fixtures ------------------------------------------------------------------------------------

fn header(class: &str) -> PreviewHeader {
    PreviewHeader {
        instance_alias: "jira-main".into(),
        op_id: if class == "write" {
            "jira.issue.edit".into()
        } else {
            "jira.issue.get".into()
        },
        class: class.into(),
        item_count: None,
        byte_size: 1234,
        fields_included: vec!["summary".into(), "status".into()],
        hidden_in_preview_bytes: 0,
        bidi_controls: 0,
        other_invisible: 0,
        executes_as: (class == "write").then(|| "jdoe".into()),
        receipt_fields: if class == "write" {
            vec!["id".into(), "key".into()]
        } else {
            Vec::new()
        },
        query: None,
        release_blocked: None,
    }
}

fn preview(class: &str, body: PreviewBody, warnings: Vec<Warning>) -> Preview {
    Preview {
        candidate_rev: CandidateRev {
            counter: 1,
            candidate_hash: [0xab; 32],
        },
        approvable: true,
        header: header(class),
        warnings,
        body,
        raw: RawPager::for_total(1234),
        also_appears_in: Vec::new(),
        preview_builder_version: PREVIEW_BUILDER_VERSION.into(),
        edit_form: None,
        deny_offers: Vec::new(),
        deny_prefill: None,
    }
}

fn requests() -> Vec<RequestView> {
    vec![
        RequestView {
            index: 0,
            method: "PUT".into(),
            resolved_url: "https://jira.example/rest/api/2/issue/PROJ-1".into(),
            content_type: Some("application/json".into()),
            body: BodyView::Text("{\"fields\":{\"summary\":\"New \u{202E}title\"}} \r\n".into()),
        },
        RequestView {
            index: 1,
            method: "POST".into(),
            resolved_url: "https://jira.example/rest/api/2/issue/PROJ-1/attachments".into(),
            content_type: None,
            body: BodyView::Base64("AAEC".into()),
        },
    ]
}

/// As core builds a `*_html` string: sanitized, then display-escaped.
fn core_html(html: &str) -> String {
    escape_for_display(&sanitize_html(html))
}

fn edit_lines() -> Vec<DiffLine> {
    let mut lines = vec![DiffLine {
        op: DiffOp::Field,
        text: "Description (description)".into(),
    }];
    lines.extend(line_diff("same\nold line \nlast", "same\nnew\r\nline\tx\nlast\n").lines);
    lines
}

/// One preview per `PreviewBody` variant (18), each with strings that exercise escaping.
fn variants() -> Vec<(&'static str, Preview)> {
    let tree = json_tree(&json!({
        "key": "PROJ-1",
        "list": [1, true, null, "x\u{202E}y"],
        "big": "z".repeat(5000),
        "a<b>": "<script>alert(1)</script>",
    }));
    vec![
        (
            "json_tree",
            preview("read", PreviewBody::JsonTree { tree }, Vec::new()),
        ),
        (
            "write_requests",
            preview(
                "write",
                PreviewBody::WriteRequests {
                    requests: requests(),
                },
                Vec::new(),
            ),
        ),
        (
            "upstream_error",
            preview(
                "read",
                PreviewBody::upstream_error(
                    404,
                    &escape_for_display("Issue does not exist <b>PROJ-9</b>\nsecond line "),
                ),
                Vec::new(),
            ),
        ),
        (
            "outcome",
            preview(
                "read",
                PreviewBody::Outcome {
                    outcome: OutcomeKind::ReleaseCap16,
                    size_or_pages: "17000000 bytes received, 3 responses".into(),
                    query: "project = PROJ".into(),
                },
                Vec::new(),
            ),
        ),
        (
            "enrichment_error",
            preview(
                "write",
                PreviewBody::enrichment_error(None, "", Some(OutcomeKind::PerCallTimeout30)),
                Vec::new(),
            ),
        ),
        (
            "unresolved_name",
            preview(
                "write",
                PreviewBody::UnresolvedName {
                    param: "assignee".into(),
                    value: escape_for_display("j\u{200B}doe"),
                    matches: 2,
                    candidates: vec!["jdoe (John Doe)".into(), "jdoe2 (Jane Doe)".into()],
                },
                Vec::new(),
            ),
        ),
        (
            "conflict",
            preview(
                "write",
                PreviewBody::Conflict {
                    summary: "conflict: fields changed since the agent read it: summary".into(),
                    diff_text: "summary: \"Old\" → \"New\"\n".into(),
                    // Jira (M7 Δ2): the requests, no line lists.
                    base_to_current: Vec::new(),
                    intended: Vec::new(),
                    requests: requests(),
                },
                vec![Warning::new(
                    WarningId::Conflict,
                    "conflict: fields changed since the agent read it: summary",
                )],
            ),
        ),
        (
            "could_not_recheck",
            preview(
                "write",
                PreviewBody::CouldNotRecheck {
                    class: "network error after send".into(),
                    requests: requests(),
                },
                vec![
                    Warning::new(WarningId::MixedScript, warning::mixed_script("PRОJ-1")),
                    Warning::new(WarningId::CouldNotRecheck, warning::TEXT_COULD_NOT_RECHECK),
                ],
            ),
        ),
        (
            "jira_issue",
            preview(
                "read",
                PreviewBody::JiraIssue {
                    card: IssueCard {
                        key: "PROJ-1".into(),
                        summary: escape_for_display("Fix \u{202E}the bug"),
                        issue_type: "Bug".into(),
                        status: "Open".into(),
                        priority: Some("High".into()),
                        assignee: None,
                        reporter: Some("John Doe (jdoe)".into()),
                    },
                    fields: vec![
                        FieldRow {
                            id: "summary".into(),
                            name: "Summary".into(),
                            value_text: "Fix the bug".into(),
                            restricted: false,
                        },
                        FieldRow {
                            id: "customfield_10200".into(),
                            name: "customfield_10200 (unknown field)".into(),
                            value_text: "line one\nline two  ".into(),
                            restricted: true,
                        },
                    ],
                    description_html: Some(core_html(
                        "<p>Hello <b>world</b> \u{202E}x <a href=\"https://evil.example/\">link</a>\
                         <img src=\"https://evil.example/t.png\"><script>alert(1)</script></p>",
                    )),
                    comments: vec![CommentView {
                        id: "10001".into(),
                        author: Some("Jane Doe (jane)".into()),
                        created: Some("2026-10-01T10:00:00.000+0000".into()),
                        body_html: core_html("<p onclick=\"x()\">restricted <i>note</i></p>"),
                        restricted: true,
                    }],
                },
                vec![
                    Warning::new(
                        WarningId::RestrictedComments,
                        warning::TEXT_RESTRICTED_COMMENTS,
                    ),
                    Warning::new(WarningId::CustomFields, warning::custom_fields(1)),
                ],
            ),
        ),
        (
            "table",
            preview(
                "read",
                PreviewBody::Table {
                    columns: vec!["key".into(), "summary".into()],
                    rows: vec![
                        vec!["PROJ-1".into(), "First".into()],
                        vec!["PROJ-2".into(), escape_for_display("Second\u{2066}")],
                    ],
                    count: Some(ItemCount {
                        shown: 2,
                        total: Some(40),
                        more_available: true,
                    }),
                },
                vec![Warning::new(
                    WarningId::TruncatedByCap,
                    warning::truncated_by_cap(2, 40),
                )],
            ),
        ),
        (
            "write_summary",
            preview(
                "write",
                PreviewBody::WriteSummary {
                    sentence: "Comment on PROJ-1".into(),
                    rows: vec![("issue".into(), "PROJ-1".into())],
                    constructs: Some(ConstructList {
                        macros: vec!["code".into()],
                        mentions: vec!["jdoe".into()],
                        links: vec!["https://evil.example/".into()],
                        ..ConstructList::default()
                    }),
                    requests: requests(),
                },
                Vec::new(),
            ),
        ),
        (
            "edit_diff",
            preview(
                "write",
                PreviewBody::EditDiff {
                    rendered: edit_lines(),
                    raw: edit_lines(),
                    raw_only_changes: 1,
                    requests: requests(),
                },
                vec![Warning::new(
                    WarningId::RawOnlyDiff,
                    warning::raw_only_diff(1),
                )],
            ),
        ),
        (
            "transition",
            preview(
                "write",
                PreviewBody::Transition {
                    transition: "Resolve (31)".into(),
                    from: "In Progress".into(),
                    to: "Done".into(),
                    fields: vec![("resolution".into(), "Fixed".into())],
                    constructs: None,
                    requests: requests(),
                },
                Vec::new(),
            ),
        ),
        // ---- M7 Δ2: the Confluence variants (appended: tests pick variants by index) ----------
        (
            "confluence_page_markdown",
            confluence(
                "read",
                "confluence.page.get",
                PreviewBody::ConfluencePage {
                    title: escape_for_display("Release \u{202E}plan"),
                    space: "Development (DEV)".into(),
                    version: Some(7),
                    ancestors: vec!["Home".into(), "Projects".into()],
                    format: "markdown".into(),
                    body_html: core_html(
                        "<h1>Plan</h1><p>See <a href=\"https://evil.example/\">the site</a> and \
                         [macro: toc {}]</p><img src=\"https://evil.example/t.png\">\
                         <ul><li>one</li></ul><script>alert(1)</script>",
                    ),
                    conversion: Some(ConversionFacts {
                        lossy: true,
                        macros: 1,
                        images: 0,
                        links: 2,
                        layouts: 1,
                        unresolved_users: 1,
                        fallback: false,
                    }),
                },
                vec![Warning::new(
                    WarningId::UnresolvedMention,
                    warning::TEXT_UNRESOLVED_MENTION,
                )],
            ),
        ),
        (
            "confluence_comments",
            confluence(
                "read",
                "confluence.comment.list",
                PreviewBody::ConfluenceComments {
                    comments: comment_thread(),
                    count: Some(ItemCount {
                        shown: 4,
                        total: Some(4),
                        more_available: false,
                    }),
                },
                Vec::new(),
            ),
        ),
        (
            "confluence_content_write",
            confluence(
                "write",
                "confluence.page.create",
                PreviewBody::ContentWrite {
                    sentence: "Create page 'Release plan' in Development (DEV) under 'Projects'"
                        .into(),
                    rows: vec![
                        ("space".into(), "Development (DEV)".into()),
                        ("parent".into(), "Projects".into()),
                        ("title".into(), "Release plan".into()),
                    ],
                    body_html: Some(core_html(
                        "<h2>Goals</h2><p>Ship <strong>M7</strong>, see \
                         <a href=\"https://example.com/\">notes</a></p>",
                    )),
                    constructs: Some(ConstructList {
                        links: vec!["https://example.com/".into()],
                        ..ConstructList::default()
                    }),
                    requests: confluence_requests("POST", "/rest/api/content"),
                },
                vec![Warning::new(
                    WarningId::DuplicateTitle,
                    warning::duplicate_title("Release plan", "DEV"),
                )],
            ),
        ),
        (
            "confluence_page_move",
            confluence(
                "write",
                "confluence.page.move",
                PreviewBody::PageMove {
                    page: "Release plan".into(),
                    from_path: vec!["Home".into(), "Projects".into(), "Release plan".into()],
                    to_path: vec!["Home".into(), "Archive".into(), "Release plan".into()],
                    requests: confluence_requests("PUT", "/rest/api/content/65537"),
                },
                Vec::new(),
            ),
        ),
        (
            "confluence_attachment_card",
            confluence(
                "write",
                "confluence.attachment.upload",
                PreviewBody::AttachmentUpload {
                    filename: escape_for_display("logo\u{200B}.png"),
                    size: 70,
                    mime: "image/png".into(),
                    sha256: "5a".repeat(32),
                    thumbnail_data_uri: Some(PNG_DATA_URI.into()),
                    replaces_version: Some(3),
                    existing: None,
                    comment: Some("new logo".into()),
                    requests: vec![RequestView {
                        index: 0,
                        method: "POST".into(),
                        resolved_url: "https://wiki.example/wiki/rest/api/content/65537/child/\
                                       attachment/att9001/data"
                            .into(),
                        content_type: Some("multipart/form-data; boundary=atlas-duck-5a5a".into()),
                        body: BodyView::Text(format!(
                            "--atlas-duck-5a5a\r\nContent-Disposition: form-data; name=\"file\"; \
                             filename=\"logo.png\"\r\nContent-Type: image/png\r\n\r\n{}\r\n\
                             --atlas-duck-5a5a--\r\n",
                            atlas_duck_preview::body_digest_line(70, &"5a".repeat(32))
                        )),
                    }],
                },
                Vec::new(),
            ),
        ),
    ]
}

/// A 1×1 PNG as the attachment thumbnail (PD-110).
const PNG_DATA_URI: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

/// A Confluence preview: the instance and op named.
fn confluence(class: &str, op: &str, body: PreviewBody, warnings: Vec<Warning>) -> Preview {
    let mut p = preview(class, body, warnings);
    p.header.instance_alias = "wiki".into();
    p.header.op_id = op.into();
    p
}

/// One Confluence write request with a JSON body.
fn confluence_requests(method: &str, path: &str) -> Vec<RequestView> {
    vec![RequestView {
        index: 0,
        method: method.into(),
        resolved_url: format!("https://wiki.example/wiki{path}"),
        content_type: Some("application/json".into()),
        body: BodyView::Text("{\"type\":\"page\",\"title\":\"Release plan\"}".into()),
    }]
}

/// A thread: a top-level comment, a reply, a reply to the reply, another top-level comment
/// without a reported location.
fn comment_thread() -> Vec<ConfluenceComment> {
    let c =
        |id: &str, depth: u32, parent: Option<&str>, location: Option<&str>| ConfluenceComment {
            id: id.into(),
            author: Some(format!("User {id} (u{id})")),
            created: Some(format!("2026-10-1{id}T10:00:00.000Z")),
            location: location.map(Into::into),
            depth,
            parent_id: parent.map(Into::into),
            body_html: core_html(&format!("<p>comment <em>{id}</em></p>")),
        };
    vec![
        c("1", 0, None, Some("footer")),
        c("2", 1, Some("1"), Some("footer")),
        c("3", 2, Some("2"), Some("inline")),
        c("4", 0, None, None),
    ]
}

/// The Confluence goldens beyond one per variant: the server-rendered view, the collision card,
/// the conflict card with both diffs.
fn confluence_extras() -> Vec<(&'static str, Preview)> {
    let page_view = confluence(
        "read",
        "confluence.page.get",
        PreviewBody::ConfluencePage {
            title: "Release plan".into(),
            space: "Development (DEV)".into(),
            version: Some(7),
            ancestors: Vec::new(),
            format: "view".into(),
            body_html: core_html(
                "<div class=\"confluence-information-macro\" style=\"color:red\"><p>Included \
                 from <a href=\"/wiki/display/DEV/Other\">Other</a></p></div>\
                 <script>alert(1)</script>",
            ),
            conversion: None,
        },
        vec![Warning::new(
            WarningId::ServerRenderedView,
            warning::TEXT_SERVER_RENDERED_VIEW,
        )],
    );
    let mut collision = confluence(
        "write",
        "confluence.attachment.upload",
        PreviewBody::AttachmentUpload {
            filename: "report.pdf".into(),
            size: 2_000_000,
            mime: "application/pdf".into(),
            sha256: "c3".repeat(32),
            thumbnail_data_uri: None,
            replaces_version: None,
            existing: Some("attachment att9001, version 2, 1200 bytes".into()),
            comment: None,
            requests: vec![RequestView {
                index: 0,
                method: "POST".into(),
                resolved_url: "https://wiki.example/wiki/rest/api/content/65537/child/\
                               attachment?allowDuplicated=false"
                    .into(),
                content_type: Some("multipart/form-data; boundary=atlas-duck-c3c3".into()),
                body: BodyView::Digest {
                    bytes: 2_000_321,
                    sha256: "d4".repeat(32),
                },
            }],
        },
        Vec::new(),
    );
    collision.approvable = false;
    let mut conflict = confluence(
        "write",
        "confluence.page.update",
        PreviewBody::Conflict {
            summary: warning::conflict(5, 6),
            diff_text: "base version v5, current version v6".into(),
            base_to_current: line_diff("# Plan\nold line\nend\n", "# Plan\ncurrent line\nend\n")
                .lines,
            intended: line_diff("# Plan\nold line\nend\n", "# Plan\nnew  line\nend\n").lines,
            requests: confluence_requests("PUT", "/rest/api/content/65537"),
        },
        vec![Warning::new(WarningId::Conflict, warning::conflict(5, 6))],
    );
    conflict.approvable = false;
    vec![
        ("confluence_page_view", page_view),
        ("confluence_attachment_collision", collision),
        ("confluence_conflict_intended", conflict),
    ]
}

/// The header and both warning levels at once: every header row, the release-blocked banner, a
/// Caution strip and an Info line.
fn header_and_strip() -> Preview {
    let mut p = preview(
        "write",
        PreviewBody::WriteRequests {
            requests: Vec::new(),
        },
        vec![
            Warning::new(WarningId::CustomFields, warning::custom_fields(3)),
            Warning::new(WarningId::BidiControls, warning::bidi_controls(2)),
            Warning::new(WarningId::CqlBroad, warning::TEXT_CQL_BROAD),
            Warning::new(WarningId::TokenChanged, warning::token_changed("jdoe")),
        ],
    );
    p.header.item_count = Some(ItemCount {
        shown: 50,
        total: None,
        more_available: true,
    });
    p.header.hidden_in_preview_bytes = 7;
    p.header.bidi_controls = 2;
    p.header.other_invisible = 1;
    p.header.query = Some(escape_for_display("project = PROJ AND text ~ \"\u{202E}\""));
    p.header.release_blocked = Some("release blocked: the candidate could not be built exactly");
    p
}

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/render")
}

fn doc(p: &Preview) -> String {
    render::document(p, Platform::MacOsLinux)
}

/// The text between `<body>` and `</body>`.
fn body_of(doc: &str) -> &str {
    let start = doc.find("<body>").map_or(0, |i| i + "<body>".len());
    let end = doc.rfind("</body>").unwrap_or(doc.len());
    &doc[start..end]
}

/// The text of `html` outside its tags (canonical sanitizer output: attribute values are
/// double-quoted, `<` in text is `&lt;`).
fn text_outside_tags(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    let mut quoted = false;
    for c in html.chars() {
        match (in_tag, c) {
            (false, '<') => in_tag = true,
            (false, c) => out.push(c),
            (true, '"') => quoted = !quoted,
            (true, '>') if !quoted => in_tag = false,
            _ => {}
        }
    }
    out
}

// ---- goldens -------------------------------------------------------------------------------------

#[test]
fn goldens_every_body_variant_and_the_header() -> TestResult {
    let mut all = variants();
    assert_eq!(all.len(), 18, "one golden per PreviewBody variant");
    all.extend(confluence_extras());
    all.push(("header_and_strip", header_and_strip()));
    let update = std::env::var_os("UPDATE_GOLDENS").is_some();
    let dir = golden_dir();
    let mut stale = Vec::new();
    for (name, p) in &all {
        let got = doc(p);
        assert_eq!(got, doc(p), "{name}: deterministic");
        let path = dir.join(format!("{name}.html"));
        if update {
            std::fs::create_dir_all(&dir)?;
            std::fs::write(&path, &got)?;
        } else if std::fs::read_to_string(&path).ok().as_deref() != Some(got.as_str()) {
            stale.push(*name);
        }
    }
    assert!(
        !update,
        "goldens rewritten; run again without UPDATE_GOLDENS"
    );
    assert!(
        stale.is_empty(),
        "stale goldens (UPDATE_GOLDENS=1): {stale:?}"
    );
    Ok(())
}

/// The head is exactly [`head`] (its one `<style>` is the renderer's `preview.css`, PD-92
/// contingency); the body has no style, class, script, link or frame.
#[test]
fn goldens_have_no_class_or_style_attribute() -> TestResult {
    let mut n = 0;
    for entry in std::fs::read_dir(golden_dir())? {
        let path = entry?.path();
        let text = std::fs::read_to_string(&path)?;
        assert!(
            text.starts_with(&head(Platform::MacOsLinux)),
            "{}: head",
            path.display()
        );
        assert_eq!(text.matches("<style").count(), 1, "{}", path.display());
        let body = body_of(&text);
        for bad in [
            "class=", "style=", "<style", "<script", "<a ", "<a>", "<form", "<iframe", "<link",
        ] {
            assert!(!body.contains(bad), "{}: {bad}", path.display());
        }
        n += 1;
    }
    assert_eq!(
        n, 22,
        "18 variants + 3 Confluence extras + the header golden"
    );
    Ok(())
}

/// M7 Task 8: the golden rule over the eight Confluence goldens by name (each exists, so the rule
/// is not vacuous for them), plus what the Confluence arms must never emit: a remote or non-image
/// source, a link.
#[test]
fn confluence_goldens_have_no_class_or_style() -> TestResult {
    let names = [
        "page_markdown",
        "page_view",
        "comments",
        "content_write",
        "page_move",
        "attachment_card",
        "attachment_collision",
        "conflict_intended",
    ];
    for name in names {
        let path = golden_dir().join(format!("confluence_{name}.html"));
        let text = std::fs::read_to_string(&path)?;
        assert!(
            text.starts_with(&head(Platform::MacOsLinux)),
            "{name}: head"
        );
        let body = body_of(&text);
        for bad in [
            "class=",
            "style=",
            "<style",
            "<script",
            "<a ",
            "<a>",
            "<form",
            "<iframe",
            "<link",
            "src=\"http",
            "src=\"/",
            "href=",
        ] {
            assert!(!body.contains(bad), "{name}: {bad}");
        }
        // The only image source is the attachment card's thumbnail, a data URI (a remote image
        // in a page body keeps no source).
        let sources = body.matches("src=").count();
        assert_eq!(sources, usize::from(name == "attachment_card"), "{name}");
        assert_eq!(
            body.matches("<img src=\"data:image/png;base64,").count(),
            sources,
            "{name}"
        );
        assert_inert(&text, Platform::MacOsLinux);
    }
    Ok(())
}

// ---- S-06: no active content, whatever the strings ---------------------------------------------

/// Elements a document may contain: the renderer's own and what `sanitize_html` keeps in a
/// `*_html` string. Defined here, apart from the crate's lists, so widening either fails this.
const ALLOWED_TAGS: &[&str] = &[
    "header",
    "section",
    "mark",
    "p",
    "br",
    "hr",
    "div",
    "span",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "b",
    "strong",
    "i",
    "em",
    "u",
    "s",
    "del",
    "ins",
    "code",
    "pre",
    "kbd",
    "samp",
    "var",
    "blockquote",
    "ul",
    "ol",
    "li",
    "dl",
    "dt",
    "dd",
    "table",
    "thead",
    "tbody",
    "tfoot",
    "tr",
    "td",
    "th",
    "caption",
    "bdi",
    "img",
];

/// The allowlist as a sanitizer: a body it changes held something outside the allowlist (or was
/// not canonical).
fn strict() -> ammonia::Builder<'static> {
    let mut b = ammonia::Builder::default();
    b.tags(ALLOWED_TAGS.iter().copied().collect::<HashSet<_>>())
        .tag_attributes(HashMap::from([
            ("img", HashSet::from(["src", "alt"])),
            ("td", HashSet::from(["colspan", "rowspan"])),
            ("th", HashSet::from(["colspan", "rowspan"])),
            ("ol", HashSet::from(["start"])),
        ]))
        .generic_attributes(HashSet::new())
        .generic_attribute_prefixes(HashSet::new())
        .allowed_classes(HashMap::new())
        .clean_content_tags(HashSet::from(["script", "style"]))
        .url_schemes(HashSet::from(["data"]))
        .url_relative(ammonia::UrlRelative::Deny)
        .link_rel(None)
        .strip_comments(true)
        .attribute_filter(|element, attribute, value| match (element, attribute) {
            ("img", "src") => value.starts_with("data:image/").then(|| value.into()),
            _ => Some(value.into()),
        });
    b
}

/// The head of every document (PD-92 contingency, ruling C1: `preview.css` inline, admitted by
/// its hash; the same on every platform).
fn head(_platform: Platform) -> String {
    format!(
        "<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" \
         content=\"default-src 'none'; style-src {PREVIEW_CSS_HASH}; img-src data:\">\
         <style>{PREVIEW_CSS}</style></head><body>"
    )
}

/// The S-06 / S-12 checks every document must pass.
fn assert_inert(doc: &str, platform: Platform) {
    let head = head(platform);
    assert!(
        doc.starts_with(&head),
        "head: {}",
        &doc[..doc.len().min(400)]
    );
    assert!(doc.ends_with("</body></html>"));
    let body = body_of(doc);
    assert_eq!(
        strict().clean(body).to_string(),
        body,
        "element or attribute outside the allowlist"
    );
    // A `<` in text is always `&lt;`, so these can only be markup.
    let lower = body.to_ascii_lowercase();
    for bad in [
        "<script", "<style", "<a ", "<a>", "<form", "<iframe", "<svg", "<math", "<object",
        "<embed", "<link", "<meta", "<base", "<input", "<button", "<!--", "<![cdata",
    ] {
        assert!(!lower.contains(bad), "{bad} in the body");
    }
    // Inside tags (quote-aware: an `alt` value may hold a `>`): no event, style, class, id or
    // dir attribute, no script URL, no remote source. Text may show any of them as text.
    let mut in_tag = false;
    let mut quoted = false;
    let mut tag = String::new();
    for c in lower.chars() {
        match (in_tag, c) {
            (false, '<') => {
                in_tag = true;
                tag.clear();
            }
            (false, _) => {}
            (true, '"') => {
                quoted = !quoted;
                tag.push(c);
            }
            (true, '>') if !quoted => {
                in_tag = false;
                let names: String = tag.split('"').step_by(2).collect();
                for attr in [
                    " on", " style=", " class=", " id=", " dir=", " href=", " action=",
                ] {
                    assert!(!names.contains(attr), "{attr} in <{tag}>");
                }
                assert!(!tag.contains("javascript:"), "script URL: <{tag}>");
                assert!(!tag.contains("src=\"http"), "remote source: <{tag}>");
            }
            (true, c) => tag.push(c),
        }
    }
    // Every flagged character is escaped, and every `⟨` in the text starts a marked escape.
    let text = text_outside_tags(body);
    for (c, flagged) in text.chars().zip(invisible::flags(&text)) {
        assert!(!flagged, "raw flagged U+{:04X} in the text", u32::from(c));
    }
    let marked = body.matches("<mark>⟨").count();
    assert_eq!(
        text.matches('⟨').count(),
        marked,
        "an unmarked ⟨ in the text"
    );
    // None raw in a tag either: an attribute value (an `alt`) holds the escape (T10 review M-1).
    let tags = text_inside_tags(body);
    for (c, flagged) in tags.chars().zip(invisible::flags(&tags)) {
        assert!(!flagged, "raw flagged U+{:04X} in a tag", u32::from(c));
    }
}

/// The text of `html` inside its tags, each tag followed by a newline.
fn text_inside_tags(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    let mut quoted = false;
    for c in html.chars() {
        match (in_tag, c) {
            (false, '<') => in_tag = true,
            (false, _) => {}
            (true, '"') => {
                quoted = !quoted;
                out.push(c);
            }
            (true, '>') if !quoted => {
                in_tag = false;
                out.push('\n');
            }
            (true, c) => out.push(c),
        }
    }
    out
}

const CORPUS: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<img src=http://x>",
    "</bdi>",
    "\"><svg onload=alert(1)>",
    "<![CDATA[<script>x</script>]]>",
    "&lt;script&gt;",
    "&#60;script&#62;",
    "&#x3C;img src=x onerror=y&#x3E;",
    "&#x202E;",
    "\u{202E}evil\u{202C}",
    "\u{2066}x\u{2069}",
    "\u{200B}",
    "\u{1F469}\u{200D}\u{1F4BB}",
    "<a href=\"javascript:x\">t</a>",
    "<a href=\"https://evil.example/\">t</a>",
    "<style>*{color:red}</style>",
    "<iframe src=//x></iframe>",
    "<form action=//x><input></form>",
    "<!-- c -->",
    "<object data=x></object>",
    "<base href=//x>",
    "<meta http-equiv=refresh content=0;url=//x>",
    "<link rel=stylesheet href=//x>",
    "<p style=\"display:none\" class=x id=y dir=rtl>s</p>",
    "⟨U+202E⟩",
    "⟨",
    "⟩",
    "&#8203;",
    "\r\n",
    " \t",
    "\n",
    "<mark>m</mark>",
    "<section><h2>Caution</h2></section>",
    "<header>h</header>",
    "<math><mi xlink:href=x>m</mi></math>",
    "<svg><script>x</script></svg>",
    "<table><tr><td>t",
    "<pre>\nx</pre>",
    "\0",
    "\u{85}",
    "<img src=\"data:image/png;base64,AAAA\" alt=\"\u{202E}a>b\">",
];

fn text() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            prop::sample::select(CORPUS).prop_map(String::from),
            prop::collection::vec(any::<char>(), 0..4).prop_map(String::from_iter),
        ],
        0..4,
    )
    .prop_map(|parts| parts.concat())
}

/// A preview of variant `kind` built from `s` the way core builds it: display-escaped where core
/// escapes, raw where the model carries raw text (diff lines, requests, JSON tree).
fn arbitrary_preview(kind: usize, s: &[String]) -> Preview {
    let e = |i: usize| escape_for_display(&s[i % s.len()]);
    let r = |i: usize| s[i % s.len()].clone();
    let req = |i: usize| RequestView {
        index: 0,
        method: r(i),
        resolved_url: r(i + 1),
        content_type: Some(r(i + 2)),
        body: if i.is_multiple_of(2) {
            BodyView::Text(r(i + 3))
        } else {
            BodyView::Base64(r(i + 3))
        },
    };
    let lines = |i: usize| {
        let mut l = vec![DiffLine {
            op: DiffOp::Field,
            text: e(i),
        }];
        l.extend(line_diff(&r(i + 1), &r(i + 2)).lines);
        l
    };
    let constructs = |i: usize| ConstructList {
        macros: vec![e(i)],
        mentions: vec![e(i + 1)],
        includes: vec![e(i + 2)],
        links: vec![e(i + 3)],
        images: vec![e(i + 4)],
        attachments: vec![e(i + 5)],
    };
    let body = match kind {
        0 => PreviewBody::JsonTree {
            tree: json_tree(&json!({ r(0): [r(1), { r(2): r(3) }, 1.5, null] })),
        },
        1 => PreviewBody::WriteRequests {
            requests: vec![req(0), req(1)],
        },
        2 => PreviewBody::upstream_error(400, &e(0)),
        3 => PreviewBody::Outcome {
            outcome: OutcomeKind::LaterPageRefused,
            size_or_pages: e(0),
            query: e(1),
        },
        4 => PreviewBody::enrichment_error(Some(500), &e(0), None),
        5 => PreviewBody::UnresolvedName {
            param: e(0),
            value: e(1),
            matches: 0,
            candidates: vec![e(2), e(3)],
        },
        6 => PreviewBody::Conflict {
            summary: e(0),
            diff_text: e(1),
            base_to_current: lines(2),
            intended: lines(5),
            requests: vec![req(0)],
        },
        7 => PreviewBody::CouldNotRecheck {
            class: e(0),
            requests: vec![req(1)],
        },
        8 => PreviewBody::JiraIssue {
            card: IssueCard {
                key: e(0),
                summary: e(1),
                issue_type: e(2),
                status: e(3),
                priority: Some(e(4)),
                assignee: Some(e(5)),
                reporter: None,
            },
            fields: vec![FieldRow {
                id: e(6),
                name: e(7),
                value_text: e(8),
                restricted: true,
            }],
            description_html: Some(core_html(&r(9))),
            comments: vec![CommentView {
                id: e(10),
                author: Some(e(11)),
                created: Some(e(0)),
                body_html: core_html(&format!("{}{}", r(1), r(2))),
                restricted: false,
            }],
        },
        9 => PreviewBody::Table {
            columns: vec![e(0), e(1)],
            rows: vec![vec![e(2), e(3)], vec![e(4)]],
            count: None,
        },
        10 => PreviewBody::WriteSummary {
            sentence: e(0),
            rows: vec![(e(1), e(2))],
            constructs: Some(constructs(3)),
            requests: vec![req(2)],
        },
        11 => PreviewBody::EditDiff {
            rendered: lines(0),
            raw: lines(3),
            raw_only_changes: 1,
            requests: vec![req(3)],
        },
        12 => PreviewBody::Transition {
            transition: e(0),
            from: e(1),
            to: e(2),
            fields: vec![(e(3), e(4))],
            constructs: Some(constructs(5)),
            requests: vec![req(4)],
        },
        13 => PreviewBody::ConfluencePage {
            title: e(0),
            space: e(1),
            version: Some(7),
            ancestors: vec![e(2), e(3)],
            format: if r(4).len() % 2 == 0 {
                "view".into()
            } else {
                e(4)
            },
            body_html: core_html(&r(5)),
            conversion: Some(ConversionFacts {
                lossy: true,
                macros: 1,
                images: 2,
                links: 3,
                layouts: 4,
                unresolved_users: 5,
                fallback: true,
            }),
        },
        14 => PreviewBody::ConfluenceComments {
            // Arbitrary depths: jumps, drops and a huge depth keep the lists balanced.
            comments: [0, 3, u32::MAX, 1, 0, 2]
                .into_iter()
                .enumerate()
                .map(|(i, depth)| ConfluenceComment {
                    id: e(i),
                    author: (i % 2 == 0).then(|| e(i + 1)),
                    created: Some(e(i + 2)),
                    location: (i % 3 != 0).then(|| e(i + 3)),
                    depth,
                    parent_id: Some(e(i + 4)),
                    body_html: core_html(&r(i + 5)),
                })
                .collect(),
            count: None,
        },
        15 => PreviewBody::ContentWrite {
            sentence: e(0),
            rows: vec![(e(1), e(2))],
            body_html: Some(core_html(&r(3))),
            constructs: Some(constructs(4)),
            requests: vec![req(5)],
        },
        16 => PreviewBody::PageMove {
            page: e(0),
            from_path: vec![e(1), e(2)],
            to_path: vec![e(3), e(4), e(5)],
            requests: vec![req(6)],
        },
        _ => PreviewBody::AttachmentUpload {
            filename: e(0),
            size: 1,
            mime: e(1),
            sha256: e(2),
            // An arbitrary text after an image prefix: only base64 may become a source.
            thumbnail_data_uri: Some(if r(2).len() % 2 == 0 {
                format!("data:image/png;base64,{}", r(3))
            } else {
                r(3)
            }),
            replaces_version: Some(2),
            existing: Some(e(4)),
            comment: Some(e(5)),
            requests: vec![
                req(6),
                RequestView {
                    index: 1,
                    method: r(7),
                    resolved_url: r(8),
                    content_type: None,
                    body: BodyView::Digest {
                        bytes: 9,
                        sha256: r(9),
                    },
                },
            ],
        },
    };
    let mut p = preview(
        "write",
        body,
        vec![
            Warning::new(WarningId::MixedScript, warning::mixed_script(&e(5))),
            Warning::new(WarningId::UserRenamed, warning::user_renamed(&e(6), &e(7))),
            Warning::new(WarningId::UnknownMacros, e(8)),
        ],
    );
    p.header.instance_alias = e(9);
    p.header.fields_included = vec![e(10), e(11)];
    p.header.executes_as = Some(e(0));
    p.header.query = Some(e(1));
    p
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn s06_document_has_no_active_content(
        kind in 0usize..18,
        strings in prop::collection::vec(text(), 12),
        windows in any::<bool>(),
    ) {
        let platform = if windows { Platform::Windows } else { Platform::MacOsLinux };
        let p = arbitrary_preview(kind, &strings);
        assert_inert(&render::document(&p, platform), platform);
    }
}

/// The checker itself: each kind of active or disallowed content in a body fails it.
#[test]
fn assert_inert_rejects_active_content() {
    let head = head(Platform::MacOsLinux);
    for body in [
        "<p onclick=\"x()\">t</p>",
        "<a href=\"https://x\">t</a>",
        "<img src=\"https://x/t.png\">",
        "<p style=\"color:red\">t</p>",
        "<p class=\"x\">t</p>",
        "<script>x</script>",
        "<form></form>",
        "<p>\u{202E}</p>",
        "<p>⟨U+202E⟩</p>",
        "<details>t</details>",
        "<!-- c -->",
        "<img src=\"data:image/png;base64,AAAA\" alt=\"a\u{202E}b\">",
    ] {
        let doc = format!("{head}{body}</body></html>");
        let caught = std::panic::catch_unwind(|| assert_inert(&doc, Platform::MacOsLinux));
        assert!(caught.is_err(), "not caught: {body}");
    }
    assert_inert(
        &format!("{head}<p><bdi><mark>⟨U+202E⟩</mark></bdi></p></body></html>"),
        Platform::MacOsLinux,
    );
}

#[test]
fn every_golden_variant_is_inert() {
    for (name, p) in variants()
        .into_iter()
        .chain(confluence_extras())
        .chain([("header", header_and_strip())])
    {
        for platform in [Platform::MacOsLinux, Platform::Windows] {
            let d = render::document(&p, platform);
            assert_inert(&d, platform);
            assert!(!d.is_empty(), "{name}");
        }
    }
}

// ---- S-12 ---------------------------------------------------------------------------------------

#[test]
fn s12_preview_document_marks_invisible_and_neutralizes_remote() {
    let (_, p) = variants().swap_remove(8);
    let d = doc(&p);
    // The summary's U+202E (escaped by core) and the description's (escaped by core over the
    // sanitized HTML) are marked escapes; none is left raw.
    assert!(
        d.contains("<bdi>Fix <mark>⟨U+202E⟩</mark>the bug</bdi>"),
        "{d}"
    );
    assert!(d.contains("<mark>⟨U+202E⟩</mark>x"), "{d}");
    assert!(!d.contains('\u{202E}'));
    // The remote image lost its source, the link is text with its URL, the script is gone.
    assert!(!d.contains("evil.example/t.png"), "{d}");
    assert!(d.contains("link (https://evil.example/)"), "{d}");
    assert!(!d.contains("alert(1)"));
    assert!(!d.contains("onclick"));
    // A flagged character core left raw (here in a table cell) is escaped by the renderer.
    let mut t = preview(
        "read",
        PreviewBody::Table {
            columns: vec!["c".into()],
            rows: vec![vec!["a\u{2067}b\u{1}".into()]],
            count: None,
        },
        Vec::new(),
    );
    t.header.instance_alias = "x\u{200F}".into();
    let d = doc(&t);
    assert!(
        d.contains("<bdi>a<mark>⟨U+2067⟩</mark>b<mark>⟨U+0001⟩</mark></bdi>"),
        "{d}"
    );
    assert!(d.contains("<bdi>x<mark>⟨U+200F⟩</mark></bdi>"), "{d}");
    // An RGI emoji keeps its joiner (§6.4: not flagged inside an RGI sequence).
    let mut e = t.clone();
    e.header.instance_alias = "\u{1F469}\u{200D}\u{1F4BB}".into();
    assert!(doc(&e).contains("<bdi>\u{1F469}\u{200D}\u{1F4BB}</bdi>"));
}

#[test]
fn s12_raw_only_diff_caution_in_strip() {
    let strip = |p: &Preview| {
        let d = doc(p);
        let start = d
            .find("<h2>Caution</h2>")
            .map(|i| i + "<h2>Caution</h2>".len());
        start.map(|s| d[s..s + d[s..].find("</section>").unwrap_or(0)].to_owned())
    };
    let (_, mut p) = variants().swap_remove(11);
    let s = strip(&p).unwrap_or_default();
    assert_eq!(
        s.matches("1 changes not visible in rendered diff").count(),
        1,
        "{s}"
    );
    // The strip shows exactly the model's warnings (shown = audited, T10 review deviation 6):
    // without the warning (core always adds it) there is no strip line.
    p.warnings.clear();
    assert_eq!(strip(&p), None);
    // The raw diff's section names it, from the body's own count.
    assert!(doc(&p).contains(
        "<h2>Raw diff</h2><p><strong>1 changes not visible in rendered diff</strong></p>"
    ));
    // No raw-only change, no line.
    if let PreviewBody::EditDiff {
        raw_only_changes, ..
    } = &mut p.body
    {
        *raw_only_changes = 0;
    }
    assert_eq!(strip(&p), None);
}

// ---- PD-69 --------------------------------------------------------------------------------------

#[test]
fn pd69_trailing_ws_cr_and_missing_newline_visible() {
    assert_eq!(ws::visible_line("a \n"), "a⟨U+0020⟩");
    assert_eq!(ws::visible_line("b\r\n"), "b⟨U+000D⟩");
    assert_eq!(ws::visible_line("c"), "c ⟨no newline at end⟩");
    assert_eq!(
        ws::visible_line("\tx\ty \t\n"),
        "⟨U+0009⟩x⟨U+0009⟩y⟨U+0020⟩⟨U+0009⟩"
    );
    assert_eq!(ws::visible_line("a\rb\n"), "a⟨U+000D⟩b");
    assert_eq!(ws::visible_line("a \r\n"), "a⟨U+0020⟩⟨U+000D⟩");
    assert_eq!(ws::visible_line("\n"), "");
    assert_eq!(ws::visible_line(""), " ⟨no newline at end⟩");
    // Values: tabs inside a line stay, terminators stay, trailing whitespace per line is marked.
    assert_eq!(
        ws::visible_value("a\tb \nc\r\n  "),
        "a\tb⟨U+0020⟩\nc⟨U+000D⟩\n⟨U+0020⟩⟨U+0020⟩"
    );
    assert_eq!(ws::visible_value(""), "");

    // In the document: a `\n`-only change, a `\r\n` change and a trailing-space change all show.
    let raw = line_diff("x\ny \nz", "x\r\ny\nz\n").lines;
    let p = preview(
        "write",
        PreviewBody::EditDiff {
            rendered: Vec::new(),
            raw,
            raw_only_changes: 3,
            requests: Vec::new(),
        },
        Vec::new(),
    );
    let d = doc(&p);
    for want in [
        "<td>-</td><td><pre><del><bdi>x</bdi></del></pre></td>",
        "<td>+</td><td><pre><ins><bdi>x<mark>⟨U+000D⟩</mark></bdi></ins></pre></td>",
        "<td>-</td><td><pre><del><bdi>y<mark>⟨U+0020⟩</mark></bdi></del></pre></td>",
        "<td>-</td><td><pre><del><bdi>z <mark>⟨no newline at end⟩</mark></bdi></del></pre></td>",
        "<td>+</td><td><pre><ins><bdi>z</bdi></ins></pre></td>",
    ] {
        assert!(d.contains(want), "{want}\n{d}");
    }
    // A request body value: trailing space and `\r` visible.
    let (_, w) = variants().swap_remove(1);
    assert!(
        doc(&w).contains(
            "New <mark>⟨U+202E⟩</mark>title\"}}<mark>⟨U+0020⟩</mark><mark>⟨U+000D⟩</mark>\n</bdi>"
        ),
        "{}",
        doc(&w)
    );
}

#[test]
fn diff_hunks_are_runs_and_fields_are_headings() {
    let (_, p) = variants().swap_remove(11);
    let d = doc(&p);
    assert!(d.contains("<h2>Rendered diff</h2><h3><bdi>Description (description)</bdi></h3><table><tbody><tr><td> </td>"), "{d}");
    // one same line, then one hunk (the rest differs): two bodies.
    let section =
        &d[d.find("<h2>Rendered diff</h2>").unwrap_or(0)..d.find("<h2>Raw diff</h2>").unwrap_or(0)];
    assert_eq!(section.matches("<tbody>").count(), 2, "{section}");
}

/// What a browser shows for `html` with no stylesheet (UA defaults only): tags dropped; outside a
/// `<pre>` a run of spaces, tabs and newlines is one space, dropped at the start and end (the
/// cell is a block); inside a `<pre>` whitespace stays as it is.
fn shown_without_css(html: &str) -> String {
    let mut out = String::new();
    let mut pre = 0usize;
    let mut space = false;
    let mut rest = html;
    while let Some(c) = rest.chars().next() {
        if c == '<' {
            let end = rest.find('>').map_or(rest.len(), |i| i + 1);
            match &rest[..end] {
                "<pre>" => pre += 1,
                "</pre>" => pre = pre.saturating_sub(1),
                _ => {}
            }
            rest = &rest[end..];
            continue;
        }
        rest = &rest[c.len_utf8()..];
        if pre == 0 && matches!(c, ' ' | '\t' | '\n') {
            space = true;
            continue;
        }
        if space && !out.is_empty() {
            out.push(' ');
        }
        space = false;
        out.push(c);
    }
    out
}

/// T10 review I-1: whitespace a browser would collapse shows without `preview.css` (PD-92 leaves
/// its load unproven). The checks read the document as a browser renders it with no stylesheet.
#[test]
fn whitespace_shows_without_the_stylesheet() {
    // An `a  b` → `a b` edit: two different rows.
    let p = preview(
        "write",
        PreviewBody::EditDiff {
            rendered: Vec::new(),
            raw: line_diff("a  b\n", "a b\n").lines,
            raw_only_changes: 0,
            requests: Vec::new(),
        },
        Vec::new(),
    );
    let d = doc(&p);
    let cell = |marker: &str| {
        let open = format!("<td>{marker}</td><td>");
        let at = d.find(&open).map_or(0, |i| i + open.len());
        d[at..at + d[at..].find("</td>").unwrap_or(0)].to_owned()
    };
    let (del, ins) = (cell("-"), cell("+"));
    assert_eq!(shown_without_css(&del), "a  b", "{d}");
    assert_eq!(shown_without_css(&ins), "a b", "{d}");
    // Non-vacuous: render1's cell (no `<pre>`) showed both rows as `a b`.
    assert_eq!(
        shown_without_css("<del><code><bdi>a  b</bdi></code></del>"),
        shown_without_css("<ins><code><bdi>a b</bdi></code></ins>")
    );
    // Leading spaces and a tab inside a diff line.
    let p = preview(
        "write",
        PreviewBody::EditDiff {
            rendered: Vec::new(),
            raw: line_diff("x\n", "  x\n").lines,
            raw_only_changes: 0,
            requests: Vec::new(),
        },
        Vec::new(),
    );
    assert!(doc(&p).contains("<td>+</td><td><pre><ins><bdi>  x</bdi></ins></pre></td>"));

    // A multi-line field value keeps its line break; a run of spaces, a leading space and a tab
    // in a one-line value stay; a plain value gets no `<pre>`.
    let (_, j) = variants().swap_remove(8);
    let d = doc(&j);
    let value = "<td><strong>restricted visibility</strong> <pre><bdi>line one\nline two<mark>⟨U+0020⟩</mark><mark>⟨U+0020⟩</mark></bdi></pre></td>";
    assert!(d.contains(value), "{d}");
    assert!(shown_without_css(value).contains("line one\nline two"));
    let p = preview(
        "write",
        PreviewBody::WriteSummary {
            sentence: "Comment  on PROJ-1".into(),
            rows: vec![
                ("body".into(), " lead\ttab".into()),
                ("issue".into(), "PROJ-1".into()),
            ],
            constructs: None,
            requests: Vec::new(),
        },
        Vec::new(),
    );
    let d = doc(&p);
    for (html, shown) in [
        (
            "<div><pre><bdi>Comment  on PROJ-1</bdi></pre></div>",
            "Comment  on PROJ-1",
        ),
        ("<td><pre><bdi> lead\ttab</bdi></pre></td>", " lead\ttab"),
    ] {
        assert!(d.contains(html), "{html}\n{d}");
        assert_eq!(shown_without_css(html), shown);
    }
    assert!(d.contains("<td><bdi>PROJ-1</bdi></td>"), "{d}");
    // A value in a `<pre>` already (a request body) gets no second one.
    let (_, w) = variants().swap_remove(1);
    assert!(!doc(&w).contains("<pre><pre>") && !doc(&w).contains("<code><pre>"));
}

// ---- U-34, could-not-recheck, release blocked -------------------------------------------------

#[test]
fn u34_caution_strip_info_line_levels() {
    let p = header_and_strip();
    let d = doc(&p);
    let strip_start = d
        .find("<header><section><h2>Caution</h2><ul>")
        .unwrap_or(usize::MAX);
    assert_ne!(strip_start, usize::MAX, "{d}");
    let strip = &d[strip_start..strip_start + d[strip_start..].find("</section>").unwrap_or(0)];
    let info_start = d.find("<div><strong>Info:</strong> ").unwrap_or(usize::MAX);
    assert_ne!(info_start, usize::MAX, "{d}");
    let info = &d[info_start..info_start + d[info_start..].find("</div>").unwrap_or(0)];
    for w in &p.warnings {
        let (inside, outside) = match w.id.level() {
            atlas_duck_preview::Level::Caution => (strip, info),
            atlas_duck_preview::Level::Info => (info, strip),
        };
        assert!(inside.contains(&w.text), "{:?} in its own place", w.id);
        assert!(!outside.contains(&w.text), "{:?} not in the other", w.id);
    }
    assert_eq!(
        strip.matches("<li>").count(),
        3,
        "banner + two Cautions: {strip}"
    );
    // The release-blocked banner leads the strip.
    assert!(
        strip.contains("<ul><li>release blocked: the candidate could not be built exactly</li>")
    );
    assert!(info.contains("contains 3 custom fields</bdi>; <bdi>CQL may enumerate many results"));
    // No warning, no strip and no Info line.
    let mut q = p.clone();
    q.warnings.clear();
    q.header.release_blocked = None;
    let d = doc(&q);
    assert!(!d.contains("<h2>Caution</h2>") && !d.contains("<strong>Info:</strong>"));
    // Header rows (§6.1 principle 3, §5.6).
    let d = doc(&p);
    for row in [
        "<tr><th>instance</th><td><bdi>jira-main</bdi></td></tr>",
        "<tr><th>items</th><td>50 shown, more available</td></tr>",
        "<tr><th>size</th><td>1234 bytes</td></tr>",
        "<tr><th>fields included</th><td><bdi>summary</bdi>, <bdi>status</bdi></td></tr>",
        "<tr><th>hidden in preview</th><td>7 bytes</td></tr>",
        "<tr><th>bidi controls</th><td>2</td></tr>",
        "<tr><th>other invisible</th><td>1</td></tr>",
        "<tr><th>executes as</th><td><bdi>jdoe</bdi></td></tr>",
        "<tr><th>agent receives</th><td><bdi>id</bdi>, <bdi>key</bdi></td></tr>",
        "<tr><th>query</th><td><code><bdi>project = PROJ AND text ~ \"<mark>⟨U+202E⟩</mark>\"</bdi></code></td></tr>",
    ] {
        assert!(d.contains(row), "{row}\n{d}");
    }
    assert_eq!(
        render::item_count_text(&ItemCount {
            shown: 2,
            total: Some(9),
            more_available: true
        }),
        "2 of 9"
    );
    assert_eq!(
        render::item_count_text(&ItemCount {
            shown: 2,
            total: None,
            more_available: false
        }),
        "2 shown"
    );
}

#[test]
fn could_not_recheck_leads_card_and_strip() {
    let (_, p) = variants().swap_remove(7);
    let d = doc(&p);
    let lead = format!(
        "<header><section><h2>Caution</h2><ul><li><bdi>{}</bdi></li><li>",
        warning::TEXT_COULD_NOT_RECHECK
    );
    assert!(
        d.starts_with(&head(Platform::MacOsLinux)) && d.contains(&lead),
        "{d}"
    );
    // The body's first section is the card, led by the same text, then the unchanged requests.
    let body = &d[d.find("</header>").unwrap_or(0)..];
    assert!(
        body.starts_with(&format!(
            "</header><section><h2>{}</h2>",
            warning::TEXT_COULD_NOT_RECHECK
        )),
        "{body}"
    );
    assert!(body.contains("<h2>Requests to be sent (unchanged)</h2>"));
    assert!(
        body.contains(
            "<tr><th>failure class</th><td><bdi>network error after send</bdi></td></tr>"
        )
    );
    // The strip shows exactly the model's warnings (T10 review deviation 6): without the
    // warning (core asserts the body implies it) the strip has no line for it; the card still
    // leads the body.
    let mut q = p.clone();
    q.warnings.retain(|w| w.id != WarningId::CouldNotRecheck);
    assert!(!q.body.implied_warning_present(&q.warnings));
    let d = doc(&q);
    let strip = &d[..d.find("</header>").unwrap_or(0)];
    assert!(!strip.contains(warning::TEXT_COULD_NOT_RECHECK), "{d}");
    assert!(d.contains(&format!(
        "</header><section><h2>{}</h2>",
        warning::TEXT_COULD_NOT_RECHECK
    )));
    // Another body with the warning (the T19 path: the pre-change preview) leads the strip too.
    let (_, mut e) = variants().swap_remove(11);
    e.warnings.push(Warning::new(
        WarningId::CouldNotRecheck,
        warning::TEXT_COULD_NOT_RECHECK,
    ));
    let d = doc(&e);
    assert!(
        d.contains(&format!(
            "<h2>Caution</h2><ul><li><bdi>{}</bdi></li>",
            warning::TEXT_COULD_NOT_RECHECK
        )),
        "{d}"
    );
}

#[test]
fn card_consequence_lines_verbatim() {
    let (_, p) = variants().swap_remove(2);
    let d = doc(&p);
    for line in [
        "<li><strong>Release</strong> → agent receives <code>failed</code> (exit 6), HTTP 404 + the text below</li>",
        "<li><strong>Release status only</strong> → agent receives <code>failed</code> (exit 6), HTTP 404, no text</li>",
        "<li><strong>Deny</strong> → agent receives <code>denied</code> (exit 3) + your reason</li>",
    ] {
        assert!(d.contains(line), "{line}\n{d}");
    }
    // The text comes after the lines ("the text below"), as text.
    let lines_at = d.find("+ the text below").unwrap_or(usize::MAX);
    let text_at = d
        .find("Issue does not exist &lt;b&gt;PROJ-9&lt;/b&gt;")
        .unwrap_or(0);
    assert!(text_at > lines_at, "{d}");
    let (_, o) = variants().swap_remove(3);
    assert!(doc(&o).contains("<li><strong>Release outcome</strong> → agent receives <code>failed</code> (exit 6), <code>result_too_large</code> / <code>upstream_network</code> / <code>upstream_unavailable</code> and a fixed hint; no size</li>"));
    assert!(doc(&o).contains("<tr><th>outcome</th><td>16 MiB release cap</td></tr>"));
    let (_, en) = variants().swap_remove(4);
    assert!(doc(&en).contains("<li><strong>Deny</strong> → agent receives <code>denied</code> (exit 3), <code>upstream_network</code> / <code>upstream_unavailable</code> / <code>result_too_large</code>, no size</li>"));
    // Every card kind carries a Deny line.
    for i in [2, 3, 4, 5, 6, 7] {
        let (name, p) = variants().swap_remove(i);
        assert!(
            doc(&p).contains(
                "<li><strong>Deny</strong> → agent receives <code>denied</code> (exit 3)"
            ),
            "{name}"
        );
    }
}

// ---- caps ---------------------------------------------------------------------------------------

#[test]
fn caps_insert_hidden_note_and_count_bytes() {
    let hidden = |d: &str| -> u64 {
        let at = d
            .find("<tr><th>hidden in preview</th><td>")
            .map(|i| i + 34)
            .unwrap_or(0);
        d[at..]
            .split(' ')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(0)
    };
    // 2 001 rows: one row left out, noted and counted.
    let rows: Vec<Vec<String>> = (0..=DOC_MAX_ROWS)
        .map(|i| vec![format!("PROJ-{i}"), "s".into()])
        .collect();
    let mut p = preview(
        "read",
        PreviewBody::Table {
            columns: vec!["key".into(), "summary".into()],
            rows,
            count: None,
        },
        Vec::new(),
    );
    p.header.hidden_in_preview_bytes = 5;
    let d = doc(&p);
    assert!(
        d.contains("<p>1 more rows not shown here; see Structured or Raw</p>"),
        "note"
    );
    assert!(d.contains("PROJ-1999") && !d.contains("PROJ-2000"));
    assert_eq!(hidden(&d), 5 + "PROJ-2000".len() as u64 + 1);

    // A diff over its line cap.
    let raw: Vec<DiffLine> = (0..DOC_MAX_DIFF_LINES + 3)
        .map(|i| DiffLine {
            op: DiffOp::Add,
            text: format!("l{i}\n"),
        })
        .collect();
    let p = preview(
        "write",
        PreviewBody::EditDiff {
            rendered: Vec::new(),
            raw,
            raw_only_changes: 0,
            requests: Vec::new(),
        },
        Vec::new(),
    );
    let d = doc(&p);
    assert!(d.contains("<p>3 more lines not shown here; see Structured or Raw</p>"));
    assert!(hidden(&d) > 0);

    // A JSON tree past the byte budget: the rest is left out, noted and counted.
    let items: Vec<String> = (0..20_000).map(|i| format!("{i:0>300}")).collect();
    let p = preview(
        "read",
        PreviewBody::JsonTree {
            tree: json_tree(&json!(items)),
        },
        Vec::new(),
    );
    let d = doc(&p);
    assert!(body_of(&d).len() < DOC_MAX_BYTES + 64 * 1024, "{}", d.len());
    assert!(d.contains(" more items not shown here; see Structured or Raw</li>"));
    assert!(hidden(&d) > 1_000_000);

    // One text past the byte budget is cut, noted at the end of the body and counted.
    let big = "y".repeat(DOC_MAX_BYTES + 100);
    let p = preview(
        "write",
        PreviewBody::Conflict {
            summary: String::new(),
            diff_text: big,
            base_to_current: Vec::new(),
            intended: Vec::new(),
            requests: Vec::new(),
        },
        Vec::new(),
    );
    let d = doc(&p);
    assert!(d.contains("…</bdi>"));
    assert!(d.contains("more bytes not shown here; see Structured or Raw</p></body></html>"));
    assert!(hidden(&d) >= 100);

    // The header's own caps count too (T10 review M-3): a list past its row cap...
    let empty = PreviewBody::Table {
        columns: Vec::new(),
        rows: Vec::new(),
        count: None,
    };
    let mut p = preview("read", empty, Vec::new());
    p.header.fields_included = (0..=DOC_MAX_ROWS).map(|i| format!("f{i}")).collect();
    let d = doc(&p);
    assert!(
        d.contains("<bdi>f1999</bdi>, 1 more entries not shown here; see Structured or Raw</td>"),
        "{}",
        &d[..d.len().min(600)]
    );
    assert_eq!(hidden(&d), "f2000".len() as u64);
    // ...and a header text past the byte budget: cut, counted, noted at the end of the body.
    p.header.fields_included = Vec::new();
    p.header.query = Some("q".repeat(DOC_MAX_BYTES + 10));
    let d = doc(&p);
    assert!(d.contains("…</bdi></code></td></tr>"));
    assert!(hidden(&d) >= 10);
    assert!(d.contains(&format!(
        "<p>{} more bytes not shown here; see Structured or Raw</p></body></html>",
        hidden(&d)
    )));
}

/// T10 review M-1: a flagged character in an attribute value of a `*_html` string (an `alt`) is
/// escaped too, also when core did not display-escape the string.
#[test]
fn flagged_characters_in_attribute_values_are_escaped() {
    let (_, mut p) = variants().swap_remove(8);
    if let PreviewBody::JiraIssue {
        description_html, ..
    } = &mut p.body
    {
        *description_html = Some(sanitize_html(
            "<p><img src=\"data:image/png;base64,AAAA\" alt=\"x\u{202E}y\"></p>",
        ));
    }
    let d = doc(&p);
    assert!(d.contains("alt=\"x⟨U+202E⟩y\""), "{d}");
    assert!(!d.contains('\u{202E}'));
    assert_inert(&d, Platform::MacOsLinux);
}

// ---- document head, platforms, PD-79, version -------------------------------------------------

#[test]
fn meta_csp_is_first_head_element() {
    for (_, p) in variants() {
        for platform in [Platform::MacOsLinux, Platform::Windows] {
            let d = render::document(&p, platform);
            assert!(d.starts_with(&head(platform)));
            assert_eq!(d.matches("<meta").count(), 1);
            assert_eq!(d.matches("<link").count(), 0);
            // The renderer's one stylesheet (PD-92 contingency, ruling C1), nothing else.
            assert_eq!(d.matches("<style").count(), 1);
        }
    }
}

/// Since the PD-92 contingency (ruling C1) the document names no origin: the stylesheet is inline
/// and admitted by its hash, so both platforms get the same document.
#[test]
fn iframe_document_origin_per_platform() {
    let (_, p) = variants().swap_remove(0);
    let w = render::document(&p, Platform::Windows);
    let m = render::document(&p, Platform::MacOsLinux);
    assert_eq!(w, m);
    assert!(w.contains(&format!("style-src {PREVIEW_CSS_HASH}; img-src data:")));
    assert!(!w.contains("tauri://") && !w.contains("tauri.localhost"));
    assert_eq!(body_of(&w), body_of(&m));
    let current = if cfg!(windows) {
        Platform::Windows
    } else {
        Platform::MacOsLinux
    };
    assert_eq!(Platform::current(), current);
}

#[test]
fn amp_8203_literal() {
    // PD-79: `{{&#8203;code}}` shows the literal `&#8203;`, never a U+200B.
    let mut p = preview(
        "write",
        PreviewBody::WriteSummary {
            sentence: "Comment on PROJ-1".into(),
            rows: vec![("body".into(), "use {{&#8203;code}} here".into())],
            constructs: None,
            requests: Vec::new(),
        },
        Vec::new(),
    );
    let d = doc(&p);
    assert!(d.contains("<bdi>use {{&amp;#8203;code}} here</bdi>"), "{d}");
    assert!(!d.contains('\u{200B}') && !d.contains("U+200B"));
    // The same in rendered HTML (the wiki renderer's `{{…}}`).
    p.body = PreviewBody::JiraIssue {
        card: IssueCard {
            key: "PROJ-1".into(),
            summary: String::new(),
            issue_type: String::new(),
            status: String::new(),
            priority: None,
            assignee: None,
            reporter: None,
        },
        fields: Vec::new(),
        description_html: Some(core_html("<p><code>&amp;#8203;code</code></p>")),
        comments: Vec::new(),
    };
    let d = doc(&p);
    assert!(d.contains("<code>&amp;#8203;code</code>"), "{d}");
    assert!(!d.contains('\u{200B}') && !d.contains("U+200B"));
}

#[test]
fn builder_version_names_the_render_version() {
    assert_eq!(PREVIEW_BUILDER_VERSION, "pb2;render4;icu-17.0;emoji-17.0");
    // M7 Task 8 (ruling B-1): `render4` is appended after the M6 versions, which never change.
    let names: Vec<&str> = RENDER_VERSIONS.iter().map(|(n, _)| *n).collect();
    assert_eq!(names, ["render1", "render2", "render3", "render4"]);
    assert_eq!(RENDER_VERSIONS[2], ("render3", 0x18d6_262f_815e_9ad3));
}

/// FNV-1a 64 over every golden (by file name: the name, NUL, the bytes, NUL), then
/// `app/ui/public/preview.css` the same way.
fn render_digest() -> Result<u64, Box<dyn std::error::Error>> {
    let mut paths = std::fs::read_dir(golden_dir())?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    paths.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../app/ui/public/preview.css"));
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for path in &paths {
        let name = path.file_name().ok_or("no file name")?.to_string_lossy();
        let bytes = std::fs::read(path)?;
        for b in name.bytes().chain([0]).chain(bytes).chain([0]) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    Ok(h)
}

/// T10 review M-8: the goldens and the stylesheet are what a `renderN` shows; a change to either
/// without a new version (and a new `RENDER_VERSIONS` entry) fails here.
#[test]
fn render_output_change_bumps_the_render_version() -> TestResult {
    let got = render_digest()?;
    let &(current, pinned) = RENDER_VERSIONS.last().ok_or("no render version")?;
    assert!(
        PREVIEW_BUILDER_VERSION.contains(&format!(";{current};")),
        "PREVIEW_BUILDER_VERSION {PREVIEW_BUILDER_VERSION} does not name {current}, the last \
         RENDER_VERSIONS entry"
    );
    let names: HashSet<&str> = RENDER_VERSIONS.iter().map(|(n, _)| *n).collect();
    let digests: HashSet<u64> = RENDER_VERSIONS.iter().map(|(_, d)| *d).collect();
    assert_eq!(names.len(), RENDER_VERSIONS.len(), "a render version twice");
    assert_eq!(digests.len(), RENDER_VERSIONS.len(), "a digest twice");
    assert_eq!(
        got, pinned,
        "the goldens or preview.css changed (digest {got:#018x}): bump renderN in \
         PREVIEW_BUILDER_VERSION and append (\"renderN\", {got:#018x}) to RENDER_VERSIONS"
    );
    Ok(())
}

#[test]
fn literal_escape_text_is_never_a_marked_escape() {
    // A literal `⟨U+202E⟩` in raw text (here a request body) is escaped delimiter by delimiter, so
    // it cannot pass for an escape; the real U+202E next to it is one marked escape.
    let p = preview(
        "write",
        PreviewBody::WriteRequests {
            requests: vec![RequestView {
                index: 0,
                method: "POST".into(),
                resolved_url: "https://jira.example/x".into(),
                content_type: None,
                body: BodyView::Text("⟨U+202E⟩\u{202E}".into()),
            }],
        },
        Vec::new(),
    );
    let d = doc(&p);
    assert!(
        d.contains(
            "<bdi><mark>⟨U+27E8⟩</mark>U+202E<mark>⟨U+27E9⟩</mark><mark>⟨U+202E⟩</mark></bdi>"
        ),
        "{d}"
    );
}

// ---- M7 Task 8: the Confluence arms (Δ2) --------------------------------------------------------

/// The fixture named `name` (a variant or a Confluence extra).
fn named(name: &str) -> Preview {
    variants()
        .into_iter()
        .chain(confluence_extras())
        .find(|(n, _)| *n == name)
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("no fixture {name}"))
}

/// The document of fixture `name`, checked against its golden and for inertness.
fn golden_doc(name: &str) -> String {
    let d = doc(&named(name));
    let path = golden_dir().join(format!("{name}.html"));
    if std::env::var_os("UPDATE_GOLDENS").is_none() {
        assert_eq!(
            std::fs::read_to_string(&path).ok().as_deref(),
            Some(d.as_str()),
            "{name}: golden"
        );
    }
    assert_inert(&d, Platform::MacOsLinux);
    d
}

fn assert_has(d: &str, wants: &[&str]) {
    for want in wants {
        assert!(d.contains(want), "{want}\n{d}");
    }
}

#[test]
fn render_confluence_page_golden() {
    let d = golden_doc("confluence_page_markdown");
    assert_has(
        &d,
        &[
            "</header><section><h2>Confluence page</h2><table><tbody>\
             <tr><th>title</th><td><bdi>Release <mark>⟨U+202E⟩</mark>plan</bdi></td></tr>",
            "<tr><th>space</th><td><bdi>Development (DEV)</bdi></td></tr>",
            "<tr><th>version</th><td>7</td></tr>",
            "<tr><th>ancestors</th><td><bdi>Home</bdi> / <bdi>Projects</bdi></td></tr>",
            "<tr><th>format</th><td><bdi>markdown</bdi></td></tr>",
            "<h3>Body</h3><h1>Plan</h1>",
            "the site (https://evil.example/)",
            "<h3>Conversion</h3><table><tbody><tr><th>lossy</th><td>yes</td></tr>\
             <tr><th>macros lost</th><td>1</td></tr><tr><th>images lost</th><td>0</td></tr>\
             <tr><th>links lost</th><td>2</td></tr><tr><th>layouts lost</th><td>1</td></tr>\
             <tr><th>unresolved mentions</th><td>1</td></tr>\
             <tr><th>fallback conversion</th><td>no</td></tr></tbody></table>",
        ],
    );
    assert!(!d.contains("evil.example/t.png") && !d.contains("alert(1)"));
    assert!(!d.contains("server-rendered view (secondary)"));
    // No version, no ancestors, no conversion facts: "none" rows, no Conversion section.
    let mut p = named("confluence_page_markdown");
    if let PreviewBody::ConfluencePage {
        version,
        ancestors,
        conversion,
        ..
    } = &mut p.body
    {
        *version = None;
        ancestors.clear();
        *conversion = None;
    }
    let d = doc(&p);
    assert_has(
        &d,
        &[
            "<tr><th>version</th><td>none</td></tr>",
            "<tr><th>ancestors</th><td>none</td></tr>",
        ],
    );
    assert!(!d.contains("<h3>Conversion</h3>"));
}

#[test]
fn render_page_view_labelled_secondary() {
    let d = golden_doc("confluence_page_view");
    assert_has(
        &d,
        &[
            "<tr><th>format</th><td><bdi>view</bdi></td></tr>",
            "<h3>Body</h3><p><strong>server-rendered view (secondary)</strong></p>",
            // §6.2: the Caution comes from the model's warning.
            "<li><bdi>server-rendered view: macros may include content from other pages</bdi></li>",
            "Included from Other (/wiki/display/DEV/Other)",
        ],
    );
    assert!(!d.contains("confluence-information-macro") && !d.contains("alert(1)"));
    // Only `view` is labelled.
    for format in ["markdown", "storage"] {
        let mut p = named("confluence_page_view");
        if let PreviewBody::ConfluencePage { format: f, .. } = &mut p.body {
            *f = format.into();
        }
        assert!(
            !doc(&p).contains("server-rendered view (secondary)"),
            "{format}"
        );
    }
}

/// The nesting of `<ul>` lists in `html`: (opened, closed, deepest).
fn list_nesting(html: &str) -> (usize, usize, usize) {
    let (mut open, mut close, mut level, mut deepest) = (0, 0, 0usize, 0);
    let mut rest = html;
    while let Some(i) = rest.find('<') {
        rest = &rest[i..];
        if rest.starts_with("<ul>") {
            open += 1;
            level += 1;
            deepest = deepest.max(level);
        } else if rest.starts_with("</ul>") {
            close += 1;
            level = level.saturating_sub(1);
        }
        rest = &rest[1..];
    }
    (open, close, deepest)
}

#[test]
fn render_comments_thread_golden() {
    let d = golden_doc("confluence_comments");
    let start = d.find("<h2>Comments</h2>").unwrap_or(0);
    let section = &d[start..];
    assert_has(
        section,
        &[
            "<h2>Comments</h2><p>4 of 4</p><ul><li><section><h4>Comment <bdi>1</bdi></h4>\
             <div><bdi>User 1 (u1)</bdi>, <bdi>2026-10-11T10:00:00.000Z</bdi>, \
             <strong><bdi>footer</bdi></strong></div><p>comment <em>1</em></p></section>",
            // The reply nests under its parent, the reply to the reply under the reply.
            "</section><ul><li><section><h4>Comment <bdi>2</bdi></h4>",
            "</section><ul><li><section><h4>Comment <bdi>3</bdi></h4>",
            "<strong><bdi>inline</bdi></strong>",
            // Back to the top level.
            "</section></li></ul></li></ul></li><li><section><h4>Comment <bdi>4</bdi></h4>",
            // PD-103: no location in the answer.
            "<bdi>2026-10-14T10:00:00.000Z</bdi>, location not reported</div>",
        ],
    );
    assert_eq!(list_nesting(section), (3, 3, 3));
    assert_eq!(
        section.matches("<li>").count(),
        section.matches("</li>").count()
    );

    // Jumps, drops and huge depths keep the lists balanced; a reply is never more than one level
    // below the comment before it, and nesting stops at 32 levels.
    let mut p = named("confluence_comments");
    let depths: Vec<u32> = [5, 0, u32::MAX, 1, 3, 0].into_iter().chain(0..40).collect();
    if let PreviewBody::ConfluenceComments { comments, .. } = &mut p.body {
        let template = comments[0].clone();
        *comments = depths
            .iter()
            .enumerate()
            .map(|(i, &depth)| ConfluenceComment {
                id: i.to_string(),
                depth,
                ..template.clone()
            })
            .collect();
    }
    let d = doc(&p);
    assert_inert(&d, Platform::MacOsLinux);
    let (open, close, deepest) = list_nesting(&d);
    assert_eq!(open, close, "{d}");
    assert_eq!(deepest, 32);
    assert_eq!(d.matches("<li>").count(), d.matches("</li>").count());
    // The first comment (depth 5) starts at the top; the u32::MAX reply sits one level below the
    // comment before it.
    assert!(d.contains("<h2>Comments</h2><p>4 of 4</p><ul><li><section><h4>Comment <bdi>0</bdi>"));
    assert!(d.contains("</section></li><li><section><h4>Comment <bdi>1</bdi></h4>"));
    assert!(d.contains("</section><ul><li><section><h4>Comment <bdi>2</bdi></h4>"));

    // No comments.
    if let PreviewBody::ConfluenceComments { comments, count } = &mut p.body {
        comments.clear();
        *count = None;
    }
    assert!(doc(&p).contains("<h2>Comments</h2><p>none</p></section>"));
}

#[test]
fn render_content_write_card() {
    let d = golden_doc("confluence_content_write");
    assert_has(
        &d,
        &[
            "<li><bdi>a page titled 'Release plan' already exists in DEV</bdi></li>",
            "<section><h2>Summary</h2><div><bdi>Create page 'Release plan' in Development (DEV) \
             under 'Projects'</bdi></div>",
            "<tr><th><bdi>parent</bdi></th><td><bdi>Projects</bdi></td></tr>",
            "<h3>Body</h3><h2>Goals</h2><p>Ship <strong>M7</strong>, see notes (https://example.com/)</p>",
            "<h3>Storage constructs in the body</h3><table><tbody><tr><th>links</th>\
             <td><bdi>https://example.com/</bdi></td></tr></tbody></table>",
            "</section><section><h2>Requests to be sent</h2><h3>Request 0</h3>",
        ],
    );
}

#[test]
fn render_page_move_paths_golden() {
    let d = golden_doc("confluence_page_move");
    assert_has(
        &d,
        &[
            "</header><section><h2>Page move</h2><table><tbody>\
             <tr><th>page</th><td><bdi>Release plan</bdi></td></tr></tbody></table>\
             <h3>Old ancestor path</h3><ol><li><bdi>Home</bdi></li><li><bdi>Projects</bdi></li>\
             <li><bdi>Release plan</bdi></li></ol>\
             <h3>New ancestor path</h3><ol><li><bdi>Home</bdi></li><li><bdi>Archive</bdi></li>\
             <li><bdi>Release plan</bdi></li></ol>\
             <p>body not sent; title and body kept by Confluence</p></section>\
             <section><h2>Requests to be sent</h2><h3>Request 0</h3>",
            "<tr><th>method</th><td><bdi>PUT</bdi></td></tr>",
        ],
    );
}

#[test]
fn render_attachment_card_thumbnail_data_uri_only() {
    let d = golden_doc("confluence_attachment_card");
    assert_has(
        &d,
        &[
            "<tr><th>file name</th><td><bdi>logo<mark>⟨U+200B⟩</mark>.png</bdi></td></tr>",
            "<tr><th>size</th><td>70 bytes</td></tr>",
            "<tr><th>MIME type</th><td><bdi>image/png</bdi></td></tr>",
            &format!(
                "<tr><th>SHA-256</th><td><bdi>{}</bdi></td></tr>",
                "5a".repeat(32)
            ),
            "<tr><th>comment</th><td><bdi>new logo</bdi></td></tr>",
            &format!("<h3>Thumbnail</h3><img src=\"{PNG_DATA_URI}\" alt=\"\">"),
        ],
    );
    assert!(!d.contains("no thumbnail"));
    let thumb = |uri: Option<&str>| {
        let mut p = named("confluence_attachment_card");
        if let PreviewBody::AttachmentUpload {
            thumbnail_data_uri, ..
        } = &mut p.body
        {
            *thumbnail_data_uri = uri.map(Into::into);
        }
        let d = doc(&p);
        assert_inert(&d, Platform::MacOsLinux);
        d
    };
    // The four raster types are shown.
    for t in ["png", "jpeg", "gif", "webp"] {
        let uri = format!("data:image/{t};base64,R0lGODlhAQABAAAAACw=");
        assert!(
            thumb(Some(&uri)).contains(&format!("<img src=\"{uri}\" alt=\"\">")),
            "{t}"
        );
    }
    // Anything else is the PD-110 text and no image.
    for uri in [
        None,
        Some("https://evil.example/a.png"),
        Some("http://evil.example/a.png"),
        Some("data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+"),
        Some("data:image/svg+xml,<svg onload=alert(1)>"),
        Some("DATA:image/png;base64,AAAA"),
        Some(" data:image/png;base64,AAAA"),
        Some("data:image/png,AAAA"),
        Some("data:image/png;base64,"),
        Some("data:image/png;base64,AA\" onerror=\"alert(1)"),
        Some("data:image/png;base64,AA AA"),
        Some("data:text/html;base64,PHNjcmlwdD4="),
        Some("javascript:alert(1)"),
        Some(""),
    ] {
        let d = thumb(uri);
        assert!(!d.contains("<img"), "{uri:?}");
        assert!(
            d.contains(
                "<h3>Thumbnail</h3><p>no thumbnail (not an image, or larger than 2 MiB)</p>"
            ),
            "{uri:?}"
        );
    }
}

#[test]
fn render_attachment_collision_line() {
    let d = golden_doc("confluence_attachment_collision");
    assert_has(
        &d,
        &[
            "</header><section><h2>Attachment upload</h2>\
             <p><strong>attachment already exists</strong></p>\
             <div><bdi>attachment att9001, version 2, 1200 bytes</bdi></div>",
            "<tr><th>comment</th><td>none</td></tr>",
        ],
    );
    assert!(!d.contains("replaces existing attachment"));
    let d = doc(&named("confluence_attachment_card"));
    assert!(d.contains("<p>replaces existing attachment v3</p>"), "{d}");
    assert!(!d.contains("attachment already exists"));
}

#[test]
fn conflict_card_shows_intended_change() {
    let d = golden_doc("confluence_conflict_intended");
    let base = d
        .find("<h3>Diff from the agent's base to the current state</h3><table>")
        .unwrap_or(usize::MAX);
    let intended = d
        .find("<h3>The agent's intended change</h3><table>")
        .unwrap_or(usize::MAX);
    let deny = d.find("<li><strong>Deny</strong>").unwrap_or(usize::MAX);
    let requests = d
        .find("</section><section><h2>Requests to be sent</h2>")
        .unwrap_or(usize::MAX);
    assert!(base < intended && intended < deny && deny < requests, "{d}");
    assert_has(
        &d,
        &[
            "<section><h2>Changed since the agent read it</h2><div><bdi>conflict: page changed \
             since the agent read it (v5 → v6)</bdi></div>",
            "<td>+</td><td><pre><ins><bdi>current line</bdi></ins></pre></td>",
            "<td>+</td><td><pre><ins><bdi>new  line</bdi></ins></pre></td>",
            "<tr><th>method</th><td><bdi>PUT</bdi></td></tr>",
        ],
    );
    // Jira: no line lists, so no diff sections; the requests are shown (M6 T10 review M-5).
    let j = doc(&named("conflict"));
    assert!(!j.contains("Diff from the agent's base") && !j.contains("intended change"));
    assert!(j.contains("</section><section><h2>Requests to be sent</h2><h3>Request 0</h3>"));
    // Each list is capped on its own.
    let lines = |n: usize| -> Vec<DiffLine> {
        (0..n)
            .map(|i| DiffLine {
                op: DiffOp::Add,
                text: format!("l{i}\n"),
            })
            .collect()
    };
    let mut p = named("confluence_conflict_intended");
    if let PreviewBody::Conflict {
        base_to_current,
        intended,
        ..
    } = &mut p.body
    {
        *base_to_current = lines(DOC_MAX_DIFF_LINES + 2);
        *intended = lines(DOC_MAX_DIFF_LINES + 3);
    }
    let d = doc(&p);
    assert_has(
        &d,
        &[
            "<p>2 more lines not shown here; see Structured or Raw</p>\
             <h3>The agent's intended change</h3>",
            "<p>3 more lines not shown here; see Structured or Raw</p>",
        ],
    );
}

#[test]
fn render_digest_body_one_line() {
    let d = golden_doc("confluence_attachment_collision");
    let section = &d[d.find("<h2>Requests to be sent</h2>").unwrap_or(0)..];
    let line = format!(
        "<p><bdi>2000321 bytes, SHA-256 {} (not shown)</bdi></p>",
        "d4".repeat(32)
    );
    assert!(section.contains(&line), "{section}");
    assert!(
        section.ends_with(&format!("{line}</section></body></html>")),
        "{section}"
    );
    for other in ["Body:", "Binary body", "No body.", "<pre>"] {
        assert!(!section.contains(other), "{other}: {section}");
    }
    assert_eq!(section.matches("(not shown)").count(), 1);
}
