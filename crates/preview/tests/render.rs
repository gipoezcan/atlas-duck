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
    BodyView, CandidateRev, CommentView, ConstructList, FieldRow, IssueCard, ItemCount,
    OutcomeKind, PREVIEW_BUILDER_VERSION, PREVIEW_CSS, PREVIEW_CSS_HASH, Platform, Preview,
    PreviewBody, PreviewHeader, ProvenanceRow, RENDER_VERSIONS, RawPager, RequestView,
    ScriptItemKind, json_tree, sanitize_html,
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
        preselect: None,
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

/// One preview per `PreviewBody` variant (14), each with strings that exercise escaping.
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
        ("script_result", script_preview(ScriptItemKind::Result)),
    ]
}

/// The source of the script fixtures: a tab inside a line, a trailing space before `\r\n`, a
/// markup-looking string, no final newline.
const SCRIPT_SOURCE: &str = "const r = atlas.call(\"jira.search\", {jql: \"project = PROJ\"});\n\
                             \tif (r.total > 0) {\n\
                             \x20 atlas.log(\"<b>found</b>\"); \r\n\
                             }\n\
                             return r;";

/// A script release item as core builds it (M8 T17): the candidate view (the JSON tree of the
/// result, or of `{script_error}`), then the raw source, host calls, logs and stderr.
fn script_preview(item: ScriptItemKind) -> Preview {
    let candidate = match item {
        ScriptItemKind::Result => json!({ "count": 1, "keys": ["PROJ-1"] }),
        ScriptItemKind::ErrorDetails => json!({ "script_error": {
            "class": "TypeError",
            "message": "cannot read property 'key' of undefined",
            "stack": "    at main (script.js:3:12)\n    at <anonymous>",
            "elapsed": 412,
            "logs": ["fetched 0 issues"],
        }}),
    };
    let mut p = preview(
        "script",
        PreviewBody::Script {
            item,
            view: Box::new(PreviewBody::JsonTree {
                tree: json_tree(&candidate),
            }),
            source: SCRIPT_SOURCE.into(),
            provenance: vec![
                ProvenanceRow {
                    call_id: 1,
                    op_id: "jira.search".into(),
                    instance: "jira-main".into(),
                    target_display: "project = PROJ".into(),
                    outcome: "ok".into(),
                },
                ProvenanceRow {
                    call_id: 2,
                    op_id: "jira.issue.get".into(),
                    instance: "jira-main".into(),
                    target_display: "PROJ-1".into(),
                    outcome: "rejected:upstream_http".into(),
                },
            ],
            logs: vec!["fetched 0 issues".into(), "two  spaces".into()],
            logs_note: (item == ScriptItemKind::ErrorDetails).then(|| {
                "output was cut at its size bound; the audit record keeps the full text".into()
            }),
            stderr: "warning: deprecated\n".into(),
        },
        vec![Warning::new(
            WarningId::HostCallsLossy,
            warning::host_calls_lossy(1),
        )],
    );
    p.header.instance_alias = String::new();
    p.header.op_id = "script.run".into();
    p.header.fields_included = Vec::new();
    p
}

/// The part of `d` from `<h2>{title}</h2>` up to the end of its section (the next `</section>`).
fn script_section<'a>(d: &'a str, title: &str) -> &'a str {
    let open = format!("<h2>{title}</h2>");
    let at = d.find(&open).unwrap_or(d.len());
    let end = d[at..].find("</section>").map_or(d.len(), |i| at + i);
    &d[at..end]
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
    assert_eq!(all.len(), 14, "one golden per PreviewBody variant");
    all.push((
        "script_error_details",
        script_preview(ScriptItemKind::ErrorDetails),
    ));
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
        n, 16,
        "14 variants + the script error details + the header golden"
    );
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
        // M8 T18: the script item; source, provenance, logs and stderr are raw (T17).
        _ => PreviewBody::Script {
            item: if r(0).len().is_multiple_of(2) {
                ScriptItemKind::Result
            } else {
                ScriptItemKind::ErrorDetails
            },
            view: Box::new(PreviewBody::JsonTree {
                tree: json_tree(&json!({ r(0): [r(1), { "script_error": r(2) }] })),
            }),
            source: format!("{}\n{}\r\n{}", r(2), r(3), r(4)),
            provenance: vec![ProvenanceRow {
                call_id: 7,
                op_id: r(4),
                instance: r(5),
                target_display: r(6),
                outcome: r(7),
            }],
            logs: vec![r(8), r(9)],
            logs_note: Some(r(10)),
            stderr: r(11),
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
        kind in 0usize..14,
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
    assert_eq!(PREVIEW_BUILDER_VERSION, "pb2;render3;icu-17.0;emoji-17.0");
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

// ---- M8 T18: script items (§6.3 Script result / Script error details, Δ5) ---------------------

/// The "hidden in preview" bytes of the document `d`.
fn hidden_bytes(d: &str) -> u64 {
    let label = "<tr><th>hidden in preview</th><td>";
    let at = d.find(label).map_or(0, |i| i + label.len());
    d[at..]
        .split(' ')
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

fn set_script(p: &mut Preview, f: impl FnOnce(&mut PreviewBody, &mut Vec<ProvenanceRow>)) {
    let mut body = p.body.clone();
    if let PreviewBody::Script {
        view, provenance, ..
    } = &mut body
    {
        f(view, provenance);
    }
    p.body = body;
}

#[test]
fn script_result_document_table_and_tree() {
    let p = script_preview(ScriptItemKind::Result);
    let d = doc(&p);
    assert_inert(&d, Platform::MacOsLinux);
    // The item heading leads the body; the candidate view (the tree) is inside it.
    assert!(
        d.contains(
            "</header><section><h2>Script result</h2><section><h2>Result (JSON tree)</h2>\
             <ul><li>object, 2 keys"
        ),
        "{d}"
    );
    assert!(
        d.contains("<li><code><bdi>count</bdi></code>: <code><bdi>1</bdi></code></li>"),
        "{d}"
    );
    // The sections in plan order, each once.
    let titles = [
        "<h2>Script result</h2>",
        "<h2>Result (JSON tree)</h2>",
        "<h2>Script source</h2>",
        "<h2>Host calls</h2>",
        "<h2>atlas.log</h2>",
        "<h2>stderr</h2>",
    ];
    let mut last = 0;
    for t in titles {
        assert_eq!(d.matches(t).count(), 1, "{t}\n{d}");
        let at = d.find(t).unwrap_or(0);
        assert!(at > last, "{t} out of order\n{d}");
        last = at;
    }
    // The source, line-numbered; a tab inside a line stays, trailing space and CR are marked.
    let source = script_section(&d, "Script source");
    for row in [
        // (The document's last sanitizer pass serializes a text `"` as is.)
        "<tr><td>1</td><td><pre><bdi>const r = atlas.call(\"jira.search\", \
         {jql: \"project = PROJ\"});</bdi></pre></td></tr>",
        "<tr><td>2</td><td><pre><bdi>\tif (r.total &gt; 0) {</bdi></pre></td></tr>",
        "<tr><td>3</td><td><pre><bdi>  atlas.log(\"&lt;b&gt;found&lt;/b&gt;\");\
         <mark>⟨U+0020⟩</mark><mark>⟨U+000D⟩</mark></bdi></pre></td></tr>",
        "<tr><td>4</td><td><pre><bdi>}</bdi></pre></td></tr>",
        "<tr><td>5</td><td><pre><bdi>return r;</bdi></pre></td></tr></tbody></table>",
    ] {
        assert!(source.contains(row), "{row}\n{source}");
    }
    assert!(!source.contains("<td>6</td>"), "{source}");
    // The leading spaces of line 3 show without the stylesheet.
    assert!(
        shown_without_css(source).contains("3  atlas.log"),
        "{source}"
    );
    // Host calls: one row per call, from the request.
    let calls = script_section(&d, "Host calls");
    for want in [
        "<thead><tr><th>call</th><th>operation</th><th>instance</th><th>target</th>\
         <th>outcome</th></tr></thead>",
        "<tr><td>1</td><td><code><bdi>jira.search</bdi></code></td><td><bdi>jira-main</bdi></td>\
         <td><bdi>project = PROJ</bdi></td><td><code><bdi>ok</bdi></code></td></tr>",
        "<tr><td>2</td><td><code><bdi>jira.issue.get</bdi></code></td>\
         <td><bdi>jira-main</bdi></td><td><bdi>PROJ-1</bdi></td>\
         <td><code><bdi>rejected:upstream_http</bdi></code></td></tr>",
    ] {
        assert!(calls.contains(want), "{want}\n{calls}");
    }
    // atlas.log: one item per line, a run of spaces kept; a result's logs here are cut by no note.
    let logs = script_section(&d, "atlas.log");
    assert!(
        logs.contains(
            "<ul><li><bdi>fetched 0 issues</bdi></li><li><pre><bdi>two  spaces</bdi></pre></li></ul>"
        ),
        "{logs}"
    );
    assert!(!logs.contains("audit record"), "{logs}");
    assert!(
        d.contains("<h2>stderr</h2><pre><code><bdi>warning: deprecated\n</bdi></code></pre>"),
        "{d}"
    );
    // The host-computed lossy warning is on the Info line.
    assert!(d.contains(&warning::host_calls_lossy(1)), "{d}");

    // A table view (the M7 list rule) goes through the table arm.
    let mut t = p.clone();
    set_script(&mut t, |view, _| {
        *view = PreviewBody::Table {
            columns: vec!["key".into()],
            rows: vec![vec!["PROJ-1".into()]],
            count: None,
        };
    });
    let d = doc(&t);
    assert!(
        d.contains(
            "<section><h2>Script result</h2><section><h2>Results</h2><table><thead><tr>\
             <th><bdi>key</bdi></th></tr></thead><tbody><tr><td><bdi>PROJ-1</bdi></td></tr>"
        ),
        "{d}"
    );
    assert_inert(&d, Platform::Windows);

    // Nothing to show: `none` in each section.
    let mut e = p.clone();
    if let PreviewBody::Script {
        source,
        provenance,
        logs,
        stderr,
        ..
    } = &mut e.body
    {
        source.clear();
        provenance.clear();
        logs.clear();
        stderr.clear();
    }
    let d = doc(&e);
    for t in ["Script source", "Host calls", "atlas.log", "stderr"] {
        assert!(d.contains(&format!("<h2>{t}</h2><p>none</p>")), "{t}\n{d}");
    }
}

#[test]
fn script_source_and_logs_are_escaped_text() {
    let evil = "<script>alert(1)</script><img src=x onerror=alert(1)>\u{202E}⟨U+202E⟩";
    // Escaped, the flagged character marked, the literal escape text escaped delimiter by
    // delimiter (so it cannot pass for a marked escape: the renderer display-escapes these raw
    // strings itself).
    let shown = "&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;\
                 <mark>⟨U+202E⟩</mark><mark>⟨U+27E8⟩</mark>U+202E<mark>⟨U+27E9⟩</mark>";
    for item in [ScriptItemKind::Result, ScriptItemKind::ErrorDetails] {
        let mut p = script_preview(item);
        if let PreviewBody::Script {
            source,
            provenance,
            logs,
            logs_note,
            stderr,
            ..
        } = &mut p.body
        {
            *source = format!("{evil}\n{evil}");
            *provenance = vec![ProvenanceRow {
                call_id: 1,
                op_id: evil.into(),
                instance: evil.into(),
                target_display: evil.into(),
                outcome: evil.into(),
            }];
            *logs = vec![evil.into()];
            *logs_note = Some(evil.into());
            *stderr = evil.into();
        }
        let d = doc(&p);
        for platform in [Platform::MacOsLinux, Platform::Windows] {
            assert_inert(&render::document(&p, platform), platform);
        }
        assert!(!d.contains('\u{202E}'));
        let body = body_of(&d).to_ascii_lowercase();
        assert!(!body.contains("<script") && !body.contains("<img"), "{d}");
        for (title, n) in [
            ("Script source", 2),
            ("Host calls", 4),
            ("atlas.log", 2),
            ("stderr", 1),
        ] {
            let s = script_section(&d, title);
            assert_eq!(s.matches(shown).count(), n, "{title}\n{s}");
            // Each one bidi-isolated.
            assert_eq!(
                s.matches(&format!("<bdi>{shown}</bdi>")).count(),
                n,
                "{title}\n{s}"
            );
        }
    }
}

#[test]
fn script_error_document_fields() {
    let p = script_preview(ScriptItemKind::ErrorDetails);
    let d = doc(&p);
    assert_inert(&d, Platform::MacOsLinux);
    assert!(
        d.contains(
            "</header><section><h2>Script error details</h2><section>\
             <h2>Result (JSON tree)</h2>"
        ),
        "{d}"
    );
    assert!(!d.contains("<h2>Script result</h2>"));
    // Class, message, stack (its leading spaces and line break kept) and elapsed time.
    for want in [
        "<li><code><bdi>class</bdi></code>: \"<bdi>TypeError</bdi>\"</li>",
        "<li><code><bdi>message</bdi></code>: \
         \"<bdi>cannot read property 'key' of undefined</bdi>\"</li>",
        "<li><code><bdi>stack</bdi></code>: <pre>\"<bdi>    at main (script.js:3:12)\n    \
         at &lt;anonymous&gt;</bdi>\"</pre></li>",
        "<li><code><bdi>elapsed</bdi></code>: <code><bdi>412</bdi></code></li>",
    ] {
        assert!(d.contains(want), "{want}\n{d}");
    }
    // Provenance, the logs with the cut note, stderr.
    assert!(
        script_section(&d, "Host calls").contains("<td><code><bdi>rejected:upstream_http</bdi>"),
        "{d}"
    );
    let logs = script_section(&d, "atlas.log");
    assert!(
        logs.contains(
            "</ul><div><bdi>output was cut at its size bound; the audit record keeps the full \
             text</bdi></div>"
        ),
        "{logs}"
    );
    assert!(
        logs.contains("<li><bdi>fetched 0 issues</bdi></li>"),
        "{logs}"
    );
    assert!(script_section(&d, "stderr").contains("warning: deprecated"));
    // The note shows even with no log line (it may be about stderr or the error text).
    let mut q = p.clone();
    if let PreviewBody::Script { logs, .. } = &mut q.body {
        logs.clear();
    }
    let d = doc(&q);
    assert!(
        script_section(&d, "atlas.log")
            .contains("<p>none</p><div><bdi>output was cut at its size bound;"),
        "{d}"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// S-06 for the script item alone (the variant is also among the kinds of
    /// `s06_document_has_no_active_content`).
    #[test]
    fn s06_script_document_has_no_active_content(
        strings in prop::collection::vec(text(), 12),
        windows in any::<bool>(),
    ) {
        let platform = if windows { Platform::Windows } else { Platform::MacOsLinux };
        let p = arbitrary_preview(13, &strings);
        let is_script = matches!(p.body, PreviewBody::Script { .. });
        prop_assert!(is_script);
        assert_inert(&render::document(&p, platform), platform);
    }
}

#[test]
fn doc_caps_note_for_long_logs() {
    let base = script_preview(ScriptItemKind::Result);
    let with = |f: &dyn Fn(&mut String, &mut Vec<ProvenanceRow>, &mut Vec<String>, &mut String)| {
        let mut p = base.clone();
        if let PreviewBody::Script {
            source,
            provenance,
            logs,
            stderr,
            ..
        } = &mut p.body
        {
            f(source, provenance, logs, stderr);
        }
        p
    };

    // atlas.log past its row cap: two lines left out, noted and counted.
    let p = with(&|_, _, logs, _| {
        *logs = (0..DOC_MAX_ROWS + 2).map(|i| format!("log {i}")).collect();
    });
    let d = doc(&p);
    let logs = script_section(&d, "atlas.log");
    assert!(
        logs.contains("<li><bdi>log 1999</bdi></li></ul><p>2 more lines not shown here; see Structured or Raw</p>"),
        "{logs}"
    );
    assert!(!logs.contains("<bdi>log 2000</bdi>"));
    assert_eq!(
        hidden_bytes(&d),
        ("log 2000".len() + "log 2001".len()) as u64
    );
    assert_inert(&d, Platform::MacOsLinux);

    // The source past its line cap: the rest (with its line ends) left out.
    let p = with(&|source, _, _, _| {
        *source = (0..=DOC_MAX_DIFF_LINES)
            .map(|i| format!("x{i}\n"))
            .collect();
    });
    let d = doc(&p);
    let source = script_section(&d, "Script source");
    assert!(
        source.contains(
            "<tr><td>5000</td><td><pre><bdi>x4999</bdi></pre></td></tr></tbody></table>\
             <p>1 more lines not shown here; see Structured or Raw</p>"
        ),
        "{}",
        &source[source.len().saturating_sub(400)..]
    );
    assert_eq!(hidden_bytes(&d), "x5000\n".len() as u64);
    // A source line that fills the byte budget: it is cut, the lines after it left out whole.
    let p = with(&|source, _, _, _| {
        *source = format!("{}\nafter1\nafter2", "s".repeat(DOC_MAX_BYTES));
    });
    let d = doc(&p);
    let source = script_section(&d, "Script source");
    assert!(
        source.ends_with("…</bdi></pre></td></tr></tbody></table><p>2 more lines not shown here; see Structured or Raw</p>"),
        "{}",
        &source[source.len().saturating_sub(400)..]
    );
    assert!(!source.contains("<td>2</td>"));

    // Host calls past the row cap.
    let p = with(&|_, provenance, _, _| {
        *provenance = (0..=DOC_MAX_ROWS as u64)
            .map(|i| ProvenanceRow {
                call_id: i,
                op_id: "jira.issue.get".into(),
                instance: "jira-main".into(),
                target_display: format!("PROJ-{i}"),
                outcome: "ok".into(),
            })
            .collect();
    });
    let d = doc(&p);
    let calls = script_section(&d, "Host calls");
    assert!(
        calls.contains("</tbody></table><p>1 more rows not shown here; see Structured or Raw</p>"),
        "{}",
        &calls[calls.len().saturating_sub(400)..]
    );
    assert!(calls.contains("PROJ-1999") && !calls.contains("PROJ-2000"));
    assert_eq!(
        hidden_bytes(&d),
        ("jira.issue.get".len() + "jira-main".len() + "PROJ-2000".len() + "ok".len()) as u64
    );

    // stderr past the byte budget: cut, counted, noted at the end of the body; nothing after it
    // in the document is lost silently.
    let p = with(&|_, _, _, stderr| {
        *stderr = "e".repeat(DOC_MAX_BYTES + 10);
    });
    let d = doc(&p);
    assert!(d.contains("…</bdi></code></pre></section>"), "cut");
    assert!(hidden_bytes(&d) >= 10);
    assert!(d.contains(&format!(
        "<p>{} more bytes not shown here; see Structured or Raw</p></body></html>",
        hidden_bytes(&d)
    )));

    // A huge log fills the budget: the log lines after it are left out and counted.
    let p = with(&|_, _, logs, _| {
        *logs = vec!["l".repeat(DOC_MAX_BYTES), "after".into(), "after2".into()];
    });
    let d = doc(&p);
    assert!(!script_section(&d, "atlas.log").contains("<bdi>after"));
    assert!(script_section(&d, "atlas.log").contains("<p>2 more lines not shown here"));
    assert!(body_of(&d).len() < DOC_MAX_BYTES + 64 * 1024);
}
