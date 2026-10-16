#![cfg(feature = "testing")]
//! M7 Task 12b: the Confluence read previews (§6.3, §6.2, §6.4; §13 U-34, S-12; PD-100, PD-103,
//! PD-114). `confluence.page.get` and `confluence.page.history` with `version` preview as a page
//! card (the released Markdown rendered locally, the released storage rendered locally and
//! labelled, or the server's `view` HTML sanitized under the Caution `server_rendered_view`);
//! `confluence.comment.list` as a depth-first thread; the list ops as tables
//! (`generic::list_table`); single objects and the history summary keep the JSON tree. The Raw
//! tab pages the candidate bytes unchanged.
//!
//! (The plan puts these tests in `confluence_reads.rs`; they live here because another task
//! commits that file concurrently.)

mod common;

use atlas_duck_atlassian::testing::{MockDc, fixtures};
use atlas_duck_convert::ConversionReport;
use atlas_duck_core::ops::{PreviewCtx, PreviewInput, PreviewModel, ReadView, op_table};
use atlas_duck_core::testing::Harness;
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_preview::warning::{Level, Warning, WarningId};
use atlas_duck_preview::{ConfluenceComment, Preview, PreviewBody};
use common::confluence::{
    PAGE_EXAMPLE_STORAGE, content_path, mount_attachments, mount_children, mount_comments,
    mount_history_summary, mount_history_version, mount_page, mount_page_view, mount_search,
    mount_title_lookup, mount_users, page_with_storage, page_with_view, server_example,
};
use common::{TestError, TestResult, de, request_id};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const PAGE_GET: &str = "confluence.page.get";
const PAGE_HISTORY: &str = "confluence.page.history";
const COMMENT_LIST: &str = "confluence.comment.list";
const ID: &str = "65537";

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no wiki mock".into())
}

/// Submits, expects `pending`, and waits until the read waits for release.
async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    Ok(id)
}

/// Queues `op` and opens its preview.
async fn opened(h: &Harness, op: &str, params: Value) -> Result<(String, Preview), TestError> {
    let id = queued(h, op, params).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    Ok((id, preview))
}

/// Releases `id` and returns the released envelope.
async fn released(h: &Harness, id: &str) -> Result<Envelope, TestError> {
    h.approver().release(id).map_err(de)?;
    let env = h.await_(id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    Ok(env)
}

fn json_answer(mock: &MockDc, body: &Value) -> ResponseTemplate {
    mock.response(200)
        .set_body_raw(body.to_string(), "application/json")
}

/// `GET <p>` (any query) answers `body`.
async fn mount_json(mock: &MockDc, p: &str, body: &Value) {
    Mock::given(method("GET"))
        .and(path(mock.path(p)))
        .respond_with(json_answer(mock, body))
        .mount(mock.server())
        .await;
}

fn ids_at(warnings: &[Warning], level: Level) -> Vec<WarningId> {
    warnings
        .iter()
        .filter(|w| w.level == level)
        .map(|w| w.id)
        .collect()
}

struct PageCard<'a> {
    title: &'a str,
    space: &'a str,
    version: Option<u64>,
    ancestors: &'a [String],
    format: &'a str,
    body_html: &'a str,
    conversion: Option<atlas_duck_preview::ConversionFacts>,
}

fn page_card(body: &PreviewBody) -> Result<PageCard<'_>, TestError> {
    match body {
        PreviewBody::ConfluencePage {
            title,
            space,
            version,
            ancestors,
            format,
            body_html,
            conversion,
        } => Ok(PageCard {
            title,
            space,
            version: *version,
            ancestors,
            format,
            body_html,
            conversion: *conversion,
        }),
        other => Err(format!("not a page card: {other:?}").into()),
    }
}

/// No active content and no remote resource survives in a preview body (§6.4, S-12): no image
/// source except a `data:` one, no script, link, style or event handler.
fn assert_inert(html: &str) {
    for needle in [
        "<script", "<a ", "href", "style=", "<style", "<iframe", "onerror", "srcset",
    ] {
        assert!(!html.contains(needle), "{needle} in {html}");
    }
    let mut rest = html;
    while let Some(at) = rest.find("src=") {
        let after = &rest[at + 4..];
        assert!(after.starts_with("\"data:"), "remote src in {html}");
        rest = after;
    }
}

// ---- the page card (§6.3, U-34, S-12) ------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u34_default_page_get_zero_caution() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(
        mock,
        ID,
        &page_with_storage("<p>Check the <em>build</em>.</p>"),
    )
    .await;
    let (_, preview) = opened(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert!(
        ids_at(&preview.warnings, Level::Caution).is_empty(),
        "{:?}",
        preview.warnings
    );
    assert!(preview.warnings.is_empty(), "{:?}", preview.warnings);
    let card = page_card(&preview.body)?;
    assert_eq!(card.title, "Release checklist");
    assert_eq!(card.space, "Documentation (DOC)");
    assert_eq!(card.version, Some(7));
    assert_eq!(card.ancestors, ["Home"]);
    assert_eq!(card.format, "markdown");
    assert_eq!(card.body_html, "<p>Check the <em>build</em>.</p>\n");
    let facts = card.conversion.ok_or("no conversion facts")?;
    assert!(!facts.lossy && !facts.fallback, "{facts:?}");
    assert_eq!(preview.header.op_id, PAGE_GET);
    assert_eq!(
        (preview.header.bidi_controls, preview.header.other_invisible),
        (0, 0)
    );
    // The card leaves out the page's links, ids and version author: counted, Raw has them.
    assert!(preview.header.hidden_in_preview_bytes > 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u34_view_format_exactly_one_caution() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page_view(
        mock,
        ID,
        &page_with_view("<p>Rendered <b>by the server</b>.</p>"),
    )
    .await;
    let (_, preview) = opened(&h, PAGE_GET, json!({ "id": ID, "format": "view" })).await?;
    let cautions: Vec<&Warning> = preview
        .warnings
        .iter()
        .filter(|w| w.level == Level::Caution)
        .collect();
    let [only] = cautions.as_slice() else {
        return Err(format!("{} Cautions: {:?}", cautions.len(), preview.warnings).into());
    };
    assert_eq!(only.id, WarningId::ServerRenderedView);
    assert_eq!(
        only.text,
        "server-rendered view: macros may include content from other pages"
    );
    let card = page_card(&preview.body)?;
    assert_eq!(card.format, "view");
    assert_eq!(card.body_html, "<p>Rendered <b>by the server</b>.</p>");
    assert!(card.conversion.is_none());
    assert!(preview.body.implied_warning_present(&preview.warnings));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u34_confluence_info_warnings_are_info() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    // An unknown macro (`jira` is server-generated content) and a mention the lookup cannot
    // resolve.
    let storage = r#"<p>See <ac:link><ri:user ri:userkey="k404"/></ac:link>.</p><ac:structured-macro ac:name="jira"><ac:parameter ac:name="key">ABC-1</ac:parameter></ac:structured-macro>"#;
    mount_page(mock, ID, &page_with_storage(storage)).await;
    mount_users(mock, &[("k404", None)]).await;
    let (_, preview) = opened(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert!(
        ids_at(&preview.warnings, Level::Caution).is_empty(),
        "{:?}",
        preview.warnings
    );
    assert_eq!(
        ids_at(&preview.warnings, Level::Info),
        [WarningId::UnknownMacros, WarningId::UnresolvedMention]
    );
    let text = |id: WarningId| {
        preview
            .warnings
            .iter()
            .find(|w| w.id == id)
            .map(|w| w.text.clone())
    };
    assert_eq!(
        text(WarningId::UnknownMacros).as_deref(),
        Some("body contains unknown macros")
    );
    assert_eq!(
        text(WarningId::UnresolvedMention).as_deref(),
        Some("mention could not be resolved")
    );
    let card = page_card(&preview.body)?;
    let facts = card.conversion.ok_or("no conversion facts")?;
    assert_eq!(facts.unresolved_users, 1);
    assert!(facts.lossy && facts.macros >= 1, "{facts:?}");
    assert!(card.body_html.contains("@user:k404"), "{}", card.body_html);

    // The third Confluence Info, `cql_broad` (Task 12a), is Info too.
    let search: Value = serde_json::from_str(fixtures::CONFLUENCE_SEARCH_PAGE)?;
    mount_search(mock, &search).await;
    let (_, preview) = opened(&h, "confluence.search", json!({ "cql": "text ~ \"x\"" })).await?;
    let broad = preview
        .warnings
        .iter()
        .find(|w| w.id == WarningId::CqlBroad)
        .ok_or("no cql_broad")?;
    assert_eq!(broad.level, Level::Info);
    for id in [
        WarningId::UnknownMacros,
        WarningId::UnresolvedMention,
        WarningId::CqlBroad,
    ] {
        assert_eq!(id.level(), Level::Info, "{id:?}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s12_confluence_page_preview_neutralizes_remote_and_marks_invisible() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let storage = concat!(
        "<p>Look \u{202e}here</p>",
        "<p><img src=\"https://evil.example/x.png\"/></p>",
        "<ac:image><ri:url ri:value=\"https://evil.example/y.png\"/></ac:image>",
        "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>",
        "<script>alert(2)</script>",
        "<p><a href=\"https://evil.example/z\">z</a></p>",
    );
    mount_page(mock, ID, &page_with_storage(storage)).await;
    for format in ["markdown", "storage"] {
        let (_, preview) = opened(&h, PAGE_GET, json!({ "id": ID, "format": format })).await?;
        let card = page_card(&preview.body)?;
        assert_inert(card.body_html);
        // The local renderer writes images as text (`[image: …]`), never an element.
        assert!(!card.body_html.contains("<img"), "{}", card.body_html);
        // The bidi control is visible as an escape, not a live character.
        assert!(
            card.body_html.contains("\u{27e8}U+202E\u{27e9}"),
            "{}",
            card.body_html
        );
        assert!(!card.body_html.contains('\u{202e}'));
        assert_eq!(preview.header.bidi_controls, 1, "{format}");
        assert!(
            ids_at(&preview.warnings, Level::Caution).contains(&WarningId::BidiControls),
            "{format}: {:?}",
            preview.warnings
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s12_view_format_server_html_sanitized() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let html = concat!(
        "<p style=\"color:red\" class=\"x\">styled</p>",
        "<img src=\"https://evil.example/a.png\"/>",
        "<img src=https://evil.example/b.png>",
        "<a href=\"https://evil.example/\">link</a>",
        "<script>alert(1)</script>",
        "<p onclick=\"x()\">click</p>",
    );
    mount_page_view(mock, ID, &page_with_view(html)).await;
    let (_, preview) = opened(&h, PAGE_GET, json!({ "id": ID, "format": "view" })).await?;
    let card = page_card(&preview.body)?;
    assert_inert(card.body_html);
    assert!(!card.body_html.contains("class="), "{}", card.body_html);
    assert!(!card.body_html.contains("onclick"), "{}", card.body_html);
    assert!(card.body_html.contains("styled") && card.body_html.contains("link"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn storage_format_is_rendered_locally_and_labelled() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let storage = r#"<p>Owner <ac:link><ri:user ri:userkey="k1"/></ac:link>.</p><ac:structured-macro ac:name="jira"/>"#;
    mount_page(mock, ID, &page_with_storage(storage)).await;
    let (_, preview) = opened(&h, PAGE_GET, json!({ "id": ID, "format": "storage" })).await?;
    let card = page_card(&preview.body)?;
    assert_eq!(card.format, "storage");
    assert!(
        card.body_html
            .starts_with("<p><strong>rendered locally from storage</strong></p>"),
        "{}",
        card.body_html
    );
    // Rendered with an empty map: the mention shows as its key; nothing was looked up.
    assert!(card.body_html.contains("@user:k1"), "{}", card.body_html);
    assert!(
        card.body_html.contains("[macro: jira {}]"),
        "{}",
        card.body_html
    );
    // The release is the storage as sent: no conversion facts, no unresolved mention.
    assert!(card.conversion.is_none());
    assert_eq!(
        ids_at(&preview.warnings, Level::Info),
        [WarningId::UnknownMacros]
    );
    assert!(ids_at(&preview.warnings, Level::Caution).is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_history_version_is_a_page_card_and_the_summary_a_tree() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let mut old = page_with_storage("<p>Old text.</p>");
    old["version"]["number"] = json!(3);
    mount_history_version(mock, ID, 3, &old).await;
    let (id, preview) = opened(&h, PAGE_HISTORY, json!({ "id": ID, "version": 3 })).await?;
    let card = page_card(&preview.body)?;
    assert_eq!(card.version, Some(3));
    assert_eq!(card.body_html, "<p>Old text.</p>\n");
    released(&h, &id).await?;

    let summary = atlas_duck_registry::get(PAGE_HISTORY)
        .ok_or("no registry op")?
        .result_example_json();
    mount_history_summary(mock, ID, &summary).await;
    let (_, preview) = opened(&h, PAGE_HISTORY, json!({ "id": ID, "format": "view" })).await?;
    assert!(
        matches!(preview.body, PreviewBody::JsonTree { .. }),
        "{:?}",
        preview.body
    );
    // `format` is ignored for the summary: no view Caution (the read of the same page above
    // makes it a similar request, a Caution of its own).
    assert!(
        !ids_at(&preview.warnings, Level::Caution).contains(&WarningId::ServerRenderedView),
        "{:?}",
        preview.warnings
    );
    Ok(())
}

/// §6.3 "Rendered Markdown + Raw tab" (plan review m-20): the generic Raw pager pages the
/// candidate of a Markdown read, which is exactly what the agent receives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confluence_page_raw_tab_pages_candidate() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let prose: String = "Lorem ipsum dolor sit amet. ".repeat(40_000);
    mount_page(mock, ID, &page_with_storage(&format!("<p>{prose}</p>"))).await;
    let (id, preview) = opened(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert!(preview.raw.page_count > 1, "{:?}", preview.raw);
    assert_eq!(preview.raw.total_bytes, preview.header.byte_size);
    let rev = preview.candidate_rev;
    let mut bytes = Vec::new();
    for page in 0..preview.raw.page_count {
        bytes.extend(h.decisions().raw_page(&id, rev, page).map_err(de)?.bytes);
    }
    assert_eq!(u64::try_from(bytes.len())?, preview.raw.total_bytes);
    // The card shows a capped rendering; Raw has every byte, counted as hidden.
    let card = page_card(&preview.body)?;
    assert!(
        card.body_html.contains("more bytes (see Raw)"),
        "cut not said"
    );
    assert!(preview.header.hidden_in_preview_bytes > 700_000);
    let env = released(&h, &id).await?;
    let result = env.data.ok_or("no data")?["result"].clone();
    assert_eq!(bytes, serde_json::to_vec(&result)?);
    assert_eq!(result["body"]["format"], "markdown");
    Ok(())
}

/// Δ4 f: the registry's `confluence.page.get` example is the release of the same page answered
/// with the storage `<p>Version 1.4 fixes the login.</p>` (`common::confluence::server_example`,
/// which the X-09 mounts answer with).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_get_example_is_the_markdown_release_of_its_storage() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let example = atlas_duck_registry::get(PAGE_GET)
        .ok_or("no registry op")?
        .result_example_json();
    let answer = server_example(PAGE_GET)?;
    assert_eq!(answer["body"]["storage"]["value"], PAGE_EXAMPLE_STORAGE);
    mount_page(mock, "123456", &answer).await;
    let id = queued(&h, PAGE_GET, json!({ "id": "123456" })).await?;
    let env = released(&h, &id).await?;
    assert_eq!(env.data.ok_or("no data")?["result"], example);
    Ok(())
}

// ---- comments (§6.3, PD-103) ---------------------------------------------------------------

/// A comment of `confluence.comment.list` (`expand=body.storage,history,ancestors,version`);
/// `parents` is its `ancestors` (root first, the parent last).
fn comment(id: &str, parents: &[&str], location: Option<&str>, storage: &str) -> Value {
    let mut c = json!({
        "id": id,
        "type": "comment",
        "status": "current",
        "title": format!("Re: {id}"),
        "body": {"storage": {"value": storage, "representation": "storage"}},
        "history": {
            "createdBy": {"type": "known", "username": format!("u{id}"), "displayName": format!("User {id}")},
            "createdDate": format!("2026-10-1{}T10:00:00.000Z", id.len() % 10)
        },
        "ancestors": parents.iter().map(|p| json!({"id": p, "type": "comment"})).collect::<Vec<_>>(),
        "version": {"number": 1},
        "_links": {"webui": format!("/display/DOC/Release+checklist?focusedCommentId={id}")}
    });
    if let Some(l) = location {
        c["extensions"] = json!({ "location": l });
    }
    c
}

fn comment_page(comments: Vec<Value>) -> Value {
    let size = comments.len();
    json!({
        "results": comments,
        "start": 0,
        "limit": 25,
        "size": size,
        "_links": {"base": "https://wiki.corp.example", "context": ""}
    })
}

fn thread(body: &PreviewBody) -> Result<&[ConfluenceComment], TestError> {
    match body {
        PreviewBody::ConfluenceComments { comments, .. } => Ok(comments),
        other => Err(format!("not a comment thread: {other:?}").into()),
    }
}

/// `(id, depth)` of each comment in order.
fn shape(comments: &[ConfluenceComment]) -> Vec<(&str, u32)> {
    comments.iter().map(|c| (c.id.as_str(), c.depth)).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comments_preview_threaded() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let page = comment_page(vec![
        comment("801", &[], Some("footer"), "<p>first <em>one</em></p>"),
        comment("802", &[], None, "<p>second</p>"),
        comment("803", &["802"], Some("inline"), "<p>a reply</p>"),
    ]);
    mount_comments(mock, ID, &[page]).await;
    let (_, preview) = opened(&h, COMMENT_LIST, json!({ "id": ID })).await?;
    let comments = thread(&preview.body)?;
    assert_eq!(shape(comments), [("801", 0), ("802", 0), ("803", 1)]);
    let first = comments.first().ok_or("no comment")?;
    assert_eq!(first.author.as_deref(), Some("User 801 (u801)"));
    assert_eq!(first.location.as_deref(), Some("footer"));
    assert_eq!(first.body_html, "<p>first <em>one</em></p>\n");
    assert_eq!(first.parent_id, None);
    let second = comments.get(1).ok_or("no second comment")?;
    // No `extensions.location`: the renderer says "location not reported".
    assert_eq!(second.location, None);
    let reply = comments.get(2).ok_or("no reply")?;
    assert_eq!(reply.location.as_deref(), Some("inline"));
    assert_eq!(reply.parent_id.as_deref(), Some("802"));
    assert!(reply.created.is_some());
    if let PreviewBody::ConfluenceComments { count, .. } = &preview.body {
        assert_eq!(count.map(|c| c.shown), Some(3));
    }
    assert!(ids_at(&preview.warnings, Level::Caution).is_empty());
    Ok(())
}

/// What `op`'s previewer makes of `candidate` (no harness).
fn model_of(
    op: &str,
    params: &Value,
    candidate: &Value,
    conversion: Option<ConversionReport>,
) -> Result<PreviewModel, TestError> {
    let spec = atlas_duck_registry::get(op).ok_or("no registry op")?;
    let imp = op_table().get(op).ok_or("no op table row")?;
    Ok((imp.previewer)(&PreviewCtx {
        spec,
        instance_alias: "wiki",
        params,
        input: PreviewInput::Read(ReadView {
            candidate,
            byte_size: u64::try_from(candidate.to_string().len())?,
            server_total: None,
            more_available: false,
            clamped: false,
            comments_truncated: None,
            conversion,
        }),
        field_names: None,
    }))
}

/// T8 review m-6: core emits depth-first thread order, so a reply whose list position differs
/// from its thread position still nests under its parent.
#[test]
fn comments_thread_order_differs_from_list_order() -> TestResult {
    let page = comment_page(vec![
        comment("1", &[], None, "<p>a</p>"),
        comment("2", &[], None, "<p>b</p>"),
        comment("3", &["1"], None, "<p>reply to a</p>"),
        comment("4", &["1", "3"], None, "<p>reply to the reply</p>"),
        comment("5", &["2"], None, "<p>reply to b</p>"),
        // Its parent is not in this list (another page): a top-level entry where it appears.
        comment("6", &["999"], None, "<p>orphan</p>"),
    ]);
    let model = model_of(COMMENT_LIST, &json!({ "id": ID }), &page, None)?;
    assert_eq!(
        shape(thread(&model.body)?),
        [("1", 0), ("3", 1), ("4", 2), ("2", 0), ("5", 1), ("6", 0)]
    );
    Ok(())
}

/// Server data can make `ancestors` cycle: every comment is still shown exactly once.
#[test]
fn comments_ancestor_cycle_shows_each_comment_once() -> TestResult {
    let page = comment_page(vec![
        comment("7", &["8"], None, "<p>x</p>"),
        comment("8", &["7"], None, "<p>y</p>"),
        comment("9", &["9"], None, "<p>self</p>"),
        comment("10", &[], None, "<p>z</p>"),
    ]);
    let model = model_of(COMMENT_LIST, &json!({ "id": ID }), &page, None)?;
    assert_eq!(
        shape(thread(&model.body)?),
        [("9", 0), ("10", 0), ("7", 0), ("8", 1)]
    );
    Ok(())
}

#[test]
fn comment_bodies_are_inert() -> TestResult {
    let page = comment_page(vec![comment(
        "1",
        &[],
        Some("inline\u{202e}"),
        "<p><img src=\"https://evil.example/x.png\"/><a href=\"https://evil.example\">l</a>\u{202e}</p><ac:image><ri:url ri:value=\"https://evil.example/y.png\"/></ac:image>",
    )]);
    let model = model_of(COMMENT_LIST, &json!({ "id": ID }), &page, None)?;
    let comments = thread(&model.body)?;
    let c = comments.first().ok_or("no comment")?;
    assert_inert(&c.body_html);
    assert!(!c.body_html.contains("<img"), "{}", c.body_html);
    assert!(
        c.body_html.contains("\u{27e8}U+202E\u{27e9}"),
        "{}",
        c.body_html
    );
    assert_eq!(c.location.as_deref(), Some("inline\u{27e8}U+202E\u{27e9}"));
    assert_eq!(model.header.bidi_controls, 2);
    Ok(())
}

// ---- lists (PD-114) -----------------------------------------------------------------------

fn table(body: &PreviewBody) -> Result<(&[String], &[Vec<String>]), TestError> {
    match body {
        PreviewBody::Table { columns, rows, .. } => Ok((columns, rows)),
        other => Err(format!("not a table: {other:?}").into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lists_preview_tables() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;

    let spaces: Value = serde_json::from_str(&fixtures::confluence_space_page(0, 25, 2, None))?;
    mount_json(mock, "/rest/api/space", &spaces).await;
    let (_, preview) = opened(&h, "confluence.space.list", json!({})).await?;
    let (columns, rows) = table(&preview.body)?;
    assert_eq!(columns, ["id", "key", "name", "type"]);
    assert_eq!(
        rows.first().map(Vec::as_slice),
        Some(&["98305", "S1", "Space 1", "global"].map(String::from)[..])
    );
    assert_eq!(rows.len(), 2);
    // `padding` and `_links` are content the table leaves out; the page keys are the count.
    assert!(preview.header.hidden_in_preview_bytes > 0);

    let children = json!({
        "results": [
            {"id": "65538", "type": "page", "status": "current", "title": "Child one", "_links": {"webui": "/display/DOC/Child+one"}},
            {"id": "65539", "type": "page", "status": "current", "title": "Child \u{202e}two", "_links": {"webui": "/display/DOC/Child+two"}}
        ],
        "start": 0, "limit": 25, "size": 2,
        "_links": {"base": "https://wiki.corp.example", "context": ""}
    });
    mount_children(mock, ID, &[children]).await;
    let (_, preview) = opened(&h, "confluence.page.children", json!({ "id": ID })).await?;
    let (columns, rows) = table(&preview.body)?;
    assert_eq!(columns, ["id", "title", "status", "type"]);
    assert_eq!(
        rows.get(1).and_then(|r| r.get(1)).map(String::as_str),
        Some("Child \u{27e8}U+202E\u{27e9}two")
    );
    assert_eq!(preview.header.bidi_controls, 1);

    let labels = json!({
        "results": [{"prefix": "global", "name": "release", "id": "2001"}],
        "start": 0, "limit": 200, "size": 1
    });
    mount_json(mock, &format!("{}/label", content_path(ID)), &labels).await;
    let (_, preview) = opened(&h, "confluence.label.list", json!({ "id": ID })).await?;
    let (columns, rows) = table(&preview.body)?;
    assert_eq!(columns, ["id", "name", "prefix"]);
    assert_eq!(rows, [["2001", "release", "global"].map(String::from)]);
    assert_eq!(preview.header.hidden_in_preview_bytes, 0);

    let attachments: Value = atlas_duck_registry::get("confluence.attachment.list")
        .ok_or("no registry op")?
        .result_example_json();
    mount_attachments(mock, ID, &attachments).await;
    let (_, preview) = opened(&h, "confluence.attachment.list", json!({ "id": ID })).await?;
    let (columns, rows) = table(&preview.body)?;
    assert_eq!(columns, ["id", "title", "status", "type"]);
    assert_eq!(
        rows,
        [["att3001", "diagram.png", "current", "attachment"].map(String::from)]
    );
    // `metadata`, `extensions` and `_links` are left out and counted.
    assert!(preview.header.hidden_in_preview_bytes > 0);

    // `page.find` with `space` expanded: the nested `key`/`name` become columns (PD-114).
    let found = vec![json!({
        "id": "65537", "type": "page", "title": "Release checklist",
        "space": {"id": 98305, "key": "DOC", "name": "Documentation"}
    })];
    mount_title_lookup(mock, "DOC", "Release checklist", &found).await;
    let (_, preview) = opened(
        &h,
        "confluence.page.find",
        json!({ "space": "DOC", "title": "Release checklist" }),
    )
    .await?;
    let (columns, rows) = table(&preview.body)?;
    assert_eq!(columns, ["id", "title", "space.key", "space.name", "type"]);
    assert_eq!(
        rows,
        [["65537", "Release checklist", "DOC", "Documentation", "page"].map(String::from)]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_objects_keep_the_json_tree() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let space = atlas_duck_registry::get("confluence.space.get")
        .ok_or("no registry op")?
        .result_example_json();
    mount_json(mock, "/rest/api/space/ABC", &space).await;
    let (_, preview) = opened(&h, "confluence.space.get", json!({ "key": "ABC" })).await?;
    assert!(
        matches!(preview.body, PreviewBody::JsonTree { .. }),
        "{:?}",
        preview.body
    );
    Ok(())
}

/// A list's nested values the flattened columns do not show are counted as hidden, and a page
/// body over the cap says so (unit level: the previewers over a hand-built candidate).
#[test]
fn hidden_bytes_follow_what_the_layout_leaves_out() -> TestResult {
    let item = json!({"id": "1", "title": "T", "space": {"key": "DOC", "name": "Docs"}});
    let list = json!({"results": [item], "start": 0, "limit": 25, "size": 1});
    let model = model_of(
        "confluence.page.children",
        &json!({ "id": ID }),
        &list,
        None,
    )?;
    assert_eq!(
        model.header.hidden_in_preview_bytes, 0,
        "everything is shown"
    );
    let more = json!({"results": [{"id": "1", "title": "T", "space": {"key": "DOC", "id": 5}}], "start": 0, "limit": 25, "size": 1});
    let model = model_of(
        "confluence.page.children",
        &json!({ "id": ID }),
        &more,
        None,
    )?;
    // `space.id` (the key and the value, `id` + `5`) is the one member left out.
    assert_eq!(model.header.hidden_in_preview_bytes, 3);

    let markdown = "word ".repeat(100_000);
    let page = json!({"id": ID, "title": "Big", "body": {"format": "markdown", "value": markdown}});
    let model = model_of(
        PAGE_GET,
        &json!({ "id": ID }),
        &page,
        Some(ConversionReport::default()),
    )?;
    let card = page_card(&model.body)?;
    assert!(
        card.body_html.ends_with("more bytes (see Raw)</p>"),
        "no cut note"
    );
    assert!(model.header.hidden_in_preview_bytes >= 500_000 - 256 * 1024);
    Ok(())
}

/// A Markdown read without a converted body (the content had no `body.storage`) keeps the JSON
/// tree, as does a `view` read without `body.view`: the card never invents a body.
#[test]
fn page_without_its_body_text_keeps_the_json_tree() -> TestResult {
    let page: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE)?;
    let mut bare = page.clone();
    if let Some(o) = bare.as_object_mut() {
        o.remove("body");
    }
    for (params, candidate) in [
        (json!({ "id": ID }), &bare),
        (json!({ "id": ID, "format": "view" }), &page),
    ] {
        let model = model_of(PAGE_GET, &params, candidate, None)?;
        assert!(
            matches!(model.body, PreviewBody::JsonTree { .. }),
            "{params}: {:?}",
            model.body
        );
        assert!(model.warnings.is_empty(), "{:?}", model.warnings);
    }
    Ok(())
}
