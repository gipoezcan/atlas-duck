#![cfg(feature = "testing")]
//! `confluence.comment.add` (M7 Task 18, PD-107; §7.4 payload verbatim): the container type from
//! the enrichment, the reply `ancestors` after the `reply_to` resolution (a comment on this very
//! content, else the unresolved-name hold), the `ContentWrite` card (the outgoing storage rendered
//! locally, its constructs listed), no stale rule and the pre-write identity call that still runs.
//!
//! The label writes (Task 19, PD-108) follow below the comment tests.
//!
//! Checked twice: as pure functions of the op table (plan, judge, executor, previewer as the
//! engine calls them) and end to end through the harness.

mod common;

use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, UserKind, fixtures};
use atlas_duck_atlassian::{GetCall, HttpRequestSpec};
use atlas_duck_audit::EventType;
use atlas_duck_core::lifecycle::model::Hold;
use atlas_duck_core::ops::{
    EnrichCtx, EnrichPurpose, EnrichStep, EnrichVerdict, ExecCtx, ExecError, ExecPlan, PreviewCtx,
    PreviewInput, PreviewModel, WriteView, op_table,
};
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::Harness;
use atlas_duck_core::{DecisionError, DecisionOutcome, DenyDetails, Edits, QueueItem};
use atlas_duck_ipc::envelope::{ErrorCode, Status};
use atlas_duck_preview::{ConstructList, Preview, PreviewBody, WarningId};
use common::confluence::content_path;
use common::{TestError, TestResult, code, de, detail, exit, request_id};
use serde_json::{Map, Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const COMMENT: &str = "confluence.comment.add";
const ID: &str = "65537";
const COMMENT_ID: &str = "790";
const OTHER_COMMENT_ID: &str = "791";

// ---- pure helpers: the op table as the engine calls it ---------------------------------------

fn spec() -> Result<&'static atlas_duck_registry::OperationSpec, TestError> {
    atlas_duck_registry::get(COMMENT).ok_or_else(|| "no confluence.comment.add".into())
}

/// The fixture page (`Release checklist`, space `DOC`) as content of `kind`.
fn container(kind: &str) -> Value {
    let mut c: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE).unwrap_or(Value::Null);
    c["type"] = json!(kind);
    c
}

/// A comment `id` as `GET /rest/api/content/{id}?expand=container` answers it, on `on`.
fn comment_on(id: &str, on: &str) -> Value {
    json!({
        "id": id,
        "type": "comment",
        "status": "current",
        "container": {"id": on, "type": "page", "title": "Release checklist"},
    })
}

fn params(body: &str, reply_to: Option<&str>) -> Value {
    let mut p = json!({ "content_id": ID, "body": body });
    if let Some(r) = reply_to {
        p["reply_to"] = json!(r);
    }
    p
}

type Rounds = Vec<Vec<(EnrichPurpose, GetCall)>>;

/// The rule's rounds over `answers` the way the engine's staged driver feeds them, then the judge.
fn staged(params: &Value, answers: &[Value]) -> Result<(Rounds, EnrichVerdict), TestError> {
    let rule = op_table()
        .get(COMMENT)
        .and_then(|i| i.enrich)
        .ok_or("no enrich rule")?;
    let ctx = EnrichCtx {
        spec: spec()?,
        params,
    };
    let mut given: Vec<Value> = Vec::new();
    let mut rounds = Vec::new();
    loop {
        match (rule.plan)(&ctx, &given) {
            EnrichStep::Judge => break,
            EnrichStep::Fetch(calls) => {
                for _ in &calls {
                    let next = answers
                        .get(given.len())
                        .ok_or("the plan asked for more answers than the test gives")?;
                    given.push(next.clone());
                }
                rounds.push(calls);
            }
        }
        if rounds.len() > 4 {
            return Err("more than four rounds".into());
        }
    }
    Ok((rounds, (rule.judge)(&ctx, &given)))
}

/// The executor on `params` with `v` as the verdict.
fn exec(params: &Value, v: Option<&EnrichVerdict>) -> Result<ExecPlan, ExecError> {
    let base = atlas_duck_atlassian::normalize_base_url("https://wiki.example.invalid/wiki")
        .map_err(|_| ExecError::NotInThisBuild)?;
    let imp = op_table().get(COMMENT).ok_or(ExecError::NotInThisBuild)?;
    let spec = spec().map_err(|_| ExecError::NotInThisBuild)?;
    let ctx = ExecCtx {
        spec,
        params,
        base: &base,
        enrichment: v,
        effective_max: None,
        comments_cap: None,
        test_fault: None,
    };
    (imp.executor)(&ctx)
}

fn requests(params: &Value, v: &EnrichVerdict) -> Result<Vec<HttpRequestSpec>, TestError> {
    match exec(params, Some(v)) {
        Ok(ExecPlan::Write(r)) => Ok(r),
        other => Err(format!("not a write: {other:?}").into()),
    }
}

fn preview_of(
    params: &Value,
    v: &EnrichVerdict,
    reqs: &[HttpRequestSpec],
) -> Result<PreviewModel, TestError> {
    let imp = op_table().get(COMMENT).ok_or("no OpImpl")?;
    let ctx = PreviewCtx {
        spec: spec()?,
        instance_alias: "wiki",
        params,
        input: PreviewInput::Write(WriteView {
            requests: reqs,
            hold: v.hold,
            enrichment: Some(v),
            failure: None,
        }),
        field_names: None,
    };
    Ok((imp.previewer)(&ctx))
}

/// The verdict of a comment on a page (no reply).
fn verdict(p: &Value) -> Result<EnrichVerdict, TestError> {
    Ok(staged(p, &[container("page")])?.1)
}

fn sent(r: &[HttpRequestSpec]) -> Result<Value, TestError> {
    let [one] = r else {
        return Err(format!("{} requests", r.len()).into());
    };
    Ok(serde_json::from_slice(&one.body)?)
}

#[test]
fn comment_add_plan_stages() -> TestResult {
    // No reply: the container only (stage 1, `enrich`), asked with `expand=space`.
    let p = params("Looks good.", None);
    let (rounds, v) = staged(&p, &[container("page")])?;
    assert_eq!(rounds.len(), 1);
    let [(purpose, call)] = rounds[0].as_slice() else {
        return Err("not one GET".into());
    };
    assert_eq!(*purpose, EnrichPurpose::Enrich);
    assert_eq!(call.endpoint_template, "/rest/api/content/{content_id}");
    assert_eq!(call.params, json!({"content_id": ID}));
    assert_eq!(call.query, [("expand".to_owned(), "space".to_owned())]);
    assert_eq!(v.hold, Hold::Preview);

    // A reply: the comment second (stage 2, `resolve`), asked with `expand=container`.
    let p = params("Agreed.", Some(COMMENT_ID));
    let (rounds, v) = staged(&p, &[container("page"), comment_on(COMMENT_ID, ID)])?;
    assert_eq!(rounds.len(), 2);
    let [(purpose, call)] = rounds[1].as_slice() else {
        return Err("not one GET".into());
    };
    assert_eq!(*purpose, EnrichPurpose::Resolve);
    assert_eq!(call.endpoint_template, "/rest/api/content/{reply_to}");
    assert_eq!(call.params, json!({"reply_to": COMMENT_ID}));
    assert_eq!(call.query, [("expand".to_owned(), "container".to_owned())]);
    assert_eq!(v.hold, Hold::Preview);

    // Content that is neither a page nor a blog post ends the plan after stage 1: no stage 2.
    for kind in ["comment", "attachment", "space"] {
        let (rounds, v) = staged(&p, &[container(kind)])?;
        assert_eq!(rounds.len(), 1, "{kind}");
        assert_eq!(v.hold, Hold::EnrichmentError, "{kind}");
        assert!(requests(&p, &v).is_err(), "{kind}: no request");
    }
    Ok(())
}

#[test]
fn comment_add_executor_needs_a_matching_verdict() -> TestResult {
    let plain = params("Looks good.", None);
    assert_eq!(exec(&plain, None), Err(ExecError::EnrichmentRequired));
    let v = verdict(&plain)?;
    assert!(requests(&plain, &v).is_ok());
    // Another hold renders nothing.
    for hold in [
        Hold::EnrichmentError,
        Hold::UnresolvedName,
        Hold::Conflict,
        Hold::IdentityMismatch,
    ] {
        let mut held = v.clone();
        held.hold = hold;
        assert_eq!(
            exec(&plain, Some(&held)),
            Err(ExecError::EnrichmentRequired),
            "{hold:?}"
        );
    }
    // A verdict about another container, another reply or none never sends an `ancestors`.
    let mut other = v.clone();
    other.resolved.insert("content_id".into(), json!("1"));
    assert_eq!(
        exec(&plain, Some(&other)),
        Err(ExecError::EnrichmentRequired)
    );
    let reply = params("Agreed.", Some(COMMENT_ID));
    let unchecked = verdict(&plain)?;
    assert_eq!(
        exec(&reply, Some(&unchecked)),
        Err(ExecError::EnrichmentRequired),
        "a verdict without the reply resolution"
    );
    let checked = staged(&reply, &[container("page"), comment_on(COMMENT_ID, ID)])?.1;
    assert!(requests(&reply, &checked).is_ok());
    let edited = params("Agreed.", Some(OTHER_COMMENT_ID));
    assert_eq!(
        exec(&edited, Some(&checked)),
        Err(ExecError::EnrichmentRequired),
        "a verdict for another reply_to"
    );
    let dropped = params("Agreed.", None);
    assert_eq!(
        exec(&dropped, Some(&checked)),
        Err(ExecError::EnrichmentRequired),
        "a verdict that resolved a reply the params no longer carry"
    );
    Ok(())
}

/// The Task 9 rule applied here (plan review I-5): the body checks answer before any verdict is
/// asked for, so the validation dry call refuses them before enrichment.
#[test]
fn comment_add_body_checked_before_enrichment_required() -> TestResult {
    let invalid = |body: &str, format: Option<&str>| -> Option<ErrorCode> {
        let mut p = params(body, None);
        if let Some(f) = format {
            p["body_format"] = json!(f);
        }
        match exec(&p, None) {
            Err(ExecError::Invalid(e)) => Some(e.code),
            _ => None,
        }
    };
    assert_eq!(
        invalid("see @user:8a7f808a1", None),
        Some(ErrorCode::MarkdownPlaceholders)
    );
    assert_eq!(
        invalid("<!DOCTYPE x><p>a</p>", Some("storage")),
        Some(ErrorCode::Validation)
    );
    // An empty converted body: a comment may not be empty (T9 ruling 1).
    for blank in [" ", " \n\n "] {
        assert_eq!(
            invalid(blank, None),
            Some(ErrorCode::Validation),
            "{blank:?}"
        );
    }
    assert_eq!(invalid("fine", None), None);
    Ok(())
}

#[test]
fn comment_add_body_is_the_spec_payload_verbatim() -> TestResult {
    // Markdown: the converter's storage; a page container.
    let p = params("**bold** reply", None);
    let r = requests(&p, &verdict(&p)?)?;
    assert_eq!(r[0].method, "POST");
    assert_eq!(
        r[0].resolved_url,
        "https://wiki.example.invalid/wiki/rest/api/content"
    );
    assert_eq!(r[0].content_type.as_deref(), Some("application/json"));
    assert_eq!(
        sent(&r)?,
        json!({
            "type": "comment",
            "container": {"id": ID, "type": "page"},
            "body": {"storage": {
                "value": "<p><strong>bold</strong> reply</p>",
                "representation": "storage",
            }},
        })
    );
    // A reply on a blog post, storage verbatim.
    let mut p = params("<p>x</p>", Some(COMMENT_ID));
    p["body_format"] = json!("storage");
    let v = staged(&p, &[container("blogpost"), comment_on(COMMENT_ID, ID)])?.1;
    let body = sent(&requests(&p, &v)?)?;
    assert_eq!(body["container"], json!({"id": ID, "type": "blogpost"}));
    assert_eq!(body["ancestors"], json!([{"id": COMMENT_ID}]));
    assert_eq!(body["body"]["storage"]["value"], json!("<p>x</p>"));
    // Deterministic: every render gives the same bytes.
    assert_eq!(requests(&p, &v)?, requests(&p, &v)?);
    Ok(())
}

#[test]
fn comment_add_reply_to_other_content_judged_unresolved() -> TestResult {
    let p = params("Agreed.", Some(COMMENT_ID));
    let wrong: [(&str, Value); 4] = [
        (
            "a comment on other content",
            comment_on(COMMENT_ID, "99999"),
        ),
        ("a page, not a comment", container("page")),
        ("no container", json!({"id": COMMENT_ID, "type": "comment"})),
        (
            "a numeric container id of another content",
            json!({"id": COMMENT_ID, "type": "comment", "container": {"id": 99999}}),
        ),
    ];
    for (what, answer) in wrong {
        let (rounds, v) = staged(&p, &[container("page"), answer])?;
        assert_eq!(rounds.len(), 2, "{what}");
        assert_eq!(v.hold, Hold::UnresolvedName, "{what}");
        assert_eq!(
            v.unresolved,
            Some(("reply_to".to_owned(), COMMENT_ID.to_owned(), 0, Vec::new())),
            "{what}"
        );
        assert!(requests(&p, &v).is_err(), "{what}: nothing is rendered");
    }
    // The server may send ids as numbers: the same content still resolves.
    let numeric = json!({"id": COMMENT_ID, "type": "comment", "container": {"id": 65537}});
    let v = staged(&p, &[container("page"), numeric])?.1;
    assert_eq!(v.hold, Hold::Preview);
    Ok(())
}

struct Card<'a> {
    sentence: &'a str,
    rows: &'a [(String, String)],
    html: Option<&'a str>,
    constructs: &'a ConstructList,
}

fn card(m: &PreviewModel) -> Result<Card<'_>, TestError> {
    match &m.body {
        PreviewBody::ContentWrite {
            sentence,
            rows,
            body_html,
            constructs: Some(constructs),
            requests,
        } => {
            assert_eq!(requests.len(), 1, "the request list stays part of the body");
            Ok(Card {
                sentence,
                rows,
                html: body_html.as_deref(),
                constructs,
            })
        }
        other => Err(format!("not a content-write card: {other:?}").into()),
    }
}

#[test]
fn comment_add_markdown_converted_constructs_listed() -> TestResult {
    // A Markdown body converts to storage with no construct of its own: the list is empty.
    let p = params("**bold** and `code` in a reply", None);
    let v = verdict(&p)?;
    let reqs = requests(&p, &v)?;
    let m = preview_of(&p, &v, &reqs)?;
    let c = card(&m)?;
    assert_eq!(*c.constructs, ConstructList::default());
    assert!(
        c.sentence.contains("Release checklist") && c.sentence.contains("page"),
        "{}",
        c.sentence
    );
    assert!(
        c.rows
            .iter()
            .any(|(k, v)| k == "Space" && v.contains("DOC")),
        "{:?}",
        c.rows
    );
    assert!(
        c.html
            .is_some_and(|h| h.contains("bold") && h.contains("code")),
        "{:?}",
        c.html
    );
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);

    // A storage body with a `toc` macro lists it.
    let mut p = params(
        "<ac:structured-macro ac:name=\"toc\"/><p>Hello</p>",
        Some(COMMENT_ID),
    );
    p["body_format"] = json!("storage");
    let v = staged(&p, &[container("page"), comment_on(COMMENT_ID, ID)])?.1;
    let reqs = requests(&p, &v)?;
    let m = preview_of(&p, &v, &reqs)?;
    let c = card(&m)?;
    assert_eq!(c.constructs.macros, ["toc"]);
    assert!(c.constructs.mentions.is_empty() && c.constructs.links.is_empty());
    assert!(
        c.rows
            .iter()
            .any(|(k, v)| k == "Reply to" && v.contains(COMMENT_ID)),
        "{:?}",
        c.rows
    );
    assert!(c.sentence.contains("reply"), "{}", c.sentence);
    assert!(c.html.is_some_and(|h| h.contains("Hello")), "{:?}", c.html);
    // Every construct kind of the outgoing storage, display-escaped.
    let mut p = params(
        "<p><ac:link><ri:user ri:userkey=\"8a7f\"/></ac:link> \
         <ac:link><ri:page ri:content-title=\"Notes\"/></ac:link> \
         <ac:image><ri:attachment ri:filename=\"logo.png\"/></ac:image></p>\
         <ac:structured-macro ac:name=\"include\"><ac:parameter ac:name=\"\">\
         <ac:link><ri:page ri:content-title=\"Shared\"/></ac:link></ac:parameter></ac:structured-macro>",
        None,
    );
    p["body_format"] = json!("storage");
    let v = verdict(&p)?;
    let reqs = requests(&p, &v)?;
    let m = preview_of(&p, &v, &reqs)?;
    let c = card(&m)?.constructs;
    assert_eq!(c.mentions, ["8a7f"]);
    assert_eq!(c.links, ["Notes"]);
    assert_eq!(c.images, ["logo.png"]);
    assert!(!c.includes.is_empty(), "{c:?}");
    Ok(())
}

/// T7 review m-1 / T12b: a write card renders from the outgoing storage, and what the render
/// leaves out of storage the agent sends is counted and said (the hidden-content rule).
#[test]
fn comment_add_card_counts_what_the_render_drops() -> TestResult {
    let mut p = params(
        "<p title=\"secret hint\">visible</p><!-- a note for the server -->",
        None,
    );
    p["body_format"] = json!("storage");
    let v = verdict(&p)?;
    let reqs = requests(&p, &v)?;
    let m = preview_of(&p, &v, &reqs)?;
    let html = card(&m)?.html.ok_or("no body")?;
    assert!(html.contains("visible"), "{html}");
    assert!(
        !html.contains("secret hint") && !html.contains("a note for the server"),
        "{html}"
    );
    assert!(
        m.warnings
            .iter()
            .any(|w| w.id == WarningId::SourceFormattingRemoved),
        "{:?}",
        m.warnings
    );
    // The attribute from its name to the end of its value, and the whole comment (T12b rules).
    let dropped = "title=\"secret hint\"".len() + "<!-- a note for the server -->".len();
    assert_eq!(m.header.hidden_in_preview_bytes, u64::try_from(dropped)?);
    Ok(())
}

/// The card shows what is sent (the request), not what the params say: a request whose storage
/// differs from `params.body` is rendered and counted from the request.
#[test]
fn comment_add_card_renders_the_request_not_the_params() -> TestResult {
    let mut p = params("<p>param text</p>", None);
    p["body_format"] = json!("storage");
    let v = verdict(&p)?;
    let mut reqs = requests(&p, &v)?;
    let [one] = reqs.as_mut_slice() else {
        return Err("not one request".into());
    };
    let mut body = sent(std::slice::from_ref(one))?;
    body["body"]["storage"]["value"] = json!("<p title=\"x\">other</p>");
    one.body = serde_json::to_vec(&body)?;
    let m = preview_of(&p, &v, &reqs)?;
    let html = card(&m)?.html.ok_or("no body")?;
    assert!(
        html.contains("other") && !html.contains("param text"),
        "{html}"
    );
    assert_eq!(m.header.hidden_in_preview_bytes, "title=\"x\"".len() as u64);

    // A Markdown body shows its rendering, never the raw Markdown.
    let p = params("**bold** words", None);
    let v = verdict(&p)?;
    let reqs = requests(&p, &v)?;
    let m = preview_of(&p, &v, &reqs)?;
    let html = card(&m)?.html.ok_or("no body")?;
    assert!(html.contains("bold") && !html.contains("**"), "{html}");
    Ok(())
}

/// The space name the Space row shows takes part in the invisible-character count.
#[test]
fn comment_add_card_counts_invisible_characters_in_the_space_name() -> TestResult {
    let p = params("Looks good.", None);
    let mut page = container("page");
    page["space"]["name"] = json!("Docs\u{202e}Team");
    let v = staged(&p, &[page])?.1;
    let reqs = requests(&p, &v)?;
    let m = preview_of(&p, &v, &reqs)?;
    assert_eq!(m.header.bidi_controls, 1);
    assert!(
        m.warnings.iter().any(|w| w.id == WarningId::BidiControls),
        "{:?}",
        m.warnings
    );
    Ok(())
}

/// An unknown macro in the outgoing storage raises the Info `unknown_macros` on the comment card.
#[test]
fn comment_add_card_notes_unknown_macros() -> TestResult {
    let mut p = params("<ac:structured-macro ac:name=\"made-up\"/><p>Hi</p>", None);
    p["body_format"] = json!("storage");
    let v = verdict(&p)?;
    let reqs = requests(&p, &v)?;
    let m = preview_of(&p, &v, &reqs)?;
    assert!(
        m.warnings.iter().any(|w| w.id == WarningId::UnknownMacros),
        "{:?}",
        m.warnings
    );
    Ok(())
}

#[test]
fn comment_add_card_keeps_the_generic_body_without_a_verdict() -> TestResult {
    // Another hold has no request list: the generic write card stays.
    let p = params("Looks good.", None);
    let mut held = verdict(&p)?;
    held.hold = Hold::EnrichmentError;
    let m = preview_of(&p, &held, &[])?;
    assert!(
        !matches!(m.body, PreviewBody::ContentWrite { .. }),
        "{:?}",
        m.body
    );
    Ok(())
}

// ---- end to end ------------------------------------------------------------------------------

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no wiki mock".into())
}

fn json_answer(mock: &MockDc, status: u16, body: &Value) -> ResponseTemplate {
    mock.response(status)
        .set_body_raw(body.to_string(), "application/json")
}

/// `GET /rest/api/content/<id>` answers `body`.
async fn mount_content(mock: &MockDc, id: &str, body: &Value) {
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(id))))
        .respond_with(json_answer(mock, 200, body))
        .mount(mock.server())
        .await;
}

/// The server side of a comment: the identity call, the container (a `kind` with id 65537), the
/// comment 790 on it and 791 on another page, and the answer of the POST.
async fn comment_server(mock: &MockDc, kind: &str) {
    mock.confluence_user_current(UserKind::Known, TEST_USER, TEST_USER_KEY)
        .await;
    mount_content(mock, ID, &container(kind)).await;
    mount_content(mock, COMMENT_ID, &comment_on(COMMENT_ID, ID)).await;
    mount_content(
        mock,
        OTHER_COMMENT_ID,
        &comment_on(OTHER_COMMENT_ID, "99999"),
    )
    .await;
    Mock::given(method("POST"))
        .and(path(mock.path("/rest/api/content")))
        .respond_with(json_answer(
            mock,
            200,
            &json!({"id": "792", "type": "comment", "status": "current",
                    "version": {"number": 1},
                    "_links": {"webui": "/display/DOC/Release+checklist?focusedCommentId=792"}}),
        ))
        .mount(mock.server())
        .await;
}

async fn queued(h: &Harness, params: Value) -> Result<String, TestError> {
    let env = h.submit(COMMENT, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

fn opened(h: &Harness, id: &str) -> Result<Preview, TestError> {
    Ok(h.approver().open(id).map_err(de)?.preview)
}

fn not_approvable(res: Result<DecisionOutcome, DecisionError>) -> TestResult {
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    Ok(())
}

async fn posts(mock: &MockDc) -> Vec<wiremock::Request> {
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
        .collect()
}

async fn gets_of(mock: &MockDc, p: &str) -> Vec<wiremock::Request> {
    let want = mock.path(p);
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "GET" && r.url.path() == want)
        .collect()
}

async fn purposes(h: &Harness, id: &str) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::PREVIEW_FETCH)
        .map(|(_, p)| p["purpose"].clone())
        .collect())
}

async fn approved(h: &Harness, id: &str) -> TestResult {
    h.approver().open(id).map_err(de)?;
    h.approver().approve(id).map_err(de)?;
    let env = h.await_(id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    Ok(())
}

async fn item_after(h: &Harness, id: &str, rev: u64) -> Result<QueueItem, TestError> {
    for _ in 0..400 {
        if let Some(item) = h.approver().item(id)
            && item.candidate_rev.counter > rev
        {
            return Ok(item);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err("the revision never advanced".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comment_add_container_type_from_enrichment() -> TestResult {
    for kind in ["page", "blogpost"] {
        let h = Harness::confluence().await?;
        let mock = wiki(&h)?;
        comment_server(mock, kind).await;
        let id = queued(&h, params("Looks good.", None)).await?;
        approved(&h, &id).await?;
        let sent: Value = {
            let all = posts(mock).await;
            let [one] = all.as_slice() else {
                return Err(format!("{} POSTs", all.len()).into());
            };
            serde_json::from_slice(&one.body)?
        };
        assert_eq!(
            sent,
            json!({
                "type": "comment",
                "container": {"id": ID, "type": kind},
                "body": {"storage": {"value": "<p>Looks good.</p>", "representation": "storage"}},
            }),
            "{kind}"
        );
        assert!(
            sent.get("ancestors").is_none(),
            "{kind}: no reply, no ancestors"
        );
        // The container GET asked for its space; the receipt is the projection of the answer.
        let gets = gets_of(mock, &content_path(ID)).await;
        assert!(
            gets.iter().any(|g| g.url.query() == Some("expand=space")),
            "{gets:?}"
        );
        let env = h.await_(&id, 1000).await;
        assert_eq!(
            env.data,
            Some(json!({"receipt": {
                "id": "792", "type": "comment", "status": "current",
                "version": {"number": 1},
                "_links": {"webui": "/display/DOC/Release+checklist?focusedCommentId=792"},
            }})),
            "{kind}"
        );
        // No reply: one enrichment GET, then (after the approval) the pre-write identity call,
        // recorded as the stale-check step although the op has no stale rule.
        assert_eq!(
            purposes(&h, &id).await?,
            [json!("enrich"), json!("stale_check")],
            "{kind}"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comment_add_on_a_comment_is_an_enrichment_error() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    comment_server(mock, "comment").await;
    let id = queued(&h, params("Looks good.", None)).await?;
    let p = opened(&h, &id)?;
    assert!(
        matches!(p.body, PreviewBody::EnrichmentError { .. }),
        "{:?}",
        p.body
    );
    assert!(!p.approvable);
    not_approvable(h.approver().approve_unopened(&id))?;
    assert!(posts(mock).await.is_empty(), "nothing was sent");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comment_add_reply_to_sets_ancestors() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    comment_server(mock, "page").await;
    let id = queued(&h, params("Agreed.", Some(COMMENT_ID))).await?;
    assert_eq!(
        purposes(&h, &id).await?[..2],
        [json!("enrich"), json!("resolve")]
    );
    approved(&h, &id).await?;
    let all = posts(mock).await;
    let [one] = all.as_slice() else {
        return Err(format!("{} POSTs", all.len()).into());
    };
    let sent: Value = serde_json::from_slice(&one.body)?;
    assert_eq!(sent["ancestors"], json!([{"id": COMMENT_ID}]));
    assert_eq!(sent["container"], json!({"id": ID, "type": "page"}));
    // The reply target was read with its container.
    let gets = gets_of(mock, &content_path(COMMENT_ID)).await;
    assert!(
        gets.iter()
            .any(|g| g.url.query() == Some("expand=container")),
        "{gets:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comment_add_reply_to_other_content_held() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    comment_server(mock, "page").await;
    let id = queued(&h, params("Agreed.", Some(OTHER_COMMENT_ID))).await?;
    let p = opened(&h, &id)?;
    match &p.body {
        PreviewBody::UnresolvedName {
            param,
            value,
            matches,
            candidates,
        } => {
            assert_eq!(
                (param.as_str(), value.as_str(), *matches),
                ("reply_to", OTHER_COMMENT_ID, 0)
            );
            assert!(candidates.is_empty());
        }
        other => return Err(format!("not the unresolved-name card: {other:?}").into()),
    }
    assert!(!p.approvable);
    not_approvable(h.approver().approve_unopened(&id))?;
    assert!(posts(mock).await.is_empty(), "nothing was sent");
    // The agent's deny names the reply (the resolution message, plan text).
    h.approver()
        .deny_with(
            &id,
            "no such reply",
            DenyDetails::ResolutionFailed {
                include_candidates: false,
            },
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
    assert_eq!(code(&env), "resolution_failed");
    assert_eq!(detail(&env, "param"), json!("reply_to"));
    assert_eq!(
        detail(&env, "message"),
        json!(format!("no comment {OTHER_COMMENT_ID} on content {ID}"))
    );
    Ok(())
}

/// Plan review I-6 a: `reply_to` is no target param, so an approver edit of it re-runs the
/// resolution; a reply to a comment on other content is never sent unchecked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reply_to_edit_reruns_resolution() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    comment_server(mock, "page").await;
    let id = queued(&h, params("Agreed.", Some(COMMENT_ID))).await?;
    let p = opened(&h, &id)?;
    assert!(p.approvable, "{:?}", p.body);
    let rev = h.approver().rev(&id).map_err(de)?;
    let before = purposes(&h, &id).await?.len();
    let mut set = Map::new();
    set.insert("reply_to".into(), json!(OTHER_COMMENT_ID));
    h.approver()
        .edit(
            &id,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
        .map_err(de)?;
    let item = item_after(&h, &id, rev.counter).await?;
    assert!(!item.approvable, "the edited reply is not on this content");
    assert_eq!(
        purposes(&h, &id).await?.len(),
        before + 2,
        "the edit re-ran both stages"
    );
    let p = opened(&h, &id)?;
    match &p.body {
        PreviewBody::UnresolvedName { param, value, .. } => {
            assert_eq!(
                (param.as_str(), value.as_str()),
                ("reply_to", OTHER_COMMENT_ID)
            );
        }
        other => return Err(format!("not the unresolved-name card: {other:?}").into()),
    }
    not_approvable(h.approver().approve(&id))?;
    assert!(posts(mock).await.is_empty(), "nothing was sent");

    // An edit back to the first reply resolves again; the sent `ancestors` is the checked one.
    let rev = h.approver().rev(&id).map_err(de)?;
    let mut set = Map::new();
    set.insert("reply_to".into(), json!(COMMENT_ID));
    h.approver()
        .edit(
            &id,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
        .map_err(de)?;
    assert!(item_after(&h, &id, rev.counter).await?.approvable);
    approved(&h, &id).await?;
    let all = posts(mock).await;
    let [one] = all.as_slice() else {
        return Err(format!("{} POSTs", all.len()).into());
    };
    let sent: Value = serde_json::from_slice(&one.body)?;
    assert_eq!(sent["ancestors"], json!([{"id": COMMENT_ID}]));
    Ok(())
}

/// §5.4 step 5: no stale rule for `comment.add`, but the identity call still runs. A token that
/// now answers `type: anonymous` stops the write before it is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comment_add_identity_call_runs() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    comment_server(mock, "page").await;
    let id = queued(&h, params("Looks good.", None)).await?;
    h.approver().open(&id).map_err(de)?;
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    assert!(
        op_table()
            .get(COMMENT)
            .is_some_and(|i| i.stale_check.is_none()),
        "no stale rule"
    );
    // From here the identity call answers as anonymous (the PAT stopped working).
    mock.server().reset().await;
    mock.confluence_user_current(UserKind::Anonymous, "", "")
        .await;
    h.approver().approve(&id).map_err(de)?;
    let after = item_after(&h, &id, rev).await?;
    assert!(!after.approvable);
    let reasons: Vec<Value> = h
        .events(&id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::WRITE_STALE)
        .map(|(_, p)| p["reason"].clone())
        .collect();
    assert_eq!(reasons, [json!("identity_mismatch")]);
    assert!(posts(mock).await.is_empty(), "nothing was sent");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comment_add_whitespace_markdown_refused_at_validation() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    comment_server(mock, "page").await;
    let before = mock.received().await.len();
    for blank in [" ", " \n\n "] {
        let env = h.submit(COMMENT, params(blank, None)).await;
        assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
        assert_eq!(code(&env), "validation");
        assert_eq!(exit(&env), 2);
        assert_eq!(detail(&env, "param"), json!("body"));
    }
    assert_eq!(mock.received().await.len(), before, "no wiremock hit");
    Ok(())
}

// ---- confluence.label.add / confluence.label.remove (M7 Task 19, PD-108) -----------------------

const LABEL_ADD: &str = "confluence.label.add";
const LABEL_REMOVE: &str = "confluence.label.remove";

fn op_spec(id: &str) -> Result<&'static atlas_duck_registry::OperationSpec, TestError> {
    atlas_duck_registry::get(id).ok_or_else(|| format!("no {id}").into())
}

/// `GET /rest/api/content/<id>?expand=metadata.labels` as the server answers it: a global
/// `release`, a global `Docs` and a personal `mine`.
fn labelled_page() -> Value {
    json!({
        "id": ID,
        "type": "page",
        "status": "current",
        "title": "Release checklist",
        "metadata": {"labels": {
            "results": [
                {"prefix": "global", "name": "release", "id": "1"},
                {"prefix": "global", "name": "Docs", "id": "2"},
                {"prefix": "my", "name": "mine", "id": "3"},
            ],
            "start": 0, "limit": 200, "size": 3,
        }},
    })
}

fn add_params(labels: &[&str]) -> Value {
    json!({ "id": ID, "labels": labels })
}

fn remove_params(label: &str) -> Value {
    json!({ "id": ID, "label": label })
}

fn label_staged(op: &str, params: &Value, answers: &[Value]) -> Result<EnrichVerdict, TestError> {
    let rule = op_table()
        .get(op)
        .and_then(|i| i.enrich)
        .ok_or("no enrich rule")?;
    let ctx = EnrichCtx {
        spec: op_spec(op)?,
        params,
    };
    let mut given: Vec<Value> = Vec::new();
    while let EnrichStep::Fetch(calls) = (rule.plan)(&ctx, &given) {
        for _ in &calls {
            given.push(
                answers
                    .get(given.len())
                    .ok_or("the plan asked for more answers than the test gives")?
                    .clone(),
            );
        }
        if given.len() > 4 {
            return Err("more than four answers".into());
        }
    }
    Ok((rule.judge)(&ctx, &given))
}

fn label_verdict(op: &str, params: &Value) -> Result<EnrichVerdict, TestError> {
    label_staged(op, params, &[labelled_page()])
}

fn label_exec(op: &str, params: &Value, v: Option<&EnrichVerdict>) -> Result<ExecPlan, ExecError> {
    let base = atlas_duck_atlassian::normalize_base_url("https://wiki.example.invalid/wiki")
        .map_err(|_| ExecError::NotInThisBuild)?;
    let imp = op_table().get(op).ok_or(ExecError::NotInThisBuild)?;
    let spec = op_spec(op).map_err(|_| ExecError::NotInThisBuild)?;
    (imp.executor)(&ExecCtx {
        spec,
        params,
        base: &base,
        enrichment: v,
        effective_max: None,
        comments_cap: None,
        test_fault: None,
    })
}

fn label_requests(
    op: &str,
    params: &Value,
    v: &EnrichVerdict,
) -> Result<Vec<HttpRequestSpec>, TestError> {
    match label_exec(op, params, Some(v)) {
        Ok(ExecPlan::Write(r)) => Ok(r),
        other => Err(format!("not a write: {other:?}").into()),
    }
}

/// The op's previewer over `reqs` and the verdict `v`.
fn label_preview_of(
    op: &str,
    params: &Value,
    v: &EnrichVerdict,
    reqs: &[HttpRequestSpec],
) -> Result<PreviewModel, TestError> {
    let imp = op_table().get(op).ok_or("no OpImpl")?;
    Ok((imp.previewer)(&PreviewCtx {
        spec: op_spec(op)?,
        instance_alias: "wiki",
        params,
        input: PreviewInput::Write(WriteView {
            requests: reqs,
            hold: v.hold,
            enrichment: Some(v),
            failure: None,
        }),
        field_names: None,
    }))
}

fn label_card(op: &str, params: &Value) -> Result<PreviewModel, TestError> {
    let v = label_verdict(op, params)?;
    let reqs = label_requests(op, params, &v)?;
    label_preview_of(op, params, &v, &reqs)
}

type SummaryCard<'a> = (&'a str, &'a [(String, String)]);

fn summary(m: &PreviewModel) -> Result<SummaryCard<'_>, TestError> {
    match &m.body {
        PreviewBody::WriteSummary {
            sentence,
            rows,
            constructs: None,
            requests,
        } => {
            assert_eq!(requests.len(), 1, "the request list stays part of the body");
            Ok((sentence, rows))
        }
        other => Err(format!("not a label summary card: {other:?}").into()),
    }
}

#[test]
fn label_plan_reads_the_labels_once() -> TestResult {
    for (op, p) in [
        (LABEL_ADD, add_params(&["a"])),
        (LABEL_REMOVE, remove_params("a")),
    ] {
        let rule = op_table()
            .get(op)
            .and_then(|i| i.enrich)
            .ok_or("no enrich rule")?;
        let ctx = EnrichCtx {
            spec: op_spec(op)?,
            params: &p,
        };
        let EnrichStep::Fetch(calls) = (rule.plan)(&ctx, &[]) else {
            return Err("no first fetch".into());
        };
        let [(purpose, call)] = calls.as_slice() else {
            return Err("not one GET".into());
        };
        assert_eq!(*purpose, EnrichPurpose::Enrich, "{op}");
        assert_eq!(call.endpoint_template, "/rest/api/content/{id}");
        assert_eq!(call.params, json!({"id": ID}), "{op}: only the placeholder");
        assert_eq!(
            call.query,
            [("expand".to_owned(), "metadata.labels".to_owned())]
        );
        assert!(matches!(
            (rule.plan)(&ctx, &[labelled_page()]),
            EnrichStep::Judge
        ));
        assert!(op_table().get(op).is_some_and(|i| i.stale_check.is_none()));
    }
    Ok(())
}

#[test]
fn label_judge_keeps_global_labels_and_fails_closed() -> TestResult {
    let p = add_params(&["a"]);
    let v = label_staged(LABEL_ADD, &p, &[labelled_page()])?;
    assert_eq!(v.hold, Hold::Preview);
    let facts = v
        .summary
        .as_ref()
        .and_then(|s| s.confluence.as_ref())
        .ok_or("no facts")?;
    assert_eq!(facts.current_labels, ["release", "Docs"], "no `my:` label");
    assert_eq!(
        facts
            .page
            .as_ref()
            .map(|p| (p.id.as_str(), p.title.as_str())),
        Some((ID, "Release checklist"))
    );
    // An answer without the label list is no content answer: no write is rendered for it.
    for bad in [
        json!({"id": ID, "type": "page", "title": "T"}),
        json!({"id": ID, "metadata": {"labels": {"results": "x"}}}),
        json!([]),
    ] {
        let v = label_staged(LABEL_ADD, &p, &[bad])?;
        assert_eq!(v.hold, Hold::EnrichmentError);
        assert!(label_requests(LABEL_ADD, &p, &v).is_err());
    }
    Ok(())
}

#[test]
fn label_executors_need_a_verdict_for_this_content() -> TestResult {
    for (op, p) in [
        (LABEL_ADD, add_params(&["a"])),
        (LABEL_REMOVE, remove_params("a")),
    ] {
        assert_eq!(
            label_exec(op, &p, None),
            Err(ExecError::EnrichmentRequired),
            "{op}"
        );
        let v = label_verdict(op, &p)?;
        assert!(label_requests(op, &p, &v).is_ok(), "{op}");
        for hold in [
            Hold::EnrichmentError,
            Hold::UnresolvedName,
            Hold::Conflict,
            Hold::IdentityMismatch,
        ] {
            let mut held = v.clone();
            held.hold = hold;
            assert_eq!(
                label_exec(op, &p, Some(&held)),
                Err(ExecError::EnrichmentRequired),
                "{op} {hold:?}"
            );
        }
        let mut other = p.clone();
        other["id"] = json!("1");
        assert_eq!(
            label_exec(op, &other, Some(&v)),
            Err(ExecError::EnrichmentRequired),
            "{op}: a verdict about another content"
        );
    }
    Ok(())
}

#[test]
fn label_add_body_is_the_spec_payload_in_order() -> TestResult {
    let p = add_params(&["release", "docs", "Team:Alpha"]);
    let r = label_requests(LABEL_ADD, &p, &label_verdict(LABEL_ADD, &p)?)?;
    let [one] = r.as_slice() else {
        return Err("not one request".into());
    };
    assert_eq!(one.method, "POST");
    assert_eq!(
        one.resolved_url,
        format!("https://wiki.example.invalid/wiki/rest/api/content/{ID}/label")
    );
    assert_eq!(one.content_type.as_deref(), Some("application/json"));
    assert_eq!(
        serde_json::from_slice::<Value>(&one.body)?,
        json!([
            {"prefix": "global", "name": "release"},
            {"prefix": "global", "name": "docs"},
            {"prefix": "global", "name": "Team:Alpha"},
        ]),
        "params' order, names as written (no case folding, prefix always global)"
    );
    Ok(())
}

#[test]
fn label_remove_request_is_a_bare_delete() -> TestResult {
    for (label, encoded) in [
        ("release", "release"),
        ("team:alpha", "team%3Aalpha"),
        ("a-b_c.d", "a-b_c.d"),
    ] {
        let p = remove_params(label);
        let r = label_requests(LABEL_REMOVE, &p, &label_verdict(LABEL_REMOVE, &p)?)?;
        let [one] = r.as_slice() else {
            return Err("not one request".into());
        };
        assert_eq!(one.method, "DELETE");
        assert_eq!(
            one.resolved_url,
            format!("https://wiki.example.invalid/wiki/rest/api/content/{ID}/label/{encoded}")
        );
        assert_eq!(one.content_type, None, "no body, no content type");
        assert!(one.body.is_empty());
    }
    Ok(())
}

/// The schema lets `.` and `..` through the label pattern; as a path segment they would name
/// another resource (`DELETE .../label/..` is `DELETE .../content/<id>`), so the URL builder refuses
/// them before anything is rendered, enrichment verdict or not.
#[test]
fn label_remove_dot_segment_labels_refused_before_any_request() -> TestResult {
    for label in [".", ".."] {
        let p = remove_params(label);
        let v = label_verdict(LABEL_REMOVE, &p)?;
        for verdict in [None, Some(&v)] {
            match label_exec(LABEL_REMOVE, &p, verdict) {
                Err(ExecError::Invalid(e)) => {
                    assert_eq!(e.code, ErrorCode::Validation, "{label}");
                    assert_eq!(e.details.get("param"), Some(&json!("label")), "{label}");
                }
                other => return Err(format!("{label}: {other:?}").into()),
            }
        }
    }
    Ok(())
}

#[test]
fn label_cards() -> TestResult {
    // Add: the sentence names the labels as sent; `docs` is already on the page as `Docs`
    // (Confluence folds label names to lower case), `new` is not.
    let m = label_card(LABEL_ADD, &add_params(&["new", "docs"]))?;
    let (sentence, rows) = summary(&m)?;
    assert_eq!(sentence, "Add labels new, docs to 'Release checklist'");
    assert_eq!(
        rows,
        [
            ("Content".to_owned(), format!("page {ID}")),
            ("Already present".to_owned(), "docs".to_owned()),
        ]
    );
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);

    // One label reads in the singular; nothing present means no row.
    let m = label_card(LABEL_ADD, &add_params(&["new"]))?;
    let (sentence, rows) = summary(&m)?;
    assert_eq!(sentence, "Add label new to 'Release checklist'");
    assert_eq!(rows.len(), 1, "{rows:?}");

    // Remove: a label the page has needs no row; one it does not have is named.
    let m = label_card(LABEL_REMOVE, &remove_params("release"))?;
    let (sentence, rows) = summary(&m)?;
    assert_eq!(sentence, "Remove label release from 'Release checklist'");
    assert_eq!(rows.len(), 1, "{rows:?}");
    let m = label_card(LABEL_REMOVE, &remove_params("absent"))?;
    let (sentence, rows) = summary(&m)?;
    assert_eq!(sentence, "Remove label absent from 'Release checklist'");
    assert_eq!(
        rows,
        [
            ("Content".to_owned(), format!("page {ID}")),
            ("Not present".to_owned(), "absent".to_owned()),
        ]
    );
    // A personal label of the same name is not the global one a remove by name touches.
    let m = label_card(LABEL_REMOVE, &remove_params("mine"))?;
    assert_eq!(summary(&m)?.1.len(), 2);
    Ok(())
}

/// The card reads the labels from the request, not from the params, and counts the invisible
/// characters of the server's title (the hidden-content rule, T12b).
#[test]
fn label_card_renders_the_request_and_counts_the_title() -> TestResult {
    let p = add_params(&["a", "b"]);
    let mut page = labelled_page();
    page["title"] = json!("Docs\u{202e}Team");
    let v = label_staged(LABEL_ADD, &p, &[page])?;
    let mut reqs = label_requests(LABEL_ADD, &p, &v)?;
    reqs[0].body = serde_json::to_vec(&json!([{"prefix": "global", "name": "other"}]))?;
    let m = label_preview_of(LABEL_ADD, &p, &v, &reqs)?;
    let (sentence, _) = summary(&m)?;
    assert!(sentence.starts_with("Add label other to "), "{sentence}");
    assert_eq!(m.header.bidi_controls, 1);
    assert!(
        m.warnings.iter().any(|w| w.id == WarningId::BidiControls),
        "{:?}",
        m.warnings
    );
    // Another hold has no verdict facts: the generic card stays.
    let mut held = v.clone();
    held.hold = Hold::EnrichmentError;
    let m = label_preview_of(LABEL_ADD, &p, &held, &[])?;
    assert!(
        !matches!(m.body, PreviewBody::WriteSummary { .. }),
        "{:?}",
        m.body
    );
    Ok(())
}

// ---- end to end: labels ------------------------------------------------------------------------

fn label_path(id: &str, label: Option<&str>) -> String {
    match label {
        Some(l) => format!("/rest/api/content/{id}/label/{l}"),
        None => format!("/rest/api/content/{id}/label"),
    }
}

/// The identity call, the content with its labels, the label POST (answering with more labels
/// than the agent sent) and the label DELETE (`delete_status`, empty).
async fn label_server(mock: &MockDc, delete_status: u16) {
    mock.confluence_user_current(UserKind::Known, TEST_USER, TEST_USER_KEY)
        .await;
    mount_content(mock, ID, &labelled_page()).await;
    Mock::given(method("POST"))
        .and(path(mock.path(&label_path(ID, None))))
        .respond_with(json_answer(
            mock,
            200,
            &json!({"results": [
                {"prefix": "global", "name": "release", "id": "10"},
                {"prefix": "global", "name": "docs", "id": "11"},
                {"prefix": "global", "name": "someone-elses", "id": "12"},
            ], "start": 0, "limit": 200, "size": 3}),
        ))
        .mount(mock.server())
        .await;
    Mock::given(method("DELETE"))
        .and(path(mock.path(&label_path(ID, Some("release")))))
        .respond_with(mock.response(delete_status))
        .mount(mock.server())
        .await;
}

async fn label_queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

async fn requests_with(mock: &MockDc, http_method: &str) -> Vec<wiremock::Request> {
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == http_method)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn label_add_body_and_receipt_agent_labels() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    label_server(mock, 204).await;
    let id = label_queued(&h, LABEL_ADD, add_params(&["release", "docs"])).await?;
    // The enrichment read the labels for the card; the card is the labels summary.
    let p = opened(&h, &id)?;
    assert!(p.approvable, "{:?}", p.body);
    assert!(
        matches!(p.body, PreviewBody::WriteSummary { .. }),
        "{:?}",
        p.body
    );
    assert!(
        requests_with(mock, "POST").await.is_empty(),
        "nothing sent before approval"
    );
    let gets = gets_of(mock, &content_path(ID)).await;
    assert!(
        gets.iter()
            .any(|g| g.url.query() == Some("expand=metadata.labels")),
        "{gets:?}"
    );
    approved(&h, &id).await?;
    let all = requests_with(mock, "POST").await;
    let [one] = all.as_slice() else {
        return Err(format!("{} POSTs", all.len()).into());
    };
    assert_eq!(
        serde_json::from_slice::<Value>(&one.body)?,
        json!([
            {"prefix": "global", "name": "release"},
            {"prefix": "global", "name": "docs"},
        ])
    );
    // The server answered with a third label; the receipt lists only the agent's (§4.2).
    let env = h.await_(&id, 1000).await;
    assert_eq!(
        env.data,
        Some(json!({"receipt": {"labels": ["release", "docs"]}}))
    );
    assert_eq!(
        purposes(&h, &id).await?,
        [json!("enrich"), json!("stale_check")]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn label_add_already_present_is_a_row_not_a_hold() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    label_server(mock, 204).await;
    let id = label_queued(&h, LABEL_ADD, add_params(&["release"])).await?;
    let p = opened(&h, &id)?;
    assert!(p.approvable, "{:?}", p.body);
    match &p.body {
        PreviewBody::WriteSummary { rows, .. } => {
            assert!(rows.iter().any(|(k, _)| k == "Already present"), "{rows:?}");
        }
        other => return Err(format!("not a summary: {other:?}").into()),
    }
    approved(&h, &id).await?;
    assert_eq!(requests_with(mock, "POST").await.len(), 1);
    Ok(())
}

/// An approver edit of `labels` changes what is sent; the sent body is the edited one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn label_add_edit_changes_the_sent_labels() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    label_server(mock, 204).await;
    let id = label_queued(&h, LABEL_ADD, add_params(&["release", "docs"])).await?;
    opened(&h, &id)?;
    let rev = h.approver().rev(&id).map_err(de)?;
    let mut set = Map::new();
    set.insert("labels".into(), json!(["docs"]));
    h.approver()
        .edit(
            &id,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
        .map_err(de)?;
    assert!(item_after(&h, &id, rev.counter).await?.approvable);
    approved(&h, &id).await?;
    let all = requests_with(mock, "POST").await;
    let [one] = all.as_slice() else {
        return Err(format!("{} POSTs", all.len()).into());
    };
    assert_eq!(
        serde_json::from_slice::<Value>(&one.body)?,
        json!([{"prefix": "global", "name": "docs"}])
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn label_remove_204_empty_receipt() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    label_server(mock, 204).await;
    let id = label_queued(&h, LABEL_REMOVE, remove_params("release")).await?;
    let p = opened(&h, &id)?;
    assert!(p.approvable, "{:?}", p.body);
    // The method guard (§5.1 inv. 3): enrichment is GET-only, so no DELETE exists before the
    // write is approved.
    assert!(requests_with(mock, "DELETE").await.is_empty());
    assert!(
        h.events(&id)
            .await?
            .iter()
            .all(|(t, _)| *t != EventType::WRITE_APPROVED)
    );
    approved(&h, &id).await?;
    let all = requests_with(mock, "DELETE").await;
    let [one] = all.as_slice() else {
        return Err(format!("{} DELETEs", all.len()).into());
    };
    assert_eq!(one.url.path(), mock.path(&label_path(ID, Some("release"))));
    assert!(one.body.is_empty());
    assert_eq!(
        one.url.query(),
        None,
        "the label is a path segment, not a query"
    );
    let env = h.await_(&id, 1000).await;
    assert_eq!(env.data, Some(json!({"receipt": {}})));
    assert!(
        h.events(&id)
            .await?
            .iter()
            .any(|(t, _)| *t == EventType::WRITE_EXECUTED)
    );
    Ok(())
}

/// §7.2: the declared success is an empty 204. Anything else that arrives as 2xx (a captive
/// portal's 200 page) is not that success: `outcome_unknown`, never reported as done.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn label_remove_html_body_outcome_unknown() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mock.confluence_user_current(UserKind::Known, TEST_USER, TEST_USER_KEY)
        .await;
    mount_content(mock, ID, &labelled_page()).await;
    Mock::given(method("DELETE"))
        .and(path(mock.path(&label_path(ID, Some("release")))))
        .respond_with(
            mock.response(200)
                .set_body_raw("<html><body>Please log in</body></html>", "text/html"),
        )
        .mount(mock.server())
        .await;
    let id = label_queued(&h, LABEL_REMOVE, remove_params("release")).await?;
    h.approver().open(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(
        (env.status, exit(&env)),
        (Status::OutcomeUnknown, 6),
        "{}",
        env.to_json_line()
    );
    assert!(!env.to_json_line().contains("Please log in"));
    assert_eq!(requests_with(mock, "DELETE").await.len(), 1);
    Ok(())
}

/// Removing a label the page does not have: the card says so, Approve stays enabled, and the
/// server's 404 is the write's own failure (§5.4 step 5: no stale rule, a vanished target surfaces
/// as the write's error).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn label_remove_missing_label_is_the_servers_404() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    label_server(mock, 204).await;
    Mock::given(method("DELETE"))
        .and(path(mock.path(&label_path(ID, Some("absent")))))
        .respond_with(json_answer(
            mock,
            404,
            &json!({"statusCode": 404, "message": "No label with name 'absent' found"}),
        ))
        .mount(mock.server())
        .await;
    let id = label_queued(&h, LABEL_REMOVE, remove_params("absent")).await?;
    let p = opened(&h, &id)?;
    assert!(p.approvable, "{:?}", p.body);
    match &p.body {
        PreviewBody::WriteSummary { rows, .. } => {
            assert!(rows.iter().any(|(k, _)| k == "Not present"), "{rows:?}");
        }
        other => return Err(format!("not a summary: {other:?}").into()),
    }
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(
        (env.status, exit(&env)),
        (Status::Failed, 6),
        "{}",
        env.to_json_line()
    );
    assert_eq!(code(&env), "upstream_http");
    assert_eq!(detail(&env, "status"), json!(404));
    assert_eq!(requests_with(mock, "DELETE").await.len(), 1);
    Ok(())
}

/// Label names are checked by the params schema before anything is fetched: the allowed
/// characters, 255 characters, 1 to 20 distinct labels (distinct case-sensitively: Confluence folds
/// case, so `A` and `a` are sent as two entries and the server keeps one), and `.`/`..` for a
/// remove (the URL builder).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn label_names_validated_before_any_hit() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    label_server(mock, 204).await;
    let before = mock.received().await.len();
    let long = "a".repeat(256);
    let many: Vec<String> = (0..21).map(|i| format!("l{i}")).collect();
    let cases: Vec<(&str, Value)> = vec![
        (LABEL_ADD, json!({"id": ID, "labels": []})),
        (LABEL_ADD, json!({"id": ID, "labels": ["has space"]})),
        (LABEL_ADD, json!({"id": ID, "labels": ["slash/x"]})),
        (LABEL_ADD, json!({"id": ID, "labels": ["tab\t"]})),
        (LABEL_ADD, json!({"id": ID, "labels": ["a", "a"]})),
        (LABEL_ADD, json!({"id": ID, "labels": [long.clone()]})),
        (LABEL_ADD, json!({"id": ID, "labels": many})),
        (LABEL_ADD, json!({"id": "abc", "labels": ["a"]})),
        (LABEL_REMOVE, json!({"id": ID, "label": ""})),
        (LABEL_REMOVE, json!({"id": ID, "label": "a b"})),
        (LABEL_REMOVE, json!({"id": ID, "label": "a?b"})),
        (LABEL_REMOVE, json!({"id": ID, "label": long})),
        (LABEL_REMOVE, json!({"id": ID, "label": ".."})),
        (LABEL_REMOVE, json!({"id": ID, "label": "."})),
    ];
    for (op, params) in cases {
        let env = h.submit(op, params.clone()).await;
        assert_eq!(
            env.status,
            Status::Failed,
            "{op} {params}: {}",
            env.to_json_line()
        );
        assert_eq!(code(&env), "validation", "{op} {params}");
        assert_eq!(exit(&env), 2, "{op} {params}");
    }
    assert_eq!(mock.received().await.len(), before, "no wiremock hit");
    Ok(())
}

/// §5.4 step 5: no stale rule, but the pre-write identity call still runs for a label write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn label_write_identity_call_runs() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    label_server(mock, 204).await;
    let id = label_queued(&h, LABEL_REMOVE, remove_params("release")).await?;
    h.approver().open(&id).map_err(de)?;
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    mock.server().reset().await;
    mock.confluence_user_current(UserKind::Anonymous, "", "")
        .await;
    h.approver().approve(&id).map_err(de)?;
    assert!(!item_after(&h, &id, rev).await?.approvable);
    let reasons: Vec<Value> = h
        .events(&id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::WRITE_STALE)
        .map(|(_, p)| p["reason"].clone())
        .collect();
    assert_eq!(reasons, [json!("identity_mismatch")]);
    assert!(
        requests_with(mock, "DELETE").await.is_empty(),
        "nothing was sent"
    );
    Ok(())
}
