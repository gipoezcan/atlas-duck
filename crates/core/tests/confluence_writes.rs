#![cfg(feature = "testing")]
//! `confluence.comment.add` (M7 Task 18, PD-107; §7.4 payload verbatim): the container type from
//! the enrichment, the reply `ancestors` after the `reply_to` resolution (a comment on this very
//! content, else the unresolved-name hold), the `ContentWrite` card (the outgoing storage rendered
//! locally, its constructs listed), no stale rule and the pre-write identity call that still runs.
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
