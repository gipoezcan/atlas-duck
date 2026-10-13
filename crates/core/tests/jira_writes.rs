#![cfg(feature = "testing")]
//! `jira.comment.add` and `jira.issue.transition` previews (Task 14): the comment card with its
//! construct list and visibility (PD-47), the transition card with from and to status, the fields
//! and the comment set during the transition, the required-field Caution of the transition screen,
//! transition name resolution (I-35 transition), the verbatim transition comment (PD-42) and the
//! identity call before a Markdown comment (I-28).

mod common;

use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_convert::{markdown_to_wiki, wiki_to_text};
use atlas_duck_core::lifecycle::model::Hold;
use atlas_duck_core::ops::{
    EnrichCtx, EnrichVerdict, ExecCtx, ExecPlan, PreviewCtx, PreviewInput, PreviewModel, WriteView,
    op_table,
};
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::Harness;
use atlas_duck_core::{DecisionError, DenyDetails, QueueItem};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::form::InputKind;
use atlas_duck_preview::{ConstructList, Level, Preview, PreviewBody, WarningId};
use common::{TestError, TestResult, de, request_id};
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::path;

const COMMENT: &str = "jira.comment.add";
const TRANSITION: &str = "jira.issue.transition";
const KEY: &str = "ABC-1";

// ---- pure helpers: the op table without the engine -------------------------------------------

fn spec(op: &str) -> Result<&'static atlas_duck_registry::OperationSpec, TestError> {
    atlas_duck_registry::get(op).ok_or_else(|| format!("no {op}").into())
}

/// The write requests of `op` for `params` (the verdict, when the op has one).
fn requests(
    op: &str,
    params: &Value,
    verdict: Option<&EnrichVerdict>,
) -> Result<Vec<atlas_duck_atlassian::HttpRequestSpec>, TestError> {
    let base = atlas_duck_atlassian::normalize_base_url("https://jira.example.invalid")?;
    let imp = op_table().get(op).ok_or("no OpImpl")?;
    let ctx = ExecCtx {
        spec: spec(op)?,
        params,
        base: &base,
        enrichment: verdict,
        effective_max: None,
        comments_cap: None,
        test_fault: None,
    };
    match (imp.executor)(&ctx) {
        Ok(ExecPlan::Write(r)) => Ok(r),
        other => Err(format!("not a write: {other:?}").into()),
    }
}

fn preview_of(
    op: &str,
    params: &Value,
    verdict: Option<&EnrichVerdict>,
) -> Result<(PreviewModel, Vec<atlas_duck_atlassian::HttpRequestSpec>), TestError> {
    let reqs = requests(op, params, verdict)?;
    let imp = op_table().get(op).ok_or("no OpImpl")?;
    let ctx = PreviewCtx {
        spec: spec(op)?,
        instance_alias: "jira-main",
        params,
        input: PreviewInput::Write(WriteView {
            requests: &reqs,
            hold: Hold::Preview,
            enrichment: verdict,
            failure: None,
        }),
        field_names: None,
    };
    Ok(((imp.previewer)(&ctx), reqs))
}

struct Summary {
    sentence: String,
    rows: Vec<(String, String)>,
    constructs: Option<ConstructList>,
}

fn summary(m: &PreviewModel) -> Result<Summary, TestError> {
    match &m.body {
        PreviewBody::WriteSummary {
            sentence,
            rows,
            constructs,
            requests,
        } => {
            assert_eq!(requests.len(), 1, "the exact request list stays (inv. 4)");
            Ok(Summary {
                sentence: sentence.clone(),
                rows: rows.clone(),
                constructs: constructs.clone(),
            })
        }
        other => Err(format!("not a write summary: {other:?}").into()),
    }
}

fn row<'a>(s: &'a Summary, name: &str) -> Option<&'a str> {
    s.rows
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

fn comment_preview(params: &Value) -> Result<(PreviewModel, Value), TestError> {
    let (m, reqs) = preview_of(COMMENT, params, None)?;
    let wire: Value = serde_json::from_slice(&reqs.first().ok_or("no request")?.body)?;
    Ok((m, wire))
}

// ---- comment.add ------------------------------------------------------------------------------

#[test]
fn comment_preview_lists_constructs() -> TestResult {
    let (m, wire) = comment_preview(&json!({
        "key": KEY, "body": "{toc} [~jdoe] [link|https://x]", "body_format": "wiki"
    }))?;
    assert_eq!(wire["body"], "{toc} [~jdoe] [link|https://x]");
    let s = summary(&m)?;
    assert_eq!(s.sentence, "Comment on ABC-1");
    let c = s.constructs.clone().ok_or("no constructs")?;
    assert_eq!(c.macros, ["toc"]);
    assert_eq!(c.mentions, ["jdoe"]);
    assert_eq!(c.links, ["https://x"]);
    assert!(c.includes.is_empty() && c.images.is_empty() && c.attachments.is_empty());
    let body = row(&s, "Body").ok_or("no Body row")?;
    assert!(!body.contains("<a"), "{body}");
    assert!(body.contains("link"), "the rendered text is shown: {body}");
    // No visibility, no restriction warning.
    assert!(row(&s, "Visibility").is_none());
    assert!(
        !m.warnings
            .iter()
            .any(|w| w.id == WarningId::RestrictedComments)
    );
    Ok(())
}

#[test]
fn comment_preview_markdown_rendered() -> TestResult {
    let md = "Some **bold** and more";
    let (m, wire) = comment_preview(&json!({ "key": KEY, "body": md }))?;
    // The wire body is the converter's output with its trailing newline (T7), read back from the
    // request, not converted a second time by the previewer.
    let (expected, _) = markdown_to_wiki(md);
    assert_eq!(wire["body"], expected);
    assert!(expected.ends_with('\n'));
    let s = summary(&m)?;
    let body = row(&s, "Body").ok_or("no Body row")?;
    assert_eq!(
        body,
        wiki_to_text(&expected),
        "the converted wiki, rendered"
    );
    assert!(body.contains("Some bold and more"), "{body}");
    assert!(!body.contains("**"), "{body}");
    assert_eq!(s.constructs, Some(ConstructList::default()), "none emitted");
    Ok(())
}

/// T14 review I1: §6.2 defines `restricted_comments` for released reads; a restricted comment
/// being written is the protective choice, shows its Visibility row and raises no Caution (it
/// would inflate the queue's Caution count).
#[test]
fn comment_visibility_row_without_a_restricted_comments_caution() -> TestResult {
    let (m, wire) = comment_preview(&json!({
        "key": KEY, "body": "x", "body_format": "wiki",
        "visibility": {"type": "role", "value": "Administrators"}
    }))?;
    assert_eq!(
        wire["visibility"],
        json!({"type": "role", "value": "Administrators"})
    );
    let s = summary(&m)?;
    assert_eq!(row(&s, "Visibility"), Some("role: Administrators"));
    assert!(
        m.warnings
            .iter()
            .all(|w| w.id != WarningId::RestrictedComments && w.level != Level::Caution),
        "{:?}",
        m.warnings
    );
    // Role and group text are escaped, one line.
    let (m, _) = comment_preview(&json!({
        "key": KEY, "body": "x", "body_format": "wiki",
        "visibility": {"type": "group", "value": "a\u{202e}b\nc"}
    }))?;
    let s = summary(&m)?;
    let shown = row(&s, "Visibility").ok_or("no Visibility row")?;
    assert_eq!(shown, "group: a⟨U+202E⟩b⟨U+000A⟩c", "{shown}");
    assert!(
        m.warnings
            .iter()
            .all(|w| w.id != WarningId::RestrictedComments)
    );
    Ok(())
}

/// T14 review M3: the card reads the request that is sent. A request whose wire body differs from
/// the params (a previewer converting `params.body` a second time would show the params' text).
#[test]
fn comment_preview_reads_the_rendered_request_not_the_params() -> TestResult {
    let params = json!({ "key": KEY, "body": "FROM PARAMS {panel}", "body_format": "wiki" });
    let mut reqs = requests(COMMENT, &params, None)?;
    let first = reqs.first_mut().ok_or("no request")?;
    first.body = serde_json::to_vec(&json!({
        "body": "FROM WIRE {toc}",
        "visibility": {"type": "role", "value": "Wire"}
    }))?;
    let imp = op_table().get(COMMENT).ok_or("no OpImpl")?;
    let ctx = PreviewCtx {
        spec: spec(COMMENT)?,
        instance_alias: "jira-main",
        params: &params,
        input: PreviewInput::Write(WriteView {
            requests: &reqs,
            hold: Hold::Preview,
            enrichment: None,
            failure: None,
        }),
        field_names: None,
    };
    let m = (imp.previewer)(&ctx);
    let s = summary(&m)?;
    let body = row(&s, "Body").ok_or("no Body row")?;
    assert!(body.contains("FROM WIRE"), "{body}");
    assert!(!body.contains("PARAMS"), "{body}");
    assert_eq!(row(&s, "Visibility"), Some("role: Wire"));
    let c = s.constructs.ok_or("no constructs")?;
    assert_eq!(c.macros, ["toc"], "the constructs of the sent body");
    Ok(())
}

#[test]
fn comment_preview_escapes_and_caps_what_it_shows() -> TestResult {
    // Invisible characters show as escapes, in the body and in the visibility value.
    let (m, _) = comment_preview(&json!({
        "key": KEY, "body": "a\u{202e}b {toc\u{202e}}", "body_format": "wiki",
        "visibility": {"type": "group", "value": "x\u{202e}y"}
    }))?;
    let s = summary(&m)?;
    // Every shown text, not its Debug form (which escapes U+202E itself).
    for (name, value) in &s.rows {
        assert!(!value.contains('\u{202e}'), "{name}: {value}");
    }
    assert!(row(&s, "Body").is_some_and(|b| b.contains("a⟨U+202E⟩b")));
    assert_eq!(row(&s, "Visibility"), Some("group: x⟨U+202E⟩y"));
    // A body of 20 000 chars that each escape to 10 bytes: the cut counts escaped bytes.
    let big = "\u{202e}".repeat(20_000);
    let (m, _) = comment_preview(&json!({ "key": KEY, "body": big, "body_format": "wiki" }))?;
    let s = summary(&m)?;
    let body = row(&s, "Body").ok_or("no Body row")?;
    assert!(body.len() <= 16 * 1024 + 200, "{} bytes shown", body.len());
    assert!(body.contains("see Raw"), "the cut says so");
    assert!(m.header.hidden_in_preview_bytes > 0);
    // No escape is cut in half: without the "… N more bytes" suffix the body ends on a whole
    // escape, and its opening and closing brackets pair up.
    let (cut_text, _) = body.rsplit_once('…').ok_or("no cut marker")?;
    assert!(cut_text.ends_with('⟩'), "the body ends in a split escape");
    assert_eq!(cut_text.matches('⟨').count(), cut_text.matches('⟩').count());
    // One unit (T14 review M7): the count in the suffix is the header's hidden count.
    let said: u64 = body
        .rsplit_once("… ")
        .and_then(|(_, tail)| tail.split(' ').next())
        .ok_or("no count")?
        .parse()?;
    assert_eq!(said, m.header.hidden_in_preview_bytes);
    Ok(())
}

// ---- transition -------------------------------------------------------------------------------

fn transitions_answer() -> Value {
    json!({"expand": "transitions", "transitions": [
        {"id": "21", "name": "Start Progress",
         "to": {"id": "3", "name": "In Progress"}, "fields": {}},
        {"id": "31", "name": "Done", "to": {"id": "10001", "name": "Done"},
         "fields": {
            "resolution": {"required": true, "name": "Resolution",
                           "schema": {"type": "resolution"},
                           "allowedValues": [{"id": "1", "name": "Fixed"}]},
            "customfield_10300": {"required": true, "hasDefaultValue": true,
                                  "name": "Defaulted", "schema": {"type": "string"}},
            "customfield_10301": {"required": false, "name": "Optional",
                                  "schema": {"type": "string"}}
         }}
    ]})
}

fn status_answer(id: &str, name: &str) -> Value {
    json!({"id": "10001", "key": KEY, "fields": {"status": {"id": id, "name": name}}})
}

fn judge(params: &Value, answers: &[Value]) -> Result<EnrichVerdict, TestError> {
    let rule = op_table()
        .get(TRANSITION)
        .and_then(|i| i.enrich)
        .ok_or("no enrich rule")?;
    let ctx = EnrichCtx {
        spec: spec(TRANSITION)?,
        params,
    };
    Ok((rule.judge)(&ctx, answers))
}

fn transition_preview(
    params: &Value,
    transitions: &Value,
) -> Result<(PreviewModel, EnrichVerdict, Value), TestError> {
    let v = judge(
        params,
        &[transitions.clone(), status_answer("3", "In Progress")],
    )?;
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    let (m, reqs) = preview_of(TRANSITION, params, Some(&v))?;
    let wire: Value = serde_json::from_slice(&reqs.first().ok_or("no request")?.body)?;
    Ok((m, v, wire))
}

struct Card {
    transition: String,
    from: String,
    to: String,
    fields: Vec<(String, String)>,
    constructs: Option<ConstructList>,
}

fn card(m: &PreviewModel) -> Result<Card, TestError> {
    match &m.body {
        PreviewBody::Transition {
            transition,
            from,
            to,
            fields,
            constructs,
            requests,
        } => {
            assert_eq!(requests.len(), 1, "the exact request list stays (inv. 4)");
            Ok(Card {
                transition: transition.clone(),
                from: from.clone(),
                to: to.clone(),
                fields: fields.clone(),
                constructs: constructs.clone(),
            })
        }
        other => Err(format!("not a transition card: {other:?}").into()),
    }
}

#[test]
fn transition_preview_from_to_and_fields() -> TestResult {
    let params = json!({
        "key": KEY, "transition": "Done", "fields": {"resolution": {"name": "Fixed"}}
    });
    let (m, v, wire) = transition_preview(&params, &transitions_answer())?;
    // Facts (Δ4): the status the issue is in and the status the transition leads to.
    let facts = v.summary.as_ref().ok_or("no facts")?;
    assert_eq!(facts.from_status.as_deref(), Some("In Progress"));
    assert_eq!(facts.to_status.as_deref(), Some("Done"));
    assert_eq!(wire["transition"], json!({"id": "31"}));
    let c = card(&m)?;
    assert_eq!((c.from.as_str(), c.to.as_str()), ("In Progress", "Done"));
    // T14 review M5: the transition the agent asked for, by name and id.
    assert_eq!(c.transition, "Done (31)");
    // A field row is named like the Caution names a field (`<name> (<id>)`) where the transition
    // screen names it, with the value as it is sent.
    assert_eq!(
        c.fields,
        [(
            "Resolution (resolution)".to_owned(),
            r#"{"name":"Fixed"}"#.to_owned()
        )]
    );
    assert_eq!(c.constructs, None, "no comment, no constructs");
    // The required field is set: no Caution.
    assert!(
        m.warnings.iter().all(|w| w.level != Level::Caution),
        "{:?}",
        m.warnings
    );
    Ok(())
}

#[test]
fn transition_required_fields_are_a_caution_that_does_not_block() -> TestResult {
    // `resolution` is required without a default and not set; the default-valued and the optional
    // ones are not listed.
    let params = json!({ "key": KEY, "transition": "Done" });
    let (m, v, _) = transition_preview(&params, &transitions_answer())?;
    assert_eq!(v.hold, Hold::Preview, "never a block (PD-49)");
    assert_eq!(v.missing_fields_total, 1);
    assert_eq!(v.missing_fields.len(), 1);
    assert_eq!(v.missing_fields[0].id, "resolution");
    let w: Vec<_> = m
        .warnings
        .iter()
        .filter(|w| w.id == WarningId::MissingRequiredFields)
        .collect();
    assert_eq!(w.len(), 1, "{:?}", m.warnings);
    assert_eq!(
        w[0].text,
        "missing required fields: Resolution (resolution, resolution)"
    );
    // A transition without a screen (`Start Progress`) has none.
    let (m, v, _) = transition_preview(
        &json!({ "key": KEY, "transition": "Start Progress" }),
        &transitions_answer(),
    )?;
    assert_eq!(v.missing_fields_total, 0);
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);
    // The comment param sets a required `comment` field.
    let mut t = transitions_answer();
    t["transitions"][0]["fields"] = json!({
        "comment": {"required": true, "name": "Comment", "schema": {"type": "comment"}}
    });
    let (_, v, _) = transition_preview(&json!({ "key": KEY, "transition": "21" }), &t)?;
    assert_eq!(v.missing_fields_total, 1);
    let (_, v, _) = transition_preview(
        &json!({ "key": KEY, "transition": "21", "comment": "ok" }),
        &t,
    )?;
    assert_eq!(v.missing_fields_total, 0);
    Ok(())
}

#[test]
fn transition_comment_is_listed_and_sent_verbatim() -> TestResult {
    let params = json!({
        "key": KEY, "transition": "Start Progress", "comment": "{toc} [~jdoe] see [x|https://y]"
    });
    let (m, _, wire) = transition_preview(&params, &transitions_answer())?;
    // PD-42: wiki markup as given, in `update.comment`.
    assert_eq!(
        wire["update"]["comment"],
        json!([{"add": {"body": "{toc} [~jdoe] see [x|https://y]"}}])
    );
    let c = card(&m)?;
    let k = c.constructs.ok_or("no constructs")?;
    assert_eq!(k.macros, ["toc"]);
    assert_eq!(k.mentions, ["jdoe"]);
    assert_eq!(k.links, ["https://y"]);
    let comment = c
        .fields
        .iter()
        .find(|(n, _)| n == "comment (update.comment)")
        .ok_or("no comment row")?;
    assert!(comment.1.contains("see"), "{comment:?}");
    assert!(!comment.1.contains("<a"));
    Ok(())
}

/// T14 review M8: a `fields.comment` entry and the `comment` param are two rows with two labels.
#[test]
fn transition_comment_rows_have_distinct_labels() -> TestResult {
    let params = json!({
        "key": KEY, "transition": "Start Progress", "comment": "plain",
        "fields": {"comment": [{"add": {"body": "other"}}]}
    });
    let (m, _, _) = transition_preview(&params, &transitions_answer())?;
    let c = card(&m)?;
    let labels: Vec<&str> = c.fields.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(labels.len(), 2, "{labels:?}");
    assert_ne!(labels[0], labels[1], "{labels:?}");
    assert!(labels.contains(&"comment (update.comment)"), "{labels:?}");
    Ok(())
}

/// T14 review M8: the `fields` rows are bounded; the rest is said and counted as hidden.
#[test]
fn transition_field_rows_are_capped_and_counted() -> TestResult {
    let mut fields = serde_json::Map::new();
    for n in 0..60 {
        fields.insert(format!("customfield_{n:03}"), json!("v".repeat(40)));
    }
    let params = json!({ "key": KEY, "transition": "Start Progress", "fields": fields });
    let (m, _, _) = transition_preview(&params, &transitions_answer())?;
    let c = card(&m)?;
    assert!(c.fields.len() <= 26, "{} rows", c.fields.len());
    let (label, note) = c.fields.last().ok_or("no rows")?;
    assert!(
        label.contains("more fields") || note.contains("more fields"),
        "{label} {note}"
    );
    assert!(m.header.hidden_in_preview_bytes > 0);
    // A short list shows no note.
    let params = json!({ "key": KEY, "transition": "Start Progress", "fields": {"a": 1} });
    let (m, _, _) = transition_preview(&params, &transitions_answer())?;
    assert!(
        !card(&m)?
            .fields
            .iter()
            .any(|(n, v)| n.contains("more fields") || v.contains("more fields"))
    );
    Ok(())
}

#[test]
fn transition_card_escapes_what_the_server_names() -> TestResult {
    let mut t = transitions_answer();
    t["transitions"][1]["to"]["name"] = json!("Do\u{202e}ne");
    t["transitions"][1]["fields"]["resolution"]["name"] = json!("Reso\u{202e}lution");
    let v = judge(
        &json!({"key": KEY, "transition": "31", "fields": {"resolution": {"name": "Fixed"}}}),
        &[t, status_answer("3", "In\nProgress\u{202e}")],
    )?;
    let params =
        json!({"key": KEY, "transition": "31", "fields": {"resolution": {"name": "Fixed"}}});
    let (m, _) = preview_of(TRANSITION, &params, Some(&v))?;
    let c = card(&m)?;
    let shown = format!("{c:?}", c = (&c.from, &c.to, &c.fields));
    assert!(!shown.contains('\u{202e}'), "{shown}");
    assert!(shown.contains("⟨U+202E⟩"), "{shown}");
    assert!(!c.from.contains('\n') && !c.to.contains('\n'));
    Ok(())
}

// ---- end to end -------------------------------------------------------------------------------

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

async fn records(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let id = request_id(&h.submit(op, params).await)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

fn opened(h: &Harness, id: &str) -> Result<Preview, TestError> {
    Ok(h.approver().open(id).map_err(de)?.preview)
}

async fn mount_post(mock: &MockDc, p: &str, status: u16) {
    Mock::given(wiremock::matchers::method("POST"))
        .and(path(mock.path(p)))
        .respond_with(mock.response(status))
        .with_priority(1)
        .mount(mock.server())
        .await;
}

async fn posts(mock: &MockDc, p: &str) -> Vec<wiremock::Request> {
    let full = mock.path(p);
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == full)
        .collect()
}

async fn mount_transitions(mock: &MockDc, transitions: &Value) {
    mock.json(
        "/rest/api/2/issue/ABC-1/transitions",
        200,
        &transitions.to_string(),
    )
    .await;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transition_comment_sent_verbatim() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_transitions(mock, &transitions_answer()).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_post(mock, "/rest/api/2/issue/ABC-1/transitions", 204).await;
    let id = queued(
        &h,
        TRANSITION,
        json!({
            "key": KEY, "transition": "done", "comment": "{toc}",
            "fields": {"resolution": {"name": "Fixed"}}
        }),
    )
    .await?;
    let p = opened(&h, &id)?;
    match &p.body {
        PreviewBody::Transition {
            from,
            to,
            fields,
            constructs,
            ..
        } => {
            // The fixture issue is `In Progress`.
            assert_eq!((from.as_str(), to.as_str()), ("In Progress", "Done"));
            assert!(fields.iter().any(|(n, _)| n == "comment (update.comment)"));
            assert_eq!(
                constructs.as_ref().map(|c| c.macros.clone()),
                Some(vec!["toc".to_owned()])
            );
        }
        other => return Err(format!("not the transition card: {other:?}").into()),
    }
    assert!(p.approvable);
    assert!(p.edit_form.is_some(), "an edit form on every write preview");
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let sent = posts(mock, "/rest/api/2/issue/ABC-1/transitions").await;
    assert_eq!(sent.len(), 1);
    let body: Value = serde_json::from_slice(&sent[0].body)?;
    assert_eq!(body["update"]["comment"][0]["add"]["body"], "{toc}");
    assert_eq!(body["transition"], json!({"id": "31"}));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transition_missing_field_has_a_preadded_input_and_stays_approvable() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_transitions(mock, &transitions_answer()).await;
    let id = queued(&h, TRANSITION, json!({ "key": KEY, "transition": "Done" })).await?;
    let p = opened(&h, &id)?;
    assert!(
        p.approvable,
        "a missing required field is a Caution, not a block"
    );
    assert!(
        p.warnings
            .iter()
            .any(|w| w.id == WarningId::MissingRequiredFields)
    );
    let form = p.edit_form.ok_or("no edit form")?;
    let input = form
        .inputs
        .iter()
        .find(|i| i.path == "fields.resolution")
        .ok_or("no pre-added input")?;
    assert!(input.pre_added && input.required && !input.read_only);
    assert!(
        matches!(input.kind, InputKind::Choice(_)),
        "{:?}",
        input.kind
    );
    // The targets stay read-only (L06): the issue key and the transition name's baseline.
    let read_only = |path: &str| form.inputs.iter().any(|i| i.path == path && i.read_only);
    assert!(read_only("key"));
    // Denying with the missing-fields hint is accepted (§4.3): exit 3, `missing_fields` listed.
    h.approver()
        .deny_with(
            &id,
            "set a resolution",
            DenyDetails::MissingFields {
                include_allowed_values: true,
            },
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Denied);
    let listed = common::detail(&env, "missing_fields");
    assert_eq!(listed[0]["id"], "resolution");
    assert_eq!(listed[0]["allowed_values"], json!(["Fixed"]));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transition_picking_the_missing_field_reruns_enrichment_and_sends_it() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_transitions(mock, &transitions_answer()).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_post(mock, "/rest/api/2/issue/ABC-1/transitions", 204).await;
    let id = queued(&h, TRANSITION, json!({ "key": KEY, "transition": "Done" })).await?;
    let rev = h.approver().rev(&id).map_err(de)?;
    let before = records(&h, &id, EventType::PREVIEW_FETCH).await?.len();
    h.approver()
        .choose_preadded(&id, "fields.resolution", "Fixed")
        .map_err(de)?;
    let item = item_after(&h, &id, rev.counter).await?;
    assert!(item.approvable);
    let fetched: Vec<Value> = records(&h, &id, EventType::PREVIEW_FETCH)
        .await?
        .iter()
        .skip(before)
        .map(|f| f["purpose"].clone())
        .collect();
    assert_eq!(fetched, ["resolve", "enrich"], "enrichment ran again");
    let p = opened(&h, &id)?;
    assert!(
        !p.warnings
            .iter()
            .any(|w| w.id == WarningId::MissingRequiredFields),
        "{:?}",
        p.warnings
    );
    match &p.body {
        PreviewBody::Transition { fields, .. } => {
            assert_eq!(fields.len(), 1, "{fields:?}");
            assert_eq!(fields[0].1, r#"{"id":"1"}"#);
        }
        other => return Err(format!("not the transition card: {other:?}").into()),
    }
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert!(env.edited);
    let sent = posts(mock, "/rest/api/2/issue/ABC-1/transitions").await;
    let body: Value = serde_json::from_slice(&sent.first().ok_or("no POST")?.body)?;
    assert_eq!(body["fields"]["resolution"], json!({"id": "1"}));
    Ok(())
}

/// T14 review M2/M4: a required `priority`, and a required array of `version` / `component`, are
/// choices too (an arm removed from `missing_kind` leaves a JSON input); a pick sends `{"id"}`,
/// inside an array for the array fields; a list over ten values says how many are listed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transition_priority_version_component_inputs_are_choices() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    let versions: Vec<Value> = (1..=13)
        .map(|n| json!({"id": format!("{}", 100 + n), "name": format!("v{n}")}))
        .collect();
    let mut t = transitions_answer();
    t["transitions"][1]["fields"] = json!({
        "priority": {"required": true, "name": "Priority", "schema": {"type": "priority"},
                     "allowedValues": [{"id": "2", "name": "High"}, {"id": "3", "name": "Low"}]},
        "fixVersions": {"required": true, "name": "Fix Version/s",
                        "schema": {"type": "array", "items": "version"},
                        "allowedValues": versions},
        "components": {"required": true, "name": "Component/s",
                       "schema": {"type": "array", "items": "component"},
                       "allowedValues": [{"id": "7", "name": "Core"}]}
    });
    mount_transitions(mock, &t).await;
    let id = queued(&h, TRANSITION, json!({ "key": KEY, "transition": "Done" })).await?;
    let form = opened(&h, &id)?.edit_form.ok_or("no edit form")?;
    let input = |path: &str| {
        form.inputs
            .iter()
            .find(|i| i.path == path)
            .ok_or_else(|| format!("no input {path}"))
    };
    for path in ["fields.priority", "fields.fixVersions", "fields.components"] {
        let i = input(path)?;
        assert!(
            matches!(i.kind, InputKind::Choice(_)),
            "{path}: {:?}",
            i.kind
        );
    }
    // The ten-value cap says so (M4); free-form entry beyond the list is refused (a label the
    // choice does not list is not a value).
    let label = &input("fields.fixVersions")?.label;
    assert!(label.contains("10 of 13 values listed"), "{label}");
    for (path, pick, wire) in [
        ("fields.priority", "High", json!({"id": "2"})),
        ("fields.fixVersions", "v1", json!([{"id": "101"}])),
        ("fields.components", "Core", json!([{"id": "7"}])),
    ] {
        let rev = h.approver().rev(&id).map_err(de)?;
        h.approver().choose_preadded(&id, path, pick).map_err(de)?;
        item_after(&h, &id, rev.counter).await?;
        let key = path.trim_start_matches("fields.");
        let sent = opened(&h, &id)?;
        match sent.body {
            PreviewBody::Transition { requests, .. } => {
                let body = match &requests.first().ok_or("no request")?.body {
                    atlas_duck_preview::BodyView::Text(t) => t.clone(),
                    other => return Err(format!("body: {other:?}").into()),
                };
                let body: Value = serde_json::from_str(&body)?;
                assert_eq!(body["fields"][key], wire, "{path}");
            }
            other => return Err(format!("not the transition card: {other:?}").into()),
        }
    }
    let refused = h
        .approver()
        .choose_preadded(&id, "fields.fixVersions", "v13");
    assert!(refused.is_err(), "v13 is beyond the listed values");
    Ok(())
}

async fn assert_unresolved(h: &Harness, id: &str, matches: u64, candidates: &[&str]) -> TestResult {
    match opened(h, id)?.body {
        PreviewBody::UnresolvedName {
            param,
            matches: n,
            candidates: c,
            ..
        } => {
            assert_eq!((param.as_str(), n), ("transition", matches));
            assert_eq!(c, candidates);
        }
        other => return Err(format!("not the unresolved-name card: {other:?}").into()),
    }
    let res = h.approver().approve_unopened(id);
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    assert!(records(h, id, EventType::WRITE_APPROVED).await?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i35_transition_no_match_and_ambiguous() -> TestResult {
    let h = Harness::jira().await?;
    mount_transitions(jira(&h)?, &transitions_answer()).await;
    let id = queued(&h, TRANSITION, json!({ "key": KEY, "transition": "Doen" })).await?;
    // No match: every name is a candidate.
    assert_unresolved(&h, &id, 0, &["Start Progress", "Done"]).await?;
    assert_eq!(records(&h, &id, EventType::PREVIEW_FETCH).await?.len(), 2);

    let h = Harness::jira().await?;
    let two_close = json!({"transitions": [
        {"id": "41", "name": "Close", "to": {"id": "6", "name": "Closed"}, "fields": {}},
        {"id": "42", "name": "Close", "to": {"id": "7", "name": "Resolved"}, "fields": {}},
        {"id": "43", "name": "Reopen", "to": {"id": "4", "name": "Reopened"}, "fields": {}}
    ]});
    mount_transitions(jira(&h)?, &two_close).await;
    let id = queued(&h, TRANSITION, json!({ "key": KEY, "transition": "close" })).await?;
    assert_unresolved(&h, &id, 2, &["Close", "Close"]).await?;
    // The deny hint the user ticks carries the candidates, nothing else of the card.
    h.approver()
        .deny_with(
            &id,
            "two Close transitions",
            DenyDetails::ResolutionFailed {
                include_candidates: true,
            },
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Denied);
    assert_eq!(common::code(&env), "resolution_failed");
    assert_eq!(
        common::detail(&env, "candidates"),
        json!(["Close", "Close"])
    );
    // Nothing was sent.
    assert!(
        posts(jira(&h)?, "/rest/api/2/issue/ABC-1/transitions")
            .await
            .is_empty()
    );
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
async fn i28_markdown_comment_identity_call_stale() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.json(
        "/rest/api/2/issue/ABC-1/comment",
        201,
        fixtures::JIRA_COMMENT,
    )
    .await;
    let id = queued(
        &h,
        COMMENT,
        json!({ "key": KEY, "body": "Reproduced on **staging**." }),
    )
    .await?;
    let p = opened(&h, &id)?;
    match &p.body {
        PreviewBody::WriteSummary { rows, .. } => {
            let body = rows
                .iter()
                .find(|(n, _)| n == "Body")
                .ok_or("no Body row")?;
            assert!(body.1.contains("Reproduced on staging."), "{body:?}");
        }
        other => return Err(format!("not the comment card: {other:?}").into()),
    }
    let before = h.approver().item(&id).ok_or("not queued")?;
    // From here the identity call answers as anonymous (the PAT stopped working).
    mock.server().reset().await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Anonymous)
        .await;
    mock.json(
        "/rest/api/2/issue/ABC-1/comment",
        201,
        fixtures::JIRA_COMMENT,
    )
    .await;
    h.approver().approve(&id).map_err(de)?;
    let after = item_after(&h, &id, before.candidate_rev.counter).await?;
    assert!(!after.approvable, "Approve is disabled");
    let reasons: Vec<Value> = records(&h, &id, EventType::WRITE_STALE)
        .await?
        .into_iter()
        .map(|p| p["reason"].clone())
        .collect();
    assert_eq!(reasons, [json!("identity_mismatch")]);
    assert!(
        posts(mock, "/rest/api/2/issue/ABC-1/comment")
            .await
            .is_empty(),
        "nothing was sent"
    );
    Ok(())
}
