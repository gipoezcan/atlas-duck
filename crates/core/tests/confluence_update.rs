#![cfg(feature = "testing")]
//! `confluence.page.update` complete (M7 Task 15, PD-104, PD-111): the two enrichment stages (the
//! current page, then the agent's base version when it is behind), the conflict hold and its card
//! (the rendered diff base → current, the agent's intended change, the requests; I-36, I-06),
//! the edit preview (rendered and raw diffs, raw-only changes, the outgoing storage constructs;
//! S-12), the lossy check of a Markdown update and the hold over an unparsable current body, the
//! sent version, and the I-32 re-render of a Markdown update.
//!
//! The previews are checked twice: as pure functions of the op table (judge, executor,
//! previewer, as the engine calls them) and end to end through the harness.

mod common;

use std::sync::Arc;
use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, UserKind, fixtures};
use atlas_duck_atlassian::{GetCall, HttpRequestSpec};
use atlas_duck_audit::EventType;
use atlas_duck_convert::{
    UserResolutions, markdown_to_storage, storage_lines, storage_to_markdown_within,
};
use atlas_duck_core::lifecycle::model::Hold;
use atlas_duck_core::ops::{
    EnrichCtx, EnrichFailure, EnrichStep, EnrichVerdict, ExecCtx, ExecError, ExecPlan, PreviewCtx,
    PreviewInput, PreviewModel, WriteView, confluence, op_table,
};
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::Harness;
use atlas_duck_core::{
    BatchFailure, BatchItem, BuildPause, Confirm, DecisionError, Edits, Pause, TestHooks,
};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::diff::{DiffLine, DiffOp, line_diff, line_diff_lines};
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::warning;
use atlas_duck_preview::{Level, PreviewBody, WarningId};
use common::confluence::{content_path, mount_history_version, mount_page, page_with_storage};
use common::{TestError, TestResult, code, de, exit, request_id};
use secrecy::SecretString;
use serde_json::{Map, Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const UPDATE: &str = "confluence.page.update";
const ID: &str = "65537";

/// PD-94 (plan text): the hold over a Markdown update whose current page does not parse.
const UNPARSABLE: &str =
    "the current page storage could not be parsed; what this update removes cannot be counted";

// ---- pure helpers: the op table as the engine calls it -----------------------------------------

fn spec() -> Result<&'static atlas_duck_registry::OperationSpec, TestError> {
    atlas_duck_registry::get(UPDATE).ok_or_else(|| "no confluence.page.update".into())
}

/// The fixture page (`Release checklist`, space `DOC`) at `version` with `storage` as its body.
fn page(version: u64, storage: &str) -> Value {
    let mut p = page_with_storage(storage);
    p["version"]["number"] = json!(version);
    p
}

/// What `?version=<v>&status=historical&expand=body.storage` answers: the page as it was.
fn historical(version: u64, storage: &str) -> Value {
    let mut p = page(version, storage);
    p["status"] = json!("historical");
    p
}

fn params(base: u64, body: &str, format: Option<&str>) -> Value {
    let mut p = json!({ "id": ID, "base_version": base, "body": body });
    if let Some(f) = format {
        p["body_format"] = json!(f);
    }
    p
}

/// The rule's rounds over `answers` the way the engine's staged driver feeds them (each round's
/// GETs take the next answers), then the judge.
fn staged(
    params: &Value,
    answers: &[Value],
) -> Result<(Vec<Vec<GetCall>>, EnrichVerdict), TestError> {
    let rule = op_table()
        .get(UPDATE)
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
                rounds.push(calls.into_iter().map(|(_, c)| c).collect());
            }
        }
        if rounds.len() > 4 {
            return Err("more than four rounds".into());
        }
    }
    Ok((rounds, (rule.judge)(&ctx, &given)))
}

/// The executor's requests for `v` (the engine renders under `Preview` and `Conflict`); an empty
/// list when it needs another verdict.
fn requests(params: &Value, v: &EnrichVerdict) -> Result<Vec<HttpRequestSpec>, TestError> {
    let base = atlas_duck_atlassian::normalize_base_url("https://wiki.example.invalid/wiki")?;
    let imp = op_table().get(UPDATE).ok_or("no OpImpl")?;
    let ctx = ExecCtx {
        spec: spec()?,
        params,
        base: &base,
        enrichment: Some(v),
        effective_max: None,
        comments_cap: None,
        test_fault: None,
    };
    match (imp.executor)(&ctx) {
        Ok(ExecPlan::Write(r)) => Ok(r),
        Err(ExecError::EnrichmentRequired) => Ok(Vec::new()),
        other => Err(format!("not a write: {other:?}").into()),
    }
}

fn preview_of(
    params: &Value,
    v: &EnrichVerdict,
    reqs: &[HttpRequestSpec],
    failure: Option<&EnrichFailure>,
) -> Result<PreviewModel, TestError> {
    let imp = op_table().get(UPDATE).ok_or("no OpImpl")?;
    let ctx = PreviewCtx {
        spec: spec()?,
        instance_alias: "wiki",
        params,
        input: PreviewInput::Write(WriteView {
            requests: reqs,
            hold: v.hold,
            enrichment: Some(v),
            failure,
        }),
        field_names: None,
    };
    Ok((imp.previewer)(&ctx))
}

/// [`preview_of`] with the update card's Markdown projections held to `budget` bytes (T15 review
/// m-1: the over-budget path with a small body).
fn preview_within(
    params: &Value,
    v: &EnrichVerdict,
    reqs: &[HttpRequestSpec],
    budget: usize,
) -> Result<PreviewModel, TestError> {
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
    Ok(confluence::update_preview_within(&ctx, budget))
}

/// `reqs` with the first request's JSON body changed by `edit` (what is sent, not the params).
fn swapped(
    mut reqs: Vec<HttpRequestSpec>,
    edit: impl FnOnce(&mut Value),
) -> Result<Vec<HttpRequestSpec>, TestError> {
    let first = reqs.first_mut().ok_or("no request")?;
    let mut body: Value = serde_json::from_slice(&first.body)?;
    edit(&mut body);
    first.body = serde_json::to_vec(&body)?;
    Ok(reqs)
}

/// Judge, executor and previewer over `answers`.
fn preview(params: &Value, answers: &[Value]) -> Result<(EnrichVerdict, PreviewModel), TestError> {
    let (_, v) = staged(params, answers)?;
    let reqs = requests(params, &v)?;
    let m = preview_of(params, &v, &reqs, None)?;
    Ok((v, m))
}

/// The Markdown projection the cards diff (empty user map, PD-104).
fn md(storage: &str) -> Result<String, TestError> {
    storage_to_markdown_within(storage, &UserResolutions::new(), 16 * 1024 * 1024)
        .map(|(m, _, _)| m)
        .map_err(|_| "too large".into())
}

/// A diff's lines as the card carries them: each text display-escaped (core's rule).
fn shown(lines: Vec<DiffLine>) -> Vec<DiffLine> {
    lines
        .into_iter()
        .map(|l| DiffLine {
            op: l.op,
            text: escape_for_display(&l.text),
        })
        .collect()
}

fn rendered_diff(old: &str, new: &str) -> Result<Vec<DiffLine>, TestError> {
    Ok(shown(line_diff(&md(old)?, &md(new)?).lines))
}

fn raw_diff(old: &str, new: &str) -> Vec<DiffLine> {
    shown(line_diff_lines(&storage_lines(old), &storage_lines(new)).lines)
}

fn ids(m: &PreviewModel) -> Vec<WarningId> {
    m.warnings.iter().map(|w| w.id).collect()
}

fn warning_text(m: &PreviewModel, id: WarningId) -> Option<String> {
    m.warnings
        .iter()
        .find(|w| w.id == id)
        .map(|w| w.text.clone())
}

/// The storage the request sends (`body.storage.value`).
fn sent_storage(r: &HttpRequestSpec) -> Result<String, TestError> {
    let body: Value = serde_json::from_slice(&r.body)?;
    body["body"]["storage"]["value"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "no body.storage.value".into())
}

// ---- the stages (pure) --------------------------------------------------------------------------

/// PD-104: stage 1 reads the current page with its storage; only a base behind (or ahead of) the
/// current version asks for the base version's body, as §5.4 step 2 names it.
#[test]
fn stages_fetch_the_base_only_when_it_differs() -> TestResult {
    let p = params(7, "<p>x</p>", Some("storage"));
    let (rounds, v) = staged(&p, &[page(7, "<p>a</p>")])?;
    assert_eq!(rounds.len(), 1);
    assert_eq!(rounds[0][0].endpoint_template, "/rest/api/content/{id}");
    assert_eq!(
        rounds[0][0].query,
        [(
            "expand".to_owned(),
            "body.storage,version,space,ancestors".to_owned()
        )]
    );
    assert_eq!(v.hold, Hold::Preview);
    assert_eq!(
        v.baseline,
        json!({"version": 7, "title": "Release checklist", "space_key": "DOC"})
    );

    let p = params(5, "<p>x</p>", Some("storage"));
    let (rounds, v) = staged(&p, &[page(7, "<p>a</p>"), historical(5, "<p>b</p>")])?;
    assert_eq!(rounds.len(), 2);
    assert_eq!(rounds[1].len(), 1);
    assert_eq!(rounds[1][0].endpoint_template, "/rest/api/content/{id}");
    assert_eq!(
        rounds[1][0].query,
        [
            ("version".to_owned(), "5".to_owned()),
            ("status".to_owned(), "historical".to_owned()),
            ("expand".to_owned(), "body.storage".to_owned()),
        ]
    );
    assert_eq!(v.hold, Hold::Conflict);
    // The stale baseline is the current page's; the conflict names both versions.
    assert_eq!(
        v.baseline,
        json!({"version": 7, "title": "Release checklist", "space_key": "DOC"})
    );
    assert_eq!(
        v.conflict.as_deref(),
        Some(warning::conflict(5, 7).as_str())
    );
    assert_eq!(v.diff_text, "base version v5, current version v7");
    Ok(())
}

/// Fail closed: a stage-2 answer that is not the base version (another version, another page,
/// no storage) is no base body: "enrichment failed", never a diff from the wrong text.
#[test]
fn stage2_answer_that_is_not_the_base_is_unusable() -> TestResult {
    let p = params(5, "<p>x</p>", Some("storage"));
    let mut other_page = historical(5, "<p>b</p>");
    other_page["id"] = json!("99999");
    let mut no_body = historical(5, "<p>b</p>");
    no_body["body"] = json!({});
    // T15 review I-2: an answer that says it is the current page is no historical version (a
    // server or proxy that ignored `version` / `status=historical`), with or without `version`.
    let mut current_status = historical(5, "<p>b</p>");
    current_status["status"] = json!("current");
    let mut bare_current = current_status.clone();
    bare_current
        .as_object_mut()
        .ok_or("not an object")?
        .remove("version");
    for wrong in [
        historical(6, "<p>b</p>"),
        other_page,
        no_body,
        current_status,
        bare_current,
    ] {
        let (_, v) = staged(&p, &[page(7, "<p>a</p>"), wrong])?;
        assert_eq!(v.hold, Hold::EnrichmentError);
    }
    // An answer without `version` (the expand names only the body) is taken as asked for; so is
    // one without `status`.
    let mut bare = historical(5, "<p>b</p>");
    bare.as_object_mut()
        .ok_or("not an object")?
        .remove("version");
    let (_, v) = staged(&p, &[page(7, "<p>a</p>"), bare.clone()])?;
    assert_eq!(v.hold, Hold::Conflict);
    bare.as_object_mut()
        .ok_or("not an object")?
        .remove("status");
    let (_, v) = staged(&p, &[page(7, "<p>a</p>"), bare])?;
    assert_eq!(v.hold, Hold::Conflict);
    Ok(())
}

/// The bodies an update keeps for its card (T15 review I-1, lead ruling c).
fn kept_bodies(v: &EnrichVerdict) -> Result<(Option<String>, Option<String>), TestError> {
    let facts = v
        .summary
        .as_ref()
        .and_then(|s| s.confluence.as_ref())
        .ok_or("no Confluence facts")?;
    let owned = |s: &Option<std::sync::Arc<str>>| s.as_deref().map(str::to_owned);
    Ok((owned(&facts.current_storage), owned(&facts.base_storage)))
}

/// T15 review I-1 (lead ruling c): a current or base body longer than the 16 MiB diff budget is
/// not kept: the judge holds "enrichment failed" with the plan text, Approve disabled, and no
/// body stays in the write's state. A current body past it needs no base body either.
#[test]
fn page_over_the_diff_budget_is_held() -> TestResult {
    const BUDGET: usize = 16 * 1024 * 1024;
    let body = |len: usize| format!("<p>{}</p>", "a".repeat(len - "<p></p>".len()));
    let p = params(7, "<p>x</p>", Some("storage"));
    let (_, v) = staged(&p, &[page(7, &body(BUDGET))])?;
    assert_eq!(v.hold, Hold::Preview, "exactly the budget is kept");

    let (rounds, v) = staged(&p, &[page(7, &body(BUDGET + 1))])?;
    assert_eq!(rounds.len(), 1);
    assert_eq!(v.hold, Hold::EnrichmentError);
    assert_eq!(kept_bodies(&v)?, (None, None));
    let m = preview_of(&p, &v, &requests(&p, &v)?, None)?;
    match &m.body {
        PreviewBody::EnrichmentError { text, status, .. } => {
            assert_eq!(text, confluence::TEXT_PAGE_TOO_LARGE);
            assert_eq!(*status, None);
        }
        other => return Err(format!("not the enrichment card: {other:?}").into()),
    }
    assert!(
        confluence::TEXT_PAGE_TOO_LARGE.contains("16 MiB"),
        "{}",
        confluence::TEXT_PAGE_TOO_LARGE
    );

    // A base behind: the current body past the budget asks for no base body.
    let p = params(5, "<p>x</p>", Some("storage"));
    let (rounds, v) = staged(&p, &[page(7, &body(BUDGET + 1))])?;
    assert_eq!(rounds.len(), 1, "no stage 2");
    assert_eq!(v.hold, Hold::EnrichmentError);
    assert_eq!(kept_bodies(&v)?, (None, None));
    // The base body past it: held the same way, no conflict Caution beside it.
    let (rounds, v) = staged(&p, &[page(7, "<p>a</p>"), historical(5, &body(BUDGET + 1))])?;
    assert_eq!(rounds.len(), 2);
    assert_eq!(v.hold, Hold::EnrichmentError);
    assert_eq!(kept_bodies(&v)?, (None, None));
    assert!(v.warnings.is_empty(), "{:?}", v.warnings);
    assert!(v.conflict.is_none());
    let m = preview_of(&p, &v, &[], None)?;
    assert!(matches!(
        &m.body,
        PreviewBody::EnrichmentError { text, .. } if text == confluence::TEXT_PAGE_TOO_LARGE
    ));
    Ok(())
}

// ---- the conflict card (pure) -------------------------------------------------------------------

/// I-36 / M6 T10 review M-5: the card shows the rendered diff base → current and the agent's
/// intended change base → outgoing, both computed from the stage answers and the request that
/// is sent; the requests are there (T8 review I-1).
#[test]
fn conflict_card_diffs_and_requests() -> TestResult {
    let (base, current) = (
        "<h1>Plan</h1><p>old line</p>",
        "<h1>Plan</h1><p>current line</p>",
    );
    let p = params(5, "# Plan\n\nnew line", None);
    let (v, m) = preview(&p, &[page(6, current), historical(5, base)])?;
    assert_eq!(v.hold, Hold::Conflict);
    let reqs = requests(&p, &v)?;
    assert_eq!(
        reqs.len(),
        1,
        "the executor renders under the conflict hold"
    );
    let outgoing = sent_storage(&reqs[0])?;
    let PreviewBody::Conflict {
        summary,
        diff_text,
        base_to_current,
        intended,
        requests: views,
    } = &m.body
    else {
        return Err(format!("not the conflict card: {:?}", m.body).into());
    };
    assert_eq!(summary, &warning::conflict(5, 6));
    assert_eq!(diff_text, "base version v5, current version v6");
    assert_eq!(base_to_current, &rendered_diff(base, current)?);
    assert_eq!(intended, &rendered_diff(base, &outgoing)?);
    assert!(
        base_to_current
            .iter()
            .any(|l| l.op == DiffOp::Add && l.text.contains("current line"))
    );
    assert!(
        intended
            .iter()
            .any(|l| l.op == DiffOp::Add && l.text.contains("new line"))
    );
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].method, "PUT");
    assert_eq!(
        warning_text(&m, WarningId::Conflict).as_deref(),
        Some(warning::conflict(5, 6).as_str())
    );
    // A rebuild from the same state gives the same card.
    assert_eq!(preview_of(&p, &v, &reqs, None)?, m);
    Ok(())
}

/// The intended change is the request's, not the params' (§5.1 inv. 4: the approver sees what
/// is sent).
#[test]
fn conflict_intended_change_reads_the_sent_body() -> TestResult {
    let p = params(5, "<p>from params</p>", Some("storage"));
    let (v, _) = preview(&p, &[page(6, "<p>c</p>"), historical(5, "<p>b</p>")])?;
    let mut reqs = requests(&p, &v)?;
    let mut body: Value = serde_json::from_slice(&reqs[0].body)?;
    body["body"]["storage"]["value"] = json!("<p>on the wire</p>");
    reqs[0].body = serde_json::to_vec(&body)?;
    let m = preview_of(&p, &v, &reqs, None)?;
    let PreviewBody::Conflict { intended, .. } = &m.body else {
        return Err("not the conflict card".into());
    };
    let text: String = intended.iter().map(|l| l.text.as_str()).collect();
    assert!(
        text.contains("on the wire") && !text.contains("from params"),
        "{text}"
    );
    Ok(())
}

/// §6.4 / T12b: what the card's Markdown projections leave out of the base and current server
/// bodies (comments, attributes the converter does not write) counts as hidden with the Info
/// `source_formatting_removed`; their invisible characters count into the header.
#[test]
fn conflict_card_counts_what_it_hides_of_the_server_bodies() -> TestResult {
    let base = "<p>a<!-- secret note --></p>";
    let current = "<p title=\"hover text\">a\u{202E}b</p>";
    let p = params(5, "<p>a</p>", Some("storage"));
    let (_, m) = preview(&p, &[page(6, current), historical(5, base)])?;
    assert!(matches!(m.body, PreviewBody::Conflict { .. }));
    let hidden = m.header.hidden_in_preview_bytes;
    let expected = "<!-- secret note -->".len() + "title=\"hover text\"".len();
    assert!(hidden >= expected as u64, "{hidden} < {expected}");
    assert!(ids(&m).contains(&WarningId::SourceFormattingRemoved));
    assert!(m.header.bidi_controls >= 1);
    assert!(ids(&m).contains(&WarningId::BidiControls));
    Ok(())
}

/// T20a review I-1: the edit and conflict cards add their counts to what the request views
/// already hide (a body shown as its digest: here a second request, no UTF-8, above 1 MiB),
/// never overwrite it.
#[test]
fn update_cards_add_to_what_the_request_views_hide() -> TestResult {
    let extra = 1024 * 1024 + 1;
    let binary = HttpRequestSpec {
        index: 1,
        method: "POST".to_owned(),
        resolved_url: "https://wiki.example.invalid/wiki/rest/api/content".to_owned(),
        content_type: Some("application/octet-stream".to_owned()),
        body: vec![0xff; extra],
    };
    let edit = params(7, "<p>a</p><p>b</p>", Some("storage"));
    let conflict = params(5, "<p>a</p>", Some("storage"));
    for (p, answers) in [
        (edit, vec![page(7, "<p>a<!-- note --></p>")]),
        (
            conflict,
            vec![
                page(6, "<p title=\"hover\">a</p>"),
                historical(5, "<p>a<!-- note --></p>"),
            ],
        ),
    ] {
        let (v, plain) = preview(&p, &answers)?;
        let mut reqs = requests(&p, &v)?;
        reqs.push(binary.clone());
        let m = preview_of(&p, &v, &reqs, None)?;
        assert_eq!(
            std::mem::discriminant(&m.body),
            std::mem::discriminant(&plain.body),
            "the same card"
        );
        assert!(matches!(
            m.body,
            PreviewBody::EditDiff { .. } | PreviewBody::Conflict { .. }
        ));
        assert_eq!(
            m.header.hidden_in_preview_bytes,
            plain.header.hidden_in_preview_bytes + extra as u64
        );
    }
    Ok(())
}

// ---- the edit preview (pure) --------------------------------------------------------------------

/// PD-104: the rendered diff over the Markdown projections of the current and the sent storage,
/// the raw diff over their `storage_lines`, both from the request that is sent.
#[test]
fn page_update_rendered_and_raw_diffs() -> TestResult {
    let current = "<h1>Plan</h1><p>one</p><p>two</p>";
    let p = params(7, "<h1>Plan</h1><p>one</p><p>2</p>", Some("storage"));
    let (v, m) = preview(&p, &[page(7, current)])?;
    assert_eq!(v.hold, Hold::Preview);
    let outgoing = sent_storage(&requests(&p, &v)?[0])?;
    let PreviewBody::EditDiff {
        rendered,
        raw,
        raw_only_changes,
        constructs,
        requests: views,
    } = &m.body
    else {
        return Err(format!("not the edit diff: {:?}", m.body).into());
    };
    assert_eq!(rendered, &rendered_diff(current, &outgoing)?);
    assert_eq!(raw, &raw_diff(current, &outgoing));
    assert!(
        raw.iter()
            .any(|l| l.op == DiffOp::Del && l.text == "<p>two</p>")
    );
    assert_eq!(*raw_only_changes, 0);
    assert!(constructs.is_some());
    assert_eq!(views.len(), 1);
    assert!(!ids(&m).contains(&WarningId::RawOnlyDiff));
    Ok(())
}

/// The edit diff reads the request, not the params (§5.1 inv. 4).
#[test]
fn edit_diff_reads_the_sent_body() -> TestResult {
    let p = params(7, "<p>from params</p>", Some("storage"));
    let (v, _) = preview(&p, &[page(7, "<p>a</p>")])?;
    let mut reqs = requests(&p, &v)?;
    let mut body: Value = serde_json::from_slice(&reqs[0].body)?;
    body["body"]["storage"]["value"] = json!("<p>on the wire</p>");
    reqs[0].body = serde_json::to_vec(&body)?;
    let m = preview_of(&p, &v, &reqs, None)?;
    let PreviewBody::EditDiff { raw, .. } = &m.body else {
        return Err("not the edit diff".into());
    };
    assert!(
        raw.iter()
            .any(|l| l.op == DiffOp::Add && l.text == "<p>on the wire</p>")
    );
    assert!(!raw.iter().any(|l| l.text.contains("from params")));
    Ok(())
}

/// T15 review m-6: the lossy Caution and the construct list follow the storage that is sent too:
/// a request whose body keeps the macro the params' Markdown would drop has no Caution, and its
/// construct list names the macro.
#[test]
fn lossy_and_constructs_read_the_sent_body() -> TestResult {
    let current = "<ac:structured-macro ac:name=\"toc\"/><p>a</p>";
    let p = params(7, "a", None);
    let (v, m) = preview(&p, &[page(7, current)])?;
    assert_eq!(
        warning_text(&m, WarningId::LossyUpdate).as_deref(),
        Some("this update will remove 1 macros / 0 images / 0 links")
    );
    let PreviewBody::EditDiff { constructs, .. } = &m.body else {
        return Err("not the edit diff".into());
    };
    assert!(constructs.as_ref().ok_or("no list")?.macros.is_empty());

    let reqs = swapped(requests(&p, &v)?, |b| {
        b["body"]["storage"]["value"] = json!("<ac:structured-macro ac:name=\"toc\"/><p>b</p>");
    })?;
    let m = preview_of(&p, &v, &reqs, None)?;
    assert!(!ids(&m).contains(&WarningId::LossyUpdate), "{:?}", ids(&m));
    let PreviewBody::EditDiff { constructs, .. } = &m.body else {
        return Err("not the edit diff".into());
    };
    let macros = &constructs.as_ref().ok_or("no list")?.macros;
    assert!(macros.iter().any(|s| s.contains("toc")), "{macros:?}");
    Ok(())
}

/// T15 review m-5: a title the request changes heads the diffs with a `title` section (the
/// current title deleted, the sent one added), then the body's section; the title is read from
/// the request (§5.1 inv. 4). An unchanged title adds nothing.
#[test]
fn title_change_heads_the_diff() -> TestResult {
    let current = "<p>one</p><p>two</p>";
    let mut p = params(7, "<p>one</p><p>2</p>", Some("storage"));
    p["title"] = json!("Renamed");
    let (v, m) = preview(&p, &[page(7, current)])?;
    let outgoing = sent_storage(&requests(&p, &v)?[0])?;
    let head = |new: &str| {
        vec![
            DiffLine {
                op: DiffOp::Field,
                text: "title".to_owned(),
            },
            DiffLine {
                op: DiffOp::Del,
                text: "Release checklist".to_owned(),
            },
            DiffLine {
                op: DiffOp::Add,
                text: new.to_owned(),
            },
            DiffLine {
                op: DiffOp::Field,
                text: "body".to_owned(),
            },
        ]
    };
    let PreviewBody::EditDiff {
        rendered,
        raw,
        raw_only_changes,
        ..
    } = &m.body
    else {
        return Err(format!("not the edit diff: {:?}", m.body).into());
    };
    let mut want = head("Renamed");
    want.extend(rendered_diff(current, &outgoing)?);
    assert_eq!(rendered, &want);
    let mut want = head("Renamed");
    want.extend(raw_diff(current, &outgoing));
    assert_eq!(raw, &want);
    assert_eq!(*raw_only_changes, 0);

    // What is sent, not the params.
    let reqs = swapped(requests(&p, &v)?, |b| b["title"] = json!("On the wire"))?;
    let m = preview_of(&p, &v, &reqs, None)?;
    let PreviewBody::EditDiff { rendered, .. } = &m.body else {
        return Err("not the edit diff".into());
    };
    assert_eq!(rendered.get(..4), Some(head("On the wire").as_slice()));

    // The current title given again: no section.
    p["title"] = json!("Release checklist");
    let (_, m) = preview(&p, &[page(7, current)])?;
    let PreviewBody::EditDiff { rendered, .. } = &m.body else {
        return Err("not the edit diff".into());
    };
    assert_eq!(rendered, &rendered_diff(current, &outgoing)?);

    // The current title is server text the card shows: its invisible characters count.
    let mut tricky = page(7, current);
    tricky["title"] = json!("Release\u{202E}checklist");
    p["title"] = json!("Renamed");
    let (_, m) = preview(&p, &[tricky])?;
    assert!(m.header.bidi_controls >= 1);
    let PreviewBody::EditDiff { rendered, .. } = &m.body else {
        return Err("not the edit diff".into());
    };
    assert_eq!(
        rendered.get(1).map(|l| l.text.clone()),
        Some(escape_for_display("Release\u{202E}checklist"))
    );
    Ok(())
}

/// T15 review m-1: a side whose Markdown projection is past the budget is not projected: no
/// rendered lines, both texts counted as cut (`diff_truncated`, the header count), the raw diff
/// still there and every raw hunk raw-only (`raw_only_diff`; truthful, nothing is rendered);
/// the lossy count does not depend on the projection.
#[test]
fn update_card_past_the_projection_budget() -> TestResult {
    let current = "<p>a</p><ac:structured-macro ac:name=\"toc\"/>";
    let p = params(7, "b", None);
    let (v, full) = preview(&p, &[page(7, current)])?;
    let reqs = requests(&p, &v)?;
    let outgoing = sent_storage(&reqs[0])?;
    let m = preview_within(&p, &v, &reqs, 1)?;
    let PreviewBody::EditDiff {
        rendered,
        raw,
        raw_only_changes,
        ..
    } = &m.body
    else {
        return Err(format!("not the edit diff: {:?}", m.body).into());
    };
    assert!(rendered.is_empty(), "{rendered:?}");
    assert_eq!(raw, &raw_diff(current, &outgoing));
    let raw_hunks = atlas_duck_preview::diff::hunks(raw);
    assert!(raw_hunks > 0);
    assert_eq!(*raw_only_changes, raw_hunks);
    let cut = (current.len() + outgoing.len()) as u64;
    assert_eq!(m.header.hidden_in_preview_bytes, cut);
    assert_eq!(
        warning_text(&m, WarningId::DiffTruncated).as_deref(),
        Some(warning::diff_truncated(cut).as_str())
    );
    assert_eq!(
        warning_text(&m, WarningId::RawOnlyDiff).as_deref(),
        Some(warning::raw_only_diff(raw_hunks).as_str())
    );
    assert_eq!(
        warning_text(&m, WarningId::LossyUpdate),
        warning_text(&full, WarningId::LossyUpdate)
    );
    assert!(warning_text(&m, WarningId::LossyUpdate).is_some());
    // The full budget projects both sides.
    let PreviewBody::EditDiff { rendered, .. } = &full.body else {
        return Err("not the edit diff".into());
    };
    assert!(!rendered.is_empty());
    assert!(!ids(&full).contains(&WarningId::DiffTruncated));
    Ok(())
}

/// S-12 (diff half): a storage update that changes only an attribute's quoting renders the same
/// and differs raw: `raw_only_changes` counts it and the Caution `raw_only_diff` is shown.
#[test]
fn s12_confluence_raw_only_diff_flagged() -> TestResult {
    let current = "<p class=\"x\">same</p>";
    let p = params(7, "<p class='x'>same</p>", Some("storage"));
    let (_, m) = preview(&p, &[page(7, current)])?;
    let PreviewBody::EditDiff {
        rendered,
        raw,
        raw_only_changes,
        ..
    } = &m.body
    else {
        return Err("not the edit diff".into());
    };
    assert!(
        rendered.iter().all(|l| l.op == DiffOp::Same),
        "{rendered:?}"
    );
    assert!(raw.iter().any(|l| l.op != DiffOp::Same));
    assert_eq!(*raw_only_changes, 1);
    assert_eq!(
        warning_text(&m, WarningId::RawOnlyDiff).as_deref(),
        Some(warning::raw_only_diff(1).as_str())
    );
    Ok(())
}

/// §7.6 (T9 review I-2, ruling a): the card lists every macro, mention, include and link of the
/// outgoing storage, also past the diff caps (`diff_truncated`).
#[test]
fn update_lists_outgoing_constructs_past_the_diff_cap() -> TestResult {
    let filler = "<p>l</p>".repeat(25_000);
    let body = format!(
        "{filler}<ac:structured-macro ac:name=\"include\"><ac:parameter ac:name=\"\">\
         <ac:link><ri:page ri:content-title=\"Secret\"/></ac:link></ac:parameter>\
         </ac:structured-macro><p><ac:link><ri:user ri:userkey=\"k1\"/></ac:link></p>"
    );
    let p = params(7, &body, Some("storage"));
    let (_, m) = preview(&p, &[page(7, "<p>x</p>")])?;
    let PreviewBody::EditDiff { constructs, .. } = &m.body else {
        return Err("not the edit diff".into());
    };
    let c = constructs.as_ref().ok_or("no construct list")?;
    assert!(!c.includes.is_empty(), "{c:?}");
    assert!(!c.mentions.is_empty(), "{c:?}");
    assert!(ids(&m).contains(&WarningId::DiffTruncated));
    Ok(())
}

/// PD-104 lossy check (lead ruling Q10, plan review I-11): outermost constructs only, layouts
/// appended when lost, a page link counted once; Approve stays enabled.
#[test]
fn lossy_update_caution_counts() -> TestResult {
    let current = "<p>a</p><ac:structured-macro ac:name=\"toc\"/>\
                   <ac:structured-macro ac:name=\"info\"><ac:rich-text-body><p>i</p>\
                   </ac:rich-text-body></ac:structured-macro>\
                   <ac:image><ri:attachment ri:filename=\"x.png\"/></ac:image>";
    let p = params(7, "a", None);
    let (v, m) = preview(&p, &[page(7, current)])?;
    assert_eq!(v.hold, Hold::Preview);
    assert_eq!(
        warning_text(&m, WarningId::LossyUpdate).as_deref(),
        Some("this update will remove 2 macros / 1 images / 0 links")
    );
    assert!(
        !requests(&p, &v)?.is_empty(),
        "approvable: the request is built"
    );

    let layout = "<ac:layout><ac:layout-section ac:type=\"single\"><ac:layout-cell><p>L</p>\
                  </ac:layout-cell></ac:layout-section></ac:layout>";
    let (_, m) = preview(&p, &[page(7, layout)])?;
    assert_eq!(
        warning_text(&m, WarningId::LossyUpdate).as_deref(),
        Some("this update will remove 0 macros / 0 images / 0 links, 1 layouts")
    );

    let link = "<p><ac:link><ri:page ri:content-title=\"Other\"/></ac:link></p>";
    let (_, m) = preview(&p, &[page(7, link)])?;
    assert_eq!(
        warning_text(&m, WarningId::LossyUpdate).as_deref(),
        Some("this update will remove 0 macros / 0 images / 1 links")
    );

    // Nothing lost: no Caution.
    let (_, m) = preview(&p, &[page(7, "<p>b</p>")])?;
    assert!(!ids(&m).contains(&WarningId::LossyUpdate));
    Ok(())
}

/// PD-104: only a Markdown update is counted; a storage update sends what the agent wrote.
#[test]
fn storage_update_has_no_lossy_check() -> TestResult {
    let current = "<ac:structured-macro ac:name=\"toc\"/><p>a</p>";
    let p = params(7, "<p>a</p>", Some("storage"));
    let (_, m) = preview(&p, &[page(7, current)])?;
    assert!(!ids(&m).contains(&WarningId::LossyUpdate), "{:?}", ids(&m));
    Ok(())
}

/// PD-94 / plan review I-3 c: a Markdown update over a current body that does not parse is held
/// ("enrichment failed", the plan text); a storage update needs no count and is not held.
#[test]
fn unparsable_current_holds_only_a_markdown_update() -> TestResult {
    let broken = "<p>a<b>c</p>";
    let p = params(7, "new text", None);
    let (v, m) = preview(&p, &[page(7, broken)])?;
    assert_eq!(v.hold, Hold::EnrichmentError);
    match &m.body {
        PreviewBody::EnrichmentError { text, status, .. } => {
            assert_eq!(text, UNPARSABLE);
            assert_eq!(*status, None);
        }
        other => return Err(format!("not the enrichment card: {other:?}").into()),
    }
    let p = params(7, "<p>new</p>", Some("storage"));
    let (v, _) = preview(&p, &[page(7, broken)])?;
    assert_eq!(v.hold, Hold::Preview);
    Ok(())
}

/// The current title is sent unless the agent gives one; `version.number` is `base + 1`.
#[test]
fn title_kept_unless_given() -> TestResult {
    let p = params(7, "<p>x</p>", Some("storage"));
    let (_, v) = staged(&p, &[page(7, "<p>a</p>")])?;
    let body: Value = serde_json::from_slice(&requests(&p, &v)?[0].body)?;
    assert_eq!(body["title"], "Release checklist");
    assert_eq!(body["version"]["number"], 8);
    let mut titled = p.clone();
    titled["title"] = json!("Renamed");
    let body: Value = serde_json::from_slice(&requests(&titled, &v)?[0].body)?;
    assert_eq!(body["title"], "Renamed");
    Ok(())
}

// ---- end to end ----------------------------------------------------------------------------------

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no confluence mock".into())
}

fn json_answer(mock: &MockDc, status: u16, body: &Value) -> ResponseTemplate {
    mock.response(status)
        .set_body_raw(body.to_string(), "application/json")
}

/// The stale check's `GET ?expand=version` answers the page at `version`.
async fn mount_stale_check(mock: &MockDc, id: &str, version: u64) {
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(id))))
        .and(query_param("expand", "version"))
        .respond_with(json_answer(mock, 200, &page(version, "<p>x</p>")))
        .mount(mock.server())
        .await;
}

/// `PUT /rest/api/content/{id}` answers `status` with `body`.
async fn mount_put(mock: &MockDc, id: &str, status: u16, body: &str) {
    Mock::given(method("PUT"))
        .and(path(mock.path(&content_path(id))))
        .respond_with(
            mock.response(status)
                .set_body_raw(body.to_owned(), "application/json"),
        )
        .mount(mock.server())
        .await;
}

async fn records(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

async fn queued(h: &Harness, params: Value) -> Result<String, TestError> {
    let env = h.submit(UPDATE, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

fn not_approvable(res: Result<atlas_duck_core::DecisionOutcome, DecisionError>) -> TestResult {
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    Ok(())
}

async fn puts(mock: &MockDc) -> Vec<wiremock::Request> {
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "PUT")
        .collect()
}

async fn rev_after(
    h: &Harness,
    id: &str,
    counter: u64,
) -> Result<atlas_duck_core::QueueItem, TestError> {
    for _ in 0..800 {
        if let Some(i) = h.approver().item(id)
            && i.candidate_rev.counter > counter
        {
            return Ok(i);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("no new revision".into())
}

/// I-36: base v5 against the page at v6 is the conflict hold: the exact §6.2 Caution, Approve
/// disabled in Rust, two enrichment GETs (the second for the agent's base body, §5.4 step 2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i36_page_update_base_behind_is_conflict_not_approvable() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page(6, "<p>current</p>")).await;
    mount_history_version(mock, ID, 5, &historical(5, "<p>base</p>")).await;
    let id = queued(&h, params(5, "<p>x</p>", Some("storage"))).await?;
    let item = h.approver().item(&id).ok_or("not queued")?;
    assert!(!item.approvable);
    let p = h.approver().open(&id).map_err(de)?.preview;
    assert!(!p.approvable);
    assert!(matches!(p.body, PreviewBody::Conflict { .. }));
    let caution = p
        .warnings
        .iter()
        .find(|w| w.id == WarningId::Conflict)
        .ok_or("no conflict Caution")?;
    assert_eq!(
        caution.text,
        "conflict: page changed since the agent read it (v5 → v6)"
    );
    not_approvable(h.approver().approve(&id))?;
    assert_eq!(
        records(&h, &id, EventType::DECISION_INVALID)
            .await?
            .first()
            .map(|r| r["reason"].clone()),
        Some(json!("not_approvable"))
    );
    assert!(
        records(&h, &id, EventType::WRITE_APPROVED)
            .await?
            .is_empty()
    );
    let fetches = records(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(fetches.len(), 2, "{fetches:?}");
    assert!(fetches.iter().all(|f| f["purpose"] == "enrich"));
    let second = fetches[1]["path"].as_str().unwrap_or_default();
    assert!(
        second.ends_with("/rest/api/content/65537?version=5&status=historical&expand=body.storage"),
        "{second}"
    );
    assert!(puts(mock).await.is_empty());
    Ok(())
}

/// I-36 / M6 T10 review M-5: the conflict card carries the rendered base → current diff, the
/// agent's intended change and the `PUT` (T8 review I-1); opening again shows the same card.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i36_page_update_conflict_shows_base_to_current_diff() -> TestResult {
    let (base, current) = ("<p>Ship on Monday.</p>", "<p>Ship on Friday.</p>");
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page(6, current)).await;
    mount_history_version(mock, ID, 5, &historical(5, base)).await;
    let md_body = "Ship on Tuesday.";
    let id = queued(&h, params(5, md_body, None)).await?;
    let p = h.approver().open(&id).map_err(de)?.preview;
    let outgoing = markdown_to_storage(md_body).0;
    match &p.body {
        PreviewBody::Conflict {
            diff_text,
            base_to_current,
            intended,
            requests,
            ..
        } => {
            assert_eq!(diff_text, "base version v5, current version v6");
            assert_eq!(base_to_current, &rendered_diff(base, current)?);
            assert_eq!(intended, &rendered_diff(base, &outgoing)?);
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].method, "PUT");
            let body = match &requests[0].body {
                atlas_duck_preview::BodyView::Text(t) => serde_json::from_str::<Value>(t)?,
                other => return Err(format!("body {other:?}").into()),
            };
            assert_eq!(body["version"]["number"], 6);
            assert_eq!(body["body"]["storage"]["value"], outgoing.as_str());
        }
        other => return Err(format!("not the conflict card: {other:?}").into()),
    }
    let again = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(again.body, p.body);
    assert_eq!(again.candidate_rev, p.candidate_rev);
    Ok(())
}

/// Plan review m-8: a base ahead of the current version asks for a version that does not exist;
/// the JSON 404 is "enrichment failed", Approve disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn base_version_ahead_of_current() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page(7, "<p>a</p>")).await;
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(ID))))
        .and(query_param("version", "9"))
        .respond_with(json_answer(
            mock,
            404,
            &json!({"statusCode": 404, "message": "No content found with id: ContentId{id=65537}"}),
        ))
        .with_priority(1)
        .mount(mock.server())
        .await;
    let id = queued(&h, params(9, "<p>x</p>", Some("storage"))).await?;
    let p = h.approver().open(&id).map_err(de)?.preview;
    match &p.body {
        PreviewBody::EnrichmentError { status, .. } => assert_eq!(*status, Some(404)),
        other => return Err(format!("not enrichment failed: {other:?}").into()),
    }
    not_approvable(h.approver().approve(&id))?;
    assert!(puts(mock).await.is_empty());
    Ok(())
}

/// Plan review I-3 c: the unparsable current body holds a Markdown update; the same page with a
/// storage update is approvable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn current_storage_unparsable_holds_markdown_update() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page(7, "<p>a<b>c</p>")).await;
    let id = queued(&h, params(7, "new text", None)).await?;
    let p = h.approver().open(&id).map_err(de)?.preview;
    match &p.body {
        PreviewBody::EnrichmentError { text, .. } => assert_eq!(text, UNPARSABLE),
        other => return Err(format!("not the hold: {other:?}").into()),
    }
    not_approvable(h.approver().approve(&id))?;
    assert!(
        records(&h, &id, EventType::WRITE_APPROVED)
            .await?
            .is_empty()
    );

    let id = queued(&h, params(7, "<p>new</p>", Some("storage"))).await?;
    assert!(h.approver().item(&id).ok_or("not queued")?.approvable);
    Ok(())
}

/// Plan review I-6 b: `body_format` re-runs enrichment, so an edit from `storage` to `markdown`
/// brings the lossy Caution.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn body_format_edit_reruns_lossy_check() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(
        mock,
        ID,
        &page(7, "<ac:structured-macro ac:name=\"toc\"/><p>a</p>"),
    )
    .await;
    let id = queued(&h, params(7, "<p>a</p>", Some("storage"))).await?;
    let before = h.approver().open(&id).map_err(de)?.preview;
    assert!(
        !before
            .warnings
            .iter()
            .any(|w| w.id == WarningId::LossyUpdate)
    );
    let enrich_before = records(&h, &id, EventType::PREVIEW_FETCH).await?.len();
    let mut set = Map::new();
    set.insert("body_format".into(), json!("markdown"));
    h.approver()
        .edit(
            &id,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
        .map_err(de)?;
    // The re-enrichment ends with a decidable revision that carries the Caution.
    let mut lossy = None;
    for _ in 0..800 {
        if let Some(item) = h.approver().item(&id)
            && item.candidate_rev.counter > before.candidate_rev.counter
            && item.approvable
        {
            let after = h.approver().open(&id).map_err(de)?.preview;
            lossy = after
                .warnings
                .iter()
                .find(|w| w.id == WarningId::LossyUpdate)
                .map(|w| w.text.clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        lossy.as_deref(),
        Some("this update will remove 1 macros / 0 images / 0 links")
    );
    assert!(records(&h, &id, EventType::PREVIEW_FETCH).await?.len() > enrich_before);
    Ok(())
}

/// I-36: `base_version` is required (static validation, exit 2, nothing queued).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i36_page_update_without_base_version_exit2() -> TestResult {
    let h = Harness::confluence().await?;
    let env = h
        .submit(
            UPDATE,
            json!({ "id": ID, "body": "<p>x</p>", "body_format": "storage" }),
        )
        .await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(exit(&env), 2);
    assert_eq!(code(&env), "validation");
    let id = request_id(&env)?;
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
    );
    assert!(h.approver().item(&id).is_none(), "nothing queued");
    Ok(())
}

/// I-36 / §5.4 step 6: approved at v5, the PUT answers 409; the refresh sees v6 and the base
/// body: back in the queue in the conflict state, the card carries the `PUT`, not re-approvable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i36_page_update_409_returns_conflict_not_reapprovable() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    // The enrichment sees v5 once, the refresh after the conflict sees v6.
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(ID))))
        .and(query_param(
            "expand",
            common::confluence::PAGE_EXPAND_STORAGE,
        ))
        .respond_with(json_answer(mock, 200, &page(5, "<p>base</p>")))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(ID))))
        .and(query_param(
            "expand",
            common::confluence::PAGE_EXPAND_STORAGE,
        ))
        .respond_with(json_answer(mock, 200, &page(6, "<p>theirs</p>")))
        .with_priority(2)
        .mount(mock.server())
        .await;
    mount_history_version(mock, ID, 5, &historical(5, "<p>base</p>")).await;
    mount_stale_check(mock, ID, 5).await;
    mount_put(mock, ID, 409, fixtures::CONFLUENCE_VERSION_CONFLICT_409).await;
    let id = queued(&h, params(5, "<p>mine</p>", Some("storage"))).await?;
    let rev1 = h.approver().rev(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    let item = rev_after(&h, &id, rev1.counter + 1).await?;
    assert!(!item.approvable && item.stale);
    let stale = records(&h, &id, EventType::WRITE_STALE).await?;
    assert_eq!(
        stale.first().map(|s| s["reason"].clone()),
        Some(json!("version_conflict"))
    );
    let refresh: Vec<Value> = records(&h, &id, EventType::PREVIEW_FETCH)
        .await?
        .into_iter()
        .filter(|r| r["purpose"] == "refresh")
        .collect();
    assert_eq!(refresh.len(), 2, "the current page and the base body");
    let p = h.approver().open(&id).map_err(de)?.preview;
    match &p.body {
        PreviewBody::Conflict {
            summary,
            base_to_current,
            requests,
            ..
        } => {
            assert_eq!(summary, &warning::conflict(5, 6));
            assert_eq!(
                base_to_current,
                &rendered_diff("<p>base</p>", "<p>theirs</p>")?
            );
            assert_eq!(requests.len(), 1);
        }
        other => return Err(format!("not the conflict card: {other:?}").into()),
    }
    not_approvable(h.approver().approve(&id))?;
    assert_eq!(records(&h, &id, EventType::WRITE_APPROVED).await?.len(), 1);
    assert_eq!(puts(mock).await.len(), 1, "the one PUT that answered 409");
    Ok(())
}

/// I-36: a Markdown body is sent converted, with `version.number = base_version + 1`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i36_sent_version_is_base_plus_one() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page(5, "<p>old</p>")).await;
    mount_stale_check(mock, ID, 5).await;
    mount_put(mock, ID, 200, fixtures::CONFLUENCE_PAGE_UPDATED).await;
    let md_body = "## New\n\nText with *emphasis*.";
    let id = queued(&h, params(5, md_body, None)).await?;
    h.approver().open(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let sent = puts(mock).await;
    assert_eq!(sent.len(), 1);
    let body: Value = serde_json::from_slice(&sent[0].body)?;
    assert_eq!(body["version"]["number"], 6);
    assert_eq!(
        body["body"]["storage"]["value"],
        markdown_to_storage(md_body).0.as_str()
    );
    assert_eq!(body["body"]["storage"]["representation"], "storage");
    Ok(())
}

/// I-06 (conflict): the conflict item in a batch with a clean, opened update of another page
/// rejects the whole batch; nothing is decided or sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_page_update_conflict_batch_rejected() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page(6, "<p>c</p>")).await;
    mount_history_version(mock, ID, 5, &historical(5, "<p>b</p>")).await;
    let mut other = page(7, "<p>o</p>");
    other["id"] = json!("65538");
    other["title"] = json!("Other page");
    mount_page(mock, "65538", &other).await;
    let conflict = queued(&h, params(5, "<p>x</p>", Some("storage"))).await?;
    let mut clean_params = params(7, "<p>y</p>", Some("storage"));
    clean_params["id"] = json!("65538");
    let clean = queued(&h, clean_params).await?;
    h.approver().open(&conflict).map_err(de)?;
    h.approver().open(&clean).map_err(de)?;
    assert!(h.approver().item(&clean).ok_or("gone")?.approvable);
    let batch = [&clean, &conflict]
        .iter()
        .map(|r| {
            Ok(BatchItem {
                request_id: (*r).clone(),
                candidate_rev: h.approver().rev(r).map_err(de)?,
            })
        })
        .collect::<Result<Vec<_>, TestError>>()?;
    match h.decisions().decide_batch(batch) {
        Err(DecisionError::BatchRejected { failed }) => assert_eq!(
            failed,
            [(
                conflict.clone(),
                BatchFailure::Invalid(InvalidReason::NotApprovable)
            )]
        ),
        other => return Err(format!("expected BatchRejected, got {other:?}").into()),
    }
    for r in [&clean, &conflict] {
        assert!(records(&h, r, EventType::WRITE_APPROVED).await?.is_empty());
    }
    assert!(puts(mock).await.is_empty());
    Ok(())
}

/// §5.4 step 4 / L06: `id` (the target) and `base_version` (the conflict baseline) are shown
/// read-only, and an edit of `base_version` is refused (`target_param_edit`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edit_form_base_version_read_only() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page(7, "<p>a</p>")).await;
    let id = queued(&h, params(7, "<p>x</p>", Some("storage"))).await?;
    let p = h.approver().open(&id).map_err(de)?.preview;
    let form = p.edit_form.as_ref().ok_or("no edit form")?;
    for name in ["id", "base_version"] {
        let input = form
            .inputs
            .iter()
            .find(|i| i.path == name)
            .ok_or_else(|| format!("no {name} input"))?;
        assert!(input.read_only, "{name}");
    }
    let mut set = Map::new();
    set.insert("base_version".into(), json!(8));
    let res = h.approver().edit(
        &id,
        Edits {
            set,
            remove: Vec::new(),
        },
    );
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::TargetParamEdit))
        ),
        "{res:?}"
    );
    assert!(records(&h, &id, EventType::WRITE_EDITED).await?.is_empty());
    Ok(())
}

/// RF-2 / L31: stage 2 answered by a redirect is decided on its status and headers: a direct
/// `REQUEST_FAILED {upstream_unavailable}`, exit 6, nothing queued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stage2_historical_3xx_direct() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page(6, "<p>c</p>")).await;
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(ID))))
        .and(query_param("status", "historical"))
        .respond_with(
            mock.response(302)
                .insert_header("Location", "https://sso.corp.example/login"),
        )
        .with_priority(1)
        .mount(mock.server())
        .await;
    let env = h
        .submit(UPDATE, params(5, "<p>x</p>", Some("storage")))
        .await;
    let id = request_id(&env)?;
    assert!(h.settled(&id, 10_000).await, "never settled");
    let env = h.await_(&id, 1000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(exit(&env), 6);
    assert_eq!(code(&env), "upstream_unavailable");
    assert_eq!(records(&h, &id, EventType::REQUEST_FAILED).await?.len(), 1);
    assert_eq!(records(&h, &id, EventType::PREVIEW_FETCH).await?.len(), 2);
    assert!(puts(mock).await.is_empty());
    Ok(())
}

/// T13 identity rule for the base GETs: both stages run in the one enrichment, so another user's
/// PAT stored between them (here: after stage 1 answered, before stage 2 starts; T15 review m-2:
/// held there by `pause_after_get`, no timing) does not let the answers of two identities make
/// one verdict: the verdict that met the change is followed by `WRITE_STALE {credential_changed}`
/// and both stages again under the new PAT, before it can be approved (the M3 rule,
/// `route_change`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_replaced_between_the_stages_refreshes() -> TestResult {
    let pause = Pause::new();
    let h = Harness::builder()
        .confluence("wiki")
        .confirm(vec![Confirm::Ok])
        .hooks(TestHooks {
            pause_after_get: Some(pause.clone()),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let mock = wiki(&h)?;
    mock.applinks_manifest("9.2.1").await;
    mount_page(mock, ID, &page(6, "<p>c</p>")).await;
    mount_history_version(mock, ID, 5, &historical(5, "<p>b</p>")).await;
    let env = h
        .submit(UPDATE, params(5, "<p>x</p>", Some("storage")))
        .await;
    let id = request_id(&env)?;
    // Stage 1 answered and its record is parked; stage 2 has not started.
    tokio::time::timeout(Duration::from_secs(10), pause.reached.notified())
        .await
        .map_err(|_| "stage 1 never held")?;
    assert_eq!(records(&h, &id, EventType::PREVIEW_FETCH).await?.len(), 0);
    let historical = mock
        .received()
        .await
        .iter()
        .filter(|r| {
            r.url
                .query()
                .is_some_and(|q| q.contains("status=historical"))
        })
        .count();
    assert_eq!(historical, 0, "stage 2 has not started");
    // Another user's PAT (`TokenReplaced`; the same user's is `TokenStored`, which changes no
    // identity and so nothing to re-read).
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/user/current")))
        .respond_with(mock.response(200).set_body_raw(
            fixtures::confluence_user_current("bob", "8a7f808a2"),
            "application/json",
        ))
        .with_priority(1)
        .mount(mock.server())
        .await;
    h.instances()
        .set_token("wiki", SecretString::from("bobs-pat".to_owned()), None)
        .await?;
    // Every later GET (stage 2, then both stages of the refresh) goes on when it holds.
    let releaser = {
        let pause = pause.clone();
        tokio::spawn(async move {
            loop {
                pause.release.notify_one();
                pause.reached.notified().await;
            }
        })
    };
    // The verdict that met the change is followed by `WRITE_STALE {credential_changed}` and a
    // refresh (both stages again, under the new PAT).
    let mut stale = Vec::new();
    for _ in 0..400 {
        stale = records(&h, &id, EventType::WRITE_STALE).await?;
        if !stale.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        stale.first().map(|s| s["reason"].clone()),
        Some(json!("credential_changed")),
        "{:?}",
        h.events(&id).await?
    );
    let mut refreshed = 0;
    for _ in 0..400 {
        refreshed = records(&h, &id, EventType::PREVIEW_FETCH)
            .await?
            .iter()
            .filter(|r| r["purpose"] == "refresh")
            .count();
        if refreshed >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(refreshed, 2, "both stages again");
    assert!(!h.approver().item(&id).ok_or("gone")?.approvable);
    assert!(puts(mock).await.is_empty());
    releaser.abort();
    Ok(())
}

/// I-32 with a Markdown body: after the confirmed base-URL change and a new PAT the request is
/// rendered again under the new origin with the same converted body; nothing reaches the old one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i32_markdown_update_rerendered_under_new_origin() -> TestResult {
    let h = Harness::builder()
        .confluence("wiki")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let a = wiki(&h)?;
    a.applinks_manifest("9.2.1").await;
    mount_page(a, ID, &page(5, "<p>old</p>")).await;
    let md_body = "New *text*.";
    let id = queued(&h, params(5, md_body, None)).await?;
    let first = h.approver().open(&id).map_err(de)?.preview;
    let rev1 = first.candidate_rev.counter;
    let b = MockDc::start(atlas_duck_atlassian::Product::Confluence, "/wiki2").await;
    b.confluence_user_current(UserKind::Known, TEST_USER, TEST_USER_KEY)
        .await;
    b.applinks_manifest("9.2.1").await;
    mount_page(&b, ID, &page(5, "<p>old</p>")).await;
    mount_stale_check(&b, ID, 5).await;
    mount_put(&b, ID, 200, fixtures::CONFLUENCE_PAGE_UPDATED).await;
    let received_at_a = a.received().await.len();
    h.instances().change_base_url("wiki", &b.base_url())?;
    rev_after(&h, &id, rev1).await?;
    h.instances()
        .set_token("wiki", SecretString::from("new-pat".to_owned()), None)
        .await?;
    let mut ok = false;
    for _ in 0..400 {
        if h.approver().item(&id).is_some_and(|i| i.approvable) {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(ok, "never approvable again");
    let p = h.approver().open(&id).map_err(de)?.preview;
    let PreviewBody::EditDiff { requests, .. } = &p.body else {
        return Err(format!("not the edit diff: {:?}", p.body).into());
    };
    assert!(
        requests[0].resolved_url.starts_with(&b.base_url()),
        "{}",
        requests[0].resolved_url
    );
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let sent = puts(&b).await;
    assert_eq!(sent.len(), 1);
    let body: Value = serde_json::from_slice(&sent[0].body)?;
    assert_eq!(
        body["body"]["storage"]["value"],
        markdown_to_storage(md_body).0.as_str()
    );
    assert!(puts(a).await.is_empty());
    assert_eq!(
        a.received().await.len(),
        received_at_a,
        "A receives nothing after the change"
    );
    Ok(())
}

// ---- T23b: the caution card is built off the entry lock ------------------------------------------

/// Releases the held build when the test ends, passed or not, so a failing test never leaves a
/// thread waiting on the pause.
struct ReleaseOnDrop(Arc<BuildPause>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// A Confluence harness whose caution builds hold on the returned pause once it is armed. Shared,
/// so every engine call made while a build may be held runs on a task of its own ([`bounded`],
/// [`bounded_async`]): the test thread itself never waits on an entry lock.
async fn held_builds() -> Result<(Arc<Harness>, Arc<BuildPause>, ReleaseOnDrop), TestError> {
    let pause = BuildPause::new();
    let h = Harness::builder()
        .confluence("wiki")
        .hooks(TestHooks {
            hold_caution_build: Some(pause.clone()),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let release = ReleaseOnDrop(pause.clone());
    Ok((Arc::new(h), pause, release))
}

const PROBE_WAIT: Duration = Duration::from_secs(10);

async fn reached(pause: &BuildPause) -> TestResult {
    tokio::time::timeout(PROBE_WAIT, pause.reached.notified())
        .await
        .map_err(|_| "the caution build never started")?;
    Ok(())
}

/// `f` (a synchronous engine call) on a blocking thread, bounded: one that waits behind the
/// entry lock fails the test (and the guard then releases the held build) instead of hanging it.
async fn bounded<T: Send + 'static>(
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, TestError> {
    match tokio::time::timeout(PROBE_WAIT, tokio::task::spawn_blocking(f)).await {
        Ok(done) => Ok(done?),
        Err(_) => Err(format!("{what} waited for the caution build").into()),
    }
}

/// [`bounded`] for an async engine call, driven on a blocking thread too: a call that blocks its
/// thread on the entry lock must not take a runtime worker with it (the timeout itself needs the
/// workers).
async fn bounded_async<T: Send + 'static>(
    what: &str,
    f: impl std::future::Future<Output = T> + Send + 'static,
) -> Result<T, TestError> {
    let runtime = tokio::runtime::Handle::current();
    bounded(what, move || runtime.block_on(f)).await
}

/// The Caution warnings of a card: what the queue row's count counts (§5.6).
fn cautions(p: &atlas_duck_preview::Preview) -> u32 {
    let n = p
        .warnings
        .iter()
        .filter(|w| w.level == Level::Caution)
        .count();
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// T23b (T23 review I-4): the card build behind the queue row's caution count runs off the entry
/// lock. A lossy Markdown update's enrichment build is held (the pause stands in for the seconds a
/// body near the 16 MiB limit takes, so the page is small); meanwhile the queue listing (it takes
/// every entry's lock), a status poll of the same request and a decision on another request
/// answer. Released, the revision is queued with its count stored in the same critical section
/// as its verdict: the pause is armed again and no later build is needed.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn caution_build_does_not_hold_the_entry_lock() -> TestResult {
    let (h, pause, _release) = held_builds().await?;
    let mock = wiki(&h)?;
    mount_page(
        mock,
        ID,
        &page(7, "<ac:structured-macro ac:name=\"toc\"/><p>a</p>"),
    )
    .await;
    let mut other = page(7, "<p>o</p>");
    other["id"] = json!("65538");
    mount_page(mock, "65538", &other).await;
    let mut other_params = params(7, "<p>y</p>", Some("storage"));
    other_params["id"] = json!("65538");
    let other_id = queued(&h, other_params).await?;

    pause.arm();
    let submit = h.clone();
    let env = bounded_async("the submit", async move {
        submit.submit(UPDATE, params(7, "a", None)).await
    })
    .await?;
    let id = request_id(&env)?;
    reached(&pause).await?;
    let decisions = h.decisions();
    let listed = bounded("the queue listing", move || decisions.queue_list()).await?;
    assert!(listed.iter().any(|i| i.request_id == other_id));
    assert!(
        !listed.iter().any(|i| i.request_id == id),
        "still enriching"
    );
    let (handler, poll) = (h.handler(), id.clone());
    let status = bounded_async(
        "the status poll",
        async move { handler.status(&poll).await },
    )
    .await?;
    assert_eq!(status.status, Status::Pending);
    let (approver, deny) = (h.approver(), other_id.clone());
    bounded("a decision on another request", move || {
        approver.deny_unopened(&deny, "no")
    })
    .await?
    .map_err(de)?;

    // Released, armed again: a count not stored with the verdict would need a build that now
    // holds, and the row would show none.
    pause.release();
    pause.arm();
    let (queued_h, wait) = (h.clone(), id.clone());
    let item = bounded_async(
        "the queue",
        async move { queued_h.queued(&wait, 5_000).await },
    )
    .await?
    .ok_or("never queued")?;
    let (approver, open) = (h.approver(), id.clone());
    let card = bounded("opening the card", move || approver.open(&open))
        .await?
        .map_err(de)?
        .preview;
    assert!(card.warnings.iter().any(|w| w.id == WarningId::LossyUpdate));
    assert!(cautions(&card) >= 1);
    assert_eq!(item.caution_count, cautions(&card));
    Ok(())
}

/// T23b: a caution count built for a revision the entry has left is dropped, never stored. A
/// failed stale check returns an approved update to the queue (`recheck_failed`: a new revision
/// whose card leads with the "could not re-check" Caution) and its count is built after the
/// return. While that build is held the approver opens the card and edits the body; the edit's
/// re-enrichment makes a newer revision whose count (no re-check Caution) is stored with it. The
/// held build then finishes for the revision the entry left, and its count is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn caution_of_a_left_revision_is_dropped() -> TestResult {
    let (h, pause, _release) = held_builds().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page(7, "<p>a</p>")).await;
    // The stale check's GET fails: back to the queue as `recheck_failed`.
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(ID))))
        .and(query_param("expand", "version"))
        .respond_with(mock.response(503))
        .mount(mock.server())
        .await;
    let id = queued(&h, params(7, "<p>b</p>", Some("storage"))).await?;
    let first = h.approver().rev(&id).map_err(de)?;

    pause.arm();
    let (approver, approve) = (h.approver(), id.clone());
    bounded("the approval", move || approver.approve(&approve))
        .await?
        .map_err(de)?;
    reached(&pause).await?;
    let (approver, item) = (h.approver(), id.clone());
    let returned = bounded("the queue row", move || approver.item(&item))
        .await?
        .ok_or("not back in the queue")?;
    assert!(returned.stale);
    assert_eq!(returned.candidate_rev.counter, first.counter + 1);
    let (approver, open) = (h.approver(), id.clone());
    let card = bounded("opening the card", move || approver.open(&open))
        .await?
        .map_err(de)?
        .preview;
    assert_eq!(
        card.warnings.first().map(|w| w.id),
        Some(WarningId::CouldNotRecheck)
    );
    let left_count = cautions(&card);

    let mut set = Map::new();
    set.insert("body".into(), json!("<p>c</p>"));
    let (approver, edit) = (h.approver(), id.clone());
    bounded("an edit", move || {
        approver.edit(
            &edit,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
    })
    .await?
    .map_err(de)?;
    // `body` re-runs the enrichment: the newer revision is queued with its own count.
    let (later, wait, counter) = (h.clone(), id.clone(), returned.candidate_rev.counter);
    let edited = bounded_async("the edited revision", async move {
        rev_after(&later, &wait, counter)
            .await
            .map_err(|e| e.to_string())
    })
    .await??;
    let (approver, open) = (h.approver(), id.clone());
    let card = bounded("opening the edited card", move || approver.open(&open))
        .await?
        .map_err(de)?
        .preview;
    assert!(
        !card
            .warnings
            .iter()
            .any(|w| w.id == WarningId::CouldNotRecheck)
    );
    assert_eq!(edited.caution_count, cautions(&card));
    assert!(edited.caution_count < left_count, "the counts differ");

    pause.release();
    tokio::time::timeout(PROBE_WAIT, pause.settled.notified())
        .await
        .map_err(|_| "the held build never settled")?;
    let now = h.approver().item(&id).ok_or("not in the queue")?;
    assert_eq!(now.candidate_rev, edited.candidate_rev);
    assert_eq!(
        now.caution_count, edited.caution_count,
        "the count of the revision the entry left was stored"
    );
    Ok(())
}

/// The queue row of `id` once `ready` holds for it, polled (every read bounded) for at most
/// [`PROBE_WAIT`]: a count that is never stored fails by timeout, never by a hang.
async fn row_when(
    h: &Arc<Harness>,
    id: &str,
    what: &str,
    ready: impl Fn(&atlas_duck_core::QueueItem) -> bool,
) -> Result<atlas_duck_core::QueueItem, TestError> {
    let deadline = std::time::Instant::now() + PROBE_WAIT;
    loop {
        let (approver, item) = (h.approver(), id.to_owned());
        let row = bounded("the queue row", move || approver.item(&item)).await?;
        if let Some(row) = row
            && ready(&row)
        {
            return Ok(row);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("the queue row never showed {what}").into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// An approved update whose stale check fails (GET 503) and is queued again as `recheck_failed`,
/// with the harness' caution builds unarmed: the row, the card that leads with the "could not
/// re-check" Caution and that card's count.
async fn recheck_failed_return(
    h: &Arc<Harness>,
) -> Result<(String, atlas_duck_core::QueueItem, u32), TestError> {
    let mock = wiki(h)?;
    mount_page(mock, ID, &page(7, "<p>a</p>")).await;
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(ID))))
        .and(query_param("expand", "version"))
        .respond_with(mock.response(503))
        .mount(mock.server())
        .await;
    let id = queued(h, params(7, "<p>b</p>", Some("storage"))).await?;
    let (approver, approve) = (h.approver(), id.clone());
    bounded("the approval", move || approver.approve(&approve))
        .await?
        .map_err(de)?;
    let returned = row_when(h, &id, "the return", |r| r.stale).await?;
    let (approver, open) = (h.approver(), id.clone());
    let card = bounded("opening the card", move || approver.open(&open))
        .await?
        .map_err(de)?
        .preview;
    assert_eq!(
        card.warnings.first().map(|w| w.id),
        Some(WarningId::CouldNotRecheck)
    );
    Ok((id, returned, cautions(&card)))
}

/// T23b review I-1: a write returned to the queue gets the count of its new revision stored. The
/// count is built after the return (`recount`), so the row first shows the previous revision's
/// count and then the card's (the stored count is what separates "stored" from "never stored").
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn returned_write_row_shows_the_count_of_its_card() -> TestResult {
    let (h, _pause, _release) = held_builds().await?;
    let (id, _, card_count) = recheck_failed_return(&h).await?;
    assert!(card_count >= 1, "the return adds a Caution");
    let row = row_when(&h, &id, "the card's count", |r| {
        r.caution_count == card_count
    })
    .await?;
    assert!(row.stale);
    Ok(())
}

/// T23b review I-1: an edit that does not re-enrich stores the count of its new revision with the
/// edit. A `body` set to the value it already has changes no enrichment key, and the edit clears
/// the return reason (the "could not re-check" Caution), so the count falls. The pause is armed
/// after the edit was applied: a count not stored with the edit would need a build that now holds,
/// and the row would keep the returned revision's count.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn edit_without_enrichment_stores_the_count_with_the_edit() -> TestResult {
    let (h, pause, _release) = held_builds().await?;
    let (id, returned, returned_count) = recheck_failed_return(&h).await?;
    assert!(returned_count >= 1);
    row_when(&h, &id, "the returned count", |r| {
        r.caution_count == returned_count
    })
    .await?;

    let mut set = Map::new();
    set.insert("body".into(), json!("<p>b</p>"));
    let (approver, edit) = (h.approver(), id.clone());
    bounded("an edit", move || {
        approver.edit(
            &edit,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
    })
    .await?
    .map_err(de)?;
    pause.arm();
    let (approver, item) = (h.approver(), id.clone());
    let edited = bounded("the queue row", move || approver.item(&item))
        .await?
        .ok_or("not in the queue")?;
    assert!(
        edited.candidate_rev.counter > returned.candidate_rev.counter,
        "a new revision"
    );
    let (approver, open) = (h.approver(), id.clone());
    let card = bounded("opening the edited card", move || approver.open(&open))
        .await?
        .map_err(de)?
        .preview;
    assert!(
        !card
            .warnings
            .iter()
            .any(|w| w.id == WarningId::CouldNotRecheck)
    );
    assert!(cautions(&card) < returned_count, "the counts differ");
    assert_eq!(
        edited.caution_count,
        cautions(&card),
        "the edit left the returned revision's count"
    );
    Ok(())
}
