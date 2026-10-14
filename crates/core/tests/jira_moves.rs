#![cfg(feature = "testing")]
//! `jira.sprint.move_issues` and `jira.backlog.move_issues` (Task 18, PD-54): the 50-issue limit at
//! validation (U-02, §7.3), the sprint-state enrichment and its closed-sprint hold, the sprint
//! stale rule (§5.4 step 5), the move card read from the sent request (§6.3 "sprint move"), and
//! the move cases of the batch rules (I-06, §5.6).

mod common;

use std::time::Duration;

use atlas_duck_atlassian::HttpRequestSpec;
use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser};
use atlas_duck_audit::EventType;
use atlas_duck_core::lifecycle::model::Hold;
use atlas_duck_core::ops::{
    EnrichCtx, EnrichPurpose, EnrichStep, EnrichVerdict, ExecCtx, ExecError, ExecPlan, PreviewCtx,
    PreviewInput, PreviewModel, StaleCtx, StaleVerdict, WriteView, op_table,
};
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::Harness;
use atlas_duck_core::validate::MOVE_LIMIT_HINT;
use atlas_duck_core::{
    BatchFailure, BatchItem, Confirm, DecisionError, DecisionOutcome, DenyDetails, Edits, QueueItem,
};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::{Preview, PreviewBody, WarningId};
use common::jira::{gets_on, mount_sprint};
use common::{TestError, TestResult, code, de, detail, exit, message, request_id};
use serde_json::{Map, Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path};

const SPRINT_MOVE: &str = "jira.sprint.move_issues";
const BACKLOG_MOVE: &str = "jira.backlog.move_issues";
const SPRINT_PATH: &str = "/rest/agile/1.0/sprint/7";
const SPRINT_POST: &str = "/rest/agile/1.0/sprint/7/issue";
const BACKLOG_POST: &str = "/rest/agile/1.0/backlog/issue";

/// `GET /rest/agile/1.0/sprint/{id}` as Jira Software answers it.
fn sprint(id: u64, name: &str, state: &str) -> Value {
    json!({
        "id": id,
        "self": format!("https://jira.corp.example/rest/agile/1.0/sprint/{id}"),
        "state": state,
        "name": name,
        "startDate": "2026-10-01T09:00:00.000+02:00",
        "endDate": "2026-10-15T09:00:00.000+02:00",
        "originBoardId": 3,
        "goal": "Ship it"
    })
}

fn sprint_params(issues: &[&str]) -> Value {
    json!({"id": 7, "issues": issues})
}

fn backlog_params(issues: &[&str]) -> Value {
    json!({"issues": issues})
}

/// `n` distinct keys `ABC-1` .. `ABC-n`.
fn keys(n: usize) -> Vec<String> {
    (1..=n).map(|i| format!("ABC-{i}")).collect()
}

// ---- pure: the rule, the executors and the card without the engine --------------------------

fn spec(op: &str) -> Result<&'static atlas_duck_registry::OperationSpec, TestError> {
    atlas_duck_registry::get(op).ok_or_else(|| format!("no {op}").into())
}

/// The enrichment of a sprint move over `answers`: the GETs its plan asks for, then the verdict.
fn enrich(
    params: &Value,
    answers: &[Value],
) -> Result<(Vec<(EnrichPurpose, String)>, EnrichVerdict), TestError> {
    let rule = op_table()
        .get(SPRINT_MOVE)
        .and_then(|i| i.enrich)
        .ok_or("no enrich rule")?;
    let ctx = EnrichCtx {
        spec: spec(SPRINT_MOVE)?,
        params,
    };
    let mut got: Vec<Value> = Vec::new();
    let mut asked = Vec::new();
    for _ in 0..4 {
        match (rule.plan)(&ctx, &got) {
            EnrichStep::Judge => break,
            EnrichStep::Fetch(calls) => {
                for (purpose, call) in calls {
                    let mut p = call.endpoint_template.clone();
                    for (k, v) in call.params.as_object().into_iter().flatten() {
                        p = p.replace(&format!("{{{k}}}"), &v.to_string());
                    }
                    asked.push((purpose, p));
                    let next = answers.get(got.len()).ok_or("the plan asked for more")?;
                    got.push(next.clone());
                }
            }
        }
    }
    Ok((asked, (rule.judge)(&ctx, &got)))
}

fn exec(op: &str, params: &Value, verdict: Option<&EnrichVerdict>) -> Result<ExecPlan, ExecError> {
    let base = atlas_duck_atlassian::normalize_base_url("https://jira.example.invalid")
        .map_err(|_| ExecError::EnrichmentRequired)?;
    let imp = op_table().get(op).ok_or(ExecError::EnrichmentRequired)?;
    let spec = atlas_duck_registry::get(op).ok_or(ExecError::EnrichmentRequired)?;
    let ctx = ExecCtx {
        spec,
        params,
        base: &base,
        enrichment: verdict,
        effective_max: None,
        comments_cap: None,
        test_fault: None,
    };
    (imp.executor)(&ctx)
}

fn requests(
    op: &str,
    params: &Value,
    verdict: Option<&EnrichVerdict>,
) -> Result<Vec<HttpRequestSpec>, TestError> {
    match exec(op, params, verdict) {
        Ok(ExecPlan::Write(r)) => Ok(r),
        other => Err(format!("not a write: {other:?}").into()),
    }
}

/// The verdict a future or active sprint 7 gives.
fn active_verdict(params: &Value) -> Result<EnrichVerdict, TestError> {
    let (_, v) = enrich(params, &[sprint(7, "Sprint 7", "active")])?;
    assert_eq!(v.hold, Hold::Preview);
    Ok(v)
}

/// The card of `op` over `reqs` (the request list that is sent) and `verdict`.
fn card_over(
    op: &str,
    params: &Value,
    reqs: &[HttpRequestSpec],
    verdict: Option<&EnrichVerdict>,
) -> Result<PreviewModel, TestError> {
    let imp = op_table().get(op).ok_or("no OpImpl")?;
    let ctx = PreviewCtx {
        spec: spec(op)?,
        instance_alias: "jira-main",
        params,
        input: PreviewInput::Write(WriteView {
            requests: reqs,
            hold: verdict.map_or(Hold::Preview, |v| v.hold),
            enrichment: verdict,
            failure: None,
        }),
        field_names: None,
    };
    Ok((imp.previewer)(&ctx))
}

struct Card {
    sentence: String,
    rows: Vec<(String, String)>,
}

fn card(m: &PreviewModel) -> Result<Card, TestError> {
    match &m.body {
        PreviewBody::WriteSummary {
            sentence,
            rows,
            constructs,
            requests,
        } => {
            assert_eq!(requests.len(), 1, "the exact request list stays (inv. 4)");
            assert_eq!(*constructs, None, "a move carries no wiki text");
            Ok(Card {
                sentence: sentence.clone(),
                rows: rows.clone(),
            })
        }
        other => Err(format!("not a write summary: {other:?}").into()),
    }
}

fn row<'a>(c: &'a Card, name: &str) -> Option<&'a str> {
    c.rows
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// The `Issue N` rows, in order.
fn issue_rows(c: &Card) -> Vec<String> {
    c.rows
        .iter()
        .filter(|(n, _)| n.starts_with("Issue ") && n != "Issues (sent)")
        .map(|(_, v)| v.clone())
        .collect()
}

#[test]
fn sprint_move_reads_the_sprint_and_sends_the_keys() -> TestResult {
    let params = sprint_params(&["ABC-1", "ABC-2"]);
    let (asked, verdict) = enrich(&params, &[sprint(7, "Sprint 7", "active")])?;
    assert_eq!(
        asked,
        [(EnrichPurpose::Enrich, SPRINT_PATH.to_owned())],
        "one GET of the sprint the request moves into"
    );
    assert_eq!(verdict.hold, Hold::Preview);
    assert_eq!(
        verdict.baseline,
        json!({"state": "active", "name": "Sprint 7"})
    );
    // A future sprint is a target too.
    let (_, future) = enrich(&params, &[sprint(7, "Next", "future")])?;
    assert_eq!(future.hold, Hold::Preview);
    assert_eq!(future.baseline, json!({"state": "future", "name": "Next"}));

    let reqs = requests(SPRINT_MOVE, &params, Some(&verdict))?;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(
        reqs[0].resolved_url,
        format!("https://jira.example.invalid{SPRINT_POST}")
    );
    assert_eq!(reqs[0].content_type.as_deref(), Some("application/json"));
    let body: Value = serde_json::from_slice(&reqs[0].body)?;
    assert_eq!(body, json!({"issues": ["ABC-1", "ABC-2"]}));
    // Only a `Preview` verdict renders a request.
    assert_eq!(
        exec(SPRINT_MOVE, &params, None),
        Err(ExecError::EnrichmentRequired)
    );
    let (_, closed) = enrich(&params, &[sprint(7, "Sprint 7", "closed")])?;
    assert_eq!(
        exec(SPRINT_MOVE, &params, Some(&closed)),
        Err(ExecError::EnrichmentRequired)
    );
    // ... and only one whose facts are about this sprint, in a state issues can move into.
    let mut bare = verdict.clone();
    bare.summary = None;
    let mut other = verdict.clone();
    if let Some(s) = other.summary.as_mut().and_then(|s| s.sprint.as_mut()) {
        s.id = 8;
    }
    let mut shut = verdict.clone();
    if let Some(s) = shut.summary.as_mut().and_then(|s| s.sprint.as_mut()) {
        s.state = "closed".to_owned();
    }
    for v in [bare, other, shut] {
        assert_eq!(
            exec(SPRINT_MOVE, &params, Some(&v)),
            Err(ExecError::EnrichmentRequired)
        );
    }
    Ok(())
}

#[test]
fn backlog_move_sends_the_keys_without_enrichment() -> TestResult {
    let params = backlog_params(&["ABC-3", "XYZ-12"]);
    assert!(
        op_table()
            .get(BACKLOG_MOVE)
            .is_some_and(|i| i.enrich.is_none() && i.stale_check.is_none()),
        "PD-54: no enrichment and no stale rule"
    );
    let reqs = requests(BACKLOG_MOVE, &params, None)?;
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(
        reqs[0].resolved_url,
        format!("https://jira.example.invalid{BACKLOG_POST}")
    );
    let body: Value = serde_json::from_slice(&reqs[0].body)?;
    assert_eq!(body, json!({"issues": ["ABC-3", "XYZ-12"]}));
    Ok(())
}

#[test]
fn sprint_judge_fails_closed() -> TestResult {
    let params = sprint_params(&["ABC-1"]);
    // PD-54: a closed sprint holds the move, with the facts the card names it by.
    let (_, closed) = enrich(&params, &[sprint(7, "Sprint 7", "closed")])?;
    assert_eq!(closed.hold, Hold::EnrichmentError);
    let facts = closed
        .summary
        .as_ref()
        .and_then(|s| s.sprint.as_ref())
        .ok_or("no sprint facts")?;
    assert_eq!(
        (facts.id, facts.name.as_str(), facts.state.as_str()),
        (7, "Sprint 7", "closed")
    );
    // Anything else it cannot read is no `Preview` either.
    let mut no_state = sprint(7, "Sprint 7", "active");
    no_state["state"] = Value::Null;
    let mut no_name = sprint(7, "Sprint 7", "active");
    no_name.as_object_mut().ok_or("object")?.remove("name");
    let mut no_id = sprint(7, "Sprint 7", "active");
    no_id.as_object_mut().ok_or("object")?.remove("id");
    for answer in [
        sprint(8, "Sprint 8", "active"),
        sprint(7, "Sprint 7", "ACTIVE"),
        sprint(7, "Sprint 7", "deleted"),
        no_state,
        no_name,
        no_id,
        json!({"id": "7", "name": "Sprint 7", "state": "active"}),
        json!([sprint(7, "Sprint 7", "active")]),
        json!("active"),
    ] {
        let (_, v) = enrich(&params, std::slice::from_ref(&answer))?;
        assert_eq!(v.hold, Hold::EnrichmentError, "{answer}");
        assert_eq!(
            exec(SPRINT_MOVE, &params, Some(&v)),
            Err(ExecError::EnrichmentRequired),
            "{answer}"
        );
    }
    Ok(())
}

/// The issue-list checks of both executors (validation dry call: no verdict).
fn refused(op: &str, params: &Value) -> Option<(String, String)> {
    match exec(op, params, None) {
        Err(ExecError::Invalid(e)) => Some((
            e.details
                .get("param")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            e.details
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        )),
        _ => None,
    }
}

#[test]
fn move_issue_lists_are_checked_statically() -> TestResult {
    let long = format!("A{}-1", "B".repeat(254));
    assert_eq!(long.len(), 257);
    let fits = format!("A{}-1", "B".repeat(252));
    assert_eq!(fits.len(), 255);
    let fifty: Vec<String> = keys(50);
    let fifty_one: Vec<String> = keys(51);
    for (op, with) in [(SPRINT_MOVE, json!({"id": 7})), (BACKLOG_MOVE, json!({}))] {
        let params = |issues: Value| {
            let mut p = with.clone();
            p["issues"] = issues;
            p
        };
        let twice = "must not list an issue twice";
        for (issues, why) in [
            (json!(["ABC-1", "ABC-1"]), twice),
            // Jira reads the number, so a leading zero names the same issue.
            (json!(["ABC-1", "ABC-01"]), twice),
            (json!(["ABC-007", "ABC-2", "ABC-7"]), twice),
            (json!([]), "must list at least one issue"),
            (
                json!([long.clone()]),
                "must be issue keys of at most 255 characters",
            ),
            (json!(["abc-1"]), "must be issue keys such as ABC-123"),
            (json!(["ABC-1 "]), "must be issue keys such as ABC-123"),
            (json!(["ABC-"]), "must be issue keys such as ABC-123"),
            (json!([1]), "must be issue keys such as ABC-123"),
            (json!("ABC-1"), "must be a list of issue keys"),
            (json!(fifty_one.clone()), MOVE_LIMIT_HINT),
        ] {
            assert_eq!(
                refused(op, &params(issues.clone())),
                Some(("issues".to_owned(), why.to_owned())),
                "{op} {issues}"
            );
        }
        // Distinct keys of other projects, 50 of them, and a 255-character key pass.
        for issues in [
            json!(fifty.clone()),
            json!(["ABC-1", "ABD-1", "AB-11", "ABC-10"]),
            json!([fits.clone()]),
        ] {
            assert_eq!(refused(op, &params(issues.clone())), None, "{op} {issues}");
        }
    }
    Ok(())
}

fn stale(baseline: &Value, answer: &Value) -> Result<StaleVerdict, TestError> {
    let rule = op_table()
        .get(SPRINT_MOVE)
        .and_then(|i| i.stale_check)
        .ok_or("no stale rule")?;
    let params = sprint_params(&["ABC-1"]);
    let ctx = StaleCtx {
        spec: spec(SPRINT_MOVE)?,
        params: &params,
        baseline,
    };
    let calls = (rule.plan)(&ctx);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].endpoint_template, "/rest/agile/1.0/sprint/{id}");
    assert_eq!(calls[0].params, json!({"id": 7}));
    assert!(calls[0].query.is_empty());
    Ok((rule.judge)(&ctx, std::slice::from_ref(answer)))
}

#[test]
fn sprint_stale_rule_wants_a_future_or_active_sprint() -> TestResult {
    let was = json!({"state": "active", "name": "Sprint 7"});
    let was_future = json!({"state": "future", "name": "Sprint 7"});
    assert_eq!(
        stale(&was, &sprint(7, "Sprint 7", "active"))?,
        StaleVerdict::Unchanged
    );
    // PD-54: still future or active; a start or a rename is no change.
    assert_eq!(
        stale(&was_future, &sprint(7, "Sprint 7", "active"))?,
        StaleVerdict::Unchanged
    );
    assert_eq!(
        stale(&was, &sprint(7, "Renamed", "active"))?,
        StaleVerdict::Unchanged
    );
    assert_eq!(
        stale(&was, &sprint(7, "Sprint 7", "closed"))?,
        StaleVerdict::Changed {
            delta: "sprint closed since review".to_owned()
        }
    );
    // Never `Unchanged` on an answer it cannot read, or about another sprint.
    for answer in [
        sprint(8, "Sprint 8", "active"),
        sprint(7, "Sprint 7", "deleted"),
        json!({"id": 7, "name": "Sprint 7"}),
        json!({}),
    ] {
        assert!(
            matches!(stale(&was, &answer)?, StaleVerdict::Changed { .. }),
            "{answer}"
        );
    }
    Ok(())
}

#[test]
fn sprint_card_names_the_sprint_and_lists_every_key() -> TestResult {
    let params = sprint_params(&["ABC-1", "ABC-2"]);
    let verdict = active_verdict(&params)?;
    let reqs = requests(SPRINT_MOVE, &params, Some(&verdict))?;
    let m = card_over(SPRINT_MOVE, &params, &reqs, Some(&verdict))?;
    let c = card(&m)?;
    assert_eq!(
        c.sentence,
        "Move 2 issues to sprint \"Sprint 7\" (id 7, active)"
    );
    assert_eq!(row(&c, "Sprint id (sent)"), Some("7"));
    assert_eq!(row(&c, "Sprint name"), Some("Sprint 7"));
    assert_eq!(row(&c, "Sprint state"), Some("active"));
    assert_eq!(row(&c, "Issues (sent)"), Some("2"));
    assert_eq!(issue_rows(&c), ["ABC-1", "ABC-2"]);
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);
    assert_eq!(m.header.hidden_in_preview_bytes, 0);

    // One issue reads as one; all 50 keys of a full request are listed, none hidden.
    let one = sprint_params(&["ABC-9"]);
    let reqs = requests(SPRINT_MOVE, &one, Some(&verdict))?;
    let c = card(&card_over(SPRINT_MOVE, &one, &reqs, Some(&verdict))?)?;
    assert_eq!(
        c.sentence,
        "Move 1 issue to sprint \"Sprint 7\" (id 7, active)"
    );
    let all = keys(50);
    let full = json!({"id": 7, "issues": all});
    let reqs = requests(SPRINT_MOVE, &full, Some(&verdict))?;
    let m = card_over(SPRINT_MOVE, &full, &reqs, Some(&verdict))?;
    let c = card(&m)?;
    assert_eq!(issue_rows(&c), all);
    assert_eq!(row(&c, "Issues (sent)"), Some("50"));
    assert_eq!(row(&c, "Issue 50"), Some("ABC-50"));
    assert_eq!(m.header.hidden_in_preview_bytes, 0);
    // The longest key the executor sends shows whole.
    let longest = format!("A{}-1", "B".repeat(252));
    let p = json!({"id": 7, "issues": [longest]});
    let reqs = requests(SPRINT_MOVE, &p, Some(&verdict))?;
    let m = card_over(SPRINT_MOVE, &p, &reqs, Some(&verdict))?;
    assert_eq!(issue_rows(&card(&m)?), [longest]);
    assert_eq!(m.header.hidden_in_preview_bytes, 0);
    Ok(())
}

/// T12 review M4 / T17 review I2: the card is read from the request that is sent, the sprint id
/// from its URL and the keys from its body, never from the params.
#[test]
fn move_card_is_read_from_the_sent_request() -> TestResult {
    let params = sprint_params(&["ABC-1", "ABC-2"]);
    let verdict = active_verdict(&params)?;
    let mut sent = requests(SPRINT_MOVE, &params, Some(&verdict))?;
    sent[0].body = serde_json::to_vec(&json!({"issues": ["XYZ-5", "XYZ-6", "XYZ-7"]}))?;
    let c = card(&card_over(SPRINT_MOVE, &params, &sent, Some(&verdict))?)?;
    assert_eq!(issue_rows(&c), ["XYZ-5", "XYZ-6", "XYZ-7"]);
    assert!(c.sentence.starts_with("Move 3 issues"), "{}", c.sentence);
    assert!(!format!("{:?}", c.rows).contains("ABC-"), "{:?}", c.rows);
    // Another sprint id in the URL: the facts (about sprint 7) do not name it.
    sent[0].resolved_url = sent[0].resolved_url.replace("/sprint/7/", "/sprint/8/");
    let c = card(&card_over(SPRINT_MOVE, &params, &sent, Some(&verdict))?)?;
    assert_eq!(
        c.sentence,
        "Move 3 issues to sprint 8 (enrichment read sprint 7)"
    );
    assert_eq!(row(&c, "Sprint id (sent)"), Some("8"));
    assert_eq!(row(&c, "Sprint name"), None);
    assert!(!format!("{:?}", c.rows).contains("Sprint 7"));

    let backlog = backlog_params(&["ABC-1"]);
    let mut sent = requests(BACKLOG_MOVE, &backlog, None)?;
    sent[0].body = serde_json::to_vec(&json!({"issues": ["XYZ-5", "XYZ-6"]}))?;
    let c = card(&card_over(BACKLOG_MOVE, &backlog, &sent, None)?)?;
    assert_eq!(c.sentence, "Move 2 issues to the backlog");
    assert_eq!(issue_rows(&c), ["XYZ-5", "XYZ-6"]);
    Ok(())
}

#[test]
fn backlog_card_says_what_a_backlog_move_does() -> TestResult {
    let params = backlog_params(&["ABC-1", "ABC-2"]);
    let reqs = requests(BACKLOG_MOVE, &params, None)?;
    let m = card_over(BACKLOG_MOVE, &params, &reqs, None)?;
    let c = card(&m)?;
    assert_eq!(c.sentence, "Move 2 issues to the backlog");
    assert_eq!(
        row(&c, "Meaning"),
        Some("each issue leaves its future and active sprints")
    );
    assert_eq!(row(&c, "Issues (sent)"), Some("2"));
    assert_eq!(issue_rows(&c), ["ABC-1", "ABC-2"]);
    // No request (nothing rendered): the generic preview stays.
    let m = card_over(BACKLOG_MOVE, &params, &[], None)?;
    assert!(
        !matches!(m.body, PreviewBody::WriteSummary { .. }),
        "{:?}",
        m.body
    );
    Ok(())
}

/// The sprint name is server text: cut short, display-escaped, quoted in the sentence, and its
/// invisible characters counted into the §6.4 Cautions.
#[test]
fn sprint_name_is_capped_escaped_and_counted() -> TestResult {
    let params = sprint_params(&["ABC-1"]);
    let name = format!("Sp\u{202e}rint\u{200b} \"7\" {}", "x".repeat(200));
    let (_, verdict) = enrich(&params, &[sprint(7, &name, "future")])?;
    assert_eq!(verdict.hold, Hold::Preview);
    let reqs = requests(SPRINT_MOVE, &params, Some(&verdict))?;
    let m = card_over(SPRINT_MOVE, &params, &reqs, Some(&verdict))?;
    let c = card(&m)?;
    let shown = format!("{} {:?}", c.sentence, c.rows);
    assert!(!shown.contains('\u{202e}') && !shown.contains('\u{200b}'));
    assert!(shown.contains("⟨U+202E⟩"), "{shown}");
    assert!(
        c.sentence
            .starts_with("Move 1 issue to sprint \"Sp⟨U+202E⟩rint⟨U+200B⟩ \\\"7\\\" "),
        "{}",
        c.sentence
    );
    assert!(c.sentence.ends_with("…\" (id 7, future)"), "{}", c.sentence);
    assert!(m.header.hidden_in_preview_bytes > 0);
    assert!(c.sentence.chars().count() < 200, "{}", c.sentence);
    let ids: Vec<WarningId> = m.warnings.iter().map(|w| w.id).collect();
    assert!(ids.contains(&WarningId::BidiControls), "{ids:?}");
    assert!(ids.contains(&WarningId::OtherInvisible), "{ids:?}");
    assert_eq!(m.header.bidi_controls, 1);
    Ok(())
}

/// PD-54: the closed-sprint hold shows the app's text, the name escaped and cut.
#[test]
fn closed_sprint_card_text() -> TestResult {
    let params = sprint_params(&["ABC-1"]);
    let (_, closed) = enrich(&params, &[sprint(7, "Sprint 7", "closed")])?;
    let m = card_over(SPRINT_MOVE, &params, &[], Some(&closed))?;
    match &m.body {
        PreviewBody::EnrichmentError {
            status,
            text,
            outcome,
        } => {
            assert_eq!((*status, *outcome), (None, None));
            assert_eq!(
                text,
                "sprint Sprint 7 is closed; issues cannot be moved into a closed sprint"
            );
        }
        other => return Err(format!("not the enrichment error: {other:?}").into()),
    }
    let (_, closed) = enrich(&params, &[sprint(7, "Old\u{202e}", "closed")])?;
    let m = card_over(SPRINT_MOVE, &params, &[], Some(&closed))?;
    match &m.body {
        PreviewBody::EnrichmentError { text, .. } => assert_eq!(
            text,
            "sprint Old⟨U+202E⟩ is closed; issues cannot be moved into a closed sprint"
        ),
        other => return Err(format!("not the enrichment error: {other:?}").into()),
    }
    assert_eq!(m.header.bidi_controls, 1);
    // An answer it cannot read keeps the generic "unusable" text.
    let (_, unusable) = enrich(&params, &[json!({})])?;
    let m = card_over(SPRINT_MOVE, &params, &[], Some(&unusable))?;
    match &m.body {
        PreviewBody::EnrichmentError { text, .. } => {
            assert!(!text.contains("closed"), "{text}");
        }
        other => return Err(format!("not the enrichment error: {other:?}").into()),
    }
    Ok(())
}

#[test]
fn move_schema_text_states_the_limits() -> TestResult {
    for op in [SPRINT_MOVE, BACKLOG_MOVE] {
        let schema = spec(op)?.params_schema_json();
        let issues = schema["properties"]["issues"]["description"]
            .as_str()
            .ok_or("no issues description")?;
        for needle in ["1 to 50", MOVE_LIMIT_HINT, "once", "255 characters"] {
            assert!(issues.contains(needle), "{op}: {needle:?} in {issues:?}");
        }
    }
    let schema = spec(SPRINT_MOVE)?.params_schema_json();
    let id = schema["properties"]["id"]["description"]
        .as_str()
        .ok_or("no id description")?;
    for needle in ["future or active", "closed"] {
        assert!(id.contains(needle), "{needle:?} in {id:?}");
    }
    let schema = spec(BACKLOG_MOVE)?.params_schema_json();
    let issues = schema["properties"]["issues"]["description"]
        .as_str()
        .ok_or("no issues description")?;
    assert!(
        issues.contains("leaves its future and active sprints"),
        "{issues:?}"
    );
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

async fn purposes(h: &Harness, id: &str) -> Result<Vec<Value>, TestError> {
    Ok(records(h, id, EventType::PREVIEW_FETCH)
        .await?
        .into_iter()
        .map(|r| r["purpose"].clone())
        .collect())
}

async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
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

async fn mount_post(mock: &MockDc, p: &str) {
    Mock::given(method("POST"))
        .and(path(mock.path(p)))
        .respond_with(mock.response(204))
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

async fn sent_bodies(mock: &MockDc, p: &str) -> Result<Vec<Value>, TestError> {
    posts(mock, p)
        .await
        .iter()
        .map(|r| Ok(serde_json::from_slice(&r.body)?))
        .collect()
}

fn card_rows(p: &Preview) -> Result<(String, Vec<(String, String)>), TestError> {
    match &p.body {
        PreviewBody::WriteSummary { sentence, rows, .. } => Ok((sentence.clone(), rows.clone())),
        other => Err(format!("not the move card: {other:?}").into()),
    }
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

/// U-02 (§7.3): 51 keys are refused at validation with the hint, verbatim; nothing is queued,
/// fetched or sent.
async fn over_50_rejected(op: &str, params: Value) -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_sprint(mock, 7, &sprint(7, "Sprint 7", "active")).await;
    mount_post(mock, SPRINT_POST).await;
    mount_post(mock, BACKLOG_POST).await;
    let before = mock.received().await.len();
    let env = h.submit(op, params).await;
    assert_eq!(
        (env.status, exit(&env), code(&env)),
        (Status::Failed, 2, "validation".to_owned()),
        "{}",
        env.to_json_line()
    );
    assert_eq!(message(&env), format!("params/issues: {MOVE_LIMIT_HINT}"));
    assert_eq!(detail(&env, "message"), json!(MOVE_LIMIT_HINT));
    assert_eq!(detail(&env, "param"), json!("issues"));
    assert_eq!(detail(&env, "limit"), json!(50));
    let id = request_id(&env)?;
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
    );
    assert!(h.approver().item(&id).is_none(), "nothing queued");
    assert_eq!(
        mock.received().await.len(),
        before,
        "nothing fetched or sent"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u02_sprint_move_over_50_rejected() -> TestResult {
    over_50_rejected(SPRINT_MOVE, json!({"id": 7, "issues": keys(51)})).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u02_backlog_move_over_50_rejected() -> TestResult {
    over_50_rejected(BACKLOG_MOVE, json!({"issues": keys(51)})).await
}

/// A list the executor refuses is exit 2 at validation as well: nothing queued or fetched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn move_invalid_lists_are_validation_errors() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_sprint(mock, 7, &sprint(7, "Sprint 7", "active")).await;
    let before = mock.received().await.len();
    for (op, params) in [
        (SPRINT_MOVE, json!({"id": 7, "issues": ["ABC-1", "ABC-01"]})),
        (BACKLOG_MOVE, json!({"issues": ["ABC-2", "ABC-2"]})),
        (BACKLOG_MOVE, json!({"issues": []})),
    ] {
        let env = h.submit(op, params.clone()).await;
        assert_eq!(
            (env.status, exit(&env), code(&env)),
            (Status::Failed, 2, "validation".to_owned()),
            "{params}: {}",
            env.to_json_line()
        );
        assert_eq!(detail(&env, "param"), json!("issues"), "{params}");
    }
    assert_eq!(mock.received().await.len(), before);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sprint_move_happy_path() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_sprint(mock, 7, &sprint(7, "Sprint 7", "active")).await;
    mount_post(mock, SPRINT_POST).await;
    let id = queued(&h, SPRINT_MOVE, sprint_params(&["ABC-1", "ABC-2"])).await?;
    let p = opened(&h, &id)?;
    assert!(p.approvable);
    let (sentence, rows) = card_rows(&p)?;
    assert_eq!(
        sentence,
        "Move 2 issues to sprint \"Sprint 7\" (id 7, active)"
    );
    assert!(
        rows.contains(&("Issue 2".into(), "ABC-2".into())),
        "{rows:?}"
    );
    // L06: the sprint and the issues are the targets; nothing is editable.
    let form = p.edit_form.as_ref().ok_or("no edit form")?;
    assert_eq!(form.inputs.len(), 2);
    assert!(form.inputs.iter().all(|i| i.read_only), "{form:?}");
    let mut set = Map::new();
    set.insert("issues".into(), json!(["ABC-3"]));
    let rev = h.approver().rev(&id).map_err(de)?;
    let edited = h.approver().edit(
        &id,
        Edits {
            set,
            remove: Vec::new(),
        },
    );
    assert!(
        matches!(
            edited,
            Err(DecisionError::Invalid(InvalidReason::TargetParamEdit))
        ),
        "{edited:?}"
    );
    assert_eq!(h.approver().rev(&id).map_err(de)?, rev);

    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(
        (env.status, exit(&env)),
        (Status::Succeeded, 0),
        "{}",
        env.to_json_line()
    );
    assert_eq!(env.data, Some(json!({ "receipt": {} })));
    assert_eq!(
        sent_bodies(mock, SPRINT_POST).await?,
        [json!({"issues": ["ABC-1", "ABC-2"]})]
    );
    // The sprint GET, then the identity call and the sprint stale check (L29).
    assert_eq!(
        purposes(&h, &id).await?,
        ["enrich", "stale_check", "stale_check"]
    );
    let gets: Vec<String> = records(&h, &id, EventType::PREVIEW_FETCH)
        .await?
        .iter()
        .filter_map(|r| r["path"].as_str().map(str::to_owned))
        .collect();
    assert!(gets[0].ends_with(SPRINT_PATH), "{gets:?}");
    assert!(gets[1].ends_with("/rest/api/2/myself"), "{gets:?}");
    assert_eq!(
        gets[0], gets[2],
        "the stale check reads what enrichment read"
    );
    assert_eq!(records(&h, &id, EventType::WRITE_EXECUTED).await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backlog_move_happy_path() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_post(mock, BACKLOG_POST).await;
    let id = queued(&h, BACKLOG_MOVE, backlog_params(&["ABC-1", "XYZ-2"])).await?;
    let p = opened(&h, &id)?;
    assert!(p.approvable);
    let (sentence, _) = card_rows(&p)?;
    assert_eq!(sentence, "Move 2 issues to the backlog");
    let form = p.edit_form.as_ref().ok_or("no edit form")?;
    assert!(form.inputs.iter().all(|i| i.read_only), "{form:?}");
    // No enrichment: nothing is fetched before the approval.
    assert!(purposes(&h, &id).await?.is_empty());
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(
        (env.status, exit(&env)),
        (Status::Succeeded, 0),
        "{}",
        env.to_json_line()
    );
    assert_eq!(env.data, Some(json!({ "receipt": {} })));
    assert_eq!(
        sent_bodies(mock, BACKLOG_POST).await?,
        [json!({"issues": ["ABC-1", "XYZ-2"]})]
    );
    // §5.4 step 5: no stale rule, the identity call still runs.
    assert_eq!(purposes(&h, &id).await?, ["stale_check"]);
    Ok(())
}

/// Review Focus 2 (PD-54): a closed target sprint holds the move: Approve disabled in Rust, no
/// deny hint applies, a plain deny is the only way out, and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sprint_closed_not_approvable() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_sprint(mock, 7, &sprint(7, "Sprint 7", "closed")).await;
    mount_post(mock, SPRINT_POST).await;
    let id = queued(&h, SPRINT_MOVE, sprint_params(&["ABC-1"])).await?;
    let p = opened(&h, &id)?;
    assert!(!p.approvable);
    match &p.body {
        PreviewBody::EnrichmentError { text, .. } => assert_eq!(
            text,
            "sprint Sprint 7 is closed; issues cannot be moved into a closed sprint"
        ),
        other => return Err(format!("not the closed-sprint card: {other:?}").into()),
    }
    assert!(!h.approver().item(&id).ok_or("not queued")?.approvable);
    not_approvable(h.approver().approve(&id))?;
    assert!(
        records(&h, &id, EventType::WRITE_APPROVED)
            .await?
            .is_empty()
    );
    for details in [
        DenyDetails::UpstreamHttp {
            include_messages: true,
        },
        DenyDetails::UpstreamHttp {
            include_messages: false,
        },
        DenyDetails::OutcomeHint,
        DenyDetails::ResolutionFailed {
            include_candidates: true,
        },
        DenyDetails::MissingFields {
            include_allowed_values: false,
        },
    ] {
        let res = h.approver().deny_with(&id, "closed", details);
        assert!(res.is_err(), "{details:?}: {res:?}");
        assert!(records(&h, &id, EventType::WRITE_DENIED).await?.is_empty());
    }
    h.approver().deny(&id, "the sprint is closed").map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(
        (env.status, exit(&env)),
        (Status::Denied, 3),
        "{}",
        env.to_json_line()
    );
    for key in ["status", "error_messages", "param", "missing_fields"] {
        assert_eq!(detail(&env, key), Value::Null, "{key}");
    }
    assert!(
        posts(mock, SPRINT_POST).await.is_empty(),
        "nothing was sent"
    );
    assert_eq!(purposes(&h, &id).await?, ["enrich"]);
    Ok(())
}

/// The sprint GET answers `first` once, then `then` on every later GET.
async fn sprint_answers(mock: &MockDc, first: &Value, then: &Value) {
    for (priority, body, once) in [(1, first, true), (2, then, false)] {
        let m = Mock::given(method("GET"))
            .and(path(mock.path(SPRINT_PATH)))
            .respond_with(
                mock.response(200)
                    .set_body_raw(body.to_string(), "application/json"),
            )
            .with_priority(priority);
        let m = if once { m.up_to_n_times(1) } else { m };
        m.mount(mock.server()).await;
    }
}

/// Review Focus 4: the sprint closed between the review and the approval: `WRITE_STALE
/// {changed}` with the PD-54 delta, nothing sent; the refresh reads the closed sprint and the
/// move is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sprint_move_stale_when_sprint_closed() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    sprint_answers(
        mock,
        &sprint(7, "Sprint 7", "active"),
        &sprint(7, "Sprint 7", "closed"),
    )
    .await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_post(mock, SPRINT_POST).await;
    let id = queued(&h, SPRINT_MOVE, sprint_params(&["ABC-1"])).await?;
    assert!(opened(&h, &id)?.approvable);
    let rev = h.approver().rev(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    let item = item_after(&h, &id, rev.counter + 1).await?;
    assert!(item.stale, "{item:?}");
    let mut refreshed = false;
    for _ in 0..400 {
        let p = purposes(&h, &id).await?;
        if p.iter().any(|p| p == "refresh")
            && matches!(
                h.approver().open(&id).map(|d| d.preview.body),
                Ok(PreviewBody::EnrichmentError { .. })
            )
        {
            refreshed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(refreshed, "never refreshed into the closed-sprint hold");
    assert_eq!(
        records(&h, &id, EventType::WRITE_STALE).await?,
        [json!({"reason": "changed", "class": null,
                "delta": "sprint closed since review"})]
    );
    assert!(
        posts(mock, SPRINT_POST).await.is_empty(),
        "nothing was sent"
    );
    assert_eq!(
        purposes(&h, &id).await?,
        ["enrich", "stale_check", "stale_check", "refresh"]
    );
    not_approvable(h.approver().approve(&id))?;
    assert_eq!(records(&h, &id, EventType::WRITE_APPROVED).await?.len(), 1);
    assert!(gets_on(mock, SPRINT_PATH).await.len() >= 3);
    Ok(())
}

fn batch_items(h: &Harness, ids: &[&str]) -> Result<Vec<BatchItem>, TestError> {
    ids.iter()
        .map(|id| {
            Ok(BatchItem {
                request_id: (*id).to_owned(),
                candidate_rev: h.approver().rev(id).map_err(de)?,
            })
        })
        .collect()
}

/// I-06 (§5.6): three opened moves of disjoint issue sets into one sprint are not "similar" and
/// batch-approve; each executes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_three_disjoint_moves_batch_approve() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_sprint(mock, 7, &sprint(7, "Sprint 7", "active")).await;
    mount_post(mock, SPRINT_POST).await;
    let first: Vec<String> = keys(50);
    let second: Vec<String> = (51..=100).map(|i| format!("ABC-{i}")).collect();
    let mut ids = Vec::new();
    for issues in [json!(first), json!(second), json!(["XYZ-1"])] {
        ids.push(queued(&h, SPRINT_MOVE, json!({"id": 7, "issues": issues})).await?);
    }
    for id in &ids {
        opened(&h, id)?;
        let row = h.approver().item(id).ok_or("not queued")?;
        assert_eq!(row.similar_to, None, "{id}");
        assert_eq!(row.possible_duplicate_of, None, "{id}");
        assert!(row.approvable, "{id}");
    }
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let out = h
        .decisions()
        .decide_batch(batch_items(&h, &refs)?)
        .map_err(de)?;
    assert_eq!(out.items.len(), 3);
    for id in &ids {
        let env = h.await_(id, 10_000).await;
        assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
        assert_eq!(records(&h, id, EventType::WRITE_EXECUTED).await?.len(), 1);
    }
    let mut sent: Vec<usize> = sent_bodies(mock, SPRINT_POST)
        .await?
        .iter()
        .map(|b| b["issues"].as_array().map_or(0, Vec::len))
        .collect();
    sent.sort_unstable();
    assert_eq!(sent, [1, 50, 50]);
    Ok(())
}

/// I-06 (§5.6): two moves into one sprint that share an issue key are "similar"; their batch is
/// rejected and decides nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_moves_sharing_key_flagged_batch_rejected() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_sprint(mock, 7, &sprint(7, "Sprint 7", "active")).await;
    mount_post(mock, SPRINT_POST).await;
    let a = queued(&h, SPRINT_MOVE, sprint_params(&["ABC-1", "ABC-2"])).await?;
    let b = queued(&h, SPRINT_MOVE, sprint_params(&["ABC-2", "ABC-3"])).await?;
    let ap = h.approver();
    ap.open(&a).map_err(de)?;
    let p = ap.open(&b).map_err(de)?.preview;
    let row = ap.item(&b).ok_or("not queued")?;
    assert_eq!(row.similar_to.as_deref(), Some(a.as_str()));
    assert_eq!(row.possible_duplicate_of, None);
    assert!(
        p.warnings
            .iter()
            .any(|w| w.id == WarningId::SimilarRequest
                && w.text == format!("similar to {a} pending")),
        "{:?}",
        p.warnings
    );
    let res = h.decisions().decide_batch(batch_items(&h, &[&a, &b])?);
    let failed = match res {
        Err(DecisionError::BatchRejected { failed }) => failed,
        other => return Err(format!("expected BatchRejected, got {other:?}").into()),
    };
    let flagged = BatchFailure::Invalid(InvalidReason::BatchItemFlagged);
    let mut want = vec![(a.clone(), flagged), (b.clone(), flagged)];
    want.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(failed, want);
    assert!(h.confirmer().texts().is_empty(), "no dialog");
    for id in [&a, &b] {
        assert!(records(&h, id, EventType::WRITE_APPROVED).await?.is_empty());
        assert!(h.approver().item(id).is_some(), "still queued");
    }
    assert!(posts(mock, SPRINT_POST).await.is_empty());
    Ok(())
}
