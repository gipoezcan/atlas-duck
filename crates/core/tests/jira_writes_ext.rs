#![cfg(feature = "testing")]
//! `jira.issue.assign` (Task 15, PD-52): the assignable-user resolution under the username
//! comparison (§7.2), the unassign body, the assignee stale rule (§5.4 step 5), the from → to
//! card and the unresolved or ambiguous assignee (I-35 assignable user).

mod common;

use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser};
use atlas_duck_audit::EventType;
use atlas_duck_core::lifecycle::model::Hold;
use atlas_duck_core::ops::{
    EnrichCtx, EnrichStep, EnrichVerdict, ExecCtx, ExecError, ExecPlan, PreviewCtx, PreviewInput,
    PreviewModel, StaleCtx, StaleVerdict, WriteView, op_table,
};
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::Harness;
use atlas_duck_core::{DecisionError, DecisionOutcome, DenyDetails, Edits, QueueItem};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::{Preview, PreviewBody, WarningId};
use common::jira::{gets_on, issue_path, mount_assignable, mount_issue, query};
use common::{TestError, TestResult, code, de, detail, request_id};
use serde_json::{Map, Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path};

const ASSIGN: &str = "jira.issue.assign";
const KEY: &str = "ABC-1";
const ASSIGNABLE: &str = "/rest/api/2/user/assignable/search";

fn spec() -> Result<&'static atlas_duck_registry::OperationSpec, TestError> {
    atlas_duck_registry::get(ASSIGN).ok_or_else(|| "no jira.issue.assign".into())
}

fn user(name: &str, key: &str, display: &str) -> Value {
    json!({
        "self": format!("https://jira.corp.example/rest/api/2/user?username={name}"),
        "name": name, "key": key, "displayName": display, "active": true
    })
}

fn jane() -> Value {
    user("jdoe", "JIRAUSER1", "Jane Doe")
}

fn bob() -> Value {
    user("bob", "JIRAUSER2", "Bob")
}

/// The stage-2 answer: the issue with `assignee` (or `null`).
fn issue_with(assignee: &Value) -> Value {
    json!({"id": "10001", "key": KEY, "fields": {"assignee": assignee}})
}

// ---- pure: the rule, the executor and the card without the engine ---------------------------

/// Runs the enrichment plan over `answers` the way the engine does: each round's answers are
/// taken from `answers` in order; returns the answers the plan asked for and the judge's verdict.
fn enrich(params: &Value, answers: &[Value]) -> Result<(usize, EnrichVerdict), TestError> {
    let rule = op_table()
        .get(ASSIGN)
        .and_then(|i| i.enrich)
        .ok_or("no enrich rule")?;
    let ctx = EnrichCtx {
        spec: spec()?,
        params,
    };
    let mut got: Vec<Value> = Vec::new();
    for _ in 0..4 {
        match (rule.plan)(&ctx, &got) {
            EnrichStep::Judge => break,
            EnrichStep::Fetch(calls) => {
                for _ in calls {
                    let next = answers.get(got.len()).ok_or("the plan asked for more")?;
                    got.push(next.clone());
                }
            }
        }
    }
    let used = got.len();
    Ok((used, (rule.judge)(&ctx, &got)))
}

fn exec(params: &Value, verdict: Option<&EnrichVerdict>) -> Result<ExecPlan, ExecError> {
    let base = atlas_duck_atlassian::normalize_base_url("https://jira.example.invalid")
        .map_err(|_| ExecError::EnrichmentRequired)?;
    let imp = op_table()
        .get(ASSIGN)
        .ok_or(ExecError::EnrichmentRequired)?;
    let spec = atlas_duck_registry::get(ASSIGN).ok_or(ExecError::EnrichmentRequired)?;
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

fn wire(params: &Value, verdict: &EnrichVerdict) -> Result<Value, TestError> {
    match exec(params, Some(verdict)) {
        Ok(ExecPlan::Write(reqs)) => {
            assert_eq!(reqs.len(), 1);
            let r = &reqs[0];
            assert_eq!(r.method, "PUT");
            assert!(
                r.resolved_url.ends_with("/rest/api/2/issue/ABC-1/assignee"),
                "{}",
                r.resolved_url
            );
            Ok(serde_json::from_slice(&r.body)?)
        }
        other => Err(format!("not a write: {other:?}").into()),
    }
}

fn preview(params: &Value, verdict: &EnrichVerdict) -> Result<PreviewModel, TestError> {
    let reqs = match exec(params, Some(verdict)) {
        Ok(ExecPlan::Write(r)) => r,
        other => return Err(format!("not a write: {other:?}").into()),
    };
    let imp = op_table().get(ASSIGN).ok_or("no OpImpl")?;
    let ctx = PreviewCtx {
        spec: spec()?,
        instance_alias: "jira-main",
        params,
        input: PreviewInput::Write(WriteView {
            requests: &reqs,
            hold: verdict.hold,
            enrichment: Some(verdict),
            failure: None,
        }),
        field_names: None,
    };
    Ok((imp.previewer)(&ctx))
}

struct Summary {
    sentence: String,
    rows: Vec<(String, String)>,
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
            assert_eq!(*constructs, None, "an assignment carries no wiki text");
            Ok(Summary {
                sentence: sentence.clone(),
                rows: rows.clone(),
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

/// The name a `Preview` verdict resolved for the wire.
fn resolved_name(v: &EnrichVerdict) -> Option<&str> {
    v.resolved.get("assignee").and_then(Value::as_str)
}

#[test]
fn assign_preview_from_to() -> TestResult {
    let params = json!({"key": KEY, "assignee": "bob"});
    let (used, v) = enrich(&params, &[json!([jane(), bob()]), issue_with(&jane())])?;
    assert_eq!(used, 2, "stage 1 resolve, stage 2 the current assignee");
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    assert_eq!(
        v.baseline,
        json!({"assignee_key": "JIRAUSER1", "assignee_name": "jdoe"})
    );
    assert_eq!(wire(&params, &v)?, json!({"name": "bob"}));
    let m = preview(&params, &v)?;
    let s = summary(&m)?;
    assert_eq!(s.sentence, "Assign ABC-1 to Bob (bob)");
    assert_eq!(row(&s, "From"), Some("Jane Doe (jdoe)"));
    assert_eq!(row(&s, "To"), Some("Bob (bob)"));
    // §7.3: previews record both `name` and `key`.
    assert_eq!(row(&s, "From user key"), Some("JIRAUSER1"));
    assert_eq!(row(&s, "To user key"), Some("JIRAUSER2"));

    // Unassign: no resolution, the current assignee only.
    let params = json!({"key": KEY, "assignee": null});
    let (used, v) = enrich(&params, &[issue_with(&jane())])?;
    assert_eq!(used, 1);
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    assert_eq!(wire(&params, &v)?, json!({"name": null}));
    let s = summary(&preview(&params, &v)?)?;
    assert_eq!(s.sentence, "Unassign ABC-1");
    assert_eq!(row(&s, "From"), Some("Jane Doe (jdoe)"));
    assert_eq!(row(&s, "To"), Some("(unassigned)"));

    // An unassigned issue: the baseline key is null.
    let params = json!({"key": KEY, "assignee": "bob"});
    let (_, v) = enrich(&params, &[json!([bob()]), issue_with(&Value::Null)])?;
    assert_eq!(
        v.baseline,
        json!({"assignee_key": null, "assignee_name": null})
    );
    let s = summary(&preview(&params, &v)?)?;
    assert_eq!(row(&s, "From"), Some("(unassigned)"));
    Ok(())
}

/// The card reads the request that is sent: a To row never names a user the body does not send.
#[test]
fn assign_card_names_the_sent_user_only() -> TestResult {
    let params = json!({"key": KEY, "assignee": "bob"});
    let (_, mut v) = enrich(&params, &[json!([bob()]), issue_with(&jane())])?;
    // A verdict whose facts name another user than the one resolved for the wire.
    v.resolved.insert("assignee".into(), json!("mallory"));
    let s = summary(&preview(&params, &v)?)?;
    let to = row(&s, "To").ok_or("no To row")?;
    assert!(to.starts_with("mallory"), "{to}");
    assert!(!to.contains("Bob (bob)"), "{to}");
    assert!(s.sentence.contains("mallory"), "{}", s.sentence);
    Ok(())
}

#[test]
fn assign_card_escapes_server_names_and_flags_mixed_script() -> TestResult {
    // A display name with a bidi override and a newline, and a username in two scripts
    // (Cyrillic `а` in a Latin name) that the agent named by its display name.
    let spoof = user("j\u{0430}doe", "JIRAUSER7", "Jane\u{202e} Doe\nX");
    let params = json!({"key": KEY, "assignee": "jane\u{202e} doe\nx"});
    let (_, v) = enrich(&params, &[json!([spoof]), issue_with(&jane())])?;
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    let m = preview(&params, &v)?;
    let s = summary(&m)?;
    for (name, value) in &s.rows {
        assert!(
            !value.contains('\u{202e}') && !value.contains('\n'),
            "{name}: {value}"
        );
    }
    let to = row(&s, "To").ok_or("no To row")?;
    assert!(to.contains("⟨U+202E⟩"), "{to}");
    assert!(!s.sentence.contains('\u{202e}'), "{}", s.sentence);
    // The resolved username is an identifier the param did not name: mixed-script Caution.
    assert!(
        m.warnings
            .iter()
            .any(|w| w.id == WarningId::MixedScript && w.text.contains("j\u{0430}doe")),
        "{:?}",
        m.warnings
    );
    Ok(())
}

#[test]
fn assignee_matches_percent_encoded_and_case() -> TestResult {
    let users = json!([
        jane(),
        user("jdoe@corp.example", "JIRAUSER5", "Jay Doe"),
        user("bbuilder", "JIRAUSER9", "Bob Builder"),
    ]);
    let current = issue_with(&Value::Null);
    for (asked, resolved) in [
        // §7.2 username comparison: case folding, percent-decoding, trimming.
        ("JDoe", "jdoe"),
        (" jdoe ", "jdoe"),
        ("jdoe%40corp.example", "jdoe@corp.example"),
        ("JDOE@CORP.EXAMPLE", "jdoe@corp.example"),
        // Then the key, exactly.
        ("JIRAUSER9", "bbuilder"),
        // Then a unique display name, case-insensitively.
        ("bob builder", "bbuilder"),
    ] {
        let params = json!({"key": KEY, "assignee": asked});
        let (_, v) = enrich(&params, &[users.clone(), current.clone()])?;
        assert_eq!(v.hold, Hold::Preview, "{asked}: {v:?}");
        assert_eq!(resolved_name(&v), Some(resolved), "{asked}");
        // The server's name is sent, never the agent's spelling of it.
        assert_eq!(wire(&params, &v)?, json!({"name": resolved}), "{asked}");
    }
    // A key is exact: another case is no key match (and no name or display name match).
    let params = json!({"key": KEY, "assignee": "jirauser9"});
    let (used, v) = enrich(&params, &[users.clone(), current.clone()])?;
    assert_eq!(v.hold, Hold::UnresolvedName, "{v:?}");
    assert_eq!(used, 1, "an unresolved assignee asks for nothing more");
    // `anonymous` never resolves through the username comparison.
    let params = json!({"key": KEY, "assignee": "anonymous"});
    let (_, v) = enrich(
        &params,
        &[json!([user("anonymous", "JIRAUSER0", "Anon")]), current],
    )?;
    assert_eq!(v.hold, Hold::UnresolvedName, "{v:?}");
    Ok(())
}

/// The first rule with any hit decides; two hits under one rule are ambiguous, never a pick.
#[test]
fn assignee_rules_never_pick_one_of_several() -> TestResult {
    let current = issue_with(&Value::Null);
    let unresolved = |v: &EnrichVerdict| v.unresolved.clone();
    // A name match wins over another user's display name.
    let params = json!({"key": KEY, "assignee": "bob"});
    let (_, v) = enrich(
        &params,
        &[
            json!([user("rob", "JIRAUSER3", "bob"), bob()]),
            current.clone(),
        ],
    )?;
    assert_eq!(resolved_name(&v), Some("bob"));
    // Two users the username comparison both matches (a server that lists them): ambiguous.
    let (_, v) = enrich(
        &params,
        &[
            json!([bob(), user("BOB", "JIRAUSER4", "Bobby")]),
            current.clone(),
        ],
    )?;
    assert_eq!(v.hold, Hold::UnresolvedName);
    assert_eq!(
        unresolved(&v),
        Some((
            "assignee".into(),
            "bob".into(),
            2,
            vec!["bob".into(), "BOB".into()]
        ))
    );
    // Two users with one display name: ambiguous, the candidates are their usernames.
    let params = json!({"key": KEY, "assignee": "Jane Doe"});
    let (_, v) = enrich(
        &params,
        &[
            json!([
                user("jdoe1", "JIRAUSER11", "Jane Doe"),
                user("jdoe2", "JIRAUSER12", "jane doe"),
                bob()
            ]),
            current.clone(),
        ],
    )?;
    assert_eq!(
        unresolved(&v),
        Some((
            "assignee".into(),
            "Jane Doe".into(),
            2,
            vec!["jdoe1".into(), "jdoe2".into()]
        ))
    );
    // No match: every listed username is a candidate, at most ten.
    let many: Vec<Value> = (0..14)
        .map(|n| user(&format!("u{n}"), &format!("K{n}"), &format!("User {n}")))
        .collect();
    let params = json!({"key": KEY, "assignee": "nobody"});
    let (_, v) = enrich(&params, &[Value::Array(many), current.clone()])?;
    let (_, _, n, candidates) = v.unresolved.clone().ok_or("not unresolved")?;
    assert_eq!(n, 0);
    assert_eq!(candidates.len(), 10);
    assert_eq!(candidates[0], "u0");
    // A resolved user without a usable `name` cannot be sent: fail closed.
    let (_, v) = enrich(
        &params,
        &[
            json!([{"key": "K1", "displayName": "nobody"}]),
            current.clone(),
        ],
    )?;
    assert_eq!(v.hold, Hold::EnrichmentError, "{v:?}");
    // Answers of the wrong shape fail closed too.
    let (_, v) = enrich(&params, &[json!({"users": []}), current])?;
    assert_eq!(v.hold, Hold::EnrichmentError, "{v:?}");
    let params = json!({"key": KEY, "assignee": "bob"});
    let (_, v) = enrich(&params, &[json!([bob()]), json!({"key": KEY})])?;
    assert_eq!(v.hold, Hold::EnrichmentError, "no fields.assignee: {v:?}");
    let (_, v) = enrich(
        &params,
        &[json!([bob()]), issue_with(&json!({"name": "jdoe"}))],
    )?;
    assert_eq!(
        v.hold,
        Hold::EnrichmentError,
        "an assignee without a key: {v:?}"
    );
    Ok(())
}

#[test]
fn assign_executor_needs_the_verdict_for_its_params() -> TestResult {
    let params = json!({"key": KEY, "assignee": "bob"});
    assert_eq!(exec(&params, None), Err(ExecError::EnrichmentRequired));
    let unassign = json!({"key": KEY, "assignee": null});
    assert_eq!(exec(&unassign, None), Err(ExecError::EnrichmentRequired));
    // A verdict for the other kind of assignment renders nothing (never a stale pick).
    let (_, named) = enrich(&params, &[json!([bob()]), issue_with(&jane())])?;
    let (_, nobody) = enrich(&unassign, &[issue_with(&jane())])?;
    assert_eq!(
        exec(&unassign, Some(&named)),
        Err(ExecError::EnrichmentRequired)
    );
    assert_eq!(
        exec(&params, Some(&nobody)),
        Err(ExecError::EnrichmentRequired)
    );
    // An unresolved verdict renders nothing either.
    let asked = json!({"key": KEY, "assignee": "nobody"});
    let (_, v) = enrich(&asked, &[json!([bob()])])?;
    assert_eq!(exec(&asked, Some(&v)), Err(ExecError::EnrichmentRequired));
    Ok(())
}

fn stale(baseline: &Value, answer: &Value) -> Result<StaleVerdict, TestError> {
    let rule = op_table()
        .get(ASSIGN)
        .and_then(|i| i.stale_check)
        .ok_or("no stale rule")?;
    let params = json!({"key": KEY, "assignee": "bob"});
    let ctx = StaleCtx {
        spec: spec()?,
        params: &params,
        baseline,
    };
    let calls = (rule.plan)(&ctx);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].endpoint_template, "/rest/api/2/issue/{key}");
    assert_eq!(
        calls[0].query,
        [("fields".to_owned(), "assignee".to_owned())]
    );
    Ok((rule.judge)(&ctx, std::slice::from_ref(answer)))
}

#[test]
fn assign_stale_rule_compares_the_assignee_key() -> TestResult {
    let was_jane = json!({"assignee_key": "JIRAUSER1", "assignee_name": "jdoe"});
    let was_nobody = json!({"assignee_key": null, "assignee_name": null});
    assert_eq!(
        stale(&was_jane, &issue_with(&jane()))?,
        StaleVerdict::Unchanged
    );
    // A rename keeps the key: unchanged.
    assert_eq!(
        stale(
            &was_jane,
            &issue_with(&user("jane.doe", "JIRAUSER1", "Jane Doe"))
        )?,
        StaleVerdict::Unchanged
    );
    assert_eq!(
        stale(&was_nobody, &issue_with(&Value::Null))?,
        StaleVerdict::Unchanged
    );
    let changed = StaleVerdict::Changed {
        delta: "assignee changed since review".to_owned(),
    };
    assert_eq!(stale(&was_jane, &issue_with(&bob()))?, changed);
    assert_eq!(stale(&was_jane, &issue_with(&Value::Null))?, changed);
    assert_eq!(stale(&was_nobody, &issue_with(&jane()))?, changed);
    // Never `Unchanged` on an answer it cannot read.
    for unreadable in [
        json!({"key": KEY}),
        json!({"fields": {}}),
        issue_with(&json!({"name": "jdoe"})),
    ] {
        assert!(
            matches!(stale(&was_jane, &unreadable)?, StaleVerdict::Changed { .. }),
            "{unreadable}"
        );
    }
    assert!(matches!(
        stale(&json!({}), &issue_with(&jane()))?,
        StaleVerdict::Changed { .. }
    ));
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

async fn queued(h: &Harness, params: Value) -> Result<String, TestError> {
    let env = h.submit(ASSIGN, params).await;
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

const ASSIGNEE_PUT: &str = "/rest/api/2/issue/ABC-1/assignee";

async fn mount_put(mock: &MockDc) {
    Mock::given(method("PUT"))
        .and(path(mock.path(ASSIGNEE_PUT)))
        .respond_with(mock.response(204))
        .mount(mock.server())
        .await;
}

async fn puts(mock: &MockDc) -> Vec<wiremock::Request> {
    let full = mock.path(ASSIGNEE_PUT);
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "PUT" && r.url.path() == full)
        .collect()
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

fn card_rows(p: &Preview) -> Result<(String, Vec<(String, String)>), TestError> {
    match &p.body {
        PreviewBody::WriteSummary { sentence, rows, .. } => Ok((sentence.clone(), rows.clone())),
        other => Err(format!("not the assign card: {other:?}").into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn assign_happy_path() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_assignable(mock, &json!([jane(), bob()])).await;
    mount_issue(mock, KEY, &issue_with(&bob())).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_put(mock).await;
    let id = queued(&h, json!({"key": KEY, "assignee": "jdoe"})).await?;
    let p = opened(&h, &id)?;
    let (sentence, rows) = card_rows(&p)?;
    assert_eq!(sentence, "Assign ABC-1 to Jane Doe (jdoe)");
    assert!(
        rows.contains(&("From".into(), "Bob (bob)".into())),
        "{rows:?}"
    );
    assert!(p.approvable);
    // L06: the issue key is a read-only target; the assignee can be edited.
    let form = p.edit_form.as_ref().ok_or("no edit form")?;
    let input = |name: &str| form.inputs.iter().find(|i| i.path == name);
    assert!(input("key").is_some_and(|i| i.read_only));
    assert!(input("assignee").is_some_and(|i| !i.read_only));
    // The resolution GET carries the agent's value and the issue key, never server data.
    let searches = gets_on(mock, ASSIGNABLE).await;
    assert_eq!(searches.len(), 1);
    assert_eq!(query(&searches[0], "username").as_deref(), Some("jdoe"));
    assert_eq!(query(&searches[0], "issueKey").as_deref(), Some(KEY));
    assert_eq!(query(&searches[0], "maxResults").as_deref(), Some("50"));

    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(env.data, Some(json!({ "receipt": {} })));
    let sent = puts(mock).await;
    assert_eq!(sent.len(), 1);
    let body: Value = serde_json::from_slice(&sent[0].body)?;
    assert_eq!(body, json!({"name": "jdoe"}));
    // Resolve, enrich, then the identity call and the assignee stale check (L29).
    assert_eq!(
        purposes(&h, &id).await?,
        ["resolve", "enrich", "stale_check", "stale_check"]
    );
    let gets: Vec<String> = records(&h, &id, EventType::PREVIEW_FETCH)
        .await?
        .iter()
        .filter_map(|r| r["path"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(gets.len(), 4, "{gets:?}");
    assert!(gets[2].ends_with("/rest/api/2/myself"), "{gets:?}");
    assert!(
        gets[3].ends_with("/rest/api/2/issue/ABC-1?fields=assignee"),
        "{gets:?}"
    );
    assert!(
        gets[0].contains("/rest/api/2/user/assignable/search?"),
        "{gets:?}"
    );
    assert_eq!(
        gets[1], gets[3],
        "the stale check reads what enrichment read"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn assign_null_unassigns_without_resolution() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_assignable(mock, &json!([jane()])).await;
    mount_issue(mock, KEY, &issue_with(&jane())).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_put(mock).await;
    let id = queued(&h, json!({"key": KEY, "assignee": null})).await?;
    let p = opened(&h, &id)?;
    let (sentence, rows) = card_rows(&p)?;
    assert_eq!(sentence, "Unassign ABC-1");
    assert!(
        rows.contains(&("From".into(), "Jane Doe (jdoe)".into())),
        "{rows:?}"
    );
    assert!(
        rows.contains(&("To".into(), "(unassigned)".into())),
        "{rows:?}"
    );
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let sent = puts(mock).await;
    assert_eq!(sent.len(), 1);
    let body: Value = serde_json::from_slice(&sent[0].body)?;
    assert_eq!(body, json!({"name": null}));
    assert!(
        gets_on(mock, ASSIGNABLE).await.is_empty(),
        "no assignable search"
    );
    assert_eq!(
        purposes(&h, &id).await?,
        ["enrich", "stale_check", "stale_check"]
    );
    Ok(())
}

async fn assert_unresolved(
    h: &Harness,
    id: &str,
    value: &str,
    matches: u64,
    candidates: &[&str],
) -> TestResult {
    match opened(h, id)?.body {
        PreviewBody::UnresolvedName {
            param,
            value: v,
            matches: n,
            candidates: c,
        } => {
            assert_eq!(
                (param.as_str(), v.as_str(), n),
                ("assignee", value, matches)
            );
            assert_eq!(c, candidates);
        }
        other => return Err(format!("not the unresolved-name card: {other:?}").into()),
    }
    not_approvable(h.approver().approve_unopened(id))?;
    assert!(records(h, id, EventType::WRITE_APPROVED).await?.is_empty());
    // Nothing after the resolution GET: the current assignee is not read.
    assert_eq!(purposes(h, id).await?, ["resolve"]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i35_assignee_no_match_and_ambiguous() -> TestResult {
    // No match: the search lists nobody.
    let h = Harness::jira().await?;
    mount_assignable(jira(&h)?, &json!([])).await;
    mount_issue(jira(&h)?, KEY, &issue_with(&jane())).await;
    let id = queued(&h, json!({"key": KEY, "assignee": "jdoee"})).await?;
    assert_unresolved(&h, &id, "jdoee", 0, &[]).await?;
    h.approver()
        .deny_with(
            &id,
            "no such user",
            DenyDetails::ResolutionFailed {
                include_candidates: false,
            },
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Denied);
    assert_eq!(code(&env), "resolution_failed");
    assert_eq!(detail(&env, "param"), "assignee");
    assert_eq!(detail(&env, "value"), "jdoee");
    assert_eq!(
        detail(&env, "message"),
        "no assignable user 'jdoee' for ABC-1"
    );
    assert_eq!(detail(&env, "candidates"), Value::Null);

    // Ambiguous: two users share the display name; no username matches.
    for include_candidates in [false, true] {
        let h = Harness::jira().await?;
        let mock = jira(&h)?;
        mount_assignable(
            mock,
            &json!([
                user("jdoe1", "JIRAUSER11", "Jane Doe"),
                user("jdoe2", "JIRAUSER12", "Jane Doe")
            ]),
        )
        .await;
        mount_issue(mock, KEY, &issue_with(&Value::Null)).await;
        let id = queued(&h, json!({"key": KEY, "assignee": "Jane Doe"})).await?;
        assert_unresolved(&h, &id, "Jane Doe", 2, &["jdoe1", "jdoe2"]).await?;
        h.approver()
            .deny_with(
                &id,
                "which Jane?",
                DenyDetails::ResolutionFailed { include_candidates },
            )
            .map_err(de)?;
        let env = h.await_(&id, 5000).await;
        assert_eq!(env.status, Status::Denied);
        assert_eq!(code(&env), "resolution_failed");
        assert_eq!(
            detail(&env, "message"),
            "no assignable user 'Jane Doe' for ABC-1"
        );
        let candidates = if include_candidates {
            json!(["jdoe1", "jdoe2"])
        } else {
            Value::Null
        };
        assert_eq!(detail(&env, "candidates"), candidates);
        assert!(puts(mock).await.is_empty(), "nothing was sent");
    }
    Ok(())
}

/// §5.4 step 4: `assignee` is an enrichment key: an edit resolves again and the new revision
/// sends the newly resolved user.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn assign_edit_resolves_again() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_assignable(mock, &json!([jane(), bob()])).await;
    mount_issue(mock, KEY, &issue_with(&Value::Null)).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_put(mock).await;
    let id = queued(&h, json!({"key": KEY, "assignee": "nobody"})).await?;
    let rev = h.approver().rev(&id).map_err(de)?;
    let mut set = Map::new();
    set.insert("assignee".into(), json!("bob"));
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
    assert!(item.approvable);
    assert_eq!(purposes(&h, &id).await?, ["resolve", "resolve", "enrich"]);
    let (sentence, _) = card_rows(&opened(&h, &id)?)?;
    assert_eq!(sentence, "Assign ABC-1 to Bob (bob)");
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let sent = puts(mock).await;
    let body: Value = serde_json::from_slice(&sent.first().ok_or("no PUT")?.body)?;
    assert_eq!(body, json!({"name": "bob"}));
    Ok(())
}

/// The issue GET answers `first` once, then `then` on every later GET.
async fn issue_answers(mock: &MockDc, first: &Value, then: &Value) {
    for (priority, body, once) in [(1, first, true), (2, then, false)] {
        let m = Mock::given(method("GET"))
            .and(path(mock.path(&issue_path(KEY))))
            .respond_with(
                mock.response(200)
                    .set_body_raw(body.to_string(), "application/json"),
            )
            .with_priority(priority);
        let m = if once { m.up_to_n_times(1) } else { m };
        m.mount(mock.server()).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn assign_stale_when_assignee_changed() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_assignable(mock, &json!([jane(), bob()])).await;
    // Reviewed while Jane is the assignee; Bob took the issue before the approval.
    issue_answers(mock, &issue_with(&jane()), &issue_with(&bob())).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_put(mock).await;
    let id = queued(&h, json!({"key": KEY, "assignee": "jdoe"})).await?;
    let (_, rows) = card_rows(&opened(&h, &id)?)?;
    assert!(
        rows.contains(&("From".into(), "Jane Doe (jdoe)".into())),
        "{rows:?}"
    );
    let rev = h.approver().rev(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    let item = item_after(&h, &id, rev.counter + 1).await?;
    assert!(item.stale, "{item:?}");
    // The refresh (both GETs again) ends in a new revision.
    let mut refreshed = false;
    for _ in 0..400 {
        let p = purposes(&h, &id).await?;
        if p.iter().filter(|p| *p == "refresh").count() == 2
            && h.approver().item(&id).is_some_and(|i| i.approvable)
        {
            refreshed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(refreshed, "never refreshed");
    let stale = records(&h, &id, EventType::WRITE_STALE).await?;
    assert_eq!(
        stale,
        [json!({"reason": "changed", "class": null,
                "delta": "assignee changed since review"})]
    );
    assert!(puts(mock).await.is_empty(), "nothing was sent");
    // Refreshed: the enrichment ran again and the card shows the new current assignee.
    assert_eq!(
        purposes(&h, &id).await?,
        [
            "resolve",
            "enrich",
            "stale_check",
            "stale_check",
            "refresh",
            "refresh"
        ]
    );
    let (_, rows) = card_rows(&opened(&h, &id)?)?;
    assert!(
        rows.contains(&("From".into(), "Bob (bob)".into())),
        "{rows:?}"
    );
    Ok(())
}
