#![cfg(feature = "testing")]
//! `jira.issue.assign` (Task 15, PD-52): the assignable-user resolution under the username
//! comparison (§7.2), the unassign body, the assignee stale rule (§5.4 step 5), the from → to
//! card and the unresolved or ambiguous assignee (I-35 assignable user).
//!
//! `jira.issuelink.create` (Task 16, PD-53): the link-type resolution, the link sentence in the
//! direction Jira reads the body, the declared empty success (I-25), and the unresolved-name
//! table over every Jira resolution kind (I-35).

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
use atlas_duck_core::{
    BatchFailure, BatchItem, Confirm, DecisionError, DecisionOutcome, DenyDetails, Edits, QueueItem,
};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_preview::{ConstructList, Preview, PreviewBody, WarningId};
use common::jira::{
    PROJECTS_PATH, gets_on, issue_path, issuetypes_path, mount_assignable, mount_issue,
    mount_link_types, query,
};
use common::{TestError, TestResult, code, de, detail, exit, request_id};
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
    enrich_as(ASSIGN, params, answers)
}

fn enrich_as(
    op: &str,
    params: &Value,
    answers: &[Value],
) -> Result<(usize, EnrichVerdict), TestError> {
    let rule = op_table()
        .get(op)
        .and_then(|i| i.enrich)
        .ok_or("no enrich rule")?;
    let ctx = EnrichCtx {
        spec: atlas_duck_registry::get(op).ok_or("no spec")?,
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
    exec_as(ASSIGN, params, verdict)
}

fn exec_as(
    op: &str,
    params: &Value,
    verdict: Option<&EnrichVerdict>,
) -> Result<ExecPlan, ExecError> {
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
    preview_as(ASSIGN, params, verdict)
}

fn preview_as(
    op: &str,
    params: &Value,
    verdict: &EnrichVerdict,
) -> Result<PreviewModel, TestError> {
    let reqs = match exec_as(op, params, Some(verdict)) {
        Ok(ExecPlan::Write(r)) => r,
        other => return Err(format!("not a write: {other:?}").into()),
    };
    let imp = op_table().get(op).ok_or("no OpImpl")?;
    let ctx = PreviewCtx {
        spec: atlas_duck_registry::get(op).ok_or("no spec")?,
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
    // The username leads (T15 review I1): it is what is sent.
    assert_eq!(s.sentence, "Assign ABC-1 to bob (Bob)");
    assert_eq!(row(&s, "From"), Some("jdoe (Jane Doe)"));
    assert_eq!(row(&s, "To"), Some("bob (Bob)"));
    assert_eq!(row(&s, "Sent as user name"), Some("bob"));
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
    assert_eq!(row(&s, "From"), Some("jdoe (Jane Doe)"));
    assert_eq!(row(&s, "To"), Some("(unassigned)"));
    assert_eq!(
        row(&s, "Sent as user name"),
        None,
        "an unassign sends no name"
    );

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
    assert!(!to.contains("bob (Bob)"), "{to}");
    assert!(s.sentence.contains("mallory"), "{}", s.sentence);
    assert_eq!(row(&s, "Sent as user name"), Some("mallory"));
    Ok(())
}

/// T15 review I1: a display name padded with invisible characters (each shown as an 8-char
/// `⟨U+XXXX⟩`) never pushes the sent username out of the sentence or the `To` row; the display
/// name shows at most 64 escaped chars, never a split escape, the cut bytes counted, and its
/// invisible characters raise the Caution although the request carries none.
#[test]
fn assign_card_keeps_the_sent_username_in_view() -> TestResult {
    let padded = format!("Jane Doe (jdoe){}", "\u{2060}".repeat(50));
    let params = json!({"key": KEY, "assignee": "mallory"});
    let (_, v) = enrich(
        &params,
        &[
            json!([user("mallory", "JIRAUSER10200", &padded)]),
            issue_with(&Value::Null),
        ],
    )?;
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    assert_eq!(wire(&params, &v)?, json!({"name": "mallory"}));
    let m = preview(&params, &v)?;
    let s = summary(&m)?;
    assert!(
        s.sentence.starts_with("Assign ABC-1 to mallory ("),
        "{}",
        s.sentence
    );
    assert_eq!(row(&s, "Sent as user name"), Some("mallory"));
    let to = row(&s, "To").ok_or("no To row")?;
    let shown = to
        .strip_prefix("mallory (")
        .and_then(|t| t.strip_suffix("…)"))
        .ok_or_else(|| format!("not `mallory (<display name>…)`: {to}"))?;
    // "Jane Doe (jdoe)" and six escapes are 63 chars; the seventh would pass 64.
    assert_eq!(
        shown,
        format!("Jane Doe (jdoe){}", "⟨U+2060⟩".repeat(6)),
        "{to}"
    );
    assert!(
        s.sentence.ends_with(&format!("{shown}…)")),
        "{}",
        s.sentence
    );
    // The 44 word joiners cut (3 bytes each), counted once.
    assert_eq!(m.header.hidden_in_preview_bytes, 44 * 3);
    assert_eq!(m.header.other_invisible, 50);
    assert!(
        m.warnings.iter().any(|w| w.id == WarningId::OtherInvisible
            && w.text == "contains 50 other invisible characters"),
        "{:?}",
        m.warnings
    );
    // The current assignee's display name: the same cap and count on the `From` row.
    let (_, v) = enrich(
        &params,
        &[
            json!([user("mallory", "JIRAUSER10200", "Mallory")]),
            issue_with(&user("jdoe", "JIRAUSER1", &padded)),
        ],
    )?;
    let m = preview(&params, &v)?;
    let s = summary(&m)?;
    assert_eq!(s.sentence, "Assign ABC-1 to mallory (Mallory)");
    let from = row(&s, "From").ok_or("no From row")?;
    assert!(
        from.starts_with("jdoe (Jane Doe (jdoe)⟨U+2060⟩") && from.ends_with("…)"),
        "{from}"
    );
    assert_eq!(m.header.other_invisible, 50);
    assert_eq!(
        m.warnings
            .iter()
            .filter(|w| w.id == WarningId::OtherInvisible)
            .count(),
        1,
        "{:?}",
        m.warnings
    );
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
    // The display name's bidi override counts although the request has none (T15 review I1).
    assert_eq!(m.header.bidi_controls, 1);
    assert!(
        m.warnings.iter().any(|w| w.id == WarningId::BidiControls
            && w.text == "contains 1 bidirectional control characters"),
        "{:?}",
        m.warnings
    );
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
    // An empty or blank value names nobody, not a user with an empty key or display name, and
    // neither does `-1` (Jira's automatic assignee, T15 review M2): unresolved without a search
    // (T15 review M4: an empty `username=` may list every assignable user).
    for blank in ["", "  ", "-1", " -1 "] {
        let params = json!({"key": KEY, "assignee": blank});
        let (used, v) = enrich(
            &params,
            &[
                json!([{"name": "x", "key": blank, "displayName": blank}]),
                current.clone(),
            ],
        )?;
        assert_eq!(v.hold, Hold::UnresolvedName, "{blank:?}: {v:?}");
        assert_eq!(used, 0, "{blank:?}: no search");
        assert_eq!(
            unresolved(&v),
            Some(("assignee".into(), blank.into(), 0, Vec::new())),
            "{blank:?}"
        );
    }
    // A user named `-1` never resolves (by key or display name) and is never a candidate.
    let minus = json!([user("-1", "JIRAUSER99", "Minus"), bob()]);
    for asked in ["Minus", "JIRAUSER99"] {
        let params = json!({"key": KEY, "assignee": asked});
        let (used, v) = enrich(&params, &[minus.clone(), current.clone()])?;
        assert_eq!(
            unresolved(&v),
            Some(("assignee".into(), asked.into(), 0, vec!["bob".into()])),
            "{asked}: {v:?}"
        );
        assert_eq!(used, 1);
    }
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

/// T15 review M1: a full page (as many users as the search asked for) may leave out the user the
/// agent named, or a namesake: only the username rule resolves there; the key and display-name
/// rules end unresolved with their hits as the candidates.
#[test]
fn assignee_full_page_resolves_by_username_only() -> TestResult {
    let current = issue_with(&Value::Null);
    let mut page: Vec<Value> = (0..49)
        .map(|n| user(&format!("alx{n}"), &format!("K{n}"), &format!("Alex {n}")))
        .collect();
    page.push(user("al.jones", "JIRAUSER50", "Al"));
    let full = Value::Array(page.clone());
    for asked in ["al", "JIRAUSER50"] {
        let params = json!({"key": KEY, "assignee": asked});
        let (used, v) = enrich(&params, &[full.clone(), current.clone()])?;
        assert_eq!(v.hold, Hold::UnresolvedName, "{asked}: {v:?}");
        assert_eq!(used, 1, "{asked}");
        assert_eq!(
            v.unresolved,
            Some(("assignee".into(), asked.into(), 1, vec!["al.jones".into()])),
            "{asked}"
        );
    }
    // The username the hint names resolves on the same page.
    let params = json!({"key": KEY, "assignee": "al.jones"});
    let (_, v) = enrich(&params, &[full, current.clone()])?;
    assert_eq!(resolved_name(&v), Some("al.jones"), "{v:?}");
    // One user fewer is not a full page: the display name resolves.
    page.remove(0);
    let params = json!({"key": KEY, "assignee": "al"});
    let (_, v) = enrich(&params, &[Value::Array(page), current])?;
    assert_eq!(resolved_name(&v), Some("al.jones"), "{v:?}");
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
    // Only a `Preview` verdict renders: the same resolved name under any other hold renders
    // nothing (T15 review M6).
    assert!(exec(&params, Some(&named)).is_ok());
    for hold in [
        Hold::EnrichmentError,
        Hold::Collision,
        Hold::UnresolvedName,
        Hold::Conflict,
        Hold::IdentityMismatch,
    ] {
        let mut held = named.clone();
        held.hold = hold;
        assert_eq!(
            exec(&params, Some(&held)),
            Err(ExecError::EnrichmentRequired),
            "{hold:?}"
        );
    }
    // `-1` (Jira's automatic assignee) is never sent, whatever a verdict says (T15 review M2).
    let mut minus = named.clone();
    minus.resolved.insert("assignee".into(), json!("-1"));
    assert_eq!(
        exec(&params, Some(&minus)),
        Err(ExecError::EnrichmentRequired)
    );
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
    queued_as(h, ASSIGN, params).await
}

async fn queued_as(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
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
    assert_eq!(sentence, "Assign ABC-1 to jdoe (Jane Doe)");
    assert!(
        rows.contains(&("From".into(), "bob (Bob)".into())),
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
        rows.contains(&("From".into(), "jdoe (Jane Doe)".into())),
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

/// T15 review M2/M4: a blank value and `-1` (Jira's automatic assignee) name nobody: the
/// unresolved-name card without any GET (an empty `username=` may list every assignable user).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i35_assignee_blank_or_automatic_never_searches() -> TestResult {
    for value in ["", "-1"] {
        let h = Harness::jira().await?;
        let mock = jira(&h)?;
        mount_assignable(mock, &json!([jane(), user("-1", "JIRAUSER99", "Minus")])).await;
        mount_issue(mock, KEY, &issue_with(&jane())).await;
        mount_put(mock).await;
        let id = queued(&h, json!({"key": KEY, "assignee": value})).await?;
        match opened(&h, &id)?.body {
            PreviewBody::UnresolvedName {
                param,
                value: v,
                matches,
                candidates,
            } => {
                assert_eq!(
                    (param.as_str(), v.as_str(), matches),
                    ("assignee", value, 0)
                );
                assert!(candidates.is_empty(), "{candidates:?}");
            }
            other => {
                return Err(format!("{value:?}: not the unresolved-name card: {other:?}").into());
            }
        }
        not_approvable(h.approver().approve_unopened(&id))?;
        assert!(purposes(&h, &id).await?.is_empty(), "{value:?}: no GET");
        assert!(gets_on(mock, ASSIGNABLE).await.is_empty(), "{value:?}");
        assert!(
            gets_on(mock, &issue_path(KEY)).await.is_empty(),
            "{value:?}"
        );
        assert!(puts(mock).await.is_empty(), "{value:?}: nothing was sent");
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
    assert_eq!(sentence, "Assign ABC-1 to bob (Bob)");
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
        rows.contains(&("From".into(), "jdoe (Jane Doe)".into())),
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
        rows.contains(&("From".into(), "bob (Bob)".into())),
        "{rows:?}"
    );
    Ok(())
}

// ---- jira.issuelink.create (Task 16) --------------------------------------------------------

const LINK: &str = "jira.issuelink.create";
const LINK_POST: &str = "/rest/api/2/issueLink";
const LINK_TYPES: &str = "/rest/api/2/issueLinkType";

fn link_type(id: &str, name: &str, inward: &str, outward: &str) -> Value {
    json!({
        "id": id, "name": name, "inward": inward, "outward": outward,
        "self": format!("https://jira.corp.example/rest/api/2/issueLinkType/{id}")
    })
}

/// Jira's default link types.
fn default_types() -> Vec<Value> {
    vec![
        link_type("10000", "Blocks", "is blocked by", "blocks"),
        link_type("10001", "Cloners", "is cloned by", "clones"),
        link_type("10002", "Duplicate", "is duplicated by", "duplicates"),
        link_type("10003", "Relates", "relates to", "relates to"),
    ]
}

/// The `GET /rest/api/2/issueLinkType` answer listing `types`.
fn types_answer(types: Vec<Value>) -> Value {
    json!({ "issueLinkTypes": types })
}

fn link_params(kind: &str) -> Value {
    json!({"type": kind, "inward": "ABC-124", "outward": "ABC-123"})
}

/// The one POST a resolved link renders, as JSON.
fn link_wire(params: &Value, verdict: &EnrichVerdict) -> Result<Value, TestError> {
    match exec_as(LINK, params, Some(verdict)) {
        Ok(ExecPlan::Write(reqs)) => {
            assert_eq!(reqs.len(), 1);
            let r = &reqs[0];
            assert_eq!(r.method, "POST");
            assert!(r.resolved_url.ends_with(LINK_POST), "{}", r.resolved_url);
            assert_eq!(r.content_type.as_deref(), Some("application/json"));
            Ok(serde_json::from_slice(&r.body)?)
        }
        other => Err(format!("not a write: {other:?}").into()),
    }
}

struct LinkCard {
    sentence: String,
    rows: Vec<(String, String)>,
    constructs: Option<ConstructList>,
}

fn link_card(m: &PreviewModel) -> Result<LinkCard, TestError> {
    match &m.body {
        PreviewBody::WriteSummary {
            sentence,
            rows,
            constructs,
            requests,
        } => {
            assert_eq!(requests.len(), 1, "the exact request list stays (inv. 4)");
            Ok(LinkCard {
                sentence: sentence.clone(),
                rows: rows.clone(),
                constructs: constructs.clone(),
            })
        }
        other => Err(format!("not a write summary: {other:?}").into()),
    }
}

fn link_row<'a>(c: &'a LinkCard, name: &str) -> Option<&'a str> {
    c.rows
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// PD-53 + the Jira 9.12 REST reference ("Link issues": the link goes "from the first issue to
/// the second issue using the outward description"; the first issue is `inwardIssue`): the
/// `inward` param is the issue the outward phrase starts from. The params map onto the fields of
/// the same names, and the phrase that named the type never changes the direction.
#[test]
fn issuelink_body_and_sentence() -> TestResult {
    let types = types_answer(default_types());
    let params = link_params("blocks");
    let (used, v) = enrich_as(LINK, &params, std::slice::from_ref(&types))?;
    assert_eq!(used, 1, "one GET: the link types");
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    let want = json!({
        "type": {"name": "Blocks"},
        "inwardIssue": {"key": "ABC-124"},
        "outwardIssue": {"key": "ABC-123"}
    });
    assert_eq!(link_wire(&params, &v)?, want);
    let card = link_card(&preview_as(LINK, &params, &v)?)?;
    assert_eq!(card.sentence, "ABC-124 blocks ABC-123 (Blocks)");
    // What Jira shows on the other issue: the same link read from its other end.
    assert_eq!(
        link_row(&card, "Reads as"),
        Some("ABC-123 is blocked by ABC-124")
    );
    assert_eq!(link_row(&card, "Link type"), Some("Blocks (10000)"));
    assert_eq!(link_row(&card, "Sent as link type name"), Some("Blocks"));
    assert_eq!(
        link_row(&card, "Inward issue (inwardIssue)"),
        Some("ABC-124")
    );
    assert_eq!(
        link_row(&card, "Outward issue (outwardIssue)"),
        Some("ABC-123")
    );
    assert_eq!(card.constructs, None, "no comment, no wiki text");

    // The same type by its name (any case), its id and its inward phrase: the same request and
    // the same sentence.
    for named in [
        "Blocks",
        "BLOCKS",
        "10000",
        "is blocked by",
        "Is Blocked By",
    ] {
        let params = link_params(named);
        let (_, v) = enrich_as(LINK, &params, std::slice::from_ref(&types))?;
        assert_eq!(v.hold, Hold::Preview, "{named}: {v:?}");
        assert_eq!(link_wire(&params, &v)?, want, "{named}");
        let card = link_card(&preview_as(LINK, &params, &v)?)?;
        assert_eq!(card.sentence, "ABC-124 blocks ABC-123 (Blocks)", "{named}");
    }

    // A comment is sent verbatim as wiki markup (PD-42) and its constructs are listed (PD-47).
    let wiki = "Linked: {code}x{code} for [~jdoe], see [docs|https://docs.example/x]";
    let mut params = link_params("duplicates");
    params["comment"] = json!(wiki);
    let (_, v) = enrich_as(LINK, &params, std::slice::from_ref(&types))?;
    assert_eq!(
        link_wire(&params, &v)?,
        json!({
            "type": {"name": "Duplicate"},
            "inwardIssue": {"key": "ABC-124"},
            "outwardIssue": {"key": "ABC-123"},
            "comment": {"body": wiki}
        })
    );
    let card = link_card(&preview_as(LINK, &params, &v)?)?;
    assert_eq!(card.sentence, "ABC-124 duplicates ABC-123 (Duplicate)");
    assert_eq!(
        link_row(&card, "Reads as"),
        Some("ABC-123 is duplicated by ABC-124")
    );
    let comment = link_row(&card, "Comment").ok_or("no comment row")?;
    assert!(comment.contains("Linked:"), "{comment}");
    let constructs = card.constructs.ok_or("no construct list")?;
    assert_eq!(constructs.mentions, ["jdoe"]);
    assert!(
        constructs.macros.iter().any(|m| m == "code"),
        "{constructs:?}"
    );
    assert!(
        constructs
            .links
            .iter()
            .any(|l| l == "https://docs.example/x"),
        "{constructs:?}"
    );
    Ok(())
}

/// I-35 link type (PD-53, tightened): a value matches a type by its id, its name, its outward or
/// its inward phrase (case-insensitively, the id exactly); more than one type matched in any way
/// is ambiguous, never a pick; no match lists the type names (≤ 10). The name the request sends
/// must name exactly one type, and a blank value names none (no GET).
#[test]
fn i35_link_type_no_match_and_ambiguous() -> TestResult {
    let one = |kind: &str, types: Vec<Value>| -> Result<(usize, EnrichVerdict), TestError> {
        enrich_as(LINK, &link_params(kind), &[types_answer(types)])
    };
    let unresolved = |kind: &str, n: u64, candidates: &[&str]| {
        Some((
            "type".to_owned(),
            kind.to_owned(),
            n,
            candidates
                .iter()
                .map(|c| (*c).to_owned())
                .collect::<Vec<_>>(),
        ))
    };
    // Two types whose names differ only in case: ambiguous on the name.
    let twins = vec![
        link_type("10003", "Relates", "relates to", "relates to"),
        link_type("10004", "relates", "is related to", "relates"),
        link_type("10000", "Blocks", "is blocked by", "blocks"),
    ];
    let (_, v) = one("Relates", twins.clone())?;
    assert_eq!(v.hold, Hold::UnresolvedName, "{v:?}");
    assert_eq!(
        v.unresolved,
        unresolved("Relates", 2, &["Relates", "relates"])
    );
    assert_eq!(
        exec_as(LINK, &link_params("Relates"), Some(&v)),
        Err(ExecError::EnrichmentRequired)
    );
    // A name of one type that is the outward phrase of another: ambiguous too.
    let (_, v) = one("relates", twins.clone())?;
    assert_eq!(
        v.unresolved,
        unresolved("relates", 2, &["Relates", "relates"])
    );
    let cross = vec![
        link_type("10010", "Problem/Incident", "is caused by", "causes"),
        link_type("10011", "Causes", "follows", "leads to"),
    ];
    let (_, v) = one("causes", cross)?;
    assert_eq!(
        v.unresolved,
        unresolved("causes", 2, &["Problem/Incident", "Causes"])
    );
    // An inward phrase two types share.
    let shared = vec![
        link_type("10020", "Depends", "is needed by", "depends on"),
        link_type("10021", "Requires", "is needed by", "requires"),
    ];
    let (_, v) = one("is needed by", shared)?;
    assert_eq!(
        v.unresolved,
        unresolved("is needed by", 2, &["Depends", "Requires"])
    );
    // No match: every type name is a candidate.
    let (used, v) = one("zzz", default_types())?;
    assert_eq!(used, 1);
    assert_eq!(
        v.unresolved,
        unresolved("zzz", 0, &["Blocks", "Cloners", "Duplicate", "Relates"])
    );
    // ... at most ten of them.
    let many: Vec<Value> = (0..12)
        .map(|n| link_type(&format!("{}", 11_000 + n), &format!("T{n}"), "in", "out"))
        .collect();
    let (_, v) = one("zzz", many)?;
    let (_, _, n, candidates) = v.unresolved.clone().ok_or("not unresolved")?;
    assert_eq!((n, candidates.len()), (0, 10));
    assert_eq!(candidates[0], "T0");
    // Resolved by id to a name another type also has (any case): the name the body sends would
    // not say which one, so it is ambiguous.
    let same_name = vec![
        link_type("10030", "Follows", "is followed by", "follows"),
        link_type("10031", "FOLLOWS", "comes after", "comes before"),
    ];
    let (_, v) = one("10030", same_name)?;
    assert_eq!(
        v.unresolved,
        unresolved("10030", 2, &["Follows", "FOLLOWS"])
    );
    // A blank value names no type: unresolved without a GET.
    for blank in ["  ", "\t"] {
        let (used, v) = one(blank, default_types())?;
        assert_eq!(used, 0, "{blank:?}: no GET");
        assert_eq!(v.unresolved, unresolved(blank, 0, &[]), "{blank:?}");
    }
    // Answers it cannot use fail closed (enrichment error): not the documented object, a
    // matched type without a name, an empty name, or a missing phrase.
    for answer in [
        json!([]),
        json!({"issueLinkTypes": {}}),
        json!({"issueLinkTypes": [{"id": "10000", "inward": "is blocked by", "outward": "blocks"}]}),
        json!({"issueLinkTypes": [link_type("10000", "", "is blocked by", "blocks")]}),
        json!({"issueLinkTypes": [{"id": "10000", "name": "Blocks", "outward": "blocks"}]}),
        json!({"issueLinkTypes": [{"id": "10000", "name": "Blocks", "inward": "is blocked by"}]}),
    ] {
        let params = if answer.pointer("/issueLinkTypes/0/name").is_some() {
            link_params("Blocks")
        } else {
            link_params("10000")
        };
        let (_, v) = enrich_as(LINK, &params, std::slice::from_ref(&answer))?;
        assert_eq!(v.hold, Hold::EnrichmentError, "{answer}: {v:?}");
        assert_eq!(
            exec_as(LINK, &params, Some(&v)),
            Err(ExecError::EnrichmentRequired),
            "{answer}"
        );
    }
    Ok(())
}

/// The executor's static checks run at validation (before the enrichment is there): a link of
/// an issue to itself and a blank comment are refused; only a `Preview` verdict renders.
#[test]
fn issuelink_executor_static_checks() -> TestResult {
    let invalid_param = |r: Result<ExecPlan, ExecError>| match r {
        Err(ExecError::Invalid(e)) => e.details.get("param").cloned(),
        _ => None,
    };
    let selflink = json!({"type": "Blocks", "inward": "ABC-1", "outward": "ABC-1"});
    assert_eq!(
        invalid_param(exec_as(LINK, &selflink, None)),
        Some(json!("outward"))
    );
    for blank in ["  ", "\n\t"] {
        let mut params = link_params("Blocks");
        params["comment"] = json!(blank);
        assert_eq!(
            invalid_param(exec_as(LINK, &params, None)),
            Some(json!("comment")),
            "{blank:?}"
        );
    }
    let params = link_params("Blocks");
    assert_eq!(
        exec_as(LINK, &params, None),
        Err(ExecError::EnrichmentRequired)
    );
    let (_, v) = enrich_as(LINK, &params, &[types_answer(default_types())])?;
    assert!(exec_as(LINK, &params, Some(&v)).is_ok());
    for hold in [
        Hold::EnrichmentError,
        Hold::UnresolvedName,
        Hold::Conflict,
        Hold::IdentityMismatch,
    ] {
        let mut held = v.clone();
        held.hold = hold;
        assert_eq!(
            exec_as(LINK, &params, Some(&held)),
            Err(ExecError::EnrichmentRequired),
            "{hold:?}"
        );
    }
    let mut empty = v.clone();
    empty.resolved.insert("type".into(), json!(""));
    assert_eq!(
        exec_as(LINK, &params, Some(&empty)),
        Err(ExecError::EnrichmentRequired)
    );
    Ok(())
}

/// Server text on the link card never pushes a sent value out of view: phrases and the type name
/// are cut short (escaped, the cut counted), the issue keys have rows of their own, and the
/// invisible characters of the phrases count into the Cautions although the request has none.
/// The sent type name gets the mixed-script check; facts about another name are not shown as
/// this link's.
#[test]
fn issuelink_card_keeps_sent_values_in_view() -> TestResult {
    let padded = format!("blocks{}", "\u{2060}".repeat(100));
    let types = types_answer(vec![link_type("10000", "Blocks", "is blocked by", &padded)]);
    let params = link_params("Blocks");
    let (_, v) = enrich_as(LINK, &params, std::slice::from_ref(&types))?;
    let m = preview_as(LINK, &params, &v)?;
    let card = link_card(&m)?;
    assert!(
        card.sentence.starts_with("ABC-124 blocks⟨U+2060⟩"),
        "{}",
        card.sentence
    );
    assert!(
        card.sentence.ends_with("… ABC-123 (Blocks)"),
        "{}",
        card.sentence
    );
    assert_eq!(
        link_row(&card, "Inward issue (inwardIssue)"),
        Some("ABC-124")
    );
    assert_eq!(
        link_row(&card, "Outward issue (outwardIssue)"),
        Some("ABC-123")
    );
    assert_eq!(m.header.other_invisible, 100);
    assert!(m.header.hidden_in_preview_bytes > 0);
    assert!(
        m.warnings.iter().any(|w| w.id == WarningId::OtherInvisible),
        "{:?}",
        m.warnings
    );

    // A type name in two scripts (Cyrillic `В`) with a bidi override in its inward phrase.
    let spoof = "\u{0412}locks";
    let types = types_answer(vec![link_type(
        "10000",
        spoof,
        "is\u{202e} blocked by",
        "blocks",
    )]);
    let params = link_params("10000");
    let (_, v) = enrich_as(LINK, &params, std::slice::from_ref(&types))?;
    let m = preview_as(LINK, &params, &v)?;
    let card = link_card(&m)?;
    for (name, value) in &card.rows {
        assert!(!value.contains('\u{202e}'), "{name}: {value}");
    }
    assert_eq!(
        link_row(&card, "Reads as"),
        Some("ABC-123 is⟨U+202E⟩ blocked by ABC-124")
    );
    assert!(m.header.bidi_controls >= 1);
    assert!(
        m.warnings.iter().any(|w| w.id == WarningId::BidiControls),
        "{:?}",
        m.warnings
    );
    assert!(
        m.warnings
            .iter()
            .any(|w| w.id == WarningId::MixedScript && w.text.contains(spoof)),
        "{:?}",
        m.warnings
    );

    // Facts about another type than the one the request names: no phrase is shown for it.
    let params = link_params("Blocks");
    let (_, mut v) = enrich_as(LINK, &params, &[types_answer(default_types())])?;
    v.resolved.insert("type".into(), json!("Relates"));
    let card = link_card(&preview_as(LINK, &params, &v)?)?;
    assert_eq!(
        card.sentence,
        "Link ABC-124 to ABC-123 with link type Relates (enrichment resolved Blocks)"
    );
    assert_eq!(link_row(&card, "Reads as"), None);
    assert_eq!(link_row(&card, "Sent as link type name"), Some("Relates"));
    Ok(())
}

// ---- jira.issuelink.create end to end --------------------------------------------------------

async fn link_posts(mock: &MockDc) -> Vec<wiremock::Request> {
    let full = mock.path(LINK_POST);
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == full)
        .collect()
}

/// The `Attention` kinds the core raised for the UI so far.
fn attention_kinds(h: &Harness) -> Vec<String> {
    h.capture()
        .on(atlas_duck_core::testing::Channel::UiEvent)
        .iter()
        .filter_map(|r| serde_json::from_str::<Value>(&r.json).ok())
        .filter_map(|e| e.pointer("/Attention/kind")?.as_str().map(str::to_owned))
        .collect()
}

/// Queues a link of ABC-124 → ABC-123 typed `Blocks` with a comment, opens it, approves it and
/// returns its final envelope.
async fn link_executed(h: &Harness) -> Result<(String, Envelope), TestError> {
    let mock = jira(h)?;
    mount_link_types(mock, &Value::Array(default_types())).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    let mut params = link_params("Blocks");
    params["comment"] = json!("Linked by *atlas-duck*");
    let id = queued_as(h, LINK, params).await?;
    let p = opened(h, &id)?;
    assert!(p.approvable);
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    Ok((id, env))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i25_issuelink_201_empty_html_succeeded_receipt_empty() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    // Jira 10: 201, no body, `Content-Type: text/html` (§7.2).
    mock.empty(LINK_POST, 201, Some("text/html;charset=UTF-8"))
        .await;
    let (id, env) = link_executed(&h).await?;
    assert_eq!(
        (env.status, exit(&env)),
        (Status::Succeeded, 0),
        "{}",
        env.to_json_line()
    );
    assert_eq!(env.data, Some(json!({ "receipt": {} })));
    let sent = link_posts(mock).await;
    assert_eq!(sent.len(), 1);
    let body: Value = serde_json::from_slice(&sent[0].body)?;
    assert_eq!(
        body,
        json!({
            "type": {"name": "Blocks"},
            "inwardIssue": {"key": "ABC-124"},
            "outwardIssue": {"key": "ABC-123"},
            "comment": {"body": "Linked by *atlas-duck*"}
        })
    );
    // The link types (resolve), then the pre-write identity call; no stale rule (spec).
    assert_eq!(purposes(&h, &id).await?, ["resolve", "stale_check"]);
    let types = gets_on(mock, LINK_TYPES).await;
    assert_eq!(types.len(), 1);
    assert_eq!(
        types[0].url.query(),
        None,
        "nothing of the params in the URL"
    );
    let kinds = attention_kinds(&h);
    assert!(
        !kinds.iter().any(|k| k == "Failed" || k == "OutcomeUnknown"),
        "{kinds:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i25_issuelink_201_html_body_outcome_unknown() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.html(LINK_POST, 201).await;
    let (id, env) = link_executed(&h).await?;
    assert_eq!(
        (env.status, exit(&env)),
        (Status::OutcomeUnknown, 6),
        "{}",
        env.to_json_line()
    );
    assert!(!env.to_json_line().contains("Please log in"));
    assert_eq!(link_posts(mock).await.len(), 1);
    assert_eq!(
        records(&h, &id, EventType::WRITE_OUTCOME_UNKNOWN)
            .await?
            .len(),
        1
    );
    assert!(
        records(&h, &id, EventType::WRITE_EXECUTED)
            .await?
            .is_empty()
    );
    Ok(())
}

/// §7.2: an op that declares a JSON success answered by an empty 2xx is `outcome_unknown`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i25_comment_add_empty_200_outcome_unknown() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.empty(
        "/rest/api/2/issue/ABC-1/comment",
        200,
        Some("application/json;charset=UTF-8"),
    )
    .await;
    let id = queued_as(
        &h,
        "jira.comment.add",
        json!({"key": KEY, "body": "Reproduced.", "body_format": "wiki"}),
    )
    .await?;
    opened(&h, &id)?;
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(
        (env.status, exit(&env)),
        (Status::OutcomeUnknown, 6),
        "{}",
        env.to_json_line()
    );
    assert!(
        records(&h, &id, EventType::WRITE_EXECUTED)
            .await?
            .is_empty()
    );
    Ok(())
}

/// L06: the issue keys are read-only targets; the type and the comment can be edited, and an
/// edited type is resolved again (§5.4 step 4). A self-link is refused at validation (exit 2,
/// nothing fetched, nothing queued).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issuelink_edit_form_and_type_edit() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_link_types(mock, &Value::Array(default_types())).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.empty(LINK_POST, 201, None).await;
    let id = queued_as(&h, LINK, link_params("zzz")).await?;
    let p = opened(&h, &id)?;
    assert!(!p.approvable);
    let form = p.edit_form.as_ref().ok_or("no edit form")?;
    let input = |name: &str| form.inputs.iter().find(|i| i.path == name);
    assert!(input("inward").is_some_and(|i| i.read_only));
    assert!(input("outward").is_some_and(|i| i.read_only));
    assert!(input("type").is_some_and(|i| !i.read_only));
    let rev = h.approver().rev(&id).map_err(de)?;
    let mut set = Map::new();
    set.insert("type".into(), json!("relates to"));
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
    assert_eq!(purposes(&h, &id).await?, ["resolve", "resolve"]);
    let (sentence, _) = card_rows(&opened(&h, &id)?)?;
    assert_eq!(sentence, "ABC-124 relates to ABC-123 (Relates)");
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let sent = link_posts(mock).await;
    let body: Value = serde_json::from_slice(&sent.first().ok_or("no POST")?.body)?;
    assert_eq!(body["type"], json!({"name": "Relates"}));

    // Linking an issue to itself: rejected at validation.
    let env = h
        .submit(
            LINK,
            json!({"type": "Blocks", "inward": "ABC-7", "outward": "ABC-7"}),
        )
        .await;
    assert_eq!(
        (env.status, exit(&env), code(&env)),
        (Status::Failed, 2, "validation".to_owned()),
        "{}",
        env.to_json_line()
    );
    assert_eq!(detail(&env, "param"), "outward");
    assert_eq!(gets_on(mock, LINK_TYPES).await.len(), 2, "no further GET");
    Ok(())
}

// ---- I-35: every Jira resolution kind --------------------------------------------------------

/// One resolution kind of the I-35 table: the op, its mounts, a no-match and an ambiguous
/// request, and what each is expected to say.
struct Kind {
    op: &'static str,
    param: &'static str,
    cases: [Case; 2],
}

struct Case {
    params: Value,
    value: &'static str,
    matches: u64,
    candidates: &'static [&'static str],
    message: &'static str,
}

fn kinds() -> Vec<Kind> {
    let create = |project: &str, issuetype: &str, summary: &str| json!({"project": project, "issuetype": issuetype, "summary": summary});
    vec![
        Kind {
            op: "jira.issue.create",
            param: "project",
            cases: [
                Case {
                    params: create("Nope", "Bug", "S1"),
                    value: "Nope",
                    matches: 0,
                    candidates: &["Alpha", "alpha", "Operations"],
                    message: "no project named 'Nope'",
                },
                Case {
                    params: create("ALPHA", "Bug", "S2"),
                    value: "ALPHA",
                    matches: 2,
                    candidates: &["Alpha", "alpha"],
                    message: "no project named 'ALPHA'",
                },
            ],
        },
        Kind {
            op: "jira.issue.create",
            param: "issuetype",
            cases: [
                Case {
                    params: create("ABC", "Bugg", "S3"),
                    value: "Bugg",
                    matches: 0,
                    candidates: &["Story", "Bug", "BUG"],
                    message: "no issue type named 'Bugg' in ABC",
                },
                Case {
                    params: create("ABC", "bug", "S4"),
                    value: "bug",
                    matches: 2,
                    candidates: &["Bug", "BUG"],
                    message: "no issue type named 'bug' in ABC",
                },
            ],
        },
        Kind {
            op: "jira.issue.transition",
            param: "transition",
            cases: [
                Case {
                    params: json!({"key": "ABC-1", "transition": "Doen"}),
                    value: "Doen",
                    matches: 0,
                    candidates: &["Start Progress", "Done", "done"],
                    message: "no transition named 'Doen' for ABC-1",
                },
                Case {
                    params: json!({"key": "ABC-2", "transition": "DONE"}),
                    value: "DONE",
                    matches: 2,
                    candidates: &["Done", "done"],
                    message: "no transition named 'DONE' for ABC-2",
                },
            ],
        },
        Kind {
            op: ASSIGN,
            param: "assignee",
            cases: [
                Case {
                    params: json!({"key": "ABC-1", "assignee": "nobody"}),
                    value: "nobody",
                    matches: 0,
                    candidates: &["jdoe1", "jdoe2"],
                    message: "no assignable user 'nobody' for ABC-1",
                },
                Case {
                    params: json!({"key": "ABC-2", "assignee": "Jane Doe"}),
                    value: "Jane Doe",
                    matches: 2,
                    candidates: &["jdoe1", "jdoe2"],
                    message: "no assignable user 'Jane Doe' for ABC-2",
                },
            ],
        },
        Kind {
            op: LINK,
            param: "type",
            cases: [
                Case {
                    params: json!({"type": "zzz", "inward": "ABC-1", "outward": "ABC-2"}),
                    value: "zzz",
                    matches: 0,
                    candidates: &["Relates", "relates", "Blocks"],
                    message: "no issue link type named 'zzz'",
                },
                Case {
                    params: json!({"type": "Relates", "inward": "ABC-3", "outward": "ABC-4"}),
                    value: "Relates",
                    matches: 2,
                    candidates: &["Relates", "relates"],
                    message: "no issue link type named 'Relates'",
                },
            ],
        },
    ]
}

/// The answers every kind's resolution GETs get: two names that differ only in case each.
async fn mount_kind(mock: &MockDc, param: &str) -> TestResult {
    match param {
        "project" => {
            let projects = json!([
                {"id": "1", "key": "ALA", "name": "Alpha"},
                {"id": "2", "key": "ALB", "name": "alpha"},
                {"id": "3", "key": "OPS", "name": "Operations"}
            ]);
            mock.json(PROJECTS_PATH, 200, &projects.to_string()).await;
        }
        "issuetype" => {
            let projects = json!([{"id": "10000", "key": "ABC", "name": "Alpha Beta"}]);
            mock.json(PROJECTS_PATH, 200, &projects.to_string()).await;
            let types = json!({"isLast": true, "values": [
                {"id": "1", "name": "Story"}, {"id": "2", "name": "Bug"}, {"id": "3", "name": "BUG"}
            ]});
            mock.json(&issuetypes_path("ABC"), 200, &types.to_string())
                .await;
        }
        "transition" => {
            let transitions = json!({"transitions": [
                {"id": "21", "name": "Start Progress", "to": {"id": "3", "name": "In Progress"}},
                {"id": "31", "name": "Done", "to": {"id": "10001", "name": "Done"}},
                {"id": "41", "name": "done", "to": {"id": "10002", "name": "Closed"}}
            ]});
            for key in ["ABC-1", "ABC-2"] {
                mock.json(
                    &format!("/rest/api/2/issue/{key}/transitions"),
                    200,
                    &transitions.to_string(),
                )
                .await;
                let issue = json!({"key": key, "fields": {"status": {"id": "1", "name": "Open"}}});
                mount_issue(mock, key, &issue).await;
            }
        }
        "assignee" => {
            mount_assignable(
                mock,
                &json!([
                    user("jdoe1", "JIRAUSER11", "Jane Doe"),
                    user("jdoe2", "JIRAUSER12", "Jane Doe")
                ]),
            )
            .await;
        }
        "type" => {
            mount_link_types(
                mock,
                &json!([
                    link_type("10003", "Relates", "relates to", "relates to"),
                    link_type("10004", "relates", "is related to", "relates"),
                    link_type("10000", "Blocks", "is blocked by", "blocks")
                ]),
            )
            .await;
        }
        other => return Err(format!("no mounts for {other}").into()),
    }
    Ok(())
}

/// I-35 (§13, Review Focus 2): per resolution kind (project, issue type, transition, assignable
/// user, link type) a no-match and an ambiguous request each leave Approve disabled in Rust:
/// alone, and in a batch with a clean opened `jira.comment.add`, which is rejected whole with
/// nothing decided; deny with the candidates ticked delivers `resolution_failed`, exit 3.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i35_jira_kinds_no_match_and_ambiguous_not_approvable() -> TestResult {
    for kind in kinds() {
        let h = Harness::builder()
            .jira("jira-main")
            .confirm(vec![Confirm::Ok, Confirm::Ok])
            .start()
            .await?;
        let mock = jira(&h)?;
        mount_kind(mock, kind.param).await?;
        let clean = queued_as(
            &h,
            "jira.comment.add",
            json!({"key": "XYZ-9", "body": "clean", "body_format": "wiki"}),
        )
        .await?;
        opened(&h, &clean)?;
        assert!(h.approver().item(&clean).ok_or("gone")?.approvable);
        for case in &kind.cases {
            let what = format!("{} {}", kind.param, case.value);
            let id = queued_as(&h, kind.op, case.params.clone()).await?;
            match opened(&h, &id)?.body {
                PreviewBody::UnresolvedName {
                    param,
                    value,
                    matches,
                    candidates,
                } => {
                    assert_eq!(
                        (param.as_str(), value.as_str(), matches),
                        (kind.param, case.value, case.matches),
                        "{what}"
                    );
                    assert_eq!(candidates, case.candidates, "{what}");
                }
                other => return Err(format!("{what}: not the unresolved card: {other:?}").into()),
            }
            not_approvable(h.approver().approve(&id))?;
            let batch = [&clean, &id]
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
                        id.clone(),
                        BatchFailure::Invalid(InvalidReason::NotApprovable)
                    )],
                    "{what}"
                ),
                other => return Err(format!("{what}: not rejected: {other:?}").into()),
            }
            for r in [&clean, &id] {
                assert!(
                    records(&h, r, EventType::WRITE_APPROVED).await?.is_empty(),
                    "{what}"
                );
            }
            assert!(
                h.approver().item(&clean).ok_or("gone")?.approvable,
                "{what}"
            );
            h.approver()
                .deny_with(
                    &id,
                    "cannot tell",
                    DenyDetails::ResolutionFailed {
                        include_candidates: true,
                    },
                )
                .map_err(de)?;
            let env = h.await_(&id, 5000).await;
            assert_eq!(
                (env.status, exit(&env), code(&env)),
                (Status::Denied, 3, "resolution_failed".to_owned()),
                "{what}"
            );
            assert_eq!(detail(&env, "param"), kind.param, "{what}");
            assert_eq!(detail(&env, "value"), case.value, "{what}");
            assert_eq!(detail(&env, "message"), case.message, "{what}");
            assert_eq!(detail(&env, "candidates"), json!(case.candidates), "{what}");
        }
        // Nothing was written by any of them.
        let writes = mock
            .received()
            .await
            .into_iter()
            .filter(|r| r.method.as_str() != "GET")
            .count();
        assert_eq!(writes, 0, "{}", kind.param);
    }
    Ok(())
}

/// I-35 link type end to end: deny without the candidates ticked carries none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i35_link_type_deny_without_candidates() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_link_types(mock, &Value::Array(default_types())).await;
    let id = queued_as(&h, LINK, link_params("zzz")).await?;
    opened(&h, &id)?;
    not_approvable(h.approver().approve_unopened(&id))?;
    h.approver()
        .deny_with(
            &id,
            "no such type",
            DenyDetails::ResolutionFailed {
                include_candidates: false,
            },
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!((env.status, exit(&env)), (Status::Denied, 3));
    assert_eq!(code(&env), "resolution_failed");
    assert_eq!(detail(&env, "message"), "no issue link type named 'zzz'");
    assert_eq!(detail(&env, "candidates"), Value::Null);
    assert!(link_posts(mock).await.is_empty());
    Ok(())
}
