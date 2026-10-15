#![cfg(feature = "testing")]
//! `jira.issue.create` complete (Task 12): staged enrichment (Δ3) with project and issue-type
//! resolution (PD-48, PD-62), the createmeta required fields (PD-49), the edit form (§5.4 step 4,
//! L06), the `missing_fields` deny details (§4.3) and the create preview (§6.3). I-18, I-35
//! (project and issue type), U-30 (Jira create), the I-23 stage-GET case and the round limit.

mod common;

use std::time::Duration;

use atlas_duck_atlassian::GetCall;
use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_core::ops::{
    EnrichCtx, EnrichPurpose, EnrichRule, EnrichStep, EnrichVerdict, MAX_ENRICH_STAGES,
};
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::{ConverterFault, Harness};
use atlas_duck_core::{
    DecisionError, DecisionOutcome, DenyDetails, Edits, Pause, ShutdownReason, TestHooks,
};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::form::{EditInput, InputKind};
use atlas_duck_preview::{Level, Preview, PreviewBody, WarningId};
use common::jira::{PROJECTS_PATH, gets_on, issuetypes_path, mount_create_stages, query};
use common::{TestError, TestResult, code, de, exit, message, request_id, test_hits};
use serde_json::{Map, Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path, query_param, query_param_is_missing};

const CREATE: &str = "jira.issue.create";
const CREATE_PATH: &str = "/rest/api/2/issue";
/// `common::jira::create_fields_path("ABC", "10002")`.
const BUG_FIELDS: &str = "/rest/api/2/issue/createmeta/ABC/issuetypes/10002";
/// §5.4 step 2 / PD-49: the Caution of the createmeta fixture with a required `Team`.
const TEAM_CAUTION: &str = "missing required fields: Team (customfield_10200, option)";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

fn params(summary: &str) -> Value {
    json!({ "project": "ABC", "issuetype": "Bug", "summary": summary })
}

/// The identity call before a write (§5.4 step 5) and the create's `201`.
async fn approvable_server(mock: &MockDc) {
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.json(CREATE_PATH, 201, fixtures::JIRA_ISSUE_CREATED)
        .await;
}

/// createmeta fields of `Bug` with `customfield_10200` (`Team`, an `option`) required and
/// without a default (PD-49, §6.2's example).
fn team_fields() -> Value {
    json!({
        "maxResults": 50, "startAt": 0, "total": 3, "isLast": true,
        "values": [
            {"required": true, "schema": {"type": "string", "system": "summary"},
             "name": "Summary", "fieldId": "summary", "hasDefaultValue": false},
            {"required": true,
             "schema": {"type": "option",
                        "custom": "com.atlassian.jira.plugin.system.customfieldtypes:select",
                        "customId": 10200},
             "name": "Team", "fieldId": "customfield_10200", "hasDefaultValue": false,
             "operations": ["set"], "allowedValues": [{"id": "10400", "value": "Platform"}]},
            {"required": true, "schema": {"type": "user", "system": "reporter"},
             "name": "Reporter", "fieldId": "reporter", "hasDefaultValue": true}
        ]
    })
}

/// Projects and issue types as usual; the `Bug` fields with the required `Team`.
async fn mount_team_stages(mock: &MockDc) {
    mock.json(PROJECTS_PATH, 200, fixtures::JIRA_PROJECTS).await;
    mock.json(
        &issuetypes_path("ABC"),
        200,
        fixtures::JIRA_CREATEMETA_ISSUETYPES,
    )
    .await;
    mock.json(BUG_FIELDS, 200, &team_fields().to_string()).await;
}

async fn queued(h: &Harness, p: Value) -> Result<String, TestError> {
    let env = h.submit(CREATE, p).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

async fn records(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

fn preview(h: &Harness, id: &str) -> Result<Preview, TestError> {
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

/// Waits until the queue row's revision is past `counter` (a re-enrichment ended).
async fn rev_after(h: &Harness, id: &str, counter: u64) -> Result<(), TestError> {
    for _ in 0..500 {
        if h.approver()
            .item(id)
            .is_some_and(|i| i.candidate_rev.counter > counter)
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("no new revision".into())
}

/// The one POST the mock received, as JSON.
async fn sent_create(mock: &MockDc) -> Result<Value, TestError> {
    let posts: Vec<_> = mock
        .received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
        .collect();
    let [post] = posts.as_slice() else {
        return Err(format!("{} POSTs", posts.len()).into());
    };
    Ok(serde_json::from_slice(&post.body)?)
}

fn input<'a>(p: &'a Preview, path: &str) -> Result<&'a EditInput, TestError> {
    p.edit_form
        .as_ref()
        .ok_or("no edit form")?
        .inputs
        .iter()
        .find(|i| i.path == path)
        .ok_or_else(|| format!("no input {path}").into())
}

fn details(env: &atlas_duck_ipc::envelope::Envelope) -> Result<Value, TestError> {
    env.error
        .as_ref()
        .and_then(|e| e.details.clone())
        .map(Value::Object)
        .ok_or_else(|| "no details".into())
}

// ---- stages and their records -----------------------------------------------------------------

/// Δ3: three stages, each `PREVIEW_FETCH` committed before the next GET leaves; the purposes are
/// `resolve` (projects), `resolve` (issue types), `enrich` (fields).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_three_stage_enrichment_records() -> TestResult {
    let pause = Pause::new();
    let h = Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            pause_after_get: Some(pause.clone()),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let mock = jira(&h)?;
    mount_create_stages(mock).await;
    let id = request_id(&h.submit(CREATE, params("Fix login")).await)?;

    // Stage 1 answered, its record parked: stage 2 has not left.
    pause.reached.notified().await;
    assert_eq!(h.event_types(&id).await?, [EventType::REQUEST_RECEIVED]);
    assert_eq!(gets_on(mock, PROJECTS_PATH).await.len(), 1);
    assert!(gets_on(mock, &issuetypes_path("ABC")).await.is_empty());
    pause.release.notify_one();

    // Stage 2 answered: stage 1's record was committed before it left.
    pause.reached.notified().await;
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::PREVIEW_FETCH]
    );
    assert_eq!(gets_on(mock, &issuetypes_path("ABC")).await.len(), 1);
    assert!(gets_on(mock, BUG_FIELDS).await.is_empty());
    pause.release.notify_one();

    // Stage 3 answered: stage 2's record was committed before it left.
    pause.reached.notified().await;
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::PREVIEW_FETCH
        ]
    );
    assert_eq!(gets_on(mock, BUG_FIELDS).await.len(), 1);
    pause.release.notify_one();

    let item = h.queued(&id, 10_000).await.ok_or("never queued")?;
    assert!(item.approvable);
    let fetches = records(&h, &id, EventType::PREVIEW_FETCH).await?;
    let purposes: Vec<&Value> = fetches.iter().map(|f| &f["purpose"]).collect();
    assert_eq!(
        purposes,
        [&json!("resolve"), &json!("resolve"), &json!("enrich")]
    );
    let paths: Vec<String> = fetches.iter().map(|f| f["path"].to_string()).collect();
    assert!(paths[0].ends_with("/rest/api/2/project\""), "{paths:?}");
    assert!(
        paths[1].ends_with("/rest/api/2/issue/createmeta/ABC/issuetypes\""),
        "{paths:?}"
    );
    assert!(paths[2].contains(BUG_FIELDS), "{paths:?}");
    // The verdict's record is the third GET's (committed with `Enriched`), nothing after it.
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::PREVIEW_FETCH,
            EventType::PREVIEW_FETCH
        ]
    );
    Ok(())
}

/// PD-49 paging inside the round limit: page 1 says `isLast: false`; the remaining pages (≤ 3)
/// are one round, so the whole enrichment stays within `MAX_ENRICH_STAGES` rounds. A missing
/// field on page 3 is found.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_fields_pages_fetched_in_one_round() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.json(PROJECTS_PATH, 200, fixtures::JIRA_PROJECTS).await;
    mock.json(
        &issuetypes_path("ABC"),
        200,
        fixtures::JIRA_CREATEMETA_ISSUETYPES,
    )
    .await;
    let field = |n: u64| {
        json!({"required": false, "schema": {"type": "string"}, "name": format!("F{n}"),
               "fieldId": format!("customfield_{}", 20_000 + n), "hasDefaultValue": false})
    };
    let page = |start: u64, last: bool, extra: Option<Value>| {
        let mut values: Vec<Value> = (start..start + 2).map(field).collect();
        values.extend(extra);
        json!({"maxResults": 2, "startAt": start, "total": 6, "isLast": last, "values": values})
    };
    let team = team_fields()["values"][1].clone();
    let answer = |v: Value| {
        mock.response(200)
            .set_body_raw(v.to_string(), "application/json")
    };
    Mock::given(method("GET"))
        .and(path(mock.path(BUG_FIELDS)))
        .and(query_param_is_missing("startAt"))
        .respond_with(answer(page(0, false, None)))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(mock.path(BUG_FIELDS)))
        .and(query_param("startAt", "2"))
        .and(query_param("maxResults", "2"))
        .respond_with(answer(page(2, false, None)))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(mock.path(BUG_FIELDS)))
        .and(query_param("startAt", "4"))
        .and(query_param("maxResults", "2"))
        .respond_with(answer(page(4, true, Some(team))))
        .mount(mock.server())
        .await;
    let id = queued(&h, params("Paged fields")).await?;
    // Pages 2 and 3 only: page 4 would start at the total.
    assert_eq!(gets_on(mock, BUG_FIELDS).await.len(), 3);
    let fetches = records(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(fetches.len(), 5);
    let p = preview(&h, &id)?;
    assert!(p.approvable);
    assert!(
        p.warnings
            .iter()
            .any(|w| w.id == WarningId::MissingRequiredFields && w.text == TEAM_CAUTION),
        "{:?}",
        p.warnings
    );
    Ok(())
}

// ---- I-35: project and issue type -------------------------------------------------------------

/// Denies `id` with `ResolutionFailed {include_candidates}` and returns the envelope.
async fn deny_resolution(
    h: &Harness,
    id: &str,
    include_candidates: bool,
) -> Result<atlas_duck_ipc::envelope::Envelope, TestError> {
    h.approver()
        .deny_with(
            id,
            "unknown name",
            DenyDetails::ResolutionFailed { include_candidates },
        )
        .map_err(de)?;
    let env = h.await_(id, 5000).await;
    assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
    assert_eq!(exit(&env), 3);
    assert_eq!(code(&env), "resolution_failed");
    Ok(env)
}

/// An unresolved write: the card, Approve refused (`DECISION_INVALID {not_approvable}`), nothing
/// approved.
async fn assert_unresolved(
    h: &Harness,
    id: &str,
    want_param: &str,
    want_matches: u64,
    want_candidates: &[&str],
) -> TestResult {
    let item = h.approver().item(id).ok_or("not queued")?;
    assert!(!item.approvable);
    let p = preview(h, id)?;
    assert!(!p.approvable);
    match &p.body {
        PreviewBody::UnresolvedName {
            param,
            matches,
            candidates,
            ..
        } => {
            assert_eq!((param.as_str(), *matches), (want_param, want_matches));
            assert_eq!(candidates, want_candidates);
        }
        other => return Err(format!("not the unresolved-name card: {other:?}").into()),
    }
    not_approvable(h.approver().approve_unopened(id))?;
    assert!(records(h, id, EventType::WRITE_APPROVED).await?.is_empty());
    assert_eq!(
        records(h, id, EventType::DECISION_INVALID)
            .await?
            .last()
            .map(|r| r["reason"].clone()),
        Some(json!("not_approvable"))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i35_project_no_match_and_ambiguous() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_create_stages(mock).await;
    let nope = json!({ "project": "Nope", "issuetype": "Bug", "summary": "S1" });
    let id = queued(&h, nope.clone()).await?;
    assert_unresolved(&h, &id, "project", 0, &["Alpha Beta", "Operations"]).await?;
    // `Judge` early: no issue-type or fields GET after an unresolved project.
    assert!(gets_on(mock, &issuetypes_path("Nope")).await.is_empty());
    assert!(gets_on(mock, &issuetypes_path("ABC")).await.is_empty());
    assert_eq!(records(&h, &id, EventType::PREVIEW_FETCH).await?.len(), 1);
    let env = deny_resolution(&h, &id, false).await?;
    assert_eq!(
        details(&env)?,
        json!({ "param": "project", "value": "Nope", "message": "no project named 'Nope'" })
    );

    let nope2 = json!({ "project": "Nope", "issuetype": "Bug", "summary": "S2" });
    let id = queued(&h, nope2).await?;
    let env = deny_resolution(&h, &id, true).await?;
    assert_eq!(
        details(&env)?["candidates"],
        json!(["Alpha Beta", "Operations"])
    );

    // Two projects named "Alpha" (case-insensitively): ambiguous; the candidates are the matches.
    let h = Harness::jira().await?;
    let projects = json!([
        {"id": "1", "key": "ALA", "name": "Alpha"},
        {"id": "2", "key": "ALB", "name": "alpha"},
        {"id": "3", "key": "OPS", "name": "Operations"}
    ]);
    jira(&h)?
        .json(PROJECTS_PATH, 200, &projects.to_string())
        .await;
    let id = queued(
        &h,
        json!({ "project": "ALPHA", "issuetype": "Bug", "summary": "S" }),
    )
    .await?;
    assert_unresolved(&h, &id, "project", 2, &["Alpha", "alpha"]).await?;

    // No match among many: every name is a candidate, at most 10.
    let h = Harness::jira().await?;
    let many: Vec<Value> = (0..12)
        .map(|n| json!({"id": format!("{}", 100 + n), "key": format!("P{n}"), "name": format!("Project {n}")}))
        .collect();
    jira(&h)?
        .json(PROJECTS_PATH, 200, &Value::Array(many).to_string())
        .await;
    let id = queued(
        &h,
        json!({ "project": "Nope", "issuetype": "Bug", "summary": "S" }),
    )
    .await?;
    let want: Vec<String> = (0..10).map(|n| format!("Project {n}")).collect();
    let want: Vec<&str> = want.iter().map(String::as_str).collect();
    assert_unresolved(&h, &id, "project", 0, &want).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i35_issuetype_no_match_and_ambiguous() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_create_stages(mock).await;
    let id = queued(
        &h,
        json!({ "project": "ABC", "issuetype": "Bugg", "summary": "S1" }),
    )
    .await?;
    assert_unresolved(&h, &id, "issuetype", 0, &["Story", "Bug"]).await?;
    // No fields GET after an unresolved issue type.
    assert!(gets_on(mock, BUG_FIELDS).await.is_empty());
    assert_eq!(records(&h, &id, EventType::PREVIEW_FETCH).await?.len(), 2);
    let env = deny_resolution(&h, &id, true).await?;
    assert_eq!(
        details(&env)?,
        json!({
            "param": "issuetype",
            "value": "Bugg",
            "message": "no issue type named 'Bugg' in ABC",
            "candidates": ["Story", "Bug"]
        })
    );

    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.json(PROJECTS_PATH, 200, fixtures::JIRA_PROJECTS).await;
    let twice =
        json!({"isLast": true, "values": [{"id": "1", "name": "Bug"}, {"id": "2", "name": "BUG"}]});
    mock.json(&issuetypes_path("ABC"), 200, &twice.to_string())
        .await;
    let id = queued(&h, params("S2")).await?;
    assert_unresolved(&h, &id, "issuetype", 2, &["Bug", "BUG"]).await?;
    let env = deny_resolution(&h, &id, false).await?;
    assert!(details(&env)?.get("candidates").is_none());
    Ok(())
}

/// PD-48: an id, a key (any case) or a name (any case) resolves to the project's key, and the
/// request body names the key; the stage-2 and stage-3 paths use the key too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn project_name_resolves_to_key() -> TestResult {
    for (n, project) in ["Alpha Beta", "alpha beta", "abc", "10000"]
        .iter()
        .enumerate()
    {
        let h = Harness::jira().await?;
        let mock = jira(&h)?;
        mount_create_stages(mock).await;
        approvable_server(mock).await;
        let p = json!({ "project": project, "issuetype": "bug", "summary": format!("S{n}") });
        let id = queued(&h, p).await?;
        assert_eq!(gets_on(mock, &issuetypes_path("ABC")).await.len(), 1);
        assert_eq!(gets_on(mock, BUG_FIELDS).await.len(), 1);
        h.approver().approve(&id).map_err(de)?;
        let env = h.await_(&id, 10_000).await;
        assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
        let body = sent_create(mock).await?;
        assert_eq!(
            body["fields"]["project"],
            json!({ "key": "ABC" }),
            "{project}"
        );
        assert_eq!(body["fields"]["issuetype"], json!({ "id": "10002" }));
    }
    Ok(())
}

// ---- I-18: missing required fields ------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i18_missing_fields_warning_approve_enabled() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_team_stages(mock).await;
    approvable_server(mock).await;
    let id = queued(&h, params("Needs a team")).await?;
    let item = h.approver().item(&id).ok_or("not queued")?;
    assert!(item.approvable, "a missing field is a warning, not a block");
    assert!(item.caution_count >= 1);
    let p = preview(&h, &id)?;
    assert!(p.approvable);
    let caution = p
        .warnings
        .iter()
        .find(|w| w.id == WarningId::MissingRequiredFields)
        .ok_or("no missing-fields warning")?;
    assert_eq!(caution.level, Level::Caution);
    assert_eq!(caution.text, TEAM_CAUTION);
    let team = input(&p, "fields.customfield_10200")?;
    assert!(team.pre_added && team.required && !team.read_only);
    // The UI sees the labels only (T12 review I1); core keeps the Jira value of each.
    match &team.kind {
        InputKind::Choice(allowed) => assert_eq!(allowed.as_slice(), ["Platform"]),
        other => return Err(format!("not a choice: {other:?}").into()),
    }
    assert_eq!(team.value, Value::Null);
    assert!(team.label.contains("Team"), "{}", team.label);
    // The create card: resolved project and issue type, the request list.
    match &p.body {
        PreviewBody::WriteSummary { rows, requests, .. } => {
            assert_eq!(requests.len(), 1);
            let row = |name: &str| rows.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
            assert_eq!(row("Project").as_deref(), Some("ABC (Alpha Beta)"));
            assert_eq!(row("Issue type").as_deref(), Some("Bug"));
            assert_eq!(row("Summary").as_deref(), Some("Needs a team"));
        }
        other => return Err(format!("not the create card: {other:?}").into()),
    }
    // Approve stays enabled: the create is sent as it is (Jira decides).
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert!(
        sent_create(mock).await?["fields"]
            .get("customfield_10200")
            .is_none()
    );
    Ok(())
}

/// Opens, picks `Platform` in the pre-added Team input (the label the UI shows, T12 review I1),
/// waits for the re-enrichment; returns the request id.
async fn edited_team_create(h: &Harness) -> Result<String, TestError> {
    let mock = jira(h)?;
    mount_team_stages(mock).await;
    approvable_server(mock).await;
    let id = queued(h, params("Team added")).await?;
    let rev = h.approver().rev(&id).map_err(de)?;
    let fetched = records(h, &id, EventType::PREVIEW_FETCH).await?.len();
    h.approver()
        .choose_preadded(&id, "fields.customfield_10200", "Platform")
        .map_err(de)?;
    rev_after(h, &id, rev.counter).await?;
    // The edit touched `fields` (an `enrich_keys` param): the enrichment ran again.
    let fetches = records(h, &id, EventType::PREVIEW_FETCH).await?;
    let again: Vec<&Value> = fetches
        .iter()
        .skip(fetched)
        .map(|f| &f["purpose"])
        .collect();
    assert_eq!(
        again,
        [&json!("resolve"), &json!("resolve"), &json!("enrich")]
    );
    Ok(id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i18_edit_and_approve_preadded_input_sends_field() -> TestResult {
    let h = Harness::jira().await?;
    let id = edited_team_create(&h).await?;
    let p = preview(&h, &id)?;
    assert!(p.approvable);
    assert!(
        !p.warnings
            .iter()
            .any(|w| w.id == WarningId::MissingRequiredFields),
        "the warning is gone: {:?}",
        p.warnings
    );
    let form = p.edit_form.as_ref().ok_or("no edit form")?;
    assert!(form.inputs.iter().all(|i| !i.pre_added));
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert!(env.edited);
    let data = env.data.clone().ok_or("no data")?;
    assert_eq!(
        data["edited_keys"]["added"],
        json!(["fields.customfield_10200"])
    );
    // The picked label went out as the option's id (createmeta gave one).
    let body = sent_create(jira(&h)?).await?;
    assert_eq!(
        body["fields"]["customfield_10200"],
        json!({ "id": "10400" })
    );
    // One approval, of the edited revision (the wire bytes are the approved list).
    let approved = records(&h, &id, EventType::WRITE_APPROVED).await?;
    assert_eq!(approved.len(), 1);
    assert_eq!(records(&h, &id, EventType::WRITE_EDITED).await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u30_create_added_field_value_not_delivered() -> TestResult {
    let h = Harness::jira().await?;
    let id = edited_team_create(&h).await?;
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let line = env.to_json_line();
    assert!(!line.contains("Platform"), "{line}");
    let data = env.data.clone().ok_or("no data")?;
    // The agent sent no `fields`: the delivery view has none.
    assert!(data["executed_params"].get("fields").is_none(), "{line}");
    assert_eq!(
        data["edited_keys"]["added"],
        json!(["fields.customfield_10200"])
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i18_deny_missing_fields_allowed_values_only_when_ticked() -> TestResult {
    let h = Harness::jira().await?;
    mount_team_stages(jira(&h)?).await;
    for (n, ticked) in [false, true].into_iter().enumerate() {
        let id = queued(&h, params(&format!("Deny {n}"))).await?;
        h.approver()
            .deny_with(
                &id,
                "pick a team first",
                DenyDetails::MissingFields {
                    include_allowed_values: ticked,
                },
            )
            .map_err(de)?;
        let env = h.await_(&id, 5000).await;
        assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
        assert_eq!(exit(&env), 3);
        assert_eq!(code(&env), "denied");
        assert_eq!(message(&env), "pick a team first");
        let mut want =
            json!({ "id": "customfield_10200", "name": "Team", "schema_type": "option" });
        if ticked {
            want["allowed_values"] = json!(["Platform"]);
        }
        assert_eq!(
            details(&env)?,
            json!({ "missing_fields": [want] }),
            "{ticked}"
        );
        // Stored in `WRITE_DENIED`.
        let denied = records(&h, &id, EventType::WRITE_DENIED).await?;
        assert_eq!(
            denied[0]["hint"]["details"]["missing_fields"],
            json!([want])
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_fields_hint_refused_without_missing_fields() -> TestResult {
    let h = Harness::jira().await?;
    mount_create_stages(jira(&h)?).await;
    let ticks = [
        DenyDetails::MissingFields {
            include_allowed_values: true,
        },
        DenyDetails::MissingFields {
            include_allowed_values: false,
        },
    ];
    let complete = queued(&h, params("Nothing missing")).await?;
    let unresolved = queued(
        &h,
        json!({ "project": "Nope", "issuetype": "Bug", "summary": "S" }),
    )
    .await?;
    for id in [&complete, &unresolved] {
        for details in ticks {
            let res = h.approver().deny_with(id, "no", details);
            assert!(
                matches!(res, Err(DecisionError::EditRejected(_))),
                "{res:?}"
            );
        }
        // Refused like a malformed edit: nothing logged, still waiting.
        assert!(records(&h, id, EventType::WRITE_DENIED).await?.is_empty());
        assert!(
            records(&h, id, EventType::DECISION_INVALID)
                .await?
                .is_empty()
        );
        assert!(h.approver().item(id).is_some());
        assert_eq!(h.status(id).await.status, Status::Pending);
    }
    Ok(())
}

// ---- the edit form ----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edit_form_read_only_targets() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_create_stages(mock).await;
    let p = json!({ "project": "ABC", "issuetype": "Bug", "summary": "Form",
                    "description": "Some *text*", "fields": {"labels": ["web"]} });
    let id = queued(&h, p).await?;
    let pv = preview(&h, &id)?;
    let project = input(&pv, "project")?;
    assert!(project.read_only && project.required && !project.pre_added);
    assert_eq!(project.value, json!("ABC"));
    let summary = input(&pv, "summary")?;
    assert!(!summary.read_only && summary.required);
    assert_eq!(summary.kind, InputKind::Text);
    assert_eq!(summary.value, json!("Form"));
    assert!(!input(&pv, "issuetype")?.read_only);
    assert_eq!(input(&pv, "description")?.kind, InputKind::LongText);
    assert!(!input(&pv, "description")?.required);
    assert_eq!(input(&pv, "fields")?.kind, InputKind::Json);
    assert_eq!(input(&pv, "fields")?.value, json!({"labels": ["web"]}));
    // An absent optional param is still an input, empty.
    assert_eq!(input(&pv, "body_format")?.value, Value::Null);
    let form = pv.edit_form.as_ref().ok_or("no edit form")?;
    assert!(form.inputs.iter().all(|i| !i.pre_added));

    // L06: an edit of the target is `DECISION_INVALID {target_param_edit}` (M3).
    let mut set = Map::new();
    set.insert("project".into(), json!("OPS"));
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
    assert_eq!(
        records(&h, &id, EventType::DECISION_INVALID)
            .await?
            .last()
            .map(|r| r["reason"].clone()),
        Some(json!("target_param_edit"))
    );

    // Every write preview has the form: a comment's key is a read-only target, its body long text.
    let id = request_id(
        &h.submit(
            "jira.comment.add",
            json!({ "key": "ABC-1", "body": "Done.", "body_format": "wiki" }),
        )
        .await,
    )?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    let pv = preview(&h, &id)?;
    assert!(input(&pv, "key")?.read_only);
    assert_eq!(input(&pv, "body")?.kind, InputKind::LongText);
    assert!(!input(&pv, "body")?.read_only);
    Ok(())
}

/// A required `description` counts as set only when the param is there (PD-49): its own input is
/// marked required (no `fields.description`, which validation refuses as a duplicate of the
/// param), and filling it re-runs enrichment, so the Caution goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn description_edit_reruns_enrichment() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.json(PROJECTS_PATH, 200, fixtures::JIRA_PROJECTS).await;
    mock.json(
        &issuetypes_path("ABC"),
        200,
        fixtures::JIRA_CREATEMETA_ISSUETYPES,
    )
    .await;
    let mut fields = team_fields();
    fields["values"][1] = json!({"required": true, "name": "Description", "fieldId": "description",
                                 "schema": {"type": "string", "system": "description"},
                                 "hasDefaultValue": false});
    mock.json(BUG_FIELDS, 200, &fields.to_string()).await;
    let id = queued(&h, params("No description")).await?;
    let p = preview(&h, &id)?;
    let caution = p
        .warnings
        .iter()
        .find(|w| w.id == WarningId::MissingRequiredFields)
        .ok_or("no missing-fields warning")?;
    assert_eq!(
        caution.text,
        "missing required fields: Description (description, string)"
    );
    let description = input(&p, "description")?;
    assert!(description.required && !description.pre_added && !description.read_only);
    assert!(input(&p, "fields.description").is_err());

    let rev = h.approver().rev(&id).map_err(de)?;
    let fetched = records(&h, &id, EventType::PREVIEW_FETCH).await?.len();
    let mut set = Map::new();
    set.insert("description".into(), json!("Steps to reproduce"));
    h.approver()
        .edit(
            &id,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
        .map_err(de)?;
    rev_after(&h, &id, rev.counter).await?;
    assert_eq!(
        records(&h, &id, EventType::PREVIEW_FETCH).await?.len(),
        fetched + 3,
        "the edit re-ran the three stages"
    );
    let p = preview(&h, &id)?;
    assert!(
        !p.warnings
            .iter()
            .any(|w| w.id == WarningId::MissingRequiredFields),
        "{:?}",
        p.warnings
    );
    Ok(())
}

/// `edit_preadded` is for the inputs enrichment pre-added, nothing else. Like the approvals UI,
/// it opens the revision first (the form is only reachable from an opened preview, §5.6), so
/// that open's `PREVIEW_SHOWN` is logged; the refusal itself logs nothing (T12 review M9).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edit_preadded_refuses_other_paths() -> TestResult {
    let h = Harness::jira().await?;
    mount_create_stages(jira(&h)?).await;
    let id = queued(&h, params("No team needed")).await?;
    let res = h.approver().edit_preadded(
        &id,
        "fields.customfield_10200",
        json!({ "value": "Platform" }),
    );
    assert!(
        matches!(res, Err(DecisionError::EditRejected(_))),
        "{res:?}"
    );
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::PREVIEW_FETCH,
            EventType::PREVIEW_FETCH,
            EventType::PREVIEW_SHOWN
        ]
    );
    Ok(())
}

// ---- stage failures ---------------------------------------------------------------------------

/// RF-2 / L31: a stage GET decided by status or headers (stage 2 answers 302) is direct, like
/// every M3 enrichment GET; stage 3 is never requested.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_enrichment_stage2_3xx_direct() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.json(PROJECTS_PATH, 200, fixtures::JIRA_PROJECTS).await;
    mock.redirect(&issuetypes_path("ABC"), "https://sso.corp.example/login")
        .await;
    mock.json(BUG_FIELDS, 200, fixtures::JIRA_CREATEMETA_FIELDS)
        .await;
    let id = request_id(&h.submit(CREATE, params("Redirected")).await)?;
    assert!(h.settled(&id, 10_000).await, "never settled");
    let env = h.await_(&id, 1000).await;
    assert_eq!((env.status, exit(&env)), (Status::Failed, 6));
    assert_eq!(code(&env), "upstream_unavailable");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert!(env.error.as_ref().is_some_and(|e| e.details.is_none()));
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::PREVIEW_FETCH,
            EventType::REQUEST_FAILED,
            EventType::DELIVERED
        ]
    );
    let fetches = records(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(fetches[1]["class"], "redirect_3xx");
    assert!(gets_on(mock, BUG_FIELDS).await.is_empty());
    assert!(h.approver().item(&id).is_none());
    Ok(())
}

/// L25: a stage failure after the server answered (stage 3's JSON body cut off) is gated: the
/// "enrichment failed" hold, Approve disabled, `pending` for the agent; a deny may attach the
/// fixed outcome hint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stage_failure_post_send_is_enrichment_failed() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.json(PROJECTS_PATH, 200, fixtures::JIRA_PROJECTS).await;
    mock.json(
        &issuetypes_path("ABC"),
        200,
        fixtures::JIRA_CREATEMETA_ISSUETYPES,
    )
    .await;
    mock.json(
        BUG_FIELDS,
        200,
        r#"{"maxResults":50,"values":[{"required":true,"#,
    )
    .await;
    let id = queued(&h, params("Cut off")).await?;
    assert_eq!(h.status(&id).await.status, Status::Pending);
    let p = preview(&h, &id)?;
    assert!(!p.approvable);
    match p.body {
        PreviewBody::EnrichmentError { outcome, .. } => assert_eq!(
            outcome,
            Some(atlas_duck_preview::OutcomeKind::JsonBodyUnreadable)
        ),
        other => return Err(format!("not the enrichment-error card: {other:?}").into()),
    }
    not_approvable(h.approver().approve_unopened(&id))?;
    assert!(
        records(&h, &id, EventType::REQUEST_FAILED)
            .await?
            .is_empty()
    );
    h.approver()
        .deny_with(&id, "broken answer", DenyDetails::OutcomeHint)
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Denied);
    assert_eq!(code(&env), "upstream_unavailable");
    assert_eq!(
        message(&env),
        atlas_duck_core::engine::write::HINT_ENRICH_UNPARSABLE
    );
    Ok(())
}

// ---- the round limit (Δ3) ---------------------------------------------------------------------

fn endless_plan(_: &EnrichCtx<'_>, _: &[Value]) -> EnrichStep {
    EnrichStep::Fetch(vec![(
        EnrichPurpose::Resolve,
        GetCall {
            endpoint_template: "/rest/api/2/project".to_owned(),
            params: json!({}),
            query: Vec::new(),
        },
    )])
}

fn endless_judge(_: &EnrichCtx<'_>, _: &[Value]) -> EnrichVerdict {
    EnrichVerdict::preview(Value::Null, Map::new())
}

/// A rule whose plan never says `Judge`.
static ENDLESS: EnrichRule = EnrichRule {
    plan: endless_plan,
    judge: endless_judge,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enrich_round_limit_fails_closed() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            enrich_rule: Some(&ENDLESS),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let mock = jira(&h)?;
    mount_create_stages(mock).await;
    let id = queued(&h, params("Endless")).await?;
    // Exactly `MAX_ENRICH_STAGES` rounds were fetched and recorded; no fifth GET.
    assert_eq!(MAX_ENRICH_STAGES, 4);
    assert_eq!(gets_on(mock, PROJECTS_PATH).await.len(), 4);
    assert_eq!(records(&h, &id, EventType::PREVIEW_FETCH).await?.len(), 4);
    let p = preview(&h, &id)?;
    assert!(!p.approvable);
    match p.body {
        PreviewBody::EnrichmentError {
            status, outcome, ..
        } => {
            assert_eq!((status, outcome), (None, None));
        }
        other => return Err(format!("not the enrichment-error card: {other:?}").into()),
    }
    not_approvable(h.approver().approve_unopened(&id))?;
    // Nothing the agent may be told: no hint applies.
    let res = h.approver().deny_with(&id, "no", DenyDetails::OutcomeHint);
    assert!(
        matches!(res, Err(DecisionError::EditRejected(_))),
        "{res:?}"
    );
    assert_eq!(h.status(&id).await.status, Status::Pending);
    Ok(())
}

// ---- validation first (T7 ordering) -----------------------------------------------------------

/// PD-43 after the rewrite: a converter fault on a create is rejected by the validation dry call,
/// before the stage-1 project GET.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_markdown_fault_rejected_before_stage1_get() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            converter_fault: Some(ConverterFault::Include),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let mock = jira(&h)?;
    mount_create_stages(mock).await;
    let before = test_hits(mock).await.len();
    let p = json!({ "project": "ABC", "issuetype": "Bug", "summary": "S", "description": "**x**" });
    let env = h.submit(CREATE, p).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!((code(&env), exit(&env)), ("validation".to_owned(), 2));
    let id = request_id(&env)?;
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
    );
    assert_eq!(test_hits(mock).await.len(), before, "zero wiremock hits");
    assert!(gets_on(mock, PROJECTS_PATH).await.is_empty());
    Ok(())
}

/// PD-47 / T7 M-6: the create card lists the constructs of the outgoing description, taken from
/// the request that is sent (verbatim wiki here), and shows its text.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_preview_lists_description_constructs() -> TestResult {
    let h = Harness::jira().await?;
    mount_create_stages(jira(&h)?).await;
    let p = json!({ "project": "Alpha Beta", "issuetype": "Bug", "summary": "Card",
                    "description": "{toc} see [~jdoe] and [docs|https://docs.example]",
                    "body_format": "wiki" });
    let id = queued(&h, p).await?;
    let pv = preview(&h, &id)?;
    match &pv.body {
        PreviewBody::WriteSummary {
            sentence,
            rows,
            constructs,
            ..
        } => {
            assert!(
                sentence.contains("ABC") && sentence.contains("Bug"),
                "{sentence}"
            );
            let c = constructs.as_ref().ok_or("no constructs")?;
            assert_eq!(c.macros, ["toc"]);
            assert_eq!(c.mentions, ["jdoe"]);
            assert_eq!(c.links, ["https://docs.example"]);
            assert!(
                rows.iter()
                    .any(|(k, v)| k == "Description" && v.contains("see")),
                "{rows:?}"
            );
        }
        other => return Err(format!("not the create card: {other:?}").into()),
    }
    // Nothing fetched reaches the agent before a decision (§4.5).
    let line = h.status(&id).await.to_json_line();
    assert!(
        !line.contains("Operations") && !line.contains("Story"),
        "{line}"
    );
    Ok(())
}

// ---- T12 review fixes ---------------------------------------------------------------------------

/// A required createmeta field of `schema` with `allowed` values.
fn choice_field(id: &str, name: &str, schema: Value, allowed: Value) -> Value {
    json!({"required": true, "schema": schema, "name": name, "fieldId": id,
           "hasDefaultValue": false, "operations": ["set"], "allowedValues": allowed})
}

/// The `Bug` fields page of `values` (one page, complete).
fn one_page(values: Vec<Value>) -> Value {
    json!({"maxResults": 50, "startAt": 0, "total": values.len(), "isLast": true,
           "values": values})
}

/// Projects and issue types as usual; the `Bug` fields are `page`.
async fn mount_fields_page(mock: &MockDc, page: &Value) {
    mock.json(PROJECTS_PATH, 200, fixtures::JIRA_PROJECTS).await;
    mock.json(
        &issuetypes_path("ABC"),
        200,
        fixtures::JIRA_CREATEMETA_ISSUETYPES,
    )
    .await;
    mock.json(BUG_FIELDS, 200, &page.to_string()).await;
}

/// Picks `label` in the pre-added input `path` as the approvals UI does, and waits for the
/// re-enrichment the edit starts.
async fn choose(h: &Harness, id: &str, path: &str, label: &str) -> TestResult {
    let rev = h.approver().rev(id).map_err(de)?;
    h.approver().choose_preadded(id, path, label).map_err(de)?;
    rev_after(h, id, rev.counter).await
}

/// T12 review I1: the approver picks labels; core sends each as the Jira value createmeta gave:
/// `{"id"}` when the allowed value has an id, else `{"value"}`, in an array for an `array` of
/// `option`. `WRITE_EDITED` records the params that run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i1_chosen_labels_go_out_in_the_jira_shape() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    let option = json!({"type": "option"});
    let page = one_page(vec![
        choice_field(
            "customfield_10200",
            "Team",
            option.clone(),
            json!([{"id": "10400", "value": "Platform"}, {"id": "10401", "value": "Ops"}]),
        ),
        choice_field(
            "customfield_10300",
            "Areas",
            json!({"type": "array", "items": "option"}),
            json!([{"id": "1", "value": "UI"}, {"id": "2", "value": "API"}]),
        ),
        choice_field(
            "customfield_10400",
            "Site",
            option.clone(),
            json!([{"id": "20001"}]),
        ),
        choice_field(
            "customfield_10500",
            "Tier",
            option,
            json!([{"value": "Gold"}, {"value": "Silver"}]),
        ),
    ]);
    mount_fields_page(mock, &page).await;
    approvable_server(mock).await;
    let id = queued(&h, params("Four choices")).await?;
    let p = preview(&h, &id)?;
    match &input(&p, "fields.customfield_10400")?.kind {
        InputKind::Choice(allowed) => {
            assert_eq!(allowed.as_slice(), ["20001"]);
            assert!(!allowed.is_multiple(), "an option is a single pick");
        }
        other => return Err(format!("not a choice: {other:?}").into()),
    }
    match &input(&p, "fields.customfield_10300")?.kind {
        InputKind::Choice(allowed) => assert!(allowed.is_multiple(), "an array is a multi-pick"),
        other => return Err(format!("not a choice: {other:?}").into()),
    }
    for (path, label) in [
        ("fields.customfield_10200", "Platform"),
        ("fields.customfield_10300", "UI"),
        ("fields.customfield_10400", "20001"),
        ("fields.customfield_10500", "Gold"),
    ] {
        choose(&h, &id, path, label).await?;
    }
    let p = preview(&h, &id)?;
    assert!(
        !p.warnings
            .iter()
            .any(|w| w.id == WarningId::MissingRequiredFields),
        "{:?}",
        p.warnings
    );
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let want = json!({
        "customfield_10200": {"id": "10400"},
        "customfield_10300": [{"id": "1"}],
        "customfield_10400": {"id": "20001"},
        "customfield_10500": {"value": "Gold"}
    });
    let body = sent_create(mock).await?;
    for (k, v) in want.as_object().ok_or("not an object")? {
        assert_eq!(&body["fields"][k], v, "{k}");
    }
    let edited = records(&h, &id, EventType::WRITE_EDITED).await?;
    assert_eq!(edited.len(), 4);
    assert_eq!(
        edited.last().map(|e| e["edited"]["fields"].clone()),
        Some(want)
    );
    Ok(())
}

/// T12 review I1: a pick core cannot turn into a Jira value is refused, nothing logged: a label
/// whose allowed value has neither an id nor a value, and a text the input does not list.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i1_pick_without_a_jira_value_is_refused() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    let page = one_page(vec![choice_field(
        "customfield_10200",
        "Team",
        json!({"type": "option"}),
        json!([{"name": "Legacy"}, {"id": "7", "value": "Modern"}]),
    )]);
    mount_fields_page(mock, &page).await;
    let id = queued(&h, params("Unpickable")).await?;
    let path = "fields.customfield_10200";
    let refused = [
        h.approver().choose_preadded(&id, path, "Legacy"),
        h.approver().edit_preadded(&id, path, json!("Nope")),
    ];
    for res in refused {
        assert!(
            matches!(res, Err(DecisionError::EditRejected(_))),
            "{res:?}"
        );
    }
    assert!(records(&h, &id, EventType::WRITE_EDITED).await?.is_empty());
    assert!(
        records(&h, &id, EventType::DECISION_INVALID)
            .await?
            .is_empty()
    );
    assert!(h.approver().item(&id).is_some());
    Ok(())
}

/// M5 M-12: a multi-pick (an `array` of `option`) takes a list of the labels shown; core sends
/// each as its Jira value, joined into one array. A label the input does not list refuses the
/// whole edit, nothing logged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m12_array_choice_labels_mapped() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    let page = one_page(vec![choice_field(
        "customfield_10300",
        "Areas",
        json!({"type": "array", "items": "option"}),
        json!([{"id": "1", "value": "UI"}, {"id": "2", "value": "API"}, {"value": "Docs"}]),
    )]);
    mount_fields_page(mock, &page).await;
    approvable_server(mock).await;
    let id = queued(&h, params("Three areas")).await?;
    let path = "fields.customfield_10300";
    // T16: the form tells the UI this is a multi-pick (it sends a list of labels).
    match &input(&preview(&h, &id)?, path)?.kind {
        InputKind::Choice(allowed) => assert!(allowed.is_multiple()),
        other => return Err(format!("not a choice: {other:?}").into()),
    }
    // Unknown (or ambiguous) labels refuse the edit; nothing is logged, the revision stays.
    let rev = h.approver().rev(&id).map_err(de)?;
    let res = h.approver().edit_preadded(&id, path, json!(["UI", "Nope"]));
    assert!(
        matches!(res, Err(DecisionError::EditRejected(_))),
        "{res:?}"
    );
    assert!(records(&h, &id, EventType::WRITE_EDITED).await?.is_empty());
    assert_eq!(h.approver().rev(&id).map_err(de)?, rev);
    // The listed labels go out as one array of Jira values, in the order picked.
    h.approver()
        .edit_preadded(&id, path, json!(["API", "Docs", "UI"]))
        .map_err(de)?;
    rev_after(&h, &id, rev.counter).await?;
    let p = preview(&h, &id)?;
    assert!(p.approvable, "{:?}", p.warnings);
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let want = json!([{"id": "2"}, {"value": "Docs"}, {"id": "1"}]);
    assert_eq!(
        sent_create(mock).await?["fields"]["customfield_10300"],
        want
    );
    let edited = records(&h, &id, EventType::WRITE_EDITED).await?;
    assert_eq!(edited.len(), 1);
    assert_eq!(edited[0]["edited"]["fields"]["customfield_10300"], want);
    Ok(())
}

/// T12 review M5: the cuts are visible: a choice of the first 10 of 12 values says so in its
/// label, and a deny that attaches the lists counts what they leave out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cut_lists_say_what_they_leave_out() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    let allowed: Vec<Value> = (0..12)
        .map(|n| json!({"id": format!("{}", 600 + n), "value": format!("V{n}")}))
        .collect();
    let mut values = vec![choice_field(
        "customfield_10200",
        "Team",
        json!({"type": "option"}),
        json!(allowed),
    )];
    values.extend((1..=101).map(|n| {
        json!({"required": true, "schema": {"type": "string"}, "name": format!("F{n}"),
               "fieldId": format!("customfield_{}", 40_000 + n), "hasDefaultValue": false})
    }));
    mount_fields_page(mock, &one_page(values)).await;
    let id = queued(&h, params("Many missing")).await?;
    let p = preview(&h, &id)?;
    let team = input(&p, "fields.customfield_10200")?;
    assert_eq!(
        team.label,
        "Team (customfield_10200), 10 of 12 values listed"
    );
    match &team.kind {
        InputKind::Choice(allowed) => assert_eq!(allowed.as_slice().len(), 10),
        other => return Err(format!("not a choice: {other:?}").into()),
    }
    h.approver()
        .deny_with(
            &id,
            "too many",
            DenyDetails::MissingFields {
                include_allowed_values: true,
            },
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
    let d = details(&env)?;
    assert_eq!(d["missing_fields"].as_array().map(Vec::len), Some(100));
    assert_eq!(d["missing_fields_total"], json!(102));
    let first = &d["missing_fields"][0];
    assert_eq!(first["allowed_values"].as_array().map(Vec::len), Some(10));
    assert_eq!(first["allowed_values_total"], json!(12));
    // A field whose list is complete carries no count.
    assert!(d["missing_fields"][1].get("allowed_values_total").is_none());
    Ok(())
}

/// T12 review M7: a missing `number` field (Jira takes decimals) is a number input, not an
/// integer one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_number_field_is_a_number_input() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    let points = json!({"required": true, "schema": {"type": "number"}, "name": "Points",
                        "fieldId": "customfield_10106", "hasDefaultValue": false});
    mount_fields_page(mock, &one_page(vec![points])).await;
    let id = queued(&h, params("Estimate")).await?;
    let p = preview(&h, &id)?;
    let input = input(&p, "fields.customfield_10106")?;
    assert_eq!(input.kind, InputKind::Number);
    assert_eq!(input.label, "Points (customfield_10106)");
    Ok(())
}

/// PD-49 / T12 review M10: a create screen of 1000 fields: pages 2..4 are fetched in one round and
/// no fifth; the list is cut, which an Info says; Approve stays enabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn field_pages_stop_at_four_with_an_info() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.json(PROJECTS_PATH, 200, fixtures::JIRA_PROJECTS).await;
    mock.json(
        &issuetypes_path("ABC"),
        200,
        fixtures::JIRA_CREATEMETA_ISSUETYPES,
    )
    .await;
    let page = |start: u64| {
        let values: Vec<Value> = (start..start + 50)
            .map(|n| {
                json!({"required": false, "schema": {"type": "string"}, "name": format!("F{n}"),
                       "fieldId": format!("customfield_{}", 50_000 + n),
                       "hasDefaultValue": false})
            })
            .collect();
        let body = json!({"maxResults": 50, "startAt": start, "total": 1000, "isLast": false,
                          "values": values});
        mock.response(200)
            .set_body_raw(body.to_string(), "application/json")
    };
    Mock::given(method("GET"))
        .and(path(mock.path(BUG_FIELDS)))
        .and(query_param_is_missing("startAt"))
        .respond_with(page(0))
        .mount(mock.server())
        .await;
    for start in [50u64, 100, 150, 200] {
        Mock::given(method("GET"))
            .and(path(mock.path(BUG_FIELDS)))
            .and(query_param("startAt", start.to_string().as_str()))
            .respond_with(page(start))
            .mount(mock.server())
            .await;
    }
    let id = queued(&h, params("Huge screen")).await?;
    let mut starts: Vec<Option<String>> = gets_on(mock, BUG_FIELDS)
        .await
        .iter()
        .map(|r| query(r, "startAt"))
        .collect();
    starts.sort();
    assert_eq!(
        starts,
        [
            None,
            Some("100".to_owned()),
            Some("150".to_owned()),
            Some("50".to_owned())
        ]
    );
    let p = preview(&h, &id)?;
    assert!(p.approvable);
    let info = p
        .warnings
        .iter()
        .find(|w| w.id == WarningId::RequiredFieldListIncomplete)
        .ok_or("no incomplete-list warning")?;
    assert_eq!(info.level, Level::Info);
    assert_eq!(
        info.text,
        "required-field list incomplete: 4 of 20 pages read"
    );
    Ok(())
}

/// A harness whose enrichment GETs hold after their record is parked (Task 24 I-2), the create
/// stages mounted and a create submitted; returns once stage 1 holds.
async fn create_held_after_stage1(
    pause: &std::sync::Arc<Pause>,
) -> Result<(Harness, String), TestError> {
    let h = Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            pause_after_get: Some(pause.clone()),
            ..TestHooks::none()
        })
        .start()
        .await?;
    mount_create_stages(jira(&h)?).await;
    let id = request_id(&h.submit(CREATE, params("Stopped")).await)?;
    pause.reached.notified().await;
    Ok((h, id))
}

/// After the request ended: stage 1's record committed before `CANCELLED`, no later stage's GET
/// left.
async fn stopped_after_stage1(h: &Harness, id: &str) -> TestResult {
    assert_eq!(
        h.event_types(id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::CANCELLED
        ]
    );
    let fetch = records(h, id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(fetch[0]["purpose"], "resolve");
    let mock = jira(h)?;
    assert_eq!(gets_on(mock, PROJECTS_PATH).await.len(), 1);
    assert!(gets_on(mock, &issuetypes_path("ABC")).await.is_empty());
    assert!(gets_on(mock, BUG_FIELDS).await.is_empty());
    Ok(())
}

/// T12 review M1: a client cancel between stages (stage 1 answered, its record parked): the
/// record is committed, the enrichment stops, stage 2 never leaves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_between_stages_stops_the_enrichment() -> TestResult {
    let pause = Pause::new();
    let (h, id) = create_held_after_stage1(&pause).await?;
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    // The enrichment goes on and finds the request ended.
    pause.release.notify_one();
    tokio::time::sleep(Duration::from_millis(300)).await;
    stopped_after_stage1(&h, &id).await
}

/// T12 review M1: a shutdown between stages ends the create like a cancel; nothing is logged or
/// sent after `APP_STOP`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_between_stages_stops_the_enrichment() -> TestResult {
    let pause = Pause::new();
    let (h, id) = create_held_after_stage1(&pause).await?;
    let report = h.core().shutdown(ShutdownReason::Quit).await;
    assert!(
        report.app_stop_logged && report.cancelled == 1,
        "{report:?}"
    );
    // The enrichment goes on after `APP_STOP` and finds the request ended.
    pause.release.notify_one();
    tokio::time::sleep(Duration::from_millis(300)).await;
    stopped_after_stage1(&h, &id).await?;
    let last = h
        .audit_records()
        .await?
        .into_iter()
        .max_by_key(|r| r.seq)
        .ok_or("empty log")?;
    assert_eq!(last.event_type, EventType::APP_STOP);
    Ok(())
}
