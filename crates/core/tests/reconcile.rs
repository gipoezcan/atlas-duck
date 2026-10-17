#![cfg(feature = "testing")]
//! `Core::start` (Task 28): the start order, `APP_START`, `pats_deleted`, the crash
//! reconciliation end to end (I-26, the same predicate as `Model::Crash`), the startup notice,
//! the RF-4 flag after a crash and S-15 (a panicking read leaves nothing but the encrypted
//! `REQUEST_RECEIVED` payload behind).
//!
//! A crash is `FaultPlan::freeze_after(type)`: the append of that type commits, then the core
//! writes nothing more (its port answers `Closed`); `Harness::crash_and_restart` then starts a new
//! `Core` over the same store.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use atlas_duck_atlassian::CredentialProvider;
use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::{EventType, RestoreReport};
use atlas_duck_core::payloads::{EventCtx, InvalidReason, SubmittedDecision, decision_invalid};
use atlas_duck_core::testing::{
    Channel, FakeScriptRunner, FaultPlan, Freeze, Harness, InstanceAt, ScriptPlan,
};
use atlas_duck_core::{Decision, DecisionKind, HookPoint, RunEnd, TestHooks};
use atlas_duck_ipc::build_info::APP_VERSION;
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_preview::warning::WarningId;
use atlas_duck_registry::Product;
use common::{TestError, TestResult, de, exit, request_id};
use serde_json::{Map, Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path, query_param};

const ISSUE: &str = "jira.issue.get";
const SEARCH: &str = "jira.search";
const CREATE: &str = "jira.issue.create";
const COMMENT: &str = "jira.comment.add";
const TRANSITION: &str = "jira.issue.transition";
const ASSIGN: &str = "jira.issue.assign";
const PAGE_UPDATE: &str = "confluence.page.update";
const PAGE_MOVE: &str = "confluence.page.move";
const ATTACHMENT_UPLOAD: &str = "confluence.attachment.upload";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no confluence mock".into())
}

async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    Ok(id)
}

/// Waits for the crash point (the append of the armed type committed).
async fn tripped(f: &Freeze) -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), f.wait())
        .await
        .map_err(|_| "the crash point was never reached")?;
    Ok(())
}

fn page_at(version: u64) -> String {
    let mut page: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE).unwrap_or(Value::Null);
    page["version"]["number"] = json!(version);
    page.to_string()
}

fn create_params(summary: &str) -> Value {
    json!({ "project": "ABC", "issuetype": "Bug", "summary": summary, "body_format": "wiki" })
}

/// A transition write in the queue (both enrichment GETs done); the next `PREVIEW_FETCH` is the
/// stale check.
async fn queued_transition(h: &Harness) -> Result<String, TestError> {
    let mock = jira(h)?;
    mock.json(
        "/rest/api/2/issue/ABC-1/transitions",
        200,
        fixtures::JIRA_TRANSITIONS,
    )
    .await;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    queued(
        h,
        TRANSITION,
        json!({ "key": "ABC-1", "transition": "Done" }),
    )
    .await
}

/// A queued `jira.issue.assign` of `ABC-1` to `jdoe` (T15: stale-ruled, PD-52).
async fn queued_assign(h: &Harness) -> Result<String, TestError> {
    let mock = jira(h)?;
    mock.json(
        "/rest/api/2/user/assignable/search",
        200,
        r#"[{"name":"jdoe","key":"JIRAUSER1","displayName":"Jane Doe"}]"#,
    )
    .await;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    queued(h, ASSIGN, json!({ "key": "ABC-1", "assignee": "jdoe" })).await
}

async fn queued_page_update(h: &Harness) -> Result<String, TestError> {
    let mock = wiki(h)?;
    mock.confluence_user_current(
        atlas_duck_atlassian::testing::UserKind::Known,
        TEST_USER,
        TEST_USER_KEY,
    )
    .await;
    mock.json("/rest/api/content/65537", 200, &page_at(5)).await;
    queued(
        h,
        PAGE_UPDATE,
        json!({ "id": "65537", "base_version": 5, "body": "<p>New text.</p>", "body_format": "storage" }),
    )
    .await
}

/// A move of page 65537 (version 5, under `Home`) under page 123400, a sibling, in the queue
/// (both enrichment GETs done); the next `PREVIEW_FETCH` is the stale check's identity call.
async fn queued_page_move(h: &Harness) -> Result<String, TestError> {
    let mock = wiki(h)?;
    mock.confluence_user_current(
        atlas_duck_atlassian::testing::UserKind::Known,
        TEST_USER,
        TEST_USER_KEY,
    )
    .await;
    mock.json("/rest/api/content/65537", 200, &page_at(5)).await;
    let parent = json!({
        "id": "123400", "type": "page", "status": "current", "title": "Release notes",
        "space": {"key": "DOC", "name": "Documentation"},
        "ancestors": [{"id": "65536", "type": "page", "status": "current", "title": "Home"}],
    });
    mock.json("/rest/api/content/123400", 200, &parent.to_string())
        .await;
    queued(h, PAGE_MOVE, json!({ "id": "65537", "parent": "123400" })).await
}

/// A replace of `notes.txt` (attachment `att3001`, version 2) on page 65537 in the queue (the
/// lookup done); the next `PREVIEW_FETCH` is the stale check's identity call.
async fn queued_attachment_replace(h: &Harness) -> Result<String, TestError> {
    let mock = wiki(h)?;
    mock.confluence_user_current(
        atlas_duck_atlassian::testing::UserKind::Known,
        TEST_USER,
        TEST_USER_KEY,
    )
    .await;
    let found = json!({"results": [{
        "id": "att3001", "type": "attachment", "status": "current", "title": "notes.txt",
        "version": {"number": 2},
    }], "start": 0, "limit": 50, "size": 1});
    mock.json(
        "/rest/api/content/65537/child/attachment",
        200,
        &found.to_string(),
    )
    .await;
    queued(
        h,
        ATTACHMENT_UPLOAD,
        json!({ "id": "65537", "filename": "notes.txt", "content_base64": "aGVsbG8gd29ybGQ=",
                "replace": true }),
    )
    .await
}

fn assert_outcome_unknown(env: &Envelope) {
    assert_eq!(env.status, Status::OutcomeUnknown, "{}", env.to_json_line());
    assert_eq!(exit(env), 6);
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
}

fn assert_abandoned(env: &Envelope) {
    assert_eq!(env.status, Status::Abandoned, "{}", env.to_json_line());
    assert_eq!(exit(env), 7);
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
}

/// After the restart: `await` says `outcome_unknown` with `data {target}`, and the startup notice
/// lists that very target.
async fn assert_listed_unknown(h: &Harness, id: &str, target: &str) -> TestResult {
    let env = h.await_(id, 10_000).await;
    assert_outcome_unknown(&env);
    assert_eq!(env.data, Some(json!({ "target": target })));
    let notice = h.core().startup_notice();
    let w = notice
        .iter()
        .find(|w| w.request_id == id)
        .ok_or("not in the startup notice")?;
    assert_eq!(w.target.as_deref(), Some(target));
    assert_eq!(w.request_index, 0);
    Ok(())
}

/// The request's records without the `DELIVERED` that an `await` adds.
async fn types(h: &Harness, id: &str) -> Result<Vec<EventType>, TestError> {
    let mut t = h.event_types(id).await?;
    t.retain(|e| *e != EventType::DELIVERED);
    Ok(t)
}

// ---- the start order and APP_START ----------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_order_and_pats_deleted() -> TestResult {
    let plan = FaultPlan::new();
    plan.record_trail(true);
    plan.record_appends(true);
    let gone = ["ins_gone_a".to_owned(), "ins_gone_b".to_owned()];
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .pats_deleted(gone.to_vec())
        .start()
        .await?;
    assert_eq!(
        plan.trail(),
        [
            "reconcile_after_crash",
            "reconcile_config_file",
            "append:APP_START",
            "append:INSTANCE_STATE_CHANGED",
            "append:INSTANCE_STATE_CHANGED",
            // PD-46: the field-name cache's start fill follows APP_START (start, result).
            "append:SYSTEM_FETCH",
            "append:SYSTEM_FETCH",
        ]
    );
    // One audit transaction (M3 review M-7); the fill's records are appends of their own.
    let calls: Vec<_> = plan
        .appends()
        .into_iter()
        .filter(|c| c.iter().all(|e| e.event_type != EventType::SYSTEM_FETCH))
        .collect();
    assert_eq!(
        calls.len(),
        1,
        "APP_START and the needs_token records are one batch"
    );
    assert_eq!(
        calls[0].iter().map(|e| e.event_type).collect::<Vec<_>>(),
        [
            EventType::APP_START,
            EventType::INSTANCE_STATE_CHANGED,
            EventType::INSTANCE_STATE_CHANGED,
        ]
    );
    let headers = h.store().recent_headers(Duration::from_secs(3600))?;
    let start = headers
        .iter()
        .find(|e| e.event_type == EventType::APP_START)
        .ok_or("no APP_START")?;
    // `target` carries the install id (§8.2).
    assert_eq!(start.target.as_deref(), Some(h.store().install_id()));
    let changed: Vec<_> = headers
        .iter()
        .filter(|e| e.event_type == EventType::INSTANCE_STATE_CHANGED)
        .collect();
    assert_eq!(
        changed
            .iter()
            .map(|e| e.instance_id.clone().unwrap_or_default())
            .collect::<Vec<_>>(),
        gone
    );
    let starts = h.events_of(EventType::APP_START).await?;
    assert_eq!(
        starts.first().map(|p| p["pats_deleted"].clone()),
        Some(json!(gone))
    );
    let states = h.events_of(EventType::INSTANCE_STATE_CHANGED).await?;
    assert_eq!(states.len(), 2);
    assert!(
        states.iter().all(|p| p["state"] == "needs_token"),
        "{states:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_start_and_needs_token_one_batch() -> TestResult {
    // A failing batch: the start fails and neither record was committed.
    let plan = FaultPlan::new();
    plan.record_appends(true);
    plan.fail_nth(EventType::INSTANCE_STATE_CHANGED, 1);
    let started = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .pats_deleted(vec!["ins_gone_a".to_owned()])
        .start()
        .await;
    let err = started.err().ok_or("the start must fail")?;
    assert!(
        matches!(
            err.downcast_ref::<atlas_duck_core::StartError>(),
            Some(atlas_duck_core::StartError::Audit(_))
        ),
        "{err}"
    );
    assert_eq!(plan.attempts(EventType::APP_START), 1);
    assert!(plan.appends().is_empty(), "nothing was committed");

    // Without the fault both are consecutive records.
    let h = Harness::builder()
        .jira("jira-main")
        .pats_deleted(vec!["ins_gone_a".to_owned()])
        .start()
        .await?;
    let headers = h.store().recent_headers(Duration::from_secs(3600))?;
    let at = headers
        .iter()
        .position(|e| e.event_type == EventType::APP_START)
        .ok_or("no APP_START")?;
    let next = headers.get(at + 1).ok_or("no record after APP_START")?;
    assert_eq!(next.event_type, EventType::INSTANCE_STATE_CHANGED);
    assert_eq!(next.seq, headers[at].seq + 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_start_effective_proxy_is_host_and_port_only() -> TestResult {
    let h = Harness::builder()
        .instance_at(
            "jira-main",
            Product::Jira,
            InstanceAt {
                base_url: "https://jira.corp.example".to_owned(),
                proxy: Some("proxy.corp.example:3128".to_owned()),
                ..InstanceAt::default()
            },
        )
        .start()
        .await?;
    let starts = h.events_of(EventType::APP_START).await?;
    let [p] = starts.as_slice() else {
        return Err(format!("{} APP_START records", starts.len()).into());
    };
    assert_eq!(
        p["effective_proxy"],
        json!({ "jira-main": "proxy.corp.example:3128" })
    );
    // No credentials of any kind in the record.
    assert!(!p.to_string().contains('@'), "{p}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_similarity_seed_is_recorded_in_app_start() -> TestResult {
    let plan = FaultPlan::new();
    plan.fail_recent_headers(true);
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .start()
        .await?;
    plan.fail_recent_headers(false);
    let starts = h.events_of(EventType::APP_START).await?;
    let [p] = starts.as_slice() else {
        return Err(format!("{} APP_START records", starts.len()).into());
    };
    assert_eq!(p["similarity_seed_failed"], true, "{p}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_start_payload_carries_version_proxy_and_the_app_fields() -> TestResult {
    let mut extra = Map::new();
    extra.insert("tray_host".into(), json!("windows"));
    // The app cannot override the two fields the core owns.
    extra.insert("app_version".into(), json!("0.0.0-forged"));
    let h = Harness::builder()
        .jira("jira-main")
        .confluence("wiki")
        .app_start_extra(extra)
        .start()
        .await?;
    let starts = h.events_of(EventType::APP_START).await?;
    let [p] = starts.as_slice() else {
        return Err(format!("{} APP_START records", starts.len()).into());
    };
    assert_eq!(p["app_version"], APP_VERSION);
    assert_eq!(p["install_id"], h.store().install_id());
    assert_eq!(p["tray_host"], "windows");
    assert_eq!(
        p["effective_proxy"],
        json!({ "jira-main": "direct", "wiki": "direct" })
    );
    assert!(p.get("config_read_only").is_none(), "{p}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_start_names_a_read_only_config() -> TestResult {
    let h = Harness::builder()
        .config_text("schema_version = 99\n")
        .start()
        .await?;
    let starts = h.events_of(EventType::APP_START).await?;
    let p = starts.first().ok_or("no APP_START")?;
    assert_eq!(
        p["config_read_only"],
        json!({ "schema_version": 99, "parsed": true })
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_start_logs_its_own_app_start() -> TestResult {
    let mut h = Harness::jira().await?;
    h.restart().await?;
    h.crash_and_restart().await?;
    assert_eq!(h.events_of(EventType::APP_START).await?.len(), 3);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_integrity_error_of_the_reconciliation_is_a_start_error_with_no_app_start() -> TestResult
{
    let plan = FaultPlan::new();
    plan.record_trail(true);
    plan.fail_crash_reconcile(true);
    let started = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .start()
        .await;
    let Err(e) = started else {
        return Err("the core started over an integrity error".into());
    };
    assert!(e.to_string().contains("audit store"), "{e}");
    // Nothing was appended after the failed reconciliation: no APP_START, no notices.
    // The config reconcile, which unblocks the prune, never ran (review I-2).
    assert_eq!(plan.trail(), ["reconcile_after_crash"]);
    Ok(())
}

// ---- the audit policy of config.toml (X-01) -------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_config_file_policy_is_reconciled_before_app_start() -> TestResult {
    let plan = FaultPlan::new();
    plan.record_trail(true);
    // A raise takes effect, a lowering and a lifted hold do not (§8.8); a hold is set.
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .extra_config("[audit]\nretention_days = 120\nlegal_hold = true\n")
        .start()
        .await?;
    let changed = h.events_of(EventType::CONFIG_CHANGED).await?;
    let retention = changed
        .iter()
        .find(|p| p["key"] == "retention_days")
        .ok_or("no retention record")?;
    assert_eq!(retention["source"], "file");
    assert_eq!(retention["applied"], true);
    assert_eq!(retention["new"], 120);
    let hold = h.events_of(EventType::LEGAL_HOLD_CHANGED).await?;
    assert_eq!(
        hold.first().map(|p| p["source"].clone()),
        Some(json!("file"))
    );
    assert_eq!(h.store().settings().retention_days, 120);
    assert!(h.store().settings().legal_hold);
    let trail = plan.trail();
    // After the crash reconciliation (review I-2), before anything else is appended.
    assert_eq!(
        trail.iter().take(2).map(String::as_str).collect::<Vec<_>>(),
        ["reconcile_after_crash", "reconcile_config_file"]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lower_retention_in_the_file_is_logged_and_not_applied() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .extra_config("[audit]\nretention_days = 95\n")
        .start()
        .await?;
    let changed = h.events_of(EventType::CONFIG_CHANGED).await?;
    let p = changed
        .iter()
        .find(|p| p["key"] == "retention_days")
        .ok_or("no retention record")?;
    assert_eq!(
        (p["source"].clone(), p["applied"].clone()),
        (json!("file"), json!(false))
    );
    assert_eq!(h.store().settings().retention_days, 100);
    Ok(())
}

// ---- after_restore (M2 handoff 3) -----------------------------------------------------------

fn restore_report(pats_deleted: Vec<String>) -> RestoreReport {
    RestoreReport {
        restore_seq: 1,
        new_chain_id: "chain".to_owned(),
        source_install_id: String::new(),
        source_chain_id: "source".to_owned(),
        replaced_db: None,
        records_lost: 0,
        pats_lost: true,
        pats_deleted,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_restore_reconciles_the_file_again_and_marks_the_deleted_pats() -> TestResult {
    let plan = FaultPlan::new();
    plan.record_trail(true);
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .start()
        .await?;
    let id = h.instance("jira-main").ok_or("no instance")?.id.clone();
    assert_eq!(h.instances().list().first().map(|i| i.state), Some("ok"));
    // The restore deleted this instance's PAT.
    h.credentials().delete(&id).map_err(|e| format!("{e:?}"))?;
    let before = plan.trail().len();
    h.core()
        .after_restore(&restore_report(vec![id.clone()]))
        .await?;
    assert_eq!(
        plan.trail().get(before..).map(<[String]>::to_vec),
        Some(vec![
            "reconcile_config_file".to_owned(),
            "append:INSTANCE_STATE_CHANGED".to_owned(),
        ])
    );
    let changed = h.events_of(EventType::INSTANCE_STATE_CHANGED).await?;
    assert_eq!(
        changed.last().map(|p| p["state"].clone()),
        Some(json!("needs_token"))
    );
    // The runtime follows: the instance answers `needs_token` now.
    assert_eq!(
        h.instances().list().first().map(|i| i.state),
        Some("needs_token")
    );
    Ok(())
}

// ---- I-26: the crash predicate ---------------------------------------------------------------

async fn crash_after_stale_check(h: &mut Harness, id: &str) -> TestResult {
    let freeze = h.plan().freeze_after(EventType::PREVIEW_FETCH);
    h.approver().approve(id).map_err(de)?;
    tripped(&freeze).await?;
    // The stale check's own record is the last one.
    assert_eq!(types(h, id).await?.last(), Some(&EventType::PREVIEW_FETCH));
    h.crash_and_restart().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_crash_after_stale_check_fetch_is_outcome_unknown_jira_transition() -> TestResult {
    let mut h = Harness::jira().await?;
    let id = queued_transition(&h).await?;
    crash_after_stale_check(&mut h, &id).await?;
    assert_listed_unknown(&h, &id, "ABC-1").await?;
    let t = types(&h, &id).await?;
    assert!(t.ends_with(&[EventType::PREVIEW_FETCH, EventType::WRITE_OUTCOME_UNKNOWN]));
    let unknown = h.events_of(EventType::WRITE_OUTCOME_UNKNOWN).await?;
    assert_eq!(
        unknown
            .last()
            .map(|p| (p["request_index"].clone(), p["reason"].clone())),
        Some((json!(0), json!("crash")))
    );
    Ok(())
}

/// I-26 for the stale rule M5 adds (T15): the assignee check's identity call committed, the crash
/// comes before anything else, and the restart reconciles it like the transition.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_crash_after_stale_check_fetch_is_outcome_unknown_jira_assign() -> TestResult {
    let mut h = Harness::jira().await?;
    let id = queued_assign(&h).await?;
    crash_after_stale_check(&mut h, &id).await?;
    assert_listed_unknown(&h, &id, "ABC-1").await?;
    let t = types(&h, &id).await?;
    assert!(t.ends_with(&[EventType::PREVIEW_FETCH, EventType::WRITE_OUTCOME_UNKNOWN]));
    let unknown = h.events_of(EventType::WRITE_OUTCOME_UNKNOWN).await?;
    assert_eq!(
        unknown
            .last()
            .map(|p| (p["request_index"].clone(), p["reason"].clone())),
        Some((json!(0), json!("crash")))
    );
    // Nothing was sent before the crash.
    let puts = jira(&h)?
        .received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "PUT")
        .count();
    assert_eq!(puts, 0);
    Ok(())
}

/// I-26 across a real reopen (M3 final review I-2): the store is shut down and opened again by
/// the real startup, whose `VERIFY` finds nothing, and the core reconciles the log from there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_reopened_store_reconciles_stale_check_crash() -> TestResult {
    let mut h = Harness::jira().await?;
    let id = queued_transition(&h).await?;
    let freeze = h.plan().freeze_after(EventType::PREVIEW_FETCH);
    h.approver().approve(&id).map_err(de)?;
    tripped(&freeze).await?;
    assert_eq!(
        types(&h, &id).await?.last(),
        Some(&EventType::PREVIEW_FETCH)
    );
    let verifies = |h: &Harness| -> Result<usize, TestError> {
        Ok(h.store()
            .recent_headers(Duration::from_secs(24 * 3600))?
            .iter()
            .filter(|e| e.event_type == EventType::VERIFY)
            .count())
    };
    let before = verifies(&h)?;
    h.reopen_and_restart().await?;
    // The real startup ran: `audit::open` left its `VERIFY` row.
    assert_eq!(
        verifies(&h)?,
        before + 1,
        "the reopen wrote no startup VERIFY"
    );
    assert!(h.store().open_incidents().is_empty());
    assert_listed_unknown(&h, &id, "ABC-1").await?;
    let t = types(&h, &id).await?;
    assert!(t.ends_with(&[EventType::PREVIEW_FETCH, EventType::WRITE_OUTCOME_UNKNOWN]));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_crash_after_stale_check_fetch_is_outcome_unknown_confluence_update() -> TestResult {
    let mut h = Harness::confluence().await?;
    let id = queued_page_update(&h).await?;
    crash_after_stale_check(&mut h, &id).await?;
    assert_listed_unknown(&h, &id, "65537").await
}

/// I-26 for the stale rule M7 adds (T17, `stale::PAGE_MOVE`): the move's stale-check record
/// committed, the crash comes before anything else, and the restart reconciles it as
/// `outcome_unknown` like the update; nothing was sent before the crash.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_crash_after_stale_check_fetch_is_outcome_unknown_confluence_move() -> TestResult {
    let mut h = Harness::confluence().await?;
    let id = queued_page_move(&h).await?;
    crash_after_stale_check(&mut h, &id).await?;
    assert_listed_unknown(&h, &id, "65537").await?;
    let t = types(&h, &id).await?;
    assert!(t.ends_with(&[EventType::PREVIEW_FETCH, EventType::WRITE_OUTCOME_UNKNOWN]));
    let unknown = h.events_of(EventType::WRITE_OUTCOME_UNKNOWN).await?;
    assert_eq!(
        unknown
            .last()
            .map(|p| (p["request_index"].clone(), p["reason"].clone())),
        Some((json!(0), json!("crash")))
    );
    let puts = wiki(&h)?
        .received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "PUT")
        .count();
    assert_eq!(puts, 0);
    Ok(())
}

/// I-26 for the attachment stale rule M7 adds (T20a, `stale::ATTACHMENT_REPLACE`): the replace's
/// stale-check record committed, the crash comes before anything else, and the restart reconciles
/// it as `outcome_unknown` like the update; nothing was sent before the crash.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_crash_after_stale_check_fetch_is_outcome_unknown_confluence_replace() -> TestResult {
    let mut h = Harness::confluence().await?;
    let id = queued_attachment_replace(&h).await?;
    crash_after_stale_check(&mut h, &id).await?;
    assert_listed_unknown(&h, &id, "65537").await?;
    let t = types(&h, &id).await?;
    assert!(t.ends_with(&[EventType::PREVIEW_FETCH, EventType::WRITE_OUTCOME_UNKNOWN]));
    let unknown = h.events_of(EventType::WRITE_OUTCOME_UNKNOWN).await?;
    assert_eq!(
        unknown
            .last()
            .map(|p| (p["request_index"].clone(), p["reason"].clone())),
        Some((json!(0), json!("crash")))
    );
    let posts = wiki(&h)?
        .received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
        .count();
    assert_eq!(posts, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_crash_after_post_approval_decision_stale() -> TestResult {
    let mut h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    // The POST never answers in time: the write stays `executing`.
    Mock::given(method("POST"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1/comment")))
        .respond_with(
            mock.response(201)
                .set_body_raw(fixtures::JIRA_COMMENT, "application/json")
                .set_delay(Duration::from_secs(30)),
        )
        .mount(mock.server())
        .await;
    let id = queued(
        &h,
        COMMENT,
        json!({ "key": "ABC-1", "body": "Reproduced.", "body_format": "wiki" }),
    )
    .await?;
    let rev = h.approver().rev(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    let freeze = h.plan().freeze_after(EventType::DECISION_STALE);
    // A second decision on the old revision, after the approval: `DECISION_STALE` (the request
    // is past its approval; it does not return to the queue).
    let late = h.decisions().decide(Decision {
        request_id: id.clone(),
        decision: DecisionKind::Approve,
        candidate_rev: rev,
        edits: None,
        redactions: None,
        reason: None,
        deny_details: None,
    });
    assert!(late.is_err(), "{late:?}");
    tripped(&freeze).await?;
    assert!(types(&h, &id).await?.contains(&EventType::DECISION_STALE));
    h.crash_and_restart().await?;
    assert_listed_unknown(&h, &id, "ABC-1").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_crash_after_post_approval_decision_invalid() -> TestResult {
    let mut h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    // The POST never answers in time: the write stays `executing`, so nothing ends the request
    // while the record is appended.
    Mock::given(method("POST"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1/comment")))
        .respond_with(
            mock.response(201)
                .set_body_raw(fixtures::JIRA_COMMENT, "application/json")
                .set_delay(Duration::from_secs(30)),
        )
        .mount(mock.server())
        .await;
    let id = queued(
        &h,
        COMMENT,
        json!({ "key": "ABC-1", "body": "Reproduced.", "body_format": "wiki" }),
    )
    .await?;
    h.approver().approve(&id).map_err(de)?;
    for _ in 0..1000 {
        let posts = jira(&h)?
            .received()
            .await
            .iter()
            .filter(|r| r.method.as_str() == "POST")
            .count();
        if posts > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        h.status(&id).await.status,
        Status::Executing,
        "{:?}",
        types(&h, &id).await?
    );
    let freeze = h.plan().freeze_after(EventType::DECISION_INVALID);
    // No decision call reaches `DECISION_INVALID` after an approval (they all answer stale in
    // `StaleCheck` / `Executing`); the record is appended as the store would see it.
    let ctx = EventCtx {
        request_id: Some(id.clone()),
        op_id: Some(COMMENT.to_owned()),
        op_class: Some("write".to_owned()),
        ..EventCtx::default()
    };
    let ev = decision_invalid(
        &ctx,
        InvalidReason::NotApprovable,
        1,
        SubmittedDecision::Approve,
        false,
    );
    h.port().append(ev)?;
    tripped(&freeze).await?;
    h.crash_and_restart().await?;
    assert_listed_unknown(&h, &id, "ABC-1").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_control_after_write_stale_is_abandoned() -> TestResult {
    let mut h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mock.confluence_user_current(
        atlas_duck_atlassian::testing::UserKind::Known,
        TEST_USER,
        TEST_USER_KEY,
    )
    .await;
    let content = mock.path("/rest/api/content/65537");
    let enrich_q = "body.storage,version,space,ancestors";
    // Enrichment sees v5 once, the refresh after the conflict sees v6; the stale check sees v5.
    for (version, once, priority) in [(5, true, 1u8), (6, false, 2u8)] {
        let mut m = Mock::given(method("GET"))
            .and(path(content.clone()))
            .and(query_param("expand", enrich_q))
            .respond_with(
                mock.response(200)
                    .set_body_raw(page_at(version), "application/json"),
            )
            .with_priority(priority);
        if once {
            m = m.up_to_n_times(1);
        }
        m.mount(mock.server()).await;
    }
    // M7 Task 15: the refresh at v6 reads the agent's base body (stage 2).
    common::confluence::mount_history_version(
        mock,
        "65537",
        5,
        &serde_json::from_str(&page_at(5))?,
    )
    .await;
    Mock::given(method("GET"))
        .and(path(content.clone()))
        .and(query_param("expand", "version"))
        .respond_with(
            mock.response(200)
                .set_body_raw(page_at(5), "application/json"),
        )
        .mount(mock.server())
        .await;
    Mock::given(method("PUT"))
        .and(path(content))
        .respond_with(mock.response(409).set_body_raw(
            fixtures::CONFLUENCE_VERSION_CONFLICT_409,
            "application/json",
        ))
        .mount(mock.server())
        .await;
    let params = json!({
        "id": "65537", "base_version": 5, "body": "<p>New text.</p>", "body_format": "storage"
    });
    let id = queued(&h, PAGE_UPDATE, params).await?;
    let rev1 = h.approver().rev(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    // Back in the queue after `WRITE_STALE` and the refresh `PREVIEW_FETCH`: the crash point.
    let mut back = false;
    for _ in 0..1000 {
        if h.approver()
            .item(&id)
            .is_some_and(|i| i.candidate_rev.counter > rev1.counter + 1)
        {
            back = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(back, "never back in the queue");
    let t = types(&h, &id).await?;
    assert_eq!(t.last(), Some(&EventType::PREVIEW_FETCH));
    assert!(t.contains(&EventType::WRITE_STALE));
    h.crash_and_restart().await?;
    // The approval was returned to the queue (`WRITE_STALE` after it): nothing was sent.
    let env = h.await_(&id, 10_000).await;
    assert_abandoned(&env);
    assert!(h.core().startup_notice().iter().all(|w| w.request_id != id));
    let t = types(&h, &id).await?;
    assert_eq!(t.last(), Some(&EventType::ABANDONED));
    assert!(!t.contains(&EventType::WRITE_OUTCOME_UNKNOWN));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_pending_read_abandoned() -> TestResult {
    let mut h = Harness::jira().await?;
    let mock = jira(&h)?;
    Mock::given(path(mock.path("/rest/api/2/issue/ABC-1")))
        .respond_with(
            mock.response(200)
                .set_body_raw(fixtures::JIRA_ISSUE, "application/json")
                .set_delay(Duration::from_secs(30)),
        )
        .mount(mock.server())
        .await;
    let env = h.submit(ISSUE, json!({ "key": "ABC-1" })).await;
    let id = request_id(&env)?;
    // The fetch is on the wire.
    for _ in 0..500 {
        if !mock.received().await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    h.crash_and_restart().await?;
    let env = h.await_(&id, 10_000).await;
    assert_abandoned(&env);
    assert_eq!(
        types(&h, &id).await?,
        [EventType::REQUEST_RECEIVED, EventType::ABANDONED]
    );
    assert!(h.core().startup_notice().is_empty());
    Ok(())
}

/// A Confluence read that crashed after the records of its user lookup and its identity GET
/// (PD-99, PD-93) and before `READ_FETCHED`: `PREVIEW_FETCH` is no write's, so the read is
/// abandoned like any pending read, never `outcome_unknown`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_identity_fetch_reconciles_as_read() -> TestResult {
    let pause = atlas_duck_core::Pause::new();
    let mut h = Harness::builder()
        .confluence("wiki")
        .hooks(TestHooks {
            pause_after_lookups: Some(pause.clone()),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let mock = wiki(&h)?;
    let storage = r#"<p>Owner <ri:user ri:userkey="key-jdoe"/>.</p>"#;
    common::confluence::mount_page(
        mock,
        "65537",
        &common::confluence::page_with_storage(storage),
    )
    .await;
    common::confluence::mount_users(mock, &[("key-jdoe", Some("jdoe"))]).await;
    let env = h
        .submit("confluence.page.get", json!({ "id": "65537" }))
        .await;
    let id = request_id(&env)?;
    // The lookup is committed; the identity GET's record is the crash point. Bounded: a change that
    // skips the hook fails here instead of hanging (T13 review I-3).
    tokio::time::timeout(Duration::from_secs(20), pause.reached.notified())
        .await
        .map_err(|_| "hook never reached")?;
    let freeze = h.plan().freeze_after(EventType::PREVIEW_FETCH);
    pause.release.notify_one();
    tripped(&freeze).await?;
    let fetches = h.events_of(EventType::PREVIEW_FETCH).await?;
    let purposes: Vec<&Value> = fetches.iter().map(|f| &f["purpose"]).collect();
    assert_eq!(purposes, [&json!("resolve"), &json!("identity")]);
    h.crash_and_restart().await?;
    let env = h.await_(&id, 10_000).await;
    assert_abandoned(&env);
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::PREVIEW_FETCH,
            EventType::ABANDONED,
        ]
    );
    assert!(h.core().startup_notice().is_empty());
    Ok(())
}

/// The same after the user lookup's record alone (the identity GET never ran).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_resolve_fetch_reconciles_as_read() -> TestResult {
    let mut h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let storage = r#"<p>Owner <ri:user ri:userkey="key-jdoe"/>.</p>"#;
    common::confluence::mount_page(
        mock,
        "65537",
        &common::confluence::page_with_storage(storage),
    )
    .await;
    common::confluence::mount_users(mock, &[("key-jdoe", Some("jdoe"))]).await;
    let freeze = h.plan().freeze_after(EventType::PREVIEW_FETCH);
    let env = h
        .submit("confluence.page.get", json!({ "id": "65537" }))
        .await;
    let id = request_id(&env)?;
    tripped(&freeze).await?;
    h.crash_and_restart().await?;
    let env = h.await_(&id, 10_000).await;
    assert_abandoned(&env);
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::ABANDONED,
        ]
    );
    assert!(h.core().startup_notice().is_empty());
    Ok(())
}

/// A harness whose script runner plays `plan` once.
async fn with_script(plan: ScriptPlan) -> Result<(Harness, Arc<FakeScriptRunner>), TestError> {
    let runner = FakeScriptRunner::new(vec![plan]);
    let h = Harness::builder()
        .jira("jira-main")
        .scripts(runner.clone())
        .start()
        .await?;
    Ok((h, runner))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_running_script_is_abandoned() -> TestResult {
    let (mut h, runner) =
        with_script(ScriptPlan::new(Vec::new(), RunEnd::Crashed).holding(60_000)).await?;
    let env = h.submit_script(json!({ "source": "return 1;" })).await;
    let id = request_id(&env)?;
    for _ in 0..1000 {
        if runner.starts() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    h.crash_and_restart().await?;
    assert_abandoned(&h.await_(&id, 10_000).await);
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::ABANDONED
        ]
    );
    assert!(h.core().startup_notice().is_empty());
    Ok(())
}

/// §11.3: a `SCRIPT_FAILED` that is not `direct` does not end its request; a script that sits
/// in the queue after a user kill (or after its result) is abandoned by a crash.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_script_awaiting_release_is_abandoned() -> TestResult {
    let end = RunEnd::Result {
        value: json!({ "n": 1 }),
        logs: Vec::new(),
        stderr: String::new(),
    };
    let (mut h, _runner) = with_script(ScriptPlan::new(Vec::new(), end)).await?;
    let env = h.submit_script(json!({ "source": "return 1;" })).await;
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    h.crash_and_restart().await?;
    assert_abandoned(&h.await_(&id, 10_000).await);
    let t = types(&h, &id).await?;
    assert_eq!(t.last(), Some(&EventType::ABANDONED));
    assert!(t.contains(&EventType::SCRIPT_FINISHED));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_killed_script_in_the_queue_is_abandoned() -> TestResult {
    let (mut h, runner) =
        with_script(ScriptPlan::new(Vec::new(), RunEnd::Crashed).holding(60_000)).await?;
    let env = h.submit_script(json!({ "source": "return 1;" })).await;
    let id = request_id(&env)?;
    for _ in 0..1000 {
        if runner.starts() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // The user kills the run: a non-terminal `SCRIPT_FAILED` and a release item.
    assert!(h.engine().kill_script(&id));
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let t = types(&h, &id).await?;
    assert!(t.contains(&EventType::SCRIPT_FAILED), "{t:?}");
    assert!(!t.contains(&EventType::CANCELLED));
    h.crash_and_restart().await?;
    assert_abandoned(&h.await_(&id, 10_000).await);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_a_second_start_finds_nothing_left() -> TestResult {
    let mut h = Harness::jira().await?;
    let id = queued_transition(&h).await?;
    crash_after_stale_check(&mut h, &id).await?;
    assert_eq!(h.core().startup_notice().len(), 1);
    // The records written by the first reconciliation are terminal: the next start is quiet.
    h.restart().await?;
    assert!(h.core().startup_notice().is_empty());
    assert_eq!(
        types(&h, &id)
            .await?
            .iter()
            .filter(|t| **t == EventType::WRITE_OUTCOME_UNKNOWN)
            .count(),
        1
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i26_startup_notice_lists_targets() -> TestResult {
    // One write dies mid-check, a second request was only enriched: the notice lists the
    // write's target, the other request is plainly abandoned, and the banner is asked for once.
    let mut h = Harness::both().await?;
    let tx = queued_transition(&h).await?;
    let page = queued_page_update(&h).await?;
    let freeze = h.plan().freeze_after(EventType::PREVIEW_FETCH);
    h.approver().approve(&tx).map_err(de)?;
    tripped(&freeze).await?;
    h.crash_and_restart().await?;
    let notice = h.core().startup_notice();
    assert_eq!(
        notice.iter().map(|w| w.target.clone()).collect::<Vec<_>>(),
        [Some("ABC-1".to_owned())]
    );
    assert_abandoned(&h.await_(&page, 10_000).await);
    let banners: Vec<_> = h
        .capture()
        .records()
        .into_iter()
        .filter(|c| c.channel == Channel::UiEvent && c.json.contains("check_target"))
        .collect();
    assert_eq!(banners.len(), 1, "{banners:?}");
    // No banner without a write to check.
    let quiet = Harness::jira().await?;
    assert!(
        quiet
            .capture()
            .records()
            .iter()
            .all(|c| !c.json.contains("check_target"))
    );
    Ok(())
}

// ---- RF-4 after a crash ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf4_create_after_crash_is_flagged() -> TestResult {
    let mut h = Harness::jira().await?;
    let mock = jira(&h)?;
    // The create's three enrichment stages (Task 12).
    common::jira::mount_create_stages(mock).await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    let first = queued(&h, CREATE, create_params("Fix login")).await?;
    let freeze = h.plan().freeze_after(EventType::WRITE_APPROVED);
    h.approver().approve(&first).map_err(de)?;
    tripped(&freeze).await?;
    h.crash_and_restart().await?;
    assert_eq!(h.core().startup_notice().len(), 1);
    // The agent resubmits the identical create: it is flagged, and still approvable.
    let second = queued(&h, CREATE, create_params("Fix login")).await?;
    let ap = h.approver();
    let row = ap.item(&second).ok_or("not queued")?;
    assert_eq!(row.similar_to.as_deref(), Some(first.as_str()));
    assert!(row.approvable);
    let preview = ap.open(&second).map_err(de)?.preview;
    let w = preview
        .warnings
        .iter()
        .find(|w| w.id == WarningId::SimilarRequest)
        .ok_or("no similar_request warning")?;
    assert_eq!(w.text, format!("similar to {first} outcome unknown"));
    assert_eq!(h.engine().similarity().seed_skipped(), 0);
    Ok(())
}

// ---- S-15 -------------------------------------------------------------------------------------

/// Every `tracing` event of the process, as text (message and fields).
#[derive(Default)]
struct LogCapture {
    lines: Mutex<Vec<String>>,
}

fn lines(c: &LogCapture) -> MutexGuard<'_, Vec<String>> {
    c.lines.lock().unwrap_or_else(|e| e.into_inner())
}

struct Collect(String);

impl tracing::field::Visit for Collect {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={value:?}", field.name()));
    }
}

struct Sink(Arc<LogCapture>);

impl tracing::Subscriber for Sink {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut c = Collect(event.metadata().target().to_owned());
        event.record(&mut c);
        lines(&self.0).push(c.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

fn log_capture() -> &'static Arc<LogCapture> {
    static CAPTURE: OnceLock<Arc<LogCapture>> = OnceLock::new();
    CAPTURE.get_or_init(|| {
        let c = Arc::new(LogCapture::default());
        // Global: the read task runs on a worker thread. Only this test installs one.
        let installed = tracing::subscriber::set_global_default(Sink(c.clone()));
        assert!(installed.is_ok(), "another global subscriber is installed");
        // The capture is live for events of any thread: without this the sentinel checks
        // below would pass over a sink that sees nothing (M-8).
        let probe = std::thread::spawn(|| tracing::info!("capture probe"));
        assert!(probe.join().is_ok());
        assert!(!lines(&c).is_empty(), "the capture saw no log line");
        c
    })
}

/// Counts the panics of the S-15 hook (its payload is this text) without hiding any other.
static HOOK_PANICS: AtomicUsize = AtomicUsize::new(0);

fn count_hook_panics() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if info.payload().downcast_ref::<&str>() == Some(&"read task panic (test hook)") {
                HOOK_PANICS.fetch_add(1, Ordering::SeqCst);
            }
            previous(info);
        }));
    });
}

fn files_under(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) -> TestResult {
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if p.is_dir() {
            files_under(&p, out)?;
        } else {
            out.push(p);
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s15_panic_mid_search_reconciles_next_start() -> TestResult {
    const SENTINEL: &str = "SENTINEL-JQL-7f3a91c2";
    let logs = log_capture().clone();
    count_hook_panics();
    let panics_before = HOOK_PANICS.load(Ordering::SeqCst);
    let mut h = Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            panic_on_jql: Some(SENTINEL.to_owned()),
            ..TestHooks::none()
        })
        .start()
        .await?;
    // The process dies with the panic (`panic = "abort"` in a release build): after
    // `REQUEST_RECEIVED` nothing more is committed.
    let freeze = h.plan().freeze_after(EventType::REQUEST_RECEIVED);
    let env = h
        .submit(SEARCH, json!({ "jql": format!("text ~ \"{SENTINEL}\"") }))
        .await;
    let id = request_id(&env)?;
    tripped(&freeze).await?;
    // The read task really ran into its panic.
    for _ in 0..1000 {
        if HOOK_PANICS.load(Ordering::SeqCst) > panics_before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(HOOK_PANICS.load(Ordering::SeqCst), panics_before + 1);
    // Let the unwinding finish before the process "dies".
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.crash_and_restart().await?;
    let env = h.await_(&id, 10_000).await;
    assert_abandoned(&env);
    assert_eq!(
        types(&h, &id).await?,
        [EventType::REQUEST_RECEIVED, EventType::ABANDONED]
    );
    // The sentinel is in no log line, no captured value and no plaintext of the store.
    assert!(
        lines(&logs).iter().all(|l| !l.contains(SENTINEL)),
        "{:?}",
        lines(&logs)
    );
    assert!(
        h.capture()
            .records()
            .iter()
            .all(|c| !c.json.contains(SENTINEL))
    );
    let headers = h.store().recent_headers(Duration::from_secs(3600))?;
    assert!(headers.iter().all(|e| !format!("{e:?}").contains(SENTINEL)));
    let mut files = Vec::new();
    files_under(h.data_dir(), &mut files)?;
    let mut scanned = 0;
    for f in files {
        // The instance lock is held open exclusively: there is nothing in it to read.
        if f.file_name().is_some_and(|n| n == "instance.lock") {
            continue;
        }
        let bytes = std::fs::read(&f)?;
        scanned += 1;
        assert!(
            !bytes
                .windows(SENTINEL.len())
                .any(|w| w == SENTINEL.as_bytes()),
            "the sentinel is in {}",
            f.display()
        );
    }
    assert!(scanned >= 3, "the database files were not scanned");
    // The encrypted `REQUEST_RECEIVED` payload does hold the query: it is the one place.
    let received = h.events(&id).await?;
    let (_, p) = received.first().ok_or("no record")?;
    assert!(p.to_string().contains(SENTINEL));
    Ok(())
}

// A restart without a crash point keeps every earlier test honest about the hook: it is only
// armed where a test arms it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn freeze_at_hook_arms_the_crash_point_at_start() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            freeze_at: Some(HookPoint::AfterAppend(EventType::APP_START)),
            ..TestHooks::none()
        })
        .start()
        .await?;
    // `APP_START` committed, then the core froze: a request cannot even be recorded.
    let env = h.submit(ISSUE, json!({ "key": "ABC-1" })).await;
    assert_ne!(env.status, Status::Pending, "{}", env.to_json_line());
    assert_eq!(h.events_of(EventType::APP_START).await?.len(), 1);
    assert!(h.events_of(EventType::REQUEST_RECEIVED).await?.is_empty());
    Ok(())
}
