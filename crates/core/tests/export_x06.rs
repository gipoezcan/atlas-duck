#![cfg(feature = "testing")]
//! X-06 through the compliance export (SC2, §8.10, M10 T7): every payload kind the core writes,
//! fetched, released, denied, edited, delivered and executed, is in `events.jsonl` decrypted,
//! byte for byte what the audit API decrypts.

mod common;

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::{EventType, ExportControl, RustChosenPath, TimeRange};
use atlas_duck_core::Edits;
use atlas_duck_core::testing::Harness;
use atlas_duck_ipc::envelope::Status;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::jira::mount_create_stages;
use common::{TestError, TestResult, de, request_id};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const SEARCH: &str = "jira.search";
const CREATE: &str = "jira.issue.create";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

/// `(event_type, request_id, plaintext)` of one exported row.
type Exported = (String, Option<String>, Vec<u8>);

/// Every exported row, the plaintext from `payload_b64` checked against `payload_sha256`.
fn exported(dir: &std::path::Path) -> Result<Vec<Exported>, TestError> {
    let text = std::fs::read_to_string(dir.join("events.jsonl"))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let v: Value = serde_json::from_str(line)?;
        let plain = STANDARD.decode(v["payload_b64"].as_str().ok_or("no payload_b64")?)?;
        let digest: [u8; 32] = Sha256::digest(&plain).into();
        assert_eq!(v["payload_sha256"], hex::encode(digest));
        out.push((
            v["event_type"].as_str().ok_or("no event_type")?.to_owned(),
            v["request_id"].as_str().map(str::to_owned),
            plain,
        ));
    }
    Ok(out)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x06_six_payload_kinds_in_export() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.json("/rest/api/2/search", 200, fixtures::JIRA_SEARCH_PAGE)
        .await;
    mount_create_stages(mock).await;
    mock.json("/rest/api/2/issue", 201, fixtures::JIRA_ISSUE_CREATED)
        .await;

    // A search released (fetched, released, delivered) and one denied.
    let released = queued(&h, SEARCH, json!({ "jql": "project = ABC" })).await?;
    h.approver().release(&released).map_err(de)?;
    assert_eq!(h.await_(&released, 5000).await.status, Status::Released);
    let denied = queued(&h, SEARCH, json!({ "jql": "project = XYZ" })).await?;
    h.approver().deny(&denied, "not needed").map_err(de)?;
    assert_eq!(h.await_(&denied, 5000).await.status, Status::Denied);
    // A create edited, then approved and executed.
    let write = queued(
        &h,
        CREATE,
        json!({ "project": "ABC", "issuetype": "Bug", "summary": "Fix login" }),
    )
    .await?;
    let rev = h.approver().rev(&write).map_err(de)?;
    let mut set = Map::new();
    set.insert("summary".into(), json!("Fix login, edited"));
    h.approver()
        .edit(
            &write,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
        .map_err(de)?;
    let mut bumped = false;
    for _ in 0..500 {
        if h.approver()
            .item(&write)
            .is_some_and(|i| i.candidate_rev.counter > rev.counter && i.approvable)
        {
            bumped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(bumped, "the edit never produced an approvable revision");
    h.approver().approve(&write).map_err(de)?;
    assert_eq!(h.await_(&write, 10_000).await.status, Status::Succeeded);

    // The export of the whole log.
    let out = tempfile::tempdir()?;
    let store = h.store();
    let chosen = RustChosenPath::from_native_dialog(out.path().to_path_buf());
    let receipt = tokio::task::spawn_blocking(move || {
        let cancel = AtomicBool::new(false);
        let progress = |_: u64, _: u64| {};
        store.export(
            TimeRange::all(),
            chosen,
            &ExportControl {
                progress: &progress,
                cancel: &cancel,
            },
        )
    })
    .await??;
    let rows = exported(&out.path().join(&receipt.dir_name))?;
    assert_eq!(rows.len() as u64, receipt.rows);

    // Each kind is in the export, decrypted to exactly what the audit API decrypts.
    let kinds = [
        (&released, EventType::READ_FETCHED),
        (&released, EventType::READ_RELEASED),
        (&released, EventType::DELIVERED),
        (&denied, EventType::READ_DENIED),
        (&write, EventType::WRITE_EDITED),
        (&write, EventType::WRITE_APPROVED),
        (&write, EventType::WRITE_EXECUTED),
    ];
    for (id, kind) in kinds {
        let api: Vec<Value> = h
            .events(id)
            .await?
            .into_iter()
            .filter(|(t, _)| *t == kind)
            .map(|(_, p)| p)
            .collect();
        assert!(!api.is_empty(), "no {kind:?} for {id}");
        let in_export: Vec<Value> = rows
            .iter()
            .filter(|(t, r, _)| t == kind.as_str() && r.as_deref() == Some(id.as_str()))
            .map(|(_, _, p)| serde_json::from_slice(p))
            .collect::<Result<_, _>>()?;
        assert_eq!(in_export, api, "{kind:?} of {id}");
    }
    let one = |id: &str, kind: EventType| -> Result<String, TestError> {
        rows.iter()
            .find(|(t, r, _)| t == kind.as_str() && r.as_deref() == Some(id))
            .map(|(_, _, p)| String::from_utf8_lossy(p).into_owned())
            .ok_or_else(|| format!("no {kind:?}").into())
    };
    // fetched: the instance's search page; denied: the reason; edited: both summaries;
    // executed: the 201 of the create.
    let fetched: Value = serde_json::from_str(&one(&released, EventType::READ_FETCHED)?)?;
    assert_eq!(fetched["responses"][0]["status"], 200);
    assert!(one(&denied, EventType::READ_DENIED)?.contains("not needed"));
    let edited = one(&write, EventType::WRITE_EDITED)?;
    assert!(edited.contains("\"Fix login\""), "{edited}");
    assert!(edited.contains("Fix login, edited"), "{edited}");
    let executed: Value = serde_json::from_str(&one(&write, EventType::WRITE_EXECUTED)?)?;
    assert_eq!(executed["response"]["status"], 201);
    Ok(())
}

/// RF-4: a write whose outcome a crash left unknown is in the export as its reconciliation
/// wrote it, `WRITE_OUTCOME_UNKNOWN {reason: crash}`, decrypted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf4_crash_outcome_unknown_in_export() -> TestResult {
    let mut h = Harness::jira().await?;
    let mock = jira(&h)?;
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
    let id = queued(
        &h,
        "jira.issue.transition",
        json!({ "key": "ABC-1", "transition": "Done" }),
    )
    .await?;
    // The stale check's record commits, then the core writes nothing more: a crash.
    let freeze = h.plan().freeze_after(EventType::PREVIEW_FETCH);
    h.approver().approve(&id).map_err(de)?;
    tokio::time::timeout(Duration::from_secs(20), freeze.wait())
        .await
        .map_err(|_| "the crash point was never reached")?;
    h.crash_and_restart().await?;

    let out = tempfile::tempdir()?;
    let store = h.store();
    let chosen = RustChosenPath::from_native_dialog(out.path().to_path_buf());
    let receipt = tokio::task::spawn_blocking(move || {
        let cancel = AtomicBool::new(false);
        let progress = |_: u64, _: u64| {};
        store.export(
            TimeRange::all(),
            chosen,
            &ExportControl {
                progress: &progress,
                cancel: &cancel,
            },
        )
    })
    .await??;
    let rows = exported(&out.path().join(&receipt.dir_name))?;
    let unknown: Vec<Value> = rows
        .iter()
        .filter(|(t, r, _)| {
            t == EventType::WRITE_OUTCOME_UNKNOWN.as_str() && r.as_deref() == Some(id.as_str())
        })
        .map(|(_, _, p)| serde_json::from_slice(p))
        .collect::<Result<_, _>>()?;
    assert_eq!(unknown.len(), 1, "{unknown:?}");
    assert_eq!(unknown[0]["reason"], "crash");
    assert_eq!(unknown[0]["request_index"], 0);
    Ok(())
}
