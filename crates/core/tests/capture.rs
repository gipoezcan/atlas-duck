#![cfg(feature = "testing")]
//! S-16 capture-hook half (PD-12): every handler envelope, progress notification, `UiEvent` and
//! `DecisionApi`/`InstanceAdmin` return passes the capture, and no captured record carries the
//! PAT or fetched data. Task 29 repeats the sweeps over full flows.

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use atlas_duck_core::UiEvent;
use atlas_duck_core::testing::{Channel, Harness};
use atlas_duck_ipc::proto::{AwaitParams, ProgressNotification, ProgressSink};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use common::{TestResult, request_id};
use serde_json::json;

struct Drop0;
impl ProgressSink for Drop0 {
    fn progress(&self, _n: ProgressNotification) {}
}

fn random_hex() -> Result<String, Box<dyn std::error::Error>> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b)?;
    Ok(hex::encode(b))
}

/// The canary as it could appear: raw, fully percent-encoded, and base64 (standard and URL-safe,
/// at each of the three byte alignments inside a longer encoded string).
fn needles(canary: &str) -> Vec<String> {
    let mut out = vec![canary.to_owned()];
    out.push(canary.bytes().map(|b| format!("%{b:02X}")).collect());
    out.push(canary.bytes().map(|b| format!("%{b:02x}")).collect());
    for pad in 0..3usize {
        let mut bytes = vec![b'x'; pad];
        bytes.extend_from_slice(canary.as_bytes());
        for enc in [
            STANDARD.encode(&bytes),
            URL_SAFE.encode(&bytes),
            URL_SAFE_NO_PAD.encode(&bytes),
        ] {
            // Skip the characters the prefix touches and the padded tail.
            let skip = (pad * 4).div_ceil(3);
            let core: String = enc.trim_end_matches('=').chars().skip(skip).collect();
            let keep = core.len().saturating_sub(2);
            out.push(core.chars().take(keep).collect());
        }
    }
    out.retain(|n| n.len() >= 8);
    out
}

async fn exercise(h: &Harness) -> Result<String, Box<dyn std::error::Error>> {
    let id = request_id(&h.submit("jira.issue.get", json!({ "key": "ABC-1" })).await)?;
    h.status(&id).await;
    h.await_(&id, 20).await;
    let handler = h.handler();
    handler.requests_list(None, None, None).await;
    handler.instances_list().await;
    handler.doctor().await;
    handler
        .ops_describe("jira.issue.get", Some("jira-main"))
        .await;
    h.decisions().queue_list();
    h.decisions().queue_get(&id);
    h.instances().list();
    Ok(id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s16_capture_records_every_channel() -> TestResult {
    let h = Harness::jira().await?;
    let id = exercise(&h).await?;
    h.ui().emit(UiEvent::QueueChanged {
        request_ids: vec![id.clone()],
    });
    // A status change during an `await` is a progress notification.
    let handler = h.handler();
    let conn = h.default_conn().clone();
    let waiting = handler.await_request(
        &conn,
        AwaitParams {
            request_id: id.clone(),
            timeout_ms: Some(10_000),
        },
        &Drop0,
    );
    let expire = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        h.expire_now(&id).await
    };
    let (_env, expired) = tokio::join!(waiting, expire);
    assert!(expired);

    let records = h.capture().records();
    let channels: BTreeSet<String> = records.iter().map(|r| format!("{:?}", r.channel)).collect();
    for c in [
        Channel::Envelope,
        Channel::Progress,
        Channel::UiEvent,
        Channel::Decision,
        Channel::Instance,
    ] {
        assert!(channels.contains(&format!("{c:?}")), "no {c:?} record");
    }
    // Progress carries `{request_id, status}` only (§4.5).
    for p in h.capture().on(Channel::Progress) {
        let v: serde_json::Value = serde_json::from_str(&p.json)?;
        let keys: BTreeSet<&str> = v
            .as_object()
            .map(|o| o.keys().map(String::as_str).collect())
            .unwrap_or_default();
        assert_eq!(keys, BTreeSet::from(["request_id", "status"]));
    }
    assert!(
        records.iter().all(|r| !r.json.is_empty()),
        "every record serialized"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s16_pat_canary_never_captured() -> TestResult {
    let canary = format!("PATCANARY-{}", random_hex()?);
    let h = Harness::builder()
        .jira("jira-main")
        .pat(&canary)
        .start()
        .await?;
    // The PAT is stored (the harness put it in the in-memory keychain).
    let id = h.instance("jira-main").ok_or("instance")?.id.clone();
    assert!(h.credentials().contains(&id));
    exercise(&h).await?;
    let needles = needles(&canary);
    for r in h.capture().records() {
        for n in &needles {
            assert!(
                !r.json.contains(n.as_str()),
                "{:?} record carries the PAT",
                r.channel
            );
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s16_ui_events_carry_no_data_canary() -> TestResult {
    let h = Harness::jira().await?;
    let mock = h.mock("jira-main").ok_or("mock")?;
    let body = json!({ "key": "ABC-1", "fields": { "summary": "DATACANARY-summary" } });
    mock.json("/rest/api/2/issue/ABC-1", 200, &body.to_string())
        .await;
    let id = exercise(&h).await?;
    h.expire_now(&id).await;
    for r in h.capture().on(Channel::UiEvent) {
        assert!(!r.json.contains("DATACANARY"), "{}", r.json);
    }
    for r in h.capture().records() {
        assert!(
            !r.json.contains("DATACANARY"),
            "{:?}: {}",
            r.channel,
            r.json
        );
    }
    Ok(())
}
