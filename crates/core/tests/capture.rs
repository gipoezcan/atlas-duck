#![cfg(feature = "testing")]
//! S-16 capture-hook half (PD-12): every handler envelope, progress notification, `UiEvent` and
//! `DecisionApi`/`InstanceAdmin` return passes the capture, and no captured record, log line or
//! decrypted audit payload carries the PAT; no `UiEvent` carries fetched data. The sweeps run over
//! full flows (reads, writes, cancels, connection tests, token replacement).

mod common;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use atlas_duck_atlassian::CredentialProvider as _;
use atlas_duck_core::UiEvent;
use atlas_duck_core::testing::{Channel, Flow, Harness};
use atlas_duck_ipc::proto::{AwaitParams, ProgressNotification, ProgressSink};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use common::flows::{flow_harness, flow_harness_with_pat, mount_jira, mount_jira_with, run_flow};
use common::{TestResult, request_id};
use secrecy::SecretString;
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

/// The process-wide log capture (global because the core's tasks run on worker threads; no other
/// test in this binary installs a subscriber).
fn log_capture() -> &'static Arc<LogCapture> {
    static CAPTURE: OnceLock<Arc<LogCapture>> = OnceLock::new();
    CAPTURE.get_or_init(|| {
        let c = Arc::new(LogCapture::default());
        let installed = tracing::subscriber::set_global_default(Sink(c.clone())).is_ok();
        assert!(
            installed,
            "another tracing subscriber was installed first: the log sweep would be vacuous"
        );
        c
    })
}

/// Every flow but `Quit` once, numbered from `first`.
async fn all_flows(h: &Harness, first: usize) -> TestResult {
    for (n, f) in Flow::ALL_BUT_QUIT.iter().enumerate() {
        run_flow(h, *f, first + n)
            .await
            .map_err(|e| format!("{f:?}: {e}"))?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s16_capture_records_every_channel() -> TestResult {
    let h = flow_harness().await?;
    mount_jira(&h).await?;
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
    // And every kind of flow on top: reads, writes, cancels, connection tests, doctor.
    all_flows(&h, 100).await?;

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
    // The flows' decisions and connection tests passed the hook too.
    assert!(h.capture().on(Channel::Decision).len() > 10);
    assert!(!h.capture().on(Channel::Instance).is_empty());
    // A successful `hello` is captured too.
    assert!(
        h.capture()
            .on(Channel::Envelope)
            .iter()
            .any(|r| r.json.contains("\"build_id\""))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s16_pat_canary_never_captured() -> TestResult {
    let logs = log_capture().clone();
    let canary = format!("PATCANARY-{}", random_hex()?);
    let second = format!("PATCANARY-{}", random_hex()?);
    let h = flow_harness_with_pat(&canary).await?;
    mount_jira(&h).await?;
    // The PAT is stored (the harness put it in the in-memory keychain).
    let id = h.instance("jira-main").ok_or("instance")?.id.clone();
    assert!(h.credentials().contains(&id));
    let mock = h.mock("jira-main").ok_or("mock")?;
    // Reads, writes, cancels, connection tests; then the token is replaced and they run again.
    exercise(&h).await?;
    all_flows(&h, 10).await?;
    h.instances()
        .set_token("jira-main", SecretString::from(second.clone()), None)
        .await
        .map_err(|e| format!("{e:?}"))?;
    all_flows(&h, 50).await?;
    h.instances().retest_token("jira-main").await?;

    // Both PATs did go out, to the instance only (so the sweeps below are not vacuous): in the
    // `Authorization` header and nowhere else of the requests.
    let sent = mock.received().await;
    for pat in [&canary, &second] {
        let want = format!("Bearer {pat}");
        assert!(
            sent.iter().any(|r| r
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v == want)),
            "{pat} was never sent"
        );
        for r in &sent {
            for (name, value) in r.headers.iter() {
                if name.as_str() != "authorization" {
                    assert!(!value.to_str().unwrap_or_default().contains(pat.as_str()));
                }
            }
            assert!(!String::from_utf8_lossy(&r.body).contains(pat.as_str()));
            assert!(!r.url.as_str().contains(pat.as_str()));
        }
    }
    let mut all = needles(&canary);
    all.extend(needles(&second));
    for r in h.capture().records() {
        for n in &all {
            assert!(
                !r.json.contains(n.as_str()),
                "{:?} record carries the PAT",
                r.channel
            );
        }
    }
    // No log line carries it.
    for l in lines(&logs).iter() {
        for n in &all {
            assert!(!l.contains(n.as_str()), "log line carries the PAT: {l}");
        }
    }
    // No decrypted audit payload carries it.
    let records = h.audit_records().await?;
    assert!(records.len() > 50, "{} records", records.len());
    for r in &records {
        assert!(
            !r.payload.is_null(),
            "{:?} {} did not decrypt",
            r.event_type,
            r.seq
        );
        let text = serde_json::to_string(&r.payload)?;
        for n in &all {
            assert!(
                !text.contains(n.as_str()),
                "{:?} {} carries the PAT",
                r.event_type,
                r.seq
            );
        }
    }
    // The keychain holds the replacement.
    let stored = h.credentials().load(&id)?.ok_or("not stored")?;
    assert_eq!(stored.pat.expose_secret(), second);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s16_ui_events_carry_no_data_canary() -> TestResult {
    let h = flow_harness().await?;
    let body = json!({ "key": "ABC-1", "fields": { "summary": "DATACANARY-summary" } });
    mount_jira_with(&h, &body.to_string()).await?;
    let id = exercise(&h).await?;
    h.expire_now(&id).await;
    for r in h.capture().on(Channel::UiEvent) {
        assert!(!r.json.contains("DATACANARY"), "{}", r.json);
    }
    // Before any release nothing the core hands out carries it at all.
    for r in h.capture().records() {
        assert!(
            !r.json.contains("DATACANARY"),
            "{:?}: {}",
            r.channel,
            r.json
        );
    }
    // Over full flows the data reaches the agent (released) and the approver (previews), and
    // still no `UiEvent` and no progress notification carries it.
    let flows = [
        Flow::ReadRelease,
        Flow::ReadDeny,
        Flow::ReadCancelMidFetch,
        Flow::WriteApprove,
        Flow::ConnectionTest,
    ];
    for (n, f) in flows.iter().enumerate() {
        run_flow(&h, *f, 20 + n).await?;
    }
    let delivered = h
        .capture()
        .on(Channel::Envelope)
        .iter()
        .any(|r| r.json.contains("DATACANARY"));
    assert!(
        delivered,
        "the data never reached the agent: the sweep is vacuous"
    );
    assert!(!h.capture().on(Channel::UiEvent).is_empty());
    for ch in [Channel::UiEvent, Channel::Progress] {
        for r in h.capture().on(ch) {
            assert!(!r.json.contains("DATACANARY"), "{ch:?}: {}", r.json);
        }
    }
    Ok(())
}
