#![cfg(feature = "testing")]
//! Queue limits, admission and the memory budget (Task 20): low-space admission (X-03, §8.1),
//! the pending limits and `max_pending_bytes` answered with the constant `busy` (§3.3, §5.2,
//! L44, RF-2b), reservations released at every terminal, the byte-bounded candidate LRU and its
//! rebuild from the committed record (I-37 core half).
//!
//! Reads fetch at once (Task 21) and wait in `AwaitingRelease`, which is pending for the limits
//! exactly like `Validated` or `Fetching`. Tests that drive an entry's model by hand park the
//! read in `Validated` with the `pause_before_fetch` hook instead.

mod common;

use std::sync::Arc;
use std::time::Duration;

use atlas_duck_atlassian::UpstreamResponse;
use atlas_duck_audit::EventType;
use atlas_duck_core::CandidateRev;
use atlas_duck_core::RedactionOp;
use atlas_duck_core::config::ConfigState;
use atlas_duck_core::config::limits::{LimitsError, limits_config};
use atlas_duck_core::engine::cache::{
    Candidate, CandidateCache, RebuildError, build_candidate, fetched_responses,
};
use atlas_duck_core::engine::queue::{Admission, AgentKey, KeyOrigin, Limits, MIB, Reservation};
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::payloads::{ReadFetched, read_fetched};
use atlas_duck_core::testing::{FaultPlan, Harness};
use atlas_duck_core::{Decision, DecisionError, DecisionKind};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::proto::{
    BUSY_RETRY_PENDING_S, ClientKind, ConnectionMeta, PeerInfo, busy_envelope,
};
use atlas_duck_registry::RELEASE_CAP_BYTES;
use common::{TestError, TestResult, code, detail, exit, request_id};
use serde_json::{Value, json};

const ISSUE: &str = "jira.issue.get";

fn issue(key: &str) -> Value {
    json!({ "key": key })
}

/// A Jira issue body of about `size` bytes whose summary is `filler` repeated.
fn issue_body(key: &str, size: usize, filler: char) -> String {
    let summary: String = std::iter::repeat_n(filler, size).collect();
    json!({ "key": key, "fields": { "summary": summary } }).to_string()
}

async fn mount_issue(h: &Harness, key: &str, size: usize, filler: char) -> TestResult {
    let mock = h.mock("jira-main").ok_or("no mock")?;
    mock.json(
        &format!("/rest/api/2/issue/{key}"),
        200,
        &issue_body(key, size, filler),
    )
    .await;
    Ok(())
}

fn is_busy(env: &Envelope) -> bool {
    code(env) == "busy"
}

/// The `busy` envelope as §3.3 fixes it: retryable, `retry_after_s` 30, exit 11, nothing else.
fn assert_busy(env: &Envelope) -> TestResult {
    assert_eq!(env.status, Status::Failed);
    assert_eq!(code(env), "busy");
    assert_eq!(exit(env), 11);
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(detail(env, "retry_after_s"), json!(30));
    assert_eq!(env.request_id, None);
    assert_eq!(env.op_id, None);
    assert_eq!(env.instance, None);
    assert_eq!(
        env.to_json_line(),
        busy_envelope(BUSY_RETRY_PENDING_S).to_json_line(),
        "busy is the constant envelope"
    );
    Ok(())
}

fn limits_with(f: impl FnOnce(&mut Limits)) -> Limits {
    let mut l = Limits::default();
    f(&mut l);
    l
}

fn conn(id: &str, peer: PeerInfo) -> ConnectionMeta {
    ConnectionMeta {
        connection_id: id.to_owned(),
        peer,
    }
}

fn key(name: &str) -> AgentKey {
    AgentKey::new(Some(name), ClientKind::Cli, &conn("c", PeerInfo::default()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x03_storage_low_refuses_nothing_queued() -> TestResult {
    let h = Harness::jira().await?;
    mount_issue(&h, "ABC-1", 64, 'a').await?;
    let before = h.event_count().await?;
    h.free_space().set(0);
    let env = h.submit(ISSUE, issue("ABC-1")).await;
    assert_eq!(env.status, Status::Failed);
    assert_eq!(code(&env), "audit_storage_low");
    assert_eq!(exit(&env), 1);
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(env.request_id, None);
    // Nothing queued, nothing logged, nothing sent, nothing reserved.
    assert!(h.engine().pending_entries().is_empty());
    assert_eq!(h.event_count().await?, before);
    assert_eq!(h.engine().admission().pending_total(), 0);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        h.mock("jira-main")
            .ok_or("no mock")?
            .received()
            .await
            .is_empty()
    );
    // A failing probe refuses the same way (the store reports it as low space).
    h.free_space().set(u64::MAX);
    h.free_space().set_failing(true);
    assert_eq!(
        code(&h.submit(ISSUE, issue("ABC-1")).await),
        "audit_storage_low"
    );
    h.free_space().set_failing(false);
    assert_eq!(h.event_count().await?, before);
    // Space back: admitted.
    let env = h.submit(ISSUE, issue("ABC-1")).await;
    assert_eq!(env.status, Status::Pending);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_agent_limit_32() -> TestResult {
    let h = Harness::jira().await?;
    mount_issue(&h, "ABC-1", 1024, 'a').await?;
    let a = h.conn("agent-a").await?;
    let mut ids = Vec::new();
    for _ in 0..32 {
        let env = h.submit_with(&a, ISSUE, issue("ABC-1"), None).await;
        assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
        ids.push(request_id(&env)?);
    }
    let before = h.event_count().await?;
    let env = h.submit_with(&a, ISSUE, issue("ABC-1"), None).await;
    assert_busy(&env)?;
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    // Nothing queued or logged for the refused submit.
    assert_eq!(h.event_count().await?, before);
    assert_eq!(h.engine().pending_entries().len(), 32);
    // Another connection of the same agent key is in the same bucket.
    let a2 = h.conn("agent-a").await?;
    assert_busy(&h.submit_with(&a2, ISSUE, issue("ABC-1"), None).await)?;
    // A different agent is still admitted.
    let b = h.conn("agent-b").await?;
    let env = h.submit_with(&b, ISSUE, issue("ABC-1"), None).await;
    assert_eq!(env.status, Status::Pending);
    // A terminal request frees its slot (cancel, then expiry).
    let first = ids.first().ok_or("no id")?;
    assert_eq!(h.handler().cancel(first).await.status, Status::Cancelled);
    let env = h.submit_with(&a, ISSUE, issue("ABC-1"), None).await;
    assert_eq!(env.status, Status::Pending);
    assert_busy(&h.submit_with(&a, ISSUE, issue("ABC-1"), None).await)?;
    assert!(h.expire_now(ids.get(1).ok_or("no id")?).await);
    let env = h.submit_with(&a, ISSUE, issue("ABC-1"), None).await;
    assert_eq!(env.status, Status::Pending);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn total_limit_256() -> TestResult {
    // Scaled: total 8 (the harness override; production reads the §3.3 constants).
    let h = Harness::builder()
        .jira("jira-main")
        .limits(limits_with(|l| l.total = 8))
        .start()
        .await?;
    assert_eq!(Limits::default().total, 256);
    assert_eq!(Limits::default().per_agent, 32);
    let mut ids = Vec::new();
    for agent in ["a", "b", "c", "d"] {
        let c = h.conn(agent).await?;
        for _ in 0..2 {
            let env = h.submit_with(&c, ISSUE, issue("ABC-1"), None).await;
            assert_eq!(env.status, Status::Pending);
            ids.push(request_id(&env)?);
        }
    }
    let fresh = h.conn("e").await?;
    assert_busy(&h.submit_with(&fresh, ISSUE, issue("ABC-1"), None).await)?;
    assert_eq!(h.engine().admission().pending_total(), 8);
    // Refusals and failures before or at validation never keep a slot.
    let first = ids.first().ok_or("no id")?;
    assert_eq!(h.handler().cancel(first).await.status, Status::Cancelled);
    let rejected = h.submit_with(&fresh, ISSUE, json!({}), None).await;
    assert_eq!(code(&rejected), "validation");
    assert_eq!(h.engine().admission().pending_total(), 7);
    let env = h.submit_with(&fresh, ISSUE, issue("ABC-1"), None).await;
    assert_eq!(env.status, Status::Pending);
    assert_busy(&h.submit_with(&fresh, ISSUE, issue("ABC-1"), None).await)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reservations_released_on_failure_paths() -> TestResult {
    let plan = FaultPlan::new();
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .limits(limits_with(|l| l.total = 1))
        .start()
        .await?;
    // `REQUEST_RECEIVED` fails: nothing exists, the reservation is gone.
    plan.fail_nth(EventType::REQUEST_RECEIVED, 1);
    assert_eq!(
        code(&h.submit(ISSUE, issue("ABC-1")).await),
        "audit_failure"
    );
    assert_eq!(h.engine().admission().pending_total(), 0);
    // `REQUEST_REJECTED` fails: the failure stays in memory, the reservation does not.
    plan.fail_nth(EventType::REQUEST_REJECTED, 1);
    let env = h.submit(ISSUE, json!({})).await;
    assert_eq!(code(&env), "audit_failure");
    assert!(h.engine().entry(&request_id(&env)?).is_some());
    assert_eq!(h.engine().admission().pending_total(), 0);
    // A params integer JCS rejects (after admission, before `REQUEST_RECEIVED`).
    let env = h
        .submit(
            ISSUE,
            json!({ "key": "ABC-1", "x": 9_007_199_254_740_993_u64 }),
        )
        .await;
    assert_eq!(code(&env), "validation");
    assert_eq!(h.engine().admission().pending_total(), 0);
    // `CANCELLED` fails: the request is failed (unlogged) and its slot is free.
    let id = request_id(&h.submit(ISSUE, issue("ABC-1")).await)?;
    assert_busy(&h.submit(ISSUE, issue("ABC-1")).await)?;
    plan.fail_nth(EventType::CANCELLED, 1);
    let env = h.handler().cancel(&id).await;
    assert_eq!(code(&env), "audit_failure");
    assert_eq!(h.engine().admission().pending_total(), 0);
    assert_eq!(
        h.submit(ISSUE, issue("ABC-1")).await.status,
        Status::Pending
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_submits_hold_the_limit() -> TestResult {
    let h = Arc::new(Harness::jira().await?);
    let a = h.conn("racer").await?;
    let mut tasks = Vec::new();
    for _ in 0..64 {
        let (h, a) = (h.clone(), a.clone());
        tasks.push(tokio::spawn(async move {
            h.submit_with(&a, ISSUE, issue("ABC-1"), None).await
        }));
    }
    let mut pending = Vec::new();
    let mut busy = 0;
    for t in tasks {
        let env = t.await?;
        if is_busy(&env) {
            assert_busy(&env)?;
            busy += 1;
        } else {
            assert_eq!(env.status, Status::Pending);
            pending.push(request_id(&env)?);
        }
    }
    assert_eq!((pending.len(), busy), (32, 32));
    assert_eq!(h.engine().admission().pending_total(), 32);
    for id in &pending {
        assert_eq!(h.handler().cancel(id).await.status, Status::Cancelled);
    }
    assert_eq!(h.engine().admission().pending_total(), 0);
    assert_eq!(h.engine().admission().pending_for(&key("racer")), 0);
    Ok(())
}

/// One RF-2b scenario: the decisions and the `busy` envelopes of a fixed submit sequence.
async fn rf2b_scenario(size: usize, filler: char) -> Result<(Vec<bool>, Vec<String>), TestError> {
    let h = Harness::builder()
        .jira("jira-main")
        .extra_config("[limits]\nmax_pending_bytes_mb = 64\n")
        .start()
        .await?;
    let keys = ["ABC-1", "ABC-2", "ABC-3", "ABC-4", "ABC-5", "ABC-6"];
    for k in keys {
        mount_issue(&h, k, size, filler).await?;
    }
    let mut admitted = Vec::new();
    let mut busy = Vec::new();
    let mut first = None;
    for k in keys {
        let env = h.submit(ISSUE, issue(k)).await;
        admitted.push(env.status == Status::Pending);
        if env.status == Status::Pending {
            first.get_or_insert(request_id(&env)?);
        } else {
            busy.push(env.to_json_line());
        }
        // Give a dispatched fetch (Task 21) time to finish before the next decision.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let first = first.ok_or("nothing admitted")?;
    assert_eq!(h.handler().cancel(&first).await.status, Status::Cancelled);
    let env = h.submit(ISSUE, issue("ABC-6")).await;
    admitted.push(env.status == Status::Pending);
    Ok((admitted, busy))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf2b_busy_retry_after_independent_of_sizes() -> TestResult {
    let small = rf2b_scenario(1024, 's').await?;
    let large = rf2b_scenario(15 * 1024 * 1024, 'L').await?;
    // 64 MiB / 16 MiB static reservations: four admitted, then busy; a cancel frees one.
    assert_eq!(
        small.0,
        [true, true, true, true, false, false, true],
        "decisions"
    );
    assert_eq!(
        small, large,
        "admission depends on nothing but count and kind"
    );
    for b in &small.1 {
        assert_eq!(b, &busy_envelope(BUSY_RETRY_PENDING_S).to_json_line());
    }
    // The same bytes whichever limit refused: pending count, total, `max_pending_bytes`.
    let adm = Admission::new(limits_with(|l| {
        l.per_agent = 1;
        l.total = 2;
        l.max_pending_bytes = Some(RELEASE_CAP_BYTES);
    }));
    let read = Reservation::read(atlas_duck_registry::get(ISSUE).ok_or("op")?);
    let _t1 = adm.admit(key("x"), read).map_err(|_| "busy")?;
    let per_agent = adm
        .admit(key("x"), Reservation::none())
        .err()
        .ok_or("admitted")?;
    let bytes = adm.admit(key("y"), read).err().ok_or("admitted")?;
    let _t2 = adm
        .admit(key("y"), Reservation::none())
        .map_err(|_| "busy")?;
    let total = adm
        .admit(key("z"), Reservation::none())
        .err()
        .ok_or("admitted")?;
    // A refusal carries nothing: which limit refused cannot change the answer.
    assert_eq!((per_agent, bytes), (total, total));
    assert_busy(&total.envelope())?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i37_max_pending_bytes_busy() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .extra_config("[limits]\nmax_pending_bytes_mb = 32\n")
        .start()
        .await?;
    assert_eq!(h.engine().limits().max_pending_bytes, Some(32 * MIB));
    for k in ["ABC-1", "ABC-2", "ABC-3"] {
        mount_issue(&h, k, 1024, 'a').await?;
    }
    let one = h.submit(ISSUE, issue("ABC-1")).await;
    assert_eq!(one.status, Status::Pending);
    let two = h.conn("other").await?;
    assert_eq!(
        h.submit_with(&two, ISSUE, issue("ABC-2"), None)
            .await
            .status,
        Status::Pending
    );
    assert_eq!(h.engine().admission().reserved_bytes(), 32 * MIB);
    assert_busy(&h.submit(ISSUE, issue("ABC-3")).await)?;
    // Writes reserve nothing (§5.2 names reads and scripts): not busy.
    let w = h
        .submit(
            "jira.issue.assign",
            json!({ "key": "ABC-1", "assignee": "u" }),
        )
        .await;
    assert!(!is_busy(&w), "{}", w.to_json_line());
    // A cancelled read frees its 16 MiB.
    assert_eq!(
        h.handler().cancel(&request_id(&one)?).await.status,
        Status::Cancelled
    );
    assert_eq!(h.engine().admission().reserved_bytes(), 16 * MIB);
    assert_eq!(
        h.submit(ISSUE, issue("ABC-3")).await.status,
        Status::Pending
    );

    // Static reservations: a read its op's static cap (at most 16 MiB), a script its static
    // `max_result_mb` (§9.4), a write nothing.
    let limits = Limits::default();
    let read = Reservation::read(atlas_duck_registry::get(ISSUE).ok_or("op")?);
    assert_eq!(read.bytes(), RELEASE_CAP_BYTES);
    assert_eq!(Reservation::script(&limits).bytes(), 16 * MIB);
    let write = Reservation::for_op(atlas_duck_registry::get("jira.issue.create").ok_or("op")?);
    assert_eq!(write.bytes(), 0);
    let adm = Admission::new(limits_with(|l| {
        l.max_pending_bytes = Some(32 * MIB);
        l.max_result_mb = 20;
    }));
    let script = Reservation::script(adm.limits());
    assert_eq!(script.bytes(), 20 * MIB);
    let t = adm.admit(key("s"), script).map_err(|_| "busy")?;
    // 20 + 16 > 32: the read does not fit beside the script.
    assert_busy(
        &adm.admit(key("r"), read)
            .err()
            .ok_or("admitted")?
            .envelope(),
    )?;
    drop(t);
    assert_eq!(adm.reserved_bytes(), 0);
    let _r = adm.admit(key("r"), read).map_err(|_| "busy")?;
    Ok(())
}

#[test]
fn admission_tickets_release_exactly_once() -> TestResult {
    let adm = Admission::new(limits_with(|l| {
        l.per_agent = 2;
        l.total = 3;
        l.max_pending_bytes = Some(48 * MIB);
    }));
    let read = Reservation::read(atlas_duck_registry::get(ISSUE).ok_or("op")?);
    let t1 = adm.admit(key("a"), read).map_err(|_| "busy")?;
    let t2 = adm.admit(key("a"), read).map_err(|_| "busy")?;
    assert!(adm.admit(key("a"), Reservation::none()).is_err());
    assert_eq!((adm.pending_total(), adm.reserved_bytes()), (2, 32 * MIB));
    t1.release();
    assert_eq!((adm.pending_total(), adm.reserved_bytes()), (1, 16 * MIB));
    assert_eq!(adm.pending_for(&key("a")), 1);
    drop(t2);
    assert_eq!((adm.pending_total(), adm.reserved_bytes()), (0, 0));
    assert_eq!(adm.pending_for(&key("a")), 0);
    // A refused admit changed nothing.
    let _keep: Vec<_> = (0..3)
        .map(|i| adm.admit(key(&format!("k{i}")), read))
        .collect::<Result<_, _>>()
        .map_err(|_| "busy")?;
    assert!(adm.admit(key("k9"), read).is_err());
    assert_eq!((adm.pending_total(), adm.reserved_bytes()), (3, 48 * MIB));
    Ok(())
}

#[test]
fn agent_key_rules() {
    let origin = PeerInfo {
        peer_exe: Some("/usr/bin/atlas-duck".into()),
        peer_origin_exe: Some("/opt/agent/bin/agent".into()),
        ..PeerInfo::default()
    };
    let no_origin = PeerInfo {
        peer_exe: Some("/usr/bin/atlas-duck".into()),
        ..PeerInfo::default()
    };
    // `agent_name` + `peer_origin_exe`.
    let k = AgentKey::new(Some("bot"), ClientKind::Cli, &conn("c1", origin.clone()));
    assert_eq!(k.agent_name.as_deref(), Some("bot"));
    assert_eq!(k.origin, KeyOrigin::Exe("/opt/agent/bin/agent".into()));
    // The connection does not matter while an origin is known.
    assert_eq!(
        k,
        AgentKey::new(Some("bot"), ClientKind::Mcp, &conn("c2", origin.clone()))
    );
    // Unnamed: bucketed by the origin.
    let u = AgentKey::new(None, ClientKind::Cli, &conn("c1", origin));
    assert_eq!(u.agent_name, None);
    assert_eq!(u.origin, KeyOrigin::Exe("/opt/agent/bin/agent".into()));
    // MCP without an origin: by `connection_id`.
    let m = AgentKey::new(None, ClientKind::Mcp, &conn("c7", no_origin.clone()));
    assert_eq!(m.origin, KeyOrigin::Connection("c7".into()));
    // CLI without an origin: `peer_exe`.
    let c = AgentKey::new(None, ClientKind::Cli, &conn("c7", no_origin));
    assert_eq!(c.origin, KeyOrigin::Exe("/usr/bin/atlas-duck".into()));
    // Nothing known at all.
    let n = AgentKey::new(
        Some("bot"),
        ClientKind::Cli,
        &conn("c7", PeerInfo::default()),
    );
    assert_eq!(n.origin, KeyOrigin::Unknown);
}

#[test]
fn limits_from_config_keys() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("config.toml");
    let load = |text: &str| -> Result<ConfigState, TestError> {
        std::fs::write(&path, text)?;
        Ok(atlas_duck_core::config::load_config(&path)?)
    };
    // Absent file or table: defaults (bytes cap off, cache 512 MiB).
    let none = limits_config(&ConfigState::Absent)?;
    assert_eq!(Limits::from_config(&none), Limits::default());
    assert_eq!(Limits::default().max_pending_bytes, None);
    assert_eq!(Limits::default().candidate_cache_bytes, 512 * MIB);
    assert_eq!(Limits::default().fetching, 8);
    let cfg = load("schema_version = 1\n")?;
    assert_eq!(
        Limits::from_config(&limits_config(&cfg)?),
        Limits::default()
    );
    // Both keys.
    let cfg =
        load("schema_version = 1\n[limits]\nmax_pending_bytes_mb = 64\ncandidate_cache_mb = 8\n")?;
    let l = Limits::from_config(&limits_config(&cfg)?);
    assert_eq!(l.max_pending_bytes, Some(64 * MIB));
    assert_eq!(l.candidate_cache_bytes, 8 * MIB);
    assert_eq!((l.per_agent, l.total), (32, 256));
    // Malformed values are errors naming the key only.
    for (text, key) in [
        (
            "[limits]\nmax_pending_bytes_mb = 0\n",
            "max_pending_bytes_mb",
        ),
        (
            "[limits]\nmax_pending_bytes_mb = -4\n",
            "max_pending_bytes_mb",
        ),
        (
            "[limits]\ncandidate_cache_mb = \"big\"\n",
            "candidate_cache_mb",
        ),
        (
            "[limits]\ncandidate_cache_mb = 9999999999\n",
            "candidate_cache_mb",
        ),
    ] {
        let cfg = load(&format!("schema_version = 1\n{text}"))?;
        match limits_config(&cfg) {
            Err(LimitsError::Malformed { key: k, .. }) => assert_eq!(k, key),
            other => return Err(format!("{text}: {other:?}").into()),
        }
    }
    let cfg = load("schema_version = 1\nlimits = 3\n")?;
    assert_eq!(limits_config(&cfg), Err(LimitsError::NotATable));
    Ok(())
}

fn candidate(n: usize) -> Result<Arc<Candidate>, TestError> {
    let filler: String = std::iter::repeat_n('x', n).collect();
    Ok(Arc::new(Candidate::from_value(
        json!({ "summary": filler }),
    )?))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i37_scaled_lru_bounded() -> TestResult {
    // PD-15 scaled: 32 candidates of 1 MiB through an 8 MiB cache.
    let h = Harness::builder()
        .jira("jira-main")
        .extra_config("[limits]\ncandidate_cache_mb = 8\n")
        .start()
        .await?;
    let cache = h.engine().candidates();
    assert_eq!(cache.cap(), 8 * MIB);
    for i in 0..32 {
        let c = candidate(MIB as usize)?;
        assert!(c.charge() >= MIB);
        cache.insert(&format!("req_{i}"), c);
        assert!(cache.bytes() <= 8 * MIB, "after {i}: {}", cache.bytes());
        assert!(cache.contains(&format!("req_{i}")), "the newest stays");
    }
    assert!(!cache.contains("req_0"), "the oldest was evicted");
    assert!(cache.len() < 8);
    // A use promotes: the touched entry outlives a newer one.
    let survivor = format!("req_{}", 32 - cache.len());
    assert!(cache.get(&survivor).is_some());
    cache.insert("req_new", candidate(MIB as usize)?);
    assert!(cache.contains(&survivor));
    assert!(cache.bytes() <= 8 * MIB);
    // One candidate larger than the whole cache is not kept (rebuilt when needed).
    cache.insert("req_huge", candidate(9 * MIB as usize)?);
    assert!(!cache.contains("req_huge"));
    assert!(cache.bytes() <= 8 * MIB);
    // Removal and re-insertion keep the accounting exact.
    let before = cache.bytes();
    let c = cache.get("req_new").ok_or("evicted")?;
    cache.remove("req_new");
    assert_eq!(cache.bytes(), before - c.charge());
    cache.insert("req_new", c.clone());
    cache.insert("req_new", c.clone());
    assert_eq!(cache.bytes(), before);
    let standalone = CandidateCache::new(4 * MIB);
    standalone.insert("a", candidate(1024)?);
    standalone.remove("a");
    assert_eq!((standalone.bytes(), standalone.len()), (0, 0));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_drops_the_cached_candidate() -> TestResult {
    let h = Harness::jira().await?;
    let id = request_id(&h.submit(ISSUE, issue("ABC-1")).await)?;
    h.engine().candidates().insert(&id, candidate(1024)?);
    assert!(h.engine().candidates().contains(&id));
    assert_eq!(h.handler().cancel(&id).await.status, Status::Cancelled);
    assert!(!h.engine().candidates().contains(&id));
    assert_eq!(h.engine().candidates().bytes(), 0);
    Ok(())
}

/// The simplest normalization: the one page's JSON body.
fn first_page(payload: &Value) -> Result<Value, RebuildError> {
    let pages = fetched_responses(payload)?;
    let page = pages.first().ok_or(RebuildError::Malformed)?;
    serde_json::from_slice(&page.body).map_err(|_| RebuildError::Malformed)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rebuild_from_committed_record() -> TestResult {
    // The reads stay in `Validated`: this test commits the record and sets the hash itself.
    let parked = atlas_duck_core::Pause::new();
    let h = Harness::builder()
        .jira("jira-main")
        .hooks(atlas_duck_core::TestHooks {
            pause_before_fetch: Some(parked.clone()),
            ..atlas_duck_core::TestHooks::none()
        })
        .start()
        .await?;
    mount_issue(&h, "ABC-1", 64, 'n').await?;
    let id = request_id(&h.submit(ISSUE, issue("ABC-1")).await)?;
    let entry = h.engine().entry(&id).ok_or("not in memory")?;
    let spec = entry.spec;
    // What a fetch would commit (Task 21): one page, bytes stored losslessly.
    let raw = r#"{"key":"ABC-1","fields":{"summary":"a secret here","b":"é"}}"#
        .as_bytes()
        .to_vec();
    let page = UpstreamResponse {
        status: 200,
        content_type: Some("application/json".into()),
        body: raw.clone(),
    };
    let ev = read_fetched(&entry.ctx, &ReadFetched::Pages { responses: &[page] }, None);
    h.store().append(ev)?;
    let ops = vec![RedactionOp::MaskText {
        text: "secret".into(),
        every_occurrence: true,
        at: None,
    }];
    let body: Value = serde_json::from_slice(&raw)?;
    let expected = build_candidate(spec, body, &ops).map_err(|e| format!("{e:?}"))?;
    assert!(!String::from_utf8_lossy(expected.bytes()).contains("secret"));
    {
        let mut st = entry.state();
        st.candidate_hash = *expected.hash();
        st.redaction_ops = ops.clone();
    }
    let hits = h.mock("jira-main").ok_or("no mock")?.received().await.len();

    // Not cached: rebuilt from the record, equal bytes, then cached.
    assert!(!h.engine().candidates().contains(&id));
    let c = h
        .engine()
        .candidate(&entry, first_page)
        .await
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(c.hash(), expected.hash());
    assert_eq!(&**c.bytes(), &**expected.bytes());
    assert!(h.engine().candidates().contains(&id));
    // Cached now: the same `Arc`, no rebuild (a failing normalization is never called).
    let again = h
        .engine()
        .candidate(&entry, |_| Err(RebuildError::Malformed))
        .await
        .map_err(|e| format!("{e:?}"))?;
    assert!(Arc::ptr_eq(&c, &again));
    // A rebuild never touches the network.
    assert_eq!(
        h.mock("jira-main").ok_or("no mock")?.received().await.len(),
        hits
    );
    // A different normalization result than the committed revision: fail closed.
    h.evict_candidate(&id);
    let res = h
        .engine()
        .candidate(&entry, |_| Ok(json!({ "key": "ABC-1" })))
        .await;
    assert!(matches!(res, Err(RebuildError::HashMismatch)), "{res:?}");
    assert!(entry.state().rebuild_failed);
    assert!(!entry.state().model.approvable());
    assert!(!h.engine().candidates().contains(&id));
    // A corrupted revision hash mismatches too, also for a cached candidate.
    entry.state().rebuild_failed = false;
    assert!(h.engine().candidate(&entry, first_page).await.is_ok());
    assert!(h.corrupt_candidate_hash(&id));
    let res = h.engine().candidate(&entry, first_page).await;
    assert!(matches!(res, Err(RebuildError::HashMismatch)), "{res:?}");
    assert!(entry.state().rebuild_failed);
    // A request with no candidate record.
    let other = request_id(&h.submit(ISSUE, issue("ABC-1")).await)?;
    let other = h.engine().entry(&other).ok_or("not in memory")?;
    let res = h.engine().candidate(&other, first_page).await;
    assert!(matches!(res, Err(RebuildError::NoSource)), "{res:?}");
    // No candidate yet (zero hash): nothing is disabled.
    assert!(!other.state().rebuild_failed);
    // A revision with a hash but no record: disabled.
    other.state().candidate_hash = [7; 32];
    let res = h.engine().candidate(&other, first_page).await;
    assert!(matches!(res, Err(RebuildError::NoSource)), "{res:?}");
    assert!(other.state().rebuild_failed);
    Ok(())
}

#[test]
fn fetched_responses_restores_every_byte() -> TestResult {
    // A body cut inside a multibyte character keeps its tail (`{"text", "tail_b64"}`).
    let cut = "ok \u{20ac}".as_bytes();
    let cut = cut.get(..cut.len() - 1).ok_or("short")?.to_vec();
    let pages = [
        UpstreamResponse {
            status: 200,
            content_type: Some("application/json".into()),
            body: b"{\"a\":1}".to_vec(),
        },
        UpstreamResponse {
            status: 502,
            content_type: None,
            body: cut.clone(),
        },
    ];
    let ev = read_fetched(
        &atlas_duck_core::payloads::EventCtx::default(),
        &ReadFetched::UpstreamError { responses: &pages },
        None,
    );
    let back = fetched_responses(&ev.payload).map_err(|e| format!("{e:?}"))?;
    assert_eq!(back.len(), 2);
    assert_eq!(
        back.first().map(|r| (r.status, r.body.clone())),
        Some((200, b"{\"a\":1}".to_vec()))
    );
    assert_eq!(
        back.get(1)
            .map(|r| (r.status, r.content_type.clone(), r.body.clone())),
        Some((502, None, cut))
    );
    assert!(matches!(
        fetched_responses(&json!({ "pages": 1 })),
        Err(RebuildError::Malformed)
    ));
    Ok(())
}

fn release(id: &str, rev: CandidateRev) -> Decision {
    Decision {
        request_id: id.to_owned(),
        decision: DecisionKind::Release,
        candidate_rev: rev,
        edits: None,
        redactions: None,
        reason: None,
        deny_details: None,
    }
}

/// Waits until `id` is in the queue (Task 21 fetches it); `None` after `ms`.
async fn queued(h: &Harness, id: &str, ms: u64) -> Option<atlas_duck_core::QueueItem> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        if let Some(item) = h.decisions().queue_get(id) {
            return Some(item);
        }
        if tokio::time::Instant::now() > deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i37_evicted_rebuild_no_mock_hit() -> TestResult {
    let h = Harness::jira().await?;
    mount_issue(&h, "ABC-1", 4096, 'r').await?;
    let id = request_id(&h.submit(ISSUE, issue("ABC-1")).await)?;
    let item = queued(&h, &id, 5000).await.ok_or("never queued")?;
    let first = h
        .decisions()
        .preview_fetch(&id, Some(item.candidate_rev))
        .map_err(|e| format!("{e:?}"))?;
    let hits = h.mock("jira-main").ok_or("no mock")?.received().await.len();
    h.evict_candidate(&id);
    assert!(!h.engine().candidates().contains(&id));
    let again = h
        .decisions()
        .preview_fetch(&id, Some(item.candidate_rev))
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        h.mock("jira-main").ok_or("no mock")?.received().await.len(),
        hits,
        "a rebuild makes no network call"
    );
    assert_eq!(
        again.preview.candidate_rev.candidate_hash,
        first.preview.candidate_rev.candidate_hash
    );
    assert!(h.engine().candidates().contains(&id));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i37_rebuild_hash_mismatch_disables_release() -> TestResult {
    let h = Harness::jira().await?;
    mount_issue(&h, "ABC-1", 4096, 'r').await?;
    let id = request_id(&h.submit(ISSUE, issue("ABC-1")).await)?;
    let item = queued(&h, &id, 5000).await.ok_or("never queued")?;
    h.decisions()
        .preview_fetch(&id, Some(item.candidate_rev))
        .map_err(|e| format!("{e:?}"))?;
    assert!(h.corrupt_candidate_hash(&id));
    let rev = h.decisions().queue_get(&id).ok_or("gone")?.candidate_rev;
    let res = h.decisions().decide(release(&id, rev));
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    let item = h.decisions().queue_get(&id).ok_or("gone")?;
    assert!(!item.approvable, "release is disabled after a mismatch");
    let events = h.events(&id).await?;
    assert!(
        events
            .iter()
            .any(|(t, p)| *t == EventType::DECISION_INVALID
                && p["reason"] == json!("not_approvable"))
    );
    assert!(!events.iter().any(|(t, _)| *t == EventType::READ_RELEASED));
    // Deny stays possible.
    let deny = h.decisions().decide(Decision {
        decision: DecisionKind::Deny,
        reason: Some("rebuild failed".into()),
        ..release(&id, rev)
    });
    assert!(deny.is_ok(), "{deny:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i37_await_delivers_committed_bytes() -> TestResult {
    let h = Harness::jira().await?;
    mount_issue(&h, "ABC-1", 4096, 'd').await?;
    let id = request_id(&h.submit(ISSUE, issue("ABC-1")).await)?;
    let item = queued(&h, &id, 5000).await.ok_or("never queued")?;
    h.decisions()
        .preview_fetch(&id, Some(item.candidate_rev))
        .map_err(|e| format!("{e:?}"))?;
    h.evict_candidate(&id);
    h.decisions()
        .decide(release(&id, item.candidate_rev))
        .map_err(|e| format!("{e:?}"))?;
    h.engine().candidates().clear();
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released);
    let summary = env
        .data
        .as_ref()
        .and_then(|d| d.pointer("/result/fields/summary"))
        .and_then(Value::as_str)
        .ok_or("no summary")?;
    assert_eq!(summary.len(), 4096);
    Ok(())
}

/// Resident set size of this process in bytes; `None` where it is not read (macOS).
fn rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        // `VmRSS:   12345 kB` (independent of the page size).
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = s.lines().find(|l| l.starts_with("VmRSS:"))?;
        let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kb * 1024)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let mut c = PROCESS_MEMORY_COUNTERS {
            cb: 0,
            PageFaultCount: 0,
            PeakWorkingSetSize: 0,
            WorkingSetSize: 0,
            QuotaPeakPagedPoolUsage: 0,
            QuotaPagedPoolUsage: 0,
            QuotaPeakNonPagedPoolUsage: 0,
            QuotaNonPagedPoolUsage: 0,
            PagefileUsage: 0,
            PeakPagefileUsage: 0,
        };
        let size = u32::try_from(std::mem::size_of::<PROCESS_MEMORY_COUNTERS>()).ok()?;
        c.cb = size;
        // SAFETY: the pseudo handle needs no closing; `c` is a valid, sized out-pointer.
        let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut c, size) };
        (ok != 0).then(|| u64::try_from(c.WorkingSetSize).unwrap_or(u64::MAX))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "PD-15: full size, run with ATLAS_DUCK_BIG_TESTS=1 (one CI step, Task 30)"]
async fn i37_rss_bounded_256_pending() -> TestResult {
    // Run with `--ignored` but without the gate: fail loudly instead of passing vacuously.
    if std::env::var("ATLAS_DUCK_BIG_TESTS").as_deref() != Ok("1") {
        return Err("set ATLAS_DUCK_BIG_TESTS=1 to run the full-size memory test (PD-15)".into());
    }
    let h = Harness::jira().await?;
    let cache_mb = h.engine().limits().candidate_cache_bytes / MIB;
    let fetching = h.engine().limits().fetching;
    // ~16 MiB, just under the release cap once wrapped. One fixture serves every read, so the
    // mock (in this process) holds one body, not 256.
    mount_issue(&h, "ABC-1", 16 * 1024 * 1024 - 4096, 'm').await?;
    let mut peak = rss_bytes().unwrap_or(0);
    let mut conns = Vec::new();
    for n in 0..8 {
        conns.push(h.conn(&format!("big-{n}")).await?);
    }
    let mut ids = Vec::new();
    for c in &conns {
        // 32 per agent key: eight agents fill the 256.
        for _ in 0..32 {
            let env = h.submit_with(c, ISSUE, issue("ABC-1"), None).await;
            assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
            ids.push(request_id(&env)?);
            peak = peak.max(rss_bytes().unwrap_or(0));
        }
    }
    assert_busy(&h.submit(ISSUE, issue("ABC-1")).await)?;
    // Sample until every read waits for release, or until no fetch is in flight and the queue
    // stopped growing for 2 s (before Task 21 nothing fetches).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    let (mut last, mut still) = (usize::MAX, 0u32);
    loop {
        peak = peak.max(rss_bytes().unwrap_or(0));
        let queued = h.decisions().queue_list().len();
        let idle = h.engine().fetch_slots().available_permits() == fetching;
        still = if queued == last && idle { still + 1 } else { 0 };
        last = queued;
        if queued >= ids.len() || still >= 8 || tokio::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(h.engine().candidates().bytes() <= cache_mb * MIB);
    if rss_bytes().is_some() {
        assert!(
            peak < (cache_mb + 1024) * MIB,
            "peak RSS {} MiB exceeds candidate_cache_mb + 1 GiB",
            peak / MIB
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rebuild_failure_survives_a_transition_replace() -> TestResult {
    use atlas_duck_core::lifecycle::model::{Event, ReleaseItem, step};
    use atlas_duck_core::payloads::preview_shown;
    use atlas_duck_core::{Pause, TestHooks};
    let pause = Pause::new();
    let parked = Pause::new();
    let h = Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            pause_in_transition: Some(pause.clone()),
            // The read stays in `Validated`: this test steps the model itself.
            pause_before_fetch: Some(parked.clone()),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let id = request_id(&h.submit(ISSUE, issue("ABC-1")).await)?;
    let entry = h.engine().entry(&id).ok_or("not in memory")?;
    // As if the read had fetched (Task 21): an approvable release item with a candidate hash.
    {
        let mut st = entry.state();
        let _ = step(&mut st.model, Event::FetchStarted);
        let _ = step(&mut st.model, Event::Fetched(ReleaseItem::Result));
        st.model.set_approvable(true);
        st.candidate_hash = [9; 32];
    }
    let rev = entry.state().model.rev();
    // An event that keeps rev and phase (`PreviewShown`) goes through `transition`; while its
    // append is committed and the apply waits, a rebuild fails (no candidate record).
    let ctx = entry.ctx.clone();
    let engine = h.engine().clone();
    let e2 = entry.clone();
    let transition = tokio::spawn(async move {
        engine
            .transition(&e2, Event::PreviewShown { rev }, move |_| {
                let r = CandidateRev {
                    counter: rev,
                    candidate_hash: [9; 32],
                };
                preview_shown(&ctx, &r, &[], "test")
            })
            .await
    });
    pause.reached.notified().await;
    let res = h.engine().candidate(&entry, |v| Ok(v.clone())).await;
    assert!(matches!(res, Err(RebuildError::NoSource)), "{res:?}");
    assert!(entry.state().rebuild_failed);
    assert!(!entry.state().model.approvable());
    pause.release.notify_one();
    assert!(transition.await?.is_ok());
    let st = entry.state();
    assert!(st.model.opened(), "the clone was applied");
    assert!(
        !st.model.approvable(),
        "the rebuild failure survives the replace"
    );
    let mut m = st.model.clone();
    assert!(
        step(
            &mut m,
            Event::Release {
                rev,
                redacted: false
            }
        )
        .is_err()
    );
    Ok(())
}
