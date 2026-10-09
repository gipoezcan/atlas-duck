//! The audit port against a real temp-dir store: covers only after a durable commit (§5.1
//! inv. 1, RF-3), the date bridge (§8.8), `FaultyAudit` (X-04) and the §8.3 builders' records.
#![cfg(feature = "testing")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use atlas_duck_atlassian::{
    CoverIssuer, DateObserver, NotCommitted, UnknownReason, UpstreamResponse,
};
use atlas_duck_audit::testing::{FaultPoint, Faults};
use atlas_duck_audit::{
    Actor, AuditError, Committed, Confirmed, DecisionColumn, EventFlags, EventHeader, EventType,
    NewEvent, QueryKind, ReconcileReport, RequestRecord, SettingChange, Settings, UtcInstant,
    request_set_hash,
};
use atlas_duck_core::audit_port::{
    AuditPort, CommittedSet, DateBridge, StoreProbe, commit_request_received,
    commit_system_fetch_start,
};
use atlas_duck_core::ids::{BatchId, FetchId, RequestId};
use atlas_duck_core::lifecycle::model::CancelReason;
use atlas_duck_core::payloads::{self, *};
use atlas_duck_core::redact::{DropScope, RedactionOp};
use atlas_duck_core::testing::{FaultPlan, FaultyAudit, TempStore};
use atlas_duck_ipc::envelope::ErrorCode;
use atlas_duck_ipc::proto::{
    AgentNameSource, ClientKind, ConnectionMeta, Hello, PeerHop, PeerInfo, params_sha256,
};
use atlas_duck_preview::CandidateRev;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PAT_CANARY: &str = "PATCANARY-7f3e9a1c-not-our-token";

fn hello() -> Hello {
    Hello {
        build_id: "0.1.0+000000000000".to_owned(),
        client_kind: ClientKind::Cli,
        agent_name: Some("claude\u{202E}code".to_owned()),
        agent_name_source: AgentNameSource::Flag,
        cwd_basename: "atlas-duck".to_owned(),
    }
}

fn conn() -> ConnectionMeta {
    ConnectionMeta {
        connection_id: "conn_1".to_owned(),
        peer: PeerInfo {
            peer_pid: Some(4242),
            peer_exe: Some(PathBuf::from("/usr/bin/atlas-duck")),
            // A Windows FILETIME-sized start time: beyond the integers JCS accepts.
            peer_chain: vec![PeerHop {
                pid: 1,
                start_time: u64::MAX,
                exe: PathBuf::from("/usr/bin/bash"),
            }],
            peer_origin_exe: Some(PathBuf::from("/usr/bin/bash")),
            peer_origin_start_time: Some(u64::MAX),
        },
    }
}

fn ctx(request_id: &str) -> EventCtx {
    EventCtx {
        request_id: Some(request_id.to_owned()),
        op_id: Some("jira.issue.get".to_owned()),
        op_class: Some("read".to_owned()),
        instance_id: Some("ins_00000000000000000000000000000001".to_owned()),
        target: Some("ABC-1".to_owned()),
        actor: Actor::default(),
    }
}

fn received(request_id: &str, params: &Value) -> Result<NewEvent, Box<dyn std::error::Error>> {
    let c = ctx(request_id);
    let sha = params_sha256("jira.issue.get", c.instance_id.as_deref(), params)?;
    Ok(payloads::request_received(
        &c,
        params,
        &sha,
        &hello(),
        &conn(),
        Some("look at\nthe issue"),
    ))
}

fn payload_of(port: &dyn AuditPort, c: &Committed) -> Result<Value, Box<dyn std::error::Error>> {
    let bytes = port.read_payload(c.seq)?;
    Ok(serde_json::from_slice(bytes.as_slice())?)
}

#[test]
fn cover_refused_until_append_returns_ok() -> TestResult {
    let ts = TempStore::new()?;
    let plan = FaultPlan::new();
    plan.fail_nth(EventType::REQUEST_RECEIVED, 1);
    let port = FaultyAudit::wrap(ts.port(), plan.clone());
    let set = Arc::new(CommittedSet::default());
    let issuer = CoverIssuer::new(Arc::new(StoreProbe(set.clone())));
    let id = RequestId::new()?;
    let ev = received(id.as_str(), &json!({ "key": "ABC-1" }))?;

    assert_eq!(issuer.for_request(id.as_str()).err(), Some(NotCommitted));
    let head = ts.store().head().0;
    let r = commit_request_received(&port, &set, ev.clone());
    assert!(matches!(r, Err(AuditError::AppendFailed(_))), "{r:?}");
    assert_eq!(issuer.for_request(id.as_str()).err(), Some(NotCommitted));
    // Nothing reached the store.
    assert_eq!(ts.store().head().0, head);
    assert!(ts.store().headers_for_request(id.as_str())?.is_empty());

    let c = commit_request_received(&port, &set, ev)?;
    let cover = issuer.for_request(id.as_str())?;
    assert_eq!(cover.request_id(), Some(id.as_str()));
    assert_eq!(cover.fetch_id(), None);
    let headers = ts.store().headers_for_request(id.as_str())?;
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].seq, c.seq);
    assert_eq!(headers[0].event_type, EventType::REQUEST_RECEIVED);
    assert_eq!(plan.attempts(EventType::REQUEST_RECEIVED), 2);

    // Request covers never cover system fetches; terminal forgets the id.
    assert!(issuer.for_system_fetch(id.as_str()).is_err());
    set.forget_request(id.as_str());
    assert_eq!(issuer.for_request(id.as_str()).err(), Some(NotCommitted));
    Ok(())
}

#[test]
fn real_rollback_marks_nothing() -> TestResult {
    // The store's own writer fault: the append rolls back and returns `AppendFailed`.
    let faults = Faults::new();
    let ts = TempStore::with_faults(faults.clone())?;
    let set = CommittedSet::default();
    let port = ts.port();
    let id = RequestId::new()?;
    faults.fail(FaultPoint::WriterBeforeCommit, 1);
    let r = commit_request_received(&*port, &set, received(id.as_str(), &json!({}))?);
    assert!(matches!(r, Err(AuditError::AppendFailed(_))), "{r:?}");
    assert!(!set.request_committed(id.as_str()));
    assert!(ts.store().headers_for_request(id.as_str())?.is_empty());

    commit_request_received(&*port, &set, received(id.as_str(), &json!({}))?)?;
    assert!(set.request_committed(id.as_str()));
    Ok(())
}

#[test]
fn commit_request_received_refuses_other_records() -> TestResult {
    let ts = TempStore::new()?;
    let port = ts.port();
    let set = CommittedSet::default();
    let head = ts.store().head().0;

    let shown = payloads::preview_shown(
        &ctx("req_x"),
        &CandidateRev {
            counter: 1,
            candidate_hash: [7; 32],
        },
        &[],
        "v1",
    );
    let r = commit_request_received(&*port, &set, shown);
    assert!(matches!(r, Err(AuditError::Invalid(_))), "{r:?}");

    let mut no_id = received("req_y", &json!({}))?;
    no_id.request_id = None;
    let r = commit_request_received(&*port, &set, no_id);
    assert!(matches!(r, Err(AuditError::Invalid(_))), "{r:?}");
    assert_eq!(ts.store().head().0, head);
    assert!(!set.request_committed("req_x"));

    // A script's start record covers its host calls.
    let mut started = received("req_s", &json!({}))?;
    started.event_type = EventType::SCRIPT_STARTED;
    commit_request_received(&*port, &set, started)?;
    assert!(set.request_committed("req_s"));
    Ok(())
}

#[test]
fn fetch_cover_only_after_start_record() -> TestResult {
    let ts = TempStore::new()?;
    let plan = FaultPlan::new();
    plan.fail_nth(EventType::SYSTEM_FETCH, 1);
    let port = FaultyAudit::wrap(ts.port(), plan);
    let set = Arc::new(CommittedSet::default());
    let issuer = CoverIssuer::new(Arc::new(StoreProbe(set.clone())));
    let fid = FetchId::new()?;
    let inst = "ins_00000000000000000000000000000001";
    let planned = [
        ("GET", "/rest/api/2/myself"),
        ("GET", "/rest/api/2/serverInfo"),
    ];
    let start = || {
        payloads::system_fetch_start(
            SystemFetchPurpose::ConnectionTest,
            inst,
            fid.as_str(),
            &planned,
        )
    };

    assert!(issuer.for_system_fetch(fid.as_str()).is_err());
    let r = commit_system_fetch_start(&port, &set, start(), fid.as_str());
    assert!(matches!(r, Err(AuditError::AppendFailed(_))), "{r:?}");
    assert!(issuer.for_system_fetch(fid.as_str()).is_err());

    // A start record for another fetch id, or a result record, marks nothing.
    let other = FetchId::new()?;
    let r = commit_system_fetch_start(&port, &set, start(), other.as_str());
    assert!(matches!(r, Err(AuditError::Invalid(_))), "{r:?}");
    let resp = UpstreamResponse {
        status: 200,
        content_type: Some("application/json".into()),
        body: br#"{"name":"jdoe"}"#.to_vec(),
    };
    let result = payloads::system_fetch_result(
        SystemFetchPurpose::ConnectionTest,
        inst,
        fid.as_str(),
        "GET",
        "/rest/api/2/myself",
        &FetchRecord::Response(&resp),
    );
    let r = commit_system_fetch_start(&port, &set, result.clone(), fid.as_str());
    assert!(matches!(r, Err(AuditError::Invalid(_))), "{r:?}");
    assert!(issuer.for_system_fetch(fid.as_str()).is_err());

    let c = commit_system_fetch_start(&port, &set, start(), fid.as_str())?;
    let cover = issuer.for_system_fetch(fid.as_str())?;
    assert_eq!(cover.fetch_id(), Some(fid.as_str()));
    assert!(issuer.for_request(fid.as_str()).is_err());
    assert!(issuer.for_system_fetch(other.as_str()).is_err());

    let p = payload_of(&port, &c)?;
    assert_eq!(p["phase"], "start");
    assert_eq!(p["purpose"], "connection_test");
    assert_eq!(p["fetch_id"], fid.as_str());
    assert_eq!(
        p["planned"],
        json!([
            {"method": "GET", "path": "/rest/api/2/myself"},
            {"method": "GET", "path": "/rest/api/2/serverInfo"}
        ])
    );
    let c = port.append(result)?;
    let p = payload_of(&port, &c)?;
    assert_eq!(p["phase"], "result");
    assert_eq!(p["status"], 200);
    assert_eq!(p["response"]["body"]["text"], r#"{"name":"jdoe"}"#);

    set.forget_fetch(fid.as_str());
    assert!(issuer.for_system_fetch(fid.as_str()).is_err());
    Ok(())
}

/// An `AuditPort` double that records `observe_server_date` and answers nothing else.
#[derive(Default)]
struct RecordingPort {
    dates: Mutex<Vec<(String, SystemTime, Instant)>>,
}

impl AuditPort for RecordingPort {
    fn append(&self, _ev: NewEvent) -> Result<Committed, AuditError> {
        Err(AuditError::Closed)
    }
    fn append_batch(&self, _evs: Vec<NewEvent>) -> Result<Vec<Committed>, AuditError> {
        Err(AuditError::Closed)
    }
    fn admission_check(&self) -> Result<(), AuditError> {
        Ok(())
    }
    fn query_tag(&self, _kind: QueryKind, _query: &str) -> String {
        String::new()
    }
    fn read_payload(&self, _seq: u64) -> Result<Zeroizing<Vec<u8>>, AuditError> {
        Err(AuditError::Closed)
    }
    fn headers_for_request(&self, _request_id: &str) -> Result<Vec<EventHeader>, AuditError> {
        Ok(Vec::new())
    }
    fn recent_headers(&self, _since: Duration) -> Result<Vec<EventHeader>, AuditError> {
        Ok(Vec::new())
    }
    fn reconcile_after_crash(&self) -> Result<ReconcileReport, AuditError> {
        Err(AuditError::Closed)
    }
    fn observe_server_date(&self, instance_id: &str, d: SystemTime, at: Instant) {
        if let Ok(mut v) = self.dates.lock() {
            v.push((instance_id.to_owned(), d, at));
        }
    }
    fn settings(&self) -> Settings {
        Settings::default()
    }
    fn apply_setting(
        &self,
        _c: SettingChange,
        _confirmed: Option<Confirmed>,
    ) -> Result<Committed, AuditError> {
        Err(AuditError::Closed)
    }
    fn flush_head_anchor(&self) -> Result<(), AuditError> {
        Ok(())
    }
}

#[test]
fn date_bridge_forwards() -> TestResult {
    let rec = Arc::new(RecordingPort::default());
    let bridge = DateBridge(rec.clone());
    let d = UNIX_EPOCH + Duration::from_secs(1_791_460_800);
    let at = Instant::now();
    bridge.observe("ins_a", d, at);
    let seen = rec.dates.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(seen, vec![("ins_a".to_owned(), d, at)]);

    // Through the real store: a server `Date` equal to the fake clock corroborates the local
    // date, so the next record carries an epoch (GENESIS has none, §8.2).
    let ts = TempStore::new()?;
    let port = ts.port();
    let start = UtcInstant::parse_rfc3339_ms(atlas_duck_core::testing::store::TEMP_STORE_START)
        .ok_or("start")?;
    let server = UNIX_EPOCH + Duration::from_millis(u64::try_from(start.0)?);
    let c0 = port.append(payloads::app_stop(AppStopReason::Quit))?;
    DateBridge(port.clone()).observe("ins_a", server, Instant::now());
    let c1 = port.append(payloads::app_stop(AppStopReason::Quit))?;
    let headers = port.recent_headers(Duration::from_secs(3_600))?;
    let epoch = |seq| {
        headers
            .iter()
            .find(|h| h.seq == seq)
            .map(|h| h.epoch.clone())
    };
    assert_eq!(epoch(c0.seq), Some(None));
    assert_eq!(epoch(c1.seq), Some(Some("2026-10-08".to_owned())));
    Ok(())
}

#[test]
fn faulty_audit_fails_nth_of_type() -> TestResult {
    let ts = TempStore::new()?;
    let plan = FaultPlan::new();
    plan.fail_nth(EventType::PREVIEW_SHOWN, 2);
    let port = FaultyAudit::wrap(ts.port(), plan.clone());
    let rev = CandidateRev {
        counter: 1,
        candidate_hash: [1; 32],
    };
    let shown = || payloads::preview_shown(&ctx("req_f"), &rev, &[], "v1");

    port.append(shown())?;
    port.append(payloads::expired(&ctx("req_other")))?; // another type: not counted
    let r = port.append(shown());
    assert!(matches!(r, Err(AuditError::AppendFailed(_))), "{r:?}");
    port.append(shown())?;
    assert_eq!(plan.attempts(EventType::PREVIEW_SHOWN), 3);
    assert_eq!(plan.attempts(EventType::EXPIRED), 1);
    let shown_rows = ts
        .store()
        .headers_for_request("req_f")?
        .iter()
        .filter(|h| h.event_type == EventType::PREVIEW_SHOWN)
        .count();
    assert_eq!(shown_rows, 2);

    // A batch containing the failing attempt fails whole; nothing is committed.
    plan.fail_nth(EventType::CANCELLED, 1);
    let head = ts.store().head().0;
    let r = port.append_batch(vec![
        payloads::expired(&ctx("req_b1")),
        payloads::cancelled(&ctx("req_b2"), CancelReason::ByClient),
    ]);
    assert!(matches!(r, Err(AuditError::AppendFailed(_))), "{r:?}");
    assert_eq!(ts.store().head().0, head);
    let ok = port.append_batch(vec![
        payloads::expired(&ctx("req_b1")),
        payloads::cancelled(&ctx("req_b2"), CancelReason::ByClient),
    ])?;
    assert_eq!(ok.len(), 2);

    // The switch fails every append until it is flipped back; reads still pass through.
    plan.fail_all(true);
    let head = ts.store().head().0;
    assert!(matches!(
        port.append(payloads::app_stop(AppStopReason::Quit)),
        Err(AuditError::AppendFailed(_))
    ));
    assert!(matches!(
        port.append_batch(vec![payloads::app_stop(AppStopReason::Quit)]),
        Err(AuditError::AppendFailed(_))
    ));
    assert!(matches!(
        port.apply_setting(SettingChange::RetentionDays(400), None),
        Err(AuditError::AppendFailed(_))
    ));
    assert_eq!(ts.store().head().0, head);
    assert!(!port.headers_for_request("req_f")?.is_empty());
    port.admission_check()?;
    plan.fail_all(false);
    port.append(payloads::app_stop(AppStopReason::Quit))?;
    Ok(())
}

#[test]
fn request_received_payload_and_columns() -> TestResult {
    let ts = TempStore::new()?;
    let port = ts.port();
    // Agents may send anything, our canary string included: it is stored as sent.
    let params = json!({ "key": "ABC-1", "jql": PAT_CANARY, "n": 9_007_199_254_740_991u64 });
    let id = RequestId::new()?;
    let c = port.append(received(id.as_str(), &params)?)?;
    let p = payload_of(&*port, &c)?;
    assert_eq!(p["params"], params);
    assert!(p.to_string().contains(PAT_CANARY));
    let sha = params_sha256("jira.issue.get", ctx("x").instance_id.as_deref(), &params)?;
    assert_eq!(p["params_sha256"], hex::encode(sha));
    assert_eq!(p["reason"], "look at\nthe issue");
    assert_eq!(p["connection"]["agent_name"], "claude\u{202E}code");
    assert_eq!(p["connection"]["agent_name_source"], "flag");
    assert_eq!(p["connection"]["client_kind"], "cli");
    assert_eq!(p["connection"]["cwd_basename"], "atlas-duck");
    assert_eq!(p["connection"]["connection_id"], "conn_1");
    assert_eq!(p["connection"]["peer_pid"], 4242);
    assert_eq!(p["connection"]["peer_exe"], "/usr/bin/atlas-duck");
    assert_eq!(
        p["connection"]["peer_chain"][0]["start_time"],
        u64::MAX.to_string()
    );
    assert_eq!(p["connection"]["peer_origin_exe"], "/usr/bin/bash");
    assert_eq!(
        p["connection"]["peer_origin_start_time"],
        u64::MAX.to_string()
    );
    assert_eq!(
        p["normalized"],
        json!({
            "agent_name": "claudecode",
            "cwd_basename": "atlas-duck",
            "reason": "look at\nthe issue",
            "unusual": true,
        })
    );

    let h = &port.headers_for_request(id.as_str())?[0];
    assert_eq!(h.actor.agent_name.as_deref(), Some("claudecode"));
    assert_eq!(h.actor.agent_name_source.as_deref(), Some("flag"));
    assert_eq!(h.actor.client_kind.as_deref(), Some("cli"));
    assert_eq!(h.actor.connection_id.as_deref(), Some("conn_1"));
    assert_eq!(h.actor.peer_pid, Some(4242));
    assert_eq!(
        h.actor.peer_origin_exe,
        Some(PathBuf::from("/usr/bin/bash"))
    );
    assert_eq!(h.op_id.as_deref(), Some("jira.issue.get"));
    assert_eq!(h.target.as_deref(), Some("ABC-1"));
    assert_eq!(h.decision, None);
    Ok(())
}

#[test]
fn builders_append_with_their_columns() -> TestResult {
    let ts = TempStore::new()?;
    let port = ts.port();
    let c = ctx("req_all");
    let rev = CandidateRev {
        counter: 3,
        candidate_hash: [0xab; 32],
    };
    let ok = UpstreamResponse {
        status: 200,
        content_type: Some("application/json".into()),
        body: br#"{"key":"ABC-1"}"#.to_vec(),
    };
    let binary = UpstreamResponse {
        status: 200,
        content_type: Some("application/octet-stream".into()),
        body: vec![0xff, 0xfe, 0x00],
    };
    let records = vec![RequestRecord {
        index: 0,
        method: "POST".into(),
        resolved_url: "https://jira.corp/rest/api/2/issue/ABC-1/comment".into(),
        content_type: Some("application/json".into()),
        body_bytes: br#"{"body":"hi"}"#.to_vec(),
    }];
    let batch = BatchId::new()?;
    let ops = vec![RedactionOp::DropField {
        path: "fields.description".into(),
        scope: DropScope::PerItem,
    }];
    let mut details = Map::new();
    details.insert(
        "user_renamed".into(),
        json!({"old": "a", "new": "b", "user_key": "k"}),
    );

    let cases: Vec<(NewEvent, Option<DecisionColumn>, EventFlags)> = vec![
        (
            payloads::request_rejected(&c, ErrorCode::Validation, "bad", &json!({"param": "key"})),
            Some(DecisionColumn::Reject),
            EventFlags::default(),
        ),
        (
            payloads::request_failed(&c, ErrorCode::Internal),
            None,
            EventFlags::default(),
        ),
        (
            payloads::preview_fetch(
                &c,
                PreviewFetchPurpose::StaleCheck,
                "GET",
                "/rest/api/2/issue/{key}",
                &FetchRecord::Outcome {
                    outcome: OutcomeKind::Timeout,
                    status: Some(200),
                    content_type: Some("application/json"),
                    received: b"{\"partial",
                },
            ),
            None,
            EventFlags::default(),
        ),
        (
            payloads::decision_stale(&c, 2, 3, SubmittedDecision::Approve, true),
            None,
            EventFlags::default(),
        ),
        (
            payloads::decision_invalid(
                &c,
                InvalidReason::NotOpened,
                3,
                SubmittedDecision::Release,
                false,
            ),
            None,
            EventFlags::default(),
        ),
        (
            payloads::preview_shown(&c, &rev, &["W-1".to_owned()], "pb-1"),
            None,
            EventFlags::default(),
        ),
        (
            payloads::batch_confirmed(
                &Actor {
                    os_user: Some("jdoe".into()),
                    ..Actor::default()
                },
                batch.as_str(),
                &[("req_all".to_owned(), rev)],
                &[9; 32],
            ),
            None,
            EventFlags::default(),
        ),
        (
            payloads::delivered(&c, &hello(), &conn(), &[5; 32]),
            None,
            EventFlags::default(),
        ),
        (
            payloads::read_fetched(
                &c,
                &ReadFetched::CancelledInFlight {
                    reason: InFlightReason::Expired,
                    responses: std::slice::from_ref(&ok),
                    partial: b"[1,2",
                    size: 19,
                },
                Some(&json!({"ri:user": "x"})),
            ),
            None,
            EventFlags::default(),
        ),
        (
            payloads::read_released(&c, &binary.body, &ops)?,
            Some(DecisionColumn::ReleaseRedacted),
            EventFlags::REDACTED,
        ),
        (
            payloads::with_batch(payloads::read_released(&c, b"{}", &[])?, batch.as_str()),
            Some(DecisionColumn::Release),
            EventFlags::BATCH,
        ),
        (
            payloads::read_released_outcome(&c, ErrorCode::ResultTooLarge, "narrow the query"),
            Some(DecisionColumn::Release),
            EventFlags::default(),
        ),
        (
            payloads::read_denied(&c, Some("not now")),
            Some(DecisionColumn::Deny),
            EventFlags::default(),
        ),
        (
            payloads::read_failed(&c, ErrorCode::NeedsToken, "needs token", &json!({}), None),
            None,
            EventFlags::default(),
        ),
        (
            payloads::write_edited(&c, &json!({"a": 1}), &json!({"a": 2})),
            None,
            EventFlags::EDITED,
        ),
        (
            payloads::write_approved(&c, &rev, &records, true),
            Some(DecisionColumn::ApproveEdited),
            EventFlags::EDITED,
        ),
        (
            payloads::write_denied(&c, None, Some(&json!({"code": "resolution_failed"}))),
            Some(DecisionColumn::Deny),
            EventFlags::default(),
        ),
        (
            payloads::write_stale(&c, WriteStaleReason::RecheckFailed, Some("network")),
            None,
            EventFlags::STALE,
        ),
        (
            payloads::write_executed(&c, 0, &ok, Some("jdoe")),
            None,
            EventFlags::default(),
        ),
        (
            payloads::write_failed(
                &c,
                0,
                ErrorCode::UpstreamUnavailable,
                "redirect",
                &WriteFailure::Class {
                    class: "redirect",
                    status: Some(302),
                    received: b"<html>",
                },
            ),
            None,
            EventFlags::default(),
        ),
        (
            payloads::write_outcome_unknown(
                &c,
                0,
                &UnknownReason::IdentityMismatch {
                    server_user: Some("anonymous".into()),
                },
                Some(201),
                b"<html>",
            ),
            None,
            EventFlags::default(),
        ),
        (
            payloads::expired(&c),
            Some(DecisionColumn::Expire),
            EventFlags::default(),
        ),
        (
            payloads::cancelled(&c, CancelReason::AppQuit),
            Some(DecisionColumn::Cancel),
            EventFlags::default(),
        ),
        (
            payloads::instance_state_changed("ins_1", "user_renamed", &details),
            None,
            EventFlags::default(),
        ),
        (
            payloads::credential_changed(
                "ins_1",
                CredentialChange::Replaced,
                Some("k1"),
                Some("k2"),
                Some("2027-01-31"),
            ),
            None,
            EventFlags::default(),
        ),
        (
            payloads::config_changed(
                ConfigSource::File,
                "instance.ins_1.origin",
                &json!("https://a"),
                &json!("https://b"),
                false,
            ),
            None,
            EventFlags::default(),
        ),
        (
            payloads::config_changed(
                ConfigSource::App,
                "instance.ins_1.effective_proxy",
                &Value::Null,
                &json!("proxy.corp:3128"),
                true,
            ),
            None,
            EventFlags::default(),
        ),
        (
            payloads::app_start(ts.install_id(), &Map::new()),
            None,
            EventFlags::default(),
        ),
        (
            payloads::app_stop(AppStopReason::OsShutdown),
            None,
            EventFlags::default(),
        ),
    ];
    for (ev, decision, flags) in cases {
        let t = ev.event_type;
        let committed = port.append(ev)?;
        let h = port
            .recent_headers(Duration::from_secs(3_600))?
            .into_iter()
            .find(|h| h.seq == committed.seq)
            .ok_or("header")?;
        assert_eq!(h.event_type, t);
        assert_eq!(h.decision, decision, "{}", t.as_str());
        assert_eq!(h.flags, flags, "{}", t.as_str());
    }

    // WRITE_APPROVED: the F.8 shape and the hash the store verifies.
    let c2 = port.append(payloads::write_approved(&c, &rev, &records, false))?;
    let p = payload_of(&*port, &c2)?;
    assert_eq!(
        p["request_set_hash"],
        hex::encode(request_set_hash(&records))
    );
    assert_eq!(p["requests"][0]["method"], "POST");
    assert_eq!(p["requests"][0]["index"], 0);
    assert_eq!(
        p["candidate_rev"],
        json!({"counter": 3, "candidate_hash": hex::encode([0xab; 32])})
    );
    assert!(ts.store().full_verify().is_empty());
    Ok(())
}

/// A read at the 50 MiB fetch cap commits its `READ_FETCHED` with every byte (§5.2 step 3/6),
/// even for quote-dense, multibyte content whose partial page is cut inside a character
/// (Task 17 review I-3): bodies never encode larger than base64, and the store's limit fits.
#[test]
fn read_fetched_at_the_fetch_cap_commits() -> TestResult {
    let ts = TempStore::new()?;
    let port = ts.port();
    let mib = 1024 * 1024;
    // Quote-dense JSON with umlauts (escaped longer than raw, shorter than base64).
    let unit = r#"{"name":"Müller Straße","note":"lorem ipsum dolor"},"#;
    let fill = |n: usize| -> Vec<u8> {
        let mut v = unit.repeat(n / unit.len() + 1).into_bytes();
        v.truncate(n);
        v
    };
    let page = UpstreamResponse {
        status: 200,
        content_type: Some("application/json".into()),
        body: fill(18 * mib),
    };
    // 32 MiB + 1 chunk, cut after the first byte of a 2-byte `ü`.
    let mut partial = fill(32 * mib + 64 * 1024);
    while std::str::from_utf8(&partial).is_ok() {
        partial.pop();
    }
    let size = (page.body.len() + partial.len()) as u64;
    assert!(size > 50 * 1024 * 1024);
    let ev = payloads::read_fetched(
        &ctx("req_cap"),
        &ReadFetched::Outcome {
            outcome: OutcomeKind::TooLarge,
            cap_or_budget: Some(CapOrBudget::FetchCap50MiB),
            responses: std::slice::from_ref(&page),
            partial: &partial,
            size,
        },
        None,
    );
    let c = port.append(ev)?;
    let p = payload_of(&*port, &c)?;
    assert_eq!(
        payloads::body_from_json(&p["responses"][0]["body"]),
        Some(page.body.clone())
    );
    assert_eq!(payloads::body_from_json(&p["partial"]), Some(partial));
    assert!(p["partial"]["tail_b64"].is_string());
    assert_eq!(p["size"], size);
    Ok(())
}
