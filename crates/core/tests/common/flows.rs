//! Runs `testing::Flow`s over a harness (Task 29) and checks the audit properties that hold over
//! any sequence of them: coverage of every authenticated wiremock hit (I-19) and `PREVIEW_SHOWN`
//! before every positive decision (U-32).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_PAT, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_atlassian::{ReadBudget, Timeouts};
use atlas_duck_audit::EventType;
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::{AuditRecord, Flow, Harness};
use atlas_duck_core::{DecisionError, Edits, RedactionOp, ShutdownReason};
use atlas_duck_ipc::build_info::APP_VERSION;
use atlas_duck_ipc::envelope::Status;
use serde_json::{Map, Value, json};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, Request, ResponseTemplate};

use super::{TestError, de, request_id};

const ISSUE: &str = "jira.issue.get";
const SEARCH: &str = "jira.search";
const COMMENT: &str = "jira.comment.add";
const EDIT: &str = "jira.issue.edit";
const TRANSITION: &str = "jira.issue.transition";

/// A delayed answer outlives any flow: the flows that use it cancel or expire the request first.
const HANG: Duration = Duration::from_secs(5);

/// `path_regex` needs the context path's characters taken literally.
fn regex_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            let special = ".+*?()|[]{}^$\\".contains(c);
            special
                .then_some('\\')
                .into_iter()
                .chain(std::iter::once(c))
        })
        .collect()
}

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

/// A `jira-main` harness whose per-call timeout and response cap are small, so a slow key is a
/// timeout outcome and a 100 KiB body an over-cap outcome without a long wait.
pub async fn flow_harness() -> Result<Harness, TestError> {
    flow_harness_with_pat(TEST_PAT).await
}

/// `flow_harness` whose stored PAT is `pat`.
pub async fn flow_harness_with_pat(pat: &str) -> Result<Harness, TestError> {
    Harness::builder()
        .jira("jira-main")
        .pat(pat)
        .timeouts(Timeouts {
            per_call: Duration::from_millis(800),
            ..Timeouts::default()
        })
        .read_budget(ReadBudget {
            max_response_bytes: 64 * 1024,
            max_bytes: 128 * 1024,
            ..ReadBudget::default()
        })
        .start()
        .await
}

fn issue_re(mock: &MockDc, keys: &str, tail: &str) -> String {
    format!(
        "^{}(?:{keys})-[0-9]+{tail}$",
        regex_escape(&mock.path("/rest/api/2/issue/"))
    )
}

async fn mount(mock: &MockDc, m: &str, re: String, t: ResponseTemplate) {
    Mock::given(method(m))
        .and(path_regex(re))
        .respond_with(t)
        .mount(mock.server())
        .await;
}

/// The answers every flow key family gets (`ABC` released, `ERR` 404, `SLOW` slower than the
/// per-call timeout, `OUT` over the response cap, `HANG` and `ENR` that never answer in time).
pub async fn mount_jira(h: &Harness) -> Result<(), TestError> {
    mount_jira_with(h, fixtures::JIRA_ISSUE).await
}

/// `mount_jira` with `issue` as the body of every `ABC`/`EDT` issue.
pub async fn mount_jira_with(h: &Harness, issue: &str) -> Result<(), TestError> {
    let mock = jira(h)?;
    // A server of an earlier harness may have had this very URI (a port is reused): its hits
    // are not this mock's.
    hits_of(mock)
        .seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.jira_server_info("9.12.0").await;
    let json_body = |t: ResponseTemplate, b: &str| t.set_body_raw(b.to_owned(), "application/json");
    mount(
        mock,
        "GET",
        issue_re(mock, "ABC|EDT", ""),
        json_body(mock.response(200), issue),
    )
    .await;
    mount(
        mock,
        "GET",
        issue_re(mock, "ERR", ""),
        json_body(
            mock.response(404),
            r#"{"errorMessages":["Issue does not exist"],"errors":{}}"#,
        ),
    )
    .await;
    mount_hang(
        mock,
        issue_re(mock, "SLOW|HANG", ""),
        json_body(mock.response(200), fixtures::JIRA_ISSUE).set_delay(HANG),
    )
    .await;
    let filler: String = std::iter::repeat_n('o', 100 * 1024).collect();
    // One search page over the response cap: an outcome item (a single `GET` has the fixed
    // 32 MiB cap, only paged reads scale with the budget).
    let page = json!({
        "startAt": 0, "maxResults": 1, "total": 100_000,
        "issues": [{ "id": "1", "key": "OUT-1", "fields": { "summary": filler } }]
    });
    mount(
        mock,
        "POST",
        format!("^{}$", regex_escape(&mock.path("/rest/api/2/search"))),
        json_body(mock.response(200), &page.to_string()),
    )
    .await;
    mount_hang(
        mock,
        issue_re(mock, "ENR", "/transitions"),
        json_body(mock.response(200), fixtures::JIRA_TRANSITIONS).set_delay(HANG),
    )
    .await;
    mount(
        mock,
        "POST",
        issue_re(mock, "ABC", "/comment"),
        json_body(mock.response(201), fixtures::JIRA_COMMENT),
    )
    .await;
    mount(mock, "PUT", issue_re(mock, "EDT", ""), mock.response(204)).await;
    Ok(())
}

fn issue_with(summary: &str) -> String {
    let mut issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE).unwrap_or(Value::Null);
    issue["fields"]["summary"] = json!(summary);
    issue.to_string()
}

/// The paths a mock was asked for by the delayed answers, in order, with a counter that moves
/// on every hit: a flow waits on the arrival itself, with no poll interval that could outlast
/// the per-call timeout and turn the flow's intended outcome into a timeout one.
struct Hits {
    seen: Mutex<Vec<String>>,
    count: tokio::sync::watch::Sender<u64>,
}

/// One `Hits` per mock server (its URI): flows of different harnesses never see each other.
fn hits_of(mock: &MockDc) -> Arc<Hits> {
    static ALL: OnceLock<Mutex<HashMap<String, Arc<Hits>>>> = OnceLock::new();
    let mut all = ALL
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    all.entry(mock.server().uri())
        .or_insert_with(|| {
            Arc::new(Hits {
                seen: Mutex::new(Vec::new()),
                count: tokio::sync::watch::channel(0).0,
            })
        })
        .clone()
}

/// `mount` for an answer that is delayed by `HANG`: the arrival of the request is recorded the
/// moment the mock answers.
async fn mount_hang(mock: &MockDc, re: String, t: ResponseTemplate) {
    let hits = hits_of(mock);
    Mock::given(method("GET"))
        .and(path_regex(re))
        .respond_with(move |req: &Request| {
            hits.seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(req.url.path().to_owned());
            hits.count.send_modify(|n| *n += 1);
            t.clone()
        })
        .mount(mock.server())
        .await;
}

/// Waits until a delayed-answer request on a path ending `tail` has arrived at the mock.
async fn wait_hit(mock: &MockDc, tail: &str) -> Result<(), TestError> {
    let hits = hits_of(mock);
    let mut rx = hits.count.subscribe();
    let arrived = async {
        loop {
            let seen = hits
                .seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .any(|p| p.ends_with(tail));
            if seen {
                return Ok(());
            }
            rx.changed().await?;
        }
    };
    match tokio::time::timeout(Duration::from_secs(10), arrived).await {
        Ok(r) => r,
        Err(_) => Err(format!("the mock never received {tail}").into()),
    }
}

/// The request's `READ_FETCHED` is the one a cancel or expiry commits for bytes in flight, with
/// the given reason: a timeout or budget outcome in its place would pass the status check of the
/// flow and cover the wrong thing (I-19).
async fn expect_cancelled_in_flight(h: &Harness, id: &str, reason: &str) -> Result<(), TestError> {
    let events = h.events(id).await?;
    let fetched = events
        .iter()
        .find(|(t, _)| *t == EventType::READ_FETCHED)
        .map(|(_, p)| p.clone())
        .ok_or_else(|| {
            let types: Vec<_> = events.iter().map(|(t, _)| t.as_str()).collect();
            format!("no READ_FETCHED record, only {types:?}")
        })?;
    if fetched["outcome"] != "cancelled_in_flight" || fetched["reason"] != reason {
        return Err(format!("READ_FETCHED is not cancelled_in_flight/{reason}: {fetched}").into());
    }
    Ok(())
}

async fn submit_queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    if env.status != Status::Pending {
        return Err(format!("not pending: {}", env.to_json_line()).into());
    }
    let id = request_id(&env)?;
    h.queued(&id, 20_000)
        .await
        .ok_or_else(|| format!("{id} never queued"))?;
    Ok(id)
}

fn expect(what: &str, got: Status, want: Status) -> Result<(), TestError> {
    if got == want {
        Ok(())
    } else {
        Err(format!("{what}: {got:?}, wanted {want:?}").into())
    }
}

/// Runs flow number `n` (its keys are unique to it).
pub async fn run_flow(h: &Harness, flow: Flow, n: usize) -> Result<(), TestError> {
    let mock = jira(h)?;
    let ap = h.approver();
    match flow {
        Flow::ReadRelease => {
            let id = submit_queued(h, ISSUE, json!({ "key": format!("ABC-{n}") })).await?;
            ap.release(&id).map_err(de)?;
            expect(
                "release",
                h.await_(&id, 10_000).await.status,
                Status::Released,
            )
        }
        Flow::ReadDeny => {
            let id = submit_queued(h, ISSUE, json!({ "key": format!("ABC-{n}") })).await?;
            ap.deny(&id, "not needed").map_err(de)?;
            expect("deny", h.await_(&id, 10_000).await.status, Status::Denied)
        }
        Flow::ReadUpstreamError => {
            let id = submit_queued(h, ISSUE, json!({ "key": format!("ERR-{n}") })).await?;
            ap.release(&id).map_err(de)?;
            expect("error", h.await_(&id, 10_000).await.status, Status::Failed)
        }
        Flow::ReadOutcome => {
            let id = submit_queued(
                h,
                SEARCH,
                json!({ "jql": format!("project = OUT AND n = {n}"), "max": 10 }),
            )
            .await?;
            ap.release(&id).map_err(de)?;
            expect(
                "outcome",
                h.await_(&id, 10_000).await.status,
                Status::Failed,
            )?;
            // A slow answer is the per-call timeout outcome.
            let id = submit_queued(h, ISSUE, json!({ "key": format!("SLOW-{n}") })).await?;
            ap.release(&id).map_err(de)?;
            expect(
                "timeout",
                h.await_(&id, 10_000).await.status,
                Status::Failed,
            )
        }
        Flow::ReadCancelMidFetch => {
            let key = format!("HANG-{n}");
            let env = h.submit(ISSUE, json!({ "key": key })).await;
            let id = request_id(&env)?;
            wait_hit(mock, &format!("/{key}")).await?;
            expect(
                "cancel",
                h.handler().cancel(&id).await.status,
                Status::Cancelled,
            )?;
            expect_cancelled_in_flight(h, &id, "by_client").await
        }
        Flow::ReadExpireMidFetch => {
            let key = format!("HANG-{n}");
            let env = h.submit(ISSUE, json!({ "key": key })).await;
            let id = request_id(&env)?;
            wait_hit(mock, &format!("/{key}")).await?;
            if !h.expire_now(&id).await {
                return Err("expire_now: not pending".into());
            }
            expect("expire", h.status(&id).await.status, Status::Expired)?;
            expect_cancelled_in_flight(h, &id, "expired").await
        }
        Flow::WriteApprove | Flow::WriteDeny => {
            let params =
                json!({ "key": format!("ABC-{n}"), "body": "Seen.", "body_format": "wiki" });
            let id = submit_queued(h, COMMENT, params).await?;
            if flow == Flow::WriteDeny {
                ap.deny(&id, "no").map_err(de)?;
                expect(
                    "write deny",
                    h.await_(&id, 10_000).await.status,
                    Status::Denied,
                )
            } else {
                ap.approve(&id).map_err(de)?;
                expect(
                    "write",
                    h.await_(&id, 10_000).await.status,
                    Status::Succeeded,
                )
            }
        }
        Flow::WriteEditApprove => {
            let params = json!({
                "key": format!("EDT-{n}"),
                "fields": { "summary": "Login fails" },
                "expected": { "summary": "Login page times out" }
            });
            let id = submit_queued(h, EDIT, params).await?;
            let rev1 = ap.rev(&id).map_err(de)?;
            let mut set = Map::new();
            set.insert("fields.summary".into(), json!("Login fails after reset"));
            ap.edit(
                &id,
                Edits {
                    set,
                    remove: Vec::new(),
                },
            )
            .map_err(de)?;
            // `fields` is enrichment-relevant: a re-enrichment, then a new revision.
            let mut bumped = false;
            for _ in 0..500 {
                if ap
                    .item(&id)
                    .is_some_and(|i| i.candidate_rev.counter > rev1.counter)
                {
                    bumped = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if !bumped {
                return Err("the edit never produced a new revision".into());
            }
            ap.approve(&id).map_err(de)?;
            expect(
                "edit",
                h.await_(&id, 10_000).await.status,
                Status::Succeeded,
            )
        }
        Flow::WriteStaleChanged => {
            let key = format!("STL-{n}");
            let exact = format!(
                "^{}$",
                regex_escape(&mock.path(&format!("/rest/api/2/issue/{key}")))
            );
            // Enrichment sees `Before`, the stale check `After`.
            Mock::given(method("GET"))
                .and(path_regex(exact.clone()))
                .respond_with(
                    mock.response(200)
                        .set_body_raw(issue_with("Before"), "application/json"),
                )
                .up_to_n_times(1)
                .with_priority(1)
                .mount(mock.server())
                .await;
            Mock::given(method("GET"))
                .and(path_regex(exact))
                .respond_with(
                    mock.response(200)
                        .set_body_raw(issue_with("After"), "application/json"),
                )
                .with_priority(2)
                .mount(mock.server())
                .await;
            let params = json!({
                "key": key,
                "fields": { "summary": "New" },
                "expected": { "summary": "Before" }
            });
            let id = submit_queued(h, EDIT, params).await?;
            ap.approve(&id).map_err(de)?;
            let mut reason = Value::Null;
            for _ in 0..500 {
                let events = h.events(&id).await?;
                if let Some((_, p)) = events.iter().find(|(t, _)| *t == EventType::WRITE_STALE) {
                    reason = p["reason"].clone();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if reason != json!("changed") {
                return Err(format!("stale reason {reason}").into());
            }
            // `WRITE_STALE` commits before the write is back in the queue (stale, decidable).
            for _ in 0..500 {
                if ap.item(&id).is_some_and(|i| i.stale) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            ap.deny(&id, "changed meanwhile").map_err(de)?;
            expect("stale", h.await_(&id, 10_000).await.status, Status::Denied)
        }
        Flow::EnrichCancel => {
            let key = format!("ENR-{n}");
            let env = h
                .submit(TRANSITION, json!({ "key": key, "transition": "Done" }))
                .await;
            let id = request_id(&env)?;
            wait_hit(mock, &format!("/{key}/transitions")).await?;
            expect(
                "cancel",
                h.handler().cancel(&id).await.status,
                Status::Cancelled,
            )
        }
        Flow::ConnectionTest => {
            h.instances()
                .retest_token("jira-main")
                .await
                .map_err(|e| format!("{e:?}"))?;
            Ok(())
        }
        Flow::Doctor => {
            h.handler().doctor().await;
            Ok(())
        }
        Flow::Quit => {
            h.core().shutdown(ShutdownReason::Quit).await;
            Ok(())
        }
    }
}

/// Decisions on revisions nobody opened (M3 T29 M-11): after a redaction (a read) and after an
/// edit (a write) the new revision is refused as `NotOpened`, then opened and decided, so the
/// U-32 property runs over a log that saw the guard fire. Flow number `n` (its keys are unique).
pub async fn run_unopened_attempts(h: &Harness, n: usize) -> Result<(), TestError> {
    let ap = h.approver();
    let not_opened = |what: &str, res: Result<_, DecisionError>| -> Result<(), TestError> {
        match res {
            Err(DecisionError::Invalid(InvalidReason::NotOpened)) => Ok(()),
            Err(e) => Err(format!("{what}: {e:?}, wanted NotOpened").into()),
            Ok(_) => Err(format!("{what}: decided an unopened revision").into()),
        }
    };
    // A read: open, redact, release the redacted revision unopened (refused), open, release.
    let id = submit_queued(h, ISSUE, json!({ "key": format!("ABC-{n}") })).await?;
    ap.open(&id).map_err(de)?;
    let mask = RedactionOp::MaskText {
        text: "Login page".into(),
        every_occurrence: true,
        at: None,
    };
    ap.redact(&id, vec![mask]).map_err(de)?;
    not_opened("release after a redaction", ap.release_unopened(&id))?;
    ap.release(&id).map_err(de)?;
    expect(
        "redacted release",
        h.await_(&id, 10_000).await.status,
        Status::Released,
    )?;
    // A write: edit (a new revision), approve it unopened (refused), open, approve.
    let params = json!({
        "key": format!("EDT-{n}"),
        "fields": { "summary": "Login fails" },
        "expected": { "summary": "Login page times out" }
    });
    let id = submit_queued(h, EDIT, params).await?;
    let rev1 = ap.rev(&id).map_err(de)?;
    ap.open(&id).map_err(de)?;
    let mut set = Map::new();
    set.insert("fields.summary".into(), json!("Login fails after reset"));
    ap.edit(
        &id,
        Edits {
            set,
            remove: Vec::new(),
        },
    )
    .map_err(de)?;
    let mut bumped = false;
    for _ in 0..500 {
        if ap
            .item(&id)
            .is_some_and(|i| i.candidate_rev.counter > rev1.counter)
        {
            bumped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if !bumped {
        return Err("the edit never produced a new revision".into());
    }
    not_opened("approve after an edit", ap.approve_unopened(&id))?;
    ap.approve(&id).map_err(de)?;
    expect(
        "edited write",
        h.await_(&id, 10_000).await.status,
        Status::Succeeded,
    )
}

// ---- Properties over the log ---------------------------------------------------------------------------

fn seq_of(first: &HashMap<String, u64>, id: &str) -> Option<u64> {
    first.get(id).copied()
}

/// The path of a resolved URL, without query.
fn url_path(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let from_path = rest.find('/').map_or("", |i| &rest[i..]);
    from_path.split('?').next().unwrap_or_default().to_owned()
}

fn bare(p: &str) -> String {
    p.split('?').next().unwrap_or_default().to_owned()
}

/// I-19: every wiremock hit with an `Authorization` header has a response record (a
/// `READ_FETCHED` page or in-flight cancel, a `PREVIEW_FETCH`, a `SYSTEM_FETCH` result, a write's
/// executed/failed/unknown) committed after its covering start (`REQUEST_RECEIVED`, the system
/// fetch's `start`, the write's approval), and no `(method, path)` was hit more often than it has
/// such records. Every hit carries the app's `User-Agent`. Returns how many authenticated hits it
/// covered.
pub async fn check_coverage(h: &Harness) -> Result<usize, String> {
    let mock = jira(h).map_err(|e| e.to_string())?;
    let recs = h.audit_records().await.map_err(|e| e.to_string())?;
    let mut received: HashMap<String, (u64, Value)> = HashMap::new();
    let mut started: HashMap<String, u64> = HashMap::new();
    let mut approved: HashMap<String, Vec<(u64, Value)>> = HashMap::new();
    let mut first: HashMap<String, u64> = HashMap::new();
    for r in &recs {
        match (r.event_type, &r.request_id) {
            (EventType::REQUEST_RECEIVED, Some(id)) => {
                first.entry(id.clone()).or_insert(r.seq);
                received.insert(id.clone(), (r.seq, r.payload.clone()));
            }
            (EventType::WRITE_APPROVED, Some(id)) => {
                approved
                    .entry(id.clone())
                    .or_default()
                    .push((r.seq, r.payload.clone()));
            }
            (EventType::SYSTEM_FETCH, _) if r.payload["phase"] == "start" => {
                if let Some(f) = r.payload["fetch_id"].as_str() {
                    started.insert(f.to_owned(), r.seq);
                }
            }
            _ => {}
        }
    }
    let after_received = |r: &AuditRecord| -> Result<(), String> {
        let id = r
            .request_id
            .as_deref()
            .ok_or_else(|| format!("{:?} without a request id", r.event_type))?;
        match seq_of(&first, id) {
            Some(s) if s < r.seq => Ok(()),
            _ => Err(format!(
                "{:?} {} before its REQUEST_RECEIVED",
                r.event_type, r.seq
            )),
        }
    };
    let mut covers: HashMap<(String, String), usize> = HashMap::new();
    let mut add = |m: &str, p: &str, n: usize| {
        *covers.entry((m.to_owned(), bare(p))).or_insert(0) += n;
    };
    for r in &recs {
        match r.event_type {
            EventType::READ_FETCHED => {
                after_received(r)?;
                let id = r.request_id.as_deref().unwrap_or_default();
                let params = received
                    .get(id)
                    .map(|(_, p)| p["params"].clone())
                    .unwrap_or(Value::Null);
                // A page record carries no method or path: they follow from the op.
                let (m, p) = match r.op_id.as_deref() {
                    Some(ISSUE) => {
                        let key = params["key"].as_str().ok_or("read without a key")?;
                        ("GET", mock.path(&format!("/rest/api/2/issue/{key}")))
                    }
                    Some(SEARCH) => ("POST", mock.path("/rest/api/2/search")),
                    other => return Err(format!("unexpected read op {other:?}")),
                };
                let pages = r.payload["responses"].as_array().map_or(0, Vec::len);
                let marker = usize::from(r.payload["outcome"].is_string());
                // Coverage is per (method, path) across requests: a hit carries no request id
                // and `READ_FETCHED` no path. The marker is the over-cap / timeout / cancelled
                // answer that has a hit but no response page; it can mask one extra hit.
                add(m, &p, pages + marker);
            }
            EventType::PREVIEW_FETCH => {
                after_received(r)?;
                add(
                    r.payload["method"].as_str().unwrap_or_default(),
                    r.payload["path"].as_str().unwrap_or_default(),
                    1,
                );
            }
            EventType::SYSTEM_FETCH if r.payload["phase"] == "result" => {
                let f = r.payload["fetch_id"].as_str().unwrap_or_default();
                match started.get(f) {
                    Some(s) if *s < r.seq => {}
                    _ => {
                        return Err(format!(
                            "SYSTEM_FETCH result {} without an earlier start",
                            r.seq
                        ));
                    }
                }
                add(
                    r.payload["method"].as_str().unwrap_or_default(),
                    r.payload["path"].as_str().unwrap_or_default(),
                    1,
                );
            }
            EventType::WRITE_EXECUTED
            | EventType::WRITE_FAILED
            | EventType::WRITE_OUTCOME_UNKNOWN => {
                after_received(r)?;
                let id = r.request_id.as_deref().unwrap_or_default();
                let (_, ap) = approved
                    .get(id)
                    .and_then(|v| v.iter().rev().find(|(s, _)| *s < r.seq))
                    .ok_or_else(|| {
                        format!("{:?} {} without an earlier approval", r.event_type, r.seq)
                    })?;
                let idx = r.payload["request_index"].as_u64().unwrap_or(0) as usize;
                let req = &ap["requests"][idx];
                add(
                    req["method"].as_str().unwrap_or_default(),
                    &url_path(req["url"].as_str().unwrap_or_default()),
                    1,
                );
            }
            _ => {}
        }
    }
    let ua = format!("atlas-duck/{APP_VERSION}");
    let mut hits: HashMap<(String, String), usize> = HashMap::new();
    let mut authed = 0;
    for r in mock.received().await {
        let got = r.headers.get("user-agent").and_then(|v| v.to_str().ok());
        if got != Some(ua.as_str()) {
            return Err(format!("{} {}: User-Agent {got:?}", r.method, r.url.path()));
        }
        if !r.headers.contains_key("authorization") {
            return Err(format!(
                "{} {}: no Authorization header",
                r.method,
                r.url.path()
            ));
        }
        *hits
            .entry((r.method.to_string(), r.url.path().to_owned()))
            .or_insert(0) += 1;
        authed += 1;
    }
    for (k, n) in &hits {
        let have = covers.get(k).copied().unwrap_or(0);
        if *n > have {
            return Err(format!(
                "{} {}: {n} hits, {have} response records",
                k.0, k.1
            ));
        }
    }
    Ok(authed)
}

/// U-32 (PD-57): every `READ_RELEASED`, `WRITE_APPROVED` and `SCRIPT_RELEASED` carries a
/// `candidate_rev` (an object, never null) equal to that of an earlier `PREVIEW_SHOWN` of the same
/// request. A data release's bytes also hash to that revision's `candidate_hash`.
pub async fn check_preview_shown(h: &Harness) -> Result<usize, String> {
    let recs = h.audit_records().await.map_err(|e| e.to_string())?;
    let mut checked = 0;
    for r in &recs {
        if !matches!(
            r.event_type,
            EventType::READ_RELEASED | EventType::WRITE_APPROVED | EventType::SCRIPT_RELEASED
        ) {
            continue;
        }
        let id = r
            .request_id
            .as_deref()
            .ok_or("positive decision without a request id")?;
        let rev = &r.payload["candidate_rev"];
        if !rev.is_object() {
            return Err(format!(
                "{:?} {} of {id} has no candidate_rev object: {rev}",
                r.event_type, r.seq
            ));
        }
        let shown = |p: &Value| -> bool {
            p["candidate_rev"] == *rev
                && (r.event_type != EventType::READ_RELEASED
                    || !r.payload["released_sha256"].is_string()
                    || p["candidate_rev"]["candidate_hash"] == r.payload["released_sha256"])
        };
        let ok = recs.iter().any(|s| {
            s.event_type == EventType::PREVIEW_SHOWN
                && s.seq < r.seq
                && s.request_id.as_deref() == Some(id)
                && shown(&s.payload)
        });
        if !ok {
            return Err(format!(
                "{:?} {} of {id} has no earlier PREVIEW_SHOWN of its revision",
                r.event_type, r.seq
            ));
        }
        checked += 1;
    }
    Ok(checked)
}
