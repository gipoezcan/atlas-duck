#![cfg(feature = "testing")]
//! Task 19: the identity and re-check sweep on the Jira paths.
//!
//! * RF-5b (PD-58): Agile and `POST /rest/api/2/search` answers without `X-AUSERNAME` run the
//!   token re-check and fail `upstream_unavailable`, the check is never skipped.
//! * I-23 (§5.4 step 5, §7.2): every Jira write's last pre-write GET (the stale rule's GET, or the
//!   identity call where the rule is "none") and every refresh GET that is not a parsed 2xx JSON
//!   answer returns the write as `WRITE_STALE {recheck_failed, class}`; nothing is sent.
//! * The M3 Task 26 test gaps (stale-check rename re-run, refresh identity failure, header class,
//!   inconclusive re-check, write-response rename, keychain failure on a rename), PD-61 (a parsed
//!   `/myself` 200 without `name` or `key` is a token failure) and PD-65 (a stale check against a
//!   `needs_token` instance is `identity_mismatch`).
//!
//! A stale check cancelled by the shutdown is `shutdown.rs::a_write_in_stale_check_is_cancelled_by
//! _the_shutdown` (M3); it is not repeated here.

mod common;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_PAT, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_atlassian::{CredentialProvider, Timeouts};
use atlas_duck_audit::EventType;
use atlas_duck_core::identity::{RecheckResult, on_result};
use atlas_duck_core::testing::{Channel, Harness, InstanceAt};
use atlas_duck_core::{Pause, QueueItem, ShutdownReason, TestHooks, op_table};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_preview::warning::WarningId;
use atlas_duck_registry::{OpClass, Product};
use common::jira::mount_without_xauser;
use common::{TestError, TestResult, code, de, detail, exit, request_id, test_hits};
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

/// Text that only ever sits in an upstream body: it may reach the audit log, never an envelope.
const MARKER: &str = "UPSTREAM-BODY-MARKER";
const MYSELF: &str = "/rest/api/2/myself";
const ISSUE_PATH: &str = "/rest/api/2/issue/ABC-1";
const TRANSITIONS_PATH: &str = "/rest/api/2/issue/ABC-1/transitions";
const SPRINT_PATH: &str = "/rest/agile/1.0/sprint/7";
const COMMENT: &str = "jira.comment.add";
const TRANSITION: &str = "jira.issue.transition";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn wait_for<F: Fn() -> bool>(what: &str, f: F) -> TestResult {
    for _ in 0..1000 {
        if f() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("timed out waiting for {what}").into())
}

/// The queue item once its revision moved past `rev`.
async fn item_after(h: &Harness, id: &str, rev: u64) -> Result<QueueItem, TestError> {
    for _ in 0..1200 {
        if let Some(item) = h.approver().item(id)
            && item.candidate_rev.counter > rev
        {
            return Ok(item);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err("the revision never advanced".into())
}

/// The payloads of `id`'s records of type `t`, in order.
async fn payloads(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

/// The `SYSTEM_FETCH {purpose: token_recheck}` records of `phase`.
async fn rechecks(h: &Harness, phase: &str) -> Result<Vec<Value>, TestError> {
    Ok(h.events_of(EventType::SYSTEM_FETCH)
        .await?
        .into_iter()
        .filter(|p| p["purpose"] == "token_recheck" && p["phase"] == phase)
        .collect())
}

async fn state_changes(h: &Harness) -> Result<Vec<Value>, TestError> {
    h.events_of(EventType::INSTANCE_STATE_CHANGED).await
}

fn state_of(h: &Harness) -> &'static str {
    h.instances().list().first().map_or("?", |i| i.state)
}

/// No envelope the agent received carries an upstream body.
fn assert_no_marker_in_envelopes(h: &Harness) {
    assert!(
        !h.capture()
            .on(Channel::Envelope)
            .iter()
            .any(|c| c.json.contains(MARKER)),
        "an upstream body reached an envelope"
    );
}

/// The non-GET requests the mock received.
async fn sends(mock: &MockDc) -> usize {
    mock.received()
        .await
        .iter()
        .filter(|r| r.method.as_str() != "GET")
        .count()
}

/// The `path` of every `PREVIEW_FETCH {purpose}` of `id`, without the query and without the
/// mock's `/jira` context path.
async fn fetch_paths(h: &Harness, id: &str, purpose: &str) -> Result<Vec<String>, TestError> {
    Ok(payloads(h, id, EventType::PREVIEW_FETCH)
        .await?
        .into_iter()
        .filter(|p| p["purpose"] == purpose)
        .filter_map(|p| {
            p["path"]
                .as_str()
                .and_then(|s| s.split('?').next())
                .map(|s| s.strip_prefix("/jira").unwrap_or(s).to_owned())
        })
        .collect())
}

/// A failed read's terminal envelope.
async fn failed_read(h: &Harness, id: &str) -> Result<Envelope, TestError> {
    assert!(h.settled(id, 20_000).await, "never settled");
    let env = h.await_(id, 1000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    Ok(env)
}

// ---- a path-routed raw HTTP server ---------------------------------------------------------------
//
// `wiremock` cannot cut a body short (a connection reset), and `RawHttpServer` answers by
// connection order; the I-23 table needs both a reset and answers chosen by path, so this server
// answers each connection by its request line (`METHOD /path`, the query ignored). Every answer
// says `Connection: close`, so each request is its own connection.

/// Raw response bytes, sent `delay` after the request arrived; then the connection closes.
#[derive(Clone)]
struct Answer {
    bytes: Arc<Vec<u8>>,
    delay: Duration,
}

impl Answer {
    fn new(bytes: Vec<u8>) -> Answer {
        Answer {
            bytes: Arc::new(bytes),
            delay: Duration::ZERO,
        }
    }

    fn after(self, delay: Duration) -> Answer {
        Answer { delay, ..self }
    }
}

#[derive(Default)]
struct Routes {
    /// `METHOD /path` → the answers in order; the last one repeats.
    table: Mutex<HashMap<String, VecDeque<Answer>>>,
    /// `METHOD /path` of every request, in arrival order.
    hits: Mutex<Vec<String>>,
    active: AtomicUsize,
    max_active: AtomicUsize,
}

struct Router {
    addr: SocketAddr,
    routes: Arc<Routes>,
    task: JoinHandle<()>,
}

impl Router {
    async fn start() -> Result<Router, TestError> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let routes = Arc::new(Routes::default());
        let r = routes.clone();
        let task = tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(serve(sock, r.clone()));
            }
        });
        Ok(Router { addr, routes, task })
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// From now on `METHOD /path` answers `answers` in order (the last one repeats).
    fn route(&self, key: &str, answers: Vec<Answer>) {
        lock(&self.routes.table).insert(key.to_owned(), answers.into());
    }

    fn hits(&self) -> Vec<String> {
        lock(&self.routes.hits).clone()
    }

    /// The non-GET requests received.
    fn sends(&self) -> Vec<String> {
        self.hits()
            .into_iter()
            .filter(|h| !h.starts_with("GET "))
            .collect()
    }

    fn max_active(&self) -> usize {
        self.routes.max_active.load(Ordering::SeqCst)
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(mut sock: TcpStream, routes: Arc<Routes>) {
    let now = routes.active.fetch_add(1, Ordering::SeqCst) + 1;
    routes.max_active.fetch_max(now, Ordering::SeqCst);
    if let Some(key) = request_key(&mut sock).await {
        lock(&routes.hits).push(key.clone());
        let answer = {
            let mut table = lock(&routes.table);
            table.get_mut(&key).and_then(|q| {
                if q.len() > 1 {
                    q.pop_front()
                } else {
                    q.front().cloned()
                }
            })
        };
        let answer = answer
            .unwrap_or_else(|| json_answer("404 Not Found", r#"{"errorMessages":["no route"]}"#));
        tokio::time::sleep(answer.delay).await;
        // The connection stops counting before its answer goes out: the client frees its limiter
        // permit only after it read the answer, so the server's count never exceeds the
        // client's (a new connection cannot be counted while this one still is).
        routes.active.fetch_sub(1, Ordering::SeqCst);
        let _ = sock.write_all(&answer.bytes).await;
        let _ = sock.flush().await;
    } else {
        routes.active.fetch_sub(1, Ordering::SeqCst);
    }
    let _ = sock.shutdown().await;
}

/// Reads the request head and its `Content-Length` body; returns `METHOD /path`.
async fn request_key(sock: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 || buf.len() > 64 * 1024 {
            return None;
        }
        buf.extend_from_slice(tmp.get(..n)?);
    };
    let head = String::from_utf8_lossy(buf.get(..head_end)?).into_owned();
    let body_len = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf.len() - head_end;
    while body < body_len {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body += n;
    }
    let mut line = head.lines().next()?.split_whitespace();
    let (m, target) = (line.next()?, line.next()?);
    Some(format!("{m} {}", target.split('?').next()?))
}

/// An HTTP/1.1 answer with `Connection: close` and the body's `Content-Length`.
fn raw(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut head = format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        let _ = write!(head, "{k}: {v}\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// A JSON answer as Jira sends it to the harness user (`X-AUSERNAME: jdoe`).
fn json_answer(status: &str, body: &str) -> Answer {
    Answer::new(raw(
        status,
        &[
            ("Content-Type", "application/json;charset=UTF-8"),
            ("X-AUSERNAME", TEST_USER),
        ],
        body.as_bytes(),
    ))
}

fn ok_json(body: &str) -> Answer {
    json_answer("200 OK", body)
}

/// `204 No Content` (the declared success of the `Empty` Jira writes; no `Content-Length`). Jira
/// names the user on every answer, and a write's answer is identity-checked too (§7.2).
fn no_content() -> Answer {
    Answer::new(
        format!("HTTP/1.1 204 No Content\r\nConnection: close\r\nX-AUSERNAME: {TEST_USER}\r\n\r\n")
            .into_bytes(),
    )
}

/// How the faulted GET answers, and the `class` §5.4 step 5 records for it.
#[derive(Debug, Clone, Copy)]
enum Fault {
    Http503,
    Redirect,
    Html200,
    TooLarge,
    Reset,
    Http404,
    BadJson,
    Stall,
}

/// The faults of the brief's table (§13 I-23: 503, 302, HTML 200, > 32 MiB, a reset).
const BRIEF_FAULTS: [Fault; 5] = [
    Fault::Http503,
    Fault::Redirect,
    Fault::Html200,
    Fault::TooLarge,
    Fault::Reset,
];

/// The other answers §5.4 step 5 names: a 4xx (a deleted target), a JSON 2xx that does not
/// parse, a timeout.
const MORE_FAULTS: [Fault; 3] = [Fault::Http404, Fault::BadJson, Fault::Stall];

impl Fault {
    fn class(self) -> &'static str {
        match self {
            Fault::Http503 => "http_503",
            Fault::Redirect => "redirect",
            Fault::Html200 | Fault::BadJson => "non_json",
            Fault::TooLarge => "too_large",
            Fault::Reset | Fault::Stall => "network",
            Fault::Http404 => "http_404",
        }
    }

    fn answer(self) -> Answer {
        let html = format!("<html><body>{MARKER}: please log in</body></html>");
        let html_ct = ("Content-Type", "text/html;charset=UTF-8");
        match self {
            Fault::Http503 => {
                Answer::new(raw("503 Service Unavailable", &[html_ct], html.as_bytes()))
            }
            Fault::Redirect => Answer::new(raw(
                "302 Found",
                &[("Location", "https://sso.corp.example/login"), html_ct],
                html.as_bytes(),
            )),
            Fault::Html200 => Answer::new(raw("200 OK", &[html_ct], html.as_bytes())),
            Fault::TooLarge => {
                let body = format!(r#"{{"{MARKER}":"{}"}}"#, "x".repeat(33 * 1024 * 1024));
                ok_json(&body)
            }
            Fault::Reset => {
                // A JSON 200 head announcing 4096 bytes, 30 of them sent, then the close.
                let mut bytes = raw(
                    "200 OK",
                    &[
                        ("Content-Type", "application/json"),
                        ("X-AUSERNAME", TEST_USER),
                    ],
                    b"",
                );
                let head = String::from_utf8_lossy(&bytes)
                    .replace("Content-Length: 0", "Content-Length: 4096");
                bytes = head.into_bytes();
                bytes.extend_from_slice(format!(r#"{{"fields":{{"{MARKER}":"#).as_bytes());
                Answer::new(bytes)
            }
            Fault::Http404 => json_answer(
                "404 Not Found",
                &format!(r#"{{"errorMessages":["{MARKER}: Issue Does Not Exist"],"errors":{{}}}}"#),
            ),
            Fault::BadJson => ok_json(&format!(r#"{{"fields":{{"{MARKER}": }}}}"#)),
            Fault::Stall => ok_json("{}").after(Duration::from_secs(4)),
        }
    }

    /// A stalled answer outlasts a 1 s per-call timeout; every other fault keeps the defaults.
    fn timeouts(self) -> Timeouts {
        match self {
            Fault::Stall => Timeouts {
                per_call: Duration::from_secs(1),
                ..Timeouts::default()
            },
            _ => Timeouts::default(),
        }
    }
}

// ---- the Jira writes, one row each ----------------------------------------------------------------

/// One Jira write: its params, the GETs its enrichment and stale rule read, the stale rule's GET
/// paths (none: the identity call is the last GET before the send) and its own request.
struct Row {
    op: &'static str,
    params: Value,
    gets: Vec<(&'static str, String)>,
    rule: &'static [&'static str],
    /// `METHOD /path` of the write and its declared success.
    write: (&'static str, Answer),
    /// A stale-rule answer that makes the rule say `Changed` (the refresh table).
    changed: Option<(&'static str, String)>,
}

fn sprint(state: &str) -> String {
    json!({
        "id": 7, "self": "https://jira.corp.example/rest/agile/1.0/sprint/7",
        "state": state, "name": "Sprint 7", "originBoardId": 3
    })
    .to_string()
}

fn issue_with(fields: Value) -> String {
    json!({ "id": "10001", "key": "ABC-1", "fields": fields }).to_string()
}

fn rows() -> Vec<Row> {
    let created = || json_answer("201 Created", fixtures::JIRA_ISSUE_CREATED);
    vec![
        Row {
            op: "jira.issue.create",
            params: json!({ "project": "ABC", "issuetype": "Bug", "summary": "S", "body_format": "wiki" }),
            gets: vec![
                ("/rest/api/2/project", fixtures::JIRA_PROJECTS.to_owned()),
                (
                    "/rest/api/2/issue/createmeta/ABC/issuetypes",
                    fixtures::JIRA_CREATEMETA_ISSUETYPES.to_owned(),
                ),
                (
                    "/rest/api/2/issue/createmeta/ABC/issuetypes/10002",
                    fixtures::JIRA_CREATEMETA_FIELDS.to_owned(),
                ),
            ],
            rule: &[],
            write: ("POST /rest/api/2/issue", created()),
            changed: None,
        },
        Row {
            op: "jira.issue.edit",
            params: json!({ "key": "ABC-1", "fields": { "summary": "New summary" } }),
            gets: vec![(ISSUE_PATH, issue_with(json!({ "summary": "Old summary" })))],
            rule: &[ISSUE_PATH],
            write: ("PUT /rest/api/2/issue/ABC-1", no_content()),
            changed: Some((
                ISSUE_PATH,
                issue_with(json!({ "summary": "Changed elsewhere" })),
            )),
        },
        Row {
            op: COMMENT,
            params: json!({ "key": "ABC-1", "body": "Reproduced.", "body_format": "wiki" }),
            gets: vec![],
            rule: &[],
            write: (
                "POST /rest/api/2/issue/ABC-1/comment",
                json_answer("201 Created", fixtures::JIRA_COMMENT),
            ),
            changed: None,
        },
        Row {
            op: TRANSITION,
            params: json!({ "key": "ABC-1", "transition": "Start Progress" }),
            gets: vec![
                (TRANSITIONS_PATH, fixtures::JIRA_TRANSITIONS.to_owned()),
                (ISSUE_PATH, fixtures::JIRA_ISSUE.to_owned()),
            ],
            rule: &[TRANSITIONS_PATH, ISSUE_PATH],
            write: ("POST /rest/api/2/issue/ABC-1/transitions", no_content()),
            changed: Some((
                ISSUE_PATH,
                issue_with(json!({ "status": { "id": "1", "name": "Open" } })),
            )),
        },
        Row {
            op: "jira.issue.assign",
            params: json!({ "key": "ABC-1", "assignee": "bob" }),
            gets: vec![
                (
                    "/rest/api/2/user/assignable/search",
                    json!([{ "name": "bob", "key": "JIRAUSER2", "displayName": "Bob", "active": true }])
                        .to_string(),
                ),
                (ISSUE_PATH, fixtures::JIRA_ISSUE.to_owned()),
            ],
            rule: &[ISSUE_PATH],
            write: ("PUT /rest/api/2/issue/ABC-1/assignee", no_content()),
            changed: Some((
                ISSUE_PATH,
                issue_with(json!({
                    "assignee": { "name": "carol", "key": "JIRAUSER3", "displayName": "Carol" }
                })),
            )),
        },
        Row {
            op: "jira.worklog.add",
            params: json!({ "key": "ABC-1", "time_spent": "2h" }),
            gets: vec![],
            rule: &[],
            write: (
                "POST /rest/api/2/issue/ABC-1/worklog",
                json_answer("201 Created", r#"{"id":"11001","timeSpent":"2h"}"#),
            ),
            changed: None,
        },
        Row {
            op: "jira.issuelink.create",
            params: json!({ "type": "Blocks", "inward": "ABC-124", "outward": "ABC-123" }),
            gets: vec![(
                "/rest/api/2/issueLinkType",
                json!({ "issueLinkTypes": [{
                    "id": "10000", "name": "Blocks", "inward": "is blocked by", "outward": "blocks"
                }] })
                .to_string(),
            )],
            rule: &[],
            write: (
                "POST /rest/api/2/issueLink",
                Answer::new(raw(
                    "201 Created",
                    &[
                        ("Content-Type", "text/html;charset=UTF-8"),
                        ("X-AUSERNAME", TEST_USER),
                    ],
                    b"",
                )),
            ),
            changed: None,
        },
        Row {
            op: "jira.sprint.move_issues",
            params: json!({ "id": 7, "issues": ["ABC-1"] }),
            gets: vec![(SPRINT_PATH, sprint("active"))],
            rule: &[SPRINT_PATH],
            write: ("POST /rest/agile/1.0/sprint/7/issue", no_content()),
            changed: Some((SPRINT_PATH, sprint("closed"))),
        },
        Row {
            op: "jira.backlog.move_issues",
            params: json!({ "issues": ["ABC-1"] }),
            gets: vec![],
            rule: &[],
            write: ("POST /rest/agile/1.0/backlog/issue", no_content()),
            changed: None,
        },
    ]
}

impl Row {
    /// The GETs a fault replaces: the stale rule's, or the identity call's for a rule "none".
    fn faulted(&self) -> Vec<&'static str> {
        if self.rule.is_empty() {
            vec![MYSELF]
        } else {
            self.rule.to_vec()
        }
    }
}

/// A Jira instance at a fresh router that answers `row`'s GETs, the identity call and the write.
async fn row_server(row: &Row, timeouts: Timeouts) -> Result<(Router, Harness), TestError> {
    let router = Router::start().await?;
    router.route(
        &format!("GET {MYSELF}"),
        vec![ok_json(&fixtures::jira_myself(TEST_USER, TEST_USER_KEY))],
    );
    for (p, body) in &row.gets {
        router.route(&format!("GET {p}"), vec![ok_json(body)]);
    }
    router.route(row.write.0, vec![row.write.1.clone()]);
    let h = Harness::builder()
        .instance_at(
            "jira-main",
            Product::Jira,
            InstanceAt {
                base_url: router.base_url(),
                ..InstanceAt::default()
            },
        )
        .timeouts(timeouts)
        .start()
        .await?;
    Ok((router, h))
}

/// Submits `row`, waits for its approvable preview and opens it; returns the id and revision.
async fn opened(h: &Harness, row: &Row) -> Result<(String, u64), TestError> {
    let env = h.submit(row.op, row.params.clone()).await;
    assert_eq!(
        env.status,
        Status::Pending,
        "{}: {}",
        row.op,
        env.to_json_line()
    );
    let id = request_id(&env)?;
    let item = h.queued(&id, 30_000).await.ok_or("never queued")?;
    assert!(item.approvable, "{}: {item:?}", row.op);
    h.approver().open(&id).map_err(de)?;
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    Ok((id, rev))
}

/// The write came back to the queue with `WRITE_STALE` records `reasons` (the last one carrying
/// `class`), not opened, approvable again, nothing sent, still `pending` for the agent (§4.5).
async fn assert_returned(
    h: &Harness,
    router: &Router,
    (id, rev): (&str, u64),
    row: &Row,
    reasons: &[&str],
    class: &str,
    purpose: &str,
) -> TestResult {
    let what = format!("{} {class}", row.op);
    let mut stale = Vec::new();
    for _ in 0..1200 {
        stale = payloads(h, id, EventType::WRITE_STALE).await?;
        if stale.len() >= reasons.len() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let got: Vec<&str> = stale.iter().filter_map(|p| p["reason"].as_str()).collect();
    assert_eq!(got, reasons, "{what}: {stale:?}");
    let last = stale.last().ok_or("no WRITE_STALE")?;
    assert_eq!(
        *last,
        json!({ "reason": "recheck_failed", "class": class }),
        "{what}"
    );
    let item = item_after(h, id, rev).await?;
    assert!(
        !item.opened && item.approvable && item.stale,
        "{what}: {item:?}"
    );
    // The failing GET is the one this row names, logged before the return (audit before effect).
    let types = h.event_types(id).await?;
    let tail: Vec<EventType> = types.iter().rev().take(2).rev().copied().collect();
    assert_eq!(
        tail,
        [EventType::PREVIEW_FETCH, EventType::WRITE_STALE],
        "{what}: {types:?}"
    );
    let failed = fetch_paths(h, id, purpose).await?;
    let last_path = failed.last().ok_or("no fetch of that purpose")?;
    assert!(
        row.faulted().contains(&last_path.as_str()),
        "{what}: the last {purpose} GET was {last_path}"
    );
    assert!(router.sends().is_empty(), "{what}: {:?}", router.sends());
    assert_eq!(h.status(id).await.status, Status::Pending, "{what}");
    assert_no_marker_in_envelopes(h);
    let lead = h.approver().open(id).map_err(de)?.preview;
    assert_eq!(
        lead.warnings.first().map(|w| w.id),
        Some(WarningId::CouldNotRecheck),
        "{what}: the re-review leads with the re-check"
    );
    Ok(())
}

/// I-23 over every Jira write: approved, then the last GET before the send (the stale rule's,
/// or the identity call where the rule is "none") answers `fault`.
async fn stale_check_case(row: &Row, fault: Fault) -> TestResult {
    let (router, h) = row_server(row, fault.timeouts()).await?;
    let (id, rev) = opened(&h, row).await?;
    for p in row.faulted() {
        router.route(&format!("GET {p}"), vec![fault.answer()]);
    }
    h.approver().approve(&id).map_err(de)?;
    assert_returned(
        &h,
        &router,
        (&id, rev),
        row,
        &["recheck_failed"],
        fault.class(),
        "stale_check",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_jira_stale_rules_recheck_failed_classes() -> TestResult {
    for row in rows() {
        for fault in BRIEF_FAULTS {
            stale_check_case(&row, fault).await?;
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_jira_stale_rules_more_recheck_failed_classes() -> TestResult {
    for row in rows() {
        for fault in MORE_FAULTS {
            stale_check_case(&row, fault).await?;
        }
    }
    Ok(())
}

/// §5.4 step 5 "stale-check and refresh fetches": the rule says `Changed`, and the refresh's
/// GET fails: `WRITE_STALE {changed}` then `{recheck_failed, class}`, still nothing sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_jira_refresh_recheck_failed_classes() -> TestResult {
    for row in rows() {
        let Some((changed_path, changed_body)) = &row.changed else {
            continue;
        };
        for fault in BRIEF_FAULTS.into_iter().chain(MORE_FAULTS) {
            let (router, h) = row_server(&row, fault.timeouts()).await?;
            let (id, rev) = opened(&h, &row).await?;
            for p in row.faulted() {
                let first = if p == *changed_path {
                    ok_json(changed_body)
                } else {
                    // The other rule GET of a transition answers as before, then fails.
                    ok_json(
                        &row.gets
                            .iter()
                            .find(|(g, _)| *g == p)
                            .map(|(_, b)| b.clone())
                            .unwrap_or_default(),
                    )
                };
                router.route(&format!("GET {p}"), vec![first, fault.answer()]);
            }
            h.approver().approve(&id).map_err(de)?;
            assert_returned(
                &h,
                &router,
                (&id, rev),
                &row,
                &["changed", "recheck_failed"],
                fault.class(),
                "refresh",
            )
            .await?;
        }
    }
    Ok(())
}

/// The positive control of the tables: with nothing faulted every row's write is sent exactly
/// once and succeeds, so the mounts and params above are what the engine really asks for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_jira_rows_send_when_nothing_fails() -> TestResult {
    for row in rows() {
        let (router, h) = row_server(&row, Timeouts::default()).await?;
        let (id, _) = opened(&h, &row).await?;
        h.approver().approve(&id).map_err(de)?;
        assert!(h.settled(&id, 30_000).await, "{} never settled", row.op);
        let env = h.await_(&id, 1000).await;
        assert_eq!(
            env.status,
            Status::Succeeded,
            "{}: {} {:?}",
            row.op,
            env.to_json_line(),
            payloads(&h, &id, EventType::WRITE_OUTCOME_UNKNOWN).await?
        );
        assert_eq!(router.sends(), [row.write.0], "{}", row.op);
        let stale = fetch_paths(&h, &id, "stale_check").await?;
        let mut want = vec![MYSELF.to_owned()];
        want.extend(row.rule.iter().map(|p| (*p).to_owned()));
        assert_eq!(stale, want, "{}", row.op);
    }
    Ok(())
}

/// The table is every Jira write of the registry, and its stale-rule column is the op table's:
/// a Jira write added (or given a stale rule) without a row here fails this test.
#[test]
fn i23_rows_cover_every_jira_write() {
    let rows = rows();
    let table: BTreeSet<&str> = rows.iter().map(|r| r.op).collect();
    let registry: BTreeSet<&str> = atlas_duck_registry::all()
        .iter()
        .filter(|s| s.product == Product::Jira && s.class == OpClass::Write)
        .map(|s| s.id)
        .collect();
    assert_eq!(table, registry);
    assert_eq!(rows.len(), table.len(), "one row per op");
    let ruled: BTreeSet<&str> = rows
        .iter()
        .filter(|r| !r.rule.is_empty())
        .map(|r| r.op)
        .collect();
    let with_rule: BTreeSet<&str> = op_table()
        .iter()
        .filter(|(id, imp)| table.contains(*id) && imp.stale_check.is_some())
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(ruled, with_rule);
    let changed: BTreeSet<&str> = rows
        .iter()
        .filter(|r| r.changed.is_some())
        .map(|r| r.op)
        .collect();
    assert_eq!(changed, with_rule, "a refresh row per stale rule");
}

// ---- RF-5b (PD-58) ---------------------------------------------------------------------------------

const BOARDS: &str = "/rest/agile/1.0/board";
const SPRINT_ISSUES: &str = "/rest/agile/1.0/sprint/7/issue";

fn board_page() -> String {
    json!({
        "maxResults": 50, "startAt": 0, "isLast": true,
        "values": [{ "id": 3, "name": MARKER, "type": "scrum" }]
    })
    .to_string()
}

fn agile_issue_page() -> String {
    json!({
        "maxResults": 50, "startAt": 0, "total": 1,
        "issues": [{ "id": "10001", "key": "ABC-1", "fields": { "summary": MARKER } }]
    })
    .to_string()
}

/// `upstream_unavailable`, exit 6, retryable, no `details.reason`; the body in `READ_FETCHED`
/// only; never a release item.
async fn assert_rf5b_failed(h: &Harness, id: &str) -> TestResult {
    let env = failed_read(h, id).await?;
    assert_eq!(
        (exit(&env), code(&env).as_str()),
        (6, "upstream_unavailable"),
        "{}",
        env.to_json_line()
    );
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(detail(&env, "reason"), Value::Null);
    assert_eq!(env.data, None);
    assert_eq!(
        h.event_types(id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::READ_FETCHED,
            EventType::READ_FAILED,
            EventType::DELIVERED
        ]
    );
    let fetched = payloads(h, id, EventType::READ_FETCHED).await?;
    assert!(
        fetched[0].to_string().contains(MARKER),
        "the body is audited"
    );
    assert!(h.approver().item(id).is_none(), "never a release item");
    assert_no_marker_in_envelopes(h);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5b_jira_agile_header_absent() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    // `/myself` carries the header; the Agile answers carry none.
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mount_without_xauser(mock, "GET", BOARDS, &board_page()).await;
    mount_without_xauser(mock, "GET", SPRINT_ISSUES, &agile_issue_page()).await;
    // One after the other: a recheck in flight would answer a concurrent read too.
    let reads = [
        ("jira.board.list", json!({ "max": 50 })),
        ("jira.sprint.issues", json!({ "id": 7, "max": 50 })),
    ];
    for (n, (op, params)) in reads.into_iter().enumerate() {
        let id = request_id(&h.submit(op, params).await)?;
        assert_rf5b_failed(&h, &id).await?;
        let starts = rechecks(&h, "start").await?;
        assert_eq!(starts.len(), n + 1, "{op}: one token_recheck per read");
        assert_eq!(rechecks(&h, "result").await?.len(), n + 1, "{op}");
        assert_eq!(starts[n]["planned"][0]["path"], MYSELF);
    }
    assert_eq!(state_of(&h), "ok");
    assert!(state_changes(&h).await?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5b_search_post_header_absent() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    let page = json!({
        "startAt": 0, "maxResults": 50, "total": 1,
        "issues": [{ "id": "10001", "key": "ABC-1", "fields": { "summary": MARKER } }]
    });
    mount_without_xauser(mock, "POST", "/rest/api/2/search", &page.to_string()).await;
    let id = request_id(
        &h.submit("jira.search", json!({ "jql": "project = ABC" }))
            .await,
    )?;
    assert_rf5b_failed(&h, &id).await?;
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(rechecks(&h, "result").await?.len(), 1);
    assert_eq!(state_of(&h), "ok");
    assert!(state_changes(&h).await?.is_empty());
    Ok(())
}

/// Eight concurrent Agile reads without the header: the re-checks coalesce (at least one, at most
/// one per read), each is logged start and result, every GET (the reads' and the re-checks') went
/// through the instance limiter (never more than 4 open at the server), and no read is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf5b_rechecks_coalesce_and_are_logged() -> TestResult {
    let router = Router::start().await?;
    let slow = Duration::from_millis(500);
    router.route(
        &format!("GET {MYSELF}"),
        vec![ok_json(&fixtures::jira_myself(TEST_USER, TEST_USER_KEY)).after(slow)],
    );
    let bare = raw(
        "200 OK",
        &[("Content-Type", "application/json")],
        board_page().as_bytes(),
    );
    router.route(
        &format!("GET {BOARDS}"),
        vec![Answer::new(bare).after(slow)],
    );
    let h = Harness::builder()
        .instance_at(
            "jira-main",
            Product::Jira,
            InstanceAt {
                base_url: router.base_url(),
                ..InstanceAt::default()
            },
        )
        .start()
        .await?;
    let mut ids = Vec::new();
    for _ in 0..8 {
        ids.push(request_id(
            &h.submit("jira.board.list", json!({ "max": 50 })).await,
        )?);
    }
    for id in &ids {
        let env = failed_read(&h, id).await?;
        assert_eq!(
            (exit(&env), code(&env).as_str()),
            (6, "upstream_unavailable")
        );
        assert!(h.approver().item(id).is_none());
    }
    let starts = rechecks(&h, "start").await?;
    let results = rechecks(&h, "result").await?;
    assert!(
        (1..8).contains(&starts.len()),
        "{} token_recheck starts for 8 reads (no coalescing at 8)",
        starts.len()
    );
    assert_eq!(
        results.len(),
        starts.len(),
        "every recheck logged its result"
    );
    let calls = router
        .hits()
        .iter()
        .filter(|h| *h == &format!("GET {MYSELF}"))
        .count();
    assert_eq!(calls, starts.len(), "one /myself per logged recheck");
    assert!(router.max_active() <= 4, "{} at once", router.max_active());
    assert!(router.max_active() >= 2, "the reads never overlapped");
    assert_eq!(state_of(&h), "ok");
    assert_no_marker_in_envelopes(&h);
    Ok(())
}

// ---- the M3 Task 26 gaps -------------------------------------------------------------------------

/// The mock answers every call as `user` (header and body), with the comment `POST` and the
/// transition's GETs and `POST`.
async fn world_as(mock: &MockDc, user: &str) {
    mock.server().reset().await;
    let as_user = |t: ResponseTemplate| t.insert_header("X-AUSERNAME", user);
    Mock::given(method("GET"))
        .and(path(mock.path(MYSELF)))
        .respond_with(as_user(ResponseTemplate::new(200)).set_body_raw(
            fixtures::jira_myself(user, TEST_USER_KEY),
            "application/json",
        ))
        .mount(mock.server())
        .await;
    for (p, body) in [
        (TRANSITIONS_PATH, fixtures::JIRA_TRANSITIONS),
        (ISSUE_PATH, fixtures::JIRA_ISSUE),
    ] {
        Mock::given(method("GET"))
            .and(path(mock.path(p)))
            .respond_with(
                as_user(ResponseTemplate::new(200)).set_body_raw(body, "application/json"),
            )
            .mount(mock.server())
            .await;
    }
    Mock::given(method("POST"))
        .and(path(mock.path(TRANSITIONS_PATH)))
        .respond_with(as_user(ResponseTemplate::new(204)))
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1/comment")))
        .respond_with(
            as_user(ResponseTemplate::new(201))
                .set_body_raw(fixtures::JIRA_COMMENT, "application/json"),
        )
        .mount(mock.server())
        .await;
}

/// Submits `op`, waits for the approvable preview and opens it; returns the id and revision.
async fn queued_open(h: &Harness, op: &str, params: Value) -> Result<(String, u64), TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    let item = h.queued(&id, 20_000).await.ok_or("never queued")?;
    assert!(item.approvable, "{item:?}");
    h.approver().open(&id).map_err(de)?;
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    Ok((id, rev))
}

fn transition_params() -> Value {
    json!({ "key": "ABC-1", "transition": "Start Progress" })
}

fn comment_params() -> Value {
    json!({ "key": "ABC-1", "body": "Reproduced.", "body_format": "wiki" })
}

/// The `WRITE_STALE` payloads of `id`, a `null` member (`class` of a reason without one) left
/// out.
async fn stale_reasons(h: &Harness, id: &str) -> Result<Vec<Value>, TestError> {
    Ok(payloads(h, id, EventType::WRITE_STALE)
        .await?
        .into_iter()
        .map(|mut p| {
            if let Some(o) = p.as_object_mut() {
                o.retain(|_, v| !v.is_null());
            }
            p
        })
        .collect())
}

async fn executed(h: &Harness, id: &str) -> Result<Value, TestError> {
    assert!(h.settled(id, 20_000).await, "never settled");
    let env = h.await_(id, 1000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    payloads(h, id, EventType::WRITE_EXECUTED)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| "no WRITE_EXECUTED".into())
}

/// §7.1 *Username rename* on the stale check's identity call: the key matches, the name and the
/// header are new. The rename is recorded, the identity call runs once more, then the rule and
/// the write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_stale_check_rename_reruns_once() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    world_as(mock, TEST_USER).await;
    let (id, _) = queued_open(&h, TRANSITION, transition_params()).await?;
    world_as(mock, "jdoe2").await;
    h.approver().approve(&id).map_err(de)?;
    let done = executed(&h, &id).await?;
    assert_eq!(done["server_user"], "jdoe2");
    assert_eq!(
        fetch_paths(&h, &id, "stale_check").await?,
        [MYSELF, MYSELF, TRANSITIONS_PATH, ISSUE_PATH],
        "the identity call ran twice, the rule once"
    );
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    let renames: Vec<Value> = state_changes(&h)
        .await?
        .into_iter()
        .filter(|c| c["state"] == "user_renamed")
        .collect();
    assert_eq!(renames.len(), 1);
    assert_eq!(
        (&renames[0]["old"], &renames[0]["new"]),
        (&json!("jdoe"), &json!("jdoe2"))
    );
    assert!(stale_reasons(&h, &id).await?.is_empty(), "never returned");
    assert_eq!(sends(mock).await, 1);
    Ok(())
}

/// The same rename seen on the stale rule's own GET: that GET runs once more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_stale_rule_get_rename_reruns_once() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    world_as(mock, TEST_USER).await;
    let (id, _) = queued_open(&h, TRANSITION, transition_params()).await?;
    world_as(mock, "jdoe2").await;
    // The identity call still answers as jdoe; the rename shows from the rule's GET on.
    Mock::given(method("GET"))
        .and(path(mock.path(MYSELF)))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-AUSERNAME", TEST_USER)
                .set_body_raw(
                    fixtures::jira_myself(TEST_USER, TEST_USER_KEY),
                    "application/json",
                ),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    h.approver().approve(&id).map_err(de)?;
    executed(&h, &id).await?;
    assert_eq!(
        fetch_paths(&h, &id, "stale_check").await?,
        [MYSELF, TRANSITIONS_PATH, TRANSITIONS_PATH, ISSUE_PATH]
    );
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(sends(mock).await, 1);
    Ok(())
}

/// A refresh after `changed` whose GET fails the identity check and whose re-check confirms a
/// token failure: `WRITE_STALE {changed}`, then `{identity_mismatch}`; Approve stays disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_refresh_identity_failure_returns_identity_mismatch() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    world_as(mock, TEST_USER).await;
    let (id, rev) = queued_open(&h, TRANSITION, transition_params()).await?;
    mock.server().reset().await;
    // The stale check: identity call and transitions as jdoe, the status moved on.
    Mock::given(method("GET"))
        .and(path(mock.path(MYSELF)))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-AUSERNAME", TEST_USER)
                .set_body_raw(
                    fixtures::jira_myself(TEST_USER, TEST_USER_KEY),
                    "application/json",
                ),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(mock.path(MYSELF)))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-AUSERNAME", "anonymous")
                .set_body_raw(
                    fixtures::jira_myself(TEST_USER, TEST_USER_KEY),
                    "application/json",
                ),
        )
        .with_priority(2)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(mock.path(TRANSITIONS_PATH)))
        .respond_with(
            mock.response(200)
                .set_body_raw(fixtures::JIRA_TRANSITIONS, "application/json"),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(mock.path(ISSUE_PATH)))
        .respond_with(mock.response(200).set_body_raw(
            issue_with(json!({ "status": { "id": "1", "name": "Open" } })),
            "application/json",
        ))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    // The refresh: every later answer calls the caller anonymous.
    for p in [TRANSITIONS_PATH, ISSUE_PATH] {
        Mock::given(method("GET"))
            .and(path(mock.path(p)))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-AUSERNAME", "anonymous")
                    .set_body_raw(format!(r#"{{"{MARKER}":1}}"#), "application/json"),
            )
            .with_priority(5)
            .mount(mock.server())
            .await;
    }
    h.approver().approve(&id).map_err(de)?;
    let mut reasons = Vec::new();
    for _ in 0..800 {
        reasons = stale_reasons(&h, &id).await?;
        if reasons.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        reasons,
        [
            json!({ "reason": "changed", "delta": "status changed since review" }),
            json!({ "reason": "identity_mismatch" })
        ]
    );
    let item = item_after(&h, &id, rev).await?;
    assert!(!item.approvable, "{item:?}");
    assert_eq!(state_of(&h), "needs_token");
    assert_eq!(sends(mock).await, 0);
    let refresh = payloads(&h, &id, EventType::PREVIEW_FETCH)
        .await?
        .into_iter()
        .filter(|p| p["purpose"] == "refresh")
        .count();
    assert_eq!(refresh, 1, "the refresh stopped at its first GET");
    assert_no_marker_in_envelopes(&h);
    Ok(())
}

/// §7.2 *Header lost* found by the stale check's identity call: the re-check's own `/myself` has
/// no header either. `WRITE_STALE {identity_mismatch, class: identity_header_missing}`, the
/// admin Caution, Approve disabled, nothing sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_header_class_write_stale() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    world_as(mock, TEST_USER).await;
    let (id, rev) = queued_open(&h, COMMENT, comment_params()).await?;
    mock.server().reset().await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Missing)
        .await;
    h.approver().approve(&id).map_err(de)?;
    let item = item_after(&h, &id, rev).await?;
    assert!(!item.approvable && !item.opened, "{item:?}");
    assert_eq!(
        stale_reasons(&h, &id).await?,
        [json!({ "reason": "identity_mismatch", "class": "identity_header_missing" })]
    );
    assert_eq!(state_of(&h), "identity_header_missing");
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(!preview.approvable);
    let lead = preview.warnings.first().ok_or("no Caution")?;
    assert_eq!(lead.id, WarningId::IdentityHeaderLost);
    assert!(
        lead.text.contains("ask the Jira administrator"),
        "{}",
        lead.text
    );
    assert_eq!(sends(mock).await, 0);
    Ok(())
}

/// A re-check that concludes nothing (its `/myself` answers 503) after the stale check's identity
/// call failed the header check: `recheck_failed {identity_recheck}`, approvable again later, the
/// instance state unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_inconclusive_stale_recheck_recheck_failed() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    world_as(mock, TEST_USER).await;
    let (id, rev) = queued_open(&h, COMMENT, comment_params()).await?;
    mock.server().reset().await;
    Mock::given(method("GET"))
        .and(path(mock.path(MYSELF)))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            fixtures::jira_myself(TEST_USER, TEST_USER_KEY),
            "application/json",
        ))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    mock.html(MYSELF, 503).await;
    h.approver().approve(&id).map_err(de)?;
    let item = item_after(&h, &id, rev).await?;
    assert!(item.approvable && !item.opened, "{item:?}");
    assert_eq!(
        stale_reasons(&h, &id).await?,
        [json!({ "reason": "recheck_failed", "class": "identity_recheck" })]
    );
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(rechecks(&h, "result").await?.len(), 1);
    assert_eq!(state_of(&h), "ok");
    assert!(state_changes(&h).await?.is_empty());
    assert_eq!(sends(mock).await, 0);
    Ok(())
}

/// A write's own answer naming the renamed user: `WRITE_OUTCOME_UNKNOWN {identity_mismatch,
/// server_user}`, never retried; the re-check that follows records the rename.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_write_response_rename_stays_outcome_unknown() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    world_as(mock, TEST_USER).await;
    let (id, _) = queued_open(&h, COMMENT, comment_params()).await?;
    world_as(mock, "jdoe2").await;
    // The stale check's identity call still answers as jdoe.
    Mock::given(method("GET"))
        .and(path(mock.path(MYSELF)))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-AUSERNAME", TEST_USER)
                .set_body_raw(
                    fixtures::jira_myself(TEST_USER, TEST_USER_KEY),
                    "application/json",
                ),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 20_000).await;
    assert_eq!(env.status, Status::OutcomeUnknown, "{}", env.to_json_line());
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    let unknown = payloads(&h, &id, EventType::WRITE_OUTCOME_UNKNOWN)
        .await?
        .into_iter()
        .next()
        .ok_or("no WRITE_OUTCOME_UNKNOWN")?;
    assert_eq!(unknown["reason"], "identity_mismatch");
    assert_eq!(unknown["server_user"], "jdoe2");
    wait_for("the rename record", || {
        h.instances()
            .list()
            .first()
            .and_then(|i| i.executes_as.clone())
            .as_deref()
            == Some("jdoe2")
    })
    .await?;
    assert_eq!(sends(mock).await, 1, "never retried");
    let renames = state_changes(&h)
        .await?
        .into_iter()
        .filter(|c| c["state"] == "user_renamed")
        .count();
    assert_eq!(renames, 1);
    Ok(())
}

/// PD-61 (M3 T26 review M-3): a parsed Jira `/myself` 200 without `name` or `key` is a confirmed
/// token failure, like Confluence's (§7.1 "any other parsed JSON response"), on a read's
/// re-check and on a stale check's identity call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pd61_recheck_without_name_or_key_is_token_failure() -> TestResult {
    for body in [
        "{}",
        r#"{"name":"jdoe"}"#,
        r#"{"key":"JIRAUSER1"}"#,
        r#"{"name":"","key":"JIRAUSER1"}"#,
        "[]",
    ] {
        // A read whose answer lacks the header triggers the re-check.
        let h = Harness::jira().await?;
        let mock = jira(&h)?;
        mount_without_xauser(mock, "GET", ISSUE_PATH, fixtures::JIRA_ISSUE).await;
        Mock::given(method("GET"))
            .and(path(mock.path(MYSELF)))
            .respond_with(mock.response(200).set_body_raw(body, "application/json"))
            .mount(mock.server())
            .await;
        let id = request_id(&h.submit("jira.issue.get", json!({ "key": "ABC-1" })).await)?;
        let env = failed_read(&h, &id).await?;
        assert_eq!(
            (exit(&env), code(&env).as_str()),
            (9, "needs_token"),
            "{body}"
        );
        assert_eq!(state_of(&h), "needs_token", "{body}");
        let changes = state_changes(&h).await?;
        assert_eq!(changes.len(), 1, "{body}");
        assert_eq!(changes[0]["state"], "needs_token", "{body}");
        let sid = h.instance("jira-main").ok_or("instance")?.id.clone();
        assert!(h.credentials().load(&sid)?.is_some(), "the PAT stays");
    }
    // The stale check's identity call answering `{}`: identity_mismatch, and the re-check that
    // follows confirms the token failure.
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    world_as(mock, TEST_USER).await;
    let (id, rev) = queued_open(&h, COMMENT, comment_params()).await?;
    mock.server().reset().await;
    Mock::given(method("GET"))
        .and(path(mock.path(MYSELF)))
        .respond_with(mock.response(200).set_body_raw("{}", "application/json"))
        .mount(mock.server())
        .await;
    h.approver().approve(&id).map_err(de)?;
    let item = item_after(&h, &id, rev).await?;
    assert!(!item.approvable);
    assert_eq!(
        stale_reasons(&h, &id).await?,
        [json!({ "reason": "identity_mismatch" })]
    );
    wait_for("needs_token", || state_of(&h) == "needs_token").await?;
    assert_eq!(sends(mock).await, 0);
    Ok(())
}

/// M3 T26 review M-1 (fixed in M3 `f8d0b47`; `identity.rs::failed_rename_store_records_once`
/// covers the record count): a rename whose name the keychain cannot store leaves the runtime
/// name as it was and refreshes no queued write; the next answer records no second rename.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_m1_rename_keychain_failure_no_table_update() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    world_as(mock, TEST_USER).await;
    let (write, rev) = queued_open(&h, COMMENT, comment_params()).await?;
    world_as(mock, "jdoe2").await;
    h.credentials().fail_store(true);
    for _ in 0..2 {
        let id = request_id(&h.submit("jira.issue.get", json!({ "key": "ABC-1" })).await)?;
        assert!(h.settled(&id, 20_000).await, "never settled");
    }
    let renames = state_changes(&h)
        .await?
        .into_iter()
        .filter(|c| c["state"] == "user_renamed")
        .count();
    assert_eq!(renames, 1, "recorded once, not once per answer");
    let view = h.instances().list().into_iter().next().ok_or("no view")?;
    assert_eq!(view.executes_as.as_deref(), Some(TEST_USER));
    let sid = h.instance("jira-main").ok_or("instance")?.id.clone();
    let stored = h.credentials().load(&sid)?.ok_or("no token")?;
    assert_eq!(stored.identity.atlassian_user, TEST_USER);
    // The queued write was not refreshed: same revision, still opened, no `user_renamed`.
    let item = h.approver().item(&write).ok_or("left the queue")?;
    assert_eq!(item.candidate_rev.counter, rev);
    assert!(item.opened);
    assert!(stale_reasons(&h, &write).await?.is_empty());
    Ok(())
}

/// PD-65 (M3 T26 review M-6): a write approved while its instance was `ok`, whose instance left
/// `ok` before the stale check read the state, is returned `identity_mismatch` (with the header
/// class for the identity-header states) without any request; Approve stays disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_m6_needs_token_stale_is_identity_mismatch() -> TestResult {
    let cases = [
        (
            RecheckResult::TokenFailure { other_user: None },
            "needs_token",
            json!({ "reason": "identity_mismatch" }),
            WarningId::TokenIdentityMismatch,
        ),
        (
            RecheckResult::HeaderMissing,
            "identity_header_missing",
            json!({ "reason": "identity_mismatch", "class": "identity_header_missing" }),
            WarningId::IdentityHeaderLost,
        ),
        (
            RecheckResult::HeaderMismatch,
            "identity_header_mismatch",
            json!({ "reason": "identity_mismatch", "class": "identity_header_mismatch" }),
            WarningId::IdentityHeaderLost,
        ),
    ];
    for (result, state, stale, lead) in cases {
        let pause = Pause::new();
        let h = Harness::builder()
            .jira("jira-main")
            .hooks(TestHooks {
                pause_in_transition: Some(pause.clone()),
                ..TestHooks::none()
            })
            .start()
            .await?;
        let mock = jira(&h)?;
        world_as(mock, TEST_USER).await;
        // The setup's transitions pass the hook.
        let auto = |p: Arc<Pause>| {
            tokio::spawn(async move {
                loop {
                    p.reached.notified().await;
                    p.release.notify_one();
                }
            })
        };
        let setup = auto(pause.clone());
        let (id, rev) = queued_open(&h, COMMENT, comment_params()).await?;
        setup.abort();
        let _ = setup.await;
        let before = test_hits(mock).await.len();
        // The approval's transition holds after `WRITE_APPROVED` committed: the instance leaves
        // `ok` right then, before the stale check starts.
        let approver = h.approver();
        let rid = id.clone();
        let decision = std::thread::spawn(move || approver.approve_unopened(&rid).map(|_| ()));
        tokio::time::timeout(Duration::from_secs(10), pause.reached.notified()).await?;
        let (engine, sid) = (
            h.engine().clone(),
            h.instance("jira-main").ok_or("instance")?.id.clone(),
        );
        let flip = tokio::spawn(async move { on_result(&engine, &sid, &result).await });
        wait_for(state, || state_of(&h) == state).await?;
        pause.release.notify_one();
        let rest = auto(pause.clone());
        decision
            .join()
            .map_err(|_| "decision thread panicked")?
            .map_err(de)?;
        let item = item_after(&h, &id, rev).await?;
        assert!(!item.approvable && !item.opened, "{state}: {item:?}");
        assert_eq!(
            stale_reasons(&h, &id).await?,
            std::slice::from_ref(&stale),
            "{state}"
        );
        assert_eq!(
            test_hits(mock).await.len(),
            before,
            "{state}: nothing was sent, not even the identity call"
        );
        let preview = h.approver().open(&id).map_err(de)?.preview;
        assert!(!preview.approvable, "{state}");
        assert_eq!(
            preview.warnings.first().map(|w| w.id),
            Some(lead),
            "{state}"
        );
        flip.await?;
        rest.abort();
    }
    Ok(())
}

/// T19 review M-7: the way out of a PD-65 return. An instance in `needs_token` holds the write
/// as `WRITE_STALE {identity_mismatch}` (not approvable); storing a token makes the instance `ok`
/// again, the hold is refreshed and the write is approvable again, and approving it sends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t19_m7_token_stored_makes_the_returned_write_approvable() -> TestResult {
    let pause = Pause::new();
    let h = Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            pause_in_transition: Some(pause.clone()),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let mock = jira(&h)?;
    world_as(mock, TEST_USER).await;
    let auto = |p: Arc<Pause>| {
        tokio::spawn(async move {
            loop {
                p.reached.notified().await;
                p.release.notify_one();
            }
        })
    };
    let setup = auto(pause.clone());
    let (id, rev) = queued_open(&h, COMMENT, comment_params()).await?;
    setup.abort();
    let _ = setup.await;
    let approver = h.approver();
    let rid = id.clone();
    let decision = std::thread::spawn(move || approver.approve_unopened(&rid).map(|_| ()));
    tokio::time::timeout(Duration::from_secs(10), pause.reached.notified()).await?;
    let (engine, sid) = (
        h.engine().clone(),
        h.instance("jira-main").ok_or("instance")?.id.clone(),
    );
    let flip = tokio::spawn(async move {
        on_result(
            &engine,
            &sid,
            &RecheckResult::TokenFailure { other_user: None },
        )
        .await
    });
    wait_for("needs_token", || state_of(&h) == "needs_token").await?;
    pause.release.notify_one();
    let rest = auto(pause.clone());
    decision
        .join()
        .map_err(|_| "decision thread panicked")?
        .map_err(de)?;
    let held = item_after(&h, &id, rev).await?;
    assert!(!held.approvable && !held.opened, "{held:?}");
    assert_eq!(
        stale_reasons(&h, &id).await?,
        [json!({ "reason": "identity_mismatch" })]
    );
    flip.await?;
    // The way out: a token that resolves to the stored identity.
    world_as(mock, TEST_USER).await;
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/serverInfo")))
        .respond_with(
            mock.response(200)
                .insert_header("X-AUSERNAME", TEST_USER)
                .set_body_raw(fixtures::jira_server_info("9.12.0"), "application/json"),
        )
        .mount(mock.server())
        .await;
    h.instances()
        .set_token("jira-main", SecretString::from(TEST_PAT.to_owned()), None)
        .await?;
    assert_eq!(state_of(&h), "ok");
    let back = item_after(&h, &id, held.candidate_rev.counter).await?;
    assert!(back.approvable, "{back:?}");
    assert_eq!(
        sends(mock).await,
        0,
        "nothing was sent before the new approval"
    );
    h.approver().open(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    executed(&h, &id).await?;
    assert_eq!(sends(mock).await, 1);
    rest.abort();
    Ok(())
}

/// T19 review M-3: a token re-check that never ends does not hold the shutdown beyond the drain
/// bound, and `APP_STOP` is still written (the late result would follow it; the shutdown logs
/// that it gave up).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_recheck_that_never_ends_is_waited_for_only_up_to_the_bound() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            shutdown_drain_wait: Some(Duration::from_millis(600)),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let parked = h.engine().park_recheck();
    let started = std::time::Instant::now();
    let report = h.core().shutdown(ShutdownReason::Quit).await;
    let took = started.elapsed();
    assert!(report.app_stop_logged);
    assert!(
        took >= Duration::from_millis(500),
        "the shutdown did not wait for the re-check: {took:?}"
    );
    assert!(
        took < Duration::from_secs(20),
        "the shutdown was not bounded: {took:?}"
    );
    let all = h.audit_records().await?;
    let last = all.iter().max_by_key(|r| r.seq).ok_or("empty log")?;
    assert_eq!(last.event_type, EventType::APP_STOP, "{:?}", last.payload);
    h.engine().unpark_recheck(parked);
    Ok(())
}

/// §2.5 step 5 for the token re-check: a re-check in flight when the shutdown runs is cancelled
/// and ends before `APP_STOP` (its `/myself` would answer only after the shutdown's 5 s wait), so
/// every `token_recheck` start has its result and nothing follows `APP_STOP`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_recheck_in_flight_ends_before_app_stop() -> TestResult {
    // The drain bound is 10 s and the answer comes after 30 s: without the cancel the shutdown
    // takes the whole bound, with it a few ms; 5 s is the margin on both sides.
    let h = Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            shutdown_drain_wait: Some(Duration::from_secs(10)),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let mock = jira(&h)?;
    mount_without_xauser(mock, "GET", ISSUE_PATH, fixtures::JIRA_ISSUE).await;
    Mock::given(method("GET"))
        .and(path(mock.path(MYSELF)))
        .respond_with(
            mock.response(200)
                .set_body_raw(
                    fixtures::jira_myself(TEST_USER, TEST_USER_KEY),
                    "application/json",
                )
                .set_delay(Duration::from_secs(30)),
        )
        .mount(mock.server())
        .await;
    let id = request_id(&h.submit("jira.issue.get", json!({ "key": "ABC-1" })).await)?;
    for _ in 0..400 {
        if !rechecks(&h, "start").await?.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        rechecks(&h, "start").await?.len(),
        1,
        "the re-check is in flight"
    );
    let started = std::time::Instant::now();
    let _report = h.core().shutdown(ShutdownReason::Quit).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the shutdown waited for the re-check's answer"
    );
    // A re-check left running would record its result after `APP_STOP`.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let all = h.audit_records().await?;
    let last = all.iter().max_by_key(|r| r.seq).ok_or("empty log")?;
    assert_eq!(last.event_type, EventType::APP_STOP, "{:?}", last.payload);
    let starts: Vec<_> = all
        .iter()
        .filter(|r| {
            r.event_type == EventType::SYSTEM_FETCH
                && r.payload["purpose"] == "token_recheck"
                && r.payload["phase"] == "start"
        })
        .collect();
    for start in starts {
        let result = all
            .iter()
            .find(|r| {
                r.event_type == EventType::SYSTEM_FETCH
                    && r.payload["phase"] == "result"
                    && r.payload["fetch_id"] == start.payload["fetch_id"]
            })
            .ok_or("a token_recheck start without its result")?;
        assert!(start.seq < result.seq && result.seq < last.seq);
        assert_eq!(result.payload["class"], "cancelled", "{:?}", result.payload);
    }
    assert!(h.settled(&id, 1000).await);
    Ok(())
}
