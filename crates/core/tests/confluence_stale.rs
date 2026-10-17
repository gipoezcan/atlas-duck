#![cfg(feature = "testing")]
//! Task 21 (M7): the identity and stale sweep on the Confluence writes, and L101.
//!
//! * I-23 (§5.4 step 5, §7.2): every Confluence stale rule's GET that is not a parsed 2xx JSON
//!   answer returns the write as `WRITE_STALE {recheck_failed, class}`; nothing is sent.
//! * The pre-write identity call of every Confluence write (incl. the rule-"none" ones): an
//!   anonymous `user/current` is `WRITE_STALE {identity_mismatch}`; a refused origin is
//!   `recheck_failed {origin_mismatch}`.
//! * L99 (L153): the identity call and the re-check judge `user/current` alike; the unit half is
//!   `engine::write::tests::l99_confluence_identity_call_and_recheck_agree`.
//! * L101 (PD-113, L151): a dropped re-check waiter leaves no `token_recheck` start without its
//!   result and starts no second fetch; the shutdown ends the spawned re-check before `APP_STOP`.
//!
//! The plan names `confluence_identity.rs` for these; they live here so they run locally (that
//! suite is CI-only on the development machines).

mod common;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use atlas_duck_atlassian::testing::{TEST_PAT, TEST_USER, TEST_USER_KEY, fixtures};
use atlas_duck_atlassian::{CredentialProvider, normalize_base_url, url_hash};
use atlas_duck_audit::EventType;
use atlas_duck_core::identity::{RecheckResult, recheck};
use atlas_duck_core::testing::{Channel, Harness, InstanceAt};
use atlas_duck_core::{QueueItem, ShutdownReason, TestHooks, op_table};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::warning::WarningId;
use atlas_duck_registry::{OpClass, Product};
use common::{TestError, TestResult, de, request_id};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

/// Text that only ever sits in an upstream body: it may reach the audit log, never an envelope.
const MARKER: &str = "UPSTREAM-BODY-MARKER";
const IDENTITY: &str = "/rest/api/user/current";
const PAGE: &str = "/rest/api/content/65537";
const PARENT: &str = "/rest/api/content/123400";
const ATTACHMENTS: &str = "/rest/api/content/65537/child/attachment";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
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

/// The `path` of every `PREVIEW_FETCH {purpose}` of `id`, without the query.
async fn fetch_paths(h: &Harness, id: &str, purpose: &str) -> Result<Vec<String>, TestError> {
    Ok(payloads(h, id, EventType::PREVIEW_FETCH)
        .await?
        .into_iter()
        .filter(|p| p["purpose"] == purpose)
        .filter_map(|p| {
            p["path"]
                .as_str()
                .and_then(|s| s.split('?').next())
                .map(str::to_owned)
        })
        .collect())
}

// ---- a path-routed raw HTTP server ---------------------------------------------------------------
//
// The router of `jira_identity.rs` (I-23 needs a connection reset and answers chosen by path,
// which `wiremock` cannot give), without the `X-AUSERNAME` header Confluence does not send.

/// Raw response bytes; the connection closes after them.
#[derive(Clone)]
struct Answer {
    bytes: Arc<Vec<u8>>,
}

impl Answer {
    fn new(bytes: Vec<u8>) -> Answer {
        Answer {
            bytes: Arc::new(bytes),
        }
    }
}

#[derive(Default)]
struct Routes {
    /// `METHOD /path` → the answers in order; the last one repeats.
    table: Mutex<HashMap<String, VecDeque<Answer>>>,
    /// `METHOD /path` of every request, in arrival order.
    hits: Mutex<Vec<String>>,
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
}

impl Drop for Router {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(mut sock: TcpStream, routes: Arc<Routes>) {
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
        let answer = answer.unwrap_or_else(|| {
            json_answer(
                "404 Not Found",
                r#"{"statusCode":404,"message":"no route"}"#,
            )
        });
        let _ = sock.write_all(&answer.bytes).await;
        let _ = sock.flush().await;
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

fn json_answer(status: &str, body: &str) -> Answer {
    Answer::new(raw(
        status,
        &[("Content-Type", "application/json;charset=UTF-8")],
        body.as_bytes(),
    ))
}

fn ok_json(body: &str) -> Answer {
    json_answer("200 OK", body)
}

fn no_content() -> Answer {
    Answer::new(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_vec())
}

/// `GET /rest/api/user/current` for `username` under the stored key.
fn user_current(username: &str) -> Answer {
    ok_json(&fixtures::confluence_user_current(username, TEST_USER_KEY))
}

/// How the faulted GET answers, and the `class` §5.4 step 5 records for it.
#[derive(Debug, Clone, Copy)]
enum Fault {
    Http503,
    Redirect,
    Html200,
    TooLarge,
    Reset,
}

/// The faults of the I-23 table (§13: 503, 302, HTML 200, > 32 MiB, a reset).
const FAULTS: [Fault; 5] = [
    Fault::Http503,
    Fault::Redirect,
    Fault::Html200,
    Fault::TooLarge,
    Fault::Reset,
];

impl Fault {
    fn class(self) -> &'static str {
        match self {
            Fault::Http503 => "http_503",
            Fault::Redirect => "redirect",
            Fault::Html200 => "non_json",
            Fault::TooLarge => "too_large",
            Fault::Reset => "network",
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
                let head = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4096\r\n\
                            Content-Type: application/json\r\n\r\n";
                let mut bytes = head.as_bytes().to_vec();
                bytes.extend_from_slice(format!(r#"{{"version":{{"{MARKER}":"#).as_bytes());
                Answer::new(bytes)
            }
        }
    }
}

// ---- the Confluence writes, one row each -----------------------------------------------------------

/// One Confluence write: its params, the GETs its enrichment and stale rule read, the stale
/// rule's GET paths (none: the identity call is the last GET before the send) and its request.
struct Row {
    /// The row's name in messages (the op, and `replace` for the attachment replace).
    name: &'static str,
    op: &'static str,
    params: Value,
    gets: Vec<(&'static str, String)>,
    rule: &'static [&'static str],
    /// `METHOD /path` of the write and its declared success.
    write: (&'static str, Answer),
}

/// `fixtures::CONFLUENCE_PAGE` (page 65537 in `DOC` at version 7, under `Home`) with labels: the
/// answer of every enrichment and stale GET of the page.
fn page() -> String {
    let mut p: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE).unwrap_or(Value::Null);
    p["metadata"] = json!({"labels": {
        "results": [{"prefix": "global", "name": "release", "id": "1"}],
        "start": 0, "limit": 200, "size": 1,
    }});
    p.to_string()
}

/// The move's new parent `Release notes` (123400), a sibling of the page under `Home`.
fn parent() -> String {
    json!({
        "id": "123400", "type": "page", "status": "current", "title": "Release notes",
        "space": {"id": 98305, "key": "DOC", "name": "Documentation", "type": "global"},
        "ancestors": [{"id": "65536", "type": "page", "status": "current", "title": "Home"}],
    })
    .to_string()
}

/// The attachment lookup's answer listing `found`.
fn attachments(found: &[Value]) -> String {
    json!({"results": found, "start": 0, "limit": 50, "size": found.len(), "_links": {}})
        .to_string()
}

fn notes_txt() -> Value {
    json!({
        "id": "att3001", "type": "attachment", "status": "current", "title": "notes.txt",
        "version": {"number": 2, "when": "2026-10-06T14:00:00.000+02:00"},
        "metadata": {"mediaType": "text/plain", "comment": null},
        "extensions": {"mediaType": "text/plain", "fileSize": 11},
    })
}

fn upload_params(replace: bool) -> Value {
    let mut p =
        json!({ "id": "65537", "filename": "notes.txt", "content_base64": "aGVsbG8gd29ybGQ=" });
    if replace {
        p["replace"] = json!(true);
    }
    p
}

fn rows() -> Vec<Row> {
    let comment = json!({"id": "792", "type": "comment", "status": "current",
                         "version": {"number": 1},
                         "_links": {"webui": "/display/DOC/Release+checklist?focusedCommentId=792"}});
    let created = json!({
        "id": "123500", "type": "page", "status": "current", "title": "Release 1.5 notes",
        "space": {"key": "DOC"}, "version": {"number": 1}, "ancestors": [{"id": "123400"}],
        "_links": {"webui": "/display/DOC/Release+1.5+notes"},
    });
    let uploaded = json!({"results": [{
        "id": "att3002", "type": "attachment", "status": "current", "title": "notes.txt",
        "version": {"number": 1}, "_links": {"download": "/download/attachments/65537/notes.txt"},
    }], "size": 1});
    let mut replaced = notes_txt();
    replaced["version"] = json!({"number": 3});
    vec![
        Row {
            name: "confluence.page.update",
            op: "confluence.page.update",
            params: json!({
                "id": "65537", "base_version": 7, "body": "<p>New text.</p>",
                "body_format": "storage"
            }),
            gets: vec![(PAGE, page())],
            rule: &[PAGE],
            write: (
                "PUT /rest/api/content/65537",
                ok_json(fixtures::CONFLUENCE_PAGE_UPDATED),
            ),
        },
        Row {
            name: "confluence.page.move",
            op: "confluence.page.move",
            params: json!({ "id": "65537", "parent": "123400" }),
            gets: vec![(PAGE, page()), (PARENT, parent())],
            rule: &[PAGE],
            write: (
                "PUT /rest/api/content/65537",
                ok_json(fixtures::CONFLUENCE_PAGE_UPDATED),
            ),
        },
        Row {
            name: "confluence.attachment.upload (replace)",
            op: "confluence.attachment.upload",
            params: upload_params(true),
            gets: vec![(ATTACHMENTS, attachments(&[notes_txt()]))],
            rule: &[ATTACHMENTS],
            write: (
                "POST /rest/api/content/65537/child/attachment/att3001/data",
                ok_json(&replaced.to_string()),
            ),
        },
        Row {
            name: "confluence.attachment.upload",
            op: "confluence.attachment.upload",
            params: upload_params(false),
            gets: vec![(ATTACHMENTS, attachments(&[]))],
            rule: &[],
            write: (
                "POST /rest/api/content/65537/child/attachment",
                ok_json(&uploaded.to_string()),
            ),
        },
        Row {
            name: "confluence.page.create",
            op: "confluence.page.create",
            params: json!({
                "space": "DOC", "title": "Release 1.5 notes", "parent": "123400",
                "body": "New page."
            }),
            gets: vec![
                (
                    "/rest/api/space/DOC",
                    json!({"id": 98305, "key": "DOC", "name": "Documentation", "type": "global"})
                        .to_string(),
                ),
                (PARENT, parent()),
                (
                    "/rest/api/content",
                    json!({"results": [], "start": 0, "limit": 50, "size": 0}).to_string(),
                ),
            ],
            rule: &[],
            write: ("POST /rest/api/content", ok_json(&created.to_string())),
        },
        Row {
            name: "confluence.comment.add",
            op: "confluence.comment.add",
            params: json!({ "content_id": "65537", "body": "Reproduced." }),
            gets: vec![(PAGE, page())],
            rule: &[],
            write: ("POST /rest/api/content", ok_json(&comment.to_string())),
        },
        Row {
            name: "confluence.label.add",
            op: "confluence.label.add",
            params: json!({ "id": "65537", "labels": ["docs"] }),
            gets: vec![(PAGE, page())],
            rule: &[],
            write: (
                "POST /rest/api/content/65537/label",
                ok_json(
                    &json!({"results": [{"prefix": "global", "name": "docs", "id": "11"}],
                             "start": 0, "limit": 200, "size": 1})
                    .to_string(),
                ),
            ),
        },
        Row {
            name: "confluence.label.remove",
            op: "confluence.label.remove",
            params: json!({ "id": "65537", "label": "release" }),
            gets: vec![(PAGE, page())],
            rule: &[],
            write: ("DELETE /rest/api/content/65537/label/release", no_content()),
        },
    ]
}

/// A Confluence instance at a fresh router that answers `row`'s GETs, the identity call (as the
/// stored user) and the write.
async fn row_server(row: &Row) -> Result<(Router, Harness), TestError> {
    let router = Router::start().await?;
    router.route(&format!("GET {IDENTITY}"), vec![user_current(TEST_USER)]);
    for (p, body) in &row.gets {
        router.route(&format!("GET {p}"), vec![ok_json(body)]);
    }
    router.route(row.write.0, vec![row.write.1.clone()]);
    let h = Harness::builder()
        .instance_at(
            "wiki",
            Product::Confluence,
            InstanceAt {
                base_url: router.base_url(),
                ..InstanceAt::default()
            },
        )
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
        row.name,
        env.to_json_line()
    );
    let id = request_id(&env)?;
    let item = h.queued(&id, 30_000).await.ok_or("never queued")?;
    assert!(item.approvable, "{}: {item:?}", row.name);
    h.approver().open(&id).map_err(de)?;
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    Ok((id, rev))
}

/// The `WRITE_STALE` records of `id` once there are `n`, `null` members left out.
async fn stale_records(h: &Harness, id: &str, n: usize) -> Result<Vec<Value>, TestError> {
    let mut stale = Vec::new();
    for _ in 0..1200 {
        stale = payloads(h, id, EventType::WRITE_STALE).await?;
        if stale.len() >= n {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Ok(stale
        .into_iter()
        .map(|mut p| {
            if let Some(o) = p.as_object_mut() {
                o.retain(|_, v| !v.is_null());
            }
            p
        })
        .collect())
}

/// The write came back to the queue with one `WRITE_STALE {recheck_failed, class}` after the
/// failing GET (one of `faulted`), not opened, approvable again, nothing sent, still `pending`
/// for the agent (§4.5), and the re-review leads with the failed re-check.
async fn assert_recheck_failed(
    h: &Harness,
    router: &Router,
    (id, rev): (&str, u64),
    what: &str,
    class: &str,
    faulted: &[&str],
) -> TestResult {
    let stale = stale_records(h, id, 1).await?;
    assert_eq!(
        stale,
        [json!({ "reason": "recheck_failed", "class": class })],
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
    let failed = fetch_paths(h, id, "stale_check").await?;
    let last_path = failed.last().ok_or("no stale_check fetch")?;
    assert!(
        faulted.contains(&last_path.as_str()),
        "{what}: the last stale_check GET was {last_path}"
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

/// I-23 over every Confluence stale rule (`page.update`, `page.move`, `attachment.upload` with
/// `replace`): approved, then the rule's GET answers each fault of the table.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_confluence_stale_rules_recheck_failed_classes() -> TestResult {
    for row in rows().iter().filter(|r| !r.rule.is_empty()) {
        for fault in FAULTS {
            let (router, h) = row_server(row).await?;
            let (id, rev) = opened(&h, row).await?;
            for p in row.rule {
                router.route(&format!("GET {p}"), vec![fault.answer()]);
            }
            h.approver().approve(&id).map_err(de)?;
            let what = format!("{} {}", row.name, fault.class());
            assert_recheck_failed(&h, &router, (&id, rev), &what, fault.class(), row.rule).await?;
        }
    }
    Ok(())
}

/// The positive control of the tables: with nothing faulted every row's write is sent exactly
/// once and succeeds, after the identity call and the row's stale rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confluence_rows_send_when_nothing_fails() -> TestResult {
    for row in rows() {
        let (router, h) = row_server(&row).await?;
        let (id, _) = opened(&h, &row).await?;
        h.approver().approve(&id).map_err(de)?;
        assert!(h.settled(&id, 30_000).await, "{} never settled", row.name);
        let env = h.await_(&id, 1000).await;
        assert_eq!(
            env.status,
            Status::Succeeded,
            "{}: {} {:?}",
            row.name,
            env.to_json_line(),
            payloads(&h, &id, EventType::WRITE_OUTCOME_UNKNOWN).await?
        );
        assert_eq!(router.sends(), [row.write.0], "{}", row.name);
        let stale = fetch_paths(&h, &id, "stale_check").await?;
        let mut want = vec![IDENTITY.to_owned()];
        want.extend(row.rule.iter().map(|p| (*p).to_owned()));
        assert_eq!(stale, want, "{}", row.name);
    }
    Ok(())
}

/// The table is every Confluence write of the registry, and its stale-rule column is the op
/// table's (the attachment upload twice: with and without `replace`).
#[test]
fn rows_cover_every_confluence_write() {
    let rows = rows();
    let table: BTreeSet<&str> = rows.iter().map(|r| r.op).collect();
    let registry: BTreeSet<&str> = atlas_duck_registry::all()
        .iter()
        .filter(|s| s.product == Product::Confluence && s.class == OpClass::Write)
        .map(|s| s.id)
        .collect();
    assert_eq!(table, registry);
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
}

/// §5.4 step 5 for every Confluence write, the rule-"none" ones included: the identity call
/// answers `type: anonymous` (a parsed answer that is not the token's user). Nothing is sent, the
/// write returns as `WRITE_STALE {identity_mismatch}` with Approve disabled, and the token
/// re-check sets `needs_token`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confluence_pre_write_identity_anonymous_is_write_stale() -> TestResult {
    for row in rows() {
        let (router, h) = row_server(&row).await?;
        let (id, rev) = opened(&h, &row).await?;
        router.route(
            &format!("GET {IDENTITY}"),
            vec![ok_json(fixtures::CONFLUENCE_USER_ANONYMOUS)],
        );
        h.approver().approve(&id).map_err(de)?;
        let stale = stale_records(&h, &id, 1).await?;
        assert_eq!(
            stale,
            [json!({"reason": "identity_mismatch"})],
            "{}",
            row.name
        );
        let item = item_after(&h, &id, rev).await?;
        assert!(!item.approvable && !item.opened, "{}: {item:?}", row.name);
        assert_eq!(
            fetch_paths(&h, &id, "stale_check").await?,
            [IDENTITY],
            "{}: only the identity call ran",
            row.name
        );
        assert!(
            router.sends().is_empty(),
            "{}: {:?}",
            row.name,
            router.sends()
        );
        assert_eq!(state_of(&h), "needs_token", "{}", row.name);
        assert_eq!(rechecks(&h, "start").await?.len(), 1, "{}", row.name);
        assert_eq!(h.status(&id).await.status, Status::Pending, "{}", row.name);
        // Approve stays disabled once opened again.
        h.approver().open(&id).map_err(de)?;
        assert!(h.approver().approve(&id).is_err(), "{}", row.name);
        assert!(router.sends().is_empty(), "{}", row.name);
    }
    Ok(())
}

/// §7.2 origin guard on the identity call of every Confluence write: the stored PAT is bound to
/// another origin, so the client refuses the GET before it leaves; the write returns as
/// `WRITE_STALE {recheck_failed, origin_mismatch}` and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confluence_write_origin_guard_refused_is_recheck_failed_origin_mismatch() -> TestResult {
    let elsewhere = url_hash(&normalize_base_url("https://elsewhere.corp.example/wiki")?);
    for row in rows() {
        let (router, h) = row_server(&row).await?;
        let (id, rev) = opened(&h, &row).await?;
        let sid = h.instance("wiki").ok_or("instance")?.id.clone();
        h.credentials()
            .put(&sid, TEST_PAT, elsewhere, TEST_USER, TEST_USER_KEY);
        let before = router.hits().len();
        h.approver().approve(&id).map_err(de)?;
        assert_recheck_failed(
            &h,
            &router,
            (&id, rev),
            row.name,
            "origin_mismatch",
            &[IDENTITY],
        )
        .await?;
        assert_eq!(
            router.hits().len(),
            before,
            "{}: nothing left after the approval",
            row.name
        );
        assert!(h.credentials().load(&sid)?.is_some(), "the PAT stays");
    }
    Ok(())
}

// ---- L99: the identity call and the re-check agree (L153) ------------------------------------------

/// The page update of the table, approved with the identity call answering `answer`.
async fn update_with_identity(answer: Answer) -> Result<(Router, Harness, String, u64), TestError> {
    update_with_identity_answers(vec![answer]).await
}

/// [`update_with_identity`] with `GET user/current` answering `answers` in order from the
/// approval on (the last one repeats): the identity call, then the token re-check.
async fn update_with_identity_answers(
    answers: Vec<Answer>,
) -> Result<(Router, Harness, String, u64), TestError> {
    let rows = rows();
    let row = rows.first().ok_or("no rows")?;
    let (router, h) = row_server(row).await?;
    let (id, rev) = opened(&h, row).await?;
    router.route(&format!("GET {IDENTITY}"), answers);
    h.approver().approve(&id).map_err(de)?;
    Ok((router, h, id, rev))
}

/// L99: a known user with the stored key but no `username` is not an identity match at the
/// identity call either (the re-check's rule): `WRITE_STALE {identity_mismatch}`, nothing sent,
/// and the re-check's own answer (the same) sets `needs_token`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l99_confluence_identity_call_without_username_is_identity_mismatch() -> TestResult {
    let no_name = json!({"type": "known", "userKey": TEST_USER_KEY, "displayName": "Jane Doe"});
    let (router, h, id, rev) = update_with_identity(ok_json(&no_name.to_string())).await?;
    let stale = stale_records(&h, &id, 1).await?;
    assert_eq!(stale, [json!({"reason": "identity_mismatch"})]);
    let item = item_after(&h, &id, rev).await?;
    assert!(!item.approvable);
    assert!(router.sends().is_empty(), "{:?}", router.sends());
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    assert_eq!(state_of(&h), "needs_token");
    Ok(())
}

/// L99: the stored key under another `username` at the identity call is §7.1's rename, as the
/// re-check judges it: one token re-check confirms it and stores the new name
/// (`INSTANCE_STATE_CHANGED {user_renamed}`), the identity call runs once more and passes under
/// the new name, then the rule and the write (§7.1: "a stale-check or refresh fetch is re-run
/// once").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l99_confluence_identity_call_rename_reruns_once() -> TestResult {
    let (router, h, id, _) = update_with_identity(user_current("jdoe2")).await?;
    assert!(h.settled(&id, 30_000).await, "never settled");
    let env = h.await_(&id, 1000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(
        fetch_paths(&h, &id, "stale_check").await?,
        [IDENTITY, IDENTITY, PAGE],
        "the identity call ran twice, the rule once"
    );
    assert_eq!(rechecks(&h, "start").await?.len(), 1);
    let renames: Vec<Value> = h
        .events_of(EventType::INSTANCE_STATE_CHANGED)
        .await?
        .into_iter()
        .filter(|c| c["state"] == "user_renamed")
        .collect();
    assert_eq!(renames.len(), 1, "{renames:?}");
    assert_eq!(
        (&renames[0]["old"], &renames[0]["new"]),
        (&json!(TEST_USER), &json!("jdoe2"))
    );
    assert!(
        stale_records(&h, &id, 0).await?.is_empty(),
        "never returned"
    );
    assert_eq!(router.sends(), ["PUT /rest/api/content/65537"]);
    let sid = h.instance("wiki").ok_or("instance")?.id.clone();
    let stored = h.credentials().load(&sid)?.ok_or("no token")?;
    assert_eq!(stored.identity.atlassian_user, "jdoe2");
    assert_eq!(state_of(&h), "ok");
    Ok(())
}

/// The same rename when the keychain refuses to store the new name: the rename is recorded once,
/// the stored name stays, so the identity call's second answer is still not a match under it: it
/// is not re-run again, the write returns as `WRITE_STALE {identity_mismatch}` and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l99_confluence_rename_not_stored_is_identity_mismatch() -> TestResult {
    let rows = rows();
    let row = rows.first().ok_or("no rows")?;
    let (router, h) = row_server(row).await?;
    let (id, rev) = opened(&h, row).await?;
    router.route(&format!("GET {IDENTITY}"), vec![user_current("jdoe2")]);
    h.credentials().fail_store(true);
    h.approver().approve(&id).map_err(de)?;
    let stale = stale_records(&h, &id, 1).await?;
    assert_eq!(stale, [json!({"reason": "identity_mismatch"})]);
    item_after(&h, &id, rev).await?;
    assert_eq!(
        fetch_paths(&h, &id, "stale_check").await?,
        [IDENTITY, IDENTITY],
        "re-run once, then returned"
    );
    let renames = h
        .events_of(EventType::INSTANCE_STATE_CHANGED)
        .await?
        .into_iter()
        .filter(|c| c["state"] == "user_renamed")
        .count();
    assert_eq!(renames, 1);
    assert!(router.sends().is_empty(), "{:?}", router.sends());
    let sid = h.instance("wiki").ok_or("instance")?.id.clone();
    let stored = h.credentials().load(&sid)?.ok_or("no token")?;
    assert_eq!(stored.identity.atlassian_user, TEST_USER);
    Ok(())
}

/// The same rename when the token re-check that would confirm it concludes nothing (a 503): the
/// write returns as `WRITE_STALE {recheck_failed, identity_recheck}`, nothing is renamed or sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l99_confluence_rename_with_an_inconclusive_recheck_is_recheck_failed() -> TestResult {
    let unavailable = Fault::Http503.answer();
    let (router, h, id, rev) =
        update_with_identity_answers(vec![user_current("jdoe2"), unavailable]).await?;
    let stale = stale_records(&h, &id, 1).await?;
    assert_eq!(
        stale,
        [json!({"reason": "recheck_failed", "class": "identity_recheck"})]
    );
    item_after(&h, &id, rev).await?;
    assert_eq!(rechecks(&h, "result").await?.len(), 1);
    assert!(
        h.events_of(EventType::INSTANCE_STATE_CHANGED)
            .await?
            .is_empty()
    );
    assert!(router.sends().is_empty(), "{:?}", router.sends());
    assert_eq!(state_of(&h), "ok");
    Ok(())
}

// ---- L101: the spawned re-check (PD-113, L151) ------------------------------------------------------

/// `GET /rest/api/user/current` answers the stored user `delay` after the request arrived.
async fn slow_identity(h: &Harness, delay: Duration) -> TestResult {
    let mock = h.mock("wiki").ok_or("no wiki mock")?;
    Mock::given(method("GET"))
        .and(path(mock.path(IDENTITY)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(
                    fixtures::confluence_user_current(TEST_USER, TEST_USER_KEY),
                    "application/json",
                )
                .set_delay(delay),
        )
        .mount(mock.server())
        .await;
    Ok(())
}

/// Waits until a `token_recheck` start is committed.
async fn recheck_started(h: &Harness) -> TestResult {
    for _ in 0..2000 {
        if !rechecks(h, "start").await?.is_empty() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("no token_recheck started".into())
}

/// L101 (plan review I-9): the first waiter of a re-check is dropped (its task aborted) while the
/// fetch is in flight, and a second waiter of the same epoch comes: there is exactly one
/// `token_recheck` start and one result for that epoch, and the second waiter gets the result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l101_dropped_recheck_waiter_leaves_no_orphan_start() -> TestResult {
    let h = Harness::confluence().await?;
    slow_identity(&h, Duration::from_millis(1500)).await?;
    let sid = h.instance("wiki").ok_or("instance")?.id.clone();
    let (engine, id) = (h.engine().clone(), sid.clone());
    let first = tokio::spawn(async move { recheck(&engine, &id, 0).await });
    recheck_started(&h).await?;
    first.abort();
    assert!(first.await.is_err(), "the first waiter was dropped");
    let (engine, id) = (h.engine().clone(), sid.clone());
    let second = tokio::spawn(async move { recheck(&engine, &id, 0).await });
    let result = tokio::time::timeout(Duration::from_secs(20), second).await??;
    assert_eq!(result, RecheckResult::IdentityMatch);
    let (starts, results) = (rechecks(&h, "start").await?, rechecks(&h, "result").await?);
    assert_eq!(starts.len(), 1, "one fetch for the epoch: {starts:?}");
    assert_eq!(results.len(), 1, "{results:?}");
    assert_eq!(starts[0]["fetch_id"], results[0]["fetch_id"]);
    assert_eq!(results[0]["status"], 200, "{:?}", results[0]);
    let mock = h.mock("wiki").ok_or("no wiki mock")?;
    let sent = mock
        .received()
        .await
        .iter()
        .filter(|r| r.url.path() == mock.path(IDENTITY))
        .count();
    assert_eq!(sent, 1, "one user/current GET");
    Ok(())
}

/// PD-113 shutdown: the re-check's only waiter is gone and its spawned task is in flight when the
/// shutdown runs: the shutdown cancels its GET, and its result record (`class: cancelled`, the
/// bytes received so far) commits before `APP_STOP`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recheck_shutdown_commits_result_before_app_stop() -> TestResult {
    let h = Harness::builder()
        .confluence("wiki")
        .hooks(TestHooks {
            shutdown_drain_wait: Some(Duration::from_secs(10)),
            ..TestHooks::none()
        })
        .start()
        .await?;
    slow_identity(&h, Duration::from_secs(30)).await?;
    let sid = h.instance("wiki").ok_or("instance")?.id.clone();
    let engine = h.engine().clone();
    let waiter = tokio::spawn(async move { recheck(&engine, &sid, 0).await });
    recheck_started(&h).await?;
    waiter.abort();
    let _ = waiter.await;
    let started = std::time::Instant::now();
    let report = h.core().shutdown(ShutdownReason::Quit).await;
    assert!(report.app_stop_logged);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the shutdown waited for the re-check's answer"
    );
    // A re-check left running would record its result after `APP_STOP`.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let all = h.audit_records().await?;
    let last = all.iter().max_by_key(|r| r.seq).ok_or("empty log")?;
    assert_eq!(last.event_type, EventType::APP_STOP, "{:?}", last.payload);
    let fetches: Vec<_> = all
        .iter()
        .filter(|r| {
            r.event_type == EventType::SYSTEM_FETCH && r.payload["purpose"] == "token_recheck"
        })
        .collect();
    let starts: Vec<_> = fetches
        .iter()
        .filter(|r| r.payload["phase"] == "start")
        .collect();
    assert_eq!(starts.len(), 1);
    let result = fetches
        .iter()
        .find(|r| {
            r.payload["phase"] == "result" && r.payload["fetch_id"] == starts[0].payload["fetch_id"]
        })
        .ok_or("the token_recheck start has no result")?;
    assert!(starts[0].seq < result.seq && result.seq < last.seq);
    assert_eq!(result.payload["class"], "cancelled", "{:?}", result.payload);
    Ok(())
}
