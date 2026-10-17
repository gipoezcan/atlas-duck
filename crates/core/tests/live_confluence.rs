#![cfg(feature = "testing")]
//! L-01 (Confluence): env-gated live tests against a real Confluence Data Center, M7 Task 25,
//! PD-60 analog. They are manual: no CI leg runs them, no agent may run them, and every one of
//! them is `#[ignore]`.
//!
//! A run needs `ATLAS_DUCK_LIVE_CONFLUENCE_URL` (https, with the context path if any),
//! `ATLAS_DUCK_LIVE_CONFLUENCE_PAT` and `ATLAS_DUCK_LIVE_CONFLUENCE_SPACE` (a scratch space: every
//! write goes only there). SPACE must be a personal space (key starting with `~`) unless
//! `ATLAS_DUCK_LIVE_CONFLUENCE_SPACE_OK=1` says the operator knows it is safe to fill with test
//! pages; host and space are printed before the first write. At the end (and after a failed probe)
//! a test makes a best-effort raw `DELETE /rest/api/content/{id}` of every page it created (they
//! land in the space trash; comments and attachments go with their page). Optional:
//! `ATLAS_DUCK_LIVE_CONFLUENCE_SSO_URL` (an SSO front, V23) and
//! `ATLAS_DUCK_LIVE_CONFLUENCE_BAD_PAT` (a revoked or expired token, V25). Without the three
//! required variables a test prints `skipped: live env not set` and returns `Ok(())`.
//!
//! Run by hand, one at a time, with output shown:
//! `cargo test -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing
//! --test live_confluence -- --ignored --nocapture --test-threads=1`.
//!
//! Every finding is a printed line (`V04 ...`, `V06 ...`, `V23 ...`, `V25 ...`, `W ...` for the
//! converter, move, title and upload probes) for the lead to turn into spec and ledger entries; each
//! test names the PDs its answer can overturn. The PAT is never printed; usernames only as
//! `<configured user>` or `<other>`; server text appears escaped (`{:?}`) and capped. The app's own
//! path (the handler API over `Harness::live_confluence`) is used wherever the question is what the
//! app does; a raw `InstanceClient` (the same client and PAT) is used where the question is what the
//! server sends or accepts on the wire. A raw client built for the Jira product shows what
//! `X-AUSERNAME` a Confluence response carries (only Jira answers are identity-checked, so its
//! `describe_fetch` line is the header observation) and, for a refused PUT, the status and message
//! the Confluence-product client folds into `VersionConflict`.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use atlas_duck_atlassian::testing::{RecordingDates, test_cover, test_write_cover};
use atlas_duck_atlassian::{
    ApprovedWrite, ClientConfig, CredentialProvider, ExpectedBody, FetchFailure, FetchOutcome,
    GetCall, HttpRequestSpec, IdentityObserved, InstanceClient, NormalizedBaseUrl,
    Product as WireProduct, ProxyChoice, SuccessExpectation, Timeouts, UpstreamResponse,
    WriteOutcome, build_url, normalize_base_url,
};
use atlas_duck_audit::EventType;
use atlas_duck_core::payloads::body_from_json;
use atlas_duck_core::testing::{Harness, InstanceAt, LIVE_CONFLUENCE_ALIAS};
use atlas_duck_core::{AdminError, ops::confluence::effective_cql};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_registry::{OperationSpec, Product, StatusSet, SuccessBody};
use common::{TestError, TestResult, de, request_id};
use serde_json::{Value, json};

const SKIPPED: &str = "skipped: live env not set";
/// Free text of a server shown in a finding line is cut here.
const SHOWN: usize = 400;

// ---- environment ------------------------------------------------------------------------------

/// The T25 variables. No `Debug`: the PAT is in it.
struct Env {
    url: String,
    pat: String,
    space: String,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

impl Env {
    fn read() -> Option<Env> {
        Some(Env {
            url: var("ATLAS_DUCK_LIVE_CONFLUENCE_URL")?,
            pat: var("ATLAS_DUCK_LIVE_CONFLUENCE_PAT")?,
            space: var("ATLAS_DUCK_LIVE_CONFLUENCE_SPACE")?,
        })
    }
}

/// A server's text, escaped and capped.
fn shown(s: &str) -> String {
    let cut: String = s.chars().take(SHOWN).collect();
    format!("{cut:?}")
}

fn shown_bytes(b: &[u8]) -> String {
    shown(&String::from_utf8_lossy(b))
}

/// What a JSON answer looks like without its values: kind, key names, length of `results`.
fn shape(body: &[u8]) -> String {
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(m)) => format!(
            "object keys={:?} results_len={}",
            m.keys().collect::<Vec<_>>(),
            m.get("results")
                .and_then(Value::as_array)
                .map_or_else(|| "-".to_owned(), |a| a.len().to_string())
        ),
        Ok(Value::Array(a)) => format!("array len={}", a.len()),
        Ok(_) => "json scalar".to_owned(),
        Err(_) if body.is_empty() => "empty".to_owned(),
        Err(_) => "not json".to_owned(),
    }
}

/// A unique tag for the titles of one run.
fn tag() -> String {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    format!("{n:x}")
}

/// Standard base64 (the upload parameter), without a dependency.
fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let at = |shift: u32| char::from(A[((n >> shift) & 63) as usize]);
        out.push(at(18));
        out.push(at(12));
        out.push(if chunk.len() > 1 { at(6) } else { '=' });
        out.push(if chunk.len() > 2 { at(0) } else { '=' });
    }
    out
}

// ---- the app's path ---------------------------------------------------------------------------

/// A harness over the live instance, the configured user's name (never printed) and the scratch
/// space.
struct Live {
    h: Harness,
    url: String,
    space: String,
    user: String,
    tag: String,
    /// Ids of the pages this run created, for `cleanup`.
    created: Mutex<Vec<String>>,
}

/// The host part of `url`, for the guard line.
fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?', '#']).next().unwrap_or(rest)
}

/// Refuses a SPACE that is neither personal nor explicitly approved; prints host and space.
fn space_guard(env: &Env) -> Result<(), TestError> {
    println!(
        "live: host={} space={} (scratch pages are created here)",
        host_of(&env.url),
        shown(&env.space)
    );
    if env.space.starts_with('~')
        || var("ATLAS_DUCK_LIVE_CONFLUENCE_SPACE_OK").as_deref() == Some("1")
    {
        return Ok(());
    }
    Err("SPACE is not a personal space (key starting with ~): set \
         ATLAS_DUCK_LIVE_CONFLUENCE_SPACE_OK=1 to write test pages there"
        .into())
}

async fn start_live(env: &Env) -> Result<Live, TestError> {
    space_guard(env)?;
    let h = Harness::builder()
        .live_confluence(&env.url, &env.pat)
        .start()
        .await?;
    let report = h
        .instances()
        .retest_token(LIVE_CONFLUENCE_ALIAS)
        .await
        .map_err(|e| format!("live connection test failed: {e:?}"))?;
    println!(
        "live: connected, product={:?} version={}",
        report.product, report.version
    );
    Ok(Live {
        h,
        url: env.url.clone(),
        space: env.space.clone(),
        user: report.atlassian_user,
        tag: tag(),
        created: Mutex::new(Vec::new()),
    })
}

/// Best-effort removal of the pages the test created (children first): a raw DELETE each. Every
/// outcome is a printed line; nothing here fails the test.
async fn cleanup(l: &Live) {
    let ids = l.created.lock().map(|g| g.clone()).unwrap_or_default();
    if ids.is_empty() {
        return;
    }
    let raw = match Raw::new(
        &l.h,
        LIVE_CONFLUENCE_ALIAS,
        &l.url,
        &l.user,
        WireProduct::Confluence,
    ) {
        Ok(r) => r,
        Err(e) => {
            println!(
                "cleanup: no client ({e}); {} pages left in the space",
                ids.len()
            );
            return;
        }
    };
    let mut deleted = 0usize;
    for id in ids.iter().rev() {
        match raw
            .send_json(
                "DELETE",
                "/rest/api/content/{id}",
                &json!({"id": id}),
                &[],
                None,
                ExpectedBody::Empty,
            )
            .await
        {
            Ok(WriteOutcome::Executed { .. }) => deleted += 1,
            Ok(o) => println!("cleanup: page {id} not deleted: {}", describe_write(&o)),
            Err(e) => println!("cleanup: page {id} not deleted: {e}"),
        }
    }
    println!(
        "cleanup: deleted {deleted} of {} created pages (now in the space trash)",
        ids.len()
    );
}

/// One request of the app, end to end.
struct Run {
    env: Envelope,
    events: Vec<(EventType, Value)>,
}

impl Run {
    fn code(&self) -> String {
        common::code(&self.env)
    }

    fn data(&self, key: &str) -> Value {
        self.env
            .data
            .as_ref()
            .map_or(Value::Null, |d| d[key].clone())
    }

    fn receipt(&self) -> Value {
        self.data("receipt")
    }

    fn summary(&self) -> String {
        format!("status={:?} code={:?}", self.env.status, self.code())
    }

    fn event_names(&self) -> Vec<&'static str> {
        self.events.iter().map(|(t, _)| t.as_str()).collect()
    }

    /// Every page the instance answered to a read: status, content type, body.
    fn raw_pages(&self) -> Vec<(u64, Option<String>, Vec<u8>)> {
        let mut out = Vec::new();
        for (t, p) in &self.events {
            if *t != EventType::READ_FETCHED {
                continue;
            }
            for r in p["responses"].as_array().into_iter().flatten() {
                out.push((
                    r["status"].as_u64().unwrap_or(0),
                    r["content_type"].as_str().map(str::to_owned),
                    body_from_json(&r["body"]).unwrap_or_default(),
                ));
            }
        }
        out
    }

    /// The response of the write (executed or refused by the server) and `X-AUSERNAME` if it came.
    fn write_facts(&self) -> Option<WriteFacts> {
        for (t, p) in &self.events {
            if *t == EventType::WRITE_EXECUTED || *t == EventType::WRITE_FAILED {
                let r = p.get("response")?;
                let body = body_from_json(&r["body"]).unwrap_or_default();
                return Some(WriteFacts {
                    status: r["status"].as_u64().unwrap_or(0),
                    content_type: r["content_type"].as_str().map(str::to_owned),
                    body_empty: body.is_empty(),
                    shape: shape(&body),
                    server_user: p["server_user"].as_str().map(str::to_owned),
                });
            }
        }
        None
    }
}

struct WriteFacts {
    status: u64,
    content_type: Option<String>,
    body_empty: bool,
    shape: String,
    server_user: Option<String>,
}

/// Waits until `id` waits for a decision (true) or ended without (false).
async fn decidable(h: &Harness, id: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if h.approver().item(id).is_some() {
            return true;
        }
        if h.settled(id, 0).await || Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Submits `op`; a read is released, a write approved (a write the app will not approve is denied
/// and reported). The final envelope and the request's records come back.
async fn run(h: &Harness, op: &str, params: Value, write: bool) -> Result<Run, TestError> {
    let first = h.submit(op, params).await;
    if first.status != Status::Pending {
        return Ok(Run {
            env: first,
            events: Vec::new(),
        });
    }
    let id = request_id(&first)?;
    if decidable(h, &id).await {
        if write {
            if let Err(e) = h.approver().approve(&id) {
                println!("  {op}: not approvable ({e:?}), denied");
                let _ = h.approver().deny(&id, "live probe: not approvable");
            }
        } else {
            h.approver().release(&id).map_err(de)?;
        }
    }
    let env = h.await_(&id, 120_000).await;
    let events = h.events(&id).await?;
    Ok(Run { env, events })
}

async fn write(l: &Live, op: &str, params: Value) -> Result<Run, TestError> {
    run(&l.h, op, params, true).await
}

/// A new scratch page (Markdown body unless `format` says otherwise); its id.
async fn create_page(
    l: &Live,
    title: &str,
    body: &str,
    format: &str,
    parent: Option<&str>,
) -> Result<(String, Run), TestError> {
    let mut params = json!({
        "space": l.space,
        "title": title,
        "body": body,
        "body_format": format
    });
    if let (Some(p), Some(o)) = (parent, params.as_object_mut()) {
        o.insert("parent".to_owned(), json!(p));
    }
    let r = write(l, "confluence.page.create", params).await?;
    let id = r.receipt()["id"]
        .as_str()
        .ok_or_else(|| format!("create '{title}' failed: {}", r.summary()))?
        .to_owned();
    if let Ok(mut g) = l.created.lock() {
        g.push(id.clone());
    }
    Ok((id, r))
}

/// Whether `status` and emptiness are what the registry declares for `spec` (V06).
fn declared_match(spec: &OperationSpec, status: u64, body_empty: bool) -> bool {
    let status_ok = match spec.success.statuses {
        StatusSet::Any2xx => (200..300).contains(&status),
        StatusSet::Exactly(list) => list.iter().any(|s| u64::from(*s) == status),
    };
    let body_ok = match spec.success.body {
        SuccessBody::Empty => body_empty,
        SuccessBody::Json => !body_empty,
    };
    status_ok && body_ok
}

fn user_class(l: &Live, seen: &str) -> &'static str {
    if seen == l.user {
        "<configured user> (exact bytes)"
    } else if seen.eq_ignore_ascii_case(&l.user) {
        "<configured user> (case differs)"
    } else {
        "<other>"
    }
}

/// One `V06` line for a write run.
fn report_write(l: &Live, op: &str, r: &Run) {
    let Some(f) = r.write_facts() else {
        println!(
            "V06 op={op} no write response ({}) events={:?}",
            r.summary(),
            r.event_names()
        );
        return;
    };
    let declared = atlas_duck_registry::get(op).map(|s| declared_match(s, f.status, f.body_empty));
    let header = match &f.server_user {
        Some(u) => format!("present, {}", user_class(l, u)),
        None => "absent".to_owned(),
    };
    println!(
        "V06 op={op} status={} content_type={:?} body_empty={} shape=({}) x_ausername={header} \
         declared_match={declared:?} outcome=({})",
        f.status,
        f.content_type,
        f.body_empty,
        f.shape,
        r.summary()
    );
}

// ---- the wire: a raw client over the same PAT -------------------------------------------------

/// What a raw read answered, from a 2xx or from any failure that carries the answer.
struct Answer {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn from(r: &UpstreamResponse) -> Answer {
        Answer {
            status: r.status,
            content_type: r.content_type.clone(),
            body: r.body.clone(),
        }
    }

    fn line(&self) -> String {
        format!(
            "status={} content_type={:?} shape=({})",
            self.status,
            self.content_type,
            shape(&self.body)
        )
    }

    /// `message` of a Confluence error body, escaped and capped.
    fn message(&self) -> String {
        let v = self.json();
        v["message"]
            .as_str()
            .or_else(|| v["errorMessages"][0].as_str())
            .map_or_else(|| shown_bytes(&self.body), shown)
    }
}

struct Raw {
    client: InstanceClient,
    base: NormalizedBaseUrl,
    user: String,
}

impl Raw {
    fn new(
        h: &Harness,
        alias: &str,
        url: &str,
        user: &str,
        product: WireProduct,
    ) -> Result<Raw, TestError> {
        let inst = h.instance(alias).ok_or("no such instance")?;
        let base = normalize_base_url(url).map_err(|e| format!("{e:?}"))?;
        let cfg = ClientConfig {
            instance_id: inst.id.clone(),
            product,
            base: base.clone(),
            custom_ca_pem: None,
            proxy: ProxyChoice::Direct,
            user_agent: format!("atlas-duck-live-probe/{}", env!("CARGO_PKG_VERSION")),
            timeouts: Timeouts::default(),
        };
        let creds: Arc<dyn CredentialProvider> = h.credentials().clone();
        let client = InstanceClient::build(cfg, creds, Arc::new(RecordingDates::default()))?;
        Ok(Raw {
            client,
            base,
            user: user.to_owned(),
        })
    }

    async fn get(
        &self,
        template: &str,
        params: Value,
        query: &[(&str, &str)],
    ) -> Result<FetchOutcome, TestError> {
        let call = GetCall {
            endpoint_template: template.to_owned(),
            params,
            query: query
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        };
        let cover = test_cover().map_err(|e| format!("{e:?}"))?;
        Ok(self.client.get(&cover, &call).await)
    }

    /// A GET whose answer is whatever the server sent (any status), or an error when nothing
    /// answered.
    async fn get_any(
        &self,
        template: &str,
        params: Value,
        query: &[(&str, &str)],
    ) -> Result<Answer, TestError> {
        match self.get(template, params, query).await? {
            FetchOutcome::Response(r) => Ok(Answer::from(&r)),
            FetchOutcome::Failed(
                FetchFailure::StatusHeaderDecided { response, .. }
                | FetchFailure::BodyDecided { response, .. }
                | FetchFailure::IdentityCheckFailed { response, .. },
            ) => Ok(Answer::from(&response)),
            other => Err(format!("GET {template}: {}", self.describe_fetch(&other)).into()),
        }
    }

    /// A GET whose answer is a parsed JSON 2xx, or an error naming what it was instead.
    async fn get_json(
        &self,
        template: &str,
        params: Value,
        query: &[(&str, &str)],
    ) -> Result<Value, TestError> {
        let a = self.get_any(template, params, query).await?;
        if (200..300).contains(&a.status) {
            Ok(a.json())
        } else {
            Err(format!("GET {template}: {} message={}", a.line(), a.message()).into())
        }
    }

    /// One approved request of the probe (the PAT of the live instance, no preview: the caller is
    /// the human running the manual test).
    async fn send(
        &self,
        method: &str,
        template: &str,
        params: &Value,
        query: &[(&str, &str)],
        content: Option<(&str, Vec<u8>)>,
        expect: ExpectedBody,
    ) -> Result<WriteOutcome, TestError> {
        let query: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let url = build_url(&self.base, template, params, &query).map_err(|e| format!("{e:?}"))?;
        let (content_type, body) = match content {
            Some((ct, b)) => (Some(ct.to_owned()), b),
            None => (None, Vec::new()),
        };
        let spec = HttpRequestSpec {
            index: 0,
            method: method.to_owned(),
            resolved_url: url.to_string(),
            content_type,
            body,
        };
        let approved = ApprovedWrite {
            request_id: "req_test".to_owned(),
            candidate_counter: 1,
            requests: vec![spec],
            success: SuccessExpectation {
                statuses: None,
                body: expect,
            },
        };
        let cover = test_write_cover().map_err(|e| format!("{e:?}"))?;
        Ok(self.client.send_approved(cover, &approved).await)
    }

    async fn send_json(
        &self,
        method: &str,
        template: &str,
        params: &Value,
        query: &[(&str, &str)],
        body: Option<&Value>,
        expect: ExpectedBody,
    ) -> Result<WriteOutcome, TestError> {
        let content = body
            .map(|b| serde_json::to_vec(b).map(|v| ("application/json", v)))
            .transpose()?;
        self.send(method, template, params, query, content, expect)
            .await
    }

    /// What an identity observation says, without any name.
    fn observed(&self, o: &IdentityObserved) -> String {
        match o {
            IdentityObserved::Missing => "X-AUSERNAME missing".to_owned(),
            IdentityObserved::Anonymous => "X-AUSERNAME anonymous".to_owned(),
            IdentityObserved::Other(n) if *n == self.user => {
                "X-AUSERNAME <configured user> (exact bytes)".to_owned()
            }
            IdentityObserved::Other(n) if n.eq_ignore_ascii_case(&self.user) => {
                "X-AUSERNAME <configured user> (case differs)".to_owned()
            }
            IdentityObserved::Other(_) => "X-AUSERNAME <other>".to_owned(),
        }
    }

    /// A read's answer as a finding: status, content type and what the identity check made of
    /// `X-AUSERNAME`. A Confluence-product client checks nothing, so a `Response` line says nothing
    /// about the header there; a Jira-product client only checks JSON answers, so for it a
    /// `Response` means no identity failure, and the header is exact only when the answer was JSON
    /// (its content type is in the line).
    fn describe_fetch(&self, o: &FetchOutcome) -> String {
        match o {
            FetchOutcome::Response(r) => format!(
                "status={} content_type={:?} body_len={} (no identity failure; whether \
                 X-AUSERNAME was checked depends on the client's product and a JSON answer)",
                r.status,
                r.content_type,
                r.body.len()
            ),
            FetchOutcome::Failed(FetchFailure::IdentityCheckFailed { observed, response }) => {
                format!(
                    "status={} content_type={:?} identity check failed: {}",
                    response.status,
                    response.content_type,
                    self.observed(observed)
                )
            }
            FetchOutcome::Failed(FetchFailure::StatusHeaderDecided { reason, response }) => {
                format!(
                    "status={} content_type={:?} classified {reason:?} (status/header decided)",
                    response.status, response.content_type
                )
            }
            FetchOutcome::Failed(FetchFailure::BodyDecided { kind, response }) => format!(
                "status={} content_type={:?} classified {kind:?} (body decided)",
                response.status, response.content_type
            ),
            FetchOutcome::Failed(f) => format!("failed: {f:?}"),
        }
    }
}

fn describe_write(o: &WriteOutcome) -> String {
    match o {
        WriteOutcome::Executed {
            response,
            server_user,
            ..
        } => format!(
            "executed status={} content_type={:?} body_len={} shape=({}) x_ausername={}",
            response.status,
            response.content_type,
            response.body.len(),
            shape(&response.body),
            if server_user.is_some() {
                "present"
            } else {
                "absent"
            }
        ),
        WriteOutcome::Failed4xx { response, .. } => format!(
            "refused by the server status={} content_type={:?} body={}",
            response.status,
            response.content_type,
            shown_bytes(&response.body)
        ),
        WriteOutcome::VersionConflict { .. } => {
            "VersionConflict (the client saw a 409, or a 400 naming a version conflict)".to_owned()
        }
        other => format!("{other:?}"),
    }
}

/// The JSON answer of an executed write, or `Null`.
fn executed_json(o: &WriteOutcome) -> Value {
    match o {
        WriteOutcome::Executed { response, .. } => {
            serde_json::from_slice(&response.body).unwrap_or(Value::Null)
        }
        _ => Value::Null,
    }
}

/// `multipart/form-data` with one `file` part and an optional `comment` part: the content type and
/// the body.
fn multipart(filename: &str, bytes: &[u8], comment: Option<&str>) -> (String, Vec<u8>) {
    let boundary = format!("atlas-duck-live-{}", tag());
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; \
             filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
    if let Some(c) = comment {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; \
                 name=\"comment\"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{c}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

/// A page's current `version.number`, title and body (storage), read raw.
async fn page_now(raw: &Raw, id: &str) -> Result<(u64, String, String), TestError> {
    let v = raw
        .get_json(
            "/rest/api/content/{id}",
            json!({"id": id}),
            &[("expand", "version,body.storage")],
        )
        .await?;
    Ok((
        v["version"]["number"].as_u64().unwrap_or(0),
        v["title"].as_str().unwrap_or_default().to_owned(),
        v["body"]["storage"]["value"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    ))
}

/// Pages of size 1 through `template` until the server stops sending `_links.next` (at most 6):
/// per page `size`, whether `_links.next` is there, and `totalSize` where reported (PD-111 minor 8).
async fn walk(
    raw: &Raw,
    label: &str,
    template: &str,
    params: &Value,
    query: &[(&str, &str)],
) -> Result<(), TestError> {
    let mut start = 0u64;
    for n in 1..=6 {
        let s = start.to_string();
        let mut q = query.to_vec();
        q.push(("start", s.as_str()));
        q.push(("limit", "1"));
        let a = raw.get_any(template, params.clone(), &q).await?;
        let v = a.json();
        let size = v["size"].as_u64().unwrap_or(0);
        let next = v["_links"]["next"].is_string();
        println!(
            "V04 paging {label} page={n} start={start} status={} size={size} limit={} \
             totalSize={} links_next_present={next}",
            a.status, v["limit"], v["totalSize"]
        );
        if size == 0 {
            println!(
                "V04 paging {label} inconclusive: empty page {n} (next present={next}); no data \
                 page was walked"
            );
            return Ok(());
        }
        if !next {
            if n == 1 {
                println!(
                    "V04 paging {label} inconclusive: the only page had next absent (a single page \
                     shows nothing about `_links.next` on non-last pages)"
                );
            } else {
                println!(
                    "V04 paging {label} ended at page {n} with data (size={size}): next absent \
                     on the last page, present on pages 1..{}",
                    n - 1
                );
            }
            return Ok(());
        }
        start += size;
    }
    println!("V04 paging {label} capped at 6 pages with `_links.next` still present");
    Ok(())
}

// ---- V04 --------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Confluence DC (L-01)"]
async fn v04_confluence_endpoints_and_cql_rewrite() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    let res = v04_body(&l).await;
    cleanup(&l).await;
    res
}

/// Prints a failed probe as a line and counts it, so later probes still run.
fn probe(label: &str, r: TestResult, failed: &mut usize) {
    if let Err(e) = r {
        *failed += 1;
        println!("V04 {label} error: {e}");
    }
}

/// Polls the search (up to 60 s, 2 s apart) until it reports `totalSize >= want`: the index lags
/// behind writes. `false` if it never got there.
async fn wait_indexed(raw: &Raw, cql: &str, want: u64) -> bool {
    let start = Instant::now();
    let mut seen = None;
    for _ in 0..=30 {
        if let Ok(a) = raw
            .get_any(
                "/rest/api/search",
                json!({}),
                &[("cql", cql), ("limit", "1")],
            )
            .await
        {
            seen = a.json()["totalSize"].as_u64();
            if seen.is_some_and(|n| n >= want) {
                println!(
                    "V04 search index ready after {} s (totalSize={seen:?})",
                    start.elapsed().as_secs()
                );
                return true;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    println!("V04 search index NOT ready after 60 s (totalSize={seen:?}, wanted {want})");
    false
}

async fn v04_body(l: &Live) -> TestResult {
    let raw = Raw::new(
        &l.h,
        LIVE_CONFLUENCE_ALIAS,
        &l.url,
        &l.user,
        WireProduct::Confluence,
    )?;
    let jraw = Raw::new(
        &l.h,
        LIVE_CONFLUENCE_ALIAS,
        &l.url,
        &l.user,
        WireProduct::Jira,
    )?;
    let t = &l.tag;

    // A page with a version 2 (so version 1 is historical) and two children (paging).
    let (page, _) = create_page(
        l,
        &format!("atlas-duck live V04 {t}"),
        "V04 first body",
        "markdown",
        None,
    )
    .await?;
    let r = write(
        l,
        "confluence.page.update",
        json!({"id": page, "base_version": 1, "body": "V04 second body"}),
    )
    .await?;
    println!("V04 page {page} updated to v2: {}", r.summary());
    for n in 1..=2 {
        create_page(
            l,
            &format!("atlas-duck live V04 child {n} {t}"),
            "child",
            "markdown",
            Some(&page),
        )
        .await?;
    }

    let mut failed = 0usize;
    probe("comments", v04_comments(&raw, &page).await, &mut failed);
    probe(
        "history and manifest",
        v04_history(&raw, &page).await,
        &mut failed,
    );
    probe("search", v04_search(l, &raw).await, &mut failed);
    probe("paging", v04_paging(l, &raw, &page).await, &mut failed);
    probe(
        "stale PUT",
        v04_stale_put(&raw, &jraw, &page).await,
        &mut failed,
    );
    println!("V04 scratch page {page} and its children: cleanup follows");
    if failed > 0 {
        return Err(format!("{failed} V04 probes failed (see the `error:` lines)").into());
    }
    Ok(())
}

async fn v04_comments(raw: &Raw, page: &str) -> TestResult {
    // Comment create payload (PD-107): `container.type` and a reply through `ancestors`.
    let comment = json!({
        "type": "comment",
        "container": {"id": page, "type": "page"},
        "body": {"storage": {"value": "<p>V04 comment</p>", "representation": "storage"}}
    });
    let o = raw
        .send_json(
            "POST",
            "/rest/api/content",
            &json!({}),
            &[],
            Some(&comment),
            ExpectedBody::Json,
        )
        .await?;
    println!(
        "V04 comment create (container.type page): {}",
        describe_write(&o)
    );
    let first = executed_json(&o);
    if let Some(cid) = first["id"].as_str() {
        let reply = json!({
            "type": "comment",
            "container": {"id": page, "type": "page"},
            "ancestors": [{"id": cid}],
            "body": {"storage": {"value": "<p>V04 reply</p>", "representation": "storage"}}
        });
        let o = raw
            .send_json(
                "POST",
                "/rest/api/content",
                &json!({}),
                &[],
                Some(&reply),
                ExpectedBody::Json,
            )
            .await?;
        let rv = executed_json(&o);
        println!(
            "V04 comment reply (ancestors [parent]): {} answer_ancestors={} answer_container_type={}",
            describe_write(&o),
            rv["ancestors"].as_array().map_or(0, Vec::len),
            rv["container"]["type"]
        );
    }

    // child/comment with the registry's own expand and depth=all: is `extensions.location` there
    // without a further expand (PD-103)?
    let a = raw
        .get_any(
            "/rest/api/content/{id}/child/comment",
            json!({"id": page}),
            &[
                ("expand", "body.storage,history,ancestors,version"),
                ("depth", "all"),
            ],
        )
        .await?;
    let v = a.json();
    println!("V04 child/comment depth=all: {}", a.line());
    for (i, c) in v["results"].as_array().into_iter().flatten().enumerate() {
        println!(
            "V04 child/comment result {i}: extensions_present={} extensions.location={} \
             ancestors={} history_present={} body.storage_present={} version_present={}",
            !c["extensions"].is_null(),
            c["extensions"]["location"],
            c["ancestors"].as_array().map_or(0, Vec::len),
            !c["history"].is_null(),
            c["body"]["storage"]["value"].is_string(),
            !c["version"].is_null()
        );
    }
    let a = raw
        .get_any(
            "/rest/api/content/{id}/child/comment",
            json!({"id": page}),
            &[(
                "expand",
                "body.storage,history,ancestors,version,extensions.inlineProperties",
            )],
        )
        .await?;
    println!(
        "V04 child/comment without depth, plus extensions.inlineProperties: {} location_in_first={}",
        a.line(),
        a.json()["results"][0]["extensions"]["location"]
    );

    Ok(())
}

async fn v04_history(raw: &Raw, page: &str) -> TestResult {
    // The historical body (page.history --version).
    let a = raw
        .get_any(
            "/rest/api/content/{id}",
            json!({"id": page}),
            &[
                ("version", "1"),
                ("status", "historical"),
                ("expand", "body.storage,version"),
            ],
        )
        .await?;
    let v = a.json();
    println!(
        "V04 historical v1: {} version.number={} content status={} body_is_first={}",
        a.line(),
        v["version"]["number"],
        v["status"],
        v["body"]["storage"]["value"]
            .as_str()
            .is_some_and(|b| b.contains("first body"))
    );

    // The applinks manifest under `Accept: application/json` (the client's default header).
    let a = raw
        .get_any("/rest/applinks/1.0/manifest", json!({}), &[])
        .await?;
    let v = a.json();
    println!(
        "V04 applinks manifest: {} typeId={} version_key_present={}",
        a.line(),
        v["typeId"],
        !v["version"].is_null()
    );

    Ok(())
}

async fn v04_search(l: &Live, raw: &Raw) -> TestResult {
    // Search: `excerpt=indexed`, `totalSize`, the rewritten CQL (trailing ORDER BY included). The
    // index lags behind the writes, so wait until the three V04 pages are searchable.
    let plain = format!(
        "space = \"{}\" AND title ~ \"atlas-duck live V04\"",
        l.space
    );
    if !wait_indexed(raw, &effective_cql(&plain)?, 3).await {
        println!("V04 search probes skipped: index not ready (rerun later)");
        return Ok(());
    }
    let ordered = format!("{plain} ORDER BY created DESC");
    for (label, cql) in [("plain", plain.as_str()), ("order-by", ordered.as_str())] {
        let effective = effective_cql(cql)?;
        println!("V04 rewritten CQL ({label}): {}", shown(&effective));
        for excerpt in ["none", "indexed"] {
            let a = raw
                .get_any(
                    "/rest/api/search",
                    json!({}),
                    &[
                        ("cql", effective.as_str()),
                        ("excerpt", excerpt),
                        ("limit", "2"),
                    ],
                )
                .await?;
            let v = a.json();
            let first = &v["results"][0];
            println!(
                "V04 search {label} excerpt={excerpt}: {} totalSize={} size={} limit={} \
                 first_keys={:?} excerpt_present={} message={}",
                a.line(),
                v["totalSize"],
                v["size"],
                v["limit"],
                first
                    .as_object()
                    .map(|m| m.keys().collect::<Vec<_>>())
                    .unwrap_or_default(),
                first["excerpt"].is_string(),
                if a.status >= 400 {
                    a.message()
                } else {
                    String::new()
                }
            );
        }
    }

    Ok(())
}

async fn v04_paging(l: &Live, raw: &Raw, page: &str) -> TestResult {
    // `_links.next` exactly on the last page (PD-111 minor 8). A walk error does not stop the
    // later walks.
    let mut failed = 0usize;
    let effective = effective_cql(&format!(
        "space = \"{}\" AND title ~ \"atlas-duck live V04\"",
        l.space
    ))?;
    // The search walk only means something once the index holds the pages.
    if wait_indexed(raw, &effective, 3).await {
        probe(
            "paging search",
            walk(
                raw,
                "search",
                "/rest/api/search",
                &json!({}),
                &[("cql", effective.as_str())],
            )
            .await,
            &mut failed,
        );
    } else {
        println!("V04 paging search skipped: index not ready");
    }
    probe(
        "paging child/comment",
        walk(
            raw,
            "child/comment",
            "/rest/api/content/{id}/child/comment",
            &json!({"id": page}),
            &[("depth", "all")],
        )
        .await,
        &mut failed,
    );
    probe(
        "paging child/page",
        walk(
            raw,
            "child/page",
            "/rest/api/content/{id}/child/page",
            &json!({"id": page}),
            &[],
        )
        .await,
        &mut failed,
    );
    probe(
        "paging space",
        walk(raw, "space", "/rest/api/space", &json!({}), &[]).await,
        &mut failed,
    );
    if failed > 0 {
        return Err(format!("{failed} paging walks failed").into());
    }
    Ok(())
}

async fn v04_stale_put(raw: &Raw, jraw: &Raw, page: &str) -> TestResult {
    // A PUT with a stale version: 409 or 400, and its text (PD-111, `is_version_conflict`).
    let (now, title, _) = page_now(raw, page).await?;
    let stale = json!({
        "id": page,
        "type": "page",
        "title": title,
        "version": {"number": now},
        "body": {"storage": {"value": "<p>V04 stale write</p>", "representation": "storage"}}
    });
    let o = raw
        .send_json(
            "PUT",
            "/rest/api/content/{id}",
            &json!({"id": page}),
            &[],
            Some(&stale),
            ExpectedBody::Json,
        )
        .await?;
    println!(
        "V04 stale PUT version.number={now} (current) as the app sends it: {}",
        describe_write(&o)
    );
    let o = jraw
        .send_json(
            "PUT",
            "/rest/api/content/{id}",
            &json!({"id": page}),
            &[],
            Some(&stale),
            ExpectedBody::Json,
        )
        .await?;
    println!(
        "V04 stale PUT, wire status and message (Jira-product client keeps the refusal): {}",
        describe_write(&o)
    );
    Ok(())
}

// ---- V06 --------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Confluence DC (L-01)"]
async fn v06_confluence_write_success_shapes() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    let res = v06_confluence_write_success_shapes_body(&l).await;
    cleanup(&l).await;
    res
}

async fn v06_confluence_write_success_shapes_body(l: &Live) -> TestResult {
    let t = &l.tag;

    let (a, created) = create_page(
        l,
        &format!("atlas-duck live V06 A {t}"),
        "V06 body A",
        "markdown",
        None,
    )
    .await?;
    report_write(l, "confluence.page.create", &created);
    let (b, _) = create_page(
        l,
        &format!("atlas-duck live V06 B {t}"),
        "V06 body B",
        "markdown",
        Some(&a),
    )
    .await?;
    let (c, _) = create_page(
        l,
        &format!("atlas-duck live V06 C {t}"),
        "V06 body C",
        "markdown",
        None,
    )
    .await?;

    let r = write(
        l,
        "confluence.page.update",
        json!({"id": a, "base_version": 1, "body": "V06 body A (edited)", "title": format!("atlas-duck live V06 A edited {t}")}),
    )
    .await?;
    report_write(l, "confluence.page.update", &r);

    let r = write(l, "confluence.page.move", json!({"id": b, "parent": c})).await?;
    report_write(l, "confluence.page.move", &r);

    let r = write(
        l,
        "confluence.comment.add",
        json!({"content_id": a, "body": "V06 comment"}),
    )
    .await?;
    report_write(l, "confluence.comment.add", &r);
    if let Some(cid) = r.receipt()["id"].as_str() {
        let r = write(
            l,
            "confluence.comment.add",
            json!({"content_id": a, "body": "V06 reply", "reply_to": cid}),
        )
        .await?;
        report_write(l, "confluence.comment.add (reply)", &r);
    }

    let r = write(
        l,
        "confluence.label.add",
        json!({"id": a, "labels": ["atlas-duck-live", "atlas-duck-live-2"]}),
    )
    .await?;
    report_write(l, "confluence.label.add", &r);
    let r = write(
        l,
        "confluence.label.remove",
        json!({"id": a, "label": "atlas-duck-live"}),
    )
    .await?;
    report_write(l, "confluence.label.remove", &r);

    let r = write(
        l,
        "confluence.attachment.upload",
        json!({"id": a, "filename": "v06.txt", "content_base64": base64(b"V06 one"), "comment": "V06"}),
    )
    .await?;
    report_write(l, "confluence.attachment.upload (new)", &r);
    let r = write(
        l,
        "confluence.attachment.upload",
        json!({"id": a, "filename": "v06.txt", "content_base64": base64(b"V06 two"), "replace": true}),
    )
    .await?;
    report_write(l, "confluence.attachment.upload (replace)", &r);
    println!("V06 scratch pages {a}, {b} and {c}: cleanup follows");
    Ok(())
}

// ---- V23 --------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Confluence DC (L-01)"]
async fn v23_confluence_sso_front_classification() -> TestResult {
    let (Some(env), Some(sso)) = (Env::read(), var("ATLAS_DUCK_LIVE_CONFLUENCE_SSO_URL")) else {
        println!("{SKIPPED}");
        return Ok(());
    };
    // The PAT goes to the SSO front as it would from a configured instance; the identity the
    // harness stores for it is a stand-in, so only the front's own answer matters here.
    let h = Harness::builder()
        .instance_at(
            "sso",
            Product::Confluence,
            InstanceAt {
                base_url: sso.clone(),
                ..InstanceAt::default()
            },
        )
        .strict_https()
        .pat(&env.pat)
        .start()
        .await?;
    let raw = Raw::new(&h, "sso", &sso, "", WireProduct::Confluence)?;
    let o = raw.get("/rest/api/user/current", json!({}), &[]).await?;
    println!(
        "V23 wire GET /user/current through the SSO front: {}",
        raw.describe_fetch(&o)
    );
    let r = run(&h, "confluence.user.current", json!({}), false).await?;
    for (status, ct, body) in r.raw_pages() {
        println!(
            "V23 app read pages: status={status} content_type={ct:?} body_len={}",
            body.len()
        );
    }
    println!(
        "V23 app classification: {} events={:?}",
        r.summary(),
        r.event_names()
    );
    let t = h.instances().retest_token("sso").await;
    println!(
        "V23 connection test: {}",
        match &t {
            Ok(_) => "ok".to_owned(),
            Err(AdminError::ConnectionFailed(f)) => format!("ConnectionFailed({f:?})"),
            Err(e) => format!("{e:?}"),
        }
    );
    Ok(())
}

// ---- V25 --------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Confluence DC (L-01)"]
async fn v25_confluence_anonymous_fallback_and_header() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    // The good PAT, as a Jira-product client: its identity check is the header observation.
    let jraw = Raw::new(
        &l.h,
        LIVE_CONFLUENCE_ALIAS,
        &l.url,
        &l.user,
        WireProduct::Jira,
    )?;
    let space_query = [
        ("spaceKey", l.space.as_str()),
        ("type", "page"),
        ("limit", "1"),
    ];
    for (label, template, query) in [
        ("user/current", "/rest/api/user/current", &[][..]),
        ("content list", "/rest/api/content", &space_query[..]),
        ("space", "/rest/api/space", &[("limit", "1")][..]),
    ] {
        let o = jraw.get(template, json!({}), query).await?;
        println!(
            "V25 good PAT, header on {label}: {}",
            jraw.describe_fetch(&o)
        );
    }
    let page = l.space.clone();
    let o = jraw
        .get(
            "/rest/api/space/{key}",
            json!({"key": page}),
            &[("expand", "homepage")],
        )
        .await?;
    println!(
        "V25 good PAT, header on space/{{key}}: {}",
        jraw.describe_fetch(&o)
    );

    let good = Raw::new(
        &l.h,
        LIVE_CONFLUENCE_ALIAS,
        &l.url,
        &l.user,
        WireProduct::Confluence,
    )?;
    let cur = good
        .get_any("/rest/api/user/current", json!({}), &[])
        .await?;
    println!(
        "V25 good PAT user/current: {} type={} has_username={}",
        cur.line(),
        cur.json()["type"],
        cur.json()["username"].is_string()
    );
    let content = good
        .get_any("/rest/api/content", json!({}), &space_query)
        .await?;
    println!(
        "V25 good PAT content list in the scratch space: {} size={}",
        content.line(),
        content.json()["size"]
    );

    let Some(bad) = var("ATLAS_DUCK_LIVE_CONFLUENCE_BAD_PAT") else {
        println!("V25 revoked-token half skipped: ATLAS_DUCK_LIVE_CONFLUENCE_BAD_PAT not set");
        return Ok(());
    };
    // The revoked token, bound to the same URL; the stored identity is a stand-in.
    let h = Harness::builder()
        .instance_at(
            "bad",
            Product::Confluence,
            InstanceAt {
                base_url: l.url.clone(),
                ..InstanceAt::default()
            },
        )
        .strict_https()
        .pat(&bad)
        .start()
        .await?;
    let braw = Raw::new(&h, "bad", &l.url, "", WireProduct::Confluence)?;
    let bjraw = Raw::new(&h, "bad", &l.url, "", WireProduct::Jira)?;
    let a = braw
        .get_any("/rest/api/user/current", json!({}), &[])
        .await?;
    println!(
        "V25 revoked PAT user/current: {} type={} has_username={} message={}",
        a.line(),
        a.json()["type"],
        a.json()["username"].is_string(),
        if a.status >= 400 {
            a.message()
        } else {
            String::new()
        }
    );
    let a = braw
        .get_any("/rest/api/content", json!({}), &space_query)
        .await?;
    println!(
        "V25 revoked PAT content list in the scratch space (a public page read): {} size={}",
        a.line(),
        a.json()["size"]
    );
    for (label, template, query) in [
        ("user/current", "/rest/api/user/current", &[][..]),
        ("content list", "/rest/api/content", &space_query[..]),
    ] {
        let o = bjraw.get(template, json!({}), query).await?;
        println!(
            "V25 revoked PAT, header on {label}: {}",
            bjraw.describe_fetch(&o)
        );
    }
    // What the app makes of it (PD-93: the identity GET after the content).
    let r = run(&h, "confluence.space.get", json!({"key": l.space}), false).await?;
    println!(
        "V25 app confluence.space.get with the revoked PAT: {} events={:?}",
        r.summary(),
        r.event_names()
    );
    Ok(())
}

// ---- converter probes (storage rendering) -----------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Confluence DC (L-01)"]
async fn v_storage_render_probes() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    let res = v_storage_render_probes_body(&l).await;
    cleanup(&l).await;
    res
}

async fn v_storage_render_probes_body(l: &Live) -> TestResult {
    let raw = Raw::new(
        &l.h,
        LIVE_CONFLUENCE_ALIAS,
        &l.url,
        &l.user,
        WireProduct::Confluence,
    )?;
    // (label, Markdown the agent sends). The PD-95 look-alikes are the escapes the converter
    // writes for text that would read as a placeholder; PD-96 is the Markdown -> storage output.
    let probes: Vec<(&str, &str)> = vec![
        (
            "pd95-lookalike-escapes",
            "\\[macro: toc {}] and \\@user:abc and a literal <ac:structured-macro ac:name=\"toc\"/> \
             and <ri:user ri:username=\"x\"/> in prose",
        ),
        ("pd96-strike", "~~struck~~ **bold** *em* `code`"),
        ("pd96-code-cdata", "```\nbefore ]]> after ]]>]]>\n```"),
        (
            "pd96-blocks",
            "# H1\n\n1. one\n2. two\n\n> quote\n\n---\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n- [ ] open\n- [x] done",
        ),
        (
            "pd96-links",
            "[ok](https://example.org/x?a=1&b=2) [bad](javascript:alert(1)) ![img](https://example.org/i.png)",
        ),
    ];
    for (label, body) in probes {
        let title = format!("atlas-duck live render {label} {}", l.tag);
        let (id, run_) = match create_page(l, &title, body, "markdown", None).await {
            Ok(v) => v,
            Err(e) => {
                println!("W {label} not created: {e}");
                continue;
            }
        };
        report_write(l, "confluence.page.create", &run_);
        let v = raw
            .get_json(
                "/rest/api/content/{id}",
                json!({"id": id}),
                &[("expand", "body.view,body.storage")],
            )
            .await?;
        println!(
            "W {label} body.view={}",
            shown(v["body"]["view"]["value"].as_str().unwrap_or_default())
        );
        println!(
            "W {label} body.storage={}",
            shown(v["body"]["storage"]["value"].as_str().unwrap_or_default())
        );
    }
    // The checks the lead reads off the lines: `pd95-lookalike-escapes` renders `[macro: toc {}]`,
    // `@user:abc` and the two tags as text (no TOC, no mention); `pd96-strike` renders a
    // strikethrough element (`<del>` or `<s>`); `pd96-code-cdata` shows `]]>` in the code block
    // (`]]&gt;` in the HTML); `pd96-links` keeps the `javascript:` target out of any `href`.
    println!("W scratch pages: cleanup follows");
    Ok(())
}

// ---- page.move body (PD-106, release-blocking) ------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Confluence DC (L-01)"]
async fn v_page_move_keeps_body() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    let res = v_page_move_keeps_body_body(&l).await;
    cleanup(&l).await;
    res
}

async fn v_page_move_keeps_body_body(l: &Live) -> TestResult {
    let raw = Raw::new(
        &l.h,
        LIVE_CONFLUENCE_ALIAS,
        &l.url,
        &l.user,
        WireProduct::Confluence,
    )?;
    let t = &l.tag;
    let marker = format!("MOVE-KEEP-{t}");
    let title = format!("atlas-duck live move subject {t}");
    let (page, _) = create_page(
        l,
        &title,
        &format!("body marker {marker}"),
        "markdown",
        None,
    )
    .await?;
    let (target, _) = create_page(
        l,
        &format!("atlas-duck live move target {t}"),
        "target",
        "markdown",
        None,
    )
    .await?;
    let (v0, _, body0) = page_now(&raw, &page).await?;
    println!(
        "W(move) before: version={v0} body_len={} body_has_marker={}",
        body0.len(),
        body0.contains(&marker)
    );

    // The app's request: a PUT without `body` (PD-106).
    let r = write(
        l,
        "confluence.page.move",
        json!({"id": page, "parent": target}),
    )
    .await?;
    println!("W(move) app run: {}", r.summary());
    report_write(l, "confluence.page.move", &r);

    let v = raw
        .get_json(
            "/rest/api/content/{id}",
            json!({"id": page}),
            &[("expand", "version,body.storage,ancestors")],
        )
        .await?;
    let body1 = v["body"]["storage"]["value"].as_str().unwrap_or_default();
    println!(
        "W(move) after: version={} title_kept={} body_len={} body_has_marker={} body_emptied={} \
         last_ancestor_is_target={}",
        v["version"]["number"],
        v["title"].as_str() == Some(title.as_str()),
        body1.len(),
        body1.contains(&marker),
        body1.is_empty(),
        v["ancestors"]
            .as_array()
            .and_then(|a| a.last())
            .is_some_and(|a| a["id"].as_str() == Some(target.as_str()))
    );
    let title_kept = v["title"].as_str() == Some(title.as_str());
    let verdict = if r.receipt()["id"].is_null() {
        "refused"
    } else if body1.is_empty() {
        "emptied"
    } else if title_kept && body1.contains(&marker) {
        "kept"
    } else {
        "changed"
    };
    println!(
        "W(move) VERDICT {verdict} (kept = title and marker survive; emptied = body is empty; \
         refused = the app run ended without a receipt, see its V06 line; changed = anything \
         else)"
    );
    println!("W(move) scratch pages {page} and {target}: cleanup follows");
    Ok(())
}

// ---- parent and duplicate title lookup (PD-105) -----------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Confluence DC (L-01)"]
async fn v_parent_title_lookup() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    let res = v_parent_title_lookup_body(&l).await;
    cleanup(&l).await;
    res
}

async fn v_parent_title_lookup_body(l: &Live) -> TestResult {
    let raw = Raw::new(
        &l.h,
        LIVE_CONFLUENCE_ALIAS,
        &l.url,
        &l.user,
        WireProduct::Confluence,
    )?;
    let t = &l.tag;
    let plain = format!("Atlas Duck Lookup {t}");
    let odd = format!("Atlas+Duck & Lookup \u{fc}ber {t}");
    for title in [&plain, &odd] {
        let (id, _) = create_page(l, title, "lookup probe", "markdown", None).await?;
        println!("W(105) created page {id}");
    }
    // Is a title that differs only in case a duplicate for the server?
    let lower = plain.to_lowercase();
    match create_page(l, &lower, "lookup probe lower-case twin", "markdown", None).await {
        Ok((id, _)) => println!(
            "W(105) a page whose title differs only in case was created ({id}): titles are case-sensitive on create"
        ),
        Err(e) => println!("W(105) the case-only twin was not created: {e}"),
    }
    let variants: Vec<(&str, String)> = vec![
        ("exact", plain.clone()),
        ("lower-case", lower),
        ("upper-case", plain.to_uppercase()),
        ("padded", format!(" {plain} ")),
        ("plus-ampersand-umlaut exact", odd.clone()),
        ("prefix only", "Atlas Duck Lookup".to_owned()),
    ];
    for (label, title) in &variants {
        let a = raw
            .get_any(
                "/rest/api/content",
                json!({}),
                &[
                    ("spaceKey", l.space.as_str()),
                    ("title", title.as_str()),
                    ("type", "page"),
                    ("expand", "ancestors"),
                    ("limit", "2"),
                ],
            )
            .await?;
        let v = a.json();
        let titles: Vec<String> = v["results"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| r["title"].as_str())
            .map(|s| s.chars().take(80).collect())
            .collect();
        println!(
            "W(105) title lookup {label}: status={} size={} titles={titles:?} message={}",
            a.status,
            v["size"],
            if a.status >= 400 {
                a.message()
            } else {
                String::new()
            }
        );
    }
    // A digits-only title is a page id for the app (PD-105): what does the title query say?
    let a = raw
        .get_any(
            "/rest/api/content",
            json!({}),
            &[
                ("spaceKey", l.space.as_str()),
                ("title", "12345"),
                ("type", "page"),
            ],
        )
        .await?;
    println!("W(105) title lookup digits-only '12345': {}", a.line());
    println!("W(105) scratch pages: cleanup follows");
    Ok(())
}

// ---- attachments (PD-109) ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Confluence DC (L-01)"]
async fn v_upload_allow_duplicated_and_replace() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    let res = v_upload_allow_duplicated_and_replace_body(&l).await;
    cleanup(&l).await;
    res
}

async fn v_upload_allow_duplicated_and_replace_body(l: &Live) -> TestResult {
    let raw = Raw::new(
        &l.h,
        LIVE_CONFLUENCE_ALIAS,
        &l.url,
        &l.user,
        WireProduct::Confluence,
    )?;
    let (page, _) = create_page(
        l,
        &format!("atlas-duck live upload {}", l.tag),
        "upload probe",
        "markdown",
        None,
    )
    .await?;

    // New files through the app, including the m-9 names.
    let names = [
        "plain.txt",
        "Bericht-\u{fc}.pdf",
        "notes..v1.txt",
        "..hidden",
    ];
    for name in names {
        let r = write(
            l,
            "confluence.attachment.upload",
            json!({"id": page, "filename": name, "content_base64": base64(b"first bytes"), "comment": "probe"}),
        )
        .await?;
        println!("W(109) app upload {name:?}: {}", r.summary());
        report_write(l, "confluence.attachment.upload", &r);
    }
    let list = |filename: &'static str| {
        let raw = &raw;
        let page = page.clone();
        async move {
            raw.get_any(
                "/rest/api/content/{id}/child/attachment",
                json!({"id": page}),
                &[("filename", filename), ("expand", "version")],
            )
            .await
        }
    };
    for name in names {
        let a = list(name).await?;
        let v = a.json();
        println!(
            "W(109) filename query {name:?}: status={} size={} stored_title_equals_name={} \
             stored_title={} version={}",
            a.status,
            v["size"],
            v["results"][0]["title"].as_str() == Some(name),
            shown(v["results"][0]["title"].as_str().unwrap_or_default()),
            v["results"][0]["version"]["number"]
        );
    }

    // A second upload of an existing name on the wire: with allowDuplicated=false, and without.
    let before = list("plain.txt").await?.json();
    let id_before = before["results"][0]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    for (label, query) in [
        ("allowDuplicated=false", &[("allowDuplicated", "false")][..]),
        ("no query", &[][..]),
    ] {
        let (ct, body) = multipart("plain.txt", b"second bytes", Some("dup"));
        let o = raw
            .send(
                "POST",
                "/rest/api/content/{id}/child/attachment",
                &json!({"id": page}),
                query,
                Some((ct.as_str(), body)),
                ExpectedBody::Json,
            )
            .await?;
        println!(
            "W(109) wire duplicate upload, {label}: {}",
            describe_write(&o)
        );
        let v = list("plain.txt").await?.json();
        println!(
            "W(109) after {label}: attachments_named_plain.txt={} first_version={}",
            v["size"], v["results"][0]["version"]["number"]
        );
    }

    // Replace: the app (`.../data` of the one attachment).
    let umlaut_before = list("Bericht-\u{fc}.pdf").await?.json();
    let umlaut_id = umlaut_before["results"][0]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let r = write(
        l,
        "confluence.attachment.upload",
        json!({"id": page, "filename": "Bericht-\u{fc}.pdf", "content_base64": base64(b"second bytes"), "replace": true}),
    )
    .await?;
    println!("W(109) app replace of the non-ASCII name: {}", r.summary());
    report_write(l, "confluence.attachment.upload (replace)", &r);
    let v = list("Bericht-\u{fc}.pdf").await?.json();
    println!(
        "W(109) after replace: size={} version={} same_attachment_id={}",
        v["size"],
        v["results"][0]["version"]["number"],
        v["results"][0]["id"].as_str() == Some(umlaut_id.as_str())
    );
    // The same replace on the wire, to see the answer shape (an object, not `{results: [...]}`).
    let target = list("plain.txt").await?.json();
    if let Some(att) = target["results"][0]["id"].as_str() {
        let (ct, body) = multipart("plain.txt", b"third bytes", None);
        let o = raw
            .send(
                "POST",
                "/rest/api/content/{id}/child/attachment/{att}/data",
                &json!({"id": page, "att": att}),
                &[],
                Some((ct.as_str(), body)),
                ExpectedBody::Json,
            )
            .await?;
        println!(
            "W(109) wire replace answer: {} same_id_as_before={}",
            describe_write(&o),
            att == id_before
        );
    }
    println!("W(109) scratch page {page}: cleanup follows");
    Ok(())
}
