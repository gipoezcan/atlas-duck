#![cfg(feature = "testing")]
//! L-01 (Jira): env-gated live tests against a real Jira Data Center, M5 Task 24, PD-60. They are
//! manual: no CI leg runs them, no agent may run them, and every one of them is `#[ignore]`.
//!
//! A run needs `ATLAS_DUCK_LIVE_JIRA_URL` (https), `ATLAS_DUCK_LIVE_JIRA_PAT` and
//! `ATLAS_DUCK_LIVE_JIRA_PROJECT` (a scratch project: every write goes only there, and the scratch
//! issues it creates stay). Optional: `ATLAS_DUCK_LIVE_JIRA_ISSUETYPE` (default `Task`),
//! `ATLAS_DUCK_LIVE_JIRA_SPRINT` (a future or active sprint id for the sprint move),
//! `ATLAS_DUCK_LIVE_JIRA_SSO_URL` (an SSO front, V23) and `ATLAS_DUCK_LIVE_PUBLIC_URL` (a host
//! with a public CA, M-16). Without the three required variables a test prints
//! `skipped: live env not set` and returns `Ok(())`.
//!
//! Run by hand, one at a time, with output shown:
//! `cargo test -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing
//! --test live_jira -- --ignored --nocapture --test-threads=1`.
//!
//! Every finding is a printed line (`V05 ...`, `V06 ...`, `V23 ...`, `V25 ...`, `M16 ...`, `W ...`
//! for the wiki and issue-link probes) for the lead to turn into spec and ledger entries. The PAT
//! is never printed; usernames only as `<configured user>` or `<other>`; server text appears
//! escaped (`{:?}`) and capped. The app's own path (the handler API over `Harness::live`) is used
//! wherever the question is what the app does; a raw `InstanceClient` (the same client and PAT) is
//! used where the question is what the server sends or accepts on the wire.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_duck_atlassian::testing::{
    RecordingDates, generate_ca_pem, test_cover, test_write_cover,
};
use atlas_duck_atlassian::{
    ApprovedWrite, ClientConfig, CredentialProvider, ExpectedBody, FetchFailure, FetchOutcome,
    GetCall, HttpRequestSpec, IdentityObserved, InstanceClient, NormalizedBaseUrl,
    Product as WireProduct, ProxyChoice, SearchCall, SuccessExpectation, Timeouts, WriteOutcome,
    build_url, normalize_base_url,
};
use atlas_duck_audit::EventType;
use atlas_duck_core::payloads::body_from_json;
use atlas_duck_core::testing::{Harness, InstanceAt, LIVE_ALIAS};
use atlas_duck_core::{AdminError, ConnectionFailure};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_registry::{OperationSpec, Product, StatusSet, SuccessBody};
use common::{TestError, TestResult, de, request_id};
use secrecy::SecretString;
use serde_json::{Value, json};

const SKIPPED: &str = "skipped: live env not set";
/// Free text of a server shown in a finding line is cut here.
const SHOWN: usize = 400;

// ---- environment ------------------------------------------------------------------------------

/// The PD-60 variables. No `Debug`: the PAT is in it.
struct Env {
    url: String,
    pat: String,
    project: String,
    issuetype: String,
    sprint: Option<u64>,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

impl Env {
    fn read() -> Option<Env> {
        Some(Env {
            url: var("ATLAS_DUCK_LIVE_JIRA_URL")?,
            pat: var("ATLAS_DUCK_LIVE_JIRA_PAT")?,
            project: var("ATLAS_DUCK_LIVE_JIRA_PROJECT")?,
            issuetype: var("ATLAS_DUCK_LIVE_JIRA_ISSUETYPE").unwrap_or_else(|| "Task".to_owned()),
            sprint: var("ATLAS_DUCK_LIVE_JIRA_SPRINT").and_then(|v| v.parse().ok()),
        })
    }
}

/// A server's text, escaped and capped.
fn shown(s: &str) -> String {
    let cut: String = s.chars().take(SHOWN).collect();
    format!("{cut:?}")
}

// ---- the app's path ---------------------------------------------------------------------------

/// A harness over the live instance, the configured user's name (never printed) and the scratch
/// project.
struct Live {
    h: Harness,
    url: String,
    project: String,
    issuetype: String,
    sprint: Option<u64>,
    user: String,
}

async fn start_live(env: &Env) -> Result<Live, TestError> {
    let h = Harness::builder().live(&env.url, &env.pat).start().await?;
    let report = h
        .instances()
        .retest_token(LIVE_ALIAS)
        .await
        .map_err(|e| format!("live connection test failed: {e:?}"))?;
    println!(
        "live: connected, product={:?} version={}",
        report.product, report.version
    );
    Ok(Live {
        h,
        url: env.url.clone(),
        project: env.project.clone(),
        issuetype: env.issuetype.clone(),
        sprint: env.sprint,
        user: report.atlassian_user,
    })
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

    fn result(&self) -> Value {
        self.data("result")
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
                return Some(WriteFacts {
                    status: r["status"].as_u64().unwrap_or(0),
                    content_type: r["content_type"].as_str().map(str::to_owned),
                    body_empty: body_from_json(&r["body"]).is_some_and(|b| b.is_empty()),
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

async fn read(l: &Live, op: &str, params: Value) -> Result<Run, TestError> {
    run(&l.h, op, params, false).await
}

async fn write(l: &Live, op: &str, params: Value) -> Result<Run, TestError> {
    run(&l.h, op, params, true).await
}

/// A new scratch issue.
async fn create_issue(l: &Live, summary: &str) -> Result<(String, Run), TestError> {
    let r = write(
        l,
        "jira.issue.create",
        json!({"project": l.project, "issuetype": l.issuetype, "summary": summary}),
    )
    .await?;
    let key = r.receipt()["key"]
        .as_str()
        .ok_or_else(|| format!("create failed: {}", r.summary()))?
        .to_owned();
    Ok((key, r))
}

/// The released `result` of `jira.issue.get`.
async fn issue_fields(l: &Live, key: &str, fields: &[&str]) -> Result<Value, TestError> {
    let r = read(l, "jira.issue.get", json!({"key": key, "fields": fields})).await?;
    if r.result().is_null() {
        return Err(format!("issue read failed: {}", r.summary()).into());
    }
    Ok(r.result())
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
        "V06 op={op} status={} content_type={:?} body_empty={} x_ausername={header} \
         declared_match={declared:?} outcome=({})",
        f.status,
        f.content_type,
        f.body_empty,
        r.summary()
    );
}

// ---- the wire: a raw client over the same PAT -------------------------------------------------

struct Raw {
    client: InstanceClient,
    base: NormalizedBaseUrl,
    user: String,
}

impl Raw {
    fn new(h: &Harness, alias: &str, url: &str, user: &str) -> Result<Raw, TestError> {
        let inst = h.instance(alias).ok_or("no such instance")?;
        let base = normalize_base_url(url).map_err(|e| format!("{e:?}"))?;
        let cfg = ClientConfig {
            instance_id: inst.id.clone(),
            product: WireProduct::Jira,
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

    /// A GET whose answer is a parsed JSON 2xx, or an error naming what it was instead.
    async fn get_json(
        &self,
        template: &str,
        params: Value,
        query: &[(&str, &str)],
    ) -> Result<Value, TestError> {
        match self.get(template, params, query).await? {
            FetchOutcome::Response(r) if (200..300).contains(&r.status) => {
                Ok(serde_json::from_slice(&r.body)?)
            }
            other => Err(format!("GET {template}: {}", self.describe_fetch(&other)).into()),
        }
    }

    async fn search(&self, body: Value) -> Result<FetchOutcome, TestError> {
        let call = SearchCall {
            endpoint_template: "/rest/api/2/search".to_owned(),
            body,
        };
        let cover = test_cover().map_err(|e| format!("{e:?}"))?;
        Ok(self.client.post_search(&cover, &call).await)
    }

    /// One approved request of the probe (the PAT of the live instance, no preview: the caller is
    /// the human running the manual test).
    async fn send(
        &self,
        method: &str,
        template: &str,
        params: &Value,
        body: Option<&Value>,
        expect: ExpectedBody,
    ) -> Result<WriteOutcome, TestError> {
        let url = build_url(&self.base, template, params, &[]).map_err(|e| format!("{e:?}"))?;
        let spec = HttpRequestSpec {
            index: 0,
            method: method.to_owned(),
            resolved_url: url.to_string(),
            content_type: body.map(|_| "application/json".to_owned()),
            body: body
                .map(serde_json::to_vec)
                .transpose()?
                .unwrap_or_default(),
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

    /// A read's answer as a finding: status, content type, and what the identity check made of
    /// `X-AUSERNAME` (a parsed answer passed it, so the header was present and the configured
    /// user's exact bytes).
    fn describe_fetch(&self, o: &FetchOutcome) -> String {
        match o {
            FetchOutcome::Response(r) => format!(
                "status={} content_type={:?} body_len={} identity check passed (X-AUSERNAME present, \
                 <configured user>, exact bytes)",
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
            "executed status={} content_type={:?} body_len={} x_ausername={}",
            response.status,
            response.content_type,
            response.body.len(),
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
            shown(&String::from_utf8_lossy(&response.body))
        ),
        other => format!("{other:?}"),
    }
}

// ---- V05 --------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Jira DC (L-01)"]
async fn v05_max_results_clamp_labels_update_unassign() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;

    // maxResults as the server clamps it on POST /search: the first raw page answers it.
    for max in [500u64, 1000] {
        let r = read(
            &l,
            "jira.search",
            json!({
                "jql": format!("project = \"{}\" ORDER BY created DESC", l.project),
                "fields": ["summary"],
                "max": max
            }),
        )
        .await?;
        let pages = r.raw_pages();
        let first: Value = pages
            .first()
            .and_then(|(_, _, b)| serde_json::from_slice(b).ok())
            .unwrap_or(Value::Null);
        println!(
            "V05 search max={max} server_maxResults_first_page={} issues_first_page={} total={} \
             pages={} released_issues={} meta_page={} outcome=({})",
            first["maxResults"],
            first["issues"].as_array().map_or(0, Vec::len),
            first["total"],
            pages.len(),
            r.result()["issues"].as_array().map_or(0, Vec::len),
            r.env
                .meta
                .as_ref()
                .map_or(Value::Null, |m| m["page"].clone()),
            r.summary()
        );
    }

    // Labels through `update`.
    let (key, _) = create_issue(&l, "atlas-duck live V05 labels and assignee").await?;
    for (what, op) in [("add", "add"), ("remove", "remove")] {
        let r = write(
            &l,
            "jira.issue.edit",
            json!({"key": key, "update": {"labels": [{(op): "atlas-duck-live"}]}}),
        )
        .await?;
        let labels = issue_fields(&l, &key, &["labels"]).await?["fields"]["labels"].clone();
        println!(
            "V05 labels {what} via update: write ({}) labels_after={labels}",
            r.summary()
        );
        report_write(&l, "jira.issue.edit", &r);
    }

    // Assign, then unassign with {"name": null}.
    let a = write(
        &l,
        "jira.issue.assign",
        json!({"key": key, "assignee": l.user}),
    )
    .await?;
    let after_assign = issue_fields(&l, &key, &["assignee"]).await?["fields"]["assignee"].clone();
    println!(
        "V05 assign <configured user>: write ({}) assignee_is_configured_user={}",
        a.summary(),
        after_assign["name"].as_str() == Some(l.user.as_str())
    );
    let u = write(
        &l,
        "jira.issue.assign",
        json!({"key": key, "assignee": null}),
    )
    .await?;
    let after_unassign = issue_fields(&l, &key, &["assignee"]).await?["fields"]["assignee"].clone();
    println!(
        "V05 unassign {{\"name\": null}}: write ({}) assignee_is_null={} assignee_is_configured_user={}",
        u.summary(),
        after_unassign.is_null(),
        after_unassign["name"].as_str() == Some(l.user.as_str())
    );
    report_write(&l, "jira.issue.assign", &u);
    println!("V05 scratch issue {key} left in the project");
    Ok(())
}

// ---- V06 --------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Jira DC (L-01)"]
async fn v06_jira_write_success_shapes() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    let (a, created) = create_issue(&l, "atlas-duck live V06 A").await?;
    report_write(&l, "jira.issue.create", &created);
    let (b, _) = create_issue(&l, "atlas-duck live V06 B").await?;

    let r = write(
        &l,
        "jira.issue.edit",
        json!({"key": a, "fields": {"summary": "atlas-duck live V06 A (edited)"}}),
    )
    .await?;
    report_write(&l, "jira.issue.edit", &r);

    let r = write(
        &l,
        "jira.comment.add",
        json!({"key": a, "body": "V06 comment"}),
    )
    .await?;
    report_write(&l, "jira.comment.add", &r);

    let t = read(&l, "jira.transition.list", json!({"key": a})).await?;
    match t.result()["transitions"][0]["name"].as_str() {
        Some(name) => {
            let r = write(
                &l,
                "jira.issue.transition",
                json!({"key": a, "transition": name}),
            )
            .await?;
            report_write(&l, "jira.issue.transition", &r);
        }
        None => println!(
            "V06 op=jira.issue.transition no transition listed ({})",
            t.summary()
        ),
    }

    let r = write(
        &l,
        "jira.issue.assign",
        json!({"key": a, "assignee": l.user}),
    )
    .await?;
    report_write(&l, "jira.issue.assign", &r);

    let r = write(
        &l,
        "jira.worklog.add",
        json!({"key": a, "time_spent": "1m"}),
    )
    .await?;
    report_write(&l, "jira.worklog.add", &r);

    let types = read(&l, "jira.issuelinktype.list", json!({})).await?;
    let link_type = types.result()["issueLinkTypes"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|t| t["name"] == "Blocks")
                .or_else(|| a.first())
        })
        .and_then(|t| t["name"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "Blocks".to_owned());
    let r = write(
        &l,
        "jira.issuelink.create",
        json!({"type": link_type, "inward": a, "outward": b}),
    )
    .await?;
    report_write(&l, "jira.issuelink.create", &r);

    let r = write(&l, "jira.backlog.move_issues", json!({"issues": [a]})).await?;
    report_write(&l, "jira.backlog.move_issues", &r);

    match l.sprint {
        Some(id) => {
            let r = write(
                &l,
                "jira.sprint.move_issues",
                json!({"id": id, "issues": [a]}),
            )
            .await?;
            report_write(&l, "jira.sprint.move_issues", &r);
        }
        None => {
            println!("V06 op=jira.sprint.move_issues skipped: ATLAS_DUCK_LIVE_JIRA_SPRINT not set")
        }
    }
    println!("V06 scratch issues {a} and {b} left in the project");
    Ok(())
}

// ---- V23 --------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Jira DC (L-01)"]
async fn v23_jira_sso_front_classification() -> TestResult {
    let (Some(env), Some(sso)) = (Env::read(), var("ATLAS_DUCK_LIVE_JIRA_SSO_URL")) else {
        println!("{SKIPPED}");
        return Ok(());
    };
    // The PAT goes to the SSO front as it would from a configured instance; the identity the
    // harness stores for it is a stand-in, so only the front's own answer matters here.
    let h = Harness::builder()
        .instance_at(
            "sso",
            Product::Jira,
            InstanceAt {
                base_url: sso.clone(),
                ..InstanceAt::default()
            },
        )
        .strict_https()
        .pat(&env.pat)
        .start()
        .await?;
    let raw = Raw::new(&h, "sso", &sso, "")?;
    let o = raw.get("/rest/api/2/myself", json!({}), &[]).await?;
    println!(
        "V23 wire GET /myself through the SSO front: {}",
        raw.describe_fetch(&o)
    );
    let r = run(&h, "jira.myself", json!({}), false).await?;
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
#[ignore = "manual live run against a real Jira DC (L-01)"]
async fn v25_agile_and_search_send_xausername() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    let raw = Raw::new(&l.h, LIVE_ALIAS, &l.url, &l.user)?;

    let o = raw.get("/rest/api/2/myself", json!({}), &[]).await?;
    println!("V25 GET /rest/api/2/myself: {}", raw.describe_fetch(&o));
    let o = raw
        .search(json!({
            "jql": format!("project = \"{}\"", l.project),
            "maxResults": 1,
            "fields": ["summary"]
        }))
        .await?;
    println!("V25 POST /rest/api/2/search: {}", raw.describe_fetch(&o));
    let o = raw
        .get("/rest/agile/1.0/board", json!({}), &[("maxResults", "1")])
        .await?;
    println!("V25 GET /rest/agile/1.0/board: {}", raw.describe_fetch(&o));

    // What the app makes of the same answers (PD-58: a missing header runs the token re-check).
    for (op, params) in [
        (
            "jira.search",
            json!({"jql": format!("project = \"{}\"", l.project), "max": 1}),
        ),
        ("jira.board.list", json!({"max": 1})),
    ] {
        let r = read(&l, op, params).await?;
        println!("V25 app {op}: {} events={:?}", r.summary(), r.event_names());
    }
    Ok(())
}

// ---- M-16 -------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Jira DC (L-01)"]
async fn m16_public_ca_with_custom_ca_connects() -> TestResult {
    let (Some(_), Some(public)) = (Env::read(), var("ATLAS_DUCK_LIVE_PUBLIC_URL")) else {
        println!("{SKIPPED}");
        return Ok(());
    };
    // A public-CA host with an unrelated custom CA configured: the system roots must still be
    // trusted. The host is not a Jira, so the answer is not a success; it must not be TLS.
    let probe = "m16-probe-not-a-token";
    let h = Harness::builder()
        .instance_at(
            "public",
            Product::Jira,
            InstanceAt {
                base_url: public,
                ca_pem: Some(generate_ca_pem()?),
                ..InstanceAt::default()
            },
        )
        .strict_https()
        .pat(probe)
        .start()
        .await?;
    let r = h
        .instances()
        .set_token("public", SecretString::from(probe), None)
        .await;
    let kind = match &r {
        Ok(_) => "connected".to_owned(),
        Err(AdminError::ConnectionFailed(f)) => format!("ConnectionFailed({f:?})"),
        Err(e) => format!("{e:?}"),
    };
    println!("M16 public CA host with an unrelated custom CA: {kind}");
    assert!(
        !matches!(
            r,
            Err(AdminError::ConnectionFailed(ConnectionFailure::Tls(_)))
        ),
        "the public CA no longer connects while a custom CA is configured"
    );
    Ok(())
}

// ---- wiki rendering probes (Step 1b a-i) ------------------------------------------------------

struct Probe {
    label: String,
    format: &'static str,
    body: String,
}

fn probe(label: &str, format: &'static str, body: &str) -> Probe {
    Probe {
        label: label.to_owned(),
        format,
        body: body.to_owned(),
    }
}

fn wiki_probes() -> Vec<Probe> {
    let mut p = vec![
        // (a) a control or zero-width character before `~` in link text: a mention?
        probe("a-control", "wiki", "[\u{1}\\~jdoe|http://x.example]"),
        probe("a-zero-width", "wiki", "[\u{200B}\\~jdoe|http://x.example]"),
        probe("a-plain-control", "wiki", "[\u{1}~jdoe|http://x.example]"),
        // (c) inline-code spelling of macros: monospace or a macro?
        probe("c-include-toc", "wiki", "{{include:X}}\n\n{{toc}}"),
        // (d) escapes and a character reference in link text
        probe("d-escapes", "wiki", "\\# \\+ \\^ \\~ \\?"),
        probe("d-ref-in-link", "wiki", "[a&#126;b|http://x.example]"),
        // (e) character references
        probe("e-refs", "wiki", "&#92; &#104; &#98; &#94; &#38; &#160;"),
        // (f) a whitespace-led tag inside a code body stays opaque
        probe(
            "f-code-body",
            "wiki",
            "{code}\n{ code}\n{include:SECRET}\n{code}",
        ),
        // (g) {code:rust} (formatter error panel) against allowlisted languages
        probe("g-code-rust", "wiki", "{code:rust}\nfn main() {}\n{code}"),
        probe("g-code-java", "wiki", "{code:java}\nint x;\n{code}"),
        probe("g-code-sql", "wiki", "{code:sql}\nselect 1;\n{code}"),
        // (h) the converter's own output shapes
        probe("h-fenced", "markdown", "```\n{ code}\n{include:X}\n```"),
        probe("h-inline-include", "markdown", "`include:X`"),
        // (i) two noformat bodies holding {code}, scanned left to right
        probe(
            "i-noformat-pair",
            "wiki",
            "{noformat}\n{code}\n{noformat}\n{noformat}\n{code}\n{include:X}\n{noformat}",
        ),
    ];
    // (b) U+2028 and U+0085 before a heading, list or quote marker at a "line start"
    for (name, ch) in [("2028", '\u{2028}'), ("0085", '\u{0085}')] {
        for (marker, text) in [("h1", "h1. "), ("list", "# "), ("bq", "bq. ")] {
            p.push(Probe {
                label: format!("b-{name}-{marker}"),
                format: "wiki",
                body: format!("first line{ch}{text}second"),
            });
        }
    }
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Jira DC (L-01)"]
async fn v_wiki_render_probes() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    let raw = Raw::new(&l.h, LIVE_ALIAS, &l.url, &l.user)?;
    let (key, _) = create_issue(&l, "atlas-duck live wiki render probes").await?;

    let mut posted: Vec<(String, String)> = Vec::new();
    for p in wiki_probes() {
        let r = write(
            &l,
            "jira.comment.add",
            json!({"key": key, "body": p.body, "body_format": p.format}),
        )
        .await?;
        match r.receipt()["id"].as_str() {
            Some(id) => posted.push((p.label, id.to_owned())),
            None => println!("W {} not posted: {}", p.label, r.summary()),
        }
    }

    let issue = raw
        .get_json(
            "/rest/api/2/issue/{key}",
            json!({"key": key}),
            &[("fields", "comment"), ("expand", "renderedFields")],
        )
        .await?;
    let rendered = &issue["renderedFields"]["comment"]["comments"];
    for (label, id) in &posted {
        let html = rendered
            .as_array()
            .into_iter()
            .flatten()
            .find(|c| c["id"].as_str() == Some(id.as_str()))
            .and_then(|c| c["body"].as_str());
        println!(
            "W {label} rendered={}",
            html.map_or("<none>".to_owned(), shown)
        );
    }

    // (h) the converter's output `{code}\n{ code}\n{include:X}\n{code}` is what `h-fenced`
    // posted in wiki form; (f) and (h) must agree (`{ code}` does not close the body and
    // `{include:X}` stays inert), and (i) must keep B's `{include:X}` inert.
    println!("W scratch issue {key} left in the project");
    Ok(())
}

// ---- renderedFields without fields (Step 1b j) ------------------------------------------------

/// `v` at `path`, or `Null`.
fn at<'a>(v: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(v, |v, k| &v[*k])
}

fn ids(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e["id"].as_str().map(str::to_owned))
        .collect()
}

/// Per mirror: is `renderedFields.X` present while `fields.X` is absent, does every rendered
/// entry have an `id`, do the two arrays hold the same ids. Counts only.
fn mirror_lines(label: &str, issue: &Value) {
    for (name, path) in [
        ("comment.comments", &["comment", "comments"][..]),
        ("worklog.worklogs", &["worklog", "worklogs"][..]),
        ("attachment", &["attachment"][..]),
    ] {
        let rendered = at(&issue["renderedFields"], path);
        let plain = at(&issue["fields"], path);
        let rendered_ids = ids(rendered);
        let every_has_id = rendered
            .as_array()
            .is_some_and(|a| a.len() == rendered_ids.len());
        println!(
            "W(j) {label} mirror={name} rendered_present={} fields_present={} rendered_without_counterpart={} \
             every_rendered_has_id={every_has_id} rendered_count={} fields_count={} same_ids={}",
            !rendered.is_null(),
            !plain.is_null(),
            !rendered.is_null() && plain.is_null(),
            rendered.as_array().map_or(0, Vec::len),
            plain.as_array().map_or(0, Vec::len),
            ids(plain) == rendered_ids
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Jira DC (L-01)"]
async fn v_rendered_fields_without_counterpart() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    let raw = Raw::new(&l.h, LIVE_ALIAS, &l.url, &l.user)?;
    // A scratch issue with comments and a worklog. An attachment cannot be added through the app:
    // the `attachment` mirror is only meaningful if one is added to this issue by hand first
    // (set ATLAS_DUCK_LIVE_JIRA_KEY to a scratch issue that has one).
    let key = match var("ATLAS_DUCK_LIVE_JIRA_KEY") {
        Some(k) => k,
        None => {
            let (k, _) = create_issue(&l, "atlas-duck live renderedFields probe").await?;
            for n in 1..=2 {
                let c = write(
                    &l,
                    "jira.comment.add",
                    json!({"key": k, "body": format!("probe {n}")}),
                )
                .await?;
                println!("W(j) comment {n}: {}", c.summary());
            }
            let w = write(
                &l,
                "jira.worklog.add",
                json!({"key": k, "time_spent": "1m"}),
            )
            .await?;
            println!("W(j) worklog: {}", w.summary());
            k
        }
    };
    for fields in ["summary", "comment,attachment"] {
        let issue = raw
            .get_json(
                "/rest/api/2/issue/{key}",
                json!({"key": key}),
                &[("fields", fields), ("expand", "renderedFields")],
            )
            .await?;
        mirror_lines(&format!("issue.get fields={fields}"), &issue);
        let o = raw
            .search(json!({
                "jql": format!("key = {key}"),
                "fields": fields.split(',').collect::<Vec<_>>(),
                "expand": ["renderedFields"]
            }))
            .await?;
        match o {
            FetchOutcome::Response(r) => {
                let body: Value = serde_json::from_slice(&r.body)?;
                mirror_lines(&format!("search fields={fields}"), &body["issues"][0]);
            }
            other => println!(
                "W(j) search fields={fields}: {}",
                raw.describe_fetch(&other)
            ),
        }
    }
    println!("W(j) scratch issue {key}");
    Ok(())
}

// ---- assignable search (Step 1b k) ------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Jira DC (L-01)"]
async fn v_assignable_search_matching() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    let raw = Raw::new(&l.h, LIVE_ALIAS, &l.url, &l.user)?;
    let (key, _) = create_issue(&l, "atlas-duck live assignable probe").await?;
    let me = raw.get_json("/rest/api/2/myself", json!({}), &[]).await?;
    let display = me["displayName"].as_str().unwrap_or_default().to_owned();

    let swapped: String = l
        .user
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    let prefix = |s: &str, n: usize| s.chars().take(n).collect::<String>();
    let variants: Vec<(&str, String)> = vec![
        ("case-changed", swapped),
        ("padded", format!(" {} ", l.user)),
        (
            "percent-encoded (sent verbatim)",
            format!("{}%40corp.example", l.user),
        ),
        ("empty", String::new()),
        ("-1", "-1".to_owned()),
        ("name-prefix-2", prefix(&l.user, 2)),
        ("name-prefix-3", prefix(&l.user, 3)),
        ("display-prefix-2", prefix(&display, 2)),
        ("display-prefix-3", prefix(&display, 3)),
    ];
    for (label, v) in &variants {
        let o = raw
            .get(
                "/rest/api/2/user/assignable/search",
                json!({}),
                &[("username", v), ("issueKey", &key), ("maxResults", "50")],
            )
            .await?;
        match o {
            FetchOutcome::Response(r) => {
                let users: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
                let list = users.as_array();
                let count = list.map_or(0, Vec::len);
                let me_in = list.is_some_and(|a| {
                    a.iter()
                        .any(|u| u["name"].as_str() == Some(l.user.as_str()))
                });
                println!(
                    "W(k) username={label} status={} count={count} configured_user_present={me_in} full_page={}",
                    r.status,
                    count == 50
                );
            }
            other => println!("W(k) username={label}: {}", raw.describe_fetch(&other)),
        }
    }
    Ok(())
}

// ---- issue-link direction and type naming (Step 1b l) -----------------------------------------

/// `(other_key, direction)` of every link of `issue` (a `fields.issuelinks` value) as
/// "outward" (this issue blocks) or "inward" (is blocked by), with the link id and type.
fn link_view(issue: &Value) -> Vec<(String, &'static str, String, String)> {
    issue["fields"]["issuelinks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|link| {
            let (other, dir) = if let Some(k) = link["outwardIssue"]["key"].as_str() {
                (k, "outward")
            } else {
                (link["inwardIssue"]["key"].as_str()?, "inward")
            };
            Some((
                other.to_owned(),
                dir,
                link["id"].as_str()?.to_owned(),
                format!(
                    "{}/{}",
                    link["type"]["name"].as_str().unwrap_or("?"),
                    link["type"]["id"].as_str().unwrap_or("?")
                ),
            ))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Jira DC (L-01)"]
async fn v_issuelink_direction_and_type_naming() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    let raw = Raw::new(&l.h, LIVE_ALIAS, &l.url, &l.user)?;
    let (a, _) = create_issue(&l, "atlas-duck live link A").await?;
    let (b, _) = create_issue(&l, "atlas-duck live link B").await?;
    let types = raw
        .get_json("/rest/api/2/issueLinkType", json!({}), &[])
        .await?;
    let blocks_id = types["issueLinkTypes"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|t| t["name"] == "Blocks")
        .and_then(|t| t["id"].as_str().map(str::to_owned))
        .ok_or("no link type named Blocks on this instance")?;

    let variants: Vec<(&str, Value)> = vec![
        ("type by name Blocks", json!({"name": "Blocks"})),
        ("type by id only", json!({"id": blocks_id})),
        ("type by name in another case", json!({"name": "blocks"})),
    ];
    for (label, type_value) in variants {
        let body = json!({
            "type": type_value,
            "inwardIssue": {"key": a},
            "outwardIssue": {"key": b}
        });
        let o = raw
            .send(
                "POST",
                "/rest/api/2/issueLink",
                &json!({}),
                Some(&body),
                ExpectedBody::Empty,
            )
            .await?;
        println!(
            "W(l) {label}: POST issueLink inwardIssue={a} outwardIssue={b}: {}",
            describe_write(&o)
        );
        for (name, issue_key, other) in [("A", &a, &b), ("B", &b, &a)] {
            let issue = raw
                .get_json(
                    "/rest/api/2/issue/{key}",
                    json!({"key": issue_key}),
                    &[("fields", "issuelinks")],
                )
                .await?;
            for (to, dir, id, ty) in link_view(&issue) {
                if to == *other {
                    println!(
                        "W(l) {label}: issue {name} lists {} under {dir}Issue ({}) type={ty}",
                        if to == a { "A" } else { "B" },
                        if dir == "outward" {
                            "blocks"
                        } else {
                            "is blocked by"
                        }
                    );
                    if name == "A" {
                        let d = raw
                            .send(
                                "DELETE",
                                "/rest/api/2/issueLink/{id}",
                                &json!({"id": id}),
                                None,
                                ExpectedBody::Empty,
                            )
                            .await?;
                        println!("W(l) {label}: delete link: {}", describe_write(&d));
                    }
                }
            }
        }
    }
    println!("W(l) scratch issues {a} and {b} left in the project");
    Ok(())
}

// ---- worklog in the future (Step 1c) ----------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Jira DC (L-01)"]
async fn v_worklog_future_started() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let l = start_live(&env).await?;
    let raw = Raw::new(&l.h, LIVE_ALIAS, &l.url, &l.user)?;
    let (key, _) = create_issue(&l, "atlas-duck live worklog future start").await?;
    // The app adds no check (PD-55): whatever the server says is what the app would show. The wire
    // probe names the server's message; the app run shows what the approver would see.
    let started = "2099-01-02T09:00:00.000+0000";
    let body = json!({"timeSpent": "1m", "started": started});
    let o = raw
        .send(
            "POST",
            "/rest/api/2/issue/{key}/worklog",
            &json!({"key": key}),
            Some(&body),
            ExpectedBody::Json,
        )
        .await?;
    println!("W(1c) worklog started={started}: {}", describe_write(&o));
    let r = write(
        &l,
        "jira.worklog.add",
        json!({"key": key, "time_spent": "1m", "started": started}),
    )
    .await?;
    println!("W(1c) app run: {}", r.summary());
    report_write(&l, "jira.worklog.add", &r);
    Ok(())
}
