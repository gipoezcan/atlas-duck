//! The black-box server e2e suite (M14 PD-260, T23). It runs against the server at
//! `ATLAS_DUCK_E2E_BASE_URL` (the hardened container in GitHub CI), signs in the users of
//! `ATLAS_DUCK_E2E_USERS_FILE` and drives the HTTP, MCP and OAuth surfaces like a browser and an
//! agent would. Cases run in order, each bounded by 60 s; the summary is one
//! `ok|fail|skip <case> <ms>` line per case and the exit code is 1 on any `fail`. Without its
//! environment it prints its usage and exits 2.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "e2e/client.rs"]
mod client;
#[path = "e2e/jira.rs"]
mod jira;

use std::future::Future;
use std::pin::Pin;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use atlas_duck_audit::server_anchor::EXCERPT_FILE;
use atlas_duck_audit::verify_export::{ANCHOR_CHAIN_OK, AnchorChain, MANIFEST_AND_CHAIN_OK};
use atlas_duck_server_e2e::{Env, Jira, Line, Outcome, parse_env};
use client::*;
use reqwest::Method;
use serde_json::{Value, json};

const CASE_LIMIT: Duration = Duration::from_secs(60);

/// What every case gets.
struct T {
    env: Env,
    s: Server,
    users: Users,
    /// The HTTPS Jira mock (`ATLAS_DUCK_E2E_JIRA=mock`).
    jira: Option<jira::Jira>,
}

impl T {
    fn alice(&self) -> &User {
        &self.users.plain[0]
    }

    fn bob(&self) -> &User {
        &self.users.plain[1]
    }
}

type CaseFn = for<'a> fn(&'a T) -> Pin<Box<dyn Future<Output = R<Outcome>> + 'a>>;

macro_rules! cases {
    ($($name:ident),* $(,)?) => {
        [$((stringify!($name), (|t| Box::pin($name(t))) as CaseFn)),*]
    };
}

fn skip(why: &str) -> R<Outcome> {
    Ok(Outcome::Skip(why.to_owned()))
}

/// The Jira mock, or why the Jira cases skip (review environment: none, L258).
fn jira_of(t: &T) -> Result<&jira::Jira, Outcome> {
    t.jira
        .as_ref()
        .ok_or_else(|| Outcome::Skip("no Jira (ATLAS_DUCK_E2E_JIRA=none)".into()))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> ExitCode {
    // The CA step runs before the server starts (its CA bundle must exist then).
    if let Some(dir) = std::env::var_os("ATLAS_DUCK_E2E_MAKE_CA") {
        return match jira::make_ca(std::path::Path::new(&dir)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("cannot make the test CA: {e}");
                ExitCode::from(2)
            }
        };
    }
    let env = match parse_env(|k| std::env::var(k).ok()) {
        Ok(e) => e,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let setup = Server::new(&env.base_url, env.ca_file.as_deref())
        .and_then(|s| Users::read(&env.users_file).map(|u| (s, u)));
    let (s, users) = match setup {
        Ok(x) => x,
        Err(e) => {
            eprintln!("cannot start: {e}");
            return ExitCode::from(2);
        }
    };
    let jira = match &env.jira {
        Jira::None => None,
        Jira::Mock { ca_dir } => match jira::Jira::start(std::path::Path::new(ca_dir)).await {
            Ok(j) => Some(j),
            Err(e) => {
                eprintln!("cannot start the Jira mock: {e}");
                return ExitCode::from(2);
            }
        },
    };
    let t = T {
        env,
        s,
        users,
        jira,
    };
    let mut failed = false;
    for (name, case) in cases![
        health_and_ready,
        login_logout_csrf_origin,
        api_key_lifecycle,
        pat_entry,
        mcp_api_key_read,
        write_approval_flow,
        oauth_discovery_registration_consent_token_refresh_revoke,
        oauth_refresh_reuse_revokes_grant,
        oauth_token_not_accepted_for_approvals,
        script_run_via_oauth,
        script_slots_and_busy,
        own_audit_view,
        auditor_list_browse_export_and_verify,
        auditor_reads_recorded,
        admin_has_no_audit_access,
        deactivation_revokes_tokens,
    ] {
        let start = Instant::now();
        let outcome = match tokio::time::timeout(CASE_LIMIT, case(&t)).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => Outcome::Fail(e),
            Err(_) => Outcome::Fail(format!("timed out after {} s", CASE_LIMIT.as_secs())),
        };
        failed |= matches!(outcome, Outcome::Fail(_));
        println!(
            "{}",
            Line {
                case: name,
                ms: start.elapsed().as_millis(),
                outcome: &outcome,
            }
        );
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

async fn health_and_ready(t: &T) -> R<Outcome> {
    let (st, _) = t.s.send(Method::GET, "/healthz", None, None).await?;
    ensure!(st == 200, "/healthz {st}");
    let (st, v) = t.s.send(Method::GET, "/readyz", None, None).await?;
    ensure!(st == 200, "/readyz {st} {v}");
    ensure!(
        v["scripts"] == t.env.scripts.as_str(),
        "/readyz scripts is {}, expected {}",
        v["scripts"],
        t.env.scripts
    );
    Ok(Outcome::Ok)
}

async fn login_logout_csrf_origin(t: &T) -> R<Outcome> {
    let s = &t.s;
    let (st, _) = s
        .send_with(
            Method::POST,
            "/api/login",
            None,
            Some(json!({"username": t.alice().name, "password": "wrong-password"})),
            false,
            Some(&s.base),
        )
        .await?;
    ensure!(st == 401, "a wrong password answered {st}");
    let b = s.login(t.alice()).await?;
    let (st, v) = s.send(Method::GET, "/api/session", Some(&b), None).await?;
    ensure!(st == 200, "session {st} {v}");
    let body = json!({"name": "csrf", "scopes": ["read"]});
    let (st, _) = s
        .send_with(
            Method::POST,
            "/api/me/api-keys",
            Some(&b),
            Some(body.clone()),
            false,
            Some(&s.base),
        )
        .await?;
    ensure!(st == 403, "no CSRF token answered {st}");
    let (st, _) = s
        .send_with(
            Method::POST,
            "/api/me/api-keys",
            Some(&b),
            Some(body),
            true,
            Some("https://evil.example"),
        )
        .await?;
    ensure!(st == 403, "a foreign Origin answered {st}");
    let (st, v) = s.send(Method::POST, "/api/logout", Some(&b), None).await?;
    ensure!(st == 200 || st == 204, "logout {st} {v}");
    let (st, _) = s.send(Method::GET, "/api/session", Some(&b), None).await?;
    ensure!(st == 401, "the session survived logout: {st}");
    Ok(Outcome::Ok)
}

async fn api_key_lifecycle(t: &T) -> R<Outcome> {
    let s = &t.s;
    let b = s.login(t.alice()).await?;
    let (id, key) = s.api_key(&b, &["read"]).await?;
    ensure!(
        s.mcp_status(&key).await? == 200,
        "a new key is refused at /mcp"
    );
    let agent = s.mcp(&key).await?;
    let tools = agent
        .list_all_tools()
        .await
        .ctx("tools/list")?
        .into_iter()
        .map(|t| t.name.to_string())
        .collect::<Vec<_>>();
    ensure!(
        tools.iter().any(|n| n == "jira_issue_get"),
        "tools/list: {tools:?}"
    );
    ensure!(
        !tools.iter().any(|n| n == "script_run"),
        "a read key lists script_run"
    );
    let (st, v) = s
        .send(Method::GET, "/api/me/api-keys", Some(&b), None)
        .await?;
    ensure!(
        st == 200 && v.to_string().contains(&id),
        "list keys {st} {v}"
    );
    ensure!(
        !v.to_string().contains(&key),
        "the key list shows the secret"
    );
    let (st, _) = s
        .send(
            Method::DELETE,
            &format!("/api/me/api-keys/{id}"),
            Some(&b),
            None,
        )
        .await?;
    ensure!(st == 204, "revoke key {st}");
    ensure!(
        s.mcp_status(&key).await? == 401,
        "a revoked key is still accepted"
    );
    Ok(Outcome::Ok)
}

/// The admin adds the HTTPS mock as `work` (the org CA bundle, idempotent); alice stores the test
/// PAT, checked against the mock.
async fn work_with_pat(t: &T, j: &jira::Jira) -> R<Browser> {
    let s = &t.s;
    let carol = s.login(&t.users.admin).await?;
    let spec = json!({"alias": "work", "product": "jira", "base_url": j.base_url,
                      "proxy": "direct", "ca_ref": "org", "is_default": true});
    let (mut st, mut v) = s
        .send(
            Method::POST,
            "/api/admin/instances",
            Some(&carol),
            Some(spec.clone()),
        )
        .await?;
    if st == 409 {
        // From an earlier case of this run or an earlier run against the same server: the mock's
        // port may have changed, so the instance is replaced.
        let (dst, dv) = s
            .send(
                Method::DELETE,
                "/api/admin/instances/work",
                Some(&carol),
                None,
            )
            .await?;
        ensure!(dst == 204, "admin remove {dst} {dv}");
        (st, v) = s
            .send(
                Method::POST,
                "/api/admin/instances",
                Some(&carol),
                Some(spec),
            )
            .await?;
    }
    ensure!(st == 201, "admin add {st} {v}");
    let alice = s.login(t.alice()).await?;
    let (st, v) = s
        .send(
            Method::PUT,
            "/api/me/pats/work",
            Some(&alice),
            Some(json!({"pat": atlas_duck_atlassian::testing::TEST_PAT})),
        )
        .await?;
    ensure!(st == 200, "PAT entry {st} {v}");
    Ok(alice)
}

/// Releases or approves the queued request `id` in the browser.
async fn decide(s: &Server, b: &Browser, id: &str, decision: &str) -> R<()> {
    let (st, p) = s.cmd(b, "preview_fetch", json!({"request_id": id})).await?;
    ensure!(st == 200, "preview {st} {p}");
    let rev = p["preview"]["candidate_rev"].clone();
    let (st, v) = s
        .cmd(
            b,
            "decide",
            json!({"request_id": id, "decision": decision, "candidate_rev": rev}),
        )
        .await?;
    ensure!(st == 200, "decide {st} {v}");
    Ok(())
}

/// The request ids in `b`'s queue now.
async fn queue_ids(s: &Server, b: &Browser) -> R<Vec<String>> {
    let (st, q) = s.cmd(b, "queue_list", json!({})).await?;
    ensure!(st == 200, "queue_list {st} {q}");
    Ok(q.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|r| r["request_id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default())
}

/// The first request queued for `b` that was not in `before`.
async fn queued(s: &Server, b: &Browser, before: &[String]) -> R<String> {
    for _ in 0..300 {
        if let Some(id) = queue_ids(s, b)
            .await?
            .into_iter()
            .find(|id| !before.contains(id))
        {
            return Ok(id);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("nothing was queued".into())
}
async fn pat_entry(t: &T) -> R<Outcome> {
    let j = match jira_of(t) {
        Ok(j) => j,
        Err(o) => return Ok(o),
    };
    // The PAT is checked against the mock (its identity call) when it is stored.
    work_with_pat(t, j).await?;
    Ok(Outcome::Ok)
}

async fn mcp_api_key_read(t: &T) -> R<Outcome> {
    let j = match jira_of(t) {
        Ok(j) => j,
        Err(o) => return Ok(o),
    };
    let s = &t.s;
    let alice = work_with_pat(t, j).await?;
    let (_, key) = s.api_key(&alice, &["read"]).await?;
    let agent = std::sync::Arc::new(s.mcp(&key).await?);
    let before = queue_ids(s, &alice).await?;
    let reading = {
        let agent = agent.clone();
        tokio::spawn(async move { call(&agent, "jira_issue_get", json!({"key": "ABC-1"})).await })
    };
    let id = queued(s, &alice, &before).await?;
    decide(s, &alice, &id, "release").await?;
    let env = reading.await.ctx("read task")??;
    ensure!(env["status"] == "released", "read: {env}");
    ensure!(
        env["data"].to_string().contains("ABC-1"),
        "read data: {env}"
    );
    Ok(Outcome::Ok)
}

async fn write_approval_flow(t: &T) -> R<Outcome> {
    let j = match jira_of(t) {
        Ok(j) => j,
        Err(o) => return Ok(o),
    };
    let s = &t.s;
    let alice = work_with_pat(t, j).await?;
    let before = j.writes().await.len();
    let (_, key) = s.api_key(&alice, &["read", "propose_write"]).await?;
    let agent = std::sync::Arc::new(s.mcp(&key).await?);
    let queued_before = queue_ids(s, &alice).await?;
    let writing = {
        let agent = agent.clone();
        tokio::spawn(async move {
            call(
                &agent,
                "jira_comment_add",
                json!({"key": "ABC-1", "body": "Seen on staging.", "body_format": "wiki",
                       "reason": "e2e"}),
            )
            .await
        })
    };
    let id = queued(s, &alice, &queued_before).await?;
    let pending = call(&agent, "request_status", json!({"request_id": id})).await?;
    ensure!(pending["status"] == "pending", "status: {pending}");
    ensure!(
        pending["meta"]["approval_url"] == format!("{}/approvals?item={id}", s.base).as_str(),
        "approval_url: {pending}"
    );
    ensure!(
        j.writes().await.len() == before,
        "a write reached Jira before approval"
    );
    decide(s, &alice, &id, "approve").await?;
    let env = writing.await.ctx("write task")??;
    ensure!(env["status"] == "succeeded", "write: {env}");
    let writes = j.writes().await;
    ensure!(
        writes.len() == before + 1,
        "{} writes reached Jira",
        writes.len() - before
    );
    let w = &writes[writes.len() - 1];
    ensure!(
        w.url.path() == "/rest/api/2/issue/ABC-1/comment",
        "write path {}",
        w.url.path()
    );
    ensure!(
        w.headers.get("authorization").and_then(|v| v.to_str().ok())
            == Some(format!("Bearer {}", atlas_duck_atlassian::testing::TEST_PAT).as_str()),
        "the write did not carry alice's PAT"
    );
    Ok(Outcome::Ok)
}
async fn oauth_discovery_registration_consent_token_refresh_revoke(t: &T) -> R<Outcome> {
    let s = &t.s;
    let b = s.login(t.alice()).await?;
    let (c, tok) = OAuthClient::tokens_for(s, &b, &["read"]).await?;
    ensure!(tok["token_type"] == "Bearer", "{tok}");
    ensure!(tok["scope"] == "read", "{tok}");
    let access = field(&tok, "access_token")?;
    ensure!(
        s.mcp_status(&access).await? == 200,
        "the access token is refused"
    );
    let (st, tok2) = c.refresh(s, &field(&tok, "refresh_token")?).await?;
    ensure!(st == 200, "refresh {st} {tok2}");
    let access2 = field(&tok2, "access_token")?;
    ensure!(
        s.mcp_status(&access2).await? == 200,
        "the refreshed token is refused"
    );
    // The grant is listed under connected apps; revoking the refresh token ends it.
    let (st, v) = s
        .send(Method::GET, "/api/me/oauth/grants", Some(&b), None)
        .await?;
    ensure!(
        st == 200 && v.to_string().contains(&c.client_id),
        "grants {st} {v}"
    );
    ensure!(
        c.revoke(s, &field(&tok2, "refresh_token")?).await? == 200,
        "revoke"
    );
    ensure!(
        s.mcp_status(&access2).await? == 401,
        "an access token of a revoked grant is accepted"
    );
    Ok(Outcome::Ok)
}

async fn oauth_refresh_reuse_revokes_grant(t: &T) -> R<Outcome> {
    let s = &t.s;
    let b = s.login(t.alice()).await?;
    let (c, tok) = OAuthClient::tokens_for(s, &b, &["read"]).await?;
    let rt1 = field(&tok, "refresh_token")?;
    let (st, tok2) = c.refresh(s, &rt1).await?;
    ensure!(st == 200, "refresh {st} {tok2}");
    let (st, e) = c.refresh(s, &rt1).await?;
    ensure!(
        st == 400 && e["error"] == "invalid_grant",
        "a reused refresh token answered {st} {e}"
    );
    let (st, e) = c.refresh(s, &field(&tok2, "refresh_token")?).await?;
    ensure!(st == 400, "the family survived the reuse: {st} {e}");
    ensure!(
        s.mcp_status(&field(&tok2, "access_token")?).await? == 401,
        "the access token survived the reuse"
    );
    Ok(Outcome::Ok)
}

async fn oauth_token_not_accepted_for_approvals(t: &T) -> R<Outcome> {
    let s = &t.s;
    let b = s.login(t.alice()).await?;
    let (_, tok) = OAuthClient::tokens_for(s, &b, &["read", "propose_write"]).await?;
    let access = field(&tok, "access_token")?;
    for (path, body) in [
        (
            "/api/cmd/decide",
            json!({"request_id": "req_x", "decision": "approve"}),
        ),
        ("/api/cmd/queue_list", json!({})),
    ] {
        let res = s
            .http
            .post(s.url(path))
            .header("authorization", format!("Bearer {access}"))
            .header("origin", &s.base)
            .json(&body)
            .send()
            .await
            .ctx(path)?;
        let st = res.status().as_u16();
        ensure!(
            st == 401 || st == 403,
            "{path} with an OAuth token answered {st}"
        );
    }
    Ok(Outcome::Ok)
}

async fn script_run_via_oauth(t: &T) -> R<Outcome> {
    if t.env.scripts != "met" {
        return skip("the sandbox floor is not met on this host (ATLAS_DUCK_E2E_SCRIPTS=not_met)");
    }
    let s = &t.s;
    let b = s.login(t.alice()).await?;
    let (_, tok) = OAuthClient::tokens_for(s, &b, &["read", "scripts"]).await?;
    let agent = s.mcp(&field(&tok, "access_token")?).await?;
    // No host call without a Jira: a dry run of a pure script in the container's sandbox.
    let env = call(
        &agent,
        "script_run",
        json!({"source": "return 1 + 1;", "dry_run": "sparse"}),
    )
    .await?;
    ensure!(env["status"] == "succeeded", "script_run: {env}");
    // A read token cannot run scripts.
    let (_, tok) = OAuthClient::tokens_for(s, &b, &["read"]).await?;
    let agent = s.mcp(&field(&tok, "access_token")?).await?;
    let refused = call(
        &agent,
        "script_run",
        json!({"source": "return 1;", "dry_run": "sparse"}),
    )
    .await;
    ensure!(
        refused
            .as_ref()
            .map_or(true, |e| e["status"] != "succeeded"),
        "a read token ran a script: {refused:?}"
    );
    Ok(Outcome::Ok)
}

async fn script_slots_and_busy(t: &T) -> R<Outcome> {
    // `/metrics` is never served through a proxy (M13): behind the review ingress it is 404.
    let (st, _) = t.s.send(Method::GET, "/metrics", None, None).await?;
    if st == 404 {
        return skip("/metrics is not reachable here (behind a proxy)");
    }
    let text =
        t.s.http
            .get(t.s.url("/metrics"))
            .send()
            .await
            .ctx("/metrics")?
            .text()
            .await
            .ctx("/metrics body")?;
    let floor = format!("atlas_duck_scripts_floor{{state=\"{}\"}} 1", t.env.scripts);
    for want in [
        floor.as_str(),
        "atlas_duck_script_runs_active{kind=\"run\"} 0",
        "atlas_duck_script_runs_active{kind=\"dry\"} 0",
    ] {
        ensure!(text.lines().any(|l| l == want), "/metrics lacks {want}");
    }
    ensure!(
        text.lines()
            .any(|l| l.starts_with("atlas_duck_script_runs_max{kind=\"run\"} ")),
        "/metrics lacks the run pool size"
    );
    // Saturation queues instead of answering busy (M14 T12 Decision); the pools are idle again
    // after the earlier script case.
    Ok(Outcome::Ok)
}
/// The `event_type`s of `b`'s own chain (first page).
async fn own_kinds(s: &Server, b: &Browser) -> R<Vec<String>> {
    let (st, v) = s.cmd(b, "audit_query", json!({"filter": {}})).await?;
    ensure!(st == 200, "audit_query {st} {v}");
    Ok(v["rows"]
        .as_array()
        .ctx("audit_query rows")?
        .iter()
        .filter_map(|r| r["event_type"].as_str().map(str::to_owned))
        .collect())
}

async fn own_audit_view(t: &T) -> R<Outcome> {
    let s = &t.s;
    let a = s.login(t.alice()).await?;
    let kinds = own_kinds(s, &a).await?;
    ensure!(
        kinds.iter().any(|k| k == "LOGIN"),
        "alice's chain: {kinds:?}"
    );
    // There is no route to another user's chain without the auditor role.
    let b = s.login(t.bob()).await?;
    let (st, _) = s
        .send(Method::GET, "/api/auditor/users", Some(&b), None)
        .await?;
    ensure!(st == 403, "a plain user listed users: {st}");
    Ok(Outcome::Ok)
}

/// The `user_id` of `name` from the auditor's `GET /api/auditor/users`.
async fn user_id_of(s: &Server, auditor: &Browser, name: &str) -> R<String> {
    let (st, v) = s
        .send(Method::GET, "/api/auditor/users", Some(auditor), None)
        .await?;
    ensure!(st == 200, "auditor users {st} {v}");
    let list = v["users"].as_array().or(v.as_array()).ctx("users list")?;
    list.iter()
        .find(|u| u["username"] == name)
        .and_then(|u| u["user_id"].as_str().map(str::to_owned))
        .ctx("the auditor list lacks the user")
}

async fn auditor_list_browse_export_and_verify(t: &T) -> R<Outcome> {
    let s = &t.s;
    let alice = s.login(t.alice()).await?;
    let _ = s.api_key(&alice, &["read"]).await?;
    let dave = s.login(&t.users.auditor).await?;
    let alice_id = user_id_of(s, &dave, &t.alice().name).await?;
    let base = format!("/api/auditor/users/{alice_id}");
    let (st, page) = s
        .send(
            Method::POST,
            &format!("{base}/audit_query"),
            Some(&dave),
            Some(json!({"filter": {}})),
        )
        .await?;
    ensure!(
        st == 200 && page["rows"].is_array(),
        "auditor query {st} {page}"
    );
    let (st, job) = s
        .send(
            Method::POST,
            &format!("{base}/exports"),
            Some(&dave),
            Some(json!({})),
        )
        .await?;
    ensure!(st == 202, "export {st} {job}");
    let id = field(&job, "job_id")?;
    let mut done = Value::Null;
    for _ in 0..200 {
        let (st, v) = s
            .send(
                Method::GET,
                &format!("{base}/exports/{id}"),
                Some(&dave),
                None,
            )
            .await?;
        ensure!(st == 200, "job {st} {v}");
        match v["state"].as_str() {
            Some("done") => {
                done = v;
                break;
            }
            Some("failed") => return Err(format!("the export failed: {v}")),
            _ => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    ensure!(done["state"] == "done", "the export never finished");
    let res = s
        .http
        .get(s.url(&format!("{base}/exports/{id}/download")))
        .header("cookie", &dave.cookie)
        .send()
        .await
        .ctx("download")?;
    ensure!(res.status() == 200, "download {}", res.status());
    let manifest_hex = res
        .headers()
        .get("x-atlas-duck-manifest-sha256")
        .and_then(|v| v.to_str().ok())
        .ctx("no manifest header")?
        .to_owned();
    ensure!(done["manifest_sha256"] == manifest_hex.as_str(), "{done}");
    let archive = res.bytes().await.ctx("download body")?;
    let mut manifest = [0u8; 32];
    hex32(&manifest_hex, &mut manifest)?;
    // The pin is the job's own anchor head (T18/T20 Decision), not the moving live head.
    let head_hash = field(&done["anchor_head"], "hash")?;
    let mut pin_hash = [0u8; 32];
    hex32(&head_hash, &mut pin_hash)?;
    let pin_seq = done["anchor_head"]["seq"].as_u64().ctx("anchor_head.seq")?;
    let out = tempfile::tempdir().ctx("temp dir")?;
    let mut dir = None;
    for (name, data) in untar(&archive)? {
        let (d, f) = name.split_once('/').ctx("member name")?;
        ensure!(
            !f.contains('/') && !d.contains("..") && !f.contains(".."),
            "member {name}"
        );
        std::fs::create_dir_all(out.path().join(d)).ctx("mkdir")?;
        std::fs::write(out.path().join(d).join(f), data).ctx("write member")?;
        dir = Some(out.path().join(d));
    }
    let dir = dir.ctx("an empty archive")?;
    let excerpt = dir.join(EXCERPT_FILE);
    let chain = || {
        Some(AnchorChain {
            excerpt: &excerpt,
            head: Some((pin_seq, pin_hash)),
        })
    };
    let v = atlas_duck_audit::verify_export_full(&dir, None, chain(), Some(manifest));
    ensure!(
        v.exit_code() == 0 && v.report().last().map(String::as_str) == Some(MANIFEST_AND_CHAIN_OK),
        "verify (manifest + chain): {:?}",
        v.report()
    );
    let v = atlas_duck_audit::verify_export_full(&dir, None, chain(), None);
    ensure!(
        v.exit_code() == 0 && v.report().last().map(String::as_str) == Some(ANCHOR_CHAIN_OK),
        "verify (chain only): {:?}",
        v.report()
    );
    if let Some(prefix) = &t.env.verify_exec {
        // The image's own verify-export on the same files (GitHub: a container of the image).
        let mut words = prefix.split_whitespace();
        let program = words.next().ctx("ATLAS_DUCK_E2E_VERIFY_EXEC is empty")?;
        let status = tokio::process::Command::new(program)
            .args(words)
            .arg(&dir)
            .arg(EXCERPT_FILE)
            .arg(format!("{pin_seq}:{head_hash}"))
            .arg(&manifest_hex)
            .status()
            .await
            .ctx("verify exec")?;
        ensure!(
            status.success(),
            "the image's verify-export exited {status}"
        );
    }
    Ok(Outcome::Ok)
}

fn hex32(text: &str, out: &mut [u8; 32]) -> R<()> {
    hex::decode_to_slice(text, out).ctx("64 hex digits")
}

async fn auditor_reads_recorded(t: &T) -> R<Outcome> {
    let s = &t.s;
    let _ = s.login(t.alice()).await?;
    let dave = s.login(&t.users.auditor).await?;
    let alice_id = user_id_of(s, &dave, &t.alice().name).await?;
    let (st, _) = s
        .send(
            Method::POST,
            &format!("/api/auditor/users/{alice_id}/audit_query"),
            Some(&dave),
            Some(json!({"filter": {}})),
        )
        .await?;
    ensure!(st == 200, "auditor query {st}");
    let kinds = own_kinds(s, &dave).await?;
    ensure!(
        kinds.iter().any(|k| k == "AUDITOR_READ"),
        "the auditor's chain lacks AUDITOR_READ: {kinds:?}"
    );
    Ok(Outcome::Ok)
}

async fn admin_has_no_audit_access(t: &T) -> R<Outcome> {
    let s = &t.s;
    let dave = s.login(&t.users.auditor).await?;
    let alice_id = user_id_of(s, &dave, &t.alice().name).await?;
    let carol = s.login(&t.users.admin).await?;
    let (st, _) = s
        .send(Method::GET, "/api/auditor/users", Some(&carol), None)
        .await?;
    ensure!(st == 403, "the admin listed users as an auditor: {st}");
    let (st, _) = s
        .send(
            Method::POST,
            &format!("/api/auditor/users/{alice_id}/audit_query"),
            Some(&carol),
            Some(json!({"filter": {}})),
        )
        .await?;
    ensure!(st == 403, "the admin read alice's chain: {st}");
    Ok(Outcome::Ok)
}

async fn deactivation_revokes_tokens(t: &T) -> R<Outcome> {
    let Some(prefix) = &t.env.admin_exec else {
        return skip("ATLAS_DUCK_E2E_ADMIN_EXEC is not set (review: verify:review-ops-drill)");
    };
    // The last case: it deactivates the second plain user for good.
    let s = &t.s;
    let user = t.bob();
    let b = s.login(user).await?;
    let (c, tok) = OAuthClient::tokens_for(s, &b, &["read"]).await?;
    let (_, key) = s.api_key(&b, &["read"]).await?;
    let access = field(&tok, "access_token")?;
    ensure!(s.mcp_status(&access).await? == 200, "token refused before");
    let mut words = prefix.split_whitespace();
    let program = words.next().ctx("ATLAS_DUCK_E2E_ADMIN_EXEC is empty")?;
    let out = tokio::process::Command::new(program)
        .args(words)
        .args(["users", "deactivate", &user.name])
        .output()
        .await
        .ctx("admin exec")?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    ensure!(out.status.success(), "users deactivate: {text}");
    ensure!(
        text.split_whitespace()
            .collect::<String>()
            .contains("\"oauth_grants_revoked\":1"),
        "deactivation report: {text}"
    );
    ensure!(
        s.mcp_status(&access).await? == 401,
        "the OAuth token survived"
    );
    ensure!(s.mcp_status(&key).await? == 401, "the API key survived");
    let (st, e) = c.refresh(s, &field(&tok, "refresh_token")?).await?;
    ensure!(st == 400, "refresh after deactivation: {st} {e}");
    let (st, _) = s.send(Method::GET, "/api/session", Some(&b), None).await?;
    ensure!(st == 401, "the session survived: {st}");
    let res = s
        .http
        .post(s.url("/api/login"))
        .header("origin", &s.base)
        .json(&json!({"username": user.name, "password": user.password}))
        .send()
        .await
        .ctx("login")?;
    ensure!(
        res.status() == 403,
        "a deactivated user signed in: {}",
        res.status()
    );
    Ok(Outcome::Ok)
}
