//! The black-box server e2e suite (M14 PD-260, T23). It runs against the server at
//! `ATLAS_DUCK_E2E_BASE_URL` (the hardened container in GitHub CI), signs in the users of
//! `ATLAS_DUCK_E2E_USERS_FILE` and drives the HTTP, MCP and OAuth surfaces like a browser and an
//! agent would. Cases run in order, each bounded by 60 s; the summary is one
//! `ok|fail|skip <case> <ms>` line per case and the exit code is 1 on any `fail`. Without its
//! environment it prints its usage and exits 2.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "e2e/client.rs"]
mod client;

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

/// The Jira cases: the container job has no Jira the server can reach (it accepts HTTPS
/// instances only), and the HTTPS mock mode is not built on this branch (M14 T23 Decision).
fn jira_case(t: &T) -> R<Outcome> {
    match t.env.jira {
        Jira::None => skip("no Jira (ATLAS_DUCK_E2E_JIRA=none)"),
        Jira::Mock => skip("the HTTPS Jira mock mode is not built yet (M14 T23 Decision)"),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> ExitCode {
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
    let t = T { env, s, users };
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

async fn pat_entry(t: &T) -> R<Outcome> {
    jira_case(t)
}

async fn mcp_api_key_read(t: &T) -> R<Outcome> {
    jira_case(t)
}

async fn write_approval_flow(t: &T) -> R<Outcome> {
    jira_case(t)
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

async fn script_slots_and_busy(_t: &T) -> R<Outcome> {
    skip(
        "no /metrics gauge and no busy answer on this branch (saturation queues, M14 T12 \
         Decision); the server cap is tested in process (tests::scripts)",
    )
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
    match &t.env.admin_exec {
        None => skip("ATLAS_DUCK_E2E_ADMIN_EXEC is not set"),
        Some(_) => skip(
            "user deactivation is M13's admin command (not on this branch; M13 merge); the \
             offline admin CLI also refuses while the server runs",
        ),
    }
}
