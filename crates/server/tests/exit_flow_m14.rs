//! The M14 exit criterion in process (T22; master plan M14): an OAuth MCP client runs a script
//! whose result the user releases in the browser, and an auditor exports another user's chain,
//! which verifies offline against the manifest SHA-256 and the server anchor chain.
//!
//! On Linux the script runs in the real sandbox worker (`ATLAS_DUCK_SANDBOX_BIN`, set by the CI
//! step); elsewhere the core's fake runner stands in and the test carries `_fake_runner` in its
//! name, so the CI evidence names the real one.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use atlas_duck_atlassian::testing::TEST_PAT;
use atlas_duck_audit::EventType;
use atlas_duck_audit::server_anchor::{EXCERPT_FILE, EXCERPT_MANIFEST_FILE};
use atlas_duck_audit::types::{AuditCursor, AuditFilter};
use atlas_duck_audit::verify_export::{ANCHOR_CHAIN_OK, AnchorChain, MANIFEST_AND_CHAIN_OK};
use atlas_duck_server::anchor;
use atlas_duck_server::scripts::{ScriptsConfig, ServerScripts};
use atlas_duck_server::users::user_id_for;
use reqwest::Method;
use serde_json::{Value, json};
use support::oauth_client::{OAuthClient, Pkce, discover};
use support::*;

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(120), f)
        .await
        .expect("timed out")
}

/// `(kind, request_id)` of every record of `user`'s chain, oldest first (the runtime is open:
/// the user logged in); the chain verifies.
async fn chain_of(s: &TestServer, user: &str) -> Vec<(EventType, Option<String>)> {
    let uid = user_id_for(user);
    let rt = s
        .registry
        .open_runtimes()
        .await
        .into_iter()
        .find(|r| r.user_id() == uid)
        .expect("the user's runtime is open");
    let page = rt
        .audit_store()
        .query(&AuditFilter::default(), AuditCursor::first(500))
        .unwrap();
    let findings = rt.audit_store().full_verify();
    assert!(findings.is_empty(), "{user}: {findings:?}");
    let mut out: Vec<_> = page
        .rows
        .iter()
        .map(|r| (r.event_type, r.request_id.clone()))
        .collect();
    out.reverse();
    out
}

/// The script's single Jira read and its summary.
const SUMMARY: &str = "ABC-1 read";
const SOURCE: &str = "const issue = await atlas.call('jira.issue.get', {key: 'ABC-1'});\n\
                      return {summary: issue ? 'ABC-1 read' : 'nothing'};";

#[cfg(target_os = "linux")]
fn scripts() -> Arc<ServerScripts> {
    let bin = std::env::var_os("ATLAS_DUCK_SANDBOX_BIN")
        .expect("ATLAS_DUCK_SANDBOX_BIN must name the built worker (set by the CI step)");
    let dir = tempfile::tempdir().unwrap().keep();
    Arc::new(ServerScripts::start(
        ScriptsConfig {
            sandbox_bin: std::path::PathBuf::from(bin),
            ..ScriptsConfig::defaults()
        },
        &dir,
    ))
}

#[cfg(not(target_os = "linux"))]
fn scripts() -> Arc<ServerScripts> {
    use atlas_duck_core::testing::{FakeScriptRunner, ScriptPlan, host_call};
    let plan = ScriptPlan::new(
        vec![host_call(1, "jira.issue.get", json!({"key": "ABC-1"}))],
        atlas_duck_core::RunEnd::Result {
            value: json!({"summary": SUMMARY}),
            logs: Vec::new(),
            stderr: String::new(),
        },
    );
    Arc::new(ServerScripts::with_runner(
        ScriptsConfig::defaults(),
        FakeScriptRunner::new(vec![plan]),
    ))
}

fn writes_seen(reqs: &[wiremock::Request]) -> usize {
    reqs.iter().filter(|r| r.method.as_str() != "GET").count()
}

async fn oauth_client_runs_a_script_flow() {
    let s = TestServer::start_with_scripts(Some(scripts())).await;
    #[cfg(target_os = "linux")]
    {
        let sc = s.registry.deps().scripts.clone().unwrap();
        within(sc.probe.wait(Duration::from_secs(60))).await;
        assert_eq!(sc.state(), "met");
    }
    s.add_work().await;
    let alice = s.login(ALICE).await;
    s.store_pat(&alice, TEST_PAT).await;
    // Client X: discovery, registration, alice's consent to `read scripts`, tokens.
    let d = discover(&s).await;
    let x = OAuthClient::register(&s, &d, "Client X").await;
    let pkce = Pkce::new();
    let q = x
        .authorize(&s, &alice, &pkce, "read scripts", "x-state", &["scripts"])
        .await;
    let (status, tok) = x.redeem(&s, &q["code"], &pkce.verifier).await;
    assert_eq!(status, 200, "{tok}");
    let agent = Arc::new(s.mcp(tok["access_token"].as_str().unwrap()).await);
    // The real run pends with its approval URL.
    let running = {
        let agent = agent.clone();
        tokio::spawn(async move {
            call(
                &agent,
                "script_run",
                json!({"source": SOURCE, "reason": "summary"}),
            )
            .await
        })
    };
    let item = s.queue_of(&alice, 1).await;
    let id = item[0]["request_id"].as_str().unwrap().to_owned();
    let status = envelope(&call(&agent, "request_status", json!({"request_id": id})).await);
    assert_eq!(status["status"], "pending", "{status}");
    assert_eq!(
        status["meta"]["approval_url"],
        format!("{}/approvals?item={id}", s.base)
    );
    // Alice releases the result in the browser.
    let (st, p) = s
        .cmd(&alice, "preview_fetch", json!({"request_id": id}))
        .await;
    assert_eq!(st, 200, "{p}");
    let rev = p["preview"]["candidate_rev"].clone();
    let (st, out) = s
        .cmd(
            &alice,
            "decide",
            json!({"request_id": id, "decision": "release", "candidate_rev": rev}),
        )
        .await;
    assert_eq!(st, 200, "{out}");
    let first = within(running).await.unwrap();
    let awaited = envelope(&call(&agent, "request_await", json!({"request_id": id})).await);
    for env in [envelope(&first), awaited] {
        assert!(
            env.to_string().contains(SUMMARY),
            "the summary came back: {env}"
        );
    }
    // Alice's chain: the grant, the script's lifecycle, no write; the mock saw no write.
    let chain = chain_of(&s, ALICE.0).await;
    let kinds: Vec<&str> = chain.iter().map(|(k, _)| k.as_str()).collect();
    assert!(kinds.contains(&"OAUTH_GRANT_CREATED"), "{kinds:?}");
    assert!(
        chain
            .iter()
            .any(|(k, r)| k.as_str().starts_with("SCRIPT_") && r.as_deref() == Some(id.as_str())),
        "{kinds:?}"
    );
    assert!(!kinds.iter().any(|k| k.starts_with("WRITE_")), "{kinds:?}");
    let reads = s.mock.received().await;
    assert_eq!(writes_seen(&reads), 0);
    assert!(
        reads.iter().any(|r| r.url.path().ends_with("/issue/ABC-1")),
        "the script read ABC-1"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_client_runs_a_script() {
    within(oauth_client_runs_a_script_flow()).await;
}

#[cfg(not(target_os = "linux"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_client_runs_a_script_fake_runner() {
    within(oauth_client_runs_a_script_flow()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auditor_exports_another_users_chain_and_verify_passes() {
    within(async {
        let s = TestServer::start().await;
        let alice = s.login(ALICE).await;
        // Something in alice's chain beyond the login.
        let _ = s.api_key(&alice, &["read"]).await;
        let dave = s.login(DAVE).await;
        let alice_id = user_id_for(ALICE.0);
        let base = format!("/api/auditor/users/{alice_id}/exports");
        let (status, job) = s
            .send(Method::POST, &base, Some(&dave), Some(json!({})))
            .await;
        assert_eq!(status, 202, "{job}");
        s.state.exports.wait_idle().await;
        let id = job["job_id"].as_str().unwrap();
        let (status, done) = s
            .send(Method::GET, &format!("{base}/{id}"), Some(&dave), None)
            .await;
        assert_eq!(
            (status, done["state"].as_str()),
            (200, Some("done")),
            "{done}"
        );
        // The download: the manifest SHA-256 from the header, the pin from the job page.
        let res = s
            .http
            .get(s.url(&format!("{base}/{id}/download")))
            .header("cookie", format!("{COOKIE}={}", dave.cookie))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let manifest_hex = res.headers()["x-atlas-duck-manifest-sha256"]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(done["manifest_sha256"], manifest_hex.as_str());
        let archive = res.bytes().await.unwrap();
        let mut manifest = [0u8; 32];
        hex::decode_to_slice(&manifest_hex, &mut manifest).unwrap();
        let mut pin_hash = [0u8; 32];
        hex::decode_to_slice(done["anchor_head"]["hash"].as_str().unwrap(), &mut pin_hash).unwrap();
        let pin = (done["anchor_head"]["seq"].as_u64().unwrap(), pin_hash);
        // Only the download's own AUDITOR_READ row was anchored since the job: the live head
        // moved one row past the pin.
        let (_, head) = s
            .send(Method::GET, "/api/anchor/head", Some(&dave), None)
            .await;
        assert_eq!(head["seq"], pin.0 + 1);
        // Untar into a temp dir.
        let out = tempfile::tempdir().unwrap();
        let mut dir = None;
        for (name, data) in untar(&archive) {
            let (d, f) = name.split_once('/').unwrap();
            std::fs::create_dir_all(out.path().join(d)).unwrap();
            std::fs::write(out.path().join(d).join(f), data).unwrap();
            dir = Some(out.path().join(d));
        }
        let dir = dir.unwrap();
        assert!(dir.join(EXCERPT_MANIFEST_FILE).is_file());
        let chain = |head| {
            Some(AnchorChain {
                excerpt: Box::leak(dir.join(EXCERPT_FILE).into_boxed_path()),
                head,
            })
        };
        let v = atlas_duck_audit::verify_export_full(&dir, None, chain(Some(pin)), Some(manifest));
        assert_eq!(v.exit_code(), 0, "{:#?}", v.report());
        assert_eq!(v.report().last().unwrap(), MANIFEST_AND_CHAIN_OK);
        let v = atlas_duck_audit::verify_export_full(&dir, None, chain(Some(pin)), None);
        assert_eq!(v.exit_code(), 0, "{:#?}", v.report());
        assert_eq!(v.report().last().unwrap(), ANCHOR_CHAIN_OK);
        // Dave's chain has the export read; alice's has the EXPORT.
        let dave_chain = chain_of(&s, DAVE.0).await;
        assert!(
            dave_chain
                .iter()
                .any(|(k, _)| *k == EventType::AUDITOR_READ)
        );
        let alice_chain = chain_of(&s, ALICE.0).await;
        assert!(alice_chain.iter().any(|(k, _)| *k == EventType::EXPORT));
        // The anchor chain verifies, its v2 leaves included.
        let report = anchor::verify(s.store.as_ref()).unwrap();
        assert!(report.last_seq >= pin.0);
        let _: Value = done;
    })
    .await;
}

/// The ids in `b`'s approval queue.
async fn queue_ids(s: &TestServer, b: &Browser) -> Vec<String> {
    let (_, q) = s.cmd(b, "queue_list", json!({})).await;
    q.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|r| r["request_id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// A read through `agent` must pend in alice's queue; answers its id and the still running call.
async fn read_pends(
    s: &TestServer,
    alice: &Browser,
    agent: &Arc<rmcp::service::RunningService<rmcp::RoleClient, ()>>,
) -> (String, tokio::task::JoinHandle<rmcp::model::CallToolResult>) {
    let before = queue_ids(s, alice).await;
    let task = {
        let agent = agent.clone();
        tokio::spawn(async move { call(&agent, "jira_issue_get", json!({"key": "ABC-1"})).await })
    };
    for _ in 0..300 {
        if let Some(id) = queue_ids(s, alice)
            .await
            .into_iter()
            .find(|i| !before.contains(i))
        {
            assert!(!task.is_finished(), "the read answered before any approval");
            return (id, task);
        }
        if task.is_finished() {
            let r = task.await.unwrap();
            panic!("the read never queued; it answered {:?}", envelope(&r));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the read never queued");
}

/// Concern from batch 5: replacing an instance (same alias, other base URL) must not let a read
/// through without approval, nor carry the old PAT or an earlier release across.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_instance_still_needs_approval_and_keeps_nothing() {
    within(async {
        let s = TestServer::start().await;
        s.add_work().await;
        let alice = s.login(ALICE).await;
        s.store_pat(&alice, TEST_PAT).await;
        let (_, key) = s.api_key(&alice, &["read"]).await;
        let agent = Arc::new(s.mcp(&key).await);
        let (id, task) = read_pends(&s, &alice, &agent).await;
        let (st, p) = s
            .cmd(&alice, "preview_fetch", json!({"request_id": id}))
            .await;
        assert_eq!(st, 200, "{p}");
        let rev = p["preview"]["candidate_rev"].clone();
        let (st, out) = s
            .cmd(
                &alice,
                "decide",
                json!({"request_id": id, "decision": "release", "candidate_rev": rev}),
            )
            .await;
        assert_eq!(st, 200, "{out}");
        assert_eq!(envelope(&task.await.unwrap())["status"], "released");

        // The admin replaces `work` with another Jira.
        let old_seen = s.mock.received().await.len();
        let carol = s.login(CAROL).await;
        let (st, v) = s
            .send(
                Method::DELETE,
                "/api/admin/instances/work",
                Some(&carol),
                None,
            )
            .await;
        assert_eq!(st, 204, "{v}");
        let other = jira_mock().await;
        let (st, v) = s
            .send(
                Method::POST,
                "/api/admin/instances",
                Some(&carol),
                Some(
                    json!({"alias": "work", "product": "jira", "base_url": other.base_url(),
                            "proxy": "direct", "is_default": true}),
                ),
            )
            .await;
        assert_eq!(st, 201, "{v}");
        // The old PAT is gone: a read now fails for want of a credential, it is never served.
        let before_other = other.received().await.len();
        let env = envelope(&call(&agent, "jira_issue_get", json!({"key": "ABC-1"})).await);
        assert_ne!(env["status"], "released", "{env}");
        assert_ne!(env["status"], "succeeded", "{env}");
        assert_eq!(
            other.received().await.len(),
            before_other,
            "the new Jira saw the old PAT"
        );
        // With a new PAT a read pends again and needs its own release.
        s.store_pat(&alice, TEST_PAT).await;
        let (id2, task2) = read_pends(&s, &alice, &agent).await;
        let old_after: Vec<_> = s.mock.received().await.split_off(old_seen);
        assert_ne!(id2, id);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!task2.is_finished(), "served without a release");
        let (st, p) = s
            .cmd(&alice, "preview_fetch", json!({"request_id": id2}))
            .await;
        assert_eq!(st, 200, "{p}");
        let rev = p["preview"]["candidate_rev"].clone();
        let (st, out) = s
            .cmd(
                &alice,
                "decide",
                json!({"request_id": id2, "decision": "deny", "candidate_rev": rev}),
            )
            .await;
        assert_eq!(st, 200, "{out}");
        let env = envelope(&task2.await.unwrap());
        assert_ne!(env["status"], "released", "{env}");
        assert!(!env.to_string().contains("ABC-1 summary"), "{env}");
        // The read went to the new Jira with the new PAT, never to the replaced one.
        let to_new = other.received().await;
        assert!(
            to_new
                .iter()
                .any(|r| r.url.path().ends_with("/issue/ABC-1")),
            "new host unused"
        );
        assert!(
            old_after
                .iter()
                .all(|r| !r.url.path().ends_with("/issue/ABC-1")),
            "the replaced Jira was asked"
        );
    })
    .await;
}
