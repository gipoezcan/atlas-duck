#![cfg(feature = "testing")]
//! Audit coverage (§5.1 inv. 1, §13 I-19): over random sequences of lifecycle flows every
//! authenticated request the instance received has a response record committed after its covering
//! start, and the approved write hash recomputes from the stored requests.

mod common;

use atlas_duck_audit::EventType;
use atlas_duck_audit::request_set::requests_from_json;
use atlas_duck_audit::request_set_hash;
use atlas_duck_core::testing::Harness;
use atlas_duck_core::testing::flows::flow_sequences;
use atlas_duck_ipc::envelope::Status;
use common::flows::{
    ConfluenceFlow, check_coverage, check_coverage_on, check_preview_shown,
    confluence_flow_sequences, flow_harness, mount_confluence_flows, mount_jira,
    run_confluence_flow, run_flow,
};
use common::{TestResult, de, request_id};
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use serde_json::json;

fn fail(e: impl std::fmt::Display) -> TestCaseError {
    TestCaseError::fail(e.to_string())
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
}

/// I-19 and U-32 over the flow generator, each case on a fresh harness.
#[test]
fn i19_every_hit_is_covered() -> TestResult {
    let rt = runtime()?;
    let mut runner = TestRunner::new(Config {
        cases: 32,
        failure_persistence: None,
        max_shrink_iters: 64,
        ..Config::default()
    });
    let hits = std::cell::Cell::new(0usize);
    let decisions = std::cell::Cell::new(0usize);
    runner
        .run(&flow_sequences(), |flows| {
            rt.block_on(async {
                let h = flow_harness().await.map_err(fail)?;
                mount_jira(&h).await.map_err(fail)?;
                for (n, f) in flows.iter().enumerate() {
                    run_flow(&h, *f, n)
                        .await
                        .map_err(|e| fail(format!("{f:?}: {e}")))?;
                }
                let n = check_coverage(&h).await.map_err(fail)?;
                hits.set(hits.get() + n);
                let d = check_preview_shown(&h).await.map_err(fail)?;
                decisions.set(decisions.get() + d);
                Ok::<_, TestCaseError>(())
            })
        })
        .map_err(|e| format!("{e}"))?;
    assert!(hits.get() > 0, "no authenticated hit was covered");
    assert!(decisions.get() > 0, "no positive decision was checked");
    Ok(())
}

/// The stored request-set hash recomputes from the stored requests, and the bytes the instance
/// received for the write are `requests[0]`'s.
#[test]
fn i19_write_hash_recomputes() -> TestResult {
    let rt = runtime()?;
    rt.block_on(async {
        let h = flow_harness().await?;
        mount_jira(&h).await?;
        let mock = h.mock("jira-main").ok_or("mock")?;
        let comment =
            json!({ "key": "ABC-1", "body": "Seen on *staging*.", "body_format": "wiki" });
        let env = h.submit("jira.comment.add", comment).await;
        let id = request_id(&env)?;
        h.queued(&id, 10_000).await.ok_or("never queued")?;
        h.approver().approve(&id).map_err(de)?;
        assert_eq!(h.await_(&id, 10_000).await.status, Status::Succeeded);
        let edit = json!({
            "key": "EDT-1",
            "fields": { "summary": "Login fails" },
            "expected": { "summary": "Login page times out" }
        });
        let env = h.submit("jira.issue.edit", edit).await;
        let id2 = request_id(&env)?;
        h.queued(&id2, 10_000).await.ok_or("never queued")?;
        h.approver().approve(&id2).map_err(de)?;
        assert_eq!(h.await_(&id2, 10_000).await.status, Status::Succeeded);

        let sent: Vec<_> = mock
            .received()
            .await
            .into_iter()
            .filter(|r| r.method.as_str() != "GET")
            .collect();
        let mut approvals = 0;
        for r in h.audit_records().await? {
            if r.event_type != EventType::WRITE_APPROVED {
                continue;
            }
            approvals += 1;
            let list = requests_from_json(&r.payload["requests"])?;
            assert_eq!(
                r.payload["request_set_hash"],
                hex::encode(request_set_hash(&list))
            );
            let first = list.first().ok_or("empty request set")?;
            let wire = sent
                .iter()
                .find(|s| {
                    s.method.as_str() == first.method && first.resolved_url.ends_with(s.url.path())
                })
                .ok_or("the write never reached the instance")?;
            assert_eq!(
                wire.body, first.body_bytes,
                "{} {}",
                first.method, first.resolved_url
            );
        }
        assert_eq!(approvals, 2);
        assert_eq!(sent.len(), 2);
        drop(h);
        Ok::<_, common::TestError>(())
    })?;
    Ok(())
}

/// Every flow once, `Quit` last: the coverage check sees the hits of every kind of call (reads,
/// in-flight cancels, enrichment, stale checks, writes, connection tests), so the property above
/// is not vacuous for any of them.
#[test]
fn i19_every_flow_kind_is_covered() -> TestResult {
    use atlas_duck_core::testing::Flow;
    let rt = runtime()?;
    rt.block_on(async {
        let h = flow_harness().await?;
        mount_jira(&h).await?;
        let mut flows = Flow::ALL_BUT_QUIT.to_vec();
        flows.push(Flow::Quit);
        for (n, f) in flows.iter().enumerate() {
            run_flow(&h, *f, n).await?;
        }
        let hits = check_coverage(&h).await?;
        // 10 request-bound fetches: release, error, search outcome, slow outcome, 2 cancelled
        // reads, comment write (+ stale check), edit (3 GETs + PUT), stale (3 GETs), enrichment
        // cancel, and the connection test's two calls: well over 15 in all.
        assert!(hits >= 15, "only {hits} authenticated hits");
        drop(h);
        Ok::<_, common::TestError>(())
    })?;
    Ok(())
}

/// I-19 and U-32 over random sequences of the Confluence flows (a Markdown page get with two user
/// lookups, a page update, an update that conflicts at stage 2, a move, an upload, a label
/// remove), each case on a fresh Confluence harness.
#[test]
fn i19_confluence_every_hit_is_covered() -> TestResult {
    let rt = runtime()?;
    let mut runner = TestRunner::new(Config {
        cases: 12,
        failure_persistence: None,
        max_shrink_iters: 32,
        ..Config::default()
    });
    let hits = std::cell::Cell::new(0usize);
    runner
        .run(&confluence_flow_sequences(), |flows| {
            rt.block_on(async {
                let h = Harness::confluence().await.map_err(fail)?;
                mount_confluence_flows(&h).await.map_err(fail)?;
                for (n, f) in flows.iter().enumerate() {
                    run_confluence_flow(&h, *f, n)
                        .await
                        .map_err(|e| fail(format!("{f:?}: {e}")))?;
                }
                hits.set(hits.get() + check_coverage_on(&h, "wiki").await.map_err(fail)?);
                check_preview_shown(&h).await.map_err(fail)?;
                Ok::<_, TestCaseError>(())
            })
        })
        .map_err(|e| format!("{e}"))?;
    assert!(hits.get() > 0, "no authenticated hit was covered");
    Ok(())
}

/// The Confluence flows, each once, reach the instance's endpoints (the page and its user
/// lookups, the identity GET, stage 2 of an update, the stale checks, the attachment lookup, the
/// multipart `POST`, the label `DELETE`), and every one of those hits has its covering record and
/// a response record with the app's `User-Agent` (I-19). The paths are asserted, so a flow that
/// stopped sending a call cannot leave the property vacuous for it.
#[test]
fn i19_m7_flows_cover_their_hits() -> TestResult {
    let rt = runtime()?;
    rt.block_on(async {
        let h = Harness::confluence().await?;
        mount_confluence_flows(&h).await?;
        let mock = h.mock("wiki").ok_or("no wiki mock")?;
        for (n, f) in ConfluenceFlow::ALL.iter().enumerate() {
            run_confluence_flow(&h, *f, n).await?;
        }
        let seen: Vec<(String, String, Option<String>)> = mock
            .received()
            .await
            .iter()
            .map(|r| {
                (
                    r.method.to_string(),
                    r.url.path().to_owned(),
                    r.url.query().map(str::to_owned),
                )
            })
            .collect();
        let sent = |m: &str, p: &str, q: Option<&str>| {
            let full = mock.path(p);
            seen.iter().any(|(sm, sp, sq)| {
                sm == m
                    && *sp == full
                    && q.is_none_or(|q| sq.as_deref().is_some_and(|s| s.contains(q)))
            })
        };
        for (m, p, q) in [
            ("GET", "/rest/api/user/current", None),
            ("GET", "/rest/api/content/65543", None),
            ("GET", "/rest/api/user", Some("key=key-jdoe")),
            ("GET", "/rest/api/user", Some("key=key-asmith")),
            ("GET", "/rest/api/content/65538", Some("expand=version")),
            ("PUT", "/rest/api/content/65538", None),
            ("GET", "/rest/api/content/65537", Some("status=historical")),
            ("GET", "/rest/api/content/65539", None),
            ("GET", "/rest/api/content/65540", None),
            ("PUT", "/rest/api/content/65539", None),
            (
                "GET",
                "/rest/api/content/65541/child/attachment",
                Some("limit=50"),
            ),
            (
                "POST",
                "/rest/api/content/65541/child/attachment",
                Some("allowDuplicated=false"),
            ),
            (
                "GET",
                "/rest/api/content/65542",
                Some("expand=metadata.labels"),
            ),
            ("DELETE", "/rest/api/content/65542/label/release", None),
        ] {
            assert!(sent(m, p, q), "{m} {p} {q:?} was never sent: {seen:?}");
        }
        // Nothing the flows did not plan.
        let planned = [
            "/rest/api/user/current",
            "/rest/api/user",
            "/rest/api/content/65543",
            "/rest/api/content/65538",
            "/rest/api/content/65537",
            "/rest/api/content/65539",
            "/rest/api/content/65540",
            "/rest/api/content/65541/child/attachment",
            "/rest/api/content/65542",
            "/rest/api/content/65542/label/release",
        ];
        for (m, p, _) in &seen {
            assert!(
                planned.iter().any(|x| mock.path(x) == *p),
                "unplanned request {m} {p}"
            );
        }
        let covered = check_coverage_on(&h, "wiki").await?;
        assert!(covered >= 14, "only {covered} authenticated hits");
        let shown = check_preview_shown(&h).await?;
        assert!(shown >= 5, "only {shown} positive decisions");
        drop(h);
        Ok::<_, common::TestError>(())
    })?;
    Ok(())
}

/// The M5 flows (a Markdown comment, a three-stage create, an assign, an issuelink, a sprint
/// move, an issue get with `--comments`) reach the instance's endpoints, and every one of those
/// hits (the cache fill, the stage GETs, the comment page, the stale checks) has its covering
/// record and a response record with the app's `User-Agent` (I-19). The paths are asserted, so a
/// flow that stopped sending a call cannot leave the property vacuous for it.
#[test]
fn i19_m5_flows_cover_their_hits() -> TestResult {
    use atlas_duck_core::testing::Flow;
    let rt = runtime()?;
    rt.block_on(async {
        let h = flow_harness().await?;
        mount_jira(&h).await?;
        let mock = h.mock("jira-main").ok_or("no jira mock")?;
        let flows = [
            Flow::CommentMarkdown,
            Flow::CreateThreeStage,
            Flow::Assign,
            Flow::IssueLink,
            Flow::SprintMove,
            Flow::IssueGetComments,
        ];
        for (n, f) in flows.iter().enumerate() {
            run_flow(&h, *f, n).await?;
        }
        let seen: Vec<(String, String)> = mock
            .received()
            .await
            .iter()
            .map(|r| (r.method.to_string(), r.url.path().to_owned()))
            .collect();
        for (m, p) in [
            ("GET", "/rest/api/2/field"),
            ("GET", "/rest/api/2/myself"),
            ("GET", "/rest/api/2/project"),
            ("GET", "/rest/api/2/issue/createmeta/ABC/issuetypes"),
            ("GET", "/rest/api/2/issue/createmeta/ABC/issuetypes/10002"),
            ("POST", "/rest/api/2/issue"),
            ("GET", "/rest/api/2/user/assignable/search"),
            ("PUT", "/rest/api/2/issue/ABC-2/assignee"),
            ("GET", "/rest/api/2/issueLinkType"),
            ("POST", "/rest/api/2/issueLink"),
            ("GET", "/rest/agile/1.0/sprint/7"),
            ("POST", "/rest/agile/1.0/sprint/7/issue"),
            ("POST", "/rest/api/2/issue/ABC-0/comment"),
            ("GET", "/rest/api/2/issue/ABC-5/comment"),
        ] {
            let full = mock.path(p);
            assert!(
                seen.iter().any(|(sm, sp)| sm == m && *sp == full),
                "{m} {p} was never sent: {seen:?}"
            );
        }
        let covered = check_coverage(&h).await?;
        assert!(covered >= 14, "only {covered} authenticated hits");
        let shown = check_preview_shown(&h).await?;
        assert!(shown >= 6, "only {shown} positive decisions");
        drop(h);
        Ok::<_, common::TestError>(())
    })?;
    Ok(())
}
