#![cfg(feature = "testing")]
//! Audit coverage (§5.1 inv. 1, §13 I-19): over random sequences of lifecycle flows every
//! authenticated request the instance received has a response record committed after its covering
//! start, and the approved write hash recomputes from the stored requests.

mod common;

use atlas_duck_audit::EventType;
use atlas_duck_audit::request_set::requests_from_json;
use atlas_duck_audit::request_set_hash;
use atlas_duck_core::testing::flows::flow_sequences;
use atlas_duck_ipc::envelope::Status;
use common::flows::{check_coverage, check_preview_shown, flow_harness, mount_jira, run_flow};
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
