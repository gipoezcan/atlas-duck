#![cfg(feature = "testing")]
//! Audit properties over random decision sequences (U-32). Every decision record with the
//! `batch` flag follows a `BATCH_CONFIRMED` of the same `append_batch` that lists it with its
//! revision (L43); every positive decision has a `PREVIEW_SHOWN` of the same request and revision
//! before it (§5.6), over random lifecycle flows.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};

use atlas_duck_atlassian::testing::fixtures;
use atlas_duck_audit::{EventFlags, EventType};
use atlas_duck_core::testing::{Harness, RecordedEvent};
use atlas_duck_core::{BatchItem, Confirm, DecisionError};
use common::{TestError, TestResult, request_id};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path_regex};

/// What happens to one queued read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    /// Into the case's batch approval.
    Batch,
    Release,
    Deny,
    /// Into the case's batch deny.
    DenyBatch,
}

fn acts() -> impl Strategy<Value = (Vec<Act>, bool)> {
    let act = prop_oneof![
        2 => Just(Act::Batch),
        1 => Just(Act::Release),
        1 => Just(Act::Deny),
        1 => Just(Act::DenyBatch),
    ];
    // The bool: the batch dialog is cancelled (its items are then denied in a batch).
    (prop::collection::vec(act, 1..=4), prop::bool::weighted(0.2))
}

fn fail(e: impl std::fmt::Debug) -> TestCaseError {
    TestCaseError::fail(format!("{e:?}"))
}

/// U-32 (batch half) over every recorded `append` / `append_batch` call. Returns how many
/// flagged per-item decisions it checked.
fn check_batch_records(calls: &[Vec<RecordedEvent>]) -> Result<usize, String> {
    let mut checked = 0;
    for call in calls {
        let lead = call
            .iter()
            .position(|e| e.event_type == EventType::BATCH_CONFIRMED);
        if let Some(at) = lead
            && at != 0
        {
            return Err("BATCH_CONFIRMED is not first in its append".into());
        }
        let listed: Vec<(String, Value)> = match lead {
            Some(_) => call[0].payload["items"]
                .as_array()
                .ok_or("BATCH_CONFIRMED without items")?
                .iter()
                .map(|i| {
                    (
                        i["request_id"].as_str().unwrap_or_default().to_owned(),
                        i["candidate_rev"].clone(),
                    )
                })
                .collect(),
            None => Vec::new(),
        };
        let mut seen = Vec::new();
        for e in call.iter().skip(1) {
            if !e.flags.contains(EventFlags::BATCH) {
                continue;
            }
            let Some(lead) = call.first().filter(|_| lead.is_some()) else {
                return Err(format!(
                    "{} with the batch flag outside a confirmed batch",
                    e.event_type.as_str()
                ));
            };
            if e.payload["batch_id"] != lead.payload["batch_id"] {
                return Err("batch_id differs from its BATCH_CONFIRMED".into());
            }
            let id = e
                .request_id
                .clone()
                .ok_or("per-item record without request id")?;
            let rev = listed
                .iter()
                .find(|(l, _)| *l == id)
                .map(|(_, r)| r)
                .ok_or_else(|| format!("{id} not listed in its BATCH_CONFIRMED"))?;
            match e.event_type {
                EventType::WRITE_APPROVED if e.payload["candidate_rev"] != *rev => {
                    return Err("WRITE_APPROVED names another revision".into());
                }
                // An unredacted result is the candidate itself: same bytes, same hash.
                EventType::READ_RELEASED
                    if e.payload["released_sha256"].is_string()
                        && e.payload["redaction_ops"] == json!([])
                        && e.payload["released_sha256"] != rev["candidate_hash"] =>
                {
                    return Err("READ_RELEASED released another revision".into());
                }
                EventType::WRITE_APPROVED | EventType::READ_RELEASED => {}
                other => return Err(format!("{} carries the batch flag", other.as_str())),
            }
            seen.push(id);
            checked += 1;
        }
        // Every listed item got exactly one flagged decision in the same transaction.
        for (id, _) in &listed {
            if seen.iter().filter(|s| *s == id).count() != 1 {
                return Err(format!("{id} listed without exactly one decision"));
            }
        }
        // Nothing outside an append that starts with `BATCH_CONFIRMED` carries the flag.
        if lead.is_none() && call.iter().any(|e| e.flags.contains(EventFlags::BATCH)) {
            return Err("batch flag without BATCH_CONFIRMED".into());
        }
    }
    Ok(checked)
}

#[test]
fn u32_batch_decisions_follow_batch_confirmed() -> TestResult {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let h = rt.block_on(Harness::jira())?;
    let mock = h.mock("jira-main").ok_or("no mock")?;
    let issue = format!("^{}[^/]+$", regex_escape(&mock.path("/rest/api/2/issue/")));
    rt.block_on(
        Mock::given(method("GET"))
            .and(path_regex(issue))
            .respond_with(
                mock.response(200)
                    .set_body_raw(fixtures::JIRA_ISSUE, "application/json"),
            )
            .mount(mock.server()),
    );
    h.plan().record_appends(true);
    let next = AtomicU32::new(0);
    let mut runner = TestRunner::new(Config {
        cases: 64,
        failure_persistence: None,
        ..Config::default()
    });
    runner
        .run(&acts(), |(acts, cancel)| {
            let case = next.fetch_add(1, Ordering::SeqCst);
            // Fresh keys per case: an earlier decision on the same key would flag "similar".
            let ids = rt
                .block_on(async {
                    let mut ids = Vec::new();
                    for i in 0..acts.len() {
                        let key = format!("P{case}-{i}");
                        let env = h.submit("jira.issue.get", json!({ "key": key })).await;
                        let id = request_id(&env)?;
                        h.queued(&id, 10_000).await.ok_or("never queued")?;
                        ids.push(id);
                    }
                    Ok::<_, TestError>(ids)
                })
                .map_err(fail)?;
            let ap = h.approver();
            for id in &ids {
                ap.open(id).map_err(fail)?;
            }
            let pick = |a: Act| -> Vec<String> {
                ids.iter()
                    .zip(&acts)
                    .filter(|(_, x)| **x == a)
                    .map(|(id, _)| id.clone())
                    .collect()
            };
            let batch = pick(Act::Batch);
            if !batch.is_empty() {
                h.confirmer()
                    .push(if cancel { Confirm::Cancel } else { Confirm::Ok });
                let items: Vec<BatchItem> = batch
                    .iter()
                    .map(|id| {
                        Ok(BatchItem {
                            request_id: id.clone(),
                            candidate_rev: ap.rev(id)?,
                        })
                    })
                    .collect::<Result<_, DecisionError>>()
                    .map_err(fail)?;
                match h.decisions().decide_batch(items) {
                    Ok(out) => prop_assert_eq!(out.items.len(), batch.len()),
                    Err(DecisionError::Cancelled) if cancel => {
                        let n = h
                            .decisions()
                            .deny_batch(&batch, "cancelled batch")
                            .map_err(fail)?;
                        prop_assert_eq!(n, batch.len());
                    }
                    Err(e) => return Err(fail(e)),
                }
            }
            for id in pick(Act::Release) {
                ap.release(&id).map_err(fail)?;
            }
            for id in pick(Act::Deny) {
                ap.deny(&id, "no").map_err(fail)?;
            }
            let denied = pick(Act::DenyBatch);
            let n = h
                .decisions()
                .deny_batch(&denied, "not needed")
                .map_err(fail)?;
            prop_assert_eq!(n, denied.len());
            check_batch_records(&h.plan().appends()).map_err(TestCaseError::fail)?;
            Ok(())
        })
        .map_err(|e| format!("{e}"))?;
    let checked = check_batch_records(&h.plan().appends())?;
    assert!(checked > 0, "no batch decision was made");
    // The harness (mock servers, core tasks) goes down on its runtime.
    rt.block_on(async move { drop(h) });
    Ok(())
}

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

/// U-32 (preview half) over random sequences of lifecycle flows, each on a fresh harness: every
/// `READ_RELEASED`, `WRITE_APPROVED` and `SCRIPT_RELEASED` has an earlier `PREVIEW_SHOWN` of the
/// same request and revision. (`i19_every_hit_is_covered` runs the same check over its flows.)
#[test]
fn u32_every_positive_decision_has_preview_shown() -> TestResult {
    use common::flows::{check_preview_shown, flow_harness, mount_jira, run_flow};
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let checked = std::cell::Cell::new(0usize);
    let mut runner = TestRunner::new(Config {
        cases: 32,
        failure_persistence: None,
        max_shrink_iters: 64,
        ..Config::default()
    });
    runner
        .run(
            &atlas_duck_core::testing::flows::flow_sequences(),
            |flows| {
                rt.block_on(async {
                    let h = flow_harness().await.map_err(fail)?;
                    mount_jira(&h).await.map_err(fail)?;
                    for (n, f) in flows.iter().enumerate() {
                        run_flow(&h, *f, n)
                            .await
                            .map_err(|e| fail(format!("{f:?}: {e}")))?;
                    }
                    let n = check_preview_shown(&h).await.map_err(TestCaseError::fail)?;
                    checked.set(checked.get() + n);
                    Ok::<_, TestCaseError>(())
                })
            },
        )
        .map_err(|e| format!("{e}"))?;
    assert!(checked.get() > 0, "no positive decision was checked");
    Ok(())
}

/// U-32 is enforced, not only observed (M3 T29 M-11): flows try `release_unopened` after a
/// redaction and `approve_unopened` after an edit, get `Err(Invalid(NotOpened))`, and the property
/// then runs over the log: every release and approval, outcome releases included, names the
/// `candidate_rev` of an earlier `PREVIEW_SHOWN` of its request.
#[test]
fn u32_unopened_attempts_rejected_then_property_holds() -> TestResult {
    use atlas_duck_core::testing::Flow;
    use common::flows::{
        check_preview_shown, flow_harness, mount_jira, run_flow, run_unopened_attempts,
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    rt.block_on(async {
        let h = flow_harness().await?;
        mount_jira(&h).await?;
        run_unopened_attempts(&h, 0).await?;
        run_flow(&h, Flow::ReadOutcome, 1).await?;
        let checked = check_preview_shown(&h).await?;
        // The redacted release, the edited approval and the outcome release at the least.
        assert!(checked >= 3, "only {checked} decisions checked");
        let refused = h
            .audit_records()
            .await?
            .iter()
            .filter(|r| r.event_type == EventType::DECISION_INVALID)
            .count();
        assert!(refused >= 2, "{refused} refusals, wanted the two attempts");
        drop(h);
        Ok::<_, TestError>(())
    })?;
    Ok(())
}

/// PD-57: every `READ_RELEASED` and `SCRIPT_RELEASED` of the flow property carries a
/// `candidate_rev` object equal to that of an earlier `PREVIEW_SHOWN` of the same request, the
/// outcome releases (`{code, hint}`) included; the fixed sequence has data, upstream-error and
/// outcome releases.
#[test]
fn u32_released_candidate_rev_matches_preview_shown() -> TestResult {
    use atlas_duck_core::testing::Flow;
    use common::flows::{check_preview_shown, flow_harness, mount_jira, run_flow};
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    rt.block_on(async {
        let h = flow_harness().await?;
        mount_jira(&h).await?;
        let flows = [
            Flow::ReadRelease,
            Flow::ReadUpstreamError,
            Flow::ReadOutcome,
            Flow::ReadDeny,
        ];
        for (n, f) in flows.iter().enumerate() {
            run_flow(&h, *f, n).await?;
        }
        let checked = check_preview_shown(&h).await?;
        let released: Vec<_> = h
            .audit_records()
            .await?
            .into_iter()
            .filter(|r| r.event_type == EventType::READ_RELEASED)
            .collect();
        assert!(
            released.len() >= 3 && released.iter().any(|r| r.payload["code"].is_string()),
            "{} releases, no outcome release among them",
            released.len()
        );
        for r in &released {
            assert!(r.payload["candidate_rev"].is_object(), "{}", r.payload);
        }
        assert!(checked >= released.len());
        drop(h);
        Ok::<_, TestError>(())
    })?;
    Ok(())
}

/// A fixed sequence that makes every kind of positive decision (a plain release, a released
/// upstream error, an approval, an edited approval, a stale write returned and denied): the
/// property is not vacuous for any of them.
#[test]
fn u32_fixed_sequence_decisions_have_preview_shown() -> TestResult {
    use atlas_duck_core::testing::Flow;
    use common::flows::{check_preview_shown, flow_harness, mount_jira, run_flow};
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    rt.block_on(async {
        let h = flow_harness().await?;
        mount_jira(&h).await?;
        let flows = [
            Flow::ReadRelease,
            Flow::ReadUpstreamError,
            Flow::WriteApprove,
            Flow::WriteEditApprove,
            Flow::WriteStaleChanged,
            Flow::ReadDeny,
            Flow::WriteDeny,
        ];
        for (n, f) in flows.iter().enumerate() {
            run_flow(&h, *f, n).await?;
        }
        let checked = check_preview_shown(&h).await?;
        // 2 releases and 2 approvals at the least (the edit's second revision is its own).
        assert!(checked >= 4, "only {checked} decisions checked");
        drop(h);
        Ok::<_, TestError>(())
    })?;
    Ok(())
}
