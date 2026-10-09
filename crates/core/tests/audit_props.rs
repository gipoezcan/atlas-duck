#![cfg(feature = "testing")]
//! Audit properties over random decision sequences (U-32). Task 23: every decision record with
//! the `batch` flag follows a `BATCH_CONFIRMED` of the same `append_batch` that lists it with
//! its revision (L43). Task 29 adds the `PREVIEW_SHOWN` half.

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
