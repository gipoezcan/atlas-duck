#![cfg(feature = "testing")]
//! Opacity before a decision (§4.5, I-07 read cases; Task 29 adds the script and write cases):
//! whatever a read fetched (data, an upstream error, an outcome) and whatever the human will
//! decide, the agent-visible streams are identical until the decision.

mod common;

use std::sync::Mutex;

use atlas_duck_atlassian::testing::{MockDc, fixtures};
use atlas_duck_core::testing::Harness;
use atlas_duck_ipc::envelope::Status;
use atlas_duck_ipc::proto::{AwaitParams, ProgressNotification, ProgressSink};
use common::{TestError, TestResult, de, request_id};
use serde_json::json;

const ISSUE: &str = "jira.issue.get";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

#[derive(Default)]
struct Rec(Mutex<Vec<ProgressNotification>>);

impl ProgressSink for Rec {
    fn progress(&self, n: ProgressNotification) {
        if let Ok(mut v) = self.0.lock() {
            v.push(n);
        }
    }
}

/// One observation round: `status`, then `await` with a 50 ms bound and its notifications, as
/// JSON lines with the request id replaced.
async fn observe(h: &Harness, id: &str, into: &mut Vec<String>) -> TestResult {
    let rec = Rec::default();
    let st = h.status(id).await;
    let aw = h
        .handler()
        .await_request(
            h.default_conn(),
            AwaitParams {
                request_id: id.to_owned(),
                timeout_ms: Some(50),
            },
            &rec,
        )
        .await;
    into.push(st.to_json_line().replace(id, "REQ"));
    into.push(aw.to_json_line().replace(id, "REQ"));
    let notes = rec.0.lock().map_err(|_| "poisoned")?;
    for n in notes.iter() {
        into.push(serde_json::to_string(n)?.replace(id, "REQ"));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i07_streams_identical_released_denied_upstream_outcome() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    let big: String = std::iter::repeat_n('o', 17 * 1024 * 1024).collect();
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.json("/rest/api/2/issue/ABC-2", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.json(
        "/rest/api/2/issue/ABC-3",
        404,
        r#"{"errorMessages":["Issue does not exist"],"errors":{}}"#,
    )
    .await;
    mock.json(
        "/rest/api/2/issue/ABC-4",
        200,
        &json!({ "key": "ABC-4", "fields": { "summary": big } }).to_string(),
    )
    .await;
    // Identical params shapes: only the key differs.
    let mut streams = Vec::new();
    let mut ids = Vec::new();
    for key in ["ABC-1", "ABC-2", "ABC-3", "ABC-4"] {
        let env = h.submit(ISSUE, json!({ "key": key })).await;
        let id = request_id(&env)?;
        let mut s = vec![env.to_json_line().replace(&id, "REQ")];
        observe(&h, &id, &mut s).await?;
        h.queued(&id, 20_000).await.ok_or("never queued")?;
        observe(&h, &id, &mut s).await?;
        ids.push(id);
        streams.push(s);
    }
    let first = streams.first().ok_or("no streams")?;
    for (n, s) in streams.iter().enumerate() {
        assert_eq!(s, first, "request {n} differs before its decision");
        assert!(s.iter().all(|line| !line.contains("executing")));
    }
    assert!(first.iter().all(|l| !l.contains("ABC-")));
    // The decisions then differ as they should.
    let ap = h.approver();
    let [a, b, c, d] = ids.as_slice() else {
        return Err("four ids".into());
    };
    ap.release(a).map_err(de)?;
    ap.deny(b, "no").map_err(de)?;
    ap.release(c).map_err(de)?;
    ap.release(d).map_err(de)?;
    let mut got = Vec::new();
    for id in [a, b, c, d] {
        got.push(h.await_(id, 5000).await.status);
    }
    assert_eq!(
        got,
        [
            Status::Released,
            Status::Denied,
            Status::Failed,
            Status::Failed
        ]
    );
    Ok(())
}
