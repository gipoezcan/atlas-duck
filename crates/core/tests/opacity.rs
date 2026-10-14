#![cfg(feature = "testing")]
//! Opacity before a decision (§4.5, I-07): whatever a read fetched (data, an upstream error, an
//! outcome), whatever a script returned or threw, and whatever the human will decide about a
//! write, the agent-visible streams are identical until the decision.

mod common;

use std::sync::Mutex;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_core::RunEnd;
use atlas_duck_core::testing::{FakeScriptRunner, Harness, ScriptPlan, host_call};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_ipc::proto::{AwaitParams, ProgressNotification, ProgressSink};
use common::{TestError, TestResult, de, request_id};
use serde_json::json;
use wiremock::Mock;
use wiremock::matchers::{method, path};

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

/// What the agent can see of `id` before the decision: `submit`'s envelope, then `status` and
/// a bounded `await` with its notifications, twice (before and after the item is queued).
async fn pending_stream(h: &Harness, env_line: String, id: &str) -> Result<Vec<String>, TestError> {
    let mut s = vec![env_line.replace(id, "REQ")];
    observe(h, id, &mut s).await?;
    h.queued(id, 20_000).await.ok_or("never queued")?;
    observe(h, id, &mut s).await?;
    Ok(s)
}

/// I-07 for writes: three writes with the same shape, one to be denied, one approved and
/// executed, one approved and refused by the instance, look the same to the agent until each
/// decision (`executing` appears only after an approval, §4.5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i07_write_streams_identical_denied_approved_failed() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    let post = |status: u16, body: &str| {
        mock.response(status)
            .set_body_raw(body.to_owned(), "application/json")
    };
    // The first POST is created, the next one refused.
    Mock::given(method("POST"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1/comment")))
        .respond_with(post(201, fixtures::JIRA_COMMENT))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1/comment")))
        .respond_with(post(
            400,
            r#"{"errorMessages":["Comment body can not be empty!"],"errors":{}}"#,
        ))
        .with_priority(2)
        .mount(mock.server())
        .await;
    let mut streams = Vec::new();
    let mut ids = Vec::new();
    for body in ["First text.", "Second text.", "Third text."] {
        let env = h
            .submit(
                "jira.comment.add",
                json!({ "key": "ABC-1", "body": body, "body_format": "wiki" }),
            )
            .await;
        let id = request_id(&env)?;
        streams.push(pending_stream(&h, env.to_json_line(), &id).await?);
        ids.push(id);
    }
    let first = streams.first().ok_or("no streams")?;
    for (n, s) in streams.iter().enumerate() {
        assert_eq!(s, first, "write {n} differs before its decision");
        assert!(
            s.iter()
                .all(|l| !l.contains("executing") && !l.contains("text."))
        );
    }
    let ap = h.approver();
    let [a, b, c] = ids.as_slice() else {
        return Err("three ids".into());
    };
    ap.approve(a).map_err(de)?;
    assert_eq!(h.await_(a, 10_000).await.status, Status::Succeeded);
    ap.deny(b, "no").map_err(de)?;
    assert_eq!(h.await_(b, 10_000).await.status, Status::Denied);
    ap.approve(c).map_err(de)?;
    assert_eq!(h.await_(c, 10_000).await.status, Status::Failed);
    Ok(())
}

fn script_error() -> RunEnd {
    RunEnd::Error {
        class: "TypeError".to_owned(),
        message: "x is not a function".to_owned(),
        stack: "at main (script:3)".to_owned(),
        elapsed_ms: 12,
        logs: vec!["step 1".to_owned()],
        stderr: String::new(),
    }
}

/// I-07 for scripts: a result, a thrown error and a result after a failed host call (whatever
/// the instance answered inside the run) are the same `pending` to the agent until released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i07_script_streams_identical_result_error_failed_call() -> TestResult {
    let runner = FakeScriptRunner::new(vec![
        ScriptPlan::new(
            vec![host_call(1, "jira.issue.get", json!({ "key": "ABC-1" }))],
            RunEnd::Result {
                value: json!({ "n": 1 }),
                logs: Vec::new(),
                stderr: String::new(),
            },
        ),
        ScriptPlan::new(Vec::new(), script_error()),
        ScriptPlan::new(
            vec![host_call(1, "jira.issue.get", json!({ "key": "ABC-9" }))],
            RunEnd::Result {
                value: json!({ "n": 2 }),
                logs: Vec::new(),
                stderr: String::new(),
            },
        ),
    ]);
    let h = Harness::builder()
        .jira("jira-main")
        .scripts(runner)
        .start()
        .await?;
    let mock = jira(&h)?;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.json(
        "/rest/api/2/issue/ABC-9",
        404,
        r#"{"errorMessages":["Issue does not exist"],"errors":{}}"#,
    )
    .await;
    let mut streams = Vec::new();
    let mut ids = Vec::new();
    for n in 0..3 {
        let env = h
            .submit_script(json!({ "source": "return 1;", "args": { "n": n } }))
            .await;
        let id = request_id(&env)?;
        streams.push(pending_stream(&h, env.to_json_line(), &id).await?);
        ids.push(id);
    }
    let first = streams.first().ok_or("no streams")?;
    for (n, s) in streams.iter().enumerate() {
        assert_eq!(s, first, "script {n} differs before its decision");
        assert!(
            s.iter()
                .all(|l| !l.contains("TypeError") && !l.contains("does not exist"))
        );
    }
    let ap = h.approver();
    let [a, b, c] = ids.as_slice() else {
        return Err("three ids".into());
    };
    ap.release(a).map_err(de)?;
    ap.release(b).map_err(de)?;
    ap.deny(c, "no").map_err(de)?;
    assert_eq!(h.await_(a, 5000).await.status, Status::Released);
    assert_eq!(h.await_(b, 5000).await.status, Status::Released);
    assert_eq!(h.await_(c, 5000).await.status, Status::Denied);
    Ok(())
}

/// I-07 for writes over what enrichment learned (M3 T29 M-10): three `jira.issue.edit`, one whose
/// `expected` matches the instance, one that conflicts with it and one whose enrichment GET
/// answers 404, look the same to the agent until the decision: the instance's answer to the read
/// that built the preview stays with the human.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i07_write_streams_identical_enrichment_conflict_vs_match() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    let issue = mock.path("/rest/api/2/issue/ABC-1");
    // The first two enrichment reads see the issue, the third a 404.
    Mock::given(method("GET"))
        .and(path(issue.clone()))
        .respond_with(
            mock.response(200)
                .set_body_raw(fixtures::JIRA_ISSUE, "application/json"),
        )
        .up_to_n_times(2)
        .with_priority(1)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(issue))
        .respond_with(mock.response(404).set_body_raw(
            r#"{"errorMessages":["Issue does not exist"],"errors":{}}"#,
            "application/json",
        ))
        .with_priority(2)
        .mount(mock.server())
        .await;
    let mut streams = Vec::new();
    let mut ids = Vec::new();
    for expected in [
        "Login page times out",
        "Something else",
        "Login page times out",
    ] {
        let env = h
            .submit(
                "jira.issue.edit",
                json!({
                    "key": "ABC-1",
                    "fields": { "summary": "Login fails" },
                    "expected": { "summary": expected }
                }),
            )
            .await;
        let id = request_id(&env)?;
        streams.push(pending_stream(&h, env.to_json_line(), &id).await?);
        ids.push(id);
    }
    let first = streams.first().ok_or("no streams")?;
    for (n, s) in streams.iter().enumerate() {
        assert_eq!(s, first, "write {n} differs before its decision");
        assert!(
            s.iter()
                .all(|l| !l.contains("executing") && !l.contains("times out")),
            "{s:?}"
        );
    }
    for id in &ids {
        h.approver().deny(id, "no").map_err(de)?;
        assert_eq!(h.await_(id, 10_000).await.status, Status::Denied);
    }
    Ok(())
}
