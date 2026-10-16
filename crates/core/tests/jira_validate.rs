#![cfg(feature = "testing")]
//! Jira bodies at validation (Task 7): Markdown `description`/`body` converted to wiki markup and
//! hard-checked by the validation dry call (§5.4 step 1, §7.6, PD-42, PD-43), the U-24 injected
//! converter fault (PD-64), and the U-33 Jira completions.

mod common;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_audit::request_set::requests_from_json;
use atlas_duck_convert::markdown_to_wiki;
use atlas_duck_core::TestHooks;
use atlas_duck_core::testing::{ConverterFault, Harness};
use atlas_duck_ipc::envelope::{Envelope, Status};
use common::{TestError, TestResult, code, de, detail, exit, message, request_id, test_hits};
use serde_json::{Value, json};

const COMMENT: &str = "jira.comment.add";
const CREATE: &str = "jira.issue.create";
const COMMENT_PATH: &str = "/rest/api/2/issue/ABC-1/comment";
const CREATE_PATH: &str = "/rest/api/2/issue";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

/// The requests the mock received apart from the field-name cache's fills (T7 review M-1).
async fn hits(mock: &MockDc) -> usize {
    test_hits(mock).await.len()
}

/// A harness whose converter output gets `fault` appended before the hard check.
async fn faulty(fault: ConverterFault) -> Result<Harness, TestError> {
    Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            converter_fault: Some(fault),
            ..TestHooks::none()
        })
        .start()
        .await
}

/// The identity call before a write (§5.4 step 5) answers as the PAT's user.
async fn identity_ok(mock: &MockDc) {
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
}

/// Submits, waits until decidable, approves and waits for `succeeded`; returns the request id.
async fn approved(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    h.approver().open(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    Ok(id)
}

/// The one non-GET request the mock received, and the one request `WRITE_APPROVED` holds: the
/// bodies must be the same bytes (U-03); returns the sent body as JSON.
async fn sent_body(h: &Harness, mock: &MockDc, id: &str) -> Result<Value, TestError> {
    let writes: Vec<_> = mock
        .received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() != "GET")
        .collect();
    let [sent] = writes.as_slice() else {
        return Err(format!("{} writes sent", writes.len()).into());
    };
    let approved = h
        .events(id)
        .await?
        .into_iter()
        .find(|(t, _)| *t == EventType::WRITE_APPROVED)
        .map(|(_, p)| p)
        .ok_or("no WRITE_APPROVED")?;
    let list = requests_from_json(&approved["requests"])?;
    let [approved_req] = list.as_slice() else {
        return Err("not exactly one approved request".into());
    };
    assert_eq!(
        sent.body, approved_req.body_bytes,
        "wire bytes == WRITE_APPROVED bytes"
    );
    Ok(serde_json::from_slice(&sent.body)?)
}

/// A rejected submit: `failed`, `validation`, exit 2, a request id, nothing but
/// `REQUEST_RECEIVED` + `REQUEST_REJECTED`, nothing queued.
async fn assert_rejected_at_validation(h: &Harness, env: &Envelope) -> TestResult {
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(env), "validation");
    assert_eq!(exit(env), 2);
    let id = request_id(env)?;
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
    );
    assert!(h.approver().item(&id).is_none(), "nothing queued");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u33_jira_markdown_body_format_accepted() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mock.json(COMMENT_PATH, 201, fixtures::JIRA_COMMENT).await;
    let md = "**bold** and {toc}";
    // No `body_format`: Markdown (the schema default, M3 "absent counts as markdown").
    let id = approved(&h, COMMENT, json!({ "key": "ABC-1", "body": md })).await?;
    let body = sent_body(&h, mock, &id).await?;
    // The converter's exact output (it ends in one newline), sent byte for byte as checked.
    assert_eq!(body["body"], json!("*bold* and \\{toc\\}\n"));
    assert_eq!(body["body"], json!(markdown_to_wiki(md).0));
    // `body_format: markdown` is the same request.
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mock.json(COMMENT_PATH, 201, fixtures::JIRA_COMMENT).await;
    let params = json!({ "key": "ABC-1", "body": md, "body_format": "markdown" });
    let id = approved(&h, COMMENT, params).await?;
    assert_eq!(
        sent_body(&h, mock, &id).await?["body"],
        json!("*bold* and \\{toc\\}\n")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u33_confluence_markdown_now_accepted() -> TestResult {
    // M7 (Task 9): Confluence converts Markdown too; the M3 refusal is gone (absent counts as
    // Markdown, as for Jira). `tests/confluence_validate.rs` covers the conversion itself.
    let h = Harness::confluence().await?;
    for params in [
        json!({ "id": "65537", "base_version": 5, "body": "**hi**" }),
        json!({ "id": "65537", "base_version": 5, "body": "**hi**", "body_format": "markdown" }),
    ] {
        let env = h.submit("confluence.page.update", params).await;
        assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wiki_body_format_is_verbatim() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mock.json(COMMENT_PATH, 201, fixtures::JIRA_COMMENT).await;
    let wiki = "{toc} [~jdoe]";
    let params = json!({ "key": "ABC-1", "body": wiki, "body_format": "wiki" });
    let id = approved(&h, COMMENT, params).await?;
    // Verbatim: no conversion, no hard check, no added newline.
    assert_eq!(sent_body(&h, mock, &id).await?["body"], json!(wiki));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u24_injected_fault_fails_validation_exit2() -> TestResult {
    for (fault, construct) in [
        (ConverterFault::Include, "include"),
        (ConverterFault::Mention, "mention"),
        (ConverterFault::Html, "macro"),
    ] {
        let h = faulty(fault).await?;
        let mock = jira(&h)?;
        let before = hits(mock).await;
        let params = json!({ "project": "ABC", "issuetype": "Bug", "summary": "S",
                             "description": "Steps:\n\n1. log in\n2. `reset`" });
        let env = h.submit(CREATE, params).await;
        assert_rejected_at_validation(&h, &env).await?;
        assert_eq!(detail(&env, "param"), json!("description"), "{construct}");
        assert_eq!(detail(&env, "construct"), json!(construct));
        assert_eq!(detail(&env, "count"), json!(1));
        assert_eq!(
            message(&env),
            format!("markdown conversion produced an unrecorded {construct}")
        );
        // The error carries the kind, never the body or the injected text.
        let line = env.to_json_line();
        assert!(
            !line.contains("Steps") && !line.contains("injected") && !line.contains("Injected")
        );
        assert_eq!(hits(mock).await, before, "no wiremock hit");
        // The same through `jira.comment.add`'s `body`.
        let env = h
            .submit(COMMENT, json!({ "key": "ABC-1", "body": "plain *text*" }))
            .await;
        assert_rejected_at_validation(&h, &env).await?;
        assert_eq!(detail(&env, "param"), json!("body"));
        assert_eq!(detail(&env, "construct"), json!(construct));
        assert_eq!(hits(mock).await, before, "no wiremock hit");
        // The fault touches only converted text: verbatim wiki still passes validation.
        let env = h
            .submit(
                COMMENT,
                json!({ "key": "ABC-1", "body": "plain", "body_format": "wiki" }),
            )
            .await;
        assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    }
    Ok(())
}

/// T7 review M-4: whitespace-only Markdown converts to `"\n"`, which Jira answers with a 400
/// after a human approved it. It is refused at validation instead, without echoing the text.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whitespace_only_markdown_rejected_at_validation() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    let before = hits(mock).await;
    let blank = " \n\t \n";
    for (op, params, param) in [
        (COMMENT, json!({ "key": "ABC-1", "body": blank }), "body"),
        (
            COMMENT,
            json!({ "key": "ABC-1", "body": blank, "body_format": "markdown" }),
            "body",
        ),
        (
            CREATE,
            json!({ "project": "ABC", "issuetype": "Bug", "summary": "S", "description": blank }),
            "description",
        ),
    ] {
        let env = h.submit(op, params).await;
        assert_rejected_at_validation(&h, &env).await?;
        assert_eq!(detail(&env, "param"), json!(param), "{op}");
        assert_eq!(
            detail(&env, "message"),
            json!("is empty after markdown conversion")
        );
        assert_eq!(
            message(&env),
            format!("params/{param}: is empty after markdown conversion")
        );
        assert!(!env.to_json_line().contains("\\t"), "no body text echoed");
    }
    assert_eq!(hits(mock).await, before, "no wiremock hit");
    // Verbatim wiki stays the agent's choice (PD-42): not converted, not refused here.
    let env = h
        .submit(
            COMMENT,
            json!({ "key": "ABC-1", "body": blank, "body_format": "wiki" }),
        )
        .await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_markdown_description_converted_before_enrichment() -> TestResult {
    // The dry call converts and checks before the executor asks for enrichment: a fault is
    // rejected before the first enrichment GET (Task 12: the projects).
    let h = faulty(ConverterFault::Include).await?;
    let mock = jira(&h)?;
    common::jira::mount_create_stages(mock).await;
    let before = hits(mock).await;
    let params = json!({ "project": "ABC", "issuetype": "Bug", "summary": "S",
                         "description": "**x**" });
    let env = h.submit(CREATE, params.clone()).await;
    assert_rejected_at_validation(&h, &env).await?;
    assert_eq!(hits(mock).await, before, "wiremock saw zero requests");

    // Without a fault the same params enrich, and the approved request carries the converted
    // description.
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    common::jira::mount_create_stages(mock).await;
    mock.json(CREATE_PATH, 201, fixtures::JIRA_ISSUE_CREATED)
        .await;
    let id = approved(&h, CREATE, params).await?;
    let body = sent_body(&h, mock, &id).await?;
    assert_eq!(body["fields"]["description"], json!("*x*\n"));
    assert_eq!(body["fields"]["issuetype"], json!({ "id": "10002" }));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u33_issue_get_comments_param_validates() -> TestResult {
    let h = Harness::jira().await?;
    let env = h
        .submit(
            "jira.issue.get",
            json!({ "key": "ABC-1", "comments": "yes" }),
        )
        .await;
    assert_rejected_at_validation(&h, &env).await?;
    assert_eq!(detail(&env, "param"), json!("comments"));
    let env = h
        .submit(
            "jira.issue.get",
            json!({ "key": "ABC-1", "comments": true }),
        )
        .await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    Ok(())
}
