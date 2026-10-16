#![cfg(feature = "testing")]
//! Confluence bodies at validation (M7 Task 9): the Markdown placeholder check (U-25, PD-98), the
//! Markdown → storage conversion with its storage hard check (U-24, PD-97) and the agent-supplied
//! storage check (PD-94), all in the validation dry call of `confluence.page.update` (§5.4 step 1,
//! §7.6), plus the per-product converter fault (PD-64, plan review I-15).

mod common;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, UserKind, XAuser, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_audit::request_set::requests_from_json;
use atlas_duck_convert::{
    UserResolutions, markdown_to_storage, markdown_to_wiki, storage_to_markdown,
};
use atlas_duck_core::TestHooks;
use atlas_duck_core::testing::{ConverterFault, Harness};
use atlas_duck_ipc::envelope::{Envelope, Status};
use common::{TestError, TestResult, code, de, detail, exit, message, request_id, test_hits};
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path};

const UPDATE: &str = "confluence.page.update";
const CONTENT: &str = "/rest/api/content/65537";

/// §7.6 (verbatim): the hint of a Markdown body that still holds `page get` placeholders.
const HINT: &str = "fetch with `--format storage` and submit `body_format=storage`";
/// The full message: the hint, then the escape guidance (T4 review m-6, lead ruling).
const PLACEHOLDER_MESSAGE: &str = "fetch with `--format storage` and submit `body_format=storage`. \
     To keep such text as prose, escape it: `\\@` before `@user:` and `\\[` before `[macro:`.";

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no confluence mock".into())
}

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

async fn hits(mock: &MockDc) -> usize {
    test_hits(mock).await.len()
}

/// A Confluence harness (`wiki`) whose converter output gets `fault` appended before the hard
/// check.
async fn faulty(fault: ConverterFault) -> Result<Harness, TestError> {
    Harness::builder()
        .confluence("wiki")
        .hooks(TestHooks {
            converter_fault: Some(fault),
            ..TestHooks::none()
        })
        .start()
        .await
}

/// The page update's server side: the identity call, page 65537 at version 7 for every GET
/// (enrichment, stale check), and the PUT's answer.
async fn page_server(mock: &MockDc) {
    mock.confluence_user_current(UserKind::Known, TEST_USER, TEST_USER_KEY)
        .await;
    Mock::given(method("GET"))
        .and(path(mock.path(CONTENT)))
        .respond_with(
            mock.response(200)
                .set_body_raw(fixtures::CONFLUENCE_PAGE, "application/json"),
        )
        .mount(mock.server())
        .await;
    Mock::given(method("PUT"))
        .and(path(mock.path(CONTENT)))
        .respond_with(
            mock.response(200)
                .set_body_raw(fixtures::CONFLUENCE_PAGE_UPDATED, "application/json"),
        )
        .mount(mock.server())
        .await;
}

/// `page.update` params at the fixture's version 7.
fn update(body: &str, format: Option<&str>) -> Value {
    let mut p = json!({ "id": "65537", "base_version": 7, "body": body });
    if let Some(f) = format {
        p["body_format"] = json!(f);
    }
    p
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

/// A submit refused at validation with `code`: `failed`, exit 2, not retryable, nothing but
/// `REQUEST_RECEIVED` + `REQUEST_REJECTED`, nothing queued.
async fn assert_rejected(h: &Harness, env: &Envelope, want: &str) -> TestResult {
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(env), want, "{}", env.to_json_line());
    assert_eq!(exit(env), 2);
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    let id = request_id(env)?;
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
    );
    assert!(h.approver().item(&id).is_none(), "nothing queued");
    Ok(())
}

/// A Markdown body with a heading, emphasis, a list, a quote, a link and a code block.
const MARKDOWN: &str = "# Release 1.4\n\n**Fixes** the [login](https://x.example/a?b=1&c=2) and \
                        <the> reset flow:\n\n- one\n- two\n\n> quoted\n\n```rust\nlet x = \"]]>\";\n```\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u33_confluence_markdown_body_format_accepted() -> TestResult {
    let storage = markdown_to_storage(MARKDOWN).0;
    assert!(storage.contains("<ac:structured-macro ac:name=\"code\">"));
    for format in [None, Some("markdown")] {
        let h = Harness::confluence().await?;
        let mock = wiki(&h)?;
        page_server(mock).await;
        let id = approved(&h, UPDATE, update(MARKDOWN, format)).await?;
        let body = sent_body(&h, mock, &id).await?;
        // The converter's exact output, sent byte for byte as checked; never the agent's text.
        assert_eq!(
            body["body"]["storage"]["value"],
            json!(storage),
            "{format:?}"
        );
        assert_eq!(body["body"]["storage"]["representation"], json!("storage"));
        assert_eq!(body["version"]["number"], json!(8));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u25_markdown_placeholders_rejected_exit2_counts() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    page_server(mock).await;
    let before = hits(mock).await;
    // One of each kind, the macro first in the source: the details keep the fixed kind order.
    let md = "[macro: toc {}]\n\nSee [the page](confluence:DOC/Release%20notes) and \
              ![logo](confluence:attachment/logo.png), asked by @user:8a7f808a1.\n";
    for format in [None, Some("markdown")] {
        let env = h.submit(UPDATE, update(md, format)).await;
        assert_rejected(&h, &env, "markdown_placeholders").await?;
        assert_eq!(
            detail(&env, "placeholders"),
            json!([
                {"kind": "link", "count": 1},
                {"kind": "image", "count": 1},
                {"kind": "macro", "count": 1},
                {"kind": "user", "count": 1},
            ])
        );
        // The §7.6 hint verbatim, then one sentence on escaping genuine prose.
        let text = message(&env);
        assert!(text.starts_with(HINT), "{text}");
        assert_eq!(text, PLACEHOLDER_MESSAGE);
        // Kinds and counts only: no body text, no key.
        let line = env.to_json_line();
        assert!(!line.contains("8a7f808a1") && !line.contains("Release") && !line.contains("logo"));
    }
    // Counts per kind; kinds with no hit are left out.
    let env = h
        .submit(UPDATE, update("@user:a and @user:b, [macro: x {}]", None))
        .await;
    assert_rejected(&h, &env, "markdown_placeholders").await?;
    assert_eq!(
        detail(&env, "placeholders"),
        json!([{"kind": "macro", "count": 1}, {"kind": "user", "count": 2}])
    );
    // U-25 end to end: what `page get` released as Markdown, resubmitted as Markdown.
    let storage = "<ac:structured-macro ac:name=\"toc\"/><p>See \
                   <ac:link><ri:page ri:content-title=\"Release notes\"/></ac:link>, \
                   <ac:image><ri:attachment ri:filename=\"logo.png\"/></ac:image> and \
                   <ac:link><ri:user ri:userkey=\"8a7f808a1\"/></ac:link>.</p>";
    let users = UserResolutions::from([("8a7f808a1".to_owned(), None)]);
    let (released, _, _) = storage_to_markdown(storage, &users);
    let env = h.submit(UPDATE, update(&released, None)).await;
    assert_rejected(&h, &env, "markdown_placeholders").await?;
    assert_eq!(
        detail(&env, "placeholders"),
        json!([
            {"kind": "link", "count": 1},
            {"kind": "image", "count": 1},
            {"kind": "macro", "count": 1},
            {"kind": "user", "count": 1},
        ]),
        "{released}"
    );
    assert_eq!(hits(mock).await, before, "no wiremock hit");
    // Escaped look-alikes are prose and pass.
    let env = h
        .submit(
            UPDATE,
            update("\\@user:abc and \\[macro: toc {}] in text", None),
        )
        .await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn placeholder_check_runs_before_conversion() -> TestResult {
    let h = faulty(ConverterFault::RiUser).await?;
    let mock = wiki(&h)?;
    let before = hits(mock).await;
    let env = h
        .submit(UPDATE, update("plain text with @user:8a7f808a1", None))
        .await;
    // A placeholder answers before the conversion (and its injected fault) runs.
    assert_rejected(&h, &env, "markdown_placeholders").await?;
    assert_eq!(
        detail(&env, "placeholders"),
        json!([{"kind": "user", "count": 1}])
    );
    assert_eq!(hits(mock).await, before, "no wiremock hit");
    // Without a placeholder the same harness reaches the hard check.
    let env = h.submit(UPDATE, update("plain text", None)).await;
    assert_rejected(&h, &env, "validation").await?;
    assert_eq!(detail(&env, "construct"), json!("mention"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u24_storage_injected_fault_fails_validation_exit2() -> TestResult {
    for (fault, construct) in [
        (ConverterFault::RiUser, "mention"),
        (ConverterFault::IncludeMacro, "include"),
        (ConverterFault::AcLink, "link"),
    ] {
        let h = faulty(fault).await?;
        let mock = wiki(&h)?;
        page_server(mock).await;
        let before = hits(mock).await;
        let env = h.submit(UPDATE, update(MARKDOWN, None)).await;
        assert_rejected(&h, &env, "validation").await?;
        assert_eq!(detail(&env, "param"), json!("body"), "{construct}");
        assert_eq!(detail(&env, "construct"), json!(construct));
        assert_eq!(detail(&env, "count"), json!(1));
        assert_eq!(
            message(&env),
            format!("markdown conversion produced an unrecorded {construct}")
        );
        // The error carries the kind, never the body or the injected text.
        let line = env.to_json_line();
        assert!(
            !line.contains("Release") && !line.contains("injected") && !line.contains("Injected"),
            "{line}"
        );
        assert_eq!(hits(mock).await, before, "no wiremock hit");
        // The fault touches only converted text: a storage body is verbatim and still passes.
        let env = h
            .submit(UPDATE, update("<p>plain</p>", Some("storage")))
            .await;
        assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jira_fault_on_confluence_body_is_inert() -> TestResult {
    // A Jira variant on a Confluence Markdown body: nothing is appended, the body is accepted
    // and sent as the converter wrote it.
    for fault in [
        ConverterFault::Mention,
        ConverterFault::Include,
        ConverterFault::Html,
    ] {
        let h = faulty(fault).await?;
        let mock = wiki(&h)?;
        page_server(mock).await;
        let id = approved(&h, UPDATE, update(MARKDOWN, None)).await?;
        let body = sent_body(&h, mock, &id).await?;
        let value = body["body"]["storage"]["value"].as_str().unwrap_or("");
        assert_eq!(value, markdown_to_storage(MARKDOWN).0, "{fault:?}");
        assert!(!value.contains(fault.text()), "{fault:?}");
    }
    // A storage variant on a Jira Markdown body: accepted, the wiki text as converted.
    for fault in [
        ConverterFault::RiUser,
        ConverterFault::IncludeMacro,
        ConverterFault::AcLink,
    ] {
        let h = Harness::builder()
            .jira("jira-main")
            .hooks(TestHooks {
                converter_fault: Some(fault),
                ..TestHooks::none()
            })
            .start()
            .await?;
        let mock = jira(&h)?;
        mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
            .await;
        Mock::given(method("POST"))
            .and(path(mock.path("/rest/api/2/issue/ABC-1/comment")))
            .respond_with(
                mock.response(201)
                    .set_body_raw(fixtures::JIRA_COMMENT, "application/json"),
            )
            .mount(mock.server())
            .await;
        let md = "**bold** and `code`";
        let id = approved(
            &h,
            "jira.comment.add",
            json!({ "key": "ABC-1", "body": md }),
        )
        .await?;
        let body = sent_body(&h, mock, &id).await?;
        assert_eq!(body["body"], json!(markdown_to_wiki(md).0), "{fault:?}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn storage_body_format_is_verbatim() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    page_server(mock).await;
    let storage = "<ac:structured-macro ac:name=\"toc\"/>";
    let id = approved(&h, UPDATE, update(storage, Some("storage"))).await?;
    // Verbatim: no conversion, no placeholder check, no hard check.
    assert_eq!(
        sent_body(&h, mock, &id).await?["body"]["storage"]["value"],
        json!(storage)
    );
    // Placeholder look-alikes in a storage body are the agent's storage, not placeholders.
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    page_server(mock).await;
    let storage = "<p>[macro: toc {}] @user:abc</p>";
    let id = approved(&h, UPDATE, update(storage, Some("storage"))).await?;
    assert_eq!(
        sent_body(&h, mock, &id).await?["body"]["storage"]["value"],
        json!(storage)
    );
    Ok(())
}

/// Each storage body is refused at validation with `details.storage == reason`.
async fn assert_storage_rejected(cases: &[(&str, &str)]) -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    page_server(mock).await;
    let before = hits(mock).await;
    for (body, reason) in cases {
        let env = h.submit(UPDATE, update(body, Some("storage"))).await;
        assert_rejected(&h, &env, "validation").await?;
        assert_eq!(detail(&env, "param"), json!("body"), "{body}");
        assert_eq!(detail(&env, "storage"), json!(reason), "{body}");
        assert_eq!(message(&env), format!("storage body rejected: {reason}"));
        // The reason only: the body is never echoed.
        assert!(!env.to_json_line().contains("secret"), "{body}");
    }
    assert_eq!(hits(mock).await, before, "no wiremock hit");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn storage_body_doctype_entity_pi_rejected_exit2() -> TestResult {
    assert_storage_rejected(&[
        (
            "<!DOCTYPE x [<!ENTITY e \"<ri:user ri:userkey='secret'/>\">]><p>&e;</p>",
            "doctype",
        ),
        ("<!ENTITY e \"secret\"><p>&e;</p>", "entity_decl"),
        ("<p>secret</p><?x ?>", "processing_instruction"),
    ])
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn storage_body_xmlns_rejected_exit2() -> TestResult {
    assert_storage_rejected(&[
        (
            "<zz:structured-macro xmlns:zz=\"http://atlassian.com/content\" zz:name=\"include\"/>",
            "namespace_decl",
        ),
        ("<p>secret</p><at:var/>", "unknown_prefix"),
    ])
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn storage_body_unparsable_rejected_exit2() -> TestResult {
    assert_storage_rejected(&[
        ("<p>a<b>secret</p>", "not_well_formed"),
        (
            &format!("{}secret{}", "<div>".repeat(100), "</div>".repeat(100)),
            "too_deep",
        ),
    ])
    .await
}

/// T6 review: Markdown that nests deeper than the storage parser's 64 levels makes the hard check
/// fail closed (`Markup`); validation names the nesting, not a converter fault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn markdown_nesting_too_deep_rejected_exit2() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    page_server(mock).await;
    let before = hits(mock).await;
    let deep = format!("{} secret\n", ">".repeat(100));
    for format in [None, Some("markdown")] {
        let env = h.submit(UPDATE, update(&deep, format)).await;
        assert_rejected(&h, &env, "validation").await?;
        assert_eq!(detail(&env, "param"), json!("body"));
        assert_eq!(detail(&env, "storage"), json!("too_deep"));
        assert_eq!(detail(&env, "construct"), Value::Null);
        assert_eq!(
            message(&env),
            "the Markdown nests deeper than Confluence storage allows (64 levels)"
        );
        assert!(!env.to_json_line().contains("secret"));
    }
    assert_eq!(hits(mock).await, before, "no wiremock hit");
    // 20 levels convert and pass.
    let env = h
        .submit(UPDATE, update(&format!("{} ok\n", ">".repeat(20)), None))
        .await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    Ok(())
}
