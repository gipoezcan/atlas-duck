#![cfg(feature = "testing")]
//! Confluence reads in M7. Task 10: `format` on `confluence.page.get` and on
//! `confluence.page.history` with `version` (PD-100, §7.4): `markdown` (the default) expands
//! `body.storage`, converts it with the committed `user_resolutions` map and replaces `body` with
//! `{"format": "markdown", "value": …}`, releasing `meta.conversion`; `storage` releases the body
//! as sent; `view` expands `body.view` instead. The history summary ignores `format`.
//!
//! Task 11 (PD-99, §7.6, I-37): the user keys of a Markdown body are resolved before its
//! `READ_FETCHED` from the per-instance cache and, for misses, by sequential
//! `GET /rest/api/user?key=` lookups under the request's cover (`PREVIEW_FETCH {purpose:
//! resolve}`); the map is committed in `READ_FETCHED` and is the only one a rebuild uses.
//!
//! Task 12a (PD-101, PD-102, §13 U-28, U-31): `confluence.search` releases only the §7.4 keys,
//! previews as a table under the effective CQL, and raises the Info `cql_broad`.
//!
//! Every read here also ends with the identity GET of Task 13 (PD-93, `PREVIEW_FETCH {purpose:
//! identity}` after the lookups; the harness answers it as the stored user). Its own cases are in
//! `confluence_identity.rs`.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use atlas_duck_atlassian::ReadBudget;
use atlas_duck_atlassian::testing::{MockDc, TEST_PAT, TEST_USER, TEST_USER_KEY, UserKind};
use atlas_duck_audit::EventType;
use atlas_duck_core::engine::cache::RebuildError;
use atlas_duck_core::engine::cancel::{CancelCause, ShutdownReason};
use atlas_duck_core::engine::queue::{Limits, MIB};
use atlas_duck_core::engine::read::normalize;
use atlas_duck_core::testing::Harness;
use atlas_duck_core::{Confirm, Pause, TestHooks};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_preview::{OutcomeKind, PreviewBody};
use common::confluence::{
    PAGE_EXPAND_STORAGE, PAGE_EXPAND_VIEW, amplified_storage, content_path, fetched_payload,
    mount_history_summary, mount_history_version, mount_page, mount_page_delayed, mount_page_view,
    mount_search, mount_user_answer, mount_users, mount_users_delayed, page_with_storage,
    page_with_view, search_gets, user, user_gets,
};
use common::jira::{gets_on, query};
use common::{TestError, TestResult, code, de, exit, request_id, test_hits};
use secrecy::SecretString;
use serde_json::{Map, Value, json};

const PAGE_GET: &str = "confluence.page.get";
const PAGE_HISTORY: &str = "confluence.page.history";
const ID: &str = "65537";
/// The identity GET that ends every Confluence read (PD-93, Task 13; `confluence_identity.rs`).
const IDENTITY_PATH: &str = "/rest/api/user/current";

/// A page body with one `info` macro (one lost macro) and plain prose.
const INFO_STORAGE: &str = r#"<p>Check the build.</p><ac:structured-macro ac:name="info"><ac:rich-text-body><p>Read me first.</p></ac:rich-text-body></ac:structured-macro>"#;

/// A page body with a mention (`ri:userkey`) and a link to another page.
const MENTION_STORAGE: &str = r#"<p>Owner <ac:link><ri:user ri:userkey="8a7f808a1"/></ac:link>, see <ac:link><ri:page ri:content-title="Release plan"/></ac:link>.</p><ac:structured-macro ac:name="toc"/>"#;

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no wiki mock".into())
}

/// Submits, expects `pending`, and waits until the read waits for release.
async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    Ok(id)
}

/// Releases `id` and returns the released envelope.
async fn released(h: &Harness, id: &str) -> Result<Envelope, TestError> {
    h.approver().release(id).map_err(de)?;
    let env = h.await_(id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    Ok(env)
}

fn result_of(env: &Envelope) -> Result<Value, TestError> {
    Ok(env.data.clone().ok_or("no data")?["result"].clone())
}

fn meta_of(env: &Envelope) -> Result<Value, TestError> {
    Ok(env.meta.clone().ok_or("no meta")?)
}

/// The one `READ_FETCHED` payload of `id`.
async fn read_fetched(h: &Harness, id: &str) -> Result<Value, TestError> {
    let fetched: Vec<Value> = h
        .events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == EventType::READ_FETCHED)
        .map(|(_, p)| p)
        .collect();
    match fetched.as_slice() {
        [f] => Ok(f.clone()),
        other => Err(format!("{} READ_FETCHED records", other.len()).into()),
    }
}

/// What the converter makes of `storage` with an empty map (Task 10: no lookups yet).
fn markdown_of(storage: &str) -> String {
    atlas_duck_convert::storage_to_markdown(storage, &BTreeMap::new()).0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_get_markdown_replaces_body_and_reports_conversion() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let page = page_with_storage(INFO_STORAGE);
    mount_page(mock, ID, &page).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    let env = released(&h, &id).await?;
    let result = result_of(&env)?;
    let markdown = markdown_of(INFO_STORAGE);
    assert!(markdown.contains("[macro: info {}]"), "{markdown}");
    assert!(markdown.contains("Check the build."), "{markdown}");
    assert_eq!(
        result["body"],
        json!({ "format": "markdown", "value": markdown })
    );
    // Everything but `body` as Confluence sent it.
    let mut rest = result.clone();
    let mut sent = page.clone();
    for v in [&mut rest, &mut sent] {
        if let Some(o) = v.as_object_mut() {
            o.remove("body");
        }
    }
    assert_eq!(rest, sent);
    assert_eq!(
        meta_of(&env)?["conversion"],
        json!({ "lossy": true, "lost": { "macros": 1, "images": 0, "links": 0, "layouts": 0 } })
    );
    let gets = gets_on(mock, &content_path(ID)).await;
    let [only] = gets.as_slice() else {
        return Err(format!("{} content GETs", gets.len()).into());
    };
    assert_eq!(query(only, "expand").as_deref(), Some(PAGE_EXPAND_STORAGE));
    // Nothing else was sent but the identity GET that ends every Confluence read (PD-93).
    let hits: Vec<String> = test_hits(mock)
        .await
        .iter()
        .map(|r| r.url.path().to_owned())
        .collect();
    assert_eq!(
        hits,
        [mock.path(&content_path(ID)), mock.path(IDENTITY_PATH)]
    );

    // `format: markdown` given explicitly is the same read.
    let id = queued(&h, PAGE_GET, json!({ "id": ID, "format": "markdown" })).await?;
    let env = released(&h, &id).await?;
    assert_eq!(result_of(&env)?, result);
    assert_eq!(meta_of(&env)?["conversion"]["lost"]["macros"], 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_get_storage_releases_storage() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let page = page_with_storage(INFO_STORAGE);
    mount_page(mock, ID, &page).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID, "format": "storage" })).await?;
    let env = released(&h, &id).await?;
    assert_eq!(result_of(&env)?, page);
    assert!(meta_of(&env)?.get("conversion").is_none(), "{:?}", env.meta);
    let gets = gets_on(mock, &content_path(ID)).await;
    assert_eq!(
        gets.iter().map(|r| query(r, "expand")).collect::<Vec<_>>(),
        [Some(PAGE_EXPAND_STORAGE.to_owned())]
    );
    // PD-99: a storage read resolves nothing, so it commits no map.
    assert!(
        read_fetched(&h, &id)
            .await?
            .get("user_resolutions")
            .is_none()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_get_view_expands_body_view() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let page = page_with_view("<p>Rendered <b>by the server</b>.</p>");
    mount_page_view(mock, ID, &page).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID, "format": "view" })).await?;
    let env = released(&h, &id).await?;
    let result = result_of(&env)?;
    assert_eq!(result, page);
    assert_eq!(result["body"]["view"], page["body"]["view"], "as sent");
    assert!(meta_of(&env)?.get("conversion").is_none(), "{:?}", env.meta);
    let gets = gets_on(mock, &content_path(ID)).await;
    let [only] = gets.as_slice() else {
        return Err(format!("{} content GETs", gets.len()).into());
    };
    assert_eq!(query(only, "expand").as_deref(), Some(PAGE_EXPAND_VIEW));
    assert!(
        read_fetched(&h, &id)
            .await?
            .get("user_resolutions")
            .is_none()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_history_version_markdown() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let mut old = page_with_storage(INFO_STORAGE);
    old["version"]["number"] = json!(2);
    old["status"] = json!("historical");
    mount_history_version(mock, ID, 2, &old).await;
    let id = queued(&h, PAGE_HISTORY, json!({ "id": ID, "version": 2 })).await?;
    let env = released(&h, &id).await?;
    let result = result_of(&env)?;
    assert_eq!(
        result["body"],
        json!({ "format": "markdown", "value": markdown_of(INFO_STORAGE) })
    );
    assert_eq!(result["version"]["number"], 2);
    assert_eq!(
        meta_of(&env)?["conversion"],
        json!({ "lossy": true, "lost": { "macros": 1, "images": 0, "links": 0, "layouts": 0 } })
    );
    let gets = gets_on(mock, &content_path(ID)).await;
    let [only] = gets.as_slice() else {
        return Err(format!("{} content GETs", gets.len()).into());
    };
    assert_eq!(query(only, "version").as_deref(), Some("2"));
    assert_eq!(query(only, "status").as_deref(), Some("historical"));
    assert_eq!(
        query(only, "expand").as_deref(),
        Some("body.storage,version")
    );
    assert!(read_fetched(&h, &id).await?["user_resolutions"].is_object());

    // The other two formats apply to the historical body too: `view` swaps the expand, and
    // neither converts.
    for (format, expand) in [
        ("view", "body.view,version"),
        ("storage", "body.storage,version"),
    ] {
        let id = queued(
            &h,
            PAGE_HISTORY,
            json!({ "id": ID, "version": 2, "format": format }),
        )
        .await?;
        let env = released(&h, &id).await?;
        assert_eq!(result_of(&env)?, old, "{format}");
        assert!(meta_of(&env)?.get("conversion").is_none(), "{format}");
        let gets = gets_on(mock, &content_path(ID)).await;
        let last = gets.last().ok_or("no GET")?;
        assert_eq!(query(last, "expand").as_deref(), Some(expand), "{format}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_history_summary_ignores_format() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let summary: Value = atlas_duck_registry::get(PAGE_HISTORY)
        .ok_or("no registry op")?
        .result_example_json();
    mount_history_summary(mock, ID, &summary).await;
    let history = format!("{}/history", content_path(ID));
    for (n, format) in [None, Some("view"), Some("markdown"), Some("storage")]
        .into_iter()
        .enumerate()
    {
        let params = match format {
            Some(f) => json!({ "id": ID, "format": f }),
            None => json!({ "id": ID }),
        };
        let id = queued(&h, PAGE_HISTORY, params).await?;
        let env = released(&h, &id).await?;
        assert_eq!(result_of(&env)?, summary, "{format:?}: the summary as sent");
        assert!(meta_of(&env)?.get("conversion").is_none(), "{format:?}");
        assert!(
            read_fetched(&h, &id)
                .await?
                .get("user_resolutions")
                .is_none(),
            "{format:?}"
        );
        let gets = gets_on(mock, &history).await;
        assert_eq!(gets.len(), n + 1);
        let last = gets.last().ok_or("no GET")?;
        assert_eq!(
            query(last, "expand").as_deref(),
            Some("lastUpdated,previousVersion,contributors.publishers"),
            "{format:?}"
        );
    }
    assert!(gets_on(mock, &content_path(ID)).await.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn markdown_candidate_rebuild_hash_stable() -> TestResult {
    // A cache smaller than any candidate: every preview and the release rebuild from the record.
    let h = Harness::builder()
        .confluence("wiki")
        .limits(Limits {
            candidate_cache_bytes: MIB / 1024,
            ..Limits::default()
        })
        .start()
        .await?;
    let mock = wiki(&h)?;
    let mut page = page_with_storage(MENTION_STORAGE);
    // Big enough to be over the cache's cap.
    page["title"] = json!("x".repeat(2048));
    mount_page(mock, ID, &page).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    let rev = h.approver().item(&id).ok_or("not queued")?.candidate_rev;
    assert!(!h.engine().candidates().contains(&id));
    let hits = test_hits(mock).await.len();
    let first = h.approver().open(&id).map_err(de)?.preview;
    h.evict_candidate(&id);
    let again = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(
        test_hits(mock).await.len(),
        hits,
        "a rebuild makes no network call"
    );
    assert_eq!(first.candidate_rev.candidate_hash, rev.candidate_hash);
    assert_eq!(again.candidate_rev.candidate_hash, rev.candidate_hash);
    assert!(again.approvable, "the rebuilt candidate matches its hash");
    let env = released(&h, &id).await?;
    let value = result_of(&env)?["body"]["value"]
        .as_str()
        .ok_or("no Markdown value")?
        .to_owned();
    assert_eq!(value, markdown_of(MENTION_STORAGE));
    // The mock knows no such user (Task 11: the lookup answered 404): the mention is its key.
    assert!(value.contains("@user:8a7f808a1"), "{value}");
    assert_eq!(
        meta_of(&env)?["conversion"],
        json!({ "lossy": true, "lost": { "macros": 1, "images": 0, "links": 2, "layouts": 0 } })
    );
    assert_eq!(test_hits(mock).await.len(), hits);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_fetched_carries_user_resolutions() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(MENTION_STORAGE)).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    let fetched = read_fetched(&h, &id).await?;
    // Committed before the candidate hash (§5.2 steps 3–4). Task 11: the one key was looked up;
    // the mock knows no such user (an unmounted path), so it is unresolved.
    assert_eq!(fetched["user_resolutions"], json!({ "8a7f808a1": null }));
    assert_eq!(fetched["pages"], 1);
    // A page without mentions commits an empty map.
    mount_page(mock, "65538", &page_with_storage(INFO_STORAGE)).await;
    let id = queued(&h, PAGE_GET, json!({ "id": "65538" })).await?;
    assert_eq!(read_fetched(&h, &id).await?["user_resolutions"], json!({}));
    Ok(())
}

/// A content answer without `body.storage` (e.g. an id that is not a page) is released as
/// sent, without `meta.conversion` (no failure).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn markdown_without_storage_body_releases_raw() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let mut content = page_with_storage("");
    if let Some(o) = content.as_object_mut() {
        o.remove("body");
    }
    content["type"] = json!("attachment");
    mount_page(mock, ID, &content).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    let env = released(&h, &id).await?;
    assert_eq!(result_of(&env)?, content);
    assert!(meta_of(&env)?.get("conversion").is_none(), "{:?}", env.meta);
    Ok(())
}

// ---- Task 10 fix round ---------------------------------------------------------------------------

/// T10 review I-1: the normalization converts with the payload's committed map and nothing else,
/// and a Markdown record without a usable map is malformed (fail closed).
#[test]
fn normalize_converts_with_the_committed_map_only() -> TestResult {
    let spec = atlas_duck_registry::get(PAGE_GET).ok_or("no registry op")?;
    let page = page_with_storage(MENTION_STORAGE);
    let params = json!({ "id": ID });
    let markdown = |key: &str, name: Option<&str>| {
        let users = BTreeMap::from([(key.to_owned(), name.map(str::to_owned))]);
        atlas_duck_convert::storage_to_markdown(MENTION_STORAGE, &users).0
    };
    // (a) A resolved user in the map is the mention, so the payload's map is the one used.
    let users = json!({ "8a7f808a1": "jdoe" });
    let body = normalize(spec, &params, &fetched_payload(&page, Some(users)))
        .map_err(|e| format!("{e:?}"))?;
    let expected = markdown("8a7f808a1", Some("jdoe"));
    assert!(expected.contains("@jdoe"), "{expected}");
    assert_eq!(
        body["body"],
        json!({ "format": "markdown", "value": expected })
    );
    // `null` is an unresolved user: the mention is its key.
    let body = normalize(
        spec,
        &params,
        &fetched_payload(&page, Some(json!({ "8a7f808a1": null }))),
    )
    .map_err(|e| format!("{e:?}"))?;
    assert_eq!(body["body"]["value"], markdown("8a7f808a1", None));
    // (b) no map, (c) a value that is neither a string nor null, (d) a map that is no object.
    for users in [
        None,
        Some(json!({ "8a7f808a1": 7 })),
        Some(json!({ "8a7f808a1": ["jdoe"] })),
        Some(json!([])),
        Some(json!("jdoe")),
    ] {
        let got = normalize(spec, &params, &fetched_payload(&page, users.clone()));
        assert!(
            matches!(got, Err(RebuildError::Malformed)),
            "{users:?}: {got:?}"
        );
    }
    // (e) `format: storage` converts nothing and needs no map.
    let body = normalize(
        spec,
        &json!({ "id": ID, "format": "storage" }),
        &fetched_payload(&page, None),
    )
    .map_err(|e| format!("{e:?}"))?;
    assert_eq!(body, page);
    // T10 review B-1: the conversion is held to the release cap; a record whose Markdown would
    // pass it cannot be a committed candidate (the first build committed the outcome instead).
    let big = page_with_storage(&amplified_storage(170_000));
    let got = normalize(spec, &params, &fetched_payload(&big, Some(json!({}))));
    assert!(
        matches!(got, Err(RebuildError::Malformed)),
        "{:?}",
        got.map(|_| "a body")
    );
    Ok(())
}

/// T10 review B-1: the crafted table that made `htmd` pad 50 000 rows to a 64 KiB header (about
/// 3 GiB) converts unpadded and is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wide_cell_table_page_is_released_unpadded() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let storage = format!(
        "<table><tbody><tr><th>{}</th></tr>{}</tbody></table>",
        "w".repeat(64 * 1024),
        "<tr><td>x</td></tr>".repeat(50_000)
    );
    mount_page(mock, ID, &page_with_storage(&storage)).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    let env = released(&h, &id).await?;
    let value = result_of(&env)?["body"]["value"]
        .as_str()
        .ok_or("no Markdown value")?
        .to_owned();
    assert!(value.len() < storage.len(), "{}", value.len());
    assert_eq!(value.lines().count(), 50_002);
    assert_eq!(value.lines().nth(1), Some("| --- |"));
    assert!(value.lines().skip(2).all(|l| l == "| x |"), "unpadded rows");
    Ok(())
}

/// T10 review I-3: `meta.conversion` is released with every Markdown body, a lossless one
/// included, and carries the report's counts one for one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn meta_conversion_counts_are_the_reports() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let plain = "<p>Plain <strong>prose</strong> only.</p>";
    let image_layout = r#"<ac:layout><ac:layout-section ac:type="single"><ac:layout-cell><p>Look: <ac:image><ri:attachment ri:filename="a.png"/></ac:image></p></ac:layout-cell></ac:layout-section></ac:layout>"#;
    for (id, storage, conversion) in [
        (
            "65538",
            plain,
            json!({ "lossy": false, "lost": { "macros": 0, "images": 0, "links": 0, "layouts": 0 } }),
        ),
        (
            "65539",
            image_layout,
            json!({ "lossy": true, "lost": { "macros": 0, "images": 1, "links": 0, "layouts": 1 } }),
        ),
    ] {
        mount_page(mock, id, &page_with_storage(storage)).await;
        let rid = queued(&h, PAGE_GET, json!({ "id": id })).await?;
        let env = released(&h, &rid).await?;
        assert_eq!(meta_of(&env)?["conversion"], conversion, "{storage}");
        assert_eq!(result_of(&env)?["body"]["value"], markdown_of(storage));
    }
    Ok(())
}

/// T10 review B-1: a page whose Markdown would pass the 16 MiB release cap stops converting there
/// and becomes the release-cap outcome item (no candidate past the cap is built, the process
/// lives), committed without a map; a page under the cap converts as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn markdown_over_the_release_cap_is_the_outcome_item() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let storage = amplified_storage(170_000);
    assert!(storage.len() < 512 * 1024);
    let full = markdown_of(&storage);
    assert!(full.len() > 16 * 1024 * 1024, "{}", full.len());
    drop(full);
    mount_page(mock, ID, &page_with_storage(&storage)).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    match &preview.body {
        PreviewBody::Outcome { outcome, .. } => assert_eq!(*outcome, OutcomeKind::ReleaseCap16),
        other => return Err(format!("not an outcome card: {other:?}").into()),
    }
    assert!(preview.raw.total_bytes < 1024);
    let fetched = read_fetched(&h, &id).await?;
    assert_eq!(fetched["outcome"], "too_large");
    assert_eq!(fetched["cap_or_budget"], "release_cap_16mib");
    assert!(fetched.get("user_resolutions").is_none(), "{fetched}");
    h.approver().release_unopened(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "result_too_large");
    assert_eq!(env.meta, None);

    // The same shape under the cap is a released Markdown body.
    let small = amplified_storage(1_000);
    mount_page(mock, "65540", &page_with_storage(&small)).await;
    let id = queued(&h, PAGE_GET, json!({ "id": "65540" })).await?;
    let env = released(&h, &id).await?;
    assert_eq!(result_of(&env)?["body"]["value"], markdown_of(&small));
    Ok(())
}

/// T10 review m-7: a span masked in the Markdown body is released masked; the redacted revision
/// is rebuilt from the record (converted again with its committed map) and keeps
/// `meta.conversion`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn markdown_body_redaction_rebuilds_and_releases_masked() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(INFO_STORAGE)).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    let ap = h.approver();
    ap.open(&id).map_err(de)?;
    let mask = atlas_duck_core::RedactionOp::MaskText {
        text: "Read me first".into(),
        every_occurrence: true,
        at: None,
    };
    ap.redact(&id, vec![mask]).map_err(de)?;
    ap.open(&id).map_err(de)?;
    h.evict_candidate(&id);
    let env = released(&h, &id).await?;
    assert!(env.redacted);
    let value = result_of(&env)?["body"]["value"]
        .as_str()
        .ok_or("no Markdown value")?
        .to_owned();
    assert!(!value.contains("Read me first"), "{value}");
    assert!(value.contains("Check the build."), "{value}");
    let meta = meta_of(&env)?;
    assert!(
        meta["redactions"]["spans_masked"].as_u64() >= Some(1),
        "{meta}"
    );
    assert_eq!(meta["conversion"]["lost"]["macros"], 1);
    Ok(())
}

/// T10 review m-5: a Markdown read the server answers with an error commits no map.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn markdown_upstream_error_commits_no_map() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mock.json(
        &content_path("404404"),
        404,
        r#"{"statusCode":404,"message":"No content found with id: 404404"}"#,
    )
    .await;
    let env = h.submit(PAGE_GET, json!({ "id": "404404" })).await;
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let fetched = read_fetched(&h, &id).await?;
    assert_eq!(fetched["upstream_error"], true, "{fetched}");
    assert!(fetched.get("user_resolutions").is_none(), "{fetched}");
    Ok(())
}

// ---- Task 11: user resolution (PD-99, I-37) -------------------------------------------------------

/// Two mentions by user key; sorted, `key-asmith` is looked up first.
const TWO_USERS_STORAGE: &str = r#"<p>Owners <ac:link><ri:user ri:userkey="key-jdoe"/></ac:link> and <ac:link><ri:user ri:userkey="key-asmith"/></ac:link>.</p>"#;
const JDOE: (&str, Option<&str>) = ("key-jdoe", Some("jdoe"));
const ASMITH: (&str, Option<&str>) = ("key-asmith", Some("asmith"));

/// What the converter makes of `storage` with `users` as the map.
fn markdown_with(storage: &str, users: &[(&str, Option<&str>)]) -> String {
    let map = users
        .iter()
        .map(|(k, n)| ((*k).to_owned(), n.map(str::to_owned)))
        .collect();
    atlas_duck_convert::storage_to_markdown(storage, &map).0
}

/// The payloads of `id`'s records of type `t`, in order.
async fn records(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

/// The user lookups' `PREVIEW_FETCH {purpose: resolve}` records of `id`, in order (the read's
/// identity GET, PD-93, has its own `PREVIEW_FETCH {purpose: identity}` after them).
async fn resolves(h: &Harness, id: &str) -> Result<Vec<Value>, TestError> {
    let mut fetches = records(h, id, EventType::PREVIEW_FETCH).await?;
    fetches.retain(|f| f["purpose"] == "resolve");
    Ok(fetches)
}

/// The record types of a read whose lookups recorded `lookups` records: the identity GET's record
/// comes after them, before `READ_FETCHED` (PD-93).
fn checked_read(lookups: usize) -> Vec<EventType> {
    let mut want = vec![EventType::REQUEST_RECEIVED];
    want.extend((0..=lookups).map(|_| EventType::PREVIEW_FETCH));
    want.push(EventType::READ_FETCHED);
    want
}

/// The `key` query values of the user lookups the mock received, in order.
async fn looked_up(mock: &MockDc) -> Vec<String> {
    user_gets(mock)
        .await
        .iter()
        .filter_map(|r| query(r, "key"))
        .collect()
}

/// Polls until the mock received `n` user lookups.
async fn wait_lookups(mock: &MockDc, n: usize) -> TestResult {
    for _ in 0..2000 {
        if user_gets(mock).await.len() >= n {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("never {n} user lookups").into())
}

fn released_value(env: &Envelope) -> Result<String, TestError> {
    Ok(result_of(env)?["body"]["value"]
        .as_str()
        .ok_or("no Markdown value")?
        .to_owned())
}

/// The read's `ConversionReport.unresolved_users` (the preview's Info `unresolved_mention`
/// reads it, Task 12b).
fn unresolved_users(h: &Harness, id: &str) -> Option<u64> {
    let entry = h.engine().entry(id)?;
    let st = entry.state();
    st.read
        .as_ref()
        .and_then(|r| r.conversion.as_ref())
        .map(|c| c.unresolved_users)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resolve_gets_are_preview_fetch_resolve_under_request() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(TWO_USERS_STORAGE)).await;
    mount_users(mock, &[JDOE, ASMITH]).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(looked_up(mock).await, ["key-asmith", "key-jdoe"]);
    // Every lookup after the request's `REQUEST_RECEIVED` (its cover) and recorded before the
    // read's `READ_FETCHED`, ahead of the identity GET's record (PD-93).
    assert_eq!(h.event_types(&id).await?, checked_read(2));
    let fetches = records(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(fetches.len(), 3);
    assert_eq!(fetches[2]["purpose"], "identity", "{}", fetches[2]);
    for (f, key) in fetches.iter().zip(["key-asmith", "key-jdoe"]) {
        assert_eq!(f["purpose"], "resolve", "{f}");
        assert_eq!(f["method"], "GET");
        assert_eq!(f["path"], format!("/wiki/rest/api/user?key={key}"));
        assert_eq!(f["status"], 200);
        assert!(f["response"].to_string().contains(key), "{f}");
    }
    let env = released(&h, &id).await?;
    let value = released_value(&env)?;
    assert!(
        value.contains("@jdoe") && value.contains("@asmith"),
        "{value}"
    );
    assert_eq!(value, markdown_with(TWO_USERS_STORAGE, &[JDOE, ASMITH]));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_resolutions_committed_in_read_fetched() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(TWO_USERS_STORAGE)).await;
    mount_users(mock, &[JDOE, ASMITH]).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(
        read_fetched(&h, &id).await?["user_resolutions"],
        json!({ "key-jdoe": "jdoe", "key-asmith": "asmith" })
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_hits_need_no_lookup() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(TWO_USERS_STORAGE)).await;
    mount_users(mock, &[JDOE, ASMITH]).await;
    queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(user_gets(mock).await.len(), 2);
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(
        user_gets(mock).await.len(),
        2,
        "the second read looks nobody up"
    );
    assert_eq!(h.event_types(&id).await?, checked_read(0));
    // The map still lists every key of the body (cache hits included).
    assert_eq!(
        read_fetched(&h, &id).await?["user_resolutions"],
        json!({ "key-jdoe": "jdoe", "key-asmith": "asmith" })
    );
    let env = released(&h, &id).await?;
    assert_eq!(
        released_value(&env)?,
        markdown_with(TWO_USERS_STORAGE, &[JDOE, ASMITH])
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unresolvable_user_is_null_and_info() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let storage = r#"<p>Ask <ri:user ri:userkey="key-gone"/>.</p>"#;
    mount_page(mock, ID, &page_with_storage(storage)).await;
    mount_users(mock, &[("key-gone", None)]).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    let fetch = resolves(&h, &id).await?;
    assert_eq!(fetch.len(), 1);
    assert_eq!(fetch[0]["status"], 404);
    assert_eq!(
        read_fetched(&h, &id).await?["user_resolutions"],
        json!({ "key-gone": null })
    );
    // The preview's Info `unresolved_mention` counts it (Task 12b renders it).
    assert_eq!(unresolved_users(&h, &id), Some(1));
    let env = released(&h, &id).await?;
    let value = released_value(&env)?;
    assert!(value.contains("@user:key-gone"), "{value}");
    // A JSON 404 is a definitive answer: cached, so the next read looks nobody up.
    assert_eq!(h.user_cached("wiki", "key-gone"), Some(None));
    queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(user_gets(mock).await.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resolve_lookups_capped_per_read() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let keys: Vec<String> = (0..60).map(|n| format!("u{n:02}")).collect();
    let names: Vec<String> = (0..60).map(|n| format!("name{n:02}")).collect();
    let storage: String = keys
        .iter()
        .map(|k| format!(r#"<p><ri:user ri:userkey="{k}"/></p>"#))
        .collect();
    let users: Vec<(&str, Option<&str>)> = keys
        .iter()
        .zip(&names)
        .map(|(k, n)| (k.as_str(), Some(n.as_str())))
        .collect();
    mount_page(mock, ID, &page_with_storage(&storage)).await;
    mount_users(mock, &users).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(
        looked_up(mock).await,
        keys[..50],
        "exactly 50, in key order"
    );
    let map = read_fetched(&h, &id).await?["user_resolutions"].clone();
    let map = map.as_object().ok_or("no map")?;
    assert_eq!(map.len(), 60);
    for (n, key) in keys.iter().enumerate() {
        let want = if n < 50 { json!(names[n]) } else { Value::Null };
        assert_eq!(map.get(key.as_str()), Some(&want), "{key}");
    }
    assert_eq!(resolves(&h, &id).await?.len(), 50);
    assert_eq!(unresolved_users(&h, &id), Some(10));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i37_confluence_markdown_rebuild_from_committed_map() -> TestResult {
    // A cache smaller than any candidate: every preview and the release rebuild from the record.
    let h = Harness::builder()
        .confluence("wiki")
        .limits(Limits {
            candidate_cache_bytes: MIB / 1024,
            ..Limits::default()
        })
        .start()
        .await?;
    let mock = wiki(&h)?;
    assert!(h.user_cache_set("wiki", "key-jdoe", Some("jdoe")));
    assert!(h.user_cache_set("wiki", "key-asmith", Some("asmith")));
    let mut page = page_with_storage(TWO_USERS_STORAGE);
    page["title"] = json!("x".repeat(2048));
    mount_page(mock, ID, &page).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert!(
        user_gets(mock).await.is_empty(),
        "every mention a cache hit"
    );
    assert_eq!(
        read_fetched(&h, &id).await?["user_resolutions"],
        json!({ "key-jdoe": "jdoe", "key-asmith": "asmith" })
    );
    let rev = h.approver().item(&id).ok_or("not queued")?.candidate_rev;
    assert!(!h.engine().candidates().contains(&id));
    let hits = test_hits(mock).await.len();
    h.evict_candidate(&id);
    let again = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(test_hits(mock).await.len(), hits, "a rebuild makes no call");
    assert_eq!(again.candidate_rev.candidate_hash, rev.candidate_hash);
    assert!(again.approvable, "the rebuilt candidate matches its hash");
    let env = released(&h, &id).await?;
    assert_eq!(
        released_value(&env)?,
        markdown_with(TWO_USERS_STORAGE, &[JDOE, ASMITH])
    );
    assert_eq!(test_hits(mock).await.len(), hits);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i37_user_cache_change_does_not_change_hash() -> TestResult {
    let h = Harness::builder()
        .confluence("wiki")
        .limits(Limits {
            candidate_cache_bytes: MIB / 1024,
            ..Limits::default()
        })
        .start()
        .await?;
    let mock = wiki(&h)?;
    let mut page = page_with_storage(TWO_USERS_STORAGE);
    page["title"] = json!("x".repeat(2048));
    mount_page(mock, ID, &page).await;
    mount_users(mock, &[JDOE, ASMITH]).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    let rev = h.approver().item(&id).ok_or("not queued")?.candidate_rev;
    // After the fetch the cache learns another name for the same key.
    assert!(h.user_cache_set("wiki", "key-jdoe", Some("renamed")));
    h.evict_candidate(&id);
    let again = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(again.candidate_rev.candidate_hash, rev.candidate_hash);
    assert!(again.approvable);
    let env = released(&h, &id).await?;
    let value = released_value(&env)?;
    assert!(
        value.contains("@jdoe") && !value.contains("renamed"),
        "{value}"
    );
    // A new read takes the cache as it is now.
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    let env = released(&h, &id).await?;
    assert!(released_value(&env)?.contains("@renamed"));
    Ok(())
}

/// Mounts the two-user page with lookups that answer only after a long delay, submits the read
/// and waits until its first lookup is in flight.
async fn read_held_in_lookup(h: &Harness) -> Result<String, TestError> {
    let mock = wiki(h)?;
    mount_page(mock, ID, &page_with_storage(TWO_USERS_STORAGE)).await;
    mount_users_delayed(mock, &[JDOE, ASMITH], Duration::from_secs(30)).await;
    let env = h.submit(PAGE_GET, json!({ "id": ID })).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    wait_lookups(mock, 1).await?;
    // The GET has left; the answer is held by the mock.
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(id)
}

/// The records of a read cancelled during its first lookup, for `reason`.
async fn assert_cancelled_in_lookup(h: &Harness, id: &str, reason: &str) -> TestResult {
    assert_ended_in_lookup(h, id, reason, EventType::CANCELLED).await?;
    let cancelled = records(h, id, EventType::CANCELLED).await?;
    assert_eq!(
        cancelled.first().map(|c| c["reason"].clone()),
        Some(json!(reason))
    );
    Ok(())
}

/// The records of a read that ended (`terminal`) during its first lookup, for `reason`.
async fn assert_ended_in_lookup(
    h: &Harness,
    id: &str,
    reason: &str,
    terminal: EventType,
) -> TestResult {
    assert_eq!(
        h.event_types(id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::READ_FETCHED,
            terminal,
        ]
    );
    let fetch = records(h, id, EventType::PREVIEW_FETCH).await?;
    let f = fetch.first().ok_or("no PREVIEW_FETCH")?;
    assert_eq!(f["purpose"], "resolve", "{f}");
    assert_eq!(f["outcome"], "cancelled_in_flight");
    assert_eq!(f["reason"], reason);
    assert_eq!(f["path"], "/wiki/rest/api/user?key=key-asmith");
    // §5.2 step 3: every byte received, so the content page already received.
    let r = read_fetched(h, id).await?;
    assert_eq!(r["outcome"], "cancelled_in_flight", "{r}");
    assert_eq!(r["reason"], reason);
    assert_eq!(r["pages"], 1);
    let text = r.to_string();
    assert!(
        text.contains("key-asmith") && text.contains("Owners"),
        "{r}"
    );
    assert!(r["size"].as_u64() > Some(100), "{r}");
    Ok(())
}

fn same(id: &str, env: &Envelope) -> String {
    env.to_json_line().replace(id, "<id>")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_during_resolve_records_cancelled_in_flight() -> TestResult {
    let h = Harness::confluence().await?;
    let id = read_held_in_lookup(&h).await?;
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    assert_cancelled_in_lookup(&h, &id, "by_client").await?;
    // The second lookup never left.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(looked_up(wiki(&h)?).await, ["key-asmith"]);
    // The envelope is the one of a cancel in `AwaitingRelease`.
    mount_page(wiki(&h)?, "65538", &page_with_storage(INFO_STORAGE)).await;
    let other = queued(&h, PAGE_GET, json!({ "id": "65538" })).await?;
    let env2 = h.handler().cancel(&other).await;
    assert_eq!(same(&id, &env), same(&other, &env2));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quit_during_resolve_records_cancelled_in_flight() -> TestResult {
    let h = Harness::confluence().await?;
    let id = read_held_in_lookup(&h).await?;
    let env = h
        .engine()
        .cancel_and_wait(&id, CancelCause::Shutdown(ShutdownReason::AppQuit))
        .await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    assert_cancelled_in_lookup(&h, &id, "app_quit").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookups_are_sequential() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let storage = r#"<p><ri:user ri:userkey="k1"/> <ri:user ri:userkey="k2"/> <ri:user ri:userkey="k3"/></p>"#;
    mount_page(mock, ID, &page_with_storage(storage)).await;
    mount_users_delayed(
        mock,
        &[
            ("k1", Some("one")),
            ("k2", Some("two")),
            ("k3", Some("three")),
        ],
        Duration::from_millis(300),
    )
    .await;
    let env = h.submit(PAGE_GET, json!({ "id": ID })).await;
    let id = request_id(&env)?;
    let mut seen = 0;
    for _ in 0..2000 {
        // Hits first, then the committed records: a record committed in between only helps.
        let hits = user_gets(mock).await.len();
        let types = h.event_types(&id).await?;
        let committed = types
            .iter()
            .filter(|t| **t == EventType::PREVIEW_FETCH)
            .count();
        assert!(
            hits <= committed + 1,
            "{hits} lookups sent with {committed} recorded: two in flight"
        );
        seen = seen.max(hits);
        if types.contains(&EventType::READ_FETCHED) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(seen, 3);
    assert_eq!(looked_up(mock).await, ["k1", "k2", "k3"]);
    assert_eq!(resolves(&h, &id).await?.len(), 3);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookup_key_is_a_query_pair() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let long = "k".repeat(300);
    let storage = format!(
        r#"<p><ri:user ri:userkey="a&amp;b#c/d e"/> <ri:user ri:userkey="{long}"/> <ri:user ri:userkey="x&#127;y"/></p>"#
    );
    mount_page(mock, ID, &page_with_storage(&storage)).await;
    mount_users(mock, &[("a&b#c/d e", Some("odd"))]).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    let gets = user_gets(mock).await;
    let [only] = gets.as_slice() else {
        return Err(format!("{} lookups", gets.len()).into());
    };
    // A query pair, encoded by `build_url` (form encoding: the space is `+`); never in the path.
    assert_eq!(only.url.query(), Some("key=a%26b%23c%2Fd+e"));
    assert_eq!(only.url.path(), "/wiki/rest/api/user");
    assert_eq!(query(only, "key").as_deref(), Some("a&b#c/d e"));
    // The 300-char key and the one with U+007F (a control character XML allows) are not
    // looked up: unresolved.
    let mut want = Map::new();
    want.insert("a&b#c/d e".into(), json!("odd"));
    want.insert(long.clone(), Value::Null);
    want.insert("x\u{7f}y".into(), Value::Null);
    assert_eq!(
        read_fetched(&h, &id).await?["user_resolutions"],
        Value::Object(want)
    );
    let env = released(&h, &id).await?;
    assert!(released_value(&env)?.contains("@odd"));
    // U+0001 is not an XML character: the body does not parse (`xml_ok` false), the fallback
    // renders no mention, and nothing is looked up.
    mount_page(
        mock,
        "65538",
        &page_with_storage(r#"<p><ri:user ri:userkey="a&#1;b"/></p>"#),
    )
    .await;
    let id = queued(&h, PAGE_GET, json!({ "id": "65538" })).await?;
    assert_eq!(user_gets(mock).await.len(), 1);
    assert_eq!(read_fetched(&h, &id).await?["user_resolutions"], json!({}));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookup_sub_budget_degrades_to_null() -> TestResult {
    // Less than the 20 s reserve is left after the content page.
    let h = Harness::builder()
        .confluence("wiki")
        .read_budget(ReadBudget {
            total: Duration::from_secs(15),
            ..ReadBudget::default()
        })
        .start()
        .await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(TWO_USERS_STORAGE)).await;
    mount_users(mock, &[JDOE, ASMITH]).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert!(user_gets(mock).await.is_empty());
    assert_eq!(h.event_types(&id).await?, checked_read(0));
    assert_eq!(
        read_fetched(&h, &id).await?["user_resolutions"],
        json!({ "key-jdoe": null, "key-asmith": null })
    );
    let env = released(&h, &id).await?;
    let value = released_value(&env)?;
    assert!(value.contains("@user:key-jdoe"), "{value}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_cache_cleared_on_credential_change() -> TestResult {
    let h = Harness::builder()
        .confluence("wiki")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let a = wiki(&h)?;
    // The connection test of `set_token`.
    a.confluence_user_current(UserKind::Known, TEST_USER, TEST_USER_KEY)
        .await;
    a.applinks_manifest("9.2.1").await;
    mount_page(a, ID, &page_with_storage(TWO_USERS_STORAGE)).await;
    mount_users(a, &[JDOE, ASMITH]).await;
    queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(
        user_gets(a).await.len(),
        2,
        "the second read used the cache"
    );
    // `credential_changed`: a new token (the same user's) is stored.
    h.instances()
        .set_token("wiki", SecretString::from("rotated-pat".to_owned()), None)
        .await?;
    assert_eq!(h.user_cached("wiki", "key-jdoe"), None);
    queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(
        user_gets(a).await.len(),
        4,
        "looked up again under the new token"
    );
    // `instance_changed`: the base URL moves to B (the PAT is deleted with it).
    assert_eq!(h.user_cached("wiki", "key-jdoe"), Some(Some("jdoe".into())));
    let b = MockDc::start(atlas_duck_atlassian::Product::Confluence, "/wiki2").await;
    b.confluence_user_current(UserKind::Known, TEST_USER, TEST_USER_KEY)
        .await;
    b.applinks_manifest("9.2.1").await;
    mount_page(&b, ID, &page_with_storage(TWO_USERS_STORAGE)).await;
    mount_users(&b, &[JDOE, ASMITH]).await;
    h.instances().change_base_url("wiki", &b.base_url())?;
    assert_eq!(h.user_cached("wiki", "key-jdoe"), None);
    h.instances()
        .set_token("wiki", SecretString::from("new-pat".to_owned()), None)
        .await?;
    queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(user_gets(&b).await.len(), 2, "B is asked for both users");
    assert_eq!(user_gets(a).await.len(), 4);
    Ok(())
}

/// The `authorization` header of every request on `p`, in arrival order.
async fn bearers(mock: &MockDc, p: &str) -> Vec<String> {
    gets_on(mock, p)
        .await
        .iter()
        .map(|r| {
            r.headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

/// T30 review I-2 (the T13 review B-1 cases are in `confluence_identity.rs`): a read that starts
/// while `set_token` writes the keychain takes the credential generation after the bump before
/// the store, fetches its content under the old PAT and sends its identity GET under the new one
/// (the same user's, so it matches). The bump after the store still tells the two apart:
/// `upstream_unavailable {identity_check}`, nothing released, nothing cached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_started_during_the_token_store_is_upstream_unavailable() -> TestResult {
    const MENTION: &str = r#"<p>Owner <ri:user ri:userkey="key-jdoe"/>. Secret plan.</p>"#;
    let pause = Pause::new();
    let h = Harness::builder()
        .confluence("wiki")
        .hooks(TestHooks {
            pause_after_lookups: Some(pause.clone()),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(MENTION)).await;
    mount_users(mock, &[JDOE]).await;
    // The connection test of `set_token` (its `user/current` is the harness's known answer).
    mock.applinks_manifest("9.2.1").await;
    // The keychain write holds until the read has its content and its lookups.
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    h.credentials().on_next_store(move || {
        let _ = entered_tx.send(());
        let _ = go_rx.recv_timeout(Duration::from_secs(20));
    });
    let instances = h.instances();
    let store = instances.set_token("wiki", SecretString::from("rotated-pat".to_owned()), None);
    let mut store = std::pin::pin!(store);
    tokio::select! {
        _ = &mut store => return Err("set_token returned before its keychain write".into()),
        entered = tokio::time::timeout(Duration::from_secs(20), entered_rx) => {
            entered?.map_err(|_| "the store hook never ran")?;
        }
    }
    let env = h.submit(PAGE_GET, json!({ "id": ID })).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    tokio::time::timeout(Duration::from_secs(20), pause.reached.notified()).await?;
    go_tx.send(())?;
    tokio::time::timeout(Duration::from_secs(20), &mut store).await??;
    pause.release.notify_one();
    if !h.settled(&id, 20_000).await {
        let held = h.approver().item(&id).is_some();
        return Err(format!("the read was not ended (waits for release: {held})").into());
    }
    let env = h.await_(&id, 1000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "upstream_unavailable", "{}", env.to_json_line());
    assert_eq!(exit(&env), 6);
    assert!(!env.to_json_line().contains("Secret plan"));
    assert_eq!(
        read_fetched(&h, &id).await?["unavailable"],
        "identity_check"
    );
    assert!(h.approver().item(&id).is_none(), "no release item");
    assert_eq!(h.user_cached("wiki", "key-jdoe"), None);
    // The window was hit: the content and the lookup under the old PAT, the read's identity GET
    // (after the connection test's) under the new one.
    let old = format!("Bearer {TEST_PAT}");
    assert_eq!(bearers(mock, &content_path(ID)).await, [old.clone()]);
    assert_eq!(bearers(mock, "/rest/api/user").await, [old]);
    assert_eq!(
        bearers(mock, IDENTITY_PATH).await,
        ["Bearer rotated-pat", "Bearer rotated-pat"]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn storage_format_resolves_nothing() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let mut old = page_with_storage(TWO_USERS_STORAGE);
    old["version"]["number"] = json!(2);
    mount_page(mock, ID, &page_with_storage(TWO_USERS_STORAGE)).await;
    mount_history_version(mock, ID, 2, &old).await;
    // A view answer that also carries the storage body with both mentions (T11 review m-9 (g)).
    let mut view = page_with_view("<p>Owners</p>");
    view["body"]["storage"] = json!({"value": TWO_USERS_STORAGE, "representation": "storage"});
    mount_page_view(mock, ID, &view).await;
    mount_users(mock, &[JDOE, ASMITH]).await;
    for (op, params) in [
        (PAGE_GET, json!({ "id": ID, "format": "storage" })),
        (PAGE_GET, json!({ "id": ID, "format": "view" })),
        (
            PAGE_HISTORY,
            json!({ "id": ID, "version": 2, "format": "storage" }),
        ),
    ] {
        let id = queued(&h, op, params).await?;
        assert_eq!(h.event_types(&id).await?, checked_read(0), "{op}");
        assert!(
            read_fetched(&h, &id)
                .await?
                .get("user_resolutions")
                .is_none()
        );
    }
    assert!(user_gets(mock).await.is_empty());
    // The same body as Markdown resolves both.
    queued(&h, PAGE_HISTORY, json!({ "id": ID, "version": 2 })).await?;
    assert_eq!(user_gets(mock).await.len(), 2);
    Ok(())
}

// ---- Task 11 fix round (T11 review I-1, I-2, m-2, m-3, m-9) ------------------------------------

/// A harness with `hooks`, the two-user page and both users mounted; the read is submitted.
async fn two_user_read(hooks: TestHooks) -> Result<(Harness, String), TestError> {
    let h = Harness::builder()
        .confluence("wiki")
        .hooks(hooks)
        .start()
        .await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(TWO_USERS_STORAGE)).await;
    mount_users(mock, &[JDOE, ASMITH]).await;
    let env = h.submit(PAGE_GET, json!({ "id": ID })).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    Ok((h, id))
}

/// Cancels `id` while a hook holds it, then lets the held task go on and waits for it.
async fn cancel_held(h: &Harness, id: &str, pause: &Pause) -> TestResult {
    let env = h.handler().cancel(id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    pause.release.notify_one();
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(())
}

/// The records of a read cancelled after `answered` lookups had answered (none in flight): each
/// lookup recorded once, with its answer, and as many records as the mock saw lookups.
async fn assert_answered_once(h: &Harness, id: &str, answered: &[&str]) -> TestResult {
    let mut want = vec![EventType::REQUEST_RECEIVED];
    want.extend(answered.iter().map(|_| EventType::PREVIEW_FETCH));
    want.extend([EventType::READ_FETCHED, EventType::CANCELLED]);
    assert_eq!(h.event_types(id).await?, want);
    let fetches = records(h, id, EventType::PREVIEW_FETCH).await?;
    for (f, key) in fetches.iter().zip(answered) {
        assert_eq!(f["purpose"], "resolve", "{f}");
        assert_eq!(f["status"], 200, "{f}");
        assert_ne!(f["outcome"], "cancelled_in_flight", "{f}");
        assert_eq!(f["path"], format!("/wiki/rest/api/user?key={key}"));
    }
    assert_eq!(looked_up(wiki(h)?).await, answered);
    assert_eq!(fetches.len(), user_gets(wiki(h)?).await.len());
    let r = read_fetched(h, id).await?;
    assert_eq!(r["outcome"], "cancelled_in_flight", "{r}");
    assert_eq!(r["pages"], 1);
    Ok(())
}

/// I-1: a cancel after the lookup's record is parked (its in-flight mark still set) records the
/// lookup once, from the parked record, not again as in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_after_lookup_answered_records_it_once() -> TestResult {
    let pause = Pause::new();
    let (h, id) = two_user_read(TestHooks {
        pause_after_get: Some(pause.clone()),
        ..TestHooks::none()
    })
    .await?;
    pause.reached.notified().await;
    cancel_held(&h, &id, &pause).await?;
    assert_answered_once(&h, &id, &["key-asmith"]).await
}

/// I-1: a cancel after the lookup's GET returned and before its record is parked still records
/// the GET (as in flight; its body was already taken from the control), never nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_before_lookup_park_records_it_in_flight() -> TestResult {
    let pause = Pause::new();
    let (h, id) = two_user_read(TestHooks {
        pause_before_lookup_park: Some(pause.clone()),
        ..TestHooks::none()
    })
    .await?;
    pause.reached.notified().await;
    cancel_held(&h, &id, &pause).await?;
    assert_cancelled_in_lookup(&h, &id, "by_client").await?;
    let fetches = records(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(fetches.len(), user_gets(wiki(&h)?).await.len());
    assert_eq!(looked_up(wiki(&h)?).await, ["key-asmith"]);
    Ok(())
}

/// I-1, the second lookup: the first is committed, the second parked when the cancel lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_after_second_lookup_answered_records_each_once() -> TestResult {
    let pause = Pause::new();
    let (h, id) = two_user_read(TestHooks {
        pause_after_get: Some(pause.clone()),
        ..TestHooks::none()
    })
    .await?;
    pause.reached.notified().await;
    pause.release.notify_one();
    pause.reached.notified().await;
    cancel_held(&h, &id, &pause).await?;
    assert_answered_once(&h, &id, &["key-asmith", "key-jdoe"]).await
}

/// m-9 (a): a cancel after the last lookup was committed finds no lookup in flight (the mark was
/// cleared), so nothing is recorded again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_after_the_lookups_records_none_again() -> TestResult {
    let pause = Pause::new();
    let (h, id) = two_user_read(TestHooks {
        pause_after_lookups: Some(pause.clone()),
        ..TestHooks::none()
    })
    .await?;
    pause.reached.notified().await;
    cancel_held(&h, &id, &pause).await?;
    assert_answered_once(&h, &id, &["key-asmith", "key-jdoe"]).await
}

/// m-9 (h): an expiry during a lookup is recorded like a cancel (`reason: expired`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_during_resolve_records_cancelled_in_flight() -> TestResult {
    let h = Harness::confluence().await?;
    let id = read_held_in_lookup(&h).await?;
    assert!(h.expire_now(&id).await);
    assert_ended_in_lookup(&h, &id, "expired", EventType::EXPIRED).await?;
    let env = h.status(&id).await;
    assert_eq!(env.status, Status::Expired, "{}", env.to_json_line());
    Ok(())
}

/// I-2: an answer over the 64 KiB lookup cap is cut there (`too_large`, at most cap + 1 bytes
/// recorded), `null` and not cached; the read goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_lookup_answer_is_null_and_not_cached() -> TestResult {
    const CAP: usize = 64 * 1024;
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let storage = r#"<p>Ask <ri:user ri:userkey="key-big"/>.</p>"#;
    mount_page(mock, ID, &page_with_storage(storage)).await;
    let big = json!({"userKey": "key-big", "username": "big", "pad": "x".repeat(100 * 1024)});
    mount_user_answer(mock, "key-big", 200, &big).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    let fetch = resolves(&h, &id).await?;
    let [f] = fetch.as_slice() else {
        return Err(format!("{} lookup records", fetch.len()).into());
    };
    assert_eq!(f["outcome"], "too_large", "{f}");
    let received = f["received"]["text"].as_str().ok_or("no received text")?;
    assert_eq!(received.len(), CAP + 1);
    assert_eq!(
        read_fetched(&h, &id).await?["user_resolutions"],
        json!({ "key-big": null })
    );
    assert_eq!(h.user_cached("wiki", "key-big"), None);
    let env = released(&h, &id).await?;
    assert!(released_value(&env)?.contains("@user:key-big"));
    Ok(())
}

/// I-2: a lookup is cut at the read's deadline less the identity GET's reserve (`timeout`): the
/// read ends within its budget, not at the 30 s per-call timeout, and the next key is `null` (less
/// than the reserve is left). A failed lookup never fails the read (L141): the identity GET that
/// follows (PD-93) has its reserve left, and the read releases with the names `null` (T13 review
/// I-2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookup_cut_at_the_read_budget() -> TestResult {
    // Both reserves are shortened to 1 s (T11 fix review m-4): the 4 s budget cuts the lookups at
    // 3 s, leaving 2 s of margin for the first one to start and 1 s for the identity GET; a lookup
    // that runs to the per-call timeout would take 10 s.
    let h = Harness::builder()
        .confluence("wiki")
        .hooks(TestHooks {
            read_budget: Some(ReadBudget {
                total: Duration::from_secs(4),
                ..ReadBudget::default()
            }),
            lookup_reserve: Some(Duration::from_secs(1)),
            identity_reserve: Some(Duration::from_secs(1)),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let mock = wiki(&h)?;
    mount_page(mock, ID, &page_with_storage(TWO_USERS_STORAGE)).await;
    mount_users_delayed(mock, &[JDOE, ASMITH], Duration::from_secs(10)).await;
    let began = std::time::Instant::now();
    let env = h.submit(PAGE_GET, json!({ "id": ID })).await;
    let id = request_id(&env)?;
    h.queued(&id, 40_000).await.ok_or("never queued")?;
    let took = began.elapsed();
    assert!(took < Duration::from_secs(8), "{took:?}");
    let fetch = resolves(&h, &id).await?;
    let [f] = fetch.as_slice() else {
        return Err(format!("{} lookup records", fetch.len()).into());
    };
    assert_eq!(f["outcome"], "timeout", "{f}");
    assert_eq!(f["path"], "/wiki/rest/api/user?key=key-asmith");
    assert_eq!(looked_up(mock).await, ["key-asmith"]);
    assert_eq!(h.event_types(&id).await?, checked_read(1));
    let identity = records(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(
        identity.last().map(|f| &f["purpose"]),
        Some(&json!("identity"))
    );
    assert_eq!(identity.last().map(|f| &f["status"]), Some(&json!(200)));
    let r = read_fetched(&h, &id).await?;
    assert!(r.get("outcome").is_none(), "{r}");
    assert_eq!(
        r["user_resolutions"],
        json!({ "key-jdoe": null, "key-asmith": null })
    );
    assert_eq!(h.user_cached("wiki", "key-asmith"), None);
    let env = released(&h, &id).await?;
    assert!(released_value(&env)?.contains("@user:key-asmith"));
    Ok(())
}

/// m-9 (e): the reserve is measured from the read's deadline, taken before the content GET: a
/// 4 s budget with a 2 s reserve and a content page that answers after 2.5 s leaves less than the
/// reserve, so no lookup starts. (The identity GET's reserve is 0 here, so only the lookup reserve
/// decides.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookup_deadline_counts_from_the_read_start() -> TestResult {
    let h = Harness::builder()
        .confluence("wiki")
        .hooks(TestHooks {
            read_budget: Some(ReadBudget {
                total: Duration::from_secs(4),
                ..ReadBudget::default()
            }),
            lookup_reserve: Some(Duration::from_secs(2)),
            identity_reserve: Some(Duration::ZERO),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let mock = wiki(&h)?;
    mount_page_delayed(
        mock,
        ID,
        &page_with_storage(TWO_USERS_STORAGE),
        Duration::from_millis(2500),
    )
    .await;
    mount_users(mock, &[JDOE, ASMITH]).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert!(user_gets(mock).await.is_empty());
    assert_eq!(
        read_fetched(&h, &id).await?["user_resolutions"],
        json!({ "key-jdoe": null, "key-asmith": null })
    );
    Ok(())
}

/// m-9 (c), m-2, m-3: what is cached. A 503 and an object for another key are `null` and not
/// cached (looked up again by the next read); an object for the key without a username is a
/// definitive `null`, cached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_definitive_answers_are_cached() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let storage = r#"<p><ri:user ri:userkey="key-down"/> <ri:user ri:userkey="key-nameless"/> <ri:user ri:userkey="key-other"/></p>"#;
    mount_page(mock, ID, &page_with_storage(storage)).await;
    mount_user_answer(mock, "key-down", 503, &json!({"message": "down"})).await;
    mount_user_answer(
        mock,
        "key-nameless",
        200,
        &json!({"type": "known", "userKey": "key-nameless", "displayName": "N"}),
    )
    .await;
    // A front answering with another user's object.
    mount_user_answer(mock, "key-other", 200, &user("key-someone", "someone")).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(
        read_fetched(&h, &id).await?["user_resolutions"],
        json!({ "key-down": null, "key-nameless": null, "key-other": null })
    );
    assert_eq!(h.user_cached("wiki", "key-down"), None);
    assert_eq!(h.user_cached("wiki", "key-nameless"), Some(None));
    assert_eq!(h.user_cached("wiki", "key-other"), None);
    let env = released(&h, &id).await?;
    assert!(!released_value(&env)?.contains("someone"));
    queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(
        looked_up(mock).await,
        [
            "key-down",
            "key-nameless",
            "key-other",
            "key-down",
            "key-other"
        ]
    );
    Ok(())
}

/// m-9 (d): only lookups sent count toward the 50 per read: 50 cache hits and 5 keys that are
/// never looked up (sorted first) leave room for all 50 fresh keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_hits_and_unlookable_keys_do_not_count_toward_the_cap() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let cached: Vec<String> = (0..50).map(|n| format!("c{n:02}")).collect();
    let unlookable: Vec<String> = (0..5).map(|n| format!("a{n}{}", "k".repeat(300))).collect();
    let fresh: Vec<String> = (0..50).map(|n| format!("u{n:02}")).collect();
    for k in &cached {
        assert!(h.user_cache_set("wiki", k, Some(&format!("name-{k}"))));
    }
    let storage: String = cached
        .iter()
        .chain(&unlookable)
        .chain(&fresh)
        .map(|k| format!(r#"<p><ri:user ri:userkey="{k}"/></p>"#))
        .collect();
    let names: Vec<String> = fresh.iter().map(|k| format!("name-{k}")).collect();
    let users: Vec<(&str, Option<&str>)> = fresh
        .iter()
        .zip(&names)
        .map(|(k, n)| (k.as_str(), Some(n.as_str())))
        .collect();
    mount_page(mock, ID, &page_with_storage(&storage)).await;
    mount_users(mock, &users).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert_eq!(looked_up(mock).await, fresh);
    let map = read_fetched(&h, &id).await?["user_resolutions"].clone();
    let map = map.as_object().ok_or("no map")?;
    assert_eq!(map.len(), 105);
    for k in cached.iter().chain(&fresh) {
        assert_eq!(
            map.get(k.as_str()),
            Some(&json!(format!("name-{k}"))),
            "{k}"
        );
    }
    for k in &unlookable {
        assert_eq!(map.get(k.as_str()), Some(&Value::Null));
    }
    assert_eq!(unresolved_users(&h, &id), Some(5));
    Ok(())
}

/// m-9 (f): a body that is not `xml_ok` resolves nothing, even a mention before the bad
/// character (which the partial tree holds).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn body_not_xml_ok_looks_nobody_up() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let storage = r#"<p><ri:user ri:userkey="key-jdoe"/></p><p>&#1;</p>"#;
    mount_page(mock, ID, &page_with_storage(storage)).await;
    mount_users(mock, &[JDOE]).await;
    let id = queued(&h, PAGE_GET, json!({ "id": ID })).await?;
    assert!(user_gets(mock).await.is_empty());
    assert_eq!(read_fetched(&h, &id).await?["user_resolutions"], json!({}));
    Ok(())
}

// ---- Task 12a: search release list, search table, cql_broad (PD-101, PD-102, U-28, U-31) ------

const SEARCH: &str = "confluence.search";

/// One `/rest/api/search` result as Confluence DC sends it, with the keys §7.4 does not release
/// (`content.status`, `content.title`, `content._links`, `entityType`, `iconCssClass`,
/// `friendlyLastModified`, `breadcrumbs`, `resultGlobalContainer.displayUrl`).
fn search_hit(id: &str, title: &str, space: &str, kind: &str) -> Value {
    let slug = title.replace(' ', "+");
    json!({
        "content": {
            "id": id, "type": kind, "status": "current", "title": title,
            "_links": {"webui": format!("/display/DOC/{slug}"), "self": format!("https://wiki.corp.example/rest/api/content/{id}")}
        },
        "title": title,
        "excerpt": format!("About {title}"),
        "url": format!("/display/DOC/{slug}"),
        "resultGlobalContainer": {"title": space, "displayUrl": "/display/DOC"},
        "breadcrumbs": [{"label": space, "url": "/display/DOC"}],
        "entityType": "content",
        "iconCssClass": "aui-icon content-type-page",
        "lastModified": "2026-10-06T14:00:00.000+02:00",
        "friendlyLastModified": "Oct 06, 2026"
    })
}

/// A search answer page holding `results`, with `totalSize` and the root keys DC adds.
fn search_answer(results: Vec<Value>, total: u64) -> Value {
    json!({
        "results": results.clone(),
        "start": 0,
        "limit": 25,
        "size": results.len(),
        "totalSize": total,
        "cqlQuery": "secret effective query",
        "searchDuration": 12,
        "_links": {"base": "https://wiki.corp.example", "context": "/wiki"}
    })
}

/// Every string of `v` (keys and values).
fn strings_of(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().flat_map(strings_of).collect(),
        Value::Object(m) => m
            .iter()
            .flat_map(|(k, v)| std::iter::once(k.clone()).chain(strings_of(v)))
            .collect(),
        _ => Vec::new(),
    }
}

/// §13 U-28 (`confluence.search`): an every-occurrence mask of the title reaches the `url` (a
/// URL field), whose `%`-encoded, lower-hex and entity forms all match; the release stays blocked
/// until the user picks what happens to the URL.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u28_confluence_search_mask_reaches_url() -> TestResult {
    use atlas_duck_core::redact::BlockReason;
    use atlas_duck_core::redact::views::canonical_hit;
    use atlas_duck_core::{RedactionOp, UrlMode};
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let title = "Falcon Müller Plan";
    let mut hit = search_hit("65537", title, "Legal", "page");
    hit["url"] = json!("/display/LEGAL/Falcon+M%C3%BCller+Plan");
    hit["excerpt"] = json!("see Falcon%20M%c3%bcller%20Plan");
    hit["resultGlobalContainer"]["title"] = json!("Falcon M&uuml;ller Plan space");
    // Not released (PD-101): never part of the candidate, so never a path to mask.
    hit["content"]["title"] = json!("Falcon M&#252;ller Plan");
    let mut second = search_hit("65538", "Falcon M&#252;ller Plan (draft)", "Legal", "page");
    second["url"] = json!("/display/LEGAL/Draft");
    second["excerpt"] = json!("");
    let mut answer = search_answer(vec![hit, second], 2);
    // DC echoes the effective CQL, percent-encoded, in `_links.next`: a URL field too.
    answer["_links"]["next"] =
        json!("/rest/api/search?cql=title%20~%20%22Falcon%20M%C3%BCller%20Plan%22&start=2");
    mount_search(mock, &answer).await;
    let params = json!({ "cql": "space = LEGAL", "excerpt": "indexed" });
    let mask = || RedactionOp::MaskText {
        text: title.into(),
        every_occurrence: true,
        at: None,
    };
    let paths = [
        "_links.next",
        "results[0].excerpt",
        "results[0].resultGlobalContainer.title",
        "results[0].title",
        "results[0].url",
        "results[1].title",
    ];

    let id = queued(&h, SEARCH, params.clone()).await?;
    let ap = h.approver();
    ap.open(&id).map_err(de)?;
    // No URL choice: every canonical form is listed and the URL blocks the release.
    let report = ap.redaction_preview(&id, &[mask()]).map_err(de)?;
    let mut listed = report.also_appears_in.clone();
    listed.sort();
    listed.dedup();
    assert_eq!(listed, paths);
    for url_path in ["results[0].url", "_links.next"] {
        assert!(
            report.blocked.contains(&BlockReason::MaskStillOccurs {
                path: url_path.into()
            }),
            "{url_path}: {:?}",
            report.blocked
        );
    }
    assert!(
        ap.redact(&id, vec![mask()]).is_err(),
        "release stays blocked"
    );

    // The URL replaced whole: nothing blocks, the release holds no form of the title.
    let url = RedactionOp::UrlField {
        mode: UrlMode::ReplaceWhole,
    };
    assert!(
        ap.redaction_preview(&id, &[mask(), url.clone()])
            .map_err(de)?
            .blocked
            .is_empty()
    );
    ap.redact(&id, vec![mask(), url]).map_err(de)?;
    ap.open(&id).map_err(de)?;
    let env = released(&h, &id).await?;
    assert!(env.redacted);
    let result = result_of(&env)?;
    assert_eq!(result["results"][0]["url"], "[REDACTED]");
    assert_eq!(result["results"][1]["url"], "/display/LEGAL/Draft");
    assert_eq!(result["_links"]["next"], "[REDACTED]");
    for s in strings_of(&result) {
        assert!(!canonical_hit(&s, title), "still in {s:?}");
    }
    assert!(result["results"][0]["content"].get("title").is_none());

    // The URL dropped instead: gone, and named in `fields_dropped`.
    let id = queued(&h, SEARCH, params).await?;
    ap.open(&id).map_err(de)?;
    let drop = RedactionOp::UrlField {
        mode: UrlMode::Drop,
    };
    ap.redact(&id, vec![mask(), drop]).map_err(de)?;
    ap.open(&id).map_err(de)?;
    let env = released(&h, &id).await?;
    let result = result_of(&env)?;
    assert!(result["results"][0].get("url").is_none(), "{result}");
    assert!(result["_links"].get("next").is_none(), "{result}");
    let dropped = meta_of(&env)?["redactions"]["fields_dropped"].clone();
    let dropped: Vec<&str> = dropped
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    // `fields_dropped` names the leaf key (`_links.next` is `next`).
    for path in ["url", "next"] {
        assert!(dropped.contains(&path), "{path} not in {dropped:?}");
    }
    for s in strings_of(&result) {
        assert!(!canonical_hit(&s, title), "still in {s:?}");
    }
    Ok(())
}

/// §13 U-31: the rewritten CQL is what goes on the wire, and the preview header shows it
/// display-escaped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u31_effective_cql_on_the_wire_and_in_preview() -> TestResult {
    use atlas_duck_preview::invisible::escape_for_display;
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_search(
        mock,
        &search_answer(vec![search_hit("1", "A", "Docs", "page")], 1),
    )
    .await;
    let cql = "space = DOC OR label = \"x\u{202E}y\" ORDER BY title";
    let effective = "(space = DOC OR label = \"x\u{202E}y\") AND type in (page,blogpost,comment,attachment) ORDER BY title";
    let id = queued(&h, SEARCH, json!({ "cql": cql })).await?;
    let gets = search_gets(mock).await;
    let [only] = gets.as_slice() else {
        return Err(format!("{} search GETs", gets.len()).into());
    };
    assert_eq!(query(only, "cql").as_deref(), Some(effective));
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let shown = escape_for_display(effective);
    assert!(shown.contains("⟨U+202E⟩"), "{shown}");
    assert_eq!(preview.header.query.as_deref(), Some(shown.as_str()));
    Ok(())
}

/// §13 U-31: a mid-query `ORDER BY`, an unterminated quote and a parenthesis escape are
/// refused at validation: exit 2, `details.param == "cql"`, the CQL never echoed, nothing queued,
/// nothing sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u31_rejections_exit2_nothing_queued() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_search(mock, &search_answer(Vec::new(), 0)).await;
    for cql in [
        "space = DOC ORDER BY title AND label = zebra",
        "title ~ \"zebra unterminated",
        "space=ZEBRA) OR (type=space",
    ] {
        let env = h.submit(SEARCH, json!({ "cql": cql })).await;
        let line = env.to_json_line();
        assert_eq!(env.status, Status::Failed, "{line}");
        assert_eq!(code(&env), "validation", "{line}");
        assert_eq!(common::exit(&env), 2);
        assert_eq!(common::detail(&env, "param"), "cql", "{line}");
        assert!(!line.to_lowercase().contains("zebra"), "CQL echoed: {line}");
        let id = request_id(&env)?;
        assert_eq!(
            h.event_types(&id).await?,
            [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
        );
        assert!(h.approver().item(&id).is_none(), "nothing queued");
    }
    assert!(test_hits(mock).await.is_empty(), "nothing sent");
    Ok(())
}

/// PD-101 (lead ruling Q7): the released results carry only the §7.4 keys, the root only its
/// paging keys; `totalSize` stays as sent; a result without `content` is removed and counted.
/// The pruning is a function of the committed payload alone (a rebuild agrees).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn search_results_pruned_to_spec_fields() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let mut bare = search_hit("0", "a space, not content", "Docs", "page");
    if let Some(o) = bare.as_object_mut() {
        o.remove("content");
    }
    let mut odd = search_hit("65538", "Odd", "Docs", "blogpost");
    odd["resultGlobalContainer"] = json!("not an object");
    odd["content"]["id"] = json!(65538);
    let answer = search_answer(
        vec![
            search_hit("65537", "Release checklist", "Docs", "page"),
            bare,
            odd,
        ],
        57,
    );
    mount_search(mock, &answer).await;
    let params = json!({ "cql": "space = DOC", "excerpt": "indexed" });
    let id = queued(&h, SEARCH, params.clone()).await?;
    let env = released(&h, &id).await?;
    let result = result_of(&env)?;
    assert_eq!(
        result,
        json!({
            "results": [
                {
                    "content": {"id": "65537", "type": "page"},
                    "title": "Release checklist",
                    "excerpt": "About Release checklist",
                    "url": "/display/DOC/Release+checklist",
                    "resultGlobalContainer": {"title": "Docs"},
                    "lastModified": "2026-10-06T14:00:00.000+02:00"
                },
                {
                    "content": {"id": 65538, "type": "blogpost"},
                    "title": "Odd",
                    "excerpt": "About Odd",
                    "url": "/display/DOC/Odd",
                    "lastModified": "2026-10-06T14:00:00.000+02:00"
                }
            ],
            "start": 0,
            "limit": 25,
            "size": 3,
            "totalSize": 57,
            "_links": {"base": "https://wiki.corp.example", "context": "/wiki"}
        })
    );
    let meta = meta_of(&env)?;
    assert_eq!(meta["redactions"]["items_dropped"], 1);
    // The record keeps every byte received; only the candidate is pruned.
    let fetched = read_fetched(&h, &id).await?;
    let spec = atlas_duck_registry::get(SEARCH).ok_or("no registry op")?;
    let pruned = |payload: &Value| normalize(spec, &params, payload).map_err(|e| format!("{e:?}"));
    assert_eq!(pruned(&fetched)?, result);
    assert_eq!(pruned(&fetched)?, result, "deterministic");
    assert_eq!(pruned(&fetched_payload(&answer, None))?, result);
    Ok(())
}

/// PD-102 (provisional, lead ruling Q11): the Info `cql_broad` is raised unless the agent's CQL
/// narrows (every `OR` alternative holds a `=`/`IN` clause on a narrowing field or a narrowing
/// group; `NOT`, `!=`, `~` and comparisons never narrow). The tables pin the one-place rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cql_broad_info_rule() -> TestResult {
    use atlas_duck_core::ops::confluence::cql_broad;
    use atlas_duck_preview::warning::{Level, WarningId};
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mount_search(
        mock,
        &search_answer(vec![search_hit("1", "A", "Docs", "page")], 1),
    )
    .await;
    for (cql, broad) in [
        ("text ~ \"x\"", true),
        ("space = DOC AND text ~ \"x\"", false),
        ("space = DOC OR text ~ \"x\"", true),
    ] {
        let id = queued(&h, SEARCH, json!({ "cql": cql })).await?;
        let preview = h.approver().open(&id).map_err(de)?.preview;
        let found: Vec<_> = preview
            .warnings
            .iter()
            .filter(|w| w.id == WarningId::CqlBroad)
            .collect();
        if broad {
            let [w] = found.as_slice() else {
                return Err(format!("{cql}: {} cql_broad", found.len()).into());
            };
            assert_eq!(w.level, Level::Info);
            assert_eq!(w.text, atlas_duck_preview::warning::TEXT_CQL_BROAD);
        } else {
            assert!(found.is_empty(), "{cql}");
        }
    }
    // Broad: the query does not narrow (an OR alternative, a negation, a comparison, a fuzzy match).
    for cql in [
        "text ~ \"x\"",
        "siteSearch ~ \"release\"",
        "type = page",
        "type = page ORDER BY lastmodified desc",
        "lastmodified > now(\"-1d\")",
        "created >= \"2026-01-01\"",
        "macro = jira",
        "mention = currentUser()",
        "space.type = personal",
        "text ~ \"space = DOC\"",
        "\"space\" = DOC",
        "TEXT ~ x ORDER BY title",
        "type in (page, space)",
        "space = DOC OR text ~ \"x\"",
        "text ~ \"x\" or space = DOC",
        "(space = DOC OR text ~ \"x\") AND type = page",
        "text ~ \"x\" OR space = DOC AND label = y",
        "creator = currentUser() OR text ~ \"x\"",
        "NOT space = DOC",
        "type = page AND NOT space = DOC",
        "NOT (space = DOC AND label = x)",
        "label not in (draft)",
        "space != DOC",
        "label != x",
        "creator != jdoe",
        "id > 0",
        "id >= 1",
        "ancestor != 1",
        "title ~ \"Release\"",
        "space.title ~ \"Docs\"",
    ] {
        assert!(cql_broad(cql), "should flag: {cql}");
    }
    // Narrowing: every OR alternative holds <field> = … or <field> IN (…) of a narrowing field.
    for cql in [
        "space = DOC AND text ~ \"x\"",
        "SPACE=DOC",
        "space in (DOC, OPS)",
        "space IN (DOC) AND text ~ x",
        "space.key = DOC",
        "space.title = \"Docs\"",
        "ancestor = 65537",
        "parent = 65537",
        "container = 65537",
        "id = 65537",
        "id in (1, 2)",
        "content = 65537",
        "title = \"Release notes\"",
        "label = draft",
        "creator = currentUser()",
        "contributor = jdoe",
        "space = DOC OR space = OPS",
        "space = DOC OR (label = x AND text ~ \"y\")",
        "(space = DOC OR label = x) AND text ~ \"y\"",
        "text ~ \"x\" AND (space = DOC OR ancestor = 1)",
        "((space = DOC))",
        "text ~ \"x\" AND space = DOC OR label = y",
        "space = DOC AND NOT label = draft",
        "lastmodified > now(\"-1d\") AND space = DOC",
        "space = DOC OR label = y ORDER BY title",
    ] {
        assert!(!cql_broad(cql), "should not flag: {cql}");
    }
    // A CQL the rewrite refuses raises nothing (validation rejected it already).
    assert!(!cql_broad("text ~ \"x"));
    Ok(())
}

/// §6.3 "Confluence search": columns `title`, `space`, `type`, `last modified` (and `excerpt`
/// only with `excerpt=indexed`), a row per released result, the count "N of totalSize".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn search_table_columns_and_count() -> TestResult {
    use atlas_duck_preview::ItemCount;
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let mut tricky = search_hit("65538", "Bidi \u{202E}title", "Ops", "blogpost");
    tricky["excerpt"] = json!("line one\nline two");
    let mut answer = search_answer(
        vec![
            search_hit("65537", "Release checklist", "Docs", "page"),
            tricky,
        ],
        40,
    );
    // 38 more results: DC sends `_links.next`, its absence would end the results (Task 14).
    answer["_links"]["next"] = json!("/rest/api/search?cql=space+%3D+DOC&start=2");
    mount_search(mock, &answer).await;

    let table = |preview: atlas_duck_preview::Preview| match preview.body {
        PreviewBody::Table {
            columns,
            rows,
            count,
        } => Ok((columns, rows, count, preview.header)),
        other => Err(format!("not a table: {other:?}")),
    };

    let id = queued(&h, SEARCH, json!({ "cql": "space = DOC", "max": 2 })).await?;
    let (columns, rows, count, header) = table(h.approver().open(&id).map_err(de)?.preview)?;
    assert_eq!(columns, ["title", "space", "type", "last modified"]);
    assert_eq!(
        rows,
        [
            [
                "Release checklist",
                "Docs",
                "page",
                "2026-10-06T14:00:00.000+02:00"
            ],
            [
                "Bidi ⟨U+202E⟩title",
                "Ops",
                "blogpost",
                "2026-10-06T14:00:00.000+02:00"
            ]
        ]
    );
    let want = ItemCount {
        shown: 2,
        total: Some(40),
        more_available: true,
    };
    assert_eq!(count, Some(want));
    assert_eq!(header.item_count, Some(want));
    // What the table leaves out (the excerpts, the URLs, the root's `_links`) is counted.
    assert!(header.hidden_in_preview_bytes > 0);

    let id = queued(
        &h,
        SEARCH,
        json!({ "cql": "space = DOC", "max": 2, "excerpt": "indexed" }),
    )
    .await?;
    let (columns, rows, count, _) = table(h.approver().open(&id).map_err(de)?.preview)?;
    assert_eq!(
        columns,
        ["title", "space", "type", "last modified", "excerpt"]
    );
    assert_eq!(rows[0][4], "About Release checklist");
    assert!(!rows[1][4].contains('\n'), "{}", rows[1][4]);
    assert!(rows[1][4].starts_with("line one"), "{}", rows[1][4]);
    assert_eq!(count, Some(want));

    // An answer that is no result list keeps the Fallback.
    let h = Harness::confluence().await?;
    wiki(&h)?
        .json(
            "/rest/api/search",
            400,
            r#"{"statusCode":400,"message":"bad"}"#,
        )
        .await;
    let env = h.submit(SEARCH, json!({ "cql": "text ~ \"x\"" })).await;
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(
        !matches!(preview.body, PreviewBody::Table { .. }),
        "{:?}",
        preview.body
    );
    // No result list: the query's breadth is not what is released, so no `cql_broad`.
    assert!(
        preview
            .warnings
            .iter()
            .all(|w| w.id != atlas_duck_preview::warning::WarningId::CqlBroad),
        "{:?}",
        preview.warnings
    );
    Ok(())
}

// ---- Task 14: paging end signal, I-22 context path and `meta.page` ----------------------------

/// `RedactionOp::DropItem` of the `results` item whose `id` is `id`.
fn drop_result(id: &str) -> atlas_duck_core::RedactionOp {
    atlas_duck_core::RedactionOp::DropItem {
        array_path: "results".into(),
        key: "id".into(),
        value: json!(id),
    }
}

/// Releases `id` after `ops` redacted the read; returns the released `meta` and `data.result`.
async fn release_with(
    h: &Harness,
    id: &str,
    ops: Vec<atlas_duck_core::RedactionOp>,
) -> Result<(Value, Value), TestError> {
    h.approver().release_redacted(id, ops).map_err(de)?;
    let env = h.await_(id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    Ok((meta_of(&env)?, result_of(&env)?))
}

/// The child-page pages of 25 children (`ID`), by `start`: `size` children of `start..` with
/// `_links.next` on every page but the last (Confluence DC: absent on the last page).
fn children_page(start: u64, limit: u64, total: u64) -> Value {
    let size = limit.min(total.saturating_sub(start));
    let results: Vec<Value> = (start..start + size)
        .map(|i| {
            json!({
                "id": format!("{}", 70_000 + i), "type": "page", "status": "current",
                "title": format!("Child {i}"), "_links": {"webui": format!("/display/DOC/Child+{i}")}
            })
        })
        .collect();
    let mut links = json!({"base": "https://wiki.corp.example", "context": "/wiki"});
    if start + size < total {
        links["next"] = json!(format!(
            "/rest/api/content/{ID}/child/page?limit={limit}&start={}",
            start + size
        ));
    }
    json!({"results": results, "start": start, "limit": limit, "size": size, "_links": links})
}

/// §13 I-22 (Confluence, direct read): the server answers `_links.next` without the context path
/// (`/rest/api/space?limit=25&start=25`); page 2 is rebuilt from the template under `/wiki`, and
/// nothing is requested outside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i22_confluence_context_path_direct_read() -> TestResult {
    use atlas_duck_atlassian::testing::fixtures::confluence_space_page;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, Request};
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let ok = mock.response(200);
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/space")))
        .respond_with(move |req: &Request| {
            let start = query(req, "start")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0u64);
            // The server clamps the page size to 25 whatever is asked.
            let size = 25u64.min(100 - start);
            ok.clone().set_body_raw(
                confluence_space_page(
                    start,
                    25,
                    size,
                    Some("/rest/api/space?limit=25&start=25").filter(|_| start + size < 100),
                ),
                "application/json",
            )
        })
        .mount(mock.server())
        .await;

    let id = queued(&h, "confluence.space.list", json!({ "max": 50 })).await?;
    let env = released(&h, &id).await?;
    assert_eq!(
        result_of(&env)?["results"].as_array().map(Vec::len),
        Some(25 + 25)
    );
    let hits = gets_on(mock, "/rest/api/space").await;
    let starts: Vec<_> = hits.iter().map(|r| query(r, "start")).collect();
    assert_eq!(starts, [Some("0".to_owned()), Some("25".to_owned())]);
    assert!(
        hits.iter()
            .all(|r| r.url.path() == mock.path("/rest/api/space")),
        "{:?}",
        hits.iter().map(|r| r.url.to_string()).collect::<Vec<_>>()
    );
    // Nothing was requested outside `/wiki` (the identity GET included).
    let all = mock.received().await;
    assert!(
        all.iter().all(|r| r.url.path().starts_with("/wiki/")),
        "{:?}",
        all.iter().map(|r| r.url.to_string()).collect::<Vec<_>>()
    );
    assert_eq!(
        meta_of(&env)?["page"],
        json!({"start": 0, "returned": 50, "total": null, "truncated": true, "next_start": 50})
    );
    // Page 1's `next` is stale after the merge (no context path, a range already merged in).
    let result = result_of(&env)?;
    assert!(result["_links"].get("next").is_none(), "{result}");
    Ok(())
}

/// A merged multi-page search drops page 1's `_links.next` (through the §7.4 pruning too) and keeps
/// the rest of the root's `_links`; `meta.page` carries the continuation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn merged_pages_release_no_stale_links_next() -> TestResult {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, Request};
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let ok = mock.response(200);
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/search")))
        .respond_with(move |req: &Request| {
            let start = query(req, "start")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0u64);
            let size = 25u64.min(35 - start);
            let hits = (start..start + size)
                .map(|i| {
                    search_hit(
                        &format!("{}", 80_000 + i),
                        &format!("Hit {i}"),
                        "DOC",
                        "page",
                    )
                })
                .collect();
            let mut answer = search_answer(hits, 35);
            answer["start"] = json!(start);
            if start + size < 35 {
                answer["_links"]["next"] = json!("/rest/api/search?cql=x&start=25");
            }
            ok.clone()
                .set_body_raw(answer.to_string(), "application/json")
        })
        .mount(mock.server())
        .await;
    let id = queued(&h, SEARCH, json!({ "cql": "space = DOC", "max": 50 })).await?;
    let env = released(&h, &id).await?;
    let result = result_of(&env)?;
    assert_eq!(result["results"].as_array().map(Vec::len), Some(35));
    assert!(result["_links"].get("next").is_none(), "{result}");
    assert_eq!(result["_links"]["context"], "/wiki");
    assert_eq!(meta_of(&env)?["page"]["next_start"], Value::Null);

    // One page only: the answer's `_links.next` stays as it is.
    use common::confluence::mount_children;
    let h = Harness::confluence().await?;
    mount_children(wiki(&h)?, ID, &[children_page(0, 10, 25)]).await;
    let id = queued(
        &h,
        "confluence.page.children",
        json!({ "id": ID, "max": 10 }),
    )
    .await?;
    let env = released(&h, &id).await?;
    let result = result_of(&env)?;
    assert!(result["_links"].get("next").is_some(), "{result}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i22_confluence_drops_keep_totals_and_next_start() -> TestResult {
    use common::confluence::mount_children;
    let h = Harness::confluence().await?;
    let pages = [
        children_page(0, 10, 25),
        children_page(10, 10, 25),
        children_page(20, 10, 25),
    ];
    mount_children(wiki(&h)?, ID, &pages).await;
    let id = queued(
        &h,
        "confluence.page.children",
        json!({ "id": ID, "max": 10 }),
    )
    .await?;
    let (meta, result) =
        release_with(&h, &id, vec![drop_result("70002"), drop_result("70003")]).await?;
    // §7.5: the page is what the server answered; the drops only lower `returned`.
    assert_eq!(
        meta["page"],
        json!({"start": 0, "returned": 8, "total": null, "truncated": true, "next_start": 10})
    );
    assert_eq!(meta["redactions"]["items_dropped"], 2);
    assert_eq!(result["results"].as_array().map(Vec::len), Some(8));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i22_confluence_next_start_loop_rerequests_no_dropped_item() -> TestResult {
    use common::confluence::{content_path, mount_children};
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let pages = [
        children_page(0, 10, 25),
        children_page(10, 10, 25),
        children_page(20, 10, 25),
    ];
    mount_children(mock, ID, &pages).await;
    let mut next = Some(0u64);
    let mut dropped: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    while let Some(start) = next {
        let id = queued(
            &h,
            "confluence.page.children",
            json!({ "id": ID, "max": 10, "start": start }),
        )
        .await?;
        // Every page drops its first two children.
        let first = |n: u64| format!("{}", 70_000 + start + n);
        dropped.extend([first(0), first(1)]);
        let (meta, result) = release_with(
            &h,
            &id,
            vec![drop_result(&first(0)), drop_result(&first(1))],
        )
        .await?;
        seen.extend(
            result["results"]
                .as_array()
                .ok_or("no results")?
                .iter()
                .filter_map(|c| c["id"].as_str().map(str::to_owned)),
        );
        next = meta["page"]["next_start"].as_u64();
        assert_eq!(meta["page"]["start"], start);
    }
    // The agent followed `next_start` only: it never asked for a range holding a dropped item.
    let starts: Vec<_> = gets_on(mock, &format!("{}/child/page", content_path(ID)))
        .await
        .iter()
        .map(|r| query(r, "start"))
        .collect();
    assert_eq!(
        starts,
        [
            Some("0".to_owned()),
            Some("10".to_owned()),
            Some("20".to_owned())
        ]
    );
    assert!(
        seen.iter().all(|k| !dropped.contains(k)),
        "a dropped child came back: {seen:?}"
    );
    assert_eq!(seen.len(), 25 - 6);
    Ok(())
}
