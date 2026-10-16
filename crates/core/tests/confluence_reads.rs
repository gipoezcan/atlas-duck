#![cfg(feature = "testing")]
//! Confluence reads in M7. Task 10: `format` on `confluence.page.get` and on
//! `confluence.page.history` with `version` (PD-100, §7.4): `markdown` (the default) expands
//! `body.storage`, converts it with the committed `user_resolutions` map and replaces `body` with
//! `{"format": "markdown", "value": …}`, releasing `meta.conversion`; `storage` releases the body
//! as sent; `view` expands `body.view` instead. The history summary ignores `format`.

mod common;

use std::collections::BTreeMap;

use atlas_duck_atlassian::testing::MockDc;
use atlas_duck_audit::EventType;
use atlas_duck_core::engine::queue::{Limits, MIB};
use atlas_duck_core::testing::Harness;
use atlas_duck_ipc::envelope::{Envelope, Status};
use common::confluence::{
    PAGE_EXPAND_STORAGE, PAGE_EXPAND_VIEW, content_path, mount_history_summary,
    mount_history_version, mount_page, mount_page_view, page_with_storage, page_with_view,
};
use common::jira::{gets_on, query};
use common::{TestError, TestResult, de, request_id, test_hits};
use serde_json::{Value, json};

const PAGE_GET: &str = "confluence.page.get";
const PAGE_HISTORY: &str = "confluence.page.history";
const ID: &str = "65537";

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
    assert_eq!(test_hits(mock).await.len(), 1, "nothing else was sent");

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
    // The committed map is empty until Task 11: the mention is its key.
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
    // Committed before the candidate hash (§5.2 steps 3–4); empty until Task 11's lookups.
    assert_eq!(fetched["user_resolutions"], json!({}));
    assert_eq!(fetched["pages"], 1);
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
