//! `confluence_flows` (M7 Task 24): eight flows of the real binaries on the Confluence paths, each
//! against a store provisioned in the wizard's order and the mock Confluence `wiki`. Requests are
//! decided by the scripted approver through the `atlas-test:<directive>` reason (PD-03); the wire
//! is read back from the mock (`MockDc::received`).
//!
//! Every flow spawns a binary and therefore starts with [`opted_in`]: it skips unless
//! `ATLAS_DUCK_CLI_FLOWS=1` (CI).
//!
//! Mounts: a `MockDc` matches by method and path only (never by query) and answers the first mount
//! that matches, so a flow never mounts a path the fixture set of the provisioning already answers
//! (`/rest/api/content/65537`, `/rest/api/search`, `/rest/api/user/current`, the applinks manifest)
//! with something else. A flow that needs another answer for one of them starts the mock over
//! ([`restart_wiki`]) and mounts what it needs, the identity and the applinks answers included.
//! The identity key is the one `mount_fixture_set` gives Confluence (`8a7f808a1`, what the
//! connection test stored); a Confluence answer carries no `X-AUSERNAME`: the identity check is the
//! `user/current` GET after a read and before a write.

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, UserKind, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::proto::exit_code;
use atlas_duck_registry::Product;
use serde_json::{Value, json};

use crate::harness::{CliRun, PAT_CANARY, Result, World, WorldOpts, opted_in};

/// The page of the fixture set, and its wire path under the context path.
const PAGE_ID: &str = "65537";
const PAGE_PATH: &str = "/rest/api/content/65537";
/// The `userKey` `MockDc::mount_fixture_set` answers `user/current` with for Confluence.
const WIKI_USER_KEY: &str = "8a7f808a1";

// ---- helpers -----------------------------------------------------------------------------------

/// A test home with one Confluence instance `wiki` (the only one of its product, so the CLI routes
/// `confluence ...` to it); the mock answers the fixture set: `user/current` (known), the applinks
/// manifest, page `65537` at version 7 and a search page.
async fn wiki_world() -> Result<World> {
    let mut world = World::new(WorldOpts::default())?;
    world
        .provision_store(&[("wiki", Product::Confluence)])
        .await?;
    Ok(world)
}

fn wiki(world: &World) -> Result<&MockDc> {
    world.mock("wiki").ok_or_else(|| "no mock for wiki".into())
}

/// The mock started over: no mount of the fixture set is left (a mount of the same path would not
/// win against the fixture's), only the identity and the applinks answers of the provisioning.
async fn restart_wiki(mock: &MockDc) {
    mock.server().reset().await;
    mock.confluence_user_current(UserKind::Known, TEST_USER, WIKI_USER_KEY)
        .await;
    mock.applinks_manifest(fixtures::CONFLUENCE_8_5_VERSION)
        .await;
}

/// One `atlas-duck <args>` run. What holds for every run: when stdout holds an envelope, the exit
/// code is the one the §4.3 matrix gives it, and the PAT canary is on neither stream.
async fn run(world: &World, args: &[&str]) -> Result<CliRun> {
    let r = world.cli(args).await?;
    for (name, text) in [("stdout", &r.stdout), ("stderr", &r.stderr)] {
        if text.contains(PAT_CANARY) {
            return Err(format!("the PAT canary is on {name} of {args:?}").into());
        }
    }
    if let Some(env) = &r.envelope {
        let want = exit_code(env);
        if r.exit != want {
            return Err(format!(
                "{args:?}: exit {} but the matrix says {want}: {}",
                r.exit, r.stdout
            )
            .into());
        }
    }
    Ok(r)
}

fn envelope(r: &CliRun) -> Result<&Envelope> {
    r.envelope
        .as_ref()
        .ok_or_else(|| format!("no envelope on stdout: {:?} / {:?}", r.stdout, r.stderr).into())
}

/// `data` walked along `path`.
fn data_at<'a>(env: &'a Envelope, path: &[&str]) -> Option<&'a Value> {
    let mut v = env.data.as_ref()?;
    for key in path {
        v = v.get(*key)?;
    }
    Some(v)
}

/// `error.code` as its wire name.
fn error_code(env: &Envelope) -> Result<Value> {
    let err = env.error.as_ref().ok_or("no error in the envelope")?;
    Ok(serde_json::to_value(err.code)?)
}

/// The bodies of the requests `method` `path` the mock received.
async fn sent(mock: &MockDc, method: &str, path: &str) -> Result<Vec<Value>> {
    let want = mock.path(path);
    let mut out = Vec::new();
    for req in mock.received().await {
        if req.method.as_str() == method && req.url.path() == want {
            out.push(serde_json::from_slice(&req.body)?);
        }
    }
    Ok(out)
}

/// How many requests of `method` the mock received at all.
async fn count_of(mock: &MockDc, method: &str) -> usize {
    mock.received()
        .await
        .iter()
        .filter(|r| r.method.as_str() == method)
        .count()
}

/// The queries (`name=value` pairs, decoded) of the `GET`s of `path`, in the order received.
async fn get_queries(mock: &MockDc, path: &str) -> Vec<Vec<(String, String)>> {
    let want = mock.path(path);
    mock.received()
        .await
        .iter()
        .filter(|r| r.method.as_str() == "GET" && r.url.path() == want)
        .map(|r| {
            r.url
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .collect()
}

/// Every audit record of the world, read after the app quit (the log needs the app gone).
async fn audit(world: &World) -> Result<Vec<(EventType, Value)>> {
    world.quit_app().await?;
    world.audit_records()
}

/// How many records of `kind` the log holds.
fn records_of(records: &[(EventType, Value)], kind: EventType) -> usize {
    records.iter().filter(|(t, _)| *t == kind).count()
}

/// The fixture page with `metadata.labels` (a whole, not full, list of one label `release`): the
/// content answer of the enrichment of a label write (PD-108).
fn labeled_page_json() -> Result<String> {
    let mut v: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE)?;
    v["metadata"] = json!({
        "labels": {
            "results": [{"prefix": "global", "name": "release", "id": "1", "label": "release"}],
            "start": 0, "limit": 200, "size": 1
        }
    });
    Ok(v.to_string())
}

/// The fixture page as the historical version 6 (stage 2 of a page update, PD-104).
fn historical_page_json() -> Result<String> {
    let mut v: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE)?;
    v["status"] = json!("historical");
    v["version"]["number"] = json!(6);
    v["body"]["storage"]["value"] = json!("<p>Check the build, first draft.</p>");
    Ok(v.to_string())
}

// ---- the flows ---------------------------------------------------------------------------------

/// The harness over the Confluence ops: a read is released, `confluence.page.get` answers with the
/// page, its body as Markdown (the default format, PD-100).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confluence_flows_smoke() -> Result<()> {
    if !opted_in("confluence_flows_smoke") {
        return Ok(());
    }
    let world = wiki_world().await?;
    let r = run(
        &world,
        &[
            "confluence",
            "page",
            "get",
            PAGE_ID,
            "--reason",
            "atlas-test:release",
        ],
    )
    .await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Released, "{}", r.stdout);
    assert_eq!(
        data_at(env, &["result", "body", "format"]),
        Some(&json!("markdown")),
        "{}",
        r.stdout
    );
    Ok(())
}

/// I-7 (plan review) / §7.6: a Markdown body goes out as storage (`<p><strong>done</strong></p>`),
/// with `version.number` = `base_version + 1`. The page is the fixture set's `65537` at version 7,
/// so the base version 7 is current: one enrichment GET, no stage 2, no conflict. The `PUT` is
/// answered by the fixture page (any 2xx with a JSON body is the declared success).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn md_page_update_sent_as_storage() -> Result<()> {
    if !opted_in("md_page_update_sent_as_storage") {
        return Ok(());
    }
    let world = wiki_world().await?;
    let mock = wiki(&world)?;
    let r = run(
        &world,
        &[
            "confluence",
            "page",
            "update",
            PAGE_ID,
            "--base-version",
            "7",
            "--body",
            "**done**",
            "--reason",
            "atlas-test:approve",
        ],
    )
    .await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Succeeded, "{}", r.stdout);
    let puts = sent(mock, "PUT", PAGE_PATH).await?;
    assert_eq!(puts.len(), 1, "{puts:?}");
    assert_eq!(
        puts[0]["body"]["storage"]["value"],
        json!("<p><strong>done</strong></p>")
    );
    assert_eq!(
        puts[0]["body"]["storage"]["representation"],
        json!("storage")
    );
    assert_eq!(puts[0]["version"]["number"], json!(8));
    assert_eq!(puts[0]["type"], json!("page"));
    let records = audit(&world).await?;
    assert_eq!(records_of(&records, EventType::WRITE_APPROVED), 1);
    assert_eq!(records_of(&records, EventType::WRITE_EXECUTED), 1);
    Ok(())
}

/// §7.6 / PD-98: a Markdown body that still holds a `page get` placeholder is refused at
/// validation: exit 2, `markdown_placeholders` with the kinds and counts (never the text), after
/// the request is received and before anything is fetched or queued: no enrichment GET, nothing
/// pending, no write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn placeholders_rejected_exit2() -> Result<()> {
    if !opted_in("placeholders_rejected_exit2") {
        return Ok(());
    }
    let world = wiki_world().await?;
    let mock = wiki(&world)?;
    let r = run(
        &world,
        &[
            "confluence",
            "page",
            "update",
            PAGE_ID,
            "--base-version",
            "7",
            "--body",
            "[macro: toc {}]",
            "--reason",
            "atlas-test:approve",
        ],
    )
    .await?;
    assert_eq!(r.exit, 2, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(
        error_code(env)?,
        json!("markdown_placeholders"),
        "{}",
        r.stdout
    );
    assert!(env.request_id.is_some(), "{}", r.stdout);
    let details = env
        .error
        .as_ref()
        .and_then(|e| e.details.as_ref())
        .ok_or_else(|| format!("no details in {}", r.stdout))?;
    assert_eq!(
        details.get("placeholders"),
        Some(&json!([{"kind": "macro", "count": 1}])),
        "{}",
        r.stdout
    );

    let list = run(&world, &["requests", "list", "--state", "pending"]).await?;
    assert_eq!(list.exit, 0, "{}", list.stdout);
    let rows = data_at(envelope(&list)?, &["requests"])
        .and_then(Value::as_array)
        .ok_or_else(|| format!("no request list in {}", list.stdout))?;
    assert!(rows.is_empty(), "{}", list.stdout);
    assert!(
        get_queries(mock, PAGE_PATH).await.is_empty(),
        "the page was fetched for a refused body"
    );
    assert_eq!(count_of(mock, "PUT").await, 0);
    let records = audit(&world).await?;
    assert_eq!(records_of(&records, EventType::REQUEST_RECEIVED), 1);
    assert_eq!(records_of(&records, EventType::REQUEST_REJECTED), 1);
    assert_eq!(records_of(&records, EventType::PREVIEW_SHOWN), 0);
    assert_eq!(records_of(&records, EventType::WRITE_APPROVED), 0);
    Ok(())
}

/// PD-104 / I-36 analog: an update from base version 6 of a page that is at version 7 reads the
/// current page (stage 1) and then the base version (stage 2: `version=6&status=historical`), the
/// conflict card holds it, and the human denies: exit 3, `denied`, nothing written. The mock keys
/// by path only, so the page path answers the current page once (stage 1) and the historical
/// version after that (stage 2); the queries of the two GETs are asserted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_update_conflict_denied_exit3() -> Result<()> {
    if !opted_in("page_update_conflict_denied_exit3") {
        return Ok(());
    }
    let world = wiki_world().await?;
    let mock = wiki(&world)?;
    restart_wiki(mock).await;
    mock.json_once(PAGE_PATH, 200, fixtures::CONFLUENCE_PAGE)
        .await;
    mock.json(PAGE_PATH, 200, &historical_page_json()?).await;
    let r = run(
        &world,
        &[
            "confluence",
            "page",
            "update",
            PAGE_ID,
            "--base-version",
            "6",
            "--body",
            "**done**",
            "--reason",
            "atlas-test:deny",
        ],
    )
    .await?;
    assert_eq!(r.exit, 3, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Denied, "{}", r.stdout);
    let gets = get_queries(mock, PAGE_PATH).await;
    assert_eq!(gets.len(), 2, "{gets:?}");
    let has = |q: &[(String, String)], name: &str, value: &str| {
        q.iter().any(|(k, v)| k == name && v == value)
    };
    assert!(has(
        &gets[0],
        "expand",
        "body.storage,version,space,ancestors"
    ));
    assert!(!has(&gets[0], "status", "historical"), "{gets:?}");
    assert!(has(&gets[1], "version", "6"), "{gets:?}");
    assert!(has(&gets[1], "status", "historical"), "{gets:?}");
    assert_eq!(count_of(mock, "PUT").await, 0);
    let records = audit(&world).await?;
    assert_eq!(records_of(&records, EventType::WRITE_DENIED), 1);
    assert_eq!(records_of(&records, EventType::WRITE_APPROVED), 0);
    Ok(())
}

/// §7.4 / PD-109 (plan review m-18): an upload of a filename the page already has, without
/// `replace`, is the collision hold; the human denies: exit 3, `denied`, no upload sent. The file
/// is written into the world's own temp dir and read by the CLI (`--content-base64-file` takes the
/// raw bytes and names the attachment by the file's name). The lookup answer is a whole, not full,
/// page (`limit` 50, one entry).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_collision_denied_exit3() -> Result<()> {
    if !opted_in("attachment_collision_denied_exit3") {
        return Ok(());
    }
    let world = wiki_world().await?;
    let mock = wiki(&world)?;
    let lookup = json!({
        "results": [{
            "id": "att3001", "type": "attachment", "status": "current", "title": "notes.txt",
            "version": {"number": 2}, "extensions": {"fileSize": 5}
        }],
        "start": 0, "limit": 50, "size": 1
    });
    mock.json(
        &format!("{PAGE_PATH}/child/attachment"),
        200,
        &lookup.to_string(),
    )
    .await;
    let file = world.root().join("notes.txt");
    std::fs::write(&file, b"hello")?;
    let file = file.to_str().ok_or("the temp path is not UTF-8")?;
    let r = run(
        &world,
        &[
            "confluence",
            "attachment",
            "upload",
            PAGE_ID,
            "--content-base64-file",
            file,
            "--reason",
            "atlas-test:deny",
        ],
    )
    .await?;
    assert_eq!(r.exit, 3, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Denied, "{}", r.stdout);
    let lookups = get_queries(mock, &format!("{PAGE_PATH}/child/attachment")).await;
    assert_eq!(lookups.len(), 1, "{lookups:?}");
    assert!(
        lookups[0]
            .iter()
            .any(|(k, v)| k == "filename" && v == "notes.txt"),
        "{lookups:?}"
    );
    assert_eq!(count_of(mock, "POST").await, 0);
    let records = audit(&world).await?;
    assert_eq!(records_of(&records, EventType::WRITE_DENIED), 1);
    assert_eq!(records_of(&records, EventType::WRITE_APPROVED), 0);
    Ok(())
}

/// U-31 (§7.4): the CQL the agent wrote is wrapped before it is sent: its filter clause is
/// parenthesized and the content-type filter appended, the one trailing `ORDER BY` kept after it.
/// The mock's `cql` query value is the rewritten text.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cql_rewrite_on_the_wire() -> Result<()> {
    if !opted_in("cql_rewrite_on_the_wire") {
        return Ok(());
    }
    let world = wiki_world().await?;
    let mock = wiki(&world)?;
    let r = run(
        &world,
        &[
            "confluence",
            "search",
            "space = DOC ORDER BY title",
            "--reason",
            "atlas-test:release",
        ],
    )
    .await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    assert_eq!(envelope(&r)?.status, Status::Released, "{}", r.stdout);
    let queries = get_queries(mock, "/rest/api/search").await;
    assert_eq!(queries.len(), 1, "{queries:?}");
    let cql: Vec<&str> = queries[0]
        .iter()
        .filter(|(k, _)| k == "cql")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(
        cql,
        ["(space = DOC) AND type in (page,blogpost,comment,attachment) ORDER BY title"],
        "{queries:?}"
    );
    Ok(())
}

/// §4.2 (PD-100): a page released as Markdown carries `meta.conversion` with `lossy` and the four
/// `lost` counters, from the committed release record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_get_markdown_released_with_conversion_meta() -> Result<()> {
    if !opted_in("page_get_markdown_released_with_conversion_meta") {
        return Ok(());
    }
    let world = wiki_world().await?;
    let r = run(
        &world,
        &[
            "confluence",
            "page",
            "get",
            PAGE_ID,
            "--reason",
            "atlas-test:release",
        ],
    )
    .await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Released, "{}", r.stdout);
    let meta = env
        .meta
        .as_ref()
        .ok_or_else(|| format!("no meta in {}", r.stdout))?;
    let lossy = meta.pointer("/conversion/lossy");
    assert!(
        lossy.is_some_and(Value::is_boolean),
        "no meta.conversion.lossy in {}",
        r.stdout
    );
    for counter in ["macros", "images", "links", "layouts"] {
        let at = format!("/conversion/lost/{counter}");
        assert!(
            meta.pointer(&at).is_some_and(Value::is_u64),
            "no meta{at} in {}",
            r.stdout
        );
    }
    Ok(())
}

/// §1.3 / PD-108: the only `DELETE`: `label remove` answers `204` with no body, the declared empty
/// success, and the receipt is `{}`. The enrichment reads the page's labels first (a content
/// answer with `metadata.labels`, a whole list), so the flow starts the mock over and mounts the
/// page with its label, the `DELETE` answer and the identity.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn label_remove_204_succeeded() -> Result<()> {
    if !opted_in("label_remove_204_succeeded") {
        return Ok(());
    }
    let world = wiki_world().await?;
    let mock = wiki(&world)?;
    restart_wiki(mock).await;
    mock.json(PAGE_PATH, 200, &labeled_page_json()?).await;
    mock.empty_for("DELETE", &format!("{PAGE_PATH}/label/release"), 204)
        .await;
    let r = run(
        &world,
        &[
            "confluence",
            "label",
            "remove",
            PAGE_ID,
            "--label",
            "release",
            "--reason",
            "atlas-test:approve",
        ],
    )
    .await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Succeeded, "{}", r.stdout);
    assert_eq!(data_at(env, &["receipt"]), Some(&json!({})), "{}", r.stdout);
    let deletes: Vec<_> = mock
        .received()
        .await
        .into_iter()
        .filter(|req| req.method.as_str() == "DELETE")
        .collect();
    assert_eq!(deletes.len(), 1, "{deletes:?}");
    assert_eq!(
        deletes[0].url.path(),
        mock.path(&format!("{PAGE_PATH}/label/release"))
    );
    assert!(deletes[0].body.is_empty());
    let records = audit(&world).await?;
    assert_eq!(records_of(&records, EventType::WRITE_APPROVED), 1);
    assert_eq!(records_of(&records, EventType::WRITE_EXECUTED), 1);
    Ok(())
}
