#![cfg(feature = "testing")]
//! The per-instance Jira field-name cache (Task 8, PD-46, §7.3, §8.3 `SYSTEM_FETCH`): every fill
//! is `SYSTEM_FETCH {purpose: metadata_cache}` start → `GET /rest/api/2/field` → result, outside
//! any request; a preview never waits for it; a failed fill keeps the old map.

mod common;

use std::time::{Duration, Instant};

use atlas_duck_atlassian::testing::{MockDc, TEST_PAT, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_core::Confirm;
use atlas_duck_core::metadata::{FIELD_CACHE_TTL, FieldNames, UNKNOWN_FIELD_SUFFIX, field_label};
use atlas_duck_core::testing::{AuditRecord, FaultPlan, Harness, JIRA_FIELDS};
use atlas_duck_ipc::envelope::Status;
use common::{TestError, TestResult, de, request_id};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const ISSUE: &str = "jira.issue.get";
const FIELD: &str = "/rest/api/2/field";
/// A later answer of the field list: `customfield_10200` is now known.
const FIELDS_WITH_TEAM: &str = r#"[{"id":"summary","name":"Summary","custom":false},{"id":"customfield_10100","name":"Story Points","custom":true},{"id":"customfield_10200","name":"Team","custom":true}]"#;

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

/// The `metadata_cache` records, in seq order.
async fn cache_records(h: &Harness) -> Result<Vec<AuditRecord>, TestError> {
    Ok(h.audit_records()
        .await?
        .into_iter()
        .filter(|r| {
            r.event_type == EventType::SYSTEM_FETCH && r.payload["purpose"] == "metadata_cache"
        })
        .collect())
}

/// How many fills started (committed `phase: start` records).
async fn fills(h: &Harness) -> Result<usize, TestError> {
    Ok(cache_records(h)
        .await?
        .iter()
        .filter(|r| r.payload["phase"] == "start")
        .count())
}

/// The requests the mock received on `GET /rest/api/2/field`.
async fn field_hits(mock: &MockDc) -> usize {
    let field = mock.path(FIELD);
    mock.received()
        .await
        .iter()
        .filter(|r| r.url.path() == field && r.method.as_str() == "GET")
        .count()
}

fn name_of<'a>(names: &'a Option<std::sync::Arc<FieldNames>>, id: &str) -> Option<&'a str> {
    names.as_ref().and_then(|n| n.get(id))
}

/// An issue that carries `customfield_10200`.
fn issue_with_team() -> String {
    let mut issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE).unwrap_or(Value::Null);
    issue["fields"]["customfield_10200"] = json!({ "value": "Platform" });
    issue.to_string()
}

/// Submits `jira.issue.get` for ABC-1 and waits until its preview can be built.
async fn queued_read(h: &Harness) -> Result<String, TestError> {
    let env = h.submit(ISSUE, json!({ "key": "ABC-1" })).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

/// Waits until `n` fills have started (the start record commits before the GET leaves).
async fn fills_reach(h: &Harness, n: usize) -> Result<(), TestError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while fills(h).await? < n {
        if Instant::now() > deadline {
            return Err(format!("only {} fills started, wanted {n}", fills(h).await?).into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_cache_fill_is_covered_by_system_fetch() -> TestResult {
    let h = Harness::jira().await?;
    assert!(h.field_cache_filled().await, "the start fill never ended");
    let mock = jira(&h)?;
    let all = h.audit_records().await?;
    let app_start = all
        .iter()
        .find(|r| r.event_type == EventType::APP_START)
        .ok_or("no APP_START")?;
    let recs = cache_records(&h).await?;
    let [start, result] = recs.as_slice() else {
        return Err(format!("{} metadata_cache records", recs.len()).into());
    };
    // Outside any request, after APP_START, start before result, one fetch id.
    assert_eq!(
        (start.request_id.as_deref(), result.request_id.as_deref()),
        (None, None)
    );
    assert!(app_start.seq < start.seq && start.seq < result.seq);
    assert_eq!(start.payload["phase"], "start");
    assert_eq!(
        start.payload["planned"],
        json!([{ "method": "GET", "path": FIELD }])
    );
    assert_eq!(result.payload["phase"], "result");
    assert_eq!(result.payload["fetch_id"], start.payload["fetch_id"]);
    assert_eq!(result.payload["method"], "GET");
    assert_eq!(result.payload["path"], json!(mock.path(FIELD)));
    assert_eq!(result.payload["status"], 200);
    let id = h.instance("jira-main").ok_or("no instance")?.id.clone();
    assert_eq!(start.payload["instance_id"], json!(id));
    // One hit, and the map it carried.
    assert_eq!(field_hits(mock).await, 1);
    let names = h.field_names("jira-main");
    assert_eq!(name_of(&names, "customfield_10100"), Some("Story Points"));
    assert_eq!(name_of(&names, "summary"), Some("Summary"));
    assert_eq!(name_of(&names, "customfield_10200"), None);
    assert_eq!(h.field_cache_failures("jira-main"), 0);

    // Audit before effect: when the start record cannot commit, the GET never leaves.
    let plan = FaultPlan::new();
    plan.fail_nth(EventType::SYSTEM_FETCH, 1);
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .start()
        .await?;
    assert!(h.field_cache_filled().await);
    assert_eq!(plan.attempts(EventType::SYSTEM_FETCH), 1);
    assert_eq!(
        field_hits(jira(&h)?).await,
        0,
        "no GET without its start record"
    );
    assert!(h.field_names("jira-main").is_none());
    assert_eq!(h.field_cache_failures("jira-main"), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_cache_never_under_a_request_id() -> TestResult {
    let h = Harness::jira().await?;
    assert!(h.field_cache_filled().await);
    let mock = jira(&h)?;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.json(FIELD, 200, FIELDS_WITH_TEAM).await;
    // The map is stale: building this read's preview refreshes it during the flow.
    h.clock().advance(FIELD_CACHE_TTL + Duration::from_secs(60));
    let id = queued_read(&h).await?;
    h.approver().open(&id).map_err(de)?;
    h.approver().release(&id).map_err(de)?;
    assert_eq!(h.await_(&id, 10_000).await.status, Status::Released);
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 2, "the start fill and the refresh");
    assert_eq!(
        name_of(&h.field_names("jira-main"), "customfield_10200"),
        Some("Team")
    );
    // No record of the read names the field list; no cache record names a request.
    for (t, payload) in h.events(&id).await? {
        assert_ne!(t, EventType::SYSTEM_FETCH);
        assert!(
            !payload.to_string().contains("rest/api/2/field"),
            "{t:?} names the field list"
        );
    }
    for r in h.events_of(EventType::PREVIEW_FETCH).await? {
        assert!(!r["path"].to_string().contains("rest/api/2/field"));
    }
    for r in cache_records(&h).await? {
        assert_eq!(r.request_id, None);
        assert_eq!(r.op_id, None);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_cache_never_blocks_preview() -> TestResult {
    let h = Harness::jira().await?;
    assert!(h.field_cache_filled().await);
    let mock = jira(&h)?;
    mock.json("/rest/api/2/issue/ABC-1", 200, &issue_with_team())
        .await;
    mock.json_delayed(FIELD, 200, FIELDS_WITH_TEAM, Duration::from_secs(10))
        .await;
    h.clock().advance(FIELD_CACHE_TTL + Duration::from_secs(60));
    let t0 = Instant::now();
    let id = queued_read(&h).await?;
    let delivery = h.approver().open(&id).map_err(de)?;
    assert!(
        t0.elapsed() < Duration::from_secs(3),
        "the preview waited {:?}",
        t0.elapsed()
    );
    assert!(delivery.preview.approvable);
    // The refresh is running (its start record committed) while the preview was built from the
    // map cached before it: `customfield_10200` is not in it.
    fills_reach(&h, 2).await?;
    assert!(!h.field_cache_filled_within(Duration::from_millis(50)).await);
    let names = h.field_names("jira-main");
    assert_eq!(name_of(&names, "customfield_10200"), None);
    assert_eq!(
        field_label(names.as_deref(), "customfield_10200"),
        "customfield_10200 (unknown field)"
    );
    assert_eq!(
        field_label(names.as_deref(), "customfield_10100"),
        "Story Points"
    );
    assert_eq!(field_label(None, "summary"), "summary");
    assert_eq!(UNKNOWN_FIELD_SUFFIX, " (unknown field)");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_cache_failure_keeps_old_map() -> TestResult {
    let h = Harness::jira().await?;
    assert!(h.field_cache_filled().await);
    let mock = jira(&h)?;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    // Two failing answers, then a good one.
    for _ in 0..2 {
        mock.json_once(FIELD, 500, r#"{"errorMessages":["boom"]}"#)
            .await;
    }
    mock.json(FIELD, 200, FIELDS_WITH_TEAM).await;
    assert_eq!(h.field_cache_failures("jira-main"), 0);
    h.clock().advance(FIELD_CACHE_TTL + Duration::from_secs(60));
    let id = queued_read(&h).await?;
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 2);
    let last = cache_records(&h).await?.pop().ok_or("no record")?;
    assert_eq!(
        (
            last.payload["phase"].clone(),
            last.payload["status"].clone()
        ),
        (json!("result"), json!(500))
    );
    // The old map still resolves; the failure was logged once.
    let names = h.field_names("jira-main");
    assert_eq!(name_of(&names, "customfield_10100"), Some("Story Points"));
    assert_eq!(h.field_cache_failures("jira-main"), 1);
    // A failed fill is retried after a 5 min backoff, not on every preview build and not only
    // after the hour (lead ruling, T8 review M-4): nothing at once or 4 min later, one at 5 min.
    h.approver().open(&id).map_err(de)?;
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 2);
    assert_eq!(h.field_cache_failures("jira-main"), 1);
    h.clock().advance(Duration::from_secs(4 * 60));
    h.approver().open(&id).map_err(de)?;
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 2, "retried within the backoff");
    h.clock().advance(Duration::from_secs(60));
    h.approver().open(&id).map_err(de)?;
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 3, "not retried after the backoff");
    assert_eq!(h.field_cache_failures("jira-main"), 2);
    // After a success the hour counts again: 5 min later nothing starts.
    h.clock().advance(Duration::from_secs(5 * 60));
    h.approver().open(&id).map_err(de)?;
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 4);
    assert_eq!(
        name_of(&h.field_names("jira-main"), "customfield_10200"),
        Some("Team")
    );
    h.clock().advance(Duration::from_secs(5 * 60));
    h.approver().open(&id).map_err(de)?;
    assert!(h.field_cache_filled().await);
    assert_eq!(
        fills(&h).await?,
        4,
        "refreshed within the hour after a success"
    );
    Ok(())
}

/// The field list is untrusted: at most 20 000 entries are kept and a name is cut to 256 chars
/// (T8 review I-2), whatever the 32 MiB response cap lets through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_cache_caps_untrusted_content() -> TestResult {
    let h = Harness::jira().await?;
    assert!(h.field_cache_filled().await);
    let mock = jira(&h)?;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.json(
        FIELD,
        200,
        &oversized_field_list(20_050, 100_000).to_string(),
    )
    .await;
    h.clock().advance(FIELD_CACHE_TTL + Duration::from_secs(60));
    queued_read(&h).await?;
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 2);
    let names = h.field_names("jira-main").ok_or("no map")?;
    assert_eq!(names.len(), 20_000);
    let long = names.get("customfield_0").ok_or("first entry dropped")?;
    assert_eq!(long.chars().count(), 256);
    assert!(long.ends_with('…'));
    assert_eq!(names.get("customfield_19999"), Some("Field 19999"));
    assert_eq!(names.get("customfield_20000"), None);
    assert_eq!(names.capped(), 51, "50 dropped, 1 cut");
    assert_eq!(h.field_cache_failures("jira-main"), 0);
    Ok(())
}

/// `n` fields `customfield_0..n`; the first one's name is `long` chars.
fn oversized_field_list(n: usize, long: usize) -> Value {
    Value::Array(
        (0..n)
            .map(|i| {
                let name = if i == 0 {
                    "x".repeat(long)
                } else {
                    format!("Field {i}")
                };
                json!({ "id": format!("customfield_{i}"), "name": name, "custom": true })
            })
            .collect(),
    )
}

/// A new origin is another server: the old server's names are dropped with the client
/// (T8 review M-5), so its custom ids are never labelled with them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_cache_forgotten_on_origin_change() -> TestResult {
    let h = Harness::jira().await?;
    assert!(h.field_cache_filled().await);
    assert!(h.field_names("jira-main").is_some());
    let second = MockDc::start(atlas_duck_atlassian::Product::Jira, "/moved").await;
    h.confirmer().push(Confirm::Ok);
    h.instances()
        .change_base_url("jira-main", &second.base_url())?;
    assert!(h.field_names("jira-main").is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_cache_refreshes_after_ttl() -> TestResult {
    let h = Harness::jira().await?;
    assert!(h.field_cache_filled().await);
    let mock = jira(&h)?;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.json(FIELD, 200, FIELDS_WITH_TEAM).await;
    // Within the TTL a preview build fetches nothing.
    h.clock().advance(FIELD_CACHE_TTL / 2);
    let id = queued_read(&h).await?;
    h.approver().open(&id).map_err(de)?;
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 1);
    assert_eq!(field_hits(mock).await, 1);
    assert_eq!(
        name_of(&h.field_names("jira-main"), "customfield_10200"),
        None
    );
    // Past it, the next preview build (the approver opening it again) refreshes the map.
    h.clock()
        .advance(FIELD_CACHE_TTL / 2 + Duration::from_secs(1));
    h.approver().open(&id).map_err(de)?;
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 2);
    assert_eq!(field_hits(mock).await, 2);
    assert_eq!(
        name_of(&h.field_names("jira-main"), "customfield_10200"),
        Some("Team")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fill_after_set_token() -> TestResult {
    let h = Harness::jira().await?;
    assert!(h.field_cache_filled().await);
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.jira_server_info(fixtures::JIRA_9_12_VERSION).await;
    mock.json(FIELD, 200, FIELDS_WITH_TEAM).await;
    assert_eq!(fills(&h).await?, 1);
    // A replaced token: one fill, in the background, with the new map.
    h.instances()
        .set_token("jira-main", secrecy::SecretString::from(TEST_PAT), None)
        .await?;
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 2);
    assert_eq!(
        name_of(&h.field_names("jira-main"), "customfield_10200"),
        Some("Team")
    );
    // A passing re-test fills too.
    h.instances().retest_token("jira-main").await?;
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 3);
    Ok(())
}

/// At most one fill per instance runs; a token set during a fill gets one more run after it
/// (the running one may still carry the old token's answer).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_set_during_a_fill_runs_one_more_after_it() -> TestResult {
    let h = Harness::jira().await?;
    assert!(h.field_cache_filled().await);
    let mock = jira(&h)?;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.jira_server_info(fixtures::JIRA_9_12_VERSION).await;
    mock.json_delayed(FIELD, 200, FIELDS_WITH_TEAM, Duration::from_millis(800))
        .await;
    h.clock().advance(FIELD_CACHE_TTL + Duration::from_secs(60));
    queued_read(&h).await?;
    fills_reach(&h, 2).await?;
    // The refresh is in flight: the token's fill waits for it, then runs once.
    h.instances()
        .set_token("jira-main", secrecy::SecretString::from(TEST_PAT), None)
        .await?;
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 3);
    assert_eq!(field_hits(mock).await, 3);
    let recs = cache_records(&h).await?;
    let phases: Vec<&str> = recs
        .iter()
        .filter_map(|r| r.payload["phase"].as_str())
        .collect();
    // Never two at once: each start is followed by its own result.
    assert_eq!(
        phases,
        ["start", "result", "start", "result", "start", "result"]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_cache_identity_failure_rechecks_and_keeps_map() -> TestResult {
    let h = Harness::jira().await?;
    assert!(h.field_cache_filled().await);
    let mock = jira(&h)?;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    // The field list answered under another user's name: the M3 per-response check fails.
    Mock::given(method("GET"))
        .and(path(mock.path(FIELD)))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-AUSERNAME", "mallory")
                .set_body_raw(FIELDS_WITH_TEAM, "application/json"),
        )
        .mount(mock.server())
        .await;
    h.clock().advance(FIELD_CACHE_TTL + Duration::from_secs(60));
    queued_read(&h).await?;
    assert!(h.field_cache_filled().await);
    let recs = h.events_of(EventType::SYSTEM_FETCH).await?;
    let purposes: Vec<&str> = recs
        .iter()
        .filter(|p| p["phase"] == "start")
        .filter_map(|p| p["purpose"].as_str())
        .collect();
    assert_eq!(
        purposes,
        ["metadata_cache", "metadata_cache", "token_recheck"]
    );
    let names = h.field_names("jira-main");
    assert_eq!(name_of(&names, "customfield_10100"), Some("Story Points"));
    assert_eq!(
        name_of(&names, "customfield_10200"),
        None,
        "map not replaced"
    );
    assert_eq!(h.field_cache_failures("jira-main"), 1);
    Ok(())
}

/// Only a Jira instance in state `ok` fills: an unconfirmed one sends nothing and records
/// nothing (the start filter and the fill's own state check), nor does a Confluence instance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_fill_unless_jira_and_ok() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confluence("wiki")
        .unconfirmed()
        .start()
        .await?;
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 0);
    assert_eq!(field_hits(jira(&h)?).await, 0);
    assert!(h.field_names("jira-main").is_none());
    let h = Harness::confluence().await?;
    assert!(h.field_cache_filled().await);
    assert_eq!(fills(&h).await?, 0);
    let wiki = h.mock("wiki").ok_or("no wiki mock")?;
    assert!(wiki.received().await.is_empty());
    Ok(())
}

#[test]
fn field_names_parse_and_label() {
    let names = FieldNames::parse(br#"[{"id":"customfield_1","name":"Team"},{"id":"x"},{"name":"y"},7,{"id":"summary","name":"Summary"}]"#);
    let names = names.as_ref();
    assert_eq!(names.and_then(|n| n.get("customfield_1")), Some("Team"));
    assert_eq!(names.and_then(|n| n.get("summary")), Some("Summary"));
    assert_eq!(names.map(FieldNames::len), Some(2));
    // Not a JSON array: no map.
    assert!(FieldNames::parse(br#"{"id":"a","name":"b"}"#).is_none());
    assert!(FieldNames::parse(b"not json").is_none());
    // Names are display-escaped when shown.
    let odd =
        FieldNames::parse("[{\"id\":\"customfield_2\",\"name\":\"Te\u{202e}am\"}]".as_bytes());
    assert_eq!(field_label(odd.as_ref(), "customfield_2"), "Te⟨U+202E⟩am");
    assert_eq!(
        field_label(odd.as_ref(), "customfield_3"),
        "customfield_3 (unknown field)"
    );
    assert_eq!(field_label(odd.as_ref(), "labels"), "labels");
    assert!(JIRA_FIELDS.contains("customfield_10100"));
}

/// A label is one line: `\n`, `\r` and `\t` in a name are shown as escapes like every other
/// flagged char (T8 review M-1), so a name cannot pass for a second table row.
#[test]
fn field_label_is_one_line() {
    let names = FieldNames::parse(
        br#"[{"id":"customfield_1","name":"Story Points\nAssignee: admin"},{"id":"customfield_2","name":"a\r\tb"}]"#,
    );
    assert_eq!(
        field_label(names.as_ref(), "customfield_1"),
        "Story Points⟨U+000A⟩Assignee: admin"
    );
    assert_eq!(
        field_label(names.as_ref(), "customfield_2"),
        "a⟨U+000D⟩⟨U+0009⟩b"
    );
    // A literal escape in a name stays distinguishable from a neutralised newline.
    let lit = FieldNames::parse("[{\"id\":\"customfield_3\",\"name\":\"⟨U+000A⟩\"}]".as_bytes());
    assert_eq!(
        field_label(lit.as_ref(), "customfield_3"),
        "⟨U+27E8⟩U+000A⟨U+27E9⟩"
    );
}

/// `parse` caps what it keeps: 20 000 entries (answer order), names cut to 256 chars with `…`,
/// ids over 256 chars dropped (T8 review I-2).
#[test]
fn field_names_parse_caps() {
    let names = FieldNames::parse(
        oversized_field_list(25_000, 1_000_000)
            .to_string()
            .as_bytes(),
    )
    .unwrap_or_default();
    assert_eq!(names.len(), 20_000);
    let long = names.get("customfield_0").unwrap_or_default();
    assert_eq!(long.chars().count(), 256);
    assert!(long.ends_with('…'));
    assert_eq!(names.get("customfield_24999"), None);
    assert_eq!(names.capped(), 5_001, "5 000 dropped, 1 cut");
    // A name of exactly 256 chars is kept as it is; multi-byte chars are cut on a char boundary.
    let exact = "é".repeat(256);
    let over = "é".repeat(257);
    let body = json!([
        { "id": "customfield_1", "name": exact },
        { "id": "customfield_2", "name": over },
        { "id": "c".repeat(257), "name": "Too long an id" },
    ]);
    let names = FieldNames::parse(body.to_string().as_bytes()).unwrap_or_default();
    assert_eq!(names.get("customfield_1"), Some(exact.as_str()));
    let cut = names.get("customfield_2").unwrap_or_default();
    assert_eq!(cut.chars().count(), 256);
    assert!(cut.starts_with(&"é".repeat(255)) && cut.ends_with('…'));
    assert_eq!(names.len(), 2, "the over-long id is dropped");
    assert_eq!(names.capped(), 2);
    // The redacting `Debug` shows counts only.
    assert_eq!(format!("{names:?}"), "FieldNames(2 fields, 2 capped)");
}
