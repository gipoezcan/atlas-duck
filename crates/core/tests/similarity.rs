#![cfg(feature = "testing")]
//! "Possible duplicate" and "similar request" (Task 23, §5.6, L45) and the RF-4 seeding of the
//! similarity index from the log.

mod common;

use std::sync::Arc;
use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, fixtures};
use atlas_duck_audit::testing::FakeClock;
use atlas_duck_audit::{Clock, EventType, UtcInstant};
use atlas_duck_core::similarity::{SimRecord, SimilarityIndex, normalize_title, sim_key};
use atlas_duck_core::testing::{Channel, Harness};
use atlas_duck_preview::warning::WarningId;
use common::{TestError, TestResult, de, request_id};
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::path;

const ISSUE: &str = "jira.issue.get";
const CREATE: &str = "jira.issue.create";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

fn spec(id: &str) -> Result<&'static atlas_duck_registry::OperationSpec, TestError> {
    atlas_duck_registry::get(id).ok_or_else(|| format!("no op {id}").into())
}

async fn queued(h: &Harness, env: atlas_duck_ipc::envelope::Envelope) -> Result<String, TestError> {
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

fn create_params(summary: &str) -> Value {
    json!({ "project": "ABC", "issuetype": "Bug", "summary": summary, "body_format": "wiki" })
}

async fn createmeta_ok(mock: &MockDc) {
    mock.json(
        "/rest/api/2/issue/createmeta/ABC/issuetypes",
        200,
        fixtures::JIRA_CREATEMETA_ISSUETYPES,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn target_similarity_any_agent() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    for key in ["ABC-1", "ABC-2"] {
        mock.json(
            &format!("/rest/api/2/issue/{key}"),
            200,
            fixtures::JIRA_ISSUE,
        )
        .await;
    }
    let other = h.conn("another-agent").await?;
    let first = queued(&h, h.submit(ISSUE, json!({ "key": "ABC-1" })).await).await?;
    // Different params (`fields`), different agent: not a duplicate, still similar.
    let second = queued(
        &h,
        h.submit_with(
            &other,
            ISSUE,
            json!({ "key": "ABC-1", "fields": ["summary"] }),
            None,
        )
        .await,
    )
    .await?;
    let unrelated = queued(&h, h.submit(ISSUE, json!({ "key": "ABC-2" })).await).await?;
    let ap = h.approver();
    let row = ap.item(&second).ok_or("not queued")?;
    assert_eq!(row.similar_to.as_deref(), Some(first.as_str()));
    assert_eq!(row.possible_duplicate_of, None);
    assert!(row.caution_count >= 1, "the flag is a Caution");
    assert_eq!(
        ap.item(&first).ok_or("not queued")?.similar_to.as_deref(),
        Some(second.as_str())
    );
    assert_eq!(ap.item(&unrelated).ok_or("not queued")?.similar_to, None);
    // The preview carries the Caution text; `PREVIEW_SHOWN` names it.
    let preview = ap.open(&second).map_err(de)?.preview;
    let w = preview
        .warnings
        .iter()
        .find(|w| w.id == WarningId::SimilarRequest)
        .ok_or("no similar_request warning")?;
    assert_eq!(w.text, format!("similar to {first} pending"));
    let shown = h
        .events(&second)
        .await?
        .into_iter()
        .find(|(t, _)| *t == EventType::PREVIEW_SHOWN)
        .ok_or("no PREVIEW_SHOWN")?;
    assert!(
        shown.1["warning_ids"]
            .as_array()
            .is_some_and(|a| a.contains(&json!("similar_request")))
    );
    // Decided within 24 h: still similar, with the decision named.
    ap.release(&first).map_err(de)?;
    let row = ap.item(&second).ok_or("not queued")?;
    assert_eq!(row.similar_to.as_deref(), Some(first.as_str()));
    let preview = ap.open(&second).map_err(de)?.preview;
    let text = preview
        .warnings
        .iter()
        .find(|w| w.id == WarningId::SimilarRequest)
        .map(|w| w.text.clone())
        .ok_or("no warning")?;
    assert!(
        text.starts_with(&format!("similar to {first} released ")),
        "{text}"
    );
    // Opacity: no flag reaches an agent-facing channel.
    for r in h.capture().records() {
        if matches!(r.channel, Channel::Envelope | Channel::Progress) {
            assert!(!r.json.contains("similar to"), "{}", r.json);
            assert!(!r.json.contains("possible duplicate"), "{}", r.json);
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_similarity_normalized_title() -> TestResult {
    let h = Harness::jira().await?;
    createmeta_ok(jira(&h)?).await;
    let a = queued(&h, h.submit(CREATE, create_params("Fix  Login")).await).await?;
    let b = queued(&h, h.submit(CREATE, create_params(" fix login ")).await).await?;
    let c = queued(&h, h.submit(CREATE, create_params("Fix logout")).await).await?;
    let ap = h.approver();
    assert_eq!(
        ap.item(&b).ok_or("not queued")?.similar_to.as_deref(),
        Some(a.as_str())
    );
    assert_eq!(ap.item(&c).ok_or("not queued")?.similar_to, None);
    assert_eq!(normalize_title("  Fix \u{3000} LOGIN "), "fix login");
    Ok(())
}

#[test]
fn move_issues_shared_key() -> TestResult {
    let start = UtcInstant::parse_rfc3339_ms("2026-10-08T12:00:00.000Z").ok_or("instant")?;
    let index = SimilarityIndex::new(Arc::new(FakeClock::new(start)));
    let s = spec("jira.sprint.move_issues")?;
    let rec = |id: &str, params: Value| SimRecord {
        request_id: id.to_owned(),
        op_id: s.id.to_owned(),
        instance_id: "ins_1".to_owned(),
        params_sha256: Some(id.to_owned()),
        key: sim_key(s, &params),
    };
    index.on_submit(rec("req_1", json!({ "id": 5, "issues": ["A-1", "A-2"] })));
    let shared = rec("req_2", json!({ "id": 5, "issues": ["A-2"] }));
    let disjoint = rec("req_3", json!({ "id": 5, "issues": ["A-3", "A-4"] }));
    let other_sprint = rec("req_4", json!({ "id": 6, "issues": ["A-1", "A-2"] }));
    assert_eq!(
        index.similar_to(&shared).map(|h| h.request_id),
        Some("req_1".to_owned())
    );
    assert_eq!(index.similar_to(&disjoint), None);
    assert_eq!(index.similar_to(&other_sprint), None);
    // Backlog moves: any shared key.
    let b = spec("jira.backlog.move_issues")?;
    let backlog = |id: &str, issues: Value| SimRecord {
        request_id: id.to_owned(),
        op_id: b.id.to_owned(),
        instance_id: "ins_1".to_owned(),
        params_sha256: None,
        key: sim_key(b, &json!({ "issues": issues })),
    };
    index.on_submit(backlog("req_5", json!(["B-1", "B-2"])));
    assert!(
        index
            .similar_to(&backlog("req_6", json!(["B-2"])))
            .is_some()
    );
    assert!(
        index
            .similar_to(&backlog("req_7", json!(["B-3"])))
            .is_none()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn none_ops_never_similar() -> TestResult {
    let h = Harness::jira().await?;
    jira(&h)?
        .json("/rest/api/2/search", 200, fixtures::JIRA_SEARCH_PAGE)
        .await;
    let q = json!({ "jql": "project = ABC" });
    let a = queued(&h, h.submit("jira.search", q.clone()).await).await?;
    let b = queued(&h, h.submit("jira.search", q).await).await?;
    let c = queued(
        &h,
        h.submit("jira.search", json!({ "jql": "project = XYZ" }))
            .await,
    )
    .await?;
    let ap = h.approver();
    let row = ap.item(&b).ok_or("not queued")?;
    assert_eq!(row.similar_to, None);
    assert_eq!(row.possible_duplicate_of.as_deref(), Some(a.as_str()));
    let row = ap.item(&c).ok_or("not queued")?;
    assert_eq!((row.similar_to, row.possible_duplicate_of), (None, None));
    let preview = ap.open(&b).map_err(de)?.preview;
    let w = preview
        .warnings
        .iter()
        .find(|w| w.id == WarningId::PossibleDuplicate)
        .ok_or("no possible_duplicate warning")?;
    assert_eq!(w.text, format!("possible duplicate of {a}"));
    // A duplicate that is no longer pending no longer flags.
    ap.deny(&a, "dup").map_err(de)?;
    assert_eq!(ap.item(&b).ok_or("gone")?.possible_duplicate_of, None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf4_seeding_reads_create_and_move_payloads() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    createmeta_ok(mock).await;
    // The identity call of the approved create never answers: it stays mid-execution, as if
    // the app crashed there.
    Mock::given(path(mock.path("/rest/api/2/myself")))
        .respond_with(
            mock.response(200)
                .set_body_raw(
                    fixtures::jira_myself(TEST_USER, TEST_USER_KEY),
                    "application/json",
                )
                .set_delay(Duration::from_secs(60)),
        )
        .mount(mock.server())
        .await;
    let approved = queued(&h, h.submit(CREATE, create_params("Fix login")).await).await?;
    let open = queued(&h, h.submit(CREATE, create_params("Add dark mode")).await).await?;
    let unreadable = queued(&h, h.submit(CREATE, create_params("Third thing")).await).await?;
    h.approver().approve(&approved).map_err(de)?;
    // The third request's `REQUEST_RECEIVED` payload can no longer be decrypted.
    let seq = h
        .store()
        .headers_for_request(&unreadable)?
        .first()
        .map(|e| e.seq)
        .ok_or("no record")?;
    h.plan().fail_read_payload(seq);

    let s = spec(CREATE)?;
    let instance_id = h.instance("jira-main").ok_or("no instance")?.id.clone();
    let resubmitted = |summary: &str| SimRecord {
        request_id: "req_resubmitted".to_owned(),
        op_id: CREATE.to_owned(),
        instance_id: instance_id.clone(),
        params_sha256: None,
        key: sim_key(s, &create_params(summary)),
    };
    let clock: Arc<dyn Clock> = h.clock().clone();

    // Seeded before reconciliation: both are still open.
    let index = SimilarityIndex::seed(&*h.port(), clock.clone())?;
    assert_eq!(index.seed_skipped(), 1);
    let hit = index
        .similar_to(&resubmitted("FIX LOGIN"))
        .ok_or("no hit")?;
    assert_eq!(
        (hit.request_id.as_str(), hit.when.as_str()),
        (approved.as_str(), "pending")
    );
    let hit = index
        .similar_to(&resubmitted("add dark mode"))
        .ok_or("no hit")?;
    assert_eq!(
        (hit.request_id.as_str(), hit.when.as_str()),
        (open.as_str(), "pending")
    );
    assert_eq!(index.similar_to(&resubmitted("Third thing")), None);

    // After the crash reconciliation (§11.3): the approved create is `outcome_unknown`, the
    // never-approved one abandoned (never decided: no longer a hit).
    h.store().reconcile_after_crash()?;
    let index = SimilarityIndex::seed(&*h.port(), clock)?;
    let hit = index
        .similar_to(&resubmitted("Fix login"))
        .ok_or("no hit")?;
    assert_eq!(
        (hit.request_id.as_str(), hit.when.as_str()),
        (approved.as_str(), "outcome unknown")
    );
    assert_eq!(hit.text(), format!("similar to {approved} outcome unknown"));
    assert_eq!(index.similar_to(&resubmitted("Add dark mode")), None);
    Ok(())
}
