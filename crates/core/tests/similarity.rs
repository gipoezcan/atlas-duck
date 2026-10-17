#![cfg(feature = "testing")]
//! "Possible duplicate" and "similar request" (Task 23, §5.6, L45) and the RF-4 seeding of the
//! similarity index from the log.

mod common;

use std::sync::Arc;
use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::testing::FakeClock;
use atlas_duck_audit::{Clock, EventType, UtcInstant};
use atlas_duck_core::similarity::{SimRecord, SimilarityIndex, normalize_title, sim_key};
use atlas_duck_core::testing::{Channel, Harness};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::warning::WarningId;
use common::{TestError, TestResult, de, request_id};
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path};

const ISSUE: &str = "jira.issue.get";
const CREATE: &str = "jira.issue.create";
const COMMENT: &str = "jira.comment.add";

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

/// The three enrichment answers of a create in `ABC` (Task 12: projects, issue types, fields).
async fn createmeta_ok(mock: &MockDc) {
    common::jira::mount_create_stages(mock).await;
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

    // A crash and a restart (Task 28): `Core::start` reconciles the log (§11.3) and then seeds
    // its own index. The approved create is `outcome_unknown`, the never-approved one abandoned
    // (never decided: no longer a hit), and so is the one whose payload cannot be read.
    let mut h = h;
    h.crash_and_restart().await?;
    assert_eq!(h.core().startup_notice().len(), 1);
    let index = h.engine().similarity();
    // (The unreadable request was abandoned by the reconciliation: a gone request is not read.)
    assert_eq!(index.seed_skipped(), 0);
    let hit = index
        .similar_to(&resubmitted("Fix login"))
        .ok_or("no hit")?;
    assert_eq!(
        (hit.request_id.as_str(), hit.when.as_str()),
        (approved.as_str(), "outcome unknown")
    );
    assert_eq!(hit.text(), format!("similar to {approved} outcome unknown"));
    assert_eq!(index.similar_to(&resubmitted("Add dark mode")), None);
    // The agent resubmits the identical create: the queue item names the first one, as a
    // Caution (still approvable), and the preview says so.
    let again = queued(&h, h.submit(CREATE, create_params("Fix login")).await).await?;
    let row = h.approver().item(&again).ok_or("not queued")?;
    assert_eq!(row.similar_to.as_deref(), Some(approved.as_str()));
    assert!(row.approvable && row.caution_count >= 1);
    let preview = h.approver().open(&again).map_err(de)?.preview;
    let w = preview
        .warnings
        .iter()
        .find(|w| w.id == WarningId::SimilarRequest)
        .ok_or("no similar_request warning")?;
    assert_eq!(w.text, format!("similar to {approved} outcome unknown"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf4_seeding_reads_target_payloads_of_reads_and_writes() -> TestResult {
    // The move ops' seeding (their keys come from the decrypted payload, not this column) is
    // `rf4_seeding_reads_move_payloads`.
    let h = Harness::jira().await?;
    jira(&h)?
        .json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    let read = queued(&h, h.submit(ISSUE, json!({ "key": "ABC-1" })).await).await?;
    let comment_params = json!({ "key": "ABC-1", "body": "Done.", "body_format": "wiki" });
    let write = queued(&h, h.submit(COMMENT, comment_params.clone()).await).await?;
    let instance_id = h.instance("jira-main").ok_or("no instance")?.id.clone();
    let record = |op: &str, params: Value| -> Result<SimRecord, TestError> {
        Ok(SimRecord {
            request_id: "req_resubmitted".to_owned(),
            op_id: op.to_owned(),
            instance_id: instance_id.clone(),
            params_sha256: None,
            key: sim_key(spec(op)?, &params),
        })
    };
    let clock: Arc<dyn Clock> = h.clock().clone();
    let index = SimilarityIndex::seed(&*h.port(), clock)?;
    assert_eq!(index.seed_skipped(), 0);
    let hit = |r: &SimRecord| index.similar_to(r).map(|x| (x.request_id, x.when));
    let pending = |id: &String| Some((id.clone(), "pending".to_owned()));
    // `Target`: from the plaintext column, no decryption.
    assert_eq!(
        hit(&record(ISSUE, json!({ "key": "ABC-1" }))?),
        pending(&read)
    );
    assert_eq!(hit(&record(ISSUE, json!({ "key": "ABC-2" }))?), None);
    assert_eq!(hit(&record(COMMENT, comment_params)?), pending(&write));
    let other = json!({ "key": "ABC-2", "body": "Done.", "body_format": "wiki" });
    assert_eq!(hit(&record(COMMENT, other)?), None);
    Ok(())
}

const SPRINT_MOVE: &str = "jira.sprint.move_issues";
const BACKLOG_MOVE: &str = "jira.backlog.move_issues";

/// RF-4 (Task 18, the carried M3 T23 test): after a crash and a restart over the reopened store,
/// the index is seeded from the decrypted `REQUEST_RECEIVED` params of the move ops, so a move
/// that shares an issue key with an executed one (a sprint move: into the same sprint) is
/// "similar" to it; a disjoint move, or one into another sprint, is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf4_seeding_reads_move_payloads() -> TestResult {
    let mut h = Harness::jira().await?;
    {
        let mock = jira(&h)?;
        mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
            .await;
        for id in [7u64, 8] {
            common::jira::mount_sprint(
                mock,
                id,
                &json!({"id": id, "name": format!("Sprint {id}"), "state": "active"}),
            )
            .await;
        }
        for p in [
            "/rest/agile/1.0/sprint/7/issue",
            "/rest/agile/1.0/sprint/8/issue",
            "/rest/agile/1.0/backlog/issue",
        ] {
            Mock::given(method("POST"))
                .and(path(mock.path(p)))
                .respond_with(mock.response(204))
                .mount(mock.server())
                .await;
        }
    }
    let mut executed = Vec::new();
    for (op, params) in [
        (SPRINT_MOVE, json!({"id": 7, "issues": ["ABC-1", "ABC-2"]})),
        (BACKLOG_MOVE, json!({"issues": ["XYZ-1", "XYZ-2"]})),
    ] {
        let id = queued(&h, h.submit(op, params).await).await?;
        h.approver().approve(&id).map_err(de)?;
        let env = h.await_(&id, 10_000).await;
        assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
        executed.push(id);
    }
    let (sprint_move, backlog_move) = (executed[0].clone(), executed[1].clone());

    h.reopen_and_restart().await?;
    assert_eq!(h.engine().similarity().seed_skipped(), 0);
    let similar =
        |text: &str, first: &str| text.starts_with(&format!("similar to {first} executed "));
    // A sprint move sharing ABC-2, into the same sprint: names the first request.
    let again = queued(
        &h,
        h.submit(SPRINT_MOVE, json!({"id": 7, "issues": ["ABC-2", "ABC-3"]}))
            .await,
    )
    .await?;
    let row = h.approver().item(&again).ok_or("not queued")?;
    assert_eq!(row.similar_to.as_deref(), Some(sprint_move.as_str()));
    assert!(row.caution_count >= 1);
    let text = similar_text(&h, &again).await?;
    assert!(similar(&text, &sprint_move), "{text}");
    // A backlog move sharing XYZ-1 likewise.
    let back = queued(
        &h,
        h.submit(BACKLOG_MOVE, json!({"issues": ["XYZ-1"]})).await,
    )
    .await?;
    assert_eq!(
        h.approver()
            .item(&back)
            .ok_or("not queued")?
            .similar_to
            .as_deref(),
        Some(backlog_move.as_str())
    );
    let text = similar_text(&h, &back).await?;
    assert!(similar(&text, &backlog_move), "{text}");
    // Another sprint, or no shared key: not similar to the seeded moves.
    let other_sprint = queued(
        &h,
        h.submit(SPRINT_MOVE, json!({"id": 8, "issues": ["ABC-1"]}))
            .await,
    )
    .await?;
    assert_eq!(
        h.approver()
            .item(&other_sprint)
            .ok_or("not queued")?
            .similar_to,
        None
    );
    let disjoint = queued(
        &h,
        h.submit(BACKLOG_MOVE, json!({"issues": ["QQ-9"]})).await,
    )
    .await?;
    assert_eq!(
        h.approver().item(&disjoint).ok_or("not queued")?.similar_to,
        None
    );
    Ok(())
}

/// `HH:MM` of the fake clock's now, shifted by `minutes`.
fn clock_hhmm(h: &Harness, minutes: i64) -> Result<String, TestError> {
    let ts = h.clock().now_utc().to_rfc3339_ms();
    let hour: i64 = ts.get(11..13).ok_or("timestamp")?.parse()?;
    let min: i64 = ts.get(14..16).ok_or("timestamp")?.parse()?;
    let total = (hour * 60 + min + minutes).rem_euclid(24 * 60);
    Ok(format!("{:02}:{:02}", total / 60, total % 60))
}

async fn similar_text(h: &Harness, id: &str) -> Result<String, TestError> {
    let preview = h.approver().open(id).map_err(de)?.preview;
    let w = preview
        .warnings
        .iter()
        .find(|w| w.id == WarningId::SimilarRequest)
        .ok_or("no similar_request warning")?;
    Ok(w.text.clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn similarity_text_uses_local_offset() -> TestResult {
    let h = Harness::jira().await?;
    jira(&h)?
        .json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    let first = queued(&h, h.submit(ISSUE, json!({ "key": "ABC-1" })).await).await?;
    h.approver().open(&first).map_err(de)?;
    h.approver().release(&first).map_err(de)?;
    assert!(h.settled(&first, 10_000).await);

    let second = queued(
        &h,
        h.submit(ISSUE, json!({ "key": "ABC-1", "fields": ["summary"] }))
            .await,
    )
    .await?;
    let utc = similar_text(&h, &second).await?;
    assert!(utc.starts_with(&format!("similar to {first} ")), "{utc}");
    assert!(
        utc.ends_with(&format!("{} UTC", clock_hhmm(&h, 0)?)),
        "{utc}"
    );

    // An open request is always reported first: cancel it so the decided one is the hit.
    h.handler().cancel(&second).await;
    h.core().set_utc_offset(Some(120));
    let third = queued(
        &h,
        h.submit(ISSUE, json!({ "key": "ABC-1", "fields": ["description"] }))
            .await,
    )
    .await?;
    let local = similar_text(&h, &third).await?;
    assert!(
        local.ends_with(&format!(" {}", clock_hhmm(&h, 120)?)),
        "{local}"
    );
    assert!(!local.contains("UTC"), "{local}");

    h.handler().cancel(&third).await;
    h.core().set_utc_offset(None);
    let fourth = queued(
        &h,
        h.submit(ISSUE, json!({ "key": "ABC-1", "fields": ["status"] }))
            .await,
    )
    .await?;
    assert!(similar_text(&h, &fourth).await?.ends_with("UTC"));
    Ok(())
}

/// RF-4 for `confluence.page.create` (M7 Task 16; a `Create` op over `(space, parent, title)`):
/// a create that crashed after `WRITE_APPROVED` is `outcome_unknown` after the restart, and the
/// same create submitted again is flagged "similar to req_… outcome unknown", a Caution with
/// Approve still enabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf4_page_create_after_crash_is_flagged() -> TestResult {
    const PAGE_CREATE: &str = "confluence.page.create";
    let mut h = Harness::confluence().await?;
    let create = json!({"space": "DOC", "title": "Release 1.5 notes", "body": "Hello.",
                        "parent": "123400"});
    {
        let mock = h.mock("wiki").ok_or("no wiki mock")?;
        let answer = |body: Value| {
            mock.response(200)
                .set_body_raw(body.to_string(), "application/json")
        };
        common::confluence::mount_space(
            mock,
            "DOC",
            &json!({"id": 98305, "key": "DOC", "name": "Documentation", "type": "global"}),
        )
        .await;
        Mock::given(method("GET"))
            .and(path(mock.path("/rest/api/content/123400")))
            .respond_with(answer(json!({
                "id": "123400", "type": "page", "status": "current", "title": "Release notes",
                "space": {"key": "DOC", "name": "Documentation"}, "ancestors": [],
            })))
            .mount(mock.server())
            .await;
        common::confluence::mount_title_lookup(mock, "DOC", "Release 1.5 notes", &[]).await;
        // The identity call of the approved create never answers: it stays mid-execution, as if
        // the app crashed there.
        Mock::given(path(mock.path("/rest/api/user/current")))
            .respond_with(
                answer(
                    json!({"type": "known", "username": TEST_USER, "userKey": TEST_USER_KEY,
                              "displayName": "Jane Doe"}),
                )
                .set_delay(Duration::from_secs(60)),
            )
            .mount(mock.server())
            .await;
    }
    let approved = queued(&h, h.submit(PAGE_CREATE, create.clone()).await).await?;
    assert!(h.approver().open(&approved).map_err(de)?.preview.approvable);
    h.approver().approve(&approved).map_err(de)?;
    let mut seen = false;
    for _ in 0..400 {
        if h.event_types(&approved)
            .await?
            .contains(&EventType::WRITE_APPROVED)
        {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(seen, "WRITE_APPROVED never committed");

    h.crash_and_restart().await?;
    assert_eq!(h.core().startup_notice().len(), 1);
    let again = queued(&h, h.submit(PAGE_CREATE, create).await).await?;
    let row = h.approver().item(&again).ok_or("not queued")?;
    assert_eq!(row.similar_to.as_deref(), Some(approved.as_str()));
    assert!(row.approvable && row.caution_count >= 1);
    let text = similar_text(&h, &again).await?;
    assert_eq!(text, format!("similar to {approved} outcome unknown"));
    Ok(())
}
