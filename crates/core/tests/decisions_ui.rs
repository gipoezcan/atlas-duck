#![cfg(feature = "testing")]
//! M6 Task 7 (Δ2): the decision API's side reads for the approvals UI. `redaction_preview` (§5.3,
//! the M3 handoff): the release path's verdict on a set of ops, nothing logged and nothing
//! changed; `recent` and `needs_attention` ("Recently decided (24 h) / Needs attention", §5.6,
//! X-13); a write preview's Rust-computed deny offers and the conflict pre-fill (PD-70); path-free
//! session ids (PD-86); M5 M-8 (server text in a deny hint stripped, the hint bounded).

mod common;

use std::time::Duration;

use atlas_duck_atlassian::Timeouts;
use atlas_duck_atlassian::testing::{
    MockDc, RawHttpServer, RawStep, TEST_USER, TEST_USER_KEY, XAuser, fixtures,
};
use atlas_duck_audit::EventType;
use atlas_duck_core::engine::write::CONFLICT_DENY_PREFILL;
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::redact::{BlockReason, apply};
use atlas_duck_core::testing::{Channel, Harness, InstanceAt};
use atlas_duck_core::{
    DecisionError, DecisionOutcome, DenyDetails, QueueItem, RedactionOp, RedactionReport, UrlMode,
};
use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::envelope::Status;
use atlas_duck_ipc::proto::{AgentNameSource, ClientKind, ConnectionMeta, Hello, PeerInfo};
use atlas_duck_preview::{DenyOffer, DenyOfferKind};
use atlas_duck_registry::Product;
use common::jira::{PROJECTS_PATH, full_issue, issuetypes_path, mount_issue};
use common::{TestError, TestResult, code, de, detail, request_id};
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path};

const ISSUE: &str = "jira.issue.get";
const COMMENT: &str = "jira.comment.add";
const TRANSITION: &str = "jira.issue.transition";
const CREATE: &str = "jira.issue.create";
const EDIT: &str = "jira.issue.edit";
const KEY: &str = "ABC-7";
/// `common::jira::create_fields_path("ABC", "10002")`.
const BUG_FIELDS: &str = "/rest/api/2/issue/createmeta/ABC/issuetypes/10002";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no confluence mock".into())
}

/// Submits on the default connection and waits until the request waits for a decision.
async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    Ok(id)
}

fn mask(text: &str, every_occurrence: bool) -> RedactionOp {
    RedactionOp::MaskText {
        text: text.to_owned(),
        every_occurrence,
        at: None,
    }
}

/// The payloads of `id`'s records of type `t`.
async fn records(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

/// How many UI events the capture hook saw.
fn ui_events(h: &Harness) -> usize {
    h.capture()
        .records()
        .iter()
        .filter(|r| r.channel == Channel::UiEvent)
        .count()
}

/// The current revision's exact candidate (Raw page 0 of an opened item; small fixtures).
fn candidate(h: &Harness, id: &str) -> Result<Value, TestError> {
    let rev = h.approver().rev(id).map_err(de)?;
    let page = h.decisions().raw_page(id, rev, 0).map_err(de)?;
    assert_eq!(page.page_count, 1, "a one-page fixture");
    Ok(serde_json::from_slice(&page.bytes)?)
}

/// What the redaction engine says of `ops` on `doc`, in the report's terms.
fn engine_report(op: &str, doc: &Value, ops: &[RedactionOp]) -> Result<RedactionReport, TestError> {
    let spec = atlas_duck_registry::get(op).ok_or("no spec")?;
    let out = apply(
        doc,
        &spec.redaction_rules,
        spec.paginated.map(|p| p.items_key),
        ops,
    );
    Ok(RedactionReport {
        blocked: out.blocked,
        also_appears_in: out.also_appears_in,
        other_occurrences: out.other_occurrences,
        released_bytes: u64::try_from(serde_json::to_vec(&out.released)?.len())?,
    })
}

// ---- redaction_preview (M3 handoff) ------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redaction_preview_logs_nothing_and_changes_nothing() -> TestResult {
    let h = Harness::jira().await?;
    mount_issue(jira(&h)?, KEY, &full_issue(KEY)).await;
    let id = queued(&h, ISSUE, json!({ "key": KEY })).await?;
    let ap = h.approver();
    ap.open(&id).map_err(de)?;
    let before = ap.item(&id).ok_or("not queued")?;
    let (count, events) = (h.event_count().await?, ui_events(&h));
    // The issue id is also in the `self` URL: without a URL choice the mask blocks (§5.3 rule 2).
    let blocking = [mask("10007", true)];
    let report = ap.redaction_preview(&id, &blocking).map_err(de)?;
    assert!(
        report.blocked.contains(&BlockReason::MaskStillOccurs {
            path: "self".into()
        }),
        "{report:?}"
    );
    assert!(report.also_appears_in.iter().any(|p| p == "self"));
    let report = ap
        .redaction_preview(
            &id,
            &[
                mask("10007", true),
                RedactionOp::UrlField {
                    mode: UrlMode::ReplaceWhole,
                },
            ],
        )
        .map_err(de)?;
    assert!(report.blocked.is_empty(), "{report:?}");
    // Nothing logged (no `PREVIEW_SHOWN`, no `DECISION_*`), no UI event, the item as it was: same
    // revision, opened, approvable (a blocked preview does not fail the item closed).
    assert_eq!(h.event_count().await?, count);
    assert_eq!(ui_events(&h), events);
    assert_eq!(ap.item(&id).ok_or("left the queue")?, before);
    assert!(before.opened && before.approvable);
    // The decision with the blocking ops is refused for the same reason, and that one is logged.
    let res = ap.redact(&id, blocking.to_vec());
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    assert_eq!(
        records(&h, &id, EventType::DECISION_INVALID).await?.len(),
        1
    );
    ap.release(&id).map_err(de)?;
    assert_eq!(h.await_(&id, 5000).await.status, Status::Released);
    Ok(())
}

/// §13 U-28 verbatim fixture, as a `confluence.search` answer.
fn falcon_page() -> Value {
    json!({
        "results": [{
            "title": "Falcon Müller Plan",
            "url": "/display/LEGAL/Falcon+M%C3%BCller+Plan",
            "excerpt": "Falcon%20M%c3%bcller%20Plan",
            "content": {"title": "Falcon M&#252;ller Plan", "_links": {"webui": "/pages/1"}},
            "resultGlobalContainer": {"title": "Falcon M&uuml;ller Plan", "displayUrl": "/display/LEGAL"},
            "lastModified": "Falcon Mu\u{308}ller Plan",
            "entityType": "content",
            "breadcrumbs": "x Falcon%20M%C3%BCller%20Plan%2Fv2 and Falcon M&uuml;ller Plan&amp;co"
        }],
        "start": 0, "limit": 25, "size": 1,
        "_links": {"base": "https://confluence.example"}
    })
}

/// The fixture's paths that hold a form of the title once the search is pruned to the §7.4
/// release list (PD-101: `breadcrumbs` and `content.title` are never released).
const FALCON_PATHS: [&str; 5] = [
    "results[0].excerpt",
    "results[0].lastModified",
    "results[0].resultGlobalContainer.title",
    "results[0].title",
    "results[0].url",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redaction_preview_reports_also_appears_in_and_other_occurrences() -> TestResult {
    let h = Harness::confluence().await?;
    wiki(&h)?
        .json("/rest/api/search", 200, &falcon_page().to_string())
        .await;
    let id = queued(
        &h,
        "confluence.search",
        json!({ "cql": "title ~ \"Falcon\"" }),
    )
    .await?;
    let ap = h.approver();
    ap.open(&id).map_err(de)?;
    let count = h.event_count().await?;
    let doc = candidate(&h, &id)?;
    let title = "Falcon Müller Plan";
    let url_choice = RedactionOp::UrlField {
        mode: UrlMode::ReplaceWhole,
    };

    // Every occurrence, no URL choice: every canonical form is listed, the URL blocks.
    let ops = [mask(title, true)];
    let report = ap.redaction_preview(&id, &ops).map_err(de)?;
    let mut listed = report.also_appears_in.clone();
    listed.sort();
    listed.dedup();
    assert_eq!(listed, FALCON_PATHS);
    assert!(report.blocked.contains(&BlockReason::MaskStillOccurs {
        path: "results[0].url".into()
    }));
    assert_eq!(report, engine_report("confluence.search", &doc, &ops)?);

    // With the URL choice nothing blocks; the size is the redacted candidate's.
    let ops = [mask(title, true), url_choice];
    let report = ap.redaction_preview(&id, &ops).map_err(de)?;
    assert!(report.blocked.is_empty(), "{report:?}");
    assert_eq!(report.other_occurrences, 0);
    assert_eq!(report, engine_report("confluence.search", &doc, &ops)?);

    // One occurrence: "N other occurrences remain" (§5.3 single-occurrence confirmation).
    let ops = [mask(title, false)];
    let report = ap.redaction_preview(&id, &ops).map_err(de)?;
    assert!(report.other_occurrences >= 4, "{report:?}");
    assert_eq!(report, engine_report("confluence.search", &doc, &ops)?);

    assert_eq!(h.event_count().await?, count, "a preview logs nothing");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redaction_preview_unopened_is_not_opened() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_issue(mock, KEY, &full_issue(KEY)).await;
    identity_ok(mock).await;
    let id = queued(&h, ISSUE, json!({ "key": KEY })).await?;
    let ap = h.approver();
    let count = h.event_count().await?;
    let ops = [mask("Login", true)];
    let res = ap.redaction_preview(&id, &ops);
    assert!(
        matches!(res, Err(DecisionError::Invalid(InvalidReason::NotOpened))),
        "{res:?}"
    );
    // Nothing logged (not even `DECISION_INVALID`), nothing opened.
    assert_eq!(h.event_count().await?, count);
    assert!(!ap.item(&id).ok_or("left the queue")?.opened);
    // Another revision is `Stale`, an unknown id `NotDecidable`, as for `raw_page`.
    let mut rev = ap.rev(&id).map_err(de)?;
    rev.counter += 1;
    let res = h.decisions().redaction_preview(&id, rev, &ops);
    assert!(matches!(res, Err(DecisionError::Stale { .. })), "{res:?}");
    let res = h.decisions().redaction_preview("req_unknown", rev, &ops);
    assert!(matches!(res, Err(DecisionError::NotDecidable)), "{res:?}");
    // A write has nothing to redact.
    let w = comment_item(&h, "Fixed.").await?;
    ap.open(&w).map_err(de)?;
    let res = ap.redaction_preview(&w, &ops);
    assert!(
        matches!(res, Err(DecisionError::EditRejected(_))),
        "{res:?}"
    );
    assert_eq!(
        records(&h, &id, EventType::DECISION_INVALID).await?.len(),
        0
    );
    Ok(())
}

/// M6 T17: a delivery carries its revision's own ops, as `decide` stored them, and the op's URL
/// fields: the panel appends ops built on what the revision shows to them (a new set replaces
/// the old one, so sent alone they would bring the earlier drops back). A write has none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preview_delivery_carries_the_revision_ops() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mount_issue(mock, KEY, &full_issue(KEY)).await;
    identity_ok(mock).await;
    let id = queued(&h, ISSUE, json!({ "key": KEY })).await?;
    let ap = h.approver();
    let first = ap
        .open(&id)
        .map_err(de)?
        .redaction
        .ok_or("a read has one")?;
    assert!(first.ops.is_empty());
    let spec = atlas_duck_registry::get(ISSUE).ok_or("no spec")?;
    assert_eq!(first.url_fields, spec.redaction_rules.url_fields);
    assert!(!first.url_fields.is_empty());
    let ops = vec![
        RedactionOp::DropField {
            path: "fields.summary".into(),
            scope: atlas_duck_core::redact::DropScope::PerItem,
        },
        RedactionOp::UrlField {
            mode: UrlMode::Drop,
        },
    ];
    ap.redact(&id, ops.clone()).map_err(de)?;
    let second = ap.open(&id).map_err(de)?.redaction.ok_or("still a read")?;
    assert_eq!(second.ops, ops);
    // A reopen of the same revision carries the same ops.
    assert_eq!(ap.open(&id).map_err(de)?.redaction.ok_or("read")?.ops, ops);
    let w = comment_item(&h, "Fixed.").await?;
    assert_eq!(ap.open(&w).map_err(de)?.redaction, None);
    Ok(())
}

/// M6 T17, the panel's rule in engine terms: ops built on the candidate a revision shows (the
/// source with its ops applied), appended to that revision's ops, give what they give on the
/// shown candidate itself, mirrors and copies included. Index paths resolve against the shown
/// candidate because each drop resolves against the document the earlier drops left.
#[test]
fn ops_appended_to_a_revision_act_on_what_it_shows() -> TestResult {
    let spec = atlas_duck_registry::get(ISSUE).ok_or("no spec")?;
    let rules = &spec.redaction_rules;
    let comments = |ids: &[&str]| -> Vec<Value> {
        ids.iter()
            .map(|i| json!({"id": i, "body": format!("comment {i} by Falcon")}))
            .collect()
    };
    let source = json!({
        "key": KEY,
        "fields": {
            "summary": "Falcon",
            "labels": ["a", "b", "c", "d"],
            "comment": {"comments": comments(&["1", "2", "3"])}
        },
        "renderedFields": {"comment": {"comments": comments(&["1", "2", "3"])}}
    });
    let drop = |p: &str| RedactionOp::DropField {
        path: p.into(),
        scope: atlas_duck_core::redact::DropScope::PerItem,
    };
    let base = vec![drop("fields.labels[0]"), drop("fields.comment.comments[0]")];
    let shown = apply(&source, rules, None, &base);
    assert!(shown.blocked.is_empty(), "{:?}", shown.blocked);
    // Built on the shown candidate: its `labels[0]` is the source's "b", its first comment id 2.
    let round = vec![
        drop("fields.labels[1]"),
        drop("fields.labels[0]"),
        drop("fields.comment.comments[0]"),
        mask("Falcon", true),
    ];
    let on_shown = apply(&shown.released, rules, None, &round);
    let appended: Vec<RedactionOp> = base.iter().chain(&round).cloned().collect();
    let on_source = apply(&source, rules, None, &appended);
    assert!(on_source.blocked.is_empty(), "{:?}", on_source.blocked);
    assert_eq!(on_source.released, on_shown.released);
    assert_eq!(on_source.released["fields"]["labels"], json!(["d"]));
    assert_eq!(
        on_source.released["renderedFields"]["comment"]["comments"][0]["id"],
        json!("3")
    );
    // Sent alone, the round acts on the source instead: another label, another comment.
    let alone = apply(&source, rules, None, &round);
    assert_ne!(alone.released, on_shown.released);
    Ok(())
}

fn drop_at(p: &str) -> RedactionOp {
    RedactionOp::DropField {
        path: p.into(),
        scope: atlas_duck_core::redact::DropScope::PerItem,
    }
}

fn op_target_missing(blocked: &[BlockReason], at: &str) -> bool {
    blocked
        .iter()
        .any(|b| matches!(b, BlockReason::OpTargetMissing { path } if path == at))
}

/// M6 T17 review C1, the rule the panel relies on: a single-occurrence mask's `at` is resolved
/// after every drop of the set (apply.rs: drops first, then masks), so a drop appended to a
/// revision that holds one moves the mask to another element. The panel offers no drop or
/// preset on such a revision.
#[test]
fn a_later_drop_moves_a_revision_single_occurrence_mask() -> TestResult {
    let spec = atlas_duck_registry::get(ISSUE).ok_or("no spec")?;
    let rules = &spec.redaction_rules;
    let issues = |four: &str| {
        json!({"issues": [
            {"summary": "s0"}, {"summary": "s1"}, {"summary": "s2"},
            {"summary": "s3 Falcon"}, {"summary": four}
        ]})
    };
    let single = RedactionOp::MaskText {
        text: "Falcon".into(),
        every_occurrence: false,
        at: Some("issues[3].summary".into()),
    };
    let url = RedactionOp::UrlField {
        mode: UrlMode::ReplaceWhole,
    };
    let round = [drop_at("issues[1]")];
    let appended =
        |base: &[RedactionOp]| -> Vec<RedactionOp> { base.iter().chain(&round).cloned().collect() };

    // The element after the shown issues[3] does not hold the text: the mask names nothing.
    let source = issues("s4");
    let base = vec![single.clone(), url.clone()];
    let shown = apply(&source, rules, None, &base);
    assert!(shown.blocked.is_empty(), "{:?}", shown.blocked);
    assert_eq!(
        shown.released["issues"][3]["summary"],
        json!("s3 [REDACTED]")
    );
    let on_shown = apply(&shown.released, rules, None, &round);
    assert!(on_shown.blocked.is_empty(), "{:?}", on_shown.blocked);
    let on_source = apply(&source, rules, None, &appended(&base));
    assert!(
        op_target_missing(&on_source.blocked, "issues[3].summary"),
        "{:?}",
        on_source.blocked
    );

    // It does: the wrong value is masked and the masked one comes back, nothing blocked.
    let source = issues("s4 Falcon");
    let on_source = apply(&source, rules, None, &appended(&base));
    assert!(on_source.blocked.is_empty(), "{:?}", on_source.blocked);
    assert_eq!(
        on_source.released["issues"][2]["summary"],
        json!("s3 Falcon")
    );
    assert_eq!(
        on_source.released["issues"][3]["summary"],
        json!("s4 [REDACTED]")
    );

    // Control: an every-occurrence mask has no location, so the drop acts as on the shown one.
    let base = vec![mask("Falcon", true), url];
    let shown = apply(&source, rules, None, &base);
    let on_shown = apply(&shown.released, rules, None, &round);
    let on_source = apply(&source, rules, None, &appended(&base));
    assert!(on_source.blocked.is_empty(), "{:?}", on_source.blocked);
    assert_eq!(on_source.released, on_shown.released);
    Ok(())
}

/// M6 T17 review I1: a drop built on what a revision shows is checked against the source as well
/// (apply.rs `drop_field`/`drop_item`: "matching nothing in the candidate is a mismatch"). Where
/// the path continues past an element named by index whose list the revision shortened, that
/// check reads another element than the one shown and blocks; a path ending in that index, or
/// one that names elements by identity, reads the same element. The panel offers only those.
#[test]
fn a_drop_past_a_shifted_index_is_checked_on_another_element() -> TestResult {
    let spec = atlas_duck_registry::get(ISSUE).ok_or("no spec")?;
    let rules = &spec.redaction_rules;
    let source = json!({"list": [
        {"body": "x"},
        {"body": "y", "author": "Ann"},
        {"body": "z", "author": "Bo"}
    ]});
    let base = vec![drop_at("list[0]")];
    let shown = apply(&source, rules, None, &base);
    assert!(shown.blocked.is_empty(), "{:?}", shown.blocked);
    assert_eq!(shown.released["list"][0]["author"], json!("Ann"));
    let appended =
        |round: &[RedactionOp]| -> Vec<RedactionOp> { base.iter().chain(round).cloned().collect() };

    // The shown list[0] has an author, the source's list[0] has none: blocked.
    let tail = [drop_at("list[0].author")];
    let on_shown = apply(&shown.released, rules, None, &tail);
    assert!(on_shown.blocked.is_empty(), "{:?}", on_shown.blocked);
    let on_source = apply(&source, rules, None, &appended(&tail));
    assert!(
        op_target_missing(&on_source.blocked, "list[0].author"),
        "{:?}",
        on_source.blocked
    );

    // Offered: the element itself by index (again `list[0]`, a repeat of the base op) and a
    // field across all items (no index left to read).
    for round in [
        vec![drop_at("list[0]")],
        vec![RedactionOp::DropField {
            path: "list[0].author".into(),
            scope: atlas_duck_core::redact::DropScope::AllItems,
        }],
    ] {
        let on_shown = apply(&shown.released, rules, None, &round);
        let on_source = apply(&source, rules, None, &appended(&round));
        assert!(
            on_source.blocked.is_empty(),
            "{round:?}: {:?}",
            on_source.blocked
        );
        assert_eq!(on_source.released, on_shown.released, "{round:?}");
    }
    let repeat = apply(&source, rules, None, &appended(&[drop_at("list[0]")]));
    assert_eq!(
        repeat.released,
        json!({"list": [{"body": "z", "author": "Bo"}]})
    );
    Ok(())
}

// ---- recent / needs attention (§5.6, X-13) ---------------------------------------------------------

/// The identity call of the stale check (§5.4 step 5) answers as the PAT's user.
async fn identity_ok(mock: &MockDc) {
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
}

/// `POST .../ABC-1/comment` answers `status` (an error body with `message` below 300).
async fn mount_comment_post(mock: &MockDc, status: u16, message: &str) {
    let t = if status < 300 {
        mock.response(status)
            .set_body_raw(fixtures::JIRA_COMMENT, "application/json")
    } else {
        let body = json!({ "errorMessages": [message], "errors": {} });
        mock.response(status)
            .set_body_raw(body.to_string(), "application/json")
    };
    Mock::given(method("POST"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1/comment")))
        .respond_with(t)
        .with_priority(1)
        .mount(mock.server())
        .await;
}

/// A `jira.comment.add` on `ABC-1`, queued.
async fn comment_item(h: &Harness, body: &str) -> Result<String, TestError> {
    queued(
        h,
        COMMENT,
        json!({ "key": "ABC-1", "body": body, "body_format": "wiki" }),
    )
    .await
}

/// A comment approved and failed (the POST answers 400).
async fn failed_write(h: &Harness, body: &str) -> Result<String, TestError> {
    let id = comment_item(h, body).await?;
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    Ok(id)
}

fn row(h: &Harness, id: &str) -> Result<atlas_duck_core::RecentItem, TestError> {
    h.approver()
        .recent_row(id)
        .ok_or_else(|| format!("{id} not listed").into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x13_recent_needs_attention_ack_resets_on_restart() -> TestResult {
    let mut h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount_comment_post(mock, 400, "Comment body can not be empty!").await;
    mount_issue(mock, KEY, &full_issue(KEY)).await;
    let w1 = failed_write(&h, "one").await?;
    let w2 = failed_write(&h, "two").await?;
    // A denied read is listed without attention; a request never decided is the queue's.
    let read = queued(&h, ISSUE, json!({ "key": KEY })).await?;
    h.approver().deny(&read, "not now").map_err(de)?;
    let waiting = comment_item(&h, "three").await?;

    let mut want = vec![w1.clone(), w2.clone()];
    want.sort();
    assert_eq!(h.decisions().needs_attention(), want);
    for id in [&w1, &w2] {
        let r = row(&h, id)?;
        assert_eq!(
            (
                r.status,
                r.class,
                r.op_id.as_str(),
                r.instance_alias.as_str()
            ),
            (Status::Failed, "write", COMMENT, "jira-main")
        );
        assert_eq!(r.target_display, "ABC-1");
        assert!(r.needs_attention && !r.acknowledged, "{r:?}");
    }
    let r = row(&h, &read)?;
    assert_eq!(r.status, Status::Denied);
    assert!(!r.needs_attention && !r.acknowledged);
    assert!(h.approver().recent_row(&waiting).is_none());

    // Acknowledged in memory: the row says so, the count drops.
    h.decisions()
        .acknowledge_attention(std::slice::from_ref(&w1));
    assert!(row(&h, &w1)?.acknowledged);
    assert!(!row(&h, &w2)?.acknowledged);
    assert_eq!(h.decisions().needs_attention(), std::slice::from_ref(&w2));

    // §5.6: acknowledgement is UI state that resets on restart; the rows stay (the log knows
    // them) and nothing awaits acknowledgement (the §11.3 startup notice covers interrupted
    // writes).
    h.restart().await?;
    assert!(h.decisions().needs_attention().is_empty());
    for id in [&w1, &w2] {
        let r = row(&h, id)?;
        assert!(r.needs_attention && r.acknowledged, "{r:?}");
    }
    // A failure after the restart needs attention again.
    let w3 = failed_write(&h, "four").await?;
    assert_eq!(h.decisions().needs_attention(), std::slice::from_ref(&w3));
    let r = row(&h, &w3)?;
    assert!(r.needs_attention && !r.acknowledged, "{r:?}");
    Ok(())
}

/// Whether the needs-attention count reached the UI before the `Failed` attention event (the
/// toast and the tooltip line are built from the count known at that event; final review I-1).
fn count_told_before_failed_attention(events: &[String]) -> bool {
    let at = |needle: &str| events.iter().position(|j| j.contains(needle));
    match (at("NeedsAttentionChanged"), at("\"Failed\"")) {
        (Some(count), Some(attention)) => count < attention,
        _ => false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_write_tells_the_count_before_the_attention_event() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount_comment_post(mock, 400, "Comment body can not be empty!").await;
    failed_write(&h, "one").await?;
    let events: Vec<String> = h
        .capture()
        .on(Channel::UiEvent)
        .into_iter()
        .map(|r| r.json)
        .collect();
    assert!(
        events.iter().any(|j| j.contains("\"Failed\"")),
        "no Failed attention event: {events:?}"
    );
    assert!(count_told_before_failed_attention(&events), "{events:?}");
    // Negative control: the old order, and a run without the count, do not pass the check.
    let mut reversed = events.clone();
    reversed.reverse();
    assert!(!count_told_before_failed_attention(&reversed));
    let without: Vec<String> = events
        .into_iter()
        .filter(|j| !j.contains("NeedsAttentionChanged"))
        .collect();
    assert!(!count_told_before_failed_attention(&without));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recent_error_text_only_while_deliverable() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount_comment_post(mock, 400, "Comment body \u{202e}can not be empty!").await;
    let w = failed_write(&h, "one").await?;
    // The capped Atlassian error, display-escaped (§6.4), while `await` delivers it (§4.4).
    let text = row(&h, &w)?.error_text.ok_or("no error text")?;
    assert!(text.contains("can not be empty!"), "{text}");
    assert!(
        text.contains("⟨U+202E⟩") && !text.contains('\u{202e}'),
        "{text}"
    );
    assert!(text.len() <= atlas_duck_preview::ERROR_TEXT_CAP_BYTES);
    // After the 1 h window the row stays (24 h), without the text.
    h.clock().advance(Duration::from_secs(61 * 60));
    let r = row(&h, &w)?;
    assert_eq!(r.error_text, None);
    assert!(r.needs_attention);
    assert_eq!(r.status, Status::Failed);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_return_is_listed_until_decided() -> TestResult {
    // No `/myself` answer: the stale check cannot run and the approval returns to the queue
    // (§5.4 step 5, `recheck_failed`).
    let h = Harness::jira().await?;
    mount_comment_post(jira(&h)?, 201, "").await;
    let w = comment_item(&h, "one").await?;
    let rev = h.approver().rev(&w).map_err(de)?;
    h.approver().approve(&w).map_err(de)?;
    for _ in 0..400 {
        if h.approver().item(&w).is_some_and(|i| i.stale) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let item = h.approver().item(&w).ok_or("not back in the queue")?;
    assert!(item.stale && item.candidate_rev.counter >= rev.counter);
    let stale = records(&h, &w, EventType::WRITE_STALE).await?;
    assert_eq!(
        stale
            .iter()
            .map(|s| s["reason"].clone())
            .collect::<Vec<_>>(),
        [json!("recheck_failed")]
    );
    let r = row(&h, &w)?;
    assert_eq!(r.status, Status::Pending);
    assert!(r.needs_attention && !r.acknowledged, "{r:?}");
    // Decided again: listed as decided, without attention.
    h.approver().deny(&w, "later").map_err(de)?;
    let r = row(&h, &w)?;
    assert_eq!(r.status, Status::Denied);
    assert!(!r.needs_attention);
    Ok(())
}

// ---- deny offers (PD-70) -----------------------------------------------------------------------

/// Every `DenyDetails` value, with the offer kind it stands for.
fn every_detail() -> Vec<(DenyOfferKind, DenyDetails)> {
    let mut out = Vec::new();
    for b in [false, true] {
        out.push((
            DenyOfferKind::UpstreamHttp,
            DenyDetails::UpstreamHttp {
                include_messages: b,
            },
        ));
        out.push((
            DenyOfferKind::ResolutionFailed,
            DenyDetails::ResolutionFailed {
                include_candidates: b,
            },
        ));
        out.push((
            DenyOfferKind::MissingFields,
            DenyDetails::MissingFields {
                include_allowed_values: b,
            },
        ));
    }
    out.push((DenyOfferKind::OutcomeHint, DenyDetails::OutcomeHint));
    out
}

fn kinds(offers: &[DenyOffer]) -> Vec<DenyOfferKind> {
    offers.iter().map(|o| o.kind).collect()
}

fn refused(res: Result<DecisionOutcome, DecisionError>) -> TestResult {
    assert!(
        matches!(res, Err(DecisionError::EditRejected(_))),
        "{res:?}"
    );
    Ok(())
}

/// The property: on `ids` (requests of one hold, all queued) every detail of a kind the preview
/// does not offer is refused (nothing logged) and every offered one is accepted (one request
/// each, the last ones). Returns the offers.
async fn offers_match(h: &Harness, ids: &[String]) -> Result<Vec<DenyOffer>, TestError> {
    let first = ids.first().ok_or("no request")?;
    let offers = h.approver().open(first).map_err(de)?.preview.deny_offers;
    for id in ids {
        let p = h.approver().open(id).map_err(de)?.preview;
        assert_eq!(p.deny_offers, offers, "same hold, same offers");
    }
    let offered = kinds(&offers);
    for (kind, details) in every_detail() {
        if !offered.contains(&kind) {
            refused(h.approver().deny_with(first, "x", details))?;
        }
    }
    assert!(records(h, first, EventType::WRITE_DENIED).await?.is_empty());
    let accepted: Vec<DenyDetails> = every_detail()
        .into_iter()
        .filter(|(k, _)| offered.contains(k))
        .map(|(_, d)| d)
        .collect();
    assert!(
        accepted.len() <= ids.len(),
        "one request per accepted detail"
    );
    for (details, id) in accepted.into_iter().zip(ids) {
        h.approver().deny_with(id, "x", details).map_err(de)?;
        let env = h.await_(id, 5000).await;
        assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
    }
    Ok(offers)
}

async fn requests(
    h: &Harness,
    op: &str,
    params: Value,
    n: usize,
) -> Result<Vec<String>, TestError> {
    let mut ids = Vec::new();
    for _ in 0..n {
        ids.push(queued(h, op, params.clone()).await?);
    }
    Ok(ids)
}

fn offer(kind: DenyOfferKind, has_optional_detail: bool) -> DenyOffer {
    DenyOffer {
        kind,
        has_optional_detail,
    }
}

/// Transitions `Start Progress` and `Done` of `ABC-1` (and the issue the transition reads).
async fn mount_transitions(mock: &MockDc, names: &[&str]) {
    let transitions: Vec<Value> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            json!({"id": format!("{}", 11 + i), "name": n,
                   "to": {"id": "3", "name": "In Progress"}, "fields": {}})
        })
        .collect();
    mock.json(
        "/rest/api/2/issue/ABC-1/transitions",
        200,
        &json!({ "transitions": transitions }).to_string(),
    )
    .await;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
}

/// createmeta of `Bug` in `ABC` with the fields `values`.
async fn mount_create_fields(mock: &MockDc, values: Vec<Value>) {
    mock.json(PROJECTS_PATH, 200, fixtures::JIRA_PROJECTS).await;
    mock.json(
        &issuetypes_path("ABC"),
        200,
        fixtures::JIRA_CREATEMETA_ISSUETYPES,
    )
    .await;
    let page = json!({"maxResults": 50, "startAt": 0, "total": values.len(), "isLast": true,
                      "values": values});
    mock.json(BUG_FIELDS, 200, &page.to_string()).await;
}

fn team_field() -> Value {
    json!({"required": true,
           "schema": {"type": "option",
                      "custom": "com.atlassian.jira.plugin.system.customfieldtypes:select"},
           "name": "Team", "fieldId": "customfield_10200", "hasDefaultValue": false,
           "operations": ["set"], "allowedValues": [{"id": "10400", "value": "Platform"}]})
}

fn create_params() -> Value {
    json!({ "project": "ABC", "issuetype": "Bug", "summary": "S" })
}

/// A Jira at a raw server whose answer to the enrichment GET never completes (an outcome hold).
async fn raw_jira(script: Vec<RawStep>) -> Result<(Harness, RawHttpServer), TestError> {
    let server = RawHttpServer::serve(script).await?;
    let h = Harness::builder()
        .instance_at(
            "jira-main",
            Product::Jira,
            InstanceAt {
                base_url: server.base_url(),
                ..InstanceAt::default()
            },
        )
        .timeouts(Timeouts {
            per_call: Duration::from_millis(400),
            ..Timeouts::default()
        })
        .start()
        .await?;
    Ok((h, server))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deny_offers_match_deny_hint_acceptance() -> TestResult {
    // `Preview` without missing fields: nothing to attach.
    let h = Harness::jira().await?;
    let ids = vec![comment_item(&h, "Fixed.").await?];
    assert_eq!(offers_match(&h, &ids).await?, []);

    // `EnrichmentError` of an upstream answer: `upstream_http`, its messages optional.
    let h = Harness::jira().await?;
    jira(&h)?
        .json(
            "/rest/api/2/issue/NOPE-1/transitions",
            404,
            r#"{"errorMessages":["Issue does not exist"],"errors":{}}"#,
        )
        .await;
    let ids = requests(
        &h,
        TRANSITION,
        json!({ "key": "NOPE-1", "transition": "Done" }),
        2,
    )
    .await?;
    assert_eq!(
        offers_match(&h, &ids).await?,
        [offer(DenyOfferKind::UpstreamHttp, true)]
    );

    // `UnresolvedName`: `resolution_failed`, its candidates optional.
    let h = Harness::jira().await?;
    mount_transitions(jira(&h)?, &["Start Progress", "Done"]).await;
    let ids = requests(
        &h,
        TRANSITION,
        json!({ "key": "ABC-1", "transition": "Doen" }),
        2,
    )
    .await?;
    assert_eq!(
        offers_match(&h, &ids).await?,
        [offer(DenyOfferKind::ResolutionFailed, true)]
    );

    // `Preview` with a missing required field: `missing_fields`, its allowed values optional.
    let h = Harness::jira().await?;
    mount_create_fields(jira(&h)?, vec![team_field()]).await;
    let ids = requests(&h, CREATE, create_params(), 2).await?;
    assert_eq!(
        offers_match(&h, &ids).await?,
        [offer(DenyOfferKind::MissingFields, true)]
    );
    // A missing field without allowed values has nothing optional to attach.
    let h = Harness::jira().await?;
    let points = json!({"required": true, "schema": {"type": "number"}, "name": "Points",
                        "fieldId": "customfield_10106", "hasDefaultValue": false});
    mount_create_fields(jira(&h)?, vec![points]).await;
    let ids = requests(&h, CREATE, create_params(), 2).await?;
    assert_eq!(
        offers_match(&h, &ids).await?,
        [offer(DenyOfferKind::MissingFields, false)]
    );

    // `Conflict`: no detail (the reason field is pre-filled instead).
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount_issue(mock, "ABC-1", &serde_json::from_str(fixtures::JIRA_ISSUE)?).await;
    let ids = vec![queued(&h, EDIT, conflict_params()).await?];
    assert_eq!(offers_match(&h, &ids).await?, []);

    // `EnrichmentError` of a post-send outcome: `outcome_hint`, nothing optional.
    let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-AUSERNAME: jdoe\r\n\
                Connection: close\r\nContent-Length: 100\r\n\r\n";
    let (h, _server) = raw_jira(vec![
        RawStep::Send(head.as_bytes().to_vec()),
        RawStep::Sleep(5_000),
    ])
    .await?;
    let ids = vec![
        queued(
            &h,
            TRANSITION,
            json!({ "key": "ABC-1", "transition": "Done" }),
        )
        .await?,
    ];
    assert_eq!(
        offers_match(&h, &ids).await?,
        [offer(DenyOfferKind::OutcomeHint, false)]
    );
    Ok(())
}

/// An edit whose `expected` summary differs from the issue's (the conflict hold, I-36).
fn conflict_params() -> Value {
    json!({"key": "ABC-1", "fields": {"summary": "Login fails after reset"},
           "expected": {"summary": "Login page time out"}})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conflict_hold_has_prefill() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    mount_issue(mock, "ABC-1", &serde_json::from_str(fixtures::JIRA_ISSUE)?).await;
    mount_issue(mock, KEY, &full_issue(KEY)).await;
    let id = queued(&h, EDIT, conflict_params()).await?;
    let p = h.approver().open(&id).map_err(de)?.preview;
    assert!(!p.approvable);
    assert_eq!(p.deny_prefill.as_deref(), Some(CONFLICT_DENY_PREFILL));
    assert!(p.deny_offers.is_empty());
    // Other holds and reads have none.
    let w = comment_item(&h, "Fixed.").await?;
    assert_eq!(
        h.approver().open(&w).map_err(de)?.preview.deny_prefill,
        None
    );
    let r = queued(&h, ISSUE, json!({ "key": KEY })).await?;
    let p = h.approver().open(&r).map_err(de)?.preview;
    assert_eq!((p.deny_prefill, p.deny_offers), (None, Vec::new()));
    Ok(())
}

// ---- sessions (PD-86) --------------------------------------------------------------------------

/// A CLI connection of agent `bot` in `proj`, started by `origin`.
async fn conn_from(h: &Harness, id: &str, origin: &str) -> Result<ConnectionMeta, TestError> {
    let conn = ConnectionMeta {
        connection_id: id.to_owned(),
        peer: PeerInfo {
            peer_exe: Some("/usr/bin/atlas-duck".into()),
            peer_origin_exe: Some(origin.into()),
            ..PeerInfo::default()
        },
    };
    let hello = Hello {
        build_id: BUILD_ID.to_owned(),
        client_kind: ClientKind::Cli,
        agent_name: Some("bot".to_owned()),
        agent_name_source: AgentNameSource::Flag,
        cwd_basename: "proj".to_owned(),
    };
    h.handler()
        .hello(&conn, hello)
        .await
        .map_err(|e| format!("hello refused: {}", e.to_json_line()))?;
    Ok(conn)
}

async fn item_on(h: &Harness, conn: &ConnectionMeta, key: &str) -> Result<QueueItem, TestError> {
    let env = h
        .submit_with(conn, ISSUE, json!({ "key": key }), None)
        .await;
    let id = request_id(&env)?;
    Ok(h.queued(&id, 20_000).await.ok_or("never queued")?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_id_stable_and_path_free() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    for key in ["ABC-1", "ABC-2", "ABC-3"] {
        mount_issue(mock, key, &full_issue(key)).await;
    }
    let origin = "/opt/PATHCANARY-7c1/agent";
    let a = conn_from(&h, "conn-a", origin).await?;
    let b = conn_from(&h, "conn-b", origin).await?;
    let other = conn_from(&h, "conn-c", "/opt/elsewhere/agent").await?;
    let one = item_on(&h, &a, "ABC-1").await?;
    let two = item_on(&h, &b, "ABC-2").await?;
    let three = item_on(&h, &other, "ABC-3").await?;
    // Same `SessionKey` (a CLI session is not per connection), same id; another origin, another.
    assert_eq!(one.session, two.session);
    assert_eq!(one.session_id, two.session_id);
    assert_ne!(one.session_id, three.session_id);
    assert_eq!(one.session_id, one.session.id());
    assert_eq!(one.session_id.len(), 64);
    assert!(
        one.session_id
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    );
    assert_eq!(one.session_label, "bot · proj");
    // The serialized row is path-free: no `SessionKey`, no origin.
    let line = serde_json::to_string(&one)?;
    assert!(!line.contains("PATHCANARY"), "{line}");
    assert!(!line.contains("peer_origin_exe"), "{line}");
    assert!(!line.contains("\"session\""), "{line}");
    assert!(line.contains(&one.session_id), "{line}");
    // The whole list too, as the UI gets it.
    let list = serde_json::to_string(&h.decisions().queue_list())?;
    assert!(!list.contains("PATHCANARY"), "{list}");
    // The app resolves an id to its key through the list; the session deny takes it.
    let session = h
        .decisions()
        .queue_list()
        .into_iter()
        .find(|i| i.session_id == one.session_id)
        .ok_or("no item of the session")?
        .session;
    assert_eq!(h.decisions().deny_session(session, "stop").map_err(de)?, 2);
    assert!(h.approver().item(&three.request_id).is_some());
    Ok(())
}

// ---- M5 M-8: server text in deny hints ---------------------------------------------------------

/// Every string anywhere in `v`.
fn strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(o) => o.iter().for_each(|(k, x)| {
            out.push(k.clone());
            strings(x, out);
        }),
        _ => {}
    }
}

fn clean(v: &Value) -> bool {
    let mut all = Vec::new();
    strings(v, &mut all);
    all.iter()
        .all(|s| !s.contains('\u{202e}') && !s.contains('\n') && !s.contains('\t'))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m8_deny_hint_strings_stripped_and_bounded() -> TestResult {
    use atlas_duck_core::decision::DENY_HINT_MAX_BYTES;
    // 100 required option fields, long names and 10 long labels each, every one with a bidi
    // control and a line break: about 270 KB of server text.
    let fields: Vec<Value> = (0..100)
        .map(|n| {
            let allowed: Vec<Value> = (0..10)
                .map(|k| {
                    json!({"id": format!("{}", 1000 * n + k),
                           "value": format!("L{k} \u{202e}{}\n", "y".repeat(230))})
                })
                .collect();
            json!({"required": true, "schema": {"type": "option"},
                   "name": format!("F{n} \u{202e}name\t{}", "x".repeat(180)),
                   "fieldId": format!("customfield_{}", 20_000 + n), "hasDefaultValue": false,
                   "operations": ["set"], "allowedValues": allowed})
        })
        .collect();
    let h = Harness::jira().await?;
    mount_create_fields(jira(&h)?, fields).await;
    let ids = requests(&h, CREATE, create_params(), 2).await?;
    for (id, ticked) in ids.iter().zip([true, false]) {
        h.approver()
            .deny_with(
                id,
                "too much",
                DenyDetails::MissingFields {
                    include_allowed_values: ticked,
                },
            )
            .map_err(de)?;
        let env = h.await_(id, 5000).await;
        assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
        let details = Value::Object(
            env.error
                .as_ref()
                .and_then(|e| e.details.clone())
                .ok_or("no details")?,
        );
        assert!(
            clean(&details),
            "{ticked}: a flagged character reached the agent"
        );
        let hint = &records(&h, id, EventType::WRITE_DENIED).await?[0]["hint"];
        assert!(
            serde_json::to_vec(hint)?.len() <= DENY_HINT_MAX_BYTES,
            "{ticked}"
        );
        let listed = details["missing_fields"].as_array().ok_or("no list")?;
        let first = &listed[0];
        assert_eq!(first["name"], format!("F0 name{}", "x".repeat(180)));
        if ticked {
            // Cut at a field boundary: the fields listed are whole, the total is kept.
            assert!(listed.len() < 100, "{}", listed.len());
            assert_eq!(details["missing_fields_total"], json!(100));
            for f in listed {
                assert_eq!(f["allowed_values"].as_array().map(Vec::len), Some(10));
            }
            assert_eq!(
                first["allowed_values"][0],
                json!(format!("L0 {}", "y".repeat(230)))
            );
        } else {
            assert_eq!(listed.len(), 100);
            assert!(details.get("missing_fields_total").is_none());
        }
    }

    // Resolution candidates.
    let h = Harness::jira().await?;
    mount_transitions(jira(&h)?, &["Start\u{202e} Progress", "Do\nne"]).await;
    let id = queued(
        &h,
        TRANSITION,
        json!({ "key": "ABC-1", "transition": "Doen" }),
    )
    .await?;
    h.approver()
        .deny_with(
            &id,
            "no",
            DenyDetails::ResolutionFailed {
                include_candidates: true,
            },
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(code(&env), "resolution_failed");
    assert_eq!(
        detail(&env, "candidates"),
        json!(["Start Progress", "Done"])
    );

    // Upstream messages.
    let h = Harness::jira().await?;
    jira(&h)?
        .json(
            "/rest/api/2/issue/NOPE-1/transitions",
            404,
            &json!({"errorMessages": ["Issue \u{202e}does\nnot exist"], "errors": {}}).to_string(),
        )
        .await;
    let id = queued(
        &h,
        TRANSITION,
        json!({ "key": "NOPE-1", "transition": "Done" }),
    )
    .await?;
    h.approver()
        .deny_with(
            &id,
            "gone",
            DenyDetails::UpstreamHttp {
                include_messages: true,
            },
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(code(&env), "upstream_http");
    // Stripped like the human's reason: flagged characters go, the line per message stays.
    let text = detail(&env, "error_messages");
    let text = text.as_str().ok_or("no error_messages")?;
    assert_eq!(text, "Issue does\nnot exist");
    Ok(())
}

/// T7 review M-1: a single server string longer than the whole bound (createmeta's
/// `schema.type` is not capped upstream) is cut on its own, so one missing field cannot carry
/// the hint past `DENY_HINT_MAX_BYTES`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m8_single_over_long_field_cut() -> TestResult {
    use atlas_duck_core::decision::DENY_HINT_MAX_BYTES;
    // 80 Ki quotes serialize to 160 KiB: alone more than twice the bound.
    let huge = "\"".repeat(80 * 1024);
    let fields = vec![json!({"required": true, "schema": {"type": huge},
                             "name": "Team", "fieldId": "customfield_30000",
                             "hasDefaultValue": false, "operations": ["set"]})];
    let h = Harness::jira().await?;
    mount_create_fields(jira(&h)?, fields).await;
    let id = &queued(&h, CREATE, create_params()).await?;
    h.approver()
        .deny_with(
            id,
            "too much",
            DenyDetails::MissingFields {
                include_allowed_values: true,
            },
        )
        .map_err(de)?;
    let env = h.await_(id, 5000).await;
    assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
    let hint = &records(&h, id, EventType::WRITE_DENIED).await?[0]["hint"];
    let size = serde_json::to_vec(hint)?.len();
    assert!(size <= DENY_HINT_MAX_BYTES, "{size}");
    let listed = detail(&env, "missing_fields");
    let listed = listed.as_array().ok_or("no list")?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"], json!("customfield_30000"));
    let ty = listed[0]["schema_type"].as_str().ok_or("no schema_type")?;
    assert!(ty.len() <= 1024, "{}", ty.len());
    assert!(ty.starts_with("\"\"\"") && ty.ends_with('…'), "{ty}");
    Ok(())
}
