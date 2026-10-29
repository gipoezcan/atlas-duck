#![cfg(feature = "testing")]
//! `confluence.page.move` (M7 Task 17, PD-106; §5.4 steps 2 and 5, §6.3 Page move, §7.4): the page
//! read with its version, space and ancestors, the new parent resolved by id or by title within the
//! page's own space (I-35: no match and ambiguous hold the write; a page of another space is no
//! match, cross-space moves are a non-goal), the hold of a move under the page itself or one of its
//! descendants, the `PUT` with the current title, `version.number` + 1 and the new `ancestors`
//! (no `body`, lead ruling Q4), the version stale rule (`stale::PAGE_MOVE`), the `PageMove` card
//! over the exact request and the pre-write identity call.
//!
//! Checked twice: as pure functions of the op table (plan, judge, executor, stale rule, previewer
//! as the engine calls them) and end to end through the harness. A file of its own (not
//! `confluence_writes.rs`, plan text): its helpers would clash with the comment suite's.

mod common;

use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, UserKind, fixtures};
use atlas_duck_atlassian::{GetCall, HttpRequestSpec};
use atlas_duck_audit::EventType;
use atlas_duck_core::lifecycle::model::Hold;
use atlas_duck_core::ops::{
    EnrichCtx, EnrichPurpose, EnrichStep, EnrichVerdict, ExecCtx, ExecError, ExecPlan, PreviewCtx,
    PreviewInput, PreviewModel, StaleCtx, StaleVerdict, WriteView, op_table,
};
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::Harness;
use atlas_duck_core::{DecisionError, DecisionOutcome, DenyDetails, Edits, QueueItem};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::{Platform, Preview, PreviewBody, WarningId, render};
use common::confluence::content_path;
use common::{TestError, TestResult, code, de, detail, exit, request_id};
use serde_json::{Map, Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const MOVE: &str = "confluence.page.move";
const PAGE_ID: &str = "65537";
const PAGE_TITLE: &str = "Release checklist";
const SPACE: &str = "DOC";
const HOME_ID: &str = "65536";
const PARENT_ID: &str = "123400";
const PARENT_TITLE: &str = "Release notes";
/// A child of the moved page.
const CHILD_ID: &str = "65600";
/// PD-106 (plan text): the card of a move under the page itself or one of its descendants.
const CYCLE_TEXT: &str = "a page cannot be moved under itself or one of its descendants";
/// The card's fixed row (PD-106, plan review m-14), written by the renderer.
const BODY_NOT_SENT: &str = "body not sent; title and body kept by Confluence";
/// The stage-1 `expand` (PD-106).
const PAGE_EXPAND: &str = "version,space,ancestors";

// ---- pure helpers: the op table as the engine calls it ---------------------------------------

fn spec() -> Result<&'static atlas_duck_registry::OperationSpec, TestError> {
    atlas_duck_registry::get(MOVE).ok_or_else(|| "no confluence.page.move".into())
}

/// A page as `GET /rest/api/content/{id}?expand=…space,ancestors` (and each title-lookup
/// result) answers it: `ancestors` are `(id, title)`, root first.
fn page(id: &str, title: &str, space: &str, ancestors: &[(&str, &str)]) -> Value {
    let ancestors: Vec<Value> = ancestors
        .iter()
        .map(|(id, title)| json!({"id": id, "type": "page", "status": "current", "title": title}))
        .collect();
    json!({
        "id": id,
        "type": "page",
        "status": "current",
        "title": title,
        "space": {"id": 98305, "key": space, "name": "Documentation", "type": "global"},
        "ancestors": ancestors,
        "_links": {"webui": format!("/display/{space}/{id}")},
    })
}

/// The moved page (stage 1): `Release checklist` under `Home` in `DOC` at `version`.
fn moved_page(version: u64) -> Value {
    let mut p = page(PAGE_ID, PAGE_TITLE, SPACE, &[(HOME_ID, "Home")]);
    p["version"] = json!({"number": version, "when": "2026-10-06T14:00:00.000+02:00"});
    p
}

/// The new parent `Release notes` (a sibling of the moved page, under `Home`).
fn parent_answer() -> Value {
    page(PARENT_ID, PARENT_TITLE, SPACE, &[(HOME_ID, "Home")])
}

/// A child of the moved page, as the parent answer of a move under it.
fn child_answer() -> Value {
    page(
        CHILD_ID,
        "Checklist details",
        SPACE,
        &[(HOME_ID, "Home"), (PAGE_ID, PAGE_TITLE)],
    )
}

/// A title lookup's answer (`GET /rest/api/content?spaceKey&title&type=page…`).
fn lookup(results: &[Value]) -> Value {
    json!({"results": results, "start": 0, "limit": 50, "size": results.len()})
}

fn params(parent: &str) -> Value {
    json!({ "id": PAGE_ID, "parent": parent })
}

type Rounds = Vec<Vec<(EnrichPurpose, GetCall)>>;

/// The rule's rounds over `answers` the way the engine's staged driver feeds them, then the judge.
fn staged(params: &Value, answers: &[Value]) -> Result<(Rounds, EnrichVerdict), TestError> {
    let rule = op_table()
        .get(MOVE)
        .and_then(|i| i.enrich)
        .ok_or("no enrich rule")?;
    let ctx = EnrichCtx {
        spec: spec()?,
        params,
    };
    let mut given: Vec<Value> = Vec::new();
    let mut rounds = Vec::new();
    loop {
        match (rule.plan)(&ctx, &given) {
            EnrichStep::Judge => break,
            EnrichStep::Fetch(calls) => {
                for _ in &calls {
                    let next = answers
                        .get(given.len())
                        .ok_or("the plan asked for more answers than the test gives")?;
                    given.push(next.clone());
                }
                rounds.push(calls);
            }
        }
        if rounds.len() > 4 {
            return Err("more than four rounds".into());
        }
    }
    Ok((rounds, (rule.judge)(&ctx, &given)))
}

/// The verdict of a move under `PARENT_ID` at version 7.
fn verdict() -> Result<EnrichVerdict, TestError> {
    Ok(staged(&params(PARENT_ID), &[moved_page(7), parent_answer()])?.1)
}

/// The executor on `params` with `v` as the verdict.
fn exec(params: &Value, v: Option<&EnrichVerdict>) -> Result<ExecPlan, ExecError> {
    let base = atlas_duck_atlassian::normalize_base_url("https://wiki.example.invalid/wiki")
        .map_err(|_| ExecError::NotInThisBuild)?;
    let imp = op_table().get(MOVE).ok_or(ExecError::NotInThisBuild)?;
    let spec = spec().map_err(|_| ExecError::NotInThisBuild)?;
    let ctx = ExecCtx {
        spec,
        params,
        base: &base,
        enrichment: v,
        effective_max: None,
        comments_cap: None,
        test_fault: None,
    };
    (imp.executor)(&ctx)
}

fn requests(params: &Value, v: &EnrichVerdict) -> Result<Vec<HttpRequestSpec>, TestError> {
    match exec(params, Some(v)) {
        Ok(ExecPlan::Write(r)) => Ok(r),
        other => Err(format!("not a write: {other:?}").into()),
    }
}

fn preview_of(
    params: &Value,
    v: &EnrichVerdict,
    reqs: &[HttpRequestSpec],
) -> Result<PreviewModel, TestError> {
    let imp = op_table().get(MOVE).ok_or("no OpImpl")?;
    let ctx = PreviewCtx {
        spec: spec()?,
        instance_alias: "wiki",
        params,
        input: PreviewInput::Write(WriteView {
            requests: reqs,
            hold: v.hold,
            enrichment: Some(v),
            failure: None,
        }),
        field_names: None,
    };
    Ok((imp.previewer)(&ctx))
}

fn sent(r: &[HttpRequestSpec]) -> Result<Value, TestError> {
    let [one] = r else {
        return Err(format!("{} requests", r.len()).into());
    };
    Ok(serde_json::from_slice(&one.body)?)
}

fn query(call: &GetCall) -> Vec<(&str, &str)> {
    call.query
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

fn unresolved_of(v: &EnrichVerdict) -> Option<(&str, &str, u64, Vec<&str>)> {
    v.unresolved.as_ref().map(|(p, val, n, c)| {
        (
            p.as_str(),
            val.as_str(),
            *n,
            c.iter().map(String::as_str).collect(),
        )
    })
}

/// `(page, from_path, to_path)` of a `PageMove` card (its one request kept).
fn move_card(m: &PreviewModel) -> Result<(&str, Vec<&str>, Vec<&str>), TestError> {
    match &m.body {
        PreviewBody::PageMove {
            page,
            from_path,
            to_path,
            requests,
        } => {
            assert_eq!(requests.len(), 1, "the request list stays part of the body");
            Ok((
                page.as_str(),
                from_path.iter().map(String::as_str).collect(),
                to_path.iter().map(String::as_str).collect(),
            ))
        }
        other => Err(format!("not a page-move card: {other:?}").into()),
    }
}

/// The text of an `EnrichmentError` card.
fn enrichment_text(body: &PreviewBody) -> Result<&str, TestError> {
    match body {
        PreviewBody::EnrichmentError { text, status, .. } => {
            assert_eq!(*status, None, "the judge's hold, no failed fetch");
            Ok(text)
        }
        other => Err(format!("not the enrichment card: {other:?}").into()),
    }
}

#[test]
fn page_move_plan_stages() -> TestResult {
    // A parent id: the page (`enrich`), then the parent by id (`resolve`), one GET per round.
    let p = params(PARENT_ID);
    let (rounds, v) = staged(&p, &[moved_page(7), parent_answer()])?;
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    let [first, second] = rounds.as_slice() else {
        return Err(format!("{} rounds", rounds.len()).into());
    };
    let ([(p1, the_page)], [(p2, the_parent)]) = (first.as_slice(), second.as_slice()) else {
        return Err("not one GET per round".into());
    };
    assert_eq!((*p1, *p2), (EnrichPurpose::Enrich, EnrichPurpose::Resolve));
    assert_eq!(the_page.endpoint_template, "/rest/api/content/{id}");
    assert_eq!(the_page.params, json!({"id": PAGE_ID}));
    assert_eq!(query(the_page), [("expand", PAGE_EXPAND)]);
    assert_eq!(the_parent.endpoint_template, "/rest/api/content/{parent}");
    assert_eq!(the_parent.params, json!({"parent": PARENT_ID}));
    assert_eq!(query(the_parent), [("expand", "space,ancestors")]);
    // The stale baseline is the version enrichment read; the executor's inputs are resolved.
    assert_eq!(v.baseline["version"], json!(7));
    // The baseline names both ends of the move: the page's current parent (its last ancestor) and
    // the destination; neither is the other's value under a vague key.
    assert_eq!(v.baseline["from_parent_id"], json!(HOME_ID));
    assert_eq!(v.baseline["to_parent_id"], json!(PARENT_ID));
    assert!(v.baseline.get("parent_id").is_none(), "{:?}", v.baseline);
    assert_eq!(v.resolved.get("id"), Some(&json!(PAGE_ID)));
    assert_eq!(v.resolved.get("parent"), Some(&json!(PARENT_ID)));
    assert_eq!(v.resolved.get("parent_id"), Some(&json!(PARENT_ID)));
    assert_eq!(v.resolved.get("title"), Some(&json!(PAGE_TITLE)));

    // A parent title: looked up in the page's own space (the stage-1 answer's key, not a param),
    // current pages, at most fifty.
    let mut eng = moved_page(7);
    eng["space"]["key"] = json!("ENG");
    let p = params(PARENT_TITLE);
    let (rounds, v) = staged(
        &p,
        &[
            eng,
            lookup(&[page(PARENT_ID, PARENT_TITLE, "ENG", &[(HOME_ID, "Home")])]),
        ],
    )?;
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    let [(purpose, by_title)] = rounds[1].as_slice() else {
        return Err("not one GET".into());
    };
    assert_eq!(*purpose, EnrichPurpose::Resolve);
    assert_eq!(by_title.endpoint_template, "/rest/api/content");
    assert_eq!(
        query(by_title),
        [
            ("spaceKey", "ENG"),
            ("title", PARENT_TITLE),
            ("type", "page"),
            ("status", "current"),
            ("expand", "space,ancestors"),
            ("limit", "50")
        ]
    );
    assert_eq!(v.resolved.get("parent_id"), Some(&json!(PARENT_ID)));

    // A page the judge cannot use ends the plan after stage 1: no parent lookup.
    let mut blog = moved_page(7);
    blog["type"] = json!("blogpost");
    let (rounds, v) = staged(&params(PARENT_ID), &[blog])?;
    assert_eq!((rounds.len(), v.hold), (1, Hold::EnrichmentError));

    // A root page has no current parent.
    let mut root = moved_page(7);
    root["ancestors"] = json!([]);
    let (_, v) = staged(&params(PARENT_ID), &[root, parent_answer()])?;
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    assert_eq!(v.baseline["from_parent_id"], Value::Null);
    Ok(())
}

/// The stage-1 answer must be this very page, a current `page` with a version, a title, a space
/// key and an `ancestors` array of page ids (the old path); anything else fails closed.
#[test]
fn page_move_page_answer_fails_closed() -> TestResult {
    let p = params(PARENT_ID);
    let without = |key: &str| -> Result<Value, TestError> {
        let mut v = moved_page(7);
        v.as_object_mut().ok_or("not an object")?.remove(key);
        Ok(v)
    };
    let with = |key: &str, val: Value| {
        let mut v = moved_page(7);
        v[key] = val;
        v
    };
    let mut no_space_key = moved_page(7);
    no_space_key["space"] = json!({"name": "Documentation"});
    for (what, answer) in [
        ("another id", with("id", json!("65538"))),
        ("a blog post", with("type", json!("blogpost"))),
        ("trashed", with("status", json!("trashed"))),
        ("no status", without("status")?),
        ("no version", without("version")?),
        (
            "a version that is no number",
            with("version", json!({"number": "7"})),
        ),
        ("no title", without("title")?),
        ("no space key", no_space_key),
        ("no ancestors", without("ancestors")?),
        ("ancestors not a list", with("ancestors", json!({}))),
        (
            "an ancestor without id",
            with("ancestors", json!([{"title": "Home"}])),
        ),
        (
            "an ancestor id that is no page id",
            with("ancestors", json!([{"id": "x1", "title": "Home"}])),
        ),
    ] {
        let (rounds, v) = staged(&p, &[answer, parent_answer()])?;
        assert_eq!(v.hold, Hold::EnrichmentError, "{what}");
        assert_eq!(rounds.len(), 1, "{what}: no parent lookup");
        assert!(requests(&p, &v).is_err(), "{what}");
    }
    // The server may send the id as a number; a root page has no ancestors.
    assert_eq!(
        staged(&p, &[with("id", json!(65_537)), parent_answer()])?
            .1
            .hold,
        Hold::Preview
    );
    assert_eq!(
        staged(&p, &[with("ancestors", json!([])), parent_answer()])?
            .1
            .hold,
        Hold::Preview
    );
    Ok(())
}

/// PD-106: a parent that is the page itself or has the page among its ancestors is held
/// ("enrichment failed" with the plan text; Approve disabled, nothing rendered); the comparison
/// is by page id over the whole ancestor chain, never by text.
#[test]
fn page_move_into_own_subtree_is_held() -> TestResult {
    let held = |parent: &str, answer: Value| -> TestResult {
        let p = params(parent);
        let v = staged(&p, &[moved_page(7), answer.clone()])?.1;
        assert_eq!(v.hold, Hold::EnrichmentError, "{parent}: {answer}");
        assert!(
            matches!(exec(&p, Some(&v)), Err(ExecError::EnrichmentRequired)),
            "{parent}: nothing renders"
        );
        let m = preview_of(&p, &v, &[])?;
        assert_eq!(enrichment_text(&m.body)?, CYCLE_TEXT, "{parent}");
        Ok(())
    };
    // The page itself, by id.
    held(
        PAGE_ID,
        page(PAGE_ID, PAGE_TITLE, SPACE, &[(HOME_ID, "Home")]),
    )?;
    // A child, a deep descendant, and a child whose chain names the page as a number or with
    // leading zeros.
    held(CHILD_ID, child_answer())?;
    held(
        "65700",
        page(
            "65700",
            "Deep",
            SPACE,
            &[
                (HOME_ID, "Home"),
                (PAGE_ID, PAGE_TITLE),
                (CHILD_ID, "Checklist details"),
                ("65650", "Mid"),
            ],
        ),
    )?;
    let mut numeric = child_answer();
    numeric["ancestors"][1]["id"] = json!(65_537);
    held(CHILD_ID, numeric)?;
    let mut zeros = child_answer();
    zeros["ancestors"][1]["id"] = json!("0065537");
    held(CHILD_ID, zeros)?;
    // By title: the one page of that title is a child of the page.
    held(
        "Checklist details",
        lookup(&[page(
            CHILD_ID,
            "Checklist details",
            SPACE,
            &[(HOME_ID, "Home"), (PAGE_ID, PAGE_TITLE)],
        )]),
    )?;
    // By title: the page itself.
    held(
        PAGE_TITLE,
        lookup(&[page(PAGE_ID, PAGE_TITLE, SPACE, &[(HOME_ID, "Home")])]),
    )?;

    // Not a descendant: a sibling, the page's own ancestor, an id that only contains the digits.
    let free = |parent: &str, answer: Value| -> TestResult {
        let p = params(parent);
        let v = staged(&p, &[moved_page(7), answer.clone()])?.1;
        assert_eq!(v.hold, Hold::Preview, "{parent}: {answer}");
        assert!(requests(&p, &v).is_ok());
        Ok(())
    };
    free(PARENT_ID, parent_answer())?;
    free(HOME_ID, page(HOME_ID, "Home", SPACE, &[]))?;
    free(
        "655370",
        page(
            "655370",
            "Other",
            SPACE,
            &[(HOME_ID, "Home"), ("6553", "x")],
        ),
    )?;
    Ok(())
}

/// §7.4 "same space only" / §1.3: the parent is resolved within the page's own space; a page of
/// another space is no match ("unresolved name", Approve disabled).
#[test]
fn page_move_parent_in_other_space_is_unresolved() -> TestResult {
    let p = params(PARENT_ID);
    let v = staged(
        &p,
        &[
            moved_page(7),
            page(PARENT_ID, PARENT_TITLE, "OPS", &[(HOME_ID, "Home")]),
        ],
    )?
    .1;
    assert_eq!(
        unresolved_of(&v),
        Some(("parent", PARENT_ID, 0, Vec::new()))
    );
    assert!(requests(&p, &v).is_err());
    let p = params(PARENT_TITLE);
    let v = staged(
        &p,
        &[
            moved_page(7),
            lookup(&[page(PARENT_ID, PARENT_TITLE, "OPS", &[])]),
        ],
    )?
    .1;
    assert_eq!(v.hold, Hold::UnresolvedName);
    // I-35 by title: none, and two (ambiguous: their titles the candidates).
    let v = staged(&p, &[moved_page(7), lookup(&[])])?.1;
    assert_eq!(
        unresolved_of(&v),
        Some(("parent", PARENT_TITLE, 0, Vec::new()))
    );
    let v = staged(
        &p,
        &[
            moved_page(7),
            lookup(&[
                page("1", PARENT_TITLE, SPACE, &[]),
                page("2", "release notes", SPACE, &[]),
            ]),
        ],
    )?
    .1;
    assert_eq!(
        unresolved_of(&v),
        Some((
            "parent",
            PARENT_TITLE,
            2,
            vec![PARENT_TITLE, "release notes"]
        ))
    );
    assert!(requests(&p, &v).is_err());
    Ok(())
}

/// PD-106 (lead ruling Q4): `PUT /rest/api/content/{id}` with the current title, the version
/// enrichment read + 1 and the resolved parent as the one ancestor; no `body`, no `space`.
#[test]
fn page_move_body_is_the_spec_payload() -> TestResult {
    let p = params(PARENT_TITLE);
    let v = staged(
        &p,
        &[
            moved_page(41),
            lookup(&[page(PARENT_ID, PARENT_TITLE, SPACE, &[(HOME_ID, "Home")])]),
        ],
    )?
    .1;
    let r = requests(&p, &v)?;
    assert_eq!(r[0].method, "PUT");
    assert_eq!(
        r[0].resolved_url,
        "https://wiki.example.invalid/wiki/rest/api/content/65537"
    );
    assert_eq!(r[0].content_type.as_deref(), Some("application/json"));
    assert_eq!(
        sent(&r)?,
        json!({
            "id": PAGE_ID,
            "type": "page",
            "title": PAGE_TITLE,
            "version": {"number": 42},
            "ancestors": [{"id": PARENT_ID}],
        })
    );
    // Deterministic (`WRITE_APPROVED` hashes it).
    assert_eq!(requests(&p, &v)?, requests(&p, &v)?);
    Ok(())
}

#[test]
fn page_move_executor_needs_a_matching_verdict() -> TestResult {
    let p = params(PARENT_ID);
    // The validation dry call: the op is no longer "not in this build".
    assert_eq!(exec(&p, None), Err(ExecError::EnrichmentRequired));
    let v = verdict()?;
    assert!(requests(&p, &v).is_ok());
    for hold in [
        Hold::EnrichmentError,
        Hold::UnresolvedName,
        Hold::Conflict,
        Hold::Collision,
        Hold::IdentityMismatch,
    ] {
        let mut held = v.clone();
        held.hold = hold;
        assert_eq!(
            exec(&p, Some(&held)),
            Err(ExecError::EnrichmentRequired),
            "{hold:?}"
        );
    }
    // The verdict must be about these very params: another parent (an edit not re-enriched yet,
    // by id or by title) or another page.
    for (what, q) in [
        ("parent", params("123401")),
        ("parent title", params(PARENT_TITLE)),
        ("page", json!({"id": "65538", "parent": PARENT_ID})),
    ] {
        assert_eq!(
            exec(&q, Some(&v)),
            Err(ExecError::EnrichmentRequired),
            "{what}"
        );
    }
    for key in ["id", "parent", "parent_id", "title"] {
        let mut broken = v.clone();
        broken.resolved.remove(key);
        assert_eq!(
            exec(&p, Some(&broken)),
            Err(ExecError::EnrichmentRequired),
            "{key}"
        );
    }
    for (what, parent_id) in [("no page id", json!("abc")), ("the page", json!(PAGE_ID))] {
        let mut broken = v.clone();
        broken.resolved.insert("parent_id".into(), parent_id);
        assert_eq!(
            exec(&p, Some(&broken)),
            Err(ExecError::EnrichmentRequired),
            "{what}"
        );
    }
    // The version comes from the stale baseline: without a usable one nothing renders.
    for baseline in [
        json!({}),
        json!({"version": "7"}),
        json!({"version": u64::MAX}),
    ] {
        let mut broken = v.clone();
        broken.baseline = baseline.clone();
        assert_eq!(
            exec(&p, Some(&broken)),
            Err(ExecError::EnrichmentRequired),
            "{baseline}"
        );
    }
    Ok(())
}

/// §5.4 step 5: `stale::PAGE_MOVE` re-reads `version.number` and compares it with the baseline
/// the approver's verdict carries.
#[test]
fn page_move_stale_rule_is_the_version() -> TestResult {
    let rule = op_table()
        .get(MOVE)
        .and_then(|i| i.stale_check)
        .ok_or("no stale rule")?;
    let p = params(PARENT_ID);
    let v = verdict()?;
    let ctx = StaleCtx {
        spec: spec()?,
        params: &p,
        baseline: &v.baseline,
    };
    let calls = (rule.plan)(&ctx);
    let [call] = calls.as_slice() else {
        return Err(format!("{} stale GETs", calls.len()).into());
    };
    assert_eq!(call.endpoint_template, "/rest/api/content/{id}");
    assert_eq!(call.params, json!({"id": PAGE_ID}));
    assert_eq!(query(call), [("expand", "version")]);
    assert_eq!(
        (rule.judge)(&ctx, &[moved_page(7)]),
        StaleVerdict::Unchanged
    );
    assert_eq!(
        (rule.judge)(&ctx, &[moved_page(8)]),
        StaleVerdict::Changed {
            delta: "page version changed since review (v7 → v8)".to_owned()
        }
    );
    for unreadable in [vec![], vec![json!({"id": PAGE_ID})]] {
        assert!(
            matches!(
                (rule.judge)(&ctx, &unreadable),
                StaleVerdict::Changed { .. }
            ),
            "fail closed"
        );
    }
    Ok(())
}

/// §6.3 Page move: the old path (the page's ancestors, then the page) and the new path (the
/// parent's ancestors, the parent, then the page), over the request that is sent; the page row
/// names the version the `PUT` replaces and the one it writes.
#[test]
fn page_move_card_paths() -> TestResult {
    let p = params(PARENT_ID);
    let v = verdict()?;
    let m = preview_of(&p, &v, &requests(&p, &v)?)?;
    let (page_row, from, to) = move_card(&m)?;
    assert_eq!(page_row, "Release checklist (page 65537, version 7 → 8)");
    assert_eq!(from, ["Home", PAGE_TITLE]);
    assert_eq!(to, ["Home", PARENT_TITLE, PAGE_TITLE]);
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);

    // A root page moved under a root page.
    let mut root = moved_page(7);
    root["ancestors"] = json!([]);
    let p = params(HOME_ID);
    let v = staged(&p, &[root, page(HOME_ID, "Home", SPACE, &[])])?.1;
    let m = preview_of(&p, &v, &requests(&p, &v)?)?;
    let (_, from, to) = move_card(&m)?;
    assert_eq!(from, [PAGE_TITLE]);
    assert_eq!(to, ["Home", PAGE_TITLE]);
    Ok(())
}

/// §5.1 inv. 4: the card reads the page, title, version and parent from the request that is
/// sent; a request that is not the move JSON for what enrichment resolved (another parent, page,
/// title, version or type, or a `body` the fixed row says is not sent) keeps the generic card.
#[test]
fn page_move_card_reads_the_sent_request() -> TestResult {
    let p = params(PARENT_ID);
    let v = verdict()?;
    let generic = |edit: &dyn Fn(&mut Value)| -> TestResult {
        let mut reqs = requests(&p, &v)?;
        let mut body = sent(&reqs)?;
        edit(&mut body);
        if let Some(r) = reqs.first_mut() {
            r.body = serde_json::to_vec(&body)?;
        }
        let m = preview_of(&p, &v, &reqs)?;
        assert!(
            !matches!(m.body, PreviewBody::PageMove { .. }),
            "{body}: {:?}",
            m.body
        );
        Ok(())
    };
    generic(&|b| b["ancestors"] = json!([{"id": "999"}]))?;
    generic(&|b| b["ancestors"] = json!([{"id": PARENT_ID}, {"id": "999"}]))?;
    generic(&|b| b["ancestors"] = json!([]))?;
    generic(&|b| b["id"] = json!("65538"))?;
    generic(&|b| b["title"] = json!("Renamed"))?;
    generic(&|b| b["version"] = json!({"number": 9}))?;
    generic(&|b| b["version"] = json!({"number": 7}))?;
    generic(&|b| b["type"] = json!("blogpost"))?;
    generic(&|b| {
        b["body"] = json!({"storage": {"value": "", "representation": "storage"}});
    })?;
    generic(&|b| b["space"] = json!({"key": SPACE}))?;
    Ok(())
}

/// T16 review m-2 (applied here): only a Preview verdict gives the move card, even with the very
/// requests a Preview would show.
#[test]
fn page_move_card_keeps_the_generic_body_without_a_verdict() -> TestResult {
    let p = params(PARENT_ID);
    let v = verdict()?;
    let reqs = requests(&p, &v)?;
    move_card(&preview_of(&p, &v, &reqs)?)?;
    for hold in [
        Hold::EnrichmentError,
        Hold::Collision,
        Hold::UnresolvedName,
        Hold::Conflict,
        Hold::IdentityMismatch,
    ] {
        let mut held = v.clone();
        held.hold = hold;
        let m = preview_of(&p, &held, &reqs)?;
        assert!(
            !matches!(m.body, PreviewBody::PageMove { .. }),
            "{hold:?}: {:?}",
            m.body
        );
    }
    let m = preview_of(&p, &v, &[])?;
    assert!(
        !matches!(m.body, PreviewBody::PageMove { .. }),
        "{:?}",
        m.body
    );
    Ok(())
}

/// §6.4 / T12b rules: the titles the card shows beyond the request (the ancestors and the
/// parent) are server text: display-escaped and their invisible characters counted; a title past
/// the cell cap is cut and the cut bytes count as hidden.
#[test]
fn page_move_card_counts_what_it_shows() -> TestResult {
    let p = params(PARENT_ID);
    let parent = page(
        PARENT_ID,
        "Notes\u{202e}txt",
        SPACE,
        &[(HOME_ID, "Ho\u{200b}me")],
    );
    let v = staged(&p, &[moved_page(7), parent])?.1;
    let m = preview_of(&p, &v, &requests(&p, &v)?)?;
    let (_, from, to) = move_card(&m)?;
    assert!(
        to.iter()
            .chain(&from)
            .all(|t| !t.contains('\u{202e}') && !t.contains('\u{200b}')),
        "{to:?}"
    );
    assert!(to.iter().any(|t| t.contains("U+202E")), "{to:?}");
    assert!(m.header.bidi_controls >= 1, "{:?}", m.header.bidi_controls);
    assert!(
        m.header.other_invisible >= 1,
        "{:?}",
        m.header.other_invisible
    );
    assert!(
        m.warnings.iter().any(|w| w.id == WarningId::BidiControls),
        "{:?}",
        m.warnings
    );

    let long = "x".repeat(5000);
    let v = staged(
        &p,
        &[
            moved_page(7),
            page(PARENT_ID, &long, SPACE, &[(HOME_ID, "Home")]),
        ],
    )?
    .1;
    let m = preview_of(&p, &v, &requests(&p, &v)?)?;
    let (_, _, to) = move_card(&m)?;
    assert!(to.iter().all(|t| t.len() < long.len()), "the title is cut");
    assert!(m.header.hidden_in_preview_bytes > 0);
    Ok(())
}

/// The old path (`from_path`, the moved page's own ancestors) is shown too, so an invisible
/// character in one of its titles is counted, not only escaped. The new path is plain here, so
/// only the old path can account for the character.
#[test]
fn page_move_card_counts_invisibles_in_the_old_path() -> TestResult {
    let p = params(PARENT_ID);
    let card_with = |ancestor: &str| -> Result<PreviewModel, TestError> {
        let mut moved = moved_page(7);
        moved["ancestors"] = json!([{"id": HOME_ID, "type": "page", "title": ancestor}]);
        let v = staged(&p, &[moved, parent_answer()])?.1;
        preview_of(&p, &v, &requests(&p, &v)?)
    };
    let plain = card_with("Home")?;
    let m = card_with("Ho\u{200b}me")?;
    let from = move_card(&m)?.1;
    assert!(from.iter().all(|t| !t.contains('\u{200b}')), "{from:?}");
    assert_eq!(
        m.header.other_invisible,
        plain.header.other_invisible + 1,
        "one ZWSP in the old path"
    );
    Ok(())
}

// ---- end to end ------------------------------------------------------------------------------

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no wiki mock".into())
}

fn json_answer(mock: &MockDc, status: u16, body: &Value) -> ResponseTemplate {
    mock.response(status)
        .set_body_raw(body.to_string(), "application/json")
}

/// `GET /rest/api/content/<id>` (any query) answers `body` with `status`.
async fn mount_content(mock: &MockDc, id: &str, status: u16, body: &Value) {
    Mock::given(method("GET"))
        .and(path(mock.path(&content_path(id))))
        .respond_with(json_answer(mock, status, body))
        .mount(mock.server())
        .await;
}

/// `GET /rest/api/content/<id>?expand=<expand>` answers `body`, ahead of a [`mount_content`] of
/// the same path; only the first `times` requests when given.
async fn mount_expand(mock: &MockDc, id: &str, expand: &str, body: &Value, times: Option<u64>) {
    let m = Mock::given(method("GET"))
        .and(path(mock.path(&content_path(id))))
        .and(query_param("expand", expand))
        .respond_with(json_answer(mock, 200, body));
    let m = match times {
        Some(n) => m.up_to_n_times(n).with_priority(1),
        None => m.with_priority(2),
    };
    m.mount(mock.server()).await;
}

/// `PUT /rest/api/content/65537` answers `status` with `body`; only the first `times` when given.
async fn mount_put(mock: &MockDc, status: u16, body: &str, times: Option<u64>) {
    let m = Mock::given(method("PUT"))
        .and(path(mock.path(&content_path(PAGE_ID))))
        .respond_with(
            mock.response(status)
                .set_body_raw(body.to_owned(), "application/json"),
        );
    let m = match times {
        Some(n) => m.up_to_n_times(n).with_priority(1),
        None => m.with_priority(2),
    };
    m.mount(mock.server()).await;
}

/// The server side of a move in `DOC`: the identity call, the page at version 7 (stage 1 and the
/// stale check), the parent by id, its child and the `PUT`'s answer.
async fn move_server(mock: &MockDc) {
    move_reads(mock).await;
    mount_put(mock, 200, fixtures::CONFLUENCE_PAGE_UPDATED, None).await;
}

/// Everything `move_server` mounts but the `PUT`.
async fn move_reads(mock: &MockDc) {
    mock.confluence_user_current(UserKind::Known, TEST_USER, TEST_USER_KEY)
        .await;
    mount_content(mock, PAGE_ID, 200, &moved_page(7)).await;
    mount_content(mock, PARENT_ID, 200, &parent_answer()).await;
    mount_content(mock, CHILD_ID, 200, &child_answer()).await;
}

async fn queued(h: &Harness, params: Value) -> Result<String, TestError> {
    let env = h.submit(MOVE, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

fn opened(h: &Harness, id: &str) -> Result<Preview, TestError> {
    Ok(h.approver().open(id).map_err(de)?.preview)
}

fn not_approvable(res: Result<DecisionOutcome, DecisionError>) -> TestResult {
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    Ok(())
}

async fn puts(mock: &MockDc) -> Vec<wiremock::Request> {
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "PUT")
        .collect()
}

async fn sent_puts(mock: &MockDc) -> Result<Vec<Value>, TestError> {
    puts(mock)
        .await
        .iter()
        .map(|r| serde_json::from_slice(&r.body).map_err(Into::into))
        .collect()
}

async fn purposes(h: &Harness, id: &str) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::PREVIEW_FETCH)
        .map(|(_, p)| p["purpose"].clone())
        .collect())
}

async fn stale_reasons(h: &Harness, id: &str) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::WRITE_STALE)
        .map(|(_, p)| p["reason"].clone())
        .collect())
}

async fn item_after(h: &Harness, id: &str, rev: u64) -> Result<QueueItem, TestError> {
    for _ in 0..400 {
        if let Some(item) = h.approver().item(id)
            && item.candidate_rev.counter > rev
        {
            return Ok(item);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err("the revision never advanced".into())
}

fn unresolved_card(p: &Preview) -> Result<(&str, &str, u64, &[String]), TestError> {
    match &p.body {
        PreviewBody::UnresolvedName {
            param,
            value,
            matches,
            candidates,
        } => Ok((param, value, *matches, candidates)),
        other => Err(format!("not the unresolved-name card: {other:?}").into()),
    }
}

fn set_parent(parent: &str) -> Edits {
    let mut set = Map::new();
    set.insert("parent".into(), json!(parent));
    Edits {
        set,
        remove: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_move_sends_ancestors_and_version_plus_one() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    move_server(mock).await;
    let id = queued(&h, params(PARENT_ID)).await?;
    assert!(opened(&h, &id)?.approvable);
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let sent = sent_puts(mock).await?;
    assert_eq!(
        sent,
        [json!({
            "id": PAGE_ID,
            "type": "page",
            "title": PAGE_TITLE,
            "version": {"number": 8},
            "ancestors": [{"id": PARENT_ID}],
        })]
    );
    assert!(sent[0].get("body").is_none(), "no body (lead ruling Q4)");
    // The receipt is the projection of the PUT's answer (`CONFLUENCE_PAGE_UPDATED`).
    assert_eq!(
        env.data,
        Some(json!({"receipt": {
            "id": PAGE_ID, "type": "page", "status": "current",
            "version": {"number": 8},
            "_links": {"webui": "/display/DOC/Release+checklist"},
        }}))
    );
    // The page (`enrich`) and the parent (`resolve`); after the approval the identity call and
    // the version re-read (both `stale_check`).
    assert_eq!(
        purposes(&h, &id).await?,
        [
            json!("enrich"),
            json!("resolve"),
            json!("stale_check"),
            json!("stale_check")
        ]
    );
    // Stage 1 asked for the version, space and ancestors; the stale check for the version.
    let page_gets: Vec<String> = mock
        .received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "GET" && r.url.path() == mock.path(&content_path(PAGE_ID)))
        .filter_map(|r| r.url.query().map(str::to_owned))
        .collect();
    assert_eq!(
        page_gets,
        ["expand=version%2Cspace%2Cancestors", "expand=version"]
    );
    Ok(())
}

/// I-35 (parent page): no match and ambiguous disable Approve; a parent id the server does not
/// know (JSON 404) is an enrichment error (the engine holds a non-2xx answer before the judge,
/// T16 deviation 1): Approve disabled too. Nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i35_move_parent_no_match_and_ambiguous() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    move_server(mock).await;
    common::confluence::mount_title_lookup(mock, SPACE, "Nowhere", &[]).await;
    let id = queued(&h, params("Nowhere")).await?;
    let p = opened(&h, &id)?;
    assert_eq!(unresolved_card(&p)?, ("parent", "Nowhere", 0, &[][..]));
    assert!(!p.approvable);
    not_approvable(h.approver().approve(&id))?;

    common::confluence::mount_title_lookup(
        mock,
        SPACE,
        "Notes",
        &[
            page("1", "Notes", SPACE, &[]),
            page("2", "notes", SPACE, &[]),
        ],
    )
    .await;
    let id = queued(&h, params("Notes")).await?;
    let p = opened(&h, &id)?;
    let (param, value, matches, candidates) = unresolved_card(&p)?;
    assert_eq!((param, value, matches), ("parent", "Notes", 2));
    assert_eq!(candidates, ["Notes", "notes"]);
    not_approvable(h.approver().approve(&id))?;

    mount_content(
        mock,
        "404404",
        404,
        &json!({"statusCode": 404, "message": "No content found with id: 404404"}),
    )
    .await;
    let id = queued(&h, params("404404")).await?;
    let p = opened(&h, &id)?;
    assert!(
        matches!(p.body, PreviewBody::EnrichmentError { .. }),
        "{:?}",
        p.body
    );
    not_approvable(h.approver().approve_unopened(&id))?;
    assert!(puts(mock).await.is_empty(), "nothing was sent");
    Ok(())
}

/// §5.4 step 2: the deny hint names the parent and the page in the agent's own words (the space
/// is server data the agent never named); the candidate titles only when the approver ticks them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i35_move_parent_deny_hint_candidates_only_when_ticked() -> TestResult {
    for ticked in [false, true] {
        let h = Harness::confluence().await?;
        let mock = wiki(&h)?;
        move_server(mock).await;
        common::confluence::mount_title_lookup(
            mock,
            SPACE,
            "Notes",
            &[
                page("1", "Notes", SPACE, &[]),
                page("2", "notes", SPACE, &[]),
            ],
        )
        .await;
        let id = queued(&h, params("Notes")).await?;
        h.approver().open(&id).map_err(de)?;
        h.approver()
            .deny_with(
                &id,
                "which one?",
                DenyDetails::ResolutionFailed {
                    include_candidates: ticked,
                },
            )
            .map_err(de)?;
        let env = h.await_(&id, 5000).await;
        assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
        assert_eq!(code(&env), "resolution_failed");
        assert_eq!(exit(&env), 3);
        assert_eq!(detail(&env, "param"), json!("parent"));
        assert_eq!(detail(&env, "value"), json!("Notes"));
        assert_eq!(
            detail(&env, "message"),
            json!("no page 'Notes' in the space of page 65537")
        );
        if ticked {
            assert_eq!(detail(&env, "candidates"), json!(["Notes", "notes"]));
        } else {
            assert_eq!(detail(&env, "candidates"), Value::Null);
            assert!(!env.to_json_line().contains("notes"), "no server title");
        }
        assert!(
            !env.to_json_line().contains(SPACE),
            "the space key is the server's"
        );
        assert!(puts(mock).await.is_empty(), "nothing was sent");
    }
    Ok(())
}

/// PD-106: a move under a child of the page is held with the plan text: Approve disabled, a plain
/// deny only (no detail to attach), and the denial carries no server text.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_move_into_own_subtree_held() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    move_server(mock).await;
    let id = queued(&h, params(CHILD_ID)).await?;
    let p = opened(&h, &id)?;
    assert_eq!(enrichment_text(&p.body)?, CYCLE_TEXT);
    assert!(!p.approvable);
    assert!(p.deny_offers.is_empty(), "{:?}", p.deny_offers);
    not_approvable(h.approver().approve(&id))?;
    not_approvable(h.approver().approve_unopened(&id))?;
    assert!(
        records_of(&h, &id, EventType::WRITE_APPROVED)
            .await?
            .is_empty()
    );
    h.approver().deny(&id, "not there").map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
    assert_eq!(exit(&env), 3);
    let line = env.to_json_line();
    for server_text in ["Checklist details", "Home", PAGE_TITLE] {
        assert!(!line.contains(server_text), "{server_text}: {line}");
    }
    assert!(puts(mock).await.is_empty(), "nothing was sent");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_move_cross_space_refused() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    move_server(mock).await;
    mount_content(
        mock,
        "777",
        200,
        &page("777", "Runbook", "OPS", &[("700", "Ops home")]),
    )
    .await;
    let id = queued(&h, params("777")).await?;
    let p = opened(&h, &id)?;
    assert_eq!(unresolved_card(&p)?, ("parent", "777", 0, &[][..]));
    not_approvable(h.approver().approve(&id))?;
    h.approver()
        .deny_with(
            &id,
            "wrong space",
            DenyDetails::ResolutionFailed {
                include_candidates: false,
            },
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(code(&env), "resolution_failed");
    assert_eq!(
        detail(&env, "message"),
        json!("no page '777' in the space of page 65537")
    );
    assert!(puts(mock).await.is_empty(), "nothing was sent");
    Ok(())
}

/// §5.4 step 5: the stale check re-reads the page's version; a newer one returns the write as
/// `WRITE_STALE {changed}` with the delta leading the re-review, and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_move_stale_when_version_changed() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    move_server(mock).await;
    // Enrichment read v7; the stale check's `?expand=version` sees v8.
    mount_expand(mock, PAGE_ID, "version", &moved_page(8), Some(1)).await;
    let id = queued(&h, params(PARENT_ID)).await?;
    h.approver().open(&id).map_err(de)?;
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    h.approver().approve(&id).map_err(de)?;
    let item = item_after(&h, &id, rev).await?;
    assert!(item.stale, "{item:?}");
    assert_eq!(stale_reasons(&h, &id).await?, [json!("changed")]);
    assert!(puts(mock).await.is_empty(), "nothing was sent");
    let p = opened(&h, &id)?;
    let changed = p
        .warnings
        .iter()
        .find(|w| w.id == WarningId::ChangedSinceReview)
        .ok_or("no changed-since-review warning")?;
    assert!(
        changed
            .text
            .contains("page version changed since review (v7 → v8)"),
        "{}",
        changed.text
    );
    Ok(())
}

/// §6.3 Page move end to end: the opened card shows both paths, and the rendered document has the
/// fixed row "body not sent; title and body kept by Confluence" (PD-106, plan review m-14) and
/// the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_move_preview_old_and_new_paths() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    move_server(mock).await;
    common::confluence::mount_title_lookup(mock, SPACE, PARENT_TITLE, &[parent_answer()]).await;
    let id = queued(&h, params(PARENT_TITLE)).await?;
    let p = opened(&h, &id)?;
    match &p.body {
        PreviewBody::PageMove {
            page,
            from_path,
            to_path,
            requests,
        } => {
            assert_eq!(page, "Release checklist (page 65537, version 7 → 8)");
            assert_eq!(from_path, &["Home", PAGE_TITLE]);
            assert_eq!(to_path, &["Home", PARENT_TITLE, PAGE_TITLE]);
            assert_eq!(requests.len(), 1);
        }
        other => return Err(format!("not the page-move card: {other:?}").into()),
    }
    let doc = render::document(atlas_duck_preview::Lang::En, &p, Platform::current());
    assert!(doc.contains(BODY_NOT_SENT), "the fixed row");
    assert!(doc.contains("Old ancestor path") && doc.contains("New ancestor path"));
    Ok(())
}

/// Plan review I-6 c: `parent` is no target param, so an approver edit of it re-runs both stages;
/// a parent under the page is held, never sent unchecked; `id` is the target and read-only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parent_edit_reruns_resolution() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    move_server(mock).await;
    common::confluence::mount_title_lookup(mock, SPACE, PARENT_TITLE, &[parent_answer()]).await;
    mount_content(mock, HOME_ID, 200, &page(HOME_ID, "Home", SPACE, &[])).await;
    let id = queued(&h, params(HOME_ID)).await?;
    let p = opened(&h, &id)?;
    let before = purposes(&h, &id).await?.len();

    // `id` cannot be edited.
    let mut set = Map::new();
    set.insert("id".into(), json!("65538"));
    let res = h.approver().edit(
        &id,
        Edits {
            set,
            remove: Vec::new(),
        },
    );
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::TargetParamEdit))
        ),
        "{res:?}"
    );

    // Under a child of the page: both stages again, then the hold.
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    h.approver().edit(&id, set_parent(CHILD_ID)).map_err(de)?;
    let item = item_after(&h, &id, rev).await?;
    assert!(!item.approvable, "the edited parent is a child of the page");
    assert_eq!(
        purposes(&h, &id).await?.len(),
        before + 2,
        "the edit re-ran both stages"
    );
    assert_eq!(enrichment_text(&opened(&h, &id)?.body)?, CYCLE_TEXT);
    not_approvable(h.approver().approve(&id))?;
    assert!(puts(mock).await.is_empty(), "nothing was sent");

    // By title to a sibling: resolved again; the sent `ancestors` is the checked parent.
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    h.approver()
        .edit(&id, set_parent(PARENT_TITLE))
        .map_err(de)?;
    assert!(item_after(&h, &id, rev).await?.approvable);
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let sent = sent_puts(mock).await?;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["ancestors"], json!([{"id": PARENT_ID}]));
    assert!(p.approvable, "the first parent was fine");
    Ok(())
}

/// §5.4 step 5: the identity call precedes the stale rule; a token that now answers `type:
/// anonymous` stops the move before anything is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_move_identity_call_runs() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    move_server(mock).await;
    let id = queued(&h, params(PARENT_ID)).await?;
    h.approver().open(&id).map_err(de)?;
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    mock.server().reset().await;
    mock.confluence_user_current(UserKind::Anonymous, "", "")
        .await;
    h.approver().approve(&id).map_err(de)?;
    let after = item_after(&h, &id, rev).await?;
    assert!(!after.approvable);
    assert_eq!(stale_reasons(&h, &id).await?, [json!("identity_mismatch")]);
    assert!(puts(mock).await.is_empty(), "nothing was sent");
    Ok(())
}

/// §5.4 step 6 (PD-111, PUT only): a 409 on the move's `PUT` is Confluence's optimistic lock:
/// `WRITE_STALE {version_conflict}`, back to the queue refreshed. A move has no agent baseline
/// (no `base_version`), so the refresh is a new `Preview` at the new version, approvable again
/// after a fresh review; the next `PUT` carries that version + 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_move_409_returns_refreshed_at_the_new_version() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    move_reads(mock).await;
    // Enrichment and the first stale check see v7; everything after the conflict sees v8.
    mount_expand(mock, PAGE_ID, PAGE_EXPAND, &moved_page(7), Some(1)).await;
    mount_expand(mock, PAGE_ID, PAGE_EXPAND, &moved_page(8), None).await;
    mount_expand(mock, PAGE_ID, "version", &moved_page(7), Some(1)).await;
    mount_expand(mock, PAGE_ID, "version", &moved_page(8), None).await;
    mount_put(
        mock,
        409,
        fixtures::CONFLUENCE_VERSION_CONFLICT_409,
        Some(1),
    )
    .await;
    mount_put(mock, 200, fixtures::CONFLUENCE_PAGE_UPDATED, None).await;
    let id = queued(&h, params(PARENT_ID)).await?;
    h.approver().open(&id).map_err(de)?;
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    h.approver().approve(&id).map_err(de)?;
    let mut item = item_after(&h, &id, rev).await?;
    for _ in 0..400 {
        if item.approvable {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        item = h.approver().item(&id).ok_or("not queued")?;
    }
    assert!(item.approvable, "{item:?}");
    assert_eq!(stale_reasons(&h, &id).await?, [json!("version_conflict")]);
    // No Caution marks the return, so the cleared opened flag is what forces a fresh look: the
    // earlier approval is gone and the item is flagged stale until it is re-opened.
    assert!(item.stale, "{item:?}");
    let res = h.approver().approve_unopened(&id);
    assert!(
        matches!(res, Err(DecisionError::Invalid(InvalidReason::NotOpened))),
        "{res:?}"
    );
    let p = opened(&h, &id)?;
    match &p.body {
        PreviewBody::PageMove { page, .. } => {
            assert_eq!(page, "Release checklist (page 65537, version 8 → 9)");
        }
        other => return Err(format!("not the page-move card: {other:?}").into()),
    }
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let versions: Vec<Value> = sent_puts(mock)
        .await?
        .iter()
        .map(|b| b["version"]["number"].clone())
        .collect();
    assert_eq!(versions, [json!(8), json!(9)]);
    Ok(())
}

async fn records_of(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}
