#![cfg(feature = "testing")]
//! `confluence.page.create` (M7 Task 16, PD-105; §5.4 step 2, §6.3 Create, §7.4): the space
//! resolved by its key, the parent page by id or by title within that space (I-35: no match and
//! ambiguous hold the write, Approve disabled; a deny may attach the candidates when ticked), the
//! duplicate-title Caution (Approve stays enabled; Confluence refuses the create itself), the
//! `ContentWrite` card (resolved names, the outgoing storage rendered locally, its constructs) and
//! the pre-write identity call.
//!
//! Checked twice: as pure functions of the op table (plan, judge, executor, previewer as the
//! engine calls them) and end to end through the harness.

mod common;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, UserKind};
use atlas_duck_atlassian::{GetCall, HttpRequestSpec};
use atlas_duck_audit::EventType;
use atlas_duck_core::lifecycle::model::Hold;
use atlas_duck_core::ops::{
    EnrichCtx, EnrichPurpose, EnrichStep, EnrichVerdict, ExecCtx, ExecError, ExecPlan, PreviewCtx,
    PreviewInput, PreviewModel, WriteView, op_table,
};
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::Harness;
use atlas_duck_core::{DecisionError, DecisionOutcome, DenyDetails, Edits};
use atlas_duck_ipc::envelope::{ErrorCode, Status};
use atlas_duck_preview::{ConstructList, Preview, PreviewBody, WarningId};
use common::confluence::{content_path, mount_space, mount_title_lookup};
use common::{TestError, TestResult, code, de, detail, exit, request_id};
use serde_json::{Map, Value, json};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const CREATE: &str = "confluence.page.create";
const SPACE: &str = "DOC";
const TITLE: &str = "Release 1.5 notes";
const PARENT_ID: &str = "123400";
const PARENT_TITLE: &str = "Release notes";
const NEW_ID: &str = "123500";

// ---- pure helpers: the op table as the engine calls it ---------------------------------------

fn spec() -> Result<&'static atlas_duck_registry::OperationSpec, TestError> {
    atlas_duck_registry::get(CREATE).ok_or_else(|| "no confluence.page.create".into())
}

/// `GET /rest/api/space/DOC` as Confluence answers it.
fn space_answer(key: &str) -> Value {
    json!({
        "id": 98305,
        "key": key,
        "name": "Documentation",
        "type": "global",
        "_links": {"webui": format!("/display/{key}"), "self": format!("https://wiki.corp.example/rest/api/space/{key}")},
    })
}

/// A page `id` titled `title` in space `space`, under `Home`, as `GET /rest/api/content/{id}
/// ?expand=space,ancestors` (and each title-lookup result) answers it.
fn page(id: &str, title: &str, space: &str) -> Value {
    json!({
        "id": id,
        "type": "page",
        "status": "current",
        "title": title,
        "space": {"id": 98305, "key": space, "name": "Documentation", "type": "global"},
        "ancestors": [{"id": "65536", "type": "page", "status": "current", "title": "Home"}],
        "_links": {"webui": format!("/display/{space}/{id}")},
    })
}

/// A title lookup's answer (`GET /rest/api/content?spaceKey&title&type=page`) with `results`.
fn lookup(results: &[Value]) -> Value {
    json!({"results": results, "start": 0, "limit": 2, "size": results.len()})
}

fn params(body: &str, parent: Option<&str>) -> Value {
    let mut p = json!({ "space": SPACE, "title": TITLE, "body": body });
    if let Some(parent) = parent {
        p["parent"] = json!(parent);
    }
    p
}

type Rounds = Vec<Vec<(EnrichPurpose, GetCall)>>;

/// The rule's rounds over `answers` the way the engine's staged driver feeds them, then the judge.
fn staged(params: &Value, answers: &[Value]) -> Result<(Rounds, EnrichVerdict), TestError> {
    let rule = op_table()
        .get(CREATE)
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

/// The answers of a create under parent id `PARENT_ID` with no page titled `TITLE` yet.
fn by_id_answers() -> Vec<Value> {
    vec![
        space_answer(SPACE),
        page(PARENT_ID, PARENT_TITLE, SPACE),
        lookup(&[]),
    ]
}

/// The executor on `params` with `v` as the verdict.
fn exec(params: &Value, v: Option<&EnrichVerdict>) -> Result<ExecPlan, ExecError> {
    let base = atlas_duck_atlassian::normalize_base_url("https://wiki.example.invalid/wiki")
        .map_err(|_| ExecError::NotInThisBuild)?;
    let imp = op_table().get(CREATE).ok_or(ExecError::NotInThisBuild)?;
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
    let imp = op_table().get(CREATE).ok_or("no OpImpl")?;
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

#[test]
fn page_create_plan_stages() -> TestResult {
    // A parent id: the space (`resolve`), the parent by id (`resolve`), the duplicate-title check
    // (`enrich`), one GET per round.
    let p = params("Hello.", Some(PARENT_ID));
    let (rounds, v) = staged(&p, &by_id_answers())?;
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    let calls: Vec<&(EnrichPurpose, GetCall)> = rounds
        .iter()
        .map(|r| match r.as_slice() {
            [one] => Ok(one),
            _ => Err("not one GET per round"),
        })
        .collect::<Result<_, _>>()?;
    let [(p1, space), (p2, parent), (p3, dup)] = calls.as_slice() else {
        return Err(format!("{} rounds", calls.len()).into());
    };
    assert_eq!(
        (*p1, *p2, *p3),
        (
            EnrichPurpose::Resolve,
            EnrichPurpose::Resolve,
            EnrichPurpose::Enrich
        )
    );
    assert_eq!(space.endpoint_template, "/rest/api/space/{space}");
    assert_eq!(space.params, json!({"space": SPACE}));
    assert!(space.query.is_empty());
    assert_eq!(parent.endpoint_template, "/rest/api/content/{parent}");
    assert_eq!(parent.params, json!({"parent": PARENT_ID}));
    assert_eq!(query(parent), [("expand", "space,ancestors")]);
    assert_eq!(dup.endpoint_template, "/rest/api/content");
    assert_eq!(
        query(dup),
        [
            ("spaceKey", SPACE),
            ("title", TITLE),
            ("type", "page"),
            ("limit", "1")
        ]
    );

    // A parent title: the lookup by title in the resolved space, current pages, at most fifty.
    let p = params("Hello.", Some(PARENT_TITLE));
    let (rounds, v) = staged(
        &p,
        &[
            space_answer(SPACE),
            lookup(&[page(PARENT_ID, PARENT_TITLE, SPACE)]),
            lookup(&[]),
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
            ("spaceKey", SPACE),
            ("title", PARENT_TITLE),
            ("type", "page"),
            ("status", "current"),
            ("expand", "space,ancestors"),
            ("limit", "50")
        ]
    );
    assert_eq!(v.resolved.get("parent_id"), Some(&json!(PARENT_ID)));

    // No parent: the space, then the duplicate check.
    let p = params("Hello.", None);
    let (rounds, v) = staged(&p, &[space_answer(SPACE), lookup(&[])])?;
    assert_eq!(rounds.len(), 2);
    assert_eq!(v.hold, Hold::Preview);
    assert!(!v.resolved.contains_key("parent_id"));

    // An unresolved space ends the plan after stage 1; an unresolved parent after stage 2.
    let (rounds, v) = staged(&params("x", Some(PARENT_ID)), &[space_answer("OPS")])?;
    assert_eq!((rounds.len(), v.hold), (1, Hold::UnresolvedName));
    let (rounds, v) = staged(
        &params("x", Some(PARENT_TITLE)),
        &[space_answer(SPACE), lookup(&[])],
    )?;
    assert_eq!((rounds.len(), v.hold), (2, Hold::UnresolvedName));
    Ok(())
}

/// The space key the body sends is the server's, matched ASCII case-insensitively; any other key
/// in the answer is no match ("no space"), and an answer without a key fails closed.
#[test]
fn space_resolution_never_guesses() -> TestResult {
    let mut p = params("x", None);
    p["space"] = json!("doc");
    let v = staged(&p, &[space_answer("DOC"), lookup(&[])])?.1;
    assert_eq!(v.hold, Hold::Preview);
    assert_eq!(sent(&requests(&p, &v)?)?["space"], json!({"key": "DOC"}));

    for other in ["OPS", "DOCS", "DO"] {
        let v = staged(&params("x", None), &[space_answer(other)])?.1;
        assert_eq!(v.hold, Hold::UnresolvedName, "{other}");
        assert_eq!(unresolved_of(&v), Some(("space", SPACE, 0, Vec::new())));
    }
    for broken in [
        json!({"name": "Documentation"}),
        json!({"key": 7}),
        json!([]),
        Value::Null,
    ] {
        let v = staged(&params("x", None), std::slice::from_ref(&broken))?.1;
        assert_eq!(v.hold, Hold::EnrichmentError, "{broken}");
        assert!(requests(&params("x", None), &v).is_err());
    }
    Ok(())
}

/// I-35 (judge half): a parent that matches nothing or more than one page holds the write; a
/// page of another space, a non-page, a page that is not current or the wrong id is no match.
#[test]
fn parent_resolution_holds_what_it_cannot_pin() -> TestResult {
    let judge = |parent: &str, answer: Value| -> Result<EnrichVerdict, TestError> {
        Ok(staged(
            &params("x", Some(parent)),
            &[space_answer(SPACE), answer, lookup(&[])],
        )?
        .1)
    };
    // By title: none, or two (ambiguous: the candidates are the titles).
    let v = judge(PARENT_TITLE, lookup(&[]))?;
    assert_eq!(
        unresolved_of(&v),
        Some(("parent", PARENT_TITLE, 0, Vec::new()))
    );
    let two = lookup(&[
        page("1", PARENT_TITLE, SPACE),
        page("2", "release notes", SPACE),
    ]);
    let v = judge(PARENT_TITLE, two)?;
    assert_eq!(v.hold, Hold::UnresolvedName);
    assert_eq!(
        unresolved_of(&v),
        Some((
            "parent",
            PARENT_TITLE,
            2,
            vec![PARENT_TITLE, "release notes"]
        ))
    );
    // One result whose title is not the one asked for is no match; its title is the candidate.
    let v = judge(
        PARENT_TITLE,
        lookup(&[page("1", "Release notes (old)", SPACE)]),
    )?;
    assert_eq!(
        unresolved_of(&v),
        Some(("parent", PARENT_TITLE, 0, vec!["Release notes (old)"]))
    );
    // A result in another space, or not a page.
    let v = judge(PARENT_TITLE, lookup(&[page("1", PARENT_TITLE, "OPS")]))?;
    assert_eq!(v.hold, Hold::UnresolvedName);
    let mut blog = page("1", PARENT_TITLE, SPACE);
    blog["type"] = json!("blogpost");
    let v = judge(PARENT_TITLE, lookup(&[blog]))?;
    assert_eq!(
        unresolved_of(&v),
        Some(("parent", PARENT_TITLE, 0, Vec::new()))
    );

    // By id: another space, another type, not current: no match.
    let v = judge(PARENT_ID, page(PARENT_ID, PARENT_TITLE, "OPS"))?;
    assert_eq!(
        unresolved_of(&v),
        Some(("parent", PARENT_ID, 0, Vec::new()))
    );
    let mut blog = page(PARENT_ID, PARENT_TITLE, SPACE);
    blog["type"] = json!("blogpost");
    assert_eq!(judge(PARENT_ID, blog)?.hold, Hold::UnresolvedName);
    let mut trashed = page(PARENT_ID, PARENT_TITLE, SPACE);
    trashed["status"] = json!("trashed");
    assert_eq!(judge(PARENT_ID, trashed)?.hold, Hold::UnresolvedName);
    // T16 review m-8: a page without a `status` is not current, by id as by title.
    let mut no_status = page(PARENT_ID, PARENT_TITLE, SPACE);
    no_status
        .as_object_mut()
        .ok_or("not an object")?
        .remove("status");
    assert_eq!(
        unresolved_of(&judge(PARENT_ID, no_status.clone())?),
        Some(("parent", PARENT_ID, 0, Vec::new()))
    );
    assert_eq!(
        unresolved_of(&judge(PARENT_TITLE, lookup(&[no_status]))?),
        Some(("parent", PARENT_TITLE, 0, Vec::new()))
    );
    // The space matches case-insensitively, as the stage-1 key does.
    assert_eq!(
        judge(PARENT_ID, page(PARENT_ID, PARENT_TITLE, "doc"))?.hold,
        Hold::Preview
    );
    // The server may send the id as a number.
    let mut numeric = page(PARENT_ID, PARENT_TITLE, SPACE);
    numeric["id"] = json!(123_400);
    assert_eq!(judge(PARENT_ID, numeric)?.hold, Hold::Preview);

    // T16 review m-4: the match count is the real one and the candidates stop at ten.
    let twelve: Vec<Value> = (1..=12)
        .map(|i| page(&i.to_string(), PARENT_TITLE, SPACE))
        .collect();
    let v = judge(PARENT_TITLE, lookup(&twelve))?;
    let (_, _, n, candidates) = unresolved_of(&v).ok_or("not unresolved")?;
    assert_eq!((n, candidates.len()), (12, 10));
    // A full lookup page (the limit, 50) that pins no match is held: a current page titled
    // like the value may lie beyond it. One short of the limit resolves.
    let blogs = |n: usize| -> Vec<Value> {
        (0..n)
            .map(|i| {
                let mut b = page(&format!("{}", 500 + i), PARENT_TITLE, SPACE);
                b["type"] = json!("blogpost");
                b
            })
            .collect()
    };
    let mut full = blogs(49);
    full.push(page(PARENT_ID, PARENT_TITLE, SPACE));
    assert_eq!(
        judge(PARENT_TITLE, lookup(&full))?.hold,
        Hold::EnrichmentError
    );
    let mut short = blogs(48);
    short.push(page(PARENT_ID, PARENT_TITLE, SPACE));
    assert_eq!(judge(PARENT_TITLE, lookup(&short))?.hold, Hold::Preview);

    // Malformed answers fail closed (enrichment error): another id, no space, no title, no
    // results array, ancestors that are not an array of entries with page ids (T16 review m-5:
    // `page.move`'s cycle check reads them).
    let with_ancestors = |a: Value| -> Result<Value, TestError> {
        let mut p = page(PARENT_ID, PARENT_TITLE, SPACE);
        match a {
            Value::Null => {
                p.as_object_mut()
                    .ok_or("not an object")?
                    .remove("ancestors");
            }
            a => p["ancestors"] = a,
        }
        Ok(p)
    };
    let mut wrong_id = page(PARENT_ID, PARENT_TITLE, SPACE);
    wrong_id["id"] = json!("999");
    let mut no_space = page(PARENT_ID, PARENT_TITLE, SPACE);
    no_space
        .as_object_mut()
        .ok_or("not an object")?
        .remove("space");
    let mut no_title = page(PARENT_ID, PARENT_TITLE, SPACE);
    no_title
        .as_object_mut()
        .ok_or("not an object")?
        .remove("title");
    for (what, parent, answer) in [
        ("another id", PARENT_ID, wrong_id),
        ("no space", PARENT_ID, no_space.clone()),
        ("no title", PARENT_ID, no_title),
        ("no results", PARENT_TITLE, json!({"size": 0})),
        ("a result without space", PARENT_TITLE, lookup(&[no_space])),
        ("no ancestors", PARENT_ID, with_ancestors(Value::Null)?),
        (
            "ancestors not a list",
            PARENT_ID,
            with_ancestors(json!({}))?,
        ),
        (
            "an ancestor without id",
            PARENT_ID,
            with_ancestors(json!([{"id": "65536", "title": "Home"}, {"title": "Mid"}]))?,
        ),
        (
            "an ancestor id that is no page id",
            PARENT_ID,
            with_ancestors(json!([{"id": "x1", "title": "Home"}]))?,
        ),
        (
            "a title match with an ancestor without id",
            PARENT_TITLE,
            lookup(&[with_ancestors(json!([{"title": "Home"}]))?]),
        ),
    ] {
        let v = judge(parent, answer)?;
        assert_eq!(v.hold, Hold::EnrichmentError, "{what}");
        assert!(requests(&params("x", Some(parent)), &v).is_err(), "{what}");
    }
    Ok(())
}

/// PD-105 / lead ruling Q3: a page of that title in the space is a Caution; Approve stays
/// enabled (the request still renders).
#[test]
fn duplicate_title_is_a_caution() -> TestResult {
    let p = params("x", None);
    let v = staged(
        &p,
        &[space_answer(SPACE), lookup(&[page("9", TITLE, SPACE)])],
    )?
    .1;
    assert_eq!(v.hold, Hold::Preview);
    let w: Vec<_> = v.warnings.iter().map(|w| (w.id, w.text.as_str())).collect();
    assert_eq!(
        w,
        [(
            WarningId::DuplicateTitle,
            "a page titled 'Release 1.5 notes' already exists in DOC"
        )]
    );
    assert!(requests(&p, &v).is_ok());
    // No page of that title: no warning. An answer without `results` fails closed.
    let v = staged(&p, &[space_answer(SPACE), lookup(&[])])?.1;
    assert!(v.warnings.is_empty());
    let v = staged(&p, &[space_answer(SPACE), json!({})])?.1;
    assert_eq!(v.hold, Hold::EnrichmentError);
    // The title is display-escaped in the Caution.
    let mut p = params("x", None);
    p["title"] = json!("a\u{202e}b");
    let v = staged(
        &p,
        &[
            space_answer(SPACE),
            lookup(&[page("9", "a\u{202e}b", SPACE)]),
        ],
    )?
    .1;
    let text = &v.warnings.first().ok_or("no warning")?.text;
    assert!(
        !text.contains('\u{202e}') && text.contains("U+202E"),
        "{text}"
    );
    Ok(())
}

#[test]
fn page_create_body_is_the_spec_payload() -> TestResult {
    // Markdown: the converter's storage, the resolved space key and parent id.
    let p = params("**Release** 1.5 fixes the login.", Some(PARENT_TITLE));
    let v = staged(
        &p,
        &[
            space_answer(SPACE),
            lookup(&[page(PARENT_ID, PARENT_TITLE, SPACE)]),
            lookup(&[]),
        ],
    )?
    .1;
    let r = requests(&p, &v)?;
    assert_eq!(r[0].method, "POST");
    assert_eq!(
        r[0].resolved_url,
        "https://wiki.example.invalid/wiki/rest/api/content"
    );
    assert_eq!(r[0].content_type.as_deref(), Some("application/json"));
    assert_eq!(
        sent(&r)?,
        json!({
            "type": "page",
            "title": TITLE,
            "space": {"key": SPACE},
            "ancestors": [{"id": PARENT_ID}],
            "body": {"storage": {
                "value": "<p><strong>Release</strong> 1.5 fixes the login.</p>",
                "representation": "storage",
            }},
        })
    );
    // Storage verbatim, no parent: no `ancestors`.
    let mut p = params("<p>x</p>", None);
    p["body_format"] = json!("storage");
    let v = staged(&p, &[space_answer(SPACE), lookup(&[])])?.1;
    let body = sent(&requests(&p, &v)?)?;
    assert!(body.get("ancestors").is_none(), "{body}");
    assert_eq!(body["body"]["storage"]["value"], json!("<p>x</p>"));
    // Deterministic. A page may be created empty (T9 ruling 1).
    assert_eq!(requests(&p, &v)?, requests(&p, &v)?);
    let blank = params(" \n", None);
    let v = staged(&blank, &[space_answer(SPACE), lookup(&[])])?.1;
    assert_eq!(
        sent(&requests(&blank, &v)?)?["body"]["storage"]["value"],
        json!("")
    );
    Ok(())
}

#[test]
fn page_create_executor_needs_a_matching_verdict() -> TestResult {
    let p = params("Hello.", Some(PARENT_ID));
    assert_eq!(exec(&p, None), Err(ExecError::EnrichmentRequired));
    let v = staged(&p, &by_id_answers())?.1;
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
    // The verdict must be about these very params: another title (an edit not re-enriched yet),
    // another space, another parent, a parent the params no longer carry, or none resolved.
    let changed = |k: &str, val: Value| {
        let mut q = p.clone();
        q[k] = val;
        q
    };
    for (what, q) in [
        ("title", changed("title", json!("Other"))),
        ("space", changed("space", json!("OPS"))),
        ("parent", changed("parent", json!("123401"))),
        ("no parent", params("Hello.", None)),
    ] {
        assert_eq!(
            exec(&q, Some(&v)),
            Err(ExecError::EnrichmentRequired),
            "{what}"
        );
    }
    let no_parent = params("Hello.", None);
    let unparented = staged(&no_parent, &[space_answer(SPACE), lookup(&[])])?.1;
    assert_eq!(
        exec(&p, Some(&unparented)),
        Err(ExecError::EnrichmentRequired),
        "a parent the verdict never resolved"
    );
    for key in ["space_key", "parent_id"] {
        let mut broken = v.clone();
        broken.resolved.remove(key);
        assert_eq!(
            exec(&p, Some(&broken)),
            Err(ExecError::EnrichmentRequired),
            "{key}"
        );
    }
    let mut foreign = v.clone();
    foreign.resolved.insert("space_key".into(), json!("OPS"));
    assert_eq!(exec(&p, Some(&foreign)), Err(ExecError::EnrichmentRequired));
    Ok(())
}

/// The Task 9 rule applied here (plan review I-5): the body checks answer before any verdict is
/// asked for, so the validation dry call refuses them before enrichment.
#[test]
fn page_create_body_checked_before_enrichment_required() -> TestResult {
    let invalid = |body: &str, format: Option<&str>| -> Option<ErrorCode> {
        let mut p = params(body, None);
        if let Some(f) = format {
            p["body_format"] = json!(f);
        }
        match exec(&p, None) {
            Err(ExecError::Invalid(e)) => Some(e.code),
            _ => None,
        }
    };
    assert_eq!(
        invalid("see [macro: toc {}]", None),
        Some(ErrorCode::MarkdownPlaceholders)
    );
    assert_eq!(
        invalid("<!DOCTYPE x><p>a</p>", Some("storage")),
        Some(ErrorCode::Validation)
    );
    assert_eq!(invalid("fine", None), None);
    assert_eq!(invalid(" ", None), None, "a page may be empty");
    Ok(())
}

struct Card<'a> {
    sentence: &'a str,
    rows: &'a [(String, String)],
    html: Option<&'a str>,
    constructs: &'a ConstructList,
}

fn card(m: &PreviewModel) -> Result<Card<'_>, TestError> {
    match &m.body {
        PreviewBody::ContentWrite {
            sentence,
            rows,
            body_html,
            constructs: Some(constructs),
            requests,
        } => {
            assert_eq!(requests.len(), 1, "the request list stays part of the body");
            Ok(Card {
                sentence,
                rows,
                html: body_html.as_deref(),
                constructs,
            })
        }
        other => Err(format!("not a content-write card: {other:?}").into()),
    }
}

fn row<'a>(c: &'a Card<'_>, name: &str) -> Option<&'a str> {
    c.rows
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[test]
fn page_create_card_resolved_names() -> TestResult {
    let p = params("**bold** and `code`", Some(PARENT_ID));
    let v = staged(&p, &by_id_answers())?.1;
    let reqs = requests(&p, &v)?;
    let m = preview_of(&p, &v, &reqs)?;
    let c = card(&m)?;
    assert_eq!(
        c.sentence,
        "Create page 'Release 1.5 notes' in Documentation (DOC) under 'Release notes'"
    );
    assert_eq!(row(&c, "Space"), Some("Documentation (DOC)"));
    assert_eq!(row(&c, "Parent"), Some("Release notes (page 123400)"));
    assert_eq!(row(&c, "Path"), Some("Home / Release notes"));
    // A Markdown body converts with no construct of its own.
    assert_eq!(*c.constructs, ConstructList::default());
    assert!(
        c.html
            .is_some_and(|h| h.contains("<strong>bold</strong>") && h.contains("code")),
        "{:?}",
        c.html
    );
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);

    // No parent: no "under", no parent rows.
    let p = params("x", None);
    let v = staged(&p, &[space_answer(SPACE), lookup(&[])])?.1;
    let reqs = requests(&p, &v)?;
    let m = preview_of(&p, &v, &reqs)?;
    let c = card(&m)?;
    assert_eq!(
        c.sentence,
        "Create page 'Release 1.5 notes' in Documentation (DOC)"
    );
    assert_eq!((row(&c, "Parent"), row(&c, "Path")), (None, None));

    // The duplicate Caution reaches the card; the card stays approvable (its requests remain).
    let v = staged(
        &p,
        &[space_answer(SPACE), lookup(&[page("9", TITLE, SPACE)])],
    )?
    .1;
    let m = preview_of(&p, &v, &requests(&p, &v)?)?;
    assert!(
        m.warnings.iter().any(|w| w.id == WarningId::DuplicateTitle),
        "{:?}",
        m.warnings
    );
    card(&m)?;

    // A storage body lists its constructs.
    let mut p = params(
        "<ac:structured-macro ac:name=\"toc\"/><p><ac:link><ri:user ri:userkey=\"8a7f\"/></ac:link></p>",
        None,
    );
    p["body_format"] = json!("storage");
    let v = staged(&p, &[space_answer(SPACE), lookup(&[])])?.1;
    let m = preview_of(&p, &v, &requests(&p, &v)?)?;
    let c = card(&m)?;
    assert_eq!(c.constructs.macros, ["toc"]);
    assert_eq!(c.constructs.mentions, ["8a7f"]);
    Ok(())
}

/// §5.1 inv. 4 / T7 review m-1: the card reads the title and the body from the request that is
/// sent, never from the params.
#[test]
fn page_create_card_reads_the_sent_request() -> TestResult {
    let p = params("from the params", None);
    let v = staged(&p, &[space_answer(SPACE), lookup(&[])])?.1;
    let mut reqs = requests(&p, &v)?;
    let mut body = sent(&reqs)?;
    body["title"] = json!("Sent title");
    body["body"]["storage"]["value"] = json!("<p>sent body</p>");
    if let Some(r) = reqs.first_mut() {
        r.body = serde_json::to_vec(&body)?;
    }
    let m = preview_of(&p, &v, &reqs)?;
    let c = card(&m)?;
    assert!(c.sentence.contains("'Sent title'"), "{}", c.sentence);
    assert!(
        c.html
            .is_some_and(|h| h.contains("sent body") && !h.contains("from the params")),
        "{:?}",
        c.html
    );

    // T16 review m-1: a request whose parent, space key or type is not what enrichment resolved
    // never gets the named card (it would put the resolved names over other bytes).
    let generic = |p: &Value, v: &EnrichVerdict, edit: &dyn Fn(&mut Value)| -> TestResult {
        let mut reqs = requests(p, v)?;
        let mut body = sent(&reqs)?;
        edit(&mut body);
        if let Some(r) = reqs.first_mut() {
            r.body = serde_json::to_vec(&body)?;
        }
        let m = preview_of(p, v, &reqs)?;
        assert!(
            !matches!(m.body, PreviewBody::ContentWrite { .. }),
            "{body}: {:?}",
            m.body
        );
        Ok(())
    };
    let with_parent = params("x", Some(PARENT_ID));
    let resolved_parent = staged(&with_parent, &by_id_answers())?.1;
    card(&preview_of(
        &with_parent,
        &resolved_parent,
        &requests(&with_parent, &resolved_parent)?,
    )?)?;
    generic(&with_parent, &resolved_parent, &|b| {
        b["ancestors"] = json!([{"id": "999"}]);
    })?;
    generic(&p, &v, &|b| b["ancestors"] = json!([{"id": PARENT_ID}]))?;
    generic(&p, &v, &|b| b["space"]["key"] = json!("OPS"))?;
    generic(&p, &v, &|b| b["space"]["key"] = json!("doc"))?;
    generic(&p, &v, &|b| b["type"] = json!("blogpost"))?;
    Ok(())
}

/// T12b rules: what the render leaves out of storage the agent sends is counted and said; the
/// server text the card shows beyond the request (space name, parent title) counts into the
/// §6.4 header.
#[test]
fn page_create_card_counts_what_it_hides() -> TestResult {
    let mut p = params(
        "<p title=\"secret hint\">visible</p><!-- a note for the server -->",
        None,
    );
    p["body_format"] = json!("storage");
    let v = staged(&p, &[space_answer(SPACE), lookup(&[])])?.1;
    let m = preview_of(&p, &v, &requests(&p, &v)?)?;
    let html = card(&m)?.html.ok_or("no body")?;
    assert!(html.contains("visible"), "{html}");
    assert!(
        !html.contains("secret hint") && !html.contains("a note for the server"),
        "{html}"
    );
    assert!(
        m.warnings
            .iter()
            .any(|w| w.id == WarningId::SourceFormattingRemoved),
        "{:?}",
        m.warnings
    );
    let dropped = "title=\"secret hint\"".len() + "<!-- a note for the server -->".len();
    assert_eq!(m.header.hidden_in_preview_bytes, u64::try_from(dropped)?);

    // A bidi control in the parent's title (server text) is counted and shown escaped.
    let p = params("x", Some(PARENT_ID));
    let v = staged(
        &p,
        &[
            space_answer(SPACE),
            page(PARENT_ID, "Notes\u{202e}txt", SPACE),
            lookup(&[]),
        ],
    )?
    .1;
    let m = preview_of(&p, &v, &requests(&p, &v)?)?;
    assert!(m.header.bidi_controls >= 1, "{:?}", m.header.bidi_controls);
    let c = card(&m)?;
    assert!(!c.sentence.contains('\u{202e}'), "{}", c.sentence);
    Ok(())
}

/// T16 review m-2: only a Preview verdict gives the named card, even with the very requests a
/// Preview would show (a stale or identity-mismatch view keeps the generic body).
#[test]
fn page_create_card_keeps_the_generic_body_without_a_verdict() -> TestResult {
    let p = params("x", None);
    let v = staged(&p, &[space_answer(SPACE), lookup(&[])])?.1;
    let reqs = requests(&p, &v)?;
    card(&preview_of(&p, &v, &reqs)?)?;
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
            !matches!(m.body, PreviewBody::ContentWrite { .. }),
            "{hold:?}: {:?}",
            m.body
        );
    }
    let m = preview_of(&p, &v, &[])?;
    assert!(
        !matches!(m.body, PreviewBody::ContentWrite { .. }),
        "{:?}",
        m.body
    );
    Ok(())
}

/// T16 review m-7 (as T18 M-4): a storage body with a macro the converter does not know raises
/// the `unknown_macros` Info on the create card.
#[test]
fn page_create_card_says_unknown_macros() -> TestResult {
    let mut p = params("<p>a</p><ac:structured-macro ac:name=\"made-up\"/>", None);
    p["body_format"] = json!("storage");
    let v = staged(&p, &[space_answer(SPACE), lookup(&[])])?.1;
    let m = preview_of(&p, &v, &requests(&p, &v)?)?;
    assert_eq!(card(&m)?.constructs.macros, ["made-up"]);
    assert!(
        m.warnings.iter().any(|w| w.id == WarningId::UnknownMacros),
        "{:?}",
        m.warnings
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

/// What `POST /rest/api/content` answers for the new page.
fn created() -> Value {
    json!({
        "id": NEW_ID, "type": "page", "status": "current", "title": TITLE,
        "space": {"key": SPACE}, "version": {"number": 1, "when": "2026-10-17T10:00:00.000+02:00"},
        "ancestors": [{"id": PARENT_ID}],
        "_links": {"webui": "/display/DOC/Release+1.5+notes", "self": "https://wiki.corp.example/rest/api/content/123500"},
    })
}

/// The server side of a create in `DOC`: the identity call, the space, the parent by id and by
/// title, no page titled `TITLE` yet, and the answer of the POST.
async fn create_server(mock: &MockDc) {
    create_reads(mock).await;
    mount_post(mock, 200, &created()).await;
}

/// Everything `create_server` mounts but the POST.
async fn create_reads(mock: &MockDc) {
    mock.confluence_user_current(UserKind::Known, TEST_USER, TEST_USER_KEY)
        .await;
    mount_space(mock, SPACE, &space_answer(SPACE)).await;
    mount_content(mock, PARENT_ID, 200, &page(PARENT_ID, PARENT_TITLE, SPACE)).await;
    mount_title_lookup(
        mock,
        SPACE,
        PARENT_TITLE,
        &[page(PARENT_ID, PARENT_TITLE, SPACE)],
    )
    .await;
    mount_title_lookup(mock, SPACE, TITLE, &[]).await;
}

async fn mount_post(mock: &MockDc, status: u16, body: &Value) {
    Mock::given(method("POST"))
        .and(path(mock.path("/rest/api/content")))
        .respond_with(json_answer(mock, status, body))
        .mount(mock.server())
        .await;
}

async fn queued(h: &Harness, params: Value) -> Result<String, TestError> {
    let env = h.submit(CREATE, params).await;
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

async fn posts(mock: &MockDc) -> Vec<wiremock::Request> {
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
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

async fn sent_post(mock: &MockDc) -> Result<Value, TestError> {
    let all = posts(mock).await;
    let [one] = all.as_slice() else {
        return Err(format!("{} POSTs", all.len()).into());
    };
    Ok(serde_json::from_slice(&one.body)?)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_create_markdown_converted_and_sent() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    create_server(mock).await;
    let id = queued(
        &h,
        params("Release **1.5** fixes the login.", Some(PARENT_ID)),
    )
    .await?;
    assert!(opened(&h, &id)?.approvable);
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(
        sent_post(mock).await?,
        json!({
            "type": "page",
            "title": TITLE,
            "space": {"key": SPACE},
            "ancestors": [{"id": PARENT_ID}],
            "body": {"storage": {
                "value": "<p>Release <strong>1.5</strong> fixes the login.</p>",
                "representation": "storage",
            }},
        })
    );
    assert_eq!(
        env.data,
        Some(json!({"receipt": {
            "id": NEW_ID, "type": "page", "status": "current",
            "version": {"number": 1},
            "_links": {"webui": "/display/DOC/Release+1.5+notes"},
        }}))
    );
    // Stages: the space and the parent (`resolve`), the duplicate check (`enrich`), then after
    // the approval the pre-write identity call (recorded as the stale-check step, T18 decision 4).
    assert_eq!(
        purposes(&h, &id).await?,
        [
            json!("resolve"),
            json!("resolve"),
            json!("enrich"),
            json!("stale_check")
        ]
    );
    Ok(())
}

/// Plan review I-5: a placeholder in a Markdown body is refused at validation, before any GET
/// (not even the space).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_create_markdown_rejected_before_enrichment() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    create_server(mock).await;
    let before = mock.received().await.len();
    let env = h
        .submit(
            CREATE,
            params("See [macro: toc {}] and @user:8a7f808a1.", Some(PARENT_ID)),
        )
        .await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "markdown_placeholders");
    assert_eq!(exit(&env), 2);
    assert_eq!(mock.received().await.len(), before, "no wiremock hit");
    Ok(())
}

/// I-35 (parent page): no match and ambiguous disable Approve, individually; a parent id the
/// server does not know (JSON 404) is an enrichment error (the engine classifies a non-2xx
/// answer before any judge sees it, as for `comment.add`'s `reply_to`): Approve disabled too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i35_parent_page_no_match_and_ambiguous() -> TestResult {
    // By title, nothing.
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    create_server(mock).await;
    mount_title_lookup(mock, SPACE, "Nowhere", &[]).await;
    let id = queued(&h, params("x", Some("Nowhere"))).await?;
    let p = opened(&h, &id)?;
    assert_eq!(unresolved_card(&p)?, ("parent", "Nowhere", 0, &[][..]));
    assert!(!p.approvable);
    not_approvable(h.approver().approve(&id))?;

    // By title, two pages: ambiguous, the candidates are their titles.
    mount_title_lookup(
        mock,
        SPACE,
        "Notes",
        &[page("1", "Notes", SPACE), page("2", "notes", SPACE)],
    )
    .await;
    let id = queued(&h, params("x", Some("Notes"))).await?;
    let p = opened(&h, &id)?;
    let (param, value, matches, candidates) = unresolved_card(&p)?;
    assert_eq!((param, value, matches), ("parent", "Notes", 2));
    assert_eq!(candidates, ["Notes", "notes"]);
    assert!(!p.approvable);
    not_approvable(h.approver().approve(&id))?;

    // By id, unknown to the server.
    mount_content(
        mock,
        "404404",
        404,
        &json!({"statusCode": 404, "message": "No content found with id: 404404"}),
    )
    .await;
    let id = queued(&h, params("x", Some("404404"))).await?;
    let p = opened(&h, &id)?;
    assert!(
        matches!(p.body, PreviewBody::EnrichmentError { .. }),
        "{:?}",
        p.body
    );
    assert!(!p.approvable);
    not_approvable(h.approver().approve_unopened(&id))?;
    assert!(posts(mock).await.is_empty(), "nothing was sent");
    Ok(())
}

/// §5.4 step 2: a deny with the hint is `resolution_failed`, exit 3, the message app text; the
/// candidates (server titles) only when the approver ticks them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i35_parent_page_deny_hint_candidates_only_when_ticked() -> TestResult {
    for ticked in [false, true] {
        let h = Harness::confluence().await?;
        let mock = wiki(&h)?;
        create_server(mock).await;
        mount_title_lookup(
            mock,
            SPACE,
            "Notes",
            &[page("1", "Notes", SPACE), page("2", "notes", SPACE)],
        )
        .await;
        let id = queued(&h, params("x", Some("Notes"))).await?;
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
            json!("no page 'Notes' in space DOC")
        );
        if ticked {
            assert_eq!(detail(&env, "candidates"), json!(["Notes", "notes"]));
        } else {
            assert_eq!(detail(&env, "candidates"), Value::Null, "{ticked}");
        }
        assert!(posts(mock).await.is_empty(), "nothing was sent");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parent_in_other_space_unresolved() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    create_server(mock).await;
    mount_content(mock, "777", 200, &page("777", "Runbook", "OPS")).await;
    let id = queued(&h, params("x", Some("777"))).await?;
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
    assert_eq!(detail(&env, "message"), json!("no page '777' in space DOC"));
    assert!(posts(mock).await.is_empty(), "nothing was sent");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parent_by_title_resolves_to_id() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    create_server(mock).await;
    let id = queued(&h, params("Hello.", Some(PARENT_TITLE))).await?;
    let p = opened(&h, &id)?;
    assert!(p.approvable, "{:?}", p.body);
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let sent = sent_post(mock).await?;
    assert_eq!(sent["ancestors"], json!([{"id": PARENT_ID}]));
    // The lookup asked within the space, for current pages only, at most fifty.
    let lookups: Vec<String> = mock
        .received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "GET" && r.url.path() == mock.path("/rest/api/content"))
        .filter_map(|r| r.url.query().map(str::to_owned))
        .collect();
    assert!(
        lookups.iter().any(|q| q.contains("title=Release+notes")
            && q.contains("spaceKey=DOC")
            && q.contains("type=page")
            && q.contains("status=current")
            && q.contains("limit=50")),
        "{lookups:?}"
    );
    Ok(())
}

/// The one value enrichment rewrites reaches the wire: a space given as `doc` that the server
/// names `DOC` is looked up and sent as `DOC` (the card shows the same key).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resolved_space_key_is_what_is_sent() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    create_server(mock).await;
    mount_space(mock, "doc", &space_answer(SPACE)).await;
    let mut p = params("Hello.", Some(PARENT_TITLE));
    p["space"] = json!("doc");
    let id = queued(&h, p).await?;
    let preview = opened(&h, &id)?;
    match &preview.body {
        PreviewBody::ContentWrite { sentence, .. } => {
            assert!(sentence.contains("(DOC)"), "{sentence}");
        }
        other => return Err(format!("not a content-write card: {other:?}").into()),
    }
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(sent_post(mock).await?["space"], json!({"key": SPACE}));
    let lookups: Vec<String> = mock
        .received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "GET" && r.url.path() == mock.path("/rest/api/content"))
        .filter_map(|r| r.url.query().map(str::to_owned))
        .collect();
    assert_eq!(lookups.len(), 2, "the parent and the duplicate lookup");
    assert!(
        lookups.iter().all(|q| q.contains("spaceKey=DOC&")),
        "{lookups:?}"
    );
    Ok(())
}

/// A space the server does not know (JSON 404) holds the write as an enrichment error; an
/// answer for another key is no match (`UnresolvedName {param: space}`, "no space '<v>'").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_unresolved() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    create_server(mock).await;
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/space/NOPE")))
        .respond_with(json_answer(
            mock,
            404,
            &json!({"statusCode": 404, "message": "No space with key : NOPE"}),
        ))
        .mount(mock.server())
        .await;
    let mut p = params("x", None);
    p["space"] = json!("NOPE");
    let id = queued(&h, p).await?;
    let preview = opened(&h, &id)?;
    assert!(
        matches!(preview.body, PreviewBody::EnrichmentError { .. }),
        "{:?}",
        preview.body
    );
    not_approvable(h.approver().approve(&id))?;
    // Only the space GET left: no parent or duplicate lookup without a resolved space.
    assert_eq!(purposes(&h, &id).await?, [json!("resolve")]);

    mount_space(mock, "ALIAS", &space_answer("OTHER")).await;
    let mut p = params("x", None);
    p["space"] = json!("ALIAS");
    let id = queued(&h, p).await?;
    let preview = opened(&h, &id)?;
    assert_eq!(unresolved_card(&preview)?, ("space", "ALIAS", 0, &[][..]));
    not_approvable(h.approver().approve(&id))?;
    h.approver()
        .deny_with(
            &id,
            "no such space",
            DenyDetails::ResolutionFailed {
                include_candidates: false,
            },
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(code(&env), "resolution_failed");
    assert_eq!(detail(&env, "message"), json!("no space 'ALIAS'"));
    assert!(posts(mock).await.is_empty(), "nothing was sent");
    Ok(())
}

/// PD-105, lead ruling Q3: a duplicate title is a Caution with Approve enabled; Confluence then
/// refuses the create itself (its 400 is `WRITE_FAILED`, nothing written).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_title_caution_approve_enabled() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    mock.confluence_user_current(UserKind::Known, TEST_USER, TEST_USER_KEY)
        .await;
    mount_space(mock, SPACE, &space_answer(SPACE)).await;
    mount_title_lookup(mock, SPACE, TITLE, &[page("9", TITLE, SPACE)]).await;
    let refusal = json!({
        "statusCode": 400,
        "data": {"authorized": false, "valid": true, "errors": [], "successful": false},
        "message": "A page with this title already exists: A page already exists with the title Release 1.5 notes in the space with key DOC",
    });
    mount_post(mock, 400, &refusal).await;
    let id = queued(&h, params("x", None)).await?;
    let p = opened(&h, &id)?;
    assert!(p.approvable, "{:?}", p.body);
    let w = p
        .warnings
        .iter()
        .find(|w| w.id == WarningId::DuplicateTitle)
        .ok_or("no duplicate_title warning")?;
    assert_eq!(
        w.text,
        "a page titled 'Release 1.5 notes' already exists in DOC"
    );
    let row = h.approver().item(&id).ok_or("not queued")?;
    assert!(row.approvable && row.caution_count >= 1);
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "upstream_http");
    let types = h.event_types(&id).await?;
    assert!(types.contains(&EventType::WRITE_FAILED), "{types:?}");
    assert!(!types.contains(&EventType::WRITE_STALE), "{types:?}");
    assert_eq!(posts(mock).await.len(), 1, "one POST, no retry");
    Ok(())
}

/// Lead ruling (T16): should DC refuse a duplicate title with a 409 (the race after the check),
/// the POST is no optimistic-lock conflict: `WRITE_FAILED` with the server's message, never
/// `WRITE_STALE` back to the queue (V06/T25 confirm which status real DC sends).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_post_409_is_write_failed_not_conflict() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    create_reads(mock).await;
    let message = "A page with this title already exists: A page already exists with the title Release 1.5 notes in the space with key DOC";
    let refusal = json!({
        "statusCode": 409,
        "data": {"authorized": false, "valid": true, "errors": [], "successful": false},
        "message": message,
    });
    mount_post(mock, 409, &refusal).await;
    let id = queued(&h, params("x", None)).await?;
    let p = opened(&h, &id)?;
    assert!(p.approvable, "{:?}", p.body);
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "upstream_http");
    assert_eq!(detail(&env, "status"), json!(409));
    assert_eq!(detail(&env, "error_messages"), json!(message));
    let types = h.event_types(&id).await?;
    assert!(types.contains(&EventType::WRITE_FAILED), "{types:?}");
    assert!(!types.contains(&EventType::WRITE_STALE), "{types:?}");
    assert_eq!(posts(mock).await.len(), 1, "one POST, no retry");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_create_card_shows_resolved_names() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    create_server(mock).await;
    let id = queued(&h, params("**bold**", Some(PARENT_TITLE))).await?;
    let p = opened(&h, &id)?;
    match &p.body {
        PreviewBody::ContentWrite {
            sentence,
            rows,
            body_html,
            constructs,
            requests,
        } => {
            assert_eq!(
                sentence,
                "Create page 'Release 1.5 notes' in Documentation (DOC) under 'Release notes'"
            );
            assert!(
                rows.iter()
                    .any(|(k, v)| k == "Parent" && v == "Release notes (page 123400)"),
                "{rows:?}"
            );
            assert!(
                body_html
                    .as_deref()
                    .is_some_and(|h| h.contains("<strong>bold</strong>")),
                "{body_html:?}"
            );
            assert_eq!(constructs.as_ref(), Some(&ConstructList::default()));
            assert_eq!(requests.len(), 1);
        }
        other => return Err(format!("not a content-write card: {other:?}").into()),
    }
    assert!(p.approvable);
    Ok(())
}

/// PD-105: `title` is an enrich key, so an approver edit of it re-runs the enrichment (the
/// duplicate check sees the new title); the space and parent are target params, read-only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn title_edit_reruns_enrichment() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    create_server(mock).await;
    mount_title_lookup(mock, SPACE, "Taken", &[page("9", "Taken", SPACE)]).await;
    let id = queued(&h, params("x", Some(PARENT_ID))).await?;
    let p = opened(&h, &id)?;
    assert!(p.approvable);
    assert!(p.warnings.iter().all(|w| w.id != WarningId::DuplicateTitle));
    let rev = h.approver().rev(&id).map_err(de)?;
    let before = purposes(&h, &id).await?.len();
    let mut set = Map::new();
    set.insert("title".into(), json!("Taken"));
    h.approver()
        .edit(
            &id,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
        .map_err(de)?;
    let mut item = None;
    for _ in 0..400 {
        if let Some(i) = h.approver().item(&id)
            && i.candidate_rev.counter > rev.counter
        {
            item = Some(i);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let item = item.ok_or("the revision never advanced")?;
    assert!(item.approvable, "a duplicate title stays approvable");
    assert_eq!(
        purposes(&h, &id).await?.len(),
        before + 3,
        "the edit re-ran all three stages"
    );
    let p = opened(&h, &id)?;
    assert!(
        p.warnings.iter().any(|w| w.id == WarningId::DuplicateTitle),
        "{:?}",
        p.warnings
    );
    // The space and the parent cannot be edited (target params, §5.4 step 4).
    for (k, v) in [("space", json!("OPS")), ("parent", json!("777"))] {
        let mut set = Map::new();
        set.insert(k.into(), v);
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
            "{k}: {res:?}"
        );
    }
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(sent_post(mock).await?["title"], json!("Taken"));
    Ok(())
}

/// §5.4 step 5: no stale rule for a create, but the identity call still runs: a token that now
/// answers `type: anonymous` stops the write before it is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn page_create_identity_call_runs() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    create_server(mock).await;
    let id = queued(&h, params("x", None)).await?;
    h.approver().open(&id).map_err(de)?;
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    assert!(
        op_table()
            .get(CREATE)
            .is_some_and(|i| i.stale_check.is_none() && i.enrich_keys == ["title", "body"]),
        "no stale rule; title and body re-enrich"
    );
    mock.server().reset().await;
    mock.confluence_user_current(UserKind::Anonymous, "", "")
        .await;
    h.approver().approve(&id).map_err(de)?;
    let mut stale = Vec::new();
    for _ in 0..400 {
        stale = h
            .events(&id)
            .await?
            .into_iter()
            .filter(|(t, _)| *t == EventType::WRITE_STALE)
            .map(|(_, p)| p["reason"].clone())
            .collect();
        if !stale.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(stale, [json!("identity_mismatch")]);
    let after = h.approver().item(&id).ok_or("gone")?;
    assert!(after.candidate_rev.counter > rev && !after.approvable);
    assert!(posts(mock).await.is_empty(), "nothing was sent");
    Ok(())
}
