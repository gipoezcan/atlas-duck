//! U-30 (core half): edits, immutable targets and baselines, `executed_params`, `edited_keys`.

use atlas_duck_core::edit::{EditError, EditResult, Edits, apply_edits};
use atlas_duck_core::validate::{EffectiveCaps, ValidateCtx};
use atlas_duck_registry::OperationSpec;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn op(id: &str) -> Result<&'static OperationSpec, String> {
    atlas_duck_registry::get(id).ok_or_else(|| format!("no op {id}"))
}

fn edits(set: Value, remove: &[&str]) -> Result<Edits, String> {
    Ok(Edits {
        set: set.as_object().cloned().ok_or("set must be an object")?,
        remove: remove.iter().map(|k| (*k).to_owned()).collect(),
    })
}

fn run(
    id: &str,
    agent: &Value,
    current: &Value,
    edits: &Edits,
    enrich_keys: &[&str],
) -> Result<Result<EditResult, EditError>, String> {
    let caps = EffectiveCaps::default();
    let ctx = ValidateCtx {
        instance_version: None,
        caps: &caps,
        for_script: false,
    };
    Ok(apply_edits(
        op(id)?,
        agent,
        current,
        edits,
        enrich_keys,
        &ctx,
    ))
}

fn ok(r: Result<EditResult, EditError>) -> Result<EditResult, String> {
    r.map_err(|e| format!("unexpected: {e}"))
}

fn err(r: Result<EditResult, EditError>) -> Result<EditError, String> {
    r.err().ok_or_else(|| "expected an edit error".to_owned())
}

fn has_null(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Array(a) => a.iter().any(has_null),
        Value::Object(o) => o.values().any(has_null),
        _ => false,
    }
}

#[test]
fn u30_executed_params_only_agent_keys() -> TestResult {
    let agent = json!({"key": "ABC-1", "fields": {"summary": "old"}});
    let e = edits(
        json!({"fields.customfield_1": "x", "fields.summary": "new summary"}),
        &[],
    )?;
    let r = ok(run("jira.issue.edit", &agent, &agent, &e, &[])?)?;
    assert_eq!(
        r.executed_params,
        json!({"key": "ABC-1", "fields": {"summary": "new summary"}})
    );
    assert_eq!(r.params["fields"]["customfield_1"], "x");
    Ok(())
}

#[test]
fn u30_removed_key_absent_not_null() -> TestResult {
    let agent = json!({"key": "ABC-1", "fields": {"summary": "s", "labels": ["a"]}});
    let e = edits(json!({}), &["fields.labels"])?;
    let r = ok(run("jira.issue.edit", &agent, &agent, &e, &[])?)?;
    assert_eq!(
        r.executed_params,
        json!({"key": "ABC-1", "fields": {"summary": "s"}})
    );
    assert!(!has_null(&r.executed_params));
    assert!(!has_null(&r.params));

    // A removed top-level key is absent too.
    let agent = json!({"key": "ABC-1", "fields": {"summary": "s"}, "update": {"labels": []}});
    let e = edits(json!({}), &["update"])?;
    let r = ok(run("jira.issue.edit", &agent, &agent, &e, &[])?)?;
    assert!(r.executed_params.get("update").is_none());
    Ok(())
}

#[test]
fn u30_edited_keys_names_only() -> TestResult {
    let agent = json!({"key": "ABC-1", "fields": {"summary": "old", "labels": ["a"]}});
    let e = edits(
        json!({"fields.summary": "secret new summary", "fields.customfield_1": "v"}),
        &["fields.labels"],
    )?;
    let r = ok(run("jira.issue.edit", &agent, &agent, &e, &[])?)?;
    assert_eq!(r.edited_keys.changed, ["fields.summary"]);
    assert_eq!(r.edited_keys.added, ["fields.customfield_1"]);
    assert_eq!(r.edited_keys.removed, ["fields.labels"]);
    let serialized = serde_json::to_string(&r.edited_keys)?;
    assert!(!serialized.contains("secret new summary"));
    assert!(!format!("{r:?}").contains("secret new summary"));
    assert!(!format!("{e:?}").contains("secret new summary"));
    Ok(())
}

#[test]
fn edited_keys_sorted_and_unchanged_value_is_not_an_edit() -> TestResult {
    let agent = json!({"key": "ABC-1", "fields": {"summary": "s"}});
    let e = edits(
        json!({"fields.summary": "s", "fields.customfield_2": 1, "fields.customfield_1": 2}),
        &[],
    )?;
    let r = ok(run("jira.issue.edit", &agent, &agent, &e, &[])?)?;
    assert_eq!(
        r.edited_keys.added,
        ["fields.customfield_1", "fields.customfield_2"]
    );
    assert!(r.edited_keys.changed.is_empty() && r.edited_keys.removed.is_empty());
    Ok(())
}

#[test]
fn target_param_edit_rejected() -> TestResult {
    let agent = json!({"key": "ABC-1", "fields": {"summary": "s"}});
    let e = edits(json!({"key": "OTHER-1", "fields.summary": "t"}), &[])?;
    assert_eq!(
        err(run("jira.issue.edit", &agent, &agent, &e, &[])?)?,
        EditError::TargetParamEdit
    );

    // Removing a target is the same refusal.
    let e = edits(json!({}), &["key"])?;
    assert_eq!(
        err(run("jira.issue.edit", &agent, &agent, &e, &[])?)?,
        EditError::TargetParamEdit
    );

    // Confluence: a target (`id`) too.
    let page = json!({"id": "1", "base_version": 5, "body": "b"});
    let e = edits(json!({"id": "2"}), &[])?;
    assert_eq!(
        err(run("confluence.page.update", &page, &page, &e, &[])?)?,
        EditError::TargetParamEdit
    );
    Ok(())
}

#[test]
fn baseline_edit_rejected() -> TestResult {
    let page = json!({"id": "1", "base_version": 5, "body": "b"});
    let e = edits(json!({"base_version": 6}), &[])?;
    assert_eq!(
        err(run("confluence.page.update", &page, &page, &e, &[])?)?,
        EditError::TargetParamEdit
    );

    let agent = json!({"key": "ABC-1", "fields": {"summary": "s"}, "expected": {"summary": "o"}});
    let e = edits(json!({"expected.summary": "changed"}), &[])?;
    assert_eq!(
        err(run("jira.issue.edit", &agent, &agent, &e, &[])?)?,
        EditError::TargetParamEdit
    );
    let e = edits(json!({"expected": {"summary": "o", "x": 1}}), &[])?;
    assert_eq!(
        err(run("jira.issue.edit", &agent, &agent, &e, &[])?)?,
        EditError::TargetParamEdit
    );
    let e = edits(json!({}), &["expected.summary"])?;
    assert_eq!(
        err(run("jira.issue.edit", &agent, &agent, &e, &[])?)?,
        EditError::TargetParamEdit
    );

    // Setting a baseline to its current value is not a change.
    let e = edits(json!({"expected.summary": "o", "fields.summary": "n"}), &[])?;
    let r = ok(run("jira.issue.edit", &agent, &agent, &e, &[])?)?;
    assert_eq!(r.executed_params["expected"], json!({"summary": "o"}));
    Ok(())
}

#[test]
fn edit_revalidates() -> TestResult {
    let agent = json!({"jql": "project = ABC"});
    let e = edits(json!({"max": "x"}), &[])?;
    let rejected = err(run("jira.search", &agent, &agent, &e, &[])?)?;
    assert!(matches!(rejected, EditError::Rejected(_)), "{rejected:?}");

    let agent = json!({"key": "ABC-1", "fields": {"summary": "s"}});
    let e = edits(json!({"fields.not a field": 1}), &[])?;
    assert!(matches!(
        err(run("jira.issue.edit", &agent, &agent, &e, &[])?)?,
        EditError::Rejected(_)
    ));
    Ok(())
}

#[test]
fn bad_keys_refused() -> TestResult {
    let agent = json!({"key": "ABC-1", "fields": {"summary": "s"}});
    for key in [
        "",
        "fields.",
        "fields.a.b",
        "labels.x",
        "key.sub",
        ".summary",
    ] {
        let e = edits(json!({ key: 1 }), &[])?;
        assert_eq!(
            err(run("jira.issue.edit", &agent, &agent, &e, &[])?)?,
            EditError::BadKey(key.to_owned()),
            "{key}"
        );
        let e = edits(json!({}), &[key])?;
        assert_eq!(
            err(run("jira.issue.edit", &agent, &agent, &e, &[])?)?,
            EditError::BadKey(key.to_owned()),
            "{key}"
        );
    }
    // A map sub-key on an op without a fields map.
    let page = json!({"id": "1", "base_version": 5, "body": "b"});
    let e = edits(json!({"fields.x": 1}), &[])?;
    assert!(matches!(
        err(run("confluence.page.update", &page, &page, &e, &[])?)?,
        EditError::BadKey(_)
    ));
    Ok(())
}

#[test]
fn set_then_remove_and_map_created_on_demand() -> TestResult {
    // `remove` wins over `set` of the same key.
    let agent = json!({"key": "ABC-1", "fields": {"summary": "s"}});
    let e = edits(
        json!({"fields.customfield_1": 1}),
        &["fields.customfield_1"],
    )?;
    let r = ok(run("jira.issue.edit", &agent, &agent, &e, &[])?)?;
    assert_eq!(r.executed_params, agent);
    assert!(r.edited_keys.added.is_empty());

    // The agent sent no `fields`: an added sub-key is never executed.
    let agent = json!({"key": "ABC-1", "update": {"labels": []}});
    let e = edits(json!({"fields.summary": "n"}), &[])?;
    let r = ok(run("jira.issue.edit", &agent, &agent, &e, &[])?)?;
    assert_eq!(r.executed_params, agent);
    assert_eq!(r.edited_keys.added, ["fields.summary"]);
    Ok(())
}

#[test]
fn name_edit_marks_rerun() -> TestResult {
    let agent = json!({"key": "ABC-1", "transition": "Done"});
    let e = edits(json!({"transition": "In Progress"}), &[])?;
    let r = ok(run(
        "jira.issue.transition",
        &agent,
        &agent,
        &e,
        &["transition"],
    )?)?;
    assert!(r.rerun_enrichment);
    assert_eq!(r.edited_keys.changed, ["transition"]);

    let r = ok(run("jira.issue.transition", &agent, &agent, &e, &[])?)?;
    assert!(!r.rerun_enrichment);

    // A map sub-key counts by its first segment.
    let agent = json!({"key": "ABC-1", "fields": {"summary": "s"}});
    let e = edits(json!({"fields.summary": "n"}), &[])?;
    let r = ok(run("jira.issue.edit", &agent, &agent, &e, &["fields"])?)?;
    assert!(r.rerun_enrichment);
    Ok(())
}
