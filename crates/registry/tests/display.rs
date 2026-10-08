mod common;

use atlas_duck_registry::*;
use common::with_display;
use serde_json::json;

#[test]
fn param_renders_strings_and_numbers_without_quotes() {
    let spec = with_display(TargetDisplay::Param("key"));
    assert_eq!(target_display(&spec, &json!({"key": "ABC-123"})), "ABC-123");
    assert_eq!(target_display(&spec, &json!({"key": 42})), "42");
}

#[test]
fn missing_param_renders_question_mark() {
    let spec = with_display(TargetDisplay::Param("key"));
    assert_eq!(target_display(&spec, &json!({})), "?");
}

#[test]
fn query_cuts_at_80_scalars_with_ellipsis() {
    let spec = with_display(TargetDisplay::Query { param: "jql" });
    let long = "a".repeat(200);
    let shown = target_display(&spec, &json!({ "jql": long }));
    assert_eq!(shown, format!("{}…", "a".repeat(80)));
}

#[test]
fn query_under_the_limit_is_unchanged() {
    let spec = with_display(TargetDisplay::Query { param: "jql" });
    let short = "b".repeat(79);
    assert_eq!(target_display(&spec, &json!({ "jql": short })), short);
    let exact = "c".repeat(80);
    assert_eq!(target_display(&spec, &json!({ "jql": exact })), exact);
}

#[test]
fn query_cuts_multibyte_by_scalar_not_byte() {
    let spec = with_display(TargetDisplay::Query { param: "jql" });
    let shown = target_display(&spec, &json!({ "jql": "ü".repeat(100) }));
    assert_eq!(shown, format!("{}…", "ü".repeat(80)));
}

#[test]
fn create_in_shows_the_key() {
    let spec = with_display(TargetDisplay::CreateIn("project"));
    assert_eq!(target_display(&spec, &json!({"project": "ABC"})), "ABC");
}

#[test]
fn pair_joins_with_arrow() {
    let spec = with_display(TargetDisplay::Pair("from", "to"));
    assert_eq!(
        target_display(&spec, &json!({"from": "ABC-1", "to": "ABC-2"})),
        "ABC-1 → ABC-2"
    );
}

#[test]
fn move_into_sprint_and_backlog() {
    let sprint = with_display(TargetDisplay::MoveInto {
        sprint_param: Some("sprint"),
        issues_param: "issues",
    });
    assert_eq!(
        target_display(
            &sprint,
            &json!({"sprint": 12, "issues": ["A-1", "A-2", "A-3"]})
        ),
        "sprint 12 · 3 issues"
    );
    let backlog = with_display(TargetDisplay::MoveInto {
        sprint_param: None,
        issues_param: "issues",
    });
    assert_eq!(
        target_display(&backlog, &json!({"issues": ["A-1", "A-2"]})),
        "backlog · 2 issues"
    );
}

#[test]
fn none_shows_the_op_id() {
    let spec = with_display(TargetDisplay::None);
    assert_eq!(target_display(&spec, &json!({})), "test.thing.get");
}

#[test]
fn script_run_counts_lines() {
    assert_eq!(
        script_target_display(&json!({"source": "a\nb\nc"})),
        "script · 3 lines"
    );
    assert_eq!(
        script_target_display(&json!({"source": "x"})),
        "script · 1 lines"
    );
    assert_eq!(SCRIPT_RUN.id, "script.run");
}
