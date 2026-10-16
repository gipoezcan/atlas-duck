#![cfg(feature = "testing")]
//! `jira.issue.edit` complete (Task 13): the `expected` conflict check with the PD-50 equality
//! (JCS bytes, an over-range integer compared exactly), the stale rule over the same equality,
//! the edit preview's rendered and raw diffs with the raw-only count (PD-51, S-12 diff half), the
//! conflict card's diff and deny pre-fill (I-36 Jira half, §5.4 step 2), and `describe`
//! recommending `expected` (§7.3).

mod common;

use std::time::Duration;

use atlas_duck_atlassian::HttpRequestSpec;
use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_core::engine::write::CONFLICT_DENY_PREFILL;
use atlas_duck_core::lifecycle::model::Hold;
use atlas_duck_core::ops::{
    EnrichCtx, EnrichStep, EnrichVerdict, ExecCtx, ExecPlan, PreviewCtx, PreviewInput,
    PreviewModel, StaleCtx, StaleVerdict, WriteView, op_table,
};
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::Harness;
use atlas_duck_core::{BatchFailure, BatchItem, Confirm, DecisionError, DecisionOutcome};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::diff::{DiffLine, DiffOp};
use atlas_duck_preview::{Level, PreviewBody, WarningId};
use atlas_duck_registry::{DescribeEnv, LimitsSource};
use common::jira::{gets_on, issue_path, mount_issue, query};
use common::{TestError, TestResult, de, exit, request_id};
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path};

const EDIT: &str = "jira.issue.edit";
const KEY: &str = "ABC-1";

// ---- pure helpers: the op table without the engine -------------------------------------------

fn spec() -> Result<&'static atlas_duck_registry::OperationSpec, TestError> {
    atlas_duck_registry::get(EDIT).ok_or_else(|| "no jira.issue.edit".into())
}

/// The issue fixture with `fields` replaced by `fields` (what `GET ?fields=<ids>` answers).
fn issue_with_fields(fields: Value) -> Value {
    json!({"id": "10001", "key": KEY, "fields": fields})
}

/// The edit rule's one round (its GETs) and the judge over `answer`.
fn judge(
    params: &Value,
    answer: &Value,
) -> Result<(Vec<atlas_duck_atlassian::GetCall>, EnrichVerdict), TestError> {
    let rule = op_table()
        .get(EDIT)
        .and_then(|i| i.enrich)
        .ok_or("no enrich rule")?;
    let ctx = EnrichCtx {
        spec: spec()?,
        params,
    };
    let calls = match (rule.plan)(&ctx, &[]) {
        EnrichStep::Fetch(calls) => calls.into_iter().map(|(_, c)| c).collect(),
        EnrichStep::Judge => Vec::new(),
    };
    Ok((calls, (rule.judge)(&ctx, std::slice::from_ref(answer))))
}

fn stale(params: &Value, baseline: &Value, answer: &Value) -> Result<StaleVerdict, TestError> {
    let rule = op_table()
        .get(EDIT)
        .and_then(|i| i.stale_check)
        .ok_or("no stale rule")?;
    let ctx = StaleCtx {
        spec: spec()?,
        params,
        baseline,
    };
    Ok((rule.judge)(&ctx, std::slice::from_ref(answer)))
}

fn requests(params: &Value, v: &EnrichVerdict) -> Result<Vec<HttpRequestSpec>, TestError> {
    let base = atlas_duck_atlassian::normalize_base_url("https://jira.example.invalid")?;
    let imp = op_table().get(EDIT).ok_or("no OpImpl")?;
    let ctx = ExecCtx {
        spec: spec()?,
        params,
        base: &base,
        enrichment: Some(v),
        effective_max: None,
        comments_cap: None,
        test_fault: None,
    };
    match (imp.executor)(&ctx) {
        Ok(ExecPlan::Write(r)) => Ok(r),
        other => Err(format!("not a write: {other:?}").into()),
    }
}

/// The edit preview for `params` over an issue whose edited fields are `current`.
fn preview(params: &Value, current: Value) -> Result<PreviewModel, TestError> {
    let (_, v) = judge(params, &issue_with_fields(current))?;
    preview_of(params, &v)
}

fn preview_of(params: &Value, v: &EnrichVerdict) -> Result<PreviewModel, TestError> {
    let reqs = if v.hold == Hold::Preview {
        requests(params, v)?
    } else {
        Vec::new()
    };
    let imp = op_table().get(EDIT).ok_or("no OpImpl")?;
    let ctx = PreviewCtx {
        spec: spec()?,
        instance_alias: "jira-main",
        params,
        input: PreviewInput::Write(WriteView {
            requests: &reqs,
            hold: v.hold,
            enrichment: Some(v),
            failure: None,
        }),
        field_names: None,
    };
    Ok((imp.previewer)(&ctx))
}

struct Diffs {
    rendered: Vec<DiffLine>,
    raw: Vec<DiffLine>,
    raw_only_changes: u64,
}

fn diffs(m: &PreviewModel) -> Result<Diffs, TestError> {
    match &m.body {
        PreviewBody::EditDiff {
            rendered,
            raw,
            raw_only_changes,
            constructs,
            requests,
        } => {
            assert_eq!(requests.len(), 1, "§5.1 inv. 4: the exact request stays");
            // The storage construct list is Confluence's (M7 Task 15); a Jira edit has none.
            assert!(constructs.is_none());
            Ok(Diffs {
                rendered: rendered.clone(),
                raw: raw.clone(),
                raw_only_changes: *raw_only_changes,
            })
        }
        other => Err(format!("not an edit diff: {other:?}").into()),
    }
}

fn l(op: DiffOp, text: &str) -> DiffLine {
    DiffLine {
        op,
        text: text.to_owned(),
    }
}

fn count(lines: &[DiffLine], op: DiffOp) -> usize {
    lines.iter().filter(|l| l.op == op).count()
}

fn warning(m: &PreviewModel, id: WarningId) -> Option<&str> {
    m.warnings
        .iter()
        .find(|w| w.id == id)
        .map(|w| w.text.as_str())
}

// ---- PD-50: the `expected` equality -----------------------------------------------------------

/// PD-50 (T13 review M-4): an integer JCS refuses (beyond ±(2^53−1)) equals exactly the same
/// integer and nothing else (no rounding: a neighbour or a float of it differs, the conflict
/// state). `1.0` and `1` have the same JCS bytes: equal. (L59 keeps such integers out of agent
/// params, so through the engine only the current value can hold one.)
#[test]
fn expected_over_range_integer_compares_exactly() -> TestResult {
    let big = json!({"customfield_1": 9_007_199_254_740_993_u64});
    let params = json!({"key": KEY, "fields": {"summary": "S"}, "expected": big});
    let (_, v) = judge(&params, &issue_with_fields(big.clone()))?;
    assert_eq!(v.hold, Hold::Preview);
    for other in [
        json!(9_007_199_254_740_992_u64),
        json!(9_007_199_254_740_993.0_f64),
        json!("9007199254740993"),
    ] {
        let (_, v) = judge(
            &params,
            &issue_with_fields(json!({ "customfield_1": other })),
        )?;
        assert_eq!(v.hold, Hold::Conflict, "{other}");
        assert_eq!(
            v.conflict.as_deref(),
            Some("conflict: fields changed since the agent read it: customfield_1")
        );
    }
    // Nested and mixed with safe values (key order free, `2.0` = `2`).
    let nested = json!({"customfield_1": {"n": -9_007_199_254_740_993_i64, "m": [2.0, "x"]}});
    let params = json!({"key": KEY, "fields": {"summary": "S"}, "expected": nested});
    let current: Value =
        serde_json::from_str(r#"{"customfield_1":{"m":[2,"x"],"n":-9007199254740993}}"#)?;
    let (_, v) = judge(&params, &issue_with_fields(current))?;
    assert_eq!(v.hold, Hold::Preview);
    // A safe integer read back as a float is the same number in JCS.
    let params = json!({"key": KEY, "fields": {"summary": "S"},
                        "expected": {"customfield_2": 1.0}});
    let (_, v) = judge(&params, &issue_with_fields(json!({"customfield_2": 1})))?;
    assert_eq!(v.hold, Hold::Preview);
    Ok(())
}

/// The conflict card's diff is the raw diff (2-space pretty JSON) of the agent's `expected`
/// against the current value, per differing field, display-escaped.
#[test]
fn conflict_diff_is_the_raw_diff_of_expected_and_current() -> TestResult {
    let params = json!({"key": KEY, "fields": {"summary": "New"},
                        "expected": {"summary": "Old\u{202E}", "labels": ["web"],
                                     "priority": {"id": "3", "name": "Major"}}});
    let current = json!({"summary": "Now", "labels": ["web"],
                         "priority": {"name": "Minor", "id": "4"}});
    let (_, v) = judge(&params, &issue_with_fields(current))?;
    assert_eq!(v.hold, Hold::Conflict);
    assert_eq!(
        v.conflict.as_deref(),
        Some("conflict: fields changed since the agent read it: priority, summary")
    );
    assert_eq!(
        v.diff_text,
        concat!(
            "priority (- read, + current)\n",
            "  {\n",
            "-   \"id\": \"3\",\n",
            "-   \"name\": \"Major\"\n",
            "+   \"id\": \"4\",\n",
            "+   \"name\": \"Minor\"\n",
            "  }\n",
            "summary (- read, + current)\n",
            "- \"Old⟨U+202E⟩\"\n",
            "+ \"Now\"\n",
        )
    );
    // The conflict card shows it.
    let m = preview_of(&params, &v)?;
    match &m.body {
        PreviewBody::Conflict {
            summary,
            diff_text,
            base_to_current,
            intended,
            ..
        } => {
            assert_eq!(Some(summary.as_str()), v.conflict.as_deref());
            assert_eq!(diff_text, &v.diff_text);
            // M7 Δ2: Jira lists the differing fields in `diff_text`, no rendered diffs.
            assert!(base_to_current.is_empty() && intended.is_empty());
        }
        other => return Err(format!("not the conflict card: {other:?}").into()),
    }
    Ok(())
}

/// T13 review M-5/M-6: a long value's `- read` line cannot use the whole card cap: each side has
/// its own budget (escaped bytes), so the `+ current` line shows too; a cut line ends in `…`.
#[test]
fn conflict_diff_keeps_both_sides_of_a_long_value() -> TestResult {
    let read = format!("{}\u{200B}", "r".repeat(20 * 1024));
    let now = "c".repeat(20 * 1024);
    let params = json!({"key": KEY, "fields": {"description": "x"},
                        "expected": {"description": read}});
    let (_, v) = judge(&params, &issue_with_fields(json!({"description": now})))?;
    assert_eq!(v.hold, Hold::Conflict);
    let t = &v.diff_text;
    assert!(t.len() <= 16 * 1024, "{}", t.len());
    assert!(
        t.starts_with("description (- read, + current)\n- \"rrr"),
        "{t:.80}"
    );
    assert!(t.contains("…\n+ \"ccc"), "the current side shows");
    // A later field whose sides are past their budgets says so in its own section.
    let params = json!({"key": KEY, "fields": {"description": "x"},
                        "expected": {"description": "r".repeat(20 * 1024), "summary": "Old"}});
    let current = json!({"description": "c".repeat(20 * 1024), "summary": "Now"});
    let (_, v) = judge(&params, &issue_with_fields(current))?;
    let t = &v.diff_text;
    assert!(t.len() <= 16 * 1024, "{}", t.len());
    assert!(
        t.ends_with("summary (- read, + current)\n- …\n+ …\n"),
        "{:?}",
        t.get(t.len().saturating_sub(80)..)
    );
    // Escaped widths count: 6 KiB of zero-width spaces stay within the cap as well.
    let read = "\u{200B}".repeat(6 * 1024);
    let params = json!({"key": KEY, "fields": {"description": "x"},
                        "expected": {"description": read}});
    let (_, v) = judge(&params, &issue_with_fields(json!({"description": "now"})))?;
    let t = &v.diff_text;
    assert!(t.len() <= 16 * 1024, "{}", t.len());
    assert!(t.contains("\n+ \"now\"\n"), "{t:.200}");
    assert_eq!(t.matches('⟨').count(), t.matches('⟩').count());
    Ok(())
}

/// The enrichment reads the current values of exactly the `fields`/`update`/`expected` ids and
/// asks for no `renderedFields` (T13: the rendered side is the local projection).
#[test]
fn enrichment_reads_the_edited_ids_without_rendered_fields() -> TestResult {
    let params = json!({"key": KEY, "fields": {"summary": "S"},
                        "update": {"labels": [{"add": "x"}]}, "expected": {"priority": null}});
    let (calls, _) = judge(&params, &issue_with_fields(json!({})))?;
    let [call] = calls.as_slice() else {
        return Err(format!("{} GETs", calls.len()).into());
    };
    assert_eq!(call.endpoint_template, "/rest/api/2/issue/{key}");
    let q: Vec<(&str, &str)> = call
        .query
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(q, [("fields", "labels,priority,summary")]);
    Ok(())
}

// ---- PD-51: the edit diffs -------------------------------------------------------------------

#[test]
fn edit_preview_diffs() -> TestResult {
    let params = json!({"key": KEY, "fields": {"description": "a\nc", "summary": "Same"}});
    let m = preview(&params, json!({"description": "a\nb", "summary": "Same"}))?;
    let d = diffs(&m)?;
    assert_eq!(
        d.rendered,
        [
            l(DiffOp::Field, "fields.description"),
            l(DiffOp::Same, "a\n"),
            l(DiffOp::Del, "b"),
            l(DiffOp::Add, "c"),
            l(DiffOp::Field, "fields.summary (unchanged)"),
        ]
    );
    assert_eq!(
        d.raw,
        [
            l(DiffOp::Field, "fields.description"),
            l(DiffOp::Del, "\"a\\nb\""),
            l(DiffOp::Add, "\"a\\nc\""),
            l(DiffOp::Field, "fields.summary (unchanged)"),
        ]
    );
    for lines in [&d.rendered, &d.raw] {
        assert_eq!(
            (count(lines, DiffOp::Del), count(lines, DiffOp::Add)),
            (1, 1)
        );
    }
    assert_eq!(d.raw_only_changes, 0);
    assert_eq!(warning(&m, WarningId::RawOnlyDiff), None);
    Ok(())
}

/// Non-string fields: the rendered side reuses the raw diff (PD-51); a field the issue lacks
/// diffs from `null`.
#[test]
fn non_string_fields_reuse_the_raw_diff() -> TestResult {
    let params = json!({"key": KEY, "fields": {"priority": {"id": "4"}, "duedate": "2026-11-01"}});
    let m = preview(&params, json!({"priority": {"id": "3", "name": "Major"}}))?;
    let d = diffs(&m)?;
    let priority = [
        l(DiffOp::Field, "fields.priority"),
        l(DiffOp::Same, "{\n"),
        l(DiffOp::Del, "  \"id\": \"3\",\n"),
        l(DiffOp::Del, "  \"name\": \"Major\"\n"),
        l(DiffOp::Add, "  \"id\": \"4\"\n"),
        l(DiffOp::Same, "}"),
    ];
    assert_eq!(&d.raw[3..], priority);
    assert_eq!(&d.rendered[2..], priority);
    // `duedate` was absent: raw from `null`, rendered from "".
    assert_eq!(
        &d.raw[..3],
        [
            l(DiffOp::Field, "fields.duedate"),
            l(DiffOp::Del, "null"),
            l(DiffOp::Add, "\"2026-11-01\""),
        ]
    );
    assert_eq!(
        &d.rendered[..2],
        [
            l(DiffOp::Field, "fields.duedate"),
            l(DiffOp::Add, "2026-11-01"),
        ]
    );
    assert_eq!(d.raw_only_changes, 0);
    Ok(())
}

/// S-12 diff half: a change only the raw diff shows (styling, emphasis, a numeric reference)
/// counts once per field and raises the §6.2 Caution.
#[test]
fn s12_raw_only_diff_flagged() -> TestResult {
    for (old, new) in [
        ("a", "{color:red}a{color}"),
        ("a", "*a*"),
        ("a", "&#97;"),
        ("a\n", "a"),
        // A `\` escape: `\` before an escapable char shows that char (a lone trailing `\` stays
        // visible text, so it is no raw-only change).
        ("a*", "a\\*"),
    ] {
        let params = json!({"key": KEY, "fields": {"description": new}});
        let m = preview(&params, json!({"description": old}))?;
        let d = diffs(&m)?;
        assert_eq!(
            count(&d.rendered, DiffOp::Del) + count(&d.rendered, DiffOp::Add),
            0,
            "{new:?}: {:?}",
            d.rendered
        );
        assert!(count(&d.raw, DiffOp::Del) + count(&d.raw, DiffOp::Add) > 0);
        assert_eq!(d.raw_only_changes, 1, "{new:?}");
        let w = m
            .warnings
            .iter()
            .find(|w| w.id == WarningId::RawOnlyDiff)
            .ok_or("no raw_only_diff")?;
        assert_eq!(w.level, Level::Caution);
        assert_eq!(w.text, "1 changes not visible in rendered diff");
    }
    Ok(())
}

/// T10 review (deviation 6): the Caution strip renders exactly the model's warnings, so an edit
/// model with raw-only changes must carry `RawOnlyDiff` itself (`implied_warning`), and one
/// without implies none. `decision::preview_fetch` debug-asserts the same for every preview.
#[test]
fn raw_only_edit_model_carries_its_warning() -> TestResult {
    for (old, new, raw_only) in [
        ("a", "*a*", true),
        ("a\nb\nc\nd", "a\nX\nc\n{color:red}d{color}", true),
        ("a", "b", false),
    ] {
        let params = json!({"key": KEY, "fields": {"description": new}});
        let m = preview(&params, json!({"description": old}))?;
        assert_eq!(diffs(&m)?.raw_only_changes > 0, raw_only, "{new:?}");
        assert_eq!(
            m.body.implied_warning(),
            raw_only.then_some(WarningId::RawOnlyDiff),
            "{new:?}"
        );
        assert!(m.body.implied_warning_present(&m.warnings), "{new:?}");
    }
    Ok(())
}

/// T6 handoff (PD-51 weakness): a string field's raw diff is one hunk, so a visible change plus
/// an invisible one in another place of the same field would cancel out under the hunk formula.
/// Each source-line hunk whose two sides project to the same text counts on its own.
#[test]
fn raw_only_hunk_beside_a_visible_change_is_flagged() -> TestResult {
    let params = json!({"key": KEY, "fields": {"description": "a\nX\nc\n{color:red}d{color}"}});
    let m = preview(&params, json!({"description": "a\nb\nc\nd"}))?;
    let d = diffs(&m)?;
    assert_eq!(
        count(&d.rendered, DiffOp::Del) + count(&d.rendered, DiffOp::Add),
        2,
        "only b → X shows: {:?}",
        d.rendered
    );
    assert_eq!(d.raw_only_changes, 1);
    assert_eq!(
        warning(&m, WarningId::RawOnlyDiff),
        Some("1 changes not visible in rendered diff")
    );
    // Two fields with an invisible change each: counted per field.
    let params = json!({"key": KEY, "fields": {"description": "*a*", "environment": "{color:blue}e{color}"}});
    let m = preview(&params, json!({"description": "a", "environment": "e"}))?;
    assert_eq!(diffs(&m)?.raw_only_changes, 2);
    assert_eq!(
        warning(&m, WarningId::RawOnlyDiff),
        Some("2 changes not visible in rendered diff")
    );
    Ok(())
}

/// T13 review I-1: an invisible change on a line next to a visible one falls into the same source
/// hunk; each changed line whose own projection the rendered diff does not show counts (equal
/// Del/Add counts also pairwise), so the Caution fires. Plain edits, list items, a visible
/// emphasis change and a new paragraph stay without it.
#[test]
fn raw_only_line_next_to_a_visible_change_is_flagged() -> TestResult {
    for (old, new) in [
        ("Steps\n*important*", "Steps v2\nimportant"),
        ("Steps\nsee {color:red}x{color}", "Steps v2\nsee x"),
        ("x\na", "y\na "),
        (
            "t\n{panel:title=x|bg=green}x{panel}",
            "T\n{panel:title=x|bg=red}x{panel}",
        ),
        // Unequal line counts: a line that renders as nothing removed beside a visible edit.
        ("a\n{color:red}{color}", "b"),
        // Unequal line counts: an emphasis removed next to a removed line.
        ("Steps\n*imp*\nz", "Steps v2\nimp"),
        // The separated case (T13).
        ("a\nb\nc\nd", "a\nX\nc\n{color:red}d{color}"),
    ] {
        let params = json!({"key": KEY, "fields": {"description": new}});
        let m = preview(&params, json!({"description": old}))?;
        let d = diffs(&m)?;
        assert!(
            count(&d.rendered, DiffOp::Del) + count(&d.rendered, DiffOp::Add) > 0,
            "{new:?}: a visible change too"
        );
        assert!(d.raw_only_changes >= 1, "{old:?} -> {new:?}");
        let w = m
            .warnings
            .iter()
            .find(|w| w.id == WarningId::RawOnlyDiff)
            .ok_or_else(|| format!("no raw_only_diff for {old:?} -> {new:?}"))?;
        assert_eq!(w.level, Level::Caution);
    }
    for (old, new) in [
        ("a\nb", "c\nd"),
        ("Steps\nimportant", "Steps v2\nimportant!"),
        ("# one\n# two\n# three", "# one\n# two\n# four"),
        ("* a\n* b", "* a\n* c\n* d"),
        ("*a* b\nc", "*a* x\nc"),
        ("a", "a\n\nb"),
        ("h1. Title\ntext", "h1. Title v2\ntext more"),
    ] {
        let params = json!({"key": KEY, "fields": {"description": new}});
        let m = preview(&params, json!({"description": old}))?;
        assert_eq!(diffs(&m)?.raw_only_changes, 0, "{old:?} -> {new:?}");
        assert_eq!(
            warning(&m, WarningId::RawOnlyDiff),
            None,
            "{old:?} -> {new:?}"
        );
    }
    Ok(())
}

/// T13 review M-3: `summary` is plain text in Jira (shown verbatim), so its rendered view is the
/// text itself: asterisks and link brackets show, and no raw-only Caution is raised for them.
#[test]
fn summary_rendered_view_is_literal() -> TestResult {
    let params = json!({"key": KEY, "fields": {"summary": "Fix *login*"}});
    let m = preview(&params, json!({"summary": "Fix login"}))?;
    let d = diffs(&m)?;
    assert_eq!(
        d.rendered,
        [
            l(DiffOp::Field, "fields.summary"),
            l(DiffOp::Del, "Fix login"),
            l(DiffOp::Add, "Fix *login*"),
        ]
    );
    assert_eq!(d.raw_only_changes, 0);
    assert_eq!(warning(&m, WarningId::RawOnlyDiff), None);
    let params = json!({"key": KEY, "fields": {"summary": "Fix x v2 [t|https://e.invalid]"}});
    let m = preview(&params, json!({"summary": "Fix *x* v1"}))?;
    let d = diffs(&m)?;
    assert!(
        d.rendered.contains(&l(DiffOp::Del, "Fix *x* v1")),
        "{:?}",
        d.rendered
    );
    assert!(
        d.rendered
            .contains(&l(DiffOp::Add, "Fix x v2 [t|https://e.invalid]")),
        "{:?}",
        d.rendered
    );
    assert_eq!(d.raw_only_changes, 0);
    // `description` keeps the wiki projection.
    let params = json!({"key": KEY, "fields": {"description": "Fix *login*"}});
    let m = preview(&params, json!({"description": "Fix login"}))?;
    assert_eq!(diffs(&m)?.raw_only_changes, 1);
    Ok(())
}

/// T13 review M-1: `update.<id>: [{"set": v}]` replaces the value like `fields.<id>`, so it is
/// diffed against the current value (rendered projection, raw-only count). Other operation lists
/// stay raw JSON lines.
#[test]
fn update_set_is_diffed_against_the_current_value() -> TestResult {
    let params = json!({"key": KEY, "update": {"description": [{"set": "a\nc"}]}});
    let m = preview(&params, json!({"description": "a\nb"}))?;
    let d = diffs(&m)?;
    assert_eq!(
        d.rendered,
        [
            l(DiffOp::Field, "update.description"),
            l(DiffOp::Same, "a\n"),
            l(DiffOp::Del, "b"),
            l(DiffOp::Add, "c"),
        ]
    );
    assert_eq!(
        d.raw,
        [
            l(DiffOp::Field, "update.description"),
            l(DiffOp::Del, "\"a\\nb\""),
            l(DiffOp::Add, "\"a\\nc\""),
        ]
    );
    assert_eq!(d.raw_only_changes, 0);
    // An invisible change through `set` counts like one through `fields`.
    let params = json!({"key": KEY, "update": {"description": [{"set": "Steps v2\nimportant"}]}});
    let m = preview(&params, json!({"description": "Steps\n*important*"}))?;
    assert!(diffs(&m)?.raw_only_changes >= 1);
    assert!(warning(&m, WarningId::RawOnlyDiff).is_some());
    Ok(())
}

/// T13 review M-1: a section without a current value (the baseline lacks the id, or a list of
/// several operations that sets the value) shows what is sent as raw Add lines and raises a
/// visible Caution saying no current value was compared.
#[test]
fn edit_without_a_baseline_says_so() -> TestResult {
    let params = json!({"key": KEY, "fields": {"description": "short"}});
    let (_, mut v) = judge(
        &params,
        &issue_with_fields(json!({"description": "long text"})),
    )?;
    v.baseline = json!({});
    let m = preview_of(&params, &v)?;
    let d = diffs(&m)?;
    let shown = [
        l(DiffOp::Field, "fields.description"),
        l(DiffOp::Add, "\"short\""),
    ];
    assert_eq!(d.raw, shown);
    assert_eq!(d.rendered, shown);
    let caution = m
        .warnings
        .iter()
        .find(|w| w.level == Level::Caution && w.text.contains("current value"))
        .ok_or("no Caution for the missing baseline")?;
    assert_eq!(caution.id, WarningId::NoCurrentValue);
    assert_eq!(
        caution.text,
        "1 fields shown as sent, without their current value"
    );
    // Several operations on a text field: shown raw, the same Caution.
    let params = json!({"key": KEY, "update": {"description": [{"set": "a"}, {"set": "b"}]}});
    let m = preview(&params, json!({"description": "x"}))?;
    let d = diffs(&m)?;
    assert_eq!(count(&d.raw, DiffOp::Del), 0);
    assert!(
        m.warnings
            .iter()
            .any(|w| w.text == "1 fields shown as sent, without their current value"),
        "{:?}",
        m.warnings
    );
    Ok(())
}

/// T13 review M-6: a view's per-kind budget counts the escaped bytes (an invisible char widens
/// to `⟨U+XXXX⟩`), so a view stays at its cap; a cut never splits an escape.
#[test]
fn diff_budgets_count_escaped_bytes() -> TestResult {
    let zw = "\u{200B}".repeat(700 * 1024);
    let params = json!({"key": KEY, "fields": {"description": zw}});
    let m = preview(&params, json!({"description": ""}))?;
    let d = diffs(&m)?;
    for lines in [&d.raw, &d.rendered] {
        let added: usize = lines
            .iter()
            .filter(|l| l.op == DiffOp::Add)
            .map(|l| l.text.len())
            .sum();
        assert!(added <= 1024 * 1024, "{added}");
        for l in lines.iter() {
            assert_eq!(
                l.text.matches('⟨').count(),
                l.text.matches('⟩').count(),
                "an escape split at the cut"
            );
        }
    }
    assert!(warning(&m, WarningId::DiffTruncated).is_some());
    assert!(m.header.hidden_in_preview_bytes > 0);
    Ok(())
}

/// T13 review M-7: the heading cap applies to the whole heading, ` (unchanged)` included, and the
/// suffix stays visible after the cut marker.
#[test]
fn unchanged_heading_stays_within_the_cap() -> TestResult {
    let long = format!("customfield_{}", "9".repeat(300));
    let params = json!({"key": KEY, "fields": {long.clone(): "same"}});
    let m = preview(&params, json!({ long: "same" }))?;
    let d = diffs(&m)?;
    let [heading] = d.raw.as_slice() else {
        return Err(format!("{:?}", d.raw).into());
    };
    assert_eq!(heading.op, DiffOp::Field);
    assert!(
        heading.text.ends_with("… (unchanged)"),
        "{:?}",
        heading.text
    );
    assert!(
        heading.text.chars().count() <= 256,
        "{}",
        heading.text.len()
    );
    Ok(())
}

/// `update` operations (labels add/remove) are sent verbatim and shown as raw JSON lines; the
/// rendered side reuses them, so nothing the raw diff shows is missing from the rendered one.
#[test]
fn labels_update_shown_raw() -> TestResult {
    let params = json!({"key": KEY, "update": {"labels": [{"add": "x"}, {"remove": "web"}]}});
    let (_, v) = judge(&params, &issue_with_fields(json!({"labels": ["web"]})))?;
    let sent: Value = serde_json::from_slice(&requests(&params, &v)?[0].body)?;
    assert_eq!(
        sent,
        json!({"update": {"labels": [{"add": "x"}, {"remove": "web"}]}})
    );
    let m = preview_of(&params, &v)?;
    let d = diffs(&m)?;
    let ops = [
        l(DiffOp::Field, "update.labels"),
        l(DiffOp::Add, "[\n"),
        l(DiffOp::Add, "  {\n"),
        l(DiffOp::Add, "    \"add\": \"x\"\n"),
        l(DiffOp::Add, "  },\n"),
        l(DiffOp::Add, "  {\n"),
        l(DiffOp::Add, "    \"remove\": \"web\"\n"),
        l(DiffOp::Add, "  }\n"),
        l(DiffOp::Add, "]"),
    ];
    assert_eq!(d.raw, ops);
    assert_eq!(d.rendered, ops);
    assert_eq!(count(&d.raw, DiffOp::Del), 0);
    assert_eq!(d.raw_only_changes, 0);
    // Add/remove lists name their own effect: no missing-baseline Caution.
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);
    Ok(())
}

/// Diff line texts are display-escaped (§6.4); the line terminators stay.
#[test]
fn diff_lines_are_display_escaped() -> TestResult {
    let params = json!({"key": KEY, "fields": {"description": "a\u{200B}\nb"}});
    let m = preview(&params, json!({"description": "a\nb"}))?;
    let d = diffs(&m)?;
    assert!(
        d.rendered.contains(&l(DiffOp::Add, "a⟨U+200B⟩\n")),
        "{:?}",
        d.rendered
    );
    assert!(
        d.raw.contains(&l(DiffOp::Add, "\"a⟨U+200B⟩\\nb\"")),
        "{:?}",
        d.raw
    );
    Ok(())
}

/// A field id is the agent's: its section heading is display-escaped and one line, and a heading
/// cut at its cap says so (two long ids with one prefix must not look alike); the cut bytes count
/// as hidden.
#[test]
fn field_headings_are_escaped_and_visibly_capped() -> TestResult {
    let long = format!("customfield_{}", "9".repeat(300));
    let params = json!({"key": KEY, "fields": {"bad\u{202E}\nid": "x", long.clone(): "y"}});
    let m = preview(&params, json!({}))?;
    let d = diffs(&m)?;
    let headings: Vec<&str> = d
        .raw
        .iter()
        .filter(|l| l.op == DiffOp::Field)
        .map(|l| l.text.as_str())
        .collect();
    let [bad, cut] = headings.as_slice() else {
        return Err(format!("headings: {headings:?}").into());
    };
    assert!(!bad.contains('\u{202E}') && !bad.contains('\n'), "{bad:?}");
    assert!(bad.contains("⟨U+202E⟩"), "{bad:?}");
    assert!(cut.starts_with("fields.customfield_9"), "{cut:?}");
    assert!(cut.ends_with('…'), "{cut:?}");
    assert!(cut.chars().count() <= 257, "{cut:?}");
    assert!(m.header.hidden_in_preview_bytes > 0);
    Ok(())
}

/// T6 handoff: a diff cut at its caps is flagged (Caution), and the cut bytes count as hidden.
/// Each view keeps a budget per line kind, so a huge current value never pushes the outgoing
/// one out of the diff.
#[test]
fn truncated_diff_is_a_caution() -> TestResult {
    let long = "x".repeat(5 * 1024 * 1024);
    let params = json!({"key": KEY, "fields": {"description": "short"}});
    let m = preview(&params, json!({"description": long}))?;
    let d = diffs(&m)?;
    let w = m
        .warnings
        .iter()
        .find(|w| w.id == WarningId::DiffTruncated)
        .ok_or("no diff_truncated")?;
    assert_eq!(w.level, Level::Caution);
    assert_eq!(
        w.text,
        format!(
            "diff truncated: {} bytes not shown (see Request)",
            m.header.hidden_in_preview_bytes
        )
    );
    assert!(m.header.hidden_in_preview_bytes >= 4 * 1024 * 1024);
    assert!(
        d.raw.contains(&l(DiffOp::Add, "\"short\"")),
        "the outgoing value is shown"
    );
    assert!(d.rendered.contains(&l(DiffOp::Add, "short")));
    for lines in [&d.raw, &d.rendered] {
        let shown: usize = lines.iter().map(|l| l.text.len()).sum();
        assert!(shown <= 3 * 1024 * 1024 + 1024, "{shown}");
    }
    // A small edit is not flagged.
    let m = preview(&params, json!({"description": "long"}))?;
    assert_eq!(warning(&m, WarningId::DiffTruncated), None);
    assert_eq!(m.header.hidden_in_preview_bytes, 0);
    Ok(())
}

// ---- the stale rule ---------------------------------------------------------------------------

/// §5.4 step 5 / PD-50: the stale rule compares the baseline with the same equality as the
/// `expected` check: a value re-serialized (other key order, `5` read back as `5.0`) is
/// unchanged; a changed value names its id; an over-range integer read back unchanged is
/// unchanged (T13 review M-4: never permanently stale), a different one is changed.
#[test]
fn stale_edit_uses_same_equality() -> TestResult {
    let params = json!({"key": KEY, "fields": {"priority": {"id": "4"}}});
    let baseline = json!({"priority": {"id": "3", "name": "Major"}, "customfield_2": 5});
    let reordered: Value = serde_json::from_str(
        r#"{"key":"ABC-1","fields":{"customfield_2":5.0,"priority":{"name":"Major","id":"3"}}}"#,
    )?;
    assert_eq!(
        stale(&params, &baseline, &reordered)?,
        StaleVerdict::Unchanged
    );
    let changed =
        issue_with_fields(json!({"priority": {"id": "2", "name": "Critical"}, "customfield_2": 5}));
    match stale(&params, &baseline, &changed)? {
        StaleVerdict::Changed { delta } => {
            assert_eq!(delta, "fields changed since review: priority");
        }
        StaleVerdict::Unchanged => return Err("a changed priority is unchanged".into()),
    }
    let big = json!({"customfield_1": 9_007_199_254_740_993_u64});
    assert_eq!(
        stale(&params, &big, &issue_with_fields(big.clone()))?,
        StaleVerdict::Unchanged
    );
    let moved = issue_with_fields(json!({"customfield_1": 9_007_199_254_740_995_u64}));
    match stale(&params, &big, &moved)? {
        StaleVerdict::Changed { delta } => {
            assert_eq!(delta, "fields changed since review: customfield_1");
        }
        StaleVerdict::Unchanged => return Err("a changed big integer is unchanged".into()),
    }
    Ok(())
}

// ---- end to end -------------------------------------------------------------------------------

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

async fn identity_ok(mock: &MockDc) {
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
}

async fn records(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

async fn queued(h: &Harness, params: Value) -> Result<String, TestError> {
    let env = h.submit(EDIT, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
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

/// `GET /rest/api/2/issue/{key}` (GET only, so a PUT never meets it) answers the issue fixture.
async fn issue_fixture(mock: &MockDc, key: &str) -> TestResult {
    let mut issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    issue["key"] = json!(key);
    mount_issue(mock, key, &issue).await;
    Ok(())
}

async fn puts(mock: &MockDc) -> Vec<wiremock::Request> {
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "PUT")
        .collect()
}

/// The issue GET answers `first` once, then `then` on every later GET.
async fn issue_answers(mock: &MockDc, first: &Value, then: &Value) {
    for (priority, body, once) in [(1, first, true), (2, then, false)] {
        let m = Mock::given(method("GET"))
            .and(path(mock.path(&issue_path(KEY))))
            .respond_with(
                mock.response(200)
                    .set_body_raw(body.to_string(), "application/json"),
            )
            .with_priority(priority);
        let m = if once { m.up_to_n_times(1) } else { m };
        m.mount(mock.server()).await;
    }
}

/// I-36 (Jira half): an `expected` value that differs from the issue is the conflict state:
/// Approve disabled in Rust individually and in a batch with a clean item (L43), the Caution
/// names the fields, nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i36_edit_expected_conflict_not_approvable() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    issue_fixture(mock, KEY).await?;
    let id = queued(
        &h,
        json!({"key": KEY, "fields": {"summary": "Login fails after reset"},
               "expected": {"summary": "Login page time out"}}),
    )
    .await?;
    let item = h.approver().item(&id).ok_or("not queued")?;
    assert!(!item.approvable);
    let p = h.approver().open(&id).map_err(de)?.preview;
    assert!(!p.approvable);
    let w = p
        .warnings
        .iter()
        .find(|w| w.id == WarningId::Conflict)
        .ok_or("no conflict warning")?;
    assert_eq!(w.level, Level::Caution);
    assert_eq!(
        w.text,
        "conflict: fields changed since the agent read it: summary"
    );
    match &p.body {
        PreviewBody::Conflict {
            summary,
            diff_text,
            base_to_current,
            intended,
            requests,
        } => {
            assert_eq!(summary, &w.text);
            assert_eq!(
                diff_text,
                "summary (- read, + current)\n- \"Login page time out\"\n+ \"Login page times out\"\n"
            );
            // M7 Δ2: Jira lists the differing fields in `diff_text`, no rendered diffs.
            assert!(base_to_current.is_empty() && intended.is_empty());
            // M7 Task 15 (T8 review I-1): the enrichment-time conflict card carries the `PUT`
            // an approval would have sent (§5.1 inv. 4), although it is not approvable.
            assert_eq!(requests.len(), 1, "{requests:?}");
            assert_eq!(requests[0].method, "PUT");
            assert!(
                requests[0]
                    .resolved_url
                    .ends_with("/rest/api/2/issue/ABC-1")
            );
        }
        other => return Err(format!("not the conflict card: {other:?}").into()),
    }
    // The edit form shows `expected` read-only (L06).
    let form = p.edit_form.as_ref().ok_or("no edit form")?;
    let expected = form
        .inputs
        .iter()
        .find(|i| i.path == "expected")
        .ok_or("no expected input")?;
    assert!(expected.read_only);
    not_approvable(h.approver().approve(&id))?;
    assert_eq!(
        records(&h, &id, EventType::DECISION_INVALID)
            .await?
            .first()
            .map(|r| r["reason"].clone()),
        Some(json!("not_approvable"))
    );

    // In a batch with a clean, opened edit (of another issue, so the similarity rule does not
    // flag the pair): the whole batch is rejected (L43).
    issue_fixture(mock, "ABC-2").await?;
    let clean = queued(
        &h,
        json!({"key": "ABC-2", "fields": {"summary": "Login fails after reset"},
               "expected": {"summary": "Login page times out"}}),
    )
    .await?;
    h.approver().open(&clean).map_err(de)?;
    assert!(h.approver().item(&clean).ok_or("gone")?.approvable);
    let batch = [&clean, &id]
        .iter()
        .map(|r| {
            Ok(BatchItem {
                request_id: (*r).clone(),
                candidate_rev: h.approver().rev(r).map_err(de)?,
            })
        })
        .collect::<Result<Vec<_>, TestError>>()?;
    match h.decisions().decide_batch(batch) {
        Err(DecisionError::BatchRejected { failed }) => assert_eq!(
            failed,
            [(
                id.clone(),
                BatchFailure::Invalid(InvalidReason::NotApprovable)
            )]
        ),
        other => return Err(format!("expected BatchRejected, got {other:?}").into()),
    }
    for r in [&clean, &id] {
        assert!(records(&h, r, EventType::WRITE_APPROVED).await?.is_empty());
    }
    assert!(puts(mock).await.is_empty());
    Ok(())
}

/// §5.4 step 2: the user denies the conflict with the app's pre-filled reason: `denied`, exit 3,
/// `message` is that text.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i36_conflict_deny_prefill_and_exit3() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    issue_fixture(mock, KEY).await?;
    let id = queued(
        &h,
        json!({"key": KEY, "fields": {"summary": "S"}, "expected": {"summary": "Old"}}),
    )
    .await?;
    h.approver().deny(&id, CONFLICT_DENY_PREFILL).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!((env.status, exit(&env)), (Status::Denied, 3));
    assert_eq!(
        env.error.as_ref().map(|e| e.message.as_str()),
        Some(CONFLICT_DENY_PREFILL)
    );
    // Opacity (§4.5): the conflict text and the diff reach no envelope.
    let line = env.to_json_line();
    assert!(!line.contains("Login page times out"), "{line}");
    assert!(!line.contains("Old"), "{line}");
    assert!(!line.contains("conflict:"), "{line}");
    assert!(puts(mock).await.is_empty());
    Ok(())
}

/// I-36: equal `expected` values (an object given in another key order, and a nested `4.0`
/// where Jira has `4`, which plain `Value` equality calls different) leave the edit approvable;
/// the preview is the edit diff; a 204 with no body is `succeeded` with receipt `{}`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i36_expected_match_approvable() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    issue_fixture(mock, KEY).await?;
    Mock::given(method("PUT"))
        .and(path(mock.path(&issue_path(KEY))))
        .respond_with(mock.response(204))
        .mount(mock.server())
        .await;
    let params: Value = serde_json::from_str(
        r#"{"key":"ABC-1","fields":{"priority":{"id":"4"}},
            "expected":{"priority":{"name":"Major","id":"3"},"summary":"Login page times out",
                        "status":{"statusCategory":{"name":"In Progress","key":"indeterminate","id":4.0},
                                  "id":"3","name":"In Progress",
                                  "self":"https://jira.corp.example/rest/api/2/status/3"}}}"#,
    )?;
    // The discriminator: M3's `Value` comparison would call this a conflict.
    let fixture: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    assert_ne!(params["expected"]["status"], fixture["fields"]["status"]);
    let id = queued(&h, params).await?;
    let p = h.approver().open(&id).map_err(de)?.preview;
    assert!(p.approvable);
    let PreviewBody::EditDiff { raw, .. } = &p.body else {
        return Err(format!("not an edit diff: {:?}", p.body).into());
    };
    assert_eq!(raw.first(), Some(&l(DiffOp::Field, "fields.priority")));
    // The enrichment GET named every edited and expected id and no `expand`.
    let gets = gets_on(mock, &issue_path(KEY)).await;
    let first = gets.first().ok_or("no enrichment GET")?;
    assert_eq!(
        query(first, "fields").as_deref(),
        Some("priority,status,summary")
    );
    assert_eq!(query(first, "expand"), None);
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(env.data, Some(json!({"receipt": {}})));
    let put = puts(mock).await;
    let [put] = put.as_slice() else {
        return Err(format!("{} PUTs", put.len()).into());
    };
    assert_eq!(
        serde_json::from_slice::<Value>(&put.body)?,
        json!({"fields": {"priority": {"id": "4"}}})
    );
    Ok(())
}

/// The new revision's counter is past `counter` (an edit or a refresh made one).
async fn rev_after(h: &Harness, id: &str, counter: u64) -> TestResult {
    for _ in 0..500 {
        if h.approver()
            .item(id)
            .is_some_and(|i| i.candidate_rev.counter > counter)
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("no new revision".into())
}

/// §5.4 step 4 / L06: the edit form keeps `key` and `expected` read-only and lets the approver
/// edit `fields`; an edit of `fields.summary` re-runs enrichment (an `enrich_keys` param), the new
/// revision's diff shows the edited outgoing value (read from the request that is sent), the
/// approval sends it, and the envelope names the edited key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edit_form_edit_reruns_enrichment_and_sends_the_edit() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    issue_fixture(mock, KEY).await?;
    Mock::given(method("PUT"))
        .and(path(mock.path(&issue_path(KEY))))
        .respond_with(mock.response(204))
        .mount(mock.server())
        .await;
    let id = queued(
        &h,
        json!({"key": KEY, "fields": {"summary": "From the agent"},
               "expected": {"summary": "Login page times out"}}),
    )
    .await?;
    let p = h.approver().open(&id).map_err(de)?.preview;
    let form = p.edit_form.as_ref().ok_or("no edit form")?;
    let input = |name: &str| {
        form.inputs
            .iter()
            .find(|i| i.path == name)
            .ok_or_else(|| format!("no {name} input"))
    };
    assert!(input("key")?.read_only);
    assert!(input("expected")?.read_only);
    assert!(!input("fields")?.read_only);
    let rev = h.approver().rev(&id).map_err(de)?;
    let mut set = serde_json::Map::new();
    set.insert("fields.summary".to_owned(), json!("From the approver"));
    h.approver()
        .edit(
            &id,
            atlas_duck_core::edit::Edits {
                set,
                remove: Vec::new(),
            },
        )
        .map_err(de)?;
    rev_after(&h, &id, rev.counter).await?;
    let enrich: Vec<Value> = records(&h, &id, EventType::PREVIEW_FETCH)
        .await?
        .into_iter()
        .map(|r| r["purpose"].clone())
        .collect();
    assert_eq!(enrich, ["enrich", "enrich"], "the enrichment ran again");
    let p = h.approver().open(&id).map_err(de)?.preview;
    assert!(p.approvable);
    let PreviewBody::EditDiff { rendered, raw, .. } = &p.body else {
        return Err(format!("not an edit diff: {:?}", p.body).into());
    };
    assert!(
        raw.contains(&l(DiffOp::Add, "\"From the approver\"")),
        "{raw:?}"
    );
    assert!(
        rendered.contains(&l(DiffOp::Add, "From the approver")),
        "{rendered:?}"
    );
    assert!(
        raw.contains(&l(DiffOp::Del, "\"Login page times out\"")),
        "{raw:?}"
    );
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert!(env.edited);
    let data = env.data.clone().ok_or("no data")?;
    assert_eq!(data["edited_keys"]["changed"], json!(["fields.summary"]));
    let put = puts(mock).await;
    let [put] = put.as_slice() else {
        return Err(format!("{} PUTs", put.len()).into());
    };
    assert_eq!(
        serde_json::from_slice::<Value>(&put.body)?,
        json!({"fields": {"summary": "From the approver"}})
    );
    Ok(())
}

/// §5.4 step 5 end to end: the stale check sees the baseline re-serialized (`5` as `5.0`, keys
/// reordered): unchanged, the edit is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_check_passes_a_reserialized_baseline() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    let first: Value = serde_json::from_str(
        r#"{"key":"ABC-1","fields":{"customfield_2":5,"priority":{"id":"3","name":"Major"}}}"#,
    )?;
    let then: Value = serde_json::from_str(
        r#"{"key":"ABC-1","fields":{"priority":{"name":"Major","id":"3"},"customfield_2":5.0}}"#,
    )?;
    issue_answers(mock, &first, &then).await;
    Mock::given(method("PUT"))
        .and(path(mock.path(&issue_path(KEY))))
        .respond_with(mock.response(204))
        .mount(mock.server())
        .await;
    let id = queued(
        &h,
        json!({"key": KEY, "fields": {"priority": {"id": "4"}},
               "expected": {"customfield_2": 5}}),
    )
    .await?;
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert!(records(&h, &id, EventType::WRITE_STALE).await?.is_empty());
    assert_eq!(puts(mock).await.len(), 1);
    Ok(())
}

/// §5.4 step 5: the issue changed after review: `WRITE_STALE {changed}` with the delta naming
/// the field, nothing sent; the refresh re-runs enrichment, and since the agent's `expected` no
/// longer holds, the item comes back in the conflict state (not approvable).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_edit_returns_with_delta_then_conflict() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    identity_ok(mock).await;
    let first = issue_with_fields(json!({"summary": "Login page times out"}));
    let then = issue_with_fields(json!({"summary": "Someone else's edit"}));
    issue_answers(mock, &first, &then).await;
    let id = queued(
        &h,
        json!({"key": KEY, "fields": {"summary": "Mine"},
               "expected": {"summary": "Login page times out"}}),
    )
    .await?;
    let rev1 = h.approver().rev(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    let mut item = None;
    for _ in 0..500 {
        if let Some(i) = h.approver().item(&id)
            && i.candidate_rev.counter > rev1.counter + 1
        {
            item = Some(i);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let item = item.ok_or("never back in the queue")?;
    assert!(!item.approvable && item.stale);
    let stale = records(&h, &id, EventType::WRITE_STALE).await?;
    assert_eq!(
        stale,
        [json!({"reason": "changed", "class": null,
                "delta": "fields changed since review: summary"})]
    );
    let purposes: Vec<Value> = records(&h, &id, EventType::PREVIEW_FETCH)
        .await?
        .into_iter()
        .map(|r| r["purpose"].clone())
        .collect();
    assert_eq!(
        purposes,
        ["enrich", "stale_check", "stale_check", "refresh"]
    );
    let p = h.approver().open(&id).map_err(de)?.preview;
    assert!(
        matches!(p.body, PreviewBody::Conflict { .. }),
        "{:?}",
        p.body
    );
    not_approvable(h.approver().approve(&id))?;
    assert!(puts(mock).await.is_empty());
    Ok(())
}

/// §7.3: `ops describe jira.issue.edit` recommends `expected` for every edited field, especially
/// `description`.
#[test]
fn describe_recommends_expected() -> TestResult {
    let env = DescribeEnv {
        limits_source: LimitsSource::Default,
        available: None,
        caps: Value::Null,
        script_limits: Value::Null,
    };
    let d = atlas_duck_registry::describe(spec()?, &env);
    let text = d["params_schema"]["properties"]["expected"]["description"]
        .as_str()
        .ok_or("no expected description")?;
    assert!(
        text.contains("Recommended for every edited field"),
        "{text}"
    );
    assert!(text.contains("description"), "{text}");
    assert!(d.to_string().contains("expected"));
    Ok(())
}
