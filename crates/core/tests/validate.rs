//! U-33 (core half), X-10 (min_version gate), §9.1 step 2 static script checks.

use atlas_duck_core::validate::{
    EffectiveCaps, JIRA_SYSTEM_FIELDS, MOVE_LIMIT_HINT, SCRIPT_HEAP_K, ValidateCtx,
    ValidationError, validate, validate_script_submit as validate_script_submit_with,
};
use atlas_duck_ipc::envelope::ErrorCode;
use atlas_duck_ipc::sandbox::ScriptLimits;
use atlas_duck_ipc::sandbox::script::MAX_ARGS_NESTING as MAX_SCRIPT_ARGS_NESTING;
use atlas_duck_registry::{OperationSpec, Product, Version};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn op(id: &str) -> Result<&'static OperationSpec, String> {
    atlas_duck_registry::get(id).ok_or_else(|| format!("no op {id}"))
}

fn check(
    id: &str,
    params: Value,
) -> Result<Result<atlas_duck_core::validate::Validated, ValidationError>, String> {
    check_with(id, params, &EffectiveCaps::default(), None, false)
}

fn check_with(
    id: &str,
    params: Value,
    caps: &EffectiveCaps,
    instance_version: Option<Version>,
    for_script: bool,
) -> Result<Result<atlas_duck_core::validate::Validated, ValidationError>, String> {
    let ctx = ValidateCtx {
        instance_version,
        caps,
        for_script,
    };
    Ok(validate(op(id)?, &params, &ctx))
}

fn rejected(
    r: Result<atlas_duck_core::validate::Validated, ValidationError>,
) -> Result<ValidationError, String> {
    r.err()
        .ok_or_else(|| "expected a validation error".to_owned())
}

fn param(e: &ValidationError) -> Option<&str> {
    e.details.get("param").and_then(Value::as_str)
}

/// `validate_script_submit` against the built-in defaults as the ceiling.
fn validate_script_submit(
    source: &str,
    args: &Value,
    limits: &Value,
) -> Result<ScriptLimits, ValidationError> {
    validate_script_submit_with(source, args, limits, &ScriptLimits::default())
}

#[test]
fn u33_schema_rejects() -> TestResult {
    let e = rejected(check("jira.issue.get", json!({}))?)?;
    assert_eq!(e.code, ErrorCode::Validation);
    assert_eq!(param(&e), Some("key"));
    assert_eq!(e.message, "params/key: required");

    let e = rejected(check("jira.issue.get", json!({"key": "ABC-1", "foo": 1}))?)?;
    assert_eq!(e.code, ErrorCode::Validation);
    assert_eq!(param(&e), Some("foo"));

    let e = rejected(check("jira.issue.get", json!({"key": 5}))?)?;
    assert_eq!(e.code, ErrorCode::Validation);
    assert_eq!(e.message, "params/key: type");

    // The message never carries the offending value.
    let e = rejected(check("jira.issue.get", json!({"key": "secret-value-xyz"}))?)?;
    assert_eq!(e.message, "params/key: pattern");
    assert!(!serde_json::to_string(&e)?.contains("secret-value-xyz"));

    // Not an object at all.
    let e = rejected(check("jira.issue.get", json!(["ABC-1"]))?)?;
    assert_eq!(e.code, ErrorCode::Validation);

    // A valid call comes back unchanged, no defaults applied.
    let params = json!({"key": "ABC-1"});
    let ok = check("jira.issue.get", params.clone())??;
    assert_eq!(ok.params, params);
    assert_eq!(ok.effective_max, None);
    assert!(!ok.truncated_by_clamp);
    Ok(())
}

#[test]
fn u33_all_ops_compile_and_accept_their_example() -> TestResult {
    for spec in atlas_duck_registry::all() {
        let example = spec
            .params_schema_json()
            .get("examples")
            .and_then(|e| e.get(0))
            .cloned()
            .ok_or_else(|| format!("{} has no example", spec.id))?;
        let r = check(spec.id, example)?;
        // Confluence writes with a body and no `body_format` hit the PD-09 rule (no Markdown
        // conversion before M7); Jira converts from M5 on (PD-43), so every Jira example and
        // everything else passes.
        match r {
            Ok(_) => {}
            Err(e) => {
                assert_eq!(spec.product, Product::Confluence, "{}: {e}", spec.id);
                assert_eq!(param(&e), Some("body_format"), "{}: {e}", spec.id);
            }
        }
    }
    Ok(())
}

#[test]
fn u33_field_rules_jira_fields() -> TestResult {
    for ok in [
        "summary",
        "customfield_10200",
        "-description",
        "*all",
        "*navigable",
        "-customfield_1",
    ] {
        let r = check("jira.issue.get", json!({"key": "ABC-1", "fields": [ok]}))?;
        assert!(r.is_ok(), "{ok} should be accepted");
    }
    for bad in [
        "customfield_x",
        "nope",
        "*",
        "customfield_",
        "--summary",
        "-*all",
        "",
    ] {
        let e = rejected(check(
            "jira.issue.get",
            json!({"key": "ABC-1", "fields": [bad]}),
        )?)?;
        assert_eq!(e.code, ErrorCode::Validation, "{bad}");
        assert_eq!(param(&e), Some("fields"), "{bad}");
        assert!(e.details.contains_key("value"), "{bad}");
    }
    // Same rules on search and the agile lists.
    assert!(
        check(
            "jira.search",
            json!({"jql": "project = ABC", "fields": ["-summary"]})
        )?
        .is_ok()
    );
    let e = rejected(check(
        "jira.search",
        json!({"jql": "project = ABC", "fields": ["x"]}),
    )?)?;
    assert_eq!(param(&e), Some("fields"));
    let e = rejected(check(
        "jira.sprint.issues",
        json!({"id": 1, "fields": ["x"]}),
    )?)?;
    assert_eq!(param(&e), Some("fields"));
    // The list is the DC 9.12 set; every entry is itself accepted.
    assert_eq!(JIRA_SYSTEM_FIELDS.len(), 40);
    for field in JIRA_SYSTEM_FIELDS {
        assert!(check("jira.issue.get", json!({"key": "ABC-1", "fields": [field]}))?.is_ok());
    }
    Ok(())
}

#[test]
fn u33_echoed_values_are_bounded_and_escaped() -> TestResult {
    let long = format!("a\u{202E}{}", "b".repeat(500));
    let e = rejected(check(
        "jira.issue.get",
        json!({"key": "ABC-1", "fields": [long]}),
    )?)?;
    let value = e
        .details
        .get("value")
        .and_then(Value::as_str)
        .ok_or("value")?;
    assert!(value.contains("⟨U+202E⟩"));
    assert!(!value.contains('\u{202E}'));
    assert!(value.chars().count() < 100);
    assert!(value.ends_with('…'));
    Ok(())
}

#[test]
fn u33_expand_allowlist() -> TestResult {
    let r = check(
        "jira.issue.get",
        json!({"key": "ABC-1", "expand": ["names"]}),
    )?;
    assert!(r.is_ok());
    let e = rejected(check(
        "jira.issue.get",
        json!({"key": "ABC-1", "expand": ["names", "operations", "bogus"]}),
    )?);
    // `operations` may or may not be allowed; `bogus` never is.
    let e = match e {
        Ok(e) => e,
        Err(_) => return Err("bogus expand accepted".into()),
    };
    assert_eq!(param(&e), Some("expand"));
    Ok(())
}

#[test]
fn u33_create_fields_map_keys() -> TestResult {
    let base = |fields: Value| json!({"project": "ABC", "issuetype": "Bug", "summary": "s", "body_format": "wiki", "fields": fields});
    assert!(check("jira.issue.create", base(json!({"customfield_1": 1})))?.is_ok());
    assert!(check("jira.issue.create", base(json!({"labels": ["x"]})))?.is_ok());
    for dup in ["project", "issuetype", "summary", "description"] {
        let e = rejected(check("jira.issue.create", base(json!({ dup: "x" })))?)?;
        assert_eq!(e.code, ErrorCode::Validation);
        assert_eq!(param(&e), Some(format!("fields.{dup}").as_str()));
        assert_eq!(
            e.details.get("message").and_then(Value::as_str),
            Some("duplicates a dedicated parameter")
        );
    }
    for bad in ["*all", "nope", "customfield_x"] {
        let e = rejected(check("jira.issue.create", base(json!({ bad: 1 })))?)?;
        assert_eq!(e.code, ErrorCode::Validation, "{bad}");
        assert!(param(&e).is_some_and(|p| p.starts_with("fields")), "{bad}");
    }
    // The edit op: `fields` and `expected` keys are field ids; no duplicate rule there.
    let edit = |fields: Value, expected: Value| json!({"key": "ABC-1", "fields": fields, "expected": expected});
    assert!(
        check(
            "jira.issue.edit",
            edit(json!({"summary": "x"}), json!({"summary": "y"}))
        )?
        .is_ok()
    );
    let e = rejected(check(
        "jira.issue.edit",
        edit(json!({"nope": 1}), json!({})),
    )?)?;
    assert_eq!(param(&e), Some("fields.nope"));
    let e = rejected(check(
        "jira.issue.edit",
        edit(json!({}), json!({"nope": 1})),
    )?)?;
    assert_eq!(param(&e), Some("expected.nope"));
    let e = rejected(check(
        "jira.issue.edit",
        edit(json!({}), json!({"x y": 1})),
    )?)?;
    assert_eq!(param(&e), Some("expected.x y"));
    // T13 review M-2: `update` keys are field ids too (they name the enrichment and stale GET
    // `?fields=` list), so `-description` or `*all` cannot alter what is read.
    let update = |update: Value| json!({"key": "ABC-1", "update": update});
    assert!(check("jira.issue.edit", update(json!({"labels": [{"add": "x"}]})))?.is_ok());
    assert!(
        check(
            "jira.issue.edit",
            update(json!({"customfield_7": [{"set": 1}]}))
        )?
        .is_ok()
    );
    for bad in [
        "-description",
        "*all",
        "*navigable",
        "nope",
        "customfield_x",
        "a,b",
    ] {
        let e = rejected(check("jira.issue.edit", update(json!({ bad: [] })))?)?;
        assert_eq!(e.code, ErrorCode::Validation, "{bad}");
        assert!(
            param(&e).is_some_and(|p| p.starts_with("update")),
            "{bad}: {:?}",
            param(&e)
        );
    }
    Ok(())
}

#[test]
fn u33_caps_clamp_and_hard_cap() -> TestResult {
    let search = |max: Value| json!({"jql": "project = ABC", "max": max});
    let caps = EffectiveCaps::default();

    let v = check_with("jira.search", json!({"jql": "x"}), &caps, None, false)??;
    assert_eq!((v.effective_max, v.truncated_by_clamp), (Some(50), false));

    let v = check_with("jira.search", search(json!(200)), &caps, None, false)??;
    assert_eq!((v.effective_max, v.truncated_by_clamp), (Some(200), false));

    let v = check_with("jira.search", search(json!(900)), &caps, None, false)??;
    assert_eq!((v.effective_max, v.truncated_by_clamp), (Some(500), true));
    // The agent's params stay as sent.
    assert_eq!(v.params, search(json!(900)));

    let e = rejected(check_with(
        "jira.search",
        search(json!(900)),
        &caps,
        None,
        true,
    )?)?;
    assert_eq!(e.code, ErrorCode::Validation);
    assert_eq!(param(&e), Some("max"));
    assert_eq!(e.details.get("message"), Some(&json!("above the hard cap")));
    assert_eq!(e.details.get("cap"), Some(&json!(500)));

    // In a script, at the cap is fine.
    assert!(check_with("jira.search", search(json!(500)), &caps, None, true)?.is_ok());

    // A configured hard cap of 100.
    let mut configured = EffectiveCaps::default();
    configured.hard_caps.insert("jira.search", 100);
    let v = check_with("jira.search", search(json!(900)), &configured, None, false)??;
    assert_eq!((v.effective_max, v.truncated_by_clamp), (Some(100), true));
    let e = rejected(check_with(
        "jira.search",
        search(json!(101)),
        &configured,
        None,
        true,
    )?)?;
    assert_eq!(e.details.get("cap"), Some(&json!(100)));
    // A cap below the op default bounds the default too, without claiming a clamp.
    configured.hard_caps.insert("jira.search", 10);
    let v = check_with("jira.search", json!({"jql": "x"}), &configured, None, false)??;
    assert_eq!((v.effective_max, v.truncated_by_clamp), (Some(10), false));

    // Out-of-range values never reach the cap logic.
    for bad in [json!(0), json!(-1), json!(1.5), json!("5")] {
        let e = rejected(check("jira.search", search(bad))?)?;
        assert_eq!(e.code, ErrorCode::Validation);
        assert_eq!(param(&e), Some("max"));
    }
    // A value that does not fit u32 is clamped, not wrapped.
    let v = check("jira.search", search(json!(10_000_000_000u64)))??;
    assert_eq!((v.effective_max, v.truncated_by_clamp), (Some(500), true));
    Ok(())
}

/// Δ7: the comments cap is the registry's 100 unless configured, always within 1..=1000, and
/// only `jira.issue.get` has one.
#[test]
fn comments_cap_default_clamp_and_scope() -> TestResult {
    let get = json!({"key": "ABC-1", "comments": true});
    let with = |cap: Option<u32>| EffectiveCaps {
        comments_cap: cap,
        ..EffectiveCaps::default()
    };
    for (configured, expected) in [
        (None, 100),
        (Some(0), 1),
        (Some(1), 1),
        (Some(1000), 1000),
        (Some(5000), 1000),
    ] {
        let v = check_with(
            "jira.issue.get",
            get.clone(),
            &with(configured),
            None,
            false,
        )??;
        assert_eq!(v.comments_cap, Some(expected), "{configured:?}");
    }
    // A configured cap never reaches another op.
    let caps = with(Some(10));
    let v = check_with("jira.search", json!({"jql": "x"}), &caps, None, false)??;
    assert_eq!(v.comments_cap, None);
    let v = check_with(
        "jira.comment.list",
        json!({"key": "ABC-1"}),
        &caps,
        None,
        false,
    )??;
    assert_eq!(v.comments_cap, None);
    Ok(())
}

#[test]
fn move_limit_51_rejected_with_hint() -> TestResult {
    let issues = |n: usize| (1..=n).map(|i| format!("ABC-{i}")).collect::<Vec<_>>();
    assert_eq!(
        MOVE_LIMIT_HINT,
        "split into requests of ≤ 50 issues; moves of disjoint issues can be batch-approved"
    );
    for (id, mk) in [
        (
            "jira.sprint.move_issues",
            (|n: Vec<String>| json!({"id": 7, "issues": n})) as fn(Vec<String>) -> Value,
        ),
        ("jira.backlog.move_issues", |n| json!({"issues": n})),
    ] {
        assert!(check(id, mk(issues(50)))?.is_ok(), "{id} at 50");
        let e = rejected(check(id, mk(issues(51)))?)?;
        assert_eq!(e.code, ErrorCode::Validation);
        assert_eq!(param(&e), Some("issues"));
        assert_eq!(e.details.get("message"), Some(&json!(MOVE_LIMIT_HINT)));
        assert_eq!(e.message, format!("params/issues: {MOVE_LIMIT_HINT}"));
    }
    Ok(())
}

#[test]
fn upload_size_limit() -> TestResult {
    let ten_mib = 10 * 1024 * 1024;
    let encoded = |bytes: usize| {
        // base64 of `bytes` bytes: 4 chars per 3 bytes, padded.
        let full = bytes / 3 * 4;
        let rest = match bytes % 3 {
            0 => "",
            1 => "AA==",
            _ => "AAA=",
        };
        format!("{}{rest}", "A".repeat(full))
    };
    let params =
        |bytes: usize| json!({"id": "1", "filename": "a.bin", "content_base64": encoded(bytes)});
    assert!(check("confluence.attachment.upload", params(1024))?.is_ok());
    assert!(check("confluence.attachment.upload", params(ten_mib))?.is_ok());
    let e = rejected(check("confluence.attachment.upload", params(ten_mib + 1))?)?;
    assert_eq!(e.code, ErrorCode::Validation);
    assert_eq!(param(&e), Some("content_base64"));
    // The error never contains the content.
    assert!(serde_json::to_string(&e)?.len() < 400);
    Ok(())
}

#[test]
fn x10_min_version_unsupported_never_version_string() -> TestResult {
    let caps = EffectiveCaps::default();
    let params = json!({"project": "ABC", "typeId": "10001"});
    let old = Some(Version {
        major: 8,
        minor: 3,
        patch: 0,
    });
    let e = rejected(check_with(
        "jira.createmeta.fields",
        params.clone(),
        &caps,
        old,
        false,
    )?)?;
    assert_eq!(e.code, ErrorCode::OpUnsupportedByInstance);
    assert_eq!(
        Value::Object(e.details.clone()),
        json!({"min_version": "8.4.0"})
    );
    let text = serde_json::to_string(&e)?;
    assert!(!text.contains("8.3"), "{text}");

    for ok in [
        Some(Version {
            major: 8,
            minor: 4,
            patch: 0,
        }),
        Some(Version {
            major: 9,
            minor: 12,
            patch: 0,
        }),
        None,
    ] {
        assert!(check_with("jira.createmeta.fields", params.clone(), &caps, ok, false)?.is_ok());
    }
    // An op without `min_version` ignores the instance version.
    assert!(check_with("jira.issue.get", json!({"key": "ABC-1"}), &caps, old, false)?.is_ok());
    // Invalid params still say validation, whatever the version.
    let e = rejected(check_with(
        "jira.createmeta.fields",
        json!({}),
        &caps,
        old,
        false,
    )?)?;
    assert_eq!(e.code, ErrorCode::Validation);
    Ok(())
}

#[test]
fn pd09_markdown_rejected_absent_counts_as_markdown() -> TestResult {
    let jira = |extra: Value| {
        let mut p = json!({"key": "ABC-1", "body": "hello"});
        if let (Some(p), Some(extra)) = (p.as_object_mut(), extra.as_object()) {
            p.extend(extra.clone());
        }
        p
    };
    // Jira converts Markdown from M5 on (PD-43): the refusal is Confluence's until M7.
    let confluence = |extra: Value| {
        let mut p = json!({"content_id": "1", "body": "hello"});
        if let (Some(p), Some(extra)) = (p.as_object_mut(), extra.as_object()) {
            p.extend(extra.clone());
        }
        p
    };
    for params in [
        confluence(json!({})),
        confluence(json!({"body_format": "markdown"})),
    ] {
        let e = rejected(check("confluence.comment.add", params)?)?;
        assert_eq!(e.code, ErrorCode::Validation);
        assert_eq!(param(&e), Some("body_format"));
        assert_eq!(
            e.details.get("message"),
            Some(&json!("markdown conversion is not available in this build"))
        );
    }
    for format in [json!({}), json!({"body_format": "markdown"})] {
        assert!(check("jira.comment.add", jira(format))?.is_ok());
    }
    assert!(check("jira.comment.add", jira(json!({"body_format": "wiki"})))?.is_ok());
    assert!(
        check(
            "confluence.comment.add",
            json!({"content_id": "1", "body": "<p>x</p>", "body_format": "storage"})
        )?
        .is_ok()
    );
    let e = rejected(check(
        "confluence.page.update",
        json!({"id": "1", "base_version": 1, "body": "x"}),
    )?)?;
    assert_eq!(param(&e), Some("body_format"));
    // An invalid enum value is the schema's.
    let e = rejected(check(
        "jira.comment.add",
        jira(json!({"body_format": "html"})),
    )?)?;
    assert_eq!(e.message, "params/body_format: enum");
    // Ops without a body are not affected.
    assert!(check("jira.issue.get", json!({"key": "ABC-1"}))?.is_ok());
    Ok(())
}

#[test]
fn u33_validation_is_static() -> TestResult {
    // `ValidateCtx` carries a version, the configured caps and a flag; nothing fetched.
    let caps = EffectiveCaps::default();
    let ctx = ValidateCtx {
        instance_version: None,
        caps: &caps,
        for_script: false,
    };
    let spec = op("jira.search")?;
    let params = json!({"jql": "project = ABC", "max": 900, "fields": ["summary", "bad"]});
    let first = serde_json::to_vec(
        &validate(spec, &params, &ctx)
            .map_err(|e| e.to_string())
            .err(),
    )?;
    for _ in 0..100 {
        let again = serde_json::to_vec(
            &validate(spec, &params, &ctx)
                .map_err(|e| e.to_string())
                .err(),
        )?;
        assert_eq!(first, again);
    }
    let ok = json!({"jql": "project = ABC", "max": 900});
    let a = validate(spec, &ok, &ctx).map_err(|e| e.to_string())?;
    let b = validate(spec, &ok, &ctx).map_err(|e| e.to_string())?;
    assert_eq!(a, b);
    Ok(())
}

#[test]
fn debug_never_prints_params() -> TestResult {
    let v = check(
        "jira.issue.get",
        json!({"key": "ABC-1", "fields": ["summary"]}),
    )??;
    let text = format!("{v:?}");
    assert!(!text.contains("ABC-1"), "{text}");
    Ok(())
}

#[test]
fn script_submit_limits() -> TestResult {
    let args = json!({});
    let none = Value::Null;
    let ok = validate_script_submit(&"a".repeat(256 * 1024), &args, &none)?;
    assert_eq!(ok, atlas_duck_ipc::sandbox::ScriptLimits::default());

    let e = validate_script_submit(&"a".repeat(256 * 1024 + 1), &args, &none)
        .err()
        .ok_or("source accepted")?;
    assert_eq!(e.code, ErrorCode::Validation);
    assert_eq!(param(&e), Some("source"));

    let big_args = json!({"x": "a".repeat(1024 * 1024)});
    let e = validate_script_submit("1", &big_args, &none)
        .err()
        .ok_or("args accepted")?;
    assert_eq!(param(&e), Some("args"));

    let e = validate_script_submit("1", &args, &json!({"timeout_s": 600}))
        .err()
        .ok_or("raised limit accepted")?;
    assert_eq!(e.code, ErrorCode::Validation);
    assert_eq!(param(&e), Some("limits.timeout_s"));
    assert_eq!(
        e.details.get("message"),
        Some(&json!("agents may only lower limits"))
    );

    // 128 = k (8) x the default `max_call_result_mb` (16): the lowest heap the invariant allows.
    let lowered = validate_script_submit("1", &args, &json!({"heap_mb": 128}))?;
    assert_eq!(lowered.heap_mb, 128);
    assert_eq!(lowered.timeout_s, 120);

    // At the default is "not above".
    assert!(validate_script_submit("1", &args, &json!({"timeout_s": 120}))?.timeout_s == 120);

    for bad in [
        json!({"nope": 1}),
        json!({"timeout_s": 0}),
        json!({"timeout_s": -1}),
        json!({"timeout_s": 1.5}),
        json!({"timeout_s": "5"}),
        json!([1]),
        json!("x"),
    ] {
        let e = validate_script_submit("1", &args, &bad)
            .err()
            .ok_or("accepted")?;
        assert_eq!(e.code, ErrorCode::Validation, "{bad}");
    }
    // The unknown key is not echoed.
    let e = validate_script_submit("1", &args, &json!({"secret_key_name": 1}))
        .err()
        .ok_or("accepted")?;
    assert!(!serde_json::to_string(&e)?.contains("secret_key_name"));
    Ok(())
}

#[test]
fn script_limits_process_must_hold_the_heap() -> TestResult {
    let args = json!({});
    // heap 256 (default) + 88 = 344 <= 512: ok; lowering process below that is not.
    assert!(validate_script_submit("1", &args, &json!({"process_mb": 344}))?.process_mb == 344);
    let e = validate_script_submit("1", &args, &json!({"process_mb": 343}))
        .err()
        .ok_or("accepted")?;
    assert_eq!(param(&e), Some("limits.process_mb"));
    // Lowering heap together with process is fine; heap alone only helps.
    assert!(
        validate_script_submit("1", &args, &json!({"heap_mb": 128, "process_mb": 216}))?.heap_mb
            == 128
    );
    let e = validate_script_submit("1", &args, &json!({"heap_mb": 128, "process_mb": 215}))
        .err()
        .ok_or("accepted")?;
    assert_eq!(param(&e), Some("limits.process_mb"));
    Ok(())
}

#[test]
fn limits_above_configured_default_rejected_exit2() -> TestResult {
    let args = json!({});
    // The configured set is the ceiling (PD-139), not the spec default.
    let ceiling = ScriptLimits {
        timeout_s: 240,
        max_calls: 50,
        ..ScriptLimits::default()
    };
    let go = |limits: Value| validate_script_submit_with("1", &args, &limits, &ceiling);
    // Absent keys take the ceiling's value, not the spec's.
    let ok = go(Value::Null)?;
    assert_eq!((ok.timeout_s, ok.max_calls), (240, 50));
    assert_eq!(go(json!({"timeout_s": 240}))?.timeout_s, 240);
    assert_eq!(go(json!({"timeout_s": 10}))?.timeout_s, 10);
    // Above the configured default, though below the spec's: exit 2 (`validation`).
    let e = go(json!({"max_calls": 51})).err().ok_or("accepted")?;
    assert_eq!(e.code, ErrorCode::Validation);
    assert_eq!(param(&e), Some("limits.max_calls"));
    assert_eq!(
        e.details.get("message"),
        Some(&json!("agents may only lower limits"))
    );
    // And above the spec default when the configured one is raised: still "above".
    let e = go(json!({"timeout_s": 241})).err().ok_or("accepted")?;
    assert_eq!(param(&e), Some("limits.timeout_s"));
    Ok(())
}

#[test]
fn heap_k_invariant_on_limits_exit2() -> TestResult {
    assert_eq!(SCRIPT_HEAP_K, 8, "provisional until M8 measures it");
    let args = json!({});
    // heap_mb >= k x max_call_result_mb on the effective set (default call result: 16).
    assert_eq!(
        validate_script_submit("1", &args, &json!({"heap_mb": 128}))?.heap_mb,
        128
    );
    let e = validate_script_submit("1", &args, &json!({"heap_mb": 127}))
        .err()
        .ok_or("accepted")?;
    assert_eq!(e.code, ErrorCode::Validation);
    assert_eq!(param(&e), Some("limits.heap_mb"));
    assert_eq!(
        e.details.get("message"),
        Some(&json!(
            "heap_mb must be at least k × max_call_result_mb (k = 8)"
        ))
    );
    // Lowering the call result lowers the heap the run needs.
    let ok = validate_script_submit("1", &args, &json!({"heap_mb": 64, "max_call_result_mb": 8}))?;
    assert_eq!((ok.heap_mb, ok.max_call_result_mb), (64, 8));
    let e = validate_script_submit("1", &args, &json!({"heap_mb": 63, "max_call_result_mb": 8}))
        .err()
        .ok_or("accepted")?;
    assert_eq!(param(&e), Some("limits.heap_mb"));
    // Against a configured set: a raised call result is above the ceiling, a lowered one is not.
    let ceiling = ScriptLimits {
        heap_mb: 64,
        max_call_result_mb: 8,
        ..ScriptLimits::default()
    };
    assert!(
        validate_script_submit_with("1", &args, &json!({"max_call_result_mb": 4}), &ceiling)
            .is_ok()
    );
    Ok(())
}

#[test]
fn args_nested_past_the_workers_decoder_are_a_validation_error() -> TestResult {
    fn nested(depth: usize) -> Value {
        (0..depth).fold(json!(1), |inner, _| json!([inner]))
    }
    let limits = Value::Null;
    // 125 levels is the deepest the worker's first-frame decoder reads (T4 fix hand-off, T7).
    assert_eq!(MAX_SCRIPT_ARGS_NESTING, 125);
    assert!(validate_script_submit("1", &nested(MAX_SCRIPT_ARGS_NESTING), &limits).is_ok());
    let e = validate_script_submit("1", &nested(MAX_SCRIPT_ARGS_NESTING + 1), &limits)
        .err()
        .ok_or("126 levels accepted")?;
    // Exit 2, an input error: not `sandbox_unavailable`.
    assert_eq!(e.code, ErrorCode::Validation);
    assert_eq!(param(&e), Some("args"));
    // Objects count like arrays, and the bound is on the deepest branch.
    let mut deep = json!({ "k": nested(MAX_SCRIPT_ARGS_NESTING) });
    assert!(validate_script_submit("1", &deep, &limits).is_err());
    deep = json!({ "shallow": [1, 2], "k": nested(MAX_SCRIPT_ARGS_NESTING - 1) });
    assert!(validate_script_submit("1", &deep, &limits).is_ok());
    Ok(())
}

#[test]
fn create_without_a_body_needs_no_body_format() -> TestResult {
    assert!(
        check(
            "jira.issue.create",
            json!({"project": "ABC", "issuetype": "Bug", "summary": "s"})
        )?
        .is_ok()
    );
    // With a Markdown description it passes too from M5 on: the executor converts it (PD-43).
    // The body rule itself stays Confluence's (every Confluence body write requires `body`).
    assert!(
        check(
            "jira.issue.create",
            json!({"project": "ABC", "issuetype": "Bug", "summary": "s", "description": "d"})
        )?
        .is_ok()
    );
    let e = rejected(check(
        "confluence.page.create",
        json!({"space": "DOC", "title": "t", "body": "d"}),
    )?)?;
    assert_eq!(param(&e), Some("body_format"));
    Ok(())
}

#[test]
fn edit_fields_map_comes_from_the_registry() -> TestResult {
    let rules = op("jira.issue.edit")?.field_rules.ok_or("no field_rules")?;
    assert_eq!(rules.fields_map_param, Some("fields"));
    Ok(())
}
