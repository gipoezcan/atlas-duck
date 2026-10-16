mod common;

use atlas_duck_registry::*;
use common::{READ, env};
use serde_json::json;

#[test]
fn read_spec_is_release_without_available() {
    let out = describe(&READ, &env());
    assert_eq!(out["op_id"], "test.thing.get");
    assert_eq!(out["class"], "read");
    assert_eq!(out["approval"], "release");
    assert_eq!(out["limits_source"], "default");
    assert!(out.get("available").is_none());
    assert!(out.get("items_key").is_none());
    assert_eq!(out["script_limits"], json!({"timeout_s": 120}));
    assert_eq!(out["result_example"], json!({"key": "ABC-123"}));
    assert_eq!(out["defaults"], json!({"max": 50}));
    assert_eq!(out["caps"]["max"]["hard_cap"], 100);
}

#[test]
fn available_and_effective_appear_with_an_instance() {
    let mut e = env();
    e.available = Some(false);
    e.limits_source = LimitsSource::Effective;
    e.caps = json!({"max": 7});
    let out = describe(&READ, &e);
    assert_eq!(out["available"], false);
    assert_eq!(out["limits_source"], "effective");
    assert_eq!(out["caps"], json!({"max": 7}));
}

#[test]
fn write_spec_carries_the_guidance() {
    let spec = OperationSpec {
        class: OpClass::Write,
        write_guidance: true,
        ..READ
    };
    let out = describe(&spec, &env());
    assert_eq!(out["class"], "write");
    assert_eq!(out["approval"], "approve");
    assert!(
        out["description"]
            .as_str()
            .unwrap_or("")
            .contains(WRITE_GUIDANCE)
    );
}

#[test]
fn paginated_spec_has_items_key_and_rule() {
    let spec = OperationSpec {
        paginated: Some(PageSpec {
            items_key: "issues",
            offset_param: "start",
            limit_param: "max",
        }),
        ..READ
    };
    let out = describe(&spec, &env());
    assert_eq!(out["items_key"], "issues");
    assert!(
        out["description"]
            .as_str()
            .unwrap_or("")
            .contains(PAGINATION_GUIDANCE)
    );
}

#[test]
fn cli_block_and_examples_come_from_the_binding_and_schema() {
    let out = describe(&READ, &env());
    assert_eq!(out["cli"]["positional"], "key");
    assert_eq!(out["cli"]["file_variants"], json!(["--body-file"]));
    assert_eq!(
        out["cli"]["usage"],
        "atlas-duck jira issue get <key> [--max <n>] [--expand] [--body <value>] [--body-file <path>]"
    );
    assert_eq!(
        out["examples"]["cli"],
        "atlas-duck jira issue get ABC-123 --max 10 --expand"
    );
    assert_eq!(
        out["examples"]["call"],
        r#"atlas-duck call test.thing.get --params '{"expand":true,"key":"ABC-123","max":10}'"#
    );
}

#[test]
fn registry_lookups_agree_with_all() {
    for spec in all() {
        assert_eq!(get(spec.id).map(|s| s.id), Some(spec.id));
    }
    assert!(get("no.such.op").is_none());
    assert_eq!(
        read_op_ids().len(),
        all().iter().filter(|s| s.class == OpClass::Read).count()
    );
}

#[test]
fn write_class_gets_the_guidance_even_without_the_flag() {
    let spec = OperationSpec {
        class: OpClass::Write,
        write_guidance: false,
        ..READ
    };
    let out = describe(&spec, &env());
    assert!(
        out["description"]
            .as_str()
            .unwrap_or("")
            .contains(WRITE_GUIDANCE)
    );
}

#[test]
fn ops_list_json_shape() {
    let e = env();
    let out = ops_list_json(&e);
    let rows = out["ops"].as_array().unwrap();
    assert_eq!(rows.len(), 46);
    assert_eq!(out.as_object().unwrap().len(), 1);
    for (row, spec) in rows.iter().zip(all()) {
        let obj = row.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["approval", "class", "description", "op_id"]);
        let d = describe(spec, &e);
        for k in ["op_id", "class", "approval", "description"] {
            assert_eq!(row[k], d[k], "{k}");
        }
    }
}

#[test]
fn jira_writes_state_verbatim_rule() {
    // PD-42 (plan text, verbatim).
    let sentence = "Text in `fields`, `update` and `comment` is sent as Jira wiki markup unchanged; \
                    only `description`/`body` with `body_format=markdown` are converted.";
    assert_eq!(JIRA_VERBATIM_GUIDANCE, sentence);
    let mut jira_writes = 0;
    for spec in all() {
        let out = describe(spec, &env());
        let text = out["description"].as_str().unwrap_or("");
        let jira_write = spec.product == Product::Jira && spec.class == OpClass::Write;
        assert_eq!(text.contains(sentence), jira_write, "{}", spec.id);
        if jira_write {
            jira_writes += 1;
            // After the write guidance.
            let at = text.find(sentence).unwrap_or(0);
            assert!(text[..at].contains(WRITE_GUIDANCE), "{}", spec.id);
        }
    }
    assert_eq!(jira_writes, 9);
    // A read flagged for the write guidance gets that guidance only.
    let spec = OperationSpec {
        write_guidance: true,
        ..READ
    };
    let out = describe(&spec, &env());
    let text = out["description"].as_str().unwrap_or("");
    assert!(text.contains(WRITE_GUIDANCE) && !text.contains(sentence));
}

#[test]
fn confluence_describe_documents_cql_placeholders_lossy() {
    // PD-112 (plan texts, verbatim; the placeholder sentence is §12.4's onboarding sentence).
    let cql = "The CQL is sent as `(<your CQL>) AND type in (page,blogpost,comment,attachment)` \
               plus your trailing ORDER BY; an ORDER BY elsewhere, an unterminated quote or \
               unbalanced parentheses are rejected.";
    let placeholders = "A Markdown body that still contains `page get` placeholders \
                        (`[macro: …]`, `confluence:` links or images, `@user:<key>`) is rejected \
                        with `markdown_placeholders`: fetch with `--format storage` and submit \
                        `body_format=storage`.";
    let lossy = "If `page get` reported `meta.conversion.lossy = true`, edit with \
                 `body_format=storage`; a Markdown update that would remove macros (task lists \
                 included), images or links (mentions included) is flagged to the approver.";
    assert_eq!(CONFLUENCE_CQL_GUIDANCE, cql);
    assert_eq!(CONFLUENCE_PLACEHOLDER_GUIDANCE, placeholders);
    assert_eq!(CONFLUENCE_LOSSY_GUIDANCE, lossy);
    let body_ops = [
        "confluence.page.create",
        "confluence.page.update",
        "confluence.comment.add",
    ];
    let mut seen = [0; 3];
    for spec in all() {
        let out = describe(spec, &env());
        let text = out["description"].as_str().unwrap_or("");
        let id = spec.id;
        assert_eq!(text.contains(cql), id == "confluence.search", "{id}");
        assert_eq!(text.contains(placeholders), body_ops.contains(&id), "{id}");
        assert_eq!(text.contains(lossy), id == "confluence.page.update", "{id}");
        for (n, s) in seen.iter_mut().zip([cql, placeholders, lossy]) {
            if text.contains(s) {
                *n += 1;
                // Each text appears once.
                assert_eq!(text.matches(s).count(), 1, "{id}");
            }
        }
        if body_ops.contains(&id) {
            // After the write guidance; the lossy text after the placeholder text.
            let at = text.find(placeholders).unwrap_or(0);
            assert!(text[..at].contains(WRITE_GUIDANCE), "{id}");
            if let Some(l) = text.find(lossy) {
                assert!(l > at, "{id}");
            }
        }
    }
    assert_eq!(seen, [1, 3, 1]);
}
