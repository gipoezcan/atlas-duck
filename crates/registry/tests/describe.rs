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
