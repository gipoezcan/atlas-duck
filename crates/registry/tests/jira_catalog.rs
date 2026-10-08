//! Task 3 smoke tests for the Jira catalog; the catalog-wide tests arrive in Task 4.

use atlas_duck_registry::*;
use serde_json::Value;

const JIRA_IDS: [&str; 28] = [
    "jira.myself",
    "jira.project.list",
    "jira.project.get",
    "jira.issue.get",
    "jira.search",
    "jira.comment.list",
    "jira.worklog.list",
    "jira.transition.list",
    "jira.issue.editmeta",
    "jira.createmeta.issuetypes",
    "jira.createmeta.fields",
    "jira.field.list",
    "jira.issuelinktype.list",
    "jira.attachment.meta",
    "jira.user.assignable",
    "jira.board.list",
    "jira.sprint.list",
    "jira.sprint.issues",
    "jira.backlog.issues",
    "jira.issue.create",
    "jira.issue.edit",
    "jira.comment.add",
    "jira.issue.transition",
    "jira.issue.assign",
    "jira.worklog.add",
    "jira.issuelink.create",
    "jira.sprint.move_issues",
    "jira.backlog.move_issues",
];

fn jira() -> Vec<&'static OperationSpec> {
    all()
        .iter()
        .filter(|s| s.product == Product::Jira)
        .collect()
}

#[test]
fn jira_catalog_has_28_specs_in_table_order() {
    let ids: Vec<&str> = jira().iter().map(|s| s.id).collect();
    assert_eq!(ids, JIRA_IDS);
    let reads = jira().iter().filter(|s| s.class == OpClass::Read).count();
    assert_eq!((reads, jira().len() - reads), (19, 9));
}

#[test]
fn jira_specs_look_up_and_ids_are_unique() {
    for id in JIRA_IDS {
        assert_eq!(get(id).map(|s| s.id), Some(id));
    }
    let mut ids: Vec<&str> = all().iter().map(|s| s.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), all().len());
}

#[test]
fn jira_json_text_parses_and_hosts_are_reserved() {
    for spec in jira() {
        let id = spec.id;
        let params = spec.params_schema_json();
        assert_eq!(
            params["$schema"], "https://json-schema.org/draft/2020-12/schema",
            "{id}"
        );
        assert_eq!(params["additionalProperties"], false, "{id}");
        assert!(params["examples"][0].is_object(), "{id}: examples[0]");

        let result = spec.result_schema_json();
        assert!(result.is_object(), "{id}: result_schema parses");
        // Schema fit is proven by `catalog.rs` (U-05); here every URL must be an https
        // `example.invalid` host, in the full and the sparse example alike.
        for text in [spec.result_example, spec.result_example_sparse] {
            for url in text.split("http").skip(1) {
                assert!(
                    url.starts_with("s://")
                        && url[4..]
                            .split('/')
                            .next()
                            .is_some_and(|h| h.ends_with(".example.invalid")),
                    "{id}: URL host must be *.example.invalid"
                );
            }
        }
    }
}

#[test]
fn jira_path_params_are_required_and_target_params_exist() {
    for spec in jira() {
        let params = spec.params_schema_json();
        let props = params["properties"].as_object().expect("properties");
        let required: Vec<&str> = params["required"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let path = spec.endpoint.path;
        for seg in path.split('/').filter(|s| s.starts_with('{')) {
            let name = seg.trim_matches(|c| c == '{' || c == '}');
            assert!(required.contains(&name), "{}: path param {name}", spec.id);
        }
        for t in spec.target_params {
            assert!(props.contains_key(*t), "{}: target param {t}", spec.id);
        }
        for f in spec.cli.flags {
            assert!(
                props.contains_key(f.param),
                "{}: flag param {}",
                spec.id,
                f.param
            );
        }
        if let Some(p) = spec.cli.positional {
            assert!(props.contains_key(p), "{}: positional {p}", spec.id);
        }
        assert_eq!(
            spec.write_guidance,
            spec.class == OpClass::Write,
            "{}",
            spec.id
        );
    }
}

#[test]
fn jira_table_rules_hold() {
    let move_ops = ["jira.sprint.move_issues", "jira.backlog.move_issues"];
    for id in move_ops {
        let s = get(id).expect("op");
        assert_eq!(s.caps.move_limit, Some(50));
        assert_eq!(s.similarity, Similarity::MoveIssues);
        assert!(s.target_params.contains(&"issues"));
        assert_eq!(
            s.params_schema_json()["properties"]["issues"]["maxItems"],
            50
        );
    }
    let with_expand: Vec<&str> = jira()
        .iter()
        .filter(|s| {
            s.field_rules
                .is_some_and(|r| r.expand_allow.contains(&"renderedFields"))
        })
        .map(|s| s.id)
        .collect();
    assert_eq!(with_expand, ["jira.issue.get", "jira.search"]);
    for id in with_expand {
        assert!(
            !get(id).expect("op").redaction_rules.mirrors.is_empty(),
            "{id}"
        );
    }
    let edit = get("jira.issue.edit").expect("op");
    assert_eq!(edit.conflict_baselines, ["expected"]);
    assert_eq!(edit.success.statuses, StatusSet::Exactly(&[204]));
    let link = get("jira.issuelink.create").expect("op");
    assert_eq!(link.success.statuses, StatusSet::Exactly(&[201]));
    assert_eq!(link.success.body, SuccessBody::Empty);
    let min = Version {
        major: 8,
        minor: 4,
        patch: 0,
    };
    for id in ["jira.createmeta.issuetypes", "jira.createmeta.fields"] {
        assert_eq!(get(id).expect("op").min_version, Some(min));
    }
    let none_sim = [
        "jira.search",
        "jira.myself",
        "jira.project.list",
        "jira.field.list",
        "jira.issuelinktype.list",
        "jira.user.assignable",
        "jira.board.list",
    ];
    for s in jira() {
        let expected = match s.id {
            "jira.issue.create" => Similarity::Create,
            "jira.sprint.move_issues" | "jira.backlog.move_issues" => Similarity::MoveIssues,
            id if none_sim.contains(&id) => Similarity::None,
            _ => Similarity::Target,
        };
        assert_eq!(s.similarity, expected, "{}", s.id);
    }
}

#[test]
fn jira_default_fields_constants() {
    assert_eq!(
        atlas_duck_registry::ISSUE_GET_DEFAULT_FIELDS.join(","),
        "summary,status,issuetype,priority,assignee,reporter,created,updated,labels,components,fixVersions,parent,description,issuelinks,security"
    );
    assert_eq!(
        atlas_duck_registry::SEARCH_DEFAULT_FIELDS.join(","),
        "summary,status,assignee,priority,issuetype,updated"
    );
}

#[test]
fn describe_documents_default_fields_and_move_limit() {
    let env = DescribeEnv {
        limits_source: LimitsSource::Default,
        available: None,
        caps: Value::Null,
        script_limits: Value::Null,
    };
    let get_op = describe(get("jira.issue.get").expect("op"), &env);
    assert_eq!(
        get_op["defaults"]["fields"],
        serde_json::json!(ISSUE_GET_DEFAULT_FIELDS)
    );
    let search = describe(get("jira.search").expect("op"), &env);
    assert_eq!(search["defaults"]["max"], 50);
    assert_eq!(
        search["defaults"]["fields"],
        serde_json::json!(SEARCH_DEFAULT_FIELDS)
    );
    assert_eq!(search["items_key"], "issues");
    let mv = describe(get("jira.sprint.move_issues").expect("op"), &env);
    assert_eq!(mv["caps"]["move_limit"], 50);
}
