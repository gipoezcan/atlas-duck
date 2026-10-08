//! Catalog-wide tests (U-05 registry half): counts, order, schemas, examples, §7.2 declarations,
//! similarity kinds and the pure-data gate.

use atlas_duck_registry::*;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

const IDS: [&str; 46] = [
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
    "confluence.user.current",
    "confluence.space.list",
    "confluence.space.get",
    "confluence.page.get",
    "confluence.page.find",
    "confluence.search",
    "confluence.page.children",
    "confluence.comment.list",
    "confluence.label.list",
    "confluence.attachment.list",
    "confluence.page.history",
    "confluence.page.create",
    "confluence.page.update",
    "confluence.page.move",
    "confluence.comment.add",
    "confluence.label.add",
    "confluence.label.remove",
    "confluence.attachment.upload",
];

fn count(product: Product, class: OpClass) -> usize {
    all()
        .iter()
        .filter(|s| s.product == product && s.class == class)
        .count()
}

fn ids_where(pred: impl Fn(&OperationSpec) -> bool) -> BTreeSet<&'static str> {
    all().iter().filter(|s| pred(s)).map(|s| s.id).collect()
}

fn set(ids: &[&'static str]) -> BTreeSet<&'static str> {
    ids.iter().copied().collect()
}

fn id_is_well_formed(id: &str) -> bool {
    let Some((product, rest)) = id.split_once('.') else {
        return false;
    };
    (product == "jira" || product == "confluence")
        && rest
            .split('.')
            .all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
}

#[test]
fn catalog_counts() {
    assert_eq!(all().len(), 46);
    assert_eq!(count(Product::Jira, OpClass::Read), 19);
    assert_eq!(count(Product::Jira, OpClass::Write), 9);
    assert_eq!(count(Product::Confluence, OpClass::Read), 11);
    assert_eq!(count(Product::Confluence, OpClass::Write), 7);
    let ids: Vec<&str> = all().iter().map(|s| s.id).collect();
    assert_eq!(ids, IDS);
    assert_eq!(ids.iter().copied().collect::<BTreeSet<_>>().len(), 46);
    for id in ids {
        assert!(id_is_well_formed(id), "{id}");
        let product = if id.starts_with("jira.") {
            Product::Jira
        } else {
            Product::Confluence
        };
        assert_eq!(get(id).map(|s| s.product), Some(product), "{id}");
    }
}

#[test]
fn u05_examples_validate_against_result_schema() -> Result<(), String> {
    for spec in all() {
        let id = spec.id;
        let params: Value = serde_json::from_str(spec.params_schema)
            .map_err(|e| format!("{id}: params_schema is not JSON: {e}"))?;
        assert_eq!(params["additionalProperties"], false, "{id}: root");
        let validator = jsonschema::validator_for(&params)
            .map_err(|e| format!("{id}: params_schema does not compile: {e}"))?;
        let example = &params["examples"][0];
        assert!(example.is_object(), "{id}: examples[0]");
        if let Err(e) = validator.validate(example) {
            return Err(format!("{id}: params examples[0] invalid: {e}"));
        }

        let schema: Value = serde_json::from_str(spec.result_schema)
            .map_err(|e| format!("{id}: result_schema is not JSON: {e}"))?;
        let validator = jsonschema::validator_for(&schema)
            .map_err(|e| format!("{id}: result_schema does not compile: {e}"))?;
        for (name, text) in [
            ("example", spec.result_example),
            ("sparse", spec.result_example_sparse),
        ] {
            let value: Value = serde_json::from_str(text)
                .map_err(|e| format!("{id}: result {name} is not JSON: {e}"))?;
            if let Err(e) = validator.validate(&value) {
                return Err(format!("{id}: result {name} invalid: {e}"));
            }
        }
    }
    Ok(())
}

/// Same key sets at every object level; every sparse array empty; every sparse `null` nullable.
fn check_sparse(schema: &Value, full: &Value, sparse: &Value, path: &str) -> Result<(), String> {
    match (full, sparse) {
        (Value::Object(f), Value::Object(s)) => {
            // A real dynamic-key map (no declared `properties`, empty in the sparse form, e.g.
            // editmeta `fields`) is the only exemption; every other object is compared and
            // recursed into, declared in the schema or not.
            if schema.get("properties").is_none() && s.is_empty() {
                return Ok(());
            }
            let fk: BTreeSet<_> = f.keys().collect();
            let sk: BTreeSet<_> = s.keys().collect();
            if fk != sk {
                return Err(format!("{path}: key sets differ: {fk:?} vs {sk:?}"));
            }
            for (k, sv) in s {
                let sub = schema
                    .get("properties")
                    .and_then(|p| p.get(k))
                    .unwrap_or(&Value::Null);
                check_sparse(sub, &f[k], sv, &format!("{path}.{k}"))?;
            }
            Ok(())
        }
        (_, Value::Array(s)) => {
            if !s.is_empty() {
                return Err(format!("{path}: sparse array is not empty"));
            }
            Ok(())
        }
        (_, Value::Null) => {
            let nullable = match schema.get("type") {
                Some(Value::Array(types)) => types.iter().any(|t| t == "null"),
                Some(Value::String(t)) => t == "null",
                _ => false,
            };
            if nullable {
                Ok(())
            } else {
                Err(format!("{path}: sparse null is not nullable in the schema"))
            }
        }
        _ => Ok(()),
    }
}

#[test]
fn sparse_examples_have_example_shape() -> Result<(), String> {
    for spec in all() {
        let schema = spec.result_schema_json();
        let full = spec.result_example_json();
        let sparse = spec.result_example_sparse_json();
        // An array root holds items: the sparse form is the empty list (the item shape is
        // checked through the schema by U-05).
        if let (Value::Array(_), Value::Array(s)) = (&full, &sparse) {
            assert!(s.is_empty(), "{}: sparse array root", spec.id);
            continue;
        }
        check_sparse(&schema, &full, &sparse, spec.id)?;
    }
    Ok(())
}

#[test]
fn every_write_declares_success_and_projection() {
    let empty_201 = SuccessShape {
        statuses: StatusSet::Exactly(&[201]),
        body: SuccessBody::Empty,
    };
    let empty_204 = SuccessShape {
        statuses: StatusSet::Exactly(&[204]),
        body: SuccessBody::Empty,
    };
    let default = SuccessShape {
        statuses: StatusSet::Any2xx,
        body: SuccessBody::Json,
    };
    let e201 = ids_where(|s| s.class == OpClass::Write && s.success == empty_201);
    let e204 = ids_where(|s| s.class == OpClass::Write && s.success == empty_204);
    let dflt = ids_where(|s| s.class == OpClass::Write && s.success == default);
    assert_eq!(e201, set(&["jira.issuelink.create"]));
    assert_eq!(
        e204,
        set(&[
            "jira.issue.edit",
            "jira.issue.assign",
            "jira.issue.transition",
            "jira.sprint.move_issues",
            "jira.backlog.move_issues",
            "confluence.label.remove",
        ])
    );
    assert_eq!(e201.len() + e204.len() + dflt.len(), 16);
    // An empty success has an empty receipt; a JSON success projects something.
    for spec in all().iter().filter(|s| s.class == OpClass::Write) {
        let empty = spec.success.body == SuccessBody::Empty;
        assert_eq!(
            spec.result_projection == Projection::Empty,
            empty,
            "{}",
            spec.id
        );
    }
}

#[test]
fn similarity_matches_spec() {
    let create = ids_where(|s| s.similarity == Similarity::Create);
    assert_eq!(
        create,
        set(&["jira.issue.create", "confluence.page.create"])
    );
    let moves = ids_where(|s| s.similarity == Similarity::MoveIssues);
    assert_eq!(
        moves,
        set(&["jira.sprint.move_issues", "jira.backlog.move_issues"])
    );
    let none = ids_where(|s| s.similarity == Similarity::None);
    assert_eq!(
        none,
        set(&[
            "jira.search",
            "jira.myself",
            "jira.project.list",
            "jira.field.list",
            "jira.issuelinktype.list",
            "jira.user.assignable",
            "jira.board.list",
            "confluence.search",
            "confluence.user.current",
            "confluence.space.list",
            "confluence.page.find",
        ])
    );
    for spec in all().iter().filter(|s| s.similarity == Similarity::Target) {
        assert!(!spec.target_params.is_empty(), "{}", spec.id);
    }
    assert_eq!(
        count_similarity(Similarity::Target),
        46 - create.len() - moves.len() - none.len()
    );
}

fn count_similarity(kind: Similarity) -> usize {
    all().iter().filter(|s| s.similarity == kind).count()
}

#[test]
fn rendered_fields_ops_declare_mirrors() {
    for spec in all() {
        let renders = spec
            .field_rules
            .is_some_and(|r| r.expand_allow.contains(&"renderedFields"));
        if renders {
            let mirrors = spec.redaction_rules.mirrors;
            assert!(!mirrors.is_empty(), "{}", spec.id);
            assert!(
                mirrors.iter().any(|m| m.src.ends_with("comment.comments")),
                "{}: comments mirror",
                spec.id
            );
            assert!(
                mirrors.iter().any(|m| m.src.ends_with("worklog.worklogs")),
                "{}: worklogs mirror",
                spec.id
            );
        }
    }
}

#[test]
fn read_op_ids_are_the_30_reads() {
    let reads = read_op_ids();
    assert_eq!(reads.len(), 30);
    for id in &reads {
        assert_eq!(get(id).map(|s| s.class), Some(OpClass::Read), "{id}");
    }
    assert!(!reads.contains(&SCRIPT_RUN.id));
    assert!(all().iter().all(|s| s.id != SCRIPT_RUN.id));
}

#[test]
fn paths_and_methods() {
    for spec in all() {
        let id = spec.id;
        let mut endpoints = vec![spec.endpoint];
        endpoints.extend(spec.alt_endpoint.map(|a| a.endpoint));
        let params = spec.params_schema_json();
        let required: Vec<&str> = params["required"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        for ep in endpoints {
            assert!(ep.path.starts_with("/rest/"), "{id}: {}", ep.path);
            for seg in ep.path.split('/').filter(|s| s.starts_with('{')) {
                let name = seg.trim_matches(|c| c == '{' || c == '}');
                assert!(required.contains(&name), "{id}: placeholder {name}");
            }
        }
    }
    // Every endpoint of a read counts, the alt endpoint included.
    let non_get_reads = ids_where(|s| {
        s.class == OpClass::Read
            && std::iter::once(s.endpoint)
                .chain(s.alt_endpoint.map(|a| a.endpoint))
                .any(|e| e.method != Method::Get)
    });
    assert_eq!(non_get_reads, set(&["jira.search"]));
    for spec in all().iter().filter(|s| s.class == OpClass::Read) {
        let body = if spec.id == "jira.search" {
            BodySource::ParamsAsJson
        } else {
            BodySource::None
        };
        assert_eq!(spec.endpoint.body, body, "{}", spec.id);
        assert!(
            spec.alt_endpoint
                .is_none_or(|a| a.endpoint.body == BodySource::None)
        );
    }
    let search = get("jira.search").expect("jira.search");
    assert_eq!(search.endpoint.method, Method::Post);
    assert_eq!(search.endpoint.path, "/rest/api/2/search");
    let deletes = ids_where(|s| s.endpoint.method == Method::Delete);
    assert_eq!(deletes, set(&["confluence.label.remove"]));
}

fn rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn registry_is_pure_data() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rs_files(&root.join("src"), &mut files);
    assert!(files.len() > 10);
    let banned = [
        "fn(",
        "std::fs",
        "std::net",
        "std::process",
        "std::env",
        "tokio",
        "reqwest",
    ];
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read source");
        for needle in banned {
            assert!(
                !text.contains(needle),
                "{}: contains {needle}",
                file.display()
            );
        }
    }
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml");
    let deps: Vec<&str> = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("[dependencies]")
        .lines()
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('['))
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split('=').next().unwrap_or("").trim())
        .collect();
    assert_eq!(deps, ["serde", "serde_json"]);
}

#[test]
fn confluence_table_rules_hold() {
    let spec = |id: &str| get(id).expect("op");
    let update = spec("confluence.page.update");
    assert_eq!(update.conflict_baselines, ["base_version"]);
    assert_eq!(
        update.params_schema_json()["properties"]["base_version"]["minimum"],
        1
    );
    assert!(spec("confluence.page.move").conflict_baselines.is_empty());
    assert_eq!(
        spec("confluence.page.create").target_params,
        ["space", "parent"]
    );
    assert_eq!(spec("confluence.page.move").target_params, ["id"]);
    assert_eq!(
        spec("confluence.attachment.upload").caps.upload_max_bytes,
        Some(10 * 1024 * 1024)
    );
    assert_eq!(
        spec("confluence.label.add").params_schema_json()["properties"]["labels"]["maxItems"],
        20
    );
    assert_eq!(
        spec("confluence.label.add").result_projection,
        Projection::AgentLabels
    );
    let history = spec("confluence.page.history");
    let alt = history.alt_endpoint.expect("alt_endpoint");
    assert_eq!(alt.when_param_present, "version");
    assert_eq!(alt.endpoint.path, "/rest/api/content/{id}");
    for (id, default, hard) in [
        ("confluence.space.list", 25, 500),
        ("confluence.search", 25, 200),
        ("confluence.comment.list", 25, 200),
    ] {
        let max = spec(id).caps.max.expect("max cap");
        assert_eq!((max.default, max.hard_cap_default), (default, hard), "{id}");
        assert_eq!(
            spec(id).paginated.map(|p| p.items_key),
            Some("results"),
            "{id}"
        );
    }
    assert_eq!(
        spec("confluence.search").target_display,
        TargetDisplay::Query { param: "cql" }
    );
}

/// Does `pattern` (`*` one key, `name[]` every element, a leading `[]` the root array) address
/// `path` (object keys; array elements are the marker `[]`)?
fn pattern_matches(pattern: &str, path: &[String]) -> bool {
    let mut want: Vec<String> = Vec::new();
    for seg in pattern.split('.') {
        match seg.strip_suffix("[]") {
            Some("") => want.push("[]".into()),
            Some(name) => {
                want.push(name.into());
                want.push("[]".into());
            }
            None => want.push(seg.into()),
        }
    }
    want.len() == path.len() && want.iter().zip(path).all(|(w, p)| w == "*" || w == p)
}

fn walk_urls(value: &Value, path: &mut Vec<String>, found: &mut Vec<Vec<String>>) {
    match value {
        Value::String(s) if s.starts_with("https://") => found.push(path.clone()),
        Value::Object(map) => {
            for (k, v) in map {
                path.push(k.clone());
                walk_urls(v, path, found);
                path.pop();
            }
        }
        Value::Array(items) => {
            for v in items {
                path.push("[]".into());
                walk_urls(v, path, found);
                path.pop();
            }
        }
        _ => {}
    }
}

#[test]
fn every_absolute_url_in_a_read_example_is_a_declared_url_field() {
    for spec in all().iter().filter(|s| s.class == OpClass::Read) {
        let mut found = Vec::new();
        walk_urls(&spec.result_example_json(), &mut Vec::new(), &mut found);
        for path in found {
            assert!(
                spec.redaction_rules
                    .url_fields
                    .iter()
                    .any(|p| pattern_matches(p, &path)),
                "{}: URL at {} is not a declared url_field",
                spec.id,
                path.join(".")
            );
        }
    }
}

#[test]
fn copies_and_mirrors_are_item_relative() {
    for spec in all() {
        let items_key = spec.paginated.map(|p| p.items_key);
        let mut paths: Vec<&str> = Vec::new();
        for c in spec.redaction_rules.copies {
            match c {
                CopyRule::Path(p) => paths.push(p),
                CopyRule::ChangelogItems { items_path, .. } => paths.push(items_path),
                CopyRule::RootPath(p) => {
                    assert!(
                        items_key.is_some(),
                        "{}: RootPath on a non-paged op",
                        spec.id
                    );
                    assert!(!p.contains("[]"), "{}: {p}", spec.id);
                }
            }
        }
        for m in spec.redaction_rules.mirrors {
            paths.push(m.src);
            paths.push(m.dst);
        }
        for p in paths {
            assert!(
                !p.contains("issues[]"),
                "{}: {p} is not item-relative",
                spec.id
            );
            if let Some(k) = items_key {
                assert!(!p.starts_with(&format!("{k}[]")), "{}: {p}", spec.id);
            }
        }
    }
    let search = get("jira.search").expect("jira.search");
    let root: Vec<_> = search
        .redaction_rules
        .copies
        .iter()
        .filter_map(|c| match c {
            CopyRule::RootPath(p) => Some(*p),
            _ => None,
        })
        .collect();
    assert_eq!(root, ["names.{field}", "schema.{field}"]);
    assert_eq!(
        search.redaction_rules.mirrors,
        get("jira.issue.get")
            .expect("jira.issue.get")
            .redaction_rules
            .mirrors
    );
    assert!(
        search
            .redaction_rules
            .mirrors
            .iter()
            .any(|m| m.dst == "renderedFields.attachment")
    );
}

#[test]
fn param_names_resolve_against_the_params_schema() {
    for spec in all() {
        let id = spec.id;
        let params = spec.params_schema_json();
        let props = params["properties"].as_object().expect("properties");
        let has = |name: &str, what: &str| {
            assert!(
                props.contains_key(name),
                "{id}: {what} {name} is not a param"
            );
        };
        for t in spec.target_params {
            has(t, "target_params");
        }
        for b in spec.conflict_baselines {
            has(b, "conflict_baselines");
        }
        for f in spec.cli.flags {
            has(f.param, "cli flag");
        }
        if let Some(p) = spec.cli.positional {
            has(p, "positional");
        }
        match spec.target_display {
            TargetDisplay::Param(p) | TargetDisplay::CreateIn(p) => has(p, "target_display"),
            TargetDisplay::Query { param } => has(param, "target_display"),
            TargetDisplay::Pair(a, b) => {
                has(a, "target_display");
                has(b, "target_display");
            }
            TargetDisplay::MoveInto {
                sprint_param,
                issues_param,
            } => {
                has(issues_param, "target_display");
                if let Some(p) = sprint_param {
                    has(p, "target_display");
                }
            }
            TargetDisplay::None => {}
        }
        let mut endpoints = vec![spec.endpoint];
        if let Some(alt) = spec.alt_endpoint {
            has(alt.when_param_present, "alt_endpoint trigger");
            endpoints.push(alt.endpoint);
        }
        for ep in endpoints {
            for q in ep.query {
                match q.value {
                    QueryValue::Param(p) | QueryValue::ParamOr { param: p, .. } => {
                        has(p, "query");
                    }
                    QueryValue::ParamBoolFlag { param, .. } => has(param, "query"),
                    QueryValue::Const(_) => {}
                }
            }
        }
        if let Some(max) = spec.caps.max {
            has(max.param, "caps.max");
        }
        if let Some(rules) = spec.field_rules {
            for p in [
                rules.fields_param,
                rules.fields_map_param,
                rules.expand_param,
            ]
            .into_iter()
            .flatten()
            {
                has(p, "field_rules");
            }
        }
    }
}

#[test]
fn confluence_search_never_inherits_the_server_excerpt_default() {
    let search = get("confluence.search").expect("confluence.search");
    let excerpt = search
        .endpoint
        .query
        .iter()
        .find(|q| q.name == "excerpt")
        .expect("excerpt query");
    assert_eq!(
        excerpt.value,
        QueryValue::ParamOr {
            param: "excerpt",
            default: "none"
        }
    );
    assert_eq!(
        get("confluence.page.children")
            .expect("op")
            .caps
            .max
            .map(|m| (m.default, m.hard_cap_default)),
        Some((25, 200))
    );
}
